use crate::error::{ArgosError, Result};
use crate::types::{BackendKind, DiskStatus, Metadata, NodeKind};
use crate::ArgosFs;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootMountMode {
    ReadWrite,
    ReadOnly,
    DegradedReadOnly,
    DegradedReadWrite,
    Recovery,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootPreflightReport {
    pub ok: bool,
    pub backend: BackendKind,
    pub mode: String,
    pub total_devices: usize,
    pub available_devices: usize,
    pub missing_devices: usize,
    pub redundancy: usize,
    pub degraded: bool,
    pub readonly: bool,
    pub can_mount_readonly: bool,
    pub can_mount_readwrite: bool,
    pub recommended_mode: String,
    pub replayed: bool,
    pub invalid_journal_entries: u64,
    pub issues: Vec<RootPreflightIssue>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootPreflightIssue {
    pub severity: String,
    pub code: String,
    pub message: String,
}

impl std::str::FromStr for RootMountMode {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "rw" => Ok(Self::ReadWrite),
            "ro" => Ok(Self::ReadOnly),
            "degraded-ro" => Ok(Self::DegradedReadOnly),
            "degraded-rw" => Ok(Self::DegradedReadWrite),
            "recovery" => Ok(Self::Recovery),
            other => Err(format!("unknown root mount mode: {other}")),
        }
    }
}

impl RootMountMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadWrite => "rw",
            Self::ReadOnly => "ro",
            Self::DegradedReadOnly => "degraded-ro",
            Self::DegradedReadWrite => "degraded-rw",
            Self::Recovery => "recovery",
        }
    }

    fn is_readwrite(self) -> bool {
        matches!(self, Self::ReadWrite | Self::DegradedReadWrite)
    }

    fn is_readonly(self) -> bool {
        matches!(
            self,
            Self::ReadOnly | Self::DegradedReadOnly | Self::Recovery
        )
    }
}

pub fn preflight_root(backend: BackendKind, mode: RootMountMode, degraded: bool) -> Result<()> {
    if backend == BackendKind::Host {
        return Err(ArgosError::UnsafeMount(
            "host backend is not accepted as a CapOS rootfs backend".to_string(),
        ));
    }
    if degraded && mode == RootMountMode::ReadWrite {
        return Err(ArgosError::ReadonlyRequired(
            "degraded rootfs requires degraded-ro or explicit degraded-rw".to_string(),
        ));
    }
    Ok(())
}

pub fn preflight_volume(fs: &ArgosFs, mode: RootMountMode) -> Result<RootPreflightReport> {
    let report = preflight_report(fs, mode);
    if report.ok {
        Ok(report)
    } else {
        Err(preflight_error(&report))
    }
}

pub fn preflight_report(fs: &ArgosFs, mode: RootMountMode) -> RootPreflightReport {
    let meta = fs.metadata_snapshot();
    let backend = meta.backend;
    let total_devices = meta.disks.len();
    let available_devices = meta
        .disks
        .values()
        .filter(|disk| matches!(disk.status, DiskStatus::Online | DiskStatus::Degraded))
        .count();
    let missing_devices = total_devices.saturating_sub(available_devices);
    let degraded = missing_devices > 0
        || meta
            .disks
            .values()
            .any(|disk| disk.status != DiskStatus::Online);
    let redundancy = minimum_active_redundancy(&meta);
    let mut issues = Vec::new();
    let mut errors = Vec::new();

    if backend == BackendKind::Host {
        push_issue(
            &mut issues,
            &mut errors,
            "error",
            "unsupported-host-backend",
            "host backend is not accepted as a CapOS rootfs backend",
        );
    }
    if degraded && mode == RootMountMode::ReadWrite {
        push_issue(
            &mut issues,
            &mut errors,
            "error",
            "degraded-rootfs-requires-explicit-mode",
            "degraded rootfs requires degraded-ro or explicit degraded-rw",
        );
    }
    if missing_devices > redundancy {
        push_issue(
            &mut issues,
            &mut errors,
            "error",
            "insufficient-redundancy",
            format!(
                "rootfs has {missing_devices} missing/offline devices but only {redundancy} parity devices"
            ),
        );
    }
    if mode == RootMountMode::DegradedReadWrite && !degraded {
        push_issue(
            &mut issues,
            &mut errors,
            "error",
            "unnecessary-degraded-rw",
            "degraded-rw was requested but the pool is not degraded",
        );
    }
    validate_switch_root_mountpoints(fs, &mut issues, &mut errors);

    let mut replayed = false;
    let mut invalid_journal_entries = 0;
    match fs.transaction_report() {
        Ok(report) => {
            replayed = report.replayed;
            invalid_journal_entries = report.invalid_entries;
            if report.invalid_entries > 0 && mode.is_readwrite() {
                push_issue(
                    &mut issues,
                    &mut errors,
                    "error",
                    "journal-replay-required",
                    format!(
                        "raw journal has {} invalid entries; mount recovery or fsck before rw rootfs",
                        report.invalid_entries
                    ),
                );
            } else if report.invalid_entries > 0 {
                push_issue(
                    &mut issues,
                    &mut errors,
                    "warning",
                    "journal-has-invalid-entries",
                    format!(
                        "raw journal has {} invalid entries; recovery or fsck is recommended",
                        report.invalid_entries
                    ),
                );
            }
            if !report.errors.is_empty() && mode.is_readwrite() {
                push_issue(
                    &mut issues,
                    &mut errors,
                    "error",
                    "transaction-errors-block-rw",
                    format!(
                        "rootfs preflight has unresolved transaction errors: {}",
                        report.errors.join("; ")
                    ),
                );
            } else {
                for message in report.errors {
                    push_issue(
                        &mut issues,
                        &mut errors,
                        "warning",
                        "transaction-audit-warning",
                        message,
                    );
                }
            }
        }
        Err(err) => push_issue(
            &mut issues,
            &mut errors,
            "error",
            "transaction-audit-failed",
            format!("transaction audit failed: {err}"),
        ),
    }

    let root_mountpoints_ready = !issues.iter().any(|issue| {
        matches!(
            issue.code.as_str(),
            "root-mountpoint-missing" | "root-mountpoint-not-directory"
        )
    });
    let can_mount_readonly =
        backend != BackendKind::Host && missing_devices <= redundancy && root_mountpoints_ready;
    let can_mount_readwrite = backend != BackendKind::Host
        && missing_devices <= redundancy
        && root_mountpoints_ready
        && invalid_journal_entries == 0
        && !issues
            .iter()
            .any(|issue| issue.severity == "error" && issue.code != "unnecessary-degraded-rw")
        && (!degraded || mode == RootMountMode::DegradedReadWrite);
    let recommended_mode = recommended_mode(
        backend,
        degraded,
        missing_devices,
        redundancy,
        invalid_journal_entries,
        &issues,
    );

    RootPreflightReport {
        ok: errors.is_empty(),
        backend,
        mode: mode.as_str().to_string(),
        total_devices,
        available_devices,
        missing_devices,
        redundancy,
        degraded,
        readonly: mode.is_readonly(),
        can_mount_readonly,
        can_mount_readwrite,
        recommended_mode,
        replayed,
        invalid_journal_entries,
        issues,
        errors,
    }
}

fn validate_switch_root_mountpoints(
    fs: &ArgosFs,
    issues: &mut Vec<RootPreflightIssue>,
    errors: &mut Vec<String>,
) {
    for path in ["/dev", "/proc", "/run", "/sys"] {
        match fs.attr_path(path, true) {
            Ok(attr) if attr.kind == NodeKind::Directory => {}
            Ok(attr) => push_issue(
                issues,
                errors,
                "error",
                "root-mountpoint-not-directory",
                format!("{path} must be a directory for initramfs switch_root handoff, found {:?}", attr.kind),
            ),
            Err(_) => push_issue(
                issues,
                errors,
                "error",
                "root-mountpoint-missing",
                format!("{path} is missing; read-only rootfs boot cannot create switch_root mountpoints"),
            ),
        }
    }
}

fn push_issue(
    issues: &mut Vec<RootPreflightIssue>,
    errors: &mut Vec<String>,
    severity: &str,
    code: &str,
    message: impl Into<String>,
) {
    let message = message.into();
    if severity == "error" {
        errors.push(message.clone());
    }
    issues.push(RootPreflightIssue {
        severity: severity.to_string(),
        code: code.to_string(),
        message,
    });
}

fn preflight_error(report: &RootPreflightReport) -> ArgosError {
    let message = report.errors.join("; ");
    let code = report
        .issues
        .iter()
        .find(|issue| issue.severity == "error")
        .map(|issue| issue.code.as_str())
        .unwrap_or("root-preflight-failed");
    match code {
        "degraded-rootfs-requires-explicit-mode" => ArgosError::ReadonlyRequired(message),
        "insufficient-redundancy" => ArgosError::DegradedPool(message),
        "journal-replay-required" => ArgosError::JournalReplayRequired(message),
        _ => ArgosError::UnsafeMount(message),
    }
}

fn recommended_mode(
    backend: BackendKind,
    degraded: bool,
    missing_devices: usize,
    redundancy: usize,
    invalid_journal_entries: u64,
    issues: &[RootPreflightIssue],
) -> String {
    if backend == BackendKind::Host {
        return "unsupported".to_string();
    }
    if missing_devices > redundancy {
        return "recovery".to_string();
    }
    if invalid_journal_entries > 0
        || issues.iter().any(|issue| {
            issue.severity == "error"
                && !matches!(
                    issue.code.as_str(),
                    "unnecessary-degraded-rw" | "degraded-rootfs-requires-explicit-mode"
                )
        })
    {
        return "recovery".to_string();
    }
    if degraded {
        "degraded-ro".to_string()
    } else {
        "rw".to_string()
    }
}

fn minimum_active_redundancy(meta: &Metadata) -> usize {
    let mut values = meta
        .inodes
        .values()
        .flat_map(|inode| inode.blocks.iter())
        .filter_map(|block| {
            let layout_id = if block.layout_id.is_empty() {
                "layout-0000"
            } else {
                &block.layout_id
            };
            meta.layouts.get(layout_id).map(|layout| layout.m)
        })
        .collect::<Vec<_>>();
    if values.is_empty() {
        values.push(
            meta.layouts
                .get(&meta.current_write_layout)
                .or_else(|| meta.layouts.get("layout-0000"))
                .map(|layout| layout.m)
                .unwrap_or(meta.config.m),
        );
    }
    values.into_iter().min().unwrap_or(0)
}

#[cfg(test)]
#[path = "rootfs_tests.rs"]
mod tests;
