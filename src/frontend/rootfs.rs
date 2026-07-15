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
mod tests {
    use super::*;
    use crate::types::VolumeConfig;
    use tempfile::tempdir;

    fn base_report() -> RootPreflightReport {
        RootPreflightReport {
            ok: false,
            backend: BackendKind::LoopBlock,
            mode: "rw".to_string(),
            total_devices: 3,
            available_devices: 2,
            missing_devices: 1,
            redundancy: 1,
            degraded: true,
            readonly: false,
            can_mount_readonly: true,
            can_mount_readwrite: false,
            recommended_mode: "degraded-ro".to_string(),
            replayed: false,
            invalid_journal_entries: 0,
            issues: Vec::new(),
            errors: Vec::new(),
        }
    }

    #[test]
    fn root_mount_mode_strings_and_flags_cover_every_mode() {
        let cases = [
            ("rw", RootMountMode::ReadWrite, true, false),
            ("ro", RootMountMode::ReadOnly, false, true),
            ("degraded-ro", RootMountMode::DegradedReadOnly, false, true),
            ("degraded-rw", RootMountMode::DegradedReadWrite, true, false),
            ("recovery", RootMountMode::Recovery, false, true),
        ];
        for (raw, mode, readwrite, readonly) in cases {
            assert_eq!(raw.parse::<RootMountMode>().unwrap(), mode);
            assert_eq!(mode.as_str(), raw);
            assert_eq!(mode.is_readwrite(), readwrite);
            assert_eq!(mode.is_readonly(), readonly);
        }
        assert!("auto".parse::<RootMountMode>().is_err());
    }

    #[test]
    fn simple_root_preflight_rejects_unsafe_combinations() {
        assert!(matches!(
            preflight_root(BackendKind::Host, RootMountMode::ReadOnly, false),
            Err(ArgosError::UnsafeMount(_))
        ));
        assert!(matches!(
            preflight_root(BackendKind::LoopBlock, RootMountMode::ReadWrite, true),
            Err(ArgosError::ReadonlyRequired(_))
        ));
        preflight_root(
            BackendKind::RawBlock,
            RootMountMode::DegradedReadWrite,
            true,
        )
        .unwrap();
        preflight_root(BackendKind::LoopBlock, RootMountMode::ReadWrite, false).unwrap();
    }

    #[test]
    fn issue_collection_separates_warnings_from_errors() {
        let mut issues = Vec::new();
        let mut errors = Vec::new();
        push_issue(
            &mut issues,
            &mut errors,
            "warning",
            "warning-code",
            "warning message",
        );
        push_issue(
            &mut issues,
            &mut errors,
            "error",
            "error-code",
            String::from("error message"),
        );
        assert_eq!(issues.len(), 2);
        assert_eq!(errors, ["error message"]);
        assert_eq!(issues[0].severity, "warning");
        assert_eq!(issues[1].code, "error-code");
    }

    #[test]
    fn preflight_error_uses_the_leading_error_code() {
        for (code, expected) in [
            ("degraded-rootfs-requires-explicit-mode", "readonly"),
            ("insufficient-redundancy", "degraded"),
            ("journal-replay-required", "journal"),
            ("root-mountpoint-missing", "unsafe"),
        ] {
            let mut report = base_report();
            report.errors.push("blocked".to_string());
            report.issues.push(RootPreflightIssue {
                severity: "error".to_string(),
                code: code.to_string(),
                message: "blocked".to_string(),
            });
            let error = preflight_error(&report);
            match expected {
                "readonly" => assert!(matches!(error, ArgosError::ReadonlyRequired(_))),
                "degraded" => assert!(matches!(error, ArgosError::DegradedPool(_))),
                "journal" => assert!(matches!(error, ArgosError::JournalReplayRequired(_))),
                _ => assert!(matches!(error, ArgosError::UnsafeMount(_))),
            }
        }

        let mut report = base_report();
        report.errors.push("unknown".to_string());
        assert!(matches!(
            preflight_error(&report),
            ArgosError::UnsafeMount(_)
        ));
    }

    #[test]
    fn recommended_mode_prioritizes_backend_redundancy_and_recovery() {
        assert_eq!(
            recommended_mode(BackendKind::Host, false, 0, 0, 0, &[]),
            "unsupported"
        );
        assert_eq!(
            recommended_mode(BackendKind::RawBlock, true, 2, 1, 0, &[]),
            "recovery"
        );
        assert_eq!(
            recommended_mode(BackendKind::RawBlock, false, 0, 1, 1, &[]),
            "recovery"
        );
        let blocking = [RootPreflightIssue {
            severity: "error".to_string(),
            code: "root-mountpoint-missing".to_string(),
            message: "missing".to_string(),
        }];
        assert_eq!(
            recommended_mode(BackendKind::RawBlock, false, 0, 1, 0, &blocking),
            "recovery"
        );
        let ignored = [
            RootPreflightIssue {
                severity: "error".to_string(),
                code: "unnecessary-degraded-rw".to_string(),
                message: "ignored".to_string(),
            },
            RootPreflightIssue {
                severity: "warning".to_string(),
                code: "audit".to_string(),
                message: "warning".to_string(),
            },
        ];
        assert_eq!(
            recommended_mode(BackendKind::LoopBlock, true, 1, 1, 0, &ignored),
            "degraded-ro"
        );
        assert_eq!(
            recommended_mode(BackendKind::LoopBlock, false, 0, 1, 0, &ignored),
            "rw"
        );
    }

    #[test]
    fn host_volume_report_lists_missing_switch_root_mountpoints() {
        let dir = tempdir().unwrap();
        let fs = ArgosFs::create(
            dir.path(),
            VolumeConfig {
                k: 1,
                m: 0,
                ..VolumeConfig::default()
            },
            1,
            false,
        )
        .unwrap();
        let report = preflight_report(&fs, RootMountMode::ReadOnly);
        assert!(!report.ok);
        assert_eq!(report.backend, BackendKind::Host);
        assert!(report.readonly);
        assert!(!report.can_mount_readonly);
        assert_eq!(report.recommended_mode, "unsupported");
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.code == "unsupported-host-backend"));
        assert!(report
            .issues
            .iter()
            .any(|issue| issue.code == "root-mountpoint-missing"));
        assert!(matches!(
            preflight_volume(&fs, RootMountMode::ReadOnly),
            Err(ArgosError::UnsafeMount(_))
        ));
    }

    #[test]
    fn switch_root_validation_distinguishes_wrong_types() {
        let dir = tempdir().unwrap();
        let fs = ArgosFs::create(
            dir.path(),
            VolumeConfig {
                k: 1,
                m: 0,
                ..VolumeConfig::default()
            },
            1,
            false,
        )
        .unwrap();
        fs.create_file_path("/dev", 0o600).unwrap();
        fs.mkdir("/proc", 0o755).unwrap();
        let mut issues = Vec::new();
        let mut errors = Vec::new();
        validate_switch_root_mountpoints(&fs, &mut issues, &mut errors);
        assert!(issues
            .iter()
            .any(|issue| issue.code == "root-mountpoint-not-directory"));
        assert!(issues
            .iter()
            .any(|issue| issue.code == "root-mountpoint-missing"));
        assert_eq!(issues.len(), errors.len());
    }

    #[test]
    fn redundancy_uses_config_when_no_blocks_exist() {
        let dir = tempdir().unwrap();
        let fs = ArgosFs::create(
            dir.path(),
            VolumeConfig {
                k: 2,
                m: 1,
                ..VolumeConfig::default()
            },
            3,
            false,
        )
        .unwrap();
        assert_eq!(minimum_active_redundancy(&fs.metadata_snapshot()), 1);
    }
}
