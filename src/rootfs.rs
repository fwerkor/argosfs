use crate::error::{ArgosError, Result};
use crate::types::{BackendKind, DiskStatus, Metadata};
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
    pub replayed: bool,
    pub invalid_journal_entries: u64,
    pub errors: Vec<String>,
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
    preflight_root(backend, mode, degraded)?;

    let redundancy = minimum_active_redundancy(&meta);
    if missing_devices > redundancy {
        return Err(ArgosError::DegradedPool(format!(
            "rootfs has {missing_devices} missing/offline devices but only {} parity devices",
            redundancy
        )));
    }
    if mode == RootMountMode::DegradedReadWrite && !degraded {
        return Err(ArgosError::UnsafeMount(
            "degraded-rw was requested but the pool is not degraded".to_string(),
        ));
    }
    let report = fs.transaction_report()?;
    if report.invalid_entries > 0
        && matches!(
            mode,
            RootMountMode::ReadWrite | RootMountMode::DegradedReadWrite
        )
    {
        return Err(ArgosError::JournalReplayRequired(format!(
            "raw journal has {} invalid entries; mount recovery or fsck before rw rootfs",
            report.invalid_entries
        )));
    }
    if !report.errors.is_empty()
        && matches!(
            mode,
            RootMountMode::ReadWrite | RootMountMode::DegradedReadWrite
        )
    {
        return Err(ArgosError::UnsafeMount(format!(
            "rootfs preflight has unresolved transaction errors: {}",
            report.errors.join("; ")
        )));
    }
    Ok(RootPreflightReport {
        ok: true,
        backend,
        mode: match mode {
            RootMountMode::ReadWrite => "rw",
            RootMountMode::ReadOnly => "ro",
            RootMountMode::DegradedReadOnly => "degraded-ro",
            RootMountMode::DegradedReadWrite => "degraded-rw",
            RootMountMode::Recovery => "recovery",
        }
        .to_string(),
        total_devices,
        available_devices,
        missing_devices,
        redundancy,
        degraded,
        readonly: matches!(
            mode,
            RootMountMode::ReadOnly | RootMountMode::DegradedReadOnly | RootMountMode::Recovery
        ),
        replayed: report.replayed,
        invalid_journal_entries: report.invalid_entries,
        errors: report.errors,
    })
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
