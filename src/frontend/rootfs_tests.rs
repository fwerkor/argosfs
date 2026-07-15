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

fn create_switch_root_dirs(fs: &ArgosFs) {
    for path in ["/dev", "/proc", "/sys", "/run"] {
        if fs.attr_path(path, false).is_err() {
            fs.mkdir(path, 0o755).unwrap();
        }
    }
}

#[test]
fn preflight_report_covers_degraded_redundancy_and_unnecessary_modes() {
    let dir = tempdir().unwrap();
    let images = [
        dir.path().join("disk0.img"),
        dir.path().join("disk1.img"),
        dir.path().join("disk2.img"),
    ];
    let fs = ArgosFs::create_loop(
        &images,
        VolumeConfig {
            k: 1,
            m: 1,
            ..VolumeConfig::default()
        },
        32 * 1024 * 1024,
        "rootfs-preflight",
        false,
    )
    .unwrap();
    create_switch_root_dirs(&fs);
    let ids = fs
        .metadata_snapshot()
        .disks
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    fs.mark_disk(&ids[0], DiskStatus::Offline).unwrap();

    let degraded_rw = preflight_report(&fs, RootMountMode::ReadWrite);
    assert!(degraded_rw
        .issues
        .iter()
        .any(|issue| issue.code == "degraded-rootfs-requires-explicit-mode"));
    let degraded_ro = preflight_report(&fs, RootMountMode::DegradedReadOnly);
    assert!(degraded_ro.degraded);
    assert_eq!(degraded_ro.missing_devices, 1);
    assert_eq!(degraded_ro.redundancy, 1);

    fs.mark_disk(&ids[1], DiskStatus::Offline).unwrap();
    let insufficient = preflight_report(&fs, RootMountMode::DegradedReadOnly);
    assert!(insufficient
        .issues
        .iter()
        .any(|issue| issue.code == "insufficient-redundancy"));

    let fresh_dir = tempdir().unwrap();
    let fresh_images = [
        fresh_dir.path().join("disk0.img"),
        fresh_dir.path().join("disk1.img"),
    ];
    let fresh = ArgosFs::create_loop(
        &fresh_images,
        VolumeConfig {
            k: 1,
            m: 1,
            ..VolumeConfig::default()
        },
        32 * 1024 * 1024,
        "rootfs-fresh",
        false,
    )
    .unwrap();
    create_switch_root_dirs(&fresh);
    let unnecessary = preflight_report(&fresh, RootMountMode::DegradedReadWrite);
    assert!(unnecessary
        .issues
        .iter()
        .any(|issue| issue.code == "unnecessary-degraded-rw"));
}

#[test]
fn preflight_report_classifies_invalid_journal_as_rw_error_and_ro_warning() {
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
    create_switch_root_dirs(&fs);
    use std::io::Write as _;
    let mut journal = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.path().join(".argosfs/journal.jsonl"))
        .unwrap();
    writeln!(journal, "not-json").unwrap();
    journal.sync_all().unwrap();

    let rw = preflight_report(&fs, RootMountMode::ReadWrite);
    assert!(rw.invalid_journal_entries > 0);
    assert!(rw
        .issues
        .iter()
        .any(|issue| issue.code == "journal-replay-required"));
    assert!(rw
        .issues
        .iter()
        .any(|issue| issue.code == "transaction-errors-block-rw"));

    let ro = preflight_report(&fs, RootMountMode::ReadOnly);
    assert!(ro
        .issues
        .iter()
        .any(|issue| issue.code == "journal-has-invalid-entries"));
    assert!(ro
        .issues
        .iter()
        .any(|issue| issue.code == "transaction-audit-warning"));
}
