use super::*;
use crate::autopilot::AutopilotMode;
use clap::error::ErrorKind;
use tempfile::TempDir;

#[test]
fn byte_size_parser_accepts_binary_and_decimal_suffixes() {
    assert_eq!(parse_byte_size_u64("64MiB").unwrap(), 64 * 1024 * 1024);
    assert_eq!(parse_byte_size_u64("1_024KiB").unwrap(), 1024 * 1024);
    assert_eq!(parse_byte_size_u64("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
    assert_eq!(parse_byte_size_u64("3GB").unwrap(), 3_000_000_000);
    assert!(parse_byte_size_u64("1.5GiB").is_err());
}

#[test]
fn backend_selector_infers_raw_from_devices() {
    let resolved = commands::BackendArgs {
        devices: vec![PathBuf::from("/dev/test")],
        ..Default::default()
    }
    .resolve(BackendKind::LoopBlock)
    .unwrap();
    assert_eq!(resolved.backend, BackendKind::RawBlock);
    assert!(resolved.images.is_empty());
}

#[test]
fn explicit_backend_rejects_wrong_path_type() {
    let error = commands::BackendArgs {
        backend: Some(BackendKind::LoopBlock),
        devices: vec![PathBuf::from("/dev/test")],
        ..Default::default()
    }
    .resolve(BackendKind::LoopBlock)
    .unwrap_err();
    assert!(error.to_string().contains("loop backend requires --images"));
}

#[test]
fn pool_config_resolves_relative_paths_and_pool_name() {
    let temp = TempDir::new().unwrap();
    let config_dir = temp.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("pool.json");
    fs::write(
        &config_path,
        r#"{"backend":"loop","images":["disk0.img","disk1.img"],"pool":"rootpool"}"#,
    )
    .unwrap();

    let resolved = commands::BackendArgs {
        pool_config: Some(config_path),
        ..Default::default()
    }
    .resolve(BackendKind::Host)
    .unwrap();
    assert_eq!(resolved.backend, BackendKind::LoopBlock);
    assert_eq!(resolved.pool.as_deref(), Some("rootpool"));
    assert_eq!(resolved.images[0], config_dir.join("disk0.img"));
}

#[test]
fn clap_rejects_images_and_devices_together() {
    let error = match Cli::try_parse_from([
        "argosfs",
        "inspect-pool",
        "--images",
        "disk.img",
        "--devices",
        "/dev/test",
    ]) {
        Ok(_) => panic!("conflicting selectors were accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
}

#[test]
fn version_flag_is_available() {
    let error = match Cli::try_parse_from(["argosfs", "--version"]) {
        Ok(_) => panic!("--version unexpectedly parsed as a normal command"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), ErrorKind::DisplayVersion);
    assert!(error.to_string().contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn dry_run_autopilot_summary_shows_decisions() {
    let report = serde_json::json!({
        "dry_run": true,
        "health": {"volume_uuid": "volume-1", "txid": 42},
        "planner": {"adaptive_mode": "safe"},
        "decisions": [{
            "target": "disk-0001",
            "chosen_action": "observe",
            "expected_utility": 0.2,
            "rejected_actions": [{"action": "drain", "reason": "risk below threshold"}]
        }]
    });
    let lines = autopilot_summary_lines(&report);
    assert!(lines[0].contains("volume=volume-1"));
    assert!(lines[0].contains("txid=42"));
    assert!(lines[0].contains("decisions=1"));
    assert!(!lines[0].contains("actions=0"));
    assert!(lines[1].contains("disk-0001: observe"));
    assert!(lines[1].contains("drain rejected: risk below threshold"));
}

#[test]
fn json_flag_is_global() {
    let cli = Cli::try_parse_from(["argosfs", "health", "/tmp/volume", "--json"]).unwrap();
    assert!(cli.json);
}

#[test]
fn backend_path_and_tree_argument_helpers_cover_all_syntaxes() {
    assert!(require_paths(Vec::new(), "missing").is_err());
    assert_eq!(
        require_paths(vec![PathBuf::from("a")], "missing").unwrap(),
        [PathBuf::from("a")]
    );
    assert!(backend_paths(BackendKind::Host, vec![], vec![]).is_err());
    assert!(backend_paths(BackendKind::LoopBlock, vec![], vec![]).is_err());
    assert_eq!(
        backend_paths(
            BackendKind::LoopBlock,
            vec![PathBuf::from("disk.img")],
            vec![]
        )
        .unwrap(),
        [PathBuf::from("disk.img")]
    );
    assert_eq!(
        backend_paths(
            BackendKind::RawBlock,
            vec![],
            vec![PathBuf::from("/dev/test")]
        )
        .unwrap(),
        [PathBuf::from("/dev/test")]
    );

    assert!(import_args(BackendKind::Host, vec![]).is_err());
    assert!(import_args(
        BackendKind::Host,
        vec![
            PathBuf::from("root"),
            PathBuf::from("source"),
            PathBuf::from("dest"),
            PathBuf::from("extra")
        ]
    )
    .is_err());
    assert_eq!(
        import_args(
            BackendKind::Host,
            vec![PathBuf::from("root"), PathBuf::from("source")]
        )
        .unwrap(),
        (
            Some(PathBuf::from("root")),
            PathBuf::from("source"),
            "/".to_string()
        )
    );
    assert_eq!(
        import_args(
            BackendKind::Host,
            vec![
                PathBuf::from("root"),
                PathBuf::from("source"),
                PathBuf::from("/dest")
            ]
        )
        .unwrap()
        .2,
        "/dest"
    );
    assert!(import_args(BackendKind::LoopBlock, vec![]).is_err());
    assert!(import_args(
        BackendKind::RawBlock,
        vec![
            PathBuf::from("source"),
            PathBuf::from("dest"),
            PathBuf::from("extra")
        ]
    )
    .is_err());
    assert_eq!(
        import_args(BackendKind::LoopBlock, vec![PathBuf::from("source")]).unwrap(),
        (None, PathBuf::from("source"), "/".to_string())
    );

    assert!(export_args(BackendKind::Host, vec![]).is_err());
    assert_eq!(
        export_args(
            BackendKind::Host,
            vec![PathBuf::from("root"), PathBuf::from("dest")]
        )
        .unwrap(),
        (Some(PathBuf::from("root")), PathBuf::from("dest"))
    );
    assert!(export_args(
        BackendKind::LoopBlock,
        vec![PathBuf::from("one"), PathBuf::from("two")]
    )
    .is_err());
    assert_eq!(
        export_args(BackendKind::RawBlock, vec![PathBuf::from("dest")]).unwrap(),
        (None, PathBuf::from("dest"))
    );
}

#[test]
fn backend_open_pool_validation_and_root_options_cover_errors_and_defaults() {
    let temp = TempDir::new().unwrap();
    let fs = ArgosFs::create(
        temp.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap();
    validate_requested_pool(&fs, None).unwrap();
    let meta = fs.metadata_snapshot();
    validate_requested_pool(&fs, Some(&meta.uuid)).unwrap();
    validate_requested_pool(&fs, Some(&meta.raw_pool.pool_name)).unwrap();
    assert!(validate_requested_pool(&fs, Some("wrong")).is_err());
    drop(fs);
    assert!(open_backend(None, BackendKind::Host, vec![], vec![], false).is_err());
    assert!(open_backend(None, BackendKind::LoopBlock, vec![], vec![], false).is_err());
    assert!(open_backend(None, BackendKind::RawBlock, vec![], vec![], false).is_err());
    let opened = open_backend(
        Some(temp.path().to_path_buf()),
        BackendKind::Host,
        vec![],
        vec![],
        false,
    )
    .unwrap();
    assert_eq!(opened.root(), temp.path());

    assert_eq!(root_mount_options(vec![]), ["allow_other"]);
    assert_eq!(
        root_mount_options(vec!["allow_root".to_string()]),
        ["allow_root"]
    );
    assert_eq!(
        root_mount_options(vec!["allow_other".to_string(), "ro".to_string()]),
        ["allow_other", "ro"]
    );
}

#[test]
fn policy_passphrase_inline_and_kind_helpers_cover_inputs_and_files() {
    let temp = TempDir::new().unwrap();
    let default = load_autopilot_policy(temp.path(), None).unwrap();
    assert!(matches!(default.mode, AutopilotMode::Safe));
    let policy = temp.path().join("policy.json");
    fs::write(&policy, r#"{"mode":"observe"}"#).unwrap();
    assert!(matches!(
        load_autopilot_policy(temp.path(), Some(&policy))
            .unwrap()
            .mode,
        AutopilotMode::Observe
    ));
    let malformed = temp.path().join("bad.json");
    fs::write(&malformed, "{").unwrap();
    assert!(load_autopilot_policy(temp.path(), Some(&malformed)).is_err());

    assert!(load_passphrase(Some("a".to_string()), Some(policy.clone()), false).is_err());
    assert!(load_passphrase(Some("a".to_string()), None, true).is_err());
    assert_eq!(
        load_passphrase(Some(" visible ".to_string()), None, false).unwrap(),
        " visible "
    );
    let key = temp.path().join("key");
    fs::write(&key, "secret\r\n").unwrap();
    assert_eq!(load_passphrase(None, Some(key), false).unwrap(), "secret");

    assert_eq!(load_inline_or_file("inline").unwrap(), "inline");
    let value_file = temp.path().join("value.txt");
    fs::write(&value_file, "from-file").unwrap();
    assert_eq!(
        load_inline_or_file(&format!("@{}", value_file.display())).unwrap(),
        "from-file"
    );
    assert!(load_inline_or_file("@/definitely/missing").is_err());
    assert_eq!(kind_name(&NodeKind::File), "file");
    assert_eq!(kind_name(&NodeKind::Directory), "dir");
    assert_eq!(kind_name(&NodeKind::Symlink), "symlink");
    assert_eq!(kind_name(&NodeKind::Special), "special");
}

#[test]
fn autopilot_action_summary_and_json_print_helpers_cover_missing_fields() {
    let report = serde_json::json!({
        "health": {},
        "planner": {"stopped_for_conflict": true},
        "actions": [
            {"action": "scrub", "reason": "due"},
            {"error": "failed"},
            {}
        ]
    });
    let lines = autopilot_summary_lines(&report);
    assert!(lines[0].contains("volume=unknown"));
    assert!(lines[0].contains("txid=0"));
    assert!(lines[0].contains("actions=3"));
    assert!(lines[0].contains("stopped_for_conflict=true"));
    assert_eq!(lines[1], "  scrub: due");
    assert_eq!(lines[2], "  unknown: failed");
    assert_eq!(lines[3], "  unknown");
    print_autopilot_report(&report, true).unwrap();
    assert!(structured_json_requested(true));

    let temp = TempDir::new().unwrap();
    let fs = ArgosFs::create(
        temp.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            ..VolumeConfig::default()
        },
        1,
        false,
    )
    .unwrap();
    print_health_report(&fs.health_report(), true, false).unwrap();
    print_fsck_report(
        &FsckReport {
            errors: vec!["example".to_string()],
            ..FsckReport::default()
        },
        true,
    )
    .unwrap();
    print_transaction_report(
        &TransactionReport {
            raw_journal_quorum: Some(true),
            errors: vec!["example".to_string()],
            ..TransactionReport::default()
        },
        true,
    )
    .unwrap();
    print_preflight_report(
        &rootfs::RootPreflightReport {
            ok: false,
            backend: BackendKind::LoopBlock,
            mode: "ro".to_string(),
            total_devices: 2,
            available_devices: 1,
            missing_devices: 1,
            redundancy: 1,
            degraded: true,
            readonly: true,
            can_mount_readonly: true,
            can_mount_readwrite: false,
            recommended_mode: "degraded-ro".to_string(),
            replayed: false,
            invalid_journal_entries: 0,
            issues: vec![rootfs::RootPreflightIssue {
                severity: "warning".to_string(),
                code: "test".to_string(),
                message: "example".to_string(),
            }],
            errors: Vec::new(),
        },
        true,
    )
    .unwrap();
}

#[test]
fn backend_validation_image_sizes_and_numeric_parsers_cover_errors() {
    assert!(validate_root_backend(None, BackendKind::Host).is_err());
    assert!(validate_root_backend(Some(Path::new("root")), BackendKind::LoopBlock).is_err());
    assert!(validate_root_backend(Some(Path::new("root")), BackendKind::RawBlock).is_err());
    validate_root_backend(Some(Path::new("root")), BackendKind::Host).unwrap();
    validate_root_backend(None, BackendKind::LoopBlock).unwrap();
    assert!(reject_option(true, "--test", BackendKind::RawBlock).is_err());
    reject_option(false, "--test", BackendKind::RawBlock).unwrap();
    assert_eq!(
        block_image_size(BackendKind::LoopBlock, Some(123)).unwrap(),
        123
    );
    assert_eq!(
        block_image_size(BackendKind::LoopBlock, None).unwrap(),
        DEFAULT_LOOP_IMAGE_SIZE
    );
    assert!(block_image_size(BackendKind::RawBlock, Some(1)).is_err());
    assert_eq!(block_image_size(BackendKind::RawBlock, None).unwrap(), 0);
    assert!(block_image_size(BackendKind::Host, None).is_err());

    for invalid in [
        "",
        "_",
        "KiB",
        "1XB",
        "18446744073709551616",
        "18446744073709551615TiB",
    ] {
        assert!(parse_byte_size_u64(invalid).is_err(), "{invalid}");
    }
    assert_eq!(parse_byte_size_u64("1_024 B").unwrap(), 1024);
    assert_eq!(parse_byte_size_usize("2KiB").unwrap(), 2048);
    for (raw, expected) in [("0o755", 0o755), ("0x10", 16), ("755", 0o755), ("89", 89)] {
        assert_eq!(parse_u32_auto(raw).unwrap(), expected);
        assert_eq!(parse_u64_auto(raw).unwrap(), expected as u64);
    }
    for invalid in ["0o9", "0xGG", "not-number"] {
        assert!(parse_u32_auto(invalid).is_err());
        assert!(parse_u64_auto(invalid).is_err());
    }
}
