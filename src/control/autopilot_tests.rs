use super::*;

fn health_report(latency: f64, read_rate: f64, write_rate: f64) -> HealthReport {
    use crate::types::{
        CapacitySource, DiskClass, DiskStatus, HealthCounters, HealthDiskReport, IoMode,
    };
    use std::collections::BTreeMap;

    HealthReport {
        volume_uuid: "volume".to_string(),
        txid: 1,
        files: 1,
        directories: 1,
        symlinks: 0,
        specials: 0,
        disks: vec![HealthDiskReport {
            id: "disk-0000".to_string(),
            status: DiskStatus::Online,
            tier: StorageTier::Warm,
            weight: 1.0,
            used_bytes: 0,
            capacity_bytes: 1,
            used_bytes_source: "metadata".to_string(),
            capacity_source: CapacitySource::UserOverride,
            available_bytes: 1,
            class: DiskClass::Ssd,
            backing_device: None,
            rotational: Some(false),
            numa_node: None,
            read_latency_ewma_ms: latency,
            write_latency_ewma_ms: latency / 2.0,
            observed_read_mib_s: read_rate,
            observed_write_mib_s: write_rate,
            risk_score: 0.0,
            predicted_failure: false,
            smart_stale: false,
            reasons: Vec::new(),
            health: HealthCounters {
                latency_ms: latency / 4.0,
                ..HealthCounters::default()
            },
        }],
        cache: BTreeMap::new(),
        io_mode: IoMode::Buffered,
        encryption_enabled: false,
    }
}

#[test]
fn defaults_and_policy_paths_are_stable() {
    let policy = AutopilotPolicy::default();
    assert!(matches!(policy.mode, AutopilotMode::Safe));
    assert_eq!(policy.max_drains_per_day, 1);
    assert_eq!(policy.background_io.target_foreground_p99_ms, 75.0);
    assert_eq!(
        AutopilotPolicy::default_path(Path::new("/volume")),
        Path::new("/volume/.argosfs/autopilot-policy.json")
    );
    validate_policy_path("/boot/kernel").unwrap();
    validate_policy_path("/").unwrap();
    assert!(validate_policy_path("relative/path").is_err());
    assert!(validate_policy_path("/boot/../etc").is_err());
}

#[test]
fn loading_optional_policies_handles_missing_valid_and_invalid_files() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.json");
    assert!(AutopilotPolicy::load_optional_json(&missing)
        .unwrap()
        .is_none());

    let valid = dir.path().join("valid.json");
    fs::write(
        &valid,
        r#"{"mode":"balanced","max_drains_per_day":2,"paths":{"boot_critical":["/boot"]}}"#,
    )
    .unwrap();
    let loaded = AutopilotPolicy::load_json(&valid).unwrap();
    assert!(matches!(loaded.mode, AutopilotMode::Balanced));
    assert_eq!(loaded.max_drains_per_day, 2);
    assert!(AutopilotPolicy::load_optional_json(&valid)
        .unwrap()
        .is_some());

    let malformed = dir.path().join("malformed.json");
    fs::write(&malformed, "{").unwrap();
    assert!(matches!(
        AutopilotPolicy::load_json(&malformed),
        Err(ArgosError::Invalid(_))
    ));
    assert!(matches!(
        AutopilotPolicy::load_json(&dir.path().join("absent.json")),
        Err(ArgosError::Io(_))
    ));
}

#[test]
fn validation_rejects_all_nonfinite_thresholds_and_zero_copies() {
    for value in [f64::NAN, f64::INFINITY, -1.0] {
        let mut policy = AutopilotPolicy::default();
        policy.background_io.max_write_mib_s = Some(value);
        assert!(policy.validate().is_err());
    }
    for value in [0.0, -1.0, f64::INFINITY, f64::NAN] {
        let mut policy = AutopilotPolicy::default();
        policy.background_io.target_foreground_p99_ms = value;
        assert!(policy.validate().is_err());

        let mut policy = AutopilotPolicy::default();
        policy.background_io.pause_if_foreground_p99_ms = Some(value);
        assert!(policy.validate().is_err());

        let mut policy = AutopilotPolicy::default();
        policy.background_io.pause_if_loadavg_gt = Some(value);
        assert!(policy.validate().is_err());
    }
    let mut policy = AutopilotPolicy::default();
    policy.placement.min_boot_copies = Some(0);
    assert!(policy.validate().is_err());
}

#[test]
fn observe_and_aggressive_modes_keep_their_distinct_budget_behavior() {
    let report = health_report(200.0, 10.0, 20.0);
    let mut policy = AutopilotPolicy {
        mode: AutopilotMode::Observe,
        ..AutopilotPolicy::default()
    };
    let observe = plan_background_io("scrub", "files", 8, &report, &policy);
    assert_eq!(observe.effective_budget, 0);
    assert_eq!(
        observe.pause_reason.as_deref(),
        Some("policy mode is observe")
    );
    assert_eq!(observe.observed_read_mib_s, 10.0);
    assert_eq!(observe.observed_write_mib_s, 20.0);

    policy.mode = AutopilotMode::Aggressive;
    let aggressive = plan_background_io("unknown", "files", 8, &report, &policy);
    assert_eq!(aggressive.effective_budget, 8);
    assert!(aggressive.pause_reason.is_none());
    assert!(aggressive.notes.is_empty());
}

#[test]
fn safe_mode_reduces_budget_for_latency_and_rate_caps() {
    let report = health_report(200.0, 30.0, 40.0);
    let mut policy = AutopilotPolicy::default();
    policy.background_io.max_read_mib_s = Some(3.9);
    policy.background_io.max_write_mib_s = Some(2.9);
    let scrub = plan_background_io("scrub", "files", 10, &report, &policy);
    assert_eq!(scrub.effective_budget, 1);
    assert!(scrub.notes.iter().any(|note| note.contains("2x target")));
    assert!(scrub.notes.iter().any(|note| note.contains("capped")));

    let rebalance = plan_background_io("rebalance", "files", 10, &report, &policy);
    assert_eq!(rebalance.effective_budget, 1);
    assert_eq!(action_rate_limit_mib_s("rebalance", &policy), Some(2.9));
    assert_eq!(action_rate_limit_mib_s("drain", &policy), Some(2.9));
    assert_eq!(action_rate_limit_mib_s("repair", &policy), Some(3.9));
    assert_eq!(action_rate_limit_mib_s("other", &policy), None);
}

#[test]
fn balanced_mode_halves_budget_and_pause_threshold_overrides_it() {
    let report = health_report(100.0, 0.0, 0.0);
    let mut policy = AutopilotPolicy {
        mode: AutopilotMode::Balanced,
        ..AutopilotPolicy::default()
    };
    let halved = plan_background_io("scrub", "files", 9, &report, &policy);
    assert_eq!(halved.effective_budget, 4);
    assert!(halved.notes.iter().any(|note| note.contains("halved")));

    policy.background_io.pause_if_foreground_p99_ms = Some(90.0);
    let paused = plan_background_io("scrub", "files", 9, &report, &policy);
    assert_eq!(paused.effective_budget, 0);
    assert!(paused
        .pause_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("pause threshold")));
}

#[test]
fn rate_limit_selection_handles_one_sided_and_missing_limits() {
    let mut policy = AutopilotPolicy::default();
    assert_eq!(action_rate_limit_mib_s("rebalance", &policy), None);
    policy.background_io.max_read_mib_s = Some(5.0);
    assert_eq!(action_rate_limit_mib_s("rebalance", &policy), Some(5.0));
    policy.background_io.max_read_mib_s = None;
    policy.background_io.max_write_mib_s = Some(4.0);
    assert_eq!(action_rate_limit_mib_s("drain", &policy), Some(4.0));
    assert!(read_loadavg_1m().is_some());
}

#[test]
fn rejects_unsafe_policy_values() {
    let mut policy = AutopilotPolicy::default();
    policy.background_io.max_read_mib_s = Some(f64::NAN);
    assert!(policy.validate().is_err());

    let mut policy = AutopilotPolicy::default();
    policy.paths.boot_critical.push("../boot".to_string());
    assert!(policy.validate().is_err());
}
