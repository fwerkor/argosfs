use super::*;
use crate::types::{
    CapacitySource, DiskClass, HealthCounters, HealthDiskReport, IoMode, VolumeConfig,
};
use std::collections::BTreeMap;
use tempfile::tempdir;

fn disk(
    id: &str,
    status: DiskStatus,
    used: u64,
    capacity: u64,
    risk: f64,
    predicted_failure: bool,
    io_errors: u64,
) -> HealthDiskReport {
    HealthDiskReport {
        id: id.to_string(),
        status,
        tier: StorageTier::Warm,
        weight: 1.0,
        used_bytes: used,
        capacity_bytes: capacity,
        used_bytes_source: "metadata".to_string(),
        capacity_source: CapacitySource::UserOverride,
        available_bytes: capacity.saturating_sub(used),
        class: DiskClass::Ssd,
        backing_device: None,
        rotational: Some(false),
        numa_node: None,
        read_latency_ewma_ms: 0.0,
        write_latency_ewma_ms: 0.0,
        observed_read_mib_s: 0.0,
        observed_write_mib_s: 0.0,
        risk_score: risk,
        predicted_failure,
        smart_stale: false,
        reasons: Vec::new(),
        health: HealthCounters {
            io_errors,
            ..HealthCounters::default()
        },
    }
}

fn report(disks: Vec<HealthDiskReport>) -> HealthReport {
    HealthReport {
        volume_uuid: "volume".to_string(),
        txid: 1,
        files: 0,
        directories: 1,
        symlinks: 0,
        specials: 0,
        disks,
        cache: BTreeMap::new(),
        io_mode: IoMode::Buffered,
        encryption_enabled: false,
    }
}

#[test]
fn autopilot_defaults_are_conservative_and_versioned() {
    let config = AutopilotConfig::default();
    assert_eq!(config.probe_interval_sec, 3600);
    assert_eq!(config.smart_interval_sec, 600);
    assert_eq!(config.scrub_interval_sec, 300);
    assert_eq!(config.rebalance_interval_sec, 600);
    assert_eq!(config.risk_confirmations, 2);
    assert_eq!(config.scrub_files_per_run, 128);
    assert_eq!(config.rebalance_files_per_run, 32);
    assert_eq!(config.max_drains_per_run, 1);
    assert_eq!(config.foreground_latency_target_ms, 75.0);
    assert_eq!(autopilot_state_version(), 2);
}

#[test]
fn due_calculation_handles_disabled_new_due_and_recent_actions() {
    assert!(!autopilot_due(0.0, u64::MAX, 100.0));
    assert!(autopilot_due(0.0, 60, 100.0));
    assert!(autopilot_due(40.0, 60, 100.0));
    assert!(!autopilot_due(41.0, 60, 100.0));
}

#[test]
fn risk_memory_requires_two_healthy_observations_to_clear_streaks() {
    let mut state = AutopilotState::default();
    let risky = report(vec![disk(
        "disk-a",
        DiskStatus::Online,
        0,
        100,
        0.7,
        true,
        0,
    )]);
    update_autopilot_risk_memory(&mut state, &risky, 10.0);
    update_autopilot_risk_memory(&mut state, &risky, 20.0);
    let disk_state = state.disks.get("disk-a").unwrap();
    assert_eq!(disk_state.risk_streak, 2);
    assert_eq!(disk_state.healthy_streak, 0);
    assert!(disk_state.last_predicted_failure);

    state.disks.get_mut("disk-a").unwrap().next_action_after = 100.0;
    let healthy = report(vec![disk(
        "disk-a",
        DiskStatus::Online,
        0,
        100,
        0.0,
        false,
        0,
    )]);
    update_autopilot_risk_memory(&mut state, &healthy, 30.0);
    assert_eq!(state.disks["disk-a"].risk_streak, 2);
    update_autopilot_risk_memory(&mut state, &healthy, 40.0);
    assert_eq!(state.disks["disk-a"].risk_streak, 0);
    assert_eq!(state.disks["disk-a"].next_action_after, 40.0);
}

#[test]
fn drain_decision_prioritizes_cooldown_critical_and_confirmation() {
    let config = AutopilotConfig::default();
    let risky = disk("disk-a", DiskStatus::Online, 0, 100, 0.9, true, 0);
    let mut state = AutopilotDiskState {
        next_action_after: 20.0,
        ..AutopilotDiskState::default()
    };
    assert_eq!(
        autopilot_drain_decision(&risky, &state, 10.0, &config),
        AutopilotDrainDecision::Cooldown
    );
    state.next_action_after = 0.0;
    assert_eq!(
        autopilot_drain_decision(&risky, &state, 10.0, &config),
        AutopilotDrainDecision::Drain
    );

    let io_risky = disk("disk-a", DiskStatus::Online, 0, 100, 0.1, true, 40);
    assert_eq!(
        autopilot_drain_decision(&io_risky, &state, 10.0, &config),
        AutopilotDrainDecision::Drain
    );

    let moderate = disk("disk-a", DiskStatus::Online, 0, 100, 0.5, true, 0);
    assert_eq!(
        autopilot_drain_decision(&moderate, &state, 10.0, &config),
        AutopilotDrainDecision::Observe
    );
    state.risk_streak = config.risk_confirmations;
    assert_eq!(
        autopilot_drain_decision(&moderate, &state, 10.0, &config),
        AutopilotDrainDecision::Drain
    );
}

#[test]
fn rebalance_skew_handles_empty_single_capacity_and_absolute_usage() {
    assert_eq!(autopilot_rebalance_skew(&report(Vec::new())), 0.0);
    assert_eq!(
        autopilot_rebalance_skew(&report(vec![disk(
            "a",
            DiskStatus::Online,
            50,
            100,
            0.0,
            false,
            0,
        )])),
        0.0
    );
    let balanced = report(vec![
        disk("a", DiskStatus::Online, 50, 100, 0.0, false, 0),
        disk("b", DiskStatus::Online, 100, 200, 0.0, false, 0),
        disk("c", DiskStatus::Offline, 10_000, 1, 0.0, false, 0),
    ]);
    assert_eq!(autopilot_rebalance_skew(&balanced), 2.0 / 3.0);

    let zero_capacity = report(vec![
        disk("a", DiskStatus::Online, 0, 0, 0.0, false, 0),
        disk("b", DiskStatus::Online, 10, 0, 0.0, false, 0),
    ]);
    assert_eq!(autopilot_rebalance_skew(&zero_capacity), 10.0);
}

#[test]
fn adaptive_budget_scales_with_utility_and_respects_zero() {
    assert_eq!(adaptive_autopilot_budget(0, None), 0);
    assert_eq!(adaptive_autopilot_budget(10, None), 10);
    let high = AutopilotActionStats {
        utility_ewma: 4.0,
        ..AutopilotActionStats::default()
    };
    assert_eq!(adaptive_autopilot_budget(10, Some(&high)), 20);
    let low = AutopilotActionStats {
        utility_ewma: -1.0,
        ..AutopilotActionStats::default()
    };
    assert_eq!(adaptive_autopilot_budget(9, Some(&low)), 5);
    let extreme = AutopilotActionStats {
        utility_ewma: 100.0,
        ..AutopilotActionStats::default()
    };
    assert_eq!(
        adaptive_autopilot_budget(usize::MAX, Some(&extreme)),
        usize::MAX
    );
}

#[test]
fn policy_conversion_covers_every_mode() {
    let observe = policy_to_config(&AutopilotPolicy {
        mode: AutopilotMode::Observe,
        max_drains_per_day: 99,
        ..AutopilotPolicy::default()
    });
    assert_eq!(observe.max_drains_per_run, 0);
    assert_eq!(observe.scrub_files_per_run, 0);
    assert_eq!(observe.rebalance_files_per_run, 0);

    let safe = policy_to_config(&AutopilotPolicy::default());
    assert_eq!(safe.scrub_files_per_run, 128);

    let balanced = policy_to_config(&AutopilotPolicy {
        mode: AutopilotMode::Balanced,
        ..AutopilotPolicy::default()
    });
    assert_eq!(balanced.scrub_files_per_run, 256);
    assert_eq!(balanced.rebalance_files_per_run, 64);

    let aggressive = policy_to_config(&AutopilotPolicy {
        mode: AutopilotMode::Aggressive,
        ..AutopilotPolicy::default()
    });
    assert_eq!(aggressive.risk_confirmations, 1);
    assert_eq!(aggressive.scrub_files_per_run, 512);
    assert_eq!(aggressive.rebalance_files_per_run, 128);
    assert_eq!(aggressive.foreground_latency_target_ms, 112.5);

    let runtime = runtime_policy_from_config(&AutopilotConfig {
        max_drains_per_run: 7,
        foreground_latency_target_ms: 44.0,
        ..AutopilotConfig::default()
    });
    assert_eq!(runtime.max_drains_per_day, 7);
    assert_eq!(runtime.background_io.target_foreground_p99_ms, 44.0);
}

#[test]
fn action_statistics_track_counts_totals_and_ewma() {
    let mut state = AutopilotState::default();
    record_autopilot_action(&mut state, "scrub", true, 10.0, 2, 3);
    let stats = &state.action_stats["scrub"];
    assert_eq!(stats.runs, 1);
    assert_eq!(stats.successes, 1);
    assert_eq!(stats.failures, 0);
    assert_eq!(stats.rewritten_files, 2);
    assert_eq!(stats.repaired_files, 3);
    assert_eq!(stats.utility_ewma, 10.0);

    record_autopilot_action(&mut state, "scrub", false, 0.0, 4, 5);
    let stats = &state.action_stats["scrub"];
    assert_eq!(stats.runs, 2);
    assert_eq!(stats.successes, 1);
    assert_eq!(stats.failures, 1);
    assert_eq!(stats.rewritten_files, 6);
    assert_eq!(stats.repaired_files, 8);
    assert!((stats.utility_ewma - 8.5).abs() < f64::EPSILON);
}

#[test]
fn adaptive_mode_reduces_after_repeated_failures() {
    let mut state = AutopilotState::default();
    assert_eq!(adaptive_autopilot_mode(&state), "normal");
    record_autopilot_action(&mut state, "probe", false, -1.0, 0, 0);
    assert_eq!(adaptive_autopilot_mode(&state), "normal");
    record_autopilot_action(&mut state, "smart", false, -1.0, 0, 0);
    assert_eq!(adaptive_autopilot_mode(&state), "reduced");
    record_autopilot_action(&mut state, "scrub", true, 1.0, 0, 0);
    record_autopilot_action(&mut state, "verify", true, 1.0, 0, 0);
    assert_eq!(adaptive_autopilot_mode(&state), "normal");
}

#[test]
fn state_loading_resets_corrupt_files_and_save_round_trips() {
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
    let (fresh, warning) = fs.load_autopilot_state();
    assert_eq!(fresh.version, autopilot_state_version());
    assert!(warning.is_none());

    let mut state = AutopilotState {
        runs: 3,
        ..AutopilotState::default()
    };
    fs.save_autopilot_state(&state).unwrap();
    let (loaded, warning) = fs.load_autopilot_state();
    assert_eq!(loaded.runs, 3);
    assert_eq!(loaded.version, autopilot_state_version());
    assert!(warning.is_none());

    std::fs::write(dir.path().join(".argosfs/autopilot-state.json"), b"{").unwrap();
    let (reset, warning) = fs.load_autopilot_state();
    assert_eq!(reset.runs, 0);
    assert!(warning.is_some());

    state.version = 1;
    fs.save_autopilot_state(&state).unwrap();
    let (upgraded, _) = fs.load_autopilot_state();
    assert_eq!(upgraded.version, autopilot_state_version());
}

fn autopilot_host_volume(disks: usize) -> (tempfile::TempDir, ArgosFs) {
    let dir = tempdir().unwrap();
    let fs = ArgosFs::create(
        dir.path(),
        VolumeConfig {
            k: 1,
            m: 0,
            ..VolumeConfig::default()
        },
        disks,
        false,
    )
    .unwrap();
    (dir, fs)
}

#[test]
fn public_autopilot_wrappers_run_and_reject_invalid_policies() {
    let (_dir, fs) = autopilot_host_volume(2);
    let once = fs.autopilot_once().unwrap();
    assert!(once["actions"].is_array());
    let policy_once = fs
        .autopilot_once_with_policy(AutopilotPolicy {
            mode: AutopilotMode::Observe,
            ..AutopilotPolicy::default()
        })
        .unwrap();
    assert!(policy_once["planner"]["background_io"]["throttle_decisions"].is_array());

    let config = AutopilotConfig {
        probe_interval_sec: u64::MAX,
        smart_interval_sec: u64::MAX,
        scrub_interval_sec: u64::MAX,
        rebalance_interval_sec: u64::MAX,
        ..AutopilotConfig::default()
    };
    assert!(fs.autopilot_once_with_config(config.clone()).is_ok());
    assert!(fs.autopilot_dry_run().unwrap()["decisions"].is_array());
    assert!(fs
        .autopilot_dry_run_with_policy(AutopilotPolicy::default())
        .unwrap()["decisions"]
        .is_array());
    assert!(fs.autopilot_dry_run_with_config(config).unwrap()["decisions"].is_array());

    let invalid = AutopilotPolicy {
        background_io: crate::autopilot::BackgroundIoPolicy {
            target_foreground_p99_ms: 0.0,
            ..Default::default()
        },
        ..AutopilotPolicy::default()
    };
    assert!(fs.autopilot_once_with_policy(invalid.clone()).is_err());
    assert!(fs.autopilot_dry_run_with_policy(invalid).is_err());
}

#[test]
fn autopilot_resets_corrupt_state_and_records_probe_smart_and_paused_actions() {
    let (dir, fs) = autopilot_host_volume(1);
    std::fs::write(dir.path().join(".argosfs/autopilot-state.json"), b"{").unwrap();
    let config = AutopilotConfig {
        probe_interval_sec: 1,
        smart_interval_sec: 1,
        scrub_interval_sec: 1,
        rebalance_interval_sec: 1,
        max_drains_per_run: 0,
        scrub_files_per_run: 0,
        rebalance_files_per_run: 0,
        rebalance_min_skew: 0.0,
        ..AutopilotConfig::default()
    };
    let result = fs
        .autopilot_once_with_config_and_policy(
            config,
            AutopilotPolicy {
                mode: AutopilotMode::Observe,
                ..AutopilotPolicy::default()
            },
        )
        .unwrap();
    let actions = result["actions"].as_array().unwrap();
    assert!(actions
        .iter()
        .any(|action| action["action"] == "autopilot-state-reset"));
    assert!(actions
        .iter()
        .any(|action| { action["action"] == "probe" || action["action"] == "probe-skipped" }));
    assert!(actions.iter().any(|action| {
        action["action"] == "smart-refresh" || action["action"] == "smart-refresh-skipped"
    }));
    assert!(actions
        .iter()
        .any(|action| action["action"] == "background-io-paused"));
    assert!(actions
        .iter()
        .any(|action| action["action"] == "scrub-paused"));
    assert!(actions
        .iter()
        .any(|action| action["action"] == "rebalance-paused"));
    assert!(actions
        .iter()
        .any(|action| action["action"] == "verify-actions"));
}

#[test]
fn dry_run_explains_budget_redundancy_cooldown_and_low_risk_rejections() {
    let (dir, fs) = autopilot_host_volume(2);
    let ids = fs
        .metadata_snapshot()
        .disks
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    fs.set_disk_health(
        &ids[0],
        HealthCounters {
            reallocated_sectors: 500,
            pending_sectors: 10,
            io_errors: 50,
            ..HealthCounters::default()
        },
    )
    .unwrap();

    let observe = fs
        .autopilot_dry_run_with_policy(AutopilotPolicy {
            mode: AutopilotMode::Observe,
            ..AutopilotPolicy::default()
        })
        .unwrap();
    assert!(observe["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|decision| {
            decision["rejected_actions"]
                .as_array()
                .is_some_and(|items| {
                    items.iter().any(|item| {
                        item["reason"]
                            .as_str()
                            .is_some_and(|reason| reason.contains("observe"))
                    })
                })
        }));

    let mut state = AutopilotState::default();
    state.disks.insert(
        ids[0].clone(),
        AutopilotDiskState {
            risk_streak: 10,
            next_action_after: now_f64() + 3600.0,
            ..AutopilotDiskState::default()
        },
    );
    fs.save_autopilot_state(&state).unwrap();
    let cooldown = fs.autopilot_dry_run().unwrap();
    assert!(cooldown["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|decision| {
            decision["rejected_actions"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item["reason"] == "cooldown"))
        }));

    std::fs::remove_file(dir.path().join(".argosfs/autopilot-state.json")).unwrap();
    let low_risk = fs.autopilot_dry_run().unwrap();
    assert!(low_risk["decisions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|decision| {
            decision["rejected_actions"]
                .as_array()
                .is_some_and(|items| {
                    items
                        .iter()
                        .any(|item| item["reason"] == "risk below threshold")
                })
        }));
}
