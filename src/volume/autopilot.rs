use super::*;

#[derive(Clone, Debug)]
pub struct AutopilotConfig {
    pub probe_interval_sec: u64,
    pub smart_interval_sec: u64,
    pub scrub_interval_sec: u64,
    pub rebalance_interval_sec: u64,
    pub drain_cooldown_sec: u64,
    pub failed_action_cooldown_sec: u64,
    pub risk_confirmations: u64,
    pub scrub_files_per_run: usize,
    pub rebalance_files_per_run: usize,
    pub rebalance_min_skew: f64,
    pub critical_risk_score: f64,
    pub max_drains_per_run: usize,
    pub foreground_latency_target_ms: f64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ReshapeReport {
    pub reshape_id: String,
    pub target_layout: String,
    pub target_k: usize,
    pub target_m: usize,
    pub rewritten_files: u64,
    pub remaining_files: u64,
    pub complete: bool,
}

impl Default for AutopilotConfig {
    fn default() -> Self {
        Self {
            probe_interval_sec: 60 * 60,
            smart_interval_sec: 10 * 60,
            scrub_interval_sec: 5 * 60,
            rebalance_interval_sec: 10 * 60,
            drain_cooldown_sec: 30 * 60,
            failed_action_cooldown_sec: 10 * 60,
            risk_confirmations: 2,
            scrub_files_per_run: 128,
            rebalance_files_per_run: 32,
            rebalance_min_skew: 0.08,
            critical_risk_score: 0.85,
            max_drains_per_run: 1,
            foreground_latency_target_ms: 75.0,
        }
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
struct AutopilotState {
    #[serde(default = "autopilot_state_version")]
    version: u32,
    #[serde(default)]
    runs: u64,
    #[serde(default)]
    last_run_at: f64,
    #[serde(default)]
    last_probe_at: f64,
    #[serde(default)]
    last_smart_at: f64,
    #[serde(default)]
    last_scrub_at: f64,
    #[serde(default)]
    last_rebalance_at: f64,
    #[serde(default)]
    scrub_cursor: Option<InodeId>,
    #[serde(default)]
    rebalance_cursor: Option<InodeId>,
    #[serde(default)]
    disks: BTreeMap<String, AutopilotDiskState>,
    #[serde(default)]
    action_stats: BTreeMap<String, AutopilotActionStats>,
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
struct AutopilotDiskState {
    #[serde(default)]
    risk_streak: u64,
    #[serde(default)]
    healthy_streak: u64,
    #[serde(default)]
    last_risk_score: f64,
    #[serde(default)]
    last_predicted_failure: bool,
    #[serde(default)]
    last_drain_attempt_at: f64,
    #[serde(default)]
    next_action_after: f64,
    #[serde(default)]
    last_action: String,
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
struct AutopilotActionStats {
    #[serde(default)]
    runs: u64,
    #[serde(default)]
    successes: u64,
    #[serde(default)]
    failures: u64,
    #[serde(default)]
    rewritten_files: u64,
    #[serde(default)]
    repaired_files: u64,
    #[serde(default)]
    utility_ewma: f64,
}

fn autopilot_state_version() -> u32 {
    2
}

impl ArgosFs {
    pub fn autopilot_once(&self) -> Result<serde_json::Value> {
        self.autopilot_once_with_config(AutopilotConfig::default())
    }

    pub fn autopilot_once_with_policy(&self, policy: AutopilotPolicy) -> Result<serde_json::Value> {
        self.autopilot_once_with_config_and_policy(policy_to_config(&policy), policy)
    }

    pub fn autopilot_once_with_config(&self, config: AutopilotConfig) -> Result<serde_json::Value> {
        let policy = runtime_policy_from_config(&config);
        self.autopilot_once_with_config_and_policy(config, policy)
    }

    pub fn autopilot_once_with_config_and_policy(
        &self,
        config: AutopilotConfig,
        policy: AutopilotPolicy,
    ) -> Result<serde_json::Value> {
        policy.validate()?;
        let now = now_f64();
        let (mut state, state_warning) = self.load_autopilot_state();
        state.version = autopilot_state_version();
        state.runs = state.runs.saturating_add(1);
        state.last_run_at = now;

        let mut actions = Vec::new();
        let mut throttle_decisions = Vec::new();
        let mut stop_mutations = false;
        if let Some(warning) = state_warning {
            actions.push(json!({"action": "autopilot-state-reset", "error": warning}));
        }

        if autopilot_due(state.last_probe_at, config.probe_interval_sec, now) {
            match self.refresh_disk_probe_observations(None) {
                Ok(probes) => {
                    state.last_probe_at = now;
                    record_autopilot_action(&mut state, "probe", true, 0.2, 0, 0);
                    actions.push(
                        json!({"action": "probe", "disks": probes.len(), "mode": "observe-only"}),
                    );
                }
                Err(err) => {
                    stop_mutations |= matches!(err, ArgosError::Conflict(_));
                    record_autopilot_action(&mut state, "probe", false, -1.0, 0, 0);
                    actions.push(json!({"action": "probe-skipped", "error": err.to_string()}));
                }
            }
        }

        if !stop_mutations && autopilot_due(state.last_smart_at, config.smart_interval_sec, now) {
            match self.refresh_smart_health(None) {
                Ok(updates) => {
                    state.last_smart_at = now;
                    record_autopilot_action(&mut state, "smart", true, updates.len() as f64, 0, 0);
                    actions
                        .push(json!({"action": "smart-refresh", "updated_disks": updates.len()}));
                }
                Err(err) => {
                    stop_mutations |= matches!(err, ArgosError::Conflict(_));
                    record_autopilot_action(&mut state, "smart", false, -0.2, 0, 0);
                    actions
                        .push(json!({"action": "smart-refresh-skipped", "error": err.to_string()}));
                }
            }
        }

        let mut report = self.health_report();
        update_autopilot_risk_memory(&mut state, &report, now);

        if !stop_mutations {
            let drain_throttle = plan_background_io(
                "drain",
                "disks",
                config.max_drains_per_run,
                &report,
                &policy,
            );
            let drain_budget = drain_throttle.effective_budget;
            if drain_budget == 0 {
                actions.push(json!({
                    "action": "background-io-paused",
                    "scope": "drain",
                    "reason": drain_throttle.pause_reason.clone().unwrap_or_else(|| "background I/O policy budget is zero".to_string())
                }));
            }
            throttle_decisions.push(json!(drain_throttle));
            let mut drains = 0usize;
            for disk in report
                .disks
                .iter()
                .filter(|disk| disk.predicted_failure && disk.status == DiskStatus::Online)
            {
                let decision = state
                    .disks
                    .get(&disk.id)
                    .map(|disk_state| autopilot_drain_decision(disk, disk_state, now, &config))
                    .unwrap_or(AutopilotDrainDecision::Observe);
                match decision {
                    AutopilotDrainDecision::Drain if drains < drain_budget => {
                        drains += 1;
                        if let Some(disk_state) = state.disks.get_mut(&disk.id) {
                            disk_state.last_drain_attempt_at = now;
                        }
                        match self.drain_disk(&disk.id) {
                            Ok(rewritten) => match self.mark_disk(&disk.id, DiskStatus::Degraded) {
                                Ok(()) => {
                                    if let Some(disk_state) = state.disks.get_mut(&disk.id) {
                                        disk_state.next_action_after =
                                            now + config.drain_cooldown_sec as f64;
                                        disk_state.last_action = "drained".to_string();
                                    }
                                    record_autopilot_action(
                                        &mut state,
                                        "drain",
                                        true,
                                        4.0 + disk.risk_score * 6.0,
                                        rewritten,
                                        0,
                                    );
                                    actions.push(json!({"action": "drain-predicted-failure", "disk_id": disk.id, "rewritten_files": rewritten, "risk": disk.risk_score, "confirmations": state.disks.get(&disk.id).map(|disk| disk.risk_streak).unwrap_or_default()}));
                                }
                                Err(err) => {
                                    stop_mutations |= matches!(err, ArgosError::Conflict(_));
                                    record_autopilot_action(
                                        &mut state, "drain", false, -2.0, rewritten, 0,
                                    );
                                    actions.push(json!({"action": "drain-mark-degraded-failed", "disk_id": disk.id, "rewritten_files": rewritten, "error": err.to_string()}));
                                }
                            },
                            Err(err) => {
                                if let Some(disk_state) = state.disks.get_mut(&disk.id) {
                                    disk_state.next_action_after =
                                        now + config.failed_action_cooldown_sec as f64;
                                    disk_state.last_action = "drain-deferred".to_string();
                                }
                                stop_mutations |= matches!(err, ArgosError::Conflict(_));
                                record_autopilot_action(&mut state, "drain", false, -1.5, 0, 0);
                                actions.push(json!({"action": "skip-drain-predicted-failure", "disk_id": disk.id, "risk": disk.risk_score, "error": err.to_string()}));
                            }
                        }
                    }
                    AutopilotDrainDecision::Drain => {
                        actions.push(json!({"action": "defer-drain-budget", "disk_id": disk.id, "risk": disk.risk_score}));
                    }
                    AutopilotDrainDecision::Cooldown => {
                        actions.push(json!({"action": "defer-drain-cooldown", "disk_id": disk.id, "risk": disk.risk_score}));
                    }
                    AutopilotDrainDecision::Observe => {
                        actions.push(json!({"action": "observe-predicted-failure", "disk_id": disk.id, "risk": disk.risk_score, "confirmations": state.disks.get(&disk.id).map(|disk| disk.risk_streak).unwrap_or_default()}));
                    }
                }
            }
            if drains > 0 {
                report = self.health_report();
            }
        }

        if !stop_mutations && autopilot_due(state.last_scrub_at, config.scrub_interval_sec, now) {
            let scrub_throttle = plan_background_io(
                "scrub",
                "files",
                config.scrub_files_per_run,
                &report,
                &policy,
            );
            let scrub_budget = scrub_throttle.effective_budget;
            let scrub_pause_reason = scrub_throttle.pause_reason.clone();
            throttle_decisions.push(json!(scrub_throttle));
            if scrub_budget > 0 {
                let (fsck, cursor) = self.scrub_limited(scrub_budget, state.scrub_cursor);
                let repaired = fsck.repaired_files;
                let utility = fsck.repaired_files as f64 * 3.0
                    - fsck.unrecoverable_files as f64 * 5.0
                    - fsck.errors.len() as f64;
                state.scrub_cursor = cursor;
                state.last_scrub_at = now;
                record_autopilot_action(
                    &mut state,
                    "scrub",
                    fsck.errors.is_empty(),
                    utility,
                    0,
                    repaired,
                );
                actions.push(json!({"action": "scrub-incremental", "budget_files": scrub_budget, "requested_budget_files": config.scrub_files_per_run, "cursor": state.scrub_cursor, "report": fsck}));
            } else {
                actions.push(json!({
                    "action": "scrub-paused",
                    "reason": scrub_pause_reason.unwrap_or_else(|| "background I/O policy budget is zero".to_string())
                }));
            }
        }

        let skew = autopilot_rebalance_skew(&report);
        if !stop_mutations
            && autopilot_due(state.last_rebalance_at, config.rebalance_interval_sec, now)
            && skew >= config.rebalance_min_skew
        {
            let requested_budget = adaptive_autopilot_budget(
                config.rebalance_files_per_run,
                state.action_stats.get("rebalance"),
            );
            let rebalance_throttle =
                plan_background_io("rebalance", "files", requested_budget, &report, &policy);
            let budget = rebalance_throttle.effective_budget;
            let rebalance_pause_reason = rebalance_throttle.pause_reason.clone();
            throttle_decisions.push(json!(rebalance_throttle));
            if budget > 0 {
                match self.rebalance_limited(budget, state.rebalance_cursor) {
                    Ok((rewritten, cursor)) => {
                        state.rebalance_cursor = cursor;
                        state.last_rebalance_at = now;
                        record_autopilot_action(
                            &mut state,
                            "rebalance",
                            true,
                            skew * 10.0 - rewritten as f64 * 0.02,
                            rewritten,
                            0,
                        );
                        actions.push(json!({"action": "rebalance-incremental", "budget_files": budget, "requested_budget_files": config.rebalance_files_per_run, "rewritten_files": rewritten, "cursor": state.rebalance_cursor, "skew": skew}));
                    }
                    Err(err) => {
                        stop_mutations |= matches!(err, ArgosError::Conflict(_));
                        state.last_rebalance_at = now;
                        record_autopilot_action(&mut state, "rebalance", false, -2.0, 0, 0);
                        actions.push(json!({"action": "rebalance-skipped", "budget_files": budget, "skew": skew, "error": err.to_string()}));
                    }
                }
            } else {
                actions.push(json!({
                    "action": "rebalance-paused",
                    "skew": skew,
                    "reason": rebalance_pause_reason.unwrap_or_else(|| "background I/O policy budget is zero".to_string())
                }));
            }
        } else if !stop_mutations {
            actions.push(json!({"action": "rebalance-not-needed", "skew": skew, "threshold": config.rebalance_min_skew}));
        }

        let verification = self.fsck(false, false);
        match &verification {
            Ok(report) if report.errors.is_empty() && report.unrecoverable_files == 0 => {
                actions.push(json!({"action": "verify-actions", "result": "ok"}));
            }
            Ok(report) => {
                actions.push(
                    json!({"action": "verify-actions", "result": "failed", "report": report}),
                );
                record_autopilot_action(&mut state, "verify", false, -4.0, 0, 0);
            }
            Err(err) => {
                actions.push(json!({"action": "verify-actions", "result": "error", "error": err.to_string()}));
                record_autopilot_action(&mut state, "verify", false, -4.0, 0, 0);
            }
        }
        let health = self.health_report();
        let adaptive_mode = adaptive_autopilot_mode(&state);
        let result = json!({
            "actions": actions.clone(),
            "health": health,
            "policy": policy,
            "planner": {
                "state_version": state.version,
                "runs": state.runs,
                "adaptive_mode": adaptive_mode,
                "scrub_cursor": state.scrub_cursor,
                "rebalance_cursor": state.rebalance_cursor,
                "stopped_for_conflict": stop_mutations,
                "background_io": {
                    "throttle_decisions": throttle_decisions
                }
            }
        });
        self.save_autopilot_state(&state)?;
        append_json_line(&self.root.join(".argosfs/autopilot.jsonl"), &result)?;
        let meta = self.meta.read();
        self.journal_locked(&meta, "autopilot", json!({"actions": actions}))?;
        Ok(result)
    }

    pub fn autopilot_dry_run(&self) -> Result<serde_json::Value> {
        self.autopilot_dry_run_with_config(AutopilotConfig::default())
    }

    pub fn autopilot_dry_run_with_policy(
        &self,
        policy: AutopilotPolicy,
    ) -> Result<serde_json::Value> {
        self.autopilot_dry_run_with_config_and_policy(policy_to_config(&policy), policy)
    }

    pub fn autopilot_dry_run_with_config(
        &self,
        config: AutopilotConfig,
    ) -> Result<serde_json::Value> {
        let policy = runtime_policy_from_config(&config);
        self.autopilot_dry_run_with_config_and_policy(config, policy)
    }

    pub fn autopilot_dry_run_with_config_and_policy(
        &self,
        config: AutopilotConfig,
        policy: AutopilotPolicy,
    ) -> Result<serde_json::Value> {
        policy.validate()?;
        let now = now_f64();
        let (mut state, state_warning) = self.load_autopilot_state();
        let report = self.health_report();
        update_autopilot_risk_memory(&mut state, &report, now);
        let drain_throttle = plan_background_io(
            "drain",
            "disks",
            config.max_drains_per_run,
            &report,
            &policy,
        );
        let scrub_throttle = plan_background_io(
            "scrub",
            "files",
            config.scrub_files_per_run,
            &report,
            &policy,
        );
        let online = report
            .disks
            .iter()
            .filter(|disk| disk.status == DiskStatus::Online)
            .count();
        let required_after_drain = {
            let meta = self.meta.read();
            max_layout_total(&meta)?
        };
        let mut decisions = Vec::new();
        for disk in &report.disks {
            let disk_state = state.disks.get(&disk.id).cloned().unwrap_or_default();
            let drain_decision = autopilot_drain_decision(disk, &disk_state, now, &config);
            let enough_online_disks = online.saturating_sub(1) >= required_after_drain;
            let chosen_action = if disk.predicted_failure
                && disk.status == DiskStatus::Online
                && enough_online_disks
                && drain_decision == AutopilotDrainDecision::Drain
                && drain_throttle.effective_budget > 0
            {
                "drain"
            } else {
                "observe"
            };
            let rejected_actions = if drain_throttle.effective_budget == 0 {
                vec![
                    json!({"action": "drain", "reason": drain_throttle.pause_reason.clone().unwrap_or_else(|| "background I/O policy budget is zero".to_string())}),
                ]
            } else if !enough_online_disks {
                vec![json!({"action": "drain", "reason": "not enough online disks after drain"})]
            } else if drain_decision == AutopilotDrainDecision::Cooldown {
                vec![json!({"action": "drain", "reason": "cooldown"})]
            } else if !disk.predicted_failure {
                vec![json!({"action": "drain", "reason": "risk below threshold"})]
            } else {
                Vec::new()
            };
            decisions.push(json!({
                "target": disk.id,
                "chosen_action": chosen_action,
                "candidates": [
                    {"action": "observe", "score": 0.2},
                    {"action": "drain", "score": if disk.predicted_failure { 4.0 + disk.risk_score * 6.0 } else { -1.0 }}
                ],
                "rejected_actions": rejected_actions,
                "safety_checks": {
                    "enough_online_disks": enough_online_disks,
                    "metadata_conflict": false,
                    "boot_critical_safe": enough_online_disks
                },
                "expected_utility": if chosen_action == "drain" { 4.0 + disk.risk_score * 6.0 } else { 0.2 },
                "observations": {
                    "risk_score": disk.risk_score,
                    "predicted_failure": disk.predicted_failure,
                    "smart_fields_observed": disk.health.smart_fields_observed.clone(),
                    "smart_fields_missing": disk.health.smart_fields_missing.clone(),
                    "smart_stale": disk.smart_stale
                }
            }));
        }
        let skew = autopilot_rebalance_skew(&report);
        let requested_rebalance_budget = adaptive_autopilot_budget(
            config.rebalance_files_per_run,
            state.action_stats.get("rebalance"),
        );
        let rebalance_throttle = plan_background_io(
            "rebalance",
            "files",
            requested_rebalance_budget,
            &report,
            &policy,
        );
        let rebalance_budget = rebalance_throttle.effective_budget;
        Ok(json!({
            "dry_run": true,
            "mutated": false,
            "state_warning": state_warning,
            "decisions": decisions,
            "policy": policy,
            "planner": {
                "state_version": autopilot_state_version(),
                "adaptive_mode": adaptive_autopilot_mode(&state),
                "rebalance": {
                    "skew": skew,
                    "threshold": config.rebalance_min_skew,
                    "would_run": skew >= config.rebalance_min_skew && rebalance_budget > 0,
                    "budget_files": rebalance_budget
                },
                "background_io": {
                    "throttle_decisions": [
                        drain_throttle,
                        scrub_throttle,
                        rebalance_throttle
                    ]
                }
            },
            "health": report
        }))
    }

    fn load_autopilot_state(&self) -> (AutopilotState, Option<String>) {
        let path = self.root.join(".argosfs/autopilot-state.json");
        if !path.exists() {
            let state = AutopilotState {
                version: autopilot_state_version(),
                ..AutopilotState::default()
            };
            return (state, None);
        }
        match fs::read(&path).map_err(ArgosError::Io).and_then(|bytes| {
            serde_json::from_slice::<AutopilotState>(&bytes).map_err(ArgosError::Json)
        }) {
            Ok(mut state) => {
                state.version = autopilot_state_version();
                (state, None)
            }
            Err(err) => {
                let state = AutopilotState {
                    version: autopilot_state_version(),
                    ..AutopilotState::default()
                };
                (state, Some(err.to_string()))
            }
        }
    }

    fn save_autopilot_state(&self, state: &AutopilotState) -> Result<()> {
        atomic_write(
            &self.root.join(".argosfs/autopilot-state.json"),
            serde_json::to_vec_pretty(state)?.as_slice(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AutopilotDrainDecision {
    Observe,
    Cooldown,
    Drain,
}

fn autopilot_due(last_at: f64, interval_sec: u64, now: f64) -> bool {
    interval_sec != u64::MAX && (last_at <= 0.0 || now - last_at >= interval_sec as f64)
}

fn update_autopilot_risk_memory(state: &mut AutopilotState, report: &HealthReport, now: f64) {
    for disk in &report.disks {
        let disk_state = state.disks.entry(disk.id.clone()).or_default();
        if disk.predicted_failure {
            disk_state.risk_streak = disk_state.risk_streak.saturating_add(1);
            disk_state.healthy_streak = 0;
        } else {
            disk_state.healthy_streak = disk_state.healthy_streak.saturating_add(1);
            if disk_state.healthy_streak >= 2 {
                disk_state.risk_streak = 0;
                disk_state.next_action_after = disk_state.next_action_after.min(now);
            }
        }
        disk_state.last_risk_score = disk.risk_score;
        disk_state.last_predicted_failure = disk.predicted_failure;
    }
}

fn autopilot_drain_decision(
    disk: &HealthDiskReport,
    state: &AutopilotDiskState,
    now: f64,
    config: &AutopilotConfig,
) -> AutopilotDrainDecision {
    if now < state.next_action_after {
        return AutopilotDrainDecision::Cooldown;
    }
    let critical = disk.risk_score >= config.critical_risk_score || disk.health.io_errors >= 40;
    let confirmed = state.risk_streak >= config.risk_confirmations;
    if critical || confirmed {
        AutopilotDrainDecision::Drain
    } else {
        AutopilotDrainDecision::Observe
    }
}

fn autopilot_rebalance_skew(report: &HealthReport) -> f64 {
    let mut min_ratio = f64::INFINITY;
    let mut max_ratio = 0.0f64;
    let mut min_used = u64::MAX;
    let mut max_used = 0u64;
    let mut total_used = 0u64;
    let mut count = 0usize;
    for disk in report
        .disks
        .iter()
        .filter(|disk| disk.status == DiskStatus::Online)
    {
        let ratio = if disk.capacity_bytes > 0 {
            disk.used_bytes as f64 / disk.capacity_bytes as f64
        } else {
            disk.used_bytes as f64
        };
        min_ratio = min_ratio.min(ratio);
        max_ratio = max_ratio.max(ratio);
        min_used = min_used.min(disk.used_bytes);
        max_used = max_used.max(disk.used_bytes);
        total_used = total_used.saturating_add(disk.used_bytes);
        count += 1;
    }
    if count < 2 || !min_ratio.is_finite() {
        0.0
    } else {
        let capacity_ratio_skew = max_ratio - min_ratio;
        let avg_used = total_used as f64 / count as f64;
        let relative_used_skew = if avg_used > 0.0 {
            (max_used.saturating_sub(min_used) as f64 / avg_used).min(1.0)
        } else {
            0.0
        };
        capacity_ratio_skew.max(relative_used_skew)
    }
}

fn adaptive_autopilot_budget(base: usize, stats: Option<&AutopilotActionStats>) -> usize {
    if base == 0 {
        return 0;
    }
    let multiplier = match stats.map(|stats| stats.utility_ewma) {
        Some(utility) if utility > 3.0 => 2.0,
        Some(utility) if utility < -0.5 => 0.5,
        _ => 1.0,
    };
    ((base as f64 * multiplier).round() as usize).clamp(1, base.saturating_mul(4).max(1))
}

fn policy_to_config(policy: &AutopilotPolicy) -> AutopilotConfig {
    let mut config = AutopilotConfig {
        max_drains_per_run: policy.max_drains_per_day.min(usize::MAX as u64) as usize,
        foreground_latency_target_ms: policy.background_io.target_foreground_p99_ms,
        ..AutopilotConfig::default()
    };
    match policy.mode {
        AutopilotMode::Observe => {
            config.max_drains_per_run = 0;
            config.scrub_files_per_run = 0;
            config.rebalance_files_per_run = 0;
        }
        AutopilotMode::Safe => {}
        AutopilotMode::Balanced => {
            config.scrub_files_per_run = config.scrub_files_per_run.saturating_mul(2);
            config.rebalance_files_per_run = config.rebalance_files_per_run.saturating_mul(2);
        }
        AutopilotMode::Aggressive => {
            config.risk_confirmations = 1;
            config.scrub_files_per_run = config.scrub_files_per_run.saturating_mul(4);
            config.rebalance_files_per_run = config.rebalance_files_per_run.saturating_mul(4);
            config.foreground_latency_target_ms *= 1.5;
        }
    }
    config
}

fn runtime_policy_from_config(config: &AutopilotConfig) -> AutopilotPolicy {
    AutopilotPolicy {
        max_drains_per_day: config.max_drains_per_run as u64,
        background_io: BackgroundIoPolicy {
            target_foreground_p99_ms: config.foreground_latency_target_ms,
            ..BackgroundIoPolicy::default()
        },
        ..AutopilotPolicy::default()
    }
}

fn adaptive_autopilot_mode(state: &AutopilotState) -> &'static str {
    let failures: u64 = state
        .action_stats
        .values()
        .map(|stats| stats.failures)
        .sum();
    let successes: u64 = state
        .action_stats
        .values()
        .map(|stats| stats.successes)
        .sum();
    if failures > successes && failures >= 2 {
        "reduced"
    } else {
        "normal"
    }
}

fn record_autopilot_action(
    state: &mut AutopilotState,
    action: &str,
    success: bool,
    utility: f64,
    rewritten_files: u64,
    repaired_files: u64,
) {
    let stats = state.action_stats.entry(action.to_string()).or_default();
    stats.runs = stats.runs.saturating_add(1);
    if success {
        stats.successes = stats.successes.saturating_add(1);
    } else {
        stats.failures = stats.failures.saturating_add(1);
    }
    stats.rewritten_files = stats.rewritten_files.saturating_add(rewritten_files);
    stats.repaired_files = stats.repaired_files.saturating_add(repaired_files);
    stats.utility_ewma = if stats.runs == 1 {
        utility
    } else {
        stats.utility_ewma * 0.85 + utility * 0.15
    };
}
