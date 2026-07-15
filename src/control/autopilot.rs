use crate::error::{ArgosError, Result};
use crate::types::{HealthReport, StorageTier};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use std::{fs, io};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AutopilotMode {
    Observe,
    #[default]
    Safe,
    Balanced,
    Aggressive,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AutopilotPolicy {
    #[serde(default)]
    pub mode: AutopilotMode,
    #[serde(default = "default_max_drains_per_day")]
    pub max_drains_per_day: u64,
    #[serde(default)]
    pub allow_degraded_boot: bool,
    #[serde(default)]
    pub background_io: BackgroundIoPolicy,
    #[serde(default)]
    pub placement: PlacementPolicy,
    #[serde(default)]
    pub paths: PathPolicy,
}

impl Default for AutopilotPolicy {
    fn default() -> Self {
        Self {
            mode: AutopilotMode::Safe,
            max_drains_per_day: default_max_drains_per_day(),
            allow_degraded_boot: false,
            background_io: BackgroundIoPolicy::default(),
            placement: PlacementPolicy::default(),
            paths: PathPolicy::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackgroundIoPolicy {
    #[serde(default)]
    pub max_read_mib_s: Option<f64>,
    #[serde(default)]
    pub max_write_mib_s: Option<f64>,
    #[serde(default = "default_foreground_latency_target_ms")]
    pub target_foreground_p99_ms: f64,
    #[serde(default)]
    pub pause_if_foreground_p99_ms: Option<f64>,
    #[serde(default)]
    pub pause_if_loadavg_gt: Option<f64>,
}

impl Default for BackgroundIoPolicy {
    fn default() -> Self {
        Self {
            max_read_mib_s: None,
            max_write_mib_s: None,
            target_foreground_p99_ms: default_foreground_latency_target_ms(),
            pause_if_foreground_p99_ms: None,
            pause_if_loadavg_gt: None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PlacementPolicy {
    #[serde(default)]
    pub boot_critical_tier: Option<StorageTier>,
    #[serde(default)]
    pub min_boot_copies: Option<usize>,
    #[serde(default)]
    pub failure_domain_aware: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PathPolicy {
    #[serde(default)]
    pub boot_critical: Vec<String>,
    #[serde(default)]
    pub cold_candidates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackgroundThrottleDecision {
    pub action: String,
    pub budget_unit: String,
    pub requested_budget: usize,
    pub effective_budget: usize,
    pub max_foreground_latency_ms: f64,
    pub target_foreground_p99_ms: f64,
    pub observed_read_mib_s: f64,
    pub observed_write_mib_s: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_read_mib_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_write_mib_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loadavg_1m: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<String>,
    pub notes: Vec<String>,
}

impl AutopilotPolicy {
    pub fn load_json(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|err| {
            ArgosError::Io(io::Error::new(
                err.kind(),
                format!("failed to read autopilot policy {}: {err}", path.display()),
            ))
        })?;
        let policy: Self = serde_json::from_slice(&bytes).map_err(|err| {
            ArgosError::Invalid(format!(
                "failed to parse autopilot policy {}: {err}",
                path.display()
            ))
        })?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn load_optional_json(path: &Path) -> Result<Option<Self>> {
        if path.exists() {
            Self::load_json(path).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn default_path(root: &Path) -> PathBuf {
        root.join(".argosfs/autopilot-policy.json")
    }

    pub fn validate(&self) -> Result<()> {
        validate_optional_rate(
            "background_io.max_read_mib_s",
            self.background_io.max_read_mib_s,
        )?;
        validate_optional_rate(
            "background_io.max_write_mib_s",
            self.background_io.max_write_mib_s,
        )?;
        validate_positive_finite(
            "background_io.target_foreground_p99_ms",
            self.background_io.target_foreground_p99_ms,
        )?;
        validate_optional_threshold(
            "background_io.pause_if_foreground_p99_ms",
            self.background_io.pause_if_foreground_p99_ms,
        )?;
        validate_optional_threshold(
            "background_io.pause_if_loadavg_gt",
            self.background_io.pause_if_loadavg_gt,
        )?;
        if let Some(copies) = self.placement.min_boot_copies {
            if copies == 0 {
                return Err(ArgosError::Invalid(
                    "placement.min_boot_copies must be greater than zero".to_string(),
                ));
            }
        }
        for path in self
            .paths
            .boot_critical
            .iter()
            .chain(self.paths.cold_candidates.iter())
        {
            validate_policy_path(path)?;
        }
        Ok(())
    }
}

pub fn plan_background_io(
    action: &str,
    budget_unit: &str,
    requested_budget: usize,
    report: &HealthReport,
    policy: &AutopilotPolicy,
) -> BackgroundThrottleDecision {
    let max_foreground_latency_ms = max_foreground_latency_ms(report);
    let observed_read_mib_s = report
        .disks
        .iter()
        .map(|disk| disk.observed_read_mib_s)
        .fold(0.0_f64, f64::max);
    let observed_write_mib_s = report
        .disks
        .iter()
        .map(|disk| disk.observed_write_mib_s)
        .fold(0.0_f64, f64::max);
    let loadavg_1m = read_loadavg_1m();
    let mut effective_budget = requested_budget;
    let mut notes = Vec::new();
    let mut pause_reason = None;

    match policy.mode {
        AutopilotMode::Observe => {
            effective_budget = 0;
            pause_reason = Some("policy mode is observe".to_string());
        }
        AutopilotMode::Aggressive => {}
        AutopilotMode::Balanced | AutopilotMode::Safe => {
            let target = policy.background_io.target_foreground_p99_ms;
            if max_foreground_latency_ms > target * 2.0 {
                effective_budget = effective_budget.min(1);
                notes.push("foreground latency above 2x target; reduced budget to one".to_string());
            } else if max_foreground_latency_ms > target {
                effective_budget = effective_budget.min((requested_budget / 2).max(1));
                notes.push("foreground latency above target; halved budget".to_string());
            }
        }
    }

    if let Some(limit) = action_rate_limit_mib_s(action, policy) {
        let rate_budget = limit.floor() as usize;
        effective_budget = effective_budget.min(rate_budget);
        notes.push(format!(
            "background I/O rate policy capped this run at {rate_budget} {budget_unit}"
        ));
    }

    if let Some(threshold) = policy.background_io.pause_if_foreground_p99_ms {
        if max_foreground_latency_ms > threshold {
            effective_budget = 0;
            pause_reason = Some(format!(
                "foreground latency {max_foreground_latency_ms:.2}ms exceeded pause threshold {threshold:.2}ms"
            ));
        }
    }
    if let (Some(load), Some(threshold)) = (loadavg_1m, policy.background_io.pause_if_loadavg_gt) {
        if load > threshold {
            effective_budget = 0;
            pause_reason = Some(format!(
                "loadavg {load:.2} exceeded pause threshold {threshold:.2}"
            ));
        }
    }

    BackgroundThrottleDecision {
        action: action.to_string(),
        budget_unit: budget_unit.to_string(),
        requested_budget,
        effective_budget,
        max_foreground_latency_ms,
        target_foreground_p99_ms: policy.background_io.target_foreground_p99_ms,
        observed_read_mib_s,
        observed_write_mib_s,
        max_read_mib_s: policy.background_io.max_read_mib_s,
        max_write_mib_s: policy.background_io.max_write_mib_s,
        loadavg_1m,
        pause_reason,
        notes,
    }
}

fn action_rate_limit_mib_s(action: &str, policy: &AutopilotPolicy) -> Option<f64> {
    let read = policy.background_io.max_read_mib_s;
    let write = policy.background_io.max_write_mib_s;
    match action {
        "scrub" | "repair" => read,
        "rebalance" | "drain" => match (read, write) {
            (Some(read), Some(write)) => Some(read.min(write)),
            (Some(read), None) => Some(read),
            (None, Some(write)) => Some(write),
            (None, None) => None,
        },
        _ => None,
    }
}

fn max_foreground_latency_ms(report: &HealthReport) -> f64 {
    report
        .disks
        .iter()
        .map(|disk| {
            disk.read_latency_ewma_ms
                .max(disk.write_latency_ewma_ms)
                .max(disk.health.latency_ms)
        })
        .fold(0.0_f64, f64::max)
}

fn read_loadavg_1m() -> Option<f64> {
    let text = fs::read_to_string("/proc/loadavg").ok()?;
    text.split_whitespace().next()?.parse().ok()
}

fn default_max_drains_per_day() -> u64 {
    1
}

fn default_foreground_latency_target_ms() -> f64 {
    75.0
}

fn validate_optional_rate(name: &str, value: Option<f64>) -> Result<()> {
    if let Some(value) = value {
        if !value.is_finite() || value < 0.0 {
            return Err(ArgosError::Invalid(format!(
                "{name} must be a finite non-negative MiB/s value"
            )));
        }
    }
    Ok(())
}

fn validate_optional_threshold(name: &str, value: Option<f64>) -> Result<()> {
    if let Some(value) = value {
        validate_positive_finite(name, value)?;
    }
    Ok(())
}

fn validate_positive_finite(name: &str, value: f64) -> Result<()> {
    if !value.is_finite() || value <= 0.0 {
        return Err(ArgosError::Invalid(format!(
            "{name} must be a finite positive value"
        )));
    }
    Ok(())
}

fn validate_policy_path(path: &str) -> Result<()> {
    let parsed = Path::new(path);
    if !parsed.is_absolute()
        || parsed
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ArgosError::Invalid(format!(
            "policy paths must be absolute and normalized: {path}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
}
