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
#[path = "autopilot_tests.rs"]
mod tests;
