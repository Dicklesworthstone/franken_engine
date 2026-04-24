//! Deterministic performance regression gate for RGC-703 (`bd-1lsy.8.3`).
//!
//! This module converts benchmark observations into a fail-closed promotion
//! verdict with deterministic culprit ranking and waiver-expiry enforcement.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PERFORMANCE_REGRESSION_GATE_COMPONENT: &str = "performance_regression_gate";
pub const PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION: &str =
    "franken-engine.rgc-performance-regression-gate.v1";

const MILLION: u32 = 1_000_000;

const ERROR_ZERO_BASELINE: &str = "FE-RGC-703-BASELINE-0001";
const ERROR_MISSING_METADATA: &str = "FE-RGC-703-INTEGRITY-0002";
const ERROR_LOW_CONFIDENCE: &str = "FE-RGC-703-SIGNIFICANCE-0003";
const ERROR_CRITICAL_REGRESSION: &str = "FE-RGC-703-REGRESSION-0004";
const ERROR_FAIL_REGRESSION: &str = "FE-RGC-703-REGRESSION-0005";
const ERROR_WAIVER_EXPIRED: &str = "FE-RGC-703-WAIVER-0006";
const WARN_REGRESSION: &str = "WARN-RGC-703-REGRESSION-0001";
const ERROR_SERIALIZATION: &str = "FE-RGC-703-SERIALIZATION-0007";
const ERROR_REPORT_WRITE: &str = "FE-RGC-703-REPORT-0008";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionGateInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub now_unix_seconds: u64,
    pub observations: Vec<RegressionObservation>,
    #[serde(default)]
    pub waivers: Vec<RegressionWaiver>,
}

impl RegressionGateInput {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        now_unix_seconds: u64,
        observations: Vec<RegressionObservation>,
        waivers: Vec<RegressionWaiver>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
            now_unix_seconds,
            observations,
            waivers,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionObservation {
    pub workload_id: String,
    pub scenario_id: String,
    pub benchmark_metadata_hash: String,
    pub baseline_ns: u64,
    pub observed_ns: u64,
    pub p_value_millionths: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_id: Option<String>,
}

impl RegressionObservation {
    pub fn new(
        workload_id: impl Into<String>,
        scenario_id: impl Into<String>,
        benchmark_metadata_hash: impl Into<String>,
        baseline_ns: u64,
        observed_ns: u64,
        p_value_millionths: u32,
        commit_id: Option<String>,
    ) -> Self {
        Self {
            workload_id: workload_id.into(),
            scenario_id: scenario_id.into(),
            benchmark_metadata_hash: benchmark_metadata_hash.into(),
            baseline_ns,
            observed_ns,
            p_value_millionths,
            commit_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionWaiver {
    pub waiver_id: String,
    pub workload_id: String,
    pub owner: String,
    pub expires_at_unix_seconds: u64,
    pub reason: String,
}

impl RegressionWaiver {
    pub fn new(
        waiver_id: impl Into<String>,
        workload_id: impl Into<String>,
        owner: impl Into<String>,
        expires_at_unix_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            waiver_id: waiver_id.into(),
            workload_id: workload_id.into(),
            owner: owner.into(),
            expires_at_unix_seconds,
            reason: reason.into(),
        }
    }

    fn is_expired(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds > self.expires_at_unix_seconds
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionGatePolicy {
    /// Warning threshold in millionths over baseline mean.
    pub warning_regression_millionths: u32,
    /// High-severity fail threshold in millionths over baseline mean.
    pub fail_regression_millionths: u32,
    /// Critical regression threshold in millionths over baseline mean.
    pub critical_regression_millionths: u32,
    /// Maximum accepted p-value (millionths) for statistically significant deltas.
    pub max_p_value_millionths: u32,
    /// Maximum number of ranked culprit entries in report output.
    pub max_culprits: usize,
}

impl Default for RegressionGatePolicy {
    fn default() -> Self {
        Self {
            warning_regression_millionths: 25_000,
            fail_regression_millionths: 50_000,
            critical_regression_millionths: 100_000,
            max_p_value_millionths: 50_000,
            max_culprits: 10,
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum RegressionSeverity {
    #[default]
    None,
    Warning,
    High,
    Critical,
}

impl RegressionSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Warning => "warning",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    fn score_weight(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Warning => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }

    fn is_blocking(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

impl fmt::Display for RegressionSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RegressionStatus {
    #[default]
    Active,
    Waived,
}

impl RegressionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Waived => "waived",
        }
    }
}

impl fmt::Display for RegressionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionFinding {
    pub workload_id: String,
    pub scenario_id: String,
    pub severity: RegressionSeverity,
    pub status: RegressionStatus,
    pub regression_millionths: u32,
    pub p_value_millionths: u32,
    pub error_code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiver_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiver_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiver_expires_at_unix_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CulpritCandidate {
    pub rank: usize,
    pub workload_id: String,
    pub severity: RegressionSeverity,
    pub score: u64,
    pub regression_millionths: u32,
    pub p_value_millionths: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionGateLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub workload_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionGateReport {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub blocking: bool,
    pub is_blocking: bool,
    pub highest_severity: RegressionSeverity,
    pub severity: RegressionSeverity,
    pub regressions: Vec<RegressionFinding>,
    pub culprit_ranking: Vec<CulpritCandidate>,
    pub logs: Vec<RegressionGateLogEvent>,
}

#[derive(Debug, Error)]
pub enum RegressionGateError {
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("report write failed for `{path}`: {source}")]
    ReportWrite {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl RegressionGateError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::Serialization(_) => ERROR_SERIALIZATION,
            Self::ReportWrite { .. } => ERROR_REPORT_WRITE,
        }
    }
}

pub fn evaluate_performance_regression_gate(
    input: &RegressionGateInput,
    policy: &RegressionGatePolicy,
) -> RegressionGateReport {
    let mut observations = input.observations.clone();
    observations.sort_by(|left, right| {
        left.workload_id
            .cmp(&right.workload_id)
            .then_with(|| left.scenario_id.cmp(&right.scenario_id))
    });

    let mut waivers = input.waivers.clone();
    // Prefer the waiver with the furthest expiry for each workload so an
    // older expired waiver cannot shadow a newer active waiver.
    waivers.sort_by(|left, right| {
        left.workload_id
            .cmp(&right.workload_id)
            .then_with(|| {
                right
                    .expires_at_unix_seconds
                    .cmp(&left.expires_at_unix_seconds)
            })
            .then_with(|| left.waiver_id.cmp(&right.waiver_id))
    });
    let waivers_by_workload = waivers
        .into_iter()
        .fold(BTreeMap::new(), |mut map, waiver| {
            map.entry(waiver.workload_id.clone()).or_insert(waiver);
            map
        });

    let mut regressions = Vec::new();
    let mut logs = Vec::new();
    let mut highest_active_severity = RegressionSeverity::None;

    for observation in &observations {
        let regression = regression_millionths(observation.baseline_ns, observation.observed_ns);
        let base = classify_finding(observation, regression, policy);
        let Some((severity, error_code, message)) = base else {
            continue;
        };

        let mut finding = RegressionFinding {
            workload_id: observation.workload_id.clone(),
            scenario_id: observation.scenario_id.clone(),
            severity,
            status: RegressionStatus::Active,
            regression_millionths: regression,
            p_value_millionths: observation.p_value_millionths,
            error_code: error_code.to_string(),
            message,
            waiver_id: None,
            waiver_owner: None,
            waiver_expires_at_unix_seconds: None,
            commit_id: observation.commit_id.clone(),
        };

        if let Some(waiver) = waivers_by_workload.get(&observation.workload_id) {
            if waiver.is_expired(input.now_unix_seconds) && severity.is_blocking() {
                let expiry_finding = RegressionFinding {
                    workload_id: observation.workload_id.clone(),
                    scenario_id: observation.scenario_id.clone(),
                    severity: RegressionSeverity::High,
                    status: RegressionStatus::Active,
                    regression_millionths: regression,
                    p_value_millionths: observation.p_value_millionths,
                    error_code: ERROR_WAIVER_EXPIRED.to_string(),
                    message: format!(
                        "waiver `{}` expired at {} (owner `{}`)",
                        waiver.waiver_id, waiver.expires_at_unix_seconds, waiver.owner
                    ),
                    waiver_id: Some(waiver.waiver_id.clone()),
                    waiver_owner: Some(waiver.owner.clone()),
                    waiver_expires_at_unix_seconds: Some(waiver.expires_at_unix_seconds),
                    commit_id: observation.commit_id.clone(),
                };
                highest_active_severity = highest_active_severity.max(expiry_finding.severity);
                logs.push(build_log(
                    input,
                    "regression_finding",
                    "active",
                    Some(ERROR_WAIVER_EXPIRED),
                    Some(observation.workload_id.clone()),
                ));
                regressions.push(expiry_finding);
            } else {
                finding.status = RegressionStatus::Waived;
                finding.waiver_id = Some(waiver.waiver_id.clone());
                finding.waiver_owner = Some(waiver.owner.clone());
                finding.waiver_expires_at_unix_seconds = Some(waiver.expires_at_unix_seconds);
                finding.message = format!("{} (waived by `{}`)", finding.message, waiver.waiver_id);
            }
        }

        if finding.status == RegressionStatus::Active {
            highest_active_severity = highest_active_severity.max(finding.severity);
        }

        logs.push(build_log(
            input,
            "regression_finding",
            finding.status.as_str(),
            Some(&finding.error_code),
            Some(observation.workload_id.clone()),
        ));
        regressions.push(finding);
    }

    let culprit_ranking = rank_culprits(&regressions, policy.max_culprits);
    let blocking = regressions.iter().any(|finding| {
        finding.status == RegressionStatus::Active && finding.severity.is_blocking()
    });

    logs.push(build_log(
        input,
        "gate_decision",
        if blocking { "hold" } else { "promote" },
        None,
        None,
    ));

    RegressionGateReport {
        schema_version: PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION.to_string(),
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: PERFORMANCE_REGRESSION_GATE_COMPONENT.to_string(),
        blocking,
        is_blocking: blocking,
        highest_severity: highest_active_severity,
        severity: highest_active_severity,
        regressions,
        culprit_ranking,
        logs,
    }
}

pub fn write_regression_report(
    report: &RegressionGateReport,
    path: impl AsRef<Path>,
) -> Result<(), RegressionGateError> {
    let rendered = serde_json::to_string_pretty(report)
        .map_err(|error| RegressionGateError::Serialization(error.to_string()))?;
    let target = path.as_ref();
    fs::write(target, rendered).map_err(|source| RegressionGateError::ReportWrite {
        path: target.display().to_string(),
        source,
    })?;
    Ok(())
}

fn build_log(
    input: &RegressionGateInput,
    event: &str,
    outcome: &str,
    error_code: Option<&str>,
    workload_id: Option<String>,
) -> RegressionGateLogEvent {
    RegressionGateLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: PERFORMANCE_REGRESSION_GATE_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code: error_code.map(ToString::to_string),
        workload_id,
    }
}

fn classify_finding(
    observation: &RegressionObservation,
    regression_millionths: u32,
    policy: &RegressionGatePolicy,
) -> Option<(RegressionSeverity, &'static str, String)> {
    if observation.baseline_ns == 0 {
        return Some((
            RegressionSeverity::Critical,
            ERROR_ZERO_BASELINE,
            "missing or zero baseline".to_string(),
        ));
    }

    if observation.benchmark_metadata_hash.trim().is_empty() {
        return Some((
            RegressionSeverity::High,
            ERROR_MISSING_METADATA,
            "missing benchmark metadata hash".to_string(),
        ));
    }

    if regression_millionths < policy.warning_regression_millionths {
        return None;
    }

    if observation.p_value_millionths > policy.max_p_value_millionths {
        return Some((
            RegressionSeverity::High,
            ERROR_LOW_CONFIDENCE,
            format!(
                "insufficient significance: p_value={} > max={}",
                observation.p_value_millionths, policy.max_p_value_millionths
            ),
        ));
    }

    if regression_millionths >= policy.critical_regression_millionths {
        return Some((
            RegressionSeverity::Critical,
            ERROR_CRITICAL_REGRESSION,
            format!(
                "critical regression {} millionths exceeds {}",
                regression_millionths, policy.critical_regression_millionths
            ),
        ));
    }

    if regression_millionths >= policy.fail_regression_millionths {
        return Some((
            RegressionSeverity::High,
            ERROR_FAIL_REGRESSION,
            format!(
                "regression {} millionths exceeds fail threshold {}",
                regression_millionths, policy.fail_regression_millionths
            ),
        ));
    }

    Some((
        RegressionSeverity::Warning,
        WARN_REGRESSION,
        format!(
            "warning regression {} millionths exceeds warning threshold {}",
            regression_millionths, policy.warning_regression_millionths
        ),
    ))
}

fn rank_culprits(regressions: &[RegressionFinding], max_culprits: usize) -> Vec<CulpritCandidate> {
    if max_culprits == 0 {
        return Vec::new();
    }

    let mut by_workload: BTreeMap<String, CulpritAccumulator> = BTreeMap::new();
    for finding in regressions {
        if finding.status != RegressionStatus::Active
            || finding.severity == RegressionSeverity::None
        {
            continue;
        }
        let entry = by_workload
            .entry(finding.workload_id.clone())
            .or_insert_with(|| CulpritAccumulator::new(finding.workload_id.clone()));
        entry.observe(finding);
    }

    let mut candidates = by_workload
        .into_values()
        .map(CulpritAccumulator::finalize)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| right.severity.cmp(&left.severity))
            .then_with(|| right.regression_millionths.cmp(&left.regression_millionths))
            .then_with(|| left.p_value_millionths.cmp(&right.p_value_millionths))
            .then_with(|| left.workload_id.cmp(&right.workload_id))
    });

    candidates
        .into_iter()
        .take(max_culprits)
        .enumerate()
        .map(|(index, mut candidate)| {
            candidate.rank = index + 1;
            candidate
        })
        .collect()
}

fn regression_millionths(baseline_ns: u64, observed_ns: u64) -> u32 {
    if baseline_ns == 0 || observed_ns <= baseline_ns {
        return 0;
    }
    let millionths = observed_ns
        .saturating_sub(baseline_ns)
        .saturating_mul(MILLION as u64)
        .saturating_div(baseline_ns);
    millionths.min(u64::from(u32::MAX)) as u32
}

#[derive(Debug, Clone)]
struct CulpritAccumulator {
    workload_id: String,
    severity: RegressionSeverity,
    regression_millionths: u32,
    p_value_millionths: u32,
    error_codes: Vec<String>,
    commit_id: Option<String>,
    score: u64,
}

impl CulpritAccumulator {
    fn new(workload_id: String) -> Self {
        Self {
            workload_id,
            severity: RegressionSeverity::None,
            regression_millionths: 0,
            p_value_millionths: MILLION,
            error_codes: Vec::new(),
            commit_id: None,
            score: 0,
        }
    }

    fn observe(&mut self, finding: &RegressionFinding) {
        self.severity = self.severity.max(finding.severity);
        self.regression_millionths = self
            .regression_millionths
            .max(finding.regression_millionths);
        self.p_value_millionths = self.p_value_millionths.min(finding.p_value_millionths);
        if let Some(commit_id) = finding.commit_id.as_ref() {
            match self.commit_id.as_ref() {
                Some(existing) if existing <= commit_id => {}
                _ => self.commit_id = Some(commit_id.clone()),
            }
        }

        if !self.error_codes.contains(&finding.error_code) {
            self.error_codes.push(finding.error_code.clone());
            self.error_codes.sort();
        }

        let confidence_bonus = MILLION.saturating_sub(finding.p_value_millionths);
        let finding_score = finding.severity.score_weight() * 1_000_000_000
            + (finding.regression_millionths as u64) * 1_000
            + confidence_bonus as u64;
        self.score = self.score.max(finding_score);
    }

    fn finalize(self) -> CulpritCandidate {
        CulpritCandidate {
            rank: 0,
            workload_id: self.workload_id,
            severity: self.severity,
            score: self.score,
            regression_millionths: self.regression_millionths,
            p_value_millionths: self.p_value_millionths,
            error_codes: self.error_codes,
            commit_id: self.commit_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_policy() -> RegressionGatePolicy {
        RegressionGatePolicy {
            warning_regression_millionths: 20_000,
            fail_regression_millionths: 40_000,
            critical_regression_millionths: 90_000,
            max_p_value_millionths: 50_000,
            max_culprits: 5,
        }
    }

    fn mk_obs(workload: &str, baseline: u64, observed: u64, p_value: u32) -> RegressionObservation {
        RegressionObservation::new(
            workload,
            "scenario",
            "sha256:meta",
            baseline,
            observed,
            p_value,
            Some(format!("commit-{workload}")),
        )
    }

    #[test]
    fn deterministic_output_under_input_permutation() {
        let policy = baseline_policy();
        let input_a = RegressionGateInput::new(
            "trace",
            "decision",
            "policy",
            1_700_000_000,
            vec![
                mk_obs("w-c", 100_000, 140_000, 12_000),
                mk_obs("w-a", 100_000, 130_000, 10_000),
                mk_obs("w-b", 100_000, 111_000, 20_000),
            ],
            Vec::new(),
        );
        let input_b = RegressionGateInput::new(
            "trace",
            "decision",
            "policy",
            1_700_000_000,
            vec![
                mk_obs("w-a", 100_000, 130_000, 10_000),
                mk_obs("w-b", 100_000, 111_000, 20_000),
                mk_obs("w-c", 100_000, 140_000, 12_000),
            ],
            Vec::new(),
        );

        let left = evaluate_performance_regression_gate(&input_a, &policy);
        let right = evaluate_performance_regression_gate(&input_b, &policy);
        assert_eq!(left, right);
    }

    #[test]
    fn no_regressions_yield_non_blocking_report() {
        let input = RegressionGateInput::new(
            "trace",
            "decision",
            "policy",
            1_700_000_000,
            vec![
                mk_obs("w-a", 100_000, 100_000, 5_000),
                mk_obs("w-b", 100_000, 99_000, 6_000),
            ],
            Vec::new(),
        );
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        assert!(!report.blocking);
        assert_eq!(report.highest_severity, RegressionSeverity::None);
        assert!(report.regressions.is_empty());
        assert!(report.culprit_ranking.is_empty());
    }

    #[test]
    fn high_regression_blocks_without_waiver() {
        // 6% regression: above fail (4%) but below critical (9%)
        let input = RegressionGateInput::new(
            "trace",
            "decision",
            "policy",
            1_700_000_000,
            vec![mk_obs("w-a", 100_000, 106_000, 10_000)],
            Vec::new(),
        );
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        assert!(report.blocking);
        assert_eq!(report.highest_severity, RegressionSeverity::High);
        assert_eq!(report.regressions.len(), 1);
        assert_eq!(report.regressions[0].status, RegressionStatus::Active);
        assert_eq!(report.culprit_ranking.len(), 1);
    }

    #[test]
    fn valid_waiver_suppresses_blocking() {
        let waiver = RegressionWaiver::new(
            "waiver-a",
            "w-a",
            "owner-a",
            1_800_000_000,
            "temporary noisy host",
        );
        let input = RegressionGateInput::new(
            "trace",
            "decision",
            "policy",
            1_700_000_000,
            vec![mk_obs("w-a", 100_000, 160_000, 10_000)],
            vec![waiver],
        );
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        assert!(!report.blocking);
        assert_eq!(report.highest_severity, RegressionSeverity::None);
        assert_eq!(report.regressions.len(), 1);
        assert_eq!(report.regressions[0].status, RegressionStatus::Waived);
        assert!(report.culprit_ranking.is_empty());
    }

    #[test]
    fn expired_waiver_is_fail_closed() {
        // 6% regression (High severity) with expired waiver → still blocking
        let waiver =
            RegressionWaiver::new("waiver-old", "w-a", "owner-a", 1_600_000_000, "expired");
        let input = RegressionGateInput::new(
            "trace",
            "decision",
            "policy",
            1_700_000_000,
            vec![mk_obs("w-a", 100_000, 106_000, 10_000)],
            vec![waiver],
        );
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        assert!(report.blocking);
        assert_eq!(report.highest_severity, RegressionSeverity::High);
        assert_eq!(report.regressions.len(), 2);
        assert!(
            report
                .regressions
                .iter()
                .any(|finding| finding.error_code == ERROR_WAIVER_EXPIRED)
        );
    }

    #[test]
    fn culprit_ranking_is_stable_for_ties() {
        let policy = RegressionGatePolicy {
            max_culprits: 2,
            ..baseline_policy()
        };
        let input = RegressionGateInput::new(
            "trace",
            "decision",
            "policy",
            1_700_000_000,
            vec![
                mk_obs("w-b", 100_000, 140_000, 10_000),
                mk_obs("w-a", 100_000, 140_000, 10_000),
                mk_obs("w-c", 100_000, 125_000, 10_000),
            ],
            Vec::new(),
        );
        let report = evaluate_performance_regression_gate(&input, &policy);
        assert_eq!(report.culprit_ranking.len(), 2);
        assert_eq!(report.culprit_ranking[0].workload_id, "w-a");
        assert_eq!(report.culprit_ranking[1].workload_id, "w-b");
    }

    #[test]
    fn write_report_round_trip() {
        let input = RegressionGateInput::new(
            "trace",
            "decision",
            "policy",
            1_700_000_000,
            vec![mk_obs("w-a", 100_000, 140_000, 10_000)],
            Vec::new(),
        );
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());

        let tmp = std::env::temp_dir().join("rgc_703_report_round_trip.json");
        write_regression_report(&report, &tmp).expect("report write should succeed");
        let rendered = fs::read_to_string(&tmp).expect("report should exist");
        let parsed: RegressionGateReport =
            serde_json::from_str(&rendered).expect("report should parse");
        assert_eq!(report, parsed);
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn regression_millionths_zero_baseline_is_zero() {
        assert_eq!(regression_millionths(0, 123), 0);
    }

    #[test]
    fn regression_millionths_non_regression_is_zero() {
        assert_eq!(regression_millionths(100, 90), 0);
        assert_eq!(regression_millionths(100, 100), 0);
    }

    #[test]
    fn regression_millionths_positive_regression() {
        // +10% regression -> 100_000 millionths.
        assert_eq!(regression_millionths(1_000, 1_100), 100_000);
    }

    #[test]
    fn serialization_error_code_is_stable() {
        let error = RegressionGateError::Serialization("x".to_string());
        assert_eq!(error.stable_code(), ERROR_SERIALIZATION);
    }

    #[test]
    fn report_write_error_code_is_stable() {
        let error = RegressionGateError::ReportWrite {
            path: "x".to_string(),
            source: std::io::Error::other("boom"),
        };
        assert_eq!(error.stable_code(), ERROR_REPORT_WRITE);
    }

    #[test]
    fn severity_display_is_stable() {
        assert_eq!(RegressionSeverity::None.to_string(), "none");
        assert_eq!(RegressionSeverity::Warning.to_string(), "warning");
        assert_eq!(RegressionSeverity::High.to_string(), "high");
        assert_eq!(RegressionSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn status_display_is_stable() {
        assert_eq!(RegressionStatus::Active.to_string(), "active");
        assert_eq!(RegressionStatus::Waived.to_string(), "waived");
    }

    // -- Severity ordering and properties -----------------------------------

    #[test]
    fn severity_ordering_none_lt_warning_lt_high_lt_critical() {
        assert!(RegressionSeverity::None < RegressionSeverity::Warning);
        assert!(RegressionSeverity::Warning < RegressionSeverity::High);
        assert!(RegressionSeverity::High < RegressionSeverity::Critical);
    }

    #[test]
    fn severity_as_str_matches_display() {
        for sev in [
            RegressionSeverity::None,
            RegressionSeverity::Warning,
            RegressionSeverity::High,
            RegressionSeverity::Critical,
        ] {
            assert_eq!(sev.as_str(), &sev.to_string());
        }
    }

    #[test]
    fn severity_default_is_none() {
        assert_eq!(RegressionSeverity::default(), RegressionSeverity::None);
    }

    #[test]
    fn severity_serde_roundtrip() {
        for sev in [
            RegressionSeverity::None,
            RegressionSeverity::Warning,
            RegressionSeverity::High,
            RegressionSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).expect("serde deserialization should succeed");
            let back: RegressionSeverity =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn status_default_is_active() {
        assert_eq!(RegressionStatus::default(), RegressionStatus::Active);
    }

    #[test]
    fn status_as_str_matches_display() {
        for st in [RegressionStatus::Active, RegressionStatus::Waived] {
            assert_eq!(st.as_str(), &st.to_string());
        }
    }

    #[test]
    fn status_serde_roundtrip() {
        for st in [RegressionStatus::Active, RegressionStatus::Waived] {
            let json = serde_json::to_string(&st).expect("serde deserialization should succeed");
            let back: RegressionStatus =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(st, back);
        }
    }

    // -- Policy defaults ----------------------------------------------------

    #[test]
    fn default_policy_thresholds_are_sensible() {
        let p = RegressionGatePolicy::default();
        assert!(p.warning_regression_millionths < p.fail_regression_millionths);
        assert!(p.fail_regression_millionths < p.critical_regression_millionths);
        assert!(p.max_p_value_millionths > 0);
        assert!(p.max_culprits > 0);
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = baseline_policy();
        let json = serde_json::to_string(&p).expect("serde deserialization should succeed");
        let back: RegressionGatePolicy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(p, back);
    }

    // -- regression_millionths edge cases -----------------------------------

    #[test]
    fn regression_millionths_100_percent() {
        assert_eq!(regression_millionths(500, 1000), MILLION);
    }

    #[test]
    fn regression_millionths_small_delta() {
        assert_eq!(regression_millionths(100_000, 101_000), 10_000);
    }

    #[test]
    fn regression_millionths_saturates_on_large_values() {
        let result = regression_millionths(1, u64::MAX);
        assert_eq!(result, u32::MAX);
    }

    // -- classify_finding paths ---------------------------------------------

    #[test]
    fn classify_zero_baseline_yields_critical() {
        let obs = RegressionObservation::new("w", "s", "h", 0, 100, 10_000, None);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert!(report.blocking);
        assert_eq!(report.highest_severity, RegressionSeverity::Critical);
        assert!(
            report
                .regressions
                .iter()
                .any(|f| f.error_code == ERROR_ZERO_BASELINE)
        );
    }

    #[test]
    fn classify_missing_metadata_hash_yields_high() {
        let obs = RegressionObservation::new("w", "s", "", 100_000, 130_000, 10_000, None);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert!(report.blocking);
        assert!(
            report
                .regressions
                .iter()
                .any(|f| f.error_code == ERROR_MISSING_METADATA)
        );
    }

    #[test]
    fn classify_whitespace_only_metadata_hash_yields_high() {
        let obs = RegressionObservation::new("w", "s", "   ", 100_000, 130_000, 10_000, None);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert!(
            report
                .regressions
                .iter()
                .any(|f| f.error_code == ERROR_MISSING_METADATA)
        );
    }

    #[test]
    fn classify_low_confidence_observation_yields_high() {
        let obs = mk_obs("w", 100_000, 130_000, 60_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert!(
            report
                .regressions
                .iter()
                .any(|f| f.error_code == ERROR_LOW_CONFIDENCE)
        );
    }

    #[test]
    fn classify_critical_regression() {
        let obs = mk_obs("w", 100_000, 200_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert_eq!(report.highest_severity, RegressionSeverity::Critical);
        assert!(
            report
                .regressions
                .iter()
                .any(|f| f.error_code == ERROR_CRITICAL_REGRESSION)
        );
    }

    #[test]
    fn classify_fail_regression() {
        // 5% = 50_000 millionths, >= fail (40_000), < critical (90_000)
        let obs = mk_obs("w", 100_000, 105_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert_eq!(report.highest_severity, RegressionSeverity::High);
        assert!(
            report
                .regressions
                .iter()
                .any(|f| f.error_code == ERROR_FAIL_REGRESSION)
        );
    }

    #[test]
    fn classify_warning_regression() {
        // 2.5% = 25_000 millionths, >= warn (20_000), < fail (40_000)
        let obs = mk_obs("w", 1_000_000, 1_025_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert_eq!(report.highest_severity, RegressionSeverity::Warning);
        assert!(
            report
                .regressions
                .iter()
                .any(|f| f.error_code == WARN_REGRESSION)
        );
    }

    #[test]
    fn warning_is_non_blocking() {
        // 2.5% = warning level, not blocking
        let obs = mk_obs("w", 1_000_000, 1_025_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert!(!report.blocking);
    }

    // -- Waiver edge cases --------------------------------------------------

    #[test]
    fn waiver_exactly_at_expiry_is_not_expired() {
        let waiver = RegressionWaiver::new("w-id", "w-a", "owner", 1_700_000_000, "reason");
        let obs = mk_obs("w-a", 100_000, 160_000, 10_000);
        let input = RegressionGateInput::new("t", "d", "p", 1_700_000_000, vec![obs], vec![waiver]);
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        assert!(!report.blocking);
        assert_eq!(report.regressions[0].status, RegressionStatus::Waived);
    }

    #[test]
    fn waiver_one_second_after_expiry_is_expired() {
        let waiver = RegressionWaiver::new("w-id", "w-a", "owner", 1_700_000_000, "reason");
        let obs = mk_obs("w-a", 100_000, 160_000, 10_000);
        let input = RegressionGateInput::new("t", "d", "p", 1_700_000_001, vec![obs], vec![waiver]);
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        assert!(report.blocking);
    }

    #[test]
    fn newest_active_waiver_wins_when_older_waiver_is_expired() {
        let waivers = vec![
            RegressionWaiver::new("waiver-a-expired", "w-a", "owner-old", 1_600_000_000, "old"),
            RegressionWaiver::new("waiver-z-active", "w-a", "owner-new", 1_800_000_000, "new"),
        ];
        let obs = mk_obs("w-a", 100_000, 160_000, 10_000);
        let input = RegressionGateInput::new("t", "d", "p", 1_700_000_000, vec![obs], waivers);
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());

        assert!(!report.blocking);
        assert_eq!(report.regressions.len(), 1);
        assert_eq!(report.regressions[0].status, RegressionStatus::Waived);
        assert_eq!(
            report.regressions[0].waiver_id.as_deref(),
            Some("waiver-z-active")
        );
    }

    #[test]
    fn waiver_for_wrong_workload_is_ignored() {
        let waiver = RegressionWaiver::new("w-id", "other-workload", "owner", 1_800_000_000, "r");
        let obs = mk_obs("w-a", 100_000, 160_000, 10_000);
        let input = RegressionGateInput::new("t", "d", "p", 1_700_000_000, vec![obs], vec![waiver]);
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        assert!(report.blocking);
        assert_eq!(report.regressions[0].status, RegressionStatus::Active);
    }

    #[test]
    fn expired_waiver_on_warning_is_not_escalated() {
        let waiver = RegressionWaiver::new("w-id", "w-a", "owner", 1_600_000_000, "expired");
        // 2.5% = warning level, not blocking
        let obs = mk_obs("w-a", 1_000_000, 1_025_000, 10_000);
        let input = RegressionGateInput::new("t", "d", "p", 1_700_000_000, vec![obs], vec![waiver]);
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        assert!(
            !report
                .regressions
                .iter()
                .any(|f| f.error_code == ERROR_WAIVER_EXPIRED)
        );
    }

    #[test]
    fn waived_finding_populates_waiver_fields() {
        let waiver = RegressionWaiver::new("wv-1", "w-a", "alice", 1_800_000_000, "noisy");
        let obs = mk_obs("w-a", 100_000, 160_000, 10_000);
        let input = RegressionGateInput::new("t", "d", "p", 1_700_000_000, vec![obs], vec![waiver]);
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        let finding = &report.regressions[0];
        assert_eq!(finding.waiver_id.as_deref(), Some("wv-1"));
        assert_eq!(finding.waiver_owner.as_deref(), Some("alice"));
        assert_eq!(finding.waiver_expires_at_unix_seconds, Some(1_800_000_000));
        assert!(finding.message.contains("waived by"));
    }

    // -- Culprit ranking details --------------------------------------------

    #[test]
    fn culprit_max_culprits_zero_returns_empty() {
        let policy = RegressionGatePolicy {
            max_culprits: 0,
            ..baseline_policy()
        };
        let obs = mk_obs("w-a", 100_000, 160_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &policy,
        );
        assert!(report.culprit_ranking.is_empty());
    }

    #[test]
    fn culprit_rank_starts_at_one() {
        let obs = mk_obs("w-a", 100_000, 160_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert_eq!(report.culprit_ranking[0].rank, 1);
    }

    #[test]
    fn culprit_score_increases_with_severity() {
        // 2.5% = warning, 5% = high (fail)
        let obs_warn = mk_obs("w-warn", 1_000_000, 1_025_000, 10_000);
        let obs_high = mk_obs("w-high", 100_000, 105_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs_warn, obs_high], Vec::new()),
            &baseline_policy(),
        );
        let scores: Vec<_> = report.culprit_ranking.iter().map(|c| c.score).collect();
        assert!(scores[0] > scores[1]);
        assert_eq!(report.culprit_ranking[0].workload_id, "w-high");
    }

    #[test]
    fn culprit_commit_id_propagated() {
        let obs = mk_obs("w-a", 100_000, 160_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert_eq!(
            report.culprit_ranking[0].commit_id.as_deref(),
            Some("commit-w-a")
        );
    }

    #[test]
    fn culprit_error_codes_sorted() {
        let obs1 = RegressionObservation::new("w-a", "s1", "h", 100_000, 160_000, 10_000, None);
        let obs2 = RegressionObservation::new("w-a", "s2", "h", 100_000, 200_000, 10_000, None);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs1, obs2], Vec::new()),
            &baseline_policy(),
        );
        let culprit = &report.culprit_ranking[0];
        let codes = &culprit.error_codes;
        let mut sorted = codes.clone();
        sorted.sort();
        assert_eq!(codes, &sorted);
    }

    #[test]
    fn waived_findings_excluded_from_culprit_ranking() {
        let waiver = RegressionWaiver::new("wv", "w-a", "owner", 1_800_000_000, "r");
        let obs = mk_obs("w-a", 100_000, 160_000, 10_000);
        let input = RegressionGateInput::new("t", "d", "p", 1_700_000_000, vec![obs], vec![waiver]);
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        assert!(report.culprit_ranking.is_empty());
    }

    // -- Report structure ---------------------------------------------------

    #[test]
    fn report_schema_version_is_stable() {
        let obs = mk_obs("w-a", 100_000, 100_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert_eq!(
            report.schema_version,
            PERFORMANCE_REGRESSION_GATE_SCHEMA_VERSION
        );
    }

    #[test]
    fn report_component_is_stable() {
        let obs = mk_obs("w-a", 100_000, 100_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert_eq!(report.component, PERFORMANCE_REGRESSION_GATE_COMPONENT);
    }

    #[test]
    fn report_blocking_equals_is_blocking() {
        for observed in [100_000u64, 160_000, 200_000] {
            let obs = mk_obs("w", 100_000, observed, 10_000);
            let report = evaluate_performance_regression_gate(
                &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
                &baseline_policy(),
            );
            assert_eq!(report.blocking, report.is_blocking);
        }
    }

    #[test]
    fn report_severity_equals_highest_severity() {
        let obs = mk_obs("w", 100_000, 160_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert_eq!(report.severity, report.highest_severity);
    }

    #[test]
    fn report_traces_propagated() {
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("my-trace", "my-dec", "my-pol", 100, Vec::new(), Vec::new()),
            &baseline_policy(),
        );
        assert_eq!(report.trace_id, "my-trace");
        assert_eq!(report.decision_id, "my-dec");
        assert_eq!(report.policy_id, "my-pol");
    }

    // -- Log events ---------------------------------------------------------

    #[test]
    fn logs_contain_gate_decision_event() {
        let obs = mk_obs("w", 100_000, 160_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert!(report.logs.iter().any(|l| l.event == "gate_decision"));
    }

    #[test]
    fn logs_gate_decision_outcome_promote_when_non_blocking() {
        let obs = mk_obs("w", 100_000, 100_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        let decision = report
            .logs
            .iter()
            .find(|l| l.event == "gate_decision")
            .expect("serde deserialization should succeed");
        assert_eq!(decision.outcome, "promote");
    }

    #[test]
    fn logs_gate_decision_outcome_hold_when_blocking() {
        let obs = mk_obs("w", 100_000, 160_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        let decision = report
            .logs
            .iter()
            .find(|l| l.event == "gate_decision")
            .expect("serde deserialization should succeed");
        assert_eq!(decision.outcome, "hold");
    }

    #[test]
    fn logs_include_finding_per_regression() {
        let obs1 = mk_obs("w-a", 100_000, 160_000, 10_000);
        let obs2 = mk_obs("w-b", 100_000, 150_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs1, obs2], Vec::new()),
            &baseline_policy(),
        );
        let findings: Vec<_> = report
            .logs
            .iter()
            .filter(|l| l.event == "regression_finding")
            .collect();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn log_events_carry_component() {
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, Vec::new(), Vec::new()),
            &baseline_policy(),
        );
        for log in &report.logs {
            assert_eq!(log.component, PERFORMANCE_REGRESSION_GATE_COMPONENT);
        }
    }

    // -- Serde roundtrips ---------------------------------------------------

    #[test]
    fn input_serde_roundtrip() {
        let input = RegressionGateInput::new(
            "t",
            "d",
            "p",
            100,
            vec![mk_obs("w", 100, 200, 5000)],
            vec![RegressionWaiver::new("wv", "w", "o", 200, "r")],
        );
        let json = serde_json::to_string(&input).expect("serde deserialization should succeed");
        let back: RegressionGateInput =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(input, back);
    }

    #[test]
    fn report_serde_roundtrip_with_regressions() {
        let obs = mk_obs("w", 100_000, 160_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        let json = serde_json::to_string(&report).expect("serde deserialization should succeed");
        let back: RegressionGateReport =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(report, back);
    }

    #[test]
    fn culprit_candidate_serde_roundtrip() {
        let candidate = CulpritCandidate {
            rank: 1,
            workload_id: "w".to_string(),
            severity: RegressionSeverity::High,
            score: 42,
            regression_millionths: 100_000,
            p_value_millionths: 10_000,
            error_codes: vec![ERROR_FAIL_REGRESSION.to_string()],
            commit_id: Some("abc".to_string()),
        };
        let json = serde_json::to_string(&candidate).expect("serde deserialization should succeed");
        let back: CulpritCandidate =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(candidate, back);
    }

    // -- Error display ------------------------------------------------------

    #[test]
    fn serialization_error_display() {
        let err = RegressionGateError::Serialization("bad json".to_string());
        let msg = err.to_string();
        assert!(msg.contains("serialization failed"));
        assert!(msg.contains("bad json"));
    }

    #[test]
    fn report_write_error_display() {
        let err = RegressionGateError::ReportWrite {
            path: "/tmp/foo".to_string(),
            source: std::io::Error::other("disk full"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/foo"));
        assert!(msg.contains("report write failed"));
    }

    // -- Empty input --------------------------------------------------------

    #[test]
    fn empty_observations_yields_non_blocking_report() {
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, Vec::new(), Vec::new()),
            &baseline_policy(),
        );
        assert!(!report.blocking);
        assert_eq!(report.highest_severity, RegressionSeverity::None);
        assert!(report.regressions.is_empty());
        assert!(report.culprit_ranking.is_empty());
        assert!(report.logs.iter().any(|l| l.event == "gate_decision"));
    }

    // -- Multiple workloads mixed severities --------------------------------

    #[test]
    fn highest_severity_reflects_worst_active_finding() {
        // 2.5% warning + 100% critical
        let obs_warn = mk_obs("w-warn", 1_000_000, 1_025_000, 10_000);
        let obs_crit = mk_obs("w-crit", 100_000, 200_000, 10_000);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs_warn, obs_crit], Vec::new()),
            &baseline_policy(),
        );
        assert_eq!(report.highest_severity, RegressionSeverity::Critical);
    }

    #[test]
    fn waived_critical_reduces_highest_to_remaining() {
        let waiver = RegressionWaiver::new("wv", "w-crit", "owner", 1_800_000_000, "r");
        let obs_warn = mk_obs("w-warn", 1_000_000, 1_025_000, 10_000);
        let obs_crit = mk_obs("w-crit", 100_000, 200_000, 10_000);
        let input = RegressionGateInput::new(
            "t",
            "d",
            "p",
            1_700_000_000,
            vec![obs_warn, obs_crit],
            vec![waiver],
        );
        let report = evaluate_performance_regression_gate(&input, &baseline_policy());
        assert_eq!(report.highest_severity, RegressionSeverity::Warning);
        assert!(!report.blocking);
    }

    // -- Observation without commit_id --------------------------------------

    #[test]
    fn observation_without_commit_id_works() {
        let obs = RegressionObservation::new("w", "s", "h", 100_000, 160_000, 10_000, None);
        let report = evaluate_performance_regression_gate(
            &RegressionGateInput::new("t", "d", "p", 100, vec![obs], Vec::new()),
            &baseline_policy(),
        );
        assert!(report.blocking);
        assert!(report.culprit_ranking[0].commit_id.is_none());
    }
}
