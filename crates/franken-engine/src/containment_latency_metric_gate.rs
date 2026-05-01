#![forbid(unsafe_code)]

//! Containment-latency metric gate for signal-to-action evidence.
//!
//! This child gate produces the `containment_latency_median_ms` metric artifact
//! consumed by `disruptive_floor_metric_gate`. Containment latency is measured
//! as `containment_action_applied_at_ms - signal_detected_at_ms` using one
//! monotonic clock source across every trace in the scenario set.

use serde::{Deserialize, Serialize};

use crate::disruptive_floor_metric_gate::{
    DEFAULT_MAX_FRESHNESS_DAYS, DisruptiveMetricId, MetricArtifact,
};
use crate::proof_artifact::validate_sha256;

pub const SCHEMA_VERSION: &str = "franken-engine.containment-latency-metric-gate.v1";
pub const COMPONENT: &str = "containment_latency_metric_gate";
pub const BEAD_ID: &str = "bd-38mby";
pub const CONTAINMENT_LATENCY_THRESHOLD_MS: u64 = 250;
pub const COVERAGE_SCALE_MILLIONTHS: u64 = 1_000_000;
pub const REQUIRED_CLOCK_SOURCE: &str = "monotonic_ms";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentAction {
    Throttle,
    Isolate,
    RevokeCapability,
    KillExecution,
}

impl ContainmentAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Throttle => "throttle",
            Self::Isolate => "isolate",
            Self::RevokeCapability => "revoke_capability",
            Self::KillExecution => "kill_execution",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentLatencyEvidence {
    pub signal_id: String,
    pub trace_id: String,
    pub policy_id: String,
    pub workload_profile: String,
    pub signal_detected_at_ms: u64,
    pub containment_action_applied_at_ms: Option<u64>,
    pub clock_id: String,
    pub clock_source: String,
    pub action: ContainmentAction,
    pub action_command: String,
    pub action_exit_code: i32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentLatencyMetricInput {
    pub code_revision: String,
    pub freshness_days: u64,
    pub scenario_set: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub verification_command: String,
    pub redaction_status: String,
    pub confidence_millionths: u64,
    pub signals: Vec<ContainmentLatencyEvidence>,
}

impl ContainmentLatencyMetricInput {
    pub fn representative_fixture(code_revision: impl Into<String>) -> Self {
        Self {
            code_revision: code_revision.into(),
            freshness_days: 0,
            scenario_set: "policy_signal_to_containment_action_v1".to_string(),
            artifact_path: "artifacts/containment_latency_metric/latency_details.json".to_string(),
            artifact_hash:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            verification_command: "scripts/run_containment_latency_metric_gate.sh ci".to_string(),
            redaction_status: "redacted".to_string(),
            confidence_millionths: 990_000,
            signals: vec![
                containment_signal(
                    "ambient-write-denied",
                    1_000,
                    1_080,
                    ContainmentAction::Isolate,
                ),
                containment_signal(
                    "capability-revoked",
                    2_000,
                    2_120,
                    ContainmentAction::RevokeCapability,
                ),
                containment_signal(
                    "compute-budget-killed",
                    3_000,
                    3_200,
                    ContainmentAction::KillExecution,
                ),
            ],
        }
    }
}

fn containment_signal(
    signal_id: impl Into<String>,
    detected_at_ms: u64,
    applied_at_ms: u64,
    action: ContainmentAction,
) -> ContainmentLatencyEvidence {
    let signal_id = signal_id.into();
    ContainmentLatencyEvidence {
        trace_id: format!("trace-{signal_id}"),
        policy_id: format!("policy-{signal_id}"),
        workload_profile: "extension_host_mixed_policy_signals".to_string(),
        signal_detected_at_ms: detected_at_ms,
        containment_action_applied_at_ms: Some(applied_at_ms),
        clock_id: "proof-clock-1".to_string(),
        clock_source: REQUIRED_CLOCK_SOURCE.to_string(),
        action,
        action_command: format!(
            "frankenctl policy contain --signal {signal_id} --action {}",
            action.as_str()
        ),
        action_exit_code: 0,
        duration_ms: 1,
        signal_id,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentLatencyDecision {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentLatencyStructuredEvent {
    pub metric_id: DisruptiveMetricId,
    pub proof_manifest_id: String,
    pub command_id: String,
    pub signal_id: String,
    pub trace_id: String,
    pub policy_id: String,
    pub workload_profile: String,
    pub signal_detected_at_ms: u64,
    pub containment_action_applied_at_ms: Option<u64>,
    pub latency_ms: Option<u64>,
    pub median_latency_ms: Option<u64>,
    pub threshold_ms: u64,
    pub clock_id: String,
    pub clock_source: String,
    pub action: ContainmentAction,
    pub action_class: String,
    pub coverage_numerator: u64,
    pub coverage_denominator: u64,
    pub coverage_percent: String,
    pub command: String,
    pub exit_code: i32,
    pub decision: String,
    pub reason: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub code_revision: String,
    pub duration_ms: u64,
    pub freshness_days: u64,
    pub redaction_status: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentLatencyMetricReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub metric_artifact: MetricArtifact,
    pub total_signal_events: u64,
    pub contained_signal_events: u64,
    pub median_latency_ms: Option<u64>,
    pub threshold_ms: u64,
    pub coverage_millionths: u64,
    pub decision: ContainmentLatencyDecision,
    pub reason: String,
    pub invalid_trace_ids: Vec<String>,
    pub events: Vec<ContainmentLatencyStructuredEvent>,
}

impl ContainmentLatencyMetricReport {
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Containment Latency Metric Gate\n\n");
        out.push_str(&format!("Decision: `{:?}`\n\n", self.decision));
        out.push_str(&format!(
            "Median latency: `{:?}` ms, threshold: `{}` ms\n\n",
            self.median_latency_ms, self.threshold_ms
        ));
        if !self.invalid_trace_ids.is_empty() {
            out.push_str("Invalid traces:\n");
            for trace_id in &self.invalid_trace_ids {
                out.push_str(&format!("- `{trace_id}`\n"));
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceEvaluation {
    latency_ms: Option<u64>,
    reason: &'static str,
}

pub fn evaluate_containment_latency_metric(
    input: &ContainmentLatencyMetricInput,
) -> ContainmentLatencyMetricReport {
    let mut global_failures = Vec::new();
    if input.code_revision.trim().is_empty() {
        global_failures.push("missing_code_revision");
    }
    if input.artifact_path.trim().is_empty() {
        global_failures.push("missing_artifact_path");
    }
    if validate_sha256(&input.artifact_hash).is_err() {
        global_failures.push("invalid_artifact_hash");
    }
    if input.freshness_days > DEFAULT_MAX_FRESHNESS_DAYS {
        global_failures.push("stale_manifest");
    }
    if input.redaction_status != "redacted" {
        global_failures.push("unredacted_command_transcript");
    }

    let expected_clock_id = input
        .signals
        .first()
        .map(|signal| signal.clock_id.as_str())
        .unwrap_or_default();
    let expected_clock_source = input
        .signals
        .first()
        .map(|signal| signal.clock_source.as_str())
        .unwrap_or_default();

    let mut latencies = Vec::new();
    let mut invalid_trace_ids = Vec::new();
    let mut evaluated = Vec::new();
    for signal in &input.signals {
        let evaluation = evaluate_signal(signal, expected_clock_id, expected_clock_source);
        if let Some(latency_ms) = evaluation.latency_ms {
            latencies.push(latency_ms);
        } else {
            invalid_trace_ids.push(trace_id_for_report(signal));
        }
        evaluated.push(evaluation);
    }

    let total = input.signals.len() as u64;
    let contained = latencies.len() as u64;
    let median_latency_ms = median_latency_ms(latencies);
    let coverage_millionths = coverage_millionths(contained, total);
    let coverage_percent = format!("{:.6}", coverage_millionths as f64 / 10_000.0);
    let threshold_ms = CONTAINMENT_LATENCY_THRESHOLD_MS;
    let passed = total > 0
        && global_failures.is_empty()
        && invalid_trace_ids.is_empty()
        && median_latency_ms.is_some_and(|median| median <= threshold_ms);

    let reason = if total == 0 {
        "missing_signal_trace_inventory".to_string()
    } else if !global_failures.is_empty() {
        global_failures.join(",")
    } else if !invalid_trace_ids.is_empty() {
        "invalid_signal_to_action_trace".to_string()
    } else if median_latency_ms.is_some_and(|median| median > threshold_ms) {
        "median_latency_exceeds_threshold".to_string()
    } else {
        "median_latency_within_threshold".to_string()
    };

    let metric_id = DisruptiveMetricId::ContainmentLatencyMedianMs;
    let fail_closed_observed_value = metric_id.threshold().saturating_add(1);
    let observed_value = if global_failures.is_empty() && invalid_trace_ids.is_empty() {
        median_latency_ms.unwrap_or(fail_closed_observed_value)
    } else {
        median_latency_ms
            .unwrap_or(fail_closed_observed_value)
            .max(fail_closed_observed_value)
    };

    let metric_artifact = MetricArtifact {
        metric_id,
        threshold: metric_id.threshold(),
        observed_value,
        unit: metric_id.unit().to_string(),
        baseline: metric_id.expected_baseline().to_string(),
        candidate: "franken_engine".to_string(),
        denominator_id: format!("containment_signals:{total}"),
        scenario_set: input.scenario_set.clone(),
        artifact_path: input.artifact_path.clone(),
        artifact_hash: input.artifact_hash.clone(),
        code_revision: input.code_revision.clone(),
        freshness_days: input.freshness_days,
        confidence_millionths: input.confidence_millionths.min(COVERAGE_SCALE_MILLIONTHS),
        coverage_millionths,
        verification_command: input.verification_command.clone(),
        redaction_status: input.redaction_status.clone(),
    };

    let events = input
        .signals
        .iter()
        .zip(evaluated)
        .map(|(signal, evaluation)| {
            let contained_trace = evaluation.latency_ms.is_some();
            ContainmentLatencyStructuredEvent {
                metric_id,
                proof_manifest_id: format!("{COMPONENT}:{}", input.scenario_set),
                command_id: format!("containment:{}", signal.trace_id),
                signal_id: signal.signal_id.clone(),
                trace_id: signal.trace_id.clone(),
                policy_id: signal.policy_id.clone(),
                workload_profile: signal.workload_profile.clone(),
                signal_detected_at_ms: signal.signal_detected_at_ms,
                containment_action_applied_at_ms: signal.containment_action_applied_at_ms,
                latency_ms: evaluation.latency_ms,
                median_latency_ms,
                threshold_ms,
                clock_id: signal.clock_id.clone(),
                clock_source: signal.clock_source.clone(),
                action: signal.action,
                action_class: signal.action.as_str().to_string(),
                coverage_numerator: contained,
                coverage_denominator: total,
                coverage_percent: coverage_percent.clone(),
                command: signal.action_command.clone(),
                exit_code: signal.action_exit_code,
                decision: if contained_trace {
                    "contained".to_string()
                } else {
                    "not_contained".to_string()
                },
                reason: evaluation.reason.to_string(),
                artifact_path: input.artifact_path.clone(),
                artifact_hash: input.artifact_hash.clone(),
                code_revision: input.code_revision.clone(),
                duration_ms: signal.duration_ms,
                freshness_days: input.freshness_days,
                redaction_status: input.redaction_status.clone(),
                remediation: if contained_trace {
                    "none".to_string()
                } else {
                    "record monotonic signal/action timestamps and rerun containment verifier"
                        .to_string()
                },
            }
        })
        .collect();

    ContainmentLatencyMetricReport {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        metric_artifact,
        total_signal_events: total,
        contained_signal_events: contained,
        median_latency_ms,
        threshold_ms,
        coverage_millionths,
        decision: if passed {
            ContainmentLatencyDecision::Pass
        } else {
            ContainmentLatencyDecision::FailClosed
        },
        reason,
        invalid_trace_ids,
        events,
    }
}

fn evaluate_signal(
    signal: &ContainmentLatencyEvidence,
    expected_clock_id: &str,
    expected_clock_source: &str,
) -> TraceEvaluation {
    let failure = |reason| TraceEvaluation {
        latency_ms: None,
        reason,
    };

    if signal.signal_id.trim().is_empty() {
        return failure("missing_signal_id");
    }
    if signal.trace_id.trim().is_empty() {
        return failure("missing_trace_id");
    }
    if signal.policy_id.trim().is_empty() {
        return failure("missing_policy_id");
    }
    if signal.workload_profile.trim().is_empty() {
        return failure("missing_workload_profile");
    }
    if signal.clock_id.trim().is_empty() || signal.clock_source.trim().is_empty() {
        return failure("missing_clock_metadata");
    }
    if signal.clock_source != REQUIRED_CLOCK_SOURCE {
        return failure("unsupported_clock_source");
    }
    if signal.clock_id != expected_clock_id || signal.clock_source != expected_clock_source {
        return failure("mixed_clock_metadata");
    }
    if signal.action_command.trim().is_empty() {
        return failure("missing_action_command");
    }
    if signal.action_exit_code != 0 {
        return failure("containment_action_failed");
    }

    let Some(action_at_ms) = signal.containment_action_applied_at_ms else {
        return failure("missing_action_timestamp");
    };
    if action_at_ms < signal.signal_detected_at_ms {
        return failure("non_monotonic_action_timestamp");
    }

    TraceEvaluation {
        latency_ms: Some(action_at_ms - signal.signal_detected_at_ms),
        reason: "signal_to_action_latency_observed",
    }
}

fn trace_id_for_report(signal: &ContainmentLatencyEvidence) -> String {
    if signal.trace_id.trim().is_empty() {
        format!("missing-trace-id:{}", signal.signal_id)
    } else {
        signal.trace_id.clone()
    }
}

pub fn median_latency_ms(mut latencies: Vec<u64>) -> Option<u64> {
    if latencies.is_empty() {
        return None;
    }
    latencies.sort_unstable();
    let middle = latencies.len() / 2;
    if latencies.len().is_multiple_of(2) {
        let lower = latencies[middle - 1];
        let upper = latencies[middle];
        Some(lower + ((upper - lower) / 2))
    } else {
        Some(latencies[middle])
    }
}

pub const fn coverage_millionths(contained: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        ((contained as u128 * COVERAGE_SCALE_MILLIONTHS as u128) / total as u128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disruptive_floor_metric_gate::{
        DisruptiveFloorGateConfig, DisruptiveMetricId, GateDecisionState,
        evaluate_disruptive_floor_gate,
    };

    #[test]
    fn representative_fixture_emits_parent_metric_artifact() {
        let report = evaluate_containment_latency_metric(
            &ContainmentLatencyMetricInput::representative_fixture("rev-under-test"),
        );
        assert_eq!(report.decision, ContainmentLatencyDecision::Pass);
        assert_eq!(report.median_latency_ms, Some(120));
        assert_eq!(
            report.metric_artifact.metric_id,
            DisruptiveMetricId::ContainmentLatencyMedianMs
        );
        assert_eq!(report.metric_artifact.observed_value, 120);
        assert_eq!(report.metric_artifact.baseline, "signal_to_action_trace");
        assert_eq!(
            report.metric_artifact.denominator_id,
            "containment_signals:3"
        );
    }

    #[test]
    fn fixture_json_deserializes_and_passes() {
        let input: ContainmentLatencyMetricInput = serde_json::from_str(include_str!(
            "../tests/fixtures/containment_latency_metric_input_v1.json"
        ))
        .unwrap();
        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.decision, ContainmentLatencyDecision::Pass);
        assert_eq!(report.events.len(), 3);
        assert_eq!(report.median_latency_ms, Some(120));
    }

    #[test]
    fn missing_action_timestamp_fails_closed() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");
        input.signals[1].containment_action_applied_at_ms = None;
        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.decision, ContainmentLatencyDecision::FailClosed);
        assert_eq!(report.contained_signal_events, 2);
        assert_eq!(report.coverage_millionths, 666_666);
        assert_eq!(report.events[1].reason, "missing_action_timestamp");
        assert_eq!(
            report.invalid_trace_ids,
            vec!["trace-capability-revoked".to_string()]
        );
        assert_eq!(report.metric_artifact.observed_value, 251);
    }

    #[test]
    fn non_monotonic_action_timestamp_fails_closed() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");
        input.signals[0].containment_action_applied_at_ms = Some(999);
        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.decision, ContainmentLatencyDecision::FailClosed);
        assert_eq!(report.events[0].reason, "non_monotonic_action_timestamp");
    }

    #[test]
    fn mixed_clock_metadata_fails_closed() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");
        input.signals[2].clock_id = "proof-clock-2".to_string();
        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.decision, ContainmentLatencyDecision::FailClosed);
        assert_eq!(report.events[2].reason, "mixed_clock_metadata");
    }

    #[test]
    fn median_threshold_overage_fails_closed() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");
        input.signals[0].containment_action_applied_at_ms = Some(1_400);
        input.signals[1].containment_action_applied_at_ms = Some(2_360);
        input.signals[2].containment_action_applied_at_ms = Some(3_410);
        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.median_latency_ms, Some(360));
        assert_eq!(report.decision, ContainmentLatencyDecision::FailClosed);
        assert_eq!(report.reason, "median_latency_exceeds_threshold");
        assert_eq!(report.metric_artifact.observed_value, 360);
    }

    #[test]
    fn parent_integrator_accepts_containment_latency_child_metric_artifact() {
        let containment_report = evaluate_containment_latency_metric(
            &ContainmentLatencyMetricInput::representative_fixture("rev-under-test"),
        );
        let config = DisruptiveFloorGateConfig::new("rev-under-test");
        let report = evaluate_disruptive_floor_gate(&config, &[containment_report.metric_artifact]);
        let containment_decision = report
            .metric_decisions
            .iter()
            .find(|decision| decision.metric_id == DisruptiveMetricId::ContainmentLatencyMedianMs)
            .unwrap();
        assert_eq!(containment_decision.reason, "metric_passed");
        assert_eq!(report.decision, GateDecisionState::FailClosed);
        assert!(
            report
                .metric_decisions
                .iter()
                .any(|decision| decision.reason == "missing_metric_artifact")
        );
    }

    #[test]
    fn report_serialization_is_deterministic_for_fixed_input() {
        let report = evaluate_containment_latency_metric(
            &ContainmentLatencyMetricInput::representative_fixture("rev-under-test"),
        );
        let first = serde_json::to_string(&report).unwrap();
        let second = serde_json::to_string(&report).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn even_latency_count_uses_deterministic_midpoint() {
        assert_eq!(median_latency_ms(vec![80, 120, 200, 240]), Some(160));
    }
}
