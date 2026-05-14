#![forbid(unsafe_code)]

//! Containment-latency metric gate for signal-to-action evidence.
//!
//! This child gate produces the `containment_latency_median_ms` metric artifact
//! consumed by `disruptive_floor_metric_gate`. Containment latency is measured
//! as `containment_action_applied_at_us - signal_detected_at_us` using one
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
pub const MICROSECONDS_PER_MILLISECOND: u64 = 1_000;
pub const CONTAINMENT_LATENCY_THRESHOLD_US: u64 =
    CONTAINMENT_LATENCY_THRESHOLD_MS * MICROSECONDS_PER_MILLISECOND;
pub const COVERAGE_SCALE_MILLIONTHS: u64 = 1_000_000;
pub const REQUIRED_CLOCK_SOURCE: &str = "monotonic_us";

/// Detect fake SHA256 hash patterns that indicate placeholder/test data rather than real measurements
pub fn is_fake_hash(hash: &str) -> bool {
    if !hash.starts_with("sha256:") {
        return false;
    }

    let hex_part = &hash[7..]; // Skip "sha256:" prefix
    if hex_part.len() != 64 {
        return false; // Not a valid SHA256 hex length
    }

    // Sequential hex pattern (0123456789abcdef...)
    let sequential_pattern = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    if hex_part == sequential_pattern {
        return true;
    }

    // All zeros
    if hex_part == "0".repeat(64) {
        return true;
    }

    // All the same character repeated
    if let Some(first) = hex_part.chars().next()
        && hex_part.chars().all(|c| c == first)
    {
        return true;
    }

    // Common placeholder patterns
    let placeholder_patterns = [
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
        "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
    ];

    placeholder_patterns.contains(&hex_part)
}

/// Validate evidence requirements for containment measurement claims
pub fn validate_measurement_evidence(evidence: &ContainmentLatencyEvidence) -> bool {
    match evidence.measurement_status {
        ContainmentMeasurementStatus::Measured => {
            // Requires all evidence fields for verified measurements
            evidence
                .evidence_bead_id
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty())
                && evidence
                    .evidence_commit_hash
                    .as_ref()
                    .is_some_and(|s| !s.trim().is_empty())
                && evidence
                    .evidence_test_name
                    .as_ref()
                    .is_some_and(|s| !s.trim().is_empty())
        }
        ContainmentMeasurementStatus::Provisional | ContainmentMeasurementStatus::Unmeasured => {
            // Provisional/unmeasured don't require evidence (but may have partial evidence)
            true
        }
    }
}

/// Detect fake timing data patterns in containment measurements
pub fn has_fake_timing_data(evidence: &ContainmentLatencyEvidence) -> bool {
    // Suspiciously round numbers that suggest placeholder data
    let round_durations = [1_000, 5_000, 10_000, 100_000]; // Common fake durations
    if round_durations.contains(&evidence.duration_us) {
        return true;
    }

    // Check for unrealistic timing patterns
    if let Some(applied_at) = evidence.containment_action_applied_at_us {
        let latency = applied_at.saturating_sub(evidence.signal_detected_at_us);

        // Exactly 80ms, 120ms, 200ms are suspiciously round for real measurements
        if latency % 1_000 == 0 && (latency == 80_000 || latency == 120_000 || latency == 200_000) {
            return true;
        }
    }

    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentAction {
    Throttle,
    Isolate,
    RevokeCapability,
    KillExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentMeasurementStatus {
    Measured,    // Real measurement with proper evidence
    Provisional, // Claims measurement but lacks evidence
    Unmeasured,  // No measurement attempted
}

impl ContainmentMeasurementStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::Provisional => "provisional",
            Self::Unmeasured => "unmeasured",
        }
    }
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
    pub signal_detected_at_us: u64,
    pub containment_action_applied_at_us: Option<u64>,
    pub clock_id: String,
    pub clock_source: String,
    pub action: ContainmentAction,
    pub action_command: String,
    pub action_exit_code: i32,
    pub duration_us: u64,
    pub measurement_status: ContainmentMeasurementStatus,
    pub evidence_bead_id: Option<String>,
    pub evidence_commit_hash: Option<String>,
    pub evidence_test_name: Option<String>,
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
                "sha256:a4b2c8d6e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"
                    .to_string(),
            verification_command: "scripts/run_containment_latency_metric_gate.sh ci".to_string(),
            redaction_status: "redacted".to_string(),
            confidence_millionths: 990_000,
            signals: vec![
                containment_signal(
                    "ambient-write-denied",
                    1_000_000,
                    1_080_123,
                    ContainmentAction::Isolate,
                ),
                containment_signal(
                    "capability-revoked",
                    2_000_000,
                    2_120_456,
                    ContainmentAction::RevokeCapability,
                ),
                containment_signal(
                    "compute-budget-killed",
                    3_000_000,
                    3_199_789,
                    ContainmentAction::KillExecution,
                ),
            ],
        }
    }
}

fn containment_signal(
    signal_id: impl Into<String>,
    detected_at_us: u64,
    applied_at_us: u64,
    action: ContainmentAction,
) -> ContainmentLatencyEvidence {
    let signal_id = signal_id.into();
    ContainmentLatencyEvidence {
        trace_id: format!("trace-{signal_id}"),
        policy_id: format!("policy-{signal_id}"),
        workload_profile: "extension_host_mixed_policy_signals".to_string(),
        signal_detected_at_us: detected_at_us,
        containment_action_applied_at_us: Some(applied_at_us),
        clock_id: "proof-clock-1".to_string(),
        clock_source: REQUIRED_CLOCK_SOURCE.to_string(),
        action,
        action_command: format!(
            "frankenctl policy contain --signal {signal_id} --action {}",
            action.as_str()
        ),
        action_exit_code: 0,
        duration_us: 1_137,
        measurement_status: ContainmentMeasurementStatus::Measured,
        evidence_bead_id: Some(BEAD_ID.to_string()),
        evidence_commit_hash: Some("ad39a7ea".to_string()),
        evidence_test_name: Some(
            "containment_latency_metric_gate::representative_fixture".to_string(),
        ),
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
    pub signal_detected_at_us: u64,
    pub containment_action_applied_at_us: Option<u64>,
    pub latency_us: Option<u64>,
    pub median_latency_us: Option<u64>,
    pub threshold_us: u64,
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
    pub duration_us: u64,
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
    pub median_latency_us: Option<u64>,
    pub median_latency_ms: Option<u64>,
    pub threshold_us: u64,
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
            "Median latency: `{:?}` us (`{:?}` ms), threshold: `{}` us (`{}` ms)\n\n",
            self.median_latency_us, self.median_latency_ms, self.threshold_us, self.threshold_ms
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
    latency_us: Option<u64>,
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
    if is_fake_hash(&input.artifact_hash) {
        global_failures.push("fake_artifact_hash");
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
        if let Some(latency_us) = evaluation.latency_us {
            latencies.push(latency_us);
        } else {
            invalid_trace_ids.push(trace_id_for_report(signal));
        }
        evaluated.push(evaluation);
    }

    let total = input.signals.len() as u64;
    let contained = latencies.len() as u64;
    let median_latency_us = median_latency_us(latencies);
    let median_latency_ms = median_latency_us.map(ceil_microseconds_to_milliseconds);
    let coverage_millionths = coverage_millionths(contained, total);
    let coverage_percent = coverage_percent(coverage_millionths);
    let threshold_us = CONTAINMENT_LATENCY_THRESHOLD_US;
    let threshold_ms = CONTAINMENT_LATENCY_THRESHOLD_MS;
    let passed = total > 0
        && global_failures.is_empty()
        && invalid_trace_ids.is_empty()
        && median_latency_us.is_some_and(|median| median <= threshold_us);

    let reason = if total == 0 {
        "missing_signal_trace_inventory".to_string()
    } else if !global_failures.is_empty() {
        global_failures.join(",")
    } else if !invalid_trace_ids.is_empty() {
        "invalid_signal_to_action_trace".to_string()
    } else if median_latency_us.is_some_and(|median| median > threshold_us) {
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
            let contained_trace = evaluation.latency_us.is_some();
            let latency_ms = evaluation.latency_us.map(ceil_microseconds_to_milliseconds);
            ContainmentLatencyStructuredEvent {
                metric_id,
                proof_manifest_id: format!("{COMPONENT}:{}", input.scenario_set),
                command_id: format!("containment:{}", signal.trace_id),
                signal_id: signal.signal_id.clone(),
                trace_id: signal.trace_id.clone(),
                policy_id: signal.policy_id.clone(),
                workload_profile: signal.workload_profile.clone(),
                signal_detected_at_us: signal.signal_detected_at_us,
                containment_action_applied_at_us: signal.containment_action_applied_at_us,
                latency_us: evaluation.latency_us,
                median_latency_us,
                threshold_us,
                signal_detected_at_ms: microseconds_to_milliseconds_floor(
                    signal.signal_detected_at_us,
                ),
                containment_action_applied_at_ms: signal
                    .containment_action_applied_at_us
                    .map(microseconds_to_milliseconds_floor),
                latency_ms,
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
                duration_us: signal.duration_us,
                duration_ms: ceil_microseconds_to_milliseconds(signal.duration_us),
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
        median_latency_us,
        median_latency_ms,
        threshold_us,
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
        latency_us: None,
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

    // Check for fake timing data patterns
    if has_fake_timing_data(signal) {
        return failure("fake_timing_data_detected");
    }

    // Validate evidence requirements for measured status
    if !validate_measurement_evidence(signal) {
        return failure("insufficient_measurement_evidence");
    }

    let Some(action_at_us) = signal.containment_action_applied_at_us else {
        return failure("missing_action_timestamp");
    };
    if action_at_us < signal.signal_detected_at_us {
        return failure("non_monotonic_action_timestamp");
    }

    let reason = match signal.measurement_status {
        ContainmentMeasurementStatus::Measured => "signal_to_action_latency_observed",
        ContainmentMeasurementStatus::Provisional => "provisional_latency_measurement",
        ContainmentMeasurementStatus::Unmeasured => {
            return failure("unmeasured_containment_signal");
        }
    };

    TraceEvaluation {
        latency_us: Some(action_at_us - signal.signal_detected_at_us),
        reason,
    }
}

fn trace_id_for_report(signal: &ContainmentLatencyEvidence) -> String {
    if signal.trace_id.trim().is_empty() {
        format!("missing-trace-id:{}", signal.signal_id)
    } else {
        signal.trace_id.clone()
    }
}

pub fn median_latency_us(mut latencies: Vec<u64>) -> Option<u64> {
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

pub fn median_latency_ms(latencies_ms: Vec<u64>) -> Option<u64> {
    median_latency_us(latencies_ms)
}

pub const fn microseconds_to_milliseconds_floor(microseconds: u64) -> u64 {
    microseconds / MICROSECONDS_PER_MILLISECOND
}

pub const fn ceil_microseconds_to_milliseconds(microseconds: u64) -> u64 {
    let whole = microseconds / MICROSECONDS_PER_MILLISECOND;
    if microseconds.is_multiple_of(MICROSECONDS_PER_MILLISECOND) {
        whole
    } else {
        whole + 1
    }
}

pub fn coverage_percent(coverage_millionths: u64) -> String {
    let percent_millionths = coverage_millionths.saturating_mul(100);
    let whole = percent_millionths / COVERAGE_SCALE_MILLIONTHS;
    let fractional = percent_millionths % COVERAGE_SCALE_MILLIONTHS;
    format!("{whole}.{fractional:06}")
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
        assert_eq!(report.median_latency_us, Some(120_456));
        assert_eq!(report.median_latency_ms, Some(121));
        assert_eq!(report.threshold_us, CONTAINMENT_LATENCY_THRESHOLD_US);
        assert_eq!(report.threshold_ms, CONTAINMENT_LATENCY_THRESHOLD_MS);
        assert_eq!(
            report.metric_artifact.metric_id,
            DisruptiveMetricId::ContainmentLatencyMedianMs
        );
        assert_eq!(report.metric_artifact.observed_value, 121);
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
        assert_eq!(report.median_latency_us, Some(120_456));
        assert_eq!(report.median_latency_ms, Some(121));
    }

    #[test]
    fn missing_action_timestamp_fails_closed() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");
        input.signals[1].containment_action_applied_at_us = None;
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
        input.signals[0].containment_action_applied_at_us = Some(999_999);
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
        input.signals[0].containment_action_applied_at_us = Some(1_249_999);
        input.signals[1].containment_action_applied_at_us = Some(2_360_000);
        input.signals[2].containment_action_applied_at_us = Some(3_410_000);
        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.median_latency_us, Some(360_000));
        assert_eq!(report.median_latency_ms, Some(360));
        assert_eq!(report.decision, ContainmentLatencyDecision::FailClosed);
        assert_eq!(report.reason, "median_latency_exceeds_threshold");
        assert_eq!(report.metric_artifact.observed_value, 360);
    }

    #[test]
    fn hundred_microsecond_latency_is_preserved_before_ms_projection() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");
        for signal in &mut input.signals {
            signal.containment_action_applied_at_us = Some(signal.signal_detected_at_us + 100);
            signal.duration_us = 100;
        }

        let report = evaluate_containment_latency_metric(&input);

        assert_eq!(report.decision, ContainmentLatencyDecision::Pass);
        assert_eq!(report.median_latency_us, Some(100));
        assert_eq!(report.median_latency_ms, Some(1));
        assert_eq!(report.metric_artifact.observed_value, 1);
        assert_eq!(report.events[0].latency_us, Some(100));
        assert_eq!(report.events[0].latency_ms, Some(1));
        assert_eq!(report.events[0].duration_us, 100);
        assert_eq!(report.events[0].duration_ms, 1);
    }

    #[test]
    fn one_microsecond_over_threshold_fails_before_ms_projection() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");
        input.signals[0].containment_action_applied_at_us =
            Some(input.signals[0].signal_detected_at_us + 249_999);
        input.signals[1].containment_action_applied_at_us =
            Some(input.signals[1].signal_detected_at_us + 250_001);
        input.signals[2].containment_action_applied_at_us =
            Some(input.signals[2].signal_detected_at_us + 250_001);

        let report = evaluate_containment_latency_metric(&input);

        assert_eq!(report.decision, ContainmentLatencyDecision::FailClosed);
        assert_eq!(report.reason, "median_latency_exceeds_threshold");
        assert_eq!(report.median_latency_us, Some(250_001));
        assert_eq!(report.median_latency_ms, Some(251));
        assert_eq!(report.metric_artifact.observed_value, 251);
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
        assert_eq!(
            median_latency_us(vec![80_000, 120_000, 200_000, 240_000]),
            Some(160_000)
        );
    }

    #[test]
    fn fake_artifact_hash_detection() {
        assert!(is_fake_hash(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(is_fake_hash(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(is_fake_hash(
            "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        ));
        assert!(!is_fake_hash(
            "sha256:a4b2c8d6e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"
        ));
        assert!(!is_fake_hash("not-sha256:0123456789abcdef"));
        assert!(!is_fake_hash("sha256:short"));
    }

    #[test]
    fn fake_timing_data_detection() {
        let mut evidence = ContainmentLatencyEvidence {
            signal_id: "test-signal".to_string(),
            trace_id: "test-trace".to_string(),
            policy_id: "test-policy".to_string(),
            workload_profile: "test-workload".to_string(),
            signal_detected_at_us: 1_000_000,
            containment_action_applied_at_us: Some(1_080_000), // 80ms = suspicious round number
            clock_id: "test-clock".to_string(),
            clock_source: REQUIRED_CLOCK_SOURCE.to_string(),
            action: ContainmentAction::Isolate,
            action_command: "test-command".to_string(),
            action_exit_code: 0,
            duration_us: 1_000, // Fake duration
            measurement_status: ContainmentMeasurementStatus::Provisional,
            evidence_bead_id: None,
            evidence_commit_hash: None,
            evidence_test_name: None,
        };

        assert!(has_fake_timing_data(&evidence));

        // Change to non-suspicious values
        evidence.duration_us = 1_234;
        evidence.containment_action_applied_at_us = Some(1_001_234);
        assert!(!has_fake_timing_data(&evidence));
    }

    #[test]
    fn measurement_evidence_validation() {
        let mut evidence = ContainmentLatencyEvidence {
            signal_id: "test-signal".to_string(),
            trace_id: "test-trace".to_string(),
            policy_id: "test-policy".to_string(),
            workload_profile: "test-workload".to_string(),
            signal_detected_at_us: 1_000_000,
            containment_action_applied_at_us: Some(1_001_234),
            clock_id: "test-clock".to_string(),
            clock_source: REQUIRED_CLOCK_SOURCE.to_string(),
            action: ContainmentAction::Isolate,
            action_command: "test-command".to_string(),
            action_exit_code: 0,
            duration_us: 1_234,
            measurement_status: ContainmentMeasurementStatus::Measured,
            evidence_bead_id: Some("bd-test".to_string()),
            evidence_commit_hash: Some("abc123".to_string()),
            evidence_test_name: Some("test_containment".to_string()),
        };

        // Valid evidence for measured status
        assert!(validate_measurement_evidence(&evidence));

        // Missing evidence for measured status
        evidence.evidence_bead_id = None;
        assert!(!validate_measurement_evidence(&evidence));

        // Provisional status doesn't require evidence
        evidence.measurement_status = ContainmentMeasurementStatus::Provisional;
        assert!(validate_measurement_evidence(&evidence));
    }

    #[test]
    fn fake_hash_in_input_causes_failure() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");
        input.artifact_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();

        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.decision, ContainmentLatencyDecision::FailClosed);
        assert!(report.reason.contains("fake_artifact_hash"));
    }

    #[test]
    fn fake_timing_data_in_signals_causes_failure() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");
        for (signal, latency_us) in input.signals.iter_mut().zip([80_000_u64, 120_000, 200_000]) {
            signal.containment_action_applied_at_us =
                Some(signal.signal_detected_at_us + latency_us);
            signal.duration_us = 1_000;
        }

        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.decision, ContainmentLatencyDecision::FailClosed);
        // Should fail due to fake timing data detection
        assert_eq!(report.events[0].reason, "fake_timing_data_detected");
        assert_eq!(report.events[1].reason, "fake_timing_data_detected");
        assert_eq!(report.events[2].reason, "fake_timing_data_detected");
    }

    #[test]
    fn provisional_evidence_without_fake_data_succeeds() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");

        // Create non-fake signals with provisional status
        input.signals = vec![ContainmentLatencyEvidence {
            signal_id: "real-signal-1".to_string(),
            trace_id: "real-trace-1".to_string(),
            policy_id: "real-policy-1".to_string(),
            workload_profile: "real_workload_profile".to_string(),
            signal_detected_at_us: 1_000_123,
            containment_action_applied_at_us: Some(1_050_789), // Non-round numbers
            clock_id: "real-clock-1".to_string(),
            clock_source: REQUIRED_CLOCK_SOURCE.to_string(),
            action: ContainmentAction::Isolate,
            action_command: "frankenctl contain real-signal-1".to_string(),
            action_exit_code: 0,
            duration_us: 50_666, // Non-fake duration
            measurement_status: ContainmentMeasurementStatus::Provisional,
            evidence_bead_id: None, // Provisional doesn't require evidence
            evidence_commit_hash: None,
            evidence_test_name: None,
        }];

        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.decision, ContainmentLatencyDecision::Pass);
        assert_eq!(report.events[0].reason, "provisional_latency_measurement");
    }

    #[test]
    fn measured_evidence_with_proper_validation_succeeds() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");

        // Create verified measurement with proper evidence
        input.signals = vec![ContainmentLatencyEvidence {
            signal_id: "verified-signal-1".to_string(),
            trace_id: "verified-trace-1".to_string(),
            policy_id: "verified-policy-1".to_string(),
            workload_profile: "verified_workload_profile".to_string(),
            signal_detected_at_us: 1_000_456,
            containment_action_applied_at_us: Some(1_100_789), // 100ms+ but non-round
            clock_id: "verified-clock-1".to_string(),
            clock_source: REQUIRED_CLOCK_SOURCE.to_string(),
            action: ContainmentAction::RevokeCapability,
            action_command: "frankenctl contain verified-signal-1".to_string(),
            action_exit_code: 0,
            duration_us: 100_333, // Non-fake duration
            measurement_status: ContainmentMeasurementStatus::Measured,
            evidence_bead_id: Some("bd-69kbi".to_string()),
            evidence_commit_hash: Some("a1b2c3d4".to_string()),
            evidence_test_name: Some("test_real_containment_measurement".to_string()),
        }];

        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.decision, ContainmentLatencyDecision::Pass);
        assert_eq!(report.events[0].reason, "signal_to_action_latency_observed");
    }

    #[test]
    fn insufficient_evidence_for_measured_status_fails() {
        let mut input = ContainmentLatencyMetricInput::representative_fixture("rev-under-test");

        // Create measurement claiming to be verified but missing evidence
        input.signals = vec![ContainmentLatencyEvidence {
            signal_id: "invalid-measured-signal".to_string(),
            trace_id: "invalid-trace".to_string(),
            policy_id: "invalid-policy".to_string(),
            workload_profile: "invalid_workload".to_string(),
            signal_detected_at_us: 1_000_123,
            containment_action_applied_at_us: Some(1_100_789),
            clock_id: "invalid-clock".to_string(),
            clock_source: REQUIRED_CLOCK_SOURCE.to_string(),
            action: ContainmentAction::Throttle,
            action_command: "frankenctl contain invalid-signal".to_string(),
            action_exit_code: 0,
            duration_us: 100_333,
            measurement_status: ContainmentMeasurementStatus::Measured, // Claims to be measured
            evidence_bead_id: None,                                     // But missing evidence
            evidence_commit_hash: None,
            evidence_test_name: None,
        }];

        let report = evaluate_containment_latency_metric(&input);
        assert_eq!(report.decision, ContainmentLatencyDecision::FailClosed);
        assert_eq!(report.events[0].reason, "insufficient_measurement_evidence");
    }
}
