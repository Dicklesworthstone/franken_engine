#![forbid(unsafe_code)]

//! Replay-coverage metric gate for security-critical decisions.
//!
//! This child gate produces the `security_decision_replay_coverage` metric
//! artifact consumed by `disruptive_floor_metric_gate`.

use serde::{Deserialize, Serialize};

use crate::disruptive_floor_metric_gate::{
    DEFAULT_MAX_FRESHNESS_DAYS, DisruptiveMetricId, MetricArtifact,
};
use crate::proof_artifact::validate_sha256;

pub const SCHEMA_VERSION: &str = "franken-engine.replay-coverage-metric-gate.v1";
pub const COMPONENT: &str = "replay_coverage_metric_gate";
pub const BEAD_ID: &str = "bd-2488a";
pub const COVERAGE_SCALE_MILLIONTHS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityDecisionKind {
    Allow,
    Deny,
    Escalate,
}

impl SecurityDecisionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Escalate => "escalate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityDecisionReplayEvidence {
    pub decision_id: String,
    pub decision_kind: SecurityDecisionKind,
    pub security_critical: bool,
    pub trace_id: String,
    pub replay_mode: String,
    pub replay_trace_path: String,
    pub replay_report_path: String,
    pub expected_hash: String,
    pub actual_hash: String,
    pub replay_report_hash: String,
    pub replay_verified: bool,
    pub replay_command: String,
    pub replay_exit_code: i32,
    pub duration_ms: u64,
}

impl SecurityDecisionReplayEvidence {
    pub fn replay_backed(&self) -> bool {
        self.security_critical
            && self.replay_verified
            && self.replay_exit_code == 0
            && self.expected_hash == self.actual_hash
            && !self.replay_trace_path.trim().is_empty()
            && !self.replay_report_path.trim().is_empty()
            && !self.replay_command.trim().is_empty()
            && validate_sha256(&self.replay_report_hash).is_ok()
            && validate_sha256(&self.expected_hash).is_ok()
            && validate_sha256(&self.actual_hash).is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCoverageMetricInput {
    pub code_revision: String,
    pub freshness_days: u64,
    pub scenario_set: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub verification_command: String,
    pub redaction_status: String,
    pub confidence_millionths: u64,
    pub decisions: Vec<SecurityDecisionReplayEvidence>,
}

impl ReplayCoverageMetricInput {
    pub fn representative_fixture(code_revision: impl Into<String>) -> Self {
        Self {
            code_revision: code_revision.into(),
            freshness_days: 0,
            scenario_set: "security_critical_allow_deny_escalate_v1".to_string(),
            artifact_path: "artifacts/replay_coverage_metric/coverage_details.json".to_string(),
            artifact_hash:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            verification_command: "scripts/run_replay_coverage_metric_gate.sh ci".to_string(),
            redaction_status: "redacted".to_string(),
            confidence_millionths: COVERAGE_SCALE_MILLIONTHS,
            decisions: vec![
                replay_evidence("allow-extension-read", SecurityDecisionKind::Allow),
                replay_evidence("deny-ambient-write", SecurityDecisionKind::Deny),
                replay_evidence("escalate-high-risk-signal", SecurityDecisionKind::Escalate),
            ],
        }
    }
}

fn replay_evidence(
    decision_id: impl Into<String>,
    decision_kind: SecurityDecisionKind,
) -> SecurityDecisionReplayEvidence {
    let decision_id = decision_id.into();
    SecurityDecisionReplayEvidence {
        decision_kind,
        security_critical: true,
        trace_id: format!("trace-{decision_id}"),
        replay_mode: "deterministic_strict".to_string(),
        replay_trace_path: format!("artifacts/replay_coverage_metric/traces/{decision_id}.json"),
        replay_report_path: format!("artifacts/replay_coverage_metric/reports/{decision_id}.json"),
        expected_hash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            .to_string(),
        actual_hash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            .to_string(),
        replay_report_hash:
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        replay_verified: true,
        replay_command: format!(
            "frankenctl replay run --trace artifacts/replay_coverage_metric/traces/{decision_id}.json --mode strict"
        ),
        replay_exit_code: 0,
        duration_ms: 1,
        decision_id,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayCoverageDecision {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCoverageStructuredEvent {
    pub metric_id: DisruptiveMetricId,
    pub proof_manifest_id: String,
    pub command_id: String,
    pub decision_id: String,
    pub decision_class: String,
    pub decision_kind: SecurityDecisionKind,
    pub trace_id: String,
    pub replay_mode: String,
    pub security_critical: bool,
    pub replay_verified: bool,
    pub replay_trace_path: String,
    pub replay_report_path: String,
    pub expected_hash: String,
    pub actual_hash: String,
    pub replay_report_hash: String,
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
pub struct ReplayCoverageMetricReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub metric_artifact: MetricArtifact,
    pub total_security_critical_decisions: u64,
    pub replay_backed_security_critical_decisions: u64,
    pub coverage_millionths: u64,
    pub decision: ReplayCoverageDecision,
    pub reason: String,
    pub uncovered_decision_ids: Vec<String>,
    pub events: Vec<ReplayCoverageStructuredEvent>,
}

impl ReplayCoverageMetricReport {
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Replay Coverage Metric Gate\n\n");
        out.push_str(&format!("Decision: `{:?}`\n\n", self.decision));
        out.push_str(&format!(
            "Coverage: `{}` / `{}` security-critical decisions (`{}` millionths)\n\n",
            self.replay_backed_security_critical_decisions,
            self.total_security_critical_decisions,
            self.coverage_millionths
        ));
        if !self.uncovered_decision_ids.is_empty() {
            out.push_str("Uncovered decisions:\n");
            for decision_id in &self.uncovered_decision_ids {
                out.push_str(&format!("- `{decision_id}`\n"));
            }
        }
        out
    }
}

pub fn evaluate_replay_coverage_metric(
    input: &ReplayCoverageMetricInput,
) -> ReplayCoverageMetricReport {
    // The seed inventory is explicit so the gate can fail closed on missing
    // replay evidence before live security-decision logs exist.
    let critical_decisions = input
        .decisions
        .iter()
        .filter(|decision| decision.security_critical)
        .collect::<Vec<_>>();
    let total = critical_decisions.len() as u64;
    let mut covered = 0_u64;
    let mut uncovered_decision_ids = Vec::new();
    let mut events = Vec::new();
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

    for decision in &critical_decisions {
        let replay_backed = decision.replay_backed();
        if replay_backed {
            covered += 1;
        } else {
            uncovered_decision_ids.push(decision.decision_id.clone());
        }
    }

    let coverage_millionths = coverage_millionths(covered, total);
    let coverage_percent = format!("{:.6}", coverage_millionths as f64 / 10_000.0);
    for decision in &critical_decisions {
        let replay_backed = decision.replay_backed();
        let event_reason = if replay_backed {
            "replay_artifact_verified"
        } else if decision.replay_trace_path.trim().is_empty() {
            "missing_replay_trace"
        } else if decision.replay_report_path.trim().is_empty() {
            "missing_replay_report"
        } else if decision.expected_hash != decision.actual_hash {
            "nondeterministic_replay_output"
        } else if decision.replay_exit_code != 0 {
            "replay_command_failed"
        } else {
            "missing_or_unverified_replay_artifact"
        }
        .to_string();

        events.push(ReplayCoverageStructuredEvent {
            metric_id: DisruptiveMetricId::SecurityDecisionReplayCoverage,
            proof_manifest_id: format!("{COMPONENT}:{}", input.scenario_set),
            command_id: format!("replay:{}", decision.trace_id),
            decision_id: decision.decision_id.clone(),
            decision_class: decision.decision_kind.as_str().to_string(),
            decision_kind: decision.decision_kind,
            trace_id: decision.trace_id.clone(),
            replay_mode: decision.replay_mode.clone(),
            security_critical: decision.security_critical,
            replay_verified: decision.replay_verified,
            replay_trace_path: decision.replay_trace_path.clone(),
            replay_report_path: decision.replay_report_path.clone(),
            expected_hash: decision.expected_hash.clone(),
            actual_hash: decision.actual_hash.clone(),
            replay_report_hash: decision.replay_report_hash.clone(),
            coverage_numerator: covered,
            coverage_denominator: total,
            coverage_percent: coverage_percent.clone(),
            command: decision.replay_command.clone(),
            exit_code: decision.replay_exit_code,
            decision: if replay_backed {
                "covered".to_string()
            } else {
                "uncovered".to_string()
            },
            reason: event_reason,
            artifact_path: input.artifact_path.clone(),
            artifact_hash: input.artifact_hash.clone(),
            code_revision: input.code_revision.clone(),
            duration_ms: decision.duration_ms,
            freshness_days: input.freshness_days,
            redaction_status: input.redaction_status.clone(),
            remediation: if replay_backed {
                "none".to_string()
            } else {
                "record a replay trace, rerun strict replay, and compare deterministic output hashes"
                    .to_string()
            },
        });
    }

    let metric_id = DisruptiveMetricId::SecurityDecisionReplayCoverage;
    let metric_artifact = MetricArtifact {
        metric_id,
        threshold: metric_id.threshold(),
        observed_value: coverage_millionths,
        unit: metric_id.unit().to_string(),
        baseline: metric_id.expected_baseline().to_string(),
        candidate: "franken_engine".to_string(),
        denominator_id: format!("security_critical_decisions:{total}"),
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

    let passed =
        total > 0 && coverage_millionths == COVERAGE_SCALE_MILLIONTHS && global_failures.is_empty();
    ReplayCoverageMetricReport {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        metric_artifact,
        total_security_critical_decisions: total,
        replay_backed_security_critical_decisions: covered,
        coverage_millionths,
        decision: if passed {
            ReplayCoverageDecision::Pass
        } else {
            ReplayCoverageDecision::FailClosed
        },
        reason: if total == 0 {
            "missing_security_critical_decision_inventory".to_string()
        } else if !global_failures.is_empty() {
            global_failures.join(",")
        } else if passed {
            "all_security_critical_decisions_replay_backed".to_string()
        } else {
            "uncovered_security_critical_decisions".to_string()
        },
        uncovered_decision_ids,
        events,
    }
}

pub const fn coverage_millionths(covered: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        ((covered as u128 * COVERAGE_SCALE_MILLIONTHS as u128) / total as u128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disruptive_floor_metric_gate::{
        DisruptiveFloorGateConfig, GateDecisionState, evaluate_disruptive_floor_gate,
    };

    #[test]
    fn full_security_decision_coverage_emits_parent_metric_artifact() {
        let report = evaluate_replay_coverage_metric(
            &ReplayCoverageMetricInput::representative_fixture("rev-under-test"),
        );
        assert_eq!(report.decision, ReplayCoverageDecision::Pass);
        assert_eq!(report.coverage_millionths, COVERAGE_SCALE_MILLIONTHS);
        assert_eq!(
            report.metric_artifact.metric_id,
            DisruptiveMetricId::SecurityDecisionReplayCoverage
        );
        assert_eq!(report.metric_artifact.observed_value, 1_000_000);
        assert_eq!(
            report.metric_artifact.baseline,
            "security_decision_inventory"
        );
    }

    #[test]
    fn uncovered_security_decision_fails_closed() {
        let mut input = ReplayCoverageMetricInput::representative_fixture("rev-under-test");
        input.decisions[1].replay_verified = false;
        let report = evaluate_replay_coverage_metric(&input);
        assert_eq!(report.decision, ReplayCoverageDecision::FailClosed);
        assert_eq!(report.replay_backed_security_critical_decisions, 2);
        assert_eq!(report.total_security_critical_decisions, 3);
        assert_eq!(report.coverage_millionths, 666_666);
        assert_eq!(
            report.uncovered_decision_ids,
            vec!["deny-ambient-write".to_string()]
        );
    }

    #[test]
    fn empty_security_decision_inventory_fails_closed() {
        let mut input = ReplayCoverageMetricInput::representative_fixture("rev-under-test");
        input.decisions.clear();
        let report = evaluate_replay_coverage_metric(&input);
        assert_eq!(report.decision, ReplayCoverageDecision::FailClosed);
        assert_eq!(
            report.reason,
            "missing_security_critical_decision_inventory"
        );
        assert_eq!(report.coverage_millionths, 0);
    }

    #[test]
    fn non_security_decisions_do_not_expand_denominator() {
        let mut input = ReplayCoverageMetricInput::representative_fixture("rev-under-test");
        input.decisions.push(SecurityDecisionReplayEvidence {
            decision_id: "non-critical-observation".to_string(),
            decision_kind: SecurityDecisionKind::Allow,
            security_critical: false,
            trace_id: "trace-non-critical-observation".to_string(),
            replay_mode: "deterministic_strict".to_string(),
            replay_trace_path: String::new(),
            replay_report_path: String::new(),
            expected_hash: String::new(),
            actual_hash: String::new(),
            replay_report_hash: String::new(),
            replay_verified: false,
            replay_command: String::new(),
            replay_exit_code: 1,
            duration_ms: 0,
        });
        let report = evaluate_replay_coverage_metric(&input);
        assert_eq!(report.total_security_critical_decisions, 3);
        assert_eq!(report.coverage_millionths, 1_000_000);
    }

    #[test]
    fn missing_trace_fails_closed() {
        let mut input = ReplayCoverageMetricInput::representative_fixture("rev-under-test");
        input.decisions[0].replay_trace_path.clear();
        let report = evaluate_replay_coverage_metric(&input);
        assert_eq!(report.decision, ReplayCoverageDecision::FailClosed);
        assert_eq!(report.coverage_millionths, 666_666);
        assert_eq!(report.events[0].reason, "missing_replay_trace");
    }

    #[test]
    fn nondeterministic_replay_output_fails_closed() {
        let mut input = ReplayCoverageMetricInput::representative_fixture("rev-under-test");
        input.decisions[0].actual_hash =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let report = evaluate_replay_coverage_metric(&input);
        assert_eq!(report.decision, ReplayCoverageDecision::FailClosed);
        assert_eq!(report.events[0].reason, "nondeterministic_replay_output");
    }

    #[test]
    fn stale_manifest_fails_closed_even_with_complete_coverage() {
        let mut input = ReplayCoverageMetricInput::representative_fixture("rev-under-test");
        input.freshness_days = DEFAULT_MAX_FRESHNESS_DAYS + 1;
        let report = evaluate_replay_coverage_metric(&input);
        assert_eq!(report.decision, ReplayCoverageDecision::FailClosed);
        assert_eq!(report.coverage_millionths, 1_000_000);
        assert_eq!(report.reason, "stale_manifest");
    }

    #[test]
    fn unclassified_decision_kind_is_rejected_by_deserializer() {
        let json = r#"{
          "code_revision": "rev-under-test",
          "freshness_days": 0,
          "scenario_set": "security_critical_allow_deny_escalate_v1",
          "artifact_path": "artifacts/replay_coverage_metric/coverage_details.json",
          "artifact_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "verification_command": "scripts/run_replay_coverage_metric_gate.sh ci",
          "redaction_status": "redacted",
          "confidence_millionths": 1000000,
          "decisions": [
            {
              "decision_id": "unknown-decision",
              "decision_kind": "prompt_engineer",
              "security_critical": true,
              "trace_id": "trace-unknown-decision",
              "replay_mode": "deterministic_strict",
              "replay_trace_path": "artifacts/replay_coverage_metric/traces/unknown.json",
              "replay_report_path": "artifacts/replay_coverage_metric/reports/unknown.json",
              "expected_hash": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
              "actual_hash": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
              "replay_report_hash": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
              "replay_verified": true,
              "replay_command": "frankenctl replay run --trace artifacts/replay_coverage_metric/traces/unknown.json --mode strict",
              "replay_exit_code": 0,
              "duration_ms": 1
            }
          ]
        }"#;
        assert!(serde_json::from_str::<ReplayCoverageMetricInput>(json).is_err());
    }

    #[test]
    fn report_serialization_is_deterministic_for_fixed_input() {
        let report = evaluate_replay_coverage_metric(
            &ReplayCoverageMetricInput::representative_fixture("rev-under-test"),
        );
        let first = serde_json::to_string(&report).unwrap();
        let second = serde_json::to_string(&report).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn fixture_json_deserializes_and_passes() {
        let input: ReplayCoverageMetricInput = serde_json::from_str(include_str!(
            "../tests/fixtures/replay_coverage_metric_input_v1.json"
        ))
        .unwrap();
        let report = evaluate_replay_coverage_metric(&input);
        assert_eq!(report.decision, ReplayCoverageDecision::Pass);
        assert_eq!(report.events.len(), 3);
    }

    #[test]
    fn parent_integrator_accepts_replay_child_metric_artifact() {
        let replay_report = evaluate_replay_coverage_metric(
            &ReplayCoverageMetricInput::representative_fixture("rev-under-test"),
        );
        let config = DisruptiveFloorGateConfig::new("rev-under-test");
        let report = evaluate_disruptive_floor_gate(&config, &[replay_report.metric_artifact]);
        let replay_decision = report
            .metric_decisions
            .iter()
            .find(|decision| {
                decision.metric_id == DisruptiveMetricId::SecurityDecisionReplayCoverage
            })
            .unwrap();
        assert_eq!(replay_decision.reason, "metric_passed");
        assert_eq!(report.decision, GateDecisionState::FailClosed);
        assert!(
            report
                .metric_decisions
                .iter()
                .any(|decision| decision.reason == "missing_metric_artifact")
        );
    }

    #[test]
    fn markdown_report_names_uncovered_decisions() {
        let mut input = ReplayCoverageMetricInput::representative_fixture("rev-under-test");
        input.decisions[2].replay_report_hash.clear();
        let report = evaluate_replay_coverage_metric(&input);
        let markdown = report.to_markdown();
        assert!(markdown.contains("Replay Coverage Metric Gate"));
        assert!(markdown.contains("escalate-high-risk-signal"));
    }
}
