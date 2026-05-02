#![forbid(unsafe_code)]

//! Disruptive-floor metric gate.
//!
//! This gate is intentionally an integrator: it does not manufacture benchmark,
//! security, replay, or feature-catalog evidence. It consumes child metric
//! artifacts and fails closed unless every disruptive-floor claim has fresh,
//! denominator-matched, revision-matched proof.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "franken-engine.disruptive-floor-metric-gate.v1";
pub const COMPONENT: &str = "disruptive_floor_metric_gate";
pub const BEAD_ID: &str = "bd-x7nod";

pub const DEFAULT_MAX_FRESHNESS_DAYS: u64 = 14;
pub const DEFAULT_MIN_CONFIDENCE_MILLIONTHS: u64 = 950_000;
pub const DEFAULT_MIN_COVERAGE_MILLIONTHS: u64 = 950_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisruptiveMetricId {
    WeightedThroughputNodeBun,
    RedTeamCompromiseRateReduction,
    ContainmentLatencyMedianMs,
    SecurityDecisionReplayCoverage,
    ImpossibleByDefaultProductionFeatures,
}

impl DisruptiveMetricId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WeightedThroughputNodeBun => "weighted_throughput_node_bun",
            Self::RedTeamCompromiseRateReduction => "red_team_compromise_rate_reduction",
            Self::ContainmentLatencyMedianMs => "containment_latency_median_ms",
            Self::SecurityDecisionReplayCoverage => "security_decision_replay_coverage",
            Self::ImpossibleByDefaultProductionFeatures => {
                "impossible_by_default_production_features"
            }
        }
    }

    pub const fn threshold(self) -> u64 {
        match self {
            Self::WeightedThroughputNodeBun => 3,
            Self::RedTeamCompromiseRateReduction => 10,
            Self::ContainmentLatencyMedianMs => 250,
            Self::SecurityDecisionReplayCoverage => 1_000_000,
            Self::ImpossibleByDefaultProductionFeatures => 3,
        }
    }

    pub const fn unit(self) -> &'static str {
        match self {
            Self::WeightedThroughputNodeBun => "x_weighted_geomean",
            Self::RedTeamCompromiseRateReduction => "x_rate_reduction",
            Self::ContainmentLatencyMedianMs => "ms",
            Self::SecurityDecisionReplayCoverage => "millionths",
            Self::ImpossibleByDefaultProductionFeatures => "feature_count",
        }
    }

    pub const fn comparison(self) -> ThresholdComparison {
        match self {
            Self::ContainmentLatencyMedianMs => ThresholdComparison::AtMost,
            Self::WeightedThroughputNodeBun
            | Self::RedTeamCompromiseRateReduction
            | Self::SecurityDecisionReplayCoverage
            | Self::ImpossibleByDefaultProductionFeatures => ThresholdComparison::AtLeast,
        }
    }

    pub const fn claim_id(self) -> &'static str {
        match self {
            Self::WeightedThroughputNodeBun => "disruptive_floor.throughput_geomean_3x",
            Self::RedTeamCompromiseRateReduction => "disruptive_floor.red_team_compromise_rate_10x",
            Self::ContainmentLatencyMedianMs => "disruptive_floor.containment_latency_250ms",
            Self::SecurityDecisionReplayCoverage => {
                "disruptive_floor.security_decision_replay_coverage_100pct"
            }
            Self::ImpossibleByDefaultProductionFeatures => {
                "disruptive_floor.impossible_by_default_features_3"
            }
        }
    }

    pub const fn owning_bead(self) -> &'static str {
        match self {
            Self::WeightedThroughputNodeBun => "bd-y6v8s",
            Self::RedTeamCompromiseRateReduction => "bd-1vwza",
            Self::ContainmentLatencyMedianMs => "bd-38mby",
            Self::SecurityDecisionReplayCoverage => "bd-2488a",
            Self::ImpossibleByDefaultProductionFeatures => "bd-1qr4f",
        }
    }

    pub const fn expected_baseline(self) -> &'static str {
        match self {
            Self::WeightedThroughputNodeBun | Self::RedTeamCompromiseRateReduction => {
                "node_and_bun"
            }
            Self::ContainmentLatencyMedianMs => "signal_to_action_trace",
            Self::SecurityDecisionReplayCoverage => "security_decision_inventory",
            Self::ImpossibleByDefaultProductionFeatures => "feature_catalog",
        }
    }

    pub fn downgrade_text(self) -> String {
        match self {
            Self::WeightedThroughputNodeBun => {
                "State >=3x weighted-geometric-mean throughput versus Node/Bun as a target until fresh denominator-matched benchmark evidence passes.".to_string()
            }
            Self::RedTeamCompromiseRateReduction => {
                "State >=10x red-team host compromise-rate reduction versus Node/Bun defaults as a target until fresh security evidence passes.".to_string()
            }
            Self::ContainmentLatencyMedianMs => {
                "State <=250ms median containment latency as a target until fresh signal-to-action timing evidence passes.".to_string()
            }
            Self::SecurityDecisionReplayCoverage => {
                "State 100% replay coverage for security-critical allow/deny/escalation decisions as a target until fresh replay inventory evidence passes.".to_string()
            }
            Self::ImpossibleByDefaultProductionFeatures => {
                "State production impossible-by-default feature count as a target until the feature catalog proves at least three live features.".to_string()
            }
        }
    }

    pub const ALL: [Self; 5] = [
        Self::WeightedThroughputNodeBun,
        Self::RedTeamCompromiseRateReduction,
        Self::ContainmentLatencyMedianMs,
        Self::SecurityDecisionReplayCoverage,
        Self::ImpossibleByDefaultProductionFeatures,
    ];
}

impl fmt::Display for DisruptiveMetricId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdComparison {
    AtLeast,
    AtMost,
}

impl ThresholdComparison {
    pub const fn passes(self, observed_value: u64, threshold: u64) -> bool {
        match self {
            Self::AtLeast => observed_value >= threshold,
            Self::AtMost => observed_value <= threshold,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricArtifact {
    pub metric_id: DisruptiveMetricId,
    pub threshold: u64,
    pub observed_value: u64,
    pub unit: String,
    pub baseline: String,
    pub candidate: String,
    pub denominator_id: String,
    pub scenario_set: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub code_revision: String,
    pub freshness_days: u64,
    pub confidence_millionths: u64,
    pub coverage_millionths: u64,
    pub verification_command: String,
    pub redaction_status: String,
}

impl MetricArtifact {
    pub fn for_metric(metric_id: DisruptiveMetricId, observed_value: u64) -> Self {
        Self {
            metric_id,
            threshold: metric_id.threshold(),
            observed_value,
            unit: metric_id.unit().to_string(),
            baseline: metric_id.expected_baseline().to_string(),
            candidate: "franken_engine".to_string(),
            denominator_id: format!("denominator.{}", metric_id.as_str()),
            scenario_set: format!("scenario_set.{}", metric_id.as_str()),
            artifact_path: format!("artifacts/{}/run_manifest.json", metric_id.as_str()),
            artifact_hash: "sha256:0123456789abcdef".to_string(),
            code_revision: "rev-under-test".to_string(),
            freshness_days: 0,
            confidence_millionths: 990_000,
            coverage_millionths: 990_000,
            verification_command: format!("scripts/run_{}_gate.sh ci", metric_id.as_str()),
            redaction_status: "redacted".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisruptiveFloorGateConfig {
    pub max_freshness_days: u64,
    pub min_confidence_millionths: u64,
    pub min_coverage_millionths: u64,
    pub code_revision: String,
    pub required_metrics: BTreeSet<DisruptiveMetricId>,
}

impl DisruptiveFloorGateConfig {
    pub fn new(code_revision: impl Into<String>) -> Self {
        Self {
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            min_confidence_millionths: DEFAULT_MIN_CONFIDENCE_MILLIONTHS,
            min_coverage_millionths: DEFAULT_MIN_COVERAGE_MILLIONTHS,
            code_revision: code_revision.into(),
            required_metrics: DisruptiveMetricId::ALL.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricDecisionState {
    Pass,
    Fail,
}

impl MetricDecisionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricDecision {
    pub metric_id: DisruptiveMetricId,
    pub threshold: u64,
    pub observed_value: Option<u64>,
    pub unit: String,
    pub baseline: String,
    pub candidate: String,
    pub denominator_id: String,
    pub scenario_set: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub code_revision: String,
    pub freshness_days: Option<u64>,
    pub decision: MetricDecisionState,
    pub downgrade_text: String,
    pub reason: String,
    pub verification_command: String,
    pub redaction_status: String,
}

impl MetricDecision {
    fn missing(metric_id: DisruptiveMetricId) -> Self {
        Self {
            metric_id,
            threshold: metric_id.threshold(),
            observed_value: None,
            unit: metric_id.unit().to_string(),
            baseline: metric_id.expected_baseline().to_string(),
            candidate: "franken_engine".to_string(),
            denominator_id: String::new(),
            scenario_set: String::new(),
            artifact_path: String::new(),
            artifact_hash: String::new(),
            code_revision: String::new(),
            freshness_days: None,
            decision: MetricDecisionState::Fail,
            downgrade_text: metric_id.downgrade_text(),
            reason: "missing_metric_artifact".to_string(),
            verification_command: String::new(),
            redaction_status: String::new(),
        }
    }

    pub const fn passed(&self) -> bool {
        matches!(self.decision, MetricDecisionState::Pass)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecisionState {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimMatrixProjection {
    pub claim_id: String,
    pub claim_scope: String,
    pub source_path: String,
    pub source_span: String,
    pub allowed_state: String,
    pub actual_wording_state: String,
    pub artifact_path: String,
    pub verification_command: String,
    pub freshness_days: Option<u64>,
    pub decision: String,
    pub reason: String,
    pub owning_bead: String,
    pub downgrade_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisruptiveFloorGateReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub code_revision: String,
    pub decision: GateDecisionState,
    pub observed_disruptive_floor_wording_allowed: bool,
    pub metric_decisions: Vec<MetricDecision>,
    pub claim_matrix_projection: Vec<ClaimMatrixProjection>,
    pub downgrade_texts: BTreeMap<String, String>,
}

impl DisruptiveFloorGateReport {
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Disruptive Floor Metric Gate\n\n");
        out.push_str(&format!("Decision: `{:?}`\n\n", self.decision));
        out.push_str("| Metric | Decision | Observed | Threshold | Reason |\n");
        out.push_str("|---|---:|---:|---:|---|\n");
        for decision in &self.metric_decisions {
            let observed = decision
                .observed_value
                .map(|value| value.to_string())
                .unwrap_or_else(|| "missing".to_string());
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | {} |\n",
                decision.metric_id,
                decision.decision.as_str(),
                observed,
                decision.threshold,
                decision.reason
            ));
        }
        out
    }
}

pub fn evaluate_disruptive_floor_gate(
    config: &DisruptiveFloorGateConfig,
    artifacts: &[MetricArtifact],
) -> DisruptiveFloorGateReport {
    let mut by_metric: BTreeMap<DisruptiveMetricId, Vec<&MetricArtifact>> = BTreeMap::new();
    for artifact in artifacts {
        by_metric
            .entry(artifact.metric_id)
            .or_default()
            .push(artifact);
    }

    let mut decisions = Vec::new();
    for metric_id in &config.required_metrics {
        let decision = match by_metric.get(metric_id).map(Vec::as_slice) {
            None | Some([]) => MetricDecision::missing(*metric_id),
            Some([artifact]) => evaluate_metric(config, artifact),
            Some(_) => duplicate_metric_decision(*metric_id),
        };
        decisions.push(decision);
    }

    let observed_allowed = decisions.iter().all(MetricDecision::passed);
    let claim_matrix_projection = decisions
        .iter()
        .map(|decision| claim_matrix_projection(decision, observed_allowed))
        .collect::<Vec<_>>();
    let downgrade_texts = decisions
        .iter()
        .filter(|decision| !decision.passed())
        .map(|decision| {
            (
                decision.metric_id.claim_id().to_string(),
                decision.downgrade_text.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    DisruptiveFloorGateReport {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        code_revision: config.code_revision.clone(),
        decision: if observed_allowed {
            GateDecisionState::Pass
        } else {
            GateDecisionState::FailClosed
        },
        observed_disruptive_floor_wording_allowed: observed_allowed,
        metric_decisions: decisions,
        claim_matrix_projection,
        downgrade_texts,
    }
}

fn duplicate_metric_decision(metric_id: DisruptiveMetricId) -> MetricDecision {
    let mut decision = MetricDecision::missing(metric_id);
    decision.reason = "duplicate_metric_artifact".to_string();
    decision
}

fn evaluate_metric(
    config: &DisruptiveFloorGateConfig,
    artifact: &MetricArtifact,
) -> MetricDecision {
    let mut reasons = Vec::new();

    if artifact.threshold != artifact.metric_id.threshold() {
        reasons.push("threshold_mismatch");
    }
    if artifact.unit != artifact.metric_id.unit() {
        reasons.push("unit_mismatch");
    }
    if artifact.baseline != artifact.metric_id.expected_baseline() {
        reasons.push("baseline_mismatch");
    }
    if artifact.candidate.trim().is_empty() {
        reasons.push("missing_candidate");
    }
    if artifact.denominator_id.trim().is_empty() {
        reasons.push("missing_denominator");
    }
    if artifact.scenario_set.trim().is_empty() {
        reasons.push("missing_scenario_set");
    }
    if artifact.artifact_path.trim().is_empty() {
        reasons.push("missing_artifact_path");
    }
    if !artifact.artifact_hash.starts_with("sha256:") {
        reasons.push("missing_artifact_hash");
    }
    if artifact.code_revision != config.code_revision {
        reasons.push("code_revision_mismatch");
    }
    if artifact.freshness_days > config.max_freshness_days {
        reasons.push("stale_artifact");
    }
    if artifact.confidence_millionths < config.min_confidence_millionths {
        reasons.push("confidence_below_threshold");
    }
    if artifact.coverage_millionths < config.min_coverage_millionths {
        reasons.push("coverage_below_threshold");
    }
    if !artifact
        .metric_id
        .comparison()
        .passes(artifact.observed_value, artifact.threshold)
    {
        reasons.push("observed_value_misses_threshold");
    }

    let passed = reasons.is_empty();
    MetricDecision {
        metric_id: artifact.metric_id,
        threshold: artifact.threshold,
        observed_value: Some(artifact.observed_value),
        unit: artifact.unit.clone(),
        baseline: artifact.baseline.clone(),
        candidate: artifact.candidate.clone(),
        denominator_id: artifact.denominator_id.clone(),
        scenario_set: artifact.scenario_set.clone(),
        artifact_path: artifact.artifact_path.clone(),
        artifact_hash: artifact.artifact_hash.clone(),
        code_revision: artifact.code_revision.clone(),
        freshness_days: Some(artifact.freshness_days),
        decision: if passed {
            MetricDecisionState::Pass
        } else {
            MetricDecisionState::Fail
        },
        downgrade_text: artifact.metric_id.downgrade_text(),
        reason: if passed {
            "metric_passed".to_string()
        } else {
            reasons.join(",")
        },
        verification_command: artifact.verification_command.clone(),
        redaction_status: artifact.redaction_status.clone(),
    }
}

fn claim_matrix_projection(
    decision: &MetricDecision,
    observed_allowed: bool,
) -> ClaimMatrixProjection {
    ClaimMatrixProjection {
        claim_id: decision.metric_id.claim_id().to_string(),
        claim_scope: "disruptive_floor".to_string(),
        source_path: "PLAN_TO_CREATE_FRANKEN_ENGINE.md".to_string(),
        source_span: "disruptive-floor metrics".to_string(),
        allowed_state: if observed_allowed && decision.passed() {
            "observed".to_string()
        } else {
            "target".to_string()
        },
        actual_wording_state: if observed_allowed && decision.passed() {
            "observed".to_string()
        } else {
            "downgrade_required".to_string()
        },
        artifact_path: decision.artifact_path.clone(),
        verification_command: decision.verification_command.clone(),
        freshness_days: decision.freshness_days,
        decision: decision.decision.as_str().to_string(),
        reason: decision.reason.clone(),
        owning_bead: decision.metric_id.owning_bead().to_string(),
        downgrade_text: decision.downgrade_text.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing_artifacts() -> Vec<MetricArtifact> {
        DisruptiveMetricId::ALL
            .into_iter()
            .map(|metric_id| MetricArtifact::for_metric(metric_id, metric_id.threshold()))
            .collect()
    }

    fn config() -> DisruptiveFloorGateConfig {
        DisruptiveFloorGateConfig::new("rev-under-test")
    }

    #[test]
    fn all_metrics_pass_enables_observed_wording() {
        let report = evaluate_disruptive_floor_gate(&config(), &passing_artifacts());
        assert_eq!(report.decision, GateDecisionState::Pass);
        assert!(report.observed_disruptive_floor_wording_allowed);
        assert!(report.metric_decisions.iter().all(MetricDecision::passed));
        assert!(report.downgrade_texts.is_empty());
    }

    #[test]
    fn parent_accepts_replay_coverage_child_artifact() {
        let child_report = crate::replay_coverage_metric_gate::evaluate_replay_coverage_metric(
            &crate::replay_coverage_metric_gate::ReplayCoverageMetricInput::representative_fixture(
                "rev-under-test",
            ),
        );
        let mut artifacts = passing_artifacts();
        let replay_slot = artifacts
            .iter_mut()
            .find(|artifact| {
                artifact.metric_id == DisruptiveMetricId::SecurityDecisionReplayCoverage
            })
            .unwrap();
        *replay_slot = child_report.metric_artifact;

        let report = evaluate_disruptive_floor_gate(&config(), &artifacts);
        assert_eq!(report.decision, GateDecisionState::Pass);
        assert!(report.observed_disruptive_floor_wording_allowed);
        assert!(report.metric_decisions.iter().all(MetricDecision::passed));
    }

    #[test]
    fn parent_rejects_provisional_replay_child_artifact() {
        let child_report = crate::replay_coverage_metric_gate::evaluate_replay_coverage_metric(
            &crate::replay_coverage_metric_gate::ReplayCoverageMetricInput::provisional_fixture(
                "rev-under-test",
            ),
        );
        assert_eq!(
            child_report.decision,
            crate::replay_coverage_metric_gate::ReplayCoverageDecision::FailClosed
        );

        let mut artifacts = passing_artifacts();
        let replay_slot = artifacts
            .iter_mut()
            .find(|artifact| {
                artifact.metric_id == DisruptiveMetricId::SecurityDecisionReplayCoverage
            })
            .unwrap();
        *replay_slot = child_report.metric_artifact;

        let report = evaluate_disruptive_floor_gate(&config(), &artifacts);
        let replay_decision = report
            .metric_decisions
            .iter()
            .find(|decision| {
                decision.metric_id == DisruptiveMetricId::SecurityDecisionReplayCoverage
            })
            .unwrap();

        assert_eq!(report.decision, GateDecisionState::FailClosed);
        assert!(!report.observed_disruptive_floor_wording_allowed);
        assert_eq!(replay_decision.decision, MetricDecisionState::Fail);
        assert!(replay_decision.reason.contains("coverage_below_threshold"));
        assert!(
            replay_decision
                .reason
                .contains("observed_value_misses_threshold")
        );
    }

    #[test]
    fn parent_accepts_containment_latency_child_artifact() {
        let child_report =
            crate::containment_latency_metric_gate::evaluate_containment_latency_metric(
                &crate::containment_latency_metric_gate::ContainmentLatencyMetricInput::representative_fixture(
                    "rev-under-test",
                ),
            );
        let mut artifacts = passing_artifacts();
        let containment_slot = artifacts
            .iter_mut()
            .find(|artifact| artifact.metric_id == DisruptiveMetricId::ContainmentLatencyMedianMs)
            .unwrap();
        *containment_slot = child_report.metric_artifact;

        let report = evaluate_disruptive_floor_gate(&config(), &artifacts);
        assert_eq!(report.decision, GateDecisionState::Pass);
        assert!(report.observed_disruptive_floor_wording_allowed);
        assert!(report.metric_decisions.iter().all(MetricDecision::passed));
    }

    #[test]
    fn stale_artifact_fails_closed_with_downgrade() {
        let mut artifacts = passing_artifacts();
        artifacts[0].freshness_days = DEFAULT_MAX_FRESHNESS_DAYS + 1;
        let report = evaluate_disruptive_floor_gate(&config(), &artifacts);
        assert_eq!(report.decision, GateDecisionState::FailClosed);
        assert!(!report.observed_disruptive_floor_wording_allowed);
        assert!(report.metric_decisions[0].reason.contains("stale_artifact"));
        assert!(
            report
                .downgrade_texts
                .contains_key(DisruptiveMetricId::WeightedThroughputNodeBun.claim_id())
        );
    }

    #[test]
    fn denominator_mismatch_fails_independently() {
        let mut artifacts = passing_artifacts();
        artifacts[1].baseline = "node_only".to_string();
        let report = evaluate_disruptive_floor_gate(&config(), &artifacts);
        let decision = report
            .metric_decisions
            .iter()
            .find(|entry| entry.metric_id == DisruptiveMetricId::RedTeamCompromiseRateReduction)
            .unwrap();
        assert_eq!(decision.decision, MetricDecisionState::Fail);
        assert!(decision.reason.contains("baseline_mismatch"));
    }

    #[test]
    fn missing_metric_blocks_observed_claims() {
        let mut artifacts = passing_artifacts();
        artifacts.pop();
        let report = evaluate_disruptive_floor_gate(&config(), &artifacts);
        assert_eq!(report.decision, GateDecisionState::FailClosed);
        assert!(
            report
                .metric_decisions
                .iter()
                .any(|entry| entry.reason == "missing_metric_artifact")
        );
    }

    #[test]
    fn at_most_threshold_boundary_passes() {
        let artifact = MetricArtifact::for_metric(
            DisruptiveMetricId::ContainmentLatencyMedianMs,
            DisruptiveMetricId::ContainmentLatencyMedianMs.threshold(),
        );
        let decision = evaluate_metric(&config(), &artifact);
        assert_eq!(decision.decision, MetricDecisionState::Pass);
    }

    #[test]
    fn at_most_threshold_overage_fails() {
        let artifact = MetricArtifact::for_metric(
            DisruptiveMetricId::ContainmentLatencyMedianMs,
            DisruptiveMetricId::ContainmentLatencyMedianMs.threshold() + 1,
        );
        let decision = evaluate_metric(&config(), &artifact);
        assert_eq!(decision.decision, MetricDecisionState::Fail);
        assert!(decision.reason.contains("observed_value_misses_threshold"));
    }

    #[test]
    fn duplicate_metric_fails_closed() {
        let mut artifacts = passing_artifacts();
        artifacts.push(MetricArtifact::for_metric(
            DisruptiveMetricId::WeightedThroughputNodeBun,
            3,
        ));
        let report = evaluate_disruptive_floor_gate(&config(), &artifacts);
        assert!(
            report
                .metric_decisions
                .iter()
                .any(|entry| entry.reason == "duplicate_metric_artifact")
        );
    }

    #[test]
    fn claim_projection_downgrades_all_rows_when_one_metric_fails() {
        let mut artifacts = passing_artifacts();
        artifacts[0].observed_value = 2;
        let report = evaluate_disruptive_floor_gate(&config(), &artifacts);
        assert!(
            report
                .claim_matrix_projection
                .iter()
                .all(|row| row.allowed_state == "target")
        );
    }

    #[test]
    fn report_serializes_with_stable_schema() {
        let report = evaluate_disruptive_floor_gate(&config(), &passing_artifacts());
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema_version"], SCHEMA_VERSION);
        assert_eq!(json["component"], COMPONENT);
        assert_eq!(json["bead_id"], BEAD_ID);
    }

    #[test]
    fn markdown_report_includes_per_metric_decisions() {
        let report = evaluate_disruptive_floor_gate(&config(), &passing_artifacts());
        let markdown = report.to_markdown();
        assert!(markdown.contains("Disruptive Floor Metric Gate"));
        assert!(markdown.contains("weighted_throughput_node_bun"));
        assert!(markdown.contains("| Metric | Decision |"));
    }
}
