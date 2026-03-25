//! Oracle-backed release-gate scripts, blocker thresholds, and operator triage bundles.
//!
//! Bead: bd-3nr.1.4.3 [10.13X.D3]
//!
//! Promotes release-gate scripts, blocker thresholds, and operator triage bundles
//! to upstream-compatible oracle semantics. Each gate condition is backed by a
//! deterministic oracle that produces a verdict with evidence linkage, allowing
//! release decisions to be replayed and audited.
//!
//! # Design
//!
//! - `OracleKind` classifies the backing oracle (scenario, replay, contract, metric).
//! - `BlockerThreshold` defines the pass/fail boundary for a gate condition.
//! - `OracleGateCondition` ties a named gate to an oracle, threshold, and evidence.
//! - `GateEvaluation` records the oracle verdict for a single condition.
//! - `OracleReleaseGateReport` aggregates all evaluations for one release candidate.
//! - `TriageBundleEntry` and `TriageBundle` capture actionable operator guidance
//!   for any failed gate.
//! - `OracleReleaseGateEvent` is the structured audit event.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [10.13X.D3]

use std::collections::BTreeMap;
use std::fmt;

use crate::hash_tiers::ContentHash;
use crate::runtime_config::GatesConfig;
use crate::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for oracle release gate artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.oracle-release-gate.v1";

/// Bead identifier.
pub const BEAD_ID: &str = "bd-3nr.1.4.3";

/// Policy identifier.
pub const POLICY_ID: &str = "10.13X.D3";

/// Component name.
pub const COMPONENT: &str = "oracle_release_gate";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLIONTHS: u64 = 1_000_000;

/// Default minimum pass rate for scenario oracles (millionths). 100% = 1_000_000.
pub const DEFAULT_MIN_PASS_RATE: u64 = MILLIONTHS;

/// Default maximum allowed regression (millionths). 5% = 50_000.
pub const DEFAULT_MAX_REGRESSION: u64 = 50_000;

/// Default maximum unresolved blocker count.
pub const DEFAULT_MAX_UNRESOLVED: u64 = 0;

const SHIPPED_REPLAY_VALIDATE_HINT: &str =
    "frankenctl replay run --trace <trace.json> --mode validate";

// ---------------------------------------------------------------------------
// OracleKind
// ---------------------------------------------------------------------------

/// Classification of the backing oracle for a gate condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleKind {
    /// Oracle backed by frankenlab lifecycle scenarios.
    Scenario,
    /// Oracle backed by deterministic replay checks.
    Replay,
    /// Oracle backed by cross-repo contract tests.
    Contract,
    /// Oracle backed by a quantitative metric (latency, throughput, etc.).
    Metric,
    /// Oracle backed by evidence completeness checks.
    Evidence,
    /// Oracle backed by obligation resolution.
    Obligation,
}

impl OracleKind {
    /// Stable string identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scenario => "scenario",
            Self::Replay => "replay",
            Self::Contract => "contract",
            Self::Metric => "metric",
            Self::Evidence => "evidence",
            Self::Obligation => "obligation",
        }
    }

    /// All oracle kinds.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Scenario,
            Self::Replay,
            Self::Contract,
            Self::Metric,
            Self::Evidence,
            Self::Obligation,
        ]
    }
}

impl fmt::Display for OracleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ThresholdDirection
// ---------------------------------------------------------------------------

/// Direction of a threshold comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdDirection {
    /// The observed value must be >= the threshold to pass.
    AtLeast,
    /// The observed value must be <= the threshold to pass.
    AtMost,
    /// The observed value must be exactly equal to the threshold.
    Exactly,
}

impl ThresholdDirection {
    /// Check whether an observed value passes the threshold.
    pub fn passes(self, observed: u64, threshold: u64) -> bool {
        match self {
            Self::AtLeast => observed >= threshold,
            Self::AtMost => observed <= threshold,
            Self::Exactly => observed == threshold,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AtLeast => "at_least",
            Self::AtMost => "at_most",
            Self::Exactly => "exactly",
        }
    }
}

impl fmt::Display for ThresholdDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BlockerThreshold
// ---------------------------------------------------------------------------

/// A pass/fail threshold for a gate condition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockerThreshold {
    /// Human-readable name for the threshold.
    pub name: String,
    /// Threshold value in millionths (or raw count depending on context).
    pub threshold_value: u64,
    /// Direction of the comparison.
    pub direction: ThresholdDirection,
    /// Whether exceeding this threshold is a hard blocker (vs advisory).
    pub is_hard_blocker: bool,
}

impl BlockerThreshold {
    /// Evaluate whether an observed value passes this threshold.
    pub fn evaluate(&self, observed: u64) -> bool {
        self.direction.passes(observed, self.threshold_value)
    }
}

// ---------------------------------------------------------------------------
// OracleGateCondition
// ---------------------------------------------------------------------------

/// A single gate condition backed by an oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleGateCondition {
    /// Unique identifier for this condition.
    pub condition_id: String,
    /// Human-readable description.
    pub description: String,
    /// Which oracle backs this condition.
    pub oracle_kind: OracleKind,
    /// The threshold for pass/fail.
    pub threshold: BlockerThreshold,
    /// Policy reference.
    pub policy_ref: String,
    /// Upstream bead reference (if any).
    pub bead_ref: Option<String>,
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Verdict for a single gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// Gate passed: observed value satisfies threshold.
    Pass,
    /// Gate failed: observed value violates threshold (hard blocker).
    Fail,
    /// Gate produced a warning but does not block (advisory threshold).
    Advisory,
    /// Oracle could not produce a verdict (infrastructure error = fail-closed).
    Inconclusive,
}

impl GateVerdict {
    /// Whether this verdict blocks release.
    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Fail | Self::Inconclusive)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Advisory => "advisory",
            Self::Inconclusive => "inconclusive",
        }
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateEvaluation
// ---------------------------------------------------------------------------

/// The result of evaluating a single gate condition against its oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvaluation {
    /// Which condition was evaluated.
    pub condition_id: String,
    /// The observed value from the oracle (millionths or count).
    pub observed_value: u64,
    /// The threshold value.
    pub threshold_value: u64,
    /// Verdict.
    pub verdict: GateVerdict,
    /// Evidence reference (trace ID, bundle hash, etc.).
    pub evidence_ref: Option<String>,
    /// Replay command (for deterministic re-evaluation).
    pub replay_ref: Option<String>,
    /// Margin: how far the observed value is from the threshold.
    /// Positive = passing by this margin; negative = failing by this margin.
    pub margin_millionths: i64,
}

/// Evaluate a gate condition against an observed value.
pub fn evaluate_condition(
    condition: &OracleGateCondition,
    observed_value: u64,
    evidence_ref: Option<&str>,
    replay_ref: Option<&str>,
) -> GateEvaluation {
    let passes = condition.threshold.evaluate(observed_value);
    let verdict = if passes {
        GateVerdict::Pass
    } else if condition.threshold.is_hard_blocker {
        GateVerdict::Fail
    } else {
        GateVerdict::Advisory
    };

    let margin = match condition.threshold.direction {
        ThresholdDirection::AtLeast => {
            observed_value as i64 - condition.threshold.threshold_value as i64
        }
        ThresholdDirection::AtMost => {
            condition.threshold.threshold_value as i64 - observed_value as i64
        }
        ThresholdDirection::Exactly => {
            let diff = (observed_value as i64 - condition.threshold.threshold_value as i64).abs();
            if passes { 0 } else { -diff }
        }
    };

    GateEvaluation {
        condition_id: condition.condition_id.clone(),
        observed_value,
        threshold_value: condition.threshold.threshold_value,
        verdict,
        evidence_ref: evidence_ref.map(|s| s.to_string()),
        replay_ref: replay_ref.map(|s| s.to_string()),
        margin_millionths: margin,
    }
}

// ---------------------------------------------------------------------------
// OracleReleaseGateReport
// ---------------------------------------------------------------------------

/// Aggregate report for a release candidate's gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleReleaseGateReport {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Component name.
    pub component: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Release candidate identifier.
    pub release_candidate_id: String,
    /// All gate evaluations.
    pub evaluations: Vec<GateEvaluation>,
    /// Overall verdict: blocked if any hard-blocker fails.
    pub overall_verdict: GateVerdict,
    /// Count of passing gates.
    pub pass_count: u64,
    /// Count of failing gates (hard blockers).
    pub fail_count: u64,
    /// Count of advisory warnings.
    pub advisory_count: u64,
    /// Count of inconclusive evaluations.
    pub inconclusive_count: u64,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

/// Build a release gate report from a set of evaluations.
pub fn build_report(
    epoch: SecurityEpoch,
    release_candidate_id: &str,
    evaluations: Vec<GateEvaluation>,
) -> OracleReleaseGateReport {
    let mut pass_count: u64 = 0;
    let mut fail_count: u64 = 0;
    let mut advisory_count: u64 = 0;
    let mut inconclusive_count: u64 = 0;

    for eval in &evaluations {
        match eval.verdict {
            GateVerdict::Pass => pass_count += 1,
            GateVerdict::Fail => fail_count += 1,
            GateVerdict::Advisory => advisory_count += 1,
            GateVerdict::Inconclusive => inconclusive_count += 1,
        }
    }

    let overall_verdict = if fail_count > 0 || inconclusive_count > 0 {
        GateVerdict::Fail
    } else if advisory_count > 0 {
        GateVerdict::Advisory
    } else {
        GateVerdict::Pass
    };

    let content_hash = compute_report_hash(
        SCHEMA_VERSION,
        BEAD_ID,
        POLICY_ID,
        COMPONENT,
        &evaluations,
        release_candidate_id,
        epoch,
        overall_verdict,
        pass_count,
        fail_count,
        advisory_count,
        inconclusive_count,
    );

    OracleReleaseGateReport {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        epoch,
        release_candidate_id: release_candidate_id.to_string(),
        evaluations,
        overall_verdict,
        pass_count,
        fail_count,
        advisory_count,
        inconclusive_count,
        content_hash,
    }
}

impl OracleReleaseGateReport {
    /// Whether this report blocks release.
    pub fn blocks_release(&self) -> bool {
        self.overall_verdict.blocks_release()
    }

    /// Total number of evaluations.
    pub fn total_evaluations(&self) -> u64 {
        self.pass_count + self.fail_count + self.advisory_count + self.inconclusive_count
    }

    /// Verify content hash integrity.
    pub fn verify_integrity(&self) -> bool {
        let expected = compute_report_hash(
            &self.schema_version,
            &self.bead_id,
            &self.policy_id,
            &self.component,
            &self.evaluations,
            &self.release_candidate_id,
            self.epoch,
            self.overall_verdict,
            self.pass_count,
            self.fail_count,
            self.advisory_count,
            self.inconclusive_count,
        );
        self.content_hash == expected
    }

    /// Get evaluations that block release.
    pub fn blockers(&self) -> Vec<&GateEvaluation> {
        self.evaluations
            .iter()
            .filter(|e| e.verdict.blocks_release())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// TriageBundleEntry / TriageBundle
// ---------------------------------------------------------------------------

/// Severity for a triage entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageSeverity {
    /// Must be fixed before release.
    Blocker,
    /// Should be investigated before release.
    Warning,
    /// Informational only.
    Info,
}

impl TriageSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocker => "blocker",
            Self::Warning => "warning",
            Self::Info => "info",
        }
    }
}

impl fmt::Display for TriageSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single entry in the operator triage bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageBundleEntry {
    /// Which gate condition triggered this entry.
    pub condition_id: String,
    /// Oracle kind.
    pub oracle_kind: OracleKind,
    /// Triage severity.
    pub severity: TriageSeverity,
    /// Human-readable summary.
    pub summary: String,
    /// Remediation guidance.
    pub remediation: String,
    /// Evidence reference.
    pub evidence_ref: Option<String>,
    /// Replay command.
    pub replay_ref: Option<String>,
}

/// An operator triage bundle aggregating all gate failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageBundle {
    /// Schema version.
    pub schema_version: String,
    /// Release candidate identifier.
    pub release_candidate_id: String,
    /// All triage entries.
    pub entries: Vec<TriageBundleEntry>,
    /// Count of blocker-severity entries.
    pub blocker_count: u64,
    /// Count of warning-severity entries.
    pub warning_count: u64,
    /// Count of info-severity entries.
    pub info_count: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

/// Build a triage bundle from a release gate report.
pub fn build_triage_bundle(
    report: &OracleReleaseGateReport,
    conditions: &[OracleGateCondition],
) -> TriageBundle {
    let condition_map: BTreeMap<String, &OracleGateCondition> = conditions
        .iter()
        .map(|c| (c.condition_id.clone(), c))
        .collect();

    let mut entries = Vec::new();
    let mut blocker_count: u64 = 0;
    let mut warning_count: u64 = 0;
    let mut info_count: u64 = 0;

    for eval in &report.evaluations {
        if eval.verdict == GateVerdict::Pass {
            continue;
        }

        let condition = condition_map.get(&eval.condition_id);
        let oracle_kind = condition
            .map(|c| c.oracle_kind)
            .unwrap_or(OracleKind::Scenario);
        let description = condition
            .map(|c| c.description.clone())
            .unwrap_or_else(|| format!("Unknown condition: {}", eval.condition_id));

        let severity = match eval.verdict {
            GateVerdict::Fail | GateVerdict::Inconclusive => TriageSeverity::Blocker,
            GateVerdict::Advisory => TriageSeverity::Warning,
            GateVerdict::Pass => TriageSeverity::Info,
        };

        match severity {
            TriageSeverity::Blocker => blocker_count += 1,
            TriageSeverity::Warning => warning_count += 1,
            TriageSeverity::Info => info_count += 1,
        }

        let remediation = match oracle_kind {
            OracleKind::Scenario => {
                "Re-run frankenlab scenarios with --verbose and investigate failures.".to_string()
            }
            OracleKind::Replay => format!(
                "Check replay logs for divergence. Run `{SHIPPED_REPLAY_VALIDATE_HINT}` to isolate."
            ),
            OracleKind::Contract => {
                "Verify cross-repo contract test alignment. Check pinned versions.".to_string()
            }
            OracleKind::Metric => format!(
                "Observed {} vs threshold {}. Profile the regression.",
                eval.observed_value, eval.threshold_value
            ),
            OracleKind::Evidence => {
                "Check evidence pipeline for gaps. Ensure all high-impact actions emit entries."
                    .to_string()
            }
            OracleKind::Obligation => {
                "Resolve outstanding obligations before release. Check obligation ledger."
                    .to_string()
            }
        };

        entries.push(TriageBundleEntry {
            condition_id: eval.condition_id.clone(),
            oracle_kind,
            severity,
            summary: description,
            remediation,
            evidence_ref: eval.evidence_ref.clone(),
            replay_ref: eval.replay_ref.clone(),
        });
    }

    let content_hash = compute_triage_hash(
        SCHEMA_VERSION,
        &entries,
        &report.release_candidate_id,
        blocker_count,
        warning_count,
        info_count,
    );

    TriageBundle {
        schema_version: SCHEMA_VERSION.to_string(),
        release_candidate_id: report.release_candidate_id.clone(),
        entries,
        blocker_count,
        warning_count,
        info_count,
        content_hash,
    }
}

impl TriageBundle {
    /// Total entries.
    pub fn total_entries(&self) -> u64 {
        self.blocker_count + self.warning_count + self.info_count
    }

    /// Whether any blockers exist.
    pub fn has_blockers(&self) -> bool {
        self.blocker_count > 0
    }

    /// Verify integrity.
    pub fn verify_integrity(&self) -> bool {
        let expected = compute_triage_hash(
            &self.schema_version,
            &self.entries,
            &self.release_candidate_id,
            self.blocker_count,
            self.warning_count,
            self.info_count,
        );
        self.content_hash == expected
    }
}

// ---------------------------------------------------------------------------
// OracleReleaseGateEvent
// ---------------------------------------------------------------------------

/// Structured audit event for oracle release gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleReleaseGateEvent {
    /// Schema version.
    pub schema_version: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Decision identifier.
    pub decision_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Component name.
    pub component: String,
    /// Event kind.
    pub event: String,
    /// Release candidate identifier.
    pub release_candidate_id: String,
    /// Overall verdict.
    pub overall_verdict: String,
    /// Number of conditions evaluated.
    pub conditions_evaluated: u64,
    /// Number of blockers.
    pub blockers: u64,
    /// Seed for deterministic replay.
    pub seed: String,
}

/// Build an audit event from a report.
pub fn build_gate_event(
    trace_id: &str,
    decision_id: &str,
    report: &OracleReleaseGateReport,
) -> OracleReleaseGateEvent {
    OracleReleaseGateEvent {
        schema_version: SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "oracle_release_gate_evaluated".to_string(),
        release_candidate_id: report.release_candidate_id.clone(),
        overall_verdict: report.overall_verdict.as_str().to_string(),
        conditions_evaluated: report.total_evaluations(),
        blockers: report.fail_count + report.inconclusive_count,
        seed: format!("{BEAD_ID}-gate-v1"),
    }
}

// ---------------------------------------------------------------------------
// Default gate conditions
// ---------------------------------------------------------------------------

/// Build the canonical set of release gate conditions.
pub fn default_gate_conditions() -> Vec<OracleGateCondition> {
    default_gate_conditions_with_gates_config(&GatesConfig::default())
}

/// Build the canonical set of release gate conditions using runtime gate thresholds.
pub fn default_gate_conditions_with_gates_config(config: &GatesConfig) -> Vec<OracleGateCondition> {
    vec![
        OracleGateCondition {
            condition_id: "scenario-pass-rate".to_string(),
            description: "All frankenlab lifecycle scenarios must pass".to_string(),
            oracle_kind: OracleKind::Scenario,
            threshold: BlockerThreshold {
                name: "scenario_pass_rate".to_string(),
                threshold_value: config.min_pass_rate_millionths,
                direction: ThresholdDirection::AtLeast,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: Some("bd-3nr.1.4.1".to_string()),
        },
        OracleGateCondition {
            condition_id: "replay-divergence".to_string(),
            description: "Deterministic replay must show zero divergences".to_string(),
            oracle_kind: OracleKind::Replay,
            threshold: BlockerThreshold {
                name: "replay_divergences".to_string(),
                threshold_value: 0,
                direction: ThresholdDirection::Exactly,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: Some("bd-3nr.1.4.2".to_string()),
        },
        OracleGateCondition {
            condition_id: "contract-pass-rate".to_string(),
            description: "Cross-repo contract tests must all pass".to_string(),
            oracle_kind: OracleKind::Contract,
            threshold: BlockerThreshold {
                name: "contract_pass_rate".to_string(),
                threshold_value: config.min_pass_rate_millionths,
                direction: ThresholdDirection::AtLeast,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: Some("bd-3nr.1.5.1".to_string()),
        },
        OracleGateCondition {
            condition_id: "perf-regression".to_string(),
            description: "No performance regression beyond threshold".to_string(),
            oracle_kind: OracleKind::Metric,
            threshold: BlockerThreshold {
                name: "max_regression".to_string(),
                threshold_value: config.max_regression_millionths,
                direction: ThresholdDirection::AtMost,
                is_hard_blocker: false,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: Some("bd-3nr.1.5.2".to_string()),
        },
        OracleGateCondition {
            condition_id: "evidence-completeness".to_string(),
            description: "Evidence pipeline has no gaps for high-impact actions".to_string(),
            oracle_kind: OracleKind::Evidence,
            threshold: BlockerThreshold {
                name: "evidence_gap_count".to_string(),
                threshold_value: 0,
                direction: ThresholdDirection::Exactly,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: None,
        },
        OracleGateCondition {
            condition_id: "obligation-resolution".to_string(),
            description: "All obligations resolved before release".to_string(),
            oracle_kind: OracleKind::Obligation,
            threshold: BlockerThreshold {
                name: "unresolved_obligations".to_string(),
                threshold_value: config.max_unresolved,
                direction: ThresholdDirection::AtMost,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn compute_report_hash(
    schema_version: &str,
    bead_id: &str,
    policy_id: &str,
    component: &str,
    evaluations: &[GateEvaluation],
    release_candidate_id: &str,
    epoch: SecurityEpoch,
    overall_verdict: GateVerdict,
    pass_count: u64,
    fail_count: u64,
    advisory_count: u64,
    inconclusive_count: u64,
) -> ContentHash {
    #[derive(Serialize)]
    struct ReportHashInput<'a> {
        schema_version: &'a str,
        bead_id: &'a str,
        policy_id: &'a str,
        component: &'a str,
        release_candidate_id: &'a str,
        epoch: u64,
        overall_verdict: &'static str,
        pass_count: u64,
        fail_count: u64,
        advisory_count: u64,
        inconclusive_count: u64,
        evaluations: &'a [GateEvaluation],
    }

    let payload = ReportHashInput {
        schema_version,
        bead_id,
        policy_id,
        component,
        release_candidate_id,
        epoch: epoch.as_u64(),
        overall_verdict: overall_verdict.as_str(),
        pass_count,
        fail_count,
        advisory_count,
        inconclusive_count,
        evaluations,
    };
    let bytes = serde_json::to_vec(&payload)
        .expect("oracle release gate report hash input serialization must succeed");
    ContentHash::compute(&bytes)
}

fn compute_triage_hash(
    schema_version: &str,
    entries: &[TriageBundleEntry],
    release_candidate_id: &str,
    blocker_count: u64,
    warning_count: u64,
    info_count: u64,
) -> ContentHash {
    #[derive(Serialize)]
    struct TriageHashInput<'a> {
        schema_version: &'a str,
        release_candidate_id: &'a str,
        blocker_count: u64,
        warning_count: u64,
        info_count: u64,
        entries: &'a [TriageBundleEntry],
    }

    let payload = TriageHashInput {
        schema_version,
        release_candidate_id,
        blocker_count,
        warning_count,
        info_count,
        entries,
    };
    let bytes = serde_json::to_vec(&payload)
        .expect("oracle release gate triage hash input serialization must succeed");
    ContentHash::compute(&bytes)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn oracle_kind_all_variants_unique() {
        let mut seen = BTreeSet::new();
        for kind in OracleKind::all() {
            assert!(seen.insert(kind.as_str()), "duplicate: {kind}");
        }
    }

    #[test]
    fn oracle_kind_display() {
        assert_eq!(OracleKind::Scenario.to_string(), "scenario");
        assert_eq!(OracleKind::Replay.to_string(), "replay");
        assert_eq!(OracleKind::Contract.to_string(), "contract");
        assert_eq!(OracleKind::Metric.to_string(), "metric");
    }

    #[test]
    fn threshold_at_least_passes() {
        assert!(ThresholdDirection::AtLeast.passes(100, 50));
        assert!(ThresholdDirection::AtLeast.passes(50, 50));
        assert!(!ThresholdDirection::AtLeast.passes(49, 50));
    }

    #[test]
    fn threshold_at_most_passes() {
        assert!(ThresholdDirection::AtMost.passes(50, 100));
        assert!(ThresholdDirection::AtMost.passes(100, 100));
        assert!(!ThresholdDirection::AtMost.passes(101, 100));
    }

    #[test]
    fn threshold_exactly_passes() {
        assert!(ThresholdDirection::Exactly.passes(42, 42));
        assert!(!ThresholdDirection::Exactly.passes(41, 42));
        assert!(!ThresholdDirection::Exactly.passes(43, 42));
    }

    #[test]
    fn blocker_threshold_evaluate() {
        let t = BlockerThreshold {
            name: "test".to_string(),
            threshold_value: 100,
            direction: ThresholdDirection::AtLeast,
            is_hard_blocker: true,
        };
        assert!(t.evaluate(100));
        assert!(t.evaluate(200));
        assert!(!t.evaluate(50));
    }

    #[test]
    fn gate_verdict_blocks_release() {
        assert!(!GateVerdict::Pass.blocks_release());
        assert!(GateVerdict::Fail.blocks_release());
        assert!(!GateVerdict::Advisory.blocks_release());
        assert!(GateVerdict::Inconclusive.blocks_release());
    }

    #[test]
    fn evaluate_passing_condition() {
        let condition = OracleGateCondition {
            condition_id: "test".to_string(),
            description: "test condition".to_string(),
            oracle_kind: OracleKind::Scenario,
            threshold: BlockerThreshold {
                name: "pass_rate".to_string(),
                threshold_value: MILLIONTHS,
                direction: ThresholdDirection::AtLeast,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: None,
        };
        let eval = evaluate_condition(&condition, MILLIONTHS, None, None);
        assert_eq!(eval.verdict, GateVerdict::Pass);
        assert_eq!(eval.margin_millionths, 0);
    }

    #[test]
    fn evaluate_failing_hard_blocker() {
        let condition = OracleGateCondition {
            condition_id: "test".to_string(),
            description: "test".to_string(),
            oracle_kind: OracleKind::Scenario,
            threshold: BlockerThreshold {
                name: "pass_rate".to_string(),
                threshold_value: MILLIONTHS,
                direction: ThresholdDirection::AtLeast,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: None,
        };
        let eval = evaluate_condition(&condition, 500_000, None, None);
        assert_eq!(eval.verdict, GateVerdict::Fail);
        assert!(eval.margin_millionths < 0);
    }

    #[test]
    fn evaluate_failing_advisory() {
        let condition = OracleGateCondition {
            condition_id: "test".to_string(),
            description: "test".to_string(),
            oracle_kind: OracleKind::Metric,
            threshold: BlockerThreshold {
                name: "regression".to_string(),
                threshold_value: 50_000,
                direction: ThresholdDirection::AtMost,
                is_hard_blocker: false,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: None,
        };
        let eval = evaluate_condition(&condition, 100_000, None, None);
        assert_eq!(eval.verdict, GateVerdict::Advisory);
    }

    #[test]
    fn build_report_all_pass() {
        let evals = vec![
            GateEvaluation {
                condition_id: "a".to_string(),
                observed_value: MILLIONTHS,
                threshold_value: MILLIONTHS,
                verdict: GateVerdict::Pass,
                evidence_ref: None,
                replay_ref: None,
                margin_millionths: 0,
            },
            GateEvaluation {
                condition_id: "b".to_string(),
                observed_value: 0,
                threshold_value: 0,
                verdict: GateVerdict::Pass,
                evidence_ref: None,
                replay_ref: None,
                margin_millionths: 0,
            },
        ];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        assert_eq!(report.overall_verdict, GateVerdict::Pass);
        assert_eq!(report.pass_count, 2);
        assert!(!report.blocks_release());
    }

    #[test]
    fn build_report_with_failure() {
        let evals = vec![
            GateEvaluation {
                condition_id: "a".to_string(),
                observed_value: MILLIONTHS,
                threshold_value: MILLIONTHS,
                verdict: GateVerdict::Pass,
                evidence_ref: None,
                replay_ref: None,
                margin_millionths: 0,
            },
            GateEvaluation {
                condition_id: "b".to_string(),
                observed_value: 500_000,
                threshold_value: MILLIONTHS,
                verdict: GateVerdict::Fail,
                evidence_ref: None,
                replay_ref: None,
                margin_millionths: -500_000,
            },
        ];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        assert_eq!(report.overall_verdict, GateVerdict::Fail);
        assert!(report.blocks_release());
        assert_eq!(report.blockers().len(), 1);
    }

    #[test]
    fn report_integrity_check() {
        let evals = vec![GateEvaluation {
            condition_id: "a".to_string(),
            observed_value: MILLIONTHS,
            threshold_value: MILLIONTHS,
            verdict: GateVerdict::Pass,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: 0,
        }];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        assert!(report.verify_integrity());
    }

    #[test]
    fn default_conditions_cover_all_oracle_kinds() {
        let conditions = default_gate_conditions();
        let kinds: BTreeSet<OracleKind> = conditions.iter().map(|c| c.oracle_kind).collect();
        for kind in OracleKind::all() {
            assert!(
                kinds.contains(kind),
                "missing condition for oracle kind {kind}"
            );
        }
    }

    #[test]
    fn triage_bundle_from_clean_report() {
        let conditions = default_gate_conditions();
        let evals: Vec<GateEvaluation> = conditions
            .iter()
            .map(|c| evaluate_condition(c, c.threshold.threshold_value, None, None))
            .collect();
        let report = build_report(SecurityEpoch::from_raw(1), "rc-clean", evals);
        let bundle = build_triage_bundle(&report, &conditions);
        assert_eq!(bundle.total_entries(), 0);
        assert!(!bundle.has_blockers());
    }

    #[test]
    fn triage_bundle_from_failing_report() {
        let conditions = default_gate_conditions();
        let evals = vec![evaluate_condition(
            &conditions[0],
            500_000,
            Some("ev-1"),
            None,
        )];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-fail", evals);
        let bundle = build_triage_bundle(&report, &conditions);
        assert!(bundle.has_blockers());
        assert_eq!(bundle.blocker_count, 1);
    }

    #[test]
    fn replay_triage_bundle_uses_shipped_replay_run_command() {
        let condition = OracleGateCondition {
            condition_id: "replay".to_string(),
            description: "replay drift".to_string(),
            oracle_kind: OracleKind::Replay,
            threshold: BlockerThreshold {
                name: "replay_failures".to_string(),
                threshold_value: 0,
                direction: ThresholdDirection::Exactly,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: None,
        };
        let evals = vec![evaluate_condition(&condition, 1, None, Some("replay-ref"))];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-replay", evals);
        let bundle = build_triage_bundle(&report, &[condition]);

        assert_eq!(bundle.entries.len(), 1);
        assert!(
            bundle.entries[0]
                .remediation
                .contains(SHIPPED_REPLAY_VALIDATE_HINT)
        );
        assert!(
            !bundle.entries[0]
                .remediation
                .contains("frankenctl replay --diff")
        );
    }

    #[test]
    fn report_serde_roundtrip() {
        let evals = vec![GateEvaluation {
            condition_id: "test".to_string(),
            observed_value: 42,
            threshold_value: 100,
            verdict: GateVerdict::Fail,
            evidence_ref: Some("ev".to_string()),
            replay_ref: Some("replay".to_string()),
            margin_millionths: -58,
        }];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: OracleReleaseGateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
    }

    #[test]
    fn triage_bundle_serde_roundtrip() {
        let conditions = default_gate_conditions();
        let evals = vec![evaluate_condition(&conditions[0], 500_000, None, None)];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        let bundle = build_triage_bundle(&report, &conditions);
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: TriageBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, parsed);
    }

    #[test]
    fn gate_event_structure() {
        let evals = vec![GateEvaluation {
            condition_id: "a".to_string(),
            observed_value: MILLIONTHS,
            threshold_value: MILLIONTHS,
            verdict: GateVerdict::Pass,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: 0,
        }];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        let event = build_gate_event("trace-1", "decision-1", &report);
        assert_eq!(event.component, COMPONENT);
        assert_eq!(event.policy_id, POLICY_ID);
        assert_eq!(event.overall_verdict, "pass");
    }

    #[test]
    fn constants_non_empty() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!POLICY_ID.is_empty());
        assert!(!COMPONENT.is_empty());
    }

    #[test]
    fn deterministic_report_builds() {
        let evals1 = vec![GateEvaluation {
            condition_id: "a".to_string(),
            observed_value: MILLIONTHS,
            threshold_value: MILLIONTHS,
            verdict: GateVerdict::Pass,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: 0,
        }];
        let evals2 = evals1.clone();
        let r1 = build_report(SecurityEpoch::from_raw(1), "rc-1", evals1);
        let r2 = build_report(SecurityEpoch::from_raw(1), "rc-1", evals2);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn triage_severity_display() {
        assert_eq!(TriageSeverity::Blocker.to_string(), "blocker");
        assert_eq!(TriageSeverity::Warning.to_string(), "warning");
        assert_eq!(TriageSeverity::Info.to_string(), "info");
    }

    #[test]
    fn triage_bundle_integrity() {
        let conditions = default_gate_conditions();
        let evals = vec![evaluate_condition(&conditions[0], 500_000, None, None)];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        let bundle = build_triage_bundle(&report, &conditions);
        assert!(bundle.verify_integrity());
    }

    #[test]
    fn triage_bundle_integrity_detects_remediation_tamper() {
        let conditions = default_gate_conditions();
        let evals = vec![evaluate_condition(
            &conditions[0],
            500_000,
            Some("ev-1"),
            None,
        )];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        let mut bundle = build_triage_bundle(&report, &conditions);
        assert!(bundle.verify_integrity());
        bundle.entries[0].remediation.push_str(" tampered");
        assert!(!bundle.verify_integrity());
    }

    #[test]
    fn triage_bundle_integrity_detects_schema_version_tamper() {
        let conditions = default_gate_conditions();
        let evals = vec![evaluate_condition(&conditions[0], 500_000, None, None)];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        let mut bundle = build_triage_bundle(&report, &conditions);
        assert!(bundle.verify_integrity());
        bundle.schema_version = "tampered.schema".to_string();
        assert!(!bundle.verify_integrity());
    }

    // --- Enrichment tests (PearlTower 2026-03-16) ---

    #[test]
    fn oracle_kind_serde_roundtrip() {
        for kind in OracleKind::all() {
            let json = serde_json::to_string(kind).unwrap();
            let parsed: OracleKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, parsed);
        }
    }

    #[test]
    fn oracle_kind_as_str_distinct() {
        let strs: BTreeSet<&str> = OracleKind::all().iter().map(|k| k.as_str()).collect();
        assert_eq!(strs.len(), OracleKind::all().len());
    }

    #[test]
    fn oracle_kind_evidence_and_obligation_display() {
        assert_eq!(OracleKind::Evidence.to_string(), "evidence");
        assert_eq!(OracleKind::Obligation.to_string(), "obligation");
    }

    #[test]
    fn threshold_direction_serde_roundtrip() {
        for dir in [
            ThresholdDirection::AtLeast,
            ThresholdDirection::AtMost,
            ThresholdDirection::Exactly,
        ] {
            let json = serde_json::to_string(&dir).unwrap();
            let parsed: ThresholdDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(dir, parsed);
        }
    }

    #[test]
    fn threshold_direction_as_str_distinct() {
        let at_least = ThresholdDirection::AtLeast.as_str();
        let at_most = ThresholdDirection::AtMost.as_str();
        let exactly = ThresholdDirection::Exactly.as_str();
        assert_ne!(at_least, at_most);
        assert_ne!(at_most, exactly);
        assert_ne!(at_least, exactly);
    }

    #[test]
    fn threshold_direction_display() {
        assert_eq!(ThresholdDirection::AtLeast.to_string(), "at_least");
        assert_eq!(ThresholdDirection::AtMost.to_string(), "at_most");
        assert_eq!(ThresholdDirection::Exactly.to_string(), "exactly");
    }

    #[test]
    fn threshold_boundary_zero() {
        assert!(ThresholdDirection::AtLeast.passes(0, 0));
        assert!(ThresholdDirection::AtMost.passes(0, 0));
        assert!(ThresholdDirection::Exactly.passes(0, 0));
    }

    #[test]
    fn threshold_boundary_max() {
        assert!(ThresholdDirection::AtLeast.passes(u64::MAX, u64::MAX));
        assert!(ThresholdDirection::AtMost.passes(u64::MAX, u64::MAX));
        assert!(ThresholdDirection::Exactly.passes(u64::MAX, u64::MAX));
    }

    #[test]
    fn threshold_at_least_one_below() {
        assert!(!ThresholdDirection::AtLeast.passes(99, 100));
    }

    #[test]
    fn threshold_at_most_one_above() {
        assert!(!ThresholdDirection::AtMost.passes(101, 100));
    }

    #[test]
    fn blocker_threshold_soft_advisory() {
        let t = BlockerThreshold {
            name: "soft".to_string(),
            threshold_value: 50,
            direction: ThresholdDirection::AtMost,
            is_hard_blocker: false,
        };
        assert!(t.evaluate(50));
        assert!(t.evaluate(0));
        assert!(!t.evaluate(51));
    }

    #[test]
    fn gate_verdict_serde_roundtrip() {
        for v in [
            GateVerdict::Pass,
            GateVerdict::Fail,
            GateVerdict::Advisory,
            GateVerdict::Inconclusive,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: GateVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, v);
        }
    }

    #[test]
    fn gate_verdict_as_str_distinct() {
        let strs: BTreeSet<&str> = [
            GateVerdict::Pass,
            GateVerdict::Fail,
            GateVerdict::Advisory,
            GateVerdict::Inconclusive,
        ]
        .iter()
        .map(|v| v.as_str())
        .collect();
        assert_eq!(strs.len(), 4);
    }

    #[test]
    fn evaluate_condition_with_evidence_and_replay() {
        let condition = OracleGateCondition {
            condition_id: "test".to_string(),
            description: "test".to_string(),
            oracle_kind: OracleKind::Evidence,
            threshold: BlockerThreshold {
                name: "gap_count".to_string(),
                threshold_value: 0,
                direction: ThresholdDirection::Exactly,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: Some("bd-test".to_string()),
        };
        let eval = evaluate_condition(&condition, 0, Some("ev-123"), Some("replay-cmd"));
        assert_eq!(eval.verdict, GateVerdict::Pass);
        assert_eq!(eval.evidence_ref, Some("ev-123".to_string()));
        assert_eq!(eval.replay_ref, Some("replay-cmd".to_string()));
        assert_eq!(eval.margin_millionths, 0);
    }

    #[test]
    fn evaluate_margin_at_least_positive() {
        let condition = OracleGateCondition {
            condition_id: "m".to_string(),
            description: "m".to_string(),
            oracle_kind: OracleKind::Metric,
            threshold: BlockerThreshold {
                name: "rate".to_string(),
                threshold_value: 100,
                direction: ThresholdDirection::AtLeast,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: None,
        };
        let eval = evaluate_condition(&condition, 150, None, None);
        assert_eq!(eval.margin_millionths, 50);
    }

    #[test]
    fn evaluate_margin_exactly_failing() {
        let condition = OracleGateCondition {
            condition_id: "r".to_string(),
            description: "r".to_string(),
            oracle_kind: OracleKind::Replay,
            threshold: BlockerThreshold {
                name: "divergences".to_string(),
                threshold_value: 0,
                direction: ThresholdDirection::Exactly,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: None,
        };
        let eval = evaluate_condition(&condition, 3, None, None);
        assert_eq!(eval.verdict, GateVerdict::Fail);
        assert_eq!(eval.margin_millionths, -3);
    }

    #[test]
    fn report_with_inconclusive_blocks() {
        let evals = vec![GateEvaluation {
            condition_id: "a".to_string(),
            observed_value: 0,
            threshold_value: 0,
            verdict: GateVerdict::Inconclusive,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: 0,
        }];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        assert_eq!(report.overall_verdict, GateVerdict::Fail);
        assert!(report.blocks_release());
        assert_eq!(report.inconclusive_count, 1);
    }

    #[test]
    fn report_advisory_only_no_block() {
        let evals = vec![GateEvaluation {
            condition_id: "a".to_string(),
            observed_value: 100,
            threshold_value: 50,
            verdict: GateVerdict::Advisory,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: -50,
        }];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        assert_eq!(report.overall_verdict, GateVerdict::Advisory);
        assert!(!report.blocks_release());
    }

    #[test]
    fn report_empty_evaluations_pass() {
        let report = build_report(SecurityEpoch::from_raw(1), "rc-empty", vec![]);
        assert_eq!(report.overall_verdict, GateVerdict::Pass);
        assert_eq!(report.total_evaluations(), 0);
    }

    #[test]
    fn report_content_hash_varies_with_epoch() {
        let evals = vec![GateEvaluation {
            condition_id: "a".to_string(),
            observed_value: 100,
            threshold_value: 100,
            verdict: GateVerdict::Pass,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: 0,
        }];
        let r1 = build_report(SecurityEpoch::from_raw(1), "rc-1", evals.clone());
        let r2 = build_report(SecurityEpoch::from_raw(2), "rc-1", evals);
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_verify_integrity_detects_tamper() {
        let evals = vec![GateEvaluation {
            condition_id: "a".to_string(),
            observed_value: 100,
            threshold_value: 100,
            verdict: GateVerdict::Pass,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: 0,
        }];
        let mut report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        assert!(report.verify_integrity());
        report.release_candidate_id = "tampered".to_string();
        assert!(!report.verify_integrity());
    }

    #[test]
    fn report_verify_integrity_detects_evidence_ref_tamper() {
        let evals = vec![GateEvaluation {
            condition_id: "a".to_string(),
            observed_value: 100,
            threshold_value: 100,
            verdict: GateVerdict::Pass,
            evidence_ref: Some("ev-1".to_string()),
            replay_ref: Some("replay-1".to_string()),
            margin_millionths: 0,
        }];
        let mut report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        assert!(report.verify_integrity());
        report.evaluations[0].evidence_ref = Some("ev-2".to_string());
        assert!(!report.verify_integrity());
    }

    #[test]
    fn report_verify_integrity_detects_component_tamper() {
        let evals = vec![GateEvaluation {
            condition_id: "a".to_string(),
            observed_value: 100,
            threshold_value: 100,
            verdict: GateVerdict::Pass,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: 0,
        }];
        let mut report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        assert!(report.verify_integrity());
        report.component = "tampered_component".to_string();
        assert!(!report.verify_integrity());
    }

    #[test]
    fn default_conditions_unique_ids() {
        let conditions = default_gate_conditions();
        let ids: BTreeSet<&str> = conditions.iter().map(|c| c.condition_id.as_str()).collect();
        assert_eq!(ids.len(), conditions.len());
    }

    #[test]
    fn default_conditions_have_policy_refs() {
        for c in &default_gate_conditions() {
            assert!(!c.policy_ref.is_empty());
        }
    }

    #[test]
    fn default_conditions_with_gates_config_override_thresholds() {
        let config = GatesConfig {
            min_pass_rate_millionths: 910_000,
            max_regression_millionths: 25_000,
            max_unresolved: 2,
            ..GatesConfig::default()
        };
        let conditions = default_gate_conditions_with_gates_config(&config);

        let scenario = conditions
            .iter()
            .find(|condition| condition.condition_id == "scenario-pass-rate")
            .unwrap();
        assert_eq!(scenario.threshold.threshold_value, 910_000);

        let contract = conditions
            .iter()
            .find(|condition| condition.condition_id == "contract-pass-rate")
            .unwrap();
        assert_eq!(contract.threshold.threshold_value, 910_000);

        let metric = conditions
            .iter()
            .find(|condition| condition.condition_id == "perf-regression")
            .unwrap();
        assert_eq!(metric.threshold.threshold_value, 25_000);

        let obligations = conditions
            .iter()
            .find(|condition| condition.condition_id == "obligation-resolution")
            .unwrap();
        assert_eq!(obligations.threshold.threshold_value, 2);
    }

    #[test]
    fn triage_bundle_unknown_condition() {
        let conditions = default_gate_conditions();
        let evals = vec![GateEvaluation {
            condition_id: "unknown".to_string(),
            observed_value: 0,
            threshold_value: 100,
            verdict: GateVerdict::Fail,
            evidence_ref: None,
            replay_ref: None,
            margin_millionths: -100,
        }];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        let bundle = build_triage_bundle(&report, &conditions);
        assert_eq!(bundle.entries.len(), 1);
        assert!(bundle.entries[0].summary.contains("Unknown"));
    }

    #[test]
    fn gate_event_blocker_count() {
        let evals = vec![
            GateEvaluation {
                condition_id: "a".to_string(),
                observed_value: 0,
                threshold_value: 100,
                verdict: GateVerdict::Fail,
                evidence_ref: None,
                replay_ref: None,
                margin_millionths: -100,
            },
            GateEvaluation {
                condition_id: "b".to_string(),
                observed_value: 0,
                threshold_value: 0,
                verdict: GateVerdict::Inconclusive,
                evidence_ref: None,
                replay_ref: None,
                margin_millionths: 0,
            },
        ];
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", evals);
        let event = build_gate_event("t-1", "d-1", &report);
        assert_eq!(event.blockers, 2);
        assert_eq!(event.conditions_evaluated, 2);
    }

    #[test]
    fn gate_event_serde_roundtrip() {
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", vec![]);
        let event = build_gate_event("t-1", "d-1", &report);
        let json = serde_json::to_string(&event).unwrap();
        let parsed: OracleReleaseGateEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn gate_condition_serde_roundtrip() {
        let condition = OracleGateCondition {
            condition_id: "test".to_string(),
            description: "Test".to_string(),
            oracle_kind: OracleKind::Contract,
            threshold: BlockerThreshold {
                name: "pass".to_string(),
                threshold_value: MILLIONTHS,
                direction: ThresholdDirection::AtLeast,
                is_hard_blocker: true,
            },
            policy_ref: POLICY_ID.to_string(),
            bead_ref: Some("bd-test".to_string()),
        };
        let json = serde_json::to_string(&condition).unwrap();
        let parsed: OracleGateCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(condition, parsed);
    }

    #[test]
    fn triage_severity_serde_roundtrip() {
        for sev in [
            TriageSeverity::Blocker,
            TriageSeverity::Warning,
            TriageSeverity::Info,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let parsed: TriageSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, parsed);
        }
    }

    #[test]
    fn report_schema_fields_correct() {
        let report = build_report(SecurityEpoch::from_raw(1), "rc-1", vec![]);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.bead_id, BEAD_ID);
        assert_eq!(report.policy_id, POLICY_ID);
        assert_eq!(report.component, COMPONENT);
    }

    #[test]
    fn default_conditions_metric_is_soft() {
        let metric = default_gate_conditions()
            .into_iter()
            .find(|c| c.oracle_kind == OracleKind::Metric);
        assert!(metric.is_some());
        assert!(!metric.unwrap().threshold.is_hard_blocker);
    }

    #[test]
    fn empty_triage_bundle_integrity() {
        let conditions = default_gate_conditions();
        let report = build_report(SecurityEpoch::from_raw(1), "rc-clean", vec![]);
        let bundle = build_triage_bundle(&report, &conditions);
        assert!(bundle.verify_integrity());
        assert!(!bundle.has_blockers());
        assert_eq!(bundle.total_entries(), 0);
    }
}
