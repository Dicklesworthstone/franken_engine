#![forbid(unsafe_code)]
//! Oracle-backed release-gate scripts, blocker thresholds, and operator triage
//! bundles promotion.
//!
//! Bead: bd-3nr.1.4.3 \[10.13X.D3\]
//!
//! Promotes release-gate scripts, blocker thresholds, and operator triage bundles
//! to the upstream-compatible oracle model. Where [`frankenlab_release_gate`]
//! defines gate kinds and verdicts, this module adds:
//!
//! 1. **Oracle-backed gate evaluation** — each gate kind is backed by one or more
//!    oracle invariants from the bridge contract, making gate verdicts evidence-based
//!    rather than assertion-based.
//! 2. **Blocker thresholds** — configurable thresholds that determine when a gate
//!    transitions from advisory to release-blocking.
//! 3. **Operator triage bundles** — structured diagnostic bundles that operators
//!    can use to understand and remediate gate failures.
//! 4. **Promotion status tracking** — which gates have been promoted from local
//!    assertion-based to oracle-backed evaluation.
//!
//! Plan references: Section 10.13X item D3.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the release gate promotion format.
pub const RELEASE_GATE_PROMOTION_SCHEMA_VERSION: &str =
    "franken-engine.frankenlab-release-gate-promotion.v1";

/// Bead identifier for this module.
pub const RELEASE_GATE_PROMOTION_BEAD_ID: &str = "bd-3nr.1.4.3";

/// Fixed-point scale (1_000_000 = 100%).
const SCALE: u64 = 1_000_000;

/// Default minimum oracle pass rate for release (95%).
const DEFAULT_MIN_ORACLE_PASS_RATE: u64 = 950_000;

/// Default maximum tolerated release-blocking violations.
#[allow(dead_code)]
const DEFAULT_MAX_BLOCKING_VIOLATIONS: usize = 0;

// ---------------------------------------------------------------------------
// PromotedGateKind — gate kinds with oracle backing
// ---------------------------------------------------------------------------

/// Extended gate kinds that include oracle-backed evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotedGateKind {
    /// Frankenlab lifecycle scenario oracle gate.
    LifecycleScenarios,
    /// Replay determinism oracle gate.
    ReplayDeterminism,
    /// Obligation resolution oracle gate.
    ObligationResolution,
    /// Evidence completeness oracle gate.
    EvidenceCompleteness,
    /// Budget propagation contract gate.
    BudgetPropagation,
    /// Capability narrowing contract gate.
    CapabilityNarrowing,
    /// Mock seam absence gate.
    MockSeamAbsence,
    /// Outcome propagation correctness gate.
    OutcomePropagation,
}

impl PromotedGateKind {
    /// All gate kinds in deterministic order.
    pub const ALL: [Self; 8] = [
        Self::LifecycleScenarios,
        Self::ReplayDeterminism,
        Self::ObligationResolution,
        Self::EvidenceCompleteness,
        Self::BudgetPropagation,
        Self::CapabilityNarrowing,
        Self::MockSeamAbsence,
        Self::OutcomePropagation,
    ];

    /// Whether this gate was in the original release gate set.
    pub fn is_original_gate(&self) -> bool {
        matches!(
            self,
            Self::LifecycleScenarios
                | Self::ReplayDeterminism
                | Self::ObligationResolution
                | Self::EvidenceCompleteness
        )
    }

    /// Whether this gate was added by the correction wave.
    pub fn is_correction_wave_gate(&self) -> bool {
        !self.is_original_gate()
    }
}

impl fmt::Display for PromotedGateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LifecycleScenarios => write!(f, "lifecycle_scenarios"),
            Self::ReplayDeterminism => write!(f, "replay_determinism"),
            Self::ObligationResolution => write!(f, "obligation_resolution"),
            Self::EvidenceCompleteness => write!(f, "evidence_completeness"),
            Self::BudgetPropagation => write!(f, "budget_propagation"),
            Self::CapabilityNarrowing => write!(f, "capability_narrowing"),
            Self::MockSeamAbsence => write!(f, "mock_seam_absence"),
            Self::OutcomePropagation => write!(f, "outcome_propagation"),
        }
    }
}

// ---------------------------------------------------------------------------
// PromotionStatus — gate promotion state
// ---------------------------------------------------------------------------

/// Promotion status for a single gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionStatus {
    /// Gate uses local assertion-based evaluation only.
    AssertionBased,
    /// Gate has oracle wiring but not yet validated.
    OracleWired,
    /// Gate uses oracle-backed evaluation, validated.
    OracleBacked,
    /// Gate fully promoted with cross-validation evidence.
    FullyPromoted,
}

impl PromotionStatus {
    /// Whether the gate is oracle-backed.
    pub fn is_oracle_backed(&self) -> bool {
        matches!(self, Self::OracleBacked | Self::FullyPromoted)
    }
}

impl fmt::Display for PromotionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssertionBased => write!(f, "assertion_based"),
            Self::OracleWired => write!(f, "oracle_wired"),
            Self::OracleBacked => write!(f, "oracle_backed"),
            Self::FullyPromoted => write!(f, "fully_promoted"),
        }
    }
}

// ---------------------------------------------------------------------------
// BlockerThreshold — configurable gate blocking thresholds
// ---------------------------------------------------------------------------

/// Configurable threshold determining when a gate blocks release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockerThreshold {
    /// Which gate this threshold applies to.
    pub gate: PromotedGateKind,
    /// Minimum oracle pass rate to avoid blocking (millionths).
    pub min_pass_rate_millionths: u64,
    /// Maximum tolerated failures before blocking.
    pub max_failures: usize,
    /// Whether infrastructure errors block release.
    pub infra_errors_block: bool,
    /// Whether timeouts block release.
    pub timeouts_block: bool,
    /// Human-readable rationale for the threshold.
    pub rationale: String,
}

impl BlockerThreshold {
    /// Create a strict threshold (zero tolerance).
    pub fn strict(gate: PromotedGateKind) -> Self {
        Self {
            gate,
            min_pass_rate_millionths: SCALE,
            max_failures: 0,
            infra_errors_block: true,
            timeouts_block: true,
            rationale: String::new(),
        }
    }

    /// Create a relaxed threshold.
    pub fn relaxed(gate: PromotedGateKind) -> Self {
        Self {
            gate,
            min_pass_rate_millionths: DEFAULT_MIN_ORACLE_PASS_RATE,
            max_failures: 2,
            infra_errors_block: false,
            timeouts_block: true,
            rationale: String::new(),
        }
    }

    /// Set the rationale.
    pub fn with_rationale(mut self, rationale: &str) -> Self {
        self.rationale = rationale.to_owned();
        self
    }

    /// Check if a given pass rate and failure count would block.
    pub fn would_block(&self, pass_rate_millionths: u64, failures: usize) -> bool {
        pass_rate_millionths < self.min_pass_rate_millionths || failures > self.max_failures
    }
}

// ---------------------------------------------------------------------------
// TriageFinding — a single finding in a triage bundle
// ---------------------------------------------------------------------------

/// A single finding in an operator triage bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageFinding {
    /// Which gate produced this finding.
    pub gate: PromotedGateKind,
    /// Severity of the finding.
    pub severity: TriageSeverity,
    /// Short summary for the operator.
    pub summary: String,
    /// Detailed description.
    pub detail: String,
    /// Suggested remediation steps.
    pub remediation_steps: Vec<String>,
    /// Related scenario (if applicable).
    pub scenario_id: Option<String>,
    /// Related oracle invariant (if applicable).
    pub oracle_invariant: Option<String>,
}

/// Severity levels for triage findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageSeverity {
    /// Informational — no action needed.
    Info,
    /// Warning — investigate but not blocking.
    Warning,
    /// Error — blocks release, remediation needed.
    Error,
    /// Critical — blocks release, immediate attention.
    Critical,
}

impl TriageSeverity {
    /// Whether this severity blocks release.
    pub fn is_release_blocking(&self) -> bool {
        matches!(self, Self::Error | Self::Critical)
    }
}

impl fmt::Display for TriageSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// TriageBundle — structured diagnostic for operators
// ---------------------------------------------------------------------------

/// Structured diagnostic bundle for operators to understand and remediate
/// gate failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageBundle {
    /// All findings in this bundle.
    pub findings: Vec<TriageFinding>,
    /// Overall severity (max of all findings).
    pub max_severity: Option<TriageSeverity>,
    /// Number of release-blocking findings.
    pub blocking_count: usize,
    /// Gates that contributed findings.
    pub gates_involved: BTreeSet<String>,
    /// Content hash for deduplication.
    pub content_hash: ContentHash,
}

impl TriageBundle {
    /// Build a triage bundle from findings.
    pub fn from_findings(findings: Vec<TriageFinding>) -> Self {
        let max_severity = findings.iter().map(|f| f.severity).max();
        let blocking_count = findings
            .iter()
            .filter(|f| f.severity.is_release_blocking())
            .count();
        let gates_involved: BTreeSet<String> =
            findings.iter().map(|f| f.gate.to_string()).collect();

        // Sort findings for deterministic hashing before computing content hash.
        let mut sorted_for_hash = findings.clone();
        sorted_for_hash.sort_by(|a, b| {
            a.gate
                .to_string()
                .cmp(&b.gate.to_string())
                .then_with(|| a.summary.cmp(&b.summary))
        });
        let content_bytes = serde_json::to_vec(&sorted_for_hash).unwrap_or_default();
        let content_hash = ContentHash::compute(&content_bytes);

        Self {
            findings,
            max_severity,
            blocking_count,
            gates_involved,
            content_hash,
        }
    }

    /// Whether this bundle has any release-blocking findings.
    pub fn has_blockers(&self) -> bool {
        self.blocking_count > 0
    }

    /// Whether the bundle is clean (no findings at all).
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Findings filtered by gate.
    pub fn findings_for_gate(&self, gate: PromotedGateKind) -> Vec<&TriageFinding> {
        self.findings.iter().filter(|f| f.gate == gate).collect()
    }

    /// Findings filtered by severity.
    pub fn findings_at_severity(&self, min_severity: TriageSeverity) -> Vec<&TriageFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= min_severity)
            .collect()
    }
}

impl fmt::Display for TriageBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TriageBundle(findings={}, blockers={}, max_severity={}, gates={})",
            self.findings.len(),
            self.blocking_count,
            self.max_severity
                .map(|s| s.to_string())
                .unwrap_or_else(|| "none".to_owned()),
            self.gates_involved.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// GatePromotionEntry — per-gate promotion tracking
// ---------------------------------------------------------------------------

/// Tracks the promotion status of a single gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatePromotionEntry {
    /// Which gate.
    pub gate: PromotedGateKind,
    /// Current promotion status.
    pub status: PromotionStatus,
    /// Oracle invariants backing this gate.
    pub oracle_invariants: BTreeSet<String>,
    /// Blocker threshold for this gate.
    pub threshold: BlockerThreshold,
    /// Whether cross-validation with local assertions succeeded.
    pub cross_validated: bool,
    /// Number of evaluation runs completed.
    pub evaluation_runs: usize,
    /// Number of passing runs.
    pub passing_runs: usize,
}

impl GatePromotionEntry {
    /// Create a new entry in assertion-based status.
    pub fn assertion_based(gate: PromotedGateKind) -> Self {
        Self {
            gate,
            status: PromotionStatus::AssertionBased,
            oracle_invariants: BTreeSet::new(),
            threshold: BlockerThreshold::strict(gate),
            cross_validated: false,
            evaluation_runs: 0,
            passing_runs: 0,
        }
    }

    /// Pass rate in millionths.
    pub fn pass_rate_millionths(&self) -> u64 {
        if self.evaluation_runs == 0 {
            return 0;
        }
        (self.passing_runs as u64) * SCALE / (self.evaluation_runs as u64)
    }

    /// Record an evaluation run.
    pub fn record_run(&mut self, passed: bool) {
        self.evaluation_runs += 1;
        if passed {
            self.passing_runs += 1;
        }
    }

    /// Whether the gate currently blocks release based on threshold.
    pub fn blocks_release(&self) -> bool {
        if self.evaluation_runs == 0 {
            return true; // No data → fail-closed
        }
        let failures = self.evaluation_runs - self.passing_runs;
        self.threshold
            .would_block(self.pass_rate_millionths(), failures)
    }

    /// Promote to oracle-wired.
    pub fn wire_oracles(&mut self, invariants: BTreeSet<String>) {
        self.oracle_invariants = invariants;
        self.status = PromotionStatus::OracleWired;
    }

    /// Promote to oracle-backed.
    pub fn promote_to_oracle_backed(&mut self) {
        self.status = PromotionStatus::OracleBacked;
    }

    /// Promote to fully promoted.
    pub fn promote_fully(&mut self) {
        self.status = PromotionStatus::FullyPromoted;
        self.cross_validated = true;
    }
}

// ---------------------------------------------------------------------------
// ReleaseGatePromotionRegistry — tracks all gate promotions
// ---------------------------------------------------------------------------

/// Registry tracking promotion of all release gates from assertion-based
/// to oracle-backed evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGatePromotionRegistry {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Per-gate promotion entries.
    pub gates: Vec<GatePromotionEntry>,
}

impl ReleaseGatePromotionRegistry {
    /// Create an empty registry.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            schema_version: RELEASE_GATE_PROMOTION_SCHEMA_VERSION.to_owned(),
            epoch,
            gates: Vec::new(),
        }
    }

    /// Create a registry pre-populated with all gate kinds.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        let mut reg = Self::new(epoch);
        for gate in PromotedGateKind::ALL {
            reg.gates.push(GatePromotionEntry::assertion_based(gate));
        }
        reg
    }

    /// Get gate entry by kind.
    pub fn gate(&self, kind: PromotedGateKind) -> Option<&GatePromotionEntry> {
        self.gates.iter().find(|g| g.gate == kind)
    }

    /// Get mutable gate entry by kind.
    pub fn gate_mut(&mut self, kind: PromotedGateKind) -> Option<&mut GatePromotionEntry> {
        self.gates.iter_mut().find(|g| g.gate == kind)
    }

    /// Count gates by promotion status.
    pub fn status_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for g in &self.gates {
            *counts.entry(g.status.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// How many gates are oracle-backed.
    pub fn oracle_backed_count(&self) -> usize {
        self.gates
            .iter()
            .filter(|g| g.status.is_oracle_backed())
            .count()
    }

    /// Overall promotion progress in millionths.
    pub fn promotion_progress_millionths(&self) -> u64 {
        if self.gates.is_empty() {
            return 0;
        }
        let promoted = self.oracle_backed_count() as u64;
        promoted * SCALE / (self.gates.len() as u64)
    }

    /// Evaluate all gates and produce a triage bundle.
    pub fn evaluate_and_triage(&self) -> TriageBundle {
        let mut findings = Vec::new();

        for gate in &self.gates {
            // Check if gate has no evaluation data
            if gate.evaluation_runs == 0 && gate.status.is_oracle_backed() {
                findings.push(TriageFinding {
                    gate: gate.gate,
                    severity: TriageSeverity::Warning,
                    summary: format!(
                        "Gate '{}' is oracle-backed but has no evaluation runs",
                        gate.gate
                    ),
                    detail: "Oracle-backed gates should have at least one evaluation run."
                        .to_owned(),
                    remediation_steps: vec![
                        "Run the gate evaluation pipeline.".to_owned(),
                        "Check oracle availability.".to_owned(),
                    ],
                    scenario_id: None,
                    oracle_invariant: None,
                });
            }

            // Check if gate blocks release
            if gate.evaluation_runs > 0 && gate.blocks_release() {
                let failures = gate.evaluation_runs - gate.passing_runs;
                findings.push(TriageFinding {
                    gate: gate.gate,
                    severity: TriageSeverity::Error,
                    summary: format!(
                        "Gate '{}' blocks release: {}/{} runs passed ({} failures)",
                        gate.gate, gate.passing_runs, gate.evaluation_runs, failures,
                    ),
                    detail: format!(
                        "Pass rate {}‰ is below threshold {}‰.",
                        gate.pass_rate_millionths() / 1_000,
                        gate.threshold.min_pass_rate_millionths / 1_000,
                    ),
                    remediation_steps: vec![
                        "Investigate failing oracle invariants.".to_owned(),
                        "Check scenario execution logs.".to_owned(),
                        "Review bridge contract violations.".to_owned(),
                    ],
                    scenario_id: None,
                    oracle_invariant: None,
                });
            }

            // Check if oracle-backed gate has no oracles
            if gate.status.is_oracle_backed() && gate.oracle_invariants.is_empty() {
                findings.push(TriageFinding {
                    gate: gate.gate,
                    severity: TriageSeverity::Critical,
                    summary: format!(
                        "Gate '{}' claims oracle-backed but has no oracle invariants",
                        gate.gate
                    ),
                    detail:
                        "A gate promoted to oracle-backed must have at least one oracle invariant."
                            .to_owned(),
                    remediation_steps: vec![
                        "Wire oracle invariants to this gate.".to_owned(),
                        "Demote gate to assertion_based until oracles are available.".to_owned(),
                    ],
                    scenario_id: None,
                    oracle_invariant: None,
                });
            }
        }

        TriageBundle::from_findings(findings)
    }

    /// Build a promotion report.
    pub fn build_report(&self) -> ReleaseGatePromotionReport {
        let status_counts = self.status_counts();
        let triage = self.evaluate_and_triage();

        let total_oracle_invariants: usize =
            self.gates.iter().map(|g| g.oracle_invariants.len()).sum();

        let total_evaluation_runs: usize = self.gates.iter().map(|g| g.evaluation_runs).sum();

        let total_passing_runs: usize = self.gates.iter().map(|g| g.passing_runs).sum();

        let cross_validated_count = self.gates.iter().filter(|g| g.cross_validated).count();

        let release_blocked = triage.has_blockers()
            || self
                .gates
                .iter()
                .any(|g| g.evaluation_runs > 0 && g.blocks_release());

        let mut sorted_gates = self.gates.clone();
        sorted_gates.sort_by_key(|a| a.gate);
        let content_bytes = serde_json::to_vec(&sorted_gates).unwrap_or_default();
        let content_hash = ContentHash::compute(&content_bytes);

        ReleaseGatePromotionReport {
            schema_version: RELEASE_GATE_PROMOTION_SCHEMA_VERSION.to_owned(),
            epoch: self.epoch,
            total_gates: self.gates.len(),
            status_counts,
            oracle_backed_count: self.oracle_backed_count(),
            promotion_progress_millionths: self.promotion_progress_millionths(),
            total_oracle_invariants,
            total_evaluation_runs,
            total_passing_runs,
            cross_validated_count,
            triage_finding_count: triage.findings.len(),
            triage_blocking_count: triage.blocking_count,
            release_blocked,
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// ReleaseGatePromotionReport
// ---------------------------------------------------------------------------

/// Report on release gate promotion progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGatePromotionReport {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Total number of gates.
    pub total_gates: usize,
    /// Counts by promotion status.
    pub status_counts: BTreeMap<String, usize>,
    /// Number of oracle-backed gates.
    pub oracle_backed_count: usize,
    /// Promotion progress in millionths.
    pub promotion_progress_millionths: u64,
    /// Total oracle invariants across all gates.
    pub total_oracle_invariants: usize,
    /// Total evaluation runs across all gates.
    pub total_evaluation_runs: usize,
    /// Total passing runs across all gates.
    pub total_passing_runs: usize,
    /// Number of cross-validated gates.
    pub cross_validated_count: usize,
    /// Number of triage findings.
    pub triage_finding_count: usize,
    /// Number of release-blocking triage findings.
    pub triage_blocking_count: usize,
    /// Whether release is currently blocked.
    pub release_blocked: bool,
    /// Content hash for deterministic comparison.
    pub content_hash: ContentHash,
}

impl ReleaseGatePromotionReport {
    /// Whether all gates are oracle-backed.
    pub fn fully_promoted(&self) -> bool {
        self.oracle_backed_count == self.total_gates && self.total_gates > 0
    }

    /// Overall pass rate in millionths.
    pub fn overall_pass_rate_millionths(&self) -> u64 {
        if self.total_evaluation_runs == 0 {
            return 0;
        }
        (self.total_passing_runs as u64) * SCALE / (self.total_evaluation_runs as u64)
    }
}

impl fmt::Display for ReleaseGatePromotionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReleaseGatePromotionReport(gates={}/{} oracle-backed, progress={}‰, \
             runs={}/{}, findings={}, blocked={})",
            self.oracle_backed_count,
            self.total_gates,
            self.promotion_progress_millionths / 1_000,
            self.total_passing_runs,
            self.total_evaluation_runs,
            self.triage_finding_count,
            self.release_blocked,
        )
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(500)
    }

    // -- PromotedGateKind tests --

    #[test]
    fn promoted_gate_all_has_eight() {
        assert_eq!(PromotedGateKind::ALL.len(), 8);
    }

    #[test]
    fn promoted_gate_original_vs_correction() {
        let original: Vec<_> = PromotedGateKind::ALL
            .iter()
            .filter(|g| g.is_original_gate())
            .collect();
        let correction: Vec<_> = PromotedGateKind::ALL
            .iter()
            .filter(|g| g.is_correction_wave_gate())
            .collect();
        assert_eq!(original.len(), 4);
        assert_eq!(correction.len(), 4);
    }

    #[test]
    fn promoted_gate_serde_roundtrip() {
        for gate in PromotedGateKind::ALL {
            let json = serde_json::to_string(&gate).unwrap();
            let round: PromotedGateKind = serde_json::from_str(&json).unwrap();
            assert_eq!(gate, round);
        }
    }

    // -- PromotionStatus tests --

    #[test]
    fn promotion_status_oracle_backed() {
        assert!(!PromotionStatus::AssertionBased.is_oracle_backed());
        assert!(!PromotionStatus::OracleWired.is_oracle_backed());
        assert!(PromotionStatus::OracleBacked.is_oracle_backed());
        assert!(PromotionStatus::FullyPromoted.is_oracle_backed());
    }

    #[test]
    fn promotion_status_serde_roundtrip() {
        for status in [
            PromotionStatus::AssertionBased,
            PromotionStatus::OracleWired,
            PromotionStatus::OracleBacked,
            PromotionStatus::FullyPromoted,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let round: PromotionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, round);
        }
    }

    // -- BlockerThreshold tests --

    #[test]
    fn threshold_strict_blocks_any_failure() {
        let t = BlockerThreshold::strict(PromotedGateKind::LifecycleScenarios);
        assert!(t.would_block(999_999, 0)); // 99.9999% < 100%
        assert!(t.would_block(SCALE, 1)); // 1 failure > 0 max
        assert!(!t.would_block(SCALE, 0)); // perfect
    }

    #[test]
    fn threshold_relaxed_allows_some_failures() {
        let t = BlockerThreshold::relaxed(PromotedGateKind::ReplayDeterminism);
        assert!(!t.would_block(DEFAULT_MIN_ORACLE_PASS_RATE, 1));
        assert!(!t.would_block(SCALE, 2));
        assert!(t.would_block(SCALE, 3)); // 3 > max_failures=2
    }

    #[test]
    fn threshold_serde_roundtrip() {
        let t = BlockerThreshold::strict(PromotedGateKind::BudgetPropagation)
            .with_rationale("zero tolerance for budget violations");
        let json = serde_json::to_string(&t).unwrap();
        let round: BlockerThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(t, round);
    }

    // -- TriageSeverity tests --

    #[test]
    fn triage_severity_blocking() {
        assert!(!TriageSeverity::Info.is_release_blocking());
        assert!(!TriageSeverity::Warning.is_release_blocking());
        assert!(TriageSeverity::Error.is_release_blocking());
        assert!(TriageSeverity::Critical.is_release_blocking());
    }

    #[test]
    fn triage_severity_ordering() {
        assert!(TriageSeverity::Info < TriageSeverity::Warning);
        assert!(TriageSeverity::Warning < TriageSeverity::Error);
        assert!(TriageSeverity::Error < TriageSeverity::Critical);
    }

    // -- TriageBundle tests --

    #[test]
    fn triage_bundle_empty() {
        let bundle = TriageBundle::from_findings(vec![]);
        assert!(bundle.is_clean());
        assert!(!bundle.has_blockers());
        assert!(bundle.max_severity.is_none());
    }

    #[test]
    fn triage_bundle_with_findings() {
        let findings = vec![
            TriageFinding {
                gate: PromotedGateKind::LifecycleScenarios,
                severity: TriageSeverity::Warning,
                summary: "test".to_owned(),
                detail: "detail".to_owned(),
                remediation_steps: vec![],
                scenario_id: None,
                oracle_invariant: None,
            },
            TriageFinding {
                gate: PromotedGateKind::BudgetPropagation,
                severity: TriageSeverity::Error,
                summary: "budget".to_owned(),
                detail: "detail".to_owned(),
                remediation_steps: vec!["fix".to_owned()],
                scenario_id: Some("s1".to_owned()),
                oracle_invariant: None,
            },
        ];

        let bundle = TriageBundle::from_findings(findings);
        assert!(!bundle.is_clean());
        assert!(bundle.has_blockers());
        assert_eq!(bundle.blocking_count, 1);
        assert_eq!(bundle.max_severity, Some(TriageSeverity::Error));
        assert_eq!(bundle.gates_involved.len(), 2);
    }

    #[test]
    fn triage_bundle_filter_by_gate() {
        let findings = vec![
            TriageFinding {
                gate: PromotedGateKind::LifecycleScenarios,
                severity: TriageSeverity::Info,
                summary: "a".to_owned(),
                detail: String::new(),
                remediation_steps: vec![],
                scenario_id: None,
                oracle_invariant: None,
            },
            TriageFinding {
                gate: PromotedGateKind::BudgetPropagation,
                severity: TriageSeverity::Warning,
                summary: "b".to_owned(),
                detail: String::new(),
                remediation_steps: vec![],
                scenario_id: None,
                oracle_invariant: None,
            },
        ];

        let bundle = TriageBundle::from_findings(findings);
        assert_eq!(
            bundle
                .findings_for_gate(PromotedGateKind::LifecycleScenarios)
                .len(),
            1
        );
        assert_eq!(
            bundle
                .findings_for_gate(PromotedGateKind::MockSeamAbsence)
                .len(),
            0
        );
    }

    #[test]
    fn triage_bundle_filter_by_severity() {
        let findings = vec![
            TriageFinding {
                gate: PromotedGateKind::LifecycleScenarios,
                severity: TriageSeverity::Info,
                summary: "info".to_owned(),
                detail: String::new(),
                remediation_steps: vec![],
                scenario_id: None,
                oracle_invariant: None,
            },
            TriageFinding {
                gate: PromotedGateKind::LifecycleScenarios,
                severity: TriageSeverity::Error,
                summary: "error".to_owned(),
                detail: String::new(),
                remediation_steps: vec![],
                scenario_id: None,
                oracle_invariant: None,
            },
        ];

        let bundle = TriageBundle::from_findings(findings);
        assert_eq!(bundle.findings_at_severity(TriageSeverity::Info).len(), 2);
        assert_eq!(bundle.findings_at_severity(TriageSeverity::Error).len(), 1);
    }

    #[test]
    fn triage_bundle_serde_roundtrip() {
        let bundle = TriageBundle::from_findings(vec![TriageFinding {
            gate: PromotedGateKind::LifecycleScenarios,
            severity: TriageSeverity::Warning,
            summary: "test".to_owned(),
            detail: "detail".to_owned(),
            remediation_steps: vec!["step1".to_owned()],
            scenario_id: Some("s1".to_owned()),
            oracle_invariant: Some("safety".to_owned()),
        }]);
        let json = serde_json::to_string(&bundle).unwrap();
        let round: TriageBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, round);
    }

    // -- GatePromotionEntry tests --

    #[test]
    fn gate_entry_defaults() {
        let entry = GatePromotionEntry::assertion_based(PromotedGateKind::LifecycleScenarios);
        assert_eq!(entry.status, PromotionStatus::AssertionBased);
        assert!(entry.oracle_invariants.is_empty());
        assert!(!entry.cross_validated);
        assert_eq!(entry.pass_rate_millionths(), 0);
    }

    #[test]
    fn gate_entry_record_runs() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::ReplayDeterminism);
        entry.record_run(true);
        entry.record_run(true);
        entry.record_run(false);
        assert_eq!(entry.evaluation_runs, 3);
        assert_eq!(entry.passing_runs, 2);
        assert_eq!(entry.pass_rate_millionths(), 666_666);
    }

    #[test]
    fn gate_entry_promotion_lifecycle() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::CapabilityNarrowing);

        // Wire oracles
        let mut invariants = BTreeSet::new();
        invariants.insert("narrowing_check".to_owned());
        entry.wire_oracles(invariants);
        assert_eq!(entry.status, PromotionStatus::OracleWired);

        // Promote to oracle-backed
        entry.promote_to_oracle_backed();
        assert!(entry.status.is_oracle_backed());

        // Fully promote
        entry.promote_fully();
        assert_eq!(entry.status, PromotionStatus::FullyPromoted);
        assert!(entry.cross_validated);
    }

    #[test]
    fn gate_entry_blocks_release_no_data() {
        let entry = GatePromotionEntry::assertion_based(PromotedGateKind::LifecycleScenarios);
        assert!(entry.blocks_release()); // fail-closed with no data
    }

    #[test]
    fn gate_entry_blocks_release_with_failures() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::LifecycleScenarios);
        entry.record_run(true);
        entry.record_run(true);
        entry.record_run(false);
        assert!(entry.blocks_release()); // strict threshold: 0 failures allowed
    }

    // -- Registry tests --

    #[test]
    fn registry_defaults_populated() {
        let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        assert_eq!(reg.gates.len(), 8);
    }

    #[test]
    fn registry_gate_lookup() {
        let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        assert!(reg.gate(PromotedGateKind::LifecycleScenarios).is_some());
        assert!(reg.gate(PromotedGateKind::MockSeamAbsence).is_some());
    }

    #[test]
    fn registry_initial_progress_zero() {
        let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        assert_eq!(reg.promotion_progress_millionths(), 0);
        assert_eq!(reg.oracle_backed_count(), 0);
    }

    #[test]
    fn registry_serde_roundtrip() {
        let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let json = serde_json::to_string_pretty(&reg).unwrap();
        let round: ReleaseGatePromotionRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, round);
    }

    // -- Report tests --

    #[test]
    fn report_initial() {
        let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let report = reg.build_report();
        assert!(!report.fully_promoted());
        assert_eq!(report.total_gates, 8);
        assert_eq!(report.oracle_backed_count, 0);
        assert_eq!(report.total_evaluation_runs, 0);
    }

    #[test]
    fn report_after_promotion() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());

        // Promote 4 gates to oracle-backed
        for gate_kind in [
            PromotedGateKind::LifecycleScenarios,
            PromotedGateKind::ReplayDeterminism,
            PromotedGateKind::BudgetPropagation,
            PromotedGateKind::CapabilityNarrowing,
        ] {
            let gate = reg.gate_mut(gate_kind).unwrap();
            let mut invariants = BTreeSet::new();
            invariants.insert(format!("{gate_kind}_oracle"));
            gate.wire_oracles(invariants);
            gate.promote_to_oracle_backed();
            gate.record_run(true);
            gate.record_run(true);
        }

        let report = reg.build_report();
        assert_eq!(report.oracle_backed_count, 4);
        assert_eq!(report.promotion_progress_millionths, 500_000);
        assert_eq!(report.total_evaluation_runs, 8);
        assert_eq!(report.total_passing_runs, 8);
    }

    #[test]
    fn report_serde_roundtrip() {
        let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let report = reg.build_report();
        let json = serde_json::to_string_pretty(&report).unwrap();
        let round: ReleaseGatePromotionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, round);
    }

    #[test]
    fn report_content_hash_deterministic() {
        let make = || {
            let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
            reg.build_report()
        };
        let r1 = make();
        let r2 = make();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_content_hash_ignores_gate_insertion_order() {
        let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let mut reversed = reg.clone();
        reversed.gates.reverse();

        assert_eq!(
            reg.build_report().content_hash,
            reversed.build_report().content_hash
        );
    }

    #[test]
    fn report_display() {
        let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let report = reg.build_report();
        let s = format!("{report}");
        assert!(s.contains("ReleaseGatePromotionReport"));
    }

    // -- Triage tests --

    #[test]
    fn triage_clean_for_assertion_based_gates() {
        let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let bundle = reg.evaluate_and_triage();
        // Assertion-based gates with no runs → no findings
        assert!(bundle.is_clean());
    }

    #[test]
    fn triage_warns_for_oracle_backed_no_runs() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let gate = reg.gate_mut(PromotedGateKind::LifecycleScenarios).unwrap();
        let mut invariants = BTreeSet::new();
        invariants.insert("safety".to_owned());
        gate.wire_oracles(invariants);
        gate.promote_to_oracle_backed();

        let bundle = reg.evaluate_and_triage();
        assert!(!bundle.is_clean());
        assert_eq!(bundle.findings.len(), 1);
        assert_eq!(bundle.findings[0].severity, TriageSeverity::Warning);
    }

    #[test]
    fn triage_critical_for_oracle_backed_no_invariants() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let gate = reg.gate_mut(PromotedGateKind::LifecycleScenarios).unwrap();
        gate.status = PromotionStatus::OracleBacked;
        // No invariants wired

        let bundle = reg.evaluate_and_triage();
        assert!(bundle.has_blockers());
        let critical_findings: Vec<_> = bundle
            .findings
            .iter()
            .filter(|f| f.severity == TriageSeverity::Critical)
            .collect();
        assert!(!critical_findings.is_empty());
    }

    // =====================================================================
    // Deep enrichment tests
    // =====================================================================

    // -- Enum serde roundtrip exhaustive --

    #[test]
    fn promoted_gate_kind_serde_snake_case_values() {
        // Verify the exact JSON representation (snake_case from #[serde(rename_all)])
        let expected = [
            (
                PromotedGateKind::LifecycleScenarios,
                "\"lifecycle_scenarios\"",
            ),
            (
                PromotedGateKind::ReplayDeterminism,
                "\"replay_determinism\"",
            ),
            (
                PromotedGateKind::ObligationResolution,
                "\"obligation_resolution\"",
            ),
            (
                PromotedGateKind::EvidenceCompleteness,
                "\"evidence_completeness\"",
            ),
            (
                PromotedGateKind::BudgetPropagation,
                "\"budget_propagation\"",
            ),
            (
                PromotedGateKind::CapabilityNarrowing,
                "\"capability_narrowing\"",
            ),
            (PromotedGateKind::MockSeamAbsence, "\"mock_seam_absence\""),
            (
                PromotedGateKind::OutcomePropagation,
                "\"outcome_propagation\"",
            ),
        ];
        for (variant, json_str) in expected {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, json_str, "mismatch for {variant:?}");
            let deserialized: PromotedGateKind = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, variant);
        }
    }

    #[test]
    fn promotion_status_serde_snake_case_values() {
        let expected = [
            (PromotionStatus::AssertionBased, "\"assertion_based\""),
            (PromotionStatus::OracleWired, "\"oracle_wired\""),
            (PromotionStatus::OracleBacked, "\"oracle_backed\""),
            (PromotionStatus::FullyPromoted, "\"fully_promoted\""),
        ];
        for (variant, json_str) in expected {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, json_str, "mismatch for {variant:?}");
            let deserialized: PromotionStatus = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, variant);
        }
    }

    #[test]
    fn triage_severity_serde_snake_case_values() {
        let expected = [
            (TriageSeverity::Info, "\"info\""),
            (TriageSeverity::Warning, "\"warning\""),
            (TriageSeverity::Error, "\"error\""),
            (TriageSeverity::Critical, "\"critical\""),
        ];
        for (variant, json_str) in expected {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, json_str, "mismatch for {variant:?}");
            let deserialized: TriageSeverity = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, variant);
        }
    }

    // -- Display / as_str consistency --

    #[test]
    fn promoted_gate_kind_display_matches_serde() {
        // Display output should match the serde snake_case string (without quotes)
        for gate in PromotedGateKind::ALL {
            let display = gate.to_string();
            let serde_str = serde_json::to_string(&gate).unwrap();
            // serde_str is e.g. "\"lifecycle_scenarios\"", strip quotes
            let serde_inner = &serde_str[1..serde_str.len() - 1];
            assert_eq!(
                display, serde_inner,
                "Display vs serde mismatch for {gate:?}"
            );
        }
    }

    #[test]
    fn promotion_status_display_matches_serde() {
        for status in [
            PromotionStatus::AssertionBased,
            PromotionStatus::OracleWired,
            PromotionStatus::OracleBacked,
            PromotionStatus::FullyPromoted,
        ] {
            let display = status.to_string();
            let serde_str = serde_json::to_string(&status).unwrap();
            let serde_inner = &serde_str[1..serde_str.len() - 1];
            assert_eq!(
                display, serde_inner,
                "Display vs serde mismatch for {status:?}"
            );
        }
    }

    #[test]
    fn triage_severity_display_matches_serde() {
        for severity in [
            TriageSeverity::Info,
            TriageSeverity::Warning,
            TriageSeverity::Error,
            TriageSeverity::Critical,
        ] {
            let display = severity.to_string();
            let serde_str = serde_json::to_string(&severity).unwrap();
            let serde_inner = &serde_str[1..serde_str.len() - 1];
            assert_eq!(
                display, serde_inner,
                "Display vs serde mismatch for {severity:?}"
            );
        }
    }

    // -- Error Display formatting --

    #[test]
    fn triage_bundle_display_with_no_findings() {
        let bundle = TriageBundle::from_findings(vec![]);
        let s = format!("{bundle}");
        assert!(s.contains("findings=0"));
        assert!(s.contains("blockers=0"));
        assert!(s.contains("max_severity=none"));
        assert!(s.contains("gates=0"));
    }

    #[test]
    fn triage_bundle_display_with_mixed_findings() {
        let findings = vec![
            TriageFinding {
                gate: PromotedGateKind::LifecycleScenarios,
                severity: TriageSeverity::Info,
                summary: "a".to_owned(),
                detail: String::new(),
                remediation_steps: vec![],
                scenario_id: None,
                oracle_invariant: None,
            },
            TriageFinding {
                gate: PromotedGateKind::BudgetPropagation,
                severity: TriageSeverity::Critical,
                summary: "b".to_owned(),
                detail: String::new(),
                remediation_steps: vec![],
                scenario_id: None,
                oracle_invariant: None,
            },
        ];
        let bundle = TriageBundle::from_findings(findings);
        let s = format!("{bundle}");
        assert!(s.contains("findings=2"));
        assert!(s.contains("blockers=1"));
        assert!(s.contains("max_severity=critical"));
        assert!(s.contains("gates=2"));
    }

    #[test]
    fn report_display_includes_all_fields() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let gate = reg.gate_mut(PromotedGateKind::LifecycleScenarios).unwrap();
        let mut inv = BTreeSet::new();
        inv.insert("inv_a".to_owned());
        gate.wire_oracles(inv);
        gate.promote_to_oracle_backed();
        gate.record_run(true);

        let report = reg.build_report();
        let s = format!("{report}");
        assert!(s.contains("oracle-backed"));
        assert!(s.contains("progress="));
        assert!(s.contains("runs="));
        assert!(s.contains("findings="));
        assert!(s.contains("blocked="));
    }

    // -- Edge cases: empty inputs, boundary values --

    #[test]
    fn registry_empty_has_zero_progress() {
        let reg = ReleaseGatePromotionRegistry::new(test_epoch());
        assert_eq!(reg.gates.len(), 0);
        assert_eq!(reg.promotion_progress_millionths(), 0);
        assert_eq!(reg.oracle_backed_count(), 0);
    }

    #[test]
    fn registry_empty_evaluate_and_triage_clean() {
        let reg = ReleaseGatePromotionRegistry::new(test_epoch());
        let bundle = reg.evaluate_and_triage();
        assert!(bundle.is_clean());
    }

    #[test]
    fn registry_empty_report_not_fully_promoted() {
        let reg = ReleaseGatePromotionRegistry::new(test_epoch());
        let report = reg.build_report();
        assert!(!report.fully_promoted());
        assert_eq!(report.total_gates, 0);
        assert!(!report.release_blocked);
    }

    #[test]
    fn gate_entry_pass_rate_zero_runs() {
        let entry = GatePromotionEntry::assertion_based(PromotedGateKind::MockSeamAbsence);
        assert_eq!(entry.pass_rate_millionths(), 0);
    }

    #[test]
    fn gate_entry_pass_rate_all_passing() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::OutcomePropagation);
        for _ in 0..100 {
            entry.record_run(true);
        }
        assert_eq!(entry.pass_rate_millionths(), SCALE);
    }

    #[test]
    fn gate_entry_pass_rate_all_failing() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::EvidenceCompleteness);
        for _ in 0..50 {
            entry.record_run(false);
        }
        assert_eq!(entry.pass_rate_millionths(), 0);
        assert_eq!(entry.evaluation_runs, 50);
        assert_eq!(entry.passing_runs, 0);
    }

    #[test]
    fn gate_entry_pass_rate_boundary_one_run_pass() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::ReplayDeterminism);
        entry.record_run(true);
        assert_eq!(entry.pass_rate_millionths(), SCALE);
    }

    #[test]
    fn gate_entry_pass_rate_boundary_one_run_fail() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::ReplayDeterminism);
        entry.record_run(false);
        assert_eq!(entry.pass_rate_millionths(), 0);
    }

    #[test]
    fn blocker_threshold_would_block_boundary_exact_threshold() {
        let t = BlockerThreshold::strict(PromotedGateKind::LifecycleScenarios);
        // Exact threshold: pass_rate == min_pass_rate, failures == max_failures
        assert!(!t.would_block(SCALE, 0));
        // Just below threshold
        assert!(t.would_block(SCALE - 1, 0));
    }

    #[test]
    fn blocker_threshold_relaxed_boundary_exact_pass_rate() {
        let t = BlockerThreshold::relaxed(PromotedGateKind::CapabilityNarrowing);
        // Exactly at min pass rate with max failures => should NOT block
        assert!(!t.would_block(DEFAULT_MIN_ORACLE_PASS_RATE, 2));
        // One below pass rate => blocks
        assert!(t.would_block(DEFAULT_MIN_ORACLE_PASS_RATE - 1, 2));
        // One above max failures => blocks
        assert!(t.would_block(SCALE, 3));
    }

    #[test]
    fn blocker_threshold_with_rationale_preserves_fields() {
        let t = BlockerThreshold::strict(PromotedGateKind::MockSeamAbsence)
            .with_rationale("no mock seams in production");
        assert_eq!(t.rationale, "no mock seams in production");
        assert_eq!(t.gate, PromotedGateKind::MockSeamAbsence);
        assert!(t.infra_errors_block);
        assert!(t.timeouts_block);
    }

    // -- State machine transitions --

    #[test]
    fn gate_promotion_state_machine_full_lifecycle() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::ObligationResolution);

        // Start: AssertionBased
        assert_eq!(entry.status, PromotionStatus::AssertionBased);
        assert!(!entry.status.is_oracle_backed());
        assert!(!entry.cross_validated);

        // Step 1: Wire oracles -> OracleWired
        let mut inv = BTreeSet::new();
        inv.insert("obligation_inv_1".to_owned());
        inv.insert("obligation_inv_2".to_owned());
        entry.wire_oracles(inv.clone());
        assert_eq!(entry.status, PromotionStatus::OracleWired);
        assert!(!entry.status.is_oracle_backed());
        assert_eq!(entry.oracle_invariants.len(), 2);

        // Step 2: Promote to oracle-backed
        entry.promote_to_oracle_backed();
        assert_eq!(entry.status, PromotionStatus::OracleBacked);
        assert!(entry.status.is_oracle_backed());
        assert!(!entry.cross_validated);

        // Step 3: Fully promote
        entry.promote_fully();
        assert_eq!(entry.status, PromotionStatus::FullyPromoted);
        assert!(entry.status.is_oracle_backed());
        assert!(entry.cross_validated);
    }

    #[test]
    fn gate_entry_wire_oracles_replaces_previous_invariants() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::BudgetPropagation);
        let mut inv1 = BTreeSet::new();
        inv1.insert("old_invariant".to_owned());
        entry.wire_oracles(inv1);
        assert_eq!(entry.oracle_invariants.len(), 1);
        assert!(entry.oracle_invariants.contains("old_invariant"));

        let mut inv2 = BTreeSet::new();
        inv2.insert("new_a".to_owned());
        inv2.insert("new_b".to_owned());
        entry.wire_oracles(inv2);
        assert_eq!(entry.oracle_invariants.len(), 2);
        assert!(!entry.oracle_invariants.contains("old_invariant"));
        assert!(entry.oracle_invariants.contains("new_a"));
        assert!(entry.oracle_invariants.contains("new_b"));
        assert_eq!(entry.status, PromotionStatus::OracleWired);
    }

    #[test]
    fn gate_entry_blocks_release_relaxed_threshold_passing() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::OutcomePropagation);
        entry.threshold = BlockerThreshold::relaxed(PromotedGateKind::OutcomePropagation);
        // 98 pass, 2 fail => pass rate = 980_000, failures = 2
        for _ in 0..98 {
            entry.record_run(true);
        }
        for _ in 0..2 {
            entry.record_run(false);
        }
        // Pass rate 980_000 >= 950_000, failures 2 <= 2 => not blocking
        assert!(!entry.blocks_release());
    }

    #[test]
    fn gate_entry_blocks_release_relaxed_threshold_failing() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::OutcomePropagation);
        entry.threshold = BlockerThreshold::relaxed(PromotedGateKind::OutcomePropagation);
        // 94 pass, 6 fail => pass rate = 940_000, failures = 6
        for _ in 0..94 {
            entry.record_run(true);
        }
        for _ in 0..6 {
            entry.record_run(false);
        }
        // Pass rate 940_000 < 950_000 => blocking
        assert!(entry.blocks_release());
    }

    // -- Canonical hash determinism --

    #[test]
    fn triage_bundle_content_hash_deterministic() {
        let make_bundle = || {
            let findings = vec![
                TriageFinding {
                    gate: PromotedGateKind::LifecycleScenarios,
                    severity: TriageSeverity::Warning,
                    summary: "warn".to_owned(),
                    detail: "d".to_owned(),
                    remediation_steps: vec!["step".to_owned()],
                    scenario_id: Some("s1".to_owned()),
                    oracle_invariant: Some("inv1".to_owned()),
                },
                TriageFinding {
                    gate: PromotedGateKind::BudgetPropagation,
                    severity: TriageSeverity::Error,
                    summary: "err".to_owned(),
                    detail: "e".to_owned(),
                    remediation_steps: vec![],
                    scenario_id: None,
                    oracle_invariant: None,
                },
            ];
            TriageBundle::from_findings(findings)
        };
        let b1 = make_bundle();
        let b2 = make_bundle();
        assert_eq!(b1.content_hash, b2.content_hash);
    }

    #[test]
    fn triage_bundle_content_hash_changes_with_different_findings() {
        let f1 = vec![TriageFinding {
            gate: PromotedGateKind::LifecycleScenarios,
            severity: TriageSeverity::Info,
            summary: "a".to_owned(),
            detail: String::new(),
            remediation_steps: vec![],
            scenario_id: None,
            oracle_invariant: None,
        }];
        let f2 = vec![TriageFinding {
            gate: PromotedGateKind::LifecycleScenarios,
            severity: TriageSeverity::Critical,
            summary: "a".to_owned(),
            detail: String::new(),
            remediation_steps: vec![],
            scenario_id: None,
            oracle_invariant: None,
        }];
        let b1 = TriageBundle::from_findings(f1);
        let b2 = TriageBundle::from_findings(f2);
        assert_ne!(b1.content_hash, b2.content_hash);
    }

    #[test]
    fn report_content_hash_changes_with_promotion() {
        let reg1 = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let r1 = reg1.build_report();

        let mut reg2 = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let gate = reg2.gate_mut(PromotedGateKind::LifecycleScenarios).unwrap();
        gate.promote_to_oracle_backed();
        let r2 = reg2.build_report();

        assert_ne!(r1.content_hash, r2.content_hash);
    }

    // -- Registry promotion progress --

    #[test]
    fn registry_promotion_progress_partial() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        // Promote 2 of 8 gates
        for kind in [
            PromotedGateKind::LifecycleScenarios,
            PromotedGateKind::ReplayDeterminism,
        ] {
            let gate = reg.gate_mut(kind).unwrap();
            gate.promote_to_oracle_backed();
        }
        assert_eq!(reg.oracle_backed_count(), 2);
        // 2/8 = 250_000
        assert_eq!(reg.promotion_progress_millionths(), 250_000);
    }

    #[test]
    fn registry_promotion_progress_full() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        for kind in PromotedGateKind::ALL {
            let gate = reg.gate_mut(kind).unwrap();
            gate.promote_fully();
        }
        assert_eq!(reg.oracle_backed_count(), 8);
        assert_eq!(reg.promotion_progress_millionths(), SCALE);
    }

    #[test]
    fn report_fully_promoted_requires_all_gates() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        // Promote 7 out of 8
        for kind in &PromotedGateKind::ALL[..7] {
            let gate = reg.gate_mut(*kind).unwrap();
            gate.promote_to_oracle_backed();
        }
        let report = reg.build_report();
        assert!(!report.fully_promoted());

        // Promote the last one
        let gate = reg.gate_mut(PromotedGateKind::ALL[7]).unwrap();
        gate.promote_to_oracle_backed();
        let report = reg.build_report();
        assert!(report.fully_promoted());
    }

    #[test]
    fn report_overall_pass_rate_zero_when_no_runs() {
        let reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let report = reg.build_report();
        assert_eq!(report.overall_pass_rate_millionths(), 0);
    }

    #[test]
    fn report_overall_pass_rate_aggregates_all_gates() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        // Gate 1: 3 pass / 4 total
        let g1 = reg.gate_mut(PromotedGateKind::LifecycleScenarios).unwrap();
        for _ in 0..3 {
            g1.record_run(true);
        }
        g1.record_run(false);

        // Gate 2: 2 pass / 2 total
        let g2 = reg.gate_mut(PromotedGateKind::ReplayDeterminism).unwrap();
        g2.record_run(true);
        g2.record_run(true);

        let report = reg.build_report();
        assert_eq!(report.total_evaluation_runs, 6);
        assert_eq!(report.total_passing_runs, 5);
        // 5/6 * 1_000_000 = 833_333
        assert_eq!(report.overall_pass_rate_millionths(), 833_333);
    }

    // -- Triage advanced scenarios --

    #[test]
    fn triage_error_finding_when_gate_blocks_release() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let gate = reg.gate_mut(PromotedGateKind::LifecycleScenarios).unwrap();
        // strict threshold: 0 failures allowed
        gate.record_run(true);
        gate.record_run(false);

        let bundle = reg.evaluate_and_triage();
        assert!(bundle.has_blockers());
        assert_eq!(bundle.blocking_count, 1);
        let err_findings: Vec<_> = bundle
            .findings
            .iter()
            .filter(|f| f.severity == TriageSeverity::Error)
            .collect();
        assert_eq!(err_findings.len(), 1);
        assert!(err_findings[0].summary.contains("blocks release"));
    }

    #[test]
    fn triage_combined_warning_and_critical_for_oracle_backed_empty_invariants_no_runs() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        let gate = reg
            .gate_mut(PromotedGateKind::EvidenceCompleteness)
            .unwrap();
        // Force oracle-backed without invariants and without runs
        gate.status = PromotionStatus::OracleBacked;

        let bundle = reg.evaluate_and_triage();
        // Should get both: Warning (no runs) + Critical (no invariants)
        let warnings: Vec<_> = bundle
            .findings
            .iter()
            .filter(|f| f.severity == TriageSeverity::Warning)
            .collect();
        let criticals: Vec<_> = bundle
            .findings
            .iter()
            .filter(|f| f.severity == TriageSeverity::Critical)
            .collect();
        assert!(!warnings.is_empty(), "expected warning for no runs");
        assert!(!criticals.is_empty(), "expected critical for no invariants");
        assert!(bundle.has_blockers());
    }

    #[test]
    fn registry_status_counts_reflect_mixed_statuses() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        // Default: all 8 assertion_based
        let counts = reg.status_counts();
        assert_eq!(counts.get("assertion_based"), Some(&8));

        // Promote 2 to different statuses
        reg.gate_mut(PromotedGateKind::LifecycleScenarios)
            .unwrap()
            .promote_to_oracle_backed();
        reg.gate_mut(PromotedGateKind::ReplayDeterminism)
            .unwrap()
            .promote_fully();

        let counts = reg.status_counts();
        assert_eq!(counts.get("assertion_based"), Some(&6));
        assert_eq!(counts.get("oracle_backed"), Some(&1));
        assert_eq!(counts.get("fully_promoted"), Some(&1));
    }

    #[test]
    fn registry_gate_lookup_returns_none_when_not_present() {
        let mut reg = ReleaseGatePromotionRegistry::new(test_epoch());
        // Empty registry — no gates
        assert!(reg.gate(PromotedGateKind::LifecycleScenarios).is_none());
        assert!(reg.gate_mut(PromotedGateKind::LifecycleScenarios).is_none());
    }

    #[test]
    fn triage_findings_for_gate_with_multiple_findings_same_gate() {
        let findings = vec![
            TriageFinding {
                gate: PromotedGateKind::LifecycleScenarios,
                severity: TriageSeverity::Info,
                summary: "first".to_owned(),
                detail: String::new(),
                remediation_steps: vec![],
                scenario_id: None,
                oracle_invariant: None,
            },
            TriageFinding {
                gate: PromotedGateKind::LifecycleScenarios,
                severity: TriageSeverity::Error,
                summary: "second".to_owned(),
                detail: String::new(),
                remediation_steps: vec![],
                scenario_id: None,
                oracle_invariant: None,
            },
            TriageFinding {
                gate: PromotedGateKind::BudgetPropagation,
                severity: TriageSeverity::Warning,
                summary: "third".to_owned(),
                detail: String::new(),
                remediation_steps: vec![],
                scenario_id: None,
                oracle_invariant: None,
            },
        ];
        let bundle = TriageBundle::from_findings(findings);
        let lc_findings = bundle.findings_for_gate(PromotedGateKind::LifecycleScenarios);
        assert_eq!(lc_findings.len(), 2);
        let bp_findings = bundle.findings_for_gate(PromotedGateKind::BudgetPropagation);
        assert_eq!(bp_findings.len(), 1);
    }

    #[test]
    fn triage_severity_ordering_is_total() {
        let severities = [
            TriageSeverity::Info,
            TriageSeverity::Warning,
            TriageSeverity::Error,
            TriageSeverity::Critical,
        ];
        for i in 0..severities.len() {
            for j in (i + 1)..severities.len() {
                assert!(
                    severities[i] < severities[j],
                    "{:?} should be less than {:?}",
                    severities[i],
                    severities[j]
                );
            }
        }
    }

    #[test]
    fn promoted_gate_kind_ordering_is_deterministic() {
        // ALL array is in deterministic order; verify Ord agrees
        for i in 0..PromotedGateKind::ALL.len() {
            for j in (i + 1)..PromotedGateKind::ALL.len() {
                assert!(
                    PromotedGateKind::ALL[i] < PromotedGateKind::ALL[j],
                    "{:?} should be less than {:?}",
                    PromotedGateKind::ALL[i],
                    PromotedGateKind::ALL[j]
                );
            }
        }
    }

    #[test]
    fn schema_version_constant_is_correct() {
        assert_eq!(
            RELEASE_GATE_PROMOTION_SCHEMA_VERSION,
            "franken-engine.frankenlab-release-gate-promotion.v1"
        );
    }

    #[test]
    fn bead_id_constant_is_correct() {
        assert_eq!(RELEASE_GATE_PROMOTION_BEAD_ID, "bd-3nr.1.4.3");
    }

    #[test]
    fn registry_new_uses_correct_schema_version() {
        let reg = ReleaseGatePromotionRegistry::new(test_epoch());
        assert_eq!(reg.schema_version, RELEASE_GATE_PROMOTION_SCHEMA_VERSION);
        assert_eq!(reg.epoch, test_epoch());
    }

    #[test]
    fn report_release_blocked_when_any_gate_blocks() {
        let mut reg = ReleaseGatePromotionRegistry::with_defaults(test_epoch());
        // All gates pass except one
        for kind in PromotedGateKind::ALL {
            let gate = reg.gate_mut(kind).unwrap();
            gate.threshold = BlockerThreshold::relaxed(kind);
            for _ in 0..10 {
                gate.record_run(true);
            }
        }
        // Make one gate fail
        let gate = reg.gate_mut(PromotedGateKind::MockSeamAbsence).unwrap();
        gate.threshold = BlockerThreshold::strict(PromotedGateKind::MockSeamAbsence);
        gate.record_run(false);

        let report = reg.build_report();
        assert!(report.release_blocked);
    }

    #[test]
    fn gate_entry_serde_roundtrip_with_runs_and_invariants() {
        let mut entry = GatePromotionEntry::assertion_based(PromotedGateKind::CapabilityNarrowing);
        let mut inv = BTreeSet::new();
        inv.insert("narrowing_a".to_owned());
        inv.insert("narrowing_b".to_owned());
        entry.wire_oracles(inv);
        entry.promote_to_oracle_backed();
        entry.record_run(true);
        entry.record_run(true);
        entry.record_run(false);

        let json = serde_json::to_string(&entry).unwrap();
        let round: GatePromotionEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, round);
        assert_eq!(round.evaluation_runs, 3);
        assert_eq!(round.passing_runs, 2);
        assert_eq!(round.oracle_invariants.len(), 2);
    }
}
