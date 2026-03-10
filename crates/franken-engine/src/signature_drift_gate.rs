#![forbid(unsafe_code)]

//! Signature-drift and transition-budget compliance gate for adaptive claims.
//!
//! Implements [RGC-617C]: gates adaptive performance claims and shipped behavior
//! on regime signature drift and transition-budget compliance so wins only count
//! when the regime context is stable and well-characterized.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::regime_signature_feature::RegimeLabel;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for drift gate artifacts.
pub const DRIFT_GATE_SCHEMA_VERSION: &str = "franken-engine.signature-drift-gate.v1";

/// Maximum signature drift (L1, millionths) before a claim is downgraded.
/// 150_000 = 15% total drift across all signature dimensions.
pub const DEFAULT_MAX_DRIFT_MILLIONTHS: i64 = 150_000;

/// Maximum number of transitions consumed before budget violation.
pub const DEFAULT_MAX_TRANSITIONS: u64 = 10;

/// Staleness window: maximum epochs since last signature refresh before
/// the gate abstains.
pub const DEFAULT_MAX_STALENESS_EPOCHS: u64 = 5;

/// Minimum number of observations required for a signature to be considered
/// trustworthy for drift calculation.
pub const MIN_OBSERVATIONS_FOR_DRIFT: u64 = 10;

/// Fixed-point unit.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Drift measurement
// ---------------------------------------------------------------------------

/// A snapshot of a regime signature at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureSnapshot {
    /// Trace/signature ID.
    pub signature_id: String,
    /// Regime label at snapshot time.
    pub regime: RegimeLabel,
    /// Feature vector in millionths, keyed by feature name.
    pub features: BTreeMap<String, i64>,
    /// Number of observations backing this snapshot.
    pub observation_count: u64,
    /// Epoch at which this snapshot was taken.
    pub epoch: SecurityEpoch,
    /// Content hash for deterministic identity.
    pub content_hash: ContentHash,
}

impl SignatureSnapshot {
    /// Create a new snapshot from raw features.
    pub fn new(
        signature_id: String,
        regime: RegimeLabel,
        features: BTreeMap<String, i64>,
        observation_count: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        let content_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(DRIFT_GATE_SCHEMA_VERSION.as_bytes());
            buf.extend_from_slice(signature_id.as_bytes());
            for (k, v) in &features {
                buf.extend_from_slice(k.as_bytes());
                buf.extend_from_slice(&v.to_le_bytes());
            }
            buf.extend_from_slice(&observation_count.to_le_bytes());
            ContentHash::compute(&buf)
        };
        Self {
            signature_id,
            regime,
            features,
            observation_count,
            epoch,
            content_hash,
        }
    }

    /// True if the snapshot has enough observations to be trustworthy.
    pub fn is_trustworthy(&self) -> bool {
        self.observation_count >= MIN_OBSERVATIONS_FOR_DRIFT
    }

    /// Number of feature dimensions.
    pub fn dimension(&self) -> usize {
        self.features.len()
    }
}

/// Result of computing drift between two signature snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftMeasurement {
    /// L1 (Manhattan) drift across shared dimensions.
    pub l1_drift_millionths: i64,
    /// L∞ (Chebyshev) drift — maximum single-dimension drift.
    pub linf_drift_millionths: i64,
    /// Per-feature drift contributions (sorted by key).
    pub per_feature_drift: BTreeMap<String, i64>,
    /// Number of shared dimensions.
    pub shared_dimensions: usize,
    /// Features present in baseline but missing in current.
    pub missing_features: BTreeSet<String>,
    /// Features present in current but not in baseline.
    pub new_features: BTreeSet<String>,
    /// Whether the regime label changed.
    pub regime_changed: bool,
}

/// Compute drift between a baseline and current signature snapshot.
pub fn compute_drift(
    baseline: &SignatureSnapshot,
    current: &SignatureSnapshot,
) -> DriftMeasurement {
    let mut per_feature_drift = BTreeMap::new();
    let mut l1: i64 = 0;
    let mut linf: i64 = 0;
    let mut shared: usize = 0;

    // Shared features.
    for (key, baseline_val) in &baseline.features {
        if let Some(current_val) = current.features.get(key) {
            let diff = baseline_val.saturating_sub(*current_val).abs();
            per_feature_drift.insert(key.clone(), diff);
            l1 = l1.saturating_add(diff);
            linf = linf.max(diff);
            shared += 1;
        }
    }

    let missing: BTreeSet<String> = baseline
        .features
        .keys()
        .filter(|k| !current.features.contains_key(*k))
        .cloned()
        .collect();

    let new_features: BTreeSet<String> = current
        .features
        .keys()
        .filter(|k| !baseline.features.contains_key(*k))
        .cloned()
        .collect();

    let regime_changed = baseline.regime != current.regime;

    DriftMeasurement {
        l1_drift_millionths: l1,
        linf_drift_millionths: linf,
        per_feature_drift,
        shared_dimensions: shared,
        missing_features: missing,
        new_features,
        regime_changed,
    }
}

// ---------------------------------------------------------------------------
// Transition budget tracking
// ---------------------------------------------------------------------------

/// A record of a regime transition event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionEvent {
    /// Sequential transition number.
    pub sequence: u64,
    /// Source regime.
    pub from_regime: RegimeLabel,
    /// Target regime.
    pub to_regime: RegimeLabel,
    /// L1 drift at transition.
    pub drift_at_transition_millionths: i64,
    /// Epoch of the transition.
    pub epoch: SecurityEpoch,
}

/// Tracks transitions against a budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionBudgetTracker {
    /// Maximum transitions allowed.
    pub max_transitions: u64,
    /// Transitions consumed so far.
    pub transitions_consumed: u64,
    /// History of transitions.
    pub history: Vec<TransitionEvent>,
    /// Epoch at which the budget was last reset.
    pub reset_epoch: SecurityEpoch,
}

impl TransitionBudgetTracker {
    /// Create a new tracker with the given budget.
    pub fn new(max_transitions: u64, epoch: SecurityEpoch) -> Self {
        Self {
            max_transitions,
            transitions_consumed: 0,
            history: Vec::new(),
            reset_epoch: epoch,
        }
    }

    /// Record a transition. Returns true if budget is still within limits.
    pub fn record_transition(
        &mut self,
        from: RegimeLabel,
        to: RegimeLabel,
        drift_millionths: i64,
        epoch: SecurityEpoch,
    ) -> bool {
        self.transitions_consumed += 1;
        self.history.push(TransitionEvent {
            sequence: self.transitions_consumed,
            from_regime: from,
            to_regime: to,
            drift_at_transition_millionths: drift_millionths,
            epoch,
        });
        self.is_within_budget()
    }

    /// True if transitions consumed is within budget.
    pub fn is_within_budget(&self) -> bool {
        self.transitions_consumed <= self.max_transitions
    }

    /// Remaining transitions before violation.
    pub fn remaining(&self) -> u64 {
        self.max_transitions
            .saturating_sub(self.transitions_consumed)
    }

    /// Reset the tracker to zero with a new epoch.
    pub fn reset(&mut self, epoch: SecurityEpoch) {
        self.transitions_consumed = 0;
        self.history.clear();
        self.reset_epoch = epoch;
    }

    /// Fraction of budget consumed (millionths).
    pub fn utilization_millionths(&self) -> i64 {
        if self.max_transitions == 0 {
            return MILLION;
        }
        let consumed = self.transitions_consumed.min(self.max_transitions) as i64;
        consumed
            .checked_mul(MILLION)
            .map(|n| n / self.max_transitions as i64)
            .unwrap_or(MILLION)
    }
}

// ---------------------------------------------------------------------------
// Gate configuration and verdict
// ---------------------------------------------------------------------------

/// Configuration for the drift gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftGateConfig {
    /// Maximum L1 drift (millionths) before downgrade.
    pub max_l1_drift_millionths: i64,
    /// Maximum L∞ drift (millionths) per single feature.
    pub max_linf_drift_millionths: i64,
    /// Maximum transitions before budget violation.
    pub max_transitions: u64,
    /// Maximum epochs since baseline before staleness.
    pub max_staleness_epochs: u64,
    /// Minimum observations for trustworthy snapshots.
    pub min_observations: u64,
    /// Whether regime change alone triggers downgrade.
    pub regime_change_triggers_downgrade: bool,
}

impl Default for DriftGateConfig {
    fn default() -> Self {
        Self {
            max_l1_drift_millionths: DEFAULT_MAX_DRIFT_MILLIONTHS,
            max_linf_drift_millionths: DEFAULT_MAX_DRIFT_MILLIONTHS / 2,
            max_transitions: DEFAULT_MAX_TRANSITIONS,
            max_staleness_epochs: DEFAULT_MAX_STALENESS_EPOCHS,
            min_observations: MIN_OBSERVATIONS_FOR_DRIFT,
            regime_change_triggers_downgrade: true,
        }
    }
}

/// Reason a claim was downgraded by the drift gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DowngradeReason {
    /// L1 drift exceeded threshold.
    ExcessiveL1Drift,
    /// Single-feature drift exceeded L∞ threshold.
    ExcessiveLinfDrift,
    /// Transition budget exhausted.
    TransitionBudgetExhausted,
    /// Regime changed since baseline.
    RegimeChanged,
    /// Baseline signature is stale (too many epochs old).
    StaleBaseline,
    /// Baseline has insufficient observations.
    InsufficientBaselineObservations,
    /// Current snapshot has insufficient observations.
    InsufficientCurrentObservations,
    /// No shared dimensions between baseline and current.
    NoSharedDimensions,
}

impl fmt::Display for DowngradeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExcessiveL1Drift => write!(f, "excessive_l1_drift"),
            Self::ExcessiveLinfDrift => write!(f, "excessive_linf_drift"),
            Self::TransitionBudgetExhausted => write!(f, "transition_budget_exhausted"),
            Self::RegimeChanged => write!(f, "regime_changed"),
            Self::StaleBaseline => write!(f, "stale_baseline"),
            Self::InsufficientBaselineObservations => {
                write!(f, "insufficient_baseline_observations")
            }
            Self::InsufficientCurrentObservations => {
                write!(f, "insufficient_current_observations")
            }
            Self::NoSharedDimensions => write!(f, "no_shared_dimensions"),
        }
    }
}

/// Gate verdict for an adaptive claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GateVerdict {
    /// Claim passes: drift and budget within limits.
    Pass,
    /// Claim downgraded: drift or budget violation, but not catastrophic.
    Downgrade,
    /// Claim blocked: conditions are too far out of spec.
    Block,
    /// Gate abstains: insufficient evidence to decide.
    Abstain,
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Downgrade => write!(f, "downgrade"),
            Self::Block => write!(f, "block"),
            Self::Abstain => write!(f, "abstain"),
        }
    }
}

/// Full gate decision with evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecision {
    /// Schema version.
    pub schema_version: String,
    /// Decision ID.
    pub decision_id: String,
    /// The claim being gated (opaque identifier).
    pub claim_id: String,
    /// Overall verdict.
    pub verdict: GateVerdict,
    /// Downgrade reasons (empty if Pass).
    pub downgrade_reasons: BTreeSet<DowngradeReason>,
    /// Drift measurement (None if abstained early).
    pub drift: Option<DriftMeasurement>,
    /// Budget status at decision time.
    pub budget_utilization_millionths: i64,
    /// Budget remaining transitions.
    pub budget_remaining: u64,
    /// Staleness in epochs (current - baseline).
    pub staleness_epochs: u64,
    /// Epoch at decision.
    pub epoch: SecurityEpoch,
    /// Content hash for audit.
    pub content_hash: ContentHash,
}

impl GateDecision {
    /// True if the claim passes.
    pub fn is_pass(&self) -> bool {
        self.verdict == GateVerdict::Pass
    }

    /// True if the claim is blocked.
    pub fn is_blocked(&self) -> bool {
        self.verdict == GateVerdict::Block
    }

    /// True if the gate abstained.
    pub fn is_abstained(&self) -> bool {
        self.verdict == GateVerdict::Abstain
    }

    /// Number of downgrade reasons.
    pub fn reason_count(&self) -> usize {
        self.downgrade_reasons.len()
    }
}

// ---------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------

/// Evaluate the drift gate for a claim.
pub fn evaluate_gate(
    claim_id: &str,
    baseline: &SignatureSnapshot,
    current: &SignatureSnapshot,
    budget: &TransitionBudgetTracker,
    config: &DriftGateConfig,
    epoch: SecurityEpoch,
) -> GateDecision {
    let mut reasons: BTreeSet<DowngradeReason> = BTreeSet::new();

    // Check observation counts.
    if baseline.observation_count < config.min_observations {
        reasons.insert(DowngradeReason::InsufficientBaselineObservations);
    }
    if current.observation_count < config.min_observations {
        reasons.insert(DowngradeReason::InsufficientCurrentObservations);
    }

    // If either snapshot is untrustworthy, abstain.
    if !baseline.is_trustworthy() || !current.is_trustworthy() {
        let hash = compute_decision_hash(claim_id, "abstain", &reasons);
        let decision_id = format!("dg-abstain-{}", &hash.to_hex()[..12]);
        return GateDecision {
            schema_version: DRIFT_GATE_SCHEMA_VERSION.to_string(),
            decision_id,
            claim_id: claim_id.to_string(),
            verdict: GateVerdict::Abstain,
            downgrade_reasons: reasons,
            drift: None,
            budget_utilization_millionths: budget.utilization_millionths(),
            budget_remaining: budget.remaining(),
            staleness_epochs: epoch.as_u64().abs_diff(baseline.epoch.as_u64()),
            epoch,
            content_hash: hash,
        };
    }

    // Staleness check.
    let staleness = epoch.as_u64().abs_diff(baseline.epoch.as_u64());
    if staleness > config.max_staleness_epochs {
        reasons.insert(DowngradeReason::StaleBaseline);
    }

    // Compute drift.
    let drift = compute_drift(baseline, current);

    // No shared dimensions → abstain.
    if drift.shared_dimensions == 0 {
        reasons.insert(DowngradeReason::NoSharedDimensions);
        let hash = compute_decision_hash(claim_id, "abstain-noshared", &reasons);
        let decision_id = format!("dg-abstain-{}", &hash.to_hex()[..12]);
        return GateDecision {
            schema_version: DRIFT_GATE_SCHEMA_VERSION.to_string(),
            decision_id,
            claim_id: claim_id.to_string(),
            verdict: GateVerdict::Abstain,
            downgrade_reasons: reasons,
            drift: Some(drift),
            budget_utilization_millionths: budget.utilization_millionths(),
            budget_remaining: budget.remaining(),
            staleness_epochs: staleness,
            epoch,
            content_hash: hash,
        };
    }

    // L1 drift check.
    if drift.l1_drift_millionths > config.max_l1_drift_millionths {
        reasons.insert(DowngradeReason::ExcessiveL1Drift);
    }

    // L∞ drift check.
    if drift.linf_drift_millionths > config.max_linf_drift_millionths {
        reasons.insert(DowngradeReason::ExcessiveLinfDrift);
    }

    // Regime change check.
    if config.regime_change_triggers_downgrade && drift.regime_changed {
        reasons.insert(DowngradeReason::RegimeChanged);
    }

    // Budget check.
    if !budget.is_within_budget() {
        reasons.insert(DowngradeReason::TransitionBudgetExhausted);
    }

    // Determine verdict.
    let verdict = if reasons.is_empty() {
        GateVerdict::Pass
    } else if reasons.contains(&DowngradeReason::TransitionBudgetExhausted)
        && reasons.contains(&DowngradeReason::ExcessiveL1Drift)
    {
        // Multiple severe violations → block
        GateVerdict::Block
    } else if reasons.len() >= 3 {
        GateVerdict::Block
    } else {
        GateVerdict::Downgrade
    };

    let hash = compute_decision_hash(claim_id, &verdict.to_string(), &reasons);
    let decision_id = format!("dg-{}-{}", verdict, &hash.to_hex()[..12]);

    GateDecision {
        schema_version: DRIFT_GATE_SCHEMA_VERSION.to_string(),
        decision_id,
        claim_id: claim_id.to_string(),
        verdict,
        downgrade_reasons: reasons,
        drift: Some(drift),
        budget_utilization_millionths: budget.utilization_millionths(),
        budget_remaining: budget.remaining(),
        staleness_epochs: staleness,
        epoch,
        content_hash: hash,
    }
}

fn compute_decision_hash(
    claim_id: &str,
    verdict: &str,
    reasons: &BTreeSet<DowngradeReason>,
) -> ContentHash {
    let mut buf = Vec::new();
    buf.extend_from_slice(DRIFT_GATE_SCHEMA_VERSION.as_bytes());
    buf.extend_from_slice(claim_id.as_bytes());
    buf.extend_from_slice(verdict.as_bytes());
    for r in reasons {
        buf.extend_from_slice(r.to_string().as_bytes());
    }
    ContentHash::compute(&buf)
}

// ---------------------------------------------------------------------------
// Batch gate runner
// ---------------------------------------------------------------------------

/// Batch result from gating multiple claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchGateResult {
    /// Schema version.
    pub schema_version: String,
    /// All decisions.
    pub decisions: Vec<GateDecision>,
    /// Count of each verdict.
    pub verdict_counts: BTreeMap<String, usize>,
    /// Overall pass rate (millionths).
    pub pass_rate_millionths: i64,
    /// Content hash for audit.
    pub content_hash: ContentHash,
}

/// Run the drift gate over multiple claims with shared baseline/current.
pub fn batch_evaluate(
    claim_ids: &[&str],
    baseline: &SignatureSnapshot,
    current: &SignatureSnapshot,
    budget: &TransitionBudgetTracker,
    config: &DriftGateConfig,
    epoch: SecurityEpoch,
) -> BatchGateResult {
    let decisions: Vec<GateDecision> = claim_ids
        .iter()
        .map(|id| evaluate_gate(id, baseline, current, budget, config, epoch))
        .collect();

    let mut verdict_counts: BTreeMap<String, usize> = BTreeMap::new();
    for d in &decisions {
        *verdict_counts.entry(d.verdict.to_string()).or_insert(0) += 1;
    }

    let pass_count = decisions.iter().filter(|d| d.is_pass()).count();
    let pass_rate_millionths = if decisions.is_empty() {
        0
    } else {
        (pass_count as i64)
            .checked_mul(MILLION)
            .map(|n| n / decisions.len() as i64)
            .unwrap_or(0)
    };

    let mut hash_buf = Vec::new();
    hash_buf.extend_from_slice(DRIFT_GATE_SCHEMA_VERSION.as_bytes());
    for d in &decisions {
        hash_buf.extend_from_slice(d.content_hash.as_bytes());
    }
    let content_hash = ContentHash::compute(&hash_buf);

    BatchGateResult {
        schema_version: DRIFT_GATE_SCHEMA_VERSION.to_string(),
        decisions,
        verdict_counts,
        pass_rate_millionths,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Claim scope ledger
// ---------------------------------------------------------------------------

/// Records the regime scope under which a claim is valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimScopeRecord {
    /// Claim identifier.
    pub claim_id: String,
    /// Regime under which the claim was established.
    pub valid_regime: RegimeLabel,
    /// Baseline signature at claim establishment.
    pub baseline_hash: ContentHash,
    /// Maximum drift observed while claim was still passing.
    pub max_passing_drift_millionths: i64,
    /// Whether the claim is currently active.
    pub active: bool,
    /// Gate decision that deactivated the claim (if any).
    pub deactivation_reason: Option<DowngradeReason>,
    /// Epoch of last validation.
    pub last_validated_epoch: SecurityEpoch,
}

/// A ledger of claim scope records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimScopeLedger {
    /// Schema version.
    pub schema_version: String,
    /// All scope records, keyed by claim_id.
    pub records: Vec<ClaimScopeRecord>,
    /// Epoch of ledger creation.
    pub epoch: SecurityEpoch,
}

impl ClaimScopeLedger {
    /// Create a new empty ledger.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            schema_version: DRIFT_GATE_SCHEMA_VERSION.to_string(),
            records: Vec::new(),
            epoch,
        }
    }

    /// Add a scope record.
    pub fn add_record(&mut self, record: ClaimScopeRecord) {
        self.records.push(record);
    }

    /// Number of active claims.
    pub fn active_count(&self) -> usize {
        self.records.iter().filter(|r| r.active).count()
    }

    /// Number of deactivated claims.
    pub fn deactivated_count(&self) -> usize {
        self.records.iter().filter(|r| !r.active).count()
    }

    /// Look up a record by claim_id.
    pub fn get_record(&self, claim_id: &str) -> Option<&ClaimScopeRecord> {
        self.records.iter().find(|r| r.claim_id == claim_id)
    }

    /// Update a record based on a gate decision.
    pub fn apply_decision(&mut self, decision: &GateDecision) {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|r| r.claim_id == decision.claim_id)
        {
            record.last_validated_epoch = decision.epoch;
            if let Some(drift) = &decision.drift
                && decision.is_pass()
            {
                record.max_passing_drift_millionths = record
                    .max_passing_drift_millionths
                    .max(drift.l1_drift_millionths);
            }
            if decision.is_blocked() {
                record.active = false;
                record.deactivation_reason = decision.downgrade_reasons.iter().next().copied();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

/// Specimen family for drift gate evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DriftGateSpecimenFamily {
    /// Stable regime, low drift.
    StableLowDrift,
    /// Moderate drift within limits.
    ModerateDrift,
    /// Excessive drift triggering downgrade.
    ExcessiveDrift,
    /// Regime change triggering downgrade.
    RegimeChange,
    /// Budget exhaustion.
    BudgetExhaustion,
    /// Stale baseline.
    StaleBaseline,
    /// Insufficient observations.
    InsufficientData,
}

impl fmt::Display for DriftGateSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StableLowDrift => write!(f, "stable_low_drift"),
            Self::ModerateDrift => write!(f, "moderate_drift"),
            Self::ExcessiveDrift => write!(f, "excessive_drift"),
            Self::RegimeChange => write!(f, "regime_change"),
            Self::BudgetExhaustion => write!(f, "budget_exhaustion"),
            Self::StaleBaseline => write!(f, "stale_baseline"),
            Self::InsufficientData => write!(f, "insufficient_data"),
        }
    }
}

/// A specimen in the evidence corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftGateSpecimen {
    /// Specimen ID.
    pub id: String,
    /// Family classification.
    pub family: DriftGateSpecimenFamily,
    /// Description.
    pub description: String,
    /// Expected verdict.
    pub expected_verdict: GateVerdict,
    /// Gate decision.
    pub decision: GateDecision,
}

/// Build the standard evidence corpus.
pub fn build_evidence_corpus(epoch: SecurityEpoch) -> Vec<DriftGateSpecimen> {
    let config = DriftGateConfig::default();
    let mut specimens = Vec::new();
    let regime = RegimeLabel::Classified(crate::regime_detector::Regime::Normal);

    // 1. Stable low drift — should pass
    {
        let baseline = make_snapshot(
            "bl-stable",
            regime,
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
            epoch,
        );
        let current = make_snapshot(
            "cur-stable",
            regime,
            &[("cpu", 510_000), ("mem", 305_000)],
            100,
            epoch,
        );
        let budget = TransitionBudgetTracker::new(config.max_transitions, epoch);
        let decision = evaluate_gate("claim-stable", &baseline, &current, &budget, &config, epoch);
        specimens.push(DriftGateSpecimen {
            id: "specimen-stable-01".into(),
            family: DriftGateSpecimenFamily::StableLowDrift,
            description: "Low drift, same regime, budget unused".into(),
            expected_verdict: GateVerdict::Pass,
            decision,
        });
    }

    // 2. Moderate drift — should pass
    {
        let baseline = make_snapshot(
            "bl-moderate",
            regime,
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
            epoch,
        );
        let current = make_snapshot(
            "cur-moderate",
            regime,
            &[("cpu", 550_000), ("mem", 350_000)],
            100,
            epoch,
        );
        let budget = TransitionBudgetTracker::new(config.max_transitions, epoch);
        let decision = evaluate_gate(
            "claim-moderate",
            &baseline,
            &current,
            &budget,
            &config,
            epoch,
        );
        specimens.push(DriftGateSpecimen {
            id: "specimen-moderate-01".into(),
            family: DriftGateSpecimenFamily::ModerateDrift,
            description: "Moderate drift within L1 threshold".into(),
            expected_verdict: GateVerdict::Pass,
            decision,
        });
    }

    // 3. Excessive drift — should downgrade
    {
        let baseline = make_snapshot(
            "bl-excess",
            regime,
            &[("cpu", 100_000), ("mem", 100_000)],
            100,
            epoch,
        );
        let current = make_snapshot(
            "cur-excess",
            regime,
            &[("cpu", 500_000), ("mem", 500_000)],
            100,
            epoch,
        );
        let budget = TransitionBudgetTracker::new(config.max_transitions, epoch);
        let decision = evaluate_gate("claim-excess", &baseline, &current, &budget, &config, epoch);
        specimens.push(DriftGateSpecimen {
            id: "specimen-excessive-01".into(),
            family: DriftGateSpecimenFamily::ExcessiveDrift,
            description: "L1 drift 800k > threshold 150k".into(),
            expected_verdict: GateVerdict::Downgrade,
            decision,
        });
    }

    // 4. Regime change — should downgrade
    {
        let elevated = RegimeLabel::Classified(crate::regime_detector::Regime::Elevated);
        let baseline = make_snapshot(
            "bl-regime",
            regime,
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
            epoch,
        );
        let current = make_snapshot(
            "cur-regime",
            elevated,
            &[("cpu", 510_000), ("mem", 305_000)],
            100,
            epoch,
        );
        let budget = TransitionBudgetTracker::new(config.max_transitions, epoch);
        let decision = evaluate_gate("claim-regime", &baseline, &current, &budget, &config, epoch);
        specimens.push(DriftGateSpecimen {
            id: "specimen-regime-change-01".into(),
            family: DriftGateSpecimenFamily::RegimeChange,
            description: "Regime changed from Normal to Elevated".into(),
            expected_verdict: GateVerdict::Downgrade,
            decision,
        });
    }

    // 5. Budget exhaustion — should downgrade
    {
        let baseline = make_snapshot(
            "bl-budget",
            regime,
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
            epoch,
        );
        let current = make_snapshot(
            "cur-budget",
            regime,
            &[("cpu", 510_000), ("mem", 305_000)],
            100,
            epoch,
        );
        let mut budget = TransitionBudgetTracker::new(config.max_transitions, epoch);
        for i in 0..=config.max_transitions {
            budget.record_transition(
                regime,
                regime,
                1_000,
                SecurityEpoch::from_raw(epoch.as_u64() + i),
            );
        }
        let decision = evaluate_gate("claim-budget", &baseline, &current, &budget, &config, epoch);
        specimens.push(DriftGateSpecimen {
            id: "specimen-budget-01".into(),
            family: DriftGateSpecimenFamily::BudgetExhaustion,
            description: "Budget exhausted with 11 transitions > max 10".into(),
            expected_verdict: GateVerdict::Downgrade,
            decision,
        });
    }

    // 6. Stale baseline — should downgrade
    {
        let old_epoch = SecurityEpoch::from_raw(epoch.as_u64().saturating_sub(100));
        let baseline = make_snapshot(
            "bl-stale",
            regime,
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
            old_epoch,
        );
        let current = make_snapshot(
            "cur-stale",
            regime,
            &[("cpu", 510_000), ("mem", 305_000)],
            100,
            epoch,
        );
        let budget = TransitionBudgetTracker::new(config.max_transitions, epoch);
        let decision = evaluate_gate("claim-stale", &baseline, &current, &budget, &config, epoch);
        specimens.push(DriftGateSpecimen {
            id: "specimen-stale-01".into(),
            family: DriftGateSpecimenFamily::StaleBaseline,
            description: "Baseline is 100 epochs old > max 5".into(),
            expected_verdict: GateVerdict::Downgrade,
            decision,
        });
    }

    // 7. Insufficient observations — should abstain
    {
        let baseline = make_snapshot("bl-insuff", regime, &[("cpu", 500_000)], 3, epoch);
        let current = make_snapshot("cur-insuff", regime, &[("cpu", 510_000)], 3, epoch);
        let budget = TransitionBudgetTracker::new(config.max_transitions, epoch);
        let decision = evaluate_gate("claim-insuff", &baseline, &current, &budget, &config, epoch);
        specimens.push(DriftGateSpecimen {
            id: "specimen-insufficient-01".into(),
            family: DriftGateSpecimenFamily::InsufficientData,
            description: "Only 3 observations < minimum 10".into(),
            expected_verdict: GateVerdict::Abstain,
            decision,
        });
    }

    specimens
}

fn make_snapshot(
    id: &str,
    regime: RegimeLabel,
    features: &[(&str, i64)],
    obs: u64,
    epoch: SecurityEpoch,
) -> SignatureSnapshot {
    let feat_map: BTreeMap<String, i64> =
        features.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    SignatureSnapshot::new(id.to_string(), regime, feat_map, obs, epoch)
}

/// Run the evidence corpus and return a deterministic manifest hash.
pub fn run_evidence_corpus(epoch: SecurityEpoch) -> (Vec<DriftGateSpecimen>, ContentHash) {
    let specimens = build_evidence_corpus(epoch);
    let mut hash_buf = Vec::new();
    hash_buf.extend_from_slice(DRIFT_GATE_SCHEMA_VERSION.as_bytes());
    for s in &specimens {
        hash_buf.extend_from_slice(s.id.as_bytes());
        hash_buf.extend_from_slice(s.decision.content_hash.as_bytes());
    }
    let manifest_hash = ContentHash::compute(&hash_buf);
    (specimens, manifest_hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regime_detector::Regime;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(50)
    }

    fn normal_regime() -> RegimeLabel {
        RegimeLabel::Classified(Regime::Normal)
    }

    fn elevated_regime() -> RegimeLabel {
        RegimeLabel::Classified(Regime::Elevated)
    }

    fn default_config() -> DriftGateConfig {
        DriftGateConfig::default()
    }

    fn snapshot(
        id: &str,
        regime: RegimeLabel,
        features: &[(&str, i64)],
        obs: u64,
    ) -> SignatureSnapshot {
        make_snapshot(id, regime, features, obs, test_epoch())
    }

    // --- Schema and constants ---

    #[test]
    fn schema_version_format() {
        assert!(DRIFT_GATE_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(DRIFT_GATE_SCHEMA_VERSION.contains(".v1"));
    }

    #[test]
    fn default_thresholds_reasonable() {
        assert!(DEFAULT_MAX_DRIFT_MILLIONTHS > 0);
        assert!(DEFAULT_MAX_DRIFT_MILLIONTHS < MILLION);
        assert!(DEFAULT_MAX_TRANSITIONS > 0);
        assert!(DEFAULT_MAX_STALENESS_EPOCHS > 0);
        assert!(MIN_OBSERVATIONS_FOR_DRIFT > 0);
    }

    // --- SignatureSnapshot ---

    #[test]
    fn snapshot_basic() {
        let s = snapshot(
            "s1",
            normal_regime(),
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
        );
        assert_eq!(s.dimension(), 2);
        assert!(s.is_trustworthy());
    }

    #[test]
    fn snapshot_untrustworthy() {
        let s = snapshot("s2", normal_regime(), &[("cpu", 500_000)], 3);
        assert!(!s.is_trustworthy());
    }

    #[test]
    fn snapshot_content_hash_deterministic() {
        let s1 = snapshot("same", normal_regime(), &[("cpu", 500_000)], 100);
        let s2 = snapshot("same", normal_regime(), &[("cpu", 500_000)], 100);
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn snapshot_content_hash_varies() {
        let s1 = snapshot("a", normal_regime(), &[("cpu", 500_000)], 100);
        let s2 = snapshot("b", normal_regime(), &[("cpu", 600_000)], 100);
        assert_ne!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn snapshot_serde_roundtrip() {
        let s = snapshot(
            "serde",
            normal_regime(),
            &[("cpu", 500_000), ("mem", 300_000)],
            50,
        );
        let json = serde_json::to_string(&s).unwrap();
        let back: SignatureSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- DriftMeasurement ---

    #[test]
    fn drift_identical_snapshots() {
        let s = snapshot(
            "same",
            normal_regime(),
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
        );
        let drift = compute_drift(&s, &s);
        assert_eq!(drift.l1_drift_millionths, 0);
        assert_eq!(drift.linf_drift_millionths, 0);
        assert_eq!(drift.shared_dimensions, 2);
        assert!(!drift.regime_changed);
        assert!(drift.missing_features.is_empty());
        assert!(drift.new_features.is_empty());
    }

    #[test]
    fn drift_simple_l1() {
        let bl = snapshot(
            "bl",
            normal_regime(),
            &[("cpu", 100_000), ("mem", 200_000)],
            100,
        );
        let cur = snapshot(
            "cur",
            normal_regime(),
            &[("cpu", 150_000), ("mem", 250_000)],
            100,
        );
        let drift = compute_drift(&bl, &cur);
        assert_eq!(drift.l1_drift_millionths, 100_000); // 50k + 50k
        assert_eq!(drift.linf_drift_millionths, 50_000);
    }

    #[test]
    fn drift_regime_change_detected() {
        let bl = snapshot("bl", normal_regime(), &[("cpu", 500_000)], 100);
        let cur = snapshot("cur", elevated_regime(), &[("cpu", 500_000)], 100);
        let drift = compute_drift(&bl, &cur);
        assert!(drift.regime_changed);
        assert_eq!(drift.l1_drift_millionths, 0);
    }

    #[test]
    fn drift_missing_and_new_features() {
        let bl = snapshot(
            "bl",
            normal_regime(),
            &[("cpu", 500_000), ("old_feat", 100_000)],
            100,
        );
        let cur = snapshot(
            "cur",
            normal_regime(),
            &[("cpu", 510_000), ("new_feat", 200_000)],
            100,
        );
        let drift = compute_drift(&bl, &cur);
        assert_eq!(drift.shared_dimensions, 1);
        assert!(drift.missing_features.contains("old_feat"));
        assert!(drift.new_features.contains("new_feat"));
    }

    #[test]
    fn drift_serde_roundtrip() {
        let bl = snapshot("bl", normal_regime(), &[("cpu", 100_000)], 100);
        let cur = snapshot("cur", normal_regime(), &[("cpu", 200_000)], 100);
        let drift = compute_drift(&bl, &cur);
        let json = serde_json::to_string(&drift).unwrap();
        let back: DriftMeasurement = serde_json::from_str(&json).unwrap();
        assert_eq!(drift, back);
    }

    // --- TransitionBudgetTracker ---

    #[test]
    fn budget_new() {
        let b = TransitionBudgetTracker::new(10, test_epoch());
        assert!(b.is_within_budget());
        assert_eq!(b.remaining(), 10);
        assert_eq!(b.utilization_millionths(), 0);
    }

    #[test]
    fn budget_record_transition() {
        let mut b = TransitionBudgetTracker::new(3, test_epoch());
        assert!(b.record_transition(normal_regime(), elevated_regime(), 10_000, test_epoch()));
        assert_eq!(b.remaining(), 2);
        assert!(b.record_transition(elevated_regime(), normal_regime(), 5_000, test_epoch()));
        assert!(b.record_transition(normal_regime(), normal_regime(), 1_000, test_epoch()));
        assert!(!b.record_transition(normal_regime(), elevated_regime(), 2_000, test_epoch()));
        assert!(!b.is_within_budget());
    }

    #[test]
    fn budget_utilization() {
        let mut b = TransitionBudgetTracker::new(4, test_epoch());
        assert_eq!(b.utilization_millionths(), 0);
        b.record_transition(normal_regime(), normal_regime(), 0, test_epoch());
        assert_eq!(b.utilization_millionths(), 250_000); // 1/4
        b.record_transition(normal_regime(), normal_regime(), 0, test_epoch());
        assert_eq!(b.utilization_millionths(), 500_000); // 2/4
    }

    #[test]
    fn budget_reset() {
        let mut b = TransitionBudgetTracker::new(2, test_epoch());
        b.record_transition(normal_regime(), normal_regime(), 0, test_epoch());
        b.record_transition(normal_regime(), normal_regime(), 0, test_epoch());
        b.record_transition(normal_regime(), normal_regime(), 0, test_epoch());
        assert!(!b.is_within_budget());
        let new_epoch = SecurityEpoch::from_raw(100);
        b.reset(new_epoch);
        assert!(b.is_within_budget());
        assert_eq!(b.remaining(), 2);
        assert_eq!(b.reset_epoch, new_epoch);
    }

    #[test]
    fn budget_zero_max() {
        let b = TransitionBudgetTracker::new(0, test_epoch());
        assert!(b.is_within_budget()); // 0 consumed <= 0 max
        assert_eq!(b.utilization_millionths(), MILLION); // 0/0 = 100%
    }

    // --- DriftGateConfig ---

    #[test]
    fn config_default_sane() {
        let cfg = default_config();
        assert!(cfg.max_l1_drift_millionths > 0);
        assert!(cfg.max_linf_drift_millionths > 0);
        assert!(cfg.max_linf_drift_millionths <= cfg.max_l1_drift_millionths);
        assert!(cfg.regime_change_triggers_downgrade);
    }

    // --- DowngradeReason ---

    #[test]
    fn downgrade_reason_display_all() {
        let reasons = [
            DowngradeReason::ExcessiveL1Drift,
            DowngradeReason::ExcessiveLinfDrift,
            DowngradeReason::TransitionBudgetExhausted,
            DowngradeReason::RegimeChanged,
            DowngradeReason::StaleBaseline,
            DowngradeReason::InsufficientBaselineObservations,
            DowngradeReason::InsufficientCurrentObservations,
            DowngradeReason::NoSharedDimensions,
        ];
        for r in reasons {
            assert!(!r.to_string().is_empty());
        }
        assert_eq!(reasons.len(), 8);
    }

    #[test]
    fn downgrade_reason_serde() {
        let r = DowngradeReason::ExcessiveL1Drift;
        let json = serde_json::to_string(&r).unwrap();
        let back: DowngradeReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- GateVerdict ---

    #[test]
    fn gate_verdict_display() {
        assert_eq!(GateVerdict::Pass.to_string(), "pass");
        assert_eq!(GateVerdict::Downgrade.to_string(), "downgrade");
        assert_eq!(GateVerdict::Block.to_string(), "block");
        assert_eq!(GateVerdict::Abstain.to_string(), "abstain");
    }

    #[test]
    fn gate_verdict_serde() {
        let v = GateVerdict::Pass;
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // --- Gate evaluation ---

    #[test]
    fn gate_pass_stable() {
        let bl = snapshot(
            "bl",
            normal_regime(),
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
        );
        let cur = snapshot(
            "cur",
            normal_regime(),
            &[("cpu", 510_000), ("mem", 305_000)],
            100,
        );
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let decision = evaluate_gate(
            "claim-1",
            &bl,
            &cur,
            &budget,
            &default_config(),
            test_epoch(),
        );
        assert!(decision.is_pass());
        assert!(decision.downgrade_reasons.is_empty());
        assert!(decision.decision_id.starts_with("dg-pass-"));
    }

    #[test]
    fn gate_downgrade_excessive_drift() {
        let bl = snapshot(
            "bl",
            normal_regime(),
            &[("cpu", 100_000), ("mem", 100_000)],
            100,
        );
        let cur = snapshot(
            "cur",
            normal_regime(),
            &[("cpu", 500_000), ("mem", 500_000)],
            100,
        );
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let decision = evaluate_gate(
            "claim-2",
            &bl,
            &cur,
            &budget,
            &default_config(),
            test_epoch(),
        );
        assert_eq!(decision.verdict, GateVerdict::Downgrade);
        assert!(
            decision
                .downgrade_reasons
                .contains(&DowngradeReason::ExcessiveL1Drift)
        );
    }

    #[test]
    fn gate_downgrade_regime_change() {
        let bl = snapshot(
            "bl",
            normal_regime(),
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
        );
        let cur = snapshot(
            "cur",
            elevated_regime(),
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
        );
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let decision = evaluate_gate(
            "claim-3",
            &bl,
            &cur,
            &budget,
            &default_config(),
            test_epoch(),
        );
        assert_eq!(decision.verdict, GateVerdict::Downgrade);
        assert!(
            decision
                .downgrade_reasons
                .contains(&DowngradeReason::RegimeChanged)
        );
    }

    #[test]
    fn gate_block_multiple_violations() {
        let bl = snapshot(
            "bl",
            normal_regime(),
            &[("cpu", 100_000), ("mem", 100_000)],
            100,
        );
        let cur = snapshot(
            "cur",
            normal_regime(),
            &[("cpu", 800_000), ("mem", 800_000)],
            100,
        );
        let mut budget = TransitionBudgetTracker::new(2, test_epoch());
        budget.record_transition(normal_regime(), elevated_regime(), 100_000, test_epoch());
        budget.record_transition(elevated_regime(), normal_regime(), 100_000, test_epoch());
        budget.record_transition(normal_regime(), normal_regime(), 50_000, test_epoch());
        let decision = evaluate_gate(
            "claim-4",
            &bl,
            &cur,
            &budget,
            &default_config(),
            test_epoch(),
        );
        assert!(decision.is_blocked());
    }

    #[test]
    fn gate_abstain_insufficient_observations() {
        let bl = snapshot("bl", normal_regime(), &[("cpu", 500_000)], 3);
        let cur = snapshot("cur", normal_regime(), &[("cpu", 510_000)], 3);
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let decision = evaluate_gate(
            "claim-5",
            &bl,
            &cur,
            &budget,
            &default_config(),
            test_epoch(),
        );
        assert!(decision.is_abstained());
    }

    #[test]
    fn gate_abstain_no_shared_dims() {
        let bl = snapshot("bl", normal_regime(), &[("only_a", 500_000)], 100);
        let cur = snapshot("cur", normal_regime(), &[("only_b", 510_000)], 100);
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let decision = evaluate_gate(
            "claim-6",
            &bl,
            &cur,
            &budget,
            &default_config(),
            test_epoch(),
        );
        assert!(decision.is_abstained());
    }

    #[test]
    fn gate_downgrade_stale_baseline() {
        let old = SecurityEpoch::from_raw(1);
        let bl = make_snapshot("bl", normal_regime(), &[("cpu", 500_000)], 100, old);
        let cur = snapshot("cur", normal_regime(), &[("cpu", 510_000)], 100);
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let decision = evaluate_gate(
            "claim-7",
            &bl,
            &cur,
            &budget,
            &default_config(),
            test_epoch(),
        );
        assert_eq!(decision.verdict, GateVerdict::Downgrade);
        assert!(
            decision
                .downgrade_reasons
                .contains(&DowngradeReason::StaleBaseline)
        );
    }

    #[test]
    fn gate_decision_serde_roundtrip() {
        let bl = snapshot("bl", normal_regime(), &[("cpu", 500_000)], 100);
        let cur = snapshot("cur", normal_regime(), &[("cpu", 510_000)], 100);
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let decision = evaluate_gate(
            "claim-s",
            &bl,
            &cur,
            &budget,
            &default_config(),
            test_epoch(),
        );
        let json = serde_json::to_string(&decision).unwrap();
        let back: GateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn gate_decision_reason_count() {
        let bl = snapshot("bl", normal_regime(), &[("cpu", 100_000)], 100);
        let cur = snapshot("cur", elevated_regime(), &[("cpu", 500_000)], 100);
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let decision = evaluate_gate(
            "claim-rc",
            &bl,
            &cur,
            &budget,
            &default_config(),
            test_epoch(),
        );
        assert!(decision.reason_count() >= 2); // drift + regime change
    }

    // --- Batch evaluation ---

    #[test]
    fn batch_basic() {
        let bl = snapshot(
            "bl",
            normal_regime(),
            &[("cpu", 500_000), ("mem", 300_000)],
            100,
        );
        let cur = snapshot(
            "cur",
            normal_regime(),
            &[("cpu", 510_000), ("mem", 305_000)],
            100,
        );
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let result = batch_evaluate(
            &["c1", "c2", "c3"],
            &bl,
            &cur,
            &budget,
            &default_config(),
            test_epoch(),
        );
        assert_eq!(result.decisions.len(), 3);
        assert_eq!(result.pass_rate_millionths, MILLION); // all pass
    }

    #[test]
    fn batch_mixed_verdicts() {
        let bl = snapshot("bl", normal_regime(), &[("cpu", 100_000)], 100);
        let cur = snapshot("cur", normal_regime(), &[("cpu", 500_000)], 100);
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let result = batch_evaluate(&["c1"], &bl, &cur, &budget, &default_config(), test_epoch());
        assert_eq!(result.decisions.len(), 1);
        assert!(result.pass_rate_millionths < MILLION); // not all pass
    }

    #[test]
    fn batch_serde() {
        let bl = snapshot("bl", normal_regime(), &[("cpu", 500_000)], 100);
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let result = batch_evaluate(&["c1"], &bl, &bl, &budget, &default_config(), test_epoch());
        let json = serde_json::to_string(&result).unwrap();
        let back: BatchGateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.decisions.len(), back.decisions.len());
    }

    // --- ClaimScopeLedger ---

    #[test]
    fn ledger_new_empty() {
        let ledger = ClaimScopeLedger::new(test_epoch());
        assert_eq!(ledger.active_count(), 0);
        assert_eq!(ledger.deactivated_count(), 0);
    }

    #[test]
    fn ledger_add_and_query() {
        let mut ledger = ClaimScopeLedger::new(test_epoch());
        ledger.add_record(ClaimScopeRecord {
            claim_id: "c1".into(),
            valid_regime: normal_regime(),
            baseline_hash: ContentHash::compute(b"test"),
            max_passing_drift_millionths: 0,
            active: true,
            deactivation_reason: None,
            last_validated_epoch: test_epoch(),
        });
        assert_eq!(ledger.active_count(), 1);
        assert!(ledger.get_record("c1").is_some());
        assert!(ledger.get_record("c2").is_none());
    }

    #[test]
    fn ledger_apply_pass_decision() {
        let mut ledger = ClaimScopeLedger::new(test_epoch());
        ledger.add_record(ClaimScopeRecord {
            claim_id: "c1".into(),
            valid_regime: normal_regime(),
            baseline_hash: ContentHash::compute(b"test"),
            max_passing_drift_millionths: 0,
            active: true,
            deactivation_reason: None,
            last_validated_epoch: test_epoch(),
        });

        let bl = snapshot("bl", normal_regime(), &[("cpu", 500_000)], 100);
        let cur = snapshot("cur", normal_regime(), &[("cpu", 520_000)], 100);
        let budget = TransitionBudgetTracker::new(10, test_epoch());
        let decision = evaluate_gate("c1", &bl, &cur, &budget, &default_config(), test_epoch());
        ledger.apply_decision(&decision);

        let record = ledger.get_record("c1").unwrap();
        assert!(record.active);
        assert!(record.max_passing_drift_millionths > 0);
    }

    #[test]
    fn ledger_apply_block_decision() {
        let mut ledger = ClaimScopeLedger::new(test_epoch());
        ledger.add_record(ClaimScopeRecord {
            claim_id: "c1".into(),
            valid_regime: normal_regime(),
            baseline_hash: ContentHash::compute(b"test"),
            max_passing_drift_millionths: 0,
            active: true,
            deactivation_reason: None,
            last_validated_epoch: test_epoch(),
        });

        let bl = snapshot("bl", normal_regime(), &[("cpu", 100_000)], 100);
        let cur = snapshot("cur", normal_regime(), &[("cpu", 900_000)], 100);
        let mut budget = TransitionBudgetTracker::new(2, test_epoch());
        for _ in 0..3 {
            budget.record_transition(normal_regime(), normal_regime(), 100_000, test_epoch());
        }
        let decision = evaluate_gate("c1", &bl, &cur, &budget, &default_config(), test_epoch());
        ledger.apply_decision(&decision);

        let record = ledger.get_record("c1").unwrap();
        assert!(!record.active);
        assert!(record.deactivation_reason.is_some());
    }

    // --- Evidence corpus ---

    #[test]
    fn evidence_corpus_builds() {
        let (specimens, hash) = run_evidence_corpus(test_epoch());
        assert_eq!(specimens.len(), 7);
        assert!(!hash.to_hex().is_empty());
    }

    #[test]
    fn evidence_corpus_deterministic() {
        let (_, h1) = run_evidence_corpus(test_epoch());
        let (_, h2) = run_evidence_corpus(test_epoch());
        assert_eq!(h1, h2);
    }

    #[test]
    fn evidence_corpus_all_families_present() {
        let (specimens, _) = run_evidence_corpus(test_epoch());
        let families: BTreeSet<DriftGateSpecimenFamily> =
            specimens.iter().map(|s| s.family).collect();
        assert!(families.contains(&DriftGateSpecimenFamily::StableLowDrift));
        assert!(families.contains(&DriftGateSpecimenFamily::ExcessiveDrift));
        assert!(families.contains(&DriftGateSpecimenFamily::RegimeChange));
        assert!(families.contains(&DriftGateSpecimenFamily::BudgetExhaustion));
        assert!(families.contains(&DriftGateSpecimenFamily::InsufficientData));
    }

    #[test]
    fn evidence_corpus_verdicts_match_expectations() {
        let (specimens, _) = run_evidence_corpus(test_epoch());
        for s in &specimens {
            assert_eq!(
                s.decision.verdict, s.expected_verdict,
                "specimen {} expected {:?} got {:?}",
                s.id, s.expected_verdict, s.decision.verdict
            );
        }
    }

    #[test]
    fn evidence_corpus_ids_unique() {
        let (specimens, _) = run_evidence_corpus(test_epoch());
        let ids: BTreeSet<&str> = specimens.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids.len(), specimens.len());
    }

    #[test]
    fn evidence_corpus_specimen_serde() {
        let (specimens, _) = run_evidence_corpus(test_epoch());
        for s in &specimens {
            let json = serde_json::to_string(s).unwrap();
            let back: DriftGateSpecimen = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn specimen_family_display() {
        assert_eq!(
            DriftGateSpecimenFamily::StableLowDrift.to_string(),
            "stable_low_drift"
        );
        assert_eq!(
            DriftGateSpecimenFamily::ExcessiveDrift.to_string(),
            "excessive_drift"
        );
        assert_eq!(
            DriftGateSpecimenFamily::BudgetExhaustion.to_string(),
            "budget_exhaustion"
        );
    }
}
