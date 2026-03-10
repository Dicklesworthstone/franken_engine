#![forbid(unsafe_code)]

//! Acquisition-guided experiment selection oracle.
//!
//! Implements [RGC-706B] (bead bd-1lsy.8.6.2): uses acquisition-function
//! semantics to choose the next board cells, corpus additions, and adversarial
//! probes.  The oracle balances live-shift pressure, coverage debt, persistent
//! holes, semantic dark matter, adversarial opportunities, and the cost of
//! measurement.  Every proposal includes a machine-readable justification
//! explaining why the experiment is worth running and what uncertainty it is
//! expected to reduce.
//!
//! Key design decisions:
//! - Each `ExperimentProposal` carries a vector of weighted `AcquisitionSignal`s
//!   that describe why the experiment site deserves attention.
//! - `score_proposal` reduces that vector to a single cost-adjusted acquisition
//!   value using caller-supplied signal weights.
//! - `select_experiments` greedily fills a budget with the highest-value
//!   proposals and returns an `ExperimentPlan` that is content-hashed for
//!   deterministic audit.
//! - `record_outcome` and `calibrate_oracle` close the loop: actual information
//!   gains are compared to predictions so the oracle can be recalibrated.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the acquisition experiment oracle.
pub const SCHEMA_VERSION: &str = "franken-engine.acquisition-experiment-oracle.v1";

/// Bead identifier for traceability.
pub const BEAD_ID: &str = "bd-1lsy.8.6.2";

/// Component name.
pub const COMPONENT: &str = "acquisition-experiment-oracle";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-706B";

/// One million — the unit for fixed-point millionths arithmetic.
pub const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Compute a deterministic content hash from arbitrary bytes.
fn compute_content_hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

/// Saturating subtraction for unsigned — returns absolute difference.
fn abs_diff(a: u64, b: u64) -> u64 {
    if a >= b {
        a.saturating_sub(b)
    } else {
        b.saturating_sub(a)
    }
}

// ---------------------------------------------------------------------------
// ExperimentKind
// ---------------------------------------------------------------------------

/// The kind of experiment the oracle may propose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExperimentKind {
    /// Probe a specific board cell for new information.
    BoardCellProbe,
    /// Add a new corpus entry to improve coverage.
    CorpusAddition,
    /// Launch an adversarial probe to test defences.
    AdversarialProbe,
    /// Validate that a live-shift signal is genuine.
    ShiftValidation,
    /// Recover lost coverage in a regression zone.
    CoverageRecovery,
    /// Fill a persistent, known hole in the test surface.
    HoleFilling,
    /// Explore semantic dark matter — regions never reached.
    DarkMatterExploration,
}

impl ExperimentKind {
    /// All variants in declaration order.
    pub const ALL: &'static [ExperimentKind] = &[
        ExperimentKind::BoardCellProbe,
        ExperimentKind::CorpusAddition,
        ExperimentKind::AdversarialProbe,
        ExperimentKind::ShiftValidation,
        ExperimentKind::CoverageRecovery,
        ExperimentKind::HoleFilling,
        ExperimentKind::DarkMatterExploration,
    ];

    /// Machine-readable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BoardCellProbe => "board_cell_probe",
            Self::CorpusAddition => "corpus_addition",
            Self::AdversarialProbe => "adversarial_probe",
            Self::ShiftValidation => "shift_validation",
            Self::CoverageRecovery => "coverage_recovery",
            Self::HoleFilling => "hole_filling",
            Self::DarkMatterExploration => "dark_matter_exploration",
        }
    }
}

impl fmt::Display for ExperimentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// AcquisitionSignal
// ---------------------------------------------------------------------------

/// Signals that drive the acquisition function.
///
/// Each signal represents a distinct reason why a particular experiment site
/// is interesting.  Signals are weighted and combined into a single score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AcquisitionSignal {
    /// A live-shift in production behaviour makes this region urgent.
    LiveShiftPressure,
    /// Coverage in this region is below the debt threshold.
    CoverageDebt,
    /// A persistent hole that has survived multiple campaigns.
    PersistentHole,
    /// This region has never been reached — semantic dark matter.
    SemanticDarkMatter,
    /// An adversarial opportunity exists (e.g. fuzzing found a near-miss).
    AdversarialOpportunity,
    /// The existing evidence for this region is stale.
    StalenessAlarm,
    /// The ratchet for this region has not advanced recently.
    RatchetGap,
}

impl AcquisitionSignal {
    /// All variants in declaration order.
    pub const ALL: &'static [AcquisitionSignal] = &[
        AcquisitionSignal::LiveShiftPressure,
        AcquisitionSignal::CoverageDebt,
        AcquisitionSignal::PersistentHole,
        AcquisitionSignal::SemanticDarkMatter,
        AcquisitionSignal::AdversarialOpportunity,
        AcquisitionSignal::StalenessAlarm,
        AcquisitionSignal::RatchetGap,
    ];

    /// Machine-readable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LiveShiftPressure => "live_shift_pressure",
            Self::CoverageDebt => "coverage_debt",
            Self::PersistentHole => "persistent_hole",
            Self::SemanticDarkMatter => "semantic_dark_matter",
            Self::AdversarialOpportunity => "adversarial_opportunity",
            Self::StalenessAlarm => "staleness_alarm",
            Self::RatchetGap => "ratchet_gap",
        }
    }
}

impl fmt::Display for AcquisitionSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ExperimentProposal
// ---------------------------------------------------------------------------

/// A proposed experiment with expected information gain, cost, and
/// justification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperimentProposal {
    /// Unique identifier for this proposal.
    pub proposal_id: String,
    /// What kind of experiment this is.
    pub kind: ExperimentKind,
    /// The target cell (board cell name, corpus key, etc.).
    pub target_cell: String,
    /// Signals that motivate this experiment, each with a strength value
    /// in millionths.
    pub signals: Vec<(AcquisitionSignal, u64)>,
    /// Expected information gain (in millionths).
    pub expected_information_gain_millionths: u64,
    /// Expected uncertainty reduction (in millionths).
    pub expected_uncertainty_reduction_millionths: u64,
    /// Estimated cost to run the experiment (in millionths).
    pub estimated_cost_millionths: u64,
    /// Human-readable justification for why this experiment is worth running.
    pub justification: String,
    /// Content hash of the proposal envelope for integrity.
    pub content_hash: ContentHash,
}

impl ExperimentProposal {
    /// Recompute and set the content hash.
    pub fn seal(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.proposal_id.as_bytes());
        data.extend_from_slice(self.kind.as_str().as_bytes());
        data.extend_from_slice(self.target_cell.as_bytes());
        for (signal, strength) in &self.signals {
            data.extend_from_slice(signal.as_str().as_bytes());
            data.extend_from_slice(&strength.to_le_bytes());
        }
        data.extend_from_slice(&self.expected_information_gain_millionths.to_le_bytes());
        data.extend_from_slice(&self.expected_uncertainty_reduction_millionths.to_le_bytes());
        data.extend_from_slice(&self.estimated_cost_millionths.to_le_bytes());
        data.extend_from_slice(self.justification.as_bytes());
        self.content_hash = compute_content_hash(&data);
    }

    /// Create a new proposal and immediately seal it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal_id: String,
        kind: ExperimentKind,
        target_cell: String,
        signals: Vec<(AcquisitionSignal, u64)>,
        expected_information_gain_millionths: u64,
        expected_uncertainty_reduction_millionths: u64,
        estimated_cost_millionths: u64,
        justification: String,
    ) -> Self {
        let mut p = Self {
            proposal_id,
            kind,
            target_cell,
            signals,
            expected_information_gain_millionths,
            expected_uncertainty_reduction_millionths,
            estimated_cost_millionths,
            justification,
            content_hash: ContentHash::compute(b""),
        };
        p.seal();
        p
    }
}

impl fmt::Display for ExperimentProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Proposal({}, {}, target={}, gain={}, cost={})",
            self.proposal_id,
            self.kind,
            self.target_cell,
            self.expected_information_gain_millionths,
            self.estimated_cost_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// AcquisitionScore
// ---------------------------------------------------------------------------

/// Computed acquisition score for a single proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionScore {
    /// Which proposal this score belongs to.
    pub proposal_id: String,
    /// Raw weighted gain before cost adjustment.
    pub raw_gain_millionths: u64,
    /// Gain after dividing by cost.
    pub cost_adjusted_millionths: u64,
    /// Per-signal weight contributions that were used.
    pub signal_weights: BTreeMap<String, u64>,
    /// The signal that contributed most to the score.
    pub dominant_signal: AcquisitionSignal,
}

impl fmt::Display for AcquisitionScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Score({}, raw={}, adjusted={}, dominant={})",
            self.proposal_id,
            self.raw_gain_millionths,
            self.cost_adjusted_millionths,
            self.dominant_signal,
        )
    }
}

// ---------------------------------------------------------------------------
// ExperimentPlan
// ---------------------------------------------------------------------------

/// A plan consisting of selected experiments with budget and gain tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperimentPlan {
    /// Unique identifier for this plan.
    pub plan_id: String,
    /// Security epoch at plan creation time.
    pub epoch: SecurityEpoch,
    /// The selected proposals in priority order.
    pub proposals: Vec<ExperimentProposal>,
    /// The corresponding scores, same order as `proposals`.
    pub scores: Vec<AcquisitionScore>,
    /// Budget remaining after selecting all proposals.
    pub budget_remaining_millionths: u64,
    /// Sum of expected gains across selected proposals.
    pub total_expected_gain_millionths: u64,
    /// Content hash of the plan envelope for integrity.
    pub content_hash: ContentHash,
}

impl ExperimentPlan {
    /// Recompute and set the content hash.
    pub fn seal(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.plan_id.as_bytes());
        data.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        for proposal in &self.proposals {
            data.extend_from_slice(proposal.content_hash.as_bytes());
        }
        data.extend_from_slice(&self.budget_remaining_millionths.to_le_bytes());
        data.extend_from_slice(&self.total_expected_gain_millionths.to_le_bytes());
        self.content_hash = compute_content_hash(&data);
    }
}

impl fmt::Display for ExperimentPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Plan({}, epoch={}, experiments={}, budget_remaining={}, total_gain={})",
            self.plan_id,
            self.epoch,
            self.proposals.len(),
            self.budget_remaining_millionths,
            self.total_expected_gain_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// ExperimentOutcome
// ---------------------------------------------------------------------------

/// Outcome of a completed experiment, used for calibration feedback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperimentOutcome {
    /// Which proposal this outcome corresponds to.
    pub proposal_id: String,
    /// Actual information gain observed (in millionths).
    pub actual_information_gain_millionths: u64,
    /// Surprise: absolute difference between expected and actual gain.
    pub surprise_millionths: u64,
    /// Regret: information loss from choosing this over the best alternative.
    pub regret_millionths: u64,
    /// Content hash of the outcome envelope for integrity.
    pub content_hash: ContentHash,
}

impl ExperimentOutcome {
    /// Recompute and set the content hash.
    pub fn seal(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.proposal_id.as_bytes());
        data.extend_from_slice(&self.actual_information_gain_millionths.to_le_bytes());
        data.extend_from_slice(&self.surprise_millionths.to_le_bytes());
        data.extend_from_slice(&self.regret_millionths.to_le_bytes());
        self.content_hash = compute_content_hash(&data);
    }
}

impl fmt::Display for ExperimentOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Outcome({}, actual={}, surprise={}, regret={})",
            self.proposal_id,
            self.actual_information_gain_millionths,
            self.surprise_millionths,
            self.regret_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// OracleCalibration
// ---------------------------------------------------------------------------

/// Calibration state of the oracle, summarising prediction accuracy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleCalibration {
    /// Unique identifier for this calibration snapshot.
    pub calibration_id: String,
    /// Total number of predictions evaluated.
    pub predictions_count: u64,
    /// Mean absolute error of predictions (in millionths).
    pub mean_absolute_error_millionths: u64,
    /// Signed bias: positive means over-predicting, negative means
    /// under-predicting (in millionths).
    pub bias_millionths: i64,
    /// Content hash of the calibration envelope for integrity.
    pub content_hash: ContentHash,
}

impl OracleCalibration {
    /// Recompute and set the content hash.
    pub fn seal(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.calibration_id.as_bytes());
        data.extend_from_slice(&self.predictions_count.to_le_bytes());
        data.extend_from_slice(&self.mean_absolute_error_millionths.to_le_bytes());
        data.extend_from_slice(&self.bias_millionths.to_le_bytes());
        self.content_hash = compute_content_hash(&data);
    }
}

impl fmt::Display for OracleCalibration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Calibration({}, n={}, mae={}, bias={})",
            self.calibration_id,
            self.predictions_count,
            self.mean_absolute_error_millionths,
            self.bias_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// AcquisitionError
// ---------------------------------------------------------------------------

/// Errors that may occur during acquisition experiment selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcquisitionError {
    /// No candidate proposals were provided.
    NoCandidates,
    /// The experiment budget is exhausted — no proposal fits.
    BudgetExhausted,
    /// The oracle calibration has drifted beyond acceptable bounds.
    CalibrationDrift,
    /// An invalid or unrecognised signal was encountered.
    InvalidSignal,
    /// An internal error with a descriptive message.
    InternalError(String),
}

impl fmt::Display for AcquisitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCandidates => {
                write!(f, "acquisition error: no candidate proposals provided")
            }
            Self::BudgetExhausted => {
                write!(f, "acquisition error: experiment budget exhausted")
            }
            Self::CalibrationDrift => {
                write!(f, "acquisition error: oracle calibration has drifted")
            }
            Self::InvalidSignal => {
                write!(f, "acquisition error: invalid or unrecognised signal")
            }
            Self::InternalError(msg) => {
                write!(f, "acquisition error: internal: {msg}")
            }
        }
    }
}

impl std::error::Error for AcquisitionError {}

// ---------------------------------------------------------------------------
// Core Functions
// ---------------------------------------------------------------------------

/// Score a single proposal using the provided signal weights.
///
/// The raw gain is computed by summing `signal_strength * weight` for each
/// signal present in the proposal.  The cost-adjusted score divides the
/// raw gain by the estimated cost (both in millionths), producing a
/// value-per-unit-cost metric.
///
/// If a signal key is not present in `weights`, a default weight of
/// `MILLIONTHS` (1.0) is used.
pub fn score_proposal(
    proposal: &ExperimentProposal,
    weights: &BTreeMap<String, u64>,
) -> AcquisitionScore {
    let mut signal_weights_used = BTreeMap::new();
    let mut raw_gain: u64 = 0;
    let mut max_contribution: u64 = 0;
    let mut dominant = AcquisitionSignal::CoverageDebt; // default

    for (signal, strength) in &proposal.signals {
        let key = signal.as_str().to_string();
        let weight = weights.get(&key).copied().unwrap_or(MILLIONTHS);
        // contribution = strength * weight / MILLIONTHS
        let contribution = strength
            .saturating_mul(weight)
            .checked_div(MILLIONTHS)
            .unwrap_or(0);
        raw_gain = raw_gain.saturating_add(contribution);
        signal_weights_used.insert(key, weight);

        if contribution > max_contribution {
            max_contribution = contribution;
            dominant = *signal;
        }
    }

    // Also add the proposal's own expected gain, weighted at 1.0.
    raw_gain = raw_gain.saturating_add(proposal.expected_information_gain_millionths);

    // Cost-adjusted: raw_gain * MILLIONTHS / max(cost, 1)
    let cost = if proposal.estimated_cost_millionths == 0 {
        1
    } else {
        proposal.estimated_cost_millionths
    };
    let cost_adjusted = raw_gain
        .saturating_mul(MILLIONTHS)
        .checked_div(cost)
        .unwrap_or(0);

    AcquisitionScore {
        proposal_id: proposal.proposal_id.clone(),
        raw_gain_millionths: raw_gain,
        cost_adjusted_millionths: cost_adjusted,
        signal_weights: signal_weights_used,
        dominant_signal: dominant,
    }
}

/// Rank proposals by cost-adjusted acquisition score (descending).
///
/// Returns pairs of `(proposal, score)` sorted best-first.
pub fn rank_proposals(
    proposals: Vec<ExperimentProposal>,
    weights: &BTreeMap<String, u64>,
) -> Vec<(ExperimentProposal, AcquisitionScore)> {
    let mut scored: Vec<(ExperimentProposal, AcquisitionScore)> = proposals
        .into_iter()
        .map(|p| {
            let s = score_proposal(&p, weights);
            (p, s)
        })
        .collect();

    // Sort descending by cost-adjusted score, tie-break by proposal_id
    // for determinism.
    scored.sort_by(|a, b| {
        b.1.cost_adjusted_millionths
            .cmp(&a.1.cost_adjusted_millionths)
            .then_with(|| a.0.proposal_id.cmp(&b.0.proposal_id))
    });

    scored
}

/// Greedily select experiments within a budget.
///
/// Proposals are ranked by cost-adjusted gain, then selected greedily
/// until the budget is exhausted.  Returns an `ExperimentPlan` or an
/// error if no proposals are available or the budget is too small for
/// any candidate.
pub fn select_experiments(
    proposals: Vec<ExperimentProposal>,
    budget_millionths: u64,
    weights: &BTreeMap<String, u64>,
) -> Result<ExperimentPlan, AcquisitionError> {
    if proposals.is_empty() {
        return Err(AcquisitionError::NoCandidates);
    }

    let ranked = rank_proposals(proposals, weights);

    let mut selected_proposals: Vec<ExperimentProposal> = Vec::new();
    let mut selected_scores: Vec<AcquisitionScore> = Vec::new();
    let mut remaining = budget_millionths;
    let mut total_gain: u64 = 0;

    for (proposal, score) in ranked {
        if proposal.estimated_cost_millionths <= remaining {
            remaining = remaining.saturating_sub(proposal.estimated_cost_millionths);
            total_gain = total_gain.saturating_add(proposal.expected_information_gain_millionths);
            selected_proposals.push(proposal);
            selected_scores.push(score);
        }
    }

    if selected_proposals.is_empty() {
        return Err(AcquisitionError::BudgetExhausted);
    }

    let gain_hex = hex_encode(&total_gain.to_le_bytes());
    let plan_id = format!("plan-{}-{}", BEAD_ID, &gain_hex[..8]);

    let mut plan = ExperimentPlan {
        plan_id,
        epoch: SecurityEpoch::GENESIS,
        proposals: selected_proposals,
        scores: selected_scores,
        budget_remaining_millionths: remaining,
        total_expected_gain_millionths: total_gain,
        content_hash: ContentHash::compute(b""),
    };
    plan.seal();

    Ok(plan)
}

/// Record the outcome of a completed experiment.
///
/// Compares the actual information gain against the prediction in the
/// proposal and computes surprise (absolute error) and regret.
pub fn record_outcome(proposal: &ExperimentProposal, actual_gain: u64) -> ExperimentOutcome {
    let surprise = abs_diff(proposal.expected_information_gain_millionths, actual_gain);
    let regret = compute_regret(proposal.expected_information_gain_millionths, actual_gain);

    let mut outcome = ExperimentOutcome {
        proposal_id: proposal.proposal_id.clone(),
        actual_information_gain_millionths: actual_gain,
        surprise_millionths: surprise,
        regret_millionths: regret,
        content_hash: ContentHash::compute(b""),
    };
    outcome.seal();
    outcome
}

/// Compute regret: information lost by choosing this experiment.
///
/// Regret is defined as `max(0, expected - actual)` — there is no
/// negative regret.  If the experiment performed better than expected,
/// regret is zero.
pub fn compute_regret(expected: u64, actual: u64) -> u64 {
    expected.saturating_sub(actual)
}

/// Calibrate the oracle by comparing outcomes to their original proposals.
///
/// The calibration computes the mean absolute error (MAE) and bias across
/// all outcome-proposal pairs.  Proposals and outcomes are matched by
/// `proposal_id`.
///
/// Returns an `OracleCalibration` describing the accuracy of the oracle.
pub fn calibrate_oracle(
    outcomes: &[ExperimentOutcome],
    proposals: &[ExperimentProposal],
) -> OracleCalibration {
    // Build a lookup from proposal_id -> expected gain.
    let expected_map: BTreeMap<&str, u64> = proposals
        .iter()
        .map(|p| {
            (
                p.proposal_id.as_str(),
                p.expected_information_gain_millionths,
            )
        })
        .collect();

    let mut total_abs_error: u64 = 0;
    let mut total_signed_error: i64 = 0;
    let mut matched_count: u64 = 0;

    for outcome in outcomes {
        if let Some(&expected) = expected_map.get(outcome.proposal_id.as_str()) {
            let abs_err = abs_diff(expected, outcome.actual_information_gain_millionths);
            total_abs_error = total_abs_error.saturating_add(abs_err);

            // Bias: positive = over-prediction, negative = under-prediction.
            let signed_err =
                (expected as i64).saturating_sub(outcome.actual_information_gain_millionths as i64);
            total_signed_error = total_signed_error.saturating_add(signed_err);
            matched_count += 1;
        }
    }

    let mae = if matched_count > 0 {
        total_abs_error.checked_div(matched_count).unwrap_or(0)
    } else {
        0
    };

    let bias = if matched_count > 0 {
        total_signed_error
            .checked_div(matched_count as i64)
            .unwrap_or(0)
    } else {
        0
    };

    let mut cal = OracleCalibration {
        calibration_id: format!("cal-{}-n{}", BEAD_ID, matched_count),
        predictions_count: matched_count,
        mean_absolute_error_millionths: mae,
        bias_millionths: bias,
        content_hash: ContentHash::compute(b""),
    };
    cal.seal();
    cal
}

/// Produce a canonical reference experiment plan (manifest).
///
/// This creates a representative plan with one proposal per experiment
/// kind, demonstrating the oracle's coverage of all experiment families.
/// Useful for testing and schema validation.
pub fn franken_engine_acquisition_manifest() -> ExperimentPlan {
    let default_weights: BTreeMap<String, u64> = BTreeMap::new();

    let kinds_and_signals: Vec<(ExperimentKind, AcquisitionSignal, &str)> = vec![
        (
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::LiveShiftPressure,
            "Live shift detected on cell A1; probing to confirm regression.",
        ),
        (
            ExperimentKind::CorpusAddition,
            AcquisitionSignal::CoverageDebt,
            "Coverage debt exceeds threshold in module-loading path.",
        ),
        (
            ExperimentKind::AdversarialProbe,
            AcquisitionSignal::AdversarialOpportunity,
            "Fuzzer near-miss suggests untested boundary condition.",
        ),
        (
            ExperimentKind::ShiftValidation,
            AcquisitionSignal::StalenessAlarm,
            "Staleness alarm fired for shift signal; validate freshness.",
        ),
        (
            ExperimentKind::CoverageRecovery,
            AcquisitionSignal::PersistentHole,
            "Persistent hole in error-recovery path since campaign 3.",
        ),
        (
            ExperimentKind::HoleFilling,
            AcquisitionSignal::RatchetGap,
            "Ratchet gap: coverage ratchet has not advanced for 5 iterations.",
        ),
        (
            ExperimentKind::DarkMatterExploration,
            AcquisitionSignal::SemanticDarkMatter,
            "No evidence exists for the async-generator teardown path.",
        ),
    ];

    let mut proposals = Vec::new();
    for (i, (kind, signal, justification)) in kinds_and_signals.into_iter().enumerate() {
        let proposal = ExperimentProposal::new(
            format!("manifest-{}-{}", BEAD_ID, i),
            kind,
            format!("cell-{}", kind.as_str()),
            vec![(signal, 800_000)],
            500_000, // expected gain: 0.5
            300_000, // uncertainty reduction: 0.3
            100_000, // cost: 0.1
            justification.to_string(),
        );
        proposals.push(proposal);
    }

    let budget = 7 * 100_000; // enough for all 7
    select_experiments(proposals, budget, &default_weights)
        .expect("manifest plan should always succeed")
}

// ---------------------------------------------------------------------------
// Signal strength helpers
// ---------------------------------------------------------------------------

/// Combine multiple signal strengths into a composite strength value.
///
/// Uses a capped sum with diminishing returns: each additional signal
/// beyond the first is halved.
pub fn combine_signal_strengths(strengths: &[u64]) -> u64 {
    if strengths.is_empty() {
        return 0;
    }

    let mut sorted: Vec<u64> = strengths.to_vec();
    sorted.sort_by(|a, b| b.cmp(a)); // descending

    let mut total = sorted[0];
    let mut divisor: u64 = 2;

    for &s in &sorted[1..] {
        total = total.saturating_add(s.checked_div(divisor).unwrap_or(0));
        divisor = divisor.saturating_mul(2);
    }

    total
}

/// Compute the information density of a proposal: gain per unit cost.
///
/// Returns the ratio `expected_gain * MILLIONTHS / cost` (in millionths).
/// A higher density means more information per unit of effort.
pub fn information_density(proposal: &ExperimentProposal) -> u64 {
    let cost = if proposal.estimated_cost_millionths == 0 {
        1
    } else {
        proposal.estimated_cost_millionths
    };
    proposal
        .expected_information_gain_millionths
        .saturating_mul(MILLIONTHS)
        .checked_div(cost)
        .unwrap_or(0)
}

/// Check whether a proposal's expected gain justifies its cost.
///
/// A proposal is justified if `expected_gain >= cost * threshold`,
/// where `threshold` is a minimum gain-to-cost ratio in millionths.
pub fn is_justified(proposal: &ExperimentProposal, threshold_millionths: u64) -> bool {
    let min_gain = proposal
        .estimated_cost_millionths
        .saturating_mul(threshold_millionths)
        .checked_div(MILLIONTHS)
        .unwrap_or(0);
    proposal.expected_information_gain_millionths >= min_gain
}

/// Compute the diversity bonus for a set of proposals.
///
/// The bonus rewards plans that cover many different experiment kinds.
/// Returns a value in millionths where `MILLIONTHS` = all 7 kinds covered.
pub fn diversity_bonus(proposals: &[ExperimentProposal]) -> u64 {
    let mut seen = std::collections::BTreeSet::new();
    for p in proposals {
        seen.insert(p.kind);
    }
    let total_kinds = ExperimentKind::ALL.len() as u64;
    if total_kinds == 0 {
        return 0;
    }
    (seen.len() as u64)
        .saturating_mul(MILLIONTHS)
        .checked_div(total_kinds)
        .unwrap_or(0)
}

/// Compute a staleness penalty for a proposal whose evidence age exceeds
/// a threshold.
///
/// `evidence_age_ticks` is the age in ticks and `max_fresh_ticks` is the
/// threshold below which no penalty applies.  The penalty grows linearly
/// up to `MILLIONTHS`.
pub fn staleness_penalty(evidence_age_ticks: u64, max_fresh_ticks: u64) -> u64 {
    if evidence_age_ticks <= max_fresh_ticks {
        return 0;
    }
    let over = evidence_age_ticks.saturating_sub(max_fresh_ticks);
    // Penalty grows linearly; cap at MILLIONTHS.
    over.saturating_mul(MILLIONTHS)
        .checked_div(max_fresh_ticks.max(1))
        .unwrap_or(MILLIONTHS)
        .min(MILLIONTHS)
}

/// Partition proposals by experiment kind.
///
/// Returns a `BTreeMap` grouping proposals by their `ExperimentKind`.
pub fn partition_by_kind(
    proposals: &[ExperimentProposal],
) -> BTreeMap<ExperimentKind, Vec<&ExperimentProposal>> {
    let mut map: BTreeMap<ExperimentKind, Vec<&ExperimentProposal>> = BTreeMap::new();
    for p in proposals {
        map.entry(p.kind).or_default().push(p);
    }
    map
}

/// Find the dominant signal across a set of proposals.
///
/// Sums signal strengths by signal type and returns the signal with the
/// highest total.  Returns `None` if no proposals have signals.
pub fn find_dominant_signal(proposals: &[ExperimentProposal]) -> Option<AcquisitionSignal> {
    let mut totals: BTreeMap<AcquisitionSignal, u64> = BTreeMap::new();
    for p in proposals {
        for (signal, strength) in &p.signals {
            *totals.entry(*signal).or_insert(0) += strength;
        }
    }
    totals.into_iter().max_by_key(|&(_, v)| v).map(|(k, _)| k)
}

/// Create a budget allocation across experiment kinds.
///
/// Distributes `total_budget` proportionally to the number of proposals
/// of each kind.  Returns per-kind budgets.
pub fn allocate_budget_by_kind(
    proposals: &[ExperimentProposal],
    total_budget: u64,
) -> BTreeMap<ExperimentKind, u64> {
    let partitioned = partition_by_kind(proposals);
    let total_count = proposals.len() as u64;
    if total_count == 0 {
        return BTreeMap::new();
    }

    let mut allocation = BTreeMap::new();
    let mut allocated: u64 = 0;
    let kinds: Vec<ExperimentKind> = partitioned.keys().copied().collect();

    for (i, kind) in kinds.iter().enumerate() {
        let count = partitioned[kind].len() as u64;
        let share = total_budget
            .saturating_mul(count)
            .checked_div(total_count)
            .unwrap_or(0);

        // Last kind gets the remainder to avoid rounding loss.
        if i == kinds.len() - 1 {
            allocation.insert(*kind, total_budget.saturating_sub(allocated));
        } else {
            allocation.insert(*kind, share);
            allocated = allocated.saturating_add(share);
        }
    }

    allocation
}

/// Compute the exploration-exploitation balance ratio.
///
/// Exploration proposals are `DarkMatterExploration`, `HoleFilling`, and
/// `CoverageRecovery`.  Exploitation proposals are the rest.  Returns the
/// ratio of exploration cost to total cost in millionths.
pub fn exploration_ratio(proposals: &[ExperimentProposal]) -> u64 {
    let mut exploration_cost: u64 = 0;
    let mut total_cost: u64 = 0;

    for p in proposals {
        let cost = p.estimated_cost_millionths;
        total_cost = total_cost.saturating_add(cost);
        match p.kind {
            ExperimentKind::DarkMatterExploration
            | ExperimentKind::HoleFilling
            | ExperimentKind::CoverageRecovery => {
                exploration_cost = exploration_cost.saturating_add(cost);
            }
            _ => {}
        }
    }

    if total_cost == 0 {
        return 0;
    }

    exploration_cost
        .saturating_mul(MILLIONTHS)
        .checked_div(total_cost)
        .unwrap_or(0)
}

/// Validate that a plan is internally consistent.
///
/// Checks:
/// - All scores reference proposals that exist in the plan.
/// - Budget remaining + sum of costs = original budget (reconstructed).
/// - Total expected gain matches sum of proposal gains.
///
/// Returns a list of validation errors (empty = valid).
pub fn validate_plan(plan: &ExperimentPlan) -> Vec<String> {
    let mut errors = Vec::new();

    // Check score-proposal alignment.
    if plan.proposals.len() != plan.scores.len() {
        errors.push(format!(
            "proposal count ({}) != score count ({})",
            plan.proposals.len(),
            plan.scores.len()
        ));
    }

    for (i, score) in plan.scores.iter().enumerate() {
        if let Some(proposal) = plan.proposals.get(i)
            && score.proposal_id != proposal.proposal_id
        {
            errors.push(format!(
                "score[{}] proposal_id mismatch: {} vs {}",
                i, score.proposal_id, proposal.proposal_id
            ));
        }
    }

    // Check total gain.
    let sum_gain: u64 = plan
        .proposals
        .iter()
        .map(|p| p.expected_information_gain_millionths)
        .fold(0u64, |acc, g| acc.saturating_add(g));

    if sum_gain != plan.total_expected_gain_millionths {
        errors.push(format!(
            "total_expected_gain mismatch: sum={} vs declared={}",
            sum_gain, plan.total_expected_gain_millionths
        ));
    }

    errors
}

/// Summarise a plan as a human-readable report string.
pub fn summarise_plan(plan: &ExperimentPlan) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "Experiment Plan: {} (epoch {})",
        plan.plan_id, plan.epoch
    ));
    lines.push(format!(
        "  Budget remaining: {} / total gain: {}",
        plan.budget_remaining_millionths, plan.total_expected_gain_millionths
    ));
    lines.push(format!("  Experiments ({})", plan.proposals.len()));

    for (i, proposal) in plan.proposals.iter().enumerate() {
        let score = plan.scores.get(i);
        lines.push(format!(
            "    [{}] {} on '{}' — gain={}, cost={}, adjusted={}",
            i,
            proposal.kind,
            proposal.target_cell,
            proposal.expected_information_gain_millionths,
            proposal.estimated_cost_millionths,
            score.map(|s| s.cost_adjusted_millionths).unwrap_or(0),
        ));
        if !proposal.justification.is_empty() {
            lines.push(format!("        Justification: {}", proposal.justification));
        }
    }

    lines.push(format!("  Content hash: {}", plan.content_hash));
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_proposal(
        id: &str,
        kind: ExperimentKind,
        signals: Vec<(AcquisitionSignal, u64)>,
        gain: u64,
        uncertainty: u64,
        cost: u64,
    ) -> ExperimentProposal {
        ExperimentProposal::new(
            id.to_string(),
            kind,
            format!("cell-{id}"),
            signals,
            gain,
            uncertainty,
            cost,
            format!("justification for {id}"),
        )
    }

    fn default_weights() -> BTreeMap<String, u64> {
        let mut w = BTreeMap::new();
        for signal in AcquisitionSignal::ALL {
            w.insert(signal.as_str().to_string(), MILLIONTHS);
        }
        w
    }

    // -----------------------------------------------------------------------
    // ExperimentKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn experiment_kind_variant_count() {
        assert_eq!(ExperimentKind::ALL.len(), 7);
    }

    #[test]
    fn experiment_kind_as_str_round_trip() {
        for &kind in ExperimentKind::ALL {
            let s = kind.as_str();
            assert!(!s.is_empty());
            assert_eq!(kind.to_string(), s);
        }
    }

    #[test]
    fn experiment_kind_serde_round_trip() {
        for &kind in ExperimentKind::ALL {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ExperimentKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn experiment_kind_ordering_is_stable() {
        assert!(ExperimentKind::BoardCellProbe < ExperimentKind::CorpusAddition);
        assert!(ExperimentKind::CorpusAddition < ExperimentKind::AdversarialProbe);
        assert!(ExperimentKind::HoleFilling < ExperimentKind::DarkMatterExploration);
    }

    // -----------------------------------------------------------------------
    // AcquisitionSignal tests
    // -----------------------------------------------------------------------

    #[test]
    fn acquisition_signal_variant_count() {
        assert_eq!(AcquisitionSignal::ALL.len(), 7);
    }

    #[test]
    fn acquisition_signal_as_str_round_trip() {
        for &signal in AcquisitionSignal::ALL {
            let s = signal.as_str();
            assert!(!s.is_empty());
            assert_eq!(signal.to_string(), s);
        }
    }

    #[test]
    fn acquisition_signal_serde_round_trip() {
        for &signal in AcquisitionSignal::ALL {
            let json = serde_json::to_string(&signal).unwrap();
            let back: AcquisitionSignal = serde_json::from_str(&json).unwrap();
            assert_eq!(back, signal);
        }
    }

    #[test]
    fn acquisition_signal_ordering_is_stable() {
        assert!(AcquisitionSignal::LiveShiftPressure < AcquisitionSignal::CoverageDebt);
        assert!(AcquisitionSignal::StalenessAlarm < AcquisitionSignal::RatchetGap);
    }

    // -----------------------------------------------------------------------
    // ExperimentProposal tests
    // -----------------------------------------------------------------------

    #[test]
    fn proposal_new_sets_content_hash() {
        let p = make_proposal(
            "p1",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 500_000)],
            400_000,
            200_000,
            100_000,
        );
        assert_ne!(p.content_hash, ContentHash::compute(b""));
    }

    #[test]
    fn proposal_seal_is_deterministic() {
        let p1 = make_proposal(
            "p1",
            ExperimentKind::CorpusAddition,
            vec![(AcquisitionSignal::CoverageDebt, 800_000)],
            600_000,
            300_000,
            200_000,
        );
        let p2 = make_proposal(
            "p1",
            ExperimentKind::CorpusAddition,
            vec![(AcquisitionSignal::CoverageDebt, 800_000)],
            600_000,
            300_000,
            200_000,
        );
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn proposal_different_ids_produce_different_hashes() {
        let p1 = make_proposal(
            "p1",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 500_000)],
            400_000,
            200_000,
            100_000,
        );
        let p2 = make_proposal(
            "p2",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 500_000)],
            400_000,
            200_000,
            100_000,
        );
        assert_ne!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn proposal_serde_round_trip() {
        let p = make_proposal(
            "serde-test",
            ExperimentKind::AdversarialProbe,
            vec![
                (AcquisitionSignal::AdversarialOpportunity, 700_000),
                (AcquisitionSignal::PersistentHole, 300_000),
            ],
            500_000,
            250_000,
            150_000,
        );
        let json = serde_json::to_string(&p).unwrap();
        let back: ExperimentProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn proposal_display() {
        let p = make_proposal(
            "disp-1",
            ExperimentKind::HoleFilling,
            vec![(AcquisitionSignal::PersistentHole, 600_000)],
            450_000,
            200_000,
            80_000,
        );
        let s = p.to_string();
        assert!(s.contains("disp-1"));
        assert!(s.contains("hole_filling"));
        assert!(s.contains("450000"));
    }

    // -----------------------------------------------------------------------
    // score_proposal tests
    // -----------------------------------------------------------------------

    #[test]
    fn score_proposal_basic() {
        let p = make_proposal(
            "score-1",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, MILLIONTHS)],
            500_000,
            300_000,
            200_000,
        );
        let w = default_weights();
        let score = score_proposal(&p, &w);
        assert_eq!(score.proposal_id, "score-1");
        // Raw gain = signal_contribution(1.0 * 1.0) + expected_gain(0.5)
        // = 1_000_000 + 500_000 = 1_500_000
        assert_eq!(score.raw_gain_millionths, 1_500_000);
        assert!(score.cost_adjusted_millionths > 0);
        assert_eq!(score.dominant_signal, AcquisitionSignal::LiveShiftPressure);
    }

    #[test]
    fn score_proposal_multiple_signals() {
        let p = make_proposal(
            "multi-sig",
            ExperimentKind::CoverageRecovery,
            vec![
                (AcquisitionSignal::CoverageDebt, 600_000),
                (AcquisitionSignal::PersistentHole, 400_000),
            ],
            300_000,
            200_000,
            100_000,
        );
        let w = default_weights();
        let score = score_proposal(&p, &w);
        // contribution(CoverageDebt) = 600_000 * 1_000_000 / 1_000_000 = 600_000
        // contribution(PersistentHole) = 400_000 * 1_000_000 / 1_000_000 = 400_000
        // raw = 600_000 + 400_000 + 300_000 = 1_300_000
        assert_eq!(score.raw_gain_millionths, 1_300_000);
        assert_eq!(score.dominant_signal, AcquisitionSignal::CoverageDebt);
    }

    #[test]
    fn score_proposal_custom_weights() {
        let p = make_proposal(
            "custom-w",
            ExperimentKind::AdversarialProbe,
            vec![
                (AcquisitionSignal::AdversarialOpportunity, 500_000),
                (AcquisitionSignal::LiveShiftPressure, 500_000),
            ],
            200_000,
            100_000,
            100_000,
        );
        let mut w = BTreeMap::new();
        // Adversarial weight 2.0, shift weight 0.5
        w.insert("adversarial_opportunity".to_string(), 2_000_000);
        w.insert("live_shift_pressure".to_string(), 500_000);

        let score = score_proposal(&p, &w);
        // adversarial: 500_000 * 2_000_000 / 1_000_000 = 1_000_000
        // shift: 500_000 * 500_000 / 1_000_000 = 250_000
        // raw = 1_000_000 + 250_000 + 200_000 = 1_450_000
        assert_eq!(score.raw_gain_millionths, 1_450_000);
        assert_eq!(
            score.dominant_signal,
            AcquisitionSignal::AdversarialOpportunity
        );
    }

    #[test]
    fn score_proposal_zero_cost() {
        let p = make_proposal(
            "zero-cost",
            ExperimentKind::ShiftValidation,
            vec![(AcquisitionSignal::StalenessAlarm, MILLIONTHS)],
            MILLIONTHS,
            500_000,
            0, // zero cost
        );
        let w = default_weights();
        let score = score_proposal(&p, &w);
        // With zero cost, divisor is 1, so adjusted = raw * MILLIONTHS
        assert!(score.cost_adjusted_millionths > score.raw_gain_millionths);
    }

    #[test]
    fn score_proposal_no_signals() {
        let p = make_proposal(
            "no-sig",
            ExperimentKind::BoardCellProbe,
            vec![],
            500_000,
            200_000,
            100_000,
        );
        let w = default_weights();
        let score = score_proposal(&p, &w);
        // Raw gain = only the expected gain since no signals
        assert_eq!(score.raw_gain_millionths, 500_000);
    }

    #[test]
    fn score_proposal_missing_weight_uses_default() {
        let p = make_proposal(
            "default-w",
            ExperimentKind::DarkMatterExploration,
            vec![(AcquisitionSignal::SemanticDarkMatter, 800_000)],
            400_000,
            200_000,
            100_000,
        );
        // Empty weights — all signals should get default weight of 1.0
        let w = BTreeMap::new();
        let score = score_proposal(&p, &w);
        // contribution = 800_000 * 1_000_000 / 1_000_000 = 800_000
        // raw = 800_000 + 400_000 = 1_200_000
        assert_eq!(score.raw_gain_millionths, 1_200_000);
    }

    // -----------------------------------------------------------------------
    // rank_proposals tests
    // -----------------------------------------------------------------------

    #[test]
    fn rank_proposals_descending_by_adjusted_score() {
        let p1 = make_proposal(
            "rank-low",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 100_000)],
            100_000,
            50_000,
            500_000, // expensive
        );
        let p2 = make_proposal(
            "rank-high",
            ExperimentKind::CorpusAddition,
            vec![(AcquisitionSignal::CoverageDebt, 900_000)],
            800_000,
            400_000,
            50_000, // cheap
        );

        let w = default_weights();
        let ranked = rank_proposals(vec![p1, p2], &w);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].0.proposal_id, "rank-high");
        assert_eq!(ranked[1].0.proposal_id, "rank-low");
    }

    #[test]
    fn rank_proposals_tie_break_by_id() {
        // Same kind, signals, gain, cost — differ only by id.
        let p1 = make_proposal(
            "aaa",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 500_000)],
            500_000,
            250_000,
            100_000,
        );
        let p2 = make_proposal(
            "bbb",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 500_000)],
            500_000,
            250_000,
            100_000,
        );

        let w = default_weights();
        let ranked = rank_proposals(vec![p2, p1], &w);
        // "aaa" < "bbb" alphabetically, so "aaa" comes first on tie.
        assert_eq!(ranked[0].0.proposal_id, "aaa");
        assert_eq!(ranked[1].0.proposal_id, "bbb");
    }

    #[test]
    fn rank_proposals_empty() {
        let w = default_weights();
        let ranked = rank_proposals(vec![], &w);
        assert!(ranked.is_empty());
    }

    // -----------------------------------------------------------------------
    // select_experiments tests
    // -----------------------------------------------------------------------

    #[test]
    fn select_experiments_within_budget() {
        let p1 = make_proposal(
            "sel-1",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 800_000)],
            600_000,
            300_000,
            200_000,
        );
        let p2 = make_proposal(
            "sel-2",
            ExperimentKind::CorpusAddition,
            vec![(AcquisitionSignal::CoverageDebt, 700_000)],
            500_000,
            250_000,
            300_000,
        );

        let w = default_weights();
        let plan = select_experiments(vec![p1, p2], 500_000, &w).unwrap();
        assert_eq!(plan.proposals.len(), 2);
        assert_eq!(plan.total_expected_gain_millionths, 1_100_000);
        assert_eq!(plan.budget_remaining_millionths, 0);
    }

    #[test]
    fn select_experiments_budget_too_small() {
        let p1 = make_proposal(
            "expensive",
            ExperimentKind::AdversarialProbe,
            vec![(AcquisitionSignal::AdversarialOpportunity, 900_000)],
            800_000,
            400_000,
            MILLIONTHS, // cost = 1.0
        );

        let w = default_weights();
        let result = select_experiments(vec![p1], 500_000, &w);
        assert_eq!(result.unwrap_err(), AcquisitionError::BudgetExhausted);
    }

    #[test]
    fn select_experiments_no_candidates() {
        let w = default_weights();
        let result = select_experiments(vec![], MILLIONTHS, &w);
        assert_eq!(result.unwrap_err(), AcquisitionError::NoCandidates);
    }

    #[test]
    fn select_experiments_partial_budget() {
        let p1 = make_proposal(
            "cheap",
            ExperimentKind::ShiftValidation,
            vec![(AcquisitionSignal::StalenessAlarm, 600_000)],
            400_000,
            200_000,
            100_000,
        );
        let p2 = make_proposal(
            "expensive",
            ExperimentKind::DarkMatterExploration,
            vec![(AcquisitionSignal::SemanticDarkMatter, 500_000)],
            300_000,
            150_000,
            900_000,
        );

        let w = default_weights();
        // Budget only fits the cheap one.
        let plan = select_experiments(vec![p1, p2], 200_000, &w).unwrap();
        assert_eq!(plan.proposals.len(), 1);
        assert_eq!(plan.proposals[0].proposal_id, "cheap");
        assert_eq!(plan.budget_remaining_millionths, 100_000);
    }

    #[test]
    fn select_experiments_plan_has_valid_hash() {
        let p1 = make_proposal(
            "hash-check",
            ExperimentKind::HoleFilling,
            vec![(AcquisitionSignal::RatchetGap, 700_000)],
            500_000,
            250_000,
            100_000,
        );
        let w = default_weights();
        let plan = select_experiments(vec![p1], MILLIONTHS, &w).unwrap();
        assert_ne!(plan.content_hash, ContentHash::compute(b""));
    }

    #[test]
    fn select_experiments_plan_is_valid() {
        let p1 = make_proposal(
            "valid-1",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 500_000)],
            300_000,
            150_000,
            100_000,
        );
        let p2 = make_proposal(
            "valid-2",
            ExperimentKind::CorpusAddition,
            vec![(AcquisitionSignal::CoverageDebt, 600_000)],
            400_000,
            200_000,
            150_000,
        );
        let w = default_weights();
        let plan = select_experiments(vec![p1, p2], MILLIONTHS, &w).unwrap();
        let errors = validate_plan(&plan);
        assert!(errors.is_empty(), "validation errors: {errors:?}");
    }

    // -----------------------------------------------------------------------
    // record_outcome tests
    // -----------------------------------------------------------------------

    #[test]
    fn record_outcome_exact_match() {
        let p = make_proposal(
            "exact",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 500_000)],
            500_000,
            250_000,
            100_000,
        );
        let outcome = record_outcome(&p, 500_000);
        assert_eq!(outcome.proposal_id, "exact");
        assert_eq!(outcome.actual_information_gain_millionths, 500_000);
        assert_eq!(outcome.surprise_millionths, 0);
        assert_eq!(outcome.regret_millionths, 0);
    }

    #[test]
    fn record_outcome_over_performance() {
        let p = make_proposal(
            "over",
            ExperimentKind::CorpusAddition,
            vec![(AcquisitionSignal::CoverageDebt, 700_000)],
            400_000,
            200_000,
            100_000,
        );
        let outcome = record_outcome(&p, 600_000);
        assert_eq!(outcome.surprise_millionths, 200_000);
        assert_eq!(outcome.regret_millionths, 0); // no regret when better
    }

    #[test]
    fn record_outcome_under_performance() {
        let p = make_proposal(
            "under",
            ExperimentKind::AdversarialProbe,
            vec![(AcquisitionSignal::AdversarialOpportunity, 800_000)],
            600_000,
            300_000,
            200_000,
        );
        let outcome = record_outcome(&p, 200_000);
        assert_eq!(outcome.surprise_millionths, 400_000);
        assert_eq!(outcome.regret_millionths, 400_000);
    }

    #[test]
    fn record_outcome_has_hash() {
        let p = make_proposal(
            "hash-out",
            ExperimentKind::ShiftValidation,
            vec![(AcquisitionSignal::StalenessAlarm, 500_000)],
            400_000,
            200_000,
            100_000,
        );
        let outcome = record_outcome(&p, 350_000);
        assert_ne!(outcome.content_hash, ContentHash::compute(b""));
    }

    // -----------------------------------------------------------------------
    // compute_regret tests
    // -----------------------------------------------------------------------

    #[test]
    fn compute_regret_no_regret() {
        assert_eq!(compute_regret(500_000, 600_000), 0);
    }

    #[test]
    fn compute_regret_with_loss() {
        assert_eq!(compute_regret(800_000, 300_000), 500_000);
    }

    #[test]
    fn compute_regret_exact() {
        assert_eq!(compute_regret(MILLIONTHS, MILLIONTHS), 0);
    }

    #[test]
    fn compute_regret_zero_expected() {
        assert_eq!(compute_regret(0, 500_000), 0);
    }

    // -----------------------------------------------------------------------
    // calibrate_oracle tests
    // -----------------------------------------------------------------------

    #[test]
    fn calibrate_oracle_perfect_predictions() {
        let p1 = make_proposal(
            "cal-1",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 500_000)],
            500_000,
            250_000,
            100_000,
        );
        let o1 = record_outcome(&p1, 500_000);

        let cal = calibrate_oracle(&[o1], &[p1]);
        assert_eq!(cal.predictions_count, 1);
        assert_eq!(cal.mean_absolute_error_millionths, 0);
        assert_eq!(cal.bias_millionths, 0);
    }

    #[test]
    fn calibrate_oracle_over_prediction_bias() {
        let p1 = make_proposal(
            "bias-1",
            ExperimentKind::CorpusAddition,
            vec![(AcquisitionSignal::CoverageDebt, 700_000)],
            800_000,
            400_000,
            100_000,
        );
        let o1 = record_outcome(&p1, 400_000); // under-delivered

        let cal = calibrate_oracle(&[o1], &[p1]);
        assert_eq!(cal.predictions_count, 1);
        assert_eq!(cal.mean_absolute_error_millionths, 400_000);
        assert!(cal.bias_millionths > 0); // positive = over-prediction
    }

    #[test]
    fn calibrate_oracle_under_prediction_bias() {
        let p1 = make_proposal(
            "under-bias",
            ExperimentKind::AdversarialProbe,
            vec![(AcquisitionSignal::AdversarialOpportunity, 500_000)],
            200_000,
            100_000,
            100_000,
        );
        let o1 = record_outcome(&p1, 600_000); // over-delivered

        let cal = calibrate_oracle(&[o1], &[p1]);
        assert!(cal.bias_millionths < 0); // negative = under-prediction
    }

    #[test]
    fn calibrate_oracle_empty_outcomes() {
        let cal = calibrate_oracle(&[], &[]);
        assert_eq!(cal.predictions_count, 0);
        assert_eq!(cal.mean_absolute_error_millionths, 0);
        assert_eq!(cal.bias_millionths, 0);
    }

    #[test]
    fn calibrate_oracle_unmatched_outcomes_ignored() {
        let p1 = make_proposal(
            "match-me",
            ExperimentKind::BoardCellProbe,
            vec![(AcquisitionSignal::LiveShiftPressure, 500_000)],
            500_000,
            250_000,
            100_000,
        );
        // Outcome with a different id — should not match
        let mut o_unmatched = record_outcome(&p1, 500_000);
        o_unmatched.proposal_id = "no-match".to_string();

        let cal = calibrate_oracle(&[o_unmatched], &[p1]);
        assert_eq!(cal.predictions_count, 0);
    }

    #[test]
    fn calibrate_oracle_has_hash() {
        let cal = calibrate_oracle(&[], &[]);
        assert_ne!(cal.content_hash, ContentHash::compute(b""));
    }

    // -----------------------------------------------------------------------
    // AcquisitionError tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_no_candidates() {
        let e = AcquisitionError::NoCandidates;
        assert!(e.to_string().contains("no candidate"));
    }

    #[test]
    fn error_display_budget_exhausted() {
        let e = AcquisitionError::BudgetExhausted;
        assert!(e.to_string().contains("budget exhausted"));
    }

    #[test]
    fn error_display_calibration_drift() {
        let e = AcquisitionError::CalibrationDrift;
        assert!(e.to_string().contains("calibration"));
    }

    #[test]
    fn error_display_invalid_signal() {
        let e = AcquisitionError::InvalidSignal;
        assert!(e.to_string().contains("invalid"));
    }

    #[test]
    fn error_display_internal_error() {
        let e = AcquisitionError::InternalError("test failure".to_string());
        assert!(e.to_string().contains("test failure"));
    }

    #[test]
    fn error_serde_round_trip() {
        let variants = vec![
            AcquisitionError::NoCandidates,
            AcquisitionError::BudgetExhausted,
            AcquisitionError::CalibrationDrift,
            AcquisitionError::InvalidSignal,
            AcquisitionError::InternalError("oops".to_string()),
        ];
        for err in &variants {
            let json = serde_json::to_string(err).unwrap();
            let back: AcquisitionError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, err);
        }
    }

    // -----------------------------------------------------------------------
    // Manifest tests
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_returns_valid_plan() {
        let plan = franken_engine_acquisition_manifest();
        assert_eq!(plan.proposals.len(), 7);
        assert_eq!(plan.scores.len(), 7);
        let errors = validate_plan(&plan);
        assert!(errors.is_empty(), "manifest validation errors: {errors:?}");
    }

    #[test]
    fn manifest_covers_all_experiment_kinds() {
        let plan = franken_engine_acquisition_manifest();
        let mut kinds: Vec<ExperimentKind> = plan.proposals.iter().map(|p| p.kind).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), ExperimentKind::ALL.len());
    }

    #[test]
    fn manifest_content_hash_is_deterministic() {
        let plan1 = franken_engine_acquisition_manifest();
        let plan2 = franken_engine_acquisition_manifest();
        assert_eq!(plan1.content_hash, plan2.content_hash);
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn combine_signal_strengths_single() {
        assert_eq!(combine_signal_strengths(&[500_000]), 500_000);
    }

    #[test]
    fn combine_signal_strengths_multiple() {
        // First = 800_000, second = 400_000/2 = 200_000, third = 200_000/4 = 50_000
        let result = combine_signal_strengths(&[800_000, 400_000, 200_000]);
        assert_eq!(result, 1_050_000);
    }

    #[test]
    fn combine_signal_strengths_empty() {
        assert_eq!(combine_signal_strengths(&[]), 0);
    }

    #[test]
    fn information_density_normal() {
        let p = make_proposal(
            "density",
            ExperimentKind::BoardCellProbe,
            vec![],
            500_000,
            200_000,
            100_000,
        );
        // density = 500_000 * 1_000_000 / 100_000 = 5_000_000
        assert_eq!(information_density(&p), 5_000_000);
    }

    #[test]
    fn information_density_zero_cost() {
        let p = make_proposal(
            "free",
            ExperimentKind::BoardCellProbe,
            vec![],
            500_000,
            200_000,
            0,
        );
        // Zero cost treated as 1, so density = 500_000 * 1_000_000 / 1
        assert_eq!(information_density(&p), 500_000_000_000);
    }

    #[test]
    fn is_justified_yes() {
        let p = make_proposal(
            "just",
            ExperimentKind::CorpusAddition,
            vec![],
            500_000,
            200_000,
            100_000,
        );
        // Threshold 1.0: min_gain = 100_000 * 1_000_000 / 1_000_000 = 100_000
        // 500_000 >= 100_000 => justified
        assert!(is_justified(&p, MILLIONTHS));
    }

    #[test]
    fn is_justified_no() {
        let p = make_proposal(
            "unjust",
            ExperimentKind::CorpusAddition,
            vec![],
            50_000,
            20_000,
            500_000,
        );
        // Threshold 2.0: min_gain = 500_000 * 2_000_000 / 1_000_000 = 1_000_000
        // 50_000 < 1_000_000 => not justified
        assert!(!is_justified(&p, 2_000_000));
    }

    #[test]
    fn diversity_bonus_all_kinds() {
        let mut proposals = Vec::new();
        for (i, &kind) in ExperimentKind::ALL.iter().enumerate() {
            proposals.push(make_proposal(
                &format!("div-{i}"),
                kind,
                vec![],
                100_000,
                50_000,
                50_000,
            ));
        }
        assert_eq!(diversity_bonus(&proposals), MILLIONTHS);
    }

    #[test]
    fn diversity_bonus_single_kind() {
        let p = make_proposal(
            "mono",
            ExperimentKind::BoardCellProbe,
            vec![],
            100_000,
            50_000,
            50_000,
        );
        // 1 / 7 = 142857 millionths
        let bonus = diversity_bonus(&[p]);
        assert_eq!(bonus, MILLIONTHS / 7);
    }

    #[test]
    fn staleness_penalty_fresh() {
        assert_eq!(staleness_penalty(5, 10), 0);
    }

    #[test]
    fn staleness_penalty_stale() {
        // 15 ticks, max fresh = 10 => over = 5
        // penalty = 5 * 1_000_000 / 10 = 500_000
        assert_eq!(staleness_penalty(15, 10), 500_000);
    }

    #[test]
    fn staleness_penalty_very_stale_capped() {
        // 1000 ticks, max fresh = 10 => over = 990
        // penalty = 990 * 1_000_000 / 10 = 99_000_000 => capped at MILLIONTHS
        assert_eq!(staleness_penalty(1000, 10), MILLIONTHS);
    }

    #[test]
    fn partition_by_kind_groups_correctly() {
        let p1 = make_proposal(
            "part-1",
            ExperimentKind::BoardCellProbe,
            vec![],
            100_000,
            50_000,
            50_000,
        );
        let p2 = make_proposal(
            "part-2",
            ExperimentKind::BoardCellProbe,
            vec![],
            200_000,
            100_000,
            50_000,
        );
        let p3 = make_proposal(
            "part-3",
            ExperimentKind::CorpusAddition,
            vec![],
            300_000,
            150_000,
            50_000,
        );

        let binding = [p1, p2, p3];
        let partitioned = partition_by_kind(&binding);
        assert_eq!(partitioned.len(), 2);
        assert_eq!(partitioned[&ExperimentKind::BoardCellProbe].len(), 2);
        assert_eq!(partitioned[&ExperimentKind::CorpusAddition].len(), 1);
    }

    #[test]
    fn find_dominant_signal_picks_strongest() {
        let p1 = make_proposal(
            "dom-1",
            ExperimentKind::BoardCellProbe,
            vec![
                (AcquisitionSignal::LiveShiftPressure, 300_000),
                (AcquisitionSignal::CoverageDebt, 800_000),
            ],
            100_000,
            50_000,
            50_000,
        );
        let p2 = make_proposal(
            "dom-2",
            ExperimentKind::CorpusAddition,
            vec![(AcquisitionSignal::CoverageDebt, 200_000)],
            100_000,
            50_000,
            50_000,
        );

        let dominant = find_dominant_signal(&[p1, p2]);
        // CoverageDebt total = 800_000 + 200_000 = 1_000_000
        // LiveShiftPressure total = 300_000
        assert_eq!(dominant, Some(AcquisitionSignal::CoverageDebt));
    }

    #[test]
    fn find_dominant_signal_empty() {
        assert_eq!(find_dominant_signal(&[]), None);
    }

    #[test]
    fn allocate_budget_by_kind_distributes_proportionally() {
        let p1 = make_proposal(
            "alloc-1",
            ExperimentKind::BoardCellProbe,
            vec![],
            100_000,
            50_000,
            50_000,
        );
        let p2 = make_proposal(
            "alloc-2",
            ExperimentKind::BoardCellProbe,
            vec![],
            100_000,
            50_000,
            50_000,
        );
        let p3 = make_proposal(
            "alloc-3",
            ExperimentKind::CorpusAddition,
            vec![],
            100_000,
            50_000,
            50_000,
        );

        let allocation = allocate_budget_by_kind(&[p1, p2, p3], MILLIONTHS);
        // BoardCellProbe: 2/3 of budget
        // CorpusAddition: 1/3 of budget (gets remainder)
        let probe_budget = allocation[&ExperimentKind::BoardCellProbe];
        let corpus_budget = allocation[&ExperimentKind::CorpusAddition];
        assert_eq!(probe_budget + corpus_budget, MILLIONTHS);
    }

    #[test]
    fn exploration_ratio_all_exploration() {
        let p1 = make_proposal(
            "explore",
            ExperimentKind::DarkMatterExploration,
            vec![],
            100_000,
            50_000,
            MILLIONTHS,
        );
        assert_eq!(exploration_ratio(&[p1]), MILLIONTHS);
    }

    #[test]
    fn exploration_ratio_all_exploitation() {
        let p1 = make_proposal(
            "exploit",
            ExperimentKind::BoardCellProbe,
            vec![],
            100_000,
            50_000,
            MILLIONTHS,
        );
        assert_eq!(exploration_ratio(&[p1]), 0);
    }

    #[test]
    fn exploration_ratio_mixed() {
        let p1 = make_proposal(
            "explore",
            ExperimentKind::HoleFilling,
            vec![],
            100_000,
            50_000,
            500_000,
        );
        let p2 = make_proposal(
            "exploit",
            ExperimentKind::AdversarialProbe,
            vec![],
            100_000,
            50_000,
            500_000,
        );
        // 500_000 / 1_000_000 = 0.5 => 500_000 millionths
        assert_eq!(exploration_ratio(&[p1, p2]), 500_000);
    }

    #[test]
    fn validate_plan_detects_gain_mismatch() {
        let p1 = make_proposal(
            "v1",
            ExperimentKind::BoardCellProbe,
            vec![],
            300_000,
            150_000,
            100_000,
        );
        let s1 = score_proposal(&p1, &default_weights());

        let plan = ExperimentPlan {
            plan_id: "bad-plan".to_string(),
            epoch: SecurityEpoch::GENESIS,
            proposals: vec![p1],
            scores: vec![s1],
            budget_remaining_millionths: 900_000,
            total_expected_gain_millionths: 999_999, // wrong
            content_hash: ContentHash::compute(b"test"),
        };

        let errors = validate_plan(&plan);
        assert!(!errors.is_empty());
        assert!(errors[0].contains("total_expected_gain"));
    }

    #[test]
    fn validate_plan_detects_count_mismatch() {
        let p1 = make_proposal(
            "v2",
            ExperimentKind::BoardCellProbe,
            vec![],
            300_000,
            150_000,
            100_000,
        );

        let plan = ExperimentPlan {
            plan_id: "bad-count".to_string(),
            epoch: SecurityEpoch::GENESIS,
            proposals: vec![p1],
            scores: vec![], // empty — mismatch
            budget_remaining_millionths: 900_000,
            total_expected_gain_millionths: 300_000,
            content_hash: ContentHash::compute(b"test"),
        };

        let errors = validate_plan(&plan);
        assert!(!errors.is_empty());
        assert!(errors[0].contains("score count"));
    }

    #[test]
    fn summarise_plan_includes_key_info() {
        let plan = franken_engine_acquisition_manifest();
        let summary = summarise_plan(&plan);
        assert!(summary.contains("Experiment Plan"));
        assert!(summary.contains("Budget remaining"));
        assert!(summary.contains("Justification"));
        assert!(summary.contains("Content hash"));
    }

    // -----------------------------------------------------------------------
    // Outcome serde
    // -----------------------------------------------------------------------

    #[test]
    fn outcome_serde_round_trip() {
        let p = make_proposal(
            "os-1",
            ExperimentKind::CoverageRecovery,
            vec![(AcquisitionSignal::PersistentHole, 600_000)],
            400_000,
            200_000,
            100_000,
        );
        let outcome = record_outcome(&p, 350_000);
        let json = serde_json::to_string(&outcome).unwrap();
        let back: ExperimentOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, outcome);
    }

    // -----------------------------------------------------------------------
    // Calibration serde
    // -----------------------------------------------------------------------

    #[test]
    fn calibration_serde_round_trip() {
        let p = make_proposal(
            "cs-1",
            ExperimentKind::ShiftValidation,
            vec![(AcquisitionSignal::StalenessAlarm, 500_000)],
            400_000,
            200_000,
            100_000,
        );
        let o = record_outcome(&p, 350_000);
        let cal = calibrate_oracle(&[o], &[p]);
        let json = serde_json::to_string(&cal).unwrap();
        let back: OracleCalibration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cal);
    }

    // -----------------------------------------------------------------------
    // AcquisitionScore serde
    // -----------------------------------------------------------------------

    #[test]
    fn score_serde_round_trip() {
        let p = make_proposal(
            "ss-1",
            ExperimentKind::DarkMatterExploration,
            vec![(AcquisitionSignal::SemanticDarkMatter, 800_000)],
            600_000,
            300_000,
            200_000,
        );
        let w = default_weights();
        let score = score_proposal(&p, &w);
        let json = serde_json::to_string(&score).unwrap();
        let back: AcquisitionScore = serde_json::from_str(&json).unwrap();
        assert_eq!(back, score);
    }

    // -----------------------------------------------------------------------
    // ExperimentPlan serde
    // -----------------------------------------------------------------------

    #[test]
    fn plan_serde_round_trip() {
        let plan = franken_engine_acquisition_manifest();
        let json = serde_json::to_string(&plan).unwrap();
        let back: ExperimentPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back, plan);
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn constants_are_set() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert_eq!(BEAD_ID, "bd-1lsy.8.6.2");
        assert!(!COMPONENT.is_empty());
        assert_eq!(POLICY_ID, "RGC-706B");
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Display impls
    // -----------------------------------------------------------------------

    #[test]
    fn outcome_display() {
        let p = make_proposal(
            "disp-out",
            ExperimentKind::BoardCellProbe,
            vec![],
            400_000,
            200_000,
            100_000,
        );
        let o = record_outcome(&p, 300_000);
        let s = o.to_string();
        assert!(s.contains("disp-out"));
        assert!(s.contains("300000"));
    }

    #[test]
    fn calibration_display() {
        let cal = calibrate_oracle(&[], &[]);
        let s = cal.to_string();
        assert!(s.contains("Calibration"));
        assert!(s.contains("n=0"));
    }

    #[test]
    fn score_display() {
        let p = make_proposal(
            "sc-disp",
            ExperimentKind::CorpusAddition,
            vec![(AcquisitionSignal::CoverageDebt, 500_000)],
            300_000,
            150_000,
            100_000,
        );
        let w = default_weights();
        let score = score_proposal(&p, &w);
        let s = score.to_string();
        assert!(s.contains("sc-disp"));
        assert!(s.contains("Score"));
    }

    #[test]
    fn plan_display() {
        let plan = franken_engine_acquisition_manifest();
        let s = plan.to_string();
        assert!(s.contains("Plan"));
        assert!(s.contains("experiments=7"));
    }
}
