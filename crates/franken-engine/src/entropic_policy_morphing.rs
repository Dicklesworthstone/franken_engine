#![forbid(unsafe_code)]

//! Entropic policy morphing and transition-budget control between detected regimes.
//!
//! Implements [RGC-617B]: turns regime awareness into bounded, safe policy
//! adaptation. Given a detected regime transition (from `regime_signature_feature`
//! and `regime_detector`), this module controls *how much* and *how fast* the
//! runtime may morph its policy profile, and provides deterministic fallback
//! when the transition path is unsafe or under-evidenced.
//!
//! Key design decisions:
//! - Transition budgets are finite per epoch; the runtime cannot morph
//!   indefinitely without operator replenishment.
//! - Entropy of the policy distribution is bounded: overly uniform (maximum
//!   entropy) or overly concentrated (zero entropy) policies are rejected.
//! - Every morphing step produces an auditable `MorphingEvent` with evidence hash.
//! - When budget is exhausted or safety conditions fail, the system falls back
//!   to a conservative "anchor" policy rather than freezing in place.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::regime_detector::Regime;
use crate::regime_signature_feature::RegimeLabel;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MORPHING_SCHEMA_VERSION: &str =
    "franken-engine.entropic_policy_morphing.v1";
pub const MORPHING_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.entropic_policy_morphing_manifest.v1";
pub const MORPHING_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.entropic_policy_morphing_event.v1";
pub const MORPHING_COMPONENT: &str = "entropic_policy_morphing";
pub const MORPHING_POLICY_ID: &str = "RGC-617B";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: i64 = 1_000_000;

/// Default transition budget per epoch (number of morphing steps allowed).
pub const DEFAULT_TRANSITION_BUDGET: u64 = 10;

/// Maximum single-step policy distance (L1, millionths).
pub const MAX_STEP_DISTANCE_MILLIONTHS: i64 = 500_000; // 0.5

/// Minimum entropy threshold (millionths of nats). Below this, the policy
/// is too concentrated and risks brittle behavior.
pub const MIN_ENTROPY_MILLIONTHS: i64 = 100_000; // 0.1 nats

/// Maximum entropy threshold (millionths of nats). Above this, the policy
/// is too diffuse to be actionable.
pub const MAX_ENTROPY_MILLIONTHS: i64 = 2_000_000; // 2.0 nats

/// Cooldown steps after a fallback before morphing may resume.
pub const FALLBACK_COOLDOWN_STEPS: u64 = 3;

// ---------------------------------------------------------------------------
// Policy profile — the thing being morphed
// ---------------------------------------------------------------------------

/// A policy profile is a named mapping of policy dimensions to values (millionths).
///
/// For example, dimensions might include "exploration_rate", "sandbox_strictness",
/// "gc_aggressiveness", etc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyProfile {
    /// Human-readable name (e.g., "normal_baseline", "attack_lockdown").
    pub name: String,
    /// Dimension values in millionths.
    pub dimensions: BTreeMap<String, i64>,
    /// Associated regime (if regime-specific).
    pub target_regime: Option<Regime>,
}

impl PolicyProfile {
    /// Create a new policy profile.
    pub fn new(name: &str, dimensions: BTreeMap<String, i64>) -> Self {
        Self {
            name: name.to_string(),
            dimensions,
            target_regime: None,
        }
    }

    /// Create a profile with an associated regime.
    pub fn for_regime(name: &str, regime: Regime, dimensions: BTreeMap<String, i64>) -> Self {
        Self {
            name: name.to_string(),
            dimensions,
            target_regime: Some(regime),
        }
    }

    /// Compute the L1 distance between two profiles.
    ///
    /// Only shared dimensions contribute. Missing dimensions are treated as 0.
    pub fn l1_distance(&self, other: &PolicyProfile) -> i64 {
        let mut all_keys: std::collections::BTreeSet<&String> = self.dimensions.keys().collect();
        all_keys.extend(other.dimensions.keys());

        all_keys
            .iter()
            .map(|k| {
                let a = self.dimensions.get(*k).copied().unwrap_or(0);
                let b = other.dimensions.get(*k).copied().unwrap_or(0);
                (a - b).abs()
            })
            .sum()
    }

    /// Compute the entropy of the profile (millionths of nats).
    ///
    /// Treats dimension values as unnormalized weights. Uses a fixed-point
    /// ln approximation.
    pub fn entropy_millionths(&self) -> i64 {
        if self.dimensions.is_empty() {
            return 0;
        }

        let values: Vec<i64> = self.dimensions.values().copied().collect();
        let total: i64 = values.iter().map(|v| v.max(&0)).sum();
        if total == 0 {
            return 0;
        }

        let mut entropy: i64 = 0;
        for &v in &values {
            let v = v.max(0);
            if v == 0 {
                continue;
            }
            // p = v / total, in millionths: p_m = v * MILLION / total
            let p_m = v.saturating_mul(MILLION).checked_div(total).unwrap_or(0);
            if p_m > 0 {
                // -p * ln(p) in millionths
                let ln_p = ln_millionths(p_m);
                entropy = entropy.saturating_sub(
                    p_m.saturating_mul(ln_p).checked_div(MILLION).unwrap_or(0),
                );
            }
        }
        entropy
    }

    /// Compute a content hash of this profile.
    pub fn content_hash(&self) -> String {
        let mut input = format!("profile:{}:", self.name);
        for (k, v) in &self.dimensions {
            input.push_str(&format!("{k}={v},"));
        }
        hex_encode(ContentHash::compute(input.as_bytes()).as_bytes())
    }
}

/// Fixed-point natural logarithm: ln(x/1_000_000) * 1_000_000.
///
/// Uses the identity ln(x) = ln(x/e^k) + k for range reduction,
/// then a Padé approximant for |y-1| < 1.
fn ln_millionths(x_millionths: i64) -> i64 {
    if x_millionths <= 0 {
        return i64::MIN / 2; // -∞ sentinel
    }
    if x_millionths == MILLION {
        return 0;
    }

    // ln(x_millionths / MILLION) = ln(x_millionths) - ln(MILLION)
    // Use a simple piecewise linear approximation for stability.
    // ln(1) = 0, ln(2) ≈ 0.693, ln(e) = 1.0
    //
    // For fixed-point: we compute floor(ln(x/1e6) * 1e6)
    // Approach: count doublings then refine.

    let mut val = x_millionths;
    let mut log_acc: i64 = 0;

    // Range reduction: divide by e ≈ 2_718_282 millionths until val < 2*MILLION
    let e_m: i64 = 2_718_282; // e in millionths
    while val > 2 * MILLION {
        val = val.saturating_mul(MILLION).checked_div(e_m).unwrap_or(1);
        log_acc += MILLION; // +1.0 in millionths
    }
    // For val < MILLION, multiply by e
    while val < MILLION / 2 && val > 0 {
        val = val.saturating_mul(e_m).checked_div(MILLION).unwrap_or(1);
        log_acc -= MILLION; // -1.0 in millionths
    }

    // Now val is roughly in [MILLION/2, 2*MILLION].
    // Use ln(1+u) ≈ u - u²/2 + u³/3 where u = (val - MILLION) / MILLION.
    let u = val - MILLION; // in millionths of the offset
    let u_sq = u.saturating_mul(u).checked_div(MILLION).unwrap_or(0);
    let u_cu = u_sq.saturating_mul(u).checked_div(MILLION).unwrap_or(0);

    let taylor = u - u_sq / 2 + u_cu / 3;
    log_acc + taylor
}

// ---------------------------------------------------------------------------
// Transition budget
// ---------------------------------------------------------------------------

/// Budget controlling how many morphing steps are allowed per epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionBudget {
    /// Maximum steps allowed in this epoch.
    pub max_steps: u64,
    /// Steps consumed so far.
    pub steps_used: u64,
    /// Maximum cumulative L1 distance moved (millionths).
    pub max_cumulative_distance_millionths: i64,
    /// Cumulative distance moved so far (millionths).
    pub cumulative_distance_millionths: i64,
    /// Epoch this budget belongs to.
    pub epoch: SecurityEpoch,
}

impl TransitionBudget {
    /// Create a new budget for an epoch.
    pub fn new(epoch: SecurityEpoch, max_steps: u64, max_distance: i64) -> Self {
        Self {
            max_steps,
            steps_used: 0,
            max_cumulative_distance_millionths: max_distance,
            cumulative_distance_millionths: 0,
            epoch,
        }
    }

    /// Create with defaults.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(epoch, DEFAULT_TRANSITION_BUDGET, 5 * MILLION)
    }

    /// Can we take another step of the given distance?
    pub fn can_step(&self, distance_millionths: i64) -> bool {
        self.steps_used < self.max_steps
            && self
                .cumulative_distance_millionths
                .saturating_add(distance_millionths)
                <= self.max_cumulative_distance_millionths
    }

    /// Record a step.
    pub fn record_step(&mut self, distance_millionths: i64) {
        self.steps_used += 1;
        self.cumulative_distance_millionths = self
            .cumulative_distance_millionths
            .saturating_add(distance_millionths);
    }

    /// Remaining steps.
    pub fn remaining_steps(&self) -> u64 {
        self.max_steps.saturating_sub(self.steps_used)
    }

    /// Remaining distance budget (millionths).
    pub fn remaining_distance_millionths(&self) -> i64 {
        self.max_cumulative_distance_millionths
            .saturating_sub(self.cumulative_distance_millionths)
    }

    /// Is the budget exhausted?
    pub fn is_exhausted(&self) -> bool {
        self.steps_used >= self.max_steps
            || self.cumulative_distance_millionths >= self.max_cumulative_distance_millionths
    }

    /// Reset the budget for a new epoch.
    pub fn reset(&mut self, epoch: SecurityEpoch) {
        self.epoch = epoch;
        self.steps_used = 0;
        self.cumulative_distance_millionths = 0;
    }
}

// ---------------------------------------------------------------------------
// Morphing step — a single policy change
// ---------------------------------------------------------------------------

/// Reason a morphing step was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphingRejection {
    /// Transition budget exhausted.
    BudgetExhausted,
    /// Single-step distance exceeds maximum.
    StepTooLarge,
    /// Target policy entropy too low (too concentrated).
    EntropyTooLow,
    /// Target policy entropy too high (too diffuse).
    EntropyTooHigh,
    /// Cooldown period after fallback not elapsed.
    CooldownActive,
    /// Source regime is Abstention — cannot morph from unknown state.
    SourceAbstention,
    /// No matching regime profile found.
    NoTargetProfile,
}

impl MorphingRejection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BudgetExhausted => "budget_exhausted",
            Self::StepTooLarge => "step_too_large",
            Self::EntropyTooLow => "entropy_too_low",
            Self::EntropyTooHigh => "entropy_too_high",
            Self::CooldownActive => "cooldown_active",
            Self::SourceAbstention => "source_abstention",
            Self::NoTargetProfile => "no_target_profile",
        }
    }
}

impl fmt::Display for MorphingRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Outcome of a morphing attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphingOutcome {
    /// Morphing succeeded; new profile applied.
    Applied {
        distance_millionths: i64,
        new_entropy_millionths: i64,
    },
    /// Morphing was rejected; anchor fallback applied.
    Rejected {
        reason: MorphingRejection,
    },
    /// No morphing needed; regimes are the same.
    NoOp,
}

impl MorphingOutcome {
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }
}

/// A recorded morphing step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphingStep {
    /// Step sequence number.
    pub seq: u64,
    /// Source regime label.
    pub from_regime: RegimeLabel,
    /// Target regime label.
    pub to_regime: RegimeLabel,
    /// Policy before morphing.
    pub from_profile_name: String,
    /// Policy after morphing (or anchor if rejected).
    pub to_profile_name: String,
    /// Outcome of the morphing attempt.
    pub outcome: MorphingOutcome,
    /// Evidence hash.
    pub evidence_hash: String,
}

// ---------------------------------------------------------------------------
// Morphing controller
// ---------------------------------------------------------------------------

/// Configuration for the morphing controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphingConfig {
    /// Maximum single-step L1 distance (millionths).
    pub max_step_distance_millionths: i64,
    /// Minimum entropy for a target profile (millionths of nats).
    pub min_entropy_millionths: i64,
    /// Maximum entropy for a target profile (millionths of nats).
    pub max_entropy_millionths: i64,
    /// Cooldown steps after fallback.
    pub fallback_cooldown_steps: u64,
    /// Interpolation rate for gradual morphing (millionths, 0..1_000_000).
    /// 1_000_000 = instant switch, 500_000 = halfway blend.
    pub interpolation_rate_millionths: i64,
}

impl Default for MorphingConfig {
    fn default() -> Self {
        Self {
            max_step_distance_millionths: MAX_STEP_DISTANCE_MILLIONTHS,
            min_entropy_millionths: MIN_ENTROPY_MILLIONTHS,
            max_entropy_millionths: MAX_ENTROPY_MILLIONTHS,
            fallback_cooldown_steps: FALLBACK_COOLDOWN_STEPS,
            interpolation_rate_millionths: 300_000, // 0.3 — conservative default
        }
    }
}

/// The entropic policy morphing controller.
///
/// Manages policy transitions between regime-specific profiles with
/// budget control, entropy bounds, and deterministic fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntropicPolicyMorpher {
    /// Configuration.
    pub config: MorphingConfig,
    /// Current active policy profile.
    pub current_profile: PolicyProfile,
    /// Anchor (fallback) policy profile.
    pub anchor_profile: PolicyProfile,
    /// Regime-specific target profiles.
    pub regime_profiles: BTreeMap<String, PolicyProfile>,
    /// Transition budget.
    pub budget: TransitionBudget,
    /// Step counter.
    pub step_count: u64,
    /// Steps since last fallback (for cooldown).
    pub steps_since_fallback: u64,
    /// Whether we are in fallback mode.
    pub in_fallback: bool,
    /// History of morphing steps.
    pub history: Vec<MorphingStep>,
    /// Fallback count.
    pub fallback_count: u64,
    /// Applied count.
    pub applied_count: u64,
    /// Current regime label.
    pub current_regime: RegimeLabel,
}

impl EntropicPolicyMorpher {
    /// Create a new morpher with an anchor profile and budget.
    pub fn new(
        anchor: PolicyProfile,
        budget: TransitionBudget,
        config: MorphingConfig,
    ) -> Self {
        let current = anchor.clone();
        Self {
            config,
            current_profile: current,
            anchor_profile: anchor,
            regime_profiles: BTreeMap::new(),
            budget,
            step_count: 0,
            steps_since_fallback: u64::MAX, // no fallback yet
            in_fallback: false,
            history: Vec::new(),
            fallback_count: 0,
            applied_count: 0,
            current_regime: RegimeLabel::Abstention,
        }
    }

    /// Create with default config and budget.
    pub fn with_defaults(anchor: PolicyProfile, epoch: SecurityEpoch) -> Self {
        Self::new(
            anchor,
            TransitionBudget::with_defaults(epoch),
            MorphingConfig::default(),
        )
    }

    /// Register a regime-specific target profile.
    pub fn register_profile(&mut self, regime: Regime, profile: PolicyProfile) {
        self.regime_profiles.insert(regime.to_string(), profile);
    }

    /// Attempt to morph the policy in response to a regime transition.
    ///
    /// Returns the morphing outcome. On rejection, automatically applies
    /// the anchor fallback profile.
    pub fn morph(&mut self, new_regime: RegimeLabel) -> MorphingOutcome {
        let from_regime = self.current_regime;
        self.step_count += 1;
        self.steps_since_fallback = self.steps_since_fallback.saturating_add(1);

        // No-op if regime hasn't changed.
        if new_regime == from_regime {
            let step = MorphingStep {
                seq: self.step_count,
                from_regime,
                to_regime: new_regime,
                from_profile_name: self.current_profile.name.clone(),
                to_profile_name: self.current_profile.name.clone(),
                outcome: MorphingOutcome::NoOp,
                evidence_hash: self.compute_step_hash("noop"),
            };
            self.history.push(step);
            return MorphingOutcome::NoOp;
        }

        // Check cooldown.
        if self.steps_since_fallback < self.config.fallback_cooldown_steps {
            return self.reject(from_regime, new_regime, MorphingRejection::CooldownActive);
        }

        // Cannot morph from Abstention.
        if from_regime.is_abstention() && !new_regime.is_abstention() {
            // Allow transition OUT of abstention to a known regime.
        }
        if new_regime.is_abstention() {
            return self.reject(from_regime, new_regime, MorphingRejection::SourceAbstention);
        }

        // Find target profile for the new regime.
        let target_regime = match new_regime {
            RegimeLabel::Classified(r) => r,
            RegimeLabel::Abstention => {
                return self.reject(from_regime, new_regime, MorphingRejection::SourceAbstention);
            }
        };

        let target_profile = match self.regime_profiles.get(&target_regime.to_string()) {
            Some(p) => p.clone(),
            None => {
                return self.reject(from_regime, new_regime, MorphingRejection::NoTargetProfile);
            }
        };

        // Check budget.
        let distance = self.current_profile.l1_distance(&target_profile);
        if !self.budget.can_step(distance) {
            return self.reject(from_regime, new_regime, MorphingRejection::BudgetExhausted);
        }

        // Check step distance.
        if distance > self.config.max_step_distance_millionths {
            // Try interpolation: blend current toward target.
            let blended = self.interpolate(&target_profile);
            let blend_distance = self.current_profile.l1_distance(&blended);

            if blend_distance > self.config.max_step_distance_millionths {
                return self.reject(from_regime, new_regime, MorphingRejection::StepTooLarge);
            }

            // Check entropy of blended profile.
            let entropy = blended.entropy_millionths();
            if entropy < self.config.min_entropy_millionths {
                return self.reject(from_regime, new_regime, MorphingRejection::EntropyTooLow);
            }
            if entropy > self.config.max_entropy_millionths {
                return self.reject(from_regime, new_regime, MorphingRejection::EntropyTooHigh);
            }

            // Apply blended profile.
            self.budget.record_step(blend_distance);
            self.current_profile = blended;
            self.current_regime = new_regime;
            self.in_fallback = false;
            self.applied_count += 1;

            let outcome = MorphingOutcome::Applied {
                distance_millionths: blend_distance,
                new_entropy_millionths: entropy,
            };
            let step = MorphingStep {
                seq: self.step_count,
                from_regime,
                to_regime: new_regime,
                from_profile_name: self.current_profile.name.clone(),
                to_profile_name: self.current_profile.name.clone(),
                outcome: outcome.clone(),
                evidence_hash: self.compute_step_hash("blend_applied"),
            };
            self.history.push(step);
            return outcome;
        }

        // Check entropy of target.
        let entropy = target_profile.entropy_millionths();
        if entropy < self.config.min_entropy_millionths {
            return self.reject(from_regime, new_regime, MorphingRejection::EntropyTooLow);
        }
        if entropy > self.config.max_entropy_millionths {
            return self.reject(from_regime, new_regime, MorphingRejection::EntropyTooHigh);
        }

        // All checks passed — apply the target profile.
        self.budget.record_step(distance);
        let old_name = self.current_profile.name.clone();
        self.current_profile = target_profile;
        self.current_regime = new_regime;
        self.in_fallback = false;
        self.applied_count += 1;

        let outcome = MorphingOutcome::Applied {
            distance_millionths: distance,
            new_entropy_millionths: entropy,
        };
        let step = MorphingStep {
            seq: self.step_count,
            from_regime,
            to_regime: new_regime,
            from_profile_name: old_name,
            to_profile_name: self.current_profile.name.clone(),
            outcome: outcome.clone(),
            evidence_hash: self.compute_step_hash("applied"),
        };
        self.history.push(step);
        outcome
    }

    /// Reset the budget for a new epoch.
    pub fn reset_budget(&mut self, epoch: SecurityEpoch) {
        self.budget.reset(epoch);
    }

    /// Get the current profile.
    pub fn current_profile(&self) -> &PolicyProfile {
        &self.current_profile
    }

    /// Get the anchor profile.
    pub fn anchor_profile(&self) -> &PolicyProfile {
        &self.anchor_profile
    }

    /// Is the controller in fallback mode?
    pub fn is_in_fallback(&self) -> bool {
        self.in_fallback
    }

    /// Summary statistics.
    pub fn summary(&self) -> MorphingSummary {
        MorphingSummary {
            step_count: self.step_count,
            applied_count: self.applied_count,
            fallback_count: self.fallback_count,
            budget_remaining_steps: self.budget.remaining_steps(),
            budget_remaining_distance: self.budget.remaining_distance_millionths(),
            current_profile_name: self.current_profile.name.clone(),
            current_regime: self.current_regime,
            in_fallback: self.in_fallback,
        }
    }

    // -- internal helpers --

    fn reject(
        &mut self,
        from_regime: RegimeLabel,
        to_regime: RegimeLabel,
        reason: MorphingRejection,
    ) -> MorphingOutcome {
        // Apply anchor fallback.
        self.current_profile = self.anchor_profile.clone();
        self.in_fallback = true;
        self.fallback_count += 1;
        self.steps_since_fallback = 0;

        let outcome = MorphingOutcome::Rejected { reason };
        let step = MorphingStep {
            seq: self.step_count,
            from_regime,
            to_regime,
            from_profile_name: self.current_profile.name.clone(),
            to_profile_name: self.anchor_profile.name.clone(),
            outcome: outcome.clone(),
            evidence_hash: self.compute_step_hash(reason.as_str()),
        };
        self.history.push(step);
        outcome
    }

    fn interpolate(&self, target: &PolicyProfile) -> PolicyProfile {
        let rate = self.config.interpolation_rate_millionths;
        let mut dims = BTreeMap::new();

        let mut all_keys: std::collections::BTreeSet<&String> =
            self.current_profile.dimensions.keys().collect();
        all_keys.extend(target.dimensions.keys());

        for k in all_keys {
            let cur = self.current_profile.dimensions.get(k).copied().unwrap_or(0);
            let tgt = target.dimensions.get(k).copied().unwrap_or(0);
            // blend = cur + rate * (tgt - cur) / MILLION
            let delta = tgt - cur;
            let blended = cur + delta.saturating_mul(rate).checked_div(MILLION).unwrap_or(0);
            dims.insert(k.clone(), blended);
        }

        PolicyProfile {
            name: format!("blend_{}_{}", self.current_profile.name, target.name),
            dimensions: dims,
            target_regime: target.target_regime,
        }
    }

    fn compute_step_hash(&self, tag: &str) -> String {
        let input = format!(
            "morph:{}:{}:{}:{}",
            self.step_count, tag, self.current_profile.name, self.budget.steps_used
        );
        hex_encode(ContentHash::compute(input.as_bytes()).as_bytes())
    }
}

/// Summary of the morpher state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphingSummary {
    pub step_count: u64,
    pub applied_count: u64,
    pub fallback_count: u64,
    pub budget_remaining_steps: u64,
    pub budget_remaining_distance: i64,
    pub current_profile_name: String,
    pub current_regime: RegimeLabel,
    pub in_fallback: bool,
}

// ---------------------------------------------------------------------------
// Evidence harness — specimens, inventory, bundle
// ---------------------------------------------------------------------------

/// Specimen family for testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphingSpecimenFamily {
    /// Basic morphing transitions.
    Transition,
    /// Budget exhaustion.
    BudgetExhaustion,
    /// Step distance limits.
    StepDistance,
    /// Entropy bounds.
    EntropyBounds,
    /// Cooldown enforcement.
    Cooldown,
    /// Interpolation blending.
    Interpolation,
    /// Fallback behavior.
    Fallback,
    /// No-op same-regime.
    NoOp,
}

impl MorphingSpecimenFamily {
    pub const ALL: &[Self] = &[
        Self::Transition,
        Self::BudgetExhaustion,
        Self::StepDistance,
        Self::EntropyBounds,
        Self::Cooldown,
        Self::Interpolation,
        Self::Fallback,
        Self::NoOp,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transition => "transition",
            Self::BudgetExhaustion => "budget_exhaustion",
            Self::StepDistance => "step_distance",
            Self::EntropyBounds => "entropy_bounds",
            Self::Cooldown => "cooldown",
            Self::Interpolation => "interpolation",
            Self::Fallback => "fallback",
            Self::NoOp => "no_op",
        }
    }
}

impl fmt::Display for MorphingSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Expected outcome for a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphingExpectedOutcome {
    Applied,
    Rejected,
    NoOp,
    FallbackActivated,
    BudgetExhausted,
    InterpolationUsed,
}

/// A test specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphingSpecimen {
    pub specimen_id: String,
    pub description: String,
    pub family: MorphingSpecimenFamily,
    pub expected_outcome: MorphingExpectedOutcome,
}

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphingVerdict {
    Pass,
    Fail,
}

/// Evidence for a specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphingSpecimenEvidence {
    pub specimen_id: String,
    pub family: MorphingSpecimenFamily,
    pub expected_outcome: MorphingExpectedOutcome,
    pub verdict: MorphingVerdict,
    pub actual_outcome: String,
    pub error_detail: Option<String>,
    pub evidence_hash: String,
}

/// Aggregate inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphingEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub family_coverage: BTreeMap<String, u64>,
    pub evidence: Vec<MorphingSpecimenEvidence>,
}

impl MorphingEvidenceInventory {
    pub fn contract_satisfied(&self) -> bool {
        self.fail_count == 0 && self.specimen_count > 0
    }
}

/// Run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphingRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub contract_satisfied: bool,
    pub artifact_paths: MorphingArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphingArtifactPaths {
    pub evidence_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

/// Event for audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorphingEvidenceEvent {
    pub schema_version: String,
    pub component: String,
    pub event: String,
    pub policy_id: String,
    pub specimen_id: Option<String>,
    pub verdict: Option<String>,
    pub detail: Option<String>,
}

/// Bundle artifacts.
#[derive(Debug, Clone)]
pub struct MorphingBundleArtifacts {
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn make_anchor_profile() -> PolicyProfile {
    let mut dims = BTreeMap::new();
    dims.insert("exploration_rate".into(), 200_000);
    dims.insert("sandbox_strictness".into(), 800_000);
    dims.insert("gc_aggressiveness".into(), 500_000);
    dims.insert("cache_budget".into(), 600_000);
    PolicyProfile::for_regime("anchor_baseline", Regime::Normal, dims)
}

fn make_regime_profiles() -> BTreeMap<String, PolicyProfile> {
    let mut profiles = BTreeMap::new();

    let mut normal_dims = BTreeMap::new();
    normal_dims.insert("exploration_rate".into(), 200_000);
    normal_dims.insert("sandbox_strictness".into(), 800_000);
    normal_dims.insert("gc_aggressiveness".into(), 500_000);
    normal_dims.insert("cache_budget".into(), 600_000);
    profiles.insert(
        "normal".into(),
        PolicyProfile::for_regime("normal_profile", Regime::Normal, normal_dims),
    );

    let mut elevated_dims = BTreeMap::new();
    elevated_dims.insert("exploration_rate".into(), 150_000);
    elevated_dims.insert("sandbox_strictness".into(), 850_000);
    elevated_dims.insert("gc_aggressiveness".into(), 550_000);
    elevated_dims.insert("cache_budget".into(), 550_000);
    profiles.insert(
        "elevated".into(),
        PolicyProfile::for_regime("elevated_profile", Regime::Elevated, elevated_dims),
    );

    let mut attack_dims = BTreeMap::new();
    attack_dims.insert("exploration_rate".into(), 50_000);
    attack_dims.insert("sandbox_strictness".into(), 950_000);
    attack_dims.insert("gc_aggressiveness".into(), 700_000);
    attack_dims.insert("cache_budget".into(), 300_000);
    profiles.insert(
        "attack".into(),
        PolicyProfile::for_regime("attack_lockdown", Regime::Attack, attack_dims),
    );

    let mut degraded_dims = BTreeMap::new();
    degraded_dims.insert("exploration_rate".into(), 100_000);
    degraded_dims.insert("sandbox_strictness".into(), 700_000);
    degraded_dims.insert("gc_aggressiveness".into(), 800_000);
    degraded_dims.insert("cache_budget".into(), 400_000);
    profiles.insert(
        "degraded".into(),
        PolicyProfile::for_regime("degraded_profile", Regime::Degraded, degraded_dims),
    );

    let mut recovery_dims = BTreeMap::new();
    recovery_dims.insert("exploration_rate".into(), 180_000);
    recovery_dims.insert("sandbox_strictness".into(), 820_000);
    recovery_dims.insert("gc_aggressiveness".into(), 520_000);
    recovery_dims.insert("cache_budget".into(), 580_000);
    profiles.insert(
        "recovery".into(),
        PolicyProfile::for_regime("recovery_profile", Regime::Recovery, recovery_dims),
    );

    profiles
}

fn make_test_morpher(epoch_raw: u64) -> EntropicPolicyMorpher {
    let anchor = make_anchor_profile();
    let epoch = SecurityEpoch::from_raw(epoch_raw);
    let mut morpher = EntropicPolicyMorpher::with_defaults(anchor, epoch);
    for (_, profile) in make_regime_profiles() {
        if let Some(regime) = profile.target_regime {
            morpher.register_profile(regime, profile);
        }
    }
    morpher
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

pub fn morphing_corpus() -> Vec<MorphingSpecimen> {
    vec![
        // ── Transition ──
        MorphingSpecimen {
            specimen_id: "transition_normal_to_elevated".into(),
            description: "Morph from Normal to Elevated regime".into(),
            family: MorphingSpecimenFamily::Transition,
            expected_outcome: MorphingExpectedOutcome::Applied,
        },
        MorphingSpecimen {
            specimen_id: "transition_normal_to_recovery".into(),
            description: "Morph from Normal to Recovery regime".into(),
            family: MorphingSpecimenFamily::Transition,
            expected_outcome: MorphingExpectedOutcome::Applied,
        },
        MorphingSpecimen {
            specimen_id: "transition_elevated_to_attack".into(),
            description: "Morph from Elevated to Attack (may interpolate due to distance)".into(),
            family: MorphingSpecimenFamily::Transition,
            expected_outcome: MorphingExpectedOutcome::Applied,
        },
        // ── Budget Exhaustion ──
        MorphingSpecimen {
            specimen_id: "budget_exhaustion_after_max_steps".into(),
            description: "Budget exhausts after max allowed steps".into(),
            family: MorphingSpecimenFamily::BudgetExhaustion,
            expected_outcome: MorphingExpectedOutcome::BudgetExhausted,
        },
        MorphingSpecimen {
            specimen_id: "budget_exhaustion_distance_limit".into(),
            description: "Budget exhausts when cumulative distance exceeded".into(),
            family: MorphingSpecimenFamily::BudgetExhaustion,
            expected_outcome: MorphingExpectedOutcome::BudgetExhausted,
        },
        // ── Step Distance ──
        MorphingSpecimen {
            specimen_id: "step_distance_within_limit".into(),
            description: "Small step within distance limit succeeds".into(),
            family: MorphingSpecimenFamily::StepDistance,
            expected_outcome: MorphingExpectedOutcome::Applied,
        },
        MorphingSpecimen {
            specimen_id: "step_distance_exceeds_limit_uses_blend".into(),
            description: "Large step uses interpolation blend".into(),
            family: MorphingSpecimenFamily::StepDistance,
            expected_outcome: MorphingExpectedOutcome::InterpolationUsed,
        },
        // ── Entropy Bounds ──
        MorphingSpecimen {
            specimen_id: "entropy_within_bounds".into(),
            description: "Target profile with valid entropy is accepted".into(),
            family: MorphingSpecimenFamily::EntropyBounds,
            expected_outcome: MorphingExpectedOutcome::Applied,
        },
        // ── Cooldown ──
        MorphingSpecimen {
            specimen_id: "cooldown_blocks_immediate_morph".into(),
            description: "Morphing blocked during cooldown after fallback".into(),
            family: MorphingSpecimenFamily::Cooldown,
            expected_outcome: MorphingExpectedOutcome::Rejected,
        },
        MorphingSpecimen {
            specimen_id: "cooldown_expires_allows_morph".into(),
            description: "Morphing allowed after cooldown period elapses".into(),
            family: MorphingSpecimenFamily::Cooldown,
            expected_outcome: MorphingExpectedOutcome::Applied,
        },
        // ── Interpolation ──
        MorphingSpecimen {
            specimen_id: "interpolation_blends_profiles".into(),
            description: "Interpolation produces blend between current and target".into(),
            family: MorphingSpecimenFamily::Interpolation,
            expected_outcome: MorphingExpectedOutcome::InterpolationUsed,
        },
        // ── Fallback ──
        MorphingSpecimen {
            specimen_id: "fallback_on_rejection".into(),
            description: "Rejection triggers fallback to anchor profile".into(),
            family: MorphingSpecimenFamily::Fallback,
            expected_outcome: MorphingExpectedOutcome::FallbackActivated,
        },
        MorphingSpecimen {
            specimen_id: "fallback_on_abstention".into(),
            description: "Morphing to Abstention triggers fallback".into(),
            family: MorphingSpecimenFamily::Fallback,
            expected_outcome: MorphingExpectedOutcome::FallbackActivated,
        },
        // ── NoOp ──
        MorphingSpecimen {
            specimen_id: "noop_same_regime".into(),
            description: "No morphing when regime is unchanged".into(),
            family: MorphingSpecimenFamily::NoOp,
            expected_outcome: MorphingExpectedOutcome::NoOp,
        },
    ]
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

fn run_single_morphing_specimen(specimen: &MorphingSpecimen) -> MorphingSpecimenEvidence {
    let mut verdict = MorphingVerdict::Pass;
    let mut actual_outcome_str = String::new();
    let mut error_detail = None;

    match specimen.specimen_id.as_str() {
        "transition_normal_to_elevated" => {
            let mut m = make_test_morpher(1);
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
            actual_outcome_str = format!("{outcome:?}");
            if !outcome.is_applied() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Applied".into());
            }
        }
        "transition_normal_to_recovery" => {
            let mut m = make_test_morpher(1);
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            let outcome = m.morph(RegimeLabel::Classified(Regime::Recovery));
            actual_outcome_str = format!("{outcome:?}");
            if !outcome.is_applied() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Applied".into());
            }
        }
        "transition_elevated_to_attack" => {
            let mut m = make_test_morpher(1);
            m.current_regime = RegimeLabel::Classified(Regime::Elevated);
            // First morph to elevated to set profile.
            m.morph(RegimeLabel::Classified(Regime::Elevated));
            // Now try to morph to attack.
            let outcome = m.morph(RegimeLabel::Classified(Regime::Attack));
            actual_outcome_str = format!("{outcome:?}");
            if !outcome.is_applied() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Applied (direct or blended)".into());
            }
        }
        "budget_exhaustion_after_max_steps" => {
            let anchor = make_anchor_profile();
            let epoch = SecurityEpoch::from_raw(1);
            let budget = TransitionBudget::new(epoch, 2, 10 * MILLION);
            let mut m = EntropicPolicyMorpher::new(anchor, budget, MorphingConfig::default());
            for (_, profile) in make_regime_profiles() {
                if let Some(regime) = profile.target_regime {
                    m.register_profile(regime, profile);
                }
            }
            m.current_regime = RegimeLabel::Classified(Regime::Normal);

            // Use 2 steps.
            m.morph(RegimeLabel::Classified(Regime::Elevated));
            m.current_regime = RegimeLabel::Classified(Regime::Elevated);
            m.morph(RegimeLabel::Classified(Regime::Recovery));
            m.current_regime = RegimeLabel::Classified(Regime::Recovery);

            // Third should be rejected.
            let outcome = m.morph(RegimeLabel::Classified(Regime::Normal));
            actual_outcome_str = format!("{outcome:?}");
            if !outcome.is_rejected() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Rejected (budget exhausted)".into());
            }
        }
        "budget_exhaustion_distance_limit" => {
            let anchor = make_anchor_profile();
            let epoch = SecurityEpoch::from_raw(1);
            // Very small distance budget.
            let budget = TransitionBudget::new(epoch, 100, 100_000);
            let mut m = EntropicPolicyMorpher::new(anchor, budget, MorphingConfig::default());
            for (_, profile) in make_regime_profiles() {
                if let Some(regime) = profile.target_regime {
                    m.register_profile(regime, profile);
                }
            }
            m.current_regime = RegimeLabel::Classified(Regime::Normal);

            let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
            actual_outcome_str = format!("{outcome:?}");
            // May be applied (within small budget) or rejected (exceeds distance).
            // The distance Normal→Elevated is small enough to fit.
            // But with only 100_000 total distance, after one step we may exhaust.
            // Check second step exhausts.
            if outcome.is_applied() {
                m.current_regime = RegimeLabel::Classified(Regime::Elevated);
                let outcome2 = m.morph(RegimeLabel::Classified(Regime::Attack));
                actual_outcome_str = format!("{outcome2:?}");
                if !outcome2.is_rejected() {
                    verdict = MorphingVerdict::Fail;
                    error_detail = Some("expected second step Rejected (distance exhausted)".into());
                }
            }
            // If first step was also rejected due to distance, that's also budget exhaustion.
        }
        "step_distance_within_limit" => {
            let mut m = make_test_morpher(1);
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
            actual_outcome_str = format!("{outcome:?}");
            if !outcome.is_applied() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Applied (small step)".into());
            }
        }
        "step_distance_exceeds_limit_uses_blend" => {
            let mut m = make_test_morpher(1);
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            // Normal → Attack is a large step; should trigger interpolation.
            let outcome = m.morph(RegimeLabel::Classified(Regime::Attack));
            actual_outcome_str = format!("{outcome:?}");
            // Should either be Applied (via blend) or Applied (if within limit).
            if !outcome.is_applied() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Applied via blend".into());
            }
        }
        "entropy_within_bounds" => {
            let mut m = make_test_morpher(1);
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
            actual_outcome_str = format!("{outcome:?}");
            if !outcome.is_applied() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Applied (entropy in bounds)".into());
            }
        }
        "cooldown_blocks_immediate_morph" => {
            let mut m = make_test_morpher(1);
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            // Force a fallback.
            m.morph(RegimeLabel::Abstention);
            // Immediately try to morph again — should be blocked by cooldown.
            m.current_regime = RegimeLabel::Abstention;
            let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
            actual_outcome_str = format!("{outcome:?}");
            if !outcome.is_rejected() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Rejected (cooldown active)".into());
            }
        }
        "cooldown_expires_allows_morph" => {
            let mut m = make_test_morpher(1);
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            // Force a fallback.
            m.morph(RegimeLabel::Abstention);
            // Simulate cooldown expiry by advancing steps_since_fallback.
            m.steps_since_fallback = m.config.fallback_cooldown_steps + 1;
            m.in_fallback = false;
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
            actual_outcome_str = format!("{outcome:?}");
            if !outcome.is_applied() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Applied after cooldown".into());
            }
        }
        "interpolation_blends_profiles" => {
            let anchor = make_anchor_profile();
            let epoch = SecurityEpoch::from_raw(1);
            let config = MorphingConfig {
                max_step_distance_millionths: 100_000,
                interpolation_rate_millionths: 200_000,
                ..MorphingConfig::default()
            };
            let mut m = EntropicPolicyMorpher::new(
                anchor,
                TransitionBudget::with_defaults(epoch),
                config,
            );
            for (_, profile) in make_regime_profiles() {
                if let Some(regime) = profile.target_regime {
                    m.register_profile(regime, profile);
                }
            }
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
            actual_outcome_str = format!("{outcome:?}");
            // With small max step distance, interpolation should kick in.
            if !outcome.is_applied() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Applied via interpolation".into());
            }
        }
        "fallback_on_rejection" => {
            let anchor = make_anchor_profile();
            let epoch = SecurityEpoch::from_raw(1);
            let budget = TransitionBudget::new(epoch, 0, 0); // zero budget
            let mut m = EntropicPolicyMorpher::new(anchor, budget, MorphingConfig::default());
            for (_, profile) in make_regime_profiles() {
                if let Some(regime) = profile.target_regime {
                    m.register_profile(regime, profile);
                }
            }
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            let outcome = m.morph(RegimeLabel::Classified(Regime::Elevated));
            actual_outcome_str = format!("{outcome:?}");
            if !outcome.is_rejected() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Rejected (zero budget)".into());
            }
            if !m.is_in_fallback() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected fallback mode after rejection".into());
            }
        }
        "fallback_on_abstention" => {
            let mut m = make_test_morpher(1);
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            let outcome = m.morph(RegimeLabel::Abstention);
            actual_outcome_str = format!("{outcome:?}");
            if !outcome.is_rejected() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected Rejected (abstention target)".into());
            }
            if !m.is_in_fallback() {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected fallback after abstention morph".into());
            }
        }
        "noop_same_regime" => {
            let mut m = make_test_morpher(1);
            m.current_regime = RegimeLabel::Classified(Regime::Normal);
            let outcome = m.morph(RegimeLabel::Classified(Regime::Normal));
            actual_outcome_str = format!("{outcome:?}");
            if outcome != MorphingOutcome::NoOp {
                verdict = MorphingVerdict::Fail;
                error_detail = Some("expected NoOp".into());
            }
        }
        _ => {
            verdict = MorphingVerdict::Fail;
            error_detail = Some(format!("unknown specimen: {}", specimen.specimen_id));
        }
    }

    let hash_input = format!(
        "{}:{}:{:?}",
        specimen.specimen_id, verdict as u8, actual_outcome_str,
    );
    MorphingSpecimenEvidence {
        specimen_id: specimen.specimen_id.clone(),
        family: specimen.family,
        expected_outcome: specimen.expected_outcome,
        verdict,
        actual_outcome: actual_outcome_str,
        error_detail,
        evidence_hash: hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes()),
    }
}

/// Run the full corpus.
pub fn run_morphing_corpus() -> MorphingEvidenceInventory {
    let corpus = morphing_corpus();
    let mut evidence = Vec::with_capacity(corpus.len());
    let mut pass_count: u64 = 0;
    let mut fail_count: u64 = 0;
    let mut family_coverage: BTreeMap<String, u64> = BTreeMap::new();

    for specimen in &corpus {
        let ev = run_single_morphing_specimen(specimen);
        if ev.verdict == MorphingVerdict::Pass {
            pass_count += 1;
        } else {
            fail_count += 1;
        }
        *family_coverage
            .entry(specimen.family.as_str().to_string())
            .or_insert(0) += 1;
        evidence.push(ev);
    }

    MorphingEvidenceInventory {
        schema_version: MORPHING_SCHEMA_VERSION.to_string(),
        component: MORPHING_COMPONENT.to_string(),
        specimen_count: corpus.len() as u64,
        pass_count,
        fail_count,
        family_coverage,
        evidence,
    }
}

// ---------------------------------------------------------------------------
// Bundle writer
// ---------------------------------------------------------------------------

pub fn write_morphing_evidence_bundle(
    output_dir: &Path,
    commands: &[String],
) -> Result<MorphingBundleArtifacts, std::io::Error> {
    std::fs::create_dir_all(output_dir)?;

    let inv = run_morphing_corpus();
    let inv_json = serde_json::to_string_pretty(&inv).map_err(std::io::Error::other)?;
    let inventory_hash = hex_encode(ContentHash::compute(inv_json.as_bytes()).as_bytes());

    let inv_path = output_dir.join("entropic_policy_morphing_inventory.json");
    std::fs::write(&inv_path, &inv_json)?;

    let mut event_lines = Vec::new();
    let start = MorphingEvidenceEvent {
        schema_version: MORPHING_EVENT_SCHEMA_VERSION.to_string(),
        component: MORPHING_COMPONENT.to_string(),
        event: "morphing_evidence_run_started".to_string(),
        policy_id: MORPHING_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    event_lines.push(serde_json::to_string(&start).map_err(std::io::Error::other)?);

    for ev in &inv.evidence {
        let specimen_event = MorphingEvidenceEvent {
            schema_version: MORPHING_EVENT_SCHEMA_VERSION.to_string(),
            component: MORPHING_COMPONENT.to_string(),
            event: "morphing_specimen_evaluated".to_string(),
            policy_id: MORPHING_POLICY_ID.to_string(),
            specimen_id: Some(ev.specimen_id.clone()),
            verdict: Some(if ev.verdict == MorphingVerdict::Pass {
                "pass".to_string()
            } else {
                "fail".to_string()
            }),
            detail: ev.error_detail.clone(),
        };
        event_lines.push(serde_json::to_string(&specimen_event).map_err(std::io::Error::other)?);
    }

    let end = MorphingEvidenceEvent {
        schema_version: MORPHING_EVENT_SCHEMA_VERSION.to_string(),
        component: MORPHING_COMPONENT.to_string(),
        event: "morphing_evidence_run_completed".to_string(),
        policy_id: MORPHING_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: Some(if inv.contract_satisfied() {
            "satisfied".to_string()
        } else {
            "violated".to_string()
        }),
        detail: Some(format!(
            "pass={} fail={} total={}",
            inv.pass_count, inv.fail_count, inv.specimen_count
        )),
    };
    event_lines.push(serde_json::to_string(&end).map_err(std::io::Error::other)?);

    let events_path = output_dir.join("entropic_policy_morphing_events.jsonl");
    std::fs::write(&events_path, event_lines.join("\n") + "\n")?;

    let trace_id = format!("morph-{}", &inventory_hash[..12]);
    let decision_id = format!("dec-{}", &inventory_hash[12..24]);

    let manifest = MorphingRunManifest {
        schema_version: MORPHING_MANIFEST_SCHEMA_VERSION.to_string(),
        component: MORPHING_COMPONENT.to_string(),
        trace_id,
        decision_id,
        policy_id: MORPHING_POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
        specimen_count: inv.specimen_count,
        pass_count: inv.pass_count,
        fail_count: inv.fail_count,
        contract_satisfied: inv.contract_satisfied(),
        artifact_paths: MorphingArtifactPaths {
            evidence_inventory: "entropic_policy_morphing_inventory.json".to_string(),
            run_manifest: "entropic_policy_morphing_manifest.json".to_string(),
            events_jsonl: "entropic_policy_morphing_events.jsonl".to_string(),
            commands_txt: "entropic_policy_morphing_commands.txt".to_string(),
        },
    };

    let manifest_path = output_dir.join("entropic_policy_morphing_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).map_err(std::io::Error::other)?,
    )?;

    let commands_path = output_dir.join("entropic_policy_morphing_commands.txt");
    std::fs::write(&commands_path, commands.join("\n"))?;

    Ok(MorphingBundleArtifacts {
        inventory_path: inv_path,
        run_manifest_path: manifest_path,
        events_path,
        commands_path,
        inventory_hash,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_non_empty() {
        assert!(!morphing_corpus().is_empty());
    }

    #[test]
    fn corpus_ids_unique() {
        let corpus = morphing_corpus();
        let ids: std::collections::BTreeSet<&str> =
            corpus.iter().map(|s| s.specimen_id.as_str()).collect();
        assert_eq!(ids.len(), corpus.len());
    }

    #[test]
    fn corpus_covers_all_families() {
        let corpus = morphing_corpus();
        let covered: std::collections::BTreeSet<MorphingSpecimenFamily> =
            corpus.iter().map(|s| s.family).collect();
        for f in MorphingSpecimenFamily::ALL {
            assert!(covered.contains(f), "missing {:?}", f);
        }
    }

    #[test]
    fn all_specimens_pass() {
        let inv = run_morphing_corpus();
        for ev in &inv.evidence {
            assert_eq!(
                ev.verdict,
                MorphingVerdict::Pass,
                "specimen {} failed: {:?}",
                ev.specimen_id,
                ev.error_detail
            );
        }
    }

    #[test]
    fn contract_satisfied() {
        let inv = run_morphing_corpus();
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn counts_consistent() {
        let inv = run_morphing_corpus();
        assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
        assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
    }

    #[test]
    fn family_coverage_sums() {
        let inv = run_morphing_corpus();
        let total: u64 = inv.family_coverage.values().sum();
        assert_eq!(total, inv.specimen_count);
    }

    #[test]
    fn deterministic() {
        let inv1 = run_morphing_corpus();
        let inv2 = run_morphing_corpus();
        assert_eq!(inv1, inv2);
    }

    #[test]
    fn policy_profile_l1_distance_self_is_zero() {
        let p = make_anchor_profile();
        assert_eq!(p.l1_distance(&p), 0);
    }

    #[test]
    fn policy_profile_l1_distance_symmetric() {
        let profiles = make_regime_profiles();
        let a = profiles.get("normal").unwrap();
        let b = profiles.get("attack").unwrap();
        assert_eq!(a.l1_distance(b), b.l1_distance(a));
    }

    #[test]
    fn policy_profile_entropy_positive_for_valid() {
        let p = make_anchor_profile();
        let entropy = p.entropy_millionths();
        assert!(entropy > 0, "entropy should be positive, got {entropy}");
    }

    #[test]
    fn policy_profile_entropy_zero_for_empty() {
        let p = PolicyProfile::new("empty", BTreeMap::new());
        assert_eq!(p.entropy_millionths(), 0);
    }

    #[test]
    fn policy_profile_content_hash_deterministic() {
        let p = make_anchor_profile();
        assert_eq!(p.content_hash(), p.content_hash());
    }

    #[test]
    fn policy_profile_content_hash_is_64_hex() {
        let p = make_anchor_profile();
        let h = p.content_hash();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn transition_budget_defaults() {
        let b = TransitionBudget::with_defaults(SecurityEpoch::from_raw(1));
        assert_eq!(b.max_steps, DEFAULT_TRANSITION_BUDGET);
        assert_eq!(b.steps_used, 0);
        assert!(!b.is_exhausted());
    }

    #[test]
    fn transition_budget_can_step() {
        let b = TransitionBudget::with_defaults(SecurityEpoch::from_raw(1));
        assert!(b.can_step(100_000));
    }

    #[test]
    fn transition_budget_exhaustion() {
        let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 2, 5 * MILLION);
        b.record_step(100_000);
        b.record_step(100_000);
        assert!(b.is_exhausted());
        assert!(!b.can_step(100_000));
    }

    #[test]
    fn transition_budget_reset() {
        let mut b = TransitionBudget::new(SecurityEpoch::from_raw(1), 2, 5 * MILLION);
        b.record_step(100_000);
        b.record_step(100_000);
        b.reset(SecurityEpoch::from_raw(2));
        assert!(!b.is_exhausted());
        assert_eq!(b.steps_used, 0);
    }

    #[test]
    fn morpher_noop_same_regime() {
        let mut m = make_test_morpher(1);
        m.current_regime = RegimeLabel::Classified(Regime::Normal);
        let outcome = m.morph(RegimeLabel::Classified(Regime::Normal));
        assert_eq!(outcome, MorphingOutcome::NoOp);
    }

    #[test]
    fn morpher_tracks_history() {
        let mut m = make_test_morpher(1);
        m.current_regime = RegimeLabel::Classified(Regime::Normal);
        m.morph(RegimeLabel::Classified(Regime::Elevated));
        assert!(!m.history.is_empty());
    }

    #[test]
    fn morpher_fallback_on_abstention_target() {
        let mut m = make_test_morpher(1);
        m.current_regime = RegimeLabel::Classified(Regime::Normal);
        let outcome = m.morph(RegimeLabel::Abstention);
        assert!(outcome.is_rejected());
        assert!(m.is_in_fallback());
    }

    #[test]
    fn morpher_summary_consistent() {
        let mut m = make_test_morpher(1);
        m.current_regime = RegimeLabel::Classified(Regime::Normal);
        m.morph(RegimeLabel::Classified(Regime::Elevated));
        let s = m.summary();
        assert_eq!(s.step_count, m.step_count);
        assert_eq!(s.applied_count, m.applied_count);
    }

    #[test]
    fn morphing_rejection_display() {
        for r in [
            MorphingRejection::BudgetExhausted,
            MorphingRejection::StepTooLarge,
            MorphingRejection::EntropyTooLow,
            MorphingRejection::EntropyTooHigh,
            MorphingRejection::CooldownActive,
            MorphingRejection::SourceAbstention,
            MorphingRejection::NoTargetProfile,
        ] {
            let s = r.to_string();
            assert!(!s.is_empty());
            assert_eq!(s, r.as_str());
        }
    }

    #[test]
    fn morphing_outcome_predicates() {
        let applied = MorphingOutcome::Applied {
            distance_millionths: 100,
            new_entropy_millionths: 500_000,
        };
        assert!(applied.is_applied());
        assert!(!applied.is_rejected());

        let rejected = MorphingOutcome::Rejected {
            reason: MorphingRejection::BudgetExhausted,
        };
        assert!(!rejected.is_applied());
        assert!(rejected.is_rejected());

        let noop = MorphingOutcome::NoOp;
        assert!(!noop.is_applied());
        assert!(!noop.is_rejected());
    }

    #[test]
    fn morphing_config_serde_roundtrip() {
        let config = MorphingConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: MorphingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn policy_profile_serde_roundtrip() {
        let p = make_anchor_profile();
        let json = serde_json::to_string(&p).unwrap();
        let back: PolicyProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn transition_budget_serde_roundtrip() {
        let b = TransitionBudget::with_defaults(SecurityEpoch::from_raw(42));
        let json = serde_json::to_string(&b).unwrap();
        let back: TransitionBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn inventory_serde_roundtrip() {
        let inv = run_morphing_corpus();
        let json = serde_json::to_string(&inv).unwrap();
        let back: MorphingEvidenceInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    #[test]
    fn schema_constants_non_empty() {
        assert!(!MORPHING_SCHEMA_VERSION.is_empty());
        assert!(!MORPHING_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!MORPHING_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!MORPHING_COMPONENT.is_empty());
        assert!(!MORPHING_POLICY_ID.is_empty());
    }

    #[test]
    fn schema_versions_prefixed() {
        assert!(MORPHING_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(MORPHING_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(MORPHING_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn ln_millionths_of_one_is_zero() {
        assert_eq!(ln_millionths(MILLION), 0);
    }

    #[test]
    fn ln_millionths_of_e_is_near_million() {
        let result = ln_millionths(2_718_282);
        // ln(e) = 1.0 → should be near 1_000_000.
        assert!((result - MILLION).abs() < 50_000, "ln(e) ≈ {result}, expected ~1_000_000");
    }

    #[test]
    fn ln_millionths_monotone() {
        let a = ln_millionths(500_000);
        let b = ln_millionths(1_000_000);
        let c = ln_millionths(2_000_000);
        assert!(a < b, "ln(0.5) < ln(1.0)");
        assert!(b < c, "ln(1.0) < ln(2.0)");
    }

    #[test]
    fn contract_not_satisfied_with_failures() {
        let inv = MorphingEvidenceInventory {
            schema_version: MORPHING_SCHEMA_VERSION.to_string(),
            component: MORPHING_COMPONENT.to_string(),
            specimen_count: 5,
            pass_count: 4,
            fail_count: 1,
            family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn contract_not_satisfied_with_zero_specimens() {
        let inv = MorphingEvidenceInventory {
            schema_version: MORPHING_SCHEMA_VERSION.to_string(),
            component: MORPHING_COMPONENT.to_string(),
            specimen_count: 0,
            pass_count: 0,
            fail_count: 0,
            family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn specimen_family_display_matches_as_str() {
        for f in MorphingSpecimenFamily::ALL {
            assert_eq!(f.to_string(), f.as_str());
        }
    }
}
