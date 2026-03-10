//! Tier-eligibility substrate for profiling and deopt/probe infrastructure.
//!
//! Implements [RGC-310B]: real tier-eligibility evaluation, profiling data
//! collection, deoptimization tracking, and probe instrumentation for the
//! FrankenEngine JIT pipeline. Works alongside `tier_up_profiler` to
//! provide the substrate layer that captures fine-grained execution
//! characteristics and drives tier-transition decisions.
//!
//! # Design
//!
//! Functions progress through execution tiers (Interpreted -> Baseline ->
//! Optimized -> Specialized) based on profile data collected via probes.
//! Each tier transition requires meeting policy thresholds for invocation
//! count, feedback stability, and deopt cooldown. Deoptimization events
//! push functions back down and impose cooldown periods.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-310B], bead bd-1lsy.4.11.2

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for tier-eligibility substrate artifacts.
pub const TIER_ELIGIBILITY_SCHEMA_VERSION: &str = "franken-engine.tier-eligibility-substrate.v1";

/// Bead reference.
pub const TIER_ELIGIBILITY_BEAD_ID: &str = "bd-1lsy.4.11.2";

/// Policy reference.
pub const TIER_ELIGIBILITY_POLICY_ID: &str = "RGC-310B";

/// Component name for logging/tracing.
pub const COMPONENT: &str = "tier_eligibility_substrate";

/// Fixed-point denominator: 1_000_000 = 1.0.
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// ExecutionTier
// ---------------------------------------------------------------------------

/// The execution tier a function currently resides in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTier {
    /// Interpreted execution (slowest, no compilation).
    Interpreted,
    /// Baseline-compiled (fast compilation, minimal optimization).
    Baseline,
    /// Optimized compilation (significant optimization passes).
    Optimized,
    /// Specialized compilation (type-specialized, maximal optimization).
    Specialized,
    /// Deoptimized: fell back from a higher tier due to speculation failure.
    Deoptimized,
}

impl fmt::Display for ExecutionTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interpreted => write!(f, "interpreted"),
            Self::Baseline => write!(f, "baseline"),
            Self::Optimized => write!(f, "optimized"),
            Self::Specialized => write!(f, "specialized"),
            Self::Deoptimized => write!(f, "deoptimized"),
        }
    }
}

/// Return a numeric rank for tier ordering.
///
/// Higher rank means a more aggressively compiled tier.
/// `Deoptimized` ranks below `Interpreted` since it indicates regression.
pub fn tier_rank(tier: ExecutionTier) -> u32 {
    match tier {
        ExecutionTier::Deoptimized => 0,
        ExecutionTier::Interpreted => 1,
        ExecutionTier::Baseline => 2,
        ExecutionTier::Optimized => 3,
        ExecutionTier::Specialized => 4,
    }
}

// ---------------------------------------------------------------------------
// TierTransitionReason
// ---------------------------------------------------------------------------

/// Reason for a tier transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierTransitionReason {
    /// A hot loop was detected via iteration counting.
    HotLoopDetected,
    /// Invocation/execution count reached the policy threshold.
    ProfileThresholdReached,
    /// Inline cache settled to monomorphic state.
    InlineCacheMonomorphic,
    /// Type feedback has been stable across enough samples.
    TypeFeedbackStable,
    /// A deoptimization bailout forced tier regression.
    DeoptBailout,
    /// A policy override forced the transition.
    PolicyOverride,
    /// A manual probe/diagnostic triggered the transition.
    ManualProbe,
}

impl fmt::Display for TierTransitionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HotLoopDetected => write!(f, "hot_loop_detected"),
            Self::ProfileThresholdReached => write!(f, "profile_threshold_reached"),
            Self::InlineCacheMonomorphic => write!(f, "inline_cache_monomorphic"),
            Self::TypeFeedbackStable => write!(f, "type_feedback_stable"),
            Self::DeoptBailout => write!(f, "deopt_bailout"),
            Self::PolicyOverride => write!(f, "policy_override"),
            Self::ManualProbe => write!(f, "manual_probe"),
        }
    }
}

// ---------------------------------------------------------------------------
// DeoptReason
// ---------------------------------------------------------------------------

/// Reason for a deoptimization event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeoptReason {
    /// A type guard failed (observed type differs from speculated type).
    TypeMismatch,
    /// An object map/shape transition invalidated compiled code.
    MapTransition,
    /// An arithmetic overflow check triggered.
    OverflowCheck,
    /// An array bounds check triggered.
    BoundsCheck,
    /// An inline cache became megamorphic/unstable.
    UnstableInlineCache,
    /// Insufficient type feedback to maintain optimization.
    MissingFeedback,
    /// A policy rule rejected the optimized code.
    PolicyRejection,
}

impl fmt::Display for DeoptReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeMismatch => write!(f, "type_mismatch"),
            Self::MapTransition => write!(f, "map_transition"),
            Self::OverflowCheck => write!(f, "overflow_check"),
            Self::BoundsCheck => write!(f, "bounds_check"),
            Self::UnstableInlineCache => write!(f, "unstable_inline_cache"),
            Self::MissingFeedback => write!(f, "missing_feedback"),
            Self::PolicyRejection => write!(f, "policy_rejection"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProbeKind
// ---------------------------------------------------------------------------

/// Kind of instrumentation probe inserted by the profiling substrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    /// Type profile probe: records observed types at a site.
    TypeProfile,
    /// Allocation site probe: tracks allocation frequency/size.
    AllocationSite,
    /// Branch coverage probe: records branch-taken frequency.
    BranchCoverage,
    /// Call frequency probe: counts call-site invocations.
    CallFrequency,
    /// Inline cache state probe: monitors IC transitions.
    InlineCacheState,
}

impl fmt::Display for ProbeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeProfile => write!(f, "type_profile"),
            Self::AllocationSite => write!(f, "allocation_site"),
            Self::BranchCoverage => write!(f, "branch_coverage"),
            Self::CallFrequency => write!(f, "call_frequency"),
            Self::InlineCacheState => write!(f, "inline_cache_state"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProbeRecord
// ---------------------------------------------------------------------------

/// A single probe measurement record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProbeRecord {
    /// Unique identifier for this probe instance.
    pub probe_id: String,
    /// The kind of probe.
    pub kind: ProbeKind,
    /// Identifier for the instrumentation site (e.g., bytecode offset).
    pub site_id: String,
    /// Number of samples collected by this probe.
    pub sample_count: u64,
    /// Measured value in millionths (interpretation depends on `kind`).
    pub value_millionths: u64,
}

impl ProbeRecord {
    /// Compute the content hash for this probe record.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.probe_id.as_bytes());
        hasher.update(self.kind.to_string().as_bytes());
        hasher.update(self.site_id.as_bytes());
        hasher.update(self.sample_count.to_le_bytes());
        hasher.update(self.value_millionths.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        ContentHash(bytes)
    }
}

impl fmt::Display for ProbeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "probe[{}]:{}@{} samples={} value={}",
            self.probe_id, self.kind, self.site_id, self.sample_count, self.value_millionths
        )
    }
}

// ---------------------------------------------------------------------------
// TierEligibilityPolicy
// ---------------------------------------------------------------------------

/// Policy governing tier-transition eligibility decisions.
///
/// All thresholds use fixed-point millionths where applicable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierEligibilityPolicy {
    /// Policy identifier.
    pub policy_id: String,
    /// Minimum invocation count before a function is eligible to tier up.
    pub min_invocations: u64,
    /// Minimum probe feedback stability (millionths) to consider feedback
    /// stable enough for optimization.
    pub min_feedback_stability_millionths: u64,
    /// Cooldown in epochs after a deopt before the function may re-tier-up.
    pub deopt_cooldown_epochs: u64,
    /// Maximum deopt rate (millionths) permitted for tier-up eligibility.
    pub max_deopt_rate_millionths: u64,
    /// Minimum probe sample count required per probe site.
    pub min_probe_samples: u64,
    /// Maximum number of deopts before permanently pinning to baseline.
    pub max_lifetime_deopts: u64,
    /// Minimum confidence (millionths) for an eligibility verdict.
    pub min_confidence_millionths: u64,
}

impl Default for TierEligibilityPolicy {
    fn default() -> Self {
        Self {
            policy_id: "policy-tier-eligibility-v1".to_string(),
            min_invocations: 100,
            min_feedback_stability_millionths: 800_000, // 80%
            deopt_cooldown_epochs: 3,
            max_deopt_rate_millionths: 50_000, // 5%
            min_probe_samples: 10,
            max_lifetime_deopts: 10,
            min_confidence_millionths: 750_000, // 75%
        }
    }
}

impl TierEligibilityPolicy {
    /// Compute the content hash of this policy.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.policy_id.as_bytes());
        hasher.update(self.min_invocations.to_le_bytes());
        hasher.update(self.min_feedback_stability_millionths.to_le_bytes());
        hasher.update(self.deopt_cooldown_epochs.to_le_bytes());
        hasher.update(self.max_deopt_rate_millionths.to_le_bytes());
        hasher.update(self.min_probe_samples.to_le_bytes());
        hasher.update(self.max_lifetime_deopts.to_le_bytes());
        hasher.update(self.min_confidence_millionths.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        ContentHash(bytes)
    }
}

impl fmt::Display for TierEligibilityPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TierEligibilityPolicy[{}](min_inv={}, stability={}, cooldown={}, max_deopt_rate={})",
            self.policy_id,
            self.min_invocations,
            self.min_feedback_stability_millionths,
            self.deopt_cooldown_epochs,
            self.max_deopt_rate_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// DeoptEvent
// ---------------------------------------------------------------------------

/// A recorded deoptimization event for a function.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeoptEvent {
    /// Unique identifier for this deopt event.
    pub event_id: String,
    /// The reason for deoptimization.
    pub reason: DeoptReason,
    /// The tier the function was at when deopted.
    pub source_tier: ExecutionTier,
    /// The bytecode/IR site that triggered the deopt.
    pub bailout_site: String,
    /// The epoch in which the deopt occurred.
    pub epoch: SecurityEpoch,
    /// Monotonic counter for ordering deopt events.
    pub counter: u64,
}

impl fmt::Display for DeoptEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "deopt[{}]:{}@{} from={} epoch={} counter={}",
            self.event_id,
            self.reason,
            self.bailout_site,
            self.source_tier,
            self.epoch.as_u64(),
            self.counter,
        )
    }
}

// ---------------------------------------------------------------------------
// TierProfile
// ---------------------------------------------------------------------------

/// Profiling data for a single function, aggregating probes and deopt events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierProfile {
    /// Unique identifier for this profile.
    pub profile_id: String,
    /// Identifier for the function being profiled.
    pub function_id: String,
    /// Current execution tier.
    pub current_tier: ExecutionTier,
    /// Total invocation count.
    pub invocation_count: u64,
    /// Total deoptimization count (lifetime).
    pub deopt_count: u64,
    /// Collected probe records.
    pub probes: Vec<ProbeRecord>,
    /// Recorded deoptimization events.
    pub deopt_events: Vec<DeoptEvent>,
    /// Epoch of the last tier transition (or genesis if none).
    pub last_transition_epoch: SecurityEpoch,
    /// Content hash of this profile state.
    pub content_hash: ContentHash,
}

impl TierProfile {
    /// Create a new profile for a function starting at the Interpreted tier.
    pub fn new(profile_id: &str, function_id: &str) -> Self {
        let mut profile = Self {
            profile_id: profile_id.to_string(),
            function_id: function_id.to_string(),
            current_tier: ExecutionTier::Interpreted,
            invocation_count: 0,
            deopt_count: 0,
            probes: Vec::new(),
            deopt_events: Vec::new(),
            last_transition_epoch: SecurityEpoch::GENESIS,
            content_hash: ContentHash::default(),
        };
        profile.rehash();
        profile
    }

    /// Recompute the content hash from current state.
    pub fn rehash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.profile_id.as_bytes());
        hasher.update(self.function_id.as_bytes());
        hasher.update(self.current_tier.to_string().as_bytes());
        hasher.update(self.invocation_count.to_le_bytes());
        hasher.update(self.deopt_count.to_le_bytes());
        hasher.update(self.last_transition_epoch.as_u64().to_le_bytes());
        for probe in &self.probes {
            hasher.update(probe.content_hash().as_bytes());
        }
        for evt in &self.deopt_events {
            hasher.update(evt.event_id.as_bytes());
            hasher.update(evt.counter.to_le_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        self.content_hash = ContentHash(bytes);
    }
}

impl fmt::Display for TierProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TierProfile[{}](fn={}, tier={}, inv={}, deopt={}, probes={})",
            self.profile_id,
            self.function_id,
            self.current_tier,
            self.invocation_count,
            self.deopt_count,
            self.probes.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// TierEligibilityVerdict
// ---------------------------------------------------------------------------

/// The result of evaluating a function's eligibility for tier transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierEligibilityVerdict {
    /// Whether the function is eligible for tier-up.
    pub eligible: bool,
    /// The target tier (the tier the function would move to).
    pub target_tier: ExecutionTier,
    /// Reasons supporting the verdict.
    pub reasons: Vec<TierTransitionReason>,
    /// Summary of probe data considered.
    pub probe_summary: String,
    /// Confidence in this verdict (millionths).
    pub confidence_millionths: u64,
    /// Content hash of the verdict.
    pub content_hash: ContentHash,
}

impl TierEligibilityVerdict {
    /// Create an ineligible verdict with the given target and reason.
    pub fn ineligible(target: ExecutionTier, reason: &str) -> Self {
        let mut verdict = Self {
            eligible: false,
            target_tier: target,
            reasons: Vec::new(),
            probe_summary: reason.to_string(),
            confidence_millionths: MILLIONTHS,
            content_hash: ContentHash::default(),
        };
        verdict.rehash();
        verdict
    }

    /// Recompute content hash.
    fn rehash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(if self.eligible { b"1" } else { b"0" });
        hasher.update(self.target_tier.to_string().as_bytes());
        for r in &self.reasons {
            hasher.update(r.to_string().as_bytes());
        }
        hasher.update(self.probe_summary.as_bytes());
        hasher.update(self.confidence_millionths.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        self.content_hash = ContentHash(bytes);
    }
}

impl fmt::Display for TierEligibilityVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TierEligibilityVerdict(eligible={}, target={}, confidence={}, reasons={})",
            self.eligible,
            self.target_tier,
            self.confidence_millionths,
            self.reasons.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// TierEligibilityReport
// ---------------------------------------------------------------------------

/// Batch report covering eligibility evaluation for multiple functions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierEligibilityReport {
    /// Unique report identifier.
    pub report_id: String,
    /// The epoch this report was generated in.
    pub epoch: SecurityEpoch,
    /// Profiles that were evaluated.
    pub profiles: Vec<TierProfile>,
    /// Verdicts for each profile.
    pub verdicts: Vec<TierEligibilityVerdict>,
    /// Total number of functions evaluated.
    pub total_functions: usize,
    /// Number of functions deemed eligible for tier-up.
    pub eligible_count: usize,
    /// Aggregate deopt rate across all evaluated functions (millionths).
    pub deopt_rate_millionths: u64,
    /// Content hash of the report.
    pub content_hash: ContentHash,
}

impl TierEligibilityReport {
    /// Recompute content hash from current state.
    pub fn rehash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.report_id.as_bytes());
        hasher.update(self.epoch.as_u64().to_le_bytes());
        hasher.update((self.total_functions as u64).to_le_bytes());
        hasher.update((self.eligible_count as u64).to_le_bytes());
        hasher.update(self.deopt_rate_millionths.to_le_bytes());
        for p in &self.profiles {
            hasher.update(p.content_hash.as_bytes());
        }
        for v in &self.verdicts {
            hasher.update(v.content_hash.as_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        self.content_hash = ContentHash(bytes);
    }
}

impl fmt::Display for TierEligibilityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TierEligibilityReport[{}](epoch={}, total={}, eligible={}, deopt_rate={})",
            self.report_id,
            self.epoch.as_u64(),
            self.total_functions,
            self.eligible_count,
            self.deopt_rate_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// Core Functions
// ---------------------------------------------------------------------------

/// Compute the deopt rate for a profile in millionths.
///
/// Returns `deopt_count * MILLIONTHS / invocation_count`, or 0 if no
/// invocations have occurred.
pub fn compute_deopt_rate(profile: &TierProfile) -> u64 {
    if profile.invocation_count == 0 {
        return 0;
    }
    profile
        .deopt_count
        .saturating_mul(MILLIONTHS)
        .checked_div(profile.invocation_count)
        .unwrap_or(0)
}

/// Check whether probe feedback is stable enough for optimization.
///
/// Stability is measured as the fraction of probes that have collected
/// at least `min_probe_samples` samples. Returns true if that fraction
/// (in millionths) meets or exceeds `stability_threshold`.
pub fn is_feedback_stable(profile: &TierProfile, stability_threshold: u64) -> bool {
    if profile.probes.is_empty() {
        // No probes means no feedback; not stable.
        return false;
    }
    let sufficient_count = profile
        .probes
        .iter()
        .filter(|p| p.sample_count >= 10)
        .count() as u64;
    let total = profile.probes.len() as u64;
    let stability_millionths = sufficient_count
        .saturating_mul(MILLIONTHS)
        .checked_div(total)
        .unwrap_or(0);
    stability_millionths >= stability_threshold
}

/// Check whether a deopt cooldown is currently active for the given profile.
///
/// Returns `true` if any deopt event occurred within `cooldown_epochs` of
/// the current epoch, preventing re-optimization.
pub fn cooldown_active(
    profile: &TierProfile,
    cooldown_epochs: u64,
    current_epoch: &SecurityEpoch,
) -> bool {
    for evt in &profile.deopt_events {
        let evt_epoch = evt.epoch.as_u64();
        let cur = current_epoch.as_u64();
        if cur.saturating_sub(evt_epoch) < cooldown_epochs {
            return true;
        }
    }
    false
}

/// Determine the next tier up from the current tier.
///
/// Returns the next higher tier, or `None` if the function is already at
/// the highest tier or is in Deoptimized state (which goes to Interpreted).
fn next_tier_up(tier: ExecutionTier) -> Option<ExecutionTier> {
    match tier {
        ExecutionTier::Deoptimized => Some(ExecutionTier::Interpreted),
        ExecutionTier::Interpreted => Some(ExecutionTier::Baseline),
        ExecutionTier::Baseline => Some(ExecutionTier::Optimized),
        ExecutionTier::Optimized => Some(ExecutionTier::Specialized),
        ExecutionTier::Specialized => None, // already at top
    }
}

/// Evaluate whether a function should tier up based on its profile and policy.
pub fn evaluate_eligibility(
    profile: &TierProfile,
    policy: &TierEligibilityPolicy,
) -> TierEligibilityVerdict {
    let target = match next_tier_up(profile.current_tier) {
        Some(t) => t,
        None => {
            return TierEligibilityVerdict::ineligible(
                profile.current_tier,
                "already at highest tier",
            );
        }
    };

    let mut reasons = Vec::new();
    let mut rejection_reasons = Vec::new();

    // Check 1: minimum invocations
    if profile.invocation_count < policy.min_invocations {
        rejection_reasons.push(format!(
            "invocations {} < {}",
            profile.invocation_count, policy.min_invocations
        ));
    } else {
        reasons.push(TierTransitionReason::ProfileThresholdReached);
    }

    // Check 2: deopt rate
    let deopt_rate = compute_deopt_rate(profile);
    if deopt_rate > policy.max_deopt_rate_millionths {
        rejection_reasons.push(format!(
            "deopt_rate {} > {}",
            deopt_rate, policy.max_deopt_rate_millionths
        ));
    }

    // Check 3: lifetime deopts
    if profile.deopt_count > policy.max_lifetime_deopts {
        rejection_reasons.push(format!(
            "lifetime_deopts {} > {}",
            profile.deopt_count, policy.max_lifetime_deopts
        ));
    }

    // Check 4: feedback stability (only for tiers above Baseline)
    if tier_rank(target) >= tier_rank(ExecutionTier::Optimized) {
        if is_feedback_stable(profile, policy.min_feedback_stability_millionths) {
            reasons.push(TierTransitionReason::TypeFeedbackStable);
        } else {
            rejection_reasons.push("feedback not stable".to_string());
        }
    }

    // Check 5: cooldown (use last_transition_epoch as current reference)
    // We check against the profile's own last_transition_epoch as a proxy.
    if cooldown_active(
        profile,
        policy.deopt_cooldown_epochs,
        &profile.last_transition_epoch,
    ) {
        rejection_reasons.push("deopt cooldown active".to_string());
    }

    let eligible = rejection_reasons.is_empty() && !reasons.is_empty();

    // Compute confidence based on evidence strength.
    let confidence = if eligible {
        compute_confidence(profile, policy)
    } else {
        0
    };

    let probe_summary = if rejection_reasons.is_empty() {
        format!(
            "eligible: {} reasons, {} probes, inv={}",
            reasons.len(),
            profile.probes.len(),
            profile.invocation_count
        )
    } else {
        format!("rejected: {}", rejection_reasons.join("; "))
    };

    let mut verdict = TierEligibilityVerdict {
        eligible,
        target_tier: target,
        reasons,
        probe_summary,
        confidence_millionths: confidence,
        content_hash: ContentHash::default(),
    };
    verdict.rehash();
    verdict
}

/// Compute confidence (millionths) for a tier-up decision.
fn compute_confidence(profile: &TierProfile, policy: &TierEligibilityPolicy) -> u64 {
    // Confidence is the geometric mean (approximated) of several factors:
    //   1. Invocation saturation: min(inv / (2 * min_inv), 1.0)
    //   2. Feedback quality: fraction of probes with sufficient samples
    //   3. Deopt margin: 1.0 - (deopt_rate / max_deopt_rate)
    // Each factor is clamped to [0, MILLIONTHS].

    let inv_factor = {
        let threshold = policy.min_invocations.saturating_mul(2);
        if threshold == 0 {
            MILLIONTHS
        } else {
            let ratio = profile
                .invocation_count
                .saturating_mul(MILLIONTHS)
                .checked_div(threshold)
                .unwrap_or(0);
            ratio.min(MILLIONTHS)
        }
    };

    let feedback_factor = if profile.probes.is_empty() {
        MILLIONTHS / 2 // partial confidence without probes
    } else {
        let sufficient = profile
            .probes
            .iter()
            .filter(|p| p.sample_count >= policy.min_probe_samples)
            .count() as u64;
        let total = profile.probes.len() as u64;
        sufficient
            .saturating_mul(MILLIONTHS)
            .checked_div(total)
            .unwrap_or(0)
    };

    let deopt_factor = if policy.max_deopt_rate_millionths == 0 {
        if profile.deopt_count == 0 {
            MILLIONTHS
        } else {
            0
        }
    } else {
        let rate = compute_deopt_rate(profile);
        let used = rate
            .saturating_mul(MILLIONTHS)
            .checked_div(policy.max_deopt_rate_millionths)
            .unwrap_or(0);
        MILLIONTHS.saturating_sub(used.min(MILLIONTHS))
    };

    // Average of the three factors.
    let sum = inv_factor
        .saturating_add(feedback_factor)
        .saturating_add(deopt_factor);
    sum.checked_div(3).unwrap_or(0)
}

/// Record a deoptimization event on a profile.
///
/// Increments the deopt counter, pushes the event, transitions the tier
/// to `Deoptimized`, and rehashes.
pub fn record_deopt(
    profile: &mut TierProfile,
    reason: DeoptReason,
    site: &str,
    epoch: &SecurityEpoch,
) {
    profile.deopt_count += 1;
    let event = DeoptEvent {
        event_id: format!(
            "deopt-{}-{}-{}",
            profile.function_id,
            profile.deopt_count,
            epoch.as_u64()
        ),
        reason,
        source_tier: profile.current_tier,
        bailout_site: site.to_string(),
        epoch: *epoch,
        counter: profile.deopt_count,
    };
    profile.deopt_events.push(event);
    profile.current_tier = ExecutionTier::Deoptimized;
    profile.last_transition_epoch = *epoch;
    profile.rehash();
}

/// Add a probe record to a profile.
///
/// Creates a `ProbeRecord` with a generated ID and appends it. Rehashes.
pub fn add_probe(
    profile: &mut TierProfile,
    kind: ProbeKind,
    site: &str,
    samples: u64,
    value_millionths: u64,
) {
    let probe = ProbeRecord {
        probe_id: format!(
            "probe-{}-{}-{}",
            profile.function_id,
            site,
            profile.probes.len()
        ),
        kind,
        site_id: site.to_string(),
        sample_count: samples,
        value_millionths,
    };
    profile.probes.push(probe);
    profile.rehash();
}

/// Build an eligibility report for a batch of profiles.
pub fn build_eligibility_report(
    profiles: &[TierProfile],
    policy: &TierEligibilityPolicy,
    epoch: &SecurityEpoch,
) -> TierEligibilityReport {
    let mut verdicts = Vec::with_capacity(profiles.len());
    let mut eligible_count = 0usize;

    for profile in profiles {
        let verdict = evaluate_eligibility(profile, policy);
        if verdict.eligible {
            eligible_count += 1;
        }
        verdicts.push(verdict);
    }

    let total_functions = profiles.len();

    // Aggregate deopt rate: total deopts / total invocations.
    let total_deopts: u64 = profiles.iter().map(|p| p.deopt_count).sum();
    let total_invocations: u64 = profiles.iter().map(|p| p.invocation_count).sum();
    let deopt_rate_millionths = if total_invocations == 0 {
        0
    } else {
        total_deopts
            .saturating_mul(MILLIONTHS)
            .checked_div(total_invocations)
            .unwrap_or(0)
    };

    let mut report = TierEligibilityReport {
        report_id: format!("eligibility-report-epoch-{}", epoch.as_u64()),
        epoch: *epoch,
        profiles: profiles.to_vec(),
        verdicts,
        total_functions,
        eligible_count,
        deopt_rate_millionths,
        content_hash: ContentHash::default(),
    };
    report.rehash();
    report
}

/// Produce a canonical empty manifest for the tier-eligibility substrate.
pub fn franken_engine_tier_eligibility_manifest() -> TierEligibilityReport {
    let mut report = TierEligibilityReport {
        report_id: format!(
            "{}-manifest-{}",
            TIER_ELIGIBILITY_BEAD_ID, TIER_ELIGIBILITY_SCHEMA_VERSION
        ),
        epoch: SecurityEpoch::GENESIS,
        profiles: Vec::new(),
        verdicts: Vec::new(),
        total_functions: 0,
        eligible_count: 0,
        deopt_rate_millionths: 0,
        content_hash: ContentHash::default(),
    };
    report.rehash();
    report
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- tier_rank ordering --

    #[test]
    fn tier_rank_ordering() {
        assert!(tier_rank(ExecutionTier::Deoptimized) < tier_rank(ExecutionTier::Interpreted));
        assert!(tier_rank(ExecutionTier::Interpreted) < tier_rank(ExecutionTier::Baseline));
        assert!(tier_rank(ExecutionTier::Baseline) < tier_rank(ExecutionTier::Optimized));
        assert!(tier_rank(ExecutionTier::Optimized) < tier_rank(ExecutionTier::Specialized));
    }

    #[test]
    fn tier_rank_values_are_distinct() {
        let ranks: Vec<u32> = [
            ExecutionTier::Deoptimized,
            ExecutionTier::Interpreted,
            ExecutionTier::Baseline,
            ExecutionTier::Optimized,
            ExecutionTier::Specialized,
        ]
        .iter()
        .map(|t| tier_rank(*t))
        .collect();
        let unique: std::collections::BTreeSet<u32> = ranks.iter().copied().collect();
        assert_eq!(unique.len(), 5);
    }

    // -- default policy --

    #[test]
    fn default_policy_has_sensible_values() {
        let policy = TierEligibilityPolicy::default();
        assert!(policy.min_invocations > 0);
        assert!(policy.min_feedback_stability_millionths <= MILLIONTHS);
        assert!(policy.deopt_cooldown_epochs > 0);
        assert!(policy.max_deopt_rate_millionths <= MILLIONTHS);
        assert!(policy.min_probe_samples > 0);
        assert!(policy.max_lifetime_deopts > 0);
        assert!(policy.min_confidence_millionths <= MILLIONTHS);
    }

    #[test]
    fn default_policy_content_hash_deterministic() {
        let a = TierEligibilityPolicy::default().content_hash();
        let b = TierEligibilityPolicy::default().content_hash();
        assert_eq!(a, b);
    }

    // -- evaluate_eligibility --

    #[test]
    fn evaluate_eligible_baseline_to_optimized() {
        let policy = TierEligibilityPolicy::default();
        let mut profile = TierProfile::new("p1", "fn_hot");
        profile.current_tier = ExecutionTier::Baseline;
        profile.invocation_count = 500;
        // Add stable probes.
        for i in 0..5 {
            add_probe(
                &mut profile,
                ProbeKind::TypeProfile,
                &format!("site-{i}"),
                100,
                900_000,
            );
        }
        profile.rehash();

        let verdict = evaluate_eligibility(&profile, &policy);
        assert!(verdict.eligible);
        assert_eq!(verdict.target_tier, ExecutionTier::Optimized);
        assert!(!verdict.reasons.is_empty());
        assert!(verdict.confidence_millionths > 0);
    }

    #[test]
    fn evaluate_ineligible_insufficient_invocations() {
        let policy = TierEligibilityPolicy::default();
        let mut profile = TierProfile::new("p2", "fn_cold");
        profile.current_tier = ExecutionTier::Interpreted;
        profile.invocation_count = 5; // below min_invocations
        profile.rehash();

        let verdict = evaluate_eligibility(&profile, &policy);
        assert!(!verdict.eligible);
    }

    #[test]
    fn evaluate_ineligible_high_deopt_rate() {
        let policy = TierEligibilityPolicy::default();
        let mut profile = TierProfile::new("p3", "fn_flaky");
        profile.current_tier = ExecutionTier::Interpreted;
        profile.invocation_count = 200;
        profile.deopt_count = 100; // 50% deopt rate — way above threshold
        profile.rehash();

        let verdict = evaluate_eligibility(&profile, &policy);
        assert!(!verdict.eligible);
        assert!(verdict.probe_summary.contains("deopt_rate"));
    }

    #[test]
    fn evaluate_ineligible_already_specialized() {
        let policy = TierEligibilityPolicy::default();
        let mut profile = TierProfile::new("p4", "fn_max");
        profile.current_tier = ExecutionTier::Specialized;
        profile.invocation_count = 10_000;
        profile.rehash();

        let verdict = evaluate_eligibility(&profile, &policy);
        assert!(!verdict.eligible);
        assert!(verdict.probe_summary.contains("highest tier"));
    }

    #[test]
    fn evaluate_deopt_cooldown_blocks_eligibility() {
        let policy = TierEligibilityPolicy {
            deopt_cooldown_epochs: 5,
            ..TierEligibilityPolicy::default()
        };
        let mut profile = TierProfile::new("p5", "fn_cooled");
        profile.current_tier = ExecutionTier::Interpreted;
        profile.invocation_count = 500;
        // Record a deopt at epoch 8.
        record_deopt(
            &mut profile,
            DeoptReason::TypeMismatch,
            "bc:42",
            &SecurityEpoch::from_raw(8),
        );
        // Force tier back to interpreted and set last_transition to epoch 10
        // (within cooldown window of the deopt at epoch 8).
        profile.current_tier = ExecutionTier::Interpreted;
        profile.last_transition_epoch = SecurityEpoch::from_raw(10);
        profile.rehash();

        let verdict = evaluate_eligibility(&profile, &policy);
        assert!(!verdict.eligible);
        assert!(verdict.probe_summary.contains("cooldown"));
    }

    // -- record_deopt --

    #[test]
    fn record_deopt_increments_count() {
        let mut profile = TierProfile::new("p6", "fn_deopt");
        profile.current_tier = ExecutionTier::Optimized;
        profile.invocation_count = 100;
        assert_eq!(profile.deopt_count, 0);

        record_deopt(
            &mut profile,
            DeoptReason::BoundsCheck,
            "bc:10",
            &SecurityEpoch::from_raw(5),
        );
        assert_eq!(profile.deopt_count, 1);
        assert_eq!(profile.current_tier, ExecutionTier::Deoptimized);
        assert_eq!(profile.deopt_events.len(), 1);
        assert_eq!(profile.deopt_events[0].reason, DeoptReason::BoundsCheck);
        assert_eq!(profile.last_transition_epoch, SecurityEpoch::from_raw(5));
    }

    #[test]
    fn record_deopt_multiple_events() {
        let mut profile = TierProfile::new("p7", "fn_multi_deopt");
        profile.current_tier = ExecutionTier::Baseline;
        profile.invocation_count = 50;

        record_deopt(
            &mut profile,
            DeoptReason::TypeMismatch,
            "bc:1",
            &SecurityEpoch::from_raw(1),
        );
        record_deopt(
            &mut profile,
            DeoptReason::OverflowCheck,
            "bc:2",
            &SecurityEpoch::from_raw(2),
        );
        assert_eq!(profile.deopt_count, 2);
        assert_eq!(profile.deopt_events.len(), 2);
    }

    // -- add_probe --

    #[test]
    fn add_probe_appends_record() {
        let mut profile = TierProfile::new("p8", "fn_probed");
        assert!(profile.probes.is_empty());

        add_probe(
            &mut profile,
            ProbeKind::CallFrequency,
            "site-0",
            50,
            750_000,
        );
        assert_eq!(profile.probes.len(), 1);
        assert_eq!(profile.probes[0].kind, ProbeKind::CallFrequency);
        assert_eq!(profile.probes[0].sample_count, 50);
        assert_eq!(profile.probes[0].value_millionths, 750_000);
    }

    #[test]
    fn add_probe_changes_content_hash() {
        let mut profile = TierProfile::new("p9", "fn_hash_change");
        let hash_before = profile.content_hash.clone();
        add_probe(
            &mut profile,
            ProbeKind::BranchCoverage,
            "site-1",
            20,
            500_000,
        );
        assert_ne!(profile.content_hash, hash_before);
    }

    // -- compute_deopt_rate --

    #[test]
    fn compute_deopt_rate_zero_invocations() {
        let profile = TierProfile::new("p10", "fn_zero");
        assert_eq!(compute_deopt_rate(&profile), 0);
    }

    #[test]
    fn compute_deopt_rate_no_deopts() {
        let mut profile = TierProfile::new("p11", "fn_clean");
        profile.invocation_count = 1000;
        profile.rehash();
        assert_eq!(compute_deopt_rate(&profile), 0);
    }

    #[test]
    fn compute_deopt_rate_half() {
        let mut profile = TierProfile::new("p12", "fn_half");
        profile.invocation_count = 100;
        profile.deopt_count = 50;
        profile.rehash();
        assert_eq!(compute_deopt_rate(&profile), 500_000); // 50%
    }

    #[test]
    fn compute_deopt_rate_full() {
        let mut profile = TierProfile::new("p13", "fn_all_deopt");
        profile.invocation_count = 200;
        profile.deopt_count = 200;
        profile.rehash();
        assert_eq!(compute_deopt_rate(&profile), MILLIONTHS); // 100%
    }

    // -- is_feedback_stable --

    #[test]
    fn is_feedback_stable_no_probes() {
        let profile = TierProfile::new("p14", "fn_no_probes");
        assert!(!is_feedback_stable(&profile, 800_000));
    }

    #[test]
    fn is_feedback_stable_all_sufficient() {
        let mut profile = TierProfile::new("p15", "fn_stable");
        for i in 0..5 {
            add_probe(
                &mut profile,
                ProbeKind::TypeProfile,
                &format!("s{i}"),
                100,
                900_000,
            );
        }
        assert!(is_feedback_stable(&profile, 800_000));
    }

    #[test]
    fn is_feedback_stable_half_insufficient() {
        let mut profile = TierProfile::new("p16", "fn_partial");
        // 2 with enough samples, 2 without.
        add_probe(&mut profile, ProbeKind::TypeProfile, "s0", 100, 900_000);
        add_probe(&mut profile, ProbeKind::TypeProfile, "s1", 100, 900_000);
        add_probe(&mut profile, ProbeKind::TypeProfile, "s2", 3, 900_000);
        add_probe(&mut profile, ProbeKind::TypeProfile, "s3", 5, 900_000);
        // 50% stable (500_000) — below 800_000 threshold.
        assert!(!is_feedback_stable(&profile, 800_000));
        // But above a lower threshold.
        assert!(is_feedback_stable(&profile, 400_000));
    }

    // -- build_eligibility_report --

    #[test]
    fn build_report_empty_profiles() {
        let policy = TierEligibilityPolicy::default();
        let epoch = SecurityEpoch::from_raw(10);
        let report = build_eligibility_report(&[], &policy, &epoch);
        assert_eq!(report.total_functions, 0);
        assert_eq!(report.eligible_count, 0);
        assert_eq!(report.deopt_rate_millionths, 0);
        assert!(report.verdicts.is_empty());
    }

    #[test]
    fn build_report_mixed_eligibility() {
        let policy = TierEligibilityPolicy::default();
        let epoch = SecurityEpoch::from_raw(10);

        // Profile that should be eligible.
        let mut eligible_profile = TierProfile::new("pe", "fn_eligible");
        eligible_profile.current_tier = ExecutionTier::Interpreted;
        eligible_profile.invocation_count = 500;
        eligible_profile.rehash();

        // Profile that should not be eligible.
        let mut ineligible_profile = TierProfile::new("pi", "fn_ineligible");
        ineligible_profile.current_tier = ExecutionTier::Interpreted;
        ineligible_profile.invocation_count = 2; // too few
        ineligible_profile.rehash();

        let profiles = [eligible_profile, ineligible_profile];
        let report = build_eligibility_report(&profiles, &policy, &epoch);
        assert_eq!(report.total_functions, 2);
        assert_eq!(report.eligible_count, 1);
    }

    // -- cooldown_active --

    #[test]
    fn cooldown_active_no_events() {
        let profile = TierProfile::new("pc1", "fn_no_deopt");
        assert!(!cooldown_active(&profile, 5, &SecurityEpoch::from_raw(10)));
    }

    #[test]
    fn cooldown_active_within_window() {
        let mut profile = TierProfile::new("pc2", "fn_recent_deopt");
        record_deopt(
            &mut profile,
            DeoptReason::MapTransition,
            "bc:5",
            &SecurityEpoch::from_raw(8),
        );
        // Current epoch 10, cooldown 5 => deopt at 8 is within window (10-8=2 < 5).
        assert!(cooldown_active(&profile, 5, &SecurityEpoch::from_raw(10)));
    }

    #[test]
    fn cooldown_active_outside_window() {
        let mut profile = TierProfile::new("pc3", "fn_old_deopt");
        record_deopt(
            &mut profile,
            DeoptReason::MapTransition,
            "bc:5",
            &SecurityEpoch::from_raw(2),
        );
        // Current epoch 10, cooldown 5 => deopt at 2 is outside window (10-2=8 >= 5).
        assert!(!cooldown_active(&profile, 5, &SecurityEpoch::from_raw(10)));
    }

    // -- serde roundtrips --

    #[test]
    fn serde_roundtrip_execution_tier() {
        for tier in [
            ExecutionTier::Interpreted,
            ExecutionTier::Baseline,
            ExecutionTier::Optimized,
            ExecutionTier::Specialized,
            ExecutionTier::Deoptimized,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize");
            let restored: ExecutionTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(tier, restored);
        }
    }

    #[test]
    fn serde_roundtrip_deopt_reason() {
        for reason in [
            DeoptReason::TypeMismatch,
            DeoptReason::MapTransition,
            DeoptReason::OverflowCheck,
            DeoptReason::BoundsCheck,
            DeoptReason::UnstableInlineCache,
            DeoptReason::MissingFeedback,
            DeoptReason::PolicyRejection,
        ] {
            let json = serde_json::to_string(&reason).expect("serialize");
            let restored: DeoptReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(reason, restored);
        }
    }

    #[test]
    fn serde_roundtrip_probe_kind() {
        for kind in [
            ProbeKind::TypeProfile,
            ProbeKind::AllocationSite,
            ProbeKind::BranchCoverage,
            ProbeKind::CallFrequency,
            ProbeKind::InlineCacheState,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let restored: ProbeKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn serde_roundtrip_tier_profile() {
        let mut profile = TierProfile::new("serde-p1", "fn_serde");
        profile.invocation_count = 42;
        add_probe(&mut profile, ProbeKind::TypeProfile, "s0", 10, 500_000);
        record_deopt(
            &mut profile,
            DeoptReason::BoundsCheck,
            "bc:3",
            &SecurityEpoch::from_raw(1),
        );

        let json = serde_json::to_string(&profile).expect("serialize");
        let restored: TierProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile, restored);
    }

    #[test]
    fn serde_roundtrip_eligibility_report() {
        let policy = TierEligibilityPolicy::default();
        let epoch = SecurityEpoch::from_raw(5);
        let report = build_eligibility_report(&[], &policy, &epoch);

        let json = serde_json::to_string(&report).expect("serialize");
        let restored: TierEligibilityReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, restored);
    }

    #[test]
    fn serde_roundtrip_policy() {
        let policy = TierEligibilityPolicy::default();
        let json = serde_json::to_string(&policy).expect("serialize");
        let restored: TierEligibilityPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, restored);
    }

    // -- Display impls --

    #[test]
    fn display_execution_tier_all_unique() {
        let tiers = [
            ExecutionTier::Interpreted,
            ExecutionTier::Baseline,
            ExecutionTier::Optimized,
            ExecutionTier::Specialized,
            ExecutionTier::Deoptimized,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for t in &tiers {
            seen.insert(t.to_string());
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn display_deopt_reason_all_unique() {
        let reasons = [
            DeoptReason::TypeMismatch,
            DeoptReason::MapTransition,
            DeoptReason::OverflowCheck,
            DeoptReason::BoundsCheck,
            DeoptReason::UnstableInlineCache,
            DeoptReason::MissingFeedback,
            DeoptReason::PolicyRejection,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for r in &reasons {
            seen.insert(r.to_string());
        }
        assert_eq!(seen.len(), 7);
    }

    #[test]
    fn display_probe_kind_all_unique() {
        let kinds = [
            ProbeKind::TypeProfile,
            ProbeKind::AllocationSite,
            ProbeKind::BranchCoverage,
            ProbeKind::CallFrequency,
            ProbeKind::InlineCacheState,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for k in &kinds {
            seen.insert(k.to_string());
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn display_tier_profile() {
        let profile = TierProfile::new("disp1", "fn_display");
        let display = profile.to_string();
        assert!(display.contains("TierProfile"));
        assert!(display.contains("fn_display"));
    }

    #[test]
    fn display_policy() {
        let policy = TierEligibilityPolicy::default();
        let display = policy.to_string();
        assert!(display.contains("TierEligibilityPolicy"));
    }

    #[test]
    fn display_verdict() {
        let verdict = TierEligibilityVerdict::ineligible(ExecutionTier::Baseline, "test reason");
        let display = verdict.to_string();
        assert!(display.contains("TierEligibilityVerdict"));
        assert!(display.contains("eligible=false"));
    }

    #[test]
    fn display_report() {
        let report = franken_engine_tier_eligibility_manifest();
        let display = report.to_string();
        assert!(display.contains("TierEligibilityReport"));
    }

    // -- content hash determinism --

    #[test]
    fn content_hash_determinism_profile() {
        let mut a = TierProfile::new("det-p", "fn_det");
        a.invocation_count = 100;
        a.rehash();

        let mut b = TierProfile::new("det-p", "fn_det");
        b.invocation_count = 100;
        b.rehash();

        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn content_hash_changes_on_mutation() {
        let mut profile = TierProfile::new("mut-p", "fn_mut");
        let h1 = profile.content_hash.clone();
        profile.invocation_count = 999;
        profile.rehash();
        assert_ne!(profile.content_hash, h1);
    }

    // -- empty/edge cases --

    #[test]
    fn empty_manifest() {
        let manifest = franken_engine_tier_eligibility_manifest();
        assert_eq!(manifest.total_functions, 0);
        assert_eq!(manifest.eligible_count, 0);
        assert_eq!(manifest.epoch, SecurityEpoch::GENESIS);
        assert!(manifest.profiles.is_empty());
        assert!(manifest.verdicts.is_empty());
    }

    #[test]
    fn next_tier_up_from_deoptimized() {
        assert_eq!(
            next_tier_up(ExecutionTier::Deoptimized),
            Some(ExecutionTier::Interpreted)
        );
    }

    #[test]
    fn next_tier_up_chain() {
        assert_eq!(
            next_tier_up(ExecutionTier::Interpreted),
            Some(ExecutionTier::Baseline)
        );
        assert_eq!(
            next_tier_up(ExecutionTier::Baseline),
            Some(ExecutionTier::Optimized)
        );
        assert_eq!(
            next_tier_up(ExecutionTier::Optimized),
            Some(ExecutionTier::Specialized)
        );
        assert_eq!(next_tier_up(ExecutionTier::Specialized), None);
    }

    #[test]
    fn probe_record_content_hash_deterministic() {
        let probe = ProbeRecord {
            probe_id: "probe-1".to_string(),
            kind: ProbeKind::TypeProfile,
            site_id: "site-0".to_string(),
            sample_count: 50,
            value_millionths: 800_000,
        };
        let h1 = probe.content_hash();
        let h2 = probe.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn probe_record_display() {
        let probe = ProbeRecord {
            probe_id: "probe-disp".to_string(),
            kind: ProbeKind::CallFrequency,
            site_id: "site-disp".to_string(),
            sample_count: 42,
            value_millionths: 123_456,
        };
        let display = probe.to_string();
        assert!(display.contains("probe-disp"));
        assert!(display.contains("call_frequency"));
    }

    #[test]
    fn deopt_event_display() {
        let evt = DeoptEvent {
            event_id: "evt-1".to_string(),
            reason: DeoptReason::OverflowCheck,
            source_tier: ExecutionTier::Optimized,
            bailout_site: "bc:99".to_string(),
            epoch: SecurityEpoch::from_raw(7),
            counter: 1,
        };
        let display = evt.to_string();
        assert!(display.contains("evt-1"));
        assert!(display.contains("overflow_check"));
        assert!(display.contains("optimized"));
    }

    #[test]
    fn evaluate_interpreted_to_baseline_no_feedback_needed() {
        // Tiering from Interpreted to Baseline should NOT require feedback stability.
        let policy = TierEligibilityPolicy::default();
        let mut profile = TierProfile::new("p-int-base", "fn_simple");
        profile.current_tier = ExecutionTier::Interpreted;
        profile.invocation_count = 500;
        profile.rehash();

        let verdict = evaluate_eligibility(&profile, &policy);
        assert!(verdict.eligible);
        assert_eq!(verdict.target_tier, ExecutionTier::Baseline);
    }

    #[test]
    fn evaluate_lifetime_deopts_exceeds_max() {
        let policy = TierEligibilityPolicy {
            max_lifetime_deopts: 3,
            ..TierEligibilityPolicy::default()
        };
        let mut profile = TierProfile::new("p-life", "fn_too_many_deopts");
        profile.current_tier = ExecutionTier::Interpreted;
        profile.invocation_count = 500;
        profile.deopt_count = 5; // exceeds max of 3
        profile.rehash();

        let verdict = evaluate_eligibility(&profile, &policy);
        assert!(!verdict.eligible);
    }

    #[test]
    fn schema_constants_are_set() {
        assert!(!TIER_ELIGIBILITY_SCHEMA_VERSION.is_empty());
        assert!(TIER_ELIGIBILITY_BEAD_ID.starts_with("bd-"));
        assert!(TIER_ELIGIBILITY_POLICY_ID.starts_with("RGC-"));
        assert!(!COMPONENT.is_empty());
    }

    #[test]
    fn transition_reason_display_all_unique() {
        let reasons = [
            TierTransitionReason::HotLoopDetected,
            TierTransitionReason::ProfileThresholdReached,
            TierTransitionReason::InlineCacheMonomorphic,
            TierTransitionReason::TypeFeedbackStable,
            TierTransitionReason::DeoptBailout,
            TierTransitionReason::PolicyOverride,
            TierTransitionReason::ManualProbe,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for r in &reasons {
            seen.insert(r.to_string());
        }
        assert_eq!(seen.len(), 7);
    }

    #[test]
    fn serde_roundtrip_transition_reason() {
        for reason in [
            TierTransitionReason::HotLoopDetected,
            TierTransitionReason::ProfileThresholdReached,
            TierTransitionReason::InlineCacheMonomorphic,
            TierTransitionReason::TypeFeedbackStable,
            TierTransitionReason::DeoptBailout,
            TierTransitionReason::PolicyOverride,
            TierTransitionReason::ManualProbe,
        ] {
            let json = serde_json::to_string(&reason).expect("serialize");
            let restored: TierTransitionReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(reason, restored);
        }
    }

    #[test]
    fn report_deopt_rate_aggregation() {
        let policy = TierEligibilityPolicy::default();
        let epoch = SecurityEpoch::from_raw(10);

        let mut p1 = TierProfile::new("agg1", "fn_a");
        p1.invocation_count = 100;
        p1.deopt_count = 10; // 10%
        p1.rehash();

        let mut p2 = TierProfile::new("agg2", "fn_b");
        p2.invocation_count = 100;
        p2.deopt_count = 0; // 0%
        p2.rehash();

        let report = build_eligibility_report(&[p1, p2], &policy, &epoch);
        // Aggregate: 10 deopts / 200 invocations = 5% = 50_000 millionths.
        assert_eq!(report.deopt_rate_millionths, 50_000);
    }
}
