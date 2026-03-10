//! Polymorphic inline cache (PIC) policy, site profiling, and deterministic
//! bailout logic built on top of the canonical shape-transition algebra.
//!
//! Bead: bd-1lsy.7.6.2 [RGC-606B]
//!
//! This module sits above `shape_transition_algebra` and provides:
//! - **IC site profiles**: per-instruction IC history with stable ordering.
//! - **Promotion/demotion policy**: when to widen (mono→poly→mega) and
//!   shrink (prune cold entries), all with explicit replay receipts.
//! - **Bailout decisions**: deterministic deopt verdicts with cryptographic
//!   evidence so the decision is replayable.
//! - **IC replay log**: a deterministic trace of every state transition that
//!   can be diffed across runs for regression detection.
//! - **Evidence harness**: specimen corpus for integration testing.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "polymorphic_inline_cache";
pub const BEAD_ID: &str = "bd-1lsy.7.6.2";
pub const PIC_SCHEMA_VERSION: &str = "frankenengine.polymorphic-inline-cache.v1";
pub const PIC_PROFILE_SCHEMA_VERSION: &str = "frankenengine.pic-profile.v1";
pub const PIC_DECISION_SCHEMA_VERSION: &str = "frankenengine.pic-decision.v1";
pub const PIC_REPLAY_SCHEMA_VERSION: &str = "frankenengine.pic-replay.v1";

/// One million — unit for fixed-point millionths arithmetic.
const MILLION: i64 = 1_000_000;

/// Default maximum polymorphic entries before megamorphic transition.
pub const DEFAULT_MAX_POLY_ENTRIES: usize = 4;

/// Default minimum hit rate (millionths) to consider a PIC site "warm."
pub const DEFAULT_MIN_WARM_HIT_RATE: i64 = 700_000; // 70%

/// Default minimum accesses before a site is eligible for analysis.
pub const DEFAULT_MIN_ACCESS_COUNT: u64 = 100;

/// Default megamorphic threshold: shape count beyond which IC is megamorphic.
pub const DEFAULT_MEGAMORPHIC_THRESHOLD: u32 = 8;

/// Default cold entry pruning threshold (millionths of total hits).
pub const DEFAULT_COLD_PRUNE_THRESHOLD: i64 = 50_000; // 5%

// ---------------------------------------------------------------------------
// IcSiteKind — what kind of property access
// ---------------------------------------------------------------------------

/// Kind of property access at an IC site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IcSiteKind {
    /// Named property load (e.g., `obj.x`).
    PropertyLoad,
    /// Named property store (e.g., `obj.x = v`).
    PropertyStore,
    /// Computed property load (e.g., `obj[key]`).
    ComputedLoad,
    /// Computed property store (e.g., `obj[key] = v`).
    ComputedStore,
    /// Call site (e.g., `obj.method()`).
    CallSite,
    /// Constructor call (e.g., `new Foo()`).
    ConstructorSite,
    /// `in` operator (e.g., `key in obj`).
    InOperator,
    /// `instanceof` check.
    InstanceOf,
}

impl fmt::Display for IcSiteKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PropertyLoad => write!(f, "property_load"),
            Self::PropertyStore => write!(f, "property_store"),
            Self::ComputedLoad => write!(f, "computed_load"),
            Self::ComputedStore => write!(f, "computed_store"),
            Self::CallSite => write!(f, "call_site"),
            Self::ConstructorSite => write!(f, "constructor_site"),
            Self::InOperator => write!(f, "in_operator"),
            Self::InstanceOf => write!(f, "instance_of"),
        }
    }
}

impl IcSiteKind {
    pub const ALL: &[Self] = &[
        Self::PropertyLoad,
        Self::PropertyStore,
        Self::ComputedLoad,
        Self::ComputedStore,
        Self::CallSite,
        Self::ConstructorSite,
        Self::InOperator,
        Self::InstanceOf,
    ];

    /// Whether this site kind benefits from monomorphic fast paths.
    pub fn benefits_from_monomorphic(self) -> bool {
        matches!(
            self,
            Self::PropertyLoad | Self::PropertyStore | Self::CallSite | Self::ConstructorSite
        )
    }
}

// ---------------------------------------------------------------------------
// IcSiteProfile — per-instruction IC history
// ---------------------------------------------------------------------------

/// Profile of a single IC site, tracking its state evolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcSiteProfile {
    /// Schema version.
    pub schema_version: String,
    /// Instruction offset in the bytecode.
    pub instruction_offset: u32,
    /// What kind of property access.
    pub site_kind: IcSiteKind,
    /// Function or scope identifier.
    pub scope_id: String,
    /// Current IC state.
    pub current_state: IcSiteState,
    /// Total accesses at this site.
    pub total_accesses: u64,
    /// Number of state transitions (degradations/promotions).
    pub transition_count: u32,
    /// Number of guard failures (deopts).
    pub guard_failure_count: u32,
    /// Distinct shape IDs observed at this site.
    pub observed_shapes: Vec<u64>,
    /// Whether this site has been marked "megamorphic sticky" (never returns
    /// to polymorphic once mega).
    pub megamorphic_sticky: bool,
    /// Content hash for deterministic replay.
    pub content_hash: ContentHash,
}

/// Simplified IC state for the profile (without full entries).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IcSiteState {
    Uninitialised,
    Monomorphic,
    Polymorphic,
    Megamorphic,
}

impl fmt::Display for IcSiteState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialised => write!(f, "uninitialised"),
            Self::Monomorphic => write!(f, "monomorphic"),
            Self::Polymorphic => write!(f, "polymorphic"),
            Self::Megamorphic => write!(f, "megamorphic"),
        }
    }
}

impl IcSiteState {
    pub const ALL: &[Self] = &[
        Self::Uninitialised,
        Self::Monomorphic,
        Self::Polymorphic,
        Self::Megamorphic,
    ];
}

impl IcSiteProfile {
    /// Create a new, uninitialised profile.
    pub fn new(instruction_offset: u32, site_kind: IcSiteKind, scope_id: &str) -> Self {
        let content_hash = Self::compute_hash(
            instruction_offset,
            site_kind,
            scope_id,
            IcSiteState::Uninitialised,
            0,
        );
        Self {
            schema_version: PIC_PROFILE_SCHEMA_VERSION.into(),
            instruction_offset,
            site_kind,
            scope_id: scope_id.into(),
            current_state: IcSiteState::Uninitialised,
            total_accesses: 0,
            transition_count: 0,
            guard_failure_count: 0,
            observed_shapes: Vec::new(),
            megamorphic_sticky: false,
            content_hash,
        }
    }

    /// Record an access from a given shape. Returns whether the state changed.
    pub fn record_access(&mut self, shape_id: u64) -> bool {
        self.total_accesses = self.total_accesses.saturating_add(1);
        if !self.observed_shapes.contains(&shape_id) {
            self.observed_shapes.push(shape_id);
            self.observed_shapes.sort();
        }

        let old_state = self.current_state;
        let shape_count = self.observed_shapes.len() as u32;
        let new_state = if shape_count == 0 {
            IcSiteState::Uninitialised
        } else if shape_count == 1 {
            IcSiteState::Monomorphic
        } else if shape_count <= DEFAULT_MAX_POLY_ENTRIES as u32 {
            IcSiteState::Polymorphic
        } else {
            IcSiteState::Megamorphic
        };

        // Megamorphic sticky: once mega, never go back
        if self.megamorphic_sticky && old_state == IcSiteState::Megamorphic {
            self.rehash();
            return false;
        }

        self.current_state = new_state;
        if new_state != old_state {
            self.transition_count = self.transition_count.saturating_add(1);
            if new_state == IcSiteState::Megamorphic {
                self.megamorphic_sticky = true;
            }
            self.rehash();
            true
        } else {
            self.rehash();
            false
        }
    }

    /// Record a guard failure at this site.
    pub fn record_guard_failure(&mut self) {
        self.guard_failure_count = self.guard_failure_count.saturating_add(1);
        self.rehash();
    }

    /// Hit rate for this site (millionths). Defined as the fraction of
    /// accesses that did NOT result in a state transition or guard failure.
    pub fn hit_rate_millionths(&self) -> i64 {
        if self.total_accesses == 0 {
            return 0;
        }
        let misses = (self.transition_count as u64).saturating_add(self.guard_failure_count as u64);
        let hits = self.total_accesses.saturating_sub(misses);
        (hits as i64).checked_mul(MILLION).unwrap_or(0) / (self.total_accesses as i64)
    }

    /// Whether the site is considered "warm" (enough accesses for analysis).
    pub fn is_warm(&self) -> bool {
        self.total_accesses >= DEFAULT_MIN_ACCESS_COUNT
    }

    /// Whether the site is monomorphic.
    pub fn is_monomorphic(&self) -> bool {
        self.current_state == IcSiteState::Monomorphic
    }

    /// Whether the site is megamorphic.
    pub fn is_megamorphic(&self) -> bool {
        self.current_state == IcSiteState::Megamorphic
    }

    fn rehash(&mut self) {
        self.content_hash = Self::compute_hash(
            self.instruction_offset,
            self.site_kind,
            &self.scope_id,
            self.current_state,
            self.total_accesses,
        );
    }

    fn compute_hash(
        offset: u32,
        kind: IcSiteKind,
        scope_id: &str,
        state: IcSiteState,
        accesses: u64,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(offset.to_le_bytes());
        hasher.update([kind as u8]);
        hasher.update(scope_id.as_bytes());
        hasher.update([state as u8]);
        hasher.update(accesses.to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// BailoutVerdict — deterministic deopt decision
// ---------------------------------------------------------------------------

/// Verdict of whether an IC site should trigger a bailout (deoptimisation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BailoutVerdict {
    /// Stay on the current fast path. No action needed.
    Continue,
    /// Widen the IC (add a new shape to the polymorphic entries).
    Widen,
    /// Promote to megamorphic: use generic slow path.
    PromoteToMegamorphic,
    /// Prune cold entries from the polymorphic IC.
    PruneColdEntries,
    /// Deoptimise: abandon optimised code and fall back to interpreter.
    Deoptimise,
    /// Recompile: the IC profile has changed enough to warrant recompilation.
    Recompile,
}

impl fmt::Display for BailoutVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue => write!(f, "continue"),
            Self::Widen => write!(f, "widen"),
            Self::PromoteToMegamorphic => write!(f, "promote_to_megamorphic"),
            Self::PruneColdEntries => write!(f, "prune_cold_entries"),
            Self::Deoptimise => write!(f, "deoptimise"),
            Self::Recompile => write!(f, "recompile"),
        }
    }
}

impl BailoutVerdict {
    pub const ALL: &[Self] = &[
        Self::Continue,
        Self::Widen,
        Self::PromoteToMegamorphic,
        Self::PruneColdEntries,
        Self::Deoptimise,
        Self::Recompile,
    ];

    /// Whether this verdict causes a code invalidation.
    pub fn causes_invalidation(self) -> bool {
        matches!(self, Self::Deoptimise | Self::Recompile)
    }
}

// ---------------------------------------------------------------------------
// BailoutDecision — a deterministic deopt decision with evidence
// ---------------------------------------------------------------------------

/// A deterministic bailout decision with supporting evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BailoutDecision {
    /// Schema version.
    pub schema_version: String,
    /// IC site instruction offset.
    pub instruction_offset: u32,
    /// Scope identifier.
    pub scope_id: String,
    /// The verdict.
    pub verdict: BailoutVerdict,
    /// Reason for the verdict (human-readable).
    pub reason: String,
    /// IC site state at decision time.
    pub site_state: IcSiteState,
    /// Number of observed shapes at decision time.
    pub observed_shape_count: u32,
    /// Guard failure count at decision time.
    pub guard_failure_count: u32,
    /// Hit rate at decision time (millionths).
    pub hit_rate_millionths: i64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Content hash for deterministic replay.
    pub decision_hash: ContentHash,
}

impl BailoutDecision {
    fn compute_hash(
        offset: u32,
        scope_id: &str,
        verdict: BailoutVerdict,
        epoch: SecurityEpoch,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(offset.to_le_bytes());
        hasher.update(scope_id.as_bytes());
        hasher.update([verdict as u8]);
        hasher.update(epoch.as_u64().to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// IcPolicyConfig — configuration for IC promotion/demotion policy
// ---------------------------------------------------------------------------

/// Configuration for the IC policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcPolicyConfig {
    /// Max polymorphic entries before megamorphic transition.
    pub max_poly_entries: usize,
    /// Minimum hit rate (millionths) to stay on fast path.
    pub min_hit_rate_millionths: i64,
    /// Minimum access count before analysis.
    pub min_access_count: u64,
    /// Megamorphic threshold (shape count).
    pub megamorphic_threshold: u32,
    /// Cold entry pruning threshold (millionths of total hits).
    pub cold_prune_threshold_millionths: i64,
    /// Maximum guard failures before forced deopt.
    pub max_guard_failures: u32,
    /// Whether megamorphic is sticky (never returns to poly).
    pub megamorphic_sticky: bool,
}

impl Default for IcPolicyConfig {
    fn default() -> Self {
        Self {
            max_poly_entries: DEFAULT_MAX_POLY_ENTRIES,
            min_hit_rate_millionths: DEFAULT_MIN_WARM_HIT_RATE,
            min_access_count: DEFAULT_MIN_ACCESS_COUNT,
            megamorphic_threshold: DEFAULT_MEGAMORPHIC_THRESHOLD,
            cold_prune_threshold_millionths: DEFAULT_COLD_PRUNE_THRESHOLD,
            max_guard_failures: 10,
            megamorphic_sticky: true,
        }
    }
}

// ---------------------------------------------------------------------------
// decide_bailout — deterministic bailout decision
// ---------------------------------------------------------------------------

/// Evaluate the current IC site profile and produce a deterministic bailout
/// decision with cryptographic evidence.
pub fn decide_bailout(
    profile: &IcSiteProfile,
    config: &IcPolicyConfig,
    epoch: SecurityEpoch,
) -> BailoutDecision {
    let (verdict, reason) = compute_verdict(profile, config);
    let decision_hash = BailoutDecision::compute_hash(
        profile.instruction_offset,
        &profile.scope_id,
        verdict,
        epoch,
    );

    BailoutDecision {
        schema_version: PIC_DECISION_SCHEMA_VERSION.into(),
        instruction_offset: profile.instruction_offset,
        scope_id: profile.scope_id.clone(),
        verdict,
        reason,
        site_state: profile.current_state,
        observed_shape_count: profile.observed_shapes.len() as u32,
        guard_failure_count: profile.guard_failure_count,
        hit_rate_millionths: profile.hit_rate_millionths(),
        epoch,
        decision_hash,
    }
}

fn compute_verdict(profile: &IcSiteProfile, config: &IcPolicyConfig) -> (BailoutVerdict, String) {
    // Not enough data yet → continue.
    if profile.total_accesses < config.min_access_count {
        return (
            BailoutVerdict::Continue,
            "insufficient accesses for analysis".into(),
        );
    }

    // Too many guard failures → deoptimise.
    if profile.guard_failure_count >= config.max_guard_failures {
        return (
            BailoutVerdict::Deoptimise,
            format!(
                "guard failures ({}) exceed max ({})",
                profile.guard_failure_count, config.max_guard_failures
            ),
        );
    }

    // Already megamorphic and sticky → continue on slow path.
    if profile.is_megamorphic() && config.megamorphic_sticky {
        return (
            BailoutVerdict::Continue,
            "megamorphic (sticky), using slow path".into(),
        );
    }

    let shape_count = profile.observed_shapes.len() as u32;

    // Shape count exceeds megamorphic threshold → promote.
    if shape_count > config.megamorphic_threshold {
        return (
            BailoutVerdict::PromoteToMegamorphic,
            format!(
                "observed shapes ({shape_count}) exceed megamorphic threshold ({})",
                config.megamorphic_threshold
            ),
        );
    }

    // Shape count exceeds max poly entries → promote to megamorphic.
    if shape_count > config.max_poly_entries as u32 {
        return (
            BailoutVerdict::PromoteToMegamorphic,
            format!(
                "observed shapes ({shape_count}) exceed max poly entries ({})",
                config.max_poly_entries
            ),
        );
    }

    let hit_rate = profile.hit_rate_millionths();

    // Hit rate too low → check if recompilation would help.
    if hit_rate < config.min_hit_rate_millionths {
        if profile.transition_count > 3 {
            return (
                BailoutVerdict::Recompile,
                format!(
                    "hit rate ({hit_rate} millionths) below threshold ({}) with {} transitions",
                    config.min_hit_rate_millionths, profile.transition_count
                ),
            );
        }
        return (
            BailoutVerdict::PruneColdEntries,
            format!(
                "hit rate ({hit_rate} millionths) below threshold ({})",
                config.min_hit_rate_millionths
            ),
        );
    }

    // Polymorphic with new shape seen → widen.
    if profile.current_state == IcSiteState::Polymorphic
        && shape_count > 1
        && shape_count <= config.max_poly_entries as u32
    {
        // Already at polymorphic level, check if we need to widen
        // (additional shape just observed).
        if profile.transition_count > 0 && profile.total_accesses == config.min_access_count {
            return (
                BailoutVerdict::Widen,
                format!("polymorphic site with {shape_count} shapes, widening"),
            );
        }
    }

    (BailoutVerdict::Continue, "stable IC site".into())
}

// ---------------------------------------------------------------------------
// IcReplayEvent — deterministic IC state transition trace
// ---------------------------------------------------------------------------

/// A single IC replay event for deterministic trace diffing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcReplayEvent {
    /// Sequence number within the replay log.
    pub sequence: u64,
    /// Instruction offset.
    pub instruction_offset: u32,
    /// Previous IC state.
    pub from_state: IcSiteState,
    /// New IC state.
    pub to_state: IcSiteState,
    /// Shape ID that triggered the transition.
    pub trigger_shape_id: u64,
    /// Total accesses at time of transition.
    pub access_count: u64,
}

/// Replay log collecting all IC state transitions for a scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcReplayLog {
    /// Schema version.
    pub schema_version: String,
    /// Scope identifier.
    pub scope_id: String,
    /// Ordered events.
    pub events: Vec<IcReplayEvent>,
    /// Content hash for deterministic comparison.
    pub content_hash: ContentHash,
}

impl IcReplayLog {
    /// Create a new empty replay log.
    pub fn new(scope_id: &str) -> Self {
        Self {
            schema_version: PIC_REPLAY_SCHEMA_VERSION.into(),
            scope_id: scope_id.into(),
            events: Vec::new(),
            content_hash: ContentHash::compute(&[]),
        }
    }

    /// Append a state transition event.
    pub fn push(
        &mut self,
        instruction_offset: u32,
        from_state: IcSiteState,
        to_state: IcSiteState,
        trigger_shape_id: u64,
        access_count: u64,
    ) {
        let sequence = self.events.len() as u64;
        self.events.push(IcReplayEvent {
            sequence,
            instruction_offset,
            from_state,
            to_state,
            trigger_shape_id,
            access_count,
        });
        self.rehash();
    }

    /// Number of events in the log.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Count transitions that resulted in megamorphic state.
    pub fn megamorphic_transitions(&self) -> usize {
        self.events
            .iter()
            .filter(|e| e.to_state == IcSiteState::Megamorphic)
            .count()
    }

    fn rehash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.scope_id.as_bytes());
        for event in &self.events {
            hasher.update(event.sequence.to_le_bytes());
            hasher.update(event.instruction_offset.to_le_bytes());
            hasher.update([event.from_state as u8]);
            hasher.update([event.to_state as u8]);
            hasher.update(event.trigger_shape_id.to_le_bytes());
        }
        self.content_hash = ContentHash::compute(&hasher.finalize());
    }
}

// ---------------------------------------------------------------------------
// IcScopeProfile — aggregate profile for all sites in a scope
// ---------------------------------------------------------------------------

/// Aggregate IC profile for all sites within a scope (function/module).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcScopeProfile {
    /// Scope identifier.
    pub scope_id: String,
    /// Per-site profiles (keyed by instruction offset).
    pub sites: BTreeMap<u32, IcSiteProfile>,
    /// Replay log.
    pub replay_log: IcReplayLog,
    /// Total accesses across all sites.
    pub total_accesses: u64,
    /// Total guard failures across all sites.
    pub total_guard_failures: u32,
}

impl IcScopeProfile {
    /// Create a new empty scope profile.
    pub fn new(scope_id: &str) -> Self {
        Self {
            scope_id: scope_id.into(),
            sites: BTreeMap::new(),
            replay_log: IcReplayLog::new(scope_id),
            total_accesses: 0,
            total_guard_failures: 0,
        }
    }

    /// Register a new IC site.
    pub fn register_site(&mut self, offset: u32, kind: IcSiteKind) {
        self.sites
            .entry(offset)
            .or_insert_with(|| IcSiteProfile::new(offset, kind, &self.scope_id));
    }

    /// Record an access at a specific site. Returns whether the IC state changed.
    pub fn record_access(&mut self, offset: u32, shape_id: u64) -> bool {
        self.total_accesses = self.total_accesses.saturating_add(1);
        if let Some(profile) = self.sites.get_mut(&offset) {
            let old_state = profile.current_state;
            let changed = profile.record_access(shape_id);
            if changed {
                self.replay_log.push(
                    offset,
                    old_state,
                    profile.current_state,
                    shape_id,
                    profile.total_accesses,
                );
            }
            changed
        } else {
            false
        }
    }

    /// Record a guard failure at a specific site.
    pub fn record_guard_failure(&mut self, offset: u32) {
        self.total_guard_failures = self.total_guard_failures.saturating_add(1);
        if let Some(profile) = self.sites.get_mut(&offset) {
            profile.record_guard_failure();
        }
    }

    /// Number of sites in this scope.
    pub fn site_count(&self) -> usize {
        self.sites.len()
    }

    /// Number of monomorphic sites.
    pub fn monomorphic_count(&self) -> usize {
        self.sites.values().filter(|p| p.is_monomorphic()).count()
    }

    /// Number of megamorphic sites.
    pub fn megamorphic_count(&self) -> usize {
        self.sites.values().filter(|p| p.is_megamorphic()).count()
    }

    /// Monomorphic rate (millionths). Mono / total sites.
    pub fn monomorphic_rate_millionths(&self) -> i64 {
        if self.sites.is_empty() {
            return 0;
        }
        let mono = self.monomorphic_count() as i64;
        let total = self.sites.len() as i64;
        mono.checked_mul(MILLION).unwrap_or(0) / total
    }

    /// Evaluate all warm sites and produce bailout decisions.
    pub fn evaluate_all(
        &self,
        config: &IcPolicyConfig,
        epoch: SecurityEpoch,
    ) -> Vec<BailoutDecision> {
        self.sites
            .values()
            .filter(|p| p.is_warm())
            .map(|p| decide_bailout(p, config, epoch))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

/// Specimen families for PIC integration testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PicSpecimenFamily {
    /// Monomorphic fast path (single shape).
    MonomorphicFastPath,
    /// Polymorphic with shape set within threshold.
    PolymorphicInBounds,
    /// Megamorphic transition.
    MegamorphicTransition,
    /// Guard failure handling.
    GuardFailure,
    /// Cold entry pruning.
    ColdEntryPruning,
    /// Deterministic replay.
    DeterministicReplay,
    /// Bailout decision logic.
    BailoutDecisionLogic,
    /// Scope-level aggregation.
    ScopeAggregation,
}

impl fmt::Display for PicSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MonomorphicFastPath => write!(f, "monomorphic_fast_path"),
            Self::PolymorphicInBounds => write!(f, "polymorphic_in_bounds"),
            Self::MegamorphicTransition => write!(f, "megamorphic_transition"),
            Self::GuardFailure => write!(f, "guard_failure"),
            Self::ColdEntryPruning => write!(f, "cold_entry_pruning"),
            Self::DeterministicReplay => write!(f, "deterministic_replay"),
            Self::BailoutDecisionLogic => write!(f, "bailout_decision_logic"),
            Self::ScopeAggregation => write!(f, "scope_aggregation"),
        }
    }
}

impl PicSpecimenFamily {
    pub const ALL: &[Self] = &[
        Self::MonomorphicFastPath,
        Self::PolymorphicInBounds,
        Self::MegamorphicTransition,
        Self::GuardFailure,
        Self::ColdEntryPruning,
        Self::DeterministicReplay,
        Self::BailoutDecisionLogic,
        Self::ScopeAggregation,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MonomorphicFastPath => "monomorphic_fast_path",
            Self::PolymorphicInBounds => "polymorphic_in_bounds",
            Self::MegamorphicTransition => "megamorphic_transition",
            Self::GuardFailure => "guard_failure",
            Self::ColdEntryPruning => "cold_entry_pruning",
            Self::DeterministicReplay => "deterministic_replay",
            Self::BailoutDecisionLogic => "bailout_decision_logic",
            Self::ScopeAggregation => "scope_aggregation",
        }
    }
}

/// Expected outcome for a PIC specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PicExpectedOutcome {
    MonomorphicHit,
    PolymorphicHit,
    MegamorphicPromotion,
    GuardFailureDetected,
    BailoutTriggered,
    StableProfile,
    ReplayMatch,
    ScopeMetricsCorrect,
}

/// Verdict for a PIC specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PicVerdict {
    Pass,
    Fail,
}

/// Evidence inventory for PIC integration testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PicEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub specimen_count: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub family_coverage: BTreeMap<PicSpecimenFamily, usize>,
    pub evidence: Vec<PicSpecimenResult>,
}

impl PicEvidenceInventory {
    /// Contract is satisfied if no failures and at least one specimen.
    pub fn contract_satisfied(&self) -> bool {
        self.fail_count == 0 && self.specimen_count > 0
    }
}

/// Result of running a single PIC specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PicSpecimenResult {
    pub family: PicSpecimenFamily,
    pub name: String,
    pub verdict: PicVerdict,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    // --- IcSiteKind ---

    #[test]
    fn site_kind_all_eight_variants() {
        assert_eq!(IcSiteKind::ALL.len(), 8);
    }

    #[test]
    fn site_kind_display_non_empty() {
        for kind in IcSiteKind::ALL {
            let s = format!("{kind}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn site_kind_serde_roundtrip() {
        for kind in IcSiteKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: IcSiteKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn site_kind_monomorphic_benefit() {
        assert!(IcSiteKind::PropertyLoad.benefits_from_monomorphic());
        assert!(IcSiteKind::PropertyStore.benefits_from_monomorphic());
        assert!(!IcSiteKind::ComputedLoad.benefits_from_monomorphic());
        assert!(!IcSiteKind::InOperator.benefits_from_monomorphic());
    }

    // --- IcSiteState ---

    #[test]
    fn site_state_all_four_variants() {
        assert_eq!(IcSiteState::ALL.len(), 4);
    }

    #[test]
    fn site_state_display() {
        assert_eq!(format!("{}", IcSiteState::Uninitialised), "uninitialised");
        assert_eq!(format!("{}", IcSiteState::Megamorphic), "megamorphic");
    }

    #[test]
    fn site_state_serde_roundtrip() {
        for state in IcSiteState::ALL {
            let json = serde_json::to_string(state).unwrap();
            let back: IcSiteState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, back);
        }
    }

    // --- IcSiteProfile ---

    #[test]
    fn profile_new_is_uninitialised() {
        let p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        assert_eq!(p.current_state, IcSiteState::Uninitialised);
        assert_eq!(p.total_accesses, 0);
        assert_eq!(p.transition_count, 0);
        assert!(p.observed_shapes.is_empty());
    }

    #[test]
    fn profile_first_access_becomes_monomorphic() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        let changed = p.record_access(42);
        assert!(changed);
        assert_eq!(p.current_state, IcSiteState::Monomorphic);
        assert_eq!(p.total_accesses, 1);
        assert_eq!(p.observed_shapes, vec![42]);
    }

    #[test]
    fn profile_same_shape_stays_monomorphic() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        p.record_access(42);
        let changed = p.record_access(42);
        assert!(!changed);
        assert_eq!(p.current_state, IcSiteState::Monomorphic);
        assert_eq!(p.total_accesses, 2);
    }

    #[test]
    fn profile_second_shape_becomes_polymorphic() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        p.record_access(42);
        let changed = p.record_access(99);
        assert!(changed);
        assert_eq!(p.current_state, IcSiteState::Polymorphic);
        assert_eq!(p.observed_shapes, vec![42, 99]);
    }

    #[test]
    fn profile_exceeding_poly_limit_becomes_megamorphic() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        for i in 0..=DEFAULT_MAX_POLY_ENTRIES as u64 {
            p.record_access(i + 1);
        }
        assert_eq!(p.current_state, IcSiteState::Megamorphic);
        assert!(p.megamorphic_sticky);
    }

    #[test]
    fn profile_megamorphic_sticky_stays() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        for i in 0..=DEFAULT_MAX_POLY_ENTRIES as u64 {
            p.record_access(i + 1);
        }
        assert!(p.is_megamorphic());
        // More accesses with same shape don't change state
        let changed = p.record_access(1);
        assert!(!changed);
        assert!(p.is_megamorphic());
    }

    #[test]
    fn profile_guard_failure_increments() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        p.record_guard_failure();
        p.record_guard_failure();
        assert_eq!(p.guard_failure_count, 2);
    }

    #[test]
    fn profile_hit_rate_no_accesses() {
        let p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        assert_eq!(p.hit_rate_millionths(), 0);
    }

    #[test]
    fn profile_hit_rate_all_hits() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        p.record_access(42); // transition (uninit→mono) counts as miss
        for _ in 0..99 {
            p.record_access(42);
        }
        // 1 transition out of 100 accesses → 99% hit rate
        assert_eq!(p.hit_rate_millionths(), 990_000);
    }

    #[test]
    fn profile_is_warm() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        assert!(!p.is_warm());
        for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
            p.record_access(42);
        }
        assert!(p.is_warm());
    }

    #[test]
    fn profile_serde_roundtrip() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        p.record_access(42);
        let json = serde_json::to_string(&p).unwrap();
        let back: IcSiteProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn profile_deterministic_hash() {
        let mut p1 = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        let mut p2 = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:test");
        p1.record_access(42);
        p2.record_access(42);
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    // --- BailoutVerdict ---

    #[test]
    fn verdict_all_six_variants() {
        assert_eq!(BailoutVerdict::ALL.len(), 6);
    }

    #[test]
    fn verdict_display_non_empty() {
        for v in BailoutVerdict::ALL {
            let s = format!("{v}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn verdict_causes_invalidation() {
        assert!(BailoutVerdict::Deoptimise.causes_invalidation());
        assert!(BailoutVerdict::Recompile.causes_invalidation());
        assert!(!BailoutVerdict::Continue.causes_invalidation());
        assert!(!BailoutVerdict::Widen.causes_invalidation());
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in BailoutVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: BailoutVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- IcPolicyConfig ---

    #[test]
    fn config_default_sensible() {
        let config = IcPolicyConfig::default();
        assert!(config.max_poly_entries > 0);
        assert!(config.min_hit_rate_millionths > 0);
        assert!(config.min_access_count > 0);
        assert!(config.max_guard_failures > 0);
        assert!(config.megamorphic_sticky);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = IcPolicyConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: IcPolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- decide_bailout ---

    #[test]
    fn bailout_cold_site_continues() {
        let p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:cold");
        let config = IcPolicyConfig::default();
        let decision = decide_bailout(&p, &config, epoch());
        assert_eq!(decision.verdict, BailoutVerdict::Continue);
    }

    #[test]
    fn bailout_too_many_guard_failures_deopts() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:fail");
        for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
            p.record_access(42);
        }
        for _ in 0..11 {
            p.record_guard_failure();
        }
        let config = IcPolicyConfig::default();
        let decision = decide_bailout(&p, &config, epoch());
        assert_eq!(decision.verdict, BailoutVerdict::Deoptimise);
    }

    #[test]
    fn bailout_megamorphic_sticky_continues() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:mega");
        for i in 0..=DEFAULT_MAX_POLY_ENTRIES as u64 {
            p.record_access(i + 1);
        }
        for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
            p.record_access(1);
        }
        let config = IcPolicyConfig::default();
        let decision = decide_bailout(&p, &config, epoch());
        assert_eq!(decision.verdict, BailoutVerdict::Continue);
        assert!(decision.reason.contains("megamorphic"));
    }

    #[test]
    fn bailout_decision_hash_deterministic() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:det");
        for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
            p.record_access(42);
        }
        let config = IcPolicyConfig::default();
        let d1 = decide_bailout(&p, &config, epoch());
        let d2 = decide_bailout(&p, &config, epoch());
        assert_eq!(d1.decision_hash, d2.decision_hash);
    }

    #[test]
    fn bailout_decision_serde_roundtrip() {
        let mut p = IcSiteProfile::new(10, IcSiteKind::PropertyLoad, "fn:serde");
        p.record_access(42);
        let config = IcPolicyConfig::default();
        let decision = decide_bailout(&p, &config, epoch());
        let json = serde_json::to_string(&decision).unwrap();
        let back: BailoutDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    // --- IcReplayLog ---

    #[test]
    fn replay_log_new_empty() {
        let log = IcReplayLog::new("fn:test");
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn replay_log_push_increments() {
        let mut log = IcReplayLog::new("fn:test");
        log.push(
            10,
            IcSiteState::Uninitialised,
            IcSiteState::Monomorphic,
            42,
            1,
        );
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
        assert_eq!(log.events[0].sequence, 0);
    }

    #[test]
    fn replay_log_megamorphic_transitions_count() {
        let mut log = IcReplayLog::new("fn:test");
        log.push(
            10,
            IcSiteState::Uninitialised,
            IcSiteState::Monomorphic,
            1,
            1,
        );
        log.push(10, IcSiteState::Monomorphic, IcSiteState::Polymorphic, 2, 2);
        log.push(10, IcSiteState::Polymorphic, IcSiteState::Megamorphic, 3, 3);
        assert_eq!(log.megamorphic_transitions(), 1);
    }

    #[test]
    fn replay_log_deterministic_hash() {
        let mut l1 = IcReplayLog::new("fn:det");
        let mut l2 = IcReplayLog::new("fn:det");
        l1.push(
            10,
            IcSiteState::Uninitialised,
            IcSiteState::Monomorphic,
            42,
            1,
        );
        l2.push(
            10,
            IcSiteState::Uninitialised,
            IcSiteState::Monomorphic,
            42,
            1,
        );
        assert_eq!(l1.content_hash, l2.content_hash);
    }

    #[test]
    fn replay_log_serde_roundtrip() {
        let mut log = IcReplayLog::new("fn:serde");
        log.push(
            10,
            IcSiteState::Uninitialised,
            IcSiteState::Monomorphic,
            42,
            1,
        );
        let json = serde_json::to_string(&log).unwrap();
        let back: IcReplayLog = serde_json::from_str(&json).unwrap();
        assert_eq!(log, back);
    }

    // --- IcScopeProfile ---

    #[test]
    fn scope_new_empty() {
        let scope = IcScopeProfile::new("fn:test");
        assert_eq!(scope.site_count(), 0);
        assert_eq!(scope.total_accesses, 0);
    }

    #[test]
    fn scope_register_and_access() {
        let mut scope = IcScopeProfile::new("fn:test");
        scope.register_site(10, IcSiteKind::PropertyLoad);
        scope.register_site(20, IcSiteKind::PropertyStore);
        assert_eq!(scope.site_count(), 2);

        scope.record_access(10, 42);
        assert_eq!(scope.total_accesses, 1);
        assert_eq!(scope.sites.get(&10).unwrap().total_accesses, 1);
    }

    #[test]
    fn scope_monomorphic_rate() {
        let mut scope = IcScopeProfile::new("fn:test");
        scope.register_site(10, IcSiteKind::PropertyLoad);
        scope.register_site(20, IcSiteKind::PropertyStore);
        scope.record_access(10, 42); // mono
        scope.record_access(20, 99); // mono
        assert_eq!(scope.monomorphic_count(), 2);
        assert_eq!(scope.monomorphic_rate_millionths(), MILLION);
    }

    #[test]
    fn scope_replay_log_captures_transitions() {
        let mut scope = IcScopeProfile::new("fn:test");
        scope.register_site(10, IcSiteKind::PropertyLoad);
        scope.record_access(10, 42); // uninit → mono
        scope.record_access(10, 99); // mono → poly
        assert_eq!(scope.replay_log.len(), 2);
    }

    #[test]
    fn scope_guard_failure_propagates() {
        let mut scope = IcScopeProfile::new("fn:test");
        scope.register_site(10, IcSiteKind::PropertyLoad);
        scope.record_guard_failure(10);
        assert_eq!(scope.total_guard_failures, 1);
        assert_eq!(scope.sites.get(&10).unwrap().guard_failure_count, 1);
    }

    #[test]
    fn scope_evaluate_all_warm_sites() {
        let mut scope = IcScopeProfile::new("fn:test");
        scope.register_site(10, IcSiteKind::PropertyLoad);
        // Make it warm
        for _ in 0..DEFAULT_MIN_ACCESS_COUNT {
            scope.record_access(10, 42);
        }
        let config = IcPolicyConfig::default();
        let decisions = scope.evaluate_all(&config, epoch());
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].verdict, BailoutVerdict::Continue);
    }

    // --- PicSpecimenFamily ---

    #[test]
    fn specimen_family_all_eight() {
        assert_eq!(PicSpecimenFamily::ALL.len(), 8);
    }

    #[test]
    fn specimen_family_display_matches_as_str() {
        for fam in PicSpecimenFamily::ALL {
            assert_eq!(format!("{fam}"), fam.as_str());
        }
    }

    #[test]
    fn specimen_family_serde_roundtrip() {
        for fam in PicSpecimenFamily::ALL {
            let json = serde_json::to_string(fam).unwrap();
            let back: PicSpecimenFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*fam, back);
        }
    }

    // --- PicVerdict ---

    #[test]
    fn pic_verdict_serde_roundtrip() {
        for v in [PicVerdict::Pass, PicVerdict::Fail] {
            let json = serde_json::to_string(&v).unwrap();
            let back: PicVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // --- PicEvidenceInventory ---

    #[test]
    fn evidence_inventory_passes_when_no_failures() {
        let inv = PicEvidenceInventory {
            schema_version: PIC_SCHEMA_VERSION.into(),
            component: COMPONENT.into(),
            specimen_count: 5,
            pass_count: 5,
            fail_count: 0,
            family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn evidence_inventory_fails_with_failures() {
        let inv = PicEvidenceInventory {
            schema_version: PIC_SCHEMA_VERSION.into(),
            component: COMPONENT.into(),
            specimen_count: 5,
            pass_count: 4,
            fail_count: 1,
            family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn evidence_inventory_fails_when_empty() {
        let inv = PicEvidenceInventory {
            schema_version: PIC_SCHEMA_VERSION.into(),
            component: COMPONENT.into(),
            specimen_count: 0,
            pass_count: 0,
            fail_count: 0,
            family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    // --- Schema constants ---

    #[test]
    fn schema_constants_non_empty() {
        assert!(!COMPONENT.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!PIC_SCHEMA_VERSION.is_empty());
        assert!(!PIC_PROFILE_SCHEMA_VERSION.is_empty());
        assert!(!PIC_DECISION_SCHEMA_VERSION.is_empty());
        assert!(!PIC_REPLAY_SCHEMA_VERSION.is_empty());
    }
}
