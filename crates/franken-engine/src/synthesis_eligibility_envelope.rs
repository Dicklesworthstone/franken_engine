//! Hot-kernel schema mining and synthesis eligibility envelope.
//!
//! Implements [RGC-613A]: mines recurring hot-kernel schemas from the engine's
//! real workload corpus and defines exactly which kernels are eligible for
//! synthesis, which are forbidden, and why.
//!
//! # Design
//!
//! - `KernelSchema` captures the structural pattern of a hot code region:
//!   operation mix, input/output shape, side-effect profile, and branch depth.
//! - `EligibilityVerdict` determines whether a kernel is eligible for synthesis,
//!   with explicit reasons for rejection.
//! - `SynthesisEnvelope` aggregates eligible and forbidden kernels with coverage
//!   tracking and content-addressed hashing.
//! - `KernelCorpus` collects observed kernel instances and mines frequent schemas.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-613A]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.synthesis-eligibility-envelope.v1";

/// Component name.
pub const COMPONENT: &str = "synthesis_eligibility_envelope";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.13.1";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-613A";

/// Fixed-point unit: 1.0 = 1_000_000.
const MILLION: u64 = 1_000_000;

/// Maximum branch depth allowed for synthesis eligibility.
pub const MAX_SYNTHESIZABLE_BRANCH_DEPTH: u32 = 8;

/// Maximum number of operations in a synthesizable kernel.
pub const MAX_SYNTHESIZABLE_OPS: u32 = 256;

/// Minimum frequency (millionths) for a schema to be considered "hot."
pub const HOT_SCHEMA_THRESHOLD: u64 = 10_000; // 1%

/// Maximum number of side effects allowed for synthesis.
pub const MAX_SIDE_EFFECTS: u32 = 4;

/// Minimum input/output shape stability for eligibility (millionths).
pub const MIN_SHAPE_STABILITY: u64 = 900_000; // 90%

// ---------------------------------------------------------------------------
// OperationKind
// ---------------------------------------------------------------------------

/// Classification of operations within a kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Arithmetic: add, sub, mul, div, mod, etc.
    Arithmetic,
    /// Comparison: eq, lt, gt, etc.
    Comparison,
    /// Bitwise: and, or, xor, shift.
    Bitwise,
    /// Load from memory/property.
    Load,
    /// Store to memory/property.
    Store,
    /// Function call (non-builtin).
    Call,
    /// Builtin/intrinsic call (Math.*, Array.*, etc.).
    BuiltinCall,
    /// Branch/conditional.
    Branch,
    /// Type check or guard.
    TypeCheck,
    /// String operation.
    StringOp,
    /// Allocation.
    Allocation,
}

impl OperationKind {
    pub const ALL: &[Self] = &[
        Self::Arithmetic,
        Self::Comparison,
        Self::Bitwise,
        Self::Load,
        Self::Store,
        Self::Call,
        Self::BuiltinCall,
        Self::Branch,
        Self::TypeCheck,
        Self::StringOp,
        Self::Allocation,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arithmetic => "arithmetic",
            Self::Comparison => "comparison",
            Self::Bitwise => "bitwise",
            Self::Load => "load",
            Self::Store => "store",
            Self::Call => "call",
            Self::BuiltinCall => "builtin_call",
            Self::Branch => "branch",
            Self::TypeCheck => "type_check",
            Self::StringOp => "string_op",
            Self::Allocation => "allocation",
        }
    }

    /// Whether this operation kind has observable side effects.
    pub const fn has_side_effects(self) -> bool {
        matches!(self, Self::Store | Self::Call | Self::Allocation)
    }
}

impl fmt::Display for OperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SideEffectKind
// ---------------------------------------------------------------------------

/// Classification of side effects in a kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectKind {
    /// Writes to object properties.
    PropertyWrite,
    /// Writes to array elements.
    ArrayWrite,
    /// Allocates new objects.
    HeapAllocation,
    /// Calls external functions.
    ExternalCall,
    /// Throws exceptions.
    ThrowsException,
    /// Modifies global state.
    GlobalMutation,
}

impl SideEffectKind {
    pub const ALL: &[Self] = &[
        Self::PropertyWrite,
        Self::ArrayWrite,
        Self::HeapAllocation,
        Self::ExternalCall,
        Self::ThrowsException,
        Self::GlobalMutation,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PropertyWrite => "property_write",
            Self::ArrayWrite => "array_write",
            Self::HeapAllocation => "heap_allocation",
            Self::ExternalCall => "external_call",
            Self::ThrowsException => "throws_exception",
            Self::GlobalMutation => "global_mutation",
        }
    }

    /// Whether synthesis must prove equivalence for this effect.
    pub const fn requires_equivalence_proof(self) -> bool {
        matches!(
            self,
            Self::PropertyWrite | Self::ArrayWrite | Self::ExternalCall | Self::GlobalMutation
        )
    }
}

impl fmt::Display for SideEffectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// KernelSchema
// ---------------------------------------------------------------------------

/// Structural pattern of a hot code region.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KernelSchema {
    /// Unique schema identifier.
    pub schema_id: String,
    /// Operation mix: kind → count.
    pub operation_counts: BTreeMap<OperationKind, u32>,
    /// Total operations.
    pub total_ops: u32,
    /// Maximum branch nesting depth.
    pub branch_depth: u32,
    /// Side effects observed.
    pub side_effects: BTreeSet<SideEffectKind>,
    /// Input shape stability (millionths): how consistently shaped are inputs.
    pub input_shape_stability: u64,
    /// Output shape stability (millionths).
    pub output_shape_stability: u64,
    /// Number of distinct input shapes observed.
    pub input_shape_count: u32,
    /// Number of distinct output shapes observed.
    pub output_shape_count: u32,
    /// Content hash of this schema.
    pub content_hash: ContentHash,
}

impl KernelSchema {
    /// Create a new kernel schema with computed content hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema_id: impl Into<String>,
        operation_counts: BTreeMap<OperationKind, u32>,
        branch_depth: u32,
        side_effects: BTreeSet<SideEffectKind>,
        input_shape_stability: u64,
        output_shape_stability: u64,
        input_shape_count: u32,
        output_shape_count: u32,
    ) -> Self {
        let schema_id = schema_id.into();
        let total_ops: u32 = operation_counts.values().sum();

        let mut h = Sha256::new();
        h.update(schema_id.as_bytes());
        for (k, v) in &operation_counts {
            h.update(k.as_str().as_bytes());
            h.update(v.to_le_bytes());
        }
        h.update(branch_depth.to_le_bytes());
        for se in &side_effects {
            h.update(se.as_str().as_bytes());
        }
        h.update(input_shape_stability.to_le_bytes());
        h.update(output_shape_stability.to_le_bytes());
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            schema_id,
            operation_counts,
            total_ops,
            branch_depth,
            side_effects,
            input_shape_stability,
            output_shape_stability,
            input_shape_count,
            output_shape_count,
            content_hash,
        }
    }

    /// Count of operations for a specific kind.
    pub fn op_count(&self, kind: OperationKind) -> u32 {
        self.operation_counts.get(&kind).copied().unwrap_or(0)
    }

    /// Side effect count.
    pub fn side_effect_count(&self) -> usize {
        self.side_effects.len()
    }

    /// Whether this schema is pure (no side effects).
    pub fn is_pure(&self) -> bool {
        self.side_effects.is_empty()
    }

    /// Whether this schema has stable shapes.
    pub fn has_stable_shapes(&self) -> bool {
        self.input_shape_stability >= MIN_SHAPE_STABILITY
            && self.output_shape_stability >= MIN_SHAPE_STABILITY
    }
}

// ---------------------------------------------------------------------------
// RejectionReason
// ---------------------------------------------------------------------------

/// Reason a kernel is rejected from synthesis.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Too many operations for synthesis budget.
    TooManyOps { count: u32, limit: u32 },
    /// Branch depth exceeds synthesizer capability.
    ExcessiveBranchDepth { depth: u32, limit: u32 },
    /// Too many side effects for provable equivalence.
    TooManySideEffects { count: u32, limit: u32 },
    /// Contains global mutations that cannot be safely synthesized.
    UnsafeGlobalMutation,
    /// Input shapes too unstable for synthesis.
    UnstableInputShapes { stability: u64, threshold: u64 },
    /// Output shapes too unstable.
    UnstableOutputShapes { stability: u64, threshold: u64 },
    /// Schema frequency too low to justify synthesis cost.
    InsufficientFrequency { frequency: u64, threshold: u64 },
    /// Explicitly forbidden by policy.
    ForbiddenByPolicy { policy_note: String },
}

impl RejectionReason {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::TooManyOps { .. } => "too_many_ops",
            Self::ExcessiveBranchDepth { .. } => "excessive_branch_depth",
            Self::TooManySideEffects { .. } => "too_many_side_effects",
            Self::UnsafeGlobalMutation => "unsafe_global_mutation",
            Self::UnstableInputShapes { .. } => "unstable_input_shapes",
            Self::UnstableOutputShapes { .. } => "unstable_output_shapes",
            Self::InsufficientFrequency { .. } => "insufficient_frequency",
            Self::ForbiddenByPolicy { .. } => "forbidden_by_policy",
        }
    }
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyOps { count, limit } => {
                write!(f, "too many ops: {} > {}", count, limit)
            }
            Self::ExcessiveBranchDepth { depth, limit } => {
                write!(f, "branch depth: {} > {}", depth, limit)
            }
            Self::TooManySideEffects { count, limit } => {
                write!(f, "side effects: {} > {}", count, limit)
            }
            Self::UnsafeGlobalMutation => write!(f, "unsafe global mutation"),
            Self::UnstableInputShapes {
                stability,
                threshold,
            } => write!(f, "unstable inputs: {} < {}", stability, threshold),
            Self::UnstableOutputShapes {
                stability,
                threshold,
            } => write!(f, "unstable outputs: {} < {}", stability, threshold),
            Self::InsufficientFrequency {
                frequency,
                threshold,
            } => write!(f, "low frequency: {} < {}", frequency, threshold),
            Self::ForbiddenByPolicy { policy_note } => {
                write!(f, "policy: {}", policy_note)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EligibilityVerdict
// ---------------------------------------------------------------------------

/// Whether a kernel schema is eligible for synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EligibilityVerdict {
    /// Eligible for synthesis.
    Eligible,
    /// Eligible with caveats (some side effects need proofs).
    EligibleWithCaveats { caveats: Vec<String> },
    /// Rejected with explicit reasons.
    Rejected { reasons: Vec<RejectionReason> },
}

impl EligibilityVerdict {
    pub fn is_eligible(&self) -> bool {
        matches!(self, Self::Eligible | Self::EligibleWithCaveats { .. })
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::EligibleWithCaveats { .. } => "eligible_with_caveats",
            Self::Rejected { .. } => "rejected",
        }
    }
}

impl fmt::Display for EligibilityVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eligible => write!(f, "eligible"),
            Self::EligibleWithCaveats { caveats } => {
                write!(f, "eligible with {} caveats", caveats.len())
            }
            Self::Rejected { reasons } => write!(f, "rejected ({} reasons)", reasons.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// EligibilityEntry
// ---------------------------------------------------------------------------

/// An eligibility assessment for one kernel schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityEntry {
    /// The assessed schema ID.
    pub schema_id: String,
    /// Observed frequency (millionths of total kernel invocations).
    pub frequency_millionths: u64,
    /// The eligibility verdict.
    pub verdict: EligibilityVerdict,
}

// ---------------------------------------------------------------------------
// SynthesisEnvelope
// ---------------------------------------------------------------------------

/// The complete synthesis eligibility envelope: which kernels can and cannot
/// be synthesized, with full audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisEnvelope {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch when this envelope was computed.
    pub epoch: SecurityEpoch,
    /// All assessed entries.
    pub entries: Vec<EligibilityEntry>,
    /// Number of eligible schemas.
    pub eligible_count: usize,
    /// Number of rejected schemas.
    pub rejected_count: usize,
    /// Coverage: eligible frequency mass (millionths).
    pub eligible_frequency_mass: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl SynthesisEnvelope {
    /// Compute a synthesis envelope from schemas and their frequencies.
    pub fn compute(
        epoch: SecurityEpoch,
        schemas: &[KernelSchema],
        frequencies: &BTreeMap<String, u64>,
    ) -> Self {
        let mut entries = Vec::new();
        let mut eligible_count = 0;
        let mut rejected_count = 0;
        let mut eligible_frequency_mass: u64 = 0;

        for schema in schemas {
            let freq = frequencies.get(&schema.schema_id).copied().unwrap_or(0);
            let verdict = evaluate_eligibility(schema, freq);
            if verdict.is_eligible() {
                eligible_count += 1;
                eligible_frequency_mass = eligible_frequency_mass.saturating_add(freq);
            } else {
                rejected_count += 1;
            }
            entries.push(EligibilityEntry {
                schema_id: schema.schema_id.clone(),
                frequency_millionths: freq,
                verdict,
            });
        }

        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update((entries.len() as u64).to_le_bytes());
        for e in &entries {
            h.update(e.schema_id.as_bytes());
            h.update(e.frequency_millionths.to_le_bytes());
            h.update(e.verdict.tag().as_bytes());
        }
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            entries,
            eligible_count,
            rejected_count,
            eligible_frequency_mass,
            content_hash,
        }
    }

    /// Total assessed schemas.
    pub fn total_count(&self) -> usize {
        self.entries.len()
    }

    /// Eligibility rate (millionths).
    pub fn eligibility_rate(&self) -> u64 {
        let total = self.entries.len() as u64;
        (self.eligible_count as u64)
            .saturating_mul(MILLION)
            .checked_div(total)
            .unwrap_or(0)
    }

    /// Look up the verdict for a specific schema.
    pub fn verdict_for(&self, schema_id: &str) -> Option<&EligibilityVerdict> {
        self.entries
            .iter()
            .find(|e| e.schema_id == schema_id)
            .map(|e| &e.verdict)
    }

    /// Collect all eligible schema IDs.
    pub fn eligible_ids(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.verdict.is_eligible())
            .map(|e| e.schema_id.as_str())
            .collect()
    }

    /// Collect all rejected schema IDs.
    pub fn rejected_ids(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.verdict.is_rejected())
            .map(|e| e.schema_id.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Eligibility evaluation
// ---------------------------------------------------------------------------

/// Evaluate whether a kernel schema is eligible for synthesis.
pub fn evaluate_eligibility(schema: &KernelSchema, frequency: u64) -> EligibilityVerdict {
    let mut reasons = Vec::new();

    // Check frequency threshold
    if frequency < HOT_SCHEMA_THRESHOLD {
        reasons.push(RejectionReason::InsufficientFrequency {
            frequency,
            threshold: HOT_SCHEMA_THRESHOLD,
        });
    }

    // Check operation count
    if schema.total_ops > MAX_SYNTHESIZABLE_OPS {
        reasons.push(RejectionReason::TooManyOps {
            count: schema.total_ops,
            limit: MAX_SYNTHESIZABLE_OPS,
        });
    }

    // Check branch depth
    if schema.branch_depth > MAX_SYNTHESIZABLE_BRANCH_DEPTH {
        reasons.push(RejectionReason::ExcessiveBranchDepth {
            depth: schema.branch_depth,
            limit: MAX_SYNTHESIZABLE_BRANCH_DEPTH,
        });
    }

    // Check side effect count
    if schema.side_effect_count() as u32 > MAX_SIDE_EFFECTS {
        reasons.push(RejectionReason::TooManySideEffects {
            count: schema.side_effect_count() as u32,
            limit: MAX_SIDE_EFFECTS,
        });
    }

    // Check for unsafe global mutation
    if schema
        .side_effects
        .contains(&SideEffectKind::GlobalMutation)
    {
        reasons.push(RejectionReason::UnsafeGlobalMutation);
    }

    // Check shape stability
    if schema.input_shape_stability < MIN_SHAPE_STABILITY {
        reasons.push(RejectionReason::UnstableInputShapes {
            stability: schema.input_shape_stability,
            threshold: MIN_SHAPE_STABILITY,
        });
    }
    if schema.output_shape_stability < MIN_SHAPE_STABILITY {
        reasons.push(RejectionReason::UnstableOutputShapes {
            stability: schema.output_shape_stability,
            threshold: MIN_SHAPE_STABILITY,
        });
    }

    if !reasons.is_empty() {
        return EligibilityVerdict::Rejected { reasons };
    }

    // Check for caveats (side effects that need proofs)
    let proof_needed: Vec<String> = schema
        .side_effects
        .iter()
        .filter(|se| se.requires_equivalence_proof())
        .map(|se| format!("{} requires equivalence proof", se.as_str()))
        .collect();

    if proof_needed.is_empty() {
        EligibilityVerdict::Eligible
    } else {
        EligibilityVerdict::EligibleWithCaveats {
            caveats: proof_needed,
        }
    }
}

// ---------------------------------------------------------------------------
// KernelCorpus
// ---------------------------------------------------------------------------

/// A collection of observed kernel schemas with frequency tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelCorpus {
    /// All observed schemas.
    pub schemas: Vec<KernelSchema>,
    /// Schema ID → observation count.
    pub observation_counts: BTreeMap<String, u64>,
    /// Total observations across all schemas.
    pub total_observations: u64,
}

impl KernelCorpus {
    /// Create an empty corpus.
    pub fn new() -> Self {
        Self {
            schemas: Vec::new(),
            observation_counts: BTreeMap::new(),
            total_observations: 0,
        }
    }

    /// Record an observation of a kernel schema.
    pub fn observe(&mut self, schema: KernelSchema, count: u64) {
        let id = schema.schema_id.clone();
        *self.observation_counts.entry(id.clone()).or_insert(0) += count;
        self.total_observations = self.total_observations.saturating_add(count);
        if !self.schemas.iter().any(|s| s.schema_id == id) {
            self.schemas.push(schema);
        }
    }

    /// Number of distinct schemas.
    pub fn schema_count(&self) -> usize {
        self.schemas.len()
    }

    /// Compute frequencies (millionths) for all schemas.
    pub fn frequencies(&self) -> BTreeMap<String, u64> {
        self.observation_counts
            .iter()
            .map(|(id, count)| {
                let freq = count
                    .saturating_mul(MILLION)
                    .checked_div(self.total_observations)
                    .unwrap_or(0);
                (id.clone(), freq)
            })
            .collect()
    }

    /// Get schemas above the hot threshold.
    pub fn hot_schemas(&self) -> Vec<&KernelSchema> {
        let freqs = self.frequencies();
        self.schemas
            .iter()
            .filter(|s| freqs.get(&s.schema_id).copied().unwrap_or(0) >= HOT_SCHEMA_THRESHOLD)
            .collect()
    }

    /// Compute the synthesis envelope for this corpus.
    pub fn compute_envelope(&self, epoch: SecurityEpoch) -> SynthesisEnvelope {
        let freqs = self.frequencies();
        SynthesisEnvelope::compute(epoch, &self.schemas, &freqs)
    }
}

impl Default for KernelCorpus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(400)
    }

    fn pure_arithmetic_schema(id: &str) -> KernelSchema {
        let mut ops = BTreeMap::new();
        ops.insert(OperationKind::Arithmetic, 10);
        ops.insert(OperationKind::Load, 5);
        ops.insert(OperationKind::Comparison, 2);
        KernelSchema::new(id, ops, 2, BTreeSet::new(), 950_000, 980_000, 1, 1)
    }

    fn side_effect_schema(id: &str) -> KernelSchema {
        let mut ops = BTreeMap::new();
        ops.insert(OperationKind::Arithmetic, 5);
        ops.insert(OperationKind::Store, 3);
        let effects = BTreeSet::from([SideEffectKind::PropertyWrite, SideEffectKind::ArrayWrite]);
        KernelSchema::new(id, ops, 1, effects, 920_000, 950_000, 2, 1)
    }

    fn oversized_schema(id: &str) -> KernelSchema {
        let mut ops = BTreeMap::new();
        ops.insert(OperationKind::Arithmetic, 300);
        KernelSchema::new(id, ops, 10, BTreeSet::new(), 500_000, 500_000, 5, 5)
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "synthesis_eligibility_envelope");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
    }

    #[test]
    fn thresholds_positive() {
        assert!(MAX_SYNTHESIZABLE_BRANCH_DEPTH > 0);
        assert!(MAX_SYNTHESIZABLE_OPS > 0);
        assert!(HOT_SCHEMA_THRESHOLD > 0);
        assert!(MAX_SIDE_EFFECTS > 0);
        assert!(MIN_SHAPE_STABILITY > 0);
        assert!(MIN_SHAPE_STABILITY <= MILLION);
    }

    // --- OperationKind ---

    #[test]
    fn op_kind_all_length() {
        assert_eq!(OperationKind::ALL.len(), 11);
    }

    #[test]
    fn op_kind_names_unique() {
        let names: BTreeSet<&str> = OperationKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), OperationKind::ALL.len());
    }

    #[test]
    fn op_kind_side_effects() {
        assert!(OperationKind::Store.has_side_effects());
        assert!(OperationKind::Call.has_side_effects());
        assert!(OperationKind::Allocation.has_side_effects());
        assert!(!OperationKind::Arithmetic.has_side_effects());
        assert!(!OperationKind::Load.has_side_effects());
    }

    #[test]
    fn op_kind_display() {
        for k in OperationKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn op_kind_serde() {
        for k in OperationKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: OperationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- SideEffectKind ---

    #[test]
    fn side_effect_all_length() {
        assert_eq!(SideEffectKind::ALL.len(), 6);
    }

    #[test]
    fn side_effect_names_unique() {
        let names: BTreeSet<&str> = SideEffectKind::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), SideEffectKind::ALL.len());
    }

    #[test]
    fn side_effect_proof_requirements() {
        assert!(SideEffectKind::PropertyWrite.requires_equivalence_proof());
        assert!(SideEffectKind::ArrayWrite.requires_equivalence_proof());
        assert!(SideEffectKind::ExternalCall.requires_equivalence_proof());
        assert!(SideEffectKind::GlobalMutation.requires_equivalence_proof());
        assert!(!SideEffectKind::HeapAllocation.requires_equivalence_proof());
        assert!(!SideEffectKind::ThrowsException.requires_equivalence_proof());
    }

    #[test]
    fn side_effect_display() {
        for s in SideEffectKind::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn side_effect_serde() {
        for s in SideEffectKind::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: SideEffectKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- KernelSchema ---

    #[test]
    fn schema_pure_arithmetic() {
        let s = pure_arithmetic_schema("s1");
        assert_eq!(s.total_ops, 17);
        assert!(s.is_pure());
        assert!(s.has_stable_shapes());
        assert_eq!(s.op_count(OperationKind::Arithmetic), 10);
        assert_eq!(s.op_count(OperationKind::Branch), 0);
    }

    #[test]
    fn schema_with_side_effects() {
        let s = side_effect_schema("s2");
        assert!(!s.is_pure());
        assert_eq!(s.side_effect_count(), 2);
    }

    #[test]
    fn schema_hash_deterministic() {
        let s1 = pure_arithmetic_schema("s1");
        let s2 = pure_arithmetic_schema("s1");
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn schema_different_ops_different_hash() {
        let s1 = pure_arithmetic_schema("s1");
        let s2 = side_effect_schema("s1");
        assert_ne!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn schema_serde_roundtrip() {
        let s = side_effect_schema("test");
        let json = serde_json::to_string(&s).unwrap();
        let back: KernelSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- RejectionReason ---

    #[test]
    fn rejection_tags_unique() {
        let reasons = vec![
            RejectionReason::TooManyOps {
                count: 300,
                limit: 256,
            },
            RejectionReason::ExcessiveBranchDepth {
                depth: 10,
                limit: 8,
            },
            RejectionReason::TooManySideEffects { count: 5, limit: 4 },
            RejectionReason::UnsafeGlobalMutation,
            RejectionReason::UnstableInputShapes {
                stability: 500_000,
                threshold: 900_000,
            },
            RejectionReason::UnstableOutputShapes {
                stability: 500_000,
                threshold: 900_000,
            },
            RejectionReason::InsufficientFrequency {
                frequency: 1000,
                threshold: 10_000,
            },
            RejectionReason::ForbiddenByPolicy {
                policy_note: "test".into(),
            },
        ];
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), 8);
    }

    #[test]
    fn rejection_display_content() {
        let r = RejectionReason::TooManyOps {
            count: 300,
            limit: 256,
        };
        let s = r.to_string();
        assert!(s.contains("300"));
        assert!(s.contains("256"));
    }

    #[test]
    fn rejection_serde() {
        let r = RejectionReason::ExcessiveBranchDepth {
            depth: 12,
            limit: 8,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- EligibilityVerdict ---

    #[test]
    fn verdict_eligible() {
        let v = EligibilityVerdict::Eligible;
        assert!(v.is_eligible());
        assert!(!v.is_rejected());
        assert_eq!(v.tag(), "eligible");
    }

    #[test]
    fn verdict_eligible_with_caveats() {
        let v = EligibilityVerdict::EligibleWithCaveats {
            caveats: vec!["proof needed".into()],
        };
        assert!(v.is_eligible());
        assert!(!v.is_rejected());
    }

    #[test]
    fn verdict_rejected() {
        let v = EligibilityVerdict::Rejected {
            reasons: vec![RejectionReason::UnsafeGlobalMutation],
        };
        assert!(!v.is_eligible());
        assert!(v.is_rejected());
    }

    #[test]
    fn verdict_display() {
        let v = EligibilityVerdict::Rejected {
            reasons: vec![
                RejectionReason::UnsafeGlobalMutation,
                RejectionReason::TooManyOps {
                    count: 300,
                    limit: 256,
                },
            ],
        };
        assert!(v.to_string().contains("2 reasons"));
    }

    #[test]
    fn verdict_serde() {
        let v = EligibilityVerdict::EligibleWithCaveats {
            caveats: vec!["test caveat".into()],
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: EligibilityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // --- evaluate_eligibility ---

    #[test]
    fn eligible_pure_schema() {
        let s = pure_arithmetic_schema("s1");
        let v = evaluate_eligibility(&s, 50_000);
        assert!(v.is_eligible());
        assert_eq!(v.tag(), "eligible");
    }

    #[test]
    fn eligible_with_caveats_side_effects() {
        let s = side_effect_schema("s1");
        let v = evaluate_eligibility(&s, 50_000);
        assert!(v.is_eligible());
        assert_eq!(v.tag(), "eligible_with_caveats");
    }

    #[test]
    fn rejected_low_frequency() {
        let s = pure_arithmetic_schema("s1");
        let v = evaluate_eligibility(&s, 1_000);
        assert!(v.is_rejected());
    }

    #[test]
    fn rejected_oversized() {
        let s = oversized_schema("s1");
        let v = evaluate_eligibility(&s, 50_000);
        assert!(v.is_rejected());
    }

    #[test]
    fn rejected_global_mutation() {
        let mut ops = BTreeMap::new();
        ops.insert(OperationKind::Store, 1);
        let effects = BTreeSet::from([SideEffectKind::GlobalMutation]);
        let s = KernelSchema::new("gm", ops, 1, effects, 950_000, 950_000, 1, 1);
        let v = evaluate_eligibility(&s, 100_000);
        assert!(v.is_rejected());
    }

    // --- SynthesisEnvelope ---

    #[test]
    fn envelope_empty() {
        let e = SynthesisEnvelope::compute(epoch(), &[], &BTreeMap::new());
        assert_eq!(e.total_count(), 0);
        assert_eq!(e.eligible_count, 0);
        assert_eq!(e.rejected_count, 0);
        assert_eq!(e.eligibility_rate(), 0);
    }

    #[test]
    fn envelope_mixed() {
        let schemas = vec![pure_arithmetic_schema("good"), oversized_schema("bad")];
        let mut freqs = BTreeMap::new();
        freqs.insert("good".into(), 100_000);
        freqs.insert("bad".into(), 50_000);
        let e = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
        assert_eq!(e.eligible_count, 1);
        assert_eq!(e.rejected_count, 1);
        assert_eq!(e.eligible_frequency_mass, 100_000);
    }

    #[test]
    fn envelope_verdict_lookup() {
        let schemas = vec![pure_arithmetic_schema("s1")];
        let mut freqs = BTreeMap::new();
        freqs.insert("s1".into(), 50_000);
        let e = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
        assert!(e.verdict_for("s1").unwrap().is_eligible());
        assert!(e.verdict_for("nonexistent").is_none());
    }

    #[test]
    fn envelope_eligible_ids() {
        let schemas = vec![
            pure_arithmetic_schema("good1"),
            pure_arithmetic_schema("good2"),
            oversized_schema("bad"),
        ];
        let mut freqs = BTreeMap::new();
        freqs.insert("good1".into(), 100_000);
        freqs.insert("good2".into(), 50_000);
        freqs.insert("bad".into(), 50_000);
        let e = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
        let ids = e.eligible_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"good1"));
        assert!(ids.contains(&"good2"));
    }

    #[test]
    fn envelope_hash_deterministic() {
        let schemas = vec![pure_arithmetic_schema("s1")];
        let mut freqs = BTreeMap::new();
        freqs.insert("s1".into(), 50_000);
        let e1 = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
        let e2 = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
        assert_eq!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let schemas = vec![pure_arithmetic_schema("s1"), side_effect_schema("s2")];
        let mut freqs = BTreeMap::new();
        freqs.insert("s1".into(), 50_000);
        freqs.insert("s2".into(), 80_000);
        let e = SynthesisEnvelope::compute(epoch(), &schemas, &freqs);
        let json = serde_json::to_string(&e).unwrap();
        let back: SynthesisEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- KernelCorpus ---

    #[test]
    fn corpus_empty() {
        let c = KernelCorpus::new();
        assert_eq!(c.schema_count(), 0);
        assert_eq!(c.total_observations, 0);
    }

    #[test]
    fn corpus_observe() {
        let mut c = KernelCorpus::new();
        c.observe(pure_arithmetic_schema("s1"), 100);
        assert_eq!(c.schema_count(), 1);
        assert_eq!(c.total_observations, 100);
    }

    #[test]
    fn corpus_observe_duplicate() {
        let mut c = KernelCorpus::new();
        c.observe(pure_arithmetic_schema("s1"), 50);
        c.observe(pure_arithmetic_schema("s1"), 30);
        assert_eq!(c.schema_count(), 1);
        assert_eq!(c.total_observations, 80);
        assert_eq!(*c.observation_counts.get("s1").unwrap(), 80);
    }

    #[test]
    fn corpus_frequencies() {
        let mut c = KernelCorpus::new();
        c.observe(pure_arithmetic_schema("s1"), 500);
        c.observe(side_effect_schema("s2"), 500);
        let freqs = c.frequencies();
        assert_eq!(freqs.get("s1").copied(), Some(500_000));
        assert_eq!(freqs.get("s2").copied(), Some(500_000));
    }

    #[test]
    fn corpus_hot_schemas() {
        let mut c = KernelCorpus::new();
        c.observe(pure_arithmetic_schema("hot"), 900);
        c.observe(side_effect_schema("cold"), 1);
        let hot = c.hot_schemas();
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].schema_id, "hot");
    }

    #[test]
    fn corpus_compute_envelope() {
        let mut c = KernelCorpus::new();
        c.observe(pure_arithmetic_schema("good"), 800);
        c.observe(oversized_schema("bad"), 200);
        let e = c.compute_envelope(epoch());
        assert_eq!(e.total_count(), 2);
        assert_eq!(e.eligible_count, 1);
        assert_eq!(e.rejected_count, 1);
    }

    #[test]
    fn corpus_serde_roundtrip() {
        let mut c = KernelCorpus::new();
        c.observe(pure_arithmetic_schema("s1"), 100);
        let json = serde_json::to_string(&c).unwrap();
        let back: KernelCorpus = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn corpus_default() {
        let c = KernelCorpus::default();
        assert_eq!(c.schema_count(), 0);
    }
}
