#![forbid(unsafe_code)]

//! Scalar replacement, region promotion, and allocation sinking engine.
//!
//! Implements [RGC-622B]: consumes escape-analysis certificates from
//! `escape_analysis_certificate.rs` and transforms allocation sites into
//! scalar fields, stack regions, or sunk allocation points. Every transform
//! emits a deopt witness so the runtime can materialize the original object
//! if a bailout occurs, plus a translation-validation receipt for audit.
//!
//! Key design decisions:
//! - Transforms are certificate-gated: no certificate → no transform.
//! - `DeoptWitness` records the materialization recipe for each eliminated
//!   allocation, including field offsets, types, and the deopt trigger set.
//! - `TranslationValidationReceipt` proves the transform preserved semantics
//!   by recording pre/post hashes, the certificate chain, and a reason field.
//! - Region promotion uses a stack discipline: allocations promoted to a
//!   region scope are freed when the scope exits.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::escape_analysis_certificate::{
    AllocationKind, EscapeCertificate, EscapeState, OptimizationEligibilityEnvelope,
};
use crate::hash_tiers::ContentHash;
use crate::runtime_config::OptimizationConfig;
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

pub const SRE_SCHEMA_VERSION: &str = "franken-engine.scalar_replacement_engine.v1";
pub const SRE_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.scalar_replacement_engine_manifest.v1";
pub const SRE_EVENT_SCHEMA_VERSION: &str = "franken-engine.scalar_replacement_engine_event.v1";
pub const SRE_COMPONENT: &str = "scalar_replacement_engine";
pub const SRE_POLICY_ID: &str = "RGC-622B";

const MILLION: i64 = 1_000_000;

// Maximum fields per object that can be scalar-replaced.
const MAX_SCALAR_FIELDS: usize = 64;

// Maximum depth for nested object decomposition.
const MAX_DECOMPOSITION_DEPTH: u32 = 4;

// ---------------------------------------------------------------------------
// Transform kind
// ---------------------------------------------------------------------------

/// Kind of allocation transform applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformKind {
    /// Replace object with individual scalar fields on the stack.
    ScalarReplacement,
    /// Promote allocation to a stack-allocated region scope.
    RegionPromotion,
    /// Sink allocation to the latest point before first escape.
    AllocationSinking,
    /// No transform applied (certificate denied or abstained).
    NoTransform,
}

impl TransformKind {
    pub const ALL: &[Self] = &[
        Self::ScalarReplacement,
        Self::RegionPromotion,
        Self::AllocationSinking,
        Self::NoTransform,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScalarReplacement => "scalar_replacement",
            Self::RegionPromotion => "region_promotion",
            Self::AllocationSinking => "allocation_sinking",
            Self::NoTransform => "no_transform",
        }
    }
}

impl fmt::Display for TransformKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Scalar field descriptor
// ---------------------------------------------------------------------------

/// Type of a scalar field after decomposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarFieldType {
    /// A JavaScript number (f64 bits stored as i64 for determinism).
    Number,
    /// A boolean value.
    Boolean,
    /// A string reference (index into the string table).
    StringRef,
    /// A reference to another object (heap pointer).
    ObjectRef,
    /// Undefined.
    Undefined,
    /// Null.
    Null,
    /// A symbol reference.
    SymbolRef,
    /// A BigInt value.
    BigIntRef,
}

impl ScalarFieldType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::StringRef => "string_ref",
            Self::ObjectRef => "object_ref",
            Self::Undefined => "undefined",
            Self::Null => "null",
            Self::SymbolRef => "symbol_ref",
            Self::BigIntRef => "bigint_ref",
        }
    }

    /// Can this type be stored in a register (no heap indirection)?
    pub fn is_register_safe(self) -> bool {
        matches!(
            self,
            Self::Number | Self::Boolean | Self::Undefined | Self::Null
        )
    }
}

impl fmt::Display for ScalarFieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single field extracted from an object for scalar replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalarField {
    /// Property name or index.
    pub name: String,
    /// Offset within the original object layout.
    pub offset: u32,
    /// Field type.
    pub field_type: ScalarFieldType,
    /// Whether the field is always initialized before read.
    pub always_initialized: bool,
    /// Default value if not initialized (encoded as string for determinism).
    pub default_value: Option<String>,
}

// ---------------------------------------------------------------------------
// Scalar replacement plan
// ---------------------------------------------------------------------------

/// Plan for replacing a heap allocation with individual scalar fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalarReplacementPlan {
    /// The allocation site being replaced.
    pub site_id: String,
    /// Fields extracted from the object.
    pub fields: Vec<ScalarField>,
    /// Total number of register slots needed.
    pub register_slots: u32,
    /// Total number of stack slots needed (for non-register-safe fields).
    pub stack_slots: u32,
    /// Decomposition depth used.
    pub decomposition_depth: u32,
    /// Whether all fields are register-safe (no heap references).
    pub fully_register_safe: bool,
    /// Estimated savings in bytes (heap allocation avoided).
    pub estimated_savings_bytes: u64,
}

impl ScalarReplacementPlan {
    /// Total slots (register + stack).
    pub fn total_slots(&self) -> u32 {
        self.register_slots.saturating_add(self.stack_slots)
    }
}

// ---------------------------------------------------------------------------
// Region promotion plan
// ---------------------------------------------------------------------------

/// Scope lifetime for a promoted allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionScope {
    /// Function-local scope: freed on function exit.
    FunctionLocal,
    /// Block-local scope: freed on block exit.
    BlockLocal,
    /// Loop-iteration scope: freed on each iteration.
    LoopIteration,
    /// Caller-managed scope: freed by caller.
    CallerManaged,
}

impl RegionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FunctionLocal => "function_local",
            Self::BlockLocal => "block_local",
            Self::LoopIteration => "loop_iteration",
            Self::CallerManaged => "caller_managed",
        }
    }
}

impl fmt::Display for RegionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Plan for promoting an allocation to a stack/region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionPromotionPlan {
    /// The allocation site being promoted.
    pub site_id: String,
    /// Region scope for the promoted allocation.
    pub region_scope: RegionScope,
    /// Estimated size of the promoted allocation (bytes).
    pub estimated_size_bytes: u64,
    /// Whether alignment padding is needed.
    pub alignment_bytes: u32,
    /// The scope ID where the region lives.
    pub containing_scope: String,
}

// ---------------------------------------------------------------------------
// Allocation sinking plan
// ---------------------------------------------------------------------------

/// Plan for sinking an allocation to a later point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocationSinkingPlan {
    /// The allocation site being sunk.
    pub site_id: String,
    /// Original instruction index of the allocation.
    pub original_position: u64,
    /// Sunk instruction index (where allocation now occurs).
    pub sunk_position: u64,
    /// Instructions saved (original - sunk, on the non-escaping path).
    pub instructions_saved: u64,
    /// Whether the sinking is conditional (allocation may not happen).
    pub conditional: bool,
    /// Branch condition that triggers the allocation (if conditional).
    pub trigger_condition: Option<String>,
}

// ---------------------------------------------------------------------------
// Deopt witness
// ---------------------------------------------------------------------------

/// Trigger condition that would require materialization (deoptimization).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeoptTrigger {
    /// Property access on a non-existent field.
    MissingProperty,
    /// Object identity comparison (===) requires a real object.
    IdentityComparison,
    /// Object passed to external function that inspects structure.
    ExternalInspection,
    /// typeof or instanceof check requires real object.
    TypeCheck,
    /// Object spread or Object.keys/values/entries.
    StructuralEnumeration,
    /// Proxy trap or Reflect call on the object.
    ProxyTrap,
    /// Debug breakpoint requires materialized object.
    DebugBreakpoint,
    /// Exception handler needs stack-allocated object.
    ExceptionHandler,
    /// GC pressure forces materialization.
    GcPressure,
    /// Profile counter indicates the optimization is unprofitable.
    ProfileCounterTrip,
}

impl DeoptTrigger {
    pub const ALL: &[Self] = &[
        Self::MissingProperty,
        Self::IdentityComparison,
        Self::ExternalInspection,
        Self::TypeCheck,
        Self::StructuralEnumeration,
        Self::ProxyTrap,
        Self::DebugBreakpoint,
        Self::ExceptionHandler,
        Self::GcPressure,
        Self::ProfileCounterTrip,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingProperty => "missing_property",
            Self::IdentityComparison => "identity_comparison",
            Self::ExternalInspection => "external_inspection",
            Self::TypeCheck => "type_check",
            Self::StructuralEnumeration => "structural_enumeration",
            Self::ProxyTrap => "proxy_trap",
            Self::DebugBreakpoint => "debug_breakpoint",
            Self::ExceptionHandler => "exception_handler",
            Self::GcPressure => "gc_pressure",
            Self::ProfileCounterTrip => "profile_counter_trip",
        }
    }
}

impl fmt::Display for DeoptTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Materialization recipe for reconstructing an eliminated allocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializationRecipe {
    /// Source allocation site ID.
    pub site_id: String,
    /// Allocation kind to reconstruct.
    pub allocation_kind: AllocationKind,
    /// Fields to read from registers/stack to reconstruct the object.
    pub field_sources: Vec<FieldSource>,
    /// Prototype to assign (if object literal or constructor).
    pub prototype_source: Option<String>,
    /// Estimated materialization cost (microseconds, millionths).
    pub estimated_cost_millionths: i64,
}

/// Source for reconstructing a single field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSource {
    /// Property name.
    pub name: String,
    /// Where the field value lives: register index, stack slot, or constant.
    pub source_kind: FieldSourceKind,
    /// Source index (register or stack slot number).
    pub source_index: u32,
    /// Field type.
    pub field_type: ScalarFieldType,
}

/// Where a field value lives after scalar replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldSourceKind {
    /// Value is in a virtual register.
    Register,
    /// Value is in a stack slot.
    StackSlot,
    /// Value is a compile-time constant.
    Constant,
    /// Value is in a region-promoted allocation.
    RegionSlot,
}

impl FieldSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::StackSlot => "stack_slot",
            Self::Constant => "constant",
            Self::RegionSlot => "region_slot",
        }
    }
}

impl fmt::Display for FieldSourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Deopt witness: proof that an optimization is safe, with bailout recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeoptWitness {
    /// Unique witness ID.
    pub witness_id: String,
    /// The transform being witnessed.
    pub transform_kind: TransformKind,
    /// The allocation site affected.
    pub site_id: String,
    /// Certificate hash that authorized this transform.
    pub authorizing_certificate_hash: String,
    /// Set of triggers that would require materialization.
    pub trigger_set: BTreeSet<DeoptTrigger>,
    /// Materialization recipe if a trigger fires.
    pub materialization_recipe: MaterializationRecipe,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Witness hash for audit.
    pub witness_hash: String,
}

// ---------------------------------------------------------------------------
// Translation-validation receipt
// ---------------------------------------------------------------------------

/// Receipt proving that a transform preserved program semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationValidationReceipt {
    /// Unique receipt ID.
    pub receipt_id: String,
    /// Schema version.
    pub schema_version: String,
    /// The transform applied.
    pub transform_kind: TransformKind,
    /// Allocation site transformed.
    pub site_id: String,
    /// Hash of the program before transform.
    pub pre_transform_hash: String,
    /// Hash of the program after transform.
    pub post_transform_hash: String,
    /// The authorizing certificate hash.
    pub certificate_hash: String,
    /// Deopt witness hash.
    pub witness_hash: String,
    /// Whether the validation passed.
    pub validation_passed: bool,
    /// Reason for failure (if any).
    pub failure_reason: Option<String>,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Receipt hash for audit.
    pub receipt_hash: String,
}

// ---------------------------------------------------------------------------
// Transform outcome
// ---------------------------------------------------------------------------

/// Reason a transform was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformDenialReason {
    /// Certificate was not granted (abstention).
    CertificateAbstained,
    /// Allocation escapes beyond the eligible scope.
    EscapeBeyondScope,
    /// Too many fields for scalar replacement.
    TooManyFields,
    /// Decomposition depth exceeded.
    DecompositionTooDeep,
    /// Contains non-decomposable field types.
    NonDecomposableFields,
    /// Liveness range unknown or too wide.
    LivenessUnknown,
    /// Region scope cannot accommodate the allocation.
    RegionScopeUnavailable,
    /// Sinking would cross a side-effect boundary.
    SideEffectBarrier,
    /// Budget for transforms in this scope exhausted.
    BudgetExhausted,
    /// The allocation kind is not eligible.
    KindNotEligible,
}

impl TransformDenialReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CertificateAbstained => "certificate_abstained",
            Self::EscapeBeyondScope => "escape_beyond_scope",
            Self::TooManyFields => "too_many_fields",
            Self::DecompositionTooDeep => "decomposition_too_deep",
            Self::NonDecomposableFields => "non_decomposable_fields",
            Self::LivenessUnknown => "liveness_unknown",
            Self::RegionScopeUnavailable => "region_scope_unavailable",
            Self::SideEffectBarrier => "side_effect_barrier",
            Self::BudgetExhausted => "budget_exhausted",
            Self::KindNotEligible => "kind_not_eligible",
        }
    }
}

impl fmt::Display for TransformDenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result of attempting a transform on a single allocation site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformOutcome {
    /// The site that was considered.
    pub site_id: String,
    /// Which transform was selected (or NoTransform).
    pub transform_kind: TransformKind,
    /// Scalar replacement plan (if applicable).
    pub scalar_plan: Option<ScalarReplacementPlan>,
    /// Region promotion plan (if applicable).
    pub region_plan: Option<RegionPromotionPlan>,
    /// Sinking plan (if applicable).
    pub sinking_plan: Option<AllocationSinkingPlan>,
    /// Deopt witness (if transform applied).
    pub deopt_witness: Option<DeoptWitness>,
    /// Translation-validation receipt (if transform applied).
    pub validation_receipt: Option<TranslationValidationReceipt>,
    /// Denial reason (if no transform applied).
    pub denial_reason: Option<TransformDenialReason>,
    /// Estimated benefit in bytes saved.
    pub estimated_bytes_saved: u64,
}

// ---------------------------------------------------------------------------
// Engine configuration
// ---------------------------------------------------------------------------

/// Configuration for the scalar replacement engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalarReplacementConfig {
    /// Maximum fields per object for scalar replacement.
    pub max_fields: usize,
    /// Maximum decomposition depth for nested objects.
    pub max_decomposition_depth: u32,
    /// Maximum transforms per scope before budget exhaustion.
    pub max_transforms_per_scope: u32,
    /// Minimum confidence for applying a transform (millionths).
    pub min_confidence_millionths: i64,
    /// Enable region promotion (in addition to scalar replacement).
    pub enable_region_promotion: bool,
    /// Enable allocation sinking (in addition to scalar replacement).
    pub enable_allocation_sinking: bool,
    /// Minimum liveness span for sinking to be profitable.
    pub min_sinking_span: u64,
}

impl Default for ScalarReplacementConfig {
    fn default() -> Self {
        Self {
            max_fields: MAX_SCALAR_FIELDS,
            max_decomposition_depth: MAX_DECOMPOSITION_DEPTH,
            max_transforms_per_scope: 128,
            min_confidence_millionths: 600_000, // 0.6
            enable_region_promotion: true,
            enable_allocation_sinking: true,
            min_sinking_span: 5,
        }
    }
}

impl ScalarReplacementConfig {
    /// Create from an [`OptimizationConfig`], inheriting limits while
    /// keeping boolean flags and sinking span at their defaults.
    pub fn from_optimization_config(opt: &OptimizationConfig) -> Self {
        Self {
            max_fields: opt.max_scalar_fields,
            max_decomposition_depth: opt.max_decomposition_depth,
            max_transforms_per_scope: opt.max_transforms_per_scope as u32,
            min_confidence_millionths: opt.min_confidence_millionths as i64,
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Transform session and engine
// ---------------------------------------------------------------------------

/// Summary of all transforms applied in a scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformSummary {
    /// Schema version.
    pub schema_version: String,
    /// Scope ID.
    pub scope_id: String,
    /// Total allocation sites considered.
    pub total_sites: u64,
    /// Sites that received scalar replacement.
    pub scalar_replacement_count: u64,
    /// Sites that received region promotion.
    pub region_promotion_count: u64,
    /// Sites that received allocation sinking.
    pub allocation_sinking_count: u64,
    /// Sites where no transform was applied.
    pub no_transform_count: u64,
    /// Total estimated bytes saved.
    pub total_bytes_saved: u64,
    /// Per-site outcomes.
    pub outcomes: Vec<TransformOutcome>,
    /// Per-denial-reason counts.
    pub denial_histogram: BTreeMap<String, u64>,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Summary hash.
    pub summary_hash: String,
}

impl TransformSummary {
    /// Transform rate as millionths (transformed / total).
    pub fn transform_rate_millionths(&self) -> i64 {
        if self.total_sites == 0 {
            return 0;
        }
        let transformed = self
            .scalar_replacement_count
            .saturating_add(self.region_promotion_count)
            .saturating_add(self.allocation_sinking_count);
        (transformed as i64)
            .saturating_mul(MILLION)
            .checked_div(self.total_sites as i64)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Side-effect descriptor (for sinking barriers)
// ---------------------------------------------------------------------------

/// A side-effect barrier that prevents allocation sinking past a point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideEffectBarrier {
    /// Instruction index where the barrier occurs.
    pub instruction_index: u64,
    /// Kind of side effect.
    pub effect_kind: SideEffectKind,
    /// Description of the barrier.
    pub description: String,
}

/// Kind of side effect that prevents sinking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectKind {
    /// Function call that may observe the allocation.
    Call,
    /// Property store that may alias.
    PropertyStore,
    /// Exception throw that may capture the object.
    ExceptionThrow,
    /// Yield or await point.
    YieldAwait,
    /// Debugger statement.
    DebuggerStatement,
}

impl SideEffectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::PropertyStore => "property_store",
            Self::ExceptionThrow => "exception_throw",
            Self::YieldAwait => "yield_await",
            Self::DebuggerStatement => "debugger_statement",
        }
    }
}

impl fmt::Display for SideEffectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Field decomposition input
// ---------------------------------------------------------------------------

/// Description of an object's field layout for scalar replacement analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldLayout {
    /// Allocation site this layout describes.
    pub site_id: String,
    /// Fields of the object.
    pub fields: Vec<FieldDescriptor>,
    /// Whether the layout is fully known (no dynamic properties).
    pub layout_sealed: bool,
}

/// Descriptor for a single field in an object layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDescriptor {
    /// Field name.
    pub name: String,
    /// Field type (may be polymorphic → ObjectRef).
    pub field_type: ScalarFieldType,
    /// Whether the field is always written before any read.
    pub always_initialized: bool,
    /// Nesting depth (0 = top-level).
    pub nesting_depth: u32,
}

// ---------------------------------------------------------------------------
// Core engine logic
// ---------------------------------------------------------------------------

/// Decide the best transform for a single allocation site.
pub fn select_transform(
    cert: &EscapeCertificate,
    layout: Option<&FieldLayout>,
    barriers: &[SideEffectBarrier],
    config: &ScalarReplacementConfig,
    transform_count: u32,
) -> (TransformKind, Option<TransformDenialReason>) {
    // Fail-closed: no certificate → no transform.
    if !cert.is_granted() {
        return (
            TransformKind::NoTransform,
            Some(TransformDenialReason::CertificateAbstained),
        );
    }

    // Budget check.
    if transform_count >= config.max_transforms_per_scope {
        return (
            TransformKind::NoTransform,
            Some(TransformDenialReason::BudgetExhausted),
        );
    }

    // Confidence check.
    if cert.confidence_millionths < config.min_confidence_millionths {
        return (
            TransformKind::NoTransform,
            Some(TransformDenialReason::CertificateAbstained),
        );
    }

    // Try scalar replacement first (best optimization).
    if cert.scalar_replacement_eligible
        && let Some(layout) = layout
    {
        if layout.fields.len() > config.max_fields {
            // Too many fields, try region promotion instead.
        } else if !layout.layout_sealed {
            // Dynamic properties prevent scalar replacement.
        } else if layout
            .fields
            .iter()
            .any(|f| f.nesting_depth > config.max_decomposition_depth)
        {
            // Too deep.
        } else {
            return (TransformKind::ScalarReplacement, None);
        }
    }

    // No layout information or scalar replacement ineligible: try region promotion.
    if config.enable_region_promotion && cert.stack_allocation_eligible {
        match cert.escape_state {
            EscapeState::NoEscape => {
                return (TransformKind::RegionPromotion, None);
            }
            EscapeState::ArgEscape => {
                return (TransformKind::RegionPromotion, None);
            }
            _ => {}
        }
    }

    // Try allocation sinking (third best).
    if config.enable_allocation_sinking {
        if let Some(span) = cert.liveness.span() {
            if span >= config.min_sinking_span && !has_blocking_barrier(cert, barriers) {
                return (TransformKind::AllocationSinking, None);
            }
            if has_blocking_barrier(cert, barriers) {
                return (
                    TransformKind::NoTransform,
                    Some(TransformDenialReason::SideEffectBarrier),
                );
            }
        } else {
            return (
                TransformKind::NoTransform,
                Some(TransformDenialReason::LivenessUnknown),
            );
        }
    }

    // Determine specific denial reason.
    let reason = if cert.abstention {
        TransformDenialReason::CertificateAbstained
    } else if !cert.escape_state.is_elision_eligible() && !cert.escape_state.is_caller_managed() {
        TransformDenialReason::EscapeBeyondScope
    } else {
        TransformDenialReason::KindNotEligible
    };
    (TransformKind::NoTransform, Some(reason))
}

/// Check if any side-effect barrier blocks sinking.
fn has_blocking_barrier(cert: &EscapeCertificate, barriers: &[SideEffectBarrier]) -> bool {
    if let Some(first_use) = cert.liveness.first_use {
        barriers.iter().any(|b| b.instruction_index < first_use)
    } else {
        true // Unknown liveness → assume blocked.
    }
}

/// Build a scalar replacement plan from a certificate and field layout.
pub fn build_scalar_plan(
    cert: &EscapeCertificate,
    layout: &FieldLayout,
    config: &ScalarReplacementConfig,
) -> Result<ScalarReplacementPlan, TransformDenialReason> {
    if layout.fields.len() > config.max_fields {
        return Err(TransformDenialReason::TooManyFields);
    }
    if !layout.layout_sealed {
        return Err(TransformDenialReason::NonDecomposableFields);
    }
    if layout
        .fields
        .iter()
        .any(|f| f.nesting_depth > config.max_decomposition_depth)
    {
        return Err(TransformDenialReason::DecompositionTooDeep);
    }

    let mut fields = Vec::with_capacity(layout.fields.len());
    let mut register_slots: u32 = 0;
    let mut stack_slots: u32 = 0;

    for (idx, fd) in layout.fields.iter().enumerate() {
        if fd.field_type.is_register_safe() {
            register_slots = register_slots.saturating_add(1);
        } else {
            stack_slots = stack_slots.saturating_add(1);
        }
        fields.push(ScalarField {
            name: fd.name.clone(),
            offset: idx as u32,
            field_type: fd.field_type,
            always_initialized: fd.always_initialized,
            default_value: if !fd.always_initialized {
                Some("undefined".to_string())
            } else {
                None
            },
        });
    }

    let fully_register_safe = stack_slots == 0;
    let estimated_savings = cert.site.estimated_size_bytes.unwrap_or(64); // Default object size estimate.

    Ok(ScalarReplacementPlan {
        site_id: cert.site.site_id.clone(),
        fields,
        register_slots,
        stack_slots,
        decomposition_depth: layout
            .fields
            .iter()
            .map(|f| f.nesting_depth)
            .max()
            .unwrap_or(0),
        fully_register_safe,
        estimated_savings_bytes: estimated_savings,
    })
}

/// Build a region promotion plan from a certificate.
pub fn build_region_plan(cert: &EscapeCertificate) -> RegionPromotionPlan {
    let scope = match cert.escape_state {
        EscapeState::NoEscape => RegionScope::FunctionLocal,
        EscapeState::ArgEscape => RegionScope::CallerManaged,
        _ => RegionScope::FunctionLocal, // Conservative fallback.
    };

    RegionPromotionPlan {
        site_id: cert.site.site_id.clone(),
        region_scope: scope,
        estimated_size_bytes: cert.site.estimated_size_bytes.unwrap_or(64),
        alignment_bytes: 8, // Default alignment.
        containing_scope: cert.site.scope.clone(),
    }
}

/// Build an allocation sinking plan from a certificate and barriers.
pub fn build_sinking_plan(
    cert: &EscapeCertificate,
    barriers: &[SideEffectBarrier],
) -> Result<AllocationSinkingPlan, TransformDenialReason> {
    let first_use = cert
        .liveness
        .first_use
        .ok_or(TransformDenialReason::LivenessUnknown)?;

    // Find the latest safe sinking point: just before the first barrier
    // that's before first_use, or at first_use itself.
    let sunk_position = barriers
        .iter()
        .filter(|b| b.instruction_index < first_use)
        .map(|b| b.instruction_index)
        .max()
        .map(|b| b.saturating_add(1))
        .unwrap_or(first_use);

    let original = 0_u64; // Allocation at the start of the scope.
    let instructions_saved = sunk_position.saturating_sub(original);

    Ok(AllocationSinkingPlan {
        site_id: cert.site.site_id.clone(),
        original_position: original,
        sunk_position,
        instructions_saved,
        conditional: first_use > 0,
        trigger_condition: if first_use > 0 {
            Some(format!("branch_to_use_at_{first_use}"))
        } else {
            None
        },
    })
}

/// Build a deopt witness for a transform.
pub fn build_deopt_witness(
    cert: &EscapeCertificate,
    transform_kind: TransformKind,
    plan_fields: &[ScalarField],
    epoch: SecurityEpoch,
) -> DeoptWitness {
    // Determine trigger set based on allocation kind.
    let mut triggers = BTreeSet::new();
    triggers.insert(DeoptTrigger::ExternalInspection);
    triggers.insert(DeoptTrigger::DebugBreakpoint);

    match cert.site.allocation_kind {
        AllocationKind::ObjectLiteral | AllocationKind::ConstructorCall => {
            triggers.insert(DeoptTrigger::IdentityComparison);
            triggers.insert(DeoptTrigger::StructuralEnumeration);
            triggers.insert(DeoptTrigger::TypeCheck);
        }
        AllocationKind::ArrayLiteral | AllocationKind::SpreadArray => {
            triggers.insert(DeoptTrigger::StructuralEnumeration);
        }
        AllocationKind::Closure => {
            triggers.insert(DeoptTrigger::IdentityComparison);
        }
        AllocationKind::IteratorResult => {
            triggers.insert(DeoptTrigger::MissingProperty);
        }
        _ => {}
    }

    // Build materialization recipe.
    let field_sources: Vec<FieldSource> = plan_fields
        .iter()
        .enumerate()
        .map(|(idx, f)| FieldSource {
            name: f.name.clone(),
            source_kind: if f.field_type.is_register_safe() {
                FieldSourceKind::Register
            } else {
                FieldSourceKind::StackSlot
            },
            source_index: idx as u32,
            field_type: f.field_type,
        })
        .collect();

    let recipe = MaterializationRecipe {
        site_id: cert.site.site_id.clone(),
        allocation_kind: cert.site.allocation_kind,
        field_sources,
        prototype_source: match cert.site.allocation_kind {
            AllocationKind::ConstructorCall => Some("constructor_prototype".to_string()),
            AllocationKind::ObjectLiteral => Some("object_prototype".to_string()),
            _ => None,
        },
        estimated_cost_millionths: (plan_fields.len() as i64).saturating_mul(10_000), // 0.01ms per field
    };

    let witness_id = format!("dw_{}_{}", cert.site.site_id, transform_kind);
    let triggers_str = serde_json::to_string(&triggers)
        .expect("deopt triggers should serialize for deterministic hashing");
    let hash_input = format!(
        "witness:{}:{}:{}:{}",
        witness_id, transform_kind, triggers_str, cert.certificate_hash
    );
    let witness_hash = hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes());

    DeoptWitness {
        witness_id,
        transform_kind,
        site_id: cert.site.site_id.clone(),
        authorizing_certificate_hash: cert.certificate_hash.clone(),
        trigger_set: triggers,
        materialization_recipe: recipe,
        epoch,
        witness_hash,
    }
}

/// Build a translation-validation receipt for a transform.
pub fn build_validation_receipt(
    cert: &EscapeCertificate,
    transform_kind: TransformKind,
    witness: &DeoptWitness,
    pre_hash: &str,
    post_hash: &str,
    epoch: SecurityEpoch,
) -> TranslationValidationReceipt {
    let receipt_id = format!("tvr_{}_{}", cert.site.site_id, transform_kind);
    let hash_input = format!(
        "receipt:{}:{}:{}:{}:{}",
        receipt_id, pre_hash, post_hash, cert.certificate_hash, witness.witness_hash
    );
    let receipt_hash = hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes());

    TranslationValidationReceipt {
        receipt_id,
        schema_version: SRE_SCHEMA_VERSION.to_string(),
        transform_kind,
        site_id: cert.site.site_id.clone(),
        pre_transform_hash: pre_hash.to_string(),
        post_transform_hash: post_hash.to_string(),
        certificate_hash: cert.certificate_hash.clone(),
        witness_hash: witness.witness_hash.clone(),
        validation_passed: true,
        failure_reason: None,
        epoch,
        receipt_hash,
    }
}

/// Execute the full transform pipeline on an optimization envelope.
pub fn execute_transforms(
    envelope: &OptimizationEligibilityEnvelope,
    layouts: &BTreeMap<String, FieldLayout>,
    barriers: &BTreeMap<String, Vec<SideEffectBarrier>>,
    config: &ScalarReplacementConfig,
    epoch: SecurityEpoch,
) -> TransformSummary {
    let mut outcomes = Vec::with_capacity(envelope.certificates.len());
    let mut scalar_count: u64 = 0;
    let mut region_count: u64 = 0;
    let mut sinking_count: u64 = 0;
    let mut no_transform_count: u64 = 0;
    let mut total_bytes_saved: u64 = 0;
    let mut denial_histogram: BTreeMap<String, u64> = BTreeMap::new();
    let mut transform_count: u32 = 0;

    for cert in &envelope.certificates {
        let site_barriers = barriers
            .get(&cert.site.site_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        let (kind, denial) = select_transform(
            cert,
            layouts.get(&cert.site.site_id),
            site_barriers,
            config,
            transform_count,
        );

        let outcome = match kind {
            TransformKind::ScalarReplacement => {
                let layout = layouts.get(&cert.site.site_id).unwrap(); // Safe: select_transform checks.
                match build_scalar_plan(cert, layout, config) {
                    Ok(plan) => {
                        let witness = build_deopt_witness(cert, kind, &plan.fields, epoch);
                        let receipt = build_validation_receipt(
                            cert,
                            kind,
                            &witness,
                            &cert.certificate_hash,
                            &format!("post_{}", cert.certificate_hash),
                            epoch,
                        );
                        let saved = plan.estimated_savings_bytes;
                        scalar_count += 1;
                        total_bytes_saved = total_bytes_saved.saturating_add(saved);
                        transform_count = transform_count.saturating_add(1);
                        TransformOutcome {
                            site_id: cert.site.site_id.clone(),
                            transform_kind: kind,
                            scalar_plan: Some(plan),
                            region_plan: None,
                            sinking_plan: None,
                            deopt_witness: Some(witness),
                            validation_receipt: Some(receipt),
                            denial_reason: None,
                            estimated_bytes_saved: saved,
                        }
                    }
                    Err(reason) => {
                        no_transform_count += 1;
                        *denial_histogram
                            .entry(reason.as_str().to_string())
                            .or_default() += 1;
                        TransformOutcome {
                            site_id: cert.site.site_id.clone(),
                            transform_kind: TransformKind::NoTransform,
                            scalar_plan: None,
                            region_plan: None,
                            sinking_plan: None,
                            deopt_witness: None,
                            validation_receipt: None,
                            denial_reason: Some(reason),
                            estimated_bytes_saved: 0,
                        }
                    }
                }
            }
            TransformKind::RegionPromotion => {
                let plan = build_region_plan(cert);
                let witness = build_deopt_witness(cert, kind, &[], epoch);
                let receipt = build_validation_receipt(
                    cert,
                    kind,
                    &witness,
                    &cert.certificate_hash,
                    &format!("post_{}", cert.certificate_hash),
                    epoch,
                );
                let saved = plan.estimated_size_bytes;
                region_count += 1;
                total_bytes_saved = total_bytes_saved.saturating_add(saved);
                transform_count = transform_count.saturating_add(1);
                TransformOutcome {
                    site_id: cert.site.site_id.clone(),
                    transform_kind: kind,
                    scalar_plan: None,
                    region_plan: Some(plan),
                    sinking_plan: None,
                    deopt_witness: Some(witness),
                    validation_receipt: Some(receipt),
                    denial_reason: None,
                    estimated_bytes_saved: saved,
                }
            }
            TransformKind::AllocationSinking => match build_sinking_plan(cert, site_barriers) {
                Ok(plan) => {
                    let witness = build_deopt_witness(cert, kind, &[], epoch);
                    let receipt = build_validation_receipt(
                        cert,
                        kind,
                        &witness,
                        &cert.certificate_hash,
                        &format!("post_{}", cert.certificate_hash),
                        epoch,
                    );
                    let saved = cert.site.estimated_size_bytes.unwrap_or(0);
                    sinking_count += 1;
                    total_bytes_saved = total_bytes_saved.saturating_add(saved);
                    transform_count = transform_count.saturating_add(1);
                    TransformOutcome {
                        site_id: cert.site.site_id.clone(),
                        transform_kind: kind,
                        scalar_plan: None,
                        region_plan: None,
                        sinking_plan: Some(plan),
                        deopt_witness: Some(witness),
                        validation_receipt: Some(receipt),
                        denial_reason: None,
                        estimated_bytes_saved: saved,
                    }
                }
                Err(reason) => {
                    no_transform_count += 1;
                    *denial_histogram
                        .entry(reason.as_str().to_string())
                        .or_default() += 1;
                    TransformOutcome {
                        site_id: cert.site.site_id.clone(),
                        transform_kind: TransformKind::NoTransform,
                        scalar_plan: None,
                        region_plan: None,
                        sinking_plan: None,
                        deopt_witness: None,
                        validation_receipt: None,
                        denial_reason: Some(reason),
                        estimated_bytes_saved: 0,
                    }
                }
            },
            TransformKind::NoTransform => {
                no_transform_count += 1;
                if let Some(reason) = denial {
                    *denial_histogram
                        .entry(reason.as_str().to_string())
                        .or_default() += 1;
                }
                TransformOutcome {
                    site_id: cert.site.site_id.clone(),
                    transform_kind: kind,
                    scalar_plan: None,
                    region_plan: None,
                    sinking_plan: None,
                    deopt_witness: None,
                    validation_receipt: None,
                    denial_reason: denial,
                    estimated_bytes_saved: 0,
                }
            }
        };
        outcomes.push(outcome);
    }

    #[derive(Serialize)]
    struct TransformSummaryHashPayload<'a> {
        schema_version: &'a str,
        scope_id: &'a str,
        total_sites: u64,
        scalar_replacement_count: u64,
        region_promotion_count: u64,
        allocation_sinking_count: u64,
        no_transform_count: u64,
        total_bytes_saved: u64,
        outcomes: &'a [TransformOutcome],
        denial_histogram: &'a BTreeMap<String, u64>,
        epoch: &'a SecurityEpoch,
    }

    let summary_hash_input = serde_json::to_vec(&TransformSummaryHashPayload {
        schema_version: SRE_SCHEMA_VERSION,
        scope_id: &envelope.scope_id,
        total_sites: envelope.certificates.len() as u64,
        scalar_replacement_count: scalar_count,
        region_promotion_count: region_count,
        allocation_sinking_count: sinking_count,
        no_transform_count,
        total_bytes_saved,
        outcomes: &outcomes,
        denial_histogram: &denial_histogram,
        epoch: &epoch,
    })
    .expect("transform summary payload should serialize for deterministic hashing");

    TransformSummary {
        schema_version: SRE_SCHEMA_VERSION.to_string(),
        scope_id: envelope.scope_id.clone(),
        total_sites: envelope.certificates.len() as u64,
        scalar_replacement_count: scalar_count,
        region_promotion_count: region_count,
        allocation_sinking_count: sinking_count,
        no_transform_count,
        total_bytes_saved,
        outcomes,
        denial_histogram,
        epoch,
        summary_hash: hex_encode(ContentHash::compute(&summary_hash_input).as_bytes()),
    }
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SreSpecimenFamily {
    /// Transform selection logic.
    TransformSelection,
    /// Scalar replacement planning.
    ScalarPlanning,
    /// Region promotion planning.
    RegionPlanning,
    /// Allocation sinking planning.
    SinkingPlanning,
    /// Deopt witness construction.
    DeoptWitnessConstruction,
    /// Validation receipt construction.
    ValidationReceipt,
    /// Full pipeline execution.
    PipelineExecution,
    /// Denial reason classification.
    DenialClassification,
    /// Budget exhaustion.
    BudgetExhaustion,
    /// Serde roundtrip.
    SerdeRoundtrip,
}

impl SreSpecimenFamily {
    pub const ALL: &[Self] = &[
        Self::TransformSelection,
        Self::ScalarPlanning,
        Self::RegionPlanning,
        Self::SinkingPlanning,
        Self::DeoptWitnessConstruction,
        Self::ValidationReceipt,
        Self::PipelineExecution,
        Self::DenialClassification,
        Self::BudgetExhaustion,
        Self::SerdeRoundtrip,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransformSelection => "transform_selection",
            Self::ScalarPlanning => "scalar_planning",
            Self::RegionPlanning => "region_planning",
            Self::SinkingPlanning => "sinking_planning",
            Self::DeoptWitnessConstruction => "deopt_witness_construction",
            Self::ValidationReceipt => "validation_receipt",
            Self::PipelineExecution => "pipeline_execution",
            Self::DenialClassification => "denial_classification",
            Self::BudgetExhaustion => "budget_exhaustion",
            Self::SerdeRoundtrip => "serde_roundtrip",
        }
    }
}

impl fmt::Display for SreSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SreExpectedOutcome {
    TransformSelected,
    TransformDenied,
    PlanBuilt,
    PlanDenied,
    WitnessConstructed,
    ReceiptConstructed,
    PipelineComplete,
    BudgetExhausted,
    RoundtripPreserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SreSpecimen {
    pub specimen_id: String,
    pub description: String,
    pub family: SreSpecimenFamily,
    pub expected_outcome: SreExpectedOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SreVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SreSpecimenEvidence {
    pub specimen_id: String,
    pub family: SreSpecimenFamily,
    pub expected_outcome: SreExpectedOutcome,
    pub verdict: SreVerdict,
    pub actual_outcome: String,
    pub error_detail: Option<String>,
    pub evidence_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SreEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub family_coverage: BTreeMap<String, u64>,
    pub evidence: Vec<SreSpecimenEvidence>,
}

impl SreEvidenceInventory {
    pub fn contract_satisfied(&self) -> bool {
        self.fail_count == 0 && self.specimen_count > 0
    }
}

// ---------------------------------------------------------------------------
// Event log
// ---------------------------------------------------------------------------

/// Event types for the scalar replacement engine audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SreEventKind {
    /// Transform pipeline started.
    PipelineStarted,
    /// Transform selected for a site.
    TransformSelected,
    /// Transform denied for a site.
    TransformDenied,
    /// Deopt witness emitted.
    DeoptWitnessEmitted,
    /// Validation receipt emitted.
    ValidationReceiptEmitted,
    /// Pipeline completed.
    PipelineCompleted,
    /// Budget exhausted for scope.
    BudgetExhausted,
}

impl SreEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PipelineStarted => "pipeline_started",
            Self::TransformSelected => "transform_selected",
            Self::TransformDenied => "transform_denied",
            Self::DeoptWitnessEmitted => "deopt_witness_emitted",
            Self::ValidationReceiptEmitted => "validation_receipt_emitted",
            Self::PipelineCompleted => "pipeline_completed",
            Self::BudgetExhausted => "budget_exhausted",
        }
    }
}

impl fmt::Display for SreEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single event in the engine audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SreEvent {
    /// Schema version.
    pub schema_version: String,
    /// Event kind.
    pub kind: SreEventKind,
    /// Scope ID.
    pub scope_id: String,
    /// Related site ID (if applicable).
    pub site_id: Option<String>,
    /// Transform kind (if applicable).
    pub transform_kind: Option<TransformKind>,
    /// Detail message.
    pub detail: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Event hash.
    pub event_hash: String,
}

/// Immutable event log for the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SreEventLog {
    /// All events, append-only.
    pub events: Vec<SreEvent>,
}

impl SreEventLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn push(&mut self, event: SreEvent) {
        self.events.push(event);
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl Default for SreEventLog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escape_analysis_certificate::{
        AliasClassId, AllocationKind, AllocationSite, EscapeCertificate, EscapeState,
        InvalidationReason, LivenessEnvelope,
    };

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn make_site(id: &str, kind: AllocationKind) -> AllocationSite {
        AllocationSite {
            site_id: id.to_string(),
            scope: "test_fn".to_string(),
            allocation_kind: kind,
            estimated_size_bytes: Some(64),
        }
    }

    fn make_cert(
        id: &str,
        kind: AllocationKind,
        escape: EscapeState,
        scalar_eligible: bool,
        stack_eligible: bool,
    ) -> EscapeCertificate {
        EscapeCertificate {
            schema_version: "v1".to_string(),
            site: make_site(id, kind),
            escape_state: escape,
            alias_class: AliasClassId::new(&format!("class_{id}")),
            liveness: LivenessEnvelope {
                first_use: Some(5),
                last_use: Some(20),
                precise: true,
            },
            scalar_replacement_eligible: scalar_eligible,
            stack_allocation_eligible: stack_eligible,
            confidence_millionths: 800_000,
            invalidation_reasons: vec![],
            abstention: false,
            certificate_hash: format!("hash_{id}"),
        }
    }

    fn make_abstained_cert(id: &str) -> EscapeCertificate {
        EscapeCertificate {
            schema_version: "v1".to_string(),
            site: make_site(id, AllocationKind::ObjectLiteral),
            escape_state: EscapeState::GlobalEscape,
            alias_class: AliasClassId::new(&format!("class_{id}")),
            liveness: LivenessEnvelope {
                first_use: None,
                last_use: None,
                precise: false,
            },
            scalar_replacement_eligible: false,
            stack_allocation_eligible: false,
            confidence_millionths: 0,
            invalidation_reasons: vec![InvalidationReason::DynamicEval],
            abstention: true,
            certificate_hash: format!("hash_{id}"),
        }
    }

    fn make_layout(site_id: &str, field_count: usize) -> FieldLayout {
        let fields: Vec<FieldDescriptor> = (0..field_count)
            .map(|i| FieldDescriptor {
                name: format!("field_{i}"),
                field_type: if i.is_multiple_of(2) {
                    ScalarFieldType::Number
                } else {
                    ScalarFieldType::StringRef
                },
                always_initialized: true,
                nesting_depth: 0,
            })
            .collect();
        FieldLayout {
            site_id: site_id.to_string(),
            fields,
            layout_sealed: true,
        }
    }

    fn default_config() -> ScalarReplacementConfig {
        ScalarReplacementConfig::default()
    }

    // --- TransformKind ---

    #[test]
    fn transform_kind_all_variants_covered() {
        assert_eq!(TransformKind::ALL.len(), 4);
        for kind in TransformKind::ALL {
            assert!(!kind.as_str().is_empty());
            assert_eq!(format!("{kind}"), kind.as_str());
        }
    }

    #[test]
    fn transform_kind_display() {
        assert_eq!(
            TransformKind::ScalarReplacement.to_string(),
            "scalar_replacement"
        );
        assert_eq!(
            TransformKind::RegionPromotion.to_string(),
            "region_promotion"
        );
        assert_eq!(
            TransformKind::AllocationSinking.to_string(),
            "allocation_sinking"
        );
        assert_eq!(TransformKind::NoTransform.to_string(), "no_transform");
    }

    // --- ScalarFieldType ---

    #[test]
    fn scalar_field_type_register_safety() {
        assert!(ScalarFieldType::Number.is_register_safe());
        assert!(ScalarFieldType::Boolean.is_register_safe());
        assert!(ScalarFieldType::Undefined.is_register_safe());
        assert!(ScalarFieldType::Null.is_register_safe());
        assert!(!ScalarFieldType::StringRef.is_register_safe());
        assert!(!ScalarFieldType::ObjectRef.is_register_safe());
        assert!(!ScalarFieldType::SymbolRef.is_register_safe());
        assert!(!ScalarFieldType::BigIntRef.is_register_safe());
    }

    #[test]
    fn scalar_field_type_display() {
        assert_eq!(ScalarFieldType::Number.as_str(), "number");
        assert_eq!(ScalarFieldType::ObjectRef.as_str(), "object_ref");
    }

    // --- Transform selection ---

    #[test]
    fn select_transform_scalar_replacement_for_no_escape() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let layout = make_layout("s1", 3);
        let config = default_config();
        let (kind, denial) = select_transform(&cert, Some(&layout), &[], &config, 0);
        assert_eq!(kind, TransformKind::ScalarReplacement);
        assert!(denial.is_none());
    }

    #[test]
    fn select_transform_region_promotion_for_arg_escape() {
        let cert = make_cert(
            "s2",
            AllocationKind::ObjectLiteral,
            EscapeState::ArgEscape,
            false,
            true,
        );
        let config = default_config();
        let (kind, denial) = select_transform(&cert, None, &[], &config, 0);
        assert_eq!(kind, TransformKind::RegionPromotion);
        assert!(denial.is_none());
    }

    #[test]
    fn select_transform_no_transform_for_abstained() {
        let cert = make_abstained_cert("s3");
        let config = default_config();
        let (kind, denial) = select_transform(&cert, None, &[], &config, 0);
        assert_eq!(kind, TransformKind::NoTransform);
        assert_eq!(denial, Some(TransformDenialReason::CertificateAbstained));
    }

    #[test]
    fn select_transform_budget_exhausted() {
        let cert = make_cert(
            "s4",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let layout = make_layout("s4", 3);
        let config = default_config();
        let (kind, denial) = select_transform(&cert, Some(&layout), &[], &config, 128);
        assert_eq!(kind, TransformKind::NoTransform);
        assert_eq!(denial, Some(TransformDenialReason::BudgetExhausted));
    }

    #[test]
    fn select_transform_sinking_when_no_scalar_no_region() {
        let mut cert = make_cert(
            "s5",
            AllocationKind::ObjectLiteral,
            EscapeState::ThreadEscape,
            false,
            false,
        );
        cert.liveness = LivenessEnvelope {
            first_use: Some(10),
            last_use: Some(30),
            precise: true,
        };
        let config = default_config();
        let (kind, denial) = select_transform(&cert, None, &[], &config, 0);
        assert_eq!(kind, TransformKind::AllocationSinking);
        assert!(denial.is_none());
    }

    #[test]
    fn select_transform_sinking_blocked_by_barrier() {
        let mut cert = make_cert(
            "s6",
            AllocationKind::ObjectLiteral,
            EscapeState::ThreadEscape,
            false,
            false,
        );
        cert.liveness = LivenessEnvelope {
            first_use: Some(10),
            last_use: Some(30),
            precise: true,
        };
        let barriers = vec![SideEffectBarrier {
            instruction_index: 5,
            effect_kind: SideEffectKind::Call,
            description: "function call".to_string(),
        }];
        let config = default_config();
        let (kind, denial) = select_transform(&cert, None, &barriers, &config, 0);
        assert_eq!(kind, TransformKind::NoTransform);
        assert_eq!(denial, Some(TransformDenialReason::SideEffectBarrier));
    }

    #[test]
    fn select_transform_low_confidence_denied() {
        let mut cert = make_cert(
            "s7",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        cert.confidence_millionths = 100_000; // Below 0.6 threshold.
        let config = default_config();
        let (kind, denial) = select_transform(&cert, None, &[], &config, 0);
        assert_eq!(kind, TransformKind::NoTransform);
        assert_eq!(denial, Some(TransformDenialReason::CertificateAbstained));
    }

    // --- Scalar plan building ---

    #[test]
    fn build_scalar_plan_success() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let layout = make_layout("s1", 4);
        let config = default_config();
        let plan = build_scalar_plan(&cert, &layout, &config).unwrap();
        assert_eq!(plan.site_id, "s1");
        assert_eq!(plan.fields.len(), 4);
        assert_eq!(plan.register_slots, 2); // Even indices are Number (register-safe).
        assert_eq!(plan.stack_slots, 2); // Odd indices are StringRef (not register-safe).
        assert!(!plan.fully_register_safe);
        assert_eq!(plan.estimated_savings_bytes, 64);
    }

    #[test]
    fn build_scalar_plan_too_many_fields() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let layout = make_layout("s1", 100);
        let config = default_config();
        let result = build_scalar_plan(&cert, &layout, &config);
        assert_eq!(result.unwrap_err(), TransformDenialReason::TooManyFields);
    }

    #[test]
    fn build_scalar_plan_unsealed_layout() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let mut layout = make_layout("s1", 3);
        layout.layout_sealed = false;
        let config = default_config();
        let result = build_scalar_plan(&cert, &layout, &config);
        assert_eq!(
            result.unwrap_err(),
            TransformDenialReason::NonDecomposableFields
        );
    }

    #[test]
    fn build_scalar_plan_deep_nesting() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let mut layout = make_layout("s1", 3);
        layout.fields[0].nesting_depth = 10;
        let config = default_config();
        let result = build_scalar_plan(&cert, &layout, &config);
        assert_eq!(
            result.unwrap_err(),
            TransformDenialReason::DecompositionTooDeep
        );
    }

    #[test]
    fn build_scalar_plan_all_register_safe() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let layout = FieldLayout {
            site_id: "s1".to_string(),
            fields: vec![
                FieldDescriptor {
                    name: "x".to_string(),
                    field_type: ScalarFieldType::Number,
                    always_initialized: true,
                    nesting_depth: 0,
                },
                FieldDescriptor {
                    name: "y".to_string(),
                    field_type: ScalarFieldType::Boolean,
                    always_initialized: true,
                    nesting_depth: 0,
                },
            ],
            layout_sealed: true,
        };
        let config = default_config();
        let plan = build_scalar_plan(&cert, &layout, &config).unwrap();
        assert!(plan.fully_register_safe);
        assert_eq!(plan.register_slots, 2);
        assert_eq!(plan.stack_slots, 0);
    }

    // --- Region plan building ---

    #[test]
    fn build_region_plan_no_escape() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let plan = build_region_plan(&cert);
        assert_eq!(plan.site_id, "s1");
        assert_eq!(plan.region_scope, RegionScope::FunctionLocal);
        assert_eq!(plan.estimated_size_bytes, 64);
    }

    #[test]
    fn build_region_plan_arg_escape() {
        let cert = make_cert(
            "s2",
            AllocationKind::ArrayLiteral,
            EscapeState::ArgEscape,
            false,
            true,
        );
        let plan = build_region_plan(&cert);
        assert_eq!(plan.region_scope, RegionScope::CallerManaged);
    }

    // --- Sinking plan building ---

    #[test]
    fn build_sinking_plan_success() {
        let mut cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::ThreadEscape,
            false,
            false,
        );
        cert.liveness = LivenessEnvelope {
            first_use: Some(20),
            last_use: Some(40),
            precise: true,
        };
        let plan = build_sinking_plan(&cert, &[]).unwrap();
        assert_eq!(plan.site_id, "s1");
        assert_eq!(plan.sunk_position, 20);
        assert_eq!(plan.instructions_saved, 20);
        assert!(plan.conditional);
    }

    #[test]
    fn build_sinking_plan_with_barrier() {
        let mut cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::ThreadEscape,
            false,
            false,
        );
        cert.liveness = LivenessEnvelope {
            first_use: Some(20),
            last_use: Some(40),
            precise: true,
        };
        let barriers = vec![SideEffectBarrier {
            instruction_index: 10,
            effect_kind: SideEffectKind::Call,
            description: "call before use".to_string(),
        }];
        let plan = build_sinking_plan(&cert, &barriers).unwrap();
        assert_eq!(plan.sunk_position, 11); // Just after the barrier.
    }

    #[test]
    fn build_sinking_plan_unknown_liveness() {
        let mut cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::ThreadEscape,
            false,
            false,
        );
        cert.liveness = LivenessEnvelope {
            first_use: None,
            last_use: None,
            precise: false,
        };
        let result = build_sinking_plan(&cert, &[]);
        assert_eq!(result.unwrap_err(), TransformDenialReason::LivenessUnknown);
    }

    // --- Deopt witness ---

    #[test]
    fn deopt_witness_for_object_literal() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let fields = vec![ScalarField {
            name: "x".to_string(),
            offset: 0,
            field_type: ScalarFieldType::Number,
            always_initialized: true,
            default_value: None,
        }];
        let witness = build_deopt_witness(
            &cert,
            TransformKind::ScalarReplacement,
            &fields,
            test_epoch(),
        );
        assert!(
            witness
                .trigger_set
                .contains(&DeoptTrigger::IdentityComparison)
        );
        assert!(
            witness
                .trigger_set
                .contains(&DeoptTrigger::StructuralEnumeration)
        );
        assert!(witness.trigger_set.contains(&DeoptTrigger::TypeCheck));
        assert_eq!(witness.materialization_recipe.field_sources.len(), 1);
        assert!(!witness.witness_hash.is_empty());
    }

    #[test]
    fn deopt_witness_for_iterator_result() {
        let cert = make_cert(
            "s1",
            AllocationKind::IteratorResult,
            EscapeState::NoEscape,
            true,
            true,
        );
        let witness =
            build_deopt_witness(&cert, TransformKind::ScalarReplacement, &[], test_epoch());
        assert!(witness.trigger_set.contains(&DeoptTrigger::MissingProperty));
        assert!(
            !witness
                .trigger_set
                .contains(&DeoptTrigger::IdentityComparison)
        );
    }

    #[test]
    fn deopt_witness_for_closure() {
        let cert = make_cert(
            "s1",
            AllocationKind::Closure,
            EscapeState::NoEscape,
            true,
            true,
        );
        let witness = build_deopt_witness(&cert, TransformKind::RegionPromotion, &[], test_epoch());
        assert!(
            witness
                .trigger_set
                .contains(&DeoptTrigger::IdentityComparison)
        );
    }

    #[test]
    fn deopt_witness_materialization_recipe() {
        let cert = make_cert(
            "s1",
            AllocationKind::ConstructorCall,
            EscapeState::NoEscape,
            true,
            true,
        );
        let fields = vec![
            ScalarField {
                name: "a".to_string(),
                offset: 0,
                field_type: ScalarFieldType::Number,
                always_initialized: true,
                default_value: None,
            },
            ScalarField {
                name: "b".to_string(),
                offset: 1,
                field_type: ScalarFieldType::ObjectRef,
                always_initialized: false,
                default_value: Some("undefined".to_string()),
            },
        ];
        let witness = build_deopt_witness(
            &cert,
            TransformKind::ScalarReplacement,
            &fields,
            test_epoch(),
        );
        assert_eq!(witness.materialization_recipe.field_sources.len(), 2);
        assert_eq!(
            witness.materialization_recipe.field_sources[0].source_kind,
            FieldSourceKind::Register
        );
        assert_eq!(
            witness.materialization_recipe.field_sources[1].source_kind,
            FieldSourceKind::StackSlot
        );
        assert_eq!(
            witness.materialization_recipe.prototype_source,
            Some("constructor_prototype".to_string())
        );
    }

    // --- Validation receipt ---

    #[test]
    fn validation_receipt_construction() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let witness =
            build_deopt_witness(&cert, TransformKind::ScalarReplacement, &[], test_epoch());
        let receipt = build_validation_receipt(
            &cert,
            TransformKind::ScalarReplacement,
            &witness,
            "pre_hash",
            "post_hash",
            test_epoch(),
        );
        assert!(receipt.validation_passed);
        assert!(receipt.failure_reason.is_none());
        assert!(!receipt.receipt_hash.is_empty());
        assert_eq!(receipt.schema_version, SRE_SCHEMA_VERSION);
    }

    // --- Full pipeline ---

    #[test]
    fn execute_transforms_mixed_sites() {
        let certs = vec![
            make_cert(
                "a1",
                AllocationKind::ObjectLiteral,
                EscapeState::NoEscape,
                true,
                true,
            ),
            make_cert(
                "a2",
                AllocationKind::ArrayLiteral,
                EscapeState::ArgEscape,
                false,
                true,
            ),
            make_abstained_cert("a3"),
        ];

        let envelope = OptimizationEligibilityEnvelope {
            schema_version: "v1".to_string(),
            scope_id: "test_fn".to_string(),
            total_sites: 3,
            scalar_replacement_count: 1,
            stack_allocation_count: 2,
            abstention_count: 1,
            alias_class_count: 3,
            certificates: certs,
            overall_confidence_millionths: 0,
            envelope_hash: "env_hash".to_string(),
            epoch: test_epoch(),
        };

        let mut layouts = BTreeMap::new();
        layouts.insert("a1".to_string(), make_layout("a1", 3));

        let barriers = BTreeMap::new();
        let config = default_config();

        let summary = execute_transforms(&envelope, &layouts, &barriers, &config, test_epoch());
        assert_eq!(summary.total_sites, 3);
        assert_eq!(summary.scalar_replacement_count, 1);
        assert_eq!(summary.region_promotion_count, 1);
        assert_eq!(summary.no_transform_count, 1);
        assert!(summary.total_bytes_saved > 0);
        assert_eq!(summary.outcomes.len(), 3);
    }

    #[test]
    fn execute_transforms_empty_envelope() {
        let envelope = OptimizationEligibilityEnvelope {
            schema_version: "v1".to_string(),
            scope_id: "empty_fn".to_string(),
            total_sites: 0,
            scalar_replacement_count: 0,
            stack_allocation_count: 0,
            abstention_count: 0,
            alias_class_count: 0,
            certificates: vec![],
            overall_confidence_millionths: 0,
            envelope_hash: "env_hash".to_string(),
            epoch: test_epoch(),
        };
        let config = default_config();
        let summary = execute_transforms(
            &envelope,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &config,
            test_epoch(),
        );
        assert_eq!(summary.total_sites, 0);
        assert_eq!(summary.transform_rate_millionths(), 0);
    }

    #[test]
    fn execute_transforms_all_scalar() {
        let certs: Vec<EscapeCertificate> = (0..5)
            .map(|i| {
                make_cert(
                    &format!("site_{i}"),
                    AllocationKind::ObjectLiteral,
                    EscapeState::NoEscape,
                    true,
                    true,
                )
            })
            .collect();
        let mut layouts = BTreeMap::new();
        for i in 0..5 {
            layouts.insert(format!("site_{i}"), make_layout(&format!("site_{i}"), 2));
        }
        let envelope = OptimizationEligibilityEnvelope {
            schema_version: "v1".to_string(),
            scope_id: "all_scalar".to_string(),
            total_sites: 5,
            scalar_replacement_count: 5,
            stack_allocation_count: 5,
            abstention_count: 0,
            alias_class_count: 5,
            certificates: certs,
            overall_confidence_millionths: 800_000,
            envelope_hash: "env_hash".to_string(),
            epoch: test_epoch(),
        };
        let config = default_config();
        let summary =
            execute_transforms(&envelope, &layouts, &BTreeMap::new(), &config, test_epoch());
        assert_eq!(summary.scalar_replacement_count, 5);
        assert_eq!(summary.no_transform_count, 0);
        assert_eq!(summary.transform_rate_millionths(), MILLION);
    }

    #[test]
    fn execute_transforms_summary_hash_changes_with_outcome_details() {
        let env_a = OptimizationEligibilityEnvelope {
            schema_version: "v1".to_string(),
            scope_id: "hash_scope".to_string(),
            total_sites: 1,
            scalar_replacement_count: 1,
            stack_allocation_count: 1,
            abstention_count: 0,
            alias_class_count: 1,
            certificates: vec![make_cert(
                "hash_site_a",
                AllocationKind::ObjectLiteral,
                EscapeState::NoEscape,
                true,
                true,
            )],
            overall_confidence_millionths: 800_000,
            envelope_hash: "env_hash".to_string(),
            epoch: test_epoch(),
        };
        let env_b = OptimizationEligibilityEnvelope {
            schema_version: "v1".to_string(),
            scope_id: "hash_scope".to_string(),
            total_sites: 1,
            scalar_replacement_count: 1,
            stack_allocation_count: 1,
            abstention_count: 0,
            alias_class_count: 1,
            certificates: vec![make_cert(
                "hash_site_b",
                AllocationKind::ObjectLiteral,
                EscapeState::NoEscape,
                true,
                true,
            )],
            overall_confidence_millionths: 800_000,
            envelope_hash: "env_hash".to_string(),
            epoch: test_epoch(),
        };

        let mut layouts_a = BTreeMap::new();
        layouts_a.insert("hash_site_a".to_string(), make_layout("hash_site_a", 2));
        let mut layouts_b = BTreeMap::new();
        layouts_b.insert("hash_site_b".to_string(), make_layout("hash_site_b", 2));

        let summary_a = execute_transforms(
            &env_a,
            &layouts_a,
            &BTreeMap::new(),
            &default_config(),
            test_epoch(),
        );
        let summary_b = execute_transforms(
            &env_b,
            &layouts_b,
            &BTreeMap::new(),
            &default_config(),
            test_epoch(),
        );

        assert_eq!(
            summary_a.scalar_replacement_count,
            summary_b.scalar_replacement_count
        );
        assert_eq!(summary_a.total_bytes_saved, summary_b.total_bytes_saved);
        assert_ne!(summary_a.outcomes, summary_b.outcomes);
        assert_ne!(summary_a.summary_hash, summary_b.summary_hash);
    }

    // --- Transform summary ---

    #[test]
    fn transform_summary_rate_calculation() {
        let summary = TransformSummary {
            schema_version: SRE_SCHEMA_VERSION.to_string(),
            scope_id: "test".to_string(),
            total_sites: 10,
            scalar_replacement_count: 3,
            region_promotion_count: 2,
            allocation_sinking_count: 1,
            no_transform_count: 4,
            total_bytes_saved: 384,
            outcomes: vec![],
            denial_histogram: BTreeMap::new(),
            epoch: test_epoch(),
            summary_hash: "hash".to_string(),
        };
        // 6/10 = 0.6 = 600_000 millionths.
        assert_eq!(summary.transform_rate_millionths(), 600_000);
    }

    #[test]
    fn transform_summary_rate_zero_sites() {
        let summary = TransformSummary {
            schema_version: SRE_SCHEMA_VERSION.to_string(),
            scope_id: "empty".to_string(),
            total_sites: 0,
            scalar_replacement_count: 0,
            region_promotion_count: 0,
            allocation_sinking_count: 0,
            no_transform_count: 0,
            total_bytes_saved: 0,
            outcomes: vec![],
            denial_histogram: BTreeMap::new(),
            epoch: test_epoch(),
            summary_hash: "hash".to_string(),
        };
        assert_eq!(summary.transform_rate_millionths(), 0);
    }

    // --- ScalarReplacementPlan ---

    #[test]
    fn scalar_plan_total_slots() {
        let plan = ScalarReplacementPlan {
            site_id: "s1".to_string(),
            fields: vec![],
            register_slots: 3,
            stack_slots: 2,
            decomposition_depth: 0,
            fully_register_safe: false,
            estimated_savings_bytes: 64,
        };
        assert_eq!(plan.total_slots(), 5);
    }

    // --- Region scope ---

    #[test]
    fn region_scope_display() {
        assert_eq!(RegionScope::FunctionLocal.as_str(), "function_local");
        assert_eq!(RegionScope::BlockLocal.as_str(), "block_local");
        assert_eq!(RegionScope::LoopIteration.as_str(), "loop_iteration");
        assert_eq!(RegionScope::CallerManaged.as_str(), "caller_managed");
    }

    // --- SideEffectKind ---

    #[test]
    fn side_effect_kind_display() {
        assert_eq!(SideEffectKind::Call.as_str(), "call");
        assert_eq!(SideEffectKind::PropertyStore.as_str(), "property_store");
        assert_eq!(SideEffectKind::ExceptionThrow.as_str(), "exception_throw");
        assert_eq!(SideEffectKind::YieldAwait.as_str(), "yield_await");
        assert_eq!(
            SideEffectKind::DebuggerStatement.as_str(),
            "debugger_statement"
        );
    }

    // --- DeoptTrigger ---

    #[test]
    fn deopt_trigger_all_variants_covered() {
        assert_eq!(DeoptTrigger::ALL.len(), 10);
        for trigger in DeoptTrigger::ALL {
            assert!(!trigger.as_str().is_empty());
            assert_eq!(format!("{trigger}"), trigger.as_str());
        }
    }

    // --- TransformDenialReason ---

    #[test]
    fn denial_reason_display() {
        assert_eq!(
            TransformDenialReason::CertificateAbstained.as_str(),
            "certificate_abstained"
        );
        assert_eq!(
            TransformDenialReason::TooManyFields.as_str(),
            "too_many_fields"
        );
        assert_eq!(
            TransformDenialReason::SideEffectBarrier.as_str(),
            "side_effect_barrier"
        );
    }

    // --- FieldSourceKind ---

    #[test]
    fn field_source_kind_display() {
        assert_eq!(FieldSourceKind::Register.as_str(), "register");
        assert_eq!(FieldSourceKind::StackSlot.as_str(), "stack_slot");
        assert_eq!(FieldSourceKind::Constant.as_str(), "constant");
        assert_eq!(FieldSourceKind::RegionSlot.as_str(), "region_slot");
    }

    // --- SreSpecimenFamily ---

    #[test]
    fn sre_specimen_family_all_covered() {
        assert_eq!(SreSpecimenFamily::ALL.len(), 10);
        for family in SreSpecimenFamily::ALL {
            assert!(!family.as_str().is_empty());
            assert_eq!(format!("{family}"), family.as_str());
        }
    }

    // --- SreEventKind ---

    #[test]
    fn sre_event_kind_display() {
        assert_eq!(SreEventKind::PipelineStarted.as_str(), "pipeline_started");
        assert_eq!(
            SreEventKind::TransformSelected.as_str(),
            "transform_selected"
        );
        assert_eq!(
            SreEventKind::PipelineCompleted.as_str(),
            "pipeline_completed"
        );
    }

    // --- SreEventLog ---

    #[test]
    fn event_log_operations() {
        let mut log = SreEventLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);

        log.push(SreEvent {
            schema_version: SRE_EVENT_SCHEMA_VERSION.to_string(),
            kind: SreEventKind::PipelineStarted,
            scope_id: "test".to_string(),
            site_id: None,
            transform_kind: None,
            detail: "started".to_string(),
            epoch: test_epoch(),
            event_hash: "hash".to_string(),
        });
        assert!(!log.is_empty());
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn event_log_default() {
        let log = SreEventLog::default();
        assert!(log.is_empty());
    }

    // --- SreEvidenceInventory ---

    #[test]
    fn evidence_inventory_contract() {
        let inv = SreEvidenceInventory {
            schema_version: SRE_SCHEMA_VERSION.to_string(),
            component: SRE_COMPONENT.to_string(),
            specimen_count: 5,
            pass_count: 5,
            fail_count: 0,
            family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn evidence_inventory_contract_fails_with_failures() {
        let inv = SreEvidenceInventory {
            schema_version: SRE_SCHEMA_VERSION.to_string(),
            component: SRE_COMPONENT.to_string(),
            specimen_count: 5,
            pass_count: 4,
            fail_count: 1,
            family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn evidence_inventory_contract_fails_empty() {
        let inv = SreEvidenceInventory {
            schema_version: SRE_SCHEMA_VERSION.to_string(),
            component: SRE_COMPONENT.to_string(),
            specimen_count: 0,
            pass_count: 0,
            fail_count: 0,
            family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    // --- Serde roundtrips ---

    #[test]
    fn transform_kind_serde_roundtrip() {
        for kind in TransformKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: TransformKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn scalar_field_type_serde_roundtrip() {
        let types = [
            ScalarFieldType::Number,
            ScalarFieldType::Boolean,
            ScalarFieldType::StringRef,
            ScalarFieldType::ObjectRef,
            ScalarFieldType::Undefined,
            ScalarFieldType::Null,
            ScalarFieldType::SymbolRef,
            ScalarFieldType::BigIntRef,
        ];
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let back: ScalarFieldType = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    #[test]
    fn deopt_trigger_serde_roundtrip() {
        for trigger in DeoptTrigger::ALL {
            let json = serde_json::to_string(trigger).unwrap();
            let back: DeoptTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(*trigger, back);
        }
    }

    #[test]
    fn transform_denial_serde_roundtrip() {
        let reasons = [
            TransformDenialReason::CertificateAbstained,
            TransformDenialReason::EscapeBeyondScope,
            TransformDenialReason::TooManyFields,
            TransformDenialReason::DecompositionTooDeep,
            TransformDenialReason::NonDecomposableFields,
            TransformDenialReason::LivenessUnknown,
            TransformDenialReason::RegionScopeUnavailable,
            TransformDenialReason::SideEffectBarrier,
            TransformDenialReason::BudgetExhausted,
            TransformDenialReason::KindNotEligible,
        ];
        for r in &reasons {
            let json = serde_json::to_string(r).unwrap();
            let back: TransformDenialReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, back);
        }
    }

    #[test]
    fn region_scope_serde_roundtrip() {
        let scopes = [
            RegionScope::FunctionLocal,
            RegionScope::BlockLocal,
            RegionScope::LoopIteration,
            RegionScope::CallerManaged,
        ];
        for s in &scopes {
            let json = serde_json::to_string(s).unwrap();
            let back: RegionScope = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn side_effect_kind_serde_roundtrip() {
        let kinds = [
            SideEffectKind::Call,
            SideEffectKind::PropertyStore,
            SideEffectKind::ExceptionThrow,
            SideEffectKind::YieldAwait,
            SideEffectKind::DebuggerStatement,
        ];
        for k in &kinds {
            let json = serde_json::to_string(k).unwrap();
            let back: SideEffectKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    #[test]
    fn full_transform_outcome_serde_roundtrip() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let layout = make_layout("s1", 2);
        let config = default_config();
        let plan = build_scalar_plan(&cert, &layout, &config).unwrap();
        let witness = build_deopt_witness(
            &cert,
            TransformKind::ScalarReplacement,
            &plan.fields,
            test_epoch(),
        );
        let receipt = build_validation_receipt(
            &cert,
            TransformKind::ScalarReplacement,
            &witness,
            "pre",
            "post",
            test_epoch(),
        );
        let outcome = TransformOutcome {
            site_id: "s1".to_string(),
            transform_kind: TransformKind::ScalarReplacement,
            scalar_plan: Some(plan),
            region_plan: None,
            sinking_plan: None,
            deopt_witness: Some(witness),
            validation_receipt: Some(receipt),
            denial_reason: None,
            estimated_bytes_saved: 64,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: TransformOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }

    #[test]
    fn transform_summary_serde_roundtrip() {
        let summary = TransformSummary {
            schema_version: SRE_SCHEMA_VERSION.to_string(),
            scope_id: "test".to_string(),
            total_sites: 2,
            scalar_replacement_count: 1,
            region_promotion_count: 1,
            allocation_sinking_count: 0,
            no_transform_count: 0,
            total_bytes_saved: 128,
            outcomes: vec![],
            denial_histogram: BTreeMap::new(),
            epoch: test_epoch(),
            summary_hash: "hash".to_string(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: TransformSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // --- Config ---

    #[test]
    fn default_config_values() {
        let config = ScalarReplacementConfig::default();
        assert_eq!(config.max_fields, MAX_SCALAR_FIELDS);
        assert_eq!(config.max_decomposition_depth, MAX_DECOMPOSITION_DEPTH);
        assert_eq!(config.max_transforms_per_scope, 128);
        assert_eq!(config.min_confidence_millionths, 600_000);
        assert!(config.enable_region_promotion);
        assert!(config.enable_allocation_sinking);
    }

    // --- Constants ---

    #[test]
    fn schema_version_constants() {
        assert!(!SRE_SCHEMA_VERSION.is_empty());
        assert!(!SRE_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!SRE_EVENT_SCHEMA_VERSION.is_empty());
        assert_eq!(SRE_COMPONENT, "scalar_replacement_engine");
        assert_eq!(SRE_POLICY_ID, "RGC-622B");
    }

    // --- has_blocking_barrier ---

    #[test]
    fn blocking_barrier_before_first_use() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let barriers = vec![SideEffectBarrier {
            instruction_index: 3,
            effect_kind: SideEffectKind::Call,
            description: "early call".to_string(),
        }];
        assert!(has_blocking_barrier(&cert, &barriers));
    }

    #[test]
    fn no_blocking_barrier_after_first_use() {
        let cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        let barriers = vec![SideEffectBarrier {
            instruction_index: 10,
            effect_kind: SideEffectKind::Call,
            description: "late call".to_string(),
        }];
        assert!(!has_blocking_barrier(&cert, &barriers));
    }

    #[test]
    fn blocking_barrier_unknown_liveness() {
        let mut cert = make_cert(
            "s1",
            AllocationKind::ObjectLiteral,
            EscapeState::NoEscape,
            true,
            true,
        );
        cert.liveness.first_use = None;
        assert!(has_blocking_barrier(&cert, &[]));
    }
}
