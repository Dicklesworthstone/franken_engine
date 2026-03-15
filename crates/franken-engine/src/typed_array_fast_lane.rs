//! Array and typed-array fast lanes with element-kind transitions,
//! boxed/unboxed movement, and deopt evidence.
//!
//! Implements [RGC-606C]: explicit element-kind tracking for V8-inspired
//! dense/sparse array representations and typed-array validation, with
//! deterministic transition graphs, fast-lane eligibility decisions,
//! and content-hashed certificates for audit trails.
//!
//! Key design decisions:
//! - `ElementKind` captures the six V8-inspired element representations
//!   (SmiInteger, HeapNumber, String, HeapObject, Hole, Packed) to model
//!   the internal storage kind of a JS array.
//! - `ArrayStorageMode` distinguishes dense, sparse, dictionary, and
//!   type-specific fast paths (FastSmi, FastDouble, FastObject).
//! - `ElementTransition` records kind-to-kind transitions with trigger
//!   and reversibility metadata.
//! - `FastLaneDecision` summarises whether a given array profile qualifies
//!   for fast-lane execution or must deopt.
//! - `FastLaneCertificate` bundles a decision with its transition history
//!   and a content hash for deterministic replay.
//! - `TypedArrayValidation` validates typed-array backing-store invariants
//!   (byte alignment, detach state, element count).
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for typed-array fast-lane artifacts.
pub const TYPED_ARRAY_SCHEMA_VERSION: &str = "franken-engine.typed-array-fast-lane.v1";

/// Component identifier for this module.
pub const TYPED_ARRAY_COMPONENT: &str = "typed_array_fast_lane";

/// Policy identifier for RGC-606C.
pub const TYPED_ARRAY_POLICY_ID: &str = "RGC-606C";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLIONTHS: u64 = 1_000_000;

/// Minimum fast-lane hit ratio (in millionths) to qualify for fast-lane.
/// 800_000 = 80%.
const MIN_FAST_LANE_HIT_RATIO: u64 = 800_000;

// ---------------------------------------------------------------------------
// ElementKind
// ---------------------------------------------------------------------------

/// Element kind describes the internal storage representation of array
/// elements, inspired by V8's element-kind lattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElementKind {
    /// Small integer values that fit in a tagged pointer.
    SmiInteger,
    /// Heap-allocated double-precision numbers.
    HeapNumber,
    /// Heap-allocated string values.
    String,
    /// Generic heap-allocated object references.
    HeapObject,
    /// Hole (undefined gap in a sparse array).
    Hole,
    /// Packed dense representation (no holes, homogeneous).
    Packed,
}

impl ElementKind {
    /// All variants in declaration order.
    pub const ALL: &[Self] = &[
        Self::SmiInteger,
        Self::HeapNumber,
        Self::String,
        Self::HeapObject,
        Self::Hole,
        Self::Packed,
    ];

    /// Whether this kind stores unboxed (raw) values.
    pub fn is_unboxed(&self) -> bool {
        matches!(self, Self::SmiInteger | Self::Packed)
    }

    /// Whether this kind is boxed (heap-allocated).
    pub fn is_boxed(&self) -> bool {
        matches!(self, Self::HeapNumber | Self::String | Self::HeapObject)
    }

    /// Whether this kind represents a hole.
    pub fn is_hole(&self) -> bool {
        matches!(self, Self::Hole)
    }

    /// Generality rank (higher = more general).
    pub fn rank(&self) -> u32 {
        match self {
            Self::SmiInteger => 0,
            Self::HeapNumber => 1,
            Self::String => 2,
            Self::Packed => 3,
            Self::HeapObject => 4,
            Self::Hole => 5,
        }
    }

    /// Stable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SmiInteger => "smi_integer",
            Self::HeapNumber => "heap_number",
            Self::String => "string",
            Self::HeapObject => "heap_object",
            Self::Hole => "hole",
            Self::Packed => "packed",
        }
    }
}

impl std::fmt::Display for ElementKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TypedArrayKind
// ---------------------------------------------------------------------------

/// Typed array element types, matching the ECMAScript TypedArray constructors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedArrayKind {
    /// `Int8Array`
    Int8,
    /// `Uint8Array`
    Uint8,
    /// `Uint8ClampedArray`
    Uint8Clamped,
    /// `Int16Array`
    Int16,
    /// `Uint16Array`
    Uint16,
    /// `Int32Array`
    Int32,
    /// `Uint32Array`
    Uint32,
    /// `Float32Array`
    Float32,
    /// `Float64Array`
    Float64,
    /// `BigInt64Array`
    BigInt64,
    /// `BigUint64Array`
    BigUint64,
}

impl TypedArrayKind {
    /// All variants in declaration order.
    pub const ALL: &[Self] = &[
        Self::Int8,
        Self::Uint8,
        Self::Uint8Clamped,
        Self::Int16,
        Self::Uint16,
        Self::Int32,
        Self::Uint32,
        Self::Float32,
        Self::Float64,
        Self::BigInt64,
        Self::BigUint64,
    ];

    /// Stable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Int8 => "int8",
            Self::Uint8 => "uint8",
            Self::Uint8Clamped => "uint8_clamped",
            Self::Int16 => "int16",
            Self::Uint16 => "uint16",
            Self::Int32 => "int32",
            Self::Uint32 => "uint32",
            Self::Float32 => "float32",
            Self::Float64 => "float64",
            Self::BigInt64 => "big_int64",
            Self::BigUint64 => "big_uint64",
        }
    }
}

impl std::fmt::Display for TypedArrayKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ArrayStorageMode
// ---------------------------------------------------------------------------

/// Array storage mode, describing the backing-store strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArrayStorageMode {
    /// Contiguous elements, no gaps.
    Dense,
    /// Sparse representation with a property map.
    Sparse,
    /// Dictionary-mode (hash table) storage.
    Dictionary,
    /// Fast path for SMI-only arrays.
    FastSmi,
    /// Fast path for double-only arrays.
    FastDouble,
    /// Fast path for boxed-object arrays.
    FastObject,
}

impl ArrayStorageMode {
    /// All variants in declaration order.
    pub const ALL: &[Self] = &[
        Self::Dense,
        Self::Sparse,
        Self::Dictionary,
        Self::FastSmi,
        Self::FastDouble,
        Self::FastObject,
    ];

    /// Whether this is a fast-path storage mode.
    pub fn is_fast_path(&self) -> bool {
        matches!(
            self,
            Self::Dense | Self::FastSmi | Self::FastDouble | Self::FastObject
        )
    }

    /// Stable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dense => "dense",
            Self::Sparse => "sparse",
            Self::Dictionary => "dictionary",
            Self::FastSmi => "fast_smi",
            Self::FastDouble => "fast_double",
            Self::FastObject => "fast_object",
        }
    }
}

impl std::fmt::Display for ArrayStorageMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TransitionTrigger
// ---------------------------------------------------------------------------

/// What triggered an element-kind transition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionTrigger {
    /// A non-SMI value was stored into a SMI array.
    StoreNonSmi,
    /// A double (float) value was stored.
    StoreDouble,
    /// A heap object was stored.
    StoreObject,
    /// A hole was introduced (element deletion).
    StoreHole,
    /// Array grew beyond its pre-allocated capacity.
    GrowBeyondCapacity,
    /// Array was shrunk to zero length.
    ShrinkToEmpty,
    /// The backing ArrayBuffer was detached.
    DetachBuffer,
}

impl TransitionTrigger {
    /// All variants.
    pub const ALL: &[Self] = &[
        Self::StoreNonSmi,
        Self::StoreDouble,
        Self::StoreObject,
        Self::StoreHole,
        Self::GrowBeyondCapacity,
        Self::ShrinkToEmpty,
        Self::DetachBuffer,
    ];

    /// Stable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StoreNonSmi => "store_non_smi",
            Self::StoreDouble => "store_double",
            Self::StoreObject => "store_object",
            Self::StoreHole => "store_hole",
            Self::GrowBeyondCapacity => "grow_beyond_capacity",
            Self::ShrinkToEmpty => "shrink_to_empty",
            Self::DetachBuffer => "detach_buffer",
        }
    }
}

// ---------------------------------------------------------------------------
// ElementTransition
// ---------------------------------------------------------------------------

/// Records a single element-kind transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementTransition {
    /// The element kind before the transition.
    pub from_kind: ElementKind,
    /// The element kind after the transition.
    pub to_kind: ElementKind,
    /// What triggered this transition.
    pub trigger: TransitionTrigger,
    /// Whether this transition can be reversed without deopt.
    pub reversible: bool,
}

// ---------------------------------------------------------------------------
// FastLaneConfig
// ---------------------------------------------------------------------------

/// Configuration for fast-lane eligibility evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneConfig {
    /// Maximum length for a dense array to qualify for fast-lane.
    pub max_dense_length: u64,
    /// Minimum SMI range value.
    pub smi_range_min: i64,
    /// Maximum SMI range value.
    pub smi_range_max: i64,
    /// Growth factor in millionths (e.g. 2_000_000 = 2x).
    pub growth_factor_millionths: u64,
    /// Copy-on-write threshold: arrays under this length use COW.
    pub cow_threshold: u64,
}

impl Default for FastLaneConfig {
    fn default() -> Self {
        Self {
            max_dense_length: 65_536,
            smi_range_min: -1_073_741_824,            // -2^30
            smi_range_max: 1_073_741_823,             // 2^30 - 1
            growth_factor_millionths: 2 * MILLIONTHS, // 2.0x
            cow_threshold: 128,
        }
    }
}

// ---------------------------------------------------------------------------
// DeoptReason
// ---------------------------------------------------------------------------

/// Reason why a fast-lane array was deoptimised.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeoptReason {
    /// An element-kind transition forced a deopt.
    ElementKindTransition,
    /// Out-of-bounds access.
    OutOfBounds,
    /// The underlying ArrayBuffer was detached.
    DetachedBuffer,
    /// Too many different element kinds observed (megamorphic).
    Megamorphic,
    /// The array's prototype chain was modified.
    PrototypeModified,
    /// The array was frozen or sealed.
    FrozenOrSealed,
    /// A Proxy trap intercepted the operation.
    ProxyTrap,
}

impl DeoptReason {
    /// All variants.
    pub const ALL: &[Self] = &[
        Self::ElementKindTransition,
        Self::OutOfBounds,
        Self::DetachedBuffer,
        Self::Megamorphic,
        Self::PrototypeModified,
        Self::FrozenOrSealed,
        Self::ProxyTrap,
    ];

    /// Stable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ElementKindTransition => "element_kind_transition",
            Self::OutOfBounds => "out_of_bounds",
            Self::DetachedBuffer => "detached_buffer",
            Self::Megamorphic => "megamorphic",
            Self::PrototypeModified => "prototype_modified",
            Self::FrozenOrSealed => "frozen_or_sealed",
            Self::ProxyTrap => "proxy_trap",
        }
    }
}

// ---------------------------------------------------------------------------
// FastLaneDecision
// ---------------------------------------------------------------------------

/// Outcome of fast-lane eligibility evaluation for a single array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneDecision {
    /// Identifier for the array being evaluated.
    pub array_id: String,
    /// The chosen storage mode.
    pub storage_mode: ArrayStorageMode,
    /// The current element kind.
    pub element_kind: ElementKind,
    /// Whether the array qualifies for fast-lane execution.
    pub is_fast_lane: bool,
    /// If not fast-lane, the reason for deopt.
    pub deopt_reason: Option<DeoptReason>,
}

// ---------------------------------------------------------------------------
// FastLaneCertificate
// ---------------------------------------------------------------------------

/// A content-hashed certificate attesting that a fast-lane decision was
/// made and recorded with its transition history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneCertificate {
    /// Schema version.
    pub schema_version: String,
    /// The array this certificate was issued for.
    pub array_id: String,
    /// The fast-lane decision.
    pub decision: FastLaneDecision,
    /// All transitions that led to the current element kind.
    pub transitions: Vec<ElementTransition>,
    /// Content hash over the certificate data.
    pub certificate_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// TypedArrayValidation
// ---------------------------------------------------------------------------

/// Validation state for a typed array's backing store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedArrayValidation {
    /// The typed array element type.
    pub kind: TypedArrayKind,
    /// Total byte length of the backing buffer.
    pub byte_length: u64,
    /// Number of elements.
    pub element_count: u64,
    /// Whether the buffer has been detached.
    pub is_detached: bool,
    /// Whether this is a SharedArrayBuffer.
    pub is_shared: bool,
    /// Byte offset into the buffer.
    pub byte_offset: u64,
}

// ---------------------------------------------------------------------------
// ArrayProfile
// ---------------------------------------------------------------------------

/// Runtime profiling data for a single array, used to drive fast-lane
/// eligibility decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArrayProfile {
    /// Unique identifier for the array.
    pub id: String,
    /// Total number of accesses observed.
    pub total_accesses: u64,
    /// Proportion of accesses that hit the fast lane, in millionths.
    pub fast_lane_hits_millionths: u64,
    /// Recorded transitions.
    pub transitions: Vec<ElementTransition>,
    /// Current element kind.
    pub current_kind: ElementKind,
    /// Current storage mode.
    pub current_mode: ArrayStorageMode,
}

// ---------------------------------------------------------------------------
// FastLaneError
// ---------------------------------------------------------------------------

/// Errors that can occur during typed-array fast-lane operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastLaneError {
    /// The typed array's buffer has been detached.
    DetachedBuffer,
    /// Byte offset is not aligned to the element size.
    MisalignedByteOffset {
        /// Actual byte offset.
        offset: u64,
        /// Required alignment in bytes.
        alignment: u64,
    },
    /// Byte length does not match expected value.
    InvalidByteLength {
        /// Expected byte length.
        expected: u64,
        /// Actual byte length.
        actual: u64,
    },
    /// Arithmetic overflow protection triggered.
    OverflowProtection,
    /// Invalid element kind for the requested operation.
    InvalidElementKind,
    /// The profile is empty (no accesses recorded).
    EmptyProfile,
}

impl std::fmt::Display for FastLaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DetachedBuffer => write!(f, "typed array buffer is detached"),
            Self::MisalignedByteOffset { offset, alignment } => {
                write!(
                    f,
                    "misaligned byte offset: offset {offset} must be a multiple of {alignment}"
                )
            }
            Self::InvalidByteLength { expected, actual } => {
                write!(f, "invalid byte length: expected {expected}, got {actual}")
            }
            Self::OverflowProtection => write!(f, "arithmetic overflow protection"),
            Self::InvalidElementKind => write!(f, "invalid element kind"),
            Self::EmptyProfile => write!(f, "empty profile: no accesses recorded"),
        }
    }
}

impl std::error::Error for FastLaneError {}

// ---------------------------------------------------------------------------
// FastLaneEvidenceManifest
// ---------------------------------------------------------------------------

/// Evidence manifest summarising a batch of fast-lane evaluations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneEvidenceManifest {
    /// Schema version.
    pub schema_version: String,
    /// Number of profiles evaluated.
    pub profiles_evaluated: u32,
    /// Number that qualified for fast-lane.
    pub fast_lane_count: u32,
    /// Number that required deopt.
    pub deopt_count: u32,
    /// Certificates issued.
    pub certificates: Vec<FastLaneCertificate>,
    /// Content hash over the manifest.
    pub manifest_hash: ContentHash,
    /// Error message if the evidence run failed.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/// Evaluate whether a profiled array qualifies for fast-lane execution.
///
/// Returns a `FastLaneDecision` based on the profile's hit ratio,
/// transition history, and storage mode.
pub fn evaluate_fast_lane(profile: &ArrayProfile, _config: &FastLaneConfig) -> FastLaneDecision {
    // Empty profile cannot be fast-laned.
    if profile.total_accesses == 0 {
        return FastLaneDecision {
            array_id: profile.id.clone(),
            storage_mode: profile.current_mode,
            element_kind: profile.current_kind,
            is_fast_lane: false,
            deopt_reason: Some(DeoptReason::OutOfBounds),
        };
    }

    // Check for megamorphic (too many distinct transition kinds).
    let distinct_kinds = count_distinct_kinds(&profile.transitions);
    if distinct_kinds > 3 {
        return FastLaneDecision {
            array_id: profile.id.clone(),
            storage_mode: profile.current_mode,
            element_kind: profile.current_kind,
            is_fast_lane: false,
            deopt_reason: Some(DeoptReason::Megamorphic),
        };
    }

    // Check if any transition was triggered by detach.
    if profile
        .transitions
        .iter()
        .any(|t| t.trigger == TransitionTrigger::DetachBuffer)
    {
        return FastLaneDecision {
            array_id: profile.id.clone(),
            storage_mode: profile.current_mode,
            element_kind: profile.current_kind,
            is_fast_lane: false,
            deopt_reason: Some(DeoptReason::DetachedBuffer),
        };
    }

    // Check if current kind is a hole (sparse).
    if profile.current_kind == ElementKind::Hole {
        return FastLaneDecision {
            array_id: profile.id.clone(),
            storage_mode: profile.current_mode,
            element_kind: profile.current_kind,
            is_fast_lane: false,
            deopt_reason: Some(DeoptReason::ElementKindTransition),
        };
    }

    // Check the fast-lane hit ratio against the threshold.
    if profile.fast_lane_hits_millionths < MIN_FAST_LANE_HIT_RATIO {
        return FastLaneDecision {
            array_id: profile.id.clone(),
            storage_mode: profile.current_mode,
            element_kind: profile.current_kind,
            is_fast_lane: false,
            deopt_reason: Some(DeoptReason::ElementKindTransition),
        };
    }

    // Storage mode must be a fast path.
    if !profile.current_mode.is_fast_path() {
        return FastLaneDecision {
            array_id: profile.id.clone(),
            storage_mode: profile.current_mode,
            element_kind: profile.current_kind,
            is_fast_lane: false,
            deopt_reason: Some(DeoptReason::ElementKindTransition),
        };
    }

    // Passed all checks — fast-lane eligible.
    // Determine the best storage mode based on element kind.
    let chosen_mode = match profile.current_kind {
        ElementKind::SmiInteger => ArrayStorageMode::FastSmi,
        ElementKind::HeapNumber => ArrayStorageMode::FastDouble,
        ElementKind::Packed => ArrayStorageMode::Dense,
        _ => profile.current_mode,
    };

    FastLaneDecision {
        array_id: profile.id.clone(),
        storage_mode: chosen_mode,
        element_kind: profile.current_kind,
        is_fast_lane: true,
        deopt_reason: None,
    }
}

/// Count distinct element kinds across a set of transitions.
fn count_distinct_kinds(transitions: &[ElementTransition]) -> usize {
    let mut seen = std::collections::BTreeSet::new();
    for t in transitions {
        seen.insert(t.from_kind);
        seen.insert(t.to_kind);
    }
    seen.len()
}

/// Return the set of valid target element kinds reachable from `from`.
///
/// Transitions follow the V8-inspired widening lattice:
/// - SmiInteger -> HeapNumber, Packed, Hole
/// - HeapNumber -> HeapObject, Hole
/// - String -> HeapObject, Hole
/// - HeapObject -> Hole
/// - Packed -> SmiInteger, HeapNumber, HeapObject, Hole
/// - Hole -> (none, terminal)
pub fn allowed_transitions(from: ElementKind) -> Vec<ElementKind> {
    match from {
        ElementKind::SmiInteger => vec![
            ElementKind::HeapNumber,
            ElementKind::Packed,
            ElementKind::Hole,
        ],
        ElementKind::HeapNumber => vec![ElementKind::HeapObject, ElementKind::Hole],
        ElementKind::String => vec![ElementKind::HeapObject, ElementKind::Hole],
        ElementKind::HeapObject => vec![ElementKind::Hole],
        ElementKind::Packed => vec![
            ElementKind::SmiInteger,
            ElementKind::HeapNumber,
            ElementKind::HeapObject,
            ElementKind::Hole,
        ],
        ElementKind::Hole => Vec::new(),
    }
}

/// Whether a transition from `from` to `to` can be reversed without deopt.
///
/// Narrowing transitions (from a more general kind to a more specific kind)
/// are generally not reversible. Only transitions within the packed/smi
/// pair are considered reversible.
pub fn is_transition_reversible(from: ElementKind, to: ElementKind) -> bool {
    matches!(
        (from, to),
        (ElementKind::SmiInteger, ElementKind::Packed)
            | (ElementKind::Packed, ElementKind::SmiInteger)
    )
}

/// Compute the byte size of a single element for a given typed-array kind.
pub fn compute_element_size(kind: &TypedArrayKind) -> u64 {
    match kind {
        TypedArrayKind::Int8 | TypedArrayKind::Uint8 | TypedArrayKind::Uint8Clamped => 1,
        TypedArrayKind::Int16 | TypedArrayKind::Uint16 => 2,
        TypedArrayKind::Int32 | TypedArrayKind::Uint32 | TypedArrayKind::Float32 => 4,
        TypedArrayKind::Float64 | TypedArrayKind::BigInt64 | TypedArrayKind::BigUint64 => 8,
    }
}

/// Validate a typed array's backing-store invariants.
///
/// Checks:
/// 1. Buffer is not detached.
/// 2. `byte_offset` is aligned to the element size.
/// 3. `byte_length` equals `element_count * element_size`.
/// 4. `byte_offset + byte_length` does not overflow.
pub fn validate_typed_array(validation: &TypedArrayValidation) -> Result<(), FastLaneError> {
    if validation.is_detached {
        return Err(FastLaneError::DetachedBuffer);
    }

    let element_size = compute_element_size(&validation.kind);
    if validation.byte_offset % element_size != 0 {
        return Err(FastLaneError::MisalignedByteOffset {
            offset: validation.byte_offset,
            alignment: element_size,
        });
    }

    let expected_byte_length = validation
        .element_count
        .checked_mul(element_size)
        .ok_or(FastLaneError::OverflowProtection)?;

    if validation.byte_length != expected_byte_length {
        return Err(FastLaneError::InvalidByteLength {
            expected: expected_byte_length,
            actual: validation.byte_length,
        });
    }

    // Check for overflow in offset + length.
    validation
        .byte_offset
        .checked_add(validation.byte_length)
        .ok_or(FastLaneError::OverflowProtection)?;

    Ok(())
}

/// Issue a fast-lane certificate for a profiled array.
///
/// Evaluates the profile against the configuration, bundles the decision
/// with the transition history, and computes a content hash.
pub fn certify_fast_lane(profile: &ArrayProfile, config: &FastLaneConfig) -> FastLaneCertificate {
    let decision = evaluate_fast_lane(profile, config);
    let transitions = profile.transitions.clone();

    let mut hash_buf = Vec::new();
    hash_buf.extend_from_slice(TYPED_ARRAY_SCHEMA_VERSION.as_bytes());
    hash_buf.extend_from_slice(profile.id.as_bytes());
    hash_buf.push(u8::from(decision.is_fast_lane));
    hash_buf.extend_from_slice(decision.element_kind.as_str().as_bytes());
    hash_buf.extend_from_slice(decision.storage_mode.as_str().as_bytes());
    for t in &transitions {
        hash_buf.extend_from_slice(t.from_kind.as_str().as_bytes());
        hash_buf.extend_from_slice(t.to_kind.as_str().as_bytes());
        hash_buf.extend_from_slice(t.trigger.as_str().as_bytes());
        hash_buf.push(u8::from(t.reversible));
    }
    let certificate_hash = ContentHash::compute(&hash_buf);

    FastLaneCertificate {
        schema_version: TYPED_ARRAY_SCHEMA_VERSION.to_string(),
        array_id: profile.id.clone(),
        decision,
        transitions,
        certificate_hash,
    }
}

/// Build the full element-kind transition graph.
///
/// Returns a map from each element kind to the set of kinds it can
/// transition to.
pub fn build_transition_graph() -> BTreeMap<ElementKind, Vec<ElementKind>> {
    let mut graph = BTreeMap::new();
    for kind in ElementKind::ALL {
        graph.insert(*kind, allowed_transitions(*kind));
    }
    graph
}

/// Run the fast-lane evidence corpus and produce an evidence manifest.
///
/// Evaluates a set of canonical array profiles and collects certificates.
pub fn run_fast_lane_evidence() -> FastLaneEvidenceManifest {
    let config = FastLaneConfig::default();

    let profiles = canonical_profiles();
    let mut certificates = Vec::new();
    let mut fast_count = 0u32;
    let mut deopt_count = 0u32;

    for profile in &profiles {
        let cert = certify_fast_lane(profile, &config);
        if cert.decision.is_fast_lane {
            fast_count += 1;
        } else {
            deopt_count += 1;
        }
        certificates.push(cert);
    }

    let hash_data = serde_json::to_vec(&certificates).unwrap_or_default();

    FastLaneEvidenceManifest {
        schema_version: TYPED_ARRAY_SCHEMA_VERSION.to_string(),
        profiles_evaluated: profiles.len() as u32,
        fast_lane_count: fast_count,
        deopt_count,
        certificates,
        manifest_hash: ContentHash::compute(&hash_data),
        error: None,
    }
}

/// Canonical array profiles for evidence corpus evaluation.
fn canonical_profiles() -> Vec<ArrayProfile> {
    vec![
        // Profile 1: Pure SMI, fast-lane eligible.
        ArrayProfile {
            id: "smi_dense_array".to_string(),
            total_accesses: 10_000,
            fast_lane_hits_millionths: 950_000,
            transitions: Vec::new(),
            current_kind: ElementKind::SmiInteger,
            current_mode: ArrayStorageMode::FastSmi,
        },
        // Profile 2: Packed array with good hit ratio.
        ArrayProfile {
            id: "packed_array".to_string(),
            total_accesses: 5_000,
            fast_lane_hits_millionths: 900_000,
            transitions: vec![ElementTransition {
                from_kind: ElementKind::SmiInteger,
                to_kind: ElementKind::Packed,
                trigger: TransitionTrigger::StoreNonSmi,
                reversible: true,
            }],
            current_kind: ElementKind::Packed,
            current_mode: ArrayStorageMode::Dense,
        },
        // Profile 3: Megamorphic — too many transitions, should deopt.
        ArrayProfile {
            id: "megamorphic_array".to_string(),
            total_accesses: 1_000,
            fast_lane_hits_millionths: 600_000,
            transitions: vec![
                ElementTransition {
                    from_kind: ElementKind::SmiInteger,
                    to_kind: ElementKind::HeapNumber,
                    trigger: TransitionTrigger::StoreDouble,
                    reversible: false,
                },
                ElementTransition {
                    from_kind: ElementKind::HeapNumber,
                    to_kind: ElementKind::HeapObject,
                    trigger: TransitionTrigger::StoreObject,
                    reversible: false,
                },
                ElementTransition {
                    from_kind: ElementKind::HeapObject,
                    to_kind: ElementKind::Hole,
                    trigger: TransitionTrigger::StoreHole,
                    reversible: false,
                },
            ],
            current_kind: ElementKind::Hole,
            current_mode: ArrayStorageMode::Sparse,
        },
        // Profile 4: Detached buffer — should deopt.
        ArrayProfile {
            id: "detached_buffer_array".to_string(),
            total_accesses: 500,
            fast_lane_hits_millionths: 990_000,
            transitions: vec![ElementTransition {
                from_kind: ElementKind::SmiInteger,
                to_kind: ElementKind::Hole,
                trigger: TransitionTrigger::DetachBuffer,
                reversible: false,
            }],
            current_kind: ElementKind::Hole,
            current_mode: ArrayStorageMode::Sparse,
        },
        // Profile 5: Low hit ratio — should deopt.
        ArrayProfile {
            id: "low_hit_array".to_string(),
            total_accesses: 2_000,
            fast_lane_hits_millionths: 500_000,
            transitions: Vec::new(),
            current_kind: ElementKind::SmiInteger,
            current_mode: ArrayStorageMode::FastSmi,
        },
        // Profile 6: Dictionary mode — not fast path.
        ArrayProfile {
            id: "dictionary_array".to_string(),
            total_accesses: 3_000,
            fast_lane_hits_millionths: 950_000,
            transitions: Vec::new(),
            current_kind: ElementKind::HeapObject,
            current_mode: ArrayStorageMode::Dictionary,
        },
        // Profile 7: HeapNumber with high hit ratio, fast-lane.
        ArrayProfile {
            id: "heap_number_array".to_string(),
            total_accesses: 8_000,
            fast_lane_hits_millionths: 850_000,
            transitions: vec![ElementTransition {
                from_kind: ElementKind::SmiInteger,
                to_kind: ElementKind::HeapNumber,
                trigger: TransitionTrigger::StoreDouble,
                reversible: false,
            }],
            current_kind: ElementKind::HeapNumber,
            current_mode: ArrayStorageMode::FastDouble,
        },
    ]
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ElementKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn element_kind_all_variants() {
        assert_eq!(ElementKind::ALL.len(), 6);
    }

    #[test]
    fn element_kind_unboxed() {
        assert!(ElementKind::SmiInteger.is_unboxed());
        assert!(ElementKind::Packed.is_unboxed());
        assert!(!ElementKind::HeapNumber.is_unboxed());
        assert!(!ElementKind::String.is_unboxed());
        assert!(!ElementKind::HeapObject.is_unboxed());
        assert!(!ElementKind::Hole.is_unboxed());
    }

    #[test]
    fn element_kind_boxed() {
        assert!(ElementKind::HeapNumber.is_boxed());
        assert!(ElementKind::String.is_boxed());
        assert!(ElementKind::HeapObject.is_boxed());
        assert!(!ElementKind::SmiInteger.is_boxed());
        assert!(!ElementKind::Packed.is_boxed());
        assert!(!ElementKind::Hole.is_boxed());
    }

    #[test]
    fn element_kind_rank_ordering() {
        assert!(ElementKind::SmiInteger.rank() < ElementKind::HeapNumber.rank());
        assert!(ElementKind::HeapNumber.rank() < ElementKind::String.rank());
        assert!(ElementKind::String.rank() < ElementKind::Packed.rank());
        assert!(ElementKind::Packed.rank() < ElementKind::HeapObject.rank());
        assert!(ElementKind::HeapObject.rank() < ElementKind::Hole.rank());
    }

    #[test]
    fn element_kind_display() {
        assert_eq!(ElementKind::SmiInteger.to_string(), "smi_integer");
        assert_eq!(ElementKind::Hole.to_string(), "hole");
    }

    // -----------------------------------------------------------------------
    // TypedArrayKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn typed_array_kind_all_variants() {
        assert_eq!(TypedArrayKind::ALL.len(), 11);
    }

    #[test]
    fn typed_array_kind_display() {
        assert_eq!(TypedArrayKind::Int8.to_string(), "int8");
        assert_eq!(TypedArrayKind::BigUint64.to_string(), "big_uint64");
    }

    // -----------------------------------------------------------------------
    // ArrayStorageMode tests
    // -----------------------------------------------------------------------

    #[test]
    fn storage_mode_fast_path() {
        assert!(ArrayStorageMode::Dense.is_fast_path());
        assert!(ArrayStorageMode::FastSmi.is_fast_path());
        assert!(ArrayStorageMode::FastDouble.is_fast_path());
        assert!(ArrayStorageMode::FastObject.is_fast_path());
        assert!(!ArrayStorageMode::Sparse.is_fast_path());
        assert!(!ArrayStorageMode::Dictionary.is_fast_path());
    }

    #[test]
    fn storage_mode_all_variants() {
        assert_eq!(ArrayStorageMode::ALL.len(), 6);
    }

    // -----------------------------------------------------------------------
    // compute_element_size tests
    // -----------------------------------------------------------------------

    #[test]
    fn element_size_one_byte() {
        assert_eq!(compute_element_size(&TypedArrayKind::Int8), 1);
        assert_eq!(compute_element_size(&TypedArrayKind::Uint8), 1);
        assert_eq!(compute_element_size(&TypedArrayKind::Uint8Clamped), 1);
    }

    #[test]
    fn element_size_two_bytes() {
        assert_eq!(compute_element_size(&TypedArrayKind::Int16), 2);
        assert_eq!(compute_element_size(&TypedArrayKind::Uint16), 2);
    }

    #[test]
    fn element_size_four_bytes() {
        assert_eq!(compute_element_size(&TypedArrayKind::Int32), 4);
        assert_eq!(compute_element_size(&TypedArrayKind::Uint32), 4);
        assert_eq!(compute_element_size(&TypedArrayKind::Float32), 4);
    }

    #[test]
    fn element_size_eight_bytes() {
        assert_eq!(compute_element_size(&TypedArrayKind::Float64), 8);
        assert_eq!(compute_element_size(&TypedArrayKind::BigInt64), 8);
        assert_eq!(compute_element_size(&TypedArrayKind::BigUint64), 8);
    }

    // -----------------------------------------------------------------------
    // allowed_transitions tests
    // -----------------------------------------------------------------------

    #[test]
    fn smi_transitions() {
        let targets = allowed_transitions(ElementKind::SmiInteger);
        assert!(targets.contains(&ElementKind::HeapNumber));
        assert!(targets.contains(&ElementKind::Packed));
        assert!(targets.contains(&ElementKind::Hole));
        assert!(!targets.contains(&ElementKind::SmiInteger));
    }

    #[test]
    fn hole_is_terminal() {
        let targets = allowed_transitions(ElementKind::Hole);
        assert!(targets.is_empty());
    }

    #[test]
    fn heap_object_transitions_only_to_hole() {
        let targets = allowed_transitions(ElementKind::HeapObject);
        assert_eq!(targets, vec![ElementKind::Hole]);
    }

    // -----------------------------------------------------------------------
    // is_transition_reversible tests
    // -----------------------------------------------------------------------

    #[test]
    fn reversible_smi_packed() {
        assert!(is_transition_reversible(
            ElementKind::SmiInteger,
            ElementKind::Packed
        ));
        assert!(is_transition_reversible(
            ElementKind::Packed,
            ElementKind::SmiInteger
        ));
    }

    #[test]
    fn irreversible_smi_heap_number() {
        assert!(!is_transition_reversible(
            ElementKind::SmiInteger,
            ElementKind::HeapNumber
        ));
    }

    #[test]
    fn irreversible_heap_number_hole() {
        assert!(!is_transition_reversible(
            ElementKind::HeapNumber,
            ElementKind::Hole
        ));
    }

    // -----------------------------------------------------------------------
    // validate_typed_array tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_valid_int32_array() {
        let v = TypedArrayValidation {
            kind: TypedArrayKind::Int32,
            byte_length: 40,
            element_count: 10,
            is_detached: false,
            is_shared: false,
            byte_offset: 0,
        };
        assert!(validate_typed_array(&v).is_ok());
    }

    #[test]
    fn validate_detached_buffer() {
        let v = TypedArrayValidation {
            kind: TypedArrayKind::Float64,
            byte_length: 80,
            element_count: 10,
            is_detached: true,
            is_shared: false,
            byte_offset: 0,
        };
        assert_eq!(validate_typed_array(&v), Err(FastLaneError::DetachedBuffer));
    }

    #[test]
    fn validate_byte_length_mismatch() {
        let v = TypedArrayValidation {
            kind: TypedArrayKind::Uint16,
            byte_length: 100,
            element_count: 10,
            is_detached: false,
            is_shared: false,
            byte_offset: 0,
        };
        assert_eq!(
            validate_typed_array(&v),
            Err(FastLaneError::InvalidByteLength {
                expected: 20,
                actual: 100,
            })
        );
    }

    #[test]
    fn validate_misaligned_byte_offset() {
        let v = TypedArrayValidation {
            kind: TypedArrayKind::Int32,
            byte_length: 40,
            element_count: 10,
            is_detached: false,
            is_shared: false,
            byte_offset: 2,
        };
        assert_eq!(
            validate_typed_array(&v),
            Err(FastLaneError::MisalignedByteOffset {
                offset: 2,
                alignment: 4,
            })
        );
    }

    #[test]
    fn validate_overflow_protection() {
        let v = TypedArrayValidation {
            kind: TypedArrayKind::Float64,
            byte_length: u64::MAX,
            element_count: u64::MAX,
            is_detached: false,
            is_shared: false,
            byte_offset: 0,
        };
        assert_eq!(
            validate_typed_array(&v),
            Err(FastLaneError::OverflowProtection)
        );
    }

    #[test]
    fn validate_offset_plus_length_overflow() {
        let v = TypedArrayValidation {
            kind: TypedArrayKind::Uint8,
            byte_length: 10,
            element_count: 10,
            is_detached: false,
            is_shared: false,
            byte_offset: u64::MAX - 5,
        };
        assert_eq!(
            validate_typed_array(&v),
            Err(FastLaneError::OverflowProtection)
        );
    }

    // -----------------------------------------------------------------------
    // evaluate_fast_lane tests
    // -----------------------------------------------------------------------

    #[test]
    fn fast_lane_smi_eligible() {
        let config = FastLaneConfig::default();
        let profile = ArrayProfile {
            id: "test_smi".to_string(),
            total_accesses: 1_000,
            fast_lane_hits_millionths: 950_000,
            transitions: Vec::new(),
            current_kind: ElementKind::SmiInteger,
            current_mode: ArrayStorageMode::FastSmi,
        };
        let decision = evaluate_fast_lane(&profile, &config);
        assert!(decision.is_fast_lane);
        assert_eq!(decision.storage_mode, ArrayStorageMode::FastSmi);
        assert!(decision.deopt_reason.is_none());
    }

    #[test]
    fn fast_lane_zero_accesses_rejected() {
        let config = FastLaneConfig::default();
        let profile = ArrayProfile {
            id: "empty".to_string(),
            total_accesses: 0,
            fast_lane_hits_millionths: 0,
            transitions: Vec::new(),
            current_kind: ElementKind::SmiInteger,
            current_mode: ArrayStorageMode::FastSmi,
        };
        let decision = evaluate_fast_lane(&profile, &config);
        assert!(!decision.is_fast_lane);
    }

    #[test]
    fn fast_lane_megamorphic_rejected() {
        let config = FastLaneConfig::default();
        let profile = ArrayProfile {
            id: "mega".to_string(),
            total_accesses: 1_000,
            fast_lane_hits_millionths: 950_000,
            transitions: vec![
                ElementTransition {
                    from_kind: ElementKind::SmiInteger,
                    to_kind: ElementKind::HeapNumber,
                    trigger: TransitionTrigger::StoreDouble,
                    reversible: false,
                },
                ElementTransition {
                    from_kind: ElementKind::HeapNumber,
                    to_kind: ElementKind::String,
                    trigger: TransitionTrigger::StoreObject,
                    reversible: false,
                },
                ElementTransition {
                    from_kind: ElementKind::String,
                    to_kind: ElementKind::HeapObject,
                    trigger: TransitionTrigger::StoreObject,
                    reversible: false,
                },
            ],
            current_kind: ElementKind::HeapObject,
            current_mode: ArrayStorageMode::FastObject,
        };
        let decision = evaluate_fast_lane(&profile, &config);
        assert!(!decision.is_fast_lane);
        assert_eq!(decision.deopt_reason, Some(DeoptReason::Megamorphic));
    }

    #[test]
    fn fast_lane_detach_rejected() {
        let config = FastLaneConfig::default();
        let profile = ArrayProfile {
            id: "detached".to_string(),
            total_accesses: 100,
            fast_lane_hits_millionths: 900_000,
            transitions: vec![ElementTransition {
                from_kind: ElementKind::SmiInteger,
                to_kind: ElementKind::Hole,
                trigger: TransitionTrigger::DetachBuffer,
                reversible: false,
            }],
            current_kind: ElementKind::Hole,
            current_mode: ArrayStorageMode::Sparse,
        };
        let decision = evaluate_fast_lane(&profile, &config);
        assert!(!decision.is_fast_lane);
        assert_eq!(decision.deopt_reason, Some(DeoptReason::DetachedBuffer));
    }

    #[test]
    fn fast_lane_low_hit_ratio_rejected() {
        let config = FastLaneConfig::default();
        let profile = ArrayProfile {
            id: "low_ratio".to_string(),
            total_accesses: 1_000,
            fast_lane_hits_millionths: 500_000,
            transitions: Vec::new(),
            current_kind: ElementKind::SmiInteger,
            current_mode: ArrayStorageMode::FastSmi,
        };
        let decision = evaluate_fast_lane(&profile, &config);
        assert!(!decision.is_fast_lane);
    }

    #[test]
    fn fast_lane_dictionary_mode_rejected() {
        let config = FastLaneConfig::default();
        let profile = ArrayProfile {
            id: "dict".to_string(),
            total_accesses: 1_000,
            fast_lane_hits_millionths: 950_000,
            transitions: Vec::new(),
            current_kind: ElementKind::HeapObject,
            current_mode: ArrayStorageMode::Dictionary,
        };
        let decision = evaluate_fast_lane(&profile, &config);
        assert!(!decision.is_fast_lane);
    }

    #[test]
    fn fast_lane_heap_number_eligible() {
        let config = FastLaneConfig::default();
        let profile = ArrayProfile {
            id: "doubles".to_string(),
            total_accesses: 5_000,
            fast_lane_hits_millionths: 900_000,
            transitions: vec![ElementTransition {
                from_kind: ElementKind::SmiInteger,
                to_kind: ElementKind::HeapNumber,
                trigger: TransitionTrigger::StoreDouble,
                reversible: false,
            }],
            current_kind: ElementKind::HeapNumber,
            current_mode: ArrayStorageMode::FastDouble,
        };
        let decision = evaluate_fast_lane(&profile, &config);
        assert!(decision.is_fast_lane);
        assert_eq!(decision.storage_mode, ArrayStorageMode::FastDouble);
    }

    // -----------------------------------------------------------------------
    // certify_fast_lane tests
    // -----------------------------------------------------------------------

    #[test]
    fn certify_produces_valid_certificate() {
        let config = FastLaneConfig::default();
        let profile = ArrayProfile {
            id: "cert_test".to_string(),
            total_accesses: 2_000,
            fast_lane_hits_millionths: 950_000,
            transitions: Vec::new(),
            current_kind: ElementKind::SmiInteger,
            current_mode: ArrayStorageMode::FastSmi,
        };
        let cert = certify_fast_lane(&profile, &config);
        assert_eq!(cert.schema_version, TYPED_ARRAY_SCHEMA_VERSION);
        assert_eq!(cert.array_id, "cert_test");
        assert!(cert.decision.is_fast_lane);
        assert_ne!(cert.certificate_hash, ContentHash::compute(b""));
    }

    #[test]
    fn certify_deopt_certificate() {
        let config = FastLaneConfig::default();
        let profile = ArrayProfile {
            id: "deopt_cert".to_string(),
            total_accesses: 0,
            fast_lane_hits_millionths: 0,
            transitions: Vec::new(),
            current_kind: ElementKind::SmiInteger,
            current_mode: ArrayStorageMode::FastSmi,
        };
        let cert = certify_fast_lane(&profile, &config);
        assert!(!cert.decision.is_fast_lane);
    }

    // -----------------------------------------------------------------------
    // build_transition_graph tests
    // -----------------------------------------------------------------------

    #[test]
    fn transition_graph_has_all_kinds() {
        let graph = build_transition_graph();
        assert_eq!(graph.len(), ElementKind::ALL.len());
        for kind in ElementKind::ALL {
            assert!(graph.contains_key(kind));
        }
    }

    #[test]
    fn transition_graph_hole_terminal() {
        let graph = build_transition_graph();
        assert!(graph[&ElementKind::Hole].is_empty());
    }

    #[test]
    fn transition_graph_smi_has_targets() {
        let graph = build_transition_graph();
        let smi_targets = &graph[&ElementKind::SmiInteger];
        assert!(!smi_targets.is_empty());
        assert!(smi_targets.contains(&ElementKind::HeapNumber));
    }

    // -----------------------------------------------------------------------
    // run_fast_lane_evidence tests
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_manifest_non_empty() {
        let manifest = run_fast_lane_evidence();
        assert_eq!(manifest.schema_version, TYPED_ARRAY_SCHEMA_VERSION);
        assert!(manifest.profiles_evaluated > 0);
        assert_eq!(
            manifest.fast_lane_count + manifest.deopt_count,
            manifest.profiles_evaluated
        );
        assert!(manifest.error.is_none());
    }

    #[test]
    fn evidence_manifest_deterministic() {
        let m1 = run_fast_lane_evidence();
        let m2 = run_fast_lane_evidence();
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
        assert_eq!(m1.profiles_evaluated, m2.profiles_evaluated);
        assert_eq!(m1.fast_lane_count, m2.fast_lane_count);
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn serde_element_kind_round_trip() {
        for kind in ElementKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: ElementKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn serde_typed_array_kind_round_trip() {
        for kind in TypedArrayKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: TypedArrayKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn serde_deopt_reason_round_trip() {
        for reason in DeoptReason::ALL {
            let json = serde_json::to_string(reason).unwrap();
            let back: DeoptReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, back);
        }
    }

    #[test]
    fn serde_fast_lane_certificate_round_trip() {
        let config = FastLaneConfig::default();
        let profile = ArrayProfile {
            id: "serde_test".to_string(),
            total_accesses: 100,
            fast_lane_hits_millionths: 900_000,
            transitions: vec![ElementTransition {
                from_kind: ElementKind::SmiInteger,
                to_kind: ElementKind::HeapNumber,
                trigger: TransitionTrigger::StoreDouble,
                reversible: false,
            }],
            current_kind: ElementKind::HeapNumber,
            current_mode: ArrayStorageMode::FastDouble,
        };
        let cert = certify_fast_lane(&profile, &config);
        let json = serde_json::to_string(&cert).unwrap();
        let back: FastLaneCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }

    #[test]
    fn serde_evidence_manifest_round_trip() {
        let manifest = run_fast_lane_evidence();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: FastLaneEvidenceManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    // -----------------------------------------------------------------------
    // FastLaneConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn default_config_sane_values() {
        let config = FastLaneConfig::default();
        assert!(config.max_dense_length > 0);
        assert!(config.smi_range_min < 0);
        assert!(config.smi_range_max > 0);
        assert!(config.growth_factor_millionths >= MILLIONTHS);
        assert!(config.cow_threshold > 0);
    }

    // -----------------------------------------------------------------------
    // FastLaneError Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_detached() {
        let err = FastLaneError::DetachedBuffer;
        assert!(err.to_string().contains("detached"));
    }

    #[test]
    fn error_display_invalid_byte_length() {
        let err = FastLaneError::InvalidByteLength {
            expected: 40,
            actual: 80,
        };
        let msg = err.to_string();
        assert!(msg.contains("40"));
        assert!(msg.contains("80"));
    }

    #[test]
    fn error_display_misaligned_byte_offset() {
        let err = FastLaneError::MisalignedByteOffset {
            offset: 6,
            alignment: 4,
        };
        let msg = err.to_string();
        assert!(msg.contains("6"));
        assert!(msg.contains("4"));
        assert!(msg.contains("multiple"));
    }
}
