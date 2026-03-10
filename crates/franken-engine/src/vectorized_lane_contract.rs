#![forbid(unsafe_code)]

//! Row-to-lane lowering contract, selection-vector semantics, scalar oracles,
//! and JS-observable ordering rules for vectorizable builtin families.
//!
//! Implements [RGC-624A]: defines lane semantics (Array.map, Array.filter,
//! string operations, JSON parsing, typed-array bulk ops) so that the runtime
//! can safely widen scalar builtin calls into SIMD-width batches when all
//! preconditions (scalar oracles) are satisfied.
//!
//! Key design decisions:
//! - Each `BuiltinFamily` carries a static `LaneEligibility` record that
//!   declares the maximum lane width, required scalar oracles, ordering
//!   constraints, and masking/early-exit support.
//! - A `SelectionVector` tracks which lanes are active vs. masked, enabling
//!   predicated execution without branching.
//! - `ScalarOracleResult` records whether each precondition (type homogeneity,
//!   no side effects, bounded length, etc.) is satisfied, with a confidence
//!   score in fixed-point millionths.
//! - `LaneContract::evaluate` produces a `VectorizationDecision` that is
//!   either eligible (with a chosen width) or rejected (with a reason).
//! - All decisions are content-hashed for deterministic audit trails.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
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

/// Compute a deterministic content hash from arbitrary bytes.
fn compute_content_hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the vectorized lane contract.
pub const VECTORIZED_LANE_SCHEMA_VERSION: &str = "franken-engine.vectorized-lane-contract.v1";

/// Bead identifier for this module.
pub const VECTORIZED_LANE_BEAD_ID: &str = "bd-1lsy.7.24.1";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Minimum confidence threshold (in millionths) for an oracle to be
/// considered satisfied. 900_000 = 0.9 = 90%.
const MIN_ORACLE_CONFIDENCE: u64 = 900_000;

// ---------------------------------------------------------------------------
// BuiltinFamily
// ---------------------------------------------------------------------------

/// Builtin function families eligible for vectorized lane execution.
///
/// Each variant represents a group of semantically related JS builtins
/// that share lane-width, oracle, and ordering characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinFamily {
    /// `Array.prototype.map`
    ArrayMap,
    /// `Array.prototype.filter`
    ArrayFilter,
    /// `Array.prototype.reduce` / `reduceRight`
    ArrayReduce,
    /// `Array.prototype.forEach`
    ArrayForEach,
    /// `Array.prototype.every`
    ArrayEvery,
    /// `Array.prototype.some`
    ArraySome,
    /// `Array.prototype.find` / `findIndex`
    ArrayFind,
    /// `String.prototype.replace` / `replaceAll`
    StringReplace,
    /// `String.prototype.split`
    StringSplit,
    /// `String.prototype.match` / `matchAll`
    StringMatch,
    /// `JSON.parse`
    JsonParse,
    /// `JSON.stringify`
    JsonStringify,
    /// `TypedArray.prototype.sort`
    TypedArraySort,
    /// `TypedArray.prototype.copyWithin`
    TypedArrayCopy,
    /// `TypedArray.prototype.fill`
    TypedArrayFill,
}

impl BuiltinFamily {
    /// All variants in declaration order.
    pub const ALL: &[Self] = &[
        Self::ArrayMap,
        Self::ArrayFilter,
        Self::ArrayReduce,
        Self::ArrayForEach,
        Self::ArrayEvery,
        Self::ArraySome,
        Self::ArrayFind,
        Self::StringReplace,
        Self::StringSplit,
        Self::StringMatch,
        Self::JsonParse,
        Self::JsonStringify,
        Self::TypedArraySort,
        Self::TypedArrayCopy,
        Self::TypedArrayFill,
    ];

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArrayMap => "array_map",
            Self::ArrayFilter => "array_filter",
            Self::ArrayReduce => "array_reduce",
            Self::ArrayForEach => "array_for_each",
            Self::ArrayEvery => "array_every",
            Self::ArraySome => "array_some",
            Self::ArrayFind => "array_find",
            Self::StringReplace => "string_replace",
            Self::StringSplit => "string_split",
            Self::StringMatch => "string_match",
            Self::JsonParse => "json_parse",
            Self::JsonStringify => "json_stringify",
            Self::TypedArraySort => "typed_array_sort",
            Self::TypedArrayCopy => "typed_array_copy",
            Self::TypedArrayFill => "typed_array_fill",
        }
    }
}

impl fmt::Display for BuiltinFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LaneWidth
// ---------------------------------------------------------------------------

/// Number of elements processed per vectorized step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneWidth {
    /// Single element — no vectorization.
    Scalar,
    /// 4 elements per lane.
    Lane4,
    /// 8 elements per lane.
    Lane8,
    /// 16 elements per lane.
    Lane16,
    /// 32 elements per lane.
    Lane32,
}

impl LaneWidth {
    /// All variants in ascending width order.
    pub const ALL: &[Self] = &[
        Self::Scalar,
        Self::Lane4,
        Self::Lane8,
        Self::Lane16,
        Self::Lane32,
    ];

    /// The number of elements processed per step.
    pub fn width(self) -> u32 {
        match self {
            Self::Scalar => 1,
            Self::Lane4 => 4,
            Self::Lane8 => 8,
            Self::Lane16 => 16,
            Self::Lane32 => 32,
        }
    }

    /// Choose the best lane width that fits within `max_width` and does not
    /// exceed the input length.
    fn best_fit(max_width: Self, input_len: u64) -> Self {
        for &candidate in Self::ALL.iter().rev() {
            if candidate <= max_width && u64::from(candidate.width()) <= input_len {
                return candidate;
            }
        }
        Self::Scalar
    }
}

impl fmt::Display for LaneWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lane_width:{}", self.width())
    }
}

// ---------------------------------------------------------------------------
// SelectionBit
// ---------------------------------------------------------------------------

/// Whether a lane position is selected for execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionBit {
    /// Lane is active — its element participates in the vectorized operation.
    Active,
    /// Lane is masked — its element is skipped.
    Masked,
}

impl fmt::Display for SelectionBit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Masked => f.write_str("masked"),
        }
    }
}

// ---------------------------------------------------------------------------
// SelectionVector
// ---------------------------------------------------------------------------

/// Bit-vector tracking which lanes are active vs. masked for predicated
/// execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SelectionVector {
    bits: Vec<SelectionBit>,
}

impl SelectionVector {
    /// Create a selection vector of `len` lanes, all initially `Active`.
    pub fn new(len: usize) -> Self {
        Self {
            bits: vec![SelectionBit::Active; len],
        }
    }

    /// Number of active lanes.
    pub fn active_count(&self) -> usize {
        self.bits
            .iter()
            .filter(|b| **b == SelectionBit::Active)
            .count()
    }

    /// Number of masked lanes.
    pub fn masked_count(&self) -> usize {
        self.bits
            .iter()
            .filter(|b| **b == SelectionBit::Masked)
            .count()
    }

    /// Mask the lane at `index`. Out-of-bounds indices are silently ignored.
    pub fn mask(&mut self, index: usize) {
        if let Some(bit) = self.bits.get_mut(index) {
            *bit = SelectionBit::Masked;
        }
    }

    /// Whether the lane at `index` is active. Returns `false` for
    /// out-of-bounds indices.
    pub fn is_active(&self, index: usize) -> bool {
        self.bits
            .get(index)
            .is_some_and(|b| *b == SelectionBit::Active)
    }

    /// Whether every lane is active.
    pub fn all_active(&self) -> bool {
        self.bits.iter().all(|b| *b == SelectionBit::Active)
    }

    /// Whether no lane is active (all masked).
    pub fn none_active(&self) -> bool {
        self.bits.iter().all(|b| *b == SelectionBit::Masked)
    }

    /// Total number of lanes.
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Whether the vector is empty (zero lanes).
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }
}

impl fmt::Display for SelectionVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "selection[{}/{}]", self.active_count(), self.bits.len())
    }
}

// ---------------------------------------------------------------------------
// ScalarOracleKind
// ---------------------------------------------------------------------------

/// Categories of scalar-level preconditions that must hold before a builtin
/// can be vectorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarOracleKind {
    /// All elements share a single JS type (e.g., all numbers, all strings).
    TypeHomogeneity,
    /// The callback / operation has no observable side effects.
    NoSideEffects,
    /// The callback / operation cannot throw.
    NoExceptions,
    /// No prototype-chain accesses (no getters, no Proxy traps).
    NoPrototypeAccess,
    /// Input length is within a statically known bound.
    BoundedLength,
    /// Array is dense (no holes, no sparse indices).
    DenseElements,
    /// Array has no holes (undefined gaps).
    NoHoles,
    /// All elements are integers (SMI / int32).
    IntegerOnly,
    /// All string content is valid UTF-8 (no lone surrogates).
    Utf8Only,
}

impl ScalarOracleKind {
    /// All variants in declaration order.
    pub const ALL: &[Self] = &[
        Self::TypeHomogeneity,
        Self::NoSideEffects,
        Self::NoExceptions,
        Self::NoPrototypeAccess,
        Self::BoundedLength,
        Self::DenseElements,
        Self::NoHoles,
        Self::IntegerOnly,
        Self::Utf8Only,
    ];

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TypeHomogeneity => "type_homogeneity",
            Self::NoSideEffects => "no_side_effects",
            Self::NoExceptions => "no_exceptions",
            Self::NoPrototypeAccess => "no_prototype_access",
            Self::BoundedLength => "bounded_length",
            Self::DenseElements => "dense_elements",
            Self::NoHoles => "no_holes",
            Self::IntegerOnly => "integer_only",
            Self::Utf8Only => "utf8_only",
        }
    }
}

impl fmt::Display for ScalarOracleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ScalarOracleResult
// ---------------------------------------------------------------------------

/// Result of evaluating a single scalar oracle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScalarOracleResult {
    /// Which oracle was evaluated.
    pub kind: ScalarOracleKind,
    /// Whether the precondition is satisfied.
    pub satisfied: bool,
    /// Confidence in the result, in fixed-point millionths (1_000_000 = 100%).
    pub confidence_millionths: u64,
    /// Human-readable reason or evidence source.
    pub reason: String,
}

impl ScalarOracleResult {
    /// Create a satisfied oracle result with full confidence.
    pub fn satisfied(kind: ScalarOracleKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            satisfied: true,
            confidence_millionths: MILLION,
            reason: reason.into(),
        }
    }

    /// Create an unsatisfied oracle result.
    pub fn unsatisfied(kind: ScalarOracleKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            satisfied: false,
            confidence_millionths: 0,
            reason: reason.into(),
        }
    }

    /// Whether the result meets the minimum confidence threshold for
    /// vectorization.
    pub fn meets_threshold(&self) -> bool {
        self.satisfied && self.confidence_millionths >= MIN_ORACLE_CONFIDENCE
    }
}

impl fmt::Display for ScalarOracleResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "oracle:{} satisfied={} confidence={}.{}%",
            self.kind,
            self.satisfied,
            self.confidence_millionths / 10_000,
            (self.confidence_millionths % 10_000) / 100,
        )
    }
}

// ---------------------------------------------------------------------------
// OrderingConstraint
// ---------------------------------------------------------------------------

/// Ordering constraint on lane execution relative to JS-observable semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingConstraint {
    /// Lanes must execute left-to-right (index 0, 1, 2, ...).
    /// Required when the callback can observe ordering (e.g., Array.forEach).
    StrictLeftToRight,
    /// Lane execution order is irrelevant; only the final result matters.
    Commutative,
    /// Both associative and commutative — can be tree-reduced.
    AssociativeCommutative,
    /// No ordering constraint at all (purely independent lanes).
    NoOrdering,
}

impl OrderingConstraint {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictLeftToRight => "strict_left_to_right",
            Self::Commutative => "commutative",
            Self::AssociativeCommutative => "associative_commutative",
            Self::NoOrdering => "no_ordering",
        }
    }
}

impl fmt::Display for OrderingConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LaneEligibility
// ---------------------------------------------------------------------------

/// Static eligibility record for a builtin family, declaring the maximum
/// lane width, required scalar oracles, ordering constraints, and
/// masking/early-exit support.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LaneEligibility {
    /// The builtin family this record describes.
    pub family: BuiltinFamily,
    /// Maximum lane width the family can use.
    pub max_lane_width: LaneWidth,
    /// Scalar oracles that must all be satisfied before vectorization.
    pub required_oracles: Vec<ScalarOracleKind>,
    /// Ordering constraint imposed by JS semantics.
    pub ordering: OrderingConstraint,
    /// Whether the operation supports early exit (e.g., Array.some/every/find).
    pub supports_early_exit: bool,
    /// Whether the operation supports masked lanes (predicated execution).
    pub supports_masking: bool,
}

// ---------------------------------------------------------------------------
// VectorizationDecision
// ---------------------------------------------------------------------------

/// The outcome of evaluating a builtin call for vectorized execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VectorizationDecision {
    /// The builtin family evaluated.
    pub family: BuiltinFamily,
    /// The chosen lane width (Scalar if rejected).
    pub chosen_width: LaneWidth,
    /// Oracle results that informed the decision.
    pub oracle_results: Vec<ScalarOracleResult>,
    /// Selection vector for the first batch.
    pub selection: SelectionVector,
    /// Whether vectorization is eligible.
    pub eligible: bool,
    /// If not eligible, the reason for rejection.
    pub rejection_reason: Option<String>,
    /// Deterministic content hash for audit trails.
    pub content_hash: ContentHash,
}

impl VectorizationDecision {
    /// Compute a deterministic content hash from the decision fields.
    fn compute_hash(
        family: &BuiltinFamily,
        chosen_width: &LaneWidth,
        eligible: bool,
        rejection_reason: &Option<String>,
    ) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(family.as_str().as_bytes());
        buf.extend_from_slice(&chosen_width.width().to_le_bytes());
        buf.push(u8::from(eligible));
        if let Some(reason) = rejection_reason {
            buf.extend_from_slice(reason.as_bytes());
        }
        compute_content_hash(&buf)
    }
}

impl fmt::Display for VectorizationDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.eligible {
            write!(
                f,
                "decision:eligible family={} width={} hash={}",
                self.family,
                self.chosen_width,
                hex_encode(self.content_hash.as_bytes())
            )
        } else {
            write!(
                f,
                "decision:rejected family={} reason={}",
                self.family,
                self.rejection_reason.as_deref().unwrap_or("unknown")
            )
        }
    }
}

// ---------------------------------------------------------------------------
// LaneSpecimenFamily
// ---------------------------------------------------------------------------

/// Evidence corpus families for vectorized-lane specimens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneSpecimenFamily {
    /// Specimens for Array builtin operations.
    ArrayOps,
    /// Specimens for String builtin operations.
    StringOps,
    /// Specimens for JSON builtin operations.
    JsonOps,
    /// Specimens for TypedArray builtin operations.
    TypedArrayOps,
    /// Specimens exercising mixed lane widths.
    MixedWidth,
    /// Specimens focusing on oracle evaluation paths.
    OracleEvaluation,
}

impl LaneSpecimenFamily {
    /// All variants in declaration order.
    pub const ALL: &[Self] = &[
        Self::ArrayOps,
        Self::StringOps,
        Self::JsonOps,
        Self::TypedArrayOps,
        Self::MixedWidth,
        Self::OracleEvaluation,
    ];

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArrayOps => "array_ops",
            Self::StringOps => "string_ops",
            Self::JsonOps => "json_ops",
            Self::TypedArrayOps => "typed_array_ops",
            Self::MixedWidth => "mixed_width",
            Self::OracleEvaluation => "oracle_evaluation",
        }
    }
}

impl fmt::Display for LaneSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LaneContract
// ---------------------------------------------------------------------------

/// The vectorized-lane contract: contains eligibility rules for all builtin
/// families and provides the `evaluate` entry point for vectorization
/// decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneContract {
    /// Eligibility records for all builtin families.
    pub eligibility_map: Vec<LaneEligibility>,
    /// Schema version for serialization compatibility.
    pub schema_version: String,
}

impl LaneContract {
    /// Create a contract with default eligibility rules for all builtin
    /// families.
    pub fn new() -> Self {
        Self {
            eligibility_map: Self::default_eligibility(),
            schema_version: VECTORIZED_LANE_SCHEMA_VERSION.to_string(),
        }
    }

    /// Look up the eligibility record for a given builtin family.
    pub fn lookup(&self, family: BuiltinFamily) -> Option<&LaneEligibility> {
        self.eligibility_map.iter().find(|e| e.family == family)
    }

    /// Evaluate whether a builtin call can be vectorized.
    ///
    /// # Arguments
    /// - `family`: the builtin to evaluate.
    /// - `oracles`: results of scalar oracle checks for this call site.
    /// - `input_len`: number of elements in the input (e.g., array length).
    /// - `_epoch`: security epoch for audit tagging (currently unused but
    ///   reserved for future epoch-scoped policy gating).
    pub fn evaluate(
        &self,
        family: BuiltinFamily,
        oracles: &[ScalarOracleResult],
        input_len: u64,
        _epoch: SecurityEpoch,
    ) -> VectorizationDecision {
        let eligibility = match self.lookup(family) {
            Some(e) => e,
            None => {
                return Self::rejected(family, "no eligibility record for family".to_string());
            }
        };

        // Check that every required oracle is present and satisfied.
        for required in &eligibility.required_oracles {
            match oracles.iter().find(|o| o.kind == *required) {
                Some(result) if result.meets_threshold() => {}
                Some(result) => {
                    let reason = format!(
                        "oracle {} not met: satisfied={}, confidence={}",
                        required, result.satisfied, result.confidence_millionths
                    );
                    return Self::rejected(family, reason);
                }
                None => {
                    let reason = format!("missing required oracle: {}", required);
                    return Self::rejected(family, reason);
                }
            }
        }

        // Input length must be at least 1 for vectorization to make sense.
        if input_len == 0 {
            return Self::rejected(family, "zero-length input".to_string());
        }

        // Choose the best-fit lane width.
        let chosen_width = LaneWidth::best_fit(eligibility.max_lane_width, input_len);

        // Build the selection vector (all active for the first batch).
        let batch_size = chosen_width.width() as usize;
        let selection = SelectionVector::new(batch_size);

        let content_hash = VectorizationDecision::compute_hash(&family, &chosen_width, true, &None);

        VectorizationDecision {
            family,
            chosen_width,
            oracle_results: oracles.to_vec(),
            selection,
            eligible: true,
            rejection_reason: None,
            content_hash,
        }
    }

    /// Compute a deterministic content hash over the entire contract.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.schema_version.as_bytes());
        for entry in &self.eligibility_map {
            buf.extend_from_slice(entry.family.as_str().as_bytes());
            buf.extend_from_slice(&entry.max_lane_width.width().to_le_bytes());
            buf.push(u8::from(entry.supports_early_exit));
            buf.push(u8::from(entry.supports_masking));
            buf.extend_from_slice(entry.ordering.as_str().as_bytes());
            for oracle in &entry.required_oracles {
                buf.extend_from_slice(oracle.as_str().as_bytes());
            }
        }
        compute_content_hash(&buf)
    }

    /// Build a rejected decision.
    fn rejected(family: BuiltinFamily, reason: String) -> VectorizationDecision {
        let rejection_reason = Some(reason);
        let content_hash = VectorizationDecision::compute_hash(
            &family,
            &LaneWidth::Scalar,
            false,
            &rejection_reason,
        );
        VectorizationDecision {
            family,
            chosen_width: LaneWidth::Scalar,
            oracle_results: Vec::new(),
            selection: SelectionVector::new(0),
            eligible: false,
            rejection_reason,
            content_hash,
        }
    }

    /// Default eligibility records for all builtin families.
    fn default_eligibility() -> Vec<LaneEligibility> {
        vec![
            // --- Array operations ---
            LaneEligibility {
                family: BuiltinFamily::ArrayMap,
                max_lane_width: LaneWidth::Lane16,
                required_oracles: vec![
                    ScalarOracleKind::TypeHomogeneity,
                    ScalarOracleKind::NoSideEffects,
                    ScalarOracleKind::NoExceptions,
                    ScalarOracleKind::DenseElements,
                ],
                ordering: OrderingConstraint::NoOrdering,
                supports_early_exit: false,
                supports_masking: true,
            },
            LaneEligibility {
                family: BuiltinFamily::ArrayFilter,
                max_lane_width: LaneWidth::Lane16,
                required_oracles: vec![
                    ScalarOracleKind::TypeHomogeneity,
                    ScalarOracleKind::NoSideEffects,
                    ScalarOracleKind::NoExceptions,
                    ScalarOracleKind::DenseElements,
                ],
                ordering: OrderingConstraint::StrictLeftToRight,
                supports_early_exit: false,
                supports_masking: true,
            },
            LaneEligibility {
                family: BuiltinFamily::ArrayReduce,
                max_lane_width: LaneWidth::Lane8,
                required_oracles: vec![
                    ScalarOracleKind::TypeHomogeneity,
                    ScalarOracleKind::NoSideEffects,
                    ScalarOracleKind::NoExceptions,
                    ScalarOracleKind::IntegerOnly,
                ],
                ordering: OrderingConstraint::AssociativeCommutative,
                supports_early_exit: false,
                supports_masking: false,
            },
            LaneEligibility {
                family: BuiltinFamily::ArrayForEach,
                max_lane_width: LaneWidth::Lane16,
                required_oracles: vec![
                    ScalarOracleKind::NoSideEffects,
                    ScalarOracleKind::NoExceptions,
                    ScalarOracleKind::DenseElements,
                ],
                ordering: OrderingConstraint::StrictLeftToRight,
                supports_early_exit: false,
                supports_masking: false,
            },
            LaneEligibility {
                family: BuiltinFamily::ArrayEvery,
                max_lane_width: LaneWidth::Lane16,
                required_oracles: vec![
                    ScalarOracleKind::TypeHomogeneity,
                    ScalarOracleKind::NoSideEffects,
                    ScalarOracleKind::NoExceptions,
                    ScalarOracleKind::DenseElements,
                ],
                ordering: OrderingConstraint::Commutative,
                supports_early_exit: true,
                supports_masking: true,
            },
            LaneEligibility {
                family: BuiltinFamily::ArraySome,
                max_lane_width: LaneWidth::Lane16,
                required_oracles: vec![
                    ScalarOracleKind::TypeHomogeneity,
                    ScalarOracleKind::NoSideEffects,
                    ScalarOracleKind::NoExceptions,
                    ScalarOracleKind::DenseElements,
                ],
                ordering: OrderingConstraint::Commutative,
                supports_early_exit: true,
                supports_masking: true,
            },
            LaneEligibility {
                family: BuiltinFamily::ArrayFind,
                max_lane_width: LaneWidth::Lane8,
                required_oracles: vec![
                    ScalarOracleKind::TypeHomogeneity,
                    ScalarOracleKind::NoSideEffects,
                    ScalarOracleKind::NoExceptions,
                    ScalarOracleKind::DenseElements,
                ],
                ordering: OrderingConstraint::StrictLeftToRight,
                supports_early_exit: true,
                supports_masking: true,
            },
            // --- String operations ---
            LaneEligibility {
                family: BuiltinFamily::StringReplace,
                max_lane_width: LaneWidth::Lane4,
                required_oracles: vec![ScalarOracleKind::Utf8Only, ScalarOracleKind::BoundedLength],
                ordering: OrderingConstraint::StrictLeftToRight,
                supports_early_exit: false,
                supports_masking: false,
            },
            LaneEligibility {
                family: BuiltinFamily::StringSplit,
                max_lane_width: LaneWidth::Lane4,
                required_oracles: vec![ScalarOracleKind::Utf8Only, ScalarOracleKind::BoundedLength],
                ordering: OrderingConstraint::StrictLeftToRight,
                supports_early_exit: false,
                supports_masking: false,
            },
            LaneEligibility {
                family: BuiltinFamily::StringMatch,
                max_lane_width: LaneWidth::Lane4,
                required_oracles: vec![ScalarOracleKind::Utf8Only, ScalarOracleKind::BoundedLength],
                ordering: OrderingConstraint::StrictLeftToRight,
                supports_early_exit: false,
                supports_masking: false,
            },
            // --- JSON operations ---
            LaneEligibility {
                family: BuiltinFamily::JsonParse,
                max_lane_width: LaneWidth::Lane4,
                required_oracles: vec![
                    ScalarOracleKind::Utf8Only,
                    ScalarOracleKind::BoundedLength,
                    ScalarOracleKind::NoPrototypeAccess,
                ],
                ordering: OrderingConstraint::NoOrdering,
                supports_early_exit: false,
                supports_masking: true,
            },
            LaneEligibility {
                family: BuiltinFamily::JsonStringify,
                max_lane_width: LaneWidth::Lane4,
                required_oracles: vec![
                    ScalarOracleKind::NoPrototypeAccess,
                    ScalarOracleKind::BoundedLength,
                ],
                ordering: OrderingConstraint::NoOrdering,
                supports_early_exit: false,
                supports_masking: true,
            },
            // --- TypedArray operations ---
            LaneEligibility {
                family: BuiltinFamily::TypedArraySort,
                max_lane_width: LaneWidth::Lane32,
                required_oracles: vec![ScalarOracleKind::IntegerOnly],
                ordering: OrderingConstraint::AssociativeCommutative,
                supports_early_exit: false,
                supports_masking: false,
            },
            LaneEligibility {
                family: BuiltinFamily::TypedArrayCopy,
                max_lane_width: LaneWidth::Lane32,
                required_oracles: vec![ScalarOracleKind::BoundedLength],
                ordering: OrderingConstraint::StrictLeftToRight,
                supports_early_exit: false,
                supports_masking: false,
            },
            LaneEligibility {
                family: BuiltinFamily::TypedArrayFill,
                max_lane_width: LaneWidth::Lane32,
                required_oracles: vec![],
                ordering: OrderingConstraint::NoOrdering,
                supports_early_exit: false,
                supports_masking: false,
            },
        ]
    }
}

impl Default for LaneContract {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LaneContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LaneContract[{}] families={} hash={}",
            self.schema_version,
            self.eligibility_map.len(),
            hex_encode(self.content_hash().as_bytes())
        )
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // BuiltinFamily tests
    // -----------------------------------------------------------------------

    #[test]
    fn builtin_family_variant_count() {
        assert_eq!(BuiltinFamily::ALL.len(), 15);
    }

    #[test]
    fn builtin_family_display_round_trip() {
        for &family in BuiltinFamily::ALL {
            let s = family.to_string();
            assert_eq!(s, family.as_str());
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn builtin_family_serde_round_trip() {
        for &family in BuiltinFamily::ALL {
            let json = serde_json::to_string(&family).unwrap();
            let back: BuiltinFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(back, family);
        }
    }

    #[test]
    fn builtin_family_ordering_is_stable() {
        assert!(BuiltinFamily::ArrayMap < BuiltinFamily::ArrayFilter);
        assert!(BuiltinFamily::ArrayFilter < BuiltinFamily::TypedArrayFill);
    }

    // -----------------------------------------------------------------------
    // LaneWidth tests
    // -----------------------------------------------------------------------

    #[test]
    fn lane_width_values() {
        assert_eq!(LaneWidth::Scalar.width(), 1);
        assert_eq!(LaneWidth::Lane4.width(), 4);
        assert_eq!(LaneWidth::Lane8.width(), 8);
        assert_eq!(LaneWidth::Lane16.width(), 16);
        assert_eq!(LaneWidth::Lane32.width(), 32);
    }

    #[test]
    fn lane_width_ordering() {
        assert!(LaneWidth::Scalar < LaneWidth::Lane4);
        assert!(LaneWidth::Lane4 < LaneWidth::Lane8);
        assert!(LaneWidth::Lane8 < LaneWidth::Lane16);
        assert!(LaneWidth::Lane16 < LaneWidth::Lane32);
    }

    #[test]
    fn lane_width_display() {
        assert_eq!(LaneWidth::Lane8.to_string(), "lane_width:8");
        assert_eq!(LaneWidth::Scalar.to_string(), "lane_width:1");
    }

    #[test]
    fn lane_width_best_fit_small_input() {
        // Input length 3 with max Lane16 → should pick Scalar (3 < 4)
        let w = LaneWidth::best_fit(LaneWidth::Lane16, 3);
        assert_eq!(w, LaneWidth::Scalar);
    }

    #[test]
    fn lane_width_best_fit_exact() {
        let w = LaneWidth::best_fit(LaneWidth::Lane8, 8);
        assert_eq!(w, LaneWidth::Lane8);
    }

    #[test]
    fn lane_width_best_fit_capped_by_max() {
        // Max is Lane4, even though input is large.
        let w = LaneWidth::best_fit(LaneWidth::Lane4, 1000);
        assert_eq!(w, LaneWidth::Lane4);
    }

    // -----------------------------------------------------------------------
    // SelectionBit tests
    // -----------------------------------------------------------------------

    #[test]
    fn selection_bit_display() {
        assert_eq!(SelectionBit::Active.to_string(), "active");
        assert_eq!(SelectionBit::Masked.to_string(), "masked");
    }

    // -----------------------------------------------------------------------
    // SelectionVector tests
    // -----------------------------------------------------------------------

    #[test]
    fn selection_vector_all_active() {
        let sv = SelectionVector::new(8);
        assert!(sv.all_active());
        assert!(!sv.none_active());
        assert_eq!(sv.active_count(), 8);
        assert_eq!(sv.masked_count(), 0);
        assert_eq!(sv.len(), 8);
    }

    #[test]
    fn selection_vector_mask_element() {
        let mut sv = SelectionVector::new(4);
        sv.mask(1);
        sv.mask(3);
        assert!(!sv.all_active());
        assert!(!sv.none_active());
        assert_eq!(sv.active_count(), 2);
        assert_eq!(sv.masked_count(), 2);
        assert!(sv.is_active(0));
        assert!(!sv.is_active(1));
        assert!(sv.is_active(2));
        assert!(!sv.is_active(3));
    }

    #[test]
    fn selection_vector_mask_all() {
        let mut sv = SelectionVector::new(3);
        sv.mask(0);
        sv.mask(1);
        sv.mask(2);
        assert!(sv.none_active());
        assert!(!sv.all_active());
    }

    #[test]
    fn selection_vector_empty() {
        let sv = SelectionVector::new(0);
        assert!(sv.is_empty());
        assert!(sv.all_active());
        assert!(sv.none_active());
        assert_eq!(sv.active_count(), 0);
    }

    #[test]
    fn selection_vector_out_of_bounds_mask() {
        let mut sv = SelectionVector::new(2);
        sv.mask(999); // should not panic
        assert!(sv.all_active());
    }

    #[test]
    fn selection_vector_out_of_bounds_is_active() {
        let sv = SelectionVector::new(2);
        assert!(!sv.is_active(999));
    }

    #[test]
    fn selection_vector_display() {
        let mut sv = SelectionVector::new(4);
        sv.mask(1);
        assert_eq!(sv.to_string(), "selection[3/4]");
    }

    #[test]
    fn selection_vector_serde_round_trip() {
        let mut sv = SelectionVector::new(4);
        sv.mask(2);
        let json = serde_json::to_string(&sv).unwrap();
        let back: SelectionVector = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sv);
    }

    // -----------------------------------------------------------------------
    // ScalarOracleKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn scalar_oracle_kind_variant_count() {
        assert_eq!(ScalarOracleKind::ALL.len(), 9);
    }

    #[test]
    fn scalar_oracle_kind_display() {
        assert_eq!(
            ScalarOracleKind::TypeHomogeneity.to_string(),
            "type_homogeneity"
        );
        assert_eq!(
            ScalarOracleKind::NoSideEffects.to_string(),
            "no_side_effects"
        );
    }

    #[test]
    fn scalar_oracle_kind_serde_round_trip() {
        for &kind in ScalarOracleKind::ALL {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ScalarOracleKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    // -----------------------------------------------------------------------
    // ScalarOracleResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn oracle_result_satisfied_meets_threshold() {
        let r = ScalarOracleResult::satisfied(ScalarOracleKind::NoHoles, "dense array check");
        assert!(r.meets_threshold());
        assert_eq!(r.confidence_millionths, MILLION);
    }

    #[test]
    fn oracle_result_unsatisfied_does_not_meet_threshold() {
        let r = ScalarOracleResult::unsatisfied(ScalarOracleKind::NoHoles, "sparse array");
        assert!(!r.meets_threshold());
    }

    #[test]
    fn oracle_result_low_confidence_does_not_meet_threshold() {
        let r = ScalarOracleResult {
            kind: ScalarOracleKind::IntegerOnly,
            satisfied: true,
            confidence_millionths: 500_000, // 50% — below 90% threshold
            reason: "mixed types observed".to_string(),
        };
        assert!(!r.meets_threshold());
    }

    // -----------------------------------------------------------------------
    // OrderingConstraint tests
    // -----------------------------------------------------------------------

    #[test]
    fn ordering_constraint_display() {
        assert_eq!(
            OrderingConstraint::StrictLeftToRight.to_string(),
            "strict_left_to_right"
        );
        assert_eq!(OrderingConstraint::Commutative.to_string(), "commutative");
        assert_eq!(
            OrderingConstraint::AssociativeCommutative.to_string(),
            "associative_commutative"
        );
        assert_eq!(OrderingConstraint::NoOrdering.to_string(), "no_ordering");
    }

    // -----------------------------------------------------------------------
    // LaneEligibility tests
    // -----------------------------------------------------------------------

    #[test]
    fn lane_eligibility_defaults_cover_all_families() {
        let contract = LaneContract::new();
        for &family in BuiltinFamily::ALL {
            assert!(
                contract.lookup(family).is_some(),
                "missing eligibility for {:?}",
                family,
            );
        }
    }

    #[test]
    fn array_map_eligibility_properties() {
        let contract = LaneContract::new();
        let e = contract.lookup(BuiltinFamily::ArrayMap).unwrap();
        assert_eq!(e.max_lane_width, LaneWidth::Lane16);
        assert!(!e.supports_early_exit);
        assert!(e.supports_masking);
        assert_eq!(e.ordering, OrderingConstraint::NoOrdering);
    }

    #[test]
    fn array_every_supports_early_exit() {
        let contract = LaneContract::new();
        let e = contract.lookup(BuiltinFamily::ArrayEvery).unwrap();
        assert!(e.supports_early_exit);
    }

    #[test]
    fn typed_array_fill_no_required_oracles() {
        let contract = LaneContract::new();
        let e = contract.lookup(BuiltinFamily::TypedArrayFill).unwrap();
        assert!(e.required_oracles.is_empty());
    }

    // -----------------------------------------------------------------------
    // VectorizationDecision tests
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_eligible_array_map() {
        let contract = LaneContract::new();
        let oracles = vec![
            ScalarOracleResult::satisfied(ScalarOracleKind::TypeHomogeneity, "all numbers"),
            ScalarOracleResult::satisfied(ScalarOracleKind::NoSideEffects, "pure function"),
            ScalarOracleResult::satisfied(ScalarOracleKind::NoExceptions, "no throw"),
            ScalarOracleResult::satisfied(ScalarOracleKind::DenseElements, "no holes"),
        ];
        let epoch = SecurityEpoch::from_raw(1);
        let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, epoch);
        assert!(decision.eligible);
        assert_eq!(decision.chosen_width, LaneWidth::Lane16);
        assert!(decision.rejection_reason.is_none());
    }

    #[test]
    fn evaluate_rejected_missing_oracle() {
        let contract = LaneContract::new();
        // Only provide one of the four required oracles for ArrayMap.
        let oracles = vec![ScalarOracleResult::satisfied(
            ScalarOracleKind::TypeHomogeneity,
            "ok",
        )];
        let epoch = SecurityEpoch::from_raw(1);
        let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, epoch);
        assert!(!decision.eligible);
        assert!(decision.rejection_reason.is_some());
        assert!(
            decision
                .rejection_reason
                .as_ref()
                .unwrap()
                .contains("missing required oracle")
        );
    }

    #[test]
    fn evaluate_rejected_unsatisfied_oracle() {
        let contract = LaneContract::new();
        let oracles = vec![
            ScalarOracleResult::satisfied(ScalarOracleKind::TypeHomogeneity, "ok"),
            ScalarOracleResult::unsatisfied(ScalarOracleKind::NoSideEffects, "has side effects"),
            ScalarOracleResult::satisfied(ScalarOracleKind::NoExceptions, "ok"),
            ScalarOracleResult::satisfied(ScalarOracleKind::DenseElements, "ok"),
        ];
        let epoch = SecurityEpoch::from_raw(1);
        let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, epoch);
        assert!(!decision.eligible);
        assert!(
            decision
                .rejection_reason
                .as_ref()
                .unwrap()
                .contains("not met")
        );
    }

    #[test]
    fn evaluate_rejected_zero_length_input() {
        let contract = LaneContract::new();
        let epoch = SecurityEpoch::from_raw(1);
        // TypedArrayFill has no required oracles, but zero length should reject.
        let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 0, epoch);
        assert!(!decision.eligible);
        assert!(
            decision
                .rejection_reason
                .as_ref()
                .unwrap()
                .contains("zero-length")
        );
    }

    #[test]
    fn evaluate_eligible_typed_array_fill_no_oracles() {
        let contract = LaneContract::new();
        let epoch = SecurityEpoch::from_raw(1);
        let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 64, epoch);
        assert!(decision.eligible);
        assert_eq!(decision.chosen_width, LaneWidth::Lane32);
    }

    #[test]
    fn evaluate_small_input_falls_back_to_scalar() {
        let contract = LaneContract::new();
        let oracles = vec![
            ScalarOracleResult::satisfied(ScalarOracleKind::TypeHomogeneity, "ok"),
            ScalarOracleResult::satisfied(ScalarOracleKind::NoSideEffects, "ok"),
            ScalarOracleResult::satisfied(ScalarOracleKind::NoExceptions, "ok"),
            ScalarOracleResult::satisfied(ScalarOracleKind::DenseElements, "ok"),
        ];
        let epoch = SecurityEpoch::from_raw(1);
        let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 2, epoch);
        assert!(decision.eligible);
        assert_eq!(decision.chosen_width, LaneWidth::Scalar);
    }

    // -----------------------------------------------------------------------
    // Content hash determinism
    // -----------------------------------------------------------------------

    #[test]
    fn content_hash_deterministic() {
        let c1 = LaneContract::new();
        let c2 = LaneContract::new();
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn decision_hash_changes_with_family() {
        let contract = LaneContract::new();
        let epoch = SecurityEpoch::from_raw(1);
        let d1 = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 64, epoch);
        let d2 = contract.evaluate(
            BuiltinFamily::TypedArrayCopy,
            &[ScalarOracleResult::satisfied(
                ScalarOracleKind::BoundedLength,
                "ok",
            )],
            64,
            epoch,
        );
        assert_ne!(d1.content_hash, d2.content_hash);
    }

    // -----------------------------------------------------------------------
    // LaneSpecimenFamily tests
    // -----------------------------------------------------------------------

    #[test]
    fn lane_specimen_family_variant_count() {
        assert_eq!(LaneSpecimenFamily::ALL.len(), 6);
    }

    #[test]
    fn lane_specimen_family_display() {
        assert_eq!(LaneSpecimenFamily::ArrayOps.to_string(), "array_ops");
        assert_eq!(
            LaneSpecimenFamily::OracleEvaluation.to_string(),
            "oracle_evaluation"
        );
    }

    #[test]
    fn lane_specimen_family_serde_round_trip() {
        for &family in LaneSpecimenFamily::ALL {
            let json = serde_json::to_string(&family).unwrap();
            let back: LaneSpecimenFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(back, family);
        }
    }

    // -----------------------------------------------------------------------
    // LaneContract tests
    // -----------------------------------------------------------------------

    #[test]
    fn lane_contract_schema_version() {
        let c = LaneContract::new();
        assert_eq!(c.schema_version, VECTORIZED_LANE_SCHEMA_VERSION);
    }

    #[test]
    fn lane_contract_display() {
        let c = LaneContract::new();
        let s = c.to_string();
        assert!(s.contains("LaneContract"));
        assert!(s.contains("families=15"));
    }

    #[test]
    fn lane_contract_default() {
        let c = LaneContract::default();
        assert_eq!(c.eligibility_map.len(), 15);
    }

    #[test]
    fn lane_contract_serde_round_trip() {
        let c = LaneContract::new();
        let json = serde_json::to_string(&c).unwrap();
        let back: LaneContract = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn vectorization_decision_display_eligible() {
        let decision = VectorizationDecision {
            family: BuiltinFamily::ArrayMap,
            chosen_width: LaneWidth::Lane8,
            oracle_results: Vec::new(),
            selection: SelectionVector::new(8),
            eligible: true,
            rejection_reason: None,
            content_hash: ContentHash::compute(b"test"),
        };
        let s = decision.to_string();
        assert!(s.contains("eligible"));
        assert!(s.contains("array_map"));
    }

    #[test]
    fn vectorization_decision_display_rejected() {
        let decision = VectorizationDecision {
            family: BuiltinFamily::ArrayFilter,
            chosen_width: LaneWidth::Scalar,
            oracle_results: Vec::new(),
            selection: SelectionVector::new(0),
            eligible: false,
            rejection_reason: Some("test reason".to_string()),
            content_hash: ContentHash::compute(b"test"),
        };
        let s = decision.to_string();
        assert!(s.contains("rejected"));
        assert!(s.contains("test reason"));
    }

    #[test]
    fn evaluate_empty_oracles_for_family_with_requirements() {
        let contract = LaneContract::new();
        let epoch = SecurityEpoch::from_raw(5);
        let decision = contract.evaluate(BuiltinFamily::ArrayMap, &[], 100, epoch);
        assert!(!decision.eligible);
        assert!(
            decision
                .rejection_reason
                .as_ref()
                .unwrap()
                .contains("missing")
        );
    }
}
