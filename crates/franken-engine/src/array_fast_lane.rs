//! Array and typed-array fast lanes with element-kind transitions.
//!
//! Provides explicit element-kind tracking, boxed/unboxed movement,
//! fast-path dispatch for collection-heavy workloads, and deopt evidence
//! for deterministic rollback.
//!
//! Builds on:
//! - [`shape_transition_algebra`]: shape descriptors and property layouts
//! - [`polymorphic_inline_cache`]: IC site profiling and bailout decisions
//! - [`object_model`]: JsValue, ObjectHandle, PropertyDescriptor

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for array-fast-lane artifacts.
pub const ARRAY_FAST_LANE_SCHEMA_VERSION: &str = "franken-engine.array-fast-lane.v1";

// ---------------------------------------------------------------------------
// Element kinds
// ---------------------------------------------------------------------------

/// Element kind describes the internal storage representation of array elements.
/// Transitions are monotonically widening: once an array widens, it never narrows
/// without explicit user action (which produces a deopt record).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ElementKind {
    /// No elements allocated (empty array, length 0).
    Empty,
    /// All elements are SMI (small integer) values.
    PackedSmi,
    /// All elements are double-precision floats (includes SMI promotion).
    PackedDouble,
    /// Elements are boxed JS values (most general packed form).
    PackedElements,
    /// SMI array with holes (undefined gaps).
    HoleySmi,
    /// Double array with holes.
    HoleyDouble,
    /// Boxed elements with holes.
    HoleyElements,
    /// Frozen array (no further mutations allowed).
    Frozen,
    /// Sealed array (no deletions, length fixed, values mutable).
    Sealed,
    /// Typed array: Int8.
    TypedInt8,
    /// Typed array: Uint8.
    TypedUint8,
    /// Typed array: Uint8Clamped.
    TypedUint8Clamped,
    /// Typed array: Int16.
    TypedInt16,
    /// Typed array: Uint16.
    TypedUint16,
    /// Typed array: Int32.
    TypedInt32,
    /// Typed array: Uint32.
    TypedUint32,
    /// Typed array: Float32.
    TypedFloat32,
    /// Typed array: Float64.
    TypedFloat64,
    /// Typed array: BigInt64.
    TypedBigInt64,
    /// Typed array: BigUint64.
    TypedBigUint64,
}

impl ElementKind {
    /// Whether this kind stores unboxed (raw) values.
    pub fn is_unboxed(&self) -> bool {
        matches!(
            self,
            Self::PackedSmi
                | Self::PackedDouble
                | Self::HoleySmi
                | Self::HoleyDouble
                | Self::TypedInt8
                | Self::TypedUint8
                | Self::TypedUint8Clamped
                | Self::TypedInt16
                | Self::TypedUint16
                | Self::TypedInt32
                | Self::TypedUint32
                | Self::TypedFloat32
                | Self::TypedFloat64
                | Self::TypedBigInt64
                | Self::TypedBigUint64
        )
    }

    /// Whether this kind is a typed array.
    pub fn is_typed_array(&self) -> bool {
        matches!(
            self,
            Self::TypedInt8
                | Self::TypedUint8
                | Self::TypedUint8Clamped
                | Self::TypedInt16
                | Self::TypedUint16
                | Self::TypedInt32
                | Self::TypedUint32
                | Self::TypedFloat32
                | Self::TypedFloat64
                | Self::TypedBigInt64
                | Self::TypedBigUint64
        )
    }

    /// Whether this kind has holes.
    pub fn is_holey(&self) -> bool {
        matches!(
            self,
            Self::HoleySmi | Self::HoleyDouble | Self::HoleyElements
        )
    }

    /// Whether this kind is packed (no holes).
    pub fn is_packed(&self) -> bool {
        matches!(
            self,
            Self::PackedSmi | Self::PackedDouble | Self::PackedElements
        )
    }

    /// Whether this kind is fully immutable (frozen only; sealed arrays
    /// have fixed length but values remain mutable).
    pub fn is_immutable(&self) -> bool {
        matches!(self, Self::Frozen)
    }

    /// Byte width per element for typed arrays, None for regular arrays.
    pub fn typed_byte_width(&self) -> Option<u32> {
        match self {
            Self::TypedInt8 | Self::TypedUint8 | Self::TypedUint8Clamped => Some(1),
            Self::TypedInt16 | Self::TypedUint16 => Some(2),
            Self::TypedInt32 | Self::TypedUint32 | Self::TypedFloat32 => Some(4),
            Self::TypedFloat64 | Self::TypedBigInt64 | Self::TypedBigUint64 => Some(8),
            _ => None,
        }
    }

    /// Generality rank (higher = more general). Used for transition direction.
    pub fn rank(&self) -> u32 {
        match self {
            Self::Empty => 0,
            Self::PackedSmi => 1,
            Self::PackedDouble => 2,
            Self::PackedElements => 3,
            Self::HoleySmi => 4,
            Self::HoleyDouble => 5,
            Self::HoleyElements => 6,
            Self::Frozen | Self::Sealed => 7,
            Self::TypedInt8
            | Self::TypedUint8
            | Self::TypedUint8Clamped
            | Self::TypedInt16
            | Self::TypedUint16
            | Self::TypedInt32
            | Self::TypedUint32
            | Self::TypedFloat32
            | Self::TypedFloat64
            | Self::TypedBigInt64
            | Self::TypedBigUint64 => 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Element-kind transitions
// ---------------------------------------------------------------------------

/// Reason for an element-kind transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionReason {
    /// A non-SMI value was stored into a PackedSmi array.
    SmiToDouble,
    /// A non-numeric value was stored into a double array.
    DoubleToElements,
    /// An element was deleted, creating a hole.
    ElementDeleted,
    /// Array length was set below current element count.
    LengthContraction,
    /// Object.freeze() called.
    ObjectFreeze,
    /// Object.seal() called.
    ObjectSeal,
    /// Initial allocation with known element kind.
    InitialAllocation,
    /// Explicit typed-array construction.
    TypedArrayConstruction,
    /// Deopt forced reboxing from unboxed to boxed.
    DeoptReboxing,
}

/// Record of a single element-kind transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementKindTransition {
    /// Source element kind.
    pub from: ElementKind,
    /// Target element kind.
    pub to: ElementKind,
    /// Reason for transition.
    pub reason: TransitionReason,
    /// Epoch when transition occurred.
    pub epoch: SecurityEpoch,
    /// Instruction offset that triggered the transition.
    pub trigger_offset: u32,
    /// Whether this was a widening (generalization) transition.
    pub is_widening: bool,
}

impl ElementKindTransition {
    /// Create a new transition.
    pub fn new(
        from: ElementKind,
        to: ElementKind,
        reason: TransitionReason,
        epoch: SecurityEpoch,
        trigger_offset: u32,
    ) -> Self {
        let is_widening = to.rank() > from.rank();
        Self {
            from,
            to,
            reason,
            epoch,
            trigger_offset,
            is_widening,
        }
    }
}

// ---------------------------------------------------------------------------
// Array lane descriptor
// ---------------------------------------------------------------------------

/// Descriptor for an array's current fast-lane state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArrayLaneDescriptor {
    /// Unique array identity (content-addressed from allocation site).
    pub array_id: String,
    /// Current element kind.
    pub element_kind: ElementKind,
    /// Current length.
    pub length: u64,
    /// Capacity (allocated slots, may exceed length).
    pub capacity: u64,
    /// Whether the fast lane is active (not deopted).
    pub fast_lane_active: bool,
    /// Shape ID for this array's hidden class.
    pub shape_id: u64,
    /// Transition history.
    pub transitions: Vec<ElementKindTransition>,
    /// Deopt records.
    pub deopt_records: Vec<DeoptRecord>,
    /// Total element access count.
    pub access_count: u64,
    /// Total element store count.
    pub store_count: u64,
    /// Out-of-bounds access count.
    pub oob_count: u64,
}

impl ArrayLaneDescriptor {
    /// Create a new array lane descriptor.
    pub fn new(array_id: &str, element_kind: ElementKind, length: u64) -> Self {
        Self {
            array_id: array_id.to_string(),
            element_kind,
            length,
            capacity: length,
            fast_lane_active: true,
            shape_id: 0,
            transitions: Vec::new(),
            deopt_records: Vec::new(),
            access_count: 0,
            store_count: 0,
            oob_count: 0,
        }
    }

    /// Transition to a new element kind.
    pub fn transition(
        &mut self,
        new_kind: ElementKind,
        reason: TransitionReason,
        epoch: SecurityEpoch,
        trigger_offset: u32,
    ) -> ElementKindTransition {
        let transition =
            ElementKindTransition::new(self.element_kind, new_kind, reason, epoch, trigger_offset);
        self.transitions.push(transition.clone());
        self.element_kind = new_kind;
        transition
    }

    /// Record an element access.
    pub fn record_access(&mut self) {
        self.access_count += 1;
    }

    /// Record an element store.
    pub fn record_store(&mut self) {
        self.store_count += 1;
    }

    /// Record an out-of-bounds access. This is also counted as an access
    /// so that the OOB rate denominator is correct (an OOB-only array
    /// would otherwise never trigger the OOB deopt threshold).
    pub fn record_oob(&mut self) {
        self.access_count += 1;
        self.oob_count += 1;
    }

    /// Deoptimize this array lane.
    pub fn deopt(&mut self, reason: DeoptReason, epoch: SecurityEpoch, offset: u32) {
        if !self.fast_lane_active {
            return;
        }
        self.fast_lane_active = false;
        self.deopt_records.push(DeoptRecord {
            record_id: format!("deopt-{}-{}", self.array_id, self.deopt_records.len()),
            reason,
            element_kind_at_deopt: self.element_kind,
            epoch,
            trigger_offset: offset,
            access_count_at_deopt: self.access_count,
            store_count_at_deopt: self.store_count,
        });
    }

    /// Re-enable fast lane after deopt recovery.
    pub fn reopt(&mut self) {
        self.fast_lane_active = true;
    }

    /// Transition count.
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Deopt count.
    pub fn deopt_count(&self) -> usize {
        self.deopt_records.len()
    }

    /// OOB rate in millionths.
    pub fn oob_rate_millionths(&self) -> u64 {
        if self.access_count == 0 {
            return 0;
        }
        self.oob_count
            .saturating_mul(1_000_000)
            .checked_div(self.access_count)
            .unwrap_or(0)
    }

    /// Content hash for deterministic identity.
    pub fn content_hash(&self) -> ContentHash {
        let mut data = Vec::new();
        data.extend_from_slice(self.array_id.as_bytes());
        data.push(b'|');
        data.extend_from_slice(&(self.element_kind.rank()).to_le_bytes());
        data.extend_from_slice(&self.length.to_le_bytes());
        data.extend_from_slice(&self.shape_id.to_le_bytes());
        ContentHash::compute(&data)
    }
}

// ---------------------------------------------------------------------------
// Deopt records
// ---------------------------------------------------------------------------

/// Reason for deoptimizing an array fast lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeoptReason {
    /// Element kind transition made fast path invalid.
    ElementKindChanged,
    /// Too many out-of-bounds accesses.
    ExcessiveOob { oob_rate_millionths: u64 },
    /// Shape mismatch (prototype chain changed).
    ShapeMismatch { expected: u64, observed: u64 },
    /// Array became sparse (too many holes).
    ArrayBecameSparse { hole_ratio_millionths: u64 },
    /// Operator requested deopt.
    OperatorRequested { reason: String },
    /// Typed array buffer detached.
    BufferDetached,
    /// Length exceeded fast-lane capacity.
    LengthOverflow { length: u64, capacity: u64 },
}

/// Record of a deoptimization event for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeoptRecord {
    /// Unique record identifier.
    pub record_id: String,
    /// Reason for deopt.
    pub reason: DeoptReason,
    /// Element kind at time of deopt.
    pub element_kind_at_deopt: ElementKind,
    /// Epoch when deopt occurred.
    pub epoch: SecurityEpoch,
    /// Instruction offset that triggered deopt.
    pub trigger_offset: u32,
    /// Access count at time of deopt.
    pub access_count_at_deopt: u64,
    /// Store count at time of deopt.
    pub store_count_at_deopt: u64,
}

// ---------------------------------------------------------------------------
// Typed array descriptor
// ---------------------------------------------------------------------------

/// Descriptor for a typed array's fast-lane state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedArrayDescriptor {
    /// Unique typed array identity.
    pub typed_array_id: String,
    /// Element kind (must be a TypedXxx variant).
    pub element_kind: ElementKind,
    /// Byte length of the underlying buffer.
    pub byte_length: u64,
    /// Byte offset into the underlying buffer.
    pub byte_offset: u64,
    /// Element count.
    pub element_count: u64,
    /// Whether the underlying buffer is detached.
    pub buffer_detached: bool,
    /// Whether fast-lane access is active.
    pub fast_lane_active: bool,
    /// Total element access count.
    pub access_count: u64,
    /// Total bounds-check elimination count.
    pub bounds_check_eliminated: u64,
}

impl TypedArrayDescriptor {
    /// Create a new typed array descriptor.
    pub fn new(typed_array_id: &str, element_kind: ElementKind, element_count: u64) -> Self {
        let byte_width = element_kind.typed_byte_width().unwrap_or(1) as u64;
        Self {
            typed_array_id: typed_array_id.to_string(),
            element_kind,
            byte_length: element_count.saturating_mul(byte_width),
            byte_offset: 0,
            element_count,
            buffer_detached: false,
            fast_lane_active: true,
            access_count: 0,
            bounds_check_eliminated: 0,
        }
    }

    /// Detach the underlying buffer.
    pub fn detach(&mut self) {
        self.buffer_detached = true;
        self.fast_lane_active = false;
    }

    /// Record an element access.
    pub fn record_access(&mut self) {
        self.access_count += 1;
    }

    /// Record a bounds-check elimination.
    pub fn record_bounds_elim(&mut self) {
        self.bounds_check_eliminated += 1;
    }

    /// Bounds-check elimination rate in millionths.
    pub fn bounds_elim_rate_millionths(&self) -> u64 {
        if self.access_count == 0 {
            return 0;
        }
        self.bounds_check_eliminated
            .saturating_mul(1_000_000)
            .checked_div(self.access_count)
            .unwrap_or(0)
    }

    /// Per-element byte width.
    pub fn byte_width(&self) -> u32 {
        self.element_kind.typed_byte_width().unwrap_or(1)
    }
}

// ---------------------------------------------------------------------------
// Fast-lane policy
// ---------------------------------------------------------------------------

/// Policy governing array fast-lane behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLanePolicy {
    /// Maximum OOB rate (millionths) before deopt.
    pub max_oob_rate_millionths: u64,
    /// Maximum hole ratio (millionths) before sparse deopt.
    pub max_hole_ratio_millionths: u64,
    /// Minimum access count before evaluating deopt thresholds.
    pub min_access_count: u64,
    /// Maximum element-kind transitions before deopt.
    pub max_transitions: usize,
    /// Whether to allow reopt after deopt.
    pub allow_reopt: bool,
    /// Maximum length for fast-lane arrays.
    pub max_fast_lane_length: u64,
    /// Whether to emit transition receipts.
    pub emit_transition_receipts: bool,
}

impl Default for FastLanePolicy {
    fn default() -> Self {
        Self {
            max_oob_rate_millionths: 100_000,   // 10%
            max_hole_ratio_millionths: 500_000, // 50%
            min_access_count: 100,
            max_transitions: 5,
            allow_reopt: true,
            max_fast_lane_length: 1_000_000,
            emit_transition_receipts: true,
        }
    }
}

impl FastLanePolicy {
    /// Policy hash for deterministic comparison.
    pub fn policy_hash(&self) -> String {
        let data = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.max_oob_rate_millionths,
            self.max_hole_ratio_millionths,
            self.min_access_count,
            self.max_transitions,
            self.allow_reopt,
            self.max_fast_lane_length,
            self.emit_transition_receipts,
        );
        let hash = ContentHash::compute(data.as_bytes());
        hash.to_hex()[..16].to_string()
    }
}

// ---------------------------------------------------------------------------
// Transition receipt
// ---------------------------------------------------------------------------

/// Receipt documenting an element-kind transition for replay/audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Array identity.
    pub array_id: String,
    /// The transition that occurred.
    pub transition: ElementKindTransition,
    /// Content hash of the receipt.
    pub receipt_hash: ContentHash,
    /// Whether the fast lane remained active after transition.
    pub fast_lane_survived: bool,
}

impl TransitionReceipt {
    /// Create a new transition receipt.
    pub fn new(array_id: &str, transition: ElementKindTransition, survived: bool) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(array_id.as_bytes());
        data.push(b'|');
        data.extend_from_slice(&(transition.from.rank()).to_le_bytes());
        data.extend_from_slice(&(transition.to.rank()).to_le_bytes());
        data.extend_from_slice(&transition.trigger_offset.to_le_bytes());
        let receipt_hash = ContentHash::compute(&data);
        let receipt_id = format!("tr-{}", &receipt_hash.to_hex()[..16]);
        Self {
            receipt_id,
            array_id: array_id.to_string(),
            transition,
            receipt_hash,
            fast_lane_survived: survived,
        }
    }
}

// ---------------------------------------------------------------------------
// Fast-lane engine
// ---------------------------------------------------------------------------

/// Engine managing array fast lanes and typed-array fast paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArrayFastLaneEngine {
    /// Policy.
    pub policy: FastLanePolicy,
    /// Active array lanes, keyed by array_id.
    pub array_lanes: BTreeMap<String, ArrayLaneDescriptor>,
    /// Active typed-array descriptors, keyed by typed_array_id.
    pub typed_arrays: BTreeMap<String, TypedArrayDescriptor>,
    /// Transition receipts (audit trail).
    pub receipts: Vec<TransitionReceipt>,
    /// Current security epoch.
    pub epoch: SecurityEpoch,
    /// Deopt records (across all arrays).
    pub deopt_log: Vec<DeoptRecord>,
    /// Element-kind transition lattice (valid transitions).
    valid_transitions: BTreeSet<(ElementKind, ElementKind)>,
}

impl ArrayFastLaneEngine {
    /// Create a new engine with default policy.
    pub fn new(epoch: SecurityEpoch) -> Self {
        let mut engine = Self {
            policy: FastLanePolicy::default(),
            array_lanes: BTreeMap::new(),
            typed_arrays: BTreeMap::new(),
            receipts: Vec::new(),
            epoch,
            deopt_log: Vec::new(),
            valid_transitions: BTreeSet::new(),
        };
        engine.init_transition_lattice();
        engine
    }

    /// Create with custom policy.
    pub fn with_policy(policy: FastLanePolicy, epoch: SecurityEpoch) -> Self {
        let mut engine = Self {
            policy,
            array_lanes: BTreeMap::new(),
            typed_arrays: BTreeMap::new(),
            receipts: Vec::new(),
            epoch,
            deopt_log: Vec::new(),
            valid_transitions: BTreeSet::new(),
        };
        engine.init_transition_lattice();
        engine
    }

    fn init_transition_lattice(&mut self) {
        let widening_pairs = [
            (ElementKind::Empty, ElementKind::PackedSmi),
            (ElementKind::Empty, ElementKind::PackedDouble),
            (ElementKind::Empty, ElementKind::PackedElements),
            (ElementKind::PackedSmi, ElementKind::PackedDouble),
            (ElementKind::PackedSmi, ElementKind::PackedElements),
            (ElementKind::PackedDouble, ElementKind::PackedElements),
            (ElementKind::PackedSmi, ElementKind::HoleySmi),
            (ElementKind::PackedDouble, ElementKind::HoleyDouble),
            (ElementKind::PackedElements, ElementKind::HoleyElements),
            (ElementKind::HoleySmi, ElementKind::HoleyDouble),
            (ElementKind::HoleySmi, ElementKind::HoleyElements),
            (ElementKind::HoleyDouble, ElementKind::HoleyElements),
            (ElementKind::PackedElements, ElementKind::Frozen),
            (ElementKind::PackedElements, ElementKind::Sealed),
            (ElementKind::HoleyElements, ElementKind::Frozen),
            (ElementKind::HoleyElements, ElementKind::Sealed),
        ];
        for (from, to) in widening_pairs {
            self.valid_transitions.insert((from, to));
        }
    }

    /// Whether a transition from one element kind to another is valid.
    pub fn is_valid_transition(&self, from: ElementKind, to: ElementKind) -> bool {
        self.valid_transitions.contains(&(from, to))
    }

    /// Register a new array in the fast-lane engine.
    pub fn register_array(
        &mut self,
        array_id: &str,
        element_kind: ElementKind,
        length: u64,
    ) -> bool {
        if self.array_lanes.contains_key(array_id) {
            return false;
        }
        if length > self.policy.max_fast_lane_length {
            return false;
        }
        let desc = ArrayLaneDescriptor::new(array_id, element_kind, length);
        self.array_lanes.insert(array_id.to_string(), desc);
        true
    }

    /// Register a new typed array.
    pub fn register_typed_array(
        &mut self,
        typed_array_id: &str,
        element_kind: ElementKind,
        element_count: u64,
    ) -> bool {
        if !element_kind.is_typed_array() {
            return false;
        }
        if self.typed_arrays.contains_key(typed_array_id) {
            return false;
        }
        let desc = TypedArrayDescriptor::new(typed_array_id, element_kind, element_count);
        self.typed_arrays.insert(typed_array_id.to_string(), desc);
        true
    }

    /// Transition an array's element kind.
    pub fn transition_element_kind(
        &mut self,
        array_id: &str,
        new_kind: ElementKind,
        reason: TransitionReason,
        trigger_offset: u32,
    ) -> Option<TransitionReceipt> {
        let lane = self.array_lanes.get_mut(array_id)?;
        let old_kind = lane.element_kind;

        // Check transition validity.
        if !self.valid_transitions.contains(&(old_kind, new_kind)) && old_kind != new_kind {
            if lane.fast_lane_active {
                lane.deopt(DeoptReason::ElementKindChanged, self.epoch, trigger_offset);
                let record = lane.deopt_records.last().cloned();
                if let Some(r) = record {
                    self.deopt_log.push(r);
                }
            }
            return None;
        }

        // Check max transitions.
        if lane.transition_count() >= self.policy.max_transitions {
            if lane.fast_lane_active {
                lane.deopt(DeoptReason::ElementKindChanged, self.epoch, trigger_offset);
                let record = lane.deopt_records.last().cloned();
                if let Some(r) = record {
                    self.deopt_log.push(r);
                }
            }
            return None;
        }

        let transition = lane.transition(new_kind, reason.clone(), self.epoch, trigger_offset);
        let survived = lane.fast_lane_active;

        if self.policy.emit_transition_receipts {
            let receipt = TransitionReceipt::new(array_id, transition, survived);
            let result = receipt.clone();
            self.receipts.push(receipt);
            Some(result)
        } else {
            None
        }
    }

    /// Record an element access on an array.
    pub fn record_access(&mut self, array_id: &str) -> bool {
        if let Some(lane) = self.array_lanes.get_mut(array_id) {
            lane.record_access();
            true
        } else {
            false
        }
    }

    /// Record an element store on an array.
    pub fn record_store(&mut self, array_id: &str) -> bool {
        if let Some(lane) = self.array_lanes.get_mut(array_id) {
            lane.record_store();
            true
        } else {
            false
        }
    }

    /// Record an out-of-bounds access and auto-deopt if threshold exceeded.
    pub fn record_oob(&mut self, array_id: &str, trigger_offset: u32) -> bool {
        let max_oob = self.policy.max_oob_rate_millionths;
        let min_access = self.policy.min_access_count;
        let epoch = self.epoch;
        if let Some(lane) = self.array_lanes.get_mut(array_id) {
            lane.record_oob();
            if lane.access_count >= min_access
                && lane.oob_rate_millionths() > max_oob
                && lane.fast_lane_active
            {
                lane.deopt(
                    DeoptReason::ExcessiveOob {
                        oob_rate_millionths: lane.oob_rate_millionths(),
                    },
                    epoch,
                    trigger_offset,
                );
                let record = lane.deopt_records.last().cloned();
                if let Some(r) = record {
                    self.deopt_log.push(r);
                }
            }
            true
        } else {
            false
        }
    }

    /// Record an element access on a typed array.
    pub fn record_typed_access(&mut self, typed_array_id: &str) -> bool {
        if let Some(desc) = self.typed_arrays.get_mut(typed_array_id) {
            desc.record_access();
            true
        } else {
            false
        }
    }

    /// Record bounds-check elimination on a typed array.
    pub fn record_bounds_elim(&mut self, typed_array_id: &str) -> bool {
        if let Some(desc) = self.typed_arrays.get_mut(typed_array_id) {
            desc.record_bounds_elim();
            true
        } else {
            false
        }
    }

    /// Detach a typed array's buffer.
    pub fn detach_typed_array(&mut self, typed_array_id: &str) -> bool {
        if let Some(desc) = self.typed_arrays.get_mut(typed_array_id) {
            desc.detach();
            true
        } else {
            false
        }
    }

    /// Get an array lane descriptor.
    pub fn get_array(&self, array_id: &str) -> Option<&ArrayLaneDescriptor> {
        self.array_lanes.get(array_id)
    }

    /// Get a typed array descriptor.
    pub fn get_typed_array(&self, typed_array_id: &str) -> Option<&TypedArrayDescriptor> {
        self.typed_arrays.get(typed_array_id)
    }

    /// Count of active fast-lane arrays.
    pub fn active_array_count(&self) -> usize {
        self.array_lanes
            .values()
            .filter(|l| l.fast_lane_active)
            .count()
    }

    /// Total array count (including deopted).
    pub fn total_array_count(&self) -> usize {
        self.array_lanes.len()
    }

    /// Typed array count.
    pub fn typed_array_count(&self) -> usize {
        self.typed_arrays.len()
    }

    /// Total deopt count across all arrays.
    pub fn total_deopt_count(&self) -> usize {
        self.deopt_log.len()
    }

    /// Total receipt count.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Arrays grouped by element kind.
    pub fn arrays_by_kind(&self) -> BTreeMap<ElementKind, Vec<String>> {
        let mut result: BTreeMap<ElementKind, Vec<String>> = BTreeMap::new();
        for (id, lane) in &self.array_lanes {
            result
                .entry(lane.element_kind)
                .or_default()
                .push(id.clone());
        }
        result
    }

    /// Diagnostics snapshot.
    pub fn diagnostics(&self) -> ArrayFastLaneDiagnostics {
        let total_arrays = self.array_lanes.len() as u32;
        let active_arrays = self.active_array_count() as u32;
        let deopted_arrays = total_arrays - active_arrays;
        let typed_arrays = self.typed_arrays.len() as u32;
        let total_transitions: u32 = self
            .array_lanes
            .values()
            .map(|l| l.transition_count() as u32)
            .sum();
        let total_deopts = self.deopt_log.len() as u32;
        let total_receipts = self.receipts.len() as u32;
        let total_accesses: u64 = self.array_lanes.values().map(|l| l.access_count).sum();
        let total_stores: u64 = self.array_lanes.values().map(|l| l.store_count).sum();
        let total_oob: u64 = self.array_lanes.values().map(|l| l.oob_count).sum();

        ArrayFastLaneDiagnostics {
            total_arrays,
            active_arrays,
            deopted_arrays,
            typed_arrays,
            total_transitions,
            total_deopts,
            total_receipts,
            total_accesses,
            total_stores,
            total_oob,
            policy_hash: self.policy.policy_hash(),
        }
    }
}

/// Diagnostics snapshot for the array fast-lane engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArrayFastLaneDiagnostics {
    pub total_arrays: u32,
    pub active_arrays: u32,
    pub deopted_arrays: u32,
    pub typed_arrays: u32,
    pub total_transitions: u32,
    pub total_deopts: u32,
    pub total_receipts: u32,
    pub total_accesses: u64,
    pub total_stores: u64,
    pub total_oob: u64,
    pub policy_hash: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    // --- ElementKind tests ---

    #[test]
    fn test_element_kind_is_unboxed() {
        assert!(ElementKind::PackedSmi.is_unboxed());
        assert!(ElementKind::PackedDouble.is_unboxed());
        assert!(ElementKind::TypedInt32.is_unboxed());
        assert!(!ElementKind::PackedElements.is_unboxed());
        assert!(!ElementKind::Empty.is_unboxed());
    }

    #[test]
    fn test_element_kind_is_typed_array() {
        assert!(ElementKind::TypedInt8.is_typed_array());
        assert!(ElementKind::TypedFloat64.is_typed_array());
        assert!(!ElementKind::PackedSmi.is_typed_array());
        assert!(!ElementKind::HoleyElements.is_typed_array());
    }

    #[test]
    fn test_element_kind_is_holey() {
        assert!(ElementKind::HoleySmi.is_holey());
        assert!(ElementKind::HoleyDouble.is_holey());
        assert!(ElementKind::HoleyElements.is_holey());
        assert!(!ElementKind::PackedSmi.is_holey());
    }

    #[test]
    fn test_element_kind_is_packed() {
        assert!(ElementKind::PackedSmi.is_packed());
        assert!(ElementKind::PackedDouble.is_packed());
        assert!(ElementKind::PackedElements.is_packed());
        assert!(!ElementKind::HoleySmi.is_packed());
    }

    #[test]
    fn test_element_kind_is_immutable() {
        assert!(ElementKind::Frozen.is_immutable());
        // Sealed has fixed length but values remain mutable (not immutable).
        assert!(!ElementKind::Sealed.is_immutable());
        assert!(!ElementKind::PackedSmi.is_immutable());
    }

    #[test]
    fn test_typed_byte_width() {
        assert_eq!(ElementKind::TypedInt8.typed_byte_width(), Some(1));
        assert_eq!(ElementKind::TypedInt16.typed_byte_width(), Some(2));
        assert_eq!(ElementKind::TypedInt32.typed_byte_width(), Some(4));
        assert_eq!(ElementKind::TypedFloat64.typed_byte_width(), Some(8));
        assert_eq!(ElementKind::PackedSmi.typed_byte_width(), None);
    }

    #[test]
    fn test_element_kind_rank_ordering() {
        assert!(ElementKind::Empty.rank() < ElementKind::PackedSmi.rank());
        assert!(ElementKind::PackedSmi.rank() < ElementKind::PackedDouble.rank());
        assert!(ElementKind::PackedDouble.rank() < ElementKind::PackedElements.rank());
        assert!(ElementKind::PackedElements.rank() < ElementKind::HoleySmi.rank());
    }

    // --- ElementKindTransition tests ---

    #[test]
    fn test_transition_widening() {
        let t = ElementKindTransition::new(
            ElementKind::PackedSmi,
            ElementKind::PackedDouble,
            TransitionReason::SmiToDouble,
            epoch(1),
            0,
        );
        assert!(t.is_widening);
    }

    #[test]
    fn test_transition_to_frozen_is_widening() {
        let t = ElementKindTransition::new(
            ElementKind::PackedElements,
            ElementKind::Frozen,
            TransitionReason::ObjectFreeze,
            epoch(1),
            0,
        );
        // Frozen rank > PackedElements rank (7 vs 3) → actually widening
        assert!(t.is_widening);
    }

    #[test]
    fn test_transition_non_widening() {
        let t = ElementKindTransition::new(
            ElementKind::HoleyElements,
            ElementKind::PackedElements,
            TransitionReason::LengthContraction,
            epoch(1),
            0,
        );
        // PackedElements rank < HoleyElements rank (3 vs 6) → non-widening
        assert!(!t.is_widening);
    }

    // --- ArrayLaneDescriptor tests ---

    #[test]
    fn test_array_lane_creation() {
        let lane = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
        assert_eq!(lane.array_id, "arr-1");
        assert_eq!(lane.element_kind, ElementKind::PackedSmi);
        assert_eq!(lane.length, 10);
        assert!(lane.fast_lane_active);
    }

    #[test]
    fn test_array_lane_transition() {
        let mut lane = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
        lane.transition(
            ElementKind::PackedDouble,
            TransitionReason::SmiToDouble,
            epoch(1),
            0,
        );
        assert_eq!(lane.element_kind, ElementKind::PackedDouble);
        assert_eq!(lane.transition_count(), 1);
    }

    #[test]
    fn test_array_lane_deopt() {
        let mut lane = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
        lane.deopt(DeoptReason::ElementKindChanged, epoch(1), 0);
        assert!(!lane.fast_lane_active);
        assert_eq!(lane.deopt_count(), 1);
    }

    #[test]
    fn test_array_lane_reopt() {
        let mut lane = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
        lane.deopt(DeoptReason::ElementKindChanged, epoch(1), 0);
        lane.reopt();
        assert!(lane.fast_lane_active);
    }

    #[test]
    fn test_array_lane_access_tracking() {
        let mut lane = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
        lane.record_access();
        lane.record_access();
        lane.record_store();
        assert_eq!(lane.access_count, 2);
        assert_eq!(lane.store_count, 1);
    }

    #[test]
    fn test_array_lane_oob_rate() {
        let mut lane = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
        for _ in 0..100 {
            lane.record_access();
        }
        for _ in 0..10 {
            lane.record_oob(); // also increments access_count
        }
        // 10 OOB out of 110 total accesses = 10/110 * 1_000_000 = 90_909
        assert_eq!(lane.oob_rate_millionths(), 90_909);
        assert_eq!(lane.access_count, 110);
        assert_eq!(lane.oob_count, 10);
    }

    #[test]
    fn test_array_lane_oob_rate_zero_access() {
        let lane = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 0);
        assert_eq!(lane.oob_rate_millionths(), 0);
    }

    #[test]
    fn test_array_lane_content_hash_deterministic() {
        let l1 = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
        let l2 = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
        assert_eq!(l1.content_hash(), l2.content_hash());
    }

    // --- TypedArrayDescriptor tests ---

    #[test]
    fn test_typed_array_creation() {
        let ta = TypedArrayDescriptor::new("ta-1", ElementKind::TypedInt32, 100);
        assert_eq!(ta.element_count, 100);
        assert_eq!(ta.byte_length, 400); // 100 * 4
        assert_eq!(ta.byte_width(), 4);
        assert!(ta.fast_lane_active);
        assert!(!ta.buffer_detached);
    }

    #[test]
    fn test_typed_array_detach() {
        let mut ta = TypedArrayDescriptor::new("ta-1", ElementKind::TypedFloat64, 50);
        ta.detach();
        assert!(ta.buffer_detached);
        assert!(!ta.fast_lane_active);
    }

    #[test]
    fn test_typed_array_bounds_elim_rate() {
        let mut ta = TypedArrayDescriptor::new("ta-1", ElementKind::TypedInt32, 100);
        for _ in 0..100 {
            ta.record_access();
        }
        for _ in 0..80 {
            ta.record_bounds_elim();
        }
        assert_eq!(ta.bounds_elim_rate_millionths(), 800_000); // 80%
    }

    // --- FastLanePolicy tests ---

    #[test]
    fn test_default_policy() {
        let policy = FastLanePolicy::default();
        assert_eq!(policy.max_oob_rate_millionths, 100_000);
        assert!(policy.allow_reopt);
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let p1 = FastLanePolicy::default();
        let p2 = FastLanePolicy::default();
        assert_eq!(p1.policy_hash(), p2.policy_hash());
    }

    // --- TransitionReceipt tests ---

    #[test]
    fn test_transition_receipt() {
        let transition = ElementKindTransition::new(
            ElementKind::PackedSmi,
            ElementKind::PackedDouble,
            TransitionReason::SmiToDouble,
            epoch(1),
            0,
        );
        let receipt = TransitionReceipt::new("arr-1", transition, true);
        assert!(receipt.receipt_id.starts_with("tr-"));
        assert!(receipt.fast_lane_survived);
    }

    // --- ArrayFastLaneEngine tests ---

    #[test]
    fn test_engine_creation() {
        let engine = ArrayFastLaneEngine::new(epoch(1));
        assert_eq!(engine.total_array_count(), 0);
        assert_eq!(engine.active_array_count(), 0);
        assert_eq!(engine.typed_array_count(), 0);
    }

    #[test]
    fn test_engine_register_array() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        assert!(engine.register_array("arr-1", ElementKind::PackedSmi, 10));
        assert_eq!(engine.total_array_count(), 1);
        assert_eq!(engine.active_array_count(), 1);
    }

    #[test]
    fn test_engine_register_duplicate_array() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        assert!(engine.register_array("arr-1", ElementKind::PackedSmi, 10));
        assert!(!engine.register_array("arr-1", ElementKind::PackedSmi, 10));
    }

    #[test]
    fn test_engine_register_oversized_array() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        engine.policy.max_fast_lane_length = 100;
        assert!(!engine.register_array("arr-1", ElementKind::PackedSmi, 200));
    }

    #[test]
    fn test_engine_register_typed_array() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        assert!(engine.register_typed_array("ta-1", ElementKind::TypedInt32, 100));
        assert_eq!(engine.typed_array_count(), 1);
    }

    #[test]
    fn test_engine_reject_non_typed_kind() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        assert!(!engine.register_typed_array("ta-1", ElementKind::PackedSmi, 100));
    }

    #[test]
    fn test_engine_valid_transition() {
        let engine = ArrayFastLaneEngine::new(epoch(1));
        assert!(engine.is_valid_transition(ElementKind::PackedSmi, ElementKind::PackedDouble));
        assert!(engine.is_valid_transition(ElementKind::PackedSmi, ElementKind::HoleySmi));
        assert!(!engine.is_valid_transition(ElementKind::PackedDouble, ElementKind::PackedSmi));
    }

    #[test]
    fn test_engine_element_kind_transition() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        engine.register_array("arr-1", ElementKind::PackedSmi, 10);
        let receipt = engine.transition_element_kind(
            "arr-1",
            ElementKind::PackedDouble,
            TransitionReason::SmiToDouble,
            0,
        );
        assert!(receipt.is_some());
        let lane = engine.get_array("arr-1").unwrap();
        assert_eq!(lane.element_kind, ElementKind::PackedDouble);
    }

    #[test]
    fn test_engine_invalid_transition_causes_deopt() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        engine.register_array("arr-1", ElementKind::PackedDouble, 10);
        let receipt = engine.transition_element_kind(
            "arr-1",
            ElementKind::PackedSmi, // narrowing = invalid
            TransitionReason::DeoptReboxing,
            0,
        );
        assert!(receipt.is_none());
        let lane = engine.get_array("arr-1").unwrap();
        assert!(!lane.fast_lane_active);
    }

    #[test]
    fn test_engine_max_transitions_deopt() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        engine.policy.max_transitions = 2;
        engine.register_array("arr-1", ElementKind::Empty, 0);

        engine.transition_element_kind(
            "arr-1",
            ElementKind::PackedSmi,
            TransitionReason::InitialAllocation,
            0,
        );
        engine.transition_element_kind(
            "arr-1",
            ElementKind::PackedDouble,
            TransitionReason::SmiToDouble,
            4,
        );
        // Third transition exceeds limit.
        let receipt = engine.transition_element_kind(
            "arr-1",
            ElementKind::PackedElements,
            TransitionReason::DoubleToElements,
            8,
        );
        assert!(receipt.is_none());
        assert!(!engine.get_array("arr-1").unwrap().fast_lane_active);
    }

    #[test]
    fn test_engine_record_access_and_store() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        engine.register_array("arr-1", ElementKind::PackedSmi, 10);
        assert!(engine.record_access("arr-1"));
        assert!(engine.record_store("arr-1"));
        let lane = engine.get_array("arr-1").unwrap();
        assert_eq!(lane.access_count, 1);
        assert_eq!(lane.store_count, 1);
    }

    #[test]
    fn test_engine_oob_auto_deopt() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        engine.policy.max_oob_rate_millionths = 100_000; // 10%
        engine.policy.min_access_count = 10;
        engine.register_array("arr-1", ElementKind::PackedSmi, 5);

        for _ in 0..10 {
            engine.record_access("arr-1");
        }
        // 2 OOB out of 10+2 accesses = ~16% > 10%
        engine.record_oob("arr-1", 0);
        engine.record_oob("arr-1", 0);

        let lane = engine.get_array("arr-1").unwrap();
        assert!(!lane.fast_lane_active);
    }

    #[test]
    fn test_engine_typed_array_access() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        engine.register_typed_array("ta-1", ElementKind::TypedFloat32, 50);
        assert!(engine.record_typed_access("ta-1"));
        assert!(engine.record_bounds_elim("ta-1"));
        let ta = engine.get_typed_array("ta-1").unwrap();
        assert_eq!(ta.access_count, 1);
        assert_eq!(ta.bounds_check_eliminated, 1);
    }

    #[test]
    fn test_engine_detach_typed_array() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        engine.register_typed_array("ta-1", ElementKind::TypedInt32, 100);
        assert!(engine.detach_typed_array("ta-1"));
        let ta = engine.get_typed_array("ta-1").unwrap();
        assert!(ta.buffer_detached);
        assert!(!ta.fast_lane_active);
    }

    #[test]
    fn test_engine_arrays_by_kind() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        engine.register_array("arr-1", ElementKind::PackedSmi, 10);
        engine.register_array("arr-2", ElementKind::PackedSmi, 20);
        engine.register_array("arr-3", ElementKind::PackedDouble, 30);
        let by_kind = engine.arrays_by_kind();
        assert_eq!(by_kind.get(&ElementKind::PackedSmi).unwrap().len(), 2);
        assert_eq!(by_kind.get(&ElementKind::PackedDouble).unwrap().len(), 1);
    }

    #[test]
    fn test_engine_diagnostics() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        engine.register_array("arr-1", ElementKind::PackedSmi, 10);
        engine.register_typed_array("ta-1", ElementKind::TypedInt32, 50);
        let diag = engine.diagnostics();
        assert_eq!(diag.total_arrays, 1);
        assert_eq!(diag.active_arrays, 1);
        assert_eq!(diag.typed_arrays, 1);
    }

    #[test]
    fn test_engine_nonexistent_access() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        assert!(!engine.record_access("nonexistent"));
        assert!(!engine.record_store("nonexistent"));
        assert!(!engine.record_oob("nonexistent", 0));
    }

    #[test]
    fn test_engine_nonexistent_typed_access() {
        let mut engine = ArrayFastLaneEngine::new(epoch(1));
        assert!(!engine.record_typed_access("nonexistent"));
        assert!(!engine.record_bounds_elim("nonexistent"));
        assert!(!engine.detach_typed_array("nonexistent"));
    }

    // --- Serialization tests ---

    #[test]
    fn test_element_kind_serde() {
        let kinds = vec![
            ElementKind::Empty,
            ElementKind::PackedSmi,
            ElementKind::PackedDouble,
            ElementKind::PackedElements,
            ElementKind::HoleyElements,
            ElementKind::TypedInt32,
            ElementKind::Frozen,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let decoded: ElementKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, decoded);
        }
    }

    #[test]
    fn test_array_lane_serde() {
        let lane = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
        let json = serde_json::to_string(&lane).unwrap();
        let decoded: ArrayLaneDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, decoded);
    }

    #[test]
    fn test_typed_array_serde() {
        let ta = TypedArrayDescriptor::new("ta-1", ElementKind::TypedFloat64, 100);
        let json = serde_json::to_string(&ta).unwrap();
        let decoded: TypedArrayDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(ta, decoded);
    }

    #[test]
    fn test_deopt_reason_serde() {
        let reasons = vec![
            DeoptReason::ElementKindChanged,
            DeoptReason::ExcessiveOob {
                oob_rate_millionths: 150_000,
            },
            DeoptReason::ShapeMismatch {
                expected: 1,
                observed: 2,
            },
            DeoptReason::BufferDetached,
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let decoded: DeoptReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, decoded);
        }
    }

    #[test]
    fn test_diagnostics_serde() {
        let engine = ArrayFastLaneEngine::new(epoch(1));
        let diag = engine.diagnostics();
        let json = serde_json::to_string(&diag).unwrap();
        let decoded: ArrayFastLaneDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(diag, decoded);
    }

    #[test]
    fn test_policy_serde() {
        let policy = FastLanePolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: FastLanePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, decoded);
    }

    #[test]
    fn test_schema_version() {
        assert_eq!(
            ARRAY_FAST_LANE_SCHEMA_VERSION,
            "franken-engine.array-fast-lane.v1"
        );
    }
}
