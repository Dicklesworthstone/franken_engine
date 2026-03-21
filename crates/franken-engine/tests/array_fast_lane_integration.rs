//! Integration tests for the array fast-lane module.
//!
//! Covers end-to-end workflows: element-kind transitions, deopt chains,
//! typed-array lifecycle, policy enforcement, diagnostics, and serialization.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::array_fast_lane::{
    ARRAY_FAST_LANE_SCHEMA_VERSION, ArrayFastLaneDiagnostics, ArrayFastLaneEngine,
    ArrayLaneDescriptor, DeoptReason, ElementKind, ElementKindTransition, FastLanePolicy,
    TransitionReason, TransitionReceipt, TypedArrayDescriptor,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ---------------------------------------------------------------------------
// Element-kind lattice
// ---------------------------------------------------------------------------

#[test]
fn test_element_kind_widening_lattice() {
    let engine = ArrayFastLaneEngine::new(epoch(1));
    // Packed SMI can widen to double, elements
    assert!(engine.is_valid_transition(ElementKind::PackedSmi, ElementKind::PackedDouble));
    assert!(engine.is_valid_transition(ElementKind::PackedSmi, ElementKind::PackedElements));
    assert!(engine.is_valid_transition(ElementKind::PackedSmi, ElementKind::HoleySmi));

    // Double can widen to elements, holey double
    assert!(engine.is_valid_transition(ElementKind::PackedDouble, ElementKind::PackedElements));
    assert!(engine.is_valid_transition(ElementKind::PackedDouble, ElementKind::HoleyDouble));

    // Holey paths
    assert!(engine.is_valid_transition(ElementKind::HoleySmi, ElementKind::HoleyDouble));
    assert!(engine.is_valid_transition(ElementKind::HoleySmi, ElementKind::HoleyElements));
    assert!(engine.is_valid_transition(ElementKind::HoleyDouble, ElementKind::HoleyElements));
}

#[test]
fn test_narrowing_transitions_forbidden() {
    let engine = ArrayFastLaneEngine::new(epoch(1));
    assert!(!engine.is_valid_transition(ElementKind::PackedDouble, ElementKind::PackedSmi));
    assert!(!engine.is_valid_transition(ElementKind::PackedElements, ElementKind::PackedDouble));
    assert!(!engine.is_valid_transition(ElementKind::HoleyElements, ElementKind::HoleySmi));
    assert!(!engine.is_valid_transition(ElementKind::HoleyDouble, ElementKind::PackedDouble));
}

#[test]
fn test_empty_to_any_packed_is_valid() {
    let engine = ArrayFastLaneEngine::new(epoch(1));
    assert!(engine.is_valid_transition(ElementKind::Empty, ElementKind::PackedSmi));
    assert!(engine.is_valid_transition(ElementKind::Empty, ElementKind::PackedDouble));
    assert!(engine.is_valid_transition(ElementKind::Empty, ElementKind::PackedElements));
}

#[test]
fn test_freeze_and_seal_transitions() {
    let engine = ArrayFastLaneEngine::new(epoch(1));
    assert!(engine.is_valid_transition(ElementKind::PackedElements, ElementKind::Frozen));
    assert!(engine.is_valid_transition(ElementKind::PackedElements, ElementKind::Sealed));
    assert!(engine.is_valid_transition(ElementKind::HoleyElements, ElementKind::Frozen));
    assert!(engine.is_valid_transition(ElementKind::HoleyElements, ElementKind::Sealed));
    // Can't freeze SMI directly
    assert!(!engine.is_valid_transition(ElementKind::PackedSmi, ElementKind::Frozen));
}

// ---------------------------------------------------------------------------
// Element kind properties
// ---------------------------------------------------------------------------

#[test]
fn test_element_kind_properties_comprehensive() {
    // Packed kinds
    assert!(ElementKind::PackedSmi.is_packed());
    assert!(ElementKind::PackedSmi.is_unboxed());
    assert!(!ElementKind::PackedSmi.is_holey());
    assert!(!ElementKind::PackedSmi.is_typed_array());
    assert!(!ElementKind::PackedSmi.is_immutable());

    // Holey kinds
    assert!(ElementKind::HoleyDouble.is_holey());
    assert!(ElementKind::HoleyDouble.is_unboxed());
    assert!(!ElementKind::HoleyDouble.is_packed());

    // Typed kinds
    assert!(ElementKind::TypedFloat64.is_typed_array());
    assert!(ElementKind::TypedFloat64.is_unboxed());
    assert!(!ElementKind::TypedFloat64.is_holey());

    // Immutable kinds
    assert!(ElementKind::Frozen.is_immutable());
    assert!(ElementKind::Sealed.is_immutable());
    assert!(!ElementKind::Frozen.is_unboxed());
}

#[test]
fn test_typed_byte_widths() {
    assert_eq!(ElementKind::TypedInt8.typed_byte_width(), Some(1));
    assert_eq!(ElementKind::TypedUint8.typed_byte_width(), Some(1));
    assert_eq!(ElementKind::TypedUint8Clamped.typed_byte_width(), Some(1));
    assert_eq!(ElementKind::TypedInt16.typed_byte_width(), Some(2));
    assert_eq!(ElementKind::TypedUint16.typed_byte_width(), Some(2));
    assert_eq!(ElementKind::TypedInt32.typed_byte_width(), Some(4));
    assert_eq!(ElementKind::TypedUint32.typed_byte_width(), Some(4));
    assert_eq!(ElementKind::TypedFloat32.typed_byte_width(), Some(4));
    assert_eq!(ElementKind::TypedFloat64.typed_byte_width(), Some(8));
    assert_eq!(ElementKind::TypedBigInt64.typed_byte_width(), Some(8));
    assert_eq!(ElementKind::TypedBigUint64.typed_byte_width(), Some(8));
    assert_eq!(ElementKind::PackedSmi.typed_byte_width(), None);
    assert_eq!(ElementKind::Empty.typed_byte_width(), None);
}

#[test]
fn test_element_kind_rank_monotonic() {
    let kinds = [
        ElementKind::Empty,
        ElementKind::PackedSmi,
        ElementKind::PackedDouble,
        ElementKind::PackedElements,
        ElementKind::HoleySmi,
        ElementKind::HoleyDouble,
        ElementKind::HoleyElements,
        ElementKind::Frozen,
        ElementKind::Sealed,
    ];
    for i in 0..kinds.len() - 1 {
        assert!(
            kinds[i].rank() <= kinds[i + 1].rank(),
            "{:?} rank {} should be <= {:?} rank {}",
            kinds[i],
            kinds[i].rank(),
            kinds[i + 1],
            kinds[i + 1].rank()
        );
    }
}

// ---------------------------------------------------------------------------
// Array lane descriptor lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_array_lane_full_lifecycle() {
    let mut lane = ArrayLaneDescriptor::new("arr-lifecycle", ElementKind::Empty, 0);
    assert!(lane.fast_lane_active);
    assert_eq!(lane.transition_count(), 0);

    // Transition Empty → PackedSmi
    lane.transition(
        ElementKind::PackedSmi,
        TransitionReason::InitialAllocation,
        epoch(1),
        0,
    );
    assert_eq!(lane.element_kind, ElementKind::PackedSmi);
    assert_eq!(lane.transition_count(), 1);

    // Transition PackedSmi → PackedDouble
    lane.transition(
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        epoch(1),
        4,
    );
    assert_eq!(lane.element_kind, ElementKind::PackedDouble);
    assert_eq!(lane.transition_count(), 2);

    // Deopt
    lane.deopt(DeoptReason::ElementKindChanged, epoch(1), 8);
    assert!(!lane.fast_lane_active);
    assert_eq!(lane.deopt_count(), 1);

    // Re-opt
    lane.reopt();
    assert!(lane.fast_lane_active);
}

#[test]
fn test_array_lane_access_tracking_accumulation() {
    let mut lane = ArrayLaneDescriptor::new("arr-track", ElementKind::PackedSmi, 100);
    for _ in 0..500 {
        lane.record_access();
    }
    for _ in 0..200 {
        lane.record_store();
    }
    for _ in 0..50 {
        lane.record_oob();
    }
    assert_eq!(lane.access_count, 500);
    assert_eq!(lane.store_count, 200);
    assert_eq!(lane.oob_count, 50);
    assert_eq!(lane.oob_rate_millionths(), 100_000); // 50/500 = 10%
}

#[test]
fn test_array_lane_content_hash_differs_by_kind() {
    let l1 = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
    let l2 = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedDouble, 10);
    assert_ne!(l1.content_hash(), l2.content_hash());
}

#[test]
fn test_array_lane_content_hash_differs_by_length() {
    let l1 = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
    let l2 = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 20);
    assert_ne!(l1.content_hash(), l2.content_hash());
}

#[test]
fn test_array_lane_content_hash_differs_by_id() {
    let l1 = ArrayLaneDescriptor::new("arr-1", ElementKind::PackedSmi, 10);
    let l2 = ArrayLaneDescriptor::new("arr-2", ElementKind::PackedSmi, 10);
    assert_ne!(l1.content_hash(), l2.content_hash());
}

// ---------------------------------------------------------------------------
// Transition receipts
// ---------------------------------------------------------------------------

#[test]
fn test_transition_receipt_deterministic_hash() {
    let t = ElementKindTransition::new(
        ElementKind::PackedSmi,
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        epoch(1),
        0,
    );
    let r1 = TransitionReceipt::new("arr-1", t.clone(), true);
    let r2 = TransitionReceipt::new("arr-1", t, true);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
    assert_eq!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn test_transition_receipt_differs_by_array() {
    let t = ElementKindTransition::new(
        ElementKind::PackedSmi,
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        epoch(1),
        0,
    );
    let r1 = TransitionReceipt::new("arr-1", t.clone(), true);
    let r2 = TransitionReceipt::new("arr-2", t, true);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_transition_receipt_id_format() {
    let t = ElementKindTransition::new(
        ElementKind::Empty,
        ElementKind::PackedSmi,
        TransitionReason::InitialAllocation,
        epoch(1),
        0,
    );
    let r = TransitionReceipt::new("arr-test", t, true);
    assert!(
        r.receipt_id.starts_with("tr-"),
        "receipt_id should start with 'tr-'"
    );
    assert!(r.receipt_id.len() > 3, "receipt_id should have hash suffix");
}

// ---------------------------------------------------------------------------
// Engine registration
// ---------------------------------------------------------------------------

#[test]
fn test_engine_register_multiple_arrays() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    for i in 0..20 {
        let id = format!("arr-{}", i);
        assert!(engine.register_array(&id, ElementKind::PackedSmi, 10));
    }
    assert_eq!(engine.total_array_count(), 20);
    assert_eq!(engine.active_array_count(), 20);
}

#[test]
fn test_engine_reject_duplicate_registration() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    assert!(engine.register_array("arr-1", ElementKind::PackedSmi, 10));
    assert!(!engine.register_array("arr-1", ElementKind::PackedDouble, 20));
    assert_eq!(engine.total_array_count(), 1);
    // First registration wins
    let lane = engine.get_array("arr-1").unwrap();
    assert_eq!(lane.element_kind, ElementKind::PackedSmi);
}

#[test]
fn test_engine_policy_length_limit() {
    let mut policy = FastLanePolicy::default();
    policy.max_fast_lane_length = 50;
    let mut engine = ArrayFastLaneEngine::with_policy(policy, epoch(1));
    assert!(engine.register_array("arr-ok", ElementKind::PackedSmi, 50));
    assert!(!engine.register_array("arr-too-long", ElementKind::PackedSmi, 51));
}

#[test]
fn test_engine_typed_array_registration() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    assert!(engine.register_typed_array("ta-int8", ElementKind::TypedInt8, 100));
    assert!(engine.register_typed_array("ta-f64", ElementKind::TypedFloat64, 50));
    assert!(engine.register_typed_array("ta-u32", ElementKind::TypedUint32, 200));
    assert_eq!(engine.typed_array_count(), 3);
}

#[test]
fn test_engine_typed_array_reject_non_typed_kind() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    assert!(!engine.register_typed_array("ta-bad", ElementKind::PackedSmi, 100));
    assert!(!engine.register_typed_array("ta-bad2", ElementKind::HoleyElements, 100));
    assert!(!engine.register_typed_array("ta-bad3", ElementKind::Frozen, 100));
    assert_eq!(engine.typed_array_count(), 0);
}

#[test]
fn test_engine_typed_array_reject_duplicate() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    assert!(engine.register_typed_array("ta-1", ElementKind::TypedInt32, 100));
    assert!(!engine.register_typed_array("ta-1", ElementKind::TypedFloat64, 50));
    assert_eq!(engine.typed_array_count(), 1);
}

// ---------------------------------------------------------------------------
// Engine transition pipeline
// ---------------------------------------------------------------------------

#[test]
fn test_engine_transition_chain() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-1", ElementKind::Empty, 0);

    // Empty → PackedSmi
    let r1 = engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedSmi,
        TransitionReason::InitialAllocation,
        0,
    );
    assert!(r1.is_some());

    // PackedSmi → PackedDouble
    let r2 = engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        4,
    );
    assert!(r2.is_some());

    // PackedDouble → PackedElements
    let r3 = engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedElements,
        TransitionReason::DoubleToElements,
        8,
    );
    assert!(r3.is_some());

    let lane = engine.get_array("arr-1").unwrap();
    assert_eq!(lane.element_kind, ElementKind::PackedElements);
    assert_eq!(lane.transition_count(), 3);
    assert!(lane.fast_lane_active);
    assert_eq!(engine.receipt_count(), 3);
}

#[test]
fn test_engine_invalid_transition_triggers_deopt() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-1", ElementKind::PackedDouble, 10);

    // Narrowing PackedDouble → PackedSmi is invalid
    let receipt = engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedSmi,
        TransitionReason::DeoptReboxing,
        0,
    );
    assert!(receipt.is_none());

    let lane = engine.get_array("arr-1").unwrap();
    assert!(!lane.fast_lane_active);
    assert_eq!(lane.deopt_count(), 1);
    assert_eq!(engine.total_deopt_count(), 1);
}

#[test]
fn test_engine_max_transitions_enforced() {
    let mut policy = FastLanePolicy::default();
    policy.max_transitions = 3;
    let mut engine = ArrayFastLaneEngine::with_policy(policy, epoch(1));
    engine.register_array("arr-1", ElementKind::Empty, 0);

    // Three valid transitions
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
    engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedElements,
        TransitionReason::DoubleToElements,
        8,
    );

    // Fourth should cause deopt
    let receipt = engine.transition_element_kind(
        "arr-1",
        ElementKind::HoleyElements,
        TransitionReason::ElementDeleted,
        12,
    );
    assert!(receipt.is_none());
    assert!(!engine.get_array("arr-1").unwrap().fast_lane_active);
}

#[test]
fn test_engine_transition_nonexistent_array() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    let result = engine.transition_element_kind(
        "nonexistent",
        ElementKind::PackedSmi,
        TransitionReason::InitialAllocation,
        0,
    );
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// OOB tracking and auto-deopt
// ---------------------------------------------------------------------------

#[test]
fn test_oob_auto_deopt_at_threshold() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.policy.max_oob_rate_millionths = 50_000; // 5%
    engine.policy.min_access_count = 20;
    engine.register_array("arr-1", ElementKind::PackedSmi, 10);

    // 20 accesses, 0 OOB → ok
    for _ in 0..20 {
        engine.record_access("arr-1");
    }
    assert!(engine.get_array("arr-1").unwrap().fast_lane_active);

    // 2 OOBs → 2/22 ≈ 9% > 5% → deopt
    engine.record_oob("arr-1", 0);
    engine.record_oob("arr-1", 4);
    assert!(!engine.get_array("arr-1").unwrap().fast_lane_active);
}

#[test]
fn test_oob_no_deopt_below_min_access() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.policy.max_oob_rate_millionths = 50_000;
    engine.policy.min_access_count = 100;
    engine.register_array("arr-1", ElementKind::PackedSmi, 5);

    // Only 5 accesses, below min_access_count of 100
    for _ in 0..5 {
        engine.record_access("arr-1");
    }
    // Even 100% OOB rate won't trigger deopt below min_access_count
    for _ in 0..5 {
        engine.record_oob("arr-1", 0);
    }
    assert!(engine.get_array("arr-1").unwrap().fast_lane_active);
}

#[test]
fn test_oob_rate_calculation_precision() {
    let mut lane = ArrayLaneDescriptor::new("arr-oob", ElementKind::PackedSmi, 10);
    for _ in 0..1_000 {
        lane.record_access();
    }
    for _ in 0..1 {
        lane.record_oob();
    }
    // 1/1000 = 0.1% = 1000 millionths
    assert_eq!(lane.oob_rate_millionths(), 1000);
}

// ---------------------------------------------------------------------------
// Typed array operations
// ---------------------------------------------------------------------------

#[test]
fn test_typed_array_byte_layout() {
    let ta = TypedArrayDescriptor::new("ta-f32", ElementKind::TypedFloat32, 256);
    assert_eq!(ta.byte_length, 1024); // 256 * 4
    assert_eq!(ta.byte_width(), 4);
    assert_eq!(ta.element_count, 256);
    assert_eq!(ta.byte_offset, 0);
}

#[test]
fn test_typed_array_detach_lifecycle() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_typed_array("ta-1", ElementKind::TypedInt32, 100);

    // Access before detach
    assert!(engine.record_typed_access("ta-1"));
    assert!(engine.record_bounds_elim("ta-1"));

    // Detach
    assert!(engine.detach_typed_array("ta-1"));
    let ta = engine.get_typed_array("ta-1").unwrap();
    assert!(ta.buffer_detached);
    assert!(!ta.fast_lane_active);
}

#[test]
fn test_typed_array_bounds_elim_tracking() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_typed_array("ta-1", ElementKind::TypedFloat64, 100);

    for _ in 0..100 {
        engine.record_typed_access("ta-1");
    }
    for _ in 0..90 {
        engine.record_bounds_elim("ta-1");
    }

    let ta = engine.get_typed_array("ta-1").unwrap();
    assert_eq!(ta.bounds_elim_rate_millionths(), 900_000); // 90%
}

#[test]
fn test_typed_array_all_kinds() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    let typed_kinds = [
        ("ta-i8", ElementKind::TypedInt8, 1),
        ("ta-u8", ElementKind::TypedUint8, 1),
        ("ta-u8c", ElementKind::TypedUint8Clamped, 1),
        ("ta-i16", ElementKind::TypedInt16, 2),
        ("ta-u16", ElementKind::TypedUint16, 2),
        ("ta-i32", ElementKind::TypedInt32, 4),
        ("ta-u32", ElementKind::TypedUint32, 4),
        ("ta-f32", ElementKind::TypedFloat32, 4),
        ("ta-f64", ElementKind::TypedFloat64, 8),
        ("ta-bi64", ElementKind::TypedBigInt64, 8),
        ("ta-bu64", ElementKind::TypedBigUint64, 8),
    ];
    for (id, kind, expected_width) in typed_kinds {
        assert!(engine.register_typed_array(id, kind, 100));
        let ta = engine.get_typed_array(id).unwrap();
        assert_eq!(ta.byte_width(), expected_width);
        assert_eq!(ta.byte_length, 100 * expected_width as u64);
    }
    assert_eq!(engine.typed_array_count(), 11);
}

// ---------------------------------------------------------------------------
// Engine diagnostics
// ---------------------------------------------------------------------------

#[test]
fn test_diagnostics_aggregation() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-1", ElementKind::PackedSmi, 10);
    engine.register_array("arr-2", ElementKind::PackedDouble, 20);
    engine.register_typed_array("ta-1", ElementKind::TypedInt32, 50);

    // Record some activity
    for _ in 0..10 {
        engine.record_access("arr-1");
        engine.record_store("arr-1");
    }
    for _ in 0..5 {
        engine.record_access("arr-2");
    }

    // Transition arr-1
    engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        0,
    );

    let diag = engine.diagnostics();
    assert_eq!(diag.total_arrays, 2);
    assert_eq!(diag.active_arrays, 2);
    assert_eq!(diag.deopted_arrays, 0);
    assert_eq!(diag.typed_arrays, 1);
    assert_eq!(diag.total_transitions, 1);
    assert_eq!(diag.total_accesses, 15); // 10 + 5
    assert_eq!(diag.total_stores, 10);
    assert_eq!(diag.total_oob, 0);
}

#[test]
fn test_diagnostics_with_deopts() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-1", ElementKind::PackedDouble, 10);
    engine.register_array("arr-2", ElementKind::PackedDouble, 20);

    // Force deopt on arr-1
    engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedSmi, // narrowing → deopt
        TransitionReason::DeoptReboxing,
        0,
    );

    let diag = engine.diagnostics();
    assert_eq!(diag.total_arrays, 2);
    assert_eq!(diag.active_arrays, 1);
    assert_eq!(diag.deopted_arrays, 1);
    assert_eq!(diag.total_deopts, 1);
}

#[test]
fn test_diagnostics_policy_hash_stable() {
    let engine = ArrayFastLaneEngine::new(epoch(1));
    let d1 = engine.diagnostics();
    let d2 = engine.diagnostics();
    assert_eq!(d1.policy_hash, d2.policy_hash);
    assert!(!d1.policy_hash.is_empty());
}

// ---------------------------------------------------------------------------
// Arrays by kind grouping
// ---------------------------------------------------------------------------

#[test]
fn test_arrays_by_kind_grouping() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-s1", ElementKind::PackedSmi, 10);
    engine.register_array("arr-s2", ElementKind::PackedSmi, 20);
    engine.register_array("arr-d1", ElementKind::PackedDouble, 30);
    engine.register_array("arr-e1", ElementKind::PackedElements, 40);

    let by_kind = engine.arrays_by_kind();
    assert_eq!(by_kind.get(&ElementKind::PackedSmi).unwrap().len(), 2);
    assert_eq!(by_kind.get(&ElementKind::PackedDouble).unwrap().len(), 1);
    assert_eq!(by_kind.get(&ElementKind::PackedElements).unwrap().len(), 1);
    assert!(!by_kind.contains_key(&ElementKind::HoleySmi));
}

#[test]
fn test_arrays_by_kind_reflects_transitions() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-1", ElementKind::PackedSmi, 10);
    engine.register_array("arr-2", ElementKind::PackedSmi, 20);

    // Transition arr-1 from PackedSmi to PackedDouble
    engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        0,
    );

    let by_kind = engine.arrays_by_kind();
    assert_eq!(by_kind.get(&ElementKind::PackedSmi).unwrap().len(), 1);
    assert_eq!(by_kind.get(&ElementKind::PackedDouble).unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Deopt records audit trail
// ---------------------------------------------------------------------------

#[test]
fn test_deopt_record_audit_trail() {
    let mut lane = ArrayLaneDescriptor::new("arr-audit", ElementKind::PackedSmi, 10);
    for _ in 0..100 {
        lane.record_access();
    }
    lane.deopt(
        DeoptReason::ExcessiveOob {
            oob_rate_millionths: 200_000,
        },
        epoch(5),
        42,
    );
    let record = &lane.deopt_records[0];
    assert_eq!(record.record_id, "deopt-arr-audit-0");
    assert_eq!(record.epoch, epoch(5));
    assert_eq!(record.trigger_offset, 42);
    assert_eq!(record.access_count_at_deopt, 100);
    assert_eq!(record.element_kind_at_deopt, ElementKind::PackedSmi);
}

#[test]
fn test_engine_deopt_log_accumulated() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-1", ElementKind::PackedDouble, 10);
    engine.register_array("arr-2", ElementKind::PackedElements, 20);

    // Deopt arr-1 via invalid transition
    engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedSmi,
        TransitionReason::DeoptReboxing,
        0,
    );
    // Deopt arr-2 via invalid transition
    engine.transition_element_kind(
        "arr-2",
        ElementKind::PackedSmi,
        TransitionReason::DeoptReboxing,
        4,
    );

    assert_eq!(engine.total_deopt_count(), 2);
    assert_eq!(engine.deopt_log.len(), 2);
}

// ---------------------------------------------------------------------------
// Policy customization
// ---------------------------------------------------------------------------

#[test]
fn test_custom_policy() {
    let mut policy = FastLanePolicy::default();
    policy.max_oob_rate_millionths = 200_000;
    policy.max_transitions = 10;
    policy.max_fast_lane_length = 500;
    policy.allow_reopt = false;
    policy.emit_transition_receipts = false;

    let mut engine = ArrayFastLaneEngine::with_policy(policy, epoch(1));
    engine.register_array("arr-1", ElementKind::Empty, 0);

    // Transition should succeed but no receipt emitted
    let receipt = engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedSmi,
        TransitionReason::InitialAllocation,
        0,
    );
    assert!(receipt.is_none()); // emit_transition_receipts = false
    assert_eq!(engine.receipt_count(), 0);
    // But lane should have transitioned
    assert_eq!(
        engine.get_array("arr-1").unwrap().element_kind,
        ElementKind::PackedSmi
    );
}

#[test]
fn test_policy_hash_changes_with_config() {
    let p1 = FastLanePolicy::default();
    let mut p2 = FastLanePolicy::default();
    p2.max_oob_rate_millionths = 999_999;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

// ---------------------------------------------------------------------------
// Serialization round-trips
// ---------------------------------------------------------------------------

#[test]
fn test_engine_serde_round_trip() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-1", ElementKind::PackedSmi, 10);
    engine.register_typed_array("ta-1", ElementKind::TypedFloat64, 50);
    engine.record_access("arr-1");
    engine.record_store("arr-1");
    engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        0,
    );

    let json = serde_json::to_string(&engine).unwrap();
    let decoded: ArrayFastLaneEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.total_array_count(), 1);
    assert_eq!(decoded.typed_array_count(), 1);
    assert_eq!(decoded.receipt_count(), 1);
    let lane = decoded.get_array("arr-1").unwrap();
    assert_eq!(lane.element_kind, ElementKind::PackedDouble);
    assert_eq!(lane.access_count, 1);
}

#[test]
fn test_diagnostics_serde_round_trip() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-1", ElementKind::PackedSmi, 10);
    let diag = engine.diagnostics();
    let json = serde_json::to_string(&diag).unwrap();
    let decoded: ArrayFastLaneDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, decoded);
}

#[test]
fn test_deopt_reason_variants_serde() {
    let variants = vec![
        DeoptReason::ElementKindChanged,
        DeoptReason::ExcessiveOob {
            oob_rate_millionths: 150_000,
        },
        DeoptReason::ShapeMismatch {
            expected: 1,
            observed: 2,
        },
        DeoptReason::ArrayBecameSparse {
            hole_ratio_millionths: 500_000,
        },
        DeoptReason::OperatorRequested {
            reason: "test".to_string(),
        },
        DeoptReason::BufferDetached,
        DeoptReason::LengthOverflow {
            length: 100,
            capacity: 50,
        },
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).unwrap();
        let decoded: DeoptReason = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, decoded);
    }
}

#[test]
fn test_transition_reason_serde() {
    let reasons = vec![
        TransitionReason::InitialAllocation,
        TransitionReason::SmiToDouble,
        TransitionReason::DoubleToElements,
        TransitionReason::ElementDeleted,
        TransitionReason::ObjectFreeze,
        TransitionReason::ObjectSeal,
        TransitionReason::DeoptReboxing,
    ];
    for reason in reasons {
        let json = serde_json::to_string(&reason).unwrap();
        let decoded: TransitionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, decoded);
    }
}

#[test]
fn test_element_kind_all_variants_serde() {
    let kinds = vec![
        ElementKind::Empty,
        ElementKind::PackedSmi,
        ElementKind::PackedDouble,
        ElementKind::PackedElements,
        ElementKind::HoleySmi,
        ElementKind::HoleyDouble,
        ElementKind::HoleyElements,
        ElementKind::Frozen,
        ElementKind::Sealed,
        ElementKind::TypedInt8,
        ElementKind::TypedUint8,
        ElementKind::TypedUint8Clamped,
        ElementKind::TypedInt16,
        ElementKind::TypedUint16,
        ElementKind::TypedInt32,
        ElementKind::TypedUint32,
        ElementKind::TypedFloat32,
        ElementKind::TypedFloat64,
        ElementKind::TypedBigInt64,
        ElementKind::TypedBigUint64,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: ElementKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, decoded);
    }
}

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_format() {
    assert!(ARRAY_FAST_LANE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ARRAY_FAST_LANE_SCHEMA_VERSION.contains("array-fast-lane"));
    assert!(ARRAY_FAST_LANE_SCHEMA_VERSION.ends_with(".v1"));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_zero_length_array() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    assert!(engine.register_array("arr-empty", ElementKind::Empty, 0));
    let lane = engine.get_array("arr-empty").unwrap();
    assert_eq!(lane.length, 0);
    assert_eq!(lane.capacity, 0);
    assert!(lane.fast_lane_active);
}

#[test]
fn test_same_kind_transition_is_noop() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-1", ElementKind::PackedSmi, 10);
    // Same kind → same kind: old_kind == new_kind path
    let _receipt = engine.transition_element_kind(
        "arr-1",
        ElementKind::PackedSmi,
        TransitionReason::InitialAllocation,
        0,
    );
    // Should succeed (no deopt) since old == new
    let lane = engine.get_array("arr-1").unwrap();
    assert!(lane.fast_lane_active);
}

#[test]
fn test_access_nonexistent_array() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    assert!(!engine.record_access("ghost"));
    assert!(!engine.record_store("ghost"));
    assert!(!engine.record_oob("ghost", 0));
}

#[test]
fn test_access_nonexistent_typed_array() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    assert!(!engine.record_typed_access("ghost"));
    assert!(!engine.record_bounds_elim("ghost"));
    assert!(!engine.detach_typed_array("ghost"));
}

#[test]
fn test_large_scale_registration() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    for i in 0..200 {
        let id = format!("arr-{}", i);
        engine.register_array(&id, ElementKind::PackedSmi, 10);
    }
    assert_eq!(engine.total_array_count(), 200);
    assert_eq!(engine.active_array_count(), 200);

    let diag = engine.diagnostics();
    assert_eq!(diag.total_arrays, 200);
    assert_eq!(diag.active_arrays, 200);
}

#[test]
fn test_multiple_deopts_same_array() {
    let mut lane = ArrayLaneDescriptor::new("arr-multi", ElementKind::PackedSmi, 10);
    lane.deopt(DeoptReason::ElementKindChanged, epoch(1), 0);
    lane.reopt();
    lane.deopt(DeoptReason::BufferDetached, epoch(2), 4);
    lane.reopt();
    lane.deopt(
        DeoptReason::ShapeMismatch {
            expected: 1,
            observed: 2,
        },
        epoch(3),
        8,
    );
    assert_eq!(lane.deopt_count(), 3);
    assert!(!lane.fast_lane_active);
}

#[test]
fn test_typed_array_zero_access_bounds_rate() {
    let ta = TypedArrayDescriptor::new("ta-zero", ElementKind::TypedInt32, 10);
    assert_eq!(ta.bounds_elim_rate_millionths(), 0);
}

#[test]
fn test_transition_widening_flag() {
    let t1 = ElementKindTransition::new(
        ElementKind::PackedSmi,
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        epoch(1),
        0,
    );
    assert!(t1.is_widening);

    let t2 = ElementKindTransition::new(
        ElementKind::HoleyElements,
        ElementKind::Frozen,
        TransitionReason::ObjectFreeze,
        epoch(1),
        0,
    );
    assert!(t2.is_widening); // Frozen rank > HoleyElements rank
}

// ---------------------------------------------------------------------------
// Mixed workload scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_mixed_array_and_typed_array_workload() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));

    // Register arrays
    engine.register_array("arr-smi", ElementKind::PackedSmi, 100);
    engine.register_array("arr-dbl", ElementKind::PackedDouble, 200);

    // Register typed arrays
    engine.register_typed_array("ta-i32", ElementKind::TypedInt32, 500);
    engine.register_typed_array("ta-f64", ElementKind::TypedFloat64, 300);

    // Mixed activity
    for _ in 0..50 {
        engine.record_access("arr-smi");
        engine.record_store("arr-dbl");
        engine.record_typed_access("ta-i32");
        engine.record_bounds_elim("ta-i32");
    }

    // Transition arr-smi
    engine.transition_element_kind(
        "arr-smi",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        0,
    );

    // Detach ta-f64
    engine.detach_typed_array("ta-f64");

    let diag = engine.diagnostics();
    assert_eq!(diag.total_arrays, 2);
    assert_eq!(diag.active_arrays, 2);
    assert_eq!(diag.typed_arrays, 2);
    assert_eq!(diag.total_transitions, 1);
    assert_eq!(diag.total_accesses, 50);
    assert_eq!(diag.total_stores, 50);
    assert_eq!(diag.total_receipts, 1);
}

#[test]
fn test_deopt_and_transition_interleaving() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-1", ElementKind::PackedSmi, 10);
    engine.register_array("arr-2", ElementKind::Empty, 0);

    // Valid transition on arr-2
    engine.transition_element_kind(
        "arr-2",
        ElementKind::PackedSmi,
        TransitionReason::InitialAllocation,
        0,
    );

    // Invalid transition on arr-1 → deopt
    engine.transition_element_kind(
        "arr-1",
        ElementKind::Empty, // narrowing
        TransitionReason::DeoptReboxing,
        0,
    );

    assert!(engine.get_array("arr-2").unwrap().fast_lane_active);
    assert!(!engine.get_array("arr-1").unwrap().fast_lane_active);
    assert_eq!(engine.active_array_count(), 1);
}

// ---------------------------------------------------------------------------
// Double-deopt guard tests
// ---------------------------------------------------------------------------

#[test]
fn test_double_deopt_on_lane_descriptor_is_idempotent() {
    let mut lane = ArrayLaneDescriptor::new("arr-dd-1", ElementKind::PackedSmi, 0);
    assert!(lane.fast_lane_active);

    lane.deopt(DeoptReason::ElementKindChanged, epoch(1), 0);
    assert!(!lane.fast_lane_active);
    assert_eq!(lane.deopt_count(), 1);

    // Second deopt on already-deoptimized lane should be a no-op
    lane.deopt(DeoptReason::ElementKindChanged, epoch(1), 4);
    assert!(!lane.fast_lane_active);
    assert_eq!(
        lane.deopt_count(),
        1,
        "second deopt should not add a record"
    );
}

#[test]
fn test_double_deopt_with_different_reasons_still_idempotent() {
    let mut lane = ArrayLaneDescriptor::new("arr-dd-2", ElementKind::PackedDouble, 0);

    lane.deopt(DeoptReason::ElementKindChanged, epoch(1), 0);
    assert_eq!(lane.deopt_count(), 1);

    lane.deopt(
        DeoptReason::ExcessiveOob {
            oob_rate_millionths: 500_000,
        },
        epoch(2),
        8,
    );
    assert_eq!(
        lane.deopt_count(),
        1,
        "different-reason deopt on inactive lane should still be no-op"
    );
}

#[test]
fn test_deopt_reopt_deopt_creates_two_records() {
    let mut lane = ArrayLaneDescriptor::new("arr-dd-3", ElementKind::PackedSmi, 0);

    lane.deopt(DeoptReason::ElementKindChanged, epoch(1), 0);
    assert_eq!(lane.deopt_count(), 1);
    assert!(!lane.fast_lane_active);

    lane.reopt();
    assert!(lane.fast_lane_active);

    lane.deopt(
        DeoptReason::ExcessiveOob {
            oob_rate_millionths: 800_000,
        },
        epoch(2),
        16,
    );
    assert_eq!(
        lane.deopt_count(),
        2,
        "deopt after reopt should create a second record"
    );
    assert!(!lane.fast_lane_active);
}

#[test]
fn test_engine_invalid_transition_on_already_deopted_lane_does_not_duplicate_record() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-dd-eng", ElementKind::PackedSmi, 100);

    // First invalid transition → deopt
    engine.transition_element_kind(
        "arr-dd-eng",
        ElementKind::Empty,
        TransitionReason::DeoptReboxing,
        0,
    );
    let lane = engine.get_array("arr-dd-eng").unwrap();
    assert!(!lane.fast_lane_active);
    assert_eq!(lane.deopt_count(), 1);
    let initial_log_len = engine.deopt_log.len();

    // Second invalid transition on already-deopted lane → no additional deopt
    engine.transition_element_kind(
        "arr-dd-eng",
        ElementKind::Empty,
        TransitionReason::DeoptReboxing,
        4,
    );
    let lane = engine.get_array("arr-dd-eng").unwrap();
    assert_eq!(lane.deopt_count(), 1);
    assert_eq!(
        engine.deopt_log.len(),
        initial_log_len,
        "engine deopt log should not grow on double deopt"
    );
}

#[test]
fn test_engine_max_transitions_on_already_deopted_lane_does_not_duplicate() {
    let mut policy = FastLanePolicy::default();
    policy.max_transitions = 1;
    let mut engine = ArrayFastLaneEngine::with_policy(policy, epoch(1));
    engine.register_array("arr-dd-max", ElementKind::Empty, 50);

    // One valid transition
    engine.transition_element_kind(
        "arr-dd-max",
        ElementKind::PackedSmi,
        TransitionReason::InitialAllocation,
        0,
    );

    // Second transition exceeds max → deopt
    engine.transition_element_kind(
        "arr-dd-max",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        4,
    );
    let lane = engine.get_array("arr-dd-max").unwrap();
    assert!(!lane.fast_lane_active);
    assert_eq!(lane.deopt_count(), 1);
    let log_len = engine.deopt_log.len();

    // Third transition on already-deopted lane → no additional deopt
    engine.transition_element_kind(
        "arr-dd-max",
        ElementKind::PackedElements,
        TransitionReason::ElementStoreMismatch,
        8,
    );
    let lane = engine.get_array("arr-dd-max").unwrap();
    assert_eq!(lane.deopt_count(), 1);
    assert_eq!(engine.deopt_log.len(), log_len);
}

#[test]
fn test_engine_oob_on_already_deopted_lane_does_not_duplicate() {
    let mut policy = FastLanePolicy::default();
    policy.max_oob_rate_millionths = 100_000; // 10%
    policy.min_access_count = 2;
    let mut engine = ArrayFastLaneEngine::with_policy(policy, epoch(1));
    engine.register_array("arr-dd-oob", ElementKind::PackedSmi, 100);

    // Force a deopt via invalid transition first
    engine.transition_element_kind(
        "arr-dd-oob",
        ElementKind::Empty,
        TransitionReason::DeoptReboxing,
        0,
    );
    let lane = engine.get_array("arr-dd-oob").unwrap();
    assert!(!lane.fast_lane_active);
    assert_eq!(lane.deopt_count(), 1);
    let log_len = engine.deopt_log.len();

    // Now generate OOB events that would normally trigger deopt
    for i in 0..10 {
        engine.record_oob("arr-dd-oob", i);
    }
    let lane = engine.get_array("arr-dd-oob").unwrap();
    assert_eq!(
        lane.deopt_count(),
        1,
        "OOB on already-deopted lane should not add deopt records"
    );
    assert_eq!(engine.deopt_log.len(), log_len);
}

#[test]
fn test_triple_deopt_attempt_stays_at_one_record() {
    let mut lane = ArrayLaneDescriptor::new("arr-dd-triple", ElementKind::HoleyElements, 0);

    lane.deopt(DeoptReason::ElementKindChanged, epoch(1), 0);
    lane.deopt(DeoptReason::ElementKindChanged, epoch(2), 4);
    lane.deopt(
        DeoptReason::ExcessiveOob {
            oob_rate_millionths: 999_999,
        },
        epoch(3),
        8,
    );

    assert!(!lane.fast_lane_active);
    assert_eq!(
        lane.deopt_count(),
        1,
        "only the first deopt should be recorded"
    );
}

#[test]
fn test_deopt_record_id_stability_across_reopt_cycles() {
    let mut lane = ArrayLaneDescriptor::new("arr-dd-ids", ElementKind::PackedSmi, 0);

    lane.deopt(DeoptReason::ElementKindChanged, epoch(1), 0);
    let first_record = lane.deopt_records.last().unwrap().clone();
    assert_eq!(first_record.record_id, "deopt-arr-dd-ids-0");

    lane.reopt();
    lane.deopt(DeoptReason::ElementKindChanged, epoch(2), 4);
    let second_record = lane.deopt_records.last().unwrap().clone();
    assert_eq!(second_record.record_id, "deopt-arr-dd-ids-1");
    assert_ne!(first_record.record_id, second_record.record_id);
}

#[test]
fn test_engine_diagnostics_after_double_deopt_attempts() {
    let mut engine = ArrayFastLaneEngine::new(epoch(1));
    engine.register_array("arr-diag", ElementKind::PackedSmi, 100);

    // Deopt via invalid transition
    engine.transition_element_kind(
        "arr-diag",
        ElementKind::Empty,
        TransitionReason::DeoptReboxing,
        0,
    );

    // Attempt second deopt via another invalid transition
    engine.transition_element_kind(
        "arr-diag",
        ElementKind::Empty,
        TransitionReason::DeoptReboxing,
        4,
    );

    let diag = engine.diagnostics();
    assert_eq!(diag.total_arrays, 1);
    assert_eq!(diag.active_arrays, 0);
    assert_eq!(
        diag.total_deopts, 1,
        "diagnostics should reflect exactly one deopt"
    );
}
