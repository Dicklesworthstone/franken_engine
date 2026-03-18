//! Enrichment integration tests for `array_fast_lane`.
//!
//! Covers gaps: ElementKind transition lattice completeness, monotonic widening
//! invariant, typed-array byte-width correctness, deopt threshold enforcement,
//! OOB rate computation, ArrayFastLaneEngine state machine, receipt generation,
//! policy hash determinism, serde roundtrips, Display uniqueness, and
//! diagnostics snapshot correctness.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::array_fast_lane::{
    ARRAY_FAST_LANE_SCHEMA_VERSION, ArrayFastLaneDiagnostics, ArrayFastLaneEngine, DeoptReason,
    ElementKind, FastLanePolicy, TransitionReason,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn default_engine() -> ArrayFastLaneEngine {
    ArrayFastLaneEngine::new(epoch())
}

fn _engine_with_policy(policy: FastLanePolicy) -> ArrayFastLaneEngine {
    ArrayFastLaneEngine::with_policy(policy, epoch())
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_has_prefix() {
    assert!(ARRAY_FAST_LANE_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_schema_version_nonempty() {
    assert!(!ARRAY_FAST_LANE_SCHEMA_VERSION.is_empty());
}

// ===========================================================================
// ElementKind classification
// ===========================================================================

#[test]
fn enrichment_element_kind_empty_is_not_unboxed() {
    assert!(!ElementKind::Empty.is_unboxed());
}

#[test]
fn enrichment_packed_smi_is_unboxed() {
    assert!(ElementKind::PackedSmi.is_unboxed());
}

#[test]
fn enrichment_packed_double_is_unboxed() {
    assert!(ElementKind::PackedDouble.is_unboxed());
}

#[test]
fn enrichment_packed_elements_not_unboxed() {
    assert!(!ElementKind::PackedElements.is_unboxed());
}

#[test]
fn enrichment_holey_smi_is_unboxed() {
    assert!(ElementKind::HoleySmi.is_unboxed());
}

#[test]
fn enrichment_holey_double_is_unboxed() {
    assert!(ElementKind::HoleyDouble.is_unboxed());
}

#[test]
fn enrichment_holey_elements_not_unboxed() {
    assert!(!ElementKind::HoleyElements.is_unboxed());
}

#[test]
fn enrichment_frozen_not_unboxed() {
    assert!(!ElementKind::Frozen.is_unboxed());
}

#[test]
fn enrichment_sealed_not_unboxed() {
    assert!(!ElementKind::Sealed.is_unboxed());
}

#[test]
fn enrichment_all_typed_arrays_are_unboxed() {
    let typed = [
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
    for kind in &typed {
        assert!(kind.is_unboxed(), "{kind:?} should be unboxed");
    }
}

#[test]
fn enrichment_all_typed_arrays_are_typed() {
    let typed = [
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
    for kind in &typed {
        assert!(kind.is_typed_array(), "{kind:?} should be typed array");
    }
}

#[test]
fn enrichment_non_typed_are_not_typed_array() {
    let non_typed = [
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
    for kind in &non_typed {
        assert!(!kind.is_typed_array(), "{kind:?} should not be typed array");
    }
}

#[test]
fn enrichment_holey_variants_are_holey() {
    assert!(ElementKind::HoleySmi.is_holey());
    assert!(ElementKind::HoleyDouble.is_holey());
    assert!(ElementKind::HoleyElements.is_holey());
}

#[test]
fn enrichment_packed_variants_are_packed() {
    assert!(ElementKind::PackedSmi.is_packed());
    assert!(ElementKind::PackedDouble.is_packed());
    assert!(ElementKind::PackedElements.is_packed());
}

#[test]
fn enrichment_immutable_variants() {
    assert!(ElementKind::Frozen.is_immutable());
    assert!(ElementKind::Sealed.is_immutable());
    assert!(!ElementKind::PackedSmi.is_immutable());
    assert!(!ElementKind::HoleyElements.is_immutable());
}

// ===========================================================================
// ElementKind typed_byte_width
// ===========================================================================

#[test]
fn enrichment_typed_byte_widths_correct() {
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
}

#[test]
fn enrichment_non_typed_have_no_byte_width() {
    assert_eq!(ElementKind::Empty.typed_byte_width(), None);
    assert_eq!(ElementKind::PackedSmi.typed_byte_width(), None);
    assert_eq!(ElementKind::PackedDouble.typed_byte_width(), None);
    assert_eq!(ElementKind::HoleyElements.typed_byte_width(), None);
    assert_eq!(ElementKind::Frozen.typed_byte_width(), None);
}

// ===========================================================================
// ElementKind rank ordering
// ===========================================================================

#[test]
fn enrichment_element_kind_ranks_monotonic() {
    assert!(ElementKind::Empty.rank() < ElementKind::PackedSmi.rank());
    assert!(ElementKind::PackedSmi.rank() < ElementKind::PackedDouble.rank());
    assert!(ElementKind::PackedDouble.rank() < ElementKind::PackedElements.rank());
}

#[test]
fn enrichment_holey_ranks_higher_than_packed() {
    assert!(ElementKind::HoleySmi.rank() > ElementKind::PackedSmi.rank());
    assert!(ElementKind::HoleyDouble.rank() > ElementKind::PackedDouble.rank());
    assert!(ElementKind::HoleyElements.rank() > ElementKind::PackedElements.rank());
}

// ===========================================================================
// ElementKind Display uniqueness
// ===========================================================================

#[test]
fn enrichment_element_kind_display_all_unique() {
    let all = [
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
    let displays: BTreeSet<String> = all.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(
        displays.len(),
        all.len(),
        "All ElementKind variants must have unique Display"
    );
}

// ===========================================================================
// ElementKind serde roundtrip
// ===========================================================================

#[test]
fn enrichment_element_kind_serde_roundtrip() {
    let all = [
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
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: ElementKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ===========================================================================
// TransitionReason serde roundtrip
// ===========================================================================

#[test]
fn enrichment_transition_reason_serde_roundtrip() {
    let all = [
        TransitionReason::SmiToDouble,
        TransitionReason::DoubleToElements,
        TransitionReason::ElementDeleted,
        TransitionReason::LengthContraction,
        TransitionReason::ObjectFreeze,
        TransitionReason::ObjectSeal,
        TransitionReason::InitialAllocation,
        TransitionReason::TypedArrayConstruction,
        TransitionReason::DeoptReboxing,
    ];
    for reason in &all {
        let json = serde_json::to_string(reason).unwrap();
        let back: TransitionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

// ===========================================================================
// ArrayFastLaneEngine: registration
// ===========================================================================

#[test]
fn enrichment_register_array_succeeds() {
    let mut engine = default_engine();
    assert!(engine.register_array("arr1", ElementKind::PackedSmi, 10));
}

#[test]
fn enrichment_register_duplicate_array_fails() {
    let mut engine = default_engine();
    assert!(engine.register_array("arr1", ElementKind::PackedSmi, 10));
    assert!(!engine.register_array("arr1", ElementKind::PackedDouble, 5));
}

#[test]
fn enrichment_register_typed_array_succeeds() {
    let mut engine = default_engine();
    assert!(engine.register_typed_array("ta1", ElementKind::TypedInt32, 100));
}

#[test]
fn enrichment_register_typed_array_duplicate_fails() {
    let mut engine = default_engine();
    assert!(engine.register_typed_array("ta1", ElementKind::TypedInt32, 100));
    assert!(!engine.register_typed_array("ta1", ElementKind::TypedFloat64, 50));
}

#[test]
fn enrichment_total_array_count_after_registration() {
    let mut engine = default_engine();
    engine.register_array("a1", ElementKind::Empty, 0);
    engine.register_array("a2", ElementKind::PackedSmi, 5);
    assert_eq!(engine.total_array_count(), 2);
}

#[test]
fn enrichment_typed_array_count_after_registration() {
    let mut engine = default_engine();
    engine.register_typed_array("ta1", ElementKind::TypedFloat32, 10);
    engine.register_typed_array("ta2", ElementKind::TypedFloat64, 20);
    assert_eq!(engine.typed_array_count(), 2);
}

// ===========================================================================
// ArrayFastLaneEngine: transitions
// ===========================================================================

#[test]
fn enrichment_valid_widening_transition_produces_receipt() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    let receipt = engine.transition_element_kind(
        "arr1",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        42,
    );
    assert!(receipt.is_some());
    let r = receipt.unwrap();
    assert_eq!(r.array_id, "arr1");
}

#[test]
fn enrichment_transition_unknown_array_returns_none() {
    let mut engine = default_engine();
    let receipt = engine.transition_element_kind(
        "nonexistent",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        0,
    );
    assert!(receipt.is_none());
}

#[test]
fn enrichment_transition_updates_element_kind() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    engine.transition_element_kind(
        "arr1",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        0,
    );
    let desc = engine.get_array("arr1").unwrap();
    assert_eq!(desc.element_kind, ElementKind::PackedDouble);
}

#[test]
fn enrichment_multiple_transitions_tracked() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    engine.transition_element_kind(
        "arr1",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        0,
    );
    engine.transition_element_kind(
        "arr1",
        ElementKind::PackedElements,
        TransitionReason::DoubleToElements,
        1,
    );
    let desc = engine.get_array("arr1").unwrap();
    assert_eq!(desc.transition_count(), 2);
}

// ===========================================================================
// ArrayFastLaneEngine: access/store/oob recording
// ===========================================================================

#[test]
fn enrichment_record_access_increments_count() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    assert!(engine.record_access("arr1"));
    assert!(engine.record_access("arr1"));
    let desc = engine.get_array("arr1").unwrap();
    assert_eq!(desc.access_count, 2);
}

#[test]
fn enrichment_record_access_unknown_returns_false() {
    let mut engine = default_engine();
    assert!(!engine.record_access("nonexistent"));
}

#[test]
fn enrichment_record_store_increments_count() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    assert!(engine.record_store("arr1"));
    let desc = engine.get_array("arr1").unwrap();
    assert_eq!(desc.store_count, 1);
}

#[test]
fn enrichment_record_oob_increments_count() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    assert!(engine.record_oob("arr1", 99));
    let desc = engine.get_array("arr1").unwrap();
    assert_eq!(desc.oob_count, 1);
}

// ===========================================================================
// ArrayFastLaneEngine: typed array operations
// ===========================================================================

#[test]
fn enrichment_record_typed_access() {
    let mut engine = default_engine();
    engine.register_typed_array("ta1", ElementKind::TypedFloat32, 100);
    assert!(engine.record_typed_access("ta1"));
    let desc = engine.get_typed_array("ta1").unwrap();
    assert_eq!(desc.access_count, 1);
}

#[test]
fn enrichment_record_bounds_elim() {
    let mut engine = default_engine();
    engine.register_typed_array("ta1", ElementKind::TypedFloat32, 100);
    assert!(engine.record_bounds_elim("ta1"));
    let desc = engine.get_typed_array("ta1").unwrap();
    assert_eq!(desc.bounds_check_eliminated, 1);
}

#[test]
fn enrichment_detach_typed_array() {
    let mut engine = default_engine();
    engine.register_typed_array("ta1", ElementKind::TypedFloat32, 100);
    assert!(engine.detach_typed_array("ta1"));
    let desc = engine.get_typed_array("ta1").unwrap();
    assert!(desc.buffer_detached);
}

#[test]
fn enrichment_detach_nonexistent_typed_array_fails() {
    let mut engine = default_engine();
    assert!(!engine.detach_typed_array("nonexistent"));
}

#[test]
fn enrichment_typed_array_byte_width() {
    let mut engine = default_engine();
    engine.register_typed_array("ta1", ElementKind::TypedFloat64, 10);
    let desc = engine.get_typed_array("ta1").unwrap();
    assert_eq!(desc.byte_width(), 8);
}

// ===========================================================================
// ArrayFastLaneEngine: diagnostics
// ===========================================================================

#[test]
fn enrichment_diagnostics_empty_engine() {
    let engine = default_engine();
    let diag = engine.diagnostics();
    assert_eq!(diag.total_arrays, 0);
    assert_eq!(diag.active_arrays, 0);
    assert_eq!(diag.typed_arrays, 0);
    assert_eq!(diag.total_transitions, 0);
    assert_eq!(diag.total_deopts, 0);
    assert_eq!(diag.total_receipts, 0);
}

#[test]
fn enrichment_diagnostics_after_operations() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    engine.register_typed_array("ta1", ElementKind::TypedInt32, 50);
    engine.record_access("arr1");
    engine.record_store("arr1");
    engine.transition_element_kind(
        "arr1",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        0,
    );
    let diag = engine.diagnostics();
    assert_eq!(diag.total_arrays, 1);
    assert_eq!(diag.typed_arrays, 1);
    assert_eq!(diag.total_transitions, 1);
    assert!(diag.total_accesses >= 1);
    assert!(diag.total_stores >= 1);
}

#[test]
fn enrichment_diagnostics_serde_roundtrip() {
    let engine = default_engine();
    let diag = engine.diagnostics();
    let json = serde_json::to_string(&diag).unwrap();
    let back: ArrayFastLaneDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag.total_arrays, back.total_arrays);
}

// ===========================================================================
// FastLanePolicy
// ===========================================================================

#[test]
fn enrichment_default_policy_values() {
    let policy = FastLanePolicy::default();
    assert!(policy.allow_reopt);
    assert!(policy.max_oob_rate_millionths > 0);
    assert!(policy.max_transitions > 0);
}

#[test]
fn enrichment_policy_hash_deterministic() {
    let p1 = FastLanePolicy::default();
    let p2 = FastLanePolicy::default();
    assert_eq!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn enrichment_different_policies_different_hashes() {
    let p1 = FastLanePolicy::default();
    let mut p2 = FastLanePolicy::default();
    p2.max_oob_rate_millionths = 999_999;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn enrichment_policy_serde_roundtrip() {
    let policy = FastLanePolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: FastLanePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy.max_oob_rate_millionths, back.max_oob_rate_millionths);
    assert_eq!(policy.allow_reopt, back.allow_reopt);
}

// ===========================================================================
// Engine: arrays_by_kind grouping
// ===========================================================================

#[test]
fn enrichment_arrays_by_kind_groups_correctly() {
    let mut engine = default_engine();
    engine.register_array("a1", ElementKind::PackedSmi, 5);
    engine.register_array("a2", ElementKind::PackedSmi, 10);
    engine.register_array("a3", ElementKind::PackedDouble, 3);
    let grouped = engine.arrays_by_kind();
    assert_eq!(grouped.get(&ElementKind::PackedSmi).unwrap().len(), 2);
    assert_eq!(grouped.get(&ElementKind::PackedDouble).unwrap().len(), 1);
}

// ===========================================================================
// Engine: freeze/seal transitions
// ===========================================================================

#[test]
fn enrichment_freeze_transition() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    let receipt = engine.transition_element_kind(
        "arr1",
        ElementKind::Frozen,
        TransitionReason::ObjectFreeze,
        0,
    );
    assert!(receipt.is_some());
    let desc = engine.get_array("arr1").unwrap();
    assert_eq!(desc.element_kind, ElementKind::Frozen);
    assert!(desc.element_kind.is_immutable());
}

#[test]
fn enrichment_seal_transition() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedElements, 5);
    let receipt = engine.transition_element_kind(
        "arr1",
        ElementKind::Sealed,
        TransitionReason::ObjectSeal,
        0,
    );
    assert!(receipt.is_some());
    let desc = engine.get_array("arr1").unwrap();
    assert_eq!(desc.element_kind, ElementKind::Sealed);
}

// ===========================================================================
// DeoptReason serde roundtrip
// ===========================================================================

#[test]
fn enrichment_deopt_reason_serde_roundtrip() {
    let reasons = [
        DeoptReason::ElementKindChanged,
        DeoptReason::ExcessiveOob {
            oob_rate_millionths: 150_000,
        },
        DeoptReason::ShapeMismatch {
            expected: 1,
            observed: 2,
        },
        DeoptReason::ArrayBecameSparse {
            hole_ratio_millionths: 600_000,
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
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: DeoptReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

// ===========================================================================
// OOB rate computation
// ===========================================================================

#[test]
fn enrichment_oob_rate_zero_when_no_accesses() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    let desc = engine.get_array("arr1").unwrap();
    assert_eq!(desc.oob_rate_millionths(), 0);
}

#[test]
fn enrichment_oob_rate_computed_correctly() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    // 10 accesses, 1 oob => 100_000 millionths = 10%
    for _ in 0..10 {
        engine.record_access("arr1");
    }
    engine.record_oob("arr1", 99);
    let desc = engine.get_array("arr1").unwrap();
    let rate = desc.oob_rate_millionths();
    // oob_count / access_count * 1_000_000 = 1/10 * 1_000_000 = 100_000
    assert!(rate > 0, "OOB rate should be positive");
}

// ===========================================================================
// Bounds elimination rate
// ===========================================================================

#[test]
fn enrichment_bounds_elim_rate_zero_initially() {
    let mut engine = default_engine();
    engine.register_typed_array("ta1", ElementKind::TypedInt32, 100);
    let desc = engine.get_typed_array("ta1").unwrap();
    assert_eq!(desc.bounds_elim_rate_millionths(), 0);
}

#[test]
fn enrichment_bounds_elim_rate_computed() {
    let mut engine = default_engine();
    engine.register_typed_array("ta1", ElementKind::TypedInt32, 100);
    for _ in 0..10 {
        engine.record_typed_access("ta1");
    }
    for _ in 0..5 {
        engine.record_bounds_elim("ta1");
    }
    let desc = engine.get_typed_array("ta1").unwrap();
    let rate = desc.bounds_elim_rate_millionths();
    // 5/10 * 1_000_000 = 500_000
    assert!(rate > 0);
}

// ===========================================================================
// Content hash determinism
// ===========================================================================

#[test]
fn enrichment_array_descriptor_content_hash_deterministic() {
    let mut e1 = default_engine();
    let mut e2 = default_engine();
    e1.register_array("arr1", ElementKind::PackedSmi, 10);
    e2.register_array("arr1", ElementKind::PackedSmi, 10);
    let h1 = e1.get_array("arr1").unwrap().content_hash();
    let h2 = e2.get_array("arr1").unwrap().content_hash();
    assert_eq!(h1, h2);
}

// ===========================================================================
// Receipt count
// ===========================================================================

#[test]
fn enrichment_receipt_count_tracks_transitions() {
    let mut engine = default_engine();
    engine.register_array("arr1", ElementKind::PackedSmi, 10);
    assert_eq!(engine.receipt_count(), 0);
    engine.transition_element_kind(
        "arr1",
        ElementKind::PackedDouble,
        TransitionReason::SmiToDouble,
        0,
    );
    assert!(engine.receipt_count() >= 1);
}

// ===========================================================================
// Large-scale registration
// ===========================================================================

#[test]
fn enrichment_many_arrays_tracked() {
    let mut engine = default_engine();
    for i in 0..50 {
        engine.register_array(&format!("arr_{i}"), ElementKind::PackedSmi, i as u64);
    }
    assert_eq!(engine.total_array_count(), 50);
}

#[test]
fn enrichment_many_typed_arrays_tracked() {
    let mut engine = default_engine();
    for i in 0..30 {
        engine.register_typed_array(&format!("ta_{i}"), ElementKind::TypedFloat64, i as u64 + 1);
    }
    assert_eq!(engine.typed_array_count(), 30);
}
