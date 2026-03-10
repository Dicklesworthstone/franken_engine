//! Integration tests for the `vectorized_lane_contract` module.
//!
//! Covers all public enums (Display + serde roundtrip), struct construction,
//! key methods (evaluate, lookup, content_hash), selection vectors, oracle
//! results, and edge cases.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::vectorized_lane_contract::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn satisfied_oracles_for_array_map() -> Vec<ScalarOracleResult> {
    vec![
        ScalarOracleResult::satisfied(ScalarOracleKind::TypeHomogeneity, "all numbers"),
        ScalarOracleResult::satisfied(ScalarOracleKind::NoSideEffects, "pure function"),
        ScalarOracleResult::satisfied(ScalarOracleKind::NoExceptions, "no throw"),
        ScalarOracleResult::satisfied(ScalarOracleKind::DenseElements, "no holes"),
    ]
}

// ---------------------------------------------------------------------------
// BuiltinFamily
// ---------------------------------------------------------------------------

#[test]
fn builtin_family_variant_count() {
    assert_eq!(BuiltinFamily::ALL.len(), 15);
}

#[test]
fn builtin_family_display_all() {
    let expected = [
        "array_map",
        "array_filter",
        "array_reduce",
        "array_for_each",
        "array_every",
        "array_some",
        "array_find",
        "string_replace",
        "string_split",
        "string_match",
        "json_parse",
        "json_stringify",
        "typed_array_sort",
        "typed_array_copy",
        "typed_array_fill",
    ];
    for (family, exp) in BuiltinFamily::ALL.iter().zip(expected.iter()) {
        assert_eq!(family.to_string(), *exp);
        assert_eq!(family.as_str(), *exp);
    }
}

#[test]
fn builtin_family_serde_roundtrip_all() {
    for &family in BuiltinFamily::ALL {
        let json = serde_json::to_string(&family).unwrap();
        let back: BuiltinFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(back, family);
    }
}

#[test]
fn builtin_family_ordering_stable() {
    assert!(BuiltinFamily::ArrayMap < BuiltinFamily::ArrayFilter);
    assert!(BuiltinFamily::ArrayFilter < BuiltinFamily::TypedArrayFill);
}

// ---------------------------------------------------------------------------
// LaneWidth
// ---------------------------------------------------------------------------

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
    assert_eq!(LaneWidth::Scalar.to_string(), "lane_width:1");
    assert_eq!(LaneWidth::Lane4.to_string(), "lane_width:4");
    assert_eq!(LaneWidth::Lane8.to_string(), "lane_width:8");
    assert_eq!(LaneWidth::Lane16.to_string(), "lane_width:16");
    assert_eq!(LaneWidth::Lane32.to_string(), "lane_width:32");
}

#[test]
fn lane_width_serde_roundtrip_all() {
    for &w in LaneWidth::ALL {
        let json = serde_json::to_string(&w).unwrap();
        let back: LaneWidth = serde_json::from_str(&json).unwrap();
        assert_eq!(back, w);
    }
}

// ---------------------------------------------------------------------------
// SelectionBit
// ---------------------------------------------------------------------------

#[test]
fn selection_bit_display() {
    assert_eq!(SelectionBit::Active.to_string(), "active");
    assert_eq!(SelectionBit::Masked.to_string(), "masked");
}

#[test]
fn selection_bit_serde_roundtrip() {
    for bit in [SelectionBit::Active, SelectionBit::Masked] {
        let json = serde_json::to_string(&bit).unwrap();
        let back: SelectionBit = serde_json::from_str(&json).unwrap();
        assert_eq!(back, bit);
    }
}

// ---------------------------------------------------------------------------
// SelectionVector
// ---------------------------------------------------------------------------

#[test]
fn selection_vector_all_active() {
    let sv = SelectionVector::new(8);
    assert!(sv.all_active());
    assert!(!sv.none_active());
    assert_eq!(sv.active_count(), 8);
    assert_eq!(sv.masked_count(), 0);
    assert_eq!(sv.len(), 8);
    assert!(!sv.is_empty());
}

#[test]
fn selection_vector_mask_element() {
    let mut sv = SelectionVector::new(4);
    sv.mask(1);
    sv.mask(3);
    assert!(!sv.all_active());
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
    assert_eq!(sv.len(), 0);
}

#[test]
fn selection_vector_out_of_bounds() {
    let mut sv = SelectionVector::new(2);
    sv.mask(999); // should not panic
    assert!(sv.all_active());
    assert!(!sv.is_active(999));
}

#[test]
fn selection_vector_display() {
    let mut sv = SelectionVector::new(4);
    sv.mask(1);
    assert_eq!(sv.to_string(), "selection[3/4]");
}

#[test]
fn selection_vector_serde_roundtrip() {
    let mut sv = SelectionVector::new(4);
    sv.mask(2);
    let json = serde_json::to_string(&sv).unwrap();
    let back: SelectionVector = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sv);
}

// ---------------------------------------------------------------------------
// ScalarOracleKind
// ---------------------------------------------------------------------------

#[test]
fn scalar_oracle_kind_variant_count() {
    assert_eq!(ScalarOracleKind::ALL.len(), 9);
}

#[test]
fn scalar_oracle_kind_display_all() {
    let expected = [
        "type_homogeneity",
        "no_side_effects",
        "no_exceptions",
        "no_prototype_access",
        "bounded_length",
        "dense_elements",
        "no_holes",
        "integer_only",
        "utf8_only",
    ];
    for (kind, exp) in ScalarOracleKind::ALL.iter().zip(expected.iter()) {
        assert_eq!(kind.to_string(), *exp);
    }
}

#[test]
fn scalar_oracle_kind_serde_roundtrip_all() {
    for &kind in ScalarOracleKind::ALL {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ScalarOracleKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

// ---------------------------------------------------------------------------
// ScalarOracleResult
// ---------------------------------------------------------------------------

#[test]
fn oracle_result_satisfied_meets_threshold() {
    let r = ScalarOracleResult::satisfied(ScalarOracleKind::NoHoles, "dense array check");
    assert!(r.meets_threshold());
    assert!(r.satisfied);
    assert_eq!(r.confidence_millionths, 1_000_000);
}

#[test]
fn oracle_result_unsatisfied_does_not_meet_threshold() {
    let r = ScalarOracleResult::unsatisfied(ScalarOracleKind::NoHoles, "sparse array");
    assert!(!r.meets_threshold());
    assert!(!r.satisfied);
    assert_eq!(r.confidence_millionths, 0);
}

#[test]
fn oracle_result_low_confidence_does_not_meet_threshold() {
    let r = ScalarOracleResult {
        kind: ScalarOracleKind::IntegerOnly,
        satisfied: true,
        confidence_millionths: 500_000,
        reason: "mixed types observed".to_string(),
    };
    assert!(!r.meets_threshold());
}

#[test]
fn oracle_result_serde_roundtrip() {
    let r = ScalarOracleResult::satisfied(ScalarOracleKind::TypeHomogeneity, "all ints");
    let json = serde_json::to_string(&r).unwrap();
    let back: ScalarOracleResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn oracle_result_display_format() {
    let r = ScalarOracleResult::satisfied(ScalarOracleKind::BoundedLength, "ok");
    let s = r.to_string();
    assert!(s.contains("bounded_length"));
    assert!(s.contains("satisfied=true"));
}

// ---------------------------------------------------------------------------
// OrderingConstraint
// ---------------------------------------------------------------------------

#[test]
fn ordering_constraint_display_all() {
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

#[test]
fn ordering_constraint_serde_roundtrip() {
    let all = [
        OrderingConstraint::StrictLeftToRight,
        OrderingConstraint::Commutative,
        OrderingConstraint::AssociativeCommutative,
        OrderingConstraint::NoOrdering,
    ];
    for oc in &all {
        let json = serde_json::to_string(oc).unwrap();
        let back: OrderingConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(*oc, back);
    }
}

// ---------------------------------------------------------------------------
// LaneEligibility
// ---------------------------------------------------------------------------

#[test]
fn lane_eligibility_serde_roundtrip() {
    let e = LaneEligibility {
        family: BuiltinFamily::ArrayMap,
        max_lane_width: LaneWidth::Lane16,
        required_oracles: vec![
            ScalarOracleKind::TypeHomogeneity,
            ScalarOracleKind::NoSideEffects,
        ],
        ordering: OrderingConstraint::NoOrdering,
        supports_early_exit: false,
        supports_masking: true,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: LaneEligibility = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// LaneSpecimenFamily
// ---------------------------------------------------------------------------

#[test]
fn lane_specimen_family_variant_count() {
    assert_eq!(LaneSpecimenFamily::ALL.len(), 6);
}

#[test]
fn lane_specimen_family_display_all() {
    let expected = [
        "array_ops",
        "string_ops",
        "json_ops",
        "typed_array_ops",
        "mixed_width",
        "oracle_evaluation",
    ];
    for (fam, exp) in LaneSpecimenFamily::ALL.iter().zip(expected.iter()) {
        assert_eq!(fam.to_string(), *exp);
    }
}

#[test]
fn lane_specimen_family_serde_roundtrip_all() {
    for &family in LaneSpecimenFamily::ALL {
        let json = serde_json::to_string(&family).unwrap();
        let back: LaneSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(back, family);
    }
}

// ---------------------------------------------------------------------------
// LaneContract
// ---------------------------------------------------------------------------

#[test]
fn lane_contract_new_has_all_families() {
    let contract = LaneContract::new();
    for &family in BuiltinFamily::ALL {
        assert!(
            contract.lookup(family).is_some(),
            "missing eligibility for {family:?}"
        );
    }
}

#[test]
fn lane_contract_schema_version() {
    let c = LaneContract::new();
    assert_eq!(c.schema_version, VECTORIZED_LANE_SCHEMA_VERSION);
}

#[test]
fn lane_contract_default_matches_new() {
    let c1 = LaneContract::new();
    let c2 = LaneContract::default();
    assert_eq!(c1, c2);
}

#[test]
fn lane_contract_serde_roundtrip() {
    let c = LaneContract::new();
    let json = serde_json::to_string(&c).unwrap();
    let back: LaneContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn lane_contract_display_contains_families() {
    let c = LaneContract::new();
    let s = c.to_string();
    assert!(s.contains("LaneContract"));
    assert!(s.contains("families=15"));
}

#[test]
fn lane_contract_content_hash_determinism() {
    let c1 = LaneContract::new();
    let c2 = LaneContract::new();
    assert_eq!(c1.content_hash(), c2.content_hash());
}

// ---------------------------------------------------------------------------
// LaneContract — evaluate
// ---------------------------------------------------------------------------

#[test]
fn evaluate_eligible_array_map() {
    let contract = LaneContract::new();
    let oracles = satisfied_oracles_for_array_map();
    let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.chosen_width, LaneWidth::Lane16);
    assert!(decision.rejection_reason.is_none());
}

#[test]
fn evaluate_rejected_missing_oracle() {
    let contract = LaneContract::new();
    let oracles = vec![ScalarOracleResult::satisfied(
        ScalarOracleKind::TypeHomogeneity,
        "ok",
    )];
    let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, test_epoch());
    assert!(!decision.eligible);
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
    let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, test_epoch());
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
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 0, test_epoch());
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
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 64, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.chosen_width, LaneWidth::Lane32);
}

#[test]
fn evaluate_small_input_falls_back_to_scalar() {
    let contract = LaneContract::new();
    let oracles = satisfied_oracles_for_array_map();
    let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 2, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.chosen_width, LaneWidth::Scalar);
}

#[test]
fn evaluate_array_reduce_needs_integer_only() {
    let contract = LaneContract::new();
    let oracles = vec![
        ScalarOracleResult::satisfied(ScalarOracleKind::TypeHomogeneity, "ok"),
        ScalarOracleResult::satisfied(ScalarOracleKind::NoSideEffects, "ok"),
        ScalarOracleResult::satisfied(ScalarOracleKind::NoExceptions, "ok"),
        ScalarOracleResult::satisfied(ScalarOracleKind::IntegerOnly, "ok"),
    ];
    let decision = contract.evaluate(BuiltinFamily::ArrayReduce, &oracles, 100, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.chosen_width, LaneWidth::Lane8);
}

// ---------------------------------------------------------------------------
// VectorizationDecision
// ---------------------------------------------------------------------------

#[test]
fn vectorization_decision_serde_roundtrip_eligible() {
    let contract = LaneContract::new();
    let oracles = satisfied_oracles_for_array_map();
    let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, test_epoch());
    let json = serde_json::to_string(&decision).unwrap();
    let back: VectorizationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn vectorization_decision_serde_roundtrip_rejected() {
    let contract = LaneContract::new();
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 0, test_epoch());
    let json = serde_json::to_string(&decision).unwrap();
    let back: VectorizationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn vectorization_decision_display_eligible() {
    let contract = LaneContract::new();
    let oracles = satisfied_oracles_for_array_map();
    let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, test_epoch());
    let s = decision.to_string();
    assert!(s.contains("eligible"));
    assert!(s.contains("array_map"));
}

#[test]
fn vectorization_decision_display_rejected() {
    let contract = LaneContract::new();
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 0, test_epoch());
    let s = decision.to_string();
    assert!(s.contains("rejected"));
    assert!(s.contains("typed_array_fill"));
}

#[test]
fn decision_hash_changes_with_family() {
    let contract = LaneContract::new();
    let d1 = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 64, test_epoch());
    let d2 = contract.evaluate(
        BuiltinFamily::TypedArrayCopy,
        &[ScalarOracleResult::satisfied(
            ScalarOracleKind::BoundedLength,
            "ok",
        )],
        64,
        test_epoch(),
    );
    assert_ne!(d1.content_hash, d2.content_hash);
}

// ---------------------------------------------------------------------------
// Eligibility properties
// ---------------------------------------------------------------------------

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
    assert!(e.supports_masking);
}

#[test]
fn typed_array_fill_no_required_oracles() {
    let contract = LaneContract::new();
    let e = contract.lookup(BuiltinFamily::TypedArrayFill).unwrap();
    assert!(e.required_oracles.is_empty());
    assert_eq!(e.max_lane_width, LaneWidth::Lane32);
}

#[test]
fn string_operations_use_lane4() {
    let contract = LaneContract::new();
    for family in [
        BuiltinFamily::StringReplace,
        BuiltinFamily::StringSplit,
        BuiltinFamily::StringMatch,
    ] {
        let e = contract.lookup(family).unwrap();
        assert_eq!(e.max_lane_width, LaneWidth::Lane4);
        assert_eq!(e.ordering, OrderingConstraint::StrictLeftToRight);
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_constants() {
    assert!(VECTORIZED_LANE_SCHEMA_VERSION.contains("vectorized-lane-contract"));
    assert_eq!(VECTORIZED_LANE_BEAD_ID, "bd-1lsy.7.24.1");
}
