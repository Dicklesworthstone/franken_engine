//! Enrichment integration tests for `vectorized_lane_contract`.
//!
//! Covers Copy/Clone semantics, BTreeSet dedup, Debug/Display uniqueness,
//! serde JSON field stability, determinism, boundary conditions, and
//! cross-cutting invariants NOT already tested in the base integration file.

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

use std::collections::BTreeSet;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::vectorized_lane_contract::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn all_satisfied_oracles_for(family: BuiltinFamily) -> Vec<ScalarOracleResult> {
    let contract = LaneContract::new();
    let elig = contract.lookup(family).unwrap();
    elig.required_oracles
        .iter()
        .map(|&k| ScalarOracleResult::satisfied(k, "enrichment"))
        .collect()
}

// ===========================================================================
// BuiltinFamily enrichment
// ===========================================================================

#[test]
fn enrichment_builtin_family_copy_semantics() {
    let a = BuiltinFamily::ArrayMap;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_builtin_family_clone_equals_copy() {
    for &f in BuiltinFamily::ALL {
        let cloned = f.clone();
        assert_eq!(f, cloned);
    }
}

#[test]
fn enrichment_builtin_family_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &f in BuiltinFamily::ALL {
        set.insert(f);
        set.insert(f); // duplicate
    }
    assert_eq!(set.len(), BuiltinFamily::ALL.len());
}

#[test]
fn enrichment_builtin_family_debug_all_unique() {
    let debugs: BTreeSet<String> = BuiltinFamily::ALL
        .iter()
        .map(|f| format!("{f:?}"))
        .collect();
    assert_eq!(debugs.len(), BuiltinFamily::ALL.len());
}

#[test]
fn enrichment_builtin_family_display_all_unique() {
    let displays: BTreeSet<String> = BuiltinFamily::ALL.iter().map(|f| f.to_string()).collect();
    assert_eq!(displays.len(), BuiltinFamily::ALL.len());
}

#[test]
fn enrichment_builtin_family_as_str_matches_display() {
    for &f in BuiltinFamily::ALL {
        assert_eq!(f.as_str(), &f.to_string());
    }
}

// ===========================================================================
// LaneWidth enrichment
// ===========================================================================

#[test]
fn enrichment_lane_width_copy_semantics() {
    let a = LaneWidth::Lane8;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.width(), 8);
}

#[test]
fn enrichment_lane_width_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &w in LaneWidth::ALL {
        set.insert(w);
        set.insert(w);
    }
    assert_eq!(set.len(), LaneWidth::ALL.len());
}

#[test]
fn enrichment_lane_width_debug_all_unique() {
    let debugs: BTreeSet<String> = LaneWidth::ALL.iter().map(|w| format!("{w:?}")).collect();
    assert_eq!(debugs.len(), LaneWidth::ALL.len());
}

#[test]
fn enrichment_lane_width_best_fit_input_len_1() {
    // Input of 1 element, max Lane32 => Scalar (1 < 4)
    let contract = LaneContract::new();
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 1, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.chosen_width, LaneWidth::Scalar);
}

#[test]
fn enrichment_lane_width_best_fit_exact_4() {
    let contract = LaneContract::new();
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 4, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.chosen_width, LaneWidth::Lane4);
}

#[test]
fn enrichment_lane_width_best_fit_between_widths() {
    // 5 elements, max Lane32 => Lane4 (5 >= 4 but 5 < 8)
    let contract = LaneContract::new();
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 5, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.chosen_width, LaneWidth::Lane4);
}

#[test]
fn enrichment_lane_width_best_fit_exact_32() {
    let contract = LaneContract::new();
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 32, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.chosen_width, LaneWidth::Lane32);
}

// ===========================================================================
// SelectionBit enrichment
// ===========================================================================

#[test]
fn enrichment_selection_bit_copy_semantics() {
    let a = SelectionBit::Active;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_selection_bit_serde_json_values() {
    let active_json = serde_json::to_string(&SelectionBit::Active).unwrap();
    let masked_json = serde_json::to_string(&SelectionBit::Masked).unwrap();
    assert_ne!(active_json, masked_json);
}

// ===========================================================================
// SelectionVector enrichment
// ===========================================================================

#[test]
fn enrichment_selection_vector_clone_independence() {
    let mut sv = SelectionVector::new(4);
    let cloned = sv.clone();
    sv.mask(0);
    sv.mask(1);
    // Clone should be unaffected
    assert!(cloned.all_active());
    assert_eq!(cloned.active_count(), 4);
    assert_eq!(sv.active_count(), 2);
}

#[test]
fn enrichment_selection_vector_mask_idempotent() {
    let mut sv = SelectionVector::new(4);
    sv.mask(2);
    let count_after_first = sv.masked_count();
    sv.mask(2); // mask same index again
    assert_eq!(sv.masked_count(), count_after_first);
}

#[test]
fn enrichment_selection_vector_large() {
    let mut sv = SelectionVector::new(100);
    assert_eq!(sv.len(), 100);
    assert_eq!(sv.active_count(), 100);
    for i in (0..100).step_by(2) {
        sv.mask(i);
    }
    assert_eq!(sv.active_count(), 50);
    assert_eq!(sv.masked_count(), 50);
}

#[test]
fn enrichment_selection_vector_json_field_names() {
    let sv = SelectionVector::new(2);
    let json = serde_json::to_string(&sv).unwrap();
    assert!(json.contains("bits"));
}

#[test]
fn enrichment_selection_vector_debug_nonempty() {
    let sv = SelectionVector::new(3);
    let dbg = format!("{sv:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("SelectionVector"));
}

// ===========================================================================
// ScalarOracleKind enrichment
// ===========================================================================

#[test]
fn enrichment_scalar_oracle_kind_copy_semantics() {
    let a = ScalarOracleKind::NoHoles;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_scalar_oracle_kind_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &k in ScalarOracleKind::ALL {
        set.insert(k);
        set.insert(k);
    }
    assert_eq!(set.len(), ScalarOracleKind::ALL.len());
}

#[test]
fn enrichment_scalar_oracle_kind_debug_all_unique() {
    let debugs: BTreeSet<String> = ScalarOracleKind::ALL
        .iter()
        .map(|k| format!("{k:?}"))
        .collect();
    assert_eq!(debugs.len(), ScalarOracleKind::ALL.len());
}

#[test]
fn enrichment_scalar_oracle_kind_display_all_unique() {
    let displays: BTreeSet<String> = ScalarOracleKind::ALL
        .iter()
        .map(|k| k.to_string())
        .collect();
    assert_eq!(displays.len(), ScalarOracleKind::ALL.len());
}

#[test]
fn enrichment_scalar_oracle_kind_as_str_matches_display() {
    for &k in ScalarOracleKind::ALL {
        assert_eq!(k.as_str(), &k.to_string());
    }
}

// ===========================================================================
// ScalarOracleResult enrichment
// ===========================================================================

#[test]
fn enrichment_oracle_result_clone_independence() {
    let original = ScalarOracleResult::satisfied(ScalarOracleKind::NoHoles, "dense");
    let mut cloned = original.clone();
    cloned.reason = "mutated".to_string();
    assert_eq!(original.reason, "dense");
    assert_eq!(cloned.reason, "mutated");
}

#[test]
fn enrichment_oracle_result_threshold_boundary_exact() {
    // Exactly at threshold (900_000) should meet it
    let r = ScalarOracleResult {
        kind: ScalarOracleKind::IntegerOnly,
        satisfied: true,
        confidence_millionths: 900_000,
        reason: "threshold boundary".to_string(),
    };
    assert!(r.meets_threshold());
}

#[test]
fn enrichment_oracle_result_threshold_boundary_one_below() {
    let r = ScalarOracleResult {
        kind: ScalarOracleKind::IntegerOnly,
        satisfied: true,
        confidence_millionths: 899_999,
        reason: "just below threshold".to_string(),
    };
    assert!(!r.meets_threshold());
}

#[test]
fn enrichment_oracle_result_satisfied_false_high_confidence() {
    // satisfied=false even with max confidence should not meet threshold
    let r = ScalarOracleResult {
        kind: ScalarOracleKind::NoSideEffects,
        satisfied: false,
        confidence_millionths: 1_000_000,
        reason: "high confidence but unsatisfied".to_string(),
    };
    assert!(!r.meets_threshold());
}

#[test]
fn enrichment_oracle_result_display_all_kinds() {
    for &k in ScalarOracleKind::ALL {
        let r = ScalarOracleResult::satisfied(k, "test");
        let s = r.to_string();
        assert!(s.contains(k.as_str()), "Display should contain oracle kind");
        assert!(s.contains("satisfied=true"));
    }
}

#[test]
fn enrichment_oracle_result_json_field_names() {
    let r = ScalarOracleResult::satisfied(ScalarOracleKind::TypeHomogeneity, "test");
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"satisfied\""));
    assert!(json.contains("\"confidence_millionths\""));
    assert!(json.contains("\"reason\""));
}

#[test]
fn enrichment_oracle_result_debug_nonempty() {
    let r = ScalarOracleResult::satisfied(ScalarOracleKind::Utf8Only, "utf8");
    let dbg = format!("{r:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ScalarOracleResult"));
}

// ===========================================================================
// OrderingConstraint enrichment
// ===========================================================================

#[test]
fn enrichment_ordering_constraint_copy_semantics() {
    let a = OrderingConstraint::Commutative;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_ordering_constraint_btreeset_dedup() {
    let all = [
        OrderingConstraint::StrictLeftToRight,
        OrderingConstraint::Commutative,
        OrderingConstraint::AssociativeCommutative,
        OrderingConstraint::NoOrdering,
    ];
    let mut set = BTreeSet::new();
    for oc in &all {
        set.insert(*oc);
        set.insert(*oc);
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_ordering_constraint_debug_all_unique() {
    let all = [
        OrderingConstraint::StrictLeftToRight,
        OrderingConstraint::Commutative,
        OrderingConstraint::AssociativeCommutative,
        OrderingConstraint::NoOrdering,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|o| format!("{o:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_ordering_constraint_as_str_matches_display() {
    let all = [
        OrderingConstraint::StrictLeftToRight,
        OrderingConstraint::Commutative,
        OrderingConstraint::AssociativeCommutative,
        OrderingConstraint::NoOrdering,
    ];
    for oc in &all {
        assert_eq!(oc.as_str(), &oc.to_string());
    }
}

// ===========================================================================
// LaneEligibility enrichment
// ===========================================================================

#[test]
fn enrichment_lane_eligibility_clone_independence() {
    let contract = LaneContract::new();
    let original = contract.lookup(BuiltinFamily::ArrayMap).unwrap().clone();
    let mut cloned = original.clone();
    cloned.required_oracles.push(ScalarOracleKind::Utf8Only);
    assert_eq!(original.required_oracles.len(), 4);
    assert_eq!(cloned.required_oracles.len(), 5);
}

#[test]
fn enrichment_lane_eligibility_debug_nonempty() {
    let contract = LaneContract::new();
    let e = contract.lookup(BuiltinFamily::ArrayFilter).unwrap();
    let dbg = format!("{e:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("LaneEligibility"));
}

#[test]
fn enrichment_lane_eligibility_json_field_names() {
    let contract = LaneContract::new();
    let e = contract.lookup(BuiltinFamily::ArrayMap).unwrap();
    let json = serde_json::to_string(e).unwrap();
    assert!(json.contains("\"family\""));
    assert!(json.contains("\"max_lane_width\""));
    assert!(json.contains("\"required_oracles\""));
    assert!(json.contains("\"ordering\""));
    assert!(json.contains("\"supports_early_exit\""));
    assert!(json.contains("\"supports_masking\""));
}

#[test]
fn enrichment_lane_eligibility_early_exit_families() {
    let contract = LaneContract::new();
    let early_exit_families = [
        BuiltinFamily::ArrayEvery,
        BuiltinFamily::ArraySome,
        BuiltinFamily::ArrayFind,
    ];
    for &f in &early_exit_families {
        let e = contract.lookup(f).unwrap();
        assert!(e.supports_early_exit, "{f:?} should support early exit");
    }
    let no_early_exit = [
        BuiltinFamily::ArrayMap,
        BuiltinFamily::ArrayFilter,
        BuiltinFamily::ArrayReduce,
        BuiltinFamily::ArrayForEach,
    ];
    for &f in &no_early_exit {
        let e = contract.lookup(f).unwrap();
        assert!(
            !e.supports_early_exit,
            "{f:?} should NOT support early exit"
        );
    }
}

// ===========================================================================
// LaneSpecimenFamily enrichment
// ===========================================================================

#[test]
fn enrichment_lane_specimen_family_copy_semantics() {
    let a = LaneSpecimenFamily::ArrayOps;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_lane_specimen_family_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &f in LaneSpecimenFamily::ALL {
        set.insert(f);
        set.insert(f);
    }
    assert_eq!(set.len(), LaneSpecimenFamily::ALL.len());
}

#[test]
fn enrichment_lane_specimen_family_debug_all_unique() {
    let debugs: BTreeSet<String> = LaneSpecimenFamily::ALL
        .iter()
        .map(|f| format!("{f:?}"))
        .collect();
    assert_eq!(debugs.len(), LaneSpecimenFamily::ALL.len());
}

#[test]
fn enrichment_lane_specimen_family_display_all_unique() {
    let displays: BTreeSet<String> = LaneSpecimenFamily::ALL
        .iter()
        .map(|f| f.to_string())
        .collect();
    assert_eq!(displays.len(), LaneSpecimenFamily::ALL.len());
}

#[test]
fn enrichment_lane_specimen_family_as_str_matches_display() {
    for &f in LaneSpecimenFamily::ALL {
        assert_eq!(f.as_str(), &f.to_string());
    }
}

// ===========================================================================
// LaneContract enrichment
// ===========================================================================

#[test]
fn enrichment_lane_contract_clone_independence() {
    let original = LaneContract::new();
    let mut cloned = original.clone();
    cloned.schema_version = "mutated".to_string();
    assert_eq!(original.schema_version, VECTORIZED_LANE_SCHEMA_VERSION);
    assert_eq!(cloned.schema_version, "mutated");
}

#[test]
fn enrichment_lane_contract_debug_nonempty() {
    let c = LaneContract::new();
    let dbg = format!("{c:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("LaneContract"));
}

#[test]
fn enrichment_lane_contract_json_field_names() {
    let c = LaneContract::new();
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"eligibility_map\""));
    assert!(json.contains("\"schema_version\""));
}

#[test]
fn enrichment_lane_contract_evaluate_all_families_eligible() {
    let contract = LaneContract::new();
    for &family in BuiltinFamily::ALL {
        let oracles = all_satisfied_oracles_for(family);
        let decision = contract.evaluate(family, &oracles, 100, test_epoch());
        assert!(
            decision.eligible,
            "{family:?} should be eligible with all required oracles satisfied"
        );
        assert!(decision.rejection_reason.is_none());
    }
}

#[test]
fn enrichment_lane_contract_evaluate_determinism_five_runs() {
    let contract = LaneContract::new();
    let oracles = all_satisfied_oracles_for(BuiltinFamily::ArrayMap);
    let first = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 50, test_epoch());
    for _ in 0..4 {
        let again = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 50, test_epoch());
        assert_eq!(first.eligible, again.eligible);
        assert_eq!(first.chosen_width, again.chosen_width);
        assert_eq!(first.content_hash, again.content_hash);
        assert_eq!(first.selection, again.selection);
    }
}

#[test]
fn enrichment_lane_contract_content_hash_changes_with_mutation() {
    let c1 = LaneContract::new();
    let mut c2 = LaneContract::new();
    c2.schema_version = "mutated-version".to_string();
    assert_ne!(c1.content_hash(), c2.content_hash());
}

// ===========================================================================
// VectorizationDecision enrichment
// ===========================================================================

#[test]
fn enrichment_decision_clone_independence() {
    let contract = LaneContract::new();
    let oracles = all_satisfied_oracles_for(BuiltinFamily::ArrayMap);
    let original = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, test_epoch());
    let mut cloned = original.clone();
    cloned.eligible = false;
    assert!(original.eligible);
    assert!(!cloned.eligible);
}

#[test]
fn enrichment_decision_debug_nonempty() {
    let contract = LaneContract::new();
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 64, test_epoch());
    let dbg = format!("{decision:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("VectorizationDecision"));
}

#[test]
fn enrichment_decision_json_field_names() {
    let contract = LaneContract::new();
    let oracles = all_satisfied_oracles_for(BuiltinFamily::ArrayMap);
    let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, test_epoch());
    let json = serde_json::to_string(&decision).unwrap();
    assert!(json.contains("\"family\""));
    assert!(json.contains("\"chosen_width\""));
    assert!(json.contains("\"oracle_results\""));
    assert!(json.contains("\"selection\""));
    assert!(json.contains("\"eligible\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_decision_eligible_selection_matches_width() {
    let contract = LaneContract::new();
    for &family in BuiltinFamily::ALL {
        let oracles = all_satisfied_oracles_for(family);
        let decision = contract.evaluate(family, &oracles, 100, test_epoch());
        if decision.eligible {
            assert_eq!(
                decision.selection.len(),
                decision.chosen_width.width() as usize,
                "selection vector length should match chosen width for {family:?}"
            );
            assert!(
                decision.selection.all_active(),
                "initial selection should be all-active for {family:?}"
            );
        }
    }
}

#[test]
fn enrichment_decision_rejected_has_empty_selection() {
    let contract = LaneContract::new();
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 0, test_epoch());
    assert!(!decision.eligible);
    assert!(decision.selection.is_empty());
    assert_eq!(decision.chosen_width, LaneWidth::Scalar);
}

#[test]
fn enrichment_decision_rejected_preserves_oracle_results_empty() {
    let contract = LaneContract::new();
    let decision = contract.evaluate(BuiltinFamily::TypedArrayFill, &[], 0, test_epoch());
    assert!(decision.oracle_results.is_empty());
}

#[test]
fn enrichment_decision_eligible_preserves_oracle_results() {
    let contract = LaneContract::new();
    let oracles = all_satisfied_oracles_for(BuiltinFamily::ArrayReduce);
    let decision = contract.evaluate(BuiltinFamily::ArrayReduce, &oracles, 100, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.oracle_results.len(), oracles.len());
}

// ===========================================================================
// Cross-cutting: evaluate with low-confidence oracle
// ===========================================================================

#[test]
fn enrichment_evaluate_low_confidence_oracle_rejects() {
    let contract = LaneContract::new();
    let oracles = vec![
        ScalarOracleResult::satisfied(ScalarOracleKind::TypeHomogeneity, "ok"),
        ScalarOracleResult::satisfied(ScalarOracleKind::NoSideEffects, "ok"),
        ScalarOracleResult::satisfied(ScalarOracleKind::NoExceptions, "ok"),
        ScalarOracleResult {
            kind: ScalarOracleKind::DenseElements,
            satisfied: true,
            confidence_millionths: 800_000, // 80% — below 90% threshold
            reason: "partially dense".to_string(),
        },
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
fn enrichment_evaluate_exact_threshold_oracle_accepts() {
    let contract = LaneContract::new();
    let oracles = vec![
        ScalarOracleResult::satisfied(ScalarOracleKind::TypeHomogeneity, "ok"),
        ScalarOracleResult::satisfied(ScalarOracleKind::NoSideEffects, "ok"),
        ScalarOracleResult::satisfied(ScalarOracleKind::NoExceptions, "ok"),
        ScalarOracleResult {
            kind: ScalarOracleKind::DenseElements,
            satisfied: true,
            confidence_millionths: 900_000, // exactly at threshold
            reason: "threshold boundary".to_string(),
        },
    ];
    let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, test_epoch());
    assert!(decision.eligible);
}

// ===========================================================================
// Cross-cutting: lane width choice by family max
// ===========================================================================

#[test]
fn enrichment_string_family_capped_at_lane4() {
    let contract = LaneContract::new();
    for &family in &[
        BuiltinFamily::StringReplace,
        BuiltinFamily::StringSplit,
        BuiltinFamily::StringMatch,
    ] {
        let oracles = all_satisfied_oracles_for(family);
        let decision = contract.evaluate(family, &oracles, 1000, test_epoch());
        assert!(decision.eligible);
        assert_eq!(
            decision.chosen_width,
            LaneWidth::Lane4,
            "String ops should cap at Lane4 for {family:?}"
        );
    }
}

#[test]
fn enrichment_typed_array_sort_caps_at_lane32() {
    let contract = LaneContract::new();
    let oracles = all_satisfied_oracles_for(BuiltinFamily::TypedArraySort);
    let decision = contract.evaluate(BuiltinFamily::TypedArraySort, &oracles, 1000, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.chosen_width, LaneWidth::Lane32);
}

#[test]
fn enrichment_array_reduce_caps_at_lane8() {
    let contract = LaneContract::new();
    let oracles = all_satisfied_oracles_for(BuiltinFamily::ArrayReduce);
    let decision = contract.evaluate(BuiltinFamily::ArrayReduce, &oracles, 1000, test_epoch());
    assert!(decision.eligible);
    assert_eq!(decision.chosen_width, LaneWidth::Lane8);
}

// ===========================================================================
// Cross-cutting: epoch does not affect decision
// ===========================================================================

#[test]
fn enrichment_different_epochs_same_decision() {
    let contract = LaneContract::new();
    let oracles = all_satisfied_oracles_for(BuiltinFamily::ArrayMap);
    let d1 = contract.evaluate(
        BuiltinFamily::ArrayMap,
        &oracles,
        100,
        SecurityEpoch::from_raw(1),
    );
    let d2 = contract.evaluate(
        BuiltinFamily::ArrayMap,
        &oracles,
        100,
        SecurityEpoch::from_raw(999),
    );
    assert_eq!(d1.eligible, d2.eligible);
    assert_eq!(d1.chosen_width, d2.chosen_width);
    assert_eq!(d1.content_hash, d2.content_hash);
}

// ===========================================================================
// Cross-cutting: constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stable() {
    assert_eq!(
        VECTORIZED_LANE_SCHEMA_VERSION,
        "franken-engine.vectorized-lane-contract.v1"
    );
    assert_eq!(VECTORIZED_LANE_BEAD_ID, "bd-1lsy.7.24.1");
}

// ===========================================================================
// Cross-cutting: serde roundtrips for all families' decisions
// ===========================================================================

#[test]
fn enrichment_all_families_decisions_serde_roundtrip() {
    let contract = LaneContract::new();
    for &family in BuiltinFamily::ALL {
        let oracles = all_satisfied_oracles_for(family);
        let decision = contract.evaluate(family, &oracles, 50, test_epoch());
        let json = serde_json::to_string(&decision).unwrap();
        let back: VectorizationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back, "serde roundtrip failed for {family:?}");
    }
}

// ===========================================================================
// Cross-cutting: content hash is nonempty bytes
// ===========================================================================

#[test]
fn enrichment_content_hash_nonempty_bytes() {
    let contract = LaneContract::new();
    let hash = contract.content_hash();
    assert!(!hash.as_bytes().is_empty());
    assert!(
        hash.as_bytes().iter().any(|&b| b != 0),
        "hash should not be all zeros"
    );
}

#[test]
fn enrichment_decision_content_hash_nonempty() {
    let contract = LaneContract::new();
    let oracles = all_satisfied_oracles_for(BuiltinFamily::ArrayMap);
    let decision = contract.evaluate(BuiltinFamily::ArrayMap, &oracles, 100, test_epoch());
    assert!(!decision.content_hash.as_bytes().is_empty());
}

// ===========================================================================
// Cross-cutting: ordering constraint semantics in eligibility
// ===========================================================================

#[test]
fn enrichment_ordering_constraint_coverage() {
    let contract = LaneContract::new();
    let mut orderings = BTreeSet::new();
    for &family in BuiltinFamily::ALL {
        let e = contract.lookup(family).unwrap();
        orderings.insert(e.ordering);
    }
    // Should cover at least 3 of 4 ordering constraints
    assert!(
        orderings.len() >= 3,
        "eligibility map should use diverse ordering constraints"
    );
}

#[test]
fn enrichment_masking_support_coverage() {
    let contract = LaneContract::new();
    let masking_count = BuiltinFamily::ALL
        .iter()
        .filter(|&&f| contract.lookup(f).unwrap().supports_masking)
        .count();
    let no_masking_count = BuiltinFamily::ALL.len() - masking_count;
    assert!(masking_count > 0, "some families should support masking");
    assert!(
        no_masking_count > 0,
        "some families should not support masking"
    );
}
