//! Enrichment integration tests for specialization_conformance module.
//!
//! Covers serde roundtrips, Display/as_str impls, helper methods,
//! edge cases, boundary conditions, and cross-type interactions not
//! exercised by the existing 14 integration tests.
//!
//! bd-2pv: Section 10.7 item 9.

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

use frankenengine_engine::engine_object_id::{self, ObjectDomain, SchemaId};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_specialization_receipt::{
    OptimizationClass, ProofInput, ProofType,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::specialization_conformance::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn schema_id() -> SchemaId {
    SchemaId::from_definition(b"SpecConformanceEnrichment.v1")
}

fn eid(tag: &str) -> frankenengine_engine::engine_object_id::EngineObjectId {
    engine_object_id::derive_id(
        ObjectDomain::PolicyObject,
        "enrichment",
        &schema_id(),
        tag.as_bytes(),
    )
    .unwrap()
}

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn proof_input(tag: &str, ep: SecurityEpoch) -> ProofInput {
    ProofInput {
        proof_type: ProofType::CapabilityWitness,
        proof_id: eid(&format!("proof-{tag}")),
        proof_epoch: ep,
        validity_window_ticks: 10_000,
    }
}

fn inv_entry(tag: &str, ep: SecurityEpoch, tt: TransformationType) -> SpecializationInventoryEntry {
    SpecializationInventoryEntry {
        specialization_id: eid(&format!("spec-{tag}")),
        slot_id: format!("slot-{tag}"),
        proof_inputs: vec![proof_input(tag, ep)],
        transformation_type: tt,
        optimization_receipt_hash: ContentHash::compute(format!("receipt-{tag}").as_bytes()),
        rollback_token_hash: ContentHash::compute(format!("rollback-{tag}").as_bytes()),
        validity_epoch: ep,
        fallback_path: format!("fallback-{tag}"),
    }
}

fn wl(id: &str, cat: CorpusCategory) -> SpecializationWorkload {
    SpecializationWorkload {
        workload_id: id.to_string(),
        category: cat,
        input: format!("input-{id}"),
        expected_output: format!("output-{id}"),
        expected_side_effects: vec![SideEffect {
            effect_type: "hostcall".to_string(),
            description: format!("effect-{id}"),
            sequence: 0,
        }],
    }
}

fn full_corpus(prefix: &str) -> Vec<SpecializationWorkload> {
    let mut out = Vec::new();
    for i in 0..30 {
        out.push(wl(
            &format!("{prefix}-p{i}"),
            CorpusCategory::SemanticParity,
        ));
    }
    for i in 0..10 {
        out.push(wl(&format!("{prefix}-e{i}"), CorpusCategory::EdgeCase));
    }
    for i in 0..5 {
        out.push(wl(
            &format!("{prefix}-t{i}"),
            CorpusCategory::EpochTransition,
        ));
    }
    out
}

fn ok_outcome(val: &str) -> WorkloadOutcome {
    WorkloadOutcome {
        return_value: val.to_string(),
        side_effect_trace: vec![SideEffect {
            effect_type: "hostcall".to_string(),
            description: "call-1".to_string(),
            sequence: 0,
        }],
        exceptions: vec![],
        evidence_entries: vec!["ev-1".to_string()],
    }
}

fn compare_input<'a>(
    spec_id: &'a frankenengine_engine::engine_object_id::EngineObjectId,
    wid: &'a str,
    cat: CorpusCategory,
    specialized: &'a WorkloadOutcome,
    unspecialized: &'a WorkloadOutcome,
) -> CompareOutcomesInput<'a> {
    CompareOutcomesInput {
        specialization_id: spec_id,
        workload_id: wid,
        category: cat,
        specialized,
        unspecialized,
        specialized_duration_us: 80,
        unspecialized_duration_us: 100,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
    }
}

// ===========================================================================
// Section 1: TransformationType — serde, Display, as_str, ALL
// ===========================================================================

#[test]
fn transformation_type_serde_all_variants() {
    for tt in TransformationType::ALL {
        let json = serde_json::to_string(tt).unwrap();
        let back: TransformationType = serde_json::from_str(&json).unwrap();
        assert_eq!(*tt, back);
    }
}

#[test]
fn transformation_type_as_str_matches_display() {
    for tt in TransformationType::ALL {
        assert_eq!(tt.as_str(), tt.to_string());
    }
}

#[test]
fn transformation_type_all_has_four_variants() {
    assert_eq!(TransformationType::ALL.len(), 4);
    let mut seen = std::collections::BTreeSet::new();
    for tt in TransformationType::ALL {
        assert!(seen.insert(tt.as_str()));
    }
}

#[test]
fn transformation_type_from_optimization_class_exhaustive() {
    let mappings = [
        (
            OptimizationClass::HostcallDispatchSpecialization,
            TransformationType::HostcallDispatchElision,
            "hostcall_dispatch_elision",
        ),
        (
            OptimizationClass::IfcCheckElision,
            TransformationType::LabelCheckElision,
            "label_check_elision",
        ),
        (
            OptimizationClass::PathElimination,
            TransformationType::PathRemoval,
            "path_removal",
        ),
        (
            OptimizationClass::SuperinstructionFusion,
            TransformationType::SuperinstructionFusion,
            "superinstruction_fusion",
        ),
    ];
    for (class, expected_tt, expected_str) in &mappings {
        let tt = TransformationType::from_optimization_class(*class);
        assert_eq!(tt, *expected_tt);
        assert_eq!(tt.as_str(), *expected_str);
    }
}

#[test]
fn transformation_type_ord_deterministic() {
    let mut types: Vec<TransformationType> = TransformationType::ALL.to_vec();
    types.sort();
    let sorted_strs: Vec<&str> = types.iter().map(|t| t.as_str()).collect();
    // Verify sorting is stable and deterministic
    let mut types2 = types.clone();
    types2.sort();
    let sorted_strs2: Vec<&str> = types2.iter().map(|t| t.as_str()).collect();
    assert_eq!(sorted_strs, sorted_strs2);
}

// ===========================================================================
// Section 2: CorpusCategory — serde, Display, min_count
// ===========================================================================

#[test]
fn corpus_category_serde_all() {
    let cats = [
        CorpusCategory::SemanticParity,
        CorpusCategory::EdgeCase,
        CorpusCategory::EpochTransition,
    ];
    for cat in &cats {
        let json = serde_json::to_string(cat).unwrap();
        let back: CorpusCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

#[test]
fn corpus_category_as_str_matches_display() {
    let cats = [
        CorpusCategory::SemanticParity,
        CorpusCategory::EdgeCase,
        CorpusCategory::EpochTransition,
    ];
    for cat in &cats {
        assert_eq!(cat.as_str(), cat.to_string());
    }
}

#[test]
fn corpus_category_min_count_positive() {
    let cats = [
        CorpusCategory::SemanticParity,
        CorpusCategory::EdgeCase,
        CorpusCategory::EpochTransition,
    ];
    for cat in &cats {
        assert!(cat.min_count() > 0);
    }
}

#[test]
fn corpus_category_semantic_parity_largest_minimum() {
    assert!(CorpusCategory::SemanticParity.min_count() > CorpusCategory::EdgeCase.min_count());
    assert!(CorpusCategory::EdgeCase.min_count() > CorpusCategory::EpochTransition.min_count());
}

// ===========================================================================
// Section 3: ComparisonVerdict — serde, Display, helpers
// ===========================================================================

#[test]
fn comparison_verdict_serde_match() {
    let v = ComparisonVerdict::Match;
    let json = serde_json::to_string(&v).unwrap();
    let back: ComparisonVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
    assert!(back.is_match());
    assert!(!back.is_diverge());
}

#[test]
fn comparison_verdict_serde_diverge() {
    let v = ComparisonVerdict::Diverge;
    let json = serde_json::to_string(&v).unwrap();
    let back: ComparisonVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
    assert!(!back.is_match());
    assert!(back.is_diverge());
}

#[test]
fn comparison_verdict_display_stable() {
    assert_eq!(ComparisonVerdict::Match.to_string(), "match");
    assert_eq!(ComparisonVerdict::Diverge.to_string(), "diverge");
    assert_eq!(ComparisonVerdict::Match.as_str(), "match");
    assert_eq!(ComparisonVerdict::Diverge.as_str(), "diverge");
}

// ===========================================================================
// Section 4: DivergenceKind — serde, Display, ordering
// ===========================================================================

#[test]
fn divergence_kind_serde_all() {
    let kinds = [
        DivergenceKind::ReturnValue,
        DivergenceKind::SideEffectTrace,
        DivergenceKind::ExceptionSequence,
        DivergenceKind::EvidenceEmission,
    ];
    for dk in &kinds {
        let json = serde_json::to_string(dk).unwrap();
        let back: DivergenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*dk, back);
    }
}

#[test]
fn divergence_kind_as_str_matches_display() {
    let kinds = [
        DivergenceKind::ReturnValue,
        DivergenceKind::SideEffectTrace,
        DivergenceKind::ExceptionSequence,
        DivergenceKind::EvidenceEmission,
    ];
    for dk in &kinds {
        assert_eq!(dk.as_str(), dk.to_string());
    }
}

#[test]
fn divergence_kind_all_distinct_strings() {
    let kinds = [
        DivergenceKind::ReturnValue,
        DivergenceKind::SideEffectTrace,
        DivergenceKind::ExceptionSequence,
        DivergenceKind::EvidenceEmission,
    ];
    let strs: std::collections::BTreeSet<&str> = kinds.iter().map(|dk| dk.as_str()).collect();
    assert_eq!(strs.len(), 4);
}

// ===========================================================================
// Section 5: WorkloadOutcome — content_hash, serde
// ===========================================================================

#[test]
fn workload_outcome_content_hash_deterministic() {
    let o1 = ok_outcome("42");
    let o2 = ok_outcome("42");
    assert_eq!(o1.content_hash(), o2.content_hash());
}

#[test]
fn workload_outcome_content_hash_differs_on_return_value() {
    let o1 = ok_outcome("42");
    let o2 = ok_outcome("43");
    assert_ne!(o1.content_hash(), o2.content_hash());
}

#[test]
fn workload_outcome_serde_roundtrip() {
    let o = ok_outcome("test-value");
    let json = serde_json::to_string(&o).unwrap();
    let back: WorkloadOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}

#[test]
fn workload_outcome_empty_fields_serde() {
    let o = WorkloadOutcome {
        return_value: String::new(),
        side_effect_trace: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
    };
    let json = serde_json::to_string(&o).unwrap();
    let back: WorkloadOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
    // Even empty outcome has a content hash
    let _ = o.content_hash();
}

#[test]
fn workload_outcome_with_exceptions_and_evidence() {
    let o = WorkloadOutcome {
        return_value: "ok".to_string(),
        side_effect_trace: vec![],
        exceptions: vec!["TypeError".to_string(), "RangeError".to_string()],
        evidence_entries: vec!["ev-a".to_string(), "ev-b".to_string(), "ev-c".to_string()],
    };
    let json = serde_json::to_string(&o).unwrap();
    let back: WorkloadOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
    assert_ne!(o.content_hash(), ok_outcome("ok").content_hash());
}

// ===========================================================================
// Section 6: SideEffect — serde, Ord
// ===========================================================================

#[test]
fn side_effect_serde_roundtrip() {
    let se = SideEffect {
        effect_type: "hostcall".to_string(),
        description: "log_event".to_string(),
        sequence: 42,
    };
    let json = serde_json::to_string(&se).unwrap();
    let back: SideEffect = serde_json::from_str(&json).unwrap();
    assert_eq!(se, back);
}

#[test]
fn side_effect_ord_by_fields() {
    let se_a = SideEffect {
        effect_type: "a".to_string(),
        description: "x".to_string(),
        sequence: 0,
    };
    let se_b = SideEffect {
        effect_type: "b".to_string(),
        description: "x".to_string(),
        sequence: 0,
    };
    assert!(se_a < se_b);
}

// ===========================================================================
// Section 7: SpecializationWorkload — serde
// ===========================================================================

#[test]
fn specialization_workload_serde_roundtrip() {
    let w = wl("test-w1", CorpusCategory::EdgeCase);
    let json = serde_json::to_string(&w).unwrap();
    let back: SpecializationWorkload = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn specialization_workload_all_categories() {
    for cat in [
        CorpusCategory::SemanticParity,
        CorpusCategory::EdgeCase,
        CorpusCategory::EpochTransition,
    ] {
        let w = wl("cat-test", cat);
        assert_eq!(w.category, cat);
        let json = serde_json::to_string(&w).unwrap();
        let back: SpecializationWorkload = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }
}

// ===========================================================================
// Section 8: SpecializationInventoryEntry — serde
// ===========================================================================

#[test]
fn inventory_entry_serde_roundtrip() {
    let e = inv_entry("rt", epoch(7), TransformationType::PathRemoval);
    let json = serde_json::to_string(&e).unwrap();
    let back: SpecializationInventoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn inventory_entry_all_transformation_types() {
    for tt in TransformationType::ALL {
        let e = inv_entry(&format!("tt-{}", tt.as_str()), epoch(1), *tt);
        assert_eq!(e.transformation_type, *tt);
        let json = serde_json::to_string(&e).unwrap();
        let back: SpecializationInventoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

// ===========================================================================
// Section 9: FallbackOutcome — serde, helpers
// ===========================================================================

#[test]
fn fallback_outcome_success_serde() {
    let fo = FallbackOutcome::Success {
        invalidation_evidence_id: "inv-1".to_string(),
    };
    let json = serde_json::to_string(&fo).unwrap();
    let back: FallbackOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(fo, back);
    assert!(back.is_success());
    assert!(!back.is_failure());
}

#[test]
fn fallback_outcome_failure_serde() {
    let fo = FallbackOutcome::Failure {
        reason: "crash during rollback".to_string(),
    };
    let json = serde_json::to_string(&fo).unwrap();
    let back: FallbackOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(fo, back);
    assert!(!back.is_success());
    assert!(back.is_failure());
}

// ===========================================================================
// Section 10: DifferentialResult — serde
// ===========================================================================

#[test]
fn differential_result_serde_match() {
    let r = DifferentialResult {
        trace_id: "conformance-1".to_string(),
        specialization_id: eid("spec-dr"),
        workload_id: "w-1".to_string(),
        corpus_category: CorpusCategory::SemanticParity,
        outcome: ComparisonVerdict::Match,
        specialized_duration_us: 80,
        unspecialized_duration_us: 100,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
        divergence_detail: None,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DifferentialResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn differential_result_serde_diverge_with_detail() {
    let r = DifferentialResult {
        trace_id: "conformance-2".to_string(),
        specialization_id: eid("spec-div"),
        workload_id: "w-2".to_string(),
        corpus_category: CorpusCategory::EdgeCase,
        outcome: ComparisonVerdict::Diverge,
        specialized_duration_us: 50,
        unspecialized_duration_us: 50,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
        divergence_detail: Some(DivergenceDetail {
            divergence_kind: DivergenceKind::ReturnValue,
            specialized_summary: "42".to_string(),
            unspecialized_summary: "99".to_string(),
        }),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DifferentialResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn differential_result_serde_with_fallback() {
    let r = DifferentialResult {
        trace_id: "conformance-3".to_string(),
        specialization_id: eid("spec-fb"),
        workload_id: "w-3".to_string(),
        corpus_category: CorpusCategory::EpochTransition,
        outcome: ComparisonVerdict::Match,
        specialized_duration_us: 100,
        unspecialized_duration_us: 100,
        epoch_transition_tested: true,
        fallback_outcome: Some(FallbackOutcome::Success {
            invalidation_evidence_id: "inv-99".to_string(),
        }),
        receipt_valid: true,
        divergence_detail: None,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DifferentialResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// Section 11: DivergenceDetail — serde
// ===========================================================================

#[test]
fn divergence_detail_serde_roundtrip() {
    for dk in [
        DivergenceKind::ReturnValue,
        DivergenceKind::SideEffectTrace,
        DivergenceKind::ExceptionSequence,
        DivergenceKind::EvidenceEmission,
    ] {
        let dd = DivergenceDetail {
            divergence_kind: dk,
            specialized_summary: "specialized-val".to_string(),
            unspecialized_summary: "unspecialized-val".to_string(),
        };
        let json = serde_json::to_string(&dd).unwrap();
        let back: DivergenceDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(dd, back);
    }
}

// ===========================================================================
// Section 12: EpochTransitionSimulation — serde
// ===========================================================================

#[test]
fn epoch_transition_simulation_serde() {
    let sim = EpochTransitionSimulation {
        old_epoch: epoch(5),
        new_epoch: epoch(6),
        invalidated_specialization_ids: vec![eid("spec-a"), eid("spec-b")],
        proof_revoked: true,
        transition_timestamp_ns: 1_234_567,
    };
    let json = serde_json::to_string(&sim).unwrap();
    let back: EpochTransitionSimulation = serde_json::from_str(&json).unwrap();
    assert_eq!(sim, back);
}

#[test]
fn epoch_transition_simulation_empty_invalidations() {
    let sim = EpochTransitionSimulation {
        old_epoch: epoch(1),
        new_epoch: epoch(2),
        invalidated_specialization_ids: vec![],
        proof_revoked: false,
        transition_timestamp_ns: 0,
    };
    let json = serde_json::to_string(&sim).unwrap();
    let back: EpochTransitionSimulation = serde_json::from_str(&json).unwrap();
    assert_eq!(sim, back);
}

// ===========================================================================
// Section 13: InvalidationEvidence — serde
// ===========================================================================

#[test]
fn invalidation_evidence_serde_success() {
    let ie = InvalidationEvidence {
        specialization_id: eid("spec-inv"),
        invalidation_reason: "epoch_change".to_string(),
        epoch_old: epoch(5),
        epoch_new: epoch(6),
        rollback_token: ContentHash::compute(b"rollback-token"),
        fallback_outcome: FallbackOutcome::Success {
            invalidation_evidence_id: "inv-42".to_string(),
        },
    };
    let json = serde_json::to_string(&ie).unwrap();
    let back: InvalidationEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ie, back);
}

#[test]
fn invalidation_evidence_serde_failure() {
    let ie = InvalidationEvidence {
        specialization_id: eid("spec-inv-f"),
        invalidation_reason: "proof_revoked".to_string(),
        epoch_old: epoch(3),
        epoch_new: epoch(4),
        rollback_token: ContentHash::compute(b"rb-fail"),
        fallback_outcome: FallbackOutcome::Failure {
            reason: "crash during rollback".to_string(),
        },
    };
    let json = serde_json::to_string(&ie).unwrap();
    let back: InvalidationEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ie, back);
}

// ===========================================================================
// Section 14: ReceiptValidationResult — serde, is_valid
// ===========================================================================

#[test]
fn receipt_validation_result_valid_serde() {
    let rvr = ReceiptValidationResult {
        receipt_id: eid("receipt-ok"),
        well_formed: true,
        equivalence_hash_matches: true,
        rollback_validated: true,
        proof_inputs_consistent: true,
        schema_version:
            frankenengine_engine::proof_specialization_receipt::ReceiptSchemaVersion::CURRENT,
        valid: true,
        failure_reasons: vec![],
    };
    assert!(rvr.is_valid());
    let json = serde_json::to_string(&rvr).unwrap();
    let back: ReceiptValidationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(rvr, back);
    assert!(back.is_valid());
}

#[test]
fn receipt_validation_result_invalid_serde() {
    let rvr = ReceiptValidationResult {
        receipt_id: eid("receipt-bad"),
        well_formed: false,
        equivalence_hash_matches: false,
        rollback_validated: false,
        proof_inputs_consistent: false,
        schema_version:
            frankenengine_engine::proof_specialization_receipt::ReceiptSchemaVersion::CURRENT,
        valid: false,
        failure_reasons: vec![
            "empty proof inputs".to_string(),
            "hash mismatch".to_string(),
        ],
    };
    assert!(!rvr.is_valid());
    let json = serde_json::to_string(&rvr).unwrap();
    let back: ReceiptValidationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(rvr, back);
    assert!(!back.is_valid());
}

// ===========================================================================
// Section 15: PerSpecializationVerdict — serde, helpers
// ===========================================================================

#[test]
fn per_specialization_verdict_passed_serde() {
    let v = PerSpecializationVerdict {
        specialization_id: eid("spec-v1"),
        parity_workloads_run: 30,
        edge_case_workloads_run: 10,
        epoch_transition_workloads_run: 5,
        divergence_count: 0,
        fallback_failures: 0,
        receipt_validation: ReceiptValidationResult {
            receipt_id: eid("r-v1"),
            well_formed: true,
            equivalence_hash_matches: true,
            rollback_validated: true,
            proof_inputs_consistent: true,
            schema_version:
                frankenengine_engine::proof_specialization_receipt::ReceiptSchemaVersion::CURRENT,
            valid: true,
            failure_reasons: vec![],
        },
        passed: true,
    };
    assert!(v.is_passed());
    assert!(v.corpus_coverage_sufficient());
    let json = serde_json::to_string(&v).unwrap();
    let back: PerSpecializationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn per_specialization_verdict_insufficient_coverage() {
    let v = PerSpecializationVerdict {
        specialization_id: eid("spec-v2"),
        parity_workloads_run: 10, // needs 30
        edge_case_workloads_run: 10,
        epoch_transition_workloads_run: 5,
        divergence_count: 0,
        fallback_failures: 0,
        receipt_validation: ReceiptValidationResult {
            receipt_id: eid("r-v2"),
            well_formed: true,
            equivalence_hash_matches: true,
            rollback_validated: true,
            proof_inputs_consistent: true,
            schema_version:
                frankenengine_engine::proof_specialization_receipt::ReceiptSchemaVersion::CURRENT,
            valid: true,
            failure_reasons: vec![],
        },
        passed: true,
    };
    assert!(!v.corpus_coverage_sufficient());
}

#[test]
fn per_specialization_verdict_edge_case_insufficient() {
    let v = PerSpecializationVerdict {
        specialization_id: eid("spec-v3"),
        parity_workloads_run: 30,
        edge_case_workloads_run: 5, // needs 10
        epoch_transition_workloads_run: 5,
        divergence_count: 0,
        fallback_failures: 0,
        receipt_validation: ReceiptValidationResult {
            receipt_id: eid("r-v3"),
            well_formed: true,
            equivalence_hash_matches: true,
            rollback_validated: true,
            proof_inputs_consistent: true,
            schema_version:
                frankenengine_engine::proof_specialization_receipt::ReceiptSchemaVersion::CURRENT,
            valid: true,
            failure_reasons: vec![],
        },
        passed: true,
    };
    assert!(!v.corpus_coverage_sufficient());
}

#[test]
fn per_specialization_verdict_epoch_insufficient() {
    let v = PerSpecializationVerdict {
        specialization_id: eid("spec-v4"),
        parity_workloads_run: 30,
        edge_case_workloads_run: 10,
        epoch_transition_workloads_run: 2, // needs 5
        divergence_count: 0,
        fallback_failures: 0,
        receipt_validation: ReceiptValidationResult {
            receipt_id: eid("r-v4"),
            well_formed: true,
            equivalence_hash_matches: true,
            rollback_validated: true,
            proof_inputs_consistent: true,
            schema_version:
                frankenengine_engine::proof_specialization_receipt::ReceiptSchemaVersion::CURRENT,
            valid: true,
            failure_reasons: vec![],
        },
        passed: true,
    };
    assert!(!v.corpus_coverage_sufficient());
}

// ===========================================================================
// Section 16: ConformanceEvidenceArtifact — serde, helpers, to_jsonl
// ===========================================================================

#[test]
fn conformance_evidence_artifact_serde() {
    let ep = epoch(5);
    let engine = SpecializationConformanceEngine::new("policy-serde", ep);
    let artifact = engine.produce_evidence(
        "serde-run",
        ContentHash::compute(b"reg"),
        "test-env",
        1_000_000,
    );
    let json = serde_json::to_string(&artifact).unwrap();
    let back: ConformanceEvidenceArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn conformance_evidence_artifact_to_jsonl_matches_serde() {
    let ep = epoch(5);
    let engine = SpecializationConformanceEngine::new("policy-jsonl", ep);
    let artifact = engine.produce_evidence(
        "jsonl-run",
        ContentHash::compute(b"reg"),
        "test-env",
        2_000_000,
    );
    let jsonl = artifact.to_jsonl();
    let from_to_string = serde_json::to_string(&artifact).unwrap();
    assert_eq!(jsonl, from_to_string);
}

#[test]
fn conformance_evidence_artifact_is_passed() {
    let ep = epoch(5);
    let engine = SpecializationConformanceEngine::new("policy-pass", ep);
    let artifact = engine.produce_evidence("pass-run", ContentHash::compute(b"r"), "env", 0);
    assert!(artifact.is_passed());
    assert_eq!(artifact.failed_specialization_count(), 0);
}

#[test]
fn conformance_evidence_artifact_failed_count() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("policy-fc", ep);
    let entry = inv_entry("fc", ep, TransformationType::HostcallDispatchElision);
    let spec_id = entry.specialization_id.clone();
    engine.register_specialization(entry);

    // Create a divergence
    let o1 = ok_outcome("a");
    let o2 = ok_outcome("b");
    engine.compare_outcomes(&compare_input(
        &spec_id,
        "w1",
        CorpusCategory::SemanticParity,
        &o1,
        &o2,
    ));

    let artifact = engine.produce_evidence("fc-run", ContentHash::compute(b"r"), "env", 0);
    assert!(!artifact.is_passed());
    assert_eq!(artifact.failed_specialization_count(), 1);
}

// ===========================================================================
// Section 17: ConformanceLog — serde
// ===========================================================================

#[test]
fn conformance_log_serde_roundtrip() {
    let log = ConformanceLog {
        trace_id: "conformance-1".to_string(),
        specialization_id: "spec-123".to_string(),
        workload_id: "w-1".to_string(),
        corpus_category: CorpusCategory::SemanticParity,
        outcome: ComparisonVerdict::Match,
        specialized_duration_us: 80,
        unspecialized_duration_us: 100,
        epoch_transition_tested: false,
        fallback_outcome: Some("not_tested".to_string()),
        receipt_valid: true,
    };
    let json = serde_json::to_string(&log).unwrap();
    let back: ConformanceLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log, back);
}

// ===========================================================================
// Section 18: ConformanceError — serde, Display
// ===========================================================================

#[test]
fn conformance_error_insufficient_corpus_serde() {
    let err = ConformanceError::InsufficientCorpus {
        specialization_id: "spec-1".to_string(),
        category: CorpusCategory::SemanticParity,
        required: 30,
        found: 5,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ConformanceError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
    let display = format!("{err}");
    assert!(display.contains("insufficient corpus"));
    assert!(display.contains("30"));
    assert!(display.contains("5"));
}

#[test]
fn conformance_error_specialization_not_found_serde() {
    let err = ConformanceError::SpecializationNotFound {
        specialization_id: "spec-missing".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ConformanceError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
    let display = format!("{err}");
    assert!(display.contains("not found"));
}

#[test]
fn conformance_error_receipt_invalid_serde() {
    let err = ConformanceError::ReceiptInvalid {
        receipt_id: "rcpt-bad".to_string(),
        reasons: vec!["hash mismatch".to_string(), "epoch wrong".to_string()],
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ConformanceError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
    let display = format!("{err}");
    assert!(display.contains("receipt invalid"));
    assert!(display.contains("hash mismatch"));
    assert!(display.contains("epoch wrong"));
}

#[test]
fn conformance_error_missing_corpus_serde() {
    let err = ConformanceError::MissingCorpus {
        specialization_id: "spec-no-corpus".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ConformanceError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
    let display = format!("{err}");
    assert!(display.contains("missing test corpus"));
}

#[test]
fn conformance_error_execution_error_serde() {
    let err = ConformanceError::ExecutionError {
        message: "timeout".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ConformanceError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
    let display = format!("{err}");
    assert!(display.contains("execution error"));
    assert!(display.contains("timeout"));
}

// ===========================================================================
// Section 19: PerformanceDelta — serde, edge cases
// ===========================================================================

#[test]
fn performance_delta_serde() {
    let pd = SpecializationConformanceEngine::compute_performance_delta(80, 100);
    let json = serde_json::to_string(&pd).unwrap();
    let back: PerformanceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(pd, back);
}

#[test]
fn performance_delta_zero_baseline() {
    let pd = SpecializationConformanceEngine::compute_performance_delta(80, 0);
    assert_eq!(pd.speedup_millionths, 0);
}

#[test]
fn performance_delta_equal_durations() {
    let pd = SpecializationConformanceEngine::compute_performance_delta(100, 100);
    assert_eq!(pd.speedup_millionths, 0);
}

#[test]
fn performance_delta_slowdown() {
    let pd = SpecializationConformanceEngine::compute_performance_delta(200, 100);
    assert!(pd.speedup_millionths < 0);
    assert_eq!(pd.speedup_millionths, -1_000_000); // 100% slower
}

#[test]
fn performance_delta_50_percent_speedup() {
    let pd = SpecializationConformanceEngine::compute_performance_delta(50, 100);
    assert_eq!(pd.speedup_millionths, 500_000); // 50% speedup
}

#[test]
fn performance_delta_large_values() {
    // No overflow with large u64 values thanks to i128 intermediate
    let pd =
        SpecializationConformanceEngine::compute_performance_delta(1_000_000_000, 2_000_000_000);
    // 50% speedup
    assert_eq!(pd.speedup_millionths, 500_000);
}

// ===========================================================================
// Section 20: Engine — accessor coverage
// ===========================================================================

#[test]
fn engine_new_defaults() {
    let ep = epoch(7);
    let engine = SpecializationConformanceEngine::new("test-policy", ep);
    assert_eq!(engine.policy_id(), "test-policy");
    assert_eq!(engine.current_epoch(), ep);
    assert!(engine.inventory().is_empty());
    assert!(engine.results().is_empty());
    assert!(engine.logs().is_empty());
    assert!(engine.errors().is_empty());
    assert_eq!(engine.specialization_count(), 0);
    assert_eq!(engine.total_workloads_run(), 0);
    assert_eq!(engine.total_divergences(), 0);
    assert_eq!(engine.total_matches(), 0);
}

#[test]
fn engine_register_specialization_and_count() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);
    engine.register_specialization(inv_entry("a", ep, TransformationType::PathRemoval));
    assert_eq!(engine.specialization_count(), 1);
    engine.register_specialization(inv_entry("b", ep, TransformationType::LabelCheckElision));
    assert_eq!(engine.specialization_count(), 2);
}

#[test]
fn engine_register_corpus_and_validate() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);
    engine.register_corpus("k1", full_corpus("k1"));
    let errors = engine.validate_corpus("k1");
    assert!(errors.is_empty(), "full corpus should pass: {errors:?}");
}

// ===========================================================================
// Section 21: Engine — compare_outcomes log fields
// ===========================================================================

#[test]
fn engine_compare_outcomes_log_trace_id_increments() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);
    let spec_id = eid("spec-log-inc");
    let o = ok_outcome("42");

    for i in 0..3 {
        engine.compare_outcomes(&compare_input(
            &spec_id,
            &format!("w{i}"),
            CorpusCategory::SemanticParity,
            &o,
            &o,
        ));
    }

    let logs = engine.logs();
    assert_eq!(logs.len(), 3);
    assert_eq!(logs[0].trace_id, "conformance-1");
    assert_eq!(logs[1].trace_id, "conformance-2");
    assert_eq!(logs[2].trace_id, "conformance-3");
}

#[test]
fn engine_compare_outcomes_fallback_log_format() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);
    let spec_id = eid("spec-fb-log");
    let o = ok_outcome("42");

    // No fallback
    engine.compare_outcomes(&compare_input(
        &spec_id,
        "w1",
        CorpusCategory::SemanticParity,
        &o,
        &o,
    ));

    // Success fallback
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "w2",
        category: CorpusCategory::EpochTransition,
        specialized: &o,
        unspecialized: &o,
        specialized_duration_us: 100,
        unspecialized_duration_us: 100,
        epoch_transition_tested: true,
        fallback_outcome: Some(FallbackOutcome::Success {
            invalidation_evidence_id: "inv-1".to_string(),
        }),
        receipt_valid: true,
    });

    // Failure fallback
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "w3",
        category: CorpusCategory::EpochTransition,
        specialized: &o,
        unspecialized: &o,
        specialized_duration_us: 100,
        unspecialized_duration_us: 100,
        epoch_transition_tested: true,
        fallback_outcome: Some(FallbackOutcome::Failure {
            reason: "crash".to_string(),
        }),
        receipt_valid: true,
    });

    let logs = engine.logs();
    assert_eq!(logs[0].fallback_outcome.as_deref(), Some("not_tested"));
    assert_eq!(logs[1].fallback_outcome.as_deref(), Some("success"));
    assert_eq!(logs[2].fallback_outcome.as_deref(), Some("failure:crash"));
}

// ===========================================================================
// Section 22: Engine — receipt invalid flag propagates
// ===========================================================================

#[test]
fn engine_receipt_invalid_flag_propagates_to_gate() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);
    let entry = inv_entry("ri", ep, TransformationType::HostcallDispatchElision);
    let spec_id = entry.specialization_id.clone();
    engine.register_specialization(entry);

    let o = ok_outcome("42");
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "w1",
        category: CorpusCategory::SemanticParity,
        specialized: &o,
        unspecialized: &o,
        specialized_duration_us: 80,
        unspecialized_duration_us: 100,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: false, // invalid receipt
    });

    let artifact = engine.produce_evidence("ri-run", ContentHash::compute(b"r"), "env", 0);
    assert!(!artifact.ci_gate_passed);
    assert_eq!(artifact.total_receipt_failures, 1);
}

// ===========================================================================
// Section 23: Engine — epoch transition proof_revoked
// ===========================================================================

#[test]
fn engine_epoch_transition_proof_revoked_reason() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);
    let entry = inv_entry("pr", ep, TransformationType::PathRemoval);
    let spec_id = entry.specialization_id.clone();
    engine.register_specialization(entry);

    let evidence = engine.simulate_epoch_transition(&EpochTransitionSimulation {
        old_epoch: epoch(5),
        new_epoch: epoch(6),
        invalidated_specialization_ids: vec![spec_id.clone()],
        proof_revoked: true,
        transition_timestamp_ns: 999,
    });

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].invalidation_reason, "proof_revoked");
    assert_eq!(evidence[0].epoch_old, epoch(5));
    assert_eq!(evidence[0].epoch_new, epoch(6));
    assert!(evidence[0].fallback_outcome.is_success());
}

#[test]
fn engine_epoch_transition_not_revoked_reason() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);
    let entry = inv_entry("nr", ep, TransformationType::LabelCheckElision);
    let spec_id = entry.specialization_id.clone();
    engine.register_specialization(entry);

    let evidence = engine.simulate_epoch_transition(&EpochTransitionSimulation {
        old_epoch: epoch(5),
        new_epoch: epoch(6),
        invalidated_specialization_ids: vec![spec_id],
        proof_revoked: false,
        transition_timestamp_ns: 999,
    });

    assert_eq!(evidence[0].invalidation_reason, "epoch_change");
}

// ===========================================================================
// Section 24: Engine — epoch transition unknown spec
// ===========================================================================

#[test]
fn engine_epoch_transition_unknown_spec_fails_fallback() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);

    let unknown_id = eid("spec-unknown");
    let evidence = engine.simulate_epoch_transition(&EpochTransitionSimulation {
        old_epoch: epoch(5),
        new_epoch: epoch(6),
        invalidated_specialization_ids: vec![unknown_id],
        proof_revoked: false,
        transition_timestamp_ns: 999,
    });

    assert_eq!(evidence.len(), 1);
    assert!(evidence[0].fallback_outcome.is_failure());
}

// ===========================================================================
// Section 25: Engine — corpus validation missing corpus
// ===========================================================================

#[test]
fn engine_validate_corpus_missing_returns_error() {
    let ep = epoch(5);
    let engine = SpecializationConformanceEngine::new("p", ep);
    let errors = engine.validate_corpus("nonexistent");
    assert_eq!(errors.len(), 1);
    assert!(matches!(&errors[0], ConformanceError::MissingCorpus { .. }));
}

#[test]
fn engine_validate_corpus_partial_categories() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);

    // Only parity workloads, no edge or epoch
    let corpus: Vec<_> = (0..30)
        .map(|i| wl(&format!("p{i}"), CorpusCategory::SemanticParity))
        .collect();
    engine.register_corpus("partial", corpus);

    let errors = engine.validate_corpus("partial");
    assert_eq!(errors.len(), 2); // missing edge and epoch
    assert!(errors.iter().any(|e| matches!(
        e,
        ConformanceError::InsufficientCorpus {
            category: CorpusCategory::EdgeCase,
            ..
        }
    )));
    assert!(errors.iter().any(|e| matches!(
        e,
        ConformanceError::InsufficientCorpus {
            category: CorpusCategory::EpochTransition,
            ..
        }
    )));
}

// ===========================================================================
// Section 26: Engine — registry sync multiple missing
// ===========================================================================

#[test]
fn engine_registry_sync_multiple_missing() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);
    engine.register_specialization(inv_entry(
        "a",
        ep,
        TransformationType::HostcallDispatchElision,
    ));
    engine.register_specialization(inv_entry("b", ep, TransformationType::LabelCheckElision));
    engine.register_specialization(inv_entry("c", ep, TransformationType::PathRemoval));

    // Only register corpus for "a"
    let key_a = format!(
        "{}",
        inv_entry("a", ep, TransformationType::HostcallDispatchElision).specialization_id
    );
    engine.register_corpus(&key_a, full_corpus("a"));

    let errors = engine.check_registry_sync();
    assert_eq!(errors.len(), 2);
    assert!(
        errors
            .iter()
            .all(|e| matches!(e, ConformanceError::MissingCorpus { .. }))
    );
}

// ===========================================================================
// Section 27: Engine — determinism check edge cases
// ===========================================================================

#[test]
fn engine_determinism_check_single_outcome() {
    assert!(SpecializationConformanceEngine::check_determinism(&[
        ok_outcome("42")
    ]));
}

#[test]
fn engine_determinism_check_empty() {
    assert!(SpecializationConformanceEngine::check_determinism(&[]));
}

#[test]
fn engine_determinism_check_two_identical() {
    assert!(SpecializationConformanceEngine::check_determinism(&[
        ok_outcome("42"),
        ok_outcome("42"),
    ]));
}

#[test]
fn engine_determinism_check_two_different() {
    assert!(!SpecializationConformanceEngine::check_determinism(&[
        ok_outcome("42"),
        ok_outcome("43"),
    ]));
}

// ===========================================================================
// Section 28: Engine — produce_evidence with mixed pass/fail specs
// ===========================================================================

#[test]
fn engine_produce_evidence_mixed_specs() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p-mixed", ep);

    let entry_ok = inv_entry("ok", ep, TransformationType::PathRemoval);
    let spec_ok = entry_ok.specialization_id.clone();
    engine.register_specialization(entry_ok);

    let entry_bad = inv_entry("bad", ep, TransformationType::SuperinstructionFusion);
    let spec_bad = entry_bad.specialization_id.clone();
    engine.register_specialization(entry_bad);

    let o = ok_outcome("42");
    let o_diff = ok_outcome("99");

    // OK spec — matching
    engine.compare_outcomes(&compare_input(
        &spec_ok,
        "w1",
        CorpusCategory::SemanticParity,
        &o,
        &o,
    ));

    // BAD spec — diverging
    engine.compare_outcomes(&compare_input(
        &spec_bad,
        "w2",
        CorpusCategory::SemanticParity,
        &o,
        &o_diff,
    ));

    let artifact = engine.produce_evidence("mixed-run", ContentHash::compute(b"r"), "env", 0);
    assert!(!artifact.ci_gate_passed);
    assert_eq!(artifact.total_specializations, 2);
    assert_eq!(artifact.total_workloads, 2);
    assert_eq!(artifact.total_divergences, 1);
    assert_eq!(artifact.failed_specialization_count(), 1);

    // Verify verdicts
    let passed_verdicts: Vec<_> = artifact.verdicts.iter().filter(|v| v.passed).collect();
    let failed_verdicts: Vec<_> = artifact.verdicts.iter().filter(|v| !v.passed).collect();
    assert_eq!(passed_verdicts.len(), 1);
    assert_eq!(failed_verdicts.len(), 1);
}

// ===========================================================================
// Section 29: Engine — all 4 corpus categories in produce_evidence
// ===========================================================================

#[test]
fn engine_produce_evidence_category_counts() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p-cats", ep);
    let entry = inv_entry("cats", ep, TransformationType::HostcallDispatchElision);
    let spec_id = entry.specialization_id.clone();
    engine.register_specialization(entry);

    let o = ok_outcome("42");

    // 3 parity, 2 edge, 1 epoch
    for i in 0..3 {
        engine.compare_outcomes(&compare_input(
            &spec_id,
            &format!("p{i}"),
            CorpusCategory::SemanticParity,
            &o,
            &o,
        ));
    }
    for i in 0..2 {
        engine.compare_outcomes(&compare_input(
            &spec_id,
            &format!("e{i}"),
            CorpusCategory::EdgeCase,
            &o,
            &o,
        ));
    }
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec_id,
        workload_id: "t0",
        category: CorpusCategory::EpochTransition,
        specialized: &o,
        unspecialized: &o,
        specialized_duration_us: 100,
        unspecialized_duration_us: 100,
        epoch_transition_tested: true,
        fallback_outcome: Some(FallbackOutcome::Success {
            invalidation_evidence_id: "inv-1".to_string(),
        }),
        receipt_valid: true,
    });

    let artifact = engine.produce_evidence("cat-run", ContentHash::compute(b"r"), "env", 0);
    assert_eq!(artifact.total_workloads, 6);

    let verdict = &artifact.verdicts[0];
    assert_eq!(verdict.parity_workloads_run, 3);
    assert_eq!(verdict.edge_case_workloads_run, 2);
    assert_eq!(verdict.epoch_transition_workloads_run, 1);
}

// ===========================================================================
// Section 30: JSON field name stability
// ===========================================================================

#[test]
fn json_field_names_transformation_type() {
    let json = serde_json::to_value(TransformationType::HostcallDispatchElision).unwrap();
    // Enum serializes as string
    assert!(json.is_string());
}

#[test]
fn json_field_names_workload_outcome() {
    let o = ok_outcome("42");
    let json = serde_json::to_value(&o).unwrap();
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("return_value"));
    assert!(obj.contains_key("side_effect_trace"));
    assert!(obj.contains_key("exceptions"));
    assert!(obj.contains_key("evidence_entries"));
}

#[test]
fn json_field_names_side_effect() {
    let se = SideEffect {
        effect_type: "hostcall".to_string(),
        description: "x".to_string(),
        sequence: 0,
    };
    let json = serde_json::to_value(&se).unwrap();
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("effect_type"));
    assert!(obj.contains_key("description"));
    assert!(obj.contains_key("sequence"));
}

#[test]
fn json_field_names_differential_result() {
    let r = DifferentialResult {
        trace_id: "t-1".to_string(),
        specialization_id: eid("spec-jfn"),
        workload_id: "w-1".to_string(),
        corpus_category: CorpusCategory::SemanticParity,
        outcome: ComparisonVerdict::Match,
        specialized_duration_us: 80,
        unspecialized_duration_us: 100,
        epoch_transition_tested: false,
        fallback_outcome: None,
        receipt_valid: true,
        divergence_detail: None,
    };
    let json = serde_json::to_value(&r).unwrap();
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("trace_id"));
    assert!(obj.contains_key("specialization_id"));
    assert!(obj.contains_key("workload_id"));
    assert!(obj.contains_key("corpus_category"));
    assert!(obj.contains_key("outcome"));
    assert!(obj.contains_key("specialized_duration_us"));
    assert!(obj.contains_key("unspecialized_duration_us"));
    assert!(obj.contains_key("epoch_transition_tested"));
    assert!(obj.contains_key("receipt_valid"));
}

#[test]
fn json_field_names_evidence_artifact() {
    let ep = epoch(5);
    let engine = SpecializationConformanceEngine::new("p", ep);
    let artifact = engine.produce_evidence("r", ContentHash::compute(b"x"), "e", 0);
    let json = serde_json::to_value(&artifact).unwrap();
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("run_id"));
    assert!(obj.contains_key("policy_id"));
    assert!(obj.contains_key("epoch"));
    assert!(obj.contains_key("verdicts"));
    assert!(obj.contains_key("total_specializations"));
    assert!(obj.contains_key("total_workloads"));
    assert!(obj.contains_key("total_divergences"));
    assert!(obj.contains_key("total_fallback_failures"));
    assert!(obj.contains_key("total_receipt_failures"));
    assert!(obj.contains_key("registry_hash"));
    assert!(obj.contains_key("environment_fingerprint"));
    assert!(obj.contains_key("ci_gate_passed"));
    assert!(obj.contains_key("timestamp_ns"));
}

// ===========================================================================
// Section 31: Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_transformation_types() {
    let debugs: std::collections::BTreeSet<String> = TransformationType::ALL
        .iter()
        .map(|t| format!("{t:?}"))
        .collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn debug_distinct_divergence_kinds() {
    let kinds = [
        DivergenceKind::ReturnValue,
        DivergenceKind::SideEffectTrace,
        DivergenceKind::ExceptionSequence,
        DivergenceKind::EvidenceEmission,
    ];
    let debugs: std::collections::BTreeSet<String> =
        kinds.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn debug_distinct_comparison_verdicts() {
    let verdicts = [ComparisonVerdict::Match, ComparisonVerdict::Diverge];
    let debugs: std::collections::BTreeSet<String> =
        verdicts.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 2);
}

#[test]
fn debug_distinct_corpus_categories() {
    let cats = [
        CorpusCategory::SemanticParity,
        CorpusCategory::EdgeCase,
        CorpusCategory::EpochTransition,
    ];
    let debugs: std::collections::BTreeSet<String> =
        cats.iter().map(|c| format!("{c:?}")).collect();
    assert_eq!(debugs.len(), 3);
}

// ===========================================================================
// Section 32: End-to-end pipeline with all transformation types
// ===========================================================================

#[test]
fn e2e_all_transformation_types_pass() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p-all-tt", ep);
    let o = ok_outcome("42");

    for tt in TransformationType::ALL {
        let tag = tt.as_str();
        let entry = inv_entry(tag, ep, *tt);
        let spec_id = entry.specialization_id.clone();
        engine.register_specialization(entry);

        for i in 0..3 {
            engine.compare_outcomes(&compare_input(
                &spec_id,
                &format!("{tag}-w{i}"),
                CorpusCategory::SemanticParity,
                &o,
                &o,
            ));
        }
    }

    assert_eq!(engine.specialization_count(), 4);
    assert_eq!(engine.total_workloads_run(), 12);
    assert_eq!(engine.total_matches(), 12);
    assert_eq!(engine.total_divergences(), 0);

    let artifact = engine.produce_evidence("all-tt", ContentHash::compute(b"r"), "env", 0);
    assert!(artifact.ci_gate_passed);
    assert_eq!(artifact.total_specializations, 4);
}

// ===========================================================================
// Section 33: Multiple epochs with re-registration
// ===========================================================================

#[test]
fn e2e_three_epoch_progression() {
    let mut engine = SpecializationConformanceEngine::new("p-3ep", epoch(1));
    let o = ok_outcome("42");

    // Epoch 1: register and run
    let entry1 = inv_entry("e1", epoch(1), TransformationType::PathRemoval);
    let spec1 = entry1.specialization_id.clone();
    engine.register_specialization(entry1);
    engine.compare_outcomes(&compare_input(
        &spec1,
        "w1",
        CorpusCategory::SemanticParity,
        &o,
        &o,
    ));

    // Transition 1→2
    let ev1 = engine.simulate_epoch_transition(&EpochTransitionSimulation {
        old_epoch: epoch(1),
        new_epoch: epoch(2),
        invalidated_specialization_ids: vec![spec1.clone()],
        proof_revoked: false,
        transition_timestamp_ns: 100,
    });
    assert_eq!(ev1.len(), 1);
    assert!(ev1[0].fallback_outcome.is_success());
    assert_eq!(engine.current_epoch(), epoch(2));

    // Epoch 2: run more workloads
    engine.compare_outcomes(&CompareOutcomesInput {
        specialization_id: &spec1,
        workload_id: "w2",
        category: CorpusCategory::EpochTransition,
        specialized: &o,
        unspecialized: &o,
        specialized_duration_us: 100,
        unspecialized_duration_us: 100,
        epoch_transition_tested: true,
        fallback_outcome: Some(FallbackOutcome::Success {
            invalidation_evidence_id: "inv-1".to_string(),
        }),
        receipt_valid: true,
    });

    // Transition 2→3
    let ev2 = engine.simulate_epoch_transition(&EpochTransitionSimulation {
        old_epoch: epoch(2),
        new_epoch: epoch(3),
        invalidated_specialization_ids: vec![],
        proof_revoked: false,
        transition_timestamp_ns: 200,
    });
    assert!(ev2.is_empty());
    assert_eq!(engine.current_epoch(), epoch(3));

    let artifact = engine.produce_evidence("3ep", ContentHash::compute(b"r"), "env", 300);
    assert!(artifact.ci_gate_passed);
    assert_eq!(artifact.epoch, epoch(3));
    assert_eq!(artifact.total_workloads, 2);
}

// ===========================================================================
// Section 34: Overwrite specialization in inventory
// ===========================================================================

#[test]
fn engine_register_specialization_overwrites() {
    let ep = epoch(5);
    let mut engine = SpecializationConformanceEngine::new("p", ep);
    let entry_a = inv_entry("ow", ep, TransformationType::PathRemoval);
    let key = format!("{}", entry_a.specialization_id);
    engine.register_specialization(entry_a);
    assert_eq!(
        engine.inventory().get(&key).unwrap().transformation_type,
        TransformationType::PathRemoval
    );

    // Re-register with different transformation type
    let mut entry_b = inv_entry("ow", ep, TransformationType::SuperinstructionFusion);
    // Force same specialization_id
    entry_b.specialization_id = engine
        .inventory()
        .get(&key)
        .unwrap()
        .specialization_id
        .clone();
    engine.register_specialization(entry_b);
    assert_eq!(
        engine.inventory().get(&key).unwrap().transformation_type,
        TransformationType::SuperinstructionFusion
    );
    assert_eq!(engine.specialization_count(), 1);
}

// ===========================================================================
// Section 35: Epoch transition epoch mismatch produces failure
// ===========================================================================

#[test]
fn engine_epoch_transition_entry_epoch_mismatch() {
    let mut engine = SpecializationConformanceEngine::new("p", epoch(5));
    // Register entry with validity_epoch = 5
    let entry = inv_entry("em", epoch(5), TransformationType::LabelCheckElision);
    let spec_id = entry.specialization_id.clone();
    engine.register_specialization(entry);

    // Simulate transition from epoch 3 (not 5)
    let evidence = engine.simulate_epoch_transition(&EpochTransitionSimulation {
        old_epoch: epoch(3), // mismatch: entry has epoch 5
        new_epoch: epoch(4),
        invalidated_specialization_ids: vec![spec_id],
        proof_revoked: false,
        transition_timestamp_ns: 999,
    });

    assert_eq!(evidence.len(), 1);
    assert!(evidence[0].fallback_outcome.is_failure());
}
