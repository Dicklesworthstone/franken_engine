//! Integration tests for the RGC-613 parent superoptimization gate.
//!
//! Covers deterministic candidate ranking, budget enforcement, proof-failure
//! rejection, stale synthesis invalidation, promotion provenance, rollback, and
//! the required artifact contract for `superoptimization_report.json` bundles.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::budgeted_synthesis_engine::{
    CandidateOrigin, CostEstimate, EquivalenceProof, SynthesisBudget, SynthesisCandidate,
    SynthesisReport,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::superoptimization_gate::*;
use frankenengine_engine::synthesis_eligibility_envelope::{
    KernelSchema, KernelSchemaInput, OperationKind, SynthesisEnvelope,
};
use frankenengine_engine::synthesis_kernel_promotion::{
    PromotionEvidence, PromotionGate, PromotionReport, PromotionTarget,
};

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(613)
}

fn eligible_schema(id: &str) -> KernelSchema {
    let mut operation_counts = BTreeMap::new();
    operation_counts.insert(OperationKind::Arithmetic, 12);
    operation_counts.insert(OperationKind::Load, 4);
    KernelSchema::new(KernelSchemaInput {
        schema_id: id.to_string(),
        operation_counts,
        branch_depth: 1,
        side_effects: BTreeSet::new(),
        input_shape_stability: 980_000,
        output_shape_stability: 980_000,
        input_shape_count: 1,
        output_shape_count: 1,
    })
}

fn envelope_for(schema_id: &str, epoch: SecurityEpoch) -> SynthesisEnvelope {
    let schema = eligible_schema(schema_id);
    let frequencies = BTreeMap::from([(schema_id.to_string(), 100_000)]);
    SynthesisEnvelope::compute(epoch, &[schema], &frequencies)
}

fn candidate(schema_id: &str, candidate_id: &str, speedup: u64) -> SynthesisCandidate {
    SynthesisCandidate::new(
        candidate_id,
        schema_id,
        CandidateOrigin::Enumerative,
        10,
        EquivalenceProof::verified(8, 100_000),
        Vec::new(),
        vec![CostEstimate::new("hw-a", 100_000, 10_000, 1_200_000)],
        speedup,
    )
}

fn synthesis_report(schema_id: &str, candidates: Vec<SynthesisCandidate>) -> SynthesisReport {
    SynthesisReport::new(
        epoch(),
        schema_id,
        SynthesisBudget::custom(8, 1_000_000, 500_000),
        candidates,
    )
}

fn promotion_report(candidate_id: &str) -> PromotionReport {
    let gate = PromotionGate::with_defaults();
    let targets = BTreeSet::from([PromotionTarget::BaselineHotPath]);
    let evidence = PromotionEvidence::verified(980_000, 150_000, 980_000, targets);
    PromotionReport::new(epoch(), vec![gate.evaluate(candidate_id, &evidence)])
}

#[test]
fn deterministic_ranking_prefers_speed_then_smaller_candidate_then_id() {
    let schema_id = "kernel-a";
    let mut same_speed_low_id = candidate(schema_id, "cand-a", 1_100_000);
    same_speed_low_id.op_count = 12;
    let mut same_speed_low_op = candidate(schema_id, "cand-b", 1_100_000);
    same_speed_low_op.op_count = 8;
    let faster = candidate(schema_id, "cand-c", 1_200_000);
    let report = synthesis_report(
        schema_id,
        vec![same_speed_low_id, same_speed_low_op.clone(), faster.clone()],
    );

    let ranked = rank_admissible_candidates(&report);

    assert_eq!(ranked[0].candidate_id, faster.candidate_id);
    assert_eq!(ranked[1].candidate_id, same_speed_low_op.candidate_id);
}

#[test]
fn gate_promotes_proved_and_promoted_candidate_and_lists_required_artifacts() {
    let schema_id = "kernel-a";
    let envelope = envelope_for(schema_id, epoch());
    let synthesis = synthesis_report(schema_id, vec![candidate(schema_id, "cand-a", 1_150_000)]);
    let promotion = promotion_report("cand-a");

    let report = SuperoptimizationGate::with_defaults().evaluate(
        epoch(),
        &envelope,
        &[synthesis],
        &promotion,
    );

    assert_eq!(report.promoted_count, 1);
    assert!(report.all_promoted());
    assert_eq!(
        report.artifact_names(),
        BTreeSet::from([
            COMMANDS_ARTIFACT,
            EVENTS_ARTIFACT,
            RUN_MANIFEST_ARTIFACT,
            SUPEROPTIMIZATION_REPORT_ARTIFACT,
            TRACE_IDS_ARTIFACT,
        ])
    );
    let json = serde_json::to_string(&report).unwrap();
    let decoded: SuperoptimizationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, decoded);
}

#[test]
fn over_budget_synthesis_falls_back_with_rollback_receipt() {
    let schema_id = "kernel-a";
    let envelope = envelope_for(schema_id, epoch());
    let synthesis = SynthesisReport::new(
        epoch(),
        schema_id,
        SynthesisBudget::custom(0, 50_000, 50_000),
        vec![candidate(schema_id, "cand-a", 1_150_000)],
    );
    let promotion = promotion_report("cand-a");

    let report = SuperoptimizationGate::with_defaults().evaluate(
        epoch(),
        &envelope,
        &[synthesis],
        &promotion,
    );

    assert_eq!(report.fallback_count, 1);
    assert!(report.decisions[0].is_fallback());
    assert!(report.decisions[0].rollback_receipt_hash.is_some());
    assert!(matches!(
        report.decisions[0].reasons[0],
        SuperoptimizationReason::BudgetExceeded { .. }
    ));
}

#[test]
fn proof_failure_rejects_candidate_and_rolls_back_to_baseline() {
    let schema_id = "kernel-a";
    let envelope = envelope_for(schema_id, epoch());
    let counterexample = frankenengine_engine::budgeted_synthesis_engine::Counterexample {
        input_class: "int32-array".to_string(),
        expected_output_hash: ContentHash::compute(b"baseline"),
        actual_output_hash: ContentHash::compute(b"candidate"),
        description: "divergent lane".to_string(),
    };
    let bad_candidate = SynthesisCandidate::new(
        "cand-bad",
        schema_id,
        CandidateOrigin::Stochastic,
        8,
        EquivalenceProof::refuted(8, 7, 100_000),
        vec![counterexample],
        Vec::new(),
        1_300_000,
    );
    let synthesis = synthesis_report(schema_id, vec![bad_candidate]);
    let promotion = PromotionReport::new(epoch(), Vec::new());

    let report = SuperoptimizationGate::with_defaults().evaluate(
        epoch(),
        &envelope,
        &[synthesis],
        &promotion,
    );

    assert_eq!(report.fallback_count, 1);
    assert!(matches!(
        report.decisions[0].reasons[0],
        SuperoptimizationReason::ProofFailureRejected { .. }
    ));
}

#[test]
fn stale_synthesis_is_invalidated() {
    let schema_id = "kernel-a";
    let current_epoch = SecurityEpoch::from_raw(700);
    let envelope = envelope_for(schema_id, current_epoch);
    let stale_synthesis = SynthesisReport::new(
        SecurityEpoch::from_raw(699),
        schema_id,
        SynthesisBudget::custom(8, 1_000_000, 500_000),
        vec![candidate(schema_id, "cand-a", 1_150_000)],
    );
    let promotion = promotion_report("cand-a");

    let report = SuperoptimizationGate::with_defaults().evaluate(
        current_epoch,
        &envelope,
        &[stale_synthesis],
        &promotion,
    );

    assert_eq!(report.fallback_count, 1);
    assert!(matches!(
        report.decisions[0].reasons[0],
        SuperoptimizationReason::StaleSynthesis { .. }
    ));
}
