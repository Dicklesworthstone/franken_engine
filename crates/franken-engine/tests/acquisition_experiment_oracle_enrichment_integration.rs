//! Enrichment integration tests for `acquisition_experiment_oracle`.
//!
//! Covers: ExperimentKind Display/serde, AcquisitionSignal Display/serde,
//! ExperimentProposal lifecycle, AcquisitionScore, ExperimentPlan,
//! ExperimentOutcome, OracleCalibration, AcquisitionError Display,
//! score_proposal, rank_proposals, select_experiments, record_outcome,
//! calibrate_oracle, and deterministic content hashing.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::acquisition_experiment_oracle::{
    AcquisitionError, AcquisitionSignal, BEAD_ID, COMPONENT, ExperimentKind, ExperimentProposal,
    MILLIONTHS, POLICY_ID, SCHEMA_VERSION, calibrate_oracle, franken_engine_acquisition_manifest,
    rank_proposals, record_outcome, score_proposal, select_experiments,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn make_proposal(
    id: &str,
    kind: ExperimentKind,
    signal: AcquisitionSignal,
    strength: u64,
    gain: u64,
    cost: u64,
) -> ExperimentProposal {
    ExperimentProposal::new(
        id.to_string(),
        kind,
        format!("cell-{id}"),
        vec![(signal, strength)],
        gain,
        300_000,
        cost,
        format!("test proposal {id}"),
    )
}

fn default_weights() -> BTreeMap<String, u64> {
    BTreeMap::new()
}

// ===========================================================================
// ExperimentKind Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_experiment_kind_display_all_unique() {
    let displays: BTreeSet<String> = ExperimentKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), ExperimentKind::ALL.len());
}

#[test]
fn enrichment_experiment_kind_serde_roundtrip() {
    for kind in ExperimentKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: ExperimentKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn enrichment_experiment_kind_as_str_matches_display() {
    for kind in ExperimentKind::ALL {
        assert_eq!(kind.as_str(), kind.to_string());
    }
}

#[test]
fn enrichment_experiment_kind_all_count() {
    assert_eq!(ExperimentKind::ALL.len(), 7);
}

// ===========================================================================
// AcquisitionSignal Display uniqueness and serde
// ===========================================================================

#[test]
fn enrichment_acquisition_signal_display_all_unique() {
    let displays: BTreeSet<String> = AcquisitionSignal::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), AcquisitionSignal::ALL.len());
}

#[test]
fn enrichment_acquisition_signal_serde_roundtrip() {
    for signal in AcquisitionSignal::ALL {
        let json = serde_json::to_string(signal).unwrap();
        let back: AcquisitionSignal = serde_json::from_str(&json).unwrap();
        assert_eq!(*signal, back);
    }
}

#[test]
fn enrichment_acquisition_signal_as_str_matches_display() {
    for signal in AcquisitionSignal::ALL {
        assert_eq!(signal.as_str(), signal.to_string());
    }
}

#[test]
fn enrichment_acquisition_signal_all_count() {
    assert_eq!(AcquisitionSignal::ALL.len(), 7);
}

// ===========================================================================
// ExperimentProposal lifecycle
// ===========================================================================

#[test]
fn enrichment_proposal_new_seals_content_hash() {
    let p = make_proposal("p1", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 800_000, 500_000, 100_000);
    // Content hash should not be the empty hash
    let empty_hash = frankenengine_engine::hash_tiers::ContentHash::compute(b"");
    assert_ne!(p.content_hash, empty_hash);
}

#[test]
fn enrichment_proposal_deterministic_hash() {
    let p1 = make_proposal("p-det", ExperimentKind::CorpusAddition, AcquisitionSignal::CoverageDebt, 500_000, 400_000, 50_000);
    let p2 = make_proposal("p-det", ExperimentKind::CorpusAddition, AcquisitionSignal::CoverageDebt, 500_000, 400_000, 50_000);
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_proposal_display_contains_id() {
    let p = make_proposal("abc", ExperimentKind::AdversarialProbe, AcquisitionSignal::AdversarialOpportunity, 700_000, 600_000, 100_000);
    let display = p.to_string();
    assert!(display.contains("abc"));
}

#[test]
fn enrichment_proposal_serde_roundtrip() {
    let p = make_proposal("serde", ExperimentKind::HoleFilling, AcquisitionSignal::PersistentHole, 600_000, 400_000, 80_000);
    let json = serde_json::to_string(&p).unwrap();
    let back: ExperimentProposal = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ===========================================================================
// score_proposal
// ===========================================================================

#[test]
fn enrichment_score_proposal_basic() {
    let p = make_proposal("score-test", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 800_000, 500_000, 100_000);
    let score = score_proposal(&p, &default_weights());
    assert!(score.raw_gain_millionths > 0);
    assert!(score.cost_adjusted_millionths > 0);
    assert_eq!(score.proposal_id, "score-test");
}

#[test]
fn enrichment_score_proposal_with_custom_weights() {
    let p = make_proposal("w-test", ExperimentKind::CorpusAddition, AcquisitionSignal::CoverageDebt, 800_000, 500_000, 100_000);
    let mut weights = BTreeMap::new();
    weights.insert("coverage_debt".to_string(), 2_000_000u64); // 2x weight
    let score = score_proposal(&p, &weights);
    let default_score = score_proposal(&p, &default_weights());
    // Weighted score should be different from default
    assert_ne!(score.raw_gain_millionths, default_score.raw_gain_millionths);
}

#[test]
fn enrichment_score_proposal_zero_cost_no_panic() {
    let p = make_proposal("zero-cost", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 500_000, 400_000, 0);
    let score = score_proposal(&p, &default_weights());
    assert!(score.cost_adjusted_millionths > 0);
}

// ===========================================================================
// rank_proposals
// ===========================================================================

#[test]
fn enrichment_rank_proposals_sorted_descending() {
    let proposals = vec![
        make_proposal("low", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 100_000, 50_000, 100_000),
        make_proposal("high", ExperimentKind::CorpusAddition, AcquisitionSignal::CoverageDebt, 900_000, 800_000, 100_000),
    ];
    let ranked = rank_proposals(proposals, &default_weights());
    assert_eq!(ranked.len(), 2);
    assert!(ranked[0].1.cost_adjusted_millionths >= ranked[1].1.cost_adjusted_millionths);
}

#[test]
fn enrichment_rank_proposals_empty() {
    let ranked = rank_proposals(vec![], &default_weights());
    assert!(ranked.is_empty());
}

// ===========================================================================
// select_experiments
// ===========================================================================

#[test]
fn enrichment_select_experiments_basic() {
    let proposals = vec![
        make_proposal("s1", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 800_000, 500_000, 100_000),
        make_proposal("s2", ExperimentKind::CorpusAddition, AcquisitionSignal::CoverageDebt, 600_000, 400_000, 100_000),
    ];
    let plan = select_experiments(proposals, 200_000, &default_weights()).unwrap();
    assert_eq!(plan.proposals.len(), 2);
    assert_eq!(plan.scores.len(), 2);
    assert_eq!(plan.budget_remaining_millionths, 0);
}

#[test]
fn enrichment_select_experiments_budget_limit() {
    let proposals = vec![
        make_proposal("b1", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 800_000, 500_000, 100_000),
        make_proposal("b2", ExperimentKind::CorpusAddition, AcquisitionSignal::CoverageDebt, 600_000, 400_000, 200_000),
    ];
    let plan = select_experiments(proposals, 150_000, &default_weights()).unwrap();
    assert_eq!(plan.proposals.len(), 1);
}

#[test]
fn enrichment_select_experiments_no_candidates_error() {
    let result = select_experiments(vec![], 1_000_000, &default_weights());
    assert!(matches!(result, Err(AcquisitionError::NoCandidates)));
}

#[test]
fn enrichment_select_experiments_budget_exhausted_error() {
    let proposals = vec![
        make_proposal("exp", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 800_000, 500_000, 500_000),
    ];
    let result = select_experiments(proposals, 100, &default_weights());
    assert!(matches!(result, Err(AcquisitionError::BudgetExhausted)));
}

#[test]
fn enrichment_select_experiments_plan_has_content_hash() {
    let proposals = vec![
        make_proposal("h1", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 800_000, 500_000, 100_000),
    ];
    let plan = select_experiments(proposals, 200_000, &default_weights()).unwrap();
    let empty_hash = frankenengine_engine::hash_tiers::ContentHash::compute(b"");
    assert_ne!(plan.content_hash, empty_hash);
}

// ===========================================================================
// record_outcome
// ===========================================================================

#[test]
fn enrichment_record_outcome_exact_prediction() {
    let p = make_proposal("exact", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 800_000, 500_000, 100_000);
    let outcome = record_outcome(&p, 500_000);
    assert_eq!(outcome.actual_information_gain_millionths, 500_000);
    assert_eq!(outcome.surprise_millionths, 0);
    assert_eq!(outcome.regret_millionths, 0);
}

#[test]
fn enrichment_record_outcome_over_prediction() {
    let p = make_proposal("over", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 800_000, 500_000, 100_000);
    let outcome = record_outcome(&p, 200_000);
    assert_eq!(outcome.surprise_millionths, 300_000);
    assert_eq!(outcome.regret_millionths, 300_000);
}

#[test]
fn enrichment_record_outcome_under_prediction() {
    let p = make_proposal("under", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 800_000, 500_000, 100_000);
    let outcome = record_outcome(&p, 800_000);
    assert_eq!(outcome.surprise_millionths, 300_000);
    assert_eq!(outcome.regret_millionths, 0);
}

// ===========================================================================
// calibrate_oracle
// ===========================================================================

#[test]
fn enrichment_calibrate_oracle_perfect_predictions() {
    let proposals = vec![
        make_proposal("c1", ExperimentKind::BoardCellProbe, AcquisitionSignal::LiveShiftPressure, 800_000, 500_000, 100_000),
    ];
    let outcomes = vec![record_outcome(&proposals[0], 500_000)];
    let cal = calibrate_oracle(&outcomes, &proposals);
    assert_eq!(cal.predictions_count, 1);
    assert_eq!(cal.mean_absolute_error_millionths, 0);
    assert_eq!(cal.bias_millionths, 0);
}

#[test]
fn enrichment_calibrate_oracle_over_predicting() {
    let proposals = vec![
        make_proposal("c2", ExperimentKind::CorpusAddition, AcquisitionSignal::CoverageDebt, 600_000, 500_000, 100_000),
    ];
    let outcomes = vec![record_outcome(&proposals[0], 300_000)];
    let cal = calibrate_oracle(&outcomes, &proposals);
    assert_eq!(cal.predictions_count, 1);
    assert_eq!(cal.mean_absolute_error_millionths, 200_000);
    assert!(cal.bias_millionths > 0); // over-prediction => positive bias
}

#[test]
fn enrichment_calibrate_oracle_empty() {
    let cal = calibrate_oracle(&[], &[]);
    assert_eq!(cal.predictions_count, 0);
    assert_eq!(cal.mean_absolute_error_millionths, 0);
    assert_eq!(cal.bias_millionths, 0);
}

// ===========================================================================
// AcquisitionError Display
// ===========================================================================

#[test]
fn enrichment_acquisition_error_display_all_unique() {
    let errors = [
        AcquisitionError::NoCandidates,
        AcquisitionError::BudgetExhausted,
        AcquisitionError::CalibrationDrift,
        AcquisitionError::InvalidSignal,
        AcquisitionError::InternalError("test error".to_string()),
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_acquisition_error_serde_roundtrip() {
    let errors = [
        AcquisitionError::NoCandidates,
        AcquisitionError::BudgetExhausted,
        AcquisitionError::CalibrationDrift,
        AcquisitionError::InvalidSignal,
        AcquisitionError::InternalError("msg".to_string()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: AcquisitionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// Manifest
// ===========================================================================

#[test]
fn enrichment_manifest_plan_covers_all_kinds() {
    let plan = franken_engine_acquisition_manifest();
    assert_eq!(plan.proposals.len(), 7);
    let kinds: BTreeSet<String> = plan.proposals.iter().map(|p| p.kind.to_string()).collect();
    assert_eq!(kinds.len(), 7);
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_constants_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!POLICY_ID.is_empty());
}

#[test]
fn enrichment_millionths_value() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn enrichment_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-706B");
}
