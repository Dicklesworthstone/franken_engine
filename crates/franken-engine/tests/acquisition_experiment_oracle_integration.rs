//! Integration tests for the acquisition experiment oracle (RGC-706B).

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

use std::collections::BTreeMap;

use frankenengine_engine::acquisition_experiment_oracle::{
    self, AcquisitionError, AcquisitionSignal, BEAD_ID, COMPONENT, ExperimentKind,
    ExperimentProposal, MILLIONTHS, POLICY_ID, SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("acquisition"));
}

#[test]
fn test_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component() {
    assert!(!COMPONENT.is_empty());
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-706B");
}

#[test]
fn test_millionths() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// ExperimentKind
// ---------------------------------------------------------------------------

#[test]
fn test_experiment_kind_all() {
    assert_eq!(ExperimentKind::ALL.len(), 7);
}

#[test]
fn test_experiment_kind_as_str() {
    assert_eq!(ExperimentKind::BoardCellProbe.as_str(), "board_cell_probe");
    assert_eq!(
        ExperimentKind::DarkMatterExploration.as_str(),
        "dark_matter_exploration"
    );
}

#[test]
fn test_experiment_kind_display() {
    let s = format!("{}", ExperimentKind::CorpusAddition);
    assert_eq!(s, "corpus_addition");
}

#[test]
fn test_experiment_kind_serde_roundtrip() {
    for kind in ExperimentKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: ExperimentKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// AcquisitionSignal
// ---------------------------------------------------------------------------

#[test]
fn test_acquisition_signal_all() {
    assert_eq!(AcquisitionSignal::ALL.len(), 7);
}

#[test]
fn test_acquisition_signal_as_str() {
    assert_eq!(
        AcquisitionSignal::LiveShiftPressure.as_str(),
        "live_shift_pressure"
    );
    assert_eq!(
        AcquisitionSignal::SemanticDarkMatter.as_str(),
        "semantic_dark_matter"
    );
}

#[test]
fn test_acquisition_signal_serde_roundtrip() {
    for sig in AcquisitionSignal::ALL {
        let json = serde_json::to_string(sig).unwrap();
        let back: AcquisitionSignal = serde_json::from_str(&json).unwrap();
        assert_eq!(*sig, back);
    }
}

// ---------------------------------------------------------------------------
// ExperimentProposal
// ---------------------------------------------------------------------------

#[test]
fn test_proposal_new_seals() {
    let p = make_proposal(
        "p1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    assert!(!p.proposal_id.is_empty());
    // content_hash should be non-trivially set
    assert_ne!(
        p.content_hash,
        frankenengine_engine::hash_tiers::ContentHash::compute(b"")
    );
}

#[test]
fn test_proposal_display() {
    let p = make_proposal(
        "p1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let s = format!("{p}");
    assert!(s.contains("p1"));
}

#[test]
fn test_proposal_serde_roundtrip() {
    let p = make_proposal(
        "p1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let json = serde_json::to_string(&p).unwrap();
    let back: ExperimentProposal = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// score_proposal
// ---------------------------------------------------------------------------

#[test]
fn test_score_proposal_basic() {
    let p = make_proposal(
        "s1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    assert!(score.raw_gain_millionths > 0);
    assert!(score.cost_adjusted_millionths > 0);
    assert_eq!(score.proposal_id, "s1");
}

#[test]
fn test_score_proposal_custom_weights() {
    let p = make_proposal(
        "s2",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let mut weights = BTreeMap::new();
    weights.insert("live_shift_pressure".to_string(), 2_000_000);
    let score = acquisition_experiment_oracle::score_proposal(&p, &weights);
    assert!(score.raw_gain_millionths > 0);
}

// ---------------------------------------------------------------------------
// rank_proposals
// ---------------------------------------------------------------------------

#[test]
fn test_rank_proposals_ordering() {
    let p1 = make_proposal(
        "r1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let p2 = make_proposal(
        "r2",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        200_000,
        100_000,
        100_000,
    );
    let ranked = acquisition_experiment_oracle::rank_proposals(vec![p1, p2], &default_weights());
    assert_eq!(ranked.len(), 2);
    // The higher-gain proposal should be first
    assert!(ranked[0].1.cost_adjusted_millionths >= ranked[1].1.cost_adjusted_millionths);
}

// ---------------------------------------------------------------------------
// select_experiments
// ---------------------------------------------------------------------------

#[test]
fn test_select_experiments_ok() {
    let p1 = make_proposal(
        "e1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p1], 1_000_000, &default_weights())
            .unwrap();
    assert!(!plan.proposals.is_empty());
    assert_eq!(plan.proposals.len(), plan.scores.len());
}

#[test]
fn test_select_experiments_budget_exhausted() {
    let p1 = make_proposal(
        "e2",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        2_000_000,
    );
    let result =
        acquisition_experiment_oracle::select_experiments(vec![p1], 100_000, &default_weights());
    assert!(matches!(result, Err(AcquisitionError::BudgetExhausted)));
}

#[test]
fn test_select_experiments_no_candidates() {
    let result =
        acquisition_experiment_oracle::select_experiments(vec![], 1_000_000, &default_weights());
    assert!(matches!(result, Err(AcquisitionError::NoCandidates)));
}

// ---------------------------------------------------------------------------
// record_outcome
// ---------------------------------------------------------------------------

#[test]
fn test_record_outcome() {
    let p = make_proposal(
        "o1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 600_000);
    assert_eq!(outcome.proposal_id, "o1");
    assert_eq!(outcome.actual_information_gain_millionths, 600_000);
}

// ---------------------------------------------------------------------------
// compute_regret
// ---------------------------------------------------------------------------

#[test]
fn test_compute_regret_positive() {
    assert_eq!(
        acquisition_experiment_oracle::compute_regret(500_000, 300_000),
        200_000
    );
}

#[test]
fn test_compute_regret_zero() {
    assert_eq!(
        acquisition_experiment_oracle::compute_regret(300_000, 500_000),
        0
    );
}

// ---------------------------------------------------------------------------
// calibrate_oracle
// ---------------------------------------------------------------------------

#[test]
fn test_calibrate_oracle_perfect() {
    let p = make_proposal(
        "c1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 500_000);
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[outcome], &[p]);
    assert_eq!(cal.predictions_count, 1);
    assert_eq!(cal.mean_absolute_error_millionths, 0);
    assert_eq!(cal.bias_millionths, 0);
}

// ---------------------------------------------------------------------------
// combine_signal_strengths
// ---------------------------------------------------------------------------

#[test]
fn test_combine_signal_strengths_empty() {
    assert_eq!(
        acquisition_experiment_oracle::combine_signal_strengths(&[]),
        0
    );
}

#[test]
fn test_combine_signal_strengths_single() {
    assert_eq!(
        acquisition_experiment_oracle::combine_signal_strengths(&[500_000]),
        500_000
    );
}

#[test]
fn test_combine_signal_strengths_diminishing() {
    let combined = acquisition_experiment_oracle::combine_signal_strengths(&[1_000_000, 1_000_000]);
    // Second is halved: 1_000_000 + 500_000 = 1_500_000
    assert_eq!(combined, 1_500_000);
}

// ---------------------------------------------------------------------------
// information_density
// ---------------------------------------------------------------------------

#[test]
fn test_information_density() {
    let p = make_proposal(
        "d1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        1_000_000,
        500_000,
    );
    let density = acquisition_experiment_oracle::information_density(&p);
    assert_eq!(density, 2_000_000); // 1M gain / 0.5M cost = 2.0
}

// ---------------------------------------------------------------------------
// is_justified
// ---------------------------------------------------------------------------

#[test]
fn test_is_justified_true() {
    let p = make_proposal(
        "j1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    // threshold of 1.0 => min_gain = cost * 1.0 = 100_000; gain=500_000 >= 100_000
    assert!(acquisition_experiment_oracle::is_justified(&p, 1_000_000));
}

#[test]
fn test_is_justified_false() {
    let p = make_proposal(
        "j2",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        50_000,
        1_000_000,
    );
    // threshold=1.0 => min_gain = 1_000_000; gain=50_000 < 1_000_000
    assert!(!acquisition_experiment_oracle::is_justified(&p, 1_000_000));
}

// ---------------------------------------------------------------------------
// diversity_bonus
// ---------------------------------------------------------------------------

#[test]
fn test_diversity_bonus_single_kind() {
    let p = make_proposal(
        "db1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let bonus = acquisition_experiment_oracle::diversity_bonus(&[p]);
    // 1 kind out of 7 = 1/7 * 1M
    assert!(bonus > 0);
    assert!(bonus < MILLIONTHS);
}

// ---------------------------------------------------------------------------
// staleness_penalty
// ---------------------------------------------------------------------------

#[test]
fn test_staleness_penalty_fresh() {
    assert_eq!(acquisition_experiment_oracle::staleness_penalty(5, 10), 0);
}

#[test]
fn test_staleness_penalty_stale() {
    let penalty = acquisition_experiment_oracle::staleness_penalty(20, 10);
    assert!(penalty > 0);
}

// ---------------------------------------------------------------------------
// exploration_ratio
// ---------------------------------------------------------------------------

#[test]
fn test_exploration_ratio_all_exploit() {
    let p = make_proposal(
        "ex1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let ratio = acquisition_experiment_oracle::exploration_ratio(&[p]);
    assert_eq!(ratio, 0); // BoardCellProbe is exploitation
}

#[test]
fn test_exploration_ratio_all_explore() {
    let p = make_proposal(
        "ex2",
        ExperimentKind::DarkMatterExploration,
        AcquisitionSignal::SemanticDarkMatter,
        500_000,
        500_000,
        100_000,
    );
    let ratio = acquisition_experiment_oracle::exploration_ratio(&[p]);
    assert_eq!(ratio, MILLIONTHS); // 100% exploration
}

// ---------------------------------------------------------------------------
// validate_plan
// ---------------------------------------------------------------------------

#[test]
fn test_validate_plan_valid() {
    let p = make_proposal(
        "v1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights())
            .unwrap();
    let errors = acquisition_experiment_oracle::validate_plan(&plan);
    assert!(errors.is_empty());
}

// ---------------------------------------------------------------------------
// summarise_plan
// ---------------------------------------------------------------------------

#[test]
fn test_summarise_plan() {
    let p = make_proposal(
        "sum1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights())
            .unwrap();
    let summary = acquisition_experiment_oracle::summarise_plan(&plan);
    assert!(summary.contains("Experiment Plan"));
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest() {
    let manifest = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    assert!(!manifest.proposals.is_empty());
    assert_eq!(manifest.proposals.len(), manifest.scores.len());
}

#[test]
fn test_manifest_deterministic() {
    let a = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    let b = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    assert_eq!(a.plan_id, b.plan_id);
    assert_eq!(a.content_hash, b.content_hash);
}
