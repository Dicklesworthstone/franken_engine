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
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::acquisition_experiment_oracle::{
    self, AcquisitionError, AcquisitionSignal, BEAD_ID, COMPONENT, ExperimentKind,
    ExperimentProposal, MILLIONTHS, POLICY_ID, SCHEMA_VERSION,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn load_acquisition_suite_script() -> String {
    let path = repo_root().join("scripts/run_acquisition_experiment_oracle_suite.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn load_acquisition_replay_script() -> String {
    let path = repo_root().join("scripts/e2e/acquisition_experiment_oracle_replay.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

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

#[test]
fn acquisition_oracle_suite_script_is_rch_only_and_emits_contract_artifacts() {
    let script = load_acquisition_suite_script();

    assert!(
        script.contains("${root_dir}/target_rch_acquisition_experiment_oracle_"),
        "suite script should use a repo-local namespaced remote target dir"
    );
    assert!(
        script.contains(
            "cargo test -p frankenengine-engine --test acquisition_experiment_oracle_integration"
        ),
        "suite script must run the acquisition oracle integration target"
    );
    assert!(
        script.contains("step_logs_dir=\"${run_dir}/step_logs\""),
        "suite script should retain per-step rch logs"
    );
    assert!(
        script.contains("\"acquisition_candidate_pool\":"),
        "run manifest must publish acquisition_candidate_pool"
    );
    assert!(
        script.contains("\"acquisition_score_ledger\":"),
        "run manifest must publish acquisition_score_ledger"
    );
    assert!(
        script.contains("\"acquisition_selection_report\":"),
        "run manifest must publish acquisition_selection_report"
    );
    assert!(
        script.contains("\"board_expansion_budget_report\":"),
        "run manifest must publish board_expansion_budget_report"
    );
    assert!(
        script.contains("\"trace_ids\":"),
        "run manifest must publish trace_ids"
    );
    assert!(
        script.contains("\"summary\":"),
        "run manifest must publish summary"
    );
    assert!(script.contains("\"env\":"), "run manifest must publish env");
    assert!(
        script.contains("\"repro_lock\":"),
        "run manifest must publish repro_lock"
    );
    assert!(
        script.contains("scripts/e2e/acquisition_experiment_oracle_replay.sh"),
        "suite script should point at the replay wrapper"
    );
    assert!(
        script.contains("rch is required for acquisition experiment oracle heavy commands"),
        "suite script should fail closed when rch is missing"
    );
    assert!(
        !script.contains("warning: rch not found; running locally for this environment"),
        "suite script must not allow local fallback"
    );
}

#[test]
fn acquisition_oracle_replay_wrapper_calls_suite() {
    let script = load_acquisition_replay_script();

    assert!(
        script.contains("scripts/run_acquisition_experiment_oracle_suite.sh"),
        "replay wrapper must route through the suite script"
    );
    assert!(
        script.contains("mode=\"${1:-test}\""),
        "replay wrapper should default to test mode"
    );
}

// ===========================================================================
// Enrichment tests — ExperimentKind
// ===========================================================================

#[test]
fn experiment_kind_all_unique_labels() {
    let mut labels = std::collections::BTreeSet::new();
    for kind in ExperimentKind::ALL {
        assert!(
            labels.insert(kind.as_str()),
            "duplicate label: {}",
            kind.as_str()
        );
    }
}

#[test]
fn experiment_kind_display_matches_as_str() {
    for kind in ExperimentKind::ALL {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

// ===========================================================================
// Enrichment tests — AcquisitionSignal
// ===========================================================================

#[test]
fn acquisition_signal_display_matches_as_str() {
    for signal in AcquisitionSignal::ALL {
        assert_eq!(signal.to_string(), signal.as_str());
    }
}

#[test]
fn acquisition_signal_all_unique_labels() {
    let mut labels = std::collections::BTreeSet::new();
    for signal in AcquisitionSignal::ALL {
        assert!(labels.insert(signal.as_str()), "duplicate label");
    }
}

// ===========================================================================
// Enrichment tests — AcquisitionScore serde
// ===========================================================================

#[test]
fn acquisition_score_serde_roundtrip() {
    use frankenengine_engine::acquisition_experiment_oracle::AcquisitionScore;
    let p = make_proposal(
        "sc1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    let json = serde_json::to_string(&score).unwrap();
    let back: AcquisitionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(back, score);
}

#[test]
fn acquisition_score_display() {
    let p = make_proposal(
        "sd1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    let display = format!("{score}");
    assert!(display.contains("sd1"));
    assert!(display.contains("Score"));
}

// ===========================================================================
// Enrichment tests — ExperimentPlan serde and display
// ===========================================================================

#[test]
fn experiment_plan_serde_roundtrip() {
    use frankenengine_engine::acquisition_experiment_oracle::ExperimentPlan;
    let p = make_proposal(
        "ps1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights())
            .unwrap();
    let json = serde_json::to_string(&plan).unwrap();
    let back: ExperimentPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(back, plan);
}

#[test]
fn experiment_plan_display() {
    let p = make_proposal(
        "pd1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights())
            .unwrap();
    let display = format!("{plan}");
    assert!(display.contains("Plan"));
}

// ===========================================================================
// Enrichment tests — ExperimentOutcome serde and display
// ===========================================================================

#[test]
fn experiment_outcome_serde_roundtrip() {
    use frankenengine_engine::acquisition_experiment_oracle::ExperimentOutcome;
    let p = make_proposal(
        "os1",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 600_000);
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ExperimentOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back, outcome);
}

#[test]
fn experiment_outcome_display() {
    let p = make_proposal(
        "od1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 300_000);
    let display = format!("{outcome}");
    assert!(display.contains("od1"));
    assert!(display.contains("Outcome"));
}

#[test]
fn experiment_outcome_surprise_positive_when_overestimate() {
    let p = make_proposal(
        "sur1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        800_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 200_000);
    assert!(
        outcome.surprise_millionths > 0,
        "overestimate should produce surprise"
    );
}

// ===========================================================================
// Enrichment tests — OracleCalibration serde
// ===========================================================================

#[test]
fn oracle_calibration_serde_roundtrip() {
    use frankenengine_engine::acquisition_experiment_oracle::OracleCalibration;
    let p = make_proposal(
        "cal1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 500_000);
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[outcome], &[p]);
    let json = serde_json::to_string(&cal).unwrap();
    let back: OracleCalibration = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cal);
}

#[test]
fn oracle_calibration_with_errors() {
    let p = make_proposal(
        "cal2",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        800_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 200_000);
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[outcome], &[p]);
    assert!(cal.mean_absolute_error_millionths > 0);
}

// ===========================================================================
// Enrichment tests — AcquisitionError
// ===========================================================================

#[test]
fn acquisition_error_all_variants_display() {
    let errors = [
        AcquisitionError::NoCandidates,
        AcquisitionError::BudgetExhausted,
        AcquisitionError::InternalError("test".into()),
    ];
    for e in &errors {
        let display = format!("{e}");
        assert!(!display.is_empty());
    }
}

#[test]
fn acquisition_error_serde_roundtrip() {
    let errors = [
        AcquisitionError::NoCandidates,
        AcquisitionError::BudgetExhausted,
        AcquisitionError::InternalError("bad proposal".into()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: AcquisitionError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *e);
    }
}

// ===========================================================================
// Enrichment tests — partition_by_kind
// ===========================================================================

#[test]
fn partition_by_kind_groups_correctly() {
    let p1 = make_proposal(
        "pk1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let p2 = make_proposal(
        "pk2",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let p3 = make_proposal(
        "pk3",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let proposals = [p1, p2, p3];
    let partitioned = acquisition_experiment_oracle::partition_by_kind(&proposals);
    assert_eq!(partitioned.len(), 2);
    assert_eq!(
        partitioned
            .get(&ExperimentKind::BoardCellProbe)
            .map(|v| v.len()),
        Some(2)
    );
    assert_eq!(
        partitioned
            .get(&ExperimentKind::CorpusAddition)
            .map(|v| v.len()),
        Some(1)
    );
}

// ===========================================================================
// Enrichment tests — find_dominant_signal
// ===========================================================================

#[test]
fn find_dominant_signal_empty_returns_none() {
    assert!(acquisition_experiment_oracle::find_dominant_signal(&[]).is_none());
}

#[test]
fn find_dominant_signal_returns_highest() {
    let p1 = make_proposal(
        "ds1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        200_000,
        500_000,
        100_000,
    );
    let p2 = make_proposal(
        "ds2",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        900_000,
        500_000,
        100_000,
    );
    let dominant = acquisition_experiment_oracle::find_dominant_signal(&[p1, p2]);
    assert!(dominant.is_some());
}

// ===========================================================================
// Enrichment tests — allocate_budget_by_kind
// ===========================================================================

#[test]
fn allocate_budget_by_kind_distributes() {
    let proposals = vec![
        make_proposal(
            "alloc1",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::LiveShiftPressure,
            500_000,
            300_000,
            100_000,
        ),
        make_proposal(
            "alloc2",
            ExperimentKind::CorpusAddition,
            AcquisitionSignal::StalenessAlarm,
            400_000,
            200_000,
            100_000,
        ),
    ];
    let allocation = acquisition_experiment_oracle::allocate_budget_by_kind(&proposals, 1_000_000);
    assert!(!allocation.is_empty());
    let total: u64 = allocation.values().sum();
    // Total should be close to 1_000_000 (may have rounding)
    assert!(total <= 1_000_000 + 100);
}

// ===========================================================================
// Enrichment tests — proposal content hash sensitivity
// ===========================================================================

#[test]
fn proposal_content_hash_changes_with_gain() {
    let p1 = ExperimentProposal::new(
        "ch1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 500_000)],
        500_000,
        300_000,
        100_000,
        "test".to_string(),
    );
    let p2 = ExperimentProposal::new(
        "ch1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 500_000)],
        800_000, // different gain
        300_000,
        100_000,
        "test".to_string(),
    );
    assert_ne!(p1.content_hash, p2.content_hash);
}

// ===========================================================================
// Enrichment tests — multiple proposals selection
// ===========================================================================

#[test]
fn select_experiments_multiple_within_budget() {
    let p1 = make_proposal(
        "ms1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        200_000,
    );
    let p2 = make_proposal(
        "ms2",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::PersistentHole,
        600_000,
        400_000,
        200_000,
    );
    let plan = acquisition_experiment_oracle::select_experiments(
        vec![p1, p2],
        1_000_000,
        &default_weights(),
    )
    .unwrap();
    assert_eq!(plan.proposals.len(), 2);
    assert!(plan.budget_remaining_millionths < 1_000_000);
    assert!(plan.total_expected_gain_millionths > 0);
}

// ===========================================================================
// Enrichment tests — combine_signal_strengths
// ===========================================================================

#[test]
fn combine_signal_strengths_three_signals() {
    let combined =
        acquisition_experiment_oracle::combine_signal_strengths(&[1_000_000, 1_000_000, 1_000_000]);
    // Diminishing: 1M + 500K + 250K = 1_750_000
    assert_eq!(combined, 1_750_000);
}

#[test]
fn combine_signal_strengths_monotonic() {
    let one = acquisition_experiment_oracle::combine_signal_strengths(&[500_000]);
    let two = acquisition_experiment_oracle::combine_signal_strengths(&[500_000, 500_000]);
    let three =
        acquisition_experiment_oracle::combine_signal_strengths(&[500_000, 500_000, 500_000]);
    assert!(two > one, "more signals should increase total");
    assert!(three > two, "more signals should increase total");
}

// ===========================================================================
// Enrichment tests — exploration_ratio
// ===========================================================================

#[test]
fn exploration_ratio_mixed() {
    let p1 = make_proposal(
        "er1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let p2 = make_proposal(
        "er2",
        ExperimentKind::DarkMatterExploration,
        AcquisitionSignal::SemanticDarkMatter,
        500_000,
        500_000,
        100_000,
    );
    let ratio = acquisition_experiment_oracle::exploration_ratio(&[p1, p2]);
    assert!(
        ratio > 0 && ratio < MILLIONTHS,
        "mixed should be between 0 and 1M: {}",
        ratio
    );
}

// ===========================================================================
// Enrichment tests — staleness_penalty edge cases
// ===========================================================================

#[test]
fn staleness_penalty_zero_age() {
    assert_eq!(acquisition_experiment_oracle::staleness_penalty(0, 10), 0);
}

#[test]
fn staleness_penalty_at_threshold() {
    assert_eq!(acquisition_experiment_oracle::staleness_penalty(10, 10), 0);
}

#[test]
fn staleness_penalty_increases_with_age() {
    let p20 = acquisition_experiment_oracle::staleness_penalty(20, 10);
    let p30 = acquisition_experiment_oracle::staleness_penalty(30, 10);
    assert!(p30 >= p20, "older evidence should have >= penalty");
}

// ===========================================================================
// Enrichment tests — new batch
// ===========================================================================

// ---------------------------------------------------------------------------
// ExperimentKind enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_experiment_kind_clone_eq() {
    for kind in ExperimentKind::ALL {
        let cloned = kind.clone();
        assert_eq!(*kind, cloned);
    }
}

#[test]
fn enrichment_experiment_kind_ord_is_total() {
    for (i, a) in ExperimentKind::ALL.iter().enumerate() {
        for b in &ExperimentKind::ALL[i..] {
            // Either a <= b or b <= a must hold (total order)
            assert!(a <= b || b <= a);
        }
    }
}

#[test]
fn enrichment_experiment_kind_debug_non_empty() {
    for kind in ExperimentKind::ALL {
        let dbg = format!("{kind:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_experiment_kind_as_str_no_uppercase() {
    for kind in ExperimentKind::ALL {
        let s = kind.as_str();
        assert_eq!(s, s.to_ascii_lowercase(), "as_str should be snake_case");
    }
}

#[test]
fn enrichment_experiment_kind_as_str_contains_underscore() {
    for kind in ExperimentKind::ALL {
        assert!(
            kind.as_str().contains('_'),
            "kind label should be snake_case with underscores: {}",
            kind.as_str()
        );
    }
}

#[test]
fn enrichment_experiment_kind_all_length_matches_serde_variants() {
    let mut count = 0;
    for kind in ExperimentKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let _back: ExperimentKind = serde_json::from_str(&json).unwrap();
        count += 1;
    }
    assert_eq!(count, ExperimentKind::ALL.len());
}

// ---------------------------------------------------------------------------
// AcquisitionSignal enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_acquisition_signal_clone_eq() {
    for sig in AcquisitionSignal::ALL {
        let cloned = sig.clone();
        assert_eq!(*sig, cloned);
    }
}

#[test]
fn enrichment_acquisition_signal_ord_total() {
    for (i, a) in AcquisitionSignal::ALL.iter().enumerate() {
        for b in &AcquisitionSignal::ALL[i..] {
            assert!(a <= b || b <= a);
        }
    }
}

#[test]
fn enrichment_acquisition_signal_debug_non_empty() {
    for sig in AcquisitionSignal::ALL {
        let dbg = format!("{sig:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_acquisition_signal_as_str_snake_case() {
    for sig in AcquisitionSignal::ALL {
        let s = sig.as_str();
        assert_eq!(s, s.to_ascii_lowercase());
        assert!(s.contains('_'));
    }
}

// ---------------------------------------------------------------------------
// ExperimentProposal enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_proposal_seal_idempotent() {
    let mut p = make_proposal(
        "seal-idem",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let hash_before = p.content_hash;
    p.seal();
    assert_eq!(p.content_hash, hash_before, "seal should be idempotent");
}

#[test]
fn enrichment_proposal_different_kind_different_hash() {
    let p1 = ExperimentProposal::new(
        "same-id".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 500_000)],
        500_000,
        300_000,
        100_000,
        "test".to_string(),
    );
    let p2 = ExperimentProposal::new(
        "same-id".to_string(),
        ExperimentKind::CorpusAddition,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 500_000)],
        500_000,
        300_000,
        100_000,
        "test".to_string(),
    );
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_proposal_different_target_different_hash() {
    let p1 = ExperimentProposal::new(
        "hash-t1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-alpha".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 500_000)],
        500_000,
        300_000,
        100_000,
        "test".to_string(),
    );
    let p2 = ExperimentProposal::new(
        "hash-t1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-beta".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 500_000)],
        500_000,
        300_000,
        100_000,
        "test".to_string(),
    );
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_proposal_different_justification_different_hash() {
    let p1 = ExperimentProposal::new(
        "hash-j1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        500_000,
        300_000,
        100_000,
        "reason A".to_string(),
    );
    let p2 = ExperimentProposal::new(
        "hash-j1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        500_000,
        300_000,
        100_000,
        "reason B".to_string(),
    );
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_proposal_different_signal_strength_different_hash() {
    let p1 = ExperimentProposal::new(
        "hash-ss1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 100_000)],
        500_000,
        300_000,
        100_000,
        "test".to_string(),
    );
    let p2 = ExperimentProposal::new(
        "hash-ss1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 900_000)],
        500_000,
        300_000,
        100_000,
        "test".to_string(),
    );
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_proposal_different_cost_different_hash() {
    let p1 = ExperimentProposal::new(
        "hash-c1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        500_000,
        300_000,
        100_000,
        "test".to_string(),
    );
    let p2 = ExperimentProposal::new(
        "hash-c1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        500_000,
        300_000,
        999_000,
        "test".to_string(),
    );
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_proposal_different_uncertainty_different_hash() {
    let p1 = ExperimentProposal::new(
        "hash-u1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        500_000,
        100_000,
        100_000,
        "test".to_string(),
    );
    let p2 = ExperimentProposal::new(
        "hash-u1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        500_000,
        900_000,
        100_000,
        "test".to_string(),
    );
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_proposal_display_contains_kind() {
    let p = make_proposal(
        "disp-k",
        ExperimentKind::AdversarialProbe,
        AcquisitionSignal::AdversarialOpportunity,
        700_000,
        500_000,
        100_000,
    );
    let display = format!("{p}");
    assert!(display.contains("adversarial_probe"));
}

#[test]
fn enrichment_proposal_display_contains_target() {
    let p = make_proposal(
        "disp-t",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let display = format!("{p}");
    assert!(display.contains("cell-disp-t"));
}

#[test]
fn enrichment_proposal_with_multiple_signals() {
    let p = ExperimentProposal::new(
        "multi-sig".to_string(),
        ExperimentKind::CoverageRecovery,
        "cell-multi".to_string(),
        vec![
            (AcquisitionSignal::CoverageDebt, 300_000),
            (AcquisitionSignal::PersistentHole, 400_000),
            (AcquisitionSignal::RatchetGap, 200_000),
        ],
        500_000,
        300_000,
        100_000,
        "multiple signals test".to_string(),
    );
    assert_eq!(p.signals.len(), 3);
    assert_ne!(
        p.content_hash,
        frankenengine_engine::hash_tiers::ContentHash::compute(b"")
    );
}

// ---------------------------------------------------------------------------
// score_proposal enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_score_proposal_zero_signal_strength() {
    let p = ExperimentProposal::new(
        "zero-str".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::LiveShiftPressure, 0)],
        500_000,
        300_000,
        100_000,
        "zero strength signal".to_string(),
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    // Raw = 0 (signal contribution) + 500_000 (expected gain) = 500_000
    assert_eq!(score.raw_gain_millionths, 500_000);
}

#[test]
fn enrichment_score_proposal_large_weight_saturation() {
    let p = ExperimentProposal::new(
        "large-w".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::LiveShiftPressure, MILLIONTHS)],
        0,
        0,
        100_000,
        "large weight".to_string(),
    );
    let mut weights = BTreeMap::new();
    weights.insert("live_shift_pressure".to_string(), 10_000_000); // 10x weight
    let score = acquisition_experiment_oracle::score_proposal(&p, &weights);
    // contribution = 1_000_000 * 10_000_000 / 1_000_000 = 10_000_000
    assert_eq!(score.raw_gain_millionths, 10_000_000);
}

#[test]
fn enrichment_score_proposal_dominant_signal_tracks_max() {
    let p = ExperimentProposal::new(
        "dom-check".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![
            (AcquisitionSignal::LiveShiftPressure, 100_000),
            (AcquisitionSignal::CoverageDebt, 900_000),
            (AcquisitionSignal::PersistentHole, 50_000),
        ],
        0,
        0,
        100_000,
        "dominant test".to_string(),
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    assert_eq!(score.dominant_signal, AcquisitionSignal::CoverageDebt);
}

#[test]
fn enrichment_score_proposal_signal_weights_recorded() {
    let p = ExperimentProposal::new(
        "weights-rec".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![
            (AcquisitionSignal::LiveShiftPressure, 500_000),
            (AcquisitionSignal::CoverageDebt, 300_000),
        ],
        0,
        0,
        100_000,
        "recording test".to_string(),
    );
    let mut weights = BTreeMap::new();
    weights.insert("live_shift_pressure".to_string(), 2_000_000);
    let score = acquisition_experiment_oracle::score_proposal(&p, &weights);
    assert_eq!(score.signal_weights.len(), 2);
    assert_eq!(
        score.signal_weights.get("live_shift_pressure"),
        Some(&2_000_000)
    );
    // coverage_debt not in custom weights -> default MILLIONTHS
    assert_eq!(score.signal_weights.get("coverage_debt"), Some(&MILLIONTHS));
}

#[test]
fn enrichment_score_proposal_cost_adjusted_inversely_proportional() {
    let p_cheap = make_proposal(
        "cheap",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let p_expensive = make_proposal(
        "expensive",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        500_000,
    );
    let s_cheap = acquisition_experiment_oracle::score_proposal(&p_cheap, &default_weights());
    let s_expensive =
        acquisition_experiment_oracle::score_proposal(&p_expensive, &default_weights());
    assert!(
        s_cheap.cost_adjusted_millionths > s_expensive.cost_adjusted_millionths,
        "cheaper proposal should have higher cost-adjusted score"
    );
}

#[test]
fn enrichment_score_proposal_no_signals_gives_expected_gain_only() {
    let p = ExperimentProposal::new(
        "no-sig".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        750_000,
        300_000,
        100_000,
        "no signals".to_string(),
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    assert_eq!(score.raw_gain_millionths, 750_000);
}

// ---------------------------------------------------------------------------
// rank_proposals enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rank_proposals_single_item() {
    let p = make_proposal(
        "single",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let ranked = acquisition_experiment_oracle::rank_proposals(vec![p], &default_weights());
    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].0.proposal_id, "single");
}

#[test]
fn enrichment_rank_proposals_preserves_all_entries() {
    let proposals: Vec<ExperimentProposal> = (0..5)
        .map(|i| {
            make_proposal(
                &format!("rank-{i}"),
                ExperimentKind::BoardCellProbe,
                AcquisitionSignal::CoverageDebt,
                (i as u64 + 1) * 100_000,
                400_000,
                100_000,
            )
        })
        .collect();
    let ranked = acquisition_experiment_oracle::rank_proposals(proposals, &default_weights());
    assert_eq!(ranked.len(), 5);
}

#[test]
fn enrichment_rank_proposals_descending_order_verified() {
    let p1 = make_proposal(
        "low",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        100_000,
        100_000,
        500_000,
    );
    let p2 = make_proposal(
        "mid",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        500_000,
        300_000,
        200_000,
    );
    let p3 = make_proposal(
        "high",
        ExperimentKind::AdversarialProbe,
        AcquisitionSignal::AdversarialOpportunity,
        900_000,
        400_000,
        50_000,
    );
    let ranked =
        acquisition_experiment_oracle::rank_proposals(vec![p1, p2, p3], &default_weights());
    for i in 0..ranked.len() - 1 {
        assert!(
            ranked[i].1.cost_adjusted_millionths >= ranked[i + 1].1.cost_adjusted_millionths,
            "ranking must be descending at positions {} and {}",
            i,
            i + 1
        );
    }
}

// ---------------------------------------------------------------------------
// select_experiments enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_select_experiments_plan_id_format() {
    let p = make_proposal(
        "plan-fmt",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights())
            .unwrap();
    assert!(
        plan.plan_id.starts_with("plan-"),
        "plan_id should start with 'plan-': {}",
        plan.plan_id
    );
}

#[test]
fn enrichment_select_experiments_budget_accounting() {
    let p1 = make_proposal(
        "acct1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        300_000,
    );
    let p2 = make_proposal(
        "acct2",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::PersistentHole,
        400_000,
        300_000,
        200_000,
    );
    let budget = 1_000_000;
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p1, p2], budget, &default_weights())
            .unwrap();
    let total_cost: u64 = plan
        .proposals
        .iter()
        .map(|p| p.estimated_cost_millionths)
        .sum();
    assert_eq!(
        plan.budget_remaining_millionths,
        budget - total_cost,
        "remaining budget should equal budget minus total cost"
    );
}

#[test]
fn enrichment_select_experiments_greedy_skips_too_expensive() {
    let cheap = make_proposal(
        "cheap",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let expensive = make_proposal(
        "expensive",
        ExperimentKind::DarkMatterExploration,
        AcquisitionSignal::SemanticDarkMatter,
        200_000,
        100_000,
        900_000,
    );
    // Budget allows cheap but not expensive
    let plan = acquisition_experiment_oracle::select_experiments(
        vec![cheap, expensive],
        200_000,
        &default_weights(),
    )
    .unwrap();
    assert_eq!(plan.proposals.len(), 1);
    assert_eq!(plan.proposals[0].proposal_id, "cheap");
}

#[test]
fn enrichment_select_experiments_all_seven_kinds() {
    let kinds_signals = vec![
        (
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::LiveShiftPressure,
        ),
        (
            ExperimentKind::CorpusAddition,
            AcquisitionSignal::CoverageDebt,
        ),
        (
            ExperimentKind::AdversarialProbe,
            AcquisitionSignal::AdversarialOpportunity,
        ),
        (
            ExperimentKind::ShiftValidation,
            AcquisitionSignal::StalenessAlarm,
        ),
        (
            ExperimentKind::CoverageRecovery,
            AcquisitionSignal::PersistentHole,
        ),
        (ExperimentKind::HoleFilling, AcquisitionSignal::RatchetGap),
        (
            ExperimentKind::DarkMatterExploration,
            AcquisitionSignal::SemanticDarkMatter,
        ),
    ];
    let proposals: Vec<ExperimentProposal> = kinds_signals
        .into_iter()
        .enumerate()
        .map(|(i, (kind, sig))| {
            make_proposal(&format!("k{i}"), kind, sig, 500_000, 400_000, 100_000)
        })
        .collect();
    let plan = acquisition_experiment_oracle::select_experiments(
        proposals,
        10_000_000,
        &default_weights(),
    )
    .unwrap();
    assert_eq!(plan.proposals.len(), 7);
    let errors = acquisition_experiment_oracle::validate_plan(&plan);
    assert!(errors.is_empty());
}

#[test]
fn enrichment_select_experiments_exact_budget() {
    let p = make_proposal(
        "exact-budget",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        500_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 500_000, &default_weights())
            .unwrap();
    assert_eq!(plan.proposals.len(), 1);
    assert_eq!(plan.budget_remaining_millionths, 0);
}

#[test]
fn enrichment_select_experiments_plan_hash_not_empty() {
    let p = make_proposal(
        "hash-ne",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights())
            .unwrap();
    assert_ne!(
        plan.content_hash,
        frankenengine_engine::hash_tiers::ContentHash::compute(b"")
    );
}

// ---------------------------------------------------------------------------
// record_outcome enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_record_outcome_zero_actual_gain() {
    let p = make_proposal(
        "zero-gain",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 0);
    assert_eq!(outcome.actual_information_gain_millionths, 0);
    assert_eq!(outcome.surprise_millionths, 500_000);
    assert_eq!(outcome.regret_millionths, 500_000);
}

#[test]
fn enrichment_record_outcome_massive_overperformance() {
    let p = make_proposal(
        "overperf",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        100_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 5_000_000);
    assert_eq!(outcome.regret_millionths, 0);
    assert_eq!(outcome.surprise_millionths, 4_900_000);
}

#[test]
fn enrichment_record_outcome_hash_deterministic() {
    let p = make_proposal(
        "hash-det",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let o1 = acquisition_experiment_oracle::record_outcome(&p, 300_000);
    let o2 = acquisition_experiment_oracle::record_outcome(&p, 300_000);
    assert_eq!(o1.content_hash, o2.content_hash);
}

#[test]
fn enrichment_record_outcome_different_gains_different_hash() {
    let p = make_proposal(
        "diff-hash",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let o1 = acquisition_experiment_oracle::record_outcome(&p, 300_000);
    let o2 = acquisition_experiment_oracle::record_outcome(&p, 700_000);
    assert_ne!(o1.content_hash, o2.content_hash);
}

#[test]
fn enrichment_record_outcome_serde_with_regret() {
    use frankenengine_engine::acquisition_experiment_oracle::ExperimentOutcome;
    let p = make_proposal(
        "serde-regret",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        800_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 200_000);
    assert!(outcome.regret_millionths > 0);
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ExperimentOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back.regret_millionths, outcome.regret_millionths);
}

// ---------------------------------------------------------------------------
// compute_regret enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compute_regret_symmetric_check() {
    // regret(a, b) is NOT symmetric — it's saturating_sub
    let r1 = acquisition_experiment_oracle::compute_regret(800_000, 300_000);
    let r2 = acquisition_experiment_oracle::compute_regret(300_000, 800_000);
    assert_eq!(r1, 500_000);
    assert_eq!(r2, 0);
}

#[test]
fn enrichment_compute_regret_both_zero() {
    assert_eq!(acquisition_experiment_oracle::compute_regret(0, 0), 0);
}

#[test]
fn enrichment_compute_regret_large_values() {
    let expected = 10_000_000_000u64;
    let actual = 3_000_000_000u64;
    assert_eq!(
        acquisition_experiment_oracle::compute_regret(expected, actual),
        7_000_000_000
    );
}

// ---------------------------------------------------------------------------
// calibrate_oracle enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_calibrate_oracle_multiple_outcomes() {
    let p1 = make_proposal(
        "mc1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let p2 = make_proposal(
        "mc2",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::PersistentHole,
        600_000,
        400_000,
        200_000,
    );
    let o1 = acquisition_experiment_oracle::record_outcome(&p1, 400_000); // 100k off
    let o2 = acquisition_experiment_oracle::record_outcome(&p2, 700_000); // 300k off (under-prediction)
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[o1, o2], &[p1, p2]);
    assert_eq!(cal.predictions_count, 2);
    assert_eq!(cal.mean_absolute_error_millionths, 200_000);
}

#[test]
fn enrichment_calibrate_oracle_bias_cancellation() {
    // One over-predicts by 300k, one under-predicts by 400k => average bias -50k
    let p1 = make_proposal(
        "bias-a",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        600_000,
        100_000,
    );
    let p2 = make_proposal(
        "bias-b",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::PersistentHole,
        500_000,
        400_000,
        100_000,
    );
    let o1 = acquisition_experiment_oracle::record_outcome(&p1, 300_000); // over-predicted by 300k
    let o2 = acquisition_experiment_oracle::record_outcome(&p2, 800_000); // under-predicted by 400k
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[o1, o2], &[p1, p2]);
    assert_eq!(cal.bias_millionths, -50_000);
}

#[test]
fn enrichment_calibrate_oracle_unmatched_proposal_ignored() {
    let p1 = make_proposal(
        "match1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let p2 = make_proposal(
        "nomatch",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::PersistentHole,
        600_000,
        400_000,
        100_000,
    );
    let o1 = acquisition_experiment_oracle::record_outcome(&p1, 500_000);
    // Only provide p2 in proposals — o1 won't match
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[o1], &[p2]);
    assert_eq!(cal.predictions_count, 0);
}

#[test]
fn enrichment_calibrate_oracle_calibration_id_includes_count() {
    let p = make_proposal(
        "cal-id",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let o = acquisition_experiment_oracle::record_outcome(&p, 500_000);
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[o], &[p]);
    assert!(
        cal.calibration_id.contains("n1"),
        "calibration_id should contain 'n1': {}",
        cal.calibration_id
    );
}

#[test]
fn enrichment_calibrate_oracle_hash_differs_with_data() {
    let empty_cal = acquisition_experiment_oracle::calibrate_oracle(&[], &[]);
    let p = make_proposal(
        "cal-hash",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let o = acquisition_experiment_oracle::record_outcome(&p, 500_000);
    let data_cal = acquisition_experiment_oracle::calibrate_oracle(&[o], &[p]);
    assert_ne!(empty_cal.content_hash, data_cal.content_hash);
}

// ---------------------------------------------------------------------------
// combine_signal_strengths enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_combine_signal_strengths_order_independent() {
    let a = acquisition_experiment_oracle::combine_signal_strengths(&[800_000, 400_000, 200_000]);
    let b = acquisition_experiment_oracle::combine_signal_strengths(&[200_000, 800_000, 400_000]);
    assert_eq!(a, b, "combine_signal_strengths should be order-independent");
}

#[test]
fn enrichment_combine_signal_strengths_all_zeros() {
    assert_eq!(
        acquisition_experiment_oracle::combine_signal_strengths(&[0, 0, 0]),
        0
    );
}

#[test]
fn enrichment_combine_signal_strengths_large_count() {
    let strengths: Vec<u64> = (0..10).map(|_| 1_000_000).collect();
    let combined = acquisition_experiment_oracle::combine_signal_strengths(&strengths);
    // Sum = 1M + 500K + 250K + 125K + ... converges to ~2M
    assert!(combined > 1_000_000);
    assert!(combined < 2_100_000);
}

#[test]
fn enrichment_combine_signal_strengths_strictly_less_than_sum() {
    let strengths = &[500_000, 500_000, 500_000];
    let combined = acquisition_experiment_oracle::combine_signal_strengths(strengths);
    let raw_sum: u64 = strengths.iter().sum();
    assert!(
        combined < raw_sum,
        "diminishing returns should make combined ({}) < raw sum ({})",
        combined,
        raw_sum
    );
}

// ---------------------------------------------------------------------------
// information_density enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_information_density_high_gain_low_cost() {
    let p = make_proposal(
        "hglc",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        1_000_000,
        10_000,
    );
    let density = acquisition_experiment_oracle::information_density(&p);
    // 1_000_000 * 1_000_000 / 10_000 = 100_000_000
    assert_eq!(density, 100_000_000);
}

#[test]
fn enrichment_information_density_equal_gain_and_cost() {
    let p = make_proposal(
        "eq-gc",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        500_000,
    );
    let density = acquisition_experiment_oracle::information_density(&p);
    assert_eq!(density, MILLIONTHS); // gain/cost = 1.0 => 1M millionths
}

#[test]
fn enrichment_information_density_zero_gain() {
    let p = ExperimentProposal::new(
        "zero-g".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        0,
        300_000,
        100_000,
        "zero gain".to_string(),
    );
    assert_eq!(acquisition_experiment_oracle::information_density(&p), 0);
}

// ---------------------------------------------------------------------------
// is_justified enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_is_justified_exact_boundary() {
    // gain == cost * threshold / MILLIONTHS => exactly justified
    let p = ExperimentProposal::new(
        "boundary".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        100_000, // gain
        300_000,
        100_000, // cost
        "boundary test".to_string(),
    );
    // threshold = 1.0 => min_gain = 100_000 * 1_000_000 / 1_000_000 = 100_000
    assert!(acquisition_experiment_oracle::is_justified(&p, MILLIONTHS));
}

#[test]
fn enrichment_is_justified_zero_cost_always_justified() {
    let p = ExperimentProposal::new(
        "free-exp".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        1, // any gain > 0
        0,
        0, // zero cost
        "free experiment".to_string(),
    );
    // min_gain = 0 * anything = 0, so gain(1) >= 0 => justified
    assert!(acquisition_experiment_oracle::is_justified(&p, 5_000_000));
}

#[test]
fn enrichment_is_justified_zero_gain_zero_cost() {
    let p = ExperimentProposal::new(
        "zero-all".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        0, // zero gain
        0,
        0, // zero cost
        "zero everything".to_string(),
    );
    // min_gain = 0, gain = 0, 0 >= 0 => justified
    assert!(acquisition_experiment_oracle::is_justified(&p, MILLIONTHS));
}

#[test]
fn enrichment_is_justified_high_threshold() {
    let p = make_proposal(
        "high-thresh",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    // threshold = 10.0 => min_gain = 100_000 * 10M / 1M = 1_000_000
    // gain(500_000) < 1_000_000 => not justified
    assert!(!acquisition_experiment_oracle::is_justified(&p, 10_000_000));
}

// ---------------------------------------------------------------------------
// diversity_bonus enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_diversity_bonus_empty() {
    assert_eq!(acquisition_experiment_oracle::diversity_bonus(&[]), 0);
}

#[test]
fn enrichment_diversity_bonus_two_kinds() {
    let p1 = make_proposal(
        "d1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let p2 = make_proposal(
        "d2",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let bonus = acquisition_experiment_oracle::diversity_bonus(&[p1, p2]);
    // 2 / 7 * MILLIONTHS = 285714
    assert_eq!(bonus, 2 * MILLIONTHS / 7);
}

#[test]
fn enrichment_diversity_bonus_all_seven_kinds() {
    let proposals: Vec<ExperimentProposal> = ExperimentKind::ALL
        .iter()
        .enumerate()
        .map(|(i, kind)| {
            make_proposal(
                &format!("all-{i}"),
                *kind,
                AcquisitionSignal::CoverageDebt,
                500_000,
                400_000,
                100_000,
            )
        })
        .collect();
    let bonus = acquisition_experiment_oracle::diversity_bonus(&proposals);
    assert_eq!(bonus, MILLIONTHS);
}

#[test]
fn enrichment_diversity_bonus_duplicates_dont_increase() {
    let p1 = make_proposal(
        "dup1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let p2 = make_proposal(
        "dup2",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        400_000,
        100_000,
    );
    let single_bonus = acquisition_experiment_oracle::diversity_bonus(std::slice::from_ref(&p1));
    let double_bonus = acquisition_experiment_oracle::diversity_bonus(&[p1, p2]);
    assert_eq!(
        single_bonus, double_bonus,
        "same kind repeated should not increase bonus"
    );
}

// ---------------------------------------------------------------------------
// staleness_penalty enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_staleness_penalty_exactly_double_threshold() {
    // age=20, max=10 => over=10 => penalty = 10 * 1M / 10 = 1M (capped)
    assert_eq!(
        acquisition_experiment_oracle::staleness_penalty(20, 10),
        MILLIONTHS
    );
}

#[test]
fn enrichment_staleness_penalty_just_over_threshold() {
    // age=11, max=10 => over=1 => penalty = 1 * 1M / 10 = 100_000
    assert_eq!(
        acquisition_experiment_oracle::staleness_penalty(11, 10),
        100_000
    );
}

#[test]
fn enrichment_staleness_penalty_max_fresh_zero() {
    // max_fresh_ticks=0 => everything over 0 is stale
    // age=5 => over=5, penalty = 5 * 1M / max(0,1) = 5M => capped at 1M
    assert_eq!(
        acquisition_experiment_oracle::staleness_penalty(5, 0),
        MILLIONTHS
    );
}

#[test]
fn enrichment_staleness_penalty_zero_age_zero_max() {
    // age=0, max=0 => 0 <= 0, no penalty
    assert_eq!(acquisition_experiment_oracle::staleness_penalty(0, 0), 0);
}

#[test]
fn enrichment_staleness_penalty_capped_at_millionths() {
    let penalty = acquisition_experiment_oracle::staleness_penalty(1_000_000, 1);
    assert_eq!(
        penalty, MILLIONTHS,
        "penalty should be capped at MILLIONTHS"
    );
}

// ---------------------------------------------------------------------------
// partition_by_kind enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_partition_by_kind_empty() {
    let partitioned = acquisition_experiment_oracle::partition_by_kind(&[]);
    assert!(partitioned.is_empty());
}

#[test]
fn enrichment_partition_by_kind_single_kind() {
    let proposals: Vec<ExperimentProposal> = (0..3)
        .map(|i| {
            make_proposal(
                &format!("pk-{i}"),
                ExperimentKind::BoardCellProbe,
                AcquisitionSignal::CoverageDebt,
                500_000,
                400_000,
                100_000,
            )
        })
        .collect();
    let partitioned = acquisition_experiment_oracle::partition_by_kind(&proposals);
    assert_eq!(partitioned.len(), 1);
    assert_eq!(partitioned[&ExperimentKind::BoardCellProbe].len(), 3);
}

#[test]
fn enrichment_partition_by_kind_all_kinds() {
    let proposals: Vec<ExperimentProposal> = ExperimentKind::ALL
        .iter()
        .enumerate()
        .map(|(i, kind)| {
            make_proposal(
                &format!("pk-all-{i}"),
                *kind,
                AcquisitionSignal::CoverageDebt,
                500_000,
                400_000,
                100_000,
            )
        })
        .collect();
    let partitioned = acquisition_experiment_oracle::partition_by_kind(&proposals);
    assert_eq!(partitioned.len(), 7);
}

// ---------------------------------------------------------------------------
// find_dominant_signal enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_find_dominant_signal_single_proposal_single_signal() {
    let p = make_proposal(
        "dom-single",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let dominant = acquisition_experiment_oracle::find_dominant_signal(&[p]);
    assert_eq!(dominant, Some(AcquisitionSignal::LiveShiftPressure));
}

#[test]
fn enrichment_find_dominant_signal_tie_broken_deterministically() {
    // Two proposals with equal-strength signals of different types
    let p1 = ExperimentProposal::new(
        "tie1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 500_000)],
        500_000,
        300_000,
        100_000,
        "test".to_string(),
    );
    let p2 = ExperimentProposal::new(
        "tie2".to_string(),
        ExperimentKind::CorpusAddition,
        "cell-b".to_string(),
        vec![(AcquisitionSignal::PersistentHole, 500_000)],
        500_000,
        300_000,
        100_000,
        "test".to_string(),
    );
    let dom1 = acquisition_experiment_oracle::find_dominant_signal(&[p1.clone(), p2.clone()]);
    let dom2 = acquisition_experiment_oracle::find_dominant_signal(&[p1, p2]);
    assert_eq!(dom1, dom2, "dominant signal should be deterministic");
}

#[test]
fn enrichment_find_dominant_signal_no_signals_on_proposals() {
    let p = ExperimentProposal::new(
        "no-sig".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        500_000,
        300_000,
        100_000,
        "no signals".to_string(),
    );
    assert_eq!(
        acquisition_experiment_oracle::find_dominant_signal(&[p]),
        None
    );
}

// ---------------------------------------------------------------------------
// allocate_budget_by_kind enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_allocate_budget_empty() {
    let alloc = acquisition_experiment_oracle::allocate_budget_by_kind(&[], 1_000_000);
    assert!(alloc.is_empty());
}

#[test]
fn enrichment_allocate_budget_single_kind_gets_all() {
    let p = make_proposal(
        "all-budget",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let alloc = acquisition_experiment_oracle::allocate_budget_by_kind(&[p], 1_000_000);
    assert_eq!(alloc[&ExperimentKind::BoardCellProbe], 1_000_000);
}

#[test]
fn enrichment_allocate_budget_sums_to_total() {
    let p1 = make_proposal(
        "bud1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let p2 = make_proposal(
        "bud2",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::PersistentHole,
        400_000,
        300_000,
        100_000,
    );
    let p3 = make_proposal(
        "bud3",
        ExperimentKind::AdversarialProbe,
        AcquisitionSignal::AdversarialOpportunity,
        600_000,
        300_000,
        100_000,
    );
    let total_budget = 1_000_000;
    let alloc = acquisition_experiment_oracle::allocate_budget_by_kind(&[p1, p2, p3], total_budget);
    let sum: u64 = alloc.values().sum();
    assert_eq!(
        sum, total_budget,
        "allocated budgets should sum to total: {} != {}",
        sum, total_budget
    );
}

// ---------------------------------------------------------------------------
// exploration_ratio enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_exploration_ratio_empty() {
    assert_eq!(acquisition_experiment_oracle::exploration_ratio(&[]), 0);
}

#[test]
fn enrichment_exploration_ratio_hole_filling_is_exploration() {
    let p = make_proposal(
        "hf-explore",
        ExperimentKind::HoleFilling,
        AcquisitionSignal::RatchetGap,
        500_000,
        400_000,
        100_000,
    );
    assert_eq!(
        acquisition_experiment_oracle::exploration_ratio(&[p]),
        MILLIONTHS
    );
}

#[test]
fn enrichment_exploration_ratio_coverage_recovery_is_exploration() {
    let p = make_proposal(
        "cr-explore",
        ExperimentKind::CoverageRecovery,
        AcquisitionSignal::PersistentHole,
        500_000,
        400_000,
        100_000,
    );
    assert_eq!(
        acquisition_experiment_oracle::exploration_ratio(&[p]),
        MILLIONTHS
    );
}

#[test]
fn enrichment_exploration_ratio_shift_validation_is_exploitation() {
    let p = make_proposal(
        "sv-exploit",
        ExperimentKind::ShiftValidation,
        AcquisitionSignal::StalenessAlarm,
        500_000,
        400_000,
        100_000,
    );
    assert_eq!(acquisition_experiment_oracle::exploration_ratio(&[p]), 0);
}

#[test]
fn enrichment_exploration_ratio_proportional_to_cost() {
    let explore = make_proposal(
        "exp-big",
        ExperimentKind::DarkMatterExploration,
        AcquisitionSignal::SemanticDarkMatter,
        500_000,
        400_000,
        300_000, // 3x cost
    );
    let exploit = make_proposal(
        "exploit-small",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000, // 1x cost
    );
    let ratio = acquisition_experiment_oracle::exploration_ratio(&[explore, exploit]);
    // exploration cost = 300_000, total = 400_000
    // ratio = 300_000 * 1M / 400_000 = 750_000
    assert_eq!(ratio, 750_000);
}

// ---------------------------------------------------------------------------
// validate_plan enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_plan_detects_id_mismatch() {
    use frankenengine_engine::acquisition_experiment_oracle::ExperimentPlan;
    use frankenengine_engine::security_epoch::SecurityEpoch;
    let p = make_proposal(
        "valid-id",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let mut score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    score.proposal_id = "wrong-id".to_string(); // mismatch

    let plan = ExperimentPlan {
        plan_id: "test-mismatch".to_string(),
        epoch: SecurityEpoch::GENESIS,
        proposals: vec![p],
        scores: vec![score],
        budget_remaining_millionths: 900_000,
        total_expected_gain_millionths: 500_000,
        content_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    };
    let errors = acquisition_experiment_oracle::validate_plan(&plan);
    assert!(
        errors.iter().any(|e| e.contains("mismatch")),
        "should detect proposal_id mismatch"
    );
}

// ---------------------------------------------------------------------------
// summarise_plan enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summarise_plan_includes_all_experiments() {
    let proposals: Vec<ExperimentProposal> = (0..3)
        .map(|i| {
            make_proposal(
                &format!("sum-{i}"),
                ExperimentKind::BoardCellProbe,
                AcquisitionSignal::CoverageDebt,
                500_000,
                400_000,
                100_000,
            )
        })
        .collect();
    let plan =
        acquisition_experiment_oracle::select_experiments(proposals, 1_000_000, &default_weights())
            .unwrap();
    let summary = acquisition_experiment_oracle::summarise_plan(&plan);
    assert!(summary.contains("[0]"));
    assert!(summary.contains("[1]"));
    assert!(summary.contains("[2]"));
}

#[test]
fn enrichment_summarise_plan_includes_justification() {
    let p = ExperimentProposal::new(
        "just-sum".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 500_000)],
        500_000,
        300_000,
        100_000,
        "this is the justification text".to_string(),
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights())
            .unwrap();
    let summary = acquisition_experiment_oracle::summarise_plan(&plan);
    assert!(summary.contains("this is the justification text"));
}

// ---------------------------------------------------------------------------
// Manifest enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_all_proposals_have_justifications() {
    let manifest = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    for proposal in &manifest.proposals {
        assert!(
            !proposal.justification.is_empty(),
            "manifest proposal {} should have a justification",
            proposal.proposal_id
        );
    }
}

#[test]
fn enrichment_manifest_all_proposals_have_signals() {
    let manifest = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    for proposal in &manifest.proposals {
        assert!(
            !proposal.signals.is_empty(),
            "manifest proposal {} should have at least one signal",
            proposal.proposal_id
        );
    }
}

#[test]
fn enrichment_manifest_total_gain_matches_sum() {
    let manifest = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    let sum: u64 = manifest
        .proposals
        .iter()
        .map(|p| p.expected_information_gain_millionths)
        .sum();
    assert_eq!(manifest.total_expected_gain_millionths, sum);
}

#[test]
fn enrichment_manifest_validates_clean() {
    let manifest = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    let errors = acquisition_experiment_oracle::validate_plan(&manifest);
    assert!(
        errors.is_empty(),
        "manifest should validate cleanly: {:?}",
        errors
    );
}

#[test]
fn enrichment_manifest_serde_roundtrip_full() {
    use frankenengine_engine::acquisition_experiment_oracle::ExperimentPlan;
    let manifest = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    let json = serde_json::to_string_pretty(&manifest).unwrap();
    let back: ExperimentPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(back.proposals.len(), manifest.proposals.len());
    assert_eq!(back.content_hash, manifest.content_hash);
}

#[test]
fn enrichment_manifest_budget_fully_spent() {
    let manifest = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    assert_eq!(
        manifest.budget_remaining_millionths, 0,
        "manifest should spend its entire budget"
    );
}

// ---------------------------------------------------------------------------
// AcquisitionError enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_acquisition_error_calibration_drift_display() {
    let e = AcquisitionError::CalibrationDrift;
    let display = format!("{e}");
    assert!(display.contains("calibration"));
}

#[test]
fn enrichment_acquisition_error_invalid_signal_display() {
    let e = AcquisitionError::InvalidSignal;
    let display = format!("{e}");
    assert!(display.contains("invalid"));
}

#[test]
fn enrichment_acquisition_error_all_variants_serde() {
    let variants = [
        AcquisitionError::NoCandidates,
        AcquisitionError::BudgetExhausted,
        AcquisitionError::CalibrationDrift,
        AcquisitionError::InvalidSignal,
        AcquisitionError::InternalError("detailed message".into()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: AcquisitionError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

#[test]
fn enrichment_acquisition_error_debug_non_empty() {
    let errors = [
        AcquisitionError::NoCandidates,
        AcquisitionError::BudgetExhausted,
        AcquisitionError::CalibrationDrift,
        AcquisitionError::InvalidSignal,
        AcquisitionError::InternalError("msg".into()),
    ];
    for e in &errors {
        assert!(!format!("{e:?}").is_empty());
    }
}

#[test]
fn enrichment_acquisition_error_internal_preserves_message() {
    let msg = "something went wrong in the oracle pipeline";
    let e = AcquisitionError::InternalError(msg.to_string());
    let display = format!("{e}");
    assert!(display.contains(msg));
}

// ---------------------------------------------------------------------------
// Cross-cutting integration enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_end_to_end_propose_select_record_calibrate() {
    // Full pipeline: create proposals, select, record outcomes, calibrate
    let p1 = make_proposal(
        "e2e-1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let p2 = make_proposal(
        "e2e-2",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        600_000,
        400_000,
        200_000,
    );
    let plan = acquisition_experiment_oracle::select_experiments(
        vec![p1.clone(), p2.clone()],
        1_000_000,
        &default_weights(),
    )
    .unwrap();
    assert_eq!(plan.proposals.len(), 2);

    let o1 = acquisition_experiment_oracle::record_outcome(&p1, 450_000);
    let o2 = acquisition_experiment_oracle::record_outcome(&p2, 700_000);
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[o1, o2], &[p1, p2]);
    assert_eq!(cal.predictions_count, 2);
    assert!(cal.mean_absolute_error_millionths > 0);
}

#[test]
fn enrichment_pipeline_determinism() {
    let make_proposals = || {
        vec![
            make_proposal(
                "det-1",
                ExperimentKind::BoardCellProbe,
                AcquisitionSignal::LiveShiftPressure,
                800_000,
                500_000,
                100_000,
            ),
            make_proposal(
                "det-2",
                ExperimentKind::DarkMatterExploration,
                AcquisitionSignal::SemanticDarkMatter,
                600_000,
                300_000,
                200_000,
            ),
        ]
    };
    let plan_a = acquisition_experiment_oracle::select_experiments(
        make_proposals(),
        1_000_000,
        &default_weights(),
    )
    .unwrap();
    let plan_b = acquisition_experiment_oracle::select_experiments(
        make_proposals(),
        1_000_000,
        &default_weights(),
    )
    .unwrap();
    assert_eq!(plan_a.plan_id, plan_b.plan_id);
    assert_eq!(plan_a.content_hash, plan_b.content_hash);
    assert_eq!(
        plan_a.total_expected_gain_millionths,
        plan_b.total_expected_gain_millionths
    );
}

#[test]
fn enrichment_score_ranking_and_selection_consistency() {
    let proposals = vec![
        make_proposal(
            "cons-a",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::LiveShiftPressure,
            800_000,
            500_000,
            100_000,
        ),
        make_proposal(
            "cons-b",
            ExperimentKind::CorpusAddition,
            AcquisitionSignal::CoverageDebt,
            200_000,
            100_000,
            300_000,
        ),
    ];
    let ranked =
        acquisition_experiment_oracle::rank_proposals(proposals.clone(), &default_weights());
    let plan = acquisition_experiment_oracle::select_experiments(
        proposals,
        10_000_000,
        &default_weights(),
    )
    .unwrap();
    // First selected proposal should be the same as first ranked
    assert_eq!(plan.proposals[0].proposal_id, ranked[0].0.proposal_id);
}

#[test]
fn enrichment_diversity_bonus_inversely_related_to_homogeneity() {
    let homogeneous: Vec<ExperimentProposal> = (0..5)
        .map(|i| {
            make_proposal(
                &format!("homo-{i}"),
                ExperimentKind::BoardCellProbe,
                AcquisitionSignal::CoverageDebt,
                500_000,
                400_000,
                100_000,
            )
        })
        .collect();
    let diverse = vec![
        make_proposal(
            "div-0",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::CoverageDebt,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "div-1",
            ExperimentKind::CorpusAddition,
            AcquisitionSignal::PersistentHole,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "div-2",
            ExperimentKind::AdversarialProbe,
            AcquisitionSignal::AdversarialOpportunity,
            500_000,
            400_000,
            100_000,
        ),
    ];
    let homo_bonus = acquisition_experiment_oracle::diversity_bonus(&homogeneous);
    let diverse_bonus = acquisition_experiment_oracle::diversity_bonus(&diverse);
    assert!(
        diverse_bonus > homo_bonus,
        "diverse set should have higher bonus: {} > {}",
        diverse_bonus,
        homo_bonus
    );
}

// ===========================================================================
// Enrichment batch — 80 new tests
// ===========================================================================

// ---------------------------------------------------------------------------
// ExperimentKind: serde edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_experiment_kind_from_json_string_literal() {
    let json = "\"BoardCellProbe\"";
    let kind: ExperimentKind = serde_json::from_str(json).unwrap();
    assert_eq!(kind, ExperimentKind::BoardCellProbe);
}

#[test]
fn enrichment_experiment_kind_invalid_json_rejected() {
    let json = "\"NonExistentKind\"";
    let result = serde_json::from_str::<ExperimentKind>(json);
    assert!(result.is_err());
}

#[test]
fn enrichment_experiment_kind_all_stable_length() {
    // ALL must contain exactly 7 variants; if someone adds a variant they must update ALL.
    assert_eq!(
        ExperimentKind::ALL.len(),
        7,
        "ALL array should have exactly 7 variants"
    );
}

#[test]
fn enrichment_experiment_kind_partial_ord_consistent_with_ord() {
    for a in ExperimentKind::ALL {
        for b in ExperimentKind::ALL {
            assert_eq!(
                a.partial_cmp(b),
                Some(a.cmp(b)),
                "PartialOrd and Ord must agree for {:?} vs {:?}",
                a,
                b
            );
        }
    }
}

// ---------------------------------------------------------------------------
// AcquisitionSignal: additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_acquisition_signal_invalid_json_rejected() {
    let json = "\"FakeSignal\"";
    let result = serde_json::from_str::<AcquisitionSignal>(json);
    assert!(result.is_err());
}

#[test]
fn enrichment_acquisition_signal_partial_ord_consistent() {
    for a in AcquisitionSignal::ALL {
        for b in AcquisitionSignal::ALL {
            assert_eq!(a.partial_cmp(b), Some(a.cmp(b)));
        }
    }
}

#[test]
fn enrichment_acquisition_signal_all_seven() {
    assert_eq!(AcquisitionSignal::ALL.len(), 7);
}

#[test]
fn enrichment_acquisition_signal_no_duplicate_display() {
    let mut displays = std::collections::BTreeSet::new();
    for sig in AcquisitionSignal::ALL {
        assert!(displays.insert(sig.to_string()));
    }
}

// ---------------------------------------------------------------------------
// ExperimentProposal: seal sensitivity and construction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_proposal_same_inputs_same_hash() {
    let a = ExperimentProposal::new(
        "dup-test".to_string(),
        ExperimentKind::HoleFilling,
        "cell-hole".to_string(),
        vec![(AcquisitionSignal::PersistentHole, 700_000)],
        600_000,
        400_000,
        200_000,
        "test duplication".to_string(),
    );
    let b = ExperimentProposal::new(
        "dup-test".to_string(),
        ExperimentKind::HoleFilling,
        "cell-hole".to_string(),
        vec![(AcquisitionSignal::PersistentHole, 700_000)],
        600_000,
        400_000,
        200_000,
        "test duplication".to_string(),
    );
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_proposal_empty_signals_accepted() {
    let p = ExperimentProposal::new(
        "empty-sig".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-empty".to_string(),
        vec![],
        500_000,
        300_000,
        100_000,
        "no signals".to_string(),
    );
    assert!(p.signals.is_empty());
    assert_ne!(
        p.content_hash,
        frankenengine_engine::hash_tiers::ContentHash::compute(b"")
    );
}

#[test]
fn enrichment_proposal_many_signals() {
    let signals: Vec<(AcquisitionSignal, u64)> = AcquisitionSignal::ALL
        .iter()
        .map(|s| (*s, 142_857))
        .collect();
    let p = ExperimentProposal::new(
        "all-signals".to_string(),
        ExperimentKind::CoverageRecovery,
        "cell-all".to_string(),
        signals,
        1_000_000,
        500_000,
        200_000,
        "all seven signals".to_string(),
    );
    assert_eq!(p.signals.len(), 7);
}

#[test]
fn enrichment_proposal_zero_cost_seals_correctly() {
    let p = ExperimentProposal::new(
        "zero-cost".to_string(),
        ExperimentKind::ShiftValidation,
        "cell-free".to_string(),
        vec![(AcquisitionSignal::StalenessAlarm, 500_000)],
        300_000,
        200_000,
        0,
        "free experiment".to_string(),
    );
    assert_eq!(p.estimated_cost_millionths, 0);
    assert_ne!(
        p.content_hash,
        frankenengine_engine::hash_tiers::ContentHash::compute(b"")
    );
}

#[test]
fn enrichment_proposal_display_contains_gain_and_cost() {
    let p = make_proposal(
        "disp-gc",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        500_000,
        750_000,
        250_000,
    );
    let display = format!("{p}");
    assert!(display.contains("750000"), "should contain gain value");
    assert!(display.contains("250000"), "should contain cost value");
}

#[test]
fn enrichment_proposal_clone_preserves_hash() {
    let p = make_proposal(
        "clone-hash",
        ExperimentKind::DarkMatterExploration,
        AcquisitionSignal::SemanticDarkMatter,
        900_000,
        800_000,
        150_000,
    );
    let cloned = p.clone();
    assert_eq!(p.content_hash, cloned.content_hash);
    assert_eq!(p, cloned);
}

// ---------------------------------------------------------------------------
// score_proposal: additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_score_proposal_zero_cost_produces_large_adjusted() {
    let p = ExperimentProposal::new(
        "zero-c-score".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::LiveShiftPressure, MILLIONTHS)],
        MILLIONTHS,
        300_000,
        0,
        "zero cost".to_string(),
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    // cost is treated as 1 when 0, so cost_adjusted = raw * MILLIONTHS / 1
    assert!(
        score.cost_adjusted_millionths > score.raw_gain_millionths,
        "zero cost should yield very high adjusted score"
    );
}

#[test]
fn enrichment_score_proposal_missing_weight_uses_default() {
    let p = ExperimentProposal::new(
        "missing-w".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::RatchetGap, 500_000)],
        0,
        0,
        100_000,
        "weight lookup test".to_string(),
    );
    // Empty weights => all default to MILLIONTHS
    let score = acquisition_experiment_oracle::score_proposal(&p, &BTreeMap::new());
    // contribution = 500_000 * MILLIONTHS / MILLIONTHS = 500_000
    assert_eq!(score.raw_gain_millionths, 500_000);
}

#[test]
fn enrichment_score_proposal_zero_weight_zeroes_contribution() {
    let p = ExperimentProposal::new(
        "zero-w".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::LiveShiftPressure, 800_000)],
        0,
        0,
        100_000,
        "zero weight".to_string(),
    );
    let mut weights = BTreeMap::new();
    weights.insert("live_shift_pressure".to_string(), 0);
    let score = acquisition_experiment_oracle::score_proposal(&p, &weights);
    // contribution = 800_000 * 0 / MILLIONTHS = 0, raw = 0 + 0 (expected gain) = 0
    assert_eq!(score.raw_gain_millionths, 0);
}

#[test]
fn enrichment_score_proposal_multiple_signals_sum() {
    let p = ExperimentProposal::new(
        "multi-sum".to_string(),
        ExperimentKind::CoverageRecovery,
        "cell-a".to_string(),
        vec![
            (AcquisitionSignal::CoverageDebt, MILLIONTHS),
            (AcquisitionSignal::PersistentHole, MILLIONTHS),
            (AcquisitionSignal::RatchetGap, MILLIONTHS),
        ],
        0,
        0,
        100_000,
        "three full-strength signals".to_string(),
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    // Each contributes 1M => raw = 3M
    assert_eq!(score.raw_gain_millionths, 3_000_000);
}

#[test]
fn enrichment_score_proposal_dominant_with_single_signal() {
    let p = ExperimentProposal::new(
        "single-dom".to_string(),
        ExperimentKind::AdversarialProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::AdversarialOpportunity, 750_000)],
        0,
        0,
        100_000,
        "single signal".to_string(),
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    assert_eq!(
        score.dominant_signal,
        AcquisitionSignal::AdversarialOpportunity
    );
}

// ---------------------------------------------------------------------------
// AcquisitionScore serde and display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_acquisition_score_display_contains_dominant() {
    let p = make_proposal(
        "score-disp",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    let display = format!("{score}");
    assert!(display.contains("live_shift_pressure"));
}

#[test]
fn enrichment_acquisition_score_clone_eq() {
    let p = make_proposal(
        "score-clone",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    let cloned = score.clone();
    assert_eq!(score, cloned);
}

// ---------------------------------------------------------------------------
// rank_proposals: stability and edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rank_proposals_tie_broken_by_id() {
    // Two proposals with identical scores; sort should be deterministic by proposal_id
    let p1 = make_proposal(
        "aaa",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let p2 = make_proposal(
        "zzz",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let ranked = acquisition_experiment_oracle::rank_proposals(vec![p1, p2], &default_weights());
    // Same cost-adjusted score, so alphabetical by proposal_id
    assert_eq!(ranked[0].0.proposal_id, "aaa");
    assert_eq!(ranked[1].0.proposal_id, "zzz");
}

#[test]
fn enrichment_rank_proposals_empty() {
    let ranked = acquisition_experiment_oracle::rank_proposals(vec![], &default_weights());
    assert!(ranked.is_empty());
}

#[test]
fn enrichment_rank_proposals_ten_entries() {
    let proposals: Vec<ExperimentProposal> = (0..10)
        .map(|i| {
            make_proposal(
                &format!("r10-{i}"),
                ExperimentKind::BoardCellProbe,
                AcquisitionSignal::CoverageDebt,
                (i as u64 + 1) * 100_000,
                400_000,
                100_000,
            )
        })
        .collect();
    let ranked = acquisition_experiment_oracle::rank_proposals(proposals, &default_weights());
    assert_eq!(ranked.len(), 10);
    for i in 0..9 {
        assert!(ranked[i].1.cost_adjusted_millionths >= ranked[i + 1].1.cost_adjusted_millionths);
    }
}

// ---------------------------------------------------------------------------
// select_experiments: additional budget and selection
// ---------------------------------------------------------------------------

#[test]
fn enrichment_select_experiments_skips_only_too_expensive() {
    // 3 proposals: two cheap (100K each) and one expensive (900K)
    // budget = 250K => only the two cheap ones fit
    let cheap1 = make_proposal(
        "sk-cheap1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let cheap2 = make_proposal(
        "sk-cheap2",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        700_000,
        400_000,
        100_000,
    );
    let expensive = make_proposal(
        "sk-expensive",
        ExperimentKind::DarkMatterExploration,
        AcquisitionSignal::SemanticDarkMatter,
        900_000,
        600_000,
        900_000,
    );
    let plan = acquisition_experiment_oracle::select_experiments(
        vec![cheap1, cheap2, expensive],
        250_000,
        &default_weights(),
    )
    .unwrap();
    assert_eq!(plan.proposals.len(), 2);
    for p in &plan.proposals {
        assert_ne!(p.proposal_id, "sk-expensive");
    }
}

#[test]
fn enrichment_select_experiments_plan_scores_match_proposals() {
    let proposals: Vec<ExperimentProposal> = (0..4)
        .map(|i| {
            make_proposal(
                &format!("match-{i}"),
                ExperimentKind::BoardCellProbe,
                AcquisitionSignal::CoverageDebt,
                500_000 + i as u64 * 100_000,
                400_000,
                100_000,
            )
        })
        .collect();
    let plan = acquisition_experiment_oracle::select_experiments(
        proposals,
        10_000_000,
        &default_weights(),
    )
    .unwrap();
    for (i, score) in plan.scores.iter().enumerate() {
        assert_eq!(
            score.proposal_id, plan.proposals[i].proposal_id,
            "score[{i}] must match proposal[{i}]"
        );
    }
}

#[test]
fn enrichment_select_experiments_total_gain_correct() {
    let p1 = make_proposal(
        "gain-a",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        300_000,
        100_000,
    );
    let p2 = make_proposal(
        "gain-b",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::PersistentHole,
        500_000,
        700_000,
        200_000,
    );
    let plan = acquisition_experiment_oracle::select_experiments(
        vec![p1, p2],
        1_000_000,
        &default_weights(),
    )
    .unwrap();
    let sum_gain: u64 = plan
        .proposals
        .iter()
        .map(|p| p.expected_information_gain_millionths)
        .sum();
    assert_eq!(plan.total_expected_gain_millionths, sum_gain);
}

#[test]
fn enrichment_select_experiments_single_just_fits() {
    let p = make_proposal(
        "just-fits",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        999_999,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 999_999, &default_weights())
            .unwrap();
    assert_eq!(plan.proposals.len(), 1);
    assert_eq!(plan.budget_remaining_millionths, 0);
}

#[test]
fn enrichment_select_experiments_one_over_budget_fails() {
    let p = make_proposal(
        "over-budget",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        1_000_001,
    );
    let result =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights());
    assert!(matches!(result, Err(AcquisitionError::BudgetExhausted)));
}

// ---------------------------------------------------------------------------
// ExperimentPlan: serde, display, seal
// ---------------------------------------------------------------------------

#[test]
fn enrichment_experiment_plan_display_contains_epoch() {
    let p = make_proposal(
        "plan-epoch",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights())
            .unwrap();
    let display = format!("{plan}");
    assert!(display.contains("epoch="));
}

#[test]
fn enrichment_experiment_plan_display_contains_experiment_count() {
    let proposals: Vec<ExperimentProposal> = (0..3)
        .map(|i| {
            make_proposal(
                &format!("pc-{i}"),
                ExperimentKind::BoardCellProbe,
                AcquisitionSignal::CoverageDebt,
                500_000,
                400_000,
                100_000,
            )
        })
        .collect();
    let plan =
        acquisition_experiment_oracle::select_experiments(proposals, 1_000_000, &default_weights())
            .unwrap();
    let display = format!("{plan}");
    assert!(display.contains("experiments=3"));
}

#[test]
fn enrichment_experiment_plan_seal_changes_hash() {
    use frankenengine_engine::acquisition_experiment_oracle::ExperimentPlan;
    use frankenengine_engine::security_epoch::SecurityEpoch;

    let p = make_proposal(
        "seal-test",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());
    let empty_hash = frankenengine_engine::hash_tiers::ContentHash::compute(b"");

    let mut plan = ExperimentPlan {
        plan_id: "manual-plan".to_string(),
        epoch: SecurityEpoch::GENESIS,
        proposals: vec![p],
        scores: vec![score],
        budget_remaining_millionths: 900_000,
        total_expected_gain_millionths: 500_000,
        content_hash: empty_hash,
    };
    plan.seal();
    assert_ne!(
        plan.content_hash, empty_hash,
        "seal should set a non-empty hash"
    );
}

// ---------------------------------------------------------------------------
// ExperimentOutcome: additional cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_experiment_outcome_exact_match_no_surprise() {
    let p = make_proposal(
        "exact-match",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 500_000);
    assert_eq!(outcome.surprise_millionths, 0);
    assert_eq!(outcome.regret_millionths, 0);
}

#[test]
fn enrichment_experiment_outcome_underestimate_zero_regret() {
    let p = make_proposal(
        "under-est",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        500_000,
        200_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 800_000);
    assert_eq!(outcome.regret_millionths, 0);
    assert_eq!(outcome.surprise_millionths, 600_000);
}

#[test]
fn enrichment_experiment_outcome_display_contains_actual() {
    let p = make_proposal(
        "disp-actual",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let outcome = acquisition_experiment_oracle::record_outcome(&p, 350_000);
    let display = format!("{outcome}");
    assert!(display.contains("350000"));
}

#[test]
fn enrichment_experiment_outcome_seal_idempotent() {
    let p = make_proposal(
        "seal-out",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let mut outcome = acquisition_experiment_oracle::record_outcome(&p, 400_000);
    let hash1 = outcome.content_hash;
    outcome.seal();
    assert_eq!(hash1, outcome.content_hash);
}

// ---------------------------------------------------------------------------
// OracleCalibration: additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_oracle_calibration_empty_outcomes() {
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[], &[]);
    assert_eq!(cal.predictions_count, 0);
    assert_eq!(cal.mean_absolute_error_millionths, 0);
    assert_eq!(cal.bias_millionths, 0);
}

#[test]
fn enrichment_oracle_calibration_positive_bias() {
    // Over-prediction: expected > actual
    let p = make_proposal(
        "pos-bias",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        800_000,
        100_000,
    );
    let o = acquisition_experiment_oracle::record_outcome(&p, 200_000);
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[o], &[p]);
    assert!(
        cal.bias_millionths > 0,
        "over-prediction should give positive bias"
    );
}

#[test]
fn enrichment_oracle_calibration_negative_bias() {
    // Under-prediction: actual > expected
    let p = make_proposal(
        "neg-bias",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        200_000,
        100_000,
    );
    let o = acquisition_experiment_oracle::record_outcome(&p, 900_000);
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[o], &[p]);
    assert!(
        cal.bias_millionths < 0,
        "under-prediction should give negative bias"
    );
}

#[test]
fn enrichment_oracle_calibration_display() {
    let p = make_proposal(
        "cal-disp",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let o = acquisition_experiment_oracle::record_outcome(&p, 500_000);
    let cal = acquisition_experiment_oracle::calibrate_oracle(&[o], &[p]);
    let display = format!("{cal}");
    assert!(display.contains("Calibration"));
    assert!(display.contains("cal-disp") || display.contains("n1"));
}

#[test]
fn enrichment_oracle_calibration_seal_idempotent() {
    let p = make_proposal(
        "cal-seal",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let o = acquisition_experiment_oracle::record_outcome(&p, 500_000);
    let mut cal = acquisition_experiment_oracle::calibrate_oracle(&[o], &[p]);
    let hash1 = cal.content_hash;
    cal.seal();
    assert_eq!(hash1, cal.content_hash);
}

#[test]
fn enrichment_oracle_calibration_multiple_perfect_predictions() {
    let proposals: Vec<ExperimentProposal> = (0..5)
        .map(|i| {
            make_proposal(
                &format!("perf-{i}"),
                ExperimentKind::BoardCellProbe,
                AcquisitionSignal::CoverageDebt,
                500_000,
                (i as u64 + 1) * 200_000,
                100_000,
            )
        })
        .collect();
    let outcomes: Vec<_> = proposals
        .iter()
        .map(|p| {
            acquisition_experiment_oracle::record_outcome(p, p.expected_information_gain_millionths)
        })
        .collect();
    let cal = acquisition_experiment_oracle::calibrate_oracle(&outcomes, &proposals);
    assert_eq!(cal.predictions_count, 5);
    assert_eq!(cal.mean_absolute_error_millionths, 0);
    assert_eq!(cal.bias_millionths, 0);
}

// ---------------------------------------------------------------------------
// compute_regret: boundary and identity tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compute_regret_equal_values() {
    assert_eq!(
        acquisition_experiment_oracle::compute_regret(500_000, 500_000),
        0
    );
}

#[test]
fn enrichment_compute_regret_max_u64_expected() {
    // Should not panic with saturating subtraction
    let result = acquisition_experiment_oracle::compute_regret(u64::MAX, 0);
    assert_eq!(result, u64::MAX);
}

#[test]
fn enrichment_compute_regret_max_u64_actual() {
    let result = acquisition_experiment_oracle::compute_regret(0, u64::MAX);
    assert_eq!(result, 0);
}

// ---------------------------------------------------------------------------
// combine_signal_strengths: more patterns
// ---------------------------------------------------------------------------

#[test]
fn enrichment_combine_signal_strengths_single_zero() {
    assert_eq!(
        acquisition_experiment_oracle::combine_signal_strengths(&[0]),
        0
    );
}

#[test]
fn enrichment_combine_signal_strengths_descending_already_sorted() {
    let result =
        acquisition_experiment_oracle::combine_signal_strengths(&[1_000_000, 500_000, 250_000]);
    // Already sorted desc: 1M + 500K/2 + 250K/4 = 1M + 250K + 62500 = 1_312_500
    assert_eq!(result, 1_312_500);
}

#[test]
fn enrichment_combine_signal_strengths_ascending_order() {
    // Ascending; should be sorted internally so result = same as descending input
    let result =
        acquisition_experiment_oracle::combine_signal_strengths(&[250_000, 500_000, 1_000_000]);
    assert_eq!(result, 1_312_500);
}

#[test]
fn enrichment_combine_signal_strengths_five_equal() {
    let combined = acquisition_experiment_oracle::combine_signal_strengths(&[
        MILLIONTHS, MILLIONTHS, MILLIONTHS, MILLIONTHS, MILLIONTHS,
    ]);
    // 1M + 500K + 250K + 125K + 62500 = 1_937_500
    assert_eq!(combined, 1_937_500);
}

// ---------------------------------------------------------------------------
// information_density: edge and boundary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_information_density_zero_cost() {
    let p = ExperimentProposal::new(
        "density-0c".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        500_000,
        300_000,
        0,
        "free test".to_string(),
    );
    let density = acquisition_experiment_oracle::information_density(&p);
    // cost=0 => treated as 1, density = 500_000 * 1M / 1 = 500_000_000_000
    assert_eq!(density, 500_000_000_000);
}

#[test]
fn enrichment_information_density_large_cost_small_gain() {
    let p = ExperimentProposal::new(
        "density-lg".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        1,
        0,
        MILLIONTHS,
        "tiny gain big cost".to_string(),
    );
    let density = acquisition_experiment_oracle::information_density(&p);
    // 1 * 1M / 1M = 1
    assert_eq!(density, 1);
}

// ---------------------------------------------------------------------------
// is_justified: additional threshold tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_is_justified_zero_threshold_always_true() {
    let p = make_proposal(
        "thresh-0",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        0,
        MILLIONTHS,
    );
    // threshold=0 => min_gain = cost * 0 / MILLIONTHS = 0
    assert!(acquisition_experiment_oracle::is_justified(&p, 0));
}

#[test]
fn enrichment_is_justified_fractional_threshold() {
    let p = ExperimentProposal::new(
        "frac-thresh".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        250_000,
        0,
        MILLIONTHS,
        "fractional threshold".to_string(),
    );
    // threshold = 0.5 => min_gain = 1M * 500K / 1M = 500K
    // gain(250K) < 500K => not justified
    assert!(!acquisition_experiment_oracle::is_justified(&p, 500_000));
}

#[test]
fn enrichment_is_justified_exactly_below_threshold() {
    let p = ExperimentProposal::new(
        "just-below".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![],
        99_999,
        0,
        100_000,
        "one below".to_string(),
    );
    // threshold=1.0 => min_gain = 100_000 * 1M / 1M = 100_000
    // gain(99_999) < 100_000 => not justified
    assert!(!acquisition_experiment_oracle::is_justified(&p, MILLIONTHS));
}

// ---------------------------------------------------------------------------
// diversity_bonus: boundary and unusual inputs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_diversity_bonus_three_kinds() {
    let proposals = vec![
        make_proposal(
            "db3-0",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::CoverageDebt,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "db3-1",
            ExperimentKind::AdversarialProbe,
            AcquisitionSignal::AdversarialOpportunity,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "db3-2",
            ExperimentKind::ShiftValidation,
            AcquisitionSignal::StalenessAlarm,
            500_000,
            400_000,
            100_000,
        ),
    ];
    let bonus = acquisition_experiment_oracle::diversity_bonus(&proposals);
    assert_eq!(bonus, 3 * MILLIONTHS / 7);
}

#[test]
fn enrichment_diversity_bonus_monotonically_increases_with_kinds() {
    let mut proposals = Vec::new();
    let mut prev_bonus = 0u64;
    for (i, kind) in ExperimentKind::ALL.iter().enumerate() {
        proposals.push(make_proposal(
            &format!("mono-{i}"),
            *kind,
            AcquisitionSignal::CoverageDebt,
            500_000,
            400_000,
            100_000,
        ));
        let bonus = acquisition_experiment_oracle::diversity_bonus(&proposals);
        assert!(
            bonus >= prev_bonus,
            "adding kind {:?} should not decrease bonus: {} < {}",
            kind,
            bonus,
            prev_bonus
        );
        prev_bonus = bonus;
    }
}

// ---------------------------------------------------------------------------
// staleness_penalty: more edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_staleness_penalty_linear_growth() {
    // age=15, max=10 => over=5 => penalty = 5 * 1M / 10 = 500_000
    assert_eq!(
        acquisition_experiment_oracle::staleness_penalty(15, 10),
        500_000
    );
}

#[test]
fn enrichment_staleness_penalty_large_age_capped() {
    let penalty = acquisition_experiment_oracle::staleness_penalty(100_000, 10);
    assert_eq!(
        penalty, MILLIONTHS,
        "penalty should never exceed MILLIONTHS"
    );
}

#[test]
fn enrichment_staleness_penalty_max_fresh_one() {
    // age=2, max=1 => over=1, penalty = 1 * 1M / 1 = 1M (capped)
    assert_eq!(
        acquisition_experiment_oracle::staleness_penalty(2, 1),
        MILLIONTHS
    );
}

// ---------------------------------------------------------------------------
// partition_by_kind: reference stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_partition_by_kind_preserves_proposal_ids() {
    let p1 = make_proposal(
        "part-id1",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let p2 = make_proposal(
        "part-id2",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::LiveShiftPressure,
        800_000,
        500_000,
        100_000,
    );
    let proposals = [p1, p2];
    let partitioned = acquisition_experiment_oracle::partition_by_kind(&proposals);
    let board_probes = &partitioned[&ExperimentKind::BoardCellProbe];
    let ids: Vec<&str> = board_probes
        .iter()
        .map(|p| p.proposal_id.as_str())
        .collect();
    assert!(ids.contains(&"part-id1"));
    assert!(ids.contains(&"part-id2"));
}

// ---------------------------------------------------------------------------
// find_dominant_signal: aggregation across proposals
// ---------------------------------------------------------------------------

#[test]
fn enrichment_find_dominant_signal_aggregates_across_proposals() {
    // Signal A has 200K in p1 and 400K in p2 = 600K total
    // Signal B has 500K in p3 = 500K total
    // Dominant should be A
    let p1 = ExperimentProposal::new(
        "agg1".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-a".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 200_000)],
        0,
        0,
        100_000,
        "test".to_string(),
    );
    let p2 = ExperimentProposal::new(
        "agg2".to_string(),
        ExperimentKind::BoardCellProbe,
        "cell-b".to_string(),
        vec![(AcquisitionSignal::CoverageDebt, 400_000)],
        0,
        0,
        100_000,
        "test".to_string(),
    );
    let p3 = ExperimentProposal::new(
        "agg3".to_string(),
        ExperimentKind::CorpusAddition,
        "cell-c".to_string(),
        vec![(AcquisitionSignal::PersistentHole, 500_000)],
        0,
        0,
        100_000,
        "test".to_string(),
    );
    let dominant = acquisition_experiment_oracle::find_dominant_signal(&[p1, p2, p3]);
    assert_eq!(dominant, Some(AcquisitionSignal::CoverageDebt));
}

// ---------------------------------------------------------------------------
// allocate_budget_by_kind: proportional allocation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_allocate_budget_proportional_3_1() {
    // 3 proposals of kind A, 1 of kind B => A gets 3/4 budget, B gets 1/4
    let proposals: Vec<ExperimentProposal> = (0..3)
        .map(|i| {
            make_proposal(
                &format!("prop-a-{i}"),
                ExperimentKind::BoardCellProbe,
                AcquisitionSignal::CoverageDebt,
                500_000,
                400_000,
                100_000,
            )
        })
        .chain(std::iter::once(make_proposal(
            "prop-b-0",
            ExperimentKind::CorpusAddition,
            AcquisitionSignal::PersistentHole,
            500_000,
            400_000,
            100_000,
        )))
        .collect();
    let alloc = acquisition_experiment_oracle::allocate_budget_by_kind(&proposals, 1_000_000);
    let total: u64 = alloc.values().sum();
    assert_eq!(total, 1_000_000);
    // BoardCellProbe should get approximately 750_000
    assert!(alloc[&ExperimentKind::BoardCellProbe] >= 700_000);
}

#[test]
fn enrichment_allocate_budget_two_equal_kinds() {
    let p1 = make_proposal(
        "eq-a",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let p2 = make_proposal(
        "eq-b",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::PersistentHole,
        500_000,
        400_000,
        100_000,
    );
    let alloc = acquisition_experiment_oracle::allocate_budget_by_kind(&[p1, p2], 1_000_000);
    let total: u64 = alloc.values().sum();
    assert_eq!(total, 1_000_000);
}

// ---------------------------------------------------------------------------
// exploration_ratio: three exploration kinds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_exploration_ratio_three_exploration_kinds() {
    let proposals = vec![
        make_proposal(
            "explore-dm",
            ExperimentKind::DarkMatterExploration,
            AcquisitionSignal::SemanticDarkMatter,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "explore-hf",
            ExperimentKind::HoleFilling,
            AcquisitionSignal::RatchetGap,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "explore-cr",
            ExperimentKind::CoverageRecovery,
            AcquisitionSignal::PersistentHole,
            500_000,
            400_000,
            100_000,
        ),
    ];
    let ratio = acquisition_experiment_oracle::exploration_ratio(&proposals);
    assert_eq!(ratio, MILLIONTHS); // 100% exploration
}

#[test]
fn enrichment_exploration_ratio_adversarial_is_exploitation() {
    let p = make_proposal(
        "adv-exploit",
        ExperimentKind::AdversarialProbe,
        AcquisitionSignal::AdversarialOpportunity,
        700_000,
        500_000,
        100_000,
    );
    assert_eq!(acquisition_experiment_oracle::exploration_ratio(&[p]), 0);
}

#[test]
fn enrichment_exploration_ratio_corpus_addition_is_exploitation() {
    let p = make_proposal(
        "corpus-exploit",
        ExperimentKind::CorpusAddition,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    assert_eq!(acquisition_experiment_oracle::exploration_ratio(&[p]), 0);
}

// ---------------------------------------------------------------------------
// validate_plan: additional checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_plan_detects_gain_mismatch() {
    use frankenengine_engine::acquisition_experiment_oracle::ExperimentPlan;
    use frankenengine_engine::security_epoch::SecurityEpoch;

    let p = make_proposal(
        "gain-mis",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );
    let score = acquisition_experiment_oracle::score_proposal(&p, &default_weights());

    let plan = ExperimentPlan {
        plan_id: "gain-mismatch-plan".to_string(),
        epoch: SecurityEpoch::GENESIS,
        proposals: vec![p],
        scores: vec![score],
        budget_remaining_millionths: 900_000,
        total_expected_gain_millionths: 999_999, // wrong
        content_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    };
    let errors = acquisition_experiment_oracle::validate_plan(&plan);
    assert!(
        errors.iter().any(|e| e.contains("total_expected_gain")),
        "should detect gain mismatch: {:?}",
        errors
    );
}

#[test]
fn enrichment_validate_plan_detects_count_mismatch() {
    use frankenengine_engine::acquisition_experiment_oracle::ExperimentPlan;
    use frankenengine_engine::security_epoch::SecurityEpoch;

    let p = make_proposal(
        "cnt-mis",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        500_000,
        100_000,
    );

    let plan = ExperimentPlan {
        plan_id: "count-mismatch".to_string(),
        epoch: SecurityEpoch::GENESIS,
        proposals: vec![p],
        scores: vec![], // empty scores => mismatch
        budget_remaining_millionths: 900_000,
        total_expected_gain_millionths: 500_000,
        content_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    };
    let errors = acquisition_experiment_oracle::validate_plan(&plan);
    assert!(
        errors.iter().any(|e| e.contains("score count")),
        "should detect proposal/score count mismatch: {:?}",
        errors
    );
}

// ---------------------------------------------------------------------------
// summarise_plan: content verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summarise_plan_contains_budget_remaining() {
    let p = make_proposal(
        "sum-budget",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights())
            .unwrap();
    let summary = acquisition_experiment_oracle::summarise_plan(&plan);
    assert!(summary.contains("Budget remaining"));
}

#[test]
fn enrichment_summarise_plan_contains_content_hash() {
    let p = make_proposal(
        "sum-hash",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        400_000,
        100_000,
    );
    let plan =
        acquisition_experiment_oracle::select_experiments(vec![p], 1_000_000, &default_weights())
            .unwrap();
    let summary = acquisition_experiment_oracle::summarise_plan(&plan);
    assert!(summary.contains("Content hash"));
}

// ---------------------------------------------------------------------------
// Manifest: additional invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_covers_all_experiment_kinds() {
    let manifest = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    let mut kinds = std::collections::BTreeSet::new();
    for p in &manifest.proposals {
        kinds.insert(p.kind);
    }
    assert_eq!(
        kinds.len(),
        ExperimentKind::ALL.len(),
        "manifest should cover all experiment kinds"
    );
}

#[test]
fn enrichment_manifest_proposals_all_have_non_zero_cost() {
    let manifest = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    for p in &manifest.proposals {
        assert!(
            p.estimated_cost_millionths > 0,
            "manifest proposal {} should have non-zero cost",
            p.proposal_id
        );
    }
}

#[test]
fn enrichment_manifest_plan_id_contains_bead() {
    let manifest = acquisition_experiment_oracle::franken_engine_acquisition_manifest();
    assert!(
        manifest.plan_id.contains("bd-1lsy"),
        "manifest plan_id should reference the bead: {}",
        manifest.plan_id
    );
}

// ---------------------------------------------------------------------------
// AcquisitionError: additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_acquisition_error_is_send_and_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<AcquisitionError>();
    assert_sync::<AcquisitionError>();
}

#[test]
fn enrichment_acquisition_error_clone_eq() {
    let e1 = AcquisitionError::InternalError("test clone".to_string());
    let e2 = e1.clone();
    assert_eq!(e1, e2);
}

#[test]
fn enrichment_acquisition_error_no_candidates_display_lowercase() {
    let e = AcquisitionError::NoCandidates;
    let display = format!("{e}");
    // The display should be human-readable
    assert!(display.contains("no candidate"));
}

#[test]
fn enrichment_acquisition_error_budget_exhausted_display() {
    let e = AcquisitionError::BudgetExhausted;
    let display = format!("{e}");
    assert!(display.contains("budget"));
}

// ---------------------------------------------------------------------------
// Cross-cutting: end-to-end with calibration feedback loop
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_pipeline_with_calibration_feedback() {
    // Create 5 proposals across different kinds
    let proposals: Vec<ExperimentProposal> = vec![
        make_proposal(
            "pipe-0",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::LiveShiftPressure,
            800_000,
            600_000,
            100_000,
        ),
        make_proposal(
            "pipe-1",
            ExperimentKind::CorpusAddition,
            AcquisitionSignal::CoverageDebt,
            600_000,
            400_000,
            150_000,
        ),
        make_proposal(
            "pipe-2",
            ExperimentKind::DarkMatterExploration,
            AcquisitionSignal::SemanticDarkMatter,
            700_000,
            500_000,
            200_000,
        ),
        make_proposal(
            "pipe-3",
            ExperimentKind::HoleFilling,
            AcquisitionSignal::PersistentHole,
            500_000,
            300_000,
            100_000,
        ),
        make_proposal(
            "pipe-4",
            ExperimentKind::AdversarialProbe,
            AcquisitionSignal::AdversarialOpportunity,
            900_000,
            700_000,
            250_000,
        ),
    ];

    // Step 1: Select
    let plan = acquisition_experiment_oracle::select_experiments(
        proposals.clone(),
        2_000_000,
        &default_weights(),
    )
    .unwrap();
    assert!(!plan.proposals.is_empty());
    let errors = acquisition_experiment_oracle::validate_plan(&plan);
    assert!(errors.is_empty());

    // Step 2: Record outcomes with varied accuracy
    let actuals = [500_000u64, 350_000, 600_000, 250_000, 1_200_000];
    let outcomes: Vec<_> = proposals
        .iter()
        .zip(actuals.iter())
        .map(|(p, &actual)| acquisition_experiment_oracle::record_outcome(p, actual))
        .collect();

    // Step 3: Calibrate
    let cal = acquisition_experiment_oracle::calibrate_oracle(&outcomes, &proposals);
    assert_eq!(cal.predictions_count, 5);
    assert!(cal.mean_absolute_error_millionths > 0);

    // Step 4: Summary is well-formed
    let summary = acquisition_experiment_oracle::summarise_plan(&plan);
    assert!(summary.contains("Experiment Plan"));
}

#[test]
fn enrichment_score_then_rank_then_select_agreement() {
    // Individual scores should match what rank_proposals produces
    let proposals = vec![
        make_proposal(
            "agree-a",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::LiveShiftPressure,
            800_000,
            500_000,
            100_000,
        ),
        make_proposal(
            "agree-b",
            ExperimentKind::CorpusAddition,
            AcquisitionSignal::CoverageDebt,
            400_000,
            300_000,
            200_000,
        ),
    ];
    let individual_scores: Vec<_> = proposals
        .iter()
        .map(|p| acquisition_experiment_oracle::score_proposal(p, &default_weights()))
        .collect();
    let ranked =
        acquisition_experiment_oracle::rank_proposals(proposals.clone(), &default_weights());

    // Every ranked entry should have the same raw_gain as the individual score
    for (proposal, score) in &ranked {
        let idx = proposals
            .iter()
            .position(|p| p.proposal_id == proposal.proposal_id)
            .unwrap();
        assert_eq!(
            score.raw_gain_millionths, individual_scores[idx].raw_gain_millionths,
            "raw_gain must match for {}",
            proposal.proposal_id
        );
    }
}

#[test]
fn enrichment_diversity_bonus_correlates_with_plan_quality() {
    let diverse_proposals = vec![
        make_proposal(
            "dq-0",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::LiveShiftPressure,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "dq-1",
            ExperimentKind::CorpusAddition,
            AcquisitionSignal::CoverageDebt,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "dq-2",
            ExperimentKind::AdversarialProbe,
            AcquisitionSignal::AdversarialOpportunity,
            500_000,
            400_000,
            100_000,
        ),
    ];
    let homogeneous_proposals = vec![
        make_proposal(
            "hq-0",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::CoverageDebt,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "hq-1",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::CoverageDebt,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "hq-2",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::CoverageDebt,
            500_000,
            400_000,
            100_000,
        ),
    ];
    let d_bonus = acquisition_experiment_oracle::diversity_bonus(&diverse_proposals);
    let h_bonus = acquisition_experiment_oracle::diversity_bonus(&homogeneous_proposals);
    assert!(d_bonus > h_bonus);
}

#[test]
fn enrichment_exploration_and_diversity_bonus_on_same_plan() {
    let proposals = vec![
        make_proposal(
            "ed-0",
            ExperimentKind::DarkMatterExploration,
            AcquisitionSignal::SemanticDarkMatter,
            500_000,
            400_000,
            100_000,
        ),
        make_proposal(
            "ed-1",
            ExperimentKind::BoardCellProbe,
            AcquisitionSignal::CoverageDebt,
            500_000,
            400_000,
            100_000,
        ),
    ];
    let exploration = acquisition_experiment_oracle::exploration_ratio(&proposals);
    let diversity = acquisition_experiment_oracle::diversity_bonus(&proposals);
    // 50% exploration
    assert_eq!(exploration, 500_000);
    // 2 / 7 kinds
    assert_eq!(diversity, 2 * MILLIONTHS / 7);
}

#[test]
fn enrichment_information_density_ordering_matches_score_ranking() {
    // High density proposal should score higher after cost adjustment
    let high_density = make_proposal(
        "hd",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        900_000,
        50_000,
    );
    let low_density = make_proposal(
        "ld",
        ExperimentKind::BoardCellProbe,
        AcquisitionSignal::CoverageDebt,
        500_000,
        100_000,
        500_000,
    );
    let hd_density = acquisition_experiment_oracle::information_density(&high_density);
    let ld_density = acquisition_experiment_oracle::information_density(&low_density);
    assert!(hd_density > ld_density);

    let hd_score = acquisition_experiment_oracle::score_proposal(&high_density, &default_weights());
    let ld_score = acquisition_experiment_oracle::score_proposal(&low_density, &default_weights());
    assert!(hd_score.cost_adjusted_millionths > ld_score.cost_adjusted_millionths);
}

#[test]
fn enrichment_staleness_penalty_increases_need_for_shift_validation() {
    // A stale proposal should have higher exploration value
    let fresh_penalty = acquisition_experiment_oracle::staleness_penalty(5, 10);
    let stale_penalty = acquisition_experiment_oracle::staleness_penalty(50, 10);
    assert_eq!(fresh_penalty, 0);
    assert!(stale_penalty > 0);
    assert!(stale_penalty > fresh_penalty);
}
