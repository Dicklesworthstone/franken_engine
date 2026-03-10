#![forbid(unsafe_code)]
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

use std::{
    collections::{BTreeSet, HashSet},
    fs,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

const CONTRACT_SCHEMA_VERSION: &str = "frx.pilot-rollout-harness.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/frx_pilot_rollout_harness_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PilotRolloutHarnessContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    rgc_alignment: RgcAlignment,
    track: Track,
    pilot_portfolio: PilotPortfolio,
    experiment_harness: ExperimentHarness,
    off_policy_evaluation: OffPolicyEvaluation,
    sequential_monitoring: SequentialMonitoring,
    rollout_phases: RolloutPhases,
    readiness_inputs: ReadinessInputs,
    artifact_contract: ArtifactContract,
    incident_linkage: IncidentLinkage,
    required_structured_log_fields: Vec<String>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RgcAlignment {
    bead_id: String,
    track_id: String,
    relationship: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Track {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PilotPortfolio {
    strata: Vec<PilotStratum>,
    stratification_required: bool,
    fail_closed_on_unclassified_workload: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PilotStratum {
    stratum_id: String,
    workload_archetype: String,
    risk_tier: String,
    target_share_bps: u32,
    inclusion_criteria: Vec<String>,
    exclusion_criteria: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExperimentHarness {
    modes: Vec<String>,
    deterministic_assignment_required: bool,
    required_assignment_fields: Vec<String>,
    required_observation_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OffPolicyEvaluation {
    estimators: Vec<String>,
    propensity_clip_min_millionths: u64,
    minimum_effective_sample_size: u64,
    require_baseline_predictions_for_dr: bool,
    fail_closed_on_missing_propensity: bool,
    fail_closed_on_weight_explosion: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SequentialMonitoring {
    evidence_mode: String,
    decision_actions: Vec<String>,
    thresholds_millionths: Thresholds,
    require_loss_aware_decision_path: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RolloutPhases {
    phase_order: Vec<String>,
    fail_closed_on_missing_phase_exit_scorecard: bool,
    require_forced_regression_drill: bool,
    phases: Vec<RolloutPhase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RolloutPhase {
    phase_id: String,
    user_traffic_bps: u32,
    phase_exit_scorecard_id: String,
    required_readiness_inputs: Vec<String>,
    promotion_requirements: Vec<String>,
    rollback_trigger_ids: Vec<String>,
    automatic_rollback_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReadinessInputs {
    required_inputs: Vec<String>,
    fail_closed_on_missing_inputs: bool,
    require_remediation_queue_for_blocked_workloads: bool,
    require_support_bundle_linkage: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ArtifactContract {
    artifact_root: String,
    required_files: Vec<String>,
    require_phase_exit_scorecard_per_phase: bool,
    require_quantitative_thresholds: bool,
    require_signed_promotion_decisions: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Thresholds {
    promote_min_confidence: u64,
    stop_max_regret: u64,
    rollback_incident_delta: u64,
    rollback_tail_latency_delta: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IncidentLinkage {
    required_fields: Vec<String>,
    require_replay_bundle: bool,
    require_evidence_bundle: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> PilotRolloutHarnessContract {
    serde_json::from_str(CONTRACT_JSON).expect("pilot rollout harness json must parse")
}

#[test]
fn frx_09_1_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_PILOT_ROLLOUT_HARNESS_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Pilot App Program and A/B Rollout Harness v1",
        "## Scope",
        "## Pilot Portfolio Stratification",
        "## A/B and Shadow-Run Harness Contract",
        "## Telemetry Contract for Causal and Off-Policy Safety Analysis",
        "## Off-Policy Evaluator Contract (IPS + Doubly Robust)",
        "## Sequential-Valid Monitoring and Decision Policies",
        "## Rollout Phase Contract (Shadow -> Canary -> Active)",
        "## Migration Readiness Inputs and Remediation Queue",
        "## Incident Linkage and Replay/Evidence Artifacts",
        "## Deterministic Logging and Artifact Contract",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn frx_09_1_contract_is_versioned_and_track_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-mjh3.9.1");
    assert_eq!(contract.generated_by, "bd-mjh3.9.1");
    assert_eq!(contract.track.id, "FRX-09.1");
    assert!(contract.track.name.contains("Pilot App Program"));
    assert!(contract.generated_at_utc.ends_with('Z'));
    assert_eq!(contract.rgc_alignment.bead_id, "bd-1lsy.10.3");
    assert_eq!(contract.rgc_alignment.track_id, "RGC-903");
    assert!(
        contract
            .rgc_alignment
            .relationship
            .contains("dependency_safe_prework")
    );
}

#[test]
fn frx_09_1_pilot_portfolio_is_stratified_and_actionable() {
    let contract = parse_contract();
    let portfolio = contract.pilot_portfolio;

    assert!(portfolio.stratification_required);
    assert!(portfolio.fail_closed_on_unclassified_workload);
    assert!(
        portfolio.strata.len() >= 4,
        "expected at least four pilot strata"
    );

    let mut stratum_ids = HashSet::new();
    let mut risk_tiers = HashSet::new();
    let total_share_bps: u32 = portfolio.strata.iter().map(|s| s.target_share_bps).sum();
    assert_eq!(total_share_bps, 10_000, "pilot shares must sum to 100%");

    for stratum in portfolio.strata {
        assert!(stratum_ids.insert(stratum.stratum_id.clone()));
        assert!(!stratum.workload_archetype.trim().is_empty());
        assert!(!stratum.risk_tier.trim().is_empty());
        assert!(risk_tiers.insert(stratum.risk_tier));
        assert!(
            !stratum.inclusion_criteria.is_empty(),
            "stratum must define inclusion criteria"
        );
        assert!(
            !stratum.exclusion_criteria.is_empty(),
            "stratum must define exclusion criteria"
        );
    }

    assert!(
        risk_tiers.contains("low")
            && risk_tiers.contains("medium")
            && risk_tiers.contains("high")
            && risk_tiers.contains("critical"),
        "risk tiers must cover low/medium/high/critical"
    );
}

#[test]
fn frx_09_1_harness_and_off_policy_requirements_are_complete() {
    let contract = parse_contract();

    let modes: BTreeSet<&str> = contract
        .experiment_harness
        .modes
        .iter()
        .map(String::as_str)
        .collect();
    let expected_modes: BTreeSet<&str> = ["ab_online", "shadow_run"].into_iter().collect();
    assert_eq!(modes, expected_modes);
    assert!(
        contract
            .experiment_harness
            .deterministic_assignment_required
    );

    for field in [
        "assignment_id",
        "cohort_id",
        "variant",
        "propensity_millionths",
        "policy_snapshot_id",
        "seed",
    ] {
        assert!(
            contract
                .experiment_harness
                .required_assignment_fields
                .iter()
                .any(|candidate| candidate == field),
            "missing assignment field: {field}"
        );
    }

    for field in [
        "scenario_id",
        "trace_id",
        "latency_us",
        "reward_millionths",
        "loss_millionths",
        "safety_outcome",
    ] {
        assert!(
            contract
                .experiment_harness
                .required_observation_fields
                .iter()
                .any(|candidate| candidate == field),
            "missing observation field: {field}"
        );
    }

    let estimators: BTreeSet<&str> = contract
        .off_policy_evaluation
        .estimators
        .iter()
        .map(String::as_str)
        .collect();
    let expected_estimators: BTreeSet<&str> = ["ips", "doubly_robust"].into_iter().collect();
    assert_eq!(estimators, expected_estimators);
    assert!(
        contract
            .off_policy_evaluation
            .propensity_clip_min_millionths
            > 0
            && contract
                .off_policy_evaluation
                .propensity_clip_min_millionths
                < 1_000_000
    );
    assert!(contract.off_policy_evaluation.minimum_effective_sample_size >= 100);
    assert!(
        contract
            .off_policy_evaluation
            .require_baseline_predictions_for_dr
    );
    assert!(
        contract
            .off_policy_evaluation
            .fail_closed_on_missing_propensity
    );
    assert!(
        contract
            .off_policy_evaluation
            .fail_closed_on_weight_explosion
    );
}

#[test]
fn frx_09_1_sequential_decisioning_and_incident_linkage_are_fail_closed() {
    let contract = parse_contract();

    assert_eq!(
        contract.sequential_monitoring.evidence_mode,
        "anytime_valid_e_process"
    );
    let actions: BTreeSet<&str> = contract
        .sequential_monitoring
        .decision_actions
        .iter()
        .map(String::as_str)
        .collect();
    let expected_actions: BTreeSet<&str> = ["stop", "promote", "rollback"].into_iter().collect();
    assert_eq!(actions, expected_actions);
    assert!(
        contract
            .sequential_monitoring
            .require_loss_aware_decision_path
    );
    assert!(
        contract
            .sequential_monitoring
            .thresholds_millionths
            .promote_min_confidence
            > 900_000
    );
    assert!(
        contract
            .sequential_monitoring
            .thresholds_millionths
            .stop_max_regret
            > 0
    );
    assert!(
        contract
            .sequential_monitoring
            .thresholds_millionths
            .rollback_incident_delta
            > 0
    );
    assert!(
        contract
            .sequential_monitoring
            .thresholds_millionths
            .rollback_tail_latency_delta
            > 0
    );

    let incident_fields: BTreeSet<&str> = contract
        .incident_linkage
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    let expected_incident_fields: BTreeSet<&str> = [
        "trace_id",
        "incident_id",
        "decision_id",
        "replay_bundle_id",
        "evidence_bundle_id",
        "run_manifest_id",
    ]
    .into_iter()
    .collect();
    assert_eq!(incident_fields, expected_incident_fields);
    assert!(contract.incident_linkage.require_replay_bundle);
    assert!(contract.incident_linkage.require_evidence_bundle);
}

#[test]
fn frx_09_1_rollout_phases_cover_shadow_canary_active_and_fail_closed() {
    let contract = parse_contract();
    let phases = &contract.rollout_phases;

    let expected_order: Vec<&str> = vec!["shadow", "canary", "active"];
    let actual_order: Vec<&str> = phases.phase_order.iter().map(String::as_str).collect();
    assert_eq!(actual_order, expected_order);
    assert!(phases.fail_closed_on_missing_phase_exit_scorecard);
    assert!(phases.require_forced_regression_drill);
    assert_eq!(phases.phases.len(), 3);

    for phase in &phases.phases {
        assert!(!phase.phase_exit_scorecard_id.trim().is_empty());
        assert!(!phase.required_readiness_inputs.is_empty());
        assert!(!phase.promotion_requirements.is_empty());
        assert!(!phase.rollback_trigger_ids.is_empty());
        assert!(phase.automatic_rollback_required);
    }

    let shadow = &phases.phases[0];
    let canary = &phases.phases[1];
    let active = &phases.phases[2];
    assert_eq!(shadow.phase_id, "shadow");
    assert_eq!(shadow.user_traffic_bps, 0);
    assert_eq!(canary.phase_id, "canary");
    assert!(canary.user_traffic_bps > 0 && canary.user_traffic_bps < 10_000);
    assert_eq!(active.phase_id, "active");
    assert_eq!(active.user_traffic_bps, 10_000);
}

#[test]
fn frx_09_1_readiness_inputs_and_artifact_contract_are_complete() {
    let contract = parse_contract();

    let readiness_inputs: BTreeSet<&str> = contract
        .readiness_inputs
        .required_inputs
        .iter()
        .map(String::as_str)
        .collect();
    let expected_inputs: BTreeSet<&str> = [
        "preflight_verdict",
        "compatibility_advisories",
        "onboarding_scorecard",
        "support_bundle_ref",
    ]
    .into_iter()
    .collect();
    assert_eq!(readiness_inputs, expected_inputs);
    assert!(contract.readiness_inputs.fail_closed_on_missing_inputs);
    assert!(
        contract
            .readiness_inputs
            .require_remediation_queue_for_blocked_workloads
    );
    assert!(contract.readiness_inputs.require_support_bundle_linkage);

    let required_files: BTreeSet<&str> = contract
        .artifact_contract
        .required_files
        .iter()
        .map(String::as_str)
        .collect();
    for file in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "phase_exit_scorecards.json",
        "migration_readiness_inputs.json",
        "blocked_workload_remediation_queue.json",
        "forced_regression_rollback_drill.json",
        "pilot_cohort_manifest.json",
    ] {
        assert!(
            required_files.contains(file),
            "missing artifact file: {file}"
        );
    }
    assert!(
        contract
            .artifact_contract
            .artifact_root
            .contains("artifacts/frx_pilot_rollout_harness")
    );
    assert!(
        contract
            .artifact_contract
            .require_phase_exit_scorecard_per_phase
    );
    assert!(contract.artifact_contract.require_quantitative_thresholds);
    assert!(
        contract
            .artifact_contract
            .require_signed_promotion_decisions
    );
}

#[test]
fn frx_09_1_contract_matches_logging_and_runtime_surfaces() {
    let contract = parse_contract();

    let required_fields: BTreeSet<&str> = [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "decision_path",
        "seed",
        "timing_us",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .collect();
    let actual_fields: BTreeSet<&str> = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(actual_fields, required_fields);

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|line| { line.contains("run_frx_pilot_rollout_harness_suite.sh ci") })
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|line| { line.contains("frx_pilot_rollout_harness_replay.sh") })
    );

    let harness_script =
        fs::read_to_string(repo_root().join("scripts/run_frx_pilot_rollout_harness_suite.sh"))
            .expect("pilot rollout harness suite script must exist");
    for snippet in [
        "phase_exit_scorecards.json",
        "migration_readiness_inputs.json",
        "blocked_workload_remediation_queue.json",
        "forced_regression_rollback_drill.json",
        "pilot_cohort_manifest.json",
    ] {
        assert!(
            harness_script.contains(snippet),
            "pilot rollout harness script missing: {snippet}"
        );
    }

    let activation =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/activation_lifecycle.rs"))
            .expect("activation_lifecycle source must exist");
    for snippet in ["RolloutPhase", "advance_rollout", "pub fn rollback"] {
        assert!(
            activation.contains(snippet),
            "activation_lifecycle missing: {snippet}"
        );
    }

    let decision_core =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/runtime_decision_core.rs"))
            .expect("runtime_decision_core source must exist");
    for snippet in [
        "Conformal calibration layer",
        "RoutingAction",
        "fallback:safe_mode",
    ] {
        assert!(
            decision_core.contains(snippet),
            "runtime_decision_core missing: {snippet}"
        );
    }

    let router =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/regret_bounded_router.rs"))
            .expect("regret_bounded_router source must exist");
    for snippet in [
        "counterfactual_rewards_millionths",
        "regret_within_bound",
        "exact_regret_available",
    ] {
        assert!(
            router.contains(snippet),
            "regret_bounded_router missing: {snippet}"
        );
    }

    let replayer =
        fs::read_to_string(repo_root().join("crates/franken-engine/src/forensic_replayer.rs"))
            .expect("forensic_replayer source must exist");
    for snippet in [
        "CounterfactualSpec",
        "pub fn counterfactual",
        "ReplayResult",
    ] {
        assert!(
            replayer.contains(snippet),
            "forensic_replayer missing: {snippet}"
        );
    }
}

#[test]
fn frx_09_1_strata_ids_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for stratum in &contract.pilot_portfolio.strata {
        assert!(
            seen.insert(&stratum.stratum_id),
            "duplicate stratum_id: {}",
            stratum.stratum_id
        );
    }
}

#[test]
fn frx_09_1_thresholds_are_positive() {
    let contract = parse_contract();
    let t = &contract.sequential_monitoring.thresholds_millionths;
    assert!(
        t.promote_min_confidence > 0,
        "promote_min_confidence must be positive"
    );
    assert!(t.stop_max_regret > 0, "stop_max_regret must be positive");
    assert!(
        t.rollback_incident_delta > 0,
        "rollback_incident_delta must be positive"
    );
    assert!(
        t.rollback_tail_latency_delta > 0,
        "rollback_tail_latency_delta must be positive"
    );
}

#[test]
fn frx_09_1_promote_confidence_is_above_ninety_percent() {
    let contract = parse_contract();
    assert!(
        contract
            .sequential_monitoring
            .thresholds_millionths
            .promote_min_confidence
            >= 900_000,
        "promote confidence must be at least 90%"
    );
}

#[test]
fn frx_09_1_serde_roundtrip_preserves_contract() {
    let contract = parse_contract();
    let serialized = serde_json::to_string(&contract).expect("serialize");
    let deserialized: PilotRolloutHarnessContract =
        serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(contract, deserialized);
}

#[test]
fn frx_09_1_deterministic_double_parse() {
    let a = parse_contract();
    let b = parse_contract();
    assert_eq!(a, b);
}

#[test]
fn frx_09_1_assignment_fields_are_nonempty_and_unique() {
    let contract = parse_contract();
    let fields = &contract.experiment_harness.required_assignment_fields;
    assert!(!fields.is_empty());
    let unique: BTreeSet<&str> = fields.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        fields.len(),
        "duplicate assignment fields detected"
    );
}

#[test]
fn frx_09_1_observation_fields_are_nonempty_and_unique() {
    let contract = parse_contract();
    let fields = &contract.experiment_harness.required_observation_fields;
    assert!(!fields.is_empty());
    let unique: BTreeSet<&str> = fields.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        fields.len(),
        "duplicate observation fields detected"
    );
}

#[test]
fn frx_09_1_propensity_clip_is_within_unit_interval() {
    let contract = parse_contract();
    let clip = contract
        .off_policy_evaluation
        .propensity_clip_min_millionths;
    assert!(
        clip > 0 && clip < 1_000_000,
        "propensity clip must be in (0, 1)"
    );
}

#[test]
fn frx_09_1_doc_file_exists_and_is_nonempty() {
    let path = repo_root().join("docs/FRX_PILOT_ROLLOUT_HARNESS_V1.md");
    let content = fs::read_to_string(&path).expect("read doc");
    assert!(!content.is_empty());
}

#[test]
fn frx_09_1_estimators_are_nonempty_and_unique() {
    let contract = parse_contract();
    let estimators = &contract.off_policy_evaluation.estimators;
    assert!(!estimators.is_empty());
    let unique: BTreeSet<&str> = estimators.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        estimators.len(),
        "duplicate estimators detected"
    );
}

#[test]
fn frx_09_1_operator_verification_includes_json_validation() {
    let contract = parse_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty")),
        "operator verification must include JSON validation"
    );
}

#[test]
fn frx_09_1_all_strata_have_nonempty_inclusion_and_exclusion() {
    let contract = parse_contract();
    for stratum in &contract.pilot_portfolio.strata {
        assert!(
            !stratum.inclusion_criteria.is_empty(),
            "stratum {} must have inclusion criteria",
            stratum.stratum_id
        );
        assert!(
            !stratum.exclusion_criteria.is_empty(),
            "stratum {} must have exclusion criteria",
            stratum.stratum_id
        );
    }
}

#[test]
fn frx_09_1_incident_linkage_fields_are_nonempty_and_unique() {
    let contract = parse_contract();
    let fields = &contract.incident_linkage.required_fields;
    assert!(!fields.is_empty());
    let unique: BTreeSet<&str> = fields.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        fields.len(),
        "duplicate incident linkage fields detected"
    );
}

#[test]
fn frx_09_1_contract_schema_version_matches_constant() {
    let contract = parse_contract();
    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
}

#[test]
fn frx_09_1_deterministic_triple_parse() {
    let a = parse_contract();
    let b = parse_contract();
    let c = parse_contract();
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn frx_09_1_contract_has_nonempty_generated_by() {
    let contract = parse_contract();
    assert!(!contract.generated_by.trim().is_empty());
}

#[test]
fn frx_09_1_contract_has_nonempty_bead_id() {
    let contract = parse_contract();
    assert!(!contract.bead_id.trim().is_empty());
}

#[test]
fn frx_09_1_contract_has_nonempty_track_id() {
    let contract = parse_contract();
    assert!(!contract.track.id.trim().is_empty());
}

#[test]
fn frx_09_1_doc_has_more_than_50_lines() {
    let path = repo_root().join("docs/FRX_PILOT_ROLLOUT_HARNESS_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    assert!(doc.lines().count() > 50);
}

// ---------- enrichment: deeper edge-case and structural tests ----------

#[test]
fn frx_09_1_strata_target_shares_are_all_positive() {
    let contract = parse_contract();
    for stratum in &contract.pilot_portfolio.strata {
        assert!(
            stratum.target_share_bps > 0,
            "stratum {} has zero target_share_bps",
            stratum.stratum_id
        );
    }
}

#[test]
fn frx_09_1_serde_roundtrip_via_pretty_print_preserves_contract() {
    let contract = parse_contract();
    let pretty = serde_json::to_string_pretty(&contract).expect("serialize pretty");
    let recovered: PilotRolloutHarnessContract =
        serde_json::from_str(&pretty).expect("deserialize from pretty");
    assert_eq!(contract, recovered);
}

#[test]
fn frx_09_1_sequential_monitoring_thresholds_are_within_millionths_range() {
    let contract = parse_contract();
    let t = &contract.sequential_monitoring.thresholds_millionths;
    // All thresholds should be within valid millionths range (0, 10_000_000]
    // (allowing up to 10x for regret/delta which are relative)
    for (name, val) in [
        ("promote_min_confidence", t.promote_min_confidence),
        ("stop_max_regret", t.stop_max_regret),
        ("rollback_incident_delta", t.rollback_incident_delta),
        ("rollback_tail_latency_delta", t.rollback_tail_latency_delta),
    ] {
        assert!(
            val > 0 && val <= 10_000_000,
            "{name} value {val} out of plausible millionths range"
        );
    }
}

#[test]
fn frx_09_1_experiment_modes_and_decision_actions_are_disjoint() {
    let contract = parse_contract();
    let modes: BTreeSet<&str> = contract
        .experiment_harness
        .modes
        .iter()
        .map(String::as_str)
        .collect();
    let actions: BTreeSet<&str> = contract
        .sequential_monitoring
        .decision_actions
        .iter()
        .map(String::as_str)
        .collect();
    let overlap: BTreeSet<&&str> = modes.intersection(&actions).collect();
    assert!(
        overlap.is_empty(),
        "experiment modes and decision actions should be disjoint, found overlap: {overlap:?}"
    );
}

#[test]
fn frx_09_1_workload_archetypes_are_unique_across_strata() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for stratum in &contract.pilot_portfolio.strata {
        assert!(
            seen.insert(&stratum.workload_archetype),
            "duplicate workload_archetype: {}",
            stratum.workload_archetype
        );
    }
}

// ---------- enrichment: additional edge-case tests ----------

#[test]
fn frx_09_1_doc_contains_no_todo_markers() {
    let path = repo_root().join("docs/FRX_PILOT_ROLLOUT_HARNESS_V1.md");
    let doc = fs::read_to_string(&path).expect("read doc");
    let lower = doc.to_ascii_lowercase();
    assert!(
        !lower.contains("todo") && !lower.contains("fixme") && !lower.contains("xxx"),
        "pilot rollout harness doc must not contain unresolved TODO/FIXME/XXX markers"
    );
}

#[test]
fn frx_09_1_required_structured_log_fields_are_unique() {
    let contract = parse_contract();
    let fields = &contract.required_structured_log_fields;
    let unique: BTreeSet<&str> = fields.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        fields.len(),
        "duplicate structured log fields detected"
    );
}

#[test]
fn frx_09_1_strata_risk_tiers_are_nonempty() {
    let contract = parse_contract();
    for stratum in &contract.pilot_portfolio.strata {
        assert!(
            !stratum.risk_tier.trim().is_empty(),
            "stratum {} risk_tier must not be empty",
            stratum.stratum_id
        );
    }
}

#[test]
fn frx_09_1_minimum_effective_sample_size_is_at_least_100() {
    let contract = parse_contract();
    assert!(
        contract.off_policy_evaluation.minimum_effective_sample_size >= 100,
        "minimum_effective_sample_size must be at least 100 for statistical validity, got {}",
        contract.off_policy_evaluation.minimum_effective_sample_size
    );
}

#[test]
fn frx_09_1_decision_actions_are_unique() {
    let contract = parse_contract();
    let actions = &contract.sequential_monitoring.decision_actions;
    let unique: BTreeSet<&str> = actions.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        actions.len(),
        "duplicate decision actions detected"
    );
}

#[test]
fn frx_09_1_rollout_phase_ids_and_scorecards_are_unique() {
    let contract = parse_contract();
    let phases = &contract.rollout_phases.phases;

    let phase_ids: BTreeSet<&str> = phases.iter().map(|phase| phase.phase_id.as_str()).collect();
    let scorecard_ids: BTreeSet<&str> = phases
        .iter()
        .map(|phase| phase.phase_exit_scorecard_id.as_str())
        .collect();
    assert_eq!(
        phase_ids.len(),
        phases.len(),
        "duplicate phase ids detected"
    );
    assert_eq!(
        scorecard_ids.len(),
        phases.len(),
        "duplicate phase exit scorecard ids detected"
    );
}

#[test]
fn frx_09_1_readiness_inputs_are_unique() {
    let contract = parse_contract();
    let unique: BTreeSet<&str> = contract
        .readiness_inputs
        .required_inputs
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        unique.len(),
        contract.readiness_inputs.required_inputs.len(),
        "duplicate readiness inputs detected"
    );
}

#[test]
fn frx_09_1_artifact_contract_required_files_are_unique() {
    let contract = parse_contract();
    let unique: BTreeSet<&str> = contract
        .artifact_contract
        .required_files
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        unique.len(),
        contract.artifact_contract.required_files.len(),
        "duplicate artifact contract files detected"
    );
}
