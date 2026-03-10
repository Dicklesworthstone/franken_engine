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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::plas_lockstep::{
    LockstepFailureClass, LockstepRuntime, PlasLockstepCase, PlasLockstepError, RuntimeObservation,
    RuntimeTolerance, evaluate_plas_lockstep_case,
};

fn observation(runtime: LockstepRuntime, tag: &str, elapsed_ns: u64) -> RuntimeObservation {
    RuntimeObservation {
        runtime,
        output_digest: format!("output:{tag}"),
        side_effect_digest: format!("side_effect:{tag}"),
        state_digest: format!("state:{tag}"),
        error_code: None,
        capability_denials: Vec::new(),
        elapsed_ns,
    }
}

fn baseline_case() -> PlasLockstepCase {
    PlasLockstepCase {
        trace_id: "trace-lockstep-001".to_string(),
        decision_id: "decision-lockstep-001".to_string(),
        policy_id: "policy-lockstep-v1".to_string(),
        extension_id: "extension://plas/lockstep".to_string(),
        scenario_id: "scenario-basic-pass".to_string(),
        full_manifest: observation(LockstepRuntime::FrankenEngineFull, "ok", 1_000),
        minimal_policy: observation(LockstepRuntime::FrankenEngineMinimal, "ok", 1_050),
        node_reference: Some(observation(LockstepRuntime::Node, "ok", 980)),
        bun_reference: Some(observation(LockstepRuntime::Bun, "ok", 990)),
        reference_tolerances: BTreeMap::new(),
        max_performance_degradation_millionths: 200_000,
    }
}

#[test]
fn minimal_policy_preserving_behavior_passes_lockstep() {
    let evaluation = evaluate_plas_lockstep_case(baseline_case()).expect("lockstep evaluation");
    assert!(evaluation.pass);
    assert_eq!(evaluation.failure_class, None);
    assert_eq!(evaluation.log.outcome, "pass");
    assert_eq!(evaluation.log.error_code, None);
}

#[test]
fn missing_capability_is_classified_as_capability_gap() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-capability-gap".to_string();
    case.minimal_policy.output_digest = "output:gap".to_string();
    case.minimal_policy.error_code = Some("capability_denied".to_string());
    case.minimal_policy.capability_denials =
        vec!["filesystem.read".to_string(), "network.egress".to_string()];

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert!(!evaluation.pass);
    assert_eq!(
        evaluation.failure_class,
        Some(LockstepFailureClass::CapabilityGap)
    );
    assert_eq!(evaluation.log.error_code.as_deref(), Some("capability_gap"));
}

#[test]
fn semantic_drift_without_denials_is_correctness_regression() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-correctness-regression".to_string();
    case.minimal_policy.side_effect_digest = "side_effect:drift".to_string();

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert!(!evaluation.pass);
    assert_eq!(
        evaluation.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression)
    );
    assert_eq!(
        evaluation.log.error_code.as_deref(),
        Some("correctness_regression")
    );
}

#[test]
fn reference_mismatch_with_matching_minimal_is_platform_divergence() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-platform-divergence".to_string();
    let node = case.node_reference.as_mut().expect("node reference");
    node.output_digest = "output:node-divergent".to_string();

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert!(!evaluation.pass);
    assert_eq!(
        evaluation.failure_class,
        Some(LockstepFailureClass::PlatformDivergence)
    );
    assert_eq!(
        evaluation.log.error_code.as_deref(),
        Some("platform_divergence")
    );
}

#[test]
fn configured_runtime_tolerance_allows_known_reference_difference() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-runtime-tolerance".to_string();
    let node = case.node_reference.as_mut().expect("node reference");
    node.output_digest = "output:node-known-diff".to_string();
    let mut tolerance = RuntimeTolerance {
        allow_output_digest_mismatch: true,
        allow_side_effect_digest_mismatch: false,
        allow_state_digest_mismatch: false,
        allowed_error_codes: BTreeSet::new(),
    };
    tolerance
        .allowed_error_codes
        .insert("node_known_waiver".to_string());
    case.reference_tolerances
        .insert(LockstepRuntime::Node, tolerance);

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert!(evaluation.pass);
    assert_eq!(evaluation.failure_class, None);
}

#[test]
fn excessive_performance_degradation_is_correctness_regression() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-performance-regression".to_string();
    case.max_performance_degradation_millionths = 100_000;
    case.minimal_policy.elapsed_ns = 1_400;

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert!(!evaluation.pass);
    assert_eq!(
        evaluation.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression)
    );
    let detail = evaluation.failure_detail.expect("failure detail");
    assert!(detail.contains("performance degradation"));
}

#[test]
fn requires_reference_runtime_for_cross_engine_lockstep() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-no-reference".to_string();
    case.node_reference = None;
    case.bun_reference = None;

    let err = evaluate_plas_lockstep_case(case).expect_err("expected invalid case error");
    assert!(matches!(err, PlasLockstepError::InvalidCase { .. }));
    assert!(err.to_string().contains("at least one Node/Bun reference"));
}

#[test]
fn structured_log_fields_are_stable() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-log-contract".to_string();
    case.minimal_policy.output_digest = "output:gap".to_string();
    case.minimal_policy.capability_denials = vec!["ipc.spawn".to_string()];
    case.minimal_policy.error_code = Some("capability_denied".to_string());

    let evaluation = evaluate_plas_lockstep_case(case).expect("lockstep evaluation");
    assert_eq!(evaluation.log.trace_id, "trace-lockstep-001");
    assert_eq!(evaluation.log.decision_id, "decision-lockstep-001");
    assert_eq!(evaluation.log.policy_id, "policy-lockstep-v1");
    assert_eq!(evaluation.log.component, "plas_lockstep");
    assert_eq!(evaluation.log.event, "plas_lockstep_case_evaluated");
    assert_eq!(evaluation.log.outcome, "fail");
    assert_eq!(evaluation.log.error_code.as_deref(), Some("capability_gap"));
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn lockstep_runtime_serde_round_trip_all_variants() {
    for runtime in [
        LockstepRuntime::FrankenEngineFull,
        LockstepRuntime::FrankenEngineMinimal,
        LockstepRuntime::Node,
        LockstepRuntime::Bun,
    ] {
        let json = serde_json::to_string(&runtime).expect("serialize");
        let recovered: LockstepRuntime = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(runtime, recovered);
        assert!(!runtime.as_str().is_empty());
    }
}

#[test]
fn lockstep_failure_class_serde_round_trip_all_variants() {
    for failure_class in [
        LockstepFailureClass::CorrectnessRegression,
        LockstepFailureClass::CapabilityGap,
        LockstepFailureClass::PlatformDivergence,
    ] {
        let json = serde_json::to_string(&failure_class).expect("serialize");
        let recovered: LockstepFailureClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(failure_class, recovered);
        assert!(!failure_class.error_code().is_empty());
    }
}

#[test]
fn runtime_observation_serde_round_trip() {
    let obs = observation(LockstepRuntime::Node, "serde-test", 1_500);
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: RuntimeObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, recovered);
}

#[test]
fn runtime_tolerance_default_denies_all_mismatches() {
    let tolerance = RuntimeTolerance {
        allow_output_digest_mismatch: false,
        allow_side_effect_digest_mismatch: false,
        allow_state_digest_mismatch: false,
        allowed_error_codes: BTreeSet::new(),
    };
    let json = serde_json::to_string(&tolerance).expect("serialize");
    let recovered: RuntimeTolerance = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(tolerance, recovered);
}

#[test]
fn plas_lockstep_error_display_is_non_empty() {
    let err = PlasLockstepError::InvalidCase {
        detail: "missing reference".to_string(),
    };
    let msg = err.to_string();
    assert!(!msg.is_empty());
    assert!(msg.contains("missing reference"));
}

// ────────────────────────────────────────────────────────────
// Enrichment session 2: validation, comparison, tolerance edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn rejects_empty_trace_id() {
    let mut case = baseline_case();
    case.trace_id = "   ".to_string();
    let err = evaluate_plas_lockstep_case(case).expect_err("expected error");
    assert!(err.to_string().contains("trace_id"));
}

#[test]
fn rejects_empty_decision_id() {
    let mut case = baseline_case();
    case.decision_id = String::new();
    let err = evaluate_plas_lockstep_case(case).expect_err("expected error");
    assert!(err.to_string().contains("decision_id"));
}

#[test]
fn rejects_empty_policy_id() {
    let mut case = baseline_case();
    case.policy_id = "  ".to_string();
    let err = evaluate_plas_lockstep_case(case).expect_err("expected error");
    assert!(err.to_string().contains("policy_id"));
}

#[test]
fn rejects_empty_extension_id() {
    let mut case = baseline_case();
    case.extension_id = String::new();
    let err = evaluate_plas_lockstep_case(case).expect_err("expected error");
    assert!(err.to_string().contains("extension_id"));
}

#[test]
fn rejects_empty_scenario_id() {
    let mut case = baseline_case();
    case.scenario_id = "   ".to_string();
    let err = evaluate_plas_lockstep_case(case).expect_err("expected error");
    assert!(err.to_string().contains("scenario_id"));
}

#[test]
fn rejects_wrong_full_manifest_runtime() {
    let mut case = baseline_case();
    case.full_manifest.runtime = LockstepRuntime::Node;
    let err = evaluate_plas_lockstep_case(case).expect_err("expected error");
    assert!(err.to_string().contains("full_manifest"));
}

#[test]
fn rejects_wrong_minimal_policy_runtime() {
    let mut case = baseline_case();
    case.minimal_policy.runtime = LockstepRuntime::FrankenEngineFull;
    let err = evaluate_plas_lockstep_case(case).expect_err("expected error");
    assert!(err.to_string().contains("minimal_policy"));
}

#[test]
fn rejects_wrong_node_reference_runtime() {
    let mut case = baseline_case();
    case.node_reference = Some(observation(LockstepRuntime::Bun, "wrong-runtime", 1_000));
    let err = evaluate_plas_lockstep_case(case).expect_err("expected error");
    assert!(err.to_string().contains("node_reference"));
}

#[test]
fn rejects_wrong_bun_reference_runtime() {
    let mut case = baseline_case();
    case.bun_reference = Some(observation(LockstepRuntime::Node, "wrong-runtime", 1_000));
    let err = evaluate_plas_lockstep_case(case).expect_err("expected error");
    assert!(err.to_string().contains("bun_reference"));
}

#[test]
fn passes_with_only_node_reference() {
    let mut case = baseline_case();
    case.bun_reference = None;
    let eval = evaluate_plas_lockstep_case(case).expect("should pass");
    assert!(eval.pass);
}

#[test]
fn passes_with_only_bun_reference() {
    let mut case = baseline_case();
    case.node_reference = None;
    let eval = evaluate_plas_lockstep_case(case).expect("should pass");
    assert!(eval.pass);
}

#[test]
fn bun_divergence_detected_as_platform_divergence() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-bun-divergence".to_string();
    let bun = case.bun_reference.as_mut().expect("bun");
    bun.state_digest = "state:bun-divergent".to_string();
    let eval = evaluate_plas_lockstep_case(case).expect("should evaluate");
    assert!(!eval.pass);
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::PlatformDivergence)
    );
}

#[test]
fn tolerance_allows_side_effect_mismatch_for_bun() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-bun-tolerance".to_string();
    let bun = case.bun_reference.as_mut().expect("bun");
    bun.side_effect_digest = "side_effect:bun-different".to_string();
    case.reference_tolerances.insert(
        LockstepRuntime::Bun,
        RuntimeTolerance {
            allow_output_digest_mismatch: false,
            allow_side_effect_digest_mismatch: true,
            allow_state_digest_mismatch: false,
            allowed_error_codes: BTreeSet::new(),
        },
    );
    let eval = evaluate_plas_lockstep_case(case).expect("should pass with tolerance");
    assert!(eval.pass);
}

#[test]
fn tolerance_allows_state_digest_mismatch_for_node() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-node-state-tolerance".to_string();
    let node = case.node_reference.as_mut().expect("node");
    node.state_digest = "state:node-different".to_string();
    case.reference_tolerances.insert(
        LockstepRuntime::Node,
        RuntimeTolerance {
            allow_output_digest_mismatch: false,
            allow_side_effect_digest_mismatch: false,
            allow_state_digest_mismatch: true,
            allowed_error_codes: BTreeSet::new(),
        },
    );
    let eval = evaluate_plas_lockstep_case(case).expect("should pass with tolerance");
    assert!(eval.pass);
}

#[test]
fn correctness_regression_takes_priority_over_platform_divergence() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-priority".to_string();
    // Minimal policy diverges (correctness regression)
    case.minimal_policy.output_digest = "output:diverged".to_string();
    // Node also diverges (platform divergence)
    let node = case.node_reference.as_mut().expect("node");
    node.output_digest = "output:node-diverged".to_string();
    let eval = evaluate_plas_lockstep_case(case).expect("should evaluate");
    assert!(!eval.pass);
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression)
    );
}

#[test]
fn capability_gap_takes_priority_over_platform_divergence() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-cap-gap-priority".to_string();
    // Minimal policy has capability gap
    case.minimal_policy.output_digest = "output:gap".to_string();
    case.minimal_policy.error_code = Some("capability_denied".to_string());
    case.minimal_policy.capability_denials = vec!["net.listen".to_string()];
    // Node also diverges
    let node = case.node_reference.as_mut().expect("node");
    node.output_digest = "output:node-diverged".to_string();
    let eval = evaluate_plas_lockstep_case(case).expect("should evaluate");
    assert!(!eval.pass);
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CapabilityGap)
    );
}

#[test]
fn performance_degradation_millionths_is_zero_for_equal_elapsed() {
    let mut case = baseline_case();
    case.minimal_policy.elapsed_ns = case.full_manifest.elapsed_ns;
    let eval = evaluate_plas_lockstep_case(case).expect("should pass");
    assert!(eval.pass);
    assert_eq!(eval.performance_degradation_millionths, 0);
}

#[test]
fn performance_degradation_within_threshold_passes() {
    let mut case = baseline_case();
    case.max_performance_degradation_millionths = 100_000; // 10%
    case.full_manifest.elapsed_ns = 1_000;
    case.minimal_policy.elapsed_ns = 1_099; // 9.9% — within threshold
    let eval = evaluate_plas_lockstep_case(case).expect("should pass");
    assert!(eval.pass);
}

#[test]
fn comparisons_include_all_runtimes() {
    let eval = evaluate_plas_lockstep_case(baseline_case()).expect("should pass");
    // minimal vs full + node ref + bun ref = 3 comparisons
    assert_eq!(eval.comparisons.len(), 3);
}

#[test]
fn comparisons_include_only_two_with_single_reference() {
    let mut case = baseline_case();
    case.bun_reference = None;
    let eval = evaluate_plas_lockstep_case(case).expect("should pass");
    assert_eq!(eval.comparisons.len(), 2);
}

#[test]
fn mismatch_fields_list_divergent_digest_names() {
    let mut case = baseline_case();
    case.scenario_id = "scenario-mismatch-fields".to_string();
    case.minimal_policy.output_digest = "output:different".to_string();
    case.minimal_policy.state_digest = "state:different".to_string();
    let eval = evaluate_plas_lockstep_case(case).expect("should evaluate");
    assert!(!eval.pass);
    let detail = eval.failure_detail.as_deref().expect("detail");
    assert!(detail.contains("output_digest") || detail.contains("state_digest"));
}

#[test]
fn evaluation_serde_round_trip() {
    let eval = evaluate_plas_lockstep_case(baseline_case()).expect("should pass");
    let json = serde_json::to_string(&eval).expect("serialize");
    let recovered: PlasLockstepEvaluation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(eval, recovered);
}

#[test]
fn lockstep_case_serde_round_trip() {
    let case = baseline_case();
    let json = serde_json::to_string(&case).expect("serialize");
    let recovered: PlasLockstepCase = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(case, recovered);
}

#[test]
fn log_event_serde_round_trip() {
    let eval = evaluate_plas_lockstep_case(baseline_case()).expect("should pass");
    let json = serde_json::to_string(&eval.log).expect("serialize");
    let recovered: PlasLockstepLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(eval.log, recovered);
}

#[test]
fn runtime_comparison_serde_round_trip() {
    let eval = evaluate_plas_lockstep_case(baseline_case()).expect("should pass");
    for comparison in &eval.comparisons {
        let json = serde_json::to_string(comparison).expect("serialize");
        let recovered: RuntimeComparison = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*comparison, recovered);
    }
}

#[test]
fn lockstep_runtime_display_matches_as_str() {
    for runtime in [
        LockstepRuntime::FrankenEngineFull,
        LockstepRuntime::FrankenEngineMinimal,
        LockstepRuntime::Node,
        LockstepRuntime::Bun,
    ] {
        assert_eq!(runtime.to_string(), runtime.as_str());
    }
}

#[test]
fn lockstep_failure_class_display_matches_error_code() {
    for class in [
        LockstepFailureClass::CorrectnessRegression,
        LockstepFailureClass::CapabilityGap,
        LockstepFailureClass::PlatformDivergence,
    ] {
        assert_eq!(class.to_string(), class.error_code());
    }
}

#[test]
fn lockstep_runtime_ordering_is_deterministic() {
    assert!(LockstepRuntime::FrankenEngineFull < LockstepRuntime::FrankenEngineMinimal);
    assert!(LockstepRuntime::FrankenEngineMinimal < LockstepRuntime::Node);
    assert!(LockstepRuntime::Node < LockstepRuntime::Bun);
}

#[test]
fn observation_with_error_code_serde_round_trip() {
    let mut obs = observation(LockstepRuntime::Bun, "err", 500);
    obs.error_code = Some("timeout".to_string());
    obs.capability_denials = vec!["net.egress".to_string(), "fs.write".to_string()];
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: RuntimeObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, recovered);
}

#[test]
fn tolerance_with_allowed_error_codes_serde_round_trip() {
    let mut codes = BTreeSet::new();
    codes.insert("TIMEOUT".to_string());
    codes.insert("ENOSPC".to_string());
    let tolerance = RuntimeTolerance {
        allow_output_digest_mismatch: true,
        allow_side_effect_digest_mismatch: true,
        allow_state_digest_mismatch: false,
        allowed_error_codes: codes,
    };
    let json = serde_json::to_string(&tolerance).expect("serialize");
    let recovered: RuntimeTolerance = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(tolerance, recovered);
}

#[test]
fn evaluation_determinism_across_identical_inputs() {
    let e1 = evaluate_plas_lockstep_case(baseline_case()).expect("eval");
    let e2 = evaluate_plas_lockstep_case(baseline_case()).expect("eval");
    assert_eq!(e1, e2);
}

#[test]
fn normalization_trims_whitespace_from_ids() {
    let mut case = baseline_case();
    case.trace_id = "  trace-lockstep-001  ".to_string();
    case.decision_id = " decision-lockstep-001 ".to_string();
    let eval = evaluate_plas_lockstep_case(case).expect("should pass after trim");
    assert!(eval.pass);
    assert_eq!(eval.trace_id, "trace-lockstep-001");
    assert_eq!(eval.decision_id, "decision-lockstep-001");
}

#[test]
fn plas_lockstep_error_is_std_error() {
    let err = PlasLockstepError::InvalidCase {
        detail: "test".to_string(),
    };
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

#[test]
fn plas_lockstep_error_serde_round_trip() {
    let err = PlasLockstepError::InvalidCase {
        detail: "bad input".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: PlasLockstepError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

use frankenengine_engine::plas_lockstep::{
    PlasLockstepEvaluation, PlasLockstepLogEvent, RuntimeComparison,
};
