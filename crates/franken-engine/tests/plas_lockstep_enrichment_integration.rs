//! Enrichment integration tests for `plas_lockstep` — PearlTower 2026-02-27.
//!
//! Covers JSON field-name stability, serde roundtrips from evaluate paths,
//! serde exact enum values, Debug distinctness, error Display exact messages,
//! whitespace normalization, comparison vector contents, tolerance combinations,
//! failure-class priority, performance boundary conditions, log-event contract,
//! and E2E scenarios.

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
    LockstepFailureClass, LockstepRuntime, PlasLockstepCase, PlasLockstepError,
    PlasLockstepEvaluation, PlasLockstepLogEvent, RuntimeComparison, RuntimeObservation,
    RuntimeTolerance, evaluate_plas_lockstep_case,
};

// ── helpers ──────────────────────────────────────────────────────────────

fn make_obs(runtime: LockstepRuntime, tag: &str, elapsed_ns: u64) -> RuntimeObservation {
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

fn base_case() -> PlasLockstepCase {
    PlasLockstepCase {
        trace_id: "trace-enrich-001".to_string(),
        decision_id: "decision-enrich-001".to_string(),
        policy_id: "policy-enrich-v1".to_string(),
        extension_id: "extension://plas/enrich".to_string(),
        scenario_id: "scenario-enrich-pass".to_string(),
        full_manifest: make_obs(LockstepRuntime::FrankenEngineFull, "ok", 1_000),
        minimal_policy: make_obs(LockstepRuntime::FrankenEngineMinimal, "ok", 1_050),
        node_reference: Some(make_obs(LockstepRuntime::Node, "ok", 980)),
        bun_reference: Some(make_obs(LockstepRuntime::Bun, "ok", 990)),
        reference_tolerances: BTreeMap::new(),
        max_performance_degradation_millionths: 200_000,
    }
}

fn passing_eval() -> PlasLockstepEvaluation {
    evaluate_plas_lockstep_case(base_case()).unwrap()
}

// ── 1. JSON field-name stability ─────────────────────────────────────────

#[test]
fn json_fields_evaluation() {
    let eval = passing_eval();
    let json = serde_json::to_string(&eval).unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_id",
        "scenario_id",
        "pass",
        "failure_class",
        "failure_detail",
        "performance_degradation_millionths",
        "comparisons",
        "log",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_log_event() {
    let eval = passing_eval();
    let json = serde_json::to_string(&eval.log).unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_runtime_observation() {
    let o = make_obs(LockstepRuntime::Node, "test", 100);
    let json = serde_json::to_string(&o).unwrap();
    for key in [
        "runtime",
        "output_digest",
        "side_effect_digest",
        "state_digest",
        "error_code",
        "capability_denials",
        "elapsed_ns",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_runtime_tolerance() {
    let t = RuntimeTolerance {
        allow_output_digest_mismatch: true,
        allow_side_effect_digest_mismatch: false,
        allow_state_digest_mismatch: true,
        allowed_error_codes: BTreeSet::new(),
    };
    let json = serde_json::to_string(&t).unwrap();
    for key in [
        "allow_output_digest_mismatch",
        "allow_side_effect_digest_mismatch",
        "allow_state_digest_mismatch",
        "allowed_error_codes",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_runtime_comparison() {
    let eval = passing_eval();
    assert!(!eval.comparisons.is_empty());
    let json = serde_json::to_string(&eval.comparisons[0]).unwrap();
    for key in ["runtime", "semantic_match", "mismatch_fields"] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_lockstep_case() {
    let c = base_case();
    let json = serde_json::to_string(&c).unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_id",
        "scenario_id",
        "full_manifest",
        "minimal_policy",
        "node_reference",
        "bun_reference",
        "reference_tolerances",
        "max_performance_degradation_millionths",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

// ── 2. Serde exact enum values ───────────────────────────────────────────

#[test]
fn serde_exact_runtime_values() {
    assert_eq!(
        serde_json::to_string(&LockstepRuntime::FrankenEngineFull).unwrap(),
        "\"franken_engine_full\""
    );
    assert_eq!(
        serde_json::to_string(&LockstepRuntime::FrankenEngineMinimal).unwrap(),
        "\"franken_engine_minimal\""
    );
    assert_eq!(
        serde_json::to_string(&LockstepRuntime::Node).unwrap(),
        "\"node\""
    );
    assert_eq!(
        serde_json::to_string(&LockstepRuntime::Bun).unwrap(),
        "\"bun\""
    );
}

#[test]
fn serde_exact_failure_class_values() {
    assert_eq!(
        serde_json::to_string(&LockstepFailureClass::CorrectnessRegression).unwrap(),
        "\"correctness_regression\""
    );
    assert_eq!(
        serde_json::to_string(&LockstepFailureClass::CapabilityGap).unwrap(),
        "\"capability_gap\""
    );
    assert_eq!(
        serde_json::to_string(&LockstepFailureClass::PlatformDivergence).unwrap(),
        "\"platform_divergence\""
    );
}

// ── 3. Display/as_str exact values ───────────────────────────────────────

#[test]
fn runtime_as_str_exact() {
    assert_eq!(
        LockstepRuntime::FrankenEngineFull.as_str(),
        "franken_engine_full"
    );
    assert_eq!(
        LockstepRuntime::FrankenEngineMinimal.as_str(),
        "franken_engine_minimal"
    );
    assert_eq!(LockstepRuntime::Node.as_str(), "node");
    assert_eq!(LockstepRuntime::Bun.as_str(), "bun");
}

#[test]
fn runtime_display_equals_as_str() {
    for v in [
        LockstepRuntime::FrankenEngineFull,
        LockstepRuntime::FrankenEngineMinimal,
        LockstepRuntime::Node,
        LockstepRuntime::Bun,
    ] {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

#[test]
fn failure_class_error_code_exact() {
    assert_eq!(
        LockstepFailureClass::CorrectnessRegression.error_code(),
        "correctness_regression"
    );
    assert_eq!(
        LockstepFailureClass::CapabilityGap.error_code(),
        "capability_gap"
    );
    assert_eq!(
        LockstepFailureClass::PlatformDivergence.error_code(),
        "platform_divergence"
    );
}

#[test]
fn failure_class_display_matches_error_code() {
    for v in [
        LockstepFailureClass::CorrectnessRegression,
        LockstepFailureClass::CapabilityGap,
        LockstepFailureClass::PlatformDivergence,
    ] {
        assert_eq!(format!("{v}"), v.error_code());
    }
}

// ── 4. Debug distinctness ────────────────────────────────────────────────

#[test]
fn debug_distinct_runtime() {
    let variants = [
        LockstepRuntime::FrankenEngineFull,
        LockstepRuntime::FrankenEngineMinimal,
        LockstepRuntime::Node,
        LockstepRuntime::Bun,
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn debug_distinct_failure_class() {
    let variants = [
        LockstepFailureClass::CorrectnessRegression,
        LockstepFailureClass::CapabilityGap,
        LockstepFailureClass::PlatformDivergence,
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

// ── 5. Error Display exact ───────────────────────────────────────────────

#[test]
fn error_display_exact() {
    let err = PlasLockstepError::InvalidCase {
        detail: "bad field".to_string(),
    };
    assert_eq!(format!("{err}"), "invalid lockstep case: bad field");
}

#[test]
fn error_implements_std_error() {
    let err = PlasLockstepError::InvalidCase {
        detail: "test".to_string(),
    };
    let e: &dyn std::error::Error = &err;
    assert!(!e.to_string().is_empty());
}

#[test]
fn error_serde_roundtrip() {
    let err = PlasLockstepError::InvalidCase {
        detail: "roundtrip test".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: PlasLockstepError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ── 6. Serde roundtrips from evaluate paths ──────────────────────────────

#[test]
fn serde_roundtrip_passing_evaluation() {
    let eval = passing_eval();
    assert!(eval.pass);
    let json = serde_json::to_string(&eval).unwrap();
    let back: PlasLockstepEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

#[test]
fn serde_roundtrip_correctness_regression() {
    let mut c = base_case();
    c.minimal_policy.output_digest = "output:diverged".to_string();
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(!eval.pass);
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression)
    );
    let json = serde_json::to_string(&eval).unwrap();
    let back: PlasLockstepEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

#[test]
fn serde_roundtrip_capability_gap() {
    let mut c = base_case();
    c.minimal_policy.output_digest = "output:gap".to_string();
    c.minimal_policy.capability_denials = vec!["net.connect".to_string()];
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CapabilityGap)
    );
    let json = serde_json::to_string(&eval).unwrap();
    let back: PlasLockstepEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

#[test]
fn serde_roundtrip_platform_divergence() {
    let mut c = base_case();
    c.node_reference = Some({
        let mut n = make_obs(LockstepRuntime::Node, "ok", 980);
        n.output_digest = "output:node-diff".to_string();
        n
    });
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::PlatformDivergence)
    );
    let json = serde_json::to_string(&eval).unwrap();
    let back: PlasLockstepEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ── 7. Whitespace normalization through evaluate ─────────────────────────

#[test]
fn whitespace_normalized_ids() {
    let mut c = base_case();
    c.trace_id = "  trace-enrich-001  ".to_string();
    c.decision_id = "  decision-enrich-001  ".to_string();
    c.policy_id = "  policy-enrich-v1  ".to_string();
    c.extension_id = "  extension://plas/enrich  ".to_string();
    c.scenario_id = "  scenario-enrich-pass  ".to_string();
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(eval.trace_id, "trace-enrich-001");
    assert_eq!(eval.decision_id, "decision-enrich-001");
    assert_eq!(eval.policy_id, "policy-enrich-v1");
    assert_eq!(eval.extension_id, "extension://plas/enrich");
    assert_eq!(eval.scenario_id, "scenario-enrich-pass");
}

#[test]
fn whitespace_only_trace_id_rejected() {
    let mut c = base_case();
    c.trace_id = "   ".to_string();
    let err = evaluate_plas_lockstep_case(c).unwrap_err();
    assert!(format!("{err}").contains("trace_id"));
}

#[test]
fn whitespace_only_scenario_id_rejected() {
    let mut c = base_case();
    c.scenario_id = "   ".to_string();
    let err = evaluate_plas_lockstep_case(c).unwrap_err();
    assert!(format!("{err}").contains("scenario_id"));
}

#[test]
fn observation_digest_whitespace_normalized() {
    let mut c = base_case();
    c.full_manifest.output_digest = "  output:ok  ".to_string();
    c.full_manifest.side_effect_digest = "  side_effect:ok  ".to_string();
    c.full_manifest.state_digest = "  state:ok  ".to_string();
    c.minimal_policy.output_digest = "  output:ok  ".to_string();
    c.minimal_policy.side_effect_digest = "  side_effect:ok  ".to_string();
    c.minimal_policy.state_digest = "  state:ok  ".to_string();
    c.node_reference = Some({
        let mut n = make_obs(LockstepRuntime::Node, "ok", 980);
        n.output_digest = "  output:ok  ".to_string();
        n.side_effect_digest = "  side_effect:ok  ".to_string();
        n.state_digest = "  state:ok  ".to_string();
        n
    });
    c.bun_reference = Some({
        let mut b = make_obs(LockstepRuntime::Bun, "ok", 990);
        b.output_digest = "  output:ok  ".to_string();
        b.side_effect_digest = "  side_effect:ok  ".to_string();
        b.state_digest = "  state:ok  ".to_string();
        b
    });
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(eval.pass);
}

#[test]
fn capability_denials_deduped_and_sorted() {
    let mut c = base_case();
    c.minimal_policy.output_digest = "output:gap".to_string();
    c.minimal_policy.capability_denials = vec![
        " net.egress ".to_string(),
        " fs.read ".to_string(),
        " net.egress ".to_string(), // duplicate
        "   ".to_string(),          // empty after trim
    ];
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CapabilityGap)
    );
    let detail = eval.failure_detail.unwrap();
    // After dedup/sort: ["fs.read", "net.egress"]
    assert!(detail.contains("fs.read"));
    assert!(detail.contains("net.egress"));
}

#[test]
fn whitespace_only_error_code_becomes_none() {
    let mut c = base_case();
    c.full_manifest.error_code = Some("   ".to_string());
    c.minimal_policy.error_code = Some("   ".to_string());
    // After normalization, both error_codes become None → they still match
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(eval.pass);
}

// ── 8. Validation edge cases ─────────────────────────────────────────────

#[test]
fn validation_whitespace_only_output_digest_rejected() {
    let mut c = base_case();
    c.full_manifest.output_digest = "   ".to_string();
    let err = evaluate_plas_lockstep_case(c).unwrap_err();
    assert!(format!("{err}").contains("output_digest"));
}

#[test]
fn validation_wrong_full_manifest_runtime() {
    let mut c = base_case();
    c.full_manifest.runtime = LockstepRuntime::Node;
    let err = evaluate_plas_lockstep_case(c).unwrap_err();
    assert!(format!("{err}").contains("full_manifest.runtime"));
}

#[test]
fn validation_wrong_minimal_policy_runtime() {
    let mut c = base_case();
    c.minimal_policy.runtime = LockstepRuntime::FrankenEngineFull;
    let err = evaluate_plas_lockstep_case(c).unwrap_err();
    assert!(format!("{err}").contains("minimal_policy.runtime"));
}

#[test]
fn validation_wrong_node_runtime() {
    let mut c = base_case();
    c.node_reference = Some(make_obs(LockstepRuntime::Bun, "ok", 980));
    let err = evaluate_plas_lockstep_case(c).unwrap_err();
    assert!(format!("{err}").contains("node_reference.runtime"));
}

#[test]
fn validation_wrong_bun_runtime() {
    let mut c = base_case();
    c.node_reference = None;
    c.bun_reference = Some(make_obs(LockstepRuntime::Node, "ok", 990));
    let err = evaluate_plas_lockstep_case(c).unwrap_err();
    assert!(format!("{err}").contains("bun_reference.runtime"));
}

#[test]
fn validation_no_references_rejected() {
    let mut c = base_case();
    c.node_reference = None;
    c.bun_reference = None;
    let err = evaluate_plas_lockstep_case(c).unwrap_err();
    assert!(format!("{err}").contains("at least one"));
}

// ── 9. Comparison vector contents ────────────────────────────────────────

#[test]
fn comparisons_with_both_references() {
    let eval = passing_eval();
    // minimal + node + bun = 3 comparisons
    assert_eq!(eval.comparisons.len(), 3);
    assert_eq!(
        eval.comparisons[0].runtime,
        LockstepRuntime::FrankenEngineMinimal
    );
    assert_eq!(eval.comparisons[1].runtime, LockstepRuntime::Node);
    assert_eq!(eval.comparisons[2].runtime, LockstepRuntime::Bun);
    for cmp in &eval.comparisons {
        assert!(cmp.semantic_match);
        assert!(cmp.mismatch_fields.is_empty());
    }
}

#[test]
fn comparisons_node_only() {
    let mut c = base_case();
    c.bun_reference = None;
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(eval.comparisons.len(), 2);
    assert_eq!(
        eval.comparisons[0].runtime,
        LockstepRuntime::FrankenEngineMinimal
    );
    assert_eq!(eval.comparisons[1].runtime, LockstepRuntime::Node);
}

#[test]
fn comparisons_bun_only() {
    let mut c = base_case();
    c.node_reference = None;
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(eval.comparisons.len(), 2);
    assert_eq!(
        eval.comparisons[0].runtime,
        LockstepRuntime::FrankenEngineMinimal
    );
    assert_eq!(eval.comparisons[1].runtime, LockstepRuntime::Bun);
}

#[test]
fn comparison_mismatch_fields_list_exact_digests() {
    let mut c = base_case();
    c.minimal_policy.output_digest = "output:diff".to_string();
    c.minimal_policy.side_effect_digest = "side_effect:diff".to_string();
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    let cmp = &eval.comparisons[0];
    assert!(!cmp.semantic_match);
    assert!(cmp.mismatch_fields.contains(&"output_digest".to_string()));
    assert!(
        cmp.mismatch_fields
            .contains(&"side_effect_digest".to_string())
    );
    assert!(!cmp.mismatch_fields.contains(&"state_digest".to_string()));
}

// ── 10. Failure class priority ───────────────────────────────────────────

#[test]
fn capability_gap_takes_priority_over_platform_divergence() {
    let mut c = base_case();
    // minimal diverges with capability denials (gap)
    c.minimal_policy.output_digest = "output:gap".to_string();
    c.minimal_policy.capability_denials = vec!["fs.read".to_string()];
    // node also diverges (platform)
    c.node_reference = Some({
        let mut n = make_obs(LockstepRuntime::Node, "ok", 980);
        n.output_digest = "output:node-diff".to_string();
        n
    });
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CapabilityGap)
    );
}

#[test]
fn correctness_regression_takes_priority_over_platform_divergence() {
    let mut c = base_case();
    // minimal diverges without capability denials (correctness regression)
    c.minimal_policy.state_digest = "state:diff".to_string();
    // node also diverges (platform)
    c.node_reference = Some({
        let mut n = make_obs(LockstepRuntime::Node, "ok", 980);
        n.output_digest = "output:node-diff".to_string();
        n
    });
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression)
    );
}

#[test]
fn performance_degradation_takes_priority_over_platform_divergence() {
    let mut c = base_case();
    c.full_manifest.elapsed_ns = 1_000;
    c.minimal_policy.elapsed_ns = 2_000; // 100% slower
    c.max_performance_degradation_millionths = 50_000; // only 5% allowed
    // node diverges (platform)
    c.node_reference = Some({
        let mut n = make_obs(LockstepRuntime::Node, "ok", 980);
        n.output_digest = "output:node-diff".to_string();
        n
    });
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression) // perf is classified as correctness
    );
    assert!(
        eval.failure_detail
            .as_ref()
            .unwrap()
            .contains("performance")
    );
}

// ── 11. Performance boundary conditions ──────────────────────────────────

#[test]
fn performance_at_exact_threshold_passes() {
    let mut c = base_case();
    c.full_manifest.elapsed_ns = 1_000;
    c.minimal_policy.elapsed_ns = 1_200; // 20% slower = 200_000 millionths
    c.max_performance_degradation_millionths = 200_000;
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(eval.pass, "exact threshold should pass");
    assert_eq!(eval.performance_degradation_millionths, 200_000);
}

#[test]
fn performance_just_over_threshold_fails() {
    let mut c = base_case();
    c.full_manifest.elapsed_ns = 1_000;
    c.minimal_policy.elapsed_ns = 1_201; // 20.1% slower = 201_000 millionths
    c.max_performance_degradation_millionths = 200_000;
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(!eval.pass);
    assert!(eval.performance_degradation_millionths > 200_000);
}

#[test]
fn performance_minimal_faster_is_zero() {
    let mut c = base_case();
    c.full_manifest.elapsed_ns = 1_000;
    c.minimal_policy.elapsed_ns = 500; // faster
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(eval.performance_degradation_millionths, 0);
}

#[test]
fn performance_equal_time_is_zero() {
    let mut c = base_case();
    c.full_manifest.elapsed_ns = 1_000;
    c.minimal_policy.elapsed_ns = 1_000;
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(eval.performance_degradation_millionths, 0);
}

// ── 12. Log event contract ───────────────────────────────────────────────

#[test]
fn log_component_always_plas_lockstep() {
    let eval = passing_eval();
    assert_eq!(eval.log.component, "plas_lockstep");
}

#[test]
fn log_event_always_plas_lockstep_case_evaluated() {
    let eval = passing_eval();
    assert_eq!(eval.log.event, "plas_lockstep_case_evaluated");
}

#[test]
fn log_pass_has_no_error_code() {
    let eval = passing_eval();
    assert_eq!(eval.log.outcome, "pass");
    assert!(eval.log.error_code.is_none());
}

#[test]
fn log_capability_gap_error_code() {
    let mut c = base_case();
    c.minimal_policy.output_digest = "output:gap".to_string();
    c.minimal_policy.capability_denials = vec!["net.connect".to_string()];
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(eval.log.outcome, "fail");
    assert_eq!(eval.log.error_code.as_deref(), Some("capability_gap"));
}

#[test]
fn log_correctness_regression_error_code() {
    let mut c = base_case();
    c.minimal_policy.output_digest = "output:diverged".to_string();
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(eval.log.outcome, "fail");
    assert_eq!(
        eval.log.error_code.as_deref(),
        Some("correctness_regression")
    );
}

#[test]
fn log_platform_divergence_error_code() {
    let mut c = base_case();
    c.node_reference = Some({
        let mut n = make_obs(LockstepRuntime::Node, "ok", 980);
        n.output_digest = "output:node-diff".to_string();
        n
    });
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert_eq!(eval.log.outcome, "fail");
    assert_eq!(eval.log.error_code.as_deref(), Some("platform_divergence"));
}

#[test]
fn log_ids_match_input() {
    let eval = passing_eval();
    assert_eq!(eval.log.trace_id, "trace-enrich-001");
    assert_eq!(eval.log.decision_id, "decision-enrich-001");
    assert_eq!(eval.log.policy_id, "policy-enrich-v1");
}

// ── 13. Tolerance combinations ───────────────────────────────────────────

#[test]
fn node_side_effect_tolerated() {
    let mut c = base_case();
    c.node_reference = Some({
        let mut n = make_obs(LockstepRuntime::Node, "ok", 980);
        n.side_effect_digest = "side_effect:node-diff".to_string();
        n
    });
    c.reference_tolerances.insert(
        LockstepRuntime::Node,
        RuntimeTolerance {
            allow_side_effect_digest_mismatch: true,
            ..Default::default()
        },
    );
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(eval.pass);
}

#[test]
fn bun_state_tolerated() {
    let mut c = base_case();
    c.bun_reference = Some({
        let mut b = make_obs(LockstepRuntime::Bun, "ok", 990);
        b.state_digest = "state:bun-diff".to_string();
        b
    });
    c.reference_tolerances.insert(
        LockstepRuntime::Bun,
        RuntimeTolerance {
            allow_state_digest_mismatch: true,
            ..Default::default()
        },
    );
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(eval.pass);
}

#[test]
fn error_code_tolerated_on_observed_side() {
    let mut c = base_case();
    c.node_reference = Some({
        let mut n = make_obs(LockstepRuntime::Node, "ok", 980);
        n.error_code = Some("known_err".to_string());
        n
    });
    c.reference_tolerances.insert(
        LockstepRuntime::Node,
        RuntimeTolerance {
            allowed_error_codes: ["known_err"].iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
    );
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(eval.pass);
}

#[test]
fn tolerance_normalized_whitespace_in_allowed_error_codes() {
    let mut c = base_case();
    c.node_reference = Some({
        let mut n = make_obs(LockstepRuntime::Node, "ok", 980);
        n.error_code = Some("known_err".to_string());
        n
    });
    c.reference_tolerances.insert(
        LockstepRuntime::Node,
        RuntimeTolerance {
            allowed_error_codes: ["  known_err  "].iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        },
    );
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(eval.pass);
}

// ── 14. Both references diverging ────────────────────────────────────────

#[test]
fn both_references_diverge_platform_divergence() {
    let mut c = base_case();
    c.node_reference = Some({
        let mut n = make_obs(LockstepRuntime::Node, "ok", 980);
        n.output_digest = "output:node-diff".to_string();
        n
    });
    c.bun_reference = Some({
        let mut b = make_obs(LockstepRuntime::Bun, "ok", 990);
        b.output_digest = "output:bun-diff".to_string();
        b
    });
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(!eval.pass);
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::PlatformDivergence)
    );
    let detail = eval.failure_detail.unwrap();
    assert!(detail.contains("node"));
    assert!(detail.contains("bun"));
}

// ── 15. Failure detail content ───────────────────────────────────────────

#[test]
fn capability_gap_detail_lists_denials() {
    let mut c = base_case();
    c.minimal_policy.output_digest = "output:gap".to_string();
    c.minimal_policy.capability_denials =
        vec!["filesystem.read".to_string(), "network.egress".to_string()];
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    let detail = eval.failure_detail.unwrap();
    assert!(detail.contains("filesystem.read"));
    assert!(detail.contains("network.egress"));
}

#[test]
fn correctness_regression_detail_lists_mismatch_fields() {
    let mut c = base_case();
    c.minimal_policy.output_digest = "output:diff".to_string();
    c.minimal_policy.state_digest = "state:diff".to_string();
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    let detail = eval.failure_detail.unwrap();
    assert!(detail.contains("output_digest"));
    assert!(detail.contains("state_digest"));
}

#[test]
fn performance_degradation_detail_mentions_threshold() {
    let mut c = base_case();
    c.full_manifest.elapsed_ns = 1_000;
    c.minimal_policy.elapsed_ns = 2_000;
    c.max_performance_degradation_millionths = 100_000;
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    let detail = eval.failure_detail.unwrap();
    assert!(detail.contains("100000")); // threshold
    assert!(detail.contains("performance"));
}

// ── 16. Evaluation field propagation ─────────────────────────────────────

#[test]
fn evaluation_ids_match_input() {
    let eval = passing_eval();
    assert_eq!(eval.trace_id, "trace-enrich-001");
    assert_eq!(eval.decision_id, "decision-enrich-001");
    assert_eq!(eval.policy_id, "policy-enrich-v1");
    assert_eq!(eval.extension_id, "extension://plas/enrich");
    assert_eq!(eval.scenario_id, "scenario-enrich-pass");
}

// ── 17. Serde roundtrips for all types ───────────────────────────────────

#[test]
fn runtime_serde_roundtrip_all() {
    for v in [
        LockstepRuntime::FrankenEngineFull,
        LockstepRuntime::FrankenEngineMinimal,
        LockstepRuntime::Node,
        LockstepRuntime::Bun,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: LockstepRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn failure_class_serde_roundtrip_all() {
    for v in [
        LockstepFailureClass::CorrectnessRegression,
        LockstepFailureClass::CapabilityGap,
        LockstepFailureClass::PlatformDivergence,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: LockstepFailureClass = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn observation_serde_roundtrip_with_denials() {
    let o = RuntimeObservation {
        runtime: LockstepRuntime::Node,
        output_digest: "out".to_string(),
        side_effect_digest: "se".to_string(),
        state_digest: "st".to_string(),
        error_code: Some("err_x".to_string()),
        capability_denials: vec!["cap_a".to_string(), "cap_b".to_string()],
        elapsed_ns: 42,
    };
    let json = serde_json::to_string(&o).unwrap();
    let back: RuntimeObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}

#[test]
fn tolerance_serde_roundtrip() {
    let t = RuntimeTolerance {
        allow_output_digest_mismatch: true,
        allow_side_effect_digest_mismatch: false,
        allow_state_digest_mismatch: true,
        allowed_error_codes: ["err1", "err2"].iter().map(|s| s.to_string()).collect(),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: RuntimeTolerance = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn case_serde_roundtrip_with_tolerances() {
    let mut c = base_case();
    c.reference_tolerances.insert(
        LockstepRuntime::Node,
        RuntimeTolerance {
            allow_output_digest_mismatch: true,
            ..Default::default()
        },
    );
    c.reference_tolerances.insert(
        LockstepRuntime::Bun,
        RuntimeTolerance {
            allow_state_digest_mismatch: true,
            allowed_error_codes: ["waiver".to_string()].into_iter().collect(),
            ..Default::default()
        },
    );
    let json = serde_json::to_string(&c).unwrap();
    let back: PlasLockstepCase = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn comparison_serde_roundtrip_with_mismatches() {
    let cmp = RuntimeComparison {
        runtime: LockstepRuntime::Bun,
        semantic_match: false,
        mismatch_fields: vec!["output_digest".to_string(), "error_code".to_string()],
    };
    let json = serde_json::to_string(&cmp).unwrap();
    let back: RuntimeComparison = serde_json::from_str(&json).unwrap();
    assert_eq!(cmp, back);
}

#[test]
fn log_event_serde_roundtrip_with_error() {
    let le = PlasLockstepLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "plas_lockstep".to_string(),
        event: "plas_lockstep_case_evaluated".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("capability_gap".to_string()),
    };
    let json = serde_json::to_string(&le).unwrap();
    let back: PlasLockstepLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(le, back);
}

// ── 18. E2E: side-effect-only mismatch ───────────────────────────────────

#[test]
fn side_effect_only_mismatch_is_correctness_regression() {
    let mut c = base_case();
    c.minimal_policy.side_effect_digest = "side_effect:diff".to_string();
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(!eval.pass);
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression)
    );
    let detail = eval.failure_detail.unwrap();
    assert!(detail.contains("side_effect_digest"));
}

#[test]
fn state_only_mismatch_is_correctness_regression() {
    let mut c = base_case();
    c.minimal_policy.state_digest = "state:diff".to_string();
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(!eval.pass);
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression)
    );
}

// ── 19. Error code mismatch between minimal and full ─────────────────────

#[test]
fn error_code_mismatch_minimal_vs_full_is_regression() {
    let mut c = base_case();
    c.minimal_policy.error_code = Some("runtime_error".to_string());
    let eval = evaluate_plas_lockstep_case(c).unwrap();
    assert!(!eval.pass);
    assert_eq!(
        eval.failure_class,
        Some(LockstepFailureClass::CorrectnessRegression)
    );
}

// ── 20. RuntimeTolerance default all strict ──────────────────────────────

#[test]
fn tolerance_default_all_strict() {
    let t = RuntimeTolerance::default();
    assert!(!t.allow_output_digest_mismatch);
    assert!(!t.allow_side_effect_digest_mismatch);
    assert!(!t.allow_state_digest_mismatch);
    assert!(t.allowed_error_codes.is_empty());
}
