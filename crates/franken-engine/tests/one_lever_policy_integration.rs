#![forbid(unsafe_code)]
//! Integration tests for the `one_lever_policy` module.
//!
//! Exercises every public type, enum variant, method, constant, validation
//! path, classification rule, override mechanism, scoring boundary, serde
//! round-trip, Display/Debug, and determinism guarantee from outside the
//! crate boundary.

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

use frankenengine_engine::one_lever_policy::{
    ERROR_INVALID_REQUEST, ERROR_MISSING_EVIDENCE, ERROR_MULTI_LEVER_VIOLATION,
    ERROR_SCORE_BELOW_THRESHOLD, LeverCategory, ONE_LEVER_POLICY_COMPONENT,
    ONE_LEVER_POLICY_SCHEMA_VERSION, ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS, OneLeverEvidenceRefs,
    OneLeverPolicyDecision, OneLeverPolicyEvent, OneLeverPolicyRequest, PathLeverClassification,
    evaluate_one_lever_policy,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn non_opt_request() -> OneLeverPolicyRequest {
    OneLeverPolicyRequest {
        trace_id: "t-integ".to_string(),
        decision_id: "d-integ".to_string(),
        policy_id: "p-integ".to_string(),
        commit_sha: "deadbeef".to_string(),
        commit_message: "docs: update readme".to_string(),
        changed_paths: vec!["docs/design.md".to_string()],
        evidence: OneLeverEvidenceRefs::default(),
    }
}

fn full_evidence(score: i64) -> OneLeverEvidenceRefs {
    OneLeverEvidenceRefs {
        baseline_benchmark_run_id: Some("baseline-integ".to_string()),
        post_change_benchmark_run_id: Some("post-integ".to_string()),
        delta_report_ref: Some("delta-integ".to_string()),
        semantic_equivalence_ref: Some("equiv-integ".to_string()),
        trace_replay_ref: Some("replay-integ".to_string()),
        isomorphism_ledger_ref: Some("iso-integ".to_string()),
        rollback_instructions_ref: Some("rollback-integ".to_string()),
        reprofile_after_merge_ref: Some("reprofile-integ".to_string()),
        opportunity_score_millionths: Some(score),
    }
}

fn single_lever_request(score: i64) -> OneLeverPolicyRequest {
    OneLeverPolicyRequest {
        trace_id: "t-integ".to_string(),
        decision_id: "d-integ".to_string(),
        policy_id: "p-integ".to_string(),
        commit_sha: "abc123".to_string(),
        commit_message: "perf: optimize interpreter".to_string(),
        changed_paths: vec!["crates/franken-engine/src/baseline_interpreter.rs".to_string()],
        evidence: full_evidence(score),
    }
}

fn multi_lever_request(score: i64, commit_message: &str) -> OneLeverPolicyRequest {
    OneLeverPolicyRequest {
        trace_id: "t-integ".to_string(),
        decision_id: "d-integ".to_string(),
        policy_id: "p-integ".to_string(),
        commit_sha: "multi123".to_string(),
        commit_message: commit_message.to_string(),
        changed_paths: vec![
            "crates/franken-engine/src/baseline_interpreter.rs".to_string(), // Execution
            "crates/franken-engine/src/gc_pause.rs".to_string(),             // Memory
        ],
        evidence: full_evidence(score),
    }
}

// ---------------------------------------------------------------------------
// Section 1: Constants stability
// ---------------------------------------------------------------------------

#[test]
fn constants_component_name() {
    assert_eq!(ONE_LEVER_POLICY_COMPONENT, "one_lever_policy_gate");
}

#[test]
fn constants_schema_version() {
    assert_eq!(
        ONE_LEVER_POLICY_SCHEMA_VERSION,
        "franken-engine.one-lever-policy.v1"
    );
}

#[test]
fn constants_score_threshold() {
    assert_eq!(ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS, 2_000_000);
}

#[test]
fn constants_error_codes() {
    assert_eq!(ERROR_INVALID_REQUEST, "FE-1LEV-1001");
    assert_eq!(ERROR_MULTI_LEVER_VIOLATION, "FE-1LEV-1002");
    assert_eq!(ERROR_MISSING_EVIDENCE, "FE-1LEV-1003");
    assert_eq!(ERROR_SCORE_BELOW_THRESHOLD, "FE-1LEV-1004");
}

// ---------------------------------------------------------------------------
// Section 2: LeverCategory — Display, as_str, ordering, serde
// ---------------------------------------------------------------------------

#[test]
fn lever_category_as_str_all_variants() {
    assert_eq!(LeverCategory::Execution.as_str(), "execution");
    assert_eq!(LeverCategory::Memory.as_str(), "memory");
    assert_eq!(LeverCategory::Security.as_str(), "security");
    assert_eq!(LeverCategory::Benchmark.as_str(), "benchmark");
    assert_eq!(LeverCategory::Config.as_str(), "config");
}

#[test]
fn lever_category_display_matches_as_str() {
    for cat in [
        LeverCategory::Execution,
        LeverCategory::Memory,
        LeverCategory::Security,
        LeverCategory::Benchmark,
        LeverCategory::Config,
    ] {
        assert_eq!(format!("{cat}"), cat.as_str());
    }
}

#[test]
fn lever_category_display_all_unique() {
    let displays: BTreeSet<String> = [
        LeverCategory::Execution,
        LeverCategory::Memory,
        LeverCategory::Security,
        LeverCategory::Benchmark,
        LeverCategory::Config,
    ]
    .iter()
    .map(|c| c.to_string())
    .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn lever_category_ordering() {
    let mut cats = vec![
        LeverCategory::Config,
        LeverCategory::Execution,
        LeverCategory::Benchmark,
        LeverCategory::Memory,
        LeverCategory::Security,
    ];
    cats.sort();
    assert_eq!(
        cats,
        vec![
            LeverCategory::Execution,
            LeverCategory::Memory,
            LeverCategory::Security,
            LeverCategory::Benchmark,
            LeverCategory::Config,
        ]
    );
}

#[test]
fn lever_category_serde_roundtrip_all() {
    for cat in [
        LeverCategory::Execution,
        LeverCategory::Memory,
        LeverCategory::Security,
        LeverCategory::Benchmark,
        LeverCategory::Config,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: LeverCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cat);
    }
}

#[test]
fn lever_category_serde_snake_case_format() {
    let json = serde_json::to_string(&LeverCategory::Execution).unwrap();
    assert_eq!(json, "\"execution\"");
    let json = serde_json::to_string(&LeverCategory::Config).unwrap();
    assert_eq!(json, "\"config\"");
}

#[test]
fn lever_category_debug_contains_variant_name() {
    let dbg = format!("{:?}", LeverCategory::Security);
    assert!(dbg.contains("Security"));
}

#[test]
fn lever_category_clone_eq() {
    let a = LeverCategory::Benchmark;
    let b = a;
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Section 3: OneLeverEvidenceRefs — defaults, clone, serde
// ---------------------------------------------------------------------------

#[test]
fn evidence_refs_default_all_none() {
    let ev = OneLeverEvidenceRefs::default();
    assert!(ev.baseline_benchmark_run_id.is_none());
    assert!(ev.post_change_benchmark_run_id.is_none());
    assert!(ev.delta_report_ref.is_none());
    assert!(ev.semantic_equivalence_ref.is_none());
    assert!(ev.trace_replay_ref.is_none());
    assert!(ev.isomorphism_ledger_ref.is_none());
    assert!(ev.rollback_instructions_ref.is_none());
    assert!(ev.reprofile_after_merge_ref.is_none());
    assert!(ev.opportunity_score_millionths.is_none());
}

#[test]
fn evidence_refs_clone_eq() {
    let a = full_evidence(3_500_000);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn evidence_refs_serde_roundtrip() {
    let ev = full_evidence(4_200_000);
    let json = serde_json::to_string(&ev).unwrap();
    let back: OneLeverEvidenceRefs = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ev);
}

#[test]
fn evidence_refs_serde_default_roundtrip() {
    let ev = OneLeverEvidenceRefs::default();
    let json = serde_json::to_string(&ev).unwrap();
    let back: OneLeverEvidenceRefs = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ev);
}

#[test]
fn evidence_refs_debug_not_empty() {
    let ev = full_evidence(1_000_000);
    let dbg = format!("{ev:?}");
    assert!(dbg.contains("baseline_benchmark_run_id"));
}

// ---------------------------------------------------------------------------
// Section 4: PathLeverClassification — serde, clone
// ---------------------------------------------------------------------------

#[test]
fn path_lever_classification_serde_roundtrip() {
    let plc = PathLeverClassification {
        path: "crates/franken-engine/src/parser.rs".to_string(),
        category: Some(LeverCategory::Execution),
    };
    let json = serde_json::to_string(&plc).unwrap();
    let back: PathLeverClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(back, plc);
}

#[test]
fn path_lever_classification_none_category_roundtrip() {
    let plc = PathLeverClassification {
        path: "docs/readme.md".to_string(),
        category: None,
    };
    let json = serde_json::to_string(&plc).unwrap();
    let back: PathLeverClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(back, plc);
}

// ---------------------------------------------------------------------------
// Section 5: OneLeverPolicyEvent — serde, clone, debug
// ---------------------------------------------------------------------------

#[test]
fn policy_event_serde_roundtrip() {
    let ev = OneLeverPolicyEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: ONE_LEVER_POLICY_COMPONENT.to_string(),
        event: "one_lever_policy_started".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        change_id: Some("olp-abc".to_string()),
        path: None,
        lever_category: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: OneLeverPolicyEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ev);
}

#[test]
fn policy_event_with_all_optional_fields_roundtrip() {
    let ev = OneLeverPolicyEvent {
        trace_id: "t-2".to_string(),
        decision_id: "d-2".to_string(),
        policy_id: "p-2".to_string(),
        component: ONE_LEVER_POLICY_COMPONENT.to_string(),
        event: "changed_path_classified".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("FE-1LEV-1001".to_string()),
        change_id: Some("olp-xyz".to_string()),
        path: Some("src/foo.rs".to_string()),
        lever_category: Some("execution".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: OneLeverPolicyEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ev);
}

#[test]
fn policy_event_clone_eq() {
    let ev = OneLeverPolicyEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        change_id: None,
        path: None,
        lever_category: None,
    };
    let cloned = ev.clone();
    assert_eq!(ev, cloned);
}

// ---------------------------------------------------------------------------
// Section 6: OneLeverPolicyRequest — serde, clone
// ---------------------------------------------------------------------------

#[test]
fn policy_request_serde_roundtrip() {
    let req = single_lever_request(3_000_000);
    let json = serde_json::to_string(&req).unwrap();
    let back: OneLeverPolicyRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, req);
}

#[test]
fn policy_request_clone_eq() {
    let a = single_lever_request(2_500_000);
    let b = a.clone();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Section 7: OneLeverPolicyDecision — serde, allows_change
// ---------------------------------------------------------------------------

#[test]
fn policy_decision_serde_roundtrip_allow() {
    let decision = evaluate_one_lever_policy(&single_lever_request(3_000_000));
    assert!(decision.allows_change());
    let json = serde_json::to_string(&decision).unwrap();
    let back: OneLeverPolicyDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn policy_decision_serde_roundtrip_deny() {
    let decision = evaluate_one_lever_policy(&single_lever_request(500_000));
    assert!(!decision.allows_change());
    let json = serde_json::to_string(&decision).unwrap();
    let back: OneLeverPolicyDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn policy_decision_allows_change_reflects_outcome() {
    let allow = evaluate_one_lever_policy(&non_opt_request());
    assert!(allow.allows_change());
    assert_eq!(allow.outcome, "allow");

    let deny = evaluate_one_lever_policy(&single_lever_request(1_000_000));
    assert!(!deny.allows_change());
    assert_eq!(deny.outcome, "deny");
}

// ---------------------------------------------------------------------------
// Section 8: Validation — empty required fields
// ---------------------------------------------------------------------------

#[test]
fn validation_empty_trace_id_blocked() {
    let mut req = non_opt_request();
    req.trace_id = String::new();
    let d = evaluate_one_lever_policy(&req);
    assert!(d.blocked);
    assert_eq!(d.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
    assert!(d.missing_requirements[0].contains("trace_id"));
}

#[test]
fn validation_whitespace_trace_id_blocked() {
    let mut req = non_opt_request();
    req.trace_id = "   ".to_string();
    let d = evaluate_one_lever_policy(&req);
    assert!(d.blocked);
    assert_eq!(d.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
}

#[test]
fn validation_empty_decision_id_blocked() {
    let mut req = non_opt_request();
    req.decision_id = String::new();
    let d = evaluate_one_lever_policy(&req);
    assert!(d.blocked);
    assert_eq!(d.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
}

#[test]
fn validation_empty_policy_id_blocked() {
    let mut req = non_opt_request();
    req.policy_id = "  ".to_string();
    let d = evaluate_one_lever_policy(&req);
    assert!(d.blocked);
}

#[test]
fn validation_empty_commit_sha_blocked() {
    let mut req = non_opt_request();
    req.commit_sha = String::new();
    let d = evaluate_one_lever_policy(&req);
    assert!(d.blocked);
    assert_eq!(d.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
}

#[test]
fn validation_empty_changed_paths_blocked() {
    let mut req = non_opt_request();
    req.changed_paths = Vec::new();
    let d = evaluate_one_lever_policy(&req);
    assert!(d.blocked);
    assert!(d.missing_requirements[0].contains("changed_paths"));
}

#[test]
fn validation_whitespace_only_paths_treated_as_empty() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["  ".to_string(), "\t".to_string()];
    let d = evaluate_one_lever_policy(&req);
    assert!(d.blocked);
    assert_eq!(d.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
}

#[test]
fn validation_failure_has_no_change_id() {
    let mut req = non_opt_request();
    req.trace_id = String::new();
    let d = evaluate_one_lever_policy(&req);
    assert!(d.change_id.is_none());
}

// ---------------------------------------------------------------------------
// Section 9: Non-optimization change (exempt paths)
// ---------------------------------------------------------------------------

#[test]
fn non_optimization_docs_change_allowed() {
    let d = evaluate_one_lever_policy(&non_opt_request());
    assert!(d.allows_change());
    assert!(!d.optimization_change);
    assert!(d.lever_categories.is_empty());
    assert!(d.missing_requirements.is_empty());
    assert!(!d.blocked);
}

#[test]
fn non_optimization_test_file_allowed() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["crates/franken-engine/tests/some_test.rs".to_string()];
    let d = evaluate_one_lever_policy(&req);
    assert!(d.allows_change());
    assert!(!d.optimization_change);
}

#[test]
fn non_optimization_artifacts_allowed() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["artifacts/report.txt".to_string()];
    let d = evaluate_one_lever_policy(&req);
    assert!(d.allows_change());
}

#[test]
fn non_optimization_beads_allowed() {
    let mut req = non_opt_request();
    req.changed_paths = vec![".beads/issues.jsonl".to_string()];
    let d = evaluate_one_lever_policy(&req);
    assert!(d.allows_change());
}

#[test]
fn non_optimization_github_workflows_allowed() {
    let mut req = non_opt_request();
    req.changed_paths = vec![".github/workflows/ci.yml".to_string()];
    let d = evaluate_one_lever_policy(&req);
    assert!(d.allows_change());
}

#[test]
fn non_optimization_scripts_check_allowed() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["scripts/check_lint.sh".to_string()];
    let d = evaluate_one_lever_policy(&req);
    assert!(d.allows_change());
}

#[test]
fn non_optimization_unknown_path_allowed() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["random/unknown.txt".to_string()];
    let d = evaluate_one_lever_policy(&req);
    assert!(d.allows_change());
    assert!(!d.optimization_change);
}

// ---------------------------------------------------------------------------
// Section 10: Single lever — pass/deny with evidence and scoring
// ---------------------------------------------------------------------------

#[test]
fn single_lever_execution_above_threshold_allowed() {
    let d = evaluate_one_lever_policy(&single_lever_request(3_000_000));
    assert!(d.allows_change());
    assert!(d.optimization_change);
    assert!(!d.is_multi_lever);
    assert_eq!(d.lever_categories, vec![LeverCategory::Execution]);
    assert_eq!(d.opportunity_score_millionths, Some(3_000_000));
}

#[test]
fn single_lever_exactly_at_threshold_allowed() {
    let d = evaluate_one_lever_policy(&single_lever_request(2_000_000));
    assert!(d.allows_change());
}

#[test]
fn single_lever_one_below_threshold_denied() {
    let d = evaluate_one_lever_policy(&single_lever_request(1_999_999));
    assert!(!d.allows_change());
    assert!(d.blocked);
    assert_eq!(d.error_code.as_deref(), Some(ERROR_SCORE_BELOW_THRESHOLD));
}

#[test]
fn single_lever_zero_score_denied() {
    let d = evaluate_one_lever_policy(&single_lever_request(0));
    assert!(!d.allows_change());
    assert_eq!(d.error_code.as_deref(), Some(ERROR_SCORE_BELOW_THRESHOLD));
}

#[test]
fn single_lever_negative_score_denied() {
    let d = evaluate_one_lever_policy(&single_lever_request(-1_000_000));
    assert!(!d.allows_change());
    assert_eq!(d.error_code.as_deref(), Some(ERROR_SCORE_BELOW_THRESHOLD));
}

#[test]
fn single_lever_missing_baseline_denied() {
    let mut req = single_lever_request(5_000_000);
    req.evidence.baseline_benchmark_run_id = None;
    let d = evaluate_one_lever_policy(&req);
    assert!(!d.allows_change());
    assert_eq!(d.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    assert!(
        d.missing_requirements
            .contains(&"baseline_benchmark_run_id".to_string())
    );
}

#[test]
fn single_lever_missing_multiple_evidence_fields() {
    let mut req = single_lever_request(5_000_000);
    req.evidence.baseline_benchmark_run_id = None;
    req.evidence.delta_report_ref = None;
    req.evidence.semantic_equivalence_ref = None;
    let d = evaluate_one_lever_policy(&req);
    assert!(!d.allows_change());
    assert_eq!(d.missing_requirements.len(), 3);
    assert!(
        d.missing_requirements
            .contains(&"baseline_benchmark_run_id".to_string())
    );
    assert!(
        d.missing_requirements
            .contains(&"delta_report_ref".to_string())
    );
    assert!(
        d.missing_requirements
            .contains(&"semantic_equivalence_ref".to_string())
    );
}

#[test]
fn single_lever_missing_score_denied() {
    let mut req = single_lever_request(3_000_000);
    req.evidence.opportunity_score_millionths = None;
    let d = evaluate_one_lever_policy(&req);
    assert!(!d.allows_change());
    assert_eq!(d.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
}

#[test]
fn single_lever_all_evidence_missing_lists_all_requirements() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["crates/franken-engine/src/baseline_interpreter.rs".to_string()];
    // No evidence at all for an optimization change
    let d = evaluate_one_lever_policy(&req);
    assert!(!d.allows_change());
    assert!(d.optimization_change);
    assert_eq!(d.missing_requirements.len(), 9);
}

// ---------------------------------------------------------------------------
// Section 11: Multi-lever — deny without override, allow with override
// ---------------------------------------------------------------------------

#[test]
fn multi_lever_without_override_denied() {
    let d = evaluate_one_lever_policy(&multi_lever_request(
        5_000_000,
        "perf: touches multiple levers",
    ));
    assert!(!d.allows_change());
    assert!(d.is_multi_lever);
    assert_eq!(d.error_code.as_deref(), Some(ERROR_MULTI_LEVER_VIOLATION));
    assert!(d.override_reason.is_none());
}

#[test]
fn multi_lever_with_override_allowed() {
    let d = evaluate_one_lever_policy(&multi_lever_request(
        5_000_000,
        "perf: coupled fix [multi-lever: gc and interpreter inseparable]",
    ));
    assert!(d.allows_change());
    assert!(d.is_multi_lever);
    assert_eq!(
        d.override_reason.as_deref(),
        Some("gc and interpreter inseparable")
    );
}

#[test]
fn multi_lever_override_case_insensitive() {
    let d = evaluate_one_lever_policy(&multi_lever_request(
        5_000_000,
        "perf: fix [MULTI-LEVER: Both are needed]",
    ));
    assert!(d.allows_change());
    assert_eq!(d.override_reason.as_deref(), Some("Both are needed"));
}

#[test]
fn multi_lever_empty_override_still_denied() {
    let d = evaluate_one_lever_policy(&multi_lever_request(5_000_000, "perf: fix [multi-lever: ]"));
    assert!(!d.allows_change());
    assert!(d.is_multi_lever);
    assert_eq!(d.error_code.as_deref(), Some(ERROR_MULTI_LEVER_VIOLATION));
}

#[test]
fn multi_lever_categories_sorted() {
    let d = evaluate_one_lever_policy(&multi_lever_request(
        5_000_000,
        "perf: coupled [multi-lever: test]",
    ));
    assert!(d.is_multi_lever);
    // Execution < Memory in sort order
    assert_eq!(d.lever_categories[0], LeverCategory::Execution);
    assert_eq!(d.lever_categories[1], LeverCategory::Memory);
}

// ---------------------------------------------------------------------------
// Section 12: Path classification — every lever category
// ---------------------------------------------------------------------------

#[test]
fn classify_execution_paths() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["crates/franken-engine/src/some_module.rs".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert!(d.optimization_change);
    assert_eq!(d.lever_categories, vec![LeverCategory::Execution]);
}

#[test]
fn classify_memory_paths() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["src/gc_manager.rs".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Memory]);
}

#[test]
fn classify_security_paths() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["src/capability_witness.rs".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Security]);
}

#[test]
fn classify_benchmark_paths() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["scripts/run_benchmark.sh".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Benchmark]);
}

#[test]
fn classify_config_paths() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["Cargo.toml".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Config]);
}

#[test]
fn classify_yaml_as_config() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["settings.yaml".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Config]);
}

#[test]
fn classify_json_as_config() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["config.json".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Config]);
}

#[test]
fn classify_ron_as_config() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["scene.ron".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Config]);
}

#[test]
fn classify_parser_as_execution() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["src/parser_v2.rs".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Execution]);
}

#[test]
fn classify_scheduler_as_execution() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["src/scheduler_lane.rs".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Execution]);
}

// ---------------------------------------------------------------------------
// Section 13: Normalization — trimming, dedup, whitespace-only evidence
// ---------------------------------------------------------------------------

#[test]
fn normalization_trims_trace_id() {
    let mut req = non_opt_request();
    req.trace_id = "  t-integ  ".to_string();
    let d = evaluate_one_lever_policy(&req);
    assert!(d.allows_change());
    assert_eq!(d.events[0].trace_id, "t-integ");
}

#[test]
fn normalization_deduplicates_paths() {
    let mut req = non_opt_request();
    req.changed_paths = vec![
        "docs/design.md".to_string(),
        "docs/design.md".to_string(),
        "docs/other.md".to_string(),
    ];
    let d = evaluate_one_lever_policy(&req);
    assert!(d.allows_change());
    assert_eq!(d.lever_classification.len(), 2);
}

#[test]
fn normalization_whitespace_only_evidence_becomes_none() {
    let mut req = single_lever_request(3_000_000);
    req.evidence.baseline_benchmark_run_id = Some("  ".to_string());
    let d = evaluate_one_lever_policy(&req);
    // The whitespace-only evidence is normalized to None, so it becomes missing
    assert!(!d.allows_change());
    assert!(
        d.missing_requirements
            .contains(&"baseline_benchmark_run_id".to_string())
    );
}

// ---------------------------------------------------------------------------
// Section 14: Decision metadata — schema, change_id, events, threshold
// ---------------------------------------------------------------------------

#[test]
fn decision_has_schema_version() {
    let d = evaluate_one_lever_policy(&non_opt_request());
    assert_eq!(d.schema_version, ONE_LEVER_POLICY_SCHEMA_VERSION);
}

#[test]
fn decision_has_change_id_starting_with_olp() {
    let d = evaluate_one_lever_policy(&non_opt_request());
    assert!(d.change_id.is_some());
    assert!(d.change_id.as_ref().unwrap().starts_with("olp-"));
}

#[test]
fn decision_change_id_is_deterministic() {
    let req = non_opt_request();
    let d1 = evaluate_one_lever_policy(&req);
    let d2 = evaluate_one_lever_policy(&req);
    assert_eq!(d1.change_id, d2.change_id);
}

#[test]
fn decision_change_id_differs_for_different_inputs() {
    let d1 = evaluate_one_lever_policy(&non_opt_request());
    let d2 = evaluate_one_lever_policy(&single_lever_request(3_000_000));
    assert_ne!(d1.change_id, d2.change_id);
}

#[test]
fn decision_has_started_and_completed_events() {
    let d = evaluate_one_lever_policy(&non_opt_request());
    assert!(d.events.len() >= 2);
    assert_eq!(d.events[0].event, "one_lever_policy_started");
    assert_eq!(d.events[0].component, ONE_LEVER_POLICY_COMPONENT);
    assert_eq!(d.events.last().unwrap().event, "one_lever_policy_completed");
}

#[test]
fn decision_events_include_classification_for_opt_change() {
    let d = evaluate_one_lever_policy(&single_lever_request(3_000_000));
    let classification_events: Vec<_> = d
        .events
        .iter()
        .filter(|e| e.event == "changed_path_classified")
        .collect();
    assert_eq!(classification_events.len(), 1);
    assert!(classification_events[0].path.is_some());
    assert!(classification_events[0].lever_category.is_some());
}

#[test]
fn decision_score_threshold_always_present() {
    let d = evaluate_one_lever_policy(&non_opt_request());
    assert_eq!(
        d.score_threshold_millionths,
        ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS
    );
}

#[test]
fn decision_lever_classification_sorted_by_path() {
    let mut req = non_opt_request();
    req.changed_paths = vec![
        "docs/z.md".to_string(),
        "docs/a.md".to_string(),
        "docs/m.md".to_string(),
    ];
    let d = evaluate_one_lever_policy(&req);
    let paths: Vec<&str> = d
        .lever_classification
        .iter()
        .map(|c| c.path.as_str())
        .collect();
    let mut sorted_paths = paths.clone();
    sorted_paths.sort();
    assert_eq!(paths, sorted_paths);
}

// ---------------------------------------------------------------------------
// Section 15: Determinism — same input produces identical output
// ---------------------------------------------------------------------------

#[test]
fn full_determinism_for_identical_requests() {
    let req = single_lever_request(3_000_000);
    let d1 = evaluate_one_lever_policy(&req);
    let d2 = evaluate_one_lever_policy(&req);
    assert_eq!(d1, d2);
}

// ---------------------------------------------------------------------------
// Section 16: Mixed optimization and non-optimization paths
// ---------------------------------------------------------------------------

#[test]
fn mixed_opt_and_non_opt_paths_is_optimization_change() {
    let mut req = non_opt_request();
    req.changed_paths = vec![
        "docs/design.md".to_string(), // exempt
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(), // Execution
    ];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert!(d.optimization_change);
    assert!(d.allows_change());
    assert_eq!(d.lever_categories, vec![LeverCategory::Execution]);
}

// ---------------------------------------------------------------------------
// Section 17: Edge cases — large score, workflow paths, extension host
// ---------------------------------------------------------------------------

#[test]
fn very_large_score_allowed() {
    let d = evaluate_one_lever_policy(&single_lever_request(i64::MAX));
    assert!(d.allows_change());
}

#[test]
fn workflow_path_is_exempt() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["ci/workflow_run.sh".to_string()];
    let d = evaluate_one_lever_policy(&req);
    assert!(d.allows_change());
    assert!(!d.optimization_change);
}

#[test]
fn extension_host_src_classified_as_execution() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["crates/franken-extension-host/src/runtime.rs".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Execution]);
}

#[test]
fn scripts_flamegraph_classified_as_benchmark() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["scripts/run_flamegraph.sh".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Benchmark]);
}

#[test]
fn heap_path_classified_as_memory() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["src/heap_manager.rs".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Memory]);
}

#[test]
fn ifc_path_classified_as_security() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["src/ifc_labels.rs".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Security]);
}

#[test]
fn attestation_path_classified_as_security() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["src/attestation_handshake.rs".to_string()];
    req.evidence = full_evidence(3_000_000);
    let d = evaluate_one_lever_policy(&req);
    assert_eq!(d.lever_categories, vec![LeverCategory::Security]);
}

#[test]
fn md_file_outside_docs_is_exempt() {
    let mut req = non_opt_request();
    req.changed_paths = vec!["README.md".to_string()];
    let d = evaluate_one_lever_policy(&req);
    assert!(d.allows_change());
    assert!(!d.optimization_change);
}
