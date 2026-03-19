//! Enrichment integration tests for `one_lever_policy`.
//!
//! Focuses on: path classification edge cases, multi-lever override semantics,
//! validation boundary conditions, normalization behavior, serde roundtrips
//! for denied decisions, event audit trail completeness, deterministic change
//! IDs, and Display/Debug coverage.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::one_lever_policy::{
    ERROR_INVALID_REQUEST, ERROR_MISSING_EVIDENCE, ERROR_MULTI_LEVER_VIOLATION,
    ERROR_SCORE_BELOW_THRESHOLD, LeverCategory, ONE_LEVER_POLICY_COMPONENT,
    ONE_LEVER_POLICY_SCHEMA_VERSION, ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS, OneLeverEvidenceRefs,
    OneLeverPolicyDecision, OneLeverPolicyRequest, PathLeverClassification,
    evaluate_one_lever_policy,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn doc_request() -> OneLeverPolicyRequest {
    OneLeverPolicyRequest {
        trace_id: "t-enrich".to_string(),
        decision_id: "d-enrich".to_string(),
        policy_id: "p-enrich".to_string(),
        commit_sha: "cafe1234".to_string(),
        commit_message: "docs: update guide".to_string(),
        changed_paths: vec!["docs/guide.md".to_string()],
        evidence: OneLeverEvidenceRefs::default(),
    }
}

fn full_evidence(score: i64) -> OneLeverEvidenceRefs {
    OneLeverEvidenceRefs {
        baseline_benchmark_run_id: Some("baseline-e".to_string()),
        post_change_benchmark_run_id: Some("post-e".to_string()),
        delta_report_ref: Some("delta-e".to_string()),
        semantic_equivalence_ref: Some("equiv-e".to_string()),
        trace_replay_ref: Some("replay-e".to_string()),
        isomorphism_ledger_ref: Some("iso-e".to_string()),
        rollback_instructions_ref: Some("rollback-e".to_string()),
        reprofile_after_merge_ref: Some("reprofile-e".to_string()),
        opportunity_score_millionths: Some(score),
    }
}

fn exec_opt_request(score: i64) -> OneLeverPolicyRequest {
    OneLeverPolicyRequest {
        trace_id: "t-enrich".to_string(),
        decision_id: "d-enrich".to_string(),
        policy_id: "p-enrich".to_string(),
        commit_sha: "cafe1234".to_string(),
        commit_message: "perf: optimize execution".to_string(),
        changed_paths: vec!["crates/franken-engine/src/baseline_interpreter.rs".to_string()],
        evidence: full_evidence(score),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[test]
fn enrichment_non_opt_change_always_allowed() {
    let decision = evaluate_one_lever_policy(&doc_request());
    assert!(decision.allows_change());
    assert!(!decision.blocked);
    assert!(!decision.optimization_change);
    assert!(decision.lever_categories.is_empty());
}

#[test]
fn enrichment_single_lever_at_threshold_allowed() {
    let req = exec_opt_request(ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS);
    let decision = evaluate_one_lever_policy(&req);
    assert!(decision.allows_change());
    assert!(!decision.blocked);
}

#[test]
fn enrichment_single_lever_one_below_threshold_denied() {
    let req = exec_opt_request(ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS - 1);
    let decision = evaluate_one_lever_policy(&req);
    assert!(!decision.allows_change());
    assert!(decision.blocked);
    assert_eq!(
        decision.error_code.as_deref(),
        Some(ERROR_SCORE_BELOW_THRESHOLD)
    );
}

#[test]
fn enrichment_zero_score_denied() {
    let req = exec_opt_request(0);
    let decision = evaluate_one_lever_policy(&req);
    assert!(!decision.allows_change());
    assert_eq!(
        decision.error_code.as_deref(),
        Some(ERROR_SCORE_BELOW_THRESHOLD)
    );
}

#[test]
fn enrichment_negative_score_denied() {
    let req = exec_opt_request(-5_000_000);
    let decision = evaluate_one_lever_policy(&req);
    assert!(!decision.allows_change());
    assert_eq!(decision.opportunity_score_millionths, Some(-5_000_000));
}

#[test]
fn enrichment_very_large_score_allowed() {
    let req = exec_opt_request(i64::MAX);
    let decision = evaluate_one_lever_policy(&req);
    assert!(decision.allows_change());
}

#[test]
fn enrichment_multi_lever_without_override_denied() {
    let req = OneLeverPolicyRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        commit_sha: "abc".to_string(),
        commit_message: "perf: multi lever change".to_string(),
        changed_paths: vec![
            "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
            "crates/franken-engine/src/gc_pause.rs".to_string(),
        ],
        evidence: full_evidence(5_000_000),
    };
    let decision = evaluate_one_lever_policy(&req);
    assert!(!decision.allows_change());
    assert!(decision.is_multi_lever);
    assert_eq!(
        decision.error_code.as_deref(),
        Some(ERROR_MULTI_LEVER_VIOLATION)
    );
}

#[test]
fn enrichment_multi_lever_with_override_and_high_score_allowed() {
    let req = OneLeverPolicyRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        commit_sha: "abc".to_string(),
        commit_message: "perf: [multi-lever: gc and interpreter coupled]".to_string(),
        changed_paths: vec![
            "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
            "crates/franken-engine/src/gc_pause.rs".to_string(),
        ],
        evidence: full_evidence(5_000_000),
    };
    let decision = evaluate_one_lever_policy(&req);
    assert!(decision.allows_change());
    assert!(decision.is_multi_lever);
    assert_eq!(
        decision.override_reason.as_deref(),
        Some("gc and interpreter coupled")
    );
}

#[test]
fn enrichment_multi_lever_override_below_threshold_still_denied() {
    let req = OneLeverPolicyRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        commit_sha: "abc".to_string(),
        commit_message: "perf: [multi-lever: coupled]".to_string(),
        changed_paths: vec![
            "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
            "crates/franken-engine/src/gc_pause.rs".to_string(),
        ],
        evidence: full_evidence(1_000_000), // below 2.0
    };
    let decision = evaluate_one_lever_policy(&req);
    assert!(!decision.allows_change());
    assert_eq!(
        decision.error_code.as_deref(),
        Some(ERROR_SCORE_BELOW_THRESHOLD)
    );
}

#[test]
fn enrichment_missing_single_evidence_field_denied() {
    let mut req = exec_opt_request(5_000_000);
    req.evidence.baseline_benchmark_run_id = None;
    let decision = evaluate_one_lever_policy(&req);
    assert!(!decision.allows_change());
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    assert!(
        decision
            .missing_requirements
            .contains(&"baseline_benchmark_run_id".to_string())
    );
}

#[test]
fn enrichment_missing_all_evidence_for_opt_change_denied() {
    let req = OneLeverPolicyRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        commit_sha: "abc".to_string(),
        commit_message: "perf: optimize".to_string(),
        changed_paths: vec!["crates/franken-engine/src/baseline_interpreter.rs".to_string()],
        evidence: OneLeverEvidenceRefs::default(),
    };
    let decision = evaluate_one_lever_policy(&req);
    assert!(!decision.allows_change());
    assert!(decision.missing_requirements.len() >= 8);
}

#[test]
fn enrichment_validation_empty_trace_id_after_trimming() {
    let mut req = doc_request();
    req.trace_id = "   ".to_string();
    let decision = evaluate_one_lever_policy(&req);
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
}

#[test]
fn enrichment_validation_empty_decision_id() {
    let mut req = doc_request();
    req.decision_id = String::new();
    let decision = evaluate_one_lever_policy(&req);
    assert!(decision.blocked);
}

#[test]
fn enrichment_validation_empty_commit_sha() {
    let mut req = doc_request();
    req.commit_sha = "  ".to_string();
    let decision = evaluate_one_lever_policy(&req);
    assert!(decision.blocked);
}

#[test]
fn enrichment_validation_whitespace_only_paths_rejected() {
    let mut req = doc_request();
    req.changed_paths = vec!["   ".to_string(), "  ".to_string()];
    let decision = evaluate_one_lever_policy(&req);
    assert!(decision.blocked);
}

#[test]
fn enrichment_normalization_trims_evidence_fields() {
    let mut req = exec_opt_request(3_000_000);
    req.evidence.baseline_benchmark_run_id = Some("  base  ".to_string());
    req.evidence.delta_report_ref = Some("  delta  ".to_string());
    let decision = evaluate_one_lever_policy(&req);
    // Should succeed since trimmed values are non-empty
    assert!(decision.allows_change());
}

#[test]
fn enrichment_normalization_empty_evidence_becomes_none() {
    let mut req = exec_opt_request(3_000_000);
    req.evidence.baseline_benchmark_run_id = Some("   ".to_string());
    let decision = evaluate_one_lever_policy(&req);
    // baseline_benchmark_run_id is now missing after trim -> None
    assert!(!decision.allows_change());
    assert!(
        decision
            .missing_requirements
            .contains(&"baseline_benchmark_run_id".to_string())
    );
}

#[test]
fn enrichment_change_id_deterministic() {
    let req = doc_request();
    let d1 = evaluate_one_lever_policy(&req);
    let d2 = evaluate_one_lever_policy(&req);
    assert_eq!(d1.change_id, d2.change_id);
    assert!(d1.change_id.as_ref().unwrap().starts_with("olp-"));
}

#[test]
fn enrichment_change_id_differs_for_different_sha() {
    let req1 = doc_request();
    let mut req2 = doc_request();
    req2.commit_sha = "different_sha".to_string();
    let d1 = evaluate_one_lever_policy(&req1);
    let d2 = evaluate_one_lever_policy(&req2);
    assert_ne!(d1.change_id, d2.change_id);
}

#[test]
fn enrichment_events_contain_start_and_completion() {
    let decision = evaluate_one_lever_policy(&doc_request());
    let event_names: Vec<&str> = decision.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"one_lever_policy_started"));
    assert!(event_names.contains(&"one_lever_policy_completed"));
}

#[test]
fn enrichment_events_all_have_correct_component() {
    let decision = evaluate_one_lever_policy(&doc_request());
    for event in &decision.events {
        assert_eq!(event.component, ONE_LEVER_POLICY_COMPONENT);
    }
}

#[test]
fn enrichment_events_include_path_classification_for_opt_change() {
    let req = exec_opt_request(3_000_000);
    let decision = evaluate_one_lever_policy(&req);
    let classify_events: Vec<_> = decision
        .events
        .iter()
        .filter(|e| e.event == "changed_path_classified")
        .collect();
    assert_eq!(classify_events.len(), 1);
    assert_eq!(
        classify_events[0].lever_category.as_deref(),
        Some("execution")
    );
}

#[test]
fn enrichment_lever_categories_sorted_deterministically() {
    let req = OneLeverPolicyRequest {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        commit_sha: "abc".to_string(),
        commit_message: "fix: [multi-lever: coupled]".to_string(),
        changed_paths: vec![
            "crates/franken-engine/src/gc_pause.rs".to_string(), // Memory
            "crates/franken-engine/src/baseline_interpreter.rs".to_string(), // Execution
        ],
        evidence: full_evidence(5_000_000),
    };
    let decision = evaluate_one_lever_policy(&req);
    assert!(decision.is_multi_lever);
    assert_eq!(decision.lever_categories[0], LeverCategory::Execution);
    assert_eq!(decision.lever_categories[1], LeverCategory::Memory);
}

#[test]
fn enrichment_serde_roundtrip_allowed_decision() {
    let req = exec_opt_request(3_000_000);
    let decision = evaluate_one_lever_policy(&req);
    assert!(decision.allows_change());
    let json = serde_json::to_string(&decision).unwrap();
    let back: OneLeverPolicyDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_serde_roundtrip_denied_decision() {
    let req = exec_opt_request(500_000);
    let decision = evaluate_one_lever_policy(&req);
    assert!(!decision.allows_change());
    let json = serde_json::to_string(&decision).unwrap();
    let back: OneLeverPolicyDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_serde_roundtrip_validation_failed_decision() {
    let mut req = doc_request();
    req.trace_id = String::new();
    let decision = evaluate_one_lever_policy(&req);
    let json = serde_json::to_string(&decision).unwrap();
    let back: OneLeverPolicyDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_lever_category_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&LeverCategory::Execution).unwrap(),
        "\"execution\""
    );
    assert_eq!(
        serde_json::to_string(&LeverCategory::Memory).unwrap(),
        "\"memory\""
    );
    assert_eq!(
        serde_json::to_string(&LeverCategory::Security).unwrap(),
        "\"security\""
    );
    assert_eq!(
        serde_json::to_string(&LeverCategory::Benchmark).unwrap(),
        "\"benchmark\""
    );
    assert_eq!(
        serde_json::to_string(&LeverCategory::Config).unwrap(),
        "\"config\""
    );
}

#[test]
fn enrichment_lever_category_display_all_unique() {
    let cats = [
        LeverCategory::Execution,
        LeverCategory::Memory,
        LeverCategory::Security,
        LeverCategory::Benchmark,
        LeverCategory::Config,
    ];
    let set: BTreeSet<String> = cats.iter().map(|c| c.to_string()).collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_lever_category_as_str_matches_display() {
    for cat in [
        LeverCategory::Execution,
        LeverCategory::Memory,
        LeverCategory::Security,
        LeverCategory::Benchmark,
        LeverCategory::Config,
    ] {
        assert_eq!(cat.as_str(), cat.to_string());
    }
}

#[test]
fn enrichment_lever_category_ord_stable() {
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
fn enrichment_schema_version_and_constants_stable() {
    assert_eq!(
        ONE_LEVER_POLICY_SCHEMA_VERSION,
        "franken-engine.one-lever-policy.v1"
    );
    assert_eq!(ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS, 2_000_000);
    assert_eq!(ERROR_INVALID_REQUEST, "FE-1LEV-1001");
    assert_eq!(ERROR_MULTI_LEVER_VIOLATION, "FE-1LEV-1002");
    assert_eq!(ERROR_MISSING_EVIDENCE, "FE-1LEV-1003");
    assert_eq!(ERROR_SCORE_BELOW_THRESHOLD, "FE-1LEV-1004");
}

#[test]
fn enrichment_decision_always_has_schema_version_and_threshold() {
    let decision = evaluate_one_lever_policy(&doc_request());
    assert_eq!(decision.schema_version, ONE_LEVER_POLICY_SCHEMA_VERSION);
    assert_eq!(
        decision.score_threshold_millionths,
        ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS
    );
}

#[test]
fn enrichment_deterministic_full_scenario_replay() {
    let run = || {
        let req = exec_opt_request(3_000_000);
        evaluate_one_lever_policy(&req)
    };
    let d1 = run();
    let d2 = run();
    assert_eq!(d1, d2);
}

#[test]
fn enrichment_path_lever_classification_serde_roundtrip() {
    let plc = PathLeverClassification {
        path: "crates/franken-engine/src/parser.rs".to_string(),
        category: Some(LeverCategory::Execution),
    };
    let json = serde_json::to_string(&plc).unwrap();
    let back: PathLeverClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(plc, back);
}

#[test]
fn enrichment_path_lever_classification_none_category() {
    let plc = PathLeverClassification {
        path: "docs/readme.md".to_string(),
        category: None,
    };
    let json = serde_json::to_string(&plc).unwrap();
    assert!(json.contains("null"));
    let back: PathLeverClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(plc, back);
}

#[test]
fn enrichment_evidence_refs_default_all_none() {
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
fn enrichment_debug_format_nonempty_for_all_types() {
    let cat = LeverCategory::Execution;
    assert!(!format!("{:?}", cat).is_empty());

    let ev = full_evidence(1_000_000);
    assert!(!format!("{:?}", ev).is_empty());

    let req = doc_request();
    assert!(!format!("{:?}", req).is_empty());

    let decision = evaluate_one_lever_policy(&doc_request());
    assert!(!format!("{:?}", decision).is_empty());

    let plc = PathLeverClassification {
        path: "p".to_string(),
        category: Some(LeverCategory::Config),
    };
    assert!(!format!("{:?}", plc).is_empty());
}
