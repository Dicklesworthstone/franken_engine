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

use std::path::PathBuf;

use frankenengine_engine::one_lever_policy::{
    ERROR_INVALID_REQUEST, ERROR_MISSING_EVIDENCE, ERROR_MULTI_LEVER_VIOLATION,
    ERROR_SCORE_BELOW_THRESHOLD, LeverCategory, ONE_LEVER_POLICY_COMPONENT,
    ONE_LEVER_POLICY_SCHEMA_VERSION, ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS, OneLeverEvidenceRefs,
    OneLeverPolicyDecision, OneLeverPolicyRequest, evaluate_one_lever_policy,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn complete_evidence(score_millionths: i64) -> OneLeverEvidenceRefs {
    OneLeverEvidenceRefs {
        baseline_benchmark_run_id: Some("bench://baseline/run-001".to_string()),
        post_change_benchmark_run_id: Some("bench://after/run-002".to_string()),
        delta_report_ref: Some("artifact://delta/run-002".to_string()),
        semantic_equivalence_ref: Some("artifact://golden/equivalence-v1".to_string()),
        trace_replay_ref: Some("artifact://replay/trace-001".to_string()),
        isomorphism_ledger_ref: Some("artifact://isomorphism/ledger-001".to_string()),
        rollback_instructions_ref: Some("docs://rollback/optimization-001".to_string()),
        reprofile_after_merge_ref: Some("artifact://reprofile/post-merge-001".to_string()),
        opportunity_score_millionths: Some(score_millionths),
    }
}

fn base_request() -> OneLeverPolicyRequest {
    OneLeverPolicyRequest {
        trace_id: "trace-one-lever-001".to_string(),
        decision_id: "decision-one-lever-001".to_string(),
        policy_id: "policy-one-lever-v1".to_string(),
        commit_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
        commit_message: "perf: optimize dispatch hotpath".to_string(),
        changed_paths: vec!["crates/franken-engine/src/baseline_interpreter.rs".to_string()],
        evidence: complete_evidence(2_400_000),
    }
}

#[test]
fn multi_lever_change_without_override_is_denied() {
    let mut request = base_request();
    request.changed_paths = vec![
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
        "crates/franken-engine/src/gc_pause.rs".to_string(),
    ];

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(
        decision.error_code.as_deref(),
        Some(ERROR_MULTI_LEVER_VIOLATION)
    );
    assert!(decision.is_multi_lever);
    assert!(decision.override_reason.is_none());
    assert!(
        decision
            .lever_categories
            .contains(&LeverCategory::Execution)
    );
    assert!(decision.lever_categories.contains(&LeverCategory::Memory));
}

#[test]
fn multi_lever_override_allows_with_reason() {
    let mut request = base_request();
    request.commit_message =
        "perf: coupled runtime fix [multi-lever: scheduler and gc are tightly coupled]".to_string();
    request.changed_paths = vec![
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
        "crates/franken-engine/src/gc_pause.rs".to_string(),
    ];

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(decision.allows_change());
    assert!(decision.is_multi_lever);
    assert_eq!(
        decision.override_reason.as_deref(),
        Some("scheduler and gc are tightly coupled")
    );
}

#[test]
fn missing_baseline_after_evidence_is_denied() {
    let mut request = base_request();
    request.evidence.baseline_benchmark_run_id = None;
    request.evidence.post_change_benchmark_run_id = None;

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    assert!(
        decision
            .missing_requirements
            .contains(&"baseline_benchmark_run_id".to_string())
    );
    assert!(
        decision
            .missing_requirements
            .contains(&"post_change_benchmark_run_id".to_string())
    );
}

#[test]
fn missing_semantic_equivalence_and_replay_refs_is_denied() {
    let mut request = base_request();
    request.evidence.semantic_equivalence_ref = None;
    request.evidence.trace_replay_ref = None;

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    assert!(
        decision
            .missing_requirements
            .contains(&"semantic_equivalence_ref".to_string())
    );
    assert!(
        decision
            .missing_requirements
            .contains(&"trace_replay_ref".to_string())
    );
}

#[test]
fn missing_rollback_or_reprofile_is_denied() {
    let mut request = base_request();
    request.evidence.rollback_instructions_ref = None;
    request.evidence.reprofile_after_merge_ref = None;

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    assert!(
        decision
            .missing_requirements
            .contains(&"rollback_instructions_ref".to_string())
    );
    assert!(
        decision
            .missing_requirements
            .contains(&"reprofile_after_merge_ref".to_string())
    );
}

#[test]
fn below_threshold_opportunity_score_is_denied() {
    let mut request = base_request();
    request.evidence = complete_evidence(1_999_999);

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert_eq!(
        decision.error_code.as_deref(),
        Some(ERROR_SCORE_BELOW_THRESHOLD)
    );
}

#[test]
fn docs_and_tests_only_change_is_exempt() {
    let mut request = base_request();
    request.changed_paths = vec![
        "docs/perf_playbook.md".to_string(),
        "crates/franken-engine/tests/opportunity_matrix.rs".to_string(),
        ".github/workflows/version_matrix_conformance.yml".to_string(),
    ];
    request.evidence = OneLeverEvidenceRefs::default();

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(!decision.optimization_change);
    assert!(decision.lever_categories.is_empty());
}

#[test]
fn decision_is_deterministic_for_identical_input() {
    let request = base_request();
    let decision_a = evaluate_one_lever_policy(&request);
    let decision_b = evaluate_one_lever_policy(&request);
    assert_eq!(decision_a, decision_b);
}

#[test]
fn structured_events_have_required_stable_fields() {
    let request = base_request();
    let decision = evaluate_one_lever_policy(&request);

    assert!(!decision.events.is_empty());
    for event in &decision.events {
        assert_eq!(event.trace_id, "trace-one-lever-001");
        assert_eq!(event.decision_id, "decision-one-lever-001");
        assert_eq!(event.policy_id, "policy-one-lever-v1");
        assert_eq!(event.component, ONE_LEVER_POLICY_COMPONENT);
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn lever_category_serde_roundtrip() {
    let categories = [
        LeverCategory::Execution,
        LeverCategory::Memory,
        LeverCategory::Security,
        LeverCategory::Benchmark,
        LeverCategory::Config,
    ];
    for cat in &categories {
        let json = serde_json::to_string(cat).expect("serialize");
        let recovered: LeverCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, cat);
    }
}

#[test]
fn lever_category_display_matches_as_str() {
    let categories = [
        LeverCategory::Execution,
        LeverCategory::Memory,
        LeverCategory::Security,
        LeverCategory::Benchmark,
        LeverCategory::Config,
    ];
    for cat in &categories {
        assert_eq!(cat.to_string(), cat.as_str());
    }
}

#[test]
fn evidence_refs_default_all_none() {
    let evidence = OneLeverEvidenceRefs::default();
    assert!(evidence.baseline_benchmark_run_id.is_none());
    assert!(evidence.opportunity_score_millionths.is_none());
}

#[test]
fn evidence_refs_serde_roundtrip() {
    let evidence = complete_evidence(3_000_000);
    let json = serde_json::to_string(&evidence).expect("serialize");
    let recovered: OneLeverEvidenceRefs = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.opportunity_score_millionths, Some(3_000_000));
    assert_eq!(
        recovered.baseline_benchmark_run_id,
        evidence.baseline_benchmark_run_id
    );
}

#[test]
fn policy_request_serde_roundtrip() {
    let request = base_request();
    let json = serde_json::to_string(&request).expect("serialize");
    let recovered: OneLeverPolicyRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, request.trace_id);
    assert_eq!(recovered.commit_sha, request.commit_sha);
}

#[test]
fn policy_decision_serde_roundtrip() {
    let request = base_request();
    let decision = evaluate_one_lever_policy(&request);
    let json = serde_json::to_string(&decision).expect("serialize");
    let recovered: frankenengine_engine::one_lever_policy::OneLeverPolicyDecision =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.outcome, decision.outcome);
    assert_eq!(recovered.schema_version, decision.schema_version);
}

#[test]
fn decision_schema_version_is_v1() {
    let request = base_request();
    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(
        decision.schema_version,
        frankenengine_engine::one_lever_policy::ONE_LEVER_POLICY_SCHEMA_VERSION
    );
}

#[test]
fn single_lever_with_complete_evidence_is_allowed() {
    let request = base_request();
    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(decision.allows_change());
    assert!(!decision.blocked);
    assert!(!decision.is_multi_lever);
    assert!(decision.error_code.is_none());
}

#[test]
fn missing_opportunity_score_is_denied() {
    let mut request = base_request();
    request.evidence.opportunity_score_millionths = None;

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
}

#[test]
fn version_matrix_workflow_runs_one_lever_policy_gate() {
    let workflow_path = repo_root().join(".github/workflows/version_matrix_conformance.yml");
    let workflow = std::fs::read_to_string(&workflow_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", workflow_path.display()));

    assert!(
        workflow.contains("./scripts/check_one_lever.sh ci"),
        "version_matrix_conformance workflow must run one-lever policy gate script"
    );
}

#[test]
fn lever_category_all_variants_serde_roundtrip() {
    for cat in [
        LeverCategory::Execution,
        LeverCategory::Memory,
        LeverCategory::Security,
    ] {
        let json = serde_json::to_string(&cat).expect("serialize");
        let recovered: LeverCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, cat);
    }
}

#[test]
fn one_lever_component_constant_is_nonempty() {
    assert!(!ONE_LEVER_POLICY_COMPONENT.trim().is_empty());
}

#[test]
fn error_constants_are_nonempty() {
    assert!(!ERROR_MISSING_EVIDENCE.trim().is_empty());
    assert!(!ERROR_MULTI_LEVER_VIOLATION.trim().is_empty());
    assert!(!ERROR_SCORE_BELOW_THRESHOLD.trim().is_empty());
}

// ── New edge-case and coverage tests ───────────────────────────────

#[test]
fn exact_threshold_opportunity_score_is_allowed() {
    // Score exactly at the threshold (2_000_000) should pass.
    let mut request = base_request();
    request.evidence = complete_evidence(ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS);

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(!decision.blocked);
    assert!(decision.error_code.is_none());
    assert_eq!(
        decision.opportunity_score_millionths,
        Some(ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS)
    );
}

#[test]
fn single_security_only_change_with_complete_evidence_is_allowed() {
    let mut request = base_request();
    request.changed_paths = vec!["crates/franken-engine/src/ifc_declassification.rs".to_string()];
    request.evidence = complete_evidence(3_000_000);

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(!decision.blocked);
    assert!(!decision.is_multi_lever);
    assert!(decision.optimization_change);
    assert_eq!(decision.lever_categories, vec![LeverCategory::Security]);
}

#[test]
fn benchmark_only_change_detected_as_benchmark_lever() {
    let mut request = base_request();
    request.changed_paths = vec!["scripts/run_benchmark_suite.sh".to_string()];
    request.evidence = complete_evidence(2_500_000);

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(decision.optimization_change);
    assert_eq!(decision.lever_categories, vec![LeverCategory::Benchmark]);
}

#[test]
fn config_only_change_detected_as_config_lever() {
    let mut request = base_request();
    request.changed_paths = vec!["crates/franken-engine/config.toml".to_string()];
    request.evidence = complete_evidence(2_100_000);

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(decision.optimization_change);
    assert_eq!(decision.lever_categories, vec![LeverCategory::Config]);
}

#[test]
fn empty_changed_paths_is_validation_failure() {
    let mut request = base_request();
    request.changed_paths = Vec::new();

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
    assert!(
        decision
            .missing_requirements
            .iter()
            .any(|msg| msg.contains("changed_paths"))
    );
}

#[test]
fn multi_lever_override_with_missing_evidence_is_still_denied() {
    let mut request = base_request();
    request.commit_message =
        "perf: coupled fix [multi-lever: tightly coupled subsystems]".to_string();
    request.changed_paths = vec![
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
        "crates/franken-engine/src/gc_pause.rs".to_string(),
    ];
    // Remove some evidence fields
    request.evidence.baseline_benchmark_run_id = None;
    request.evidence.semantic_equivalence_ref = None;

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert!(decision.is_multi_lever);
    // Override reason was parsed, but missing evidence still blocks
    assert!(decision.override_reason.is_some());
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    assert!(!decision.missing_requirements.is_empty());
}

#[test]
fn decision_events_contain_expected_event_types() {
    let request = base_request();
    let decision = evaluate_one_lever_policy(&request);

    let event_names: Vec<&str> = decision.events.iter().map(|e| e.event.as_str()).collect();
    assert!(
        event_names.contains(&"one_lever_policy_started"),
        "events must include one_lever_policy_started"
    );
    assert!(
        event_names.contains(&"one_lever_policy_completed"),
        "events must include one_lever_policy_completed"
    );
    // For optimization changes, classification events should be emitted.
    assert!(
        event_names.contains(&"changed_path_classified"),
        "events must include changed_path_classified for optimization changes"
    );
}

#[test]
fn lever_category_as_str_values_are_nonempty_for_all_variants() {
    let all_categories = [
        LeverCategory::Execution,
        LeverCategory::Memory,
        LeverCategory::Security,
        LeverCategory::Benchmark,
        LeverCategory::Config,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for cat in &all_categories {
        let s = cat.as_str();
        assert!(!s.is_empty(), "{:?} has empty as_str", cat);
        assert!(
            seen.insert(s),
            "duplicate as_str value {:?} for {:?}",
            s,
            cat
        );
    }
}

#[test]
fn all_error_code_constants_are_distinct() {
    let codes = [
        ERROR_INVALID_REQUEST,
        ERROR_MULTI_LEVER_VIOLATION,
        ERROR_MISSING_EVIDENCE,
        ERROR_SCORE_BELOW_THRESHOLD,
    ];
    let unique: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(
        unique.len(),
        codes.len(),
        "error codes must be distinct: {:?}",
        codes
    );
}

#[test]
fn decision_with_all_fields_populated_roundtrips_json() {
    // Exercise the full decision structure including change_id, lever_classification, etc.
    let request = base_request();
    let decision = evaluate_one_lever_policy(&request);

    // Verify key fields are populated for an allowed optimization change
    assert!(decision.change_id.is_some(), "change_id should be set");
    assert!(!decision.lever_classification.is_empty());
    assert!(!decision.events.is_empty());
    assert_eq!(
        decision.score_threshold_millionths,
        ONE_LEVER_SCORE_THRESHOLD_MILLIONTHS
    );
    assert_eq!(decision.schema_version, ONE_LEVER_POLICY_SCHEMA_VERSION);

    // Full round-trip: serialize to JSON and back
    let json = serde_json::to_string_pretty(&decision).expect("serialize");
    let recovered: OneLeverPolicyDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, decision);

    // Verify JSON structure contains expected keys
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse json");
    let obj = value.as_object().expect("top-level object");
    for key in &[
        "schema_version",
        "change_id",
        "outcome",
        "blocked",
        "optimization_change",
        "is_multi_lever",
        "lever_categories",
        "lever_classification",
        "missing_requirements",
        "opportunity_score_millionths",
        "score_threshold_millionths",
        "events",
    ] {
        assert!(obj.contains_key(*key), "JSON missing expected key: {key}");
    }
}

#[test]
fn whitespace_only_evidence_refs_are_treated_as_missing() {
    let mut request = base_request();
    request.evidence.baseline_benchmark_run_id = Some("   ".to_string());
    request.evidence.delta_report_ref = Some("\t".to_string());

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));
    assert!(
        decision
            .missing_requirements
            .contains(&"baseline_benchmark_run_id".to_string())
    );
    assert!(
        decision
            .missing_requirements
            .contains(&"delta_report_ref".to_string())
    );
}

// ── Enrichment batch: additional edge-case, serde, ordering, validation tests ──

#[test]
fn empty_trace_id_is_validation_failure() {
    let mut request = base_request();
    request.trace_id = "".to_string();

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
    assert!(
        decision
            .missing_requirements
            .iter()
            .any(|msg| msg.contains("trace_id"))
    );
    // Validation failures should have no change_id
    assert!(decision.change_id.is_none());
}

#[test]
fn empty_decision_id_is_validation_failure() {
    let mut request = base_request();
    request.decision_id = "".to_string();

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
    assert!(
        decision
            .missing_requirements
            .iter()
            .any(|msg| msg.contains("decision_id"))
    );
}

#[test]
fn empty_policy_id_is_validation_failure() {
    let mut request = base_request();
    request.policy_id = "".to_string();

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
    assert!(
        decision
            .missing_requirements
            .iter()
            .any(|msg| msg.contains("policy_id"))
    );
}

#[test]
fn empty_commit_sha_is_validation_failure() {
    let mut request = base_request();
    request.commit_sha = "".to_string();

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
    assert!(
        decision
            .missing_requirements
            .iter()
            .any(|msg| msg.contains("commit_sha"))
    );
}

#[test]
fn whitespace_only_trace_id_normalized_to_empty_triggers_validation() {
    let mut request = base_request();
    request.trace_id = "   ".to_string();

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
}

#[test]
fn lever_category_copy_semantics_preserved() {
    let original = LeverCategory::Benchmark;
    let copied = original;
    // Both the original and copied value are usable after copy
    assert_eq!(original, LeverCategory::Benchmark);
    assert_eq!(copied, LeverCategory::Benchmark);
    assert_eq!(original, copied);
}

#[test]
fn lever_category_ordering_in_btreeset() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(LeverCategory::Config);
    set.insert(LeverCategory::Execution);
    set.insert(LeverCategory::Security);
    set.insert(LeverCategory::Memory);
    set.insert(LeverCategory::Benchmark);

    let ordered: Vec<LeverCategory> = set.into_iter().collect();
    assert_eq!(
        ordered,
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
fn lever_category_debug_format_contains_variant_name() {
    let debug_str = format!("{:?}", LeverCategory::Execution);
    assert_eq!(debug_str, "Execution");

    let debug_str = format!("{:?}", LeverCategory::Config);
    assert_eq!(debug_str, "Config");
}

#[test]
fn evidence_refs_serde_roundtrip_with_all_none() {
    let evidence = OneLeverEvidenceRefs::default();
    let json = serde_json::to_string(&evidence).expect("serialize default");
    let recovered: OneLeverEvidenceRefs = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, evidence);
    // All fields should be null in JSON
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let obj = value.as_object().expect("object");
    for key in [
        "baseline_benchmark_run_id",
        "post_change_benchmark_run_id",
        "delta_report_ref",
        "semantic_equivalence_ref",
        "trace_replay_ref",
        "isomorphism_ledger_ref",
        "rollback_instructions_ref",
        "reprofile_after_merge_ref",
        "opportunity_score_millionths",
    ] {
        assert!(
            obj.get(key).is_none_or(|v| v.is_null()),
            "expected null for key {key}"
        );
    }
}

#[test]
fn path_lever_classification_serde_roundtrip_all_categories() {
    let categories = [
        Some(LeverCategory::Execution),
        Some(LeverCategory::Memory),
        Some(LeverCategory::Security),
        Some(LeverCategory::Benchmark),
        Some(LeverCategory::Config),
        None,
    ];
    for cat in &categories {
        let plc = frankenengine_engine::one_lever_policy::PathLeverClassification {
            path: "some/path.rs".to_string(),
            category: *cat,
        };
        let json = serde_json::to_string(&plc).expect("serialize");
        let recovered: frankenengine_engine::one_lever_policy::PathLeverClassification =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, plc);
    }
}

#[test]
fn policy_event_serde_roundtrip_all_optional_fields_populated() {
    let event = frankenengine_engine::one_lever_policy::OneLeverPolicyEvent {
        trace_id: "tr-42".to_string(),
        decision_id: "dec-42".to_string(),
        policy_id: "pol-42".to_string(),
        component: ONE_LEVER_POLICY_COMPONENT.to_string(),
        event: "one_lever_policy_started".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("FE-1LEV-1001".to_string()),
        change_id: Some("olp-abc123".to_string()),
        path: Some("crates/franken-engine/src/foo.rs".to_string()),
        lever_category: Some("execution".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: frankenengine_engine::one_lever_policy::OneLeverPolicyEvent =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, event);
}

#[test]
fn policy_event_serde_roundtrip_all_optional_fields_none() {
    let event = frankenengine_engine::one_lever_policy::OneLeverPolicyEvent {
        trace_id: "tr-0".to_string(),
        decision_id: "dec-0".to_string(),
        policy_id: "pol-0".to_string(),
        component: ONE_LEVER_POLICY_COMPONENT.to_string(),
        event: "test_event".to_string(),
        outcome: "fail".to_string(),
        error_code: None,
        change_id: None,
        path: None,
        lever_category: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: frankenengine_engine::one_lever_policy::OneLeverPolicyEvent =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, event);
}

#[test]
fn negative_opportunity_score_is_denied() {
    let mut request = base_request();
    request.evidence = complete_evidence(-1_000_000);

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(
        decision.error_code.as_deref(),
        Some(ERROR_SCORE_BELOW_THRESHOLD)
    );
    assert_eq!(decision.opportunity_score_millionths, Some(-1_000_000));
}

#[test]
fn very_large_opportunity_score_is_allowed() {
    let mut request = base_request();
    request.evidence = complete_evidence(i64::MAX);

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(!decision.blocked);
    assert_eq!(decision.opportunity_score_millionths, Some(i64::MAX));
}

#[test]
fn change_id_starts_with_olp_prefix() {
    let request = base_request();
    let decision = evaluate_one_lever_policy(&request);
    let change_id = decision
        .change_id
        .as_ref()
        .expect("change_id should be set");
    assert!(
        change_id.starts_with("olp-"),
        "change_id should start with 'olp-', got: {change_id}"
    );
}

#[test]
fn change_id_differs_for_different_inputs() {
    let request_a = base_request();
    let mut request_b = base_request();
    request_b.commit_sha = "fedcba9876543210fedcba9876543210fedcba98".to_string();

    let decision_a = evaluate_one_lever_policy(&request_a);
    let decision_b = evaluate_one_lever_policy(&request_b);
    assert_ne!(
        decision_a.change_id, decision_b.change_id,
        "different inputs should produce different change_ids"
    );
}

#[test]
fn multi_lever_override_reason_is_case_insensitive_on_marker() {
    let mut request = base_request();
    request.commit_message =
        "perf: coupled runtime fix [MULTI-LEVER: uppercase reason works]".to_string();
    request.changed_paths = vec![
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
        "crates/franken-engine/src/gc_pause.rs".to_string(),
    ];

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(decision.is_multi_lever);
    assert_eq!(
        decision.override_reason.as_deref(),
        Some("uppercase reason works")
    );
}

#[test]
fn multi_lever_override_with_empty_brackets_is_denied() {
    let mut request = base_request();
    request.commit_message = "perf: coupled fix [multi-lever: ]".to_string();
    request.changed_paths = vec![
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
        "crates/franken-engine/src/gc_pause.rs".to_string(),
    ];

    let decision = evaluate_one_lever_policy(&request);
    // Empty override reason means no valid override, so multi-lever is denied
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert!(decision.is_multi_lever);
    assert!(decision.override_reason.is_none());
    assert_eq!(
        decision.error_code.as_deref(),
        Some(ERROR_MULTI_LEVER_VIOLATION)
    );
}

#[test]
fn duplicate_changed_paths_are_deduplicated_by_normalization() {
    let mut request = base_request();
    request.changed_paths = vec![
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
        "crates/franken-engine/src/baseline_interpreter.rs".to_string(),
    ];

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    assert!(!decision.is_multi_lever);
    // After dedup, only one classification entry
    assert_eq!(decision.lever_classification.len(), 1);
}

#[test]
fn lever_classification_is_sorted_by_path() {
    let mut request = base_request();
    request.changed_paths = vec![
        "docs/z_readme.md".to_string(),
        "docs/a_design.md".to_string(),
        "docs/m_notes.md".to_string(),
    ];
    request.evidence = OneLeverEvidenceRefs::default();

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "allow");
    // Verify paths in lever_classification are sorted
    let paths: Vec<&str> = decision
        .lever_classification
        .iter()
        .map(|c| c.path.as_str())
        .collect();
    let mut sorted_paths = paths.clone();
    sorted_paths.sort();
    assert_eq!(
        paths, sorted_paths,
        "lever_classification should be sorted by path"
    );
}

#[test]
fn decision_clone_produces_independent_copy() {
    let request = base_request();
    let decision = evaluate_one_lever_policy(&request);
    let cloned = decision.clone();

    // Ensure they are equal
    assert_eq!(decision, cloned);
    // Ensure they serialize identically
    let json_a = serde_json::to_string(&decision).expect("serialize");
    let json_b = serde_json::to_string(&cloned).expect("serialize clone");
    assert_eq!(json_a, json_b);
}

#[test]
fn all_evidence_missing_for_optimization_reports_all_requirements() {
    let mut request = base_request();
    request.evidence = OneLeverEvidenceRefs::default();

    let decision = evaluate_one_lever_policy(&request);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_MISSING_EVIDENCE));

    // All 9 evidence fields should be reported as missing
    let expected_missing = [
        "baseline_benchmark_run_id",
        "post_change_benchmark_run_id",
        "delta_report_ref",
        "semantic_equivalence_ref",
        "trace_replay_ref",
        "isomorphism_ledger_ref",
        "rollback_instructions_ref",
        "reprofile_after_merge_ref",
        "opportunity_score_millionths",
    ];
    for field in &expected_missing {
        assert!(
            decision.missing_requirements.contains(&field.to_string()),
            "missing_requirements should contain {field}"
        );
    }
    assert_eq!(decision.missing_requirements.len(), expected_missing.len());
}
