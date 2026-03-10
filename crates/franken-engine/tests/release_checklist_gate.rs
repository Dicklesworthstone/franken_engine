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

use frankenengine_engine::release_checklist_gate::{
    ArtifactRef, ChecklistCategory, ChecklistItem, ChecklistItemStatus, ChecklistWaiver,
    ERROR_RELEASE_BLOCKED, RELEASE_CHECKLIST_COMPONENT, RELEASE_CHECKLIST_SCHEMA_VERSION,
    RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT, ReleaseChecklist, ReleaseChecklistError,
    ReleaseChecklistGateDecision, parse_release_checklist_json, query_release_checklists_by_tag,
    required_checklist_items, run_release_checklist_gate, validate_release_checklist,
};
use frankenengine_engine::storage_adapter::InMemoryStorageAdapter;

fn artifact_ref(item_id: &str) -> ArtifactRef {
    ArtifactRef {
        artifact_id: format!("artifact-{item_id}"),
        path: format!("artifacts/releases/{item_id}.json"),
        sha256: Some("deadbeef".to_string()),
    }
}

fn baseline_checklist(release_tag: &str) -> ReleaseChecklist {
    let items = required_checklist_items()
        .iter()
        .map(|required| ChecklistItem {
            item_id: required.item_id.to_string(),
            category: required.category,
            required: true,
            status: ChecklistItemStatus::Pass,
            artifact_refs: vec![artifact_ref(required.item_id)],
            waiver: None,
        })
        .collect();

    ReleaseChecklist {
        schema_version: RELEASE_CHECKLIST_SCHEMA_VERSION.to_string(),
        release_tag: release_tag.to_string(),
        generated_at_utc: "2026-02-22T06:31:00+00:00".to_string(),
        trace_id: format!("trace-release-checklist-{release_tag}"),
        decision_id: format!("decision-release-checklist-{release_tag}"),
        policy_id: "policy-release-checklist-v1".to_string(),
        items,
    }
}

fn valid_waiver() -> ChecklistWaiver {
    ChecklistWaiver {
        reason: "Deferred to next release".to_string(),
        approver: "ops-reviewer".to_string(),
        exception_artifact_link: "artifact://waiver/exception-001".to_string(),
    }
}

fn assert_gate_allows(decision: &ReleaseChecklistGateDecision) {
    assert!(decision.allows_release());
    assert_eq!(decision.outcome, "allow");
    assert!(!decision.blocked);
    assert!(decision.blockers.is_empty());
    assert_eq!(decision.error_code, None);
    assert!(!decision.rollback_required);
    assert!(decision.checklist_id.is_some());
    assert!(decision.store_key.is_some());
}

fn assert_gate_denies(decision: &ReleaseChecklistGateDecision) {
    assert!(!decision.allows_release());
    assert_eq!(decision.outcome, "deny");
    assert!(decision.blocked);
    assert!(!decision.blockers.is_empty());
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_RELEASE_BLOCKED));
}

fn assert_gate_fails(decision: &ReleaseChecklistGateDecision) {
    assert!(!decision.allows_release());
    assert_eq!(decision.outcome, "fail");
    assert!(decision.blocked);
    assert!(decision.store_key.is_none());
    assert_eq!(decision.checklist_id, None);
}

// ── Happy-path tests ──────────────────────────────────────────────────

#[test]
fn gate_allows_release_when_all_required_items_pass_and_store_with_release_tag() {
    let mut adapter = InMemoryStorageAdapter::default();
    let checklist = baseline_checklist("v1.2.3");

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_allows(&decision);
    assert_eq!(
        decision.storage_integration_point,
        RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT
    );
    assert!(
        decision
            .store_key
            .as_ref()
            .is_some_and(|value| value.contains("v1.2.3"))
    );

    for event in &decision.events {
        assert_eq!(event.component, RELEASE_CHECKLIST_COMPONENT);
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert!(!event.policy_id.is_empty());
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }

    let stored = query_release_checklists_by_tag(
        &mut adapter,
        "v1.2.3",
        &checklist.trace_id,
        &checklist.decision_id,
        &checklist.policy_id,
    )
    .expect("query should succeed");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].release_tag, "v1.2.3");
    validate_release_checklist(&stored[0]).expect("stored checklist must validate");
}

#[test]
fn gate_allows_release_with_waived_item_and_valid_waiver() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v2.0.0-waived");
    let item = checklist
        .items
        .iter_mut()
        .find(|i| i.item_id == "operational.safe_mode_test")
        .unwrap();
    item.status = ChecklistItemStatus::Waived;
    item.waiver = Some(valid_waiver());

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_allows(&decision);
}

#[test]
fn gate_allows_release_with_extra_optional_items() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v2.1.0-extras");
    checklist.items.push(ChecklistItem {
        item_id: "custom.experimental_feature".to_string(),
        category: ChecklistCategory::Operational,
        required: false,
        status: ChecklistItemStatus::Pass,
        artifact_refs: vec![artifact_ref("custom.experimental_feature")],
        waiver: None,
    });

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_allows(&decision);
}

#[test]
fn gate_allows_release_when_optional_item_fails() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v2.2.0-opt-fail");
    checklist.items.push(ChecklistItem {
        item_id: "custom.nice_to_have".to_string(),
        category: ChecklistCategory::Performance,
        required: false,
        status: ChecklistItemStatus::Fail,
        artifact_refs: vec![],
        waiver: None,
    });

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_allows(&decision);
}

// ── Deny tests ────────────────────────────────────────────────────────

#[test]
fn gate_denies_release_when_required_items_missing_or_failed() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v1.2.4");
    checklist
        .items
        .retain(|item| item.item_id != "performance.gc_pause_budget");
    let failing = checklist
        .items
        .iter_mut()
        .find(|item| item.item_id == "security.test262_es2020_gate")
        .expect("required item present");
    failing.status = ChecklistItemStatus::Fail;

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_denies(&decision);
    assert!(decision.store_key.is_some());

    let blockers = decision.blockers.join(" | ");
    assert!(blockers.contains("missing required checklist item `performance.gc_pause_budget`"));
    assert!(blockers.contains("required item `security.test262_es2020_gate` is `fail`"));
}

#[test]
fn gate_denies_when_required_item_is_not_run() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v3.0.0-notrun");
    let item = checklist
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
        .unwrap();
    item.status = ChecklistItemStatus::NotRun;

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_denies(&decision);
    assert!(decision.blockers.iter().any(|b| b.contains("not_run")));
}

#[test]
fn gate_denies_when_pass_item_has_no_artifacts() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v3.1.0-noartifacts");
    let item = checklist
        .items
        .iter_mut()
        .find(|i| i.item_id == "performance.benchmark_suite")
        .unwrap();
    item.artifact_refs.clear();

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_denies(&decision);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("no artifact_refs"))
    );
}

#[test]
fn gate_denies_when_category_mismatches_required_spec() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v3.2.0-catmismatch");
    let item = checklist
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
        .unwrap();
    item.category = ChecklistCategory::Performance;

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_denies(&decision);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("category") && b.contains("performance"))
    );
}

#[test]
fn gate_denies_when_multiple_required_items_fail() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v3.3.0-multifail");
    for item in &mut checklist.items {
        if item.item_id.starts_with("security.") {
            item.status = ChecklistItemStatus::Fail;
        }
    }

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_denies(&decision);
    assert!(decision.blockers.len() >= 6);
}

#[test]
fn gate_denies_when_all_required_items_missing() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v3.4.0-empty");
    checklist.items.clear();
    checklist.items.push(ChecklistItem {
        item_id: "custom.only".to_string(),
        category: ChecklistCategory::Operational,
        required: false,
        status: ChecklistItemStatus::Pass,
        artifact_refs: vec![],
        waiver: None,
    });

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_denies(&decision);
    assert_eq!(decision.blockers.len(), required_checklist_items().len());
}

// ── Fail tests (validation errors) ───────────────────────────────────

#[test]
fn gate_fails_when_waived_item_lacks_complete_waiver_metadata() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v1.2.5");
    let waived = checklist
        .items
        .iter_mut()
        .find(|item| item.item_id == "operational.safe_mode_test")
        .expect("required item present");
    waived.status = ChecklistItemStatus::Waived;
    waived.waiver = Some(ChecklistWaiver {
        reason: "".to_string(),
        approver: "ops-reviewer".to_string(),
        exception_artifact_link: "artifact://waiver/safe-mode".to_string(),
    });

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_fails(&decision);
    assert_eq!(decision.error_code.as_deref(), Some("FE-RCHK-1003"));
}

#[test]
fn gate_fails_when_waiver_has_empty_approver() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v4.0.0-noapprover");
    let item = checklist
        .items
        .iter_mut()
        .find(|i| i.item_id == "operational.diagnostics_cli_test")
        .unwrap();
    item.status = ChecklistItemStatus::Waived;
    item.waiver = Some(ChecklistWaiver {
        reason: "Deferred".to_string(),
        approver: "".to_string(),
        exception_artifact_link: "artifact://waiver/diag".to_string(),
    });

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_fails(&decision);
    assert_eq!(decision.error_code.as_deref(), Some("FE-RCHK-1003"));
}

#[test]
fn gate_fails_when_waiver_has_empty_exception_link() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v4.1.0-nolink");
    let item = checklist
        .items
        .iter_mut()
        .find(|i| i.item_id == "operational.evidence_export_test")
        .unwrap();
    item.status = ChecklistItemStatus::Waived;
    item.waiver = Some(ChecklistWaiver {
        reason: "Deferred".to_string(),
        approver: "reviewer".to_string(),
        exception_artifact_link: "   ".to_string(),
    });

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_fails(&decision);
}

#[test]
fn gate_fails_when_duplicate_item_ids_present() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v4.2.0-dupes");
    let first_item = checklist.items[0].clone();
    checklist.items.push(first_item);

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_fails(&decision);
    assert_eq!(decision.error_code.as_deref(), Some("FE-RCHK-1003"));
    assert!(decision.blockers.iter().any(|b| b.contains("duplicate")));
}

#[test]
fn gate_fails_when_schema_version_wrong() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v4.3.0-badschema");
    checklist.schema_version = "wrong-version".to_string();

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_fails(&decision);
    assert_eq!(decision.error_code.as_deref(), Some("FE-RCHK-1001"));
}

#[test]
fn gate_fails_when_release_tag_empty() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("placeholder");
    checklist.release_tag = "   ".to_string();

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_fails(&decision);
    assert_eq!(decision.error_code.as_deref(), Some("FE-RCHK-1001"));
}

#[test]
fn gate_fails_when_trace_id_empty() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v4.4.0-notrace");
    checklist.trace_id = "".to_string();

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_fails(&decision);
}

#[test]
fn gate_fails_when_decision_id_empty() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v4.5.0-nodecision");
    checklist.decision_id = "".to_string();

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_fails(&decision);
}

#[test]
fn gate_fails_when_policy_id_empty() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v4.6.0-nopolicy");
    checklist.policy_id = "".to_string();

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_fails(&decision);
}

#[test]
fn gate_fails_when_items_list_empty() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v4.7.0-noitems");
    checklist.items.clear();

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    // Either fail (validation) or deny (missing required items)
    assert!(!decision.allows_release());
    assert!(decision.blocked);
}

// ── Determinism tests ─────────────────────────────────────────────────

#[test]
fn gate_checklist_id_is_deterministic_for_identical_input() {
    let checklist = baseline_checklist("v1.2.6");

    let mut adapter_a = InMemoryStorageAdapter::default();
    let mut adapter_b = InMemoryStorageAdapter::default();
    let decision_a = run_release_checklist_gate(&mut adapter_a, &checklist);
    let decision_b = run_release_checklist_gate(&mut adapter_b, &checklist);

    assert_eq!(decision_a.checklist_id, decision_b.checklist_id);
    assert_eq!(decision_a.store_key, decision_b.store_key);
    assert_eq!(decision_a.outcome, "allow");
    assert_eq!(decision_b.outcome, "allow");
}

#[test]
fn checklist_id_differs_for_different_release_tags() {
    let checklist_a = baseline_checklist("v5.0.0");
    let checklist_b = baseline_checklist("v5.0.1");

    let mut adapter_a = InMemoryStorageAdapter::default();
    let mut adapter_b = InMemoryStorageAdapter::default();
    let decision_a = run_release_checklist_gate(&mut adapter_a, &checklist_a);
    let decision_b = run_release_checklist_gate(&mut adapter_b, &checklist_b);

    assert_ne!(decision_a.checklist_id, decision_b.checklist_id);
    assert_ne!(decision_a.store_key, decision_b.store_key);
}

#[test]
fn checklist_id_differs_when_item_status_changes() {
    let checklist_a = baseline_checklist("v5.1.0");
    let mut checklist_b = baseline_checklist("v5.1.0");
    checklist_b
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
        .unwrap()
        .status = ChecklistItemStatus::Fail;

    let mut adapter_a = InMemoryStorageAdapter::default();
    let mut adapter_b = InMemoryStorageAdapter::default();
    let decision_a = run_release_checklist_gate(&mut adapter_a, &checklist_a);
    let decision_b = run_release_checklist_gate(&mut adapter_b, &checklist_b);

    assert_ne!(decision_a.checklist_id, decision_b.checklist_id);
}

// ── Event sequence tests ──────────────────────────────────────────────

#[test]
fn gate_emits_correct_event_sequence_on_allow() {
    let mut adapter = InMemoryStorageAdapter::default();
    let checklist = baseline_checklist("v6.0.0-events");

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_allows(&decision);

    let event_names: Vec<&str> = decision.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"release_checklist_gate_started"));
    assert!(event_names.contains(&"release_checklist_evaluated"));
    assert!(event_names.contains(&"release_checklist_stored"));
    assert!(event_names.contains(&"release_checklist_gate_completed"));

    let started = &decision.events[0];
    assert_eq!(started.event, "release_checklist_gate_started");
    assert_eq!(started.outcome, "pass");

    let completed = decision.events.last().unwrap();
    assert_eq!(completed.event, "release_checklist_gate_completed");
    assert_eq!(completed.outcome, "allow");
    assert!(completed.checklist_id.is_some());
}

#[test]
fn gate_emits_correct_event_sequence_on_deny() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v6.1.0-deny-events");
    checklist
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
        .unwrap()
        .status = ChecklistItemStatus::Fail;

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_denies(&decision);

    let completed = decision.events.last().unwrap();
    assert_eq!(completed.event, "release_checklist_gate_completed");
    assert_eq!(completed.outcome, "deny");
    assert_eq!(completed.error_code.as_deref(), Some(ERROR_RELEASE_BLOCKED));
}

#[test]
fn gate_emits_correct_event_sequence_on_validation_fail() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v6.2.0-fail-events");
    checklist.schema_version = "wrong".to_string();

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_fails(&decision);

    let completed = decision.events.last().unwrap();
    assert_eq!(completed.event, "release_checklist_gate_completed");
    assert_eq!(completed.outcome, "fail");
    assert!(completed.error_code.is_some());
}

// ── Query tests ───────────────────────────────────────────────────────

#[test]
fn query_rejects_empty_release_tag() {
    let mut adapter = InMemoryStorageAdapter::default();
    let err = query_release_checklists_by_tag(
        &mut adapter,
        "   ",
        "trace-release-checklist-query",
        "decision-release-checklist-query",
        "policy-release-checklist-v1",
    )
    .expect_err("empty release tag should fail");

    match err {
        ReleaseChecklistError::InvalidRequest { field, .. } => {
            assert_eq!(field, "release_tag");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn query_rejects_empty_trace_id() {
    let mut adapter = InMemoryStorageAdapter::default();
    let err = query_release_checklists_by_tag(
        &mut adapter,
        "v7.0.0",
        "",
        "decision-query",
        "policy-query",
    )
    .expect_err("empty trace_id should fail");

    match err {
        ReleaseChecklistError::InvalidRequest { field, .. } => {
            assert_eq!(field, "event_context");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn query_returns_empty_for_nonexistent_tag() {
    let mut adapter = InMemoryStorageAdapter::default();
    let results = query_release_checklists_by_tag(
        &mut adapter,
        "v999.0.0",
        "trace-query",
        "decision-query",
        "policy-query",
    )
    .expect("query should succeed");
    assert!(results.is_empty());
}

#[test]
fn query_returns_multiple_checklists_for_same_tag() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist_a = baseline_checklist("v7.1.0");
    checklist_a.generated_at_utc = "2026-01-01T00:00:00+00:00".to_string();
    checklist_a.trace_id = "trace-a".to_string();

    let mut checklist_b = baseline_checklist("v7.1.0");
    checklist_b.generated_at_utc = "2026-01-02T00:00:00+00:00".to_string();
    checklist_b.trace_id = "trace-b".to_string();

    run_release_checklist_gate(&mut adapter, &checklist_a);
    run_release_checklist_gate(&mut adapter, &checklist_b);

    let results = query_release_checklists_by_tag(
        &mut adapter,
        "v7.1.0",
        "trace-query",
        "decision-query",
        "policy-query",
    )
    .expect("query should succeed");
    assert_eq!(results.len(), 2);
    assert!(results[0].generated_at_utc <= results[1].generated_at_utc);
}

// ── Validation function tests ─────────────────────────────────────────

#[test]
fn validate_accepts_correct_checklist() {
    let checklist = baseline_checklist("v8.0.0-valid");
    validate_release_checklist(&checklist).expect("valid checklist should pass");
}

#[test]
fn validate_rejects_wrong_schema_version() {
    let mut checklist = baseline_checklist("v8.1.0");
    checklist.schema_version = "wrong".to_string();
    let err = validate_release_checklist(&checklist).unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1001");
    assert!(!err.requires_rollback());
}

#[test]
fn validate_rejects_empty_release_tag() {
    let mut checklist = baseline_checklist("v8.2.0");
    checklist.release_tag = "".to_string();
    let err = validate_release_checklist(&checklist).unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1001");
}

#[test]
fn validate_rejects_duplicate_item_ids() {
    let mut checklist = baseline_checklist("v8.3.0");
    let first = checklist.items[0].clone();
    checklist.items.push(first);
    let err = validate_release_checklist(&checklist).unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1003");
}

// ── Parse function tests ──────────────────────────────────────────────

#[test]
fn parse_valid_json_succeeds() {
    let checklist = baseline_checklist("v9.0.0-parse");
    let json = serde_json::to_string_pretty(&checklist).unwrap();
    let parsed = parse_release_checklist_json(&json).expect("valid json should parse");
    assert_eq!(parsed.release_tag, "v9.0.0-parse");
    assert_eq!(parsed.items.len(), checklist.items.len());
}

#[test]
fn parse_invalid_json_returns_serialization_error() {
    let err = parse_release_checklist_json("not json").unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1004");
    assert!(!err.requires_rollback());
}

#[test]
fn parse_empty_object_fails() {
    let err = parse_release_checklist_json("{}").unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1004");
}

// ── Serde roundtrip tests ─────────────────────────────────────────────

#[test]
fn checklist_serde_roundtrip_preserves_all_fields() {
    let checklist = baseline_checklist("v10.0.0-serde");
    let json = serde_json::to_string(&checklist).unwrap();
    let deserialized: ReleaseChecklist = serde_json::from_str(&json).unwrap();
    assert_eq!(checklist, deserialized);
}

#[test]
fn decision_serde_roundtrip_preserves_all_fields() {
    let mut adapter = InMemoryStorageAdapter::default();
    let checklist = baseline_checklist("v10.1.0-decision-serde");
    let decision = run_release_checklist_gate(&mut adapter, &checklist);

    let json = serde_json::to_string(&decision).unwrap();
    let deserialized: ReleaseChecklistGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision.outcome, deserialized.outcome);
    assert_eq!(decision.checklist_id, deserialized.checklist_id);
    assert_eq!(decision.release_tag, deserialized.release_tag);
    assert_eq!(decision.events.len(), deserialized.events.len());
}

#[test]
fn artifact_ref_serde_roundtrip() {
    let artifact = ArtifactRef {
        artifact_id: "art-001".to_string(),
        path: "artifacts/test.json".to_string(),
        sha256: Some("abc123".to_string()),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let deserialized: ArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, deserialized);
}

#[test]
fn artifact_ref_without_sha256_roundtrips() {
    let artifact = ArtifactRef {
        artifact_id: "art-002".to_string(),
        path: "artifacts/nosha.json".to_string(),
        sha256: None,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let deserialized: ArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, deserialized);
}

#[test]
fn waiver_serde_roundtrip() {
    let waiver = valid_waiver();
    let json = serde_json::to_string(&waiver).unwrap();
    let deserialized: ChecklistWaiver = serde_json::from_str(&json).unwrap();
    assert_eq!(waiver, deserialized);
}

// ── Category and status tests ─────────────────────────────────────────

#[test]
fn category_as_str_matches_serde_names() {
    assert_eq!(ChecklistCategory::Security.as_str(), "security");
    assert_eq!(ChecklistCategory::Performance.as_str(), "performance");
    assert_eq!(
        ChecklistCategory::Reproducibility.as_str(),
        "reproducibility"
    );
    assert_eq!(ChecklistCategory::Operational.as_str(), "operational");
}

#[test]
fn category_display_matches_as_str() {
    assert_eq!(format!("{}", ChecklistCategory::Security), "security");
    assert_eq!(format!("{}", ChecklistCategory::Performance), "performance");
}

#[test]
fn status_as_str_values() {
    assert_eq!(ChecklistItemStatus::Pass.as_str(), "pass");
    assert_eq!(ChecklistItemStatus::Fail.as_str(), "fail");
    assert_eq!(ChecklistItemStatus::NotRun.as_str(), "not_run");
    assert_eq!(ChecklistItemStatus::Waived.as_str(), "waived");
}

#[test]
fn status_display_matches_as_str() {
    assert_eq!(format!("{}", ChecklistItemStatus::Pass), "pass");
    assert_eq!(format!("{}", ChecklistItemStatus::Fail), "fail");
}

// ── Required items tests ──────────────────────────────────────────────

#[test]
fn required_items_has_sixteen_entries() {
    assert_eq!(required_checklist_items().len(), 16);
}

#[test]
fn required_items_covers_all_categories() {
    let categories: std::collections::BTreeSet<_> = required_checklist_items()
        .iter()
        .map(|i| i.category)
        .collect();
    assert!(categories.contains(&ChecklistCategory::Security));
    assert!(categories.contains(&ChecklistCategory::Performance));
    assert!(categories.contains(&ChecklistCategory::Reproducibility));
    assert!(categories.contains(&ChecklistCategory::Operational));
}

#[test]
fn required_items_have_unique_ids() {
    let ids: std::collections::BTreeSet<_> = required_checklist_items()
        .iter()
        .map(|i| i.item_id)
        .collect();
    assert_eq!(ids.len(), required_checklist_items().len());
}

#[test]
fn required_items_id_prefix_matches_category() {
    for item in required_checklist_items() {
        let prefix = item.item_id.split('.').next().unwrap();
        assert_eq!(prefix, item.category.as_str());
    }
}

// ── Error type tests ──────────────────────────────────────────────────

#[test]
fn error_stable_codes_are_distinct() {
    let errors: Vec<ReleaseChecklistError> = vec![
        ReleaseChecklistError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        },
        ReleaseChecklistError::InvalidTimestamp { value: "v".into() },
        ReleaseChecklistError::InvalidItem {
            item_id: "i".into(),
            detail: "d".into(),
        },
        ReleaseChecklistError::SerializationFailure { detail: "d".into() },
    ];
    let codes: std::collections::BTreeSet<_> = errors.iter().map(|e| e.stable_code()).collect();
    assert_eq!(codes.len(), errors.len());
}

#[test]
fn only_storage_failure_requires_rollback() {
    let non_storage_errors = vec![
        ReleaseChecklistError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        },
        ReleaseChecklistError::InvalidTimestamp { value: "v".into() },
        ReleaseChecklistError::InvalidItem {
            item_id: "i".into(),
            detail: "d".into(),
        },
        ReleaseChecklistError::SerializationFailure { detail: "d".into() },
    ];
    for err in &non_storage_errors {
        assert!(
            !err.requires_rollback(),
            "{:?} should not require rollback",
            err
        );
    }
}

#[test]
fn error_display_contains_context() {
    let err = ReleaseChecklistError::InvalidRequest {
        field: "release_tag".to_string(),
        detail: "must not be empty".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("release_tag"));
    assert!(msg.contains("must not be empty"));
}

// ── Storage integration tests ─────────────────────────────────────────

#[test]
fn gate_stores_and_retrieves_denied_checklists() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut checklist = baseline_checklist("v11.0.0-denied-store");
    checklist
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
        .unwrap()
        .status = ChecklistItemStatus::Fail;

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_gate_denies(&decision);
    assert!(decision.store_key.is_some());

    let results = query_release_checklists_by_tag(
        &mut adapter,
        "v11.0.0-denied-store",
        "trace-q",
        "decision-q",
        "policy-q",
    )
    .expect("query should succeed");
    assert_eq!(results.len(), 1);
}

#[test]
fn store_key_contains_release_tag_and_checklist_id() {
    let mut adapter = InMemoryStorageAdapter::default();
    let checklist = baseline_checklist("v11.1.0-storekey");

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    let store_key = decision.store_key.as_ref().unwrap();
    let checklist_id = decision.checklist_id.as_ref().unwrap();

    assert!(store_key.contains("v11.1.0-storekey"));
    assert!(store_key.contains(checklist_id));
    assert!(store_key.starts_with("release_checklist/"));
}

#[test]
fn storage_integration_point_is_frankensqlite() {
    let mut adapter = InMemoryStorageAdapter::default();
    let checklist = baseline_checklist("v11.2.0-integration");

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert_eq!(
        decision.storage_integration_point,
        RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT
    );
}

#[test]
fn checklist_id_starts_with_rchk_prefix() {
    let mut adapter = InMemoryStorageAdapter::default();
    let checklist = baseline_checklist("v11.3.0-prefix");

    let decision = run_release_checklist_gate(&mut adapter, &checklist);
    assert!(decision.checklist_id.as_ref().unwrap().starts_with("rchk_"));
}
