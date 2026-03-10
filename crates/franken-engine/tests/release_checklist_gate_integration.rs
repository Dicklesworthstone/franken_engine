#![forbid(unsafe_code)]
//! Integration tests for the `release_checklist_gate` module.
//!
//! Exercises checklist construction, validation, gate evaluation,
//! storage persistence, query, and serde round-trips from outside the
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

use frankenengine_engine::release_checklist_gate::{
    ArtifactRef, ChecklistCategory, ChecklistItem, ChecklistItemStatus, ChecklistWaiver,
    ERROR_RELEASE_BLOCKED, RELEASE_CHECKLIST_COMPONENT, RELEASE_CHECKLIST_SCHEMA_VERSION,
    RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT, ReleaseChecklist, ReleaseChecklistError,
    ReleaseChecklistGateDecision, ReleaseChecklistGateEvent, parse_release_checklist_json,
    query_release_checklists_by_tag, required_checklist_items, run_release_checklist_gate,
    validate_release_checklist,
};
use frankenengine_engine::storage_adapter::InMemoryStorageAdapter;

// ===========================================================================
// Helpers
// ===========================================================================

fn passing_artifact() -> ArtifactRef {
    ArtifactRef {
        artifact_id: "art-1".into(),
        path: "/evidence/test.json".into(),
        sha256: Some("a".repeat(64)),
    }
}

fn passing_item(item_id: &str, category: ChecklistCategory) -> ChecklistItem {
    ChecklistItem {
        item_id: item_id.into(),
        category,
        required: true,
        status: ChecklistItemStatus::Pass,
        artifact_refs: vec![passing_artifact()],
        waiver: None,
    }
}

/// Build a valid checklist with all 16 required items passing.
fn valid_checklist() -> ReleaseChecklist {
    let items: Vec<ChecklistItem> = required_checklist_items()
        .iter()
        .map(|r| passing_item(r.item_id, r.category))
        .collect();
    ReleaseChecklist {
        schema_version: RELEASE_CHECKLIST_SCHEMA_VERSION.into(),
        release_tag: "v1.0.0".into(),
        generated_at_utc: "2026-02-26T12:00:00Z".into(),
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        items,
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn constants_nonempty() {
    assert!(!RELEASE_CHECKLIST_COMPONENT.is_empty());
    assert!(!RELEASE_CHECKLIST_SCHEMA_VERSION.is_empty());
    assert!(!RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT.is_empty());
    assert!(!ERROR_RELEASE_BLOCKED.is_empty());
}

// ===========================================================================
// 2. ChecklistCategory — display, as_str, serde
// ===========================================================================

#[test]
fn checklist_category_display_and_as_str() {
    for cat in [
        ChecklistCategory::Security,
        ChecklistCategory::Performance,
        ChecklistCategory::Reproducibility,
        ChecklistCategory::Operational,
    ] {
        let display = cat.to_string();
        assert_eq!(display, cat.as_str());
        assert!(!display.is_empty());
    }
}

#[test]
fn checklist_category_serde_round_trip() {
    for cat in [
        ChecklistCategory::Security,
        ChecklistCategory::Performance,
        ChecklistCategory::Reproducibility,
        ChecklistCategory::Operational,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: ChecklistCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cat);
    }
}

// ===========================================================================
// 3. ChecklistItemStatus — display, as_str, serde
// ===========================================================================

#[test]
fn checklist_item_status_display_and_as_str() {
    for s in [
        ChecklistItemStatus::Pass,
        ChecklistItemStatus::Fail,
        ChecklistItemStatus::NotRun,
        ChecklistItemStatus::Waived,
    ] {
        let display = s.to_string();
        assert_eq!(display, s.as_str());
        assert!(!display.is_empty());
    }
}

#[test]
fn checklist_item_status_serde_round_trip() {
    for s in [
        ChecklistItemStatus::Pass,
        ChecklistItemStatus::Fail,
        ChecklistItemStatus::NotRun,
        ChecklistItemStatus::Waived,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ChecklistItemStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

// ===========================================================================
// 4. Required checklist items
// ===========================================================================

#[test]
fn required_items_has_sixteen() {
    assert_eq!(required_checklist_items().len(), 16);
}

#[test]
fn required_items_unique_ids() {
    let items = required_checklist_items();
    let mut seen = std::collections::BTreeSet::new();
    for item in items {
        assert!(
            seen.insert(item.item_id),
            "duplicate required item: {}",
            item.item_id
        );
    }
}

#[test]
fn required_items_covers_all_categories() {
    let items = required_checklist_items();
    let categories: std::collections::BTreeSet<_> = items.iter().map(|i| i.category).collect();
    assert!(categories.contains(&ChecklistCategory::Security));
    assert!(categories.contains(&ChecklistCategory::Performance));
    assert!(categories.contains(&ChecklistCategory::Reproducibility));
    assert!(categories.contains(&ChecklistCategory::Operational));
}

// ===========================================================================
// 5. Validation — valid checklist passes
// ===========================================================================

#[test]
fn validate_valid_checklist_passes() {
    let cl = valid_checklist();
    validate_release_checklist(&cl).unwrap();
}

// ===========================================================================
// 6. Validation — schema version mismatch
// ===========================================================================

#[test]
fn validate_wrong_schema_version_fails() {
    let mut cl = valid_checklist();
    cl.schema_version = "wrong-version".into();
    let err = validate_release_checklist(&cl).unwrap_err();
    assert!(matches!(err, ReleaseChecklistError::InvalidRequest { .. }));
}

// ===========================================================================
// 7. Validation — empty required fields
// ===========================================================================

#[test]
fn validate_empty_release_tag_fails() {
    let mut cl = valid_checklist();
    cl.release_tag = String::new();
    assert!(validate_release_checklist(&cl).is_err());
}

#[test]
fn validate_empty_trace_id_fails() {
    let mut cl = valid_checklist();
    cl.trace_id = String::new();
    assert!(validate_release_checklist(&cl).is_err());
}

#[test]
fn validate_empty_items_fails() {
    let mut cl = valid_checklist();
    cl.items.clear();
    assert!(validate_release_checklist(&cl).is_err());
}

// ===========================================================================
// 8. Validation — duplicate item IDs
// ===========================================================================

#[test]
fn validate_duplicate_item_ids_fails() {
    let mut cl = valid_checklist();
    let dup = cl.items[0].clone();
    cl.items.push(dup);
    assert!(validate_release_checklist(&cl).is_err());
}

// ===========================================================================
// 9. Validation — missing required item
// ===========================================================================

#[test]
fn validate_missing_required_item_blocks_gate() {
    let mut cl = valid_checklist();
    cl.items
        .retain(|i| i.item_id != "security.conformance_suite");
    // Missing required item is a blocker, not a validation error
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.blocked);
    assert!(!decision.blockers.is_empty());
}

// ===========================================================================
// 10. Validation — failed required item
// ===========================================================================

#[test]
fn validate_failed_required_item_blocks_gate() {
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        item.status = ChecklistItemStatus::Fail;
    }
    // Failed required item is a blocker, not a validation error
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("conformance_suite"))
    );
}

// ===========================================================================
// 11. Validation — waived item needs waiver
// ===========================================================================

#[test]
fn validate_waived_item_without_waiver_fails() {
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        item.status = ChecklistItemStatus::Waived;
        item.waiver = None;
    }
    assert!(validate_release_checklist(&cl).is_err());
}

#[test]
fn validate_waived_item_with_waiver_passes() {
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        item.status = ChecklistItemStatus::Waived;
        item.waiver = Some(ChecklistWaiver {
            reason: "known".into(),
            approver: "admin".into(),
            exception_artifact_link: "/waivers/w1.json".into(),
        });
    }
    validate_release_checklist(&cl).unwrap();
}

// ===========================================================================
// 12. Validation — artifact refs required
// ===========================================================================

#[test]
fn validate_item_without_artifact_blocks_gate() {
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        item.artifact_refs.clear();
    }
    // Missing artifacts is a blocker, not a validation error
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.blocked);
    assert!(decision.blockers.iter().any(|b| b.contains("artifact")));
}

// ===========================================================================
// 13. JSON parsing
// ===========================================================================

#[test]
fn parse_valid_json() {
    let cl = valid_checklist();
    let json = serde_json::to_string(&cl).unwrap();
    let parsed = parse_release_checklist_json(&json).unwrap();
    assert_eq!(parsed.release_tag, cl.release_tag);
}

#[test]
fn parse_invalid_json_fails() {
    let err = parse_release_checklist_json("not json").unwrap_err();
    assert!(matches!(
        err,
        ReleaseChecklistError::SerializationFailure { .. }
    ));
}

// ===========================================================================
// 14. Gate execution — passing checklist
// ===========================================================================

#[test]
fn gate_passing_checklist_allows_release() {
    let cl = valid_checklist();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(
        decision.allows_release(),
        "gate should pass: blockers={:?}",
        decision.blockers
    );
    assert!(!decision.blocked);
    assert!(decision.blockers.is_empty());
    assert!(decision.checklist_id.is_some());
}

// ===========================================================================
// 15. Gate execution — failing checklist
// ===========================================================================

#[test]
fn gate_failing_checklist_blocks_release() {
    let mut cl = valid_checklist();
    // Fail a required item
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        item.status = ChecklistItemStatus::Fail;
    }
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(!decision.allows_release());
    assert!(decision.blocked);
    assert!(!decision.blockers.is_empty());
}

// ===========================================================================
// 16. Gate execution — events emitted
// ===========================================================================

#[test]
fn gate_emits_events() {
    let cl = valid_checklist();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(
        !decision.events.is_empty(),
        "gate should emit at least one event"
    );
    // Should have start and complete events
    let event_names: Vec<&str> = decision.events.iter().map(|e| e.event.as_str()).collect();
    assert!(
        event_names.iter().any(|e| e.contains("started")),
        "should have started event: {event_names:?}"
    );
    assert!(
        event_names.iter().any(|e| e.contains("completed")),
        "should have completed event: {event_names:?}"
    );
}

// ===========================================================================
// 17. Gate execution — storage integration
// ===========================================================================

#[test]
fn gate_stores_checklist() {
    let cl = valid_checklist();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.store_key.is_some());
    assert_eq!(
        decision.storage_integration_point,
        RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT
    );
}

// ===========================================================================
// 18. Query — by release tag
// ===========================================================================

#[test]
fn query_by_tag_returns_stored_checklists() {
    let cl = valid_checklist();
    let mut adapter = InMemoryStorageAdapter::new();
    run_release_checklist_gate(&mut adapter, &cl);

    let results =
        query_release_checklists_by_tag(&mut adapter, "v1.0.0", "t-q", "d-q", "p-q").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].release_tag, "v1.0.0");
}

#[test]
fn query_nonexistent_tag_returns_empty() {
    let mut adapter = InMemoryStorageAdapter::new();
    let results =
        query_release_checklists_by_tag(&mut adapter, "v99.99.99", "t-q", "d-q", "p-q").unwrap();
    assert!(results.is_empty());
}

#[test]
fn query_empty_tag_fails() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = query_release_checklists_by_tag(&mut adapter, "", "t-q", "d-q", "p-q").unwrap_err();
    assert!(matches!(err, ReleaseChecklistError::InvalidRequest { .. }));
}

// ===========================================================================
// 19. ReleaseChecklistError — stable_code, requires_rollback
// ===========================================================================

#[test]
fn error_stable_codes_nonempty() {
    let errs: Vec<ReleaseChecklistError> = vec![
        ReleaseChecklistError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        },
        ReleaseChecklistError::InvalidTimestamp {
            value: "bad".into(),
        },
        ReleaseChecklistError::InvalidItem {
            item_id: "i".into(),
            detail: "d".into(),
        },
        ReleaseChecklistError::SerializationFailure { detail: "d".into() },
    ];
    for e in &errs {
        let code = e.stable_code();
        assert!(
            code.starts_with("FE-RCHK"),
            "expected FE-RCHK prefix, got: {code}"
        );
    }
}

#[test]
fn error_requires_rollback_false_for_validation() {
    let e = ReleaseChecklistError::InvalidRequest {
        field: "f".into(),
        detail: "d".into(),
    };
    assert!(!e.requires_rollback());
}

// ===========================================================================
// 20. Serde round-trips
// ===========================================================================

#[test]
fn artifact_ref_serde_round_trip() {
    let ar = passing_artifact();
    let json = serde_json::to_string(&ar).unwrap();
    let back: ArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ar);
}

#[test]
fn checklist_waiver_serde_round_trip() {
    let w = ChecklistWaiver {
        reason: "known issue".into(),
        approver: "admin".into(),
        exception_artifact_link: "/waivers/w1.json".into(),
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: ChecklistWaiver = serde_json::from_str(&json).unwrap();
    assert_eq!(back, w);
}

#[test]
fn checklist_item_serde_round_trip() {
    let item = passing_item("test.item", ChecklistCategory::Security);
    let json = serde_json::to_string(&item).unwrap();
    let back: ChecklistItem = serde_json::from_str(&json).unwrap();
    assert_eq!(back, item);
}

#[test]
fn release_checklist_serde_round_trip() {
    let cl = valid_checklist();
    let json = serde_json::to_string(&cl).unwrap();
    let back: ReleaseChecklist = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cl);
}

#[test]
fn gate_decision_serde_round_trip() {
    let cl = valid_checklist();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    let json = serde_json::to_string(&decision).unwrap();
    let back: ReleaseChecklistGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, decision);
}

#[test]
fn gate_event_serde_round_trip() {
    let event = ReleaseChecklistGateEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: RELEASE_CHECKLIST_COMPONENT.into(),
        event: "test_event".into(),
        outcome: "ok".into(),
        error_code: None,
        checklist_id: Some("rchk_abc123".into()),
        item_id: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ReleaseChecklistGateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

// ===========================================================================
// 21. Checklist ID — deterministic
// ===========================================================================

#[test]
fn checklist_id_deterministic() {
    let cl = valid_checklist();
    let mut a1 = InMemoryStorageAdapter::new();
    let mut a2 = InMemoryStorageAdapter::new();
    let d1 = run_release_checklist_gate(&mut a1, &cl);
    let d2 = run_release_checklist_gate(&mut a2, &cl);
    assert_eq!(d1.checklist_id, d2.checklist_id);
}

#[test]
fn checklist_id_changes_with_content() {
    let cl1 = valid_checklist();
    let mut cl2 = valid_checklist();
    cl2.release_tag = "v2.0.0".into();
    let mut a1 = InMemoryStorageAdapter::new();
    let mut a2 = InMemoryStorageAdapter::new();
    let d1 = run_release_checklist_gate(&mut a1, &cl1);
    let d2 = run_release_checklist_gate(&mut a2, &cl2);
    assert_ne!(d1.checklist_id, d2.checklist_id);
}

// ===========================================================================
// 22. Gate decision — allows_release method
// ===========================================================================

#[test]
fn gate_decision_allows_release_method() {
    let cl = valid_checklist();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.allows_release());
    assert_eq!(decision.outcome, "allow");
}

// ===========================================================================
// 23. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_pass_store_query() {
    let mut adapter = InMemoryStorageAdapter::new();

    // 1. Run passing gate
    let cl = valid_checklist();
    let d = run_release_checklist_gate(&mut adapter, &cl);
    assert!(d.allows_release());

    // 2. Query back
    let results =
        query_release_checklists_by_tag(&mut adapter, "v1.0.0", "t-q", "d-q", "p-q").unwrap();
    assert_eq!(results.len(), 1);

    // 3. Run a second checklist with different tag
    let mut cl2 = valid_checklist();
    cl2.release_tag = "v2.0.0".into();
    cl2.trace_id = "t-2".into();
    let d2 = run_release_checklist_gate(&mut adapter, &cl2);
    assert!(d2.allows_release());

    // 4. Each tag has its own results
    let r1 = query_release_checklists_by_tag(&mut adapter, "v1.0.0", "t-q", "d-q", "p-q").unwrap();
    let r2 = query_release_checklists_by_tag(&mut adapter, "v2.0.0", "t-q", "d-q", "p-q").unwrap();
    assert_eq!(r1.len(), 1);
    assert_eq!(r2.len(), 1);

    // 5. IDs differ
    assert_ne!(d.checklist_id, d2.checklist_id);
}

#[test]
fn full_lifecycle_fail_with_waiver_passes() {
    let mut adapter = InMemoryStorageAdapter::new();

    // Build checklist with one waived security item
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        item.status = ChecklistItemStatus::Waived;
        item.waiver = Some(ChecklistWaiver {
            reason: "known regression, ticket JIRA-123".into(),
            approver: "security-lead@example.com".into(),
            exception_artifact_link: "/waivers/JIRA-123.json".into(),
        });
    }

    let d = run_release_checklist_gate(&mut adapter, &cl);
    assert!(
        d.allows_release(),
        "waived item should still allow release: blockers={:?}",
        d.blockers
    );
}
