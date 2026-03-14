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

// ===========================================================================
// 24. ChecklistCategory — Ord/PartialOrd
// ===========================================================================

#[test]
fn test_checklist_category_ordering() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(ChecklistCategory::Operational);
    set.insert(ChecklistCategory::Security);
    set.insert(ChecklistCategory::Performance);
    set.insert(ChecklistCategory::Reproducibility);
    assert_eq!(set.len(), 4);
    // BTreeSet iteration is sorted; verify all four are distinct
    let v: Vec<_> = set.into_iter().collect();
    assert_eq!(v.len(), 4);
}

// ===========================================================================
// 25. ChecklistItemStatus — Ord/PartialOrd
// ===========================================================================

#[test]
fn test_checklist_item_status_ordering() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(ChecklistItemStatus::Pass);
    set.insert(ChecklistItemStatus::Fail);
    set.insert(ChecklistItemStatus::NotRun);
    set.insert(ChecklistItemStatus::Waived);
    assert_eq!(set.len(), 4);
}

// ===========================================================================
// 26. Debug trait on all public structs
// ===========================================================================

#[test]
fn test_artifact_ref_debug() {
    let ar = passing_artifact();
    let s = format!("{ar:?}");
    assert!(s.contains("art-1"));
}

#[test]
fn test_checklist_waiver_debug() {
    let w = ChecklistWaiver {
        reason: "test reason".into(),
        approver: "approver-a".into(),
        exception_artifact_link: "/waivers/w.json".into(),
    };
    let s = format!("{w:?}");
    assert!(s.contains("test reason"));
}

#[test]
fn test_checklist_item_debug() {
    let item = passing_item("security.conformance_suite", ChecklistCategory::Security);
    let s = format!("{item:?}");
    assert!(s.contains("conformance_suite"));
}

#[test]
fn test_release_checklist_debug() {
    let cl = valid_checklist();
    let s = format!("{cl:?}");
    assert!(s.contains("v1.0.0"));
}

#[test]
fn test_gate_decision_debug() {
    let cl = valid_checklist();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    let s = format!("{decision:?}");
    assert!(s.contains("allow"));
}

#[test]
fn test_gate_event_debug() {
    let event = ReleaseChecklistGateEvent {
        trace_id: "t-dbg".into(),
        decision_id: "d-dbg".into(),
        policy_id: "p-dbg".into(),
        component: RELEASE_CHECKLIST_COMPONENT.into(),
        event: "debug_event".into(),
        outcome: "pass".into(),
        error_code: None,
        checklist_id: None,
        item_id: None,
    };
    let s = format!("{event:?}");
    assert!(s.contains("debug_event"));
}

// ===========================================================================
// 27. ReleaseChecklistError — Display messages and StorageFailure rollback
// ===========================================================================

#[test]
fn test_error_display_messages() {
    let errs: Vec<(ReleaseChecklistError, &str)> = vec![
        (
            ReleaseChecklistError::InvalidRequest {
                field: "myfield".into(),
                detail: "bad value".into(),
            },
            "myfield",
        ),
        (
            ReleaseChecklistError::InvalidTimestamp {
                value: "not-a-ts".into(),
            },
            "not-a-ts",
        ),
        (
            ReleaseChecklistError::InvalidItem {
                item_id: "security.foo".into(),
                detail: "broken".into(),
            },
            "security.foo",
        ),
        (
            ReleaseChecklistError::SerializationFailure {
                detail: "oops".into(),
            },
            "oops",
        ),
    ];
    for (err, expected_fragment) in errs {
        let msg = err.to_string();
        assert!(
            msg.contains(expected_fragment),
            "expected fragment `{expected_fragment}` in error message `{msg}`"
        );
    }
}

// ===========================================================================
// 28. Validation — empty decision_id and policy_id fail
// ===========================================================================

#[test]
fn test_validate_empty_decision_id_fails() {
    let mut cl = valid_checklist();
    cl.decision_id = String::new();
    assert!(validate_release_checklist(&cl).is_err());
}

#[test]
fn test_validate_empty_policy_id_fails() {
    let mut cl = valid_checklist();
    cl.policy_id = String::new();
    assert!(validate_release_checklist(&cl).is_err());
}

// ===========================================================================
// 29. Validation — waiver with all-whitespace fields fails
// ===========================================================================

#[test]
fn test_validate_waiver_empty_fields_fails() {
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        item.status = ChecklistItemStatus::Waived;
        item.waiver = Some(ChecklistWaiver {
            reason: "   ".into(),
            approver: "admin".into(),
            exception_artifact_link: "/waivers/w.json".into(),
        });
    }
    assert!(validate_release_checklist(&cl).is_err());
}

// ===========================================================================
// 30. Validation — waiver present on non-waived item fails
// ===========================================================================

#[test]
fn test_validate_waiver_present_on_non_waived_item_fails() {
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        // status is Pass but we attach a waiver — not allowed
        item.status = ChecklistItemStatus::Pass;
        item.waiver = Some(ChecklistWaiver {
            reason: "spurious".into(),
            approver: "admin".into(),
            exception_artifact_link: "/waivers/w.json".into(),
        });
    }
    assert!(validate_release_checklist(&cl).is_err());
}

// ===========================================================================
// 31. Validation — empty artifact_id or path inside artifact_refs fails
// ===========================================================================

#[test]
fn test_validate_empty_artifact_id_fails() {
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        item.artifact_refs = vec![ArtifactRef {
            artifact_id: "  ".into(),
            path: "/evidence/test.json".into(),
            sha256: None,
        }];
    }
    assert!(validate_release_checklist(&cl).is_err());
}

// ===========================================================================
// 32. Validation — unknown required item_id fails
// ===========================================================================

#[test]
fn test_validate_unknown_required_item_fails() {
    let mut cl = valid_checklist();
    // Add an item marked required=true with an unrecognised item_id
    cl.items.push(ChecklistItem {
        item_id: "unknown.category.xyz".into(),
        category: ChecklistCategory::Security,
        required: true,
        status: ChecklistItemStatus::Pass,
        artifact_refs: vec![passing_artifact()],
        waiver: None,
    });
    assert!(validate_release_checklist(&cl).is_err());
}

// ===========================================================================
// 33. Gate — NotRun required item blocks release
// ===========================================================================

#[test]
fn test_not_run_item_blocks_gate() {
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "performance.benchmark_suite")
    {
        item.status = ChecklistItemStatus::NotRun;
    }
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.blocked);
    assert!(!decision.allows_release());
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("benchmark_suite"))
    );
}

// ===========================================================================
// 34. Checklist ID — has expected rchk_ prefix
// ===========================================================================

#[test]
fn test_checklist_id_prefix() {
    let cl = valid_checklist();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    let id = decision.checklist_id.expect("checklist_id should be set");
    assert!(
        id.starts_with("rchk_"),
        "checklist_id should start with rchk_, got: {id}"
    );
}

// ===========================================================================
// 35. Gate decision — rollback_required is false on normal pass/deny
// ===========================================================================

#[test]
fn test_gate_decision_rollback_false_on_pass() {
    let cl = valid_checklist();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(!decision.rollback_required);
}

#[test]
fn test_gate_decision_rollback_false_on_deny() {
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        item.status = ChecklistItemStatus::Fail;
    }
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.blocked);
    assert!(!decision.rollback_required);
}

// ===========================================================================
// 36. Gate — multiple failing items all appear in blockers
// ===========================================================================

#[test]
fn test_multiple_failures_all_reported() {
    let mut cl = valid_checklist();
    // Fail two distinct required items
    for item in cl.items.iter_mut() {
        if item.item_id == "security.conformance_suite"
            || item.item_id == "performance.benchmark_suite"
        {
            item.status = ChecklistItemStatus::Fail;
        }
    }
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.blocked);
    assert!(
        decision.blockers.len() >= 2,
        "expected at least 2 blockers, got: {:?}",
        decision.blockers
    );
}

// ===========================================================================
// 37. Query — multiple checklists stored under same release tag
// ===========================================================================

#[test]
fn test_query_multiple_checklists_same_tag() {
    let mut adapter = InMemoryStorageAdapter::new();

    // Run gate twice for same release_tag but different trace_ids so IDs differ
    let cl1 = valid_checklist(); // trace_id = "t-1"
    let mut cl2 = valid_checklist();
    cl2.trace_id = "t-2".into();
    cl2.decision_id = "d-2".into();

    run_release_checklist_gate(&mut adapter, &cl1);
    run_release_checklist_gate(&mut adapter, &cl2);

    let results =
        query_release_checklists_by_tag(&mut adapter, "v1.0.0", "t-q", "d-q", "p-q").unwrap();
    assert_eq!(
        results.len(),
        2,
        "expected 2 stored checklists for same tag, got: {}",
        results.len()
    );
    assert!(results.iter().all(|r| r.release_tag == "v1.0.0"));
}

// ===========================================================================
// 38. Category as_str values are stable
// ===========================================================================

#[test]
fn test_category_as_str_stable_values() {
    assert_eq!(ChecklistCategory::Security.as_str(), "security");
    assert_eq!(ChecklistCategory::Performance.as_str(), "performance");
    assert_eq!(
        ChecklistCategory::Reproducibility.as_str(),
        "reproducibility"
    );
    assert_eq!(ChecklistCategory::Operational.as_str(), "operational");
}

// ===========================================================================
// 39. Status as_str values are stable
// ===========================================================================

#[test]
fn test_status_as_str_stable_values() {
    assert_eq!(ChecklistItemStatus::Pass.as_str(), "pass");
    assert_eq!(ChecklistItemStatus::Fail.as_str(), "fail");
    assert_eq!(ChecklistItemStatus::NotRun.as_str(), "not_run");
    assert_eq!(ChecklistItemStatus::Waived.as_str(), "waived");
}

// ===========================================================================
// 40. Gate outcome field is "deny" when blocked
// ===========================================================================

#[test]
fn test_gate_outcome_deny_when_blocked() {
    let mut cl = valid_checklist();
    if let Some(item) = cl
        .items
        .iter_mut()
        .find(|i| i.item_id == "security.conformance_suite")
    {
        item.status = ChecklistItemStatus::Fail;
    }
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert_eq!(decision.outcome, "deny");
    assert!(decision.error_code.is_some());
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_RELEASE_BLOCKED));
}

// ===========================================================================
// 41. ReleaseChecklistGateDecision Clone
// ===========================================================================

#[test]
fn test_gate_decision_clone() {
    let cl = valid_checklist();
    let mut adapter = InMemoryStorageAdapter::new();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    let cloned = decision.clone();
    assert_eq!(cloned, decision);
}

// ===========================================================================
// 42. RequiredChecklistItem — all items have non-empty item_id
// ===========================================================================

#[test]
fn test_required_items_nonempty_ids() {
    for item in required_checklist_items() {
        assert!(!item.item_id.is_empty(), "item_id must not be empty");
    }
}

// ===========================================================================
// 43. Serde — ArtifactRef with None sha256 round-trips cleanly
// ===========================================================================

#[test]
fn test_artifact_ref_no_sha256_serde() {
    let ar = ArtifactRef {
        artifact_id: "art-nosig".into(),
        path: "/evidence/nosig.json".into(),
        sha256: None,
    };
    let json = serde_json::to_string(&ar).unwrap();
    let back: ArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back.sha256, None);
    assert_eq!(back.artifact_id, "art-nosig");
}

// ===========================================================================
// 44. Validation — invalid RFC3339 timestamp fails
// ===========================================================================

#[test]
fn test_validate_invalid_timestamp_fails() {
    let mut cl = valid_checklist();
    cl.generated_at_utc = "not-a-timestamp".into();
    let err = validate_release_checklist(&cl).unwrap_err();
    assert!(matches!(
        err,
        ReleaseChecklistError::InvalidTimestamp { .. }
    ));
}

// ===========================================================================
// 45. Validation — whitespace-only release_tag fails after trim
// ===========================================================================

#[test]
fn test_validate_whitespace_release_tag_fails() {
    let mut cl = valid_checklist();
    cl.release_tag = "   ".into();
    assert!(validate_release_checklist(&cl).is_err());
}
