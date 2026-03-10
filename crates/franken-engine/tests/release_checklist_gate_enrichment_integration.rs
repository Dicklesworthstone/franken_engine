//! Enrichment integration tests for `release_checklist_gate` (FRX-10.8).
//!
//! Covers: JSON field-name stability, serde roundtrips, Display/as_str exact
//! values, Debug distinctness, error variant coverage, validation edge cases,
//! constants, required_checklist_items(), parse/validate functions, and the
//! full gate pipeline via InMemoryStorageAdapter.

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

use frankenengine_engine::release_checklist_gate::*;
use frankenengine_engine::storage_adapter::InMemoryStorageAdapter;
use std::collections::BTreeSet;

// ── helpers ──────────────────────────────────────────────────────────────

fn make_artifact_ref(id: &str) -> ArtifactRef {
    ArtifactRef {
        artifact_id: id.to_string(),
        path: format!("artifacts/{id}.json"),
        sha256: Some("a".repeat(64)),
    }
}

fn make_passing_item(item_id: &str, category: ChecklistCategory) -> ChecklistItem {
    ChecklistItem {
        item_id: item_id.to_string(),
        category,
        required: true,
        status: ChecklistItemStatus::Pass,
        artifact_refs: vec![make_artifact_ref("art-1")],
        waiver: None,
    }
}

fn make_full_checklist() -> ReleaseChecklist {
    let items: Vec<ChecklistItem> = required_checklist_items()
        .iter()
        .map(|req| make_passing_item(req.item_id, req.category))
        .collect();

    ReleaseChecklist {
        schema_version: RELEASE_CHECKLIST_SCHEMA_VERSION.to_string(),
        release_tag: "v0.1.0".to_string(),
        generated_at_utc: "2025-01-15T12:00:00Z".to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-001".to_string(),
        items,
    }
}

// ── constants ────────────────────────────────────────────────────────────

#[test]
fn constant_component_value() {
    assert_eq!(RELEASE_CHECKLIST_COMPONENT, "release_checklist_gate");
}

#[test]
fn constant_schema_version_value() {
    assert_eq!(
        RELEASE_CHECKLIST_SCHEMA_VERSION,
        "franken-engine.release-checklist.v1"
    );
}

#[test]
fn constant_error_release_blocked_value() {
    assert_eq!(ERROR_RELEASE_BLOCKED, "FE-RCHK-1005");
}

#[test]
fn constant_storage_integration_point_value() {
    assert_eq!(
        RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT,
        "frankensqlite::benchmark::ledger"
    );
}

// ── ChecklistCategory ────────────────────────────────────────────────────

#[test]
fn checklist_category_display_exact_all_variants() {
    assert_eq!(ChecklistCategory::Security.to_string(), "security");
    assert_eq!(ChecklistCategory::Performance.to_string(), "performance");
    assert_eq!(
        ChecklistCategory::Reproducibility.to_string(),
        "reproducibility"
    );
    assert_eq!(ChecklistCategory::Operational.to_string(), "operational");
}

#[test]
fn checklist_category_as_str_exact_all_variants() {
    assert_eq!(ChecklistCategory::Security.as_str(), "security");
    assert_eq!(ChecklistCategory::Performance.as_str(), "performance");
    assert_eq!(
        ChecklistCategory::Reproducibility.as_str(),
        "reproducibility"
    );
    assert_eq!(ChecklistCategory::Operational.as_str(), "operational");
}

#[test]
fn checklist_category_debug_distinct() {
    let variants = [
        ChecklistCategory::Security,
        ChecklistCategory::Performance,
        ChecklistCategory::Reproducibility,
        ChecklistCategory::Operational,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn checklist_category_serde_tags_exact() {
    assert_eq!(
        serde_json::to_string(&ChecklistCategory::Security).unwrap(),
        "\"security\""
    );
    assert_eq!(
        serde_json::to_string(&ChecklistCategory::Performance).unwrap(),
        "\"performance\""
    );
    assert_eq!(
        serde_json::to_string(&ChecklistCategory::Reproducibility).unwrap(),
        "\"reproducibility\""
    );
    assert_eq!(
        serde_json::to_string(&ChecklistCategory::Operational).unwrap(),
        "\"operational\""
    );
}

#[test]
fn checklist_category_serde_roundtrip_all() {
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

#[test]
fn checklist_category_ordering() {
    assert!(ChecklistCategory::Security < ChecklistCategory::Performance);
    assert!(ChecklistCategory::Performance < ChecklistCategory::Reproducibility);
    assert!(ChecklistCategory::Reproducibility < ChecklistCategory::Operational);
}

// ── ChecklistItemStatus ──────────────────────────────────────────────────

#[test]
fn item_status_display_exact_all_variants() {
    assert_eq!(ChecklistItemStatus::Pass.to_string(), "pass");
    assert_eq!(ChecklistItemStatus::Fail.to_string(), "fail");
    assert_eq!(ChecklistItemStatus::NotRun.to_string(), "not_run");
    assert_eq!(ChecklistItemStatus::Waived.to_string(), "waived");
}

#[test]
fn item_status_as_str_exact_all_variants() {
    assert_eq!(ChecklistItemStatus::Pass.as_str(), "pass");
    assert_eq!(ChecklistItemStatus::Fail.as_str(), "fail");
    assert_eq!(ChecklistItemStatus::NotRun.as_str(), "not_run");
    assert_eq!(ChecklistItemStatus::Waived.as_str(), "waived");
}

#[test]
fn item_status_debug_distinct() {
    let variants = [
        ChecklistItemStatus::Pass,
        ChecklistItemStatus::Fail,
        ChecklistItemStatus::NotRun,
        ChecklistItemStatus::Waived,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn item_status_serde_tags_exact() {
    assert_eq!(
        serde_json::to_string(&ChecklistItemStatus::Pass).unwrap(),
        "\"pass\""
    );
    assert_eq!(
        serde_json::to_string(&ChecklistItemStatus::Fail).unwrap(),
        "\"fail\""
    );
    assert_eq!(
        serde_json::to_string(&ChecklistItemStatus::NotRun).unwrap(),
        "\"not_run\""
    );
    assert_eq!(
        serde_json::to_string(&ChecklistItemStatus::Waived).unwrap(),
        "\"waived\""
    );
}

#[test]
fn item_status_serde_roundtrip_all() {
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

#[test]
fn item_status_ordering() {
    assert!(ChecklistItemStatus::Pass < ChecklistItemStatus::Fail);
    assert!(ChecklistItemStatus::Fail < ChecklistItemStatus::NotRun);
    assert!(ChecklistItemStatus::NotRun < ChecklistItemStatus::Waived);
}

// ── ReleaseChecklistError ────────────────────────────────────────────────

#[test]
fn error_display_invalid_request() {
    let err = ReleaseChecklistError::InvalidRequest {
        field: "release_tag".to_string(),
        detail: "must not be empty".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("release_tag"), "msg={msg}");
    assert!(msg.contains("must not be empty"), "msg={msg}");
}

#[test]
fn error_display_invalid_timestamp() {
    let err = ReleaseChecklistError::InvalidTimestamp {
        value: "bad-time".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("bad-time"), "msg={msg}");
    assert!(msg.contains("RFC3339"), "msg={msg}");
}

#[test]
fn error_display_invalid_item() {
    let err = ReleaseChecklistError::InvalidItem {
        item_id: "security.test".to_string(),
        detail: "duplicate item_id".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("security.test"), "msg={msg}");
    assert!(msg.contains("duplicate"), "msg={msg}");
}

#[test]
fn error_display_serialization_failure() {
    let err = ReleaseChecklistError::SerializationFailure {
        detail: "parse error".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("serialization failure"), "msg={msg}");
    assert!(msg.contains("parse error"), "msg={msg}");
}

#[test]
fn error_is_std_error() {
    let err = ReleaseChecklistError::InvalidRequest {
        field: "f".to_string(),
        detail: "d".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn error_debug_distinct() {
    let variants: Vec<String> = vec![
        format!(
            "{:?}",
            ReleaseChecklistError::InvalidRequest {
                field: "f".into(),
                detail: "d".into()
            }
        ),
        format!(
            "{:?}",
            ReleaseChecklistError::InvalidTimestamp { value: "v".into() }
        ),
        format!(
            "{:?}",
            ReleaseChecklistError::InvalidItem {
                item_id: "i".into(),
                detail: "d".into()
            }
        ),
        format!(
            "{:?}",
            ReleaseChecklistError::SerializationFailure { detail: "d".into() }
        ),
    ];
    let set: BTreeSet<_> = variants.iter().collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn error_stable_code_invalid_request() {
    let err = ReleaseChecklistError::InvalidRequest {
        field: "f".to_string(),
        detail: "d".to_string(),
    };
    assert_eq!(err.stable_code(), "FE-RCHK-1001");
}

#[test]
fn error_stable_code_invalid_timestamp() {
    let err = ReleaseChecklistError::InvalidTimestamp {
        value: "v".to_string(),
    };
    assert_eq!(err.stable_code(), "FE-RCHK-1002");
}

#[test]
fn error_stable_code_invalid_item() {
    let err = ReleaseChecklistError::InvalidItem {
        item_id: "i".to_string(),
        detail: "d".to_string(),
    };
    assert_eq!(err.stable_code(), "FE-RCHK-1003");
}

#[test]
fn error_stable_code_serialization() {
    let err = ReleaseChecklistError::SerializationFailure {
        detail: "d".to_string(),
    };
    assert_eq!(err.stable_code(), "FE-RCHK-1004");
}

#[test]
fn error_requires_rollback_only_storage_failure() {
    assert!(
        !ReleaseChecklistError::InvalidRequest {
            field: "f".into(),
            detail: "d".into()
        }
        .requires_rollback()
    );
    assert!(!ReleaseChecklistError::InvalidTimestamp { value: "v".into() }.requires_rollback());
    assert!(
        !ReleaseChecklistError::InvalidItem {
            item_id: "i".into(),
            detail: "d".into()
        }
        .requires_rollback()
    );
    assert!(
        !ReleaseChecklistError::SerializationFailure { detail: "d".into() }.requires_rollback()
    );
}

// ── required_checklist_items ─────────────────────────────────────────────

#[test]
fn required_items_count_16() {
    assert_eq!(required_checklist_items().len(), 16);
}

#[test]
fn required_items_security_count_6() {
    let count = required_checklist_items()
        .iter()
        .filter(|item| item.category == ChecklistCategory::Security)
        .count();
    assert_eq!(count, 6);
}

#[test]
fn required_items_performance_count_4() {
    let count = required_checklist_items()
        .iter()
        .filter(|item| item.category == ChecklistCategory::Performance)
        .count();
    assert_eq!(count, 4);
}

#[test]
fn required_items_reproducibility_count_3() {
    let count = required_checklist_items()
        .iter()
        .filter(|item| item.category == ChecklistCategory::Reproducibility)
        .count();
    assert_eq!(count, 3);
}

#[test]
fn required_items_operational_count_3() {
    let count = required_checklist_items()
        .iter()
        .filter(|item| item.category == ChecklistCategory::Operational)
        .count();
    assert_eq!(count, 3);
}

#[test]
fn required_items_unique_ids() {
    let ids: BTreeSet<&str> = required_checklist_items()
        .iter()
        .map(|item| item.item_id)
        .collect();
    assert_eq!(ids.len(), required_checklist_items().len());
}

#[test]
fn required_items_all_cover_four_categories() {
    let cats: BTreeSet<ChecklistCategory> = required_checklist_items()
        .iter()
        .map(|item| item.category)
        .collect();
    assert_eq!(cats.len(), 4);
}

// ── JSON field-name stability ────────────────────────────────────────────

#[test]
fn artifact_ref_json_fields() {
    let art = make_artifact_ref("art-1");
    let json = serde_json::to_value(&art).unwrap();
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("artifact_id"));
    assert!(obj.contains_key("path"));
    assert!(obj.contains_key("sha256"));
}

#[test]
fn checklist_waiver_json_fields() {
    let waiver = ChecklistWaiver {
        reason: "r".to_string(),
        approver: "a".to_string(),
        exception_artifact_link: "l".to_string(),
    };
    let json = serde_json::to_value(&waiver).unwrap();
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("reason"));
    assert!(obj.contains_key("approver"));
    assert!(obj.contains_key("exception_artifact_link"));
}

#[test]
fn checklist_item_json_fields() {
    let item = make_passing_item("security.conformance_suite", ChecklistCategory::Security);
    let json = serde_json::to_value(&item).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "item_id",
        "category",
        "required",
        "status",
        "artifact_refs",
        "waiver",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn release_checklist_json_fields() {
    let cl = make_full_checklist();
    let json = serde_json::to_value(&cl).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "schema_version",
        "release_tag",
        "generated_at_utc",
        "trace_id",
        "decision_id",
        "policy_id",
        "items",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn gate_event_json_fields() {
    let event = ReleaseChecklistGateEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: RELEASE_CHECKLIST_COMPONENT.into(),
        event: "test".into(),
        outcome: "pass".into(),
        error_code: None,
        checklist_id: None,
        item_id: None,
    };
    let json = serde_json::to_value(&event).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "checklist_id",
        "item_id",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

#[test]
fn gate_decision_json_fields() {
    let decision = ReleaseChecklistGateDecision {
        checklist_id: None,
        release_tag: "v1".into(),
        outcome: "allow".into(),
        blocked: false,
        blockers: vec![],
        error_code: None,
        rollback_required: false,
        storage_backend: "test".into(),
        storage_integration_point: "test".into(),
        store_key: None,
        events: vec![],
    };
    let json = serde_json::to_value(&decision).unwrap();
    let obj = json.as_object().unwrap();
    for key in &[
        "checklist_id",
        "release_tag",
        "outcome",
        "blocked",
        "blockers",
        "error_code",
        "rollback_required",
        "storage_backend",
        "storage_integration_point",
        "store_key",
        "events",
    ] {
        assert!(obj.contains_key(*key), "missing key: {key}");
    }
}

// ── serde roundtrips ─────────────────────────────────────────────────────

#[test]
fn artifact_ref_serde_roundtrip_with_sha() {
    let art = make_artifact_ref("art-1");
    let json = serde_json::to_string(&art).unwrap();
    let back: ArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, art);
}

#[test]
fn artifact_ref_serde_roundtrip_without_sha() {
    let art = ArtifactRef {
        artifact_id: "art-2".into(),
        path: "p".into(),
        sha256: None,
    };
    let json = serde_json::to_string(&art).unwrap();
    let back: ArtifactRef = serde_json::from_str(&json).unwrap();
    assert_eq!(back, art);
}

#[test]
fn checklist_waiver_serde_roundtrip() {
    let waiver = ChecklistWaiver {
        reason: "known issue".into(),
        approver: "admin".into(),
        exception_artifact_link: "bd-99".into(),
    };
    let json = serde_json::to_string(&waiver).unwrap();
    let back: ChecklistWaiver = serde_json::from_str(&json).unwrap();
    assert_eq!(back, waiver);
}

#[test]
fn checklist_item_serde_roundtrip() {
    let item = make_passing_item("security.conformance_suite", ChecklistCategory::Security);
    let json = serde_json::to_string(&item).unwrap();
    let back: ChecklistItem = serde_json::from_str(&json).unwrap();
    assert_eq!(back, item);
}

#[test]
fn release_checklist_serde_roundtrip() {
    let cl = make_full_checklist();
    let json = serde_json::to_string(&cl).unwrap();
    let back: ReleaseChecklist = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cl);
}

#[test]
fn gate_event_serde_roundtrip() {
    let event = ReleaseChecklistGateEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: RELEASE_CHECKLIST_COMPONENT.into(),
        event: "test".into(),
        outcome: "pass".into(),
        error_code: Some("FE-RCHK-1005".into()),
        checklist_id: Some("rchk_abc".into()),
        item_id: Some("item-1".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ReleaseChecklistGateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn gate_decision_serde_roundtrip() {
    let decision = ReleaseChecklistGateDecision {
        checklist_id: Some("rchk_abc".into()),
        release_tag: "v1.0.0".into(),
        outcome: "allow".into(),
        blocked: false,
        blockers: vec![],
        error_code: None,
        rollback_required: false,
        storage_backend: "in_memory".into(),
        storage_integration_point: RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT.into(),
        store_key: Some("release_checklist/v1.0.0/rchk_abc".into()),
        events: vec![],
    };
    let json = serde_json::to_string(&decision).unwrap();
    let back: ReleaseChecklistGateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, decision);
}

// ── ReleaseChecklistGateDecision ─────────────────────────────────────────

#[test]
fn decision_allows_release_when_allow() {
    let d = ReleaseChecklistGateDecision {
        checklist_id: None,
        release_tag: "v1".into(),
        outcome: "allow".into(),
        blocked: false,
        blockers: vec![],
        error_code: None,
        rollback_required: false,
        storage_backend: "test".into(),
        storage_integration_point: "test".into(),
        store_key: None,
        events: vec![],
    };
    assert!(d.allows_release());
}

#[test]
fn decision_denies_release_when_deny() {
    let d = ReleaseChecklistGateDecision {
        checklist_id: None,
        release_tag: "v1".into(),
        outcome: "deny".into(),
        blocked: true,
        blockers: vec!["b".into()],
        error_code: Some(ERROR_RELEASE_BLOCKED.into()),
        rollback_required: false,
        storage_backend: "test".into(),
        storage_integration_point: "test".into(),
        store_key: None,
        events: vec![],
    };
    assert!(!d.allows_release());
}

#[test]
fn decision_denies_release_when_fail() {
    let d = ReleaseChecklistGateDecision {
        checklist_id: None,
        release_tag: "v1".into(),
        outcome: "fail".into(),
        blocked: true,
        blockers: vec![],
        error_code: None,
        rollback_required: false,
        storage_backend: "test".into(),
        storage_integration_point: "test".into(),
        store_key: None,
        events: vec![],
    };
    assert!(!d.allows_release());
}

// ── parse_release_checklist_json ─────────────────────────────────────────

#[test]
fn parse_valid_json_roundtrip() {
    let cl = make_full_checklist();
    let json = serde_json::to_string(&cl).unwrap();
    let parsed = parse_release_checklist_json(&json).unwrap();
    assert_eq!(parsed.release_tag, "v0.1.0");
    assert_eq!(parsed.items.len(), cl.items.len());
}

#[test]
fn parse_invalid_json_returns_serialization_error() {
    let err = parse_release_checklist_json("{{not json}}").unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1004");
}

// ── validate_release_checklist ──────────────────────────────────────────

#[test]
fn validate_full_passing_checklist_ok() {
    assert!(validate_release_checklist(&make_full_checklist()).is_ok());
}

#[test]
fn validate_wrong_schema_version_fails() {
    let mut cl = make_full_checklist();
    cl.schema_version = "wrong".into();
    let err = validate_release_checklist(&cl).unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1001");
}

#[test]
fn validate_empty_release_tag_fails() {
    let mut cl = make_full_checklist();
    cl.release_tag = " ".into();
    assert!(validate_release_checklist(&cl).is_err());
}

#[test]
fn validate_empty_trace_id_fails() {
    let mut cl = make_full_checklist();
    cl.trace_id = "".into();
    assert!(validate_release_checklist(&cl).is_err());
}

#[test]
fn validate_empty_decision_id_fails() {
    let mut cl = make_full_checklist();
    cl.decision_id = "".into();
    assert!(validate_release_checklist(&cl).is_err());
}

#[test]
fn validate_empty_policy_id_fails() {
    let mut cl = make_full_checklist();
    cl.policy_id = " ".into();
    assert!(validate_release_checklist(&cl).is_err());
}

#[test]
fn validate_empty_items_fails() {
    let mut cl = make_full_checklist();
    cl.items.clear();
    assert!(validate_release_checklist(&cl).is_err());
}

#[test]
fn validate_invalid_timestamp_fails() {
    let mut cl = make_full_checklist();
    cl.generated_at_utc = "not-a-date".into();
    let err = validate_release_checklist(&cl).unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1002");
}

#[test]
fn validate_duplicate_item_id_fails() {
    let mut cl = make_full_checklist();
    let dup = cl.items[0].clone();
    cl.items.push(dup);
    let err = validate_release_checklist(&cl).unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1003");
}

#[test]
fn validate_waived_without_waiver_fails() {
    let mut cl = make_full_checklist();
    cl.items[0].status = ChecklistItemStatus::Waived;
    cl.items[0].waiver = None;
    assert!(validate_release_checklist(&cl).is_err());
}

#[test]
fn validate_waiver_on_non_waived_fails() {
    let mut cl = make_full_checklist();
    cl.items[0].status = ChecklistItemStatus::Pass;
    cl.items[0].waiver = Some(ChecklistWaiver {
        reason: "r".into(),
        approver: "a".into(),
        exception_artifact_link: "l".into(),
    });
    assert!(validate_release_checklist(&cl).is_err());
}

// ── run_release_checklist_gate (via InMemoryStorageAdapter) ──────────────

#[test]
fn gate_passing_checklist_allows_release() {
    let mut adapter = InMemoryStorageAdapter::default();
    let cl = make_full_checklist();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.allows_release());
    assert!(!decision.blocked);
    assert!(decision.blockers.is_empty());
    assert_eq!(decision.outcome, "allow");
    assert!(decision.checklist_id.is_some());
    assert!(decision.store_key.is_some());
    assert!(decision.error_code.is_none());
    assert!(!decision.rollback_required);
}

#[test]
fn gate_failing_checklist_denies_release() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut cl = make_full_checklist();
    cl.items[0].status = ChecklistItemStatus::Fail;
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(!decision.allows_release());
    assert!(decision.blocked);
    assert_eq!(decision.outcome, "deny");
    assert_eq!(decision.error_code.as_deref(), Some(ERROR_RELEASE_BLOCKED));
}

#[test]
fn gate_invalid_schema_fails_with_error_code() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut cl = make_full_checklist();
    cl.schema_version = "wrong".into();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(!decision.allows_release());
    assert_eq!(decision.outcome, "fail");
    assert!(decision.checklist_id.is_none());
}

#[test]
fn gate_events_contain_started_and_completed() {
    let mut adapter = InMemoryStorageAdapter::default();
    let cl = make_full_checklist();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    let event_names: Vec<&str> = decision.events.iter().map(|e| e.event.as_str()).collect();
    assert!(
        event_names.contains(&"release_checklist_gate_started"),
        "events={event_names:?}"
    );
    assert!(
        event_names.contains(&"release_checklist_gate_completed"),
        "events={event_names:?}"
    );
}

#[test]
fn gate_stores_checklist_and_queryable() {
    let mut adapter = InMemoryStorageAdapter::default();
    let cl = make_full_checklist();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.allows_release());

    let results = query_release_checklists_by_tag(
        &mut adapter,
        "v0.1.0",
        "trace-q",
        "decision-q",
        "policy-q",
    )
    .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].release_tag, "v0.1.0");
}

#[test]
fn gate_decision_storage_backend_is_in_memory() {
    let mut adapter = InMemoryStorageAdapter::default();
    let cl = make_full_checklist();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert_eq!(decision.storage_backend, "in_memory");
}

#[test]
fn gate_decision_storage_integration_point() {
    let mut adapter = InMemoryStorageAdapter::default();
    let cl = make_full_checklist();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert_eq!(
        decision.storage_integration_point,
        RELEASE_CHECKLIST_STORAGE_INTEGRATION_POINT
    );
}

// ── query_release_checklists_by_tag ─────────────────────────────────────

#[test]
fn query_empty_release_tag_errors() {
    let mut adapter = InMemoryStorageAdapter::default();
    let err = query_release_checklists_by_tag(&mut adapter, "", "t", "d", "p").unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1001");
}

#[test]
fn query_empty_trace_id_errors() {
    let mut adapter = InMemoryStorageAdapter::default();
    let err = query_release_checklists_by_tag(&mut adapter, "v1", "", "d", "p").unwrap_err();
    assert_eq!(err.stable_code(), "FE-RCHK-1001");
}

#[test]
fn query_nonexistent_tag_returns_empty() {
    let mut adapter = InMemoryStorageAdapter::default();
    let results =
        query_release_checklists_by_tag(&mut adapter, "nonexistent", "t", "d", "p").unwrap();
    assert!(results.is_empty());
}

// ── waived item with valid waiver passes ─────────────────────────────────

#[test]
fn waived_item_with_valid_waiver_and_artifacts_passes() {
    let mut cl = make_full_checklist();
    cl.items[0].status = ChecklistItemStatus::Waived;
    cl.items[0].waiver = Some(ChecklistWaiver {
        reason: "known gap".into(),
        approver: "eng-lead".into(),
        exception_artifact_link: "bd-100".into(),
    });
    assert!(validate_release_checklist(&cl).is_ok());
}

#[test]
fn waived_item_without_artifacts_blocked_at_gate() {
    let mut adapter = InMemoryStorageAdapter::default();
    let mut cl = make_full_checklist();
    cl.items[0].status = ChecklistItemStatus::Waived;
    cl.items[0].waiver = Some(ChecklistWaiver {
        reason: "known gap".into(),
        approver: "eng-lead".into(),
        exception_artifact_link: "bd-100".into(),
    });
    cl.items[0].artifact_refs.clear();
    let decision = run_release_checklist_gate(&mut adapter, &cl);
    assert!(decision.blocked);
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.contains("no artifact_refs")),
        "blockers={:?}",
        decision.blockers
    );
}
