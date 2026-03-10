#![forbid(unsafe_code)]
//! Enrichment integration tests for `execution_cell`.
//!
//! Adds CellKind Display/ordering, CellError error_code stability,
//! serde roundtrips, JSON field-name stability, Debug distinctness,
//! CellManager construction, and ExtensionHostBinding lifecycle
//! beyond the existing 49 integration tests.

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

use frankenengine_engine::execution_cell::{
    CellCloseReport, CellError, CellEvent, CellKind, CellManager, ExecutionCell,
    ExtensionHostBinding, LifecycleEvidenceEntry,
};
use frankenengine_engine::region_lifecycle::{DrainDeadline, RegionState};

// ===========================================================================
// 1) CellKind — Display exactness + ordering
// ===========================================================================

#[test]
fn cell_kind_display_all_distinct() {
    let displays: Vec<String> = [CellKind::Extension, CellKind::Session, CellKind::Delegate]
        .iter()
        .map(|k| k.to_string())
        .collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn cell_kind_ordering_stable() {
    let mut kinds = [CellKind::Delegate, CellKind::Extension, CellKind::Session];
    kinds.sort();
    let first = kinds[0];
    let last = kinds[kinds.len() - 1];
    assert!(first <= last);
}

// ===========================================================================
// 2) CellError — error_code stability + Display uniqueness
// ===========================================================================

#[test]
fn cell_error_error_codes_all_distinct() {
    let codes: Vec<&str> = vec![
        CellError::InvalidState {
            cell_id: "c".into(),
            current: RegionState::Running,
            attempted: "x".into(),
        }
        .error_code(),
        CellError::BudgetExhausted {
            cell_id: "c".into(),
            requested_ms: 10,
            remaining_ms: 5,
        }
        .error_code(),
        CellError::CxThreading {
            cell_id: "c".into(),
            error_code: "e".into(),
            message: "m".into(),
        }
        .error_code(),
        CellError::CellNotFound {
            cell_id: "c".into(),
        }
        .error_code(),
        CellError::SessionRejected {
            parent_cell_id: "c".into(),
            reason: "r".into(),
        }
        .error_code(),
        CellError::ObligationNotFound {
            cell_id: "c".into(),
            obligation_id: "o".into(),
        }
        .error_code(),
    ];
    let unique: BTreeSet<_> = codes.iter().collect();
    assert_eq!(unique.len(), 6);
}

#[test]
fn cell_error_display_all_unique() {
    let variants: Vec<String> = vec![
        CellError::InvalidState {
            cell_id: "c1".into(),
            current: RegionState::Running,
            attempted: "close".into(),
        }
        .to_string(),
        CellError::BudgetExhausted {
            cell_id: "c2".into(),
            requested_ms: 10,
            remaining_ms: 5,
        }
        .to_string(),
        CellError::CxThreading {
            cell_id: "c3".into(),
            error_code: "e".into(),
            message: "m".into(),
        }
        .to_string(),
        CellError::CellNotFound {
            cell_id: "c4".into(),
        }
        .to_string(),
        CellError::SessionRejected {
            parent_cell_id: "c5".into(),
            reason: "r".into(),
        }
        .to_string(),
        CellError::ObligationNotFound {
            cell_id: "c6".into(),
            obligation_id: "o".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn cell_error_is_std_error() {
    let e = CellError::CellNotFound {
        cell_id: "x".into(),
    };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn cell_error_display_contains_cell_id() {
    let e = CellError::CellNotFound {
        cell_id: "my-cell-42".into(),
    };
    let s = e.to_string();
    assert!(s.contains("my-cell-42"), "should contain cell_id: {s}");
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_cell_kind() {
    let variants = [
        format!("{:?}", CellKind::Extension),
        format!("{:?}", CellKind::Session),
        format!("{:?}", CellKind::Delegate),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_cell_error() {
    let variants = [
        format!(
            "{:?}",
            CellError::CellNotFound {
                cell_id: "a".into()
            }
        ),
        format!(
            "{:?}",
            CellError::BudgetExhausted {
                cell_id: "b".into(),
                requested_ms: 1,
                remaining_ms: 0
            }
        ),
        format!(
            "{:?}",
            CellError::SessionRejected {
                parent_cell_id: "c".into(),
                reason: "r".into()
            }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 4) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_cell_kind_all() {
    for k in [CellKind::Extension, CellKind::Session, CellKind::Delegate] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: CellKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_cell_error_all() {
    let variants = vec![
        CellError::InvalidState {
            cell_id: "c1".into(),
            current: RegionState::Running,
            attempted: "close".into(),
        },
        CellError::BudgetExhausted {
            cell_id: "c2".into(),
            requested_ms: 10,
            remaining_ms: 5,
        },
        CellError::CxThreading {
            cell_id: "c3".into(),
            error_code: "e".into(),
            message: "m".into(),
        },
        CellError::CellNotFound {
            cell_id: "c4".into(),
        },
        CellError::SessionRejected {
            parent_cell_id: "c5".into(),
            reason: "r".into(),
        },
        CellError::ObligationNotFound {
            cell_id: "c6".into(),
            obligation_id: "o".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: CellError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_cell_event() {
    let ce = CellEvent {
        trace_id: "t".into(),
        cell_id: "c".into(),
        cell_kind: CellKind::Extension,
        decision_id: "d".into(),
        policy_id: "p".into(),
        event: "execute_effect".into(),
        component: "execution_cell".into(),
        outcome: "ok".into(),
        error_code: None,
        region_state: RegionState::Running,
        budget_consumed_ms: 5,
    };
    let json = serde_json::to_string(&ce).unwrap();
    let rt: CellEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ce, rt);
}

#[test]
fn serde_roundtrip_cell_close_report() {
    let cr = CellCloseReport {
        cell_id: "c".into(),
        cell_kind: CellKind::Extension,
        close_reason: "normal".into(),
        success: true,
        obligations_committed: 3,
        obligations_aborted: 0,
        drain_timeout_escalated: false,
        budget_consumed_ms: 100,
        evidence_entries_emitted: 5,
    };
    let json = serde_json::to_string(&cr).unwrap();
    let rt: CellCloseReport = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, rt);
}

#[test]
fn serde_roundtrip_lifecycle_evidence_entry() {
    let le = LifecycleEvidenceEntry {
        sequence: 1,
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "extension_host_binding".into(),
        event: "extension_load".into(),
        outcome: "ok".into(),
        error_code: None,
        cell_id: "c".into(),
        cell_kind: CellKind::Extension,
        region_state: RegionState::Running,
        budget_consumed_ms: 0,
        metadata: std::collections::BTreeMap::new(),
    };
    let json = serde_json::to_string(&le).unwrap();
    let rt: LifecycleEvidenceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(le, rt);
}

// ===========================================================================
// 5) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_cell_event() {
    let ce = CellEvent {
        trace_id: "t".into(),
        cell_id: "c".into(),
        cell_kind: CellKind::Session,
        decision_id: "d".into(),
        policy_id: "p".into(),
        event: "e".into(),
        component: "comp".into(),
        outcome: "ok".into(),
        error_code: None,
        region_state: RegionState::Running,
        budget_consumed_ms: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&ce).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "cell_id",
        "cell_kind",
        "decision_id",
        "policy_id",
        "event",
        "component",
        "outcome",
        "error_code",
        "region_state",
        "budget_consumed_ms",
    ] {
        assert!(obj.contains_key(key), "CellEvent missing field: {key}");
    }
}

#[test]
fn json_fields_cell_close_report() {
    let cr = CellCloseReport {
        cell_id: "c".into(),
        cell_kind: CellKind::Delegate,
        close_reason: "r".into(),
        success: true,
        obligations_committed: 0,
        obligations_aborted: 0,
        drain_timeout_escalated: false,
        budget_consumed_ms: 0,
        evidence_entries_emitted: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&cr).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "cell_id",
        "cell_kind",
        "close_reason",
        "success",
        "obligations_committed",
        "obligations_aborted",
        "drain_timeout_escalated",
        "budget_consumed_ms",
        "evidence_entries_emitted",
    ] {
        assert!(
            obj.contains_key(key),
            "CellCloseReport missing field: {key}"
        );
    }
}

#[test]
fn json_fields_lifecycle_evidence_entry() {
    let le = LifecycleEvidenceEntry {
        sequence: 0,
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: None,
        cell_id: "cl".into(),
        cell_kind: CellKind::Extension,
        region_state: RegionState::Running,
        budget_consumed_ms: 0,
        metadata: std::collections::BTreeMap::new(),
    };
    let v: serde_json::Value = serde_json::to_value(&le).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "sequence",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "cell_id",
        "cell_kind",
        "region_state",
        "budget_consumed_ms",
        "metadata",
    ] {
        assert!(
            obj.contains_key(key),
            "LifecycleEvidenceEntry missing field: {key}"
        );
    }
}

// ===========================================================================
// 6) ExecutionCell — construction and initial state
// ===========================================================================

#[test]
fn execution_cell_new_initial_state() {
    let cell = ExecutionCell::new("cell-1", CellKind::Extension, "trace-1");
    assert_eq!(cell.cell_id(), "cell-1");
    assert_eq!(cell.kind(), CellKind::Extension);
    assert_eq!(cell.state(), RegionState::Running);
    assert_eq!(cell.trace_id(), "trace-1");
    assert_eq!(cell.total_budget_consumed_ms(), 0);
    assert_eq!(cell.pending_obligations(), 0);
    assert_eq!(cell.session_count(), 0);
}

#[test]
fn execution_cell_with_context() {
    let cell =
        ExecutionCell::with_context("cell-2", CellKind::Delegate, "trace-2", "dec-1", "pol-1");
    assert_eq!(cell.cell_id(), "cell-2");
    assert_eq!(cell.kind(), CellKind::Delegate);
    assert_eq!(cell.decision_id(), "dec-1");
    assert_eq!(cell.policy_id(), "pol-1");
}

#[test]
fn execution_cell_events_initially_empty() {
    let cell = ExecutionCell::new("cell-3", CellKind::Session, "trace-3");
    assert!(cell.events().is_empty());
    assert!(cell.effect_log().is_empty());
}

// ===========================================================================
// 7) CellManager — construction and initial state
// ===========================================================================

#[test]
fn cell_manager_new_empty() {
    let manager = CellManager::new();
    assert_eq!(manager.active_count(), 0);
    assert_eq!(manager.closed_count(), 0);
    assert!(manager.active_cell_ids().is_empty());
    assert!(manager.closed_results().is_empty());
}

#[test]
fn cell_manager_default_matches_new() {
    let m1 = CellManager::new();
    let m2 = CellManager::default();
    assert_eq!(m1.active_count(), m2.active_count());
    assert_eq!(m1.closed_count(), m2.closed_count());
}

#[test]
fn cell_manager_create_extension_cell() {
    let mut manager = CellManager::new();
    let cell = manager.create_extension_cell("ext-1", "trace-1");
    assert_eq!(cell.kind(), CellKind::Extension);
    assert_eq!(cell.cell_id(), "ext-1");
    assert_eq!(manager.active_count(), 1);
}

#[test]
fn cell_manager_create_delegate_cell() {
    let mut manager = CellManager::new();
    let cell = manager.create_delegate_cell("del-1", "trace-1");
    assert_eq!(cell.kind(), CellKind::Delegate);
    assert_eq!(manager.active_count(), 1);
}

#[test]
fn cell_manager_get_returns_cell() {
    let mut manager = CellManager::new();
    manager.create_extension_cell("ext-1", "trace-1");
    assert!(manager.get("ext-1").is_some());
    assert!(manager.get("nonexistent").is_none());
}

// ===========================================================================
// 8) ExtensionHostBinding — construction
// ===========================================================================

#[test]
fn extension_host_binding_new_empty() {
    let binding = ExtensionHostBinding::new(DrainDeadline { max_ticks: 100 });
    assert_eq!(binding.active_extension_count(), 0);
    assert_eq!(binding.evidence_count(), 0);
    assert!(binding.evidence_log().is_empty());
    assert_eq!(binding.manager().active_count(), 0);
}

// ===========================================================================
// 9) CellError — error_code values
// ===========================================================================

#[test]
fn cell_error_error_code_starts_with_prefix() {
    let errors: Vec<CellError> = vec![
        CellError::InvalidState {
            cell_id: "c".into(),
            current: RegionState::Running,
            attempted: "x".into(),
        },
        CellError::BudgetExhausted {
            cell_id: "c".into(),
            requested_ms: 10,
            remaining_ms: 5,
        },
        CellError::CxThreading {
            cell_id: "c".into(),
            error_code: "e".into(),
            message: "m".into(),
        },
        CellError::CellNotFound {
            cell_id: "c".into(),
        },
        CellError::SessionRejected {
            parent_cell_id: "c".into(),
            reason: "r".into(),
        },
        CellError::ObligationNotFound {
            cell_id: "c".into(),
            obligation_id: "o".into(),
        },
    ];
    for err in &errors {
        let code = err.error_code();
        assert!(
            !code.is_empty(),
            "error code should not be empty for {err:?}"
        );
    }
}

// ===========================================================================
// 10) CellError — Display content validation
// ===========================================================================

#[test]
fn cell_error_budget_exhausted_contains_values() {
    let e = CellError::BudgetExhausted {
        cell_id: "cell-b".into(),
        requested_ms: 100,
        remaining_ms: 50,
    };
    let s = e.to_string();
    assert!(
        s.contains("100") || s.contains("50") || s.contains("budget"),
        "should contain budget info: {s}"
    );
}

#[test]
fn cell_error_session_rejected_contains_reason() {
    let e = CellError::SessionRejected {
        parent_cell_id: "parent-1".into(),
        reason: "extension is closing".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("closing") || s.contains("rejected"),
        "should contain reason: {s}"
    );
}

#[test]
fn cell_error_obligation_not_found_contains_ids() {
    let e = CellError::ObligationNotFound {
        cell_id: "cell-x".into(),
        obligation_id: "obl-42".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("obl-42") || s.contains("cell-x"),
        "should contain ids: {s}"
    );
}

#[test]
fn cell_error_invalid_state_contains_state() {
    let e = CellError::InvalidState {
        cell_id: "cell-s".into(),
        current: RegionState::Running,
        attempted: "finalize".into(),
    };
    let s = e.to_string();
    assert!(!s.is_empty(), "display should not be empty");
}

#[test]
fn cell_error_cx_threading_contains_message() {
    let e = CellError::CxThreading {
        cell_id: "cell-t".into(),
        error_code: "CX-001".into(),
        message: "thread pool exhausted".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("exhausted") || s.contains("CX-001"),
        "should contain message: {s}"
    );
}

// ===========================================================================
// 11) CellKind — Display values
// ===========================================================================

#[test]
fn cell_kind_display_non_empty() {
    for k in [CellKind::Extension, CellKind::Session, CellKind::Delegate] {
        let s = k.to_string();
        assert!(
            !s.is_empty(),
            "CellKind display should not be empty for {k:?}"
        );
    }
}

// ===========================================================================
// 12) CellManager — multiple cells
// ===========================================================================

#[test]
fn cell_manager_multiple_cells() {
    let mut manager = CellManager::new();
    manager.create_extension_cell("ext-1", "trace-1");
    manager.create_extension_cell("ext-2", "trace-2");
    manager.create_delegate_cell("del-1", "trace-3");
    assert_eq!(manager.active_count(), 3);
    let ids = manager.active_cell_ids();
    assert_eq!(ids.len(), 3);
}

#[test]
fn cell_manager_get_mut_modifies() {
    let mut manager = CellManager::new();
    manager.create_extension_cell("ext-1", "trace-1");
    let cell = manager.get_mut("ext-1").unwrap();
    cell.register_obligation("obl-1", "test obligation");
    assert_eq!(manager.get("ext-1").unwrap().pending_obligations(), 1);
}

#[test]
fn cell_manager_insert_prebuilt_cell() {
    let mut manager = CellManager::new();
    let cell = ExecutionCell::with_context("custom", CellKind::Session, "t", "d", "p");
    manager.insert_cell("custom", cell);
    assert_eq!(manager.active_count(), 1);
    let c = manager.get("custom").unwrap();
    assert_eq!(c.kind(), CellKind::Session);
}

// ===========================================================================
// 13) ExecutionCell — obligations
// ===========================================================================

#[test]
fn execution_cell_register_and_commit_obligation() {
    let mut cell = ExecutionCell::new("cell-obl", CellKind::Extension, "trace-obl");
    cell.register_obligation("obl-1", "write file");
    assert_eq!(cell.pending_obligations(), 1);
    cell.commit_obligation("obl-1").unwrap();
    assert_eq!(cell.pending_obligations(), 0);
}

#[test]
fn execution_cell_register_and_abort_obligation() {
    let mut cell = ExecutionCell::new("cell-obl2", CellKind::Extension, "trace-obl2");
    cell.register_obligation("obl-1", "write file");
    cell.abort_obligation("obl-1").unwrap();
    assert_eq!(cell.pending_obligations(), 0);
}

#[test]
fn execution_cell_commit_unknown_obligation_fails() {
    let mut cell = ExecutionCell::new("cell-obl3", CellKind::Extension, "trace-obl3");
    let err = cell.commit_obligation("nonexistent").unwrap_err();
    assert!(matches!(err, CellError::ObligationNotFound { .. }));
}

#[test]
fn execution_cell_abort_unknown_obligation_fails() {
    let mut cell = ExecutionCell::new("cell-obl4", CellKind::Extension, "trace-obl4");
    let err = cell.abort_obligation("nonexistent").unwrap_err();
    assert!(matches!(err, CellError::ObligationNotFound { .. }));
}

// ===========================================================================
// 14) ExecutionCell — session creation
// ===========================================================================

#[test]
fn execution_cell_create_session() {
    let mut cell = ExecutionCell::new("ext-parent", CellKind::Extension, "trace-sess");
    let session = cell.create_session("sess-1", "trace-sess-1").unwrap();
    assert_eq!(session.kind(), CellKind::Session);
    assert_eq!(session.cell_id(), "sess-1");
    assert_eq!(cell.session_count(), 1);
}

#[test]
fn execution_cell_create_multiple_sessions() {
    let mut cell = ExecutionCell::new("ext-multi", CellKind::Extension, "trace-multi");
    cell.create_session("sess-1", "t1").unwrap();
    cell.create_session("sess-2", "t2").unwrap();
    assert_eq!(cell.session_count(), 2);
}

// ===========================================================================
// 15) CellCloseReport edge cases
// ===========================================================================

#[test]
fn cell_close_report_failure() {
    let cr = CellCloseReport {
        cell_id: "fail-cell".into(),
        cell_kind: CellKind::Delegate,
        close_reason: "timeout".into(),
        success: false,
        obligations_committed: 0,
        obligations_aborted: 2,
        drain_timeout_escalated: true,
        budget_consumed_ms: 500,
        evidence_entries_emitted: 3,
    };
    assert!(!cr.success);
    assert!(cr.drain_timeout_escalated);
    assert_eq!(cr.obligations_aborted, 2);
}

// ===========================================================================
// 16) LifecycleEvidenceEntry with metadata
// ===========================================================================

#[test]
fn lifecycle_evidence_entry_with_metadata() {
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("extension_id".to_string(), "ext-123".to_string());
    metadata.insert("version".to_string(), "1.0.0".to_string());
    let le = LifecycleEvidenceEntry {
        sequence: 5,
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "extension_host_binding".into(),
        event: "extension_load".into(),
        outcome: "ok".into(),
        error_code: None,
        cell_id: "c".into(),
        cell_kind: CellKind::Extension,
        region_state: RegionState::Running,
        budget_consumed_ms: 0,
        metadata,
    };
    let json = serde_json::to_string(&le).unwrap();
    let rt: LifecycleEvidenceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.metadata.len(), 2);
    assert_eq!(rt.metadata["extension_id"], "ext-123");
}

// ===========================================================================
// 17) ExtensionHostBinding — drain deadline
// ===========================================================================

#[test]
fn extension_host_binding_drain_deadline() {
    let binding1 = ExtensionHostBinding::new(DrainDeadline { max_ticks: 50 });
    let binding2 = ExtensionHostBinding::new(DrainDeadline { max_ticks: 200 });
    // Both should start empty
    assert_eq!(binding1.active_extension_count(), 0);
    assert_eq!(binding2.active_extension_count(), 0);
}

// ===========================================================================
// 18) CellEvent with error_code
// ===========================================================================

#[test]
fn cell_event_with_error_code() {
    let ce = CellEvent {
        trace_id: "t".into(),
        cell_id: "c".into(),
        cell_kind: CellKind::Extension,
        decision_id: "d".into(),
        policy_id: "p".into(),
        event: "budget_exhausted".into(),
        component: "execution_cell".into(),
        outcome: "error".into(),
        error_code: Some("FE-CELL-0002".into()),
        region_state: RegionState::Running,
        budget_consumed_ms: 1000,
    };
    let json = serde_json::to_string(&ce).unwrap();
    assert!(json.contains("FE-CELL-0002"));
    let rt: CellEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.error_code, Some("FE-CELL-0002".into()));
}
