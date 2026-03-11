#![forbid(unsafe_code)]

//! Integration tests for the `extension_host_lifecycle` module.
//!
//! These tests exercise the public API from outside the crate, covering:
//! - Every `HostLifecycleError` variant (construction, Display, error_code, serde)
//! - `HostLifecycleEvent` struct (construction, field access, serde round-trip)
//! - `ExtensionRecord` struct (construction, field access, serde round-trip)
//! - `ExtensionHostLifecycleManager` lifecycle state machine transitions
//! - Extension load/unload, session create/close
//! - Cancellation (quarantine, suspend, terminate, revocation)
//! - Host shutdown
//! - Query methods
//! - Determinism: same inputs produce same outputs
//! - Cross-concern integration with cancellation and cell managers

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

use frankenengine_engine::cancellation_lifecycle::LifecycleEvent;
use frankenengine_engine::control_plane::mocks::{MockBudget, MockCx};
use frankenengine_engine::extension_host_lifecycle::{
    ExtensionHostLifecycleManager, ExtensionRecord, HostLifecycleError, HostLifecycleEvent,
};
use frankenengine_engine::region_lifecycle::RegionState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mock_cx(budget_ms: u64) -> MockCx {
    MockCx::new(
        frankenengine_engine::control_plane::mocks::trace_id_from_seed(1),
        MockBudget::new(budget_ms),
    )
}

fn mock_cx_seed(seed: u64, budget_ms: u64) -> MockCx {
    MockCx::new(
        frankenengine_engine::control_plane::mocks::trace_id_from_seed(seed),
        MockBudget::new(budget_ms),
    )
}

// ===========================================================================
// HostLifecycleError — enum variant construction, Display, error_code, serde
// ===========================================================================

#[test]
fn error_extension_already_loaded_display_and_code() {
    let err = HostLifecycleError::ExtensionAlreadyLoaded {
        extension_id: "ext-dup".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("already loaded"));
    assert!(msg.contains("ext-dup"));
    assert_eq!(err.error_code(), "host_extension_already_loaded");
}

#[test]
fn error_extension_not_found_display_and_code() {
    let err = HostLifecycleError::ExtensionNotFound {
        extension_id: "ext-missing".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("not found"));
    assert!(msg.contains("ext-missing"));
    assert_eq!(err.error_code(), "host_extension_not_found");
}

#[test]
fn error_extension_not_running_display_and_code() {
    let err = HostLifecycleError::ExtensionNotRunning {
        extension_id: "ext-x".to_string(),
        state: RegionState::Closed,
    };
    let msg = format!("{err}");
    assert!(msg.contains("ext-x"));
    assert!(msg.contains("not running"));
    assert_eq!(err.error_code(), "host_extension_not_running");
}

#[test]
fn error_session_already_exists_display_and_code() {
    let err = HostLifecycleError::SessionAlreadyExists {
        extension_id: "ext-a".to_string(),
        session_id: "sess-1".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("sess-1"));
    assert!(msg.contains("already exists"));
    assert!(msg.contains("ext-a"));
    assert_eq!(err.error_code(), "host_session_already_exists");
}

#[test]
fn error_session_not_found_display_and_code() {
    let err = HostLifecycleError::SessionNotFound {
        extension_id: "ext-a".to_string(),
        session_id: "sess-gone".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("sess-gone"));
    assert!(msg.contains("not found"));
    assert_eq!(err.error_code(), "host_session_not_found");
}

#[test]
fn error_cell_error_display_and_code() {
    let err = HostLifecycleError::CellError {
        extension_id: "ext-b".to_string(),
        error_code: "cell_invalid".to_string(),
        message: "cell went wrong".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("cell error"));
    assert!(msg.contains("cell_invalid"));
    assert!(msg.contains("ext-b"));
    assert!(msg.contains("cell went wrong"));
    assert_eq!(err.error_code(), "host_cell_error");
}

#[test]
fn error_cancellation_error_display_and_code() {
    let err = HostLifecycleError::CancellationError {
        extension_id: "ext-c".to_string(),
        error_code: "cancel_fail".to_string(),
        message: "cancellation failed".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("cancellation error"));
    assert!(msg.contains("cancel_fail"));
    assert!(msg.contains("ext-c"));
    assert_eq!(err.error_code(), "host_cancellation_error");
}

#[test]
fn error_host_shutting_down_display_and_code() {
    let err = HostLifecycleError::HostShuttingDown;
    let msg = format!("{err}");
    assert!(msg.contains("shutting down"));
    assert_eq!(err.error_code(), "host_shutting_down");
}

#[test]
fn error_all_variants_error_codes_are_nonempty() {
    let variants = vec![
        HostLifecycleError::ExtensionAlreadyLoaded {
            extension_id: "x".to_string(),
        },
        HostLifecycleError::ExtensionNotFound {
            extension_id: "x".to_string(),
        },
        HostLifecycleError::ExtensionNotRunning {
            extension_id: "x".to_string(),
            state: RegionState::Running,
        },
        HostLifecycleError::SessionAlreadyExists {
            extension_id: "x".to_string(),
            session_id: "s".to_string(),
        },
        HostLifecycleError::SessionNotFound {
            extension_id: "x".to_string(),
            session_id: "s".to_string(),
        },
        HostLifecycleError::CellError {
            extension_id: "x".to_string(),
            error_code: "e".to_string(),
            message: "m".to_string(),
        },
        HostLifecycleError::CancellationError {
            extension_id: "x".to_string(),
            error_code: "e".to_string(),
            message: "m".to_string(),
        },
        HostLifecycleError::HostShuttingDown,
    ];
    for v in &variants {
        assert!(!v.error_code().is_empty(), "error_code must be non-empty");
        assert!(!format!("{v}").is_empty(), "Display must be non-empty");
    }
}

#[test]
fn error_all_variants_serde_roundtrip() {
    let variants = vec![
        HostLifecycleError::ExtensionAlreadyLoaded {
            extension_id: "ext-dup".to_string(),
        },
        HostLifecycleError::ExtensionNotFound {
            extension_id: "ext-missing".to_string(),
        },
        HostLifecycleError::ExtensionNotRunning {
            extension_id: "ext-x".to_string(),
            state: RegionState::Closed,
        },
        HostLifecycleError::SessionAlreadyExists {
            extension_id: "ext-a".to_string(),
            session_id: "s".to_string(),
        },
        HostLifecycleError::SessionNotFound {
            extension_id: "ext-a".to_string(),
            session_id: "s".to_string(),
        },
        HostLifecycleError::CellError {
            extension_id: "ext-b".to_string(),
            error_code: "cell_invalid".to_string(),
            message: "msg".to_string(),
        },
        HostLifecycleError::CancellationError {
            extension_id: "ext-c".to_string(),
            error_code: "cancel_fail".to_string(),
            message: "msg".to_string(),
        },
        HostLifecycleError::HostShuttingDown,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize error");
        let back: HostLifecycleError = serde_json::from_str(&json).expect("deserialize error");
        assert_eq!(*v, back);
    }
}

#[test]
fn error_all_error_codes_unique() {
    let variants: Vec<HostLifecycleError> = vec![
        HostLifecycleError::ExtensionAlreadyLoaded {
            extension_id: String::new(),
        },
        HostLifecycleError::ExtensionNotFound {
            extension_id: String::new(),
        },
        HostLifecycleError::ExtensionNotRunning {
            extension_id: String::new(),
            state: RegionState::Running,
        },
        HostLifecycleError::SessionAlreadyExists {
            extension_id: String::new(),
            session_id: String::new(),
        },
        HostLifecycleError::SessionNotFound {
            extension_id: String::new(),
            session_id: String::new(),
        },
        HostLifecycleError::CellError {
            extension_id: String::new(),
            error_code: String::new(),
            message: String::new(),
        },
        HostLifecycleError::CancellationError {
            extension_id: String::new(),
            error_code: String::new(),
            message: String::new(),
        },
        HostLifecycleError::HostShuttingDown,
    ];
    let codes: BTreeSet<&str> = variants.iter().map(|v| v.error_code()).collect();
    assert_eq!(
        codes.len(),
        variants.len(),
        "all error_codes must be unique"
    );
}

#[test]
fn error_extension_not_running_with_every_region_state() {
    let states = [
        RegionState::Running,
        RegionState::CancelRequested,
        RegionState::Draining,
        RegionState::Finalizing,
        RegionState::Closed,
    ];
    for state in &states {
        let err = HostLifecycleError::ExtensionNotRunning {
            extension_id: "ext".to_string(),
            state: *state,
        };
        let msg = format!("{err}");
        assert!(msg.contains("ext"), "Display should contain ext id");
        let json = serde_json::to_string(&err).unwrap();
        let back: HostLifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ===========================================================================
// HostLifecycleEvent — struct construction, field access, serde
// ===========================================================================

#[test]
fn host_lifecycle_event_construction_and_fields() {
    let event = HostLifecycleEvent {
        trace_id: "t-42".to_string(),
        extension_id: "ext-a".to_string(),
        session_id: Some("s-1".to_string()),
        component: "extension_host_lifecycle".to_string(),
        event: "session_created".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    assert_eq!(event.trace_id, "t-42");
    assert_eq!(event.extension_id, "ext-a");
    assert_eq!(event.session_id.as_deref(), Some("s-1"));
    assert_eq!(event.component, "extension_host_lifecycle");
    assert_eq!(event.event, "session_created");
    assert_eq!(event.outcome, "ok");
    assert!(event.error_code.is_none());
}

#[test]
fn host_lifecycle_event_with_error_code() {
    let event = HostLifecycleEvent {
        trace_id: "t".to_string(),
        extension_id: "ext-err".to_string(),
        session_id: None,
        component: "extension_host_lifecycle".to_string(),
        event: "extension_load_failed".to_string(),
        outcome: "error".to_string(),
        error_code: Some("host_extension_already_loaded".to_string()),
    };
    assert_eq!(
        event.error_code.as_deref(),
        Some("host_extension_already_loaded")
    );
    assert!(event.session_id.is_none());
}

#[test]
fn host_lifecycle_event_serde_roundtrip() {
    let event = HostLifecycleEvent {
        trace_id: "t".to_string(),
        extension_id: "ext-a".to_string(),
        session_id: Some("s".to_string()),
        component: "extension_host_lifecycle".to_string(),
        event: "session_created".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn host_lifecycle_event_serde_roundtrip_with_error_code() {
    let event = HostLifecycleEvent {
        trace_id: "t".to_string(),
        extension_id: "ext-a".to_string(),
        session_id: None,
        component: "extension_host_lifecycle".to_string(),
        event: "error".to_string(),
        outcome: "error".to_string(),
        error_code: Some("host_cell_error".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// ExtensionRecord — struct construction, field access, serde
// ===========================================================================

#[test]
fn extension_record_construction_and_fields() {
    let record = ExtensionRecord {
        cell_id: "ext-a".to_string(),
        sessions: BTreeSet::from(["s1".to_string(), "s2".to_string()]),
        load_trace_id: "trace-42".to_string(),
        unloaded: false,
    };
    assert_eq!(record.cell_id, "ext-a");
    assert_eq!(record.sessions.len(), 2);
    assert!(record.sessions.contains("s1"));
    assert!(record.sessions.contains("s2"));
    assert_eq!(record.load_trace_id, "trace-42");
    assert!(!record.unloaded);
}

#[test]
fn extension_record_empty_sessions() {
    let record = ExtensionRecord {
        cell_id: "ext-b".to_string(),
        sessions: BTreeSet::new(),
        load_trace_id: "t".to_string(),
        unloaded: true,
    };
    assert!(record.sessions.is_empty());
    assert!(record.unloaded);
}

#[test]
fn extension_record_serde_roundtrip() {
    let record = ExtensionRecord {
        cell_id: "ext-a".to_string(),
        sessions: BTreeSet::from(["s1".to_string(), "s2".to_string(), "s3".to_string()]),
        load_trace_id: "trace-1".to_string(),
        unloaded: false,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: ExtensionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn extension_record_serde_roundtrip_unloaded() {
    let record = ExtensionRecord {
        cell_id: "ext-gone".to_string(),
        sessions: BTreeSet::new(),
        load_trace_id: "trace-old".to_string(),
        unloaded: true,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: ExtensionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// ===========================================================================
// ExtensionHostLifecycleManager — construction and Default
// ===========================================================================

#[test]
fn manager_new_creates_empty_manager() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert_eq!(mgr.loaded_extension_count(), 0);
    assert!(!mgr.is_shutting_down());
    assert!(mgr.events().is_empty());
    assert!(mgr.extension_ids().is_empty());
    assert!(mgr.active_extension_ids().is_empty());
}

#[test]
fn manager_default_equals_new() {
    let mgr_new = ExtensionHostLifecycleManager::new();
    let mgr_default = ExtensionHostLifecycleManager::default();
    assert_eq!(
        mgr_new.loaded_extension_count(),
        mgr_default.loaded_extension_count()
    );
    assert_eq!(mgr_new.is_shutting_down(), mgr_default.is_shutting_down());
    assert_eq!(mgr_new.events().len(), mgr_default.events().len());
}

// ===========================================================================
// Extension load
// ===========================================================================

#[test]
fn load_extension_single() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    assert!(mgr.is_extension_running("ext-a"));
    assert_eq!(mgr.loaded_extension_count(), 1);
    assert_eq!(mgr.cell_manager().active_count(), 1);
}

#[test]
fn load_extension_multiple() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    for i in 0..5 {
        mgr.load_extension(&format!("ext-{i}"), &mut cx).unwrap();
    }
    assert_eq!(mgr.loaded_extension_count(), 5);
    assert_eq!(mgr.extension_ids().len(), 5);
}

#[test]
fn load_extension_duplicate_rejected() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let err = mgr.load_extension("ext-a", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_already_loaded");
    // Count unchanged
    assert_eq!(mgr.loaded_extension_count(), 1);
}

#[test]
fn load_extension_after_shutdown_rejected() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.shutdown(&mut cx);
    let err = mgr.load_extension("ext-b", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_shutting_down");
}

#[test]
fn load_extension_emits_event() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let events = mgr.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "extension_loaded");
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[0].extension_id, "ext-a");
    assert!(events[0].session_id.is_none());
    assert_eq!(events[0].component, "extension_host_lifecycle");
    assert!(!events[0].trace_id.is_empty());
}

// ===========================================================================
// Extension unload
// ===========================================================================

#[test]
fn unload_extension_success() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let outcome = mgr.unload_extension("ext-a", &mut cx).unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));
    assert_eq!(mgr.loaded_extension_count(), 0);
}

#[test]
fn unload_extension_missing_returns_not_found() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    let err = mgr.unload_extension("ext-missing", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_found");
}

#[test]
fn unload_extension_already_unloaded_returns_not_running() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();
    let err = mgr.unload_extension("ext-a", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_running");
}

#[test]
fn unload_extension_closes_sessions_first() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.create_session("ext-a", "s2", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-a"), 2);

    let outcome = mgr.unload_extension("ext-a", &mut cx).unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));
}

#[test]
fn unload_extension_clears_session_record() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.create_session("ext-a", "s2", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-a"), 2);

    let outcome = mgr.unload_extension("ext-a", &mut cx).unwrap();
    assert!(outcome.success);

    let record = mgr.extension_record("ext-a").unwrap();
    assert!(record.unloaded);
    assert!(record.sessions.is_empty());
    assert_eq!(mgr.session_count("ext-a"), 0);
}

#[test]
fn unload_extension_emits_event() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.drain_events(); // clear load event
    mgr.unload_extension("ext-a", &mut cx).unwrap();
    let events = mgr.events();
    assert!(!events.is_empty());
    let unload_event = events.iter().find(|e| e.event == "extension_unloaded");
    assert!(unload_event.is_some());
    let ev = unload_event.unwrap();
    assert_eq!(ev.extension_id, "ext-a");
    assert_eq!(ev.outcome, "ok");
}

#[test]
fn unload_one_extension_others_survive() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();
    mgr.load_extension("ext-c", &mut cx).unwrap();

    mgr.unload_extension("ext-b", &mut cx).unwrap();
    assert!(mgr.is_extension_running("ext-a"));
    assert!(!mgr.is_extension_running("ext-b"));
    assert!(mgr.is_extension_running("ext-c"));
    assert_eq!(mgr.loaded_extension_count(), 2);
}

// ===========================================================================
// Session create
// ===========================================================================

#[test]
fn create_session_success() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "sess-1", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-a"), 1);
}

#[test]
fn create_session_duplicate_rejected() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "sess-1", &mut cx).unwrap();
    let err = mgr.create_session("ext-a", "sess-1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_session_already_exists");
}

#[test]
fn create_session_on_missing_extension_fails() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    let err = mgr
        .create_session("ext-missing", "s1", &mut cx)
        .unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_found");
}

#[test]
fn create_session_on_unloaded_extension_fails() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();
    let err = mgr.create_session("ext-a", "s1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_running");
}

#[test]
fn create_session_after_shutdown_rejected() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.shutdown(&mut cx);
    let err = mgr.create_session("ext-a", "s1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_shutting_down");
}

#[test]
fn create_multiple_sessions_under_one_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    for i in 0..5 {
        mgr.create_session("ext-a", &format!("s{i}"), &mut cx)
            .unwrap();
    }
    assert_eq!(mgr.session_count("ext-a"), 5);
}

#[test]
fn create_session_emits_event() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.drain_events();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    let events = mgr.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "session_created");
    assert_eq!(events[0].extension_id, "ext-a");
    assert_eq!(events[0].session_id.as_deref(), Some("s1"));
    assert_eq!(events[0].outcome, "ok");
}

// ===========================================================================
// Session close
// ===========================================================================

#[test]
fn close_session_success() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    let outcome = mgr.close_session("ext-a", "s1", &mut cx).unwrap();
    assert!(outcome.success);
    assert_eq!(mgr.session_count("ext-a"), 0);
}

#[test]
fn close_session_not_found_returns_error() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let err = mgr
        .close_session("ext-a", "sess-gone", &mut cx)
        .unwrap_err();
    assert_eq!(err.error_code(), "host_session_not_found");
}

#[test]
fn close_session_extension_not_found_returns_error() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    let err = mgr.close_session("ext-missing", "s1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_found");
}

#[test]
fn close_session_emits_event() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.drain_events();
    mgr.close_session("ext-a", "s1", &mut cx).unwrap();
    let events = mgr.events();
    let close_ev = events.iter().find(|e| e.event == "session_closed");
    assert!(close_ev.is_some());
    let ev = close_ev.unwrap();
    assert_eq!(ev.extension_id, "ext-a");
    assert_eq!(ev.session_id.as_deref(), Some("s1"));
}

#[test]
fn close_one_session_others_survive() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.create_session("ext-a", "s2", &mut cx).unwrap();
    mgr.create_session("ext-a", "s3", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-a"), 3);

    mgr.close_session("ext-a", "s2", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-a"), 2);

    // s1 and s3 still there
    let record = mgr.extension_record("ext-a").unwrap();
    assert!(record.sessions.contains("s1"));
    assert!(!record.sessions.contains("s2"));
    assert!(record.sessions.contains("s3"));
}

// ===========================================================================
// Cancel extension — quarantine, suspend, terminate, revocation
// ===========================================================================

#[test]
fn cancel_extension_quarantine() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let outcome = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Quarantine)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));
}

#[test]
fn cancel_extension_suspend() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let outcome = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Suspend)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));
}

#[test]
fn cancel_extension_terminate() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let outcome = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));
}

#[test]
fn cancel_extension_revocation() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let outcome = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Revocation)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));
}

#[test]
fn cancel_extension_unload_event() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let outcome = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Unload)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));
}

#[test]
fn cancel_extension_with_sessions_closes_sessions() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.create_session("ext-a", "s2", &mut cx).unwrap();

    let outcome = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));
}

#[test]
fn cancel_missing_extension_returns_not_found() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    let err = mgr
        .cancel_extension("ext-missing", &mut cx, LifecycleEvent::Terminate)
        .unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_found");
}

#[test]
fn cancel_already_unloaded_extension_returns_not_running() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();
    let err = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Quarantine)
        .unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_running");
}

#[test]
fn cancel_one_extension_others_survive() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();

    mgr.cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
        .unwrap();
    assert!(!mgr.is_extension_running("ext-a"));
    assert!(mgr.is_extension_running("ext-b"));
}

#[test]
fn cancel_extension_emits_event_with_event_name() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.drain_events();
    mgr.cancel_extension("ext-a", &mut cx, LifecycleEvent::Quarantine)
        .unwrap();
    let events = mgr.events();
    let cancel_ev = events.iter().find(|e| e.event.starts_with("extension_"));
    assert!(cancel_ev.is_some());
}

// ===========================================================================
// Host shutdown
// ===========================================================================

#[test]
fn shutdown_cancels_all_extensions() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(30000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();
    mgr.load_extension("ext-c", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();

    let results = mgr.shutdown(&mut cx);
    assert_eq!(results.len(), 3);
    for r in &results {
        assert!(r.is_ok());
    }
    assert!(mgr.is_shutting_down());
    assert_eq!(mgr.loaded_extension_count(), 0);
}

#[test]
fn shutdown_empty_manager_succeeds() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    let results = mgr.shutdown(&mut cx);
    assert!(results.is_empty());
    assert!(mgr.is_shutting_down());
}

#[test]
fn shutdown_skips_already_unloaded_extensions() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();

    let results = mgr.shutdown(&mut cx);
    // Only ext-b should be cancelled (ext-a already unloaded)
    assert_eq!(results.len(), 1);
    assert!(results[0].is_ok());
}

#[test]
fn no_operations_after_shutdown() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.shutdown(&mut cx);

    // Load rejected
    let err = mgr.load_extension("ext-b", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_shutting_down");

    // Session create rejected
    let err = mgr.create_session("ext-a", "s1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_shutting_down");
}

#[test]
fn shutdown_emits_host_shutdown_event() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.drain_events();
    mgr.shutdown(&mut cx);
    let events = mgr.events();
    let shutdown_ev = events.iter().find(|e| e.event == "host_shutdown");
    assert!(shutdown_ev.is_some());
}

// ===========================================================================
// Query methods
// ===========================================================================

#[test]
fn is_extension_running_returns_false_for_nonexistent() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert!(!mgr.is_extension_running("nonexistent"));
}

#[test]
fn loaded_extension_count_excludes_unloaded() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();
    assert_eq!(mgr.loaded_extension_count(), 2);
    mgr.unload_extension("ext-a", &mut cx).unwrap();
    assert_eq!(mgr.loaded_extension_count(), 1);
}

#[test]
fn session_count_returns_zero_for_nonexistent_extension() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert_eq!(mgr.session_count("nonexistent"), 0);
}

#[test]
fn extension_ids_includes_unloaded() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();

    assert_eq!(mgr.extension_ids().len(), 2);
    assert_eq!(mgr.active_extension_ids().len(), 1);
    assert_eq!(mgr.active_extension_ids()[0], "ext-b");
}

#[test]
fn extension_ids_deterministic_order() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);
    // Load in non-alphabetical order
    mgr.load_extension("ext-c", &mut cx).unwrap();
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();

    // BTreeMap ensures sorted order
    let ids = mgr.extension_ids();
    assert_eq!(ids, vec!["ext-a", "ext-b", "ext-c"]);
}

#[test]
fn extension_record_accessible() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();

    let record = mgr.extension_record("ext-a").unwrap();
    assert_eq!(record.cell_id, "ext-a");
    assert!(!record.unloaded);
    assert!(record.sessions.contains("s1"));
    assert!(!record.load_trace_id.is_empty());
}

#[test]
fn extension_record_returns_none_for_nonexistent() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert!(mgr.extension_record("ext-missing").is_none());
}

#[test]
fn cell_manager_accessible() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    assert_eq!(mgr.cell_manager().active_count(), 1);
}

#[test]
fn cell_manager_mut_accessible() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    // Verify mutable access compiles and returns expected state
    let cell_mgr = mgr.cell_manager_mut();
    assert!(cell_mgr.get("ext-a").is_some());
}

// ===========================================================================
// Event draining
// ===========================================================================

#[test]
fn drain_events_clears_buffer() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    assert_eq!(mgr.events().len(), 1);

    let drained = mgr.drain_events();
    assert_eq!(drained.len(), 1);
    assert!(mgr.events().is_empty());
}

#[test]
fn drain_events_returns_empty_when_no_events() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let drained = mgr.drain_events();
    assert!(drained.is_empty());
}

#[test]
fn cancellation_events_accessible_after_unload() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();

    let cancel_events = mgr.drain_cancellation_events();
    assert!(!cancel_events.is_empty());
}

// ===========================================================================
// Determinism — same inputs produce same outputs
// ===========================================================================

#[test]
fn deterministic_event_sequence_single_extension() {
    let run = || {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(10000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();
        mgr.close_session("ext-a", "s1", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();
        mgr.drain_events()
    };

    let events1 = run();
    let events2 = run();
    assert_eq!(
        events1, events2,
        "identical inputs must produce identical events"
    );
}

#[test]
fn deterministic_event_sequence_multi_extension() {
    let run = || {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(30000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();
        mgr.create_session("ext-b", "s2", &mut cx).unwrap();
        mgr.cancel_extension("ext-a", &mut cx, LifecycleEvent::Quarantine)
            .unwrap();
        mgr.unload_extension("ext-b", &mut cx).unwrap();
        mgr.drain_events()
    };

    let events1 = run();
    let events2 = run();
    assert_eq!(events1, events2);
}

#[test]
fn deterministic_shutdown_sequence() {
    let run = || {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(30000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();
        mgr.shutdown(&mut cx);
        mgr.drain_events()
    };

    let events1 = run();
    let events2 = run();
    assert_eq!(events1, events2);
}

// ===========================================================================
// Full lifecycle integration
// ===========================================================================

#[test]
fn full_lifecycle_load_session_close_unload() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(30000);

    // Load two extensions
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();
    assert_eq!(mgr.loaded_extension_count(), 2);

    // Create sessions
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.create_session("ext-a", "s2", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-a"), 2);

    // Close one session
    let outcome = mgr.close_session("ext-a", "s1", &mut cx).unwrap();
    assert!(outcome.success);
    assert_eq!(mgr.session_count("ext-a"), 1);

    // Unload ext-a (session s2 closed automatically)
    let outcome = mgr.unload_extension("ext-a", &mut cx).unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));

    // ext-b still alive
    assert!(mgr.is_extension_running("ext-b"));

    // Unload ext-b
    let outcome = mgr.unload_extension("ext-b", &mut cx).unwrap();
    assert!(outcome.success);
    assert_eq!(mgr.loaded_extension_count(), 0);

    // Events cover the full lifecycle
    let events = mgr.events();
    assert!(events.len() >= 6);
}

#[test]
fn concurrent_extensions_no_cross_contamination() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(30000);

    for i in 0..5 {
        mgr.load_extension(&format!("ext-{i}"), &mut cx).unwrap();
    }
    assert_eq!(mgr.loaded_extension_count(), 5);

    // Create sessions in different extensions
    mgr.create_session("ext-0", "s0", &mut cx).unwrap();
    mgr.create_session("ext-2", "s2a", &mut cx).unwrap();
    mgr.create_session("ext-2", "s2b", &mut cx).unwrap();

    // Terminate ext-2 with sessions
    mgr.cancel_extension("ext-2", &mut cx, LifecycleEvent::Terminate)
        .unwrap();

    // ext-0 still has its session
    assert_eq!(mgr.session_count("ext-0"), 1);
    assert!(mgr.is_extension_running("ext-0"));

    // Other extensions still running
    for i in [0, 1, 3, 4] {
        assert!(mgr.is_extension_running(&format!("ext-{i}")));
    }
    assert!(!mgr.is_extension_running("ext-2"));
}

#[test]
fn lifecycle_events_have_trace_id_and_component() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();

    for event in mgr.events() {
        assert!(!event.trace_id.is_empty(), "trace_id must be present");
        assert_eq!(
            event.component, "extension_host_lifecycle",
            "component must be extension_host_lifecycle"
        );
    }
}

#[test]
fn extension_record_reflects_session_lifecycle() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);
    mgr.load_extension("ext-a", &mut cx).unwrap();

    let record = mgr.extension_record("ext-a").unwrap();
    assert!(record.sessions.is_empty());
    assert!(!record.unloaded);

    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.create_session("ext-a", "s2", &mut cx).unwrap();
    let record = mgr.extension_record("ext-a").unwrap();
    assert_eq!(record.sessions.len(), 2);

    mgr.close_session("ext-a", "s1", &mut cx).unwrap();
    let record = mgr.extension_record("ext-a").unwrap();
    assert_eq!(record.sessions.len(), 1);
    assert!(!record.sessions.contains("s1"));
    assert!(record.sessions.contains("s2"));

    mgr.unload_extension("ext-a", &mut cx).unwrap();
    let record = mgr.extension_record("ext-a").unwrap();
    assert!(record.unloaded);
}

#[test]
fn different_trace_ids_for_different_cx_seeds() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx1 = mock_cx_seed(1, 5000);
    let mut cx2 = mock_cx_seed(2, 5000);

    mgr.load_extension("ext-a", &mut cx1).unwrap();
    mgr.load_extension("ext-b", &mut cx2).unwrap();

    let events = mgr.events();
    assert_eq!(events.len(), 2);
    // Different seeds produce different trace ids
    assert_ne!(events[0].trace_id, events[1].trace_id);
}

// ===========================================================================
// Cross-concern: cancellation manager integration
// ===========================================================================

#[test]
fn cancellation_events_emitted_on_unload() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();

    let cancel_events = mgr.drain_cancellation_events();
    assert!(
        !cancel_events.is_empty(),
        "cancellation events should be emitted on unload"
    );
}

#[test]
fn cancellation_events_emitted_on_cancel() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.cancel_extension("ext-a", &mut cx, LifecycleEvent::Quarantine)
        .unwrap();

    let cancel_events = mgr.drain_cancellation_events();
    assert!(!cancel_events.is_empty());
}

#[test]
fn cancellation_events_emitted_on_shutdown() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.shutdown(&mut cx);

    let cancel_events = mgr.drain_cancellation_events();
    assert!(!cancel_events.is_empty());
}

#[test]
fn cancellation_events_drain_is_idempotent() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();

    let first_drain = mgr.drain_cancellation_events();
    assert!(!first_drain.is_empty());

    let second_drain = mgr.drain_cancellation_events();
    assert!(second_drain.is_empty(), "second drain should be empty");
}

// ===========================================================================
// Cross-concern: cell manager integration
// ===========================================================================

#[test]
fn cell_manager_tracks_extension_cells() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();

    assert_eq!(mgr.cell_manager().active_count(), 2);
    assert!(mgr.cell_manager().get("ext-a").is_some());
    assert!(mgr.cell_manager().get("ext-b").is_some());
}

#[test]
fn cell_manager_tracks_session_cells() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();

    // Session cell ID is deterministic: ext-a::session::s1
    let session_cell = mgr.cell_manager().get("ext-a::session::s1");
    assert!(
        session_cell.is_some(),
        "session cell should be registered in cell manager"
    );
}

#[test]
fn cell_manager_archives_cells_on_unload() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();

    assert!(mgr.cell_manager().get("ext-a").is_some());
    mgr.unload_extension("ext-a", &mut cx).unwrap();

    // After archival, cell may no longer be in active cells
    assert_eq!(mgr.cell_manager().active_count(), 0);
}

// ===========================================================================
// Edge cases and boundary conditions
// ===========================================================================

#[test]
fn empty_string_extension_id_works() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    // Empty string is a valid key in BTreeMap
    mgr.load_extension("", &mut cx).unwrap();
    assert!(mgr.is_extension_running(""));
    assert_eq!(mgr.loaded_extension_count(), 1);
}

#[test]
fn long_extension_id_works() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    let long_id = "a".repeat(1000);
    mgr.load_extension(&long_id, &mut cx).unwrap();
    assert!(mgr.is_extension_running(&long_id));
}

#[test]
fn unicode_extension_id_works() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("\u{1F600}-ext", &mut cx).unwrap();
    assert!(mgr.is_extension_running("\u{1F600}-ext"));
}

#[test]
fn session_count_nonexistent_returns_zero() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert_eq!(mgr.session_count("nonexistent"), 0);
}

#[test]
fn extension_record_after_cancel_shows_unloaded() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
        .unwrap();

    let record = mgr.extension_record("ext-a").unwrap();
    assert!(record.unloaded);
}

#[test]
fn cancel_extension_clears_sessions_in_record() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.create_session("ext-a", "s2", &mut cx).unwrap();

    mgr.cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
        .unwrap();

    let record = mgr.extension_record("ext-a").unwrap();
    assert!(record.sessions.is_empty(), "cancel should clear sessions");
}

#[test]
fn multiple_shutdowns_do_not_panic() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();

    let results1 = mgr.shutdown(&mut cx);
    assert_eq!(results1.len(), 1);

    // Second shutdown — all extensions already unloaded
    let results2 = mgr.shutdown(&mut cx);
    assert!(results2.is_empty());
}

// ===========================================================================
// Serde round-trip for CancellationOutcome (cross-concern)
// ===========================================================================

#[test]
fn cancellation_outcome_from_unload_is_serdeable() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let outcome = mgr.unload_extension("ext-a", &mut cx).unwrap();

    let json = serde_json::to_string(&outcome).unwrap();
    let back: frankenengine_engine::cancellation_lifecycle::CancellationOutcome =
        serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

#[test]
fn cancellation_outcome_from_cancel_is_serdeable() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let outcome = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Quarantine)
        .unwrap();

    let json = serde_json::to_string(&outcome).unwrap();
    let back: frankenengine_engine::cancellation_lifecycle::CancellationOutcome =
        serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

// ===========================================================================
// Lifecycle events cover all operation types
// ===========================================================================

#[test]
fn lifecycle_events_cover_all_operations() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(50000);

    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.close_session("ext-a", "s1", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();

    mgr.load_extension("ext-b", &mut cx).unwrap();
    mgr.cancel_extension("ext-b", &mut cx, LifecycleEvent::Quarantine)
        .unwrap();

    mgr.load_extension("ext-c", &mut cx).unwrap();
    mgr.shutdown(&mut cx);

    let events = mgr.drain_events();
    let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();

    assert!(event_names.contains(&"extension_loaded"));
    assert!(event_names.contains(&"session_created"));
    assert!(event_names.contains(&"session_closed"));
    assert!(event_names.contains(&"extension_unloaded"));
    assert!(event_names.contains(&"host_shutdown"));
}

#[test]
fn all_lifecycle_events_are_serdeable() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(30000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.close_session("ext-a", "s1", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();

    for event in mgr.events() {
        let json = serde_json::to_string(event).expect("serialize lifecycle event");
        let back: HostLifecycleEvent =
            serde_json::from_str(&json).expect("deserialize lifecycle event");
        assert_eq!(*event, back);
    }
}

// ===========================================================================
// Stress / scale scenarios
// ===========================================================================

#[test]
fn many_extensions_load_and_shutdown() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1_000_000);

    let count = 50;
    for i in 0..count {
        mgr.load_extension(&format!("ext-{i}"), &mut cx).unwrap();
    }
    assert_eq!(mgr.loaded_extension_count(), count);

    let results = mgr.shutdown(&mut cx);
    assert_eq!(results.len(), count);
    for r in &results {
        assert!(r.is_ok());
    }
    assert_eq!(mgr.loaded_extension_count(), 0);
}

#[test]
fn many_sessions_per_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1_000_000);
    mgr.load_extension("ext-a", &mut cx).unwrap();

    let session_count = 20;
    for i in 0..session_count {
        mgr.create_session("ext-a", &format!("s{i}"), &mut cx)
            .unwrap();
    }
    assert_eq!(mgr.session_count("ext-a"), session_count);

    // Close half
    for i in 0..session_count / 2 {
        mgr.close_session("ext-a", &format!("s{i}"), &mut cx)
            .unwrap();
    }
    assert_eq!(mgr.session_count("ext-a"), session_count / 2);

    // Unload closes the rest
    let outcome = mgr.unload_extension("ext-a", &mut cx).unwrap();
    assert!(outcome.success);
}

// ===========================================================================
// Interleaved operations
// ===========================================================================

#[test]
fn interleaved_load_unload_load() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(20000);

    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();

    // Re-loading with the same ID should fail because the record still exists
    // (extension_id still in BTreeMap, marked as unloaded but key present)
    let result = mgr.load_extension("ext-a", &mut cx);
    // The manager keeps the old record, so this triggers ExtensionAlreadyLoaded
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().error_code(),
        "host_extension_already_loaded"
    );
}

#[test]
fn session_interleave_across_extensions() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(30000);

    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();

    // Same session ID in different extensions should work
    mgr.create_session("ext-a", "shared-name", &mut cx).unwrap();
    mgr.create_session("ext-b", "shared-name", &mut cx).unwrap();

    assert_eq!(mgr.session_count("ext-a"), 1);
    assert_eq!(mgr.session_count("ext-b"), 1);

    // Close one, other unaffected
    mgr.close_session("ext-a", "shared-name", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-a"), 0);
    assert_eq!(mgr.session_count("ext-b"), 1);
}
