#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

//! Enrichment integration tests for the `extension_host_lifecycle` module.
//!
//! Covers: serde roundtrips, Display distinctness, error_code consistency,
//! Default implementation, lifecycle state machine edge cases, session
//! management, cancellation paths, shutdown behavior, query methods,
//! event tracking, and deterministic behavior.

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
// HostLifecycleError — serde roundtrip
// ===========================================================================

#[test]
fn enrichment_error_serde_roundtrip_all_variants() {
    let variants = vec![
        HostLifecycleError::ExtensionAlreadyLoaded {
            extension_id: "ext-a".to_string(),
        },
        HostLifecycleError::ExtensionNotFound {
            extension_id: "ext-b".to_string(),
        },
        HostLifecycleError::ExtensionNotRunning {
            extension_id: "ext-c".to_string(),
            state: RegionState::Closed,
        },
        HostLifecycleError::SessionAlreadyExists {
            extension_id: "ext-d".to_string(),
            session_id: "sess-1".to_string(),
        },
        HostLifecycleError::SessionNotFound {
            extension_id: "ext-e".to_string(),
            session_id: "sess-2".to_string(),
        },
        HostLifecycleError::CellError {
            extension_id: "ext-f".to_string(),
            error_code: "code".to_string(),
            message: "msg".to_string(),
        },
        HostLifecycleError::CancellationError {
            extension_id: "ext-g".to_string(),
            error_code: "cancel_code".to_string(),
            message: "cancel_msg".to_string(),
        },
        HostLifecycleError::HostShuttingDown,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: HostLifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// HostLifecycleError — Display distinctness
// ===========================================================================

#[test]
fn enrichment_error_display_all_distinct() {
    let displays: Vec<String> = vec![
        HostLifecycleError::ExtensionAlreadyLoaded {
            extension_id: "ext-a".to_string(),
        }
        .to_string(),
        HostLifecycleError::ExtensionNotFound {
            extension_id: "ext-b".to_string(),
        }
        .to_string(),
        HostLifecycleError::ExtensionNotRunning {
            extension_id: "ext-c".to_string(),
            state: RegionState::Closed,
        }
        .to_string(),
        HostLifecycleError::SessionAlreadyExists {
            extension_id: "ext-d".to_string(),
            session_id: "sess-1".to_string(),
        }
        .to_string(),
        HostLifecycleError::SessionNotFound {
            extension_id: "ext-e".to_string(),
            session_id: "sess-2".to_string(),
        }
        .to_string(),
        HostLifecycleError::CellError {
            extension_id: "ext-f".to_string(),
            error_code: "code".to_string(),
            message: "msg".to_string(),
        }
        .to_string(),
        HostLifecycleError::CancellationError {
            extension_id: "ext-g".to_string(),
            error_code: "cancel_code".to_string(),
            message: "cancel_msg".to_string(),
        }
        .to_string(),
        HostLifecycleError::HostShuttingDown.to_string(),
    ];
    let set: BTreeSet<&str> = displays.iter().map(String::as_str).collect();
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_error_display_contains_extension_id() {
    let err = HostLifecycleError::ExtensionAlreadyLoaded {
        extension_id: "my-ext-123".to_string(),
    };
    assert!(err.to_string().contains("my-ext-123"));
}

#[test]
fn enrichment_error_display_contains_session_id() {
    let err = HostLifecycleError::SessionNotFound {
        extension_id: "ext".to_string(),
        session_id: "sess-42".to_string(),
    };
    assert!(err.to_string().contains("sess-42"));
}

#[test]
fn enrichment_error_display_host_shutting_down() {
    let err = HostLifecycleError::HostShuttingDown;
    assert!(err.to_string().contains("shutting down"));
}

// ===========================================================================
// HostLifecycleError — error_code consistency
// ===========================================================================

#[test]
fn enrichment_error_codes_all_distinct() {
    let e1 = HostLifecycleError::ExtensionAlreadyLoaded {
        extension_id: "a".to_string(),
    };
    let e2 = HostLifecycleError::ExtensionNotFound {
        extension_id: "b".to_string(),
    };
    let e3 = HostLifecycleError::ExtensionNotRunning {
        extension_id: "c".to_string(),
        state: RegionState::Closed,
    };
    let e4 = HostLifecycleError::SessionAlreadyExists {
        extension_id: "d".to_string(),
        session_id: "s".to_string(),
    };
    let e5 = HostLifecycleError::SessionNotFound {
        extension_id: "e".to_string(),
        session_id: "s".to_string(),
    };
    let e6 = HostLifecycleError::CellError {
        extension_id: "f".to_string(),
        error_code: "c".to_string(),
        message: "m".to_string(),
    };
    let e7 = HostLifecycleError::CancellationError {
        extension_id: "g".to_string(),
        error_code: "c".to_string(),
        message: "m".to_string(),
    };
    let e8 = HostLifecycleError::HostShuttingDown;
    let codes: Vec<&str> = vec![
        e1.error_code(),
        e2.error_code(),
        e3.error_code(),
        e4.error_code(),
        e5.error_code(),
        e6.error_code(),
        e7.error_code(),
        e8.error_code(),
    ];
    let set: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_error_codes_have_host_prefix() {
    let err = HostLifecycleError::ExtensionAlreadyLoaded {
        extension_id: "x".to_string(),
    };
    assert!(err.error_code().starts_with("host_"));
}

// ===========================================================================
// HostLifecycleEvent — serde
// ===========================================================================

#[test]
fn enrichment_lifecycle_event_serde_roundtrip() {
    let event = HostLifecycleEvent {
        trace_id: "tr-1".to_string(),
        extension_id: "ext-a".to_string(),
        session_id: Some("sess-1".to_string()),
        component: "extension_host_lifecycle".to_string(),
        event: "extension_loaded".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_lifecycle_event_with_error_code_serde() {
    let event = HostLifecycleEvent {
        trace_id: "tr-2".to_string(),
        extension_id: "ext-b".to_string(),
        session_id: None,
        component: "extension_host_lifecycle".to_string(),
        event: "extension_unloaded".to_string(),
        outcome: "error".to_string(),
        error_code: Some("host_extension_not_found".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_lifecycle_event_fields_accessible() {
    let event = HostLifecycleEvent {
        trace_id: "t".to_string(),
        extension_id: "e".to_string(),
        session_id: Some("s".to_string()),
        component: "c".to_string(),
        event: "ev".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    assert_eq!(event.trace_id, "t");
    assert_eq!(event.extension_id, "e");
    assert_eq!(event.session_id.as_deref(), Some("s"));
    assert_eq!(event.component, "c");
}

// ===========================================================================
// ExtensionRecord — serde
// ===========================================================================

#[test]
fn enrichment_extension_record_serde_roundtrip() {
    let record = ExtensionRecord {
        cell_id: "ext-a".to_string(),
        sessions: {
            let mut s = BTreeSet::new();
            s.insert("sess-1".to_string());
            s.insert("sess-2".to_string());
            s
        },
        load_trace_id: "trace-load".to_string(),
        unloaded: false,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: ExtensionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn enrichment_extension_record_fields_accessible() {
    let record = ExtensionRecord {
        cell_id: "c".to_string(),
        sessions: BTreeSet::new(),
        load_trace_id: "t".to_string(),
        unloaded: true,
    };
    assert_eq!(record.cell_id, "c");
    assert!(record.sessions.is_empty());
    assert_eq!(record.load_trace_id, "t");
    assert!(record.unloaded);
}

// ===========================================================================
// ExtensionHostLifecycleManager — Default
// ===========================================================================

#[test]
fn enrichment_manager_default_is_empty() {
    let mgr = ExtensionHostLifecycleManager::default();
    assert_eq!(mgr.loaded_extension_count(), 0);
    assert!(!mgr.is_shutting_down());
    assert!(mgr.extension_ids().is_empty());
    assert!(mgr.active_extension_ids().is_empty());
    assert!(mgr.events().is_empty());
}

#[test]
fn enrichment_manager_new_equals_default() {
    let mgr1 = ExtensionHostLifecycleManager::new();
    let mgr2 = ExtensionHostLifecycleManager::default();
    assert_eq!(mgr1.loaded_extension_count(), mgr2.loaded_extension_count());
    assert_eq!(mgr1.is_shutting_down(), mgr2.is_shutting_down());
}

// ===========================================================================
// Manager — load/unload lifecycle
// ===========================================================================

#[test]
fn enrichment_load_and_verify_extension_record() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let record = mgr.extension_record("ext-a").unwrap();
    assert_eq!(record.cell_id, "ext-a");
    assert!(!record.unloaded);
    assert!(record.sessions.is_empty());
}

#[test]
fn enrichment_load_multiple_extensions() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    for i in 0..5 {
        mgr.load_extension(&format!("ext-{i}"), &mut cx).unwrap();
    }
    assert_eq!(mgr.loaded_extension_count(), 5);
    assert_eq!(mgr.extension_ids().len(), 5);
    assert_eq!(mgr.active_extension_ids().len(), 5);
}

#[test]
fn enrichment_unload_marks_extension_as_not_running() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();
    assert!(!mgr.is_extension_running("ext-a"));
    // Extension still in extension_ids (for audit trail)
    assert!(mgr.extension_ids().contains(&"ext-a"));
    // But not in active_extension_ids
    assert!(!mgr.active_extension_ids().contains(&"ext-a"));
}

#[test]
fn enrichment_unload_nonexistent_returns_not_found() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    let err = mgr.unload_extension("nonexistent", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_found");
}

#[test]
fn enrichment_double_unload_returns_not_running() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();
    let err = mgr.unload_extension("ext-a", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_running");
}

// ===========================================================================
// Manager — session lifecycle
// ===========================================================================

#[test]
fn enrichment_create_session_increments_count() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "sess-1", &mut cx).unwrap();
    mgr.create_session("ext-a", "sess-2", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-a"), 2);
}

#[test]
fn enrichment_create_duplicate_session_rejected() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "sess-1", &mut cx).unwrap();
    let err = mgr.create_session("ext-a", "sess-1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_session_already_exists");
}

#[test]
fn enrichment_create_session_on_nonexistent_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    let err = mgr.create_session("no-ext", "sess-1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_found");
}

#[test]
fn enrichment_create_session_on_unloaded_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();
    let err = mgr.create_session("ext-a", "sess-1", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_running");
}

#[test]
fn enrichment_close_session_removes_from_record() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "sess-1", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-a"), 1);
    mgr.close_session("ext-a", "sess-1", &mut cx).unwrap();
    assert_eq!(mgr.session_count("ext-a"), 0);
}

#[test]
fn enrichment_close_nonexistent_session() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let err = mgr.close_session("ext-a", "no-sess", &mut cx).unwrap_err();
    assert_eq!(err.error_code(), "host_session_not_found");
}

#[test]
fn enrichment_session_count_zero_for_nonexistent_extension() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert_eq!(mgr.session_count("no-ext"), 0);
}

// ===========================================================================
// Manager — cancellation
// ===========================================================================

#[test]
fn enrichment_cancel_extension_marks_unloaded() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let outcome = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));
}

#[test]
fn enrichment_cancel_extension_with_sessions_cancels_all() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "s1", &mut cx).unwrap();
    mgr.create_session("ext-a", "s2", &mut cx).unwrap();
    let outcome = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Quarantine)
        .unwrap();
    assert!(outcome.success);
    assert!(!mgr.is_extension_running("ext-a"));
    assert_eq!(mgr.session_count("ext-a"), 0);
}

#[test]
fn enrichment_cancel_nonexistent_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    let err = mgr
        .cancel_extension("no-ext", &mut cx, LifecycleEvent::Terminate)
        .unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_found");
}

#[test]
fn enrichment_cancel_already_unloaded_extension() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();
    let err = mgr
        .cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
        .unwrap_err();
    assert_eq!(err.error_code(), "host_extension_not_running");
}

// ===========================================================================
// Manager — shutdown
// ===========================================================================

#[test]
fn enrichment_shutdown_cancels_all_extensions() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(10000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.load_extension("ext-b", &mut cx).unwrap();
    mgr.load_extension("ext-c", &mut cx).unwrap();
    let results = mgr.shutdown(&mut cx);
    assert_eq!(results.len(), 3);
    for r in &results {
        assert!(r.is_ok());
    }
    assert!(mgr.is_shutting_down());
    assert_eq!(mgr.loaded_extension_count(), 0);
}

#[test]
fn enrichment_shutdown_empty_manager() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    let results = mgr.shutdown(&mut cx);
    assert!(results.is_empty());
    assert!(mgr.is_shutting_down());
}

#[test]
fn enrichment_load_after_shutdown_rejected() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.shutdown(&mut cx);
    let err = mgr.load_extension("ext-a", &mut cx).unwrap_err();
    assert!(matches!(err, HostLifecycleError::HostShuttingDown));
}

#[test]
fn enrichment_create_session_after_shutdown_rejected() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.shutdown(&mut cx);
    let err = mgr.create_session("ext-a", "sess", &mut cx).unwrap_err();
    // Extension was cancelled during shutdown so it's not running
    assert!(
        matches!(err, HostLifecycleError::HostShuttingDown)
            || matches!(err, HostLifecycleError::ExtensionNotRunning { .. })
    );
}

// ===========================================================================
// Manager — events
// ===========================================================================

#[test]
fn enrichment_events_recorded_for_load() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let events = mgr.events();
    assert!(!events.is_empty());
    assert!(events.iter().any(|e| e.event == "extension_loaded"));
}

#[test]
fn enrichment_events_recorded_for_unload() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.unload_extension("ext-a", &mut cx).unwrap();
    assert!(mgr.events().iter().any(|e| e.event == "extension_unloaded"));
}

#[test]
fn enrichment_events_recorded_for_session_create() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "sess-1", &mut cx).unwrap();
    assert!(mgr.events().iter().any(|e| e.event == "session_created"));
}

#[test]
fn enrichment_events_recorded_for_session_close() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    mgr.create_session("ext-a", "sess-1", &mut cx).unwrap();
    mgr.close_session("ext-a", "sess-1", &mut cx).unwrap();
    assert!(mgr.events().iter().any(|e| e.event == "session_closed"));
}

#[test]
fn enrichment_drain_events_clears_list() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(5000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    let drained = mgr.drain_events();
    assert!(!drained.is_empty());
    assert!(mgr.events().is_empty());
}

#[test]
fn enrichment_events_have_component_field() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    for event in mgr.events() {
        assert_eq!(event.component, "extension_host_lifecycle");
    }
}

// ===========================================================================
// Manager — query methods
// ===========================================================================

#[test]
fn enrichment_is_extension_running_false_for_nonexistent() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert!(!mgr.is_extension_running("does-not-exist"));
}

#[test]
fn enrichment_extension_record_none_for_nonexistent() {
    let mgr = ExtensionHostLifecycleManager::new();
    assert!(mgr.extension_record("no-ext").is_none());
}

#[test]
fn enrichment_cell_manager_accessible() {
    let mut mgr = ExtensionHostLifecycleManager::new();
    let mut cx = mock_cx(1000);
    mgr.load_extension("ext-a", &mut cx).unwrap();
    // cell_manager should have at least one cell
    assert!(mgr.cell_manager().active_count() >= 1);
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn enrichment_deterministic_load_unload_cycle() {
    let run = || {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(10000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();
        mgr.close_session("ext-a", "s1", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();
        (
            mgr.loaded_extension_count(),
            mgr.is_extension_running("ext-a"),
            mgr.is_extension_running("ext-b"),
        )
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_deterministic_shutdown_produces_same_results() {
    let run = || {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(10000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();
        let results = mgr.shutdown(&mut cx);
        results.len()
    };
    assert_eq!(run(), run());
}
