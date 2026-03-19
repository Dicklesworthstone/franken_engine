//! Enrichment integration tests for `extension_host_lifecycle` module.
//!
//! Covers: HostLifecycleError (7 variants + error_code), HostLifecycleEvent —
//! error Display all unique, error code strings unique, serde roundtrips,
//! Display content checks, std::error impl, event serde, event JSON field names.

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

use frankenengine_engine::extension_host_lifecycle::*;
use frankenengine_engine::region_lifecycle::RegionState;

// ── helpers ──────────────────────────────────────────────────────────────

fn all_error_variants() -> Vec<HostLifecycleError> {
    vec![
        HostLifecycleError::ExtensionAlreadyLoaded { extension_id: "ext-a".to_string() },
        HostLifecycleError::ExtensionNotFound { extension_id: "ext-b".to_string() },
        HostLifecycleError::ExtensionNotRunning { extension_id: "ext-c".to_string(), state: RegionState::Closed },
        HostLifecycleError::SessionAlreadyExists { extension_id: "ext-d".to_string(), session_id: "s1".to_string() },
        HostLifecycleError::SessionNotFound { extension_id: "ext-e".to_string(), session_id: "s2".to_string() },
        HostLifecycleError::CellError { extension_id: "ext-f".to_string(), error_code: "E001".to_string(), message: "cell failed".to_string() },
        HostLifecycleError::CancellationError { extension_id: "ext-g".to_string(), error_code: "C001".to_string(), message: "cancel failed".to_string() },
        HostLifecycleError::HostShuttingDown,
    ]
}

fn sample_event() -> HostLifecycleEvent {
    HostLifecycleEvent {
        trace_id: "t-1".to_string(),
        extension_id: "ext-a".to_string(),
        session_id: Some("s-1".to_string()),
        component: "extension_host_lifecycle".to_string(),
        event: "session_created".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    }
}

// ── test: error Display all unique ───────────────────────────────────────

#[test]
fn enrichment_error_display_all_unique() {
    let strs: BTreeSet<String> = all_error_variants().iter().map(|e| e.to_string()).collect();
    assert_eq!(strs.len(), 8, "all 8 variants must produce distinct Display strings");
}

// ── test: error Display non-empty ────────────────────────────────────────

#[test]
fn enrichment_error_display_non_empty() {
    for err in all_error_variants() {
        assert!(!err.to_string().is_empty(), "Display for {:?} should be non-empty", err);
    }
}

// ── test: error_code strings unique ──────────────────────────────────────

#[test]
fn enrichment_error_code_strings_unique() {
    let codes: BTreeSet<String> = all_error_variants().iter().map(|e| e.error_code().to_string()).collect();
    assert_eq!(codes.len(), 8);
}

// ── test: error_code starts with host_ ───────────────────────────────────

#[test]
fn enrichment_error_codes_start_with_host() {
    for err in all_error_variants() {
        assert!(err.error_code().starts_with("host_"), "code should start with host_: {}", err.error_code());
    }
}

// ── test: error_code stable values ───────────────────────────────────────

#[test]
fn enrichment_error_code_stable_values() {
    assert_eq!(HostLifecycleError::ExtensionAlreadyLoaded { extension_id: "x".to_string() }.error_code(), "host_extension_already_loaded");
    assert_eq!(HostLifecycleError::ExtensionNotFound { extension_id: "x".to_string() }.error_code(), "host_extension_not_found");
    assert_eq!(HostLifecycleError::ExtensionNotRunning { extension_id: "x".to_string(), state: RegionState::Closed }.error_code(), "host_extension_not_running");
    assert_eq!(HostLifecycleError::SessionAlreadyExists { extension_id: "x".to_string(), session_id: "s".to_string() }.error_code(), "host_session_already_exists");
    assert_eq!(HostLifecycleError::SessionNotFound { extension_id: "x".to_string(), session_id: "s".to_string() }.error_code(), "host_session_not_found");
    assert_eq!(HostLifecycleError::CellError { extension_id: "x".to_string(), error_code: "e".to_string(), message: "m".to_string() }.error_code(), "host_cell_error");
    assert_eq!(HostLifecycleError::CancellationError { extension_id: "x".to_string(), error_code: "e".to_string(), message: "m".to_string() }.error_code(), "host_cancellation_error");
    assert_eq!(HostLifecycleError::HostShuttingDown.error_code(), "host_shutting_down");
}

// ── test: error implements std::error::Error ─────────────────────────────

#[test]
fn enrichment_error_std_error_trait() {
    let err: Box<dyn std::error::Error> = Box::new(HostLifecycleError::HostShuttingDown);
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_none());
}

// ── test: error std::error for all variants ──────────────────────────────

#[test]
fn enrichment_error_std_error_all_variants() {
    for err in all_error_variants() {
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(!boxed.to_string().is_empty());
        assert!(boxed.source().is_none());
    }
}

// ── test: error Display content checks ───────────────────────────────────

#[test]
fn enrichment_error_display_extension_already_loaded() {
    let err = HostLifecycleError::ExtensionAlreadyLoaded { extension_id: "ext-abc".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("ext-abc"));
    assert!(msg.contains("already loaded"));
}

#[test]
fn enrichment_error_display_extension_not_found() {
    let err = HostLifecycleError::ExtensionNotFound { extension_id: "ext-xyz".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("ext-xyz"));
    assert!(msg.contains("not found"));
}

#[test]
fn enrichment_error_display_extension_not_running() {
    let err = HostLifecycleError::ExtensionNotRunning { extension_id: "ext-q".to_string(), state: RegionState::Closed };
    let msg = err.to_string();
    assert!(msg.contains("ext-q"));
    assert!(msg.contains("not running"));
}

#[test]
fn enrichment_error_display_session_already_exists() {
    let err = HostLifecycleError::SessionAlreadyExists { extension_id: "ext-a".to_string(), session_id: "s1".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("s1"));
    assert!(msg.contains("already exists"));
}

#[test]
fn enrichment_error_display_session_not_found() {
    let err = HostLifecycleError::SessionNotFound { extension_id: "ext-a".to_string(), session_id: "s-gone".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("s-gone"));
    assert!(msg.contains("not found"));
}

#[test]
fn enrichment_error_display_cell_error() {
    let err = HostLifecycleError::CellError { extension_id: "ext-x".to_string(), error_code: "E42".to_string(), message: "cell failed".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("ext-x"));
    assert!(msg.contains("E42"));
    assert!(msg.contains("cell failed"));
}

#[test]
fn enrichment_error_display_cancellation_error() {
    let err = HostLifecycleError::CancellationError { extension_id: "ext-y".to_string(), error_code: "C99".to_string(), message: "cancel failed".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("ext-y"));
    assert!(msg.contains("C99"));
    assert!(msg.contains("cancel failed"));
}

#[test]
fn enrichment_error_display_host_shutting_down() {
    let err = HostLifecycleError::HostShuttingDown;
    assert_eq!(err.to_string(), "host is shutting down");
}

// ── test: error serde roundtrip all 8 variants ───────────────────────────

#[test]
fn enrichment_error_serde_all_variants() {
    for err in all_error_variants() {
        let json = serde_json::to_string(&err).unwrap();
        let back: HostLifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ── test: error serde JSON variant keys distinct ─────────────────────────

#[test]
fn enrichment_error_serde_json_variant_keys_distinct() {
    let jsons: BTreeSet<String> = all_error_variants().iter().map(|e| serde_json::to_string(e).unwrap()).collect();
    assert_eq!(jsons.len(), 8);
}

// ── test: error Debug all distinct ───────────────────────────────────────

#[test]
fn enrichment_error_debug_all_distinct() {
    let debugs: BTreeSet<String> = all_error_variants().iter().map(|e| format!("{e:?}")).collect();
    assert_eq!(debugs.len(), 8);
}

// ── test: error Clone/Eq ─────────────────────────────────────────────────

#[test]
fn enrichment_error_clone_eq() {
    for err in all_error_variants() {
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }
}

// ── test: HostLifecycleEvent serde roundtrip ─────────────────────────────

#[test]
fn enrichment_event_serde_roundtrip() {
    let event = sample_event();
    let json = serde_json::to_string(&event).unwrap();
    let back: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ── test: event serde with None session_id ───────────────────────────────

#[test]
fn enrichment_event_serde_no_session() {
    let mut event = sample_event();
    event.session_id = None;
    let json = serde_json::to_string(&event).unwrap();
    let back: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert!(back.session_id.is_none());
}

// ── test: event serde with error_code ────────────────────────────────────

#[test]
fn enrichment_event_serde_with_error_code() {
    let mut event = sample_event();
    event.outcome = "error".to_string();
    event.error_code = Some("host_extension_not_found".to_string());
    let json = serde_json::to_string(&event).unwrap();
    let back: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.error_code.as_deref(), Some("host_extension_not_found"));
}

// ── test: event JSON field names ─────────────────────────────────────────

#[test]
fn enrichment_event_json_field_names() {
    let event = sample_event();
    let val = serde_json::to_value(&event).unwrap();
    let obj = val.as_object().unwrap();
    for key in ["trace_id", "extension_id", "session_id", "component", "event", "outcome", "error_code"] {
        assert!(obj.contains_key(key), "missing field: {key}");
    }
    assert_eq!(obj.len(), 7);
}

// ── test: event clone independence ───────────────────────────────────────

#[test]
fn enrichment_event_clone_independence() {
    let event = sample_event();
    let mut cloned = event.clone();
    cloned.trace_id = "modified".to_string();
    assert_ne!(event.trace_id, cloned.trace_id);
    assert_eq!(event.trace_id, "t-1");
}

// ── test: event Debug contains fields ────────────────────────────────────

#[test]
fn enrichment_event_debug_contains_fields() {
    let event = sample_event();
    let dbg = format!("{event:?}");
    assert!(dbg.contains("t-1"));
    assert!(dbg.contains("ext-a"));
    assert!(dbg.contains("session_created"));
}

// ── test: error with different extension_ids produce different Display ────

#[test]
fn enrichment_error_different_ids_different_display() {
    let e1 = HostLifecycleError::ExtensionNotFound { extension_id: "alpha".to_string() };
    let e2 = HostLifecycleError::ExtensionNotFound { extension_id: "beta".to_string() };
    assert_ne!(e1.to_string(), e2.to_string());
    assert!(e1.to_string().contains("alpha"));
    assert!(e2.to_string().contains("beta"));
}

// ── test: error with same variant same code ──────────────────────────────

#[test]
fn enrichment_error_same_variant_same_code() {
    let e1 = HostLifecycleError::ExtensionNotFound { extension_id: "a".to_string() };
    let e2 = HostLifecycleError::ExtensionNotFound { extension_id: "b".to_string() };
    assert_eq!(e1.error_code(), e2.error_code());
}

// ── test: error JSON field structure for struct variants ──────────────────

#[test]
fn enrichment_error_json_extension_already_loaded_fields() {
    let err = HostLifecycleError::ExtensionAlreadyLoaded { extension_id: "ext-z".to_string() };
    let val = serde_json::to_value(&err).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("ExtensionAlreadyLoaded"));
    let inner = obj["ExtensionAlreadyLoaded"].as_object().unwrap();
    assert!(inner.contains_key("extension_id"));
}

#[test]
fn enrichment_error_json_session_not_found_fields() {
    let err = HostLifecycleError::SessionNotFound { extension_id: "e".to_string(), session_id: "s".to_string() };
    let val = serde_json::to_value(&err).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("SessionNotFound"));
    let inner = obj["SessionNotFound"].as_object().unwrap();
    assert!(inner.contains_key("extension_id"));
    assert!(inner.contains_key("session_id"));
}

#[test]
fn enrichment_error_json_host_shutting_down_is_string() {
    let err = HostLifecycleError::HostShuttingDown;
    let val = serde_json::to_value(&err).unwrap();
    assert_eq!(val, serde_json::json!("HostShuttingDown"));
}

// ── test: event component field is always extension_host_lifecycle ────────

#[test]
fn enrichment_event_component_constant() {
    let event = sample_event();
    assert_eq!(event.component, "extension_host_lifecycle");
}

// ── test: HostLifecycleEvent default fields ──────────────────────────────

#[test]
fn enrichment_event_all_string_fields_non_empty() {
    let event = sample_event();
    assert!(!event.trace_id.is_empty());
    assert!(!event.extension_id.is_empty());
    assert!(!event.component.is_empty());
    assert!(!event.event.is_empty());
    assert!(!event.outcome.is_empty());
}
