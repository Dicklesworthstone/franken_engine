#![forbid(unsafe_code)]
#![allow(clippy::field_reassign_with_default)]

//! Enrichment integration tests for the `evidence_emission` module.
//!
//! Tests types that can be exercised without a `ContextAdapter` mock:
//! serde round-trips, Display, ActionCategory, EvidenceEntryId,
//! EmitterConfig, EvidenceEmissionError, and CanonicalEvidenceEmitter
//! construction / state queries.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::evidence_emission::{
    ActionCategory, CanonicalEvidenceEmitter, EmitterConfig, EvidenceEmissionError,
    EvidenceEmissionEvent, EvidenceEmissionRequest, EvidenceEntryId,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// ActionCategory — variants, ALL, as_str, Display, serde
// ---------------------------------------------------------------------------

#[test]
fn action_category_all_has_six_variants() {
    assert_eq!(ActionCategory::ALL.len(), 6);
}

#[test]
fn action_category_as_str_matches_display() {
    for cat in &ActionCategory::ALL {
        assert_eq!(cat.as_str(), cat.to_string());
    }
}

#[test]
fn action_category_as_str_values() {
    assert_eq!(ActionCategory::DecisionContract.as_str(), "decision_contract");
    assert_eq!(ActionCategory::RegionLifecycle.as_str(), "region_lifecycle");
    assert_eq!(ActionCategory::Cancellation.as_str(), "cancellation");
    assert_eq!(ActionCategory::ObligationLifecycle.as_str(), "obligation_lifecycle");
    assert_eq!(ActionCategory::ExtensionLifecycle.as_str(), "extension_lifecycle");
    assert_eq!(ActionCategory::ContainmentAction.as_str(), "containment_action");
}

#[test]
fn action_category_all_display_strings_are_unique() {
    let set: BTreeSet<String> = ActionCategory::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn action_category_serde_roundtrip_all_variants() {
    for cat in &ActionCategory::ALL {
        let json = serde_json::to_string(cat).unwrap();
        let back: ActionCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

#[test]
fn action_category_deterministic_serialization() {
    for cat in &ActionCategory::ALL {
        let a = serde_json::to_string(cat).unwrap();
        let b = serde_json::to_string(cat).unwrap();
        assert_eq!(a, b);
    }
}

#[test]
fn action_category_ordering_is_stable() {
    let mut cats = ActionCategory::ALL.to_vec();
    cats.sort();
    assert_eq!(cats, ActionCategory::ALL.to_vec());
}

#[test]
fn action_category_copy_semantics() {
    let a = ActionCategory::ContainmentAction;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.as_str(), b.as_str());
}

#[test]
fn action_category_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for cat in &ActionCategory::ALL {
        assert!(set.insert(*cat));
    }
    assert!(!set.insert(ActionCategory::DecisionContract));
    assert_eq!(set.len(), 6);
}

// ---------------------------------------------------------------------------
// EvidenceEntryId — creation, Display, serde
// ---------------------------------------------------------------------------

#[test]
fn evidence_entry_id_new_and_as_str() {
    let id = EvidenceEntryId::new("ev-42");
    assert_eq!(id.as_str(), "ev-42");
}

#[test]
fn evidence_entry_id_display() {
    let id = EvidenceEntryId::new("ev-test-display");
    assert_eq!(id.to_string(), "ev-test-display");
}

#[test]
fn evidence_entry_id_empty_string() {
    let id = EvidenceEntryId::new("");
    assert_eq!(id.as_str(), "");
    assert_eq!(id.to_string(), "");
}

#[test]
fn evidence_entry_id_serde_roundtrip() {
    let id = EvidenceEntryId::new("ev-serde-test");
    let json = serde_json::to_string(&id).unwrap();
    let back: EvidenceEntryId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn evidence_entry_id_clone_equality() {
    let id = EvidenceEntryId::new("ev-clone");
    let cloned = id.clone();
    assert_eq!(id, cloned);
    assert_eq!(id.as_str(), cloned.as_str());
}

#[test]
fn evidence_entry_id_ord_in_btreeset() {
    let ids: Vec<EvidenceEntryId> = (0..5).map(|i| EvidenceEntryId::new(format!("ev-{i}"))).collect();
    let set: BTreeSet<_> = ids.iter().cloned().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn evidence_entry_id_from_string() {
    let owned = String::from("ev-from-owned");
    let id = EvidenceEntryId::new(owned);
    assert_eq!(id.as_str(), "ev-from-owned");
}

// ---------------------------------------------------------------------------
// EmitterConfig — default, serde
// ---------------------------------------------------------------------------

#[test]
fn emitter_config_default_values() {
    let cfg = EmitterConfig::default();
    assert_eq!(cfg.buffer_capacity, 4096);
    assert_eq!(cfg.budget_cost_ms, 1);
}

#[test]
fn emitter_config_serde_roundtrip() {
    let cfg = EmitterConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: EmitterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn emitter_config_custom_serde_roundtrip() {
    let cfg = EmitterConfig {
        buffer_capacity: 100,
        budget_cost_ms: 50,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: EmitterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn emitter_config_clone_equality() {
    let cfg = EmitterConfig {
        buffer_capacity: 256,
        budget_cost_ms: 10,
    };
    let cloned = cfg.clone();
    assert_eq!(cfg, cloned);
}

#[test]
fn emitter_config_json_fields_present() {
    let cfg = EmitterConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(json.contains("buffer_capacity"));
    assert!(json.contains("budget_cost_ms"));
}

// ---------------------------------------------------------------------------
// EvidenceEmissionError — Display, serde
// ---------------------------------------------------------------------------

#[test]
fn error_display_buffer_full() {
    let e = EvidenceEmissionError::BufferFull { capacity: 10 };
    let msg = e.to_string();
    assert!(msg.contains("10"));
    assert!(msg.contains("buffer full"));
}

#[test]
fn error_display_budget_exhausted() {
    let e = EvidenceEmissionError::BudgetExhausted { requested_ms: 50 };
    let msg = e.to_string();
    assert!(msg.contains("50"));
    assert!(msg.contains("budget exhausted"));
}

#[test]
fn error_display_build_error() {
    let e = EvidenceEmissionError::BuildError {
        detail: "schema mismatch".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("schema mismatch"));
}

#[test]
fn error_display_validation_failed() {
    let e = EvidenceEmissionError::ValidationFailed {
        errors: vec!["field_x".to_string(), "field_y".to_string()],
    };
    let msg = e.to_string();
    assert!(msg.contains("field_x"));
    assert!(msg.contains("field_y"));
}

#[test]
fn error_all_variants_display_unique() {
    let errors = [
        EvidenceEmissionError::BufferFull { capacity: 1 },
        EvidenceEmissionError::BudgetExhausted { requested_ms: 1 },
        EvidenceEmissionError::BuildError { detail: "x".to_string() },
        EvidenceEmissionError::ValidationFailed { errors: vec!["y".to_string()] },
    ];
    let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let errors = vec![
        EvidenceEmissionError::BufferFull { capacity: 42 },
        EvidenceEmissionError::BudgetExhausted { requested_ms: 99 },
        EvidenceEmissionError::BuildError { detail: "detail".to_string() },
        EvidenceEmissionError::ValidationFailed { errors: vec!["e1".to_string(), "e2".to_string()] },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: EvidenceEmissionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn error_clone_equality() {
    let e = EvidenceEmissionError::ValidationFailed {
        errors: vec!["a".to_string(), "b".to_string()],
    };
    let cloned = e.clone();
    assert_eq!(e, cloned);
}

// ---------------------------------------------------------------------------
// EvidenceEmissionEvent — serde, field access
// ---------------------------------------------------------------------------

#[test]
fn emission_event_serde_roundtrip() {
    let event = EvidenceEmissionEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "evidence-emission".to_string(),
        event: "evidence_emit".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: EvidenceEmissionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn emission_event_with_error_code_serde() {
    let event = EvidenceEmissionEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "rejected".to_string(),
        error_code: Some("buffer_full".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: EvidenceEmissionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.error_code.as_deref(), Some("buffer_full"));
}

#[test]
fn emission_event_json_fields_present() {
    let event = EvidenceEmissionEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    for field in &["trace_id", "decision_id", "policy_id", "component", "event", "outcome"] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn emission_event_clone_equality() {
    let event = EvidenceEmissionEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("code".to_string()),
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
}

// ---------------------------------------------------------------------------
// CanonicalEvidenceEmitter — new, is_empty, remaining_capacity, state
// ---------------------------------------------------------------------------

#[test]
fn emitter_new_is_empty() {
    let em = CanonicalEvidenceEmitter::new(EmitterConfig::default());
    assert!(em.is_empty());
    assert_eq!(em.len(), 0);
}

#[test]
fn emitter_remaining_capacity_matches_config() {
    let em = CanonicalEvidenceEmitter::new(EmitterConfig {
        buffer_capacity: 512,
        budget_cost_ms: 1,
    });
    assert_eq!(em.remaining_capacity(), 512);
}

#[test]
fn emitter_entries_empty_initially() {
    let em = CanonicalEvidenceEmitter::new(EmitterConfig::default());
    assert!(em.entries().is_empty());
}

#[test]
fn emitter_events_empty_initially() {
    let em = CanonicalEvidenceEmitter::new(EmitterConfig::default());
    assert!(em.events().is_empty());
}

#[test]
fn emitter_category_counts_empty_initially() {
    let em = CanonicalEvidenceEmitter::new(EmitterConfig::default());
    assert!(em.category_counts().is_empty());
}

#[test]
fn emitter_verify_chain_integrity_on_empty() {
    let em = CanonicalEvidenceEmitter::new(EmitterConfig::default());
    assert!(em.verify_chain_integrity());
}

#[test]
fn emitter_rolling_hash_deterministic_genesis() {
    let em1 = CanonicalEvidenceEmitter::new(EmitterConfig::default());
    let em2 = CanonicalEvidenceEmitter::new(EmitterConfig::default());
    assert_eq!(*em1.rolling_hash(), *em2.rolling_hash());
}

#[test]
fn emitter_set_epoch() {
    let mut em = CanonicalEvidenceEmitter::new(EmitterConfig::default());
    em.set_epoch(SecurityEpoch::from_raw(42));
    // Epoch is set but no public accessor on epoch directly;
    // verified by emitting (tested in unit tests). Here we just
    // ensure set_epoch does not panic.
}

#[test]
fn emitter_serde_roundtrip_empty() {
    let em = CanonicalEvidenceEmitter::new(EmitterConfig::default());
    let json = serde_json::to_string(&em).unwrap();
    let back: CanonicalEvidenceEmitter = serde_json::from_str(&json).unwrap();
    assert!(back.is_empty());
    assert_eq!(back.remaining_capacity(), em.remaining_capacity());
    assert_eq!(*back.rolling_hash(), *em.rolling_hash());
}

// ---------------------------------------------------------------------------
// EvidenceEmissionRequest — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn request_serde_roundtrip() {
    let req = EvidenceEmissionRequest {
        category: ActionCategory::DecisionContract,
        action_name: "quarantine".to_string(),
        trace_id: frankenengine_engine::control_plane::mocks::trace_id_from_seed(1),
        decision_id: frankenengine_engine::control_plane::mocks::decision_id_from_seed(1),
        policy_id: frankenengine_engine::control_plane::mocks::policy_id_from_seed(1),
        ts_unix_ms: 1_700_000_000_000,
        posterior: vec![0.7, 0.3],
        expected_losses: {
            let mut m = BTreeMap::new();
            m.insert("allow".to_string(), 0.1);
            m
        },
        chosen_expected_loss: 0.1,
        calibration_score: 0.85,
        fallback_active: false,
        top_features: vec![("severity".to_string(), 0.6)],
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&req).unwrap();
    let back: EvidenceEmissionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn request_json_fields_present() {
    let req = EvidenceEmissionRequest {
        category: ActionCategory::Cancellation,
        action_name: "cancel".to_string(),
        trace_id: frankenengine_engine::control_plane::mocks::trace_id_from_seed(2),
        decision_id: frankenengine_engine::control_plane::mocks::decision_id_from_seed(2),
        policy_id: frankenengine_engine::control_plane::mocks::policy_id_from_seed(2),
        ts_unix_ms: 100,
        posterior: vec![0.5, 0.5],
        expected_losses: BTreeMap::new(),
        chosen_expected_loss: 0.0,
        calibration_score: 0.0,
        fallback_active: true,
        top_features: vec![],
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&req).unwrap();
    for field in &[
        "category", "action_name", "trace_id", "decision_id", "policy_id",
        "ts_unix_ms", "posterior", "expected_losses", "chosen_expected_loss",
        "calibration_score", "fallback_active", "top_features", "metadata",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn request_clone_equality() {
    let req = EvidenceEmissionRequest {
        category: ActionCategory::ObligationLifecycle,
        action_name: "fulfill".to_string(),
        trace_id: frankenengine_engine::control_plane::mocks::trace_id_from_seed(3),
        decision_id: frankenengine_engine::control_plane::mocks::decision_id_from_seed(3),
        policy_id: frankenengine_engine::control_plane::mocks::policy_id_from_seed(3),
        ts_unix_ms: 999,
        posterior: vec![0.9, 0.1],
        expected_losses: BTreeMap::new(),
        chosen_expected_loss: 0.05,
        calibration_score: 0.95,
        fallback_active: false,
        top_features: vec![],
        metadata: BTreeMap::new(),
    };
    let cloned = req.clone();
    assert_eq!(req, cloned);
}
