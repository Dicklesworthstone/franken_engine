//! Integration tests for the `evidence_emission` module.
//!
//! Covers: ActionCategory, EvidenceEntryId, EmitterConfig,
//! EvidenceEmissionRequest, CanonicalEvidenceEntry, CanonicalEvidenceEmitter,
//! EvidenceEmissionError, EvidenceEmissionEvent — Display impls, serde
//! roundtrips, core emission flow, buffer management, chain-hash integrity,
//! determinism, filtering, epoch propagation, rolling hash, and edge cases.

#![forbid(unsafe_code)]
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

use std::collections::BTreeMap;

use frankenengine_engine::control_plane::ContextAdapter;
use frankenengine_engine::control_plane::mocks::{
    MockBudget, MockCx, decision_id_from_seed, policy_id_from_seed, trace_id_from_seed,
};
use frankenengine_engine::evidence_emission::{
    ActionCategory, CanonicalEvidenceEmitter, CanonicalEvidenceEntry, EmitterConfig,
    EvidenceEmissionError, EvidenceEmissionEvent, EvidenceEmissionRequest, EvidenceEntryId,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_emitter() -> CanonicalEvidenceEmitter {
    CanonicalEvidenceEmitter::new(EmitterConfig::default())
}

fn small_emitter(cap: usize) -> CanonicalEvidenceEmitter {
    CanonicalEvidenceEmitter::new(EmitterConfig {
        buffer_capacity: cap,
        ..EmitterConfig::default()
    })
}

fn mock_cx() -> MockCx {
    MockCx::new(trace_id_from_seed(1), MockBudget::new(100_000))
}

fn make_request(category: ActionCategory, action: &str) -> EvidenceEmissionRequest {
    EvidenceEmissionRequest {
        category,
        action_name: action.to_string(),
        trace_id: trace_id_from_seed(1),
        decision_id: decision_id_from_seed(1),
        policy_id: policy_id_from_seed(1),
        ts_unix_ms: 1_700_000_000_000,
        posterior: vec![0.7, 0.3],
        expected_losses: {
            let mut m = BTreeMap::new();
            m.insert("allow".to_string(), 0.1);
            m.insert("deny".to_string(), 0.9);
            m
        },
        chosen_expected_loss: 0.1,
        calibration_score: 0.85,
        fallback_active: false,
        top_features: vec![
            ("severity".to_string(), 0.6),
            ("frequency".to_string(), 0.3),
        ],
        metadata: BTreeMap::new(),
    }
}

fn make_request_with_seed(
    category: ActionCategory,
    action: &str,
    seed: u64,
) -> EvidenceEmissionRequest {
    EvidenceEmissionRequest {
        category,
        action_name: action.to_string(),
        trace_id: trace_id_from_seed(seed),
        decision_id: decision_id_from_seed(seed),
        policy_id: policy_id_from_seed(seed),
        ts_unix_ms: 1_700_000_000_000 + seed,
        posterior: vec![0.7, 0.3],
        expected_losses: {
            let mut m = BTreeMap::new();
            m.insert("allow".to_string(), 0.1);
            m.insert("deny".to_string(), 0.9);
            m
        },
        chosen_expected_loss: 0.1,
        calibration_score: 0.85,
        fallback_active: false,
        top_features: vec![("severity".to_string(), 0.6)],
        metadata: BTreeMap::new(),
    }
}

// ===========================================================================
// ActionCategory
// ===========================================================================

#[test]
fn action_category_all_has_six_variants() {
    assert_eq!(ActionCategory::ALL.len(), 6);
}

#[test]
fn action_category_display_matches_as_str_for_all_variants() {
    for cat in &ActionCategory::ALL {
        assert_eq!(cat.to_string(), cat.as_str());
    }
}

#[test]
fn action_category_as_str_values_are_snake_case() {
    let expected = [
        "decision_contract",
        "region_lifecycle",
        "cancellation",
        "obligation_lifecycle",
        "extension_lifecycle",
        "containment_action",
    ];
    for (cat, exp) in ActionCategory::ALL.iter().zip(expected.iter()) {
        assert_eq!(cat.as_str(), *exp);
    }
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
fn action_category_ordering_is_declaration_order() {
    let mut cats = ActionCategory::ALL.to_vec();
    cats.sort();
    assert_eq!(cats, ActionCategory::ALL.to_vec());
}

#[test]
fn action_category_clone_eq() {
    let cat = ActionCategory::ContainmentAction;
    let cloned = cat;
    assert_eq!(cat, cloned);
}

// ===========================================================================
// EvidenceEntryId
// ===========================================================================

#[test]
fn evidence_entry_id_new_and_display() {
    let id = EvidenceEntryId::new("ev-test-42");
    assert_eq!(id.as_str(), "ev-test-42");
    assert_eq!(id.to_string(), "ev-test-42");
}

#[test]
fn evidence_entry_id_serde_roundtrip() {
    let id = EvidenceEntryId::new("ev-roundtrip-1");
    let json = serde_json::to_string(&id).unwrap();
    let back: EvidenceEntryId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn evidence_entry_id_ord_and_hash() {
    let a = EvidenceEntryId::new("a");
    let b = EvidenceEntryId::new("b");
    assert!(a < b);

    // Hash consistency via BTreeSet inclusion
    let mut set = std::collections::BTreeSet::new();
    set.insert(a.clone());
    set.insert(b.clone());
    assert!(set.contains(&a));
    assert!(set.contains(&b));
    assert_eq!(set.len(), 2);
}

#[test]
fn evidence_entry_id_from_string_and_str_slice() {
    let from_string = EvidenceEntryId::new(String::from("owned"));
    let from_str = EvidenceEntryId::new("borrowed");
    assert_eq!(from_string.as_str(), "owned");
    assert_eq!(from_str.as_str(), "borrowed");
}

// ===========================================================================
// EmitterConfig
// ===========================================================================

#[test]
fn emitter_config_default_values() {
    let cfg = EmitterConfig::default();
    assert_eq!(cfg.buffer_capacity, 4096);
    assert_eq!(cfg.budget_cost_ms, 1);
}

#[test]
fn emitter_config_serde_roundtrip() {
    let cfg = EmitterConfig {
        buffer_capacity: 128,
        budget_cost_ms: 5,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: EmitterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn emitter_config_custom_values_propagate() {
    let cfg = EmitterConfig {
        buffer_capacity: 10,
        budget_cost_ms: 99,
    };
    let emitter = CanonicalEvidenceEmitter::new(cfg.clone());
    assert_eq!(emitter.remaining_capacity(), 10);
    assert!(emitter.is_empty());
}

// ===========================================================================
// EvidenceEmissionRequest serde
// ===========================================================================

#[test]
fn evidence_emission_request_serde_roundtrip() {
    let req = make_request(ActionCategory::DecisionContract, "quarantine");
    let json = serde_json::to_string(&req).unwrap();
    let back: EvidenceEmissionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn evidence_emission_request_with_metadata_serde_roundtrip() {
    let mut req = make_request(ActionCategory::ExtensionLifecycle, "load");
    req.metadata
        .insert("extension_id".to_string(), "ext-001".to_string());
    req.metadata
        .insert("version".to_string(), "1.2.3".to_string());
    let json = serde_json::to_string(&req).unwrap();
    let back: EvidenceEmissionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

// ===========================================================================
// EvidenceEmissionError
// ===========================================================================

#[test]
fn error_display_buffer_full() {
    let err = EvidenceEmissionError::BufferFull { capacity: 42 };
    let msg = err.to_string();
    assert!(msg.contains("42"));
    assert!(msg.contains("buffer full"));
}

#[test]
fn error_display_budget_exhausted() {
    let err = EvidenceEmissionError::BudgetExhausted { requested_ms: 500 };
    let msg = err.to_string();
    assert!(msg.contains("500"));
    assert!(msg.contains("budget exhausted"));
}

#[test]
fn error_display_build_error() {
    let err = EvidenceEmissionError::BuildError {
        detail: "missing field".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("missing field"));
    assert!(msg.contains("build error"));
}

#[test]
fn error_display_validation_failed() {
    let err = EvidenceEmissionError::ValidationFailed {
        errors: vec!["posterior empty".to_string(), "action empty".to_string()],
    };
    let msg = err.to_string();
    assert!(msg.contains("posterior empty"));
    assert!(msg.contains("action empty"));
    assert!(msg.contains("validation failed"));
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let variants = vec![
        EvidenceEmissionError::BufferFull { capacity: 100 },
        EvidenceEmissionError::BudgetExhausted { requested_ms: 50 },
        EvidenceEmissionError::BuildError {
            detail: "oops".to_string(),
        },
        EvidenceEmissionError::ValidationFailed {
            errors: vec!["x".to_string(), "y".to_string()],
        },
    ];
    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let back: EvidenceEmissionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// EvidenceEmissionEvent
// ===========================================================================

#[test]
fn evidence_emission_event_serde_roundtrip() {
    let event = EvidenceEmissionEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
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
fn evidence_emission_event_with_error_code_roundtrip() {
    let event = EvidenceEmissionEvent {
        trace_id: "t-2".to_string(),
        decision_id: "d-2".to_string(),
        policy_id: "p-2".to_string(),
        component: "evidence-emission".to_string(),
        event: "evidence_emit".to_string(),
        outcome: "rejected".to_string(),
        error_code: Some("buffer_full".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: EvidenceEmissionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// Core emission flow
// ===========================================================================

#[test]
fn emit_single_entry_populates_all_fields() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    let req = make_request(ActionCategory::DecisionContract, "quarantine");
    let id = em.emit(&mut cx, &req).unwrap();

    assert_eq!(em.len(), 1);
    assert!(!em.is_empty());

    let entry = &em.entries()[0];
    assert_eq!(entry.entry_id, id);
    assert_eq!(entry.category, ActionCategory::DecisionContract);
    assert_eq!(entry.action_name, "quarantine");
    assert_eq!(entry.schema_version, "evidence-v1");
    assert_eq!(entry.ts_unix_ms, 1_700_000_000_000);
    assert_eq!(entry.sequence, 0);
    assert!(!entry.trace_id.is_empty());
    assert!(!entry.decision_id.is_empty());
    assert!(!entry.policy_id.is_empty());
}

#[test]
fn emit_links_trace_decision_policy_from_request() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    let req = make_request(ActionCategory::RegionLifecycle, "region_create");
    em.emit(&mut cx, &req).unwrap();

    let entry = &em.entries()[0];
    assert_eq!(entry.trace_id, req.trace_id.to_string());
    assert_eq!(entry.decision_id, req.decision_id.to_string());
    assert_eq!(entry.policy_id, req.policy_id.to_string());
}

#[test]
fn entry_id_contains_category_and_sequence() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    let req = make_request(ActionCategory::Cancellation, "cancel_job");
    let id = em.emit(&mut cx, &req).unwrap();

    let id_str = id.as_str();
    assert!(id_str.contains("cancellation"), "id={id_str}");
    assert!(id_str.contains("-0-"), "id={id_str}"); // sequence 0
}

#[test]
fn emit_all_six_categories_successfully() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    for cat in &ActionCategory::ALL {
        let req = make_request(*cat, &format!("{cat}_action"));
        em.emit(&mut cx, &req).unwrap();
    }
    assert_eq!(em.len(), 6);
    assert_eq!(em.category_counts().len(), 6);
    for count in em.category_counts().values() {
        assert_eq!(*count, 1);
    }
}

// ===========================================================================
// Sequence numbering
// ===========================================================================

#[test]
fn sequence_numbers_monotonically_increase() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    for i in 0u64..5 {
        let req = make_request(ActionCategory::DecisionContract, &format!("a{i}"));
        em.emit(&mut cx, &req).unwrap();
    }
    for (idx, entry) in em.entries().iter().enumerate() {
        assert_eq!(entry.sequence, idx as u64);
    }
}

#[test]
fn get_by_sequence_returns_correct_entry() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    for i in 0..3 {
        let req = make_request(ActionCategory::DecisionContract, &format!("a{i}"));
        em.emit(&mut cx, &req).unwrap();
    }

    assert!(em.get(0).is_some());
    assert_eq!(em.get(1).unwrap().action_name, "a1");
    assert!(em.get(3).is_none());
    assert!(em.get(u64::MAX).is_none());
}

// ===========================================================================
// Artifact hash integrity
// ===========================================================================

#[test]
fn artifact_hash_matches_ledger_content() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    let req = make_request(ActionCategory::ExtensionLifecycle, "extension_load");
    em.emit(&mut cx, &req).unwrap();

    let entry = &em.entries()[0];
    assert!(entry.verify_artifact_integrity());
}

#[test]
fn tampered_ledger_entry_detected_by_artifact_hash() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    let req = make_request(ActionCategory::ExtensionLifecycle, "extension_load");
    em.emit(&mut cx, &req).unwrap();

    let mut entry = em.entries()[0].clone();
    entry.ledger_entry.ts_unix_ms = 999; // tamper
    assert!(!entry.verify_artifact_integrity());
}

// ===========================================================================
// Chain hash integrity
// ===========================================================================

#[test]
fn chain_integrity_passes_for_valid_sequence() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    for i in 0..10 {
        let req = make_request(ActionCategory::DecisionContract, &format!("action_{i}"));
        em.emit(&mut cx, &req).unwrap();
    }
    assert!(em.verify_chain_integrity());
}

#[test]
fn chain_integrity_passes_for_empty_emitter() {
    let em = default_emitter();
    assert!(em.verify_chain_integrity());
}

#[test]
fn chain_integrity_passes_for_single_entry() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    em.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "a"),
    )
    .unwrap();
    assert!(em.verify_chain_integrity());
}

#[test]
fn chain_link_verification_works_for_individual_entries() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    for i in 0..3 {
        let req = make_request(ActionCategory::DecisionContract, &format!("a{i}"));
        em.emit(&mut cx, &req).unwrap();
    }
    let entries = em.entries();
    assert!(entries[0].verify_chain_link(None));
    assert!(entries[1].verify_chain_link(Some(&entries[0])));
    assert!(entries[2].verify_chain_link(Some(&entries[1])));
    // Wrong predecessor fails
    assert!(!entries[2].verify_chain_link(None));
}

// ===========================================================================
// Bounded buffer (back-pressure)
// ===========================================================================

#[test]
fn buffer_full_returns_buffer_full_error() {
    let mut em = small_emitter(2);
    let mut cx = mock_cx();
    let req = make_request(ActionCategory::ContainmentAction, "sandbox");

    em.emit(&mut cx, &req).unwrap();
    em.emit(&mut cx, &req).unwrap();
    let err = em.emit(&mut cx, &req).unwrap_err();
    assert_eq!(err, EvidenceEmissionError::BufferFull { capacity: 2 });
}

#[test]
fn buffer_capacity_zero_rejects_immediately() {
    let mut em = small_emitter(0);
    let mut cx = mock_cx();
    let req = make_request(ActionCategory::DecisionContract, "a");
    let err = em.emit(&mut cx, &req).unwrap_err();
    assert_eq!(err, EvidenceEmissionError::BufferFull { capacity: 0 });
}

#[test]
fn remaining_capacity_decreases_with_each_emit() {
    let mut em = small_emitter(5);
    let mut cx = mock_cx();
    let req = make_request(ActionCategory::DecisionContract, "a");

    assert_eq!(em.remaining_capacity(), 5);
    em.emit(&mut cx, &req).unwrap();
    assert_eq!(em.remaining_capacity(), 4);
    em.emit(&mut cx, &req).unwrap();
    assert_eq!(em.remaining_capacity(), 3);
}

#[test]
fn remaining_capacity_reaches_zero_at_full() {
    let mut em = small_emitter(2);
    let mut cx = mock_cx();
    let req = make_request(ActionCategory::DecisionContract, "a");

    em.emit(&mut cx, &req).unwrap();
    em.emit(&mut cx, &req).unwrap();
    assert_eq!(em.remaining_capacity(), 0);
}

// ===========================================================================
// Budget consumption
// ===========================================================================

#[test]
fn emit_consumes_budget_from_context() {
    let mut em = CanonicalEvidenceEmitter::new(EmitterConfig {
        budget_cost_ms: 10,
        ..EmitterConfig::default()
    });
    let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(100));
    let req = make_request(ActionCategory::DecisionContract, "allow");

    em.emit(&mut cx, &req).unwrap();
    assert_eq!(cx.budget().remaining_ms(), 90);

    em.emit(&mut cx, &req).unwrap();
    assert_eq!(cx.budget().remaining_ms(), 80);
}

#[test]
fn budget_exhaustion_returns_error() {
    let mut em = CanonicalEvidenceEmitter::new(EmitterConfig {
        budget_cost_ms: 200,
        ..EmitterConfig::default()
    });
    let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(100));
    let req = make_request(ActionCategory::DecisionContract, "deny");

    let err = em.emit(&mut cx, &req).unwrap_err();
    assert_eq!(
        err,
        EvidenceEmissionError::BudgetExhausted { requested_ms: 200 }
    );
}

#[test]
fn budget_exactly_sufficient_succeeds() {
    let mut em = CanonicalEvidenceEmitter::new(EmitterConfig {
        budget_cost_ms: 50,
        ..EmitterConfig::default()
    });
    let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(50));
    let req = make_request(ActionCategory::DecisionContract, "allow");

    em.emit(&mut cx, &req).unwrap();
    assert_eq!(cx.budget().remaining_ms(), 0);
}

// ===========================================================================
// Category filtering
// ===========================================================================

#[test]
fn by_category_filters_correctly() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    em.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "quarantine"),
    )
    .unwrap();
    em.emit(
        &mut cx,
        &make_request(ActionCategory::ExtensionLifecycle, "load"),
    )
    .unwrap();
    em.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "revoke"),
    )
    .unwrap();
    em.emit(
        &mut cx,
        &make_request(ActionCategory::ContainmentAction, "terminate"),
    )
    .unwrap();

    assert_eq!(em.by_category(ActionCategory::DecisionContract).len(), 2);
    assert_eq!(em.by_category(ActionCategory::ExtensionLifecycle).len(), 1);
    assert_eq!(em.by_category(ActionCategory::ContainmentAction).len(), 1);
    assert_eq!(em.by_category(ActionCategory::Cancellation).len(), 0);
}

#[test]
fn category_counts_tracked_per_category() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    for _ in 0..3 {
        em.emit(
            &mut cx,
            &make_request(ActionCategory::ObligationLifecycle, "create"),
        )
        .unwrap();
    }
    em.emit(
        &mut cx,
        &make_request(ActionCategory::RegionLifecycle, "destroy"),
    )
    .unwrap();

    let counts = em.category_counts();
    assert_eq!(counts[&ActionCategory::ObligationLifecycle], 3);
    assert_eq!(counts[&ActionCategory::RegionLifecycle], 1);
    assert!(!counts.contains_key(&ActionCategory::Cancellation));
}

// ===========================================================================
// Trace ID / Decision ID filtering
// ===========================================================================

#[test]
fn by_trace_id_filters_matching_entries() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    let req1 = make_request_with_seed(ActionCategory::DecisionContract, "a", 1);
    let req2 = make_request_with_seed(ActionCategory::DecisionContract, "b", 2);
    em.emit(&mut cx, &req1).unwrap();
    em.emit(&mut cx, &req2).unwrap();
    em.emit(&mut cx, &req1).unwrap();

    let trace_str = trace_id_from_seed(1).to_string();
    assert_eq!(em.by_trace_id(&trace_str).len(), 2);
}

#[test]
fn by_trace_id_returns_empty_for_nonexistent() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    em.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "a"),
    )
    .unwrap();

    assert_eq!(em.by_trace_id("nonexistent-trace").len(), 0);
}

#[test]
fn by_decision_id_filters_matching_entries() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    let req1 = make_request_with_seed(ActionCategory::DecisionContract, "a", 10);
    let req2 = make_request_with_seed(ActionCategory::DecisionContract, "b", 20);
    em.emit(&mut cx, &req1).unwrap();
    em.emit(&mut cx, &req2).unwrap();

    let dec_str = decision_id_from_seed(10).to_string();
    assert_eq!(em.by_decision_id(&dec_str).len(), 1);
    assert_eq!(em.by_decision_id(&dec_str)[0].action_name, "a");
}

// ===========================================================================
// Epoch propagation
// ===========================================================================

#[test]
fn epoch_propagated_to_emitted_entries() {
    let mut em = default_emitter();
    em.set_epoch(SecurityEpoch::from_raw(42));
    let mut cx = mock_cx();

    em.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "allow"),
    )
    .unwrap();
    assert_eq!(em.entries()[0].epoch, SecurityEpoch::from_raw(42));
}

#[test]
fn epoch_can_be_changed_between_emissions() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    em.set_epoch(SecurityEpoch::from_raw(1));
    em.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "a"),
    )
    .unwrap();

    em.set_epoch(SecurityEpoch::from_raw(2));
    em.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "b"),
    )
    .unwrap();

    assert_eq!(em.entries()[0].epoch, SecurityEpoch::from_raw(1));
    assert_eq!(em.entries()[1].epoch, SecurityEpoch::from_raw(2));
}

// ===========================================================================
// Rolling hash
// ===========================================================================

#[test]
fn rolling_hash_changes_with_each_emission() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    let h0 = em.rolling_hash().clone();
    em.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "a"),
    )
    .unwrap();
    let h1 = em.rolling_hash().clone();
    em.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "b"),
    )
    .unwrap();
    let h2 = em.rolling_hash().clone();

    assert_ne!(h0, h1);
    assert_ne!(h1, h2);
    assert_ne!(h0, h2);
}

#[test]
fn rolling_hash_is_deterministic_for_same_inputs() {
    let run = || {
        let mut em = default_emitter();
        em.set_epoch(SecurityEpoch::from_raw(7));
        let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(100_000));
        for i in 0..5 {
            let req = make_request(ActionCategory::DecisionContract, &format!("action_{i}"));
            em.emit(&mut cx, &req).unwrap();
        }
        em.rolling_hash().clone()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// Structured events
// ===========================================================================

#[test]
fn events_emitted_for_successful_emission() {
    let mut em = default_emitter();
    let mut cx = mock_cx();
    em.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "allow"),
    )
    .unwrap();

    assert_eq!(em.events().len(), 1);
    let ev = &em.events()[0];
    assert_eq!(ev.event, "evidence_emit");
    assert_eq!(ev.outcome, "ok");
    assert!(ev.error_code.is_none());
    assert_eq!(ev.component, "evidence-emission");
}

#[test]
fn events_emitted_for_buffer_full_rejection() {
    let mut em = small_emitter(1);
    let mut cx = mock_cx();
    let req = make_request(ActionCategory::DecisionContract, "a");

    em.emit(&mut cx, &req).unwrap();
    let _ = em.emit(&mut cx, &req); // rejected

    assert_eq!(em.events().len(), 2);
    assert_eq!(em.events()[0].outcome, "ok");
    assert_eq!(em.events()[1].outcome, "rejected");
    assert_eq!(em.events()[1].error_code.as_deref(), Some("buffer_full"));
}

#[test]
fn events_emitted_for_budget_exhaustion() {
    let mut em = CanonicalEvidenceEmitter::new(EmitterConfig {
        budget_cost_ms: 999,
        ..EmitterConfig::default()
    });
    let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(1));
    let req = make_request(ActionCategory::DecisionContract, "a");
    let _ = em.emit(&mut cx, &req);

    assert_eq!(em.events().len(), 1);
    assert_eq!(em.events()[0].outcome, "rejected");
    assert_eq!(
        em.events()[0].error_code.as_deref(),
        Some("budget_exhausted")
    );
}

// ===========================================================================
// Default posterior for missing Bayesian evaluation
// ===========================================================================

#[test]
fn empty_posterior_defaults_to_uniform() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    let mut req = make_request(ActionCategory::ExtensionLifecycle, "load");
    req.posterior = vec![];
    em.emit(&mut cx, &req).unwrap();

    assert_eq!(em.entries()[0].ledger_entry.posterior, vec![0.5, 0.5]);
}

// ===========================================================================
// Metadata passthrough
// ===========================================================================

#[test]
fn metadata_preserved_in_emitted_entry() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    let mut req = make_request(ActionCategory::ContainmentAction, "quarantine");
    req.metadata
        .insert("extension_id".to_string(), "ext-001".to_string());
    req.metadata
        .insert("reason".to_string(), "oom_detected".to_string());
    em.emit(&mut cx, &req).unwrap();

    let meta = &em.entries()[0].metadata;
    assert_eq!(meta.get("extension_id"), Some(&"ext-001".to_string()));
    assert_eq!(meta.get("reason"), Some(&"oom_detected".to_string()));
}

#[test]
fn empty_metadata_roundtrips_correctly() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    let req = make_request(ActionCategory::DecisionContract, "a");
    em.emit(&mut cx, &req).unwrap();

    assert!(em.entries()[0].metadata.is_empty());
}

// ===========================================================================
// Serde roundtrips for CanonicalEvidenceEntry and emitter
// ===========================================================================

#[test]
fn canonical_evidence_entry_serde_roundtrip() {
    let mut em = default_emitter();
    em.set_epoch(SecurityEpoch::from_raw(5));
    let mut cx = mock_cx();
    let mut req = make_request(ActionCategory::DecisionContract, "allow");
    req.metadata.insert("key".to_string(), "value".to_string());
    em.emit(&mut cx, &req).unwrap();

    let entry = &em.entries()[0];
    let json = serde_json::to_string(entry).unwrap();
    let back: CanonicalEvidenceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(*entry, back);
    // Verify integrity is preserved after deserialization
    assert!(back.verify_artifact_integrity());
}

#[test]
fn canonical_evidence_emitter_serde_roundtrip() {
    let mut em = default_emitter();
    em.set_epoch(SecurityEpoch::from_raw(3));
    let mut cx = mock_cx();
    for i in 0..3 {
        let req = make_request(ActionCategory::DecisionContract, &format!("action_{i}"));
        em.emit(&mut cx, &req).unwrap();
    }

    let json = serde_json::to_string(&em).unwrap();
    let back: CanonicalEvidenceEmitter = serde_json::from_str(&json).unwrap();

    assert_eq!(back.len(), em.len());
    assert_eq!(back.entries(), em.entries());
    assert_eq!(*back.rolling_hash(), *em.rolling_hash());
    assert!(back.verify_chain_integrity());
}

// ===========================================================================
// Deterministic replay
// ===========================================================================

#[test]
fn deterministic_replay_produces_identical_entries_and_hashes() {
    let run = || {
        let mut em = default_emitter();
        em.set_epoch(SecurityEpoch::from_raw(1));
        let mut cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(100_000));
        for i in 0..5 {
            let req = make_request(ActionCategory::DecisionContract, &format!("action_{i}"));
            em.emit(&mut cx, &req).unwrap();
        }
        (em.entries().to_vec(), em.rolling_hash().clone())
    };

    let (entries_a, hash_a) = run();
    let (entries_b, hash_b) = run();
    assert_eq!(entries_a, entries_b);
    assert_eq!(hash_a, hash_b);
}

#[test]
fn different_inputs_produce_different_hashes() {
    let mut em1 = default_emitter();
    let mut em2 = default_emitter();
    let mut cx = mock_cx();

    em1.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "action_a"),
    )
    .unwrap();
    em2.emit(
        &mut cx,
        &make_request(ActionCategory::DecisionContract, "action_b"),
    )
    .unwrap();

    assert_ne!(em1.rolling_hash(), em2.rolling_hash());
}

// ===========================================================================
// Empty expected_losses defaults to action-specific entry
// ===========================================================================

#[test]
fn empty_expected_losses_defaults_to_chosen_action() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    let mut req = make_request(ActionCategory::DecisionContract, "sandbox");
    req.expected_losses.clear();
    em.emit(&mut cx, &req).unwrap();

    let ledger = &em.entries()[0].ledger_entry;
    assert!(
        ledger.expected_loss_by_action.contains_key("sandbox"),
        "should default to action_name key"
    );
}

// ===========================================================================
// Top features passthrough
// ===========================================================================

#[test]
fn top_features_passed_through_to_ledger_entry() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    let req = make_request(ActionCategory::DecisionContract, "allow");
    em.emit(&mut cx, &req).unwrap();

    let ledger = &em.entries()[0].ledger_entry;
    assert_eq!(ledger.top_features.len(), 2);
    assert_eq!(ledger.top_features[0].0, "severity");
}

// ===========================================================================
// Fallback active flag
// ===========================================================================

#[test]
fn fallback_active_propagated_to_ledger() {
    let mut em = default_emitter();
    let mut cx = mock_cx();

    let mut req = make_request(ActionCategory::DecisionContract, "allow");
    req.fallback_active = true;
    em.emit(&mut cx, &req).unwrap();

    assert!(em.entries()[0].ledger_entry.fallback_active);
}

// ===========================================================================
// Genesis rolling hash is deterministic
// ===========================================================================

#[test]
fn genesis_rolling_hash_is_content_hash_of_evidence_genesis() {
    let em = default_emitter();
    let expected = ContentHash::compute(b"evidence-genesis");
    assert_eq!(*em.rolling_hash(), expected);
}

// ===========================================================================
// Mixed scenario: multiple categories, filtering, chain integrity
// ===========================================================================

#[test]
fn mixed_category_scenario_with_chain_verification() {
    let mut em = default_emitter();
    em.set_epoch(SecurityEpoch::from_raw(10));
    let mut cx = mock_cx();

    let categories = [
        (ActionCategory::DecisionContract, "quarantine"),
        (ActionCategory::ExtensionLifecycle, "load"),
        (ActionCategory::ContainmentAction, "sandbox"),
        (ActionCategory::Cancellation, "cancel_op"),
        (ActionCategory::ObligationLifecycle, "create"),
        (ActionCategory::RegionLifecycle, "region_destroy"),
        (ActionCategory::DecisionContract, "revoke"),
        (ActionCategory::ContainmentAction, "terminate"),
    ];

    for (cat, action) in &categories {
        let req = make_request(*cat, action);
        em.emit(&mut cx, &req).unwrap();
    }

    assert_eq!(em.len(), 8);
    assert!(em.verify_chain_integrity());

    // Category counts
    assert_eq!(em.category_counts()[&ActionCategory::DecisionContract], 2);
    assert_eq!(em.category_counts()[&ActionCategory::ContainmentAction], 2);
    assert_eq!(em.category_counts()[&ActionCategory::ExtensionLifecycle], 1);

    // Sequence monotonicity
    for (idx, entry) in em.entries().iter().enumerate() {
        assert_eq!(entry.sequence, idx as u64);
    }

    // All entries have the same epoch
    for entry in em.entries() {
        assert_eq!(entry.epoch, SecurityEpoch::from_raw(10));
    }

    // Events count matches entries
    assert_eq!(em.events().len(), 8);
}
