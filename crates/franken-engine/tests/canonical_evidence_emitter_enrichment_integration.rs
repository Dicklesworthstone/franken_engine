//! Enrichment integration tests for `canonical_evidence_emitter` (FRX-10.13).
//!
//! Covers: JSON field-name stability, serde roundtrips, Display exact values,
//! Debug distinctness, HighImpactAction taxonomy (20 variants), EmissionError
//! variants, EmissionPolicy defaults, emitter lifecycle, buffer limits,
//! ledger failure simulation, and structured log events.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::canonical_evidence_emitter::*;
use frankenengine_engine::evidence_ledger::{ChosenAction, DecisionType};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── helpers ────────────────────────────────────────────────────────────

fn test_context(action: HighImpactAction) -> EmissionContext {
    EmissionContext {
        trace_id: "trace-enrich".to_string(),
        decision_id: "decision-enrich".to_string(),
        policy_id: "policy-enrich".to_string(),
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns: 1_000_000,
        action,
        target_id: "target-1".to_string(),
    }
}

fn test_chosen() -> ChosenAction {
    ChosenAction {
        action_name: "act-1".to_string(),
        expected_loss_millionths: 500,
        rationale: "best option".to_string(),
    }
}

// ── HighImpactAction Display ───────────────────────────────────────────

#[test]
fn high_impact_action_display_sandbox() {
    assert_eq!(HighImpactAction::Sandbox.to_string(), "sandbox");
}
#[test]
fn high_impact_action_display_suspend() {
    assert_eq!(HighImpactAction::Suspend.to_string(), "suspend");
}
#[test]
fn high_impact_action_display_terminate() {
    assert_eq!(HighImpactAction::Terminate.to_string(), "terminate");
}
#[test]
fn high_impact_action_display_quarantine() {
    assert_eq!(HighImpactAction::Quarantine.to_string(), "quarantine");
}
#[test]
fn high_impact_action_display_extension_load() {
    assert_eq!(
        HighImpactAction::ExtensionLoad.to_string(),
        "extension_load"
    );
}
#[test]
fn high_impact_action_display_extension_unload() {
    assert_eq!(
        HighImpactAction::ExtensionUnload.to_string(),
        "extension_unload"
    );
}
#[test]
fn high_impact_action_display_extension_start() {
    assert_eq!(
        HighImpactAction::ExtensionStart.to_string(),
        "extension_start"
    );
}
#[test]
fn high_impact_action_display_extension_stop() {
    assert_eq!(
        HighImpactAction::ExtensionStop.to_string(),
        "extension_stop"
    );
}
#[test]
fn high_impact_action_display_policy_update() {
    assert_eq!(HighImpactAction::PolicyUpdate.to_string(), "policy_update");
}
#[test]
fn high_impact_action_display_epoch_transition() {
    assert_eq!(
        HighImpactAction::EpochTransition.to_string(),
        "epoch_transition"
    );
}
#[test]
fn high_impact_action_display_capability_grant() {
    assert_eq!(
        HighImpactAction::CapabilityGrant.to_string(),
        "capability_grant"
    );
}
#[test]
fn high_impact_action_display_revocation() {
    assert_eq!(HighImpactAction::Revocation.to_string(), "revocation");
}
#[test]
fn high_impact_action_display_obligation_create() {
    assert_eq!(
        HighImpactAction::ObligationCreate.to_string(),
        "obligation_create"
    );
}
#[test]
fn high_impact_action_display_obligation_fulfill() {
    assert_eq!(
        HighImpactAction::ObligationFulfill.to_string(),
        "obligation_fulfill"
    );
}
#[test]
fn high_impact_action_display_obligation_failure() {
    assert_eq!(
        HighImpactAction::ObligationFailure.to_string(),
        "obligation_failure"
    );
}
#[test]
fn high_impact_action_display_region_create() {
    assert_eq!(HighImpactAction::RegionCreate.to_string(), "region_create");
}
#[test]
fn high_impact_action_display_region_destroy() {
    assert_eq!(
        HighImpactAction::RegionDestroy.to_string(),
        "region_destroy"
    );
}
#[test]
fn high_impact_action_display_cancellation() {
    assert_eq!(HighImpactAction::Cancellation.to_string(), "cancellation");
}
#[test]
fn high_impact_action_display_contract_evaluation() {
    assert_eq!(
        HighImpactAction::ContractEvaluation.to_string(),
        "contract_evaluation"
    );
}
#[test]
fn high_impact_action_display_remote_authorization() {
    assert_eq!(
        HighImpactAction::RemoteAuthorization.to_string(),
        "remote_authorization"
    );
}

#[test]
fn high_impact_action_all_has_20() {
    assert_eq!(HighImpactAction::ALL.len(), 20);
}

#[test]
fn high_impact_action_display_all_unique() {
    let mut displays = BTreeSet::new();
    for a in &HighImpactAction::ALL {
        displays.insert(a.to_string());
    }
    assert_eq!(displays.len(), 20);
}

#[test]
fn high_impact_action_debug_distinct() {
    let mut dbgs = BTreeSet::new();
    for a in &HighImpactAction::ALL {
        dbgs.insert(format!("{a:?}"));
    }
    assert_eq!(dbgs.len(), 20);
}

#[test]
fn high_impact_action_serde_roundtrip_all() {
    for a in &HighImpactAction::ALL {
        let json = serde_json::to_vec(a).unwrap();
        let back: HighImpactAction = serde_json::from_slice(&json).unwrap();
        assert_eq!(*a, back);
    }
}

// ── HighImpactAction decision_type mapping ─────────────────────────────

#[test]
fn action_decision_type_security() {
    assert_eq!(
        HighImpactAction::Sandbox.decision_type(),
        DecisionType::SecurityAction
    );
    assert_eq!(
        HighImpactAction::Terminate.decision_type(),
        DecisionType::SecurityAction
    );
}

#[test]
fn action_decision_type_lifecycle() {
    assert_eq!(
        HighImpactAction::ExtensionLoad.decision_type(),
        DecisionType::ExtensionLifecycle
    );
    assert_eq!(
        HighImpactAction::ExtensionStop.decision_type(),
        DecisionType::ExtensionLifecycle
    );
}

#[test]
fn action_decision_type_policy_update() {
    assert_eq!(
        HighImpactAction::PolicyUpdate.decision_type(),
        DecisionType::PolicyUpdate
    );
}

#[test]
fn action_decision_type_epoch() {
    assert_eq!(
        HighImpactAction::EpochTransition.decision_type(),
        DecisionType::EpochTransition
    );
}

#[test]
fn action_decision_type_capability() {
    assert_eq!(
        HighImpactAction::CapabilityGrant.decision_type(),
        DecisionType::CapabilityDecision
    );
}

#[test]
fn action_decision_type_revocation() {
    assert_eq!(
        HighImpactAction::Revocation.decision_type(),
        DecisionType::Revocation
    );
}

#[test]
fn action_decision_type_remote_auth() {
    assert_eq!(
        HighImpactAction::RemoteAuthorization.decision_type(),
        DecisionType::RemoteAuthorization
    );
}

// ── HighImpactAction component mapping ─────────────────────────────────

#[test]
fn action_component_containment() {
    assert_eq!(HighImpactAction::Sandbox.component(), "containment");
    assert_eq!(HighImpactAction::Quarantine.component(), "containment");
}

#[test]
fn action_component_lifecycle() {
    assert_eq!(HighImpactAction::ExtensionLoad.component(), "lifecycle");
}

#[test]
fn action_component_obligation() {
    assert_eq!(HighImpactAction::ObligationCreate.component(), "obligation");
}

#[test]
fn action_component_region() {
    assert_eq!(HighImpactAction::RegionCreate.component(), "region");
}

#[test]
fn action_component_all_nonempty() {
    for a in &HighImpactAction::ALL {
        assert!(!a.component().is_empty(), "{a:?} has empty component");
    }
}

// ── EmissionError ──────────────────────────────────────────────────────

#[test]
fn emission_error_display_missing_field() {
    let e = EmissionError::MissingField {
        field: "trace_id".to_string(),
    };
    assert_eq!(e.to_string(), "missing required field: trace_id");
}

#[test]
fn emission_error_display_ledger_write() {
    let e = EmissionError::LedgerWriteFailure {
        reason: "disk full".to_string(),
    };
    assert_eq!(e.to_string(), "ledger write failure: disk full");
}

#[test]
fn emission_error_display_validation() {
    let e = EmissionError::ValidationFailure {
        reason: "bad entry".to_string(),
    };
    assert_eq!(e.to_string(), "validation failure: bad entry");
}

#[test]
fn emission_error_display_buffer_full() {
    let e = EmissionError::BufferFull { capacity: 1024 };
    assert_eq!(e.to_string(), "emission buffer full (capacity=1024)");
}

#[test]
fn emission_error_display_not_required() {
    let e = EmissionError::NotRequired {
        action: HighImpactAction::Sandbox,
    };
    let s = e.to_string();
    assert!(s.contains("not required"));
    assert!(s.contains("sandbox"));
}

#[test]
fn emission_error_is_std_error() {
    let e = EmissionError::MissingField {
        field: "x".to_string(),
    };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn emission_error_debug_distinct() {
    let errors = [
        EmissionError::MissingField {
            field: "f".to_string(),
        },
        EmissionError::LedgerWriteFailure {
            reason: "r".to_string(),
        },
        EmissionError::ValidationFailure {
            reason: "v".to_string(),
        },
        EmissionError::BufferFull { capacity: 1 },
        EmissionError::NotRequired {
            action: HighImpactAction::Sandbox,
        },
    ];
    let mut dbgs = BTreeSet::new();
    for e in &errors {
        dbgs.insert(format!("{e:?}"));
    }
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn emission_error_serde_roundtrip_all() {
    let errors = [
        EmissionError::MissingField {
            field: "f".to_string(),
        },
        EmissionError::LedgerWriteFailure {
            reason: "r".to_string(),
        },
        EmissionError::ValidationFailure {
            reason: "v".to_string(),
        },
        EmissionError::BufferFull { capacity: 1024 },
        EmissionError::NotRequired {
            action: HighImpactAction::Terminate,
        },
    ];
    for e in &errors {
        let json = serde_json::to_vec(e).unwrap();
        let back: EmissionError = serde_json::from_slice(&json).unwrap();
        assert_eq!(e, &back);
    }
}

// ── EmissionPolicy ─────────────────────────────────────────────────────

#[test]
fn emission_policy_default_all_20_mandatory() {
    let p = EmissionPolicy::default();
    assert_eq!(p.mandatory_actions.len(), 20);
}

#[test]
fn emission_policy_default_max_witnesses() {
    let p = EmissionPolicy::default();
    assert_eq!(p.max_witnesses, 256);
}

#[test]
fn emission_policy_default_max_candidates() {
    let p = EmissionPolicy::default();
    assert_eq!(p.max_candidates, 64);
}

#[test]
fn emission_policy_default_include_metadata_true() {
    let p = EmissionPolicy::default();
    assert!(p.include_metadata);
}

#[test]
fn emission_policy_default_buffer_capacity() {
    let p = EmissionPolicy::default();
    assert_eq!(p.buffer_capacity, 1024);
}

#[test]
fn emission_policy_requires_evidence_default() {
    let p = EmissionPolicy::default();
    for a in &HighImpactAction::ALL {
        assert!(p.requires_evidence(*a), "{a:?} should require evidence");
    }
}

#[test]
fn emission_policy_serde_roundtrip() {
    let p = EmissionPolicy::default();
    let json = serde_json::to_vec(&p).unwrap();
    let back: EmissionPolicy = serde_json::from_slice(&json).unwrap();
    assert_eq!(p, back);
}

// ── EmissionContext ────────────────────────────────────────────────────

#[test]
fn emission_context_json_fields() {
    let ctx = test_context(HighImpactAction::Sandbox);
    let v: serde_json::Value = serde_json::to_value(&ctx).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("trace_id"));
    assert!(obj.contains_key("decision_id"));
    assert!(obj.contains_key("policy_id"));
    assert!(obj.contains_key("epoch"));
    assert!(obj.contains_key("timestamp_ns"));
    assert!(obj.contains_key("action"));
    assert!(obj.contains_key("target_id"));
}

// ── EmissionReceipt ────────────────────────────────────────────────────

#[test]
fn emission_receipt_json_fields() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let ctx = test_context(HighImpactAction::Sandbox);
    let receipt = emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap();
    let v: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("entry_id"));
    assert!(obj.contains_key("artifact_hash"));
    assert!(obj.contains_key("decision_type"));
    assert!(obj.contains_key("action"));
    assert!(obj.contains_key("trace_id"));
}

#[test]
fn emission_receipt_serde_roundtrip() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let ctx = test_context(HighImpactAction::Terminate);
    let receipt = emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap();
    let json = serde_json::to_vec(&receipt).unwrap();
    let back: EmissionReceipt = serde_json::from_slice(&json).unwrap();
    assert_eq!(receipt, back);
}

// ── StructuredLogEvent ─────────────────────────────────────────────────

#[test]
fn structured_log_event_json_fields() {
    let log = StructuredLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "success".to_string(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&log).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("trace_id"));
    assert!(obj.contains_key("decision_id"));
    assert!(obj.contains_key("policy_id"));
    assert!(obj.contains_key("component"));
    assert!(obj.contains_key("event"));
    assert!(obj.contains_key("outcome"));
    assert!(obj.contains_key("error_code"));
}

#[test]
fn structured_log_event_serde_roundtrip() {
    let log = StructuredLogEvent {
        trace_id: "t-rt".to_string(),
        decision_id: "d-rt".to_string(),
        policy_id: "p-rt".to_string(),
        component: "containment".to_string(),
        event: "evidence_emitted".to_string(),
        outcome: "success".to_string(),
        error_code: None,
    };
    let json = serde_json::to_vec(&log).unwrap();
    let back: StructuredLogEvent = serde_json::from_slice(&json).unwrap();
    assert_eq!(log, back);
}

// ── Emitter lifecycle ──────────────────────────────────────────────────

#[test]
fn emitter_new_is_empty() {
    let emitter = CanonicalEvidenceEmitter::with_defaults();
    assert_eq!(emitter.ledger_len(), 0);
    assert!(emitter.ledger().is_empty());
    assert!(emitter.receipts().is_empty());
    assert!(emitter.log_events().is_empty());
}

#[test]
fn emitter_emit_increments_ledger() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let ctx = test_context(HighImpactAction::ExtensionLoad);
    let receipt = emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap();
    assert_eq!(emitter.ledger_len(), 1);
    assert_eq!(emitter.receipts().len(), 1);
    assert_eq!(receipt.action, HighImpactAction::ExtensionLoad);
    assert_eq!(receipt.trace_id, "trace-enrich");
}

#[test]
fn emitter_emit_missing_trace_id_errors() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let mut ctx = test_context(HighImpactAction::Sandbox);
    ctx.trace_id = String::new();
    let err = emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap_err();
    assert!(matches!(err, EmissionError::MissingField { .. }));
}

#[test]
fn emitter_emit_missing_decision_id_errors() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let mut ctx = test_context(HighImpactAction::Sandbox);
    ctx.decision_id = String::new();
    let err = emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap_err();
    assert!(matches!(err, EmissionError::MissingField { .. }));
}

#[test]
fn emitter_emit_missing_policy_id_errors() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let mut ctx = test_context(HighImpactAction::Sandbox);
    ctx.policy_id = String::new();
    let err = emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap_err();
    assert!(matches!(err, EmissionError::MissingField { .. }));
}

#[test]
fn emitter_ledger_failure_returns_error() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emitter.set_failed(true);
    let ctx = test_context(HighImpactAction::Sandbox);
    let err = emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap_err();
    assert!(matches!(err, EmissionError::LedgerWriteFailure { .. }));
}

#[test]
fn emitter_buffer_full_returns_error() {
    let policy = EmissionPolicy {
        buffer_capacity: 1,
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    // Fill the buffer
    let ctx1 = test_context(HighImpactAction::Sandbox);
    emitter
        .emit(
            &ctx1,
            vec![],
            vec![],
            test_chosen(),
            vec![],
            BTreeMap::new(),
        )
        .unwrap();
    // Second emission should fail
    let ctx2 = EmissionContext {
        decision_id: "decision-2".to_string(),
        ..test_context(HighImpactAction::Terminate)
    };
    let err = emitter
        .emit(
            &ctx2,
            vec![],
            vec![],
            test_chosen(),
            vec![],
            BTreeMap::new(),
        )
        .unwrap_err();
    assert!(matches!(err, EmissionError::BufferFull { .. }));
}

#[test]
fn emitter_not_required_action_errors() {
    let policy = EmissionPolicy {
        mandatory_actions: vec![HighImpactAction::Sandbox],
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    let ctx = test_context(HighImpactAction::Terminate); // not in mandatory
    let err = emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap_err();
    assert!(matches!(err, EmissionError::NotRequired { .. }));
}

#[test]
fn emitter_clear_resets() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let ctx = test_context(HighImpactAction::Sandbox);
    emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap();
    assert_eq!(emitter.ledger_len(), 1);
    emitter.clear();
    assert_eq!(emitter.ledger_len(), 0);
    assert!(emitter.receipts().is_empty());
    assert!(emitter.log_events().is_empty());
}

#[test]
fn emitter_entries_by_trace() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let ctx = test_context(HighImpactAction::Sandbox);
    emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap();
    let entries = emitter.entries_by_trace("trace-enrich");
    assert_eq!(entries.len(), 1);
    let empty = emitter.entries_by_trace("nonexistent");
    assert!(empty.is_empty());
}

#[test]
fn emitter_log_events_emitted() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let ctx = test_context(HighImpactAction::CapabilityGrant);
    emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap();
    let logs = emitter.log_events();
    assert!(!logs.is_empty());
    assert_eq!(logs[0].trace_id, "trace-enrich");
    assert_eq!(logs[0].outcome, "success");
}

#[test]
fn emitter_verify_integrity() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let ctx = test_context(HighImpactAction::Revocation);
    let receipt = emitter
        .emit(&ctx, vec![], vec![], test_chosen(), vec![], BTreeMap::new())
        .unwrap();
    let entry = &emitter.ledger()[0];
    let hash = emitter.verify_integrity(entry).unwrap();
    assert_eq!(hash, receipt.artifact_hash);
}
