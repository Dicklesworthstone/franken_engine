#![forbid(unsafe_code)]

//! Integration tests for the `canonical_evidence_emitter` module.
//!
//! Covers emission context validation, policy enforcement, buffer capacity,
//! ledger failure simulation, witness/candidate truncation, metadata injection,
//! idempotent deduplication, structured logging, integrity verification,
//! and cross-action coverage across all 20 `HighImpactAction` variants.

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

use frankenengine_engine::canonical_evidence_emitter::{
    CanonicalEvidenceEmitter, EmissionContext, EmissionError, EmissionPolicy, EmissionReceipt,
    HighImpactAction, StructuredLogEvent,
};
use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, Constraint, DecisionType, Witness,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_context(action: HighImpactAction) -> EmissionContext {
    EmissionContext {
        trace_id: "trace-001".to_string(),
        decision_id: "dec-001".to_string(),
        policy_id: "pol-001".to_string(),
        epoch: SecurityEpoch::GENESIS,
        timestamp_ns: 1_000_000,
        action,
        target_id: "ext-001".to_string(),
    }
}

fn test_context_with_trace(action: HighImpactAction, trace_id: &str) -> EmissionContext {
    EmissionContext {
        trace_id: trace_id.to_string(),
        decision_id: format!("dec-{trace_id}"),
        policy_id: "pol-001".to_string(),
        epoch: SecurityEpoch::GENESIS,
        timestamp_ns: 2_000_000,
        action,
        target_id: "ext-002".to_string(),
    }
}

fn test_candidates() -> Vec<CandidateAction> {
    vec![
        CandidateAction::new("allow", 100_000),
        CandidateAction::new("sandbox", 300_000),
        CandidateAction::new("terminate", 800_000),
    ]
}

fn test_constraints() -> Vec<Constraint> {
    vec![Constraint {
        constraint_id: "max-risk".to_string(),
        description: "risk threshold exceeded".to_string(),
        active: true,
    }]
}

fn test_chosen() -> ChosenAction {
    ChosenAction {
        action_name: "sandbox".to_string(),
        expected_loss_millionths: 300_000,
        rationale: "proportional response to elevated risk".to_string(),
    }
}

fn test_witnesses() -> Vec<Witness> {
    vec![
        Witness {
            witness_id: "w-001".to_string(),
            witness_type: "posterior".to_string(),
            value: "P(malicious)=0.35".to_string(),
        },
        Witness {
            witness_id: "w-002".to_string(),
            witness_type: "hostcall_rate".to_string(),
            value: "500_calls_per_sec".to_string(),
        },
    ]
}

fn test_metadata() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("extension_version".to_string(), "1.2.3".to_string());
    m
}

fn emit_standard(emitter: &mut CanonicalEvidenceEmitter) -> EmissionReceipt {
    emitter
        .emit(
            &test_context(HighImpactAction::Sandbox),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap()
}

fn emit_for_action(
    emitter: &mut CanonicalEvidenceEmitter,
    action: HighImpactAction,
) -> EmissionReceipt {
    emitter
        .emit(
            &test_context(action),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap()
}

// ---------------------------------------------------------------------------
// 1. Basic emission and receipt fields
// ---------------------------------------------------------------------------

#[test]
fn emit_returns_receipt_with_correct_action() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let receipt = emit_standard(&mut emitter);
    assert_eq!(receipt.action, HighImpactAction::Sandbox);
}

#[test]
fn emit_returns_receipt_with_correct_trace_id() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let receipt = emit_standard(&mut emitter);
    assert_eq!(receipt.trace_id, "trace-001");
}

#[test]
fn emit_returns_receipt_with_correct_decision_type() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let receipt = emit_standard(&mut emitter);
    assert_eq!(receipt.decision_type, DecisionType::SecurityAction);
}

#[test]
fn emit_receipt_entry_id_is_nonempty() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let receipt = emit_standard(&mut emitter);
    assert!(!receipt.entry_id.is_empty());
    assert!(receipt.entry_id.starts_with("ev-"));
}

// ---------------------------------------------------------------------------
// 2. Ledger state after emission
// ---------------------------------------------------------------------------

#[test]
fn ledger_len_increments_after_emit() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    assert_eq!(emitter.ledger_len(), 0);
    emit_standard(&mut emitter);
    assert_eq!(emitter.ledger_len(), 1);
}

#[test]
fn ledger_entries_match_emitted_receipts() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let receipt = emit_standard(&mut emitter);
    let entries = emitter.ledger();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].entry_id, receipt.entry_id);
}

#[test]
fn receipts_accumulate_across_multiple_emissions() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_for_action(&mut emitter, HighImpactAction::Sandbox);
    emit_for_action(&mut emitter, HighImpactAction::Terminate);
    emit_for_action(&mut emitter, HighImpactAction::Quarantine);
    assert_eq!(emitter.receipts().len(), 3);
    assert_eq!(emitter.ledger_len(), 3);
}

// ---------------------------------------------------------------------------
// 3. Context validation: missing fields
// ---------------------------------------------------------------------------

#[test]
fn emit_fails_on_empty_trace_id() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let mut ctx = test_context(HighImpactAction::Sandbox);
    ctx.trace_id = String::new();
    let result = emitter.emit(
        &ctx,
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(matches!(
        result,
        Err(EmissionError::MissingField { ref field }) if field == "trace_id"
    ));
}

#[test]
fn emit_fails_on_empty_decision_id() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let mut ctx = test_context(HighImpactAction::Sandbox);
    ctx.decision_id = String::new();
    let result = emitter.emit(
        &ctx,
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(matches!(
        result,
        Err(EmissionError::MissingField { ref field }) if field == "decision_id"
    ));
}

#[test]
fn emit_fails_on_empty_policy_id() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let mut ctx = test_context(HighImpactAction::Sandbox);
    ctx.policy_id = String::new();
    let result = emitter.emit(
        &ctx,
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(matches!(
        result,
        Err(EmissionError::MissingField { ref field }) if field == "policy_id"
    ));
}

// ---------------------------------------------------------------------------
// 4. Emission policy: NotRequired error
// ---------------------------------------------------------------------------

#[test]
fn emit_fails_when_action_not_in_mandatory_set() {
    let policy = EmissionPolicy {
        mandatory_actions: vec![HighImpactAction::Sandbox],
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    let ctx = test_context(HighImpactAction::Terminate);
    let result = emitter.emit(
        &ctx,
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(matches!(
        result,
        Err(EmissionError::NotRequired { action }) if action == HighImpactAction::Terminate
    ));
}

#[test]
fn emit_succeeds_when_action_is_in_mandatory_set() {
    let policy = EmissionPolicy {
        mandatory_actions: vec![HighImpactAction::Terminate],
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    let ctx = test_context(HighImpactAction::Terminate);
    let result = emitter.emit(
        &ctx,
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(result.is_ok());
}

#[test]
fn empty_mandatory_set_rejects_all_actions() {
    let policy = EmissionPolicy {
        mandatory_actions: vec![],
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    for action in HighImpactAction::ALL {
        let ctx = test_context(action);
        let result = emitter.emit(
            &ctx,
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        );
        assert!(matches!(result, Err(EmissionError::NotRequired { .. })));
    }
}

// ---------------------------------------------------------------------------
// 5. Buffer capacity: BufferFull error
// ---------------------------------------------------------------------------

#[test]
fn emit_fails_when_buffer_is_full() {
    let policy = EmissionPolicy {
        buffer_capacity: 2,
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);

    // Fill to capacity with distinct entries.
    emitter
        .emit(
            &test_context_with_trace(HighImpactAction::Sandbox, "t-a"),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();
    emitter
        .emit(
            &test_context_with_trace(HighImpactAction::Terminate, "t-b"),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();

    // Third emission should fail.
    let result = emitter.emit(
        &test_context_with_trace(HighImpactAction::Quarantine, "t-c"),
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(matches!(
        result,
        Err(EmissionError::BufferFull { capacity: 2 })
    ));
}

#[test]
fn buffer_full_does_not_add_entry_to_ledger() {
    let policy = EmissionPolicy {
        buffer_capacity: 1,
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    emit_standard(&mut emitter);
    let _ = emitter.emit(
        &test_context_with_trace(HighImpactAction::Terminate, "t-x"),
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert_eq!(emitter.ledger_len(), 1);
}

// ---------------------------------------------------------------------------
// 6. Ledger failure simulation
// ---------------------------------------------------------------------------

#[test]
fn emit_fails_when_ledger_is_failed() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emitter.set_failed(true);
    let result = emitter.emit(
        &test_context(HighImpactAction::Sandbox),
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(matches!(
        result,
        Err(EmissionError::LedgerWriteFailure { .. })
    ));
}

#[test]
fn set_failed_false_recovers_ledger() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emitter.set_failed(true);
    let _ = emitter.emit(
        &test_context(HighImpactAction::Sandbox),
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    emitter.set_failed(false);
    let result = emitter.emit(
        &test_context(HighImpactAction::Sandbox),
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// 7. Witness and candidate truncation
// ---------------------------------------------------------------------------

#[test]
fn witnesses_are_truncated_to_policy_max() {
    let policy = EmissionPolicy {
        max_witnesses: 1,
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    let receipt = emitter
        .emit(
            &test_context(HighImpactAction::Sandbox),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(), // 2 witnesses, limit is 1
            test_metadata(),
        )
        .unwrap();
    let entry = emitter
        .ledger()
        .iter()
        .find(|e| e.entry_id == receipt.entry_id)
        .unwrap();
    assert_eq!(entry.witnesses.len(), 1);
    assert_eq!(entry.witnesses[0].witness_id, "w-001");
}

#[test]
fn candidates_are_truncated_to_policy_max() {
    let policy = EmissionPolicy {
        max_candidates: 2,
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    let receipt = emitter
        .emit(
            &test_context(HighImpactAction::Sandbox),
            test_candidates(), // 3 candidates, limit is 2
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();
    let entry = emitter
        .ledger()
        .iter()
        .find(|e| e.entry_id == receipt.entry_id)
        .unwrap();
    assert_eq!(entry.candidates.len(), 2);
}

#[test]
fn zero_max_witnesses_produces_entry_with_no_witnesses() {
    let policy = EmissionPolicy {
        max_witnesses: 0,
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    let receipt = emitter
        .emit(
            &test_context(HighImpactAction::Sandbox),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();
    let entry = emitter
        .ledger()
        .iter()
        .find(|e| e.entry_id == receipt.entry_id)
        .unwrap();
    assert!(entry.witnesses.is_empty());
}

#[test]
fn zero_max_candidates_produces_entry_with_no_candidates() {
    let policy = EmissionPolicy {
        max_candidates: 0,
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    let receipt = emitter
        .emit(
            &test_context(HighImpactAction::Sandbox),
            vec![], // no candidates provided
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();
    let entry = emitter
        .ledger()
        .iter()
        .find(|e| e.entry_id == receipt.entry_id)
        .unwrap();
    assert!(entry.candidates.is_empty());
}

// ---------------------------------------------------------------------------
// 8. Metadata injection via include_metadata policy
// ---------------------------------------------------------------------------

#[test]
fn include_metadata_true_adds_action_target_component() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let receipt = emit_standard(&mut emitter);
    let entry = emitter
        .ledger()
        .iter()
        .find(|e| e.entry_id == receipt.entry_id)
        .unwrap();
    assert_eq!(
        entry.metadata.get("action").map(|s| s.as_str()),
        Some("sandbox")
    );
    assert_eq!(
        entry.metadata.get("target_id").map(|s| s.as_str()),
        Some("ext-001")
    );
    assert_eq!(
        entry.metadata.get("component").map(|s| s.as_str()),
        Some("containment")
    );
}

#[test]
fn include_metadata_false_does_not_add_auto_fields() {
    let policy = EmissionPolicy {
        include_metadata: false,
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    let receipt = emitter
        .emit(
            &test_context(HighImpactAction::Sandbox),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            BTreeMap::new(),
        )
        .unwrap();
    let entry = emitter
        .ledger()
        .iter()
        .find(|e| e.entry_id == receipt.entry_id)
        .unwrap();
    assert!(!entry.metadata.contains_key("action"));
    assert!(!entry.metadata.contains_key("target_id"));
    assert!(!entry.metadata.contains_key("component"));
}

#[test]
fn user_metadata_preserved_alongside_auto_metadata() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let receipt = emit_standard(&mut emitter);
    let entry = emitter
        .ledger()
        .iter()
        .find(|e| e.entry_id == receipt.entry_id)
        .unwrap();
    // test_metadata inserts "extension_version" => "1.2.3"
    assert_eq!(
        entry.metadata.get("extension_version").map(|s| s.as_str()),
        Some("1.2.3")
    );
    // Auto-metadata also present.
    assert!(entry.metadata.contains_key("action"));
}

// ---------------------------------------------------------------------------
// 9. Structured log events
// ---------------------------------------------------------------------------

#[test]
fn successful_emit_produces_log_event() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    let logs = emitter.log_events();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].event, "evidence_emitted");
    assert_eq!(logs[0].outcome, "success");
    assert!(logs[0].error_code.is_none());
}

#[test]
fn failed_emit_produces_log_with_failure_outcome() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emitter.set_failed(true);
    let _ = emitter.emit(
        &test_context(HighImpactAction::Sandbox),
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    let logs = emitter.log_events();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].outcome, "failure");
    assert_eq!(logs[0].error_code.as_deref(), Some("ledger_failed"));
}

#[test]
fn buffer_full_produces_log_event() {
    let policy = EmissionPolicy {
        buffer_capacity: 0,
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    let _ = emitter.emit(
        &test_context(HighImpactAction::Sandbox),
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    let logs = emitter.log_events();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].event, "buffer_full");
}

#[test]
fn log_event_trace_id_matches_context() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let ctx = test_context_with_trace(HighImpactAction::Sandbox, "trace-xyz");
    emitter
        .emit(
            &ctx,
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();
    assert_eq!(emitter.log_events()[0].trace_id, "trace-xyz");
}

#[test]
fn log_event_component_matches_action() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let ctx = test_context(HighImpactAction::PolicyUpdate);
    emitter
        .emit(
            &ctx,
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();
    assert_eq!(emitter.log_events()[0].component, "policy");
}

// ---------------------------------------------------------------------------
// 10. Integrity verification
// ---------------------------------------------------------------------------

#[test]
fn verify_integrity_returns_matching_artifact_hash() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let receipt = emit_standard(&mut emitter);
    let entry = &emitter.ledger()[0];
    let recomputed = emitter.verify_integrity(entry).unwrap();
    assert_eq!(recomputed, receipt.artifact_hash);
}

#[test]
fn verify_integrity_is_deterministic() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    let entry = &emitter.ledger()[0];
    let hash1 = emitter.verify_integrity(entry).unwrap();
    let hash2 = emitter.verify_integrity(entry).unwrap();
    assert_eq!(hash1, hash2);
}

// ---------------------------------------------------------------------------
// 11. Clear resets all state
// ---------------------------------------------------------------------------

#[test]
fn clear_resets_ledger() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    assert_eq!(emitter.ledger_len(), 1);
    emitter.clear();
    assert_eq!(emitter.ledger_len(), 0);
    assert!(emitter.receipts().is_empty());
    assert!(emitter.log_events().is_empty());
}

#[test]
fn clear_also_resets_failed_state() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emitter.set_failed(true);
    emitter.clear();
    // Should be able to emit after clear.
    let result = emitter.emit(
        &test_context(HighImpactAction::Sandbox),
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// 12. Entries by type and trace
// ---------------------------------------------------------------------------

#[test]
fn entries_by_type_returns_only_matching() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    // Sandbox -> SecurityAction, PolicyUpdate -> PolicyUpdate
    emit_for_action(&mut emitter, HighImpactAction::Sandbox);
    emitter
        .emit(
            &test_context_with_trace(HighImpactAction::PolicyUpdate, "trace-pu"),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();
    let security = emitter.entries_by_type(DecisionType::SecurityAction);
    assert_eq!(security.len(), 1);
    let policy = emitter.entries_by_type(DecisionType::PolicyUpdate);
    assert_eq!(policy.len(), 1);
}

#[test]
fn entries_by_trace_returns_only_matching() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emitter
        .emit(
            &test_context_with_trace(HighImpactAction::Sandbox, "trace-alpha"),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();
    emitter
        .emit(
            &test_context_with_trace(HighImpactAction::Terminate, "trace-beta"),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();
    let alpha = emitter.entries_by_trace("trace-alpha");
    assert_eq!(alpha.len(), 1);
    let beta = emitter.entries_by_trace("trace-beta");
    assert_eq!(beta.len(), 1);
    let none = emitter.entries_by_trace("trace-nonexistent");
    assert!(none.is_empty());
}

// ---------------------------------------------------------------------------
// 13. Policy accessor
// ---------------------------------------------------------------------------

#[test]
fn policy_returns_configured_policy() {
    let policy = EmissionPolicy {
        max_witnesses: 42,
        ..EmissionPolicy::default()
    };
    let emitter = CanonicalEvidenceEmitter::new(policy.clone());
    assert_eq!(emitter.policy().max_witnesses, 42);
}

#[test]
fn with_defaults_uses_default_policy() {
    let emitter = CanonicalEvidenceEmitter::with_defaults();
    let policy = emitter.policy();
    assert_eq!(policy.mandatory_actions.len(), 20);
    assert_eq!(policy.max_witnesses, 256);
    assert_eq!(policy.max_candidates, 64);
    assert!(policy.include_metadata);
    assert_eq!(policy.buffer_capacity, 1024);
}

// ---------------------------------------------------------------------------
// 14. HighImpactAction — exhaustive variant coverage
// ---------------------------------------------------------------------------

#[test]
fn all_20_actions_emit_successfully_with_default_policy() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    for (i, action) in HighImpactAction::ALL.iter().enumerate() {
        let ctx = EmissionContext {
            trace_id: format!("trace-{i:03}"),
            decision_id: format!("dec-{i:03}"),
            policy_id: "pol-all".to_string(),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: (i as u64) * 1_000,
            action: *action,
            target_id: format!("target-{i:03}"),
        };
        let result = emitter.emit(
            &ctx,
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        );
        assert!(result.is_ok(), "failed for action {action}");
    }
    assert_eq!(emitter.ledger_len(), 20);
}

#[test]
fn all_variants_have_nonempty_display() {
    for action in HighImpactAction::ALL {
        let display = action.to_string();
        assert!(!display.is_empty(), "empty display for {action:?}");
    }
}

#[test]
fn all_variants_have_nonempty_component() {
    for action in HighImpactAction::ALL {
        assert!(
            !action.component().is_empty(),
            "empty component for {action:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 15. Decision type mapping correctness
// ---------------------------------------------------------------------------

#[test]
fn security_containment_actions_map_to_security_action() {
    for action in [
        HighImpactAction::Sandbox,
        HighImpactAction::Suspend,
        HighImpactAction::Terminate,
        HighImpactAction::Quarantine,
        HighImpactAction::Cancellation,
    ] {
        assert_eq!(
            action.decision_type(),
            DecisionType::SecurityAction,
            "wrong decision type for {action}"
        );
    }
}

#[test]
fn lifecycle_actions_map_to_extension_lifecycle() {
    for action in [
        HighImpactAction::ExtensionLoad,
        HighImpactAction::ExtensionUnload,
        HighImpactAction::ExtensionStart,
        HighImpactAction::ExtensionStop,
        HighImpactAction::RegionCreate,
        HighImpactAction::RegionDestroy,
    ] {
        assert_eq!(
            action.decision_type(),
            DecisionType::ExtensionLifecycle,
            "wrong decision type for {action}"
        );
    }
}

#[test]
fn obligation_actions_map_to_contract_evaluation() {
    for action in [
        HighImpactAction::ObligationCreate,
        HighImpactAction::ObligationFulfill,
        HighImpactAction::ObligationFailure,
        HighImpactAction::ContractEvaluation,
    ] {
        assert_eq!(
            action.decision_type(),
            DecisionType::ContractEvaluation,
            "wrong decision type for {action}"
        );
    }
}

#[test]
fn capability_grant_maps_to_capability_decision() {
    assert_eq!(
        HighImpactAction::CapabilityGrant.decision_type(),
        DecisionType::CapabilityDecision
    );
}

#[test]
fn revocation_maps_to_revocation_type() {
    assert_eq!(
        HighImpactAction::Revocation.decision_type(),
        DecisionType::Revocation
    );
}

#[test]
fn policy_update_maps_to_policy_update_type() {
    assert_eq!(
        HighImpactAction::PolicyUpdate.decision_type(),
        DecisionType::PolicyUpdate
    );
}

#[test]
fn epoch_transition_maps_to_epoch_transition_type() {
    assert_eq!(
        HighImpactAction::EpochTransition.decision_type(),
        DecisionType::EpochTransition
    );
}

#[test]
fn remote_authorization_maps_to_remote_authorization_type() {
    assert_eq!(
        HighImpactAction::RemoteAuthorization.decision_type(),
        DecisionType::RemoteAuthorization
    );
}

// ---------------------------------------------------------------------------
// 16. Component mapping correctness
// ---------------------------------------------------------------------------

#[test]
fn containment_component_for_security_actions() {
    for action in [
        HighImpactAction::Sandbox,
        HighImpactAction::Suspend,
        HighImpactAction::Terminate,
        HighImpactAction::Quarantine,
    ] {
        assert_eq!(action.component(), "containment");
    }
}

#[test]
fn lifecycle_component_for_extension_actions() {
    for action in [
        HighImpactAction::ExtensionLoad,
        HighImpactAction::ExtensionUnload,
        HighImpactAction::ExtensionStart,
        HighImpactAction::ExtensionStop,
    ] {
        assert_eq!(action.component(), "lifecycle");
    }
}

#[test]
fn region_component() {
    assert_eq!(HighImpactAction::RegionCreate.component(), "region");
    assert_eq!(HighImpactAction::RegionDestroy.component(), "region");
}

#[test]
fn cancellation_component() {
    assert_eq!(HighImpactAction::Cancellation.component(), "cancellation");
}

// ---------------------------------------------------------------------------
// 17. Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn emission_context_serde_roundtrip() {
    let ctx = test_context(HighImpactAction::Sandbox);
    let json = serde_json::to_string(&ctx).unwrap();
    let deserialized: EmissionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, deserialized);
}

#[test]
fn emission_policy_serde_roundtrip() {
    let policy = EmissionPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let deserialized: EmissionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, deserialized);
}

#[test]
fn emission_error_serde_roundtrip() {
    let errors = vec![
        EmissionError::MissingField {
            field: "trace_id".to_string(),
        },
        EmissionError::LedgerWriteFailure {
            reason: "disk full".to_string(),
        },
        EmissionError::ValidationFailure {
            reason: "bad".to_string(),
        },
        EmissionError::BufferFull { capacity: 100 },
        EmissionError::NotRequired {
            action: HighImpactAction::Sandbox,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let deserialized: EmissionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, deserialized);
    }
}

#[test]
fn emission_receipt_serde_roundtrip() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let receipt = emit_standard(&mut emitter);
    let json = serde_json::to_string(&receipt).unwrap();
    let deserialized: EmissionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, deserialized);
}

#[test]
fn structured_log_event_serde_roundtrip() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    let log = &emitter.log_events()[0];
    let json = serde_json::to_string(log).unwrap();
    let deserialized: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(*log, deserialized);
}

#[test]
fn high_impact_action_serde_roundtrip_all_variants() {
    for action in HighImpactAction::ALL {
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: HighImpactAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, deserialized);
    }
}

// ---------------------------------------------------------------------------
// 18. EmissionError Display formatting
// ---------------------------------------------------------------------------

#[test]
fn error_display_missing_field() {
    let err = EmissionError::MissingField {
        field: "trace_id".to_string(),
    };
    assert_eq!(err.to_string(), "missing required field: trace_id");
}

#[test]
fn error_display_ledger_write_failure() {
    let err = EmissionError::LedgerWriteFailure {
        reason: "disk full".to_string(),
    };
    assert_eq!(err.to_string(), "ledger write failure: disk full");
}

#[test]
fn error_display_buffer_full() {
    let err = EmissionError::BufferFull { capacity: 512 };
    assert_eq!(err.to_string(), "emission buffer full (capacity=512)");
}

#[test]
fn error_display_not_required() {
    let err = EmissionError::NotRequired {
        action: HighImpactAction::Sandbox,
    };
    assert_eq!(err.to_string(), "evidence not required for sandbox");
}

#[test]
fn error_display_validation_failure() {
    let err = EmissionError::ValidationFailure {
        reason: "bad schema".to_string(),
    };
    assert_eq!(err.to_string(), "validation failure: bad schema");
}

// ---------------------------------------------------------------------------
// 19. Edge cases: empty witnesses, candidates, constraints, metadata
// ---------------------------------------------------------------------------

#[test]
fn emit_with_empty_witnesses_succeeds() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let result = emitter.emit(
        &test_context(HighImpactAction::Sandbox),
        test_candidates(),
        test_constraints(),
        test_chosen(),
        vec![],
        test_metadata(),
    );
    assert!(result.is_ok());
}

#[test]
fn emit_with_empty_candidates_succeeds() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let result = emitter.emit(
        &test_context(HighImpactAction::Sandbox),
        vec![],
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(result.is_ok());
}

#[test]
fn emit_with_empty_constraints_succeeds() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let result = emitter.emit(
        &test_context(HighImpactAction::Sandbox),
        test_candidates(),
        vec![],
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    assert!(result.is_ok());
}

#[test]
fn emit_with_empty_metadata_succeeds() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let result = emitter.emit(
        &test_context(HighImpactAction::Sandbox),
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        BTreeMap::new(),
    );
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// 20. Artifact hash determinism
// ---------------------------------------------------------------------------

#[test]
fn artifact_hash_is_nonzero() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let receipt = emit_standard(&mut emitter);
    // ContentHash::compute on non-empty data should produce non-trivial hash.
    let zero_hash = ContentHash::compute(&[]);
    assert_ne!(receipt.artifact_hash, zero_hash);
}

#[test]
fn different_actions_produce_different_artifact_hashes() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    let r1 = emit_for_action(&mut emitter, HighImpactAction::Sandbox);
    let r2 = emitter
        .emit(
            &test_context_with_trace(HighImpactAction::Terminate, "trace-diff"),
            test_candidates(),
            test_constraints(),
            test_chosen(),
            test_witnesses(),
            test_metadata(),
        )
        .unwrap();
    assert_ne!(r1.artifact_hash, r2.artifact_hash);
}

// ---------------------------------------------------------------------------
// 21. HighImpactAction Ord + Copy + Eq
// ---------------------------------------------------------------------------

#[test]
fn high_impact_action_is_copy() {
    let a = HighImpactAction::Sandbox;
    let b = a; // Copy
    assert_eq!(a, b);
}

#[test]
fn high_impact_action_ord_is_consistent() {
    let mut actions: Vec<HighImpactAction> = HighImpactAction::ALL.to_vec();
    actions.sort();
    // Just verify it doesn't panic and produces deterministic order.
    let mut actions2 = actions.clone();
    actions2.sort();
    assert_eq!(actions, actions2);
}

// ---------------------------------------------------------------------------
// 22. Emission policy requires_evidence
// ---------------------------------------------------------------------------

#[test]
fn requires_evidence_returns_true_for_mandatory_action() {
    let policy = EmissionPolicy::default();
    assert!(policy.requires_evidence(HighImpactAction::Sandbox));
}

#[test]
fn requires_evidence_returns_false_for_non_mandatory_action() {
    let policy = EmissionPolicy {
        mandatory_actions: vec![HighImpactAction::Sandbox],
        ..EmissionPolicy::default()
    };
    assert!(!policy.requires_evidence(HighImpactAction::Terminate));
}

// ---------------------------------------------------------------------------
// 23. Validation order: policy check before context validation
// ---------------------------------------------------------------------------

#[test]
fn not_required_error_takes_precedence_over_missing_field() {
    let policy = EmissionPolicy {
        mandatory_actions: vec![HighImpactAction::Sandbox],
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    // Terminate is not mandatory, and trace_id is empty.
    let mut ctx = test_context(HighImpactAction::Terminate);
    ctx.trace_id = String::new();
    let result = emitter.emit(
        &ctx,
        test_candidates(),
        test_constraints(),
        test_chosen(),
        test_witnesses(),
        test_metadata(),
    );
    // NotRequired should come first.
    assert!(matches!(result, Err(EmissionError::NotRequired { .. })));
}

// ---------------------------------------------------------------------------
// 24. Multiple emissions with different traces
// ---------------------------------------------------------------------------

#[test]
fn multiple_traces_are_independently_queryable() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    for i in 0..5 {
        let ctx = EmissionContext {
            trace_id: format!("trace-{i}"),
            decision_id: format!("dec-{i}"),
            policy_id: "pol-001".to_string(),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: i * 1_000,
            action: HighImpactAction::Sandbox,
            target_id: format!("ext-{i}"),
        };
        emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                test_metadata(),
            )
            .unwrap();
    }
    assert_eq!(emitter.ledger_len(), 5);
    for i in 0..5 {
        let entries = emitter.entries_by_trace(&format!("trace-{i}"));
        assert_eq!(entries.len(), 1);
    }
}

// ---------------------------------------------------------------------------
// 25. Entries by type with no matches
// ---------------------------------------------------------------------------

#[test]
fn entries_by_type_returns_empty_for_unmatched_type() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_for_action(&mut emitter, HighImpactAction::Sandbox); // SecurityAction
    let epoch_entries = emitter.entries_by_type(DecisionType::EpochTransition);
    assert!(epoch_entries.is_empty());
}

// ---------------------------------------------------------------------------
// 26. Large-scale emission: many entries
// ---------------------------------------------------------------------------

#[test]
fn emit_100_entries_all_stored() {
    let policy = EmissionPolicy {
        buffer_capacity: 200,
        ..EmissionPolicy::default()
    };
    let mut emitter = CanonicalEvidenceEmitter::new(policy);
    for i in 0..100 {
        let ctx = EmissionContext {
            trace_id: format!("trace-{i:04}"),
            decision_id: format!("dec-{i:04}"),
            policy_id: "pol-bulk".to_string(),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: i * 100,
            action: HighImpactAction::ALL[i as usize % 20],
            target_id: format!("ext-{i:04}"),
        };
        emitter
            .emit(
                &ctx,
                test_candidates(),
                test_constraints(),
                test_chosen(),
                test_witnesses(),
                test_metadata(),
            )
            .unwrap();
    }
    assert_eq!(emitter.ledger_len(), 100);
    assert_eq!(emitter.receipts().len(), 100);
    assert_eq!(emitter.log_events().len(), 100);
}

// ---------------------------------------------------------------------------
// 27. Entry fields correctness
// ---------------------------------------------------------------------------

#[test]
fn entry_trace_id_matches_context() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    let entry = &emitter.ledger()[0];
    assert_eq!(entry.trace_id, "trace-001");
}

#[test]
fn entry_decision_id_matches_context() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    let entry = &emitter.ledger()[0];
    assert_eq!(entry.decision_id, "dec-001");
}

#[test]
fn entry_policy_id_matches_context() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    let entry = &emitter.ledger()[0];
    assert_eq!(entry.policy_id, "pol-001");
}

#[test]
fn entry_decision_type_matches_action() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    let entry = &emitter.ledger()[0];
    assert_eq!(entry.decision_type, DecisionType::SecurityAction);
}

#[test]
fn entry_chosen_action_matches_input() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    let entry = &emitter.ledger()[0];
    assert_eq!(entry.chosen_action.action_name, "sandbox");
    assert_eq!(entry.chosen_action.expected_loss_millionths, 300_000);
}

#[test]
fn entry_constraints_match_input() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    let entry = &emitter.ledger()[0];
    assert_eq!(entry.constraints.len(), 1);
    assert_eq!(entry.constraints[0].constraint_id, "max-risk");
    assert!(entry.constraints[0].active);
}

#[test]
fn entry_timestamp_matches_context() {
    let mut emitter = CanonicalEvidenceEmitter::with_defaults();
    emit_standard(&mut emitter);
    let entry = &emitter.ledger()[0];
    assert_eq!(entry.timestamp_ns, 1_000_000);
}
