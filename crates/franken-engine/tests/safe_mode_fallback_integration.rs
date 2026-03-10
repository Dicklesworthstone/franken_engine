#![forbid(unsafe_code)]
//! Integration tests for the `safe_mode_fallback` module.
//!
//! Exercises deterministic safe-mode degradation, evidence ring-buffer
//! fallback, attestation-driven autonomy policies, and signed transition
//! receipts from outside the crate boundary.

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

use frankenengine_engine::safe_mode_fallback::{
    ActionTier, AttestationActionRequest, AttestationFallbackConfig, AttestationFallbackDecision,
    AttestationFallbackError, AttestationFallbackEvent, AttestationFallbackManager,
    AttestationFallbackState, AttestationHealth, AutonomousAction, EvidenceRingBuffer, FailureType,
    QueuedAttestationDecision, RingBufferEntry, SafeModeAction, SafeModeEvent, SafeModeManager,
    SafeModeStatus,
};

/// Mirror of the crate-private TEST_RING_BUFFER_CAPACITY constant.
const TEST_RING_BUFFER_CAPACITY: usize = 256;

// ===========================================================================
// 1. FailureType — display, ordering, serde
// ===========================================================================

#[test]
fn failure_type_display() {
    assert_eq!(
        FailureType::AdapterUnavailable.to_string(),
        "adapter_unavailable"
    );
    assert_eq!(
        FailureType::DecisionContractError.to_string(),
        "decision_contract_error"
    );
    assert_eq!(
        FailureType::EvidenceLedgerFull.to_string(),
        "evidence_ledger_full"
    );
    assert_eq!(FailureType::CxCorrupted.to_string(), "cx_corrupted");
    assert_eq!(
        FailureType::CancellationDeadlock.to_string(),
        "cancellation_deadlock"
    );
}

#[test]
fn failure_type_serde_round_trip() {
    for ft in [
        FailureType::AdapterUnavailable,
        FailureType::DecisionContractError,
        FailureType::EvidenceLedgerFull,
        FailureType::CxCorrupted,
        FailureType::CancellationDeadlock,
    ] {
        let json = serde_json::to_string(&ft).unwrap();
        let back: FailureType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ft);
    }
}

#[test]
fn failure_type_ordering() {
    let mut types = vec![
        FailureType::CancellationDeadlock,
        FailureType::AdapterUnavailable,
        FailureType::CxCorrupted,
    ];
    types.sort();
    // Ordering is derived, so just verify it's deterministic and stable
    let mut types2 = types.clone();
    types2.sort();
    assert_eq!(types, types2);
}

// ===========================================================================
// 2. SafeModeStatus — default, serde
// ===========================================================================

#[test]
fn safe_mode_status_default_is_normal() {
    assert_eq!(SafeModeStatus::default(), SafeModeStatus::Normal);
}

#[test]
fn safe_mode_status_serde_round_trip() {
    for s in [
        SafeModeStatus::Normal,
        SafeModeStatus::Active,
        SafeModeStatus::Recovering,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: SafeModeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

// ===========================================================================
// 3. SafeModeAction — failure_type mapping, serde
// ===========================================================================

#[test]
fn safe_mode_action_failure_type_mapping() {
    let a1 = SafeModeAction::RefuseExtensions {
        diagnostic: "test".into(),
    };
    assert_eq!(a1.failure_type(), FailureType::AdapterUnavailable);

    let a2 = SafeModeAction::DefaultDenyAndQuarantine {
        extension_id: "ext-1".into(),
        reason: "error".into(),
    };
    assert_eq!(a2.failure_type(), FailureType::DecisionContractError);

    let a3 = SafeModeAction::RingBufferFallback {
        capacity: 128,
        high_impact_blocked: true,
    };
    assert_eq!(a3.failure_type(), FailureType::EvidenceLedgerFull);

    let a4 = SafeModeAction::RejectAndRefreshCx {
        rejected_operation: "op".into(),
        corruption_detail: "detail".into(),
    };
    assert_eq!(a4.failure_type(), FailureType::CxCorrupted);

    let a5 = SafeModeAction::ForceFinalize {
        cell_id: "cell-1".into(),
        timeout_ticks: 100,
    };
    assert_eq!(a5.failure_type(), FailureType::CancellationDeadlock);
}

#[test]
fn safe_mode_action_serde_round_trip() {
    let action = SafeModeAction::DefaultDenyAndQuarantine {
        extension_id: "ext-42".into(),
        reason: "contract error".into(),
    };
    let json = serde_json::to_string(&action).unwrap();
    let back: SafeModeAction = serde_json::from_str(&json).unwrap();
    assert_eq!(back, action);
}

// ===========================================================================
// 4. SafeModeEvent — serde
// ===========================================================================

#[test]
fn safe_mode_event_serde_round_trip() {
    let event = SafeModeEvent {
        trace_id: "t-1".into(),
        failure_type: FailureType::AdapterUnavailable,
        phase: "activate".into(),
        action_summary: "refused extensions".into(),
        component: "safe_mode_fallback".into(),
        outcome: "safe_mode_active".into(),
        error_code: Some("FE-SM-001".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SafeModeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

// ===========================================================================
// 5. AttestationHealth — display, is_healthy, serde
// ===========================================================================

#[test]
fn attestation_health_display() {
    assert_eq!(AttestationHealth::Valid.to_string(), "valid");
    assert_eq!(
        AttestationHealth::VerificationFailed.to_string(),
        "verification_failed"
    );
    assert_eq!(AttestationHealth::EvidenceExpired.to_string(), "expired");
    assert_eq!(
        AttestationHealth::EvidenceUnavailable.to_string(),
        "unavailable"
    );
}

#[test]
fn attestation_health_is_healthy() {
    assert!(AttestationHealth::Valid.is_healthy());
    assert!(!AttestationHealth::VerificationFailed.is_healthy());
    assert!(!AttestationHealth::EvidenceExpired.is_healthy());
    assert!(!AttestationHealth::EvidenceUnavailable.is_healthy());
}

#[test]
fn attestation_health_serde_round_trip() {
    for h in [
        AttestationHealth::Valid,
        AttestationHealth::VerificationFailed,
        AttestationHealth::EvidenceExpired,
        AttestationHealth::EvidenceUnavailable,
    ] {
        let json = serde_json::to_string(&h).unwrap();
        let back: AttestationHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }
}

// ===========================================================================
// 6. ActionTier — display, ordering, serde
// ===========================================================================

#[test]
fn action_tier_display() {
    assert_eq!(ActionTier::HighImpact.to_string(), "high_impact");
    assert_eq!(ActionTier::Standard.to_string(), "standard");
    assert_eq!(ActionTier::LowImpact.to_string(), "low_impact");
}

#[test]
fn action_tier_serde_round_trip() {
    for t in [
        ActionTier::HighImpact,
        ActionTier::Standard,
        ActionTier::LowImpact,
    ] {
        let json = serde_json::to_string(&t).unwrap();
        let back: ActionTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}

// ===========================================================================
// 7. AutonomousAction — default_tier, display, serde
// ===========================================================================

#[test]
fn autonomous_action_default_tiers() {
    assert_eq!(
        AutonomousAction::Quarantine.default_tier(),
        ActionTier::HighImpact
    );
    assert_eq!(
        AutonomousAction::Terminate.default_tier(),
        ActionTier::HighImpact
    );
    assert_eq!(
        AutonomousAction::EmergencyGrant.default_tier(),
        ActionTier::HighImpact
    );
    assert_eq!(
        AutonomousAction::PolicyPromotion.default_tier(),
        ActionTier::HighImpact
    );
    assert_eq!(
        AutonomousAction::CapabilityEscalation.default_tier(),
        ActionTier::HighImpact
    );
    assert_eq!(
        AutonomousAction::RoutineMonitoring.default_tier(),
        ActionTier::Standard
    );
    assert_eq!(
        AutonomousAction::EvidenceCollection.default_tier(),
        ActionTier::Standard
    );
    assert_eq!(
        AutonomousAction::MetricsEmission.default_tier(),
        ActionTier::LowImpact
    );
}

#[test]
fn autonomous_action_display() {
    assert_eq!(AutonomousAction::Quarantine.to_string(), "quarantine");
    assert_eq!(AutonomousAction::Terminate.to_string(), "terminate");
    assert_eq!(
        AutonomousAction::MetricsEmission.to_string(),
        "metrics_emission"
    );
}

#[test]
fn autonomous_action_serde_round_trip() {
    for a in [
        AutonomousAction::Quarantine,
        AutonomousAction::Terminate,
        AutonomousAction::EmergencyGrant,
        AutonomousAction::PolicyPromotion,
        AutonomousAction::CapabilityEscalation,
        AutonomousAction::RoutineMonitoring,
        AutonomousAction::EvidenceCollection,
        AutonomousAction::MetricsEmission,
    ] {
        let json = serde_json::to_string(&a).unwrap();
        let back: AutonomousAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }
}

// ===========================================================================
// 8. AttestationFallbackState — default, display, serde
// ===========================================================================

#[test]
fn attestation_fallback_state_default_is_normal() {
    assert_eq!(
        AttestationFallbackState::default(),
        AttestationFallbackState::Normal
    );
}

#[test]
fn attestation_fallback_state_display() {
    assert_eq!(AttestationFallbackState::Normal.to_string(), "normal");
    assert_eq!(AttestationFallbackState::Degraded.to_string(), "degraded");
    assert_eq!(AttestationFallbackState::Restoring.to_string(), "restoring");
}

#[test]
fn attestation_fallback_state_serde_round_trip() {
    for s in [
        AttestationFallbackState::Normal,
        AttestationFallbackState::Degraded,
        AttestationFallbackState::Restoring,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: AttestationFallbackState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

// ===========================================================================
// 9. EvidenceRingBuffer — push, overflow, drain, serde
// ===========================================================================

fn make_entry(seq: u64) -> RingBufferEntry {
    RingBufferEntry {
        trace_id: format!("t-{seq}"),
        event: format!("event-{seq}"),
        outcome: "ok".into(),
        component: "test".into(),
        sequence: seq,
    }
}

#[test]
fn ring_buffer_new_is_empty() {
    let buf = EvidenceRingBuffer::new(16);
    assert!(buf.is_empty());
    assert_eq!(buf.len(), 0);
    assert_eq!(buf.total_written(), 0);
    assert!(buf.entries().is_empty());
}

#[test]
fn ring_buffer_push_and_read() {
    let mut buf = EvidenceRingBuffer::new(4);
    buf.push(make_entry(0));
    buf.push(make_entry(1));
    assert_eq!(buf.len(), 2);
    assert_eq!(buf.total_written(), 2);
    let entries = buf.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].sequence, 0);
    assert_eq!(entries[1].sequence, 1);
}

#[test]
fn ring_buffer_overflow_wraps() {
    let mut buf = EvidenceRingBuffer::new(3);
    for i in 0..5 {
        buf.push(make_entry(i));
    }
    assert_eq!(buf.len(), 3);
    assert_eq!(buf.total_written(), 5);
    let entries = buf.entries();
    // Oldest entries overwritten; should contain entries 2, 3, 4
    assert_eq!(entries.len(), 3);
    let seqs: Vec<u64> = entries.iter().map(|e| e.sequence).collect();
    assert_eq!(seqs, vec![2, 3, 4]);
}

#[test]
fn ring_buffer_drain_empties() {
    let mut buf = EvidenceRingBuffer::new(4);
    buf.push(make_entry(0));
    buf.push(make_entry(1));
    let drained = buf.drain();
    assert_eq!(drained.len(), 2);
    assert!(buf.is_empty());
    assert_eq!(buf.len(), 0);
    // total_written persists across drain
    assert_eq!(buf.total_written(), 2);
}

#[test]
fn ring_buffer_serde_round_trip() {
    let mut buf = EvidenceRingBuffer::new(8);
    buf.push(make_entry(0));
    buf.push(make_entry(1));
    let json = serde_json::to_string(&buf).unwrap();
    let back: EvidenceRingBuffer = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), buf.len());
    assert_eq!(back.total_written(), buf.total_written());
}

#[test]
fn ring_buffer_entry_serde_round_trip() {
    let entry = make_entry(42);
    let json = serde_json::to_string(&entry).unwrap();
    let back: RingBufferEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// 10. SafeModeManager — adapter unavailable lifecycle
// ===========================================================================

#[test]
fn manager_initial_state_normal() {
    let mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    assert!(!mgr.any_active());
    assert!(!mgr.extensions_refused());
    assert!(!mgr.high_impact_blocked());
    assert!(mgr.quarantined_extensions().is_empty());
    assert!(mgr.events().is_empty());
    assert_eq!(
        mgr.status(FailureType::AdapterUnavailable),
        SafeModeStatus::Normal
    );
}

#[test]
fn manager_handle_adapter_unavailable_activates() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    let action = mgr.handle_adapter_unavailable("t-1", "adapter down");
    assert!(matches!(action, SafeModeAction::RefuseExtensions { .. }));
    assert!(mgr.extensions_refused());
    assert!(mgr.any_active());
    assert_eq!(
        mgr.status(FailureType::AdapterUnavailable),
        SafeModeStatus::Active
    );
    assert_eq!(mgr.activation_count(FailureType::AdapterUnavailable), 1);
}

#[test]
fn manager_recover_adapter() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_adapter_unavailable("t-1", "adapter down");
    mgr.recover_adapter("t-2");
    assert!(!mgr.extensions_refused());
    assert!(!mgr.any_active());
    assert_eq!(mgr.recovery_count(FailureType::AdapterUnavailable), 1);
}

// ===========================================================================
// 11. SafeModeManager — decision contract error lifecycle
// ===========================================================================

#[test]
fn manager_handle_decision_contract_error_quarantines() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    let action = mgr.handle_decision_contract_error("t-1", "ext-bad", "FE-DC-001");
    assert!(matches!(
        action,
        SafeModeAction::DefaultDenyAndQuarantine { .. }
    ));
    assert!(mgr.quarantined_extensions().contains_key("ext-bad"));
    assert!(mgr.check_quarantine("ext-bad").is_some());
    assert!(mgr.check_quarantine("ext-good").is_none());
}

#[test]
fn manager_recover_decision_contract_unquarantines() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_decision_contract_error("t-1", "ext-bad", "FE-DC-001");
    mgr.recover_decision_contract("t-2", "ext-bad");
    assert!(!mgr.quarantined_extensions().contains_key("ext-bad"));
    assert!(mgr.check_quarantine("ext-bad").is_none());
}

#[test]
fn manager_multiple_quarantines() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_decision_contract_error("t-1", "ext-a", "FE-DC-001");
    mgr.handle_decision_contract_error("t-2", "ext-b", "FE-DC-002");
    assert_eq!(mgr.quarantined_extensions().len(), 2);
    mgr.recover_decision_contract("t-3", "ext-a");
    assert_eq!(mgr.quarantined_extensions().len(), 1);
    assert!(mgr.check_quarantine("ext-b").is_some());
}

// ===========================================================================
// 12. SafeModeManager — evidence ledger full lifecycle
// ===========================================================================

#[test]
fn manager_handle_evidence_ledger_full_activates_ring_buffer() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    let action = mgr.handle_evidence_ledger_full("t-1", "FE-EL-001");
    assert!(matches!(action, SafeModeAction::RingBufferFallback { .. }));
    assert!(mgr.high_impact_blocked());
    assert_eq!(
        mgr.status(FailureType::EvidenceLedgerFull),
        SafeModeStatus::Active
    );
}

#[test]
fn manager_write_ring_buffer_entry() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_evidence_ledger_full("t-1", "FE-EL-001");
    mgr.write_ring_buffer_entry("t-2", "evidence_event", "ok", "test_component");
    assert_eq!(mgr.ring_buffer().len(), 1);
    let entries = mgr.ring_buffer().entries();
    assert_eq!(entries[0].trace_id, "t-2");
    assert_eq!(entries[0].event, "evidence_event");
}

#[test]
fn manager_recover_evidence_ledger_drains() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_evidence_ledger_full("t-1", "FE-EL-001");
    mgr.write_ring_buffer_entry("t-2", "ev-1", "ok", "comp");
    mgr.write_ring_buffer_entry("t-3", "ev-2", "ok", "comp");
    let drained = mgr.recover_evidence_ledger("t-4");
    assert_eq!(drained.len(), 2);
    assert!(!mgr.high_impact_blocked());
    assert!(mgr.ring_buffer().is_empty());
}

// ===========================================================================
// 13. SafeModeManager — Cx corrupted lifecycle
// ===========================================================================

#[test]
fn manager_handle_cx_corrupted() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    let action = mgr.handle_cx_corrupted("t-1", "budget_check", "underflow detected");
    assert!(matches!(action, SafeModeAction::RejectAndRefreshCx { .. }));
    assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);
}

#[test]
fn manager_recover_cx() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_cx_corrupted("t-1", "budget_check", "underflow");
    mgr.recover_cx("t-2");
    assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Normal);
}

// ===========================================================================
// 14. SafeModeManager — cancellation deadlock lifecycle
// ===========================================================================

#[test]
fn manager_handle_cancellation_deadlock() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    let action = mgr.handle_cancellation_deadlock("t-1", "cell-42", 1000);
    assert!(matches!(action, SafeModeAction::ForceFinalize { .. }));
    if let SafeModeAction::ForceFinalize {
        cell_id,
        timeout_ticks,
    } = &action
    {
        assert_eq!(cell_id, "cell-42");
        assert_eq!(*timeout_ticks, 1000);
    }
}

#[test]
fn manager_recover_cancellation() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_cancellation_deadlock("t-1", "cell-42", 1000);
    mgr.recover_cancellation("t-2");
    assert_eq!(
        mgr.status(FailureType::CancellationDeadlock),
        SafeModeStatus::Normal
    );
}

// ===========================================================================
// 15. SafeModeManager — events and counts
// ===========================================================================

#[test]
fn manager_events_emitted_on_activation_and_recovery() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_adapter_unavailable("t-1", "down");
    mgr.recover_adapter("t-2");
    let events = mgr.events();
    assert!(events.len() >= 2);
    assert!(events.iter().any(|e| e.phase == "activate"));
    assert!(events.iter().any(|e| e.phase == "recover"));
}

#[test]
fn manager_drain_events() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_adapter_unavailable("t-1", "down");
    let drained = mgr.drain_events();
    assert!(!drained.is_empty());
    assert!(mgr.events().is_empty());
}

#[test]
fn manager_activation_count_increments() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_adapter_unavailable("t-1", "down");
    mgr.recover_adapter("t-2");
    mgr.handle_adapter_unavailable("t-3", "down again");
    assert_eq!(mgr.activation_count(FailureType::AdapterUnavailable), 2);
}

#[test]
fn manager_recovery_count_increments() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_adapter_unavailable("t-1", "down");
    mgr.recover_adapter("t-2");
    mgr.handle_adapter_unavailable("t-3", "down");
    mgr.recover_adapter("t-4");
    assert_eq!(mgr.recovery_count(FailureType::AdapterUnavailable), 2);
}

// ===========================================================================
// 16. SafeModeManager — cascading failures
// ===========================================================================

#[test]
fn manager_cascading_two_failures() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_adapter_unavailable("t-1", "down");
    mgr.handle_evidence_ledger_full("t-2", "FE-EL-001");
    assert!(mgr.any_active());
    assert!(mgr.extensions_refused());
    assert!(mgr.high_impact_blocked());

    // Recover one — still active because of the other
    mgr.recover_adapter("t-3");
    assert!(mgr.any_active());
    assert!(!mgr.extensions_refused());
    assert!(mgr.high_impact_blocked());

    // Recover second — all clear
    mgr.recover_evidence_ledger("t-4");
    assert!(!mgr.any_active());
}

#[test]
fn manager_all_five_failures_simultaneous() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_adapter_unavailable("t-1", "down");
    mgr.handle_decision_contract_error("t-2", "ext-1", "err");
    mgr.handle_evidence_ledger_full("t-3", "err");
    mgr.handle_cx_corrupted("t-4", "op", "detail");
    mgr.handle_cancellation_deadlock("t-5", "cell-1", 100);
    assert!(mgr.any_active());

    // All five failure types should be Active
    assert_eq!(
        mgr.status(FailureType::AdapterUnavailable),
        SafeModeStatus::Active
    );
    assert_eq!(
        mgr.status(FailureType::DecisionContractError),
        SafeModeStatus::Active
    );
    assert_eq!(
        mgr.status(FailureType::EvidenceLedgerFull),
        SafeModeStatus::Active
    );
    assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);
    assert_eq!(
        mgr.status(FailureType::CancellationDeadlock),
        SafeModeStatus::Active
    );
}

// ===========================================================================
// 17. SafeModeManager — check_action_blocked
// ===========================================================================

#[test]
fn manager_check_action_blocked_normal_mode() {
    let mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    assert!(mgr.check_action_blocked(true).is_none());
    assert!(mgr.check_action_blocked(false).is_none());
}

#[test]
fn manager_check_action_blocked_extensions_refused() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_adapter_unavailable("t-1", "down");
    // extensions_refused blocks actions
    assert!(mgr.check_action_blocked(true).is_some());
}

#[test]
fn manager_check_action_blocked_high_impact_only() {
    let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
    mgr.handle_evidence_ledger_full("t-1", "err");
    // High-impact blocked, but low-impact may still pass
    assert!(mgr.check_action_blocked(true).is_some());
}

// ===========================================================================
// 18. SafeModeManager — determinism
// ===========================================================================

#[test]
fn manager_deterministic_across_100_iterations() {
    let mut actions = Vec::new();
    for _ in 0..100 {
        let mut mgr = SafeModeManager::new(TEST_RING_BUFFER_CAPACITY);
        let a = mgr.handle_adapter_unavailable("t-1", "diag");
        actions.push(format!("{a:?}"));
    }
    let first = &actions[0];
    assert!(actions.iter().all(|a| a == first));
}

// ===========================================================================
// 19. AttestationActionRequest — construction, serde
// ===========================================================================

#[test]
fn attestation_action_request_new_uses_default_tier() {
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    assert_eq!(req.tier, ActionTier::HighImpact);

    let req2 =
        AttestationActionRequest::new("t-2", "d-2", "p-2", AutonomousAction::MetricsEmission, 2000);
    assert_eq!(req2.tier, ActionTier::LowImpact);
}

#[test]
fn attestation_action_request_serde_round_trip() {
    let req = AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Terminate, 5000);
    let json = serde_json::to_string(&req).unwrap();
    let back: AttestationActionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, req);
}

// ===========================================================================
// 20. AttestationFallbackConfig — default, serde
// ===========================================================================

#[test]
fn attestation_fallback_config_default() {
    let cfg = AttestationFallbackConfig::default();
    assert!(cfg.challenge_on_fallback);
    assert!(cfg.sandbox_on_fallback);
    assert!(cfg.unavailable_timeout_ns > 0);
}

#[test]
fn attestation_fallback_config_serde_round_trip() {
    let cfg = AttestationFallbackConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: AttestationFallbackConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

// ===========================================================================
// 21. AttestationFallbackManager — low-impact always executes
// ===========================================================================

#[test]
fn attestation_manager_initial_state_normal() {
    let mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
    assert_eq!(mgr.health(), AttestationHealth::Valid);
    assert!(!mgr.operator_review_required());
    assert!(mgr.pending_decisions().is_empty());
}

#[test]
fn attestation_manager_low_impact_always_executes() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    // Low-impact when healthy
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::MetricsEmission, 1000);
    let decision = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
    assert!(matches!(
        decision,
        AttestationFallbackDecision::Execute { .. }
    ));

    // Low-impact when unhealthy
    let req2 =
        AttestationActionRequest::new("t-2", "d-2", "p-2", AutonomousAction::MetricsEmission, 2000);
    let decision2 = mgr
        .evaluate_action(req2, AttestationHealth::VerificationFailed)
        .unwrap();
    assert!(matches!(
        decision2,
        AttestationFallbackDecision::Execute { .. }
    ));
}

// ===========================================================================
// 22. AttestationFallbackManager — standard actions
// ===========================================================================

#[test]
fn attestation_manager_standard_healthy_executes() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req = AttestationActionRequest::new(
        "t-1",
        "d-1",
        "p-1",
        AutonomousAction::RoutineMonitoring,
        1000,
    );
    let decision = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
    if let AttestationFallbackDecision::Execute { warning, .. } = &decision {
        assert!(warning.is_none());
    } else {
        panic!("Expected Execute, got {decision:?}");
    }
}

#[test]
fn attestation_manager_standard_unhealthy_executes_with_warning() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req = AttestationActionRequest::new(
        "t-1",
        "d-1",
        "p-1",
        AutonomousAction::RoutineMonitoring,
        1000,
    );
    let decision = mgr
        .evaluate_action(req, AttestationHealth::EvidenceExpired)
        .unwrap();
    if let AttestationFallbackDecision::Execute { warning, .. } = &decision {
        assert!(warning.is_some());
    } else {
        panic!("Expected Execute with warning, got {decision:?}");
    }
}

// ===========================================================================
// 23. AttestationFallbackManager — high-impact actions
// ===========================================================================

#[test]
fn attestation_manager_high_impact_healthy_normal_executes() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    let decision = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
    assert!(matches!(
        decision,
        AttestationFallbackDecision::Execute { .. }
    ));
}

#[test]
fn attestation_manager_high_impact_unhealthy_defers() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    let decision = mgr
        .evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();
    assert!(matches!(
        decision,
        AttestationFallbackDecision::Deferred { .. }
    ));
}

#[test]
fn attestation_manager_high_impact_deferred_increments_queue_id() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req1 =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    let d1 = mgr
        .evaluate_action(req1, AttestationHealth::VerificationFailed)
        .unwrap();
    let req2 =
        AttestationActionRequest::new("t-2", "d-2", "p-2", AutonomousAction::Terminate, 2000);
    let d2 = mgr
        .evaluate_action(req2, AttestationHealth::VerificationFailed)
        .unwrap();

    if let (
        AttestationFallbackDecision::Deferred { queue_id: q1, .. },
        AttestationFallbackDecision::Deferred { queue_id: q2, .. },
    ) = (&d1, &d2)
    {
        assert!(q2 > q1, "queue_id should increment: {q1} < {q2}");
    } else {
        panic!("Expected both Deferred");
    }
}

// ===========================================================================
// 24. AttestationFallbackManager — state transitions
// ===========================================================================

#[test]
fn attestation_manager_state_transition_normal_to_degraded() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);

    // Trigger degraded via unhealthy high-impact action
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
}

#[test]
fn attestation_manager_state_transition_degraded_to_normal() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());

    // Trigger degraded
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);

    // Recover via healthy action
    let req2 =
        AttestationActionRequest::new("t-2", "d-2", "p-2", AutonomousAction::Quarantine, 2000);
    mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();
    // Should transition through Restoring back to Normal
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
}

// ===========================================================================
// 25. AttestationFallbackManager — transition receipts
// ===========================================================================

#[test]
fn attestation_manager_transition_receipts_generated() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();
    assert!(!mgr.transition_receipts().is_empty());
}

#[test]
fn attestation_manager_transition_receipt_verify() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();
    for receipt in mgr.transition_receipts() {
        receipt.verify().expect("receipt signature should verify");
    }
}

#[test]
fn attestation_manager_transition_receipt_serde_round_trip() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();
    for receipt in mgr.transition_receipts() {
        let json = serde_json::to_string(receipt).unwrap();
        let _back: frankenengine_engine::safe_mode_fallback::AttestationTransitionReceipt =
            serde_json::from_str(&json).unwrap();
    }
}

// ===========================================================================
// 26. AttestationFallbackManager — operator review
// ===========================================================================

#[test]
fn attestation_manager_operator_review_not_required_initially() {
    let mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    assert!(!mgr.operator_review_required());
}

#[test]
fn attestation_manager_operator_review_after_timeout() {
    let cfg = AttestationFallbackConfig {
        unavailable_timeout_ns: 100,
        ..AttestationFallbackConfig::default()
    };
    let mut mgr = AttestationFallbackManager::with_default_signing_key(cfg);

    // First action at t=0 with EvidenceUnavailable
    let req = AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 0);
    mgr.evaluate_action(req, AttestationHealth::EvidenceUnavailable)
        .unwrap();

    // Second action at t=200 (past timeout)
    let req2 =
        AttestationActionRequest::new("t-2", "d-2", "p-2", AutonomousAction::Quarantine, 200);
    mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
        .unwrap();

    assert!(mgr.operator_review_required());
}

// ===========================================================================
// 27. AttestationFallbackManager — pending decisions and recovery
// ===========================================================================

#[test]
fn attestation_manager_pending_decisions_tracked() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();
    assert!(!mgr.pending_decisions().is_empty());
    assert_eq!(mgr.pending_decisions()[0].trace_id, "t-1");
}

#[test]
fn attestation_manager_take_recovery_backlog() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());

    // Defer some high-impact decisions
    let req1 =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    mgr.evaluate_action(req1, AttestationHealth::VerificationFailed)
        .unwrap();
    let req2 =
        AttestationActionRequest::new("t-2", "d-2", "p-2", AutonomousAction::Terminate, 2000);
    mgr.evaluate_action(req2, AttestationHealth::VerificationFailed)
        .unwrap();

    // Recover
    let req3 =
        AttestationActionRequest::new("t-3", "d-3", "p-3", AutonomousAction::MetricsEmission, 3000);
    mgr.evaluate_action(req3, AttestationHealth::Valid).unwrap();

    let backlog = mgr.take_recovery_backlog();
    assert_eq!(backlog.len(), 2);
}

// ===========================================================================
// 28. AttestationFallbackManager — events
// ===========================================================================

#[test]
fn attestation_manager_events_emitted() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();
    assert!(!mgr.events().is_empty());
}

#[test]
fn attestation_fallback_event_serde_round_trip() {
    let event = AttestationFallbackEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: "attestation_fallback".into(),
        event: "action_deferred".into(),
        outcome: "queued".into(),
        error_code: None,
        detail: "high_impact in degraded mode".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: AttestationFallbackEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

// ===========================================================================
// 29. AttestationFallbackDecision — serde
// ===========================================================================

#[test]
fn attestation_fallback_decision_execute_serde() {
    let d = AttestationFallbackDecision::Execute {
        attestation_status: "valid".into(),
        warning: None,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: AttestationFallbackDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

#[test]
fn attestation_fallback_decision_deferred_serde() {
    let d = AttestationFallbackDecision::Deferred {
        queue_id: 7,
        attestation_status: "verification_failed".into(),
        status: "attestation-pending".into(),
        challenge_required: true,
        sandbox_required: true,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: AttestationFallbackDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ===========================================================================
// 30. QueuedAttestationDecision — serde
// ===========================================================================

#[test]
fn queued_attestation_decision_serde_round_trip() {
    let q = QueuedAttestationDecision {
        queue_id: 1,
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        action: AutonomousAction::Quarantine,
        queued_at_ns: 1000,
        status: "attestation-pending".into(),
    };
    let json = serde_json::to_string(&q).unwrap();
    let back: QueuedAttestationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, q);
}

// ===========================================================================
// 31. AttestationFallbackError — display
// ===========================================================================

#[test]
fn attestation_fallback_error_display() {
    let err = AttestationFallbackError::SignatureFailure {
        detail: "bad key".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("bad key"), "error display: {msg}");
}

#[test]
fn attestation_fallback_error_serde_round_trip() {
    let err = AttestationFallbackError::SignatureFailure {
        detail: "test".into(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: AttestationFallbackError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ===========================================================================
// 32. Config — custom challenge/sandbox settings
// ===========================================================================

#[test]
fn attestation_config_disabled_challenge_and_sandbox() {
    let cfg = AttestationFallbackConfig {
        challenge_on_fallback: false,
        sandbox_on_fallback: false,
        ..AttestationFallbackConfig::default()
    };
    let mut mgr = AttestationFallbackManager::with_default_signing_key(cfg);
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    let decision = mgr
        .evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();
    if let AttestationFallbackDecision::Deferred {
        challenge_required,
        sandbox_required,
        ..
    } = &decision
    {
        assert!(!challenge_required);
        assert!(!sandbox_required);
    } else {
        panic!("Expected Deferred, got {decision:?}");
    }
}

// ===========================================================================
// 33. Full lifecycle integration
// ===========================================================================

#[test]
fn full_safe_mode_manager_lifecycle() {
    let mut mgr = SafeModeManager::new(64);

    // 1. Normal operation
    assert!(!mgr.any_active());

    // 2. Adapter goes down
    mgr.handle_adapter_unavailable("t-1", "connection refused");
    assert!(mgr.extensions_refused());

    // 3. Decision contract error while adapter is down
    mgr.handle_decision_contract_error("t-2", "ext-1", "FE-DC-001");
    assert!(mgr.quarantined_extensions().contains_key("ext-1"));

    // 4. Evidence ledger fills up
    mgr.handle_evidence_ledger_full("t-3", "FE-EL-001");
    assert!(mgr.high_impact_blocked());

    // 5. Write to ring buffer during evidence fallback
    mgr.write_ring_buffer_entry("t-4", "fallback_write", "ok", "test");
    assert_eq!(mgr.ring_buffer().len(), 1);

    // 6. Recover evidence ledger first
    let drained = mgr.recover_evidence_ledger("t-5");
    assert_eq!(drained.len(), 1);
    assert!(!mgr.high_impact_blocked());

    // 7. Recover adapter
    mgr.recover_adapter("t-6");
    assert!(!mgr.extensions_refused());

    // 8. Recover quarantined extension
    mgr.recover_decision_contract("t-7", "ext-1");
    assert!(mgr.quarantined_extensions().is_empty());

    // 9. All clear
    assert!(!mgr.any_active());

    // 10. Events should have been emitted for all phases
    let events = mgr.events();
    assert!(
        events.len() >= 6,
        "expected >=6 events, got {}",
        events.len()
    );
}

#[test]
fn full_attestation_fallback_lifecycle() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());

    // 1. Normal — high-impact passes
    let req =
        AttestationActionRequest::new("t-1", "d-1", "p-1", AutonomousAction::Quarantine, 1000);
    let d = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
    assert!(matches!(d, AttestationFallbackDecision::Execute { .. }));
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);

    // 2. Attestation fails — high-impact deferred
    let req2 =
        AttestationActionRequest::new("t-2", "d-2", "p-2", AutonomousAction::Terminate, 2000);
    let d2 = mgr
        .evaluate_action(req2, AttestationHealth::VerificationFailed)
        .unwrap();
    assert!(matches!(d2, AttestationFallbackDecision::Deferred { .. }));
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);

    // 3. Low-impact still passes during degraded
    let req3 =
        AttestationActionRequest::new("t-3", "d-3", "p-3", AutonomousAction::MetricsEmission, 3000);
    let d3 = mgr
        .evaluate_action(req3, AttestationHealth::VerificationFailed)
        .unwrap();
    assert!(matches!(d3, AttestationFallbackDecision::Execute { .. }));

    // 4. Attestation recovers
    let req4 =
        AttestationActionRequest::new("t-4", "d-4", "p-4", AutonomousAction::Quarantine, 4000);
    let d4 = mgr.evaluate_action(req4, AttestationHealth::Valid).unwrap();
    assert!(matches!(d4, AttestationFallbackDecision::Execute { .. }));
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);

    // 5. Recovery backlog should contain the deferred decision
    let backlog = mgr.take_recovery_backlog();
    assert_eq!(backlog.len(), 1);
    assert_eq!(backlog[0].trace_id, "t-2");

    // 6. Transition receipts should have been generated
    assert!(mgr.transition_receipts().len() >= 2);
    for receipt in mgr.transition_receipts() {
        receipt.verify().expect("receipt should verify");
    }
}

// ===========================================================================
// 34. TEST_RING_BUFFER_CAPACITY constant
// ===========================================================================

#[test]
fn default_ring_buffer_capacity_is_reasonable() {
    const { assert!(TEST_RING_BUFFER_CAPACITY >= 64) };
    const { assert!(TEST_RING_BUFFER_CAPACITY <= 4096) };
}
