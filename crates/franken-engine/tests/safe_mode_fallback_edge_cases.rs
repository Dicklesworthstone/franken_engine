//! Edge-case integration tests for `safe_mode_fallback`.
//!
//! The inline unit tests (~120) cover basic functionality. These tests
//! target boundary conditions, exhaustive variant coverage, ring buffer
//! stress, multi-failure recovery ordering, attestation policy config
//! permutations, and end-to-end integration scenarios not covered inline.

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

use frankenengine_engine::safe_mode_fallback::*;
use frankenengine_engine::signature_preimage::SigningKey;

// ── helpers ────────────────────────────────────────────────────────────────

fn default_mgr() -> SafeModeManager {
    SafeModeManager::default()
}

fn make_request(action: AutonomousAction, ts: u64) -> AttestationActionRequest {
    AttestationActionRequest::new("trace-t", "decision-d", "policy-p", action, ts)
}

fn attest_mgr() -> AttestationFallbackManager {
    AttestationFallbackManager::with_default_signing_key(Default::default())
}

fn attest_mgr_config(config: AttestationFallbackConfig) -> AttestationFallbackManager {
    AttestationFallbackManager::with_default_signing_key(config)
}

// ═══════════════════════════════════════════════════════════════════════════
// FailureType
// ═══════════════════════════════════════════════════════════════════════════

fn all_failure_types() -> Vec<FailureType> {
    vec![
        FailureType::AdapterUnavailable,
        FailureType::DecisionContractError,
        FailureType::EvidenceLedgerFull,
        FailureType::CxCorrupted,
        FailureType::CancellationDeadlock,
    ]
}

#[test]
fn failure_type_hash_all_unique() {
    let mut set = BTreeSet::new();
    for ft in all_failure_types() {
        assert!(set.insert(ft), "duplicate FailureType: {ft}");
    }
    assert_eq!(set.len(), 5);
}

#[test]
fn failure_type_display_all_lowercase_underscore() {
    for ft in all_failure_types() {
        let s = ft.to_string();
        assert_eq!(s, s.to_lowercase());
        assert!(!s.contains(' '));
    }
}

#[test]
fn failure_type_serde_all() {
    for ft in all_failure_types() {
        let json = serde_json::to_string(&ft).unwrap();
        let decoded: FailureType = serde_json::from_str(&json).unwrap();
        assert_eq!(ft, decoded);
    }
}

#[test]
fn failure_type_copy_semantics() {
    let a = FailureType::CxCorrupted;
    let b = a;
    let c = b;
    assert_eq!(a, c);
}

// ═══════════════════════════════════════════════════════════════════════════
// SafeModeAction
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn safe_mode_action_failure_type_exhaustive() {
    let actions = [
        SafeModeAction::RefuseExtensions {
            diagnostic: "d".into(),
        },
        SafeModeAction::DefaultDenyAndQuarantine {
            extension_id: "e".into(),
            reason: "r".into(),
        },
        SafeModeAction::RingBufferFallback {
            capacity: 1,
            high_impact_blocked: false,
        },
        SafeModeAction::RejectAndRefreshCx {
            rejected_operation: "op".into(),
            corruption_detail: "cd".into(),
        },
        SafeModeAction::ForceFinalize {
            cell_id: "c".into(),
            timeout_ticks: 0,
        },
    ];
    let types: Vec<FailureType> = actions.iter().map(|a| a.failure_type()).collect();
    assert_eq!(types.len(), 5);
    let unique: BTreeSet<_> = types.into_iter().collect();
    assert_eq!(unique.len(), 5);
}

#[test]
fn safe_mode_action_serde_all_variants() {
    let actions = [
        SafeModeAction::RefuseExtensions {
            diagnostic: "version mismatch".into(),
        },
        SafeModeAction::DefaultDenyAndQuarantine {
            extension_id: "ext".into(),
            reason: "panic".into(),
        },
        SafeModeAction::RingBufferFallback {
            capacity: 256,
            high_impact_blocked: true,
        },
        SafeModeAction::RejectAndRefreshCx {
            rejected_operation: "write".into(),
            corruption_detail: "budget underflow".into(),
        },
        SafeModeAction::ForceFinalize {
            cell_id: "cell-1".into(),
            timeout_ticks: u64::MAX,
        },
    ];
    for action in &actions {
        let json = serde_json::to_string(action).unwrap();
        let decoded: SafeModeAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, decoded);
    }
}

#[test]
fn safe_mode_action_force_finalize_zero_ticks() {
    let action = SafeModeAction::ForceFinalize {
        cell_id: "c".into(),
        timeout_ticks: 0,
    };
    assert_eq!(action.failure_type(), FailureType::CancellationDeadlock);
}

// ═══════════════════════════════════════════════════════════════════════════
// SafeModeEvent
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn safe_mode_event_serde_with_error_code() {
    let event = SafeModeEvent {
        trace_id: "t".into(),
        failure_type: FailureType::EvidenceLedgerFull,
        phase: "activate".into(),
        action_summary: "ring buffer active".into(),
        component: "safe_mode_fallback".into(),
        outcome: "safe_mode_active".into(),
        error_code: Some("ledger_full".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: SafeModeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn safe_mode_event_serde_without_error_code() {
    let event = SafeModeEvent {
        trace_id: "t".into(),
        failure_type: FailureType::AdapterUnavailable,
        phase: "recover".into(),
        action_summary: "adapter restored".into(),
        component: "safe_mode_fallback".into(),
        outcome: "recovery_complete".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: SafeModeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// SafeModeStatus
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn safe_mode_status_default() {
    assert_eq!(SafeModeStatus::default(), SafeModeStatus::Normal);
}

#[test]
fn safe_mode_status_serde_all() {
    for status in [
        SafeModeStatus::Normal,
        SafeModeStatus::Active,
        SafeModeStatus::Recovering,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let decoded: SafeModeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// EvidenceRingBuffer
// ═══════════════════════════════════════════════════════════════════════════

fn make_entry(trace: &str, seq: u64) -> RingBufferEntry {
    RingBufferEntry {
        trace_id: trace.to_string(),
        event: "ev".into(),
        outcome: "ok".into(),
        component: "comp".into(),
        sequence: seq,
    }
}

#[test]
fn ring_buffer_capacity_one() {
    let mut rb = EvidenceRingBuffer::new(1);
    rb.push(make_entry("a", 0));
    rb.push(make_entry("b", 1));
    rb.push(make_entry("c", 2));
    assert_eq!(rb.len(), 1);
    assert_eq!(rb.total_written(), 3);
    assert_eq!(rb.entries()[0].trace_id, "c");
}

#[test]
fn ring_buffer_exact_capacity_fill() {
    let mut rb = EvidenceRingBuffer::new(3);
    rb.push(make_entry("a", 0));
    rb.push(make_entry("b", 1));
    rb.push(make_entry("c", 2));
    assert_eq!(rb.len(), 3);
    assert_eq!(rb.total_written(), 3);
    let entries = rb.entries();
    assert_eq!(entries[0].trace_id, "a");
    assert_eq!(entries[1].trace_id, "b");
    assert_eq!(entries[2].trace_id, "c");
}

#[test]
fn ring_buffer_wrap_once() {
    let mut rb = EvidenceRingBuffer::new(3);
    for i in 0..4 {
        rb.push(make_entry(&format!("t{i}"), i));
    }
    assert_eq!(rb.len(), 3);
    let entries = rb.entries();
    assert_eq!(entries[0].trace_id, "t1");
    assert_eq!(entries[1].trace_id, "t2");
    assert_eq!(entries[2].trace_id, "t3");
}

#[test]
fn ring_buffer_wrap_multiple_times() {
    let mut rb = EvidenceRingBuffer::new(2);
    for i in 0..100 {
        rb.push(make_entry(&format!("t{i}"), i));
    }
    assert_eq!(rb.len(), 2);
    assert_eq!(rb.total_written(), 100);
    let entries = rb.entries();
    assert_eq!(entries[0].trace_id, "t98");
    assert_eq!(entries[1].trace_id, "t99");
}

#[test]
fn ring_buffer_drain_after_wrapping() {
    let mut rb = EvidenceRingBuffer::new(3);
    for i in 0..10 {
        rb.push(make_entry(&format!("t{i}"), i));
    }
    let drained = rb.drain();
    assert_eq!(drained.len(), 3);
    assert!(rb.is_empty());
    assert_eq!(rb.len(), 0);
}

#[test]
fn ring_buffer_drain_empty() {
    let mut rb = EvidenceRingBuffer::new(5);
    let drained = rb.drain();
    assert!(drained.is_empty());
}

#[test]
fn ring_buffer_push_after_drain() {
    let mut rb = EvidenceRingBuffer::new(2);
    rb.push(make_entry("a", 0));
    rb.drain();
    rb.push(make_entry("b", 1));
    assert_eq!(rb.len(), 1);
    assert_eq!(rb.entries()[0].trace_id, "b");
}

#[test]
fn ring_buffer_entry_serde() {
    let entry = make_entry("trace-serde", 42);
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: RingBufferEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, decoded);
}

#[test]
fn ring_buffer_serde_roundtrip_after_wrapping() {
    let mut rb = EvidenceRingBuffer::new(2);
    for i in 0..5 {
        rb.push(make_entry(&format!("t{i}"), i));
    }
    let json = serde_json::to_string(&rb).unwrap();
    let decoded: EvidenceRingBuffer = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded.total_written(), 5);
}

// ═══════════════════════════════════════════════════════════════════════════
// SafeModeManager — activation/recovery edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn manager_initial_state_all_normal() {
    let mgr = default_mgr();
    for ft in all_failure_types() {
        assert_eq!(mgr.status(ft), SafeModeStatus::Normal);
        assert_eq!(mgr.activation_count(ft), 0);
        assert_eq!(mgr.recovery_count(ft), 0);
    }
}

#[test]
fn manager_custom_ring_buffer_capacity() {
    let mgr = SafeModeManager::new(7);
    assert_eq!(mgr.ring_buffer().len(), 0);
    // Capacity is private, but we can verify through behavior
}

#[test]
fn handle_adapter_unavailable_returns_diagnostic() {
    let mut mgr = default_mgr();
    let action = mgr.handle_adapter_unavailable("t1", "version 0.2 != 0.3");
    match action {
        SafeModeAction::RefuseExtensions { diagnostic } => {
            assert_eq!(diagnostic, "version 0.2 != 0.3");
        }
        other => panic!("expected RefuseExtensions, got {other:?}"),
    }
}

#[test]
fn handle_decision_contract_error_quarantine_reason_includes_code() {
    let mut mgr = default_mgr();
    let action = mgr.handle_decision_contract_error("t1", "ext-1", "gateway_panic");
    match action {
        SafeModeAction::DefaultDenyAndQuarantine { reason, .. } => {
            assert!(reason.contains("gateway_panic"));
        }
        other => panic!("expected DefaultDenyAndQuarantine, got {other:?}"),
    }
}

#[test]
fn handle_evidence_ledger_full_capacity_matches_constructor() {
    let mut mgr = SafeModeManager::new(42);
    let action = mgr.handle_evidence_ledger_full("t1", "full");
    match action {
        SafeModeAction::RingBufferFallback { capacity, .. } => {
            assert_eq!(capacity, 42);
        }
        other => panic!("expected RingBufferFallback, got {other:?}"),
    }
}

#[test]
fn handle_cx_corrupted_preserves_fields() {
    let mut mgr = default_mgr();
    let action = mgr.handle_cx_corrupted("t1", "hostcall_read", "budget underflow: -100ms");
    match action {
        SafeModeAction::RejectAndRefreshCx {
            rejected_operation,
            corruption_detail,
        } => {
            assert_eq!(rejected_operation, "hostcall_read");
            assert_eq!(corruption_detail, "budget underflow: -100ms");
        }
        other => panic!("expected RejectAndRefreshCx, got {other:?}"),
    }
}

#[test]
fn handle_cancellation_deadlock_preserves_fields() {
    let mut mgr = default_mgr();
    let action = mgr.handle_cancellation_deadlock("t1", "cell-99", 50000);
    match action {
        SafeModeAction::ForceFinalize {
            cell_id,
            timeout_ticks,
        } => {
            assert_eq!(cell_id, "cell-99");
            assert_eq!(timeout_ticks, 50000);
        }
        other => panic!("expected ForceFinalize, got {other:?}"),
    }
}

#[test]
fn recover_decision_partial_keeps_active() {
    let mut mgr = default_mgr();
    mgr.handle_decision_contract_error("t1", "ext-a", "err");
    mgr.handle_decision_contract_error("t2", "ext-b", "err");
    mgr.handle_decision_contract_error("t3", "ext-c", "err");
    assert_eq!(mgr.quarantined_extensions().len(), 3);

    mgr.recover_decision_contract("t4", "ext-a");
    assert_eq!(
        mgr.status(FailureType::DecisionContractError),
        SafeModeStatus::Active
    );
    assert_eq!(mgr.quarantined_extensions().len(), 2);

    mgr.recover_decision_contract("t5", "ext-b");
    assert_eq!(
        mgr.status(FailureType::DecisionContractError),
        SafeModeStatus::Active
    );

    mgr.recover_decision_contract("t6", "ext-c");
    assert_eq!(
        mgr.status(FailureType::DecisionContractError),
        SafeModeStatus::Normal
    );
}

#[test]
fn recover_evidence_ledger_returns_ring_buffer_contents() {
    let mut mgr = SafeModeManager::new(10);
    mgr.handle_evidence_ledger_full("t1", "full");
    mgr.write_ring_buffer_entry("t1", "ev1", "ok", "comp");
    mgr.write_ring_buffer_entry("t2", "ev2", "ok", "comp");
    mgr.write_ring_buffer_entry("t3", "ev3", "ok", "comp");

    let drained = mgr.recover_evidence_ledger("t4");
    assert_eq!(drained.len(), 3);
    assert!(mgr.ring_buffer().is_empty());
    assert!(!mgr.high_impact_blocked());
}

#[test]
fn check_action_blocked_normal_allows_all() {
    let mgr = default_mgr();
    assert!(mgr.check_action_blocked(false).is_none());
    assert!(mgr.check_action_blocked(true).is_none());
}

#[test]
fn check_action_blocked_adapter_blocks_everything() {
    let mut mgr = default_mgr();
    mgr.handle_adapter_unavailable("t1", "gone");
    let reason_low = mgr.check_action_blocked(false).unwrap();
    let reason_high = mgr.check_action_blocked(true).unwrap();
    assert!(reason_low.contains("adapter"));
    assert!(reason_high.contains("adapter"));
}

#[test]
fn check_action_blocked_evidence_blocks_high_only() {
    let mut mgr = default_mgr();
    mgr.handle_evidence_ledger_full("t1", "full");
    assert!(mgr.check_action_blocked(false).is_none());
    let reason = mgr.check_action_blocked(true).unwrap();
    assert!(reason.contains("high-impact"));
}

#[test]
fn check_quarantine_returns_reason() {
    let mut mgr = default_mgr();
    mgr.handle_decision_contract_error("t1", "ext-q", "bad_code");
    let reason = mgr.check_quarantine("ext-q").unwrap();
    assert!(reason.contains("bad_code"));
    assert!(mgr.check_quarantine("ext-ok").is_none());
}

#[test]
fn drain_events_returns_and_clears() {
    let mut mgr = default_mgr();
    mgr.handle_adapter_unavailable("t1", "gone");
    mgr.handle_cx_corrupted("t2", "op", "bad");
    assert_eq!(mgr.events().len(), 2);
    let drained = mgr.drain_events();
    assert_eq!(drained.len(), 2);
    assert!(mgr.events().is_empty());
}

#[test]
fn write_ring_buffer_auto_sequences() {
    let mut mgr = SafeModeManager::new(100);
    mgr.handle_evidence_ledger_full("t1", "full");
    for _ in 0..5 {
        mgr.write_ring_buffer_entry("t1", "ev", "ok", "comp");
    }
    let entries = mgr.ring_buffer().entries();
    for i in 1..entries.len() {
        assert!(entries[i].sequence > entries[i - 1].sequence);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SafeModeManager — multi-failure interactions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn adapter_unavailable_precedence_over_evidence_blocking() {
    let mut mgr = default_mgr();
    mgr.handle_evidence_ledger_full("t1", "full");
    mgr.handle_adapter_unavailable("t2", "gone");
    // adapter check comes first regardless of arg
    let reason = mgr.check_action_blocked(false).unwrap();
    assert!(reason.contains("adapter"));
}

#[test]
fn recover_order_does_not_matter() {
    let mut mgr = default_mgr();
    mgr.handle_adapter_unavailable("t1", "gone");
    mgr.handle_evidence_ledger_full("t2", "full");
    mgr.handle_cx_corrupted("t3", "op", "bad");

    // Recover in reverse order
    mgr.recover_cx("r1");
    assert!(mgr.any_active());
    mgr.recover_evidence_ledger("r2");
    assert!(mgr.any_active());
    mgr.recover_adapter("r3");
    assert!(!mgr.any_active());
}

#[test]
fn repeated_same_failure_accumulates_activations() {
    let mut mgr = default_mgr();
    for i in 0..10 {
        mgr.handle_adapter_unavailable(&format!("t{i}"), "gone");
    }
    assert_eq!(mgr.activation_count(FailureType::AdapterUnavailable), 10);
    assert_eq!(mgr.events().len(), 10);
}

#[test]
fn activate_recover_cycle_counts() {
    let mut mgr = default_mgr();
    for i in 0..5 {
        mgr.handle_cx_corrupted(&format!("a{i}"), "op", "bad");
        mgr.recover_cx(&format!("r{i}"));
    }
    assert_eq!(mgr.activation_count(FailureType::CxCorrupted), 5);
    assert_eq!(mgr.recovery_count(FailureType::CxCorrupted), 5);
    assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Normal);
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationHealth
// ═══════════════════════════════════════════════════════════════════════════

fn all_health_states() -> Vec<AttestationHealth> {
    vec![
        AttestationHealth::Valid,
        AttestationHealth::VerificationFailed,
        AttestationHealth::EvidenceExpired,
        AttestationHealth::EvidenceUnavailable,
    ]
}

#[test]
fn attestation_health_is_healthy_only_valid() {
    for h in all_health_states() {
        if h == AttestationHealth::Valid {
            assert!(h.is_healthy());
        } else {
            assert!(!h.is_healthy(), "{h} should not be healthy");
        }
    }
}

#[test]
fn attestation_health_display_all() {
    let displays: Vec<String> = all_health_states().iter().map(|h| h.to_string()).collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn attestation_health_serde_all() {
    for h in all_health_states() {
        let json = serde_json::to_string(&h).unwrap();
        let decoded: AttestationHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(h, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ActionTier
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn action_tier_display_unique() {
    let displays: BTreeSet<String> = [
        ActionTier::HighImpact,
        ActionTier::Standard,
        ActionTier::LowImpact,
    ]
    .iter()
    .map(|t| t.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn action_tier_serde_all() {
    for tier in [
        ActionTier::HighImpact,
        ActionTier::Standard,
        ActionTier::LowImpact,
    ] {
        let json = serde_json::to_string(&tier).unwrap();
        let decoded: ActionTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AutonomousAction
// ═══════════════════════════════════════════════════════════════════════════

fn all_actions() -> Vec<AutonomousAction> {
    vec![
        AutonomousAction::Quarantine,
        AutonomousAction::Terminate,
        AutonomousAction::EmergencyGrant,
        AutonomousAction::PolicyPromotion,
        AutonomousAction::CapabilityEscalation,
        AutonomousAction::RoutineMonitoring,
        AutonomousAction::EvidenceCollection,
        AutonomousAction::MetricsEmission,
    ]
}

#[test]
fn autonomous_action_display_all_unique() {
    let displays: BTreeSet<String> = all_actions().iter().map(|a| a.to_string()).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn autonomous_action_tier_distribution() {
    let actions = all_actions();
    let high = actions
        .iter()
        .filter(|a| a.default_tier() == ActionTier::HighImpact)
        .count();
    let standard = actions
        .iter()
        .filter(|a| a.default_tier() == ActionTier::Standard)
        .count();
    let low = actions
        .iter()
        .filter(|a| a.default_tier() == ActionTier::LowImpact)
        .count();
    assert_eq!(high, 5);
    assert_eq!(standard, 2);
    assert_eq!(low, 1);
}

#[test]
fn autonomous_action_serde_all() {
    for action in all_actions() {
        let json = serde_json::to_string(&action).unwrap();
        let decoded: AutonomousAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationActionRequest
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attestation_request_new_sets_default_tier() {
    for action in all_actions() {
        let req = AttestationActionRequest::new("t", "d", "p", action, 0);
        assert_eq!(req.tier, action.default_tier());
    }
}

#[test]
fn attestation_request_serde() {
    let req =
        AttestationActionRequest::new("trace", "dec", "pol", AutonomousAction::Terminate, 999);
    let json = serde_json::to_string(&req).unwrap();
    let decoded: AttestationActionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, decoded);
}

#[test]
fn attestation_request_custom_tier_override() {
    let mut req =
        AttestationActionRequest::new("t", "d", "p", AutonomousAction::MetricsEmission, 0);
    assert_eq!(req.tier, ActionTier::LowImpact);
    req.tier = ActionTier::HighImpact; // Override
    assert_eq!(req.tier, ActionTier::HighImpact);
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackState
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attestation_fallback_state_default_is_normal() {
    assert_eq!(
        AttestationFallbackState::default(),
        AttestationFallbackState::Normal
    );
}

#[test]
fn attestation_fallback_state_ordering() {
    assert!(AttestationFallbackState::Normal < AttestationFallbackState::Degraded);
    assert!(AttestationFallbackState::Degraded < AttestationFallbackState::Restoring);
}

#[test]
fn attestation_fallback_state_serde_all() {
    for state in [
        AttestationFallbackState::Normal,
        AttestationFallbackState::Degraded,
        AttestationFallbackState::Restoring,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let decoded: AttestationFallbackState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackConfig
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attestation_config_default_values() {
    let config = AttestationFallbackConfig::default();
    assert_eq!(config.unavailable_timeout_ns, 300_000_000_000);
    assert!(config.challenge_on_fallback);
    assert!(config.sandbox_on_fallback);
}

#[test]
fn attestation_config_serde() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: 42,
        challenge_on_fallback: false,
        sandbox_on_fallback: true,
    };
    let json = serde_json::to_string(&config).unwrap();
    let decoded: AttestationFallbackConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackError
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attestation_fallback_error_display() {
    let err = AttestationFallbackError::SignatureFailure {
        detail: "invalid key material".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("signature failure"));
    assert!(msg.contains("invalid key material"));
}

#[test]
fn attestation_fallback_error_std_error() {
    use std::error::Error;
    let err = AttestationFallbackError::SignatureFailure {
        detail: "test".into(),
    };
    assert!(err.source().is_none());
}

#[test]
fn attestation_fallback_error_serde() {
    let err = AttestationFallbackError::SignatureFailure {
        detail: "test detail".into(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let decoded: AttestationFallbackError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackDecision
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attestation_decision_execute_no_warning_serde() {
    let d = AttestationFallbackDecision::Execute {
        attestation_status: "valid".into(),
        warning: None,
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: AttestationFallbackDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

#[test]
fn attestation_decision_execute_with_warning_serde() {
    let d = AttestationFallbackDecision::Execute {
        attestation_status: "degraded".into(),
        warning: Some("attestation expired".into()),
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: AttestationFallbackDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

#[test]
fn attestation_decision_deferred_serde() {
    let d = AttestationFallbackDecision::Deferred {
        queue_id: 99,
        attestation_status: "degraded".into(),
        status: "attestation-pending".into(),
        challenge_required: true,
        sandbox_required: false,
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: AttestationFallbackDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// QueuedAttestationDecision
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn queued_decision_serde() {
    let q = QueuedAttestationDecision {
        queue_id: 0,
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        action: AutonomousAction::Terminate,
        queued_at_ns: 12345,
        status: "attestation-pending".into(),
    };
    let json = serde_json::to_string(&q).unwrap();
    let decoded: QueuedAttestationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(q, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackEvent
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attestation_fallback_event_serde() {
    let event = AttestationFallbackEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "attestation_safe_mode".into(),
        event: "test_event".into(),
        outcome: "pass".into(),
        error_code: Some("test_code".into()),
        detail: "detail text".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: AttestationFallbackEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackManager — evaluate_action edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn low_impact_always_executes_regardless_of_health() {
    for health in all_health_states() {
        let mut mgr = attest_mgr();
        let req = make_request(AutonomousAction::MetricsEmission, 100);
        let decision = mgr.evaluate_action(req, health).unwrap();
        assert!(
            matches!(decision, AttestationFallbackDecision::Execute { .. }),
            "low-impact should execute with health={health}"
        );
    }
}

#[test]
fn standard_healthy_no_warning() {
    let mut mgr = attest_mgr();
    let req = make_request(AutonomousAction::RoutineMonitoring, 100);
    let decision = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
    match decision {
        AttestationFallbackDecision::Execute { warning, .. } => {
            assert!(warning.is_none());
        }
        other => panic!("expected Execute, got {other:?}"),
    }
}

#[test]
fn standard_unhealthy_has_warning() {
    for health in [
        AttestationHealth::VerificationFailed,
        AttestationHealth::EvidenceExpired,
        AttestationHealth::EvidenceUnavailable,
    ] {
        let mut mgr = attest_mgr();
        let req = make_request(AutonomousAction::EvidenceCollection, 100);
        let decision = mgr.evaluate_action(req, health).unwrap();
        match decision {
            AttestationFallbackDecision::Execute { warning, .. } => {
                assert!(warning.is_some(), "expected warning with health={health}");
            }
            other => panic!("expected Execute, got {other:?}"),
        }
    }
}

#[test]
fn high_impact_healthy_normal_executes() {
    let mut mgr = attest_mgr();
    let req = make_request(AutonomousAction::Quarantine, 100);
    let decision = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
    assert!(matches!(
        decision,
        AttestationFallbackDecision::Execute { .. }
    ));
}

#[test]
fn high_impact_unhealthy_defers_all_unhealthy_states() {
    for health in [
        AttestationHealth::VerificationFailed,
        AttestationHealth::EvidenceExpired,
        AttestationHealth::EvidenceUnavailable,
    ] {
        let mut mgr = attest_mgr();
        let req = make_request(AutonomousAction::Quarantine, 100);
        let decision = mgr.evaluate_action(req, health).unwrap();
        assert!(
            matches!(decision, AttestationFallbackDecision::Deferred { .. }),
            "high-impact should defer with health={health}"
        );
        assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
    }
}

#[test]
fn high_impact_queue_ids_increment() {
    let mut mgr = attest_mgr();
    for i in 0..5u64 {
        let req = make_request(AutonomousAction::Terminate, 100 + i);
        let decision = mgr
            .evaluate_action(req, AttestationHealth::VerificationFailed)
            .unwrap();
        match decision {
            AttestationFallbackDecision::Deferred { queue_id, .. } => {
                assert_eq!(queue_id, i);
            }
            other => panic!("expected Deferred, got {other:?}"),
        }
    }
    assert_eq!(mgr.pending_decisions().len(), 5);
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackManager — state transitions
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn normal_to_degraded_creates_receipt() {
    let mut mgr = attest_mgr();
    let req = make_request(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
    assert_eq!(mgr.transition_receipts().len(), 1);
    let receipt = &mgr.transition_receipts()[0];
    assert_eq!(receipt.from_state, AttestationFallbackState::Normal);
    assert_eq!(receipt.to_state, AttestationFallbackState::Degraded);
    receipt.verify().unwrap();
}

#[test]
fn degraded_to_normal_via_restoring() {
    let mut mgr = attest_mgr();
    // Degrade
    let req1 = make_request(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
        .unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);

    // Restore
    let req2 = make_request(AutonomousAction::MetricsEmission, 200);
    mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);

    // 3 receipts: Normal→Degraded, Degraded→Restoring, Restoring→Normal
    assert_eq!(mgr.transition_receipts().len(), 3);
    for receipt in mgr.transition_receipts() {
        receipt.verify().unwrap();
    }
}

#[test]
fn already_degraded_stays_degraded_no_extra_receipt() {
    let mut mgr = attest_mgr();
    let req1 = make_request(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::VerificationFailed)
        .unwrap();
    let count_after_first = mgr.transition_receipts().len();

    let req2 = make_request(AutonomousAction::Terminate, 200);
    mgr.evaluate_action(req2, AttestationHealth::VerificationFailed)
        .unwrap();
    // No new transition receipt since we're already degraded
    assert_eq!(mgr.transition_receipts().len(), count_after_first);
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackManager — recovery backlog
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn recovery_moves_pending_to_backlog() {
    let mut mgr = attest_mgr();
    // Queue 3 deferred decisions
    for i in 0..3 {
        let req = make_request(AutonomousAction::Quarantine, 100 + i);
        mgr.evaluate_action(req, AttestationHealth::EvidenceExpired)
            .unwrap();
    }
    assert_eq!(mgr.pending_decisions().len(), 3);

    // Recover
    let req = make_request(AutonomousAction::MetricsEmission, 200);
    mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
    assert!(mgr.pending_decisions().is_empty());
    let backlog = mgr.take_recovery_backlog();
    assert_eq!(backlog.len(), 3);
}

#[test]
fn take_recovery_backlog_clears() {
    let mut mgr = attest_mgr();
    let req1 = make_request(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
        .unwrap();
    let req2 = make_request(AutonomousAction::MetricsEmission, 200);
    mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();

    let backlog1 = mgr.take_recovery_backlog();
    assert_eq!(backlog1.len(), 1);
    let backlog2 = mgr.take_recovery_backlog();
    assert!(backlog2.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackManager — operator review escalation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn operator_review_not_before_timeout() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: 1000,
        ..Default::default()
    };
    let mut mgr = attest_mgr_config(config);
    let req = make_request(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert!(!mgr.operator_review_required());
}

#[test]
fn operator_review_at_exact_timeout() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: 1000,
        ..Default::default()
    };
    let mut mgr = attest_mgr_config(config);
    let req1 = make_request(AutonomousAction::Quarantine, 0);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    // Exactly at threshold
    let req2 = make_request(AutonomousAction::Quarantine, 1000);
    mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert!(mgr.operator_review_required());
}

#[test]
fn operator_review_only_for_unavailable() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: 100,
        ..Default::default()
    };
    let mut mgr = attest_mgr_config(config);
    let req1 = make_request(AutonomousAction::Quarantine, 0);
    mgr.evaluate_action(req1, AttestationHealth::VerificationFailed)
        .unwrap();
    let req2 = make_request(AutonomousAction::Quarantine, 1000);
    mgr.evaluate_action(req2, AttestationHealth::VerificationFailed)
        .unwrap();
    // VerificationFailed doesn't trigger operator review
    assert!(!mgr.operator_review_required());
}

#[test]
fn operator_review_cleared_on_recovery() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: 100,
        ..Default::default()
    };
    let mut mgr = attest_mgr_config(config);
    let req1 = make_request(AutonomousAction::Quarantine, 0);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    let req2 = make_request(AutonomousAction::Quarantine, 200);
    mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert!(mgr.operator_review_required());

    let req3 = make_request(AutonomousAction::MetricsEmission, 300);
    mgr.evaluate_action(req3, AttestationHealth::Valid).unwrap();
    assert!(!mgr.operator_review_required());
}

#[test]
fn operator_review_only_triggers_once() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: 100,
        ..Default::default()
    };
    let mut mgr = attest_mgr_config(config);
    let req1 = make_request(AutonomousAction::Quarantine, 0);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    let initial_events = mgr.events().len();

    let req2 = make_request(AutonomousAction::Quarantine, 200);
    mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert!(mgr.operator_review_required());
    let events_after_trigger = mgr.events().len();

    // Third request past timeout shouldn't add another review event
    let req3 = make_request(AutonomousAction::Quarantine, 400);
    mgr.evaluate_action(req3, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    // No new operator_review event (already triggered)
    let review_events: Vec<_> = mgr
        .events()
        .iter()
        .filter(|e| e.event.contains("operator_review"))
        .collect();
    assert_eq!(review_events.len(), 1);
    let _ = (initial_events, events_after_trigger); // used for clarity
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackManager — config permutations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn config_challenge_only() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: u64::MAX,
        challenge_on_fallback: true,
        sandbox_on_fallback: false,
    };
    let mut mgr = attest_mgr_config(config);
    let req = make_request(AutonomousAction::Quarantine, 100);
    let decision = mgr
        .evaluate_action(req, AttestationHealth::EvidenceExpired)
        .unwrap();
    match decision {
        AttestationFallbackDecision::Deferred {
            challenge_required,
            sandbox_required,
            ..
        } => {
            assert!(challenge_required);
            assert!(!sandbox_required);
        }
        other => panic!("expected Deferred, got {other:?}"),
    }
}

#[test]
fn config_sandbox_only() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: u64::MAX,
        challenge_on_fallback: false,
        sandbox_on_fallback: true,
    };
    let mut mgr = attest_mgr_config(config);
    let req = make_request(AutonomousAction::Quarantine, 100);
    let decision = mgr
        .evaluate_action(req, AttestationHealth::EvidenceExpired)
        .unwrap();
    match decision {
        AttestationFallbackDecision::Deferred {
            challenge_required,
            sandbox_required,
            ..
        } => {
            assert!(!challenge_required);
            assert!(sandbox_required);
        }
        other => panic!("expected Deferred, got {other:?}"),
    }
}

#[test]
fn config_neither_challenge_nor_sandbox() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: u64::MAX,
        challenge_on_fallback: false,
        sandbox_on_fallback: false,
    };
    let mut mgr = attest_mgr_config(config);
    let req = make_request(AutonomousAction::Quarantine, 100);
    let decision = mgr
        .evaluate_action(req, AttestationHealth::EvidenceExpired)
        .unwrap();
    match decision {
        AttestationFallbackDecision::Deferred {
            challenge_required,
            sandbox_required,
            ..
        } => {
            assert!(!challenge_required);
            assert!(!sandbox_required);
        }
        other => panic!("expected Deferred, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationTransitionReceipt
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn transition_receipt_verify_passes_after_serde() {
    let mut mgr = attest_mgr();
    let req = make_request(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();

    let receipt = &mgr.transition_receipts()[0];
    let json = serde_json::to_string(receipt).unwrap();
    let decoded: AttestationTransitionReceipt = serde_json::from_str(&json).unwrap();
    decoded.verify().unwrap();
}

#[test]
fn transition_receipt_different_keys_different_signatures() {
    let key_a = SigningKey::from_bytes([1u8; 32]);
    let key_b = SigningKey::from_bytes([2u8; 32]);

    let mut mgr_a = AttestationFallbackManager::new(Default::default(), key_a);
    let mut mgr_b = AttestationFallbackManager::new(Default::default(), key_b);

    let req_a = make_request(AutonomousAction::Quarantine, 100);
    let req_b = make_request(AutonomousAction::Quarantine, 100);

    mgr_a
        .evaluate_action(req_a, AttestationHealth::VerificationFailed)
        .unwrap();
    mgr_b
        .evaluate_action(req_b, AttestationHealth::VerificationFailed)
        .unwrap();

    let sig_a = &mgr_a.transition_receipts()[0].signature;
    let sig_b = &mgr_b.transition_receipts()[0].signature;
    assert_ne!(sig_a, sig_b);
}

// ═══════════════════════════════════════════════════════════════════════════
// AttestationFallbackManager — determinism
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn attestation_lifecycle_deterministic_100x() {
    let mut jsons = Vec::new();
    for _ in 0..100 {
        let mut mgr = attest_mgr();
        let req1 = make_request(AutonomousAction::Quarantine, 100);
        mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
            .unwrap();
        let req2 = make_request(AutonomousAction::Terminate, 200);
        mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        let req3 = make_request(AutonomousAction::MetricsEmission, 300);
        mgr.evaluate_action(req3, AttestationHealth::Valid).unwrap();

        let events_json = serde_json::to_string(mgr.events()).unwrap();
        let receipts_json = serde_json::to_string(mgr.transition_receipts()).unwrap();
        jsons.push((events_json, receipts_json));
    }
    for j in &jsons[1..] {
        assert_eq!(j, &jsons[0]);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Integration: full SafeModeManager + AttestationFallbackManager lifecycle
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integration_safe_mode_all_five_activate_recover() {
    let mut mgr = SafeModeManager::new(16);

    // Activate all five failure types
    mgr.handle_adapter_unavailable("t1", "gone");
    mgr.handle_decision_contract_error("t2", "ext-a", "err");
    mgr.handle_evidence_ledger_full("t3", "full");
    mgr.handle_cx_corrupted("t4", "op", "bad");
    mgr.handle_cancellation_deadlock("t5", "cell-1", 100);

    assert!(mgr.any_active());
    assert!(mgr.extensions_refused());
    assert!(mgr.high_impact_blocked());
    assert!(mgr.check_quarantine("ext-a").is_some());

    // Write some ring buffer entries
    mgr.write_ring_buffer_entry("t3", "ev1", "ok", "comp");
    mgr.write_ring_buffer_entry("t3", "ev2", "ok", "comp");

    // Recover all
    mgr.recover_adapter("r1");
    mgr.recover_decision_contract("r2", "ext-a");
    let drained = mgr.recover_evidence_ledger("r3");
    mgr.recover_cx("r4");
    mgr.recover_cancellation("r5");

    assert!(!mgr.any_active());
    assert!(!mgr.extensions_refused());
    assert!(!mgr.high_impact_blocked());
    assert_eq!(drained.len(), 2);
    assert_eq!(mgr.events().len(), 10); // 5 activate + 5 recover
}

#[test]
fn integration_attestation_full_degrade_recover_cycle() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: 500,
        challenge_on_fallback: true,
        sandbox_on_fallback: true,
    };
    let mut mgr = attest_mgr_config(config);

    // Phase 1: Normal — high-impact executes
    let req1 = make_request(AutonomousAction::Quarantine, 100);
    let d1 = mgr.evaluate_action(req1, AttestationHealth::Valid).unwrap();
    assert!(matches!(d1, AttestationFallbackDecision::Execute { .. }));

    // Phase 2: Degrade — high-impact deferred
    let req2 = make_request(AutonomousAction::Terminate, 200);
    let d2 = mgr
        .evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert!(matches!(d2, AttestationFallbackDecision::Deferred { .. }));

    // Phase 3: More deferrals
    let req3 = make_request(AutonomousAction::EmergencyGrant, 300);
    mgr.evaluate_action(req3, AttestationHealth::EvidenceUnavailable)
        .unwrap();

    // Phase 4: Operator review triggers
    let req4 = make_request(AutonomousAction::PolicyPromotion, 800);
    mgr.evaluate_action(req4, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert!(mgr.operator_review_required());

    // Phase 5: Recovery
    let req5 = make_request(AutonomousAction::MetricsEmission, 900);
    mgr.evaluate_action(req5, AttestationHealth::Valid).unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
    assert!(!mgr.operator_review_required());

    // Phase 6: Backlog available
    let backlog = mgr.take_recovery_backlog();
    assert_eq!(backlog.len(), 3);

    // All receipts verify
    for receipt in mgr.transition_receipts() {
        receipt.verify().unwrap();
    }
}

#[test]
fn integration_mixed_action_tiers_during_degradation() {
    let mut mgr = attest_mgr();

    // Degrade
    let req1 = make_request(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
        .unwrap();

    // Low-impact: always executes
    let req2 = make_request(AutonomousAction::MetricsEmission, 200);
    let d2 = mgr
        .evaluate_action(req2, AttestationHealth::EvidenceExpired)
        .unwrap();
    assert!(matches!(d2, AttestationFallbackDecision::Execute { .. }));

    // Standard: executes with warning
    let req3 = make_request(AutonomousAction::RoutineMonitoring, 300);
    let d3 = mgr
        .evaluate_action(req3, AttestationHealth::EvidenceExpired)
        .unwrap();
    match d3 {
        AttestationFallbackDecision::Execute { warning, .. } => {
            assert!(warning.is_some());
        }
        other => panic!("expected Execute, got {other:?}"),
    }

    // High-impact: deferred
    let req4 = make_request(AutonomousAction::Terminate, 400);
    let d4 = mgr
        .evaluate_action(req4, AttestationHealth::EvidenceExpired)
        .unwrap();
    assert!(matches!(d4, AttestationFallbackDecision::Deferred { .. }));
}
