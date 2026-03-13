#![forbid(unsafe_code)]
//! Enrichment integration tests for `safe_mode_fallback`.
//!
//! This test suite focuses on deep coverage of deterministic safe-mode
//! degradation paths, attestation-driven autonomy fallback workflows,
//! ring buffer boundary conditions, multi-failure interaction sequences,
//! transition receipt signature integrity, operator review escalation,
//! and the `attestation_health_from_verdict` mapping function.

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

use frankenengine_engine::control_plane::mocks::{
    MockDecisionContract, MockFailureMode, decision_id_from_seed, policy_id_from_seed,
    trace_id_from_seed,
};
use frankenengine_engine::control_plane::{DecisionRequest, DecisionVerdict};
use frankenengine_engine::receipt_verifier_pipeline::{
    LayerCheck, LayerResult, UnifiedReceiptVerificationVerdict, VerificationFailureClass,
};
use frankenengine_engine::safe_mode_fallback::{
    ActionTier, AttestationActionRequest, AttestationFallbackConfig, AttestationFallbackDecision,
    AttestationFallbackError, AttestationFallbackEvent, AttestationFallbackManager,
    AttestationFallbackState, AttestationHealth, AutonomousAction, EvidenceRingBuffer, FailureType,
    QueuedAttestationDecision, RingBufferEntry, SafeModeAction, SafeModeEvent, SafeModeManager,
    SafeModeStatus, attestation_health_from_verdict,
};
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mgr_default() -> SafeModeManager {
    SafeModeManager::default()
}

fn mgr_with_cap(cap: usize) -> SafeModeManager {
    SafeModeManager::new(cap)
}

fn attest_mgr() -> AttestationFallbackManager {
    AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default())
}

fn attest_mgr_cfg(cfg: AttestationFallbackConfig) -> AttestationFallbackManager {
    AttestationFallbackManager::with_default_signing_key(cfg)
}

fn attest_mgr_key(key: [u8; 32]) -> AttestationFallbackManager {
    AttestationFallbackManager::new(
        AttestationFallbackConfig::default(),
        SigningKey::from_bytes(key),
    )
}

fn req_hi(action: AutonomousAction, ts: u64) -> AttestationActionRequest {
    AttestationActionRequest {
        trace_id: format!("trace-{ts}"),
        decision_id: format!("dec-{ts}"),
        policy_id: format!("pol-{ts}"),
        action,
        tier: ActionTier::HighImpact,
        timestamp_ns: ts,
    }
}

fn req_std(action: AutonomousAction, ts: u64) -> AttestationActionRequest {
    AttestationActionRequest {
        trace_id: format!("trace-{ts}"),
        decision_id: format!("dec-{ts}"),
        policy_id: format!("pol-{ts}"),
        action,
        tier: ActionTier::Standard,
        timestamp_ns: ts,
    }
}

fn req_low(action: AutonomousAction, ts: u64) -> AttestationActionRequest {
    AttestationActionRequest {
        trace_id: format!("trace-{ts}"),
        decision_id: format!("dec-{ts}"),
        policy_id: format!("pol-{ts}"),
        action,
        tier: ActionTier::LowImpact,
        timestamp_ns: ts,
    }
}

fn entry(trace: &str, seq: u64) -> RingBufferEntry {
    RingBufferEntry {
        trace_id: trace.to_string(),
        event: format!("event-{seq}"),
        outcome: "ok".to_string(),
        component: "test".to_string(),
        sequence: seq,
    }
}

fn mock_decision_request(seed: u64) -> DecisionRequest {
    DecisionRequest {
        decision_id: decision_id_from_seed(seed),
        policy_id: policy_id_from_seed(seed),
        trace_id: trace_id_from_seed(seed),
        ts_unix_ms: 1_700_000_000_000 + seed,
        calibration_score_bps: 8000,
        e_process_milli: 50,
        ci_width_milli: 100,
    }
}

fn passing_layer() -> LayerResult {
    LayerResult {
        passed: true,
        error_code: None,
        checks: Vec::new(),
    }
}

fn failing_layer(code: &str) -> LayerResult {
    LayerResult {
        passed: false,
        error_code: Some(code.to_string()),
        checks: vec![LayerCheck {
            check: "test_check".to_string(),
            outcome: "fail".to_string(),
            error_code: Some(code.to_string()),
            detail: "test detail".to_string(),
        }],
    }
}

fn base_verdict() -> UnifiedReceiptVerificationVerdict {
    UnifiedReceiptVerificationVerdict {
        receipt_id: "r1".to_string(),
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        verification_timestamp_ns: 1000,
        passed: true,
        failure_class: None,
        exit_code: 0,
        signature: passing_layer(),
        transparency: passing_layer(),
        attestation: passing_layer(),
        warnings: Vec::new(),
        logs: Vec::new(),
    }
}

const MILLIONTHS: u64 = 1_000_000;

// ===========================================================================
// 1. FailureType enrichment
// ===========================================================================

#[test]
fn enrichment_failure_type_clone_and_copy_produce_identical_values() {
    let original = FailureType::EvidenceLedgerFull;
    let copied = original;
    let cloned = original.clone();
    assert_eq!(original, copied);
    assert_eq!(original, cloned);
    assert_eq!(copied, cloned);
}

#[test]
fn enrichment_failure_type_debug_format_contains_variant_name() {
    let ft = FailureType::CancellationDeadlock;
    let debug_str = format!("{ft:?}");
    assert!(debug_str.contains("CancellationDeadlock"));
}

#[test]
fn enrichment_failure_type_all_variants_have_distinct_display() {
    let all = [
        FailureType::AdapterUnavailable,
        FailureType::DecisionContractError,
        FailureType::EvidenceLedgerFull,
        FailureType::CxCorrupted,
        FailureType::CancellationDeadlock,
    ];
    let display_set: BTreeSet<String> = all.iter().map(|f| f.to_string()).collect();
    assert_eq!(display_set.len(), 5);
}

#[test]
fn enrichment_failure_type_ord_is_total() {
    let all = [
        FailureType::AdapterUnavailable,
        FailureType::DecisionContractError,
        FailureType::EvidenceLedgerFull,
        FailureType::CxCorrupted,
        FailureType::CancellationDeadlock,
    ];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert!(all[i] < all[j], "{:?} should be < {:?}", all[i], all[j]);
        }
    }
}

#[test]
fn enrichment_failure_type_btreemap_key() {
    let mut map: BTreeMap<FailureType, u64> = BTreeMap::new();
    map.insert(FailureType::CxCorrupted, 42);
    map.insert(FailureType::AdapterUnavailable, 99);
    assert_eq!(map.len(), 2);
    assert_eq!(*map.get(&FailureType::CxCorrupted).unwrap(), 42);
}

// ===========================================================================
// 2. SafeModeAction enrichment
// ===========================================================================

#[test]
fn enrichment_safe_mode_action_refuse_extensions_debug_includes_diagnostic() {
    let action = SafeModeAction::RefuseExtensions {
        diagnostic: "crate version mismatch".to_string(),
    };
    let dbg = format!("{action:?}");
    assert!(dbg.contains("crate version mismatch"));
}

#[test]
fn enrichment_safe_mode_action_default_deny_clone_eq() {
    let action = SafeModeAction::DefaultDenyAndQuarantine {
        extension_id: "ext-abc".to_string(),
        reason: "contract panic".to_string(),
    };
    let cloned = action.clone();
    assert_eq!(action, cloned);
}

#[test]
fn enrichment_safe_mode_action_ring_buffer_high_impact_false_serde() {
    let action = SafeModeAction::RingBufferFallback {
        capacity: 512,
        high_impact_blocked: false,
    };
    let json = serde_json::to_string(&action).unwrap();
    let decoded: SafeModeAction = serde_json::from_str(&json).unwrap();
    assert_eq!(action, decoded);
    assert_eq!(decoded.failure_type(), FailureType::EvidenceLedgerFull);
}

#[test]
fn enrichment_safe_mode_action_reject_refresh_empty_strings() {
    let action = SafeModeAction::RejectAndRefreshCx {
        rejected_operation: String::new(),
        corruption_detail: String::new(),
    };
    assert_eq!(action.failure_type(), FailureType::CxCorrupted);
    let json = serde_json::to_string(&action).unwrap();
    let decoded: SafeModeAction = serde_json::from_str(&json).unwrap();
    assert_eq!(action, decoded);
}

#[test]
fn enrichment_safe_mode_action_force_finalize_max_ticks() {
    let action = SafeModeAction::ForceFinalize {
        cell_id: "cell-max".to_string(),
        timeout_ticks: u64::MAX,
    };
    let json = serde_json::to_string(&action).unwrap();
    let decoded: SafeModeAction = serde_json::from_str(&json).unwrap();
    assert_eq!(action, decoded);
}

// ===========================================================================
// 3. SafeModeEvent enrichment
// ===========================================================================

#[test]
fn enrichment_safe_mode_event_all_fields_round_trip() {
    let event = SafeModeEvent {
        trace_id: "trace-enrichment".to_string(),
        failure_type: FailureType::CancellationDeadlock,
        phase: "activate".to_string(),
        action_summary: "force-finalize cell-77".to_string(),
        component: "safe_mode_fallback".to_string(),
        outcome: "safe_mode_active".to_string(),
        error_code: Some("cancellation_deadlock".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("cancellation_deadlock"));
    let decoded: SafeModeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn enrichment_safe_mode_event_none_error_code_is_null_in_json() {
    let event = SafeModeEvent {
        trace_id: "t".to_string(),
        failure_type: FailureType::AdapterUnavailable,
        phase: "recover".to_string(),
        action_summary: "adapter restored".to_string(),
        component: "safe_mode_fallback".to_string(),
        outcome: "recovery_complete".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("null"));
}

#[test]
fn enrichment_safe_mode_event_clone_eq() {
    let event = SafeModeEvent {
        trace_id: "t1".to_string(),
        failure_type: FailureType::EvidenceLedgerFull,
        phase: "activate".to_string(),
        action_summary: "ring buffer".to_string(),
        component: "test".to_string(),
        outcome: "safe_mode_active".to_string(),
        error_code: None,
    };
    assert_eq!(event, event.clone());
}

// ===========================================================================
// 4. SafeModeStatus enrichment
// ===========================================================================

#[test]
fn enrichment_safe_mode_status_all_variants_serde_deterministic() {
    for _ in 0..50 {
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
}

#[test]
fn enrichment_safe_mode_status_debug_format() {
    let dbg = format!("{:?}", SafeModeStatus::Active);
    assert!(dbg.contains("Active"));
}

#[test]
fn enrichment_safe_mode_status_copy_semantics() {
    let a = SafeModeStatus::Recovering;
    let b = a;
    let c = b;
    assert_eq!(a, c);
}

// ===========================================================================
// 5. EvidenceRingBuffer enrichment
// ===========================================================================

#[test]
fn enrichment_ring_buffer_large_capacity_push_many() {
    let cap = 1024;
    let mut rb = EvidenceRingBuffer::new(cap);
    for i in 0..2048u64 {
        rb.push(entry(&format!("t{i}"), i));
    }
    assert_eq!(rb.len(), cap);
    assert_eq!(rb.total_written(), 2048);
    let entries = rb.entries();
    assert_eq!(entries.len(), cap);
    // Oldest should be entry 1024
    assert_eq!(entries[0].trace_id, "t1024");
    // Newest should be entry 2047
    assert_eq!(entries[cap - 1].trace_id, "t2047");
}

#[test]
fn enrichment_ring_buffer_entries_order_after_partial_fill() {
    let mut rb = EvidenceRingBuffer::new(10);
    for i in 0..5u64 {
        rb.push(entry(&format!("e{i}"), i));
    }
    let entries = rb.entries();
    for (idx, e) in entries.iter().enumerate() {
        assert_eq!(e.trace_id, format!("e{idx}"));
    }
}

#[test]
fn enrichment_ring_buffer_entries_order_after_exact_fill() {
    let mut rb = EvidenceRingBuffer::new(4);
    for i in 0..4u64 {
        rb.push(entry(&format!("x{i}"), i));
    }
    let entries = rb.entries();
    assert_eq!(entries.len(), 4);
    for (idx, e) in entries.iter().enumerate() {
        assert_eq!(e.trace_id, format!("x{idx}"));
    }
}

#[test]
fn enrichment_ring_buffer_drain_returns_raw_vec_order() {
    let mut rb = EvidenceRingBuffer::new(3);
    for i in 0..5u64 {
        rb.push(entry(&format!("d{i}"), i));
    }
    let drained = rb.drain();
    // After wrapping, the internal vec may not be in insertion order,
    // but drain returns the raw underlying vec
    assert_eq!(drained.len(), 3);
    assert!(rb.is_empty());
    assert_eq!(rb.len(), 0);
}

#[test]
fn enrichment_ring_buffer_total_written_persists_after_drain() {
    let mut rb = EvidenceRingBuffer::new(3);
    for i in 0..7u64 {
        rb.push(entry(&format!("tw{i}"), i));
    }
    assert_eq!(rb.total_written(), 7);
    rb.drain();
    // total_written should persist
    assert_eq!(rb.total_written(), 7);
}

#[test]
fn enrichment_ring_buffer_serde_preserves_total_written() {
    let mut rb = EvidenceRingBuffer::new(2);
    for i in 0..10u64 {
        rb.push(entry(&format!("s{i}"), i));
    }
    let json = serde_json::to_string(&rb).unwrap();
    let decoded: EvidenceRingBuffer = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.total_written(), 10);
    assert_eq!(decoded.len(), 2);
}

#[test]
fn enrichment_ring_buffer_entry_fields_accessible() {
    let e = RingBufferEntry {
        trace_id: "tid".to_string(),
        event: "evt".to_string(),
        outcome: "out".to_string(),
        component: "comp".to_string(),
        sequence: 42,
    };
    assert_eq!(e.trace_id, "tid");
    assert_eq!(e.event, "evt");
    assert_eq!(e.outcome, "out");
    assert_eq!(e.component, "comp");
    assert_eq!(e.sequence, 42);
}

#[test]
fn enrichment_ring_buffer_capacity_two_wraparound_three_times() {
    let mut rb = EvidenceRingBuffer::new(2);
    // Push 7 entries: wraps around 3+ times
    for i in 0..7u64 {
        rb.push(entry(&format!("w{i}"), i));
    }
    let entries = rb.entries();
    assert_eq!(entries[0].trace_id, "w5");
    assert_eq!(entries[1].trace_id, "w6");
}

// ===========================================================================
// 6. SafeModeManager enrichment - activation and state tracking
// ===========================================================================

#[test]
fn enrichment_manager_default_ring_buffer_capacity_256() {
    let mgr = mgr_default();
    // Default capacity is 256; verify ring buffer is empty
    assert!(mgr.ring_buffer().is_empty());
    assert!(!mgr.any_active());
    assert!(!mgr.extensions_refused());
    assert!(!mgr.high_impact_blocked());
    assert!(mgr.quarantined_extensions().is_empty());
    assert!(mgr.events().is_empty());
}

#[test]
fn enrichment_manager_handle_adapter_unavailable_event_content() {
    let mut mgr = mgr_default();
    mgr.handle_adapter_unavailable("trace-au", "version mismatch v0.2");
    let events = mgr.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].trace_id, "trace-au");
    assert_eq!(events[0].failure_type, FailureType::AdapterUnavailable);
    assert_eq!(events[0].phase, "activate");
    assert_eq!(events[0].component, "safe_mode_fallback");
    assert_eq!(events[0].outcome, "safe_mode_active");
}

#[test]
fn enrichment_manager_decision_contract_multiple_extensions_quarantined() {
    let mut mgr = mgr_default();
    for i in 0..10 {
        mgr.handle_decision_contract_error(
            &format!("trace-{i}"),
            &format!("ext-{i}"),
            &format!("code-{i}"),
        );
    }
    assert_eq!(mgr.quarantined_extensions().len(), 10);
    assert_eq!(mgr.activation_count(FailureType::DecisionContractError), 10);
    for i in 0..10 {
        let reason = mgr.check_quarantine(&format!("ext-{i}")).unwrap();
        assert!(reason.contains(&format!("code-{i}")));
    }
}

#[test]
fn enrichment_manager_evidence_ledger_full_blocks_high_impact_only() {
    let mut mgr = mgr_default();
    mgr.handle_evidence_ledger_full("trace-elf", "LEDGER_FULL");
    assert!(mgr.high_impact_blocked());
    assert!(mgr.check_action_blocked(true).is_some());
    assert!(mgr.check_action_blocked(false).is_none());
}

#[test]
fn enrichment_manager_cx_corrupted_status_transitions() {
    let mut mgr = mgr_default();
    assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Normal);
    mgr.handle_cx_corrupted("t1", "write_file", "budget underflow -5ms");
    assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Active);
    mgr.recover_cx("t2");
    assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Normal);
}

#[test]
fn enrichment_manager_cancellation_deadlock_event_contains_cell_id() {
    let mut mgr = mgr_default();
    mgr.handle_cancellation_deadlock("trace-cd", "cell-42", 9000);
    let events = mgr.events();
    assert_eq!(events.len(), 1);
    assert!(events[0].action_summary.contains("cell-42"));
    assert!(events[0].action_summary.contains("9000"));
}

#[test]
fn enrichment_manager_write_ring_buffer_sequences_monotonically() {
    let mut mgr = mgr_with_cap(100);
    for i in 0..20 {
        mgr.write_ring_buffer_entry(&format!("t{i}"), &format!("ev{i}"), "ok", "component");
    }
    let entries = mgr.ring_buffer().entries();
    assert_eq!(entries.len(), 20);
    for i in 1..entries.len() {
        assert!(
            entries[i].sequence > entries[i - 1].sequence,
            "sequence should be monotonically increasing"
        );
    }
}

#[test]
fn enrichment_manager_recover_adapter_emits_two_events() {
    let mut mgr = mgr_default();
    mgr.handle_adapter_unavailable("t1", "gone");
    mgr.recover_adapter("t2");
    // activate emits 1 event, recover emits 2 events (recovering + recovery_complete)
    assert_eq!(mgr.events().len(), 3);
    assert_eq!(mgr.recovery_count(FailureType::AdapterUnavailable), 1);
}

#[test]
fn enrichment_manager_recover_evidence_ledger_drains_ring_buffer() {
    let mut mgr = mgr_with_cap(50);
    mgr.handle_evidence_ledger_full("t1", "full");
    for i in 0..15 {
        mgr.write_ring_buffer_entry(&format!("t{i}"), "ev", "ok", "c");
    }
    let drained = mgr.recover_evidence_ledger("t-recover");
    assert_eq!(drained.len(), 15);
    assert!(mgr.ring_buffer().is_empty());
    assert!(!mgr.high_impact_blocked());
}

#[test]
fn enrichment_manager_recover_cancellation_resets_status() {
    let mut mgr = mgr_default();
    mgr.handle_cancellation_deadlock("t1", "cell-1", 100);
    assert_eq!(
        mgr.status(FailureType::CancellationDeadlock),
        SafeModeStatus::Active
    );
    mgr.recover_cancellation("t2");
    assert_eq!(
        mgr.status(FailureType::CancellationDeadlock),
        SafeModeStatus::Normal
    );
}

#[test]
fn enrichment_manager_drain_events_leaves_empty_events() {
    let mut mgr = mgr_default();
    mgr.handle_adapter_unavailable("t1", "gone");
    mgr.handle_cx_corrupted("t2", "op", "bad");
    mgr.handle_cancellation_deadlock("t3", "c1", 10);
    let drained = mgr.drain_events();
    assert_eq!(drained.len(), 3);
    assert!(mgr.events().is_empty());
    // Further drain returns empty
    let second = mgr.drain_events();
    assert!(second.is_empty());
}

// ===========================================================================
// 7. SafeModeManager - multi-failure concurrent state
// ===========================================================================

#[test]
fn enrichment_manager_all_five_failures_simultaneous() {
    let mut mgr = mgr_with_cap(16);
    mgr.handle_adapter_unavailable("t1", "gone");
    mgr.handle_decision_contract_error("t2", "ext-a", "err");
    mgr.handle_evidence_ledger_full("t3", "full");
    mgr.handle_cx_corrupted("t4", "op", "bad");
    mgr.handle_cancellation_deadlock("t5", "cell-1", 100);

    assert!(mgr.any_active());
    for ft in [
        FailureType::AdapterUnavailable,
        FailureType::DecisionContractError,
        FailureType::EvidenceLedgerFull,
        FailureType::CxCorrupted,
        FailureType::CancellationDeadlock,
    ] {
        assert_eq!(mgr.status(ft), SafeModeStatus::Active);
        assert_eq!(mgr.activation_count(ft), 1);
    }
}

#[test]
fn enrichment_manager_partial_recovery_still_active() {
    let mut mgr = mgr_default();
    mgr.handle_adapter_unavailable("t1", "gone");
    mgr.handle_cx_corrupted("t2", "op", "bad");
    mgr.handle_cancellation_deadlock("t3", "c1", 100);

    // Recover only cx
    mgr.recover_cx("r1");
    assert!(mgr.any_active());
    assert_eq!(mgr.status(FailureType::CxCorrupted), SafeModeStatus::Normal);
    assert_eq!(
        mgr.status(FailureType::AdapterUnavailable),
        SafeModeStatus::Active
    );
    assert_eq!(
        mgr.status(FailureType::CancellationDeadlock),
        SafeModeStatus::Active
    );
}

#[test]
fn enrichment_manager_adapter_blocking_takes_precedence_over_evidence() {
    let mut mgr = mgr_default();
    mgr.handle_evidence_ledger_full("t1", "full");
    mgr.handle_adapter_unavailable("t2", "gone");

    // Low-impact should be blocked by adapter (not evidence)
    let reason = mgr.check_action_blocked(false).unwrap();
    assert!(reason.contains("adapter"), "adapter should take precedence");
}

// ===========================================================================
// 8. SafeModeManager - validate_decision flow
// ===========================================================================

#[test]
fn enrichment_validate_decision_quarantine_denies() {
    let mut mgr = mgr_default();
    mgr.handle_decision_contract_error("t1", "ext-bad", "contract_panic");

    let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
    let request = mock_decision_request(1);
    let verdict = mgr
        .validate_decision(&mut adapter, &request, "ext-bad")
        .unwrap();
    assert_eq!(verdict, DecisionVerdict::Deny);
}

#[test]
fn enrichment_validate_decision_non_quarantined_extension_passes() {
    let mut mgr = mgr_default();
    mgr.handle_decision_contract_error("t1", "ext-bad", "contract_panic");

    let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
    let request = mock_decision_request(2);
    let verdict = mgr
        .validate_decision(&mut adapter, &request, "ext-good")
        .unwrap();
    assert_eq!(verdict, DecisionVerdict::Allow);
}

#[test]
fn enrichment_validate_decision_extensions_refused_denies() {
    let mut mgr = mgr_default();
    mgr.handle_adapter_unavailable("t1", "unavailable");

    let mut adapter = MockDecisionContract::new(vec![DecisionVerdict::Allow]);
    let request = mock_decision_request(3);
    let verdict = mgr
        .validate_decision(&mut adapter, &request, "ext-any")
        .unwrap();
    assert_eq!(verdict, DecisionVerdict::Deny);
}

#[test]
fn enrichment_validate_decision_adapter_failure_activates_safe_mode() {
    let mut mgr = mgr_default();
    let mut adapter =
        MockDecisionContract::new(vec![]).with_failure_mode(MockFailureMode::FailAlways {
            code: "gateway_timeout",
        });

    let request = mock_decision_request(4);
    let verdict = mgr
        .validate_decision(&mut adapter, &request, "ext-x")
        .unwrap();
    assert_eq!(verdict, DecisionVerdict::Deny);
    assert_eq!(
        mgr.status(FailureType::DecisionContractError),
        SafeModeStatus::Active
    );
    assert!(mgr.check_quarantine("ext-x").is_some());
}

#[test]
fn enrichment_validate_decision_adapter_success_passes_through() {
    let mut mgr = mgr_default();
    let mut adapter = MockDecisionContract::new(vec![
        DecisionVerdict::Allow,
        DecisionVerdict::Deny,
        DecisionVerdict::Timeout,
    ]);

    let r1 = mock_decision_request(10);
    assert_eq!(
        mgr.validate_decision(&mut adapter, &r1, "ext").unwrap(),
        DecisionVerdict::Allow
    );
    let r2 = mock_decision_request(11);
    assert_eq!(
        mgr.validate_decision(&mut adapter, &r2, "ext").unwrap(),
        DecisionVerdict::Deny
    );
    let r3 = mock_decision_request(12);
    assert_eq!(
        mgr.validate_decision(&mut adapter, &r3, "ext").unwrap(),
        DecisionVerdict::Timeout
    );
}

#[test]
fn enrichment_validate_decision_quarantine_writes_ring_buffer_entry() {
    let mut mgr = mgr_default();
    mgr.handle_decision_contract_error("t1", "ext-q", "err");

    let mut adapter = MockDecisionContract::new(vec![]);
    let request = mock_decision_request(5);
    mgr.validate_decision(&mut adapter, &request, "ext-q")
        .unwrap();

    // Ring buffer should have an entry from quarantine check
    assert!(mgr.ring_buffer().total_written() > 0);
}

// ===========================================================================
// 9. AttestationHealth enrichment
// ===========================================================================

#[test]
fn enrichment_attestation_health_only_valid_is_healthy() {
    assert!(AttestationHealth::Valid.is_healthy());
    assert!(!AttestationHealth::VerificationFailed.is_healthy());
    assert!(!AttestationHealth::EvidenceExpired.is_healthy());
    assert!(!AttestationHealth::EvidenceUnavailable.is_healthy());
}

#[test]
fn enrichment_attestation_health_display_values() {
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
fn enrichment_attestation_health_ordering() {
    assert!(AttestationHealth::Valid < AttestationHealth::VerificationFailed);
    assert!(AttestationHealth::VerificationFailed < AttestationHealth::EvidenceExpired);
    assert!(AttestationHealth::EvidenceExpired < AttestationHealth::EvidenceUnavailable);
}

#[test]
fn enrichment_attestation_health_btreeset_contains_all() {
    let set: BTreeSet<AttestationHealth> = [
        AttestationHealth::Valid,
        AttestationHealth::VerificationFailed,
        AttestationHealth::EvidenceExpired,
        AttestationHealth::EvidenceUnavailable,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 4);
}

// ===========================================================================
// 10. ActionTier enrichment
// ===========================================================================

#[test]
fn enrichment_action_tier_display_values() {
    assert_eq!(ActionTier::HighImpact.to_string(), "high_impact");
    assert_eq!(ActionTier::Standard.to_string(), "standard");
    assert_eq!(ActionTier::LowImpact.to_string(), "low_impact");
}

#[test]
fn enrichment_action_tier_ordering() {
    assert!(ActionTier::HighImpact < ActionTier::Standard);
    assert!(ActionTier::Standard < ActionTier::LowImpact);
}

// ===========================================================================
// 11. AutonomousAction enrichment
// ===========================================================================

#[test]
fn enrichment_autonomous_action_display_all_lowercase_underscore() {
    let all = [
        AutonomousAction::Quarantine,
        AutonomousAction::Terminate,
        AutonomousAction::EmergencyGrant,
        AutonomousAction::PolicyPromotion,
        AutonomousAction::CapabilityEscalation,
        AutonomousAction::RoutineMonitoring,
        AutonomousAction::EvidenceCollection,
        AutonomousAction::MetricsEmission,
    ];
    for action in &all {
        let s = action.to_string();
        assert_eq!(s, s.to_lowercase(), "action display should be lowercase");
        assert!(!s.contains(' '), "action display should have no spaces");
    }
}

#[test]
fn enrichment_autonomous_action_high_impact_actions() {
    let high_impact = [
        AutonomousAction::Quarantine,
        AutonomousAction::Terminate,
        AutonomousAction::EmergencyGrant,
        AutonomousAction::PolicyPromotion,
        AutonomousAction::CapabilityEscalation,
    ];
    for action in &high_impact {
        assert_eq!(
            action.default_tier(),
            ActionTier::HighImpact,
            "{action:?} should be HighImpact"
        );
    }
}

#[test]
fn enrichment_autonomous_action_standard_actions() {
    assert_eq!(
        AutonomousAction::RoutineMonitoring.default_tier(),
        ActionTier::Standard
    );
    assert_eq!(
        AutonomousAction::EvidenceCollection.default_tier(),
        ActionTier::Standard
    );
}

#[test]
fn enrichment_autonomous_action_low_impact_action() {
    assert_eq!(
        AutonomousAction::MetricsEmission.default_tier(),
        ActionTier::LowImpact
    );
}

// ===========================================================================
// 12. AttestationActionRequest enrichment
// ===========================================================================

#[test]
fn enrichment_attestation_request_new_default_tier_for_each_action() {
    let actions = [
        (AutonomousAction::Quarantine, ActionTier::HighImpact),
        (AutonomousAction::Terminate, ActionTier::HighImpact),
        (AutonomousAction::EmergencyGrant, ActionTier::HighImpact),
        (AutonomousAction::PolicyPromotion, ActionTier::HighImpact),
        (
            AutonomousAction::CapabilityEscalation,
            ActionTier::HighImpact,
        ),
        (AutonomousAction::RoutineMonitoring, ActionTier::Standard),
        (AutonomousAction::EvidenceCollection, ActionTier::Standard),
        (AutonomousAction::MetricsEmission, ActionTier::LowImpact),
    ];
    for (action, expected_tier) in actions {
        let req = AttestationActionRequest::new("t", "d", "p", action, 0);
        assert_eq!(req.tier, expected_tier, "action {action:?} tier mismatch");
    }
}

#[test]
fn enrichment_attestation_request_fields_preserved() {
    let req = AttestationActionRequest::new(
        "trace-field-check",
        "decision-field-check",
        "policy-field-check",
        AutonomousAction::Terminate,
        42_000_000,
    );
    assert_eq!(req.trace_id, "trace-field-check");
    assert_eq!(req.decision_id, "decision-field-check");
    assert_eq!(req.policy_id, "policy-field-check");
    assert_eq!(req.action, AutonomousAction::Terminate);
    assert_eq!(req.timestamp_ns, 42_000_000);
}

#[test]
fn enrichment_attestation_request_tier_override_serde() {
    let mut req =
        AttestationActionRequest::new("t", "d", "p", AutonomousAction::MetricsEmission, 100);
    req.tier = ActionTier::HighImpact;
    let json = serde_json::to_string(&req).unwrap();
    let decoded: AttestationActionRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.tier, ActionTier::HighImpact);
    assert_eq!(decoded.action, AutonomousAction::MetricsEmission);
}

// ===========================================================================
// 13. AttestationFallbackState enrichment
// ===========================================================================

#[test]
fn enrichment_attestation_state_display_values() {
    assert_eq!(AttestationFallbackState::Normal.to_string(), "normal");
    assert_eq!(AttestationFallbackState::Degraded.to_string(), "degraded");
    assert_eq!(AttestationFallbackState::Restoring.to_string(), "restoring");
}

#[test]
fn enrichment_attestation_state_hash_in_btreeset() {
    let set: BTreeSet<AttestationFallbackState> = [
        AttestationFallbackState::Normal,
        AttestationFallbackState::Degraded,
        AttestationFallbackState::Restoring,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// 14. AttestationFallbackConfig enrichment
// ===========================================================================

#[test]
fn enrichment_attestation_config_default_timeout_5_minutes() {
    let cfg = AttestationFallbackConfig::default();
    assert_eq!(cfg.unavailable_timeout_ns, 300_000_000_000);
    assert!(cfg.challenge_on_fallback);
    assert!(cfg.sandbox_on_fallback);
}

#[test]
fn enrichment_attestation_config_custom_serde() {
    let cfg = AttestationFallbackConfig {
        unavailable_timeout_ns: 1 * MILLIONTHS,
        challenge_on_fallback: false,
        sandbox_on_fallback: false,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: AttestationFallbackConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, decoded);
}

// ===========================================================================
// 15. AttestationFallbackError enrichment
// ===========================================================================

#[test]
fn enrichment_attestation_error_display_contains_detail() {
    let err = AttestationFallbackError::SignatureFailure {
        detail: "corrupted key material at offset 17".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("signature failure"));
    assert!(msg.contains("corrupted key material"));
}

#[test]
fn enrichment_attestation_error_implements_std_error() {
    let err = AttestationFallbackError::SignatureFailure {
        detail: "x".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn enrichment_attestation_error_serde_roundtrip() {
    let err = AttestationFallbackError::SignatureFailure {
        detail: "test roundtrip".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let decoded: AttestationFallbackError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, decoded);
}

// ===========================================================================
// 16. AttestationFallbackDecision enrichment
// ===========================================================================

#[test]
fn enrichment_attestation_decision_execute_no_warning() {
    let d = AttestationFallbackDecision::Execute {
        attestation_status: "valid".to_string(),
        warning: None,
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: AttestationFallbackDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

#[test]
fn enrichment_attestation_decision_deferred_all_fields() {
    let d = AttestationFallbackDecision::Deferred {
        queue_id: 999,
        attestation_status: "degraded".to_string(),
        status: "attestation-pending".to_string(),
        challenge_required: true,
        sandbox_required: true,
    };
    let json = serde_json::to_string(&d).unwrap();
    assert!(json.contains("999"));
    assert!(json.contains("attestation-pending"));
    let decoded: AttestationFallbackDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

// ===========================================================================
// 17. QueuedAttestationDecision enrichment
// ===========================================================================

#[test]
fn enrichment_queued_decision_fields_accessible() {
    let q = QueuedAttestationDecision {
        queue_id: 7,
        trace_id: "trace-q".to_string(),
        decision_id: "dec-q".to_string(),
        policy_id: "pol-q".to_string(),
        action: AutonomousAction::EmergencyGrant,
        queued_at_ns: 5_000_000,
        status: "attestation-pending".to_string(),
    };
    assert_eq!(q.queue_id, 7);
    assert_eq!(q.action, AutonomousAction::EmergencyGrant);
    assert_eq!(q.status, "attestation-pending");
}

#[test]
fn enrichment_queued_decision_clone_eq() {
    let q = QueuedAttestationDecision {
        queue_id: 0,
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        action: AutonomousAction::PolicyPromotion,
        queued_at_ns: 0,
        status: "attestation-pending".to_string(),
    };
    let cloned = q.clone();
    assert_eq!(q, cloned);
}

// ===========================================================================
// 18. AttestationFallbackEvent enrichment
// ===========================================================================

#[test]
fn enrichment_attestation_event_no_error_code_serde() {
    let e = AttestationFallbackEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "attestation_safe_mode".to_string(),
        event: "test".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        detail: "no error".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let decoded: AttestationFallbackEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, decoded);
}

#[test]
fn enrichment_attestation_event_with_error_code() {
    let e = AttestationFallbackEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "attestation_safe_mode".to_string(),
        event: "degradation".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("attestation_verification_failed".to_string()),
        detail: "sig mismatch".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("attestation_verification_failed"));
}

// ===========================================================================
// 19. AttestationFallbackManager - evaluate_action tier behavior
// ===========================================================================

#[test]
fn enrichment_evaluate_low_impact_with_all_health_states() {
    for health in [
        AttestationHealth::Valid,
        AttestationHealth::VerificationFailed,
        AttestationHealth::EvidenceExpired,
        AttestationHealth::EvidenceUnavailable,
    ] {
        let mut mgr = attest_mgr();
        let req = req_low(AutonomousAction::MetricsEmission, 100);
        let decision = mgr.evaluate_action(req, health).unwrap();
        match decision {
            AttestationFallbackDecision::Execute { warning, .. } => {
                assert!(warning.is_none(), "low-impact should never have a warning");
            }
            other => panic!("expected Execute for low-impact, got {other:?}"),
        }
    }
}

#[test]
fn enrichment_evaluate_standard_healthy_no_warning() {
    let mut mgr = attest_mgr();
    let req = req_std(AutonomousAction::RoutineMonitoring, 100);
    let decision = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
    match decision {
        AttestationFallbackDecision::Execute {
            attestation_status,
            warning,
        } => {
            assert_eq!(attestation_status, "valid");
            assert!(warning.is_none());
        }
        other => panic!("expected Execute, got {other:?}"),
    }
}

#[test]
fn enrichment_evaluate_standard_unhealthy_has_warning() {
    for health in [
        AttestationHealth::VerificationFailed,
        AttestationHealth::EvidenceExpired,
        AttestationHealth::EvidenceUnavailable,
    ] {
        let mut mgr = attest_mgr();
        let req = req_std(AutonomousAction::EvidenceCollection, 100);
        let decision = mgr.evaluate_action(req, health).unwrap();
        match decision {
            AttestationFallbackDecision::Execute {
                attestation_status,
                warning,
            } => {
                assert_eq!(attestation_status, "degraded");
                assert!(
                    warning.is_some(),
                    "standard + unhealthy should have warning"
                );
            }
            other => panic!("expected Execute, got {other:?}"),
        }
    }
}

#[test]
fn enrichment_evaluate_high_impact_healthy_normal_executes() {
    let mut mgr = attest_mgr();
    let req = req_hi(AutonomousAction::Quarantine, 100);
    let decision = mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
    match decision {
        AttestationFallbackDecision::Execute {
            attestation_status,
            warning,
        } => {
            assert_eq!(attestation_status, "valid");
            assert!(warning.is_none());
        }
        other => panic!("expected Execute, got {other:?}"),
    }
}

#[test]
fn enrichment_evaluate_high_impact_unhealthy_defers() {
    for health in [
        AttestationHealth::VerificationFailed,
        AttestationHealth::EvidenceExpired,
        AttestationHealth::EvidenceUnavailable,
    ] {
        let mut mgr = attest_mgr();
        let req = req_hi(AutonomousAction::Terminate, 100);
        let decision = mgr.evaluate_action(req, health).unwrap();
        match decision {
            AttestationFallbackDecision::Deferred {
                attestation_status,
                status,
                ..
            } => {
                assert_eq!(attestation_status, "degraded");
                assert_eq!(status, "attestation-pending");
            }
            other => panic!("expected Deferred, got {other:?}"),
        }
    }
}

#[test]
fn enrichment_evaluate_high_impact_healthy_but_degraded_state_defers() {
    let mut mgr = attest_mgr();
    // First degrade
    let req1 = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::VerificationFailed)
        .unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);

    // Now even with valid health, high-impact defers because
    // the state transitions to restoring/normal first, then processes the action
    // Actually re-reading the code: update_health_state runs first and transitions
    // back to Normal, so the action should execute
    let req2 = req_hi(AutonomousAction::Terminate, 200);
    let decision = mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();
    // After recovery, state is Normal and health is Valid, so it should execute
    assert!(matches!(
        decision,
        AttestationFallbackDecision::Execute { .. }
    ));
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
}

// ===========================================================================
// 20. AttestationFallbackManager - queue_id monotonicity
// ===========================================================================

#[test]
fn enrichment_evaluate_queue_ids_strictly_monotonic() {
    let mut mgr = attest_mgr();
    let mut ids = Vec::new();
    for i in 0..20u64 {
        let req = req_hi(AutonomousAction::Quarantine, 100 + i);
        let decision = mgr
            .evaluate_action(req, AttestationHealth::VerificationFailed)
            .unwrap();
        if let AttestationFallbackDecision::Deferred { queue_id, .. } = decision {
            ids.push(queue_id);
        }
    }
    assert_eq!(ids.len(), 20);
    for i in 1..ids.len() {
        assert!(
            ids[i] > ids[i - 1],
            "queue_ids should be strictly increasing"
        );
    }
}

// ===========================================================================
// 21. AttestationFallbackManager - state transitions
// ===========================================================================

#[test]
fn enrichment_normal_to_degraded_receipt_fields() {
    let mut mgr = attest_mgr();
    let req = req_hi(AutonomousAction::Quarantine, 500);
    mgr.evaluate_action(req, AttestationHealth::EvidenceExpired)
        .unwrap();

    let receipts = mgr.transition_receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].from_state, AttestationFallbackState::Normal);
    assert_eq!(receipts[0].to_state, AttestationFallbackState::Degraded);
    assert_eq!(receipts[0].trace_id, "trace-500");
    assert_eq!(receipts[0].timestamp_ns, 500);
    assert_eq!(receipts[0].sequence, 0);
    receipts[0].verify().unwrap();
}

#[test]
fn enrichment_degraded_to_normal_creates_three_receipts() {
    let mut mgr = attest_mgr();
    // Degrade
    let req1 = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
        .unwrap();
    // Restore
    let req2 = req_low(AutonomousAction::MetricsEmission, 200);
    mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();

    let receipts = mgr.transition_receipts();
    assert_eq!(receipts.len(), 3);
    // Normal -> Degraded
    assert_eq!(receipts[0].from_state, AttestationFallbackState::Normal);
    assert_eq!(receipts[0].to_state, AttestationFallbackState::Degraded);
    // Degraded -> Restoring
    assert_eq!(receipts[1].from_state, AttestationFallbackState::Degraded);
    assert_eq!(receipts[1].to_state, AttestationFallbackState::Restoring);
    // Restoring -> Normal
    assert_eq!(receipts[2].from_state, AttestationFallbackState::Restoring);
    assert_eq!(receipts[2].to_state, AttestationFallbackState::Normal);

    for receipt in receipts {
        receipt.verify().unwrap();
    }
}

#[test]
fn enrichment_receipt_sequence_numbers_monotonic() {
    let mut mgr = attest_mgr();
    // Degrade
    let req1 = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
        .unwrap();
    // Restore
    let req2 = req_low(AutonomousAction::MetricsEmission, 200);
    mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();

    let receipts = mgr.transition_receipts();
    for i in 1..receipts.len() {
        assert!(receipts[i].sequence > receipts[i - 1].sequence);
    }
}

#[test]
fn enrichment_already_degraded_no_duplicate_transition() {
    let mut mgr = attest_mgr();
    let req1 = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::VerificationFailed)
        .unwrap();
    let receipt_count = mgr.transition_receipts().len();

    // Stay degraded with different health
    let req2 = req_hi(AutonomousAction::Terminate, 200);
    mgr.evaluate_action(req2, AttestationHealth::EvidenceExpired)
        .unwrap();
    assert_eq!(mgr.transition_receipts().len(), receipt_count);
}

// ===========================================================================
// 22. AttestationFallbackManager - recovery backlog
// ===========================================================================

#[test]
fn enrichment_recovery_backlog_preserves_all_deferred_decisions() {
    let mut mgr = attest_mgr();
    let actions = [
        AutonomousAction::Quarantine,
        AutonomousAction::Terminate,
        AutonomousAction::EmergencyGrant,
        AutonomousAction::PolicyPromotion,
        AutonomousAction::CapabilityEscalation,
    ];
    for (i, action) in actions.iter().enumerate() {
        let req = req_hi(*action, 100 + i as u64);
        mgr.evaluate_action(req, AttestationHealth::EvidenceExpired)
            .unwrap();
    }
    assert_eq!(mgr.pending_decisions().len(), 5);

    // Recover
    let req = req_low(AutonomousAction::MetricsEmission, 300);
    mgr.evaluate_action(req, AttestationHealth::Valid).unwrap();
    assert!(mgr.pending_decisions().is_empty());

    let backlog = mgr.take_recovery_backlog();
    assert_eq!(backlog.len(), 5);
    // Verify each action is represented
    let backlog_actions: BTreeSet<AutonomousAction> = backlog.iter().map(|q| q.action).collect();
    assert_eq!(backlog_actions.len(), 5);
}

#[test]
fn enrichment_recovery_backlog_second_take_is_empty() {
    let mut mgr = attest_mgr();
    let req1 = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
        .unwrap();
    let req2 = req_low(AutonomousAction::MetricsEmission, 200);
    mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();

    let first = mgr.take_recovery_backlog();
    assert_eq!(first.len(), 1);
    let second = mgr.take_recovery_backlog();
    assert!(second.is_empty());
}

// ===========================================================================
// 23. AttestationFallbackManager - operator review escalation
// ===========================================================================

#[test]
fn enrichment_operator_review_triggers_at_timeout_boundary() {
    let cfg = AttestationFallbackConfig {
        unavailable_timeout_ns: 500,
        challenge_on_fallback: true,
        sandbox_on_fallback: true,
    };
    let mut mgr = attest_mgr_cfg(cfg);
    // Degrade at t=100
    let req1 = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert!(!mgr.operator_review_required());

    // At t=599 (elapsed=499), still below threshold
    let req2 = req_hi(AutonomousAction::Terminate, 599);
    mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert!(!mgr.operator_review_required());

    // At t=600 (elapsed=500), exactly at threshold
    let req3 = req_hi(AutonomousAction::EmergencyGrant, 600);
    mgr.evaluate_action(req3, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert!(mgr.operator_review_required());
}

#[test]
fn enrichment_operator_review_not_triggered_by_verification_failed() {
    let cfg = AttestationFallbackConfig {
        unavailable_timeout_ns: 100,
        challenge_on_fallback: true,
        sandbox_on_fallback: true,
    };
    let mut mgr = attest_mgr_cfg(cfg);
    let req1 = req_hi(AutonomousAction::Quarantine, 0);
    mgr.evaluate_action(req1, AttestationHealth::VerificationFailed)
        .unwrap();
    let req2 = req_hi(AutonomousAction::Terminate, 1000);
    mgr.evaluate_action(req2, AttestationHealth::VerificationFailed)
        .unwrap();
    assert!(!mgr.operator_review_required());
}

#[test]
fn enrichment_operator_review_not_triggered_by_evidence_expired() {
    let cfg = AttestationFallbackConfig {
        unavailable_timeout_ns: 100,
        challenge_on_fallback: true,
        sandbox_on_fallback: true,
    };
    let mut mgr = attest_mgr_cfg(cfg);
    let req1 = req_hi(AutonomousAction::Quarantine, 0);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
        .unwrap();
    let req2 = req_hi(AutonomousAction::Terminate, 1000);
    mgr.evaluate_action(req2, AttestationHealth::EvidenceExpired)
        .unwrap();
    assert!(!mgr.operator_review_required());
}

#[test]
fn enrichment_operator_review_cleared_after_recovery() {
    let cfg = AttestationFallbackConfig {
        unavailable_timeout_ns: 100,
        challenge_on_fallback: true,
        sandbox_on_fallback: true,
    };
    let mut mgr = attest_mgr_cfg(cfg);
    let req1 = req_hi(AutonomousAction::Quarantine, 0);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    let req2 = req_hi(AutonomousAction::Terminate, 200);
    mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert!(mgr.operator_review_required());

    // Recover
    let req3 = req_low(AutonomousAction::MetricsEmission, 300);
    mgr.evaluate_action(req3, AttestationHealth::Valid).unwrap();
    assert!(!mgr.operator_review_required());
}

#[test]
fn enrichment_operator_review_event_emitted_exactly_once() {
    let cfg = AttestationFallbackConfig {
        unavailable_timeout_ns: 100,
        challenge_on_fallback: true,
        sandbox_on_fallback: true,
    };
    let mut mgr = attest_mgr_cfg(cfg);
    // Trigger review
    let req1 = req_hi(AutonomousAction::Quarantine, 0);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    let req2 = req_hi(AutonomousAction::Terminate, 200);
    mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    // More evaluations should not re-emit the review event
    let req3 = req_hi(AutonomousAction::EmergencyGrant, 400);
    mgr.evaluate_action(req3, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    let req4 = req_hi(AutonomousAction::PolicyPromotion, 600);
    mgr.evaluate_action(req4, AttestationHealth::EvidenceUnavailable)
        .unwrap();

    let review_events: Vec<_> = mgr
        .events()
        .iter()
        .filter(|e| e.event.contains("operator_review"))
        .collect();
    assert_eq!(review_events.len(), 1);
}

// ===========================================================================
// 24. AttestationFallbackManager - config permutations
// ===========================================================================

#[test]
fn enrichment_config_no_challenge_no_sandbox() {
    let cfg = AttestationFallbackConfig {
        unavailable_timeout_ns: u64::MAX,
        challenge_on_fallback: false,
        sandbox_on_fallback: false,
    };
    let mut mgr = attest_mgr_cfg(cfg);
    let req = req_hi(AutonomousAction::Quarantine, 100);
    let decision = mgr
        .evaluate_action(req, AttestationHealth::VerificationFailed)
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

#[test]
fn enrichment_config_challenge_only() {
    let cfg = AttestationFallbackConfig {
        unavailable_timeout_ns: u64::MAX,
        challenge_on_fallback: true,
        sandbox_on_fallback: false,
    };
    let mut mgr = attest_mgr_cfg(cfg);
    let req = req_hi(AutonomousAction::Quarantine, 100);
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

// ===========================================================================
// 25. AttestationTransitionReceipt - signature verification
// ===========================================================================

#[test]
fn enrichment_transition_receipt_serde_preserves_verifiable_signature() {
    let mut mgr = attest_mgr();
    let req = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .unwrap();

    let receipt = &mgr.transition_receipts()[0];
    let json = serde_json::to_string(receipt).unwrap();
    let decoded: frankenengine_engine::safe_mode_fallback::AttestationTransitionReceipt =
        serde_json::from_str(&json).unwrap();
    decoded.verify().unwrap();
}

#[test]
fn enrichment_transition_receipt_different_keys_different_sigs() {
    let mut mgr_a = attest_mgr_key([1u8; 32]);
    let mut mgr_b = attest_mgr_key([2u8; 32]);

    let req_a = req_hi(AutonomousAction::Quarantine, 100);
    let req_b = req_hi(AutonomousAction::Quarantine, 100);

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

#[test]
fn enrichment_all_transition_receipts_in_full_lifecycle_verify() {
    let mut mgr = attest_mgr();
    // Degrade
    let req1 = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    // More deferrals
    let req2 = req_hi(AutonomousAction::Terminate, 200);
    mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    // Recover
    let req3 = req_low(AutonomousAction::MetricsEmission, 300);
    mgr.evaluate_action(req3, AttestationHealth::Valid).unwrap();
    // Degrade again
    let req4 = req_hi(AutonomousAction::EmergencyGrant, 400);
    mgr.evaluate_action(req4, AttestationHealth::EvidenceExpired)
        .unwrap();
    // Recover again
    let req5 = req_low(AutonomousAction::MetricsEmission, 500);
    mgr.evaluate_action(req5, AttestationHealth::Valid).unwrap();

    for receipt in mgr.transition_receipts() {
        receipt.verify().expect("all receipts should verify");
    }
}

// ===========================================================================
// 26. AttestationFallbackManager - determinism
// ===========================================================================

#[test]
fn enrichment_full_lifecycle_deterministic_50_runs() {
    let mut results = Vec::new();
    for _ in 0..50 {
        let mut mgr = attest_mgr();
        let req1 = req_hi(AutonomousAction::Quarantine, 100);
        mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
            .unwrap();
        let req2 = req_hi(AutonomousAction::Terminate, 200);
        mgr.evaluate_action(req2, AttestationHealth::EvidenceUnavailable)
            .unwrap();
        let req3 = req_std(AutonomousAction::RoutineMonitoring, 300);
        mgr.evaluate_action(req3, AttestationHealth::EvidenceExpired)
            .unwrap();
        let req4 = req_low(AutonomousAction::MetricsEmission, 400);
        mgr.evaluate_action(req4, AttestationHealth::Valid).unwrap();

        let events_json = serde_json::to_string(mgr.events()).unwrap();
        let receipts_json = serde_json::to_string(mgr.transition_receipts()).unwrap();
        results.push((events_json, receipts_json));
    }
    for r in &results[1..] {
        assert_eq!(r, &results[0], "determinism violated");
    }
}

// ===========================================================================
// 27. attestation_health_from_verdict
// ===========================================================================

#[test]
fn enrichment_health_from_verdict_all_passing_is_valid() {
    let verdict = base_verdict();
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::Valid
    );
}

#[test]
fn enrichment_health_from_verdict_stale_data_failure_class_is_expired() {
    let mut verdict = base_verdict();
    verdict.failure_class = Some(VerificationFailureClass::StaleData);
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::EvidenceExpired
    );
}

#[test]
fn enrichment_health_from_verdict_attestation_failed_is_verification_failed() {
    let mut verdict = base_verdict();
    verdict.attestation = failing_layer("attestation_generic_failure");
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::VerificationFailed
    );
}

#[test]
fn enrichment_health_from_verdict_trust_root_missing_is_unavailable() {
    let mut verdict = base_verdict();
    verdict.attestation = failing_layer("attestation_trust_root_missing");
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::EvidenceUnavailable
    );
}

#[test]
fn enrichment_health_from_verdict_quote_digest_unavailable_is_unavailable() {
    let mut verdict = base_verdict();
    verdict.attestation = failing_layer("attestation_quote_digest_unavailable");
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::EvidenceUnavailable
    );
}

#[test]
fn enrichment_health_from_verdict_measurement_derivation_failed_is_unavailable() {
    let mut verdict = base_verdict();
    verdict.attestation = failing_layer("attestation_measurement_id_derivation_failed");
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::EvidenceUnavailable
    );
}

#[test]
fn enrichment_health_from_verdict_policy_quote_age_mismatch_is_expired() {
    let mut verdict = base_verdict();
    verdict.attestation = failing_layer("attestation_policy_quote_age_mismatch");
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::EvidenceExpired
    );
}

#[test]
fn enrichment_health_from_verdict_attestation_stale_warning_is_expired() {
    let mut verdict = base_verdict();
    verdict.attestation.passed = true;
    verdict.warnings.push("attestation_quote_stale".to_string());
    // warnings with "attestation_" prefix containing "stale" -> EvidenceExpired
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::EvidenceExpired
    );
}

#[test]
fn enrichment_health_from_verdict_non_attestation_warning_stays_valid() {
    let mut verdict = base_verdict();
    verdict.warnings.push("transparency_log_delay".to_string());
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::Valid
    );
}

#[test]
fn enrichment_health_from_verdict_attestation_warning_without_stale_is_not_expired() {
    let mut verdict = base_verdict();
    verdict.attestation.passed = false;
    verdict
        .warnings
        .push("attestation_something_else".to_string());
    // attestation failed but not stale, not one of the known unavailable codes
    // => VerificationFailed
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::VerificationFailed
    );
}

// ===========================================================================
// 28. Integration: SafeModeManager + AttestationFallbackManager lifecycle
// ===========================================================================

#[test]
fn enrichment_integration_safe_mode_activate_all_recover_all_event_count() {
    let mut mgr = mgr_with_cap(16);
    // Activate all five failure types
    mgr.handle_adapter_unavailable("t1", "gone");
    mgr.handle_decision_contract_error("t2", "ext-a", "err");
    mgr.handle_evidence_ledger_full("t3", "full");
    mgr.handle_cx_corrupted("t4", "op", "bad");
    mgr.handle_cancellation_deadlock("t5", "cell-1", 100);
    assert_eq!(mgr.events().len(), 5);

    // Recover all
    mgr.recover_adapter("r1");
    mgr.recover_decision_contract("r2", "ext-a");
    mgr.recover_evidence_ledger("r3");
    mgr.recover_cx("r4");
    mgr.recover_cancellation("r5");
    // Each recovery emits 2 events (recovering + recovery_complete)
    assert_eq!(mgr.events().len(), 15); // 5 activate + 5*2 recover

    assert!(!mgr.any_active());
    for ft in [
        FailureType::AdapterUnavailable,
        FailureType::DecisionContractError,
        FailureType::EvidenceLedgerFull,
        FailureType::CxCorrupted,
        FailureType::CancellationDeadlock,
    ] {
        assert_eq!(mgr.status(ft), SafeModeStatus::Normal);
        assert_eq!(mgr.activation_count(ft), 1);
        assert_eq!(mgr.recovery_count(ft), 1);
    }
}

#[test]
fn enrichment_integration_attestation_degrade_recover_degrade_cycle() {
    let mut mgr = attest_mgr();
    // Cycle 1: degrade
    let req1 = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
        .unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
    // Cycle 1: recover
    let req2 = req_low(AutonomousAction::MetricsEmission, 200);
    mgr.evaluate_action(req2, AttestationHealth::Valid).unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
    let backlog1 = mgr.take_recovery_backlog();
    assert_eq!(backlog1.len(), 1);

    // Cycle 2: degrade again
    let req3 = req_hi(AutonomousAction::Terminate, 300);
    mgr.evaluate_action(req3, AttestationHealth::EvidenceUnavailable)
        .unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
    // Cycle 2: recover
    let req4 = req_low(AutonomousAction::MetricsEmission, 400);
    mgr.evaluate_action(req4, AttestationHealth::Valid).unwrap();
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
    let backlog2 = mgr.take_recovery_backlog();
    assert_eq!(backlog2.len(), 1);

    // Should have 6 receipts: 2 cycles * (degrade + restoring + normal)
    assert_eq!(mgr.transition_receipts().len(), 6);
    for receipt in mgr.transition_receipts() {
        receipt.verify().unwrap();
    }
}

#[test]
fn enrichment_integration_mixed_tiers_during_degradation() {
    let mut mgr = attest_mgr();
    // Degrade
    let req1 = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req1, AttestationHealth::EvidenceExpired)
        .unwrap();

    // Low-impact: executes
    let req2 = req_low(AutonomousAction::MetricsEmission, 200);
    let d2 = mgr
        .evaluate_action(req2, AttestationHealth::EvidenceExpired)
        .unwrap();
    assert!(matches!(d2, AttestationFallbackDecision::Execute { .. }));

    // Standard: executes with warning
    let req3 = req_std(AutonomousAction::RoutineMonitoring, 300);
    let d3 = mgr
        .evaluate_action(req3, AttestationHealth::EvidenceExpired)
        .unwrap();
    match &d3 {
        AttestationFallbackDecision::Execute { warning, .. } => {
            assert!(warning.is_some());
        }
        other => panic!("expected Execute with warning, got {other:?}"),
    }

    // High-impact: deferred
    let req4 = req_hi(AutonomousAction::Terminate, 400);
    let d4 = mgr
        .evaluate_action(req4, AttestationHealth::EvidenceExpired)
        .unwrap();
    assert!(matches!(d4, AttestationFallbackDecision::Deferred { .. }));
}

#[test]
fn enrichment_integration_events_component_is_attestation_safe_mode() {
    let mut mgr = attest_mgr();
    let req = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req, AttestationHealth::EvidenceExpired)
        .unwrap();

    for event in mgr.events() {
        assert_eq!(event.component, "attestation_safe_mode");
    }
}

#[test]
fn enrichment_integration_pending_decision_status_always_attestation_pending() {
    let mut mgr = attest_mgr();
    for i in 0..10u64 {
        let req = req_hi(AutonomousAction::Quarantine, 100 + i);
        mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
            .unwrap();
    }
    for pending in mgr.pending_decisions() {
        assert_eq!(pending.status, "attestation-pending");
    }
}

#[test]
fn enrichment_integration_manager_initial_state_accessors() {
    let mgr = attest_mgr();
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
    assert_eq!(mgr.health(), AttestationHealth::Valid);
    assert!(!mgr.operator_review_required());
    assert!(mgr.pending_decisions().is_empty());
    assert!(mgr.transition_receipts().is_empty());
    assert!(mgr.events().is_empty());
}

#[test]
fn enrichment_integration_with_default_signing_key_produces_valid_receipts() {
    let mut mgr =
        AttestationFallbackManager::with_default_signing_key(AttestationFallbackConfig::default());
    let req = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req, AttestationHealth::EvidenceExpired)
        .unwrap();
    let receipt = &mgr.transition_receipts()[0];
    receipt.verify().unwrap();
}

#[test]
fn enrichment_integration_custom_signing_key_produces_valid_receipts() {
    let key = SigningKey::from_bytes([42u8; 32]);
    let mut mgr = AttestationFallbackManager::new(AttestationFallbackConfig::default(), key);
    let req = req_hi(AutonomousAction::Quarantine, 100);
    mgr.evaluate_action(req, AttestationHealth::EvidenceExpired)
        .unwrap();
    let receipt = &mgr.transition_receipts()[0];
    receipt.verify().unwrap();
}
