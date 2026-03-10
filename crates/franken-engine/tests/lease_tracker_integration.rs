#![forbid(unsafe_code)]

//! Integration tests for the `lease_tracker` module.
//!
//! Covers: LeaseId, LeaseType, LeaseStatus, EscalationAction, Lease,
//! LeaseEvent, LeaseError, LeaseStore.

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

use frankenengine_engine::lease_tracker::{
    EscalationAction, Lease, LeaseError, LeaseEvent, LeaseId, LeaseStatus, LeaseStore, LeaseType,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// =========================================================================
// Section 1: Display implementations
// =========================================================================

#[test]
fn lease_id_display() {
    assert_eq!(LeaseId::from_raw(0).to_string(), "lease:0");
    assert_eq!(LeaseId::from_raw(42).to_string(), "lease:42");
    assert_eq!(
        LeaseId::from_raw(u64::MAX).to_string(),
        format!("lease:{}", u64::MAX)
    );
}

#[test]
fn lease_type_display_all_variants() {
    assert_eq!(LeaseType::RemoteEndpoint.to_string(), "remote_endpoint");
    assert_eq!(LeaseType::Operation.to_string(), "operation");
    assert_eq!(LeaseType::Session.to_string(), "session");
}

#[test]
fn lease_status_display_all_variants() {
    assert_eq!(LeaseStatus::Active.to_string(), "active");
    assert_eq!(LeaseStatus::Expired.to_string(), "expired");
    assert_eq!(LeaseStatus::Released.to_string(), "released");
}

#[test]
fn escalation_action_display_all_variants() {
    let a1 = EscalationAction::MarkEndpointUnreachable {
        holder: "node-1".to_string(),
    };
    assert_eq!(a1.to_string(), "mark_endpoint_unreachable(node-1)");

    let a2 = EscalationAction::CancelOperation {
        holder: "op-alpha".to_string(),
    };
    assert_eq!(a2.to_string(), "cancel_operation(op-alpha)");

    let a3 = EscalationAction::TerminateSession {
        holder: "sess-99".to_string(),
    };
    assert_eq!(a3.to_string(), "terminate_session(sess-99)");
}

#[test]
fn lease_error_display_all_variants() {
    let e1 = LeaseError::LeaseNotFound { lease_id: 42 };
    assert!(e1.to_string().contains("42"));
    assert!(e1.to_string().contains("not found"));

    let e2 = LeaseError::LeaseExpired {
        lease_id: 7,
        expired_at: 1000,
    };
    assert!(e2.to_string().contains("7"));
    assert!(e2.to_string().contains("1000"));

    let e3 = LeaseError::LeaseReleased { lease_id: 3 };
    assert!(e3.to_string().contains("3"));
    assert!(e3.to_string().contains("released"));

    let e4 = LeaseError::EpochMismatch {
        lease_id: 5,
        lease_epoch: epoch(1),
        current_epoch: epoch(3),
    };
    let msg4 = e4.to_string();
    assert!(msg4.contains("5"), "got: {msg4}");
    assert!(msg4.contains("epoch:1"), "got: {msg4}");
    assert!(msg4.contains("epoch:3"), "got: {msg4}");

    let e5 = LeaseError::ZeroTtl;
    assert!(e5.to_string().contains("non-zero"));

    let e6 = LeaseError::EmptyHolder;
    assert!(e6.to_string().contains("non-empty"));
}

#[test]
fn lease_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(LeaseError::ZeroTtl);
    let _ = err.to_string();
}

// =========================================================================
// Section 2: Construction and defaults
// =========================================================================

#[test]
fn lease_id_from_raw_and_as_u64() {
    let id = LeaseId::from_raw(99);
    assert_eq!(id.as_u64(), 99);
    assert_eq!(id.0, 99);
}

#[test]
fn lease_store_new_empty() {
    let store = LeaseStore::new(epoch(1));
    assert_eq!(store.epoch(), epoch(1));
    assert_eq!(store.active_count(), 0);
    assert_eq!(store.total_count(), 0);
    assert!(store.event_counts().is_empty());
}

#[test]
fn lease_construction_direct() {
    let lease = Lease {
        lease_id: LeaseId::from_raw(1),
        holder: "node-1".to_string(),
        lease_type: LeaseType::RemoteEndpoint,
        granted_at: 100,
        expires_at: 200,
        ttl: 100,
        epoch: epoch(1),
        renewal_count: 0,
        status: LeaseStatus::Active,
    };
    assert_eq!(lease.holder, "node-1");
    assert_eq!(lease.ttl, 100);
    assert!(lease.is_active_at(150));
    assert!(!lease.is_active_at(200));
    assert!(!lease.is_active_at(201));
}

// =========================================================================
// Section 3: Lease grant
// =========================================================================

#[test]
fn grant_basic() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "trace-1")
        .unwrap();
    assert_eq!(id.as_u64(), 1);
    assert_eq!(store.active_count(), 1);
    assert_eq!(store.total_count(), 1);

    let lease = store.get(&id).unwrap();
    assert_eq!(lease.holder, "node-1");
    assert_eq!(lease.lease_type, LeaseType::RemoteEndpoint);
    assert_eq!(lease.ttl, 100);
    assert_eq!(lease.granted_at, 0);
    assert_eq!(lease.expires_at, 100);
    assert_eq!(lease.renewal_count, 0);
    assert_eq!(lease.status, LeaseStatus::Active);
    assert_eq!(lease.epoch, epoch(1));
}

#[test]
fn grant_assigns_monotonic_ids() {
    let mut store = LeaseStore::new(epoch(1));
    let id1 = store.grant("a", LeaseType::Operation, 100, 0, "t").unwrap();
    let id2 = store.grant("b", LeaseType::Session, 200, 10, "t").unwrap();
    let id3 = store
        .grant("c", LeaseType::RemoteEndpoint, 300, 20, "t")
        .unwrap();
    assert_eq!(id1.as_u64(), 1);
    assert_eq!(id2.as_u64(), 2);
    assert_eq!(id3.as_u64(), 3);
}

#[test]
fn grant_all_lease_types() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("ep", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    store
        .grant("op", LeaseType::Operation, 100, 0, "t")
        .unwrap();
    store
        .grant("sess", LeaseType::Session, 100, 0, "t")
        .unwrap();
    assert_eq!(store.active_count(), 3);
}

#[test]
fn grant_rejects_zero_ttl() {
    let mut store = LeaseStore::new(epoch(1));
    let err = store
        .grant("node-1", LeaseType::RemoteEndpoint, 0, 0, "t")
        .unwrap_err();
    assert!(matches!(err, LeaseError::ZeroTtl));
}

#[test]
fn grant_rejects_empty_holder() {
    let mut store = LeaseStore::new(epoch(1));
    let err = store
        .grant("", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap_err();
    assert!(matches!(err, LeaseError::EmptyHolder));
}

#[test]
fn grant_with_nonzero_start_tick() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 500, "t")
        .unwrap();
    let lease = store.get(&id).unwrap();
    assert_eq!(lease.granted_at, 500);
    assert_eq!(lease.expires_at, 600);
}

// =========================================================================
// Section 4: Lease check
// =========================================================================

#[test]
fn check_active_before_expiry() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    assert_eq!(store.check(&id, 0).unwrap(), LeaseStatus::Active);
    assert_eq!(store.check(&id, 50).unwrap(), LeaseStatus::Active);
    assert_eq!(store.check(&id, 99).unwrap(), LeaseStatus::Active);
}

#[test]
fn check_transitions_to_expired_at_expiry() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    assert_eq!(store.check(&id, 100).unwrap(), LeaseStatus::Expired);
}

#[test]
fn check_expired_stays_expired() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    assert_eq!(store.check(&id, 200).unwrap(), LeaseStatus::Expired);
    assert_eq!(store.check(&id, 300).unwrap(), LeaseStatus::Expired);
}

#[test]
fn check_released_stays_released() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    store.release(&id, "t").unwrap();
    assert_eq!(store.check(&id, 0).unwrap(), LeaseStatus::Released);
    // Released at tick 0, checking at tick 200 still shows Released (not Expired)
    assert_eq!(store.check(&id, 200).unwrap(), LeaseStatus::Released);
}

#[test]
fn check_unknown_lease() {
    let mut store = LeaseStore::new(epoch(1));
    let err = store.check(&LeaseId::from_raw(999), 0).unwrap_err();
    assert!(matches!(err, LeaseError::LeaseNotFound { lease_id: 999 }));
}

// =========================================================================
// Section 5: Lease renewal
// =========================================================================

#[test]
fn renew_extends_expiration() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();

    store.renew(&id, 50, "t-renew").unwrap();
    let lease = store.get(&id).unwrap();
    assert_eq!(lease.expires_at, 150); // 50 + 100
    assert_eq!(lease.renewal_count, 1);
}

#[test]
fn renew_multiple_times() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();

    store.renew(&id, 30, "t1").unwrap();
    assert_eq!(store.get(&id).unwrap().expires_at, 130);
    assert_eq!(store.get(&id).unwrap().renewal_count, 1);

    store.renew(&id, 60, "t2").unwrap();
    assert_eq!(store.get(&id).unwrap().expires_at, 160);
    assert_eq!(store.get(&id).unwrap().renewal_count, 2);

    store.renew(&id, 100, "t3").unwrap();
    assert_eq!(store.get(&id).unwrap().expires_at, 200);
    assert_eq!(store.get(&id).unwrap().renewal_count, 3);
}

#[test]
fn renew_expired_fails() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();

    let err = store.renew(&id, 200, "t-renew").unwrap_err();
    assert!(matches!(err, LeaseError::LeaseExpired { .. }));
    // Lease should now be marked as expired
    assert_eq!(store.get(&id).unwrap().status, LeaseStatus::Expired);
}

#[test]
fn renew_released_fails() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    store.release(&id, "t").unwrap();

    let err = store.renew(&id, 50, "t-renew").unwrap_err();
    assert!(matches!(err, LeaseError::LeaseReleased { .. }));
}

#[test]
fn renew_unknown_fails() {
    let mut store = LeaseStore::new(epoch(1));
    let err = store.renew(&LeaseId::from_raw(999), 0, "t").unwrap_err();
    assert!(matches!(err, LeaseError::LeaseNotFound { lease_id: 999 }));
}

#[test]
fn renew_after_epoch_mismatch() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 1000, 0, "t")
        .unwrap();
    store.advance_epoch(epoch(2), "t-epoch");

    // Lease was expired by epoch advance, so renew fails with LeaseExpired
    let err = store.renew(&id, 50, "t-renew").unwrap_err();
    assert!(matches!(err, LeaseError::LeaseExpired { .. }));
}

// =========================================================================
// Section 6: Lease release
// =========================================================================

#[test]
fn release_basic() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    store.release(&id, "t-rel").unwrap();

    let lease = store.get(&id).unwrap();
    assert_eq!(lease.status, LeaseStatus::Released);
    assert_eq!(store.active_count(), 0);
    assert_eq!(store.total_count(), 1); // still tracked
}

#[test]
fn double_release_fails() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    store.release(&id, "t1").unwrap();
    let err = store.release(&id, "t2").unwrap_err();
    assert!(matches!(err, LeaseError::LeaseReleased { .. }));
}

#[test]
fn release_unknown_fails() {
    let mut store = LeaseStore::new(epoch(1));
    let err = store.release(&LeaseId::from_raw(999), "t").unwrap_err();
    assert!(matches!(err, LeaseError::LeaseNotFound { lease_id: 999 }));
}

#[test]
fn release_already_expired_succeeds() {
    // An expired lease can still be released (status transitions to Released)
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    // Force expiration via check
    store.check(&id, 200).unwrap();
    assert_eq!(store.get(&id).unwrap().status, LeaseStatus::Expired);

    // Release the expired lease
    store.release(&id, "t-rel").unwrap();
    assert_eq!(store.get(&id).unwrap().status, LeaseStatus::Released);
}

// =========================================================================
// Section 7: Expiration scanning
// =========================================================================

#[test]
fn scan_detects_expired_lease() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();

    let actions = store.scan_expired(200, "t-scan");
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        &actions[0],
        EscalationAction::MarkEndpointUnreachable { holder } if holder == "node-1"
    ));
}

#[test]
fn scan_does_not_detect_active_lease() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();

    let actions = store.scan_expired(50, "t-scan");
    assert!(actions.is_empty());
}

#[test]
fn scan_detects_multiple_expired() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("ep", LeaseType::RemoteEndpoint, 100, 0, "t1")
        .unwrap();
    store
        .grant("op", LeaseType::Operation, 50, 10, "t2")
        .unwrap();
    store
        .grant("sess", LeaseType::Session, 80, 0, "t3")
        .unwrap();

    // At tick 200, all should be expired
    let actions = store.scan_expired(200, "t-scan");
    assert_eq!(actions.len(), 3);
}

#[test]
fn scan_partial_expiration() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("ep", LeaseType::RemoteEndpoint, 100, 0, "t1")
        .unwrap();
    store
        .grant("op", LeaseType::Operation, 50, 10, "t2")
        .unwrap();

    // At tick 70: op (expires at 60) expired, ep (expires at 100) still active
    let actions = store.scan_expired(70, "t-scan");
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        &actions[0],
        EscalationAction::CancelOperation { holder } if holder == "op"
    ));
}

#[test]
fn scan_skips_already_expired_leases() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();

    let a1 = store.scan_expired(200, "t1");
    assert_eq!(a1.len(), 1);

    // Second scan should not re-escalate
    let a2 = store.scan_expired(300, "t2");
    assert!(a2.is_empty());
}

#[test]
fn scan_skips_released_leases() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    store.release(&id, "t-rel").unwrap();

    let actions = store.scan_expired(200, "t-scan");
    assert!(
        actions.is_empty(),
        "released leases should not trigger escalation"
    );
}

#[test]
fn scan_correct_escalation_per_type() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("ep", LeaseType::RemoteEndpoint, 10, 0, "t")
        .unwrap();
    store.grant("op", LeaseType::Operation, 10, 0, "t").unwrap();
    store.grant("sess", LeaseType::Session, 10, 0, "t").unwrap();

    let actions = store.scan_expired(100, "t-scan");
    assert_eq!(actions.len(), 3);

    let has_endpoint = actions.iter().any(
        |a| matches!(a, EscalationAction::MarkEndpointUnreachable { holder } if holder == "ep"),
    );
    let has_operation = actions
        .iter()
        .any(|a| matches!(a, EscalationAction::CancelOperation { holder } if holder == "op"));
    let has_session = actions
        .iter()
        .any(|a| matches!(a, EscalationAction::TerminateSession { holder } if holder == "sess"));

    assert!(has_endpoint, "missing endpoint escalation");
    assert!(has_operation, "missing operation escalation");
    assert!(has_session, "missing session escalation");
}

// =========================================================================
// Section 8: Epoch binding
// =========================================================================

#[test]
fn advance_epoch_invalidates_active_leases() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
        .unwrap();
    store
        .grant("op-1", LeaseType::Operation, 1000, 0, "t")
        .unwrap();

    let actions = store.advance_epoch(epoch(2), "t-epoch");
    assert_eq!(actions.len(), 2);
    assert_eq!(store.active_count(), 0);
    assert_eq!(store.epoch(), epoch(2));
}

#[test]
fn advance_epoch_skips_already_expired() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    // Force expiration
    store.check(&id, 200).unwrap();

    let actions = store.advance_epoch(epoch(2), "t-epoch");
    assert!(
        actions.is_empty(),
        "already expired leases should not be re-escalated"
    );
}

#[test]
fn advance_epoch_skips_released() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
        .unwrap();
    store.release(&id, "t-rel").unwrap();

    let actions = store.advance_epoch(epoch(2), "t-epoch");
    assert!(
        actions.is_empty(),
        "released leases should not be re-escalated"
    );
}

#[test]
fn grant_after_epoch_advance_uses_new_epoch() {
    let mut store = LeaseStore::new(epoch(1));
    store.advance_epoch(epoch(5), "t");

    let id = store
        .grant("node-2", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    let lease = store.get(&id).unwrap();
    assert_eq!(lease.epoch, epoch(5));
}

#[test]
fn multiple_epoch_advances() {
    let mut store = LeaseStore::new(epoch(1));
    for ep in 2..=10 {
        store
            .grant(&format!("n-{ep}"), LeaseType::RemoteEndpoint, 1000, 0, "t")
            .unwrap();
        let actions = store.advance_epoch(epoch(ep), "t");
        assert!(!actions.is_empty());
        assert_eq!(store.epoch(), epoch(ep));
    }
}

// =========================================================================
// Section 9: Renewal due
// =========================================================================

#[test]
fn renewal_due_at_calculation() {
    let lease = Lease {
        lease_id: LeaseId::from_raw(1),
        holder: "n".to_string(),
        lease_type: LeaseType::RemoteEndpoint,
        granted_at: 100,
        expires_at: 400,
        ttl: 300,
        epoch: epoch(1),
        renewal_count: 0,
        status: LeaseStatus::Active,
    };
    // renewal_due_at = expires_at - ttl + ttl/3 = 400 - 300 + 100 = 200
    assert_eq!(lease.renewal_due_at(), 200);
}

#[test]
fn renewal_due_at_zero_granted() {
    let lease = Lease {
        lease_id: LeaseId::from_raw(1),
        holder: "n".to_string(),
        lease_type: LeaseType::RemoteEndpoint,
        granted_at: 0,
        expires_at: 300,
        ttl: 300,
        epoch: epoch(1),
        renewal_count: 0,
        status: LeaseStatus::Active,
    };
    // renewal_due_at = 300 - 300 + 100 = 100
    assert_eq!(lease.renewal_due_at(), 100);
}

#[test]
fn leases_due_for_renewal_single() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("node-1", LeaseType::RemoteEndpoint, 300, 0, "t")
        .unwrap();

    // renewal_due_at = 0 + 100 = 100
    let due_before = store.leases_due_for_renewal(50);
    assert!(due_before.is_empty());

    let due_at = store.leases_due_for_renewal(100);
    assert_eq!(due_at.len(), 1);
    assert_eq!(due_at[0], id);

    let due_after = store.leases_due_for_renewal(200);
    assert_eq!(due_after.len(), 1);
}

#[test]
fn leases_due_for_renewal_multiple() {
    let mut store = LeaseStore::new(epoch(1));
    let id1 = store
        .grant("n1", LeaseType::RemoteEndpoint, 300, 0, "t")
        .unwrap();
    let _id2 = store
        .grant("n2", LeaseType::RemoteEndpoint, 900, 0, "t")
        .unwrap();

    // id1: renewal_due_at = 0 + 100 = 100
    // id2: renewal_due_at = 0 + 300 = 300
    let due = store.leases_due_for_renewal(150);
    assert_eq!(due.len(), 1);
    assert_eq!(due[0], id1);

    let due_later = store.leases_due_for_renewal(500);
    assert_eq!(due_later.len(), 2);
}

#[test]
fn leases_due_for_renewal_excludes_released() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 300, 0, "t")
        .unwrap();
    store.release(&id, "t").unwrap();

    let due = store.leases_due_for_renewal(200);
    assert!(due.is_empty());
}

#[test]
fn leases_due_for_renewal_excludes_expired() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    // Force expiration
    store.check(&id, 200).unwrap();

    let due = store.leases_due_for_renewal(50);
    assert!(due.is_empty());
}

// =========================================================================
// Section 10: Lease escalation actions
// =========================================================================

#[test]
fn escalation_for_remote_endpoint() {
    let lease = Lease {
        lease_id: LeaseId::from_raw(1),
        holder: "cloud-1".to_string(),
        lease_type: LeaseType::RemoteEndpoint,
        granted_at: 0,
        expires_at: 100,
        ttl: 100,
        epoch: epoch(1),
        renewal_count: 0,
        status: LeaseStatus::Active,
    };
    let action = lease.escalation_action();
    assert!(matches!(
        action,
        EscalationAction::MarkEndpointUnreachable { holder } if holder == "cloud-1"
    ));
}

#[test]
fn escalation_for_operation() {
    let lease = Lease {
        lease_id: LeaseId::from_raw(2),
        holder: "op-sync".to_string(),
        lease_type: LeaseType::Operation,
        granted_at: 0,
        expires_at: 100,
        ttl: 100,
        epoch: epoch(1),
        renewal_count: 0,
        status: LeaseStatus::Active,
    };
    assert!(matches!(
        lease.escalation_action(),
        EscalationAction::CancelOperation { holder } if holder == "op-sync"
    ));
}

#[test]
fn escalation_for_session() {
    let lease = Lease {
        lease_id: LeaseId::from_raw(3),
        holder: "session-abc".to_string(),
        lease_type: LeaseType::Session,
        granted_at: 0,
        expires_at: 100,
        ttl: 100,
        epoch: epoch(1),
        renewal_count: 0,
        status: LeaseStatus::Active,
    };
    assert!(matches!(
        lease.escalation_action(),
        EscalationAction::TerminateSession { holder } if holder == "session-abc"
    ));
}

// =========================================================================
// Section 11: Audit events
// =========================================================================

#[test]
fn grant_emits_event() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "trace-g")
        .unwrap();

    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "grant");
    assert_eq!(events[0].holder, "node-1");
    assert_eq!(events[0].trace_id, "trace-g");
    assert_eq!(events[0].status, "active");
    assert_eq!(events[0].ttl, 100);
    assert_eq!(events[0].epoch_id, 1);
    assert_eq!(events[0].renewal_count, 0);
    assert!(events[0].escalation_action.is_empty());
}

#[test]
fn renew_emits_event() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    store.drain_events();

    store.renew(&id, 50, "trace-r").unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "renew");
    assert_eq!(events[0].renewal_count, 1);
    assert_eq!(events[0].trace_id, "trace-r");
    assert_eq!(events[0].status, "active");
}

#[test]
fn release_emits_event() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    store.drain_events();

    store.release(&id, "trace-rel").unwrap();
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "release");
    assert_eq!(events[0].status, "released");
    assert_eq!(events[0].trace_id, "trace-rel");
}

#[test]
fn expiration_emits_event_with_escalation() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    store.drain_events();

    store.scan_expired(200, "trace-exp");
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "expiration");
    assert_eq!(events[0].status, "expired");
    assert!(
        events[0]
            .escalation_action
            .contains("mark_endpoint_unreachable")
    );
}

#[test]
fn epoch_invalidation_emits_event() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
        .unwrap();
    store.drain_events();

    store.advance_epoch(epoch(2), "trace-epoch");
    let events = store.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "epoch_invalidation");
    assert_eq!(events[0].epoch_id, 2);
    assert!(
        events[0]
            .escalation_action
            .contains("mark_endpoint_unreachable")
    );
}

#[test]
fn drain_events_clears_buffer() {
    let mut store = LeaseStore::new(epoch(1));
    store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    let e1 = store.drain_events();
    assert_eq!(e1.len(), 1);
    let e2 = store.drain_events();
    assert!(e2.is_empty());
}

#[test]
fn event_counts_accumulate() {
    let mut store = LeaseStore::new(epoch(1));
    let id1 = store
        .grant("n1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    let id2 = store
        .grant("n2", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    store.renew(&id1, 30, "t").unwrap();
    store.renew(&id2, 40, "t").unwrap();
    store.renew(&id1, 50, "t").unwrap();
    store.release(&id1, "t").unwrap();

    assert_eq!(store.event_counts().get("grant"), Some(&2));
    assert_eq!(store.event_counts().get("renew"), Some(&3));
    assert_eq!(store.event_counts().get("release"), Some(&1));
}

// =========================================================================
// Section 12: Serde round-trips
// =========================================================================

#[test]
fn lease_id_serde_roundtrip() {
    let id = LeaseId::from_raw(42);
    let json = serde_json::to_string(&id).unwrap();
    let restored: LeaseId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, restored);
}

#[test]
fn lease_type_serde_roundtrip() {
    for lt in [
        LeaseType::RemoteEndpoint,
        LeaseType::Operation,
        LeaseType::Session,
    ] {
        let json = serde_json::to_string(&lt).unwrap();
        let restored: LeaseType = serde_json::from_str(&json).unwrap();
        assert_eq!(lt, restored);
    }
}

#[test]
fn lease_status_serde_roundtrip() {
    for s in [
        LeaseStatus::Active,
        LeaseStatus::Expired,
        LeaseStatus::Released,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let restored: LeaseStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }
}

#[test]
fn escalation_action_serde_roundtrip() {
    let actions = [
        EscalationAction::MarkEndpointUnreachable {
            holder: "ep-1".to_string(),
        },
        EscalationAction::CancelOperation {
            holder: "op-1".to_string(),
        },
        EscalationAction::TerminateSession {
            holder: "sess-1".to_string(),
        },
    ];
    for action in &actions {
        let json = serde_json::to_string(action).unwrap();
        let restored: EscalationAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, restored);
    }
}

#[test]
fn lease_serde_roundtrip_all_statuses() {
    for status in [
        LeaseStatus::Active,
        LeaseStatus::Expired,
        LeaseStatus::Released,
    ] {
        let lease = Lease {
            lease_id: LeaseId::from_raw(10),
            holder: "holder-x".to_string(),
            lease_type: LeaseType::Operation,
            granted_at: 50,
            expires_at: 150,
            ttl: 100,
            epoch: epoch(3),
            renewal_count: 5,
            status,
        };
        let json = serde_json::to_string(&lease).unwrap();
        let restored: Lease = serde_json::from_str(&json).unwrap();
        assert_eq!(lease, restored);
    }
}

#[test]
fn lease_event_serde_roundtrip() {
    let event = LeaseEvent {
        lease_id: 7,
        holder: "node-1".to_string(),
        epoch_id: 2,
        ttl: 500,
        status: "active".to_string(),
        escalation_action: "none".to_string(),
        trace_id: "trace-xyz".to_string(),
        event: "renew".to_string(),
        renewal_count: 3,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: LeaseEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn lease_error_serde_roundtrip_all_variants() {
    let errors = [
        LeaseError::LeaseNotFound { lease_id: 1 },
        LeaseError::LeaseExpired {
            lease_id: 2,
            expired_at: 100,
        },
        LeaseError::LeaseReleased { lease_id: 3 },
        LeaseError::EpochMismatch {
            lease_id: 4,
            lease_epoch: epoch(1),
            current_epoch: epoch(5),
        },
        LeaseError::ZeroTtl,
        LeaseError::EmptyHolder,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: LeaseError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

// =========================================================================
// Section 13: Deterministic replay
// =========================================================================

#[test]
fn deterministic_replay_same_grants() {
    let run = |store: &mut LeaseStore| -> Vec<u64> {
        let mut ids = Vec::new();
        for i in 0..5 {
            let id = store
                .grant(
                    &format!("node-{i}"),
                    LeaseType::RemoteEndpoint,
                    100 + i * 10,
                    i * 5,
                    &format!("t-{i}"),
                )
                .unwrap();
            ids.push(id.as_u64());
        }
        ids
    };

    let mut s1 = LeaseStore::new(epoch(1));
    let mut s2 = LeaseStore::new(epoch(1));
    assert_eq!(run(&mut s1), run(&mut s2));
}

#[test]
fn deterministic_event_replay() {
    let run = |store: &mut LeaseStore| -> Vec<LeaseEvent> {
        let id = store
            .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
            .unwrap();
        store.renew(&id, 50, "t").unwrap();
        store.release(&id, "t").unwrap();
        store.drain_events()
    };

    let mut s1 = LeaseStore::new(epoch(1));
    let mut s2 = LeaseStore::new(epoch(1));
    let events1 = run(&mut s1);
    let events2 = run(&mut s2);
    assert_eq!(events1.len(), events2.len());
    for (e1, e2) in events1.iter().zip(events2.iter()) {
        assert_eq!(e1.event, e2.event);
        assert_eq!(e1.lease_id, e2.lease_id);
        assert_eq!(e1.holder, e2.holder);
    }
}

// =========================================================================
// Section 14: is_active_at on Lease
// =========================================================================

#[test]
fn is_active_at_checks_status_and_time() {
    let mut lease = Lease {
        lease_id: LeaseId::from_raw(1),
        holder: "n".to_string(),
        lease_type: LeaseType::RemoteEndpoint,
        granted_at: 0,
        expires_at: 100,
        ttl: 100,
        epoch: epoch(1),
        renewal_count: 0,
        status: LeaseStatus::Active,
    };

    assert!(lease.is_active_at(0));
    assert!(lease.is_active_at(50));
    assert!(lease.is_active_at(99));
    assert!(!lease.is_active_at(100));
    assert!(!lease.is_active_at(200));

    lease.status = LeaseStatus::Expired;
    assert!(!lease.is_active_at(50)); // Expired status overrides time

    lease.status = LeaseStatus::Released;
    assert!(!lease.is_active_at(50)); // Released status overrides time
}

// =========================================================================
// Section 15: Full lifecycle scenarios
// =========================================================================

#[test]
fn full_lifecycle_grant_renew_expire_escalate() {
    let mut store = LeaseStore::new(epoch(1));

    // 1. Grant
    let id = store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
        .unwrap();

    // 2. Active check
    assert_eq!(store.check(&id, 50).unwrap(), LeaseStatus::Active);

    // 3. Renew
    store.renew(&id, 80, "t2").unwrap();
    assert_eq!(store.get(&id).unwrap().expires_at, 180);

    // 4. Expire
    assert_eq!(store.check(&id, 200).unwrap(), LeaseStatus::Expired);
    assert_eq!(store.active_count(), 0);

    // 5. Events cover the full lifecycle
    let events = store.drain_events();
    assert!(events.len() >= 2);
}

#[test]
fn full_lifecycle_grant_release_no_escalation() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();

    store.release(&id, "t-rel").unwrap();

    // No escalation on subsequent scan
    let actions = store.scan_expired(200, "t-scan");
    assert!(actions.is_empty());
}

#[test]
fn full_lifecycle_epoch_transition_with_mixed_states() {
    let mut store = LeaseStore::new(epoch(1));

    // Grant 3 leases
    let id1 = store
        .grant("n1", LeaseType::RemoteEndpoint, 1000, 0, "t")
        .unwrap();
    let id2 = store
        .grant("n2", LeaseType::Operation, 1000, 0, "t")
        .unwrap();
    let _id3 = store.grant("n3", LeaseType::Session, 1000, 0, "t").unwrap();

    // Release one, expire another
    store.release(&id1, "t").unwrap();
    store.check(&id2, 2000).unwrap(); // force expire

    // Advance epoch -- only id3 (still active) should be escalated
    let actions = store.advance_epoch(epoch(2), "t-epoch");
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        &actions[0],
        EscalationAction::TerminateSession { holder } if holder == "n3"
    ));
}

#[test]
fn scan_after_renew_uses_new_expiration() {
    let mut store = LeaseStore::new(epoch(1));
    let id = store
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();

    // Renew at tick 80
    store.renew(&id, 80, "t").unwrap();
    // New expiration: 80 + 100 = 180

    // Scan at tick 120 -- should NOT be expired (expires at 180)
    let actions = store.scan_expired(120, "t");
    assert!(actions.is_empty());

    // Scan at tick 200 -- should be expired
    let actions = store.scan_expired(200, "t");
    assert_eq!(actions.len(), 1);
}

#[test]
fn many_leases_grant_and_scan() {
    let mut store = LeaseStore::new(epoch(1));
    for i in 0..50 {
        store
            .grant(
                &format!("node-{i}"),
                LeaseType::RemoteEndpoint,
                100 + i * 10,
                0,
                "t",
            )
            .unwrap();
    }
    assert_eq!(store.active_count(), 50);

    // All expire at tick 10000
    let actions = store.scan_expired(10000, "t-scan");
    assert_eq!(actions.len(), 50);
    assert_eq!(store.active_count(), 0);
}

// =========================================================================
// Section 16: Edge cases
// =========================================================================

#[test]
fn get_returns_none_for_unknown() {
    let store = LeaseStore::new(epoch(1));
    assert!(store.get(&LeaseId::from_raw(999)).is_none());
}

#[test]
fn active_count_after_mixed_operations() {
    let mut store = LeaseStore::new(epoch(1));
    let id1 = store.grant("a", LeaseType::Session, 100, 0, "t").unwrap();
    let id2 = store.grant("b", LeaseType::Session, 100, 0, "t").unwrap();
    let _id3 = store.grant("c", LeaseType::Session, 100, 0, "t").unwrap();
    assert_eq!(store.active_count(), 3);

    store.release(&id1, "t").unwrap();
    assert_eq!(store.active_count(), 2);

    store.check(&id2, 200).unwrap(); // expire
    assert_eq!(store.active_count(), 1);
}

#[test]
fn total_count_includes_all_statuses() {
    let mut store = LeaseStore::new(epoch(1));
    let id1 = store.grant("a", LeaseType::Session, 100, 0, "t").unwrap();
    let id2 = store.grant("b", LeaseType::Session, 100, 0, "t").unwrap();
    let _id3 = store.grant("c", LeaseType::Session, 100, 0, "t").unwrap();

    store.release(&id1, "t").unwrap();
    store.check(&id2, 200).unwrap();

    // 1 released + 1 expired + 1 active = 3 total
    assert_eq!(store.total_count(), 3);
}

#[test]
fn lease_id_ordering() {
    let ids: Vec<LeaseId> = (0..5).map(LeaseId::from_raw).collect();
    let mut shuffled = ids.clone();
    shuffled.reverse();
    shuffled.sort();
    assert_eq!(ids, shuffled);
}

#[test]
fn lease_id_equality_and_hash() {
    let a = LeaseId::from_raw(42);
    let b = LeaseId::from_raw(42);
    let c = LeaseId::from_raw(43);
    assert_eq!(a, b);
    assert_ne!(a, c);

    let mut set = BTreeSet::new();
    set.insert(a.clone());
    set.insert(b);
    assert_eq!(set.len(), 1);
    set.insert(c);
    assert_eq!(set.len(), 2);
}

#[test]
fn genesis_epoch_lease() {
    let mut store = LeaseStore::new(SecurityEpoch::GENESIS);
    let id = store
        .grant("n", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    let lease = store.get(&id).unwrap();
    assert_eq!(lease.epoch, SecurityEpoch::GENESIS);
}
