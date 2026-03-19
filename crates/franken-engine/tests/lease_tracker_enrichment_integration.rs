//! Enrichment integration tests for `lease_tracker`.
//!
//! Covers: LeaseId serde/Display/ordering, LeaseType serde/Display/ordering,
//! LeaseStatus serde/Display/ordering, Lease lifecycle and boundaries,
//! LeaseStore grant/renew/release/check/scan/epoch, EscalationAction
//! serde/Display, LeaseError serde/Display, LeaseEvent serde, audit event
//! emission, event counters, determinism, and full lifecycle scenarios.

#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;

use frankenengine_engine::lease_tracker::{
    EscalationAction, Lease, LeaseError, LeaseEvent, LeaseId, LeaseStatus, LeaseStore, LeaseType,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn store() -> LeaseStore {
    LeaseStore::new(ep(1))
}

// ===========================================================================
// LeaseId tests
// ===========================================================================

#[test]
fn integ_lease_id_display() {
    assert_eq!(LeaseId::from_raw(0).to_string(), "lease:0");
    assert_eq!(LeaseId::from_raw(42).to_string(), "lease:42");
    assert_eq!(
        LeaseId::from_raw(u64::MAX).to_string(),
        format!("lease:{}", u64::MAX)
    );
}

#[test]
fn integ_lease_id_serde_roundtrip() {
    for val in [0u64, 1, 42, u64::MAX] {
        let id = LeaseId::from_raw(val);
        let json = serde_json::to_string(&id).unwrap();
        let back: LeaseId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
        assert_eq!(back.as_u64(), val);
    }
}

#[test]
fn integ_lease_id_ordering() {
    let ids: BTreeSet<LeaseId> = (0..5).rev().map(LeaseId::from_raw).collect();
    let ordered: Vec<u64> = ids.iter().map(|id| id.as_u64()).collect();
    assert_eq!(ordered, vec![0, 1, 2, 3, 4]);
}

// ===========================================================================
// LeaseType tests
// ===========================================================================

#[test]
fn integ_lease_type_display_all_unique() {
    let mut displays = BTreeSet::new();
    for t in [
        LeaseType::RemoteEndpoint,
        LeaseType::Operation,
        LeaseType::Session,
    ] {
        displays.insert(t.to_string());
    }
    assert_eq!(displays.len(), 3);
}

#[test]
fn integ_lease_type_serde_all() {
    for lt in [
        LeaseType::RemoteEndpoint,
        LeaseType::Operation,
        LeaseType::Session,
    ] {
        let json = serde_json::to_string(&lt).unwrap();
        let back: LeaseType = serde_json::from_str(&json).unwrap();
        assert_eq!(lt, back);
    }
}

#[test]
fn integ_lease_type_ordering() {
    assert!(LeaseType::RemoteEndpoint < LeaseType::Operation);
    assert!(LeaseType::Operation < LeaseType::Session);
}

// ===========================================================================
// LeaseStatus tests
// ===========================================================================

#[test]
fn integ_lease_status_display_all_unique() {
    let mut displays = BTreeSet::new();
    for s in [
        LeaseStatus::Active,
        LeaseStatus::Expired,
        LeaseStatus::Released,
    ] {
        displays.insert(s.to_string());
    }
    assert_eq!(displays.len(), 3);
}

#[test]
fn integ_lease_status_serde_all() {
    for s in [
        LeaseStatus::Active,
        LeaseStatus::Expired,
        LeaseStatus::Released,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: LeaseStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn integ_lease_status_ordering() {
    assert!(LeaseStatus::Active < LeaseStatus::Expired);
    assert!(LeaseStatus::Expired < LeaseStatus::Released);
}

// ===========================================================================
// EscalationAction tests
// ===========================================================================

#[test]
fn integ_escalation_display_all_unique() {
    let actions = [
        EscalationAction::MarkEndpointUnreachable {
            holder: "a".into(),
        },
        EscalationAction::CancelOperation {
            holder: "b".into(),
        },
        EscalationAction::TerminateSession {
            holder: "c".into(),
        },
    ];
    let mut displays = BTreeSet::new();
    for a in &actions {
        displays.insert(a.to_string());
    }
    assert_eq!(displays.len(), 3);
}

#[test]
fn integ_escalation_display_includes_holder() {
    let a = EscalationAction::MarkEndpointUnreachable {
        holder: "my-node".into(),
    };
    assert!(a.to_string().contains("my-node"));
    assert!(a.to_string().contains("mark_endpoint_unreachable"));
}

#[test]
fn integ_escalation_serde_all() {
    let actions = vec![
        EscalationAction::MarkEndpointUnreachable {
            holder: "node-1".into(),
        },
        EscalationAction::CancelOperation {
            holder: "op-1".into(),
        },
        EscalationAction::TerminateSession {
            holder: "sess-1".into(),
        },
    ];
    for a in &actions {
        let json = serde_json::to_string(a).unwrap();
        let back: EscalationAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, back);
    }
}

// ===========================================================================
// LeaseError tests
// ===========================================================================

#[test]
fn integ_error_display_all_unique() {
    let errors: Vec<LeaseError> = vec![
        LeaseError::LeaseNotFound { lease_id: 1 },
        LeaseError::LeaseExpired {
            lease_id: 2,
            expired_at: 100,
        },
        LeaseError::LeaseReleased { lease_id: 3 },
        LeaseError::EpochMismatch {
            lease_id: 4,
            lease_epoch: ep(1),
            current_epoch: ep(3),
        },
        LeaseError::ZeroTtl,
        LeaseError::EmptyHolder,
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty());
        displays.insert(msg);
    }
    assert_eq!(displays.len(), 6);
}

#[test]
fn integ_error_serde_all() {
    let errors = vec![
        LeaseError::LeaseNotFound { lease_id: 1 },
        LeaseError::LeaseExpired {
            lease_id: 2,
            expired_at: 100,
        },
        LeaseError::LeaseReleased { lease_id: 3 },
        LeaseError::EpochMismatch {
            lease_id: 4,
            lease_epoch: ep(1),
            current_epoch: ep(3),
        },
        LeaseError::ZeroTtl,
        LeaseError::EmptyHolder,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: LeaseError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn integ_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(LeaseError::ZeroTtl);
    assert!(!err.to_string().is_empty());
}

// ===========================================================================
// LeaseEvent tests
// ===========================================================================

#[test]
fn integ_lease_event_serde_roundtrip() {
    let event = LeaseEvent {
        lease_id: 1,
        holder: "node-1".into(),
        epoch_id: 1,
        ttl: 100,
        status: "active".into(),
        escalation_action: String::new(),
        trace_id: "trace-1".into(),
        event: "grant".into(),
        renewal_count: 0,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LeaseEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn integ_lease_event_json_fields() {
    let event = LeaseEvent {
        lease_id: 42,
        holder: "h".into(),
        epoch_id: 2,
        ttl: 100,
        status: "expired".into(),
        escalation_action: "cancel_operation(h)".into(),
        trace_id: "t".into(),
        event: "expiration".into(),
        renewal_count: 3,
    };
    let json = serde_json::to_string(&event).unwrap();
    for field in [
        "lease_id",
        "holder",
        "epoch_id",
        "ttl",
        "status",
        "escalation_action",
        "trace_id",
        "event",
        "renewal_count",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// Lease serde tests
// ===========================================================================

#[test]
fn integ_lease_serde_active() {
    let lease = Lease {
        lease_id: LeaseId::from_raw(1),
        holder: "node-1".into(),
        lease_type: LeaseType::RemoteEndpoint,
        granted_at: 100,
        expires_at: 200,
        ttl: 100,
        epoch: ep(1),
        renewal_count: 0,
        status: LeaseStatus::Active,
    };
    let json = serde_json::to_string(&lease).unwrap();
    let back: Lease = serde_json::from_str(&json).unwrap();
    assert_eq!(lease, back);
}

#[test]
fn integ_lease_serde_expired() {
    let lease = Lease {
        lease_id: LeaseId::from_raw(1),
        holder: "h".into(),
        lease_type: LeaseType::Session,
        granted_at: 0,
        expires_at: 100,
        ttl: 100,
        epoch: ep(1),
        renewal_count: 0,
        status: LeaseStatus::Expired,
    };
    let json = serde_json::to_string(&lease).unwrap();
    let back: Lease = serde_json::from_str(&json).unwrap();
    assert_eq!(back.status, LeaseStatus::Expired);
}

#[test]
fn integ_lease_serde_released() {
    let lease = Lease {
        lease_id: LeaseId::from_raw(1),
        holder: "h".into(),
        lease_type: LeaseType::Operation,
        granted_at: 0,
        expires_at: 100,
        ttl: 100,
        epoch: ep(1),
        renewal_count: 5,
        status: LeaseStatus::Released,
    };
    let json = serde_json::to_string(&lease).unwrap();
    let back: Lease = serde_json::from_str(&json).unwrap();
    assert_eq!(back.status, LeaseStatus::Released);
    assert_eq!(back.renewal_count, 5);
}

#[test]
fn integ_lease_json_fields() {
    let lease = Lease {
        lease_id: LeaseId::from_raw(1),
        holder: "h".into(),
        lease_type: LeaseType::Operation,
        granted_at: 10,
        expires_at: 110,
        ttl: 100,
        epoch: ep(1),
        renewal_count: 2,
        status: LeaseStatus::Active,
    };
    let json = serde_json::to_string(&lease).unwrap();
    for field in [
        "lease_id",
        "holder",
        "lease_type",
        "granted_at",
        "expires_at",
        "ttl",
        "epoch",
        "renewal_count",
        "status",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// Lease boundary tests
// ===========================================================================

#[test]
fn integ_lease_is_active_at_boundary() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    let lease = s.get(&id).unwrap();
    assert!(lease.is_active_at(99));
    assert!(!lease.is_active_at(100)); // exactly at expires_at
    assert!(!lease.is_active_at(101));
}

#[test]
fn integ_lease_escalation_action_types() {
    let mut s = store();
    let id1 = s
        .grant("n1", LeaseType::RemoteEndpoint, 10, 0, "t")
        .unwrap();
    let id2 = s.grant("n2", LeaseType::Operation, 10, 0, "t").unwrap();
    let id3 = s.grant("n3", LeaseType::Session, 10, 0, "t").unwrap();

    assert!(matches!(
        s.get(&id1).unwrap().escalation_action(),
        EscalationAction::MarkEndpointUnreachable { .. }
    ));
    assert!(matches!(
        s.get(&id2).unwrap().escalation_action(),
        EscalationAction::CancelOperation { .. }
    ));
    assert!(matches!(
        s.get(&id3).unwrap().escalation_action(),
        EscalationAction::TerminateSession { .. }
    ));
}

#[test]
fn integ_lease_renewal_due_at() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 300, 100, "t")
        .unwrap();
    let lease = s.get(&id).unwrap();
    // renewal_due_at = expires_at - ttl + ttl/3 = 400 - 300 + 100 = 200
    assert_eq!(lease.renewal_due_at(), 200);
}

// ===========================================================================
// LeaseStore grant tests
// ===========================================================================

#[test]
fn integ_store_grant_basic() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    assert_eq!(id.as_u64(), 1);
    assert_eq!(s.active_count(), 1);
    assert_eq!(s.total_count(), 1);
    let lease = s.get(&id).unwrap();
    assert_eq!(lease.holder, "node-1");
    assert_eq!(lease.ttl, 100);
    assert_eq!(lease.expires_at, 100);
    assert_eq!(lease.status, LeaseStatus::Active);
}

#[test]
fn integ_store_grant_multiple_sequential_ids() {
    let mut s = store();
    let id1 = s
        .grant("a", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    let id2 = s.grant("b", LeaseType::Operation, 100, 0, "t").unwrap();
    let id3 = s.grant("c", LeaseType::Session, 100, 0, "t").unwrap();
    assert_eq!(id1.as_u64(), 1);
    assert_eq!(id2.as_u64(), 2);
    assert_eq!(id3.as_u64(), 3);
    assert_eq!(s.active_count(), 3);
}

#[test]
fn integ_store_grant_zero_ttl_rejected() {
    let mut s = store();
    let err = s
        .grant("node", LeaseType::RemoteEndpoint, 0, 0, "t")
        .unwrap_err();
    assert!(matches!(err, LeaseError::ZeroTtl));
}

#[test]
fn integ_store_grant_empty_holder_rejected() {
    let mut s = store();
    let err = s
        .grant("", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap_err();
    assert!(matches!(err, LeaseError::EmptyHolder));
}

#[test]
fn integ_store_grant_at_nonzero_tick() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::Session, 200, 1000, "t")
        .unwrap();
    let lease = s.get(&id).unwrap();
    assert_eq!(lease.granted_at, 1000);
    assert_eq!(lease.expires_at, 1200);
}

// ===========================================================================
// LeaseStore check tests
// ===========================================================================

#[test]
fn integ_store_check_active() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    assert_eq!(s.check(&id, 50).unwrap(), LeaseStatus::Active);
}

#[test]
fn integ_store_check_expired() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    assert_eq!(s.check(&id, 100).unwrap(), LeaseStatus::Expired);
}

#[test]
fn integ_store_check_released() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.release(&id, "t").unwrap();
    assert_eq!(s.check(&id, 50).unwrap(), LeaseStatus::Released);
}

#[test]
fn integ_store_check_unknown() {
    let mut s = store();
    let err = s.check(&LeaseId::from_raw(999), 0).unwrap_err();
    assert!(matches!(err, LeaseError::LeaseNotFound { .. }));
}

// ===========================================================================
// LeaseStore renew tests
// ===========================================================================

#[test]
fn integ_store_renew_extends() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.renew(&id, 50, "t-renew").unwrap();
    let lease = s.get(&id).unwrap();
    assert_eq!(lease.expires_at, 150);
    assert_eq!(lease.renewal_count, 1);
}

#[test]
fn integ_store_renew_multiple_times() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.renew(&id, 30, "t1").unwrap();
    s.renew(&id, 60, "t2").unwrap();
    let lease = s.get(&id).unwrap();
    assert_eq!(lease.expires_at, 160); // 60 + 100
    assert_eq!(lease.renewal_count, 2);
}

#[test]
fn integ_store_renew_expired_fails() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    let err = s.renew(&id, 200, "t-renew").unwrap_err();
    assert!(matches!(err, LeaseError::LeaseExpired { .. }));
}

#[test]
fn integ_store_renew_at_exact_expiry_fails() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    let err = s.renew(&id, 100, "t-renew").unwrap_err();
    assert!(matches!(
        err,
        LeaseError::LeaseExpired {
            lease_id: 1,
            expired_at: 100
        }
    ));
}

#[test]
fn integ_store_renew_at_last_valid_tick() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.renew(&id, 99, "t-renew").unwrap();
    let lease = s.get(&id).unwrap();
    assert_eq!(lease.expires_at, 199);
}

#[test]
fn integ_store_renew_released_fails() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.release(&id, "t-rel").unwrap();
    let err = s.renew(&id, 50, "t-renew").unwrap_err();
    assert!(matches!(err, LeaseError::LeaseReleased { .. }));
}

#[test]
fn integ_store_renew_unknown_fails() {
    let mut s = store();
    let err = s.renew(&LeaseId::from_raw(999), 0, "t").unwrap_err();
    assert!(matches!(err, LeaseError::LeaseNotFound { .. }));
}

// ===========================================================================
// LeaseStore release tests
// ===========================================================================

#[test]
fn integ_store_release_sets_released() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.release(&id, "t-rel").unwrap();
    assert_eq!(s.active_count(), 0);
    let lease = s.get(&id).unwrap();
    assert_eq!(lease.status, LeaseStatus::Released);
}

#[test]
fn integ_store_double_release_fails() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.release(&id, "t1").unwrap();
    let err = s.release(&id, "t2").unwrap_err();
    assert!(matches!(err, LeaseError::LeaseReleased { .. }));
}

// ===========================================================================
// LeaseStore scan_expired tests
// ===========================================================================

#[test]
fn integ_store_scan_detects_expired() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
        .unwrap();
    s.grant("op-1", LeaseType::Operation, 50, 10, "t2")
        .unwrap();
    // At tick 70, only op-1 (expires_at=60) is expired
    let actions = s.scan_expired(70, "trace-scan");
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        &actions[0],
        EscalationAction::CancelOperation { holder } if holder == "op-1"
    ));
}

#[test]
fn integ_store_scan_multiple_expirations() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
        .unwrap();
    s.grant("sess-1", LeaseType::Session, 50, 0, "t2")
        .unwrap();
    let actions = s.scan_expired(200, "t-scan");
    assert_eq!(actions.len(), 2);
}

#[test]
fn integ_store_scan_skips_already_expired() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    let a1 = s.scan_expired(200, "t1");
    assert_eq!(a1.len(), 1);
    let a2 = s.scan_expired(300, "t2");
    assert!(a2.is_empty());
}

#[test]
fn integ_store_scan_no_expired() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
        .unwrap();
    let actions = s.scan_expired(500, "t-scan");
    assert!(actions.is_empty());
    assert_eq!(s.active_count(), 1);
}

#[test]
fn integ_store_scan_released_not_escalated() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.release(&id, "t-rel").unwrap();
    let actions = s.scan_expired(500, "t-scan");
    assert!(actions.is_empty());
}

// ===========================================================================
// Epoch binding tests
// ===========================================================================

#[test]
fn integ_store_epoch_advance_invalidates() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
        .unwrap();
    let actions = s.advance_epoch(ep(2), "t-epoch");
    assert_eq!(actions.len(), 1);
    assert!(matches!(
        &actions[0],
        EscalationAction::MarkEndpointUnreachable { holder } if holder == "node-1"
    ));
    assert_eq!(s.active_count(), 0);
}

#[test]
fn integ_store_epoch_advance_same_epoch_noop() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 1000, 0, "t")
        .unwrap();
    let actions = s.advance_epoch(ep(1), "t-same");
    assert!(actions.is_empty());
    assert_eq!(s.active_count(), 1);
}

#[test]
fn integ_store_epoch_accessor() {
    let mut s = LeaseStore::new(ep(42));
    assert_eq!(s.epoch(), ep(42));
    s.advance_epoch(ep(99), "t");
    assert_eq!(s.epoch(), ep(99));
}

#[test]
fn integ_store_epoch_invalidation_multiple() {
    let mut s = store();
    s.grant("a", LeaseType::RemoteEndpoint, 1000, 0, "t")
        .unwrap();
    s.grant("b", LeaseType::Operation, 1000, 0, "t").unwrap();
    s.grant("c", LeaseType::Session, 1000, 0, "t").unwrap();
    let actions = s.advance_epoch(ep(2), "t-adv");
    assert_eq!(actions.len(), 3);
}

// ===========================================================================
// Audit event tests
// ===========================================================================

#[test]
fn integ_store_grant_emits_event() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "trace-g")
        .unwrap();
    let events = s.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "grant");
    assert_eq!(events[0].holder, "node-1");
    assert_eq!(events[0].trace_id, "trace-g");
}

#[test]
fn integ_store_renew_emits_event() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.drain_events();
    s.renew(&id, 50, "trace-r").unwrap();
    let events = s.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "renew");
    assert_eq!(events[0].renewal_count, 1);
}

#[test]
fn integ_store_release_emits_event() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.drain_events();
    s.release(&id, "trace-rel").unwrap();
    let events = s.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "release");
    assert_eq!(events[0].status, "released");
}

#[test]
fn integ_store_expiration_emits_event() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.drain_events();
    s.scan_expired(200, "trace-exp");
    let events = s.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "expiration");
    assert!(
        events[0]
            .escalation_action
            .contains("mark_endpoint_unreachable")
    );
}

#[test]
fn integ_store_drain_events_clears() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    assert_eq!(s.drain_events().len(), 1);
    assert!(s.drain_events().is_empty());
}

#[test]
fn integ_store_event_counts() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.renew(&id, 30, "t1").unwrap();
    s.renew(&id, 60, "t2").unwrap();
    s.release(&id, "t3").unwrap();
    assert_eq!(s.event_counts().get("grant"), Some(&1));
    assert_eq!(s.event_counts().get("renew"), Some(&2));
    assert_eq!(s.event_counts().get("release"), Some(&1));
}

#[test]
fn integ_store_event_counts_expiration() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t")
        .unwrap();
    s.scan_expired(200, "t-scan");
    assert_eq!(s.event_counts().get("expiration"), Some(&1));
}

#[test]
fn integ_store_event_counts_epoch_invalidation() {
    let mut s = store();
    s.grant("a", LeaseType::RemoteEndpoint, 1000, 0, "t")
        .unwrap();
    s.grant("b", LeaseType::Operation, 1000, 0, "t").unwrap();
    s.advance_epoch(ep(2), "t-adv");
    assert_eq!(s.event_counts().get("epoch_invalidation"), Some(&2));
}

// ===========================================================================
// Renewal due tests
// ===========================================================================

#[test]
fn integ_store_leases_due_for_renewal() {
    let mut s = store();
    let id1 = s
        .grant("node-1", LeaseType::RemoteEndpoint, 300, 0, "t1")
        .unwrap();
    let _id2 = s
        .grant("node-2", LeaseType::RemoteEndpoint, 900, 0, "t2")
        .unwrap();
    // id1: renewal_due_at = 0 + 100 = 100
    // id2: renewal_due_at = 0 + 300 = 300
    let due = s.leases_due_for_renewal(150);
    assert_eq!(due.len(), 1);
    assert_eq!(due[0], id1);
}

// ===========================================================================
// Full lifecycle test
// ===========================================================================

#[test]
fn integ_full_lifecycle_grant_renew_expire_escalate() {
    let mut s = store();
    let id = s
        .grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
        .unwrap();
    assert_eq!(s.check(&id, 50).unwrap(), LeaseStatus::Active);
    s.renew(&id, 80, "t2").unwrap();
    let lease = s.get(&id).unwrap();
    assert_eq!(lease.expires_at, 180);
    assert_eq!(s.check(&id, 200).unwrap(), LeaseStatus::Expired);
    assert_eq!(s.active_count(), 0);
}

#[test]
fn integ_total_vs_active_after_expiration() {
    let mut s = store();
    s.grant("node-1", LeaseType::RemoteEndpoint, 100, 0, "t1")
        .unwrap();
    s.grant("node-2", LeaseType::Operation, 200, 0, "t2")
        .unwrap();
    s.scan_expired(150, "t-scan");
    assert_eq!(s.total_count(), 2);
    assert_eq!(s.active_count(), 1);
}
