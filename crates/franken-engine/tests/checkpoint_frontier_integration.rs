//! Integration tests for checkpoint_frontier module.
//!
//! Covers FrontierError, FrontierState, FrontierEventType, FrontierEvent,
//! InMemoryBackend, PersistenceBackend, CheckpointFrontierManager, and all
//! enforcement invariants: monotonicity, duplicate rejection, epoch regression,
//! quorum, chain linkage, persistence, recovery, and forensic history.

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

use std::slice;

use frankenengine_engine::checkpoint_frontier::{
    CheckpointFrontierManager, FrontierError, FrontierEvent, FrontierEventType, FrontierState,
    InMemoryBackend, PersistenceBackend,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::{
    CheckpointBuilder, DeterministicTimestamp, PolicyCheckpoint, PolicyHead, PolicyType,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn make_policy_head(pt: PolicyType, version: u64) -> PolicyHead {
    let hash_input = format!("{pt}-v{version}");
    PolicyHead {
        policy_type: pt,
        policy_hash: ContentHash::compute(hash_input.as_bytes()),
        policy_version: version,
    }
}

fn build_genesis(keys: &[SigningKey], zone: &str) -> PolicyCheckpoint {
    CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(100), zone)
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(keys)
        .unwrap()
}

fn build_genesis_epoch(keys: &[SigningKey], epoch: SecurityEpoch, zone: &str) -> PolicyCheckpoint {
    CheckpointBuilder::genesis(epoch, DeterministicTimestamp(100), zone)
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(keys)
        .unwrap()
}

fn build_after(
    prev: &PolicyCheckpoint,
    seq: u64,
    epoch: SecurityEpoch,
    tick: u64,
    keys: &[SigningKey],
    zone: &str,
) -> PolicyCheckpoint {
    CheckpointBuilder::after(prev, seq, epoch, DeterministicTimestamp(tick), zone)
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, seq + 1))
        .build(keys)
        .unwrap()
}

// ===========================================================================
// FrontierError — Display and Error
// ===========================================================================

#[test]
fn error_display_rollback_rejected() {
    let err = FrontierError::RollbackRejected {
        zone: "zone-a".to_string(),
        frontier_seq: 10,
        attempted_seq: 5,
    };
    let s = err.to_string();
    assert!(s.contains("zone-a"));
    assert!(s.contains("10"));
    assert!(s.contains("5"));
    assert!(s.contains("rollback"));
}

#[test]
fn error_display_duplicate_checkpoint() {
    let err = FrontierError::DuplicateCheckpoint {
        zone: "zone-b".to_string(),
        checkpoint_seq: 7,
    };
    let s = err.to_string();
    assert!(s.contains("duplicate"));
    assert!(s.contains("zone-b"));
    assert!(s.contains("7"));
}

#[test]
fn error_display_chain_linkage_failure() {
    let err = FrontierError::ChainLinkageFailure {
        zone: "zone-c".to_string(),
        detail: "hash mismatch".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("chain linkage"));
    assert!(s.contains("zone-c"));
    assert!(s.contains("hash mismatch"));
}

#[test]
fn error_display_quorum_failure() {
    let err = FrontierError::QuorumFailure {
        zone: "zone-d".to_string(),
        detail: "insufficient signers".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("quorum"));
    assert!(s.contains("zone-d"));
}

#[test]
fn error_display_unknown_zone() {
    let err = FrontierError::UnknownZone {
        zone: "zone-x".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("unknown zone"));
    assert!(s.contains("zone-x"));
}

#[test]
fn error_display_epoch_regression() {
    let err = FrontierError::EpochRegression {
        zone: "zone-e".to_string(),
        frontier_epoch: SecurityEpoch::from_raw(10),
        attempted_epoch: SecurityEpoch::from_raw(3),
    };
    let s = err.to_string();
    assert!(s.contains("epoch regression"));
    assert!(s.contains("zone-e"));
}

#[test]
fn error_display_persistence_failed() {
    let err = FrontierError::PersistenceFailed {
        zone: "zone-f".to_string(),
        detail: "disk full".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("persistence"));
    assert!(s.contains("zone-f"));
    assert!(s.contains("disk full"));
}

#[test]
fn error_is_std_error() {
    let err = FrontierError::UnknownZone {
        zone: "z".to_string(),
    };
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

// ===========================================================================
// FrontierEventType — Display
// ===========================================================================

#[test]
fn event_type_display_zone_initialized() {
    let et = FrontierEventType::ZoneInitialized {
        zone: "z1".to_string(),
        genesis_seq: 0,
    };
    let s = et.to_string();
    assert!(s.contains("zone_initialized"));
    assert!(s.contains("z1"));
}

#[test]
fn event_type_display_checkpoint_accepted() {
    let et = FrontierEventType::CheckpointAccepted {
        zone: "z1".to_string(),
        prev_seq: 1,
        new_seq: 2,
    };
    let s = et.to_string();
    assert!(s.contains("checkpoint_accepted"));
    assert!(s.contains("1"));
    assert!(s.contains("2"));
}

#[test]
fn event_type_display_rollback_rejected() {
    let et = FrontierEventType::RollbackRejected {
        zone: "z1".to_string(),
        frontier_seq: 5,
        attempted_seq: 3,
    };
    let s = et.to_string();
    assert!(s.contains("rollback_rejected"));
}

#[test]
fn event_type_display_duplicate_rejected() {
    let et = FrontierEventType::DuplicateRejected {
        zone: "z1".to_string(),
        checkpoint_seq: 4,
    };
    let s = et.to_string();
    assert!(s.contains("duplicate_rejected"));
}

#[test]
fn event_type_display_epoch_regression_rejected() {
    let et = FrontierEventType::EpochRegressionRejected {
        zone: "z1".to_string(),
        frontier_epoch: SecurityEpoch::from_raw(5),
        attempted_epoch: SecurityEpoch::from_raw(2),
    };
    let s = et.to_string();
    assert!(s.contains("epoch_regression_rejected"));
}

#[test]
fn event_type_display_frontier_loaded() {
    let et = FrontierEventType::FrontierLoaded {
        zone: "z1".to_string(),
        frontier_seq: 10,
    };
    let s = et.to_string();
    assert!(s.contains("frontier_loaded"));
    assert!(s.contains("10"));
}

// ===========================================================================
// Serde round-trips
// ===========================================================================

#[test]
fn serde_round_trip_frontier_error() {
    let errors = [
        FrontierError::RollbackRejected {
            zone: "z".to_string(),
            frontier_seq: 5,
            attempted_seq: 3,
        },
        FrontierError::DuplicateCheckpoint {
            zone: "z".to_string(),
            checkpoint_seq: 5,
        },
        FrontierError::ChainLinkageFailure {
            zone: "z".to_string(),
            detail: "bad".to_string(),
        },
        FrontierError::QuorumFailure {
            zone: "z".to_string(),
            detail: "no signers".to_string(),
        },
        FrontierError::UnknownZone {
            zone: "z".to_string(),
        },
        FrontierError::EpochRegression {
            zone: "z".to_string(),
            frontier_epoch: SecurityEpoch::from_raw(5),
            attempted_epoch: SecurityEpoch::from_raw(2),
        },
        FrontierError::PersistenceFailed {
            zone: "z".to_string(),
            detail: "io err".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let parsed: FrontierError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, parsed);
    }
}

#[test]
fn serde_round_trip_frontier_event() {
    let event = FrontierEvent {
        event_type: FrontierEventType::CheckpointAccepted {
            zone: "z".to_string(),
            prev_seq: 1,
            new_seq: 2,
        },
        trace_id: "t-1".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: FrontierEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

#[test]
fn serde_round_trip_frontier_state() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();
    let state = mgr.get_frontier("zone-a").unwrap();
    let json = serde_json::to_string(state).unwrap();
    let parsed: FrontierState = serde_json::from_str(&json).unwrap();
    assert_eq!(*state, parsed);
}

// ===========================================================================
// InMemoryBackend
// ===========================================================================

#[test]
fn in_memory_backend_default_is_empty() {
    let backend = InMemoryBackend::new();
    assert_eq!(backend.persist_count, 0);
    assert!(!backend.fail_on_persist);
    let all = backend.load_all().unwrap();
    assert!(all.is_empty());
}

#[test]
fn in_memory_backend_load_returns_none_for_unknown_zone() {
    let backend = InMemoryBackend::new();
    assert!(backend.load("nonexistent").unwrap().is_none());
}

#[test]
fn in_memory_backend_persist_and_load() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();
    assert_eq!(mgr.backend().persist_count, 1);
    let loaded = mgr.backend().load("zone-a").unwrap().unwrap();
    assert_eq!(loaded.zone, "zone-a");
    assert_eq!(loaded.frontier_seq, 0);
}

#[test]
fn in_memory_backend_fail_on_persist() {
    let mut backend = InMemoryBackend::new();
    backend.fail_on_persist = true;
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(backend);
    let err = mgr
        .accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap_err();
    assert!(matches!(err, FrontierError::PersistenceFailed { .. }));
    assert!(mgr.get_frontier("zone-a").is_none());
}

// ===========================================================================
// CheckpointFrontierManager — genesis acceptance
// ===========================================================================

#[test]
fn genesis_accepted_and_frontier_initialized() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_seq, 0);
    assert_eq!(frontier.frontier_checkpoint_id, genesis.checkpoint_id);
    assert_eq!(frontier.frontier_epoch, SecurityEpoch::GENESIS);
    assert_eq!(frontier.accept_count, 1);
    assert_eq!(frontier.recent_ids.len(), 1);
    assert_eq!(frontier.zone, "zone-a");
}

#[test]
fn genesis_emits_zone_initialized_event() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let events = mgr.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0].event_type,
        FrontierEventType::ZoneInitialized { zone, genesis_seq: 0 }
        if zone == "zone-a"
    ));
    assert_eq!(events[0].trace_id, "t-0");
}

// ===========================================================================
// CheckpointFrontierManager — sequential acceptance
// ===========================================================================

#[test]
fn sequential_checkpoints_advance_frontier() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    let cp2 = build_after(
        &cp1,
        2,
        SecurityEpoch::GENESIS,
        300,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp2, 1, slice::from_ref(&vk), "t-2")
        .unwrap();

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_seq, 2);
    assert_eq!(frontier.frontier_checkpoint_id, cp2.checkpoint_id);
    assert_eq!(frontier.accept_count, 3);
}

#[test]
fn sequential_acceptance_emits_checkpoint_accepted_events() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    let events = mgr.drain_events();
    assert_eq!(events.len(), 2);
    assert!(matches!(
        &events[0].event_type,
        FrontierEventType::ZoneInitialized { .. }
    ));
    assert!(matches!(
        &events[1].event_type,
        FrontierEventType::CheckpointAccepted {
            prev_seq: 0,
            new_seq: 1,
            ..
        }
    ));
}

// ===========================================================================
// CheckpointFrontierManager — rollback rejection (core invariant)
// ===========================================================================

#[test]
fn rollback_rejected_unconditionally() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    // Attempt rollback to seq=0
    let rollback = build_genesis(slice::from_ref(&sk), "zone-a");
    let err = mgr
        .accept_checkpoint("zone-a", &rollback, 1, slice::from_ref(&vk), "t-rollback")
        .unwrap_err();

    assert!(matches!(
        err,
        FrontierError::RollbackRejected {
            frontier_seq: 1,
            attempted_seq: 0,
            ..
        }
    ));
}

#[test]
fn rollback_emits_rejection_event() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    mgr.drain_events();
    let rollback = build_genesis(slice::from_ref(&sk), "zone-a");
    let _ = mgr.accept_checkpoint("zone-a", &rollback, 1, slice::from_ref(&vk), "t-rollback");

    let events = mgr.drain_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.event_type, FrontierEventType::RollbackRejected { .. }))
    );
}

#[test]
fn rollback_does_not_advance_frontier() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    let rollback = build_genesis(slice::from_ref(&sk), "zone-a");
    let _ = mgr.accept_checkpoint("zone-a", &rollback, 1, slice::from_ref(&vk), "t-rollback");

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_seq, 1, "frontier should not regress");
}

// ===========================================================================
// CheckpointFrontierManager — duplicate rejection
// ===========================================================================

#[test]
fn duplicate_checkpoint_rejected() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    // Attempt to accept seq=1 again
    let dup = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        250,
        slice::from_ref(&sk),
        "zone-a",
    );
    let err = mgr
        .accept_checkpoint("zone-a", &dup, 1, slice::from_ref(&vk), "t-dup")
        .unwrap_err();

    assert!(matches!(
        err,
        FrontierError::DuplicateCheckpoint {
            checkpoint_seq: 1,
            ..
        }
    ));
}

// ===========================================================================
// CheckpointFrontierManager — epoch regression
// ===========================================================================

#[test]
fn epoch_regression_rejected() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis_e5 =
        build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(5), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis_e5, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis_e5,
        1,
        SecurityEpoch::from_raw(5),
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    // Build from independent chain at lower epoch
    let independent_genesis =
        build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(3), "zone-a");
    let regressed = build_after(
        &independent_genesis,
        2,
        SecurityEpoch::from_raw(3),
        300,
        slice::from_ref(&sk),
        "zone-a",
    );

    let err = mgr
        .accept_checkpoint("zone-a", &regressed, 1, slice::from_ref(&vk), "t-regress")
        .unwrap_err();
    assert!(matches!(err, FrontierError::EpochRegression { .. }));
}

#[test]
fn epoch_regression_emits_event() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis_e5 =
        build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(5), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis_e5, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis_e5,
        1,
        SecurityEpoch::from_raw(5),
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    mgr.drain_events();

    let independent_genesis =
        build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(3), "zone-a");
    let regressed = build_after(
        &independent_genesis,
        2,
        SecurityEpoch::from_raw(3),
        300,
        slice::from_ref(&sk),
        "zone-a",
    );
    let _ = mgr.accept_checkpoint("zone-a", &regressed, 1, slice::from_ref(&vk), "t-regress");

    let events = mgr.drain_events();
    assert!(events.iter().any(|e| matches!(
        &e.event_type,
        FrontierEventType::EpochRegressionRejected { .. }
    )));
}

// ===========================================================================
// CheckpointFrontierManager — epoch transition (forward)
// ===========================================================================

#[test]
fn epoch_transition_forward_accepted() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::from_raw(5),
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_epoch, SecurityEpoch::from_raw(5));
}

// ===========================================================================
// CheckpointFrontierManager — per-zone isolation
// ===========================================================================

#[test]
fn zones_are_independent() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis_a = build_genesis(slice::from_ref(&sk), "zone-a");
    let genesis_b = build_genesis(slice::from_ref(&sk), "zone-b");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis_a, 1, slice::from_ref(&vk), "t-a0")
        .unwrap();
    mgr.accept_checkpoint("zone-b", &genesis_b, 1, slice::from_ref(&vk), "t-b0")
        .unwrap();

    let cp_a1 = build_after(
        &genesis_a,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp_a1, 1, slice::from_ref(&vk), "t-a1")
        .unwrap();

    assert_eq!(mgr.get_frontier("zone-b").unwrap().frontier_seq, 0);
    assert_eq!(mgr.get_frontier("zone-a").unwrap().frontier_seq, 1);

    let cp_b1 = build_after(
        &genesis_b,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-b",
    );
    mgr.accept_checkpoint("zone-b", &cp_b1, 1, slice::from_ref(&vk), "t-b1")
        .unwrap();
    assert_eq!(mgr.get_frontier("zone-b").unwrap().frontier_seq, 1);
}

// ===========================================================================
// CheckpointFrontierManager — quorum failure
// ===========================================================================

#[test]
fn quorum_failure_rejects_genesis() {
    let sk = make_sk(1);
    let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    let err = mgr
        .accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&wrong_vk), "t-bad")
        .unwrap_err();

    assert!(matches!(err, FrontierError::QuorumFailure { .. }));
    assert!(mgr.get_frontier("zone-a").is_none());
}

#[test]
fn quorum_failure_rejects_subsequent_checkpoint() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let wrong_vk = VerificationKey::from_bytes([0xEE; 32]);
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    let err = mgr
        .accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&wrong_vk), "t-bad")
        .unwrap_err();
    assert!(matches!(err, FrontierError::QuorumFailure { .. }));
    assert_eq!(mgr.get_frontier("zone-a").unwrap().frontier_seq, 0);
}

// ===========================================================================
// CheckpointFrontierManager — multi-signer quorum
// ===========================================================================

#[test]
fn multi_signer_quorum_accepted() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let vk1 = sk1.verification_key();
    let vk2 = sk2.verification_key();

    let genesis = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "zone-a",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&[sk1, sk2])
    .unwrap();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 2, &[vk1, vk2], "t-0")
        .unwrap();

    assert_eq!(mgr.get_frontier("zone-a").unwrap().frontier_seq, 0);
}

// ===========================================================================
// CheckpointFrontierManager — persistence
// ===========================================================================

#[test]
fn frontier_persisted_on_each_acceptance() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();
    assert_eq!(mgr.backend().persist_count, 1);

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();
    assert_eq!(mgr.backend().persist_count, 2);
}

#[test]
fn persistence_failure_prevents_frontier_advance() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    mgr.backend_mut().fail_on_persist = true;

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    let err = mgr
        .accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-fail")
        .unwrap_err();
    assert!(matches!(err, FrontierError::PersistenceFailed { .. }));
    assert_eq!(
        mgr.get_frontier("zone-a").unwrap().frontier_seq,
        0,
        "frontier must not advance on persistence failure"
    );
}

// ===========================================================================
// CheckpointFrontierManager — recovery
// ===========================================================================

#[test]
fn recovery_loads_persisted_frontier() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr1 = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr1.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr1.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    let loaded_state = mgr1.backend().load("zone-a").unwrap().unwrap();

    let mut backend2 = InMemoryBackend::new();
    backend2.persist(&loaded_state).unwrap();

    let mut mgr2 = CheckpointFrontierManager::new(backend2);
    let count = mgr2.recover("t-recover").unwrap();
    assert_eq!(count, 1);

    let frontier = mgr2.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_seq, 1);

    // Rollback to seq=0 should be rejected
    let rollback = build_genesis(slice::from_ref(&sk), "zone-a");
    let err = mgr2
        .accept_checkpoint("zone-a", &rollback, 1, slice::from_ref(&vk), "t-post")
        .unwrap_err();
    assert!(matches!(err, FrontierError::RollbackRejected { .. }));
}

#[test]
fn recovery_emits_frontier_loaded_events() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr1 = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr1.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let loaded_state = mgr1.backend().load("zone-a").unwrap().unwrap();
    let mut backend2 = InMemoryBackend::new();
    backend2.persist(&loaded_state).unwrap();

    let mut mgr2 = CheckpointFrontierManager::new(backend2);
    mgr2.recover("t-recover").unwrap();

    let events = mgr2.drain_events();
    assert!(events.iter().any(|e| matches!(
        &e.event_type,
        FrontierEventType::FrontierLoaded { zone, frontier_seq: 0 }
        if zone == "zone-a"
    )));
}

// ===========================================================================
// CheckpointFrontierManager — forensic history (recent_ids)
// ===========================================================================

#[test]
fn recent_ids_tracked() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    let cp2 = build_after(
        &cp1,
        2,
        SecurityEpoch::GENESIS,
        300,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp2, 1, slice::from_ref(&vk), "t-2")
        .unwrap();

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.recent_ids.len(), 3);
    assert_eq!(frontier.recent_ids[0].checkpoint_seq, 0);
    assert_eq!(frontier.recent_ids[1].checkpoint_seq, 1);
    assert_eq!(frontier.recent_ids[2].checkpoint_seq, 2);
}

// ===========================================================================
// CheckpointFrontierManager — zones() and get_frontier()
// ===========================================================================

#[test]
fn zones_listing() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    assert!(mgr.zones().is_empty());

    let genesis_a = build_genesis(slice::from_ref(&sk), "zone-a");
    mgr.accept_checkpoint("zone-a", &genesis_a, 1, slice::from_ref(&vk), "t-a")
        .unwrap();

    let genesis_b = build_genesis(slice::from_ref(&sk), "zone-b");
    mgr.accept_checkpoint("zone-b", &genesis_b, 1, slice::from_ref(&vk), "t-b")
        .unwrap();

    let zones = mgr.zones();
    assert_eq!(zones.len(), 2);
    assert!(zones.contains(&"zone-a"));
    assert!(zones.contains(&"zone-b"));
}

#[test]
fn get_frontier_returns_none_for_unknown_zone() {
    let mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    assert!(mgr.get_frontier("nonexistent").is_none());
}

// ===========================================================================
// CheckpointFrontierManager — event_counts()
// ===========================================================================

#[test]
fn event_counts_accurate() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    // Attempt rollback
    let rollback = build_genesis(slice::from_ref(&sk), "zone-a");
    let _ = mgr.accept_checkpoint("zone-a", &rollback, 1, slice::from_ref(&vk), "t-bad");

    let counts = mgr.event_counts();
    assert_eq!(counts["zone_initialized"], 1);
    assert_eq!(counts["checkpoint_accepted"], 1);
    assert_eq!(counts["rollback_rejected"], 1);
}

#[test]
fn drain_events_clears_events() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let events = mgr.drain_events();
    assert!(!events.is_empty());
    let events2 = mgr.drain_events();
    assert!(events2.is_empty());
}

// ===========================================================================
// CheckpointFrontierManager — chain linkage verification
// ===========================================================================

#[test]
fn linkage_verification_succeeds() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );

    mgr.verify_linkage_against_frontier("zone-a", &genesis, &cp1)
        .unwrap();
}

#[test]
fn linkage_verification_fails_wrong_prev() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    // Try with genesis as prev (but frontier is at cp1)
    let cp2 = build_after(
        &cp1,
        2,
        SecurityEpoch::GENESIS,
        300,
        slice::from_ref(&sk),
        "zone-a",
    );
    let err = mgr
        .verify_linkage_against_frontier("zone-a", &genesis, &cp2)
        .unwrap_err();
    assert!(matches!(err, FrontierError::ChainLinkageFailure { .. }));
}

#[test]
fn linkage_verification_unknown_zone() {
    let sk = make_sk(1);
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );

    let mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    let err = mgr
        .verify_linkage_against_frontier("zone-nope", &genesis, &cp1)
        .unwrap_err();
    assert!(matches!(err, FrontierError::UnknownZone { .. }));
}
