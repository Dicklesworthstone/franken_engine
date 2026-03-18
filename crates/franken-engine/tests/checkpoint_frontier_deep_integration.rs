#![forbid(unsafe_code)]
//! Deep integration tests for `checkpoint_frontier`.
//!
//! Focuses on uncovered areas: edge cases, error-path composition,
//! determinism guarantees, large-scale stress, serde round-trips with
//! boundary data, Display/Debug exhaustive checks, accept_count saturation,
//! multi-zone interleaved operations, persistence-failure recovery,
//! and sequence-number boundary conditions.

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
use std::collections::BTreeSet;
use std::slice;

use frankenengine_engine::checkpoint_frontier::{
    CheckpointFrontierManager, FrontierEntry, FrontierError, FrontierEvent, FrontierEventType,
    FrontierState, InMemoryBackend, PersistenceBackend,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
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

fn oid(seed: u8) -> EngineObjectId {
    EngineObjectId([seed; 32])
}

/// Build a chain of `count` checkpoints starting from genesis, returning all of them.
fn build_chain(
    sk: &SigningKey,
    zone: &str,
    count: u64,
    epoch: SecurityEpoch,
) -> Vec<PolicyCheckpoint> {
    let mut chain = Vec::new();
    let genesis = build_genesis_epoch(slice::from_ref(sk), epoch, zone);
    chain.push(genesis);
    for i in 1..=count {
        let prev = &chain[chain.len() - 1];
        let cp = build_after(prev, i, epoch, 100 + i * 100, slice::from_ref(sk), zone);
        chain.push(cp);
    }
    chain
}

// ===========================================================================
// 1) Large sequence-number gap acceptance
// ===========================================================================

#[test]
fn accept_checkpoint_with_large_sequence_gap() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    // Jump from seq=0 to seq=1000 (large gap is valid — only monotonicity matters)
    let cp_far = build_after(
        &genesis,
        1000,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp_far, 1, slice::from_ref(&vk), "t-far")
        .unwrap();

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_seq, 1000);
    assert_eq!(frontier.accept_count, 2);
}

// ===========================================================================
// 2) Stress: many zones in parallel
// ===========================================================================

#[test]
fn stress_many_zones_independent() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    let zone_count = 20;
    let mut geneses = Vec::new();

    for i in 0..zone_count {
        let zone_name = format!("zone-{i:03}");
        let genesis = build_genesis(slice::from_ref(&sk), &zone_name);
        mgr.accept_checkpoint(
            &zone_name,
            &genesis,
            1,
            slice::from_ref(&vk),
            &format!("t-{i}-0"),
        )
        .unwrap();
        geneses.push((zone_name, genesis));
    }

    assert_eq!(mgr.zones().len(), zone_count);

    // Advance each zone to a different seq
    for (i, (zone_name, genesis)) in geneses.iter().enumerate() {
        let target_seq = (i as u64) + 1;
        let cp = build_after(
            genesis,
            target_seq,
            SecurityEpoch::GENESIS,
            200 + (i as u64) * 100,
            slice::from_ref(&sk),
            zone_name,
        );
        mgr.accept_checkpoint(zone_name, &cp, 1, slice::from_ref(&vk), &format!("t-{i}-1"))
            .unwrap();
    }

    // Verify each zone advanced independently
    for (i, (zone_name, _)) in geneses.iter().enumerate() {
        let frontier = mgr.get_frontier(zone_name).unwrap();
        assert_eq!(frontier.frontier_seq, (i as u64) + 1);
    }
}

// ===========================================================================
// 3) Stress: long chain in single zone
// ===========================================================================

#[test]
fn stress_long_chain_single_zone() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let chain_len = 50u64;
    let chain = build_chain(&sk, "zone-long", chain_len, SecurityEpoch::GENESIS);

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    for (i, cp) in chain.iter().enumerate() {
        mgr.accept_checkpoint("zone-long", cp, 1, slice::from_ref(&vk), &format!("t-{i}"))
            .unwrap();
    }

    let frontier = mgr.get_frontier("zone-long").unwrap();
    assert_eq!(frontier.frontier_seq, chain_len);
    assert_eq!(frontier.accept_count, chain_len + 1); // genesis + chain_len
    // recent_ids should be capped at 32
    assert!(frontier.recent_ids.len() <= 32);
    // Last entry should be the final seq
    assert_eq!(
        frontier.recent_ids.last().unwrap().checkpoint_seq,
        chain_len
    );
}

// ===========================================================================
// 4) recent_ids trimming preserves correct window
// ===========================================================================

#[test]
fn recent_ids_trimming_preserves_tail_window() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let total = 40u64; // 41 checkpoints (genesis + 40), exceeds MAX_RECENT_ENTRIES=32
    let chain = build_chain(&sk, "zone-trim", total, SecurityEpoch::GENESIS);

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    for (i, cp) in chain.iter().enumerate() {
        mgr.accept_checkpoint("zone-trim", cp, 1, slice::from_ref(&vk), &format!("t-{i}"))
            .unwrap();
    }

    let frontier = mgr.get_frontier("zone-trim").unwrap();
    assert_eq!(frontier.recent_ids.len(), 32);

    // The window should contain the last 32 entries: seq 9..=40
    let first_seq = frontier.recent_ids.first().unwrap().checkpoint_seq;
    let last_seq = frontier.recent_ids.last().unwrap().checkpoint_seq;
    assert_eq!(last_seq, 40);
    assert_eq!(first_seq, 40 - 31); // 9

    // Verify monotonic sequence in window
    for w in frontier.recent_ids.windows(2) {
        assert!(w[0].checkpoint_seq < w[1].checkpoint_seq);
    }
}

// ===========================================================================
// 5) Determinism: same operations produce identical state
// ===========================================================================

#[test]
fn determinism_same_ops_same_state() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut results = Vec::new();
    for _ in 0..3 {
        let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
        let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
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
            SecurityEpoch::from_raw(3),
            300,
            slice::from_ref(&sk),
            "zone-a",
        );
        mgr.accept_checkpoint("zone-a", &cp2, 1, slice::from_ref(&vk), "t-2")
            .unwrap();

        let state = mgr.get_frontier("zone-a").unwrap().clone();
        results.push(state);
    }

    // All three runs must produce identical state
    assert_eq!(results[0], results[1]);
    assert_eq!(results[1], results[2]);
}

// ===========================================================================
// 6) Epoch forward with large gap accepted
// ===========================================================================

#[test]
fn epoch_forward_large_gap_accepted() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(1), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    // Jump from epoch 1 to epoch 1000
    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::from_raw(1000),
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_epoch, SecurityEpoch::from_raw(1000));
}

// ===========================================================================
// 7) Same epoch accepted (no regression when equal)
// ===========================================================================

#[test]
fn same_epoch_accepted_across_checkpoints() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let epoch = SecurityEpoch::from_raw(7);
    let genesis = build_genesis_epoch(slice::from_ref(&sk), epoch, "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    // seq=1 at same epoch=7 should succeed
    let cp1 = build_after(&genesis, 1, epoch, 200, slice::from_ref(&sk), "zone-a");
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    // seq=2 at same epoch=7 should also succeed
    let cp2 = build_after(&cp1, 2, epoch, 300, slice::from_ref(&sk), "zone-a");
    mgr.accept_checkpoint("zone-a", &cp2, 1, slice::from_ref(&vk), "t-2")
        .unwrap();

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_epoch, epoch);
    assert_eq!(frontier.frontier_seq, 2);
}

// ===========================================================================
// 8) Persistence failure on genesis leaves no zone initialized
// ===========================================================================

#[test]
fn persistence_failure_on_genesis_leaves_no_zone() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut backend = InMemoryBackend::new();
    backend.fail_on_persist = true;

    let mut mgr = CheckpointFrontierManager::new(backend);
    let err = mgr
        .accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap_err();

    assert!(matches!(err, FrontierError::PersistenceFailed { .. }));
    assert!(mgr.get_frontier("zone-a").is_none());
    assert!(mgr.zones().is_empty());
}

// ===========================================================================
// 9) Persistence failure recovery: re-enable persist, retry succeeds
// ===========================================================================

#[test]
fn persistence_failure_recovery_retry_succeeds() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    // Fail on next persist
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
    assert_eq!(mgr.get_frontier("zone-a").unwrap().frontier_seq, 0);

    // Re-enable persistence and retry
    mgr.backend_mut().fail_on_persist = false;
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-retry")
        .unwrap();
    assert_eq!(mgr.get_frontier("zone-a").unwrap().frontier_seq, 1);
}

// ===========================================================================
// 10) Recovery from backend + continued operation
// ===========================================================================

#[test]
fn recovery_then_continued_operation() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let chain = build_chain(&sk, "zone-a", 5, SecurityEpoch::GENESIS);

    // First session: accept genesis + 5 checkpoints
    let mut mgr1 = CheckpointFrontierManager::new(InMemoryBackend::new());
    for (i, cp) in chain.iter().enumerate() {
        mgr1.accept_checkpoint("zone-a", cp, 1, slice::from_ref(&vk), &format!("t-{i}"))
            .unwrap();
    }

    let persisted = mgr1.backend().load("zone-a").unwrap().unwrap();

    // Second session: recover then continue
    let mut backend2 = InMemoryBackend::new();
    backend2.persist(&persisted).unwrap();
    let mut mgr2 = CheckpointFrontierManager::new(backend2);
    let count = mgr2.recover("t-recover").unwrap();
    assert_eq!(count, 1);

    // Continue the chain from seq=6
    let cp6 = build_after(
        &chain[5],
        6,
        SecurityEpoch::GENESIS,
        700,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr2.accept_checkpoint("zone-a", &cp6, 1, slice::from_ref(&vk), "t-6")
        .unwrap();

    let frontier = mgr2.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_seq, 6);
    assert_eq!(frontier.accept_count, 7); // 6 from previous + 1 new
}

// ===========================================================================
// 11) Recovery of multiple zones
// ===========================================================================

#[test]
fn recovery_multiple_zones() {
    let sk = make_sk(1);
    let _vk = sk.verification_key();

    let mut backend = InMemoryBackend::new();
    for i in 0..5 {
        let zone = format!("zone-{i}");
        let genesis = build_genesis(slice::from_ref(&sk), &zone);
        let state_seq = (i as u64) * 10;
        let state = FrontierState {
            zone: zone.clone(),
            frontier_seq: state_seq,
            frontier_checkpoint_id: genesis.checkpoint_id.clone(),
            frontier_epoch: SecurityEpoch::from_raw(i as u64),
            accept_count: state_seq + 1,
            recent_ids: vec![FrontierEntry {
                checkpoint_seq: state_seq,
                checkpoint_id: genesis.checkpoint_id.clone(),
                epoch: SecurityEpoch::from_raw(i as u64),
            }],
        };
        backend.persist(&state).unwrap();
    }

    let mut mgr = CheckpointFrontierManager::new(backend);
    let count = mgr.recover("t-multi").unwrap();
    assert_eq!(count, 5);
    assert_eq!(mgr.zones().len(), 5);

    // Verify events
    let events = mgr.drain_events();
    assert_eq!(events.len(), 5);
    assert!(
        events
            .iter()
            .all(|e| matches!(e.event_type, FrontierEventType::FrontierLoaded { .. }))
    );
    assert!(events.iter().all(|e| e.trace_id == "t-multi"));
}

// ===========================================================================
// 12) Interleaved errors and successes across zones
// ===========================================================================

#[test]
fn interleaved_errors_and_successes_across_zones() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    // Zone A: genesis
    let genesis_a = build_genesis(slice::from_ref(&sk), "zone-a");
    mgr.accept_checkpoint("zone-a", &genesis_a, 1, slice::from_ref(&vk), "t-a0")
        .unwrap();

    // Zone B: genesis
    let genesis_b = build_genesis(slice::from_ref(&sk), "zone-b");
    mgr.accept_checkpoint("zone-b", &genesis_b, 1, slice::from_ref(&vk), "t-b0")
        .unwrap();

    // Zone A: advance to seq=1
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

    // Zone A: rollback attempt (should fail)
    let rollback_a = build_genesis(slice::from_ref(&sk), "zone-a");
    let err = mgr
        .accept_checkpoint("zone-a", &rollback_a, 1, slice::from_ref(&vk), "t-a-bad")
        .unwrap_err();
    assert!(matches!(err, FrontierError::RollbackRejected { .. }));

    // Zone B: advance to seq=1 (should still work despite Zone A error)
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

    assert_eq!(mgr.get_frontier("zone-a").unwrap().frontier_seq, 1);
    assert_eq!(mgr.get_frontier("zone-b").unwrap().frontier_seq, 1);
}

// ===========================================================================
// 13) Event ordering is deterministic and sequential
// ===========================================================================

#[test]
fn event_ordering_deterministic() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
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

    // Trigger a rollback rejection
    let rollback = build_genesis(slice::from_ref(&sk), "zone-a");
    let _ = mgr.accept_checkpoint("zone-a", &rollback, 1, slice::from_ref(&vk), "t-bad");

    // Trigger a duplicate rejection
    let dup = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        250,
        slice::from_ref(&sk),
        "zone-a",
    );
    let _ = mgr.accept_checkpoint("zone-a", &dup, 1, slice::from_ref(&vk), "t-dup");

    let events = mgr.drain_events();
    assert_eq!(events.len(), 4); // init, accepted, rollback_rejected, duplicate_rejected

    // Check order
    assert!(matches!(
        events[0].event_type,
        FrontierEventType::ZoneInitialized { .. }
    ));
    assert!(matches!(
        events[1].event_type,
        FrontierEventType::CheckpointAccepted { .. }
    ));
    assert!(matches!(
        events[2].event_type,
        FrontierEventType::RollbackRejected { .. }
    ));
    assert!(matches!(
        events[3].event_type,
        FrontierEventType::DuplicateRejected { .. }
    ));
}

// ===========================================================================
// 14) event_counts includes all event types
// ===========================================================================

#[test]
fn event_counts_all_types_present() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    // Pre-populate backend for recovery
    let genesis = build_genesis(slice::from_ref(&sk), "zone-preloaded");
    let pre_state = FrontierState {
        zone: "zone-preloaded".to_string(),
        frontier_seq: 5,
        frontier_checkpoint_id: genesis.checkpoint_id.clone(),
        frontier_epoch: SecurityEpoch::from_raw(10),
        accept_count: 5,
        recent_ids: vec![],
    };

    let mut backend = InMemoryBackend::new();
    backend.persist(&pre_state).unwrap();

    let mut mgr = CheckpointFrontierManager::new(backend);
    mgr.recover("t-load").unwrap();

    // Init a fresh zone
    let genesis_a = build_genesis(slice::from_ref(&sk), "zone-a");
    mgr.accept_checkpoint("zone-a", &genesis_a, 1, slice::from_ref(&vk), "t-a0")
        .unwrap();

    // Advance
    let cp1 = build_after(
        &genesis_a,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-a1")
        .unwrap();

    // Rollback
    let rollback = build_genesis(slice::from_ref(&sk), "zone-a");
    let _ = mgr.accept_checkpoint("zone-a", &rollback, 1, slice::from_ref(&vk), "t-rb");

    // Duplicate
    let dup = build_after(
        &genesis_a,
        1,
        SecurityEpoch::GENESIS,
        250,
        slice::from_ref(&sk),
        "zone-a",
    );
    let _ = mgr.accept_checkpoint("zone-a", &dup, 1, slice::from_ref(&vk), "t-dup");

    let counts = mgr.event_counts();
    assert_eq!(*counts.get("frontier_loaded").unwrap_or(&0), 1);
    assert_eq!(*counts.get("zone_initialized").unwrap_or(&0), 1);
    assert_eq!(*counts.get("checkpoint_accepted").unwrap_or(&0), 1);
    assert_eq!(*counts.get("rollback_rejected").unwrap_or(&0), 1);
    assert_eq!(*counts.get("duplicate_rejected").unwrap_or(&0), 1);
}

// ===========================================================================
// 15) event_counts after drain is empty
// ===========================================================================

#[test]
fn event_counts_after_drain_is_empty() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    assert!(!mgr.event_counts().is_empty());
    let _ = mgr.drain_events();
    assert!(mgr.event_counts().is_empty());
}

// ===========================================================================
// 16) Serde round-trip: FrontierState with max recent entries
// ===========================================================================

#[test]
fn serde_roundtrip_frontier_state_max_entries() {
    let entries: Vec<FrontierEntry> = (0..32)
        .map(|i| FrontierEntry {
            checkpoint_seq: i as u64,
            checkpoint_id: oid(i as u8),
            epoch: SecurityEpoch::from_raw(1),
        })
        .collect();

    let state = FrontierState {
        zone: "zone-max".to_string(),
        frontier_seq: 31,
        frontier_checkpoint_id: oid(31),
        frontier_epoch: SecurityEpoch::from_raw(1),
        accept_count: 32,
        recent_ids: entries,
    };

    let json = serde_json::to_string(&state).unwrap();
    let restored: FrontierState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, restored);
    assert_eq!(restored.recent_ids.len(), 32);
}

// ===========================================================================
// 17) Serde round-trip: FrontierState with empty recent_ids
// ===========================================================================

#[test]
fn serde_roundtrip_frontier_state_empty_recent() {
    let state = FrontierState {
        zone: "zone-empty".to_string(),
        frontier_seq: 0,
        frontier_checkpoint_id: oid(0),
        frontier_epoch: SecurityEpoch::GENESIS,
        accept_count: 0,
        recent_ids: vec![],
    };

    let json = serde_json::to_string(&state).unwrap();
    let restored: FrontierState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, restored);
}

// ===========================================================================
// 18) Clone equality for FrontierState
// ===========================================================================

#[test]
fn frontier_state_clone_is_equal() {
    let state = FrontierState {
        zone: "zone-clone".to_string(),
        frontier_seq: 42,
        frontier_checkpoint_id: oid(42),
        frontier_epoch: SecurityEpoch::from_raw(7),
        accept_count: 10,
        recent_ids: vec![FrontierEntry {
            checkpoint_seq: 42,
            checkpoint_id: oid(42),
            epoch: SecurityEpoch::from_raw(7),
        }],
    };
    let cloned = state.clone();
    assert_eq!(state, cloned);
}

// ===========================================================================
// 19) Clone equality for FrontierError
// ===========================================================================

#[test]
fn frontier_error_clone_is_equal() {
    let errors = vec![
        FrontierError::RollbackRejected {
            zone: "z".to_string(),
            frontier_seq: 10,
            attempted_seq: 5,
        },
        FrontierError::DuplicateCheckpoint {
            zone: "z".to_string(),
            checkpoint_seq: 7,
        },
        FrontierError::ChainLinkageFailure {
            zone: "z".to_string(),
            detail: "bad".to_string(),
        },
        FrontierError::QuorumFailure {
            zone: "z".to_string(),
            detail: "low".to_string(),
        },
        FrontierError::UnknownZone {
            zone: "z".to_string(),
        },
        FrontierError::EpochRegression {
            zone: "z".to_string(),
            frontier_epoch: SecurityEpoch::from_raw(10),
            attempted_epoch: SecurityEpoch::from_raw(3),
        },
        FrontierError::PersistenceFailed {
            zone: "z".to_string(),
            detail: "disk".to_string(),
        },
    ];
    for err in &errors {
        let cloned = err.clone();
        assert_eq!(*err, cloned);
    }
}

// ===========================================================================
// 20) Clone equality for FrontierEvent
// ===========================================================================

#[test]
fn frontier_event_clone_is_equal() {
    let event = FrontierEvent {
        event_type: FrontierEventType::CheckpointAccepted {
            zone: "z".to_string(),
            prev_seq: 1,
            new_seq: 2,
        },
        trace_id: "t-test".to_string(),
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
}

// ===========================================================================
// 21) Clone equality for FrontierEntry
// ===========================================================================

#[test]
fn frontier_entry_clone_is_equal() {
    let entry = FrontierEntry {
        checkpoint_seq: 99,
        checkpoint_id: oid(99),
        epoch: SecurityEpoch::from_raw(5),
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

// ===========================================================================
// 22) FrontierError variants are distinguishable via PartialEq
// ===========================================================================

#[test]
fn frontier_error_variants_distinguishable() {
    let rollback = FrontierError::RollbackRejected {
        zone: "z".to_string(),
        frontier_seq: 10,
        attempted_seq: 5,
    };
    let duplicate = FrontierError::DuplicateCheckpoint {
        zone: "z".to_string(),
        checkpoint_seq: 10,
    };
    let unknown = FrontierError::UnknownZone {
        zone: "z".to_string(),
    };
    assert_ne!(rollback, duplicate);
    assert_ne!(rollback, unknown);
    assert_ne!(duplicate, unknown);
}

// ===========================================================================
// 23) Display format exact content for FrontierError::RollbackRejected
// ===========================================================================

#[test]
fn display_rollback_rejected_exact_content() {
    let err = FrontierError::RollbackRejected {
        zone: "prod-zone".to_string(),
        frontier_seq: 100,
        attempted_seq: 50,
    };
    let s = err.to_string();
    assert!(s.contains("rollback rejected"));
    assert!(s.contains("prod-zone"));
    assert!(s.contains("100"));
    assert!(s.contains("50"));
}

// ===========================================================================
// 24) Display format exact content for FrontierError::EpochRegression
// ===========================================================================

#[test]
fn display_epoch_regression_exact_content() {
    let err = FrontierError::EpochRegression {
        zone: "secure-zone".to_string(),
        frontier_epoch: SecurityEpoch::from_raw(100),
        attempted_epoch: SecurityEpoch::from_raw(50),
    };
    let s = err.to_string();
    assert!(s.contains("epoch regression"));
    assert!(s.contains("secure-zone"));
}

// ===========================================================================
// 25) Display format for FrontierEventType::CheckpointAccepted shows arrow
// ===========================================================================

#[test]
fn display_checkpoint_accepted_shows_transition() {
    let et = FrontierEventType::CheckpointAccepted {
        zone: "z".to_string(),
        prev_seq: 5,
        new_seq: 6,
    };
    let s = et.to_string();
    assert!(s.contains("5"));
    assert!(s.contains("6"));
    assert!(s.contains("->"));
}

// ===========================================================================
// 26) Debug output is non-empty for all types
// ===========================================================================

#[test]
fn debug_non_empty_all_types() {
    let state = FrontierState {
        zone: "z".to_string(),
        frontier_seq: 0,
        frontier_checkpoint_id: oid(0),
        frontier_epoch: SecurityEpoch::GENESIS,
        accept_count: 0,
        recent_ids: vec![],
    };
    assert!(!format!("{state:?}").is_empty());

    let entry = FrontierEntry {
        checkpoint_seq: 0,
        checkpoint_id: oid(0),
        epoch: SecurityEpoch::GENESIS,
    };
    assert!(!format!("{entry:?}").is_empty());

    let err = FrontierError::UnknownZone {
        zone: "z".to_string(),
    };
    assert!(!format!("{err:?}").is_empty());

    let event = FrontierEvent {
        event_type: FrontierEventType::ZoneInitialized {
            zone: "z".to_string(),
            genesis_seq: 0,
        },
        trace_id: "t".to_string(),
    };
    assert!(!format!("{event:?}").is_empty());
}

// ===========================================================================
// 27) verify_linkage_against_frontier after multi-step advance
// ===========================================================================

#[test]
fn linkage_verification_after_multi_step_advance() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let chain = build_chain(&sk, "zone-a", 5, SecurityEpoch::GENESIS);

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    for (i, cp) in chain.iter().enumerate() {
        mgr.accept_checkpoint("zone-a", cp, 1, slice::from_ref(&vk), &format!("t-{i}"))
            .unwrap();
    }

    // Verify linkage: prev=chain[5] (seq=5), new=chain[6-to-be]
    let cp6 = build_after(
        &chain[5],
        6,
        SecurityEpoch::GENESIS,
        700,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.verify_linkage_against_frontier("zone-a", &chain[5], &cp6)
        .unwrap();

    // Using chain[3] as prev should fail (frontier is at chain[5])
    let err = mgr
        .verify_linkage_against_frontier("zone-a", &chain[3], &cp6)
        .unwrap_err();
    assert!(matches!(err, FrontierError::ChainLinkageFailure { .. }));
}

// ===========================================================================
// 28) verify_linkage_against_frontier on fresh manager
// ===========================================================================

#[test]
fn linkage_verification_on_empty_manager() {
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
        .verify_linkage_against_frontier("zone-a", &genesis, &cp1)
        .unwrap_err();
    assert!(matches!(err, FrontierError::UnknownZone { .. }));
}

// ===========================================================================
// 29) Quorum failure does not emit checkpoint_accepted event
// ===========================================================================

#[test]
fn quorum_failure_does_not_emit_accepted_event() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let wrong_vk = VerificationKey::from_bytes([0xAA; 32]);
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    // Now try with wrong key
    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    let _ = mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&wrong_vk), "t-bad");

    let events = mgr.drain_events();
    // Should only have the genesis init event, no accepted event for the quorum failure
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0].event_type,
        FrontierEventType::ZoneInitialized { .. }
    ));
}

// ===========================================================================
// 30) Quorum failure on subsequent does not advance frontier
// ===========================================================================

#[test]
fn quorum_failure_does_not_advance_frontier() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let wrong_vk = VerificationKey::from_bytes([0xBB; 32]);
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

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_seq, 0);
    assert_eq!(frontier.accept_count, 1);
}

// ===========================================================================
// 31) Multi-signer: threshold=2 with 3 signers
// ===========================================================================

#[test]
fn multi_signer_threshold_2_of_3() {
    let sk1 = make_sk(1);
    let sk2 = make_sk(2);
    let sk3 = make_sk(3);
    let vk1 = sk1.verification_key();
    let vk2 = sk2.verification_key();
    let vk3 = sk3.verification_key();

    let genesis = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "zone-a",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .build(&[sk1, sk2, sk3])
    .unwrap();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    // threshold=2, 3 signers provided, 3 sigs present => success
    mgr.accept_checkpoint("zone-a", &genesis, 2, &[vk1, vk2, vk3], "t-0")
        .unwrap();
    assert_eq!(mgr.get_frontier("zone-a").unwrap().frontier_seq, 0);
}

// ===========================================================================
// 32) Persist count increments correctly across zones
// ===========================================================================

#[test]
fn persist_count_across_zones() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    let genesis_a = build_genesis(slice::from_ref(&sk), "zone-a");
    mgr.accept_checkpoint("zone-a", &genesis_a, 1, slice::from_ref(&vk), "t-a0")
        .unwrap();
    assert_eq!(mgr.backend().persist_count, 1);

    let genesis_b = build_genesis(slice::from_ref(&sk), "zone-b");
    mgr.accept_checkpoint("zone-b", &genesis_b, 1, slice::from_ref(&vk), "t-b0")
        .unwrap();
    assert_eq!(mgr.backend().persist_count, 2);

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
    assert_eq!(mgr.backend().persist_count, 3);
}

// ===========================================================================
// 33) Backend load after multiple persists returns latest
// ===========================================================================

#[test]
fn backend_load_returns_latest_state() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let chain = build_chain(&sk, "zone-a", 3, SecurityEpoch::GENESIS);

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    for (i, cp) in chain.iter().enumerate() {
        mgr.accept_checkpoint("zone-a", cp, 1, slice::from_ref(&vk), &format!("t-{i}"))
            .unwrap();
    }

    let loaded = mgr.backend().load("zone-a").unwrap().unwrap();
    assert_eq!(loaded.frontier_seq, 3);
    assert_eq!(loaded.accept_count, 4);
}

// ===========================================================================
// 34) Backend load_all returns all zones after multi-zone ops
// ===========================================================================

#[test]
fn backend_load_all_returns_all_zones() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    for i in 0..4 {
        let zone = format!("zone-{i}");
        let genesis = build_genesis(slice::from_ref(&sk), &zone);
        mgr.accept_checkpoint(&zone, &genesis, 1, slice::from_ref(&vk), &format!("t-{i}"))
            .unwrap();
    }

    let all = mgr.backend().load_all().unwrap();
    assert_eq!(all.len(), 4);
    let zone_names: BTreeSet<_> = all.iter().map(|s| s.zone.as_str()).collect();
    for i in 0..4 {
        assert!(zone_names.contains(format!("zone-{i}").as_str()));
    }
}

// ===========================================================================
// 35) Trace ID propagation in every event type
// ===========================================================================

#[test]
fn trace_id_propagation_in_all_event_types() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    // Recovery event with specific trace
    let mut backend = InMemoryBackend::new();
    let state = FrontierState {
        zone: "zone-pre".to_string(),
        frontier_seq: 1,
        frontier_checkpoint_id: oid(1),
        frontier_epoch: SecurityEpoch::GENESIS,
        accept_count: 1,
        recent_ids: vec![],
    };
    backend.persist(&state).unwrap();

    let mut mgr = CheckpointFrontierManager::new(backend);
    mgr.recover("trace-recover").unwrap();

    let events = mgr.drain_events();
    assert_eq!(events[0].trace_id, "trace-recover");

    // Init event
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "trace-init")
        .unwrap();
    let events = mgr.drain_events();
    assert_eq!(events[0].trace_id, "trace-init");

    // Accept event
    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "trace-accept")
        .unwrap();
    let events = mgr.drain_events();
    assert_eq!(events[0].trace_id, "trace-accept");

    // Rollback event
    let rollback = build_genesis(slice::from_ref(&sk), "zone-a");
    let _ = mgr.accept_checkpoint(
        "zone-a",
        &rollback,
        1,
        slice::from_ref(&vk),
        "trace-rollback",
    );
    let events = mgr.drain_events();
    assert_eq!(events[0].trace_id, "trace-rollback");

    // Duplicate event
    let dup = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        250,
        slice::from_ref(&sk),
        "zone-a",
    );
    let _ = mgr.accept_checkpoint("zone-a", &dup, 1, slice::from_ref(&vk), "trace-dup");
    let events = mgr.drain_events();
    assert_eq!(events[0].trace_id, "trace-dup");
}

// ===========================================================================
// 36) Epoch regression event includes epoch values
// ===========================================================================

#[test]
fn epoch_regression_event_includes_epochs() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis = build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(10), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::from_raw(10),
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    mgr.drain_events();

    // Create regressed checkpoint from independent chain
    let ind_genesis =
        build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(3), "zone-a");
    let regressed = build_after(
        &ind_genesis,
        2,
        SecurityEpoch::from_raw(3),
        300,
        slice::from_ref(&sk),
        "zone-a",
    );
    let _ = mgr.accept_checkpoint("zone-a", &regressed, 1, slice::from_ref(&vk), "t-reg");

    let events = mgr.drain_events();
    assert_eq!(events.len(), 1);
    match &events[0].event_type {
        FrontierEventType::EpochRegressionRejected {
            zone,
            frontier_epoch,
            attempted_epoch,
        } => {
            assert_eq!(zone, "zone-a");
            assert_eq!(*frontier_epoch, SecurityEpoch::from_raw(10));
            assert_eq!(*attempted_epoch, SecurityEpoch::from_raw(3));
        }
        other => panic!("expected EpochRegressionRejected, got {other:?}"),
    }
}

// ===========================================================================
// 37) Multiple epoch transitions in sequence
// ===========================================================================

#[test]
fn multiple_epoch_transitions() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::from_raw(2),
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();
    assert_eq!(
        mgr.get_frontier("zone-a").unwrap().frontier_epoch,
        SecurityEpoch::from_raw(2)
    );

    let cp2 = build_after(
        &cp1,
        2,
        SecurityEpoch::from_raw(5),
        300,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp2, 1, slice::from_ref(&vk), "t-2")
        .unwrap();
    assert_eq!(
        mgr.get_frontier("zone-a").unwrap().frontier_epoch,
        SecurityEpoch::from_raw(5)
    );

    let cp3 = build_after(
        &cp2,
        3,
        SecurityEpoch::from_raw(100),
        400,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp3, 1, slice::from_ref(&vk), "t-3")
        .unwrap();
    assert_eq!(
        mgr.get_frontier("zone-a").unwrap().frontier_epoch,
        SecurityEpoch::from_raw(100)
    );
}

// ===========================================================================
// 38) Rollback at seq-1 boundary
// ===========================================================================

#[test]
fn rollback_at_seq_minus_one() {
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

    // Try seq=1 when frontier is at seq=2 (off by one)
    let attempt = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        350,
        slice::from_ref(&sk),
        "zone-a",
    );
    let err = mgr
        .accept_checkpoint("zone-a", &attempt, 1, slice::from_ref(&vk), "t-bad")
        .unwrap_err();
    match err {
        FrontierError::DuplicateCheckpoint {
            zone,
            checkpoint_seq,
        } => {
            // seq=1 < frontier=2, but since it's not equal, it's actually a rollback...
            // Wait, seq=1 < 2 and seq=1 != 2, so this should be RollbackRejected
            panic!(
                "Expected RollbackRejected but got DuplicateCheckpoint zone={zone} seq={checkpoint_seq}"
            );
        }
        FrontierError::RollbackRejected {
            frontier_seq,
            attempted_seq,
            ..
        } => {
            assert_eq!(frontier_seq, 2);
            assert_eq!(attempted_seq, 1);
        }
        other => panic!("Expected RollbackRejected, got {other:?}"),
    }
}

// ===========================================================================
// 39) Duplicate exactly at current frontier seq
// ===========================================================================

#[test]
fn duplicate_at_exact_frontier_seq() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    // Genesis is at seq=0, try another seq=0
    let another_genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    let err = mgr
        .accept_checkpoint("zone-a", &another_genesis, 1, slice::from_ref(&vk), "t-dup")
        .unwrap_err();

    assert!(matches!(
        err,
        FrontierError::DuplicateCheckpoint {
            checkpoint_seq: 0,
            ..
        }
    ));
}

// ===========================================================================
// 40) Persistence count not incremented on error
// ===========================================================================

#[test]
fn persist_count_not_incremented_on_rejection() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();
    let count_after_genesis = mgr.backend().persist_count;

    // Rollback attempt (no persist should happen)
    let rollback = build_genesis(slice::from_ref(&sk), "zone-a");
    let _ = mgr.accept_checkpoint("zone-a", &rollback, 1, slice::from_ref(&vk), "t-bad");
    assert_eq!(mgr.backend().persist_count, count_after_genesis);

    // Quorum failure (no persist should happen)
    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    let wrong_vk = VerificationKey::from_bytes([0xCC; 32]);
    let _ = mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&wrong_vk), "t-bad2");
    assert_eq!(mgr.backend().persist_count, count_after_genesis);
}

// ===========================================================================
// 41) Zones list is sorted (BTreeMap determinism)
// ===========================================================================

#[test]
fn zones_list_is_sorted() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    // Insert zones in reverse alphabetical order
    let zone_names = vec!["zone-z", "zone-m", "zone-a", "zone-d", "zone-b"];
    for name in &zone_names {
        let genesis = build_genesis(slice::from_ref(&sk), name);
        mgr.accept_checkpoint(name, &genesis, 1, slice::from_ref(&vk), "t")
            .unwrap();
    }

    let zones = mgr.zones();
    let mut sorted = zones.clone();
    sorted.sort();
    assert_eq!(zones, sorted);
}

// ===========================================================================
// 42) FrontierState recent_ids epoch tracking
// ===========================================================================

#[test]
fn recent_ids_track_epoch_transitions() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    // Advance with increasing epochs
    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::from_raw(2),
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    let cp2 = build_after(
        &cp1,
        2,
        SecurityEpoch::from_raw(5),
        300,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp2, 1, slice::from_ref(&vk), "t-2")
        .unwrap();

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.recent_ids.len(), 3);
    assert_eq!(frontier.recent_ids[0].epoch, SecurityEpoch::GENESIS);
    assert_eq!(frontier.recent_ids[1].epoch, SecurityEpoch::from_raw(2));
    assert_eq!(frontier.recent_ids[2].epoch, SecurityEpoch::from_raw(5));
}

// ===========================================================================
// 43) FrontierState recent_ids checkpoint IDs match
// ===========================================================================

#[test]
fn recent_ids_checkpoint_ids_match() {
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

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.recent_ids[0].checkpoint_id, genesis.checkpoint_id);
    assert_eq!(frontier.recent_ids[1].checkpoint_id, cp1.checkpoint_id);
}

// ===========================================================================
// 44) Serde round-trip stability across all FrontierEventType variants
// ===========================================================================

#[test]
fn serde_roundtrip_all_event_types_in_frontier_event() {
    let event_types = vec![
        FrontierEventType::ZoneInitialized {
            zone: "z".to_string(),
            genesis_seq: 0,
        },
        FrontierEventType::CheckpointAccepted {
            zone: "z".to_string(),
            prev_seq: 5,
            new_seq: 6,
        },
        FrontierEventType::RollbackRejected {
            zone: "z".to_string(),
            frontier_seq: 10,
            attempted_seq: 3,
        },
        FrontierEventType::DuplicateRejected {
            zone: "z".to_string(),
            checkpoint_seq: 10,
        },
        FrontierEventType::EpochRegressionRejected {
            zone: "z".to_string(),
            frontier_epoch: SecurityEpoch::from_raw(100),
            attempted_epoch: SecurityEpoch::from_raw(50),
        },
        FrontierEventType::FrontierLoaded {
            zone: "z".to_string(),
            frontier_seq: 42,
        },
    ];

    for et in event_types {
        let event = FrontierEvent {
            event_type: et,
            trace_id: "trace-rt".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: FrontierEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }
}

// ===========================================================================
// 45) JSON structure stability: FrontierError variant tags
// ===========================================================================

#[test]
fn json_structure_frontier_error_variant_tags() {
    let err = FrontierError::RollbackRejected {
        zone: "z".to_string(),
        frontier_seq: 10,
        attempted_seq: 5,
    };
    let json = serde_json::to_string(&err).unwrap();
    // The JSON should contain the variant name
    assert!(json.contains("RollbackRejected"));

    let err2 = FrontierError::DuplicateCheckpoint {
        zone: "z".to_string(),
        checkpoint_seq: 7,
    };
    let json2 = serde_json::to_string(&err2).unwrap();
    assert!(json2.contains("DuplicateCheckpoint"));
}

// ===========================================================================
// 46) JSON structure stability: FrontierEventType variant tags
// ===========================================================================

#[test]
fn json_structure_frontier_event_type_variant_tags() {
    let variants: Vec<(&str, FrontierEventType)> = vec![
        (
            "ZoneInitialized",
            FrontierEventType::ZoneInitialized {
                zone: "z".to_string(),
                genesis_seq: 0,
            },
        ),
        (
            "CheckpointAccepted",
            FrontierEventType::CheckpointAccepted {
                zone: "z".to_string(),
                prev_seq: 1,
                new_seq: 2,
            },
        ),
        (
            "RollbackRejected",
            FrontierEventType::RollbackRejected {
                zone: "z".to_string(),
                frontier_seq: 5,
                attempted_seq: 3,
            },
        ),
        (
            "DuplicateRejected",
            FrontierEventType::DuplicateRejected {
                zone: "z".to_string(),
                checkpoint_seq: 5,
            },
        ),
        (
            "EpochRegressionRejected",
            FrontierEventType::EpochRegressionRejected {
                zone: "z".to_string(),
                frontier_epoch: SecurityEpoch::from_raw(5),
                attempted_epoch: SecurityEpoch::from_raw(3),
            },
        ),
        (
            "FrontierLoaded",
            FrontierEventType::FrontierLoaded {
                zone: "z".to_string(),
                frontier_seq: 10,
            },
        ),
    ];

    for (expected_tag, et) in variants {
        let json = serde_json::to_string(&et).unwrap();
        assert!(
            json.contains(expected_tag),
            "JSON for {expected_tag} should contain the tag: {json}"
        );
    }
}

// ===========================================================================
// 47) InMemoryBackend persist overwrite semantics
// ===========================================================================

#[test]
fn in_memory_backend_persist_overwrite_preserves_zone_count() {
    let mut backend = InMemoryBackend::new();

    let state_v1 = FrontierState {
        zone: "z".to_string(),
        frontier_seq: 1,
        frontier_checkpoint_id: oid(1),
        frontier_epoch: SecurityEpoch::GENESIS,
        accept_count: 1,
        recent_ids: vec![],
    };
    backend.persist(&state_v1).unwrap();

    let state_v2 = FrontierState {
        zone: "z".to_string(),
        frontier_seq: 2,
        frontier_checkpoint_id: oid(2),
        frontier_epoch: SecurityEpoch::GENESIS,
        accept_count: 2,
        recent_ids: vec![],
    };
    backend.persist(&state_v2).unwrap();

    let all = backend.load_all().unwrap();
    assert_eq!(all.len(), 1); // Should still be one zone, not two
    assert_eq!(all[0].frontier_seq, 2);
}

// ===========================================================================
// 48) Accept_count is monotonically increasing
// ===========================================================================

#[test]
fn accept_count_monotonically_increasing() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let chain = build_chain(&sk, "zone-a", 10, SecurityEpoch::GENESIS);

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    let mut prev_count = 0u64;

    for (i, cp) in chain.iter().enumerate() {
        mgr.accept_checkpoint("zone-a", cp, 1, slice::from_ref(&vk), &format!("t-{i}"))
            .unwrap();
        let count = mgr.get_frontier("zone-a").unwrap().accept_count;
        assert!(count > prev_count, "accept_count must increase");
        prev_count = count;
    }
    assert_eq!(prev_count, 11); // genesis + 10
}

// ===========================================================================
// 49) Frontier checkpoint_id tracks latest accepted
// ===========================================================================

#[test]
fn frontier_checkpoint_id_tracks_latest() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let chain = build_chain(&sk, "zone-a", 5, SecurityEpoch::GENESIS);

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    for (i, cp) in chain.iter().enumerate() {
        mgr.accept_checkpoint("zone-a", cp, 1, slice::from_ref(&vk), &format!("t-{i}"))
            .unwrap();
        let frontier = mgr.get_frontier("zone-a").unwrap();
        assert_eq!(
            frontier.frontier_checkpoint_id, cp.checkpoint_id,
            "frontier checkpoint_id should match latest accepted at step {i}"
        );
    }
}

// ===========================================================================
// 50) FrontierState zone field matches what was passed to manager
// ===========================================================================

#[test]
fn frontier_state_zone_field_matches() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let zone_names = vec!["alpha", "beta", "gamma-zone", "zone-with-dashes"];
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    for name in &zone_names {
        let genesis = build_genesis(slice::from_ref(&sk), name);
        mgr.accept_checkpoint(name, &genesis, 1, slice::from_ref(&vk), "t")
            .unwrap();
    }

    for name in &zone_names {
        let frontier = mgr.get_frontier(name).unwrap();
        assert_eq!(frontier.zone, *name);
    }
}

// ===========================================================================
// 51) FrontierError Display uses zone name for all variants
// ===========================================================================

#[test]
fn all_error_displays_contain_zone_name() {
    let zone = "my-custom-zone";
    let errors: Vec<FrontierError> = vec![
        FrontierError::RollbackRejected {
            zone: zone.to_string(),
            frontier_seq: 1,
            attempted_seq: 0,
        },
        FrontierError::DuplicateCheckpoint {
            zone: zone.to_string(),
            checkpoint_seq: 1,
        },
        FrontierError::ChainLinkageFailure {
            zone: zone.to_string(),
            detail: "d".to_string(),
        },
        FrontierError::QuorumFailure {
            zone: zone.to_string(),
            detail: "d".to_string(),
        },
        FrontierError::UnknownZone {
            zone: zone.to_string(),
        },
        FrontierError::EpochRegression {
            zone: zone.to_string(),
            frontier_epoch: SecurityEpoch::from_raw(1),
            attempted_epoch: SecurityEpoch::GENESIS,
        },
        FrontierError::PersistenceFailed {
            zone: zone.to_string(),
            detail: "d".to_string(),
        },
    ];

    for err in &errors {
        let s = err.to_string();
        assert!(
            s.contains(zone),
            "Display for {:?} should contain zone name: {s}",
            std::mem::discriminant(err)
        );
    }
}

// ===========================================================================
// 52) FrontierEventType Display uses zone name for all variants
// ===========================================================================

#[test]
fn all_event_type_displays_contain_zone_name() {
    let zone = "my-event-zone";
    let events: Vec<FrontierEventType> = vec![
        FrontierEventType::ZoneInitialized {
            zone: zone.to_string(),
            genesis_seq: 0,
        },
        FrontierEventType::CheckpointAccepted {
            zone: zone.to_string(),
            prev_seq: 0,
            new_seq: 1,
        },
        FrontierEventType::RollbackRejected {
            zone: zone.to_string(),
            frontier_seq: 1,
            attempted_seq: 0,
        },
        FrontierEventType::DuplicateRejected {
            zone: zone.to_string(),
            checkpoint_seq: 1,
        },
        FrontierEventType::EpochRegressionRejected {
            zone: zone.to_string(),
            frontier_epoch: SecurityEpoch::from_raw(5),
            attempted_epoch: SecurityEpoch::from_raw(3),
        },
        FrontierEventType::FrontierLoaded {
            zone: zone.to_string(),
            frontier_seq: 10,
        },
    ];

    for et in &events {
        let s = et.to_string();
        assert!(
            s.contains(zone),
            "Display for {et:?} should contain zone name: {s}"
        );
    }
}

// ===========================================================================
// 53) Error path: epoch regression on genesis-only zone
// ===========================================================================

#[test]
fn epoch_regression_on_genesis_only_zone() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis = build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(10), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    // Build from independent lower-epoch chain
    let ind_genesis =
        build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(5), "zone-a");
    let regressed = build_after(
        &ind_genesis,
        1,
        SecurityEpoch::from_raw(5),
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    let err = mgr
        .accept_checkpoint("zone-a", &regressed, 1, slice::from_ref(&vk), "t-reg")
        .unwrap_err();

    assert!(matches!(err, FrontierError::EpochRegression { .. }));
    // Frontier should remain at genesis
    assert_eq!(mgr.get_frontier("zone-a").unwrap().frontier_seq, 0);
}

// ===========================================================================
// 54) Serde: FrontierState with Unicode zone name
// ===========================================================================

#[test]
fn serde_roundtrip_unicode_zone_name() {
    let state = FrontierState {
        zone: "zone-\u{1F512}".to_string(), // lock emoji in zone name
        frontier_seq: 0,
        frontier_checkpoint_id: oid(0),
        frontier_epoch: SecurityEpoch::GENESIS,
        accept_count: 0,
        recent_ids: vec![],
    };
    let json = serde_json::to_string(&state).unwrap();
    let restored: FrontierState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, restored);
}

// ===========================================================================
// 55) Serde: FrontierError with empty strings
// ===========================================================================

#[test]
fn serde_roundtrip_empty_string_fields() {
    let err = FrontierError::ChainLinkageFailure {
        zone: "".to_string(),
        detail: "".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: FrontierError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// ===========================================================================
// 56) Serde: FrontierError with very long strings
// ===========================================================================

#[test]
fn serde_roundtrip_long_string_fields() {
    let long_zone = "z".repeat(1000);
    let long_detail = "d".repeat(5000);
    let err = FrontierError::PersistenceFailed {
        zone: long_zone.clone(),
        detail: long_detail.clone(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: FrontierError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// ===========================================================================
// 57) Backend: InMemoryBackend is Debug
// ===========================================================================

#[test]
fn in_memory_backend_is_debug() {
    let backend = InMemoryBackend::new();
    let debug_str = format!("{backend:?}");
    assert!(!debug_str.is_empty());
    assert!(debug_str.contains("InMemoryBackend"));
}

// ===========================================================================
// 58) FrontierState equality distinguishes by zone
// ===========================================================================

#[test]
fn frontier_state_eq_distinguishes_zone() {
    let state_a = FrontierState {
        zone: "zone-a".to_string(),
        frontier_seq: 0,
        frontier_checkpoint_id: oid(0),
        frontier_epoch: SecurityEpoch::GENESIS,
        accept_count: 0,
        recent_ids: vec![],
    };
    let state_b = FrontierState {
        zone: "zone-b".to_string(),
        ..state_a.clone()
    };
    assert_ne!(state_a, state_b);
}

// ===========================================================================
// 59) FrontierState equality distinguishes by seq
// ===========================================================================

#[test]
fn frontier_state_eq_distinguishes_seq() {
    let state1 = FrontierState {
        zone: "z".to_string(),
        frontier_seq: 1,
        frontier_checkpoint_id: oid(1),
        frontier_epoch: SecurityEpoch::GENESIS,
        accept_count: 1,
        recent_ids: vec![],
    };
    let state2 = FrontierState {
        frontier_seq: 2,
        ..state1.clone()
    };
    assert_ne!(state1, state2);
}

// ===========================================================================
// 60) Drain events returns ownership and clears
// ===========================================================================

#[test]
fn drain_events_clears_and_returns_ownership() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let events1 = mgr.drain_events();
    assert_eq!(events1.len(), 1);

    // Second drain should be empty
    let events2 = mgr.drain_events();
    assert!(events2.is_empty());

    // New operations should accumulate fresh events
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
    let events3 = mgr.drain_events();
    assert_eq!(events3.len(), 1);
}

// ===========================================================================
// 61) Cross-zone rollback: zone A rollback does not affect zone B
// ===========================================================================

#[test]
fn cross_zone_rollback_isolation() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    let genesis_a = build_genesis(slice::from_ref(&sk), "zone-a");
    mgr.accept_checkpoint("zone-a", &genesis_a, 1, slice::from_ref(&vk), "t-a0")
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

    let genesis_b = build_genesis(slice::from_ref(&sk), "zone-b");
    mgr.accept_checkpoint("zone-b", &genesis_b, 1, slice::from_ref(&vk), "t-b0")
        .unwrap();

    // Rollback in zone A
    let rollback_a = build_genesis(slice::from_ref(&sk), "zone-a");
    let err = mgr
        .accept_checkpoint("zone-a", &rollback_a, 1, slice::from_ref(&vk), "t-bad")
        .unwrap_err();
    assert!(matches!(err, FrontierError::RollbackRejected { .. }));

    // Zone B should still be able to advance
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
// 62) Persistence failure does not corrupt backend state
// ===========================================================================

#[test]
fn persistence_failure_does_not_corrupt_backend() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let before_state = mgr.backend().load("zone-a").unwrap().unwrap();

    // Fail persist on next accept
    mgr.backend_mut().fail_on_persist = true;
    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::GENESIS,
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    let _ = mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-fail");

    // Backend should still have the old state
    let after_state = mgr.backend().load("zone-a").unwrap().unwrap();
    assert_eq!(before_state, after_state);
}

// ===========================================================================
// 63) Multiple sequential rollback attempts
// ===========================================================================

#[test]
fn multiple_sequential_rollback_attempts() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let chain = build_chain(&sk, "zone-a", 5, SecurityEpoch::GENESIS);

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    for (i, cp) in chain.iter().enumerate() {
        mgr.accept_checkpoint("zone-a", cp, 1, slice::from_ref(&vk), &format!("t-{i}"))
            .unwrap();
    }

    // Try rolling back to each previous seq
    for seq in 0..=5u64 {
        let attempt = if seq == 0 {
            build_genesis(slice::from_ref(&sk), "zone-a")
        } else {
            build_after(
                &chain[0],
                seq,
                SecurityEpoch::GENESIS,
                900 + seq,
                slice::from_ref(&sk),
                "zone-a",
            )
        };
        let err = mgr
            .accept_checkpoint("zone-a", &attempt, 1, slice::from_ref(&vk), "t-rb")
            .unwrap_err();
        // seq < 5 => RollbackRejected, seq == 5 => DuplicateCheckpoint
        if seq < 5 {
            assert!(
                matches!(err, FrontierError::RollbackRejected { .. }),
                "seq={seq}: expected RollbackRejected, got {err:?}"
            );
        } else {
            assert!(
                matches!(err, FrontierError::DuplicateCheckpoint { .. }),
                "seq={seq}: expected DuplicateCheckpoint, got {err:?}"
            );
        }
    }

    // Frontier unchanged
    assert_eq!(mgr.get_frontier("zone-a").unwrap().frontier_seq, 5);
}

// ===========================================================================
// 64) Recovery preserves recent_ids
// ===========================================================================

#[test]
fn recovery_preserves_recent_ids() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let chain = build_chain(&sk, "zone-a", 10, SecurityEpoch::GENESIS);

    let mut mgr1 = CheckpointFrontierManager::new(InMemoryBackend::new());
    for (i, cp) in chain.iter().enumerate() {
        mgr1.accept_checkpoint("zone-a", cp, 1, slice::from_ref(&vk), &format!("t-{i}"))
            .unwrap();
    }

    let original_frontier = mgr1.get_frontier("zone-a").unwrap().clone();

    // Simulate recovery
    let persisted = mgr1.backend().load("zone-a").unwrap().unwrap();
    let mut backend2 = InMemoryBackend::new();
    backend2.persist(&persisted).unwrap();
    let mut mgr2 = CheckpointFrontierManager::new(backend2);
    mgr2.recover("t-recover").unwrap();

    let recovered_frontier = mgr2.get_frontier("zone-a").unwrap();
    assert_eq!(original_frontier.recent_ids, recovered_frontier.recent_ids);
    assert_eq!(
        original_frontier.accept_count,
        recovered_frontier.accept_count
    );
}

// ===========================================================================
// 65) Epoch regression detection after epoch advance
// ===========================================================================

#[test]
fn epoch_regression_detected_after_advance() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    // Advance epoch to 10
    let cp1 = build_after(
        &genesis,
        1,
        SecurityEpoch::from_raw(10),
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp1, 1, slice::from_ref(&vk), "t-1")
        .unwrap();

    // Advance epoch to 20
    let cp2 = build_after(
        &cp1,
        2,
        SecurityEpoch::from_raw(20),
        300,
        slice::from_ref(&sk),
        "zone-a",
    );
    mgr.accept_checkpoint("zone-a", &cp2, 1, slice::from_ref(&vk), "t-2")
        .unwrap();

    // Now try epoch=15 (between 10 and 20, but below current 20)
    let ind_genesis =
        build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(15), "zone-a");
    let regressed = build_after(
        &ind_genesis,
        3,
        SecurityEpoch::from_raw(15),
        400,
        slice::from_ref(&sk),
        "zone-a",
    );
    let err = mgr
        .accept_checkpoint("zone-a", &regressed, 1, slice::from_ref(&vk), "t-reg")
        .unwrap_err();
    assert!(matches!(err, FrontierError::EpochRegression { .. }));
}

// ===========================================================================
// 66) Event counts map keys are deterministic
// ===========================================================================

#[test]
fn event_counts_keys_deterministic() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
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

    let counts = mgr.event_counts();
    let keys: Vec<&String> = counts.keys().collect();
    let mut sorted_keys = keys.clone();
    sorted_keys.sort();
    assert_eq!(keys, sorted_keys, "BTreeMap keys should be sorted");
}

// ===========================================================================
// 67) Genesis at non-zero epoch
// ===========================================================================

#[test]
fn genesis_at_non_zero_epoch() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis = build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(42), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let frontier = mgr.get_frontier("zone-a").unwrap();
    assert_eq!(frontier.frontier_seq, 0);
    assert_eq!(frontier.frontier_epoch, SecurityEpoch::from_raw(42));
    assert_eq!(frontier.accept_count, 1);
}

// ===========================================================================
// 68) Mixed policy types in checkpoint
// ===========================================================================

#[test]
fn mixed_policy_types_accepted() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis = CheckpointBuilder::genesis(
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(100),
        "zone-a",
    )
    .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
    .add_policy_head(make_policy_head(PolicyType::CapabilityLattice, 1))
    .build(slice::from_ref(&sk))
    .unwrap();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    assert_eq!(mgr.get_frontier("zone-a").unwrap().frontier_seq, 0);
}

// ===========================================================================
// 69) Quorum threshold of 0 (always passes)
// ===========================================================================

#[test]
fn quorum_threshold_zero_is_rejected_as_invalid() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    // Quorum threshold of 0 is rejected as invalid by the implementation
    let result =
        mgr.accept_checkpoint("zone-a", &genesis, 0, slice::from_ref(&vk), "t-0");
    assert!(result.is_err());
}

// ===========================================================================
// 70) Epoch regression by exactly 1
// ===========================================================================

#[test]
fn epoch_regression_by_one() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let genesis = build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(5), "zone-a");
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    // Try epoch=4 (regression by exactly 1)
    let ind_genesis =
        build_genesis_epoch(slice::from_ref(&sk), SecurityEpoch::from_raw(4), "zone-a");
    let regressed = build_after(
        &ind_genesis,
        1,
        SecurityEpoch::from_raw(4),
        200,
        slice::from_ref(&sk),
        "zone-a",
    );
    let err = mgr
        .accept_checkpoint("zone-a", &regressed, 1, slice::from_ref(&vk), "t-reg")
        .unwrap_err();

    match err {
        FrontierError::EpochRegression {
            frontier_epoch,
            attempted_epoch,
            ..
        } => {
            assert_eq!(frontier_epoch, SecurityEpoch::from_raw(5));
            assert_eq!(attempted_epoch, SecurityEpoch::from_raw(4));
        }
        other => panic!("Expected EpochRegression, got {other:?}"),
    }
}

// ===========================================================================
// 71) Stress: 10 zones each with 10-step chains
// ===========================================================================

#[test]
fn stress_ten_zones_ten_steps_each() {
    let sk = make_sk(1);
    let vk = sk.verification_key();
    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    let mut all_chains: BTreeMap<String, Vec<PolicyCheckpoint>> = BTreeMap::new();

    for z in 0..10 {
        let zone = format!("zone-{z:02}");
        let chain = build_chain(&sk, &zone, 10, SecurityEpoch::GENESIS);
        all_chains.insert(zone, chain);
    }

    // Accept all checkpoints interleaved: step 0 for all zones, then step 1, etc.
    for step in 0..=10usize {
        for (zone, chain) in &all_chains {
            mgr.accept_checkpoint(
                zone,
                &chain[step],
                1,
                slice::from_ref(&vk),
                &format!("t-{zone}-{step}"),
            )
            .unwrap();
        }
    }

    for zone in all_chains.keys() {
        let frontier = mgr.get_frontier(zone.as_str()).unwrap();
        assert_eq!(frontier.frontier_seq, 10);
        assert_eq!(frontier.accept_count, 11);
    }

    assert_eq!(mgr.zones().len(), 10);
    assert_eq!(mgr.backend().persist_count, 110); // 10 zones * 11 steps
}

// ===========================================================================
// 72) FrontierEntry with zero epoch
// ===========================================================================

#[test]
fn frontier_entry_with_zero_epoch() {
    let entry = FrontierEntry {
        checkpoint_seq: 0,
        checkpoint_id: oid(0),
        epoch: SecurityEpoch::GENESIS,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: FrontierEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
    assert_eq!(entry.epoch, SecurityEpoch::from_raw(0));
}

// ===========================================================================
// 73) FrontierError ChainLinkageFailure display contains detail
// ===========================================================================

#[test]
fn chain_linkage_failure_display_contains_all_info() {
    let err = FrontierError::ChainLinkageFailure {
        zone: "zone-chain".to_string(),
        detail: "prev hash does not match".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("zone-chain"));
    assert!(s.contains("prev hash does not match"));
    assert!(s.contains("chain linkage"));
}

// ===========================================================================
// 74) Multiple drains with operations between
// ===========================================================================

#[test]
fn multiple_drains_with_operations_between() {
    let sk = make_sk(1);
    let vk = sk.verification_key();

    let mut mgr = CheckpointFrontierManager::new(InMemoryBackend::new());

    let genesis = build_genesis(slice::from_ref(&sk), "zone-a");
    mgr.accept_checkpoint("zone-a", &genesis, 1, slice::from_ref(&vk), "t-0")
        .unwrap();

    let drain1 = mgr.drain_events();
    assert_eq!(drain1.len(), 1);

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

    let drain2 = mgr.drain_events();
    assert_eq!(drain2.len(), 2); // Two checkpoint_accepted events

    let drain3 = mgr.drain_events();
    assert!(drain3.is_empty());
}

// ===========================================================================
// 75) Serde JSON: verify FrontierState field count
// ===========================================================================

#[test]
fn serde_json_frontier_state_field_count() {
    let state = FrontierState {
        zone: "z".to_string(),
        frontier_seq: 0,
        frontier_checkpoint_id: oid(0),
        frontier_epoch: SecurityEpoch::GENESIS,
        accept_count: 0,
        recent_ids: vec![],
    };
    let val: serde_json::Value = serde_json::to_value(&state).unwrap();
    let obj = val.as_object().unwrap();
    assert_eq!(obj.len(), 6, "FrontierState should have 6 JSON fields");
}
