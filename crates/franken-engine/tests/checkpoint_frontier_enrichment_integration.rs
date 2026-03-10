#![forbid(unsafe_code)]
//! Enrichment integration tests for `checkpoint_frontier`.
//!
//! Adds JSON field-name stability, exact Display values, Debug distinctness,
//! error coverage, serde roundtrips, construction and initial state, and
//! event type coverage beyond the existing 48 integration tests.

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

use frankenengine_engine::checkpoint_frontier::{
    CheckpointFrontierManager, FrontierEntry, FrontierError, FrontierEvent, FrontierEventType,
    FrontierState, InMemoryBackend, PersistenceBackend,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn oid(seed: u8) -> EngineObjectId {
    EngineObjectId([seed; 32])
}

// ===========================================================================
// 1) FrontierError — Display uniqueness + std::error::Error
// ===========================================================================

#[test]
fn frontier_error_display_all_unique() {
    let variants: Vec<String> = vec![
        FrontierError::RollbackRejected {
            zone: "z1".into(),
            frontier_seq: 10,
            attempted_seq: 5,
        }
        .to_string(),
        FrontierError::DuplicateCheckpoint {
            zone: "z2".into(),
            checkpoint_seq: 3,
        }
        .to_string(),
        FrontierError::ChainLinkageFailure {
            zone: "z3".into(),
            detail: "bad".into(),
        }
        .to_string(),
        FrontierError::QuorumFailure {
            zone: "z4".into(),
            detail: "low".into(),
        }
        .to_string(),
        FrontierError::UnknownZone { zone: "z5".into() }.to_string(),
        FrontierError::EpochRegression {
            zone: "z6".into(),
            frontier_epoch: SecurityEpoch::from_raw(5),
            attempted_epoch: SecurityEpoch::from_raw(3),
        }
        .to_string(),
        FrontierError::PersistenceFailed {
            zone: "z7".into(),
            detail: "disk".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn frontier_error_is_std_error() {
    let e = FrontierError::UnknownZone { zone: "x".into() };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn frontier_error_display_contains_zone() {
    let e = FrontierError::RollbackRejected {
        zone: "myzone".into(),
        frontier_seq: 10,
        attempted_seq: 5,
    };
    let s = e.to_string();
    assert!(s.contains("myzone"), "should contain zone: {s}");
}

// ===========================================================================
// 2) FrontierEventType — Display exactness
// ===========================================================================

#[test]
fn frontier_event_type_display_zone_initialized() {
    let et = FrontierEventType::ZoneInitialized {
        zone: "z".into(),
        genesis_seq: 0,
    };
    let s = et.to_string();
    assert!(
        s.contains("zone_initialized") || s.contains("initialized"),
        "should describe init: {s}"
    );
    assert!(s.contains("z"), "should contain zone: {s}");
}

#[test]
fn frontier_event_type_display_checkpoint_accepted() {
    let et = FrontierEventType::CheckpointAccepted {
        zone: "z".into(),
        prev_seq: 1,
        new_seq: 2,
    };
    let s = et.to_string();
    assert!(
        s.contains("checkpoint_accepted") || s.contains("accepted"),
        "should describe accept: {s}"
    );
}

#[test]
fn frontier_event_type_display_all_distinct() {
    let variants: Vec<String> = vec![
        FrontierEventType::ZoneInitialized {
            zone: "z".into(),
            genesis_seq: 0,
        }
        .to_string(),
        FrontierEventType::CheckpointAccepted {
            zone: "z".into(),
            prev_seq: 1,
            new_seq: 2,
        }
        .to_string(),
        FrontierEventType::RollbackRejected {
            zone: "z".into(),
            frontier_seq: 3,
            attempted_seq: 1,
        }
        .to_string(),
        FrontierEventType::DuplicateRejected {
            zone: "z".into(),
            checkpoint_seq: 3,
        }
        .to_string(),
        FrontierEventType::EpochRegressionRejected {
            zone: "z".into(),
            frontier_epoch: SecurityEpoch::from_raw(5),
            attempted_epoch: SecurityEpoch::from_raw(3),
        }
        .to_string(),
        FrontierEventType::FrontierLoaded {
            zone: "z".into(),
            frontier_seq: 10,
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_frontier_error() {
    let variants = [
        format!("{:?}", FrontierError::UnknownZone { zone: "a".into() }),
        format!(
            "{:?}",
            FrontierError::PersistenceFailed {
                zone: "b".into(),
                detail: "c".into()
            }
        ),
        format!(
            "{:?}",
            FrontierError::RollbackRejected {
                zone: "d".into(),
                frontier_seq: 1,
                attempted_seq: 0
            }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 4) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_frontier_error_all() {
    let variants = vec![
        FrontierError::RollbackRejected {
            zone: "z1".into(),
            frontier_seq: 10,
            attempted_seq: 5,
        },
        FrontierError::DuplicateCheckpoint {
            zone: "z2".into(),
            checkpoint_seq: 3,
        },
        FrontierError::ChainLinkageFailure {
            zone: "z3".into(),
            detail: "bad".into(),
        },
        FrontierError::QuorumFailure {
            zone: "z4".into(),
            detail: "low".into(),
        },
        FrontierError::UnknownZone { zone: "z5".into() },
        FrontierError::EpochRegression {
            zone: "z6".into(),
            frontier_epoch: SecurityEpoch::from_raw(5),
            attempted_epoch: SecurityEpoch::from_raw(3),
        },
        FrontierError::PersistenceFailed {
            zone: "z7".into(),
            detail: "disk".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: FrontierError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_frontier_entry() {
    let fe = FrontierEntry {
        checkpoint_seq: 42,
        checkpoint_id: oid(1),
        epoch: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&fe).unwrap();
    let rt: FrontierEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(fe, rt);
}

#[test]
fn serde_roundtrip_frontier_state() {
    let fs = FrontierState {
        zone: "test-zone".into(),
        frontier_seq: 10,
        frontier_checkpoint_id: oid(2),
        frontier_epoch: SecurityEpoch::from_raw(3),
        accept_count: 10,
        recent_ids: vec![
            FrontierEntry {
                checkpoint_seq: 9,
                checkpoint_id: oid(1),
                epoch: SecurityEpoch::from_raw(2),
            },
            FrontierEntry {
                checkpoint_seq: 10,
                checkpoint_id: oid(2),
                epoch: SecurityEpoch::from_raw(3),
            },
        ],
    };
    let json = serde_json::to_string(&fs).unwrap();
    let rt: FrontierState = serde_json::from_str(&json).unwrap();
    assert_eq!(fs, rt);
}

#[test]
fn serde_roundtrip_frontier_event() {
    let fe = FrontierEvent {
        event_type: FrontierEventType::ZoneInitialized {
            zone: "z".into(),
            genesis_seq: 0,
        },
        trace_id: "trace-1".into(),
    };
    let json = serde_json::to_string(&fe).unwrap();
    let rt: FrontierEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(fe, rt);
}

// ===========================================================================
// 5) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_frontier_entry() {
    let fe = FrontierEntry {
        checkpoint_seq: 1,
        checkpoint_id: oid(1),
        epoch: SecurityEpoch::from_raw(1),
    };
    let v: serde_json::Value = serde_json::to_value(&fe).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["checkpoint_seq", "checkpoint_id", "epoch"] {
        assert!(obj.contains_key(key), "FrontierEntry missing field: {key}");
    }
}

#[test]
fn json_fields_frontier_state() {
    let fs = FrontierState {
        zone: "z".into(),
        frontier_seq: 0,
        frontier_checkpoint_id: oid(0),
        frontier_epoch: SecurityEpoch::from_raw(0),
        accept_count: 0,
        recent_ids: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&fs).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "zone",
        "frontier_seq",
        "frontier_checkpoint_id",
        "frontier_epoch",
        "accept_count",
        "recent_ids",
    ] {
        assert!(obj.contains_key(key), "FrontierState missing field: {key}");
    }
}

#[test]
fn json_fields_frontier_event() {
    let fe = FrontierEvent {
        event_type: FrontierEventType::FrontierLoaded {
            zone: "z".into(),
            frontier_seq: 0,
        },
        trace_id: "t".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&fe).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["event_type", "trace_id"] {
        assert!(obj.contains_key(key), "FrontierEvent missing field: {key}");
    }
}

// ===========================================================================
// 6) InMemoryBackend — default
// ===========================================================================

#[test]
fn in_memory_backend_default() {
    let backend = InMemoryBackend::default();
    assert!(!backend.fail_on_persist);
    assert_eq!(backend.persist_count, 0);
}

#[test]
fn in_memory_backend_new() {
    let backend = InMemoryBackend::new();
    assert!(!backend.fail_on_persist);
}

// ===========================================================================
// 7) CheckpointFrontierManager — construction and initial state
// ===========================================================================

#[test]
fn manager_new_empty() {
    let backend = InMemoryBackend::new();
    let manager = CheckpointFrontierManager::new(backend);
    assert!(manager.zones().is_empty());
}

#[test]
fn manager_get_frontier_unknown_zone() {
    let backend = InMemoryBackend::new();
    let manager = CheckpointFrontierManager::new(backend);
    assert!(manager.get_frontier("nonexistent").is_none());
}

#[test]
fn manager_drain_events_initially_empty() {
    let backend = InMemoryBackend::new();
    let mut manager = CheckpointFrontierManager::new(backend);
    assert!(manager.drain_events().is_empty());
}

#[test]
fn manager_event_counts_initially_empty() {
    let backend = InMemoryBackend::new();
    let manager = CheckpointFrontierManager::new(backend);
    assert!(manager.event_counts().is_empty());
}

#[test]
fn manager_recover_empty_backend() {
    let backend = InMemoryBackend::new();
    let mut manager = CheckpointFrontierManager::new(backend);
    let count = manager.recover("trace-1").unwrap();
    assert_eq!(count, 0);
}

#[test]
fn manager_backend_access() {
    let backend = InMemoryBackend::new();
    let manager = CheckpointFrontierManager::new(backend);
    let b = manager.backend();
    assert!(!b.fail_on_persist);
}

// ===========================================================================
// 8) PersistenceBackend trait via InMemoryBackend
// ===========================================================================

#[test]
fn persistence_backend_persist_and_load() {
    let mut backend = InMemoryBackend::new();
    let state = FrontierState {
        zone: "test-zone".into(),
        frontier_seq: 5,
        frontier_checkpoint_id: oid(10),
        frontier_epoch: SecurityEpoch::from_raw(2),
        accept_count: 5,
        recent_ids: vec![FrontierEntry {
            checkpoint_seq: 5,
            checkpoint_id: oid(10),
            epoch: SecurityEpoch::from_raw(2),
        }],
    };
    backend.persist(&state).unwrap();
    assert_eq!(backend.persist_count, 1);

    let loaded = backend.load("test-zone").unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap(), state);
}

#[test]
fn persistence_backend_load_nonexistent() {
    let backend = InMemoryBackend::new();
    let loaded = backend.load("nonexistent").unwrap();
    assert!(loaded.is_none());
}

#[test]
fn persistence_backend_load_all_empty() {
    let backend = InMemoryBackend::new();
    let all = backend.load_all().unwrap();
    assert!(all.is_empty());
}

#[test]
fn persistence_backend_load_all_multiple() {
    let mut backend = InMemoryBackend::new();
    for i in 0..3 {
        let state = FrontierState {
            zone: format!("zone-{i}"),
            frontier_seq: i as u64,
            frontier_checkpoint_id: oid(i),
            frontier_epoch: SecurityEpoch::from_raw(1),
            accept_count: i as u64,
            recent_ids: vec![],
        };
        backend.persist(&state).unwrap();
    }
    let all = backend.load_all().unwrap();
    assert_eq!(all.len(), 3);
}

#[test]
fn persistence_backend_persist_overwrites() {
    let mut backend = InMemoryBackend::new();
    let state1 = FrontierState {
        zone: "z".into(),
        frontier_seq: 1,
        frontier_checkpoint_id: oid(1),
        frontier_epoch: SecurityEpoch::from_raw(1),
        accept_count: 1,
        recent_ids: vec![],
    };
    backend.persist(&state1).unwrap();
    let state2 = FrontierState {
        frontier_seq: 2,
        frontier_checkpoint_id: oid(2),
        accept_count: 2,
        ..state1.clone()
    };
    backend.persist(&state2).unwrap();
    let loaded = backend.load("z").unwrap().unwrap();
    assert_eq!(loaded.frontier_seq, 2);
    assert_eq!(backend.persist_count, 2);
}

#[test]
fn persistence_backend_fail_on_persist() {
    let mut backend = InMemoryBackend::new();
    backend.fail_on_persist = true;
    let state = FrontierState {
        zone: "z".into(),
        frontier_seq: 0,
        frontier_checkpoint_id: oid(0),
        frontier_epoch: SecurityEpoch::from_raw(0),
        accept_count: 0,
        recent_ids: vec![],
    };
    let err = backend.persist(&state).unwrap_err();
    assert!(
        err.contains("simulated"),
        "error should be simulated: {err}"
    );
}

// ===========================================================================
// 9) Manager recover with pre-loaded backend
// ===========================================================================

#[test]
fn manager_recover_loads_persisted_zones() {
    let mut backend = InMemoryBackend::new();
    for i in 0..3 {
        let state = FrontierState {
            zone: format!("zone-{i}"),
            frontier_seq: i as u64 + 1,
            frontier_checkpoint_id: oid(i + 1),
            frontier_epoch: SecurityEpoch::from_raw(1),
            accept_count: i as u64 + 1,
            recent_ids: vec![],
        };
        backend.persist(&state).unwrap();
    }
    let mut manager = CheckpointFrontierManager::new(backend);
    let count = manager.recover("recover-trace").unwrap();
    assert_eq!(count, 3);
    assert_eq!(manager.zones().len(), 3);

    // Each zone should be accessible
    for i in 0..3 {
        let fs = manager.get_frontier(&format!("zone-{i}")).unwrap();
        assert_eq!(fs.frontier_seq, i as u64 + 1);
    }

    // Recovery should emit FrontierLoaded events
    let events = manager.drain_events();
    assert_eq!(events.len(), 3);
    for event in &events {
        assert!(
            matches!(event.event_type, FrontierEventType::FrontierLoaded { .. }),
            "expected FrontierLoaded, got {:?}",
            event.event_type
        );
        assert_eq!(event.trace_id, "recover-trace");
    }
}

#[test]
fn manager_recover_idempotent() {
    let mut backend = InMemoryBackend::new();
    let state = FrontierState {
        zone: "z".into(),
        frontier_seq: 5,
        frontier_checkpoint_id: oid(5),
        frontier_epoch: SecurityEpoch::from_raw(1),
        accept_count: 5,
        recent_ids: vec![],
    };
    backend.persist(&state).unwrap();

    let mut manager = CheckpointFrontierManager::new(backend);
    let c1 = manager.recover("t1").unwrap();
    let c2 = manager.recover("t2").unwrap();
    assert_eq!(c1, 1);
    assert_eq!(c2, 1); // Second recovery replaces same zones
    assert_eq!(manager.zones().len(), 1);
}

// ===========================================================================
// 10) Serde roundtrips for FrontierEventType variants
// ===========================================================================

#[test]
fn serde_roundtrip_frontier_event_type_all_variants() {
    let variants = vec![
        FrontierEventType::ZoneInitialized {
            zone: "z".into(),
            genesis_seq: 0,
        },
        FrontierEventType::CheckpointAccepted {
            zone: "z".into(),
            prev_seq: 1,
            new_seq: 2,
        },
        FrontierEventType::RollbackRejected {
            zone: "z".into(),
            frontier_seq: 5,
            attempted_seq: 3,
        },
        FrontierEventType::DuplicateRejected {
            zone: "z".into(),
            checkpoint_seq: 5,
        },
        FrontierEventType::EpochRegressionRejected {
            zone: "z".into(),
            frontier_epoch: SecurityEpoch::from_raw(10),
            attempted_epoch: SecurityEpoch::from_raw(5),
        },
        FrontierEventType::FrontierLoaded {
            zone: "z".into(),
            frontier_seq: 42,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: FrontierEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// 11) FrontierError field content
// ===========================================================================

#[test]
fn frontier_error_display_contains_seq_numbers() {
    let e = FrontierError::RollbackRejected {
        zone: "z".into(),
        frontier_seq: 100,
        attempted_seq: 50,
    };
    let s = e.to_string();
    assert!(
        s.contains("100") || s.contains("50"),
        "should contain seq: {s}"
    );
}

#[test]
fn frontier_error_display_duplicate_contains_seq() {
    let e = FrontierError::DuplicateCheckpoint {
        zone: "z".into(),
        checkpoint_seq: 42,
    };
    let s = e.to_string();
    assert!(s.contains("42"), "should contain seq 42: {s}");
}

#[test]
fn frontier_error_display_epoch_regression_contains_epochs() {
    let e = FrontierError::EpochRegression {
        zone: "z".into(),
        frontier_epoch: SecurityEpoch::from_raw(10),
        attempted_epoch: SecurityEpoch::from_raw(5),
    };
    let s = e.to_string();
    assert!(
        s.contains("10") || s.contains("5"),
        "should contain epochs: {s}"
    );
}

#[test]
fn frontier_error_display_quorum_contains_detail() {
    let e = FrontierError::QuorumFailure {
        zone: "z".into(),
        detail: "insufficient signatures".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("insufficient") || s.contains("quorum"),
        "should contain detail: {s}"
    );
}

#[test]
fn frontier_error_display_chain_linkage_contains_detail() {
    let e = FrontierError::ChainLinkageFailure {
        zone: "z".into(),
        detail: "prev mismatch".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("mismatch") || s.contains("linkage"),
        "should contain detail: {s}"
    );
}

#[test]
fn frontier_error_display_persistence_contains_detail() {
    let e = FrontierError::PersistenceFailed {
        zone: "z".into(),
        detail: "disk full".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("disk") || s.contains("persistence"),
        "should contain detail: {s}"
    );
}

// ===========================================================================
// 12) FrontierState initial values
// ===========================================================================

#[test]
fn frontier_state_empty_recent_ids() {
    let fs = FrontierState {
        zone: "z".into(),
        frontier_seq: 0,
        frontier_checkpoint_id: oid(0),
        frontier_epoch: SecurityEpoch::from_raw(0),
        accept_count: 0,
        recent_ids: vec![],
    };
    assert_eq!(fs.recent_ids.len(), 0);
    assert_eq!(fs.accept_count, 0);
}

// ===========================================================================
// 13) Manager backend_mut
// ===========================================================================

#[test]
fn manager_backend_mut_allows_modification() {
    let backend = InMemoryBackend::new();
    let mut manager = CheckpointFrontierManager::new(backend);
    manager.backend_mut().fail_on_persist = true;
    assert!(manager.backend().fail_on_persist);
}

// ===========================================================================
// 14) Event counts after recover
// ===========================================================================

#[test]
fn manager_event_counts_after_recover() {
    let mut backend = InMemoryBackend::new();
    for i in 0..2 {
        let state = FrontierState {
            zone: format!("zone-{i}"),
            frontier_seq: 1,
            frontier_checkpoint_id: oid(i + 1),
            frontier_epoch: SecurityEpoch::from_raw(1),
            accept_count: 1,
            recent_ids: vec![],
        };
        backend.persist(&state).unwrap();
    }
    let mut manager = CheckpointFrontierManager::new(backend);
    manager.recover("t").unwrap();
    let counts = manager.event_counts();
    // Should have FrontierLoaded events counted
    assert!(!counts.is_empty());
}

// ===========================================================================
// 15) FrontierEntry ordering
// ===========================================================================

#[test]
fn frontier_entry_eq_and_ne() {
    let e1 = FrontierEntry {
        checkpoint_seq: 1,
        checkpoint_id: oid(1),
        epoch: SecurityEpoch::from_raw(1),
    };
    let e2 = FrontierEntry {
        checkpoint_seq: 2,
        checkpoint_id: oid(2),
        epoch: SecurityEpoch::from_raw(1),
    };
    assert_eq!(e1, e1);
    assert_ne!(e1, e2);
}

// ===========================================================================
// 16) FrontierEvent trace_id propagation
// ===========================================================================

#[test]
fn frontier_event_trace_id_preserved() {
    let event = FrontierEvent {
        event_type: FrontierEventType::CheckpointAccepted {
            zone: "z".into(),
            prev_seq: 0,
            new_seq: 1,
        },
        trace_id: "my-unique-trace".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("my-unique-trace"));
    let back: FrontierEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_id, "my-unique-trace");
}

// ===========================================================================
// 17) Multiple zones isolation in manager
// ===========================================================================

#[test]
fn manager_zones_sorted_deterministic() {
    let mut backend = InMemoryBackend::new();
    // Insert in reverse order
    for i in (0..5).rev() {
        let state = FrontierState {
            zone: format!("zone-{i}"),
            frontier_seq: 1,
            frontier_checkpoint_id: oid(i + 1),
            frontier_epoch: SecurityEpoch::from_raw(1),
            accept_count: 1,
            recent_ids: vec![],
        };
        backend.persist(&state).unwrap();
    }
    let mut manager = CheckpointFrontierManager::new(backend);
    manager.recover("t").unwrap();

    let zones = manager.zones();
    assert_eq!(zones.len(), 5);
    // BTreeMap should give sorted order
    let mut sorted = zones.clone();
    sorted.sort();
    assert_eq!(zones, sorted, "zones should be in sorted order");
}
