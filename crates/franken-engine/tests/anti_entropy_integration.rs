#![forbid(unsafe_code)]

//! Integration tests for the `anti_entropy` module.
//!
//! Covers: ReconcileObjectType, ObjectId, Iblt, IbltCell, ReconcileResult,
//! ReconcileEvent, ReconcileError, ReconcileConfig, ReconcileSession,
//! FallbackTrigger, FallbackEvidence, FallbackResult, FallbackConfig,
//! FallbackProtocol, FallbackRateAlert, FallbackRateMonitor,
//! Display impls, serde round-trips, deterministic replay, state transitions.

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

use frankenengine_engine::anti_entropy::{
    FallbackConfig, FallbackEvidence, FallbackProtocol, FallbackRateAlert, FallbackRateMonitor,
    FallbackRequest, FallbackResult, FallbackTrigger, Iblt, IbltCell, ObjectId, ReconcileConfig,
    ReconcileError, ReconcileEvent, ReconcileObjectType, ReconcileResult, ReconcileSession,
    SymmetricDiff,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_hash(seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, byte) in h.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8).wrapping_mul(37);
    }
    h
}

fn make_wide_hash(val: u16, marker: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    let bytes = val.to_le_bytes();
    h[0] = bytes[0];
    h[1] = bytes[1];
    h[2] = marker;
    for i in 3..32 {
        h[i] = h[i - 1].wrapping_mul(37).wrapping_add(marker);
    }
    h
}

fn default_config() -> ReconcileConfig {
    ReconcileConfig {
        iblt_cells: 128,
        iblt_hashes: 3,
        max_retries: 2,
        retry_scale_factor: 2,
    }
}

fn tiny_config() -> ReconcileConfig {
    ReconcileConfig {
        iblt_cells: 4,
        iblt_hashes: 3,
        max_retries: 0,
        retry_scale_factor: 2,
    }
}

// =========================================================================
// Section 1: ReconcileObjectType — Display and ordering
// =========================================================================

#[test]
fn reconcile_object_type_display_all_variants() {
    assert_eq!(
        ReconcileObjectType::RevocationEvent.to_string(),
        "revocation_event"
    );
    assert_eq!(
        ReconcileObjectType::CheckpointMarker.to_string(),
        "checkpoint_marker"
    );
    assert_eq!(
        ReconcileObjectType::EvidenceEntry.to_string(),
        "evidence_entry"
    );
}

#[test]
fn reconcile_object_type_ordering_is_deterministic() {
    let mut types = [
        ReconcileObjectType::EvidenceEntry,
        ReconcileObjectType::RevocationEvent,
        ReconcileObjectType::CheckpointMarker,
    ];
    types.sort();
    // Derive(Ord) on enums uses discriminant order
    assert_eq!(types[0], ReconcileObjectType::RevocationEvent);
    assert_eq!(types[1], ReconcileObjectType::CheckpointMarker);
    assert_eq!(types[2], ReconcileObjectType::EvidenceEntry);
}

#[test]
fn reconcile_object_type_clone_and_copy() {
    let t = ReconcileObjectType::CheckpointMarker;
    let t2 = t; // Copy
    let t3 = t;
    assert_eq!(t, t2);
    assert_eq!(t, t3);
}

#[test]
fn reconcile_object_type_serde_round_trip() {
    let variants = [
        ReconcileObjectType::RevocationEvent,
        ReconcileObjectType::CheckpointMarker,
        ReconcileObjectType::EvidenceEntry,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize");
        let restored: ReconcileObjectType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*v, restored);
    }
}

#[test]
fn reconcile_object_type_can_be_btreeset_key() {
    let mut set = BTreeSet::new();
    set.insert(ReconcileObjectType::RevocationEvent);
    set.insert(ReconcileObjectType::CheckpointMarker);
    set.insert(ReconcileObjectType::EvidenceEntry);
    assert_eq!(set.len(), 3);
    // Inserting duplicate does not grow the set
    set.insert(ReconcileObjectType::EvidenceEntry);
    assert_eq!(set.len(), 3);
}

// =========================================================================
// Section 2: ObjectId — construction, Display, serde
// =========================================================================

#[test]
fn object_id_display_format() {
    let id = ObjectId {
        content_hash: ContentHash::compute(b"hello"),
        object_type: ReconcileObjectType::RevocationEvent,
        epoch: epoch(),
    };
    let display = id.to_string();
    assert!(display.starts_with("revocation_event:"));
    assert!(display.contains("@"));
}

#[test]
fn object_id_equality() {
    let id1 = ObjectId {
        content_hash: ContentHash::compute(b"test"),
        object_type: ReconcileObjectType::EvidenceEntry,
        epoch: epoch(),
    };
    let id2 = id1.clone();
    assert_eq!(id1, id2);
}

#[test]
fn object_id_inequality_on_type() {
    let id1 = ObjectId {
        content_hash: ContentHash::compute(b"test"),
        object_type: ReconcileObjectType::EvidenceEntry,
        epoch: epoch(),
    };
    let id2 = ObjectId {
        content_hash: ContentHash::compute(b"test"),
        object_type: ReconcileObjectType::CheckpointMarker,
        epoch: epoch(),
    };
    assert_ne!(id1, id2);
}

#[test]
fn object_id_inequality_on_epoch() {
    let id1 = ObjectId {
        content_hash: ContentHash::compute(b"test"),
        object_type: ReconcileObjectType::EvidenceEntry,
        epoch: SecurityEpoch::from_raw(1),
    };
    let id2 = ObjectId {
        content_hash: ContentHash::compute(b"test"),
        object_type: ReconcileObjectType::EvidenceEntry,
        epoch: SecurityEpoch::from_raw(2),
    };
    assert_ne!(id1, id2);
}

#[test]
fn object_id_serde_round_trip() {
    let id = ObjectId {
        content_hash: ContentHash::compute(b"serde-test"),
        object_type: ReconcileObjectType::CheckpointMarker,
        epoch: SecurityEpoch::from_raw(42),
    };
    let json = serde_json::to_string(&id).expect("serialize");
    let restored: ObjectId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(id, restored);
}

#[test]
fn object_id_ordering_deterministic() {
    let id1 = ObjectId {
        content_hash: ContentHash::compute(b"aaa"),
        object_type: ReconcileObjectType::RevocationEvent,
        epoch: epoch(),
    };
    let id2 = ObjectId {
        content_hash: ContentHash::compute(b"bbb"),
        object_type: ReconcileObjectType::RevocationEvent,
        epoch: epoch(),
    };
    let mut ids = vec![id2.clone(), id1.clone()];
    ids.sort();
    // Deterministic ordering from Ord derive
    let ids2 = {
        let mut v = vec![id2, id1];
        v.sort();
        v
    };
    assert_eq!(ids, ids2);
}

// =========================================================================
// Section 3: IbltCell — defaults
// =========================================================================

#[test]
fn iblt_cell_default_is_zeroed() {
    let cell = IbltCell::default();
    assert_eq!(cell.count, 0);
    assert_eq!(cell.key_hash_xor, [0u8; 32]);
    assert_eq!(cell.checksum_xor, 0);
}

#[test]
fn iblt_cell_serde_round_trip() {
    let cell = IbltCell {
        count: -3,
        key_hash_xor: [0xAB; 32],
        checksum_xor: 0xDEAD_BEEF,
    };
    let json = serde_json::to_string(&cell).expect("serialize");
    let restored: IbltCell = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cell, restored);
}

// =========================================================================
// Section 4: Iblt — construction, insert, remove, subtract, peel
// =========================================================================

#[test]
fn iblt_new_has_correct_dimensions() {
    let iblt = Iblt::new(256, 4);
    assert_eq!(iblt.num_cells(), 256);
    assert_eq!(iblt.num_hashes, 4);
    assert_eq!(iblt.cells.len(), 256);
}

#[test]
fn iblt_empty_peels_to_empty() {
    let iblt = Iblt::new(64, 3);
    let (pos, neg) = iblt.peel().expect("empty peel");
    assert!(pos.is_empty());
    assert!(neg.is_empty());
}

#[test]
fn iblt_single_insert_peel() {
    let mut iblt = Iblt::new(64, 3);
    let h = make_hash(42);
    iblt.insert(&h);

    let empty = Iblt::new(64, 3);
    let diff = iblt.subtract(&empty).unwrap();
    let (pos, neg) = diff.peel().unwrap();
    assert_eq!(pos, vec![h]);
    assert!(neg.is_empty());
}

#[test]
fn iblt_insert_remove_identity() {
    let mut iblt = Iblt::new(64, 3);
    let h1 = make_hash(1);
    let h2 = make_hash(2);
    iblt.insert(&h1);
    iblt.insert(&h2);
    iblt.remove(&h1);
    iblt.remove(&h2);
    assert_eq!(iblt, Iblt::new(64, 3));
}

#[test]
fn iblt_subtract_identical_is_empty() {
    let mut a = Iblt::new(64, 3);
    let mut b = Iblt::new(64, 3);
    for i in 0..20 {
        let h = make_hash(i);
        a.insert(&h);
        b.insert(&h);
    }
    let diff = a.subtract(&b).unwrap();
    let (pos, neg) = diff.peel().unwrap();
    assert!(pos.is_empty());
    assert!(neg.is_empty());
}

#[test]
fn iblt_subtract_size_mismatch_error() {
    let a = Iblt::new(64, 3);
    let b = Iblt::new(128, 3);
    let err = a.subtract(&b).unwrap_err();
    match err {
        ReconcileError::IbltSizeMismatch {
            local_cells,
            remote_cells,
        } => {
            assert_eq!(local_cells, 64);
            assert_eq!(remote_cells, 128);
        }
        other => panic!("expected IbltSizeMismatch, got {other:?}"),
    }
}

#[test]
fn iblt_subtract_hash_count_mismatch_error() {
    let a = Iblt::new(64, 3);
    let b = Iblt::new(64, 5);
    let err = a.subtract(&b).unwrap_err();
    assert!(matches!(err, ReconcileError::IbltSizeMismatch { .. }));
}

#[test]
fn iblt_symmetric_difference_multiple_elements() {
    let mut a = Iblt::new(256, 3);
    let mut b = Iblt::new(256, 3);

    let shared: Vec<[u8; 32]> = (0..15).map(make_hash).collect();
    let a_only: Vec<[u8; 32]> = (50..55).map(make_hash).collect();
    let b_only: Vec<[u8; 32]> = (100..103).map(make_hash).collect();

    for h in &shared {
        a.insert(h);
        b.insert(h);
    }
    for h in &a_only {
        a.insert(h);
    }
    for h in &b_only {
        b.insert(h);
    }

    let diff = a.subtract(&b).unwrap();
    let (pos, neg) = diff.peel().unwrap();

    let pos_set: BTreeSet<_> = pos.into_iter().collect();
    let neg_set: BTreeSet<_> = neg.into_iter().collect();
    let a_only_set: BTreeSet<_> = a_only.into_iter().collect();
    let b_only_set: BTreeSet<_> = b_only.into_iter().collect();

    assert_eq!(pos_set, a_only_set);
    assert_eq!(neg_set, b_only_set);
}

#[test]
fn iblt_peel_fails_when_overloaded() {
    let mut a = Iblt::new(4, 3);
    let mut b = Iblt::new(4, 3);
    for i in 0u16..200 {
        a.insert(&make_wide_hash(i, 0xAA));
    }
    for i in 200u16..400 {
        b.insert(&make_wide_hash(i, 0xBB));
    }
    let diff = a.subtract(&b).unwrap();
    let err = diff.peel().unwrap_err();
    match err {
        ReconcileError::PeelFailed { remaining_cells } => {
            assert!(remaining_cells > 0);
        }
        other => panic!("expected PeelFailed, got {other:?}"),
    }
}

#[test]
fn iblt_serde_round_trip() {
    let mut iblt = Iblt::new(16, 3);
    iblt.insert(&make_hash(1));
    iblt.insert(&make_hash(2));
    let json = serde_json::to_string(&iblt).expect("serialize");
    let restored: Iblt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(iblt, restored);
}

#[test]
fn iblt_peel_output_is_sorted() {
    let mut a = Iblt::new(128, 3);
    let empty = Iblt::new(128, 3);
    // Insert several elements in arbitrary order
    for i in [20u8, 5, 15, 10, 25] {
        a.insert(&make_hash(i));
    }
    let diff = a.subtract(&empty).unwrap();
    let (pos, _neg) = diff.peel().unwrap();
    let sorted = {
        let mut v = pos.clone();
        v.sort();
        v
    };
    assert_eq!(pos, sorted, "peel output should be sorted");
}

// =========================================================================
// Section 5: ReconcileResult — construction and serde
// =========================================================================

#[test]
fn reconcile_result_serde_round_trip() {
    let result = ReconcileResult {
        objects_to_fetch: vec![make_hash(1), make_hash(2)],
        objects_to_send: vec![make_hash(3)],
        fallback_triggered: false,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: ReconcileResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

#[test]
fn reconcile_result_empty_is_valid() {
    let result = ReconcileResult {
        objects_to_fetch: Vec::new(),
        objects_to_send: Vec::new(),
        fallback_triggered: true,
    };
    assert!(result.objects_to_fetch.is_empty());
    assert!(result.objects_to_send.is_empty());
    assert!(result.fallback_triggered);
}

// =========================================================================
// Section 6: ReconcileEvent — serde
// =========================================================================

#[test]
fn reconcile_event_serde_round_trip() {
    let event = ReconcileEvent {
        reconciliation_id: "r-42".to_string(),
        peer: "node-7".to_string(),
        objects_sent: 10,
        objects_received: 5,
        objects_conflicting: 2,
        epoch_id: 3,
        trace_id: "trace-abc".to_string(),
        event: "reconcile_success".to_string(),
        fallback_triggered: false,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: ReconcileEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

// =========================================================================
// Section 7: ReconcileError — Display and serde
// =========================================================================

#[test]
fn reconcile_error_display_iblt_size_mismatch() {
    let err = ReconcileError::IbltSizeMismatch {
        local_cells: 64,
        remote_cells: 128,
    };
    let s = err.to_string();
    assert!(s.contains("mismatch"));
    assert!(s.contains("64"));
    assert!(s.contains("128"));
}

#[test]
fn reconcile_error_display_peel_failed() {
    let err = ReconcileError::PeelFailed {
        remaining_cells: 10,
    };
    let s = err.to_string();
    assert!(s.contains("peel"));
    assert!(s.contains("10"));
}

#[test]
fn reconcile_error_display_epoch_mismatch() {
    let err = ReconcileError::EpochMismatch {
        local_epoch: SecurityEpoch::from_raw(1),
        remote_epoch: SecurityEpoch::from_raw(2),
    };
    let s = err.to_string();
    assert!(s.contains("epoch"));
    assert!(s.contains("mismatch"));
}

#[test]
fn reconcile_error_display_verification_failed() {
    let err = ReconcileError::VerificationFailed {
        object_hash: "abc".to_string(),
        reason: "bad signature".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("abc"));
    assert!(s.contains("bad signature"));
}

#[test]
fn reconcile_error_display_empty_object_set() {
    let err = ReconcileError::EmptyObjectSet;
    let s = err.to_string();
    assert!(s.contains("empty"));
}

#[test]
fn reconcile_error_is_std_error() {
    let err = ReconcileError::EmptyObjectSet;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn reconcile_error_serde_round_trip_all_variants() {
    let errors = vec![
        ReconcileError::IbltSizeMismatch {
            local_cells: 64,
            remote_cells: 256,
        },
        ReconcileError::PeelFailed { remaining_cells: 7 },
        ReconcileError::EpochMismatch {
            local_epoch: SecurityEpoch::from_raw(1),
            remote_epoch: SecurityEpoch::from_raw(99),
        },
        ReconcileError::VerificationFailed {
            object_hash: "deadbeef".to_string(),
            reason: "corrupted".to_string(),
        },
        ReconcileError::EmptyObjectSet,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: ReconcileError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// =========================================================================
// Section 8: ReconcileConfig — defaults and serde
// =========================================================================

#[test]
fn reconcile_config_default_values() {
    let config = ReconcileConfig::default();
    assert_eq!(config.iblt_cells, 256);
    assert_eq!(config.iblt_hashes, 3);
    assert_eq!(config.max_retries, 2);
    assert_eq!(config.retry_scale_factor, 2);
}

#[test]
fn reconcile_config_serde_round_trip() {
    let config = ReconcileConfig {
        iblt_cells: 512,
        iblt_hashes: 5,
        max_retries: 4,
        retry_scale_factor: 3,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let restored: ReconcileConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, restored);
}

// =========================================================================
// Section 9: ReconcileSession — reconcile, fallback, exact_difference
// =========================================================================

#[test]
fn session_reconcile_identical_sets_no_diff() {
    let mut session = ReconcileSession::new(epoch(), default_config());
    let objects: BTreeSet<[u8; 32]> = (0..30).map(make_hash).collect();
    let remote_iblt = session.build_iblt(&objects);
    let result = session
        .reconcile(&objects, &remote_iblt, "peer-1", "t1")
        .unwrap();
    assert!(!result.fallback_triggered);
    assert!(result.objects_to_send.is_empty());
    assert!(result.objects_to_fetch.is_empty());
}

#[test]
fn session_reconcile_small_difference() {
    let mut session = ReconcileSession::new(epoch(), default_config());
    let mut local: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut remote: BTreeSet<[u8; 32]> = BTreeSet::new();
    for i in 0..20 {
        let h = make_hash(i);
        local.insert(h);
        remote.insert(h);
    }
    let local_only = make_hash(100);
    local.insert(local_only);
    let remote_only = make_hash(200);
    remote.insert(remote_only);

    let remote_iblt = session.build_iblt(&remote);
    let result = session
        .reconcile(&local, &remote_iblt, "peer-1", "t1")
        .unwrap();
    assert!(!result.fallback_triggered);
    assert!(result.objects_to_send.contains(&local_only));
    assert!(result.objects_to_fetch.contains(&remote_only));
}

#[test]
fn session_reconcile_triggers_fallback_on_overloaded_iblt() {
    let mut session = ReconcileSession::new(epoch(), tiny_config());
    let local: BTreeSet<[u8; 32]> = (0u16..200).map(|i| make_wide_hash(i, 0xAA)).collect();
    let remote: BTreeSet<[u8; 32]> = (200u16..400).map(|i| make_wide_hash(i, 0xBB)).collect();
    let remote_iblt = session.build_iblt(&remote);
    let result = session
        .reconcile(&local, &remote_iblt, "peer-1", "t1")
        .unwrap();
    assert!(result.fallback_triggered);
}

#[test]
fn session_emits_success_event() {
    let mut session = ReconcileSession::new(epoch(), default_config());
    let objects: BTreeSet<[u8; 32]> = (0..10).map(make_hash).collect();
    let remote_iblt = session.build_iblt(&objects);
    session
        .reconcile(&objects, &remote_iblt, "peer-1", "t1")
        .unwrap();
    let events = session.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "reconcile_success");
    assert_eq!(events[0].peer, "peer-1");
    assert!(!events[0].fallback_triggered);
}

#[test]
fn session_emits_fallback_event() {
    let mut session = ReconcileSession::new(epoch(), tiny_config());
    let local: BTreeSet<[u8; 32]> = (0u16..200).map(|i| make_wide_hash(i, 0xAA)).collect();
    let remote: BTreeSet<[u8; 32]> = (200u16..400).map(|i| make_wide_hash(i, 0xBB)).collect();
    let remote_iblt = session.build_iblt(&remote);
    session
        .reconcile(&local, &remote_iblt, "peer-1", "t1")
        .unwrap();
    let events = session.drain_events();
    let fallback = events.iter().find(|e| e.event == "reconcile_fallback");
    assert!(fallback.is_some());
    assert!(fallback.unwrap().fallback_triggered);
}

#[test]
fn session_event_counts_track_success() {
    let mut session = ReconcileSession::new(epoch(), default_config());
    let objects: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
    let remote_iblt = session.build_iblt(&objects);
    session
        .reconcile(&objects, &remote_iblt, "peer-1", "t1")
        .unwrap();
    session
        .reconcile(&objects, &remote_iblt, "peer-2", "t2")
        .unwrap();
    assert_eq!(session.event_counts().get("reconcile_success"), Some(&2));
}

#[test]
fn session_drain_events_clears() {
    let mut session = ReconcileSession::new(epoch(), default_config());
    let objects: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
    let remote_iblt = session.build_iblt(&objects);
    session
        .reconcile(&objects, &remote_iblt, "peer-1", "t1")
        .unwrap();
    assert!(!session.drain_events().is_empty());
    assert!(session.drain_events().is_empty());
}

#[test]
fn session_epoch_accessor() {
    let e = SecurityEpoch::from_raw(99);
    let session = ReconcileSession::new(e, ReconcileConfig::default());
    assert_eq!(session.epoch(), e);
}

#[test]
fn session_exact_difference_no_overlap() {
    let local: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (5..10).map(make_hash).collect();
    let (local_only, remote_only) = ReconcileSession::exact_difference(&local, &remote);
    assert_eq!(local_only.len(), 5);
    assert_eq!(remote_only.len(), 5);
}

#[test]
fn session_exact_difference_complete_overlap() {
    let objects: BTreeSet<[u8; 32]> = (0..10).map(make_hash).collect();
    let (local_only, remote_only) = ReconcileSession::exact_difference(&objects, &objects);
    assert!(local_only.is_empty());
    assert!(remote_only.is_empty());
}

#[test]
fn session_exact_difference_empty_sets() {
    let empty: BTreeSet<[u8; 32]> = BTreeSet::new();
    let (l, r) = ReconcileSession::exact_difference(&empty, &empty);
    assert!(l.is_empty());
    assert!(r.is_empty());
}

#[test]
fn session_build_iblt_deterministic() {
    let session = ReconcileSession::new(epoch(), default_config());
    let objects: BTreeSet<[u8; 32]> = (0..20).map(make_hash).collect();
    let iblt1 = session.build_iblt(&objects);
    let iblt2 = session.build_iblt(&objects);
    assert_eq!(iblt1, iblt2);
}

// =========================================================================
// Section 10: FallbackTrigger — Display, serde
// =========================================================================

#[test]
fn fallback_trigger_display_peel_failed() {
    let t = FallbackTrigger::PeelFailed { remaining_cells: 5 };
    let s = t.to_string();
    assert!(s.contains("peel_failed"));
    assert!(s.contains("5"));
}

#[test]
fn fallback_trigger_display_verification_failed() {
    let t = FallbackTrigger::VerificationFailed {
        object_hash: "deadbeef".to_string(),
        reason: "bad hash".to_string(),
    };
    let s = t.to_string();
    assert!(s.contains("verification_failed"));
    assert!(s.contains("deadbeef"));
    assert!(s.contains("bad hash"));
}

#[test]
fn fallback_trigger_display_timeout() {
    let t = FallbackTrigger::Timeout {
        elapsed_ms: 5000,
        slo_ms: 3000,
    };
    let s = t.to_string();
    assert!(s.contains("timeout"));
    assert!(s.contains("5000"));
    assert!(s.contains("3000"));
}

#[test]
fn fallback_trigger_display_mmr_consistency() {
    let t = FallbackTrigger::MmrConsistencyFailure {
        details: "root divergence".to_string(),
    };
    let s = t.to_string();
    assert!(s.contains("mmr_consistency"));
    assert!(s.contains("root divergence"));
}

#[test]
fn fallback_trigger_serde_round_trip_all_variants() {
    let triggers = vec![
        FallbackTrigger::PeelFailed { remaining_cells: 5 },
        FallbackTrigger::VerificationFailed {
            object_hash: "abc123".to_string(),
            reason: "hash mismatch".to_string(),
        },
        FallbackTrigger::Timeout {
            elapsed_ms: 5000,
            slo_ms: 3000,
        },
        FallbackTrigger::MmrConsistencyFailure {
            details: "root divergence".to_string(),
        },
    ];
    for t in &triggers {
        let json = serde_json::to_string(t).expect("serialize");
        let restored: FallbackTrigger = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*t, restored);
    }
}

// =========================================================================
// Section 11: FallbackEvidence — serde
// =========================================================================

#[test]
fn fallback_evidence_serde_round_trip() {
    let ev = FallbackEvidence {
        fallback_id: "fb-test-1".to_string(),
        trigger: FallbackTrigger::Timeout {
            elapsed_ms: 1000,
            slo_ms: 500,
        },
        original_reconciliation_id: "r1:peer-1".to_string(),
        scope_size: 200,
        differences_found: 20,
        objects_transferred: 20,
        duration_ms: 0,
        epoch_id: 1,
        trace_id: "trace-1".to_string(),
    };
    let json = serde_json::to_string(&ev).expect("serialize");
    let restored: FallbackEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ev, restored);
}

// =========================================================================
// Section 12: FallbackConfig — defaults and serde
// =========================================================================

#[test]
fn fallback_config_default_values() {
    let config = FallbackConfig::default();
    assert_eq!(config.max_fallback_rate_pct, 5);
    assert_eq!(config.monitoring_window, 100);
}

#[test]
fn fallback_config_serde_round_trip() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 10,
        monitoring_window: 50,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let restored: FallbackConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, restored);
}

// =========================================================================
// Section 13: FallbackProtocol — execute, execute_incremental, events
// =========================================================================

#[test]
fn fallback_protocol_execute_computes_difference() {
    let mut fb = FallbackProtocol::new(epoch());
    let mut local: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut remote: BTreeSet<[u8; 32]> = BTreeSet::new();
    for i in 0..20 {
        let h = make_hash(i);
        local.insert(h);
        remote.insert(h);
    }
    let l_only = make_hash(100);
    local.insert(l_only);
    let r_only = make_hash(200);
    remote.insert(r_only);

    let result = fb.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 5 },
        reconciliation_id: "recon-1",
        peer: "peer-1",
        trace_id: "t1",
    });

    assert_eq!(result.objects_to_send.len(), 1);
    assert_eq!(result.objects_to_fetch.len(), 1);
    assert!(result.objects_to_send.contains(&l_only));
    assert!(result.objects_to_fetch.contains(&r_only));
    assert_eq!(result.evidence.differences_found, 2);
    assert_eq!(result.evidence.scope_size, 21);
}

#[test]
fn fallback_protocol_identical_sets_no_diff() {
    let mut fb = FallbackProtocol::new(epoch());
    let objects: BTreeSet<[u8; 32]> = (0..30).map(make_hash).collect();
    let result = fb.execute(FallbackRequest {
        local_hashes: &objects,
        remote_hashes: &objects,
        trigger: FallbackTrigger::Timeout {
            elapsed_ms: 5000,
            slo_ms: 3000,
        },
        reconciliation_id: "r1",
        peer: "peer-1",
        trace_id: "t1",
    });
    assert!(result.objects_to_send.is_empty());
    assert!(result.objects_to_fetch.is_empty());
    assert_eq!(result.evidence.differences_found, 0);
}

#[test]
fn fallback_protocol_perspectives_are_symmetric() {
    let local: BTreeSet<[u8; 32]> = (0..15).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (10..25).map(make_hash).collect();

    let mut fb_a = FallbackProtocol::new(epoch());
    let result_a = fb_a.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
        reconciliation_id: "r1",
        peer: "peer-b",
        trace_id: "t1",
    });

    let mut fb_b = FallbackProtocol::new(epoch());
    let result_b = fb_b.execute(FallbackRequest {
        local_hashes: &remote,
        remote_hashes: &local,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
        reconciliation_id: "r1",
        peer: "peer-a",
        trace_id: "t1",
    });

    assert_eq!(result_a.objects_to_send, result_b.objects_to_fetch);
    assert_eq!(result_a.objects_to_fetch, result_b.objects_to_send);
}

#[test]
fn fallback_protocol_emits_evidence() {
    let mut fb = FallbackProtocol::new(epoch());
    let local: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (3..8).map(make_hash).collect();

    fb.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::MmrConsistencyFailure {
            details: "root mismatch".to_string(),
        },
        reconciliation_id: "r1",
        peer: "peer-1",
        trace_id: "t1",
    });

    let events = fb.drain_events();
    assert_eq!(events.len(), 1);
    assert!(events[0].fallback_id.starts_with("fb-"));
    assert_eq!(events[0].epoch_id, 1);
    assert_eq!(fb.event_counts().get("fallback_executed"), Some(&1));
}

#[test]
fn fallback_protocol_drain_events_clears() {
    let mut fb = FallbackProtocol::new(epoch());
    let objects: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();

    fb.execute(FallbackRequest {
        local_hashes: &objects,
        remote_hashes: &objects,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r1",
        peer: "peer-1",
        trace_id: "t1",
    });
    assert!(!fb.drain_events().is_empty());
    assert!(fb.drain_events().is_empty());
}

#[test]
fn fallback_protocol_epoch_accessor() {
    let e = SecurityEpoch::from_raw(77);
    let fb = FallbackProtocol::new(e);
    assert_eq!(fb.epoch(), e);
}

#[test]
fn fallback_protocol_seq_increments() {
    let mut fb = FallbackProtocol::new(epoch());
    let objects: BTreeSet<[u8; 32]> = (0..3).map(make_hash).collect();

    let r1 = fb.execute(FallbackRequest {
        local_hashes: &objects,
        remote_hashes: &objects,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r1",
        peer: "peer-1",
        trace_id: "t1",
    });
    let r2 = fb.execute(FallbackRequest {
        local_hashes: &objects,
        remote_hashes: &objects,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r2",
        peer: "peer-1",
        trace_id: "t2",
    });
    // Sequence numbers should differ
    assert_ne!(r1.evidence.fallback_id, r2.evidence.fallback_id);
    assert_eq!(fb.event_counts().get("fallback_executed"), Some(&2));
}

#[test]
fn fallback_agrees_with_iblt_for_small_diff() {
    let mut session = ReconcileSession::new(epoch(), default_config());
    let mut fb = FallbackProtocol::new(epoch());

    let mut local: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut remote: BTreeSet<[u8; 32]> = BTreeSet::new();
    for i in 0..20 {
        let h = make_hash(i);
        local.insert(h);
        remote.insert(h);
    }
    local.insert(make_hash(100));
    remote.insert(make_hash(200));

    let remote_iblt = session.build_iblt(&remote);
    let iblt_result = session
        .reconcile(&local, &remote_iblt, "peer-1", "t1")
        .unwrap();

    let fb_result = fb.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r1",
        peer: "peer-1",
        trace_id: "t1",
    });

    let iblt_send: BTreeSet<_> = iblt_result.objects_to_send.into_iter().collect();
    let iblt_fetch: BTreeSet<_> = iblt_result.objects_to_fetch.into_iter().collect();
    let fb_send: BTreeSet<_> = fb_result.objects_to_send.into_iter().collect();
    let fb_fetch: BTreeSet<_> = fb_result.objects_to_fetch.into_iter().collect();

    assert_eq!(iblt_send, fb_send);
    assert_eq!(iblt_fetch, fb_fetch);
}

// =========================================================================
// Section 14: FallbackProtocol — execute_incremental
// =========================================================================

#[test]
fn incremental_fallback_matches_full_result() {
    let local: BTreeSet<[u8; 32]> = (0..50).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (25..75).map(make_hash).collect();

    let mut fb_full = FallbackProtocol::new(epoch());
    let full = fb_full.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
        reconciliation_id: "r1",
        peer: "peer-1",
        trace_id: "t1",
    });

    let mut fb_incr = FallbackProtocol::new(epoch());
    let incr = fb_incr.execute_incremental(
        FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
            reconciliation_id: "r1",
            peer: "peer-1",
            trace_id: "t1",
        },
        4,
    );

    assert_eq!(
        full.objects_to_send.iter().collect::<BTreeSet<_>>(),
        incr.objects_to_send.iter().collect::<BTreeSet<_>>()
    );
    assert_eq!(
        full.objects_to_fetch.iter().collect::<BTreeSet<_>>(),
        incr.objects_to_fetch.iter().collect::<BTreeSet<_>>()
    );
}

#[test]
fn incremental_fallback_skips_matching_ranges() {
    let mut fb = FallbackProtocol::new(epoch());
    let objects: BTreeSet<[u8; 32]> = (0..30).map(make_hash).collect();

    fb.execute_incremental(
        FallbackRequest {
            local_hashes: &objects,
            remote_hashes: &objects,
            trigger: FallbackTrigger::Timeout {
                elapsed_ms: 5000,
                slo_ms: 3000,
            },
            reconciliation_id: "r1",
            peer: "peer-1",
            trace_id: "t1",
        },
        4,
    );

    let skipped = fb
        .event_counts()
        .get("fallback_ranges_skipped")
        .copied()
        .unwrap_or(0);
    assert!(skipped > 0);
}

#[test]
fn incremental_fallback_with_one_range_equals_full() {
    let local: BTreeSet<[u8; 32]> = (0..10).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (5..15).map(make_hash).collect();

    let mut fb = FallbackProtocol::new(epoch());
    let result = fb.execute_incremental(
        FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
            reconciliation_id: "r1",
            peer: "peer-1",
            trace_id: "t1",
        },
        1,
    );

    // With 1 range, it delegates to execute() which does full diff
    let (exact_send, exact_fetch) = ReconcileSession::exact_difference(&local, &remote);
    assert_eq!(
        result.objects_to_send.iter().collect::<BTreeSet<_>>(),
        exact_send.iter().collect::<BTreeSet<_>>()
    );
    assert_eq!(
        result.objects_to_fetch.iter().collect::<BTreeSet<_>>(),
        exact_fetch.iter().collect::<BTreeSet<_>>()
    );
}

// =========================================================================
// Section 15: FallbackRateAlert — serde
// =========================================================================

#[test]
fn fallback_rate_alert_serde_round_trip() {
    let alert = FallbackRateAlert {
        rate_pct: 15,
        threshold_pct: 5,
        fallbacks_in_window: 3,
        total_in_window: 20,
        epoch_id: 1,
    };
    let json = serde_json::to_string(&alert).expect("serialize");
    let restored: FallbackRateAlert = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(alert, restored);
}

// =========================================================================
// Section 16: FallbackRateMonitor — record, alerts, sliding window
// =========================================================================

#[test]
fn rate_monitor_empty_window_zero_rate() {
    let config = FallbackConfig::default();
    let monitor = FallbackRateMonitor::new(epoch(), config);
    assert_eq!(monitor.current_rate_pct(), 0);
    assert!(!monitor.is_rate_exceeded());
    assert_eq!(monitor.total_recorded(), 0);
}

#[test]
fn rate_monitor_no_alert_under_threshold() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 10,
        monitoring_window: 20,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(), config);
    for _ in 0..19 {
        assert!(monitor.record(false).is_none());
    }
    // 1 fallback out of 20 = 5%, which is <= 10%
    assert!(monitor.record(true).is_none());
    assert!(!monitor.is_rate_exceeded());
}

#[test]
fn rate_monitor_alerts_over_threshold() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 5,
        monitoring_window: 10,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(), config);
    for _ in 0..9 {
        monitor.record(false);
    }
    let alert = monitor.record(true);
    assert!(alert.is_some());
    let alert = alert.unwrap();
    assert_eq!(alert.threshold_pct, 5);
    assert!(alert.rate_pct > 5);
    assert!(monitor.is_rate_exceeded());
}

#[test]
fn rate_monitor_sliding_window_evicts_old() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 5,
        monitoring_window: 10,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(), config);

    // Put fallback in first slot
    monitor.record(true);
    for _ in 0..9 {
        monitor.record(false);
    }
    assert!(monitor.is_rate_exceeded());

    // Overwrite the fallback slot with success
    monitor.record(false);
    assert!(!monitor.is_rate_exceeded());
}

#[test]
fn rate_monitor_drain_alerts_clears() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 0,
        monitoring_window: 5,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(), config);
    monitor.record(true);
    monitor.record(true);
    let alerts = monitor.drain_alerts();
    assert_eq!(alerts.len(), 2);
    assert!(monitor.drain_alerts().is_empty());
}

#[test]
fn rate_monitor_total_recorded_increments() {
    let config = FallbackConfig::default();
    let mut monitor = FallbackRateMonitor::new(epoch(), config);
    monitor.record(false);
    monitor.record(true);
    monitor.record(false);
    assert_eq!(monitor.total_recorded(), 3);
}

#[test]
fn rate_monitor_all_fallbacks_exceeds_any_threshold() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 50,
        monitoring_window: 10,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(), config);
    for _ in 0..10 {
        monitor.record(true);
    }
    assert!(monitor.is_rate_exceeded());
    assert_eq!(monitor.current_rate_pct(), 100);
}

// =========================================================================
// Section 17: Deterministic replay
// =========================================================================

#[test]
fn deterministic_reconciliation_replay() {
    let run = || -> ReconcileResult {
        let mut session = ReconcileSession::new(SecurityEpoch::from_raw(1), default_config());
        let mut local: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut remote: BTreeSet<[u8; 32]> = BTreeSet::new();
        for i in 0..20 {
            let h = make_hash(i);
            local.insert(h);
            remote.insert(h);
        }
        local.insert(make_hash(100));
        remote.insert(make_hash(200));
        let remote_iblt = session.build_iblt(&remote);
        session
            .reconcile(&local, &remote_iblt, "peer-1", "t1")
            .unwrap()
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1, r2);
}

#[test]
fn deterministic_fallback_replay() {
    let run = || -> FallbackResult {
        let mut fb = FallbackProtocol::new(SecurityEpoch::from_raw(1));
        let local: BTreeSet<[u8; 32]> = (0..15).map(make_hash).collect();
        let remote: BTreeSet<[u8; 32]> = (10..25).map(make_hash).collect();
        fb.execute(FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
            reconciliation_id: "r1",
            peer: "peer-1",
            trace_id: "t1",
        })
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1, r2);
}

#[test]
fn deterministic_incremental_fallback_replay() {
    let run = || -> FallbackResult {
        let mut fb = FallbackProtocol::new(SecurityEpoch::from_raw(1));
        let local: BTreeSet<[u8; 32]> = (0..50).map(make_hash).collect();
        let remote: BTreeSet<[u8; 32]> = (25..75).map(make_hash).collect();
        fb.execute_incremental(
            FallbackRequest {
                local_hashes: &local,
                remote_hashes: &remote,
                trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
                reconciliation_id: "r1",
                peer: "peer-1",
                trace_id: "t1",
            },
            8,
        )
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1, r2);
}

// =========================================================================
// Section 18: FallbackResult — serde
// =========================================================================

#[test]
fn fallback_result_serde_round_trip() {
    let result = FallbackResult {
        objects_to_fetch: vec![make_hash(1)],
        objects_to_send: vec![make_hash(2), make_hash(3)],
        evidence: FallbackEvidence {
            fallback_id: "fb-t1-1".to_string(),
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 5 },
            original_reconciliation_id: "r1:peer-1".to_string(),
            scope_size: 100,
            differences_found: 3,
            objects_transferred: 3,
            duration_ms: 0,
            epoch_id: 1,
            trace_id: "t1".to_string(),
        },
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: FallbackResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

// =========================================================================
// Section 19: SymmetricDiff type alias validation
// =========================================================================

#[test]
fn symmetric_diff_type_alias_works() {
    let diff: SymmetricDiff = (vec![[0u8; 32]], vec![[1u8; 32]]);
    assert_eq!(diff.0.len(), 1);
    assert_eq!(diff.1.len(), 1);
}

// =========================================================================
// Section 20: Edge cases and stress
// =========================================================================

#[test]
fn iblt_multiple_remove_then_insert_net_zero() {
    let mut iblt = Iblt::new(64, 3);
    let h = make_hash(99);
    // Double remove then double insert should yield net zero
    iblt.remove(&h);
    iblt.remove(&h);
    iblt.insert(&h);
    iblt.insert(&h);
    assert_eq!(iblt, Iblt::new(64, 3));
}

#[test]
fn session_multiple_peers_tracked_independently() {
    let mut session = ReconcileSession::new(epoch(), default_config());
    let objects: BTreeSet<[u8; 32]> = (0..10).map(make_hash).collect();
    let remote_iblt = session.build_iblt(&objects);

    session
        .reconcile(&objects, &remote_iblt, "peer-A", "t1")
        .unwrap();
    session
        .reconcile(&objects, &remote_iblt, "peer-B", "t2")
        .unwrap();

    let events = session.drain_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].peer, "peer-A");
    assert_eq!(events[1].peer, "peer-B");
}

#[test]
fn reconcile_event_reconciliation_id_includes_peer_and_trace() {
    let mut session = ReconcileSession::new(epoch(), default_config());
    let objects: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
    let remote_iblt = session.build_iblt(&objects);
    session
        .reconcile(&objects, &remote_iblt, "node-42", "trace-99")
        .unwrap();
    let events = session.drain_events();
    assert_eq!(events[0].reconciliation_id, "trace-99:node-42");
}

#[test]
fn fallback_evidence_original_reconciliation_id_format() {
    let mut fb = FallbackProtocol::new(epoch());
    let objects: BTreeSet<[u8; 32]> = (0..3).map(make_hash).collect();
    let result = fb.execute(FallbackRequest {
        local_hashes: &objects,
        remote_hashes: &objects,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "recon-42",
        peer: "node-7",
        trace_id: "trace-1",
    });
    assert_eq!(
        result.evidence.original_reconciliation_id,
        "recon-42:node-7"
    );
}
