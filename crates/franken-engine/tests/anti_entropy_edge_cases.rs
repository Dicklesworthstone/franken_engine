//! Edge-case integration tests for `anti_entropy` module.
//!
//! Covers IBLT edge cases, reconciliation session boundaries,
//! fallback protocol edge cases, incremental range splitting,
//! rate monitor boundary arithmetic, serde round-trips, and
//! cross-component integration scenarios.

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
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

/// Deterministic 32-byte hash from a seed byte.
fn make_hash(seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, byte) in h.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8).wrapping_mul(37);
    }
    h
}

/// Hash with first-byte control (for range-splitting tests).
fn make_range_hash(first_byte: u8, seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = first_byte;
    for (i, byte) in h[1..].iter_mut().enumerate() {
        *byte = seed.wrapping_add((i + 1) as u8).wrapping_mul(41);
    }
    h
}

// ===========================================================================
// ReconcileObjectType
// ===========================================================================

#[test]
fn object_type_serde_all_variants() {
    let variants = [
        ReconcileObjectType::RevocationEvent,
        ReconcileObjectType::CheckpointMarker,
        ReconcileObjectType::EvidenceEntry,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: ReconcileObjectType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn object_type_display_all_variants() {
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
fn object_type_ordering_deterministic() {
    let mut types = vec![
        ReconcileObjectType::EvidenceEntry,
        ReconcileObjectType::RevocationEvent,
        ReconcileObjectType::CheckpointMarker,
    ];
    types.sort();
    let sorted_again = {
        let mut copy = types.clone();
        copy.sort();
        copy
    };
    assert_eq!(types, sorted_again);
}

#[test]
fn object_type_hash_deterministic() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(ReconcileObjectType::RevocationEvent);
    set.insert(ReconcileObjectType::CheckpointMarker);
    set.insert(ReconcileObjectType::EvidenceEntry);
    assert_eq!(set.len(), 3);
    // Insert duplicate.
    set.insert(ReconcileObjectType::RevocationEvent);
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// ObjectId
// ===========================================================================

#[test]
fn object_id_serde_roundtrip() {
    let id = ObjectId {
        content_hash: ContentHash::compute(b"hello"),
        object_type: ReconcileObjectType::EvidenceEntry,
        epoch: epoch(42),
    };
    let json = serde_json::to_string(&id).unwrap();
    let restored: ObjectId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, restored);
}

#[test]
fn object_id_display_contains_all_parts() {
    let id = ObjectId {
        content_hash: ContentHash::compute(b"test"),
        object_type: ReconcileObjectType::RevocationEvent,
        epoch: epoch(7),
    };
    let display = id.to_string();
    assert!(display.contains("revocation_event"));
    assert!(display.contains("@"));
}

#[test]
fn object_id_ordering() {
    let id_a = ObjectId {
        content_hash: ContentHash::compute(b"aaa"),
        object_type: ReconcileObjectType::RevocationEvent,
        epoch: epoch(1),
    };
    let id_b = ObjectId {
        content_hash: ContentHash::compute(b"bbb"),
        object_type: ReconcileObjectType::RevocationEvent,
        epoch: epoch(1),
    };
    // Different content hashes produce different ordering.
    assert_ne!(id_a, id_b);
    let mut set = BTreeSet::new();
    set.insert(id_a.clone());
    set.insert(id_b.clone());
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// IbltCell
// ===========================================================================

#[test]
fn iblt_cell_default_is_zero() {
    let cell = IbltCell::default();
    assert_eq!(cell.count, 0);
    assert_eq!(cell.key_hash_xor, [0u8; 32]);
    assert_eq!(cell.checksum_xor, 0);
}

#[test]
fn iblt_cell_serde_roundtrip() {
    let cell = IbltCell {
        count: -3,
        key_hash_xor: make_hash(99),
        checksum_xor: 0xDEAD_BEEF,
    };
    let json = serde_json::to_string(&cell).unwrap();
    let restored: IbltCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, restored);
}

// ===========================================================================
// Iblt — edge cases
// ===========================================================================

#[test]
fn iblt_new_zero_cells() {
    let iblt = Iblt::new(0, 3);
    assert_eq!(iblt.num_cells(), 0);
}

#[test]
fn iblt_new_zero_hashes() {
    let mut iblt = Iblt::new(16, 0);
    // Insert with zero hash functions: no cells are touched.
    iblt.insert(&make_hash(1));
    let empty = Iblt::new(16, 0);
    assert_eq!(iblt, empty);
}

#[test]
fn iblt_single_cell_single_hash() {
    let mut iblt = Iblt::new(1, 1);
    let h = make_hash(42);
    iblt.insert(&h);
    assert_eq!(iblt.cells[0].count, 1);
    iblt.remove(&h);
    assert_eq!(iblt.cells[0].count, 0);
}

#[test]
fn iblt_double_insert_same_key() {
    let mut iblt = Iblt::new(64, 3);
    let h = make_hash(7);
    iblt.insert(&h);
    iblt.insert(&h);

    // Subtract an empty IBLT.
    let empty = Iblt::new(64, 3);
    let diff = iblt.subtract(&empty).unwrap();
    // Peel should fail — count=2 is not peelable directly.
    assert!(diff.peel().is_err());
}

#[test]
fn iblt_remove_without_insert_makes_negative() {
    let mut iblt = Iblt::new(64, 3);
    let h = make_hash(5);
    iblt.remove(&h);

    // Subtract empty → peel should produce negative entry.
    let empty = Iblt::new(64, 3);
    let diff = iblt.subtract(&empty).unwrap();
    let (pos, neg) = diff.peel().unwrap();
    assert!(pos.is_empty());
    assert_eq!(neg.len(), 1);
    assert_eq!(neg[0], h);
}

#[test]
fn iblt_subtract_hash_mismatch() {
    let a = Iblt::new(64, 3);
    let b = Iblt::new(64, 4); // different num_hashes
    let result = a.subtract(&b);
    assert!(matches!(
        result,
        Err(ReconcileError::IbltSizeMismatch { .. })
    ));
}

#[test]
fn iblt_peel_rejects_zero_count_cells_with_residual_xor() {
    let mut local = Iblt::new(64, 3);
    let mut remote = Iblt::new(64, 3);

    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    left[..12].copy_from_slice(&[
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
    ]);
    right[..12].copy_from_slice(&left[..12]);
    left[12] = 0x11;
    right[12] = 0x77;

    local.insert(&left);
    remote.insert(&right);

    let diff = local.subtract(&remote).unwrap();
    let err = diff.peel().unwrap_err();
    assert!(matches!(
        err,
        ReconcileError::PeelFailed { remaining_cells } if remaining_cells > 0
    ));
}

#[test]
fn iblt_peel_empty_iblts() {
    let a = Iblt::new(64, 3);
    let b = Iblt::new(64, 3);
    let diff = a.subtract(&b).unwrap();
    let (pos, neg) = diff.peel().unwrap();
    assert!(pos.is_empty());
    assert!(neg.is_empty());
}

#[test]
fn iblt_peel_results_are_sorted() {
    let mut a = Iblt::new(128, 3);
    let b = Iblt::new(128, 3);

    // Insert several elements only in a.
    let hashes: Vec<[u8; 32]> = (10..20).map(make_hash).collect();
    for h in &hashes {
        a.insert(h);
    }

    let diff = a.subtract(&b).unwrap();
    let (pos, neg) = diff.peel().unwrap();
    assert!(neg.is_empty());
    // Verify sorted.
    for window in pos.windows(2) {
        assert!(window[0] <= window[1]);
    }
}

#[test]
fn iblt_serde_preserves_state() {
    let mut iblt = Iblt::new(32, 3);
    iblt.insert(&make_hash(1));
    iblt.insert(&make_hash(2));
    iblt.remove(&make_hash(3));

    let json = serde_json::to_string(&iblt).unwrap();
    let restored: Iblt = serde_json::from_str(&json).unwrap();
    assert_eq!(iblt, restored);

    // Restored IBLT should peel the same way.
    let empty = Iblt::new(32, 3);
    let diff_orig = iblt.subtract(&empty).unwrap();
    let diff_rest = restored.subtract(&empty).unwrap();
    // Can't guarantee peel succeeds with remove-without-partner,
    // but the underlying data is identical.
    assert_eq!(diff_orig, diff_rest);
}

#[test]
fn iblt_large_symmetric_difference() {
    // With a properly sized IBLT, even a moderate diff should peel.
    let mut a = Iblt::new(256, 3);
    let mut b = Iblt::new(256, 3);

    // 50 shared, 5 a-only, 5 b-only.
    for i in 0..50u8 {
        let h = make_hash(i);
        a.insert(&h);
        b.insert(&h);
    }
    for i in 50..55u8 {
        a.insert(&make_hash(i));
    }
    for i in 55..60u8 {
        b.insert(&make_hash(i));
    }

    let diff = a.subtract(&b).unwrap();
    let (pos, neg) = diff.peel().unwrap();
    assert_eq!(pos.len(), 5);
    assert_eq!(neg.len(), 5);
}

// ===========================================================================
// ReconcileError
// ===========================================================================

#[test]
fn reconcile_error_display_all_variants() {
    let errors = [
        ReconcileError::IbltSizeMismatch {
            local_cells: 64,
            remote_cells: 128,
        },
        ReconcileError::PeelFailed {
            remaining_cells: 10,
        },
        ReconcileError::EpochMismatch {
            local_epoch: epoch(1),
            remote_epoch: epoch(2),
        },
        ReconcileError::VerificationFailed {
            object_hash: "abc".to_string(),
            reason: "bad checksum".to_string(),
        },
        ReconcileError::EmptyObjectSet,
    ];

    let displays: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
    assert!(displays[0].contains("64"));
    assert!(displays[0].contains("128"));
    assert!(displays[1].contains("10"));
    assert!(displays[2].contains("mismatch"));
    assert!(displays[3].contains("abc"));
    assert!(displays[3].contains("bad checksum"));
    assert!(displays[4].contains("empty"));
}

#[test]
fn reconcile_error_serde_all_variants() {
    let errors = [
        ReconcileError::IbltSizeMismatch {
            local_cells: 64,
            remote_cells: 128,
        },
        ReconcileError::PeelFailed {
            remaining_cells: 10,
        },
        ReconcileError::EpochMismatch {
            local_epoch: epoch(1),
            remote_epoch: epoch(2),
        },
        ReconcileError::VerificationFailed {
            object_hash: "abc".to_string(),
            reason: "bad checksum".to_string(),
        },
        ReconcileError::EmptyObjectSet,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: ReconcileError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn reconcile_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ReconcileError::EmptyObjectSet);
    assert!(err.to_string().contains("empty"));
}

// ===========================================================================
// ReconcileConfig
// ===========================================================================

#[test]
fn reconcile_config_default_values() {
    let config = ReconcileConfig::default();
    assert_eq!(config.iblt_cells, 256);
    assert_eq!(config.iblt_hashes, 3);
    assert_eq!(config.max_retries, 2);
    assert_eq!(config.retry_scale_factor, 2);
}

#[test]
fn reconcile_config_serde_roundtrip() {
    let config = ReconcileConfig {
        iblt_cells: 512,
        iblt_hashes: 5,
        max_retries: 10,
        retry_scale_factor: 4,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: ReconcileConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

// ===========================================================================
// ReconcileSession — edge cases
// ===========================================================================

#[test]
fn session_epoch_accessor() {
    let session = ReconcileSession::new(epoch(42), ReconcileConfig::default());
    assert_eq!(session.epoch(), epoch(42));
}

#[test]
fn session_build_iblt_empty_set() {
    let session = ReconcileSession::new(epoch(1), ReconcileConfig::default());
    let empty_set = BTreeSet::new();
    let iblt = session.build_iblt(&empty_set);
    assert_eq!(iblt.num_cells(), 256); // default
    // All cells should be zero.
    for cell in &iblt.cells {
        assert_eq!(cell.count, 0);
    }
}

#[test]
fn session_reconcile_empty_sets() {
    let config = ReconcileConfig {
        iblt_cells: 64,
        iblt_hashes: 3,
        max_retries: 2,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch(1), config);
    let empty: BTreeSet<[u8; 32]> = BTreeSet::new();
    let remote_iblt = session.build_iblt(&empty);
    let result = session
        .reconcile(&empty, &remote_iblt, "peer-1", "t1")
        .unwrap();
    assert!(!result.fallback_triggered);
    assert!(result.objects_to_send.is_empty());
    assert!(result.objects_to_fetch.is_empty());
}

#[test]
fn session_reconcile_local_only_elements() {
    let config = ReconcileConfig {
        iblt_cells: 128,
        iblt_hashes: 3,
        max_retries: 2,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch(1), config);

    let local: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = BTreeSet::new();
    let remote_iblt = session.build_iblt(&remote);

    let result = session
        .reconcile(&local, &remote_iblt, "peer-1", "t1")
        .unwrap();
    assert!(!result.fallback_triggered);
    assert_eq!(result.objects_to_send.len(), 5);
    assert!(result.objects_to_fetch.is_empty());
}

#[test]
fn session_reconcile_remote_only_elements() {
    let config = ReconcileConfig {
        iblt_cells: 128,
        iblt_hashes: 3,
        max_retries: 2,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch(1), config);

    let local: BTreeSet<[u8; 32]> = BTreeSet::new();
    let remote: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
    let remote_iblt = session.build_iblt(&remote);

    let result = session
        .reconcile(&local, &remote_iblt, "peer-1", "t1")
        .unwrap();
    assert!(!result.fallback_triggered);
    assert!(result.objects_to_send.is_empty());
    assert_eq!(result.objects_to_fetch.len(), 5);
}

#[test]
fn session_drain_events_clears() {
    let config = ReconcileConfig {
        iblt_cells: 128,
        iblt_hashes: 3,
        max_retries: 2,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch(1), config);
    let objects: BTreeSet<[u8; 32]> = (0..3).map(make_hash).collect();
    let remote_iblt = session.build_iblt(&objects);
    session.reconcile(&objects, &remote_iblt, "p", "t").unwrap();

    let events = session.drain_events();
    assert_eq!(events.len(), 1);
    // Drain again: should be empty.
    assert!(session.drain_events().is_empty());
}

#[test]
fn session_event_counts_accumulate() {
    let config = ReconcileConfig {
        iblt_cells: 128,
        iblt_hashes: 3,
        max_retries: 2,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch(1), config);
    let objects: BTreeSet<[u8; 32]> = (0..3).map(make_hash).collect();
    let remote_iblt = session.build_iblt(&objects);

    // Two successful reconciliations.
    session
        .reconcile(&objects, &remote_iblt, "p1", "t1")
        .unwrap();
    session
        .reconcile(&objects, &remote_iblt, "p2", "t2")
        .unwrap();

    assert_eq!(session.event_counts().get("reconcile_success"), Some(&2));
}

#[test]
fn session_reconcile_event_fields() {
    let config = ReconcileConfig {
        iblt_cells: 128,
        iblt_hashes: 3,
        max_retries: 2,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch(5), config);
    let mut local: BTreeSet<[u8; 32]> = (0..10).map(make_hash).collect();
    let remote = local.clone();
    local.insert(make_hash(100));
    let remote_iblt = session.build_iblt(&remote);

    session
        .reconcile(&local, &remote_iblt, "node-7", "trace-42")
        .unwrap();
    let events = session.drain_events();
    assert_eq!(events.len(), 1);
    let ev = &events[0];
    assert_eq!(ev.reconciliation_id, "trace-42:node-7");
    assert_eq!(ev.peer, "node-7");
    assert_eq!(ev.epoch_id, 5);
    assert_eq!(ev.trace_id, "trace-42");
    assert_eq!(ev.event, "reconcile_success");
    assert!(!ev.fallback_triggered);
    assert_eq!(ev.objects_sent, 1);
    assert_eq!(ev.objects_received, 0);
}

#[test]
fn session_fallback_event_fields() {
    let config = ReconcileConfig {
        iblt_cells: 4,
        iblt_hashes: 3,
        max_retries: 0,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch(3), config);
    // Use make_wide_hash pattern matching inline tests for guaranteed peel failure.
    let local: BTreeSet<[u8; 32]> = (0u16..200)
        .map(|i| {
            let mut h = [0u8; 32];
            let bytes = i.to_le_bytes();
            h[0] = bytes[0];
            h[1] = bytes[1];
            h[2] = 0xAA;
            for j in 3..32 {
                h[j] = h[j - 1].wrapping_mul(37).wrapping_add(0xAA);
            }
            h
        })
        .collect();
    let remote: BTreeSet<[u8; 32]> = (200u16..400)
        .map(|i| {
            let mut h = [0u8; 32];
            let bytes = i.to_le_bytes();
            h[0] = bytes[0];
            h[1] = bytes[1];
            h[2] = 0xBB;
            for j in 3..32 {
                h[j] = h[j - 1].wrapping_mul(37).wrapping_add(0xBB);
            }
            h
        })
        .collect();
    let remote_iblt = session.build_iblt(&remote);

    let result = session
        .reconcile(&local, &remote_iblt, "peer-x", "trace-fb")
        .unwrap();
    assert!(result.fallback_triggered);

    let events = session.drain_events();
    let fb_event = events
        .iter()
        .find(|e| e.event == "reconcile_fallback")
        .unwrap();
    assert!(fb_event.fallback_triggered);
    assert_eq!(fb_event.peer, "peer-x");
    assert_eq!(fb_event.epoch_id, 3);
    assert_eq!(session.event_counts().get("reconcile_fallback"), Some(&1));
}

#[test]
fn session_exact_difference_empty_sets() {
    let empty = BTreeSet::new();
    let (lo, ro) = ReconcileSession::exact_difference(&empty, &empty);
    assert!(lo.is_empty());
    assert!(ro.is_empty());
}

#[test]
fn session_exact_difference_disjoint_sets() {
    let local: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (5..10).map(make_hash).collect();
    let (lo, ro) = ReconcileSession::exact_difference(&local, &remote);
    assert_eq!(lo.len(), 5);
    assert_eq!(ro.len(), 5);
}

#[test]
fn session_exact_difference_identical() {
    let objects: BTreeSet<[u8; 32]> = (0..20).map(make_hash).collect();
    let (lo, ro) = ReconcileSession::exact_difference(&objects, &objects);
    assert!(lo.is_empty());
    assert!(ro.is_empty());
}

// ===========================================================================
// ReconcileResult serde
// ===========================================================================

#[test]
fn reconcile_result_serde_roundtrip() {
    let result = ReconcileResult {
        objects_to_fetch: vec![make_hash(1), make_hash(2)],
        objects_to_send: vec![make_hash(3)],
        fallback_triggered: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: ReconcileResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// ===========================================================================
// ReconcileEvent serde
// ===========================================================================

#[test]
fn reconcile_event_serde_roundtrip() {
    let event = ReconcileEvent {
        reconciliation_id: "r-1".to_string(),
        peer: "peer-a".to_string(),
        objects_sent: 10,
        objects_received: 5,
        objects_conflicting: 2,
        epoch_id: 42,
        trace_id: "t-1".to_string(),
        event: "reconcile_success".to_string(),
        fallback_triggered: false,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: ReconcileEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ===========================================================================
// FallbackTrigger
// ===========================================================================

#[test]
fn fallback_trigger_serde_all_variants() {
    let triggers = [
        FallbackTrigger::PeelFailed { remaining_cells: 0 },
        FallbackTrigger::VerificationFailed {
            object_hash: "hash-1".to_string(),
            reason: "corrupted".to_string(),
        },
        FallbackTrigger::Timeout {
            elapsed_ms: 10_000,
            slo_ms: 5_000,
        },
        FallbackTrigger::MmrConsistencyFailure {
            details: "root divergence".to_string(),
        },
    ];
    for t in &triggers {
        let json = serde_json::to_string(t).unwrap();
        let restored: FallbackTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, restored);
    }
}

#[test]
fn fallback_trigger_display_all_variants() {
    let displays = [
        (
            FallbackTrigger::PeelFailed { remaining_cells: 7 },
            "peel_failed",
        ),
        (
            FallbackTrigger::VerificationFailed {
                object_hash: "h".to_string(),
                reason: "r".to_string(),
            },
            "verification_failed",
        ),
        (
            FallbackTrigger::Timeout {
                elapsed_ms: 100,
                slo_ms: 50,
            },
            "timeout",
        ),
        (
            FallbackTrigger::MmrConsistencyFailure {
                details: "d".to_string(),
            },
            "mmr_consistency",
        ),
    ];
    for (trigger, expected_substring) in &displays {
        assert!(
            trigger.to_string().contains(expected_substring),
            "expected '{}' in '{}'",
            expected_substring,
            trigger
        );
    }
}

#[test]
fn fallback_trigger_peel_failed_display_includes_count() {
    let t = FallbackTrigger::PeelFailed {
        remaining_cells: 42,
    };
    assert!(t.to_string().contains("42"));
}

#[test]
fn fallback_trigger_timeout_display_includes_both_values() {
    let t = FallbackTrigger::Timeout {
        elapsed_ms: 9999,
        slo_ms: 3000,
    };
    let s = t.to_string();
    assert!(s.contains("9999"));
    assert!(s.contains("3000"));
}

// ===========================================================================
// FallbackEvidence serde
// ===========================================================================

#[test]
fn fallback_evidence_serde_roundtrip() {
    let ev = FallbackEvidence {
        fallback_id: "fb-t1-1".to_string(),
        trigger: FallbackTrigger::Timeout {
            elapsed_ms: 5000,
            slo_ms: 3000,
        },
        original_reconciliation_id: "r1:peer-1".to_string(),
        scope_size: 1000,
        differences_found: 50,
        objects_transferred: 50,
        duration_ms: 123,
        epoch_id: 7,
        trace_id: "t1".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let restored: FallbackEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, restored);
}

// ===========================================================================
// FallbackResult serde
// ===========================================================================

#[test]
fn fallback_result_serde_roundtrip() {
    let result = FallbackResult {
        objects_to_fetch: vec![make_hash(1)],
        objects_to_send: vec![make_hash(2), make_hash(3)],
        evidence: FallbackEvidence {
            fallback_id: "fb-1".to_string(),
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
            original_reconciliation_id: "r:p".to_string(),
            scope_size: 10,
            differences_found: 3,
            objects_transferred: 3,
            duration_ms: 0,
            epoch_id: 1,
            trace_id: "t".to_string(),
        },
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: FallbackResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// ===========================================================================
// FallbackConfig
// ===========================================================================

#[test]
fn fallback_config_default_values() {
    let config = FallbackConfig::default();
    assert_eq!(config.max_fallback_rate_pct, 5);
    assert_eq!(config.monitoring_window, 100);
}

#[test]
fn fallback_config_serde_roundtrip() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 20,
        monitoring_window: 500,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: FallbackConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

// ===========================================================================
// FallbackProtocol — edge cases
// ===========================================================================

#[test]
fn fallback_protocol_epoch_accessor() {
    let fb = FallbackProtocol::new(epoch(99));
    assert_eq!(fb.epoch(), epoch(99));
}

#[test]
fn fallback_protocol_empty_sets() {
    let mut fb = FallbackProtocol::new(epoch(1));
    let empty = BTreeSet::new();
    let result = fb.execute(FallbackRequest {
        local_hashes: &empty,
        remote_hashes: &empty,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r1",
        peer: "p1",
        trace_id: "t1",
    });
    assert!(result.objects_to_send.is_empty());
    assert!(result.objects_to_fetch.is_empty());
    assert_eq!(result.evidence.differences_found, 0);
    assert_eq!(result.evidence.scope_size, 0);
}

#[test]
fn fallback_protocol_disjoint_sets() {
    let mut fb = FallbackProtocol::new(epoch(1));
    let local: BTreeSet<[u8; 32]> = (0..3).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (3..6).map(make_hash).collect();

    let result = fb.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 5 },
        reconciliation_id: "r1",
        peer: "p1",
        trace_id: "t1",
    });
    assert_eq!(result.objects_to_send.len(), 3);
    assert_eq!(result.objects_to_fetch.len(), 3);
    assert_eq!(result.evidence.differences_found, 6);
}

#[test]
fn fallback_protocol_seq_increments() {
    let mut fb = FallbackProtocol::new(epoch(1));
    let local: BTreeSet<[u8; 32]> = (0..3).map(make_hash).collect();
    let remote = local.clone();

    let r1 = fb.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r1",
        peer: "p1",
        trace_id: "t1",
    });
    let r2 = fb.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r2",
        peer: "p1",
        trace_id: "t2",
    });

    assert!(r1.evidence.fallback_id.ends_with("-1"));
    assert!(r2.evidence.fallback_id.ends_with("-2"));
}

#[test]
fn fallback_protocol_evidence_original_reconciliation_id() {
    let mut fb = FallbackProtocol::new(epoch(1));
    let set: BTreeSet<[u8; 32]> = (0..3).map(make_hash).collect();
    let result = fb.execute(FallbackRequest {
        local_hashes: &set,
        remote_hashes: &set,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "recon-123",
        peer: "node-A",
        trace_id: "t1",
    });
    assert_eq!(
        result.evidence.original_reconciliation_id,
        "recon-123:node-A"
    );
}

#[test]
fn fallback_protocol_scope_size_is_max() {
    let mut fb = FallbackProtocol::new(epoch(1));
    let local: BTreeSet<[u8; 32]> = (0..10).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (0..20).map(make_hash).collect();

    let result = fb.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r",
        peer: "p",
        trace_id: "t",
    });
    assert_eq!(result.evidence.scope_size, 20); // max(10, 20)
}

#[test]
fn fallback_protocol_drain_events_and_counts() {
    let mut fb = FallbackProtocol::new(epoch(1));
    let set: BTreeSet<[u8; 32]> = (0..3).map(make_hash).collect();

    fb.execute(FallbackRequest {
        local_hashes: &set,
        remote_hashes: &set,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r1",
        peer: "p1",
        trace_id: "t1",
    });
    fb.execute(FallbackRequest {
        local_hashes: &set,
        remote_hashes: &set,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r2",
        peer: "p2",
        trace_id: "t2",
    });

    assert_eq!(fb.event_counts().get("fallback_executed"), Some(&2));
    let events = fb.drain_events();
    assert_eq!(events.len(), 2);
    assert!(fb.drain_events().is_empty());
}

// ===========================================================================
// Incremental fallback — edge cases
// ===========================================================================

#[test]
fn incremental_fallback_num_ranges_zero_delegates_to_full() {
    let mut fb = FallbackProtocol::new(epoch(1));
    let local: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (3..8).map(make_hash).collect();

    let result = fb.execute_incremental(
        FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
            reconciliation_id: "r1",
            peer: "p1",
            trace_id: "t1",
        },
        0, // zero ranges → delegates to execute()
    );
    // Should still produce correct results.
    let expected_send: BTreeSet<_> = local.difference(&remote).copied().collect();
    let expected_fetch: BTreeSet<_> = remote.difference(&local).copied().collect();
    let actual_send: BTreeSet<_> = result.objects_to_send.iter().copied().collect();
    let actual_fetch: BTreeSet<_> = result.objects_to_fetch.iter().copied().collect();
    assert_eq!(actual_send, expected_send);
    assert_eq!(actual_fetch, expected_fetch);
}

#[test]
fn incremental_fallback_num_ranges_one_delegates_to_full() {
    let mut fb = FallbackProtocol::new(epoch(1));
    let local: BTreeSet<[u8; 32]> = (0..5).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (3..8).map(make_hash).collect();

    let result = fb.execute_incremental(
        FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
            reconciliation_id: "r1",
            peer: "p1",
            trace_id: "t1",
        },
        1,
    );
    let expected_send: BTreeSet<_> = local.difference(&remote).copied().collect();
    let actual_send: BTreeSet<_> = result.objects_to_send.iter().copied().collect();
    assert_eq!(actual_send, expected_send);
}

#[test]
fn incremental_fallback_identical_sets_skips_all_ranges() {
    let mut fb = FallbackProtocol::new(epoch(1));
    let objects: BTreeSet<[u8; 32]> = (0..50).map(make_hash).collect();

    let result = fb.execute_incremental(
        FallbackRequest {
            local_hashes: &objects,
            remote_hashes: &objects,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
            reconciliation_id: "r1",
            peer: "p1",
            trace_id: "t1",
        },
        4,
    );
    assert!(result.objects_to_send.is_empty());
    assert!(result.objects_to_fetch.is_empty());
    // All 4 ranges should have been skipped.
    assert_eq!(fb.event_counts().get("fallback_ranges_skipped"), Some(&4));
}

#[test]
fn incremental_fallback_difference_in_one_range() {
    let mut fb = FallbackProtocol::new(epoch(1));

    // Put shared objects across many first-bytes.
    let mut local: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut remote: BTreeSet<[u8; 32]> = BTreeSet::new();

    for i in 0..10u8 {
        let h = make_range_hash(i * 25, i); // spread across byte range
        local.insert(h);
        remote.insert(h);
    }
    // Add one local-only element in a specific range.
    let extra = make_range_hash(200, 99); // first_byte=200
    local.insert(extra);

    let result = fb.execute_incremental(
        FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
            reconciliation_id: "r1",
            peer: "p1",
            trace_id: "t1",
        },
        4,
    );
    assert_eq!(result.objects_to_send.len(), 1);
    assert!(result.objects_to_send.contains(&extra));
    assert!(result.objects_to_fetch.is_empty());
    // At least some ranges should have been skipped.
    let skipped = fb
        .event_counts()
        .get("fallback_ranges_skipped")
        .copied()
        .unwrap_or(0);
    assert!(
        skipped >= 1,
        "expected at least 1 skipped range, got {skipped}"
    );
}

#[test]
fn incremental_fallback_results_match_full_fallback() {
    let local: BTreeSet<[u8; 32]> = (0..30).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (15..45).map(make_hash).collect();

    let mut fb_full = FallbackProtocol::new(epoch(1));
    let full_result = fb_full.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
        reconciliation_id: "r",
        peer: "p",
        trace_id: "t",
    });

    let mut fb_incr = FallbackProtocol::new(epoch(1));
    let incr_result = fb_incr.execute_incremental(
        FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
            reconciliation_id: "r",
            peer: "p",
            trace_id: "t",
        },
        8,
    );

    let full_send: BTreeSet<_> = full_result.objects_to_send.iter().copied().collect();
    let incr_send: BTreeSet<_> = incr_result.objects_to_send.iter().copied().collect();
    let full_fetch: BTreeSet<_> = full_result.objects_to_fetch.iter().copied().collect();
    let incr_fetch: BTreeSet<_> = incr_result.objects_to_fetch.iter().copied().collect();

    assert_eq!(full_send, incr_send);
    assert_eq!(full_fetch, incr_fetch);
}

#[test]
fn incremental_fallback_max_ranges() {
    let mut fb = FallbackProtocol::new(epoch(1));
    let local: BTreeSet<[u8; 32]> = (0..10).map(make_hash).collect();
    let remote: BTreeSet<[u8; 32]> = (5..15).map(make_hash).collect();

    // 255 ranges (maximum u8 - 1 that's > 1).
    let result = fb.execute_incremental(
        FallbackRequest {
            local_hashes: &local,
            remote_hashes: &remote,
            trigger: FallbackTrigger::PeelFailed { remaining_cells: 0 },
            reconciliation_id: "r",
            peer: "p",
            trace_id: "t",
        },
        255,
    );
    let expected_send: BTreeSet<_> = local.difference(&remote).copied().collect();
    let expected_fetch: BTreeSet<_> = remote.difference(&local).copied().collect();
    let actual_send: BTreeSet<_> = result.objects_to_send.iter().copied().collect();
    let actual_fetch: BTreeSet<_> = result.objects_to_fetch.iter().copied().collect();
    assert_eq!(actual_send, expected_send);
    assert_eq!(actual_fetch, expected_fetch);
}

// ===========================================================================
// FallbackRateAlert serde
// ===========================================================================

#[test]
fn fallback_rate_alert_serde_roundtrip() {
    let alert = FallbackRateAlert {
        rate_pct: 15,
        threshold_pct: 5,
        fallbacks_in_window: 3,
        total_in_window: 20,
        epoch_id: 42,
    };
    let json = serde_json::to_string(&alert).unwrap();
    let restored: FallbackRateAlert = serde_json::from_str(&json).unwrap();
    assert_eq!(alert, restored);
}

// ===========================================================================
// FallbackRateMonitor — edge cases
// ===========================================================================

#[test]
fn rate_monitor_zero_window_clamped_to_one() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 50,
        monitoring_window: 0, // will be clamped to 1
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    // Record a fallback.
    let alert = monitor.record(true);
    // 1 fallback out of 1 = 100% > 50%.
    assert!(alert.is_some());
    assert_eq!(monitor.current_rate_pct(), 100);
}

#[test]
fn rate_monitor_single_success_no_alert() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 0, // any fallback exceeds
        monitoring_window: 10,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    assert!(monitor.record(false).is_none());
    assert_eq!(monitor.current_rate_pct(), 0);
    assert!(!monitor.is_rate_exceeded());
}

#[test]
fn rate_monitor_exactly_at_threshold_no_alert() {
    // 5% threshold, window of 20. 1 fallback = 5% exactly.
    // The check is `> threshold`, not `>=`, so exactly at threshold is OK.
    let config = FallbackConfig {
        max_fallback_rate_pct: 5,
        monitoring_window: 20,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    monitor.record(true); // 1/1 = 100% > 5%
    // Actually at 1 record, rate is 100%. Let me fill the window properly.
    // We need 19 more successes to get 1/20 = 5%.
    // But the first record already triggered. Let me start fresh.
    let config2 = FallbackConfig {
        max_fallback_rate_pct: 5,
        monitoring_window: 20,
    };
    let mut monitor2 = FallbackRateMonitor::new(epoch(1), config2);
    // Fill 19 successes first.
    for _ in 0..19 {
        monitor2.record(false);
    }
    // Now record 1 fallback → 1/20 = 5% which is NOT > 5%.
    let alert = monitor2.record(true);
    assert!(alert.is_none(), "5% should not exceed 5% threshold");
    assert!(!monitor2.is_rate_exceeded());
}

#[test]
fn rate_monitor_one_above_threshold_alerts() {
    // To get 6% we need at least 2/20 = 10%, so let's use a window of 100.
    // 6 fallbacks / 100 = 6% > 5%.
    let config = FallbackConfig {
        max_fallback_rate_pct: 5,
        monitoring_window: 100,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    // Fill 94 successes.
    for _ in 0..94 {
        monitor.record(false);
    }
    // Now add 6 fallbacks → 6/100 = 6% > 5%.
    for _ in 0..5 {
        monitor.record(true);
    }
    let alert = monitor.record(true);
    assert!(alert.is_some());
    assert!(monitor.is_rate_exceeded());
}

#[test]
fn rate_monitor_sliding_window_evicts_fallback() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 5,
        monitoring_window: 10,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);

    // Position 0: fallback.
    monitor.record(true);
    // Positions 1-9: success.
    for _ in 0..9 {
        monitor.record(false);
    }
    // 1/10 = 10% > 5%.
    assert!(monitor.is_rate_exceeded());

    // Position 10 overwrites position 0 (the fallback) with success.
    monitor.record(false);
    // Now 0 fallbacks in window → 0%.
    assert!(!monitor.is_rate_exceeded());
    assert_eq!(monitor.current_rate_pct(), 0);
}

#[test]
fn rate_monitor_total_recorded_tracks_all() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 50,
        monitoring_window: 5,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    for _ in 0..20 {
        monitor.record(false);
    }
    assert_eq!(monitor.total_recorded(), 20);
}

#[test]
fn rate_monitor_drain_alerts_clears() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 0,
        monitoring_window: 5,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    monitor.record(true);
    monitor.record(true);
    monitor.record(true);

    let alerts = monitor.drain_alerts();
    assert_eq!(alerts.len(), 3);
    assert!(monitor.drain_alerts().is_empty());
}

#[test]
fn rate_monitor_alert_fields() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 0,
        monitoring_window: 10,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(7), config);
    let alert = monitor.record(true).unwrap();
    assert_eq!(alert.threshold_pct, 0);
    assert_eq!(alert.epoch_id, 7);
    assert_eq!(alert.total_in_window, 1);
    assert_eq!(alert.fallbacks_in_window, 1);
    assert_eq!(alert.rate_pct, 100);
}

#[test]
fn rate_monitor_empty_has_zero_rate() {
    let config = FallbackConfig::default();
    let monitor = FallbackRateMonitor::new(epoch(1), config);
    assert_eq!(monitor.current_rate_pct(), 0);
    assert!(!monitor.is_rate_exceeded());
    assert_eq!(monitor.total_recorded(), 0);
}

#[test]
fn rate_monitor_all_fallbacks() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 99,
        monitoring_window: 10,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    for _ in 0..10 {
        monitor.record(true);
    }
    assert_eq!(monitor.current_rate_pct(), 100);
    assert!(monitor.is_rate_exceeded());
}

#[test]
fn rate_monitor_no_fallbacks() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 0,
        monitoring_window: 10,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    for _ in 0..10 {
        assert!(monitor.record(false).is_none());
    }
    assert_eq!(monitor.current_rate_pct(), 0);
    assert!(!monitor.is_rate_exceeded());
}

// ===========================================================================
// Cross-component integration scenarios
// ===========================================================================

#[test]
fn iblt_reconcile_agrees_with_exact_difference() {
    let config = ReconcileConfig {
        iblt_cells: 256,
        iblt_hashes: 3,
        max_retries: 2,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch(1), config);

    let shared: BTreeSet<[u8; 32]> = (0..50).map(make_hash).collect();
    let mut local = shared.clone();
    let mut remote = shared;

    let local_extras: Vec<[u8; 32]> = (100..105).map(make_hash).collect();
    let remote_extras: Vec<[u8; 32]> = (200..208).map(make_hash).collect();

    for h in &local_extras {
        local.insert(*h);
    }
    for h in &remote_extras {
        remote.insert(*h);
    }

    let remote_iblt = session.build_iblt(&remote);
    let iblt_result = session.reconcile(&local, &remote_iblt, "p", "t").unwrap();
    let (exact_send, exact_fetch) = ReconcileSession::exact_difference(&local, &remote);

    let iblt_send: BTreeSet<_> = iblt_result.objects_to_send.iter().copied().collect();
    let iblt_fetch: BTreeSet<_> = iblt_result.objects_to_fetch.iter().copied().collect();
    let exact_send_set: BTreeSet<_> = exact_send.into_iter().collect();
    let exact_fetch_set: BTreeSet<_> = exact_fetch.into_iter().collect();

    assert_eq!(iblt_send, exact_send_set);
    assert_eq!(iblt_fetch, exact_fetch_set);
}

#[test]
fn fallback_after_iblt_failure_yields_correct_diff() {
    // Simulate: IBLT fails → fallback protocol handles it.
    // Use large disjoint sets to guarantee peel failure with tiny IBLT.
    let local: BTreeSet<[u8; 32]> = (0u16..200)
        .map(|i| {
            let mut h = [0u8; 32];
            let bytes = i.to_le_bytes();
            h[0] = bytes[0];
            h[1] = bytes[1];
            h[2] = 0xCC;
            for j in 3..32 {
                h[j] = h[j - 1].wrapping_mul(37).wrapping_add(0xCC);
            }
            h
        })
        .collect();
    let remote: BTreeSet<[u8; 32]> = (200u16..400)
        .map(|i| {
            let mut h = [0u8; 32];
            let bytes = i.to_le_bytes();
            h[0] = bytes[0];
            h[1] = bytes[1];
            h[2] = 0xDD;
            for j in 3..32 {
                h[j] = h[j - 1].wrapping_mul(37).wrapping_add(0xDD);
            }
            h
        })
        .collect();

    // IBLT with tiny table will fail.
    let config = ReconcileConfig {
        iblt_cells: 4,
        iblt_hashes: 3,
        max_retries: 0,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch(1), config);
    let remote_iblt = session.build_iblt(&remote);
    let iblt_result = session.reconcile(&local, &remote_iblt, "p", "t").unwrap();
    assert!(iblt_result.fallback_triggered);

    // Now use fallback protocol.
    let mut fb = FallbackProtocol::new(epoch(1));
    let fb_result = fb.execute(FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed {
            remaining_cells: 99,
        },
        reconciliation_id: "r",
        peer: "p",
        trace_id: "t",
    });

    let (exact_send, exact_fetch) = ReconcileSession::exact_difference(&local, &remote);
    assert_eq!(fb_result.objects_to_send, exact_send);
    assert_eq!(fb_result.objects_to_fetch, exact_fetch);
}

#[test]
fn rate_monitor_tracks_mixed_iblt_and_fallback_outcomes() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 50,
        monitoring_window: 10,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);

    // Simulate 3 IBLT successes, 2 fallbacks.
    monitor.record(false); // IBLT success
    monitor.record(false);
    monitor.record(false);
    monitor.record(true); // fallback
    monitor.record(true); // fallback

    // 2/5 = 40% < 50%.
    assert!(!monitor.is_rate_exceeded());
    assert_eq!(monitor.current_rate_pct(), 40);
    assert_eq!(monitor.total_recorded(), 5);
}

#[test]
fn full_pipeline_iblt_success_to_rate_monitor() {
    let reconcile_config = ReconcileConfig {
        iblt_cells: 128,
        iblt_hashes: 3,
        max_retries: 2,
        retry_scale_factor: 2,
    };
    let rate_config = FallbackConfig {
        max_fallback_rate_pct: 10,
        monitoring_window: 100,
    };

    let mut session = ReconcileSession::new(epoch(1), reconcile_config);
    let mut monitor = FallbackRateMonitor::new(epoch(1), rate_config);

    // Run 5 successful reconciliations with small differences.
    for i in 0..5u8 {
        let mut local: BTreeSet<[u8; 32]> = (0..20).map(make_hash).collect();
        let remote = local.clone();
        local.insert(make_hash(100 + i));
        let remote_iblt = session.build_iblt(&remote);
        let result = session
            .reconcile(&local, &remote_iblt, "p", &format!("t{i}"))
            .unwrap();
        assert!(!result.fallback_triggered);
        monitor.record(result.fallback_triggered);
    }

    assert_eq!(monitor.total_recorded(), 5);
    assert_eq!(monitor.current_rate_pct(), 0);
    assert!(!monitor.is_rate_exceeded());
    assert_eq!(session.event_counts().get("reconcile_success"), Some(&5));
}

#[test]
fn deterministic_reconciliation_replay() {
    let run = || {
        let config = ReconcileConfig {
            iblt_cells: 128,
            iblt_hashes: 3,
            max_retries: 2,
            retry_scale_factor: 2,
        };
        let mut session = ReconcileSession::new(epoch(1), config);
        let mut local: BTreeSet<[u8; 32]> = (0..30).map(make_hash).collect();
        let mut remote: BTreeSet<[u8; 32]> = (0..30).map(make_hash).collect();
        local.insert(make_hash(100));
        local.insert(make_hash(101));
        remote.insert(make_hash(200));

        let remote_iblt = session.build_iblt(&remote);
        let result = session
            .reconcile(&local, &remote_iblt, "peer-1", "trace-1")
            .unwrap();
        let events = session.drain_events();
        (result, events)
    };

    let (r1, e1) = run();
    let (r2, e2) = run();
    assert_eq!(r1, r2);
    assert_eq!(e1, e2);
}
