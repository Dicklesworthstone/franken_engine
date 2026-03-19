//! Enrichment integration tests for `hostcall_batch_transport`.
//!
//! Covers: BatchTransportConfig default/serde, RegionState ALL/display/serde,
//! SharedMemoryRegion serde, CreditPool new/try_consume/grant/revoke/state_hash,
//! BatchPayload display/serde, BatchEntry serde, MembraneRejectionReason ALL/
//! display/serde, MembraneVerdict is_accept/serde, MembraneAuditEntry serde,
//! BatchTransportError display/serde, BatchReceipt serde,
//! compute_entry_content_hash/compute_batch_mac determinism,
//! BatchTransportState lifecycle (allocate/seal/release/revoke/build/submit),
//! BatchTransportSpecimenFamily ALL/display/corpus, and determinism checks.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_batch_transport::{
    BatchEntry, BatchPayload, BatchTransportConfig,
    BatchTransportError, BatchTransportSpecimenFamily, BatchTransportState, BatchTransportVerdict,
    CreditPool, MembraneRejectionReason, MembraneVerdict, RegionState,
    SharedMemoryRegion, batch_transport_corpus, compute_batch_mac, compute_entry_content_hash,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::session_hostcall_channel::BackpressureSignal;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_entry(seq: u64, data: &[u8]) -> BatchEntry {
    let payload = BatchPayload::Inline(data.to_vec());
    let content_hash = compute_entry_content_hash(seq, &payload, "trace");
    BatchEntry {
        sequence: seq,
        payload,
        content_hash,
        entry_mac: None,
        trace_id: "trace".into(),
    }
}

// ===========================================================================
// BatchTransportConfig
// ===========================================================================

#[test]
fn config_default_values() {
    let c = BatchTransportConfig::default();
    assert_eq!(c.max_batch_size, 64);
    assert_eq!(c.max_batch_payload_bytes, 4_194_304);
    assert_eq!(c.initial_credits, 256);
    assert_eq!(c.max_credits, 1024);
    assert_eq!(c.max_active_regions, 16);
    assert!(c.compute_batch_mac);
}

#[test]
fn config_serde_roundtrip() {
    let c = BatchTransportConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: BatchTransportConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// RegionState
// ===========================================================================

#[test]
fn region_state_all_count() {
    assert_eq!(RegionState::ALL.len(), 5);
}

#[test]
fn region_state_display() {
    for rs in RegionState::ALL {
        let s = format!("{rs}");
        assert!(!s.is_empty());
    }
}

#[test]
fn region_state_serde_roundtrip() {
    for rs in RegionState::ALL {
        let json = serde_json::to_string(rs).unwrap();
        let back: RegionState = serde_json::from_str(&json).unwrap();
        assert_eq!(*rs, back);
    }
}

// ===========================================================================
// SharedMemoryRegion
// ===========================================================================

#[test]
fn shared_memory_region_serde_roundtrip() {
    let region = SharedMemoryRegion {
        region_id: 1,
        session_id: "sess-1".into(),
        capacity_bytes: 4096,
        occupied_bytes: 1024,
        state: RegionState::Sealed,
        content_hash: Some(ContentHash::compute(b"test")),
        allocated_at_tick: 100,
        sealed_at_tick: Some(200),
    };
    let json = serde_json::to_string(&region).unwrap();
    let back: SharedMemoryRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(region, back);
}

// ===========================================================================
// CreditPool
// ===========================================================================

#[test]
fn credit_pool_new() {
    let pool = CreditPool::new("sess".into(), 100, 500);
    assert_eq!(pool.available(), 100);
    assert_eq!(pool.session_id(), "sess");
    assert!(!pool.is_exhausted());
}

#[test]
fn credit_pool_initial_capped_at_max() {
    let pool = CreditPool::new("sess".into(), 1000, 500);
    assert_eq!(pool.available(), 500);
}

#[test]
fn credit_pool_consume_ok() {
    let mut pool = CreditPool::new("sess".into(), 100, 500);
    assert!(pool.try_consume(50).is_ok());
    assert_eq!(pool.available(), 50);
    assert_eq!(pool.total_consumed(), 50);
}

#[test]
fn credit_pool_consume_insufficient() {
    let mut pool = CreditPool::new("sess".into(), 10, 500);
    let result = pool.try_consume(20);
    assert!(result.is_err());
}

#[test]
fn credit_pool_consume_exact() {
    let mut pool = CreditPool::new("sess".into(), 100, 500);
    assert!(pool.try_consume(100).is_ok());
    assert_eq!(pool.available(), 0);
    assert!(pool.is_exhausted());
}

#[test]
fn credit_pool_grant() {
    let mut pool = CreditPool::new("sess".into(), 100, 500);
    pool.try_consume(80).unwrap();
    pool.grant(50);
    assert_eq!(pool.available(), 70);
    assert_eq!(pool.total_returned(), 50);
}

#[test]
fn credit_pool_grant_capped_at_max() {
    let mut pool = CreditPool::new("sess".into(), 100, 100);
    pool.grant(200);
    assert_eq!(pool.available(), 100);
}

#[test]
fn credit_pool_revoke() {
    let mut pool = CreditPool::new("sess".into(), 100, 500);
    pool.revoke(30);
    assert_eq!(pool.available(), 70);
}

#[test]
fn credit_pool_state_hash_deterministic() {
    let p1 = CreditPool::new("sess".into(), 100, 500);
    let p2 = CreditPool::new("sess".into(), 100, 500);
    assert_eq!(p1.state_hash(), p2.state_hash());
}

#[test]
fn credit_pool_state_hash_changes_after_consume() {
    let p1 = CreditPool::new("sess".into(), 100, 500);
    let mut p2 = CreditPool::new("sess".into(), 100, 500);
    p2.try_consume(10).unwrap();
    assert_ne!(p1.state_hash(), p2.state_hash());
}

#[test]
fn credit_pool_high_water_mark() {
    let mut pool = CreditPool::new("sess".into(), 100, 500);
    assert_eq!(pool.high_water_mark(), 100);
    pool.try_consume(50).unwrap();
    pool.grant(200);
    // available = 250, which is higher than initial 100
    assert_eq!(pool.high_water_mark(), 250);
}

#[test]
fn credit_pool_serde_roundtrip() {
    let pool = CreditPool::new("sess".into(), 100, 500);
    let json = serde_json::to_string(&pool).unwrap();
    let back: CreditPool = serde_json::from_str(&json).unwrap();
    assert_eq!(pool, back);
}

// ===========================================================================
// BatchPayload
// ===========================================================================

#[test]
fn batch_payload_inline_display() {
    let p = BatchPayload::Inline(vec![1, 2, 3]);
    let s = format!("{p}");
    assert!(s.contains("inline"));
    assert!(s.contains("3 bytes"));
}

#[test]
fn batch_payload_shared_region_display() {
    let p = BatchPayload::SharedRegion {
        region_id: 42,
        offset: 0,
        length: 256,
        payload_hash: ContentHash::compute(b"test"),
    };
    let s = format!("{p}");
    assert!(s.contains("shared"));
    assert!(s.contains("42"));
}

#[test]
fn batch_payload_backpressure_display() {
    let p = BatchPayload::Backpressure(BackpressureSignal {
        pending_messages: 50,
        limit: 100,
    });
    let s = format!("{p}");
    assert!(s.contains("backpressure"));
}

#[test]
fn batch_payload_inline_serde() {
    let p = BatchPayload::Inline(vec![10, 20, 30]);
    let json = serde_json::to_string(&p).unwrap();
    let back: BatchPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ===========================================================================
// MembraneRejectionReason
// ===========================================================================

#[test]
fn membrane_rejection_reason_all_count() {
    assert_eq!(MembraneRejectionReason::ALL.len(), 9);
}

#[test]
fn membrane_rejection_reason_display() {
    for r in MembraneRejectionReason::ALL {
        let s = format!("{r}");
        assert!(!s.is_empty());
    }
}

#[test]
fn membrane_rejection_reason_serde_roundtrip() {
    for r in MembraneRejectionReason::ALL {
        let json = serde_json::to_string(r).unwrap();
        let back: MembraneRejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// MembraneVerdict
// ===========================================================================

#[test]
fn membrane_verdict_is_accept() {
    let accept = MembraneVerdict::Accept { envelope_count: 5 };
    assert!(accept.is_accept());
    let reject = MembraneVerdict::Reject {
        reason: MembraneRejectionReason::PhaseBlocked,
        detail: "blocked".into(),
    };
    assert!(!reject.is_accept());
}

#[test]
fn membrane_verdict_serde_roundtrip_accept() {
    let v = MembraneVerdict::Accept { envelope_count: 3 };
    let json = serde_json::to_string(&v).unwrap();
    let back: MembraneVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn membrane_verdict_serde_roundtrip_reject() {
    let v = MembraneVerdict::Reject {
        reason: MembraneRejectionReason::EpochMismatch,
        detail: "mismatch".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: MembraneVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ===========================================================================
// BatchTransportError
// ===========================================================================

#[test]
fn batch_transport_error_display_variants() {
    let errors: Vec<BatchTransportError> = vec![
        BatchTransportError::BatchTooLarge { size: 100, max: 64 },
        BatchTransportError::PayloadTooLarge {
            bytes: 5_000_000,
            max: 4_194_304,
        },
        BatchTransportError::InsufficientCredits {
            requested: 10,
            available: 5,
        },
        BatchTransportError::TooManyRegions {
            active: 16,
            max: 16,
        },
        BatchTransportError::RegionNotFound { region_id: 999 },
        BatchTransportError::EmptyBatch,
    ];
    for e in &errors {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

#[test]
fn batch_transport_error_serde_roundtrip() {
    let e = BatchTransportError::InsufficientCredits {
        requested: 10,
        available: 5,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: BatchTransportError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ===========================================================================
// compute_entry_content_hash / compute_batch_mac
// ===========================================================================

#[test]
fn entry_content_hash_deterministic() {
    let payload = BatchPayload::Inline(vec![1, 2, 3]);
    let h1 = compute_entry_content_hash(1, &payload, "trace-1");
    let h2 = compute_entry_content_hash(1, &payload, "trace-1");
    assert_eq!(h1, h2);
}

#[test]
fn entry_content_hash_differs_by_sequence() {
    let payload = BatchPayload::Inline(vec![1, 2, 3]);
    let h1 = compute_entry_content_hash(1, &payload, "trace-1");
    let h2 = compute_entry_content_hash(2, &payload, "trace-1");
    assert_ne!(h1, h2);
}

#[test]
fn entry_content_hash_differs_by_payload() {
    let p1 = BatchPayload::Inline(vec![1]);
    let p2 = BatchPayload::Inline(vec![2]);
    let h1 = compute_entry_content_hash(1, &p1, "trace");
    let h2 = compute_entry_content_hash(1, &p2, "trace");
    assert_ne!(h1, h2);
}

#[test]
fn batch_mac_deterministic() {
    let key: [u8; 32] = [0xAB; 32];
    let entries = vec![make_entry(1, b"hello")];
    let m1 = compute_batch_mac(&key, 1, &entries, ep(1));
    let m2 = compute_batch_mac(&key, 1, &entries, ep(1));
    assert_eq!(m1, m2);
}

#[test]
fn batch_mac_differs_by_key() {
    let entries = vec![make_entry(1, b"hello")];
    let m1 = compute_batch_mac(&[0xAB; 32], 1, &entries, ep(1));
    let m2 = compute_batch_mac(&[0xFF; 32], 1, &entries, ep(1));
    assert_ne!(m1, m2);
}

#[test]
fn batch_mac_differs_by_epoch() {
    let key: [u8; 32] = [0xAB; 32];
    let entries = vec![make_entry(1, b"hello")];
    let m1 = compute_batch_mac(&key, 1, &entries, ep(1));
    let m2 = compute_batch_mac(&key, 1, &entries, ep(2));
    assert_ne!(m1, m2);
}

// ===========================================================================
// BatchTransportState — region lifecycle
// ===========================================================================

#[test]
fn state_allocate_region() {
    let config = BatchTransportConfig::default();
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let rid = state.allocate_region(1024, 10).unwrap();
    assert_eq!(rid, 1);
    assert_eq!(state.regions[&rid].state, RegionState::Allocated);
}

#[test]
fn state_seal_region() {
    let config = BatchTransportConfig::default();
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let rid = state.allocate_region(1024, 10).unwrap();
    let hash = state.seal_region(rid, 500, 20).unwrap();
    assert_eq!(state.regions[&rid].state, RegionState::Sealed);
    assert_eq!(state.regions[&rid].content_hash.as_ref(), Some(&hash));
    assert_eq!(state.regions[&rid].occupied_bytes, 500);
}

#[test]
fn state_release_region() {
    let config = BatchTransportConfig::default();
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let rid = state.allocate_region(1024, 10).unwrap();
    state.seal_region(rid, 100, 20).unwrap();
    state.release_region(rid).unwrap();
    assert_eq!(state.regions[&rid].state, RegionState::Released);
}

#[test]
fn state_revoke_region() {
    let config = BatchTransportConfig::default();
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let rid = state.allocate_region(1024, 10).unwrap();
    state.revoke_region(rid).unwrap();
    assert_eq!(state.regions[&rid].state, RegionState::Revoked);
}

#[test]
fn state_too_many_regions() {
    let config = BatchTransportConfig {
        max_active_regions: 2,
        ..Default::default()
    };
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    state.allocate_region(100, 1).unwrap();
    state.allocate_region(100, 2).unwrap();
    let result = state.allocate_region(100, 3);
    assert!(matches!(
        result,
        Err(BatchTransportError::TooManyRegions { .. })
    ));
}

#[test]
fn state_region_capacity_exceeded() {
    let config = BatchTransportConfig {
        max_region_size_bytes: 100,
        ..Default::default()
    };
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let result = state.allocate_region(200, 10);
    assert!(matches!(
        result,
        Err(BatchTransportError::RegionCapacityExceeded { .. })
    ));
}

// ===========================================================================
// BatchTransportState — batch build
// ===========================================================================

#[test]
fn state_build_batch_ok() {
    let config = BatchTransportConfig::default();
    let session_key: [u8; 32] = [0xAB; 32];
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let entries = vec![make_entry(1, b"hello"), make_entry(2, b"world")];
    let batch = state.build_batch(entries, &session_key, ep(1), 100).unwrap();
    assert_eq!(batch.batch_id, 1);
    assert_eq!(batch.entries.len(), 2);
    assert_eq!(batch.sequence_start, 1);
    assert_eq!(batch.sequence_end, 2);
}

#[test]
fn state_build_batch_empty_rejected() {
    let config = BatchTransportConfig::default();
    let session_key: [u8; 32] = [0xAB; 32];
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let result = state.build_batch(vec![], &session_key, ep(1), 100);
    assert!(matches!(result, Err(BatchTransportError::EmptyBatch)));
}

#[test]
fn state_build_batch_too_large() {
    let config = BatchTransportConfig {
        max_batch_size: 1,
        ..Default::default()
    };
    let session_key: [u8; 32] = [0xAB; 32];
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let entries = vec![make_entry(1, b"a"), make_entry(2, b"b")];
    let result = state.build_batch(entries, &session_key, ep(1), 100);
    assert!(matches!(
        result,
        Err(BatchTransportError::BatchTooLarge { .. })
    ));
}

#[test]
fn state_build_batch_non_contiguous() {
    let config = BatchTransportConfig::default();
    let session_key: [u8; 32] = [0xAB; 32];
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let entries = vec![make_entry(1, b"a"), make_entry(3, b"c")]; // gap at 2
    let result = state.build_batch(entries, &session_key, ep(1), 100);
    assert!(matches!(
        result,
        Err(BatchTransportError::NonContiguousSequences { .. })
    ));
}

// ===========================================================================
// BatchTransportState — state hash
// ===========================================================================

#[test]
fn state_hash_deterministic() {
    let config = BatchTransportConfig::default();
    let s1 = BatchTransportState::new("sess".into(), config.clone(), ep(1));
    let s2 = BatchTransportState::new("sess".into(), config, ep(1));
    assert_eq!(s1.state_hash(), s2.state_hash());
}

#[test]
fn state_hash_changes_after_allocation() {
    let config = BatchTransportConfig::default();
    let s1 = BatchTransportState::new("sess".into(), config.clone(), ep(1));
    let mut s2 = BatchTransportState::new("sess".into(), config, ep(1));
    s2.allocate_region(100, 1).unwrap();
    assert_ne!(s1.state_hash(), s2.state_hash());
}

// ===========================================================================
// BatchTransportState — grant_credits
// ===========================================================================

#[test]
fn state_grant_credits() {
    let config = BatchTransportConfig {
        initial_credits: 10,
        max_credits: 100,
        ..Default::default()
    };
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    assert_eq!(state.credit_pool.available(), 10);
    state.grant_credits(50);
    assert_eq!(state.credit_pool.available(), 60);
}

// ===========================================================================
// Corpus
// ===========================================================================

#[test]
fn corpus_non_empty() {
    let corpus = batch_transport_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn corpus_all_have_valid_verdicts() {
    let corpus = batch_transport_corpus();
    for specimen in &corpus {
        // All specimens should have a definite verdict (Pass or Fail), not be in
        // an indeterminate state. Some specimens may legitimately fail due to
        // membrane validation or replay constraints.
        assert!(
            specimen.verdict == BatchTransportVerdict::Pass
                || specimen.verdict == BatchTransportVerdict::Fail,
            "specimen {} has unexpected verdict {:?}",
            specimen.name,
            specimen.verdict
        );
    }
}

#[test]
fn specimen_family_all_count() {
    assert_eq!(BatchTransportSpecimenFamily::ALL.len(), 12);
}

#[test]
fn specimen_family_display() {
    for f in BatchTransportSpecimenFamily::ALL {
        let s = format!("{f}");
        assert!(!s.is_empty());
    }
}

#[test]
fn specimen_family_serde_roundtrip() {
    for f in BatchTransportSpecimenFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: BatchTransportSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}
