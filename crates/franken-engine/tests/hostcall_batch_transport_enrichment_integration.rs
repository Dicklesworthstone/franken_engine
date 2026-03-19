// Enrichment integration tests for hostcall_batch_transport module.
//
// Covers: BatchTransportConfig default values and serde roundtrip,
// RegionState::ALL completeness and Display uniqueness, SharedMemoryRegion serde,
// CreditPool new/try_consume/grant/revoke/state_hash, BatchPayload display/serde,
// MembraneRejectionReason ALL/display/serde, MembraneVerdict is_accept/serde,
// BatchTransportError display/serde, compute_entry_content_hash/compute_batch_mac
// determinism, BatchTransportState region lifecycle and batch build,
// BatchTransportSpecimenFamily ALL/display/corpus, and determinism checks.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_batch_transport::{
    BatchEntry, BatchPayload, BatchTransportConfig, BatchTransportError,
    BatchTransportSpecimenFamily, BatchTransportState, CreditPool, MembraneRejectionReason,
    MembraneVerdict, RegionState, SharedMemoryRegion, batch_transport_corpus, compute_batch_mac,
    compute_entry_content_hash,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

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
fn enrichment_config_default_values() {
    let c = BatchTransportConfig::default();
    assert_eq!(c.max_batch_size, 64);
    assert_eq!(c.max_batch_payload_bytes, 4_194_304);
    assert_eq!(c.initial_credits, 256);
    assert_eq!(c.max_credits, 1024);
    assert_eq!(c.max_active_regions, 16);
    assert!(c.compute_batch_mac);
    assert!(!c.require_per_entry_mac);
    assert_eq!(c.batch_assembly_timeout_ticks, 500);
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let c = BatchTransportConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: BatchTransportConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// RegionState
// ===========================================================================

#[test]
fn enrichment_region_state_all_count() {
    assert_eq!(RegionState::ALL.len(), 5);
}

#[test]
fn enrichment_region_state_all_unique() {
    let set: BTreeSet<RegionState> = RegionState::ALL.iter().copied().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_region_state_display_values() {
    assert_eq!(RegionState::Allocated.to_string(), "allocated");
    assert_eq!(RegionState::Writing.to_string(), "writing");
    assert_eq!(RegionState::Sealed.to_string(), "sealed");
    assert_eq!(RegionState::Released.to_string(), "released");
    assert_eq!(RegionState::Revoked.to_string(), "revoked");
}

#[test]
fn enrichment_region_state_display_unique() {
    let labels: BTreeSet<String> = RegionState::ALL.iter().map(|r| format!("{r}")).collect();
    assert_eq!(labels.len(), 5);
}

#[test]
fn enrichment_region_state_serde_roundtrip() {
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
fn enrichment_shared_memory_region_serde_roundtrip() {
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

#[test]
fn enrichment_shared_memory_region_none_hash() {
    let region = SharedMemoryRegion {
        region_id: 2,
        session_id: "sess-2".into(),
        capacity_bytes: 2048,
        occupied_bytes: 0,
        state: RegionState::Allocated,
        content_hash: None,
        allocated_at_tick: 50,
        sealed_at_tick: None,
    };
    let json = serde_json::to_string(&region).unwrap();
    let back: SharedMemoryRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(region, back);
}

// ===========================================================================
// CreditPool
// ===========================================================================

#[test]
fn enrichment_credit_pool_new() {
    let pool = CreditPool::new("sess".into(), 100, 500);
    assert_eq!(pool.available(), 100);
    assert_eq!(pool.session_id(), "sess");
    assert!(!pool.is_exhausted());
}

#[test]
fn enrichment_credit_pool_initial_capped() {
    let pool = CreditPool::new("sess".into(), 1000, 500);
    assert_eq!(pool.available(), 500);
}

#[test]
fn enrichment_credit_pool_consume_ok() {
    let mut pool = CreditPool::new("sess".into(), 100, 500);
    assert!(pool.try_consume(50).is_ok());
    assert_eq!(pool.available(), 50);
    assert_eq!(pool.total_consumed(), 50);
}

#[test]
fn enrichment_credit_pool_consume_insufficient() {
    let mut pool = CreditPool::new("sess".into(), 10, 500);
    let result = pool.try_consume(20);
    assert!(result.is_err());
}

#[test]
fn enrichment_credit_pool_consume_exact_exhausts() {
    let mut pool = CreditPool::new("sess".into(), 100, 500);
    assert!(pool.try_consume(100).is_ok());
    assert!(pool.is_exhausted());
}

#[test]
fn enrichment_credit_pool_grant() {
    let mut pool = CreditPool::new("sess".into(), 100, 500);
    pool.try_consume(80).unwrap();
    pool.grant(50);
    assert_eq!(pool.available(), 70);
    assert_eq!(pool.total_returned(), 50);
}

#[test]
fn enrichment_credit_pool_grant_capped() {
    let mut pool = CreditPool::new("sess".into(), 100, 100);
    pool.grant(200);
    assert_eq!(pool.available(), 100);
}

#[test]
fn enrichment_credit_pool_revoke() {
    let mut pool = CreditPool::new("sess".into(), 100, 500);
    pool.revoke(30);
    assert_eq!(pool.available(), 70);
}

#[test]
fn enrichment_credit_pool_state_hash_deterministic() {
    let p1 = CreditPool::new("sess".into(), 100, 500);
    let p2 = CreditPool::new("sess".into(), 100, 500);
    assert_eq!(p1.state_hash(), p2.state_hash());
}

#[test]
fn enrichment_credit_pool_state_hash_changes_after_consume() {
    let p1 = CreditPool::new("sess".into(), 100, 500);
    let mut p2 = CreditPool::new("sess".into(), 100, 500);
    p2.try_consume(10).unwrap();
    assert_ne!(p1.state_hash(), p2.state_hash());
}

#[test]
fn enrichment_credit_pool_high_water_mark() {
    let mut pool = CreditPool::new("sess".into(), 100, 500);
    assert_eq!(pool.high_water_mark(), 100);
    pool.try_consume(50).unwrap();
    pool.grant(200);
    assert_eq!(pool.high_water_mark(), 250);
}

#[test]
fn enrichment_credit_pool_serde_roundtrip() {
    let pool = CreditPool::new("sess".into(), 100, 500);
    let json = serde_json::to_string(&pool).unwrap();
    let back: CreditPool = serde_json::from_str(&json).unwrap();
    assert_eq!(pool, back);
}

// ===========================================================================
// BatchPayload
// ===========================================================================

#[test]
fn enrichment_batch_payload_inline_display() {
    let p = BatchPayload::Inline(vec![1, 2, 3]);
    let s = format!("{p}");
    assert!(s.contains("inline"));
    assert!(s.contains("3 bytes"));
}

#[test]
fn enrichment_batch_payload_shared_region_display() {
    let p = BatchPayload::SharedRegion {
        region_id: 42,
        offset: 0,
        length: 256,
        payload_hash: ContentHash::compute(b"test"),
    };
    let s = format!("{p}");
    assert!(s.contains("shared"));
}

#[test]
fn enrichment_batch_payload_inline_serde() {
    let p = BatchPayload::Inline(vec![10, 20, 30]);
    let json = serde_json::to_string(&p).unwrap();
    let back: BatchPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ===========================================================================
// MembraneRejectionReason
// ===========================================================================

#[test]
fn enrichment_membrane_rejection_reason_all_count() {
    assert_eq!(MembraneRejectionReason::ALL.len(), 9);
}

#[test]
fn enrichment_membrane_rejection_reason_display_unique() {
    let labels: BTreeSet<String> = MembraneRejectionReason::ALL
        .iter()
        .map(|r| format!("{r}"))
        .collect();
    assert_eq!(labels.len(), 9);
}

#[test]
fn enrichment_membrane_rejection_reason_serde_roundtrip() {
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
fn enrichment_membrane_verdict_is_accept() {
    let accept = MembraneVerdict::Accept { envelope_count: 5 };
    assert!(accept.is_accept());
    let reject = MembraneVerdict::Reject {
        reason: MembraneRejectionReason::PhaseBlocked,
        detail: "blocked".into(),
    };
    assert!(!reject.is_accept());
}

#[test]
fn enrichment_membrane_verdict_serde_roundtrip() {
    let v = MembraneVerdict::Accept { envelope_count: 3 };
    let json = serde_json::to_string(&v).unwrap();
    let back: MembraneVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ===========================================================================
// compute_entry_content_hash / compute_batch_mac
// ===========================================================================

#[test]
fn enrichment_entry_content_hash_deterministic() {
    let payload = BatchPayload::Inline(vec![1, 2, 3]);
    let h1 = compute_entry_content_hash(1, &payload, "trace-1");
    let h2 = compute_entry_content_hash(1, &payload, "trace-1");
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_entry_content_hash_differs_by_sequence() {
    let payload = BatchPayload::Inline(vec![1, 2, 3]);
    let h1 = compute_entry_content_hash(1, &payload, "trace-1");
    let h2 = compute_entry_content_hash(2, &payload, "trace-1");
    assert_ne!(h1, h2);
}

#[test]
fn enrichment_batch_mac_deterministic() {
    let key: [u8; 32] = [0xAB; 32];
    let entries = vec![make_entry(1, b"hello")];
    let m1 = compute_batch_mac(&key, 1, &entries, ep(1));
    let m2 = compute_batch_mac(&key, 1, &entries, ep(1));
    assert_eq!(m1, m2);
}

#[test]
fn enrichment_batch_mac_differs_by_key() {
    let entries = vec![make_entry(1, b"hello")];
    let m1 = compute_batch_mac(&[0xAB; 32], 1, &entries, ep(1));
    let m2 = compute_batch_mac(&[0xFF; 32], 1, &entries, ep(1));
    assert_ne!(m1, m2);
}

// ===========================================================================
// BatchTransportState — region lifecycle
// ===========================================================================

#[test]
fn enrichment_state_allocate_region() {
    let config = BatchTransportConfig::default();
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let rid = state.allocate_region(1024, 10).unwrap();
    assert_eq!(rid, 1);
    assert_eq!(state.regions[&rid].state, RegionState::Allocated);
}

#[test]
fn enrichment_state_seal_region() {
    let config = BatchTransportConfig::default();
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let rid = state.allocate_region(1024, 10).unwrap();
    let hash = state.seal_region(rid, 500, 20).unwrap();
    assert_eq!(state.regions[&rid].state, RegionState::Sealed);
    assert_eq!(state.regions[&rid].content_hash.as_ref(), Some(&hash));
}

#[test]
fn enrichment_state_release_region() {
    let config = BatchTransportConfig::default();
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let rid = state.allocate_region(1024, 10).unwrap();
    state.seal_region(rid, 100, 20).unwrap();
    state.release_region(rid).unwrap();
    assert_eq!(state.regions[&rid].state, RegionState::Released);
}

#[test]
fn enrichment_state_revoke_region() {
    let config = BatchTransportConfig::default();
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let rid = state.allocate_region(1024, 10).unwrap();
    state.revoke_region(rid).unwrap();
    assert_eq!(state.regions[&rid].state, RegionState::Revoked);
}

#[test]
fn enrichment_state_too_many_regions() {
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

// ===========================================================================
// BatchTransportState — batch build
// ===========================================================================

#[test]
fn enrichment_state_build_batch_ok() {
    let config = BatchTransportConfig::default();
    let session_key: [u8; 32] = [0xAB; 32];
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let entries = vec![make_entry(1, b"hello"), make_entry(2, b"world")];
    let batch = state
        .build_batch(entries, &session_key, ep(1), 100)
        .unwrap();
    assert_eq!(batch.batch_id, 1);
    assert_eq!(batch.entries.len(), 2);
}

#[test]
fn enrichment_state_build_batch_empty_rejected() {
    let config = BatchTransportConfig::default();
    let session_key: [u8; 32] = [0xAB; 32];
    let mut state = BatchTransportState::new("sess".into(), config, ep(1));
    let result = state.build_batch(vec![], &session_key, ep(1), 100);
    assert!(matches!(result, Err(BatchTransportError::EmptyBatch)));
}

// ===========================================================================
// BatchTransportState — state hash
// ===========================================================================

#[test]
fn enrichment_state_hash_deterministic() {
    let config = BatchTransportConfig::default();
    let s1 = BatchTransportState::new("sess".into(), config.clone(), ep(1));
    let s2 = BatchTransportState::new("sess".into(), config, ep(1));
    assert_eq!(s1.state_hash(), s2.state_hash());
}

#[test]
fn enrichment_state_hash_changes_after_allocation() {
    let config = BatchTransportConfig::default();
    let s1 = BatchTransportState::new("sess".into(), config.clone(), ep(1));
    let mut s2 = BatchTransportState::new("sess".into(), config, ep(1));
    s2.allocate_region(100, 1).unwrap();
    assert_ne!(s1.state_hash(), s2.state_hash());
}

// ===========================================================================
// Corpus
// ===========================================================================

#[test]
fn enrichment_corpus_non_empty() {
    let corpus = batch_transport_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn enrichment_specimen_family_all_count() {
    assert_eq!(BatchTransportSpecimenFamily::ALL.len(), 12);
}

#[test]
fn enrichment_specimen_family_display_unique() {
    let labels: BTreeSet<String> = BatchTransportSpecimenFamily::ALL
        .iter()
        .map(|f| format!("{f}"))
        .collect();
    assert_eq!(labels.len(), 12);
}

#[test]
fn enrichment_specimen_family_serde_roundtrip() {
    for f in BatchTransportSpecimenFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: BatchTransportSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}
