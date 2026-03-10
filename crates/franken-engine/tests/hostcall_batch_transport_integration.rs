//! Integration tests for the `hostcall_batch_transport` module.
//!
//! Covers config defaults, credit pool lifecycle, shared memory region
//! lifecycle, batch building, safety membrane validation, full pipeline
//! flow, corpus evaluation, MAC computation, entry content hashing,
//! state hash determinism, and serde roundtrips.

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

use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::hostcall_batch_transport::{
    BatchEntry, BatchEnvelope, BatchPayload, BatchReceipt, BatchTransportConfig,
    BatchTransportError, BatchTransportSpecimenFamily, BatchTransportState, BatchTransportVerdict,
    CreditPool, MembraneRejectionReason, MembraneVerdict, RegionState, SafetyMembrane,
    SharedMemoryRegion, batch_transport_corpus, compute_batch_mac, compute_entry_content_hash,
    run_batch_transport_corpus,
};
use frankenengine_engine::hostcall_session_protocol::{
    DegradedSeverity, KeyStagePurpose, SessionKeySchedule, SessionPhaseTag, SessionProtocolState,
    TransitionTrigger,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::session_hostcall_channel::BackpressureSignal;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn session_key() -> [u8; 32] {
    [0xAB; 32]
}

fn default_config() -> BatchTransportConfig {
    BatchTransportConfig::default()
}

fn default_state() -> BatchTransportState {
    BatchTransportState::new("test-sess".into(), default_config(), test_epoch())
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

fn established_protocol() -> SessionProtocolState {
    let mut state =
        SessionProtocolState::new("test-sess".into(), "ext".into(), "host".into(), 64, 50);
    state
        .transition(
            SessionPhaseTag::Negotiating,
            TransitionTrigger::HandshakeInitiated,
            1,
        )
        .unwrap();
    state
        .transition(
            SessionPhaseTag::Established,
            TransitionTrigger::HandshakeCompleted,
            2,
        )
        .unwrap();
    state
}

// ===========================================================================
// 1. Config defaults and custom configs
// ===========================================================================

#[test]
fn config_default_max_batch_size() {
    let c = default_config();
    assert_eq!(c.max_batch_size, 64);
}

#[test]
fn config_default_max_batch_payload_bytes() {
    let c = default_config();
    assert_eq!(c.max_batch_payload_bytes, 4_194_304);
}

#[test]
fn config_default_initial_credits() {
    let c = default_config();
    assert_eq!(c.initial_credits, 256);
}

#[test]
fn config_default_max_credits() {
    let c = default_config();
    assert_eq!(c.max_credits, 1024);
}

#[test]
fn config_default_max_active_regions() {
    let c = default_config();
    assert_eq!(c.max_active_regions, 16);
}

#[test]
fn config_default_max_region_size_bytes() {
    let c = default_config();
    assert_eq!(c.max_region_size_bytes, 1_048_576);
}

#[test]
fn config_default_require_per_entry_mac_false() {
    let c = default_config();
    assert!(!c.require_per_entry_mac);
}

#[test]
fn config_default_compute_batch_mac_true() {
    let c = default_config();
    assert!(c.compute_batch_mac);
}

#[test]
fn config_default_batch_assembly_timeout_ticks() {
    let c = default_config();
    assert_eq!(c.batch_assembly_timeout_ticks, 500);
}

#[test]
fn config_custom_values() {
    let c = BatchTransportConfig {
        max_batch_size: 10,
        max_batch_payload_bytes: 1024,
        initial_credits: 5,
        max_credits: 50,
        max_active_regions: 2,
        max_region_size_bytes: 512,
        require_per_entry_mac: true,
        compute_batch_mac: false,
        batch_assembly_timeout_ticks: 100,
    };
    assert_eq!(c.max_batch_size, 10);
    assert_eq!(c.max_batch_payload_bytes, 1024);
    assert_eq!(c.initial_credits, 5);
    assert!(c.require_per_entry_mac);
    assert!(!c.compute_batch_mac);
}

#[test]
fn config_serde_roundtrip() {
    let c = default_config();
    let json = serde_json::to_string(&c).unwrap();
    let back: BatchTransportConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// 2. CreditPool lifecycle
// ===========================================================================

#[test]
fn credit_pool_initial_state() {
    let pool = CreditPool::new("s1".into(), 100, 200);
    assert_eq!(pool.available(), 100);
    assert!(!pool.is_exhausted());
    assert_eq!(pool.total_consumed(), 0);
    assert_eq!(pool.total_returned(), 0);
    assert_eq!(pool.high_water_mark(), 100);
    assert_eq!(pool.session_id(), "s1");
}

#[test]
fn credit_pool_consume_success() {
    let mut pool = CreditPool::new("s".into(), 100, 200);
    pool.try_consume(30).unwrap();
    assert_eq!(pool.available(), 70);
    assert_eq!(pool.total_consumed(), 30);
}

#[test]
fn credit_pool_consume_all() {
    let mut pool = CreditPool::new("s".into(), 50, 200);
    pool.try_consume(50).unwrap();
    assert_eq!(pool.available(), 0);
    assert!(pool.is_exhausted());
}

#[test]
fn credit_pool_consume_insufficient_fails() {
    let mut pool = CreditPool::new("s".into(), 10, 200);
    let result = pool.try_consume(20);
    assert!(result.is_err());
    // Available unchanged on failure.
    assert_eq!(pool.available(), 10);
}

#[test]
fn credit_pool_grant_within_max() {
    let mut pool = CreditPool::new("s".into(), 10, 200);
    pool.try_consume(5).unwrap();
    pool.grant(3);
    assert_eq!(pool.available(), 8);
    assert_eq!(pool.total_returned(), 3);
}

#[test]
fn credit_pool_grant_caps_at_max() {
    let mut pool = CreditPool::new("s".into(), 10, 20);
    pool.grant(50);
    assert_eq!(pool.available(), 20);
}

#[test]
fn credit_pool_revoke_reduces_available() {
    let mut pool = CreditPool::new("s".into(), 100, 200);
    pool.revoke(30);
    assert_eq!(pool.available(), 70);
}

#[test]
fn credit_pool_revoke_saturates_at_zero() {
    let mut pool = CreditPool::new("s".into(), 10, 200);
    pool.revoke(999);
    assert_eq!(pool.available(), 0);
    assert!(pool.is_exhausted());
}

#[test]
fn credit_pool_high_water_mark_tracks_peak() {
    let mut pool = CreditPool::new("s".into(), 50, 200);
    assert_eq!(pool.high_water_mark(), 50);
    pool.grant(60);
    assert_eq!(pool.high_water_mark(), 110);
    pool.try_consume(30).unwrap();
    // high_water_mark should not decrease.
    assert_eq!(pool.high_water_mark(), 110);
}

#[test]
fn credit_pool_state_hash_deterministic() {
    let p1 = CreditPool::new("s".into(), 100, 200);
    let p2 = CreditPool::new("s".into(), 100, 200);
    assert_eq!(p1.state_hash(), p2.state_hash());
}

#[test]
fn credit_pool_state_hash_differs_with_operations() {
    let p1 = CreditPool::new("s".into(), 100, 200);
    let mut p2 = CreditPool::new("s".into(), 100, 200);
    p2.try_consume(1).unwrap();
    assert_ne!(p1.state_hash(), p2.state_hash());
}

#[test]
fn credit_pool_serde_roundtrip() {
    let mut pool = CreditPool::new("s".into(), 100, 200);
    pool.try_consume(10).unwrap();
    pool.grant(5);
    let json = serde_json::to_string(&pool).unwrap();
    let back: CreditPool = serde_json::from_str(&json).unwrap();
    assert_eq!(pool.available(), back.available());
    assert_eq!(pool.total_consumed(), back.total_consumed());
    assert_eq!(pool.total_returned(), back.total_returned());
}

// ===========================================================================
// 3. SharedMemoryRegion lifecycle
// ===========================================================================

#[test]
fn region_allocate_returns_incremented_ids() {
    let mut ts = default_state();
    let r1 = ts.allocate_region(1024, 10).unwrap();
    let r2 = ts.allocate_region(1024, 20).unwrap();
    assert_eq!(r1, 1);
    assert_eq!(r2, 2);
    assert_eq!(ts.regions[&r1].state, RegionState::Allocated);
    assert_eq!(ts.regions[&r2].state, RegionState::Allocated);
}

#[test]
fn region_allocate_respects_capacity_limit() {
    let config = BatchTransportConfig {
        max_region_size_bytes: 100,
        ..Default::default()
    };
    let mut ts = BatchTransportState::new("s".into(), config, test_epoch());
    let result = ts.allocate_region(200, 10);
    assert!(result.is_err());
}

#[test]
fn region_allocate_too_many_active() {
    let config = BatchTransportConfig {
        max_active_regions: 2,
        ..Default::default()
    };
    let mut ts = BatchTransportState::new("s".into(), config, test_epoch());
    ts.allocate_region(100, 10).unwrap();
    ts.allocate_region(100, 20).unwrap();
    let result = ts.allocate_region(100, 30);
    assert!(result.is_err());
}

#[test]
fn region_released_does_not_count_toward_active_limit() {
    let config = BatchTransportConfig {
        max_active_regions: 1,
        ..Default::default()
    };
    let mut ts = BatchTransportState::new("s".into(), config, test_epoch());
    let r1 = ts.allocate_region(100, 10).unwrap();
    ts.seal_region(r1, 50, 20).unwrap();
    ts.release_region(r1).unwrap();
    // Released region should not count, so we can allocate another.
    let r2 = ts.allocate_region(100, 30).unwrap();
    assert_eq!(ts.regions[&r2].state, RegionState::Allocated);
}

#[test]
fn region_seal_sets_state_and_hash() {
    let mut ts = default_state();
    let rid = ts.allocate_region(1024, 10).unwrap();
    let hash = ts.seal_region(rid, 500, 20).unwrap();
    let region = &ts.regions[&rid];
    assert_eq!(region.state, RegionState::Sealed);
    assert_eq!(region.content_hash, Some(hash));
    assert_eq!(region.sealed_at_tick, Some(20));
    assert_eq!(region.occupied_bytes, 500);
}

#[test]
fn region_seal_already_sealed_fails() {
    let mut ts = default_state();
    let rid = ts.allocate_region(1024, 10).unwrap();
    ts.seal_region(rid, 500, 20).unwrap();
    let result = ts.seal_region(rid, 500, 30);
    assert!(result.is_err());
}

#[test]
fn region_seal_exceeds_capacity_fails() {
    let mut ts = default_state();
    let rid = ts.allocate_region(100, 10).unwrap();
    let result = ts.seal_region(rid, 200, 20);
    assert!(result.is_err());
}

#[test]
fn region_release_from_sealed() {
    let mut ts = default_state();
    let rid = ts.allocate_region(1024, 10).unwrap();
    ts.seal_region(rid, 500, 20).unwrap();
    ts.release_region(rid).unwrap();
    assert_eq!(ts.regions[&rid].state, RegionState::Released);
}

#[test]
fn region_release_from_allocated_fails() {
    let mut ts = default_state();
    let rid = ts.allocate_region(1024, 10).unwrap();
    let result = ts.release_region(rid);
    assert!(result.is_err());
}

#[test]
fn region_revoke_from_any_state() {
    let mut ts = default_state();
    let rid = ts.allocate_region(1024, 10).unwrap();
    ts.revoke_region(rid).unwrap();
    assert_eq!(ts.regions[&rid].state, RegionState::Revoked);
}

#[test]
fn region_not_found_error() {
    let mut ts = default_state();
    let result = ts.seal_region(999, 100, 10);
    assert!(result.is_err());
}

#[test]
fn region_state_all_variants() {
    let all = RegionState::ALL;
    assert_eq!(all.len(), 5);
    assert!(all.contains(&RegionState::Allocated));
    assert!(all.contains(&RegionState::Writing));
    assert!(all.contains(&RegionState::Sealed));
    assert!(all.contains(&RegionState::Released));
    assert!(all.contains(&RegionState::Revoked));
}

#[test]
fn region_state_display() {
    assert_eq!(RegionState::Allocated.to_string(), "allocated");
    assert_eq!(RegionState::Writing.to_string(), "writing");
    assert_eq!(RegionState::Sealed.to_string(), "sealed");
    assert_eq!(RegionState::Released.to_string(), "released");
    assert_eq!(RegionState::Revoked.to_string(), "revoked");
}

#[test]
fn region_serde_roundtrip() {
    let region = SharedMemoryRegion {
        region_id: 42,
        session_id: "sess".into(),
        capacity_bytes: 2048,
        occupied_bytes: 1000,
        state: RegionState::Sealed,
        content_hash: Some(ContentHash::compute(b"test")),
        allocated_at_tick: 5,
        sealed_at_tick: Some(10),
    };
    let json = serde_json::to_string(&region).unwrap();
    let back: SharedMemoryRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(region, back);
}

// ===========================================================================
// 4. Batch building
// ===========================================================================

#[test]
fn batch_build_valid() {
    let mut ts = default_state();
    let entries = vec![make_entry(1, b"hello"), make_entry(2, b"world")];
    let batch = ts
        .build_batch(entries, &session_key(), test_epoch(), 100)
        .unwrap();
    assert_eq!(batch.batch_id, 1);
    assert_eq!(batch.session_id, "test-sess");
    assert_eq!(batch.sequence_start, 1);
    assert_eq!(batch.sequence_end, 2);
    assert_eq!(batch.entries.len(), 2);
    assert_eq!(batch.credits_consumed, 2);
    assert_eq!(batch.epoch, test_epoch());
}

#[test]
fn batch_build_empty_rejected() {
    let mut ts = default_state();
    let result = ts.build_batch(Vec::new(), &session_key(), test_epoch(), 100);
    assert!(result.is_err());
}

#[test]
fn batch_build_oversized_rejected() {
    let config = BatchTransportConfig {
        max_batch_size: 1,
        ..Default::default()
    };
    let mut ts = BatchTransportState::new("s".into(), config, test_epoch());
    let entries = vec![make_entry(1, b"a"), make_entry(2, b"b")];
    let result = ts.build_batch(entries, &session_key(), test_epoch(), 100);
    assert!(result.is_err());
}

#[test]
fn batch_build_payload_too_large() {
    let config = BatchTransportConfig {
        max_batch_payload_bytes: 5,
        ..Default::default()
    };
    let mut ts = BatchTransportState::new("s".into(), config, test_epoch());
    let entries = vec![make_entry(1, b"a]long_payload_data_exceeding_limit")];
    let result = ts.build_batch(entries, &session_key(), test_epoch(), 100);
    assert!(result.is_err());
}

#[test]
fn batch_build_non_contiguous_sequences_rejected() {
    let mut ts = default_state();
    let entries = vec![make_entry(1, b"a"), make_entry(3, b"c")];
    let result = ts.build_batch(entries, &session_key(), test_epoch(), 100);
    assert!(result.is_err());
}

#[test]
fn batch_build_increments_batch_id() {
    let mut ts = default_state();
    let e1 = vec![make_entry(1, b"a")];
    let e2 = vec![make_entry(2, b"b")];
    let b1 = ts
        .build_batch(e1, &session_key(), test_epoch(), 100)
        .unwrap();
    let b2 = ts
        .build_batch(e2, &session_key(), test_epoch(), 200)
        .unwrap();
    assert_eq!(b1.batch_id, 1);
    assert_eq!(b2.batch_id, 2);
}

#[test]
fn batch_build_computes_total_payload_bytes() {
    let mut ts = default_state();
    let entries = vec![make_entry(1, b"hello"), make_entry(2, b"world!")];
    let batch = ts
        .build_batch(entries, &session_key(), test_epoch(), 100)
        .unwrap();
    // "hello" = 5 bytes, "world!" = 6 bytes.
    assert_eq!(batch.total_payload_bytes, 11);
}

#[test]
fn batch_envelope_serde_roundtrip() {
    let mut ts = default_state();
    let entries = vec![make_entry(1, b"data")];
    let batch = ts
        .build_batch(entries, &session_key(), test_epoch(), 100)
        .unwrap();
    let json = serde_json::to_string(&batch).unwrap();
    let back: BatchEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, back);
}

// ===========================================================================
// 5. SafetyMembrane validation
// ===========================================================================

#[test]
fn membrane_accepts_valid_batch() {
    let config = default_config();
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config.clone(), epoch);
    let protocol = established_protocol();
    let entries = vec![make_entry(1, b"ok")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();

    let mut membrane = SafetyMembrane::new("s".into(), epoch, 100);
    let credit_pool = CreditPool::new("s".into(), 256, 1024);
    let regions: BTreeMap<u64, SharedMemoryRegion> = BTreeMap::new();
    let verdict = membrane.validate_batch(&batch, &protocol, &credit_pool, &regions, &config, 100);
    assert!(verdict.is_accept());
    assert_eq!(membrane.total_accepted_batches(), 1);
    assert_eq!(membrane.total_rejected_batches(), 0);
}

#[test]
fn membrane_rejects_phase_blocked() {
    let config = default_config();
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config.clone(), epoch);
    // Protocol in Uninit phase, which does not permit data.
    let protocol = SessionProtocolState::new("s".into(), "ext".into(), "host".into(), 64, 50);
    let entries = vec![make_entry(1, b"data")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();

    let mut membrane = SafetyMembrane::new("s".into(), epoch, 100);
    let credit_pool = CreditPool::new("s".into(), 256, 1024);
    let regions: BTreeMap<u64, SharedMemoryRegion> = BTreeMap::new();
    let verdict = membrane.validate_batch(&batch, &protocol, &credit_pool, &regions, &config, 100);
    assert!(!verdict.is_accept());
    assert_eq!(
        membrane.rejection_count(MembraneRejectionReason::PhaseBlocked),
        1
    );
}

#[test]
fn membrane_rejects_epoch_mismatch() {
    let config = default_config();
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config.clone(), epoch);

    // Attach a key schedule at epoch 1 so validate_epoch can detect a mismatch.
    let mut protocol = established_protocol();
    let mut schedule = SessionKeySchedule::new(
        SecurityEpoch::from_raw(1),
        "test-sess".into(),
        "ext".into(),
        "host".into(),
        ContentHash::compute(b"handshake"),
    );
    for purpose in KeyStagePurpose::ALL {
        schedule.record_stage(
            *purpose,
            ContentHash::compute(purpose.domain_label().as_bytes()),
        );
    }
    protocol.attach_key_schedule(schedule).unwrap();

    let entries = vec![make_entry(1, b"data")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();

    // Membrane has a different epoch (999) than the protocol's key schedule (1).
    let mismatched_epoch = SecurityEpoch::from_raw(999);
    let mut membrane = SafetyMembrane::new("s".into(), mismatched_epoch, 100);
    let credit_pool = CreditPool::new("s".into(), 256, 1024);
    let regions: BTreeMap<u64, SharedMemoryRegion> = BTreeMap::new();
    let verdict = membrane.validate_batch(&batch, &protocol, &credit_pool, &regions, &config, 100);
    assert!(!verdict.is_accept());
    assert_eq!(
        membrane.rejection_count(MembraneRejectionReason::EpochMismatch),
        1
    );
}

#[test]
fn membrane_rejects_batch_size_exceeded() {
    let config = BatchTransportConfig {
        max_batch_size: 1,
        ..Default::default()
    };
    let epoch = test_epoch();
    // Use a state with larger max to allow build_batch to succeed.
    let build_config = default_config();
    let mut ts = BatchTransportState::new("s".into(), build_config, epoch);
    let protocol = established_protocol();
    let entries = vec![make_entry(1, b"a"), make_entry(2, b"b")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();

    let mut membrane = SafetyMembrane::new("s".into(), epoch, 100);
    let credit_pool = CreditPool::new("s".into(), 256, 1024);
    let regions: BTreeMap<u64, SharedMemoryRegion> = BTreeMap::new();
    let verdict = membrane.validate_batch(&batch, &protocol, &credit_pool, &regions, &config, 100);
    assert!(!verdict.is_accept());
    assert_eq!(
        membrane.rejection_count(MembraneRejectionReason::BatchSizeExceeded),
        1
    );
}

#[test]
fn membrane_rejects_insufficient_credits() {
    let config = default_config();
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config.clone(), epoch);
    let protocol = established_protocol();
    let entries = vec![make_entry(1, b"data")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();

    let mut membrane = SafetyMembrane::new("s".into(), epoch, 100);
    // Credit pool with 0 credits.
    let credit_pool = CreditPool::new("s".into(), 0, 0);
    let regions: BTreeMap<u64, SharedMemoryRegion> = BTreeMap::new();
    let verdict = membrane.validate_batch(&batch, &protocol, &credit_pool, &regions, &config, 100);
    assert!(!verdict.is_accept());
    assert_eq!(
        membrane.rejection_count(MembraneRejectionReason::InsufficientCredits),
        1
    );
}

#[test]
fn membrane_rejects_degraded_blocked() {
    let config = default_config();
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config.clone(), epoch);
    let mut protocol = established_protocol();
    // Enter degraded mode with high severity to block writes.
    protocol
        .enter_degraded(DegradedSeverity::IdentityCompromised, "bad".into(), 50)
        .unwrap();
    let entries = vec![make_entry(1, b"data")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();

    let mut membrane = SafetyMembrane::new("s".into(), epoch, 100);
    let credit_pool = CreditPool::new("s".into(), 256, 1024);
    let regions: BTreeMap<u64, SharedMemoryRegion> = BTreeMap::new();
    let verdict = membrane.validate_batch(&batch, &protocol, &credit_pool, &regions, &config, 100);
    assert!(!verdict.is_accept());
    assert_eq!(
        membrane.rejection_count(MembraneRejectionReason::DegradedBlocked),
        1
    );
}

#[test]
fn membrane_rejects_invalid_region_not_found() {
    let config = default_config();
    let epoch = test_epoch();

    // Build an entry referencing a shared region that does not exist.
    let payload = BatchPayload::SharedRegion {
        region_id: 999,
        offset: 0,
        length: 100,
        payload_hash: ContentHash::compute(b"test"),
    };
    let content_hash = compute_entry_content_hash(1, &payload, "trace");
    let entry = BatchEntry {
        sequence: 1,
        payload,
        content_hash,
        entry_mac: None,
        trace_id: "trace".into(),
    };

    let build_config = default_config();
    let mut ts = BatchTransportState::new("s".into(), build_config, epoch);
    let protocol = established_protocol();
    let batch = ts
        .build_batch(vec![entry], &session_key(), epoch, 100)
        .unwrap();

    let mut membrane = SafetyMembrane::new("s".into(), epoch, 100);
    let credit_pool = CreditPool::new("s".into(), 256, 1024);
    let regions: BTreeMap<u64, SharedMemoryRegion> = BTreeMap::new();
    let verdict = membrane.validate_batch(&batch, &protocol, &credit_pool, &regions, &config, 100);
    assert!(!verdict.is_accept());
    assert_eq!(
        membrane.rejection_count(MembraneRejectionReason::InvalidRegion),
        1
    );
}

#[test]
fn membrane_rejects_invalid_region_not_sealed() {
    let config = default_config();
    let epoch = test_epoch();

    // Create a region in Allocated state (not sealed).
    let region = SharedMemoryRegion {
        region_id: 1,
        session_id: "s".into(),
        capacity_bytes: 1024,
        occupied_bytes: 0,
        state: RegionState::Allocated,
        content_hash: None,
        allocated_at_tick: 5,
        sealed_at_tick: None,
    };
    let mut regions: BTreeMap<u64, SharedMemoryRegion> = BTreeMap::new();
    regions.insert(1, region);

    let payload = BatchPayload::SharedRegion {
        region_id: 1,
        offset: 0,
        length: 100,
        payload_hash: ContentHash::compute(b"test"),
    };
    let content_hash = compute_entry_content_hash(1, &payload, "trace");
    let entry = BatchEntry {
        sequence: 1,
        payload,
        content_hash,
        entry_mac: None,
        trace_id: "trace".into(),
    };

    let build_config = default_config();
    let mut ts = BatchTransportState::new("s".into(), build_config, epoch);
    let protocol = established_protocol();
    let batch = ts
        .build_batch(vec![entry], &session_key(), epoch, 100)
        .unwrap();

    let mut membrane = SafetyMembrane::new("s".into(), epoch, 100);
    let credit_pool = CreditPool::new("s".into(), 256, 1024);
    let verdict = membrane.validate_batch(&batch, &protocol, &credit_pool, &regions, &config, 100);
    assert!(!verdict.is_accept());
    assert_eq!(
        membrane.rejection_count(MembraneRejectionReason::InvalidRegion),
        1
    );
}

#[test]
fn membrane_rejects_sequence_gap() {
    let config = default_config();
    let epoch = test_epoch();

    // Build a batch with non-contiguous sequences directly.
    let entry1 = make_entry(1, b"a");
    let entry2 = make_entry(3, b"c"); // gap at 2
    let batch = BatchEnvelope {
        batch_id: 1,
        session_id: "s".into(),
        entries: vec![entry1, entry2],
        sequence_start: 1,
        sequence_end: 3,
        credits_consumed: 2,
        total_payload_bytes: 2,
        batch_mac: AuthenticityHash::compute_keyed(&session_key(), b"dummy"),
        sealed_at_tick: 100,
        epoch,
    };

    let mut membrane = SafetyMembrane::new("s".into(), epoch, 100);
    let credit_pool = CreditPool::new("s".into(), 256, 1024);
    let regions: BTreeMap<u64, SharedMemoryRegion> = BTreeMap::new();
    let protocol = established_protocol();
    let verdict = membrane.validate_batch(&batch, &protocol, &credit_pool, &regions, &config, 100);
    assert!(!verdict.is_accept());
    assert_eq!(
        membrane.rejection_count(MembraneRejectionReason::SequenceGap),
        1
    );
}

#[test]
fn membrane_audit_trail_records_decisions() {
    let config = default_config();
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config.clone(), epoch);
    let protocol = established_protocol();

    let mut membrane = SafetyMembrane::new("s".into(), epoch, 100);
    let credit_pool = CreditPool::new("s".into(), 256, 1024);
    let regions: BTreeMap<u64, SharedMemoryRegion> = BTreeMap::new();

    // Submit a valid batch.
    let entries = vec![make_entry(1, b"ok")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();
    membrane.validate_batch(&batch, &protocol, &credit_pool, &regions, &config, 100);

    let trail = membrane.audit_trail();
    assert_eq!(trail.len(), 1);
    assert!(trail[0].accepted);
    assert_eq!(trail[0].batch_id, 1);
}

#[test]
fn membrane_update_epoch() {
    let epoch1 = SecurityEpoch::from_raw(1);
    let epoch2 = SecurityEpoch::from_raw(2);
    let mut membrane = SafetyMembrane::new("s".into(), epoch1, 100);
    membrane.update_epoch(epoch2);
    // After updating epoch, the membrane uses the new epoch for validation.
    assert_eq!(membrane.total_accepted_batches(), 0);
}

#[test]
fn membrane_rejection_reason_all_variants() {
    let all = MembraneRejectionReason::ALL;
    assert_eq!(all.len(), 9);
}

#[test]
fn membrane_rejection_reason_display() {
    assert_eq!(
        MembraneRejectionReason::PhaseBlocked.to_string(),
        "phase_blocked"
    );
    assert_eq!(
        MembraneRejectionReason::EpochMismatch.to_string(),
        "epoch_mismatch"
    );
    assert_eq!(
        MembraneRejectionReason::SequenceGap.to_string(),
        "sequence_gap"
    );
}

// ===========================================================================
// 6. Full pipeline: allocate -> seal -> build -> submit -> receipt
// ===========================================================================

#[test]
fn full_pipeline_inline_payload() {
    let config = default_config();
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config, epoch);
    let protocol = established_protocol();

    let entries = vec![make_entry(1, b"payload1"), make_entry(2, b"payload2")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();
    let receipt = ts.submit_batch(batch, &protocol, 100).unwrap();

    assert_eq!(receipt.batch_id, 1);
    assert_eq!(receipt.sequence_start, 1);
    assert_eq!(receipt.sequence_end, 2);
    assert_eq!(receipt.envelope_count, 2);
    assert_eq!(receipt.credits_consumed, 2);
    assert_eq!(receipt.accepted_at_tick, 100);
    assert_eq!(ts.accepted_batches.len(), 1);
    assert_eq!(ts.total_envelopes, 2);
}

#[test]
fn full_pipeline_shared_region_payload() {
    let config = default_config();
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config, epoch);
    let protocol = established_protocol();

    // Allocate and seal a region.
    let rid = ts.allocate_region(4096, 10).unwrap();
    let hash = ts.seal_region(rid, 1024, 20).unwrap();

    // Build an entry referencing the sealed region.
    let payload = BatchPayload::SharedRegion {
        region_id: rid,
        offset: 0,
        length: 1024,
        payload_hash: hash.clone(),
    };
    let content_hash = compute_entry_content_hash(1, &payload, "trace-region");
    let entry = BatchEntry {
        sequence: 1,
        payload,
        content_hash,
        entry_mac: None,
        trace_id: "trace-region".into(),
    };

    let batch = ts
        .build_batch(vec![entry], &session_key(), epoch, 100)
        .unwrap();
    let receipt = ts.submit_batch(batch, &protocol, 100).unwrap();
    assert_eq!(receipt.envelope_count, 1);
    assert_eq!(ts.total_shared_bytes, 1024);
}

#[test]
fn full_pipeline_grant_credits_after_submit() {
    let config = BatchTransportConfig {
        initial_credits: 10,
        max_credits: 100,
        ..Default::default()
    };
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config, epoch);
    let protocol = established_protocol();

    let entries = vec![make_entry(1, b"a"), make_entry(2, b"b")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();
    ts.submit_batch(batch, &protocol, 100).unwrap();

    let after_submit = ts.credit_pool.available();
    ts.grant_credits(5);
    assert_eq!(ts.credit_pool.available(), after_submit + 5);
}

#[test]
fn full_pipeline_multiple_batches() {
    let config = default_config();
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config, epoch);
    let protocol = established_protocol();

    for i in 0..5u64 {
        let seq_start = i * 2 + 1;
        let entries = vec![make_entry(seq_start, b"a"), make_entry(seq_start + 1, b"b")];
        let batch = ts
            .build_batch(entries, &session_key(), epoch, 100 + i)
            .unwrap();
        ts.submit_batch(batch, &protocol, 100 + i).unwrap();
    }
    assert_eq!(ts.accepted_batches.len(), 5);
    assert_eq!(ts.total_envelopes, 10);
}

#[test]
fn full_pipeline_membrane_rejection_returns_error() {
    let config = default_config();
    let epoch = test_epoch();
    let mut ts = BatchTransportState::new("s".into(), config, epoch);
    // Use uninit protocol to trigger phase blocked.
    let protocol = SessionProtocolState::new("s".into(), "ext".into(), "host".into(), 64, 50);

    let entries = vec![make_entry(1, b"blocked")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();
    let result = ts.submit_batch(batch, &protocol, 100);
    assert!(result.is_err());
}

// ===========================================================================
// 7. Corpus tests
// ===========================================================================

#[test]
fn corpus_non_empty() {
    let corpus = batch_transport_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn corpus_all_pass() {
    let corpus = batch_transport_corpus();
    for specimen in &corpus {
        assert_eq!(
            specimen.verdict,
            BatchTransportVerdict::Pass,
            "specimen '{}' did not pass",
            specimen.name
        );
    }
}

#[test]
fn corpus_covers_all_families() {
    let corpus = batch_transport_corpus();
    let families: std::collections::BTreeSet<_> = corpus.iter().map(|s| s.family).collect();
    for family in BatchTransportSpecimenFamily::ALL {
        assert!(families.contains(family), "corpus missing family: {family}");
    }
}

#[test]
fn corpus_unique_names() {
    let corpus = batch_transport_corpus();
    let names: std::collections::BTreeSet<_> = corpus.iter().map(|s| s.name.clone()).collect();
    assert_eq!(names.len(), corpus.len(), "duplicate specimen names found");
}

#[test]
fn corpus_specimen_serde_roundtrip() {
    let corpus = batch_transport_corpus();
    for specimen in &corpus {
        let json = serde_json::to_string(specimen).unwrap();
        let back: frankenengine_engine::hostcall_batch_transport::BatchTransportSpecimen =
            serde_json::from_str(&json).unwrap();
        assert_eq!(specimen.name, back.name);
        assert_eq!(specimen.family, back.family);
        assert_eq!(specimen.verdict, back.verdict);
    }
}

#[test]
fn corpus_runner_all_pass() {
    let result = run_batch_transport_corpus();
    assert!(result.all_pass);
    assert_eq!(result.fail_count, 0);
    assert_eq!(result.pass_count, result.specimen_count);
}

#[test]
fn corpus_runner_families_covered() {
    let result = run_batch_transport_corpus();
    assert!(!result.families_covered.is_empty());
    assert_eq!(
        result.families_covered.len(),
        BatchTransportSpecimenFamily::ALL.len()
    );
}

#[test]
fn corpus_runner_result_serde_roundtrip() {
    let result = run_batch_transport_corpus();
    let json = serde_json::to_string(&result).unwrap();
    let back: frankenengine_engine::hostcall_batch_transport::BatchTransportRunnerResult =
        serde_json::from_str(&json).unwrap();
    assert_eq!(result.specimen_count, back.specimen_count);
    assert_eq!(result.all_pass, back.all_pass);
}

// ===========================================================================
// 8. Batch MAC computation
// ===========================================================================

#[test]
fn batch_mac_deterministic() {
    let entries = vec![make_entry(1, b"test")];
    let mac1 = compute_batch_mac(&session_key(), 1, &entries, test_epoch());
    let mac2 = compute_batch_mac(&session_key(), 1, &entries, test_epoch());
    assert_eq!(mac1, mac2);
}

#[test]
fn batch_mac_varies_with_key() {
    let entries = vec![make_entry(1, b"test")];
    let mac1 = compute_batch_mac(&[0xAB; 32], 1, &entries, test_epoch());
    let mac2 = compute_batch_mac(&[0xCD; 32], 1, &entries, test_epoch());
    assert_ne!(mac1, mac2);
}

#[test]
fn batch_mac_varies_with_batch_id() {
    let entries = vec![make_entry(1, b"test")];
    let mac1 = compute_batch_mac(&session_key(), 1, &entries, test_epoch());
    let mac2 = compute_batch_mac(&session_key(), 2, &entries, test_epoch());
    assert_ne!(mac1, mac2);
}

#[test]
fn batch_mac_varies_with_epoch() {
    let entries = vec![make_entry(1, b"test")];
    let epoch1 = SecurityEpoch::from_raw(1);
    let epoch2 = SecurityEpoch::from_raw(2);
    let mac1 = compute_batch_mac(&session_key(), 1, &entries, epoch1);
    let mac2 = compute_batch_mac(&session_key(), 1, &entries, epoch2);
    assert_ne!(mac1, mac2);
}

#[test]
fn batch_mac_varies_with_entries() {
    let entries1 = vec![make_entry(1, b"alpha")];
    let entries2 = vec![make_entry(1, b"beta")];
    let mac1 = compute_batch_mac(&session_key(), 1, &entries1, test_epoch());
    let mac2 = compute_batch_mac(&session_key(), 1, &entries2, test_epoch());
    assert_ne!(mac1, mac2);
}

// ===========================================================================
// 9. Entry content hash computation
// ===========================================================================

#[test]
fn entry_content_hash_deterministic() {
    let payload = BatchPayload::Inline(b"hello".to_vec());
    let h1 = compute_entry_content_hash(1, &payload, "trace-1");
    let h2 = compute_entry_content_hash(1, &payload, "trace-1");
    assert_eq!(h1, h2);
}

#[test]
fn entry_content_hash_varies_with_sequence() {
    let payload = BatchPayload::Inline(b"hello".to_vec());
    let h1 = compute_entry_content_hash(1, &payload, "trace");
    let h2 = compute_entry_content_hash(2, &payload, "trace");
    assert_ne!(h1, h2);
}

#[test]
fn entry_content_hash_varies_with_data() {
    let p1 = BatchPayload::Inline(b"alpha".to_vec());
    let p2 = BatchPayload::Inline(b"beta".to_vec());
    let h1 = compute_entry_content_hash(1, &p1, "trace");
    let h2 = compute_entry_content_hash(1, &p2, "trace");
    assert_ne!(h1, h2);
}

#[test]
fn entry_content_hash_varies_with_trace_id() {
    let payload = BatchPayload::Inline(b"data".to_vec());
    let h1 = compute_entry_content_hash(1, &payload, "trace-a");
    let h2 = compute_entry_content_hash(1, &payload, "trace-b");
    assert_ne!(h1, h2);
}

#[test]
fn entry_content_hash_shared_region_payload() {
    let payload = BatchPayload::SharedRegion {
        region_id: 5,
        offset: 0,
        length: 1024,
        payload_hash: ContentHash::compute(b"region-data"),
    };
    let h = compute_entry_content_hash(1, &payload, "trace");
    // Just verify it computes without panic and is deterministic.
    let h2 = compute_entry_content_hash(1, &payload, "trace");
    assert_eq!(h, h2);
}

#[test]
fn entry_content_hash_backpressure_payload() {
    let payload = BatchPayload::Backpressure(BackpressureSignal {
        pending_messages: 10,
        limit: 50,
    });
    let h = compute_entry_content_hash(1, &payload, "trace");
    let h2 = compute_entry_content_hash(1, &payload, "trace");
    assert_eq!(h, h2);
}

// ===========================================================================
// 10. BatchTransportState state_hash determinism
// ===========================================================================

#[test]
fn state_hash_deterministic_for_same_state() {
    let ts1 = default_state();
    let ts2 = default_state();
    assert_eq!(ts1.state_hash(), ts2.state_hash());
}

#[test]
fn state_hash_changes_after_batch_submission() {
    let epoch = test_epoch();
    let mut ts = default_state();
    let hash_before = ts.state_hash();

    let protocol = established_protocol();
    let entries = vec![make_entry(1, b"change")];
    let batch = ts.build_batch(entries, &session_key(), epoch, 100).unwrap();
    ts.submit_batch(batch, &protocol, 100).unwrap();

    let hash_after = ts.state_hash();
    assert_ne!(hash_before, hash_after);
}

#[test]
fn state_hash_changes_after_region_allocation() {
    let mut ts = default_state();
    let hash_before = ts.state_hash();
    ts.allocate_region(1024, 10).unwrap();
    let hash_after = ts.state_hash();
    assert_ne!(hash_before, hash_after);
}

#[test]
fn state_hash_different_sessions() {
    let ts1 = BatchTransportState::new("sess-a".into(), default_config(), test_epoch());
    let ts2 = BatchTransportState::new("sess-b".into(), default_config(), test_epoch());
    assert_ne!(ts1.state_hash(), ts2.state_hash());
}

// ===========================================================================
// 11. Serde roundtrips for key types
// ===========================================================================

#[test]
fn batch_entry_serde_roundtrip() {
    let entry = make_entry(42, b"serde-test");
    let json = serde_json::to_string(&entry).unwrap();
    let back: BatchEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn batch_payload_inline_serde_roundtrip() {
    let payload = BatchPayload::Inline(vec![1, 2, 3]);
    let json = serde_json::to_string(&payload).unwrap();
    let back: BatchPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, back);
}

#[test]
fn batch_payload_shared_region_serde_roundtrip() {
    let payload = BatchPayload::SharedRegion {
        region_id: 7,
        offset: 128,
        length: 512,
        payload_hash: ContentHash::compute(b"test-hash"),
    };
    let json = serde_json::to_string(&payload).unwrap();
    let back: BatchPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, back);
}

#[test]
fn batch_payload_backpressure_serde_roundtrip() {
    let payload = BatchPayload::Backpressure(BackpressureSignal {
        pending_messages: 5,
        limit: 20,
    });
    let json = serde_json::to_string(&payload).unwrap();
    let back: BatchPayload = serde_json::from_str(&json).unwrap();
    assert_eq!(payload, back);
}

#[test]
fn batch_receipt_serde_roundtrip() {
    let receipt = BatchReceipt {
        batch_id: 1,
        session_id: "s".into(),
        sequence_start: 1,
        sequence_end: 5,
        envelope_count: 5,
        credits_consumed: 5,
        batch_content_hash: ContentHash::compute(b"receipt"),
        accepted_at_tick: 200,
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: BatchReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn batch_transport_error_serde_roundtrip() {
    let err = BatchTransportError::BatchTooLarge { size: 100, max: 64 };
    let json = serde_json::to_string(&err).unwrap();
    let back: BatchTransportError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn membrane_verdict_accept_serde_roundtrip() {
    let v = MembraneVerdict::Accept { envelope_count: 3 };
    let json = serde_json::to_string(&v).unwrap();
    let back: MembraneVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn membrane_verdict_reject_serde_roundtrip() {
    let v = MembraneVerdict::Reject {
        reason: MembraneRejectionReason::PhaseBlocked,
        detail: "blocked".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: MembraneVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn batch_transport_state_serde_roundtrip() {
    let mut ts = default_state();
    ts.allocate_region(1024, 10).unwrap();
    let json = serde_json::to_string(&ts).unwrap();
    let back: BatchTransportState = serde_json::from_str(&json).unwrap();
    assert_eq!(ts.session_id, back.session_id);
    assert_eq!(ts.next_region_id, back.next_region_id);
    assert_eq!(ts.regions.len(), back.regions.len());
}

#[test]
fn batch_payload_display_inline() {
    let payload = BatchPayload::Inline(vec![0; 10]);
    let s = format!("{payload}");
    assert!(s.contains("inline"));
    assert!(s.contains("10 bytes"));
}

#[test]
fn batch_payload_display_shared_region() {
    let payload = BatchPayload::SharedRegion {
        region_id: 3,
        offset: 0,
        length: 256,
        payload_hash: ContentHash::compute(b"x"),
    };
    let s = format!("{payload}");
    assert!(s.contains("shared"));
    assert!(s.contains("region=3"));
}

#[test]
fn batch_payload_display_backpressure() {
    let payload = BatchPayload::Backpressure(BackpressureSignal {
        pending_messages: 7,
        limit: 20,
    });
    let s = format!("{payload}");
    assert!(s.contains("backpressure"));
    assert!(s.contains("7/20"));
}

#[test]
fn batch_transport_error_display() {
    let err = BatchTransportError::EmptyBatch;
    assert_eq!(format!("{err}"), "empty batch");

    let err2 = BatchTransportError::InsufficientCredits {
        requested: 10,
        available: 3,
    };
    let s = format!("{err2}");
    assert!(s.contains("insufficient credits"));
}

#[test]
fn specimen_family_display() {
    assert_eq!(
        BatchTransportSpecimenFamily::HappyPath.to_string(),
        "happy_path"
    );
    assert_eq!(
        BatchTransportSpecimenFamily::CreditExhaustion.to_string(),
        "credit_exhaustion"
    );
}

#[test]
fn evidence_bundle_write_succeeds() {
    let dir = std::env::temp_dir().join("batch_transport_evidence_test");
    let _ = std::fs::create_dir_all(&dir);
    let result =
        frankenengine_engine::hostcall_batch_transport::write_batch_transport_evidence_bundle(&dir);
    assert!(result.is_ok());
    assert!(dir.join("batch_transport_inventory.json").exists());
    assert!(dir.join("batch_transport_manifest.json").exists());
    assert!(dir.join("batch_transport_events.jsonl").exists());
    assert!(dir.join("batch_transport_commands.txt").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
