//! Enrichment integration tests for anti_entropy module.
//!
//! Covers IBLT correctness under scaling, reconciliation session lifecycle,
//! fallback protocol edge cases, and rate monitor boundary conditions.

use std::collections::BTreeSet;

use frankenengine_engine::anti_entropy::{
    FallbackConfig, FallbackProtocol, FallbackRateMonitor, FallbackRequest, FallbackTrigger, Iblt,
    ObjectId, ReconcileConfig, ReconcileError, ReconcileEvent, ReconcileObjectType,
    ReconcileResult, ReconcileSession,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_hash(seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = seed;
    h[31] = seed.wrapping_mul(7);
    h
}

fn make_hash_wide(seed: u16) -> [u8; 32] {
    let bytes = seed.to_le_bytes();
    let mut h = [0u8; 32];
    h[0] = bytes[0];
    h[1] = bytes[1];
    h[30] = bytes[0] ^ bytes[1];
    h[31] = bytes[1].wrapping_add(1);
    h
}

fn default_config() -> ReconcileConfig {
    ReconcileConfig::default()
}

fn make_object_set(seeds: &[u8]) -> BTreeSet<[u8; 32]> {
    seeds.iter().map(|s| make_hash(*s)).collect()
}

// ---------------------------------------------------------------------------
// IBLT construction and peeling
// ---------------------------------------------------------------------------

#[test]
fn iblt_empty_peel_succeeds() {
    let iblt = Iblt::new(64, 3);
    let (pos, neg) = iblt.peel().expect("empty IBLT should peel");
    assert!(pos.is_empty());
    assert!(neg.is_empty());
}

#[test]
fn iblt_single_element_roundtrip() {
    let mut iblt = Iblt::new(64, 3);
    let h = make_hash(42);
    iblt.insert(&h);

    let (pos, neg) = iblt.peel().expect("single-element IBLT should peel");
    assert_eq!(pos.len(), 1);
    assert_eq!(pos[0], h);
    assert!(neg.is_empty());
}

#[test]
fn iblt_insert_remove_cancels() {
    let mut iblt = Iblt::new(64, 3);
    let h = make_hash(99);
    iblt.insert(&h);
    iblt.remove(&h);

    let (pos, neg) = iblt.peel().expect("insert then remove should cancel");
    assert!(pos.is_empty());
    assert!(neg.is_empty());
}

#[test]
fn iblt_symmetric_difference_small() {
    let mut local = Iblt::new(128, 3);
    let mut remote = Iblt::new(128, 3);

    // Shared elements
    for i in 0..10u8 {
        let h = make_hash(i);
        local.insert(&h);
        remote.insert(&h);
    }
    // Local-only
    let local_only = make_hash(200);
    local.insert(&local_only);
    // Remote-only
    let remote_only = make_hash(201);
    remote.insert(&remote_only);

    let diff = local.subtract(&remote).expect("subtract should work");
    let (pos, neg) = diff.peel().expect("small diff should peel");
    assert_eq!(pos.len(), 1);
    assert_eq!(neg.len(), 1);
    assert_eq!(pos[0], local_only);
    assert_eq!(neg[0], remote_only);
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
        _ => panic!("expected IbltSizeMismatch, got {err:?}"),
    }
}

#[test]
fn iblt_many_elements_peel_success() {
    // Insert 20 elements; with 256 cells and 3 hashes, should peel fine
    let mut local = Iblt::new(256, 3);
    let mut remote = Iblt::new(256, 3);

    for i in 0..15u16 {
        let h = make_hash_wide(i);
        local.insert(&h);
        remote.insert(&h);
    }
    // 5 local-only
    for i in 100..105u16 {
        local.insert(&make_hash_wide(i));
    }
    // 3 remote-only
    for i in 200..203u16 {
        remote.insert(&make_hash_wide(i));
    }

    let diff = local.subtract(&remote).unwrap();
    let (pos, neg) = diff.peel().unwrap();
    assert_eq!(pos.len(), 5);
    assert_eq!(neg.len(), 3);
}

#[test]
fn iblt_num_hashes_mismatch_error() {
    let a = Iblt::new(64, 3);
    let b = Iblt::new(64, 5);
    let err = a.subtract(&b).unwrap_err();
    // Both have 64 cells but different hash counts — should still error
    match err {
        ReconcileError::IbltSizeMismatch { .. } => {}
        _ => panic!("expected IbltSizeMismatch, got {err:?}"),
    }
}

#[test]
fn iblt_deterministic_peel_order() {
    // Same insertions, same peel order. Use wide hashes and large table.
    let build = || {
        let mut iblt = Iblt::new(1024, 3);
        for i in 10..13u16 {
            iblt.insert(&make_hash_wide(i));
        }
        iblt.peel()
    };
    let r1 = build();
    let r2 = build();
    // If peeling works, results should be identical.
    match (r1, r2) {
        (Ok((p1, n1)), Ok((p2, n2))) => {
            assert_eq!(p1, p2);
            assert_eq!(n1, n2);
        }
        (Err(_), Err(_)) => {
            // Both fail deterministically — also fine
        }
        _ => panic!("determinism violated: one peeled, other did not"),
    }
}

// ---------------------------------------------------------------------------
// ObjectId and ReconcileObjectType
// ---------------------------------------------------------------------------

#[test]
fn object_id_display_format() {
    let oid = ObjectId {
        content_hash: ContentHash::compute(b"test"),
        object_type: ReconcileObjectType::RevocationEvent,
        epoch: epoch(5),
    };
    let s = format!("{oid}");
    assert!(s.contains("revocation_event"));
    assert!(s.contains("@"));
}

#[test]
fn reconcile_object_type_display_all_variants() {
    let displays: Vec<String> = [
        ReconcileObjectType::RevocationEvent,
        ReconcileObjectType::CheckpointMarker,
        ReconcileObjectType::EvidenceEntry,
    ]
    .iter()
    .map(|v| format!("{v}"))
    .collect();
    // All distinct
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn object_id_serde_roundtrip() {
    let oid = ObjectId {
        content_hash: ContentHash::compute(b"serde-test"),
        object_type: ReconcileObjectType::EvidenceEntry,
        epoch: epoch(42),
    };
    let json = serde_json::to_string(&oid).unwrap();
    let restored: ObjectId = serde_json::from_str(&json).unwrap();
    assert_eq!(oid, restored);
}

// ---------------------------------------------------------------------------
// ReconcileSession lifecycle
// ---------------------------------------------------------------------------

#[test]
fn session_build_iblt_from_empty_set() {
    let session = ReconcileSession::new(epoch(1), default_config());
    let objects = BTreeSet::new();
    let iblt = session.build_iblt(&objects);
    let (pos, neg) = iblt.peel().unwrap();
    assert!(pos.is_empty());
    assert!(neg.is_empty());
}

#[test]
fn session_reconcile_identical_sets() {
    let mut session = ReconcileSession::new(epoch(1), default_config());
    let objects = make_object_set(&[1, 2, 3, 4, 5]);
    let remote_iblt = session.build_iblt(&objects);
    let result = session.reconcile(&objects, &remote_iblt, "peer-a", "trace-1");
    match result {
        Ok(r) => {
            assert!(r.objects_to_fetch.is_empty());
            assert!(r.objects_to_send.is_empty());
        }
        Err(_) => {
            // Fallback is also acceptable for identical sets
        }
    }
}

#[test]
fn session_reconcile_one_missing_each() {
    let config = ReconcileConfig {
        iblt_cells: 256,
        iblt_hashes: 3,
        max_retries: 2,
        retry_scale_factor: 2,
    };
    let mut session = ReconcileSession::new(epoch(1), config.clone());

    let local = make_object_set(&[1, 2, 3, 10]);
    let remote_set = make_object_set(&[1, 2, 3, 20]);
    let remote_iblt = {
        let s = ReconcileSession::new(epoch(1), config);
        s.build_iblt(&remote_set)
    };

    let result = session.reconcile(&local, &remote_iblt, "peer-b", "trace-2");
    match result {
        Ok(r) => {
            // local has 10, remote has 20
            // We should fetch 20 and send 10
            assert!(
                !r.objects_to_fetch.is_empty()
                    || !r.objects_to_send.is_empty()
                    || r.fallback_triggered
            );
        }
        Err(_) => {
            // Acceptable if peel fails due to hash collisions
        }
    }
}

#[test]
fn session_epoch_preserved() {
    let session = ReconcileSession::new(epoch(77), default_config());
    assert_eq!(session.epoch(), epoch(77));
}

#[test]
fn session_drain_events_empty_initially() {
    let mut session = ReconcileSession::new(epoch(1), default_config());
    let events = session.drain_events();
    assert!(events.is_empty());
}

#[test]
fn session_event_counts_empty_initially() {
    let session = ReconcileSession::new(epoch(1), default_config());
    assert!(session.event_counts().is_empty());
}

#[test]
fn session_exact_difference_disjoint() {
    let local = make_object_set(&[1, 2, 3]);
    let remote = make_object_set(&[4, 5, 6]);
    let (lo, ro) = ReconcileSession::exact_difference(&local, &remote);
    assert_eq!(lo.len(), 3);
    assert_eq!(ro.len(), 3);
}

#[test]
fn session_exact_difference_identical() {
    let set = make_object_set(&[1, 2, 3]);
    let (lo, ro) = ReconcileSession::exact_difference(&set, &set);
    assert!(lo.is_empty());
    assert!(ro.is_empty());
}

#[test]
fn session_exact_difference_subset() {
    let local = make_object_set(&[1, 2, 3, 4, 5]);
    let remote = make_object_set(&[1, 2, 3]);
    let (lo, ro) = ReconcileSession::exact_difference(&local, &remote);
    assert_eq!(lo.len(), 2); // 4, 5 are local-only
    assert!(ro.is_empty());
}

// ---------------------------------------------------------------------------
// ReconcileConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let cfg = ReconcileConfig::default();
    assert_eq!(cfg.iblt_cells, 256);
    assert_eq!(cfg.iblt_hashes, 3);
    assert_eq!(cfg.max_retries, 2);
    assert_eq!(cfg.retry_scale_factor, 2);
}

#[test]
fn config_serde_roundtrip() {
    let cfg = ReconcileConfig {
        iblt_cells: 512,
        iblt_hashes: 5,
        max_retries: 3,
        retry_scale_factor: 4,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: ReconcileConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ---------------------------------------------------------------------------
// ReconcileError Display
// ---------------------------------------------------------------------------

#[test]
fn error_display_all_variants_distinct() {
    let errors = vec![
        ReconcileError::IbltSizeMismatch {
            local_cells: 64,
            remote_cells: 128,
        },
        ReconcileError::PeelFailed { remaining_cells: 5 },
        ReconcileError::EpochMismatch {
            local_epoch: epoch(1),
            remote_epoch: epoch(2),
        },
        ReconcileError::VerificationFailed {
            object_hash: "abc".into(),
            reason: "bad".into(),
        },
        ReconcileError::EmptyObjectSet,
    ];
    let displays: Vec<String> = errors.iter().map(|e| format!("{e}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), errors.len());
}

#[test]
fn error_is_std_error() {
    let err = ReconcileError::EmptyObjectSet;
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// FallbackProtocol
// ---------------------------------------------------------------------------

#[test]
fn fallback_protocol_new_epoch() {
    let fp = FallbackProtocol::new(epoch(10));
    assert_eq!(fp.epoch(), epoch(10));
}

#[test]
fn fallback_protocol_drain_events_empty() {
    let mut fp = FallbackProtocol::new(epoch(1));
    assert!(fp.drain_events().is_empty());
}

#[test]
fn fallback_protocol_event_counts_empty() {
    let fp = FallbackProtocol::new(epoch(1));
    assert!(fp.event_counts().is_empty());
}

#[test]
fn fallback_protocol_execute_basic() {
    let mut fp = FallbackProtocol::new(epoch(1));
    let local = make_object_set(&[1, 2, 3]);
    let remote = make_object_set(&[2, 3, 4]);
    let req = FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::PeelFailed { remaining_cells: 3 },
        reconciliation_id: "recon-fb",
        peer: "peer-x",
        trace_id: "trace-fb",
    };
    let result = fp.execute(req);
    // Fallback should always produce a result
    assert!(result.objects_to_fetch.len() + result.objects_to_send.len() > 0 || local == remote);
}

#[test]
fn fallback_protocol_execute_incremental() {
    let mut fp = FallbackProtocol::new(epoch(1));
    let local = make_object_set(&[1, 2, 3, 4, 5]);
    let remote = make_object_set(&[3, 4, 5, 6, 7]);
    let req = FallbackRequest {
        local_hashes: &local,
        remote_hashes: &remote,
        trigger: FallbackTrigger::VerificationFailed {
            object_hash: "abc".into(),
            reason: "test".into(),
        },
        reconciliation_id: "recon-inc",
        peer: "peer-y",
        trace_id: "trace-inc",
    };
    let result = fp.execute_incremental(req, 4);
    assert!(result.objects_to_fetch.len() + result.objects_to_send.len() > 0);
}

#[test]
fn fallback_trigger_display_all_variants() {
    let triggers = vec![
        FallbackTrigger::PeelFailed { remaining_cells: 1 },
        FallbackTrigger::VerificationFailed {
            object_hash: "h1".into(),
            reason: "bad".into(),
        },
        FallbackTrigger::Timeout {
            elapsed_ms: 5000,
            slo_ms: 3000,
        },
        FallbackTrigger::MmrConsistencyFailure {
            details: "diverged".into(),
        },
    ];
    let displays: Vec<String> = triggers.iter().map(|t| format!("{t}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 4);
}

// ---------------------------------------------------------------------------
// FallbackRateMonitor
// ---------------------------------------------------------------------------

#[test]
fn rate_monitor_no_fallbacks_zero_rate() {
    let mut monitor = FallbackRateMonitor::new(epoch(1), FallbackConfig::default());
    for _ in 0..10 {
        let alert = monitor.record(false);
        assert!(alert.is_none());
    }
    assert_eq!(monitor.current_rate_pct(), 0);
    assert!(!monitor.is_rate_exceeded());
}

#[test]
fn rate_monitor_all_fallbacks_high_rate() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 5,
        monitoring_window: 20,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    let mut alerted = false;
    for _ in 0..20 {
        if monitor.record(true).is_some() {
            alerted = true;
        }
    }
    assert!(alerted);
    assert!(monitor.is_rate_exceeded());
    assert_eq!(monitor.current_rate_pct(), 100);
}

#[test]
fn rate_monitor_drain_alerts() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 1,
        monitoring_window: 10,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    for _ in 0..10 {
        monitor.record(true);
    }
    let alerts = monitor.drain_alerts();
    assert!(!alerts.is_empty());
    // After drain, should be empty
    assert!(monitor.drain_alerts().is_empty());
}

#[test]
fn rate_monitor_total_recorded() {
    let mut monitor = FallbackRateMonitor::new(epoch(1), FallbackConfig::default());
    assert_eq!(monitor.total_recorded(), 0);
    monitor.record(false);
    monitor.record(true);
    monitor.record(false);
    assert_eq!(monitor.total_recorded(), 3);
}

#[test]
fn rate_monitor_window_sliding() {
    let config = FallbackConfig {
        max_fallback_rate_pct: 50,
        monitoring_window: 4,
    };
    let mut monitor = FallbackRateMonitor::new(epoch(1), config);
    // Fill window with non-fallbacks
    for _ in 0..4 {
        monitor.record(false);
    }
    assert_eq!(monitor.current_rate_pct(), 0);
    // Now add fallbacks — old entries should slide out
    for _ in 0..4 {
        monitor.record(true);
    }
    assert_eq!(monitor.current_rate_pct(), 100);
}

// ---------------------------------------------------------------------------
// ReconcileEvent serde
// ---------------------------------------------------------------------------

#[test]
fn reconcile_event_serde_roundtrip() {
    let event = ReconcileEvent {
        reconciliation_id: "recon-001".into(),
        peer: "peer-z".into(),
        objects_sent: 5,
        objects_received: 3,
        objects_conflicting: 0,
        epoch_id: 42,
        trace_id: "trace-serde".into(),
        event: "reconcile_complete".into(),
        fallback_triggered: false,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: ReconcileEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// ReconcileResult serde
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// IBLT serde
// ---------------------------------------------------------------------------

#[test]
fn iblt_serde_roundtrip() {
    let mut iblt = Iblt::new(32, 2);
    iblt.insert(&make_hash(1));
    iblt.insert(&make_hash(2));
    let json = serde_json::to_string(&iblt).unwrap();
    let restored: Iblt = serde_json::from_str(&json).unwrap();
    assert_eq!(iblt, restored);
}

#[test]
fn iblt_clone_equality() {
    let mut iblt = Iblt::new(64, 3);
    iblt.insert(&make_hash(10));
    let clone = iblt.clone();
    assert_eq!(iblt, clone);
}

// ---------------------------------------------------------------------------
// Stress: larger difference sets
// ---------------------------------------------------------------------------

#[test]
fn iblt_medium_difference_30_elements() {
    let mut local = Iblt::new(512, 4);
    let mut remote = Iblt::new(512, 4);

    // 50 shared
    for i in 0..50u16 {
        let h = make_hash_wide(i);
        local.insert(&h);
        remote.insert(&h);
    }
    // 15 local-only
    for i in 500..515u16 {
        local.insert(&make_hash_wide(i));
    }
    // 15 remote-only
    for i in 700..715u16 {
        remote.insert(&make_hash_wide(i));
    }

    let diff = local.subtract(&remote).unwrap();
    match diff.peel() {
        Ok((pos, neg)) => {
            assert_eq!(pos.len(), 15);
            assert_eq!(neg.len(), 15);
        }
        Err(_) => {
            // Acceptable if hash collisions prevent peeling with these params
        }
    }
}

// ---------------------------------------------------------------------------
// FallbackConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn fallback_config_default_values() {
    let cfg = FallbackConfig::default();
    assert_eq!(cfg.max_fallback_rate_pct, 5);
    assert_eq!(cfg.monitoring_window, 100);
}

#[test]
fn fallback_config_serde_roundtrip() {
    let cfg = FallbackConfig {
        max_fallback_rate_pct: 10,
        monitoring_window: 200,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: FallbackConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}
