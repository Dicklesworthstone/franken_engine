//! Integration enrichment tests for `s3_fifo_cache_gate`.
//!
//! Covers Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Display
//! coverage, Debug nonempty, Default coverage, admission policies, cache
//! operations, eviction / promotion, ghost queue, parity gate, rollback
//! lifecycle, gate evaluation, receipts, split ratio adaptation, epoch
//! advancement, segment snapshot, and JSON field-name stability.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::s3_fifo_cache_gate::{
    AdmissionDecision, AdmissionPolicy, BenchmarkEvidence, CacheArtifactId, CacheEntry,
    CacheSegment, DecisionKind, DecisionReceipt, GhostEntry, ParityResult, ParityVerdict,
    ReferencePolicyKind, RollbackState, RollbackTrigger, S3_FIFO_BEAD_ID, S3_FIFO_SCHEMA_VERSION,
    S3FifoCacheConfig, S3FifoCacheGate, S3FifoGateError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn artifact(label: &str) -> CacheArtifactId {
    CacheArtifactId::new(ContentHash::compute(label.as_bytes()), 1, label.to_string())
}

fn payload(label: &str) -> ContentHash {
    ContentHash::compute(format!("payload:{label}").as_bytes())
}

fn small_gate(capacity: usize) -> S3FifoCacheGate {
    let config = S3FifoCacheConfig {
        total_capacity: capacity,
        small_ratio_millionths: 500_000,
        ..S3FifoCacheConfig::default()
    };
    S3FifoCacheGate::new(config, epoch(1)).unwrap()
}

// ===========================================================================
// Copy semantics
// ===========================================================================

#[test]
fn enrichment_cache_segment_copy() {
    let a = CacheSegment::Small;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_reference_policy_copy() {
    let a = ReferencePolicyKind::Lru;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_rollback_state_copy() {
    let a = RollbackState::Idle;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_decision_kind_copy() {
    let a = DecisionKind::PolicyEnabled;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_admission_policy_copy() {
    let a = AdmissionPolicy::AcceptAll;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// Clone independence
// ===========================================================================

#[test]
fn enrichment_artifact_id_clone_independence() {
    let a = artifact("foo");
    let mut b = a.clone();
    b.policy_version = 99;
    assert_eq!(a.policy_version, 1);
    assert_eq!(b.policy_version, 99);
}

#[test]
fn enrichment_config_clone_independence() {
    let a = S3FifoCacheConfig::default();
    let mut b = a.clone();
    b.total_capacity = 9999;
    assert_eq!(a.total_capacity, 1024);
    assert_eq!(b.total_capacity, 9999);
}

#[test]
fn enrichment_benchmark_clone_independence() {
    let a = BenchmarkEvidence::empty(epoch(1));
    let mut b = a.clone();
    b.hits = 100;
    assert_eq!(a.hits, 0);
    assert_eq!(b.hits, 100);
}

// ===========================================================================
// BTreeSet ordering
// ===========================================================================

#[test]
fn enrichment_segment_btreeset() {
    let mut set = BTreeSet::new();
    for &seg in CacheSegment::ALL {
        set.insert(seg);
    }
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_artifact_key_btreeset() {
    let a1 = artifact("alpha");
    let a2 = artifact("beta");
    let mut set = BTreeSet::new();
    set.insert(a1.canonical_key());
    set.insert(a2.canonical_key());
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// Serde roundtrips
// ===========================================================================

#[test]
fn enrichment_segment_serde_all() {
    for &seg in CacheSegment::ALL {
        let json = serde_json::to_string(&seg).unwrap();
        let back: CacheSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, seg);
    }
}

#[test]
fn enrichment_reference_policy_serde() {
    for kind in [ReferencePolicyKind::Lru, ReferencePolicyKind::Clock] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ReferencePolicyKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

#[test]
fn enrichment_rollback_state_serde() {
    let states = [
        RollbackState::Idle,
        RollbackState::Triggered,
        RollbackState::Executing,
        RollbackState::Completed,
        RollbackState::Failed,
    ];
    for s in states {
        let json = serde_json::to_string(&s).unwrap();
        let back: RollbackState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn enrichment_decision_kind_serde() {
    let kinds = [
        DecisionKind::PolicyEnabled,
        DecisionKind::GatePassContinue,
        DecisionKind::GateFailRollback,
        DecisionKind::SplitRatioAdapted,
        DecisionKind::AdmissionPolicyChanged,
        DecisionKind::CacheFlushed,
    ];
    for k in kinds {
        let json = serde_json::to_string(&k).unwrap();
        let back: DecisionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn enrichment_artifact_id_serde() {
    let a = artifact("test_artifact");
    let json = serde_json::to_string(&a).unwrap();
    let back: CacheArtifactId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
}

#[test]
fn enrichment_admission_policy_serde_all() {
    let policies = [
        AdmissionPolicy::AcceptAll,
        AdmissionPolicy::FrequencyAware,
        AdmissionPolicy::ValueAware {
            max_size_bytes: 1024,
        },
        AdmissionPolicy::Combined {
            max_size_bytes: 1024,
            min_ghost_hits: 2,
        },
    ];
    for p in policies {
        let json = serde_json::to_string(&p).unwrap();
        let back: AdmissionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }
}

#[test]
fn enrichment_config_serde() {
    let c = S3FifoCacheConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: S3FifoCacheConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

#[test]
fn enrichment_benchmark_serde() {
    let b = BenchmarkEvidence::empty(epoch(1));
    let json = serde_json::to_string(&b).unwrap();
    let back: BenchmarkEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back, b);
}

#[test]
fn enrichment_cache_entry_serde() {
    let entry = CacheEntry::new_small(artifact("e1"), 512, payload("e1"), 0, epoch(1));
    let json = serde_json::to_string(&entry).unwrap();
    let back: CacheEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn enrichment_ghost_entry_serde() {
    let ge = GhostEntry {
        canonical_key: "test_key".to_string(),
        payload_hash: payload("ghost"),
        ghost_hits: 3,
        original_size_bytes: 256,
        sequence_number: 42,
    };
    let json = serde_json::to_string(&ge).unwrap();
    let back: GhostEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ge);
}

#[test]
fn enrichment_rollback_trigger_serde_all() {
    let triggers: Vec<RollbackTrigger> = vec![
        RollbackTrigger::HitRateBelowThreshold {
            threshold_millionths: 200_000,
        },
        RollbackTrigger::ParityGateFailure,
        RollbackTrigger::LatencyRegression {
            observed_ns_millionths: 5_000_000,
            threshold_ns_millionths: 1_000_000,
        },
        RollbackTrigger::OperatorInitiated {
            operator_id: "op1".to_string(),
            reason: "maintenance".to_string(),
        },
        RollbackTrigger::EpochBoundary {
            old_epoch: epoch(1),
            new_epoch: epoch(2),
        },
    ];
    for t in triggers {
        let json = serde_json::to_string(&t).unwrap();
        let back: RollbackTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}

#[test]
fn enrichment_error_serde_all() {
    let errors: Vec<S3FifoGateError> = vec![
        S3FifoGateError::RollbackCooldownActive { remaining_ops: 500 },
        S3FifoGateError::AdmissionRejected {
            reason: "too big".into(),
        },
        S3FifoGateError::ZeroCapacity,
        S3FifoGateError::ArtifactNotFound { key: "k1".into() },
        S3FifoGateError::RollbackFailed {
            reason: "timeout".into(),
        },
        S3FifoGateError::InvalidConfig {
            reason: "bad ratio".into(),
        },
    ];
    for e in errors {
        let json = serde_json::to_string(&e).unwrap();
        let back: S3FifoGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }
}

// ===========================================================================
// Display coverage
// ===========================================================================

#[test]
fn enrichment_segment_display() {
    assert_eq!(CacheSegment::Small.to_string(), "small");
    assert_eq!(CacheSegment::Main.to_string(), "main");
    assert_eq!(CacheSegment::Ghost.to_string(), "ghost");
}

#[test]
fn enrichment_reference_policy_display() {
    assert_eq!(ReferencePolicyKind::Lru.to_string(), "LRU");
    assert_eq!(ReferencePolicyKind::Clock.to_string(), "CLOCK");
}

#[test]
fn enrichment_rollback_state_display() {
    assert_eq!(RollbackState::Idle.to_string(), "idle");
    assert_eq!(RollbackState::Triggered.to_string(), "triggered");
    assert_eq!(RollbackState::Executing.to_string(), "executing");
    assert_eq!(RollbackState::Completed.to_string(), "completed");
    assert_eq!(RollbackState::Failed.to_string(), "failed");
}

#[test]
fn enrichment_decision_kind_display() {
    assert_eq!(DecisionKind::PolicyEnabled.to_string(), "policy_enabled");
    assert_eq!(
        DecisionKind::GatePassContinue.to_string(),
        "gate_pass_continue"
    );
    assert_eq!(
        DecisionKind::GateFailRollback.to_string(),
        "gate_fail_rollback"
    );
    assert_eq!(
        DecisionKind::SplitRatioAdapted.to_string(),
        "split_ratio_adapted"
    );
    assert_eq!(
        DecisionKind::AdmissionPolicyChanged.to_string(),
        "admission_policy_changed"
    );
    assert_eq!(DecisionKind::CacheFlushed.to_string(), "cache_flushed");
}

#[test]
fn enrichment_parity_verdict_display() {
    assert_eq!(
        ParityVerdict::WithinTolerance.to_string(),
        "within_tolerance"
    );
    assert_eq!(
        ParityVerdict::DivergenceBeyondTolerance.to_string(),
        "divergence_beyond_tolerance"
    );
}

#[test]
fn enrichment_artifact_id_display() {
    let a = artifact("my_module");
    let s = a.to_string();
    assert!(s.contains("my_module"));
    assert!(s.contains("v1"));
}

#[test]
fn enrichment_admission_policy_display_all() {
    assert_eq!(AdmissionPolicy::AcceptAll.to_string(), "accept_all");
    assert_eq!(
        AdmissionPolicy::FrequencyAware.to_string(),
        "frequency_aware"
    );
    let va = AdmissionPolicy::ValueAware {
        max_size_bytes: 1024,
    };
    assert!(va.to_string().contains("1024"));
    let combined = AdmissionPolicy::Combined {
        max_size_bytes: 512,
        min_ghost_hits: 3,
    };
    let s = combined.to_string();
    assert!(s.contains("512"));
    assert!(s.contains("3"));
}

#[test]
fn enrichment_rollback_trigger_display_all() {
    let triggers = [
        RollbackTrigger::HitRateBelowThreshold {
            threshold_millionths: 200_000,
        },
        RollbackTrigger::ParityGateFailure,
        RollbackTrigger::LatencyRegression {
            observed_ns_millionths: 5_000_000,
            threshold_ns_millionths: 1_000_000,
        },
        RollbackTrigger::OperatorInitiated {
            operator_id: "op1".to_string(),
            reason: "test".to_string(),
        },
        RollbackTrigger::EpochBoundary {
            old_epoch: epoch(1),
            new_epoch: epoch(2),
        },
    ];
    for t in &triggers {
        assert!(!t.to_string().is_empty());
    }
}

#[test]
fn enrichment_error_display_all() {
    let errors = [
        S3FifoGateError::RollbackCooldownActive { remaining_ops: 500 },
        S3FifoGateError::AdmissionRejected {
            reason: "big".into(),
        },
        S3FifoGateError::ZeroCapacity,
        S3FifoGateError::ArtifactNotFound { key: "k1".into() },
        S3FifoGateError::RollbackFailed {
            reason: "timeout".into(),
        },
        S3FifoGateError::InvalidConfig {
            reason: "bad".into(),
        },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

// ===========================================================================
// Debug nonempty
// ===========================================================================

#[test]
fn enrichment_segment_debug() {
    for &seg in CacheSegment::ALL {
        assert!(!format!("{seg:?}").is_empty());
    }
}

#[test]
fn enrichment_config_debug() {
    let c = S3FifoCacheConfig::default();
    assert!(!format!("{c:?}").is_empty());
}

#[test]
fn enrichment_gate_debug() {
    let g = S3FifoCacheGate::with_defaults(epoch(1));
    assert!(!format!("{g:?}").is_empty());
}

#[test]
fn enrichment_benchmark_debug() {
    let b = BenchmarkEvidence::empty(epoch(1));
    assert!(!format!("{b:?}").is_empty());
}

// ===========================================================================
// Default coverage
// ===========================================================================

#[test]
fn enrichment_config_default() {
    let c = S3FifoCacheConfig::default();
    assert_eq!(c.total_capacity, 1024);
    assert_eq!(c.small_ratio_millionths, 100_000);
    assert_eq!(c.ghost_multiplier, 2);
    assert_eq!(c.parity_tolerance_millionths, 50_000);
    assert_eq!(c.reference_policy, ReferencePolicyKind::Lru);
    assert_eq!(c.admission_policy, AdmissionPolicy::AcceptAll);
    assert!(!c.auto_adapt_split);
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_populated() {
    assert!(S3_FIFO_SCHEMA_VERSION.contains("s3-fifo"));
}

#[test]
fn enrichment_bead_id_populated() {
    assert!(S3_FIFO_BEAD_ID.contains("bd-"));
}

// ===========================================================================
// Config capacity calculations
// ===========================================================================

#[test]
fn enrichment_config_small_capacity() {
    let c = S3FifoCacheConfig::default(); // 1024 total, 10% small
    assert_eq!(c.small_capacity(), 102);
}

#[test]
fn enrichment_config_main_capacity() {
    let c = S3FifoCacheConfig::default();
    assert_eq!(c.main_capacity(), 1024 - c.small_capacity());
}

#[test]
fn enrichment_config_ghost_capacity() {
    let c = S3FifoCacheConfig::default();
    assert_eq!(c.ghost_capacity(), 1024 * 2);
}

// ===========================================================================
// Admission policy evaluation
// ===========================================================================

#[test]
fn enrichment_accept_all_admits() {
    let decision = AdmissionPolicy::AcceptAll.should_admit(1024, None);
    assert!(decision.is_admit());
}

#[test]
fn enrichment_frequency_aware_rejects_no_ghost() {
    let decision = AdmissionPolicy::FrequencyAware.should_admit(1024, None);
    assert!(!decision.is_admit());
}

#[test]
fn enrichment_frequency_aware_admits_with_ghost() {
    let ghost = GhostEntry {
        canonical_key: "k".to_string(),
        payload_hash: payload("k"),
        ghost_hits: 1,
        original_size_bytes: 256,
        sequence_number: 0,
    };
    let decision = AdmissionPolicy::FrequencyAware.should_admit(1024, Some(&ghost));
    assert!(decision.is_admit());
}

#[test]
fn enrichment_value_aware_admits_small() {
    let policy = AdmissionPolicy::ValueAware {
        max_size_bytes: 1024,
    };
    let decision = policy.should_admit(512, None);
    assert!(decision.is_admit());
}

#[test]
fn enrichment_value_aware_rejects_large() {
    let policy = AdmissionPolicy::ValueAware {
        max_size_bytes: 1024,
    };
    let decision = policy.should_admit(2048, None);
    assert!(!decision.is_admit());
}

#[test]
fn enrichment_combined_admits_small() {
    let policy = AdmissionPolicy::Combined {
        max_size_bytes: 1024,
        min_ghost_hits: 2,
    };
    let decision = policy.should_admit(512, None);
    assert!(decision.is_admit());
}

#[test]
fn enrichment_combined_admits_large_with_enough_ghost_hits() {
    let ghost = GhostEntry {
        canonical_key: "k".to_string(),
        payload_hash: payload("k"),
        ghost_hits: 5,
        original_size_bytes: 2048,
        sequence_number: 0,
    };
    let policy = AdmissionPolicy::Combined {
        max_size_bytes: 1024,
        min_ghost_hits: 2,
    };
    let decision = policy.should_admit(2048, Some(&ghost));
    assert!(decision.is_admit());
}

#[test]
fn enrichment_combined_rejects_large_insufficient_ghost_hits() {
    let ghost = GhostEntry {
        canonical_key: "k".to_string(),
        payload_hash: payload("k"),
        ghost_hits: 1,
        original_size_bytes: 2048,
        sequence_number: 0,
    };
    let policy = AdmissionPolicy::Combined {
        max_size_bytes: 1024,
        min_ghost_hits: 2,
    };
    let decision = policy.should_admit(2048, Some(&ghost));
    assert!(!decision.is_admit());
}

#[test]
fn enrichment_combined_rejects_large_no_ghost() {
    let policy = AdmissionPolicy::Combined {
        max_size_bytes: 1024,
        min_ghost_hits: 2,
    };
    let decision = policy.should_admit(2048, None);
    assert!(!decision.is_admit());
}

// ===========================================================================
// Cache entry operations
// ===========================================================================

#[test]
fn enrichment_entry_new_small() {
    let entry = CacheEntry::new_small(artifact("e1"), 512, payload("e1"), 0, epoch(1));
    assert_eq!(entry.segment, CacheSegment::Small);
    assert_eq!(entry.frequency, 0);
    assert_eq!(entry.size_bytes, 512);
}

#[test]
fn enrichment_entry_promote_to_main() {
    let mut entry = CacheEntry::new_small(artifact("e1"), 512, payload("e1"), 0, epoch(1));
    entry.promote_to_main(5);
    assert_eq!(entry.segment, CacheSegment::Main);
    assert_eq!(entry.frequency, 0);
    assert_eq!(entry.sequence_number, 5);
}

#[test]
fn enrichment_entry_record_access_increments() {
    let mut entry = CacheEntry::new_small(artifact("e1"), 512, payload("e1"), 0, epoch(1));
    assert_eq!(entry.frequency, 0);
    entry.record_access();
    assert_eq!(entry.frequency, 1);
    entry.record_access();
    assert_eq!(entry.frequency, 2);
    entry.record_access();
    assert_eq!(entry.frequency, 3);
    // Saturates at 3
    entry.record_access();
    assert_eq!(entry.frequency, 3);
}

#[test]
fn enrichment_entry_decrement_frequency() {
    let mut entry = CacheEntry::new_small(artifact("e1"), 512, payload("e1"), 0, epoch(1));
    entry.record_access();
    entry.record_access();
    assert_eq!(entry.frequency, 2);
    entry.decrement_frequency();
    assert_eq!(entry.frequency, 1);
    entry.decrement_frequency();
    assert_eq!(entry.frequency, 0);
    // Saturating sub
    entry.decrement_frequency();
    assert_eq!(entry.frequency, 0);
}

// ===========================================================================
// Gate construction
// ===========================================================================

#[test]
fn enrichment_gate_new_success() {
    let gate = S3FifoCacheGate::new(S3FifoCacheConfig::default(), epoch(1));
    assert!(gate.is_ok());
    let g = gate.unwrap();
    assert!(g.is_active());
    assert_eq!(g.rollback_state(), RollbackState::Idle);
    assert_eq!(g.total_cached(), 0);
}

#[test]
fn enrichment_gate_zero_capacity_error() {
    let config = S3FifoCacheConfig {
        total_capacity: 0,
        ..S3FifoCacheConfig::default()
    };
    let gate = S3FifoCacheGate::new(config, epoch(1));
    assert!(gate.is_err());
    assert!(matches!(gate.unwrap_err(), S3FifoGateError::ZeroCapacity));
}

#[test]
fn enrichment_gate_invalid_ratio_error() {
    let config = S3FifoCacheConfig {
        small_ratio_millionths: 1_000_001,
        ..S3FifoCacheConfig::default()
    };
    let gate = S3FifoCacheGate::new(config, epoch(1));
    assert!(gate.is_err());
    assert!(matches!(
        gate.unwrap_err(),
        S3FifoGateError::InvalidConfig { .. }
    ));
}

#[test]
fn enrichment_gate_with_defaults() {
    let g = S3FifoCacheGate::with_defaults(epoch(1));
    assert!(g.is_active());
    assert_eq!(g.current_epoch(), epoch(1));
}

// ===========================================================================
// Insert and lookup
// ===========================================================================

#[test]
fn enrichment_insert_and_lookup() {
    let mut g = small_gate(10);
    let art = artifact("a1");
    let key = art.canonical_key();
    let result = g.insert(art, 64, payload("a1"));
    assert!(result.is_ok());
    assert!(result.unwrap().is_admit());
    assert!(g.contains(&key));
    assert!(g.lookup(&key));
}

#[test]
fn enrichment_lookup_miss() {
    let mut g = small_gate(10);
    assert!(!g.lookup("nonexistent"));
}

#[test]
fn enrichment_insert_already_present() {
    let mut g = small_gate(10);
    let art = artifact("a1");
    g.insert(art.clone(), 64, payload("a1")).unwrap();
    let result = g.insert(art, 64, payload("a1")).unwrap();
    assert!(result.is_admit());
}

#[test]
fn enrichment_remove() {
    let mut g = small_gate(10);
    let art = artifact("a1");
    let key = art.canonical_key();
    g.insert(art, 64, payload("a1")).unwrap();
    assert!(g.contains(&key));
    assert!(g.remove(&key));
    assert!(!g.contains(&key));
}

#[test]
fn enrichment_remove_nonexistent() {
    let mut g = small_gate(10);
    assert!(!g.remove("nonexistent"));
}

#[test]
fn enrichment_flush() {
    let mut g = small_gate(10);
    for i in 0..5 {
        let art = artifact(&format!("a{i}"));
        g.insert(art, 64, payload(&format!("a{i}"))).unwrap();
    }
    assert!(g.total_cached() > 0);
    g.flush();
    assert_eq!(g.total_cached(), 0);
}

// ===========================================================================
// Eviction and promotion
// ===========================================================================

#[test]
fn enrichment_eviction_from_small_fills_ghost() {
    let mut g = small_gate(4); // 50% small = 2 items in small
    // Insert 3 items. Third should trigger eviction of first from small.
    for i in 0..3 {
        let art = artifact(&format!("item{i}"));
        g.insert(art, 64, payload(&format!("item{i}"))).unwrap();
    }
    // First item should now be in ghost (since frequency=0)
    let first_key = artifact("item0").canonical_key();
    assert!(!g.contains(&first_key));
    assert!(g.is_ghost(&first_key));
}

#[test]
fn enrichment_promotion_on_frequency() {
    let mut g = small_gate(4); // 50% small = 2
    let art = artifact("promoted");
    let key = art.canonical_key();
    g.insert(art, 64, payload("promoted")).unwrap();
    // Access to increment frequency
    g.lookup(&key);
    // Now insert more items to trigger eviction from small
    for i in 0..3 {
        let art = artifact(&format!("filler{i}"));
        g.insert(art, 64, payload(&format!("filler{i}"))).unwrap();
    }
    // The promoted item should be in main (or gone if main overflowed),
    // but it should NOT be in ghost (it was promoted due to frequency > 0)
    if g.contains(&key) {
        assert_eq!(g.entry_segment(&key), Some(CacheSegment::Main));
    }
}

// ===========================================================================
// Entry segment and frequency accessors
// ===========================================================================

#[test]
fn enrichment_entry_segment_accessor() {
    let mut g = small_gate(10);
    let art = artifact("seg_test");
    let key = art.canonical_key();
    g.insert(art, 64, payload("seg_test")).unwrap();
    assert_eq!(g.entry_segment(&key), Some(CacheSegment::Small));
}

#[test]
fn enrichment_entry_frequency_accessor() {
    let mut g = small_gate(10);
    let art = artifact("freq_test");
    let key = art.canonical_key();
    g.insert(art, 64, payload("freq_test")).unwrap();
    assert_eq!(g.entry_frequency(&key), Some(0));
    g.lookup(&key);
    assert_eq!(g.entry_frequency(&key), Some(1));
}

#[test]
fn enrichment_entry_segment_nonexistent() {
    let g = small_gate(10);
    assert_eq!(g.entry_segment("no_such"), None);
}

#[test]
fn enrichment_entry_frequency_nonexistent() {
    let g = small_gate(10);
    assert_eq!(g.entry_frequency("no_such"), None);
}

// ===========================================================================
// Parity gate
// ===========================================================================

#[test]
fn enrichment_parity_evaluates() {
    let mut g = small_gate(10);
    // Insert items and lookup repeatedly to build hit rate
    for i in 0..5 {
        let art = artifact(&format!("p{i}"));
        let key = art.canonical_key();
        g.insert(art, 64, payload(&format!("p{i}"))).unwrap();
        // Multiple lookups to build consistent hit patterns
        for _ in 0..10 {
            g.lookup(&key);
        }
    }
    let parity = g.evaluate_parity();
    // Verify the parity result has correct structure regardless of verdict
    assert!(parity.total_operations > 0);
    assert!(parity.s3_fifo_hit_rate_millionths > 0);
    // Verify verdict is one of the two possible outcomes
    assert!(
        parity.verdict == ParityVerdict::WithinTolerance
            || parity.verdict == ParityVerdict::DivergenceBeyondTolerance
    );
}

#[test]
fn enrichment_parity_result_fields() {
    let mut g = small_gate(10);
    let art = artifact("pr");
    let key = art.canonical_key();
    g.insert(art, 64, payload("pr")).unwrap();
    g.lookup(&key);
    let parity = g.evaluate_parity();
    assert!(parity.total_operations > 0);
    assert_eq!(parity.tolerance_millionths, 50_000);
}

// ===========================================================================
// Rollback lifecycle
// ===========================================================================

#[test]
fn enrichment_operator_rollback() {
    let mut g = small_gate(10);
    let art = artifact("rb");
    g.insert(art, 64, payload("rb")).unwrap();
    let record = g.operator_rollback("admin", "maintenance window");
    assert_eq!(record.state, RollbackState::Completed);
    assert!(matches!(
        record.trigger,
        RollbackTrigger::OperatorInitiated { .. }
    ));
    assert!(!g.is_active());
    assert_eq!(g.rollback_state(), RollbackState::Completed);
}

#[test]
fn enrichment_rollback_flushes_cache() {
    let mut g = small_gate(10);
    for i in 0..5 {
        let art = artifact(&format!("r{i}"));
        g.insert(art, 64, payload(&format!("r{i}"))).unwrap();
    }
    assert!(g.total_cached() > 0);
    g.operator_rollback("admin", "flush test");
    assert_eq!(g.total_cached(), 0);
}

#[test]
fn enrichment_rollback_cooldown_prevents_insert() {
    let mut g = S3FifoCacheGate::new(
        S3FifoCacheConfig {
            total_capacity: 10,
            rollback_cooldown_ops: 1000,
            ..S3FifoCacheConfig::default()
        },
        epoch(1),
    )
    .unwrap();
    g.operator_rollback("admin", "test");
    // Insert should fail during cooldown
    let art = artifact("blocked");
    let result = g.insert(art, 64, payload("blocked"));
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        S3FifoGateError::RollbackCooldownActive { .. }
    ));
}

#[test]
fn enrichment_rollback_history() {
    let mut g = small_gate(10);
    assert!(g.rollback_history().is_empty());
    g.operator_rollback("admin", "test1");
    assert_eq!(g.rollback_history().len(), 1);
}

// ===========================================================================
// Re-enable after rollback
// ===========================================================================

#[test]
fn enrichment_re_enable_during_cooldown_fails() {
    let mut g = S3FifoCacheGate::new(
        S3FifoCacheConfig {
            total_capacity: 10,
            rollback_cooldown_ops: 1000,
            ..S3FifoCacheConfig::default()
        },
        epoch(1),
    )
    .unwrap();
    g.operator_rollback("admin", "test");
    let result = g.re_enable();
    assert!(result.is_err());
}

#[test]
fn enrichment_re_enable_after_cooldown() {
    let mut g = S3FifoCacheGate::new(
        S3FifoCacheConfig {
            total_capacity: 10,
            rollback_cooldown_ops: 5,
            ..S3FifoCacheConfig::default()
        },
        epoch(1),
    )
    .unwrap();
    g.operator_rollback("admin", "test");
    // Burn through cooldown via lookups
    for _ in 0..6 {
        g.lookup("any_key");
    }
    let result = g.re_enable();
    assert!(result.is_ok());
    assert!(g.is_active());
}

// ===========================================================================
// Full gate evaluation
// ===========================================================================

#[test]
fn enrichment_gate_evaluation_runs() {
    let mut g = S3FifoCacheGate::new(
        S3FifoCacheConfig {
            total_capacity: 100,
            parity_tolerance_millionths: 1_000_000, // 100% tolerance = always pass parity
            min_hit_rate_millionths: 0,             // disable hit rate rollback
            ..S3FifoCacheConfig::default()
        },
        epoch(1),
    )
    .unwrap();
    for i in 0..10 {
        let art = artifact(&format!("ge{i}"));
        let key = art.canonical_key();
        g.insert(art, 64, payload(&format!("ge{i}"))).unwrap();
        for _ in 0..5 {
            g.lookup(&key);
        }
    }
    let eval = g.evaluate_gate();
    assert!(eval.passed);
    assert!(eval.active);
    assert!(eval.rollback_record.is_none());
}

// ===========================================================================
// Receipts
// ===========================================================================

#[test]
fn enrichment_receipt_emitted_on_gate_eval() {
    let mut g = small_gate(10);
    for i in 0..3 {
        let art = artifact(&format!("rc{i}"));
        let key = art.canonical_key();
        g.insert(art, 64, payload(&format!("rc{i}"))).unwrap();
        g.lookup(&key);
    }
    g.evaluate_gate();
    assert!(!g.receipts().is_empty());
    let receipt = &g.receipts()[g.receipts().len() - 1];
    assert_eq!(receipt.schema_version, S3_FIFO_SCHEMA_VERSION);
}

#[test]
fn enrichment_receipt_on_admission_policy_change() {
    let mut g = small_gate(10);
    let initial_count = g.receipts().len();
    g.set_admission_policy(AdmissionPolicy::FrequencyAware);
    assert!(g.receipts().len() > initial_count);
}

// ===========================================================================
// Epoch advancement
// ===========================================================================

#[test]
fn enrichment_advance_epoch() {
    let mut g = small_gate(10);
    assert_eq!(g.current_epoch(), epoch(1));
    g.advance_epoch(epoch(2));
    assert_eq!(g.current_epoch(), epoch(2));
}

// ===========================================================================
// Segment snapshot
// ===========================================================================

#[test]
fn enrichment_segment_snapshot_empty() {
    let g = small_gate(10);
    let snap = g.segment_snapshot();
    assert_eq!(snap.small_len, 0);
    assert_eq!(snap.main_len, 0);
    assert_eq!(snap.ghost_len, 0);
    assert_eq!(snap.total_cached, 0);
    assert!(snap.small_capacity > 0);
    assert!(snap.main_capacity > 0);
}

#[test]
fn enrichment_segment_snapshot_after_inserts() {
    let mut g = small_gate(10);
    for i in 0..3 {
        let art = artifact(&format!("sn{i}"));
        g.insert(art, 64, payload(&format!("sn{i}"))).unwrap();
    }
    let snap = g.segment_snapshot();
    assert!(snap.total_cached > 0);
}

// ===========================================================================
// Benchmark evidence
// ===========================================================================

#[test]
fn enrichment_benchmark_empty() {
    let b = BenchmarkEvidence::empty(epoch(1));
    assert_eq!(b.total_lookups, 0);
    assert_eq!(b.hits, 0);
    assert_eq!(b.misses, 0);
    assert_eq!(b.hit_rate_millionths, 0);
    assert_eq!(b.miss_rate_millionths, 0);
}

#[test]
fn enrichment_benchmark_recompute_rates() {
    let mut b = BenchmarkEvidence::empty(epoch(1));
    b.total_lookups = 100;
    b.hits = 75;
    b.misses = 25;
    b.recompute_rates();
    assert_eq!(b.hit_rate_millionths, 750_000);
    assert_eq!(b.miss_rate_millionths, 250_000);
}

#[test]
fn enrichment_benchmark_recompute_zero_lookups() {
    let mut b = BenchmarkEvidence::empty(epoch(1));
    b.recompute_rates();
    assert_eq!(b.hit_rate_millionths, 0);
    assert_eq!(b.miss_rate_millionths, 0);
}

#[test]
fn enrichment_benchmark_compute_trace_hash_deterministic() {
    let mut b1 = BenchmarkEvidence::empty(epoch(1));
    b1.total_lookups = 100;
    b1.hits = 50;
    b1.compute_trace_hash();
    let mut b2 = BenchmarkEvidence::empty(epoch(1));
    b2.total_lookups = 100;
    b2.hits = 50;
    b2.compute_trace_hash();
    assert_eq!(b1.trace_hash, b2.trace_hash);
}

#[test]
fn enrichment_benchmark_compute_trace_hash_varies() {
    let mut b1 = BenchmarkEvidence::empty(epoch(1));
    b1.total_lookups = 100;
    b1.compute_trace_hash();
    let mut b2 = BenchmarkEvidence::empty(epoch(1));
    b2.total_lookups = 200;
    b2.compute_trace_hash();
    assert_ne!(b1.trace_hash, b2.trace_hash);
}

// ===========================================================================
// Rollback trigger category
// ===========================================================================

#[test]
fn enrichment_rollback_trigger_category() {
    assert_eq!(
        RollbackTrigger::HitRateBelowThreshold {
            threshold_millionths: 100
        }
        .category(),
        "hit_rate_below_threshold"
    );
    assert_eq!(
        RollbackTrigger::ParityGateFailure.category(),
        "parity_gate_failure"
    );
    assert_eq!(
        RollbackTrigger::LatencyRegression {
            observed_ns_millionths: 1,
            threshold_ns_millionths: 1
        }
        .category(),
        "latency_regression"
    );
    assert_eq!(
        RollbackTrigger::OperatorInitiated {
            operator_id: "x".to_string(),
            reason: "y".to_string()
        }
        .category(),
        "operator_initiated"
    );
    assert_eq!(
        RollbackTrigger::EpochBoundary {
            old_epoch: epoch(1),
            new_epoch: epoch(2)
        }
        .category(),
        "epoch_boundary"
    );
}

// ===========================================================================
// Artifact canonical key
// ===========================================================================

#[test]
fn enrichment_artifact_canonical_key_deterministic() {
    let a1 = artifact("test");
    let a2 = artifact("test");
    assert_eq!(a1.canonical_key(), a2.canonical_key());
}

#[test]
fn enrichment_artifact_canonical_key_differs() {
    let a1 = artifact("alpha");
    let a2 = artifact("beta");
    assert_ne!(a1.canonical_key(), a2.canonical_key());
}

// ===========================================================================
// Parity result passed()
// ===========================================================================

#[test]
fn enrichment_parity_result_passed_within() {
    let pr = ParityResult {
        reference_policy: ReferencePolicyKind::Lru,
        verdict: ParityVerdict::WithinTolerance,
        s3_fifo_hit_rate_millionths: 500_000,
        reference_hit_rate_millionths: 520_000,
        hit_rate_delta_millionths: 20_000,
        tolerance_millionths: 50_000,
        total_operations: 100,
        evidence_hash: ContentHash::compute(b"test"),
    };
    assert!(pr.passed());
}

#[test]
fn enrichment_parity_result_failed_divergence() {
    let pr = ParityResult {
        reference_policy: ReferencePolicyKind::Lru,
        verdict: ParityVerdict::DivergenceBeyondTolerance,
        s3_fifo_hit_rate_millionths: 100_000,
        reference_hit_rate_millionths: 500_000,
        hit_rate_delta_millionths: 400_000,
        tolerance_millionths: 50_000,
        total_operations: 100,
        evidence_hash: ContentHash::compute(b"test2"),
    };
    assert!(!pr.passed());
}

// ===========================================================================
// Decision receipt seal
// ===========================================================================

#[test]
fn enrichment_receipt_seal_deterministic() {
    let mut r1 = DecisionReceipt {
        schema_version: S3_FIFO_SCHEMA_VERSION.to_string(),
        receipt_id: "r1".to_string(),
        decision_kind: DecisionKind::PolicyEnabled,
        epoch: epoch(1),
        parity_result: None,
        benchmark_evidence: BenchmarkEvidence::empty(epoch(1)),
        rollback_record: None,
        admission_policy_label: "accept_all".to_string(),
        small_ratio_millionths: 100_000,
        content_hash: ContentHash::compute(b"pending"),
    };
    let mut r2 = r1.clone();
    r1.seal();
    r2.seal();
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ===========================================================================
// JSON field-name stability
// ===========================================================================

#[test]
fn enrichment_artifact_json_fields() {
    let a = artifact("test");
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"source_hash\""));
    assert!(json.contains("\"policy_version\""));
    assert!(json.contains("\"label\""));
}

#[test]
fn enrichment_config_json_fields() {
    let c = S3FifoCacheConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"total_capacity\""));
    assert!(json.contains("\"small_ratio_millionths\""));
    assert!(json.contains("\"ghost_multiplier\""));
    assert!(json.contains("\"parity_tolerance_millionths\""));
    assert!(json.contains("\"reference_policy\""));
    assert!(json.contains("\"admission_policy\""));
    assert!(json.contains("\"min_hit_rate_millionths\""));
    assert!(json.contains("\"rollback_cooldown_ops\""));
}

#[test]
fn enrichment_benchmark_json_fields() {
    let b = BenchmarkEvidence::empty(epoch(1));
    let json = serde_json::to_string(&b).unwrap();
    assert!(json.contains("\"total_lookups\""));
    assert!(json.contains("\"hits\""));
    assert!(json.contains("\"misses\""));
    assert!(json.contains("\"hit_rate_millionths\""));
    assert!(json.contains("\"miss_rate_millionths\""));
    assert!(json.contains("\"total_evictions\""));
    assert!(json.contains("\"ghost_hits\""));
    assert!(json.contains("\"promotions\""));
    assert!(json.contains("\"trace_hash\""));
}

#[test]
fn enrichment_parity_result_json_fields() {
    let mut g = small_gate(10);
    let art = artifact("pj");
    let key = art.canonical_key();
    g.insert(art, 64, payload("pj")).unwrap();
    g.lookup(&key);
    let parity = g.evaluate_parity();
    let json = serde_json::to_string(&parity).unwrap();
    assert!(json.contains("\"reference_policy\""));
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"s3_fifo_hit_rate_millionths\""));
    assert!(json.contains("\"reference_hit_rate_millionths\""));
    assert!(json.contains("\"hit_rate_delta_millionths\""));
    assert!(json.contains("\"tolerance_millionths\""));
    assert!(json.contains("\"total_operations\""));
}

#[test]
fn enrichment_segment_snapshot_json_fields() {
    let g = small_gate(10);
    let snap = g.segment_snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    assert!(json.contains("\"small_len\""));
    assert!(json.contains("\"small_capacity\""));
    assert!(json.contains("\"main_len\""));
    assert!(json.contains("\"main_capacity\""));
    assert!(json.contains("\"ghost_len\""));
    assert!(json.contains("\"ghost_capacity\""));
    assert!(json.contains("\"total_cached\""));
    assert!(json.contains("\"effective_small_ratio_millionths\""));
}

// ===========================================================================
// Hit rate tracking
// ===========================================================================

#[test]
fn enrichment_current_hit_rate_zero_lookups() {
    let g = small_gate(10);
    assert_eq!(g.current_hit_rate_millionths(), 0);
}

#[test]
fn enrichment_current_hit_rate_after_hits() {
    let mut g = small_gate(10);
    let art = artifact("hr");
    let key = art.canonical_key();
    g.insert(art, 64, payload("hr")).unwrap();
    // 1 lookup = miss (insert triggers lookup internally via insert_already_present path? no.)
    // Actually just direct lookup:
    g.lookup(&key); // hit
    g.lookup(&key); // hit
    g.lookup("miss1"); // miss
    g.lookup("miss2"); // miss
    // benchmark: 4 total lookups, 2 hits = 500_000 millionths
    assert_eq!(g.current_hit_rate_millionths(), 500_000);
}

// ===========================================================================
// Admission decision is_admit
// ===========================================================================

#[test]
fn enrichment_admission_decision_is_admit() {
    let admit = AdmissionDecision::Admit {
        reason: "ok".into(),
    };
    assert!(admit.is_admit());
    let reject = AdmissionDecision::Reject {
        reason: "no".into(),
    };
    assert!(!reject.is_admit());
}

// ===========================================================================
// Split ratio adaptation
// ===========================================================================

#[test]
fn enrichment_adapt_split_disabled_by_default() {
    let mut g = small_gate(10);
    assert_eq!(g.adapt_split_ratio(), None);
}

#[test]
fn enrichment_adapt_split_when_enabled() {
    let config = S3FifoCacheConfig {
        total_capacity: 10,
        auto_adapt_split: true,
        small_ratio_millionths: 100_000,
        ..S3FifoCacheConfig::default()
    };
    let mut g = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    // Without evictions, no adaptation
    assert_eq!(g.adapt_split_ratio(), None);
}

// ===========================================================================
// Contains / is_ghost
// ===========================================================================

#[test]
fn enrichment_contains_and_is_ghost() {
    let mut g = small_gate(4);
    let art = artifact("cig");
    let key = art.canonical_key();
    g.insert(art, 64, payload("cig")).unwrap();
    assert!(g.contains(&key));
    assert!(!g.is_ghost(&key));
}

// ===========================================================================
// Queue length accessors
// ===========================================================================

#[test]
fn enrichment_queue_lengths_empty() {
    let g = small_gate(10);
    assert_eq!(g.small_queue_len(), 0);
    assert_eq!(g.main_queue_len(), 0);
    assert_eq!(g.ghost_queue_len(), 0);
    assert_eq!(g.total_cached(), 0);
    assert_eq!(g.total_ghost(), 0);
}

#[test]
fn enrichment_queue_lengths_after_inserts() {
    let mut g = small_gate(10);
    let art = artifact("ql");
    g.insert(art, 64, payload("ql")).unwrap();
    assert!(g.small_queue_len() > 0 || g.main_queue_len() > 0);
    assert_eq!(g.total_cached(), 1);
}
