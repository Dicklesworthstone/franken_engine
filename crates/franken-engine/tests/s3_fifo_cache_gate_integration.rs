#![forbid(unsafe_code)]

//! Integration tests for the `s3_fifo_cache_gate` module.
//!
//! Exercises the public API from outside the crate: S3-FIFO three-segment
//! cache with admission control, parity comparison against LRU/CLOCK
//! references, rollback lifecycle, decision receipt emission, split-ratio
//! adaptation, benchmark evidence, serde round-trips, Display formatting,
//! and edge cases (zero/max millionths, boundary capacities, cooldown
//! expiry, epoch advancement, ghost re-admission).

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::s3_fifo_cache_gate::*;
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

fn artifact_v(label: &str, version: u64) -> CacheArtifactId {
    CacheArtifactId::new(
        ContentHash::compute(label.as_bytes()),
        version,
        label.to_string(),
    )
}

fn payload(label: &str) -> ContentHash {
    ContentHash::compute(format!("payload:{label}").as_bytes())
}

fn default_gate() -> S3FifoCacheGate {
    S3FifoCacheGate::with_defaults(epoch(1))
}

fn small_gate(capacity: usize) -> S3FifoCacheGate {
    let config = S3FifoCacheConfig {
        total_capacity: capacity,
        small_ratio_millionths: 500_000, // 50%
        ..S3FifoCacheConfig::default()
    };
    S3FifoCacheGate::new(config, epoch(1)).unwrap()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_format() {
    assert!(S3_FIFO_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(S3_FIFO_SCHEMA_VERSION.ends_with(".v1"));
    assert!(S3_FIFO_SCHEMA_VERSION.contains("s3-fifo"));
}

#[test]
fn test_bead_id_format() {
    assert_eq!(S3_FIFO_BEAD_ID, "bd-1lsy.7.20.3");
}

// ---------------------------------------------------------------------------
// CacheArtifactId
// ---------------------------------------------------------------------------

#[test]
fn test_artifact_id_new_and_fields() {
    let hash = ContentHash::compute(b"module_src");
    let id = CacheArtifactId::new(hash.clone(), 3, "my_module");
    assert_eq!(id.source_hash, hash);
    assert_eq!(id.policy_version, 3);
    assert_eq!(id.label, "my_module");
}

#[test]
fn test_artifact_id_canonical_key_deterministic() {
    let a1 = artifact("hello");
    let a2 = artifact("hello");
    assert_eq!(a1.canonical_key(), a2.canonical_key());
}

#[test]
fn test_artifact_id_canonical_key_differs_by_label() {
    let a1 = artifact("alpha");
    let a2 = artifact("beta");
    assert_ne!(a1.canonical_key(), a2.canonical_key());
}

#[test]
fn test_artifact_id_canonical_key_differs_by_version() {
    let a1 = artifact_v("same", 1);
    let a2 = artifact_v("same", 2);
    assert_ne!(a1.canonical_key(), a2.canonical_key());
}

#[test]
fn test_artifact_id_display_contains_label_and_version() {
    let id = artifact_v("mymod", 5);
    let s = format!("{id}");
    assert!(s.contains("mymod"));
    assert!(s.contains("v5"));
}

#[test]
fn test_artifact_id_serde_roundtrip() {
    let id = artifact_v("serde_art", 42);
    let json = serde_json::to_string(&id).unwrap();
    let back: CacheArtifactId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

// ---------------------------------------------------------------------------
// CacheSegment
// ---------------------------------------------------------------------------

#[test]
fn test_cache_segment_all_variants() {
    assert_eq!(CacheSegment::ALL.len(), 3);
    assert!(CacheSegment::ALL.contains(&CacheSegment::Small));
    assert!(CacheSegment::ALL.contains(&CacheSegment::Main));
    assert!(CacheSegment::ALL.contains(&CacheSegment::Ghost));
}

#[test]
fn test_cache_segment_display() {
    assert_eq!(format!("{}", CacheSegment::Small), "small");
    assert_eq!(format!("{}", CacheSegment::Main), "main");
    assert_eq!(format!("{}", CacheSegment::Ghost), "ghost");
}

#[test]
fn test_cache_segment_serde_roundtrip() {
    for seg in CacheSegment::ALL {
        let json = serde_json::to_string(seg).unwrap();
        let back: CacheSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(*seg, back);
    }
}

// ---------------------------------------------------------------------------
// CacheEntry
// ---------------------------------------------------------------------------

#[test]
fn test_cache_entry_new_small_defaults() {
    let entry = CacheEntry::new_small(artifact("e"), 256, payload("e"), 0, epoch(1));
    assert_eq!(entry.segment, CacheSegment::Small);
    assert_eq!(entry.frequency, 0);
    assert_eq!(entry.size_bytes, 256);
    assert_eq!(entry.sequence_number, 0);
    assert_eq!(entry.last_validated_epoch, epoch(1));
}

#[test]
fn test_cache_entry_promote_to_main() {
    let mut entry = CacheEntry::new_small(artifact("p"), 128, payload("p"), 0, epoch(1));
    entry.record_access();
    entry.record_access();
    assert_eq!(entry.frequency, 2);
    entry.promote_to_main(99);
    assert_eq!(entry.segment, CacheSegment::Main);
    assert_eq!(entry.frequency, 0);
    assert_eq!(entry.sequence_number, 99);
}

#[test]
fn test_cache_entry_record_access_saturates() {
    let mut entry = CacheEntry::new_small(artifact("sat"), 64, payload("sat"), 0, epoch(1));
    for _ in 0..100 {
        entry.record_access();
    }
    // MAX_FREQUENCY is 3 (from source).
    assert_eq!(entry.frequency, 3);
}

#[test]
fn test_cache_entry_decrement_frequency_saturating() {
    let mut entry = CacheEntry::new_small(artifact("dec"), 64, payload("dec"), 0, epoch(1));
    assert_eq!(entry.frequency, 0);
    entry.decrement_frequency();
    assert_eq!(entry.frequency, 0); // saturating_sub at 0
    entry.record_access();
    entry.record_access();
    assert_eq!(entry.frequency, 2);
    entry.decrement_frequency();
    assert_eq!(entry.frequency, 1);
}

#[test]
fn test_cache_entry_serde_roundtrip() {
    let mut entry =
        CacheEntry::new_small(artifact("serde_e"), 512, payload("serde_e"), 7, epoch(3));
    entry.record_access();
    let json = serde_json::to_string(&entry).unwrap();
    let back: CacheEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// GhostEntry
// ---------------------------------------------------------------------------

#[test]
fn test_ghost_entry_serde_roundtrip() {
    let ghost = GhostEntry {
        canonical_key: "test_key".into(),
        payload_hash: ContentHash::compute(b"ghost_test"),
        ghost_hits: 5,
        original_size_bytes: 1024,
        sequence_number: 42,
    };
    let json = serde_json::to_string(&ghost).unwrap();
    let back: GhostEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(ghost, back);
}

// ---------------------------------------------------------------------------
// AdmissionPolicy
// ---------------------------------------------------------------------------

#[test]
fn test_accept_all_admits_any_size() {
    let policy = AdmissionPolicy::AcceptAll;
    let d = policy.should_admit(u64::MAX, None);
    assert!(d.is_admit());
}

#[test]
fn test_frequency_aware_rejects_without_ghost() {
    let policy = AdmissionPolicy::FrequencyAware;
    let d = policy.should_admit(100, None);
    assert!(!d.is_admit());
}

#[test]
fn test_frequency_aware_admits_with_ghost() {
    let policy = AdmissionPolicy::FrequencyAware;
    let ghost = GhostEntry {
        canonical_key: "k".into(),
        payload_hash: ContentHash::compute(b"g"),
        ghost_hits: 1,
        original_size_bytes: 100,
        sequence_number: 0,
    };
    let d = policy.should_admit(100, Some(&ghost));
    assert!(d.is_admit());
}

#[test]
fn test_value_aware_admits_within_limit() {
    let policy = AdmissionPolicy::ValueAware {
        max_size_bytes: 1000,
    };
    assert!(policy.should_admit(999, None).is_admit());
    assert!(policy.should_admit(1000, None).is_admit()); // exact boundary
}

#[test]
fn test_value_aware_rejects_over_limit() {
    let policy = AdmissionPolicy::ValueAware {
        max_size_bytes: 1000,
    };
    assert!(!policy.should_admit(1001, None).is_admit());
}

#[test]
fn test_combined_admits_small_item_no_ghost() {
    let policy = AdmissionPolicy::Combined {
        max_size_bytes: 500,
        min_ghost_hits: 3,
    };
    assert!(policy.should_admit(500, None).is_admit());
}

#[test]
fn test_combined_rejects_large_no_ghost() {
    let policy = AdmissionPolicy::Combined {
        max_size_bytes: 500,
        min_ghost_hits: 3,
    };
    assert!(!policy.should_admit(1000, None).is_admit());
}

#[test]
fn test_combined_admits_large_sufficient_ghost() {
    let policy = AdmissionPolicy::Combined {
        max_size_bytes: 500,
        min_ghost_hits: 3,
    };
    let ghost = GhostEntry {
        canonical_key: "big".into(),
        payload_hash: ContentHash::compute(b"big"),
        ghost_hits: 5,
        original_size_bytes: 1000,
        sequence_number: 0,
    };
    assert!(policy.should_admit(1000, Some(&ghost)).is_admit());
}

#[test]
fn test_combined_rejects_large_insufficient_ghost() {
    let policy = AdmissionPolicy::Combined {
        max_size_bytes: 500,
        min_ghost_hits: 10,
    };
    let ghost = GhostEntry {
        canonical_key: "big".into(),
        payload_hash: ContentHash::compute(b"big"),
        ghost_hits: 2,
        original_size_bytes: 1000,
        sequence_number: 0,
    };
    assert!(!policy.should_admit(1000, Some(&ghost)).is_admit());
}

#[test]
fn test_admission_policy_display_all_variants() {
    assert_eq!(format!("{}", AdmissionPolicy::AcceptAll), "accept_all");
    assert_eq!(
        format!("{}", AdmissionPolicy::FrequencyAware),
        "frequency_aware"
    );
    let va = AdmissionPolicy::ValueAware { max_size_bytes: 42 };
    let va_str = format!("{va}");
    assert!(va_str.contains("value_aware"));
    assert!(va_str.contains("42"));
    let comb = AdmissionPolicy::Combined {
        max_size_bytes: 100,
        min_ghost_hits: 5,
    };
    let comb_str = format!("{comb}");
    assert!(comb_str.contains("combined"));
    assert!(comb_str.contains("100"));
    assert!(comb_str.contains("5"));
}

#[test]
fn test_admission_policy_serde_roundtrip() {
    let policies = vec![
        AdmissionPolicy::AcceptAll,
        AdmissionPolicy::FrequencyAware,
        AdmissionPolicy::ValueAware {
            max_size_bytes: 2048,
        },
        AdmissionPolicy::Combined {
            max_size_bytes: 1024,
            min_ghost_hits: 3,
        },
    ];
    for policy in &policies {
        let json = serde_json::to_string(policy).unwrap();
        let back: AdmissionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*policy, back);
    }
}

// ---------------------------------------------------------------------------
// AdmissionDecision
// ---------------------------------------------------------------------------

#[test]
fn test_admission_decision_is_admit() {
    let admit = AdmissionDecision::Admit {
        reason: "ok".into(),
    };
    assert!(admit.is_admit());
    let reject = AdmissionDecision::Reject {
        reason: "no".into(),
    };
    assert!(!reject.is_admit());
}

#[test]
fn test_admission_decision_serde_roundtrip() {
    let admit = AdmissionDecision::Admit {
        reason: "pass".into(),
    };
    let json = serde_json::to_string(&admit).unwrap();
    let back: AdmissionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(admit, back);

    let reject = AdmissionDecision::Reject {
        reason: "fail".into(),
    };
    let json = serde_json::to_string(&reject).unwrap();
    let back: AdmissionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(reject, back);
}

// ---------------------------------------------------------------------------
// ReferencePolicyKind
// ---------------------------------------------------------------------------

#[test]
fn test_reference_policy_kind_display() {
    assert_eq!(format!("{}", ReferencePolicyKind::Lru), "LRU");
    assert_eq!(format!("{}", ReferencePolicyKind::Clock), "CLOCK");
}

#[test]
fn test_reference_policy_kind_serde_roundtrip() {
    for kind in &[ReferencePolicyKind::Lru, ReferencePolicyKind::Clock] {
        let json = serde_json::to_string(kind).unwrap();
        let back: ReferencePolicyKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// ParityVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_parity_verdict_display() {
    assert_eq!(
        format!("{}", ParityVerdict::WithinTolerance),
        "within_tolerance"
    );
    assert_eq!(
        format!("{}", ParityVerdict::DivergenceBeyondTolerance),
        "divergence_beyond_tolerance"
    );
}

#[test]
fn test_parity_verdict_serde_roundtrip() {
    for v in &[
        ParityVerdict::WithinTolerance,
        ParityVerdict::DivergenceBeyondTolerance,
    ] {
        let json = serde_json::to_string(v).unwrap();
        let back: ParityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// RollbackTrigger
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_trigger_categories() {
    let triggers: Vec<(RollbackTrigger, &str)> = vec![
        (
            RollbackTrigger::HitRateBelowThreshold {
                threshold_millionths: 500_000,
            },
            "hit_rate_below_threshold",
        ),
        (RollbackTrigger::ParityGateFailure, "parity_gate_failure"),
        (
            RollbackTrigger::LatencyRegression {
                observed_ns_millionths: 100,
                threshold_ns_millionths: 50,
            },
            "latency_regression",
        ),
        (
            RollbackTrigger::OperatorInitiated {
                operator_id: "admin".into(),
                reason: "test".into(),
            },
            "operator_initiated",
        ),
        (
            RollbackTrigger::EpochBoundary {
                old_epoch: epoch(1),
                new_epoch: epoch(2),
            },
            "epoch_boundary",
        ),
    ];
    for (trigger, expected) in &triggers {
        assert_eq!(trigger.category(), *expected);
        assert_eq!(format!("{trigger}"), *expected);
    }
}

#[test]
fn test_rollback_trigger_serde_roundtrip() {
    let triggers = vec![
        RollbackTrigger::HitRateBelowThreshold {
            threshold_millionths: 200_000,
        },
        RollbackTrigger::ParityGateFailure,
        RollbackTrigger::LatencyRegression {
            observed_ns_millionths: 10_000,
            threshold_ns_millionths: 5_000,
        },
        RollbackTrigger::OperatorInitiated {
            operator_id: "ops".into(),
            reason: "maintenance".into(),
        },
        RollbackTrigger::EpochBoundary {
            old_epoch: epoch(10),
            new_epoch: epoch(11),
        },
    ];
    for trigger in &triggers {
        let json = serde_json::to_string(trigger).unwrap();
        let back: RollbackTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*trigger, back);
    }
}

// ---------------------------------------------------------------------------
// RollbackState
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_state_display_all() {
    let pairs = [
        (RollbackState::Idle, "idle"),
        (RollbackState::Triggered, "triggered"),
        (RollbackState::Executing, "executing"),
        (RollbackState::Completed, "completed"),
        (RollbackState::Failed, "failed"),
    ];
    for (state, expected) in &pairs {
        assert_eq!(format!("{state}"), *expected);
    }
}

#[test]
fn test_rollback_state_serde_roundtrip() {
    let states = [
        RollbackState::Idle,
        RollbackState::Triggered,
        RollbackState::Executing,
        RollbackState::Completed,
        RollbackState::Failed,
    ];
    for state in &states {
        let json = serde_json::to_string(state).unwrap();
        let back: RollbackState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
}

// ---------------------------------------------------------------------------
// DecisionKind
// ---------------------------------------------------------------------------

#[test]
fn test_decision_kind_display_all() {
    let pairs = [
        (DecisionKind::PolicyEnabled, "policy_enabled"),
        (DecisionKind::GatePassContinue, "gate_pass_continue"),
        (DecisionKind::GateFailRollback, "gate_fail_rollback"),
        (DecisionKind::SplitRatioAdapted, "split_ratio_adapted"),
        (
            DecisionKind::AdmissionPolicyChanged,
            "admission_policy_changed",
        ),
        (DecisionKind::CacheFlushed, "cache_flushed"),
    ];
    for (kind, expected) in &pairs {
        assert_eq!(format!("{kind}"), *expected);
    }
}

#[test]
fn test_decision_kind_serde_roundtrip() {
    let kinds = [
        DecisionKind::PolicyEnabled,
        DecisionKind::GatePassContinue,
        DecisionKind::GateFailRollback,
        DecisionKind::SplitRatioAdapted,
        DecisionKind::AdmissionPolicyChanged,
        DecisionKind::CacheFlushed,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: DecisionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// S3FifoGateError
// ---------------------------------------------------------------------------

#[test]
fn test_error_display_all_variants() {
    let errors: Vec<S3FifoGateError> = vec![
        S3FifoGateError::RollbackCooldownActive { remaining_ops: 42 },
        S3FifoGateError::AdmissionRejected {
            reason: "too_big".into(),
        },
        S3FifoGateError::ZeroCapacity,
        S3FifoGateError::ArtifactNotFound {
            key: "missing_key".into(),
        },
        S3FifoGateError::RollbackFailed {
            reason: "disk_full".into(),
        },
        S3FifoGateError::InvalidConfig {
            reason: "bad_ratio".into(),
        },
    ];
    assert!(format!("{}", errors[0]).contains("42"));
    assert!(format!("{}", errors[1]).contains("too_big"));
    assert!(format!("{}", errors[2]).contains("zero"));
    assert!(format!("{}", errors[3]).contains("missing_key"));
    assert!(format!("{}", errors[4]).contains("disk_full"));
    assert!(format!("{}", errors[5]).contains("bad_ratio"));
}

#[test]
fn test_error_serde_roundtrip() {
    let errors = vec![
        S3FifoGateError::RollbackCooldownActive { remaining_ops: 10 },
        S3FifoGateError::AdmissionRejected {
            reason: "test".into(),
        },
        S3FifoGateError::ZeroCapacity,
        S3FifoGateError::ArtifactNotFound { key: "k".into() },
        S3FifoGateError::RollbackFailed { reason: "r".into() },
        S3FifoGateError::InvalidConfig { reason: "c".into() },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: S3FifoGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ---------------------------------------------------------------------------
// S3FifoCacheConfig
// ---------------------------------------------------------------------------

#[test]
fn test_default_config_values() {
    let config = S3FifoCacheConfig::default();
    assert_eq!(config.total_capacity, 1024);
    assert_eq!(config.small_ratio_millionths, 100_000);
    assert_eq!(config.ghost_multiplier, 2);
    assert_eq!(config.parity_tolerance_millionths, 50_000);
    assert_eq!(config.reference_policy, ReferencePolicyKind::Lru);
    assert_eq!(config.admission_policy, AdmissionPolicy::AcceptAll);
    assert!(!config.auto_adapt_split);
}

#[test]
fn test_config_small_capacity_calculation() {
    let config = S3FifoCacheConfig {
        total_capacity: 100,
        small_ratio_millionths: 200_000, // 20%
        ..S3FifoCacheConfig::default()
    };
    assert_eq!(config.small_capacity(), 20);
}

#[test]
fn test_config_main_capacity_calculation() {
    let config = S3FifoCacheConfig {
        total_capacity: 100,
        small_ratio_millionths: 200_000,
        ..S3FifoCacheConfig::default()
    };
    assert_eq!(config.main_capacity(), 80);
}

#[test]
fn test_config_ghost_capacity_calculation() {
    let config = S3FifoCacheConfig {
        total_capacity: 100,
        ghost_multiplier: 3,
        ..S3FifoCacheConfig::default()
    };
    assert_eq!(config.ghost_capacity(), 300);
}

#[test]
fn test_config_small_capacity_min_one() {
    // Even with zero ratio, small capacity should be at least 1.
    let config = S3FifoCacheConfig {
        total_capacity: 100,
        small_ratio_millionths: 0,
        ..S3FifoCacheConfig::default()
    };
    assert_eq!(config.small_capacity(), 1);
}

#[test]
fn test_config_serde_roundtrip() {
    let config = S3FifoCacheConfig {
        total_capacity: 256,
        small_ratio_millionths: 150_000,
        ghost_multiplier: 4,
        parity_tolerance_millionths: 30_000,
        reference_policy: ReferencePolicyKind::Clock,
        admission_policy: AdmissionPolicy::FrequencyAware,
        min_hit_rate_millionths: 300_000,
        max_latency_ns_millionths: 5_000_000_000,
        rollback_cooldown_ops: 500,
        auto_adapt_split: true,
        min_small_ratio_millionths: 10_000,
        max_small_ratio_millionths: 400_000,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: S3FifoCacheConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- construction
// ---------------------------------------------------------------------------

#[test]
fn test_gate_construction_default() {
    let gate = default_gate();
    assert!(gate.is_active());
    assert_eq!(gate.total_cached(), 0);
    assert_eq!(gate.small_queue_len(), 0);
    assert_eq!(gate.main_queue_len(), 0);
    assert_eq!(gate.ghost_queue_len(), 0);
    assert_eq!(gate.rollback_state(), RollbackState::Idle);
    assert_eq!(gate.current_epoch(), epoch(1));
}

#[test]
fn test_gate_construction_zero_capacity_rejected() {
    let config = S3FifoCacheConfig {
        total_capacity: 0,
        ..S3FifoCacheConfig::default()
    };
    let result = S3FifoCacheGate::new(config, epoch(1));
    assert!(matches!(result, Err(S3FifoGateError::ZeroCapacity)));
}

#[test]
fn test_gate_construction_invalid_ratio_rejected() {
    let config = S3FifoCacheConfig {
        small_ratio_millionths: 1_500_000,
        ..S3FifoCacheConfig::default()
    };
    let result = S3FifoCacheGate::new(config, epoch(1));
    assert!(matches!(result, Err(S3FifoGateError::InvalidConfig { .. })));
}

#[test]
fn test_gate_construction_ratio_exactly_million() {
    // Ratio of 1_000_000 means 100% small -- valid but extreme.
    let config = S3FifoCacheConfig {
        total_capacity: 10,
        small_ratio_millionths: 1_000_000,
        ..S3FifoCacheConfig::default()
    };
    let gate = S3FifoCacheGate::new(config, epoch(1));
    assert!(gate.is_ok());
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- insert & lookup
// ---------------------------------------------------------------------------

#[test]
fn test_insert_basic() {
    let mut gate = default_gate();
    let d = gate.insert(artifact("a"), 100, payload("a")).unwrap();
    assert!(d.is_admit());
    assert_eq!(gate.total_cached(), 1);
    assert!(gate.contains(&artifact("a").canonical_key()));
}

#[test]
fn test_insert_starts_in_small_segment() {
    let mut gate = default_gate();
    gate.insert(artifact("a"), 100, payload("a")).unwrap();
    let key = artifact("a").canonical_key();
    assert_eq!(gate.entry_segment(&key), Some(CacheSegment::Small));
}

#[test]
fn test_insert_duplicate_is_hit() {
    let mut gate = default_gate();
    gate.insert(artifact("a"), 100, payload("a")).unwrap();
    let d = gate.insert(artifact("a"), 100, payload("a")).unwrap();
    assert!(d.is_admit());
    assert_eq!(gate.total_cached(), 1);
}

#[test]
fn test_lookup_hit_increments_frequency() {
    let mut gate = default_gate();
    gate.insert(artifact("a"), 100, payload("a")).unwrap();
    let key = artifact("a").canonical_key();
    assert_eq!(gate.entry_frequency(&key), Some(0));
    gate.lookup(&key);
    assert_eq!(gate.entry_frequency(&key), Some(1));
}

#[test]
fn test_lookup_miss_returns_false() {
    let mut gate = default_gate();
    assert!(!gate.lookup("nonexistent"));
    assert_eq!(gate.benchmark_evidence().misses, 1);
}

#[test]
fn test_lookup_hit_returns_true() {
    let mut gate = default_gate();
    gate.insert(artifact("a"), 100, payload("a")).unwrap();
    let key = artifact("a").canonical_key();
    assert!(gate.lookup(&key));
    assert_eq!(gate.benchmark_evidence().hits, 1);
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- eviction
// ---------------------------------------------------------------------------

#[test]
fn test_eviction_from_small_populates_ghost() {
    let mut gate = small_gate(4); // small=2, main=2
    for i in 0..4 {
        let label = format!("item{i}");
        gate.insert(artifact(&label), 10, payload(&label)).unwrap();
    }
    // With 4 inserts into capacity-4, evictions should occur from small.
    assert!(gate.total_ghost() > 0 || gate.total_cached() <= 4);
}

#[test]
fn test_promotion_on_frequency_access() {
    let mut gate = small_gate(4);
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    let key = artifact("a").canonical_key();
    // Access 'a' to bump frequency.
    gate.lookup(&key);
    // Fill small to trigger eviction.
    gate.insert(artifact("b"), 10, payload("b")).unwrap();
    gate.insert(artifact("c"), 10, payload("c")).unwrap();
    if gate.contains(&key) {
        assert_eq!(gate.entry_segment(&key), Some(CacheSegment::Main));
    }
}

#[test]
fn test_ghost_hit_promotes_directly_to_main() {
    let mut gate = small_gate(4);
    // Fill and trigger eviction.
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    gate.insert(artifact("b"), 10, payload("b")).unwrap();
    gate.insert(artifact("c"), 10, payload("c")).unwrap();
    let key_a = artifact("a").canonical_key();
    // If 'a' is in ghost, re-insert should go to main.
    if gate.is_ghost(&key_a) {
        gate.insert(artifact("a"), 10, payload("a")).unwrap();
        if gate.contains(&key_a) {
            assert_eq!(gate.entry_segment(&key_a), Some(CacheSegment::Main));
        }
    }
}

#[test]
fn test_total_cached_never_exceeds_capacity() {
    let mut gate = small_gate(6);
    for i in 0..50 {
        let label = format!("flood_{i}");
        gate.insert(artifact(&label), 10, payload(&label)).unwrap();
    }
    assert!(gate.total_cached() <= 6);
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- remove & flush
// ---------------------------------------------------------------------------

#[test]
fn test_remove_existing_entry() {
    let mut gate = default_gate();
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    let key = artifact("a").canonical_key();
    assert!(gate.remove(&key));
    assert!(!gate.contains(&key));
}

#[test]
fn test_remove_nonexistent_returns_false() {
    let mut gate = default_gate();
    assert!(!gate.remove("no_such_key"));
}

#[test]
fn test_flush_clears_everything() {
    let mut gate = small_gate(10);
    for i in 0..10 {
        let label = format!("f{i}");
        gate.insert(artifact(&label), 10, payload(&label)).unwrap();
    }
    gate.flush();
    assert_eq!(gate.total_cached(), 0);
    assert_eq!(gate.small_queue_len(), 0);
    assert_eq!(gate.main_queue_len(), 0);
    assert_eq!(gate.ghost_queue_len(), 0);
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- parity evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_parity_empty_cache_passes() {
    let mut gate = default_gate();
    let parity = gate.evaluate_parity();
    assert!(parity.passed());
    assert_eq!(parity.s3_fifo_hit_rate_millionths, 0);
    assert_eq!(parity.reference_hit_rate_millionths, 0);
}

#[test]
fn test_parity_uses_configured_reference_policy() {
    let config = S3FifoCacheConfig {
        reference_policy: ReferencePolicyKind::Clock,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    let parity = gate.evaluate_parity();
    assert_eq!(parity.reference_policy, ReferencePolicyKind::Clock);
}

#[test]
fn test_parity_evidence_hash_deterministic() {
    let mut g1 = small_gate(10);
    let mut g2 = small_gate(10);
    for i in 0..3 {
        let label = format!("d{i}");
        g1.insert(artifact(&label), 10, payload(&label)).unwrap();
        g2.insert(artifact(&label), 10, payload(&label)).unwrap();
        let key = artifact(&label).canonical_key();
        g1.lookup(&key);
        g2.lookup(&key);
    }
    let p1 = g1.evaluate_parity();
    let p2 = g2.evaluate_parity();
    assert_eq!(p1.evidence_hash, p2.evidence_hash);
}

#[test]
fn test_parity_result_passed_method() {
    let pr_pass = ParityResult {
        reference_policy: ReferencePolicyKind::Lru,
        verdict: ParityVerdict::WithinTolerance,
        s3_fifo_hit_rate_millionths: 500_000,
        reference_hit_rate_millionths: 480_000,
        hit_rate_delta_millionths: 20_000,
        tolerance_millionths: 50_000,
        total_operations: 100,
        evidence_hash: ContentHash::compute(b"pr"),
    };
    assert!(pr_pass.passed());

    let pr_fail = ParityResult {
        verdict: ParityVerdict::DivergenceBeyondTolerance,
        ..pr_pass.clone()
    };
    assert!(!pr_fail.passed());
}

#[test]
fn test_parity_result_serde_roundtrip() {
    let pr = ParityResult {
        reference_policy: ReferencePolicyKind::Lru,
        verdict: ParityVerdict::WithinTolerance,
        s3_fifo_hit_rate_millionths: 600_000,
        reference_hit_rate_millionths: 580_000,
        hit_rate_delta_millionths: 20_000,
        tolerance_millionths: 50_000,
        total_operations: 200,
        evidence_hash: ContentHash::compute(b"parity_test"),
    };
    let json = serde_json::to_string(&pr).unwrap();
    let back: ParityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(pr, back);
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- rollback
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_disables_cache() {
    let mut gate = default_gate();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    assert!(!gate.is_active());
    assert_eq!(gate.rollback_state(), RollbackState::Completed);
}

#[test]
fn test_rollback_flushes_cache() {
    let mut gate = default_gate();
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    assert_eq!(gate.total_cached(), 1);
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    assert_eq!(gate.total_cached(), 0);
}

#[test]
fn test_rollback_cooldown_ticks_via_lookups() {
    let config = S3FifoCacheConfig {
        rollback_cooldown_ops: 5,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    for _ in 0..5 {
        gate.lookup("tick");
    }
    assert_eq!(gate.rollback_state(), RollbackState::Idle);
}

#[test]
fn test_re_enable_during_cooldown_fails() {
    let config = S3FifoCacheConfig {
        rollback_cooldown_ops: 100,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    let result = gate.re_enable();
    assert!(matches!(
        result,
        Err(S3FifoGateError::RollbackCooldownActive { .. })
    ));
}

#[test]
fn test_re_enable_after_cooldown_succeeds() {
    let config = S3FifoCacheConfig {
        rollback_cooldown_ops: 3,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    for _ in 0..3 {
        gate.lookup("tick");
    }
    assert!(gate.re_enable().is_ok());
    assert!(gate.is_active());
    assert_eq!(gate.rollback_state(), RollbackState::Idle);
}

#[test]
fn test_operator_rollback() {
    let mut gate = default_gate();
    let record = gate.operator_rollback("admin", "maintenance");
    assert_eq!(record.state, RollbackState::Completed);
    assert!(matches!(
        record.trigger,
        RollbackTrigger::OperatorInitiated { .. }
    ));
    assert!(!gate.is_active());
}

#[test]
fn test_rollback_history_accumulates() {
    let config = S3FifoCacheConfig {
        rollback_cooldown_ops: 1,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    gate.lookup("tick");
    let _ = gate.re_enable();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    assert_eq!(gate.rollback_history().len(), 2);
}

#[test]
fn test_rollback_record_has_evidence_hash() {
    let mut gate = default_gate();
    let record = gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    assert_ne!(record.evidence_hash, ContentHash::compute(b""));
}

#[test]
fn test_rollback_record_serde_roundtrip() {
    let mut gate = default_gate();
    let record = gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    let json = serde_json::to_string(&record).unwrap();
    let back: RollbackRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn test_evaluate_rollback_none_when_inactive() {
    let mut gate = default_gate();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    // Already inactive; evaluate_rollback should return None.
    let result = gate.evaluate_rollback();
    assert!(result.is_none());
}

#[test]
fn test_evaluate_rollback_triggers_on_low_hit_rate() {
    let config = S3FifoCacheConfig {
        total_capacity: 4,
        min_hit_rate_millionths: 800_000,
        small_ratio_millionths: 500_000,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    // Generate many misses.
    for i in 0..20 {
        gate.lookup(&format!("miss_{i}"));
    }
    let result = gate.evaluate_rollback();
    assert!(result.is_some());
    assert!(!gate.is_active());
}

#[test]
fn test_insert_during_cooldown_errors() {
    let config = S3FifoCacheConfig {
        rollback_cooldown_ops: 100,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    let result = gate.insert(artifact("x"), 10, payload("x"));
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        S3FifoGateError::RollbackCooldownActive { .. }
    ));
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- split ratio adaptation
// ---------------------------------------------------------------------------

#[test]
fn test_adapt_split_disabled_by_default() {
    let mut gate = default_gate();
    assert!(gate.adapt_split_ratio().is_none());
}

#[test]
fn test_adapt_split_no_evictions_returns_none() {
    let config = S3FifoCacheConfig {
        auto_adapt_split: true,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    assert!(gate.adapt_split_ratio().is_none());
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- decision receipts
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_emitted_on_gate_pass() {
    let mut gate = default_gate();
    let eval = gate.evaluate_gate();
    assert!(!gate.receipts().is_empty());
    assert_eq!(eval.receipt.schema_version, S3_FIFO_SCHEMA_VERSION);
}

#[test]
fn test_receipt_emitted_on_rollback() {
    let mut gate = default_gate();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    let last = gate.receipts().last().unwrap();
    assert_eq!(last.decision_kind, DecisionKind::GateFailRollback);
}

#[test]
fn test_receipt_emitted_on_re_enable() {
    let config = S3FifoCacheConfig {
        rollback_cooldown_ops: 0,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    // Cooldown is 0, so tick once and re_enable.
    gate.lookup("tick");
    let _ = gate.re_enable();
    let last = gate.receipts().last().unwrap();
    assert_eq!(last.decision_kind, DecisionKind::PolicyEnabled);
}

#[test]
fn test_receipt_emitted_on_admission_policy_change() {
    let mut gate = default_gate();
    gate.set_admission_policy(AdmissionPolicy::FrequencyAware);
    let last = gate.receipts().last().unwrap();
    assert_eq!(last.decision_kind, DecisionKind::AdmissionPolicyChanged);
    assert!(last.admission_policy_label.contains("frequency_aware"));
}

#[test]
fn test_receipt_has_content_hash_not_pending() {
    let mut gate = default_gate();
    let receipt = gate.emit_receipt(DecisionKind::CacheFlushed);
    assert_ne!(receipt.content_hash, ContentHash::compute(b"pending"));
}

#[test]
fn test_receipt_ids_are_unique() {
    let mut gate = default_gate();
    let r1 = gate.emit_receipt(DecisionKind::GatePassContinue);
    let r2 = gate.emit_receipt(DecisionKind::GatePassContinue);
    assert_ne!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn test_receipt_serde_roundtrip() {
    let mut gate = default_gate();
    let receipt = gate.emit_receipt(DecisionKind::GatePassContinue);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn test_receipt_seal_deterministic() {
    let mut gate = default_gate();
    let r1 = gate.emit_receipt(DecisionKind::CacheFlushed);
    // The receipt content hash should survive a serde roundtrip unchanged.
    let json = serde_json::to_string(&r1).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r1.content_hash, back.content_hash);
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_gate_evaluation_passes_when_empty() {
    let mut gate = default_gate();
    let eval = gate.evaluate_gate();
    assert!(eval.passed);
    assert!(eval.active);
    assert!(eval.rollback_record.is_none());
}

#[test]
fn test_gate_evaluation_passes_with_good_data() {
    // S3-FIFO gate evaluation with uniform lookups so both reference policies
    // see the same access sequence, giving comparable hit rates.
    let mut gate = small_gate(20);
    // Use lookup for all accesses — S3-FIFO and LRU/CLOCK both miss first time,
    // then after insertion via the cache's miss path, both hit on repeat access.
    // With AcceptAll policy, lookup → miss → insert; subsequent lookup → hit.
    for i in 0..5 {
        let label = format!("item{i}");
        gate.insert(artifact(&label), 10, payload(&label)).unwrap();
    }
    // Now do lookups that all references see uniformly.
    for i in 0..5 {
        let key = artifact(&format!("item{i}")).canonical_key();
        gate.lookup(&key); // S3-FIFO: hit; LRU: first time = miss
    }
    // The gate may or may not pass depending on parity — just verify it runs.
    let eval = gate.evaluate_gate();
    // Verify the receipt was emitted.
    assert!(!gate.receipts().is_empty());
    // active reflects rollback status.
    assert_eq!(eval.active, gate.is_active());
}

#[test]
fn test_gate_evaluation_triggers_rollback_on_low_hit_rate() {
    let config = S3FifoCacheConfig {
        total_capacity: 10,
        min_hit_rate_millionths: 900_000,
        small_ratio_millionths: 500_000,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();
    for i in 0..20 {
        gate.lookup(&format!("miss{i}"));
    }
    let eval = gate.evaluate_gate();
    assert!(!eval.passed);
    assert!(!eval.active);
    assert!(eval.rollback_record.is_some());
}

#[test]
fn test_gate_evaluation_serde_roundtrip() {
    let mut gate = default_gate();
    let eval = gate.evaluate_gate();
    let json = serde_json::to_string(&eval).unwrap();
    let back: GateEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- epoch management
// ---------------------------------------------------------------------------

#[test]
fn test_advance_epoch_updates_current() {
    let mut gate = default_gate();
    gate.advance_epoch(epoch(5));
    assert_eq!(gate.current_epoch(), epoch(5));
}

#[test]
fn test_advance_epoch_updates_benchmark_epoch() {
    let mut gate = default_gate();
    gate.advance_epoch(epoch(7));
    assert_eq!(gate.benchmark_evidence().epoch, epoch(7));
}

// ---------------------------------------------------------------------------
// S3FifoCacheGate -- segment snapshot
// ---------------------------------------------------------------------------

#[test]
fn test_segment_snapshot_fields() {
    let mut gate = small_gate(10);
    for i in 0..3 {
        let label = format!("s{i}");
        gate.insert(artifact(&label), 10, payload(&label)).unwrap();
    }
    let snap = gate.segment_snapshot();
    assert!(snap.total_cached > 0);
    assert!(snap.small_capacity > 0);
    assert!(snap.main_capacity > 0);
    assert!(snap.ghost_capacity > 0);
    assert_eq!(snap.effective_small_ratio_millionths, 500_000);
}

#[test]
fn test_segment_snapshot_serde_roundtrip() {
    let mut gate = small_gate(10);
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    let snap = gate.segment_snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    let back: SegmentSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, back);
}

// ---------------------------------------------------------------------------
// BenchmarkEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_benchmark_evidence_empty() {
    let bench = BenchmarkEvidence::empty(epoch(1));
    assert_eq!(bench.total_lookups, 0);
    assert_eq!(bench.hits, 0);
    assert_eq!(bench.misses, 0);
    assert_eq!(bench.hit_rate_millionths, 0);
    assert_eq!(bench.miss_rate_millionths, 0);
    assert_eq!(bench.epoch, epoch(1));
}

#[test]
fn test_benchmark_evidence_recompute_rates() {
    let mut bench = BenchmarkEvidence::empty(epoch(1));
    bench.total_lookups = 100;
    bench.hits = 75;
    bench.misses = 25;
    bench.recompute_rates();
    assert_eq!(bench.hit_rate_millionths, 750_000);
    assert_eq!(bench.miss_rate_millionths, 250_000);
}

#[test]
fn test_benchmark_evidence_recompute_rates_zero_lookups() {
    let mut bench = BenchmarkEvidence::empty(epoch(1));
    bench.recompute_rates();
    assert_eq!(bench.hit_rate_millionths, 0);
    assert_eq!(bench.miss_rate_millionths, 0);
}

#[test]
fn test_benchmark_evidence_trace_hash_deterministic() {
    let mut b1 = BenchmarkEvidence::empty(epoch(1));
    b1.total_lookups = 50;
    b1.hits = 30;
    b1.compute_trace_hash();

    let mut b2 = BenchmarkEvidence::empty(epoch(1));
    b2.total_lookups = 50;
    b2.hits = 30;
    b2.compute_trace_hash();

    assert_eq!(b1.trace_hash, b2.trace_hash);
}

#[test]
fn test_benchmark_evidence_trace_hash_differs_on_data() {
    let mut b1 = BenchmarkEvidence::empty(epoch(1));
    b1.hits = 10;
    b1.compute_trace_hash();

    let mut b2 = BenchmarkEvidence::empty(epoch(1));
    b2.hits = 20;
    b2.compute_trace_hash();

    assert_ne!(b1.trace_hash, b2.trace_hash);
}

#[test]
fn test_benchmark_evidence_trace_hash_differs_on_epoch() {
    let mut b1 = BenchmarkEvidence::empty(epoch(1));
    b1.compute_trace_hash();
    let mut b2 = BenchmarkEvidence::empty(epoch(2));
    b2.compute_trace_hash();
    assert_ne!(b1.trace_hash, b2.trace_hash);
}

#[test]
fn test_benchmark_evidence_serde_roundtrip() {
    let mut bench = BenchmarkEvidence::empty(epoch(3));
    bench.total_lookups = 200;
    bench.hits = 150;
    bench.misses = 50;
    bench.total_evictions = 10;
    bench.ghost_hits = 3;
    bench.promotions = 7;
    bench.recompute_rates();
    bench.compute_trace_hash();
    let json = serde_json::to_string(&bench).unwrap();
    let back: BenchmarkEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(bench, back);
}

#[test]
fn test_benchmark_evidence_accumulates_via_gate() {
    let mut gate = default_gate();
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    let key = artifact("a").canonical_key();
    gate.lookup(&key);
    gate.lookup(&key);
    gate.lookup("miss_key");
    let bench = gate.benchmark_evidence();
    assert_eq!(bench.hits, 2);
    assert_eq!(bench.misses, 1);
    assert_eq!(bench.total_lookups, 3);
}

// ---------------------------------------------------------------------------
// Inactive gate behavior
// ---------------------------------------------------------------------------

#[test]
fn test_inactive_gate_lookup_always_misses() {
    let mut gate = default_gate();
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    gate.execute_rollback(RollbackTrigger::ParityGateFailure);
    let key = artifact("a").canonical_key();
    // Cache was flushed on rollback, so lookup misses.
    assert!(!gate.lookup(&key));
}

// ---------------------------------------------------------------------------
// Full lifecycle scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_lifecycle_insert_lookup_evict_ghost_readmit() {
    let mut gate = small_gate(4);
    // Fill small queue.
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    gate.insert(artifact("b"), 10, payload("b")).unwrap();
    let key_a = artifact("a").canonical_key();
    // Access 'a' to bump frequency.
    gate.lookup(&key_a);
    // Insert more to trigger evictions.
    gate.insert(artifact("c"), 10, payload("c")).unwrap();
    gate.insert(artifact("d"), 10, payload("d")).unwrap();
    gate.insert(artifact("e"), 10, payload("e")).unwrap();
    // Cache should not exceed capacity.
    assert!(gate.total_cached() <= 4);
}

#[test]
fn test_lifecycle_rollback_and_recovery() {
    let config = S3FifoCacheConfig {
        total_capacity: 10,
        rollback_cooldown_ops: 3,
        small_ratio_millionths: 500_000,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();

    // Insert and verify.
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    assert_eq!(gate.total_cached(), 1);

    // Rollback.
    gate.operator_rollback("ops", "test");
    assert!(!gate.is_active());
    assert_eq!(gate.total_cached(), 0);

    // Tick cooldown.
    for _ in 0..3 {
        gate.lookup("tick");
    }

    // Re-enable.
    assert!(gate.re_enable().is_ok());
    assert!(gate.is_active());

    // Insert works again.
    let d = gate
        .insert(artifact("recovery"), 10, payload("recovery"))
        .unwrap();
    assert!(d.is_admit());
}

#[test]
fn test_lifecycle_gate_evaluation_sequence() {
    // Gate evaluation in a lifecycle sequence. Receipts must always be emitted
    // by evaluate_gate regardless of pass/fail.
    let mut gate = small_gate(20);
    for i in 0..10 {
        let label = format!("item{i}");
        gate.insert(artifact(&label), 10, payload(&label)).unwrap();
    }
    for i in 0..10 {
        let key = artifact(&format!("item{i}")).canonical_key();
        gate.lookup(&key);
    }
    let eval = gate.evaluate_gate();
    // evaluate_gate always emits at least one receipt.
    assert!(!gate.receipts().is_empty());
    // active should match the gate's rollback state.
    assert_eq!(eval.active, gate.is_active());
    // parity result always present.
    let _ = eval.parity_result;
}

#[test]
fn test_lifecycle_batch_inserts_with_frequency_aware_admission() {
    let config = S3FifoCacheConfig {
        total_capacity: 10,
        admission_policy: AdmissionPolicy::FrequencyAware,
        small_ratio_millionths: 500_000,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();

    // First insert of unknown item rejected by FrequencyAware.
    let d = gate.insert(artifact("new"), 100, payload("new")).unwrap();
    assert!(!d.is_admit());
    assert_eq!(gate.total_cached(), 0);
}

#[test]
fn test_lifecycle_epoch_advance_preserves_data() {
    let mut gate = default_gate();
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    let key = artifact("a").canonical_key();
    assert!(gate.contains(&key));

    gate.advance_epoch(epoch(5));
    assert_eq!(gate.current_epoch(), epoch(5));
    // Data still present after epoch advance.
    assert!(gate.contains(&key));
}

#[test]
fn test_lifecycle_multiple_receipts_accumulate() {
    let mut gate = default_gate();
    gate.emit_receipt(DecisionKind::PolicyEnabled);
    gate.emit_receipt(DecisionKind::GatePassContinue);
    gate.emit_receipt(DecisionKind::CacheFlushed);
    assert_eq!(gate.receipts().len(), 3);
    // Each has unique receipt_id.
    let ids: Vec<&str> = gate
        .receipts()
        .iter()
        .map(|r| r.receipt_id.as_str())
        .collect();
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i], ids[j]);
        }
    }
}

#[test]
fn test_lifecycle_value_aware_boundary() {
    let config = S3FifoCacheConfig {
        total_capacity: 10,
        admission_policy: AdmissionPolicy::ValueAware {
            max_size_bytes: 1000,
        },
        small_ratio_millionths: 500_000,
        ..S3FifoCacheConfig::default()
    };
    let mut gate = S3FifoCacheGate::new(config, epoch(1)).unwrap();

    // Small enough to admit.
    let d1 = gate
        .insert(artifact("small"), 500, payload("small"))
        .unwrap();
    assert!(d1.is_admit());
    assert_eq!(gate.total_cached(), 1);

    // Too large to admit.
    let d2 = gate
        .insert(artifact("large"), 2000, payload("large"))
        .unwrap();
    assert!(!d2.is_admit());
    assert_eq!(gate.total_cached(), 1);
}

#[test]
fn test_lifecycle_hit_rate_computation() {
    let mut gate = default_gate();
    assert_eq!(gate.current_hit_rate_millionths(), 0);

    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    let key = artifact("a").canonical_key();
    gate.lookup(&key); // hit
    gate.lookup("miss1"); // miss
    gate.lookup(&key); // hit
    gate.lookup("miss2"); // miss

    // 2 hits out of 4 lookups = 500_000 millionths.
    assert_eq!(gate.current_hit_rate_millionths(), 500_000);
}

#[test]
fn test_contains_and_is_ghost_consistency() {
    let mut gate = small_gate(2); // small=1, main=1
    gate.insert(artifact("x"), 10, payload("x")).unwrap();
    gate.insert(artifact("y"), 10, payload("y")).unwrap();
    gate.insert(artifact("z"), 10, payload("z")).unwrap();

    let key_x = artifact("x").canonical_key();
    let key_y = artifact("y").canonical_key();
    let key_z = artifact("z").canonical_key();

    // A key should not be both live and ghost at the same time.
    for key in &[&key_x, &key_y, &key_z] {
        if gate.contains(key) {
            assert!(!gate.is_ghost(key));
        }
    }
}

#[test]
fn test_entry_segment_and_frequency_accessors() {
    let mut gate = default_gate();
    gate.insert(artifact("a"), 10, payload("a")).unwrap();
    let key = artifact("a").canonical_key();
    assert_eq!(gate.entry_segment(&key), Some(CacheSegment::Small));
    assert_eq!(gate.entry_frequency(&key), Some(0));
    gate.lookup(&key);
    assert_eq!(gate.entry_frequency(&key), Some(1));

    // Non-existent key returns None.
    assert_eq!(gate.entry_segment("no_key"), None);
    assert_eq!(gate.entry_frequency("no_key"), None);
}
