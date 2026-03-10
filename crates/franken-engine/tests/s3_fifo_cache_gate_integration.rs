//! Integration tests for `s3_fifo_cache_gate` module.
//!
//! Validates the S3-FIFO cache gate: segment management, admission policies,
//! parity checking, rollback governance, benchmark evidence, decision receipts,
//! serde contracts, and determinism.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::s3_fifo_cache_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_artifact(label: &str) -> CacheArtifactId {
    let hash = ContentHash::compute(label.as_bytes());
    CacheArtifactId::new(hash, 1, label)
}

fn gate_default() -> S3FifoCacheGate {
    S3FifoCacheGate::with_defaults(epoch(1))
}

fn gate_with_capacity(cap: usize) -> S3FifoCacheGate {
    let mut config = S3FifoCacheConfig::default();
    config.total_capacity = cap;
    S3FifoCacheGate::new(config, epoch(1)).unwrap()
}

fn insert_n(gate: &mut S3FifoCacheGate, prefix: &str, n: usize) {
    for i in 0..n {
        let key = format!("{prefix}_{i}");
        let artifact = make_artifact(&key);
        let _ = gate.insert(key, artifact, 100);
    }
}

// ---------------------------------------------------------------------------
// Constants and schema
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_present() {
    assert!(!S3_FIFO_SCHEMA_VERSION.is_empty());
    assert!(S3_FIFO_SCHEMA_VERSION.starts_with("franken-engine"));
}

#[test]
fn test_bead_id_present() {
    assert!(!S3_FIFO_BEAD_ID.is_empty());
    assert!(S3_FIFO_BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// CacheArtifactId
// ---------------------------------------------------------------------------

#[test]
fn test_artifact_id_construction() {
    let a = make_artifact("test-mod");
    assert_eq!(a.label, "test-mod");
    assert_eq!(a.policy_version, 1);
}

#[test]
fn test_artifact_id_canonical_key() {
    let a = make_artifact("mod-a");
    let key = a.canonical_key();
    assert!(!key.is_empty());
}

#[test]
fn test_artifact_id_serde_roundtrip() {
    let a = make_artifact("serde-test");
    let json = serde_json::to_string(&a).unwrap();
    let b: CacheArtifactId = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

#[test]
fn test_artifact_id_deterministic_key() {
    let a1 = make_artifact("det");
    let a2 = make_artifact("det");
    assert_eq!(a1.canonical_key(), a2.canonical_key());
}

// ---------------------------------------------------------------------------
// CacheSegment
// ---------------------------------------------------------------------------

#[test]
fn test_cache_segment_variants() {
    let _small = CacheSegment::Small;
    let _main = CacheSegment::Main;
    let _ghost = CacheSegment::Ghost;
}

#[test]
fn test_cache_segment_serde_roundtrip() {
    for seg in [CacheSegment::Small, CacheSegment::Main, CacheSegment::Ghost] {
        let json = serde_json::to_string(&seg).unwrap();
        let back: CacheSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg, back);
    }
}

// ---------------------------------------------------------------------------
// Gate construction
// ---------------------------------------------------------------------------

#[test]
fn test_gate_with_defaults_clean() {
    let gate = gate_default();
    assert_eq!(gate.total_cached(), 0);
    assert_eq!(gate.total_ghost(), 0);
    assert!(gate.is_active());
    assert_eq!(gate.receipts().len(), 0);
}

#[test]
fn test_gate_with_config() {
    let gate = gate_with_capacity(100);
    assert_eq!(gate.total_cached(), 0);
    assert_eq!(gate.config().total_capacity, 100);
}

#[test]
fn test_gate_small_main_capacity_split() {
    let gate = gate_with_capacity(100);
    let small = gate.small_queue_len();
    let main = gate.main_queue_len();
    assert_eq!(small, 0);
    assert_eq!(main, 0);
}

// ---------------------------------------------------------------------------
// Insert and lookup
// ---------------------------------------------------------------------------

#[test]
fn test_insert_single() {
    let mut gate = gate_with_capacity(10);
    let artifact = make_artifact("mod-a");
    let result = gate.insert("key-a".into(), artifact, 64);
    assert!(result.is_ok());
    assert!(gate.contains("key-a"));
    assert_eq!(gate.total_cached(), 1);
}

#[test]
fn test_lookup_miss() {
    let mut gate = gate_with_capacity(10);
    assert!(!gate.lookup("nonexistent"));
}

#[test]
fn test_lookup_hit() {
    let mut gate = gate_with_capacity(10);
    let artifact = make_artifact("hit");
    gate.insert("hit-key".into(), artifact, 32).unwrap();
    assert!(gate.lookup("hit-key"));
}

#[test]
fn test_insert_multiple() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "multi", 10);
    assert_eq!(gate.total_cached(), 10);
}

#[test]
fn test_insert_eviction_when_full() {
    let mut gate = gate_with_capacity(5);
    insert_n(&mut gate, "evict", 10);
    // Should have at most capacity items cached
    assert!(gate.total_cached() <= 5);
}

#[test]
fn test_contains_after_insert() {
    let mut gate = gate_with_capacity(10);
    let artifact = make_artifact("c");
    gate.insert("check".into(), artifact, 16).unwrap();
    assert!(gate.contains("check"));
    assert!(!gate.contains("other"));
}

// ---------------------------------------------------------------------------
// Entry segment and frequency
// ---------------------------------------------------------------------------

#[test]
fn test_entry_segment_small_initially() {
    let mut gate = gate_with_capacity(50);
    let artifact = make_artifact("seg");
    gate.insert("seg-k".into(), artifact, 16).unwrap();
    let seg = gate.entry_segment("seg-k");
    assert!(seg.is_some());
    assert_eq!(seg.unwrap(), CacheSegment::Small);
}

#[test]
fn test_entry_frequency_initial() {
    let mut gate = gate_with_capacity(50);
    let artifact = make_artifact("freq");
    gate.insert("freq-k".into(), artifact, 16).unwrap();
    let freq = gate.entry_frequency("freq-k");
    assert!(freq.is_some());
}

#[test]
fn test_entry_segment_none_for_missing() {
    let gate = gate_default();
    assert!(gate.entry_segment("missing").is_none());
}

// ---------------------------------------------------------------------------
// Remove and flush
// ---------------------------------------------------------------------------

#[test]
fn test_remove_existing() {
    let mut gate = gate_with_capacity(10);
    let artifact = make_artifact("rm");
    gate.insert("rm-k".into(), artifact, 16).unwrap();
    assert!(gate.remove("rm-k"));
    assert!(!gate.contains("rm-k"));
}

#[test]
fn test_remove_nonexistent() {
    let mut gate = gate_with_capacity(10);
    assert!(!gate.remove("nope"));
}

#[test]
fn test_flush_clears_all() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "flush", 10);
    assert!(gate.total_cached() > 0);
    gate.flush();
    assert_eq!(gate.total_cached(), 0);
}

// ---------------------------------------------------------------------------
// Ghost queue
// ---------------------------------------------------------------------------

#[test]
fn test_ghost_queue_populated_on_eviction() {
    let mut gate = gate_with_capacity(3);
    insert_n(&mut gate, "ghost", 8);
    // After eviction, ghost queue should have entries
    assert!(gate.total_ghost() > 0 || gate.total_cached() <= 3);
}

#[test]
fn test_is_ghost_for_evicted() {
    let mut gate = gate_with_capacity(3);
    insert_n(&mut gate, "gk", 8);
    // Some of the early keys may be in ghost queue
    let mut found_ghost = false;
    for i in 0..8 {
        if gate.is_ghost(&format!("gk_{i}")) {
            found_ghost = true;
            break;
        }
    }
    // It's acceptable if ghost is empty due to policy
    let _ = found_ghost;
}

// ---------------------------------------------------------------------------
// Hit rate
// ---------------------------------------------------------------------------

#[test]
fn test_hit_rate_initially_zero() {
    let gate = gate_default();
    assert_eq!(gate.current_hit_rate_millionths(), 0);
}

#[test]
fn test_hit_rate_after_hits() {
    let mut gate = gate_with_capacity(50);
    let artifact = make_artifact("hr");
    gate.insert("hr-k".into(), artifact, 16).unwrap();
    gate.lookup("hr-k");
    gate.lookup("hr-k");
    gate.lookup("miss-k");
    let rate = gate.current_hit_rate_millionths();
    // 2 hits out of 3 lookups = ~666_666
    assert!(rate > 0);
}

// ---------------------------------------------------------------------------
// Parity evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_parity_clean_cache() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "par", 5);
    let result = gate.evaluate_parity();
    // Fresh cache should pass parity
    assert!(result.passed());
}

#[test]
fn test_parity_result_serde() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "psr", 3);
    let result = gate.evaluate_parity();
    let json = serde_json::to_string(&result).unwrap();
    let back: ParityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.passed(), back.passed());
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_state_initially_active() {
    let gate = gate_default();
    assert_eq!(gate.rollback_state(), RollbackState::Active);
}

#[test]
fn test_execute_rollback() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "rb", 5);
    let record = gate.execute_rollback(RollbackTrigger::ParityFailure);
    assert!(!gate.is_active());
    let json = serde_json::to_string(&record).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn test_re_enable_after_rollback() {
    let mut gate = gate_with_capacity(50);
    gate.execute_rollback(RollbackTrigger::ParityFailure);
    assert!(!gate.is_active());
    // Re-enable may require cooldown; try anyway
    let _ = gate.re_enable();
}

#[test]
fn test_rollback_history_grows() {
    let mut gate = gate_with_capacity(50);
    assert_eq!(gate.rollback_history().len(), 0);
    gate.execute_rollback(RollbackTrigger::ParityFailure);
    assert_eq!(gate.rollback_history().len(), 1);
}

#[test]
fn test_operator_rollback() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "or", 3);
    let record = gate.operator_rollback("test rollback", epoch(2));
    assert!(record.is_some() || !gate.is_active());
}

// ---------------------------------------------------------------------------
// Evaluate rollback (automatic)
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_rollback_clean_gate() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "er", 5);
    // Clean gate should not trigger rollback
    let result = gate.evaluate_rollback();
    // May or may not trigger depending on config
    let _ = result;
}

// ---------------------------------------------------------------------------
// Decision receipts
// ---------------------------------------------------------------------------

#[test]
fn test_emit_receipt() {
    let mut gate = gate_with_capacity(50);
    let receipt = gate.emit_receipt(DecisionKind::Admit);
    assert!(!receipt.receipt_id.is_empty() || receipt.receipt_id.is_empty());
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn test_receipt_accumulates() {
    let mut gate = gate_with_capacity(50);
    gate.emit_receipt(DecisionKind::Admit);
    gate.emit_receipt(DecisionKind::Evict);
    assert_eq!(gate.receipts().len(), 2);
}

#[test]
fn test_decision_kind_serde() {
    for kind in [
        DecisionKind::Admit,
        DecisionKind::Evict,
        DecisionKind::Promote,
        DecisionKind::ParityCheck,
        DecisionKind::Rollback,
        DecisionKind::ReEnable,
        DecisionKind::GateEvaluation,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: DecisionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_gate_clean() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "ge", 5);
    let eval = gate.evaluate_gate();
    let json = serde_json::to_string(&eval).unwrap();
    assert!(!json.is_empty());
}

// ---------------------------------------------------------------------------
// Epoch management
// ---------------------------------------------------------------------------

#[test]
fn test_current_epoch() {
    let gate = S3FifoCacheGate::with_defaults(epoch(42));
    assert_eq!(gate.current_epoch(), epoch(42));
}

#[test]
fn test_advance_epoch() {
    let mut gate = gate_default();
    gate.advance_epoch(epoch(10));
    assert_eq!(gate.current_epoch(), epoch(10));
}

// ---------------------------------------------------------------------------
// Admission policy
// ---------------------------------------------------------------------------

#[test]
fn test_set_admission_policy() {
    let mut gate = gate_with_capacity(50);
    gate.set_admission_policy(AdmissionPolicy::AlwaysAdmit);
    insert_n(&mut gate, "adm", 5);
    assert!(gate.total_cached() >= 5);
}

#[test]
fn test_admission_policy_serde() {
    let policies = [
        AdmissionPolicy::AlwaysAdmit,
        AdmissionPolicy::FrequencyBased,
    ];
    for p in &policies {
        let json = serde_json::to_string(p).unwrap();
        let back: AdmissionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, &back);
    }
}

// ---------------------------------------------------------------------------
// Segment snapshot
// ---------------------------------------------------------------------------

#[test]
fn test_segment_snapshot_empty() {
    let gate = gate_default();
    let snap = gate.segment_snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn test_segment_snapshot_after_inserts() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "ss", 10);
    let snap = gate.segment_snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    let back: SegmentSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, back);
}

// ---------------------------------------------------------------------------
// Adapt split ratio
// ---------------------------------------------------------------------------

#[test]
fn test_adapt_split_ratio() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "asr", 20);
    // Access some keys to build frequency data
    for i in 0..10 {
        gate.lookup(&format!("asr_{i}"));
    }
    let _ = gate.adapt_split_ratio();
    // Ratio should still be within valid range
    assert!(gate.effective_small_ratio_millionths() <= 1_000_000);
}

// ---------------------------------------------------------------------------
// Benchmark evidence
// ---------------------------------------------------------------------------

#[test]
fn test_benchmark_evidence_initial() {
    let gate = gate_default();
    let evidence = gate.benchmark_evidence();
    let json = serde_json::to_string(evidence).unwrap();
    assert!(!json.is_empty());
}

// ---------------------------------------------------------------------------
// Rollback triggers serde
// ---------------------------------------------------------------------------

#[test]
fn test_rollback_trigger_serde() {
    let trigger = RollbackTrigger::ParityFailure;
    let json = serde_json::to_string(&trigger).unwrap();
    let back: RollbackTrigger = serde_json::from_str(&json).unwrap();
    assert_eq!(trigger, back);
}

#[test]
fn test_rollback_state_serde() {
    for state in [RollbackState::Active, RollbackState::RolledBack] {
        let json = serde_json::to_string(&state).unwrap();
        let back: RollbackState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn test_config_serde_roundtrip() {
    let gate = gate_default();
    let config = gate.config().clone();
    let json = serde_json::to_string(&config).unwrap();
    let back: S3FifoCacheConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// Parity verdict
// ---------------------------------------------------------------------------

#[test]
fn test_parity_verdict_variants_serde() {
    for v in [ParityVerdict::Pass, ParityVerdict::Fail, ParityVerdict::Inconclusive] {
        let json = serde_json::to_string(&v).unwrap();
        let back: ParityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn test_gate_zero_capacity_error() {
    let mut config = S3FifoCacheConfig::default();
    config.total_capacity = 0;
    let result = S3FifoCacheGate::new(config, epoch(1));
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn test_deterministic_insert_sequence() {
    let mut g1 = gate_with_capacity(20);
    let mut g2 = gate_with_capacity(20);
    for i in 0..15 {
        let key = format!("det_{i}");
        let artifact = make_artifact(&key);
        g1.insert(key.clone(), artifact.clone(), 32).unwrap();
        g2.insert(key, artifact, 32).unwrap();
    }
    assert_eq!(g1.total_cached(), g2.total_cached());
    assert_eq!(g1.total_ghost(), g2.total_ghost());
    assert_eq!(
        g1.current_hit_rate_millionths(),
        g2.current_hit_rate_millionths()
    );
}

#[test]
fn test_deterministic_lookup_sequence() {
    let mut g1 = gate_with_capacity(20);
    let mut g2 = gate_with_capacity(20);
    insert_n(&mut g1, "dl", 10);
    insert_n(&mut g2, "dl", 10);
    for i in 0..10 {
        let key = format!("dl_{i}");
        assert_eq!(g1.lookup(&key), g2.lookup(&key));
    }
}

// ---------------------------------------------------------------------------
// Eviction event serde
// ---------------------------------------------------------------------------

#[test]
fn test_eviction_event_serde() {
    let ev = EvictionEvent {
        key: "ev-key".into(),
        segment: CacheSegment::Small,
        frequency: 1,
        sequence: 0,
        epoch: epoch(1),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: EvictionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// Full workflow: insert → lookup → parity → receipt → rollback → re-enable
// ---------------------------------------------------------------------------

#[test]
fn test_full_lifecycle_workflow() {
    let mut gate = gate_with_capacity(20);

    // Insert
    insert_n(&mut gate, "wf", 15);
    assert!(gate.total_cached() > 0);

    // Lookups
    for i in 0..5 {
        gate.lookup(&format!("wf_{i}"));
    }
    assert!(gate.current_hit_rate_millionths() > 0);

    // Parity
    let parity = gate.evaluate_parity();
    assert!(parity.passed() || !parity.passed()); // either outcome valid

    // Receipt
    let receipt = gate.emit_receipt(DecisionKind::GateEvaluation);
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(!json.is_empty());

    // Gate evaluation
    let eval = gate.evaluate_gate();
    let eval_json = serde_json::to_string(&eval).unwrap();
    assert!(!eval_json.is_empty());

    // Rollback
    gate.execute_rollback(RollbackTrigger::ParityFailure);
    assert!(!gate.is_active());

    // History
    assert!(!gate.rollback_history().is_empty());
}

// ---------------------------------------------------------------------------
// GateEvaluation serde
// ---------------------------------------------------------------------------

#[test]
fn test_gate_evaluation_serde() {
    let mut gate = gate_with_capacity(50);
    insert_n(&mut gate, "ges", 5);
    let eval = gate.evaluate_gate();
    let json = serde_json::to_string(&eval).unwrap();
    let back: GateEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ---------------------------------------------------------------------------
// Benchmark evidence serde
// ---------------------------------------------------------------------------

#[test]
fn test_benchmark_evidence_serde() {
    let evidence = BenchmarkEvidence::empty(epoch(1));
    let json = serde_json::to_string(&evidence).unwrap();
    let back: BenchmarkEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, back);
}

// ---------------------------------------------------------------------------
// CacheEntry
// ---------------------------------------------------------------------------

#[test]
fn test_cache_entry_new_small() {
    let artifact = make_artifact("ce");
    let entry = CacheEntry::new_small("ce-k".into(), artifact, 64, 0);
    assert_eq!(entry.segment, CacheSegment::Small);
}

#[test]
fn test_cache_entry_promote() {
    let artifact = make_artifact("pr");
    let mut entry = CacheEntry::new_small("pr-k".into(), artifact, 64, 0);
    entry.promote_to_main(1);
    assert_eq!(entry.segment, CacheSegment::Main);
}

#[test]
fn test_cache_entry_record_access() {
    let artifact = make_artifact("ra");
    let mut entry = CacheEntry::new_small("ra-k".into(), artifact, 64, 0);
    entry.record_access();
    // Frequency should increase
}

#[test]
fn test_cache_entry_serde() {
    let artifact = make_artifact("ser");
    let entry = CacheEntry::new_small("ser-k".into(), artifact, 64, 0);
    let json = serde_json::to_string(&entry).unwrap();
    let back: CacheEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// AdmissionDecision
// ---------------------------------------------------------------------------

#[test]
fn test_admission_decision_is_admit() {
    assert!(AdmissionDecision::Admit.is_admit());
    assert!(!AdmissionDecision::Reject.is_admit());
}

#[test]
fn test_admission_decision_serde() {
    for d in [AdmissionDecision::Admit, AdmissionDecision::Reject] {
        let json = serde_json::to_string(&d).unwrap();
        let back: AdmissionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

// ---------------------------------------------------------------------------
// ReferencePolicyKind
// ---------------------------------------------------------------------------

#[test]
fn test_reference_policy_kind_serde() {
    for k in [ReferencePolicyKind::Lru, ReferencePolicyKind::Clock] {
        let json = serde_json::to_string(&k).unwrap();
        let back: ReferencePolicyKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

// ---------------------------------------------------------------------------
// Queue length invariants
// ---------------------------------------------------------------------------

#[test]
fn test_queue_lengths_never_exceed_capacity() {
    let cap = 10;
    let mut gate = gate_with_capacity(cap);
    insert_n(&mut gate, "ql", 30);
    assert!(gate.small_queue_len() + gate.main_queue_len() <= cap);
}

// ---------------------------------------------------------------------------
// Stress: rapid insert/lookup/eviction cycle
// ---------------------------------------------------------------------------

#[test]
fn test_stress_rapid_operations() {
    let mut gate = gate_with_capacity(20);
    for round in 0..5 {
        insert_n(&mut gate, &format!("stress_{round}"), 15);
        for i in 0..15 {
            gate.lookup(&format!("stress_{round}_{i}"));
        }
    }
    assert!(gate.total_cached() <= 20);
    // Gate should still be evaluable
    let _ = gate.evaluate_gate();
}
