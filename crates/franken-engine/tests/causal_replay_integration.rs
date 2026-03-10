#![forbid(unsafe_code)]
//! Integration tests for the `causal_replay` module.
//!
//! Exercises nondeterminism logging, trace recording, hash-chain verification,
//! replay verdicts, counterfactual branching, trace indexing and retention,
//! and serde round-trips from outside the crate boundary.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::causal_replay::{
    ActionDeltaReport, CausalReplayEngine, CounterfactualConfig, CounterfactualDecider,
    DecisionDelta, DecisionSnapshot, NondeterminismEntry, NondeterminismLog, NondeterminismSource,
    OriginalDecider, RecorderConfig, RecordingMode, ReplayDecisionOutcome, ReplayError,
    ReplayVerdict, TraceEntry, TraceIndex, TraceQuery, TraceRecord, TraceRecorder,
    TraceRetentionPolicy,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(10)
}

fn signing_key() -> Vec<u8> {
    b"test-signing-key-causal-replay".to_vec()
}

fn make_decision_snapshot(index: u64, action: &str, outcome: i64) -> DecisionSnapshot {
    DecisionSnapshot {
        decision_index: index,
        trace_id: "trace-1".into(),
        decision_id: format!("decision-{index}"),
        policy_id: "policy-main".into(),
        policy_version: 1,
        epoch: test_epoch(),
        tick: 100 + index * 10,
        threshold_millionths: 500_000,
        loss_matrix: BTreeMap::from([("allow".into(), 200_000_i64), ("deny".into(), 800_000_i64)]),
        evidence_hashes: vec![ContentHash::compute(b"evidence")],
        chosen_action: action.into(),
        outcome_millionths: outcome,
        extension_id: "ext-1".into(),
        nondeterminism_range: (index * 2, index * 2 + 1),
    }
}

fn make_recorder_config() -> RecorderConfig {
    RecorderConfig {
        trace_id: "trace-1".into(),
        recording_mode: RecordingMode::Full,
        epoch: test_epoch(),
        start_tick: 100,
        signing_key: signing_key(),
    }
}

fn record_simple_trace() -> TraceRecord {
    let mut recorder = TraceRecorder::new(make_recorder_config());
    recorder.record_nondeterminism(
        NondeterminismSource::RandomValue,
        vec![42],
        100,
        Some("ext-1".into()),
    );
    recorder.record_nondeterminism(NondeterminismSource::Timestamp, vec![0, 0, 0, 1], 110, None);
    recorder.record_decision(make_decision_snapshot(0, "allow", 300_000));
    recorder.record_nondeterminism(
        NondeterminismSource::HostcallResult,
        vec![99],
        120,
        Some("ext-1".into()),
    );
    recorder.record_nondeterminism(NondeterminismSource::IoResult, vec![1, 2, 3], 130, None);
    recorder.record_decision(make_decision_snapshot(1, "deny", -100_000));
    recorder.finalize()
}

// ===========================================================================
// 1. NondeterminismSource enum
// ===========================================================================

#[test]
fn nondeterminism_source_serde_round_trip() {
    let sources = vec![
        NondeterminismSource::RandomValue,
        NondeterminismSource::Timestamp,
        NondeterminismSource::HostcallResult,
        NondeterminismSource::IoResult,
        NondeterminismSource::SchedulingDecision,
        NondeterminismSource::OsEntropy,
        NondeterminismSource::FleetEvidenceArrival,
    ];
    for src in &sources {
        let json = serde_json::to_string(src).unwrap();
        let back: NondeterminismSource = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, src);
    }
}

// ===========================================================================
// 2. RecordingMode enum
// ===========================================================================

#[test]
fn recording_mode_full_serde() {
    let mode = RecordingMode::Full;
    let json = serde_json::to_string(&mode).unwrap();
    let back: RecordingMode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mode);
}

#[test]
fn recording_mode_security_critical_serde() {
    let mode = RecordingMode::SecurityCritical;
    let json = serde_json::to_string(&mode).unwrap();
    let back: RecordingMode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mode);
}

#[test]
fn recording_mode_sampled_serde() {
    let mode = RecordingMode::Sampled {
        rate_millionths: 500_000,
    };
    let json = serde_json::to_string(&mode).unwrap();
    let back: RecordingMode = serde_json::from_str(&json).unwrap();
    assert_eq!(back, mode);
}

// ===========================================================================
// 3. NondeterminismLog
// ===========================================================================

#[test]
fn nondeterminism_log_empty() {
    let log = NondeterminismLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
}

#[test]
fn nondeterminism_log_append_and_get() {
    let mut log = NondeterminismLog::new();
    let seq = log.append(NondeterminismSource::RandomValue, vec![42], 100, None);
    assert_eq!(seq, 0);
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());

    let entry = log.get(0).unwrap();
    assert_eq!(entry.sequence, 0);
    assert_eq!(entry.value, vec![42]);
    assert_eq!(entry.tick, 100);
    assert!(entry.extension_id.is_none());
}

#[test]
fn nondeterminism_log_multiple_entries() {
    let mut log = NondeterminismLog::new();
    let s0 = log.append(NondeterminismSource::RandomValue, vec![1], 10, None);
    let s1 = log.append(
        NondeterminismSource::Timestamp,
        vec![2],
        20,
        Some("ext-a".into()),
    );
    let s2 = log.append(NondeterminismSource::IoResult, vec![3], 30, None);

    assert_eq!(s0, 0);
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(log.len(), 3);
    assert_eq!(log.entries().len(), 3);
}

#[test]
fn nondeterminism_log_content_hash_deterministic() {
    let mut log1 = NondeterminismLog::new();
    log1.append(NondeterminismSource::RandomValue, vec![42], 100, None);

    let mut log2 = NondeterminismLog::new();
    log2.append(NondeterminismSource::RandomValue, vec![42], 100, None);

    assert_eq!(log1.content_hash(), log2.content_hash());
}

#[test]
fn nondeterminism_log_content_hash_varies() {
    let mut log1 = NondeterminismLog::new();
    log1.append(NondeterminismSource::RandomValue, vec![42], 100, None);

    let mut log2 = NondeterminismLog::new();
    log2.append(NondeterminismSource::RandomValue, vec![99], 100, None);

    assert_ne!(log1.content_hash(), log2.content_hash());
}

#[test]
fn nondeterminism_log_get_missing() {
    let log = NondeterminismLog::new();
    assert!(log.get(0).is_none());
    assert!(log.get(999).is_none());
}

// ===========================================================================
// 4. NondeterminismEntry serde
// ===========================================================================

#[test]
fn nondeterminism_entry_serde_round_trip() {
    let entry = NondeterminismEntry {
        sequence: 7,
        source: NondeterminismSource::HostcallResult,
        value: vec![1, 2, 3, 4],
        tick: 500,
        extension_id: Some("ext-42".into()),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: NondeterminismEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// 5. DecisionSnapshot
// ===========================================================================

#[test]
fn decision_snapshot_content_hash_deterministic() {
    let d1 = make_decision_snapshot(0, "allow", 300_000);
    let d2 = make_decision_snapshot(0, "allow", 300_000);
    assert_eq!(d1.content_hash(), d2.content_hash());
}

#[test]
fn decision_snapshot_content_hash_varies_by_action() {
    let d1 = make_decision_snapshot(0, "allow", 300_000);
    let d2 = make_decision_snapshot(0, "deny", 300_000);
    assert_ne!(d1.content_hash(), d2.content_hash());
}

#[test]
fn decision_snapshot_serde_round_trip() {
    let d = make_decision_snapshot(5, "deny", -100_000);
    let json = serde_json::to_string(&d).unwrap();
    let back: DecisionSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ===========================================================================
// 6. TraceRecorder
// ===========================================================================

#[test]
fn recorder_starts_empty() {
    let recorder = TraceRecorder::new(make_recorder_config());
    assert_eq!(recorder.entry_count(), 0);
    assert_eq!(recorder.nondeterminism_count(), 0);
}

#[test]
fn recorder_tracks_counts() {
    let mut recorder = TraceRecorder::new(make_recorder_config());
    recorder.record_nondeterminism(NondeterminismSource::RandomValue, vec![1], 100, None);
    assert_eq!(recorder.nondeterminism_count(), 1);
    assert_eq!(recorder.entry_count(), 0);

    recorder.record_decision(make_decision_snapshot(0, "allow", 200_000));
    assert_eq!(recorder.entry_count(), 1);
}

#[test]
fn recorder_metadata_and_incident() {
    let mut recorder = TraceRecorder::new(make_recorder_config());
    recorder.set_incident_id("INC-001".into());
    recorder.set_metadata("env".into(), "production".into());
    recorder.record_decision(make_decision_snapshot(0, "allow", 100_000));

    let trace = recorder.finalize();
    assert_eq!(trace.incident_id.as_deref(), Some("INC-001"));
    assert_eq!(
        trace.metadata.get("env").map(String::as_str),
        Some("production")
    );
}

// ===========================================================================
// 7. TraceRecord
// ===========================================================================

#[test]
fn trace_record_basic_fields() {
    let trace = record_simple_trace();
    assert_eq!(trace.trace_id, "trace-1");
    assert_eq!(trace.recording_mode, RecordingMode::Full);
    assert_eq!(trace.start_epoch, test_epoch());
    assert_eq!(trace.entries.len(), 2);
    assert_eq!(trace.nondeterminism_log.len(), 4);
}

#[test]
fn trace_record_chain_integrity_valid() {
    let trace = record_simple_trace();
    assert!(trace.verify_chain_integrity().is_ok());
}

#[test]
fn trace_record_signature_verification() {
    let trace = record_simple_trace();
    assert!(trace.verify_signature(&signing_key()));
    assert!(!trace.verify_signature(b"wrong-key"));
}

#[test]
fn trace_record_content_hash_deterministic() {
    // Two traces with same inputs should produce same content hash
    let t1 = record_simple_trace();
    let t2 = record_simple_trace();
    assert_eq!(t1.content_hash(), t2.content_hash());
}

#[test]
fn trace_record_object_id() {
    let trace = record_simple_trace();
    let id = trace.object_id("zone-a").unwrap();
    let id2 = trace.object_id("zone-a").unwrap();
    assert_eq!(id, id2);
    // Different zone = different ID
    let id3 = trace.object_id("zone-b").unwrap();
    assert_ne!(id, id3);
}

#[test]
fn trace_record_serde_round_trip() {
    let trace = record_simple_trace();
    let json = serde_json::to_string(&trace).unwrap();
    let back: TraceRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_id, trace.trace_id);
    assert_eq!(back.entries.len(), trace.entries.len());
    assert_eq!(
        back.nondeterminism_log.len(),
        trace.nondeterminism_log.len()
    );
}

// ===========================================================================
// 8. TraceEntry
// ===========================================================================

#[test]
fn trace_entry_serde_round_trip() {
    let trace = record_simple_trace();
    let entry = &trace.entries[0];
    let json = serde_json::to_string(entry).unwrap();
    let back: TraceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.entry_index, entry.entry_index);
    assert_eq!(back.entry_hash, entry.entry_hash);
}

#[test]
fn trace_entry_chain_linking() {
    let trace = record_simple_trace();
    assert_eq!(trace.entries.len(), 2);
    // Second entry's prev_entry_hash should equal first entry's entry_hash
    assert_eq!(
        trace.entries[1].prev_entry_hash,
        trace.entries[0].entry_hash
    );
}

// ===========================================================================
// 9. ReplayVerdict
// ===========================================================================

#[test]
fn replay_verdict_identical_serde() {
    let v = ReplayVerdict::Identical {
        decisions_replayed: 42,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn replay_verdict_diverged_serde() {
    let v = ReplayVerdict::Diverged {
        divergence_point: 5,
        decisions_replayed: 10,
        divergences: vec![ReplayDecisionOutcome {
            decision_index: 5,
            original_action: "allow".into(),
            replayed_action: "deny".into(),
            original_outcome_millionths: 100_000,
            replayed_outcome_millionths: -50_000,
            diverged: true,
        }],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn replay_verdict_tampered_serde() {
    let v = ReplayVerdict::Tampered {
        detail: "hash chain broken".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ===========================================================================
// 10. ReplayError
// ===========================================================================

#[test]
fn replay_error_serde_round_trip() {
    let errors = vec![
        ReplayError::ChainIntegrity {
            entry_index: 3,
            detail: "mismatch".into(),
        },
        ReplayError::NondeterminismMismatch {
            expected_sequence: 5,
            actual_sequence: 7,
        },
        ReplayError::BranchDepthExceeded {
            requested: 10,
            max: 5,
        },
        ReplayError::StorageExhausted,
        ReplayError::TraceNotFound {
            trace_id: "missing".into(),
        },
        ReplayError::SignatureInvalid,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ReplayError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

// ===========================================================================
// 11. CausalReplayEngine — basic replay
// ===========================================================================

#[test]
fn replay_identical_trace() {
    let trace = record_simple_trace();
    let engine = CausalReplayEngine::new();
    let verdict = engine.replay(&trace).unwrap();
    match verdict {
        ReplayVerdict::Identical { decisions_replayed } => {
            assert_eq!(decisions_replayed, 2);
        }
        other => panic!("expected Identical, got {other:?}"),
    }
}

#[test]
fn replay_with_original_decider() {
    let trace = record_simple_trace();
    let engine = CausalReplayEngine::new();
    let decider = OriginalDecider;
    let verdict = engine.replay_with_decider(&trace, &decider).unwrap();
    match verdict {
        ReplayVerdict::Identical { decisions_replayed } => {
            assert_eq!(decisions_replayed, 2);
        }
        other => panic!("expected Identical, got {other:?}"),
    }
}

#[test]
fn replay_verify_trace_signature() {
    let trace = record_simple_trace();
    let engine = CausalReplayEngine::new();
    assert!(engine.verify_trace_signature(&trace, &signing_key()));
    assert!(!engine.verify_trace_signature(&trace, b"wrong-key"));
}

// ===========================================================================
// 12. Counterfactual branching
// ===========================================================================

#[test]
fn counterfactual_branch_basic() {
    let trace = record_simple_trace();
    let engine = CausalReplayEngine::new();
    let config = CounterfactualConfig {
        branch_id: "branch-1".into(),
        threshold_override_millionths: Some(900_000),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let report = engine.counterfactual_branch(&trace, config).unwrap();
    assert!(report.decisions_evaluated > 0);
}

#[test]
fn counterfactual_config_serde_round_trip() {
    let config = CounterfactualConfig {
        branch_id: "branch-test".into(),
        threshold_override_millionths: Some(750_000),
        loss_matrix_overrides: BTreeMap::from([("allow".into(), 100_000_i64)]),
        policy_version_override: Some(2),
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::from([("key-a".into(), 500_000_i64)]),
        branch_from_index: 3,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: CounterfactualConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

#[test]
fn multi_branch_comparison() {
    let trace = record_simple_trace();
    let engine = CausalReplayEngine::new();

    let configs = vec![
        CounterfactualConfig {
            branch_id: "branch-a".into(),
            threshold_override_millionths: Some(300_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        CounterfactualConfig {
            branch_id: "branch-b".into(),
            threshold_override_millionths: Some(900_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
    ];

    let reports = engine.multi_branch_comparison(&trace, configs).unwrap();
    assert_eq!(reports.len(), 2);
}

#[test]
fn multi_branch_depth_exceeded() {
    let trace = record_simple_trace();
    let engine = CausalReplayEngine::new().with_max_branch_depth(2);

    // Create 3 configs, exceeding depth limit of 2
    let configs: Vec<CounterfactualConfig> = (0..3)
        .map(|i| CounterfactualConfig {
            branch_id: format!("branch-{i}"),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        })
        .collect();

    match engine.multi_branch_comparison(&trace, configs) {
        Err(ReplayError::BranchDepthExceeded {
            requested: 3,
            max: 2,
        }) => {}
        other => panic!("expected BranchDepthExceeded(3, 2), got {other:?}"),
    }
}

// ===========================================================================
// 13. ActionDeltaReport
// ===========================================================================

#[test]
fn action_delta_report_serde_round_trip() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "test".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        harm_prevented_delta_millionths: 50_000,
        false_positive_cost_delta_millionths: -10_000,
        containment_latency_delta_ticks: -5,
        resource_cost_delta_millionths: 0,
        affected_extensions: BTreeSet::from(["ext-1".into()]),
        divergence_points: vec![],
        decisions_evaluated: 10,
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: ActionDeltaReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

#[test]
fn action_delta_report_divergence_count() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "x".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        harm_prevented_delta_millionths: 0,
        false_positive_cost_delta_millionths: 0,
        containment_latency_delta_ticks: 0,
        resource_cost_delta_millionths: 0,
        affected_extensions: BTreeSet::new(),
        divergence_points: vec![
            DecisionDelta {
                decision_index: 0,
                original_action: "a".into(),
                counterfactual_action: "b".into(),
                original_outcome_millionths: 0,
                counterfactual_outcome_millionths: 0,
                diverged: true,
            },
            DecisionDelta {
                decision_index: 1,
                original_action: "c".into(),
                counterfactual_action: "d".into(),
                original_outcome_millionths: 0,
                counterfactual_outcome_millionths: 0,
                diverged: true,
            },
        ],
        decisions_evaluated: 5,
    };
    assert_eq!(report.divergence_count(), 2);
}

#[test]
fn action_delta_report_is_improvement() {
    let mut report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "x".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        harm_prevented_delta_millionths: 100_000,
        false_positive_cost_delta_millionths: 0,
        containment_latency_delta_ticks: 0,
        resource_cost_delta_millionths: 0,
        affected_extensions: BTreeSet::new(),
        divergence_points: vec![],
        decisions_evaluated: 1,
    };
    assert!(report.is_improvement());

    report.harm_prevented_delta_millionths = -100_000;
    assert!(!report.is_improvement());
}

// ===========================================================================
// 14. DecisionDelta serde
// ===========================================================================

#[test]
fn decision_delta_serde_round_trip() {
    let delta = DecisionDelta {
        decision_index: 3,
        original_action: "allow".into(),
        counterfactual_action: "deny".into(),
        original_outcome_millionths: 200_000,
        counterfactual_outcome_millionths: -50_000,
        diverged: true,
    };
    let json = serde_json::to_string(&delta).unwrap();
    let back: DecisionDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(back, delta);
}

// ===========================================================================
// 15. ReplayDecisionOutcome serde
// ===========================================================================

#[test]
fn replay_decision_outcome_serde() {
    let outcome = ReplayDecisionOutcome {
        decision_index: 2,
        original_action: "allow".into(),
        replayed_action: "allow".into(),
        original_outcome_millionths: 100_000,
        replayed_outcome_millionths: 100_000,
        diverged: false,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ReplayDecisionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back, outcome);
}

// ===========================================================================
// 16. TraceRetentionPolicy
// ===========================================================================

#[test]
fn trace_retention_policy_default() {
    let policy = TraceRetentionPolicy::default();
    assert!(policy.default_ttl_ticks > 0);
    assert!(policy.max_traces > 0);
    assert!(policy.max_storage_bytes > 0);
}

#[test]
fn trace_retention_policy_serde_round_trip() {
    let policy = TraceRetentionPolicy {
        default_ttl_ticks: 10_000,
        incident_ttl_ticks: 100_000,
        security_critical_ttl_ticks: 50_000,
        max_traces: 500,
        max_storage_bytes: 1_000_000,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: TraceRetentionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, policy);
}

// ===========================================================================
// 17. TraceIndex
// ===========================================================================

#[test]
fn trace_index_empty() {
    let index = TraceIndex::new(TraceRetentionPolicy::default());
    assert!(index.is_empty());
    assert_eq!(index.len(), 0);
}

#[test]
fn trace_index_insert_and_get() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    let trace = record_simple_trace();
    index.insert(trace.clone()).unwrap();
    assert_eq!(index.len(), 1);
    assert!(!index.is_empty());

    let got = index.get("trace-1").unwrap();
    assert_eq!(got.trace_id, "trace-1");
}

#[test]
fn trace_index_query_by_trace_id() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    index.insert(record_simple_trace()).unwrap();

    let query = TraceQuery {
        trace_id: Some("trace-1".into()),
        extension_id: None,
        policy_version: None,
        epoch_range: None,
        tick_range: None,
        incident_id: None,
        has_divergence: None,
    };
    let results = index.query(&query);
    assert_eq!(results.len(), 1);
}

#[test]
fn trace_index_query_no_match() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    index.insert(record_simple_trace()).unwrap();

    let query = TraceQuery {
        trace_id: Some("nonexistent".into()),
        extension_id: None,
        policy_version: None,
        epoch_range: None,
        tick_range: None,
        incident_id: None,
        has_divergence: None,
    };
    let results = index.query(&query);
    assert!(results.is_empty());
}

#[test]
fn trace_index_gc_removes_expired() {
    let retention = TraceRetentionPolicy {
        default_ttl_ticks: 100,
        incident_ttl_ticks: 1_000,
        security_critical_ttl_ticks: 500,
        max_traces: 1000,
        max_storage_bytes: 100_000_000,
    };
    let mut index = TraceIndex::new(retention);
    index.insert(record_simple_trace()).unwrap();
    assert_eq!(index.len(), 1);

    // GC at a tick far in the future should expire the trace
    index.gc(1_000_000);
    assert_eq!(index.len(), 0);
}

#[test]
fn trace_index_storage_estimate() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    let empty_estimate = index.storage_estimate();
    index.insert(record_simple_trace()).unwrap();
    let after_estimate = index.storage_estimate();
    assert!(after_estimate >= empty_estimate);
}

// ===========================================================================
// 18. TraceQuery serde
// ===========================================================================

#[test]
fn trace_query_serde_round_trip() {
    let query = TraceQuery {
        trace_id: Some("trace-42".into()),
        extension_id: Some("ext-1".into()),
        policy_version: Some(3),
        epoch_range: Some((5, 10)),
        tick_range: Some((100, 500)),
        incident_id: Some("INC-001".into()),
        has_divergence: Some(true),
    };
    let json = serde_json::to_string(&query).unwrap();
    let back: TraceQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, query);
}

// ===========================================================================
// 19. CounterfactualDecider
// ===========================================================================

#[test]
fn counterfactual_decider_with_threshold_override() {
    let trace = record_simple_trace();
    let engine = CausalReplayEngine::new();
    let config = CounterfactualConfig {
        branch_id: "threshold-override".into(),
        threshold_override_millionths: Some(100_000),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let decider = CounterfactualDecider::new(config.clone());
    let verdict = engine.replay_with_decider(&trace, &decider).unwrap();
    // May be Identical or Diverged depending on how threshold applies
    match &verdict {
        ReplayVerdict::Identical { .. } | ReplayVerdict::Diverged { .. } => {}
        other => panic!("expected Identical or Diverged, got {other:?}"),
    }
}

// ===========================================================================
// 20. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_record_replay_branch() {
    // 1. Record a trace
    let mut recorder = TraceRecorder::new(RecorderConfig {
        trace_id: "lifecycle-trace".into(),
        recording_mode: RecordingMode::Full,
        epoch: test_epoch(),
        start_tick: 0,
        signing_key: signing_key(),
    });

    for i in 0..5 {
        recorder.record_nondeterminism(
            NondeterminismSource::RandomValue,
            vec![i as u8],
            i * 10,
            None,
        );
        recorder.record_decision(DecisionSnapshot {
            decision_index: i,
            trace_id: "lifecycle-trace".into(),
            decision_id: format!("d-{i}"),
            policy_id: "pol-1".into(),
            policy_version: 1,
            epoch: test_epoch(),
            tick: i * 10,
            threshold_millionths: 500_000,
            loss_matrix: BTreeMap::from([
                ("allow".into(), 200_000_i64),
                ("deny".into(), 800_000_i64),
            ]),
            evidence_hashes: vec![],
            chosen_action: "allow".into(),
            outcome_millionths: 100_000,
            extension_id: "ext-1".into(),
            nondeterminism_range: (i, i),
        });
    }

    recorder.set_metadata("env".into(), "test".into());
    let trace = recorder.finalize();

    // 2. Verify integrity
    assert!(trace.verify_chain_integrity().is_ok());
    assert!(trace.verify_signature(&signing_key()));
    assert_eq!(trace.entries.len(), 5);

    // 3. Replay
    let engine = CausalReplayEngine::new();
    let verdict = engine.replay(&trace).unwrap();
    match verdict {
        ReplayVerdict::Identical { decisions_replayed } => {
            assert_eq!(decisions_replayed, 5);
        }
        other => panic!("expected Identical, got {other:?}"),
    }

    // 4. Counterfactual branch
    let config = CounterfactualConfig {
        branch_id: "what-if".into(),
        threshold_override_millionths: Some(999_000),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let report = engine.counterfactual_branch(&trace, config).unwrap();
    assert!(report.decisions_evaluated > 0);

    // 5. Index
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    index.insert(trace).unwrap();
    assert_eq!(index.len(), 1);

    let query = TraceQuery {
        trace_id: Some("lifecycle-trace".into()),
        extension_id: None,
        policy_version: None,
        epoch_range: None,
        tick_range: None,
        incident_id: None,
        has_divergence: None,
    };
    assert_eq!(index.query(&query).len(), 1);
}
