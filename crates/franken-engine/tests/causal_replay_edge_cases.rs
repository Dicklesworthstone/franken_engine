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
    OriginalDecider, PolicyDecider, RecorderConfig, RecordingMode, ReplayDecisionOutcome,
    ReplayError, ReplayVerdict, TraceEntry, TraceIndex, TraceQuery, TraceRecord, TraceRecorder,
    TraceRetentionPolicy,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_key() -> Vec<u8> {
    vec![42u8; 32]
}

fn make_snapshot(index: u64, action: &str, outcome: i64) -> DecisionSnapshot {
    DecisionSnapshot {
        decision_index: index,
        trace_id: "trace-001".into(),
        decision_id: format!("decision-{index}"),
        policy_id: "policy-alpha".into(),
        policy_version: 1,
        epoch: SecurityEpoch::from_raw(5),
        tick: 1000 + index * 100,
        threshold_millionths: 500_000,
        loss_matrix: {
            let mut m = BTreeMap::new();
            m.insert("allow".into(), 0);
            m.insert("sandbox".into(), 200_000);
            m.insert("terminate".into(), 800_000);
            m
        },
        evidence_hashes: vec![ContentHash::compute(b"evidence-1")],
        chosen_action: action.into(),
        outcome_millionths: outcome,
        extension_id: "ext-abc".into(),
        nondeterminism_range: (index * 2, index * 2 + 1),
    }
}

fn make_trace(decisions: &[(&str, i64)]) -> TraceRecord {
    let config = RecorderConfig {
        trace_id: "trace-001".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(5),
        start_tick: 1000,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);

    for i in 0..decisions.len() as u64 {
        recorder.record_nondeterminism(
            NondeterminismSource::RandomValue,
            vec![i as u8],
            1000 + i * 100,
            Some("ext-abc".into()),
        );
        recorder.record_nondeterminism(
            NondeterminismSource::Timestamp,
            (1000 + i * 100).to_be_bytes().to_vec(),
            1000 + i * 100,
            None,
        );
    }

    for (i, (action, outcome)) in decisions.iter().enumerate() {
        recorder.record_decision(make_snapshot(i as u64, action, *outcome));
    }

    recorder.finalize()
}

// ===========================================================================
// NondeterminismSource — serde roundtrip all variants
// ===========================================================================

#[test]
fn nondeterminism_source_serde_all_variants() {
    let sources = [
        NondeterminismSource::RandomValue,
        NondeterminismSource::Timestamp,
        NondeterminismSource::HostcallResult,
        NondeterminismSource::IoResult,
        NondeterminismSource::SchedulingDecision,
        NondeterminismSource::OsEntropy,
        NondeterminismSource::FleetEvidenceArrival,
    ];
    for source in sources {
        let json = serde_json::to_string(&source).expect("serialize");
        let restored: NondeterminismSource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(source, restored, "roundtrip for {source:?}");
    }
}

// ===========================================================================
// NondeterminismEntry — serde roundtrip
// ===========================================================================

#[test]
fn nondeterminism_entry_serde_roundtrip() {
    let entry = NondeterminismEntry {
        sequence: 42,
        source: NondeterminismSource::HostcallResult,
        value: vec![1, 2, 3, 4],
        tick: 5000,
        extension_id: Some("ext-xyz".to_string()),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let restored: NondeterminismEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, restored);
}

#[test]
fn nondeterminism_entry_serde_without_extension() {
    let entry = NondeterminismEntry {
        sequence: 0,
        source: NondeterminismSource::OsEntropy,
        value: vec![0xff],
        tick: 0,
        extension_id: None,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let restored: NondeterminismEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, restored);
}

// ===========================================================================
// NondeterminismLog — Default, serde, entries accessor
// ===========================================================================

#[test]
fn nondeterminism_log_default_is_empty() {
    let log = NondeterminismLog::default();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    assert!(log.entries().is_empty());
}

#[test]
fn nondeterminism_log_serde_roundtrip() {
    let mut log = NondeterminismLog::new();
    log.append(
        NondeterminismSource::RandomValue,
        vec![1, 2],
        100,
        Some("ext-1".into()),
    );
    log.append(NondeterminismSource::Timestamp, vec![3, 4], 200, None);

    let json = serde_json::to_string(&log).expect("serialize");
    let restored: NondeterminismLog = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(log, restored);
    assert_eq!(log.content_hash(), restored.content_hash());
}

#[test]
fn nondeterminism_log_entries_returns_all() {
    let mut log = NondeterminismLog::new();
    for i in 0..5u8 {
        log.append(NondeterminismSource::IoResult, vec![i], i as u64, None);
    }
    let entries = log.entries();
    assert_eq!(entries.len(), 5);
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.sequence, i as u64);
    }
}

// ===========================================================================
// DecisionSnapshot — serde roundtrip
// ===========================================================================

#[test]
fn decision_snapshot_serde_roundtrip() {
    let snapshot = make_snapshot(3, "sandbox", 200_000);
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let restored: DecisionSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(snapshot, restored);
    assert_eq!(snapshot.content_hash(), restored.content_hash());
}

// ===========================================================================
// TraceEntry — serde roundtrip
// ===========================================================================

#[test]
fn trace_entry_serde_roundtrip() {
    let snapshot = make_snapshot(0, "allow", 0);
    let prev_hash = ContentHash::compute(b"genesis");
    let entry = TraceEntry {
        entry_index: 0,
        prev_entry_hash: prev_hash.clone(),
        entry_hash: ContentHash::compute(b"test-hash"),
        decision: snapshot,
        epoch: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let restored: TraceEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, restored);
}

// ===========================================================================
// RecordingMode — serde all variants
// ===========================================================================

#[test]
fn recording_mode_serde_all_variants() {
    let modes = [
        RecordingMode::Full,
        RecordingMode::SecurityCritical,
        RecordingMode::Sampled {
            rate_millionths: 500_000,
        },
    ];
    for mode in modes {
        let json = serde_json::to_string(&mode).expect("serialize");
        let restored: RecordingMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mode, restored, "roundtrip for {mode:?}");
    }
}

// ===========================================================================
// RecorderConfig — serde roundtrip
// ===========================================================================

#[test]
fn recorder_config_serde_roundtrip() {
    let config = RecorderConfig {
        trace_id: "trace-test".into(),
        recording_mode: RecordingMode::SecurityCritical,
        epoch: SecurityEpoch::from_raw(7),
        start_tick: 42_000,
        signing_key: vec![1, 2, 3],
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let restored: RecorderConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config.trace_id, restored.trace_id);
    assert_eq!(config.recording_mode, restored.recording_mode);
    assert_eq!(config.epoch, restored.epoch);
    assert_eq!(config.start_tick, restored.start_tick);
    assert_eq!(config.signing_key, restored.signing_key);
}

// ===========================================================================
// TraceRecorder — entry_count and nondeterminism_count
// ===========================================================================

#[test]
fn trace_recorder_counts() {
    let config = RecorderConfig {
        trace_id: "count-test".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);

    assert_eq!(recorder.entry_count(), 0);
    assert_eq!(recorder.nondeterminism_count(), 0);

    recorder.record_nondeterminism(NondeterminismSource::RandomValue, vec![1], 10, None);
    recorder.record_nondeterminism(NondeterminismSource::Timestamp, vec![2], 20, None);
    assert_eq!(recorder.nondeterminism_count(), 2);

    recorder.record_decision(make_snapshot(0, "allow", 0));
    assert_eq!(recorder.entry_count(), 1);

    recorder.record_decision(make_snapshot(1, "sandbox", 200_000));
    assert_eq!(recorder.entry_count(), 2);
    assert_eq!(recorder.nondeterminism_count(), 2);
}

// ===========================================================================
// ReplayDecisionOutcome — serde roundtrip
// ===========================================================================

#[test]
fn replay_decision_outcome_serde_roundtrip() {
    let outcome = ReplayDecisionOutcome {
        decision_index: 5,
        original_action: "sandbox".to_string(),
        replayed_action: "terminate".to_string(),
        original_outcome_millionths: 200_000,
        replayed_outcome_millionths: 800_000,
        diverged: true,
    };
    let json = serde_json::to_string(&outcome).expect("serialize");
    let restored: ReplayDecisionOutcome = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(outcome, restored);
}

// ===========================================================================
// ReplayVerdict — serde roundtrip all variants
// ===========================================================================

#[test]
fn replay_verdict_serde_identical() {
    let verdict = ReplayVerdict::Identical {
        decisions_replayed: 42,
    };
    let json = serde_json::to_string(&verdict).expect("serialize");
    let restored: ReplayVerdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(verdict, restored);
}

#[test]
fn replay_verdict_serde_diverged() {
    let verdict = ReplayVerdict::Diverged {
        divergence_point: 3,
        decisions_replayed: 10,
        divergences: vec![ReplayDecisionOutcome {
            decision_index: 3,
            original_action: "allow".into(),
            replayed_action: "sandbox".into(),
            original_outcome_millionths: 0,
            replayed_outcome_millionths: 200_000,
            diverged: true,
        }],
    };
    let json = serde_json::to_string(&verdict).expect("serialize");
    let restored: ReplayVerdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(verdict, restored);
}

#[test]
fn replay_verdict_serde_tampered() {
    let verdict = ReplayVerdict::Tampered {
        detail: "hash chain broken".to_string(),
    };
    let json = serde_json::to_string(&verdict).expect("serialize");
    let restored: ReplayVerdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(verdict, restored);
}

// ===========================================================================
// CounterfactualConfig — serde roundtrip
// ===========================================================================

#[test]
fn counterfactual_config_serde_roundtrip() {
    let mut loss_overrides = BTreeMap::new();
    loss_overrides.insert("sandbox".into(), 900_000i64);
    let mut containment = BTreeMap::new();
    containment.insert("sandbox".into(), "suspend".into());
    let mut evidence = BTreeMap::new();
    evidence.insert("feature-a".into(), 1_500_000i64);

    let config = CounterfactualConfig {
        branch_id: "test-branch".into(),
        threshold_override_millionths: Some(300_000),
        loss_matrix_overrides: loss_overrides,
        policy_version_override: Some(3),
        containment_overrides: containment,
        evidence_weight_overrides: evidence,
        branch_from_index: 5,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let restored: CounterfactualConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, restored);
}

// ===========================================================================
// DecisionDelta — serde roundtrip
// ===========================================================================

#[test]
fn decision_delta_serde_roundtrip() {
    let delta = DecisionDelta {
        decision_index: 7,
        original_action: "allow".into(),
        counterfactual_action: "terminate".into(),
        original_outcome_millionths: 0,
        counterfactual_outcome_millionths: 800_000,
        diverged: true,
    };
    let json = serde_json::to_string(&delta).expect("serialize");
    let restored: DecisionDelta = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(delta, restored);
}

// ===========================================================================
// TraceQuery — serde roundtrip + Default
// ===========================================================================

#[test]
fn trace_query_default_is_all_none() {
    let query = TraceQuery::default();
    assert!(query.trace_id.is_none());
    assert!(query.extension_id.is_none());
    assert!(query.policy_version.is_none());
    assert!(query.epoch_range.is_none());
    assert!(query.tick_range.is_none());
    assert!(query.incident_id.is_none());
    assert!(query.has_divergence.is_none());
}

#[test]
fn trace_query_serde_roundtrip() {
    let query = TraceQuery {
        trace_id: Some("trace-001".into()),
        extension_id: Some("ext-abc".into()),
        policy_version: Some(2),
        epoch_range: Some((1, 10)),
        tick_range: Some((1000, 5000)),
        incident_id: Some("INC-42".into()),
        has_divergence: Some(true),
    };
    let json = serde_json::to_string(&query).expect("serialize");
    let restored: TraceQuery = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(query.trace_id, restored.trace_id);
    assert_eq!(query.extension_id, restored.extension_id);
    assert_eq!(query.policy_version, restored.policy_version);
    assert_eq!(query.epoch_range, restored.epoch_range);
    assert_eq!(query.tick_range, restored.tick_range);
    assert_eq!(query.incident_id, restored.incident_id);
}

// ===========================================================================
// TraceRetentionPolicy — serde roundtrip + Default values
// ===========================================================================

#[test]
fn trace_retention_policy_default_values() {
    let policy = TraceRetentionPolicy::default();
    assert_eq!(policy.default_ttl_ticks, 1_000_000);
    assert_eq!(policy.incident_ttl_ticks, 10_000_000);
    assert_eq!(policy.security_critical_ttl_ticks, 5_000_000);
    assert_eq!(policy.max_traces, 10_000);
    assert_eq!(policy.max_storage_bytes, 1_073_741_824);
}

#[test]
fn trace_retention_policy_serde_roundtrip() {
    let policy = TraceRetentionPolicy {
        default_ttl_ticks: 500,
        incident_ttl_ticks: 5000,
        security_critical_ttl_ticks: 2500,
        max_traces: 100,
        max_storage_bytes: 1_000_000,
    };
    let json = serde_json::to_string(&policy).expect("serialize");
    let restored: TraceRetentionPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, restored);
}

// ===========================================================================
// ReplayError — Display all variants
// ===========================================================================

#[test]
fn replay_error_display_chain_integrity() {
    let err = ReplayError::ChainIntegrity {
        entry_index: 42,
        detail: "hash mismatch".into(),
    };
    let s = err.to_string();
    assert!(s.contains("42"));
    assert!(s.contains("hash mismatch"));
}

#[test]
fn replay_error_display_nondeterminism_mismatch() {
    let err = ReplayError::NondeterminismMismatch {
        expected_sequence: 10,
        actual_sequence: 12,
    };
    let s = err.to_string();
    assert!(s.contains("10"));
    assert!(s.contains("12"));
}

#[test]
fn replay_error_display_branch_depth_exceeded() {
    let err = ReplayError::BranchDepthExceeded {
        requested: 20,
        max: 16,
    };
    let s = err.to_string();
    assert!(s.contains("20"));
    assert!(s.contains("16"));
}

#[test]
fn replay_error_display_storage_exhausted() {
    let err = ReplayError::StorageExhausted;
    assert_eq!(err.to_string(), "trace storage exhausted");
}

#[test]
fn replay_error_display_trace_not_found() {
    let err = ReplayError::TraceNotFound {
        trace_id: "missing-trace".into(),
    };
    assert!(err.to_string().contains("missing-trace"));
}

#[test]
fn replay_error_display_signature_invalid() {
    let err = ReplayError::SignatureInvalid;
    assert_eq!(err.to_string(), "trace signature invalid");
}

// ===========================================================================
// ReplayError — std::error::Error + serde
// ===========================================================================

#[test]
fn replay_error_implements_std_error() {
    let err = ReplayError::StorageExhausted;
    let e: &dyn std::error::Error = &err;
    assert!(e.source().is_none());
    assert!(!e.to_string().is_empty());
}

#[test]
fn replay_error_serde_all_variants() {
    let errors = vec![
        ReplayError::ChainIntegrity {
            entry_index: 5,
            detail: "broken".into(),
        },
        ReplayError::NondeterminismMismatch {
            expected_sequence: 1,
            actual_sequence: 2,
        },
        ReplayError::BranchDepthExceeded {
            requested: 10,
            max: 5,
        },
        ReplayError::StorageExhausted,
        ReplayError::TraceNotFound {
            trace_id: "t-1".into(),
        },
        ReplayError::SignatureInvalid,
    ];
    for err in errors {
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: ReplayError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, restored, "roundtrip for {err:?}");
    }
}

// ===========================================================================
// CausalReplayEngine — Default trait
// ===========================================================================

#[test]
fn causal_replay_engine_default() {
    let engine = CausalReplayEngine::default();
    let trace = make_trace(&[("allow", 0)]);
    let verdict = engine.replay(&trace).expect("replay");
    assert!(verdict.is_identical());
}

// ===========================================================================
// OriginalDecider — returns original decisions
// ===========================================================================

#[test]
fn original_decider_returns_original() {
    let decider = OriginalDecider;
    let snapshot = make_snapshot(0, "terminate", 800_000);
    let log = NondeterminismLog::new();
    let (action, outcome) = decider.decide(&snapshot, &log);
    assert_eq!(action, "terminate");
    assert_eq!(outcome, 800_000);
}

// ===========================================================================
// ActionDeltaReport — is_improvement edge cases
// ===========================================================================

#[test]
fn action_delta_report_zero_delta_is_not_improvement() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "neutral".into(),
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
        divergence_points: Vec::new(),
        decisions_evaluated: 5,
    };
    assert!(!report.is_improvement());
    assert_eq!(report.divergence_count(), 0);
}

#[test]
fn action_delta_report_negative_delta_is_not_improvement() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "regression".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        harm_prevented_delta_millionths: -500_000,
        false_positive_cost_delta_millionths: 0,
        containment_latency_delta_ticks: 0,
        resource_cost_delta_millionths: 0,
        affected_extensions: BTreeSet::new(),
        divergence_points: Vec::new(),
        decisions_evaluated: 5,
    };
    assert!(!report.is_improvement());
}

// ===========================================================================
// ActionDeltaReport — serde roundtrip
// ===========================================================================

#[test]
fn action_delta_report_serde_roundtrip() {
    let mut affected = BTreeSet::new();
    affected.insert("ext-abc".to_string());
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "test".into(),
            threshold_override_millionths: Some(100_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        harm_prevented_delta_millionths: 500_000,
        false_positive_cost_delta_millionths: 10_000,
        containment_latency_delta_ticks: -50,
        resource_cost_delta_millionths: 20_000,
        affected_extensions: affected,
        divergence_points: vec![DecisionDelta {
            decision_index: 2,
            original_action: "sandbox".into(),
            counterfactual_action: "allow".into(),
            original_outcome_millionths: 200_000,
            counterfactual_outcome_millionths: 0,
            diverged: true,
        }],
        decisions_evaluated: 10,
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let restored: ActionDeltaReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, restored);
}

// ===========================================================================
// TraceIndex — edge cases
// ===========================================================================

#[test]
fn trace_index_is_empty_initially() {
    let index = TraceIndex::new(TraceRetentionPolicy::default());
    assert!(index.is_empty());
    assert_eq!(index.len(), 0);
    assert_eq!(index.storage_estimate(), 0);
}

#[test]
fn trace_index_query_by_policy_version() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    let trace = make_trace(&[("sandbox", 200_000)]);
    index.insert(trace).expect("insert");

    let found = index.query(&TraceQuery {
        policy_version: Some(1), // make_snapshot uses version 1
        ..Default::default()
    });
    assert_eq!(found.len(), 1);

    let not_found = index.query(&TraceQuery {
        policy_version: Some(999),
        ..Default::default()
    });
    assert!(not_found.is_empty());
}

#[test]
fn trace_index_replace_on_same_id() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());

    let trace1 = make_trace(&[("sandbox", 200_000)]);
    let trace2 = make_trace(&[("allow", 0), ("terminate", 800_000)]);

    // Both have trace_id "trace-001".
    index.insert(trace1).expect("insert");
    assert_eq!(index.len(), 1);

    index.insert(trace2).expect("insert");
    assert_eq!(index.len(), 1);

    // Should have the second trace's entries.
    let t = index.get("trace-001").unwrap();
    assert_eq!(t.entries.len(), 2);
}

#[test]
fn trace_index_gc_reduces_storage_estimate() {
    let retention = TraceRetentionPolicy {
        default_ttl_ticks: 100,
        ..Default::default()
    };
    let mut index = TraceIndex::new(retention);

    let trace = make_trace(&[("sandbox", 200_000)]);
    index.insert(trace).expect("insert");
    let estimate_before = index.storage_estimate();
    assert!(estimate_before > 0);

    index.gc(5000);
    assert_eq!(index.len(), 0);
    assert_eq!(index.storage_estimate(), 0);
}

// ===========================================================================
// TraceRecord — serde roundtrip preserving chain integrity
// ===========================================================================

#[test]
fn trace_record_serde_preserves_chain_integrity() {
    let trace = make_trace(&[("sandbox", 200_000), ("allow", 0), ("terminate", 800_000)]);
    trace.verify_chain_integrity().expect("original valid");

    let json = serde_json::to_string(&trace).expect("serialize");
    let restored: TraceRecord = serde_json::from_str(&json).expect("deserialize");

    restored.verify_chain_integrity().expect("restored valid");
    assert_eq!(trace.content_hash(), restored.content_hash());
    assert_eq!(trace.chain_hash, restored.chain_hash);
    assert_eq!(trace.nondeterminism_hash, restored.nondeterminism_hash);
}

// ===========================================================================
// TraceRecord — object_id is zone-dependent
// ===========================================================================

#[test]
fn trace_record_object_id_differs_by_zone() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let id_a = trace.object_id("zone-a").expect("derive");
    let id_b = trace.object_id("zone-b").expect("derive");
    assert_ne!(id_a, id_b);
}

// ===========================================================================
// CounterfactualDecider — edge cases
// ===========================================================================

#[test]
fn counterfactual_decider_no_overrides_returns_original() {
    let config = CounterfactualConfig {
        branch_id: "no-op".into(),
        threshold_override_millionths: None,
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let decider = CounterfactualDecider::new(config);
    let snapshot = make_snapshot(0, "terminate", 800_000);
    let log = NondeterminismLog::new();
    let (action, outcome) = decider.decide(&snapshot, &log);
    assert_eq!(action, "terminate");
    assert_eq!(outcome, 800_000);
}

// ===========================================================================
// End-to-end: record → replay → counterfactual
// ===========================================================================

#[test]
fn end_to_end_record_replay_counterfactual() {
    // Record a trace.
    let config = RecorderConfig {
        trace_id: "e2e-trace".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(10),
        start_tick: 0,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);

    recorder.record_nondeterminism(NondeterminismSource::RandomValue, vec![1], 10, None);
    recorder.record_decision(make_snapshot(0, "sandbox", 200_000));
    recorder.record_nondeterminism(NondeterminismSource::Timestamp, vec![2], 110, None);
    recorder.record_decision(make_snapshot(1, "terminate", 800_000));

    recorder.set_incident_id("INC-E2E".into());
    recorder.set_metadata("env".into(), "staging".into());

    let trace = recorder.finalize();

    // Verify chain integrity.
    trace.verify_chain_integrity().expect("valid chain");

    // Verify signature.
    assert!(trace.verify_signature(&test_key()));

    // Replay identically.
    let engine = CausalReplayEngine::new();
    let verdict = engine.replay(&trace).expect("replay");
    assert!(verdict.is_identical());

    // Run counterfactual with lower threshold.
    let cf_config = CounterfactualConfig {
        branch_id: "aggressive".into(),
        threshold_override_millionths: Some(100_000),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let report = engine
        .counterfactual_branch(&trace, cf_config)
        .expect("counterfactual");
    assert_eq!(report.decisions_evaluated, 2);
    assert!(report.divergence_count() > 0);

    // Store in index and query.
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    index.insert(trace).expect("insert");

    let found = index.query(&TraceQuery {
        incident_id: Some("INC-E2E".into()),
        ..Default::default()
    });
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].metadata.get("env"), Some(&"staging".to_string()));
}

// ===========================================================================
// Determinism: two identical traces produce identical hashes
// ===========================================================================

#[test]
fn trace_determinism() {
    let t1 = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
    let t2 = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
    assert_eq!(t1.content_hash(), t2.content_hash());
    assert_eq!(t1.chain_hash, t2.chain_hash);
    assert_eq!(t1.nondeterminism_hash, t2.nondeterminism_hash);
    assert_eq!(t1.signature, t2.signature);
}

// ===========================================================================
// NondeterminismLog — content hash changes with extension_id
// ===========================================================================

#[test]
fn nondeterminism_log_hash_differs_with_extension_id() {
    let mut log1 = NondeterminismLog::new();
    let mut log2 = NondeterminismLog::new();

    log1.append(NondeterminismSource::RandomValue, vec![1], 0, None);
    log2.append(
        NondeterminismSource::RandomValue,
        vec![1],
        0,
        Some("ext-1".into()),
    );

    assert_ne!(log1.content_hash(), log2.content_hash());
}

// ===========================================================================
// Multi-branch: exactly at max depth
// ===========================================================================

#[test]
fn multi_branch_at_exact_max_depth_succeeds() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let engine = CausalReplayEngine::new().with_max_branch_depth(3);

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

    let reports = engine
        .multi_branch_comparison(&trace, configs)
        .expect("should succeed at exact depth");
    assert_eq!(reports.len(), 3);
}
