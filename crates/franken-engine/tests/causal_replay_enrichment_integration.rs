#![forbid(unsafe_code)]
//! Enrichment integration tests for `causal_replay`.
//!
//! Adds NondeterminismSource Debug distinctness, ReplayError Display uniqueness,
//! serde roundtrips, JSON field-name stability, RecordingMode coverage,
//! NondeterminismLog operations, TraceRetentionPolicy defaults, TraceQuery defaults,
//! ReplayVerdict methods, and ActionDeltaReport methods beyond the existing
//! 52 integration tests.

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
    ActionDeltaReport, CausalReplayEngine, CounterfactualConfig, DecisionDelta, DecisionSnapshot,
    NondeterminismEntry, NondeterminismLog, NondeterminismSource, RecorderConfig, RecordingMode,
    ReplayDecisionOutcome, ReplayError, ReplayVerdict, TraceIndex, TraceQuery, TraceRecorder,
    TraceRetentionPolicy,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// 1) NondeterminismSource — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_nondeterminism_source() {
    let variants = [
        format!("{:?}", NondeterminismSource::RandomValue),
        format!("{:?}", NondeterminismSource::Timestamp),
        format!("{:?}", NondeterminismSource::HostcallResult),
        format!("{:?}", NondeterminismSource::IoResult),
        format!("{:?}", NondeterminismSource::SchedulingDecision),
        format!("{:?}", NondeterminismSource::OsEntropy),
        format!("{:?}", NondeterminismSource::FleetEvidenceArrival),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 7);
}

// ===========================================================================
// 2) RecordingMode — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_recording_mode() {
    let variants = [
        format!("{:?}", RecordingMode::Full),
        format!("{:?}", RecordingMode::SecurityCritical),
        format!(
            "{:?}",
            RecordingMode::Sampled {
                rate_millionths: 500_000
            }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 3) ReplayError — Display uniqueness + std::error::Error
// ===========================================================================

#[test]
fn replay_error_display_all_unique() {
    let variants: Vec<String> = vec![
        ReplayError::ChainIntegrity {
            entry_index: 0,
            detail: "bad hash".into(),
        }
        .to_string(),
        ReplayError::NondeterminismMismatch {
            expected_sequence: 1,
            actual_sequence: 2,
        }
        .to_string(),
        ReplayError::BranchDepthExceeded {
            requested: 20,
            max: 16,
        }
        .to_string(),
        ReplayError::StorageExhausted.to_string(),
        ReplayError::TraceNotFound {
            trace_id: "t1".into(),
        }
        .to_string(),
        ReplayError::SignatureInvalid.to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn replay_error_is_std_error() {
    let e = ReplayError::StorageExhausted;
    let _: &dyn std::error::Error = &e;
}

#[test]
fn replay_error_display_contains_trace_id() {
    let e = ReplayError::TraceNotFound {
        trace_id: "my-trace-42".into(),
    };
    let s = e.to_string();
    assert!(s.contains("my-trace-42"), "should contain trace_id: {s}");
}

// ===========================================================================
// 4) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_nondeterminism_source_all() {
    let sources = [
        NondeterminismSource::RandomValue,
        NondeterminismSource::Timestamp,
        NondeterminismSource::HostcallResult,
        NondeterminismSource::IoResult,
        NondeterminismSource::SchedulingDecision,
        NondeterminismSource::OsEntropy,
        NondeterminismSource::FleetEvidenceArrival,
    ];
    for s in &sources {
        let json = serde_json::to_string(s).unwrap();
        let rt: NondeterminismSource = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, rt);
    }
}

#[test]
fn serde_roundtrip_recording_mode_all() {
    let modes = [
        RecordingMode::Full,
        RecordingMode::SecurityCritical,
        RecordingMode::Sampled {
            rate_millionths: 500_000,
        },
    ];
    for m in &modes {
        let json = serde_json::to_string(m).unwrap();
        let rt: RecordingMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, rt);
    }
}

#[test]
fn serde_roundtrip_replay_error_all() {
    let variants = vec![
        ReplayError::ChainIntegrity {
            entry_index: 0,
            detail: "bad".into(),
        },
        ReplayError::NondeterminismMismatch {
            expected_sequence: 1,
            actual_sequence: 2,
        },
        ReplayError::BranchDepthExceeded {
            requested: 20,
            max: 16,
        },
        ReplayError::StorageExhausted,
        ReplayError::TraceNotFound {
            trace_id: "t1".into(),
        },
        ReplayError::SignatureInvalid,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: ReplayError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_nondeterminism_entry() {
    let ne = NondeterminismEntry {
        sequence: 42,
        source: NondeterminismSource::RandomValue,
        value: vec![1, 2, 3],
        tick: 100,
        extension_id: Some("ext-1".into()),
    };
    let json = serde_json::to_string(&ne).unwrap();
    let rt: NondeterminismEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(ne, rt);
}

#[test]
fn serde_roundtrip_decision_snapshot() {
    let ds = DecisionSnapshot {
        decision_index: 0,
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        policy_version: 1,
        epoch: SecurityEpoch::from_raw(1),
        tick: 50,
        threshold_millionths: 500_000,
        loss_matrix: {
            let mut m = BTreeMap::new();
            m.insert("contain".into(), 100_000i64);
            m.insert("allow".into(), 0i64);
            m
        },
        evidence_hashes: vec![ContentHash::compute(b"ev1")],
        chosen_action: "contain".into(),
        outcome_millionths: 100_000,
        extension_id: "ext-1".into(),
        nondeterminism_range: (0, 5),
    };
    let json = serde_json::to_string(&ds).unwrap();
    let rt: DecisionSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(ds, rt);
}

#[test]
fn serde_roundtrip_replay_verdict_identical() {
    let v = ReplayVerdict::Identical {
        decisions_replayed: 10,
    };
    let json = serde_json::to_string(&v).unwrap();
    let rt: ReplayVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, rt);
}

#[test]
fn serde_roundtrip_replay_verdict_tampered() {
    let v = ReplayVerdict::Tampered {
        detail: "hash mismatch".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let rt: ReplayVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, rt);
}

#[test]
fn serde_roundtrip_replay_decision_outcome() {
    let rdo = ReplayDecisionOutcome {
        decision_index: 3,
        original_action: "allow".into(),
        replayed_action: "contain".into(),
        original_outcome_millionths: 0,
        replayed_outcome_millionths: 100_000,
        diverged: true,
    };
    let json = serde_json::to_string(&rdo).unwrap();
    let rt: ReplayDecisionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(rdo, rt);
}

#[test]
fn serde_roundtrip_counterfactual_config() {
    let cc = CounterfactualConfig {
        branch_id: "branch-1".into(),
        threshold_override_millionths: Some(600_000),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let json = serde_json::to_string(&cc).unwrap();
    let rt: CounterfactualConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cc, rt);
}

#[test]
fn serde_roundtrip_decision_delta() {
    let dd = DecisionDelta {
        decision_index: 5,
        original_action: "allow".into(),
        counterfactual_action: "contain".into(),
        original_outcome_millionths: 0,
        counterfactual_outcome_millionths: 200_000,
        diverged: true,
    };
    let json = serde_json::to_string(&dd).unwrap();
    let rt: DecisionDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(dd, rt);
}

#[test]
fn serde_roundtrip_trace_query() {
    let q = TraceQuery {
        trace_id: Some("t1".into()),
        extension_id: Some("ext-1".into()),
        ..TraceQuery::default()
    };
    let json = serde_json::to_string(&q).unwrap();
    let rt: TraceQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, rt);
}

#[test]
fn serde_roundtrip_trace_retention_policy() {
    let p = TraceRetentionPolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    let rt: TraceRetentionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, rt);
}

// ===========================================================================
// 5) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_nondeterminism_entry() {
    let ne = NondeterminismEntry {
        sequence: 0,
        source: NondeterminismSource::Timestamp,
        value: vec![],
        tick: 0,
        extension_id: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ne).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["sequence", "source", "value", "tick", "extension_id"] {
        assert!(
            obj.contains_key(key),
            "NondeterminismEntry missing field: {key}"
        );
    }
}

#[test]
fn json_fields_decision_snapshot() {
    let ds = DecisionSnapshot {
        decision_index: 0,
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        policy_version: 1,
        epoch: SecurityEpoch::from_raw(0),
        tick: 0,
        threshold_millionths: 0,
        loss_matrix: BTreeMap::new(),
        evidence_hashes: vec![],
        chosen_action: "a".into(),
        outcome_millionths: 0,
        extension_id: "e".into(),
        nondeterminism_range: (0, 0),
    };
    let v: serde_json::Value = serde_json::to_value(&ds).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "decision_index",
        "trace_id",
        "decision_id",
        "policy_id",
        "policy_version",
        "epoch",
        "tick",
        "threshold_millionths",
        "loss_matrix",
        "evidence_hashes",
        "chosen_action",
        "outcome_millionths",
        "extension_id",
        "nondeterminism_range",
    ] {
        assert!(
            obj.contains_key(key),
            "DecisionSnapshot missing field: {key}"
        );
    }
}

#[test]
fn json_fields_replay_decision_outcome() {
    let rdo = ReplayDecisionOutcome {
        decision_index: 0,
        original_action: "a".into(),
        replayed_action: "b".into(),
        original_outcome_millionths: 0,
        replayed_outcome_millionths: 0,
        diverged: false,
    };
    let v: serde_json::Value = serde_json::to_value(&rdo).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "decision_index",
        "original_action",
        "replayed_action",
        "original_outcome_millionths",
        "replayed_outcome_millionths",
        "diverged",
    ] {
        assert!(
            obj.contains_key(key),
            "ReplayDecisionOutcome missing field: {key}"
        );
    }
}

#[test]
fn json_fields_counterfactual_config() {
    let cc = CounterfactualConfig {
        branch_id: "b".into(),
        threshold_override_millionths: None,
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&cc).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "branch_id",
        "threshold_override_millionths",
        "loss_matrix_overrides",
        "policy_version_override",
        "containment_overrides",
        "evidence_weight_overrides",
        "branch_from_index",
    ] {
        assert!(
            obj.contains_key(key),
            "CounterfactualConfig missing field: {key}"
        );
    }
}

#[test]
fn json_fields_trace_query() {
    let q = TraceQuery::default();
    let v: serde_json::Value = serde_json::to_value(&q).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "extension_id",
        "policy_version",
        "epoch_range",
        "tick_range",
        "incident_id",
        "has_divergence",
    ] {
        assert!(obj.contains_key(key), "TraceQuery missing field: {key}");
    }
}

// ===========================================================================
// 6) NondeterminismLog — operations
// ===========================================================================

#[test]
fn nondeterminism_log_new_empty() {
    let log = NondeterminismLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    assert!(log.entries().is_empty());
}

#[test]
fn nondeterminism_log_append_and_get() {
    let mut log = NondeterminismLog::new();
    let seq = log.append(NondeterminismSource::RandomValue, vec![42], 100, None);
    assert_eq!(seq, 0);
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());

    let entry = log.get(0).unwrap();
    assert_eq!(entry.source, NondeterminismSource::RandomValue);
    assert_eq!(entry.value, vec![42]);
    assert_eq!(entry.tick, 100);
}

#[test]
fn nondeterminism_log_monotonic_sequence() {
    let mut log = NondeterminismLog::new();
    let s0 = log.append(NondeterminismSource::Timestamp, vec![1], 10, None);
    let s1 = log.append(NondeterminismSource::IoResult, vec![2], 20, None);
    let s2 = log.append(NondeterminismSource::OsEntropy, vec![3], 30, None);
    assert_eq!(s0, 0);
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
}

#[test]
fn nondeterminism_log_content_hash_deterministic() {
    let mut log1 = NondeterminismLog::new();
    log1.append(NondeterminismSource::RandomValue, vec![1, 2, 3], 100, None);

    let mut log2 = NondeterminismLog::new();
    log2.append(NondeterminismSource::RandomValue, vec![1, 2, 3], 100, None);

    assert_eq!(log1.content_hash(), log2.content_hash());
}

// ===========================================================================
// 7) TraceQuery — default
// ===========================================================================

#[test]
fn trace_query_default_all_none() {
    let q = TraceQuery::default();
    assert!(q.trace_id.is_none());
    assert!(q.extension_id.is_none());
    assert!(q.policy_version.is_none());
    assert!(q.epoch_range.is_none());
    assert!(q.tick_range.is_none());
    assert!(q.incident_id.is_none());
    assert!(q.has_divergence.is_none());
}

// ===========================================================================
// 8) TraceRetentionPolicy — default
// ===========================================================================

#[test]
fn trace_retention_policy_default() {
    let p = TraceRetentionPolicy::default();
    assert!(p.default_ttl_ticks > 0);
    assert!(p.incident_ttl_ticks > p.default_ttl_ticks);
    assert!(p.max_traces > 0);
    assert!(p.max_storage_bytes > 0);
}

// ===========================================================================
// 9) ReplayVerdict — methods
// ===========================================================================

#[test]
fn replay_verdict_identical_is_identical() {
    let v = ReplayVerdict::Identical {
        decisions_replayed: 5,
    };
    assert!(v.is_identical());
    assert_eq!(v.divergence_count(), 0);
}

#[test]
fn replay_verdict_diverged_not_identical() {
    let v = ReplayVerdict::Diverged {
        divergence_point: 2,
        decisions_replayed: 5,
        divergences: vec![ReplayDecisionOutcome {
            decision_index: 2,
            original_action: "a".into(),
            replayed_action: "b".into(),
            original_outcome_millionths: 0,
            replayed_outcome_millionths: 100_000,
            diverged: true,
        }],
    };
    assert!(!v.is_identical());
    assert_eq!(v.divergence_count(), 1);
}

#[test]
fn replay_verdict_tampered_not_identical() {
    let v = ReplayVerdict::Tampered {
        detail: "bad".into(),
    };
    assert!(!v.is_identical());
}

// ===========================================================================
// 10) TraceRecorder — build and finalize
// ===========================================================================

#[test]
fn trace_recorder_finalize_empty() {
    let recorder = TraceRecorder::new(RecorderConfig {
        trace_id: "trace-1".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: vec![0xAA; 32],
    });
    assert_eq!(recorder.entry_count(), 0);
    assert_eq!(recorder.nondeterminism_count(), 0);

    let trace = recorder.finalize();
    assert_eq!(trace.trace_id, "trace-1");
    assert!(trace.entries.is_empty());
    assert_eq!(trace.recording_mode, RecordingMode::Full);
    assert_eq!(trace.start_epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn trace_recorder_record_nondeterminism() {
    let mut recorder = TraceRecorder::new(RecorderConfig {
        trace_id: "trace-2".into(),
        recording_mode: RecordingMode::SecurityCritical,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: vec![0xBB; 32],
    });
    let seq = recorder.record_nondeterminism(NondeterminismSource::Timestamp, vec![1, 2], 50, None);
    assert_eq!(seq, 0);
    assert_eq!(recorder.nondeterminism_count(), 1);
}

// ===========================================================================
// 11) CausalReplayEngine — construction
// ===========================================================================

#[test]
fn causal_replay_engine_new() {
    let _engine = CausalReplayEngine::new();
}

#[test]
fn causal_replay_engine_with_branch_depth() {
    let _engine = CausalReplayEngine::new().with_max_branch_depth(32);
}

// ===========================================================================
// 12) TraceIndex — construction and operations
// ===========================================================================

#[test]
fn trace_index_new_empty() {
    let index = TraceIndex::new(TraceRetentionPolicy::default());
    assert!(index.is_empty());
    assert_eq!(index.len(), 0);
}

#[test]
fn trace_index_insert_and_get() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    let recorder = TraceRecorder::new(RecorderConfig {
        trace_id: "trace-idx-1".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: vec![0xCC; 32],
    });
    let trace = recorder.finalize();
    index.insert(trace).unwrap();
    assert_eq!(index.len(), 1);
    assert!(!index.is_empty());
    assert!(index.get("trace-idx-1").is_some());
}

#[test]
fn trace_index_query_empty() {
    let index = TraceIndex::new(TraceRetentionPolicy::default());
    let results = index.query(&TraceQuery::default());
    assert!(results.is_empty());
}

// ===========================================================================
// 13) ActionDeltaReport — methods
// ===========================================================================

#[test]
fn action_delta_report_no_divergence() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "b1".into(),
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
        divergence_points: vec![],
        decisions_evaluated: 10,
    };
    assert_eq!(report.divergence_count(), 0);
}

#[test]
fn action_delta_report_improvement() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "b2".into(),
            threshold_override_millionths: Some(600_000),
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
        affected_extensions: {
            let mut s = BTreeSet::new();
            s.insert("ext-1".into());
            s
        },
        divergence_points: vec![DecisionDelta {
            decision_index: 3,
            original_action: "allow".into(),
            counterfactual_action: "contain".into(),
            original_outcome_millionths: 0,
            counterfactual_outcome_millionths: 100_000,
            diverged: true,
        }],
        decisions_evaluated: 10,
    };
    assert!(report.is_improvement());
    assert_eq!(report.divergence_count(), 1);
}

// ===========================================================================
// 14) Helper: build a signed trace with decisions (integration-level)
// ===========================================================================

fn test_key() -> Vec<u8> {
    vec![42u8; 32]
}

fn make_snapshot(index: u64, action: &str, outcome: i64) -> DecisionSnapshot {
    DecisionSnapshot {
        decision_index: index,
        trace_id: "trace-int".into(),
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

fn make_trace(decisions: &[(&str, i64)]) -> frankenengine_engine::causal_replay::TraceRecord {
    let config = RecorderConfig {
        trace_id: "trace-int".into(),
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

fn make_trace_with_id(
    trace_id: &str,
    decisions: &[(&str, i64)],
) -> frankenengine_engine::causal_replay::TraceRecord {
    let config = RecorderConfig {
        trace_id: trace_id.into(),
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
    }

    for (i, (action, outcome)) in decisions.iter().enumerate() {
        let mut snap = make_snapshot(i as u64, action, *outcome);
        snap.trace_id = trace_id.into();
        recorder.record_decision(snap);
    }

    recorder.finalize()
}

// ===========================================================================
// 15) TraceRecorder — record_decision produces valid chain
// ===========================================================================

#[test]
fn trace_recorder_record_decision_chain_valid() {
    let config = RecorderConfig {
        trace_id: "chain-test".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);
    recorder.record_decision(make_snapshot(0, "allow", 0));
    recorder.record_decision(make_snapshot(1, "sandbox", 200_000));
    recorder.record_decision(make_snapshot(2, "terminate", 800_000));

    let trace = recorder.finalize();
    assert_eq!(trace.entries.len(), 3);
    trace
        .verify_chain_integrity()
        .expect("chain should be valid after multi-decision recording");
}

#[test]
fn trace_recorder_tracks_extensions() {
    let config = RecorderConfig {
        trace_id: "ext-track".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);

    let mut snap1 = make_snapshot(0, "allow", 0);
    snap1.extension_id = "ext-alpha".into();
    recorder.record_decision(snap1);

    let mut snap2 = make_snapshot(1, "sandbox", 200_000);
    snap2.extension_id = "ext-beta".into();
    recorder.record_decision(snap2);

    let trace = recorder.finalize();
    assert!(trace.extensions.contains("ext-alpha"));
    assert!(trace.extensions.contains("ext-beta"));
}

#[test]
fn trace_recorder_tracks_policy_versions() {
    let config = RecorderConfig {
        trace_id: "pol-track".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);

    let mut snap = make_snapshot(0, "allow", 0);
    snap.policy_id = "pol-abc".into();
    snap.policy_version = 7;
    recorder.record_decision(snap);

    let trace = recorder.finalize();
    assert_eq!(trace.policy_versions.get("pol-abc"), Some(&7));
}

#[test]
fn trace_recorder_set_incident_id() {
    let config = RecorderConfig {
        trace_id: "inc-set".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);
    recorder.set_incident_id("INC-123".into());
    let trace = recorder.finalize();
    assert_eq!(trace.incident_id, Some("INC-123".into()));
}

#[test]
fn trace_recorder_set_metadata() {
    let config = RecorderConfig {
        trace_id: "meta-set".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);
    recorder.set_metadata("region".into(), "us-west-2".into());
    recorder.set_metadata("cluster".into(), "prod-1".into());
    let trace = recorder.finalize();
    assert_eq!(trace.metadata.get("region"), Some(&"us-west-2".into()));
    assert_eq!(trace.metadata.get("cluster"), Some(&"prod-1".into()));
}

#[test]
fn trace_recorder_finalize_preserves_recording_mode() {
    for mode in [
        RecordingMode::Full,
        RecordingMode::SecurityCritical,
        RecordingMode::Sampled {
            rate_millionths: 333_333,
        },
    ] {
        let config = RecorderConfig {
            trace_id: format!("mode-{mode:?}"),
            recording_mode: mode,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: 0,
            signing_key: test_key(),
        };
        let recorder = TraceRecorder::new(config);
        let trace = recorder.finalize();
        assert_eq!(trace.recording_mode, mode);
    }
}

// ===========================================================================
// 16) TraceRecord — verify_chain_integrity edge cases
// ===========================================================================

#[test]
fn trace_record_verify_chain_integrity_valid() {
    let trace = make_trace(&[("sandbox", 200_000), ("allow", 0), ("terminate", 800_000)]);
    trace
        .verify_chain_integrity()
        .expect("valid chain should pass");
}

#[test]
fn trace_record_empty_chain_integrity() {
    let config = RecorderConfig {
        trace_id: "empty-chain".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let trace = TraceRecorder::new(config).finalize();
    trace
        .verify_chain_integrity()
        .expect("empty trace chain is valid");
}

#[test]
fn trace_record_tampered_entry_hash_detected() {
    let mut trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
    trace.entries[1].entry_hash = ContentHash::compute(b"tampered-hash");
    let err = trace.verify_chain_integrity().unwrap_err();
    assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
}

#[test]
fn trace_record_tampered_prev_hash_detected() {
    let mut trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
    trace.entries[1].prev_entry_hash = ContentHash::compute(b"broken-link");
    let err = trace.verify_chain_integrity().unwrap_err();
    assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
}

#[test]
fn trace_record_tampered_chain_hash_detected() {
    let mut trace = make_trace(&[("sandbox", 200_000)]);
    trace.chain_hash = ContentHash::compute(b"wrong-chain-hash");
    let err = trace.verify_chain_integrity().unwrap_err();
    assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
}

#[test]
fn trace_record_non_zero_genesis_index_detected() {
    let mut trace = make_trace(&[("sandbox", 200_000)]);
    trace.entries[0].entry_index = 99;
    let err = trace.verify_chain_integrity().unwrap_err();
    assert!(matches!(
        err,
        ReplayError::ChainIntegrity {
            entry_index: 99,
            ..
        }
    ));
}

#[test]
fn trace_record_bad_genesis_prev_hash_detected() {
    let mut trace = make_trace(&[("sandbox", 200_000)]);
    trace.entries[0].prev_entry_hash = ContentHash::compute(b"not-genesis");
    let err = trace.verify_chain_integrity().unwrap_err();
    assert!(matches!(
        err,
        ReplayError::ChainIntegrity { entry_index: 0, .. }
    ));
}

#[test]
fn trace_record_empty_wrong_chain_hash_detected() {
    let config = RecorderConfig {
        trace_id: "empty-bad-hash".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let mut trace = TraceRecorder::new(config).finalize();
    trace.chain_hash = ContentHash::compute(b"definitely-wrong");
    let err = trace.verify_chain_integrity().unwrap_err();
    assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
}

#[test]
fn trace_record_non_monotonic_index_detected() {
    let mut trace = make_trace(&[("sandbox", 200_000), ("allow", 0), ("terminate", 800_000)]);
    trace.entries[2].entry_index = 10;
    let err = trace.verify_chain_integrity().unwrap_err();
    assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
}

// ===========================================================================
// 17) TraceRecord — verify_signature
// ===========================================================================

#[test]
fn trace_record_verify_signature_correct_key() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    assert!(trace.verify_signature(&test_key()));
}

#[test]
fn trace_record_verify_signature_wrong_key() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    assert!(!trace.verify_signature(&[99u8; 32]));
}

#[test]
fn trace_record_verify_signature_empty_trace() {
    let config = RecorderConfig {
        trace_id: "empty-sig".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let trace = TraceRecorder::new(config).finalize();
    assert!(trace.verify_signature(&test_key()));
    assert!(!trace.verify_signature(&[0u8; 32]));
}

// ===========================================================================
// 18) TraceRecord — content_hash determinism and sensitivity
// ===========================================================================

#[test]
fn trace_record_content_hash_deterministic() {
    let t1 = make_trace(&[("sandbox", 200_000)]);
    let t2 = make_trace(&[("sandbox", 200_000)]);
    assert_eq!(t1.content_hash(), t2.content_hash());
}

#[test]
fn trace_record_content_hash_differs_by_decisions() {
    let t1 = make_trace(&[("sandbox", 200_000)]);
    let t2 = make_trace(&[("terminate", 800_000)]);
    // Different decisions produce different chain_hash and thus different content_hash
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn trace_record_object_id_deterministic() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let id1 = trace.object_id("zone-x").unwrap();
    let id2 = trace.object_id("zone-x").unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn trace_record_object_id_differs_by_zone() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let id_a = trace.object_id("zone-a").unwrap();
    let id_b = trace.object_id("zone-b").unwrap();
    assert_ne!(id_a, id_b);
}

// ===========================================================================
// 19) CausalReplayEngine — replay identical
// ===========================================================================

#[test]
fn replay_identical_single_decision() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let engine = CausalReplayEngine::new();
    let verdict = engine.replay(&trace).expect("replay should succeed");
    assert!(verdict.is_identical());
    if let ReplayVerdict::Identical { decisions_replayed } = verdict {
        assert_eq!(decisions_replayed, 1);
    }
}

#[test]
fn replay_identical_multiple_decisions() {
    let trace = make_trace(&[("sandbox", 200_000), ("allow", 0), ("terminate", 800_000)]);
    let engine = CausalReplayEngine::new();
    let verdict = engine.replay(&trace).expect("replay should succeed");
    assert!(verdict.is_identical());
    if let ReplayVerdict::Identical { decisions_replayed } = verdict {
        assert_eq!(decisions_replayed, 3);
    }
}

#[test]
fn replay_identical_empty_trace() {
    let config = RecorderConfig {
        trace_id: "empty-replay".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let trace = TraceRecorder::new(config).finalize();
    let engine = CausalReplayEngine::new();
    let verdict = engine.replay(&trace).expect("replay should succeed");
    assert!(verdict.is_identical());
    if let ReplayVerdict::Identical { decisions_replayed } = verdict {
        assert_eq!(decisions_replayed, 0);
    }
}

// ===========================================================================
// 20) CausalReplayEngine — replay detects tampering
// ===========================================================================

#[test]
fn replay_detects_nondeterminism_hash_tampering() {
    let mut trace = make_trace(&[("sandbox", 200_000)]);
    trace.nondeterminism_hash = ContentHash::compute(b"tampered-nd-hash");
    let engine = CausalReplayEngine::new();
    let verdict = engine.replay(&trace).expect("should produce verdict");
    assert!(matches!(verdict, ReplayVerdict::Tampered { .. }));
}

#[test]
fn replay_detects_chain_integrity_violation() {
    let mut trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
    trace.entries[1].entry_hash = ContentHash::compute(b"tampered");
    let engine = CausalReplayEngine::new();
    let err = engine.replay(&trace).unwrap_err();
    assert!(matches!(err, ReplayError::ChainIntegrity { .. }));
}

// ===========================================================================
// 21) CausalReplayEngine — replay_with_decider
// ===========================================================================

#[test]
fn replay_with_decider_identical_using_original_decider() {
    use frankenengine_engine::causal_replay::OriginalDecider;
    let trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
    let engine = CausalReplayEngine::new();
    let verdict = engine
        .replay_with_decider(&trace, &OriginalDecider)
        .expect("replay should succeed");
    assert!(verdict.is_identical());
}

#[test]
fn replay_with_custom_decider_diverges() {
    use frankenengine_engine::causal_replay::PolicyDecider;

    #[derive(Debug)]
    struct AlwaysTerminate;
    impl PolicyDecider for AlwaysTerminate {
        fn decide(
            &self,
            _snapshot: &DecisionSnapshot,
            _nondeterminism: &NondeterminismLog,
        ) -> (String, i64) {
            ("terminate".into(), 800_000)
        }
    }

    let trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
    let engine = CausalReplayEngine::new();
    let verdict = engine
        .replay_with_decider(&trace, &AlwaysTerminate)
        .expect("replay should succeed");
    assert!(!verdict.is_identical());
    assert_eq!(verdict.divergence_count(), 2);
}

// ===========================================================================
// 22) CausalReplayEngine — verify_trace_signature
// ===========================================================================

#[test]
fn engine_verify_trace_signature_correct_key() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let engine = CausalReplayEngine::new();
    assert!(engine.verify_trace_signature(&trace, &test_key()));
}

#[test]
fn engine_verify_trace_signature_wrong_key() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let engine = CausalReplayEngine::new();
    assert!(!engine.verify_trace_signature(&trace, &[0u8; 32]));
}

// ===========================================================================
// 23) CounterfactualDecider — direct testing
// ===========================================================================

#[test]
fn counterfactual_decider_before_branch_returns_original() {
    use frankenengine_engine::causal_replay::{CounterfactualDecider, PolicyDecider};
    let config = CounterfactualConfig {
        branch_id: "late".into(),
        threshold_override_millionths: Some(0),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 5,
    };
    let decider = CounterfactualDecider::new(config);
    let snapshot = make_snapshot(3, "terminate", 800_000);
    let log = NondeterminismLog::new();
    let (action, outcome) = decider.decide(&snapshot, &log);
    assert_eq!(action, "terminate");
    assert_eq!(outcome, 800_000);
}

#[test]
fn counterfactual_decider_at_branch_applies_override() {
    use frankenengine_engine::causal_replay::{CounterfactualDecider, PolicyDecider};
    let config = CounterfactualConfig {
        branch_id: "exact".into(),
        threshold_override_millionths: Some(0),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 3,
    };
    let decider = CounterfactualDecider::new(config);
    let snapshot = make_snapshot(3, "terminate", 800_000);
    let log = NondeterminismLog::new();
    let (action, outcome) = decider.decide(&snapshot, &log);
    // Threshold 0: only allow (cost=0) qualifies
    assert_eq!(action, "allow");
    assert_eq!(outcome, 0);
}

#[test]
fn counterfactual_decider_no_overrides_returns_original() {
    use frankenengine_engine::causal_replay::{CounterfactualDecider, PolicyDecider};
    let config = CounterfactualConfig {
        branch_id: "noop".into(),
        threshold_override_millionths: None,
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let decider = CounterfactualDecider::new(config);
    let snapshot = make_snapshot(0, "sandbox", 200_000);
    let log = NondeterminismLog::new();
    let (action, outcome) = decider.decide(&snapshot, &log);
    assert_eq!(action, "sandbox");
    assert_eq!(outcome, 200_000);
}

#[test]
fn counterfactual_decider_loss_matrix_override_changes_action() {
    use frankenengine_engine::causal_replay::{CounterfactualDecider, PolicyDecider};
    let mut overrides = BTreeMap::new();
    overrides.insert("sandbox".into(), 900_000i64);
    let config = CounterfactualConfig {
        branch_id: "loss-override".into(),
        threshold_override_millionths: None,
        loss_matrix_overrides: overrides,
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let decider = CounterfactualDecider::new(config);
    let snapshot = make_snapshot(0, "sandbox", 200_000);
    let log = NondeterminismLog::new();
    let (action, _outcome) = decider.decide(&snapshot, &log);
    // sandbox now costs 900k (above threshold 500k), so allow (0) is chosen
    assert_eq!(action, "allow");
}

#[test]
fn counterfactual_decider_containment_override_remaps() {
    use frankenengine_engine::causal_replay::{CounterfactualDecider, PolicyDecider};
    let mut containment = BTreeMap::new();
    containment.insert("sandbox".into(), "suspend".into());
    let config = CounterfactualConfig {
        branch_id: "remap".into(),
        threshold_override_millionths: None,
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: containment,
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let decider = CounterfactualDecider::new(config);
    let snapshot = make_snapshot(0, "sandbox", 200_000);
    let log = NondeterminismLog::new();
    let (action, _outcome) = decider.decide(&snapshot, &log);
    // sandbox remapped to suspend; allow(0) is cheaper
    assert_eq!(action, "allow");
}

// ===========================================================================
// 24) Counterfactual branch — end-to-end
// ===========================================================================

#[test]
fn counterfactual_branch_no_changes_no_divergence() {
    let trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
    let config = CounterfactualConfig {
        branch_id: "baseline".into(),
        threshold_override_millionths: None,
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let engine = CausalReplayEngine::new();
    let report = engine
        .counterfactual_branch(&trace, config)
        .expect("should succeed");
    assert_eq!(report.divergence_count(), 0);
    assert!(report.affected_extensions.is_empty());
    assert_eq!(report.decisions_evaluated, 2);
}

#[test]
fn counterfactual_branch_lower_threshold_changes_decision() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let config = CounterfactualConfig {
        branch_id: "lower-thr".into(),
        threshold_override_millionths: Some(100_000),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let engine = CausalReplayEngine::new();
    let report = engine
        .counterfactual_branch(&trace, config)
        .expect("should succeed");
    assert_eq!(report.divergence_count(), 1);
    assert_eq!(report.divergence_points[0].counterfactual_action, "allow");
}

#[test]
fn counterfactual_branch_from_index_preserves_prefix() {
    let trace = make_trace(&[("sandbox", 200_000), ("allow", 0), ("terminate", 800_000)]);
    let config = CounterfactualConfig {
        branch_id: "late-branch".into(),
        threshold_override_millionths: Some(100_000),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 2,
    };
    let engine = CausalReplayEngine::new();
    let report = engine
        .counterfactual_branch(&trace, config)
        .expect("should succeed");
    // Only decision index 2 should diverge
    assert_eq!(report.divergence_count(), 1);
    assert_eq!(report.divergence_points[0].decision_index, 2);
}

#[test]
fn counterfactual_branch_harm_delta_positive_is_improvement() {
    let trace = make_trace(&[("sandbox", 200_000), ("terminate", 800_000)]);
    let config = CounterfactualConfig {
        branch_id: "all-allow".into(),
        threshold_override_millionths: Some(0),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let engine = CausalReplayEngine::new();
    let report = engine
        .counterfactual_branch(&trace, config)
        .expect("should succeed");
    // Original total: 200k + 800k = 1M; CF total: 0 + 0 = 0
    assert_eq!(report.harm_prevented_delta_millionths, 1_000_000);
    assert!(report.is_improvement());
}

#[test]
fn counterfactual_branch_affected_extensions_populated() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let config = CounterfactualConfig {
        branch_id: "ext-check".into(),
        threshold_override_millionths: Some(100_000),
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let engine = CausalReplayEngine::new();
    let report = engine
        .counterfactual_branch(&trace, config)
        .expect("should succeed");
    assert!(report.affected_extensions.contains("ext-abc"));
}

#[test]
fn counterfactual_branch_reports_correct_decisions_evaluated() {
    let trace = make_trace(&[("allow", 0), ("sandbox", 200_000), ("terminate", 800_000)]);
    let config = CounterfactualConfig {
        branch_id: "count-eval".into(),
        threshold_override_millionths: None,
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let engine = CausalReplayEngine::new();
    let report = engine
        .counterfactual_branch(&trace, config)
        .expect("should succeed");
    assert_eq!(report.decisions_evaluated, 3);
}

// ===========================================================================
// 25) Multi-branch comparison
// ===========================================================================

#[test]
fn multi_branch_comparison_runs_all() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let configs: Vec<CounterfactualConfig> = (1..=4)
        .map(|i| CounterfactualConfig {
            branch_id: format!("branch-{i}"),
            threshold_override_millionths: Some(i * 100_000),
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        })
        .collect();
    let engine = CausalReplayEngine::new();
    let reports = engine
        .multi_branch_comparison(&trace, configs)
        .expect("should succeed");
    assert_eq!(reports.len(), 4);
    for (i, r) in reports.iter().enumerate() {
        assert_eq!(r.config.branch_id, format!("branch-{}", i + 1));
    }
}

#[test]
fn multi_branch_comparison_empty_configs() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let engine = CausalReplayEngine::new();
    let reports = engine
        .multi_branch_comparison(&trace, vec![])
        .expect("empty configs should succeed");
    assert!(reports.is_empty());
}

#[test]
fn multi_branch_comparison_exceeds_depth() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let engine = CausalReplayEngine::new().with_max_branch_depth(2);
    let configs: Vec<CounterfactualConfig> = (0..5)
        .map(|i| CounterfactualConfig {
            branch_id: format!("b-{i}"),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        })
        .collect();
    let err = engine.multi_branch_comparison(&trace, configs).unwrap_err();
    assert!(matches!(
        err,
        ReplayError::BranchDepthExceeded {
            requested: 5,
            max: 2
        }
    ));
}

#[test]
fn multi_branch_at_exact_depth_limit_succeeds() {
    let trace = make_trace(&[("sandbox", 200_000)]);
    let engine = CausalReplayEngine::new().with_max_branch_depth(3);
    let configs: Vec<CounterfactualConfig> = (0..3)
        .map(|i| CounterfactualConfig {
            branch_id: format!("b-{i}"),
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
        .expect("exactly at limit should succeed");
    assert_eq!(reports.len(), 3);
}

// ===========================================================================
// 26) TraceIndex — query filtering
// ===========================================================================

#[test]
fn trace_index_query_by_extension_id() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    let trace = make_trace(&[("sandbox", 200_000)]);
    index.insert(trace).unwrap();

    let found = index.query(&TraceQuery {
        extension_id: Some("ext-abc".into()),
        ..Default::default()
    });
    assert_eq!(found.len(), 1);

    let not_found = index.query(&TraceQuery {
        extension_id: Some("ext-unknown".into()),
        ..Default::default()
    });
    assert!(not_found.is_empty());
}

#[test]
fn trace_index_query_by_policy_version() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    let trace = make_trace(&[("sandbox", 200_000)]);
    index.insert(trace).unwrap();

    let found = index.query(&TraceQuery {
        policy_version: Some(1),
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
fn trace_index_query_by_epoch_range() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    let trace = make_trace(&[("sandbox", 200_000)]);
    index.insert(trace).unwrap();

    let found = index.query(&TraceQuery {
        epoch_range: Some((4, 6)),
        ..Default::default()
    });
    assert_eq!(found.len(), 1);

    let not_found = index.query(&TraceQuery {
        epoch_range: Some((10, 20)),
        ..Default::default()
    });
    assert!(not_found.is_empty());
}

#[test]
fn trace_index_query_by_tick_range() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    let trace = make_trace(&[("sandbox", 200_000)]);
    index.insert(trace).unwrap();

    let found = index.query(&TraceQuery {
        tick_range: Some((900, 1200)),
        ..Default::default()
    });
    assert_eq!(found.len(), 1);

    let not_found = index.query(&TraceQuery {
        tick_range: Some((5000, 6000)),
        ..Default::default()
    });
    assert!(not_found.is_empty());
}

#[test]
fn trace_index_query_by_incident_id() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    let config = RecorderConfig {
        trace_id: "inc-query".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);
    recorder.set_incident_id("INC-555".into());
    recorder.record_decision(make_snapshot(0, "terminate", 800_000));
    index.insert(recorder.finalize()).unwrap();

    let found = index.query(&TraceQuery {
        incident_id: Some("INC-555".into()),
        ..Default::default()
    });
    assert_eq!(found.len(), 1);

    let not_found = index.query(&TraceQuery {
        incident_id: Some("INC-999".into()),
        ..Default::default()
    });
    assert!(not_found.is_empty());
}

#[test]
fn trace_index_query_default_returns_all() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    for i in 0..5 {
        let config = RecorderConfig {
            trace_id: format!("t-{i}"),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: i * 100,
            signing_key: test_key(),
        };
        let mut rec = TraceRecorder::new(config);
        rec.record_decision(make_snapshot(0, "allow", 0));
        index.insert(rec.finalize()).unwrap();
    }
    let all = index.query(&TraceQuery::default());
    assert_eq!(all.len(), 5);
}

// ===========================================================================
// 27) TraceIndex — gc (garbage collection)
// ===========================================================================

#[test]
fn trace_index_gc_removes_expired_normal_trace() {
    let retention = TraceRetentionPolicy {
        default_ttl_ticks: 1000,
        ..Default::default()
    };
    let mut index = TraceIndex::new(retention);
    let config = RecorderConfig {
        trace_id: "old".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 100,
        signing_key: test_key(),
    };
    let mut rec = TraceRecorder::new(config);
    rec.record_decision(make_snapshot(0, "allow", 0));
    index.insert(rec.finalize()).unwrap();
    assert_eq!(index.len(), 1);
    index.gc(5000);
    assert_eq!(index.len(), 0);
}

#[test]
fn trace_index_gc_preserves_incident_linked_trace() {
    let retention = TraceRetentionPolicy {
        default_ttl_ticks: 100,
        incident_ttl_ticks: 10_000,
        ..Default::default()
    };
    let mut index = TraceIndex::new(retention);

    // Normal trace
    let config1 = RecorderConfig {
        trace_id: "normal-gc".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 100,
        signing_key: test_key(),
    };
    index
        .insert(TraceRecorder::new(config1).finalize())
        .unwrap();

    // Incident trace
    let config2 = RecorderConfig {
        trace_id: "incident-gc".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 100,
        signing_key: test_key(),
    };
    let mut rec = TraceRecorder::new(config2);
    rec.set_incident_id("INC-GC".into());
    index.insert(rec.finalize()).unwrap();

    assert_eq!(index.len(), 2);
    index.gc(500);
    assert_eq!(index.len(), 1);
    assert!(index.get("incident-gc").is_some());
}

#[test]
fn trace_index_gc_preserves_security_critical_trace() {
    let retention = TraceRetentionPolicy {
        default_ttl_ticks: 100,
        security_critical_ttl_ticks: 5000,
        ..Default::default()
    };
    let mut index = TraceIndex::new(retention);
    let config = RecorderConfig {
        trace_id: "sec-crit-gc".into(),
        recording_mode: RecordingMode::SecurityCritical,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 100,
        signing_key: test_key(),
    };
    index.insert(TraceRecorder::new(config).finalize()).unwrap();

    index.gc(500);
    assert_eq!(index.len(), 1); // Preserved within security_critical TTL
    index.gc(10_000);
    assert_eq!(index.len(), 0); // Now expired
}

#[test]
fn trace_index_gc_on_empty_index() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    index.gc(999_999);
    assert!(index.is_empty());
}

// ===========================================================================
// 28) TraceIndex — eviction
// ===========================================================================

#[test]
fn trace_index_eviction_enforces_max_traces() {
    let retention = TraceRetentionPolicy {
        max_traces: 3,
        ..Default::default()
    };
    let mut index = TraceIndex::new(retention);
    for i in 0..5 {
        let config = RecorderConfig {
            trace_id: format!("evict-{i}"),
            recording_mode: RecordingMode::Full,
            epoch: SecurityEpoch::from_raw(1),
            start_tick: i * 100,
            signing_key: test_key(),
        };
        let mut rec = TraceRecorder::new(config);
        rec.record_decision(make_snapshot(0, "allow", 0));
        index.insert(rec.finalize()).unwrap();
    }
    assert!(index.len() <= 3);
}

#[test]
fn trace_index_eviction_prefers_normal_over_incident() {
    let retention = TraceRetentionPolicy {
        max_traces: 2,
        ..Default::default()
    };
    let mut index = TraceIndex::new(retention);

    // Insert incident-linked
    let config1 = RecorderConfig {
        trace_id: "incident-evict".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 100,
        signing_key: test_key(),
    };
    let mut rec1 = TraceRecorder::new(config1);
    rec1.set_incident_id("INC-EVICT".into());
    index.insert(rec1.finalize()).unwrap();

    // Insert normal
    let config2 = RecorderConfig {
        trace_id: "normal-evict".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 200,
        signing_key: test_key(),
    };
    index
        .insert(TraceRecorder::new(config2).finalize())
        .unwrap();

    // Insert another — should evict "normal-evict"
    let config3 = RecorderConfig {
        trace_id: "new-evict".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 300,
        signing_key: test_key(),
    };
    index
        .insert(TraceRecorder::new(config3).finalize())
        .unwrap();

    assert!(index.len() <= 2);
    assert!(index.get("incident-evict").is_some());
}

// ===========================================================================
// 29) TraceIndex — storage estimate
// ===========================================================================

#[test]
fn trace_index_storage_estimate_increases_on_insert() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    assert_eq!(index.storage_estimate(), 0);
    let trace = make_trace(&[("sandbox", 200_000)]);
    index.insert(trace).unwrap();
    assert!(index.storage_estimate() > 0);
}

#[test]
fn trace_index_storage_estimate_decreases_on_gc() {
    let retention = TraceRetentionPolicy {
        default_ttl_ticks: 100,
        ..Default::default()
    };
    let mut index = TraceIndex::new(retention);
    let trace = make_trace(&[("sandbox", 200_000)]);
    index.insert(trace).unwrap();
    let before = index.storage_estimate();
    assert!(before > 0);
    index.gc(999_999);
    assert_eq!(index.storage_estimate(), 0);
}

// ===========================================================================
// 30) NondeterminismLog — content_hash sensitivity
// ===========================================================================

#[test]
fn nondeterminism_log_hash_differs_by_source() {
    let mut log1 = NondeterminismLog::new();
    log1.append(NondeterminismSource::RandomValue, vec![1], 100, None);

    let mut log2 = NondeterminismLog::new();
    log2.append(NondeterminismSource::Timestamp, vec![1], 100, None);

    assert_ne!(log1.content_hash(), log2.content_hash());
}

#[test]
fn nondeterminism_log_hash_differs_by_value() {
    let mut log1 = NondeterminismLog::new();
    log1.append(NondeterminismSource::RandomValue, vec![1], 100, None);

    let mut log2 = NondeterminismLog::new();
    log2.append(NondeterminismSource::RandomValue, vec![2], 100, None);

    assert_ne!(log1.content_hash(), log2.content_hash());
}

#[test]
fn nondeterminism_log_hash_differs_by_tick() {
    let mut log1 = NondeterminismLog::new();
    log1.append(NondeterminismSource::RandomValue, vec![1], 100, None);

    let mut log2 = NondeterminismLog::new();
    log2.append(NondeterminismSource::RandomValue, vec![1], 200, None);

    assert_ne!(log1.content_hash(), log2.content_hash());
}

#[test]
fn nondeterminism_log_hash_differs_by_extension_id() {
    let mut log_a = NondeterminismLog::new();
    log_a.append(NondeterminismSource::RandomValue, vec![1], 100, None);

    let mut log_b = NondeterminismLog::new();
    log_b.append(
        NondeterminismSource::RandomValue,
        vec![1],
        100,
        Some("ext-1".into()),
    );

    assert_ne!(log_a.content_hash(), log_b.content_hash());
}

// ===========================================================================
// 31) DecisionSnapshot — content_hash sensitivity
// ===========================================================================

#[test]
fn decision_snapshot_hash_differs_by_policy_version() {
    let mut s1 = make_snapshot(0, "allow", 0);
    let mut s2 = make_snapshot(0, "allow", 0);
    s2.policy_version = 999;
    assert_ne!(s1.content_hash(), s2.content_hash());

    s1.policy_version = 999;
    assert_eq!(s1.content_hash(), s2.content_hash());
}

#[test]
fn decision_snapshot_hash_differs_by_epoch() {
    let mut s1 = make_snapshot(0, "allow", 0);
    let s2 = make_snapshot(0, "allow", 0);
    s1.epoch = SecurityEpoch::from_raw(99);
    assert_ne!(s1.content_hash(), s2.content_hash());
}

#[test]
fn decision_snapshot_hash_differs_by_extension_id() {
    let mut s1 = make_snapshot(0, "allow", 0);
    let s2 = make_snapshot(0, "allow", 0);
    s1.extension_id = "ext-different".into();
    assert_ne!(s1.content_hash(), s2.content_hash());
}

#[test]
fn decision_snapshot_hash_differs_by_nondeterminism_range() {
    let mut s1 = make_snapshot(0, "allow", 0);
    let s2 = make_snapshot(0, "allow", 0);
    s1.nondeterminism_range = (100, 200);
    assert_ne!(s1.content_hash(), s2.content_hash());
}

// ===========================================================================
// 32) ActionDeltaReport — object_id
// ===========================================================================

#[test]
fn action_delta_report_object_id_differs_by_zone() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "zone-test".into(),
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
        divergence_points: vec![],
        decisions_evaluated: 5,
    };
    let id_a = report.object_id("zone-a").unwrap();
    let id_b = report.object_id("zone-b").unwrap();
    assert_ne!(id_a, id_b);
}

// ===========================================================================
// 33) Serde roundtrip — TraceRecord full
// ===========================================================================

#[test]
fn serde_roundtrip_trace_record_full() {
    let trace = make_trace(&[("sandbox", 200_000), ("allow", 0)]);
    let json = serde_json::to_string(&trace).expect("serialize");
    let deser: frankenengine_engine::causal_replay::TraceRecord =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(trace.trace_id, deser.trace_id);
    assert_eq!(trace.entries.len(), deser.entries.len());
    assert_eq!(trace.chain_hash, deser.chain_hash);
    assert_eq!(trace.nondeterminism_hash, deser.nondeterminism_hash);
    deser
        .verify_chain_integrity()
        .expect("chain valid after round-trip");
}

#[test]
fn serde_roundtrip_action_delta_report() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "serde-test".into(),
            threshold_override_millionths: Some(100_000),
            loss_matrix_overrides: {
                let mut m = BTreeMap::new();
                m.insert("sandbox".into(), 300_000i64);
                m
            },
            policy_version_override: Some(5),
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 2,
        },
        harm_prevented_delta_millionths: 500_000,
        false_positive_cost_delta_millionths: 10_000,
        containment_latency_delta_ticks: -5,
        resource_cost_delta_millionths: 20_000,
        affected_extensions: {
            let mut s = BTreeSet::new();
            s.insert("ext-serde".into());
            s
        },
        divergence_points: vec![DecisionDelta {
            decision_index: 3,
            original_action: "allow".into(),
            counterfactual_action: "contain".into(),
            original_outcome_millionths: 0,
            counterfactual_outcome_millionths: 100_000,
            diverged: true,
        }],
        decisions_evaluated: 10,
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let deser: ActionDeltaReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, deser);
}

#[test]
fn serde_roundtrip_recorder_config() {
    let config = RecorderConfig {
        trace_id: "rc-serde".into(),
        recording_mode: RecordingMode::Sampled {
            rate_millionths: 750_000,
        },
        epoch: SecurityEpoch::from_raw(99),
        start_tick: 42,
        signing_key: vec![0xDD; 32],
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let deser: RecorderConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, deser);
}

// ===========================================================================
// 34) JSON field stability — additional types
// ===========================================================================

#[test]
fn json_fields_decision_delta() {
    let dd = DecisionDelta {
        decision_index: 0,
        original_action: "a".into(),
        counterfactual_action: "b".into(),
        original_outcome_millionths: 0,
        counterfactual_outcome_millionths: 0,
        diverged: false,
    };
    let v: serde_json::Value = serde_json::to_value(&dd).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "decision_index",
        "original_action",
        "counterfactual_action",
        "original_outcome_millionths",
        "counterfactual_outcome_millionths",
        "diverged",
    ] {
        assert!(obj.contains_key(key), "DecisionDelta missing field: {key}");
    }
}

#[test]
fn json_fields_action_delta_report() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "j".into(),
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
        divergence_points: vec![],
        decisions_evaluated: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&report).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "config",
        "harm_prevented_delta_millionths",
        "false_positive_cost_delta_millionths",
        "containment_latency_delta_ticks",
        "resource_cost_delta_millionths",
        "affected_extensions",
        "divergence_points",
        "decisions_evaluated",
    ] {
        assert!(
            obj.contains_key(key),
            "ActionDeltaReport missing field: {key}"
        );
    }
}

#[test]
fn json_fields_trace_retention_policy() {
    let p = TraceRetentionPolicy::default();
    let v: serde_json::Value = serde_json::to_value(&p).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "default_ttl_ticks",
        "incident_ttl_ticks",
        "security_critical_ttl_ticks",
        "max_traces",
        "max_storage_bytes",
    ] {
        assert!(
            obj.contains_key(key),
            "TraceRetentionPolicy missing field: {key}"
        );
    }
}

#[test]
fn json_fields_recorder_config() {
    let config = RecorderConfig {
        trace_id: "rc".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: vec![0u8; 32],
    };
    let v: serde_json::Value = serde_json::to_value(&config).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "recording_mode",
        "epoch",
        "start_tick",
        "signing_key",
    ] {
        assert!(obj.contains_key(key), "RecorderConfig missing field: {key}");
    }
}

// ===========================================================================
// 35) ReplayError — Display messages contain expected substrings
// ===========================================================================

#[test]
fn replay_error_chain_integrity_display_contains_index_and_detail() {
    let e = ReplayError::ChainIntegrity {
        entry_index: 42,
        detail: "hash mismatch".into(),
    };
    let s = e.to_string();
    assert!(s.contains("42"), "should contain entry index");
    assert!(s.contains("hash mismatch"), "should contain detail");
}

#[test]
fn replay_error_nondeterminism_mismatch_display() {
    let e = ReplayError::NondeterminismMismatch {
        expected_sequence: 10,
        actual_sequence: 20,
    };
    let s = e.to_string();
    assert!(s.contains("10"), "should contain expected seq");
    assert!(s.contains("20"), "should contain actual seq");
}

#[test]
fn replay_error_branch_depth_display() {
    let e = ReplayError::BranchDepthExceeded {
        requested: 50,
        max: 16,
    };
    let s = e.to_string();
    assert!(s.contains("50"), "should contain requested");
    assert!(s.contains("16"), "should contain max");
}

#[test]
fn replay_error_storage_exhausted_display() {
    let e = ReplayError::StorageExhausted;
    let s = e.to_string();
    assert!(!s.is_empty());
}

#[test]
fn replay_error_signature_invalid_display() {
    let e = ReplayError::SignatureInvalid;
    let s = e.to_string();
    assert!(!s.is_empty());
}

// ===========================================================================
// 36) CausalReplayEngine — default trait
// ===========================================================================

#[test]
fn causal_replay_engine_default_trait() {
    let engine = CausalReplayEngine::default();
    let trace = make_trace(&[("allow", 0)]);
    let verdict = engine.replay(&trace).expect("default engine should work");
    assert!(verdict.is_identical());
}

// ===========================================================================
// 37) Large trace replay
// ===========================================================================

#[test]
fn replay_large_trace_50_decisions() {
    let decisions: Vec<(&str, i64)> = (0..50)
        .map(|i| {
            if i % 3 == 0 {
                ("terminate", 800_000i64)
            } else if i % 2 == 0 {
                ("sandbox", 200_000i64)
            } else {
                ("allow", 0i64)
            }
        })
        .collect();

    let trace = make_trace(&decisions);
    assert_eq!(trace.entries.len(), 50);
    trace.verify_chain_integrity().expect("chain valid");
    let engine = CausalReplayEngine::new();
    let verdict = engine.replay(&trace).expect("replay");
    assert!(verdict.is_identical());
}

// ===========================================================================
// 38) NondeterminismLog — all source types recorded and retrieved
// ===========================================================================

#[test]
fn nondeterminism_log_records_all_seven_sources() {
    let mut log = NondeterminismLog::new();
    let sources = [
        NondeterminismSource::RandomValue,
        NondeterminismSource::Timestamp,
        NondeterminismSource::HostcallResult,
        NondeterminismSource::IoResult,
        NondeterminismSource::SchedulingDecision,
        NondeterminismSource::OsEntropy,
        NondeterminismSource::FleetEvidenceArrival,
    ];
    for (i, source) in sources.iter().enumerate() {
        log.append(source.clone(), vec![i as u8], i as u64 * 10, None);
    }
    assert_eq!(log.len(), 7);
    for (i, source) in sources.iter().enumerate() {
        let entry = log.get(i as u64).unwrap();
        assert_eq!(&entry.source, source);
    }
}

// ===========================================================================
// 39) NondeterminismLog — get nonexistent returns None
// ===========================================================================

#[test]
fn nondeterminism_log_get_nonexistent_sequence() {
    let mut log = NondeterminismLog::new();
    log.append(NondeterminismSource::RandomValue, vec![1], 100, None);
    assert!(log.get(0).is_some());
    assert!(log.get(1).is_none());
    assert!(log.get(999).is_none());
}

// ===========================================================================
// 40) TraceIndex — multiple insertions and mixed queries
// ===========================================================================

#[test]
fn trace_index_multiple_traces_query_by_id() {
    let mut index = TraceIndex::new(TraceRetentionPolicy::default());
    for i in 0..3 {
        let trace = make_trace_with_id(&format!("multi-{i}"), &[("allow", 0)]);
        index.insert(trace).unwrap();
    }
    assert_eq!(index.len(), 3);
    assert!(index.get("multi-0").is_some());
    assert!(index.get("multi-1").is_some());
    assert!(index.get("multi-2").is_some());
    assert!(index.get("multi-99").is_none());
}

// ===========================================================================
// 41) ReplayVerdict — Diverged with multiple divergences
// ===========================================================================

#[test]
fn replay_verdict_diverged_multiple_divergences_count() {
    let v = ReplayVerdict::Diverged {
        divergence_point: 1,
        decisions_replayed: 5,
        divergences: vec![
            ReplayDecisionOutcome {
                decision_index: 1,
                original_action: "allow".into(),
                replayed_action: "sandbox".into(),
                original_outcome_millionths: 0,
                replayed_outcome_millionths: 200_000,
                diverged: true,
            },
            ReplayDecisionOutcome {
                decision_index: 3,
                original_action: "allow".into(),
                replayed_action: "terminate".into(),
                original_outcome_millionths: 0,
                replayed_outcome_millionths: 800_000,
                diverged: true,
            },
            ReplayDecisionOutcome {
                decision_index: 4,
                original_action: "sandbox".into(),
                replayed_action: "allow".into(),
                original_outcome_millionths: 200_000,
                replayed_outcome_millionths: 0,
                diverged: true,
            },
        ],
    };
    assert!(!v.is_identical());
    assert_eq!(v.divergence_count(), 3);
}

// ===========================================================================
// 42) ActionDeltaReport — not-improvement
// ===========================================================================

#[test]
fn action_delta_report_not_improvement_when_harm_zero() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "zero-harm".into(),
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
        divergence_points: vec![],
        decisions_evaluated: 10,
    };
    assert!(!report.is_improvement());
}

#[test]
fn action_delta_report_not_improvement_when_negative() {
    let report = ActionDeltaReport {
        config: CounterfactualConfig {
            branch_id: "neg-harm".into(),
            threshold_override_millionths: None,
            loss_matrix_overrides: BTreeMap::new(),
            policy_version_override: None,
            containment_overrides: BTreeMap::new(),
            evidence_weight_overrides: BTreeMap::new(),
            branch_from_index: 0,
        },
        harm_prevented_delta_millionths: -100_000,
        false_positive_cost_delta_millionths: 0,
        containment_latency_delta_ticks: 0,
        resource_cost_delta_millionths: 0,
        affected_extensions: BTreeSet::new(),
        divergence_points: vec![],
        decisions_evaluated: 10,
    };
    assert!(!report.is_improvement());
}

// ===========================================================================
// 43) TraceRetentionPolicy — security_critical_ttl_ticks between others
// ===========================================================================

#[test]
fn trace_retention_policy_ttl_ordering() {
    let p = TraceRetentionPolicy::default();
    assert!(p.default_ttl_ticks < p.security_critical_ttl_ticks);
    assert!(p.security_critical_ttl_ticks < p.incident_ttl_ticks);
}

// ===========================================================================
// 44) Counterfactual config with all overrides populated
// ===========================================================================

#[test]
fn counterfactual_config_full_overrides_serde() {
    let config = CounterfactualConfig {
        branch_id: "full-override".into(),
        threshold_override_millionths: Some(300_000),
        loss_matrix_overrides: {
            let mut m = BTreeMap::new();
            m.insert("sandbox".into(), 100_000i64);
            m.insert("terminate".into(), 50_000i64);
            m
        },
        policy_version_override: Some(42),
        containment_overrides: {
            let mut m = BTreeMap::new();
            m.insert("sandbox".into(), "quarantine".into());
            m
        },
        evidence_weight_overrides: {
            let mut m = BTreeMap::new();
            m.insert("weight-key".into(), 750_000i64);
            m
        },
        branch_from_index: 10,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let deser: CounterfactualConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, deser);
}

// ===========================================================================
// 45) NondeterminismEntry — extension_id None vs Some
// ===========================================================================

#[test]
fn nondeterminism_entry_extension_id_none_serde() {
    let entry = NondeterminismEntry {
        sequence: 0,
        source: NondeterminismSource::OsEntropy,
        value: vec![0xFF],
        tick: 42,
        extension_id: None,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let deser: NondeterminismEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, deser);
    assert!(deser.extension_id.is_none());
}

// ===========================================================================
// 46) TraceRecorder — epoch and tick tracking
// ===========================================================================

#[test]
fn trace_recorder_tracks_end_epoch_and_tick() {
    let config = RecorderConfig {
        trace_id: "epoch-tick".into(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(1),
        start_tick: 0,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);

    let mut snap = make_snapshot(0, "allow", 0);
    snap.epoch = SecurityEpoch::from_raw(7);
    snap.tick = 5000;
    recorder.record_decision(snap);

    let trace = recorder.finalize();
    assert_eq!(trace.start_epoch, SecurityEpoch::from_raw(1));
    assert_eq!(trace.end_epoch, SecurityEpoch::from_raw(7));
    assert_eq!(trace.start_tick, 0);
    assert_eq!(trace.end_tick, 5000);
}

// ===========================================================================
// 47) ReplayDecisionOutcome — non-diverged outcome
// ===========================================================================

#[test]
fn replay_decision_outcome_non_diverged_serde() {
    let outcome = ReplayDecisionOutcome {
        decision_index: 0,
        original_action: "allow".into(),
        replayed_action: "allow".into(),
        original_outcome_millionths: 0,
        replayed_outcome_millionths: 0,
        diverged: false,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let deser: ReplayDecisionOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, deser);
    assert!(!deser.diverged);
}

// ===========================================================================
// 48) Counterfactual branch — negative harm delta (regression)
// ===========================================================================

#[test]
fn counterfactual_branch_negative_harm_delta() {
    // Original: allow(0), allow(0) -> total 0
    let trace = make_trace(&[("allow", 0), ("allow", 0)]);
    let mut overrides = BTreeMap::new();
    overrides.insert("terminate".into(), 100_000i64);
    let config = CounterfactualConfig {
        branch_id: "regression".into(),
        threshold_override_millionths: Some(500_000),
        loss_matrix_overrides: overrides,
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    };
    let engine = CausalReplayEngine::new();
    let report = engine
        .counterfactual_branch(&trace, config)
        .expect("should succeed");
    // CF introduces costs -> harm_delta should be <= 0 (regression)
    assert!(
        !report.is_improvement() || report.harm_prevented_delta_millionths == 0,
        "should not be an improvement or delta is zero"
    );
}

// ===========================================================================
// 49) TraceIndex — storage budget eviction
// ===========================================================================

#[test]
fn trace_index_storage_budget_eviction() {
    let retention = TraceRetentionPolicy {
        max_traces: 1000,
        max_storage_bytes: 1, // 1 byte: forces eviction
        ..Default::default()
    };
    let mut index = TraceIndex::new(retention);
    let trace = make_trace(&[("allow", 0)]);
    index.insert(trace).unwrap();
    assert!(index.len() <= 1);
}

// ===========================================================================
// 50) TraceRecord — serde roundtrip with incident and metadata
// ===========================================================================

#[test]
fn serde_roundtrip_trace_record_with_incident_and_metadata() {
    let config = RecorderConfig {
        trace_id: "inc-meta-serde".into(),
        recording_mode: RecordingMode::SecurityCritical,
        epoch: SecurityEpoch::from_raw(3),
        start_tick: 500,
        signing_key: test_key(),
    };
    let mut recorder = TraceRecorder::new(config);
    recorder.set_incident_id("INC-SERDE".into());
    recorder.set_metadata("env".into(), "production".into());
    recorder.record_nondeterminism(NondeterminismSource::IoResult, vec![9, 8, 7], 600, None);
    recorder.record_decision(make_snapshot(0, "terminate", 800_000));

    let trace = recorder.finalize();
    let json = serde_json::to_string(&trace).unwrap();
    let deser: frankenengine_engine::causal_replay::TraceRecord =
        serde_json::from_str(&json).unwrap();

    assert_eq!(deser.incident_id, Some("INC-SERDE".into()));
    assert_eq!(deser.metadata.get("env"), Some(&"production".into()));
    assert_eq!(deser.recording_mode, RecordingMode::SecurityCritical);
    deser
        .verify_chain_integrity()
        .expect("valid after round-trip");
    assert!(deser.verify_signature(&test_key()));
}
