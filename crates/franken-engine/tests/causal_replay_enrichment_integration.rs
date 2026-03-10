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
