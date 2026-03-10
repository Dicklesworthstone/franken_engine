#![forbid(unsafe_code)]

//! Integration tests for the `hostcall_telemetry` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! recorder lifecycle, monotonicity invariants, content integrity,
//! rolling hashes, snapshots, epoch management, query interface,
//! extension summaries, serde round-trips, and Display formatting.

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

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_telemetry::{
    ExtensionSummary, FlowLabel, HostcallResult, HostcallType, RecordInput, RecorderConfig,
    ResourceDelta, TelemetryError, TelemetryQuery, TelemetryRecorder, TelemetrySnapshot,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_flow_label() -> FlowLabel {
    FlowLabel::new("public", "public")
}

fn make_input(ext_id: &str, htype: HostcallType) -> RecordInput {
    RecordInput {
        extension_id: ext_id.to_string(),
        hostcall_type: htype,
        capability_used: RuntimeCapability::FsRead,
        arguments_hash: ContentHash::compute(b"test-args"),
        result_status: HostcallResult::Success,
        duration_ns: 1_000,
        resource_delta: ResourceDelta::default(),
        flow_label: default_flow_label(),
        decision_id: None,
    }
}

fn make_input_with_result(
    ext_id: &str,
    htype: HostcallType,
    result: HostcallResult,
) -> RecordInput {
    RecordInput {
        extension_id: ext_id.to_string(),
        hostcall_type: htype,
        capability_used: RuntimeCapability::FsRead,
        arguments_hash: ContentHash::compute(b"test-args"),
        result_status: result,
        duration_ns: 1_000,
        resource_delta: ResourceDelta::default(),
        flow_label: default_flow_label(),
        decision_id: None,
    }
}

fn make_input_with_duration(ext_id: &str, htype: HostcallType, duration_ns: u64) -> RecordInput {
    RecordInput {
        extension_id: ext_id.to_string(),
        hostcall_type: htype,
        capability_used: RuntimeCapability::FsRead,
        arguments_hash: ContentHash::compute(b"test-args"),
        result_status: HostcallResult::Success,
        duration_ns,
        resource_delta: ResourceDelta::default(),
        flow_label: default_flow_label(),
        decision_id: None,
    }
}

fn default_recorder() -> TelemetryRecorder {
    TelemetryRecorder::new(RecorderConfig::default())
}

fn small_recorder(capacity: usize) -> TelemetryRecorder {
    TelemetryRecorder::new(RecorderConfig {
        channel_capacity: capacity,
        epoch: SecurityEpoch::GENESIS,
        enable_rolling_hash: true,
    })
}

/// Populate a recorder with a mix of extensions, types, and outcomes.
fn populated_recorder() -> TelemetryRecorder {
    let mut rec = default_recorder();
    // ext-alpha: 3 FsRead (2 success, 1 denied), 1 NetworkSend (success)
    rec.record(1000, make_input("ext-alpha", HostcallType::FsRead))
        .unwrap();
    rec.record(2000, make_input("ext-alpha", HostcallType::FsRead))
        .unwrap();
    rec.record(
        3000,
        make_input_with_result(
            "ext-alpha",
            HostcallType::FsRead,
            HostcallResult::Denied {
                reason: "policy".into(),
            },
        ),
    )
    .unwrap();
    rec.record(4000, make_input("ext-alpha", HostcallType::NetworkSend))
        .unwrap();
    // ext-beta: 1 FsWrite (success), 1 FsWrite (error), 1 CryptoOp (timeout)
    rec.record(5000, make_input("ext-beta", HostcallType::FsWrite))
        .unwrap();
    rec.record(
        6000,
        make_input_with_result(
            "ext-beta",
            HostcallType::FsWrite,
            HostcallResult::Error { code: 13 },
        ),
    )
    .unwrap();
    rec.record(
        7000,
        make_input_with_result("ext-beta", HostcallType::CryptoOp, HostcallResult::Timeout),
    )
    .unwrap();
    rec
}

// ===========================================================================
// 1. TelemetryRecorder basics
// ===========================================================================

#[test]
fn recorder_new_is_empty() {
    let rec = default_recorder();
    assert!(rec.is_empty());
    assert_eq!(rec.len(), 0);
    assert_eq!(rec.remaining_capacity(), 8192);
    assert!(rec.records().is_empty());
    assert!(rec.snapshots().is_empty());
    assert!(rec.verify_all_integrity().is_empty());
}

#[test]
fn record_returns_sequential_ids() {
    let mut rec = default_recorder();
    let id0 = rec
        .record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let id1 = rec
        .record(200, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    let id2 = rec
        .record(300, make_input("ext-b", HostcallType::NetworkSend))
        .unwrap();
    assert_eq!(id0, 0);
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
}

#[test]
fn len_is_empty_remaining_capacity_after_inserts() {
    let mut rec = small_recorder(10);
    assert!(rec.is_empty());
    assert_eq!(rec.remaining_capacity(), 10);

    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    assert!(!rec.is_empty());
    assert_eq!(rec.len(), 1);
    assert_eq!(rec.remaining_capacity(), 9);

    rec.record(200, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(300, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    assert_eq!(rec.len(), 3);
    assert_eq!(rec.remaining_capacity(), 7);
}

// ===========================================================================
// 2. Monotonicity
// ===========================================================================

#[test]
fn equal_timestamps_allowed() {
    let mut rec = default_recorder();
    rec.record(500, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(500, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    rec.record(500, make_input("ext-a", HostcallType::NetworkSend))
        .unwrap();
    assert_eq!(rec.len(), 3);
}

#[test]
fn backward_timestamp_rejected() {
    let mut rec = default_recorder();
    rec.record(2000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let err = rec
        .record(1000, make_input("ext-a", HostcallType::FsWrite))
        .unwrap_err();
    match err {
        TelemetryError::MonotonicityViolation {
            field,
            previous,
            attempted,
        } => {
            assert_eq!(field, "timestamp_ns");
            assert_eq!(previous, 2000);
            assert_eq!(attempted, 1000);
        }
        other => panic!("expected MonotonicityViolation, got {other:?}"),
    }
    // Recorder unchanged after rejection.
    assert_eq!(rec.len(), 1);
}

#[test]
fn record_id_strictly_increasing() {
    let mut rec = default_recorder();
    let mut prev_id = None;
    for ts in (100..=1000).step_by(100) {
        let id = rec
            .record(ts, make_input("ext-a", HostcallType::FsRead))
            .unwrap();
        if let Some(p) = prev_id {
            assert!(id > p, "record_id must strictly increase: {id} > {p}");
        }
        prev_id = Some(id);
    }
}

// ===========================================================================
// 3. Validation
// ===========================================================================

#[test]
fn empty_extension_id_rejected() {
    let mut rec = default_recorder();
    let err = rec
        .record(100, make_input("", HostcallType::FsRead))
        .unwrap_err();
    assert_eq!(err, TelemetryError::EmptyExtensionId);
}

#[test]
fn channel_full_backpressure() {
    let mut rec = small_recorder(2);
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(200, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let err = rec
        .record(300, make_input("ext-a", HostcallType::FsRead))
        .unwrap_err();
    assert_eq!(err, TelemetryError::ChannelFull);
    assert_eq!(rec.len(), 2);
    assert_eq!(rec.remaining_capacity(), 0);
}

// ===========================================================================
// 4. Content integrity
// ===========================================================================

#[test]
fn verify_integrity_on_fresh_record() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    assert!(rec.records()[0].verify_integrity());
}

#[test]
fn verify_integrity_detects_tampered_duration() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let mut tampered = rec.records()[0].clone();
    tampered.duration_ns = 999_999;
    assert!(!tampered.verify_integrity());
}

#[test]
fn verify_integrity_detects_tampered_extension_id() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let mut tampered = rec.records()[0].clone();
    tampered.extension_id = "ext-evil".to_string();
    assert!(!tampered.verify_integrity());
}

#[test]
fn verify_all_integrity_clean_log() {
    let mut rec = default_recorder();
    for ts in (100..=500).step_by(100) {
        rec.record(ts, make_input("ext-a", HostcallType::FsRead))
            .unwrap();
    }
    assert!(rec.verify_all_integrity().is_empty());
}

// ===========================================================================
// 5. Rolling hash
// ===========================================================================

#[test]
fn rolling_hash_changes_with_each_record() {
    let mut rec = default_recorder();
    let h0 = rec.rolling_hash().clone();
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let h1 = rec.rolling_hash().clone();
    rec.record(200, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    let h2 = rec.rolling_hash().clone();

    assert_ne!(h0, h1);
    assert_ne!(h1, h2);
    assert_ne!(h0, h2);
}

#[test]
fn rolling_hash_deterministic_same_inputs() {
    let mut r1 = default_recorder();
    let mut r2 = default_recorder();

    let input = make_input("ext-a", HostcallType::FsRead);
    r1.record(1000, input.clone()).unwrap();
    r2.record(1000, input).unwrap();

    assert_eq!(r1.rolling_hash(), r2.rolling_hash());
}

#[test]
fn rolling_hash_disabled_stays_constant() {
    let mut rec = TelemetryRecorder::new(RecorderConfig {
        channel_capacity: 100,
        epoch: SecurityEpoch::GENESIS,
        enable_rolling_hash: false,
    });
    let before = rec.rolling_hash().clone();
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(200, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    assert_eq!(before, *rec.rolling_hash());
}

// ===========================================================================
// 6. Snapshots
// ===========================================================================

#[test]
fn snapshot_captures_current_state() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let snap = rec.snapshot();
    assert_eq!(snap.record_count, 1);
    assert_eq!(snap.record_id_at_snapshot, Some(0));
    assert_eq!(snap.epoch, SecurityEpoch::GENESIS);
}

#[test]
fn multiple_snapshots_have_different_record_counts() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let s1 = rec.snapshot();
    rec.record(2000, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    rec.record(3000, make_input("ext-a", HostcallType::NetworkSend))
        .unwrap();
    let s2 = rec.snapshot();

    assert_eq!(s1.record_count, 1);
    assert_eq!(s2.record_count, 3);
    assert_ne!(s1.rolling_hash, s2.rolling_hash);
    assert_eq!(rec.snapshots().len(), 2);
}

// ===========================================================================
// 7. set_epoch
// ===========================================================================

#[test]
fn set_epoch_stamps_new_records() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    assert_eq!(rec.records()[0].epoch, SecurityEpoch::GENESIS);

    let epoch5 = SecurityEpoch::from_raw(5);
    rec.set_epoch(epoch5);
    rec.record(2000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    assert_eq!(rec.records()[1].epoch, epoch5);

    // Old record unchanged.
    assert_eq!(rec.records()[0].epoch, SecurityEpoch::GENESIS);
}

// ===========================================================================
// 8. get by record_id
// ===========================================================================

#[test]
fn get_existing_record() {
    let mut rec = default_recorder();
    rec.record(100, make_input("ext-alpha", HostcallType::FsRead))
        .unwrap();
    rec.record(200, make_input("ext-beta", HostcallType::FsWrite))
        .unwrap();

    let r0 = rec.get(0).expect("record 0 must exist");
    assert_eq!(r0.extension_id, "ext-alpha");
    assert_eq!(r0.hostcall_type, HostcallType::FsRead);

    let r1 = rec.get(1).expect("record 1 must exist");
    assert_eq!(r1.extension_id, "ext-beta");
    assert_eq!(r1.hostcall_type, HostcallType::FsWrite);
}

#[test]
fn get_nonexistent_returns_none() {
    let mut rec = default_recorder();
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    assert!(rec.get(99).is_none());
    assert!(rec.get(u64::MAX).is_none());
}

// ===========================================================================
// 9. content_hash (overall)
// ===========================================================================

#[test]
fn content_hash_deterministic() {
    let mut r1 = default_recorder();
    let mut r2 = default_recorder();

    let input = make_input("ext-a", HostcallType::FsRead);
    r1.record(1000, input.clone()).unwrap();
    r2.record(1000, input).unwrap();

    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn content_hash_different_records_produce_different_hash() {
    let mut r1 = default_recorder();
    let mut r2 = default_recorder();

    r1.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    r2.record(1000, make_input("ext-b", HostcallType::FsRead))
        .unwrap();

    assert_ne!(r1.content_hash(), r2.content_hash());
}

// ===========================================================================
// 10. TelemetryQuery
// ===========================================================================

#[test]
fn query_recent_by_extension_filters_correctly() {
    let rec = populated_recorder();
    let query = TelemetryQuery::new(rec.records());

    let alpha = query.recent_by_extension("ext-alpha", 0, 10_000);
    assert_eq!(alpha.len(), 4);

    let beta = query.recent_by_extension("ext-beta", 0, 10_000);
    assert_eq!(beta.len(), 3);

    let none = query.recent_by_extension("ext-nonexistent", 0, 10_000);
    assert!(none.is_empty());
}

#[test]
fn query_recent_by_extension_respects_time_window() {
    let rec = populated_recorder();
    let query = TelemetryQuery::new(rec.records());

    // ext-alpha records at 1000, 2000, 3000, 4000
    let window = query.recent_by_extension("ext-alpha", 2000, 3000);
    assert_eq!(window.len(), 2);
}

#[test]
fn query_recent_by_type_filters_correctly() {
    let rec = populated_recorder();
    let query = TelemetryQuery::new(rec.records());

    let fs_read = query.recent_by_type(HostcallType::FsRead, 0, 10_000);
    assert_eq!(fs_read.len(), 3);

    let fs_write = query.recent_by_type(HostcallType::FsWrite, 0, 10_000);
    assert_eq!(fs_write.len(), 2);

    let net_send = query.recent_by_type(HostcallType::NetworkSend, 0, 10_000);
    assert_eq!(net_send.len(), 1);

    let crypto = query.recent_by_type(HostcallType::CryptoOp, 0, 10_000);
    assert_eq!(crypto.len(), 1);
}

#[test]
fn query_anomaly_candidates_returns_non_success() {
    let rec = populated_recorder();
    let query = TelemetryQuery::new(rec.records());

    let anomalies = query.anomaly_candidates(0, 10_000);
    // 1 denied + 1 error + 1 timeout = 3
    assert_eq!(anomalies.len(), 3);
    for a in &anomalies {
        assert!(!matches!(a.result_status, HostcallResult::Success));
    }
}

#[test]
fn query_anomaly_candidates_empty_for_all_success() {
    let mut rec = default_recorder();
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(200, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();

    let query = TelemetryQuery::new(rec.records());
    assert!(query.anomaly_candidates(0, 10_000).is_empty());
}

#[test]
fn query_extension_summary_tallies() {
    let rec = populated_recorder();
    let query = TelemetryQuery::new(rec.records());

    let alpha_summary = query.extension_summary("ext-alpha", 0, 10_000);
    assert_eq!(alpha_summary.total_calls, 4);
    assert_eq!(alpha_summary.success_count, 3);
    assert_eq!(alpha_summary.denied_count, 1);
    assert_eq!(alpha_summary.error_count, 0);
    assert_eq!(alpha_summary.timeout_count, 0);

    let beta_summary = query.extension_summary("ext-beta", 0, 10_000);
    assert_eq!(beta_summary.total_calls, 3);
    assert_eq!(beta_summary.success_count, 1);
    assert_eq!(beta_summary.denied_count, 0);
    assert_eq!(beta_summary.error_count, 1);
    assert_eq!(beta_summary.timeout_count, 1);
}

#[test]
fn query_extension_summary_type_counts() {
    let rec = populated_recorder();
    let query = TelemetryQuery::new(rec.records());

    let summary = query.extension_summary("ext-alpha", 0, 10_000);
    assert_eq!(summary.type_counts.get(&HostcallType::FsRead), Some(&3));
    assert_eq!(
        summary.type_counts.get(&HostcallType::NetworkSend),
        Some(&1)
    );
    assert_eq!(summary.type_counts.get(&HostcallType::FsWrite), None);
}

#[test]
fn query_type_distribution_counts() {
    let rec = populated_recorder();
    let query = TelemetryQuery::new(rec.records());

    let dist = query.type_distribution(0, 10_000);
    assert_eq!(dist.get(&HostcallType::FsRead), Some(&3));
    assert_eq!(dist.get(&HostcallType::FsWrite), Some(&2));
    assert_eq!(dist.get(&HostcallType::NetworkSend), Some(&1));
    assert_eq!(dist.get(&HostcallType::CryptoOp), Some(&1));
}

#[test]
fn query_slow_calls_threshold_filtering() {
    let mut rec = default_recorder();
    rec.record(
        100,
        make_input_with_duration("ext-a", HostcallType::FsRead, 500),
    )
    .unwrap();
    rec.record(
        200,
        make_input_with_duration("ext-a", HostcallType::FsWrite, 10_000),
    )
    .unwrap();
    rec.record(
        300,
        make_input_with_duration("ext-a", HostcallType::NetworkSend, 3_000),
    )
    .unwrap();

    let query = TelemetryQuery::new(rec.records());

    let slow = query.slow_calls(5_000, 0, 10_000);
    assert_eq!(slow.len(), 1);
    assert_eq!(slow[0].hostcall_type, HostcallType::FsWrite);

    let slower = query.slow_calls(2_000, 0, 10_000);
    assert_eq!(slower.len(), 2);
}

// ===========================================================================
// 11. ExtensionSummary
// ===========================================================================

#[test]
fn extension_summary_avg_duration_ns() {
    let summary = ExtensionSummary {
        total_calls: 5,
        total_duration_ns: 5_000,
        ..Default::default()
    };
    assert_eq!(summary.avg_duration_ns(), 1_000);
}

#[test]
fn extension_summary_avg_duration_ns_zero_calls() {
    let summary = ExtensionSummary::default();
    assert_eq!(summary.avg_duration_ns(), 0);
}

#[test]
fn extension_summary_denial_rate_millionths() {
    let summary = ExtensionSummary {
        total_calls: 4,
        denied_count: 1,
        ..Default::default()
    };
    assert_eq!(summary.denial_rate_millionths(), 250_000); // 25%
}

#[test]
fn extension_summary_denial_rate_zero_calls() {
    let summary = ExtensionSummary::default();
    assert_eq!(summary.denial_rate_millionths(), 0);
}

#[test]
fn extension_summary_denial_rate_full() {
    let summary = ExtensionSummary {
        total_calls: 3,
        denied_count: 3,
        ..Default::default()
    };
    assert_eq!(summary.denial_rate_millionths(), 1_000_000); // 100%
}

// ===========================================================================
// 12. Serde round-trips
// ===========================================================================

#[test]
fn serde_hostcall_type_all_variants() {
    let variants = [
        HostcallType::FsRead,
        HostcallType::FsWrite,
        HostcallType::NetworkSend,
        HostcallType::NetworkRecv,
        HostcallType::ProcessSpawn,
        HostcallType::EnvRead,
        HostcallType::MemAlloc,
        HostcallType::TimerCreate,
        HostcallType::CryptoOp,
        HostcallType::IpcSend,
        HostcallType::IpcRecv,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let restored: HostcallType = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored, "round-trip failed for {v}");
    }
}

#[test]
fn serde_hostcall_result_all_variants() {
    let variants = [
        HostcallResult::Success,
        HostcallResult::Denied {
            reason: "no cap".into(),
        },
        HostcallResult::Error { code: 42 },
        HostcallResult::Timeout,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let restored: HostcallResult = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored, "round-trip failed for {v}");
    }
}

#[test]
fn serde_resource_delta() {
    let rd = ResourceDelta {
        memory_bytes: -4096,
        fd_count: 3,
        network_bytes: 65536,
    };
    let json = serde_json::to_string(&rd).unwrap();
    let restored: ResourceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(rd, restored);
}

#[test]
fn serde_flow_label() {
    let fl = FlowLabel::new("secret", "top-secret");
    let json = serde_json::to_string(&fl).unwrap();
    let restored: FlowLabel = serde_json::from_str(&json).unwrap();
    assert_eq!(fl, restored);
}

#[test]
fn serde_telemetry_snapshot() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let snap = rec.snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    let restored: TelemetrySnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, restored);
}

#[test]
fn serde_recorder_config() {
    let config = RecorderConfig {
        channel_capacity: 4096,
        epoch: SecurityEpoch::from_raw(7),
        enable_rolling_hash: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: RecorderConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.channel_capacity, config.channel_capacity);
    assert_eq!(restored.epoch, config.epoch);
    assert_eq!(restored.enable_rolling_hash, config.enable_rolling_hash);
}

#[test]
fn serde_telemetry_error_all_variants() {
    let variants: Vec<TelemetryError> = vec![
        TelemetryError::ChannelFull,
        TelemetryError::MonotonicityViolation {
            field: "timestamp_ns".into(),
            previous: 100,
            attempted: 50,
        },
        TelemetryError::EmptyExtensionId,
        TelemetryError::SnapshotOutOfRange {
            requested: 10,
            max: 5,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: TelemetryError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored, "round-trip failed for {v}");
    }
}

#[test]
fn serde_extension_summary() {
    let mut type_counts = BTreeMap::new();
    type_counts.insert(HostcallType::FsRead, 5);
    type_counts.insert(HostcallType::NetworkSend, 2);

    let summary = ExtensionSummary {
        total_calls: 7,
        success_count: 6,
        denied_count: 1,
        error_count: 0,
        timeout_count: 0,
        total_duration_ns: 7_000,
        type_counts,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: ExtensionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn serde_telemetry_record() {
    let mut rec = default_recorder();
    let mut input = make_input("ext-a", HostcallType::ProcessSpawn);
    input.decision_id = Some("decision-42".into());
    input.capability_used = RuntimeCapability::ProcessSpawn;
    input.resource_delta = ResourceDelta {
        memory_bytes: 1024,
        fd_count: 1,
        network_bytes: 0,
    };
    input.flow_label = FlowLabel::new("secret", "top-secret");
    rec.record(1000, input).unwrap();

    let record = &rec.records()[0];
    let json = serde_json::to_string(record).unwrap();
    let restored: frankenengine_engine::hostcall_telemetry::HostcallTelemetryRecord =
        serde_json::from_str(&json).unwrap();
    assert_eq!(record.record_id, restored.record_id);
    assert_eq!(record.content_hash, restored.content_hash);
    assert_eq!(record.hostcall_type, restored.hostcall_type);
    assert_eq!(record.extension_id, restored.extension_id);
    assert_eq!(record.decision_id, restored.decision_id);
    // Restored record should also pass integrity.
    assert!(restored.verify_integrity());
}

// ===========================================================================
// 13. Display
// ===========================================================================

#[test]
fn display_hostcall_type_all_11() {
    let cases = [
        (HostcallType::FsRead, "fs-read"),
        (HostcallType::FsWrite, "fs-write"),
        (HostcallType::NetworkSend, "network-send"),
        (HostcallType::NetworkRecv, "network-recv"),
        (HostcallType::ProcessSpawn, "process-spawn"),
        (HostcallType::EnvRead, "env-read"),
        (HostcallType::MemAlloc, "mem-alloc"),
        (HostcallType::TimerCreate, "timer-create"),
        (HostcallType::CryptoOp, "crypto-op"),
        (HostcallType::IpcSend, "ipc-send"),
        (HostcallType::IpcRecv, "ipc-recv"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected);
    }
}

#[test]
fn display_hostcall_result_all_4() {
    assert_eq!(HostcallResult::Success.to_string(), "success");
    assert_eq!(
        HostcallResult::Denied {
            reason: "no cap".into()
        }
        .to_string(),
        "denied: no cap"
    );
    assert_eq!(HostcallResult::Error { code: 42 }.to_string(), "error: 42");
    assert_eq!(HostcallResult::Timeout.to_string(), "timeout");
}

#[test]
fn display_flow_label() {
    let fl = FlowLabel::new("secret", "top-secret");
    assert_eq!(fl.to_string(), "secret:top-secret");

    let public = FlowLabel::new("public", "public");
    assert_eq!(public.to_string(), "public:public");
}

#[test]
fn display_telemetry_error_all_variants() {
    let channel_full = TelemetryError::ChannelFull;
    assert_eq!(channel_full.to_string(), "telemetry channel full");

    let mono = TelemetryError::MonotonicityViolation {
        field: "timestamp_ns".into(),
        previous: 100,
        attempted: 50,
    };
    let mono_str = mono.to_string();
    assert!(mono_str.contains("monotonicity violation"));
    assert!(mono_str.contains("timestamp_ns"));
    assert!(mono_str.contains("100"));
    assert!(mono_str.contains("50"));

    let empty = TelemetryError::EmptyExtensionId;
    assert_eq!(empty.to_string(), "empty extension id");

    let oor = TelemetryError::SnapshotOutOfRange {
        requested: 10,
        max: 5,
    };
    let oor_str = oor.to_string();
    assert!(oor_str.contains("10"));
    assert!(oor_str.contains("5"));
    assert!(oor_str.contains("out of range"));
}

// ===========================================================================
// Additional coverage: cross-cutting scenarios
// ===========================================================================

#[test]
fn decision_id_recorded_correctly() {
    let mut rec = default_recorder();
    let mut input = make_input("ext-a", HostcallType::ProcessSpawn);
    input.decision_id = Some("decision-abc".into());
    rec.record(1000, input).unwrap();

    let record = rec.get(0).unwrap();
    assert_eq!(record.decision_id.as_deref(), Some("decision-abc"));
}

#[test]
fn capability_used_recorded_correctly() {
    let mut rec = default_recorder();
    let mut input = make_input("ext-a", HostcallType::FsWrite);
    input.capability_used = RuntimeCapability::FsWrite;
    rec.record(1000, input).unwrap();
    assert_eq!(rec.records()[0].capability_used, RuntimeCapability::FsWrite);
}

#[test]
fn resource_delta_preserved() {
    let mut rec = default_recorder();
    let mut input = make_input("ext-a", HostcallType::MemAlloc);
    input.resource_delta = ResourceDelta {
        memory_bytes: 65536,
        fd_count: -2,
        network_bytes: 1024,
    };
    rec.record(1000, input).unwrap();
    let rd = &rec.records()[0].resource_delta;
    assert_eq!(rd.memory_bytes, 65536);
    assert_eq!(rd.fd_count, -2);
    assert_eq!(rd.network_bytes, 1024);
}

#[test]
fn flow_label_preserved() {
    let mut rec = default_recorder();
    let mut input = make_input("ext-a", HostcallType::FsRead);
    input.flow_label = FlowLabel::new("confidential", "top-secret");
    rec.record(1000, input).unwrap();
    assert_eq!(
        rec.records()[0].flow_label,
        FlowLabel::new("confidential", "top-secret")
    );
}

#[test]
fn recorder_config_defaults() {
    let config = RecorderConfig::default();
    assert_eq!(config.channel_capacity, 8192);
    assert_eq!(config.epoch, SecurityEpoch::GENESIS);
    assert!(config.enable_rolling_hash);
}

#[test]
fn resource_delta_default_is_zero() {
    let rd = ResourceDelta::default();
    assert_eq!(rd.memory_bytes, 0);
    assert_eq!(rd.fd_count, 0);
    assert_eq!(rd.network_bytes, 0);
}

#[test]
fn recorder_serde_roundtrip_preserves_state() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(2000, make_input("ext-b", HostcallType::FsWrite))
        .unwrap();
    rec.snapshot();

    let json = serde_json::to_string(&rec).unwrap();
    let restored: TelemetryRecorder = serde_json::from_str(&json).unwrap();

    assert_eq!(rec.len(), restored.len());
    assert_eq!(rec.rolling_hash(), restored.rolling_hash());
    assert_eq!(rec.content_hash(), restored.content_hash());
    assert_eq!(rec.snapshots().len(), restored.snapshots().len());
    assert!(restored.verify_all_integrity().is_empty());
}

#[test]
fn extension_summary_default_is_all_zeros() {
    let summary = ExtensionSummary::default();
    assert_eq!(summary.total_calls, 0);
    assert_eq!(summary.success_count, 0);
    assert_eq!(summary.denied_count, 0);
    assert_eq!(summary.error_count, 0);
    assert_eq!(summary.timeout_count, 0);
    assert_eq!(summary.total_duration_ns, 0);
    assert!(summary.type_counts.is_empty());
}

#[test]
fn query_on_empty_records() {
    let query = TelemetryQuery::new(&[]);
    assert!(query.recent_by_extension("ext-a", 0, u64::MAX).is_empty());
    assert!(
        query
            .recent_by_type(HostcallType::FsRead, 0, u64::MAX)
            .is_empty()
    );
    assert!(query.anomaly_candidates(0, u64::MAX).is_empty());
    let summary = query.extension_summary("ext-a", 0, u64::MAX);
    assert_eq!(summary.total_calls, 0);
    assert!(query.type_distribution(0, u64::MAX).is_empty());
    assert!(query.slow_calls(0, 0, u64::MAX).is_empty());
}
