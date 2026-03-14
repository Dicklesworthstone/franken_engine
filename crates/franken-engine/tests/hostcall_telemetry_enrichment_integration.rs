//! Enrichment integration tests for the `hostcall_telemetry` module.
//!
//! Covers: HostcallType ordering/Copy/Hash, HostcallResult Clone, FlowLabel Ord,
//! snapshot edge cases (empty recorder, epoch change), query time-window boundaries,
//! slow_calls exact threshold, integrity tamper (record_id, timestamp, epoch,
//! result_status), rolling hash across epochs, content hash on empty recorder,
//! denial_rate boundary values, Debug formatting, record at timestamp 0,
//! extension summary for nonexistent extension, backpressure exact boundary.

#![forbid(unsafe_code)]
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

use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_telemetry::{
    ExtensionSummary, FlowLabel, HostcallResult, HostcallType, RecordInput, RecorderConfig,
    ResourceDelta, TelemetryQuery, TelemetryRecorder, TelemetrySnapshot,
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

// =========================================================================
// A. HostcallType — ordering, Copy, Hash
// =========================================================================

#[test]
fn enrichment_hostcall_type_ordering_all_11() {
    let all = [
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
    // Each consecutive pair should maintain Ord invariant.
    for i in 0..all.len() - 1 {
        assert!(
            all[i] < all[i + 1],
            "{:?} should be < {:?}",
            all[i],
            all[i + 1]
        );
    }
}

#[test]
fn enrichment_hostcall_type_copy() {
    let t = HostcallType::CryptoOp;
    let t2 = t;
    assert_eq!(t, t2);
}

#[test]
fn enrichment_hostcall_type_hash_all_distinct() {
    use std::hash::{Hash, Hasher};
    let all = [
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
    let mut hashes = BTreeSet::new();
    for variant in &all {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        variant.hash(&mut hasher);
        hashes.insert(hasher.finish());
    }
    assert_eq!(hashes.len(), 11);
}

// =========================================================================
// B. HostcallResult — Clone independence
// =========================================================================

#[test]
fn enrichment_hostcall_result_clone_independence() {
    let original = HostcallResult::Denied {
        reason: "policy violation".into(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // Different value is not equal.
    let other = HostcallResult::Denied {
        reason: "different".into(),
    };
    assert_ne!(original, other);
}

// =========================================================================
// C. FlowLabel — Ord
// =========================================================================

#[test]
fn enrichment_flow_label_ord_by_label_class() {
    let a = FlowLabel::new("alpha", "public");
    let b = FlowLabel::new("beta", "public");
    assert!(a < b);
}

#[test]
fn enrichment_flow_label_ord_by_clearance_class_tiebreak() {
    let a = FlowLabel::new("secret", "alpha");
    let b = FlowLabel::new("secret", "beta");
    assert!(a < b);
}

#[test]
fn enrichment_flow_label_clone_independence() {
    let original = FlowLabel::new("secret", "top-secret");
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.to_string(), cloned.to_string());
}

// =========================================================================
// D. Snapshot edge cases
// =========================================================================

#[test]
fn enrichment_snapshot_on_empty_recorder() {
    let mut rec = default_recorder();
    let snap = rec.snapshot();
    assert_eq!(snap.record_id_at_snapshot, None);
    assert_eq!(snap.record_count, 0);
    assert_eq!(snap.epoch, SecurityEpoch::GENESIS);
}

#[test]
fn enrichment_snapshot_after_epoch_change() {
    let mut rec = default_recorder();
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let epoch3 = SecurityEpoch::from_raw(3);
    rec.set_epoch(epoch3);
    let snap = rec.snapshot();
    assert_eq!(snap.epoch, epoch3);
    assert_eq!(snap.record_count, 1);
}

#[test]
fn enrichment_snapshot_serde_on_empty() {
    let mut rec = default_recorder();
    let snap = rec.snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    let restored: TelemetrySnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, restored);
    assert_eq!(restored.record_id_at_snapshot, None);
}

// =========================================================================
// E. Query time-window boundary conditions
// =========================================================================

#[test]
fn enrichment_query_inclusive_boundaries() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(2000, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    rec.record(3000, make_input("ext-a", HostcallType::NetworkSend))
        .unwrap();
    let query = TelemetryQuery::new(rec.records());

    // Window [1000, 1000] should include exactly the record at ts=1000.
    let exact = query.recent_by_extension("ext-a", 1000, 1000);
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].hostcall_type, HostcallType::FsRead);
}

#[test]
fn enrichment_query_window_excludes_outside() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(5000, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    let query = TelemetryQuery::new(rec.records());

    // Window [2000, 4000] should exclude both records.
    let results = query.recent_by_extension("ext-a", 2000, 4000);
    assert!(results.is_empty());
}

#[test]
fn enrichment_query_type_distribution_window_filtering() {
    let mut rec = default_recorder();
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(200, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(300, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    rec.record(400, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let query = TelemetryQuery::new(rec.records());

    // Window [150, 350] should include ts=200 (FsRead), ts=300 (FsWrite).
    let dist = query.type_distribution(150, 350);
    assert_eq!(dist.get(&HostcallType::FsRead), Some(&1));
    assert_eq!(dist.get(&HostcallType::FsWrite), Some(&1));
    assert_eq!(dist.len(), 2);
}

// =========================================================================
// F. slow_calls exact threshold behavior
// =========================================================================

#[test]
fn enrichment_slow_calls_threshold_is_strictly_greater() {
    let mut rec = default_recorder();
    rec.record(
        100,
        make_input_with_duration("ext-a", HostcallType::FsRead, 5000),
    )
    .unwrap();
    rec.record(
        200,
        make_input_with_duration("ext-a", HostcallType::FsWrite, 5001),
    )
    .unwrap();
    let query = TelemetryQuery::new(rec.records());

    // Threshold = 5000: only duration > 5000 included.
    let slow = query.slow_calls(5000, 0, u64::MAX);
    assert_eq!(slow.len(), 1);
    assert_eq!(slow[0].hostcall_type, HostcallType::FsWrite);
}

// =========================================================================
// G. Integrity tamper detection — more fields
// =========================================================================

#[test]
fn enrichment_verify_integrity_detects_tampered_record_id() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let mut tampered = rec.records()[0].clone();
    tampered.record_id = 999;
    assert!(!tampered.verify_integrity());
}

#[test]
fn enrichment_verify_integrity_detects_tampered_timestamp() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let mut tampered = rec.records()[0].clone();
    tampered.timestamp_ns = 9999;
    assert!(!tampered.verify_integrity());
}

#[test]
fn enrichment_verify_integrity_detects_tampered_result_status() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let mut tampered = rec.records()[0].clone();
    tampered.result_status = HostcallResult::Timeout;
    assert!(!tampered.verify_integrity());
}

#[test]
fn enrichment_verify_integrity_detects_tampered_epoch() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let mut tampered = rec.records()[0].clone();
    tampered.epoch = SecurityEpoch::from_raw(999);
    assert!(!tampered.verify_integrity());
}

#[test]
fn enrichment_verify_integrity_detects_tampered_hostcall_type() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let mut tampered = rec.records()[0].clone();
    tampered.hostcall_type = HostcallType::CryptoOp;
    assert!(!tampered.verify_integrity());
}

// =========================================================================
// H. Rolling hash across epoch changes
// =========================================================================

#[test]
fn enrichment_rolling_hash_incorporates_epoch_change() {
    let mut rec1 = default_recorder();
    rec1.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec1.record(2000, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    let h1 = rec1.rolling_hash().clone();

    // Second recorder: same records but epoch change between them.
    let mut rec2 = default_recorder();
    rec2.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec2.set_epoch(SecurityEpoch::from_raw(5));
    rec2.record(2000, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    let h2 = rec2.rolling_hash().clone();

    // The rolling hashes should differ because the second record has a
    // different epoch, which changes its content hash.
    assert_ne!(h1, h2);
}

// =========================================================================
// I. Content hash on empty recorder
// =========================================================================

#[test]
fn enrichment_content_hash_empty_recorder_deterministic() {
    let r1 = default_recorder();
    let r2 = default_recorder();
    assert_eq!(r1.content_hash(), r2.content_hash());
}

// =========================================================================
// J. Denial rate boundary values
// =========================================================================

#[test]
fn enrichment_denial_rate_exactly_50_percent() {
    let summary = ExtensionSummary {
        total_calls: 2,
        denied_count: 1,
        ..Default::default()
    };
    assert_eq!(summary.denial_rate_millionths(), 500_000);
}

#[test]
fn enrichment_denial_rate_one_of_three() {
    let summary = ExtensionSummary {
        total_calls: 3,
        denied_count: 1,
        ..Default::default()
    };
    // 1/3 * 1_000_000 = 333_333 (integer division)
    assert_eq!(summary.denial_rate_millionths(), 333_333);
}

#[test]
fn enrichment_avg_duration_rounding() {
    let summary = ExtensionSummary {
        total_calls: 3,
        total_duration_ns: 10,
        ..Default::default()
    };
    // 10 / 3 = 3 (integer division)
    assert_eq!(summary.avg_duration_ns(), 3);
}

// =========================================================================
// K. Record at timestamp 0
// =========================================================================

#[test]
fn enrichment_record_at_timestamp_zero() {
    let mut rec = default_recorder();
    let id = rec
        .record(0, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    assert_eq!(id, 0);
    assert_eq!(rec.records()[0].timestamp_ns, 0);
    assert!(rec.records()[0].verify_integrity());
}

// =========================================================================
// L. Extension summary for nonexistent extension
// =========================================================================

#[test]
fn enrichment_extension_summary_nonexistent() {
    let mut rec = default_recorder();
    rec.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let query = TelemetryQuery::new(rec.records());
    let summary = query.extension_summary("ext-nonexistent", 0, u64::MAX);
    assert_eq!(summary.total_calls, 0);
    assert_eq!(summary.avg_duration_ns(), 0);
    assert_eq!(summary.denial_rate_millionths(), 0);
}

// =========================================================================
// M. Backpressure exact boundary
// =========================================================================

#[test]
fn enrichment_backpressure_exact_capacity_boundary() {
    let mut rec = small_recorder(3);
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    assert_eq!(rec.remaining_capacity(), 2);

    rec.record(200, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    assert_eq!(rec.remaining_capacity(), 1);

    rec.record(300, make_input("ext-a", HostcallType::NetworkSend))
        .unwrap();
    assert_eq!(rec.remaining_capacity(), 0);

    // Next record should fail.
    let err = rec
        .record(400, make_input("ext-a", HostcallType::CryptoOp))
        .unwrap_err();
    assert_eq!(
        err,
        frankenengine_engine::hostcall_telemetry::TelemetryError::ChannelFull
    );
    // Len still 3 after rejection.
    assert_eq!(rec.len(), 3);
}

// =========================================================================
// N. Debug formatting non-empty for all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", HostcallType::FsRead).is_empty());
    assert!(!format!("{:?}", HostcallResult::Success).is_empty());
    assert!(!format!("{:?}", HostcallResult::Denied { reason: "x".into() }).is_empty());
    assert!(!format!("{:?}", HostcallResult::Error { code: 1 }).is_empty());
    assert!(!format!("{:?}", HostcallResult::Timeout).is_empty());
    assert!(!format!("{:?}", FlowLabel::new("a", "b")).is_empty());
    assert!(!format!("{:?}", ResourceDelta::default()).is_empty());
    assert!(!format!("{:?}", RecorderConfig::default()).is_empty());
    assert!(!format!("{:?}", default_recorder()).is_empty());
}

// =========================================================================
// O. Record with all HostcallResult variants preserves them
// =========================================================================

#[test]
fn enrichment_record_preserves_all_result_variants() {
    let mut rec = default_recorder();

    rec.record(
        100,
        make_input_with_result("ext-a", HostcallType::FsRead, HostcallResult::Success),
    )
    .unwrap();
    rec.record(
        200,
        make_input_with_result(
            "ext-a",
            HostcallType::FsWrite,
            HostcallResult::Denied {
                reason: "cap denied".into(),
            },
        ),
    )
    .unwrap();
    rec.record(
        300,
        make_input_with_result(
            "ext-a",
            HostcallType::NetworkSend,
            HostcallResult::Error { code: 42 },
        ),
    )
    .unwrap();
    rec.record(
        400,
        make_input_with_result("ext-a", HostcallType::CryptoOp, HostcallResult::Timeout),
    )
    .unwrap();

    assert!(matches!(
        rec.records()[0].result_status,
        HostcallResult::Success
    ));
    assert!(matches!(
        rec.records()[1].result_status,
        HostcallResult::Denied { .. }
    ));
    assert!(matches!(
        rec.records()[2].result_status,
        HostcallResult::Error { code: 42 }
    ));
    assert!(matches!(
        rec.records()[3].result_status,
        HostcallResult::Timeout
    ));

    // All records should have valid integrity.
    assert!(rec.verify_all_integrity().is_empty());
}

// =========================================================================
// P. Multiple snapshots preserve distinct rolling hashes
// =========================================================================

#[test]
fn enrichment_multiple_snapshots_distinct_hashes() {
    let mut rec = default_recorder();
    let s0 = rec.snapshot();

    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let s1 = rec.snapshot();

    rec.record(200, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    let s2 = rec.snapshot();

    // All three snapshots should have distinct rolling hashes.
    assert_ne!(s0.rolling_hash, s1.rolling_hash);
    assert_ne!(s1.rolling_hash, s2.rolling_hash);
    assert_ne!(s0.rolling_hash, s2.rolling_hash);

    // Snapshot list grows.
    assert_eq!(rec.snapshots().len(), 3);
}

// =========================================================================
// Q. Query anomaly_candidates with mixed window
// =========================================================================

#[test]
fn enrichment_anomaly_candidates_window_filtering() {
    let mut rec = default_recorder();
    rec.record(
        100,
        make_input_with_result(
            "ext-a",
            HostcallType::FsRead,
            HostcallResult::Denied {
                reason: "early".into(),
            },
        ),
    )
    .unwrap();
    rec.record(200, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    rec.record(
        300,
        make_input_with_result(
            "ext-a",
            HostcallType::NetworkSend,
            HostcallResult::Error { code: 7 },
        ),
    )
    .unwrap();

    let query = TelemetryQuery::new(rec.records());

    // Window [150, 250] should only include the success at 200 — no anomalies.
    let anomalies = query.anomaly_candidates(150, 250);
    assert!(anomalies.is_empty());

    // Window [250, 350] should include the error at 300.
    let anomalies2 = query.anomaly_candidates(250, 350);
    assert_eq!(anomalies2.len(), 1);
}

// =========================================================================
// R. Recorder get after multiple records
// =========================================================================

#[test]
fn enrichment_get_records_by_all_ids() {
    let mut rec = default_recorder();
    for i in 0u64..5 {
        rec.record(i * 100, make_input("ext-a", HostcallType::FsRead))
            .unwrap();
    }
    for i in 0u64..5 {
        let r = rec.get(i).expect("should exist");
        assert_eq!(r.record_id, i);
        assert_eq!(r.timestamp_ns, i * 100);
    }
    assert!(rec.get(5).is_none());
}

// =========================================================================
// S. ResourceDelta serde with negative values
// =========================================================================

#[test]
fn enrichment_resource_delta_serde_negative_values() {
    let rd = ResourceDelta {
        memory_bytes: -65536,
        fd_count: -10,
        network_bytes: -1024,
    };
    let json = serde_json::to_string(&rd).unwrap();
    let restored: ResourceDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(rd, restored);
}

// =========================================================================
// T. Capability used field variation
// =========================================================================

#[test]
fn enrichment_different_capabilities_produce_different_hashes() {
    let mut rec1 = default_recorder();
    let mut input1 = make_input("ext-a", HostcallType::FsRead);
    input1.capability_used = RuntimeCapability::FsRead;
    rec1.record(1000, input1).unwrap();

    let mut rec2 = default_recorder();
    let mut input2 = make_input("ext-a", HostcallType::FsRead);
    input2.capability_used = RuntimeCapability::NetworkEgress;
    rec2.record(1000, input2).unwrap();

    // Different capability should produce different content hash.
    assert_ne!(
        rec1.records()[0].content_hash,
        rec2.records()[0].content_hash
    );
}

// =========================================================================
// U. TelemetryError — serde roundtrip for all variants
// =========================================================================

#[test]
fn enrichment_telemetry_error_serde_channel_full() {
    use frankenengine_engine::hostcall_telemetry::TelemetryError;
    let err = TelemetryError::ChannelFull;
    let json = serde_json::to_string(&err).unwrap();
    let restored: TelemetryError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_telemetry_error_serde_monotonicity_violation() {
    use frankenengine_engine::hostcall_telemetry::TelemetryError;
    let err = TelemetryError::MonotonicityViolation {
        field: "timestamp_ns".into(),
        previous: 5000,
        attempted: 3000,
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: TelemetryError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_telemetry_error_serde_empty_extension_id() {
    use frankenengine_engine::hostcall_telemetry::TelemetryError;
    let err = TelemetryError::EmptyExtensionId;
    let json = serde_json::to_string(&err).unwrap();
    let restored: TelemetryError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_telemetry_error_serde_snapshot_out_of_range() {
    use frankenengine_engine::hostcall_telemetry::TelemetryError;
    let err = TelemetryError::SnapshotOutOfRange {
        requested: 42,
        max: 10,
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: TelemetryError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// =========================================================================
// V. TelemetryError — Display distinctness for all variants
// =========================================================================

#[test]
fn enrichment_telemetry_error_display_all_variants_distinct() {
    use frankenengine_engine::hostcall_telemetry::TelemetryError;
    let variants: Vec<String> = vec![
        TelemetryError::ChannelFull.to_string(),
        TelemetryError::MonotonicityViolation {
            field: "ts".into(),
            previous: 10,
            attempted: 5,
        }
        .to_string(),
        TelemetryError::EmptyExtensionId.to_string(),
        TelemetryError::SnapshotOutOfRange {
            requested: 3,
            max: 1,
        }
        .to_string(),
    ];
    let mut seen = BTreeSet::new();
    for v in &variants {
        assert!(!v.is_empty());
        assert!(seen.insert(v.clone()), "duplicate Display: {v}");
    }
    assert_eq!(seen.len(), 4);
}

// =========================================================================
// W. HostcallResult — serde roundtrip all variants
// =========================================================================

#[test]
fn enrichment_hostcall_result_serde_all_variants() {
    let variants = vec![
        HostcallResult::Success,
        HostcallResult::Denied {
            reason: "cap denied".into(),
        },
        HostcallResult::Error { code: 42 },
        HostcallResult::Timeout,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: HostcallResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// =========================================================================
// X. HostcallResult — Display distinctness for all variants
// =========================================================================

#[test]
fn enrichment_hostcall_result_display_all_variants_distinct() {
    let variants: Vec<String> = vec![
        HostcallResult::Success.to_string(),
        HostcallResult::Denied {
            reason: "blocked".into(),
        }
        .to_string(),
        HostcallResult::Error { code: 1 }.to_string(),
        HostcallResult::Timeout.to_string(),
    ];
    let mut seen = BTreeSet::new();
    for v in &variants {
        assert!(!v.is_empty());
        assert!(seen.insert(v.clone()), "duplicate Display: {v}");
    }
    assert_eq!(seen.len(), 4);
}

// =========================================================================
// Y. MonotonicityViolation error path
// =========================================================================

#[test]
fn enrichment_monotonicity_violation_on_decreasing_timestamp() {
    use frankenengine_engine::hostcall_telemetry::TelemetryError;
    let mut rec = default_recorder();
    rec.record(5000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let err = rec
        .record(4999, make_input("ext-a", HostcallType::FsWrite))
        .unwrap_err();
    assert!(matches!(
        err,
        TelemetryError::MonotonicityViolation {
            previous: 5000,
            attempted: 4999,
            ..
        }
    ));
}

// =========================================================================
// Z. EmptyExtensionId error path
// =========================================================================

#[test]
fn enrichment_empty_extension_id_rejected() {
    use frankenengine_engine::hostcall_telemetry::TelemetryError;
    let mut rec = default_recorder();
    let err = rec
        .record(1000, make_input("", HostcallType::FsRead))
        .unwrap_err();
    assert_eq!(err, TelemetryError::EmptyExtensionId);
}

// =========================================================================
// AA. recent_by_type query
// =========================================================================

#[test]
fn enrichment_query_recent_by_type_filters_correctly() {
    let mut rec = default_recorder();
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(200, make_input("ext-b", HostcallType::FsWrite))
        .unwrap();
    rec.record(300, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(400, make_input("ext-c", HostcallType::NetworkSend))
        .unwrap();
    let query = TelemetryQuery::new(rec.records());

    let fs_reads = query.recent_by_type(HostcallType::FsRead, 0, u64::MAX);
    assert_eq!(fs_reads.len(), 2);
    assert_eq!(fs_reads[0].extension_id, "ext-a");
    assert_eq!(fs_reads[1].extension_id, "ext-a");

    // Window narrowing: only the second FsRead (ts=300) in [250, 350].
    let narrow = query.recent_by_type(HostcallType::FsRead, 250, 350);
    assert_eq!(narrow.len(), 1);
    assert_eq!(narrow[0].timestamp_ns, 300);
}

// =========================================================================
// BB. decision_id Some vs None affects content hash
// =========================================================================

#[test]
fn enrichment_decision_id_changes_content_hash() {
    let mut rec1 = default_recorder();
    let input1 = make_input("ext-a", HostcallType::FsRead);
    rec1.record(1000, input1).unwrap();

    let mut rec2 = default_recorder();
    let mut input2 = make_input("ext-a", HostcallType::FsRead);
    input2.decision_id = Some("decision-xyz".into());
    rec2.record(1000, input2).unwrap();

    assert_ne!(
        rec1.records()[0].content_hash,
        rec2.records()[0].content_hash,
        "decision_id should affect content hash"
    );
}

// =========================================================================
// CC. Recorder is_empty transitions
// =========================================================================

#[test]
fn enrichment_recorder_is_empty_transitions() {
    let mut rec = default_recorder();
    assert!(rec.is_empty());
    assert_eq!(rec.len(), 0);

    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    assert!(!rec.is_empty());
    assert_eq!(rec.len(), 1);
}

// =========================================================================
// DD. content_hash changes with each additional record
// =========================================================================

#[test]
fn enrichment_content_hash_changes_with_each_record() {
    let mut rec = default_recorder();
    let h0 = rec.content_hash();

    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    let h1 = rec.content_hash();

    rec.record(200, make_input("ext-a", HostcallType::FsWrite))
        .unwrap();
    let h2 = rec.content_hash();

    // All three content hashes must be distinct.
    assert_ne!(h0, h1);
    assert_ne!(h1, h2);
    assert_ne!(h0, h2);
}

// =========================================================================
// EE. ResourceDelta non-default positive values affect content hash
// =========================================================================

#[test]
fn enrichment_resource_delta_positive_values_affect_hash() {
    let mut rec1 = default_recorder();
    rec1.record(1000, make_input("ext-a", HostcallType::FsRead))
        .unwrap();

    let mut rec2 = default_recorder();
    let mut input2 = make_input("ext-a", HostcallType::FsRead);
    input2.resource_delta = ResourceDelta {
        memory_bytes: 4096,
        fd_count: 2,
        network_bytes: 1024,
    };
    rec2.record(1000, input2).unwrap();

    assert_ne!(
        rec1.records()[0].content_hash,
        rec2.records()[0].content_hash,
        "non-default ResourceDelta should change content hash"
    );
}

// =========================================================================
// FF. HostcallTelemetryRecord serde roundtrip
// =========================================================================

#[test]
fn enrichment_hostcall_telemetry_record_serde_roundtrip() {
    use frankenengine_engine::hostcall_telemetry::HostcallTelemetryRecord;
    let mut rec = default_recorder();
    let mut input = make_input("ext-serde", HostcallType::CryptoOp);
    input.result_status = HostcallResult::Error { code: 99 };
    input.decision_id = Some("dec-42".into());
    input.resource_delta = ResourceDelta {
        memory_bytes: -1024,
        fd_count: 3,
        network_bytes: 512,
    };
    rec.record(7777, input).unwrap();

    let record = &rec.records()[0];
    let json = serde_json::to_string(record).unwrap();
    let restored: HostcallTelemetryRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(*record, restored);
    assert!(restored.verify_integrity());
}

// =========================================================================
// GG. Max timestamp (u64::MAX) records successfully
// =========================================================================

#[test]
fn enrichment_record_at_max_timestamp() {
    let mut rec = default_recorder();
    let id = rec
        .record(u64::MAX, make_input("ext-max", HostcallType::TimerCreate))
        .unwrap();
    assert_eq!(id, 0);
    assert_eq!(rec.records()[0].timestamp_ns, u64::MAX);
    assert!(rec.records()[0].verify_integrity());
}

// =========================================================================
// HH. verify_all_integrity detects mixed valid/tampered records
// =========================================================================

#[test]
fn enrichment_verify_all_integrity_mixed_valid_and_tampered() {
    let mut rec = default_recorder();
    for i in 0u64..5 {
        rec.record(i * 100, make_input("ext-a", HostcallType::FsRead))
            .unwrap();
    }
    // All should pass initially.
    assert!(rec.verify_all_integrity().is_empty());

    // Tamper records at index 1 and 3 by mutating through a cloned recorder.
    let mut records_copy: Vec<frankenengine_engine::hostcall_telemetry::HostcallTelemetryRecord> =
        rec.records().to_vec();
    records_copy[1].duration_ns = 999_999;
    records_copy[3].extension_id = "ext-tampered".into();

    // Manually verify: tampered records fail, others pass.
    let mut tampered_ids = Vec::new();
    for r in &records_copy {
        if !r.verify_integrity() {
            tampered_ids.push(r.record_id);
        }
    }
    assert_eq!(tampered_ids, vec![1, 3]);
}

// =========================================================================
// II. RecorderConfig serde roundtrip
// =========================================================================

#[test]
fn enrichment_recorder_config_serde_roundtrip() {
    let config = RecorderConfig {
        channel_capacity: 256,
        epoch: SecurityEpoch::from_raw(7),
        enable_rolling_hash: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: RecorderConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config.channel_capacity, restored.channel_capacity);
    assert_eq!(config.epoch, restored.epoch);
    assert_eq!(config.enable_rolling_hash, restored.enable_rolling_hash);
}

// =========================================================================
// JJ. ExtensionSummary serde roundtrip with populated type_counts
// =========================================================================

#[test]
fn enrichment_extension_summary_serde_roundtrip_with_type_counts() {
    let mut rec = default_recorder();
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(200, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(
        300,
        make_input_with_result(
            "ext-a",
            HostcallType::NetworkSend,
            HostcallResult::Denied {
                reason: "cap".into(),
            },
        ),
    )
    .unwrap();
    rec.record(
        400,
        make_input_with_result(
            "ext-a",
            HostcallType::CryptoOp,
            HostcallResult::Error { code: 5 },
        ),
    )
    .unwrap();
    rec.record(
        500,
        make_input_with_result("ext-a", HostcallType::IpcSend, HostcallResult::Timeout),
    )
    .unwrap();

    let query = TelemetryQuery::new(rec.records());
    let summary = query.extension_summary("ext-a", 0, u64::MAX);

    assert_eq!(summary.total_calls, 5);
    assert_eq!(summary.success_count, 2);
    assert_eq!(summary.denied_count, 1);
    assert_eq!(summary.error_count, 1);
    assert_eq!(summary.timeout_count, 1);
    assert_eq!(summary.type_counts.get(&HostcallType::FsRead), Some(&2));
    assert_eq!(
        summary.type_counts.get(&HostcallType::NetworkSend),
        Some(&1)
    );

    let json = serde_json::to_string(&summary).unwrap();
    let restored: ExtensionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// =========================================================================
// KK. FlowLabel Display format verification
// =========================================================================

#[test]
fn enrichment_flow_label_display_format() {
    let label = FlowLabel::new("secret", "top-secret");
    assert_eq!(label.to_string(), "secret:top-secret");

    let public = FlowLabel::new("public", "public");
    assert_eq!(public.to_string(), "public:public");
}

// =========================================================================
// LL. TelemetryRecorder serde roundtrip preserves records
// =========================================================================

#[test]
fn enrichment_recorder_serde_roundtrip_preserves_state() {
    let mut rec = default_recorder();
    rec.record(100, make_input("ext-a", HostcallType::FsRead))
        .unwrap();
    rec.record(200, make_input("ext-b", HostcallType::FsWrite))
        .unwrap();
    rec.snapshot();

    let json = serde_json::to_string(&rec).unwrap();
    let restored: TelemetryRecorder = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.len(), 2);
    assert_eq!(restored.records()[0].extension_id, "ext-a");
    assert_eq!(restored.records()[1].extension_id, "ext-b");
    assert_eq!(restored.snapshots().len(), 1);
    assert_eq!(*restored.rolling_hash(), *rec.rolling_hash());
    assert_eq!(restored.content_hash(), rec.content_hash());
}
