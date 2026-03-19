//! Enrichment integration tests for `tier_telemetry_contract`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tier_telemetry_contract::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(!TELEMETRY_CONTRACT_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_bead_id_starts_with_bd() {
    assert!(TELEMETRY_CONTRACT_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_policy_id_non_empty() {
    assert!(!TELEMETRY_CONTRACT_POLICY_ID.is_empty());
}

#[test]
fn enrichment_component_non_empty() {
    assert!(!COMPONENT.is_empty());
}

// ---------------------------------------------------------------------------
// TelemetryTier
// ---------------------------------------------------------------------------

#[test]
fn enrichment_telemetry_tier_all_count() {
    assert!(TelemetryTier::ALL.len() >= 4);
}

#[test]
fn enrichment_telemetry_tier_as_key_unique() {
    let mut keys = std::collections::BTreeSet::new();
    for tier in TelemetryTier::ALL {
        assert!(
            keys.insert(tier.as_key()),
            "duplicate key: {}",
            tier.as_key()
        );
    }
}

#[test]
fn enrichment_telemetry_tier_serde_roundtrip() {
    for tier in TelemetryTier::ALL {
        let json = serde_json::to_string(tier).unwrap();
        let back: TelemetryTier = serde_json::from_str(&json).unwrap();
        assert_eq!(*tier, back);
    }
}

// ---------------------------------------------------------------------------
// TelemetryEventKind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_telemetry_event_kind_serde_roundtrip() {
    for kind in [
        TelemetryEventKind::TierTransition,
        TelemetryEventKind::DeoptOccurrence,
        TelemetryEventKind::ProbeUpdate,
        TelemetryEventKind::BenchmarkSample,
        TelemetryEventKind::LatencyObservation,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: TelemetryEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// classify_delta
// ---------------------------------------------------------------------------

#[test]
fn enrichment_classify_delta_improvement() {
    let c = classify_delta(200_000, 100_000);
    assert_eq!(c, DeltaClassification::Improvement);
}

#[test]
fn enrichment_classify_delta_regression() {
    let c = classify_delta(-200_000, 100_000);
    assert_eq!(c, DeltaClassification::Regression);
}

#[test]
fn enrichment_classify_delta_neutral() {
    let c = classify_delta(50_000, 100_000);
    assert_eq!(c, DeltaClassification::Neutral);
}

#[test]
fn enrichment_classify_delta_zero() {
    let c = classify_delta(0, 100_000);
    assert_eq!(c, DeltaClassification::Neutral);
}

// ---------------------------------------------------------------------------
// BenchmarkEvidenceKind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_benchmark_evidence_kind_serde() {
    for kind in [
        BenchmarkEvidenceKind::Throughput,
        BenchmarkEvidenceKind::Latency,
        BenchmarkEvidenceKind::MemoryUsage,
        BenchmarkEvidenceKind::CpuUtilization,
        BenchmarkEvidenceKind::CacheHitRate,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: BenchmarkEvidenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// build_benchmark_sample
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_sample_negative_delta() {
    let sample = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Interpreted,
        400_000,
        500_000,
        900_000,
    );
    assert_eq!(sample.delta_millionths, -100_000);
    assert!(sample.is_regression);
}

#[test]
fn enrichment_build_sample_positive_delta() {
    let sample = build_benchmark_sample(
        BenchmarkEvidenceKind::Latency,
        TelemetryTier::Baseline,
        600_000,
        500_000,
        900_000,
    );
    assert_eq!(sample.delta_millionths, 100_000);
    assert!(!sample.is_regression);
}

#[test]
fn enrichment_build_sample_zero_delta() {
    let sample = build_benchmark_sample(
        BenchmarkEvidenceKind::MemoryUsage,
        TelemetryTier::Optimized,
        500_000,
        500_000,
        900_000,
    );
    assert_eq!(sample.delta_millionths, 0);
    assert!(!sample.is_regression);
}

#[test]
fn enrichment_build_sample_serde_roundtrip() {
    let sample = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Specialized,
        100_000,
        100_000,
        800_000,
    );
    let json = serde_json::to_string(&sample).unwrap();
    let back: BenchmarkSample = serde_json::from_str(&json).unwrap();
    assert_eq!(sample.sample_id, back.sample_id);
}

// ---------------------------------------------------------------------------
// is_regression
// ---------------------------------------------------------------------------

#[test]
fn enrichment_is_regression_negative_delta() {
    let sample = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Interpreted,
        300_000,
        500_000,
        900_000,
    );
    assert!(is_regression(&sample));
}

#[test]
fn enrichment_is_regression_positive_delta_not_regression() {
    let sample = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Interpreted,
        600_000,
        500_000,
        900_000,
    );
    assert!(!is_regression(&sample));
}

// ---------------------------------------------------------------------------
// build_evidence_bundle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_evidence_bundle_counts() {
    let samples = vec![
        build_benchmark_sample(
            BenchmarkEvidenceKind::Throughput,
            TelemetryTier::Interpreted,
            300_000,
            500_000,
            900_000,
        ),
        build_benchmark_sample(
            BenchmarkEvidenceKind::Latency,
            TelemetryTier::Baseline,
            600_000,
            500_000,
            900_000,
        ),
        build_benchmark_sample(
            BenchmarkEvidenceKind::MemoryUsage,
            TelemetryTier::Optimized,
            500_000,
            500_000,
            900_000,
        ),
    ];
    let epoch = SecurityEpoch::from_raw(1);
    let bundle = build_evidence_bundle(samples, &epoch);
    assert_eq!(bundle.total_samples, 3);
    assert!(bundle.regression_count >= 1);
}

#[test]
fn enrichment_build_evidence_bundle_serde_roundtrip() {
    let samples = vec![build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Interpreted,
        500_000,
        500_000,
        900_000,
    )];
    let bundle = build_evidence_bundle(samples, &SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&bundle).unwrap();
    let back: BenchmarkEvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.bundle_id, back.bundle_id);
}

// ---------------------------------------------------------------------------
// regression_rate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_regression_rate_zero_samples() {
    let bundle = build_evidence_bundle(vec![], &SecurityEpoch::from_raw(1));
    assert_eq!(regression_rate(&bundle), 0);
}

// ---------------------------------------------------------------------------
// PublicationContract
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_contract_valid() {
    let contract = PublicationContract::default_contract();
    assert!(contract.required_min_samples > 0);
    assert!(contract.required_confidence_millionths > 0);
}

#[test]
fn enrichment_default_contract_serde_roundtrip() {
    let contract = PublicationContract::default_contract();
    let json = serde_json::to_string(&contract).unwrap();
    let back: PublicationContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract.contract_id, back.contract_id);
}

// ---------------------------------------------------------------------------
// evaluate_publication
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_publication_insufficient_samples() {
    let samples = vec![build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Interpreted,
        500_000,
        500_000,
        900_000,
    )];
    let bundle = build_evidence_bundle(samples, &SecurityEpoch::from_raw(1));
    let contract = PublicationContract::default_contract();
    let verdict = evaluate_publication(&bundle, &contract, &SecurityEpoch::from_raw(1));
    assert!(!verdict.is_publishable);
    assert!(!verdict.reasons.is_empty());
}

// ---------------------------------------------------------------------------
// compute_tier_distribution
// ---------------------------------------------------------------------------

#[test]
fn enrichment_tier_distribution_empty() {
    let snapshot = compute_tier_distribution(&[], &SecurityEpoch::from_raw(1));
    assert_eq!(snapshot.total_functions, 0);
}

#[test]
fn enrichment_tier_distribution_with_events() {
    let events = vec![
        build_telemetry_event(
            TelemetryEventKind::TierTransition,
            TelemetryTier::Interpreted,
            1000,
            500_000,
            BTreeMap::new(),
        ),
        build_telemetry_event(
            TelemetryEventKind::TierTransition,
            TelemetryTier::Interpreted,
            2000,
            600_000,
            BTreeMap::new(),
        ),
    ];
    let snapshot = compute_tier_distribution(&events, &SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&snapshot).unwrap();
    let back: TierDistributionSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snapshot.snapshot_id, back.snapshot_id);
}

// ---------------------------------------------------------------------------
// build_telemetry_report / manifest
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_telemetry_report_empty() {
    let report = build_telemetry_report(vec![], vec![], vec![], None, &SecurityEpoch::from_raw(1));
    assert_eq!(report.total_events, 0);
}

#[test]
fn enrichment_manifest_epoch_genesis() {
    let manifest = franken_engine_tier_telemetry_manifest();
    assert_eq!(manifest.epoch, SecurityEpoch::GENESIS);
    assert_eq!(manifest.total_events, 0);
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let manifest = franken_engine_tier_telemetry_manifest();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: TelemetryReport = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest.report_id, back.report_id);
}

// ---------------------------------------------------------------------------
// DeltaClassification serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_delta_classification_serde() {
    for c in [
        DeltaClassification::Improvement,
        DeltaClassification::Neutral,
        DeltaClassification::Regression,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: DeltaClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

// ---------------------------------------------------------------------------
// build_telemetry_event
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_telemetry_event_basic() {
    let event = build_telemetry_event(
        TelemetryEventKind::BenchmarkSample,
        TelemetryTier::Optimized,
        12345,
        500_000,
        BTreeMap::new(),
    );
    assert_eq!(event.kind, TelemetryEventKind::BenchmarkSample);
    assert_eq!(event.tier, TelemetryTier::Optimized);
    assert_eq!(event.timestamp_nanos, 12345);
}

#[test]
fn enrichment_build_telemetry_event_with_labels() {
    let mut labels = BTreeMap::new();
    labels.insert("region".to_string(), "us-east".to_string());
    let event = build_telemetry_event(
        TelemetryEventKind::ProbeUpdate,
        TelemetryTier::Baseline,
        1000,
        100_000,
        labels,
    );
    assert!(event.labels.contains_key("region"));
}

#[test]
fn enrichment_build_telemetry_event_serde_roundtrip() {
    let event = build_telemetry_event(
        TelemetryEventKind::LatencyObservation,
        TelemetryTier::Deoptimized,
        9999,
        42_000,
        BTreeMap::new(),
    );
    let json = serde_json::to_string(&event).unwrap();
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event.event_id, back.event_id);
}
