#![forbid(unsafe_code)]

//! Integration tests for the `tier_telemetry_contract` module.

use std::collections::BTreeMap;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::tier_telemetry_contract::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn sample_improvement(tier: TelemetryTier) -> BenchmarkSample {
    build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        tier,
        1_200_000,
        1_000_000,
        950_000,
    )
}

fn sample_regression(tier: TelemetryTier) -> BenchmarkSample {
    build_benchmark_sample(
        BenchmarkEvidenceKind::Latency,
        tier,
        800_000,
        1_000_000,
        950_000,
    )
}

fn sample_neutral(tier: TelemetryTier) -> BenchmarkSample {
    build_benchmark_sample(
        BenchmarkEvidenceKind::MemoryUsage,
        tier,
        1_010_000,
        1_000_000,
        950_000,
    )
}

/// Build a bundle with one sample per tier (all improvements), using given epoch.
fn all_tier_bundle(e: &SecurityEpoch) -> BenchmarkEvidenceBundle {
    let samples: Vec<BenchmarkSample> = TelemetryTier::ALL
        .iter()
        .map(|t| sample_improvement(*t))
        .collect();
    build_evidence_bundle(samples, e)
}

/// A permissive contract for testing.
fn permissive_contract() -> PublicationContract {
    PublicationContract {
        contract_id: "permissive".to_string(),
        required_min_samples: 1,
        required_confidence_millionths: 0,
        max_regression_rate_millionths: 1_000_000,
        require_all_tiers_represented: false,
        staleness_limit_epochs: 100,
        content_hash: ContentHash::compute(b"permissive"),
    }
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_constant() {
    assert_eq!(
        TELEMETRY_CONTRACT_SCHEMA_VERSION,
        "franken-engine.tier-telemetry-contract.v1"
    );
}

#[test]
fn bead_id_constant() {
    assert_eq!(TELEMETRY_CONTRACT_BEAD_ID, "bd-1lsy.4.11.3");
}

#[test]
fn policy_id_constant() {
    assert_eq!(TELEMETRY_CONTRACT_POLICY_ID, "RGC-310C");
}

#[test]
fn component_constant() {
    assert_eq!(COMPONENT, "tier_telemetry_contract");
}

// ---------------------------------------------------------------------------
// TelemetryTier enum
// ---------------------------------------------------------------------------

#[test]
fn telemetry_tier_all_count() {
    assert_eq!(TelemetryTier::ALL.len(), 5);
}

#[test]
fn telemetry_tier_as_key_exhaustive() {
    let expected = [
        (TelemetryTier::Interpreted, "interpreted"),
        (TelemetryTier::Baseline, "baseline"),
        (TelemetryTier::Optimized, "optimized"),
        (TelemetryTier::Specialized, "specialized"),
        (TelemetryTier::Deoptimized, "deoptimized"),
    ];
    for (variant, key) in &expected {
        assert_eq!(variant.as_key(), *key);
        assert_eq!(variant.to_string(), *key);
    }
}

#[test]
fn telemetry_tier_serde_roundtrip_all() {
    for tier in TelemetryTier::ALL {
        let json = serde_json::to_string(tier).unwrap();
        let back: TelemetryTier = serde_json::from_str(&json).unwrap();
        assert_eq!(*tier, back);
    }
}

#[test]
fn telemetry_tier_ordering() {
    assert!(TelemetryTier::Interpreted < TelemetryTier::Baseline);
    assert!(TelemetryTier::Baseline < TelemetryTier::Optimized);
    assert!(TelemetryTier::Optimized < TelemetryTier::Specialized);
}

// ---------------------------------------------------------------------------
// TelemetryEventKind enum
// ---------------------------------------------------------------------------

#[test]
fn telemetry_event_kind_display_exhaustive() {
    let expected = [
        (TelemetryEventKind::TierTransition, "tier_transition"),
        (TelemetryEventKind::DeoptOccurrence, "deopt_occurrence"),
        (TelemetryEventKind::ProbeUpdate, "probe_update"),
        (TelemetryEventKind::BenchmarkSample, "benchmark_sample"),
        (
            TelemetryEventKind::LatencyObservation,
            "latency_observation",
        ),
        (
            TelemetryEventKind::ThroughputObservation,
            "throughput_observation",
        ),
        (TelemetryEventKind::ErrorRate, "error_rate"),
        (TelemetryEventKind::CustomMetric, "custom_metric"),
    ];
    for (variant, s) in &expected {
        assert_eq!(variant.to_string(), *s);
    }
}

#[test]
fn telemetry_event_kind_serde_roundtrip() {
    let kinds = [
        TelemetryEventKind::TierTransition,
        TelemetryEventKind::DeoptOccurrence,
        TelemetryEventKind::ProbeUpdate,
        TelemetryEventKind::BenchmarkSample,
        TelemetryEventKind::LatencyObservation,
        TelemetryEventKind::ThroughputObservation,
        TelemetryEventKind::ErrorRate,
        TelemetryEventKind::CustomMetric,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: TelemetryEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// BenchmarkEvidenceKind enum
// ---------------------------------------------------------------------------

#[test]
fn benchmark_evidence_kind_display_exhaustive() {
    let expected = [
        (BenchmarkEvidenceKind::Throughput, "throughput"),
        (BenchmarkEvidenceKind::Latency, "latency"),
        (BenchmarkEvidenceKind::MemoryUsage, "memory_usage"),
        (BenchmarkEvidenceKind::CpuUtilization, "cpu_utilization"),
        (BenchmarkEvidenceKind::CacheHitRate, "cache_hit_rate"),
        (BenchmarkEvidenceKind::DeoptRate, "deopt_rate"),
        (BenchmarkEvidenceKind::TierDistribution, "tier_distribution"),
    ];
    for (variant, s) in &expected {
        assert_eq!(variant.to_string(), *s);
    }
}

#[test]
fn benchmark_evidence_kind_serde_roundtrip() {
    let kinds = [
        BenchmarkEvidenceKind::Throughput,
        BenchmarkEvidenceKind::Latency,
        BenchmarkEvidenceKind::MemoryUsage,
        BenchmarkEvidenceKind::CpuUtilization,
        BenchmarkEvidenceKind::CacheHitRate,
        BenchmarkEvidenceKind::DeoptRate,
        BenchmarkEvidenceKind::TierDistribution,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: BenchmarkEvidenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// DeltaClassification + classify_delta
// ---------------------------------------------------------------------------

#[test]
fn delta_classification_display() {
    assert_eq!(DeltaClassification::Regression.to_string(), "regression");
    assert_eq!(DeltaClassification::Improvement.to_string(), "improvement");
    assert_eq!(DeltaClassification::Neutral.to_string(), "neutral");
}

#[test]
fn classify_delta_regression() {
    assert_eq!(
        classify_delta(-200_000, 50_000),
        DeltaClassification::Regression
    );
}

#[test]
fn classify_delta_improvement() {
    assert_eq!(
        classify_delta(200_000, 50_000),
        DeltaClassification::Improvement
    );
}

#[test]
fn classify_delta_neutral() {
    assert_eq!(classify_delta(10_000, 50_000), DeltaClassification::Neutral);
}

#[test]
fn classify_delta_zero() {
    assert_eq!(classify_delta(0, 50_000), DeltaClassification::Neutral);
}

#[test]
fn classify_delta_exactly_at_negative_boundary() {
    // -threshold is neutral (not strictly less than)
    assert_eq!(
        classify_delta(-50_000, 50_000),
        DeltaClassification::Neutral
    );
}

#[test]
fn classify_delta_exactly_at_positive_boundary() {
    assert_eq!(classify_delta(50_000, 50_000), DeltaClassification::Neutral);
}

#[test]
fn classify_delta_just_past_negative_boundary() {
    assert_eq!(
        classify_delta(-50_001, 50_000),
        DeltaClassification::Regression
    );
}

#[test]
fn classify_delta_just_past_positive_boundary() {
    assert_eq!(
        classify_delta(50_001, 50_000),
        DeltaClassification::Improvement
    );
}

#[test]
fn classify_delta_zero_threshold() {
    // With zero threshold, positive is improvement, negative is regression
    assert_eq!(classify_delta(1, 0), DeltaClassification::Improvement);
    assert_eq!(classify_delta(-1, 0), DeltaClassification::Regression);
    assert_eq!(classify_delta(0, 0), DeltaClassification::Neutral);
}

// ---------------------------------------------------------------------------
// build_benchmark_sample
// ---------------------------------------------------------------------------

#[test]
fn benchmark_sample_improvement_fields() {
    let s = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Optimized,
        1_200_000,
        1_000_000,
        950_000,
    );
    assert_eq!(s.kind, BenchmarkEvidenceKind::Throughput);
    assert_eq!(s.tier, TelemetryTier::Optimized);
    assert_eq!(s.value_millionths, 1_200_000);
    assert_eq!(s.baseline_millionths, 1_000_000);
    assert_eq!(s.delta_millionths, 200_000);
    assert!(!s.is_regression);
    assert_eq!(s.confidence_millionths, 950_000);
    assert!(s.sample_id.starts_with("sample-"));
}

#[test]
fn benchmark_sample_regression_fields() {
    let s = build_benchmark_sample(
        BenchmarkEvidenceKind::Latency,
        TelemetryTier::Baseline,
        800_000,
        1_000_000,
        990_000,
    );
    assert!(s.is_regression);
    assert_eq!(s.delta_millionths, -200_000);
}

#[test]
fn benchmark_sample_zero_delta() {
    let s = build_benchmark_sample(
        BenchmarkEvidenceKind::CacheHitRate,
        TelemetryTier::Interpreted,
        1_000_000,
        1_000_000,
        950_000,
    );
    assert_eq!(s.delta_millionths, 0);
    assert!(!s.is_regression);
}

#[test]
fn benchmark_sample_content_hash_deterministic() {
    let a = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Optimized,
        1_000_000,
        900_000,
        950_000,
    );
    let b = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Optimized,
        1_000_000,
        900_000,
        950_000,
    );
    assert_eq!(a.content_hash, b.content_hash);
    assert_eq!(a.sample_id, b.sample_id);
}

#[test]
fn benchmark_sample_hash_differs_by_kind() {
    let a = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Optimized,
        1_000_000,
        900_000,
        950_000,
    );
    let b = build_benchmark_sample(
        BenchmarkEvidenceKind::Latency,
        TelemetryTier::Optimized,
        1_000_000,
        900_000,
        950_000,
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn benchmark_sample_hash_differs_by_tier() {
    let a = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Optimized,
        1_000_000,
        900_000,
        950_000,
    );
    let b = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Baseline,
        1_000_000,
        900_000,
        950_000,
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn benchmark_sample_display() {
    let s = sample_improvement(TelemetryTier::Optimized);
    let d = s.to_string();
    assert!(d.contains("BenchmarkSample("));
    assert!(d.contains("throughput"));
    assert!(d.contains("optimized"));
    assert!(d.contains("ok"));
}

#[test]
fn benchmark_sample_display_regression() {
    let s = sample_regression(TelemetryTier::Baseline);
    let d = s.to_string();
    assert!(d.contains("REGRESSION"));
}

#[test]
fn benchmark_sample_serde_roundtrip() {
    let s = sample_improvement(TelemetryTier::Specialized);
    let json = serde_json::to_string(&s).unwrap();
    let back: BenchmarkSample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn is_regression_function_true() {
    let s = sample_regression(TelemetryTier::Interpreted);
    assert!(is_regression(&s));
}

#[test]
fn is_regression_function_false() {
    let s = sample_improvement(TelemetryTier::Optimized);
    assert!(!is_regression(&s));
}

// ---------------------------------------------------------------------------
// build_evidence_bundle
// ---------------------------------------------------------------------------

#[test]
fn evidence_bundle_basic_aggregate() {
    let samples = vec![
        sample_improvement(TelemetryTier::Interpreted),
        sample_regression(TelemetryTier::Baseline),
        sample_neutral(TelemetryTier::Optimized),
    ];
    let e = epoch(5);
    let bundle = build_evidence_bundle(samples, &e);

    assert_eq!(bundle.total_samples, 3);
    assert_eq!(bundle.epoch, e);
    assert!(bundle.bundle_id.starts_with("bundle-"));
    // Tier distribution should have 3 entries
    assert_eq!(bundle.tier_distribution.len(), 3);
    assert_eq!(bundle.tier_distribution.get("interpreted"), Some(&1));
    assert_eq!(bundle.tier_distribution.get("baseline"), Some(&1));
    assert_eq!(bundle.tier_distribution.get("optimized"), Some(&1));
}

#[test]
fn evidence_bundle_empty() {
    let e = epoch(1);
    let bundle = build_evidence_bundle(Vec::new(), &e);
    assert_eq!(bundle.total_samples, 0);
    assert_eq!(bundle.regression_count, 0);
    assert_eq!(bundle.improvement_count, 0);
    assert_eq!(bundle.neutral_count, 0);
    assert_eq!(bundle.overall_delta_millionths, 0);
    assert!(bundle.tier_distribution.is_empty());
}

#[test]
fn evidence_bundle_all_regressions() {
    let samples = vec![
        sample_regression(TelemetryTier::Interpreted),
        sample_regression(TelemetryTier::Baseline),
    ];
    let bundle = build_evidence_bundle(samples, &epoch(1));
    assert_eq!(bundle.regression_count, 2);
    assert_eq!(bundle.improvement_count, 0);
    assert!(bundle.overall_delta_millionths < 0);
}

#[test]
fn evidence_bundle_content_hash_deterministic() {
    let mk = || {
        let s = vec![sample_improvement(TelemetryTier::Optimized)];
        build_evidence_bundle(s, &epoch(3))
    };
    assert_eq!(mk().content_hash, mk().content_hash);
}

#[test]
fn evidence_bundle_display() {
    let bundle = build_evidence_bundle(Vec::new(), &epoch(1));
    let d = bundle.to_string();
    assert!(d.contains("EvidenceBundle("));
    assert!(d.contains("samples=0"));
    assert!(d.contains("regressions=0"));
}

#[test]
fn evidence_bundle_serde_roundtrip() {
    let samples = vec![sample_improvement(TelemetryTier::Optimized)];
    let bundle = build_evidence_bundle(samples, &epoch(3));
    let json = serde_json::to_string(&bundle).unwrap();
    let back: BenchmarkEvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// ---------------------------------------------------------------------------
// regression_rate
// ---------------------------------------------------------------------------

#[test]
fn regression_rate_fifty_percent() {
    let samples = vec![
        sample_regression(TelemetryTier::Interpreted),
        sample_improvement(TelemetryTier::Baseline),
    ];
    let bundle = build_evidence_bundle(samples, &epoch(1));
    assert_eq!(regression_rate(&bundle), 500_000);
}

#[test]
fn regression_rate_zero() {
    let samples = vec![sample_improvement(TelemetryTier::Optimized)];
    let bundle = build_evidence_bundle(samples, &epoch(1));
    assert_eq!(regression_rate(&bundle), 0);
}

#[test]
fn regression_rate_hundred_percent() {
    let samples = vec![
        sample_regression(TelemetryTier::Interpreted),
        sample_regression(TelemetryTier::Baseline),
    ];
    let bundle = build_evidence_bundle(samples, &epoch(1));
    assert_eq!(regression_rate(&bundle), 1_000_000);
}

#[test]
fn regression_rate_empty_bundle() {
    let bundle = build_evidence_bundle(Vec::new(), &epoch(1));
    assert_eq!(regression_rate(&bundle), 0);
}

// ---------------------------------------------------------------------------
// PublicationContract
// ---------------------------------------------------------------------------

#[test]
fn publication_contract_defaults() {
    let c = PublicationContract::default_contract();
    assert_eq!(c.required_min_samples, 10);
    assert_eq!(c.required_confidence_millionths, 950_000);
    assert_eq!(c.max_regression_rate_millionths, 100_000);
    assert!(c.require_all_tiers_represented);
    assert_eq!(c.staleness_limit_epochs, 5);
    assert!(c.contract_id.contains("default"));
}

#[test]
fn publication_contract_display() {
    let c = PublicationContract::default_contract();
    let d = c.to_string();
    assert!(d.contains("PublicationContract"));
    assert!(d.contains("min_samples=10"));
    assert!(d.contains("max_reg_rate=100000"));
}

#[test]
fn publication_contract_serde_roundtrip() {
    let c = PublicationContract::default_contract();
    let json = serde_json::to_string(&c).unwrap();
    let back: PublicationContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// evaluate_publication
// ---------------------------------------------------------------------------

#[test]
fn evaluate_publication_publishable() {
    let e = epoch(3);
    let bundle = all_tier_bundle(&e);
    let contract = PublicationContract {
        contract_id: "test".to_string(),
        required_min_samples: 5,
        required_confidence_millionths: 900_000,
        max_regression_rate_millionths: 200_000,
        require_all_tiers_represented: true,
        staleness_limit_epochs: 10,
        content_hash: ContentHash::compute(b"test"),
    };
    let verdict = evaluate_publication(&bundle, &contract, &e);
    assert!(verdict.is_publishable);
    assert!(verdict.reasons.is_empty());
}

#[test]
fn evaluate_publication_insufficient_samples() {
    let e = epoch(1);
    let samples = vec![sample_improvement(TelemetryTier::Optimized)];
    let bundle = build_evidence_bundle(samples, &e);
    let contract = PublicationContract::default_contract();
    let verdict = evaluate_publication(&bundle, &contract, &e);
    assert!(!verdict.is_publishable);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| r.contains("insufficient samples"))
    );
}

#[test]
fn evaluate_publication_low_confidence() {
    let e = epoch(1);
    // Build a sample with low confidence
    let low_conf_sample = build_benchmark_sample(
        BenchmarkEvidenceKind::Throughput,
        TelemetryTier::Optimized,
        1_100_000,
        1_000_000,
        100_000, // very low confidence
    );
    let bundle = build_evidence_bundle(vec![low_conf_sample], &e);
    let contract = PublicationContract {
        contract_id: "strict-conf".to_string(),
        required_min_samples: 1,
        required_confidence_millionths: 950_000,
        max_regression_rate_millionths: 1_000_000,
        require_all_tiers_represented: false,
        staleness_limit_epochs: 100,
        content_hash: ContentHash::compute(b"strict-conf"),
    };
    let verdict = evaluate_publication(&bundle, &contract, &e);
    assert!(!verdict.is_publishable);
    assert!(verdict.reasons.iter().any(|r| r.contains("confidence")));
}

#[test]
fn evaluate_publication_regression_rate_exceeded() {
    let e = epoch(1);
    // All regression samples
    let samples = vec![
        sample_regression(TelemetryTier::Interpreted),
        sample_regression(TelemetryTier::Baseline),
        sample_regression(TelemetryTier::Optimized),
    ];
    let bundle = build_evidence_bundle(samples, &e);
    let contract = PublicationContract {
        contract_id: "strict-reg".to_string(),
        required_min_samples: 1,
        required_confidence_millionths: 0,
        max_regression_rate_millionths: 100_000, // 10% max
        require_all_tiers_represented: false,
        staleness_limit_epochs: 100,
        content_hash: ContentHash::compute(b"strict-reg"),
    };
    let verdict = evaluate_publication(&bundle, &contract, &e);
    assert!(!verdict.is_publishable);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| r.contains("regression rate"))
    );
}

#[test]
fn evaluate_publication_missing_tiers() {
    let e = epoch(1);
    // Only one tier represented
    let samples = vec![sample_improvement(TelemetryTier::Optimized)];
    let bundle = build_evidence_bundle(samples, &e);
    let contract = PublicationContract {
        contract_id: "all-tiers".to_string(),
        required_min_samples: 1,
        required_confidence_millionths: 0,
        max_regression_rate_millionths: 1_000_000,
        require_all_tiers_represented: true,
        staleness_limit_epochs: 100,
        content_hash: ContentHash::compute(b"all-tiers"),
    };
    let verdict = evaluate_publication(&bundle, &contract, &e);
    assert!(!verdict.is_publishable);
    assert!(verdict.reasons.iter().any(|r| r.contains("missing tier")));
}

#[test]
fn evaluate_publication_stale_data() {
    let bundle_epoch = epoch(1);
    let current_epoch = epoch(20);
    let samples = vec![sample_improvement(TelemetryTier::Optimized)];
    let bundle = build_evidence_bundle(samples, &bundle_epoch);
    let contract = PublicationContract {
        contract_id: "fresh".to_string(),
        required_min_samples: 1,
        required_confidence_millionths: 0,
        max_regression_rate_millionths: 1_000_000,
        require_all_tiers_represented: false,
        staleness_limit_epochs: 3,
        content_hash: ContentHash::compute(b"fresh"),
    };
    let verdict = evaluate_publication(&bundle, &contract, &current_epoch);
    assert!(!verdict.is_publishable);
    assert!(verdict.reasons.iter().any(|r| r.contains("stale data")));
}

#[test]
fn evaluate_publication_same_epoch_not_stale() {
    let e = epoch(5);
    let bundle = all_tier_bundle(&e);
    let contract = PublicationContract {
        contract_id: "same-epoch".to_string(),
        required_min_samples: 5,
        required_confidence_millionths: 900_000,
        max_regression_rate_millionths: 200_000,
        require_all_tiers_represented: true,
        staleness_limit_epochs: 0, // even zero works if same epoch
        content_hash: ContentHash::compute(b"same-epoch"),
    };
    let verdict = evaluate_publication(&bundle, &contract, &e);
    // Should not be stale since bundle_epoch == current_epoch
    let stale_reasons: Vec<_> = verdict
        .reasons
        .iter()
        .filter(|r| r.contains("stale"))
        .collect();
    assert!(stale_reasons.is_empty());
}

#[test]
fn evaluate_publication_verdict_content_hash_deterministic() {
    let e = epoch(1);
    let contract = permissive_contract();
    let mk = || {
        let bundle = build_evidence_bundle(vec![sample_improvement(TelemetryTier::Optimized)], &e);
        evaluate_publication(&bundle, &contract, &e)
    };
    assert_eq!(mk().content_hash, mk().content_hash);
}

#[test]
fn evaluate_publication_verdict_display() {
    let e = epoch(1);
    let bundle = build_evidence_bundle(vec![sample_improvement(TelemetryTier::Optimized)], &e);
    let verdict = evaluate_publication(&bundle, &permissive_contract(), &e);
    let d = verdict.to_string();
    assert!(d.contains("PublicationVerdict("));
    assert!(d.contains("PUBLISHABLE") || d.contains("NOT_PUBLISHABLE"));
}

#[test]
fn evaluate_publication_verdict_serde_roundtrip() {
    let e = epoch(1);
    let bundle = build_evidence_bundle(vec![sample_improvement(TelemetryTier::Optimized)], &e);
    let verdict = evaluate_publication(&bundle, &permissive_contract(), &e);
    let json = serde_json::to_string(&verdict).unwrap();
    let back: PublicationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict, back);
}

// ---------------------------------------------------------------------------
// build_telemetry_event
// ---------------------------------------------------------------------------

#[test]
fn telemetry_event_fields() {
    let mut labels = BTreeMap::new();
    labels.insert("module".to_string(), "test_mod".to_string());

    let event = build_telemetry_event(
        TelemetryEventKind::BenchmarkSample,
        TelemetryTier::Specialized,
        42_000,
        1_500_000,
        labels.clone(),
    );
    assert_eq!(event.kind, TelemetryEventKind::BenchmarkSample);
    assert_eq!(event.tier, TelemetryTier::Specialized);
    assert_eq!(event.timestamp_nanos, 42_000);
    assert_eq!(event.value_millionths, 1_500_000);
    assert_eq!(event.labels, labels);
    assert!(event.event_id.starts_with("event-"));
}

#[test]
fn telemetry_event_content_hash_deterministic() {
    let mk = || {
        build_telemetry_event(
            TelemetryEventKind::TierTransition,
            TelemetryTier::Interpreted,
            100,
            500_000,
            BTreeMap::new(),
        )
    };
    assert_eq!(mk().content_hash, mk().content_hash);
}

#[test]
fn telemetry_event_hash_differs_by_kind() {
    let a = build_telemetry_event(
        TelemetryEventKind::TierTransition,
        TelemetryTier::Interpreted,
        100,
        500_000,
        BTreeMap::new(),
    );
    let b = build_telemetry_event(
        TelemetryEventKind::ProbeUpdate,
        TelemetryTier::Interpreted,
        100,
        500_000,
        BTreeMap::new(),
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn telemetry_event_display() {
    let event = build_telemetry_event(
        TelemetryEventKind::LatencyObservation,
        TelemetryTier::Baseline,
        1000,
        2_000_000,
        BTreeMap::new(),
    );
    let d = event.to_string();
    assert!(d.contains("TelemetryEvent("));
    assert!(d.contains("latency_observation"));
    assert!(d.contains("baseline"));
}

#[test]
fn telemetry_event_serde_roundtrip() {
    let event = build_telemetry_event(
        TelemetryEventKind::ErrorRate,
        TelemetryTier::Deoptimized,
        9999,
        -100_000,
        BTreeMap::new(),
    );
    let json = serde_json::to_string(&event).unwrap();
    let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// compute_tier_distribution
// ---------------------------------------------------------------------------

#[test]
fn tier_distribution_basic() {
    let events = vec![
        build_telemetry_event(
            TelemetryEventKind::TierTransition,
            TelemetryTier::Interpreted,
            100,
            1_000_000,
            BTreeMap::new(),
        ),
        build_telemetry_event(
            TelemetryEventKind::TierTransition,
            TelemetryTier::Interpreted,
            200,
            1_000_000,
            BTreeMap::new(),
        ),
        build_telemetry_event(
            TelemetryEventKind::ProbeUpdate,
            TelemetryTier::Optimized,
            300,
            500_000,
            BTreeMap::new(),
        ),
    ];
    let snap = compute_tier_distribution(&events, &epoch(1));
    assert_eq!(snap.total_functions, 3);
    assert_eq!(snap.dominant_tier, "interpreted");
    assert_eq!(snap.distribution.get("interpreted"), Some(&2));
    assert_eq!(snap.distribution.get("optimized"), Some(&1));
    // 2/3 = 666_666
    assert_eq!(snap.dominance_ratio_millionths, 666_666);
}

#[test]
fn tier_distribution_empty() {
    let snap = compute_tier_distribution(&[], &epoch(1));
    assert_eq!(snap.total_functions, 0);
    assert_eq!(snap.dominant_tier, "none");
    assert_eq!(snap.dominance_ratio_millionths, 0);
    assert!(snap.distribution.is_empty());
}

#[test]
fn tier_distribution_single_tier() {
    let events = vec![build_telemetry_event(
        TelemetryEventKind::TierTransition,
        TelemetryTier::Specialized,
        100,
        1_000_000,
        BTreeMap::new(),
    )];
    let snap = compute_tier_distribution(&events, &epoch(1));
    assert_eq!(snap.total_functions, 1);
    assert_eq!(snap.dominant_tier, "specialized");
    assert_eq!(snap.dominance_ratio_millionths, 1_000_000);
}

#[test]
fn tier_distribution_content_hash_deterministic() {
    let events = vec![build_telemetry_event(
        TelemetryEventKind::TierTransition,
        TelemetryTier::Baseline,
        100,
        1_000_000,
        BTreeMap::new(),
    )];
    let a = compute_tier_distribution(&events, &epoch(1));
    let b = compute_tier_distribution(&events, &epoch(1));
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn tier_distribution_display() {
    let events = vec![build_telemetry_event(
        TelemetryEventKind::TierTransition,
        TelemetryTier::Optimized,
        100,
        1_000_000,
        BTreeMap::new(),
    )];
    let snap = compute_tier_distribution(&events, &epoch(1));
    let d = snap.to_string();
    assert!(d.contains("TierDistribution("));
    assert!(d.contains("total=1"));
    assert!(d.contains("dominant=optimized"));
}

#[test]
fn tier_distribution_serde_roundtrip() {
    let events = vec![build_telemetry_event(
        TelemetryEventKind::DeoptOccurrence,
        TelemetryTier::Deoptimized,
        500,
        -500_000,
        BTreeMap::new(),
    )];
    let snap = compute_tier_distribution(&events, &epoch(2));
    let json = serde_json::to_string(&snap).unwrap();
    let back: TierDistributionSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, back);
}

// ---------------------------------------------------------------------------
// build_telemetry_report
// ---------------------------------------------------------------------------

#[test]
fn telemetry_report_empty() {
    let e = epoch(5);
    let report = build_telemetry_report(Vec::new(), Vec::new(), Vec::new(), None, &e);
    assert_eq!(report.total_events, 0);
    assert_eq!(report.epoch, e);
    assert!(report.report_id.starts_with("report-"));
    assert!(report.events.is_empty());
    assert!(report.bundles.is_empty());
    assert!(report.verdicts.is_empty());
    assert!(report.distribution_snapshot.is_none());
}

#[test]
fn telemetry_report_with_events_and_snapshot() {
    let e = epoch(2);
    let events = vec![build_telemetry_event(
        TelemetryEventKind::TierTransition,
        TelemetryTier::Interpreted,
        100,
        1_000_000,
        BTreeMap::new(),
    )];
    let snapshot = compute_tier_distribution(&events, &e);
    let report = build_telemetry_report(events, Vec::new(), Vec::new(), Some(snapshot.clone()), &e);
    assert_eq!(report.total_events, 1);
    assert_eq!(report.distribution_snapshot, Some(snapshot));
}

#[test]
fn telemetry_report_content_hash_deterministic() {
    let e = epoch(1);
    let mk = || build_telemetry_report(Vec::new(), Vec::new(), Vec::new(), None, &e);
    assert_eq!(mk().content_hash, mk().content_hash);
}

#[test]
fn telemetry_report_display() {
    let report = build_telemetry_report(Vec::new(), Vec::new(), Vec::new(), None, &epoch(1));
    let d = report.to_string();
    assert!(d.contains("TelemetryReport("));
    assert!(d.contains("events=0"));
    assert!(d.contains("bundles=0"));
    assert!(d.contains("verdicts=0"));
}

#[test]
fn telemetry_report_serde_roundtrip() {
    let e = epoch(7);
    let report = build_telemetry_report(Vec::new(), Vec::new(), Vec::new(), None, &e);
    let json = serde_json::to_string(&report).unwrap();
    let back: TelemetryReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn manifest_structure() {
    let m = franken_engine_tier_telemetry_manifest();
    assert_eq!(m.epoch, epoch(0));
    assert_eq!(m.total_events, 0);
    assert!(m.events.is_empty());
    assert!(m.bundles.is_empty());
    assert!(m.verdicts.is_empty());
    assert!(m.distribution_snapshot.is_none());
}

#[test]
fn manifest_deterministic() {
    assert_eq!(
        franken_engine_tier_telemetry_manifest().content_hash,
        franken_engine_tier_telemetry_manifest().content_hash
    );
}

// ---------------------------------------------------------------------------
// End-to-end workflows
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_collect_events_bundle_evaluate() {
    let e = epoch(10);

    // Collect telemetry events for each tier
    let events: Vec<TelemetryEvent> = TelemetryTier::ALL
        .iter()
        .enumerate()
        .map(|(i, tier)| {
            build_telemetry_event(
                TelemetryEventKind::TierTransition,
                *tier,
                (i as u64 + 1) * 1000,
                1_000_000,
                BTreeMap::new(),
            )
        })
        .collect();

    // Compute distribution
    let snapshot = compute_tier_distribution(&events, &e);
    assert_eq!(snapshot.total_functions, 5);

    // Build samples for each tier
    let samples: Vec<BenchmarkSample> = TelemetryTier::ALL
        .iter()
        .map(|tier| sample_improvement(*tier))
        .collect();

    // Build bundle
    let bundle = build_evidence_bundle(samples, &e);
    assert_eq!(bundle.total_samples, 5);
    assert_eq!(bundle.tier_distribution.len(), 5);

    // Evaluate with a permissive contract
    let contract = PublicationContract {
        contract_id: "e2e-contract".to_string(),
        required_min_samples: 5,
        required_confidence_millionths: 900_000,
        max_regression_rate_millionths: 200_000,
        require_all_tiers_represented: true,
        staleness_limit_epochs: 10,
        content_hash: ContentHash::compute(b"e2e"),
    };
    let verdict = evaluate_publication(&bundle, &contract, &e);
    assert!(verdict.is_publishable);

    // Build report
    let report = build_telemetry_report(events, vec![bundle], vec![verdict], Some(snapshot), &e);
    assert_eq!(report.total_events, 5);
    assert_eq!(report.bundles.len(), 1);
    assert_eq!(report.verdicts.len(), 1);
    assert!(report.distribution_snapshot.is_some());
}

#[test]
fn end_to_end_multiple_failures_accumulated() {
    let e = epoch(1);

    // Low confidence, regression, only one tier
    let low_conf_regression = build_benchmark_sample(
        BenchmarkEvidenceKind::Latency,
        TelemetryTier::Interpreted,
        500_000,
        1_000_000,
        100_000, // low confidence
    );

    let bundle = build_evidence_bundle(vec![low_conf_regression], &e);
    let contract = PublicationContract::default_contract();
    let stale_epoch = epoch(100);
    let verdict = evaluate_publication(&bundle, &contract, &stale_epoch);

    assert!(!verdict.is_publishable);
    // Should have multiple reasons: insufficient samples, low confidence,
    // high regression rate, missing tiers, stale data
    assert!(verdict.reasons.len() >= 4);
}
