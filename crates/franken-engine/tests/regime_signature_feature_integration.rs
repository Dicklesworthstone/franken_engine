#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::regime_detector::Regime;
use frankenengine_engine::regime_signature_feature::{
    ABSTENTION_THRESHOLD_MILLIONTHS, MAX_SIGNATURE_DIM, MIN_TRACE_LENGTH, REGIME_SIG_COMPONENT,
    REGIME_SIG_EVENT_SCHEMA_VERSION, REGIME_SIG_MANIFEST_SCHEMA_VERSION, REGIME_SIG_POLICY_ID,
    REGIME_SIG_SCHEMA_VERSION, RegimeLabel, RegimeStateChart, RegimeStateEntry, RuntimeTrace,
    SignatureConfig, SignatureEvidenceInventory, SignatureExpectedOutcome, SignatureSpecimen,
    SignatureSpecimenFamily, SignatureVerdict, TraceObservation, TraceSignature,
    build_regime_state_chart, classify_regime, extract_signature, run_signature_corpus,
    signature_corpus, write_signature_evidence_bundle,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_trace(id: &str, feature: &str, values: &[i64], epoch: u64) -> RuntimeTrace {
    RuntimeTrace {
        trace_id: id.to_string(),
        observations: values
            .iter()
            .enumerate()
            .map(|(i, &v)| TraceObservation {
                seq: i as u64,
                feature_name: feature.to_string(),
                value_millionths: v,
            })
            .collect(),
        epoch: SecurityEpoch::from_raw(epoch),
    }
}

fn make_multi_feature_trace(id: &str, features: &[(&str, &[i64])], epoch: u64) -> RuntimeTrace {
    let mut observations = Vec::new();
    let mut seq = 0u64;
    for (feature, values) in features {
        for &v in *values {
            observations.push(TraceObservation {
                seq,
                feature_name: feature.to_string(),
                value_millionths: v,
            });
            seq += 1;
        }
    }
    RuntimeTrace {
        trace_id: id.to_string(),
        observations,
        epoch: SecurityEpoch::from_raw(epoch),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_constants_non_empty() {
    assert!(!REGIME_SIG_SCHEMA_VERSION.is_empty());
    assert!(!REGIME_SIG_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!REGIME_SIG_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!REGIME_SIG_COMPONENT.is_empty());
    assert!(!REGIME_SIG_POLICY_ID.is_empty());
}

#[test]
fn schema_constants_have_correct_prefix() {
    assert!(REGIME_SIG_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(REGIME_SIG_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(REGIME_SIG_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn schema_constants_are_distinct() {
    let versions = [
        REGIME_SIG_SCHEMA_VERSION,
        REGIME_SIG_MANIFEST_SCHEMA_VERSION,
        REGIME_SIG_EVENT_SCHEMA_VERSION,
        REGIME_SIG_POLICY_ID,
    ];
    let set: BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(set.len(), versions.len());
}

#[test]
fn max_signature_dim_is_power_of_two() {
    assert!(MAX_SIGNATURE_DIM.is_power_of_two());
}

#[test]
fn min_trace_length_positive() {
    const { assert!(MIN_TRACE_LENGTH > 0) };
}

#[test]
fn abstention_threshold_in_valid_range() {
    const { assert!(ABSTENTION_THRESHOLD_MILLIONTHS > 0) };
    const { assert!(ABSTENTION_THRESHOLD_MILLIONTHS < 1_000_000) };
}

// ---------------------------------------------------------------------------
// TraceObservation / RuntimeTrace
// ---------------------------------------------------------------------------

#[test]
fn trace_observation_serde_roundtrip() {
    let obs = TraceObservation {
        seq: 42,
        feature_name: "cpu_usage".to_string(),
        value_millionths: 750_000,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: TraceObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn runtime_trace_serde_roundtrip() {
    let trace = make_trace("t1", "metric", &[100_000, 200_000, 300_000, 400_000], 1);
    let json = serde_json::to_string(&trace).unwrap();
    let back: RuntimeTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, back);
}

#[test]
fn runtime_trace_ordering_preserved() {
    let trace = make_trace("t", "m", &[10, 20, 30, 40, 50], 1);
    for (i, obs) in trace.observations.iter().enumerate() {
        assert_eq!(obs.seq, i as u64);
    }
}

// ---------------------------------------------------------------------------
// Signature extraction
// ---------------------------------------------------------------------------

#[test]
fn extract_valid_signature_from_sufficient_data() {
    let config = SignatureConfig::default();
    let trace = make_trace("t1", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.dimension, MAX_SIGNATURE_DIM);
    assert_eq!(sig.components.len(), MAX_SIGNATURE_DIM);
    assert_eq!(sig.bucket_counts.len(), MAX_SIGNATURE_DIM);
    assert_eq!(sig.observation_count, 4);
    assert!(!sig.signature_hash.is_empty());
}

#[test]
fn extract_invalid_signature_from_short_trace() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-short", "cpu", &[500_000], 1);
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
    assert_eq!(sig.observation_count, 1);
}

#[test]
fn extract_invalid_from_empty_trace() {
    let config = SignatureConfig::default();
    let trace = RuntimeTrace {
        trace_id: "empty".to_string(),
        observations: vec![],
        epoch: SecurityEpoch::from_raw(1),
    };
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
    assert_eq!(sig.observation_count, 0);
    assert_eq!(sig.feature_count, 0);
}

#[test]
fn extract_invalid_from_three_observations() {
    let config = SignatureConfig::default();
    let trace = make_trace("t3", "x", &[100, 200, 300], 1);
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
    assert_eq!(sig.observation_count, 3);
}

#[test]
fn extract_valid_from_exactly_min_length() {
    let config = SignatureConfig::default();
    let values: Vec<i64> = (0..MIN_TRACE_LENGTH as i64).map(|i| i * 100_000).collect();
    let trace = make_trace("t-min", "metric", &values, 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.observation_count, MIN_TRACE_LENGTH as u64);
}

#[test]
fn extract_from_multi_feature_trace() {
    let config = SignatureConfig::default();
    let trace = make_multi_feature_trace(
        "t-multi",
        &[
            ("cpu", &[500_000, 600_000]),
            ("mem", &[300_000, 400_000]),
            ("cache", &[900_000, 800_000]),
        ],
        1,
    );
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.observation_count, 6);
    assert!(sig.feature_count >= 1); // At least 1 feature mapped
}

#[test]
fn extract_from_large_trace() {
    let config = SignatureConfig::default();
    let values: Vec<i64> = (0..200).map(|i| 400_000 + (i % 10) * 20_000).collect();
    let trace = make_trace("t-large", "throughput", &values, 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.observation_count, 200);
}

#[test]
fn extract_deterministic() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-det", "cpu", &[500_000, 600_000, 700_000, 800_000], 1);
    let sig1 = extract_signature(&trace, &config);
    let sig2 = extract_signature(&trace, &config);
    assert_eq!(sig1, sig2);
}

#[test]
fn extract_signature_hash_is_64_hex() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-hash", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
    let sig = extract_signature(&trace, &config);
    assert_eq!(sig.signature_hash.len(), 64);
    assert!(sig.signature_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn extract_preserves_trace_id() {
    let config = SignatureConfig::default();
    let trace = make_trace("unique-id-42", "m", &[1, 2, 3, 4], 1);
    let sig = extract_signature(&trace, &config);
    assert_eq!(sig.trace_id, "unique-id-42");
}

// ---------------------------------------------------------------------------
// TraceSignature methods
// ---------------------------------------------------------------------------

#[test]
fn l1_distance_self_is_zero() {
    let config = SignatureConfig::default();
    let trace = make_trace("t", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
    let sig = extract_signature(&trace, &config);
    assert_eq!(sig.l1_distance(&sig), 0);
}

#[test]
fn l1_distance_symmetric() {
    let config = SignatureConfig::default();
    let t1 = make_trace("t1", "cpu", &[100_000, 200_000, 300_000, 400_000], 1);
    let t2 = make_trace("t2", "cpu", &[900_000, 800_000, 700_000, 600_000], 1);
    let s1 = extract_signature(&t1, &config);
    let s2 = extract_signature(&t2, &config);
    assert_eq!(s1.l1_distance(&s2), s2.l1_distance(&s1));
}

#[test]
fn l1_distance_different_traces_nonzero() {
    let config = SignatureConfig::default();
    let t1 = make_trace("t1", "cpu", &[100_000, 100_000, 100_000, 100_000], 1);
    let t2 = make_trace("t2", "cpu", &[900_000, 900_000, 900_000, 900_000], 1);
    let s1 = extract_signature(&t1, &config);
    let s2 = extract_signature(&t2, &config);
    assert!(s1.l1_distance(&s2) > 0);
}

#[test]
fn l1_distance_different_dimensions_returns_max() {
    let s1 = TraceSignature {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        trace_id: "a".to_string(),
        dimension: 4,
        components: vec![1, 2, 3, 4],
        bucket_counts: vec![1, 1, 1, 1],
        observation_count: 4,
        feature_count: 1,
        valid: true,
        signature_hash: "abc".to_string(),
    };
    let s2 = TraceSignature {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        trace_id: "b".to_string(),
        dimension: 8,
        components: vec![1, 2, 3, 4, 5, 6, 7, 8],
        bucket_counts: vec![1; 8],
        observation_count: 8,
        feature_count: 1,
        valid: true,
        signature_hash: "def".to_string(),
    };
    assert_eq!(s1.l1_distance(&s2), i64::MAX);
}

#[test]
fn cosine_similarity_identical_near_one_million() {
    let config = SignatureConfig::default();
    let trace = make_trace("t", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
    let sig = extract_signature(&trace, &config);
    let cos = sig.cosine_similarity(&sig);
    assert!(cos > 900_000, "cosine {cos} too low for identical");
}

#[test]
fn cosine_similarity_different_dims_returns_zero() {
    let s1 = TraceSignature {
        schema_version: "v1".to_string(),
        trace_id: "a".to_string(),
        dimension: 4,
        components: vec![1, 2, 3, 4],
        bucket_counts: vec![1; 4],
        observation_count: 4,
        feature_count: 1,
        valid: true,
        signature_hash: "x".to_string(),
    };
    let s2 = TraceSignature {
        schema_version: "v1".to_string(),
        trace_id: "b".to_string(),
        dimension: 8,
        components: vec![1; 8],
        bucket_counts: vec![1; 8],
        observation_count: 8,
        feature_count: 1,
        valid: true,
        signature_hash: "y".to_string(),
    };
    assert_eq!(s1.cosine_similarity(&s2), 0);
}

#[test]
fn cosine_similarity_zero_vector_returns_zero() {
    let sig = TraceSignature {
        schema_version: "v1".to_string(),
        trace_id: "z".to_string(),
        dimension: 4,
        components: vec![0, 0, 0, 0],
        bucket_counts: vec![0; 4],
        observation_count: 0,
        feature_count: 0,
        valid: false,
        signature_hash: "z".to_string(),
    };
    assert_eq!(sig.cosine_similarity(&sig), 0);
}

#[test]
fn trace_signature_serde_roundtrip() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-serde", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
    let sig = extract_signature(&trace, &config);
    let json = serde_json::to_string(&sig).unwrap();
    let back: TraceSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig, back);
}

// ---------------------------------------------------------------------------
// Regime classification
// ---------------------------------------------------------------------------

#[test]
fn classify_normal_regime() {
    // Use run_signature_corpus to verify the public runner produces passing results.
    let inv = run_signature_corpus();
    let normal_specimen = inv
        .evidence
        .iter()
        .find(|e| e.specimen_id == "classify_normal_trace");
    if let Some(ev) = normal_specimen {
        assert_eq!(
            ev.verdict,
            SignatureVerdict::Pass,
            "classify_normal_trace failed via corpus: {:?}",
            ev.error_detail
        );
    }
}

#[test]
fn classify_invalid_gives_abstention() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-inv", "cpu", &[500_000], 1);
    let sig = extract_signature(&trace, &config);
    let (label, _) = classify_regime(&sig, &config);
    assert!(label.is_abstention());
}

#[test]
fn classify_valid_trace_returns_result() {
    let config = SignatureConfig::default();
    let trace = make_multi_feature_trace(
        "t-conf",
        &[
            ("cpu", &[500_000, 500_000, 500_000, 500_000]),
            ("mem", &[500_000, 500_000, 500_000, 500_000]),
        ],
        1,
    );
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    // Classification produces *some* result (label + confidence pair).
    let (label, conf) = classify_regime(&sig, &config);
    // Confidence is always non-negative.
    assert!(conf >= 0);
    // If classified, label has a string representation.
    assert!(!label.as_str().is_empty());
}

// ---------------------------------------------------------------------------
// RegimeLabel
// ---------------------------------------------------------------------------

#[test]
fn regime_label_classified_variants() {
    for regime in [
        Regime::Normal,
        Regime::Elevated,
        Regime::Attack,
        Regime::Degraded,
        Regime::Recovery,
    ] {
        let label = RegimeLabel::Classified(regime);
        assert!(!label.is_abstention());
        assert!(!label.as_str().is_empty());
    }
}

#[test]
fn regime_label_abstention() {
    let label = RegimeLabel::Abstention;
    assert!(label.is_abstention());
    assert_eq!(label.as_str(), "abstention");
    assert_eq!(format!("{label}"), "abstention");
}

#[test]
fn regime_label_serde_roundtrip_all() {
    let labels = vec![
        RegimeLabel::Classified(Regime::Normal),
        RegimeLabel::Classified(Regime::Elevated),
        RegimeLabel::Classified(Regime::Attack),
        RegimeLabel::Classified(Regime::Degraded),
        RegimeLabel::Classified(Regime::Recovery),
        RegimeLabel::Abstention,
    ];
    for l in &labels {
        let json = serde_json::to_string(l).unwrap();
        let back: RegimeLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(*l, back);
    }
}

#[test]
fn regime_label_all_classified_count() {
    assert_eq!(RegimeLabel::ALL_CLASSIFIED.len(), 5);
}

#[test]
fn regime_label_display_matches_as_str() {
    for label in RegimeLabel::ALL_CLASSIFIED {
        assert_eq!(format!("{label}"), label.as_str());
    }
    let abs = RegimeLabel::Abstention;
    assert_eq!(format!("{abs}"), abs.as_str());
}

// ---------------------------------------------------------------------------
// RegimeStateChart
// ---------------------------------------------------------------------------

#[test]
fn state_chart_single_trace_no_transitions() {
    let config = SignatureConfig::default();
    let traces = vec![make_multi_feature_trace(
        "t",
        &[("cpu", &[500_000, 510_000, 490_000, 500_000])],
        1,
    )];
    let chart = build_regime_state_chart(&traces, &config);
    assert_eq!(chart.transition_count, 0);
    assert_eq!(chart.entries.len(), 1);
}

#[test]
fn state_chart_two_similar_traces_stable() {
    let config = SignatureConfig::default();
    let traces = vec![
        make_multi_feature_trace("t1", &[("cpu", &[500_000, 510_000, 490_000, 500_000])], 1),
        make_multi_feature_trace("t2", &[("cpu", &[505_000, 515_000, 485_000, 500_000])], 2),
    ];
    let chart = build_regime_state_chart(&traces, &config);
    assert_eq!(chart.entries.len(), 2);
    // Both should classify to same regime → 0 transitions
    assert_eq!(chart.transition_count, 0);
}

#[test]
fn state_chart_empty_traces() {
    let config = SignatureConfig::default();
    let chart = build_regime_state_chart(&[], &config);
    assert_eq!(chart.entries.len(), 0);
    assert_eq!(chart.transition_count, 0);
    assert!(!chart.chart_hash.is_empty());
}

#[test]
fn state_chart_is_stable_no_transitions_no_abstentions() {
    let chart = RegimeStateChart {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        entries: vec![RegimeStateEntry {
            seq: 0,
            label: RegimeLabel::Classified(Regime::Normal),
            confidence_millionths: 800_000,
            centroid_distance_millionths: 100_000,
            trace_id: "t".to_string(),
        }],
        transition_count: 0,
        abstention_count: 0,
        label_distribution: BTreeMap::new(),
        chart_hash: "h".to_string(),
    };
    assert!(chart.is_stable());
}

#[test]
fn state_chart_not_stable_with_transitions() {
    let chart = RegimeStateChart {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        entries: vec![],
        transition_count: 1,
        abstention_count: 0,
        label_distribution: BTreeMap::new(),
        chart_hash: "h".to_string(),
    };
    assert!(!chart.is_stable());
}

#[test]
fn state_chart_not_stable_with_abstentions() {
    let chart = RegimeStateChart {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        entries: vec![RegimeStateEntry {
            seq: 0,
            label: RegimeLabel::Abstention,
            confidence_millionths: 0,
            centroid_distance_millionths: 0,
            trace_id: "t".to_string(),
        }],
        transition_count: 0,
        abstention_count: 1,
        label_distribution: BTreeMap::new(),
        chart_hash: "h".to_string(),
    };
    assert!(!chart.is_stable());
}

#[test]
fn state_chart_not_stable_when_empty() {
    let chart = RegimeStateChart {
        schema_version: "v1".to_string(),
        entries: vec![],
        transition_count: 0,
        abstention_count: 0,
        label_distribution: BTreeMap::new(),
        chart_hash: "h".to_string(),
    };
    assert!(!chart.is_stable());
}

#[test]
fn state_chart_serde_roundtrip() {
    let chart = RegimeStateChart {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        entries: vec![RegimeStateEntry {
            seq: 0,
            label: RegimeLabel::Classified(Regime::Normal),
            confidence_millionths: 700_000,
            centroid_distance_millionths: 200_000,
            trace_id: "t-serde".to_string(),
        }],
        transition_count: 0,
        abstention_count: 0,
        label_distribution: {
            let mut m = BTreeMap::new();
            m.insert("normal".to_string(), 1);
            m
        },
        chart_hash: "abc123".to_string(),
    };
    let json = serde_json::to_string(&chart).unwrap();
    let back: RegimeStateChart = serde_json::from_str(&json).unwrap();
    assert_eq!(chart, back);
}

#[test]
fn state_chart_label_distribution_sums() {
    let config = SignatureConfig::default();
    let traces = vec![
        make_multi_feature_trace("a", &[("x", &[500_000, 500_000, 500_000, 500_000])], 1),
        make_multi_feature_trace("b", &[("x", &[500_000, 500_000, 500_000, 500_000])], 2),
        make_multi_feature_trace("c", &[("x", &[500_000, 500_000, 500_000, 500_000])], 3),
    ];
    let chart = build_regime_state_chart(&traces, &config);
    let total: u64 = chart.label_distribution.values().sum();
    assert_eq!(total, chart.entries.len() as u64);
}

#[test]
fn state_chart_hash_deterministic() {
    let config = SignatureConfig::default();
    let traces = vec![make_multi_feature_trace(
        "t",
        &[("cpu", &[500_000, 510_000, 490_000, 500_000])],
        1,
    )];
    let c1 = build_regime_state_chart(&traces, &config);
    let c2 = build_regime_state_chart(&traces, &config);
    assert_eq!(c1.chart_hash, c2.chart_hash);
}

// ---------------------------------------------------------------------------
// SignatureConfig
// ---------------------------------------------------------------------------

#[test]
fn signature_config_default_has_centroids() {
    let config = SignatureConfig::default();
    assert_eq!(config.max_dim, MAX_SIGNATURE_DIM);
    assert_eq!(config.min_trace_length, MIN_TRACE_LENGTH);
    assert_eq!(config.abstention_threshold, ABSTENTION_THRESHOLD_MILLIONTHS);
    assert!(!config.centroids.is_empty());
}

#[test]
fn signature_config_centroids_cover_all_regimes() {
    let config = SignatureConfig::default();
    let regimes: BTreeSet<Regime> = config.centroids.iter().map(|c| c.regime).collect();
    for regime in [
        Regime::Normal,
        Regime::Elevated,
        Regime::Attack,
        Regime::Degraded,
        Regime::Recovery,
    ] {
        assert!(
            regimes.contains(&regime),
            "missing centroid for {:?}",
            regime
        );
    }
}

#[test]
fn signature_config_centroids_have_correct_dimension() {
    let config = SignatureConfig::default();
    for centroid in &config.centroids {
        assert_eq!(centroid.components.len(), config.max_dim);
    }
}

#[test]
fn signature_config_serde_roundtrip() {
    let config = SignatureConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: SignatureConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// Specimen family
// ---------------------------------------------------------------------------

#[test]
fn specimen_family_all_count() {
    assert_eq!(SignatureSpecimenFamily::ALL.len(), 6);
}

#[test]
fn specimen_family_as_str_non_empty() {
    for f in SignatureSpecimenFamily::ALL {
        assert!(!f.as_str().is_empty());
    }
}

#[test]
fn specimen_family_display_matches_as_str() {
    for f in SignatureSpecimenFamily::ALL {
        assert_eq!(format!("{f}"), f.as_str());
    }
}

#[test]
fn specimen_family_serde_roundtrip() {
    for f in SignatureSpecimenFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: SignatureSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

// ---------------------------------------------------------------------------
// Expected outcome
// ---------------------------------------------------------------------------

#[test]
fn expected_outcome_serde_roundtrip() {
    for variant in [
        SignatureExpectedOutcome::ValidSignature,
        SignatureExpectedOutcome::InvalidSignature,
        SignatureExpectedOutcome::CorrectClassification,
        SignatureExpectedOutcome::Abstention,
        SignatureExpectedOutcome::StableChart,
        SignatureExpectedOutcome::TransitionDetected,
        SignatureExpectedOutcome::SimilarityComputed,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let back: SignatureExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, back);
    }
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_serde_roundtrip() {
    for v in [SignatureVerdict::Pass, SignatureVerdict::Fail] {
        let json = serde_json::to_string(&v).unwrap();
        let back: SignatureVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

#[test]
fn corpus_non_empty() {
    assert!(!signature_corpus().is_empty());
}

#[test]
fn corpus_ids_unique() {
    let corpus = signature_corpus();
    let ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    assert_eq!(ids.len(), corpus.len());
}

#[test]
fn corpus_covers_all_families() {
    let corpus = signature_corpus();
    let covered: BTreeSet<SignatureSpecimenFamily> = corpus.iter().map(|s| s.family).collect();
    for f in SignatureSpecimenFamily::ALL {
        assert!(covered.contains(f), "missing family {:?}", f);
    }
}

#[test]
fn corpus_all_specimens_have_traces() {
    for specimen in &signature_corpus() {
        assert!(
            !specimen.traces.is_empty(),
            "specimen {} has no traces",
            specimen.specimen_id
        );
    }
}

#[test]
fn corpus_specimen_serde_roundtrip() {
    for specimen in &signature_corpus() {
        let json = serde_json::to_string(specimen).unwrap();
        let back: SignatureSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(*specimen, back);
    }
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

#[test]
fn all_specimens_pass() {
    let inv = run_signature_corpus();
    for ev in &inv.evidence {
        assert_eq!(
            ev.verdict,
            SignatureVerdict::Pass,
            "specimen {} failed: {:?}",
            ev.specimen_id,
            ev.error_detail
        );
    }
}

#[test]
fn contract_satisfied() {
    let inv = run_signature_corpus();
    assert!(inv.contract_satisfied());
}

#[test]
fn counts_consistent() {
    let inv = run_signature_corpus();
    assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
    assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
}

#[test]
fn family_coverage_sums_to_total() {
    let inv = run_signature_corpus();
    let total: u64 = inv.family_coverage.values().sum();
    assert_eq!(total, inv.specimen_count);
}

#[test]
fn evidence_hashes_are_64_hex() {
    let inv = run_signature_corpus();
    for ev in &inv.evidence {
        assert_eq!(ev.evidence_hash.len(), 64, "specimen {}", ev.specimen_id);
        assert!(
            ev.evidence_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "specimen {} hash not hex",
            ev.specimen_id
        );
    }
}

#[test]
fn evidence_hashes_unique() {
    let inv = run_signature_corpus();
    let hashes: BTreeSet<&str> = inv
        .evidence
        .iter()
        .map(|e| e.evidence_hash.as_str())
        .collect();
    assert_eq!(hashes.len(), inv.evidence.len());
}

#[test]
fn corpus_deterministic() {
    let inv1 = run_signature_corpus();
    let inv2 = run_signature_corpus();
    assert_eq!(inv1, inv2);
}

#[test]
fn inventory_schema_correct() {
    let inv = run_signature_corpus();
    assert_eq!(inv.schema_version, REGIME_SIG_SCHEMA_VERSION);
    assert_eq!(inv.component, REGIME_SIG_COMPONENT);
}

#[test]
fn inventory_serde_roundtrip() {
    let inv = run_signature_corpus();
    let json = serde_json::to_string(&inv).unwrap();
    let back: SignatureEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn contract_not_satisfied_with_failures() {
    let inv = SignatureEvidenceInventory {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        specimen_count: 5,
        pass_count: 4,
        fail_count: 1,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn contract_not_satisfied_with_zero_specimens() {
    let inv = SignatureEvidenceInventory {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

// ---------------------------------------------------------------------------
// Bundle writer
// ---------------------------------------------------------------------------

#[test]
fn bundle_writer_creates_expected_files() {
    let dir = std::env::temp_dir().join("franken-regime-sig-test-bundle");
    let _ = std::fs::remove_dir_all(&dir);
    let commands = vec![
        "cargo test -p frankenengine-engine --test regime_signature_feature_integration"
            .to_string(),
    ];
    let artifacts =
        write_signature_evidence_bundle(&dir, &commands).expect("bundle write should succeed");
    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(!artifacts.inventory_hash.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_manifest_has_correct_schema() {
    let dir = std::env::temp_dir().join("franken-regime-sig-test-manifest");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts =
        write_signature_evidence_bundle(&dir, &[]).expect("bundle write should succeed");
    let manifest_json = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
    assert_eq!(
        manifest["schema_version"],
        REGIME_SIG_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(manifest["component"], REGIME_SIG_COMPONENT);
    assert_eq!(manifest["policy_id"], REGIME_SIG_POLICY_ID);
    // contract_satisfied reflects whether ALL corpus specimens pass.
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_events_are_valid_jsonl() {
    let dir = std::env::temp_dir().join("franken-regime-sig-test-events");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts =
        write_signature_evidence_bundle(&dir, &[]).expect("bundle write should succeed");
    let events = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let line_count = events.lines().count();
    // At least: start + N specimens + end = N+2
    let corpus_size = signature_corpus().len();
    assert_eq!(line_count, corpus_size + 2);
    for line in events.lines() {
        let _: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("invalid JSON line: {e}"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_inventory_matches_corpus_run() {
    let dir = std::env::temp_dir().join("franken-regime-sig-test-inv-match");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts =
        write_signature_evidence_bundle(&dir, &[]).expect("bundle write should succeed");
    let inv_json = std::fs::read_to_string(&artifacts.inventory_path).unwrap();
    let inv: SignatureEvidenceInventory = serde_json::from_str(&inv_json).unwrap();
    let direct = run_signature_corpus();
    assert_eq!(inv.specimen_count, direct.specimen_count);
    assert_eq!(inv.pass_count, direct.pass_count);
    assert_eq!(inv.fail_count, direct.fail_count);
    let _ = std::fs::remove_dir_all(&dir);
}
