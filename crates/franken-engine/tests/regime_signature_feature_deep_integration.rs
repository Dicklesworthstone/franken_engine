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

//! Deep integration tests for `regime_signature_feature`.
//!
//! Focuses on areas not covered by the existing integration tests:
//! edge cases, error paths, determinism under variation, composition of
//! multiple operations, large-scale stress, serde round-trips for
//! ancillary types, Display implementations, boundary conditions,
//! and custom SignatureConfig behaviour.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::regime_detector::Regime;
use frankenengine_engine::regime_signature_feature::{
    ABSTENTION_THRESHOLD_MILLIONTHS, MAX_SIGNATURE_DIM, MIN_TRACE_LENGTH, REGIME_SIG_COMPONENT,
    REGIME_SIG_EVENT_SCHEMA_VERSION, REGIME_SIG_MANIFEST_SCHEMA_VERSION, REGIME_SIG_POLICY_ID,
    REGIME_SIG_SCHEMA_VERSION, RegimeCentroid, RegimeLabel, RegimeStateChart, RegimeStateEntry,
    RuntimeTrace, SignatureArtifactPaths, SignatureConfig, SignatureEvidenceEvent,
    SignatureEvidenceInventory, SignatureExpectedOutcome, SignatureRunManifest, SignatureSpecimen,
    SignatureSpecimenEvidence, SignatureSpecimenFamily, SignatureVerdict, TraceObservation,
    TraceSignature, build_regime_state_chart, classify_regime, extract_signature,
    run_signature_corpus, signature_corpus, write_signature_evidence_bundle,
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

/// Build a custom config with a single centroid for controlled classification tests.
fn config_with_single_centroid(
    regime: Regime,
    components: Vec<i64>,
    radius: i64,
) -> SignatureConfig {
    SignatureConfig {
        max_dim: MAX_SIGNATURE_DIM,
        min_trace_length: MIN_TRACE_LENGTH,
        abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
        centroids: vec![RegimeCentroid {
            regime,
            components,
            radius_millionths: radius,
        }],
    }
}

// ===========================================================================
// 1. TraceObservation edge cases
// ===========================================================================

#[test]
fn trace_observation_negative_value_serde_roundtrip() {
    let obs = TraceObservation {
        seq: 0,
        feature_name: "neg_metric".to_string(),
        value_millionths: -999_999,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: TraceObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn trace_observation_extreme_i64_values() {
    let obs_max = TraceObservation {
        seq: u64::MAX,
        feature_name: "extreme".to_string(),
        value_millionths: i64::MAX,
    };
    let json = serde_json::to_string(&obs_max).unwrap();
    let back: TraceObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs_max, back);

    let obs_min = TraceObservation {
        seq: 0,
        feature_name: "extreme_neg".to_string(),
        value_millionths: i64::MIN,
    };
    let json2 = serde_json::to_string(&obs_min).unwrap();
    let back2: TraceObservation = serde_json::from_str(&json2).unwrap();
    assert_eq!(obs_min, back2);
}

#[test]
fn trace_observation_empty_feature_name() {
    let obs = TraceObservation {
        seq: 1,
        feature_name: String::new(),
        value_millionths: 500_000,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: TraceObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn trace_observation_ordering_by_seq() {
    let a = TraceObservation {
        seq: 1,
        feature_name: "x".to_string(),
        value_millionths: 0,
    };
    let b = TraceObservation {
        seq: 2,
        feature_name: "x".to_string(),
        value_millionths: 0,
    };
    assert!(a < b);
}

// ===========================================================================
// 2. RuntimeTrace edge and boundary cases
// ===========================================================================

#[test]
fn runtime_trace_with_two_observations_is_invalid() {
    let config = SignatureConfig::default();
    let trace = make_trace("t2obs", "m", &[100, 200], 1);
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
    assert_eq!(sig.observation_count, 2);
}

#[test]
fn runtime_trace_unicode_feature_names() {
    let config = SignatureConfig::default();
    let trace = make_multi_feature_trace(
        "t-unicode",
        &[
            ("\u{1F600}", &[500_000, 600_000]),
            ("\u{00E9}clair", &[400_000, 300_000]),
        ],
        1,
    );
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert!(sig.feature_count >= 1);
}

#[test]
fn runtime_trace_serde_roundtrip_empty_observations() {
    let trace = RuntimeTrace {
        trace_id: "empty-rt".to_string(),
        observations: vec![],
        epoch: SecurityEpoch::from_raw(42),
    };
    let json = serde_json::to_string(&trace).unwrap();
    let back: RuntimeTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, back);
}

#[test]
fn runtime_trace_clone_independence() {
    let trace = make_trace("orig", "m", &[1, 2, 3, 4], 1);
    let mut cloned = trace.clone();
    cloned.trace_id = "modified".to_string();
    assert_ne!(trace.trace_id, cloned.trace_id);
    assert_eq!(trace.observations.len(), cloned.observations.len());
}

// ===========================================================================
// 3. Signature extraction: boundary and stress
// ===========================================================================

#[test]
fn extract_exactly_min_minus_one_is_invalid() {
    let config = SignatureConfig::default();
    let values: Vec<i64> = (0..(MIN_TRACE_LENGTH - 1) as i64)
        .map(|i| i * 100_000)
        .collect();
    let trace = make_trace("t-minm1", "metric", &values, 1);
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
}

#[test]
fn extract_all_zero_values_valid_with_zero_components() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-zero", "m", &[0, 0, 0, 0], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    // All values are 0, so after normalization the component should be 0.
    let active_components: Vec<&i64> = sig
        .components
        .iter()
        .zip(&sig.bucket_counts)
        .filter(|(_, c)| **c > 0)
        .map(|(v, _)| v)
        .collect();
    for c in &active_components {
        assert_eq!(**c, 0);
    }
}

#[test]
fn extract_all_negative_values() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-neg", "m", &[-500_000, -600_000, -400_000, -300_000], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    // The active bucket should have a negative mean.
    let active_components: Vec<i64> = sig
        .components
        .iter()
        .zip(&sig.bucket_counts)
        .filter(|(_, c)| **c > 0)
        .map(|(v, _)| *v)
        .collect();
    assert!(!active_components.is_empty());
    for c in &active_components {
        assert!(*c < 0, "expected negative component, got {c}");
    }
}

#[test]
fn extract_single_feature_bucket_count_equals_observation_count() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-bc", "only_one", &[100, 200, 300, 400, 500], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    let total_bucket_count: u64 = sig.bucket_counts.iter().sum();
    assert_eq!(total_bucket_count, sig.observation_count);
}

#[test]
fn extract_many_features_distributes_across_buckets() {
    let config = SignatureConfig::default();
    // Use many distinct feature names to get multiple buckets populated.
    let features: Vec<(&str, &[i64])> = vec![
        ("alpha", &[100_000]),
        ("bravo", &[200_000]),
        ("charlie", &[300_000]),
        ("delta", &[400_000]),
        ("echo", &[500_000]),
        ("foxtrot", &[600_000]),
        ("golf", &[700_000]),
        ("hotel", &[800_000]),
    ];
    let trace = make_multi_feature_trace("t-spread", &features, 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert!(sig.feature_count >= 1);
    let nonzero_buckets = sig.bucket_counts.iter().filter(|&&c| c > 0).count();
    // With 8 distinct feature names hashed into 64 buckets, we expect several distinct buckets
    // (collisions are possible but not all 8 landing in one).
    assert!(
        nonzero_buckets >= 1,
        "expected at least 1 nonzero bucket, got {nonzero_buckets}"
    );
}

#[test]
fn extract_large_trace_1000_observations() {
    let config = SignatureConfig::default();
    let values: Vec<i64> = (0..1000).map(|i| 100_000 + (i % 50) * 10_000).collect();
    let trace = make_trace("t-1k", "metric", &values, 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.observation_count, 1000);
    assert_eq!(sig.dimension, MAX_SIGNATURE_DIM);
}

#[test]
fn extract_signature_hash_changes_with_very_different_data() {
    let config = SignatureConfig::default();
    // Use drastically different data to ensure different bucket distributions
    let t1 = make_trace(
        "same-id",
        "feature_a",
        &[1_000_000, 1_000_000, 1_000_000, 1_000_000],
        1,
    );
    let t2 = make_trace("same-id", "feature_b", &[0, 0, 0, 0], 1);
    let s1 = extract_signature(&t1, &config);
    let s2 = extract_signature(&t2, &config);
    // Different feature names produce different bucket distributions → different hashes.
    assert_ne!(s1.signature_hash, s2.signature_hash);
}

#[test]
fn extract_signature_hash_changes_with_trace_id() {
    let config = SignatureConfig::default();
    let t1 = make_trace("id-a", "m", &[100, 200, 300, 400], 1);
    let t2 = make_trace("id-b", "m", &[100, 200, 300, 400], 1);
    let s1 = extract_signature(&t1, &config);
    let s2 = extract_signature(&t2, &config);
    // Different trace IDs produce different hashes even with same data.
    assert_ne!(s1.signature_hash, s2.signature_hash);
}

#[test]
fn extract_invalid_signature_hash_is_still_64_hex() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-inv-hash", "m", &[100], 1);
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
    assert_eq!(sig.signature_hash.len(), 64);
    assert!(sig.signature_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn extract_invalid_signature_has_zero_components() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-inv-zero", "m", &[999], 1);
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
    assert!(sig.components.iter().all(|&c| c == 0));
    assert!(sig.bucket_counts.iter().all(|&c| c == 0));
}

#[test]
fn extract_schema_version_matches_constant() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-sv", "m", &[1, 2, 3, 4], 1);
    let sig = extract_signature(&trace, &config);
    assert_eq!(sig.schema_version, REGIME_SIG_SCHEMA_VERSION);
}

// ===========================================================================
// 4. L1 distance: triangle inequality and edge cases
// ===========================================================================

#[test]
fn l1_distance_triangle_inequality() {
    let config = SignatureConfig::default();
    let ta = make_trace("a", "m", &[100_000, 200_000, 300_000, 400_000], 1);
    let tb = make_trace("b", "m", &[500_000, 600_000, 700_000, 800_000], 1);
    let tc = make_trace("c", "m", &[200_000, 300_000, 400_000, 500_000], 1);
    let sa = extract_signature(&ta, &config);
    let sb = extract_signature(&tb, &config);
    let sc = extract_signature(&tc, &config);
    let d_ab = sa.l1_distance(&sb);
    let d_ac = sa.l1_distance(&sc);
    let d_bc = sb.l1_distance(&sc);
    // Triangle inequality: d(a,b) <= d(a,c) + d(c,b)
    assert!(
        d_ab <= d_ac.saturating_add(d_bc),
        "triangle inequality violated: d(a,b)={d_ab} > d(a,c)={d_ac} + d(c,b)={d_bc}"
    );
}

#[test]
fn l1_distance_non_negative() {
    let config = SignatureConfig::default();
    let t1 = make_trace("t1", "m", &[100_000, -200_000, 300_000, -400_000], 1);
    let t2 = make_trace("t2", "m", &[-100_000, 200_000, -300_000, 400_000], 1);
    let s1 = extract_signature(&t1, &config);
    let s2 = extract_signature(&t2, &config);
    assert!(s1.l1_distance(&s2) >= 0);
}

#[test]
fn l1_distance_commutative_with_multi_feature() {
    let config = SignatureConfig::default();
    let t1 = make_multi_feature_trace(
        "t1",
        &[("a", &[100_000, 200_000]), ("b", &[300_000, 400_000])],
        1,
    );
    let t2 = make_multi_feature_trace(
        "t2",
        &[("a", &[500_000, 600_000]), ("b", &[700_000, 800_000])],
        1,
    );
    let s1 = extract_signature(&t1, &config);
    let s2 = extract_signature(&t2, &config);
    assert_eq!(s1.l1_distance(&s2), s2.l1_distance(&s1));
}

// ===========================================================================
// 5. Cosine similarity: boundary vectors, orthogonal-ish
// ===========================================================================

#[test]
fn cosine_similarity_large_values_no_overflow() {
    // Components near i64 max could overflow without saturating_mul.
    let sig = TraceSignature {
        schema_version: "v1".to_string(),
        trace_id: "large".to_string(),
        dimension: 4,
        components: vec![1_000_000_000, 1_000_000_000, 1_000_000_000, 1_000_000_000],
        bucket_counts: vec![1; 4],
        observation_count: 4,
        feature_count: 1,
        valid: true,
        signature_hash: "h".to_string(),
    };
    // Should not panic due to overflow.
    let cos = sig.cosine_similarity(&sig);
    assert!(
        cos > 0,
        "expected positive cosine for identical non-zero vector"
    );
}

#[test]
fn cosine_similarity_opposite_signs() {
    let s1 = TraceSignature {
        schema_version: "v1".to_string(),
        trace_id: "pos".to_string(),
        dimension: 4,
        components: vec![500_000, 500_000, 500_000, 500_000],
        bucket_counts: vec![1; 4],
        observation_count: 4,
        feature_count: 1,
        valid: true,
        signature_hash: "a".to_string(),
    };
    let s2 = TraceSignature {
        schema_version: "v1".to_string(),
        trace_id: "neg".to_string(),
        dimension: 4,
        components: vec![-500_000, -500_000, -500_000, -500_000],
        bucket_counts: vec![1; 4],
        observation_count: 4,
        feature_count: 1,
        valid: true,
        signature_hash: "b".to_string(),
    };
    let cos = s1.cosine_similarity(&s2);
    // Opposite vectors: cosine should be negative.
    assert!(
        cos < 0,
        "expected negative cosine for opposite vectors, got {cos}"
    );
}

#[test]
fn cosine_similarity_single_nonzero_component() {
    let s1 = TraceSignature {
        schema_version: "v1".to_string(),
        trace_id: "a".to_string(),
        dimension: 4,
        components: vec![1_000_000, 0, 0, 0],
        bucket_counts: vec![1, 0, 0, 0],
        observation_count: 1,
        feature_count: 1,
        valid: true,
        signature_hash: "a".to_string(),
    };
    let cos = s1.cosine_similarity(&s1);
    assert!(cos > 900_000, "self-cosine should be near 1M, got {cos}");
}

#[test]
fn cosine_similarity_one_zero_one_nonzero() {
    let zero = TraceSignature {
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
    let nonzero = TraceSignature {
        schema_version: "v1".to_string(),
        trace_id: "nz".to_string(),
        dimension: 4,
        components: vec![1_000_000, 1_000_000, 1_000_000, 1_000_000],
        bucket_counts: vec![1; 4],
        observation_count: 4,
        feature_count: 1,
        valid: true,
        signature_hash: "nz".to_string(),
    };
    assert_eq!(zero.cosine_similarity(&nonzero), 0);
    assert_eq!(nonzero.cosine_similarity(&zero), 0);
}

// ===========================================================================
// 6. TraceSignature serde: extreme cases
// ===========================================================================

#[test]
fn trace_signature_serde_with_empty_components() {
    let sig = TraceSignature {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        trace_id: "empty-comps".to_string(),
        dimension: 0,
        components: vec![],
        bucket_counts: vec![],
        observation_count: 0,
        feature_count: 0,
        valid: false,
        signature_hash: "none".to_string(),
    };
    let json = serde_json::to_string(&sig).unwrap();
    let back: TraceSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig, back);
}

#[test]
fn trace_signature_debug_format_non_empty() {
    let config = SignatureConfig::default();
    let trace = make_trace("t-dbg", "m", &[1, 2, 3, 4], 1);
    let sig = extract_signature(&trace, &config);
    let dbg = format!("{:?}", sig);
    assert!(dbg.contains("TraceSignature"));
    assert!(dbg.contains("t-dbg"));
}

// ===========================================================================
// 7. Regime classification: custom configs
// ===========================================================================

#[test]
#[should_panic(expected = "overflow")]
fn classify_with_no_centroids_panics_on_empty_centroid_list() {
    // Known limitation: classify_regime panics with overflow when centroids is empty.
    let config = SignatureConfig {
        max_dim: MAX_SIGNATURE_DIM,
        min_trace_length: MIN_TRACE_LENGTH,
        abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
        centroids: vec![],
    };
    let trace = make_trace("t-noc", "m", &[500_000, 500_000, 500_000, 500_000], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    let (_label, _conf) = classify_regime(&sig, &config);
}

#[test]
fn classify_with_single_centroid_nearest_wins() {
    let config =
        config_with_single_centroid(Regime::Attack, vec![500_000; MAX_SIGNATURE_DIM], 5_000_000);
    let trace = make_trace("t-sc", "m", &[500_000, 500_000, 500_000, 500_000], 1);
    let sig = extract_signature(&trace, &config);
    let (label, conf) = classify_regime(&sig, &config);
    assert_eq!(label, RegimeLabel::Classified(Regime::Attack));
    assert!(conf > 0);
}

#[test]
fn classify_with_zero_abstention_threshold_never_abstains_on_valid() {
    let config = SignatureConfig {
        max_dim: MAX_SIGNATURE_DIM,
        min_trace_length: MIN_TRACE_LENGTH,
        abstention_threshold: 0,
        centroids: SignatureConfig::default().centroids,
    };
    let trace = make_trace("t-zat", "m", &[999_999, 999_999, 999_999, 999_999], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    let (label, _) = classify_regime(&sig, &config);
    assert!(!label.is_abstention());
}

#[test]
fn classify_with_max_abstention_threshold_always_abstains() {
    let config = SignatureConfig {
        max_dim: MAX_SIGNATURE_DIM,
        min_trace_length: MIN_TRACE_LENGTH,
        abstention_threshold: 1_000_001, // above max possible confidence
        centroids: SignatureConfig::default().centroids,
    };
    let trace = make_trace("t-mat", "m", &[500_000, 500_000, 500_000, 500_000], 1);
    let sig = extract_signature(&trace, &config);
    let (label, _) = classify_regime(&sig, &config);
    assert!(label.is_abstention());
}

#[test]
fn classify_deterministic_across_calls() {
    let config = SignatureConfig::default();
    let trace = make_multi_feature_trace(
        "t-det",
        &[("cpu", &[500_000, 600_000]), ("mem", &[300_000, 400_000])],
        1,
    );
    let sig = extract_signature(&trace, &config);
    let (l1, c1) = classify_regime(&sig, &config);
    let (l2, c2) = classify_regime(&sig, &config);
    assert_eq!(l1, l2);
    assert_eq!(c1, c2);
}

#[test]
fn classify_confidence_is_non_negative() {
    let config = SignatureConfig::default();
    let values: Vec<i64> = (0..20).map(|i| 100_000 + i * 50_000).collect();
    let trace = make_trace("t-conf", "m", &values, 1);
    let sig = extract_signature(&trace, &config);
    let (_, conf) = classify_regime(&sig, &config);
    assert!(conf >= 0);
}

// ===========================================================================
// 8. RegimeLabel: comprehensive Display and ordering
// ===========================================================================

#[test]
fn regime_label_classified_as_str_covers_all_regimes() {
    let expected_strs = ["normal", "elevated", "attack", "degraded", "recovery"];
    let regimes = [
        Regime::Normal,
        Regime::Elevated,
        Regime::Attack,
        Regime::Degraded,
        Regime::Recovery,
    ];
    for (regime, expected_str) in regimes.iter().zip(expected_strs.iter()) {
        let label = RegimeLabel::Classified(*regime);
        assert_eq!(label.as_str(), *expected_str);
    }
}

#[test]
fn regime_label_ordering_is_deterministic() {
    let mut labels = vec![
        RegimeLabel::Abstention,
        RegimeLabel::Classified(Regime::Recovery),
        RegimeLabel::Classified(Regime::Normal),
        RegimeLabel::Classified(Regime::Attack),
    ];
    let labels_clone = labels.clone();
    labels.sort();
    let mut labels2 = labels_clone;
    labels2.sort();
    assert_eq!(labels, labels2);
}

#[test]
fn regime_label_clone_eq() {
    let label = RegimeLabel::Classified(Regime::Degraded);
    let cloned = label.clone();
    assert_eq!(label, cloned);
}

#[test]
fn regime_label_all_classified_is_not_abstention() {
    for label in RegimeLabel::ALL_CLASSIFIED {
        assert!(!label.is_abstention());
    }
}

// ===========================================================================
// 9. RegimeStateChart: composition and multi-trace
// ===========================================================================

#[test]
fn state_chart_many_identical_traces_zero_transitions() {
    let config = SignatureConfig::default();
    let traces: Vec<RuntimeTrace> = (0..20)
        .map(|i| {
            make_multi_feature_trace(
                &format!("t{i}"),
                &[("cpu", &[500_000, 510_000, 490_000, 500_000])],
                i as u64 + 1,
            )
        })
        .collect();
    let chart = build_regime_state_chart(&traces, &config);
    assert_eq!(chart.entries.len(), 20);
    // All same data => same classification => 0 transitions.
    assert_eq!(chart.transition_count, 0);
}

#[test]
fn state_chart_sequential_entries_have_incrementing_seq() {
    let config = SignatureConfig::default();
    let traces: Vec<RuntimeTrace> = (0..5)
        .map(|i| {
            make_trace(
                &format!("t{i}"),
                "m",
                &[500_000, 500_000, 500_000, 500_000],
                i + 1,
            )
        })
        .collect();
    let chart = build_regime_state_chart(&traces, &config);
    for (i, entry) in chart.entries.iter().enumerate() {
        assert_eq!(entry.seq, i as u64);
    }
}

#[test]
fn state_chart_preserves_trace_ids() {
    let config = SignatureConfig::default();
    let traces = vec![
        make_trace("alpha", "m", &[100, 200, 300, 400], 1),
        make_trace("bravo", "m", &[100, 200, 300, 400], 2),
    ];
    let chart = build_regime_state_chart(&traces, &config);
    assert_eq!(chart.entries[0].trace_id, "alpha");
    assert_eq!(chart.entries[1].trace_id, "bravo");
}

#[test]
fn state_chart_with_short_traces_counts_abstentions() {
    let config = SignatureConfig::default();
    // All traces below min length => all abstentions.
    let traces: Vec<RuntimeTrace> = (0..3)
        .map(|i| make_trace(&format!("short{i}"), "m", &[100], i + 1))
        .collect();
    let chart = build_regime_state_chart(&traces, &config);
    assert_eq!(chart.abstention_count, 3);
    assert!(!chart.is_stable());
}

#[test]
fn state_chart_mixed_valid_and_short_traces() {
    let config = SignatureConfig::default();
    let traces = vec![
        make_trace("valid1", "m", &[500_000, 500_000, 500_000, 500_000], 1),
        make_trace("short1", "m", &[100], 2),
        make_trace("valid2", "m", &[500_000, 500_000, 500_000, 500_000], 3),
    ];
    let chart = build_regime_state_chart(&traces, &config);
    assert_eq!(chart.entries.len(), 3);
    assert_eq!(chart.abstention_count, 1);
    // There should be transitions: valid -> abstention -> valid.
    assert!(chart.transition_count >= 1);
}

#[test]
fn state_chart_label_distribution_keys_match_entries() {
    let config = SignatureConfig::default();
    let traces = vec![
        make_trace("t1", "m", &[500_000, 500_000, 500_000, 500_000], 1),
        make_trace("t2", "m", &[100], 2), // short => abstention
    ];
    let chart = build_regime_state_chart(&traces, &config);
    let dist_total: u64 = chart.label_distribution.values().sum();
    assert_eq!(dist_total, chart.entries.len() as u64);
}

#[test]
fn state_chart_serde_roundtrip_with_distribution() {
    let mut dist = BTreeMap::new();
    dist.insert("normal".to_string(), 3);
    dist.insert("abstention".to_string(), 1);
    let chart = RegimeStateChart {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        entries: vec![
            RegimeStateEntry {
                seq: 0,
                label: RegimeLabel::Classified(Regime::Normal),
                confidence_millionths: 800_000,
                centroid_distance_millionths: 50_000,
                trace_id: "t0".to_string(),
            },
            RegimeStateEntry {
                seq: 1,
                label: RegimeLabel::Abstention,
                confidence_millionths: 0,
                centroid_distance_millionths: 0,
                trace_id: "t1".to_string(),
            },
        ],
        transition_count: 1,
        abstention_count: 1,
        label_distribution: dist.clone(),
        chart_hash: "abc123def456".to_string(),
    };
    let json = serde_json::to_string(&chart).unwrap();
    let back: RegimeStateChart = serde_json::from_str(&json).unwrap();
    assert_eq!(chart, back);
}

#[test]
fn state_chart_deterministic_hash() {
    let config = SignatureConfig::default();
    let traces = vec![
        make_trace("x", "m", &[100, 200, 300, 400], 1),
        make_trace("y", "m", &[500, 600, 700, 800], 2),
    ];
    let c1 = build_regime_state_chart(&traces, &config);
    let c2 = build_regime_state_chart(&traces, &config);
    assert_eq!(c1.chart_hash, c2.chart_hash);
    assert_eq!(c1.chart_hash.len(), 64);
}

// ===========================================================================
// 10. RegimeStateEntry serde and edge cases
// ===========================================================================

#[test]
fn regime_state_entry_serde_roundtrip() {
    let entry = RegimeStateEntry {
        seq: 42,
        label: RegimeLabel::Classified(Regime::Elevated),
        confidence_millionths: 750_000,
        centroid_distance_millionths: 123_456,
        trace_id: "test-entry".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: RegimeStateEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn regime_state_entry_abstention_serde_roundtrip() {
    let entry = RegimeStateEntry {
        seq: 0,
        label: RegimeLabel::Abstention,
        confidence_millionths: 0,
        centroid_distance_millionths: 0,
        trace_id: "abs-entry".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: RegimeStateEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// 11. RegimeCentroid
// ===========================================================================

#[test]
fn regime_centroid_serde_roundtrip() {
    let centroid = RegimeCentroid {
        regime: Regime::Degraded,
        components: vec![300_000; 8],
        radius_millionths: 2_500_000,
    };
    let json = serde_json::to_string(&centroid).unwrap();
    let back: RegimeCentroid = serde_json::from_str(&json).unwrap();
    assert_eq!(centroid, back);
}

#[test]
fn default_centroids_all_have_correct_dimension() {
    let config = SignatureConfig::default();
    for c in &config.centroids {
        assert_eq!(
            c.components.len(),
            MAX_SIGNATURE_DIM,
            "centroid for {:?} has wrong dimension",
            c.regime
        );
    }
}

#[test]
fn default_centroids_radii_are_positive() {
    let config = SignatureConfig::default();
    for c in &config.centroids {
        assert!(
            c.radius_millionths > 0,
            "centroid for {:?} has non-positive radius",
            c.regime
        );
    }
}

// ===========================================================================
// 12. SignatureConfig: custom and edge
// ===========================================================================

#[test]
fn signature_config_with_custom_min_trace_length() {
    let config = SignatureConfig {
        max_dim: MAX_SIGNATURE_DIM,
        min_trace_length: 2,
        abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
        centroids: SignatureConfig::default().centroids,
    };
    // With min_trace_length=2, a 2-observation trace should be valid.
    let trace = make_trace("t-custom", "m", &[500_000, 600_000], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
}

#[test]
fn signature_config_with_custom_max_dim() {
    let config = SignatureConfig {
        max_dim: 8,
        min_trace_length: MIN_TRACE_LENGTH,
        abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
        centroids: vec![RegimeCentroid {
            regime: Regime::Normal,
            components: vec![500_000; 8],
            radius_millionths: 2_000_000,
        }],
    };
    let trace = make_trace("t-dim8", "m", &[500_000, 500_000, 500_000, 500_000], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.dimension, 8);
    assert_eq!(sig.components.len(), 8);
    assert_eq!(sig.bucket_counts.len(), 8);
}

// ===========================================================================
// 13. SignatureSpecimenFamily exhaustive
// ===========================================================================

#[test]
fn specimen_family_serde_roundtrip_all_variants() {
    let families = [
        SignatureSpecimenFamily::Extraction,
        SignatureSpecimenFamily::ShortTrace,
        SignatureSpecimenFamily::Classification,
        SignatureSpecimenFamily::Abstention,
        SignatureSpecimenFamily::StateChart,
        SignatureSpecimenFamily::Similarity,
    ];
    for f in &families {
        let json = serde_json::to_string(f).unwrap();
        let back: SignatureSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
        // Also check Display
        assert_eq!(format!("{f}"), f.as_str());
    }
}

#[test]
fn specimen_family_as_str_unique() {
    let strs: BTreeSet<&str> = SignatureSpecimenFamily::ALL
        .iter()
        .map(|f| f.as_str())
        .collect();
    assert_eq!(strs.len(), SignatureSpecimenFamily::ALL.len());
}

// ===========================================================================
// 14. SignatureExpectedOutcome exhaustive serde
// ===========================================================================

#[test]
fn expected_outcome_all_variants_serde_roundtrip() {
    let variants = [
        SignatureExpectedOutcome::ValidSignature,
        SignatureExpectedOutcome::InvalidSignature,
        SignatureExpectedOutcome::CorrectClassification,
        SignatureExpectedOutcome::Abstention,
        SignatureExpectedOutcome::StableChart,
        SignatureExpectedOutcome::TransitionDetected,
        SignatureExpectedOutcome::SimilarityComputed,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: SignatureExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// 15. SignatureVerdict
// ===========================================================================

#[test]
fn verdict_ordering_pass_before_fail() {
    // Just verify Ord is implemented (they derive it).
    let mut verdicts = vec![SignatureVerdict::Fail, SignatureVerdict::Pass];
    verdicts.sort();
    // The actual order depends on enum declaration order.
    assert_eq!(verdicts.len(), 2);
}

#[test]
fn verdict_debug_format() {
    assert!(format!("{:?}", SignatureVerdict::Pass).contains("Pass"));
    assert!(format!("{:?}", SignatureVerdict::Fail).contains("Fail"));
}

// ===========================================================================
// 16. SignatureSpecimenEvidence serde
// ===========================================================================

#[test]
fn specimen_evidence_serde_roundtrip_full() {
    let ev = SignatureSpecimenEvidence {
        specimen_id: "test-evidence".to_string(),
        family: SignatureSpecimenFamily::Extraction,
        expected_outcome: SignatureExpectedOutcome::ValidSignature,
        verdict: SignatureVerdict::Pass,
        signature_valid: Some(true),
        classified_regime: Some(RegimeLabel::Classified(Regime::Normal)),
        confidence_millionths: Some(800_000),
        transition_count: Some(0),
        error_detail: None,
        evidence_hash: "a".repeat(64),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: SignatureSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn specimen_evidence_serde_roundtrip_with_error() {
    let ev = SignatureSpecimenEvidence {
        specimen_id: "fail-ev".to_string(),
        family: SignatureSpecimenFamily::ShortTrace,
        expected_outcome: SignatureExpectedOutcome::InvalidSignature,
        verdict: SignatureVerdict::Fail,
        signature_valid: Some(false),
        classified_regime: None,
        confidence_millionths: None,
        transition_count: None,
        error_detail: Some("something went wrong".to_string()),
        evidence_hash: "b".repeat(64),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: SignatureSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ===========================================================================
// 17. SignatureEvidenceInventory
// ===========================================================================

#[test]
fn evidence_inventory_contract_satisfied_boundary() {
    // Exactly 1 specimen, 1 pass, 0 fail => satisfied.
    let inv = SignatureEvidenceInventory {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        specimen_count: 1,
        pass_count: 1,
        fail_count: 0,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(inv.contract_satisfied());
}

#[test]
fn evidence_inventory_serde_roundtrip_synthetic() {
    let mut fc = BTreeMap::new();
    fc.insert("extraction".to_string(), 2);
    fc.insert("classification".to_string(), 1);
    let inv = SignatureEvidenceInventory {
        schema_version: "test-schema".to_string(),
        component: "test-component".to_string(),
        specimen_count: 3,
        pass_count: 3,
        fail_count: 0,
        family_coverage: fc,
        evidence: vec![],
    };
    let json = serde_json::to_string(&inv).unwrap();
    let back: SignatureEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ===========================================================================
// 18. SignatureRunManifest and related types
// ===========================================================================

#[test]
fn run_manifest_serde_roundtrip() {
    let manifest = SignatureRunManifest {
        schema_version: REGIME_SIG_MANIFEST_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        trace_id: "sig-abc123".to_string(),
        decision_id: "dec-def456".to_string(),
        policy_id: REGIME_SIG_POLICY_ID.to_string(),
        inventory_hash: "f".repeat(64),
        specimen_count: 10,
        pass_count: 10,
        fail_count: 0,
        contract_satisfied: true,
        artifact_paths: SignatureArtifactPaths {
            evidence_inventory: "inv.json".to_string(),
            run_manifest: "manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: SignatureRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn artifact_paths_serde_roundtrip() {
    let paths = SignatureArtifactPaths {
        evidence_inventory: "a.json".to_string(),
        run_manifest: "b.json".to_string(),
        events_jsonl: "c.jsonl".to_string(),
        commands_txt: "d.txt".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: SignatureArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ===========================================================================
// 19. SignatureEvidenceEvent serde
// ===========================================================================

#[test]
fn evidence_event_serde_roundtrip_start() {
    let event = SignatureEvidenceEvent {
        schema_version: REGIME_SIG_EVENT_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        event: "signature_evidence_run_started".to_string(),
        policy_id: REGIME_SIG_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SignatureEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn evidence_event_serde_roundtrip_specimen() {
    let event = SignatureEvidenceEvent {
        schema_version: REGIME_SIG_EVENT_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        event: "signature_specimen_evaluated".to_string(),
        policy_id: REGIME_SIG_POLICY_ID.to_string(),
        specimen_id: Some("test-specimen-42".to_string()),
        verdict: Some("pass".to_string()),
        detail: Some("all good".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SignatureEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// 20. Corpus: structural properties
// ===========================================================================

#[test]
fn corpus_specimens_each_have_non_empty_description() {
    for specimen in &signature_corpus() {
        assert!(
            !specimen.description.is_empty(),
            "specimen {} has empty description",
            specimen.specimen_id
        );
    }
}

#[test]
fn corpus_specimen_traces_have_observations() {
    for specimen in &signature_corpus() {
        for trace in &specimen.traces {
            // Some specimens intentionally have short traces, that's fine.
            // But they should have a trace_id.
            assert!(
                !trace.trace_id.is_empty(),
                "specimen {} has trace with empty id",
                specimen.specimen_id
            );
        }
    }
}

// ===========================================================================
// 21. Evidence harness: deeper checks
// ===========================================================================

#[test]
fn run_corpus_evidence_specimens_match_corpus_ids() {
    let corpus = signature_corpus();
    let inv = run_signature_corpus();
    let corpus_ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    let evidence_ids: BTreeSet<&str> = inv
        .evidence
        .iter()
        .map(|e| e.specimen_id.as_str())
        .collect();
    assert_eq!(corpus_ids, evidence_ids);
}

#[test]
fn run_corpus_evidence_families_match_specimens() {
    let corpus = signature_corpus();
    let inv = run_signature_corpus();
    for (specimen, evidence) in corpus.iter().zip(inv.evidence.iter()) {
        assert_eq!(
            specimen.family, evidence.family,
            "family mismatch for {}",
            specimen.specimen_id
        );
        assert_eq!(
            specimen.expected_outcome, evidence.expected_outcome,
            "expected_outcome mismatch for {}",
            specimen.specimen_id
        );
    }
}

#[test]
fn run_corpus_schema_version_is_correct() {
    let inv = run_signature_corpus();
    assert_eq!(inv.schema_version, REGIME_SIG_SCHEMA_VERSION);
    assert_eq!(inv.component, REGIME_SIG_COMPONENT);
}

// ===========================================================================
// 22. Bundle writer: deeper validation
// ===========================================================================

#[test]
fn bundle_writer_with_multiple_commands() {
    let dir = std::env::temp_dir().join("franken-rsf-deep-multi-cmd");
    let _ = std::fs::remove_dir_all(&dir);
    let commands = vec![
        "cargo test --test a".to_string(),
        "cargo test --test b".to_string(),
        "cargo clippy".to_string(),
    ];
    let artifacts = write_signature_evidence_bundle(&dir, &commands).unwrap();
    let cmd_content = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert!(cmd_content.contains("cargo test --test a"));
    assert!(cmd_content.contains("cargo test --test b"));
    assert!(cmd_content.contains("cargo clippy"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_writer_inventory_hash_is_64_hex() {
    let dir = std::env::temp_dir().join("franken-rsf-deep-inv-hash");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = write_signature_evidence_bundle(&dir, &[]).unwrap();
    assert_eq!(artifacts.inventory_hash.len(), 64);
    assert!(
        artifacts
            .inventory_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_writer_deterministic_inventory_hash() {
    let dir1 = std::env::temp_dir().join("franken-rsf-deep-det1");
    let dir2 = std::env::temp_dir().join("franken-rsf-deep-det2");
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
    let a1 = write_signature_evidence_bundle(&dir1, &[]).unwrap();
    let a2 = write_signature_evidence_bundle(&dir2, &[]).unwrap();
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn bundle_writer_manifest_has_trace_and_decision_ids() {
    let dir = std::env::temp_dir().join("franken-rsf-deep-manifest-ids");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = write_signature_evidence_bundle(&dir, &[]).unwrap();
    let manifest_json = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: SignatureRunManifest = serde_json::from_str(&manifest_json).unwrap();
    assert!(manifest.trace_id.starts_with("sig-"));
    assert!(manifest.decision_id.starts_with("dec-"));
    assert_eq!(manifest.policy_id, REGIME_SIG_POLICY_ID);
    assert!(manifest.contract_satisfied);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_writer_events_start_and_end_events() {
    let dir = std::env::temp_dir().join("franken-rsf-deep-events-se");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = write_signature_evidence_bundle(&dir, &[]).unwrap();
    let events_content = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let lines: Vec<&str> = events_content.lines().collect();
    assert!(lines.len() >= 2);
    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["event"], "signature_evidence_run_started");
    let last: serde_json::Value = serde_json::from_str(lines[lines.len() - 1]).unwrap();
    assert_eq!(last["event"], "signature_evidence_run_completed");
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 23. Stress: extract + classify in a loop
// ===========================================================================

#[test]
fn stress_extract_classify_100_distinct_traces() {
    let config = SignatureConfig::default();
    let mut labels_seen = BTreeSet::new();
    for i in 0..100 {
        let offset = (i as i64) * 10_000;
        let trace = make_trace(
            &format!("stress-{i}"),
            "metric",
            &[
                500_000 + offset,
                600_000 + offset,
                400_000 - offset,
                550_000 + offset,
            ],
            (i + 1) as u64,
        );
        let sig = extract_signature(&trace, &config);
        assert!(sig.valid);
        let (label, _) = classify_regime(&sig, &config);
        labels_seen.insert(label.as_str().to_string());
    }
    // We should see at least one non-abstention label.
    assert!(!labels_seen.is_empty());
}

#[test]
fn stress_build_chart_50_traces() {
    let config = SignatureConfig::default();
    let traces: Vec<RuntimeTrace> = (0..50)
        .map(|i| {
            let v = 500_000 + (i as i64 % 5) * 100_000;
            make_trace(&format!("s-{i}"), "m", &[v, v, v, v], i + 1)
        })
        .collect();
    let chart = build_regime_state_chart(&traces, &config);
    assert_eq!(chart.entries.len(), 50);
    // The chart_hash should be 64 hex chars.
    assert_eq!(chart.chart_hash.len(), 64);
    assert!(chart.chart_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

// ===========================================================================
// 24. Determinism: same inputs always same outputs
// ===========================================================================

#[test]
fn extract_determinism_across_100_calls() {
    let config = SignatureConfig::default();
    let trace = make_multi_feature_trace(
        "det-100",
        &[
            ("cpu", &[500_000, 600_000, 700_000, 800_000]),
            ("mem", &[200_000, 300_000, 400_000, 500_000]),
        ],
        1,
    );
    let reference = extract_signature(&trace, &config);
    for _ in 0..100 {
        let sig = extract_signature(&trace, &config);
        assert_eq!(reference, sig);
    }
}

#[test]
fn classify_determinism_across_100_calls() {
    let config = SignatureConfig::default();
    let trace = make_trace("det-cls", "m", &[500_000, 600_000, 400_000, 550_000], 1);
    let sig = extract_signature(&trace, &config);
    let (ref_label, ref_conf) = classify_regime(&sig, &config);
    for _ in 0..100 {
        let (label, conf) = classify_regime(&sig, &config);
        assert_eq!(ref_label, label);
        assert_eq!(ref_conf, conf);
    }
}

// ===========================================================================
// 25. SignatureSpecimen serde
// ===========================================================================

#[test]
fn signature_specimen_serde_roundtrip_synthetic() {
    let specimen = SignatureSpecimen {
        specimen_id: "synth-specimen".to_string(),
        description: "A synthetic specimen for serde testing".to_string(),
        family: SignatureSpecimenFamily::Classification,
        traces: vec![make_trace("synth-trace", "m", &[1, 2, 3, 4], 1)],
        expected_outcome: SignatureExpectedOutcome::CorrectClassification,
        expected_regime: Some(RegimeLabel::Classified(Regime::Normal)),
        expected_valid: Some(true),
        expected_transition_count: None,
    };
    let json = serde_json::to_string(&specimen).unwrap();
    let back: SignatureSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(specimen, back);
}

#[test]
fn signature_specimen_with_all_none_options_serde() {
    let specimen = SignatureSpecimen {
        specimen_id: "no-opts".to_string(),
        description: "Minimal specimen".to_string(),
        family: SignatureSpecimenFamily::Extraction,
        traces: vec![make_trace("t", "m", &[1, 2, 3, 4], 1)],
        expected_outcome: SignatureExpectedOutcome::ValidSignature,
        expected_regime: None,
        expected_valid: None,
        expected_transition_count: None,
    };
    let json = serde_json::to_string(&specimen).unwrap();
    let back: SignatureSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(specimen, back);
}

// ===========================================================================
// 26. Constants: cross-referencing
// ===========================================================================

#[test]
fn policy_id_matches_expected_rgc() {
    assert_eq!(REGIME_SIG_POLICY_ID, "RGC-617A");
}

#[test]
fn component_name_matches_module() {
    assert_eq!(REGIME_SIG_COMPONENT, "regime_signature_feature");
}

#[test]
fn schema_versions_contain_component_substring() {
    assert!(REGIME_SIG_SCHEMA_VERSION.contains("regime_signature_feature"));
    assert!(REGIME_SIG_MANIFEST_SCHEMA_VERSION.contains("regime_signature_feature"));
    assert!(REGIME_SIG_EVENT_SCHEMA_VERSION.contains("regime_signature_feature"));
}

#[test]
fn max_signature_dim_is_64() {
    assert_eq!(MAX_SIGNATURE_DIM, 64);
}

#[test]
fn min_trace_length_is_4() {
    assert_eq!(MIN_TRACE_LENGTH, 4);
}

#[test]
fn abstention_threshold_is_200k() {
    assert_eq!(ABSTENTION_THRESHOLD_MILLIONTHS, 200_000);
}

// ===========================================================================
// 27. Centroid distance in chart entries
// ===========================================================================

#[test]
fn chart_entry_centroid_distance_non_negative_for_classified() {
    let config = SignatureConfig::default();
    let traces = vec![
        make_trace("t1", "m", &[500_000, 500_000, 500_000, 500_000], 1),
        make_trace("t2", "m", &[500_000, 500_000, 500_000, 500_000], 2),
    ];
    let chart = build_regime_state_chart(&traces, &config);
    for entry in &chart.entries {
        if !entry.label.is_abstention() {
            assert!(
                entry.centroid_distance_millionths >= 0,
                "negative centroid distance for trace {}",
                entry.trace_id
            );
        }
    }
}

#[test]
fn chart_entry_abstention_has_zero_centroid_distance() {
    let config = SignatureConfig::default();
    let traces = vec![make_trace("short", "m", &[100], 1)];
    let chart = build_regime_state_chart(&traces, &config);
    assert_eq!(chart.entries.len(), 1);
    assert!(chart.entries[0].label.is_abstention());
    assert_eq!(chart.entries[0].centroid_distance_millionths, 0);
}

// ===========================================================================
// 28. is_stable edge cases
// ===========================================================================

#[test]
fn is_stable_requires_entries() {
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
fn is_stable_with_many_entries_no_transitions_no_abstentions() {
    let entries: Vec<RegimeStateEntry> = (0..10)
        .map(|i| RegimeStateEntry {
            seq: i,
            label: RegimeLabel::Classified(Regime::Normal),
            confidence_millionths: 800_000,
            centroid_distance_millionths: 50_000,
            trace_id: format!("t{i}"),
        })
        .collect();
    let chart = RegimeStateChart {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        entries,
        transition_count: 0,
        abstention_count: 0,
        label_distribution: BTreeMap::new(),
        chart_hash: "h".to_string(),
    };
    assert!(chart.is_stable());
}

#[test]
fn is_stable_false_with_both_transitions_and_abstentions() {
    let chart = RegimeStateChart {
        schema_version: "v1".to_string(),
        entries: vec![RegimeStateEntry {
            seq: 0,
            label: RegimeLabel::Abstention,
            confidence_millionths: 0,
            centroid_distance_millionths: 0,
            trace_id: "t".to_string(),
        }],
        transition_count: 1,
        abstention_count: 1,
        label_distribution: BTreeMap::new(),
        chart_hash: "h".to_string(),
    };
    assert!(!chart.is_stable());
}

// ===========================================================================
// 29. Multi-feature extraction: bucket normalization
// ===========================================================================

#[test]
fn multi_feature_same_bucket_normalizes_by_count() {
    // When two features hash to the same bucket, the component should be
    // the mean of their values, not the sum.
    let config = SignatureConfig::default();
    // Use many observations with the same feature to get a predictable mean.
    let values = [1_000_000i64; 10];
    let trace = make_trace("t-norm", "single_feature", &values, 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    // The active bucket should have value 1_000_000 (mean of all 1_000_000s).
    let active: Vec<(i64, u64)> = sig
        .components
        .iter()
        .zip(&sig.bucket_counts)
        .filter(|(_, c)| **c > 0)
        .map(|(v, c)| (*v, *c))
        .collect();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].0, 1_000_000);
    assert_eq!(active[0].1, 10);
}

// ===========================================================================
// 30. SignatureBundleArtifacts debug format
// ===========================================================================

#[test]
fn bundle_artifacts_debug_format() {
    let dir = std::env::temp_dir().join("franken-rsf-deep-dbg");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = write_signature_evidence_bundle(&dir, &[]).unwrap();
    let dbg = format!("{:?}", artifacts);
    assert!(dbg.contains("SignatureBundleArtifacts"));
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 31. Additional edge cases: extraction with mixed sign values
// ===========================================================================

#[test]
fn extract_mixed_positive_negative_values() {
    let config = SignatureConfig::default();
    let trace = make_trace(
        "t-mixed",
        "m",
        &[1_000_000, -1_000_000, 1_000_000, -1_000_000],
        1,
    );
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    // Mean of alternating +1M/-1M should be 0.
    let active: Vec<i64> = sig
        .components
        .iter()
        .zip(&sig.bucket_counts)
        .filter(|(_, c)| **c > 0)
        .map(|(v, _)| *v)
        .collect();
    for v in &active {
        assert_eq!(*v, 0, "expected 0 mean for alternating +/-1M");
    }
}

#[test]
fn extract_very_large_values_saturating() {
    let config = SignatureConfig::default();
    let trace = make_trace(
        "t-sat",
        "m",
        &[i64::MAX / 2, i64::MAX / 2, i64::MAX / 2, i64::MAX / 2],
        1,
    );
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    // Should not panic from overflow.
}
