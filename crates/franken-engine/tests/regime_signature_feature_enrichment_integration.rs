//! Enrichment integration tests for `regime_signature_feature`.
//!
//! Covers serde roundtrips, signature extraction, L1/cosine metrics,
//! regime classification, state chart construction, edge cases,
//! content-hash determinism, and constant validation.
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
use std::collections::BTreeSet;

use frankenengine_engine::regime_detector::Regime;
use frankenengine_engine::regime_signature_feature::*;
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

fn default_config() -> SignatureConfig {
    SignatureConfig::default()
}

fn make_signature(
    trace_id: &str,
    dim: usize,
    components: Vec<i64>,
    bucket_counts: Vec<u64>,
    valid: bool,
) -> TraceSignature {
    TraceSignature {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        dimension: dim,
        components,
        bucket_counts,
        observation_count: 4,
        feature_count: 1,
        valid,
        signature_hash: "test-hash".to_string(),
    }
}

// ---------------------------------------------------------------------------
// 1. TraceObservation serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_trace_observation_serde_roundtrip_basic() {
    let obs = TraceObservation {
        seq: 0,
        feature_name: "cpu_usage".to_string(),
        value_millionths: 750_000,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: TraceObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn enrichment_trace_observation_serde_roundtrip_negative_value() {
    let obs = TraceObservation {
        seq: 99,
        feature_name: "temperature_delta".to_string(),
        value_millionths: -300_000,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: TraceObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
    assert_eq!(back.value_millionths, -300_000);
}

#[test]
fn enrichment_trace_observation_serde_roundtrip_zero_value() {
    let obs = TraceObservation {
        seq: 42,
        feature_name: "idle_count".to_string(),
        value_millionths: 0,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: TraceObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs.value_millionths, back.value_millionths);
}

#[test]
fn enrichment_trace_observation_serde_roundtrip_large_seq() {
    let obs = TraceObservation {
        seq: u64::MAX,
        feature_name: "max_seq".to_string(),
        value_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let back: TraceObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

// ---------------------------------------------------------------------------
// 2. RuntimeTrace serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runtime_trace_serde_roundtrip_single_feature() {
    let trace = make_trace(
        "trace-001",
        "mem_usage",
        &[100_000, 200_000, 300_000, 400_000],
        5,
    );
    let json = serde_json::to_string(&trace).unwrap();
    let back: RuntimeTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, back);
}

#[test]
fn enrichment_runtime_trace_serde_roundtrip_multi_feature() {
    let trace = make_multi_feature_trace(
        "trace-multi",
        &[
            ("cpu", &[500_000, 600_000]),
            ("mem", &[300_000, 400_000]),
            ("gc_pause", &[10_000, 20_000]),
        ],
        10,
    );
    let json = serde_json::to_string(&trace).unwrap();
    let back: RuntimeTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, back);
    assert_eq!(back.observations.len(), 6);
}

#[test]
fn enrichment_runtime_trace_serde_roundtrip_empty_observations() {
    let trace = RuntimeTrace {
        trace_id: "empty-trace".to_string(),
        observations: vec![],
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&trace).unwrap();
    let back: RuntimeTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, back);
    assert!(back.observations.is_empty());
}

// ---------------------------------------------------------------------------
// 3. TraceSignature l1_distance
// ---------------------------------------------------------------------------

#[test]
fn enrichment_l1_distance_same_dimension_zero_for_identical() {
    let sig = make_signature("a", 4, vec![100, 200, 300, 400], vec![1, 1, 1, 1], true);
    assert_eq!(sig.l1_distance(&sig), 0);
}

#[test]
fn enrichment_l1_distance_same_dimension_computes_sum_of_abs_diffs() {
    let sig_a = make_signature("a", 4, vec![100, 200, 300, 400], vec![1, 1, 1, 1], true);
    let sig_b = make_signature("b", 4, vec![150, 250, 250, 450], vec![1, 1, 1, 1], true);
    // |100-150| + |200-250| + |300-250| + |400-450| = 50+50+50+50 = 200
    assert_eq!(sig_a.l1_distance(&sig_b), 200);
}

#[test]
fn enrichment_l1_distance_different_dimensions_returns_max() {
    let sig_a = make_signature("a", 3, vec![100, 200, 300], vec![1, 1, 1], true);
    let sig_b = make_signature("b", 4, vec![100, 200, 300, 400], vec![1, 1, 1, 1], true);
    assert_eq!(sig_a.l1_distance(&sig_b), i64::MAX);
    assert_eq!(sig_b.l1_distance(&sig_a), i64::MAX);
}

#[test]
fn enrichment_l1_distance_symmetric() {
    let sig_a = make_signature(
        "a",
        4,
        vec![0, 500_000, 1_000_000, 0],
        vec![1, 1, 1, 1],
        true,
    );
    let sig_b = make_signature(
        "b",
        4,
        vec![1_000_000, 0, 500_000, 500_000],
        vec![1, 1, 1, 1],
        true,
    );
    assert_eq!(sig_a.l1_distance(&sig_b), sig_b.l1_distance(&sig_a));
}

// ---------------------------------------------------------------------------
// 4. TraceSignature cosine_similarity edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cosine_similarity_identical_vectors_near_million() {
    let sig = make_signature(
        "a",
        4,
        vec![500_000, 600_000, 700_000, 800_000],
        vec![1, 1, 1, 1],
        true,
    );
    let cos = sig.cosine_similarity(&sig);
    assert!(
        cos > 900_000,
        "identical vectors should have cosine ~1M, got {cos}"
    );
}

#[test]
fn enrichment_cosine_similarity_zero_vector_returns_zero() {
    let zero_sig = make_signature("z", 4, vec![0, 0, 0, 0], vec![1, 1, 1, 1], true);
    let nonzero_sig = make_signature(
        "nz",
        4,
        vec![500_000, 600_000, 700_000, 800_000],
        vec![1, 1, 1, 1],
        true,
    );
    assert_eq!(zero_sig.cosine_similarity(&nonzero_sig), 0);
    assert_eq!(nonzero_sig.cosine_similarity(&zero_sig), 0);
}

#[test]
fn enrichment_cosine_similarity_both_zero_vectors_returns_zero() {
    let z1 = make_signature("z1", 4, vec![0, 0, 0, 0], vec![1, 1, 1, 1], true);
    let z2 = make_signature("z2", 4, vec![0, 0, 0, 0], vec![1, 1, 1, 1], true);
    assert_eq!(z1.cosine_similarity(&z2), 0);
}

#[test]
fn enrichment_cosine_similarity_different_dimensions_returns_zero() {
    let sig_a = make_signature("a", 3, vec![500_000, 600_000, 700_000], vec![1, 1, 1], true);
    let sig_b = make_signature(
        "b",
        4,
        vec![500_000, 600_000, 700_000, 800_000],
        vec![1, 1, 1, 1],
        true,
    );
    assert_eq!(sig_a.cosine_similarity(&sig_b), 0);
}

#[test]
fn enrichment_cosine_similarity_symmetric() {
    let sig_a = make_signature(
        "a",
        4,
        vec![100_000, 200_000, 300_000, 400_000],
        vec![1, 1, 1, 1],
        true,
    );
    let sig_b = make_signature(
        "b",
        4,
        vec![400_000, 300_000, 200_000, 100_000],
        vec![1, 1, 1, 1],
        true,
    );
    assert_eq!(
        sig_a.cosine_similarity(&sig_b),
        sig_b.cosine_similarity(&sig_a)
    );
}

// ---------------------------------------------------------------------------
// 5. RegimeLabel all-variant serde roundtrips, Display, as_str
// ---------------------------------------------------------------------------

#[test]
fn enrichment_regime_label_serde_all_classified_roundtrip() {
    for &label in RegimeLabel::ALL_CLASSIFIED {
        let json = serde_json::to_string(&label).unwrap();
        let back: RegimeLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(label, back, "roundtrip failed for {label:?}");
    }
}

#[test]
fn enrichment_regime_label_serde_abstention_roundtrip() {
    let label = RegimeLabel::Abstention;
    let json = serde_json::to_string(&label).unwrap();
    let back: RegimeLabel = serde_json::from_str(&json).unwrap();
    assert_eq!(label, back);
}

#[test]
fn enrichment_regime_label_display_uniqueness() {
    let mut display_strings = BTreeSet::new();
    for &label in RegimeLabel::ALL_CLASSIFIED {
        let s = label.to_string();
        assert!(
            display_strings.insert(s.clone()),
            "duplicate Display for {label:?}: {s}"
        );
    }
    let abst_str = RegimeLabel::Abstention.to_string();
    assert!(
        display_strings.insert(abst_str.clone()),
        "Abstention collides: {abst_str}"
    );
    // 5 classified + 1 abstention = 6 unique strings
    assert_eq!(display_strings.len(), 6);
}

#[test]
fn enrichment_regime_label_as_str_matches_display() {
    for &label in RegimeLabel::ALL_CLASSIFIED {
        assert_eq!(label.as_str(), label.to_string().as_str());
    }
    let abst = RegimeLabel::Abstention;
    assert_eq!(abst.as_str(), abst.to_string().as_str());
}

#[test]
fn enrichment_regime_label_is_abstention_correct() {
    assert!(RegimeLabel::Abstention.is_abstention());
    for &label in RegimeLabel::ALL_CLASSIFIED {
        assert!(!label.is_abstention(), "{label:?} should not be abstention");
    }
}

#[test]
fn enrichment_regime_label_as_str_known_values() {
    assert_eq!(RegimeLabel::Classified(Regime::Normal).as_str(), "normal");
    assert_eq!(
        RegimeLabel::Classified(Regime::Elevated).as_str(),
        "elevated"
    );
    assert_eq!(RegimeLabel::Classified(Regime::Attack).as_str(), "attack");
    assert_eq!(
        RegimeLabel::Classified(Regime::Degraded).as_str(),
        "degraded"
    );
    assert_eq!(
        RegimeLabel::Classified(Regime::Recovery).as_str(),
        "recovery"
    );
    assert_eq!(RegimeLabel::Abstention.as_str(), "abstention");
}

// ---------------------------------------------------------------------------
// 6. Signature extraction: valid traces and too-short traces
// ---------------------------------------------------------------------------

#[test]
fn enrichment_extract_signature_valid_trace_produces_valid_sig() {
    let config = default_config();
    let trace = make_trace("valid", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.dimension, MAX_SIGNATURE_DIM);
    assert_eq!(sig.components.len(), MAX_SIGNATURE_DIM);
    assert_eq!(sig.bucket_counts.len(), MAX_SIGNATURE_DIM);
    assert_eq!(sig.observation_count, 4);
    assert!(sig.feature_count >= 1);
}

#[test]
fn enrichment_extract_signature_too_short_one_obs() {
    let config = default_config();
    let trace = make_trace("short-1", "cpu", &[500_000], 1);
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
    assert_eq!(sig.observation_count, 1);
    assert_eq!(sig.feature_count, 0);
    assert!(sig.components.iter().all(|&c| c == 0));
    assert!(sig.bucket_counts.iter().all(|&c| c == 0));
}

#[test]
fn enrichment_extract_signature_too_short_three_obs() {
    let config = default_config();
    let trace = make_trace("short-3", "cpu", &[500_000, 600_000, 400_000], 1);
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
    assert_eq!(sig.observation_count, 3);
}

#[test]
fn enrichment_extract_signature_exactly_min_length_valid() {
    let config = default_config();
    let values: Vec<i64> = (0..MIN_TRACE_LENGTH as i64)
        .map(|i| 500_000 + i * 10_000)
        .collect();
    let trace = make_trace("exact-min", "cpu", &values, 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.observation_count, MIN_TRACE_LENGTH as u64);
}

#[test]
fn enrichment_extract_signature_empty_trace_invalid() {
    let config = default_config();
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
fn enrichment_extract_signature_large_trace_valid() {
    let config = default_config();
    let values: Vec<i64> = (0..200).map(|i| 400_000 + (i % 20) * 10_000).collect();
    let trace = make_trace("large", "throughput", &values, 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.observation_count, 200);
    assert_eq!(sig.feature_count, 1);
}

// ---------------------------------------------------------------------------
// 7. Constants have expected values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_max_signature_dim() {
    assert_eq!(MAX_SIGNATURE_DIM, 64);
}

#[test]
fn enrichment_constants_min_trace_length() {
    assert_eq!(MIN_TRACE_LENGTH, 4);
}

#[test]
fn enrichment_constants_abstention_threshold() {
    assert_eq!(ABSTENTION_THRESHOLD_MILLIONTHS, 200_000);
}

#[test]
fn enrichment_constants_schema_versions_contain_component_name() {
    assert!(REGIME_SIG_SCHEMA_VERSION.contains("regime_signature_feature"));
    assert!(REGIME_SIG_MANIFEST_SCHEMA_VERSION.contains("regime_signature_feature"));
    assert!(REGIME_SIG_EVENT_SCHEMA_VERSION.contains("regime_signature_feature"));
}

#[test]
fn enrichment_constants_policy_id_nonempty() {
    assert!(!REGIME_SIG_POLICY_ID.is_empty());
    assert_eq!(REGIME_SIG_POLICY_ID, "RGC-617A");
}

#[test]
fn enrichment_constants_component_name() {
    assert_eq!(REGIME_SIG_COMPONENT, "regime_signature_feature");
}

// ---------------------------------------------------------------------------
// 8. All struct serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_trace_signature_serde_roundtrip() {
    let config = default_config();
    let trace = make_trace("serde-sig", "cpu", &[100_000, 200_000, 300_000, 400_000], 1);
    let sig = extract_signature(&trace, &config);
    let json = serde_json::to_string(&sig).unwrap();
    let back: TraceSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig, back);
}

#[test]
fn enrichment_regime_state_entry_serde_roundtrip() {
    let entry = RegimeStateEntry {
        seq: 7,
        label: RegimeLabel::Classified(Regime::Recovery),
        confidence_millionths: 650_000,
        centroid_distance_millionths: 120_000,
        trace_id: "trace-recovery-1".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: RegimeStateEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_regime_state_chart_serde_roundtrip() {
    let mut label_dist = BTreeMap::new();
    label_dist.insert("normal".to_string(), 3u64);
    label_dist.insert("elevated".to_string(), 1u64);
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
                label: RegimeLabel::Classified(Regime::Elevated),
                confidence_millionths: 600_000,
                centroid_distance_millionths: 200_000,
                trace_id: "t1".to_string(),
            },
        ],
        transition_count: 1,
        abstention_count: 0,
        label_distribution: label_dist,
        chart_hash: "abc123".to_string(),
    };
    let json = serde_json::to_string(&chart).unwrap();
    let back: RegimeStateChart = serde_json::from_str(&json).unwrap();
    assert_eq!(chart, back);
}

#[test]
fn enrichment_signature_config_serde_roundtrip() {
    let config = default_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: SignatureConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_regime_centroid_serde_roundtrip() {
    let centroid = RegimeCentroid {
        regime: Regime::Degraded,
        components: vec![250_000; 16],
        radius_millionths: 1_500_000,
    };
    let json = serde_json::to_string(&centroid).unwrap();
    let back: RegimeCentroid = serde_json::from_str(&json).unwrap();
    assert_eq!(centroid, back);
}

#[test]
fn enrichment_signature_evidence_inventory_serde_roundtrip() {
    let inv = run_signature_corpus();
    let json = serde_json::to_string(&inv).unwrap();
    let back: SignatureEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn enrichment_signature_specimen_serde_roundtrip() {
    let specimen = SignatureSpecimen {
        specimen_id: "serde-specimen".into(),
        description: "A test specimen for serde".into(),
        family: SignatureSpecimenFamily::Similarity,
        traces: vec![make_trace("t", "x", &[1, 2, 3, 4], 1)],
        expected_outcome: SignatureExpectedOutcome::SimilarityComputed,
        expected_regime: None,
        expected_valid: Some(true),
        expected_transition_count: None,
    };
    let json = serde_json::to_string(&specimen).unwrap();
    let back: SignatureSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(specimen, back);
}

#[test]
fn enrichment_signature_evidence_event_serde_roundtrip() {
    let event = SignatureEvidenceEvent {
        schema_version: REGIME_SIG_EVENT_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        event: "enrichment_test".to_string(),
        policy_id: REGIME_SIG_POLICY_ID.to_string(),
        specimen_id: Some("spec-42".to_string()),
        verdict: Some("pass".to_string()),
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SignatureEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_signature_run_manifest_serde_roundtrip() {
    let manifest = SignatureRunManifest {
        schema_version: REGIME_SIG_MANIFEST_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        trace_id: "sig-enrichment-test".to_string(),
        decision_id: "dec-enrichment-test".to_string(),
        policy_id: REGIME_SIG_POLICY_ID.to_string(),
        inventory_hash: "abcdef0123456789".to_string(),
        specimen_count: 14,
        pass_count: 14,
        fail_count: 0,
        contract_satisfied: true,
        artifact_paths: SignatureArtifactPaths {
            evidence_inventory: "inventory.json".to_string(),
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
fn enrichment_signature_verdict_serde_roundtrip() {
    for verdict in [SignatureVerdict::Pass, SignatureVerdict::Fail] {
        let json = serde_json::to_string(&verdict).unwrap();
        let back: SignatureVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, back);
    }
}

#[test]
fn enrichment_expected_outcome_serde_roundtrip_all_variants() {
    let outcomes = [
        SignatureExpectedOutcome::ValidSignature,
        SignatureExpectedOutcome::InvalidSignature,
        SignatureExpectedOutcome::CorrectClassification,
        SignatureExpectedOutcome::Abstention,
        SignatureExpectedOutcome::StableChart,
        SignatureExpectedOutcome::TransitionDetected,
        SignatureExpectedOutcome::SimilarityComputed,
    ];
    for outcome in outcomes {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: SignatureExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}

#[test]
fn enrichment_specimen_family_serde_roundtrip_all_variants() {
    for &family in SignatureSpecimenFamily::ALL {
        let json = serde_json::to_string(&family).unwrap();
        let back: SignatureSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(family, back);
    }
}

// ---------------------------------------------------------------------------
// 9. Edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_case_single_observation_extraction() {
    let config = default_config();
    let trace = make_trace("single", "metric", &[999_999], 1);
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
    assert_eq!(sig.observation_count, 1);
    // Invalid signature has all-zero components.
    assert!(sig.components.iter().all(|&c| c == 0));
}

#[test]
fn enrichment_edge_case_max_dim_boundary_extraction() {
    // Use a config with max_dim = MAX_SIGNATURE_DIM and a trace with exactly
    // MAX_SIGNATURE_DIM unique feature names to try to fill every bucket.
    let config = default_config();
    let features: Vec<(String, Vec<i64>)> = (0..MAX_SIGNATURE_DIM)
        .map(|i| (format!("feature_{i}"), vec![500_000i64]))
        .collect();
    let feature_refs: Vec<(&str, &[i64])> = features
        .iter()
        .map(|(name, vals)| (name.as_str(), vals.as_slice()))
        .collect();
    let trace = make_multi_feature_trace("max-dim", &feature_refs, 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.dimension, MAX_SIGNATURE_DIM);
    assert_eq!(sig.observation_count, MAX_SIGNATURE_DIM as u64);
    // At least some buckets should be populated.
    let populated: usize = sig.bucket_counts.iter().filter(|&&c| c > 0).count();
    assert!(populated > 0);
}

#[test]
fn enrichment_edge_case_negative_values_extraction() {
    let config = default_config();
    let trace = make_trace(
        "neg",
        "metric",
        &[-1_000_000, -500_000, -250_000, -100_000],
        1,
    );
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    // The active bucket should have a negative mean.
    let active_components: Vec<i64> = sig
        .components
        .iter()
        .zip(&sig.bucket_counts)
        .filter(|&(_, &count)| count > 0)
        .map(|(&comp, _)| comp)
        .collect();
    assert!(!active_components.is_empty());
    for &comp in &active_components {
        assert!(comp < 0, "expected negative, got {comp}");
    }
}

#[test]
fn enrichment_edge_case_classify_invalid_signature_abstains() {
    let config = default_config();
    let trace = make_trace("invalid", "x", &[1], 1);
    let sig = extract_signature(&trace, &config);
    assert!(!sig.valid);
    let (label, confidence) = classify_regime(&sig, &config);
    assert!(label.is_abstention());
    assert_eq!(confidence, 0);
}

#[test]
fn enrichment_edge_case_all_zero_observations_classification() {
    let config = default_config();
    let trace = make_trace("zeros", "metric", &[0, 0, 0, 0], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    // All active buckets are zero, so norm is zero => cosine returns 0.
    // Classification should still produce some result (abstention or classified).
    let (label, _confidence) = classify_regime(&sig, &config);
    // Just verify it doesn't panic and produces a valid label.
    let _ = label.as_str();
}

#[test]
fn enrichment_edge_case_state_chart_short_traces_yield_abstentions() {
    let config = default_config();
    let traces = vec![
        make_trace("s1", "x", &[1], 1),
        make_trace("s2", "x", &[2], 2),
        make_trace("s3", "x", &[3], 3),
    ];
    let chart = build_regime_state_chart(&traces, &config);
    assert_eq!(chart.entries.len(), 3);
    assert_eq!(chart.abstention_count, 3);
    // All labels should be abstention.
    for entry in &chart.entries {
        assert!(entry.label.is_abstention());
    }
}

#[test]
fn enrichment_edge_case_state_chart_empty_traces() {
    let config = default_config();
    let chart = build_regime_state_chart(&[], &config);
    assert!(chart.entries.is_empty());
    assert_eq!(chart.transition_count, 0);
    assert_eq!(chart.abstention_count, 0);
    assert!(!chart.is_stable()); // Empty chart is not stable.
}

#[test]
fn enrichment_edge_case_bucket_counts_sum_to_observation_count() {
    let config = default_config();
    let trace = make_multi_feature_trace(
        "bucket-sum",
        &[
            ("alpha", &[100_000, 200_000, 300_000]),
            ("beta", &[400_000, 500_000]),
            ("gamma", &[600_000]),
        ],
        1,
    );
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    let total: u64 = sig.bucket_counts.iter().sum();
    assert_eq!(total, sig.observation_count);
    assert_eq!(total, 6);
}

// ---------------------------------------------------------------------------
// 10. Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_signature_deterministic() {
    let config = default_config();
    let trace = make_trace("det-hash", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
    let sig1 = extract_signature(&trace, &config);
    let sig2 = extract_signature(&trace, &config);
    assert_eq!(sig1.signature_hash, sig2.signature_hash);
    assert!(!sig1.signature_hash.is_empty());
}

#[test]
fn enrichment_content_hash_different_traces_different_hashes() {
    let config = default_config();
    let trace_a = make_trace("a", "cpu", &[100_000, 200_000, 300_000, 400_000], 1);
    let trace_b = make_trace("b", "cpu", &[500_000, 600_000, 700_000, 800_000], 1);
    let sig_a = extract_signature(&trace_a, &config);
    let sig_b = extract_signature(&trace_b, &config);
    assert_ne!(sig_a.signature_hash, sig_b.signature_hash);
}

#[test]
fn enrichment_content_hash_state_chart_deterministic() {
    let config = default_config();
    let traces = vec![
        make_trace("t1", "cpu", &[500_000, 510_000, 490_000, 505_000], 1),
        make_trace("t2", "cpu", &[600_000, 610_000, 590_000, 605_000], 2),
    ];
    let chart1 = build_regime_state_chart(&traces, &config);
    let chart2 = build_regime_state_chart(&traces, &config);
    assert_eq!(chart1.chart_hash, chart2.chart_hash);
    assert!(!chart1.chart_hash.is_empty());
}

#[test]
fn enrichment_content_hash_invalid_signature_deterministic() {
    let config = default_config();
    let trace = make_trace("short-hash", "x", &[1, 2], 1);
    let sig1 = extract_signature(&trace, &config);
    let sig2 = extract_signature(&trace, &config);
    assert!(!sig1.valid);
    assert_eq!(sig1.signature_hash, sig2.signature_hash);
}

#[test]
fn enrichment_content_hash_corpus_run_deterministic() {
    let inv1 = run_signature_corpus();
    let inv2 = run_signature_corpus();
    assert_eq!(inv1, inv2);
    // All evidence hashes should match.
    for (e1, e2) in inv1.evidence.iter().zip(&inv2.evidence) {
        assert_eq!(e1.evidence_hash, e2.evidence_hash);
    }
}

// ---------------------------------------------------------------------------
// Additional coverage: classification, state chart stability, config
// ---------------------------------------------------------------------------

#[test]
fn enrichment_classify_normal_trace_not_abstention() {
    let config = default_config();
    let trace = make_multi_feature_trace(
        "normal",
        &[
            ("cpu", &[500_000, 510_000, 490_000, 500_000]),
            ("mem", &[500_000, 480_000, 520_000, 500_000]),
        ],
        1,
    );
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    let (label, confidence) = classify_regime(&sig, &config);
    assert!(!label.is_abstention());
    assert!(confidence > 0);
}

#[test]
fn enrichment_classify_with_empty_centroids_abstains() {
    let config = SignatureConfig {
        max_dim: MAX_SIGNATURE_DIM,
        min_trace_length: MIN_TRACE_LENGTH,
        abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
        centroids: vec![],
    };
    let trace = make_trace("t", "cpu", &[500_000, 500_000, 500_000, 500_000], 1);
    let sig = extract_signature(&trace, &config);
    let (label, _) = classify_regime(&sig, &config);
    assert!(label.is_abstention());
}

#[test]
fn enrichment_classify_mismatched_centroid_dim_abstains() {
    let config = SignatureConfig {
        max_dim: 8,
        min_trace_length: 2,
        abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
        centroids: vec![RegimeCentroid {
            regime: Regime::Normal,
            components: vec![500_000; 16], // 16 != 8
            radius_millionths: 2_000_000,
        }],
    };
    let trace = make_trace("t", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
    let sig = extract_signature(&trace, &config);
    assert_eq!(sig.dimension, 8);
    let (label, _) = classify_regime(&sig, &config);
    assert!(label.is_abstention());
}

#[test]
fn enrichment_state_chart_is_stable_single_classified_entry() {
    let chart = RegimeStateChart {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        entries: vec![RegimeStateEntry {
            seq: 0,
            label: RegimeLabel::Classified(Regime::Normal),
            confidence_millionths: 900_000,
            centroid_distance_millionths: 50_000,
            trace_id: "t-stable".to_string(),
        }],
        transition_count: 0,
        abstention_count: 0,
        label_distribution: {
            let mut m = BTreeMap::new();
            m.insert("normal".to_string(), 1);
            m
        },
        chart_hash: "stable-hash".to_string(),
    };
    assert!(chart.is_stable());
}

#[test]
fn enrichment_state_chart_not_stable_with_abstentions() {
    let chart = RegimeStateChart {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        entries: vec![RegimeStateEntry {
            seq: 0,
            label: RegimeLabel::Abstention,
            confidence_millionths: 0,
            centroid_distance_millionths: 0,
            trace_id: "t-abst".to_string(),
        }],
        transition_count: 0,
        abstention_count: 1,
        label_distribution: BTreeMap::new(),
        chart_hash: "h".to_string(),
    };
    assert!(!chart.is_stable());
}

#[test]
fn enrichment_state_chart_not_stable_with_transitions() {
    let chart = RegimeStateChart {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        entries: vec![],
        transition_count: 2,
        abstention_count: 0,
        label_distribution: BTreeMap::new(),
        chart_hash: "h".to_string(),
    };
    assert!(!chart.is_stable());
}

#[test]
fn enrichment_state_chart_label_distribution_sums_to_entries() {
    let config = default_config();
    let traces: Vec<RuntimeTrace> = (0..5)
        .map(|i| {
            make_trace(
                &format!("t{i}"),
                "cpu",
                &[500_000, 510_000, 490_000, 505_000],
                i + 1,
            )
        })
        .collect();
    let chart = build_regime_state_chart(&traces, &config);
    let dist_total: u64 = chart.label_distribution.values().sum();
    assert_eq!(dist_total, chart.entries.len() as u64);
}

#[test]
fn enrichment_state_chart_entries_have_sequential_seq_numbers() {
    let config = default_config();
    let traces: Vec<RuntimeTrace> = (0..4)
        .map(|i| {
            make_trace(
                &format!("t{i}"),
                "cpu",
                &[500_000, 500_000, 500_000, 500_000],
                i + 1,
            )
        })
        .collect();
    let chart = build_regime_state_chart(&traces, &config);
    for (i, entry) in chart.entries.iter().enumerate() {
        assert_eq!(entry.seq, i as u64, "entry {i} has wrong seq");
    }
}

#[test]
fn enrichment_config_default_centroids_cover_five_regimes() {
    let config = default_config();
    let regimes: BTreeSet<Regime> = config.centroids.iter().map(|c| c.regime).collect();
    assert_eq!(regimes.len(), 5);
    assert!(regimes.contains(&Regime::Normal));
    assert!(regimes.contains(&Regime::Elevated));
    assert!(regimes.contains(&Regime::Attack));
    assert!(regimes.contains(&Regime::Degraded));
    assert!(regimes.contains(&Regime::Recovery));
}

#[test]
fn enrichment_config_default_centroids_have_correct_dimension() {
    let config = default_config();
    for centroid in &config.centroids {
        assert_eq!(
            centroid.components.len(),
            config.max_dim,
            "centroid {:?} has wrong dimension",
            centroid.regime
        );
    }
}

#[test]
fn enrichment_config_default_centroids_positive_radius() {
    let config = default_config();
    for centroid in &config.centroids {
        assert!(
            centroid.radius_millionths > 0,
            "centroid {:?} should have positive radius",
            centroid.regime
        );
    }
}

#[test]
fn enrichment_corpus_all_specimens_pass() {
    let inv = run_signature_corpus();
    assert!(inv.contract_satisfied());
    assert_eq!(inv.fail_count, 0);
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
fn enrichment_corpus_specimen_ids_unique() {
    let corpus = signature_corpus();
    let ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    assert_eq!(ids.len(), corpus.len());
}

#[test]
fn enrichment_corpus_covers_all_families() {
    let corpus = signature_corpus();
    let covered: BTreeSet<SignatureSpecimenFamily> = corpus.iter().map(|s| s.family).collect();
    for &f in SignatureSpecimenFamily::ALL {
        assert!(covered.contains(&f), "corpus missing family {f:?}");
    }
}

#[test]
fn enrichment_extract_signature_schema_version_matches() {
    let config = default_config();
    let trace = make_trace("sv", "cpu", &[1, 2, 3, 4], 1);
    let sig = extract_signature(&trace, &config);
    assert_eq!(sig.schema_version, REGIME_SIG_SCHEMA_VERSION);
}

#[test]
fn enrichment_extract_signature_preserves_trace_id() {
    let config = default_config();
    let trace = make_trace("unique-id-xyz", "cpu", &[1, 2, 3, 4], 1);
    let sig = extract_signature(&trace, &config);
    assert_eq!(sig.trace_id, "unique-id-xyz");
}

#[test]
fn enrichment_state_chart_schema_version_matches() {
    let config = default_config();
    let traces = vec![make_trace(
        "t",
        "cpu",
        &[500_000, 500_000, 500_000, 500_000],
        1,
    )];
    let chart = build_regime_state_chart(&traces, &config);
    assert_eq!(chart.schema_version, REGIME_SIG_SCHEMA_VERSION);
}

#[test]
fn enrichment_specimen_family_all_contains_six() {
    assert_eq!(SignatureSpecimenFamily::ALL.len(), 6);
}

#[test]
fn enrichment_specimen_family_display_matches_as_str() {
    for &family in SignatureSpecimenFamily::ALL {
        assert_eq!(family.as_str(), family.to_string());
    }
}

#[test]
fn enrichment_evidence_inventory_contract_false_with_failures() {
    let inv = SignatureEvidenceInventory {
        schema_version: REGIME_SIG_SCHEMA_VERSION.to_string(),
        component: REGIME_SIG_COMPONENT.to_string(),
        specimen_count: 10,
        pass_count: 9,
        fail_count: 1,
        family_coverage: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn enrichment_evidence_inventory_contract_false_with_zero_specimens() {
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

#[test]
fn enrichment_l1_distance_triangle_inequality() {
    // For any three signatures with same dimension, d(a,c) <= d(a,b) + d(b,c)
    let sig_a = make_signature(
        "a",
        4,
        vec![100_000, 200_000, 300_000, 400_000],
        vec![1, 1, 1, 1],
        true,
    );
    let sig_b = make_signature(
        "b",
        4,
        vec![200_000, 300_000, 400_000, 500_000],
        vec![1, 1, 1, 1],
        true,
    );
    let sig_c = make_signature(
        "c",
        4,
        vec![400_000, 500_000, 600_000, 700_000],
        vec![1, 1, 1, 1],
        true,
    );
    let d_ab = sig_a.l1_distance(&sig_b);
    let d_bc = sig_b.l1_distance(&sig_c);
    let d_ac = sig_a.l1_distance(&sig_c);
    assert!(
        d_ac <= d_ab + d_bc,
        "triangle inequality violated: {d_ac} > {d_ab} + {d_bc}"
    );
}

#[test]
fn enrichment_cosine_similarity_nonnegative_for_positive_components() {
    let sig_a = make_signature(
        "a",
        4,
        vec![100_000, 200_000, 300_000, 400_000],
        vec![1, 1, 1, 1],
        true,
    );
    let sig_b = make_signature(
        "b",
        4,
        vec![400_000, 300_000, 200_000, 100_000],
        vec![1, 1, 1, 1],
        true,
    );
    let cos = sig_a.cosine_similarity(&sig_b);
    assert!(
        cos >= 0,
        "cosine for positive vectors should be nonneg: {cos}"
    );
}

#[test]
fn enrichment_extract_with_custom_small_dim() {
    let config = SignatureConfig {
        max_dim: 4,
        min_trace_length: 2,
        abstention_threshold: ABSTENTION_THRESHOLD_MILLIONTHS,
        centroids: vec![],
    };
    let trace = make_trace("small-dim", "cpu", &[500_000, 600_000, 400_000, 550_000], 1);
    let sig = extract_signature(&trace, &config);
    assert!(sig.valid);
    assert_eq!(sig.dimension, 4);
    assert_eq!(sig.components.len(), 4);
    assert_eq!(sig.bucket_counts.len(), 4);
}

#[test]
fn enrichment_confidence_bounded_by_million() {
    let config = default_config();
    let trace = make_trace("bounded", "cpu", &[500_000, 500_000, 500_000, 500_000], 1);
    let sig = extract_signature(&trace, &config);
    let (_, confidence) = classify_regime(&sig, &config);
    assert!(
        confidence <= 1_000_000,
        "confidence {confidence} exceeds 1M"
    );
}
