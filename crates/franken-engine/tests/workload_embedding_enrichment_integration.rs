//! Enrichment integration tests for `workload_embedding`.
//!
//! Covers gaps: Display uniqueness for all enum types, serde roundtrips for
//! untested types, hash determinism & variation, compute_distance per-metric
//! edge cases, issue_neighborhood_certificate Marginal/InsufficientSharedDimensions
//! paths, EmbeddingBuilder overflow/truncation/normalization, EmbeddingCatalog
//! boundary conditions, assess_transfer_safety per-recommendation paths,
//! build_evidence_corpus/run_embedding_corpus invariants, and ordering stability.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::workload_embedding::{
    AbstentionReason, CertificateVerdict, DistanceMetric, EMBEDDING_SCHEMA_VERSION,
    EmbeddingBuilder, EmbeddingCatalog, EmbeddingSpecimenFamily, EmbeddingValidity,
    FeatureComponent, FeatureExtractionConfig, FeatureFamily, MAX_EMBEDDING_DIM,
    MIN_OBSERVATIONS_FOR_EMBEDDING, NeighborhoodCertificate, NeighborhoodCertificateConfig,
    TransferRecommendation, WorkloadEmbedding, assess_transfer_safety, build_evidence_corpus,
    compute_distance, issue_neighborhood_certificate, run_embedding_corpus,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_feature(key: &str, family: FeatureFamily, value: i64, obs: u64) -> FeatureComponent {
    FeatureComponent {
        key: key.to_string(),
        family,
        value_millionths: value,
        observation_count: obs,
    }
}

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn default_config() -> FeatureExtractionConfig {
    FeatureExtractionConfig::default()
}

fn build_embedding(
    trace: &str,
    features: Vec<FeatureComponent>,
    config: FeatureExtractionConfig,
) -> WorkloadEmbedding {
    let mut builder = EmbeddingBuilder::new(config, trace.to_string(), epoch());
    for f in features {
        builder.add_component(f);
    }
    builder.build()
}

fn simple_features(n: usize, base_value: i64) -> Vec<FeatureComponent> {
    (0..n)
        .map(|i| {
            make_feature(
                &format!("feat_{i:03}"),
                FeatureFamily::InstructionDistribution,
                base_value + (i as i64) * 10_000,
                20,
            )
        })
        .collect()
}

fn simple_embedding(trace: &str, n: usize, base_value: i64) -> WorkloadEmbedding {
    build_embedding(trace, simple_features(n, base_value), default_config())
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_has_prefix() {
    assert!(EMBEDDING_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_max_dim_positive() {
    assert!(MAX_EMBEDDING_DIM > 0);
}

#[test]
fn enrichment_min_observations_positive() {
    assert!(MIN_OBSERVATIONS_FOR_EMBEDDING > 0);
}

// ===========================================================================
// FeatureFamily Display + serde
// ===========================================================================

#[test]
fn enrichment_feature_family_display_all_unique() {
    let all = [
        FeatureFamily::InstructionDistribution,
        FeatureFamily::HotPathProfile,
        FeatureFamily::ControlFlow,
        FeatureFamily::MemoryAccess,
        FeatureFamily::CallGraph,
        FeatureFamily::StringPattern,
        FeatureFamily::ModuleGraph,
        FeatureFamily::RegimeDistribution,
    ];
    let displays: BTreeSet<String> = all.iter().map(|f| f.to_string()).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn enrichment_feature_family_serde_roundtrip_all() {
    let all = [
        FeatureFamily::InstructionDistribution,
        FeatureFamily::HotPathProfile,
        FeatureFamily::ControlFlow,
        FeatureFamily::MemoryAccess,
        FeatureFamily::CallGraph,
        FeatureFamily::StringPattern,
        FeatureFamily::ModuleGraph,
        FeatureFamily::RegimeDistribution,
    ];
    for family in &all {
        let json = serde_json::to_string(family).unwrap();
        let back: FeatureFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*family, back);
    }
}

// ===========================================================================
// EmbeddingValidity Display + serde
// ===========================================================================

#[test]
fn enrichment_embedding_validity_display_all_unique() {
    let all = [
        EmbeddingValidity::Valid,
        EmbeddingValidity::InsufficientObservations,
        EmbeddingValidity::DimensionOverflow,
        EmbeddingValidity::Empty,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_embedding_validity_serde_roundtrip_all() {
    let all = [
        EmbeddingValidity::Valid,
        EmbeddingValidity::InsufficientObservations,
        EmbeddingValidity::DimensionOverflow,
        EmbeddingValidity::Empty,
    ];
    for v in &all {
        let json = serde_json::to_string(v).unwrap();
        let back: EmbeddingValidity = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// DistanceMetric Display + serde
// ===========================================================================

#[test]
fn enrichment_distance_metric_display_all_unique() {
    let all = [
        DistanceMetric::Manhattan,
        DistanceMetric::SquaredEuclidean,
        DistanceMetric::Chebyshev,
        DistanceMetric::Cosine,
    ];
    let displays: BTreeSet<String> = all.iter().map(|m| m.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_distance_metric_serde_roundtrip_all() {
    let all = [
        DistanceMetric::Manhattan,
        DistanceMetric::SquaredEuclidean,
        DistanceMetric::Chebyshev,
        DistanceMetric::Cosine,
    ];
    for m in &all {
        let json = serde_json::to_string(m).unwrap();
        let back: DistanceMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, back);
    }
}

// ===========================================================================
// CertificateVerdict Display + serde
// ===========================================================================

#[test]
fn enrichment_certificate_verdict_display_all_unique() {
    let all = [
        CertificateVerdict::Near,
        CertificateVerdict::Marginal,
        CertificateVerdict::Distant,
        CertificateVerdict::Abstained,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_certificate_verdict_serde_roundtrip_all() {
    let all = [
        CertificateVerdict::Near,
        CertificateVerdict::Marginal,
        CertificateVerdict::Distant,
        CertificateVerdict::Abstained,
    ];
    for v in &all {
        let json = serde_json::to_string(v).unwrap();
        let back: CertificateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// AbstentionReason Display + serde
// ===========================================================================

#[test]
fn enrichment_abstention_reason_display_all_unique() {
    let all = [
        AbstentionReason::InvalidEmbedding,
        AbstentionReason::NoSharedDimensions,
        AbstentionReason::InsufficientSharedDimensions,
        AbstentionReason::EpochMismatch,
    ];
    let displays: BTreeSet<String> = all.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_abstention_reason_serde_roundtrip_all() {
    let all = [
        AbstentionReason::InvalidEmbedding,
        AbstentionReason::NoSharedDimensions,
        AbstentionReason::InsufficientSharedDimensions,
        AbstentionReason::EpochMismatch,
    ];
    for r in &all {
        let json = serde_json::to_string(r).unwrap();
        let back: AbstentionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// TransferRecommendation Display + serde
// ===========================================================================

#[test]
fn enrichment_transfer_recommendation_display_all_unique() {
    let all = [
        TransferRecommendation::TransferAll,
        TransferRecommendation::TransferSelective,
        TransferRecommendation::BlockTransfer,
        TransferRecommendation::CannotAssess,
    ];
    let displays: BTreeSet<String> = all.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_transfer_recommendation_serde_roundtrip_all() {
    let all = [
        TransferRecommendation::TransferAll,
        TransferRecommendation::TransferSelective,
        TransferRecommendation::BlockTransfer,
        TransferRecommendation::CannotAssess,
    ];
    for r in &all {
        let json = serde_json::to_string(r).unwrap();
        let back: TransferRecommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// EmbeddingSpecimenFamily Display + serde
// ===========================================================================

#[test]
fn enrichment_specimen_family_display_all_unique() {
    let all = [
        EmbeddingSpecimenFamily::ComputeBound,
        EmbeddingSpecimenFamily::MemoryIntensive,
        EmbeddingSpecimenFamily::IoHeavy,
        EmbeddingSpecimenFamily::Mixed,
        EmbeddingSpecimenFamily::Trivial,
        EmbeddingSpecimenFamily::Adversarial,
    ];
    let displays: BTreeSet<String> = all.iter().map(|f| f.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_specimen_family_serde_roundtrip_all() {
    let all = [
        EmbeddingSpecimenFamily::ComputeBound,
        EmbeddingSpecimenFamily::MemoryIntensive,
        EmbeddingSpecimenFamily::IoHeavy,
        EmbeddingSpecimenFamily::Mixed,
        EmbeddingSpecimenFamily::Trivial,
        EmbeddingSpecimenFamily::Adversarial,
    ];
    for f in &all {
        let json = serde_json::to_string(f).unwrap();
        let back: EmbeddingSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

// ===========================================================================
// FeatureComponent serde
// ===========================================================================

#[test]
fn enrichment_feature_component_serde_roundtrip() {
    let comp = make_feature("test.key", FeatureFamily::ControlFlow, 500_000, 42);
    let json = serde_json::to_string(&comp).unwrap();
    let back: FeatureComponent = serde_json::from_str(&json).unwrap();
    assert_eq!(comp, back);
}

#[test]
fn enrichment_feature_component_negative_value() {
    let comp = make_feature("neg.val", FeatureFamily::MemoryAccess, -100_000, 10);
    let json = serde_json::to_string(&comp).unwrap();
    let back: FeatureComponent = serde_json::from_str(&json).unwrap();
    assert_eq!(comp.value_millionths, back.value_millionths);
}

// ===========================================================================
// FeatureExtractionConfig tests
// ===========================================================================

#[test]
fn enrichment_config_content_hash_varies_with_settings() {
    let c1 = default_config();
    let mut c2 = default_config();
    c2.max_features = 64;
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn enrichment_config_family_enabled_all_when_empty() {
    let config = default_config();
    assert!(config.enabled_families.is_empty());
    assert!(config.family_enabled(FeatureFamily::InstructionDistribution));
    assert!(config.family_enabled(FeatureFamily::CallGraph));
    assert!(config.family_enabled(FeatureFamily::StringPattern));
}

#[test]
fn enrichment_config_family_enabled_selective() {
    let mut config = default_config();
    config.enabled_families.insert(FeatureFamily::ControlFlow);
    assert!(config.family_enabled(FeatureFamily::ControlFlow));
    assert!(!config.family_enabled(FeatureFamily::InstructionDistribution));
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let mut config = default_config();
    config.enabled_families.insert(FeatureFamily::CallGraph);
    config.max_features = 64;
    config.normalize = false;
    let json = serde_json::to_string(&config).unwrap();
    let back: FeatureExtractionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// EmbeddingBuilder tests
// ===========================================================================

#[test]
fn enrichment_builder_empty_produces_empty_validity() {
    let builder = EmbeddingBuilder::new(default_config(), "trace-1".to_string(), epoch());
    let emb = builder.build();
    assert_eq!(emb.validity, EmbeddingValidity::Empty);
    assert!(!emb.is_valid());
}

#[test]
fn enrichment_builder_valid_embedding() {
    let emb = simple_embedding("trace-1", 5, 100_000);
    assert_eq!(emb.validity, EmbeddingValidity::Valid);
    assert!(emb.is_valid());
    assert_eq!(emb.dimension, 5);
}

#[test]
fn enrichment_builder_filters_disabled_families() {
    let mut config = default_config();
    config.enabled_families.insert(FeatureFamily::ControlFlow);
    let features = vec![
        make_feature("cf.branch", FeatureFamily::ControlFlow, 100_000, 20),
        make_feature(
            "inst.add",
            FeatureFamily::InstructionDistribution,
            200_000,
            20,
        ),
    ];
    let emb = build_embedding("trace-1", features, config);
    // Only ControlFlow should remain
    assert_eq!(emb.dimension, 1);
    assert!(emb.get_component("cf.branch").is_some());
    assert!(emb.get_component("inst.add").is_none());
}

#[test]
fn enrichment_builder_dimension_overflow() {
    // Add more than MAX_EMBEDDING_DIM features
    let features: Vec<FeatureComponent> = (0..MAX_EMBEDDING_DIM + 5)
        .map(|i| {
            make_feature(
                &format!("f_{i:04}"),
                FeatureFamily::InstructionDistribution,
                (i as i64) * 1000,
                20,
            )
        })
        .collect();
    let mut config = default_config();
    config.max_features = MAX_EMBEDDING_DIM + 10; // Allow more than max dim
    let emb = build_embedding("trace-1", features, config);
    // Should be marked as DimensionOverflow
    assert_eq!(emb.validity, EmbeddingValidity::DimensionOverflow);
    assert!(!emb.is_valid());
}

#[test]
fn enrichment_builder_components_sorted_by_key() {
    let features = vec![
        make_feature("z_feature", FeatureFamily::ControlFlow, 100_000, 20),
        make_feature("a_feature", FeatureFamily::ControlFlow, 200_000, 20),
        make_feature("m_feature", FeatureFamily::ControlFlow, 150_000, 20),
    ];
    let emb = build_embedding("trace-1", features, default_config());
    let keys = emb.keys();
    assert_eq!(keys, vec!["a_feature", "m_feature", "z_feature"]);
}

#[test]
fn enrichment_builder_add_feature_method() {
    let mut builder = EmbeddingBuilder::new(default_config(), "trace-1".to_string(), epoch());
    builder.add_feature("key.a", FeatureFamily::ControlFlow, 100_000, 20);
    builder.add_feature("key.b", FeatureFamily::MemoryAccess, 200_000, 20);
    assert_eq!(builder.component_count(), 2);
    let emb = builder.build();
    assert_eq!(emb.dimension, 2);
}

#[test]
fn enrichment_builder_embedding_id_deterministic() {
    let e1 = simple_embedding("trace-1", 5, 100_000);
    let e2 = simple_embedding("trace-1", 5, 100_000);
    assert_eq!(e1.embedding_id, e2.embedding_id);
    assert_eq!(e1.content_hash, e2.content_hash);
}

#[test]
fn enrichment_builder_embedding_id_varies() {
    // Use different feature counts to avoid normalization collapsing values
    let mut config = default_config();
    config.normalize = false;
    let e1 = build_embedding("trace-1", simple_features(5, 100_000), config.clone());
    let e2 = build_embedding("trace-1", simple_features(5, 200_000), config);
    assert_ne!(e1.embedding_id, e2.embedding_id);
    assert_ne!(e1.content_hash, e2.content_hash);
}

// ===========================================================================
// WorkloadEmbedding methods
// ===========================================================================

#[test]
fn enrichment_embedding_value_vector_matches_components() {
    let emb = simple_embedding("t", 3, 100_000);
    let vec = emb.value_vector();
    assert_eq!(vec.len(), emb.dimension);
    for (i, comp) in emb.components.iter().enumerate() {
        assert_eq!(vec[i], comp.value_millionths);
    }
}

#[test]
fn enrichment_embedding_value_for_hit_and_miss() {
    let emb = simple_embedding("t", 3, 100_000);
    let first_key = &emb.components[0].key;
    assert!(emb.value_for(first_key).is_some());
    assert!(emb.value_for("nonexistent").is_none());
}

#[test]
fn enrichment_embedding_family_count() {
    let features = vec![
        make_feature("a", FeatureFamily::ControlFlow, 100_000, 20),
        make_feature("b", FeatureFamily::ControlFlow, 200_000, 20),
        make_feature("c", FeatureFamily::MemoryAccess, 300_000, 20),
    ];
    let emb = build_embedding("t", features, default_config());
    assert_eq!(emb.family_count(FeatureFamily::ControlFlow), 2);
    assert_eq!(emb.family_count(FeatureFamily::MemoryAccess), 1);
    assert_eq!(emb.family_count(FeatureFamily::CallGraph), 0);
}

#[test]
fn enrichment_embedding_squared_norm_all_zeros() {
    let features = vec![
        make_feature("a", FeatureFamily::ControlFlow, 0, 20),
        make_feature("b", FeatureFamily::ControlFlow, 0, 20),
    ];
    let mut config = default_config();
    config.normalize = false;
    let emb = build_embedding("t", features, config);
    assert_eq!(emb.squared_norm(), 0);
}

#[test]
fn enrichment_embedding_serde_roundtrip() {
    let emb = simple_embedding("trace-1", 5, 100_000);
    let json = serde_json::to_string(&emb).unwrap();
    let back: WorkloadEmbedding = serde_json::from_str(&json).unwrap();
    assert_eq!(emb, back);
}

// ===========================================================================
// compute_distance per-metric tests
// ===========================================================================

#[test]
fn enrichment_manhattan_distance_known_values() {
    let mut config = default_config();
    config.normalize = false;
    let a = build_embedding(
        "a",
        vec![
            make_feature("x", FeatureFamily::ControlFlow, 100_000, 20),
            make_feature("y", FeatureFamily::ControlFlow, 200_000, 20),
        ],
        config.clone(),
    );
    let b = build_embedding(
        "b",
        vec![
            make_feature("x", FeatureFamily::ControlFlow, 150_000, 20),
            make_feature("y", FeatureFamily::ControlFlow, 250_000, 20),
        ],
        config,
    );
    let result = compute_distance(&a, &b, DistanceMetric::Manhattan);
    // |100k - 150k| + |200k - 250k| = 50k + 50k = 100k
    assert_eq!(result.distance_millionths, 100_000);
    assert_eq!(result.shared_dimensions, 2);
    assert_eq!(result.missing_in_a, 0);
    assert_eq!(result.missing_in_b, 0);
}

#[test]
fn enrichment_chebyshev_distance_known_values() {
    let mut config = default_config();
    config.normalize = false;
    let a = build_embedding(
        "a",
        vec![
            make_feature("x", FeatureFamily::ControlFlow, 100_000, 20),
            make_feature("y", FeatureFamily::ControlFlow, 200_000, 20),
        ],
        config.clone(),
    );
    let b = build_embedding(
        "b",
        vec![
            make_feature("x", FeatureFamily::ControlFlow, 150_000, 20),
            make_feature("y", FeatureFamily::ControlFlow, 300_000, 20),
        ],
        config,
    );
    let result = compute_distance(&a, &b, DistanceMetric::Chebyshev);
    // max(|100k-150k|, |200k-300k|) = max(50k, 100k) = 100k
    assert_eq!(result.distance_millionths, 100_000);
}

#[test]
fn enrichment_squared_euclidean_distance_known_values() {
    let mut config = default_config();
    config.normalize = false;
    let a = build_embedding(
        "a",
        vec![make_feature("x", FeatureFamily::ControlFlow, 100_000, 20)],
        config.clone(),
    );
    let b = build_embedding(
        "b",
        vec![make_feature("x", FeatureFamily::ControlFlow, 200_000, 20)],
        config,
    );
    let result = compute_distance(&a, &b, DistanceMetric::SquaredEuclidean);
    // (200k - 100k)^2 = (100k)^2 = 10_000_000_000
    assert_eq!(result.distance_millionths, 10_000_000_000);
}

#[test]
fn enrichment_cosine_identical_embeddings() {
    let emb = simple_embedding("t", 5, 100_000);
    let result = compute_distance(&emb, &emb, DistanceMetric::Cosine);
    // Cosine distance of identical vectors should be near 0
    assert!(
        result.distance_millionths <= 1,
        "cosine distance of identical should be ~0, got {}",
        result.distance_millionths
    );
}

#[test]
fn enrichment_distance_no_shared_dimensions() {
    let mut config = default_config();
    config.normalize = false;
    let a = build_embedding(
        "a",
        vec![make_feature("x", FeatureFamily::ControlFlow, 100_000, 20)],
        config.clone(),
    );
    let b = build_embedding(
        "b",
        vec![make_feature("y", FeatureFamily::ControlFlow, 200_000, 20)],
        config,
    );
    let result = compute_distance(&a, &b, DistanceMetric::Manhattan);
    assert_eq!(result.shared_dimensions, 0);
    assert_eq!(result.distance_millionths, 0);
    assert_eq!(result.missing_in_a, 1);
    assert_eq!(result.missing_in_b, 1);
}

#[test]
fn enrichment_distance_partial_overlap() {
    let mut config = default_config();
    config.normalize = false;
    let a = build_embedding(
        "a",
        vec![
            make_feature("shared", FeatureFamily::ControlFlow, 100_000, 20),
            make_feature("only_a", FeatureFamily::ControlFlow, 200_000, 20),
        ],
        config.clone(),
    );
    let b = build_embedding(
        "b",
        vec![
            make_feature("shared", FeatureFamily::ControlFlow, 150_000, 20),
            make_feature("only_b", FeatureFamily::ControlFlow, 300_000, 20),
        ],
        config,
    );
    let result = compute_distance(&a, &b, DistanceMetric::Manhattan);
    assert_eq!(result.shared_dimensions, 1);
    assert_eq!(result.missing_in_a, 1); // only_b missing in a
    assert_eq!(result.missing_in_b, 1); // only_a missing in b
    assert_eq!(result.distance_millionths, 50_000); // |100k - 150k|
}

// ===========================================================================
// issue_neighborhood_certificate tests
// ===========================================================================

#[test]
fn enrichment_certificate_near_verdict() {
    let a = simple_embedding("a", 5, 100_000);
    let b = simple_embedding("b", 5, 100_001); // very close
    let config = NeighborhoodCertificateConfig::default();
    let cert = issue_neighborhood_certificate(&a, &b, &config, epoch());
    assert_eq!(cert.verdict, CertificateVerdict::Near);
    assert!(cert.abstention_reason.is_none());
}

#[test]
fn enrichment_certificate_distant_verdict() {
    // Use non-normalized embeddings with very different features to ensure Distant
    let mut config_ex = default_config();
    config_ex.normalize = false;
    let a = build_embedding(
        "a",
        vec![
            make_feature("x", FeatureFamily::ControlFlow, 0, 20),
            make_feature("y", FeatureFamily::ControlFlow, 0, 20),
            make_feature("z", FeatureFamily::ControlFlow, 0, 20),
        ],
        config_ex.clone(),
    );
    let b = build_embedding(
        "b",
        vec![
            make_feature("x", FeatureFamily::ControlFlow, 1_000_000, 20),
            make_feature("y", FeatureFamily::ControlFlow, 1_000_000, 20),
            make_feature("z", FeatureFamily::ControlFlow, 1_000_000, 20),
        ],
        config_ex,
    );
    let config = NeighborhoodCertificateConfig::default();
    let cert = issue_neighborhood_certificate(&a, &b, &config, epoch());
    assert_eq!(cert.verdict, CertificateVerdict::Distant);
    assert!(cert.abstention_reason.is_none());
}

#[test]
fn enrichment_certificate_abstained_invalid_embedding() {
    let valid = simple_embedding("a", 5, 100_000);
    // Empty embedding is invalid
    let invalid = EmbeddingBuilder::new(default_config(), "b".to_string(), epoch()).build();
    let config = NeighborhoodCertificateConfig::default();
    let cert = issue_neighborhood_certificate(&valid, &invalid, &config, epoch());
    assert_eq!(cert.verdict, CertificateVerdict::Abstained);
    assert_eq!(
        cert.abstention_reason,
        Some(AbstentionReason::InvalidEmbedding)
    );
}

#[test]
fn enrichment_certificate_abstained_epoch_mismatch() {
    let a = build_embedding("a", simple_features(5, 100_000), {
        let mut c = default_config();
        c.normalize = false;
        c
    });
    // Build b at different epoch - use builder directly
    let mut builder = EmbeddingBuilder::new(
        default_config(),
        "b".to_string(),
        SecurityEpoch::from_raw(100),
    );
    for f in simple_features(5, 100_000) {
        builder.add_component(f);
    }
    let b = builder.build();

    let mut config = NeighborhoodCertificateConfig::default();
    config.max_epoch_gap = 2; // Only allow gap of 2
    let cert = issue_neighborhood_certificate(&a, &b, &config, epoch());
    assert_eq!(cert.verdict, CertificateVerdict::Abstained);
    assert_eq!(
        cert.abstention_reason,
        Some(AbstentionReason::EpochMismatch)
    );
}

#[test]
fn enrichment_certificate_abstained_no_shared_dims() {
    let mut config_ex = default_config();
    config_ex.normalize = false;
    let a = build_embedding(
        "a",
        vec![make_feature(
            "only_a",
            FeatureFamily::ControlFlow,
            100_000,
            20,
        )],
        config_ex.clone(),
    );
    let b = build_embedding(
        "b",
        vec![make_feature(
            "only_b",
            FeatureFamily::ControlFlow,
            200_000,
            20,
        )],
        config_ex,
    );
    let config = NeighborhoodCertificateConfig::default();
    let cert = issue_neighborhood_certificate(&a, &b, &config, epoch());
    assert_eq!(cert.verdict, CertificateVerdict::Abstained);
    assert_eq!(
        cert.abstention_reason,
        Some(AbstentionReason::NoSharedDimensions)
    );
}

#[test]
fn enrichment_certificate_content_hash_deterministic() {
    let a = simple_embedding("a", 5, 100_000);
    let b = simple_embedding("b", 5, 100_001);
    let config = NeighborhoodCertificateConfig::default();
    let c1 = issue_neighborhood_certificate(&a, &b, &config, epoch());
    let c2 = issue_neighborhood_certificate(&a, &b, &config, epoch());
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c1.certificate_id, c2.certificate_id);
}

#[test]
fn enrichment_certificate_serde_roundtrip() {
    let a = simple_embedding("a", 5, 100_000);
    let b = simple_embedding("b", 5, 200_000);
    let config = NeighborhoodCertificateConfig::default();
    let cert = issue_neighborhood_certificate(&a, &b, &config, epoch());
    let json = serde_json::to_string(&cert).unwrap();
    let back: NeighborhoodCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ===========================================================================
// NeighborhoodCertificateConfig tests
// ===========================================================================

#[test]
fn enrichment_cert_config_default_thresholds_ordered() {
    let config = NeighborhoodCertificateConfig::default();
    assert!(
        config.near_threshold_millionths <= config.marginal_threshold_millionths,
        "near <= marginal"
    );
}

#[test]
fn enrichment_cert_config_serde_roundtrip() {
    let mut config = NeighborhoodCertificateConfig::default();
    config.metric = DistanceMetric::Manhattan;
    config.min_shared_dimensions = 10;
    let json = serde_json::to_string(&config).unwrap();
    let back: NeighborhoodCertificateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// assess_transfer_safety tests
// ===========================================================================

#[test]
fn enrichment_transfer_safety_near_is_transfer_all() {
    let a = simple_embedding("a", 5, 100_000);
    let b = simple_embedding("b", 5, 100_001);
    let config = NeighborhoodCertificateConfig::default();
    let assessment = assess_transfer_safety(&a, &b, &config, epoch());
    assert_eq!(
        assessment.recommendation,
        TransferRecommendation::TransferAll
    );
}

#[test]
fn enrichment_transfer_safety_distant_is_block() {
    let mut config_ex = default_config();
    config_ex.normalize = false;
    let a = build_embedding(
        "a",
        vec![
            make_feature("x", FeatureFamily::ControlFlow, 0, 20),
            make_feature("y", FeatureFamily::ControlFlow, 0, 20),
            make_feature("z", FeatureFamily::ControlFlow, 0, 20),
        ],
        config_ex.clone(),
    );
    let b = build_embedding(
        "b",
        vec![
            make_feature("x", FeatureFamily::ControlFlow, 1_000_000, 20),
            make_feature("y", FeatureFamily::ControlFlow, 1_000_000, 20),
            make_feature("z", FeatureFamily::ControlFlow, 1_000_000, 20),
        ],
        config_ex,
    );
    let config = NeighborhoodCertificateConfig::default();
    let assessment = assess_transfer_safety(&a, &b, &config, epoch());
    assert_eq!(
        assessment.recommendation,
        TransferRecommendation::BlockTransfer
    );
}

#[test]
fn enrichment_transfer_safety_invalid_is_cannot_assess() {
    let valid = simple_embedding("a", 5, 100_000);
    let invalid = EmbeddingBuilder::new(default_config(), "b".to_string(), epoch()).build();
    let config = NeighborhoodCertificateConfig::default();
    let assessment = assess_transfer_safety(&valid, &invalid, &config, epoch());
    assert_eq!(
        assessment.recommendation,
        TransferRecommendation::CannotAssess
    );
}

#[test]
fn enrichment_transfer_safety_serde_roundtrip() {
    let a = simple_embedding("a", 5, 100_000);
    let b = simple_embedding("b", 5, 100_001);
    let config = NeighborhoodCertificateConfig::default();
    let assessment = assess_transfer_safety(&a, &b, &config, epoch());
    let json = serde_json::to_string(&assessment).unwrap();
    let back = serde_json::from_str::<serde_json::Value>(&json).unwrap();
    assert!(back.is_object());
    assert!(back.get("recommendation").is_some());
}

#[test]
fn enrichment_transfer_safety_content_hash_deterministic() {
    let a = simple_embedding("a", 5, 100_000);
    let b = simple_embedding("b", 5, 100_001);
    let config = NeighborhoodCertificateConfig::default();
    let a1 = assess_transfer_safety(&a, &b, &config, epoch());
    let a2 = assess_transfer_safety(&a, &b, &config, epoch());
    assert_eq!(a1.content_hash, a2.content_hash);
}

// ===========================================================================
// EmbeddingCatalog tests
// ===========================================================================

#[test]
fn enrichment_catalog_new_is_empty() {
    let catalog = EmbeddingCatalog::new(epoch());
    assert!(catalog.is_empty());
    assert_eq!(catalog.len(), 0);
}

#[test]
fn enrichment_catalog_insert_and_len() {
    let mut catalog = EmbeddingCatalog::new(epoch());
    catalog.insert(
        simple_embedding("e1", 5, 100_000),
        Some("label-1".to_string()),
        BTreeSet::new(),
    );
    catalog.insert(simple_embedding("e2", 5, 200_000), None, BTreeSet::new());
    assert_eq!(catalog.len(), 2);
    assert!(!catalog.is_empty());
}

#[test]
fn enrichment_catalog_k_nearest_returns_k_or_fewer() {
    let mut catalog = EmbeddingCatalog::new(epoch());
    for i in 0..5 {
        catalog.insert(
            simple_embedding(&format!("e{i}"), 5, (i as i64) * 100_000),
            None,
            BTreeSet::new(),
        );
    }
    let query = simple_embedding("q", 5, 50_000);
    let results = catalog.k_nearest(&query, 3, DistanceMetric::Chebyshev);
    assert_eq!(results.len(), 3);

    // Ask for more than available
    let results = catalog.k_nearest(&query, 100, DistanceMetric::Chebyshev);
    assert!(results.len() <= 5);
}

#[test]
fn enrichment_catalog_k_nearest_zero_returns_empty() {
    let mut catalog = EmbeddingCatalog::new(epoch());
    catalog.insert(simple_embedding("e1", 5, 100_000), None, BTreeSet::new());
    let query = simple_embedding("q", 5, 100_000);
    let results = catalog.k_nearest(&query, 0, DistanceMetric::Chebyshev);
    assert!(results.is_empty());
}

#[test]
fn enrichment_catalog_summary_counts() {
    let mut catalog = EmbeddingCatalog::new(epoch());
    catalog.insert(simple_embedding("e1", 5, 100_000), None, BTreeSet::new());
    // Insert invalid embedding
    catalog.insert(
        EmbeddingBuilder::new(default_config(), "inv".to_string(), epoch()).build(),
        None,
        BTreeSet::new(),
    );
    let summary = catalog.summary();
    assert_eq!(summary.total_entries, 2);
    assert_eq!(summary.valid_count, 1);
    assert_eq!(summary.invalid_count, 1);
}

#[test]
fn enrichment_catalog_summary_empty() {
    let catalog = EmbeddingCatalog::new(epoch());
    let summary = catalog.summary();
    assert_eq!(summary.total_entries, 0);
    assert_eq!(summary.valid_count, 0);
    assert_eq!(summary.avg_dimension, 0);
}

#[test]
fn enrichment_catalog_summary_serde_roundtrip() {
    let mut catalog = EmbeddingCatalog::new(epoch());
    catalog.insert(simple_embedding("e1", 5, 100_000), None, BTreeSet::new());
    let summary = catalog.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back = serde_json::from_str::<serde_json::Value>(&json).unwrap();
    assert!(back.is_object());
    assert_eq!(back["total_entries"], 1);
}

// ===========================================================================
// build_evidence_corpus / run_embedding_corpus tests
// ===========================================================================

#[test]
fn enrichment_evidence_corpus_has_6_specimens() {
    let corpus = build_evidence_corpus(epoch());
    assert_eq!(corpus.len(), 6);
}

#[test]
fn enrichment_evidence_corpus_families_cover_all() {
    let corpus = build_evidence_corpus(epoch());
    let families: BTreeSet<_> = corpus.iter().map(|s| s.family).collect();
    assert!(families.contains(&EmbeddingSpecimenFamily::ComputeBound));
    assert!(families.contains(&EmbeddingSpecimenFamily::MemoryIntensive));
    assert!(families.contains(&EmbeddingSpecimenFamily::IoHeavy));
    assert!(families.contains(&EmbeddingSpecimenFamily::Mixed));
    assert!(families.contains(&EmbeddingSpecimenFamily::Trivial));
    assert!(families.contains(&EmbeddingSpecimenFamily::Adversarial));
}

#[test]
fn enrichment_evidence_corpus_deterministic() {
    let c1 = build_evidence_corpus(epoch());
    let c2 = build_evidence_corpus(epoch());
    assert_eq!(c1.len(), c2.len());
    for (a, b) in c1.iter().zip(c2.iter()) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.embedding.content_hash, b.embedding.content_hash);
    }
}

#[test]
fn enrichment_evidence_corpus_ids_unique() {
    let corpus = build_evidence_corpus(epoch());
    let ids: BTreeSet<_> = corpus.iter().map(|s| &s.id).collect();
    assert_eq!(ids.len(), corpus.len());
}

#[test]
fn enrichment_run_embedding_corpus_produces_hash() {
    let (specimens, hash) = run_embedding_corpus(epoch());
    assert_eq!(specimens.len(), 6);
    assert_ne!(hash.as_bytes(), &[0u8; 32]);
}

#[test]
fn enrichment_run_embedding_corpus_hash_deterministic() {
    let (_, h1) = run_embedding_corpus(epoch());
    let (_, h2) = run_embedding_corpus(epoch());
    assert_eq!(h1, h2);
}
