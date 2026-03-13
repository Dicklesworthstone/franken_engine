//! Integration tests for workload embedding module (RGC-612A).

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::workload_embedding::{
    AbstentionReason, CatalogEntry, CatalogSummary, CertificateVerdict,
    DEFAULT_COSINE_NEAR_THRESHOLD, DEFAULT_NEIGHBORHOOD_RADIUS, DistanceMetric, DistanceResult,
    EMBEDDING_SCHEMA_VERSION, EmbeddingBuilder, EmbeddingCatalog, EmbeddingSpecimen,
    EmbeddingSpecimenFamily, EmbeddingValidity, FeatureComponent, FeatureExtractionConfig,
    FeatureFamily, MAX_EMBEDDING_DIM, MIN_OBSERVATIONS_FOR_EMBEDDING, NeighborResult,
    NeighborhoodCertificate, NeighborhoodCertificateConfig, TransferRecommendation,
    TransferSafetyAssessment, WorkloadEmbedding, assess_transfer_safety, build_evidence_corpus,
    compute_distance, issue_neighborhood_certificate, run_embedding_corpus,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_feature(key: &str, family: FeatureFamily, value: i64, obs: u64) -> FeatureComponent {
    FeatureComponent {
        key: key.into(),
        family,
        value_millionths: value,
        observation_count: obs,
    }
}

fn build_simple_embedding(trace_id: &str, features: Vec<FeatureComponent>) -> WorkloadEmbedding {
    let mut builder = EmbeddingBuilder::new(
        FeatureExtractionConfig {
            normalize: false,
            min_observations: 1,
            ..FeatureExtractionConfig::default()
        },
        trace_id.into(),
        test_epoch(),
    );
    for f in features {
        builder.add_component(f);
    }
    builder.build()
}

fn sample_embedding_a() -> WorkloadEmbedding {
    build_simple_embedding(
        "trace-a",
        vec![
            make_feature(
                "opcode.add",
                FeatureFamily::InstructionDistribution,
                500_000,
                100,
            ),
            make_feature(
                "opcode.mul",
                FeatureFamily::InstructionDistribution,
                300_000,
                100,
            ),
            make_feature("branch_density", FeatureFamily::ControlFlow, 200_000, 50),
            make_feature("alloc_rate", FeatureFamily::MemoryAccess, 100_000, 80),
        ],
    )
}

fn sample_embedding_b() -> WorkloadEmbedding {
    build_simple_embedding(
        "trace-b",
        vec![
            make_feature(
                "opcode.add",
                FeatureFamily::InstructionDistribution,
                510_000,
                100,
            ),
            make_feature(
                "opcode.mul",
                FeatureFamily::InstructionDistribution,
                290_000,
                100,
            ),
            make_feature("branch_density", FeatureFamily::ControlFlow, 195_000, 50),
            make_feature("alloc_rate", FeatureFamily::MemoryAccess, 105_000, 80),
        ],
    )
}

fn distant_embedding() -> WorkloadEmbedding {
    build_simple_embedding(
        "trace-distant",
        vec![
            make_feature(
                "opcode.add",
                FeatureFamily::InstructionDistribution,
                900_000,
                100,
            ),
            make_feature(
                "opcode.mul",
                FeatureFamily::InstructionDistribution,
                50_000,
                100,
            ),
            make_feature("branch_density", FeatureFamily::ControlFlow, 800_000, 50),
            make_feature("alloc_rate", FeatureFamily::MemoryAccess, 10_000, 80),
        ],
    )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_have_expected_properties() {
    assert!(!EMBEDDING_SCHEMA_VERSION.is_empty());
    const {
        assert!(MAX_EMBEDDING_DIM > 0);
        assert!(MIN_OBSERVATIONS_FOR_EMBEDDING > 0);
        assert!(DEFAULT_NEIGHBORHOOD_RADIUS > 0);
        assert!(DEFAULT_COSINE_NEAR_THRESHOLD > 0);
    }
}

// ---------------------------------------------------------------------------
// FeatureFamily
// ---------------------------------------------------------------------------

#[test]
fn feature_family_display_all_variants() {
    let families = [
        FeatureFamily::InstructionDistribution,
        FeatureFamily::HotPathProfile,
        FeatureFamily::ControlFlow,
        FeatureFamily::MemoryAccess,
        FeatureFamily::CallGraph,
        FeatureFamily::StringPattern,
        FeatureFamily::ModuleGraph,
        FeatureFamily::RegimeDistribution,
    ];
    for f in &families {
        assert!(!format!("{f}").is_empty());
    }
}

#[test]
fn feature_family_serde_round_trip() {
    let f = FeatureFamily::ControlFlow;
    let json = serde_json::to_string(&f).unwrap();
    let back: FeatureFamily = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ---------------------------------------------------------------------------
// FeatureExtractionConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_reasonable() {
    let cfg = FeatureExtractionConfig::default();
    assert!(cfg.max_features > 0);
    assert!(cfg.min_observations > 0);
    assert!(cfg.normalize);
    assert!(cfg.enabled_families.is_empty()); // all families enabled
}

#[test]
fn config_family_enabled_all_when_empty() {
    let cfg = FeatureExtractionConfig::default();
    assert!(cfg.family_enabled(FeatureFamily::InstructionDistribution));
    assert!(cfg.family_enabled(FeatureFamily::ModuleGraph));
}

#[test]
fn config_family_enabled_selective() {
    let mut cfg = FeatureExtractionConfig::default();
    cfg.enabled_families.insert(FeatureFamily::ControlFlow);
    assert!(cfg.family_enabled(FeatureFamily::ControlFlow));
    assert!(!cfg.family_enabled(FeatureFamily::MemoryAccess));
}

#[test]
fn config_content_hash_deterministic() {
    let c1 = FeatureExtractionConfig::default();
    let c2 = FeatureExtractionConfig::default();
    assert_eq!(c1.content_hash(), c2.content_hash());
}

#[test]
fn config_serde_round_trip() {
    let cfg = FeatureExtractionConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: FeatureExtractionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// EmbeddingValidity
// ---------------------------------------------------------------------------

#[test]
fn embedding_validity_display() {
    let variants = [
        EmbeddingValidity::Valid,
        EmbeddingValidity::InsufficientObservations,
        EmbeddingValidity::DimensionOverflow,
        EmbeddingValidity::Empty,
    ];
    for v in &variants {
        assert!(!format!("{v}").is_empty());
    }
}

#[test]
fn embedding_validity_serde_round_trip() {
    let v = EmbeddingValidity::Valid;
    let json = serde_json::to_string(&v).unwrap();
    let back: EmbeddingValidity = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// EmbeddingBuilder + WorkloadEmbedding
// ---------------------------------------------------------------------------

#[test]
fn builder_empty_produces_empty_validity() {
    let builder = EmbeddingBuilder::new(
        FeatureExtractionConfig::default(),
        "trace-empty".into(),
        test_epoch(),
    );
    let emb = builder.build();
    assert_eq!(emb.validity, EmbeddingValidity::Empty);
    assert_eq!(emb.dimension, 0);
    assert!(!emb.is_valid());
}

#[test]
fn builder_insufficient_observations() {
    let cfg = FeatureExtractionConfig {
        min_observations: 100,
        normalize: false,
        ..FeatureExtractionConfig::default()
    };
    let mut builder = EmbeddingBuilder::new(cfg, "trace-insuff".into(), test_epoch());
    builder.add_feature("f1", FeatureFamily::ControlFlow, 500_000, 5); // below min
    let emb = builder.build();
    // Feature filtered out due to insufficient observations → empty
    assert_eq!(emb.validity, EmbeddingValidity::Empty);
}

#[test]
fn builder_valid_embedding() {
    let emb = sample_embedding_a();
    assert!(emb.is_valid());
    assert_eq!(emb.dimension, 4);
    assert_eq!(emb.total_observations, 330); // 100+100+50+80
    assert!(!emb.embedding_id.is_empty());
    assert!(!emb.content_hash.to_hex().is_empty());
}

#[test]
fn builder_filters_disabled_families() {
    let mut cfg = FeatureExtractionConfig::default();
    cfg.enabled_families.insert(FeatureFamily::ControlFlow);
    cfg.normalize = false;
    cfg.min_observations = 1;
    let mut builder = EmbeddingBuilder::new(cfg, "trace-filtered".into(), test_epoch());
    builder.add_feature("cf.1", FeatureFamily::ControlFlow, 100, 10);
    builder.add_feature("mem.1", FeatureFamily::MemoryAccess, 200, 10);
    assert_eq!(builder.component_count(), 1); // only ControlFlow accepted
}

#[test]
fn embedding_value_vector() {
    let emb = sample_embedding_a();
    let values = emb.value_vector();
    assert_eq!(values.len(), 4);
}

#[test]
fn embedding_keys() {
    let emb = sample_embedding_a();
    let keys = emb.keys();
    assert_eq!(keys.len(), 4);
    // Keys are sorted alphabetically
    for i in 1..keys.len() {
        assert!(keys[i - 1] <= keys[i]);
    }
}

#[test]
fn embedding_get_component() {
    let emb = sample_embedding_a();
    let comp = emb.get_component("opcode.add");
    assert!(comp.is_some());
    assert_eq!(comp.unwrap().family, FeatureFamily::InstructionDistribution);
    assert!(emb.get_component("nonexistent").is_none());
}

#[test]
fn embedding_value_for() {
    let emb = sample_embedding_a();
    assert_eq!(emb.value_for("opcode.add"), Some(500_000));
    assert!(emb.value_for("missing").is_none());
}

#[test]
fn embedding_family_count() {
    let emb = sample_embedding_a();
    assert_eq!(emb.family_count(FeatureFamily::InstructionDistribution), 2);
    assert_eq!(emb.family_count(FeatureFamily::ControlFlow), 1);
    assert_eq!(emb.family_count(FeatureFamily::CallGraph), 0);
}

#[test]
fn embedding_squared_norm() {
    let emb = sample_embedding_a();
    let norm = emb.squared_norm();
    assert!(norm > 0);
}

#[test]
fn embedding_content_hash_deterministic() {
    let e1 = sample_embedding_a();
    let e2 = sample_embedding_a();
    assert_eq!(e1.content_hash, e2.content_hash);
    assert_eq!(e1.embedding_id, e2.embedding_id);
}

#[test]
fn embedding_content_hash_differs() {
    let e1 = sample_embedding_a();
    let e2 = sample_embedding_b();
    assert_ne!(e1.content_hash, e2.content_hash);
}

#[test]
fn embedding_serde_round_trip() {
    let emb = sample_embedding_a();
    let json = serde_json::to_string(&emb).unwrap();
    let back: WorkloadEmbedding = serde_json::from_str(&json).unwrap();
    assert_eq!(emb, back);
}

#[test]
fn embedding_normalization() {
    let cfg = FeatureExtractionConfig {
        normalize: true,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let mut builder = EmbeddingBuilder::new(cfg, "trace-norm".into(), test_epoch());
    builder.add_feature("a", FeatureFamily::ControlFlow, 100_000, 10);
    builder.add_feature("b", FeatureFamily::ControlFlow, 500_000, 10);
    let emb = builder.build();
    let values = emb.value_vector();
    // After normalization, min maps to 0 and max maps to 1_000_000
    assert!(values.contains(&0));
    assert!(values.contains(&1_000_000));
}

// ---------------------------------------------------------------------------
// DistanceMetric
// ---------------------------------------------------------------------------

#[test]
fn distance_metric_display() {
    let metrics = [
        DistanceMetric::Manhattan,
        DistanceMetric::SquaredEuclidean,
        DistanceMetric::Chebyshev,
        DistanceMetric::Cosine,
    ];
    for m in &metrics {
        assert!(!format!("{m}").is_empty());
    }
}

#[test]
fn distance_metric_serde_round_trip() {
    let m = DistanceMetric::Cosine;
    let json = serde_json::to_string(&m).unwrap();
    let back: DistanceMetric = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ---------------------------------------------------------------------------
// compute_distance
// ---------------------------------------------------------------------------

#[test]
fn distance_identical_embeddings_is_zero() {
    let a = sample_embedding_a();
    let b = sample_embedding_a();
    for metric in [
        DistanceMetric::Manhattan,
        DistanceMetric::SquaredEuclidean,
        DistanceMetric::Chebyshev,
    ] {
        let result = compute_distance(&a, &b, metric);
        assert_eq!(result.distance_millionths, 0);
        assert_eq!(result.shared_dimensions, 4);
        assert_eq!(result.missing_in_a, 0);
        assert_eq!(result.missing_in_b, 0);
    }
}

#[test]
fn distance_nearby_embeddings_small() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let result = compute_distance(&a, &b, DistanceMetric::Chebyshev);
    assert!(result.distance_millionths > 0);
    assert!(result.distance_millionths < 100_000); // close
}

#[test]
fn distance_distant_embeddings_large() {
    let a = sample_embedding_a();
    let d = distant_embedding();
    let result = compute_distance(&a, &d, DistanceMetric::Chebyshev);
    assert!(result.distance_millionths > 100_000); // far
}

#[test]
fn distance_no_shared_dimensions() {
    let e1 = build_simple_embedding(
        "t1",
        vec![make_feature("only_a", FeatureFamily::ControlFlow, 100, 10)],
    );
    let e2 = build_simple_embedding(
        "t2",
        vec![make_feature("only_b", FeatureFamily::MemoryAccess, 200, 10)],
    );
    let result = compute_distance(&e1, &e2, DistanceMetric::Manhattan);
    assert_eq!(result.shared_dimensions, 0);
    assert_eq!(result.distance_millionths, 0); // no shared dims → 0
    assert_eq!(result.missing_in_b, 1);
    assert_eq!(result.missing_in_a, 1);
}

#[test]
fn distance_cosine_identical_is_near_zero() {
    let a = sample_embedding_a();
    let result = compute_distance(&a, &a, DistanceMetric::Cosine);
    // Cosine distance of identical vectors should be 0 (similarity = 1)
    assert!(result.distance_millionths <= 1); // allow tiny rounding
}

#[test]
fn distance_result_serde_round_trip() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let result = compute_distance(&a, &b, DistanceMetric::Manhattan);
    let json = serde_json::to_string(&result).unwrap();
    let back: DistanceResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// CertificateVerdict / AbstentionReason
// ---------------------------------------------------------------------------

#[test]
fn certificate_verdict_display() {
    let verdicts = [
        CertificateVerdict::Near,
        CertificateVerdict::Marginal,
        CertificateVerdict::Distant,
        CertificateVerdict::Abstained,
    ];
    for v in &verdicts {
        assert!(!format!("{v}").is_empty());
    }
}

#[test]
fn abstention_reason_display() {
    let reasons = [
        AbstentionReason::InvalidEmbedding,
        AbstentionReason::NoSharedDimensions,
        AbstentionReason::InsufficientSharedDimensions,
        AbstentionReason::EpochMismatch,
    ];
    for r in &reasons {
        assert!(!format!("{r}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// NeighborhoodCertificateConfig
// ---------------------------------------------------------------------------

#[test]
fn cert_config_default_reasonable() {
    let cfg = NeighborhoodCertificateConfig::default();
    assert!(cfg.near_threshold_millionths > 0);
    assert!(cfg.marginal_threshold_millionths > cfg.near_threshold_millionths);
    assert!(cfg.min_shared_dimensions > 0);
}

#[test]
fn cert_config_serde_round_trip() {
    let cfg = NeighborhoodCertificateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: NeighborhoodCertificateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// issue_neighborhood_certificate
// ---------------------------------------------------------------------------

#[test]
fn certificate_near_for_similar_embeddings() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cert = issue_neighborhood_certificate(
        &a,
        &b,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    assert!(cert.is_near());
    assert!(!cert.is_abstained());
    assert!(!cert.is_distant());
    assert!(cert.abstention_reason.is_none());
}

#[test]
fn certificate_distant_for_dissimilar_embeddings() {
    let a = sample_embedding_a();
    let d = distant_embedding();
    let cert = issue_neighborhood_certificate(
        &a,
        &d,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    assert!(cert.is_distant());
}

#[test]
fn certificate_abstained_for_invalid_embedding() {
    let valid = sample_embedding_a();
    // Build an empty/invalid embedding
    let builder = EmbeddingBuilder::new(
        FeatureExtractionConfig::default(),
        "invalid".into(),
        test_epoch(),
    );
    let invalid = builder.build();
    assert!(!invalid.is_valid());

    let cert = issue_neighborhood_certificate(
        &valid,
        &invalid,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    assert!(cert.is_abstained());
    assert_eq!(
        cert.abstention_reason,
        Some(AbstentionReason::InvalidEmbedding)
    );
}

#[test]
fn certificate_abstained_for_epoch_mismatch() {
    let a = build_simple_embedding(
        "trace-epoch-a",
        vec![make_feature("f1", FeatureFamily::ControlFlow, 100, 10)],
    );
    // Build embedding at a very different epoch
    let mut builder = EmbeddingBuilder::new(
        FeatureExtractionConfig {
            normalize: false,
            min_observations: 1,
            ..FeatureExtractionConfig::default()
        },
        "trace-epoch-b".into(),
        SecurityEpoch::from_raw(1000),
    );
    builder.add_feature("f1", FeatureFamily::ControlFlow, 100, 10);
    let b = builder.build();

    let cfg = NeighborhoodCertificateConfig {
        max_epoch_gap: 5,
        ..NeighborhoodCertificateConfig::default()
    };
    let cert = issue_neighborhood_certificate(&a, &b, &cfg, test_epoch());
    assert!(cert.is_abstained());
    assert_eq!(
        cert.abstention_reason,
        Some(AbstentionReason::EpochMismatch)
    );
}

#[test]
fn certificate_abstained_no_shared_dimensions() {
    let e1 = build_simple_embedding(
        "t1",
        vec![make_feature("only_a", FeatureFamily::ControlFlow, 100, 10)],
    );
    let e2 = build_simple_embedding(
        "t2",
        vec![make_feature("only_b", FeatureFamily::MemoryAccess, 200, 10)],
    );
    let cert = issue_neighborhood_certificate(
        &e1,
        &e2,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    assert!(cert.is_abstained());
    assert_eq!(
        cert.abstention_reason,
        Some(AbstentionReason::NoSharedDimensions)
    );
}

#[test]
fn certificate_content_hash_deterministic() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cfg = NeighborhoodCertificateConfig::default();
    let c1 = issue_neighborhood_certificate(&a, &b, &cfg, test_epoch());
    let c2 = issue_neighborhood_certificate(&a, &b, &cfg, test_epoch());
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c1.certificate_id, c2.certificate_id);
}

#[test]
fn certificate_serde_round_trip() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cert = issue_neighborhood_certificate(
        &a,
        &b,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    let json = serde_json::to_string(&cert).unwrap();
    let back: NeighborhoodCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// EmbeddingCatalog
// ---------------------------------------------------------------------------

#[test]
fn catalog_new_is_empty() {
    let cat = EmbeddingCatalog::new(test_epoch());
    assert!(cat.is_empty());
    assert_eq!(cat.len(), 0);
}

#[test]
fn catalog_insert_and_len() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(
        sample_embedding_a(),
        Some("workload-A".into()),
        BTreeSet::new(),
    );
    cat.insert(
        sample_embedding_b(),
        Some("workload-B".into()),
        BTreeSet::new(),
    );
    assert_eq!(cat.len(), 2);
}

#[test]
fn catalog_k_nearest() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_a(), Some("A".into()), BTreeSet::new());
    cat.insert(sample_embedding_b(), Some("B".into()), BTreeSet::new());
    cat.insert(distant_embedding(), Some("D".into()), BTreeSet::new());

    let query = sample_embedding_a();
    let neighbors = cat.k_nearest(&query, 2, DistanceMetric::Chebyshev);
    assert_eq!(neighbors.len(), 2);
    // B should be closer than D
    assert!(neighbors[0].distance.distance_millionths <= neighbors[1].distance.distance_millionths);
}

#[test]
fn catalog_k_nearest_excludes_self() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    let emb = sample_embedding_a();
    cat.insert(emb.clone(), Some("self".into()), BTreeSet::new());
    cat.insert(sample_embedding_b(), Some("other".into()), BTreeSet::new());

    let neighbors = cat.k_nearest(&emb, 10, DistanceMetric::Manhattan);
    // Should not include self
    for n in &neighbors {
        assert_ne!(n.embedding_id, emb.embedding_id);
    }
}

#[test]
fn catalog_within_radius() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_a(), Some("A".into()), BTreeSet::new());
    cat.insert(sample_embedding_b(), Some("B-near".into()), BTreeSet::new());
    cat.insert(distant_embedding(), Some("D-far".into()), BTreeSet::new());

    let query = sample_embedding_a();
    let within = cat.within_radius(&query, 50_000, DistanceMetric::Chebyshev);
    // B should be within radius, D should not
    assert!(within.len() >= 1);
    for n in &within {
        assert!(n.distance.distance_millionths <= 50_000);
    }
}

#[test]
fn catalog_summary() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_a(), None, BTreeSet::new());
    cat.insert(sample_embedding_b(), None, BTreeSet::new());
    let summary = cat.summary();
    assert_eq!(summary.total_entries, 2);
    assert_eq!(summary.valid_count, 2);
    assert_eq!(summary.invalid_count, 0);
    assert!(summary.avg_dimension > 0);
}

#[test]
fn catalog_summary_serde_round_trip() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_a(), None, BTreeSet::new());
    let summary = cat.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: CatalogSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// TransferRecommendation
// ---------------------------------------------------------------------------

#[test]
fn transfer_recommendation_serde_round_trip() {
    let r = TransferRecommendation::TransferAll;
    let json = serde_json::to_string(&r).unwrap();
    let back: TransferRecommendation = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// NeighborResult
// ---------------------------------------------------------------------------

#[test]
fn neighbor_result_serde_round_trip() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_b(), Some("B".into()), BTreeSet::new());
    let neighbors = cat.k_nearest(&sample_embedding_a(), 1, DistanceMetric::Manhattan);
    assert!(!neighbors.is_empty());
    let json = serde_json::to_string(&neighbors[0]).unwrap();
    let back: NeighborResult = serde_json::from_str(&json).unwrap();
    assert_eq!(neighbors[0], back);
}

// ---------------------------------------------------------------------------
// End-to-end workflow
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_extract_compare_certify() {
    // Step 1: Build two embeddings from "trace data"
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    assert!(a.is_valid());
    assert!(b.is_valid());

    // Step 2: Compute distances across all metrics
    for metric in [
        DistanceMetric::Manhattan,
        DistanceMetric::SquaredEuclidean,
        DistanceMetric::Chebyshev,
        DistanceMetric::Cosine,
    ] {
        let dist = compute_distance(&a, &b, metric);
        assert_eq!(dist.shared_dimensions, 4);
        assert_eq!(dist.missing_in_a, 0);
        assert_eq!(dist.missing_in_b, 0);
    }

    // Step 3: Issue neighborhood certificate
    let cert = issue_neighborhood_certificate(
        &a,
        &b,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    assert!(cert.is_near()); // similar embeddings → near

    // Step 4: Catalog and query
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(a.clone(), Some("A".into()), BTreeSet::new());
    cat.insert(b.clone(), Some("B".into()), BTreeSet::new());
    cat.insert(distant_embedding(), Some("D".into()), BTreeSet::new());

    let nearest = cat.k_nearest(&a, 1, DistanceMetric::Chebyshev);
    assert_eq!(nearest.len(), 1);
    assert_eq!(nearest[0].label.as_deref(), Some("B"));
}

// ===========================================================================
// Enrichment tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Constants enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_contains_v1() {
    assert!(EMBEDDING_SCHEMA_VERSION.contains(".v1"));
}

#[test]
fn enrichment_default_radius_is_five_percent() {
    assert_eq!(DEFAULT_NEIGHBORHOOD_RADIUS, 50_000);
}

#[test]
fn enrichment_default_cosine_threshold_is_seventy_percent() {
    assert_eq!(DEFAULT_COSINE_NEAR_THRESHOLD, 700_000);
}

#[test]
fn enrichment_max_dim_is_128() {
    assert_eq!(MAX_EMBEDDING_DIM, 128);
}

#[test]
fn enrichment_min_observations_is_8() {
    assert_eq!(MIN_OBSERVATIONS_FOR_EMBEDDING, 8);
}

// ---------------------------------------------------------------------------
// FeatureFamily enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_feature_family_debug_format() {
    let fam = FeatureFamily::InstructionDistribution;
    let dbg = format!("{fam:?}");
    assert!(dbg.contains("InstructionDistribution"));
}

#[test]
fn enrichment_feature_family_clone() {
    let original = FeatureFamily::HotPathProfile;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_feature_family_ordering_holds() {
    assert!(FeatureFamily::InstructionDistribution < FeatureFamily::HotPathProfile);
    assert!(FeatureFamily::HotPathProfile < FeatureFamily::ControlFlow);
}

#[test]
fn enrichment_feature_family_json_field_names() {
    let json = serde_json::to_string(&FeatureFamily::InstructionDistribution).unwrap();
    assert_eq!(json, "\"instruction_distribution\"");
    let json = serde_json::to_string(&FeatureFamily::HotPathProfile).unwrap();
    assert_eq!(json, "\"hot_path_profile\"");
    let json = serde_json::to_string(&FeatureFamily::ControlFlow).unwrap();
    assert_eq!(json, "\"control_flow\"");
    let json = serde_json::to_string(&FeatureFamily::MemoryAccess).unwrap();
    assert_eq!(json, "\"memory_access\"");
    let json = serde_json::to_string(&FeatureFamily::CallGraph).unwrap();
    assert_eq!(json, "\"call_graph\"");
    let json = serde_json::to_string(&FeatureFamily::StringPattern).unwrap();
    assert_eq!(json, "\"string_pattern\"");
    let json = serde_json::to_string(&FeatureFamily::ModuleGraph).unwrap();
    assert_eq!(json, "\"module_graph\"");
    let json = serde_json::to_string(&FeatureFamily::RegimeDistribution).unwrap();
    assert_eq!(json, "\"regime_distribution\"");
}

// ---------------------------------------------------------------------------
// FeatureComponent enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_feature_component_debug_format() {
    let comp = make_feature("test.key", FeatureFamily::ControlFlow, 500_000, 42);
    let dbg = format!("{comp:?}");
    assert!(dbg.contains("test.key"));
    assert!(dbg.contains("ControlFlow"));
}

#[test]
fn enrichment_feature_component_clone() {
    let comp = make_feature("test.key", FeatureFamily::ControlFlow, 500_000, 42);
    let cloned = comp.clone();
    assert_eq!(comp, cloned);
}

#[test]
fn enrichment_feature_component_serde_roundtrip() {
    let comp = make_feature(
        "opcode.Mul.ratio",
        FeatureFamily::InstructionDistribution,
        250_000,
        100,
    );
    let json = serde_json::to_string(&comp).unwrap();
    let back: FeatureComponent = serde_json::from_str(&json).unwrap();
    assert_eq!(comp, back);
}

#[test]
fn enrichment_feature_component_json_field_names() {
    let comp = make_feature("k", FeatureFamily::ControlFlow, 42, 10);
    let json = serde_json::to_string(&comp).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("key").is_some());
    assert!(v.get("family").is_some());
    assert!(v.get("value_millionths").is_some());
    assert!(v.get("observation_count").is_some());
}

#[test]
fn enrichment_feature_component_zero_observation() {
    let comp = make_feature("z", FeatureFamily::ControlFlow, 100, 0);
    assert_eq!(comp.observation_count, 0);
}

#[test]
fn enrichment_feature_component_negative_value() {
    let comp = make_feature("neg", FeatureFamily::MemoryAccess, -500_000, 50);
    assert_eq!(comp.value_millionths, -500_000);
    let json = serde_json::to_string(&comp).unwrap();
    let back: FeatureComponent = serde_json::from_str(&json).unwrap();
    assert_eq!(comp, back);
}

// ---------------------------------------------------------------------------
// FeatureExtractionConfig enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_default_schema_version_matches() {
    let cfg = FeatureExtractionConfig::default();
    assert_eq!(cfg.schema_version, EMBEDDING_SCHEMA_VERSION);
}

#[test]
fn enrichment_config_default_max_features_equals_max_dim() {
    let cfg = FeatureExtractionConfig::default();
    assert_eq!(cfg.max_features, MAX_EMBEDDING_DIM);
}

#[test]
fn enrichment_config_default_min_observations_matches_constant() {
    let cfg = FeatureExtractionConfig::default();
    assert_eq!(cfg.min_observations, MIN_OBSERVATIONS_FOR_EMBEDDING);
}

#[test]
fn enrichment_config_debug_format() {
    let cfg = FeatureExtractionConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("FeatureExtractionConfig"));
    assert!(dbg.contains("normalize"));
}

#[test]
fn enrichment_config_clone_eq() {
    let cfg = FeatureExtractionConfig::default();
    let cloned = cfg.clone();
    assert_eq!(cfg, cloned);
    assert_eq!(cfg.content_hash(), cloned.content_hash());
}

#[test]
fn enrichment_config_content_hash_changes_with_normalize() {
    let c1 = FeatureExtractionConfig::default();
    let mut c2 = FeatureExtractionConfig::default();
    c2.normalize = false;
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn enrichment_config_content_hash_changes_with_min_observations() {
    let c1 = FeatureExtractionConfig::default();
    let mut c2 = FeatureExtractionConfig::default();
    c2.min_observations = 100;
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn enrichment_config_content_hash_changes_with_families() {
    let c1 = FeatureExtractionConfig::default();
    let mut c2 = FeatureExtractionConfig::default();
    c2.enabled_families.insert(FeatureFamily::ControlFlow);
    assert_ne!(c1.content_hash(), c2.content_hash());
}

#[test]
fn enrichment_config_json_field_names() {
    let cfg = FeatureExtractionConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("schema_version").is_some());
    assert!(v.get("max_features").is_some());
    assert!(v.get("min_observations").is_some());
    assert!(v.get("enabled_families").is_some());
    assert!(v.get("normalize").is_some());
}

// ---------------------------------------------------------------------------
// EmbeddingValidity enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_embedding_validity_debug_format() {
    let v = EmbeddingValidity::Valid;
    let dbg = format!("{v:?}");
    assert!(dbg.contains("Valid"));
}

#[test]
fn enrichment_embedding_validity_clone() {
    let v = EmbeddingValidity::DimensionOverflow;
    let cloned = v.clone();
    assert_eq!(v, cloned);
}

#[test]
fn enrichment_embedding_validity_ordering() {
    assert!(EmbeddingValidity::Valid < EmbeddingValidity::InsufficientObservations);
    assert!(EmbeddingValidity::InsufficientObservations < EmbeddingValidity::DimensionOverflow);
    assert!(EmbeddingValidity::DimensionOverflow < EmbeddingValidity::Empty);
}

#[test]
fn enrichment_embedding_validity_json_field_names() {
    let json = serde_json::to_string(&EmbeddingValidity::Valid).unwrap();
    assert_eq!(json, "\"valid\"");
    let json = serde_json::to_string(&EmbeddingValidity::InsufficientObservations).unwrap();
    assert_eq!(json, "\"insufficient_observations\"");
    let json = serde_json::to_string(&EmbeddingValidity::DimensionOverflow).unwrap();
    assert_eq!(json, "\"dimension_overflow\"");
    let json = serde_json::to_string(&EmbeddingValidity::Empty).unwrap();
    assert_eq!(json, "\"empty\"");
}

// ---------------------------------------------------------------------------
// EmbeddingBuilder enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_builder_debug_format() {
    let builder = EmbeddingBuilder::new(
        FeatureExtractionConfig::default(),
        "dbg-trace".into(),
        test_epoch(),
    );
    let dbg = format!("{builder:?}");
    assert!(dbg.contains("EmbeddingBuilder"));
}

#[test]
fn enrichment_builder_clone() {
    let mut builder = EmbeddingBuilder::new(
        FeatureExtractionConfig::default(),
        "clone-trace".into(),
        test_epoch(),
    );
    builder.add_feature("x", FeatureFamily::ControlFlow, 100_000, 50);
    let cloned = builder.clone();
    assert_eq!(cloned.component_count(), 1);
}

#[test]
fn enrichment_builder_add_component_replaces_same_key() {
    let mut builder = EmbeddingBuilder::new(
        FeatureExtractionConfig {
            normalize: false,
            min_observations: 1,
            ..FeatureExtractionConfig::default()
        },
        "replace-trace".into(),
        test_epoch(),
    );
    builder.add_component(make_feature(
        "key.a",
        FeatureFamily::ControlFlow,
        100_000,
        10,
    ));
    builder.add_component(make_feature(
        "key.a",
        FeatureFamily::ControlFlow,
        200_000,
        10,
    ));
    assert_eq!(builder.component_count(), 1);
    let emb = builder.build();
    assert_eq!(emb.value_for("key.a"), Some(200_000));
}

#[test]
fn enrichment_builder_max_features_truncation() {
    let cfg = FeatureExtractionConfig {
        max_features: 3,
        normalize: false,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let mut builder = EmbeddingBuilder::new(cfg, "trunc-trace".into(), test_epoch());
    for i in 0..10 {
        builder.add_feature(
            &format!("f_{i:02}"),
            FeatureFamily::ControlFlow,
            (i as i64) * 1000,
            10,
        );
    }
    let emb = builder.build();
    // Truncated to 3 features (alphabetically first: f_00, f_01, f_02)
    assert_eq!(emb.dimension, 3);
    assert!(emb.get_component("f_00").is_some());
    assert!(emb.get_component("f_01").is_some());
    assert!(emb.get_component("f_02").is_some());
    assert!(emb.get_component("f_03").is_none());
}

#[test]
fn enrichment_builder_single_feature_normalization() {
    // With a single feature, normalization range = 0, so value stays as-is.
    let cfg = FeatureExtractionConfig {
        normalize: true,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let mut builder = EmbeddingBuilder::new(cfg, "single-norm".into(), test_epoch());
    builder.add_feature("only", FeatureFamily::ControlFlow, 500_000, 10);
    let emb = builder.build();
    // range = 0, so no normalization happens
    assert_eq!(emb.value_for("only"), Some(500_000));
}

#[test]
fn enrichment_builder_normalization_three_values() {
    let cfg = FeatureExtractionConfig {
        normalize: true,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let mut builder = EmbeddingBuilder::new(cfg, "three-norm".into(), test_epoch());
    builder.add_feature("a", FeatureFamily::ControlFlow, 0, 10);
    builder.add_feature("b", FeatureFamily::ControlFlow, 500_000, 10);
    builder.add_feature("c", FeatureFamily::ControlFlow, 1_000_000, 10);
    let emb = builder.build();
    // a=0 -> 0, c=1M -> 1M, b=500k -> 500k
    assert_eq!(emb.value_for("a"), Some(0));
    assert_eq!(emb.value_for("c"), Some(1_000_000));
    assert_eq!(emb.value_for("b"), Some(500_000));
}

#[test]
fn enrichment_builder_insufficient_total_observations() {
    // Individual features meet min_observations, but total < MIN_OBSERVATIONS_FOR_EMBEDDING
    let cfg = FeatureExtractionConfig {
        normalize: false,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let mut builder = EmbeddingBuilder::new(cfg, "insuff-total".into(), test_epoch());
    builder.add_feature("a", FeatureFamily::ControlFlow, 100_000, 2);
    builder.add_feature("b", FeatureFamily::ControlFlow, 200_000, 3);
    // total_observations = 5 < MIN_OBSERVATIONS_FOR_EMBEDDING (8)
    let emb = builder.build();
    assert_eq!(emb.validity, EmbeddingValidity::InsufficientObservations);
    assert!(!emb.is_valid());
}

// ---------------------------------------------------------------------------
// WorkloadEmbedding enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_embedding_debug_format() {
    let emb = sample_embedding_a();
    let dbg = format!("{emb:?}");
    assert!(dbg.contains("WorkloadEmbedding"));
    assert!(dbg.contains("embedding_id"));
}

#[test]
fn enrichment_embedding_clone_eq() {
    let emb = sample_embedding_a();
    let cloned = emb.clone();
    assert_eq!(emb, cloned);
    assert_eq!(emb.content_hash, cloned.content_hash);
}

#[test]
fn enrichment_embedding_schema_version_field() {
    let emb = sample_embedding_a();
    assert_eq!(emb.schema_version, EMBEDDING_SCHEMA_VERSION);
}

#[test]
fn enrichment_embedding_source_trace_id() {
    let emb = sample_embedding_a();
    assert_eq!(emb.source_trace_id, "trace-a");
}

#[test]
fn enrichment_embedding_id_format() {
    let emb = sample_embedding_a();
    assert!(emb.embedding_id.starts_with("emb-trace-a-"));
    assert!(emb.embedding_id.len() > 12);
}

#[test]
fn enrichment_embedding_epoch_preserved() {
    let emb = sample_embedding_a();
    assert_eq!(emb.epoch, test_epoch());
}

#[test]
fn enrichment_embedding_json_field_names() {
    let emb = sample_embedding_a();
    let json = serde_json::to_string(&emb).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("schema_version").is_some());
    assert!(v.get("embedding_id").is_some());
    assert!(v.get("source_trace_id").is_some());
    assert!(v.get("epoch").is_some());
    assert!(v.get("components").is_some());
    assert!(v.get("total_observations").is_some());
    assert!(v.get("dimension").is_some());
    assert!(v.get("validity").is_some());
    assert!(v.get("content_hash").is_some());
    assert!(v.get("config_hash").is_some());
}

#[test]
fn enrichment_embedding_config_hash_reflects_config() {
    let cfg1 = FeatureExtractionConfig {
        normalize: false,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let cfg2 = FeatureExtractionConfig {
        normalize: true,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let features = vec![
        make_feature("a", FeatureFamily::ControlFlow, 100_000, 10),
        make_feature("b", FeatureFamily::ControlFlow, 200_000, 10),
    ];
    let emb1 = build_simple_embedding_with_config("t1", features.clone(), cfg1);
    let emb2 = build_simple_embedding_with_config("t1", features, cfg2);
    assert_ne!(emb1.config_hash, emb2.config_hash);
}

fn build_simple_embedding_with_config(
    trace_id: &str,
    features: Vec<FeatureComponent>,
    config: FeatureExtractionConfig,
) -> WorkloadEmbedding {
    let mut builder = EmbeddingBuilder::new(config, trace_id.into(), test_epoch());
    for f in features {
        builder.add_component(f);
    }
    builder.build()
}

#[test]
fn enrichment_embedding_squared_norm_positive_for_nonzero() {
    let emb = sample_embedding_a();
    assert!(emb.squared_norm() > 0);
}

#[test]
fn enrichment_embedding_get_component_returns_correct_family() {
    let emb = sample_embedding_a();
    let comp = emb.get_component("branch_density").unwrap();
    assert_eq!(comp.family, FeatureFamily::ControlFlow);
}

#[test]
fn enrichment_embedding_keys_length_matches_dimension() {
    let emb = sample_embedding_a();
    assert_eq!(emb.keys().len(), emb.dimension);
}

// ---------------------------------------------------------------------------
// DistanceMetric enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_distance_metric_debug_format() {
    let m = DistanceMetric::Manhattan;
    let dbg = format!("{m:?}");
    assert!(dbg.contains("Manhattan"));
}

#[test]
fn enrichment_distance_metric_clone() {
    let m = DistanceMetric::Cosine;
    let cloned = m.clone();
    assert_eq!(m, cloned);
}

#[test]
fn enrichment_distance_metric_ordering() {
    assert!(DistanceMetric::Manhattan < DistanceMetric::SquaredEuclidean);
    assert!(DistanceMetric::SquaredEuclidean < DistanceMetric::Chebyshev);
    assert!(DistanceMetric::Chebyshev < DistanceMetric::Cosine);
}

#[test]
fn enrichment_distance_metric_json_names() {
    assert_eq!(
        serde_json::to_string(&DistanceMetric::Manhattan).unwrap(),
        "\"manhattan\""
    );
    assert_eq!(
        serde_json::to_string(&DistanceMetric::SquaredEuclidean).unwrap(),
        "\"squared_euclidean\""
    );
    assert_eq!(
        serde_json::to_string(&DistanceMetric::Chebyshev).unwrap(),
        "\"chebyshev\""
    );
    assert_eq!(
        serde_json::to_string(&DistanceMetric::Cosine).unwrap(),
        "\"cosine\""
    );
}

// ---------------------------------------------------------------------------
// DistanceResult enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_distance_result_debug_format() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let result = compute_distance(&a, &b, DistanceMetric::Manhattan);
    let dbg = format!("{result:?}");
    assert!(dbg.contains("DistanceResult"));
    assert!(dbg.contains("metric"));
}

#[test]
fn enrichment_distance_result_clone() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let result = compute_distance(&a, &b, DistanceMetric::Chebyshev);
    let cloned = result.clone();
    assert_eq!(result, cloned);
}

#[test]
fn enrichment_distance_result_json_field_names() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let result = compute_distance(&a, &b, DistanceMetric::Manhattan);
    let json = serde_json::to_string(&result).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("metric").is_some());
    assert!(v.get("distance_millionths").is_some());
    assert!(v.get("shared_dimensions").is_some());
    assert!(v.get("missing_in_b").is_some());
    assert!(v.get("missing_in_a").is_some());
}

#[test]
fn enrichment_distance_result_metric_field_matches() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let result = compute_distance(&a, &b, DistanceMetric::Chebyshev);
    assert_eq!(result.metric, DistanceMetric::Chebyshev);
}

// ---------------------------------------------------------------------------
// compute_distance enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cosine_distance_zero_vector_is_max() {
    let cfg = FeatureExtractionConfig {
        normalize: false,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let mut b1 = EmbeddingBuilder::new(cfg.clone(), "z1".into(), test_epoch());
    b1.add_feature("a", FeatureFamily::ControlFlow, 0, 10);
    b1.add_feature("b", FeatureFamily::ControlFlow, 0, 10);
    let mut b2 = EmbeddingBuilder::new(cfg, "z2".into(), test_epoch());
    b2.add_feature("a", FeatureFamily::ControlFlow, 100_000, 10);
    b2.add_feature("b", FeatureFamily::ControlFlow, 200_000, 10);
    let e1 = b1.build();
    let e2 = b2.build();
    let result = compute_distance(&e1, &e2, DistanceMetric::Cosine);
    // Zero vector -> cosine distance = MILLION (maximally distant)
    assert_eq!(result.distance_millionths, 1_000_000);
}

#[test]
fn enrichment_manhattan_is_symmetric() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let d_ab = compute_distance(&a, &b, DistanceMetric::Manhattan);
    let d_ba = compute_distance(&b, &a, DistanceMetric::Manhattan);
    assert_eq!(d_ab.distance_millionths, d_ba.distance_millionths);
}

#[test]
fn enrichment_squared_euclidean_is_symmetric() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let d_ab = compute_distance(&a, &b, DistanceMetric::SquaredEuclidean);
    let d_ba = compute_distance(&b, &a, DistanceMetric::SquaredEuclidean);
    assert_eq!(d_ab.distance_millionths, d_ba.distance_millionths);
}

#[test]
fn enrichment_chebyshev_is_symmetric() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let d_ab = compute_distance(&a, &b, DistanceMetric::Chebyshev);
    let d_ba = compute_distance(&b, &a, DistanceMetric::Chebyshev);
    assert_eq!(d_ab.distance_millionths, d_ba.distance_millionths);
}

#[test]
fn enrichment_cosine_is_symmetric() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let d_ab = compute_distance(&a, &b, DistanceMetric::Cosine);
    let d_ba = compute_distance(&b, &a, DistanceMetric::Cosine);
    assert_eq!(d_ab.distance_millionths, d_ba.distance_millionths);
}

#[test]
fn enrichment_distance_all_metrics_nonnegative() {
    let a = sample_embedding_a();
    let d = distant_embedding();
    for metric in [
        DistanceMetric::Manhattan,
        DistanceMetric::SquaredEuclidean,
        DistanceMetric::Chebyshev,
        DistanceMetric::Cosine,
    ] {
        let result = compute_distance(&a, &d, metric);
        assert!(
            result.distance_millionths >= 0,
            "negative distance for metric {metric}"
        );
    }
}

#[test]
fn enrichment_distance_deterministic_across_calls() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let r1 = compute_distance(&a, &b, DistanceMetric::Manhattan);
    let r2 = compute_distance(&a, &b, DistanceMetric::Manhattan);
    assert_eq!(r1, r2);
}

// ---------------------------------------------------------------------------
// CertificateVerdict enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_verdict_debug_format() {
    let v = CertificateVerdict::Near;
    assert!(format!("{v:?}").contains("Near"));
}

#[test]
fn enrichment_certificate_verdict_clone() {
    let v = CertificateVerdict::Marginal;
    let cloned = v.clone();
    assert_eq!(v, cloned);
}

#[test]
fn enrichment_certificate_verdict_json_names() {
    assert_eq!(
        serde_json::to_string(&CertificateVerdict::Near).unwrap(),
        "\"near\""
    );
    assert_eq!(
        serde_json::to_string(&CertificateVerdict::Marginal).unwrap(),
        "\"marginal\""
    );
    assert_eq!(
        serde_json::to_string(&CertificateVerdict::Distant).unwrap(),
        "\"distant\""
    );
    assert_eq!(
        serde_json::to_string(&CertificateVerdict::Abstained).unwrap(),
        "\"abstained\""
    );
}

// ---------------------------------------------------------------------------
// AbstentionReason enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_abstention_reason_debug_format() {
    let r = AbstentionReason::EpochMismatch;
    assert!(format!("{r:?}").contains("EpochMismatch"));
}

#[test]
fn enrichment_abstention_reason_clone() {
    let r = AbstentionReason::InvalidEmbedding;
    let cloned = r.clone();
    assert_eq!(r, cloned);
}

#[test]
fn enrichment_abstention_reason_json_names() {
    assert_eq!(
        serde_json::to_string(&AbstentionReason::InvalidEmbedding).unwrap(),
        "\"invalid_embedding\""
    );
    assert_eq!(
        serde_json::to_string(&AbstentionReason::NoSharedDimensions).unwrap(),
        "\"no_shared_dimensions\""
    );
    assert_eq!(
        serde_json::to_string(&AbstentionReason::InsufficientSharedDimensions).unwrap(),
        "\"insufficient_shared_dimensions\""
    );
    assert_eq!(
        serde_json::to_string(&AbstentionReason::EpochMismatch).unwrap(),
        "\"epoch_mismatch\""
    );
}

// ---------------------------------------------------------------------------
// NeighborhoodCertificateConfig enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cert_config_debug_format() {
    let cfg = NeighborhoodCertificateConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("NeighborhoodCertificateConfig"));
}

#[test]
fn enrichment_cert_config_clone() {
    let cfg = NeighborhoodCertificateConfig::default();
    let cloned = cfg.clone();
    assert_eq!(cfg, cloned);
}

#[test]
fn enrichment_cert_config_default_metric_is_chebyshev() {
    let cfg = NeighborhoodCertificateConfig::default();
    assert_eq!(cfg.metric, DistanceMetric::Chebyshev);
}

#[test]
fn enrichment_cert_config_default_near_eq_radius() {
    let cfg = NeighborhoodCertificateConfig::default();
    assert_eq!(cfg.near_threshold_millionths, DEFAULT_NEIGHBORHOOD_RADIUS);
}

#[test]
fn enrichment_cert_config_default_marginal_eq_2x_radius() {
    let cfg = NeighborhoodCertificateConfig::default();
    assert_eq!(
        cfg.marginal_threshold_millionths,
        DEFAULT_NEIGHBORHOOD_RADIUS * 2
    );
}

#[test]
fn enrichment_cert_config_default_min_shared_dims_is_3() {
    let cfg = NeighborhoodCertificateConfig::default();
    assert_eq!(cfg.min_shared_dimensions, 3);
}

#[test]
fn enrichment_cert_config_default_max_epoch_gap_is_5() {
    let cfg = NeighborhoodCertificateConfig::default();
    assert_eq!(cfg.max_epoch_gap, 5);
}

#[test]
fn enrichment_cert_config_json_field_names() {
    let cfg = NeighborhoodCertificateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("metric").is_some());
    assert!(v.get("near_threshold_millionths").is_some());
    assert!(v.get("marginal_threshold_millionths").is_some());
    assert!(v.get("min_shared_dimensions").is_some());
    assert!(v.get("max_epoch_gap").is_some());
}

// ---------------------------------------------------------------------------
// NeighborhoodCertificate enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_marginal_verdict() {
    // Create embeddings with distance between near and marginal thresholds
    let cfg_e = FeatureExtractionConfig {
        normalize: false,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let mut b1 = EmbeddingBuilder::new(cfg_e.clone(), "mg1".into(), test_epoch());
    b1.add_feature("a", FeatureFamily::ControlFlow, 0, 10);
    b1.add_feature("b", FeatureFamily::ControlFlow, 0, 10);
    b1.add_feature("c", FeatureFamily::ControlFlow, 0, 10);
    let mut b2 = EmbeddingBuilder::new(cfg_e, "mg2".into(), test_epoch());
    // Default near=50_000, marginal=100_000. Set diff to 75_000 (between them)
    b2.add_feature("a", FeatureFamily::ControlFlow, 75_000, 10);
    b2.add_feature("b", FeatureFamily::ControlFlow, 0, 10);
    b2.add_feature("c", FeatureFamily::ControlFlow, 0, 10);
    let e1 = b1.build();
    let e2 = b2.build();
    let cert_cfg = NeighborhoodCertificateConfig::default();
    let cert = issue_neighborhood_certificate(&e1, &e2, &cert_cfg, test_epoch());
    assert_eq!(cert.verdict, CertificateVerdict::Marginal);
    assert!(!cert.is_near());
    assert!(!cert.is_distant());
    assert!(!cert.is_abstained());
    assert!(cert.abstention_reason.is_none());
}

#[test]
fn enrichment_certificate_insufficient_shared_dims() {
    let cfg_e = FeatureExtractionConfig {
        normalize: false,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let mut b1 = EmbeddingBuilder::new(cfg_e.clone(), "isd1".into(), test_epoch());
    b1.add_feature("shared1", FeatureFamily::ControlFlow, 100, 10);
    b1.add_feature("only_a", FeatureFamily::ControlFlow, 200, 10);
    b1.add_feature("only_a2", FeatureFamily::ControlFlow, 300, 10);
    let mut b2 = EmbeddingBuilder::new(cfg_e, "isd2".into(), test_epoch());
    b2.add_feature("shared1", FeatureFamily::ControlFlow, 100, 10);
    b2.add_feature("only_b", FeatureFamily::ControlFlow, 400, 10);
    b2.add_feature("only_b2", FeatureFamily::ControlFlow, 500, 10);
    let e1 = b1.build();
    let e2 = b2.build();
    // Only 1 shared dim, but min_shared_dimensions=3
    let cert_cfg = NeighborhoodCertificateConfig::default();
    let cert = issue_neighborhood_certificate(&e1, &e2, &cert_cfg, test_epoch());
    assert!(cert.is_abstained());
    assert_eq!(
        cert.abstention_reason,
        Some(AbstentionReason::InsufficientSharedDimensions)
    );
}

#[test]
fn enrichment_certificate_debug_format() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cert = issue_neighborhood_certificate(
        &a,
        &b,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    let dbg = format!("{cert:?}");
    assert!(dbg.contains("NeighborhoodCertificate"));
    assert!(dbg.contains("verdict"));
}

#[test]
fn enrichment_certificate_clone() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cert = issue_neighborhood_certificate(
        &a,
        &b,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    let cloned = cert.clone();
    assert_eq!(cert, cloned);
}

#[test]
fn enrichment_certificate_json_field_names() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cert = issue_neighborhood_certificate(
        &a,
        &b,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    let json = serde_json::to_string(&cert).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("schema_version").is_some());
    assert!(v.get("certificate_id").is_some());
    assert!(v.get("source_embedding_id").is_some());
    assert!(v.get("target_embedding_id").is_some());
    assert!(v.get("distance").is_some());
    assert!(v.get("verdict").is_some());
    assert!(v.get("abstention_reason").is_some());
    assert!(v.get("epoch").is_some());
    assert!(v.get("content_hash").is_some());
}

#[test]
fn enrichment_certificate_near_id_format() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cert = issue_neighborhood_certificate(
        &a,
        &b,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    assert!(cert.certificate_id.starts_with("ncert-near-"));
}

#[test]
fn enrichment_certificate_abstained_id_format() {
    let valid = sample_embedding_a();
    let builder = EmbeddingBuilder::new(
        FeatureExtractionConfig::default(),
        "inv".into(),
        test_epoch(),
    );
    let invalid = builder.build();
    let cert = issue_neighborhood_certificate(
        &valid,
        &invalid,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    assert!(cert.certificate_id.starts_with("ncert-abstained-"));
}

#[test]
fn enrichment_certificate_source_and_target_ids_match() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cert = issue_neighborhood_certificate(
        &a,
        &b,
        &NeighborhoodCertificateConfig::default(),
        test_epoch(),
    );
    assert_eq!(cert.source_embedding_id, a.embedding_id);
    assert_eq!(cert.target_embedding_id, b.embedding_id);
}

// ---------------------------------------------------------------------------
// EmbeddingCatalog enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_catalog_debug_format() {
    let cat = EmbeddingCatalog::new(test_epoch());
    let dbg = format!("{cat:?}");
    assert!(dbg.contains("EmbeddingCatalog"));
}

#[test]
fn enrichment_catalog_clone() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_a(), Some("A".into()), BTreeSet::new());
    let cloned = cat.clone();
    assert_eq!(cloned.len(), 1);
}

#[test]
fn enrichment_catalog_schema_version() {
    let cat = EmbeddingCatalog::new(test_epoch());
    assert_eq!(cat.schema_version, EMBEDDING_SCHEMA_VERSION);
}

#[test]
fn enrichment_catalog_epoch_preserved() {
    let ep = SecurityEpoch::from_raw(99);
    let cat = EmbeddingCatalog::new(ep);
    assert_eq!(cat.epoch, ep);
}

#[test]
fn enrichment_catalog_insert_with_tags() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    let mut tags = BTreeSet::new();
    tags.insert("hot-path".to_string());
    tags.insert("v2".to_string());
    cat.insert(sample_embedding_a(), Some("tagged".into()), tags);
    assert_eq!(cat.len(), 1);
    assert_eq!(cat.entries[0].tags.len(), 2);
    assert!(cat.entries[0].tags.contains("hot-path"));
}

#[test]
fn enrichment_catalog_within_radius_zero_excludes_all() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_b(), Some("B".into()), BTreeSet::new());
    cat.insert(distant_embedding(), Some("D".into()), BTreeSet::new());
    let query = sample_embedding_a();
    // radius 0 excludes everything except exact match (which is excluded because same ID)
    let within = cat.within_radius(&query, 0, DistanceMetric::Chebyshev);
    // B has nonzero distance from A, so should be excluded
    for n in &within {
        assert_eq!(n.distance.distance_millionths, 0);
    }
}

#[test]
fn enrichment_catalog_within_radius_large_includes_all_valid() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_b(), Some("B".into()), BTreeSet::new());
    cat.insert(distant_embedding(), Some("D".into()), BTreeSet::new());
    let query = sample_embedding_a();
    let within = cat.within_radius(&query, i64::MAX, DistanceMetric::Chebyshev);
    assert_eq!(within.len(), 2);
}

#[test]
fn enrichment_catalog_k_nearest_sorted_by_distance() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_b(), Some("B".into()), BTreeSet::new());
    cat.insert(distant_embedding(), Some("D".into()), BTreeSet::new());
    let query = sample_embedding_a();
    let results = cat.k_nearest(&query, 10, DistanceMetric::Chebyshev);
    for i in 1..results.len() {
        assert!(
            results[i - 1].distance.distance_millionths <= results[i].distance.distance_millionths
        );
    }
}

#[test]
fn enrichment_catalog_skips_invalid_embeddings_in_k_nearest() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    // Insert an invalid (empty) embedding
    let invalid = EmbeddingBuilder::new(
        FeatureExtractionConfig::default(),
        "inv".into(),
        test_epoch(),
    )
    .build();
    cat.insert(invalid, Some("invalid".into()), BTreeSet::new());
    cat.insert(sample_embedding_b(), Some("B".into()), BTreeSet::new());
    let query = sample_embedding_a();
    let results = cat.k_nearest(&query, 10, DistanceMetric::Chebyshev);
    // Only B should appear (invalid filtered out)
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].label.as_deref(), Some("B"));
}

#[test]
fn enrichment_catalog_summary_avg_dimension() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_a(), None, BTreeSet::new()); // dim=4
    cat.insert(sample_embedding_b(), None, BTreeSet::new()); // dim=4
    let summary = cat.summary();
    assert_eq!(summary.avg_dimension, 4);
}

#[test]
fn enrichment_catalog_summary_family_feature_counts() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_a(), None, BTreeSet::new());
    let summary = cat.summary();
    // sample_embedding_a has 2 InstructionDistribution, 1 ControlFlow, 1 MemoryAccess
    assert!(summary.family_feature_counts.len() > 0);
    assert!(
        summary
            .family_feature_counts
            .contains_key("instruction_distribution")
    );
    assert!(summary.family_feature_counts.contains_key("control_flow"));
    assert!(summary.family_feature_counts.contains_key("memory_access"));
}

// ---------------------------------------------------------------------------
// CatalogEntry enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_catalog_entry_debug_format() {
    let entry = CatalogEntry {
        embedding: sample_embedding_a(),
        label: Some("test-label".into()),
        tags: BTreeSet::new(),
    };
    let dbg = format!("{entry:?}");
    assert!(dbg.contains("CatalogEntry"));
}

#[test]
fn enrichment_catalog_entry_clone() {
    let entry = CatalogEntry {
        embedding: sample_embedding_a(),
        label: Some("test-label".into()),
        tags: BTreeSet::new(),
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

#[test]
fn enrichment_catalog_entry_serde_roundtrip() {
    let mut tags = BTreeSet::new();
    tags.insert("tag1".to_string());
    let entry = CatalogEntry {
        embedding: sample_embedding_a(),
        label: Some("my-label".into()),
        tags,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: CatalogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// CatalogSummary enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_catalog_summary_debug_format() {
    let summary = CatalogSummary {
        total_entries: 3,
        valid_count: 2,
        invalid_count: 1,
        avg_dimension: 4,
        family_feature_counts: BTreeMap::new(),
    };
    let dbg = format!("{summary:?}");
    assert!(dbg.contains("CatalogSummary"));
}

#[test]
fn enrichment_catalog_summary_clone() {
    let summary = CatalogSummary {
        total_entries: 3,
        valid_count: 2,
        invalid_count: 1,
        avg_dimension: 4,
        family_feature_counts: BTreeMap::new(),
    };
    let cloned = summary.clone();
    assert_eq!(summary, cloned);
}

// ---------------------------------------------------------------------------
// NeighborResult enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_neighbor_result_debug_format() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_b(), Some("B".into()), BTreeSet::new());
    let neighbors = cat.k_nearest(&sample_embedding_a(), 1, DistanceMetric::Manhattan);
    let dbg = format!("{:?}", neighbors[0]);
    assert!(dbg.contains("NeighborResult"));
}

#[test]
fn enrichment_neighbor_result_clone() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_b(), Some("B".into()), BTreeSet::new());
    let neighbors = cat.k_nearest(&sample_embedding_a(), 1, DistanceMetric::Manhattan);
    let cloned = neighbors[0].clone();
    assert_eq!(neighbors[0], cloned);
}

// ---------------------------------------------------------------------------
// TransferRecommendation enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transfer_recommendation_debug_format() {
    let r = TransferRecommendation::TransferAll;
    assert!(format!("{r:?}").contains("TransferAll"));
}

#[test]
fn enrichment_transfer_recommendation_clone() {
    let r = TransferRecommendation::BlockTransfer;
    let cloned = r.clone();
    assert_eq!(r, cloned);
}

#[test]
fn enrichment_transfer_recommendation_json_names() {
    assert_eq!(
        serde_json::to_string(&TransferRecommendation::TransferAll).unwrap(),
        "\"transfer_all\""
    );
    assert_eq!(
        serde_json::to_string(&TransferRecommendation::TransferSelective).unwrap(),
        "\"transfer_selective\""
    );
    assert_eq!(
        serde_json::to_string(&TransferRecommendation::BlockTransfer).unwrap(),
        "\"block_transfer\""
    );
    assert_eq!(
        serde_json::to_string(&TransferRecommendation::CannotAssess).unwrap(),
        "\"cannot_assess\""
    );
}

// ---------------------------------------------------------------------------
// assess_transfer_safety enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transfer_safety_serde_roundtrip() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cfg = NeighborhoodCertificateConfig::default();
    let assessment = assess_transfer_safety(&a, &b, &cfg, test_epoch());
    let json = serde_json::to_string(&assessment).unwrap();
    let back: TransferSafetyAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(assessment, back);
}

#[test]
fn enrichment_transfer_safety_json_field_names() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cfg = NeighborhoodCertificateConfig::default();
    let assessment = assess_transfer_safety(&a, &b, &cfg, test_epoch());
    let json = serde_json::to_string(&assessment).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("schema_version").is_some());
    assert!(v.get("source_id").is_some());
    assert!(v.get("target_id").is_some());
    assert!(v.get("certificate").is_some());
    assert!(v.get("safe_families").is_some());
    assert!(v.get("blocked_families").is_some());
    assert!(v.get("family_distances").is_some());
    assert!(v.get("recommendation").is_some());
    assert!(v.get("content_hash").is_some());
}

#[test]
fn enrichment_transfer_safety_debug_format() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cfg = NeighborhoodCertificateConfig::default();
    let assessment = assess_transfer_safety(&a, &b, &cfg, test_epoch());
    let dbg = format!("{assessment:?}");
    assert!(dbg.contains("TransferSafetyAssessment"));
}

#[test]
fn enrichment_transfer_safety_clone() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cfg = NeighborhoodCertificateConfig::default();
    let assessment = assess_transfer_safety(&a, &b, &cfg, test_epoch());
    let cloned = assessment.clone();
    assert_eq!(assessment, cloned);
}

#[test]
fn enrichment_transfer_safety_deterministic() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cfg = NeighborhoodCertificateConfig::default();
    let a1 = assess_transfer_safety(&a, &b, &cfg, test_epoch());
    let a2 = assess_transfer_safety(&a, &b, &cfg, test_epoch());
    assert_eq!(a1, a2);
    assert_eq!(a1.content_hash, a2.content_hash);
}

#[test]
fn enrichment_transfer_safety_family_distances_populated() {
    let a = sample_embedding_a();
    let b = sample_embedding_b();
    let cfg = NeighborhoodCertificateConfig::default();
    let assessment = assess_transfer_safety(&a, &b, &cfg, test_epoch());
    // Should have entries for all families present in either embedding
    assert!(!assessment.family_distances.is_empty());
}

#[test]
fn enrichment_transfer_selective_when_some_families_blocked() {
    // Create embeddings where one family is near and another is distant
    let cfg_e = FeatureExtractionConfig {
        normalize: false,
        min_observations: 1,
        ..FeatureExtractionConfig::default()
    };
    let mut b1 = EmbeddingBuilder::new(cfg_e.clone(), "sel1".into(), test_epoch());
    b1.add_feature("cf.branch", FeatureFamily::ControlFlow, 100_000, 10);
    b1.add_feature("cf.loop", FeatureFamily::ControlFlow, 100_000, 10);
    b1.add_feature("cf.depth", FeatureFamily::ControlFlow, 100_000, 10);
    b1.add_feature("mem.alloc", FeatureFamily::MemoryAccess, 100_000, 10);
    let mut b2 = EmbeddingBuilder::new(cfg_e, "sel2".into(), test_epoch());
    b2.add_feature("cf.branch", FeatureFamily::ControlFlow, 110_000, 10);
    b2.add_feature("cf.loop", FeatureFamily::ControlFlow, 110_000, 10);
    b2.add_feature("cf.depth", FeatureFamily::ControlFlow, 110_000, 10);
    // mem.alloc is very different -> MemoryAccess family blocked
    b2.add_feature("mem.alloc", FeatureFamily::MemoryAccess, 900_000, 10);
    let e1 = b1.build();
    let e2 = b2.build();
    let cert_cfg = NeighborhoodCertificateConfig {
        min_shared_dimensions: 1,
        ..NeighborhoodCertificateConfig::default()
    };
    let assessment = assess_transfer_safety(&e1, &e2, &cert_cfg, test_epoch());
    // ControlFlow is safe, MemoryAccess is blocked
    assert!(assessment.safe_families.contains("control_flow"));
    assert!(assessment.blocked_families.contains("memory_access"));
}

// ---------------------------------------------------------------------------
// EmbeddingSpecimenFamily enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_family_debug_format() {
    let f = EmbeddingSpecimenFamily::Adversarial;
    assert!(format!("{f:?}").contains("Adversarial"));
}

#[test]
fn enrichment_specimen_family_clone() {
    let f = EmbeddingSpecimenFamily::Mixed;
    let cloned = f.clone();
    assert_eq!(f, cloned);
}

#[test]
fn enrichment_specimen_family_json_names() {
    assert_eq!(
        serde_json::to_string(&EmbeddingSpecimenFamily::ComputeBound).unwrap(),
        "\"compute_bound\""
    );
    assert_eq!(
        serde_json::to_string(&EmbeddingSpecimenFamily::MemoryIntensive).unwrap(),
        "\"memory_intensive\""
    );
    assert_eq!(
        serde_json::to_string(&EmbeddingSpecimenFamily::IoHeavy).unwrap(),
        "\"io_heavy\""
    );
    assert_eq!(
        serde_json::to_string(&EmbeddingSpecimenFamily::Mixed).unwrap(),
        "\"mixed\""
    );
    assert_eq!(
        serde_json::to_string(&EmbeddingSpecimenFamily::Trivial).unwrap(),
        "\"trivial\""
    );
    assert_eq!(
        serde_json::to_string(&EmbeddingSpecimenFamily::Adversarial).unwrap(),
        "\"adversarial\""
    );
}

// ---------------------------------------------------------------------------
// EmbeddingSpecimen enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_debug_format() {
    let corpus = build_evidence_corpus(test_epoch());
    let dbg = format!("{:?}", corpus[0]);
    assert!(dbg.contains("EmbeddingSpecimen"));
}

#[test]
fn enrichment_specimen_clone() {
    let corpus = build_evidence_corpus(test_epoch());
    let cloned = corpus[0].clone();
    assert_eq!(corpus[0], cloned);
}

#[test]
fn enrichment_specimen_serde_roundtrip() {
    let corpus = build_evidence_corpus(test_epoch());
    for s in &corpus {
        let json = serde_json::to_string(s).unwrap();
        let back: EmbeddingSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn enrichment_specimen_json_field_names() {
    let corpus = build_evidence_corpus(test_epoch());
    let json = serde_json::to_string(&corpus[0]).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("id").is_some());
    assert!(v.get("family").is_some());
    assert!(v.get("description").is_some());
    assert!(v.get("embedding").is_some());
}

#[test]
fn enrichment_specimen_descriptions_nonempty() {
    let corpus = build_evidence_corpus(test_epoch());
    for s in &corpus {
        assert!(!s.description.is_empty());
    }
}

#[test]
fn enrichment_specimen_embeddings_valid() {
    let corpus = build_evidence_corpus(test_epoch());
    for s in &corpus {
        assert!(s.embedding.is_valid(), "specimen {} should be valid", s.id);
    }
}

// ---------------------------------------------------------------------------
// build_evidence_corpus / run_embedding_corpus enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_corpus_hash_stable_across_same_epoch() {
    // The corpus hash depends on specimen IDs and embedding content hashes,
    // which are epoch-independent. Verify stability.
    let (_, h1) = run_embedding_corpus(SecurityEpoch::from_raw(1));
    let (_, h2) = run_embedding_corpus(SecurityEpoch::from_raw(1));
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_corpus_specimen_ids_start_with_specimen() {
    let corpus = build_evidence_corpus(test_epoch());
    for s in &corpus {
        assert!(
            s.id.starts_with("specimen-"),
            "id {} should start with specimen-",
            s.id
        );
    }
}

#[test]
fn enrichment_corpus_all_embeddings_have_schema_version() {
    let corpus = build_evidence_corpus(test_epoch());
    for s in &corpus {
        assert_eq!(s.embedding.schema_version, EMBEDDING_SCHEMA_VERSION);
    }
}

// ---------------------------------------------------------------------------
// Cross-cutting: determinism and edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_empty_embeddings_distance_is_zero() {
    let cfg = FeatureExtractionConfig::default();
    let e1 = EmbeddingBuilder::new(cfg.clone(), "e1".into(), test_epoch()).build();
    let e2 = EmbeddingBuilder::new(cfg, "e2".into(), test_epoch()).build();
    for metric in [
        DistanceMetric::Manhattan,
        DistanceMetric::SquaredEuclidean,
        DistanceMetric::Chebyshev,
        DistanceMetric::Cosine,
    ] {
        let result = compute_distance(&e1, &e2, metric);
        assert_eq!(result.shared_dimensions, 0);
    }
}

#[test]
fn enrichment_catalog_serde_roundtrip() {
    let mut cat = EmbeddingCatalog::new(test_epoch());
    cat.insert(sample_embedding_a(), Some("A".into()), BTreeSet::new());
    cat.insert(sample_embedding_b(), None, BTreeSet::new());
    let json = serde_json::to_string(&cat).unwrap();
    let back: EmbeddingCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(back.schema_version, EMBEDDING_SCHEMA_VERSION);
}

#[test]
fn enrichment_end_to_end_corpus_catalog_nearest() {
    let corpus = build_evidence_corpus(test_epoch());
    let mut cat = EmbeddingCatalog::new(test_epoch());
    for s in &corpus {
        cat.insert(s.embedding.clone(), Some(s.id.clone()), BTreeSet::new());
    }
    // Query with the compute-bound specimen
    let compute_emb = &corpus[0].embedding;
    let neighbors = cat.k_nearest(compute_emb, 2, DistanceMetric::Chebyshev);
    assert_eq!(neighbors.len(), 2);
    // Nearest neighbors should be sorted by distance
    assert!(neighbors[0].distance.distance_millionths <= neighbors[1].distance.distance_millionths);
}
