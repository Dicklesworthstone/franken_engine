//! Integration tests for workload embedding module (RGC-612A).

use std::collections::BTreeSet;

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::workload_embedding::{
    AbstentionReason, CatalogSummary, CertificateVerdict, DEFAULT_COSINE_NEAR_THRESHOLD,
    DEFAULT_NEIGHBORHOOD_RADIUS, DistanceMetric, DistanceResult, EMBEDDING_SCHEMA_VERSION,
    EmbeddingBuilder, EmbeddingCatalog, EmbeddingValidity, FeatureComponent,
    FeatureExtractionConfig, FeatureFamily, MAX_EMBEDDING_DIM, MIN_OBSERVATIONS_FOR_EMBEDDING,
    NeighborResult, NeighborhoodCertificate, NeighborhoodCertificateConfig, TransferRecommendation,
    WorkloadEmbedding, compute_distance, issue_neighborhood_certificate,
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
    assert!(MAX_EMBEDDING_DIM > 0);
    assert!(MIN_OBSERVATIONS_FOR_EMBEDDING > 0);
    assert!(DEFAULT_NEIGHBORHOOD_RADIUS > 0);
    assert!(DEFAULT_COSINE_NEAR_THRESHOLD > 0);
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
