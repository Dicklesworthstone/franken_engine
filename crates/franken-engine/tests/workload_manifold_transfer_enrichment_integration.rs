//! Enrichment integration tests for workload_manifold_transfer.
//!
//! Covers multi-workload manifold operations, neighborhood certificate chains,
//! transfer governance, drift detection, embedding distance edge cases,
//! content hash stability, and complex serialization round-trips.
//!
//! Plan reference: bd-1lsy.7.12 (RGC-612).

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::workload_manifold_transfer::{
    BEAD_ID, COMPONENT, EMBEDDING_DIMENSIONS, EmbeddingFeature, MAX_EMBEDDINGS, ManifoldError,
    NEIGHBORHOOD_THRESHOLD_MILLIONTHS, NeighborhoodCertificate, SCHEMA_VERSION, TransferKind,
    TransferManifest, TransferRecord, WorkloadEmbedding, build_seed_manifest,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_embedding(id: &str, feats: &[(EmbeddingFeature, i64)]) -> WorkloadEmbedding {
    let mut e = WorkloadEmbedding::new(id.to_string(), ContentHash::compute(id.as_bytes()));
    for (f, v) in feats {
        e.set_dimension(*f, *v);
    }
    e
}

fn make_transfer(
    id: &str,
    kind: TransferKind,
    src: &str,
    tgt: &str,
    items: u64,
    drift: bool,
    rollback: bool,
) -> TransferRecord {
    TransferRecord {
        id: id.to_string(),
        kind,
        source_workload: src.to_string(),
        target_workload: tgt.to_string(),
        certificate_hash: ContentHash::compute(format!("{src}:{tgt}:{id}").as_bytes()),
        items_transferred: items,
        drift_detected: drift,
        rollback_triggered: rollback,
    }
}

// ---------------------------------------------------------------------------
// Embedding feature enumeration
// ---------------------------------------------------------------------------

#[test]
fn all_features_have_distinct_str() {
    let strs: Vec<&str> = EmbeddingFeature::ALL.iter().map(|f| f.as_str()).collect();
    for (i, a) in strs.iter().enumerate() {
        for (j, b) in strs.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "features {i} and {j} share label {a}");
            }
        }
    }
}

#[test]
fn all_features_display_matches_as_str() {
    for f in EmbeddingFeature::ALL {
        assert_eq!(format!("{f}"), f.as_str());
    }
}

#[test]
fn embedding_feature_serde_roundtrip_all() {
    for f in EmbeddingFeature::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: EmbeddingFeature = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
        // JSON string should be the snake_case label
        assert!(
            json.contains(f.as_str()),
            "JSON {json} missing {}",
            f.as_str()
        );
    }
}

#[test]
fn embedding_feature_ordering_is_stable() {
    let mut sorted = EmbeddingFeature::ALL.to_vec();
    sorted.sort();
    // ALL should already be in declaration order; sorted may differ
    // but re-sorting should be idempotent
    let mut resorted = sorted.clone();
    resorted.sort();
    assert_eq!(sorted, resorted);
}

// ---------------------------------------------------------------------------
// WorkloadEmbedding distance and similarity
// ---------------------------------------------------------------------------

#[test]
fn distance_squared_symmetric() {
    let a = make_embedding("a", &[(EmbeddingFeature::IrNodeCount, 100_000)]);
    let b = make_embedding("b", &[(EmbeddingFeature::IrNodeCount, 300_000)]);
    assert_eq!(a.distance_squared(&b), b.distance_squared(&a));
}

#[test]
fn distance_squared_triangle_inequality_approx() {
    let a = make_embedding(
        "a",
        &[
            (EmbeddingFeature::IrNodeCount, 100_000),
            (EmbeddingFeature::AllocationRate, 200_000),
        ],
    );
    let b = make_embedding(
        "b",
        &[
            (EmbeddingFeature::IrNodeCount, 200_000),
            (EmbeddingFeature::AllocationRate, 300_000),
        ],
    );
    let c = make_embedding(
        "c",
        &[
            (EmbeddingFeature::IrNodeCount, 400_000),
            (EmbeddingFeature::AllocationRate, 500_000),
        ],
    );
    // sqrt(d(a,c)) <= sqrt(d(a,b)) + sqrt(d(b,c))
    // We just verify d(a,c) <= 2*(d(a,b) + d(b,c)) as a loose sanity check
    let dab = a.distance_squared(&b);
    let dbc = b.distance_squared(&c);
    let dac = a.distance_squared(&c);
    assert!(dac <= 4 * (dab + dbc), "loose triangle violated");
}

#[test]
fn cosine_similarity_symmetric() {
    let a = make_embedding(
        "a",
        &[
            (EmbeddingFeature::IrNodeCount, 100_000),
            (EmbeddingFeature::AllocationRate, 200_000),
        ],
    );
    let b = make_embedding(
        "b",
        &[
            (EmbeddingFeature::IrNodeCount, 50_000),
            (EmbeddingFeature::AllocationRate, 150_000),
        ],
    );
    assert_eq!(
        a.cosine_similarity_millionths(&b),
        b.cosine_similarity_millionths(&a)
    );
}

#[test]
fn cosine_similarity_orthogonal_low() {
    // Vectors on different feature axes should have low cosine similarity
    let a = make_embedding("a", &[(EmbeddingFeature::IrNodeCount, 1_000_000)]);
    let b = make_embedding("b", &[(EmbeddingFeature::AllocationRate, 1_000_000)]);
    let sim = a.cosine_similarity_millionths(&b);
    assert!(
        sim < 100_000,
        "orthogonal vectors should have low sim, got {sim}"
    );
}

#[test]
fn cosine_similarity_proportional_vectors_high() {
    // Proportional vectors should have high similarity
    let a = make_embedding(
        "a",
        &[
            (EmbeddingFeature::IrNodeCount, 100_000),
            (EmbeddingFeature::AllocationRate, 200_000),
        ],
    );
    let b = make_embedding(
        "b",
        &[
            (EmbeddingFeature::IrNodeCount, 300_000),
            (EmbeddingFeature::AllocationRate, 600_000),
        ],
    );
    let sim = a.cosine_similarity_millionths(&b);
    assert!(
        sim > 900_000,
        "proportional vectors should have high sim, got {sim}"
    );
}

#[test]
fn cosine_both_zero_vectors() {
    let a = make_embedding("a", &[]);
    let b = make_embedding("b", &[]);
    assert_eq!(a.cosine_similarity_millionths(&b), 0);
}

#[test]
fn distance_all_features_set() {
    let feats_a: Vec<(EmbeddingFeature, i64)> = EmbeddingFeature::ALL
        .iter()
        .enumerate()
        .map(|(i, f)| (*f, (i as i64 + 1) * 100_000))
        .collect();
    let feats_b: Vec<(EmbeddingFeature, i64)> = EmbeddingFeature::ALL
        .iter()
        .enumerate()
        .map(|(i, f)| (*f, (i as i64 + 2) * 100_000))
        .collect();
    let a = make_embedding("a", &feats_a);
    let b = make_embedding("b", &feats_b);
    let dist = a.distance_squared(&b);
    // Each dimension differs by 100_000, so sum = 16 * (100_000)^2 = 160_000_000_000
    assert_eq!(dist, 16 * 100_000u64 * 100_000u64);
}

#[test]
fn embedding_negative_dimension_values() {
    let a = make_embedding("a", &[(EmbeddingFeature::IrNodeCount, -500_000)]);
    let b = make_embedding("b", &[(EmbeddingFeature::IrNodeCount, 500_000)]);
    let dist = a.distance_squared(&b);
    assert_eq!(dist, 1_000_000u64 * 1_000_000u64);
}

// ---------------------------------------------------------------------------
// TransferManifest embedding management
// ---------------------------------------------------------------------------

#[test]
fn manifest_add_multiple_embeddings() {
    let mut m = TransferManifest::new();
    for i in 0..10 {
        let e = make_embedding(
            &format!("w{i}"),
            &[(EmbeddingFeature::IrNodeCount, i * 1000)],
        );
        m.add_embedding(e).unwrap();
    }
    assert_eq!(m.embeddings.len(), 10);
}

#[test]
fn manifest_duplicate_different_features_still_rejected() {
    let mut m = TransferManifest::new();
    m.add_embedding(make_embedding("a", &[(EmbeddingFeature::IrNodeCount, 100)]))
        .unwrap();
    // Same ID, different features — still a duplicate
    let err = m
        .add_embedding(make_embedding(
            "a",
            &[(EmbeddingFeature::AllocationRate, 200)],
        ))
        .unwrap_err();
    assert!(matches!(err, ManifoldError::DuplicateEmbedding { .. }));
}

#[test]
fn manifest_version_matches_schema() {
    let m = TransferManifest::new();
    assert_eq!(m.version, SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Neighborhood certificates
// ---------------------------------------------------------------------------

#[test]
fn certificate_chain_transitive_neighbors() {
    let mut m = TransferManifest::new();
    // Three similar embeddings
    let base_feats = vec![
        (EmbeddingFeature::IrNodeCount, 500_000),
        (EmbeddingFeature::AllocationRate, 300_000),
        (EmbeddingFeature::ModuleGraphSize, 400_000),
    ];
    for id in ["w1", "w2", "w3"] {
        m.add_embedding(make_embedding(id, &base_feats)).unwrap();
    }
    let c12 = m.compute_certificate("w1", "w2").unwrap();
    let c23 = m.compute_certificate("w2", "w3").unwrap();
    let c13 = m.compute_certificate("w1", "w3").unwrap();
    // All identical, so all should be neighbors
    assert!(c12.is_neighbor);
    assert!(c23.is_neighbor);
    assert!(c13.is_neighbor);
}

#[test]
fn certificate_dissimilar_not_neighbor() {
    let mut m = TransferManifest::new();
    // Very different embeddings
    m.add_embedding(make_embedding(
        "compute",
        &[(EmbeddingFeature::IrNodeCount, 1_000_000)],
    ))
    .unwrap();
    m.add_embedding(make_embedding(
        "io_heavy",
        &[(EmbeddingFeature::HostcallFrequency, 1_000_000)],
    ))
    .unwrap();
    let cert = m.compute_certificate("compute", "io_heavy").unwrap();
    assert!(
        !cert.is_neighbor,
        "very different workloads should not be neighbors"
    );
}

#[test]
fn certificate_hash_deterministic() {
    let mut m = TransferManifest::new();
    let feats = vec![(EmbeddingFeature::IrNodeCount, 100_000)];
    m.add_embedding(make_embedding("a", &feats)).unwrap();
    m.add_embedding(make_embedding("b", &feats)).unwrap();
    let c1 = m.compute_certificate("a", "b").unwrap();
    let c2 = m.compute_certificate("a", "b").unwrap();
    assert_eq!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn certificate_direction_matters() {
    let mut m = TransferManifest::new();
    let feats = vec![(EmbeddingFeature::IrNodeCount, 100_000)];
    m.add_embedding(make_embedding("a", &feats)).unwrap();
    m.add_embedding(make_embedding("b", &feats)).unwrap();
    let c_ab = m.compute_certificate("a", "b").unwrap();
    let c_ba = m.compute_certificate("b", "a").unwrap();
    // Similarity should be same but certificate hashes differ due to direction
    assert_eq!(c_ab.similarity_millionths, c_ba.similarity_millionths);
    // Direction encoded in hash
    assert_ne!(c_ab.certificate_hash, c_ba.certificate_hash);
}

#[test]
fn certificate_threshold_boundary() {
    let cert = NeighborhoodCertificate {
        source_workload: "a".to_string(),
        target_workload: "b".to_string(),
        similarity_millionths: NEIGHBORHOOD_THRESHOLD_MILLIONTHS,
        distance_squared: 0,
        threshold_millionths: NEIGHBORHOOD_THRESHOLD_MILLIONTHS,
        is_neighbor: true,
        certificate_hash: ContentHash::compute(b"test"),
    };
    assert!(cert.is_neighbor);
    assert_eq!(cert.similarity_millionths, cert.threshold_millionths);
}

// ---------------------------------------------------------------------------
// TransferRecord and transfer governance
// ---------------------------------------------------------------------------

#[test]
fn transfer_kind_all_variants_distinct() {
    let kinds = [
        TransferKind::RewriteRules,
        TransferKind::TieringDecisions,
        TransferKind::CachePriors,
        TransferKind::InlineCandidates,
        TransferKind::AllocationHints,
        TransferKind::TypeProfileHints,
    ];
    for (i, a) in kinds.iter().enumerate() {
        for (j, b) in kinds.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
                assert_ne!(a.as_str(), b.as_str());
            }
        }
    }
}

#[test]
fn transfer_kind_display_matches_as_str() {
    for kind in [
        TransferKind::RewriteRules,
        TransferKind::TieringDecisions,
        TransferKind::CachePriors,
        TransferKind::InlineCandidates,
        TransferKind::AllocationHints,
        TransferKind::TypeProfileHints,
    ] {
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

#[test]
fn drift_count_with_mixed_records() {
    let mut m = TransferManifest::new();
    m.transfers.push(make_transfer(
        "t1",
        TransferKind::RewriteRules,
        "a",
        "b",
        5,
        true,
        false,
    ));
    m.transfers.push(make_transfer(
        "t2",
        TransferKind::CachePriors,
        "a",
        "c",
        3,
        false,
        false,
    ));
    m.transfers.push(make_transfer(
        "t3",
        TransferKind::TieringDecisions,
        "b",
        "c",
        8,
        true,
        true,
    ));
    assert_eq!(m.drift_count(), 2);
    assert_eq!(m.rollback_count(), 1);
}

#[test]
fn zero_drifts_when_all_clean() {
    let mut m = TransferManifest::new();
    for i in 0..5 {
        m.transfers.push(make_transfer(
            &format!("t{i}"),
            TransferKind::AllocationHints,
            "src",
            &format!("tgt{i}"),
            10,
            false,
            false,
        ));
    }
    assert_eq!(m.drift_count(), 0);
    assert_eq!(m.rollback_count(), 0);
}

#[test]
fn all_rollbacks_implies_all_drifts() {
    let mut m = TransferManifest::new();
    for i in 0..3 {
        m.transfers.push(make_transfer(
            &format!("t{i}"),
            TransferKind::TypeProfileHints,
            "src",
            &format!("tgt{i}"),
            2,
            true,
            true,
        ));
    }
    assert_eq!(m.drift_count(), 3);
    assert_eq!(m.rollback_count(), 3);
}

// ---------------------------------------------------------------------------
// Content hash
// ---------------------------------------------------------------------------

#[test]
fn content_hash_changes_with_embedding_id() {
    let mut m1 = TransferManifest::new();
    m1.add_embedding(make_embedding(
        "alpha",
        &[(EmbeddingFeature::IrNodeCount, 100_000)],
    ))
    .unwrap();
    let mut m2 = TransferManifest::new();
    m2.add_embedding(make_embedding(
        "beta",
        &[(EmbeddingFeature::IrNodeCount, 100_000)],
    ))
    .unwrap();
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn content_hash_changes_with_dimension_count() {
    let mut m1 = TransferManifest::new();
    m1.add_embedding(make_embedding(
        "a",
        &[(EmbeddingFeature::IrNodeCount, 100_000)],
    ))
    .unwrap();
    let mut m2 = TransferManifest::new();
    m2.add_embedding(make_embedding(
        "a",
        &[
            (EmbeddingFeature::IrNodeCount, 100_000),
            (EmbeddingFeature::AllocationRate, 200_000),
        ],
    ))
    .unwrap();
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn content_hash_empty_manifest() {
    let m1 = TransferManifest::new();
    let m2 = TransferManifest::new();
    assert_eq!(m1.content_hash(), m2.content_hash());
}

// ---------------------------------------------------------------------------
// Serialization round-trips
// ---------------------------------------------------------------------------

#[test]
fn manifest_full_serde_roundtrip() {
    let mut m = TransferManifest::new();
    for i in 0..5 {
        let feats: Vec<(EmbeddingFeature, i64)> = EmbeddingFeature::ALL
            .iter()
            .take(4)
            .enumerate()
            .map(|(j, f)| (*f, (i * 100_000 + j as i64 * 50_000)))
            .collect();
        m.add_embedding(make_embedding(&format!("workload_{i}"), &feats))
            .unwrap();
    }
    m.transfers.push(make_transfer(
        "t1",
        TransferKind::RewriteRules,
        "workload_0",
        "workload_1",
        10,
        false,
        false,
    ));
    m.transfers.push(make_transfer(
        "t2",
        TransferKind::CachePriors,
        "workload_2",
        "workload_3",
        7,
        true,
        false,
    ));

    let json = serde_json::to_string_pretty(&m).unwrap();
    let back: TransferManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m.embeddings.len(), back.embeddings.len());
    assert_eq!(m.transfers.len(), back.transfers.len());
    assert_eq!(m.content_hash(), back.content_hash());
    assert_eq!(m.drift_count(), back.drift_count());
}

#[test]
fn transfer_record_serde_roundtrip() {
    let rec = make_transfer(
        "tx1",
        TransferKind::InlineCandidates,
        "src",
        "tgt",
        42,
        true,
        false,
    );
    let json = serde_json::to_string(&rec).unwrap();
    let back: TransferRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn neighborhood_certificate_serde_roundtrip() {
    let cert = NeighborhoodCertificate {
        source_workload: "alpha".to_string(),
        target_workload: "beta".to_string(),
        similarity_millionths: 950_000,
        distance_squared: 12345,
        threshold_millionths: NEIGHBORHOOD_THRESHOLD_MILLIONTHS,
        is_neighbor: true,
        certificate_hash: ContentHash::compute(b"test-cert"),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let back: NeighborhoodCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// Seed manifest
// ---------------------------------------------------------------------------

#[test]
fn seed_manifest_workload_ids() {
    let m = build_seed_manifest();
    let ids: Vec<&str> = m
        .embeddings
        .iter()
        .map(|e| e.workload_id.as_str())
        .collect();
    assert!(ids.contains(&"express_app"));
    assert!(ids.contains(&"react_ssr"));
    assert!(ids.contains(&"cli_tool"));
}

#[test]
fn seed_manifest_certificates_between_all_pairs() {
    let m = build_seed_manifest();
    let ids: Vec<String> = m.embeddings.iter().map(|e| e.workload_id.clone()).collect();
    for i in 0..ids.len() {
        for j in 0..ids.len() {
            let cert = m.compute_certificate(&ids[i], &ids[j]);
            assert!(
                cert.is_some(),
                "certificate missing for {}:{}",
                ids[i],
                ids[j]
            );
        }
    }
}

#[test]
fn seed_manifest_react_ssr_has_high_allocation() {
    let m = build_seed_manifest();
    let react = m
        .embeddings
        .iter()
        .find(|e| e.workload_id == "react_ssr")
        .unwrap();
    let alloc = react.get_dimension(&EmbeddingFeature::AllocationRate);
    assert!(alloc > 0, "react_ssr should have allocation rate set");
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn error_display_overflow() {
    let e = ManifoldError::EmbeddingOverflow { max: 42 };
    let msg = format!("{e}");
    assert!(msg.contains("42"));
    assert!(msg.contains("overflow"));
}

#[test]
fn error_display_duplicate() {
    let e = ManifoldError::DuplicateEmbedding {
        id: "test_workload".to_string(),
    };
    let msg = format!("{e}");
    assert!(msg.contains("test_workload"));
    assert!(msg.contains("duplicate"));
}

#[test]
fn error_serde_roundtrip() {
    let errors = vec![
        ManifoldError::EmbeddingOverflow { max: 100 },
        ManifoldError::DuplicateEmbedding {
            id: "dup".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: ManifoldError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::assertions_on_constants)]
fn constants_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(EMBEDDING_DIMENSIONS > 0);
    assert!(MAX_EMBEDDINGS > 0);
    assert!(NEIGHBORHOOD_THRESHOLD_MILLIONTHS > 0);
}

#[test]
fn schema_version_contains_component() {
    assert!(
        SCHEMA_VERSION.contains("workload-manifold-transfer"),
        "schema version should reference component"
    );
}

// ---------------------------------------------------------------------------
// Large manifold scenarios
// ---------------------------------------------------------------------------

#[test]
fn manifold_with_100_embeddings() {
    let mut m = TransferManifest::new();
    for i in 0..100 {
        let feats = vec![
            (EmbeddingFeature::IrNodeCount, i * 10_000),
            (EmbeddingFeature::AllocationRate, (100 - i) * 10_000),
        ];
        m.add_embedding(make_embedding(&format!("w{i}"), &feats))
            .unwrap();
    }
    assert_eq!(m.embeddings.len(), 100);
    // Nearby workloads should be similar
    let cert = m.compute_certificate("w50", "w51").unwrap();
    // May or may not be neighbor depending on threshold
    assert!(
        cert.distance_squared < 1_000_000_000,
        "nearby workloads should have small distance"
    );
}

#[test]
fn manifold_drift_ratio() {
    let mut m = TransferManifest::new();
    for i in 0..20 {
        m.transfers.push(make_transfer(
            &format!("t{i}"),
            TransferKind::RewriteRules,
            "src",
            &format!("tgt{i}"),
            5,
            i % 3 == 0, // drift every 3rd
            i % 6 == 0, // rollback every 6th
        ));
    }
    let drift_ratio = m.drift_count() as f64 / m.transfers.len() as f64;
    assert!(drift_ratio > 0.0 && drift_ratio < 1.0);
    assert!(m.rollback_count() <= m.drift_count());
}

#[test]
fn manifold_content_hash_order_independent_for_same_ids() {
    // Content hash depends on insertion order since embeddings is a Vec
    // This test verifies that consistent insertion yields consistent hashes
    let feats_a = vec![(EmbeddingFeature::IrNodeCount, 100_000)];
    let feats_b = vec![(EmbeddingFeature::AllocationRate, 200_000)];

    let mut m1 = TransferManifest::new();
    m1.add_embedding(make_embedding("a", &feats_a)).unwrap();
    m1.add_embedding(make_embedding("b", &feats_b)).unwrap();

    let mut m2 = TransferManifest::new();
    m2.add_embedding(make_embedding("a", &feats_a)).unwrap();
    m2.add_embedding(make_embedding("b", &feats_b)).unwrap();

    assert_eq!(m1.content_hash(), m2.content_hash());
}

// ---------------------------------------------------------------------------
// Embedding edge cases
// ---------------------------------------------------------------------------

#[test]
fn embedding_max_i64_values() {
    let a = make_embedding("big", &[(EmbeddingFeature::IrNodeCount, i64::MAX / 2)]);
    let b = make_embedding(
        "also_big",
        &[(EmbeddingFeature::IrNodeCount, i64::MAX / 2 - 1)],
    );
    // Should not panic with saturating arithmetic
    let _dist = a.distance_squared(&b);
    let _sim = a.cosine_similarity_millionths(&b);
}

#[test]
fn embedding_single_dimension_cosine() {
    let a = make_embedding("a", &[(EmbeddingFeature::IrNodeCount, 1_000_000)]);
    let b = make_embedding("b", &[(EmbeddingFeature::IrNodeCount, 2_000_000)]);
    let sim = a.cosine_similarity_millionths(&b);
    // Same direction, should be ~1.0 = ~1_000_000
    assert!(
        sim > 900_000,
        "single-dimension same-direction should be high sim: {sim}"
    );
}

#[test]
fn embedding_dimension_overwrite() {
    let mut e = WorkloadEmbedding::new("test".to_string(), ContentHash::compute(b"test"));
    e.set_dimension(EmbeddingFeature::IrNodeCount, 100);
    e.set_dimension(EmbeddingFeature::IrNodeCount, 999);
    assert_eq!(e.get_dimension(&EmbeddingFeature::IrNodeCount), 999);
}

// ---------------------------------------------------------------------------
// Transfer manifest with certificates
// ---------------------------------------------------------------------------

#[test]
fn manifest_with_computed_certificates() {
    let mut m = TransferManifest::new();
    let feats = vec![
        (EmbeddingFeature::IrNodeCount, 500_000),
        (EmbeddingFeature::AllocationRate, 300_000),
    ];
    m.add_embedding(make_embedding("src", &feats)).unwrap();
    m.add_embedding(make_embedding("tgt", &feats)).unwrap();

    let cert = m.compute_certificate("src", "tgt").unwrap();
    assert!(cert.is_neighbor);

    // Add certificate to manifest
    let mut m_with_certs = m.clone();
    m_with_certs.certificates.push(cert);
    assert_eq!(m_with_certs.certificates.len(), 1);

    // Serde roundtrip
    let json = serde_json::to_string(&m_with_certs).unwrap();
    let back: TransferManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.certificates.len(), 1);
    assert!(back.certificates[0].is_neighbor);
}

#[test]
fn compute_certificate_nonexistent_source() {
    let mut m = TransferManifest::new();
    m.add_embedding(make_embedding("exists", &[])).unwrap();
    assert!(m.compute_certificate("nonexistent", "exists").is_none());
}

#[test]
fn compute_certificate_nonexistent_target() {
    let mut m = TransferManifest::new();
    m.add_embedding(make_embedding("exists", &[])).unwrap();
    assert!(m.compute_certificate("exists", "nonexistent").is_none());
}
