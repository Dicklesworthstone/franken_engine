//! Integration tests for the workload-manifold compression and cross-workload
//! transfer plane (RGC-612).

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::workload_manifold_transfer::{
    BEAD_ID, COMPONENT, EMBEDDING_DIMENSIONS, EmbeddingFeature, MAX_EMBEDDINGS, ManifoldError,
    NEIGHBORHOOD_THRESHOLD_MILLIONTHS, NeighborhoodCertificate, SCHEMA_VERSION, TransferKind,
    TransferManifest, TransferRecord, WorkloadEmbedding, build_seed_manifest,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_embedding(id: &str, features: &[(EmbeddingFeature, i64)]) -> WorkloadEmbedding {
    let mut e = WorkloadEmbedding::new(id.to_string(), ContentHash::compute(id.as_bytes()));
    for (f, v) in features {
        e.set_dimension(*f, *v);
    }
    e
}

fn test_transfer(id: &str, drift: bool, rollback: bool) -> TransferRecord {
    TransferRecord {
        id: id.to_string(),
        kind: TransferKind::RewriteRules,
        source_workload: "src".to_string(),
        target_workload: "tgt".to_string(),
        certificate_hash: ContentHash::compute(id.as_bytes()),
        items_transferred: 10,
        drift_detected: drift,
        rollback_triggered: rollback,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_have_expected_values() {
    assert_eq!(COMPONENT, "workload_manifold_transfer");
    assert_eq!(BEAD_ID, "bd-1lsy.7.12");
    assert!(SCHEMA_VERSION.contains("workload-manifold-transfer"));
    assert!(SCHEMA_VERSION.contains(".v1"));
    assert_eq!(EMBEDDING_DIMENSIONS, 32);
    assert_eq!(MAX_EMBEDDINGS, 10_000);
    assert_eq!(NEIGHBORHOOD_THRESHOLD_MILLIONTHS, 800_000);
}

// ---------------------------------------------------------------------------
// EmbeddingFeature
// ---------------------------------------------------------------------------

#[test]
fn embedding_feature_all_count() {
    assert_eq!(EmbeddingFeature::ALL.len(), 16);
}

#[test]
fn embedding_feature_as_str_all() {
    let strs: Vec<&str> = EmbeddingFeature::ALL.iter().map(|f| f.as_str()).collect();
    assert!(strs.contains(&"ir_node_count"));
    assert!(strs.contains(&"allocation_rate"));
    assert!(strs.contains(&"hostcall_frequency"));
    assert!(strs.contains(&"regex_complexity"));
}

#[test]
fn embedding_feature_display_matches_as_str() {
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
    }
}

#[test]
fn embedding_feature_ordering_deterministic() {
    let mut features: Vec<EmbeddingFeature> = EmbeddingFeature::ALL.to_vec();
    let mut features2 = features.clone();
    features.sort();
    features2.sort();
    assert_eq!(features, features2);
}

// ---------------------------------------------------------------------------
// WorkloadEmbedding
// ---------------------------------------------------------------------------

#[test]
fn embedding_new_has_empty_dimensions() {
    let e = WorkloadEmbedding::new("test".to_string(), ContentHash::compute(b"test"));
    assert!(e.dimensions.is_empty());
    assert_eq!(e.workload_id, "test");
}

#[test]
fn embedding_set_and_get_dimension() {
    let mut e = WorkloadEmbedding::new("test".to_string(), ContentHash::compute(b"test"));
    e.set_dimension(EmbeddingFeature::IrNodeCount, 42_000);
    assert_eq!(e.get_dimension(&EmbeddingFeature::IrNodeCount), 42_000);
}

#[test]
fn embedding_get_missing_dimension_returns_zero() {
    let e = WorkloadEmbedding::new("test".to_string(), ContentHash::compute(b"test"));
    assert_eq!(e.get_dimension(&EmbeddingFeature::AllocationRate), 0);
}

#[test]
fn embedding_overwrite_dimension() {
    let mut e = WorkloadEmbedding::new("test".to_string(), ContentHash::compute(b"test"));
    e.set_dimension(EmbeddingFeature::IrNodeCount, 100);
    e.set_dimension(EmbeddingFeature::IrNodeCount, 200);
    assert_eq!(e.get_dimension(&EmbeddingFeature::IrNodeCount), 200);
}

#[test]
fn embedding_serde_roundtrip() {
    let e = test_embedding(
        "serde_test",
        &[
            (EmbeddingFeature::IrNodeCount, 100_000),
            (EmbeddingFeature::AllocationRate, 200_000),
        ],
    );
    let json = serde_json::to_string(&e).unwrap();
    let back: WorkloadEmbedding = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// Distance and similarity
// ---------------------------------------------------------------------------

#[test]
fn distance_squared_to_self_is_zero() {
    let e = test_embedding("a", &[(EmbeddingFeature::IrNodeCount, 100_000)]);
    assert_eq!(e.distance_squared(&e), 0);
}

#[test]
fn distance_squared_is_positive_for_different() {
    let a = test_embedding("a", &[(EmbeddingFeature::IrNodeCount, 100)]);
    let b = test_embedding("b", &[(EmbeddingFeature::IrNodeCount, 200)]);
    assert!(a.distance_squared(&b) > 0);
}

#[test]
fn distance_squared_symmetric() {
    let a = test_embedding(
        "a",
        &[
            (EmbeddingFeature::IrNodeCount, 100),
            (EmbeddingFeature::AllocationRate, 200),
        ],
    );
    let b = test_embedding(
        "b",
        &[
            (EmbeddingFeature::IrNodeCount, 300),
            (EmbeddingFeature::AllocationRate, 400),
        ],
    );
    assert_eq!(a.distance_squared(&b), b.distance_squared(&a));
}

#[test]
fn cosine_similarity_identical_is_near_one() {
    let a = test_embedding(
        "a",
        &[
            (EmbeddingFeature::IrNodeCount, 100_000),
            (EmbeddingFeature::AllocationRate, 200_000),
        ],
    );
    let sim = a.cosine_similarity_millionths(&a);
    assert!(sim >= 990_000, "expected near 1.0, got {sim}");
}

#[test]
fn cosine_similarity_zero_vector_is_zero() {
    let a = test_embedding("a", &[]);
    let b = test_embedding("b", &[(EmbeddingFeature::IrNodeCount, 100_000)]);
    assert_eq!(a.cosine_similarity_millionths(&b), 0);
}

#[test]
fn cosine_similarity_both_zero_is_zero() {
    let a = test_embedding("a", &[]);
    let b = test_embedding("b", &[]);
    assert_eq!(a.cosine_similarity_millionths(&b), 0);
}

#[test]
fn cosine_similarity_parallel_vectors_high() {
    let a = test_embedding("a", &[(EmbeddingFeature::IrNodeCount, 100_000)]);
    let b = test_embedding("b", &[(EmbeddingFeature::IrNodeCount, 200_000)]);
    let sim = a.cosine_similarity_millionths(&b);
    assert!(
        sim >= 990_000,
        "parallel vectors should be similar, got {sim}"
    );
}

// ---------------------------------------------------------------------------
// TransferKind
// ---------------------------------------------------------------------------

#[test]
fn transfer_kind_as_str_all() {
    assert_eq!(TransferKind::RewriteRules.as_str(), "rewrite_rules");
    assert_eq!(TransferKind::TieringDecisions.as_str(), "tiering_decisions");
    assert_eq!(TransferKind::CachePriors.as_str(), "cache_priors");
    assert_eq!(TransferKind::InlineCandidates.as_str(), "inline_candidates");
    assert_eq!(TransferKind::AllocationHints.as_str(), "allocation_hints");
    assert_eq!(
        TransferKind::TypeProfileHints.as_str(),
        "type_profile_hints"
    );
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
fn transfer_kind_serde_roundtrip_all() {
    for kind in [
        TransferKind::RewriteRules,
        TransferKind::TieringDecisions,
        TransferKind::CachePriors,
        TransferKind::InlineCandidates,
        TransferKind::AllocationHints,
        TransferKind::TypeProfileHints,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: TransferKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// TransferRecord
// ---------------------------------------------------------------------------

#[test]
fn transfer_record_serde_roundtrip() {
    let record = TransferRecord {
        id: "t1".to_string(),
        kind: TransferKind::CachePriors,
        source_workload: "src".to_string(),
        target_workload: "tgt".to_string(),
        certificate_hash: ContentHash::compute(b"cert"),
        items_transferred: 42,
        drift_detected: false,
        rollback_triggered: false,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: TransferRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// ---------------------------------------------------------------------------
// NeighborhoodCertificate
// ---------------------------------------------------------------------------

#[test]
fn neighborhood_certificate_serde_roundtrip() {
    let cert = NeighborhoodCertificate {
        source_workload: "a".to_string(),
        target_workload: "b".to_string(),
        similarity_millionths: 900_000,
        distance_squared: 100,
        threshold_millionths: 800_000,
        is_neighbor: true,
        certificate_hash: ContentHash::compute(b"cert"),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let back: NeighborhoodCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// TransferManifest
// ---------------------------------------------------------------------------

#[test]
fn manifest_new_is_empty() {
    let m = TransferManifest::new();
    assert!(m.embeddings.is_empty());
    assert!(m.certificates.is_empty());
    assert!(m.transfers.is_empty());
    assert_eq!(m.version, SCHEMA_VERSION);
}

#[test]
fn manifest_default_equals_new() {
    let a = TransferManifest::new();
    let b = TransferManifest::default();
    assert_eq!(a.version, b.version);
    assert_eq!(a.embeddings.len(), b.embeddings.len());
}

#[test]
fn manifest_add_embedding() {
    let mut m = TransferManifest::new();
    m.add_embedding(test_embedding("a", &[])).unwrap();
    assert_eq!(m.embeddings.len(), 1);
}

#[test]
fn manifest_duplicate_embedding_rejected() {
    let mut m = TransferManifest::new();
    m.add_embedding(test_embedding("a", &[])).unwrap();
    let err = m.add_embedding(test_embedding("a", &[])).unwrap_err();
    assert!(matches!(err, ManifoldError::DuplicateEmbedding { id } if id == "a"));
}

#[test]
fn manifest_add_multiple_embeddings() {
    let mut m = TransferManifest::new();
    m.add_embedding(test_embedding("a", &[])).unwrap();
    m.add_embedding(test_embedding("b", &[])).unwrap();
    m.add_embedding(test_embedding("c", &[])).unwrap();
    assert_eq!(m.embeddings.len(), 3);
}

// ---------------------------------------------------------------------------
// Certificate computation
// ---------------------------------------------------------------------------

#[test]
fn compute_certificate_same_workload() {
    let mut m = TransferManifest::new();
    m.add_embedding(test_embedding(
        "a",
        &[(EmbeddingFeature::IrNodeCount, 100_000)],
    ))
    .unwrap();
    let cert = m.compute_certificate("a", "a").unwrap();
    assert!(cert.is_neighbor);
    assert!(cert.similarity_millionths >= NEIGHBORHOOD_THRESHOLD_MILLIONTHS);
}

#[test]
fn compute_certificate_identical_embeddings() {
    let mut m = TransferManifest::new();
    m.add_embedding(test_embedding(
        "a",
        &[(EmbeddingFeature::IrNodeCount, 100_000)],
    ))
    .unwrap();
    m.add_embedding(test_embedding(
        "b",
        &[(EmbeddingFeature::IrNodeCount, 100_000)],
    ))
    .unwrap();
    let cert = m.compute_certificate("a", "b").unwrap();
    assert!(cert.is_neighbor);
}

#[test]
fn compute_certificate_missing_source() {
    let m = TransferManifest::new();
    assert!(m.compute_certificate("missing", "also_missing").is_none());
}

#[test]
fn compute_certificate_missing_target() {
    let mut m = TransferManifest::new();
    m.add_embedding(test_embedding("a", &[])).unwrap();
    assert!(m.compute_certificate("a", "missing").is_none());
}

#[test]
fn compute_certificate_hash_deterministic() {
    let mut m = TransferManifest::new();
    m.add_embedding(test_embedding(
        "a",
        &[(EmbeddingFeature::IrNodeCount, 100_000)],
    ))
    .unwrap();
    let cert1 = m.compute_certificate("a", "a").unwrap();
    let cert2 = m.compute_certificate("a", "a").unwrap();
    assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
}

// ---------------------------------------------------------------------------
// Content hash
// ---------------------------------------------------------------------------

#[test]
fn content_hash_deterministic() {
    let m1 = build_seed_manifest();
    let m2 = build_seed_manifest();
    assert_eq!(m1.content_hash(), m2.content_hash());
}

#[test]
fn content_hash_changes_with_extra_embedding() {
    let m1 = build_seed_manifest();
    let mut m2 = build_seed_manifest();
    m2.add_embedding(test_embedding("extra", &[])).unwrap();
    assert_ne!(m1.content_hash(), m2.content_hash());
}

// ---------------------------------------------------------------------------
// Drift / rollback counts
// ---------------------------------------------------------------------------

#[test]
fn drift_count_zero_with_no_transfers() {
    let m = TransferManifest::new();
    assert_eq!(m.drift_count(), 0);
}

#[test]
fn drift_count_tracks_drift() {
    let mut m = TransferManifest::new();
    m.transfers.push(test_transfer("t1", true, false));
    m.transfers.push(test_transfer("t2", false, false));
    m.transfers.push(test_transfer("t3", true, true));
    assert_eq!(m.drift_count(), 2);
}

#[test]
fn rollback_count_zero_with_no_transfers() {
    let m = TransferManifest::new();
    assert_eq!(m.rollback_count(), 0);
}

#[test]
fn rollback_count_tracks_rollbacks() {
    let mut m = TransferManifest::new();
    m.transfers.push(test_transfer("t1", true, true));
    m.transfers.push(test_transfer("t2", false, false));
    m.transfers.push(test_transfer("t3", true, true));
    assert_eq!(m.rollback_count(), 2);
}

// ---------------------------------------------------------------------------
// Seed manifest
// ---------------------------------------------------------------------------

#[test]
fn seed_manifest_has_embeddings() {
    let m = build_seed_manifest();
    assert_eq!(m.embeddings.len(), 3);
}

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
fn seed_manifest_embeddings_have_dimensions() {
    let m = build_seed_manifest();
    for e in &m.embeddings {
        assert!(!e.dimensions.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn manifest_serde_roundtrip() {
    let m = build_seed_manifest();
    let json = serde_json::to_string(&m).unwrap();
    let back: TransferManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m.embeddings.len(), back.embeddings.len());
    assert_eq!(m.content_hash(), back.content_hash());
}

#[test]
fn empty_manifest_serde_roundtrip() {
    let m = TransferManifest::new();
    let json = serde_json::to_string(&m).unwrap();
    let back: TransferManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m.version, back.version);
    assert!(back.embeddings.is_empty());
}

// ---------------------------------------------------------------------------
// ManifoldError
// ---------------------------------------------------------------------------

#[test]
fn error_display_duplicate_embedding() {
    let e = ManifoldError::DuplicateEmbedding {
        id: "test_id".to_string(),
    };
    let msg = format!("{e}");
    assert!(msg.contains("test_id"));
    assert!(msg.contains("duplicate"));
}

#[test]
fn error_display_overflow() {
    let e = ManifoldError::EmbeddingOverflow { max: 10_000 };
    let msg = format!("{e}");
    assert!(msg.contains("10000"));
    assert!(msg.contains("overflow"));
}

#[test]
fn error_serde_roundtrip() {
    let e = ManifoldError::DuplicateEmbedding {
        id: "test".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ManifoldError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// BTreeMap dimension determinism
// ---------------------------------------------------------------------------

#[test]
fn embedding_dimensions_deterministic_ordering() {
    let mut e1 = WorkloadEmbedding::new("test".to_string(), ContentHash::compute(b"test"));
    e1.set_dimension(EmbeddingFeature::HostcallFrequency, 100);
    e1.set_dimension(EmbeddingFeature::IrNodeCount, 200);
    e1.set_dimension(EmbeddingFeature::AllocationRate, 300);

    let mut e2 = WorkloadEmbedding::new("test".to_string(), ContentHash::compute(b"test"));
    e2.set_dimension(EmbeddingFeature::AllocationRate, 300);
    e2.set_dimension(EmbeddingFeature::IrNodeCount, 200);
    e2.set_dimension(EmbeddingFeature::HostcallFrequency, 100);

    // BTreeMap ordering is deterministic regardless of insertion order
    assert_eq!(e1, e2);
}
