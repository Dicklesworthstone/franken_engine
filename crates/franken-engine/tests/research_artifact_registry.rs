/*!
Integration tests for research artifact registry functionality.
*/

use frankenengine_engine::research_artifact_registry::{
    ArtifactMetadata, ResearchArtifactRegistry,
};

#[test]
fn test_research_artifact_registry_integration() {
    // Create registry with multiple artifacts
    let mut registry = ResearchArtifactRegistry::new();

    let artifact1 = ArtifactMetadata {
        artifact_id: "franken-performance-2026-001".to_string(),
        title: "FrankenEngine Performance Evaluation".to_string(),
        publication_date: "2026-04-20".to_string(),
        authors: vec!["Research Team".to_string()],
        abstract_text: "Performance evaluation of FrankenEngine runtime.".to_string(),
        bundle_path: "artifacts/performance-evaluation-001/".to_string(),
        artifact_type: "technical_report".to_string(),
    };

    let artifact2 = ArtifactMetadata {
        artifact_id: "franken-security-benchmark-001".to_string(),
        title: "Security Benchmark Suite".to_string(),
        publication_date: "2026-04-20".to_string(),
        authors: vec!["Security Team".to_string()],
        abstract_text: "Comprehensive security benchmark for runtime engines.".to_string(),
        bundle_path: "artifacts/security-benchmark-001/".to_string(),
        artifact_type: "benchmark".to_string(),
    };

    let artifact3 = ArtifactMetadata {
        artifact_id: "adversarial-dataset-001".to_string(),
        title: "Adversarial Campaign Dataset".to_string(),
        publication_date: "2026-04-20".to_string(),
        authors: vec!["Red Team".to_string()],
        abstract_text: "Dataset of adversarial campaigns for runtime evaluation.".to_string(),
        bundle_path: "artifacts/adversarial-dataset-001/".to_string(),
        artifact_type: "dataset".to_string(),
    };

    // Register artifacts
    registry.register_artifact(artifact1.clone());
    registry.register_artifact(artifact2.clone());
    registry.register_artifact(artifact3.clone());

    // Test listing all artifacts
    let all_artifacts = registry.list_artifacts();
    assert_eq!(all_artifacts.len(), 3);

    // Test filtering by type
    let reports = registry.get_artifacts_by_type("technical_report");
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].artifact_id, "franken-performance-2026-001");

    let benchmarks = registry.get_artifacts_by_type("benchmark");
    assert_eq!(benchmarks.len(), 1);
    assert_eq!(benchmarks[0].artifact_id, "franken-security-benchmark-001");

    let datasets = registry.get_artifacts_by_type("dataset");
    assert_eq!(datasets.len(), 1);
    assert_eq!(datasets[0].artifact_id, "adversarial-dataset-001");

    // Test retrieval by ID
    let retrieved = registry
        .get_artifact("franken-performance-2026-001")
        .unwrap();
    assert_eq!(retrieved.title, "FrankenEngine Performance Evaluation");
    assert_eq!(retrieved.authors, vec!["Research Team".to_string()]);

    // Test non-existent artifact
    assert!(registry.get_artifact("non-existent").is_none());

    // Test empty type filter
    let empty_filter = registry.get_artifacts_by_type("non-existent-type");
    assert_eq!(empty_filter.len(), 0);
}

#[test]
fn test_artifact_metadata_serialization() {
    let artifact = ArtifactMetadata {
        artifact_id: "test-serialization".to_string(),
        title: "Serialization Test".to_string(),
        publication_date: "2026-04-20".to_string(),
        authors: vec!["Test Author".to_string()],
        abstract_text: "Testing serialization and deserialization.".to_string(),
        bundle_path: "artifacts/test/".to_string(),
        artifact_type: "test".to_string(),
    };

    // Test JSON serialization/deserialization
    let json = serde_json::to_string(&artifact).expect("Failed to serialize to JSON");
    let deserialized: ArtifactMetadata =
        serde_json::from_str(&json).expect("Failed to deserialize from JSON");
    assert_eq!(artifact, deserialized);
}

#[test]
fn test_registry_serialization() {
    let mut registry = ResearchArtifactRegistry::new();

    let artifact = ArtifactMetadata {
        artifact_id: "test-registry-serialization".to_string(),
        title: "Registry Serialization Test".to_string(),
        publication_date: "2026-04-20".to_string(),
        authors: vec!["Test Author".to_string()],
        abstract_text: "Testing registry serialization.".to_string(),
        bundle_path: "artifacts/test-registry/".to_string(),
        artifact_type: "test".to_string(),
    };

    registry.register_artifact(artifact);

    // Test JSON serialization/deserialization
    let json = serde_json::to_string(&registry).expect("Failed to serialize registry to JSON");
    let deserialized: ResearchArtifactRegistry =
        serde_json::from_str(&json).expect("Failed to deserialize registry from JSON");
    assert_eq!(registry, deserialized);
}
