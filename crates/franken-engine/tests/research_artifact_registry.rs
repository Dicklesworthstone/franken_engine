/*!
Integration tests for research artifact registry functionality.
*/

use frankenengine_engine::research_artifact_registry::{
    ArtifactMetadata, ResearchArtifactRegistry,
};
use std::path::Path;

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
fn test_seeded_research_artifact_entries_have_coverage() {
    let seeded_entries: &[(&str, &str, &str, fn() -> ResearchArtifactRegistry)] = &[
        (
            "ext-eval-framework-0001",
            "evaluation_framework",
            "EXTERNAL_EVALUATION_FRAMEWORK.md",
            ResearchArtifactRegistry::with_external_evaluation_entry,
        ),
        (
            "reproducibility-scorecard-0001",
            "reproducibility_scorecard",
            "REPRODUCIBILITY_SCORECARD.md",
            ResearchArtifactRegistry::with_reproducibility_scorecard_entry,
        ),
        (
            "open-specs-publication-0001",
            "open_specification",
            "OPEN_SPECS_PUBLICATION.md",
            ResearchArtifactRegistry::with_open_specs_publication_entry,
        ),
        (
            "proof-sketch-template-0001",
            "proof_template",
            "PROOF_SKETCH_TEMPLATE.md",
            ResearchArtifactRegistry::with_proof_sketch_template_entry,
        ),
        (
            "vulnerability-disclosure-policy-0001",
            "security_policy",
            "VULNERABILITY_DISCLOSURE_POLICY.md",
            ResearchArtifactRegistry::with_vulnerability_disclosure_policy_entry,
        ),
        (
            "fuzzing-harness-manifest-0001",
            "testing_strategy",
            "FUZZING_HARNESS_MANIFEST.md",
            ResearchArtifactRegistry::with_fuzzing_harness_manifest_entry,
        ),
        (
            "benchmark-reproducibility-audit-0001",
            "benchmark_audit",
            "BENCHMARK_REPRODUCIBILITY_AUDIT.md",
            ResearchArtifactRegistry::with_benchmark_reproducibility_audit_entry,
        ),
        (
            "data-provenance-bundle-0001",
            "provenance_bundle",
            "DATA_PROVENANCE_BUNDLE.md",
            ResearchArtifactRegistry::with_data_provenance_bundle_entry,
        ),
        (
            "e2e-mock-free-test-manifest-0001",
            "e2e_testing_framework",
            "E2E_MOCK_FREE_TEST_MANIFEST.md",
            ResearchArtifactRegistry::with_e2e_mock_free_test_manifest_entry,
        ),
        (
            "audit-closure-matrix-0001",
            "audit_artifact",
            "AUDIT_CLOSURE_MATRIX.md",
            ResearchArtifactRegistry::with_audit_closure_matrix_entry,
        ),
        (
            "compatibility-advisory-report-0001",
            "compatibility_advisory",
            "COMPATIBILITY_ADVISORY_REPORT.md",
            ResearchArtifactRegistry::with_compatibility_advisory_report_entry,
        ),
        (
            "conformance-scorecard-bundle-0001",
            "conformance_scorecard",
            "CONFORMANCE_SCORECARD_BUNDLE.md",
            ResearchArtifactRegistry::with_conformance_scorecard_bundle_entry,
        ),
        (
            "containment-slo-verification-0001",
            "security_slo_verification",
            "CONTAINMENT_SLO_VERIFICATION.md",
            ResearchArtifactRegistry::with_containment_slo_verification_entry,
        ),
        (
            "differential-testing-manifest-0001",
            "differential_testing",
            "DIFFERENTIAL_TESTING_MANIFEST.md",
            ResearchArtifactRegistry::with_differential_testing_manifest_entry,
        ),
        (
            "property-based-testing-manifest-0001",
            "property_based_testing",
            "PROPERTY_BASED_TESTING_MANIFEST.md",
            ResearchArtifactRegistry::with_property_based_testing_manifest_entry,
        ),
        (
            "technical-report-template-0001",
            "report_template",
            "TECHNICAL_REPORT_TEMPLATE.md",
            ResearchArtifactRegistry::with_technical_report_template_entry,
        ),
        (
            "research-artifact-template-0001",
            "artifact_template",
            "RESEARCH_ARTIFACT_TEMPLATE.md",
            ResearchArtifactRegistry::with_research_artifact_template_entry,
        ),
        (
            "bd2501-audit-report-0001",
            "audit_report",
            "BD2501_AUDIT_REPORT.md",
            ResearchArtifactRegistry::with_bd2501_audit_report_entry,
        ),
        (
            "baseline-dedup-review-audit-0001",
            "review_audit",
            "BASELINE_DEDUP_REVIEW_AUDIT.md",
            ResearchArtifactRegistry::with_baseline_dedup_review_audit_entry,
        ),
        (
            "golden-artifact-test-bundle-0001",
            "testing_framework",
            "GOLDEN_ARTIFACT_TEST_BUNDLE.md",
            ResearchArtifactRegistry::with_golden_artifact_test_bundle_entry,
        ),
        (
            "conformance-harness-manifest-0001",
            "conformance_harness",
            "CONFORMANCE_HARNESS_MANIFEST.md",
            ResearchArtifactRegistry::with_conformance_harness_manifest_entry,
        ),
        (
            "mutation-testing-manifest-0001",
            "mutation_testing",
            "MUTATION_TESTING_MANIFEST.md",
            ResearchArtifactRegistry::with_mutation_testing_manifest_entry,
        ),
        (
            "lean-proof-feedback-0001",
            "verification_framework",
            "LEAN_PROOF_FEEDBACK_MANIFEST.md",
            ResearchArtifactRegistry::with_lean_proof_feedback_entry,
        ),
        (
            "stateful-fuzzing-manifest-0001",
            "stateful_fuzzing",
            "STATEFUL_FUZZING_MANIFEST.md",
            ResearchArtifactRegistry::with_stateful_fuzzing_manifest_entry,
        ),
        (
            "metamorphic-testing-manifest-0001",
            "metamorphic_testing",
            "METAMORPHIC_TESTING_MANIFEST.md",
            ResearchArtifactRegistry::with_metamorphic_testing_manifest_entry,
        ),
        (
            "chaos-engineering-manifest-0001",
            "chaos_engineering",
            "CHAOS_ENGINEERING_MANIFEST.md",
            ResearchArtifactRegistry::with_chaos_engineering_entry,
        ),
    ];

    assert_eq!(seeded_entries.len(), 26);

    for (artifact_id, artifact_type, bundle_suffix, build_registry) in seeded_entries {
        let registry = build_registry();
        let artifact = registry
            .get_artifact(artifact_id)
            .unwrap_or_else(|| panic!("missing seeded artifact {artifact_id}"));

        assert_eq!(&artifact.artifact_id, artifact_id);
        assert_eq!(&artifact.artifact_type, artifact_type);
        assert!(
            artifact.bundle_path.ends_with(bundle_suffix),
            "unexpected bundle path for {artifact_id}: {}",
            artifact.bundle_path
        );

        let bundle_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(&artifact.bundle_path);
        assert!(
            bundle_path.is_file(),
            "registered artifact bundle does not exist for {artifact_id}: {}",
            bundle_path.display()
        );

        let artifacts_by_type = registry.get_artifacts_by_type(artifact_type);
        assert_eq!(artifacts_by_type.len(), 1);
        assert_eq!(artifacts_by_type[0].artifact_id, *artifact_id);
        assert_eq!(registry.list_artifacts().len(), 1);
    }
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
