/*!
Research Artifact Registry

Manages metadata and tracking for FrankenEngine research artifacts and technical reports.
*/

use std::collections::BTreeMap;

/// Registry for research artifacts and technical reports
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ResearchArtifactRegistry {
    /// Mapping from artifact ID to metadata
    artifacts: BTreeMap<String, ArtifactMetadata>,
}

/// Metadata for a research artifact
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactMetadata {
    /// Unique identifier for the artifact
    pub artifact_id: String,
    /// Human-readable title
    pub title: String,
    /// Publication date (ISO 8601 format)
    pub publication_date: String,
    /// List of authors
    pub authors: Vec<String>,
    /// Abstract or summary
    pub abstract_text: String,
    /// Path to artifact bundle
    pub bundle_path: String,
    /// Artifact type (e.g., "technical_report", "benchmark", "dataset")
    pub artifact_type: String,
}

impl ResearchArtifactRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            artifacts: BTreeMap::new(),
        }
    }

    /// Construct a registry containing the first external evaluation framework entry.
    pub fn with_external_evaluation_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "ext-eval-framework-0001".to_string(),
            title: "FrankenEngine External Evaluation Framework".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Core Team".to_string()],
            abstract_text: "External evaluation framework for adversarial testing, reproducibility, and red-team reporting."
                .to_string(),
            bundle_path: "docs/EXTERNAL_EVALUATION_FRAMEWORK.md".to_string(),
            artifact_type: "evaluation_framework".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the first reproducibility scorecard entry.
    pub fn with_reproducibility_scorecard_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "reproducibility-scorecard-0001".to_string(),
            title: "Reproducibility Scorecard".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Research Team".to_string()],
            abstract_text:
                "Reproducibility scorecard documenting deterministic replay and verification thresholds."
                    .to_string(),
            bundle_path: "docs/REPRODUCIBILITY_SCORECARD.md".to_string(),
            artifact_type: "reproducibility_scorecard".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the open specifications publication entry.
    pub fn with_open_specs_publication_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "open-specs-publication-0001".to_string(),
            title: "Open Specifications Publication".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Core Team".to_string()],
            abstract_text:
                "Public protocol specification outline for trust, replay, and policy primitives."
                    .to_string(),
            bundle_path: "docs/OPEN_SPECS_PUBLICATION.md".to_string(),
            artifact_type: "open_specification".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the proof sketch template entry.
    pub fn with_proof_sketch_template_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "proof-sketch-template-0001".to_string(),
            title: "Proof Sketch Template".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Core Team".to_string()],
            abstract_text: "Template and checklist for documenting protocol claims and mechanized proof artifacts."
                .to_string(),
            bundle_path: "docs/PROOF_SKETCH_TEMPLATE.md".to_string(),
            artifact_type: "proof_template".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the vulnerability disclosure policy entry.
    pub fn with_vulnerability_disclosure_policy_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "vulnerability-disclosure-policy-0001".to_string(),
            title: "Vulnerability Disclosure Policy".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Security Team".to_string()],
            abstract_text: "Policy template for intake, severity triage, coordinated disclosure, credit, and licensing."
                .to_string(),
            bundle_path: "docs/VULNERABILITY_DISCLOSURE_POLICY.md".to_string(),
            artifact_type: "security_policy".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the fuzzing harness manifest entry.
    pub fn with_fuzzing_harness_manifest_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "fuzzing-harness-manifest-0001".to_string(),
            title: "Fuzzing Harness Manifest".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Testing Team".to_string()],
            abstract_text: "Comprehensive fuzzing strategy manifest defining target priorities, coverage instrumentation, corpus sources, crash triage workflow, and MTBC baselines for security testing."
                .to_string(),
            bundle_path: "docs/FUZZING_HARNESS_MANIFEST.md".to_string(),
            artifact_type: "testing_strategy".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the benchmark reproducibility audit entry.
    pub fn with_benchmark_reproducibility_audit_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "benchmark-reproducibility-audit-0001".to_string(),
            title: "Benchmark Reproducibility Audit".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Performance Team".to_string()],
            abstract_text:
                "Audit framework for benchmark environment pinning, workload manifests, budgets, and peer replication logs."
                    .to_string(),
            bundle_path: "docs/BENCHMARK_REPRODUCIBILITY_AUDIT.md".to_string(),
            artifact_type: "benchmark_audit".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the data provenance bundle entry.
    pub fn with_data_provenance_bundle_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "data-provenance-bundle-0001".to_string(),
            title: "Data Provenance Bundle".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Research Team".to_string()],
            abstract_text: "Provenance skeleton for source attribution, hash chains, temporal bounds, signatures, and replay rights."
                .to_string(),
            bundle_path: "docs/DATA_PROVENANCE_BUNDLE.md".to_string(),
            artifact_type: "provenance_bundle".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the e2e mock-free test manifest entry.
    pub fn with_e2e_mock_free_test_manifest_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "e2e-mock-free-test-manifest-0001".to_string(),
            title: "E2E Mock-Free Test Manifest".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Quality Team".to_string()],
            abstract_text: "Mock-free integration test manifest covering transactional isolation, service-level fixtures, rollback guarantees, structured logging, and observability-driven assertions."
                .to_string(),
            bundle_path: "docs/E2E_MOCK_FREE_TEST_MANIFEST.md".to_string(),
            artifact_type: "e2e_testing_framework".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the audit closure matrix entry.
    pub fn with_audit_closure_matrix_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "audit-closure-matrix-0001".to_string(),
            title: "Audit Closure Matrix".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Research Team".to_string()],
            abstract_text:
                "Checklist artifact for closure checks, evidence completeness, and missing-item triage."
                    .to_string(),
            bundle_path: "docs/AUDIT_CLOSURE_MATRIX.md".to_string(),
            artifact_type: "audit_artifact".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the compatibility advisory report entry.
    pub fn with_compatibility_advisory_report_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "compatibility-advisory-report-0001".to_string(),
            title: "Compatibility Advisory Report".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Reliability Team".to_string()],
            abstract_text:
                "Compatibility advisory summary covering impacted components, risks, and remediation windows."
                    .to_string(),
            bundle_path: "docs/COMPATIBILITY_ADVISORY_REPORT.md".to_string(),
            artifact_type: "compatibility_advisory".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the conformance scorecard bundle entry.
    pub fn with_conformance_scorecard_bundle_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "conformance-scorecard-bundle-0001".to_string(),
            title: "Conformance Scorecard Bundle".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Quality Team".to_string()],
            abstract_text:
                "Bundle summarizing conformance coverage, pass rates, and residual compatibility gaps."
                    .to_string(),
            bundle_path: "docs/CONFORMANCE_SCORECARD_BUNDLE.md".to_string(),
            artifact_type: "conformance_scorecard".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the containment SLO verification entry.
    pub fn with_containment_slo_verification_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "containment-slo-verification-0001".to_string(),
            title: "Containment SLO Verification".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Security Team".to_string()],
            abstract_text:
                "Operational guide and evidence bundle for containment safety SLO verification."
                    .to_string(),
            bundle_path: "docs/CONTAINMENT_SLO_VERIFICATION.md".to_string(),
            artifact_type: "security_slo_verification".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the differential testing manifest entry.
    pub fn with_differential_testing_manifest_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "differential-testing-manifest-0001".to_string(),
            title: "Differential Testing Manifest".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Quality Team".to_string()],
            abstract_text:
                "Manifest for differential test governance, discrepancy handling, and replayability criteria."
                    .to_string(),
            bundle_path: "docs/DIFFERENTIAL_TESTING_MANIFEST.md".to_string(),
            artifact_type: "differential_testing".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the property-based testing manifest entry.
    pub fn with_property_based_testing_manifest_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "property-based-testing-manifest-0001".to_string(),
            title: "Property-Based Testing Manifest".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Testing Team".to_string()],
            abstract_text:
                "Manifest defining property catalogs, seed governance, counterexample workflows, and replay logs."
                    .to_string(),
            bundle_path: "docs/PROPERTY_BASED_TESTING_MANIFEST.md".to_string(),
            artifact_type: "property_based_testing".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the technical report template entry.
    pub fn with_technical_report_template_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "technical-report-template-0001".to_string(),
            title: "Technical Report Template".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Research Team".to_string()],
            abstract_text:
                "Template guiding claim articulation, reproducibility notes, and artifact reproducibility requirements."
                    .to_string(),
            bundle_path: "docs/TECHNICAL_REPORT_TEMPLATE.md".to_string(),
            artifact_type: "report_template".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the research artifact template entry.
    pub fn with_research_artifact_template_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "research-artifact-template-0001".to_string(),
            title: "Research Artifact Template".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Research Team".to_string()],
            abstract_text:
                "Template for reusable research artifact metadata, bundle layout, and replication notes."
                    .to_string(),
            bundle_path: "docs/RESEARCH_ARTIFACT_TEMPLATE.md".to_string(),
            artifact_type: "artifact_template".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the bd-2501 audit report entry.
    pub fn with_bd2501_audit_report_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "bd2501-audit-report-0001".to_string(),
            title: "BD-2501 Audit Report".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Research Team".to_string()],
            abstract_text:
                "Audit report reconciling Section 16 research artifact coverage and registry completeness."
                    .to_string(),
            bundle_path: "docs/BD2501_AUDIT_REPORT.md".to_string(),
            artifact_type: "audit_report".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Register a new artifact
    pub fn register_artifact(&mut self, metadata: ArtifactMetadata) {
        self.artifacts
            .insert(metadata.artifact_id.clone(), metadata);
    }

    /// Get artifact metadata by ID
    pub fn get_artifact(&self, artifact_id: &str) -> Option<&ArtifactMetadata> {
        self.artifacts.get(artifact_id)
    }

    /// List all registered artifacts
    pub fn list_artifacts(&self) -> Vec<&ArtifactMetadata> {
        let mut artifacts: Vec<&ArtifactMetadata> = self.artifacts.values().collect();
        artifacts.sort_by_key(|artifact| artifact.artifact_id.as_str());
        artifacts
    }

    /// Get artifacts by type
    pub fn get_artifacts_by_type(&self, artifact_type: &str) -> Vec<&ArtifactMetadata> {
        self.artifacts
            .values()
            .filter(|artifact| artifact.artifact_type == artifact_type)
            .collect()
    }
    /// Construct a registry containing the golden artifact test bundle entry.
    pub fn with_golden_artifact_test_bundle_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "golden-artifact-test-bundle-0001".to_string(),
            title: "Golden Artifact Test Bundle".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Quality Team".to_string()],
            abstract_text: "Comprehensive golden artifact testing strategy defining golden format standards, scrubbing rules, approval workflows, regression cadence, and cross-platform stability requirements."
                .to_string(),
            bundle_path: "docs/GOLDEN_ARTIFACT_TEST_BUNDLE.md".to_string(),
            artifact_type: "testing_framework".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the conformance harness manifest entry.
    pub fn with_conformance_harness_manifest_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "conformance-harness-manifest-0001".to_string(),
            title: "Conformance Harness Manifest".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Quality Team".to_string()],
            abstract_text: "Conformance harness manifest defining target specs, cross-implementation matrices, golden input sets, diff modes, and compliance scorecards."
                .to_string(),
            bundle_path: "docs/CONFORMANCE_HARNESS_MANIFEST.md".to_string(),
            artifact_type: "conformance_harness".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the mutation testing manifest entry.
    pub fn with_mutation_testing_manifest_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "mutation-testing-manifest-0001".to_string(),
            title: "Mutation Testing Manifest".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Quality Team".to_string()],
            abstract_text: "Mutation testing manifest defining operator catalogs, survivor analysis, equivalent-mutant filtering, score baselines, and CI gate thresholds."
                .to_string(),
            bundle_path: "docs/MUTATION_TESTING_MANIFEST.md".to_string(),
            artifact_type: "mutation_testing".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the lean proof feedback manifest entry.
    pub fn with_lean_proof_feedback_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "lean-proof-feedback-0001".to_string(),
            title: "Lean Proof Feedback Manifest".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Verification Team".to_string()],
            abstract_text: "Formal verification strategy manifest integrating Lean theorem prover with Rust runtime validators, featuring proof obligations catalog, counterexample harvesting, and CI integration."
                .to_string(),
            bundle_path: "docs/LEAN_PROOF_FEEDBACK_MANIFEST.md".to_string(),
            artifact_type: "verification_framework".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the stateful fuzzing manifest entry.
    pub fn with_stateful_fuzzing_manifest_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "stateful-fuzzing-manifest-0001".to_string(),
            title: "Stateful Fuzzing Manifest".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Testing Team".to_string()],
            abstract_text: "Stateful fuzzing manifest defining transition models, transition coverage obligations, invariant monitors, crash taxonomy, and replay bundle contents."
                .to_string(),
            bundle_path: "docs/STATEFUL_FUZZING_MANIFEST.md".to_string(),
            artifact_type: "stateful_fuzzing".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the metamorphic testing manifest entry.
    pub fn with_metamorphic_testing_manifest_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "metamorphic-testing-manifest-0001".to_string(),
            title: "Metamorphic Testing Manifest".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Testing Team".to_string()],
            abstract_text: "Oracle-free metamorphic testing manifest covering relation catalogs, deterministic input transformations, output invariants, seed schedules, and property coverage."
                .to_string(),
            bundle_path: "docs/METAMORPHIC_TESTING_MANIFEST.md".to_string(),
            artifact_type: "metamorphic_testing".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }

    /// Construct a registry containing the chaos engineering manifest entry.
    pub fn with_chaos_engineering_entry() -> Self {
        let mut registry = Self::new();

        let artifact = ArtifactMetadata {
            artifact_id: "chaos-engineering-manifest-0001".to_string(),
            title: "Chaos Engineering Manifest".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Resilience Team".to_string()],
            abstract_text: "Systematic fault injection and resilience coverage manifest defining fault modes catalog, injection points, steady-state metrics, blast radius analysis, and automated rollback procedures."
                .to_string(),
            bundle_path: "docs/CHAOS_ENGINEERING_MANIFEST.md".to_string(),
            artifact_type: "chaos_engineering".to_string(),
        };

        registry.register_artifact(artifact);

        registry
    }
}

impl Default for ResearchArtifactRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_basic_operations() {
        let mut registry = ResearchArtifactRegistry::new();

        let artifact = ArtifactMetadata {
            artifact_id: "test-artifact-001".to_string(),
            title: "Test Research Artifact".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["Test Author".to_string()],
            abstract_text: "A test research artifact for validation.".to_string(),
            bundle_path: "artifacts/test-artifact-001/".to_string(),
            artifact_type: "technical_report".to_string(),
        };

        // Register artifact
        registry.register_artifact(artifact.clone());

        // Retrieve by ID
        let retrieved = registry.get_artifact("test-artifact-001").unwrap();
        assert_eq!(retrieved, &artifact);

        // List all artifacts
        let all_artifacts = registry.list_artifacts();
        assert_eq!(all_artifacts.len(), 1);
        assert_eq!(all_artifacts[0], &artifact);

        // Get by type
        let reports = registry.get_artifacts_by_type("technical_report");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0], &artifact);

        // Non-existent type
        let datasets = registry.get_artifacts_by_type("dataset");
        assert_eq!(datasets.len(), 0);
    }

    #[test]
    fn test_external_evaluation_entry() {
        let registry = ResearchArtifactRegistry::with_external_evaluation_entry();

        let artifact = registry
            .get_artifact("ext-eval-framework-0001")
            .expect("expected seeded external evaluation entry");
        assert_eq!(artifact.artifact_type, "evaluation_framework");
        assert_eq!(
            artifact.title,
            "FrankenEngine External Evaluation Framework"
        );
        assert!(
            artifact
                .bundle_path
                .ends_with("EXTERNAL_EVALUATION_FRAMEWORK.md")
        );

        let evaluations = registry.get_artifacts_by_type("evaluation_framework");
        assert_eq!(evaluations.len(), 1);
    }

    #[test]
    fn test_reproducibility_scorecard_entry() {
        let registry = ResearchArtifactRegistry::with_reproducibility_scorecard_entry();

        let artifact = registry
            .get_artifact("reproducibility-scorecard-0001")
            .expect("expected seeded reproducibility scorecard artifact");
        assert_eq!(artifact.artifact_type, "reproducibility_scorecard");
        assert_eq!(artifact.title, "Reproducibility Scorecard");
        assert!(
            artifact
                .bundle_path
                .ends_with("REPRODUCIBILITY_SCORECARD.md")
        );
    }

    #[test]
    fn test_open_specs_publication_entry() {
        let registry = ResearchArtifactRegistry::with_open_specs_publication_entry();

        let artifact = registry
            .get_artifact("open-specs-publication-0001")
            .expect("expected open specifications publication artifact");
        assert_eq!(artifact.artifact_type, "open_specification");
        assert_eq!(artifact.title, "Open Specifications Publication");
        assert!(artifact.bundle_path.ends_with("OPEN_SPECS_PUBLICATION.md"));

        let open_specs = registry.get_artifacts_by_type("open_specification");
        assert_eq!(open_specs.len(), 1);
    }

    #[test]
    fn test_proof_sketch_template_entry() {
        let registry = ResearchArtifactRegistry::with_proof_sketch_template_entry();

        let artifact = registry
            .get_artifact("proof-sketch-template-0001")
            .expect("expected proof sketch template artifact");
        assert_eq!(artifact.artifact_type, "proof_template");
        assert_eq!(artifact.title, "Proof Sketch Template");
        assert!(artifact.bundle_path.ends_with("PROOF_SKETCH_TEMPLATE.md"));
    }

    #[test]
    fn test_vulnerability_disclosure_policy_entry() {
        let registry = ResearchArtifactRegistry::with_vulnerability_disclosure_policy_entry();

        let artifact = registry
            .get_artifact("vulnerability-disclosure-policy-0001")
            .expect("expected vulnerability disclosure policy artifact");
        assert_eq!(artifact.artifact_type, "security_policy");
        assert_eq!(artifact.title, "Vulnerability Disclosure Policy");
        assert!(
            artifact
                .bundle_path
                .ends_with("VULNERABILITY_DISCLOSURE_POLICY.md")
        );
    }

    #[test]
    fn test_benchmark_reproducibility_audit_entry() {
        let registry = ResearchArtifactRegistry::with_benchmark_reproducibility_audit_entry();

        let artifact = registry
            .get_artifact("benchmark-reproducibility-audit-0001")
            .expect("expected benchmark reproducibility audit artifact");
        assert_eq!(artifact.artifact_type, "benchmark_audit");
        assert_eq!(artifact.title, "Benchmark Reproducibility Audit");
        assert!(
            artifact
                .bundle_path
                .ends_with("BENCHMARK_REPRODUCIBILITY_AUDIT.md")
        );
    }

    #[test]
    fn test_stateful_fuzzing_manifest_entry() {
        let registry = ResearchArtifactRegistry::with_stateful_fuzzing_manifest_entry();

        let artifact = registry
            .get_artifact("stateful-fuzzing-manifest-0001")
            .expect("expected stateful fuzzing manifest artifact");
        assert_eq!(artifact.artifact_type, "stateful_fuzzing");
        assert_eq!(artifact.title, "Stateful Fuzzing Manifest");
        assert!(
            artifact
                .bundle_path
                .ends_with("STATEFUL_FUZZING_MANIFEST.md")
        );
        assert_eq!(registry.get_artifacts_by_type("stateful_fuzzing").len(), 1);
    }

    #[test]
    fn test_data_provenance_bundle_entry() {
        let registry = ResearchArtifactRegistry::with_data_provenance_bundle_entry();

        let artifact = registry
            .get_artifact("data-provenance-bundle-0001")
            .expect("expected data provenance bundle artifact");
        assert_eq!(artifact.artifact_type, "provenance_bundle");
        assert_eq!(artifact.title, "Data Provenance Bundle");
        assert!(artifact.bundle_path.ends_with("DATA_PROVENANCE_BUNDLE.md"));
    }

    #[test]
    fn test_audit_closure_matrix_entry() {
        let registry = ResearchArtifactRegistry::with_audit_closure_matrix_entry();

        let artifact = registry
            .get_artifact("audit-closure-matrix-0001")
            .expect("expected audit closure matrix artifact");
        assert_eq!(artifact.artifact_type, "audit_artifact");
        assert_eq!(artifact.title, "Audit Closure Matrix");
        assert!(artifact.bundle_path.ends_with("AUDIT_CLOSURE_MATRIX.md"));
    }

    #[test]
    fn test_compatibility_advisory_report_entry() {
        let registry = ResearchArtifactRegistry::with_compatibility_advisory_report_entry();

        let artifact = registry
            .get_artifact("compatibility-advisory-report-0001")
            .expect("expected compatibility advisory report artifact");
        assert_eq!(artifact.artifact_type, "compatibility_advisory");
        assert_eq!(artifact.title, "Compatibility Advisory Report");
        assert!(
            artifact
                .bundle_path
                .ends_with("COMPATIBILITY_ADVISORY_REPORT.md")
        );
    }

    #[test]
    fn test_conformance_scorecard_bundle_entry() {
        let registry = ResearchArtifactRegistry::with_conformance_scorecard_bundle_entry();

        let artifact = registry
            .get_artifact("conformance-scorecard-bundle-0001")
            .expect("expected conformance scorecard bundle artifact");
        assert_eq!(artifact.artifact_type, "conformance_scorecard");
        assert_eq!(artifact.title, "Conformance Scorecard Bundle");
        assert!(
            artifact
                .bundle_path
                .ends_with("CONFORMANCE_SCORECARD_BUNDLE.md")
        );
    }

    #[test]
    fn test_containment_slo_verification_entry() {
        let registry = ResearchArtifactRegistry::with_containment_slo_verification_entry();

        let artifact = registry
            .get_artifact("containment-slo-verification-0001")
            .expect("expected containment SLO verification artifact");
        assert_eq!(artifact.artifact_type, "security_slo_verification");
        assert_eq!(artifact.title, "Containment SLO Verification");
        assert!(
            artifact
                .bundle_path
                .ends_with("CONTAINMENT_SLO_VERIFICATION.md")
        );
    }

    #[test]
    fn test_differential_testing_manifest_entry() {
        let registry = ResearchArtifactRegistry::with_differential_testing_manifest_entry();

        let artifact = registry
            .get_artifact("differential-testing-manifest-0001")
            .expect("expected differential testing manifest artifact");
        assert_eq!(artifact.artifact_type, "differential_testing");
        assert_eq!(artifact.title, "Differential Testing Manifest");
        assert!(
            artifact
                .bundle_path
                .ends_with("DIFFERENTIAL_TESTING_MANIFEST.md")
        );
    }

    #[test]
    fn test_e2e_mock_free_test_manifest_entry() {
        let registry = ResearchArtifactRegistry::with_e2e_mock_free_test_manifest_entry();

        let artifact = registry
            .get_artifact("e2e-mock-free-test-manifest-0001")
            .expect("expected e2e mock-free test manifest artifact");
        assert_eq!(artifact.artifact_type, "e2e_testing_framework");
        assert_eq!(artifact.title, "E2E Mock-Free Test Manifest");
        assert!(
            artifact
                .bundle_path
                .ends_with("E2E_MOCK_FREE_TEST_MANIFEST.md")
        );
    }

    #[test]
    fn test_property_based_testing_manifest_entry() {
        let registry = ResearchArtifactRegistry::with_property_based_testing_manifest_entry();

        let artifact = registry
            .get_artifact("property-based-testing-manifest-0001")
            .expect("expected property-based testing manifest artifact");
        assert_eq!(artifact.artifact_type, "property_based_testing");
        assert_eq!(artifact.title, "Property-Based Testing Manifest");
        assert!(
            artifact
                .bundle_path
                .ends_with("PROPERTY_BASED_TESTING_MANIFEST.md")
        );
    }

    #[test]
    fn test_golden_artifact_test_bundle_entry() {
        let registry = ResearchArtifactRegistry::with_golden_artifact_test_bundle_entry();

        let artifact = registry
            .get_artifact("golden-artifact-test-bundle-0001")
            .expect("expected golden artifact test bundle");
        assert_eq!(artifact.artifact_type, "testing_framework");
        assert_eq!(artifact.title, "Golden Artifact Test Bundle");
        assert!(
            artifact
                .bundle_path
                .ends_with("GOLDEN_ARTIFACT_TEST_BUNDLE.md")
        );
    }

    #[test]
    fn test_conformance_harness_manifest_entry() {
        let registry = ResearchArtifactRegistry::with_conformance_harness_manifest_entry();

        let artifact = registry
            .get_artifact("conformance-harness-manifest-0001")
            .expect("expected conformance harness manifest artifact");
        assert_eq!(artifact.artifact_type, "conformance_harness");
        assert_eq!(artifact.title, "Conformance Harness Manifest");
        assert!(
            artifact
                .bundle_path
                .ends_with("CONFORMANCE_HARNESS_MANIFEST.md")
        );
    }

    #[test]
    fn test_mutation_testing_manifest_entry() {
        let registry = ResearchArtifactRegistry::with_mutation_testing_manifest_entry();

        let artifact = registry
            .get_artifact("mutation-testing-manifest-0001")
            .expect("expected mutation testing manifest artifact");
        assert_eq!(artifact.artifact_type, "mutation_testing");
        assert_eq!(artifact.title, "Mutation Testing Manifest");
        assert!(
            artifact
                .bundle_path
                .ends_with("MUTATION_TESTING_MANIFEST.md")
        );
    }

    #[test]
    fn test_lean_proof_feedback_entry() {
        let registry = ResearchArtifactRegistry::with_lean_proof_feedback_entry();

        let artifact = registry
            .get_artifact("lean-proof-feedback-0001")
            .expect("expected lean proof feedback manifest");
        assert_eq!(artifact.artifact_type, "verification_framework");
        assert_eq!(artifact.title, "Lean Proof Feedback Manifest");
        assert!(
            artifact
                .bundle_path
                .ends_with("LEAN_PROOF_FEEDBACK_MANIFEST.md")
        );
    }

    #[test]
    fn test_metamorphic_testing_manifest_entry() {
        let registry = ResearchArtifactRegistry::with_metamorphic_testing_manifest_entry();

        let artifact = registry
            .get_artifact("metamorphic-testing-manifest-0001")
            .expect("expected metamorphic testing manifest artifact");
        assert_eq!(artifact.artifact_type, "metamorphic_testing");
        assert_eq!(artifact.title, "Metamorphic Testing Manifest");
        assert!(
            artifact
                .bundle_path
                .ends_with("METAMORPHIC_TESTING_MANIFEST.md")
        );

        let manifests = registry.get_artifacts_by_type("metamorphic_testing");
        assert_eq!(manifests.len(), 1);
    }

    #[test]
    fn test_technical_report_template_entry() {
        let registry = ResearchArtifactRegistry::with_technical_report_template_entry();

        let artifact = registry
            .get_artifact("technical-report-template-0001")
            .expect("expected technical report template artifact");
        assert_eq!(artifact.artifact_type, "report_template");
        assert_eq!(artifact.title, "Technical Report Template");
        assert!(
            artifact
                .bundle_path
                .ends_with("TECHNICAL_REPORT_TEMPLATE.md")
        );
    }

    #[test]
    fn test_research_artifact_template_entry() {
        let registry = ResearchArtifactRegistry::with_research_artifact_template_entry();

        let artifact = registry
            .get_artifact("research-artifact-template-0001")
            .expect("expected research artifact template artifact");
        assert_eq!(artifact.artifact_type, "artifact_template");
        assert_eq!(artifact.title, "Research Artifact Template");
        assert!(
            artifact
                .bundle_path
                .ends_with("RESEARCH_ARTIFACT_TEMPLATE.md")
        );
    }

    #[test]
    fn test_bd2501_audit_report_entry() {
        let registry = ResearchArtifactRegistry::with_bd2501_audit_report_entry();

        let artifact = registry
            .get_artifact("bd2501-audit-report-0001")
            .expect("expected bd-2501 audit report artifact");
        assert_eq!(artifact.artifact_type, "audit_report");
        assert_eq!(artifact.title, "BD-2501 Audit Report");
        assert!(artifact.bundle_path.ends_with("BD2501_AUDIT_REPORT.md"));
    }

    #[test]
    fn test_list_artifacts_order_deterministic() {
        let mut registry = ResearchArtifactRegistry::new();
        registry.register_artifact(ArtifactMetadata {
            artifact_id: "zeta-test-0001".to_string(),
            title: "Zeta Test Artifact".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Research Team".to_string()],
            abstract_text: "Regression guard for deterministic ordering checks.".to_string(),
            bundle_path: "docs/TECHNICAL_REPORT_TEMPLATE.md".to_string(),
            artifact_type: "check".to_string(),
        });
        registry.register_artifact(ArtifactMetadata {
            artifact_id: "alpha-test-0001".to_string(),
            title: "Alpha Test Artifact".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Research Team".to_string()],
            abstract_text: "Regression guard for deterministic ordering checks.".to_string(),
            bundle_path: "docs/TECHNICAL_REPORT_TEMPLATE.md".to_string(),
            artifact_type: "check".to_string(),
        });
        registry.register_artifact(ArtifactMetadata {
            artifact_id: "beta-test-0001".to_string(),
            title: "Beta Test Artifact".to_string(),
            publication_date: "2026-04-20".to_string(),
            authors: vec!["FrankenEngine Research Team".to_string()],
            abstract_text: "Regression guard for deterministic ordering checks.".to_string(),
            bundle_path: "docs/TECHNICAL_REPORT_TEMPLATE.md".to_string(),
            artifact_type: "check".to_string(),
        });

        let artifacts = registry.list_artifacts();
        let ids: Vec<_> = artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["alpha-test-0001", "beta-test-0001", "zeta-test-0001"]
        );
    }

    #[test]
    fn test_chaos_engineering_entry() {
        let registry = ResearchArtifactRegistry::with_chaos_engineering_entry();

        let artifact = registry
            .get_artifact("chaos-engineering-manifest-0001")
            .expect("expected chaos engineering manifest");
        assert_eq!(artifact.artifact_type, "chaos_engineering");
        assert_eq!(artifact.title, "Chaos Engineering Manifest");
        assert!(
            artifact
                .bundle_path
                .ends_with("CHAOS_ENGINEERING_MANIFEST.md")
        );
    }
}
