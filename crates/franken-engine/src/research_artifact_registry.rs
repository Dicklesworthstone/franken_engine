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
        self.artifacts.values().collect()
    }

    /// Get artifacts by type
    pub fn get_artifacts_by_type(&self, artifact_type: &str) -> Vec<&ArtifactMetadata> {
        self.artifacts
            .values()
            .filter(|artifact| artifact.artifact_type == artifact_type)
            .collect()
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
}
