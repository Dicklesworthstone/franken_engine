#![forbid(unsafe_code)]

//! Minimal compatibility advisory builder for Node/Bun divergence remediation guidance.
//!
//! Provides a simple API to create human-readable advisories with remediation hints
//! for behavioral divergences between runtime environments.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A compatibility advisory with human-readable message and remediation guidance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    /// Human-readable advisory message explaining the divergence
    pub message: String,
    /// Remediation guidance for addressing the divergence
    pub remediation: String,
}

/// Builder for creating compatibility advisories.
#[derive(Debug, Default)]
pub struct AdvisoryBuilder {
    divergence_tag: Option<String>,
    context: BTreeMap<String, String>,
}

impl AdvisoryBuilder {
    /// Create a new advisory builder.
    pub fn new() -> Self {
        Self {
            divergence_tag: None,
            context: BTreeMap::new(),
        }
    }

    /// Set the divergence tag that identifies the specific compatibility issue.
    pub fn with_divergence(mut self, tag: impl Into<String>) -> Self {
        self.divergence_tag = Some(tag.into());
        self
    }

    /// Add context information to help generate more specific advisory content.
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Build the advisory with generated message and remediation guidance.
    pub fn build(self) -> Advisory {
        let divergence = self.divergence_tag.as_deref().unwrap_or("unknown");

        let message = self.generate_message(divergence);
        let remediation = self.generate_remediation(divergence);

        Advisory {
            message,
            remediation,
        }
    }

    fn generate_message(&self, divergence_tag: &str) -> String {
        let base_message = match divergence_tag {
            "module_resolution" => "Module resolution behavior differs between Node.js and Bun",
            "import_meta" => "import.meta property access shows divergent behavior",
            "buffer_encoding" => "Buffer encoding operations produce different results",
            "async_hooks" => "Async hooks timing and lifecycle differ between runtimes",
            "process_env" => "Process environment variable handling shows inconsistencies",
            "fs_permissions" => "File system permission checks vary between environments",
            "crypto_algorithms" => "Cryptographic algorithm implementations differ",
            "stream_behavior" => "Stream processing behavior is inconsistent",
            _ => "Runtime behavior divergence detected",
        };

        // Add context-specific details if available
        if let Some(package_name) = self.context.get("package") {
            format!("{} in package '{}'", base_message, package_name)
        } else if let Some(module_path) = self.context.get("module") {
            format!("{} for module '{}'", base_message, module_path)
        } else {
            base_message.to_string()
        }
    }

    fn generate_remediation(&self, divergence_tag: &str) -> String {
        let base_remediation = match divergence_tag {
            "module_resolution" => {
                "Use explicit file extensions and avoid package.json resolution edge cases"
            }
            "import_meta" => "Check runtime type before accessing import.meta properties",
            "buffer_encoding" => "Explicitly specify encoding parameters and validate output",
            "async_hooks" => "Avoid timing-dependent logic in async hook callbacks",
            "process_env" => "Use consistent environment variable access patterns",
            "fs_permissions" => "Implement runtime-agnostic permission checking",
            "crypto_algorithms" => "Use standard crypto APIs and verify algorithm support",
            "stream_behavior" => "Add explicit stream state validation and error handling",
            _ => "Review runtime-specific documentation and test with target environments",
        };

        // Add context-specific remediation hints
        if let Some(version) = self.context.get("node_version") {
            format!("{} (Node.js {})", base_remediation, version)
        } else if let Some(severity) = self.context.get("severity") {
            match severity.as_str() {
                "high" => format!(
                    "{} - URGENT: This divergence may cause runtime failures",
                    base_remediation
                ),
                "medium" => format!(
                    "{} - MODERATE: Consider testing thoroughly",
                    base_remediation
                ),
                "low" => format!("{} - LOW: Monitor for edge cases", base_remediation),
                _ => base_remediation.to_string(),
            }
        } else {
            base_remediation.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_builder_creates_basic_advisory() {
        let advisory = AdvisoryBuilder::new()
            .with_divergence("module_resolution")
            .build();

        assert_eq!(
            advisory.message,
            "Module resolution behavior differs between Node.js and Bun"
        );
        assert_eq!(
            advisory.remediation,
            "Use explicit file extensions and avoid package.json resolution edge cases"
        );
    }

    #[test]
    fn advisory_builder_includes_package_context() {
        let advisory = AdvisoryBuilder::new()
            .with_divergence("import_meta")
            .with_context("package", "my-package")
            .build();

        assert!(advisory.message.contains("my-package"));
        assert!(!advisory.remediation.contains("my-package")); // remediation doesn't include package
    }

    #[test]
    fn advisory_builder_includes_severity_context() {
        let advisory = AdvisoryBuilder::new()
            .with_divergence("buffer_encoding")
            .with_context("severity", "high")
            .build();

        assert!(advisory.remediation.contains("URGENT"));
    }

    #[test]
    fn advisory_builder_handles_unknown_divergence() {
        let advisory = AdvisoryBuilder::new()
            .with_divergence("unknown_issue")
            .build();

        assert_eq!(advisory.message, "Runtime behavior divergence detected");
        assert_eq!(
            advisory.remediation,
            "Review runtime-specific documentation and test with target environments"
        );
    }

    #[test]
    fn advisory_builder_works_without_divergence_tag() {
        let advisory = AdvisoryBuilder::new().build();

        assert_eq!(advisory.message, "Runtime behavior divergence detected");
        assert_eq!(
            advisory.remediation,
            "Review runtime-specific documentation and test with target environments"
        );
    }

    #[test]
    fn advisory_builder_supports_multiple_context() {
        let advisory = AdvisoryBuilder::new()
            .with_divergence("fs_permissions")
            .with_context("module", "/path/to/module.js")
            .with_context("severity", "medium")
            .build();

        assert!(advisory.message.contains("/path/to/module.js"));
        assert!(advisory.remediation.contains("MODERATE"));
    }
}
