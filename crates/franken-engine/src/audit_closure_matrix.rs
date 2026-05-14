/*!
Audit Closure Matrix

Loads and verifies the audit finding closure matrix from AUDIT_CLOSURE_MATRIX.md.
Provides validation that all audit findings have complete closure evidence.
*/

use std::collections::BTreeMap;
use std::path::Path;

/// Represents a single audit finding closure entry
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditFindingClosure {
    /// Unique audit finding identifier (e.g., "RGC-920A.1")
    pub finding_id: String,
    /// Bead that implemented the fix (e.g., "bd-2muur.1.1")
    pub fixing_bead: String,
    /// File-level path where the fix was implemented
    pub file_path: String,
    /// Test coverage that verifies the fix
    pub test_coverage: String,
    /// Artifact that provides closure evidence
    pub artifact: String,
}

/// Audit closure matrix containing all finding closures
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditClosureMatrix {
    /// Mapping from finding ID to closure details
    closures: BTreeMap<String, AuditFindingClosure>,
}

/// Errors that can occur during matrix loading or validation
#[derive(Debug, Clone)]
pub enum AuditClosureError {
    /// Failed to read the matrix file
    FileReadError(String),
    /// Matrix file has invalid format
    ParseError(String),
    /// Missing required closure information
    IncompleteClosureError(String),
    /// Finding ID validation failed
    InvalidFindingId(String),
}

impl std::fmt::Display for AuditClosureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditClosureError::FileReadError(msg) => write!(f, "File read error: {}", msg),
            AuditClosureError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            AuditClosureError::IncompleteClosureError(msg) => {
                write!(f, "Incomplete closure: {}", msg)
            }
            AuditClosureError::InvalidFindingId(msg) => write!(f, "Invalid finding ID: {}", msg),
        }
    }
}

impl std::error::Error for AuditClosureError {}

impl AuditClosureMatrix {
    /// Create a new empty audit closure matrix
    pub fn new() -> Self {
        Self {
            closures: BTreeMap::new(),
        }
    }

    /// Load audit closure matrix from the default markdown file
    pub fn load_default() -> Result<Self, AuditClosureError> {
        let matrix_path = Path::new("crates/franken-engine/docs/AUDIT_CLOSURE_MATRIX.md");
        Self::load_from_file(matrix_path)
    }

    /// Load audit closure matrix from a specified file
    pub fn load_from_file(path: &Path) -> Result<Self, AuditClosureError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AuditClosureError::FileReadError(e.to_string()))?;

        Self::parse_from_markdown(&content)
    }

    /// Parse audit closure matrix from markdown content
    pub fn parse_from_markdown(content: &str) -> Result<Self, AuditClosureError> {
        let mut closures = BTreeMap::new();
        let lines: Vec<&str> = content.lines().collect();

        // Find the table header
        let table_start = lines
            .iter()
            .position(|line| line.starts_with("| Finding ID"))
            .ok_or_else(|| AuditClosureError::ParseError("Table header not found".to_string()))?;

        // Skip header and separator rows
        let data_start = table_start + 2;

        // Parse each data row
        for (line_num, line) in lines.iter().enumerate().skip(data_start) {
            if line.trim().is_empty() || !line.starts_with('|') {
                break; // End of table
            }

            let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
            if parts.len() < 6 {
                continue; // Skip malformed rows
            }

            let finding_id = parts[1].to_string();
            let fixing_bead = parts[2].to_string();
            let file_path = parts[3].to_string();
            let test_coverage = parts[4].to_string();
            let artifact = parts[5].to_string();

            // Validate finding ID format
            if !Self::is_valid_finding_id(&finding_id) {
                return Err(AuditClosureError::InvalidFindingId(format!(
                    "Invalid finding ID '{}' at line {}",
                    finding_id,
                    line_num + 1
                )));
            }

            let closure = AuditFindingClosure {
                finding_id: finding_id.clone(),
                fixing_bead,
                file_path,
                test_coverage,
                artifact,
            };

            closures.insert(finding_id, closure);
        }

        Ok(Self { closures })
    }

    /// Check if a finding ID has valid format (RGC-XXX.Y.Z)
    fn is_valid_finding_id(finding_id: &str) -> bool {
        finding_id.starts_with("RGC-") && finding_id.len() > 4
    }

    /// Get closure information for a specific finding
    pub fn get_closure(&self, finding_id: &str) -> Option<&AuditFindingClosure> {
        self.closures.get(finding_id)
    }

    /// Get all finding IDs
    pub fn get_finding_ids(&self) -> Vec<&String> {
        self.closures.keys().collect()
    }

    /// Get the total number of closed findings
    pub fn total_closures(&self) -> usize {
        self.closures.len()
    }

    /// Validate that all closures have complete information
    pub fn validate_completeness(&self) -> Result<(), AuditClosureError> {
        for (finding_id, closure) in &self.closures {
            if closure.fixing_bead.is_empty() {
                return Err(AuditClosureError::IncompleteClosureError(format!(
                    "Finding {} missing fixing bead",
                    finding_id
                )));
            }
            if closure.file_path.is_empty() {
                return Err(AuditClosureError::IncompleteClosureError(format!(
                    "Finding {} missing file path",
                    finding_id
                )));
            }
            if closure.test_coverage.is_empty() {
                return Err(AuditClosureError::IncompleteClosureError(format!(
                    "Finding {} missing test coverage",
                    finding_id
                )));
            }
            if closure.artifact.is_empty() {
                return Err(AuditClosureError::IncompleteClosureError(format!(
                    "Finding {} missing artifact",
                    finding_id
                )));
            }
        }
        Ok(())
    }

    /// Closure rate as a percentage: complete closures / total closures × 100.
    ///
    /// A closure is "complete" when every field (`fixing_bead`, `file_path`,
    /// `test_coverage`, `artifact`) is non-empty — the same predicate
    /// [`validate_completeness`](Self::validate_completeness) enforces.
    /// Returns `0.0` for an empty matrix.
    pub fn closure_rate(&self) -> f64 {
        if self.closures.is_empty() {
            return 0.0;
        }
        let complete = self
            .closures
            .values()
            .filter(|closure| {
                !closure.fixing_bead.is_empty()
                    && !closure.file_path.is_empty()
                    && !closure.test_coverage.is_empty()
                    && !closure.artifact.is_empty()
            })
            .count();
        (complete as f64 / self.closures.len() as f64) * 100.0
    }
}

impl Default for AuditClosureMatrix {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_closure_matrix_creation() {
        let matrix = AuditClosureMatrix::new();
        assert_eq!(matrix.total_closures(), 0);
        assert_eq!(matrix.closure_rate(), 0.0);
    }

    #[test]
    fn test_finding_id_validation() {
        assert!(AuditClosureMatrix::is_valid_finding_id("RGC-920A.1"));
        assert!(AuditClosureMatrix::is_valid_finding_id("RGC-123B.2.3"));
        assert!(!AuditClosureMatrix::is_valid_finding_id("INVALID"));
        assert!(!AuditClosureMatrix::is_valid_finding_id("RGC-"));
        assert!(!AuditClosureMatrix::is_valid_finding_id(""));
    }

    #[test]
    fn test_markdown_parsing() {
        let markdown_content = r#"
# Audit Closure Matrix

| Finding ID | Fixing Bead | File-Level Path | Test Coverage | Artifact |
|------------|-------------|-----------------|---------------|----------|
| RGC-920A.1 | bd-2muur.1.1 | src/test.rs:123-145 | tests/test.rs::test_fix | artifacts/fix.json |
| RGC-920A.2 | bd-2muur.1.2 | src/other.rs:67-89 | tests/other.rs::test_other | artifacts/other.json |

## Summary
        "#;

        let matrix = AuditClosureMatrix::parse_from_markdown(markdown_content)
            .expect("serde deserialization should succeed");
        assert_eq!(matrix.total_closures(), 2);

        let closure = matrix
            .get_closure("RGC-920A.1")
            .expect("serde deserialization should succeed");
        assert_eq!(closure.fixing_bead, "bd-2muur.1.1");
        assert_eq!(closure.file_path, "src/test.rs:123-145");
        assert_eq!(closure.test_coverage, "tests/test.rs::test_fix");
        assert_eq!(closure.artifact, "artifacts/fix.json");
    }

    #[test]
    fn test_completeness_validation() {
        let mut matrix = AuditClosureMatrix::new();

        // Complete closure
        let complete_closure = AuditFindingClosure {
            finding_id: "RGC-920A.1".to_string(),
            fixing_bead: "bd-2muur.1.1".to_string(),
            file_path: "src/test.rs:123-145".to_string(),
            test_coverage: "tests/test.rs::test_fix".to_string(),
            artifact: "artifacts/fix.json".to_string(),
        };

        matrix
            .closures
            .insert("RGC-920A.1".to_string(), complete_closure);
        assert!(matrix.validate_completeness().is_ok());

        // Incomplete closure (missing fixing bead)
        let incomplete_closure = AuditFindingClosure {
            finding_id: "RGC-920A.2".to_string(),
            fixing_bead: "".to_string(),
            file_path: "src/test.rs:123-145".to_string(),
            test_coverage: "tests/test.rs::test_fix".to_string(),
            artifact: "artifacts/fix.json".to_string(),
        };

        matrix
            .closures
            .insert("RGC-920A.2".to_string(), incomplete_closure);
        assert!(matrix.validate_completeness().is_err());
    }

    #[test]
    fn closure_rate_reflects_completeness_of_entries() {
        let mut matrix = AuditClosureMatrix::new();

        let complete = AuditFindingClosure {
            finding_id: "RGC-100A.1".to_string(),
            fixing_bead: "bd-1".to_string(),
            file_path: "src/a.rs".to_string(),
            test_coverage: "tests/a.rs::test".to_string(),
            artifact: "artifacts/a.json".to_string(),
        };
        let missing_bead = AuditFindingClosure {
            finding_id: "RGC-100A.2".to_string(),
            fixing_bead: String::new(),
            file_path: "src/b.rs".to_string(),
            test_coverage: "tests/b.rs::test".to_string(),
            artifact: "artifacts/b.json".to_string(),
        };
        let missing_artifact = AuditFindingClosure {
            finding_id: "RGC-100A.3".to_string(),
            fixing_bead: "bd-3".to_string(),
            file_path: "src/c.rs".to_string(),
            test_coverage: "tests/c.rs::test".to_string(),
            artifact: String::new(),
        };

        matrix
            .closures
            .insert(complete.finding_id.clone(), complete);
        matrix
            .closures
            .insert(missing_bead.finding_id.clone(), missing_bead);
        matrix
            .closures
            .insert(missing_artifact.finding_id.clone(), missing_artifact);

        // 1 complete / 3 total ≈ 33.333…
        let rate = matrix.closure_rate();
        assert!(
            (rate - (100.0 / 3.0)).abs() < 1e-9,
            "expected ~33.333%, got {rate}"
        );
    }

    #[test]
    fn closure_rate_is_one_hundred_when_all_complete() {
        let mut matrix = AuditClosureMatrix::new();
        for idx in 0..4 {
            let closure = AuditFindingClosure {
                finding_id: format!("RGC-200A.{idx}"),
                fixing_bead: format!("bd-{idx}"),
                file_path: format!("src/f{idx}.rs"),
                test_coverage: format!("tests/f{idx}.rs::test"),
                artifact: format!("artifacts/f{idx}.json"),
            };
            matrix.closures.insert(closure.finding_id.clone(), closure);
        }
        assert_eq!(matrix.closure_rate(), 100.0);
    }
}
