/*!
 * Proof Artifact Contract Conformance Harness (Enhanced)
 *
 * Systematic validation of ALL MUST/SHOULD requirements in the cd3d2b4d
 * proof-artifact contract using the testing-conformance-harnesses methodology.
 */

#![allow(dead_code)]

use frankenengine_engine::proof_artifact::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub mod fixtures;
pub mod harness;
pub mod tests;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestCategory {
    Unit,
    Integration,
    EdgeCase,
    Performance,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
pub enum TestResult {
    Pass,
    Fail { reason: String },
    Skipped { reason: String },
    ExpectedFailure { reason: String }, // Known divergence (XFAIL)
}

#[derive(Debug)]
pub struct TestContext {
    pub fixtures_dir: PathBuf,
    pub temp_dir: Option<PathBuf>,
    pub config: ConformanceConfig,
}

#[derive(Debug, Clone)]
pub struct ConformanceConfig {
    pub validate_hashes: bool,
    pub strict_redaction: bool,
    pub max_bundle_size_mb: u64,
}

impl Default for ConformanceConfig {
    fn default() -> Self {
        Self {
            validate_hashes: true,
            strict_redaction: true,
            max_bundle_size_mb: 100,
        }
    }
}

/// Core trait for all conformance tests following the harness pattern
pub trait ConformanceTest: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> TestCategory;
    fn requirement_level(&self) -> RequirementLevel;
    fn requirement_id(&self) -> &str; // e.g., "CD3D2B4D-3.1"
    fn description(&self) -> &str;
    fn run(&self, ctx: &TestContext) -> TestResult;
}

/// Section coverage statistics for compliance matrix
#[derive(Debug, Default)]
pub struct SectionStats {
    pub must_total: u32,
    pub should_total: u32,
    pub may_total: u32,
    pub passing: u32,
    pub xfail: u32,
}

/// Conformance result for a single test case
#[derive(Debug)]
pub struct ConformanceResult {
    pub test_name: String,
    pub requirement_id: String,
    pub requirement_level: RequirementLevel,
    pub category: TestCategory,
    pub result: TestResult,
    pub duration_ms: u64,
}

/// Overall conformance report
#[derive(Debug)]
pub struct ConformanceReport {
    pub total_tests: u32,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub xfail: u32,
    pub coverage_by_section: BTreeMap<String, SectionStats>,
    pub results: Vec<ConformanceResult>,
    pub overall_score: f64,
}

impl ConformanceReport {
    /// Generates markdown compliance matrix
    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        output.push_str("# Proof Artifact Contract Conformance Report\n\n");
        output.push_str(&format!(
            "**Overall Score**: {:.1}%\n\n",
            self.overall_score * 100.0
        ));

        output.push_str("## Summary\n\n");
        output.push_str(&format!("- Total Tests: {}\n", self.total_tests));
        output.push_str(&format!("- Passed: {} ✓\n", self.passed));
        output.push_str(&format!("- Failed: {} ✗\n", self.failed));
        output.push_str(&format!("- Skipped: {} ⊝\n", self.skipped));
        output.push_str(&format!("- Expected Failures: {} ⚠\n\n", self.xfail));

        output.push_str("## Coverage Accounting Matrix\n\n");
        output.push_str(
            "| Section | MUST (pass/total) | SHOULD (pass/total) | MAY (pass/total) | Score |\n",
        );
        output.push_str(
            "|---------|-------------------|---------------------|------------------|-------|\n",
        );

        for (section, stats) in &self.coverage_by_section {
            let section_score = if stats.must_total + stats.should_total > 0 {
                (stats.passing as f64) / ((stats.must_total + stats.should_total) as f64) * 100.0
            } else {
                100.0
            };

            output.push_str(&format!(
                "| {} | {}/{} | {}/{} | {}/{} | {:.1}% |\n",
                section,
                stats.passing.min(stats.must_total),
                stats.must_total,
                stats
                    .passing
                    .saturating_sub(stats.must_total)
                    .min(stats.should_total),
                stats.should_total,
                stats
                    .passing
                    .saturating_sub(stats.must_total + stats.should_total)
                    .min(stats.may_total),
                stats.may_total,
                section_score
            ));
        }

        output.push_str("\n## Requirement Coverage\n\n");
        for result in &self.results {
            let status_icon = match &result.result {
                TestResult::Pass => "✓",
                TestResult::Fail { .. } => "✗",
                TestResult::Skipped { .. } => "⊝",
                TestResult::ExpectedFailure { .. } => "⚠",
            };

            output.push_str(&format!(
                "- {} **{}** ({:?}): {}\n",
                status_icon, result.requirement_id, result.requirement_level, result.test_name
            ));

            if let TestResult::Fail { reason } = &result.result {
                output.push_str(&format!("  *Failure*: {}\n", reason));
            }
            if let TestResult::ExpectedFailure { reason } = &result.result {
                output.push_str(&format!("  *Expected failure*: {}\n", reason));
            }
        }

        output
    }
}
