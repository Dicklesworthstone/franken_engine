#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Shared Test262 conformance test scaffolding
//!
//! Common types, enums, and utilities shared across all Test262 conformance harnesses.
//! Eliminates duplication of threshold gates, requirement levels, result classifications,
//! and summary printing logic.
//!
//! Used by: arrow_function, optional_chaining, iteration_statements, template_literal,
//! iterator_protocol test262 conformance harnesses.

use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Common Test262 Enums and Types
// ---------------------------------------------------------------------------

/// ES2020 specification requirement level for Test262 conformance.
///
/// Shared across all conformance harnesses to ensure consistent classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RequirementLevel {
    /// MUST clauses - conformance required
    Must,
    /// SHOULD clauses - recommended behavior
    Should,
    /// MAY clauses - optional behavior
    May,
}

/// Expected execution result for Test262 test cases.
///
/// Standardized across conformance harnesses for consistent test expectations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpectedResult {
    /// Code should execute successfully with specific output
    Success { output: String },
    /// Code should throw a syntax error during parsing
    SyntaxError { error_type: String },
    /// Code should throw a runtime error during execution
    RuntimeError { error_type: String },
    /// Code should parse successfully (syntax check only)
    ParseSuccess,
    /// Code should produce specific iterator sequence
    IteratorSequence { values: Vec<String> },
}

/// Generic test result classification for Test262 conformance.
///
/// Parameterized by category type to allow type-safe categorization
/// while sharing common result structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Test262Result {
    /// Test passed - behavior matches ES2020 spec
    Pass,
    /// Test failed - behavior diverges from ES2020 spec
    Fail { reason: String },
    /// Test execution error - franken_engine failed to execute
    Error { error: String },
    /// Test skipped - known limitation or unsupported syntax
    Skip { reason: String },
}

/// Test262 conformance test case structure.
///
/// Generic over category type to maintain type safety while sharing structure.
#[derive(Debug, Clone)]
pub struct Test262TestCase<Category> {
    pub id: String,
    pub description: String,
    pub es2020_section: String,
    pub requirement_level: RequirementLevel,
    pub category: Category,
    pub source: String,
    pub expected_result: ExpectedResult,
}

/// Backwards-compatible test case structure for gradual migration
#[derive(Debug, Clone)]
pub struct LegacyTest262TestCase<Category> {
    pub id: String,
    pub description: String,
    pub es_spec_section: String,   // Legacy field name
    pub requirement_level: String, // Legacy string type
    pub category: Category,
    pub source_code: String, // Legacy field name
}

/// Coverage statistics for Test262 conformance categories.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryCoverage {
    pub total: u32,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub errors: u32,
}

impl CategoryCoverage {
    /// Calculate pass rate as fixed-point millionths
    pub fn pass_rate_millionths(&self) -> u32 {
        if self.total == 0 {
            1_000_000 // 100% if no tests
        } else {
            ((self.passed as u64) * 1_000_000 / (self.total as u64)) as u32
        }
    }

    /// Add a test result to coverage statistics
    pub fn record_result(&mut self, result: &Test262Result) {
        self.total += 1;
        match result {
            Test262Result::Pass => self.passed += 1,
            Test262Result::Fail { .. } => self.failed += 1,
            Test262Result::Skip { .. } => self.skipped += 1,
            Test262Result::Error { .. } => self.errors += 1,
        }
    }
}

/// Overall conformance statistics across all test categories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceStatistics {
    pub total_tests: u32,
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub errors: u32,
    pub pass_rate_millionths: u32,
}

impl ConformanceStatistics {
    /// Create statistics from individual test results
    pub fn from_results(results: &BTreeMap<String, Test262Result>) -> Self {
        let mut stats = Self {
            total_tests: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            errors: 0,
            pass_rate_millionths: 0,
        };

        for result in results.values() {
            stats.total_tests += 1;
            match result {
                Test262Result::Pass => stats.passed += 1,
                Test262Result::Fail { .. } => stats.failed += 1,
                Test262Result::Skip { .. } => stats.skipped += 1,
                Test262Result::Error { .. } => stats.errors += 1,
            }
        }

        stats.pass_rate_millionths = if stats.total_tests > 0 {
            ((stats.passed as u64) * 1_000_000 / (stats.total_tests as u64)) as u32
        } else {
            1_000_000
        };

        stats
    }
}

/// Generic Test262 conformance report structure.
///
/// Parameterized by category type for type-safe category-specific reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Test262Report<Category: Serialize + std::cmp::Ord + std::fmt::Debug + Clone> {
    pub schema_version: String,
    pub test_suite_name: String,
    pub security_epoch: SecurityEpoch,
    pub timestamp: String,
    pub test_results: BTreeMap<String, Test262Result>,
    pub statistics: ConformanceStatistics,
    pub coverage_by_category: BTreeMap<Category, CategoryCoverage>,
}

impl<Category: Serialize + Ord + Clone + std::fmt::Debug> Test262Report<Category> {
    /// Generate human-readable conformance summary
    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();

        summary.push_str(&format!(
            "# {} Test262 Conformance Report\n\n",
            self.test_suite_name
        ));
        summary.push_str(&format!("**Generated:** {}\n", self.timestamp));
        summary.push_str(&format!(
            "**Total Tests:** {}\n",
            self.statistics.total_tests
        ));
        summary.push_str(&format!(
            "**Pass Rate:** {:.1}%\n\n",
            self.statistics.pass_rate_millionths as f64 / 10_000.0
        ));

        summary.push_str("## Test Results Summary\n\n");
        summary.push_str(&format!("- ✅ **Passed:** {}\n", self.statistics.passed));
        summary.push_str(&format!("- ❌ **Failed:** {}\n", self.statistics.failed));
        summary.push_str(&format!("- ⏭️ **Skipped:** {}\n", self.statistics.skipped));
        summary.push_str(&format!("- 🔥 **Errors:** {}\n\n", self.statistics.errors));

        summary.push_str("## Category Coverage\n\n");
        for (category, coverage) in &self.coverage_by_category {
            let pass_rate = coverage.pass_rate_millionths() as f64 / 10_000.0;
            summary.push_str(&format!(
                "- **{:?}:** {}/{} ({:.1}%)\n",
                category, coverage.passed, coverage.total, pass_rate
            ));
        }

        summary.push_str("\n## Detailed Results\n\n");
        for (test_id, result) in &self.test_results {
            match result {
                Test262Result::Pass => summary.push_str(&format!("✅ {}\n", test_id)),
                Test262Result::Fail { reason } => {
                    summary.push_str(&format!("❌ {}: {}\n", test_id, reason))
                }
                Test262Result::Error { error } => {
                    summary.push_str(&format!("🔥 {}: {}\n", test_id, error))
                }
                Test262Result::Skip { reason } => {
                    summary.push_str(&format!("⏭️ {}: {}\n", test_id, reason))
                }
            }
        }

        summary
    }
}

// ---------------------------------------------------------------------------
// Common Test Execution Logic
// ---------------------------------------------------------------------------

/// Execute a Test262 test case using the HybridRouter engine.
///
/// Shared execution logic to eliminate duplication across conformance harnesses.
pub fn execute_test262_case(source_code: &str) -> Test262Result {
    use frankenengine_engine::HybridRouter;

    let mut engine = HybridRouter::default();

    match engine.eval(source_code) {
        Ok(_) => Test262Result::Pass,
        Err(err) => {
            let error_str = err.to_string();
            if error_str.contains("parse") || error_str.contains("syntax") {
                Test262Result::Error {
                    error: format!("Parse error: {}", error_str),
                }
            } else {
                Test262Result::Fail {
                    reason: format!("Runtime error: {}", error_str),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Threshold Gates and Quality Checks
// ---------------------------------------------------------------------------

/// Test262 conformance threshold gates for release quality.
///
/// Shared thresholds across all conformance suites to ensure consistent quality bars.
#[derive(Debug, Clone)]
pub struct ConformanceThresholds {
    pub minimum_pass_rate_millionths: u32,  // e.g., 800_000 = 80%
    pub maximum_error_rate_millionths: u32, // e.g., 50_000 = 5%
    pub minimum_coverage_categories: usize, // e.g., 4 categories minimum
}

impl Default for ConformanceThresholds {
    fn default() -> Self {
        Self {
            minimum_pass_rate_millionths: 750_000,  // 75% pass rate
            maximum_error_rate_millionths: 100_000, // 10% error rate
            minimum_coverage_categories: 3,         // 3+ categories
        }
    }
}

impl ConformanceThresholds {
    /// Check if conformance statistics meet release thresholds
    pub fn check_release_readiness<Category>(
        &self,
        report: &Test262Report<Category>,
    ) -> (bool, Vec<String>)
    where
        Category: Serialize + Ord + Clone + std::fmt::Debug,
    {
        let mut issues = Vec::new();
        let mut passed = true;

        // Check pass rate threshold
        if report.statistics.pass_rate_millionths < self.minimum_pass_rate_millionths {
            passed = false;
            issues.push(format!(
                "Pass rate {:.1}% below minimum {:.1}%",
                report.statistics.pass_rate_millionths as f64 / 10_000.0,
                self.minimum_pass_rate_millionths as f64 / 10_000.0
            ));
        }

        // Check error rate threshold
        let error_rate = if report.statistics.total_tests > 0 {
            (report.statistics.errors as u64 * 1_000_000) / (report.statistics.total_tests as u64)
        } else {
            0
        } as u32;

        if error_rate > self.maximum_error_rate_millionths {
            passed = false;
            issues.push(format!(
                "Error rate {:.1}% exceeds maximum {:.1}%",
                error_rate as f64 / 10_000.0,
                self.maximum_error_rate_millionths as f64 / 10_000.0
            ));
        }

        // Check category coverage
        if report.coverage_by_category.len() < self.minimum_coverage_categories {
            passed = false;
            issues.push(format!(
                "Only {} categories covered, minimum {}",
                report.coverage_by_category.len(),
                self.minimum_coverage_categories
            ));
        }

        (passed, issues)
    }
}
