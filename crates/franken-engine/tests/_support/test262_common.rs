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
use frankenengine_engine::{EvalError, EvalErrorClass, EvalOutcome, EvalResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Returns true when the engine error matches the JS-style error type test262
/// expects. Combines two checks:
///
/// 1. Substring match on the full Display string. Many engine errors include
///    the JS class name in their message (e.g. closure_model emits
///    "SyntaxError: identifier ... has already been declared").
/// 2. Class-based fallback for the cases where a correctly-classified engine
///    error does not happen to mention the JS class name in its message — for
///    example, a generic parse error like "Unexpected token at line 7" is
///    correctly a SyntaxError per spec but its message does not contain the
///    literal "SyntaxError".
fn matches_expected_error_type(error: &EvalError, error_type: &str) -> bool {
    if error.to_string().contains(error_type) {
        return true;
    }
    matches!(
        (error.class(), error_type),
        (EvalErrorClass::Parse, "SyntaxError") | (EvalErrorClass::Resolution, "ReferenceError")
    )
}

// ---------------------------------------------------------------------------
// Shared round-trip oracle (bd-wrmld FIND-22)
//
// Audit `bd-85qfs` FIND-22: harnesses that have a JSON-round-trip oracle
// reimplement the same 4-line check inline. This helper centralises that
// check so:
//
// 1. A `report` round-trips through serde_json with `PartialEq`-equality.
// 2. The report's `schema_version` matches the canonical pin the harness
//    claims to follow (caller passes both sides; the helper asserts they
//    are byte-equal).
//
// FIND-10 (`bd-rqev5`) is the follow-up that migrates the 3+ existing
// round-trip oracles to call this helper and adds the missing 6+ harnesses
// — out of scope for this commit (it's a CARGO-touching migration that
// belongs in a sibling bead).
// ---------------------------------------------------------------------------

/// Assert that a conformance `report` round-trips through `serde_json` and
/// carries the expected `schema_version` pin.
///
/// `actual_schema_version` is the version string baked into the report
/// (typically `report.schema_version` or a wrapped equivalent). The helper
/// is generic over the report type so every harness's report can call into
/// the same oracle.
///
/// Panics — i.e. fails the test — when any of the following holds:
///
/// 1. `report` does not serialize via `serde_json::to_string`.
/// 2. The serialized JSON does not deserialize back into `R`.
/// 3. The round-tripped value is not `PartialEq` equal to the original.
/// 4. `actual_schema_version` does not byte-equal `expected_schema_version`.
///
/// Use this helper as the sole load-bearing round-trip oracle in every
/// `*_test262_conformance.rs` harness; sibling beads tracked under
/// FIND-10 (`bd-rqev5`) carry the per-harness migration.
pub fn assert_report_round_trips<R>(
    report: &R,
    expected_schema_version: &str,
    actual_schema_version: &str,
) where
    R: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(report)
        .expect("conformance report must serialise via serde_json::to_string");
    let back: R = serde_json::from_str(&json)
        .expect("conformance report must deserialise back into its report type");
    assert_eq!(
        report, &back,
        "conformance report must round-trip through serde_json without loss"
    );
    assert_eq!(
        actual_schema_version, expected_schema_version,
        "conformance report schema_version must match the canonical pin"
    );
}

/// Same as [`assert_report_round_trips`] but for report types that do not
/// (yet) derive `PartialEq`. Asserts the report round-trips through
/// `serde_json` by re-serialising the decoded value and comparing the byte
/// strings — equivalent to value equality for canonically-encoded reports
/// (serde_json + `BTreeMap`-keyed test_results give a deterministic key
/// order across runs).
///
/// Use this variant when migrating round-trip coverage onto a harness whose
/// report still lacks the `PartialEq` cascade (bd-rqev5 FIND-10). Prefer
/// [`assert_report_round_trips`] once the cascade is in place.
pub fn assert_report_json_round_trips<R>(
    report: &R,
    expected_schema_version: &str,
    actual_schema_version: &str,
) where
    R: serde::Serialize + serde::de::DeserializeOwned,
{
    let first = serde_json::to_string(report)
        .expect("conformance report must serialise via serde_json::to_string");
    let back: R = serde_json::from_str(&first)
        .expect("conformance report must deserialise back into its report type");
    let second = serde_json::to_string(&back)
        .expect("decoded conformance report must re-serialise via serde_json::to_string");
    assert_eq!(
        first, second,
        "conformance report must round-trip through serde_json without byte-level drift"
    );
    assert_eq!(
        actual_schema_version, expected_schema_version,
        "conformance report schema_version must match the canonical pin"
    );
}

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

impl std::fmt::Display for RequirementLevel {
    /// Renders as the upper-case RFC-2119-style tag (`MUST` / `SHOULD` /
    /// `MAY`) so per-test log lines stay grep-friendly after harnesses
    /// migrate away from inline string literals (bd-cd0px).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = match self {
            RequirementLevel::Must => "MUST",
            RequirementLevel::Should => "SHOULD",
            RequirementLevel::May => "MAY",
        };
        f.write_str(tag)
    }
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

/// Evaluate a Test262 test case execution result against expected outcome.
///
/// This function fixes the systematic issue where conformance harnesses ignored
/// expected output and only checked for !crash. Now properly compares actual
/// execution output with expected results.
///
/// # Arguments
/// * `eval_result` - Result from HybridRouter::eval()
/// * `expected` - Expected test outcome
/// * `test_id` - Test identifier for error reporting
///
/// # Returns
/// Test262Result with proper pass/fail classification based on output comparison
pub fn evaluate_test262_result(
    eval_result: EvalResult<EvalOutcome>,
    expected: &ExpectedResult,
    test_id: &str,
) -> Test262Result {
    match eval_result {
        Ok(outcome) => match expected {
            ExpectedResult::Success { output } => {
                // Compare against console output when the program produced any
                // (Test262 ExpectedResult::Success.output is stdout-shaped —
                // expected fixtures consistently end with "\n" because the
                // tests use `console.log(...)`, which prints and then returns
                // undefined). Falling back to outcome.value preserves prior
                // behaviour for pure-expression fixtures that don't log.
                //
                // [bd-itxl9] Previously this compared outcome.value to output,
                // which made every `console.log(expr)` fixture spuriously fail
                // (outcome.value is the eval-completion value — undefined —
                // not the printed text). 12 of 18 MUST-tier optional-chaining
                // cases failed by this mechanism even though the engine
                // returned the correct value via console.log.
                let actual = if outcome.console_output.is_empty() {
                    outcome.value.clone()
                } else {
                    let mut joined = String::new();
                    for (i, entry) in outcome.console_output.iter().enumerate() {
                        if i > 0 {
                            joined.push('\n');
                        }
                        joined.push_str(&entry.message);
                    }
                    joined
                };
                if actual.trim() == output.trim() {
                    Test262Result::Pass
                } else {
                    Test262Result::Fail {
                        reason: format!(
                            "Output mismatch in {}: expected '{}', got '{}' (completion value: '{}')",
                            test_id, output, actual, outcome.value
                        ),
                    }
                }
            }
            ExpectedResult::ParseSuccess => {
                // Code parsed and executed successfully - this is correct
                Test262Result::Pass
            }
            ExpectedResult::SyntaxError { error_type } => Test262Result::Fail {
                reason: format!(
                    "Expected syntax error '{}' but execution succeeded in {}",
                    error_type, test_id
                ),
            },
            ExpectedResult::RuntimeError { error_type } => Test262Result::Fail {
                reason: format!(
                    "Expected runtime error '{}' but execution succeeded in {}",
                    error_type, test_id
                ),
            },
            ExpectedResult::IteratorSequence { values: _ } => Test262Result::Fail {
                reason: format!(
                    "ExpectedResult::IteratorSequence is not supported by the shared \
                     Test262 helper — use the iterator_protocol_test262 harness or \
                     extend evaluate_test262_result with sequence comparison ({})",
                    test_id
                ),
            },
        },
        Err(error) => match expected {
            ExpectedResult::SyntaxError { error_type } => {
                if matches_expected_error_type(&error, error_type) {
                    Test262Result::Pass
                } else {
                    Test262Result::Fail {
                        reason: format!(
                            "Expected syntax error '{}' but got '{}' in {}",
                            error_type, error, test_id
                        ),
                    }
                }
            }
            ExpectedResult::RuntimeError { error_type } => {
                if matches_expected_error_type(&error, error_type) {
                    Test262Result::Pass
                } else {
                    Test262Result::Fail {
                        reason: format!(
                            "Expected runtime error '{}' but got '{}' in {}",
                            error_type, error, test_id
                        ),
                    }
                }
            }
            ExpectedResult::Success { output } => Test262Result::Fail {
                reason: format!(
                    "Expected success with output '{}' but got error '{}' in {}",
                    output, error, test_id
                ),
            },
            ExpectedResult::ParseSuccess => Test262Result::Fail {
                reason: format!(
                    "Expected parse success but got error '{}' in {}",
                    error, test_id
                ),
            },
            ExpectedResult::IteratorSequence { values } => Test262Result::Fail {
                reason: format!(
                    "Expected iterator sequence {:?} but got error '{}' in {}",
                    values, error, test_id
                ),
            },
        },
    }
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
