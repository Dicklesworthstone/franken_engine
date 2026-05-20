#![forbid(unsafe_code)]

//! Optional Chaining Test262 Conformance Harness
//!
//! Bead: bd-24iko - [test262] Optional chaining operator conformance gap
//!
//! Implements comprehensive Test262 conformance for ES2020 optional chaining operator (?.)
//! and bracket notation (?.[). Addresses gap where parser frontier recognizes OptionalChaining
//! family but lacks complete conformance coverage.
//!
//! Focus: property access, method calls, bracket notation, short-circuiting, error cases.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod _support;
use _support::test262_common::{
    ExpectedResult, RequirementLevel, Test262Result, evaluate_test262_result,
};

// ---------------------------------------------------------------------------
// Optional Chaining Test262 Conformance Suite
// ---------------------------------------------------------------------------

/// Schema version for optional chaining conformance reports.
pub const OPTIONAL_CHAINING_CONFORMANCE_SCHEMA: &str =
    "franken-engine.optional-chaining-test262.v1";

/// Test result classification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OptionalChainingResult {
    Pass,
    Fail { reason: String },
    Error { error: String },
    Skip { reason: String },
}

// RequirementLevel now imported from shared module

/// Optional chaining test categories.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OptionalChainingCategory {
    /// Property access: obj?.prop
    PropertyAccess,
    /// Bracket notation: obj?.[expr]
    BracketNotation,
    /// Method calls: obj?.method()
    MethodCall,
    /// Short-circuiting behavior
    ShortCircuiting,
    /// Chaining combinations
    ChainingCombos,
    /// Error cases and edge conditions
    EdgeCases,
}

/// Individual optional chaining test case.
#[derive(Debug, Clone)]
pub struct OptionalChainingTest {
    pub id: String,
    pub description: String,
    pub es2020_section: String,
    pub requirement_level: RequirementLevel,
    pub category: OptionalChainingCategory,
    pub source: String,
    pub expected_result: ExpectedResult,
}

// ExpectedResult now imported from shared module

/// Optional chaining conformance harness.
pub struct OptionalChainingHarness {
    tests: Vec<OptionalChainingTest>,
}

impl Default for OptionalChainingHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl OptionalChainingHarness {
    pub fn new() -> Self {
        Self {
            tests: Self::create_optional_chaining_tests(),
        }
    }

    /// Create focused optional chaining Test262 test cases.
    fn create_optional_chaining_tests() -> Vec<OptionalChainingTest> {
        vec![
            // Basic property access
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-basic-property-access".to_string(),
                description: "Basic optional property access with existing property".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::PropertyAccess,
                source: "const obj = { x: 42 }; console.log(obj?.x);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "42\n".to_string(),
                },
            },
            // Property access on null
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-property-access-null".to_string(),
                description: "Optional property access on null returns undefined".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::PropertyAccess,
                source: "const obj = null; console.log(obj?.x);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "undefined\n".to_string(),
                },
            },
            // Property access on undefined
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-property-access-undefined".to_string(),
                description: "Optional property access on undefined returns undefined".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::PropertyAccess,
                source: "const obj = undefined; console.log(obj?.x);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "undefined\n".to_string(),
                },
            },
            // Basic bracket notation
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-basic-bracket-access".to_string(),
                description: "Basic optional bracket notation with existing property".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::BracketNotation,
                source: "const obj = { key: 'value' }; console.log(obj?.['key']);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "value\n".to_string(),
                },
            },
            // Bracket notation on null
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-bracket-access-null".to_string(),
                description: "Optional bracket notation on null returns undefined".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::BracketNotation,
                source: "const obj = null; console.log(obj?.['key']);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "undefined\n".to_string(),
                },
            },
            // Method calls with existing method
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-method-call-existing".to_string(),
                description: "Optional method call on object with method".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::MethodCall,
                source: r#"
                    const obj = {
                        getValue: function() { return 'result'; }
                    };
                    console.log(obj?.getValue());
                "#
                .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "result\n".to_string(),
                },
            },
            // Method calls on null
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-method-call-null".to_string(),
                description: "Optional method call on null returns undefined".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::MethodCall,
                source: "const obj = null; console.log(obj?.getValue());".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "undefined\n".to_string(),
                },
            },
            // Short-circuiting behavior
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-short-circuit".to_string(),
                description: "Optional chaining short-circuits on null/undefined".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::ShortCircuiting,
                source: "const obj = { nested: null }; console.log(obj?.nested?.deep?.property);"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "undefined\n".to_string(),
                },
            },
            // Chained property access
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-chained-property".to_string(),
                description: "Chained optional property access".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::ChainingCombos,
                source: r#"
                    const obj = {
                        nested: {
                            deep: { value: 123 }
                        }
                    };
                    console.log(obj?.nested?.deep?.value);
                "#
                .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "123\n".to_string(),
                },
            },
            // Mixed chaining (property + bracket + method)
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-mixed-chaining".to_string(),
                description: "Mixed optional chaining: property, bracket, method".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::ChainingCombos,
                source: r#"
                    const obj = {
                        items: {
                            'first': {
                                getValue: function() { return 'mixed'; }
                            }
                        }
                    };
                    console.log(obj?.items?.['first']?.getValue());
                "#
                .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "mixed\n".to_string(),
                },
            },
            // Dynamic property names
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-dynamic-property".to_string(),
                description: "Optional chaining with dynamic property names".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::BracketNotation,
                source: r#"
                    const obj = { prop: 'value' };
                    const key = 'prop';
                    console.log(obj?.[key]);
                "#
                .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "value\n".to_string(),
                },
            },
            // Optional chaining with function calls
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-optional-call".to_string(),
                description: "Optional call operator ?.() syntax".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::MethodCall,
                source: r#"
                    const fn = function() { return 'called'; };
                    console.log(fn?.());
                "#
                .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "called\n".to_string(),
                },
            },
            // Optional call on null
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-optional-call-null".to_string(),
                description: "Optional call operator on null/undefined".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::MethodCall,
                source: "const fn = null; console.log(fn?.());".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "undefined\n".to_string(),
                },
            },
            // Complex expression in bracket notation
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-complex-bracket".to_string(),
                description: "Optional chaining with complex bracket expression".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::BracketNotation,
                source: r#"
                    const obj = { 'key-1': 'value1', 'key-2': 'value2' };
                    const n = 1;
                    console.log(obj?.['key-' + n]);
                "#
                .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "value1\n".to_string(),
                },
            },
            // Edge case: number property
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-number-property".to_string(),
                description: "Optional chaining with numeric property".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::EdgeCases,
                source: "const arr = [10, 20, 30]; console.log(arr?.[1]);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "20\n".to_string(),
                },
            },
            // Edge case: symbol property
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-symbol-property".to_string(),
                description: "Optional chaining with symbol property".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Should,
                category: OptionalChainingCategory::EdgeCases,
                source: r#"
                    const sym = Symbol('test');
                    const obj = { [sym]: 'symbol-value' };
                    console.log(obj?.[sym]);
                "#
                .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "symbol-value\n".to_string(),
                },
            },
            // Parentheses grouping
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-parentheses-grouping".to_string(),
                description: "Optional chaining with parentheses grouping".to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::EdgeCases,
                source: r#"
                    const obj = { nested: { value: 42 } };
                    console.log((obj?.nested)?.value);
                "#
                .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "42\n".to_string(),
                },
            },
            // Side effects evaluation
            OptionalChainingTest {
                id: "ES2020-12.3.2.1-side-effects".to_string(),
                description:
                    "Optional chaining side effects are not evaluated when short-circuiting"
                        .to_string(),
                es2020_section: "12.3.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: OptionalChainingCategory::ShortCircuiting,
                source: r#"
                    let called = false;
                    const obj = null;
                    obj?.[called = true];
                    console.log(called);
                "#
                .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "false\n".to_string(),
                },
            },
        ]
    }

    /// Execute optional chaining conformance tests.
    pub fn run_conformance(&self, security_epoch: SecurityEpoch) -> OptionalChainingReport {
        let mut results = BTreeMap::new();
        let mut statistics = ConformanceStatistics::default();

        for test in &self.tests {
            let result = self.execute_test(test, security_epoch);

            match result {
                OptionalChainingResult::Pass => statistics.passed += 1,
                OptionalChainingResult::Fail { .. } => statistics.failed += 1,
                OptionalChainingResult::Error { .. } => statistics.errored += 1,
                OptionalChainingResult::Skip { .. } => statistics.skipped += 1,
            }

            statistics.total_tests += 1;
            results.insert(test.id.clone(), result);
        }

        // Calculate pass rate
        statistics.pass_rate_millionths =
            ratio_millionths(statistics.passed, statistics.total_tests);

        OptionalChainingReport {
            schema_version: OPTIONAL_CHAINING_CONFORMANCE_SCHEMA.to_string(),
            security_epoch,
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_results: results.clone(),
            statistics,
            coverage_by_category: self.calculate_coverage_by_category(&results),
        }
    }

    /// Execute a single optional chaining test.
    ///
    /// FIXED: Now properly compares expected output instead of ignoring it.
    /// Uses shared evaluate_test262_result utility to ensure consistent
    /// conformance validation across all harnesses.
    fn execute_test(
        &self,
        test: &OptionalChainingTest,
        _security_epoch: SecurityEpoch,
    ) -> OptionalChainingResult {
        let mut engine = HybridRouter::default();
        let eval_result = engine.eval(&test.source);

        // Use shared utility for proper output comparison
        let test262_result = evaluate_test262_result(eval_result, &test.expected_result, &test.id);

        // Convert Test262Result to OptionalChainingResult
        match test262_result {
            Test262Result::Pass => OptionalChainingResult::Pass,
            Test262Result::Fail { reason } => OptionalChainingResult::Fail { reason },
            Test262Result::Error { error } => OptionalChainingResult::Error { error },
            Test262Result::Skip { reason } => OptionalChainingResult::Skip { reason },
        }
    }

    /// Calculate coverage by category.
    fn calculate_coverage_by_category(
        &self,
        results: &BTreeMap<String, OptionalChainingResult>,
    ) -> BTreeMap<OptionalChainingCategory, CategoryCoverage> {
        let mut coverage = BTreeMap::new();

        for test in &self.tests {
            let category_coverage = coverage
                .entry(test.category.clone())
                .or_insert_with(CategoryCoverage::default);
            category_coverage.total += 1;

            if let Some(result) = results.get(&test.id)
                && matches!(result, OptionalChainingResult::Pass)
            {
                category_coverage.passed += 1;
            }
        }

        coverage
    }
}

/// Conformance statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConformanceStatistics {
    pub total_tests: u64,
    pub passed: u64,
    pub failed: u64,
    pub errored: u64,
    pub skipped: u64,
    pub pass_rate_millionths: u64,
}

/// Category coverage statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CategoryCoverage {
    pub total: u64,
    pub passed: u64,
}

/// Optional chaining conformance report.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OptionalChainingReport {
    pub schema_version: String,
    pub security_epoch: SecurityEpoch,
    pub timestamp: String,
    pub test_results: BTreeMap<String, OptionalChainingResult>,
    pub statistics: ConformanceStatistics,
    pub coverage_by_category: BTreeMap<OptionalChainingCategory, CategoryCoverage>,
}

fn ratio_millionths(passed: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    ((u128::from(passed) * 1_000_000_u128) / u128::from(total)).min(1_000_000_u128) as u64
}

impl OptionalChainingReport {
    /// Generate human-readable summary.
    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();

        summary.push_str("# Optional Chaining Test262 Conformance Report\n\n");
        summary.push_str(&format!("**Generated:** {}\n", self.timestamp));
        summary.push_str(&format!(
            "**Total Tests:** {}\n",
            self.statistics.total_tests
        ));
        summary.push_str(&format!(
            "**Pass Rate:** {:.1}%\n\n",
            self.statistics.pass_rate_millionths as f64 / 10_000.0
        ));

        summary.push_str("## Coverage by Category\n\n");
        for (category, coverage) in &self.coverage_by_category {
            let pass_rate = if coverage.total > 0 {
                (coverage.passed as f64 / coverage.total as f64) * 100.0
            } else {
                0.0
            };
            summary.push_str(&format!(
                "- **{:?}:** {}/{} ({:.1}%)\n",
                category, coverage.passed, coverage.total, pass_rate
            ));
        }

        summary.push_str("\n## Test Results\n\n");
        for (test_id, result) in &self.test_results {
            match result {
                OptionalChainingResult::Pass => summary.push_str(&format!("✅ {}\n", test_id)),
                OptionalChainingResult::Fail { reason } => {
                    summary.push_str(&format!("❌ {}: {}\n", test_id, reason))
                }
                OptionalChainingResult::Error { error } => {
                    summary.push_str(&format!("🔥 {}: {}\n", test_id, error))
                }
                OptionalChainingResult::Skip { reason } => {
                    summary.push_str(&format!("⏭️ {}: {}\n", test_id, reason))
                }
            }
        }

        summary
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_chaining_harness_creates_comprehensive_suite() {
        let harness = OptionalChainingHarness::new();
        assert!(!harness.tests.is_empty());
        assert!(
            harness.tests.len() >= 15,
            "Should have at least 15 test cases"
        );

        // Verify coverage of all categories
        let categories: std::collections::BTreeSet<_> =
            harness.tests.iter().map(|t| t.category.clone()).collect();

        assert!(categories.contains(&OptionalChainingCategory::PropertyAccess));
        assert!(categories.contains(&OptionalChainingCategory::BracketNotation));
        assert!(categories.contains(&OptionalChainingCategory::MethodCall));
        assert!(categories.contains(&OptionalChainingCategory::ShortCircuiting));
    }

    #[test]
    fn optional_chaining_conformance_execution() {
        let harness = OptionalChainingHarness::new();
        let epoch = SecurityEpoch::from_raw(1);
        let report = harness.run_conformance(epoch);

        assert_eq!(report.security_epoch, epoch);
        assert!(!report.test_results.is_empty());
        assert!(report.statistics.pass_rate_millionths <= 1_000_000);
    }

    #[test]
    fn pass_rate_millionths_saturates_without_overflow() {
        assert_eq!(ratio_millionths(u64::MAX, u64::MAX), 1_000_000);
        assert_eq!(ratio_millionths(u64::MAX, 1), 1_000_000);
        assert_eq!(ratio_millionths(1, 0), 0);
    }

    #[test]
    fn report_types_support_exact_comparison() {
        let harness = OptionalChainingHarness::new();
        let epoch = SecurityEpoch::from_raw(1);
        let report = harness.run_conformance(epoch);

        assert_eq!(report.clone(), report);
        assert_eq!(OptionalChainingResult::Pass, OptionalChainingResult::Pass);
        assert_eq!(
            OptionalChainingCategory::PropertyAccess,
            OptionalChainingCategory::PropertyAccess
        );
    }

    #[test]
    fn must_requirements_coverage() {
        let harness = OptionalChainingHarness::new();

        let must_tests: Vec<_> = harness
            .tests
            .iter()
            .filter(|t| t.requirement_level == RequirementLevel::Must)
            .collect();

        // Most optional chaining requirements are MUST
        assert!(
            must_tests.len() >= 12,
            "Should have at least 12 MUST requirements"
        );
    }

    #[test]
    fn report_generates_summary() {
        let harness = OptionalChainingHarness::new();
        let epoch = SecurityEpoch::from_raw(1);
        let report = harness.run_conformance(epoch);
        let summary = report.generate_summary();

        assert!(summary.contains("Optional Chaining Test262 Conformance Report"));
        assert!(summary.contains("Coverage by Category"));
        assert!(summary.contains("Test Results"));
    }

    // -----------------------------------------------------------------------
    // MUST-tier conformance gates (bd-ifk27)
    //
    // The other tests above check that the harness runs and produces a
    // well-formed report — they do NOT gate on whether the engine actually
    // implements the spec. A regression that drops every MUST-tier ES2020
    // optional-chaining test to Fail would still leave them green, because
    // `pass_rate_millionths <= 1_000_000` is trivially true for any pass rate.
    //
    // The tests below add real teeth:
    //   1. A canonical-cases smoke gate that pins the highest-signal MUST
    //      tests by id and refuses to ship if they regress.
    //   2. A full MUST-tier regression gate driven by an EXPECTED_FAILING_MUSTS
    //      allow-list. Empty by default; populated only with explicit bead
    //      references when the engine has a known semantic gap. The gate
    //      panics both ways: on unexpected failures AND on tests that start
    //      passing without the list being updated.
    // -----------------------------------------------------------------------

    /// Canonical MUST-tier optional-chaining cases that the engine MUST keep
    /// passing — the floor below which `?.` is fundamentally broken.
    ///
    /// Unlike EXPECTED_FAILING_MUSTS below, these entries have no waiver
    /// mechanism. A regression here is a P0; the engine has lost the
    /// short-circuit semantics that gate every other optional-chaining case.
    ///
    /// The list is intentionally narrow: it pins the null/undefined short-
    /// circuit paths that currently work, not the resolution paths still
    /// blocked on bd-itxl9. As bd-itxl9 is resolved, basic-property-access
    /// and basic-bracket-access should be promoted here.
    const CANONICAL_MUST_IDS: &[&str] = &[
        "ES2020-12.3.2.1-property-access-null",
        "ES2020-12.3.2.1-property-access-undefined",
        "ES2020-12.3.2.1-bracket-access-null",
        "ES2020-12.3.2.1-short-circuit",
    ];

    /// Allow-listed MUST-tier failures with their tracking bead references.
    ///
    /// Each entry MUST cite an open bead documenting the semantic gap. The
    /// allow-list is "pinned": a test entering the list because of a real
    /// regression will fail the next push (since the bead reference will be
    /// missing); a test passing again will also fail (forcing list cleanup),
    /// keeping the list honest.
    ///
    /// bd-itxl9 drained the original 12 entries: 11 of them were the Test262
    /// helper comparing `outcome.value` (eval-completion value — `undefined`
    /// for `console.log(...)` programs) against the printed-output expected
    /// strings (e.g. "42\n"), so every console.log fixture spuriously failed.
    /// The 12th (method-call-null) was a real engine gap — `obj?.method()`
    /// with a null receiver threw a TypeError instead of short-circuiting per
    /// ES2020 §12.3.2.1. Both are fixed; this allow-list is intentionally
    /// empty.
    const EXPECTED_FAILING_MUSTS: &[(&str, &str)] = &[];

    fn must_tests(harness: &OptionalChainingHarness) -> Vec<&OptionalChainingTest> {
        harness
            .tests
            .iter()
            .filter(|t| t.requirement_level == RequirementLevel::Must)
            .collect()
    }

    #[test]
    fn optional_chaining_canonical_must_cases_pass() {
        let harness = OptionalChainingHarness::new();
        let report = harness.run_conformance(SecurityEpoch::from_raw(1));

        // Sanity: every canonical id actually exists in the suite (guards
        // against renames silently dropping coverage).
        let suite_ids: std::collections::BTreeSet<&str> =
            harness.tests.iter().map(|t| t.id.as_str()).collect();
        for id in CANONICAL_MUST_IDS {
            assert!(
                suite_ids.contains(*id),
                "canonical MUST id `{id}` is no longer present in the optional-chaining suite; \
                 update CANONICAL_MUST_IDS or restore the test case",
            );
        }

        let mut failures: Vec<String> = Vec::new();
        for id in CANONICAL_MUST_IDS {
            match report.test_results.get(*id) {
                Some(OptionalChainingResult::Pass) => {}
                Some(other) => failures.push(format!("{id}: {other:?}")),
                None => failures.push(format!("{id}: <missing result>")),
            }
        }

        assert!(
            failures.is_empty(),
            "Canonical MUST-tier optional-chaining cases regressed ({} of {} failed):\n  {}\n\n\
             These cases gate the ES2020 §12.3.2.1 baseline; any failure here means the engine \
             no longer implements `?.` correctly for trivial inputs.",
            failures.len(),
            CANONICAL_MUST_IDS.len(),
            failures.join("\n  "),
        );
    }

    #[test]
    fn optional_chaining_must_tier_has_no_unexpected_regressions() {
        let harness = OptionalChainingHarness::new();
        let report = harness.run_conformance(SecurityEpoch::from_raw(1));
        let allow: std::collections::BTreeMap<&str, &str> =
            EXPECTED_FAILING_MUSTS.iter().copied().collect();

        // Every entry in EXPECTED_FAILING_MUSTS must reference a real MUST id
        // in the suite — prevents stale waivers outliving the test.
        let must_ids: std::collections::BTreeSet<&str> =
            must_tests(&harness).iter().map(|t| t.id.as_str()).collect();
        for (waived_id, bead) in allow.iter() {
            assert!(
                must_ids.contains(*waived_id),
                "EXPECTED_FAILING_MUSTS waiver references unknown id `{waived_id}`; \
                 remove the entry or update the test id",
            );
            assert!(
                bead.starts_with("bd-") && bead.len() > 3,
                "EXPECTED_FAILING_MUSTS entry for `{waived_id}` is missing a bead reference \
                 (got `{bead}`); every waiver must point at a tracking bead",
            );
        }

        let mut unexpected_failures: Vec<(String, OptionalChainingResult)> = Vec::new();
        let mut unexpected_passes: Vec<String> = Vec::new();
        for test in must_tests(&harness) {
            let result = report
                .test_results
                .get(&test.id)
                .cloned()
                .unwrap_or_else(|| OptionalChainingResult::Error {
                    error: "<missing result in report>".to_string(),
                });
            let waived = allow.contains_key(test.id.as_str());
            match (&result, waived) {
                (OptionalChainingResult::Pass, false) => {}
                (OptionalChainingResult::Pass, true) => unexpected_passes.push(test.id.clone()),
                (_, true) => {} // expected failure
                (other, false) => unexpected_failures.push((test.id.clone(), other.clone())),
            }
        }

        assert!(
            unexpected_failures.is_empty(),
            "{} MUST-tier optional-chaining test(s) regressed unexpectedly. Either fix the engine \
             or add an explicit waiver to EXPECTED_FAILING_MUSTS with a tracking bead id:\n  {}",
            unexpected_failures.len(),
            unexpected_failures
                .iter()
                .map(|(id, r)| format!("{id}: {r:?}"))
                .collect::<Vec<_>>()
                .join("\n  "),
        );
        assert!(
            unexpected_passes.is_empty(),
            "{} MUST-tier test(s) waived in EXPECTED_FAILING_MUSTS now pass — remove their entries:\n  {}",
            unexpected_passes.len(),
            unexpected_passes.join("\n  "),
        );
    }
}
