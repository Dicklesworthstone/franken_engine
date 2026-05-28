#![forbid(unsafe_code)]

//! Arrow Function Test262 Conformance Harness
//!
//! Targets Test262 conformance gaps in ES2020 arrow function syntax (Chapter 14).
//! Current pass rate: 55% in function expressions - this harness addresses
//! specific arrow function edge cases missing from franken_engine coverage.
//!
//! Focus areas: parameter destructuring, default parameters, rest parameters,
//! async arrow functions, lexical scope binding, and syntax edge cases.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod _support;
use _support::test262_common::{
    ExpectedResult, RequirementLevel, Test262Result, assert_report_json_round_trips,
    evaluate_test262_result,
};

// ---------------------------------------------------------------------------
// Test262 Arrow Function Conformance Suite
// ---------------------------------------------------------------------------

/// Schema version for arrow function conformance reports.
pub const ARROW_FUNCTION_CONFORMANCE_SCHEMA: &str = "franken-engine.arrow-function-test262.v1";

/// Test result classification for arrow function conformance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArrowFunctionResult {
    /// Test passed - behavior matches ES2020 spec
    Pass,
    /// Test failed - behavior diverges from ES2020 spec
    Fail { reason: String },
    /// Test execution error - franken_engine failed to execute
    Error { error: String },
    /// Test skipped - known limitation or unsupported syntax
    Skip { reason: String },
}

// RequirementLevel now imported from shared module

/// Arrow function test category for gap analysis.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ArrowFunctionCategory {
    /// Basic arrow function syntax
    BasicSyntax,
    /// Parameter destructuring
    ParameterDestructuring,
    /// Default parameters
    DefaultParameters,
    /// Rest parameters
    RestParameters,
    /// Async arrow functions
    AsyncArrowFunctions,
    /// Lexical this binding
    LexicalBinding,
    /// Expression vs block body
    BodySyntax,
    /// Parsing edge cases
    EdgeCases,
}

/// Individual arrow function conformance test case.
#[derive(Debug, Clone)]
pub struct ArrowFunctionTest {
    pub id: String,
    pub description: String,
    pub es2020_section: String,
    pub requirement_level: RequirementLevel,
    pub category: ArrowFunctionCategory,
    pub source: String,
    pub expected_result: ExpectedResult,
}

// ExpectedResult now imported from shared module

/// Arrow function conformance test harness.
pub struct ArrowFunctionHarness {
    tests: Vec<ArrowFunctionTest>,
}

impl Default for ArrowFunctionHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl ArrowFunctionHarness {
    pub fn new() -> Self {
        Self {
            tests: Self::create_arrow_function_tests(),
        }
    }

    /// Create focused test262 arrow function test cases.
    fn create_arrow_function_tests() -> Vec<ArrowFunctionTest> {
        vec![
            // Basic arrow function syntax
            ArrowFunctionTest {
                id: "ES2020-14.2.1-basic-arrow".to_string(),
                description: "Basic arrow function expression".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::BasicSyntax,
                source: "const f = x => x * 2; console.log(f(5));".to_string(),
                expected_result: ExpectedResult::Success { output: "10\n".to_string() },
            },

            // Parentheses around single parameter
            ArrowFunctionTest {
                id: "ES2020-14.2.1-single-param-parens".to_string(),
                description: "Arrow function with parentheses around single parameter".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::BasicSyntax,
                source: "const f = (x) => x + 1; console.log(f(3));".to_string(),
                expected_result: ExpectedResult::Success { output: "4\n".to_string() },
            },

            // Multiple parameters
            ArrowFunctionTest {
                id: "ES2020-14.2.1-multiple-params".to_string(),
                description: "Arrow function with multiple parameters".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::BasicSyntax,
                source: "const add = (a, b) => a + b; console.log(add(2, 3));".to_string(),
                expected_result: ExpectedResult::Success { output: "5\n".to_string() },
            },

            // Block body vs expression body
            ArrowFunctionTest {
                id: "ES2020-14.2.1-block-body".to_string(),
                description: "Arrow function with block body requires explicit return".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::BodySyntax,
                source: "const f = x => { return x * 3; }; console.log(f(4));".to_string(),
                expected_result: ExpectedResult::Success { output: "12\n".to_string() },
            },

            // Block body without return
            ArrowFunctionTest {
                id: "ES2020-14.2.1-block-body-no-return".to_string(),
                description: "Arrow function block body without return returns undefined".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::BodySyntax,
                source: "const f = x => { x * 3; }; console.log(f(4));".to_string(),
                expected_result: ExpectedResult::Success { output: "undefined\n".to_string() },
            },

            // Default parameters
            ArrowFunctionTest {
                id: "ES2020-14.1.19-default-params".to_string(),
                description: "Arrow function with default parameters".to_string(),
                es2020_section: "14.1.19".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::DefaultParameters,
                source: "const greet = (name = 'World') => `Hello, ${name}!`; console.log(greet());".to_string(),
                expected_result: ExpectedResult::Success { output: "Hello, World!\n".to_string() },
            },

            // Default parameters with explicit argument
            ArrowFunctionTest {
                id: "ES2020-14.1.19-default-params-override".to_string(),
                description: "Arrow function default parameter overridden by explicit argument".to_string(),
                es2020_section: "14.1.19".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::DefaultParameters,
                source: "const greet = (name = 'World') => `Hello, ${name}!`; console.log(greet('Alice'));".to_string(),
                expected_result: ExpectedResult::Success { output: "Hello, Alice!\n".to_string() },
            },

            // Rest parameters
            ArrowFunctionTest {
                id: "ES2020-14.1.20-rest-params".to_string(),
                description: "Arrow function with rest parameters".to_string(),
                es2020_section: "14.1.20".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::RestParameters,
                source: "const sum = (...numbers) => numbers.reduce((a, b) => a + b, 0); console.log(sum(1, 2, 3, 4));".to_string(),
                expected_result: ExpectedResult::Success { output: "10\n".to_string() },
            },

            // Parameter destructuring - array
            ArrowFunctionTest {
                id: "ES2020-13.3.3-array-destructuring".to_string(),
                description: "Arrow function with array destructuring parameters".to_string(),
                es2020_section: "13.3.3".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::ParameterDestructuring,
                source: "const getFirst = ([first]) => first; console.log(getFirst([1, 2, 3]));".to_string(),
                expected_result: ExpectedResult::Success { output: "1\n".to_string() },
            },

            // Parameter destructuring - object
            ArrowFunctionTest {
                id: "ES2020-13.3.3-object-destructuring".to_string(),
                description: "Arrow function with object destructuring parameters".to_string(),
                es2020_section: "13.3.3".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::ParameterDestructuring,
                source: "const getName = ({name}) => name; console.log(getName({name: 'Bob', age: 30}));".to_string(),
                expected_result: ExpectedResult::Success { output: "Bob\n".to_string() },
            },

            // Async arrow functions
            ArrowFunctionTest {
                id: "ES2020-14.7-async-arrow".to_string(),
                description: "Async arrow function basic syntax".to_string(),
                es2020_section: "14.7".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::AsyncArrowFunctions,
                source: "const asyncFn = async () => 42; asyncFn().then(console.log);".to_string(),
                expected_result: ExpectedResult::Success { output: "42\n".to_string() },
            },

            // Async arrow with parameters
            ArrowFunctionTest {
                id: "ES2020-14.7-async-arrow-params".to_string(),
                description: "Async arrow function with parameters".to_string(),
                es2020_section: "14.7".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::AsyncArrowFunctions,
                source: "const asyncAdd = async (a, b) => a + b; asyncAdd(3, 4).then(console.log);".to_string(),
                expected_result: ExpectedResult::Success { output: "7\n".to_string() },
            },

            // Lexical this binding
            ArrowFunctionTest {
                id: "ES2020-14.2.16-lexical-this".to_string(),
                description: "Arrow function lexical this binding".to_string(),
                es2020_section: "14.2.16".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::LexicalBinding,
                source: r#"
                    function Counter() {
                        this.count = 0;
                        this.increment = () => this.count++;
                    }
                    const c = new Counter();
                    c.increment();
                    console.log(c.count);
                "#.to_string(),
                expected_result: ExpectedResult::Success { output: "1\n".to_string() },
            },

            // Arrow function in method call
            ArrowFunctionTest {
                id: "ES2020-14.2.16-arrow-in-method".to_string(),
                description: "Arrow function preserves lexical this in method context".to_string(),
                es2020_section: "14.2.16".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::LexicalBinding,
                source: r#"
                    const obj = {
                        value: 10,
                        getValue() {
                            const arrow = () => this.value;
                            return arrow();
                        }
                    };
                    console.log(obj.getValue());
                "#.to_string(),
                expected_result: ExpectedResult::Success { output: "10\n".to_string() },
            },

            // Syntax error cases
            ArrowFunctionTest {
                id: "ES2020-14.2.1-syntax-error-duplicate-params".to_string(),
                description: "Arrow function with duplicate parameter names should be syntax error".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::EdgeCases,
                source: "const f = (a, a) => a + a;".to_string(),
                expected_result: ExpectedResult::SyntaxError { error_type: "SyntaxError".to_string() },
            },

            // bd-vj6kn (FIND-9): expand error-case coverage. The harness
            // imported ExpectedResult::SyntaxError but only exercised it once
            // (duplicate-params above). These three add the other classic
            // arrow-function parse errors ES2020 specifies. Each is registered
            // in KNOWN_ARROW_FUNCTION_GAPS below until the parser rejects them,
            // so the harness exercises the SyntaxError code path without
            // turning the gate red on a known engine gap.
            ArrowFunctionTest {
                id: "ES2020-14.1.20-syntax-error-rest-not-last".to_string(),
                description: "Rest parameter must be the last formal parameter (ES2020 §14.1.2 / Annex B)".to_string(),
                es2020_section: "14.1.20".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::EdgeCases,
                source: "const f = (...rest, last) => last;".to_string(),
                expected_result: ExpectedResult::SyntaxError { error_type: "SyntaxError".to_string() },
            },
            ArrowFunctionTest {
                id: "ES2020-14.2.1-syntax-error-yield-in-arrow".to_string(),
                description: "yield expression inside a non-generator arrow body is a SyntaxError".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::EdgeCases,
                source: "const f = () => { yield 1; };".to_string(),
                expected_result: ExpectedResult::SyntaxError { error_type: "SyntaxError".to_string() },
            },
            ArrowFunctionTest {
                id: "ES2020-14.2.1-syntax-error-await-in-non-async-arrow".to_string(),
                description: "await expression inside a non-async arrow body is a SyntaxError".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::EdgeCases,
                source: "const f = (x) => await x;".to_string(),
                expected_result: ExpectedResult::SyntaxError { error_type: "SyntaxError".to_string() },
            },

            // No parameters require parentheses
            ArrowFunctionTest {
                id: "ES2020-14.2.1-no-params".to_string(),
                description: "Arrow function with no parameters requires parentheses".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::BasicSyntax,
                source: "const f = () => 42; console.log(f());".to_string(),
                expected_result: ExpectedResult::Success { output: "42\n".to_string() },
            },

            // Object literal in expression body
            ArrowFunctionTest {
                id: "ES2020-14.2.1-object-literal-expression".to_string(),
                description: "Arrow function returning object literal requires parentheses".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::EdgeCases,
                source: "const makeObj = () => ({ key: 'value' }); console.log(makeObj().key);".to_string(),
                expected_result: ExpectedResult::Success { output: "value\n".to_string() },
            },

            // Nested arrow functions
            ArrowFunctionTest {
                id: "ES2020-14.2.1-nested-arrows".to_string(),
                description: "Nested arrow functions".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::EdgeCases,
                source: "const add = x => y => x + y; console.log(add(3)(4));".to_string(),
                expected_result: ExpectedResult::Success { output: "7\n".to_string() },
            },

            // Arrow function as IIFE
            ArrowFunctionTest {
                id: "ES2020-14.2.1-arrow-iife".to_string(),
                description: "Arrow function as immediately invoked function expression".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::EdgeCases,
                source: "console.log(((x) => x * 2)(5));".to_string(),
                expected_result: ExpectedResult::Success { output: "10\n".to_string() },
            },

            // Template literal in arrow body
            ArrowFunctionTest {
                id: "ES2020-14.2.1-template-literal".to_string(),
                description: "Arrow function with template literal expression body".to_string(),
                es2020_section: "14.2.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: ArrowFunctionCategory::BasicSyntax,
                source: "const greet = name => `Hello, ${name}!`; console.log(greet('Test'));".to_string(),
                expected_result: ExpectedResult::Success { output: "Hello, Test!\n".to_string() },
            },
        ]
    }

    /// Execute arrow function conformance tests.
    pub fn run_conformance(&self, security_epoch: SecurityEpoch) -> ArrowFunctionReport {
        let mut results = BTreeMap::new();
        let mut statistics = ConformanceStatistics::default();

        for test in &self.tests {
            let result = self.execute_test(test, security_epoch);

            match result {
                ArrowFunctionResult::Pass => statistics.passed += 1,
                ArrowFunctionResult::Fail { .. } => statistics.failed += 1,
                ArrowFunctionResult::Error { .. } => statistics.errored += 1,
                ArrowFunctionResult::Skip { .. } => statistics.skipped += 1,
            }

            statistics.total_tests += 1;
            results.insert(test.id.clone(), result);
        }

        // Calculate pass rate
        statistics.pass_rate_millionths = (statistics.passed * 1_000_000)
            .checked_div(statistics.total_tests)
            .unwrap_or(0);

        ArrowFunctionReport {
            schema_version: ARROW_FUNCTION_CONFORMANCE_SCHEMA.to_string(),
            security_epoch,
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_results: results.clone(),
            statistics,
            coverage_by_category: self.calculate_coverage_by_category(&results),
        }
    }

    /// Execute a single arrow function test.
    ///
    /// FIXED: Now properly compares expected output instead of ignoring it.
    /// Uses shared evaluate_test262_result utility to ensure consistent
    /// conformance validation across all harnesses.
    fn execute_test(
        &self,
        test: &ArrowFunctionTest,
        _security_epoch: SecurityEpoch,
    ) -> ArrowFunctionResult {
        let mut engine = HybridRouter::default();
        let eval_result = engine.eval(&test.source);

        // Use shared utility for proper output comparison
        let test262_result = evaluate_test262_result(eval_result, &test.expected_result, &test.id);

        // Convert Test262Result to ArrowFunctionResult
        match test262_result {
            Test262Result::Pass => ArrowFunctionResult::Pass,
            Test262Result::Fail { reason } => ArrowFunctionResult::Fail { reason },
            Test262Result::Error { error } => ArrowFunctionResult::Error { error },
            Test262Result::Skip { reason } => ArrowFunctionResult::Skip { reason },
        }
    }

    /// Calculate coverage by category.
    fn calculate_coverage_by_category(
        &self,
        results: &BTreeMap<String, ArrowFunctionResult>,
    ) -> BTreeMap<ArrowFunctionCategory, CategoryCoverage> {
        let mut coverage: BTreeMap<ArrowFunctionCategory, CategoryCoverage> = BTreeMap::new();

        for test in &self.tests {
            let category_coverage = coverage.entry(test.category.clone()).or_default();
            category_coverage.total += 1;

            if let Some(result) = results.get(&test.id)
                && matches!(result, ArrowFunctionResult::Pass)
            {
                category_coverage.passed += 1;
            }
        }

        coverage
    }
}

/// Conformance statistics.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ConformanceStatistics {
    pub total_tests: u64,
    pub passed: u64,
    pub failed: u64,
    pub errored: u64,
    pub skipped: u64,
    pub pass_rate_millionths: u64,
}

/// Category coverage statistics.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CategoryCoverage {
    pub total: u64,
    pub passed: u64,
}

/// Arrow function conformance report.
#[derive(Debug, Serialize, Deserialize)]
pub struct ArrowFunctionReport {
    pub schema_version: String,
    pub security_epoch: SecurityEpoch,
    pub timestamp: String,
    pub test_results: BTreeMap<String, ArrowFunctionResult>,
    pub statistics: ConformanceStatistics,
    pub coverage_by_category: BTreeMap<ArrowFunctionCategory, CategoryCoverage>,
}

impl ArrowFunctionReport {
    /// Generate human-readable summary.
    pub fn generate_summary(&self) -> String {
        let mut summary = String::new();

        summary.push_str("# Arrow Function Test262 Conformance Report\n\n");
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
                ArrowFunctionResult::Pass => summary.push_str(&format!("✅ {}\n", test_id)),
                ArrowFunctionResult::Fail { reason } => {
                    summary.push_str(&format!("❌ {}: {}\n", test_id, reason))
                }
                ArrowFunctionResult::Error { error } => {
                    summary.push_str(&format!("🔥 {}: {}\n", test_id, error))
                }
                ArrowFunctionResult::Skip { reason } => {
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

    /// Arrow-function test262 case ids the engine currently FAILS (bd-bg9l1.13).
    /// Freezing the exact divergence set turns the prior `pass_rate <= 100%`
    /// tautology — which a total regression would have survived — into a real
    /// gate: a newly failing id fails fast, and a fixed id also fails (forcing
    /// this list to be pruned). These are genuine ES2020 arrow-function
    /// conformance gaps surfaced by the audit; closing them is tracked under the
    /// bd-bg9l1 epic. The harness was passing green at only ~60% pass rate.
    const KNOWN_ARROW_FUNCTION_GAPS: &[&str] = &[
        "ES2020-13.3.3-array-destructuring",
        "ES2020-13.3.3-object-destructuring",
        "ES2020-14.1.19-default-params",
        "ES2020-14.1.19-default-params-override",
        "ES2020-14.1.20-rest-params",
        // bd-vj6kn (FIND-9): three newly-added SyntaxError cases. Listed here
        // until the parser rejects them so the drift detector treats them as
        // known engine gaps rather than failing the gate. Remove from this
        // list when the parser starts emitting the expected SyntaxError.
        "ES2020-14.1.20-syntax-error-rest-not-last",
        "ES2020-14.2.1-syntax-error-await-in-non-async-arrow",
        "ES2020-14.2.1-syntax-error-duplicate-params",
        "ES2020-14.2.1-syntax-error-yield-in-arrow",
        "ES2020-14.2.16-arrow-in-method",
        "ES2020-14.2.16-lexical-this",
        "ES2020-14.7-async-arrow",
        "ES2020-14.7-async-arrow-params",
    ];

    #[test]
    fn arrow_function_harness_creates_comprehensive_suite() {
        let harness = ArrowFunctionHarness::new();
        assert!(!harness.tests.is_empty());
        assert!(
            harness.tests.len() >= 20,
            "Should have at least 20 test cases"
        );

        // bd-ab9ty (follow-up to bd-s2ubw / FIND-15): every case must
        // declare its ES2020 § anchor; without this assertion an
        // empty/missing tag can land silently and the spec-section
        // coverage report under-counts.
        for test in &harness.tests {
            assert!(
                !test.es2020_section.is_empty(),
                "case es2020_section must be non-empty (case id: {})",
                test.id
            );
        }

        // Verify coverage of all categories
        let categories: std::collections::BTreeSet<_> =
            harness.tests.iter().map(|t| t.category.clone()).collect();

        assert!(categories.contains(&ArrowFunctionCategory::BasicSyntax));
        assert!(categories.contains(&ArrowFunctionCategory::DefaultParameters));
        assert!(categories.contains(&ArrowFunctionCategory::RestParameters));
        assert!(categories.contains(&ArrowFunctionCategory::ParameterDestructuring));
    }

    #[test]
    fn arrow_function_conformance_execution() {
        let harness = ArrowFunctionHarness::new();
        let epoch = SecurityEpoch::from_raw(1);
        let report = harness.run_conformance(epoch);

        assert_eq!(report.security_epoch, epoch);
        assert!(!report.test_results.is_empty());

        // Real correctness gate (bd-bg9l1.13): the engine may diverge only on
        // ids catalogued in KNOWN_ARROW_FUNCTION_GAPS. Drift in either
        // direction fails, unlike the prior `pass_rate <= 1_000_000` tautology.
        let mut observed_detail: Vec<(String, String)> = Vec::new();
        for (id, result) in &report.test_results {
            match result {
                ArrowFunctionResult::Pass => {}
                ArrowFunctionResult::Fail { reason } => {
                    observed_detail.push((id.clone(), format!("fail: {reason}")))
                }
                ArrowFunctionResult::Error { error } => {
                    observed_detail.push((id.clone(), format!("error: {error}")))
                }
                ArrowFunctionResult::Skip { reason } => {
                    observed_detail.push((id.clone(), format!("skip: {reason}")))
                }
            }
        }
        let observed: std::collections::BTreeSet<&str> =
            observed_detail.iter().map(|(id, _)| id.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> =
            KNOWN_ARROW_FUNCTION_GAPS.iter().copied().collect();
        assert_eq!(
            observed, expected,
            "arrow-function gap set drifted from KNOWN_ARROW_FUNCTION_GAPS \
             (bd-bg9l1.13). If a gap closed, remove it from the constant. If a \
             new gap opened, file or extend a follow-up bead before silencing \
             it. Observed gaps with detail:\n{observed_detail:#?}"
        );
    }

    #[test]
    fn arrow_function_harness_fails_on_expected_output_mismatch() {
        let harness = ArrowFunctionHarness { tests: Vec::new() };
        let test = ArrowFunctionTest {
            id: "regression-output-mismatch".to_string(),
            description: "Expected output mismatch must fail conformance".to_string(),
            es2020_section: "14.2.1".to_string(),
            requirement_level: RequirementLevel::Must,
            category: ArrowFunctionCategory::BasicSyntax,
            source: "console.log(1);".to_string(),
            expected_result: ExpectedResult::Success {
                output: "2\n".to_string(),
            },
        };

        let result = harness.execute_test(&test, SecurityEpoch::from_raw(1));

        match result {
            ArrowFunctionResult::Fail { reason } => {
                assert!(reason.contains("Output mismatch"));
                assert!(reason.contains("regression-output-mismatch"));
            }
            other => panic!("expected output mismatch to fail, got {other:?}"),
        }
    }

    #[test]
    fn must_requirements_are_present() {
        let harness = ArrowFunctionHarness::new();

        let must_tests: Vec<_> = harness
            .tests
            .iter()
            .filter(|t| t.requirement_level == RequirementLevel::Must)
            .collect();

        // Most arrow function requirements are MUST
        assert!(
            must_tests.len() >= 15,
            "Should have at least 15 MUST requirements"
        );
    }

    #[test]
    fn report_generates_summary() {
        let harness = ArrowFunctionHarness::new();
        let epoch = SecurityEpoch::from_raw(1);
        let report = harness.run_conformance(epoch);
        let summary = report.generate_summary();

        assert!(summary.contains("Arrow Function Test262 Conformance Report"));
        assert!(summary.contains("Coverage by Category"));
        assert!(summary.contains("Test Results"));
    }

    /// bd-rqev5 (FIND-10): every conformance harness must prove its report
    /// survives a serde_json round-trip and carries the canonical schema pin.
    #[test]
    fn report_round_trips_through_serde_json() {
        let harness = ArrowFunctionHarness::new();
        let report = harness.run_conformance(SecurityEpoch::from_raw(3));
        assert_report_json_round_trips(
            &report,
            ARROW_FUNCTION_CONFORMANCE_SCHEMA,
            &report.schema_version,
        );
    }
}
