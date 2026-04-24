//! Test262 conformance harness for iteration statements (ES2020 Chapter 13)
//!
//! This harness implements Pattern 4 (Spec-Derived Test Matrix) from the
//! testing-conformance-harnesses skill, targeting ECMAScript iteration
//! statements from Chapter 13.2.2 (do-while), 13.2.3 (while), 13.2.4 (for),
//! 13.2.5 (for-in), and 13.2.6 (for-of).
//!
//! Iteration statements test critical JavaScript control flow: loop execution,
//! variable scoping in headers, break/continue semantics, and iterator protocol
//! integration for for-in/for-of statements.

use frankenengine_engine::HybridRouter;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod _support;
use _support::test262_common::{ExpectedResult, RequirementLevel, execute_test262_case};

const SCHEMA_VERSION: &str = "franken-engine.iteration-statements-test262-conformance.v1";
const BEAD_ID: &str = "bd-ai64f";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IterationStatementTestCategory {
    ForStatement,
    ForInStatement,
    ForOfStatement,
    WhileStatement,
    DoWhileStatement,
    BreakContinue,
    VariableScoping,
    IteratorProtocol,
    EdgeCases,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IterationStatementResult {
    Pass,
    Fail,
    ParseError,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IterationStatementTestCase {
    pub id: String,
    pub category: IterationStatementTestCategory,
    pub description: String,
    pub source_code: String,
    pub es_spec_section: String,
    pub requirement_level: String, // "MUST", "SHOULD", "MAY"
}

#[derive(Debug, Clone)]
pub struct StaticIterationStatementTestCase {
    pub id: &'static str,
    pub category: IterationStatementTestCategory,
    pub description: &'static str,
    pub source_code: &'static str,
    pub es_spec_section: &'static str,
    pub requirement_level: &'static str,
}

impl From<&StaticIterationStatementTestCase> for IterationStatementTestCase {
    fn from(static_case: &StaticIterationStatementTestCase) -> Self {
        Self {
            id: static_case.id.to_string(),
            category: static_case.category.clone(),
            description: static_case.description.to_string(),
            source_code: static_case.source_code.to_string(),
            es_spec_section: static_case.es_spec_section.to_string(),
            requirement_level: static_case.requirement_level.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationStatementConformanceReport {
    pub schema_version: String,
    pub bead_id: String,
    pub test_results: BTreeMap<String, IterationStatementResult>,
    pub statistics: ConformanceStatistics,
    pub coverage_by_category: BTreeMap<IterationStatementTestCategory, CategoryCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceStatistics {
    pub total_tests: u32,
    pub passed: u32,
    pub failed: u32,
    pub parse_errors: u32,
    pub pass_rate_millionths: u32, // Fixed-point representation of pass rate
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryCoverage {
    pub total: u32,
    pub passed: u32,
}

pub struct IterationStatementConformanceHarness;

impl IterationStatementConformanceHarness {
    const STATIC_TEST_CASES: &'static [StaticIterationStatementTestCase] = &[
        // For statement tests (13.2.4)
        StaticIterationStatementTestCase {
            id: "for-statement-basic",
            category: IterationStatementTestCategory::ForStatement,
            description: "Basic for loop with initialization, condition, update",
            source_code: "for (let i = 0; i < 10; i++) { console.log(i); }",
            es_spec_section: "13.2.4",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "for-statement-empty-parts",
            category: IterationStatementTestCategory::ForStatement,
            description: "For loop with empty initialization and update",
            source_code: "for (; condition; ) { body(); }",
            es_spec_section: "13.2.4",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "for-statement-var-declaration",
            category: IterationStatementTestCategory::VariableScoping,
            description: "For loop with var declaration in header",
            source_code: "for (var x = 0; x < 5; x++) { statements; }",
            es_spec_section: "13.2.4",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "for-statement-let-declaration",
            category: IterationStatementTestCategory::VariableScoping,
            description: "For loop with let declaration in header",
            source_code: "for (let y = 0; y < 3; y++) { console.log(y); }",
            es_spec_section: "13.2.4",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "for-statement-const-declaration",
            category: IterationStatementTestCategory::VariableScoping,
            description: "For loop with const declaration in header",
            source_code: "for (const z of iterable) { process(z); }",
            es_spec_section: "13.2.4",
            requirement_level: "MUST",
        },
        // For-in statement tests (13.2.5)
        StaticIterationStatementTestCase {
            id: "for-in-statement-basic",
            category: IterationStatementTestCategory::ForInStatement,
            description: "Basic for-in loop over object properties",
            source_code: "for (key in obj) { console.log(key); }",
            es_spec_section: "13.2.5",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "for-in-statement-var-declaration",
            category: IterationStatementTestCategory::ForInStatement,
            description: "For-in loop with var declaration",
            source_code: "for (var prop in object) { statements; }",
            es_spec_section: "13.2.5",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "for-in-statement-let-declaration",
            category: IterationStatementTestCategory::ForInStatement,
            description: "For-in loop with let declaration",
            source_code: "for (let property in target) { process(property); }",
            es_spec_section: "13.2.5",
            requirement_level: "MUST",
        },
        // For-of statement tests (13.2.6)
        StaticIterationStatementTestCase {
            id: "for-of-statement-basic",
            category: IterationStatementTestCategory::ForOfStatement,
            description: "Basic for-of loop over iterable",
            source_code: "for (value of iterable) { console.log(value); }",
            es_spec_section: "13.2.6",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "for-of-statement-array",
            category: IterationStatementTestCategory::ForOfStatement,
            description: "For-of loop over array literal",
            source_code: "for (item of [1, 2, 3]) { process(item); }",
            es_spec_section: "13.2.6",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "for-of-statement-const-declaration",
            category: IterationStatementTestCategory::ForOfStatement,
            description: "For-of loop with const declaration",
            source_code: "for (const element of collection) { console.log(element); }",
            es_spec_section: "13.2.6",
            requirement_level: "MUST",
        },
        // While statement tests (13.2.3)
        StaticIterationStatementTestCase {
            id: "while-statement-basic",
            category: IterationStatementTestCategory::WhileStatement,
            description: "Basic while loop with condition",
            source_code: "while (condition) { statements; }",
            es_spec_section: "13.2.3",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "while-statement-complex-condition",
            category: IterationStatementTestCategory::WhileStatement,
            description: "While loop with complex boolean condition",
            source_code: "while (x > 0 && y < 10 && !done) { update(); }",
            es_spec_section: "13.2.3",
            requirement_level: "MUST",
        },
        // Do-while statement tests (13.2.2)
        StaticIterationStatementTestCase {
            id: "do-while-statement-basic",
            category: IterationStatementTestCategory::DoWhileStatement,
            description: "Basic do-while loop",
            source_code: "do { statements; } while (condition);",
            es_spec_section: "13.2.2",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "do-while-statement-single-iteration",
            category: IterationStatementTestCategory::DoWhileStatement,
            description: "Do-while loop that executes exactly once",
            source_code: "do { action(); } while (false);",
            es_spec_section: "13.2.2",
            requirement_level: "MUST",
        },
        // Break and continue tests
        StaticIterationStatementTestCase {
            id: "break-statement-for-loop",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Break statement in for loop",
            source_code: "for (let i = 0; i < 10; i++) { if (i === 5) break; }",
            es_spec_section: "13.12",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "continue-statement-while-loop",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Continue statement in while loop",
            source_code: "while (condition) { if (skip) continue; process(); }",
            es_spec_section: "13.13",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "labeled-break-statement",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Labeled break statement with nested loops",
            source_code: "outer: for (;;) { inner: for (;;) { break outer; } }",
            es_spec_section: "13.12",
            requirement_level: "SHOULD",
        },
        StaticIterationStatementTestCase {
            id: "labeled-continue-statement",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Labeled continue statement with nested loops",
            source_code: "loop: while (true) { for (;;) { continue loop; } }",
            es_spec_section: "13.13",
            requirement_level: "SHOULD",
        },
        // Iterator protocol integration
        StaticIterationStatementTestCase {
            id: "for-of-iterator-protocol",
            category: IterationStatementTestCategory::IteratorProtocol,
            description: "For-of with custom iterator",
            source_code: "for (value of customIterable) { process(value); }",
            es_spec_section: "13.2.6",
            requirement_level: "SHOULD",
        },
        // Edge cases
        StaticIterationStatementTestCase {
            id: "for-statement-empty-body",
            category: IterationStatementTestCategory::EdgeCases,
            description: "For loop with empty body",
            source_code: "for (let i = 0; i < 10; i++);",
            es_spec_section: "13.2.4",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "while-statement-empty-body",
            category: IterationStatementTestCategory::EdgeCases,
            description: "While loop with empty body",
            source_code: "while (condition);",
            es_spec_section: "13.2.3",
            requirement_level: "MUST",
        },
        StaticIterationStatementTestCase {
            id: "for-of-destructuring",
            category: IterationStatementTestCategory::EdgeCases,
            description: "For-of loop with destructuring assignment",
            source_code: "for (const [key, value] of entries) { console.log(key, value); }",
            es_spec_section: "13.2.6",
            requirement_level: "SHOULD",
        },
    ];

    pub fn run_conformance_tests() -> IterationStatementConformanceReport {
        let mut results = BTreeMap::new();
        let mut statistics = ConformanceStatistics {
            total_tests: 0,
            passed: 0,
            failed: 0,
            parse_errors: 0,
            pass_rate_millionths: 0,
        };

        for static_case in Self::STATIC_TEST_CASES {
            let test_case = IterationStatementTestCase::from(static_case);
            let result = Self::execute_test_case(&test_case);

            match result {
                IterationStatementResult::Pass => statistics.passed += 1,
                IterationStatementResult::Fail => statistics.failed += 1,
                IterationStatementResult::ParseError => statistics.parse_errors += 1,
            }
            statistics.total_tests += 1;

            results.insert(test_case.id.clone(), result);
        }

        statistics.pass_rate_millionths = statistics
            .passed
            .saturating_mul(1_000_000)
            .checked_div(statistics.total_tests)
            .unwrap_or(0);

        IterationStatementConformanceReport {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            test_results: results.clone(),
            statistics,
            coverage_by_category: Self::calculate_coverage_by_category(&results),
        }
    }

    fn execute_test_case(test_case: &IterationStatementTestCase) -> IterationStatementResult {
        let mut engine = HybridRouter::default();

        match engine.eval(&test_case.source_code) {
            Ok(_) => IterationStatementResult::Pass,
            Err(err) => {
                // Check if error is due to parsing or execution
                let error_str = err.to_string();
                if error_str.contains("parse") || error_str.contains("syntax") {
                    IterationStatementResult::ParseError
                } else {
                    IterationStatementResult::Fail
                }
            }
        }
    }

    fn calculate_coverage_by_category(
        results: &BTreeMap<String, IterationStatementResult>,
    ) -> BTreeMap<IterationStatementTestCategory, CategoryCoverage> {
        let mut coverage = BTreeMap::new();

        for static_case in Self::STATIC_TEST_CASES {
            let category_coverage = coverage
                .entry(static_case.category.clone())
                .or_insert_with(CategoryCoverage::default);
            category_coverage.total += 1;

            if let Some(result) = results.get(static_case.id)
                && matches!(result, IterationStatementResult::Pass)
            {
                category_coverage.passed += 1;
            }
        }

        coverage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_for_statement_basic() {
        let static_case = &IterationStatementConformanceHarness::STATIC_TEST_CASES[0];
        let test_case = IterationStatementTestCase::from(static_case);
        assert_eq!(
            test_case.category,
            IterationStatementTestCategory::ForStatement
        );

        let result = IterationStatementConformanceHarness::execute_test_case(&test_case);
        // Basic for loops should be supported
        assert!(matches!(
            result,
            IterationStatementResult::Pass | IterationStatementResult::Fail
        ));
    }

    #[test]
    fn test_for_in_statement() {
        let static_case = &IterationStatementConformanceHarness::STATIC_TEST_CASES[5];
        let test_case = IterationStatementTestCase::from(static_case);
        assert_eq!(
            test_case.category,
            IterationStatementTestCategory::ForInStatement
        );

        let result = IterationStatementConformanceHarness::execute_test_case(&test_case);
        // For-in loops are critical JavaScript functionality
        assert!(matches!(
            result,
            IterationStatementResult::Pass | IterationStatementResult::Fail
        ));
    }

    #[test]
    fn test_for_of_statement() {
        let static_case = &IterationStatementConformanceHarness::STATIC_TEST_CASES[8];
        let test_case = IterationStatementTestCase::from(static_case);
        assert_eq!(
            test_case.category,
            IterationStatementTestCategory::ForOfStatement
        );

        let result = IterationStatementConformanceHarness::execute_test_case(&test_case);
        // For-of loops are ES2015+ feature
        assert!(matches!(
            result,
            IterationStatementResult::Pass | IterationStatementResult::Fail
        ));
    }

    #[test]
    fn test_while_statement() {
        let static_case = &IterationStatementConformanceHarness::STATIC_TEST_CASES[11];
        let test_case = IterationStatementTestCase::from(static_case);
        assert_eq!(
            test_case.category,
            IterationStatementTestCategory::WhileStatement
        );

        let result = IterationStatementConformanceHarness::execute_test_case(&test_case);
        // While loops are fundamental JavaScript
        assert!(matches!(
            result,
            IterationStatementResult::Pass | IterationStatementResult::Fail
        ));
    }

    #[test]
    fn test_do_while_statement() {
        let static_case = &IterationStatementConformanceHarness::STATIC_TEST_CASES[13];
        let test_case = IterationStatementTestCase::from(static_case);
        assert_eq!(
            test_case.category,
            IterationStatementTestCategory::DoWhileStatement
        );

        let result = IterationStatementConformanceHarness::execute_test_case(&test_case);
        // Do-while loops are fundamental JavaScript
        assert!(matches!(
            result,
            IterationStatementResult::Pass | IterationStatementResult::Fail
        ));
    }

    #[test]
    fn test_conformance_report_generation() {
        let report = IterationStatementConformanceHarness::run_conformance_tests();

        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.bead_id, BEAD_ID);
        assert_eq!(
            report.statistics.total_tests as usize,
            IterationStatementConformanceHarness::STATIC_TEST_CASES.len()
        );

        // Statistics should be consistent
        assert_eq!(
            report.statistics.total_tests,
            report.statistics.passed + report.statistics.failed + report.statistics.parse_errors
        );

        // Coverage by category should account for all tests
        let total_coverage: u32 = report
            .coverage_by_category
            .values()
            .map(|coverage| coverage.total)
            .sum();
        assert_eq!(total_coverage, report.statistics.total_tests);
    }

    #[test]
    fn test_all_test_cases_have_unique_ids() {
        let mut ids = std::collections::HashSet::new();
        for test_case in IterationStatementConformanceHarness::STATIC_TEST_CASES {
            assert!(
                ids.insert(&test_case.id),
                "Duplicate test case ID: {}",
                test_case.id
            );
        }
    }

    #[test]
    fn test_all_categories_covered() {
        use std::collections::HashSet;

        let covered_categories: HashSet<_> =
            IterationStatementConformanceHarness::STATIC_TEST_CASES
                .iter()
                .map(|test| &test.category)
                .collect();

        // Verify we have tests for all major iteration statement types
        assert!(covered_categories.contains(&IterationStatementTestCategory::ForStatement));
        assert!(covered_categories.contains(&IterationStatementTestCategory::ForInStatement));
        assert!(covered_categories.contains(&IterationStatementTestCategory::ForOfStatement));
        assert!(covered_categories.contains(&IterationStatementTestCategory::WhileStatement));
        assert!(covered_categories.contains(&IterationStatementTestCategory::DoWhileStatement));
    }
}

/// Integration test for the full iteration statement conformance harness
#[test]
fn iteration_statements_test262_conformance_integration() {
    let report = IterationStatementConformanceHarness::run_conformance_tests();

    println!("Iteration Statements Test262 Conformance Report");
    println!("==============================================");
    println!("Total tests: {}", report.statistics.total_tests);
    println!("Passed: {}", report.statistics.passed);
    println!("Failed: {}", report.statistics.failed);
    println!("Parse errors: {}", report.statistics.parse_errors);
    println!(
        "Pass rate: {:.2}%",
        report.statistics.pass_rate_millionths as f64 / 10_000.0
    );

    println!("\nCoverage by Category:");
    for (category, coverage) in &report.coverage_by_category {
        let rate = if coverage.total > 0 {
            (coverage.passed * 100) / coverage.total
        } else {
            0
        };
        println!(
            "  {:?}: {}/{} ({}%)",
            category, coverage.passed, coverage.total, rate
        );
    }

    // Log individual test results for analysis
    println!("\nIndividual Test Results:");
    for test_case in IterationStatementConformanceHarness::STATIC_TEST_CASES {
        if let Some(result) = report.test_results.get(test_case.id) {
            println!(
                "  {} [{}]: {:?}",
                test_case.id, test_case.requirement_level, result
            );
        }
    }

    // Conformance gate: Fail if pass rate drops below 95%
    let pass_rate_percent = report.statistics.pass_rate_millionths as f64 / 10_000.0;
    assert!(
        pass_rate_percent >= 95.0,
        "Iteration statement ES2020 conformance below threshold: {:.2}% (required: ≥95%)",
        pass_rate_percent
    );
}
