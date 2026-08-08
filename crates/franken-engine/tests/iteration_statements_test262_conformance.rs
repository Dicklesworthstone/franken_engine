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

use frankenengine_engine::{EvalErrorCode, HybridRouter};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod _support;
use _support::test262_common::{RequirementLevel, assert_report_json_round_trips};

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
    pub requirement_level: RequirementLevel,
}

#[derive(Debug, Clone)]
pub struct StaticIterationStatementTestCase {
    pub id: &'static str,
    pub category: IterationStatementTestCategory,
    pub description: &'static str,
    pub source_code: &'static str,
    pub es_spec_section: &'static str,
    pub requirement_level: RequirementLevel,
}

impl From<&StaticIterationStatementTestCase> for IterationStatementTestCase {
    fn from(static_case: &StaticIterationStatementTestCase) -> Self {
        Self {
            id: static_case.id.to_string(),
            category: static_case.category.clone(),
            description: static_case.description.to_string(),
            source_code: static_case.source_code.to_string(),
            es_spec_section: static_case.es_spec_section.to_string(),
            requirement_level: static_case.requirement_level,
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
            source_code: "let total = 0; for (let i = 0; i < 10; i = i + 1) { total = total + i; } total;",
            es_spec_section: "13.2.4",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-statement-empty-parts",
            category: IterationStatementTestCategory::ForStatement,
            description: "For loop with empty initialization and update",
            source_code: "let condition = false; for (; condition; ) { condition = false; } condition;",
            es_spec_section: "13.2.4",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-statement-var-declaration",
            category: IterationStatementTestCategory::VariableScoping,
            description: "For loop with var declaration in header",
            source_code: "var seen = 0; for (var x = 0; x < 5; x = x + 1) { seen = x; } seen;",
            es_spec_section: "13.2.4",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-statement-let-declaration",
            category: IterationStatementTestCategory::VariableScoping,
            description: "For loop with let declaration in header",
            source_code: "let seen = 0; for (let y = 0; y < 3; y = y + 1) { seen = y; } seen;",
            es_spec_section: "13.2.4",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-statement-const-declaration",
            category: IterationStatementTestCategory::VariableScoping,
            description: "For loop with const declaration in header",
            source_code: "let seen = 0; for (const z of [1, 2, 3]) { seen = z; } seen;",
            es_spec_section: "13.2.4",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-statement-let-tdz",
            category: IterationStatementTestCategory::VariableScoping,
            description: "For loop let declaration temporal dead zone in condition",
            source_code: "for (let x = (x = 1); x < 2; x++) { } // Should throw ReferenceError",
            es_spec_section: "13.2.4",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-statement-block-scope-isolation",
            category: IterationStatementTestCategory::VariableScoping,
            description: "For loop variable scope isolation per iteration",
            source_code: r#"
                let closures = [];
                for (let i = 0; i < 3; i++) {
                    closures.push(() => i);
                }
                closures[0]() + closures[1]() + closures[2](); // Should be 0+1+2=3
            "#,
            es_spec_section: "13.2.4",
            requirement_level: RequirementLevel::Must,
        },
        // For-in statement tests (13.2.5)
        StaticIterationStatementTestCase {
            id: "for-in-statement-basic",
            category: IterationStatementTestCategory::ForInStatement,
            description: "Basic for-in loop over object properties",
            source_code: "let obj = { a: 1 }; let seen = ''; for (let key in obj) { seen = key; } seen;",
            es_spec_section: "13.2.5",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-in-statement-var-declaration",
            category: IterationStatementTestCategory::ForInStatement,
            description: "For-in loop with var declaration",
            source_code: "let object = { a: 1 }; let seen = ''; for (var prop in object) { seen = prop; } seen;",
            es_spec_section: "13.2.5",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-in-statement-let-declaration",
            category: IterationStatementTestCategory::ForInStatement,
            description: "For-in loop with let declaration",
            source_code: "let target = { a: 1 }; let seen = ''; for (let property in target) { seen = property; } seen;",
            es_spec_section: "13.2.5",
            requirement_level: RequirementLevel::Must,
        },
        // For-of statement tests (13.2.6)
        StaticIterationStatementTestCase {
            id: "for-of-statement-basic",
            category: IterationStatementTestCategory::ForOfStatement,
            description: "Basic for-of loop over iterable",
            source_code: "let iterable = [1, 2, 3]; let seen = 0; for (let value of iterable) { seen = value; } seen;",
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-of-statement-array",
            category: IterationStatementTestCategory::ForOfStatement,
            description: "For-of loop over array literal",
            source_code: "let seen = 0; for (let item of [1, 2, 3]) { seen = item; } seen;",
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-of-statement-const-declaration",
            category: IterationStatementTestCategory::ForOfStatement,
            description: "For-of loop with const declaration",
            source_code: "let seen = 0; let collection = [1, 2, 3]; for (const element of collection) { seen = element; } seen;",
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Must,
        },
        // While statement tests (13.2.3)
        StaticIterationStatementTestCase {
            id: "while-statement-basic",
            category: IterationStatementTestCategory::WhileStatement,
            description: "Basic while loop with condition",
            source_code: "let condition = false; while (condition) { condition = false; } condition;",
            es_spec_section: "13.2.3",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "while-statement-complex-condition",
            category: IterationStatementTestCategory::WhileStatement,
            description: "While loop with complex boolean condition",
            source_code: "let x = 0; let y = 0; let done = false; while (x > 0 && y < 10 && !done) { x = x - 1; } x;",
            es_spec_section: "13.2.3",
            requirement_level: RequirementLevel::Must,
        },
        // Do-while statement tests (13.2.2)
        StaticIterationStatementTestCase {
            id: "do-while-statement-basic",
            category: IterationStatementTestCategory::DoWhileStatement,
            description: "Basic do-while loop",
            source_code: "let condition = false; let seen = 0; do { seen = 1; } while (condition); seen;",
            es_spec_section: "13.2.2",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "do-while-statement-single-iteration",
            category: IterationStatementTestCategory::DoWhileStatement,
            description: "Do-while loop that executes exactly once",
            source_code: "let seen = 0; do { seen = seen + 1; } while (false); seen;",
            es_spec_section: "13.2.2",
            requirement_level: RequirementLevel::Must,
        },
        // Break and continue tests
        StaticIterationStatementTestCase {
            id: "break-statement-for-loop",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Break statement in for loop",
            source_code: "for (let i = 0; i < 10; i = i + 1) { if (i === 5) break; }",
            es_spec_section: "13.12",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "continue-statement-while-loop",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Continue statement in while loop",
            source_code: "let condition = false; let skip = false; while (condition) { if (skip) continue; condition = false; } condition;",
            es_spec_section: "13.13",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "labeled-break-statement",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Labeled break statement with nested loops",
            source_code: "outer: for (;;) { inner: for (;;) { break outer; } }",
            es_spec_section: "13.12",
            requirement_level: RequirementLevel::Should,
        },
        StaticIterationStatementTestCase {
            id: "labeled-continue-statement",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Labeled continue statement with nested loops",
            source_code: "let done = false; loop: while (!done) { done = true; for (;;) { continue loop; } } done;",
            es_spec_section: "13.13",
            requirement_level: RequirementLevel::Should,
        },
        StaticIterationStatementTestCase {
            id: "break-for-of-early-exit",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Break statement in for-of loop to test iterator cleanup",
            source_code: r#"
                let seen = [];
                for (const value of [1, 2, 3, 4, 5]) {
                    seen.push(value);
                    if (value === 3) break;
                }
                seen.length; // Should be 3
            "#,
            es_spec_section: "13.12",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "continue-for-of-skip",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Continue statement in for-of loop",
            source_code: r#"
                let sum = 0;
                for (const value of [1, 2, 3, 4, 5]) {
                    if (value % 2 === 0) continue;
                    sum += value;
                }
                sum; // Should be 1+3+5=9
            "#,
            es_spec_section: "13.13",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "unlabeled-break-error",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Unlabeled break outside loop should be syntax error",
            source_code: "break; // Should be SyntaxError",
            es_spec_section: "13.12",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "unlabeled-continue-error",
            category: IterationStatementTestCategory::BreakContinue,
            description: "Unlabeled continue outside loop should be syntax error",
            source_code: "continue; // Should be SyntaxError",
            es_spec_section: "13.13",
            requirement_level: RequirementLevel::Must,
        },
        // Iterator protocol integration - REAL iterator protocol tests
        StaticIterationStatementTestCase {
            id: "for-of-custom-iterator-basic",
            category: IterationStatementTestCategory::IteratorProtocol,
            description: "For-of with custom Symbol.iterator implementation",
            source_code: r#"
                let customIterable = {
                    [Symbol.iterator]() {
                        let count = 0;
                        return {
                            next() {
                                if (count < 3) {
                                    return { value: count++, done: false };
                                }
                                return { done: true };
                            }
                        };
                    }
                };
                let seen = 0;
                for (let value of customIterable) {
                    seen = value;
                }
                seen;
            "#,
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-of-iterator-return-method",
            category: IterationStatementTestCategory::IteratorProtocol,
            description: "For-of iterator cleanup with return() method on early exit",
            source_code: r#"
                let cleanupCalled = false;
                let customIterable = {
                    [Symbol.iterator]() {
                        let count = 0;
                        return {
                            next() {
                                return count < 10 ? { value: count++, done: false } : { done: true };
                            },
                            return() {
                                cleanupCalled = true;
                                return { done: true };
                            }
                        };
                    }
                };
                for (let value of customIterable) {
                    if (value === 2) break;
                }
                cleanupCalled;
            "#,
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Should,
        },
        StaticIterationStatementTestCase {
            id: "for-of-iterator-throw-handling",
            category: IterationStatementTestCategory::IteratorProtocol,
            description: "For-of iterator with next() method throwing",
            source_code: r#"
                let customIterable = {
                    [Symbol.iterator]() {
                        let count = 0;
                        return {
                            next() {
                                if (count === 0) {
                                    count++;
                                    return { value: 42, done: false };
                                }
                                throw new Error("Iterator error");
                            }
                        };
                    }
                };
                try {
                    for (let value of customIterable) {
                        // Should get 42 on first iteration, then throw
                    }
                } catch (e) {
                    // Expected to catch iterator error
                    42;
                }
            "#,
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Should,
        },
        StaticIterationStatementTestCase {
            id: "for-of-array-iterator-simple",
            category: IterationStatementTestCategory::IteratorProtocol,
            description: "For-of with built-in Array iterator (baseline)",
            source_code: "let customIterable = [1, 2, 3]; let seen = 0; for (let value of customIterable) { seen = value; } seen;",
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Must,
        },
        // Edge cases
        StaticIterationStatementTestCase {
            id: "for-statement-empty-body",
            category: IterationStatementTestCategory::EdgeCases,
            description: "For loop with empty body",
            source_code: "for (let i = 0; i < 10; i = i + 1) { }",
            es_spec_section: "13.2.4",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "while-statement-empty-body",
            category: IterationStatementTestCategory::EdgeCases,
            description: "While loop with empty body",
            source_code: "let condition = false; while (condition) { } condition;",
            es_spec_section: "13.2.3",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-of-destructuring-basic",
            category: IterationStatementTestCategory::EdgeCases,
            description: "For-of loop with basic array destructuring",
            source_code: "let seen = 0; let entries = [[1, 2]]; for (const [key, value] of entries) { seen = key + value; } seen;",
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Must,
        },
        StaticIterationStatementTestCase {
            id: "for-of-destructuring-nested",
            category: IterationStatementTestCategory::EdgeCases,
            description: "For-of loop with nested destructuring",
            source_code: r#"
                let result = 0;
                let data = [{ coords: [1, 2] }, { coords: [3, 4] }];
                for (const { coords: [x, y] } of data) {
                    result += x + y;
                }
                result; // Should be 10
            "#,
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Should,
        },
        StaticIterationStatementTestCase {
            id: "for-of-destructuring-defaults",
            category: IterationStatementTestCategory::EdgeCases,
            description: "For-of loop with destructuring default values",
            source_code: r#"
                let result = 0;
                let items = [{ a: 1 }, { b: 2 }, {}];
                for (const { a = 5, b = 10 } of items) {
                    result += a + b;
                }
                result; // Should be 1+10 + 5+2 + 5+10 = 33
            "#,
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Should,
        },
        StaticIterationStatementTestCase {
            id: "for-of-destructuring-rest",
            category: IterationStatementTestCategory::EdgeCases,
            description: "For-of loop with rest pattern destructuring",
            source_code: r#"
                let result = 0;
                let arrays = [[1, 2, 3, 4], [5, 6]];
                for (const [first, ...rest] of arrays) {
                    result += first + rest.length;
                }
                result; // Should be 1+3 + 5+1 = 10
            "#,
            es_spec_section: "13.2.6",
            requirement_level: RequirementLevel::Should,
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
        let mut coverage: BTreeMap<IterationStatementTestCategory, CategoryCoverage> =
            BTreeMap::new();

        for static_case in Self::STATIC_TEST_CASES {
            let category_coverage = coverage.entry(static_case.category.clone()).or_default();
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

    fn eval_value_bd_5p1dp(source: &str) -> String {
        let mut engine = HybridRouter::default();
        engine
            .eval(source)
            .unwrap_or_else(|error| panic!("bd-5p1dp eval failed for {source:?}: {error}"))
            .value
            .to_string()
    }

    fn eval_error_bd_cu3sz(source: &str) -> String {
        let mut engine = HybridRouter::default();
        match engine.eval(source) {
            Ok(value) => panic!("bd-cu3sz expected eval failure, got {}", value.value),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn bare_for_in_of_assignment_targets_observe_existing_bindings_bd_5p1dp() {
        let cases = [
            (
                "for-in identifier",
                "let key = ''; for (key in { alpha: 1, beta: 2 }) {} key;",
                "beta",
            ),
            (
                "for-in destructuring",
                "let target = 'old'; for ({ missing: target } in { xy: 1 }) {} target === undefined;",
                "true",
            ),
            (
                "for-of identifier",
                "let value = 0; for (value of [4, 7]) {} value;",
                "7",
            ),
            (
                "iterable reads existing target before assignment",
                "let value = [1]; for (value of value) {} value;",
                "1",
            ),
            (
                "for-of destructuring",
                "let left = 0; let right = 0; for ([left, right] of [[1, 2], [3, 4]]) {} left * 10 + right;",
                "34",
            ),
            (
                "nested default and rest assignment targets",
                "let picked = 0; let rest = []; for ([{ p: picked } = { p: 9 }, ...rest] of [[undefined, 1, 2]]) {} picked * 10 + rest.length;",
                "92",
            ),
            (
                "assignment pattern may repeat a target",
                "let value = 0; for ([value, value] of [[1, 2]]) {} value;",
                "2",
            ),
            (
                "nearest nested binding",
                "let result = ''; let value = 'outer'; { let value = 'block'; for (value of ['inner']) {} result = value; } result + ':' + value;",
                "inner:outer",
            ),
            (
                "shared closure cell",
                "let value = 0; let observe = () => value; for (value of [1, 2, 3]) {} observe();",
                "3",
            ),
            (
                "sloppy unresolved target",
                "for (missing of [7]) {} missing;",
                "7",
            ),
            (
                "empty iterable does not assign const target",
                "const fixed = 1; for (fixed of []) {} fixed;",
                "1",
            ),
            (
                "empty iterable does not enter target TDZ assignment",
                "for (value of []) {} let value = 9; value;",
                "9",
            ),
            (
                "scope-routed const targets preserve shadow identity",
                "const value = 1; for (value of []) {} { const value = 2; for (value of []) {} } value;",
                "1",
            ),
            (
                "explicit const head reinitializes per iteration",
                "let total = 0; for (const item of [1, 2]) { if (false) item = 3; total += item; } total;",
                "3",
            ),
            (
                "break closes iterator after bare assignment",
                r#"
                    let value = -1;
                    let iterator = {
                        count: 0,
                        closed: false,
                        next() {
                            return this.count < 10
                                ? { value: this.count++, done: false }
                                : { done: true };
                        },
                        return() {
                            this.closed = true;
                            return { done: true };
                        }
                    };
                    let customIterable = {
                        [Symbol.iterator]() { return iterator; }
                    };
                    for (value of customIterable) {
                        if (value === 2) break;
                    }
                    (iterator.closed ? 10 : 0) + value;
                "#,
                "12",
            ),
        ];

        for (label, source, expected) in cases {
            assert_eq!(
                eval_value_bd_5p1dp(source),
                expected,
                "{label} must use assignment semantics"
            );
        }
    }

    #[test]
    fn bare_for_in_of_assignment_enforces_const_and_tdz_bd_5p1dp() {
        let cases = [
            (
                "for-of const assignment",
                "const fixed = 1; for (fixed of [2]) {}",
                "assignment to constant variable",
            ),
            (
                "captured const assignment",
                "const fixed = 1; let observe = () => fixed; for (fixed of [2]) {}",
                "assignment to constant variable",
            ),
            (
                "for-in const assignment",
                "const fixed = ''; for (fixed in { key: 1 }) {}",
                "assignment to constant variable",
            ),
            (
                "for-of assignment before lexical declaration",
                "for (value of [1]) {} let value = 9;",
                "before initialization",
            ),
            (
                "for-in assignment before lexical declaration",
                "for (value in { key: 1 }) {} let value = 9;",
                "before initialization",
            ),
        ];

        for (label, source, expected_message) in cases {
            let mut engine = HybridRouter::default();
            let error = engine.eval(source).unwrap_err();
            assert_eq!(
                error.code,
                EvalErrorCode::RuntimeFault,
                "{label} must fail at runtime, not during parsing or lowering: {error}"
            );
            assert!(
                error.message.contains(expected_message),
                "{label} must report {expected_message:?} when the first yielded value is assigned: {error}"
            );
        }
    }

    #[test]
    fn bare_loop_targets_observe_strictness_and_empty_iteration_bd_0k19b() {
        let cases = [
            (
                "strict empty for-of performs no put",
                r#""use strict"; for (missing_empty_of_bd_0k19b of []) {} typeof missing_empty_of_bd_0k19b;"#,
                "undefined",
            ),
            (
                "strict empty for-in performs no put",
                r#""use strict"; for (missing_empty_in_bd_0k19b in {}) {} typeof missing_empty_in_bd_0k19b;"#,
                "undefined",
            ),
            (
                "sloppy destructuring creates globals left to right",
                "for ([left_global_bd_0k19b, right_global_bd_0k19b] of [[2, 3]]) {} left_global_bd_0k19b * 10 + right_global_bd_0k19b;",
                "23",
            ),
            (
                "sloppy for-in destructuring creates an unresolved global",
                "for ({ length: key_length_bd_0k19b } in { xy: 1 }) {} key_length_bd_0k19b;",
                "2",
            ),
            (
                "strict destructuring keeps prior resolved writes",
                r#""use strict"; let existing_bd_0k19b = 0; let caught = false; try { for ([existing_bd_0k19b, missing_destructure_bd_0k19b] of [[4, 5]]) {} } catch (error) { caught = true; } existing_bd_0k19b + ":" + caught;"#,
                "4:true",
            ),
            // INTENTIONAL SECURITY DIVERGENCE (bd-hv3mn): a sloppy
            // Function-constructor body's implicit global stays contained in
            // the generated realm (be416d778 "harden generated realm
            // isolation") and never becomes a realm global visible to outer
            // code. Node v20.19.4 and Bun 1.3.14 both leak the implicit
            // global to the realm and then resolve the strict destructuring
            // store at store time, printing `2:false:number` for this source
            // (the old expectation here, `true:1`, matched NEITHER donor nor
            // this engine — it was red from birth). The contained contract
            // pinned instead: generated code executes and returns values
            // (`2`), the strict store on the still-unresolved outer name
            // throws (`true`), and the generated implicit global is never
            // observable outside (`undefined`). Do not "fix" this toward
            // donor behavior without an explicit decision to weaken generated
            // realm isolation; the differential-oracle taxonomy class for
            // this case is `intentional_security_divergence`.
            (
                "generated-realm implicit global stays contained (bd-hv3mn)",
                r#""use strict"; let caught = false; let make = Function("default_created_bd_0k19b = 1; return 2;"); let ret = make(); try { for ([default_created_bd_0k19b = make()] of [[undefined]]) {} } catch (error) { caught = true; } ret + ":" + caught + ":" + typeof default_created_bd_0k19b;"#,
                "2:true:undefined",
            ),
            (
                "empty destructuring runs neither default nor put",
                r#""use strict"; let side = 0; for ([missing_default_bd_0k19b = (side = 1)] of []) {} side + ":" + typeof missing_default_bd_0k19b;"#,
                "0:undefined",
            ),
        ];

        for (label, source, expected) in cases {
            assert_eq!(eval_value_bd_5p1dp(source), expected, "{label}");
        }

        for (label, source, missing_name) in [
            (
                "strict for-of identifier",
                r#""use strict"; for (missing_for_of_bd_0k19b of [7]) {}"#,
                "missing_for_of_bd_0k19b",
            ),
            (
                "strict for-in identifier",
                r#""use strict"; for (missing_for_in_bd_0k19b in { key: 1 }) {}"#,
                "missing_for_in_bd_0k19b",
            ),
            (
                "strict destructuring identifier",
                r#""use strict"; for ([missing_destructure_error_bd_0k19b] of [[5]]) {}"#,
                "missing_destructure_error_bd_0k19b",
            ),
        ] {
            let mut engine = HybridRouter::default();
            let error = engine.eval(source).unwrap_err();
            assert_eq!(error.code, EvalErrorCode::RuntimeFault, "{label}: {error}");
            assert!(
                error
                    .message
                    .contains(&format!("{missing_name} is not defined")),
                "{label} must report the unresolved loop-head target: {error}"
            );
        }
    }

    #[test]
    fn strict_for_of_head_reference_error_closes_iterator_once_bd_0k19b() {
        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    "use strict";
                    let iterator = {
                        closed: 0,
                        next() { return { value: 7, done: false }; },
                        return() {
                            this.closed++;
                            return { done: true };
                        }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    let caught = false;
                    try {
                        for (missing_close_bd_0k19b of iterable) {}
                    } catch (error) {
                        caught = true;
                    }
                    caught + ":" + iterator.closed;
                "#,
            ),
            "true:1",
            "a strict unresolved loop-head put must close before propagating"
        );
    }

    #[test]
    fn abrupt_for_of_head_assignment_closes_iterator_bd_cu3sz() {
        let cases = [
            (
                "const assignment",
                r#"
                    let iterator = {
                        closed: 0,
                        next() { return { value: 2, done: false }; },
                        return() {
                            this.closed++;
                            return { done: true };
                        }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    let caught = false;
                    try {
                        const fixed = 1;
                        for (fixed of iterable) {}
                    } catch (error) {
                        caught = true;
                    }
                    (caught ? 10 : 0) + iterator.closed;
                "#,
                "11",
            ),
            (
                "temporal dead zone",
                r#"
                    let iterator = {
                        closed: 0,
                        next() { return { value: 2, done: false }; },
                        return() {
                            this.closed++;
                            return { done: true };
                        }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    let caught = false;
                    try {
                        for (value of iterable) {}
                        let value = 9;
                    } catch (error) {
                        caught = true;
                    }
                    (caught ? 10 : 0) + iterator.closed;
                "#,
                "11",
            ),
            (
                "function-local const assignment",
                r#"
                    function run() {
                        let iterator = {
                            closed: 0,
                            next() { return { value: 2, done: false }; },
                            return() {
                                this.closed++;
                                return { done: true };
                            }
                        };
                        let iterable = { [Symbol.iterator]() { return iterator; } };
                        let caught = false;
                        try {
                            const fixed = 1;
                            for (fixed of iterable) {}
                        } catch (error) {
                            caught = true;
                        }
                        return (caught ? 10 : 0) + iterator.closed;
                    }
                    run();
                "#,
                "11",
            ),
        ];

        for (label, source, expected) in cases {
            assert_eq!(
                eval_value_bd_5p1dp(source),
                expected,
                "{label} must close the iterator before propagating the head error"
            );
        }

        let diagnostics = [
            (
                "const assignment",
                r#"
                    let iterator = {
                        next() { return { value: 2, done: false }; },
                        return() { return { done: true }; }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    const fixed = 1;
                    for (fixed of iterable) {}
                "#,
                "assignment to constant variable",
            ),
            (
                "temporal dead zone",
                r#"
                    let iterator = {
                        next() { return { value: 2, done: false }; },
                        return() { return { done: true }; }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    for (value of iterable) {}
                    let value = 9;
                "#,
                "before initialization",
            ),
        ];
        for (label, source, expected) in diagnostics {
            let error = eval_error_bd_cu3sz(source);
            assert!(
                error.contains(expected),
                "{label} must preserve its original diagnostic after close: {error}"
            );
        }
    }

    #[test]
    fn abrupt_destructuring_head_closes_after_prior_targets_bd_cu3sz() {
        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let left = 0;
                    const fixed = 9;
                    let iterator = {
                        closed: 0,
                        next() { return { value: [1, 2], done: false }; },
                        return() {
                            this.closed++;
                            return { done: true };
                        }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    let caught = false;
                    try {
                        for ([left, fixed] of iterable) {}
                    } catch (error) {
                        caught = true;
                    }
                    left * 100 + (caught ? 10 : 0) + iterator.closed;
                "#,
            ),
            "111",
            "destructuring must retain earlier stores, close once, then propagate the later error"
        );
    }

    #[test]
    fn abrupt_head_error_wins_over_iterator_return_failures_bd_cu3sz() {
        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let iterator = {
                        closed: 0,
                        next() { return { value: 2, done: false }; },
                        return() {
                            this.closed++;
                            throw new Error("close-error");
                        }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    let original_error = false;
                    try {
                        const fixed = 1;
                        for (fixed of iterable) {}
                    } catch (error) {
                        original_error = true;
                    }
                    (original_error ? 10 : 0) + iterator.closed;
                "#,
            ),
            "11",
            "IteratorClose with a throw completion must preserve the original head error"
        );
        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let iterator = {
                        closed: 0,
                        next() { return { value: 2, done: false }; },
                        return() {
                            this.closed++;
                            return 0;
                        }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    let original_error = false;
                    try {
                        const fixed = 1;
                        for (fixed of iterable) {}
                    } catch (error) {
                        original_error = true;
                    }
                    (original_error ? 10 : 0) + iterator.closed;
                "#,
            ),
            "11",
            "a non-object close result must not replace the original head error"
        );

        let precedence_cases = [
            (
                "throwing return",
                r#"
                    let iterator = {
                        next() { return { value: 2, done: false }; },
                        return() { throw new Error("close-error"); }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    const fixed = 1;
                    for (fixed of iterable) {}
                "#,
                "close-error",
            ),
            (
                "non-object return",
                r#"
                    let iterator = {
                        next() { return { value: 2, done: false }; },
                        return() { return 0; }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    const fixed = 1;
                    for (fixed of iterable) {}
                "#,
                "object returned by iterator.return",
            ),
        ];
        for (label, source, displaced_diagnostic) in precedence_cases {
            let error = eval_error_bd_cu3sz(source);
            assert!(
                error.contains("assignment to constant variable"),
                "{label} must preserve the original assignment failure: {error}"
            );
            assert!(
                !error.contains(displaced_diagnostic),
                "{label} must not replace the original failure: {error}"
            );
        }
    }

    #[test]
    fn non_abrupt_unresolved_head_exhausts_without_closing_bd_cu3sz() {
        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let iterator = {
                        step: 0,
                        closed: 0,
                        next() {
                            return this.step++ === 0
                                ? { value: 7, done: false }
                                : { done: true };
                        },
                        return() {
                            this.closed++;
                            return { done: true };
                        }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    for (missing of iterable) { continue; }
                    missing * 10 + iterator.closed;
                "#,
            ),
            "70",
            "sloppy unresolved assignment is normal completion and must not close"
        );
    }

    #[test]
    fn for_of_body_throw_closes_once_and_preserves_original_bd_g73mg() {
        for mode in ["ok", "throw", "primitive"] {
            let source = format!(
                r#"
                    let closeMode = "{mode}";
                    let iterator = {{
                        closed: 0,
                        step: 0,
                        next() {{
                            return this.step++ === 0
                                ? {{ value: 1, done: false }}
                                : {{ done: true }};
                        }},
                        return() {{
                            this.closed++;
                            if (closeMode === "throw") throw new Error("close-error");
                            if (closeMode === "primitive") return 0;
                            return {{ done: true }};
                        }}
                    }};
                    let iterable = {{ [Symbol.iterator]() {{ return iterator; }} }};
                    function run() {{
                        try {{
                            for (const value of iterable) {{
                                throw new Error("body-error");
                            }}
                        }} catch (error) {{
                            return error.message + ":" + iterator.closed;
                        }}
                    }}
                    run();
                "#,
            );
            assert_eq!(
                eval_value_bd_5p1dp(&source),
                "body-error:1",
                "{mode}: a Throw completion must dominate iterator.return failure"
            );
        }
    }

    #[test]
    fn for_of_function_return_close_precedence_bd_g73mg() {
        for (mode, expected) in [
            ("ok", "value:1"),
            ("throw", "close-error:1"),
            ("primitive", "TypeError:1"),
        ] {
            let source = format!(
                r#"
                    let closeMode = "{mode}";
                    let iterator = {{
                        closed: 0,
                        next() {{ return {{ value: 1, done: false }}; }},
                        return() {{
                            this.closed++;
                            if (closeMode === "throw") throw new Error("close-error");
                            if (closeMode === "primitive") return 0;
                            return {{ done: true }};
                        }}
                    }};
                    let iterable = {{ [Symbol.iterator]() {{ return iterator; }} }};
                    function run() {{
                        try {{
                            for (const value of iterable) {{ return "value"; }}
                            return "miss";
                        }} catch (error) {{
                            return error.message === "close-error" ? "close-error" : error.name;
                        }}
                    }}
                    run() + ":" + iterator.closed;
                "#,
            );
            assert_eq!(eval_value_bd_5p1dp(&source), expected, "{mode}");
        }

        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let iterator = {
                        closed: 0,
                        next() { return { value: 1, done: false }; },
                        return() { this.closed++; return 0; }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    function run() {
                        let observed = "none";
                        try {
                            for (const value of iterable) { return "stale"; }
                        } catch (error) {
                            observed = error.name;
                        } finally {
                            observed += ":finally";
                        }
                        return observed + ":after";
                    }
                    run() + ":" + iterator.closed;
                "#,
            ),
            "TypeError:finally:after:1",
            "a caught close failure must not resurrect the displaced return"
        );

        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let iterator = {
                        closed: 0,
                        next() { return { value: 1, done: false }; },
                        return() { this.closed++; throw new Error("close-error"); }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    function run() {
                        try {
                            for (const value of iterable) {
                                try { throw new Error("body-error"); }
                                finally { return "stale"; }
                            }
                        } catch (error) {
                            return error.message;
                        }
                    }
                    run() + ":" + iterator.closed;
                "#,
            ),
            "close-error:1",
            "a return from finally overrides the body throw, then close failure overrides return"
        );
    }

    #[test]
    fn for_of_close_accepts_callable_and_promise_results_bd_g73mg() {
        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let iterator = {
                        closed: 0,
                        next() { return { value: 1, done: false }; },
                        return() { this.closed++; return function() {}; }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    function run() {
                        for (const value of iterable) { return "value"; }
                        return "miss";
                    }
                    run() + ":" + iterator.closed;
                "#,
            ),
            "value:1",
            "a callable iterator.return result is an ECMAScript object"
        );

        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let iterator = {
                        closed: 0,
                        next() { return { value: 1, done: false }; },
                        return() { this.closed++; return Promise.resolve(0); }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    for (const value of iterable) { break; }
                    iterator.closed;
                "#,
            ),
            "1",
            "a Promise iterator.return result is an ECMAScript object"
        );
    }

    #[test]
    fn for_of_close_accepts_representative_source_object_like_carriers_bd_7vfkc() {
        for (case, prelude, result_expression) in [
            ("ordinary object", "", "{}"),
            (
                "ordinary function",
                "function ordinary() { return 1; }",
                "ordinary",
            ),
            (
                "capturing closure",
                "let captured = 1; let closure = function() { return captured; };",
                "closure",
            ),
            ("builtin function", "", "Array.isArray"),
            ("Promise", "", "Promise.resolve(0)"),
            ("iterator", "", "[1][Symbol.iterator]()"),
            (
                "generator object",
                "function* values() { yield 1; } let generator = values();",
                "generator",
            ),
            (
                "generator function",
                "function* values() { yield 1; }",
                "values",
            ),
            (
                "async function",
                "async function asyncValue() { return 1; }",
                "asyncValue",
            ),
            (
                "async generator object",
                "async function* asyncValues() { yield 1; } let asyncGenerator = asyncValues();",
                "asyncGenerator",
            ),
            (
                "async generator function",
                "async function* asyncValues() { yield 1; }",
                "asyncValues",
            ),
        ] {
            let source = r#"
                    __PRELUDE__
                    let iterator = {
                        closed: 0,
                        next() { return { value: 1, done: false }; },
                        return() {
                            this.closed++;
                            return __RESULT_EXPRESSION__;
                        }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    for (const value of iterable) { break; }
                    iterator.closed;
                "#
            .replace("__PRELUDE__", prelude)
            .replace("__RESULT_EXPRESSION__", result_expression);
            assert_eq!(
                eval_value_bd_5p1dp(&source),
                "1",
                "{case}: every ECMAScript object-like return carrier must be accepted"
            );
        }
    }

    #[test]
    fn for_of_close_rejects_every_source_primitive_carrier_bd_7vfkc() {
        for (case, result_expression) in [
            ("undefined", "undefined"),
            ("null", "null"),
            ("boolean", "false"),
            ("integer number", "0"),
            ("floating-point number", "0.5"),
            ("bigint", "1n"),
            ("string", "'primitive'"),
            ("symbol", "Symbol('primitive')"),
        ] {
            let source = r#"
                    let iterator = {
                        closed: 0,
                        next() { return { value: 1, done: false }; },
                        return() {
                            this.closed++;
                            return __RESULT_EXPRESSION__;
                        }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    function run() {
                        try {
                            for (const value of iterable) { break; }
                            return "miss";
                        } catch (error) {
                            return error.name;
                        }
                    }
                    run() + ":" + iterator.closed;
                "#
            .replace("__RESULT_EXPRESSION__", result_expression);
            assert_eq!(
                eval_value_bd_5p1dp(&source),
                "TypeError:1",
                "{case}: a primitive return must throw TypeError after exactly one close call"
            );
        }
    }

    #[test]
    fn for_of_throw_completion_wins_and_closes_once_bd_7vfkc() {
        for (case, return_body) in [
            ("primitive return", "return 0;"),
            ("throwing return", "throw new Error('close-error');"),
        ] {
            let source = r#"
                    let iterator = {
                        closed: 0,
                        next() { return { value: 1, done: false }; },
                        return() {
                            this.closed++;
                            __RETURN_BODY__
                        }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    function run() {
                        try {
                            for (const value of iterable) {
                                throw new Error("body-error");
                            }
                            return "miss";
                        } catch (error) {
                            return error.message;
                        }
                    }
                    run() + ":" + iterator.closed;
                "#
            .replace("__RETURN_BODY__", return_body);
            assert_eq!(
                eval_value_bd_5p1dp(&source),
                "body-error:1",
                "{case}: Throw completion must win while iterator.return is called once"
            );
        }
    }

    #[test]
    fn for_of_crossing_labels_close_innermost_first_bd_g73mg() {
        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let trace = "";
                    function make(name) {
                        let step = 0;
                        return {
                            next() {
                                return step++ === 0
                                    ? { value: name, done: false }
                                    : { done: true };
                            },
                            return() {
                                trace += name + ",";
                                return { done: true };
                            },
                            [Symbol.iterator]() { return this; }
                        };
                    }
                    outer: for (const outerValue of make("outer")) {
                        for (const innerValue of make("inner")) { break outer; }
                    }
                    trace;
                "#,
            ),
            "inner,outer,",
            "break outer must close every crossed iterator innermost-first"
        );

        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let trace = "";
                    function make(name) {
                        let step = 0;
                        return {
                            next() {
                                return step++ === 0
                                    ? { value: name, done: false }
                                    : { done: true };
                            },
                            return() {
                                trace += name + ",";
                                return { done: true };
                            },
                            [Symbol.iterator]() { return this; }
                        };
                    }
                    outer: for (const outerValue of make("outer")) {
                        for (const innerValue of make("inner")) { continue outer; }
                    }
                    trace;
                "#,
            ),
            "inner,",
            "continue outer closes crossed inner iterators but not the target iterator"
        );
    }

    #[test]
    fn for_of_crossing_label_close_failure_promotes_to_throw_bd_g73mg() {
        for exit in ["break outer", "continue outer"] {
            let source = format!(
                r#"
                    let trace = "";
                    function make(name) {{
                        let step = 0;
                        return {{
                            next() {{
                                return step++ === 0
                                    ? {{ value: name, done: false }}
                                    : {{ done: true }};
                            }},
                            return() {{
                                trace += name + ",";
                                throw new Error(name + "-close");
                            }},
                            [Symbol.iterator]() {{ return this; }}
                        }};
                    }}
                    function run() {{
                        try {{
                            outer: for (const outerValue of make("outer")) {{
                                for (const innerValue of make("inner")) {{ {exit}; }}
                            }}
                            return trace + "miss";
                        }} catch (error) {{
                            return trace + "caught:" + error.message;
                        }}
                    }}
                    run();
                "#,
            );
            assert_eq!(
                eval_value_bd_5p1dp(&source),
                "inner,outer,caught:inner-close",
                "{exit}: an inner close failure becomes Throw while crossing the outer iterator"
            );
        }
    }

    #[test]
    fn for_of_non_crossing_and_step_failures_do_not_close_bd_g73mg() {
        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let iterator = {
                        closed: 0,
                        step: 0,
                        next() {
                            return this.step++ === 0
                                ? { value: 1, done: false }
                                : { done: true };
                        },
                        return() { this.closed++; return { done: true }; }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    for (const value of iterable) {
                        inner: { break inner; }
                        continue;
                    }
                    iterator.closed;
                "#,
            ),
            "0",
            "inner-label break, same-loop continue, and exhaustion must not close"
        );

        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let iterator = {
                        closed: 0,
                        next() { throw new Error("next-error"); },
                        return() { this.closed++; return { done: true }; }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    try { for (const value of iterable) {} } catch (error) {}
                    iterator.closed;
                "#,
            ),
            "0",
            "IteratorStep failure occurs before the body guard and must not close"
        );

        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let iterator = {
                        closed: 0,
                        next() {
                            return {
                                done: false,
                                get value() { throw new Error("value-error"); }
                            };
                        },
                        return() { this.closed++; return { done: true }; }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    function run() {
                        try { for (const value of iterable) {} } catch (error) {
                            return error.message + ":" + iterator.closed;
                        }
                    }
                    run();
                "#,
            ),
            "value-error:0",
            "IteratorValue failure occurs before the body guard and must not close"
        );
    }

    #[test]
    fn for_of_close_runs_after_source_finally_bd_g73mg() {
        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let trace = "";
                    let iterator = {
                        next() { return { value: 1, done: false }; },
                        return() { trace += "close,"; return { done: true }; }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    function run() {
                        for (const value of iterable) {
                            try { return "value"; }
                            finally { trace += "finally,"; }
                        }
                    }
                    run();
                    trace;
                "#,
            ),
            "finally,close,",
            "source finally must run before IteratorClose on return"
        );

        assert_eq!(
            eval_value_bd_5p1dp(
                r#"
                    let trace = "";
                    let iterator = {
                        next() { return { value: 1, done: false }; },
                        return() { trace += "close,"; return { done: true }; }
                    };
                    let iterable = { [Symbol.iterator]() { return iterator; } };
                    try {
                        for (const value of iterable) {
                            try { trace += "body,"; throw new Error("body-error"); }
                            finally { trace += "finally,"; }
                        }
                    } catch (error) {
                        trace += "catch,";
                    }
                    trace;
                "#,
            ),
            "body,finally,close,catch,",
            "source finally must run before IteratorClose and outer catch on throw"
        );
    }

    #[test]
    fn for_of_close_failure_respects_active_finally_ownership_bd_g73mg() {
        for (close_body, error_value, expected) in [
            (
                r#"throw new Error("close-error");"#,
                "error.message",
                "caught:close-error,after,old:1",
            ),
            (r#"return 0;"#, "error.name", "caught:TypeError,after,old:1"),
        ] {
            assert_eq!(
                eval_value_bd_5p1dp(&format!(
                    r#"
                        let trace = "";
                        let closed = 0;
                        let step = 0;
                        let iterator = {{
                            next() {{
                                return step++ === 0
                                    ? {{ value: 1, done: false }}
                                    : {{ done: true }};
                            }},
                            return() {{ closed++; {close_body} }}
                        }};
                        let iterable = {{ [Symbol.iterator]() {{ return iterator; }} }};
                        function run() {{
                            try {{ return "old"; }}
                            finally {{
                                try {{ for (const value of iterable) {{ break; }} }}
                                catch (error) {{
                                    trace += "caught:" + {error_value} + ",";
                                }}
                                trace += "after,";
                            }}
                        }}
                        let value = run();
                        trace + value + ":" + closed;
                    "#
                )),
                expected,
                "a catch inside the active finalizer must preserve its older return"
            );
        }

        for (close_body, error_value, expected) in [
            (
                r#"throw new Error("close-error");"#,
                "error.message",
                "close-error:next:cleanup:after:1",
            ),
            (
                r#"return 0;"#,
                "error.name",
                "TypeError:next:cleanup:after:1",
            ),
        ] {
            assert_eq!(
                eval_value_bd_5p1dp(&format!(
                    r#"
                        let closed = 0;
                        let step = 0;
                        let iterator = {{
                            next() {{
                                return step++ === 0
                                    ? {{ value: 1, done: false }}
                                    : {{ done: true }};
                            }},
                            return() {{ closed++; {close_body} }}
                        }};
                        let iterable = {{ [Symbol.iterator]() {{ return iterator; }} }};
                        function run() {{
                            try {{ return "old"; }}
                            finally {{ for (const value of iterable) {{ break; }} }}
                        }}
                        function observe() {{
                            try {{ run(); }} catch (error) {{ return {error_value} + ":"; }}
                        }}
                        let trace = observe();
                        try {{ trace += "next:"; }} finally {{ trace += "cleanup:"; }}
                        trace + "after:" + closed;
                    "#
                )),
                expected,
                "a close failure escaping the finalizer must replace its older return"
            );
        }
    }

    #[test]
    fn function_local_iteration_targets_preserve_binding_identity_bd_pimva() {
        let cases = [
            (
                "function-local const with empty iterable",
                "function run() { const fixed = 1; for (fixed of []) {} return fixed; } run();",
                "1",
            ),
            (
                "function-local predeclaration with empty iterable",
                "function run() { for (value of []) {} let value = 9; return value; } run();",
                "9",
            ),
            (
                "nearest nested function-local binding",
                "function run() { const value = 'outer'; let result = ''; { let value = 'block'; for (value of ['inner']) {} result = value; } return result + ':' + value; } run();",
                "inner:outer",
            ),
            (
                "function-local shared closure cell",
                "function run() { let value = 0; let observe = () => value; for (value of [1, 2, 3]) {} return observe(); } run();",
                "3",
            ),
            (
                "explicit function-local const head creates fresh per-iteration cells",
                "function run() { let first; let second; for (const item of [1, 2]) { if (item === 1) { first = () => item; } else { second = () => item; } } return first() * 10 + second(); } run();",
                "12",
            ),
            (
                "function-expression destructuring assignment",
                "let run = function () { let left = 0; let right = 0; for ([left, right] of [[3, 4]]) {} return left * 10 + right; }; run();",
                "34",
            ),
        ];

        for (label, source, expected) in cases {
            assert_eq!(
                eval_value_bd_5p1dp(source),
                expected,
                "{label} must preserve the exact deferred-frame binding"
            );
        }
    }

    #[test]
    fn function_local_iteration_targets_enforce_const_and_tdz_bd_pimva() {
        let cases = [
            (
                "function-local for-of const assignment",
                "function run() { const fixed = 1; for (fixed of [2]) {} } run();",
                "assignment to constant variable",
            ),
            (
                "arrow-local for-in const assignment",
                "let run = () => { const fixed = ''; for (fixed in { key: 1 }) {} }; run();",
                "assignment to constant variable",
            ),
            (
                "function-local assignment before lexical declaration",
                "function run() { for (value of [1]) {} let value = 9; } run();",
                "before initialization",
            ),
            (
                "function-local const TDZ precedes immutability",
                "function run() { for (value of [1]) {} const value = 9; } run();",
                "before initialization",
            ),
            (
                "function-local destructuring const assignment",
                "function run() { const fixed = 1; for ([fixed] of [[2]]) {} } run();",
                "assignment to constant variable",
            ),
            (
                "captured function-local const assignment",
                "function run() { const fixed = 1; let observe = () => fixed; for (fixed of [2]) {} return observe(); } run();",
                "assignment to constant variable",
            ),
            (
                "nested-scope function-local const assignment",
                "function run() { let value = 1; { const value = 2; for (value of [3]) {} } return value; } run();",
                "assignment to constant variable",
            ),
        ];

        for (label, source, expected_message) in cases {
            let mut engine = HybridRouter::default();
            let error = engine.eval(source).unwrap_err();
            assert_eq!(
                error.code,
                EvalErrorCode::RuntimeFault,
                "{label} must fail at runtime, not during parsing or lowering: {error}"
            );
            assert!(
                error.message.contains(expected_message),
                "{label} must report {expected_message:?}: {error}"
            );
        }
    }

    /// Smoke test: the parser must at least accept this statement form. A
    /// `ParseError` means the grammar is unsupported (a real gap); a runtime
    /// `Fail` is an execution gap, not a parser gap, and is tolerated here.
    ///
    /// These tests previously indexed `STATIC_TEST_CASES` by hard-coded position
    /// (`[5]`, `[8]`, `[11]`, `[13]`). Inserting the iterator-protocol and edge
    /// cases shifted every index, so the tests asserted the WRONG category and
    /// failed in `assert_eq!` before the engine ever ran — invisible because the
    /// green gate only compiles this binary. Look the case up by category so the
    /// test is robust to future insertions.
    fn assert_parser_accepts(category: IterationStatementTestCategory) {
        let test_case = IterationStatementConformanceHarness::STATIC_TEST_CASES
            .iter()
            .find(|c| c.category == category)
            .map(IterationStatementTestCase::from)
            .unwrap_or_else(|| panic!("no conformance case for category {category:?}"));
        assert_eq!(test_case.category, category);

        let result = IterationStatementConformanceHarness::execute_test_case(&test_case);
        assert!(
            !matches!(result, IterationStatementResult::ParseError),
            "{category:?} smoke case failed to parse: {:?}",
            test_case.source_code
        );
    }

    /// bd-bg9l1.27.4 / DISC-006: a labelled `break` must escape the named outer
    /// loop. The source nests two `for (;;)` infinite loops that only terminate
    /// if `break outer` targets the outer loop's exit — a regression would hang
    /// or fault rather than eval `Ok`.
    #[test]
    fn labeled_break_escapes_outer_loop() {
        let mut engine = HybridRouter::default();
        assert!(
            engine
                .eval("outer: for (;;) { inner: for (;;) { break outer; } }")
                .is_ok(),
            "labelled break must escape both nested loops"
        );
    }

    /// bd-t7txt / DISC-006b: KNOWN GAP. A labelled `continue` that re-enters an
    /// enclosing loop from inside a nested loop currently faults
    /// (`RuntimeFault: expected function, got string`) because the cross-loop
    /// back-jump does not unwind the operand stack / intervening scopes. This
    /// test pins the current behaviour so the fix flips it to `Ok` loudly.
    #[test]
    fn labeled_continue_cross_loop_now_works() {
        // bd-t7txt RESOLVED: a labelled `continue` that re-enters an outer loop
        // from inside a nested loop now evaluates cleanly (the statement
        // splitter recognises labelled compound statements as block-terminated,
        // so the labelled body no longer absorbs the trailing statement).
        let mut engine = HybridRouter::default();
        let result = engine.eval(
            "let done = false; loop: while (!done) { done = true; \
             for (;;) { continue loop; } } done;",
        );
        assert!(
            result.is_ok(),
            "bd-t7txt: labelled continue across a loop boundary must eval cleanly; got {:?}",
            result.err()
        );
    }

    #[test]
    fn test_for_statement_basic() {
        assert_parser_accepts(IterationStatementTestCategory::ForStatement);
    }

    #[test]
    fn test_for_in_statement() {
        assert_parser_accepts(IterationStatementTestCategory::ForInStatement);
    }

    #[test]
    fn test_for_of_statement() {
        assert_parser_accepts(IterationStatementTestCategory::ForOfStatement);
    }

    #[test]
    fn test_while_statement() {
        assert_parser_accepts(IterationStatementTestCategory::WhileStatement);
    }

    #[test]
    fn test_do_while_statement() {
        assert_parser_accepts(IterationStatementTestCategory::DoWhileStatement);
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

    /// bd-rqev5 (FIND-10): every conformance harness must prove its report
    /// survives a serde_json round-trip and carries the canonical schema pin.
    #[test]
    fn report_round_trips_through_serde_json() {
        let report = IterationStatementConformanceHarness::run_conformance_tests();
        assert_report_json_round_trips(&report, SCHEMA_VERSION, &report.schema_version);
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
        let rate = (coverage.passed * 100)
            .checked_div(coverage.total)
            .unwrap_or(0);
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

    // Exact-gap drift detector for the iteration-statement conformance frontier.
    //
    // This replaces a `>= 95%` MUST pass-rate floor that this de-novo, partial-JS
    // engine cannot currently meet (and that masked per-case regressions and
    // could never account for negative "should-throw" cases an is_ok harness
    // cannot express). Instead, the harness partitions every static case into
    // exactly one of two named buckets:
    //
    // * `EXPECTED_PASS`        — cases the engine currently executes cleanly.
    // * `KNOWN_FAILING_CASES`  — cases held out as frontier gaps, each carrying
    //                            an explicit bead + DISC-NNN reference so the
    //                            gap is grep-able from CI output and
    //                            machine-readable in compliance reports
    //                            (bd-xkbrm FIND-5; cross-ref DISC-001..010 in
    //                            `tests/ECMA262_DISCREPANCIES.md`).
    //
    // The drift detector asserts:
    //
    //   1. Every static case appears in exactly one bucket — no silent omissions.
    //   2. Every `EXPECTED_PASS` id passes (regression → fail).
    //   3. Every `KNOWN_FAILING_CASES` id still fails (gap closed → fail, force
    //      promotion to `EXPECTED_PASS` and a bead/DISC update).
    //
    // The known-gap list with its bead/DISC tags is also printed inline below so
    // CI logs surface the frontier inventory without requiring the reader to
    // chase the DISCREPANCIES.md cross-reference.
    use std::collections::BTreeSet;

    const EXPECTED_PASS: &[&str] = &[
        "break-for-of-early-exit",
        "break-statement-for-loop",
        "continue-for-of-skip",
        "continue-statement-while-loop",
        "do-while-statement-basic",
        "do-while-statement-single-iteration",
        "for-in-statement-basic",
        "for-in-statement-let-declaration",
        "for-in-statement-var-declaration",
        "for-of-array-iterator-simple",
        "for-of-custom-iterator-basic",
        "for-of-destructuring-basic",
        "for-of-destructuring-defaults",
        "for-of-destructuring-nested",
        "for-of-destructuring-rest",
        "for-of-iterator-return-method",
        "for-of-iterator-throw-handling",
        "for-of-statement-array",
        "for-of-statement-basic",
        "for-of-statement-const-declaration",
        "for-statement-basic",
        "for-statement-block-scope-isolation",
        "for-statement-const-declaration",
        "for-statement-empty-body",
        "for-statement-empty-parts",
        "for-statement-let-declaration",
        "for-statement-var-declaration",
        "labeled-break-statement",
        "labeled-continue-statement",
        "while-statement-basic",
        "while-statement-complex-condition",
        "while-statement-empty-body",
    ];

    /// 2 frontier iteration-statement cases the engine currently does NOT pass.
    /// (Was 14; bd-bg9l1.27.1 resolved the `//` comment-leak — DISC-001 — which
    /// unblocked `continue-for-of-skip` and the three `for-of-destructuring-*`
    /// cases; bd-bg9l1.27.4 + bd-t7txt added labelled `break`/`continue` —
    /// DISC-006/006b — promoting `labeled-break-statement` and
    /// `labeled-continue-statement` (the statement splitter now treats a
    /// labelled compound statement as block-terminated); bd-bg9l1.27.9 wired
    /// `Array.prototype.push` as a receiver-aware `CallMethod` builtin — DISC-012 —
    /// promoting `break-for-of-early-exit`; bd-um9a3 implemented `++`/`--`
    /// write-back, which let `for (let i...; i++)` loops terminate — promoting
    /// `for-statement-block-scope-isolation` to `EXPECTED_PASS` (DISC-010: the
    /// engine already creates a fresh per-iteration binding, confirmed by closures
    /// capturing distinct 0,1,2). The same `++`/`--` fix flipped
    /// `for-statement-let-tdz` to an is_ok `Pass` — but that case is a NEGATIVE
    /// "should throw ReferenceError" case the is_ok harness cannot credit, so it
    /// moved to `HARNESS_BLIND_SHOULD_THROW`, not `EXPECTED_PASS`. bd-bg9l1.27.3
    /// recognized `Symbol.iterator` at lowering as the canonical `"@@iterator"`
    /// key — DISC-003 — promoting `for-of-custom-iterator-basic`; the same fix
    /// unblocked `for-of-iterator-return-method` (DISC-009 return-on-break:
    /// custom-iterator dispatch + `iterator.return()` on early exit already
    /// worked, they were gated only on `Symbol.iterator` resolving). bd-bg9l1.27.7
    /// then routed a throw from the iterator's `next()` through the enclosing
    /// try/catch (ForOfNext re-routes the exception that `invoke_inline_method_call`
    /// captures) and declared function-body builtin capabilities, promoting
    /// `for-of-iterator-throw-handling`. That repaired next-error catchability,
    /// not IteratorClose. bd-cu3sz later closed on loop-head assignment failure;
    /// bd-g73mg completed DISC-009 for body Throw, function Return, and labelled
    /// exits while keeping next/value failure and natural exhaustion non-closing.
    /// Each entry pairs the test id with the tracking bead and the
    /// `ECMA262_DISCREPANCIES.md` row that documents the gap (bd-xkbrm FIND-5).
    /// Keep alphabetised by test id. When the engine repairs a gap, move the id
    /// into `EXPECTED_PASS`, drop the entry here, and flip the cited DISC row to
    /// `Status: RESOLVED`.
    const KNOWN_FAILING_CASES: &[(&str, &str, &str)] = &[
        // (test_id, tracking_bead, discrepancies_row)
        (
            "unlabeled-break-error",
            "bd-bg9l1.27.6",
            "DISC-008 (bare break/continue outside loop)",
        ),
        (
            "unlabeled-continue-error",
            "bd-bg9l1.27.6",
            "DISC-008 (bare break/continue outside loop)",
        ),
    ];

    /// NEGATIVE "should-throw" cases the is_ok harness CANNOT credit.
    ///
    /// `execute_test_case` scores `Pass` iff `engine.eval()` returns `Ok`. For a
    /// case whose spec requirement is *throw a ReferenceError* (or other error),
    /// an is_ok `Pass` is meaningless — and usually a FALSE pass: the engine
    /// returned `Ok` precisely because it did NOT throw. Such a case can be
    /// neither `EXPECTED_PASS` (that would assert the wrong, non-throwing
    /// behaviour) nor `KNOWN_FAILING_CASES` (Invariant 3 trips the moment the
    /// engine returns `Ok`, demanding a promotion that would be wrong). It lives
    /// here instead: excluded from Invariants 2 and 3, with the real gap tracked
    /// by the cited bead/DISC and verified out-of-band (e.g. static-semantics unit
    /// tests). See the §"Exact-gap drift detector" note that an is_ok harness can
    /// never express negative should-throw expectations.
    ///
    /// `for-statement-let-tdz` (`for (let x = (x = 1); ...)` — must throw a TDZ
    /// ReferenceError): static rejection landed in 8ed0e8f4 (bd-bg9l1.27.5,
    /// verified via static_semantics tests), but it is not enforced on the
    /// `HybridRouter::eval` register path, so `eval` returns `Ok`. The bd-um9a3
    /// `++`/`--` fix removed the prior incidental "budget exhausted" error, which
    /// is why this surfaced now. Runtime TDZ enforcement remains the open gap.
    const HARNESS_BLIND_SHOULD_THROW: &[(&str, &str, &str)] = &[
        // (test_id, tracking_bead, discrepancies_row)
        (
            "for-statement-let-tdz",
            "bd-bg9l1.27.5",
            "DISC-007 (let TDZ — runtime enforcement; static done in 8ed0e8f4)",
        ),
    ];

    // Surface the frontier inventory in CI output so reviewers don't have to
    // grep tests/ECMA262_DISCREPANCIES.md to know what's still red.
    println!("\nKnown failing cases (bd-xkbrm — see tests/ECMA262_DISCREPANCIES.md):");
    for (id, bead, disc) in KNOWN_FAILING_CASES {
        println!("  {id}  [{bead}]  {disc}");
    }
    println!(
        "\nHarness-blind should-throw cases (is_ok harness cannot credit — see DISCREPANCIES.md):"
    );
    for (id, bead, disc) in HARNESS_BLIND_SHOULD_THROW {
        println!("  {id}  [{bead}]  {disc}");
    }

    let expected_pass: BTreeSet<&str> = EXPECTED_PASS.iter().copied().collect();
    let harness_blind: BTreeSet<&str> = HARNESS_BLIND_SHOULD_THROW
        .iter()
        .map(|(id, _, _)| *id)
        .collect();
    let expected_fail: BTreeSet<&str> = KNOWN_FAILING_CASES.iter().map(|(id, _, _)| *id).collect();
    let actual_pass: BTreeSet<&str> = IterationStatementConformanceHarness::STATIC_TEST_CASES
        .iter()
        .filter(|test_case| {
            matches!(
                report.test_results.get(test_case.id),
                Some(IterationStatementResult::Pass)
            )
        })
        .map(|test_case| test_case.id)
        .collect();
    let all_ids: BTreeSet<&str> = IterationStatementConformanceHarness::STATIC_TEST_CASES
        .iter()
        .map(|test_case| test_case.id)
        .collect();

    let classified: BTreeSet<&str> = expected_pass
        .union(&expected_fail)
        .copied()
        .chain(harness_blind.iter().copied())
        .collect();

    // Invariant 1: every static case is in exactly one of the three buckets.
    let overlap: Vec<&str> = expected_pass
        .intersection(&expected_fail)
        .copied()
        .chain(expected_pass.intersection(&harness_blind).copied())
        .chain(expected_fail.intersection(&harness_blind).copied())
        .collect();
    assert!(
        overlap.is_empty(),
        "bd-xkbrm: cases listed in more than one of EXPECTED_PASS / KNOWN_FAILING_CASES / HARNESS_BLIND_SHOULD_THROW (must be in exactly one): {overlap:?}"
    );
    let unclassified: Vec<&str> = all_ids.difference(&classified).copied().collect();
    assert!(
        unclassified.is_empty(),
        "bd-xkbrm: static cases missing from EXPECTED_PASS / KNOWN_FAILING_CASES / HARNESS_BLIND_SHOULD_THROW (silent omission is the bug this gate was added to prevent): {unclassified:?}"
    );
    let stale: Vec<&str> = classified.difference(&all_ids).copied().collect();
    assert!(
        stale.is_empty(),
        "bd-xkbrm: EXPECTED_PASS / KNOWN_FAILING_CASES / HARNESS_BLIND_SHOULD_THROW reference test ids that no longer exist in STATIC_TEST_CASES — prune them: {stale:?}"
    );

    // Invariant 2: every EXPECTED_PASS id still passes.
    let newly_failing: Vec<&str> = expected_pass.difference(&actual_pass).copied().collect();
    assert!(
        newly_failing.is_empty(),
        "REGRESSION: iteration cases that used to execute cleanly now fail: {newly_failing:?}"
    );

    // Invariant 3: every KNOWN_FAILING_CASES id still fails — if one started
    // passing, promote it to EXPECTED_PASS and update the cited DISC row.
    let gap_closed: Vec<&str> = expected_fail.intersection(&actual_pass).copied().collect();
    assert!(
        gap_closed.is_empty(),
        "PROGRESS (bd-xkbrm): KNOWN_FAILING_CASES entries now pass — promote them to EXPECTED_PASS \
         and flip the cited DISC row in tests/ECMA262_DISCREPANCIES.md to RESOLVED: {gap_closed:?}"
    );

    // Invariant 2b: any case outside both EXPECTED_PASS and KNOWN_FAILING_CASES
    // that now passes is a brand-new uncatalogued case the harness forgot to
    // classify. Should fail loudly so the partition stays exhaustive.
    let uncatalogued_pass: Vec<&str> = actual_pass.difference(&classified).copied().collect();
    assert!(
        uncatalogued_pass.is_empty(),
        "bd-xkbrm: uncatalogued cases pass — add them to EXPECTED_PASS or KNOWN_FAILING_CASES: {uncatalogued_pass:?}"
    );
}
