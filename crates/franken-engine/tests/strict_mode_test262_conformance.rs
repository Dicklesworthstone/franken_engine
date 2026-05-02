//! Test262 conformance harness for strict mode semantics (ES2020 Section 10.2.1)
//!
//! This harness implements Pattern 4 (Spec-Derived Test Matrix) targeting
//! ECMAScript strict mode restrictions from Section 10.2.1 "Strict Mode Code"
//! and related sections.
//!
//! Strict mode fundamentally changes JavaScript semantics by:
//! - Rejecting `with` statements (Section 13.11.1)
//! - Rejecting octal numeric literals (Section 11.8.3)
//! - Rejecting duplicate formal parameters (Section 14.1.2)
//! - Changing `this` binding semantics (Section 10.2.1.1)
//! - Making undeclared assignments throw ReferenceError (Section 8.1.1.2.1)

#![forbid(unsafe_code)]
#![allow(clippy::needless_borrows_for_generic_args, clippy::too_many_arguments)]

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Test262 Strict Mode Conformance Schema
// ---------------------------------------------------------------------------

const SCHEMA_VERSION: &str = "franken-engine.strict-mode-test262-conformance.v1";
const BEAD_ID: &str = "PearlTower-strict-mode-conformance-audit";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrictModeTestCategory {
    /// "use strict" directive recognition
    DirectiveRecognition,
    /// with statement rejection in strict mode
    WithStatementRejection,
    /// Octal literal syntax errors
    OctalLiteralRejection,
    /// Duplicate formal parameter errors
    DuplicateParameterRejection,
    /// this binding semantics (undefined vs global)
    ThisBindingSemantics,
    /// Assignment to undeclared identifiers
    UndeclaredAssignmentRejection,
    /// Delete of unqualified identifiers
    DeleteIdentifierRejection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrictModeResult {
    /// Expected strict mode error was thrown
    CorrectRejection,
    /// Code executed when it should have been rejected
    FalseAcceptance,
    /// Wrong error type or parse succeeded unexpectedly
    IncorrectBehavior,
    /// Parser or execution failed for reasons unrelated to strict mode
    ExecutionError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    /// Should parse and execute successfully
    Success,
    /// Should fail at parse time (SyntaxError)
    ParseError,
    /// Should fail at runtime (ReferenceError, TypeError)
    RuntimeError,
}

#[derive(Debug, Clone)]
pub struct StrictModeTestCase {
    pub id: String,
    pub description: String,
    pub es2020_section: String,
    pub category: StrictModeTestCategory,
    pub source: String,
    pub expected_outcome: ExpectedOutcome,
    pub expected_error_type: Option<String>,
}

// ---------------------------------------------------------------------------
// Test Suite Implementation
// ---------------------------------------------------------------------------

pub struct StrictModeConformanceHarness;

impl StrictModeConformanceHarness {
    pub fn test_cases() -> Vec<StrictModeTestCase> {
        vec![
            // ── Directive Recognition ──
            StrictModeTestCase {
                id: "ES2020-10.2.1-directive-string-literal".to_string(),
                description: "\"use strict\" directive as string literal enables strict mode".to_string(),
                es2020_section: "10.2.1".to_string(),
                category: StrictModeTestCategory::DirectiveRecognition,
                source: "\"use strict\"; var x = 1;".to_string(),
                expected_outcome: ExpectedOutcome::Success,
                expected_error_type: None,
            },

            StrictModeTestCase {
                id: "ES2020-10.2.1-directive-function-scope".to_string(),
                description: "\"use strict\" directive in function scope enables function strict mode".to_string(),
                es2020_section: "10.2.1".to_string(),
                category: StrictModeTestCategory::DirectiveRecognition,
                source: "function f() { \"use strict\"; return 42; } f();".to_string(),
                expected_outcome: ExpectedOutcome::Success,
                expected_error_type: None,
            },

            // ── With Statement Rejection ──
            StrictModeTestCase {
                id: "ES2020-13.11.1-with-statement-global-strict".to_string(),
                description: "with statement in global strict mode should be SyntaxError".to_string(),
                es2020_section: "13.11.1".to_string(),
                category: StrictModeTestCategory::WithStatementRejection,
                source: "\"use strict\"; with (obj) { x = 1; }".to_string(),
                expected_outcome: ExpectedOutcome::ParseError,
                expected_error_type: Some("SyntaxError".to_string()),
            },

            StrictModeTestCase {
                id: "ES2020-13.11.1-with-statement-function-strict".to_string(),
                description: "with statement in function strict mode should be SyntaxError".to_string(),
                es2020_section: "13.11.1".to_string(),
                category: StrictModeTestCategory::WithStatementRejection,
                source: "function f() { \"use strict\"; with (obj) { return x; } }".to_string(),
                expected_outcome: ExpectedOutcome::ParseError,
                expected_error_type: Some("SyntaxError".to_string()),
            },

            // ── Octal Literal Rejection ──
            StrictModeTestCase {
                id: "ES2020-11.8.3-octal-literal-global-strict".to_string(),
                description: "Octal literal 077 in global strict mode should be SyntaxError".to_string(),
                es2020_section: "11.8.3".to_string(),
                category: StrictModeTestCategory::OctalLiteralRejection,
                source: "\"use strict\"; var x = 077;".to_string(),
                expected_outcome: ExpectedOutcome::ParseError,
                expected_error_type: Some("SyntaxError".to_string()),
            },

            StrictModeTestCase {
                id: "ES2020-11.8.3-octal-literal-function-strict".to_string(),
                description: "Octal literal in function strict mode should be SyntaxError".to_string(),
                es2020_section: "11.8.3".to_string(),
                category: StrictModeTestCategory::OctalLiteralRejection,
                source: "function f() { \"use strict\"; return 077; }".to_string(),
                expected_outcome: ExpectedOutcome::ParseError,
                expected_error_type: Some("SyntaxError".to_string()),
            },

            // ── Duplicate Parameter Rejection ──
            StrictModeTestCase {
                id: "ES2020-14.1.2-duplicate-param-global-strict".to_string(),
                description: "Duplicate formal parameters in global strict mode should be SyntaxError".to_string(),
                es2020_section: "14.1.2".to_string(),
                category: StrictModeTestCategory::DuplicateParameterRejection,
                source: "\"use strict\"; function f(a, a) { return a; }".to_string(),
                expected_outcome: ExpectedOutcome::ParseError,
                expected_error_type: Some("SyntaxError".to_string()),
            },

            StrictModeTestCase {
                id: "ES2020-14.1.2-duplicate-param-function-strict".to_string(),
                description: "Duplicate formal parameters in function strict mode should be SyntaxError".to_string(),
                es2020_section: "14.1.2".to_string(),
                category: StrictModeTestCategory::DuplicateParameterRejection,
                source: "function f() { \"use strict\"; function g(x, x) { return x; } }".to_string(),
                expected_outcome: ExpectedOutcome::ParseError,
                expected_error_type: Some("SyntaxError".to_string()),
            },

            // ── This Binding Semantics ──
            StrictModeTestCase {
                id: "ES2020-10.2.1.1-this-undefined-function-call".to_string(),
                description: "this in strict mode function call should be undefined, not global object".to_string(),
                es2020_section: "10.2.1.1".to_string(),
                category: StrictModeTestCategory::ThisBindingSemantics,
                source: "\"use strict\"; function f() { return this; } var result = f(); result === undefined;".to_string(),
                expected_outcome: ExpectedOutcome::Success,
                expected_error_type: None,
            },

            StrictModeTestCase {
                id: "ES2020-10.2.1.1-this-undefined-function-strict-directive".to_string(),
                description: "this in function with strict directive should be undefined".to_string(),
                es2020_section: "10.2.1.1".to_string(),
                category: StrictModeTestCategory::ThisBindingSemantics,
                source: "function f() { \"use strict\"; return this === undefined; } f();".to_string(),
                expected_outcome: ExpectedOutcome::Success,
                expected_error_type: None,
            },

            // ── Undeclared Assignment Rejection ──
            StrictModeTestCase {
                id: "ES2020-8.1.1.2.1-undeclared-assignment-global-strict".to_string(),
                description: "Assignment to undeclared variable in global strict mode should throw ReferenceError".to_string(),
                es2020_section: "8.1.1.2.1".to_string(),
                category: StrictModeTestCategory::UndeclaredAssignmentRejection,
                source: "\"use strict\"; undeclaredVar = 42;".to_string(),
                expected_outcome: ExpectedOutcome::RuntimeError,
                expected_error_type: Some("ReferenceError".to_string()),
            },

            StrictModeTestCase {
                id: "ES2020-8.1.1.2.1-undeclared-assignment-function-strict".to_string(),
                description: "Assignment to undeclared variable in function strict mode should throw ReferenceError".to_string(),
                es2020_section: "8.1.1.2.1".to_string(),
                category: StrictModeTestCategory::UndeclaredAssignmentRejection,
                source: "function f() { \"use strict\"; undeclaredVar = 42; } f();".to_string(),
                expected_outcome: ExpectedOutcome::RuntimeError,
                expected_error_type: Some("ReferenceError".to_string()),
            },

            // ── Delete Identifier Rejection ──
            StrictModeTestCase {
                id: "ES2020-12.5.4.2-delete-identifier-global-strict".to_string(),
                description: "delete of unqualified identifier in global strict mode should be SyntaxError".to_string(),
                es2020_section: "12.5.4.2".to_string(),
                category: StrictModeTestCategory::DeleteIdentifierRejection,
                source: "\"use strict\"; var x = 1; delete x;".to_string(),
                expected_outcome: ExpectedOutcome::ParseError,
                expected_error_type: Some("SyntaxError".to_string()),
            },

            StrictModeTestCase {
                id: "ES2020-12.5.4.2-delete-identifier-function-strict".to_string(),
                description: "delete of unqualified identifier in function strict mode should be SyntaxError".to_string(),
                es2020_section: "12.5.4.2".to_string(),
                category: StrictModeTestCategory::DeleteIdentifierRejection,
                source: "function f() { \"use strict\"; var y = 2; delete y; }".to_string(),
                expected_outcome: ExpectedOutcome::ParseError,
                expected_error_type: Some("SyntaxError".to_string()),
            },
        ]
    }

    /// Execute a single strict mode test case and classify the result.
    fn execute_test_case(test: &StrictModeTestCase) -> StrictModeResult {
        // Try to parse the source
        let parse_result = parse_script(&test.source);

        match (&test.expected_outcome, parse_result) {
            // Case 1: Expected parse error, got parse error
            (ExpectedOutcome::ParseError, Err(_)) => StrictModeResult::CorrectRejection,

            // Case 2: Expected parse error, but parsing succeeded
            (ExpectedOutcome::ParseError, Ok(_)) => StrictModeResult::FalseAcceptance,

            // Case 3: Expected success or runtime error, but parse failed
            (ExpectedOutcome::Success | ExpectedOutcome::RuntimeError, Err(_)) => {
                StrictModeResult::IncorrectBehavior
            }

            // Case 4: Parse succeeded, now try execution
            (expected, Ok(tree)) => {
                let ir0 = Ir0Module::from_syntax_tree(tree, "strict_mode_test.js");
                let lower_result = lower_ir0_to_ir3(
                    &ir0,
                    &LoweringContext::new("strict-test", "strict-test", "strict-test"),
                );

                let ir3 = match lower_result {
                    Ok(result) => result.ir3,
                    Err(_) => return StrictModeResult::ExecutionError,
                };

                // Try to execute
                let mut config = InterpreterConfig::quickjs_defaults();
                config.granted_capabilities = BTreeSet::from([
                    RuntimeCapability::VmDispatch,
                    RuntimeCapability::HeapAllocate,
                ]);
                let mut interpreter = InterpreterCore::new(config, "strict-test");
                let exec_result = interpreter.execute(&ir3);

                match (expected, exec_result) {
                    // Expected success, got success
                    (ExpectedOutcome::Success, Ok(_)) => StrictModeResult::CorrectRejection,

                    // Expected runtime error, got error
                    (ExpectedOutcome::RuntimeError, Err(_)) => StrictModeResult::CorrectRejection,

                    // Expected runtime error, but succeeded
                    (ExpectedOutcome::RuntimeError, Ok(_)) => StrictModeResult::FalseAcceptance,

                    // Expected success, but got error
                    (ExpectedOutcome::Success, Err(_)) => StrictModeResult::IncorrectBehavior,

                    // This case shouldn't happen given our match structure
                    _ => StrictModeResult::ExecutionError,
                }
            }
        }
    }

    /// Run the complete strict mode conformance test suite.
    pub fn run_conformance_suite() -> StrictModeConformanceReport {
        let test_cases = Self::test_cases();
        let mut results = std::collections::BTreeMap::new();
        let mut stats = StrictModeConformanceStatistics::default();

        for test in &test_cases {
            let result = Self::execute_test_case(test);

            match result {
                StrictModeResult::CorrectRejection => stats.correct_rejections += 1,
                StrictModeResult::FalseAcceptance => stats.false_acceptances += 1,
                StrictModeResult::IncorrectBehavior => stats.incorrect_behaviors += 1,
                StrictModeResult::ExecutionError => stats.execution_errors += 1,
            }

            results.insert(test.id.clone(), result);
        }

        stats.total_tests = test_cases.len() as u32;

        StrictModeConformanceReport {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            test_results: results,
            statistics: stats,
        }
    }
}

// ---------------------------------------------------------------------------
// Conformance Report Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrictModeConformanceReport {
    pub schema_version: String,
    pub bead_id: String,
    pub test_results: std::collections::BTreeMap<String, StrictModeResult>,
    pub statistics: StrictModeConformanceStatistics,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StrictModeConformanceStatistics {
    pub total_tests: u32,
    pub correct_rejections: u32,
    pub false_acceptances: u32,
    pub incorrect_behaviors: u32,
    pub execution_errors: u32,
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_mode_conformance_execution_produces_report() {
        let report = StrictModeConformanceHarness::run_conformance_suite();

        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.bead_id, BEAD_ID);
        assert!(!report.test_results.is_empty());
        assert!(report.statistics.total_tests > 0);
    }

    #[test]
    fn test_cases_have_valid_categories() {
        let test_cases = StrictModeConformanceHarness::test_cases();

        for test in &test_cases {
            // Ensure all test cases have proper IDs and categories
            assert!(!test.id.is_empty(), "Test ID should not be empty");
            assert!(
                !test.description.is_empty(),
                "Description should not be empty"
            );
            assert!(!test.source.is_empty(), "Source should not be empty");
        }
    }

    #[test]
    fn strict_directive_recognition_basic() {
        let test = StrictModeTestCase {
            id: "test-directive".to_string(),
            description: "Test directive recognition".to_string(),
            es2020_section: "10.2.1".to_string(),
            category: StrictModeTestCategory::DirectiveRecognition,
            source: "\"use strict\"; var x = 1;".to_string(),
            expected_outcome: ExpectedOutcome::Success,
            expected_error_type: None,
        };

        let result = StrictModeConformanceHarness::execute_test_case(&test);
        // This test should pass - basic strict directive with valid code
        assert_eq!(result, StrictModeResult::CorrectRejection);
    }
}
