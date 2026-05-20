#![forbid(unsafe_code)]

//! Conformance harness for ES2020 destructuring binding patterns (bd-7fi86)
//!
//! Pattern 4 (spec-derived test matrix). Each case is a small `console.log`
//! fixture that drives a destructuring form through HybridRouter::eval and
//! asserts the printed output, using the shared `_support::test262_common`
//! plumbing so this harness matches the optional_chaining / iteration /
//! template_literal harnesses already in tree.
//!
//! Coverage targets (ES2020 §13.3.3 BindingPattern and §13.3.3.6 Runtime
//! Semantics: BindingInitialization):
//!
//! - ArrayBasic       — `[a, b] = [1, 2]`
//! - ArrayHole        — `[, b] = [1, 2]` (elision)
//! - ArrayRest        — `[a, ...rest] = [1, 2, 3]`
//! - ArrayDefault     — `[a = 5] = [undefined]`
//! - ObjectBasic      — `{ a, b } = { a: 1, b: 2 }`
//! - ObjectAlias      — `{ a: x } = { a: 1 }`
//! - ObjectDefault    — `{ a = 5 } = {}`
//! - ObjectRest       — `{ a, ...rest } = { a: 1, b: 2, c: 3 }`
//! - NestedPattern    — `[{ a }, { b }] = [{ a: 1 }, { b: 2 }]`
//! - ParameterPattern — `function f({ a, b }) { ... }`
//! - InvalidLValue    — `[1] = [2]` (numeric literal as binding target)
//!
//! Schema: `franken-engine.destructuring-binding-test262.v1`
//! Bead: PearlTower-destructuring-binding-conformance-audit (bd-7fi86)

use std::collections::BTreeMap;

use frankenengine_engine::HybridRouter;
use serde::{Deserialize, Serialize};

mod _support;
use _support::test262_common::{
    ExpectedResult, RequirementLevel, Test262Result, evaluate_test262_result,
};

pub const DESTRUCTURING_BINDING_CONFORMANCE_SCHEMA: &str =
    "franken-engine.destructuring-binding-test262.v1";
pub const DESTRUCTURING_BINDING_BEAD_ID: &str =
    "PearlTower-destructuring-binding-conformance-audit";

// ---------------------------------------------------------------------------
// Taxonomy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestructuringCategory {
    ArrayBasic,
    ArrayHole,
    ArrayRest,
    ArrayDefault,
    ObjectBasic,
    ObjectAlias,
    ObjectDefault,
    ObjectRest,
    NestedPattern,
    ParameterPattern,
    InvalidLValue,
}

#[derive(Debug, Clone)]
pub struct DestructuringTestCase {
    pub id: &'static str,
    pub description: &'static str,
    pub es2020_section: &'static str,
    pub requirement_level: RequirementLevel,
    pub category: DestructuringCategory,
    pub source: &'static str,
    pub expected_result: ExpectedResult,
}

// ---------------------------------------------------------------------------
// Test matrix — 12 cases
// ---------------------------------------------------------------------------

fn destructuring_cases() -> Vec<DestructuringTestCase> {
    vec![
        DestructuringTestCase {
            id: "ES2020-13.3.3-array-basic",
            description: "Basic array destructuring binds positional elements",
            es2020_section: "13.3.3.6",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::ArrayBasic,
            source: "var [a, b] = [1, 2]; console.log(a + ',' + b);",
            expected_result: ExpectedResult::Success {
                output: "1,2".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-13.3.3-array-hole",
            description: "Elision skips array elements (binding pattern with holes)",
            es2020_section: "13.3.3.6",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::ArrayHole,
            source: "var [, b, , d] = [1, 2, 3, 4]; console.log(b + ',' + d);",
            expected_result: ExpectedResult::Success {
                output: "2,4".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-13.3.3-array-rest",
            description: "Rest element collects trailing array elements as a fresh Array",
            es2020_section: "13.3.3.7",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::ArrayRest,
            source: "var [a, ...rest] = [1, 2, 3]; console.log(a + ',' + rest.length);",
            expected_result: ExpectedResult::Success {
                output: "1,2".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-13.3.3-array-default-on-undefined",
            description: "Default initializer fires when the destructured value is undefined",
            es2020_section: "13.3.3.6",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::ArrayDefault,
            source: "var [a = 5, b = 6] = [undefined, 7]; console.log(a + ',' + b);",
            expected_result: ExpectedResult::Success {
                output: "5,7".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-13.3.3-object-basic",
            description: "Object destructuring binds same-named properties",
            es2020_section: "13.3.3.7",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::ObjectBasic,
            source: "var { a, b } = { a: 1, b: 2 }; console.log(a + ',' + b);",
            expected_result: ExpectedResult::Success {
                output: "1,2".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-13.3.3-object-alias",
            description: "Object destructuring binds aliased property under chosen identifier",
            es2020_section: "13.3.3.7",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::ObjectAlias,
            source: "var { a: x, b: y } = { a: 1, b: 2 }; console.log(x + ',' + y);",
            expected_result: ExpectedResult::Success {
                output: "1,2".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-13.3.3-object-default",
            description: "Object destructuring fills missing property from default initializer",
            es2020_section: "13.3.3.7",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::ObjectDefault,
            source: "var { a = 5, b = 6 } = { a: 1 }; console.log(a + ',' + b);",
            expected_result: ExpectedResult::Success {
                output: "1,6".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-13.3.3-object-rest",
            description: "Object rest collects the remaining properties into a fresh object",
            es2020_section: "13.3.3.7",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::ObjectRest,
            source: "var { a, ...rest } = { a: 1, b: 2, c: 3 }; console.log(a + ',' + rest.b + ',' + rest.c);",
            expected_result: ExpectedResult::Success {
                output: "1,2,3".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-13.3.3-nested-pattern",
            description: "Nested destructuring composes object and array patterns",
            es2020_section: "13.3.3.6",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::NestedPattern,
            source: "var [{ a }, { b }] = [{ a: 1 }, { b: 2 }]; console.log(a + ',' + b);",
            expected_result: ExpectedResult::Success {
                output: "1,2".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-14.1.20-parameter-object-pattern",
            description: "Function parameter accepts an object destructuring pattern",
            es2020_section: "14.1.20",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::ParameterPattern,
            source: "function f({ a, b }) { return a + b; } console.log(f({ a: 3, b: 4 }));",
            expected_result: ExpectedResult::Success {
                output: "7".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-14.1.20-parameter-array-pattern",
            description: "Function parameter accepts an array destructuring pattern",
            es2020_section: "14.1.20",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::ParameterPattern,
            source: "function g([x, y]) { return x * y; } console.log(g([3, 4]));",
            expected_result: ExpectedResult::Success {
                output: "12".to_string(),
            },
        },
        DestructuringTestCase {
            id: "ES2020-13.3.3-invalid-numeric-lvalue",
            description: "Numeric literal in binding-pattern position is a SyntaxError",
            es2020_section: "13.3.3",
            requirement_level: RequirementLevel::Must,
            category: DestructuringCategory::InvalidLValue,
            source: "var [1] = [2];",
            expected_result: ExpectedResult::SyntaxError {
                error_type: "SyntaxError".to_string(),
            },
        },
    ]
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn execute_case(case: &DestructuringTestCase) -> Test262Result {
    let mut engine = HybridRouter::default();
    let outcome = engine.eval(case.source);
    evaluate_test262_result(outcome, &case.expected_result, case.id)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DestructuringStatistics {
    pub total_tests: u32,
    pub passes: u32,
    pub fails: u32,
    pub errors: u32,
    pub skips: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestructuringReport {
    pub schema_version: String,
    pub bead_id: String,
    pub case_results: BTreeMap<String, String>,
    pub statistics: DestructuringStatistics,
}

fn run_conformance_suite() -> DestructuringReport {
    let cases = destructuring_cases();
    let mut case_results = BTreeMap::new();
    let mut statistics = DestructuringStatistics::default();

    for case in &cases {
        let result = execute_case(case);
        let label = match &result {
            Test262Result::Pass => "pass".to_string(),
            Test262Result::Fail { .. } => "fail".to_string(),
            Test262Result::Error { .. } => "error".to_string(),
            Test262Result::Skip { .. } => "skip".to_string(),
        };
        match &result {
            Test262Result::Pass => statistics.passes += 1,
            Test262Result::Fail { .. } => statistics.fails += 1,
            Test262Result::Error { .. } => statistics.errors += 1,
            Test262Result::Skip { .. } => statistics.skips += 1,
        }
        case_results.insert(case.id.to_string(), label);
    }
    statistics.total_tests = u32::try_from(cases.len()).unwrap_or(u32::MAX);

    DestructuringReport {
        schema_version: DESTRUCTURING_BINDING_CONFORMANCE_SCHEMA.to_string(),
        bead_id: DESTRUCTURING_BINDING_BEAD_ID.to_string(),
        case_results,
        statistics,
    }
}

// ---------------------------------------------------------------------------
// Known divergences — populated empirically on the day the harness was authored.
// Each entry is a case id where the current engine output does not match the
// ES2020 expectation. The regression test below tolerates exactly this set and
// fails on any new divergence OR any catalogued gap that has been silently
// closed (which would invalidate the cataloguing). Drift is filed under bd-7fi86.
// ---------------------------------------------------------------------------

const KNOWN_DESTRUCTURING_GAPS: &[&str] = &[
    // bd-hld87: object-rest target not initialised to {} before collection;
    // runtime faults with "expected object, got undefined".
    "ES2020-13.3.3-object-rest",
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn destructuring_cases_have_unique_ids_and_descriptions() {
    let cases = destructuring_cases();
    let mut ids = std::collections::BTreeSet::new();
    for case in &cases {
        assert!(!case.id.is_empty(), "case id must be non-empty");
        assert!(
            !case.description.is_empty(),
            "case description must be non-empty"
        );
        assert!(!case.source.is_empty(), "case source must be non-empty");
        assert!(
            !case.es2020_section.is_empty(),
            "case es2020_section must be non-empty"
        );
        assert!(
            ids.insert(case.id.to_string()),
            "duplicate case id: {}",
            case.id
        );
    }
    assert!(
        cases.len() >= 8,
        "matrix must cover at least 8 destructuring categories, found {}",
        cases.len()
    );
}

#[test]
fn destructuring_categories_cover_all_axes() {
    let mut categories = std::collections::BTreeSet::new();
    for case in destructuring_cases() {
        categories.insert(case.category);
    }
    for required in [
        DestructuringCategory::ArrayBasic,
        DestructuringCategory::ArrayHole,
        DestructuringCategory::ArrayRest,
        DestructuringCategory::ArrayDefault,
        DestructuringCategory::ObjectBasic,
        DestructuringCategory::ObjectAlias,
        DestructuringCategory::ObjectDefault,
        DestructuringCategory::ObjectRest,
        DestructuringCategory::NestedPattern,
        DestructuringCategory::ParameterPattern,
        DestructuringCategory::InvalidLValue,
    ] {
        assert!(
            categories.contains(&required),
            "matrix missing required category {required:?}"
        );
    }
}

#[test]
fn destructuring_report_round_trip_through_serde() {
    let report = run_conformance_suite();
    assert_eq!(
        report.schema_version,
        DESTRUCTURING_BINDING_CONFORMANCE_SCHEMA
    );
    assert_eq!(report.bead_id, DESTRUCTURING_BINDING_BEAD_ID);
    assert_eq!(
        report.statistics.total_tests,
        report.statistics.passes
            + report.statistics.fails
            + report.statistics.errors
            + report.statistics.skips,
        "case-result counts must sum to total_tests"
    );

    let json = serde_json::to_string(&report).expect("report should serialize");
    let round_trip: DestructuringReport =
        serde_json::from_str(&json).expect("report should deserialize");
    assert_eq!(round_trip.schema_version, report.schema_version);
    assert_eq!(round_trip.bead_id, report.bead_id);
    assert_eq!(
        round_trip.statistics.total_tests,
        report.statistics.total_tests
    );
}

#[test]
fn destructuring_full_matrix_matches_known_gap_set() {
    // Regression probe: the engine is allowed to diverge from the harness
    // only on case ids catalogued in KNOWN_DESTRUCTURING_GAPS. Any new gap
    // fails fast; any catalogued gap that silently closes also fails (forcing
    // the constant to be pruned).
    let report = run_conformance_suite();
    let mut observed_detail: Vec<(String, String)> = Vec::new();
    for case in destructuring_cases() {
        let result = execute_case(&case);
        match &result {
            Test262Result::Pass => {}
            Test262Result::Fail { reason } => {
                observed_detail.push((case.id.to_string(), format!("fail: {reason}")));
            }
            Test262Result::Error { error } => {
                observed_detail.push((case.id.to_string(), format!("error: {error}")));
            }
            Test262Result::Skip { reason } => {
                observed_detail.push((case.id.to_string(), format!("skip: {reason}")));
            }
        }
        // Touch report so it isn't dead.
        let _ = &report.case_results;
    }
    let observed: std::collections::BTreeSet<&str> =
        observed_detail.iter().map(|(id, _)| id.as_str()).collect();
    let expected: std::collections::BTreeSet<&str> =
        KNOWN_DESTRUCTURING_GAPS.iter().copied().collect();
    assert_eq!(
        observed, expected,
        "destructuring gap set drifted from KNOWN_DESTRUCTURING_GAPS (bd-7fi86). \
         If a gap closed, remove it from the constant. \
         If a new gap opened, file or extend the follow-up bead before silencing it. \
         Observed gaps with detail:\n{observed_detail:#?}"
    );
}
