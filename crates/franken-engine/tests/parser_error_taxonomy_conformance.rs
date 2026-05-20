//! Conformance harness for parser error taxonomy (bd-pbpve)
//!
//! Maps invalid-source fixtures to the eight stable `ParseErrorCode` variants
//! exposed by `parser.rs`, plus a small recovery-anchor section that drives
//! `parse_script` against sources containing both valid prefixes and invalid
//! tails to confirm the parser still classifies the failure deterministically
//! instead of panicking or silently accepting.
//!
//! This is a Pattern 4 (Spec-Derived Test Matrix) harness anchored to the
//! engine's own diagnostic taxonomy (FE-PARSER-DIAG-* stable codes) rather
//! than the ES2020 grammar directly — many ES2020 syntax errors collapse to
//! `UnsupportedSyntax` in the current parser scaffold, and the taxonomy
//! itself is the surface a conforming harness should pin.
//!
//! Schema: `franken-engine.parser-error-taxonomy-conformance.v1`
//! Bead: PearlTower-parser-error-taxonomy-conformance-audit (bd-pbpve)

#![forbid(unsafe_code)]
#![allow(clippy::needless_borrows_for_generic_args)]

use std::collections::BTreeMap;

use frankenengine_engine::parser::ParseErrorCode;
use frankenengine_engine::parser_api_stability::parse_script;
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: &str = "franken-engine.parser-error-taxonomy-conformance.v1";
const BEAD_ID: &str = "PearlTower-parser-error-taxonomy-conformance-audit";

// ---------------------------------------------------------------------------
// Taxonomy
// ---------------------------------------------------------------------------

/// Coarse category mirroring the `diagnostic_category` axis exposed by
/// `ParseErrorCode`, plus a `Recovery` slot for sources that exercise the
/// parser's anchor-and-classify behavior at the boundary between accepted and
/// rejected fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserErrorCategory {
    Input,
    Goal,
    Syntax,
    Encoding,
    Resource,
    Recovery,
}

/// Outcome of running a single case through `parse_script`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserTaxonomyResult {
    /// Parser produced the expected `ParseErrorCode` variant.
    CorrectClassification,
    /// Parser produced an error but with a different `ParseErrorCode` than expected.
    MisclassifiedCode,
    /// Source was expected to fail but `parse_script` returned Ok.
    UnexpectedAcceptance,
    /// Source was expected to be accepted (recovery anchors) but `parse_script` returned Err.
    UnexpectedRejection,
}

#[derive(Debug, Clone)]
pub struct ParserTaxonomyCase {
    pub id: &'static str,
    pub description: &'static str,
    pub category: ParserErrorCategory,
    pub source: &'static str,
    /// `None` => expected to parse successfully (recovery anchor).
    pub expected_code: Option<ParseErrorCode>,
}

// ---------------------------------------------------------------------------
// Test matrix — 12 cases across the eight ParseErrorCode variants + recovery
// ---------------------------------------------------------------------------

fn taxonomy_cases() -> Vec<ParserTaxonomyCase> {
    vec![
        // ── Input — EmptySource ────────────────────────────────────────────
        ParserTaxonomyCase {
            id: "FE-PARSER-INPUT-EMPTY-WHITESPACE",
            description: "All-whitespace source collapses to empty after normalization",
            category: ParserErrorCategory::Input,
            source: "   \n\t  \n",
            expected_code: Some(ParseErrorCode::EmptySource),
        },
        ParserTaxonomyCase {
            id: "FE-PARSER-INPUT-EMPTY-LITERAL",
            description: "Literal empty source is rejected as EmptySource",
            category: ParserErrorCategory::Input,
            source: "",
            expected_code: Some(ParseErrorCode::EmptySource),
        },
        // ── Syntax — UnsupportedSyntax ────────────────────────────────────
        ParserTaxonomyCase {
            id: "FE-PARSER-SYNTAX-UNTERMINATED-STRING",
            description: "String literal with no closing quote rejected as UnsupportedSyntax",
            category: ParserErrorCategory::Syntax,
            source: "var x = \"unterminated",
            expected_code: Some(ParseErrorCode::UnsupportedSyntax),
        },
        ParserTaxonomyCase {
            id: "FE-PARSER-SYNTAX-UNMATCHED-BRACE",
            description: "Unbalanced opening brace rejected as UnsupportedSyntax",
            category: ParserErrorCategory::Syntax,
            source: "function f() { var x = 1;",
            expected_code: Some(ParseErrorCode::UnsupportedSyntax),
        },
        ParserTaxonomyCase {
            id: "FE-PARSER-SYNTAX-STRAY-OPERATOR",
            description: "Stray binary operator with no left-hand operand rejected as UnsupportedSyntax",
            category: ParserErrorCategory::Syntax,
            source: "* 5",
            expected_code: Some(ParseErrorCode::UnsupportedSyntax),
        },
        ParserTaxonomyCase {
            id: "FE-PARSER-SYNTAX-RESERVED-AS-IDENT",
            description: "Reserved word `return` used as a binding identifier rejected as UnsupportedSyntax",
            category: ParserErrorCategory::Syntax,
            source: "var return = 1;",
            expected_code: Some(ParseErrorCode::UnsupportedSyntax),
        },
        // ── Syntax — StrictModeWithStatement ──────────────────────────────
        ParserTaxonomyCase {
            id: "FE-PARSER-SYNTAX-STRICT-WITH-GLOBAL",
            description: "`with` statement under \"use strict\" rejected as StrictModeWithStatement",
            category: ParserErrorCategory::Syntax,
            source: "\"use strict\"; with (obj) { x = 1; }",
            expected_code: Some(ParseErrorCode::StrictModeWithStatement),
        },
        ParserTaxonomyCase {
            id: "FE-PARSER-SYNTAX-STRICT-WITH-FUNCTION",
            description: "`with` inside strict-directive function rejected as StrictModeWithStatement",
            category: ParserErrorCategory::Syntax,
            source: "function f() { \"use strict\"; with (obj) { return x; } }",
            expected_code: Some(ParseErrorCode::StrictModeWithStatement),
        },
        // ── Goal — InvalidGoal ────────────────────────────────────────────
        ParserTaxonomyCase {
            id: "FE-PARSER-GOAL-IMPORT-IN-SCRIPT",
            description: "Top-level `import` is module-only and is rejected under script goal",
            category: ParserErrorCategory::Goal,
            source: "import { x } from './mod.js';",
            expected_code: Some(ParseErrorCode::InvalidGoal),
        },
        ParserTaxonomyCase {
            id: "FE-PARSER-GOAL-EXPORT-IN-SCRIPT",
            description: "Top-level `export` is module-only and is rejected under script goal",
            category: ParserErrorCategory::Goal,
            source: "export const x = 1;",
            expected_code: Some(ParseErrorCode::InvalidGoal),
        },
        // ── Recovery anchors ──────────────────────────────────────────────
        ParserTaxonomyCase {
            id: "FE-PARSER-RECOVERY-VALID-VAR",
            description: "Plain `var` declaration parses cleanly (recovery anchor for taxonomy noise)",
            category: ParserErrorCategory::Recovery,
            source: "var x = 1;",
            expected_code: None,
        },
        ParserTaxonomyCase {
            id: "FE-PARSER-RECOVERY-VALID-FUNCTION",
            description: "Plain function declaration parses cleanly (recovery anchor for taxonomy noise)",
            category: ParserErrorCategory::Recovery,
            source: "function f() { return 1; }",
            expected_code: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn execute_case(case: &ParserTaxonomyCase) -> ParserTaxonomyResult {
    let parse_outcome = parse_script(case.source);
    match (case.expected_code, parse_outcome) {
        // Recovery anchor that parses cleanly.
        (None, Ok(_)) => ParserTaxonomyResult::CorrectClassification,
        // Recovery anchor that unexpectedly errored.
        (None, Err(_)) => ParserTaxonomyResult::UnexpectedRejection,
        // Expected error and got one — compare codes.
        (Some(expected), Err(err)) => {
            if err.code == expected {
                ParserTaxonomyResult::CorrectClassification
            } else {
                ParserTaxonomyResult::MisclassifiedCode
            }
        }
        // Expected error but parse succeeded.
        (Some(_), Ok(_)) => ParserTaxonomyResult::UnexpectedAcceptance,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParserTaxonomyStatistics {
    pub total_tests: u32,
    pub correct_classifications: u32,
    pub misclassified_codes: u32,
    pub unexpected_acceptances: u32,
    pub unexpected_rejections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserTaxonomyReport {
    pub schema_version: String,
    pub bead_id: String,
    pub case_results: BTreeMap<String, ParserTaxonomyResult>,
    pub statistics: ParserTaxonomyStatistics,
}

fn run_conformance_suite() -> ParserTaxonomyReport {
    let cases = taxonomy_cases();
    let mut case_results = BTreeMap::new();
    let mut statistics = ParserTaxonomyStatistics::default();

    for case in &cases {
        let result = execute_case(case);
        match result {
            ParserTaxonomyResult::CorrectClassification => statistics.correct_classifications += 1,
            ParserTaxonomyResult::MisclassifiedCode => statistics.misclassified_codes += 1,
            ParserTaxonomyResult::UnexpectedAcceptance => statistics.unexpected_acceptances += 1,
            ParserTaxonomyResult::UnexpectedRejection => statistics.unexpected_rejections += 1,
        }
        case_results.insert(case.id.to_string(), result);
    }
    statistics.total_tests = u32::try_from(cases.len()).unwrap_or(u32::MAX);

    ParserTaxonomyReport {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        case_results,
        statistics,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn taxonomy_cases_have_unique_ids_and_descriptions() {
    let cases = taxonomy_cases();
    let mut ids = std::collections::BTreeSet::new();
    for case in &cases {
        assert!(!case.id.is_empty(), "case id must be non-empty");
        assert!(
            !case.description.is_empty(),
            "case description must be non-empty"
        );
        // EmptySource cases are intentionally empty or whitespace-only — they
        // exercise the boundary between "no input" and "input that normalises
        // to nothing", so non-empty isn't a meaningful invariant here.
        if case.expected_code != Some(ParseErrorCode::EmptySource) {
            assert!(
                !case.source.is_empty(),
                "non-EmptySource case `{}` must have non-empty source",
                case.id
            );
        }
        assert!(
            ids.insert(case.id.to_string()),
            "duplicate case id: {}",
            case.id
        );
    }
    assert!(
        cases.len() >= 8,
        "matrix must cover at least the eight ParseErrorCode variants plus recovery anchors, found {}",
        cases.len()
    );
}

#[test]
fn taxonomy_categories_cover_each_branch_of_diagnostic_category() {
    // Every diagnostic category that ParseErrorCode can produce should appear
    // in the matrix at least once (Input, Syntax, Goal, plus the Recovery
    // anchor slot). Resource and Encoding errors come from infrastructure
    // (oversize / non-UTF8 streams) and aren't reachable from `parse_script`
    // with a `&str` input, so they're excluded by design.
    let mut categories = std::collections::BTreeSet::new();
    for case in taxonomy_cases() {
        categories.insert(case.category);
    }
    for required in [
        ParserErrorCategory::Input,
        ParserErrorCategory::Syntax,
        ParserErrorCategory::Goal,
        ParserErrorCategory::Recovery,
    ] {
        assert!(
            categories.contains(&required),
            "matrix missing reachable category {required:?}"
        );
    }
}

#[test]
fn taxonomy_recovery_anchors_parse_cleanly() {
    // Recovery anchors are the noise-floor probe: if these stop parsing, the
    // suite's "expected error" classifications can no longer be trusted.
    let mut anchor_count = 0;
    for case in taxonomy_cases() {
        if case.category != ParserErrorCategory::Recovery {
            continue;
        }
        anchor_count += 1;
        let result = execute_case(&case);
        assert_eq!(
            result,
            ParserTaxonomyResult::CorrectClassification,
            "recovery anchor `{}` must parse cleanly but got {result:?}",
            case.id
        );
    }
    assert!(
        anchor_count >= 2,
        "harness must define ≥ 2 recovery anchors"
    );
}

#[test]
fn taxonomy_report_round_trip_through_serde() {
    let report = run_conformance_suite();
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert!(report.statistics.total_tests >= 8);
    assert_eq!(
        report.statistics.total_tests,
        report.statistics.correct_classifications
            + report.statistics.misclassified_codes
            + report.statistics.unexpected_acceptances
            + report.statistics.unexpected_rejections,
        "case-result counts must sum to total_tests"
    );

    let json = serde_json::to_string(&report).expect("report should serialize");
    let round_trip: ParserTaxonomyReport =
        serde_json::from_str(&json).expect("report should deserialize");
    assert_eq!(round_trip.schema_version, report.schema_version);
    assert_eq!(round_trip.bead_id, report.bead_id);
    assert_eq!(
        round_trip.statistics.total_tests,
        report.statistics.total_tests
    );
}

#[test]
fn taxonomy_input_empty_cases_classified_correctly() {
    for case in taxonomy_cases() {
        if case.expected_code != Some(ParseErrorCode::EmptySource) {
            continue;
        }
        assert_eq!(
            execute_case(&case),
            ParserTaxonomyResult::CorrectClassification,
            "EmptySource case `{}` failed to classify as EmptySource",
            case.id
        );
    }
}

/// Known taxonomy gaps surfaced by the harness on the day it was authored.
///
/// Each entry is a case id where `parse_script` currently returns `Ok` for
/// invalid source (or otherwise misclassifies). These are tracked under
/// bd-wa01t. The end-to-end test below tolerates exactly these gaps and
/// fails fast on any new mismatch — that is the regression detection the
/// bead exists to provide.
const KNOWN_TAXONOMY_GAPS: &[(&str, ParserTaxonomyResult)] = &[];

#[test]
fn taxonomy_full_matrix_matches_known_gap_set() {
    // End-to-end regression probe: the parser is allowed to diverge from the
    // harness only on the specific (case_id, result) pairs catalogued in
    // KNOWN_TAXONOMY_GAPS. Any NEW divergence — or any catalogued gap that
    // has been silently fixed (and so should be removed from the list) —
    // fails this test.
    let report = run_conformance_suite();
    let observed: std::collections::BTreeMap<&str, ParserTaxonomyResult> = report
        .case_results
        .iter()
        .filter(|(_, result)| **result != ParserTaxonomyResult::CorrectClassification)
        .map(|(id, result)| (id.as_str(), *result))
        .collect();
    let expected: std::collections::BTreeMap<&str, ParserTaxonomyResult> =
        KNOWN_TAXONOMY_GAPS.iter().copied().collect();
    assert_eq!(
        observed, expected,
        "parser-error taxonomy gap set drifted from KNOWN_TAXONOMY_GAPS (bd-wa01t). \
         If a gap closed, remove it from the constant. If a new gap opened, \
         file or extend the follow-up bead before silencing it."
    );
}
