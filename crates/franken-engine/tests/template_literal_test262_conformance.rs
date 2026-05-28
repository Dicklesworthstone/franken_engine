//! Test262 conformance harness for template literal expressions (ES2015+)
//!
//! This harness implements Pattern 4 (Spec-Derived Test Matrix) from the
//! testing-conformance-harnesses skill, targeting ECMAScript template literal
//! syntax from Chapter 12.2.9 Primary Expressions and Chapter 11.8.6 Template
//! Literal Lexical Components.
//!
//! Template literals test critical ES2015+ functionality: template syntax,
//! expression interpolation, tag function calls, raw strings, multi-line
//! literals, and escape sequence handling.

use frankenengine_engine::HybridRouter;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod _support;
use _support::test262_common::{RequirementLevel, assert_report_json_round_trips};

const SCHEMA_VERSION: &str = "franken-engine.template-literal-test262-conformance.v1";
const BEAD_ID: &str = "IndigoRidge-template-literal-conformance";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateLiteralTestCategory {
    BasicSyntax,
    ExpressionSubstitution,
    TaggedTemplates,
    RawStringAccess,
    MultiLine,
    EscapeSequences,
    NestedTemplates,
    EdgeCases,
    /// Negative-path cases the parser MUST reject (`ParseError` or `Fail`).
    /// Added by bd-t2cgg FIND-8 — the harness had only positive paths
    /// before, so the parser could silently accept malformed sources
    /// without a single test catching it.
    ErrorPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateLiteralResult {
    Pass,
    Fail,
    ParseError,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TemplateLiteralTestCase {
    pub id: String,
    pub category: TemplateLiteralTestCategory,
    pub description: String,
    pub source_code: String,
    pub es_spec_section: String,
    pub requirement_level: RequirementLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateLiteralConformanceReport {
    pub schema_version: String,
    pub bead_id: String,
    pub test_results: BTreeMap<String, TemplateLiteralResult>,
    pub statistics: ConformanceStatistics,
    pub coverage_by_category: BTreeMap<TemplateLiteralTestCategory, CategoryCoverage>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConformanceStatistics {
    pub total_tests: u32,
    pub passed: u32,
    pub failed: u32,
    pub parse_errors: u32,
    pub pass_rate_millionths: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryCoverage {
    pub total: u32,
    pub passed: u32,
}

pub struct TemplateLiteralConformanceHarness;

impl TemplateLiteralConformanceHarness {
    fn test_cases() -> Vec<TemplateLiteralTestCase> {
        vec![
            // Basic syntax tests
            TemplateLiteralTestCase {
                id: "template-literal-basic-empty".to_string(),
                category: TemplateLiteralTestCategory::BasicSyntax,
                description: "Empty template literal".to_string(),
                source_code: "``".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-basic-string".to_string(),
                category: TemplateLiteralTestCategory::BasicSyntax,
                description: "Template literal with static string".to_string(),
                source_code: "`hello world`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-basic-single-substitution".to_string(),
                category: TemplateLiteralTestCategory::ExpressionSubstitution,
                description: "Template literal with single expression substitution".to_string(),
                source_code: "`hello ${name}`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-multiple-substitutions".to_string(),
                category: TemplateLiteralTestCategory::ExpressionSubstitution,
                description: "Template literal with multiple expression substitutions".to_string(),
                source_code: "`${greeting} ${name}, you have ${count} messages`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-expression-arithmetic".to_string(),
                category: TemplateLiteralTestCategory::ExpressionSubstitution,
                description: "Template literal with arithmetic expression".to_string(),
                source_code: "`Result: ${a + b * 2}`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            // Tagged template tests
            TemplateLiteralTestCase {
                id: "tagged-template-basic".to_string(),
                category: TemplateLiteralTestCategory::TaggedTemplates,
                description: "Basic tagged template call".to_string(),
                source_code: "const name = \"name\"; const tag = function(rendered) { return rendered; }; tag`hello ${name}`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "tagged-template-member-expression".to_string(),
                category: TemplateLiteralTestCategory::TaggedTemplates,
                description: "Tagged template with member expression".to_string(),
                source_code: "const value = \"value\"; const obj = { method: function(rendered) { return rendered; } }; obj.method`template ${value}`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            // Multi-line tests
            TemplateLiteralTestCase {
                id: "template-literal-multiline".to_string(),
                category: TemplateLiteralTestCategory::MultiLine,
                description: "Multi-line template literal".to_string(),
                source_code: "`line 1\nline 2\nline 3`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-multiline-with-substitution".to_string(),
                category: TemplateLiteralTestCategory::MultiLine,
                description: "Multi-line template literal with expression substitution".to_string(),
                source_code: "`First line\nSecond line: ${value}\nThird line`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            // Escape sequence tests
            TemplateLiteralTestCase {
                id: "template-literal-escape-backslash".to_string(),
                category: TemplateLiteralTestCategory::EscapeSequences,
                description: "Template literal with escaped backslash".to_string(),
                source_code: r#"`Path: C:\\Users\\${user}`"#.to_string(),
                es_spec_section: "11.8.6".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-escape-backtick".to_string(),
                category: TemplateLiteralTestCategory::EscapeSequences,
                description: "Template literal with escaped backtick".to_string(),
                source_code: r#"`Use \`backticks\` for templates`"#.to_string(),
                es_spec_section: "11.8.6".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-escape-dollar-brace".to_string(),
                category: TemplateLiteralTestCategory::EscapeSequences,
                description: "Template literal with escaped dollar brace".to_string(),
                source_code: r#"`Price: \${amount} USD`"#.to_string(),
                es_spec_section: "11.8.6".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            // Nested templates
            TemplateLiteralTestCase {
                id: "template-literal-nested".to_string(),
                category: TemplateLiteralTestCategory::NestedTemplates,
                description: "Nested template literals".to_string(),
                source_code: "`outer ${`inner ${value}`}`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Should,
            },
            // Edge cases
            TemplateLiteralTestCase {
                id: "template-literal-undefined-substitution".to_string(),
                category: TemplateLiteralTestCategory::EdgeCases,
                description: "Template literal with explicit undefined substitution".to_string(),
                source_code: "`prefix ${undefined} suffix`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-unicode-escape".to_string(),
                category: TemplateLiteralTestCategory::EscapeSequences,
                description: "Template literal with unicode escape sequence".to_string(),
                source_code: r#"`Unicode: \u{1F600} emoji`"#.to_string(),
                es_spec_section: "11.8.6".to_string(),
                requirement_level: RequirementLevel::Should,
            },
            TemplateLiteralTestCase {
                id: "template-literal-complex-expression".to_string(),
                category: TemplateLiteralTestCategory::ExpressionSubstitution,
                description: "Template literal with complex expression".to_string(),
                source_code: "`Result: ${[\"zero\", \"one\"][1]}`".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            // ─── Error-path cases (bd-t2cgg FIND-8) ──────────────────────────
            // ES2020 §12.2.9 (Template Literal Lexical Grammar) and §11.8.6
            // (Template Literal Lexical Components) reject several malformed
            // shapes at parse time. The audit (FIND-8) flagged that this
            // harness had ZERO negative-path cases — the parser could silently
            // accept any of these without a single regression detector seeing
            // it. The cases below force the parser through each malformed
            // shape; `test_template_literal_error_cases` (mod tests) asserts
            // that none of them comes back as `Pass`. If a future engine
            // change accepts a malformed source, the test fails loudly and
            // points at the spec clause being violated.
            TemplateLiteralTestCase {
                id: "template-literal-error-unterminated-string".to_string(),
                category: TemplateLiteralTestCategory::ErrorPaths,
                description:
                    "Unterminated template literal — no closing backtick (ES2020 §11.8.6 — TemplateCharacter MUST be terminated)."
                        .to_string(),
                source_code: "`hello world".to_string(),
                es_spec_section: "11.8.6".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-error-unterminated-substitution".to_string(),
                category: TemplateLiteralTestCategory::ErrorPaths,
                description:
                    "Template literal with unterminated `${` substitution — no `}` or closing backtick (ES2020 §12.2.9)."
                        .to_string(),
                source_code: "`prefix ${value".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-error-unterminated-after-substitution".to_string(),
                category: TemplateLiteralTestCategory::ErrorPaths,
                description:
                    "Template literal terminated by `}` but missing the trailing backtick (ES2020 §12.2.9 / §11.8.6)."
                        .to_string(),
                source_code: "`prefix ${1 + 2} suffix".to_string(),
                es_spec_section: "12.2.9".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-error-octal-escape".to_string(),
                category: TemplateLiteralTestCategory::ErrorPaths,
                description:
                    "Legacy octal escape `\\01` in a template literal — ES2020 §11.8.6 / Annex B explicitly forbids legacy octals in template literals (the carve-out only applies to string literals in non-strict mode)."
                        .to_string(),
                source_code: r"`octal \01 escape`".to_string(),
                es_spec_section: "11.8.6".to_string(),
                requirement_level: RequirementLevel::Must,
            },
            TemplateLiteralTestCase {
                id: "template-literal-error-bad-unicode-escape".to_string(),
                category: TemplateLiteralTestCategory::ErrorPaths,
                description:
                    "Malformed `\\u{...}` escape with non-hex content — ES2020 §11.8.4.1 EscapeSequence rejects non-HexDigit content."
                        .to_string(),
                source_code: r"`bad unicode \u{XYZ}`".to_string(),
                es_spec_section: "11.8.4".to_string(),
                requirement_level: RequirementLevel::Must,
            },
        ]
    }

    pub fn run_conformance_tests() -> TemplateLiteralConformanceReport {
        let mut results = BTreeMap::new();
        let mut statistics = ConformanceStatistics {
            total_tests: 0,
            passed: 0,
            failed: 0,
            parse_errors: 0,
            pass_rate_millionths: 0,
        };

        let test_cases = Self::test_cases();
        for test_case in &test_cases {
            let result = Self::execute_test_case(test_case);

            match result {
                TemplateLiteralResult::Pass => statistics.passed += 1,
                TemplateLiteralResult::Fail => statistics.failed += 1,
                TemplateLiteralResult::ParseError => statistics.parse_errors += 1,
            }
            statistics.total_tests += 1;

            results.insert(test_case.id.clone(), result);
        }

        statistics.pass_rate_millionths = statistics
            .passed
            .saturating_mul(1_000_000)
            .checked_div(statistics.total_tests)
            .unwrap_or(0);

        TemplateLiteralConformanceReport {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            test_results: results.clone(),
            statistics,
            coverage_by_category: Self::calculate_coverage_by_category(&results),
        }
    }

    fn execute_test_case(test_case: &TemplateLiteralTestCase) -> TemplateLiteralResult {
        let mut engine = HybridRouter::default();

        match engine.eval(&test_case.source_code) {
            Ok(_) => TemplateLiteralResult::Pass,
            Err(err) => {
                // Check if error is due to parsing or execution
                let error_str = err.to_string();
                if error_str.contains("parse") || error_str.contains("syntax") {
                    TemplateLiteralResult::ParseError
                } else {
                    TemplateLiteralResult::Fail
                }
            }
        }
    }

    fn calculate_coverage_by_category(
        results: &BTreeMap<String, TemplateLiteralResult>,
    ) -> BTreeMap<TemplateLiteralTestCategory, CategoryCoverage> {
        let mut coverage: BTreeMap<TemplateLiteralTestCategory, CategoryCoverage> = BTreeMap::new();

        for test in Self::test_cases() {
            let category_coverage = coverage.entry(test.category.clone()).or_default();
            category_coverage.total += 1;

            if let Some(result) = results.get(&test.id)
                && matches!(result, TemplateLiteralResult::Pass)
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
    fn test_template_literal_basic_syntax() {
        let test_cases = TemplateLiteralConformanceHarness::test_cases();
        let test_case = &test_cases[0];
        assert_eq!(test_case.category, TemplateLiteralTestCategory::BasicSyntax);

        let result = TemplateLiteralConformanceHarness::execute_test_case(test_case);
        // Basic template literals should be supported
        assert!(matches!(
            result,
            TemplateLiteralResult::Pass | TemplateLiteralResult::Fail
        ));
    }

    #[test]
    fn test_template_literal_expression_substitution() {
        let test_cases = TemplateLiteralConformanceHarness::test_cases();
        let test_case = &test_cases[2];
        assert_eq!(
            test_case.category,
            TemplateLiteralTestCategory::ExpressionSubstitution
        );

        let result = TemplateLiteralConformanceHarness::execute_test_case(test_case);
        // Expression substitution is critical ES2015+ functionality
        assert!(matches!(
            result,
            TemplateLiteralResult::Pass | TemplateLiteralResult::Fail
        ));
    }

    #[test]
    fn test_template_literal_tagged_templates() {
        let test_cases = TemplateLiteralConformanceHarness::test_cases();
        let test_case = &test_cases[5];
        assert_eq!(
            test_case.category,
            TemplateLiteralTestCategory::TaggedTemplates
        );

        let result = TemplateLiteralConformanceHarness::execute_test_case(test_case);
        // Tagged templates should be supported for full ES2015+ compliance
        assert!(matches!(
            result,
            TemplateLiteralResult::Pass | TemplateLiteralResult::Fail
        ));
    }

    #[test]
    fn test_conformance_report_generation() {
        let report = TemplateLiteralConformanceHarness::run_conformance_tests();

        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.bead_id, BEAD_ID);
        assert_eq!(
            report.statistics.total_tests as usize,
            TemplateLiteralConformanceHarness::test_cases().len()
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
        for test_case in TemplateLiteralConformanceHarness::test_cases() {
            assert!(
                ids.insert(test_case.id.clone()),
                "Duplicate test case ID: {}",
                test_case.id
            );
        }
    }

    #[test]
    fn test_all_categories_covered() {
        use std::collections::HashSet;

        let covered_categories: HashSet<_> = TemplateLiteralConformanceHarness::test_cases()
            .into_iter()
            .map(|test| test.category)
            .collect();

        // Verify we have tests for all major template literal features
        assert!(covered_categories.contains(&TemplateLiteralTestCategory::BasicSyntax));
        assert!(covered_categories.contains(&TemplateLiteralTestCategory::ExpressionSubstitution));
        assert!(covered_categories.contains(&TemplateLiteralTestCategory::TaggedTemplates));
        assert!(covered_categories.contains(&TemplateLiteralTestCategory::EscapeSequences));
    }

    /// bd-rqev5 (FIND-10): every conformance harness must prove its report
    /// survives a serde_json round-trip and carries the canonical schema pin.
    #[test]
    fn report_round_trips_through_serde_json() {
        let report = TemplateLiteralConformanceHarness::run_conformance_tests();
        assert_report_json_round_trips(&report, SCHEMA_VERSION, &report.schema_version);
    }

    /// Negative-path WAIVER set for the exact-gap drift detector below: an
    /// entry that closes (engine starts rejecting) forces promotion (the test
    /// fails with PROGRESS); a new uncaught case (engine regresses on a
    /// different ErrorPaths id) fails as REGRESSION. Either edge prevents
    /// silent drift.
    ///
    /// As of bd-no788's full closure this set is EMPTY — every ErrorPaths case
    /// is now rejected by the engine:
    /// - the legacy-octal (`\01`, bd-no788.1) and malformed `\u{...}`
    ///   (`\u{XYZ}`, bd-no788.2) escapes by the `validate_template_escape_sequence`
    ///   pass in parser.rs;
    /// - the three unterminated shapes (bd-no788 cases 1-3) by the fail-closed
    ///   leading-backtick check at the tail of `parse_primary_expression`.
    ///   feb61b0e added the equivalent check to `parse_template_literal`, but
    ///   the both-backticks routing gate meant an unterminated literal never
    ///   reached it — the survivor now fails closed before the `Expression::Raw`
    ///   fallback.
    const KNOWN_FAILING_ERROR_REJECTS: &[(&str, &str)] = &[
        // (test_id, tracking_bead) — empty: bd-no788 fully closed.
    ];

    /// bd-t2cgg (FIND-8): every `ErrorPaths` case MUST be rejected by the
    /// parser — i.e. come back as `ParseError` or `Fail`, never `Pass`. The
    /// audit flagged that the harness had no negative-path tests at all, so
    /// a regression that silently started accepting malformed template
    /// literals would have gone unnoticed.
    ///
    /// Today (HEAD as of bd-t2cgg landing) the engine accepts all 5 of the
    /// initial ErrorPaths cases — they're listed in
    /// `KNOWN_FAILING_ERROR_REJECTS` and tracked under bd-no788. The drift
    /// detector below enforces an exact-gap partition: any deviation
    /// (newly accepted case OR newly rejected one) fails the test loudly so
    /// the gap inventory cannot quietly drift.
    #[test]
    fn template_literal_error_cases_must_not_pass() {
        use std::collections::BTreeSet;

        let test_cases = TemplateLiteralConformanceHarness::test_cases();
        let error_cases: Vec<&TemplateLiteralTestCase> = test_cases
            .iter()
            .filter(|tc| matches!(tc.category, TemplateLiteralTestCategory::ErrorPaths))
            .collect();

        assert!(
            !error_cases.is_empty(),
            "bd-t2cgg: TemplateLiteralTestCategory::ErrorPaths must have at least one case — the harness lost its negative-path coverage."
        );

        // Surface the parser-gap inventory in CI output so reviewers see
        // it without chasing the bd-no788 follow-up bead.
        println!(
            "\nKnown failing error-reject cases (bd-t2cgg / bd-no788 — engine accepts malformed input):"
        );
        for (id, bead) in KNOWN_FAILING_ERROR_REJECTS {
            println!("  {id}  [{bead}]");
        }

        let waived: BTreeSet<&str> = KNOWN_FAILING_ERROR_REJECTS
            .iter()
            .map(|(id, _)| *id)
            .collect();
        let all_error_ids: BTreeSet<&str> = error_cases.iter().map(|tc| tc.id.as_str()).collect();
        let actually_rejected: BTreeSet<&str> = error_cases
            .iter()
            .filter(|tc| {
                !matches!(
                    TemplateLiteralConformanceHarness::execute_test_case(tc),
                    TemplateLiteralResult::Pass,
                )
            })
            .map(|tc| tc.id.as_str())
            .collect();

        // Invariant 1: every waived id refers to an existing ErrorPaths case.
        let stale_waivers: Vec<&str> = waived.difference(&all_error_ids).copied().collect();
        assert!(
            stale_waivers.is_empty(),
            "bd-t2cgg: KNOWN_FAILING_ERROR_REJECTS references ids not present in the ErrorPaths set — prune them: {stale_waivers:?}"
        );

        // Invariant 2 (REGRESSION): a previously-correctly-rejected case
        // (i.e. an ErrorPaths id NOT in the waiver set) now passes.
        let newly_silently_accepted: Vec<&str> = all_error_ids
            .difference(&waived)
            .filter(|id| !actually_rejected.contains(*id))
            .copied()
            .collect();
        assert!(
            newly_silently_accepted.is_empty(),
            "bd-t2cgg REGRESSION: the engine silently accepted a previously-rejected malformed template literal — file a follow-up bead and waive the id in KNOWN_FAILING_ERROR_REJECTS only if intentional: {newly_silently_accepted:?}"
        );

        // Invariant 3 (PROGRESS): a waived case now rejects — promote it
        // out of KNOWN_FAILING_ERROR_REJECTS so the gap inventory stays
        // accurate and the cited bd-no788 row can be flipped to RESOLVED.
        let gap_closed: Vec<&str> = waived.intersection(&actually_rejected).copied().collect();
        assert!(
            gap_closed.is_empty(),
            "bd-t2cgg PROGRESS: the engine now rejects waived malformed sources — remove these ids from KNOWN_FAILING_ERROR_REJECTS and flip the bd-no788 entry: {gap_closed:?}"
        );
    }
}

/// Integration test for the full template literal conformance harness
#[test]
fn template_literal_test262_conformance_integration() {
    let report = TemplateLiteralConformanceHarness::run_conformance_tests();

    println!("Template Literal Test262 Conformance Report");
    println!("==========================================");
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
    for test_case in TemplateLiteralConformanceHarness::test_cases() {
        if let Some(result) = report.test_results.get(&test_case.id) {
            println!(
                "  {} [{}]: {:?}",
                test_case.id, test_case.requirement_level, result
            );
        }
    }

    // Conformance gate: fail if the positive-path pass rate drops below 95%.
    // ErrorPaths cases are negative tests whose conformant outcome is a
    // *rejection* (non-Pass) — folding them into the pass rate would conflate a
    // correct rejection with a conformance failure. Their behaviour is enforced
    // separately and exactly by `template_literal_error_cases_must_not_pass`.
    let (mut positive_total, mut positive_passed) = (0u64, 0u64);
    for test_case in TemplateLiteralConformanceHarness::test_cases() {
        if matches!(test_case.category, TemplateLiteralTestCategory::ErrorPaths) {
            continue;
        }
        positive_total += 1;
        if matches!(
            report.test_results.get(&test_case.id),
            Some(TemplateLiteralResult::Pass)
        ) {
            positive_passed += 1;
        }
    }
    let pass_rate_percent = positive_passed
        .saturating_mul(10_000)
        .checked_div(positive_total)
        .unwrap_or(0) as f64
        / 100.0;
    assert!(
        pass_rate_percent >= 95.0,
        "Template literal ES2015+ positive-path conformance below threshold: {:.2}% (required: ≥95%)",
        pass_rate_percent
    );
}

/// Positive-path template-literal test262 case ids the engine is currently
/// allowed to diverge on (bd-bg9l1.13). Empty = every catalogued positive case
/// must pass (the engine currently passes all of them). This exact-set drift
/// detector complements the coarse ≥95% pass-rate floor above: that floor
/// silently tolerates a small fraction of failures, whereas this gate names
/// every permitted gap and fails fast on any drift in either direction.
///
/// ErrorPaths cases are excluded — they are negative tests whose conformant
/// outcome is a rejection (non-Pass), enforced exactly by
/// `template_literal_error_cases_must_not_pass`.
const KNOWN_TEMPLATE_LITERAL_GAPS: &[&str] = &[];

#[test]
fn template_literal_full_matrix_matches_known_gap_set() {
    let report = TemplateLiteralConformanceHarness::run_conformance_tests();
    let error_path_ids: std::collections::BTreeSet<String> =
        TemplateLiteralConformanceHarness::test_cases()
            .iter()
            .filter(|tc| matches!(tc.category, TemplateLiteralTestCategory::ErrorPaths))
            .map(|tc| tc.id.clone())
            .collect();
    let mut observed_detail: Vec<(String, String)> = Vec::new();
    for (id, result) in &report.test_results {
        // A non-Pass result on an ErrorPaths case is the correct, conformant
        // outcome (the engine rejected malformed input) — not a positive-path gap.
        if error_path_ids.contains(id) {
            continue;
        }
        match result {
            TemplateLiteralResult::Pass => {}
            other => observed_detail.push((id.clone(), format!("{other:?}"))),
        }
    }
    let observed: std::collections::BTreeSet<&str> =
        observed_detail.iter().map(|(id, _)| id.as_str()).collect();
    let expected: std::collections::BTreeSet<&str> =
        KNOWN_TEMPLATE_LITERAL_GAPS.iter().copied().collect();
    assert_eq!(
        observed, expected,
        "template-literal gap set drifted from KNOWN_TEMPLATE_LITERAL_GAPS \
         (bd-bg9l1.13). If a gap closed, remove it from the constant. If a new \
         gap opened, file or extend a follow-up bead before silencing it. \
         Observed gaps with detail:\n{observed_detail:#?}"
    );
}
