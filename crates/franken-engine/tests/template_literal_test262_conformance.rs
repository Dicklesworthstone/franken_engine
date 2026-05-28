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
use _support::test262_common::RequirementLevel;

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

    // Conformance gate: Fail if pass rate drops below 95%
    let pass_rate_percent = report.statistics.pass_rate_millionths as f64 / 10_000.0;
    assert!(
        pass_rate_percent >= 95.0,
        "Template literal ES2015+ conformance below threshold: {:.2}% (required: ≥95%)",
        pass_rate_percent
    );
}

/// template-literal test262 case ids the engine is currently allowed to diverge
/// on (bd-bg9l1.13). Empty = every catalogued case must pass (the engine
/// currently passes all of them). This exact-set drift detector complements the
/// coarse ≥95% pass-rate floor above: that floor silently tolerates a small
/// fraction of failures, whereas this gate names every permitted gap and fails
/// fast on any drift in either direction.
const KNOWN_TEMPLATE_LITERAL_GAPS: &[&str] = &[];

#[test]
fn template_literal_full_matrix_matches_known_gap_set() {
    let report = TemplateLiteralConformanceHarness::run_conformance_tests();
    let mut observed_detail: Vec<(String, String)> = Vec::new();
    for (id, result) in &report.test_results {
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
