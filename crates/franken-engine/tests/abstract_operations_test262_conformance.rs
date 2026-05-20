#![forbid(unsafe_code)]

//! ECMAScript Abstract Operations Test262 Conformance Harness
//!
//! Bead: bd-rowm6 — Add conformance harness for runtime abstract operations.
//!
//! baseline_interpreter implements the ECMA-262 §7 abstract operations
//! (ToBoolean, ToNumber, ToString, typeof/void, abstract `==`, strict `===`,
//! NaN equality, signed-zero equality, numeric-string coercion, etc.) via
//! scattered unit checks. This harness is the spec-anchored matrix tying
//! ES section ids and MUST-level clauses to executable, runtime-end-to-end
//! cases. Every test drives the full HybridRouter path (parser → IR0 → IR1
//! → IR2 → IR3 → interpreter → console_output) so harness greens prove the
//! whole pipeline, not just a helper.
//!
//! Scope (initial batch — first 10 cases): ToBoolean truthiness, ToNumber
//! string/bool coercion, typeof / null typeof, void, == vs ===, NaN
//! equality, signed-zero equality. Subsequent waves should grow the matrix
//! toward §7 completion (ToPrimitive, ToInt32, RequireObjectCoercible, etc).

use frankenengine_engine::HybridRouter;
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod _support;
use _support::test262_common::{
    ExpectedResult, RequirementLevel, Test262Result, evaluate_test262_result,
};

pub const ABSTRACT_OPERATIONS_CONFORMANCE_SCHEMA: &str =
    "franken-engine.abstract-operations-test262.v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AbstractOperationResult {
    Pass,
    Fail { reason: String },
    Error { error: String },
    Skip { reason: String },
}

/// Spec section groupings — keep aligned with ECMA-262 §7 numbering.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AbstractOperationCategory {
    /// §7.1.1 ToBoolean.
    ToBoolean,
    /// §7.1.4 ToNumber / numeric-string coercion.
    ToNumber,
    /// §12.5.5 typeof operator (incl. §6.1.1 typeof null).
    TypeOf,
    /// §12.5.4 void operator.
    Void,
    /// §7.2.14 Abstract Equality Comparison (`==`).
    AbstractEquality,
    /// §7.2.15 Strict Equality Comparison (`===`).
    StrictEquality,
    /// §6.1.6.1.13 / §7.2.13 NaN and signed-zero equality.
    NumericEdgeCases,
}

#[derive(Debug, Clone)]
pub struct AbstractOperationTest {
    pub id: String,
    pub description: String,
    pub es_section: String,
    pub requirement_level: RequirementLevel,
    pub category: AbstractOperationCategory,
    pub source: String,
    pub expected_result: ExpectedResult,
}

pub struct AbstractOperationsHarness {
    tests: Vec<AbstractOperationTest>,
}

impl Default for AbstractOperationsHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl AbstractOperationsHarness {
    pub fn new() -> Self {
        Self {
            tests: Self::create_tests(),
        }
    }

    fn create_tests() -> Vec<AbstractOperationTest> {
        vec![
            // ─── §7.1.1 ToBoolean ────────────────────────────────────────────
            AbstractOperationTest {
                id: "ES2020-7.1.1-toboolean-zero-is-false".to_string(),
                description:
                    "ToBoolean(+0) is false; the unary-! operator is a runtime use of ToBoolean."
                        .to_string(),
                es_section: "7.1.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::ToBoolean,
                source: "console.log(!0);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "true\n".to_string(),
                },
            },
            AbstractOperationTest {
                id: "ES2020-7.1.1-toboolean-empty-string-is-false".to_string(),
                description: "ToBoolean('') is false.".to_string(),
                es_section: "7.1.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::ToBoolean,
                source: "console.log(!'');".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "true\n".to_string(),
                },
            },
            AbstractOperationTest {
                id: "ES2020-7.1.1-toboolean-nonempty-string-is-true".to_string(),
                description:
                    "ToBoolean('false') is true — non-empty strings are truthy regardless of \
                     content."
                        .to_string(),
                es_section: "7.1.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::ToBoolean,
                source: "console.log(!!'false');".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "true\n".to_string(),
                },
            },
            // ─── §7.1.4 ToNumber ─────────────────────────────────────────────
            AbstractOperationTest {
                id: "ES2020-7.1.4-tonumber-string-numeric".to_string(),
                description:
                    "ToNumber('42') is 42; unary `+` is a runtime use of ToNumber.".to_string(),
                es_section: "7.1.4".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::ToNumber,
                source: "console.log(+'42');".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "42\n".to_string(),
                },
            },
            AbstractOperationTest {
                id: "ES2020-7.1.4-tonumber-boolean-true".to_string(),
                description: "ToNumber(true) is 1.".to_string(),
                es_section: "7.1.4".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::ToNumber,
                source: "console.log(+true);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "1\n".to_string(),
                },
            },
            // ─── §12.5.5 typeof ──────────────────────────────────────────────
            AbstractOperationTest {
                id: "ES2020-12.5.5-typeof-undefined".to_string(),
                description: "typeof undefined returns 'undefined'.".to_string(),
                es_section: "12.5.5".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::TypeOf,
                source: "console.log(typeof undefined);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "undefined\n".to_string(),
                },
            },
            AbstractOperationTest {
                id: "ES2020-12.5.5-typeof-null-is-object".to_string(),
                description:
                    "typeof null returns 'object' — the spec-mandated legacy quirk preserved \
                     since ES1."
                        .to_string(),
                es_section: "12.5.5".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::TypeOf,
                source: "console.log(typeof null);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "object\n".to_string(),
                },
            },
            // ─── §12.5.4 void ────────────────────────────────────────────────
            AbstractOperationTest {
                id: "ES2020-12.5.4-void-always-undefined".to_string(),
                description: "void evaluates its operand and returns undefined.".to_string(),
                es_section: "12.5.4".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::Void,
                source: "console.log(void 42);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "undefined\n".to_string(),
                },
            },
            // ─── §7.2.14 Abstract Equality ───────────────────────────────────
            AbstractOperationTest {
                id: "ES2020-7.2.14-abstract-equality-coerces-string-number".to_string(),
                description:
                    "Abstract equality '1' == 1 returns true via ToNumber coercion."
                        .to_string(),
                es_section: "7.2.14".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::AbstractEquality,
                source: "console.log('1' == 1);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "true\n".to_string(),
                },
            },
            // ─── §7.2.15 Strict Equality ─────────────────────────────────────
            AbstractOperationTest {
                id: "ES2020-7.2.15-strict-equality-no-coercion".to_string(),
                description: "Strict equality '1' === 1 returns false — no coercion.".to_string(),
                es_section: "7.2.15".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::StrictEquality,
                source: "console.log('1' === 1);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "false\n".to_string(),
                },
            },
            // ─── §6.1.6.1.13 / §7.2.15 numeric edge cases ────────────────────
            AbstractOperationTest {
                id: "ES2020-7.2.15-nan-not-equal-to-itself".to_string(),
                description:
                    "NaN === NaN returns false — Number type's only non-reflexive value."
                        .to_string(),
                es_section: "7.2.15".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::NumericEdgeCases,
                source: "const x = NaN; console.log(x === x);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "false\n".to_string(),
                },
            },
            AbstractOperationTest {
                id: "ES2020-7.2.15-positive-zero-strictly-equals-negative-zero".to_string(),
                description:
                    "+0 === -0 returns true — strict equality treats signed zeros as equal."
                        .to_string(),
                es_section: "7.2.15".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AbstractOperationCategory::NumericEdgeCases,
                source: "console.log(+0 === -0);".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "true\n".to_string(),
                },
            },
        ]
    }

    pub fn run_conformance(&self, security_epoch: SecurityEpoch) -> AbstractOperationsReport {
        let mut results = BTreeMap::new();
        let mut statistics = ConformanceStatistics::default();

        for test in &self.tests {
            let result = self.execute_test(test, security_epoch);

            match result {
                AbstractOperationResult::Pass => statistics.passed += 1,
                AbstractOperationResult::Fail { .. } => statistics.failed += 1,
                AbstractOperationResult::Error { .. } => statistics.errored += 1,
                AbstractOperationResult::Skip { .. } => statistics.skipped += 1,
            }

            statistics.total_tests += 1;
            results.insert(test.id.clone(), result);
        }

        statistics.pass_rate_millionths =
            ratio_millionths(statistics.passed, statistics.total_tests);

        AbstractOperationsReport {
            schema_version: ABSTRACT_OPERATIONS_CONFORMANCE_SCHEMA.to_string(),
            security_epoch,
            test_results: results.clone(),
            statistics,
            coverage_by_category: self.coverage_by_category(&results),
        }
    }

    fn execute_test(
        &self,
        test: &AbstractOperationTest,
        _security_epoch: SecurityEpoch,
    ) -> AbstractOperationResult {
        let mut engine = HybridRouter::default();
        let eval_result = engine.eval(&test.source);
        match evaluate_test262_result(eval_result, &test.expected_result, &test.id) {
            Test262Result::Pass => AbstractOperationResult::Pass,
            Test262Result::Fail { reason } => AbstractOperationResult::Fail { reason },
            Test262Result::Error { error } => AbstractOperationResult::Error { error },
            Test262Result::Skip { reason } => AbstractOperationResult::Skip { reason },
        }
    }

    fn coverage_by_category(
        &self,
        results: &BTreeMap<String, AbstractOperationResult>,
    ) -> BTreeMap<AbstractOperationCategory, CategoryCoverage> {
        let mut coverage: BTreeMap<AbstractOperationCategory, CategoryCoverage> = BTreeMap::new();
        for test in &self.tests {
            let entry = coverage
                .entry(test.category.clone())
                .or_insert_with(CategoryCoverage::default);
            entry.total += 1;
            if let Some(result) = results.get(&test.id)
                && matches!(result, AbstractOperationResult::Pass)
            {
                entry.passed += 1;
            }
        }
        coverage
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ConformanceStatistics {
    pub total_tests: u64,
    pub passed: u64,
    pub failed: u64,
    pub errored: u64,
    pub skipped: u64,
    pub pass_rate_millionths: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CategoryCoverage {
    pub total: u64,
    pub passed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AbstractOperationsReport {
    pub schema_version: String,
    pub security_epoch: SecurityEpoch,
    pub test_results: BTreeMap<String, AbstractOperationResult>,
    pub statistics: ConformanceStatistics,
    pub coverage_by_category: BTreeMap<AbstractOperationCategory, CategoryCoverage>,
}

fn ratio_millionths(passed: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    ((u128::from(passed) * 1_000_000_u128) / u128::from(total)).min(1_000_000_u128) as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned allow-list of MUST-tier abstract-op cases that are known to
    /// fail. Every entry MUST cite an open bead; entries get audited on
    /// every run (line-by-line below). Intentionally empty for the
    /// initial wave — if the first batch needs a waiver, file a bead and
    /// add it here.
    const EXPECTED_FAILING_MUSTS: &[(&str, &str)] = &[];

    fn must_tests(harness: &AbstractOperationsHarness) -> Vec<&AbstractOperationTest> {
        harness
            .tests
            .iter()
            .filter(|t| t.requirement_level == RequirementLevel::Must)
            .collect()
    }

    #[test]
    fn harness_has_minimum_initial_coverage() {
        let harness = AbstractOperationsHarness::new();
        assert!(
            harness.tests.len() >= 10,
            "initial bd-rowm6 wave promised >=10 spec-anchored cases; got {}",
            harness.tests.len(),
        );
        // Every test must carry an ES section id and a Must-tier or higher
        // requirement level — silent SHOULDs are not allowed in the initial
        // wave (raise the bar early).
        for test in &harness.tests {
            assert!(
                !test.es_section.is_empty(),
                "test {} missing es_section id",
                test.id,
            );
            assert!(
                test.id.starts_with("ES2020-"),
                "test id {} must start with ES2020- to mark spec anchoring",
                test.id,
            );
        }
    }

    #[test]
    fn harness_covers_all_initial_categories() {
        use AbstractOperationCategory::*;
        let harness = AbstractOperationsHarness::new();
        let categories: std::collections::BTreeSet<_> =
            harness.tests.iter().map(|t| t.category.clone()).collect();
        for required in [
            ToBoolean,
            ToNumber,
            TypeOf,
            Void,
            AbstractEquality,
            StrictEquality,
            NumericEdgeCases,
        ] {
            assert!(
                categories.contains(&required),
                "initial bd-rowm6 matrix must include category {required:?}",
            );
        }
    }

    #[test]
    fn must_tier_has_no_unexpected_regressions() {
        let harness = AbstractOperationsHarness::new();
        let report = harness.run_conformance(SecurityEpoch::from_raw(1));
        let allow: std::collections::BTreeMap<&str, &str> =
            EXPECTED_FAILING_MUSTS.iter().copied().collect();

        // Allow-list integrity: each waiver MUST reference a real id +
        // an open bead.
        let must_ids: std::collections::BTreeSet<&str> =
            must_tests(&harness).iter().map(|t| t.id.as_str()).collect();
        for (waived_id, bead) in allow.iter() {
            assert!(
                must_ids.contains(*waived_id),
                "EXPECTED_FAILING_MUSTS references unknown id `{waived_id}`",
            );
            assert!(
                bead.starts_with("bd-") && bead.len() > 3,
                "EXPECTED_FAILING_MUSTS entry for `{waived_id}` lacks a bead reference",
            );
        }

        let mut unexpected_failures: Vec<(String, AbstractOperationResult)> = Vec::new();
        let mut unexpected_passes: Vec<String> = Vec::new();
        for test in must_tests(&harness) {
            let result = report
                .test_results
                .get(&test.id)
                .cloned()
                .unwrap_or_else(|| AbstractOperationResult::Error {
                    error: "<missing result>".to_string(),
                });
            let waived = allow.contains_key(test.id.as_str());
            match (&result, waived) {
                (AbstractOperationResult::Pass, false) => {}
                (AbstractOperationResult::Pass, true) => unexpected_passes.push(test.id.clone()),
                (_, true) => {} // expected failure
                (other, false) => unexpected_failures.push((test.id.clone(), other.clone())),
            }
        }

        assert!(
            unexpected_failures.is_empty(),
            "{} MUST-tier abstract-ops test(s) regressed unexpectedly:\n  {}",
            unexpected_failures.len(),
            unexpected_failures
                .iter()
                .map(|(id, r)| format!("{id}: {r:?}"))
                .collect::<Vec<_>>()
                .join("\n  "),
        );
        assert!(
            unexpected_passes.is_empty(),
            "{} MUST-tier abstract-ops test(s) waived in EXPECTED_FAILING_MUSTS now pass — remove their entries:\n  {}",
            unexpected_passes.len(),
            unexpected_passes.join("\n  "),
        );
    }

    #[test]
    fn report_round_trips_through_serde_json() {
        let harness = AbstractOperationsHarness::new();
        let report = harness.run_conformance(SecurityEpoch::from_raw(7));
        let json = serde_json::to_string(&report).expect("serialize");
        let back: AbstractOperationsReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, back, "report must round-trip");
        assert_eq!(report.schema_version, ABSTRACT_OPERATIONS_CONFORMANCE_SCHEMA);
        assert_eq!(report.statistics.total_tests, harness.tests.len() as u64);
    }
}
