#![forbid(unsafe_code)]

//! Async / Promise / Microtask Test262 Conformance Harness
//!
//! Bead: bd-ffavl — Add conformance harness for async promise and microtask
//! ordering.
//!
//! Promises and the microtask queue are implemented in promise_model.rs and
//! driven by baseline_interpreter; the timer/microtask substrate has unit
//! tests (see baseline_interpreter::event_loop_timer_microtask_tests added
//! under bd-5116c) but no spec-anchored Test262-style matrix that exercises
//! the user-visible end-to-end ordering through HybridRouter::eval and
//! console.log.
//!
//! This harness fills that gap. Every fixture drives the full pipeline
//! (parser → IR0 → IR1 → IR2 → IR3 → interpreter → microtask drain →
//! console_output) and asserts the printed sequence matches the spec.
//! Initial wave (10 cases): Promise.resolve / .then identity, basic
//! reject/.catch propagation, microtask-after-sync ordering, chained
//! .then values, async function fulfillment and rejection, await
//! thenable assimilation, Promise.all aggregation.
//!
//! bd-5sxc9 expands that matrix with ES2020/ES2022 Promise combinators,
//! await-rejection propagation, timer-vs-microtask ordering, host rejection
//! tracking observability, and thenable assimilation edge cases.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod _support;
use _support::test262_common::{
    ExpectedResult, RequirementLevel, Test262Result, evaluate_test262_result,
};

pub const ASYNC_PROMISE_CONFORMANCE_SCHEMA: &str = "franken-engine.async-promise-test262.v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AsyncPromiseResult {
    Pass,
    Fail { reason: String },
    Error { error: String },
    Skip { reason: String },
}

/// Spec section groupings — keep aligned with ECMA-262 §25 (Promise) and
/// §15.8 (Async Function Definitions).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AsyncPromiseCategory {
    /// §25.6.4.5 Promise.resolve + §25.6.5.4 then-fulfillment path.
    ResolveThen,
    /// §25.6.4.4 Promise.reject + §25.6.5.1 catch propagation.
    RejectCatch,
    /// §8.4.1 microtask checkpoint — microtasks drain before next macrotask
    /// AND before the script returns to the host.
    MicrotaskOrdering,
    /// §25.6.5.4 multi-step .then() value propagation.
    ChainedThen,
    /// §25.6.4.1 Promise.all aggregation.
    PromiseAll,
    /// §25.6.4.3 Promise.race first-settlement semantics.
    PromiseRace,
    /// §25.6.4.2 Promise.allSettled outcome aggregation.
    PromiseAllSettled,
    /// ES2022 Promise.any first-fulfillment / aggregate rejection semantics.
    PromiseAny,
    /// §15.8 async function: synchronous return wraps in resolved promise.
    AsyncFunctionFulfillment,
    /// §15.8.4 await rejected promise propagation.
    AwaitRejection,
    /// §15.8.4 await: thenable assimilation + resumption microtask.
    AwaitThenable,
    /// Timer macrotasks must run after the microtask checkpoint.
    TimerMicrotaskOrdering,
    /// HostPromiseRejectionTracker-facing ordering and noninterference.
    UnhandledRejectionTracking,
    /// Promise.resolve(thenable) job ordering.
    ThenableAssimilation,
}

#[derive(Debug, Clone)]
pub struct AsyncPromiseTest {
    pub id: String,
    pub description: String,
    pub es_section: String,
    pub requirement_level: RequirementLevel,
    pub category: AsyncPromiseCategory,
    pub source: String,
    pub expected_result: ExpectedResult,
}

pub struct AsyncPromiseHarness {
    tests: Vec<AsyncPromiseTest>,
}

impl Default for AsyncPromiseHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncPromiseHarness {
    pub fn new() -> Self {
        Self {
            tests: Self::create_tests(),
        }
    }

    fn create_tests() -> Vec<AsyncPromiseTest> {
        vec![
            // ─── §25.6.4.5 Promise.resolve + §25.6.5.4 .then ─────────────────
            AsyncPromiseTest {
                id: "ES2020-25.6.4.5-resolve-then-identity".to_string(),
                description:
                    "Promise.resolve(v).then(cb) — cb receives v with identity semantics."
                        .to_string(),
                es_section: "25.6.4.5".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::ResolveThen,
                source: "Promise.resolve(42).then(v => console.log(v));".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "42\n".to_string(),
                },
            },
            // ─── §25.6.4.4 Promise.reject + §25.6.5.1 .catch ─────────────────
            AsyncPromiseTest {
                id: "ES2020-25.6.4.4-reject-catch-propagates-reason".to_string(),
                description:
                    "Promise.reject(r).catch(cb) — cb receives r without altering it."
                        .to_string(),
                es_section: "25.6.4.4".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::RejectCatch,
                source: "Promise.reject('boom').catch(r => console.log(r));".to_string(),
                expected_result: ExpectedResult::Success {
                    output: "boom\n".to_string(),
                },
            },
            // ─── §8.4.1 microtask checkpoint ─────────────────────────────────
            AsyncPromiseTest {
                id: "ES2020-8.4.1-microtask-runs-after-script-sync".to_string(),
                description:
                    "Synchronous statements complete before any microtask handler runs — \
                     the microtask drained after script-as-macrotask returns."
                        .to_string(),
                es_section: "8.4.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::MicrotaskOrdering,
                source: "console.log('sync-1'); Promise.resolve().then(() => console.log('micro')); console.log('sync-2');"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "sync-1\nsync-2\nmicro\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2020-25.6.5.4-multiple-microtasks-fifo".to_string(),
                description:
                    "Independent microtasks enqueued in source order drain in FIFO order."
                        .to_string(),
                es_section: "25.6.5.4".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::MicrotaskOrdering,
                source: "Promise.resolve().then(() => console.log('A')); Promise.resolve().then(() => console.log('B')); Promise.resolve().then(() => console.log('C'));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "A\nB\nC\n".to_string(),
                },
            },
            // ─── §25.6.5.4 chained then ──────────────────────────────────────
            AsyncPromiseTest {
                id: "ES2020-25.6.5.4-chained-then-propagates-return-value".to_string(),
                description:
                    "A handler's return value becomes the fulfillment value of the chained \
                     promise the next .then() observes."
                        .to_string(),
                es_section: "25.6.5.4".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::ChainedThen,
                source: "Promise.resolve('a').then(v => v + 'b').then(v => console.log(v));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "ab\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2020-25.6.5.1-then-error-routed-to-catch".to_string(),
                description:
                    "An exception thrown in a .then handler is captured by the next .catch."
                        .to_string(),
                es_section: "25.6.5.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::RejectCatch,
                source: "Promise.resolve(0).then(() => { throw 'thrown'; }).catch(r => console.log(r));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "thrown\n".to_string(),
                },
            },
            // ─── §25.6.4.1 Promise.all ───────────────────────────────────────
            AsyncPromiseTest {
                id: "ES2020-25.6.4.1-promise-all-aggregates-fulfillments".to_string(),
                description:
                    "Promise.all([resolve(1), resolve(2), resolve(3)]) fulfills with [1,2,3]."
                        .to_string(),
                es_section: "25.6.4.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::PromiseAll,
                source: "Promise.all([Promise.resolve(1), Promise.resolve(2), Promise.resolve(3)]).then(arr => console.log(arr.join(',')));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "1,2,3\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2020-25.6.4.3-promise-race-uses-first-settled-input".to_string(),
                description:
                    "Promise.race resolves with the first already-settled input in iteration order."
                        .to_string(),
                es_section: "25.6.4.3".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::PromiseRace,
                source: "Promise.race([Promise.resolve('first'), Promise.resolve('second')]).then(v => console.log(v));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "first\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2020-25.6.4.2-promise-allsettled-preserves-status-and-order".to_string(),
                description:
                    "Promise.allSettled preserves input order and reports fulfilled/rejected status fields."
                        .to_string(),
                es_section: "25.6.4.2".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::PromiseAllSettled,
                source: "Promise.allSettled([Promise.resolve('ok'), Promise.reject('bad')]).then(r => console.log(r[0].status + ':' + r[0].value + ',' + r[1].status + ':' + r[1].reason));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "fulfilled:ok,rejected:bad\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2022-27.2.4.5-promise-any-fulfills-with-first-fulfillment".to_string(),
                description:
                    "Promise.any ignores earlier rejections and fulfills with the first fulfillment."
                        .to_string(),
                es_section: "27.2.4.5".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::PromiseAny,
                source: "Promise.any([Promise.reject('no'), Promise.resolve('yes')]).then(v => console.log(v));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "yes\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2022-27.2.4.5-promise-any-all-rejected-aggregate-errors".to_string(),
                description:
                    "Promise.any rejects with an AggregateError whose errors preserve rejection order."
                        .to_string(),
                es_section: "27.2.4.5".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::PromiseAny,
                source: "Promise.any([Promise.reject('a'), Promise.reject('b')]).catch(e => console.log(e.name + ':' + e.errors.join(',')));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "AggregateError:a,b\n".to_string(),
                },
            },
            // ─── §15.8 async function ────────────────────────────────────────
            AsyncPromiseTest {
                id: "ES2020-15.8-async-function-wraps-return-in-promise".to_string(),
                description:
                    "An async function's synchronous `return v` produces a promise that \
                     fulfills with v on the microtask queue."
                        .to_string(),
                es_section: "15.8".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::AsyncFunctionFulfillment,
                source: "async function f() { return 7; } f().then(v => console.log(v));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "7\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2020-15.8-async-function-throw-becomes-rejection".to_string(),
                description:
                    "An async function's synchronous `throw` produces a rejected promise."
                        .to_string(),
                es_section: "15.8".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::AsyncFunctionFulfillment,
                source: "async function f() { throw 'nope'; } f().catch(r => console.log(r));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "nope\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2020-15.8.4-await-rejected-promise-propagates-to-caller".to_string(),
                description:
                    "await on a rejected promise rejects the containing async function's promise."
                        .to_string(),
                es_section: "15.8.4".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::AwaitRejection,
                source: "async function f() { await Promise.reject('await-boom'); console.log('unreachable'); } f().catch(r => console.log(r));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "await-boom\n".to_string(),
                },
            },
            // ─── §15.8.4 await ───────────────────────────────────────────────
            AsyncPromiseTest {
                id: "ES2020-15.8.4-await-assimilates-thenable".to_string(),
                description:
                    "await on a fulfilled promise resumes the async function with the \
                     fulfillment value on the microtask queue."
                        .to_string(),
                es_section: "15.8.4".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::AwaitThenable,
                source: "async function f() { const v = await Promise.resolve(11); return v + 1; } f().then(v => console.log(v));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "12\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2020-8.4.1-settimeout-runs-after-microtask-checkpoint".to_string(),
                description:
                    "setTimeout(0) callbacks run after current-script microtasks drain."
                        .to_string(),
                es_section: "8.4.1".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::TimerMicrotaskOrdering,
                source: "setTimeout(() => console.log('timer'), 0); Promise.resolve().then(() => console.log('micro')); console.log('sync');"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "sync\nmicro\ntimer\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2020-25.6.1.9-unhandled-rejection-does-not-block-microtasks".to_string(),
                description:
                    "HostPromiseRejectionTracker observation must not reorder later fulfillment jobs."
                        .to_string(),
                es_section: "25.6.1.9".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::UnhandledRejectionTracking,
                source: "Promise.reject('unhandled'); Promise.resolve().then(() => console.log('after-unhandled'));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "after-unhandled\n".to_string(),
                },
            },
            AsyncPromiseTest {
                id: "ES2020-25.6.1.3-promise-resolve-thenable-enqueues-nested-microtask"
                    .to_string(),
                description:
                    "Promise.resolve(thenable) calls then and preserves nested microtask order."
                        .to_string(),
                es_section: "25.6.1.3".to_string(),
                requirement_level: RequirementLevel::Must,
                category: AsyncPromiseCategory::ThenableAssimilation,
                source: "const t = { then(resolve) { Promise.resolve().then(() => console.log('nested')); resolve('thenable'); } }; Promise.resolve(t).then(v => console.log(v));"
                    .to_string(),
                expected_result: ExpectedResult::Success {
                    output: "nested\nthenable\n".to_string(),
                },
            },
        ]
    }

    pub fn run_conformance(&self, security_epoch: SecurityEpoch) -> AsyncPromiseReport {
        let mut results = BTreeMap::new();
        let mut statistics = ConformanceStatistics::default();

        for test in &self.tests {
            let result = self.execute_test(test, security_epoch);

            match result {
                AsyncPromiseResult::Pass => statistics.passed += 1,
                AsyncPromiseResult::Fail { .. } => statistics.failed += 1,
                AsyncPromiseResult::Error { .. } => statistics.errored += 1,
                AsyncPromiseResult::Skip { .. } => statistics.skipped += 1,
            }

            statistics.total_tests += 1;
            results.insert(test.id.clone(), result);
        }

        statistics.pass_rate_millionths =
            ratio_millionths(statistics.passed, statistics.total_tests);

        AsyncPromiseReport {
            schema_version: ASYNC_PROMISE_CONFORMANCE_SCHEMA.to_string(),
            security_epoch,
            test_results: results.clone(),
            statistics,
            coverage_by_category: self.coverage_by_category(&results),
        }
    }

    fn execute_test(
        &self,
        test: &AsyncPromiseTest,
        _security_epoch: SecurityEpoch,
    ) -> AsyncPromiseResult {
        let mut engine = HybridRouter::default();
        let eval_result = engine.eval(&test.source);
        match evaluate_test262_result(eval_result, &test.expected_result, &test.id) {
            Test262Result::Pass => AsyncPromiseResult::Pass,
            Test262Result::Fail { reason } => AsyncPromiseResult::Fail { reason },
            Test262Result::Error { error } => AsyncPromiseResult::Error { error },
            Test262Result::Skip { reason } => AsyncPromiseResult::Skip { reason },
        }
    }

    fn coverage_by_category(
        &self,
        results: &BTreeMap<String, AsyncPromiseResult>,
    ) -> BTreeMap<AsyncPromiseCategory, CategoryCoverage> {
        let mut coverage: BTreeMap<AsyncPromiseCategory, CategoryCoverage> = BTreeMap::new();
        for test in &self.tests {
            let entry = coverage
                .entry(test.category.clone())
                .or_insert_with(CategoryCoverage::default);
            entry.total += 1;
            if let Some(result) = results.get(&test.id)
                && matches!(result, AsyncPromiseResult::Pass)
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
pub struct AsyncPromiseReport {
    pub schema_version: String,
    pub security_epoch: SecurityEpoch,
    pub test_results: BTreeMap<String, AsyncPromiseResult>,
    pub statistics: ConformanceStatistics,
    pub coverage_by_category: BTreeMap<AsyncPromiseCategory, CategoryCoverage>,
}

fn ratio_millionths(passed: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    ((u128::from(passed) * 1_000_000_u128) / u128::from(total)).min(1_000_000_u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned allow-list of MUST-tier async/promise cases known to fail.
    /// Empty for the initial wave — if real engine gaps surface during
    /// verification (tracked under follow-up bead), add `(id, "bd-...")`
    /// entries here AND open the bead first.
    const EXPECTED_FAILING_MUSTS: &[(&str, &str)] = &[];

    fn must_tests(harness: &AsyncPromiseHarness) -> Vec<&AsyncPromiseTest> {
        harness
            .tests
            .iter()
            .filter(|t| t.requirement_level == RequirementLevel::Must)
            .collect()
    }

    #[test]
    fn harness_has_minimum_initial_coverage() {
        let harness = AsyncPromiseHarness::new();
        assert!(
            harness.tests.len() >= 18,
            "bd-5sxc9 wave promised >=18 spec-anchored cases; got {}",
            harness.tests.len(),
        );
        for test in &harness.tests {
            assert!(
                !test.es_section.is_empty(),
                "test {} missing es_section id",
                test.id,
            );
            assert!(
                test.id.starts_with("ES2020-") || test.id.starts_with("ES2022-"),
                "test id {} must start with ES2020- or ES2022- to mark spec anchoring",
                test.id,
            );
        }
    }

    #[test]
    fn harness_covers_all_initial_categories() {
        use AsyncPromiseCategory::*;
        let harness = AsyncPromiseHarness::new();
        let categories: std::collections::BTreeSet<_> =
            harness.tests.iter().map(|t| t.category.clone()).collect();
        for required in [
            ResolveThen,
            RejectCatch,
            MicrotaskOrdering,
            ChainedThen,
            PromiseAll,
            PromiseRace,
            PromiseAllSettled,
            PromiseAny,
            AsyncFunctionFulfillment,
            AwaitRejection,
            AwaitThenable,
            TimerMicrotaskOrdering,
            UnhandledRejectionTracking,
            ThenableAssimilation,
        ] {
            assert!(
                categories.contains(&required),
                "bd-5sxc9 matrix must include category {required:?}",
            );
        }
    }

    #[test]
    fn must_tier_has_no_unexpected_regressions() {
        let harness = AsyncPromiseHarness::new();
        let report = harness.run_conformance(SecurityEpoch::from_raw(1));
        let allow: std::collections::BTreeMap<&str, &str> =
            EXPECTED_FAILING_MUSTS.iter().copied().collect();

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

        let mut unexpected_failures: Vec<(String, AsyncPromiseResult)> = Vec::new();
        let mut unexpected_passes: Vec<String> = Vec::new();
        for test in must_tests(&harness) {
            let result = report
                .test_results
                .get(&test.id)
                .cloned()
                .unwrap_or_else(|| AsyncPromiseResult::Error {
                    error: "<missing result>".to_string(),
                });
            let waived = allow.contains_key(test.id.as_str());
            match (&result, waived) {
                (AsyncPromiseResult::Pass, false) => {}
                (AsyncPromiseResult::Pass, true) => unexpected_passes.push(test.id.clone()),
                (_, true) => {}
                (other, false) => unexpected_failures.push((test.id.clone(), other.clone())),
            }
        }

        assert!(
            unexpected_failures.is_empty(),
            "{} MUST-tier async/promise test(s) regressed unexpectedly:\n  {}",
            unexpected_failures.len(),
            unexpected_failures
                .iter()
                .map(|(id, r)| format!("{id}: {r:?}"))
                .collect::<Vec<_>>()
                .join("\n  "),
        );
        assert!(
            unexpected_passes.is_empty(),
            "{} MUST-tier async/promise test(s) waived in EXPECTED_FAILING_MUSTS now pass — remove their entries:\n  {}",
            unexpected_passes.len(),
            unexpected_passes.join("\n  "),
        );
    }

    #[test]
    fn report_round_trips_through_serde_json() {
        let harness = AsyncPromiseHarness::new();
        let report = harness.run_conformance(SecurityEpoch::from_raw(3));
        let json = serde_json::to_string(&report).expect("serialize");
        let back: AsyncPromiseReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, back, "report must round-trip");
        assert_eq!(report.schema_version, ASYNC_PROMISE_CONFORMANCE_SCHEMA);
        assert_eq!(report.statistics.total_tests, harness.tests.len() as u64);
    }
}
