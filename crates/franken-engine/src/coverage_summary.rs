//! Weighted Coverage Summary (`bd-fqlfw.7.4`, E7.T4) — aggregate a real Test262
//! [`ConformanceReport`](crate::test262_conformance_runner::ConformanceReport)
//! into a reproducible, content-addressed coverage report whose headline is one
//! number — the measured fraction of the ES2020 observable surface the engine
//! executes — broken into **weighted category views** so that no single gamed
//! category can stand in for the whole.
//!
//! ## The six views
//!
//! Every in-scope Test262 case (the ES2020-normative surface: `language/*` +
//! `built-ins/*`, excluding `intl402`, `annexB`, proposals, and `harness`) is
//! classified into exactly one of five conformance views, plus a sixth view for
//! cataloged intentional divergences:
//!
//! - **parser** — `language/*` expression/type/literal/lexical surface.
//! - **builtin** — `built-ins/*` objects and functions.
//! - **control-flow** — `language/statements/*`.
//! - **async** — promises, generators, `async`/`await`/`yield`.
//! - **module** — module code, `import`/`export`.
//! - **intentional-divergence** — cases the engine deliberately does not conform
//!   to (cataloged separately); excluded from the conformance denominator so a
//!   deliberate divergence is never miscounted as a conformance failure.
//!
//! ## Why this resists a single gamed percentage
//!
//! The report publishes the per-view executed-rate for *all* views **and** a
//! `floor_view` — the weakest non-empty conformance view. The headline
//! `observable_surface_executed_millionths` is the honest aggregate over the
//! conformance views; the floor exposes the weakest category alongside it, so a
//! strong category cannot hide a 0%-executed one behind a flattering average.
//!
//! ## Determinism
//!
//! All rates are fixed-point millionths (`1_000_000` == 100%); views are keyed in
//! a `BTreeMap` and emitted sorted; the `report_digest` is a content hash over
//! the canonical `(view, passed, total)` sequence. Identical input — for a given
//! corpus commit — yields a byte-identical report.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::test262_conformance_runner::{ConformanceReport, TestResult};

/// Schema id stamped on every emitted coverage summary.
pub const COVERAGE_SUMMARY_SCHEMA_VERSION: &str = "franken-engine.coverage-summary.v1";

/// Fixed-point scale: `1_000_000` millionths == `100%`.
pub const SCALE: u64 = 1_000_000;

/// A weighted coverage view over the ES2020 observable surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CoverageView {
    /// `language/*` expression/type/literal/lexical surface.
    Parser,
    /// `built-ins/*` objects and functions.
    Builtin,
    /// `language/statements/*` control flow.
    ControlFlow,
    /// Promises, generators, `async`/`await`/`yield`.
    Async,
    /// Module code, `import`/`export`.
    Module,
    /// Cataloged intentional divergences (excluded from conformance denominator).
    IntentionalDivergence,
}

impl CoverageView {
    /// Stable lower-kebab string used in hashes and serialized output.
    pub fn as_str(self) -> &'static str {
        match self {
            CoverageView::Parser => "parser",
            CoverageView::Builtin => "builtin",
            CoverageView::ControlFlow => "control-flow",
            CoverageView::Async => "async",
            CoverageView::Module => "module",
            CoverageView::IntentionalDivergence => "intentional-divergence",
        }
    }

    /// The five conformance views (everything except intentional-divergence),
    /// in their canonical order.
    pub const CONFORMANCE_VIEWS: [CoverageView; 5] = [
        CoverageView::Parser,
        CoverageView::Builtin,
        CoverageView::ControlFlow,
        CoverageView::Async,
        CoverageView::Module,
    ];
}

/// Running pass/total tally for one view.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ViewCount {
    /// Tests that passed.
    pub passed: u64,
    /// Tests executed (pass + fail + error); `Skip` is excluded.
    pub total: u64,
}

/// Per-view coverage in the emitted report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewCoverage {
    /// View name (`parser`, `builtin`, …).
    pub view: String,
    /// Tests executed in this view.
    pub total: u64,
    /// Tests that passed in this view.
    pub passed: u64,
    /// Executed fraction in millionths (`passed / total`; 0 when empty).
    pub executed_millionths: u64,
}

/// The weighted coverage summary report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSummaryReport {
    /// Schema id (`COVERAGE_SUMMARY_SCHEMA_VERSION`).
    pub schema_version: String,
    /// Test262 corpus commit the measurement was taken against (provenance).
    pub corpus_commit: String,
    /// Total executed across the conformance views (the denominator).
    pub in_scope_total: u64,
    /// Total passed across the conformance views (the numerator).
    pub in_scope_passed: u64,
    /// Headline: executed fraction of the ES2020 observable surface, millionths.
    pub observable_surface_executed_millionths: u64,
    /// Name of the weakest non-empty conformance view (anti-gaming floor).
    pub floor_view: String,
    /// Executed fraction of the weakest conformance view, millionths.
    pub floor_view_executed_millionths: u64,
    /// Cataloged intentional divergences (excluded from the denominator).
    pub intentional_divergence_count: u64,
    /// All six views, sorted by view name.
    pub views: Vec<ViewCoverage>,
    /// Honest scope/measurement limitations carried with the number.
    pub limitations: Vec<String>,
    /// Content hash over the canonical `(view, passed, total)` sequence.
    pub report_digest: String,
}

/// Fixed-point `numerator / denominator` in millionths (0 when `denominator==0`).
pub fn ratio_millionths(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        ((numerator as u128 * SCALE as u128) / denominator as u128) as u64
    }
}

/// Classify a Test262 case path into a conformance view, or `None` when the case
/// is outside the ES2020-normative surface (`intl402`, `annexB`, proposals,
/// `harness`, …). The path may be corpus-relative (`test/language/...`) or
/// category-relative (`language/...`); a leading `test/` is ignored.
pub fn classify_view(path: &Path) -> Option<CoverageView> {
    let raw = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let rel = raw.strip_prefix("test/").unwrap_or(&raw);

    // Async first: promises, generators, async/await/yield can appear under
    // either language/ or built-ins/.
    const ASYNC_MARKERS: [&str; 11] = [
        "async-function",
        "async-generator",
        "async-arrow",
        "/await",
        "/yield",
        "generators/",
        "generator/",
        "promise",
        "asyncfunction",
        "asyncgenerator",
        "asynciterator",
    ];
    if ASYNC_MARKERS.iter().any(|m| rel.contains(m)) {
        return Some(CoverageView::Async);
    }

    // Module next: module code and import/export.
    const MODULE_MARKERS: [&str; 5] = [
        "module-code",
        "/import",
        "/export",
        "import.meta",
        "dynamic-import",
    ];
    if MODULE_MARKERS.iter().any(|m| rel.contains(m)) {
        return Some(CoverageView::Module);
    }

    if rel.starts_with("built-ins/") || rel.starts_with("builtins/") {
        return Some(CoverageView::Builtin);
    }
    if rel.starts_with("language/statements/") {
        return Some(CoverageView::ControlFlow);
    }
    if rel.starts_with("language/") {
        return Some(CoverageView::Parser);
    }
    None
}

/// Fold a conformance report's records into a per-view tally. `Pass` counts as
/// passed; `Fail`/`Error` count toward total only; `Skip` is excluded.
/// Out-of-scope cases (where [`classify_view`] returns `None`) are ignored.
pub fn accumulate_conformance(
    report: &ConformanceReport,
    tally: &mut BTreeMap<CoverageView, ViewCount>,
) {
    for record in &report.test_records {
        let Some(view) = classify_view(&record.path) else {
            continue;
        };
        let entry = tally.entry(view).or_default();
        match record.result {
            TestResult::Pass => {
                entry.passed += 1;
                entry.total += 1;
            }
            TestResult::Fail | TestResult::Error => {
                entry.total += 1;
            }
            TestResult::Skip => {}
        }
    }
}

/// Content hash over the canonical `(view, passed, total)` sequence.
fn compute_summary_digest(views: &[ViewCoverage]) -> String {
    let mut buf = Vec::new();
    for view in views {
        let name = view.view.as_bytes();
        buf.extend_from_slice(&(name.len() as u64).to_be_bytes());
        buf.extend_from_slice(name);
        buf.extend_from_slice(&view.passed.to_be_bytes());
        buf.extend_from_slice(&view.total.to_be_bytes());
    }
    ContentHash::compute(&buf).to_hex()
}

/// Finalize a per-view tally into a content-addressed coverage summary.
///
/// `intentional_divergence_count` is recorded as the sixth view (excluded from
/// the conformance denominator). `limitations` travel with the number so the
/// figure is never read without its scope caveats.
pub fn finalize_summary(
    tally: &BTreeMap<CoverageView, ViewCount>,
    corpus_commit: impl Into<String>,
    intentional_divergence_count: u64,
    limitations: Vec<String>,
) -> CoverageSummaryReport {
    // Emit every conformance view (zero-filled if unseen) plus the divergence
    // view, sorted by name for determinism.
    let mut views: Vec<ViewCoverage> = CoverageView::CONFORMANCE_VIEWS
        .iter()
        .map(|view| {
            let count = tally.get(view).copied().unwrap_or_default();
            ViewCoverage {
                view: view.as_str().to_string(),
                total: count.total,
                passed: count.passed,
                executed_millionths: ratio_millionths(count.passed, count.total),
            }
        })
        .collect();
    views.push(ViewCoverage {
        view: CoverageView::IntentionalDivergence.as_str().to_string(),
        total: intentional_divergence_count,
        passed: intentional_divergence_count,
        executed_millionths: ratio_millionths(
            intentional_divergence_count,
            intentional_divergence_count,
        ),
    });
    views.sort_by(|a, b| a.view.cmp(&b.view));

    // Headline aggregate over the conformance views only.
    let in_scope_total: u64 = CoverageView::CONFORMANCE_VIEWS
        .iter()
        .map(|v| tally.get(v).copied().unwrap_or_default().total)
        .sum();
    let in_scope_passed: u64 = CoverageView::CONFORMANCE_VIEWS
        .iter()
        .map(|v| tally.get(v).copied().unwrap_or_default().passed)
        .sum();
    let observable_surface_executed_millionths = ratio_millionths(in_scope_passed, in_scope_total);

    // Anti-gaming floor: the weakest NON-EMPTY conformance view. An empty view
    // (total 0) cannot be the floor (it has no measured surface).
    let (floor_view, floor_view_executed_millionths) = CoverageView::CONFORMANCE_VIEWS
        .iter()
        .filter_map(|view| {
            let count = tally.get(view).copied().unwrap_or_default();
            if count.total == 0 {
                None
            } else {
                Some((view.as_str(), ratio_millionths(count.passed, count.total)))
            }
        })
        // Weakest first; tie-break by view name for determinism.
        .min_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)))
        .map(|(name, rate)| (name.to_string(), rate))
        .unwrap_or_else(|| ("none".to_string(), 0));

    let report_digest = compute_summary_digest(&views);
    CoverageSummaryReport {
        schema_version: COVERAGE_SUMMARY_SCHEMA_VERSION.to_string(),
        corpus_commit: corpus_commit.into(),
        in_scope_total,
        in_scope_passed,
        observable_surface_executed_millionths,
        floor_view,
        floor_view_executed_millionths,
        intentional_divergence_count,
        views,
        limitations,
        report_digest,
    }
}

/// Convenience: summarize a single conformance report.
pub fn summarize_conformance(
    report: &ConformanceReport,
    intentional_divergence_count: u64,
    limitations: Vec<String>,
) -> CoverageSummaryReport {
    let mut tally = BTreeMap::new();
    accumulate_conformance(report, &mut tally);
    finalize_summary(
        &tally,
        report.test262_commit.clone(),
        intentional_divergence_count,
        limitations,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::SecurityEpoch;
    use crate::test262_conformance_runner::{ConformanceReport, TestRecord};
    use std::path::PathBuf;

    fn view_of(path: &str) -> Option<CoverageView> {
        classify_view(&PathBuf::from(path))
    }

    // ---- classification --------------------------------------------------

    #[test]
    fn classifies_the_five_conformance_views() {
        assert_eq!(
            view_of("language/expressions/addition/x.js"),
            Some(CoverageView::Parser)
        );
        assert_eq!(
            view_of("language/types/boolean/y.js"),
            Some(CoverageView::Parser)
        );
        assert_eq!(
            view_of("built-ins/Array/length.js"),
            Some(CoverageView::Builtin)
        );
        assert_eq!(
            view_of("language/statements/for/s.js"),
            Some(CoverageView::ControlFlow)
        );
        assert_eq!(
            view_of("built-ins/Promise/resolve.js"),
            Some(CoverageView::Async)
        );
        assert_eq!(
            view_of("language/statements/async-function/a.js"),
            Some(CoverageView::Async)
        );
        assert_eq!(
            view_of("language/expressions/await/w.js"),
            Some(CoverageView::Async)
        );
        assert_eq!(
            view_of("language/module-code/x.js"),
            Some(CoverageView::Module)
        );
        assert_eq!(
            view_of("language/expressions/import/i.js"),
            Some(CoverageView::Module)
        );
    }

    #[test]
    fn async_and_module_win_over_statements_and_builtins() {
        // A generator statement is async, not control-flow.
        assert_eq!(
            view_of("language/statements/generators/g.js"),
            Some(CoverageView::Async)
        );
        // An export statement is module, not control-flow.
        assert_eq!(
            view_of("language/statements/export/e.js"),
            Some(CoverageView::Module)
        );
        // built-ins AsyncFunction is async, not builtin.
        assert_eq!(
            view_of("built-ins/AsyncFunction/length.js"),
            Some(CoverageView::Async)
        );
    }

    #[test]
    fn out_of_scope_paths_are_unclassified() {
        // intl402, annexB, harness, staging are top-level categories outside the
        // ES2020-normative surface (language/* + built-ins/*).
        assert_eq!(view_of("intl402/Collator/x.js"), None);
        assert_eq!(view_of("annexB/language/x.js"), None);
        assert_eq!(view_of("harness/assert.js"), None);
        assert_eq!(view_of("staging/explicit/x.js"), None);
    }

    #[test]
    fn leading_test_prefix_is_ignored() {
        assert_eq!(
            view_of("test/built-ins/Map/m.js"),
            Some(CoverageView::Builtin)
        );
        assert_eq!(
            view_of("test/language/statements/if/i.js"),
            Some(CoverageView::ControlFlow)
        );
    }

    // ---- aggregation helpers ---------------------------------------------

    fn report(records: Vec<(&str, TestResult)>) -> ConformanceReport {
        let recs = records
            .into_iter()
            .map(|(p, r)| TestRecord::new(PathBuf::from(p), r, 1, None, false))
            .collect();
        ConformanceReport::new(
            SecurityEpoch::from_raw(0),
            "corpuscommit".into(),
            recs,
            0,
            true,
        )
    }

    #[test]
    fn ratio_millionths_basic() {
        assert_eq!(ratio_millionths(0, 0), 0);
        assert_eq!(ratio_millionths(0, 10), 0);
        assert_eq!(ratio_millionths(1, 2), 500_000);
        assert_eq!(ratio_millionths(10, 10), 1_000_000);
        assert_eq!(ratio_millionths(1, 4), 250_000);
    }

    #[test]
    fn summary_counts_pass_fail_error_excludes_skip() {
        let r = report(vec![
            ("built-ins/Array/a.js", TestResult::Pass),
            ("built-ins/Array/b.js", TestResult::Fail),
            ("built-ins/Array/c.js", TestResult::Error),
            ("built-ins/Array/d.js", TestResult::Skip),
        ]);
        let summary = summarize_conformance(&r, 0, vec![]);
        let builtin = summary.views.iter().find(|v| v.view == "builtin").unwrap();
        assert_eq!(builtin.total, 3, "skip excluded");
        assert_eq!(builtin.passed, 1);
        assert_eq!(builtin.executed_millionths, ratio_millionths(1, 3));
        assert_eq!(summary.corpus_commit, "corpuscommit");
    }

    #[test]
    fn all_six_views_always_present_and_sorted() {
        let summary = summarize_conformance(&report(vec![]), 0, vec![]);
        let names: Vec<&str> = summary.views.iter().map(|v| v.view.as_str()).collect();
        assert_eq!(summary.views.len(), 6);
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "views are emitted sorted by name");
        assert!(names.contains(&"intentional-divergence"));
    }

    // ---- the anti-gaming property ----------------------------------------

    #[test]
    fn floor_exposes_the_weakest_view_despite_a_strong_one() {
        // builtin 100% (10/10), parser 0% (0/5). The aggregate is high-ish but
        // the floor must expose parser at 0.
        let mut records = Vec::new();
        for i in 0..10 {
            records.push((
                Box::leak(format!("built-ins/X/{i}.js").into_boxed_str()) as &str,
                TestResult::Pass,
            ));
        }
        for i in 0..5 {
            records.push((
                Box::leak(format!("language/expressions/e{i}.js").into_boxed_str()) as &str,
                TestResult::Fail,
            ));
        }
        let summary = summarize_conformance(&report(records), 0, vec![]);
        assert_eq!(summary.floor_view, "parser");
        assert_eq!(summary.floor_view_executed_millionths, 0);
        // Headline aggregate is 10/15, but the floor reveals the 0% category.
        assert_eq!(
            summary.observable_surface_executed_millionths,
            ratio_millionths(10, 15)
        );
    }

    #[test]
    fn boosting_one_category_cannot_lift_the_floor() {
        // Start: builtin 5/5, parser 1/10 (floor = parser).
        let mut base = Vec::new();
        for i in 0..5 {
            base.push((
                Box::leak(format!("built-ins/B/{i}.js").into_boxed_str()) as &str,
                TestResult::Pass,
            ));
        }
        base.push(("language/expressions/p0.js", TestResult::Pass));
        for i in 0..9 {
            base.push((
                Box::leak(format!("language/expressions/p{}.js", i + 1).into_boxed_str()) as &str,
                TestResult::Fail,
            ));
        }
        let before = summarize_conformance(&report(base.clone()), 0, vec![]);
        // Add 100 more passing builtins (game the aggregate up).
        let mut gamed = base;
        for i in 0..100 {
            gamed.push((
                Box::leak(format!("built-ins/G/{i}.js").into_boxed_str()) as &str,
                TestResult::Pass,
            ));
        }
        let after = summarize_conformance(&report(gamed), 0, vec![]);
        assert!(
            after.observable_surface_executed_millionths
                > before.observable_surface_executed_millionths,
            "aggregate is gameable upward"
        );
        // ...but the floor (parser at 1/10) is unmoved by builtin gaming.
        assert_eq!(after.floor_view, "parser");
        assert_eq!(
            before.floor_view_executed_millionths,
            after.floor_view_executed_millionths
        );
        assert_eq!(
            after.floor_view_executed_millionths,
            ratio_millionths(1, 10)
        );
    }

    #[test]
    fn intentional_divergences_are_excluded_from_the_denominator() {
        let r = report(vec![
            ("built-ins/Array/a.js", TestResult::Pass),
            ("built-ins/Array/b.js", TestResult::Fail),
        ]);
        let summary = summarize_conformance(&r, 7, vec![]);
        assert_eq!(summary.in_scope_total, 2, "divergences not in denominator");
        assert_eq!(summary.intentional_divergence_count, 7);
        let div = summary
            .views
            .iter()
            .find(|v| v.view == "intentional-divergence")
            .unwrap();
        assert_eq!(div.total, 7);
        assert_eq!(
            div.executed_millionths, SCALE,
            "divergences execute as intended"
        );
    }

    // ---- determinism -----------------------------------------------------

    #[test]
    fn summary_is_deterministic_and_content_hashed() {
        let r = report(vec![
            ("language/statements/for/a.js", TestResult::Pass),
            ("built-ins/Map/m.js", TestResult::Fail),
            ("built-ins/Promise/p.js", TestResult::Pass),
        ]);
        let a = summarize_conformance(&r, 2, vec!["note".into()]);
        let b = summarize_conformance(&r, 2, vec!["note".into()]);
        assert_eq!(a, b);
        assert_eq!(a.report_digest, b.report_digest);
    }

    #[test]
    fn digest_changes_when_a_count_changes() {
        let one = summarize_conformance(
            &report(vec![("built-ins/A/a.js", TestResult::Pass)]),
            0,
            vec![],
        );
        let two = summarize_conformance(
            &report(vec![
                ("built-ins/A/a.js", TestResult::Pass),
                ("built-ins/A/b.js", TestResult::Pass),
            ]),
            0,
            vec![],
        );
        assert_ne!(one.report_digest, two.report_digest);
    }

    #[test]
    fn empty_report_has_zero_headline_and_none_floor() {
        let summary = summarize_conformance(&report(vec![]), 0, vec![]);
        assert_eq!(summary.in_scope_total, 0);
        assert_eq!(summary.observable_surface_executed_millionths, 0);
        assert_eq!(summary.floor_view, "none");
        assert_eq!(summary.schema_version, COVERAGE_SUMMARY_SCHEMA_VERSION);
    }
}
