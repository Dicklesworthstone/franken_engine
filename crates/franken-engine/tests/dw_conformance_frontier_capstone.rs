#![forbid(unsafe_code)]
//! bd-fqlfw.7.6 — E7.TEST Conformance-Frontier test+verify capstone.
//!
//! Consolidated end-to-end coverage for the whole E7 stack (report-first
//! conformance frontier), exercising every acceptance bullet of the bead against
//! the *real* modules and the *real* operator binary — no mocks, no synthetic
//! classifiers:
//!
//!   1. **Deterministic clustering** (E7.T1): content-hashed cluster ids are stable
//!      across runs on the same corpus; the whole report is byte-identical and each
//!      id matches the standalone `cluster_id()` helper.
//!   2. **Ranking reproducibility** (E7.T2): the transparent impact score recomputes
//!      identically (same `report_digest`) and every cluster carries a
//!      self-contained, logged explanation (count × usage × locality).
//!   3. **Drift detection / truth gate** (E7.T3): a construct that fails but is
//!      absent from the parser/lowering gap inventories is an *undocumented* gap and
//!      fails the truth gate closed; a documented construct reconciles.
//!   4. **Weighted coverage** (E7.T4): six views (parser / builtin / control-flow /
//!      async / module / intentional-divergence) plus a single gated headline number
//!      and an anti-gaming floor (the weakest non-empty view).
//!   5. **Idempotent auto-bead filing** (E7.T5): re-running files NO duplicates
//!      (dedup on the content-hashed cluster id; open OR closed clusters skipped),
//!      and each proposal carries its failing cases + an E4 intrinsic-table scaffold.
//!   6. **Operator binary E2E**: `franken_coverage_frontier` runs the rank /
//!      cross-reference / coverage-summary / file-beads modes over the real
//!      engine↔core differential oracle, producing deterministic, content-addressed
//!      output (double-run digest equality) and dedup via a persisted ledger.
//!
//! Hermetic by construction: the conformance inputs are synthesized in-process and
//! the binary E2E uses only the in-process engine↔core oracle (no node/bun spawn),
//! so the suite is deterministic on any host.

use std::path::PathBuf;
use std::process::Command;

use frankenengine_engine::coverage_frontier::{
    FailureObservation, FrontierSource, cluster_failures, cluster_id, observations_from_conformance,
};
use frankenengine_engine::coverage_frontier_filing::{
    AUTOFILE_MARKER, DEFAULT_TOP_N, FiledLedger, ScaffoldKind, build_filing_plan,
};
use frankenengine_engine::coverage_frontier_rank::{
    construct_census_from_conformance, rank_clusters,
};
use frankenengine_engine::coverage_frontier_xref::{cross_reference, default_inventory_entries};
use frankenengine_engine::coverage_summary::{CoverageView, summarize_conformance};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::test262_conformance_runner::{ConformanceReport, TestRecord, TestResult};

/// Path to the built operator binary (cargo builds it before this test runs).
const FRONTIER_BIN: &str = env!("CARGO_BIN_EXE_franken_coverage_frontier");

/// A small but view-spanning synthetic Test262 conformance report.
fn synthetic_conformance() -> ConformanceReport {
    let r = |path: &str, result: TestResult| {
        TestRecord::new(PathBuf::from(path), result, 1, None, false)
    };
    let records = vec![
        // built-ins/* (builtin view) — Map mostly failing.
        r("test/built-ins/Map/prototype/get.js", TestResult::Fail),
        r("test/built-ins/Map/prototype/set.js", TestResult::Error),
        r("test/built-ins/Map/prototype/has.js", TestResult::Pass),
        r("test/built-ins/String/prototype/at.js", TestResult::Fail),
        r("test/built-ins/String/prototype/trim.js", TestResult::Pass),
        // language/expressions (parser view).
        r(
            "test/language/expressions/optional-chaining/a.js",
            TestResult::Fail,
        ),
        r(
            "test/language/expressions/optional-chaining/b.js",
            TestResult::Pass,
        ),
        // language/statements (control-flow view).
        r("test/language/statements/for-of/a.js", TestResult::Pass),
        r("test/language/statements/for-of/b.js", TestResult::Pass),
        // module view.
        r("test/language/module-code/namespace.js", TestResult::Fail),
        // skip is ignored everywhere.
        r("test/built-ins/Map/prototype/clear.js", TestResult::Skip),
    ];
    let total = records.len() as u64;
    ConformanceReport::new(
        SecurityEpoch::from_raw(7),
        "e7capstone0000".to_string(),
        records,
        total,
        true,
    )
}

// --------------------------------------------------------------------------
// 1. Deterministic clustering (E7.T1)
// --------------------------------------------------------------------------

#[test]
fn capstone_clustering_is_deterministic_and_content_addressed() {
    let report = synthetic_conformance();
    let obs = observations_from_conformance(&report, 3);
    let a = cluster_failures(&obs, 3, 8);
    let b = cluster_failures(&obs, 3, 8);
    assert_eq!(a, b, "identical input yields a byte-identical clustering");
    assert_eq!(a.report_digest, b.report_digest);
    // Only Fail/Error are failures; Pass/Skip excluded.
    assert_eq!(a.total_failures, 5);
    // Every cluster id is the stable content hash of (source, construct).
    for cluster in &a.clusters {
        let expected = cluster_id(FrontierSource::Test262, &cluster.construct);
        assert_eq!(cluster.cluster_id, expected, "id is content-addressed");
        assert_eq!(cluster.cluster_id.len(), 64);
    }
}

// --------------------------------------------------------------------------
// 2. Ranking reproducibility + explanation (E7.T2)
// --------------------------------------------------------------------------

#[test]
fn capstone_ranking_is_reproducible_and_explains_every_cluster() {
    let report = synthetic_conformance();
    let obs = observations_from_conformance(&report, 3);
    let frontier = cluster_failures(&obs, 3, 8);
    let census = construct_census_from_conformance(&report, 3);

    let a = rank_clusters(&frontier, &census, None);
    let b = rank_clusters(&frontier, &census, None);
    assert_eq!(a, b, "ranking recomputes identically");
    assert_eq!(a.report_digest, b.report_digest);

    // Ranks are a dense 1..=N and every cluster logs its transparent formula.
    let ranks: Vec<usize> = a.ranked.iter().map(|c| c.rank).collect();
    assert_eq!(ranks, (1..=a.ranked.len()).collect::<Vec<_>>());
    for cluster in &a.ranked {
        let exp = &cluster.score.explanation;
        assert!(exp.contains("failing"), "explanation logs the count: {exp}");
        assert!(exp.contains("usage"), "explanation logs usage: {exp}");
        assert!(exp.contains("locality"), "explanation logs locality: {exp}");
    }
}

// --------------------------------------------------------------------------
// 3. Drift detection / truth gate (E7.T3)
// --------------------------------------------------------------------------

#[test]
fn capstone_truth_gate_fails_closed_on_an_undocumented_gap() {
    // A construct that is clearly absent from the parser/lowering gap inventories.
    let obs = vec![FailureObservation::new(
        FrontierSource::Test262,
        "built-ins/ZzzUndocumentedConstructXyz",
        "test/built-ins/ZzzUndocumentedConstructXyz/a.js",
        "fail",
    )];
    let frontier = cluster_failures(&obs, 3, 8);
    let xref = cross_reference(&frontier, &default_inventory_entries());
    assert!(
        !xref.truth_gate_pass,
        "an undocumented gap must fail the truth gate closed"
    );
    assert!(xref.undocumented_count >= 1);
    assert!(
        xref.findings.iter().any(|f| f.outcome == "undocumented"),
        "the undocumented cluster is surfaced as a finding"
    );
}

#[test]
fn capstone_truth_gate_is_deterministic() {
    let obs = vec![FailureObservation::new(
        FrontierSource::Test262,
        "built-ins/ZzzUndocumentedConstructXyz",
        "test/built-ins/ZzzUndocumentedConstructXyz/a.js",
        "fail",
    )];
    let frontier = cluster_failures(&obs, 3, 8);
    let a = cross_reference(&frontier, &default_inventory_entries());
    let b = cross_reference(&frontier, &default_inventory_entries());
    assert_eq!(a, b);
    assert_eq!(a.report_digest, b.report_digest);
}

// --------------------------------------------------------------------------
// 4. Weighted coverage: six views + gated number + floor (E7.T4)
// --------------------------------------------------------------------------

#[test]
fn capstone_weighted_coverage_has_six_views_and_an_antigaming_floor() {
    let report = synthetic_conformance();
    let limitations = vec!["capstone synthetic corpus; executed != conformance".to_string()];
    let summary = summarize_conformance(&report, 0, limitations.clone());

    // All six views are present, in canonical sorted order.
    let view_names: Vec<&str> = summary.views.iter().map(|v| v.view.as_str()).collect();
    for expected in [
        CoverageView::Parser.as_str(),
        CoverageView::Builtin.as_str(),
        CoverageView::ControlFlow.as_str(),
        CoverageView::Async.as_str(),
        CoverageView::Module.as_str(),
        CoverageView::IntentionalDivergence.as_str(),
    ] {
        assert!(view_names.contains(&expected), "missing view {expected}");
    }
    assert_eq!(summary.views.len(), 6);

    // A single gated headline number over the conformance views.
    assert!(summary.in_scope_total > 0);
    assert!(summary.observable_surface_executed_millionths <= 1_000_000);

    // Anti-gaming floor: the weakest NON-EMPTY view is surfaced alongside the
    // aggregate, and it is <= the aggregate (a strong view cannot hide a weak one).
    assert_ne!(summary.floor_view, "none");
    assert!(
        summary.floor_view_executed_millionths <= summary.observable_surface_executed_millionths,
        "the floor is no stronger than the aggregate"
    );

    // The figure never travels without its scope caveats, and is deterministic.
    assert!(!summary.limitations.is_empty());
    let again = summarize_conformance(&report, 0, limitations);
    assert_eq!(summary.report_digest, again.report_digest);
}

// --------------------------------------------------------------------------
// 5. Idempotent auto-bead filing + scaffold (E7.T5)
// --------------------------------------------------------------------------

#[test]
fn capstone_auto_bead_filing_is_idempotent_and_scaffolds() {
    let report = synthetic_conformance();
    let obs = observations_from_conformance(&report, 3);
    let frontier = cluster_failures(&obs, 3, 8);
    let census = construct_census_from_conformance(&report, 3);
    let ranked = rank_clusters(&frontier, &census, None);

    // Run 1: empty ledger -> everything is proposed.
    let mut ledger = FiledLedger::new();
    let first = build_filing_plan(&ranked, &frontier, &ledger, DEFAULT_TOP_N, None);
    assert!(first.proposal_count >= 1);
    assert_eq!(first.skipped_count, 0);

    // Each proposal carries its failing cases + the dedup marker; built-ins carry an
    // E4 IntrinsicRow scaffold (and only built-ins do).
    let mut saw_intrinsic = false;
    for p in &first.proposals {
        assert!(p.body.contains(AUTOFILE_MARKER));
        assert!(p.body.contains(&format!("cluster_id={}", p.cluster_id)));
        let has_row = p.scaffold.contains("IntrinsicRow {");
        assert_eq!(
            has_row,
            p.scaffold_kind == ScaffoldKind::Intrinsic,
            "only built-ins clusters scaffold a row ({})",
            p.construct
        );
        if p.scaffold_kind == ScaffoldKind::Intrinsic {
            saw_intrinsic = true;
            assert!(
                !p.sample_case_ids.is_empty(),
                "built-ins proposal lists cases"
            );
            assert!(
                p.scaffold
                    .contains(&format!("conformance: \"test262:{}\"", p.construct))
            );
        }
    }
    assert!(
        saw_intrinsic,
        "the corpus has at least one built-ins cluster"
    );

    // Operator files each proposal and records it.
    for (i, p) in first.proposals.iter().enumerate() {
        ledger.record(
            p.cluster_id.clone(),
            format!("bd-capstone-{i}"),
            p.construct.clone(),
            "filed in capstone run 1",
        );
    }

    // Run 2: identical inputs, updated ledger -> zero new, all skipped (no duplicates).
    let second = build_filing_plan(&ranked, &frontier, &ledger, DEFAULT_TOP_N, None);
    assert_eq!(
        second.proposal_count, 0,
        "re-running files no duplicate beads"
    );
    assert_eq!(second.skipped_count, first.proposal_count);
}

#[test]
fn capstone_full_pipeline_threads_cluster_id_t1_through_t5() {
    // The content-hashed cluster id from T1 is the SAME id ranking, the truth gate,
    // and the filing plan all key on — the join handle that makes the chain cohere.
    let report = synthetic_conformance();
    let obs = observations_from_conformance(&report, 3);
    let frontier = cluster_failures(&obs, 3, 8);
    let census = construct_census_from_conformance(&report, 3);
    let ranked = rank_clusters(&frontier, &census, None);
    let xref = cross_reference(&frontier, &default_inventory_entries());
    let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);

    let t1_ids: std::collections::BTreeSet<&str> = frontier
        .clusters
        .iter()
        .map(|c| c.cluster_id.as_str())
        .collect();
    for c in &ranked.ranked {
        assert!(t1_ids.contains(c.cluster_id.as_str()), "rank id ⊆ T1 ids");
    }
    for f in &xref.findings {
        assert!(t1_ids.contains(f.cluster_id.as_str()), "xref id ⊆ T1 ids");
    }
    for p in &plan.proposals {
        assert!(t1_ids.contains(p.cluster_id.as_str()), "filing id ⊆ T1 ids");
    }
}

// --------------------------------------------------------------------------
// 6. Operator binary E2E (real engine↔core oracle, deterministic + dedup)
// --------------------------------------------------------------------------

fn run_frontier(args: &[&str]) -> std::process::Output {
    Command::new(FRONTIER_BIN)
        .args(args)
        .output()
        .expect("spawn franken_coverage_frontier")
}

fn json_field(stdout: &[u8], pointer: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_slice(stdout).expect("binary emits JSON on stdout");
    v.pointer(pointer)
        .cloned()
        .unwrap_or_else(|| panic!("missing {pointer} in binary output"))
}

#[test]
fn capstone_cli_file_beads_plan_is_deterministic() {
    let a = run_frontier(&["--engine-core-oracle", "--file-beads"]);
    let b = run_frontier(&["--engine-core-oracle", "--file-beads"]);
    assert!(a.status.success(), "plan-only file-beads exits 0");
    assert!(b.status.success());
    let da = json_field(&a.stdout, "/plan_digest");
    let db = json_field(&b.stdout, "/plan_digest");
    assert_eq!(
        da, db,
        "two runs over the same oracle yield the same plan digest"
    );
    assert_eq!(a.stdout, b.stdout, "the whole plan JSON is byte-identical");
    // Plan-only must never fabricate an execution: the schema is the filing plan.
    assert_eq!(
        json_field(&a.stdout, "/schema_version"),
        serde_json::json!("franken-engine.coverage-frontier-filing.v1")
    );
}

#[test]
fn capstone_cli_file_beads_dedups_against_a_persisted_ledger() {
    // First, get the plan to learn the real cluster id the oracle produces.
    let plan = run_frontier(&["--engine-core-oracle", "--file-beads"]);
    assert!(plan.status.success());
    let v: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap();
    let proposals = v["proposals"].as_array().expect("proposals array");
    assert!(
        !proposals.is_empty(),
        "oracle seed corpus yields >=1 cluster"
    );
    let cid = proposals[0]["cluster_id"].as_str().unwrap().to_string();

    // Seed a ledger that already contains that cluster id.
    let dir = std::env::temp_dir().join(format!("e7capstone_ledger_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ledger_path = dir.join("ledger.json");
    let ledger_json = format!(
        r#"{{"schema_version":"franken-engine.coverage-frontier-filed-ledger.v1","records":{{"{cid}":{{"cluster_id":"{cid}","bead_id":"bd-seeded","construct":"runtime","note":"capstone seed"}}}}}}"#
    );
    std::fs::write(&ledger_path, ledger_json).unwrap();

    let out = run_frontier(&[
        "--engine-core-oracle",
        "--file-beads",
        "--ledger",
        ledger_path.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    let proposal_count = json_field(&out.stdout, "/proposal_count");
    let skipped_count = json_field(&out.stdout, "/skipped_count");
    assert_eq!(
        proposal_count,
        serde_json::json!(0),
        "seeded cluster is not re-proposed"
    );
    assert_eq!(
        skipped_count,
        serde_json::json!(1),
        "seeded cluster is skipped"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn capstone_cli_coverage_summary_and_rank_modes_run_deterministically() {
    // Coverage-summary mode over the oracle corpus is deterministic.
    let s1 = run_frontier(&["--engine-core-oracle", "--coverage-summary"]);
    let s2 = run_frontier(&["--engine-core-oracle", "--coverage-summary"]);
    assert!(s1.status.success() && s2.status.success());
    assert_eq!(
        json_field(&s1.stdout, "/report_digest"),
        json_field(&s2.stdout, "/report_digest"),
        "coverage-summary digest is reproducible"
    );

    // Rank mode is deterministic too.
    let r1 = run_frontier(&["--engine-core-oracle", "--rank"]);
    let r2 = run_frontier(&["--engine-core-oracle", "--rank"]);
    assert!(r1.status.success() && r2.status.success());
    assert_eq!(
        json_field(&r1.stdout, "/report_digest"),
        json_field(&r2.stdout, "/report_digest"),
        "ranked digest is reproducible"
    );
}

#[test]
fn capstone_cli_modes_are_mutually_exclusive_and_fail_closed() {
    // The exclusive-mode guard rejects combining report shapes.
    let out = run_frontier(&["--engine-core-oracle", "--file-beads", "--rank"]);
    assert!(
        !out.status.success(),
        "combining --file-beads and --rank is rejected"
    );
    // --execute without --ledger is refused (the persisted-dedup safety rule).
    let out = run_frontier(&["--engine-core-oracle", "--file-beads", "--execute"]);
    assert!(!out.status.success(), "--execute requires --ledger");
    // No failure source selected is a usage error.
    let out = run_frontier(&["--file-beads"]);
    assert!(!out.status.success(), "no source selected fails closed");
}
