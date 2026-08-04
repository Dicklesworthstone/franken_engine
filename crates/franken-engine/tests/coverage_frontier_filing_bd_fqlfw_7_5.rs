//! End-to-end integration coverage for the E7.T5 gated auto-bead-filing step
//! (`bd-fqlfw.7.5`). The unit tests in `coverage_frontier_filing.rs` cover the
//! plan internals; these exercise the full E7 pipeline a real operator drives —
//! observations → cluster (E7.T1) → rank (E7.T2) → filing plan (E7.T5) — and pin
//! the two acceptance properties end to end:
//!
//!   1. each filed bead carries the failing cases + an E4 intrinsic-table scaffold;
//!   2. re-running does not duplicate beads (dedup on the content-hashed cluster id).

use frankenengine_engine::coverage_frontier::{
    FailureObservation, FrontierSource, cluster_failures, cluster_id,
};
use frankenengine_engine::coverage_frontier_filing::{
    AUTOFILE_MARKER, COVERAGE_FRONTIER_FILING_SCHEMA_VERSION, DEFAULT_TOP_N, FiledClusterRecord,
    FiledLedger, ScaffoldKind, build_filing_plan,
};
use frankenengine_engine::coverage_frontier_rank::{ConstructCensus, rank_clusters};
use std::collections::BTreeMap;

/// Build a ranked frontier from `(source, construct, count)` gaps (neutral usage).
fn pipeline(
    gaps: &[(FrontierSource, &str, usize)],
    census: &BTreeMap<String, ConstructCensus>,
) -> (
    frankenengine_engine::coverage_frontier::CoverageFrontierReport,
    frankenengine_engine::coverage_frontier_rank::RankedFrontierReport,
) {
    let mut observations = Vec::new();
    for (source, construct, count) in gaps {
        for i in 0..*count {
            observations.push(FailureObservation::new(
                *source,
                *construct,
                format!("{construct}/case-{i}.js"),
                "fail",
            ));
        }
    }
    let frontier = cluster_failures(&observations, 3, 8);
    let ranked = rank_clusters(&frontier, census, None);
    (frontier, ranked)
}

#[test]
fn end_to_end_proposal_carries_failing_cases_and_e4_scaffold() {
    let (frontier, ranked) = pipeline(
        &[(FrontierSource::Test262, "built-ins/Map/prototype", 5)],
        &BTreeMap::new(),
    );
    let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);

    assert_eq!(plan.proposal_count, 1);
    let proposal = &plan.proposals[0];

    // (1a) failing cases are carried through from the E7.T1 cluster sample.
    assert_eq!(proposal.sample_case_ids.len(), 5);
    assert!(
        proposal
            .sample_case_ids
            .iter()
            .all(|c| c.starts_with("built-ins/Map/prototype/"))
    );
    for case in &proposal.sample_case_ids {
        assert!(
            proposal.body.contains(case),
            "body lists failing case {case}"
        );
    }

    // (1b) a real E4 IntrinsicRow scaffold, with the conformance path wired.
    assert_eq!(proposal.scaffold_kind, ScaffoldKind::Intrinsic);
    assert!(proposal.scaffold.contains("IntrinsicRow {"));
    assert!(
        proposal
            .scaffold
            .contains("conformance: \"test262:built-ins/Map/prototype\"")
    );
    assert!(proposal.body.contains("IntrinsicRow {"));

    // The bead is self-describing for ledger reconstruction.
    assert!(proposal.body.contains(AUTOFILE_MARKER));
    assert!(
        proposal
            .body
            .contains(&format!("cluster_id={}", proposal.cluster_id))
    );
}

#[test]
fn end_to_end_rerun_does_not_duplicate_beads() {
    let gaps = &[
        (FrontierSource::Test262, "built-ins/Map", 6),
        (FrontierSource::Test262, "built-ins/Set", 4),
        (
            FrontierSource::Test262,
            "language/statements/for-await-of",
            3,
        ),
    ];
    let (frontier, ranked) = pipeline(gaps, &BTreeMap::new());

    // Run 1: empty ledger -> all three proposed.
    let mut ledger = FiledLedger::new();
    let first = build_filing_plan(&ranked, &frontier, &ledger, DEFAULT_TOP_N, None);
    assert_eq!(first.proposal_count, 3);
    assert_eq!(first.skipped_count, 0);

    // Operator files each proposal and records it (what --execute persists).
    for (i, p) in first.proposals.iter().enumerate() {
        assert!(!ledger.contains(&p.cluster_id));
        ledger.record(
            p.cluster_id.clone(),
            format!("bd-filed-{i}"),
            p.construct.clone(),
            "filed in run 1",
        );
    }

    // Run 2: identical inputs, updated ledger -> zero new, all skipped.
    let second = build_filing_plan(&ranked, &frontier, &ledger, DEFAULT_TOP_N, None);
    assert_eq!(second.proposal_count, 0, "no duplicate beads on re-run");
    assert_eq!(second.skipped_count, 3);
    for skip in &second.skipped {
        assert!(skip.reason.contains("bd-filed-"));
    }

    // Run 3: a NEW gap appears in a later corpus -> only the new one is proposed.
    let gaps_grown = &[
        (FrontierSource::Test262, "built-ins/Map", 6),
        (FrontierSource::Test262, "built-ins/Set", 4),
        (
            FrontierSource::Test262,
            "language/statements/for-await-of",
            3,
        ),
        (FrontierSource::Test262, "built-ins/Reflect", 8),
    ];
    let (frontier3, ranked3) = pipeline(gaps_grown, &BTreeMap::new());
    let third = build_filing_plan(&ranked3, &frontier3, &ledger, DEFAULT_TOP_N, None);
    assert_eq!(
        third.proposal_count, 1,
        "only the newly-appeared cluster files"
    );
    assert_eq!(third.proposals[0].construct, "built-ins/Reflect");
    assert_eq!(third.skipped_count, 3);
}

#[test]
fn end_to_end_plan_is_byte_identical_across_runs() {
    let gaps = &[
        (FrontierSource::Test262, "built-ins/Map", 5),
        (FrontierSource::Test262, "language/types", 4),
        (FrontierSource::DifferentialOracle, "runtime", 2),
    ];
    let (frontier, ranked) = pipeline(gaps, &BTreeMap::new());
    let a = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
    let b = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);

    assert_eq!(a.plan_digest, b.plan_digest);
    let ja = serde_json::to_string(&a).expect("serialize plan a");
    let jb = serde_json::to_string(&b).expect("serialize plan b");
    assert_eq!(ja, jb, "serialized plan is byte-identical across runs");
    assert!(ja.contains(COVERAGE_FRONTIER_FILING_SCHEMA_VERSION));
    assert!(ja.contains("\"plan_digest\""));
    assert!(ja.contains("br create "));
}

#[test]
fn end_to_end_scaffold_kinds_are_honest_per_source() {
    let gaps = &[
        (FrontierSource::Test262, "built-ins/Array/prototype", 6),
        (
            FrontierSource::Test262,
            "language/expressions/optional-chaining",
            5,
        ),
        (FrontierSource::DifferentialOracle, "lowering", 4),
        (FrontierSource::Test262, "intl402/DateTimeFormat", 3),
    ];
    let (frontier, ranked) = pipeline(gaps, &BTreeMap::new());
    let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);

    let kind_of = |construct: &str| {
        plan.proposals
            .iter()
            .find(|p| p.construct == construct)
            .map(|p| p.scaffold_kind)
            .unwrap_or_else(|| panic!("missing proposal for {construct}"))
    };
    assert_eq!(
        kind_of("built-ins/Array/prototype"),
        ScaffoldKind::Intrinsic
    );
    assert_eq!(
        kind_of("language/expressions/optional-chaining"),
        ScaffoldKind::LanguageGap
    );
    assert_eq!(kind_of("lowering"), ScaffoldKind::RuntimeDivergence);
    assert_eq!(kind_of("intl402/DateTimeFormat"), ScaffoldKind::Other);

    // Only the built-ins cluster scaffolds an actual IntrinsicRow.
    for p in &plan.proposals {
        let has_row = p.scaffold.contains("IntrinsicRow {");
        assert_eq!(
            has_row,
            p.scaffold_kind == ScaffoldKind::Intrinsic,
            "only intrinsic clusters scaffold a row ({})",
            p.construct
        );
    }
}

#[test]
fn ledger_json_roundtrips() {
    let ledger = FiledLedger::from_records([
        FiledClusterRecord {
            cluster_id: cluster_id(FrontierSource::Test262, "built-ins/Map"),
            bead_id: "bd-aaa".into(),
            construct: "built-ins/Map".into(),
            note: "run 1".into(),
        },
        FiledClusterRecord {
            cluster_id: cluster_id(FrontierSource::Test262, "built-ins/Set"),
            bead_id: "bd-bbb".into(),
            construct: "built-ins/Set".into(),
            note: "run 1".into(),
        },
    ]);
    let json = serde_json::to_string_pretty(&ledger).expect("serialize ledger");
    let back: FiledLedger = serde_json::from_str(&json).expect("deserialize ledger");
    assert_eq!(ledger, back);
    // A loaded ledger dedups exactly the recorded clusters.
    assert!(back.contains(&cluster_id(FrontierSource::Test262, "built-ins/Map")));
    assert!(!back.contains(&cluster_id(FrontierSource::Test262, "built-ins/Array")));
}

#[test]
fn locality_reorders_filing_priority_end_to_end() {
    // Equal failing counts; the nearly-complete family ranks (and files) first.
    let mut census = BTreeMap::new();
    census.insert(
        "built-ins/Almost".to_string(),
        ConstructCensus {
            passing: 45,
            failing: 5,
        },
    );
    census.insert(
        "built-ins/Wall".to_string(),
        ConstructCensus {
            passing: 0,
            failing: 5,
        },
    );
    let (frontier, ranked) = pipeline(
        &[
            (FrontierSource::Test262, "built-ins/Almost", 5),
            (FrontierSource::Test262, "built-ins/Wall", 5),
        ],
        &census,
    );
    let plan = build_filing_plan(&ranked, &frontier, &FiledLedger::new(), DEFAULT_TOP_N, None);
    assert_eq!(plan.proposals[0].construct, "built-ins/Almost");
    assert_eq!(plan.proposals[0].rank, 1);
    assert_eq!(plan.proposals[0].priority, "P2");
}
