//! Enrichment integration tests for `budgeted_synthesis_engine` module.
//!
//! Deep coverage of serde roundtrips, Display distinctness, deterministic hashing,
//! edge-case lifecycle, ordering guarantees, and cross-type workflows.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::budgeted_synthesis_engine::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(900)
}

fn mk_verified(id: &str, speedup: u64) -> SynthesisCandidate {
    SynthesisCandidate::new(
        id,
        "kernel-x",
        CandidateOrigin::Enumerative,
        10,
        EquivalenceProof::verified(5, 500_000),
        Vec::new(),
        vec![CostEstimate::new("hw1", 100_000, 50_000, 800_000)],
        speedup,
    )
}

fn mk_refuted(id: &str) -> SynthesisCandidate {
    let cx = Counterexample {
        input_class: "arr-i32".into(),
        expected_output_hash: ContentHash::compute(b"exp"),
        actual_output_hash: ContentHash::compute(b"act"),
        description: "off-by-one".into(),
    };
    SynthesisCandidate::new(
        id,
        "kernel-x",
        CandidateOrigin::Stochastic,
        12,
        EquivalenceProof::refuted(5, 3, 300_000),
        vec![cx],
        Vec::new(),
        1_100_000,
    )
}

fn mk_timed_out(id: &str) -> SynthesisCandidate {
    SynthesisCandidate::new(
        id,
        "kernel-x",
        CandidateOrigin::TemplateBased,
        15,
        EquivalenceProof::timed_out(8, 4, 1_000_000),
        Vec::new(),
        Vec::new(),
        1_200_000,
    )
}

// ---------------------------------------------------------------------------
// ProofStatus — Display distinctness
// ---------------------------------------------------------------------------

#[test]
fn enrich_proof_status_display_strings_distinct() {
    let displays: BTreeSet<String> = ProofStatus::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), ProofStatus::ALL.len());
}

#[test]
fn enrich_proof_status_clone_eq() {
    for s in ProofStatus::ALL {
        let cloned = *s;
        assert_eq!(*s, cloned);
    }
}

#[test]
fn enrich_proof_status_hash_derives() {
    let mut set = std::collections::BTreeSet::new();
    for s in ProofStatus::ALL {
        set.insert(*s);
    }
    assert_eq!(set.len(), ProofStatus::ALL.len());
}

// ---------------------------------------------------------------------------
// CandidateOrigin — Display distinctness
// ---------------------------------------------------------------------------

#[test]
fn enrich_origin_display_strings_distinct() {
    let displays: BTreeSet<String> = CandidateOrigin::ALL.iter().map(|o| o.to_string()).collect();
    assert_eq!(displays.len(), CandidateOrigin::ALL.len());
}

#[test]
fn enrich_origin_ord_consistent() {
    assert!(CandidateOrigin::Enumerative < CandidateOrigin::Manual);
    assert!(CandidateOrigin::Stochastic < CandidateOrigin::AlgebraicSimplification);
}

#[test]
fn enrich_origin_serde_snake_case_format() {
    let json = serde_json::to_string(&CandidateOrigin::TemplateBased).unwrap();
    assert_eq!(json, "\"template_based\"");
}

// ---------------------------------------------------------------------------
// EquivalenceProof — additional determinism
// ---------------------------------------------------------------------------

#[test]
fn enrich_proof_verified_different_time_different_hash() {
    let p1 = EquivalenceProof::verified(5, 400_000);
    let p2 = EquivalenceProof::verified(5, 400_001);
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrich_proof_refuted_coverage_boundary_one_of_three() {
    let p = EquivalenceProof::refuted(3, 1, 200_000);
    assert_eq!(p.coverage_millionths(), 333_333);
}

#[test]
fn enrich_proof_timed_out_coverage_exact_half() {
    let p = EquivalenceProof::timed_out(10, 5, 500_000);
    assert_eq!(p.coverage_millionths(), 500_000);
}

#[test]
fn enrich_proof_timed_out_serde_fields_preserved() {
    let p = EquivalenceProof::timed_out(20, 12, 750_000);
    let json = serde_json::to_string(&p).unwrap();
    let back: EquivalenceProof = serde_json::from_str(&json).unwrap();
    assert_eq!(back.status, ProofStatus::TimedOut);
    assert_eq!(back.input_classes_tested, 20);
    assert_eq!(back.input_classes_verified, 12);
    assert_eq!(back.proof_time_millionths, 750_000);
}

#[test]
fn enrich_proof_verified_coverage_large_class_count() {
    let p = EquivalenceProof::verified(1_000, 999_000);
    assert_eq!(p.coverage_millionths(), 1_000_000);
}

// ---------------------------------------------------------------------------
// Counterexample — ordering and equality
// ---------------------------------------------------------------------------

#[test]
fn enrich_counterexample_same_input_class_different_description() {
    let cx1 = Counterexample {
        input_class: "alpha".into(),
        expected_output_hash: ContentHash::compute(b"e1"),
        actual_output_hash: ContentHash::compute(b"a1"),
        description: "desc-a".into(),
    };
    let cx2 = Counterexample {
        input_class: "alpha".into(),
        expected_output_hash: ContentHash::compute(b"e1"),
        actual_output_hash: ContentHash::compute(b"a1"),
        description: "desc-b".into(),
    };
    // Same input_class but different description — should differ by Ord
    assert_ne!(cx1, cx2);
}

#[test]
fn enrich_counterexample_debug_format() {
    let cx = Counterexample {
        input_class: "test".into(),
        expected_output_hash: ContentHash::compute(b"e"),
        actual_output_hash: ContentHash::compute(b"a"),
        description: "desc".into(),
    };
    let dbg = format!("{cx:?}");
    assert!(dbg.contains("test"));
    assert!(dbg.contains("desc"));
}

// ---------------------------------------------------------------------------
// CostEstimate — edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_cost_estimate_zero_values() {
    let ce = CostEstimate::new("empty", 0, 0, 0);
    assert_eq!(ce.cycles_millionths, 0);
    assert_eq!(ce.memory_pressure_millionths, 0);
    assert_eq!(ce.throughput_millionths, 0);
}

#[test]
fn enrich_cost_estimate_large_values() {
    let ce = CostEstimate::new("max", u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(ce.cycles_millionths, u64::MAX);
}

#[test]
fn enrich_cost_estimate_debug_contains_hw_id() {
    let ce = CostEstimate::new("zen5", 100, 200, 300);
    let dbg = format!("{ce:?}");
    assert!(dbg.contains("zen5"));
}

// ---------------------------------------------------------------------------
// SynthesisCandidate — skipped proof handling
// ---------------------------------------------------------------------------

#[test]
fn enrich_candidate_skipped_not_admissible() {
    let proof = EquivalenceProof {
        status: ProofStatus::Skipped,
        input_classes_tested: 0,
        input_classes_verified: 0,
        proof_time_millionths: 0,
        content_hash: ContentHash::compute(b"skipped"),
    };
    let c = SynthesisCandidate::new(
        "skip-1",
        "kernel-z",
        CandidateOrigin::Manual,
        5,
        proof,
        Vec::new(),
        Vec::new(),
        2_000_000,
    );
    assert!(!c.is_verified());
    assert!(!c.is_admissible());
}

#[test]
fn enrich_candidate_serde_preserves_all_fields() {
    let c = SynthesisCandidate::new(
        "full-id",
        "original-schema-42",
        CandidateOrigin::AlgebraicSimplification,
        99,
        EquivalenceProof::verified(50, 2_000_000),
        Vec::new(),
        vec![CostEstimate::new("hw-a", 1, 2, 3), CostEstimate::new("hw-b", 4, 5, 6)],
        1_500_000,
    );
    let json = serde_json::to_string_pretty(&c).unwrap();
    let back: SynthesisCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(back.candidate_id, "full-id");
    assert_eq!(back.original_schema_id, "original-schema-42");
    assert_eq!(back.origin, CandidateOrigin::AlgebraicSimplification);
    assert_eq!(back.op_count, 99);
    assert_eq!(back.cost_estimates.len(), 2);
    assert_eq!(back.speedup_millionths, 1_500_000);
}

#[test]
fn enrich_candidate_hash_differs_on_origin() {
    let c1 = SynthesisCandidate::new(
        "same",
        "kernel",
        CandidateOrigin::Enumerative,
        10,
        EquivalenceProof::verified(5, 500_000),
        Vec::new(),
        Vec::new(),
        1_100_000,
    );
    let c2 = SynthesisCandidate::new(
        "same",
        "kernel",
        CandidateOrigin::Stochastic,
        10,
        EquivalenceProof::verified(5, 500_000),
        Vec::new(),
        Vec::new(),
        1_100_000,
    );
    assert_ne!(c1.content_hash, c2.content_hash);
}

// ---------------------------------------------------------------------------
// SynthesisBudget — edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_budget_clone_eq() {
    let b = SynthesisBudget::custom(32, 3_000_000, 750_000);
    let b2 = b.clone();
    assert_eq!(b, b2);
}

#[test]
fn enrich_budget_debug_contains_fields() {
    let b = SynthesisBudget::default();
    let dbg = format!("{b:?}");
    assert!(dbg.contains("max_candidates"));
    assert!(dbg.contains("search_time_millionths"));
}

// ---------------------------------------------------------------------------
// SynthesisReport — multi-candidate scoring
// ---------------------------------------------------------------------------

#[test]
fn enrich_report_five_admissible_picks_best() {
    let candidates: Vec<SynthesisCandidate> = (0..5)
        .map(|i| mk_verified(&format!("c{i}"), 1_100_000 + i * 10_000))
        .collect();
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert_eq!(r.admissible_count, 5);
    assert_eq!(r.best_candidate_id.as_deref(), Some("c4"));
    assert_eq!(r.admission_rate(), 1_000_000);
}

#[test]
fn enrich_report_skipped_candidates_not_counted_as_timed_out() {
    let skipped = SynthesisCandidate::new(
        "sk",
        "k",
        CandidateOrigin::Manual,
        1,
        EquivalenceProof {
            status: ProofStatus::Skipped,
            input_classes_tested: 0,
            input_classes_verified: 0,
            proof_time_millionths: 0,
            content_hash: ContentHash::compute(b"sk"),
        },
        Vec::new(),
        Vec::new(),
        1_200_000,
    );
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), vec![skipped]);
    assert_eq!(r.timed_out_count, 0);
    assert_eq!(r.refuted_count, 0);
    assert_eq!(r.admissible_count, 0);
}

#[test]
fn enrich_report_content_hash_changes_with_different_candidates() {
    let r1 = SynthesisReport::new(
        epoch(),
        "k1",
        SynthesisBudget::default(),
        vec![mk_verified("c1", 1_100_000)],
    );
    let r2 = SynthesisReport::new(
        epoch(),
        "k1",
        SynthesisBudget::default(),
        vec![mk_verified("c1", 1_100_000), mk_verified("c2", 1_200_000)],
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrich_report_serde_preserves_all_counts() {
    let candidates = vec![
        mk_verified("v1", 1_100_000),
        mk_refuted("r1"),
        mk_timed_out("t1"),
    ];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    let json = serde_json::to_string(&r).unwrap();
    let back: SynthesisReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.admissible_count, 1);
    assert_eq!(back.refuted_count, 1);
    assert_eq!(back.timed_out_count, 1);
    assert_eq!(back.total_counterexamples, 1);
}

// ---------------------------------------------------------------------------
// CounterexampleArchive — cap and cross-schema
// ---------------------------------------------------------------------------

#[test]
fn enrich_archive_three_schemas_independent() {
    let mut archive = CounterexampleArchive::new();
    for schema in &["k1", "k2", "k3"] {
        let r = SynthesisReport::new(
            epoch(),
            *schema,
            SynthesisBudget::default(),
            vec![mk_refuted("cx")],
        );
        archive.ingest(&r);
    }
    assert_eq!(archive.schema_count(), 3);
    assert_eq!(archive.total_count, 3);
    for schema in &["k1", "k2", "k3"] {
        assert_eq!(archive.for_schema(schema).len(), 1);
    }
}

#[test]
fn enrich_archive_serde_roundtrip_with_multiple_schemas() {
    let mut archive = CounterexampleArchive::new();
    for i in 0..3 {
        let r = SynthesisReport::new(
            epoch(),
            format!("k{i}"),
            SynthesisBudget::default(),
            vec![mk_refuted(&format!("c{i}"))],
        );
        archive.ingest(&r);
    }
    let json = serde_json::to_string(&archive).unwrap();
    let back: CounterexampleArchive = serde_json::from_str(&json).unwrap();
    assert_eq!(archive, back);
}

#[test]
fn enrich_archive_ingest_idempotent_total_count() {
    let r = SynthesisReport::new(
        epoch(),
        "k1",
        SynthesisBudget::default(),
        vec![mk_refuted("c1")],
    );
    let mut a = CounterexampleArchive::new();
    a.ingest(&r);
    assert_eq!(a.total_count, 1);
    // Second ingest adds another counterexample (not deduplicated)
    a.ingest(&r);
    assert_eq!(a.total_count, 2);
}

// ---------------------------------------------------------------------------
// Cross-type workflow — multi-origin pipeline
// ---------------------------------------------------------------------------

#[test]
fn enrich_multi_origin_synthesis_workflow() {
    let candidates = vec![
        SynthesisCandidate::new(
            "enum-1",
            "kernel-hot",
            CandidateOrigin::Enumerative,
            8,
            EquivalenceProof::verified(20, 1_000_000),
            Vec::new(),
            vec![CostEstimate::new("x86", 90_000, 40_000, 1_100_000)],
            1_080_000,
        ),
        SynthesisCandidate::new(
            "stoch-1",
            "kernel-hot",
            CandidateOrigin::Stochastic,
            14,
            EquivalenceProof::refuted(15, 10, 800_000),
            vec![Counterexample {
                input_class: "edge".into(),
                expected_output_hash: ContentHash::compute(b"e"),
                actual_output_hash: ContentHash::compute(b"a"),
                description: "divergence".into(),
            }],
            Vec::new(),
            1_300_000,
        ),
        SynthesisCandidate::new(
            "alg-1",
            "kernel-hot",
            CandidateOrigin::AlgebraicSimplification,
            4,
            EquivalenceProof::verified(30, 2_000_000),
            Vec::new(),
            vec![CostEstimate::new("x86", 50_000, 20_000, 1_500_000)],
            1_250_000,
        ),
    ];
    let budget = SynthesisBudget::custom(100, 20_000_000, 5_000_000);
    let r = SynthesisReport::new(epoch(), "kernel-hot", budget, candidates);

    assert_eq!(r.candidate_count(), 3);
    assert_eq!(r.admissible_count, 2); // enum-1 (1.08x >= 1.05x) and alg-1 (1.25x)
    assert_eq!(r.refuted_count, 1);
    assert_eq!(r.best_candidate_id.as_deref(), Some("alg-1"));

    let best = r.best_candidate().unwrap();
    assert_eq!(best.origin, CandidateOrigin::AlgebraicSimplification);
    assert_eq!(best.speedup_millionths, 1_250_000);

    // Archive
    let mut archive = CounterexampleArchive::new();
    archive.ingest(&r);
    assert_eq!(archive.total_count, 1);
}

// ---------------------------------------------------------------------------
// Constants validation
// ---------------------------------------------------------------------------

#[test]
fn enrich_constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
}

#[test]
fn enrich_default_search_budget_reasonable() {
    assert!(DEFAULT_SEARCH_BUDGET >= 1_000_000);
    assert!(DEFAULT_SEARCH_BUDGET <= 60_000_000);
}

#[test]
fn enrich_max_counterexamples_positive() {
    assert!(MAX_COUNTEREXAMPLES >= 1);
}

#[test]
fn enrich_min_speedup_threshold_less_than_one() {
    assert!(MIN_SPEEDUP_THRESHOLD < 1_000_000);
}

#[test]
fn enrich_default_max_candidates_positive() {
    assert!(DEFAULT_MAX_CANDIDATES > 0);
}
