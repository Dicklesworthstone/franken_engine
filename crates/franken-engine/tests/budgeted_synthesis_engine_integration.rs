//! Integration tests for `budgeted_synthesis_engine` module.
//!
//! Validates public API, serde contracts, determinism, candidate admission,
//! report aggregation, counterexample archiving, and budget enforcement.

use std::collections::BTreeSet;

use frankenengine_engine::budgeted_synthesis_engine::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(700)
}

fn verified_candidate(id: &str, speedup: u64) -> SynthesisCandidate {
    SynthesisCandidate::new(
        id,
        "kernel-1",
        CandidateOrigin::Enumerative,
        10,
        EquivalenceProof::verified(5, 500_000),
        Vec::new(),
        vec![CostEstimate::new("hw1", 100_000, 50_000, 800_000)],
        speedup,
    )
}

fn refuted_candidate(id: &str) -> SynthesisCandidate {
    let cx = Counterexample {
        input_class: "array-int32".into(),
        expected_output_hash: ContentHash::compute(b"expected"),
        actual_output_hash: ContentHash::compute(b"actual"),
        description: "off-by-one".into(),
    };
    SynthesisCandidate::new(
        id,
        "kernel-1",
        CandidateOrigin::Stochastic,
        12,
        EquivalenceProof::refuted(5, 3, 300_000),
        vec![cx],
        Vec::new(),
        1_100_000,
    )
}

fn timed_out_candidate(id: &str) -> SynthesisCandidate {
    SynthesisCandidate::new(
        id,
        "kernel-1",
        CandidateOrigin::TemplateBased,
        15,
        EquivalenceProof::timed_out(8, 4, 1_000_000),
        Vec::new(),
        Vec::new(),
        1_200_000,
    )
}

fn manual_candidate(id: &str, speedup: u64) -> SynthesisCandidate {
    SynthesisCandidate::new(
        id,
        "kernel-2",
        CandidateOrigin::Manual,
        8,
        EquivalenceProof::verified(3, 200_000),
        Vec::new(),
        vec![
            CostEstimate::new("hw1", 80_000, 40_000, 900_000),
            CostEstimate::new("hw2", 120_000, 60_000, 700_000),
        ],
        speedup,
    )
}

fn algebraic_candidate(id: &str, speedup: u64) -> SynthesisCandidate {
    SynthesisCandidate::new(
        id,
        "kernel-3",
        CandidateOrigin::AlgebraicSimplification,
        5,
        EquivalenceProof::verified(10, 800_000),
        Vec::new(),
        vec![CostEstimate::new("hw1", 60_000, 30_000, 1_000_000)],
        speedup,
    )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("budgeted-synthesis"));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "budgeted_synthesis_engine");
}

#[test]
fn bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn threshold_invariants() {
    assert!(DEFAULT_MAX_CANDIDATES > 0);
    assert!(DEFAULT_SEARCH_BUDGET > 0);
    assert!(MAX_COUNTEREXAMPLES > 0);
    assert!(MIN_SPEEDUP_THRESHOLD > 0);
    assert!(MIN_SPEEDUP_THRESHOLD < 1_000_000);
}

// ---------------------------------------------------------------------------
// ProofStatus
// ---------------------------------------------------------------------------

#[test]
fn proof_status_all_length() {
    assert_eq!(ProofStatus::ALL.len(), 4);
}

#[test]
fn proof_status_names_unique() {
    let names: BTreeSet<&str> = ProofStatus::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(names.len(), ProofStatus::ALL.len());
}

#[test]
fn proof_status_display_matches_as_str() {
    for s in ProofStatus::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn proof_status_verified_semantics() {
    assert!(ProofStatus::Verified.is_verified());
    assert!(ProofStatus::Verified.is_terminal());
}

#[test]
fn proof_status_refuted_semantics() {
    assert!(!ProofStatus::Refuted.is_verified());
    assert!(ProofStatus::Refuted.is_terminal());
}

#[test]
fn proof_status_non_terminal() {
    assert!(!ProofStatus::TimedOut.is_terminal());
    assert!(!ProofStatus::Skipped.is_terminal());
    assert!(!ProofStatus::TimedOut.is_verified());
    assert!(!ProofStatus::Skipped.is_verified());
}

#[test]
fn proof_status_serde_all() {
    for s in ProofStatus::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: ProofStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// CandidateOrigin
// ---------------------------------------------------------------------------

#[test]
fn origin_all_length() {
    assert_eq!(CandidateOrigin::ALL.len(), 5);
}

#[test]
fn origin_names_unique() {
    let names: BTreeSet<&str> = CandidateOrigin::ALL.iter().map(|o| o.as_str()).collect();
    assert_eq!(names.len(), CandidateOrigin::ALL.len());
}

#[test]
fn origin_display_matches_as_str() {
    for o in CandidateOrigin::ALL {
        assert_eq!(o.to_string(), o.as_str());
    }
}

#[test]
fn origin_serde_all() {
    for o in CandidateOrigin::ALL {
        let json = serde_json::to_string(o).unwrap();
        let back: CandidateOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

// ---------------------------------------------------------------------------
// EquivalenceProof
// ---------------------------------------------------------------------------

#[test]
fn proof_verified_full_coverage() {
    let p = EquivalenceProof::verified(10, 500_000);
    assert_eq!(p.status, ProofStatus::Verified);
    assert_eq!(p.input_classes_tested, 10);
    assert_eq!(p.input_classes_verified, 10);
    assert_eq!(p.coverage_millionths(), 1_000_000);
}

#[test]
fn proof_refuted_partial_coverage() {
    let p = EquivalenceProof::refuted(10, 7, 300_000);
    assert_eq!(p.status, ProofStatus::Refuted);
    assert_eq!(p.coverage_millionths(), 700_000);
}

#[test]
fn proof_timed_out_partial() {
    let p = EquivalenceProof::timed_out(8, 4, 1_000_000);
    assert_eq!(p.status, ProofStatus::TimedOut);
    assert_eq!(p.coverage_millionths(), 500_000);
}

#[test]
fn proof_zero_classes_coverage() {
    let p = EquivalenceProof::verified(0, 100_000);
    // 0/0 → 0
    assert_eq!(p.coverage_millionths(), 0);
}

#[test]
fn proof_hash_deterministic() {
    let p1 = EquivalenceProof::verified(5, 400_000);
    let p2 = EquivalenceProof::verified(5, 400_000);
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn proof_different_params_different_hash() {
    let p1 = EquivalenceProof::verified(5, 400_000);
    let p2 = EquivalenceProof::verified(6, 400_000);
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn proof_serde_roundtrip() {
    let p = EquivalenceProof::verified(8, 400_000);
    let json = serde_json::to_string(&p).unwrap();
    let back: EquivalenceProof = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn proof_refuted_serde_roundtrip() {
    let p = EquivalenceProof::refuted(10, 3, 600_000);
    let json = serde_json::to_string(&p).unwrap();
    let back: EquivalenceProof = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// Counterexample
// ---------------------------------------------------------------------------

#[test]
fn counterexample_construction() {
    let cx = Counterexample {
        input_class: "int-overflow".into(),
        expected_output_hash: ContentHash::compute(b"expected"),
        actual_output_hash: ContentHash::compute(b"actual"),
        description: "overflow on u32::MAX + 1".into(),
    };
    assert_eq!(cx.input_class, "int-overflow");
    assert_ne!(cx.expected_output_hash, cx.actual_output_hash);
}

#[test]
fn counterexample_serde_roundtrip() {
    let cx = Counterexample {
        input_class: "string-concat".into(),
        expected_output_hash: ContentHash::compute(b"exp"),
        actual_output_hash: ContentHash::compute(b"act"),
        description: "encoding mismatch".into(),
    };
    let json = serde_json::to_string(&cx).unwrap();
    let back: Counterexample = serde_json::from_str(&json).unwrap();
    assert_eq!(cx, back);
}

#[test]
fn counterexample_ordering() {
    let cx1 = Counterexample {
        input_class: "aaa".into(),
        expected_output_hash: ContentHash::compute(b"a"),
        actual_output_hash: ContentHash::compute(b"b"),
        description: "first".into(),
    };
    let cx2 = Counterexample {
        input_class: "bbb".into(),
        expected_output_hash: ContentHash::compute(b"c"),
        actual_output_hash: ContentHash::compute(b"d"),
        description: "second".into(),
    };
    assert!(cx1 < cx2);
}

// ---------------------------------------------------------------------------
// CostEstimate
// ---------------------------------------------------------------------------

#[test]
fn cost_estimate_construction() {
    let ce = CostEstimate::new("arm-a78", 200_000, 100_000, 500_000);
    assert_eq!(ce.hardware_id, "arm-a78");
    assert_eq!(ce.cycles_millionths, 200_000);
    assert_eq!(ce.memory_pressure_millionths, 100_000);
    assert_eq!(ce.throughput_millionths, 500_000);
}

#[test]
fn cost_estimate_serde_roundtrip() {
    let ce = CostEstimate::new("x86-zen4", 150_000, 80_000, 900_000);
    let json = serde_json::to_string(&ce).unwrap();
    let back: CostEstimate = serde_json::from_str(&json).unwrap();
    assert_eq!(ce, back);
}

#[test]
fn cost_estimate_ordering() {
    let ce1 = CostEstimate::new("a", 100_000, 50_000, 500_000);
    let ce2 = CostEstimate::new("b", 100_000, 50_000, 500_000);
    assert!(ce1 < ce2);
}

// ---------------------------------------------------------------------------
// SynthesisCandidate
// ---------------------------------------------------------------------------

#[test]
fn candidate_verified_admissible() {
    let c = verified_candidate("c1", 1_100_000); // 1.1x > 1.05x threshold
    assert!(c.is_verified());
    assert!(c.meets_speedup_threshold());
    assert!(c.is_admissible());
}

#[test]
fn candidate_verified_below_threshold() {
    let c = verified_candidate("c1", 1_020_000); // 1.02x < 1.05x threshold
    assert!(c.is_verified());
    assert!(!c.meets_speedup_threshold());
    assert!(!c.is_admissible());
}

#[test]
fn candidate_exactly_at_threshold() {
    // MIN_SPEEDUP_THRESHOLD = 50_000, so exactly 1_050_000 should be admissible
    let c = verified_candidate("c1", 1_050_000);
    assert!(c.is_verified());
    assert!(c.meets_speedup_threshold());
    assert!(c.is_admissible());
}

#[test]
fn candidate_just_below_threshold() {
    let c = verified_candidate("c1", 1_049_999);
    assert!(c.is_verified());
    assert!(!c.meets_speedup_threshold());
    assert!(!c.is_admissible());
}

#[test]
fn candidate_refuted_not_admissible() {
    let c = refuted_candidate("c1");
    assert!(!c.is_verified());
    assert!(!c.is_admissible());
}

#[test]
fn candidate_timed_out_not_admissible() {
    let c = timed_out_candidate("c1");
    assert!(!c.is_verified());
    assert!(!c.is_admissible());
}

#[test]
fn candidate_hash_deterministic() {
    let c1 = verified_candidate("c1", 1_100_000);
    let c2 = verified_candidate("c1", 1_100_000);
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn candidate_different_id_different_hash() {
    let c1 = verified_candidate("c1", 1_100_000);
    let c2 = verified_candidate("c2", 1_100_000);
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn candidate_different_speedup_different_hash() {
    let c1 = verified_candidate("c1", 1_100_000);
    let c2 = verified_candidate("c1", 1_200_000);
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn candidate_serde_roundtrip() {
    let c = verified_candidate("c1", 1_200_000);
    let json = serde_json::to_string(&c).unwrap();
    let back: SynthesisCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn candidate_refuted_serde_roundtrip() {
    let c = refuted_candidate("r1");
    let json = serde_json::to_string(&c).unwrap();
    let back: SynthesisCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn candidate_with_counterexamples() {
    let c = refuted_candidate("r1");
    assert_eq!(c.counterexamples.len(), 1);
    assert_eq!(c.counterexamples[0].input_class, "array-int32");
}

#[test]
fn candidate_with_multiple_costs() {
    let c = manual_candidate("m1", 1_200_000);
    assert_eq!(c.cost_estimates.len(), 2);
}

#[test]
fn candidate_origin_varieties() {
    let c_enum = verified_candidate("e1", 1_100_000);
    assert_eq!(c_enum.origin, CandidateOrigin::Enumerative);

    let c_stoch = refuted_candidate("s1");
    assert_eq!(c_stoch.origin, CandidateOrigin::Stochastic);

    let c_tmpl = timed_out_candidate("t1");
    assert_eq!(c_tmpl.origin, CandidateOrigin::TemplateBased);

    let c_manual = manual_candidate("m1", 1_200_000);
    assert_eq!(c_manual.origin, CandidateOrigin::Manual);

    let c_alg = algebraic_candidate("a1", 1_300_000);
    assert_eq!(c_alg.origin, CandidateOrigin::AlgebraicSimplification);
}

// ---------------------------------------------------------------------------
// SynthesisBudget
// ---------------------------------------------------------------------------

#[test]
fn budget_default_values() {
    let b = SynthesisBudget::default_budget();
    assert_eq!(b.max_candidates, DEFAULT_MAX_CANDIDATES);
    assert_eq!(b.search_time_millionths, DEFAULT_SEARCH_BUDGET);
    assert!(b.proof_time_per_candidate_millionths > 0);
}

#[test]
fn budget_default_trait() {
    let b = SynthesisBudget::default();
    assert_eq!(b, SynthesisBudget::default_budget());
}

#[test]
fn budget_custom() {
    let b = SynthesisBudget::custom(10, 2_000_000, 500_000);
    assert_eq!(b.max_candidates, 10);
    assert_eq!(b.search_time_millionths, 2_000_000);
    assert_eq!(b.proof_time_per_candidate_millionths, 500_000);
}

#[test]
fn budget_serde_roundtrip() {
    let b = SynthesisBudget::default();
    let json = serde_json::to_string(&b).unwrap();
    let back: SynthesisBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn budget_custom_serde_roundtrip() {
    let b = SynthesisBudget::custom(128, 10_000_000, 2_000_000);
    let json = serde_json::to_string(&b).unwrap();
    let back: SynthesisBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ---------------------------------------------------------------------------
// SynthesisReport — empty
// ---------------------------------------------------------------------------

#[test]
fn report_empty_candidates() {
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), Vec::new());
    assert_eq!(r.candidate_count(), 0);
    assert!(!r.has_result());
    assert_eq!(r.admission_rate(), 0);
    assert_eq!(r.admissible_count, 0);
    assert_eq!(r.refuted_count, 0);
    assert_eq!(r.timed_out_count, 0);
    assert_eq!(r.total_counterexamples, 0);
    assert_eq!(r.total_search_time_millionths, 0);
}

#[test]
fn report_schema_version() {
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), Vec::new());
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

#[test]
fn report_epoch_preserved() {
    let e = SecurityEpoch::from_raw(999);
    let r = SynthesisReport::new(e, "k1", SynthesisBudget::default(), Vec::new());
    assert_eq!(r.epoch, e);
}

// ---------------------------------------------------------------------------
// SynthesisReport — with candidates
// ---------------------------------------------------------------------------

#[test]
fn report_single_admissible() {
    let candidates = vec![verified_candidate("c1", 1_100_000)];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert!(r.has_result());
    assert_eq!(r.admissible_count, 1);
    assert_eq!(r.best_candidate_id.as_deref(), Some("c1"));
    assert_eq!(r.admission_rate(), 1_000_000);
}

#[test]
fn report_picks_highest_speedup() {
    let candidates = vec![
        verified_candidate("c1", 1_100_000),
        verified_candidate("c2", 1_300_000),
        verified_candidate("c3", 1_200_000),
    ];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert_eq!(r.best_candidate_id.as_deref(), Some("c2"));
    assert_eq!(r.admissible_count, 3);
}

#[test]
fn report_mixed_candidates() {
    let candidates = vec![
        verified_candidate("c1", 1_100_000),
        refuted_candidate("c2"),
        timed_out_candidate("c3"),
    ];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert_eq!(r.candidate_count(), 3);
    assert_eq!(r.admissible_count, 1);
    assert_eq!(r.refuted_count, 1);
    assert_eq!(r.timed_out_count, 1);
    assert_eq!(r.best_candidate_id.as_deref(), Some("c1"));
}

#[test]
fn report_all_refuted_no_result() {
    let candidates = vec![refuted_candidate("c1"), refuted_candidate("c2")];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert!(!r.has_result());
    assert_eq!(r.refuted_count, 2);
    assert!(r.best_candidate_id.is_none());
}

#[test]
fn report_all_timed_out_no_result() {
    let candidates = vec![timed_out_candidate("c1"), timed_out_candidate("c2")];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert!(!r.has_result());
    assert_eq!(r.timed_out_count, 2);
}

#[test]
fn report_verified_below_threshold_no_result() {
    // Verified but too slow to be admissible
    let candidates = vec![
        verified_candidate("c1", 1_020_000),
        verified_candidate("c2", 1_030_000),
    ];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert!(!r.has_result());
    assert_eq!(r.admissible_count, 0);
}

#[test]
fn report_total_counterexamples() {
    let candidates = vec![refuted_candidate("c1"), refuted_candidate("c2")];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert_eq!(r.total_counterexamples, 2);
}

#[test]
fn report_total_search_time() {
    let c1 = verified_candidate("c1", 1_100_000); // proof time 500_000
    let c2 = refuted_candidate("c2"); // proof time 300_000
    let candidates = vec![c1, c2];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert_eq!(r.total_search_time_millionths, 800_000);
}

#[test]
fn report_admission_rate_half() {
    let candidates = vec![verified_candidate("c1", 1_100_000), refuted_candidate("c2")];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert_eq!(r.admission_rate(), 500_000); // 1/2 = 0.5
}

#[test]
fn report_best_candidate_accessor() {
    let candidates = vec![
        verified_candidate("c1", 1_100_000),
        verified_candidate("c2", 1_300_000),
    ];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    let best = r.best_candidate().unwrap();
    assert_eq!(best.candidate_id, "c2");
    assert_eq!(best.speedup_millionths, 1_300_000);
}

#[test]
fn report_no_best_when_empty() {
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), Vec::new());
    assert!(r.best_candidate().is_none());
}

// ---------------------------------------------------------------------------
// SynthesisReport — determinism and serde
// ---------------------------------------------------------------------------

#[test]
fn report_hash_deterministic() {
    let candidates = vec![verified_candidate("c1", 1_100_000)];
    let r1 = SynthesisReport::new(
        epoch(),
        "k1",
        SynthesisBudget::default(),
        candidates.clone(),
    );
    let r2 = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_different_epoch_different_hash() {
    let candidates = vec![verified_candidate("c1", 1_100_000)];
    let r1 = SynthesisReport::new(
        SecurityEpoch::from_raw(100),
        "k1",
        SynthesisBudget::default(),
        candidates.clone(),
    );
    let r2 = SynthesisReport::new(
        SecurityEpoch::from_raw(200),
        "k1",
        SynthesisBudget::default(),
        candidates,
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_different_target_different_hash() {
    let candidates = vec![verified_candidate("c1", 1_100_000)];
    let r1 = SynthesisReport::new(
        epoch(),
        "k1",
        SynthesisBudget::default(),
        candidates.clone(),
    );
    let r2 = SynthesisReport::new(epoch(), "k2", SynthesisBudget::default(), candidates);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_serde_roundtrip_empty() {
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), Vec::new());
    let json = serde_json::to_string(&r).unwrap();
    let back: SynthesisReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn report_serde_roundtrip_with_candidates() {
    let candidates = vec![
        verified_candidate("c1", 1_100_000),
        refuted_candidate("c2"),
        timed_out_candidate("c3"),
    ];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    let json = serde_json::to_string(&r).unwrap();
    let back: SynthesisReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// CounterexampleArchive
// ---------------------------------------------------------------------------

#[test]
fn archive_empty() {
    let a = CounterexampleArchive::new();
    assert_eq!(a.schema_count(), 0);
    assert_eq!(a.total_count, 0);
}

#[test]
fn archive_default_trait() {
    let a = CounterexampleArchive::default();
    assert_eq!(a, CounterexampleArchive::new());
}

#[test]
fn archive_ingest_single_report() {
    let candidates = vec![refuted_candidate("c1")];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    let mut a = CounterexampleArchive::new();
    a.ingest(&r);
    assert_eq!(a.schema_count(), 1);
    assert_eq!(a.total_count, 1);
    assert_eq!(a.for_schema("k1").len(), 1);
}

#[test]
fn archive_ingest_multiple_reports() {
    let r1 = SynthesisReport::new(
        epoch(),
        "k1",
        SynthesisBudget::default(),
        vec![refuted_candidate("c1")],
    );
    let r2 = SynthesisReport::new(
        epoch(),
        "k2",
        SynthesisBudget::default(),
        vec![refuted_candidate("c2")],
    );
    let mut a = CounterexampleArchive::new();
    a.ingest(&r1);
    a.ingest(&r2);
    assert_eq!(a.schema_count(), 2);
    assert_eq!(a.total_count, 2);
}

#[test]
fn archive_same_schema_accumulates() {
    let r1 = SynthesisReport::new(
        epoch(),
        "k1",
        SynthesisBudget::default(),
        vec![refuted_candidate("c1")],
    );
    let r2 = SynthesisReport::new(
        epoch(),
        "k1",
        SynthesisBudget::default(),
        vec![refuted_candidate("c2")],
    );
    let mut a = CounterexampleArchive::new();
    a.ingest(&r1);
    a.ingest(&r2);
    assert_eq!(a.schema_count(), 1);
    assert_eq!(a.total_count, 2);
    assert_eq!(a.for_schema("k1").len(), 2);
}

#[test]
fn archive_empty_schema_lookup() {
    let a = CounterexampleArchive::new();
    assert!(a.for_schema("nonexistent").is_empty());
}

#[test]
fn archive_no_counterexamples_from_verified() {
    let candidates = vec![verified_candidate("c1", 1_100_000)];
    let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
    let mut a = CounterexampleArchive::new();
    a.ingest(&r);
    // verified candidates have no counterexamples, but ingest creates the entry
    assert_eq!(a.schema_count(), 1);
    assert_eq!(a.total_count, 0);
    assert!(a.for_schema("k1").is_empty());
}

#[test]
fn archive_serde_roundtrip() {
    let mut a = CounterexampleArchive::new();
    let r = SynthesisReport::new(
        epoch(),
        "k1",
        SynthesisBudget::default(),
        vec![refuted_candidate("c1")],
    );
    a.ingest(&r);
    let json = serde_json::to_string(&a).unwrap();
    let back: CounterexampleArchive = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn archive_serde_empty_roundtrip() {
    let a = CounterexampleArchive::new();
    let json = serde_json::to_string(&a).unwrap();
    let back: CounterexampleArchive = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ---------------------------------------------------------------------------
// Cross-type workflows
// ---------------------------------------------------------------------------

#[test]
fn full_synthesis_workflow() {
    // Build candidates from various origins
    let candidates = vec![
        verified_candidate("c1", 1_100_000),
        verified_candidate("c2", 1_200_000),
        refuted_candidate("c3"),
        timed_out_candidate("c4"),
        manual_candidate("c5", 1_300_000),
    ];
    let budget = SynthesisBudget::custom(64, 10_000_000, 2_000_000);
    let r = SynthesisReport::new(epoch(), "hot-loop-1", budget, candidates);

    assert_eq!(r.candidate_count(), 5);
    assert_eq!(r.admissible_count, 3);
    assert_eq!(r.refuted_count, 1);
    assert_eq!(r.timed_out_count, 1);
    assert!(r.has_result());

    // Best should be c5 (Manual, 1.3x) — highest speedup among admissible
    assert_eq!(r.best_candidate_id.as_deref(), Some("c5"));
    let best = r.best_candidate().unwrap();
    assert_eq!(best.origin, CandidateOrigin::Manual);

    // Archive counterexamples
    let mut archive = CounterexampleArchive::new();
    archive.ingest(&r);
    assert_eq!(archive.total_count, 1); // only c3 has counterexamples
}

#[test]
fn algebraic_simplification_workflow() {
    let candidates = vec![
        algebraic_candidate("a1", 1_500_000), // 1.5x
        algebraic_candidate("a2", 1_150_000), // 1.15x
    ];
    let r = SynthesisReport::new(
        epoch(),
        "arith-kernel",
        SynthesisBudget::default(),
        candidates,
    );
    assert_eq!(r.admissible_count, 2);
    assert_eq!(r.best_candidate_id.as_deref(), Some("a1"));
}

#[test]
fn report_preserves_target_schema_id() {
    let r = SynthesisReport::new(
        epoch(),
        "my-specific-kernel-xyz",
        SynthesisBudget::default(),
        Vec::new(),
    );
    assert_eq!(r.target_schema_id, "my-specific-kernel-xyz");
}

#[test]
fn report_preserves_budget() {
    let budget = SynthesisBudget::custom(8, 1_000_000, 250_000);
    let r = SynthesisReport::new(epoch(), "k1", budget.clone(), Vec::new());
    assert_eq!(r.budget, budget);
}
