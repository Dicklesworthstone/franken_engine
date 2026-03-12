#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::law_mining::{CandidateKind, LawCandidate};
use frankenengine_engine::law_proof_refutation::{
    CounterexampleArchive, ProofCampaignConfig, ProofRefutationError, ProofRefutationPipeline,
    ProofRefutationSummary, ProofStrategy, ProofVerdict, RefutationReason, RefutationWitness,
    COMPONENT, LAW_PROOF_BEAD_ID, LAW_PROOF_SCHEMA_VERSION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn candidate(id: &str, kind: CandidateKind, rank: u64) -> LawCandidate {
    LawCandidate {
        candidate_id: id.to_string(),
        kind,
        statement: format!("law: {id}"),
        rank_millionths: rank,
        ranking_rationale: "integration test".to_string(),
        scope_hypothesis_id: "scope-int".to_string(),
        provenance_id: "prov-int".to_string(),
        supporting_source_ids: vec!["src-int".to_string()],
        candidate_hash: ContentHash::compute(format!("candidate-{id}").as_bytes()),
    }
}

// ===========================================================================
// ProofStrategy integration tests
// ===========================================================================

#[test]
fn strategy_all_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for s in ProofStrategy::ALL {
        assert!(seen.insert(s.to_string()), "duplicate strategy: {s}");
    }
}

#[test]
fn strategy_display_matches_serde() {
    for s in ProofStrategy::ALL {
        let json = serde_json::to_string(s).unwrap();
        let display = s.to_string();
        assert_eq!(json, format!("\"{display}\""));
    }
}

#[test]
fn strategy_weights_sum_to_million() {
    let sum: u64 = ProofStrategy::ALL
        .iter()
        .map(|s| s.confidence_weight_millionths())
        .sum();
    assert_eq!(sum, 1_000_000);
}

// ===========================================================================
// ProofVerdict integration tests
// ===========================================================================

#[test]
fn verdict_all_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for v in ProofVerdict::ALL {
        assert!(seen.insert(v.to_string()), "duplicate verdict: {v}");
    }
}

#[test]
fn verdict_terminal_count() {
    let terminal_count = ProofVerdict::ALL.iter().filter(|v| v.is_terminal()).count();
    assert_eq!(terminal_count, 2); // Proved, Refuted
}

// ===========================================================================
// RefutationReason integration tests
// ===========================================================================

#[test]
fn refutation_reason_all_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for r in RefutationReason::ALL {
        assert!(seen.insert(r.to_string()), "duplicate reason: {r}");
    }
}

#[test]
fn refutation_reason_display_matches_serde() {
    for r in RefutationReason::ALL {
        let json = serde_json::to_string(r).unwrap();
        let display = r.to_string();
        assert_eq!(json, format!("\"{display}\""));
    }
}

// ===========================================================================
// CounterexampleArchive integration tests
// ===========================================================================

#[test]
fn archive_multiple_witnesses_same_candidate() {
    let mut archive = CounterexampleArchive::new(epoch(1));
    for i in 0..5 {
        let mut w = RefutationWitness {
            witness_id: format!("w-{i}"),
            candidate_id: "c-same".to_string(),
            reason: RefutationReason::ReplayDivergence,
            description: format!("witness {i}"),
            input_digest: ContentHash::compute(format!("input-{i}").as_bytes()),
            expected_summary: "expected".to_string(),
            actual_summary: format!("actual-{i}"),
            discovered_epoch: epoch(1),
            witness_hash: ContentHash::compute(b"placeholder"),
        };
        // recompute_hash is called inside add_witness
        let _ = &mut w; // ensure w is mutable
        archive.add_witness(w);
    }
    assert_eq!(archive.witnesses_for("c-same").len(), 5);
    assert!(archive.is_refuted("c-same"));
}

#[test]
fn archive_witnesses_sorted_after_interleaved_adds() {
    let mut archive = CounterexampleArchive::new(epoch(1));
    for id in ["z-3", "a-1", "m-2"] {
        let w = RefutationWitness {
            witness_id: id.to_string(),
            candidate_id: "c-1".to_string(),
            reason: RefutationReason::SearchHit,
            description: "test".to_string(),
            input_digest: ContentHash::compute(b"input"),
            expected_summary: "exp".to_string(),
            actual_summary: "act".to_string(),
            discovered_epoch: epoch(1),
            witness_hash: ContentHash::compute(b"placeholder"),
        };
        archive.add_witness(w);
    }
    let ids: Vec<_> = archive
        .witnesses
        .iter()
        .map(|w| w.witness_id.as_str())
        .collect();
    assert_eq!(ids, vec!["a-1", "m-2", "z-3"]);
}

#[test]
fn archive_hash_differs_across_epochs() {
    let a1 = CounterexampleArchive::new(epoch(1));
    let a2 = CounterexampleArchive::new(epoch(2));
    assert_ne!(a1.archive_hash, a2.archive_hash);
}

#[test]
fn archive_empty_witnesses_for_unknown() {
    let archive = CounterexampleArchive::new(epoch(1));
    assert!(archive.witnesses_for("nonexistent").is_empty());
    assert!(!archive.is_refuted("nonexistent"));
}

// ===========================================================================
// ProofCampaignConfig integration tests
// ===========================================================================

#[test]
fn config_custom_strategies() {
    let config = ProofCampaignConfig {
        strategies: vec![ProofStrategy::SolverCheck],
        max_attempts: 4,
        acceptance_threshold_millionths: 500_000,
        early_termination: false,
        skip_known_refuted: false,
    };
    assert_eq!(config.strategies.len(), 1);
    assert!(!config.early_termination);
}

#[test]
fn config_serde_roundtrip() {
    let config = ProofCampaignConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: ProofCampaignConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// ProofRefutationPipeline integration tests
// ===========================================================================

#[test]
fn pipeline_multi_candidate_campaign() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    let candidates = vec![
        candidate("inv-1", CandidateKind::Invariant, 900_000),
        candidate("sc-1", CandidateKind::SideCondition, 700_000),
        candidate("nf-1", CandidateKind::NormalForm, 400_000),
        candidate("inv-2", CandidateKind::Invariant, 600_000),
        candidate("sc-2", CandidateKind::SideCondition, 300_000),
    ];
    for c in &candidates {
        pipeline.run_campaign(c);
    }
    assert_eq!(pipeline.campaign_results.len(), 5);
    let summary = pipeline.summary_report();
    assert_eq!(summary.total_candidates, 5);
}

#[test]
fn pipeline_result_for_all_candidates() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    let ids = ["a", "b", "c", "d", "e"];
    for id in &ids {
        pipeline.run_campaign(&candidate(id, CandidateKind::Invariant, 800_000));
    }
    for id in &ids {
        assert!(pipeline.result_for(id).is_some(), "missing result for {id}");
    }
}

#[test]
fn pipeline_refuted_not_accepted() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    for i in 0..20 {
        pipeline.run_campaign(&candidate(
            &format!("law-{i}"),
            CandidateKind::Invariant,
            500_000 + i * 25_000,
        ));
    }
    for result in &pipeline.campaign_results {
        if result.final_verdict == ProofVerdict::Refuted {
            assert!(!result.accepted);
        }
    }
}

#[test]
fn pipeline_accepted_implies_proved() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    for i in 0..15 {
        pipeline.run_campaign(&candidate(
            &format!("law-acc-{i}"),
            CandidateKind::Invariant,
            700_000 + i * 20_000,
        ));
    }
    for result in &pipeline.campaign_results {
        if result.accepted {
            assert_eq!(result.final_verdict, ProofVerdict::Proved);
        }
    }
}

#[test]
fn pipeline_counterexample_archive_populated() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    for i in 0..20 {
        pipeline.run_campaign(&candidate(
            &format!("law-cx-{i}"),
            if i % 3 == 0 {
                CandidateKind::NormalForm
            } else {
                CandidateKind::Invariant
            },
            200_000 + i * 30_000,
        ));
    }
    // The archive should have witnesses for any refuted laws
    let refuted_count = pipeline.refuted_candidates().len();
    if refuted_count > 0 {
        assert!(!pipeline.counterexample_archive.witnesses.is_empty());
    }
}

#[test]
fn pipeline_skip_refuted_skips_attempts() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    // Pre-populate archive with a known refutation
    let w = RefutationWitness {
        witness_id: "pre-w".to_string(),
        candidate_id: "known-bad".to_string(),
        reason: RefutationReason::SolverCountermodel,
        description: "pre-existing refutation".to_string(),
        input_digest: ContentHash::compute(b"pre"),
        expected_summary: "should hold".to_string(),
        actual_summary: "violated".to_string(),
        discovered_epoch: epoch(5),
        witness_hash: ContentHash::compute(b"pre-witness"),
    };
    pipeline.counterexample_archive.add_witness(w);

    let c = candidate("known-bad", CandidateKind::Invariant, 999_000);
    let result = pipeline.run_campaign(&c);
    assert_eq!(result.final_verdict, ProofVerdict::Refuted);
    assert!(result.attempts.is_empty());
    assert!(result.rationale.contains("previously refuted"));
}

#[test]
fn pipeline_no_skip_when_disabled() {
    let config = ProofCampaignConfig {
        skip_known_refuted: false,
        ..ProofCampaignConfig::default()
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(10));
    let w = RefutationWitness {
        witness_id: "pre-w2".to_string(),
        candidate_id: "known-bad2".to_string(),
        reason: RefutationReason::SearchHit,
        description: "pre-existing".to_string(),
        input_digest: ContentHash::compute(b"pre2"),
        expected_summary: "exp".to_string(),
        actual_summary: "act".to_string(),
        discovered_epoch: epoch(5),
        witness_hash: ContentHash::compute(b"pre-w2"),
    };
    pipeline.counterexample_archive.add_witness(w);

    let c = candidate("known-bad2", CandidateKind::Invariant, 999_000);
    let result = pipeline.run_campaign(&c);
    // Should NOT skip — attempts should be non-empty
    assert!(!result.attempts.is_empty());
}

#[test]
fn pipeline_summary_acceptance_rate() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    for i in 0..10 {
        pipeline.run_campaign(&candidate(
            &format!("rate-{i}"),
            CandidateKind::Invariant,
            800_000,
        ));
    }
    let summary = pipeline.summary_report();
    assert!(summary.acceptance_rate_millionths <= 1_000_000);
    assert_eq!(
        summary.proved_count + summary.refuted_count + summary.inconclusive_count,
        summary.total_candidates
    );
}

#[test]
fn pipeline_deterministic_across_runs() {
    let config = ProofCampaignConfig::default();
    let candidates: Vec<LawCandidate> = (0..5)
        .map(|i| candidate(&format!("det-{i}"), CandidateKind::Invariant, 700_000))
        .collect();

    let mut p1 = ProofRefutationPipeline::new(config.clone(), epoch(42));
    let mut p2 = ProofRefutationPipeline::new(config, epoch(42));

    for c in &candidates {
        p1.run_campaign(c);
    }
    for c in &candidates {
        p2.run_campaign(c);
    }

    // Sort both for comparison
    let mut r1: Vec<_> = p1
        .campaign_results
        .iter()
        .map(|r| r.candidate_id.clone())
        .collect();
    let mut r2: Vec<_> = p2
        .campaign_results
        .iter()
        .map(|r| r.candidate_id.clone())
        .collect();
    r1.sort();
    r2.sort();
    assert_eq!(r1, r2);

    // Verdicts should match
    for id in &r1 {
        let v1 = p1.result_for(id).unwrap().final_verdict;
        let v2 = p2.result_for(id).unwrap().final_verdict;
        assert_eq!(v1, v2, "verdict mismatch for {id}");
    }
}

#[test]
fn pipeline_serde_full_roundtrip() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    for i in 0..8 {
        pipeline.run_campaign(&candidate(
            &format!("serde-{i}"),
            match i % 3 {
                0 => CandidateKind::Invariant,
                1 => CandidateKind::SideCondition,
                _ => CandidateKind::NormalForm,
            },
            600_000 + i * 50_000,
        ));
    }
    let json = serde_json::to_string(&pipeline).unwrap();
    let back: ProofRefutationPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(pipeline.campaign_results.len(), back.campaign_results.len());
    assert_eq!(pipeline.pipeline_hash, back.pipeline_hash);
}

#[test]
fn pipeline_early_termination_reduces_attempts() {
    let early_config = ProofCampaignConfig {
        early_termination: true,
        ..ProofCampaignConfig::default()
    };
    let no_early_config = ProofCampaignConfig {
        early_termination: false,
        ..ProofCampaignConfig::default()
    };

    let c = candidate("term-test", CandidateKind::Invariant, 900_000);
    let mut p_early = ProofRefutationPipeline::new(early_config, epoch(10));
    let mut p_full = ProofRefutationPipeline::new(no_early_config, epoch(10));

    let r_early = p_early.run_campaign(&c);
    let r_full = p_full.run_campaign(&c);

    // Early termination should have <= attempts than full
    assert!(r_early.attempts.len() <= r_full.attempts.len());
}

#[test]
fn pipeline_custom_threshold() {
    let low_threshold = ProofCampaignConfig {
        acceptance_threshold_millionths: 100_000, // 10%
        ..ProofCampaignConfig::default()
    };
    let high_threshold = ProofCampaignConfig {
        acceptance_threshold_millionths: 999_000, // 99.9%
        ..ProofCampaignConfig::default()
    };

    let c = candidate("thresh-test", CandidateKind::Invariant, 800_000);
    let mut p_low = ProofRefutationPipeline::new(low_threshold, epoch(10));
    let mut p_high = ProofRefutationPipeline::new(high_threshold, epoch(10));

    let r_low = p_low.run_campaign(&c);
    let r_high = p_high.run_campaign(&c);

    // Low threshold should accept more easily than high threshold
    if r_low.final_verdict == ProofVerdict::Proved && r_high.final_verdict == ProofVerdict::Proved {
        // With a low threshold, if high accepts, low should also accept
        if r_high.accepted {
            assert!(r_low.accepted);
        }
    }
}

// ===========================================================================
// ProofRefutationError integration tests
// ===========================================================================

#[test]
fn error_variants_display_unique() {
    let errors = [
        ProofRefutationError::CandidateNotFound {
            candidate_id: "c".to_string(),
        },
        ProofRefutationError::DuplicateCampaign {
            candidate_id: "d".to_string(),
        },
        ProofRefutationError::MaxAttemptsExceeded { limit: 10 },
        ProofRefutationError::InvalidConfig {
            detail: "x".to_string(),
        },
    ];
    let displays: Vec<_> = errors.iter().map(|e| e.to_string()).collect();
    let unique: std::collections::BTreeSet<_> = displays.iter().collect();
    assert_eq!(displays.len(), unique.len());
}

#[test]
fn error_serde_all_variants() {
    let errors = vec![
        ProofRefutationError::CandidateNotFound {
            candidate_id: "c1".to_string(),
        },
        ProofRefutationError::DuplicateCampaign {
            candidate_id: "c2".to_string(),
        },
        ProofRefutationError::MaxAttemptsExceeded { limit: 32 },
        ProofRefutationError::InvalidConfig {
            detail: "empty strategies".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ProofRefutationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// Summary report integration tests
// ===========================================================================

#[test]
fn summary_empty_pipeline_zeroes() {
    let pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(1));
    let summary = pipeline.summary_report();
    assert_eq!(summary.total_candidates, 0);
    assert_eq!(summary.proved_count, 0);
    assert_eq!(summary.refuted_count, 0);
    assert_eq!(summary.inconclusive_count, 0);
    assert_eq!(summary.accepted_count, 0);
    assert_eq!(summary.total_attempts, 0);
    assert_eq!(summary.total_witnesses, 0);
    assert_eq!(summary.acceptance_rate_millionths, 0);
}

#[test]
fn summary_total_attempts_matches() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    for i in 0..5 {
        pipeline.run_campaign(&candidate(
            &format!("sum-att-{i}"),
            CandidateKind::Invariant,
            800_000,
        ));
    }
    let summary = pipeline.summary_report();
    let manual_total: usize = pipeline
        .campaign_results
        .iter()
        .map(|r| r.attempts.len())
        .sum();
    assert_eq!(summary.total_attempts, manual_total);
}

#[test]
fn summary_witnesses_matches_archive() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    for i in 0..10 {
        pipeline.run_campaign(&candidate(
            &format!("sum-wit-{i}"),
            CandidateKind::SideCondition,
            300_000 + i * 50_000,
        ));
    }
    let summary = pipeline.summary_report();
    assert_eq!(
        summary.total_witnesses,
        pipeline.counterexample_archive.witnesses.len()
    );
}

// ===========================================================================
// Additional serde and accessor coverage
// ===========================================================================

#[test]
fn proof_verdict_serde_roundtrip_all() {
    for v in ProofVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: ProofVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn proof_verdict_display() {
    for v in ProofVerdict::ALL {
        let s = v.to_string();
        assert!(!s.is_empty(), "empty Display for {v:?}");
    }
    assert_eq!(ProofVerdict::Proved.to_string(), "proved");
    assert_eq!(ProofVerdict::Refuted.to_string(), "refuted");
    assert_eq!(ProofVerdict::Inconclusive.to_string(), "inconclusive");
}

#[test]
fn proof_verdict_inconclusive_is_not_terminal() {
    assert!(!ProofVerdict::Inconclusive.is_terminal());
}

#[test]
fn strategy_confidence_weights_individual_values() {
    assert_eq!(ProofStrategy::DifferentialReplay.confidence_weight_millionths(), 350_000);
    assert_eq!(ProofStrategy::SolverCheck.confidence_weight_millionths(), 450_000);
    assert_eq!(ProofStrategy::CounterexampleSearch.confidence_weight_millionths(), 200_000);
}

#[test]
fn refutation_witness_serde_roundtrip() {
    let w = RefutationWitness {
        witness_id: "w-serde".to_string(),
        candidate_id: "c-serde".to_string(),
        reason: RefutationReason::SolverCountermodel,
        description: "serde test witness".to_string(),
        input_digest: ContentHash::compute(b"serde-input"),
        expected_summary: "expected".to_string(),
        actual_summary: "actual".to_string(),
        discovered_epoch: epoch(7),
        witness_hash: ContentHash::compute(b"serde-w"),
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: RefutationWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w.witness_id, back.witness_id);
    assert_eq!(w.reason, back.reason);
    assert_eq!(w.candidate_id, back.candidate_id);
}

#[test]
fn counterexample_archive_serde_roundtrip() {
    let mut archive = CounterexampleArchive::new(epoch(3));
    let w = RefutationWitness {
        witness_id: "arch-w".to_string(),
        candidate_id: "arch-c".to_string(),
        reason: RefutationReason::SearchHit,
        description: "archive serde test".to_string(),
        input_digest: ContentHash::compute(b"arch-input"),
        expected_summary: "exp".to_string(),
        actual_summary: "act".to_string(),
        discovered_epoch: epoch(3),
        witness_hash: ContentHash::compute(b"arch-w"),
    };
    archive.add_witness(w);

    let json = serde_json::to_string(&archive).unwrap();
    let back: CounterexampleArchive = serde_json::from_str(&json).unwrap();
    assert_eq!(archive.witnesses.len(), back.witnesses.len());
    assert_eq!(archive.archive_hash, back.archive_hash);
    assert!(back.is_refuted("arch-c"));
}

#[test]
fn summary_serde_roundtrip() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(5));
    for i in 0..3 {
        pipeline.run_campaign(&candidate(
            &format!("sum-serde-{i}"),
            CandidateKind::Invariant,
            800_000,
        ));
    }
    let summary = pipeline.summary_report();
    let json = serde_json::to_string(&summary).unwrap();
    let back: ProofRefutationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn summary_hash_deterministic() {
    let make_summary = || {
        let mut p = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(99));
        for i in 0..4 {
            p.run_campaign(&candidate(
                &format!("hash-det-{i}"),
                CandidateKind::Invariant,
                700_000,
            ));
        }
        p.summary_report()
    };
    let s1 = make_summary();
    let s2 = make_summary();
    assert_eq!(s1.summary_hash, s2.summary_hash);
}

#[test]
fn pipeline_accepted_candidates_accessor() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    for i in 0..10 {
        pipeline.run_campaign(&candidate(
            &format!("acc-test-{i}"),
            CandidateKind::Invariant,
            900_000,
        ));
    }
    let accepted = pipeline.accepted_candidates();
    // All accepted candidates should have Proved verdict
    for id in &accepted {
        let result = pipeline.result_for(id).unwrap();
        assert_eq!(result.final_verdict, ProofVerdict::Proved);
        assert!(result.accepted);
    }
}

#[test]
fn pipeline_inconclusive_candidates_accessor() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    for i in 0..15 {
        pipeline.run_campaign(&candidate(
            &format!("inc-test-{i}"),
            CandidateKind::NormalForm,
            400_000 + i * 30_000,
        ));
    }
    let inconclusive = pipeline.inconclusive_candidates();
    for id in &inconclusive {
        let result = pipeline.result_for(id).unwrap();
        assert_eq!(result.final_verdict, ProofVerdict::Inconclusive);
        assert!(!result.accepted);
    }
}

#[test]
fn pipeline_campaign_result_hash_deterministic() {
    let make_result = || {
        let mut p = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(42));
        p.run_campaign(&candidate("det-hash", CandidateKind::Invariant, 800_000));
        p.campaign_results[0].result_hash
    };
    assert_eq!(make_result(), make_result());
}

#[test]
fn module_constants_non_empty() {
    assert!(!LAW_PROOF_SCHEMA_VERSION.is_empty());
    assert!(!LAW_PROOF_BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(LAW_PROOF_SCHEMA_VERSION.contains("law-proof"));
    assert!(LAW_PROOF_BEAD_ID.starts_with("bd-"));
}

#[test]
fn archive_add_witness_recomputes_hash() {
    let mut archive = CounterexampleArchive::new(epoch(1));
    let hash_before = archive.archive_hash;
    let w = RefutationWitness {
        witness_id: "recomp-w".to_string(),
        candidate_id: "recomp-c".to_string(),
        reason: RefutationReason::ReplayDivergence,
        description: "hash recompute test".to_string(),
        input_digest: ContentHash::compute(b"recomp"),
        expected_summary: "exp".to_string(),
        actual_summary: "act".to_string(),
        discovered_epoch: epoch(1),
        witness_hash: ContentHash::compute(b"recomp-w"),
    };
    archive.add_witness(w);
    assert_ne!(hash_before, archive.archive_hash);
}

#[test]
fn pipeline_hash_changes_after_campaign() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(10));
    let hash_before = pipeline.pipeline_hash;
    pipeline.run_campaign(&candidate("hash-change", CandidateKind::Invariant, 800_000));
    assert_ne!(hash_before, pipeline.pipeline_hash);
}

#[test]
fn refutation_reason_scope_invalidation_serde() {
    let reason = RefutationReason::ScopeInvalidation;
    let json = serde_json::to_string(&reason).unwrap();
    let back: RefutationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(reason, back);
    assert_eq!(reason.to_string(), "scope_invalidation");
}
