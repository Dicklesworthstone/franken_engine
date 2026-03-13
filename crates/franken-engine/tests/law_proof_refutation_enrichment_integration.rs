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

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::law_mining::CandidateKind;
use frankenengine_engine::law_mining::LawCandidate;
use frankenengine_engine::law_proof_refutation::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn mk_candidate(id: &str, kind: CandidateKind, rank: u64) -> LawCandidate {
    LawCandidate {
        candidate_id: id.to_string(),
        kind,
        statement: format!("test law: {id}"),
        rank_millionths: rank,
        ranking_rationale: "enrichment test".to_string(),
        scope_hypothesis_id: "scope-enrich".to_string(),
        provenance_id: "prov-enrich".to_string(),
        supporting_source_ids: vec!["src-enrich".to_string()],
        candidate_hash: ContentHash::compute(format!("enrichment-{id}").as_bytes()),
    }
}

fn mk_witness(
    witness_id: &str,
    candidate_id: &str,
    reason: RefutationReason,
    ep: SecurityEpoch,
) -> RefutationWitness {
    RefutationWitness {
        witness_id: witness_id.to_string(),
        candidate_id: candidate_id.to_string(),
        reason,
        description: format!("witness {witness_id} for {candidate_id}"),
        input_digest: ContentHash::compute(format!("input-{witness_id}").as_bytes()),
        expected_summary: "expected output".to_string(),
        actual_summary: "actual output".to_string(),
        discovered_epoch: ep,
        witness_hash: ContentHash::compute(b"placeholder"),
    }
}

// ===========================================================================
// ProofStrategy Display uniqueness
// ===========================================================================

#[test]
fn enrichment_proof_strategy_display_all_unique() {
    let strs: BTreeSet<String> = ProofStrategy::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(strs.len(), ProofStrategy::ALL.len());
}

#[test]
fn enrichment_proof_strategy_display_nonempty() {
    for s in ProofStrategy::ALL {
        assert!(!s.to_string().is_empty());
    }
}

// ===========================================================================
// ProofStrategy serde roundtrips
// ===========================================================================

#[test]
fn enrichment_proof_strategy_serde_differential_replay() {
    let s = ProofStrategy::DifferentialReplay;
    let json = serde_json::to_string(&s).unwrap();
    let back: ProofStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
    assert!(json.contains("differential_replay"));
}

#[test]
fn enrichment_proof_strategy_serde_solver_check() {
    let s = ProofStrategy::SolverCheck;
    let json = serde_json::to_string(&s).unwrap();
    let back: ProofStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
    assert!(json.contains("solver_check"));
}

#[test]
fn enrichment_proof_strategy_serde_counterexample_search() {
    let s = ProofStrategy::CounterexampleSearch;
    let json = serde_json::to_string(&s).unwrap();
    let back: ProofStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
    assert!(json.contains("counterexample_search"));
}

// ===========================================================================
// ProofStrategy confidence weights
// ===========================================================================

#[test]
fn enrichment_proof_strategy_weights_sum_to_million() {
    let sum: u64 = ProofStrategy::ALL
        .iter()
        .map(|s| s.confidence_weight_millionths())
        .sum();
    assert_eq!(sum, 1_000_000);
}

#[test]
fn enrichment_proof_strategy_each_weight_positive_and_bounded() {
    for s in ProofStrategy::ALL {
        let w = s.confidence_weight_millionths();
        assert!(w > 0, "weight must be positive for {s}");
        assert!(w <= 1_000_000, "weight must be <= 1M for {s}");
    }
}

#[test]
fn enrichment_proof_strategy_solver_highest_weight() {
    assert!(
        ProofStrategy::SolverCheck.confidence_weight_millionths()
            > ProofStrategy::DifferentialReplay.confidence_weight_millionths()
    );
    assert!(
        ProofStrategy::SolverCheck.confidence_weight_millionths()
            > ProofStrategy::CounterexampleSearch.confidence_weight_millionths()
    );
}

// ===========================================================================
// ProofStrategy ordering
// ===========================================================================

#[test]
fn enrichment_proof_strategy_canonical_ordering() {
    assert!(ProofStrategy::DifferentialReplay < ProofStrategy::SolverCheck);
    assert!(ProofStrategy::SolverCheck < ProofStrategy::CounterexampleSearch);
}

#[test]
fn enrichment_proof_strategy_clone_eq() {
    for s in ProofStrategy::ALL {
        let cloned = *s;
        assert_eq!(*s, cloned);
    }
}

// ===========================================================================
// ProofVerdict Display uniqueness
// ===========================================================================

#[test]
fn enrichment_proof_verdict_display_all_unique() {
    let strs: BTreeSet<String> = ProofVerdict::ALL.iter().map(|v| v.to_string()).collect();
    assert_eq!(strs.len(), ProofVerdict::ALL.len());
}

#[test]
fn enrichment_proof_verdict_display_nonempty() {
    for v in ProofVerdict::ALL {
        assert!(!v.to_string().is_empty());
    }
}

// ===========================================================================
// ProofVerdict serde roundtrips
// ===========================================================================

#[test]
fn enrichment_proof_verdict_serde_proved() {
    let v = ProofVerdict::Proved;
    let json = serde_json::to_string(&v).unwrap();
    let back: ProofVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_proof_verdict_serde_refuted() {
    let v = ProofVerdict::Refuted;
    let json = serde_json::to_string(&v).unwrap();
    let back: ProofVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_proof_verdict_serde_inconclusive() {
    let v = ProofVerdict::Inconclusive;
    let json = serde_json::to_string(&v).unwrap();
    let back: ProofVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ===========================================================================
// ProofVerdict is_terminal
// ===========================================================================

#[test]
fn enrichment_proof_verdict_proved_is_terminal() {
    assert!(ProofVerdict::Proved.is_terminal());
}

#[test]
fn enrichment_proof_verdict_refuted_is_terminal() {
    assert!(ProofVerdict::Refuted.is_terminal());
}

#[test]
fn enrichment_proof_verdict_inconclusive_not_terminal() {
    assert!(!ProofVerdict::Inconclusive.is_terminal());
}

#[test]
fn enrichment_proof_verdict_terminal_count_is_two() {
    let terminal_count = ProofVerdict::ALL.iter().filter(|v| v.is_terminal()).count();
    assert_eq!(terminal_count, 2);
}

// ===========================================================================
// RefutationReason Display uniqueness
// ===========================================================================

#[test]
fn enrichment_refutation_reason_display_all_unique() {
    let strs: BTreeSet<String> = RefutationReason::ALL
        .iter()
        .map(|r| r.to_string())
        .collect();
    assert_eq!(strs.len(), RefutationReason::ALL.len());
}

#[test]
fn enrichment_refutation_reason_display_nonempty() {
    for r in RefutationReason::ALL {
        assert!(!r.to_string().is_empty());
    }
}

#[test]
fn enrichment_refutation_reason_all_count_is_four() {
    assert_eq!(RefutationReason::ALL.len(), 4);
}

// ===========================================================================
// RefutationReason serde roundtrips
// ===========================================================================

#[test]
fn enrichment_refutation_reason_serde_replay_divergence() {
    let r = RefutationReason::ReplayDivergence;
    let json = serde_json::to_string(&r).unwrap();
    let back: RefutationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_refutation_reason_serde_solver_countermodel() {
    let r = RefutationReason::SolverCountermodel;
    let json = serde_json::to_string(&r).unwrap();
    let back: RefutationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_refutation_reason_serde_search_hit() {
    let r = RefutationReason::SearchHit;
    let json = serde_json::to_string(&r).unwrap();
    let back: RefutationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_refutation_reason_serde_scope_invalidation() {
    let r = RefutationReason::ScopeInvalidation;
    let json = serde_json::to_string(&r).unwrap();
    let back: RefutationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// RefutationWitness
// ===========================================================================

#[test]
fn enrichment_refutation_witness_serde_roundtrip() {
    let w = mk_witness(
        "w-enrich-1",
        "c-enrich-1",
        RefutationReason::SearchHit,
        epoch(10),
    );
    let json = serde_json::to_string(&w).unwrap();
    let back: RefutationWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(w, back);
}

#[test]
fn enrichment_refutation_witness_different_ids_not_equal() {
    let w1 = mk_witness("w-a", "c-1", RefutationReason::SearchHit, epoch(1));
    let w2 = mk_witness("w-b", "c-1", RefutationReason::SearchHit, epoch(1));
    assert_ne!(w1.witness_id, w2.witness_id);
    assert_ne!(w1, w2);
}

#[test]
fn enrichment_refutation_witness_different_candidates_not_equal() {
    let w1 = mk_witness("w-same", "c-1", RefutationReason::SearchHit, epoch(1));
    let w2 = mk_witness("w-same", "c-2", RefutationReason::SearchHit, epoch(1));
    assert_ne!(w1.candidate_id, w2.candidate_id);
}

#[test]
fn enrichment_refutation_witness_different_reasons_not_equal() {
    let w1 = mk_witness("w-1", "c-1", RefutationReason::ReplayDivergence, epoch(1));
    let w2 = mk_witness("w-1", "c-1", RefutationReason::SolverCountermodel, epoch(1));
    assert_ne!(w1.reason, w2.reason);
}

#[test]
fn enrichment_refutation_witness_different_epochs_not_equal() {
    let w1 = mk_witness("w-1", "c-1", RefutationReason::SearchHit, epoch(1));
    let w2 = mk_witness("w-1", "c-1", RefutationReason::SearchHit, epoch(99));
    assert_ne!(w1.discovered_epoch, w2.discovered_epoch);
}

#[test]
fn enrichment_refutation_witness_clone_equality() {
    let w = mk_witness(
        "w-clone",
        "c-clone",
        RefutationReason::ScopeInvalidation,
        epoch(5),
    );
    let cloned = w.clone();
    assert_eq!(w, cloned);
}

// ===========================================================================
// ProofAttempt
// ===========================================================================

#[test]
fn enrichment_proof_attempt_serde_roundtrip_proved() {
    let a = ProofAttempt {
        attempt_id: "att-enrich-1".to_string(),
        candidate_id: "c-enrich-1".to_string(),
        strategy: ProofStrategy::DifferentialReplay,
        verdict: ProofVerdict::Proved,
        confidence_millionths: 850_000,
        refutation_witness_id: None,
        configurations_tested: 8,
        solver_queries: 0,
        search_iterations: 0,
        attempt_epoch: epoch(20),
        attempt_hash: ContentHash::compute(b"enrichment-attempt"),
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: ProofAttempt = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn enrichment_proof_attempt_serde_roundtrip_refuted_with_witness() {
    let a = ProofAttempt {
        attempt_id: "att-enrich-ref".to_string(),
        candidate_id: "c-enrich-ref".to_string(),
        strategy: ProofStrategy::CounterexampleSearch,
        verdict: ProofVerdict::Refuted,
        confidence_millionths: 1_000_000,
        refutation_witness_id: Some("w-ref-1".to_string()),
        configurations_tested: 0,
        solver_queries: 0,
        search_iterations: 128,
        attempt_epoch: epoch(30),
        attempt_hash: ContentHash::compute(b"enrichment-refuted"),
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: ProofAttempt = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn enrichment_proof_attempt_serde_roundtrip_inconclusive() {
    let a = ProofAttempt {
        attempt_id: "att-enrich-inc".to_string(),
        candidate_id: "c-enrich-inc".to_string(),
        strategy: ProofStrategy::SolverCheck,
        verdict: ProofVerdict::Inconclusive,
        confidence_millionths: 420_000,
        refutation_witness_id: None,
        configurations_tested: 0,
        solver_queries: 20,
        search_iterations: 0,
        attempt_epoch: epoch(40),
        attempt_hash: ContentHash::compute(b"enrichment-inc"),
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: ProofAttempt = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn enrichment_proof_attempt_clone_equality() {
    let a = ProofAttempt {
        attempt_id: "att-clone".to_string(),
        candidate_id: "c-clone".to_string(),
        strategy: ProofStrategy::SolverCheck,
        verdict: ProofVerdict::Proved,
        confidence_millionths: 900_000,
        refutation_witness_id: None,
        configurations_tested: 0,
        solver_queries: 10,
        search_iterations: 0,
        attempt_epoch: epoch(50),
        attempt_hash: ContentHash::compute(b"clone-test"),
    };
    assert_eq!(a, a.clone());
}

// ===========================================================================
// CounterexampleArchive
// ===========================================================================

#[test]
fn enrichment_counterexample_archive_new_empty() {
    let archive = CounterexampleArchive::new(epoch(1));
    assert!(archive.witnesses.is_empty());
    assert!(archive.refuted_candidate_ids.is_empty());
    assert_eq!(archive.schema_version, LAW_PROOF_SCHEMA_VERSION);
    assert_eq!(archive.bead_id, LAW_PROOF_BEAD_ID);
}

#[test]
fn enrichment_counterexample_archive_serde_empty() {
    let archive = CounterexampleArchive::new(epoch(5));
    let json = serde_json::to_string(&archive).unwrap();
    let back: CounterexampleArchive = serde_json::from_str(&json).unwrap();
    assert_eq!(archive, back);
}

#[test]
fn enrichment_counterexample_archive_add_one_witness() {
    let mut archive = CounterexampleArchive::new(epoch(10));
    let w = mk_witness(
        "w-add-1",
        "c-add-1",
        RefutationReason::ReplayDivergence,
        epoch(10),
    );
    archive.add_witness(w);
    assert_eq!(archive.witnesses.len(), 1);
    assert!(archive.is_refuted("c-add-1"));
    assert!(!archive.is_refuted("c-add-2"));
}

#[test]
fn enrichment_counterexample_archive_add_multiple_same_candidate() {
    let mut archive = CounterexampleArchive::new(epoch(10));
    archive.add_witness(mk_witness(
        "w-m1",
        "c-multi",
        RefutationReason::ReplayDivergence,
        epoch(10),
    ));
    archive.add_witness(mk_witness(
        "w-m2",
        "c-multi",
        RefutationReason::SolverCountermodel,
        epoch(10),
    ));
    assert_eq!(archive.witnesses.len(), 2);
    assert!(archive.is_refuted("c-multi"));
    let ws = archive.witnesses_for("c-multi");
    assert_eq!(ws.len(), 2);
}

#[test]
fn enrichment_counterexample_archive_witnesses_sorted_by_id() {
    let mut archive = CounterexampleArchive::new(epoch(10));
    archive.add_witness(mk_witness(
        "w-z",
        "c-1",
        RefutationReason::SearchHit,
        epoch(10),
    ));
    archive.add_witness(mk_witness(
        "w-a",
        "c-2",
        RefutationReason::SearchHit,
        epoch(10),
    ));
    archive.add_witness(mk_witness(
        "w-m",
        "c-3",
        RefutationReason::SearchHit,
        epoch(10),
    ));
    assert_eq!(archive.witnesses[0].witness_id, "w-a");
    assert_eq!(archive.witnesses[1].witness_id, "w-m");
    assert_eq!(archive.witnesses[2].witness_id, "w-z");
}

#[test]
fn enrichment_counterexample_archive_witnesses_for_empty() {
    let archive = CounterexampleArchive::new(epoch(10));
    assert!(archive.witnesses_for("nonexistent").is_empty());
}

#[test]
fn enrichment_counterexample_archive_hash_changes_on_add() {
    let mut archive = CounterexampleArchive::new(epoch(10));
    let h_before = archive.archive_hash;
    archive.add_witness(mk_witness(
        "w-hc",
        "c-hc",
        RefutationReason::ScopeInvalidation,
        epoch(10),
    ));
    assert_ne!(h_before, archive.archive_hash);
}

#[test]
fn enrichment_counterexample_archive_hash_deterministic_same_inputs() {
    let mut a1 = CounterexampleArchive::new(epoch(10));
    let mut a2 = CounterexampleArchive::new(epoch(10));
    let w1 = mk_witness("w-det", "c-det", RefutationReason::SearchHit, epoch(10));
    let w2 = mk_witness("w-det", "c-det", RefutationReason::SearchHit, epoch(10));
    a1.add_witness(w1);
    a2.add_witness(w2);
    assert_eq!(a1.archive_hash, a2.archive_hash);
}

#[test]
fn enrichment_counterexample_archive_serde_with_witnesses() {
    let mut archive = CounterexampleArchive::new(epoch(15));
    archive.add_witness(mk_witness(
        "w-s1",
        "c-s1",
        RefutationReason::ReplayDivergence,
        epoch(15),
    ));
    archive.add_witness(mk_witness(
        "w-s2",
        "c-s2",
        RefutationReason::SolverCountermodel,
        epoch(15),
    ));
    let json = serde_json::to_string(&archive).unwrap();
    let back: CounterexampleArchive = serde_json::from_str(&json).unwrap();
    assert_eq!(archive, back);
}

#[test]
fn enrichment_counterexample_archive_refuted_candidate_ids_tracked() {
    let mut archive = CounterexampleArchive::new(epoch(10));
    archive.add_witness(mk_witness(
        "w-t1",
        "c-x",
        RefutationReason::SearchHit,
        epoch(10),
    ));
    archive.add_witness(mk_witness(
        "w-t2",
        "c-y",
        RefutationReason::SearchHit,
        epoch(10),
    ));
    archive.add_witness(mk_witness(
        "w-t3",
        "c-x",
        RefutationReason::ScopeInvalidation,
        epoch(10),
    ));
    assert_eq!(archive.refuted_candidate_ids.len(), 2);
    assert!(archive.refuted_candidate_ids.contains("c-x"));
    assert!(archive.refuted_candidate_ids.contains("c-y"));
}

// ===========================================================================
// ProofCampaignConfig
// ===========================================================================

#[test]
fn enrichment_config_default_strategies_all() {
    let config = ProofCampaignConfig::default();
    assert_eq!(config.strategies.len(), 3);
    assert_eq!(config.strategies, ProofStrategy::ALL.to_vec());
}

#[test]
fn enrichment_config_default_max_attempts() {
    let config = ProofCampaignConfig::default();
    assert_eq!(config.max_attempts, 16);
}

#[test]
fn enrichment_config_default_threshold() {
    let config = ProofCampaignConfig::default();
    assert_eq!(config.acceptance_threshold_millionths, 800_000);
}

#[test]
fn enrichment_config_default_early_termination_true() {
    let config = ProofCampaignConfig::default();
    assert!(config.early_termination);
}

#[test]
fn enrichment_config_default_skip_known_refuted_true() {
    let config = ProofCampaignConfig::default();
    assert!(config.skip_known_refuted);
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let config = ProofCampaignConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: ProofCampaignConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_config_custom_serde_roundtrip() {
    let config = ProofCampaignConfig {
        strategies: vec![ProofStrategy::SolverCheck],
        max_attempts: 4,
        acceptance_threshold_millionths: 500_000,
        early_termination: false,
        skip_known_refuted: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: ProofCampaignConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// ProofCampaignResult
// ===========================================================================

#[test]
fn enrichment_campaign_result_serde_roundtrip() {
    let r = ProofCampaignResult {
        candidate_id: "c-res-1".to_string(),
        candidate_kind: CandidateKind::Invariant,
        final_verdict: ProofVerdict::Proved,
        aggregate_confidence_millionths: 870_000,
        attempts: Vec::new(),
        refutation_witness_ids: Vec::new(),
        accepted: true,
        rationale: "proved and accepted".to_string(),
        campaign_epoch: epoch(55),
        result_hash: ContentHash::compute(b"result-placeholder"),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ProofCampaignResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_campaign_result_clone_equality() {
    let r = ProofCampaignResult {
        candidate_id: "c-clone-res".to_string(),
        candidate_kind: CandidateKind::NormalForm,
        final_verdict: ProofVerdict::Inconclusive,
        aggregate_confidence_millionths: 300_000,
        attempts: Vec::new(),
        refutation_witness_ids: Vec::new(),
        accepted: false,
        rationale: "inconclusive".to_string(),
        campaign_epoch: epoch(60),
        result_hash: ContentHash::compute(b"clone-res"),
    };
    assert_eq!(r, r.clone());
}

// ===========================================================================
// ProofRefutationError Display uniqueness
// ===========================================================================

#[test]
fn enrichment_error_display_all_unique() {
    let errors = vec![
        ProofRefutationError::CandidateNotFound {
            candidate_id: "c-1".to_string(),
        },
        ProofRefutationError::DuplicateCampaign {
            candidate_id: "c-2".to_string(),
        },
        ProofRefutationError::MaxAttemptsExceeded { limit: 16 },
        ProofRefutationError::InvalidConfig {
            detail: "bad config".to_string(),
        },
    ];
    let strs: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(strs.len(), errors.len());
}

#[test]
fn enrichment_error_display_candidate_not_found_contains_id() {
    let e = ProofRefutationError::CandidateNotFound {
        candidate_id: "cand-xyz".to_string(),
    };
    assert!(e.to_string().contains("cand-xyz"));
    assert!(e.to_string().contains("not found"));
}

#[test]
fn enrichment_error_display_duplicate_campaign_contains_id() {
    let e = ProofRefutationError::DuplicateCampaign {
        candidate_id: "cand-dup".to_string(),
    };
    assert!(e.to_string().contains("cand-dup"));
    assert!(e.to_string().contains("already exists"));
}

#[test]
fn enrichment_error_display_max_attempts_contains_limit() {
    let e = ProofRefutationError::MaxAttemptsExceeded { limit: 32 };
    assert!(e.to_string().contains("32"));
    assert!(e.to_string().contains("max attempts"));
}

#[test]
fn enrichment_error_display_invalid_config_contains_detail() {
    let e = ProofRefutationError::InvalidConfig {
        detail: "threshold too high".to_string(),
    };
    assert!(e.to_string().contains("threshold too high"));
    assert!(e.to_string().contains("invalid config"));
}

// ===========================================================================
// ProofRefutationError serde roundtrips
// ===========================================================================

#[test]
fn enrichment_error_serde_candidate_not_found() {
    let e = ProofRefutationError::CandidateNotFound {
        candidate_id: "c-serde".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ProofRefutationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_error_serde_duplicate_campaign() {
    let e = ProofRefutationError::DuplicateCampaign {
        candidate_id: "c-dup-serde".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ProofRefutationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_error_serde_max_attempts() {
    let e = ProofRefutationError::MaxAttemptsExceeded { limit: 64 };
    let json = serde_json::to_string(&e).unwrap();
    let back: ProofRefutationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_error_serde_invalid_config() {
    let e = ProofRefutationError::InvalidConfig {
        detail: "missing strategies".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ProofRefutationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_constants_schema_version_nonempty() {
    assert!(!LAW_PROOF_SCHEMA_VERSION.is_empty());
    assert!(LAW_PROOF_SCHEMA_VERSION.contains("law-proof"));
}

#[test]
fn enrichment_constants_bead_id_nonempty() {
    assert!(!LAW_PROOF_BEAD_ID.is_empty());
    assert!(LAW_PROOF_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_constants_component_nonempty() {
    assert!(!COMPONENT.is_empty());
    assert_eq!(COMPONENT, "law_proof_refutation");
}

// ===========================================================================
// ProofRefutationPipeline creation
// ===========================================================================

#[test]
fn enrichment_pipeline_new_is_empty() {
    let pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(100));
    assert!(pipeline.campaign_results.is_empty());
    assert!(pipeline.counterexample_archive.witnesses.is_empty());
    assert_eq!(pipeline.schema_version, LAW_PROOF_SCHEMA_VERSION);
    assert_eq!(pipeline.bead_id, LAW_PROOF_BEAD_ID);
    assert_eq!(pipeline.pipeline_epoch, epoch(100));
}

#[test]
fn enrichment_pipeline_serde_roundtrip_empty() {
    let pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(100));
    let json = serde_json::to_string(&pipeline).unwrap();
    let back: ProofRefutationPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(pipeline, back);
}

// ===========================================================================
// ProofRefutationPipeline run_campaign
// ===========================================================================

#[test]
fn enrichment_pipeline_run_campaign_single_invariant() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    let c = mk_candidate("enrich-inv-1", CandidateKind::Invariant, 800_000);
    let result = pipeline.run_campaign(&c);
    assert_eq!(result.candidate_id, "enrich-inv-1");
    assert_eq!(result.candidate_kind, CandidateKind::Invariant);
    assert!(
        result.final_verdict == ProofVerdict::Proved
            || result.final_verdict == ProofVerdict::Refuted
            || result.final_verdict == ProofVerdict::Inconclusive
    );
}

#[test]
fn enrichment_pipeline_run_campaign_single_side_condition() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    let c = mk_candidate("enrich-sc-1", CandidateKind::SideCondition, 600_000);
    let result = pipeline.run_campaign(&c);
    assert_eq!(result.candidate_id, "enrich-sc-1");
    assert_eq!(result.candidate_kind, CandidateKind::SideCondition);
}

#[test]
fn enrichment_pipeline_run_campaign_single_normal_form() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    let c = mk_candidate("enrich-nf-1", CandidateKind::NormalForm, 400_000);
    let result = pipeline.run_campaign(&c);
    assert_eq!(result.candidate_id, "enrich-nf-1");
    assert_eq!(result.candidate_kind, CandidateKind::NormalForm);
}

#[test]
fn enrichment_pipeline_run_campaign_result_has_epoch() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(777));
    let c = mk_candidate("enrich-epoch", CandidateKind::Invariant, 800_000);
    let result = pipeline.run_campaign(&c);
    assert_eq!(result.campaign_epoch, epoch(777));
}

#[test]
fn enrichment_pipeline_run_campaign_rationale_nonempty() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    let c = mk_candidate("enrich-rat", CandidateKind::Invariant, 800_000);
    let result = pipeline.run_campaign(&c);
    assert!(!result.rationale.is_empty());
}

#[test]
fn enrichment_pipeline_run_campaign_multiple_candidates() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    for i in 0..5 {
        let c = mk_candidate(
            &format!("enrich-multi-{i}"),
            CandidateKind::Invariant,
            600_000 + i * 80_000,
        );
        pipeline.run_campaign(&c);
    }
    assert_eq!(pipeline.campaign_results.len(), 5);
}

// ===========================================================================
// ProofRefutationPipeline skip known refuted
// ===========================================================================

#[test]
fn enrichment_pipeline_skip_known_refuted_returns_refuted_immediately() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    pipeline.counterexample_archive.add_witness(mk_witness(
        "w-pre-known",
        "c-known-refuted",
        RefutationReason::ReplayDivergence,
        epoch(200),
    ));
    let c = mk_candidate("c-known-refuted", CandidateKind::Invariant, 999_000);
    let result = pipeline.run_campaign(&c);
    assert_eq!(result.final_verdict, ProofVerdict::Refuted);
    assert!(result.attempts.is_empty());
    assert!(!result.accepted);
    assert!(result.rationale.contains("previously refuted"));
}

#[test]
fn enrichment_pipeline_skip_disabled_runs_anyway() {
    let config = ProofCampaignConfig {
        strategies: ProofStrategy::ALL.to_vec(),
        max_attempts: 16,
        acceptance_threshold_millionths: 800_000,
        early_termination: true,
        skip_known_refuted: false,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(200));
    pipeline.counterexample_archive.add_witness(mk_witness(
        "w-pre-nonskip",
        "c-nonskip",
        RefutationReason::SearchHit,
        epoch(200),
    ));
    let c = mk_candidate("c-nonskip", CandidateKind::Invariant, 800_000);
    let result = pipeline.run_campaign(&c);
    // Since skip_known_refuted is false, it runs the campaign and has attempts
    assert!(!result.attempts.is_empty());
}

// ===========================================================================
// ProofRefutationPipeline result_for
// ===========================================================================

#[test]
fn enrichment_pipeline_result_for_existing() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    let c = mk_candidate("enrich-lookup", CandidateKind::Invariant, 800_000);
    pipeline.run_campaign(&c);
    assert!(pipeline.result_for("enrich-lookup").is_some());
}

#[test]
fn enrichment_pipeline_result_for_nonexistent() {
    let pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    assert!(pipeline.result_for("does-not-exist").is_none());
}

// ===========================================================================
// ProofRefutationPipeline candidate listings
// ===========================================================================

#[test]
fn enrichment_pipeline_accepted_refuted_inconclusive_partition() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    for i in 0..10 {
        let kind = match i % 3 {
            0 => CandidateKind::Invariant,
            1 => CandidateKind::SideCondition,
            _ => CandidateKind::NormalForm,
        };
        let c = mk_candidate(&format!("enrich-part-{i}"), kind, 400_000 + i * 60_000);
        pipeline.run_campaign(&c);
    }
    let accepted = pipeline.accepted_candidates();
    let refuted = pipeline.refuted_candidates();
    let inconclusive = pipeline.inconclusive_candidates();
    // accepted is a subset of proved results
    for a_id in &accepted {
        let r = pipeline.result_for(a_id).unwrap();
        assert_eq!(r.final_verdict, ProofVerdict::Proved);
        assert!(r.accepted);
    }
    for r_id in &refuted {
        let r = pipeline.result_for(r_id).unwrap();
        assert_eq!(r.final_verdict, ProofVerdict::Refuted);
    }
    for i_id in &inconclusive {
        let r = pipeline.result_for(i_id).unwrap();
        assert_eq!(r.final_verdict, ProofVerdict::Inconclusive);
    }
}

// ===========================================================================
// ProofRefutationPipeline hash behavior
// ===========================================================================

#[test]
fn enrichment_pipeline_hash_changes_after_campaign() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    let h_before = pipeline.pipeline_hash;
    let c = mk_candidate("enrich-hash-chg", CandidateKind::Invariant, 800_000);
    pipeline.run_campaign(&c);
    assert_ne!(h_before, pipeline.pipeline_hash);
}

#[test]
fn enrichment_pipeline_hash_deterministic() {
    let mut p1 = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    let mut p2 = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    let c1 = mk_candidate("enrich-det", CandidateKind::Invariant, 800_000);
    let c2 = mk_candidate("enrich-det", CandidateKind::Invariant, 800_000);
    p1.run_campaign(&c1);
    p2.run_campaign(&c2);
    assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
}

// ===========================================================================
// ProofRefutationPipeline serde after campaigns
// ===========================================================================

#[test]
fn enrichment_pipeline_serde_roundtrip_with_campaigns() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(200));
    for i in 0..3 {
        let c = mk_candidate(
            &format!("enrich-serde-{i}"),
            CandidateKind::Invariant,
            700_000 + i * 100_000,
        );
        pipeline.run_campaign(&c);
    }
    let json = serde_json::to_string(&pipeline).unwrap();
    let back: ProofRefutationPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(pipeline, back);
}

// ===========================================================================
// ProofRefutationSummary
// ===========================================================================

#[test]
fn enrichment_summary_empty_pipeline_zeroes() {
    let pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(300));
    let summary = pipeline.summary_report();
    assert_eq!(summary.total_candidates, 0);
    assert_eq!(summary.proved_count, 0);
    assert_eq!(summary.refuted_count, 0);
    assert_eq!(summary.inconclusive_count, 0);
    assert_eq!(summary.accepted_count, 0);
    assert_eq!(summary.total_attempts, 0);
    assert_eq!(summary.total_witnesses, 0);
    assert_eq!(summary.acceptance_rate_millionths, 0);
    assert_eq!(summary.pipeline_epoch, epoch(300));
}

#[test]
fn enrichment_summary_counts_consistent() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(300));
    for i in 0..8 {
        let kind = if i % 2 == 0 {
            CandidateKind::Invariant
        } else {
            CandidateKind::SideCondition
        };
        let c = mk_candidate(&format!("enrich-sum-{i}"), kind, 500_000 + i * 50_000);
        pipeline.run_campaign(&c);
    }
    let summary = pipeline.summary_report();
    assert_eq!(
        summary.proved_count + summary.refuted_count + summary.inconclusive_count,
        summary.total_candidates
    );
    assert!(summary.accepted_count <= summary.proved_count);
    assert_eq!(summary.total_candidates, 8);
}

#[test]
fn enrichment_summary_acceptance_rate_bounded() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(300));
    for i in 0..5 {
        let c = mk_candidate(
            &format!("enrich-rate-{i}"),
            CandidateKind::Invariant,
            800_000,
        );
        pipeline.run_campaign(&c);
    }
    let summary = pipeline.summary_report();
    assert!(summary.acceptance_rate_millionths <= 1_000_000);
}

#[test]
fn enrichment_summary_serde_roundtrip() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(300));
    let c = mk_candidate("enrich-sum-serde", CandidateKind::Invariant, 800_000);
    pipeline.run_campaign(&c);
    let summary = pipeline.summary_report();
    let json = serde_json::to_string(&summary).unwrap();
    let back: ProofRefutationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrichment_summary_total_attempts_positive_with_campaigns() {
    let mut pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(300));
    let c = mk_candidate("enrich-att-cnt", CandidateKind::Invariant, 800_000);
    pipeline.run_campaign(&c);
    let summary = pipeline.summary_report();
    assert!(summary.total_attempts > 0);
}

#[test]
fn enrichment_summary_epoch_matches_pipeline() {
    let ep = epoch(12345);
    let pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), ep);
    let summary = pipeline.summary_report();
    assert_eq!(summary.pipeline_epoch, ep);
}

// ===========================================================================
// Early termination behavior
// ===========================================================================

#[test]
fn enrichment_early_termination_limits_attempts() {
    let config = ProofCampaignConfig {
        strategies: vec![
            ProofStrategy::DifferentialReplay,
            ProofStrategy::SolverCheck,
            ProofStrategy::CounterexampleSearch,
        ],
        max_attempts: 16,
        acceptance_threshold_millionths: 0,
        early_termination: true,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(400));
    let c = mk_candidate("enrich-early-term", CandidateKind::Invariant, 900_000);
    let result = pipeline.run_campaign(&c);
    if result.final_verdict.is_terminal() {
        assert!(result.attempts.len() <= 3);
    }
}

#[test]
fn enrichment_no_early_termination_tries_all_strategies() {
    let config = ProofCampaignConfig {
        strategies: vec![
            ProofStrategy::DifferentialReplay,
            ProofStrategy::SolverCheck,
            ProofStrategy::CounterexampleSearch,
        ],
        max_attempts: 16,
        acceptance_threshold_millionths: 800_000,
        early_termination: false,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(400));
    let c = mk_candidate("enrich-no-early", CandidateKind::Invariant, 900_000);
    let result = pipeline.run_campaign(&c);
    if result.final_verdict != ProofVerdict::Refuted {
        assert_eq!(result.attempts.len(), 3);
    }
}

// ===========================================================================
// Max attempts edge case
// ===========================================================================

#[test]
fn enrichment_max_attempts_zero_yields_inconclusive() {
    let config = ProofCampaignConfig {
        strategies: vec![
            ProofStrategy::DifferentialReplay,
            ProofStrategy::SolverCheck,
        ],
        max_attempts: 0,
        acceptance_threshold_millionths: 800_000,
        early_termination: true,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(500));
    let c = mk_candidate("enrich-zero-max", CandidateKind::Invariant, 900_000);
    let result = pipeline.run_campaign(&c);
    // With max_attempts=0, loop body never executes -> empty attempts -> inconclusive
    assert!(result.attempts.is_empty());
    assert_eq!(result.final_verdict, ProofVerdict::Inconclusive);
    assert!(!result.accepted);
}

#[test]
fn enrichment_max_attempts_one_stops_after_first() {
    let config = ProofCampaignConfig {
        strategies: vec![
            ProofStrategy::DifferentialReplay,
            ProofStrategy::SolverCheck,
            ProofStrategy::CounterexampleSearch,
        ],
        max_attempts: 1,
        acceptance_threshold_millionths: 800_000,
        early_termination: false,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(500));
    let c = mk_candidate("enrich-one-max", CandidateKind::Invariant, 900_000);
    let result = pipeline.run_campaign(&c);
    assert_eq!(result.attempts.len(), 1);
}

// ===========================================================================
// Single-strategy configuration
// ===========================================================================

#[test]
fn enrichment_pipeline_single_strategy_differential_replay() {
    let config = ProofCampaignConfig {
        strategies: vec![ProofStrategy::DifferentialReplay],
        max_attempts: 16,
        acceptance_threshold_millionths: 800_000,
        early_termination: true,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(600));
    let c = mk_candidate("enrich-dr-only", CandidateKind::Invariant, 800_000);
    let result = pipeline.run_campaign(&c);
    for attempt in &result.attempts {
        assert_eq!(attempt.strategy, ProofStrategy::DifferentialReplay);
    }
}

#[test]
fn enrichment_pipeline_single_strategy_solver_check() {
    let config = ProofCampaignConfig {
        strategies: vec![ProofStrategy::SolverCheck],
        max_attempts: 16,
        acceptance_threshold_millionths: 800_000,
        early_termination: true,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(600));
    let c = mk_candidate("enrich-sc-only", CandidateKind::SideCondition, 700_000);
    let result = pipeline.run_campaign(&c);
    for attempt in &result.attempts {
        assert_eq!(attempt.strategy, ProofStrategy::SolverCheck);
    }
}

// ===========================================================================
// Acceptance threshold behavior
// ===========================================================================

#[test]
fn enrichment_zero_threshold_accepts_any_proved() {
    let config = ProofCampaignConfig {
        strategies: ProofStrategy::ALL.to_vec(),
        max_attempts: 16,
        acceptance_threshold_millionths: 0,
        early_termination: true,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(700));
    let c = mk_candidate("enrich-zero-thresh", CandidateKind::Invariant, 900_000);
    let result = pipeline.run_campaign(&c);
    if result.final_verdict == ProofVerdict::Proved {
        assert!(result.accepted);
    }
}

#[test]
fn enrichment_million_threshold_requires_full_confidence() {
    let config = ProofCampaignConfig {
        strategies: ProofStrategy::ALL.to_vec(),
        max_attempts: 16,
        acceptance_threshold_millionths: 1_000_000,
        early_termination: true,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(700));
    let c = mk_candidate("enrich-max-thresh", CandidateKind::SideCondition, 500_000);
    let result = pipeline.run_campaign(&c);
    if result.final_verdict == ProofVerdict::Proved
        && result.aggregate_confidence_millionths < 1_000_000
    {
        assert!(!result.accepted);
    }
}

// ===========================================================================
// Attempt field semantics
// ===========================================================================

#[test]
fn enrichment_attempt_configurations_tested_for_differential_replay() {
    let config = ProofCampaignConfig {
        strategies: vec![ProofStrategy::DifferentialReplay],
        max_attempts: 16,
        acceptance_threshold_millionths: 800_000,
        early_termination: true,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(800));
    let c = mk_candidate("enrich-dr-configs", CandidateKind::Invariant, 800_000);
    let result = pipeline.run_campaign(&c);
    for attempt in &result.attempts {
        if attempt.strategy == ProofStrategy::DifferentialReplay {
            assert!(attempt.configurations_tested > 0);
            assert_eq!(attempt.solver_queries, 0);
            assert_eq!(attempt.search_iterations, 0);
        }
    }
}

#[test]
fn enrichment_attempt_solver_queries_for_solver_check() {
    let config = ProofCampaignConfig {
        strategies: vec![ProofStrategy::SolverCheck],
        max_attempts: 16,
        acceptance_threshold_millionths: 800_000,
        early_termination: true,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(800));
    let c = mk_candidate("enrich-sc-queries", CandidateKind::Invariant, 800_000);
    let result = pipeline.run_campaign(&c);
    for attempt in &result.attempts {
        if attempt.strategy == ProofStrategy::SolverCheck {
            assert_eq!(attempt.configurations_tested, 0);
            assert!(attempt.solver_queries > 0);
            assert_eq!(attempt.search_iterations, 0);
        }
    }
}

#[test]
fn enrichment_attempt_search_iterations_for_counterexample_search() {
    let config = ProofCampaignConfig {
        strategies: vec![ProofStrategy::CounterexampleSearch],
        max_attempts: 16,
        acceptance_threshold_millionths: 800_000,
        early_termination: true,
        skip_known_refuted: true,
    };
    let mut pipeline = ProofRefutationPipeline::new(config, epoch(800));
    let c = mk_candidate("enrich-ce-iters", CandidateKind::Invariant, 800_000);
    let result = pipeline.run_campaign(&c);
    for attempt in &result.attempts {
        if attempt.strategy == ProofStrategy::CounterexampleSearch {
            assert_eq!(attempt.configurations_tested, 0);
            assert_eq!(attempt.solver_queries, 0);
            assert!(attempt.search_iterations > 0);
        }
    }
}

// ===========================================================================
// Determinism across identical inputs
// ===========================================================================

#[test]
fn enrichment_pipeline_deterministic_identical_runs() {
    let mut p1 = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(900));
    let mut p2 = ProofRefutationPipeline::new(ProofCampaignConfig::default(), epoch(900));
    for i in 0..4 {
        let c1 = mk_candidate(
            &format!("enrich-det-{i}"),
            CandidateKind::Invariant,
            700_000,
        );
        let c2 = mk_candidate(
            &format!("enrich-det-{i}"),
            CandidateKind::Invariant,
            700_000,
        );
        p1.run_campaign(&c1);
        p2.run_campaign(&c2);
    }
    assert_eq!(p1.campaign_results.len(), p2.campaign_results.len());
    for (r1, r2) in p1.campaign_results.iter().zip(p2.campaign_results.iter()) {
        assert_eq!(r1.final_verdict, r2.final_verdict);
        assert_eq!(
            r1.aggregate_confidence_millionths,
            r2.aggregate_confidence_millionths
        );
        assert_eq!(r1.accepted, r2.accepted);
    }
}

// ===========================================================================
// Content hash stability
// ===========================================================================

#[test]
fn enrichment_content_hash_compute_stable() {
    let h1 = ContentHash::compute(b"law_proof_refutation");
    let h2 = ContentHash::compute(b"law_proof_refutation");
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_content_hash_different_inputs_different_hashes() {
    let h1 = ContentHash::compute(b"input_a");
    let h2 = ContentHash::compute(b"input_b");
    assert_ne!(h1, h2);
}
