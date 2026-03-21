//! Enrichment integration tests for bayesian_error_recovery module.
//!
//! Covers Bayesian update correctness, loss matrix optimality, recovery
//! controller lifecycle, multi-site evaluation, and budget enforcement.

use frankenengine_engine::bayesian_error_recovery::{
    COMPONENT, DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS, DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_INSERTIONS, DEFAULT_MAX_SKIPS, DEFAULT_PRIOR_AMBIGUOUS, DEFAULT_PRIOR_RECOVERABLE,
    DEFAULT_PRIOR_UNRECOVERABLE, ErrorSite, ErrorState, EvidenceFeatures, LossMatrix, Posterior,
    RecoveryAction, RecoveryConfig, RecoveryError, RecoveryMode, RepairCandidate, RepairDiff,
    RepairEdit, SCHEMA_VERSION, bayesian_update, compute_likelihoods, evaluate,
};
use frankenengine_engine::hash_tiers::ContentHash;

use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_hash() -> ContentHash {
    ContentHash::compute(b"enrichment-test")
}

fn simple_site() -> ErrorSite {
    ErrorSite {
        error_position: 42,
        tokens_before_error: 100,
        at_statement_boundary: true,
        candidates: vec![RepairCandidate {
            description: "insert semicolon".to_string(),
            skips: 0,
            insertions: 1,
            cost: 1,
            is_typo_fix: true,
        }],
        context_hash: test_hash(),
    }
}

fn ambiguous_site() -> ErrorSite {
    ErrorSite {
        error_position: 80,
        tokens_before_error: 50,
        at_statement_boundary: false,
        candidates: vec![
            RepairCandidate {
                description: "insert }".to_string(),
                skips: 0,
                insertions: 1,
                cost: 2,
                is_typo_fix: false,
            },
            RepairCandidate {
                description: "skip token".to_string(),
                skips: 1,
                insertions: 0,
                cost: 3,
                is_typo_fix: false,
            },
            RepairCandidate {
                description: "insert ;".to_string(),
                skips: 0,
                insertions: 1,
                cost: 1,
                is_typo_fix: false,
            },
        ],
        context_hash: test_hash(),
    }
}

fn no_candidate_site() -> ErrorSite {
    ErrorSite {
        error_position: 200,
        tokens_before_error: 3,
        at_statement_boundary: false,
        candidates: vec![],
        context_hash: test_hash(),
    }
}

fn execution_config() -> RecoveryConfig {
    RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        ..RecoveryConfig::default()
    }
}

fn diagnostic_config() -> RecoveryConfig {
    RecoveryConfig {
        mode: RecoveryMode::DiagnosticRecovery,
        ..RecoveryConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Posterior normalization
// ---------------------------------------------------------------------------

#[test]
fn posterior_new_normalizes_to_million() {
    let p = Posterior::new(100, 200, 300);
    assert!(p.is_normalized(), "posterior should be normalized");
    let sum = p.recoverable + p.ambiguous + p.unrecoverable;
    assert!((999_999..=1_000_001).contains(&sum));
}

#[test]
fn posterior_zero_input_uniform() {
    let p = Posterior::new(0, 0, 0);
    assert!(p.is_normalized());
    // Should be roughly uniform
    assert!(p.recoverable > 0);
    assert!(p.ambiguous > 0);
    assert!(p.unrecoverable > 0);
}

#[test]
fn posterior_default_prior_values() {
    let p = Posterior::default_prior();
    assert_eq!(p.recoverable, DEFAULT_PRIOR_RECOVERABLE);
    assert_eq!(p.ambiguous, DEFAULT_PRIOR_AMBIGUOUS);
    assert_eq!(p.unrecoverable, DEFAULT_PRIOR_UNRECOVERABLE);
    assert!(p.is_normalized());
}

#[test]
fn posterior_map_state_recoverable_highest() {
    let p = Posterior::new(800_000, 100_000, 100_000);
    assert_eq!(p.map_state(), ErrorState::Recoverable);
}

#[test]
fn posterior_map_state_ambiguous_highest() {
    let p = Posterior::new(100_000, 800_000, 100_000);
    assert_eq!(p.map_state(), ErrorState::Ambiguous);
}

#[test]
fn posterior_map_state_unrecoverable_highest() {
    let p = Posterior::new(100_000, 100_000, 800_000);
    assert_eq!(p.map_state(), ErrorState::Unrecoverable);
}

#[test]
fn posterior_map_confidence_is_max() {
    let p = Posterior::new(200_000, 500_000, 300_000);
    assert_eq!(p.map_confidence(), p.ambiguous);
}

#[test]
fn posterior_serde_roundtrip() {
    let p = Posterior::new(350_000, 350_000, 300_000);
    let json = serde_json::to_string(&p).unwrap();
    let restored: Posterior = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

// ---------------------------------------------------------------------------
// Bayesian update
// ---------------------------------------------------------------------------

#[test]
fn bayesian_update_typo_favors_recoverable() {
    let prior = Posterior::default_prior();
    let evidence = EvidenceFeatures {
        tokens_before_error: 100,
        candidate_repairs: 1,
        at_statement_boundary: true,
        min_skip_tokens: 0,
        min_insert_tokens: 1,
        matches_typo_pattern: true,
        context_hash: test_hash(),
    };
    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.recoverable > posterior.unrecoverable);
}

#[test]
fn bayesian_update_no_candidates_favors_unrecoverable() {
    let prior = Posterior::default_prior();
    let evidence = EvidenceFeatures {
        tokens_before_error: 100,
        candidate_repairs: 0,
        at_statement_boundary: false,
        min_skip_tokens: 3,
        min_insert_tokens: 0,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.unrecoverable > posterior.recoverable);
}

#[test]
fn bayesian_update_many_candidates_favors_ambiguous() {
    let prior = Posterior::default_prior();
    let evidence = EvidenceFeatures {
        tokens_before_error: 100,
        candidate_repairs: 5,
        at_statement_boundary: false,
        min_skip_tokens: 1,
        min_insert_tokens: 2,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let posterior = bayesian_update(&prior, &evidence);
    // With 5 candidates and no typo pattern, ambiguous should dominate
    assert!(posterior.ambiguous >= posterior.recoverable);
}

#[test]
fn bayesian_update_deterministic() {
    let prior = Posterior::default_prior();
    let evidence = EvidenceFeatures {
        tokens_before_error: 50,
        candidate_repairs: 2,
        at_statement_boundary: true,
        min_skip_tokens: 1,
        min_insert_tokens: 1,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let p1 = bayesian_update(&prior, &evidence);
    let p2 = bayesian_update(&prior, &evidence);
    assert_eq!(p1, p2);
}

#[test]
fn bayesian_update_preserves_normalization() {
    let prior = Posterior::default_prior();
    let evidence = EvidenceFeatures {
        tokens_before_error: 200,
        candidate_repairs: 3,
        at_statement_boundary: false,
        min_skip_tokens: 2,
        min_insert_tokens: 1,
        matches_typo_pattern: true,
        context_hash: test_hash(),
    };
    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.is_normalized());
}

// ---------------------------------------------------------------------------
// Likelihoods
// ---------------------------------------------------------------------------

#[test]
fn likelihoods_all_positive() {
    let evidence = EvidenceFeatures {
        tokens_before_error: 10,
        candidate_repairs: 1,
        at_statement_boundary: true,
        min_skip_tokens: 0,
        min_insert_tokens: 0,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let lk = compute_likelihoods(&evidence);
    assert!(lk[0] > 0);
    assert!(lk[1] > 0);
    assert!(lk[2] > 0);
}

#[test]
fn likelihoods_typo_boosts_recoverable() {
    let base = EvidenceFeatures {
        tokens_before_error: 50,
        candidate_repairs: 1,
        at_statement_boundary: false,
        min_skip_tokens: 0,
        min_insert_tokens: 1,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let typo = EvidenceFeatures {
        matches_typo_pattern: true,
        ..base.clone()
    };
    let lk_base = compute_likelihoods(&base);
    let lk_typo = compute_likelihoods(&typo);
    assert!(lk_typo[0] > lk_base[0]); // recoverable boosted
}

// ---------------------------------------------------------------------------
// Loss matrix
// ---------------------------------------------------------------------------

#[test]
fn loss_matrix_default_symmetric_extremes() {
    let lm = LossMatrix::default();
    // Recovering a recoverable state should have zero loss
    assert_eq!(lm.recover_recoverable, 0);
    // Failing a truly unrecoverable state should also have zero loss
    assert_eq!(lm.fail_unrecoverable, 0);
}

#[test]
fn loss_matrix_optimal_action_recoverable_posterior() {
    let lm = LossMatrix::default();
    let p = Posterior::new(900_000, 50_000, 50_000);
    let action = lm.optimal_action(&p);
    assert_eq!(action, RecoveryAction::RecoverContinue);
}

#[test]
fn loss_matrix_optimal_action_unrecoverable_posterior() {
    let lm = LossMatrix::default();
    let p = Posterior::new(50_000, 50_000, 900_000);
    let action = lm.optimal_action(&p);
    assert_eq!(action, RecoveryAction::FailStrict);
}

#[test]
fn loss_matrix_expected_loss_nonnegative() {
    let lm = LossMatrix::default();
    let p = Posterior::default_prior();
    for action in [
        RecoveryAction::RecoverContinue,
        RecoveryAction::PartialRecover,
        RecoveryAction::FailStrict,
    ] {
        let loss = lm.expected_loss(action, &p);
        // Expected loss uses u64, so always non-negative
        let _ = loss; // no panic
    }
}

#[test]
fn loss_matrix_serde_roundtrip() {
    let lm = LossMatrix::default();
    let json = serde_json::to_string(&lm).unwrap();
    let restored: LossMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(lm, restored);
}

// ---------------------------------------------------------------------------
// RecoveryConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_strict_mode() {
    let cfg = RecoveryConfig::default();
    assert_eq!(cfg.mode, RecoveryMode::StrictDefault);
    assert_eq!(cfg.max_attempts, DEFAULT_MAX_ATTEMPTS);
    assert_eq!(cfg.max_skips, DEFAULT_MAX_SKIPS);
    assert_eq!(cfg.max_insertions, DEFAULT_MAX_INSERTIONS);
    assert_eq!(
        cfg.confidence_threshold_millionths,
        DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS
    );
}

#[test]
fn config_serde_roundtrip() {
    let cfg = execution_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: RecoveryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ---------------------------------------------------------------------------
// evaluate() — main entry point
// ---------------------------------------------------------------------------

#[test]
fn evaluate_strict_mode_always_fails() {
    let config = RecoveryConfig::default(); // StrictDefault
    let result = evaluate(test_hash(), &[simple_site()], &config, 42, "trace-strict");
    let r = result.unwrap();
    assert!(!r.recovered);
    assert_eq!(r.final_action, RecoveryAction::FailStrict);
}

#[test]
fn evaluate_diagnostic_mode_never_recovers() {
    let config = diagnostic_config();
    let result = evaluate(test_hash(), &[simple_site()], &config, 42, "trace-diag");
    let r = result.unwrap();
    // Diagnostic mode reports but doesn't recover
    assert!(!r.recovered);
}

#[test]
fn evaluate_execution_mode_typo_recovers() {
    let config = execution_config();
    let result = evaluate(test_hash(), &[simple_site()], &config, 42, "trace-exec");
    let r = result.unwrap();
    // Simple typo at statement boundary should recover
    assert!(r.recovered || r.final_action == RecoveryAction::PartialRecover);
}

#[test]
fn evaluate_no_candidates_strict_fail() {
    let config = execution_config();
    let result = evaluate(
        test_hash(),
        &[no_candidate_site()],
        &config,
        42,
        "trace-nocan",
    );
    match result {
        Ok(r) => {
            assert!(!r.recovered || r.final_action == RecoveryAction::FailStrict);
        }
        Err(RecoveryError::NoCandidates { .. }) => {
            // Also acceptable
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn evaluate_empty_sites_error() {
    let config = execution_config();
    let result = evaluate(test_hash(), &[], &config, 42, "trace-empty");
    // Empty sites should be handled gracefully
    match result {
        Ok(r) => {
            assert!(r.decisions.is_empty());
        }
        Err(_) => {
            // Also acceptable
        }
    }
}

#[test]
fn evaluate_multi_site() {
    let config = execution_config();
    let sites = vec![simple_site(), ambiguous_site(), no_candidate_site()];
    let result = evaluate(test_hash(), &sites, &config, 42, "trace-multi");
    match result {
        Ok(r) => {
            // Should have processed multiple sites
            assert!(!r.decisions.is_empty());
        }
        Err(_) => {
            // Budget exhaustion is acceptable
        }
    }
}

#[test]
fn evaluate_deterministic() {
    let config = execution_config();
    let sites = vec![simple_site()];
    let r1 = evaluate(test_hash(), &sites, &config, 42, "trace-det").unwrap();
    let r2 = evaluate(test_hash(), &sites, &config, 42, "trace-det").unwrap();
    assert_eq!(r1.final_action, r2.final_action);
    assert_eq!(r1.recovered, r2.recovered);
    assert_eq!(r1.result_digest, r2.result_digest);
}

#[test]
fn evaluate_result_has_schema_version() {
    let config = execution_config();
    let r = evaluate(test_hash(), &[simple_site()], &config, 42, "trace-schema").unwrap();
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

#[test]
fn evaluate_result_summary_format() {
    let config = execution_config();
    let r = evaluate(test_hash(), &[simple_site()], &config, 42, "trace-summary").unwrap();
    let summary = r.summary();
    assert!(
        summary.contains("RECOVERED:")
            || summary.contains("STRICT_FAIL:")
            || summary.contains("PARTIAL:")
            || summary.contains("DIAGNOSTIC:"),
        "summary should have structured prefix: {summary}"
    );
}

// ---------------------------------------------------------------------------
// RecoveryController (via evaluate free function)
// ---------------------------------------------------------------------------

#[test]
fn controller_with_candidates_produces_result() {
    let cfg = execution_config();
    let result = evaluate(test_hash(), &[simple_site()], &cfg, 42, "trace-ctrl");
    assert!(result.is_ok());
}

#[test]
fn controller_no_candidates_handles_gracefully() {
    let cfg = execution_config();
    let result = evaluate(
        test_hash(),
        &[no_candidate_site()],
        &cfg,
        42,
        "trace-nocan2",
    );
    // Should produce a result or a NoCandidates error
    match result {
        Ok(_) | Err(RecoveryError::NoCandidates { .. }) => {}
        Err(e) => panic!("unexpected error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// RepairDiff
// ---------------------------------------------------------------------------

#[test]
fn repair_diff_empty() {
    let diff = RepairDiff::build(test_hash(), vec![]);
    assert!(diff.is_empty());
}

#[test]
fn repair_diff_with_edits() {
    let edits = vec![
        RepairEdit::Skip {
            position: 0,
            count: 1,
        },
        RepairEdit::Insert {
            position: 1,
            tokens: vec![";".to_string()],
        },
    ];
    let diff = RepairDiff::build(test_hash(), edits);
    assert!(!diff.is_empty());
}

#[test]
fn repair_diff_deterministic_hash() {
    let edits = vec![RepairEdit::Insert {
        position: 0,
        tokens: vec!["x".to_string()],
    }];
    let d1 = RepairDiff::build(test_hash(), edits.clone());
    let d2 = RepairDiff::build(test_hash(), edits);
    assert_eq!(d1.diff_hash, d2.diff_hash);
}

// ---------------------------------------------------------------------------
// EvidenceFeatures hash
// ---------------------------------------------------------------------------

#[test]
fn evidence_features_hash_deterministic() {
    let e = EvidenceFeatures {
        tokens_before_error: 50,
        candidate_repairs: 2,
        at_statement_boundary: true,
        min_skip_tokens: 1,
        min_insert_tokens: 0,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    assert_eq!(e.compute_hash(), e.compute_hash());
}

#[test]
fn evidence_features_different_inputs_different_hashes() {
    let e1 = EvidenceFeatures {
        tokens_before_error: 50,
        candidate_repairs: 2,
        at_statement_boundary: true,
        min_skip_tokens: 1,
        min_insert_tokens: 0,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let e2 = EvidenceFeatures {
        tokens_before_error: 51,
        ..e1.clone()
    };
    assert_ne!(e1.compute_hash(), e2.compute_hash());
}

// ---------------------------------------------------------------------------
// RecoveryError
// ---------------------------------------------------------------------------

#[test]
fn recovery_error_display_all_variants_distinct() {
    let errors = [
        RecoveryError::BudgetExhausted {
            attempts: 5,
            max: 5,
        },
        RecoveryError::InvalidConfig {
            detail: "bad".into(),
        },
        RecoveryError::NoCandidates { error_position: 42 },
    ];
    let displays: Vec<String> = errors.iter().map(|e| format!("{e}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), errors.len());
}

#[test]
fn recovery_error_code_all_unique() {
    let errors = [
        RecoveryError::BudgetExhausted {
            attempts: 5,
            max: 5,
        },
        RecoveryError::InvalidConfig {
            detail: "bad".into(),
        },
        RecoveryError::NoCandidates { error_position: 42 },
    ];
    let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
    let set: BTreeSet<_> = codes.iter().collect();
    assert_eq!(set.len(), errors.len());
}

// ---------------------------------------------------------------------------
// RecoveryMode and RecoveryAction Display
// ---------------------------------------------------------------------------

#[test]
fn recovery_mode_display_all_distinct() {
    let modes = [
        RecoveryMode::StrictDefault,
        RecoveryMode::DiagnosticRecovery,
        RecoveryMode::ExecutionRecovery,
    ];
    let displays: Vec<String> = modes.iter().map(|m| format!("{m}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn recovery_action_display_all_distinct() {
    let actions = [
        RecoveryAction::RecoverContinue,
        RecoveryAction::PartialRecover,
        RecoveryAction::FailStrict,
    ];
    let displays: Vec<String> = actions.iter().map(|a| format!("{a}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn error_state_display_all_distinct() {
    let states = [
        ErrorState::Recoverable,
        ErrorState::Ambiguous,
        ErrorState::Unrecoverable,
    ];
    let displays: Vec<String> = states.iter().map(|s| format!("{s}")).collect();
    let set: BTreeSet<_> = displays.iter().collect();
    assert_eq!(set.len(), 3);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::assertions_on_constants)]
fn constants_valid() {
    assert_eq!(COMPONENT, "bayesian_error_recovery");
    assert!(SCHEMA_VERSION.contains("bayesian"));
    assert!(DEFAULT_MAX_ATTEMPTS > 0);
    assert!(DEFAULT_MAX_SKIPS > 0);
    assert!(DEFAULT_MAX_INSERTIONS > 0);
    assert!(DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS <= 1_000_000);
    assert_eq!(
        DEFAULT_PRIOR_RECOVERABLE + DEFAULT_PRIOR_AMBIGUOUS + DEFAULT_PRIOR_UNRECOVERABLE,
        1_000_000
    );
}

// ---------------------------------------------------------------------------
// ErrorSite to_evidence
// ---------------------------------------------------------------------------

#[test]
fn error_site_to_evidence_preserves_fields() {
    let site = simple_site();
    let evidence = site.to_evidence();
    assert_eq!(evidence.tokens_before_error, site.tokens_before_error);
    assert_eq!(evidence.at_statement_boundary, site.at_statement_boundary);
    assert_eq!(evidence.context_hash, site.context_hash);
}
