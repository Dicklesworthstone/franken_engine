//! Integration tests for the `bayesian_error_recovery` module.
//!
//! Exercises the public API from outside the crate: mode/state/action display,
//! posterior normalization, likelihood model, Bayesian update, loss matrix,
//! recovery controller evaluation under all three modes, budget exhaustion,
//! confidence gating, serde round-trips, and deterministic replay.

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

use frankenengine_engine::bayesian_error_recovery::*;
use frankenengine_engine::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_hash() -> ContentHash {
    ContentHash::compute(b"integration-test")
}

/// A simple error site: 1 candidate, typo fix, at statement boundary.
fn simple_site() -> ErrorSite {
    ErrorSite {
        error_position: 10,
        tokens_before_error: 20,
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

/// An ambiguous error site: 3 candidates, none is a typo fix, low context.
fn ambiguous_site() -> ErrorSite {
    ErrorSite {
        error_position: 20,
        tokens_before_error: 3,
        at_statement_boundary: false,
        candidates: vec![
            RepairCandidate {
                description: "insert paren".to_string(),
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
                description: "insert brace".to_string(),
                skips: 0,
                insertions: 2,
                cost: 4,
                is_typo_fix: false,
            },
        ],
        context_hash: test_hash(),
    }
}

/// An error site with no candidates.
fn no_candidate_site() -> ErrorSite {
    ErrorSite {
        error_position: 50,
        tokens_before_error: 30,
        at_statement_boundary: false,
        candidates: Vec::new(),
        context_hash: test_hash(),
    }
}

fn strict_config() -> RecoveryConfig {
    RecoveryConfig::default()
}

fn execution_config() -> RecoveryConfig {
    RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        ..RecoveryConfig::default()
    }
}

// ---------------------------------------------------------------------------
// 1. Mode display strings
// ---------------------------------------------------------------------------

#[test]
fn mode_display_strict() {
    assert_eq!(format!("{}", RecoveryMode::StrictDefault), "strict_default");
}

#[test]
fn mode_display_diagnostic() {
    assert_eq!(
        format!("{}", RecoveryMode::DiagnosticRecovery),
        "diagnostic_recovery"
    );
}

#[test]
fn mode_display_execution() {
    assert_eq!(
        format!("{}", RecoveryMode::ExecutionRecovery),
        "execution_recovery"
    );
}

// ---------------------------------------------------------------------------
// 2. ErrorState display strings
// ---------------------------------------------------------------------------

#[test]
fn error_state_display_recoverable() {
    assert_eq!(format!("{}", ErrorState::Recoverable), "recoverable");
}

#[test]
fn error_state_display_ambiguous() {
    assert_eq!(format!("{}", ErrorState::Ambiguous), "ambiguous");
}

#[test]
fn error_state_display_unrecoverable() {
    assert_eq!(format!("{}", ErrorState::Unrecoverable), "unrecoverable");
}

// ---------------------------------------------------------------------------
// 3. RecoveryAction display strings
// ---------------------------------------------------------------------------

#[test]
fn action_display_recover_continue() {
    assert_eq!(
        format!("{}", RecoveryAction::RecoverContinue),
        "recover_continue"
    );
}

#[test]
fn action_display_partial_recover() {
    assert_eq!(
        format!("{}", RecoveryAction::PartialRecover),
        "partial_recover"
    );
}

#[test]
fn action_display_fail_strict() {
    assert_eq!(format!("{}", RecoveryAction::FailStrict), "fail_strict");
}

// ---------------------------------------------------------------------------
// 4-5. Posterior normalization and default_prior
// ---------------------------------------------------------------------------

#[test]
fn posterior_default_prior_sums_to_million() {
    let prior = Posterior::default_prior();
    let sum = prior.recoverable + prior.ambiguous + prior.unrecoverable;
    assert_eq!(sum, 1_000_000);
}

#[test]
fn posterior_default_prior_values() {
    let prior = Posterior::default_prior();
    assert_eq!(prior.recoverable, DEFAULT_PRIOR_RECOVERABLE);
    assert_eq!(prior.ambiguous, DEFAULT_PRIOR_AMBIGUOUS);
    assert_eq!(prior.unrecoverable, DEFAULT_PRIOR_UNRECOVERABLE);
}

#[test]
fn posterior_new_normalizes_to_million() {
    let p = Posterior::new(100, 200, 300);
    assert!(p.is_normalized());
}

#[test]
fn posterior_new_zero_inputs_uniform() {
    let p = Posterior::new(0, 0, 0);
    // Each should be approximately 1/3 of a million.
    assert!(p.is_normalized());
    assert!(p.recoverable > 0);
    assert!(p.ambiguous > 0);
    assert!(p.unrecoverable > 0);
}

#[test]
fn posterior_new_preserves_ratios() {
    let p = Posterior::new(500_000, 300_000, 200_000);
    assert!(p.is_normalized());
    assert_eq!(p.recoverable, 500_000);
    assert_eq!(p.ambiguous, 300_000);
    assert_eq!(p.unrecoverable, 200_000);
}

#[test]
fn posterior_new_scales_up_small_values() {
    let p = Posterior::new(1, 1, 1);
    assert!(p.is_normalized());
    // Each should be approximately 333333.
    assert!(p.recoverable >= 333_332 && p.recoverable <= 333_334);
    assert!(p.ambiguous >= 333_332 && p.ambiguous <= 333_334);
}

// ---------------------------------------------------------------------------
// 6-7. Posterior map_state and map_confidence
// ---------------------------------------------------------------------------

#[test]
fn posterior_map_state_recoverable() {
    let p = Posterior::new(700_000, 200_000, 100_000);
    assert_eq!(p.map_state(), ErrorState::Recoverable);
}

#[test]
fn posterior_map_state_ambiguous() {
    let p = Posterior::new(100_000, 700_000, 200_000);
    assert_eq!(p.map_state(), ErrorState::Ambiguous);
}

#[test]
fn posterior_map_state_unrecoverable() {
    let p = Posterior::new(100_000, 200_000, 700_000);
    assert_eq!(p.map_state(), ErrorState::Unrecoverable);
}

#[test]
fn posterior_map_state_tie_favors_recoverable() {
    // When recoverable == ambiguous >= unrecoverable, Recoverable wins.
    let p = Posterior {
        recoverable: 400_000,
        ambiguous: 400_000,
        unrecoverable: 200_000,
    };
    assert_eq!(p.map_state(), ErrorState::Recoverable);
}

#[test]
fn posterior_map_confidence_extracts_max() {
    let p = Posterior::new(200_000, 600_000, 200_000);
    assert_eq!(p.map_confidence(), p.ambiguous);
}

// ---------------------------------------------------------------------------
// 8. EvidenceFeatures compute_hash
// ---------------------------------------------------------------------------

#[test]
fn evidence_hash_deterministic() {
    let site = simple_site();
    let ev = site.to_evidence();
    let h1 = ev.compute_hash();
    let h2 = ev.compute_hash();
    assert_eq!(h1, h2);
}

#[test]
fn evidence_hash_differs_for_different_evidence() {
    let s1 = simple_site();
    let s2 = ambiguous_site();
    let h1 = s1.to_evidence().compute_hash();
    let h2 = s2.to_evidence().compute_hash();
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// 9. compute_likelihoods
// ---------------------------------------------------------------------------

#[test]
fn likelihoods_typo_pattern_favors_recoverable() {
    let ev = EvidenceFeatures {
        tokens_before_error: 20,
        candidate_repairs: 1,
        at_statement_boundary: true,
        min_skip_tokens: 0,
        min_insert_tokens: 0,
        matches_typo_pattern: true,
        context_hash: test_hash(),
    };
    let [lr, _la, lu] = compute_likelihoods(&ev);
    assert!(
        lr > lu,
        "typo pattern should boost recoverable over unrecoverable"
    );
}

#[test]
fn likelihoods_no_candidates_favors_unrecoverable() {
    let ev = EvidenceFeatures {
        tokens_before_error: 20,
        candidate_repairs: 0,
        at_statement_boundary: false,
        min_skip_tokens: 0,
        min_insert_tokens: 0,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let [lr, _la, lu] = compute_likelihoods(&ev);
    assert!(
        lu > lr,
        "no candidates should boost unrecoverable over recoverable"
    );
}

#[test]
fn likelihoods_multiple_candidates_favors_ambiguous() {
    let ev = EvidenceFeatures {
        tokens_before_error: 20,
        candidate_repairs: 4,
        at_statement_boundary: false,
        min_skip_tokens: 0,
        min_insert_tokens: 0,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let [lr, la, _lu] = compute_likelihoods(&ev);
    assert!(
        la > lr,
        "multiple candidates should boost ambiguous over recoverable"
    );
}

#[test]
fn likelihoods_boundary_boosts_recoverable() {
    let mut ev = EvidenceFeatures {
        tokens_before_error: 20,
        candidate_repairs: 1,
        at_statement_boundary: false,
        min_skip_tokens: 0,
        min_insert_tokens: 0,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let [lr_no_boundary, _, _] = compute_likelihoods(&ev);
    ev.at_statement_boundary = true;
    let [lr_boundary, _, _] = compute_likelihoods(&ev);
    assert!(
        lr_boundary > lr_no_boundary,
        "statement boundary should boost recoverable"
    );
}

#[test]
fn likelihoods_high_skips_disfavors_recoverable() {
    let ev = EvidenceFeatures {
        tokens_before_error: 20,
        candidate_repairs: 1,
        at_statement_boundary: false,
        min_skip_tokens: 5,
        min_insert_tokens: 0,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let [lr, _la, lu] = compute_likelihoods(&ev);
    assert!(
        lu >= lr,
        "high skip count should disfavor recoverable relative to unrecoverable"
    );
}

#[test]
fn likelihoods_high_insert_count_boosts_ambiguous() {
    let ev = EvidenceFeatures {
        tokens_before_error: 20,
        candidate_repairs: 1,
        at_statement_boundary: false,
        min_skip_tokens: 0,
        min_insert_tokens: 3,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let [lr, la, _lu] = compute_likelihoods(&ev);
    assert!(
        la > lr,
        "high insertion count should boost ambiguous over recoverable"
    );
}

#[test]
fn likelihoods_few_tokens_before_error_boosts_ambiguous() {
    let ev = EvidenceFeatures {
        tokens_before_error: 2,
        candidate_repairs: 1,
        at_statement_boundary: false,
        min_skip_tokens: 0,
        min_insert_tokens: 0,
        matches_typo_pattern: false,
        context_hash: test_hash(),
    };
    let [_lr, la, _lu] = compute_likelihoods(&ev);
    // With few tokens, ambiguous likelihood is doubled.
    assert!(la >= 2_000_000);
}

// ---------------------------------------------------------------------------
// 10-11. bayesian_update
// ---------------------------------------------------------------------------

#[test]
fn bayesian_update_shifts_posterior_toward_recoverable_on_typo() {
    let prior = Posterior::default_prior();
    let ev = simple_site().to_evidence();
    let post = bayesian_update(&prior, &ev);
    assert!(post.is_normalized());
    assert!(
        post.recoverable > prior.recoverable,
        "typo evidence should shift posterior toward recoverable"
    );
}

#[test]
fn bayesian_update_deterministic() {
    let prior = Posterior::default_prior();
    let ev = simple_site().to_evidence();
    let p1 = bayesian_update(&prior, &ev);
    let p2 = bayesian_update(&prior, &ev);
    assert_eq!(p1, p2);
}

#[test]
fn bayesian_update_ambiguous_evidence() {
    let prior = Posterior::default_prior();
    let ev = ambiguous_site().to_evidence();
    let post = bayesian_update(&prior, &ev);
    assert!(post.is_normalized());
    // Ambiguous site (multi-candidate, low context) should have high ambiguous posterior.
    assert_eq!(post.map_state(), ErrorState::Ambiguous);
}

#[test]
fn bayesian_update_no_candidates_shifts_unrecoverable() {
    let prior = Posterior::default_prior();
    let ev = no_candidate_site().to_evidence();
    let post = bayesian_update(&prior, &ev);
    assert!(post.is_normalized());
    assert!(
        post.unrecoverable > prior.unrecoverable,
        "no candidates should shift toward unrecoverable"
    );
}

// ---------------------------------------------------------------------------
// 12-14. LossMatrix
// ---------------------------------------------------------------------------

#[test]
fn loss_matrix_default_values() {
    let lm = LossMatrix::default();
    assert_eq!(lm.recover_recoverable, 0);
    assert_eq!(lm.recover_ambiguous, 55);
    assert_eq!(lm.recover_unrecoverable, 90);
    assert_eq!(lm.partial_recoverable, 5);
    assert_eq!(lm.partial_ambiguous, 15);
    assert_eq!(lm.partial_unrecoverable, 40);
    assert_eq!(lm.fail_recoverable, 12);
    assert_eq!(lm.fail_ambiguous, 3);
    assert_eq!(lm.fail_unrecoverable, 0);
}

#[test]
fn expected_loss_recover_on_fully_recoverable() {
    let lm = LossMatrix::default();
    let p = Posterior {
        recoverable: 1_000_000,
        ambiguous: 0,
        unrecoverable: 0,
    };
    let el = lm.expected_loss(RecoveryAction::RecoverContinue, &p);
    // L(recover, recoverable) = 0, so expected loss = 0.
    assert_eq!(el, 0);
}

#[test]
fn expected_loss_fail_on_fully_unrecoverable() {
    let lm = LossMatrix::default();
    let p = Posterior {
        recoverable: 0,
        ambiguous: 0,
        unrecoverable: 1_000_000,
    };
    let el = lm.expected_loss(RecoveryAction::FailStrict, &p);
    // L(fail, unrecoverable) = 0.
    assert_eq!(el, 0);
}

#[test]
fn expected_loss_partial_is_intermediate() {
    let lm = LossMatrix::default();
    let p = Posterior::default_prior();
    let el_recover = lm.expected_loss(RecoveryAction::RecoverContinue, &p);
    let el_partial = lm.expected_loss(RecoveryAction::PartialRecover, &p);
    let el_fail = lm.expected_loss(RecoveryAction::FailStrict, &p);
    // Partial should be between recover and fail for uniform-ish prior.
    // (Not strictly guaranteed for all priors, but holds for the default prior.)
    let max_loss = el_recover.max(el_fail);
    assert!(
        el_partial <= max_loss,
        "partial expected loss ({el_partial}) should not exceed max of recover ({el_recover}) and fail ({el_fail})"
    );
}

#[test]
fn optimal_action_recover_when_strongly_recoverable() {
    let lm = LossMatrix::default();
    let p = Posterior {
        recoverable: 900_000,
        ambiguous: 50_000,
        unrecoverable: 50_000,
    };
    assert_eq!(lm.optimal_action(&p), RecoveryAction::RecoverContinue);
}

#[test]
fn optimal_action_fail_when_strongly_unrecoverable() {
    let lm = LossMatrix::default();
    let p = Posterior {
        recoverable: 50_000,
        ambiguous: 50_000,
        unrecoverable: 900_000,
    };
    assert_eq!(lm.optimal_action(&p), RecoveryAction::FailStrict);
}

// ---------------------------------------------------------------------------
// 15. RecoveryConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn recovery_config_defaults() {
    let cfg = RecoveryConfig::default();
    assert_eq!(cfg.mode, RecoveryMode::StrictDefault);
    assert_eq!(cfg.max_attempts, DEFAULT_MAX_ATTEMPTS);
    assert_eq!(cfg.max_skips, DEFAULT_MAX_SKIPS);
    assert_eq!(cfg.max_insertions, DEFAULT_MAX_INSERTIONS);
    assert_eq!(
        cfg.confidence_threshold_millionths,
        DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS
    );
    assert!(cfg.prior.is_normalized());
}

// ---------------------------------------------------------------------------
// 16-17. RepairCandidate and RepairEdit
// ---------------------------------------------------------------------------

#[test]
fn repair_candidate_construction() {
    let rc = RepairCandidate {
        description: "fix missing brace".to_string(),
        skips: 0,
        insertions: 1,
        cost: 5,
        is_typo_fix: false,
    };
    assert_eq!(rc.description, "fix missing brace");
    assert_eq!(rc.skips, 0);
    assert_eq!(rc.insertions, 1);
    assert_eq!(rc.cost, 5);
    assert!(!rc.is_typo_fix);
}

#[test]
fn repair_edit_skip_construction() {
    let edit = RepairEdit::Skip {
        position: 42,
        count: 2,
    };
    if let RepairEdit::Skip { position, count } = &edit {
        assert_eq!(*position, 42);
        assert_eq!(*count, 2);
    } else {
        panic!("expected Skip variant");
    }
}

#[test]
fn repair_edit_insert_construction() {
    let edit = RepairEdit::Insert {
        position: 10,
        tokens: vec!["semicolon".to_string(), "newline".to_string()],
    };
    if let RepairEdit::Insert { position, tokens } = &edit {
        assert_eq!(*position, 10);
        assert_eq!(tokens.len(), 2);
    } else {
        panic!("expected Insert variant");
    }
}

// ---------------------------------------------------------------------------
// 18-19. RepairDiff
// ---------------------------------------------------------------------------

#[test]
fn repair_diff_build_and_hash() {
    let input_hash = test_hash();
    let edits = vec![
        RepairEdit::Skip {
            position: 5,
            count: 1,
        },
        RepairEdit::Insert {
            position: 6,
            tokens: vec!["semicolon".to_string()],
        },
    ];
    let diff = RepairDiff::build(input_hash.clone(), edits);
    assert_eq!(diff.schema_version, SCHEMA_VERSION);
    assert_eq!(diff.input_hash, input_hash);
    assert_eq!(diff.edits.len(), 2);
    assert!(!diff.is_empty());
    // Hash is deterministic.
    let diff2 = RepairDiff::build(
        input_hash,
        vec![
            RepairEdit::Skip {
                position: 5,
                count: 1,
            },
            RepairEdit::Insert {
                position: 6,
                tokens: vec!["semicolon".to_string()],
            },
        ],
    );
    assert_eq!(diff.diff_hash, diff2.diff_hash);
}

#[test]
fn repair_diff_is_empty() {
    let diff = RepairDiff::build(test_hash(), Vec::new());
    assert!(diff.is_empty());
}

// ---------------------------------------------------------------------------
// 20. ErrorSite to_evidence
// ---------------------------------------------------------------------------

#[test]
fn error_site_to_evidence_simple() {
    let site = simple_site();
    let ev = site.to_evidence();
    assert_eq!(ev.tokens_before_error, 20);
    assert_eq!(ev.candidate_repairs, 1);
    assert!(ev.at_statement_boundary);
    assert_eq!(ev.min_skip_tokens, 0);
    assert_eq!(ev.min_insert_tokens, 1);
    assert!(ev.matches_typo_pattern);
}

#[test]
fn error_site_to_evidence_ambiguous() {
    let site = ambiguous_site();
    let ev = site.to_evidence();
    assert_eq!(ev.candidate_repairs, 3);
    assert!(!ev.at_statement_boundary);
    assert_eq!(ev.min_skip_tokens, 0);
    assert_eq!(ev.min_insert_tokens, 0);
    assert!(!ev.matches_typo_pattern);
}

#[test]
fn error_site_to_evidence_no_candidates() {
    let site = no_candidate_site();
    let ev = site.to_evidence();
    assert_eq!(ev.candidate_repairs, 0);
    assert_eq!(ev.min_skip_tokens, 0);
    assert_eq!(ev.min_insert_tokens, 0);
    assert!(!ev.matches_typo_pattern);
}

// ---------------------------------------------------------------------------
// 21. RecoveryController StrictDefault mode
// ---------------------------------------------------------------------------

#[test]
fn controller_strict_mode_always_fails() {
    let cfg = strict_config();
    let mut ctrl = RecoveryController::new(cfg, 42);
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-strict")
        .unwrap();
    assert!(!result.recovered);
    assert_eq!(result.final_action, RecoveryAction::FailStrict);
    assert_eq!(result.mode, RecoveryMode::StrictDefault);
    assert_eq!(result.decisions.len(), 1);
    assert_eq!(result.attempts.len(), 0);
    assert!(result.repair_diff.is_none());
}

// ---------------------------------------------------------------------------
// 22. RecoveryController DiagnosticRecovery mode
// ---------------------------------------------------------------------------

#[test]
fn controller_diagnostic_mode_does_not_report_recovered() {
    // Diagnostic mode evaluates but never sets recovered=true (it's report-only).
    let cfg = RecoveryConfig {
        mode: RecoveryMode::DiagnosticRecovery,
        confidence_threshold_millionths: 100_000, // low threshold so action is accepted
        ..RecoveryConfig::default()
    };
    let mut ctrl = RecoveryController::new(cfg, 99);
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-diag")
        .unwrap();
    // Diagnostic mode never reports recovered=true even if action succeeds.
    assert!(!result.recovered);
    assert_eq!(result.mode, RecoveryMode::DiagnosticRecovery);
}

// ---------------------------------------------------------------------------
// 23. RecoveryController ExecutionRecovery mode
// ---------------------------------------------------------------------------

#[test]
fn controller_execution_mode_recovers_simple_typo() {
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        confidence_threshold_millionths: 100_000, // low threshold for test
        ..RecoveryConfig::default()
    };
    let mut ctrl = RecoveryController::new(cfg, 1);
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-exec")
        .unwrap();
    assert!(result.recovered);
    assert_ne!(result.final_action, RecoveryAction::FailStrict);
    assert_eq!(result.mode, RecoveryMode::ExecutionRecovery);
    assert!(!result.decisions.is_empty());
    assert!(!result.attempts.is_empty());
}

// ---------------------------------------------------------------------------
// 24. Budget exhaustion
// ---------------------------------------------------------------------------

#[test]
fn controller_budget_exhaustion() {
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        max_attempts: 1,
        confidence_threshold_millionths: 100_000,
        ..RecoveryConfig::default()
    };
    let mut ctrl = RecoveryController::new(cfg, 7);
    let sites = vec![simple_site(), simple_site()];
    let err = ctrl
        .evaluate(test_hash(), &sites, "trace-budget")
        .unwrap_err();
    match err {
        RecoveryError::BudgetExhausted { attempts, max } => {
            assert_eq!(attempts, 1);
            assert_eq!(max, 1);
        }
        other => panic!("expected BudgetExhausted, got: {other}"),
    }
}

#[test]
fn controller_max_attempts_zero_is_invalid() {
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        max_attempts: 0,
        ..RecoveryConfig::default()
    };
    let mut ctrl = RecoveryController::new(cfg, 1);
    let err = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-zero")
        .unwrap_err();
    match err {
        RecoveryError::InvalidConfig { detail } => {
            assert!(detail.contains("max_attempts"));
        }
        other => panic!("expected InvalidConfig, got: {other}"),
    }
}

// ---------------------------------------------------------------------------
// 25. Confidence gating
// ---------------------------------------------------------------------------

#[test]
fn confidence_gating_below_threshold_fails_strict() {
    // Use a very high confidence threshold so the posterior never meets it.
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        confidence_threshold_millionths: 999_999,
        ..RecoveryConfig::default()
    };
    let mut ctrl = RecoveryController::new(cfg, 42);
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-conf")
        .unwrap();
    // Should not be recovered because confidence is below 99.9999%.
    assert!(!result.recovered);
    assert_eq!(result.final_action, RecoveryAction::FailStrict);
}

// ---------------------------------------------------------------------------
// 26. Multi-site evaluation
// ---------------------------------------------------------------------------

#[test]
fn multi_site_evaluation() {
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        max_attempts: 5,
        confidence_threshold_millionths: 100_000,
        ..RecoveryConfig::default()
    };
    let mut ctrl = RecoveryController::new(cfg, 123);
    let sites = vec![simple_site(), simple_site()];
    let result = ctrl.evaluate(test_hash(), &sites, "trace-multi").unwrap();
    assert_eq!(result.decisions.len(), 2);
    assert_eq!(result.attempts.len(), 2);
}

// ---------------------------------------------------------------------------
// 27. RecoveryResult summary
// ---------------------------------------------------------------------------

#[test]
fn recovery_result_summary_recovered() {
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        confidence_threshold_millionths: 100_000,
        ..RecoveryConfig::default()
    };
    let mut ctrl = RecoveryController::new(cfg, 1);
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-sum-ok")
        .unwrap();
    let summary = result.summary();
    assert!(
        summary.starts_with("RECOVERED:"),
        "expected RECOVERED prefix, got: {summary}"
    );
}

#[test]
fn recovery_result_summary_strict_fail() {
    let cfg = strict_config();
    let mut ctrl = RecoveryController::new(cfg, 2);
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-sum-fail")
        .unwrap();
    let summary = result.summary();
    assert!(
        summary.starts_with("STRICT_FAIL:"),
        "expected STRICT_FAIL prefix, got: {summary}"
    );
}

// ---------------------------------------------------------------------------
// 28. RecoveryError codes and display
// ---------------------------------------------------------------------------

#[test]
fn error_budget_exhausted_code_and_display() {
    let e = RecoveryError::BudgetExhausted {
        attempts: 5,
        max: 5,
    };
    assert_eq!(e.code(), "BUDGET_EXHAUSTED");
    assert_eq!(format!("{e}"), "budget exhausted: 5/5 attempts");
}

#[test]
fn error_invalid_config_code_and_display() {
    let e = RecoveryError::InvalidConfig {
        detail: "bad param".to_string(),
    };
    assert_eq!(e.code(), "INVALID_CONFIG");
    assert_eq!(format!("{e}"), "invalid config: bad param");
}

#[test]
fn error_no_candidates_code_and_display() {
    let e = RecoveryError::NoCandidates { error_position: 42 };
    assert_eq!(e.code(), "NO_CANDIDATES");
    assert_eq!(format!("{e}"), "no candidates at position 42");
}

// ---------------------------------------------------------------------------
// 29. Serde roundtrip for all major types
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_recovery_mode() {
    for mode in [
        RecoveryMode::StrictDefault,
        RecoveryMode::DiagnosticRecovery,
        RecoveryMode::ExecutionRecovery,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: RecoveryMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

#[test]
fn serde_roundtrip_error_state() {
    for state in [
        ErrorState::Recoverable,
        ErrorState::Ambiguous,
        ErrorState::Unrecoverable,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: ErrorState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

#[test]
fn serde_roundtrip_recovery_action() {
    for action in [
        RecoveryAction::RecoverContinue,
        RecoveryAction::PartialRecover,
        RecoveryAction::FailStrict,
    ] {
        let json = serde_json::to_string(&action).unwrap();
        let back: RecoveryAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }
}

#[test]
fn serde_roundtrip_posterior() {
    let p = Posterior::default_prior();
    let json = serde_json::to_string(&p).unwrap();
    let back: Posterior = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn serde_roundtrip_evidence_features() {
    let ev = simple_site().to_evidence();
    let json = serde_json::to_string(&ev).unwrap();
    let back: EvidenceFeatures = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn serde_roundtrip_loss_matrix() {
    let lm = LossMatrix::default();
    let json = serde_json::to_string(&lm).unwrap();
    let back: LossMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(lm, back);
}

#[test]
fn serde_roundtrip_recovery_config() {
    let cfg = RecoveryConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: RecoveryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn serde_roundtrip_repair_candidate() {
    let rc = RepairCandidate {
        description: "insert paren".to_string(),
        skips: 1,
        insertions: 0,
        cost: 3,
        is_typo_fix: false,
    };
    let json = serde_json::to_string(&rc).unwrap();
    let back: RepairCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(rc, back);
}

#[test]
fn serde_roundtrip_repair_edit() {
    let edit = RepairEdit::Insert {
        position: 5,
        tokens: vec!["tok".to_string()],
    };
    let json = serde_json::to_string(&edit).unwrap();
    let back: RepairEdit = serde_json::from_str(&json).unwrap();
    assert_eq!(edit, back);
}

#[test]
fn serde_roundtrip_repair_diff() {
    let diff = RepairDiff::build(
        test_hash(),
        vec![RepairEdit::Skip {
            position: 1,
            count: 2,
        }],
    );
    let json = serde_json::to_string(&diff).unwrap();
    let back: RepairDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, back);
}

#[test]
fn serde_roundtrip_error_site() {
    let site = simple_site();
    let json = serde_json::to_string(&site).unwrap();
    let back: ErrorSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

#[test]
fn serde_roundtrip_recovery_error() {
    let e = RecoveryError::BudgetExhausted {
        attempts: 3,
        max: 5,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: RecoveryError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn serde_roundtrip_recovery_result() {
    let cfg = execution_config();
    let mut ctrl = RecoveryController::new(
        RecoveryConfig {
            confidence_threshold_millionths: 100_000,
            ..cfg
        },
        42,
    );
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-serde")
        .unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: RecoveryResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// 30. Deterministic replay (same seed -> same decisions)
// ---------------------------------------------------------------------------

#[test]
fn deterministic_replay_same_seed() {
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        confidence_threshold_millionths: 100_000,
        ..RecoveryConfig::default()
    };
    let sites = vec![simple_site(), ambiguous_site()];
    let mut ctrl1 = RecoveryController::new(cfg.clone(), 77);
    let r1 = ctrl1.evaluate(test_hash(), &sites, "trace-det1").unwrap();
    let mut ctrl2 = RecoveryController::new(cfg, 77);
    let r2 = ctrl2.evaluate(test_hash(), &sites, "trace-det1").unwrap();
    // Decisions, posteriors, actions should be identical.
    assert_eq!(r1.decisions.len(), r2.decisions.len());
    for (d1, d2) in r1.decisions.iter().zip(r2.decisions.iter()) {
        assert_eq!(d1.action, d2.action);
        assert_eq!(d1.posterior, d2.posterior);
        assert_eq!(d1.confidence_millionths, d2.confidence_millionths);
        assert_eq!(d1.evidence_hash, d2.evidence_hash);
    }
    assert_eq!(r1.result_digest, r2.result_digest);
}

#[test]
fn different_seeds_produce_different_decision_ids() {
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        confidence_threshold_millionths: 100_000,
        ..RecoveryConfig::default()
    };
    let mut ctrl1 = RecoveryController::new(cfg.clone(), 1);
    let r1 = ctrl1
        .evaluate(test_hash(), &[simple_site()], "trace-s1")
        .unwrap();
    let mut ctrl2 = RecoveryController::new(cfg, 2);
    let r2 = ctrl2
        .evaluate(test_hash(), &[simple_site()], "trace-s1")
        .unwrap();
    // Decision IDs differ because seed differs.
    assert_ne!(r1.decisions[0].decision_id, r2.decisions[0].decision_id);
    // But posteriors/actions are the same (evidence is the same).
    assert_eq!(r1.decisions[0].action, r2.decisions[0].action);
    assert_eq!(r1.decisions[0].posterior, r2.decisions[0].posterior);
}

// ---------------------------------------------------------------------------
// 31. Evidence hash determinism
// ---------------------------------------------------------------------------

#[test]
fn evidence_hash_determinism_across_builds() {
    let ev1 = simple_site().to_evidence();
    let ev2 = simple_site().to_evidence();
    assert_eq!(ev1.compute_hash(), ev2.compute_hash());
    // Different evidence produces different hash.
    let ev3 = no_candidate_site().to_evidence();
    assert_ne!(ev1.compute_hash(), ev3.compute_hash());
}

// ---------------------------------------------------------------------------
// 32. RecoveryEvent structure verification
// ---------------------------------------------------------------------------

#[test]
fn recovery_event_structure_strict_mode() {
    let cfg = strict_config();
    let mut ctrl = RecoveryController::new(cfg, 99);
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-evt")
        .unwrap();
    assert!(!result.events.is_empty());
    let first_event = &result.events[0];
    assert_eq!(first_event.component, COMPONENT);
    assert_eq!(first_event.trace_id, "trace-evt");
    assert_eq!(first_event.event, "strict_fail");
    assert_eq!(first_event.outcome, "fail_strict");
    assert_eq!(first_event.mode, "strict_default");
}

#[test]
fn recovery_event_structure_execution_mode() {
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        confidence_threshold_millionths: 100_000,
        ..RecoveryConfig::default()
    };
    let mut ctrl = RecoveryController::new(cfg, 10);
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-evt-exec")
        .unwrap();
    assert!(
        result.events.len() >= 2,
        "expect at least site_evaluated + evaluation_complete events"
    );
    // Last event should be the final evaluation_complete event.
    let last = result.events.last().unwrap();
    assert_eq!(last.event, "evaluation_complete");
}

#[test]
fn recovery_event_serde_roundtrip() {
    let cfg = strict_config();
    let mut ctrl = RecoveryController::new(cfg, 1);
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-ev-serde")
        .unwrap();
    for event in &result.events {
        let json = serde_json::to_string(event).unwrap();
        let back: RecoveryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, &back);
    }
}

// ---------------------------------------------------------------------------
// Additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn convenience_evaluate_function() {
    let cfg = execution_config();
    let low_thresh_cfg = RecoveryConfig {
        confidence_threshold_millionths: 100_000,
        ..cfg
    };
    let result = evaluate(
        test_hash(),
        &[simple_site()],
        &low_thresh_cfg,
        42,
        "trace-conv",
    )
    .unwrap();
    assert!(result.recovered);
    assert_eq!(result.mode, RecoveryMode::ExecutionRecovery);
}

#[test]
fn schema_version_constant() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.bayesian-error-recovery.v1");
}

#[test]
fn component_constant() {
    assert_eq!(COMPONENT, "bayesian_error_recovery");
}

#[test]
fn recovery_result_schema_version_populated() {
    let cfg = strict_config();
    let mut ctrl = RecoveryController::new(cfg, 0);
    let result = ctrl
        .evaluate(test_hash(), &[simple_site()], "trace-schema")
        .unwrap();
    assert_eq!(result.schema_version, SCHEMA_VERSION);
}

#[test]
fn empty_sites_strict_mode() {
    let cfg = strict_config();
    let mut ctrl = RecoveryController::new(cfg, 0);
    let result = ctrl.evaluate(test_hash(), &[], "trace-empty").unwrap();
    assert!(!result.recovered);
    // Even with no sites, strict mode produces one decision.
    assert_eq!(result.decisions.len(), 1);
}

#[test]
fn empty_sites_execution_mode() {
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        confidence_threshold_millionths: 100_000,
        ..RecoveryConfig::default()
    };
    let mut ctrl = RecoveryController::new(cfg, 0);
    let result = ctrl.evaluate(test_hash(), &[], "trace-empty-exec").unwrap();
    // No sites means no decisions in execution mode, so not recovered.
    assert!(!result.recovered);
    assert!(result.decisions.is_empty());
}

#[test]
fn repair_diff_hash_differs_for_different_edits() {
    let d1 = RepairDiff::build(
        test_hash(),
        vec![RepairEdit::Skip {
            position: 1,
            count: 1,
        }],
    );
    let d2 = RepairDiff::build(
        test_hash(),
        vec![RepairEdit::Skip {
            position: 2,
            count: 1,
        }],
    );
    assert_ne!(d1.diff_hash, d2.diff_hash);
}

#[test]
fn repair_candidate_filtered_by_max_skips() {
    let site = ErrorSite {
        error_position: 10,
        tokens_before_error: 20,
        at_statement_boundary: true,
        candidates: vec![RepairCandidate {
            description: "big skip".to_string(),
            skips: 100, // exceeds default max_skips of 3
            insertions: 0,
            cost: 1,
            is_typo_fix: true,
        }],
        context_hash: test_hash(),
    };
    let cfg = RecoveryConfig {
        mode: RecoveryMode::ExecutionRecovery,
        confidence_threshold_millionths: 100_000,
        ..RecoveryConfig::default()
    };
    let mut ctrl = RecoveryController::new(cfg, 1);
    let result = ctrl
        .evaluate(test_hash(), &[site], "trace-skip-filter")
        .unwrap();
    // The candidate is filtered out because skips > max_skips,
    // so no repair is selected even though action might not be FailStrict.
    for attempt in &result.attempts {
        assert!(
            attempt.selected_repair.is_none(),
            "repair with excessive skips should be filtered out"
        );
    }
}
