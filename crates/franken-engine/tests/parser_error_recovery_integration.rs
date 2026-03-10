//! Integration tests for the parser_error_recovery module.

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
use std::fs;
use std::path::Path;

use frankenengine_engine::parser_error_recovery::*;
use serde::Deserialize;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn simple_error() -> SyntaxError {
    SyntaxError {
        offset: 10,
        message: "expected ';'".to_string(),
        tokens_before: 5,
        tokens_after: 20,
        at_statement_boundary: true,
        candidates: vec![";".to_string()],
    }
}

fn ambiguous_error() -> SyntaxError {
    SyntaxError {
        offset: 25,
        message: "unexpected token".to_string(),
        tokens_before: 10,
        tokens_after: 15,
        at_statement_boundary: false,
        candidates: vec![
            ";".to_string(),
            ")".to_string(),
            "}".to_string(),
            ",".to_string(),
        ],
    }
}

fn unrecoverable_error() -> SyntaxError {
    SyntaxError {
        offset: 50,
        message: "completely garbled".to_string(),
        tokens_before: 2,
        tokens_after: 0,
        at_statement_boundary: false,
        candidates: vec![],
    }
}

fn diagnostic_config() -> RecoveryConfig {
    RecoveryConfig {
        mode: RecoveryMode::Diagnostic,
        ..RecoveryConfig::default()
    }
}

fn execution_config() -> RecoveryConfig {
    RecoveryConfig {
        mode: RecoveryMode::Execution,
        ..RecoveryConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Mode display
// ---------------------------------------------------------------------------

#[test]
fn mode_display_strict() {
    assert_eq!(RecoveryMode::Strict.to_string(), "strict");
}

#[test]
fn mode_display_diagnostic() {
    assert_eq!(RecoveryMode::Diagnostic.to_string(), "diagnostic");
}

#[test]
fn mode_display_execution() {
    assert_eq!(RecoveryMode::Execution.to_string(), "execution");
}

// ---------------------------------------------------------------------------
// ErrorState display
// ---------------------------------------------------------------------------

#[test]
fn error_state_display_all() {
    assert_eq!(ErrorState::Recoverable.to_string(), "recoverable");
    assert_eq!(ErrorState::Ambiguous.to_string(), "ambiguous");
    assert_eq!(ErrorState::Unrecoverable.to_string(), "unrecoverable");
}

// ---------------------------------------------------------------------------
// RecoveryAction display
// ---------------------------------------------------------------------------

#[test]
fn action_display_all() {
    assert_eq!(
        RecoveryAction::RecoverContinue.to_string(),
        "recover-continue"
    );
    assert_eq!(
        RecoveryAction::PartialRecover.to_string(),
        "partial-recover"
    );
    assert_eq!(RecoveryAction::FailStrict.to_string(), "fail-strict");
}

// ---------------------------------------------------------------------------
// RecoveryOutcome display
// ---------------------------------------------------------------------------

#[test]
fn outcome_display_all() {
    assert_eq!(RecoveryOutcome::CleanParse.to_string(), "clean-parse");
    assert_eq!(RecoveryOutcome::Recovered.to_string(), "recovered");
    assert_eq!(
        RecoveryOutcome::PartiallyRecovered.to_string(),
        "partially-recovered"
    );
    assert_eq!(RecoveryOutcome::StrictFailed.to_string(), "strict-failed");
    assert_eq!(
        RecoveryOutcome::RecoveryFailed.to_string(),
        "recovery-failed"
    );
    assert_eq!(
        RecoveryOutcome::BudgetExhausted.to_string(),
        "budget-exhausted"
    );
}

// ---------------------------------------------------------------------------
// StateProbabilities
// ---------------------------------------------------------------------------

#[test]
fn default_prior_sums_to_million() {
    let prior = StateProbabilities::default();
    assert!(prior.is_valid());
    assert_eq!(
        prior.recoverable + prior.ambiguous + prior.unrecoverable,
        1_000_000
    );
}

#[test]
fn default_prior_values() {
    let prior = StateProbabilities::default();
    assert_eq!(prior.recoverable, 600_000);
    assert_eq!(prior.ambiguous, 300_000);
    assert_eq!(prior.unrecoverable, 100_000);
}

#[test]
fn most_likely_recoverable_when_dominant() {
    let p = StateProbabilities {
        recoverable: 700_000,
        ambiguous: 200_000,
        unrecoverable: 100_000,
    };
    assert_eq!(p.most_likely(), ErrorState::Recoverable);
}

#[test]
fn most_likely_ambiguous_when_dominant() {
    let p = StateProbabilities {
        recoverable: 200_000,
        ambiguous: 600_000,
        unrecoverable: 200_000,
    };
    assert_eq!(p.most_likely(), ErrorState::Ambiguous);
}

#[test]
fn most_likely_unrecoverable_when_dominant() {
    let p = StateProbabilities {
        recoverable: 100_000,
        ambiguous: 200_000,
        unrecoverable: 700_000,
    };
    assert_eq!(p.most_likely(), ErrorState::Unrecoverable);
}

#[test]
fn confidence_returns_max_probability() {
    let p = StateProbabilities {
        recoverable: 100_000,
        ambiguous: 200_000,
        unrecoverable: 700_000,
    };
    assert_eq!(p.confidence(), 700_000);
}

#[test]
fn is_valid_detects_invalid_sum() {
    let p = StateProbabilities {
        recoverable: 500_000,
        ambiguous: 500_000,
        unrecoverable: 500_000,
    };
    assert!(!p.is_valid());
}

// ---------------------------------------------------------------------------
// Bayesian update
// ---------------------------------------------------------------------------

#[test]
fn bayesian_update_with_simple_error_favors_recoverable() {
    let prior = StateProbabilities::default();
    let evidence = EvidenceFeatures {
        tokens_before_error: 5,
        tokens_after_error: 20,
        error_offset: 10,
        at_statement_boundary: true,
        single_token_fix: true,
        single_token_delete: true,
        candidate_count: 1,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    }
    .with_hash();

    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.is_valid());
    assert_eq!(posterior.most_likely(), ErrorState::Recoverable);
    assert!(posterior.recoverable > prior.recoverable);
}

#[test]
fn bayesian_update_with_no_candidates_favors_unrecoverable() {
    let prior = StateProbabilities::default();
    let evidence = EvidenceFeatures {
        tokens_before_error: 2,
        tokens_after_error: 0,
        error_offset: 50,
        at_statement_boundary: false,
        single_token_fix: false,
        single_token_delete: false,
        candidate_count: 0,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    }
    .with_hash();

    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.is_valid());
    assert_eq!(posterior.most_likely(), ErrorState::Unrecoverable);
}

#[test]
fn bayesian_update_with_many_candidates_favors_ambiguous() {
    let prior = StateProbabilities {
        recoverable: 333_334,
        ambiguous: 333_333,
        unrecoverable: 333_333,
    };
    let evidence = EvidenceFeatures {
        tokens_before_error: 10,
        tokens_after_error: 15,
        error_offset: 25,
        at_statement_boundary: false,
        single_token_fix: false,
        single_token_delete: true,
        candidate_count: 5,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    }
    .with_hash();

    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.is_valid());
    assert_eq!(posterior.most_likely(), ErrorState::Ambiguous);
}

#[test]
fn bayesian_update_deterministic() {
    let prior = StateProbabilities::default();
    let evidence = EvidenceFeatures {
        tokens_before_error: 5,
        tokens_after_error: 20,
        error_offset: 10,
        at_statement_boundary: true,
        single_token_fix: true,
        single_token_delete: true,
        candidate_count: 1,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    }
    .with_hash();

    let p1 = bayesian_update(&prior, &evidence);
    let p2 = bayesian_update(&prior, &evidence);
    assert_eq!(p1, p2);
}

#[test]
fn bayesian_update_normalizes_output() {
    let prior = StateProbabilities::default();
    let evidence = EvidenceFeatures {
        tokens_before_error: 100,
        tokens_after_error: 200,
        error_offset: 50,
        at_statement_boundary: true,
        single_token_fix: false,
        single_token_delete: true,
        candidate_count: 2,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
    }
    .with_hash();

    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.is_valid());
}

// ---------------------------------------------------------------------------
// Loss matrix and action selection
// ---------------------------------------------------------------------------

#[test]
fn default_loss_matrix_values() {
    let m = LossMatrix::default();
    assert_eq!(m.recover_recoverable, 2);
    assert_eq!(m.recover_unrecoverable, 90);
    assert_eq!(m.fail_unrecoverable, 1);
}

#[test]
fn expected_loss_for_strongly_recoverable_favors_recover() {
    let posterior = StateProbabilities {
        recoverable: 900_000,
        ambiguous: 50_000,
        unrecoverable: 50_000,
    };
    let matrix = LossMatrix::default();
    let el_recover = expected_loss(RecoveryAction::RecoverContinue, &posterior, &matrix);
    let el_fail = expected_loss(RecoveryAction::FailStrict, &posterior, &matrix);
    assert!(el_recover < el_fail);
}

#[test]
fn expected_loss_for_strongly_unrecoverable_favors_fail() {
    let posterior = StateProbabilities {
        recoverable: 50_000,
        ambiguous: 50_000,
        unrecoverable: 900_000,
    };
    let matrix = LossMatrix::default();
    let el_recover = expected_loss(RecoveryAction::RecoverContinue, &posterior, &matrix);
    let el_fail = expected_loss(RecoveryAction::FailStrict, &posterior, &matrix);
    assert!(el_fail < el_recover);
}

#[test]
fn select_action_picks_minimum_expected_loss() {
    let posterior = StateProbabilities {
        recoverable: 900_000,
        ambiguous: 50_000,
        unrecoverable: 50_000,
    };
    let matrix = LossMatrix::default();
    let action = select_action(&posterior, &matrix);
    assert_eq!(action, RecoveryAction::RecoverContinue);
}

#[test]
fn select_action_for_unrecoverable_picks_fail() {
    let posterior = StateProbabilities {
        recoverable: 50_000,
        ambiguous: 50_000,
        unrecoverable: 900_000,
    };
    let matrix = LossMatrix::default();
    let action = select_action(&posterior, &matrix);
    assert_eq!(action, RecoveryAction::FailStrict);
}

// ---------------------------------------------------------------------------
// RepairEdit display
// ---------------------------------------------------------------------------

#[test]
fn repair_edit_insert_display() {
    let edit = RepairEdit::Insert {
        offset: 10,
        token_text: ";".to_string(),
    };
    assert_eq!(edit.to_string(), "insert ';' at 10");
}

#[test]
fn repair_edit_delete_display() {
    let edit = RepairEdit::Delete {
        offset: 20,
        length: 3,
    };
    assert_eq!(edit.to_string(), "delete 3B at 20");
}

#[test]
fn repair_edit_replace_display() {
    let edit = RepairEdit::Replace {
        offset: 5,
        length: 2,
        replacement: "==".to_string(),
    };
    assert_eq!(edit.to_string(), "replace 2B at 5 with '=='");
}

#[test]
fn repair_edit_skip_display() {
    let edit = RepairEdit::Skip {
        offset: 30,
        count: 2,
    };
    assert_eq!(edit.to_string(), "skip 2 tokens at 30");
}

// ---------------------------------------------------------------------------
// RecoveryConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn default_config_is_strict() {
    let config = RecoveryConfig::default();
    assert_eq!(config.mode, RecoveryMode::Strict);
    assert_eq!(config.max_attempts, DEFAULT_MAX_ATTEMPTS);
    assert_eq!(config.max_token_skips, DEFAULT_MAX_TOKEN_SKIPS);
    assert_eq!(config.max_insertions, DEFAULT_MAX_INSERTIONS);
    assert_eq!(
        config.confidence_threshold_millionths,
        DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS
    );
    assert!(config.prior.is_valid());
}

// ---------------------------------------------------------------------------
// run_recovery integration tests
// ---------------------------------------------------------------------------

#[test]
fn clean_parse_no_errors() {
    let config = diagnostic_config();
    let ledger = run_recovery(&[], 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::CleanParse);
    assert!(ledger.attempts.is_empty());
    assert_eq!(ledger.total_edits, 0);
}

#[test]
fn strict_mode_always_fails() {
    let config = RecoveryConfig::default();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::StrictFailed);
    assert!(ledger.attempts.is_empty());
}

#[test]
fn diagnostic_mode_recovers_simple_error() {
    let config = diagnostic_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::Recovered);
    assert_eq!(ledger.attempts.len(), 1);
    assert!(ledger.total_edits > 0);
    assert_eq!(ledger.mode, RecoveryMode::Diagnostic);
}

#[test]
fn diagnostic_mode_with_multiple_errors() {
    let config = diagnostic_config();
    let errors = vec![simple_error(), ambiguous_error()];
    let ledger = run_recovery(&errors, 200, &config);
    assert_eq!(ledger.attempts.len(), 2);
    assert!(ledger.total_edits > 0);
}

#[test]
fn execution_mode_with_recoverable_error() {
    let config = execution_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert_eq!(ledger.mode, RecoveryMode::Execution);
    assert_eq!(ledger.attempts.len(), 1);
}

#[test]
fn unrecoverable_error_fails_recovery() {
    let config = diagnostic_config();
    let errors = vec![unrecoverable_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert_eq!(ledger.attempts.len(), 1);
    // No candidates → fails
    assert!(!ledger.attempts[0].succeeded);
}

#[test]
fn budget_exhaustion_with_many_errors() {
    let mut config = diagnostic_config();
    config.max_attempts = 2;
    let errors = vec![simple_error(), ambiguous_error(), unrecoverable_error()];
    let ledger = run_recovery(&errors, 300, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::BudgetExhausted);
    assert_eq!(ledger.attempts.len(), 2);
}

#[test]
fn attempt_records_evidence_and_posterior() {
    let config = diagnostic_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    let attempt = &ledger.attempts[0];
    assert!(attempt.posterior.is_valid());
    assert_eq!(attempt.attempt_index, 0);
    assert!(attempt.confidence_millionths > 0);
}

#[test]
fn attempt_records_rejected_actions() {
    let config = diagnostic_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    let attempt = &ledger.attempts[0];
    assert_eq!(attempt.rejected_actions.len(), 2);
}

#[test]
fn repair_diff_hash_present_when_edits_applied() {
    let config = diagnostic_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    if ledger.total_edits > 0 {
        assert!(ledger.repair_diff_hash.is_some());
    }
}

#[test]
fn repair_diff_hash_absent_when_no_edits() {
    let config = RecoveryConfig::default(); // strict
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert!(ledger.repair_diff_hash.is_none());
}

#[test]
fn schema_version_present() {
    let config = diagnostic_config();
    let ledger = run_recovery(&[], 100, &config);
    assert_eq!(ledger.schema_version, SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Confidence gating in execution mode
// ---------------------------------------------------------------------------

#[test]
fn execution_mode_gates_on_confidence() {
    let mut config = execution_config();
    config.confidence_threshold_millionths = 999_999; // very high
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    // With extremely high threshold, action may be forced to FailStrict
    let attempt = &ledger.attempts[0];
    if attempt.confidence_millionths < 999_999 {
        assert_eq!(attempt.action, RecoveryAction::FailStrict);
    }
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_replay_same_input_same_output() {
    let config = diagnostic_config();
    let errors = vec![simple_error(), ambiguous_error()];
    let l1 = run_recovery(&errors, 200, &config);
    let l2 = run_recovery(&errors, 200, &config);
    assert_eq!(l1.outcome, l2.outcome);
    assert_eq!(l1.total_edits, l2.total_edits);
    assert_eq!(l1.attempts.len(), l2.attempts.len());
    for (a1, a2) in l1.attempts.iter().zip(l2.attempts.iter()) {
        assert_eq!(a1.posterior, a2.posterior);
        assert_eq!(a1.action, a2.action);
    }
}

// ---------------------------------------------------------------------------
// CalibrationReport
// ---------------------------------------------------------------------------

#[test]
fn calibration_report_computes_rates() {
    let report = CalibrationReport::compute(80, 10, 90, 20, 800_000);
    assert_eq!(report.total_cases, 200);
    assert_eq!(report.true_positives, 80);
    assert_eq!(report.false_positives, 10);
    assert_eq!(report.true_negatives, 90);
    assert_eq!(report.false_negatives, 20);
    // FPR = 10 / (80+10) = 0.1111 ≈ 111_111 millionths
    assert!(report.false_positive_rate_millionths > 100_000);
    assert!(report.false_positive_rate_millionths < 120_000);
}

#[test]
fn calibration_report_zero_positives() {
    let report = CalibrationReport::compute(0, 0, 100, 0, 800_000);
    assert_eq!(report.false_positive_rate_millionths, 0);
}

#[test]
fn calibration_report_schema_version() {
    let report = CalibrationReport::compute(10, 1, 10, 1, 800_000);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Mode policy table
// ---------------------------------------------------------------------------

#[test]
fn mode_policy_table_has_three_entries() {
    let table = mode_policy_table();
    assert_eq!(table.len(), 3);
}

#[test]
fn mode_policy_strict_no_edits() {
    let table = mode_policy_table();
    let strict = table
        .iter()
        .find(|e| e.mode == RecoveryMode::Strict)
        .unwrap();
    assert!(!strict.edits_applied);
    assert!(!strict.execution_uses_recovery);
}

#[test]
fn mode_policy_execution_uses_recovery() {
    let table = mode_policy_table();
    let exec = table
        .iter()
        .find(|e| e.mode == RecoveryMode::Execution)
        .unwrap();
    assert!(exec.edits_applied);
    assert!(exec.execution_uses_recovery);
}

// ---------------------------------------------------------------------------
// EvidenceFeatures
// ---------------------------------------------------------------------------

#[test]
fn evidence_with_hash_updates_hash() {
    let e1 = EvidenceFeatures {
        tokens_before_error: 5,
        tokens_after_error: 20,
        error_offset: 10,
        at_statement_boundary: true,
        single_token_fix: true,
        single_token_delete: true,
        candidate_count: 1,
        features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"placeholder"),
    };
    let e2 = e1.clone().with_hash();
    // Hash should change from placeholder
    assert_ne!(e1.features_hash, e2.features_hash);
}

#[test]
fn evidence_hash_deterministic() {
    let make = || {
        EvidenceFeatures {
            tokens_before_error: 5,
            tokens_after_error: 20,
            error_offset: 10,
            at_statement_boundary: true,
            single_token_fix: true,
            single_token_delete: true,
            candidate_count: 1,
            features_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"placeholder"),
        }
        .with_hash()
    };
    assert_eq!(make().features_hash, make().features_hash);
}

// ---------------------------------------------------------------------------
// Serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_recovery_mode() {
    for mode in [
        RecoveryMode::Strict,
        RecoveryMode::Diagnostic,
        RecoveryMode::Execution,
    ] {
        let s = serde_json::to_string(&mode).unwrap();
        let back: RecoveryMode = serde_json::from_str(&s).unwrap();
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
        let s = serde_json::to_string(&state).unwrap();
        let back: ErrorState = serde_json::from_str(&s).unwrap();
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
        let s = serde_json::to_string(&action).unwrap();
        let back: RecoveryAction = serde_json::from_str(&s).unwrap();
        assert_eq!(action, back);
    }
}

#[test]
fn serde_roundtrip_state_probabilities() {
    let p = StateProbabilities::default();
    let s = serde_json::to_string(&p).unwrap();
    let back: StateProbabilities = serde_json::from_str(&s).unwrap();
    assert_eq!(p, back);
}

#[test]
fn serde_roundtrip_loss_matrix() {
    let m = LossMatrix::default();
    let s = serde_json::to_string(&m).unwrap();
    let back: LossMatrix = serde_json::from_str(&s).unwrap();
    assert_eq!(m, back);
}

#[test]
fn serde_roundtrip_recovery_config() {
    let c = RecoveryConfig::default();
    let s = serde_json::to_string(&c).unwrap();
    let back: RecoveryConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(c, back);
}

#[test]
fn serde_roundtrip_repair_edit() {
    let edits = vec![
        RepairEdit::Insert {
            offset: 10,
            token_text: ";".to_string(),
        },
        RepairEdit::Delete {
            offset: 20,
            length: 3,
        },
        RepairEdit::Replace {
            offset: 5,
            length: 2,
            replacement: "==".to_string(),
        },
        RepairEdit::Skip {
            offset: 30,
            count: 2,
        },
    ];
    for edit in edits {
        let s = serde_json::to_string(&edit).unwrap();
        let back: RepairEdit = serde_json::from_str(&s).unwrap();
        assert_eq!(edit, back);
    }
}

#[test]
fn serde_roundtrip_decision_ledger() {
    let config = diagnostic_config();
    let errors = vec![simple_error()];
    let ledger = run_recovery(&errors, 100, &config);
    let s = serde_json::to_string(&ledger).unwrap();
    let back: DecisionLedger = serde_json::from_str(&s).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn serde_roundtrip_calibration_report() {
    let report = CalibrationReport::compute(80, 10, 90, 20, 800_000);
    let s = serde_json::to_string(&report).unwrap();
    let back: CalibrationReport = serde_json::from_str(&s).unwrap();
    assert_eq!(report, back);
}

#[test]
fn serde_roundtrip_recovery_outcome() {
    for outcome in [
        RecoveryOutcome::CleanParse,
        RecoveryOutcome::Recovered,
        RecoveryOutcome::PartiallyRecovered,
        RecoveryOutcome::StrictFailed,
        RecoveryOutcome::RecoveryFailed,
        RecoveryOutcome::BudgetExhausted,
    ] {
        let s = serde_json::to_string(&outcome).unwrap();
        let back: RecoveryOutcome = serde_json::from_str(&s).unwrap();
        assert_eq!(outcome, back);
    }
}

// ---------------------------------------------------------------------------
// Mixed-scenario integration
// ---------------------------------------------------------------------------

#[test]
fn mixed_errors_produce_partially_recovered() {
    let config = diagnostic_config();
    let errors = vec![simple_error(), unrecoverable_error()];
    let ledger = run_recovery(&errors, 200, &config);
    // simple succeeds, unrecoverable fails
    assert_eq!(ledger.outcome, RecoveryOutcome::PartiallyRecovered);
}

#[test]
fn all_unrecoverable_gives_recovery_failed() {
    let config = diagnostic_config();
    let errors = vec![unrecoverable_error()];
    let ledger = run_recovery(&errors, 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::RecoveryFailed);
}

#[test]
fn input_hash_deterministic() {
    let config = diagnostic_config();
    let l1 = run_recovery(&[], 100, &config);
    let l2 = run_recovery(&[], 100, &config);
    assert_eq!(l1.input_hash, l2.input_hash);
}

#[test]
fn input_hash_changes_with_size() {
    let config = diagnostic_config();
    let l1 = run_recovery(&[], 100, &config);
    let l2 = run_recovery(&[], 200, &config);
    assert_ne!(l1.input_hash, l2.input_hash);
}

#[test]
fn constants_consistent_with_config_defaults() {
    assert_eq!(DEFAULT_MAX_ATTEMPTS, RecoveryConfig::default().max_attempts);
    assert_eq!(
        DEFAULT_MAX_TOKEN_SKIPS,
        RecoveryConfig::default().max_token_skips
    );
    assert_eq!(
        DEFAULT_MAX_INSERTIONS,
        RecoveryConfig::default().max_insertions
    );
    assert_eq!(
        DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS,
        RecoveryConfig::default().confidence_threshold_millionths
    );
}

// ---------------------------------------------------------------------------
// Adversarial e2e fixture contract (bd-2mds.1.10.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RecoveryAdversarialReplayScenario {
    scenario_id: String,
    command: String,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RecoveryAdversarialError {
    offset: u64,
    message: String,
    tokens_before: u64,
    tokens_after: u64,
    at_statement_boundary: bool,
    candidates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RecoveryAdversarialCase {
    case_id: String,
    family_id: String,
    scenario_id: String,
    mode: String,
    input_bytes: u64,
    max_attempts: u32,
    confidence_threshold_millionths: Option<u64>,
    expected_outcome: String,
    expected_action: String,
    expected_success: bool,
    count_in_success_rate: bool,
    expect_forced_fail_closed: bool,
    error: RecoveryAdversarialError,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RecoveryAdversarialFixture {
    schema_version: String,
    contract_version: String,
    min_success_rate_millionths: u32,
    required_families: Vec<String>,
    required_log_keys: Vec<String>,
    replay_command: String,
    cases: Vec<RecoveryAdversarialCase>,
    replay_scenarios: Vec<RecoveryAdversarialReplayScenario>,
}

fn load_recovery_adversarial_fixture() -> RecoveryAdversarialFixture {
    let path = Path::new("tests/fixtures/parser_error_recovery_adversarial_e2e_v1.json");
    let bytes = fs::read(path).expect("read parser error recovery adversarial fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser error recovery adversarial fixture")
}

fn load_recovery_adversarial_doc() -> String {
    let path = Path::new("../../docs/PARSER_ERROR_RECOVERY_RESYNC_ADVERSARIAL_E2E.md");
    fs::read_to_string(path).expect("read parser error recovery adversarial contract doc")
}

fn fixture_mode(raw: &str) -> RecoveryMode {
    match raw {
        "strict" => RecoveryMode::Strict,
        "diagnostic" => RecoveryMode::Diagnostic,
        "execution" => RecoveryMode::Execution,
        other => panic!("unsupported fixture mode: {other}"),
    }
}

fn fixture_outcome(raw: &str) -> RecoveryOutcome {
    match raw {
        "clean-parse" => RecoveryOutcome::CleanParse,
        "recovered" => RecoveryOutcome::Recovered,
        "partially-recovered" => RecoveryOutcome::PartiallyRecovered,
        "strict-failed" => RecoveryOutcome::StrictFailed,
        "recovery-failed" => RecoveryOutcome::RecoveryFailed,
        "budget-exhausted" => RecoveryOutcome::BudgetExhausted,
        other => panic!("unsupported fixture outcome: {other}"),
    }
}

fn fixture_action(raw: &str) -> RecoveryAction {
    match raw {
        "recover-continue" => RecoveryAction::RecoverContinue,
        "partial-recover" => RecoveryAction::PartialRecover,
        "fail-strict" => RecoveryAction::FailStrict,
        other => panic!("unsupported fixture action: {other}"),
    }
}

fn case_to_error(case: &RecoveryAdversarialCase) -> SyntaxError {
    SyntaxError {
        offset: case.error.offset,
        message: case.error.message.clone(),
        tokens_before: case.error.tokens_before,
        tokens_after: case.error.tokens_after,
        at_statement_boundary: case.error.at_statement_boundary,
        candidates: case.error.candidates.clone(),
    }
}

fn case_to_config(case: &RecoveryAdversarialCase) -> RecoveryConfig {
    let mut config = RecoveryConfig {
        mode: fixture_mode(case.mode.as_str()),
        max_attempts: case.max_attempts,
        ..RecoveryConfig::default()
    };
    if let Some(threshold) = case.confidence_threshold_millionths {
        config.confidence_threshold_millionths = threshold;
    }
    config
}

fn run_fixture_case(case: &RecoveryAdversarialCase) -> DecisionLedger {
    let config = case_to_config(case);
    let error = case_to_error(case);
    run_recovery(&[error], case.input_bytes, &config)
}

fn build_adversarial_log(case: &RecoveryAdversarialCase, ledger: &DecisionLedger) -> Value {
    let error_code = if matches!(
        ledger.outcome,
        RecoveryOutcome::Recovered
            | RecoveryOutcome::PartiallyRecovered
            | RecoveryOutcome::CleanParse
    ) {
        Value::Null
    } else {
        let normalized = case.case_id.replace('-', "_").to_uppercase();
        Value::String(format!("FE-PARSER-ERROR-RECOVERY-{normalized}-0001"))
    };

    json!({
        "schema_version": "franken-engine.parser-error-recovery-adversarial-e2e.event.v1",
        "trace_id": format!("trace-parser-error-recovery-adversarial-{}", case.case_id),
        "decision_id": format!("decision-parser-error-recovery-adversarial-{}", case.case_id),
        "policy_id": "policy-parser-error-recovery-adversarial-e2e-v1",
        "component": "parser_error_recovery_adversarial_e2e_gate",
        "event": "scenario_evaluated",
        "scenario_id": case.scenario_id,
        "case_id": case.case_id,
        "family_id": case.family_id,
        "outcome": if error_code.is_null() { "pass" } else { "fail" },
        "error_code": error_code,
        "ledger_outcome": ledger.outcome.to_string(),
        "selected_action": ledger
            .attempts
            .first()
            .map(|attempt| attempt.action.to_string())
            .unwrap_or_else(|| "none".to_string()),
        "replay_command": format!(
            "PARSER_ERROR_RECOVERY_ADVERSARIAL_SCENARIO={} ./scripts/run_parser_error_recovery_adversarial_e2e.sh test",
            case.scenario_id
        ),
    })
}

#[test]
fn parser_error_recovery_adversarial_e2e_contract_doc_and_fixture_are_well_formed() {
    let fixture = load_recovery_adversarial_fixture();
    let doc = load_recovery_adversarial_doc();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-error-recovery-adversarial-e2e.v1"
    );
    assert_eq!(fixture.contract_version, "1.0.0");
    assert!(!fixture.cases.is_empty());
    assert!(!fixture.replay_scenarios.is_empty());
    assert!(
        fixture.min_success_rate_millionths >= 700_000,
        "minimum success rate should stay high for adversarial e2e coverage"
    );
    assert_eq!(
        fixture.replay_command,
        "./scripts/e2e/parser_error_recovery_adversarial_replay.sh"
    );

    let required_sections = [
        "## Scope",
        "## Contract Version",
        "## Targeted Malformed-Input Families",
        "## Success-Rate and Deterministic Fallback Policy",
        "## Silent Semantic Corruption Guards",
        "## Structured Log Contract",
        "## Deterministic Execution and Replay",
        "## Required Artifacts",
        "## Operator Verification",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing parser error recovery adversarial doc section: {section}"
        );
    }
    assert!(doc.contains("bd-2mds.1.10.2"));
    assert!(doc.contains("./scripts/run_parser_error_recovery_adversarial_e2e.sh ci"));
    assert!(doc.contains("./scripts/e2e/parser_error_recovery_adversarial_replay.sh"));

    let required_log_keys = fixture
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(required_log_keys.contains(key));
    }

    let expected_families = fixture
        .required_families
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let seen_families = fixture
        .cases
        .iter()
        .map(|case| case.family_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(seen_families, expected_families);

    let unique_case_count = fixture
        .cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    assert_eq!(unique_case_count, fixture.cases.len());
}

#[test]
fn parser_error_recovery_adversarial_e2e_cases_are_deterministic_and_success_rate_bounded() {
    let fixture = load_recovery_adversarial_fixture();

    let mut eligible_cases = 0_u64;
    let mut successful_cases = 0_u64;
    for case in &fixture.cases {
        let first = run_fixture_case(case);
        let second = run_fixture_case(case);
        assert_eq!(
            first, second,
            "fixture case is not deterministic: {}",
            case.case_id
        );
        assert_eq!(
            first.outcome,
            fixture_outcome(case.expected_outcome.as_str()),
            "unexpected outcome for case `{}`",
            case.case_id
        );

        let attempt = first
            .attempts
            .first()
            .unwrap_or_else(|| panic!("expected at least one attempt for case `{}`", case.case_id));
        assert_eq!(
            attempt.action,
            fixture_action(case.expected_action.as_str()),
            "unexpected selected action for case `{}`",
            case.case_id
        );
        assert_eq!(
            attempt.succeeded, case.expected_success,
            "unexpected success flag for case `{}`",
            case.case_id
        );

        if case.count_in_success_rate {
            eligible_cases = eligible_cases.saturating_add(1);
            if attempt.succeeded {
                successful_cases = successful_cases.saturating_add(1);
            }
        }
    }

    assert!(
        eligible_cases > 0,
        "at least one case must count in success rate"
    );
    let success_rate_millionths = successful_cases
        .saturating_mul(1_000_000)
        .checked_div(eligible_cases)
        .expect("eligible_cases should not be zero");
    assert!(
        success_rate_millionths >= u64::from(fixture.min_success_rate_millionths),
        "adversarial recovery success rate below contract floor: rate={} minimum={}",
        success_rate_millionths,
        fixture.min_success_rate_millionths
    );
}

#[test]
fn parser_error_recovery_resync_guards_prevent_silent_semantic_corruption() {
    let fixture = load_recovery_adversarial_fixture();

    for case in &fixture.cases {
        let ledger = run_fixture_case(case);
        let attempt = ledger
            .attempts
            .first()
            .unwrap_or_else(|| panic!("expected one attempt for case `{}`", case.case_id));

        match attempt.action {
            RecoveryAction::FailStrict => {
                assert!(
                    attempt.edits.is_empty(),
                    "fail-strict case `{}` must not apply edits",
                    case.case_id
                );
                assert_eq!(
                    ledger.total_edits, 0,
                    "fail-strict case `{}` should report zero edits",
                    case.case_id
                );
                assert!(
                    ledger.repair_diff_hash.is_none(),
                    "fail-strict case `{}` must not publish repair hash",
                    case.case_id
                );
            }
            RecoveryAction::PartialRecover => {
                assert!(
                    !attempt.edits.is_empty(),
                    "partial recover case `{}` should emit skip edits",
                    case.case_id
                );
                for edit in &attempt.edits {
                    assert!(
                        matches!(edit, RepairEdit::Skip { .. }),
                        "partial recover case `{}` emitted non-resync edit kind",
                        case.case_id
                    );
                }
            }
            RecoveryAction::RecoverContinue => {
                assert!(
                    !attempt.edits.is_empty(),
                    "recover-continue case `{}` should emit insert edits",
                    case.case_id
                );
                for edit in &attempt.edits {
                    if let RepairEdit::Insert { token_text, .. } = edit {
                        assert!(
                            case.error
                                .candidates
                                .iter()
                                .any(|candidate| candidate == token_text),
                            "recover-continue case `{}` inserted token outside candidates",
                            case.case_id
                        );
                    } else {
                        panic!(
                            "recover-continue case `{}` emitted non-insert edit",
                            case.case_id
                        );
                    }
                }
            }
        }

        if case.expect_forced_fail_closed {
            let threshold = case
                .confidence_threshold_millionths
                .unwrap_or(DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS);
            assert_eq!(fixture_mode(case.mode.as_str()), RecoveryMode::Execution);
            assert_eq!(attempt.action, RecoveryAction::FailStrict);
            assert!(
                attempt.confidence_millionths < threshold,
                "forced fail-closed case `{}` must have confidence below threshold",
                case.case_id
            );
        }
    }
}

#[test]
fn parser_error_recovery_adversarial_logs_are_structured_and_replayable() {
    let fixture = load_recovery_adversarial_fixture();
    let required_log_keys = fixture
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    let left = fixture
        .cases
        .iter()
        .map(|case| build_adversarial_log(case, &run_fixture_case(case)))
        .collect::<Vec<_>>();
    let right = fixture
        .cases
        .iter()
        .map(|case| build_adversarial_log(case, &run_fixture_case(case)))
        .collect::<Vec<_>>();
    assert_eq!(left, right);

    for event in left {
        for key in &required_log_keys {
            let value = event
                .get(*key)
                .unwrap_or_else(|| panic!("missing required key in structured event: {key}"));
            if *key == "error_code" {
                assert!(value.is_null() || value.as_str().is_some());
            } else {
                assert!(value.as_str().is_some_and(|text| !text.is_empty()));
            }
        }

        let replay_command = event
            .get("replay_command")
            .and_then(Value::as_str)
            .expect("replay command must be a string");
        assert!(
            replay_command.starts_with("PARSER_ERROR_RECOVERY_ADVERSARIAL_SCENARIO="),
            "unexpected replay command prefix: {replay_command}"
        );
        assert!(
            replay_command.contains("./scripts/run_parser_error_recovery_adversarial_e2e.sh test"),
            "unexpected replay command body: {replay_command}"
        );

        let schema_version = event
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version should be present");
        assert!(schema_version.starts_with("franken-engine.parser"));
    }
}

#[test]
fn parser_error_recovery_primitives_respect_resync_edit_bounds() {
    let mut config = diagnostic_config();
    config.max_token_skips = 0;
    // This test targets the skip-bound primitive; force partial-recover selection
    // so it does not drift with global loss-matrix tuning.
    config.loss_matrix.partial_recoverable = 0;
    config.loss_matrix.partial_ambiguous = 0;
    config.loss_matrix.partial_unrecoverable = 0;
    let partial_ledger = run_recovery(&[ambiguous_error()], 120, &config);
    let partial_attempt = partial_ledger
        .attempts
        .first()
        .expect("expected attempt for ambiguous error");
    assert_eq!(partial_attempt.action, RecoveryAction::PartialRecover);
    assert_eq!(partial_attempt.edits.len(), 1);
    match &partial_attempt.edits[0] {
        RepairEdit::Skip { count, .. } => assert_eq!(*count, 0),
        other => panic!("expected skip edit for partial recover, got {:?}", other),
    }

    let recover_ledger = run_recovery(&[simple_error()], 120, &diagnostic_config());
    let recover_attempt = recover_ledger
        .attempts
        .first()
        .expect("expected attempt for simple recoverable error");
    assert_eq!(recover_attempt.action, RecoveryAction::RecoverContinue);
    match &recover_attempt.edits[0] {
        RepairEdit::Insert { token_text, .. } => assert_eq!(token_text, ";"),
        other => panic!("expected insert edit for recover-continue, got {:?}", other),
    }
}
