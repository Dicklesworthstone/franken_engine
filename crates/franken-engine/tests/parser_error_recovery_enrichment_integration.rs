#![forbid(unsafe_code)]
//! Enrichment integration tests for the `parser_error_recovery` module.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::parser_error_recovery::{
    bayesian_update, expected_loss, mode_policy_table, run_recovery, select_action,
    CalibrationReport, DecisionLedger, ErrorState, EvidenceFeatures, ExpectedLosses, LossMatrix,
    ModePolicyEntry, RecoveryAction, RecoveryConfig, RecoveryMode, RecoveryOutcome, RepairEdit,
    StateProbabilities, SyntaxError, COMPONENT, DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS,
    DEFAULT_MAX_ATTEMPTS, DEFAULT_MAX_INSERTIONS, DEFAULT_MAX_TOKEN_SKIPS,
    DEFAULT_PRIOR_AMBIGUOUS_MILLIONTHS, DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS,
    DEFAULT_PRIOR_UNRECOVERABLE_MILLIONTHS, SCHEMA_VERSION,
};

fn simple_error() -> SyntaxError {
    SyntaxError {
        offset: 10,
        message: "expected ';'".into(),
        tokens_before: 5,
        tokens_after: 20,
        at_statement_boundary: true,
        candidates: vec![";".into()],
    }
}

fn ambiguous_error() -> SyntaxError {
    SyntaxError {
        offset: 25,
        message: "unexpected token".into(),
        tokens_before: 10,
        tokens_after: 15,
        at_statement_boundary: false,
        candidates: vec![";".into(), ")".into(), "}".into(), ",".into()],
    }
}

fn unrecoverable_error() -> SyntaxError {
    SyntaxError {
        offset: 50,
        message: "completely garbled".into(),
        tokens_before: 2,
        tokens_after: 0,
        at_statement_boundary: false,
        candidates: vec![],
    }
}

#[test]
fn enrichment_constants_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert!(!SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_default_max_attempts_positive() {
    assert!(DEFAULT_MAX_ATTEMPTS > 0);
}

#[test]
fn enrichment_default_max_token_skips_positive() {
    assert!(DEFAULT_MAX_TOKEN_SKIPS > 0);
}

#[test]
fn enrichment_default_priors_sum_to_one() {
    let total = DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS
        + DEFAULT_PRIOR_AMBIGUOUS_MILLIONTHS
        + DEFAULT_PRIOR_UNRECOVERABLE_MILLIONTHS;
    assert_eq!(total, 1_000_000);
}

#[test]
fn enrichment_recovery_mode_display_all_distinct() {
    let all = [RecoveryMode::Strict, RecoveryMode::Diagnostic, RecoveryMode::Execution];
    let set: BTreeSet<String> = all.iter().map(|m| m.to_string()).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn enrichment_recovery_mode_display_values() {
    assert_eq!(RecoveryMode::Strict.to_string(), "strict");
    assert_eq!(RecoveryMode::Diagnostic.to_string(), "diagnostic");
    assert_eq!(RecoveryMode::Execution.to_string(), "execution");
}

#[test]
fn enrichment_recovery_mode_serde_roundtrip() {
    for m in [RecoveryMode::Strict, RecoveryMode::Diagnostic, RecoveryMode::Execution] {
        let json = serde_json::to_string(&m).unwrap();
        let back: RecoveryMode = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}

#[test]
fn enrichment_recovery_mode_ordering() {
    assert!(RecoveryMode::Strict < RecoveryMode::Diagnostic);
    assert!(RecoveryMode::Diagnostic < RecoveryMode::Execution);
}

#[test]
fn enrichment_error_state_display_all_distinct() {
    let all = [ErrorState::Recoverable, ErrorState::Ambiguous, ErrorState::Unrecoverable];
    let set: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn enrichment_error_state_serde_roundtrip() {
    for s in [ErrorState::Recoverable, ErrorState::Ambiguous, ErrorState::Unrecoverable] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ErrorState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn enrichment_recovery_action_display_all_distinct() {
    let all = [RecoveryAction::RecoverContinue, RecoveryAction::PartialRecover, RecoveryAction::FailStrict];
    let set: BTreeSet<String> = all.iter().map(|a| a.to_string()).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn enrichment_recovery_action_serde_roundtrip() {
    for a in [RecoveryAction::RecoverContinue, RecoveryAction::PartialRecover, RecoveryAction::FailStrict] {
        let json = serde_json::to_string(&a).unwrap();
        let back: RecoveryAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}

#[test]
fn enrichment_recovery_outcome_display_all_distinct() {
    let all = [
        RecoveryOutcome::CleanParse, RecoveryOutcome::Recovered, RecoveryOutcome::PartiallyRecovered,
        RecoveryOutcome::StrictFailed, RecoveryOutcome::RecoveryFailed, RecoveryOutcome::BudgetExhausted,
    ];
    let set: BTreeSet<String> = all.iter().map(|o| o.to_string()).collect();
    assert_eq!(set.len(), all.len());
}

#[test]
fn enrichment_recovery_outcome_serde_roundtrip() {
    for o in [
        RecoveryOutcome::CleanParse, RecoveryOutcome::Recovered, RecoveryOutcome::PartiallyRecovered,
        RecoveryOutcome::StrictFailed, RecoveryOutcome::RecoveryFailed, RecoveryOutcome::BudgetExhausted,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let back: RecoveryOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }
}

#[test]
fn enrichment_repair_edit_display_all_variants() {
    let edits = vec![
        RepairEdit::Insert { offset: 1, token_text: ";".into() },
        RepairEdit::Delete { offset: 2, length: 3 },
        RepairEdit::Replace { offset: 4, length: 5, replacement: "var".into() },
        RepairEdit::Skip { offset: 6, count: 7 },
    ];
    let set: BTreeSet<String> = edits.iter().map(|e| e.to_string()).collect();
    assert_eq!(set.len(), edits.len());
}

#[test]
fn enrichment_repair_edit_serde_all_variants() {
    let edits = vec![
        RepairEdit::Insert { offset: 10, token_text: ";".into() },
        RepairEdit::Delete { offset: 20, length: 3 },
        RepairEdit::Replace { offset: 30, length: 2, replacement: "{}".into() },
        RepairEdit::Skip { offset: 40, count: 5 },
    ];
    for e in &edits {
        let json = serde_json::to_string(e).unwrap();
        let back: RepairEdit = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn enrichment_state_probabilities_default_valid() {
    let sp = StateProbabilities::default();
    assert!(sp.is_valid());
    assert_eq!(sp.most_likely(), ErrorState::Recoverable);
}

#[test]
fn enrichment_state_probabilities_confidence_returns_max() {
    let sp = StateProbabilities { recoverable: 100_000, ambiguous: 700_000, unrecoverable: 200_000 };
    assert_eq!(sp.confidence(), 700_000);
}

#[test]
fn enrichment_state_probabilities_most_likely_each_extreme() {
    assert_eq!((StateProbabilities { recoverable: 900_000, ambiguous: 50_000, unrecoverable: 50_000 }).most_likely(), ErrorState::Recoverable);
    assert_eq!((StateProbabilities { recoverable: 50_000, ambiguous: 900_000, unrecoverable: 50_000 }).most_likely(), ErrorState::Ambiguous);
    assert_eq!((StateProbabilities { recoverable: 50_000, ambiguous: 50_000, unrecoverable: 900_000 }).most_likely(), ErrorState::Unrecoverable);
}

#[test]
fn enrichment_state_probabilities_serde_roundtrip() {
    let sp = StateProbabilities::default();
    let json = serde_json::to_string(&sp).unwrap();
    let back: StateProbabilities = serde_json::from_str(&json).unwrap();
    assert_eq!(sp, back);
}

#[test]
fn enrichment_bayesian_update_deterministic() {
    let prior = StateProbabilities::default();
    let evidence = EvidenceFeatures {
        tokens_before_error: 5, tokens_after_error: 20, error_offset: 10,
        at_statement_boundary: true, single_token_fix: true, single_token_delete: true,
        candidate_count: 1, features_hash: ContentHash::compute(b"test"),
    };
    let p1 = bayesian_update(&prior, &evidence);
    let p2 = bayesian_update(&prior, &evidence);
    assert_eq!(p1, p2);
}

#[test]
fn enrichment_bayesian_update_strong_recovery_evidence() {
    let prior = StateProbabilities::default();
    let evidence = EvidenceFeatures {
        tokens_before_error: 50, tokens_after_error: 100, error_offset: 200,
        at_statement_boundary: true, single_token_fix: true, single_token_delete: true,
        candidate_count: 1, features_hash: ContentHash::compute(b"strong"),
    };
    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.recoverable > prior.recoverable);
    assert_eq!(posterior.most_likely(), ErrorState::Recoverable);
}

#[test]
fn enrichment_bayesian_update_zero_priors_fallback() {
    let prior = StateProbabilities { recoverable: 0, ambiguous: 0, unrecoverable: 0 };
    let evidence = EvidenceFeatures {
        tokens_before_error: 5, tokens_after_error: 20, error_offset: 10,
        at_statement_boundary: true, single_token_fix: true, single_token_delete: true,
        candidate_count: 1, features_hash: ContentHash::compute(b"zero"),
    };
    let posterior = bayesian_update(&prior, &evidence);
    assert!(posterior.is_valid());
}

#[test]
fn enrichment_loss_matrix_default_serde_roundtrip() {
    let m = LossMatrix::default();
    let json = serde_json::to_string(&m).unwrap();
    let back: LossMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn enrichment_expected_loss_zero_probabilities() {
    let posterior = StateProbabilities { recoverable: 0, ambiguous: 0, unrecoverable: 0 };
    let loss = expected_loss(RecoveryAction::RecoverContinue, &posterior, &LossMatrix::default());
    assert_eq!(loss, 0);
}

#[test]
fn enrichment_select_action_fully_recoverable() {
    let posterior = StateProbabilities { recoverable: 1_000_000, ambiguous: 0, unrecoverable: 0 };
    assert_eq!(select_action(&posterior, &LossMatrix::default()), RecoveryAction::RecoverContinue);
}

#[test]
fn enrichment_select_action_fully_unrecoverable() {
    let posterior = StateProbabilities { recoverable: 0, ambiguous: 0, unrecoverable: 1_000_000 };
    assert_eq!(select_action(&posterior, &LossMatrix::default()), RecoveryAction::FailStrict);
}

#[test]
fn enrichment_recovery_config_default() {
    let config = RecoveryConfig::default();
    assert_eq!(config.mode, RecoveryMode::Strict);
    assert_eq!(config.max_attempts, DEFAULT_MAX_ATTEMPTS);
    assert_eq!(config.max_token_skips, DEFAULT_MAX_TOKEN_SKIPS);
    assert_eq!(config.max_insertions, DEFAULT_MAX_INSERTIONS);
    assert_eq!(config.confidence_threshold_millionths, DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS);
    assert!(config.prior.is_valid());
}

#[test]
fn enrichment_recovery_config_serde_roundtrip() {
    let config = RecoveryConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: RecoveryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_run_recovery_no_errors_clean() {
    let config = RecoveryConfig { mode: RecoveryMode::Diagnostic, ..RecoveryConfig::default() };
    let ledger = run_recovery(&[], 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::CleanParse);
    assert!(ledger.attempts.is_empty());
    assert_eq!(ledger.total_edits, 0);
}

#[test]
fn enrichment_run_recovery_strict_mode_no_attempts() {
    let config = RecoveryConfig::default();
    let ledger = run_recovery(&[simple_error()], 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::StrictFailed);
    assert!(ledger.attempts.is_empty());
}

#[test]
fn enrichment_run_recovery_diagnostic_simple() {
    let config = RecoveryConfig { mode: RecoveryMode::Diagnostic, ..RecoveryConfig::default() };
    let ledger = run_recovery(&[simple_error()], 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::Recovered);
    assert!(ledger.total_edits > 0);
    assert!(ledger.repair_diff_hash.is_some());
}

#[test]
fn enrichment_run_recovery_budget_exhaustion() {
    let config = RecoveryConfig { mode: RecoveryMode::Diagnostic, max_attempts: 1, ..RecoveryConfig::default() };
    let ledger = run_recovery(&[simple_error(), simple_error()], 100, &config);
    assert_eq!(ledger.outcome, RecoveryOutcome::BudgetExhausted);
    assert_eq!(ledger.attempts.len(), 1);
}

#[test]
fn enrichment_run_recovery_execution_high_threshold_gates() {
    let config = RecoveryConfig { mode: RecoveryMode::Execution, confidence_threshold_millionths: 999_000, ..RecoveryConfig::default() };
    let ledger = run_recovery(&[ambiguous_error()], 100, &config);
    assert_eq!(ledger.attempts[0].action, RecoveryAction::FailStrict);
}

#[test]
fn enrichment_run_recovery_deterministic() {
    let config = RecoveryConfig { mode: RecoveryMode::Diagnostic, ..RecoveryConfig::default() };
    let l1 = run_recovery(&[simple_error()], 100, &config);
    let l2 = run_recovery(&[simple_error()], 100, &config);
    assert_eq!(l1.outcome, l2.outcome);
    assert_eq!(l1.total_edits, l2.total_edits);
}

#[test]
fn enrichment_run_recovery_mixed_errors() {
    let config = RecoveryConfig { mode: RecoveryMode::Diagnostic, ..RecoveryConfig::default() };
    let ledger = run_recovery(&[simple_error(), ambiguous_error(), unrecoverable_error()], 200, &config);
    assert_eq!(ledger.attempts.len(), 3);
}

#[test]
fn enrichment_decision_ledger_serde_roundtrip() {
    let config = RecoveryConfig { mode: RecoveryMode::Diagnostic, ..RecoveryConfig::default() };
    let ledger = run_recovery(&[simple_error()], 100, &config);
    let json = serde_json::to_string(&ledger).unwrap();
    let back: DecisionLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn enrichment_decision_ledger_schema_version() {
    let config = RecoveryConfig { mode: RecoveryMode::Diagnostic, ..RecoveryConfig::default() };
    let ledger = run_recovery(&[], 100, &config);
    assert_eq!(ledger.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_calibration_report_compute() {
    let report = CalibrationReport::compute(80, 5, 90, 10, 800_000);
    assert_eq!(report.total_cases, 185);
    assert!(report.false_positive_rate_millionths > 0);
    assert!(report.false_negative_rate_millionths > 0);
}

#[test]
fn enrichment_calibration_report_zero_actuals() {
    let report = CalibrationReport::compute(0, 0, 0, 0, 800_000);
    assert_eq!(report.total_cases, 0);
    assert_eq!(report.false_positive_rate_millionths, 0);
    assert_eq!(report.false_negative_rate_millionths, 0);
}

#[test]
fn enrichment_calibration_report_serde_roundtrip() {
    let report = CalibrationReport::compute(50, 3, 40, 7, 800_000);
    let json = serde_json::to_string(&report).unwrap();
    let back: CalibrationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_calibration_report_operating_point_id() {
    let report = CalibrationReport::compute(10, 1, 10, 1, 750_000);
    assert_eq!(report.operating_point_id, "threshold-750000");
}

#[test]
fn enrichment_mode_policy_table_three_entries() {
    assert_eq!(mode_policy_table().len(), 3);
}

#[test]
fn enrichment_mode_policy_strict_no_edits() {
    let table = mode_policy_table();
    let strict = table.iter().find(|e| e.mode == RecoveryMode::Strict).unwrap();
    assert!(!strict.edits_applied);
    assert!(!strict.execution_uses_recovery);
}

#[test]
fn enrichment_mode_policy_execution_safety() {
    let table = mode_policy_table();
    let exec = table.iter().find(|e| e.mode == RecoveryMode::Execution).unwrap();
    assert!(exec.execution_uses_recovery);
    assert!(exec.min_confidence_millionths > 0);
    assert!(exec.max_fpr_millionths <= 20_000);
}

#[test]
fn enrichment_mode_policy_serde_roundtrip() {
    let table = mode_policy_table();
    let json = serde_json::to_string(&table).unwrap();
    let back: Vec<ModePolicyEntry> = serde_json::from_str(&json).unwrap();
    assert_eq!(table, back);
}

#[test]
fn enrichment_evidence_features_with_hash_deterministic() {
    let e1 = EvidenceFeatures {
        tokens_before_error: 10, tokens_after_error: 20, error_offset: 100,
        at_statement_boundary: true, single_token_fix: false, single_token_delete: false,
        candidate_count: 2, features_hash: ContentHash::compute(b"a"),
    }.with_hash();
    let e2 = EvidenceFeatures {
        tokens_before_error: 10, tokens_after_error: 20, error_offset: 100,
        at_statement_boundary: true, single_token_fix: false, single_token_delete: false,
        candidate_count: 2, features_hash: ContentHash::compute(b"b"),
    }.with_hash();
    assert_eq!(e1.features_hash, e2.features_hash);
}

#[test]
fn enrichment_evidence_features_serde_roundtrip() {
    let e = EvidenceFeatures {
        tokens_before_error: 5, tokens_after_error: 10, error_offset: 50,
        at_statement_boundary: false, single_token_fix: true, single_token_delete: false,
        candidate_count: 3, features_hash: ContentHash::compute(b"serde-test"),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: EvidenceFeatures = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_syntax_error_serde_roundtrip() {
    let err = simple_error();
    let json = serde_json::to_string(&err).unwrap();
    let back: SyntaxError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_expected_losses_serde_roundtrip() {
    let el = ExpectedLosses { recover_continue: 5, partial_recover: 12, fail_strict: 8 };
    let json = serde_json::to_string(&el).unwrap();
    let back: ExpectedLosses = serde_json::from_str(&json).unwrap();
    assert_eq!(el, back);
}
