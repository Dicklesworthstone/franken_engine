#![forbid(unsafe_code)]
//! Conformance tests for parser error recovery contracts.

use frankenengine_engine::parser_error_recovery::{
    DecisionLedger, LossMatrix, RecoveryAction, RecoveryConfig, RecoveryMode, RecoveryOutcome,
    RepairEdit, SCHEMA_VERSION, SyntaxError, run_recovery,
};

fn diagnostic_config() -> RecoveryConfig {
    RecoveryConfig {
        mode: RecoveryMode::Diagnostic,
        ..RecoveryConfig::default()
    }
}

fn partial_preferred_config() -> RecoveryConfig {
    RecoveryConfig {
        mode: RecoveryMode::Diagnostic,
        loss_matrix: LossMatrix {
            recover_recoverable: 100,
            recover_ambiguous: 100,
            recover_unrecoverable: 100,
            partial_recoverable: 0,
            partial_ambiguous: 0,
            partial_unrecoverable: 0,
            fail_recoverable: 100,
            fail_ambiguous: 100,
            fail_unrecoverable: 100,
        },
        ..RecoveryConfig::default()
    }
}

fn semicolon_error(offset: u64) -> SyntaxError {
    SyntaxError {
        offset,
        message: "expected ';' after statement".to_string(),
        tokens_before: 4,
        tokens_after: 6,
        at_statement_boundary: true,
        candidates: vec![";".to_string()],
    }
}

fn ambiguous_expression_error(offset: u64) -> SyntaxError {
    SyntaxError {
        offset,
        message: "unexpected expression terminator".to_string(),
        tokens_before: 9,
        tokens_after: 5,
        at_statement_boundary: false,
        candidates: vec![
            ")".to_string(),
            "}".to_string(),
            ",".to_string(),
            ";".to_string(),
        ],
    }
}

fn unrecoverable_error(offset: u64) -> SyntaxError {
    SyntaxError {
        offset,
        message: "unterminated nested grammar fragment".to_string(),
        tokens_before: 2,
        tokens_after: 0,
        at_statement_boundary: false,
        candidates: Vec::new(),
    }
}

#[test]
fn conformance_clean_input_emits_clean_parse_without_attempts() {
    let ledger = run_recovery(&[], 128, &diagnostic_config());

    assert_eq!(ledger.schema_version, SCHEMA_VERSION);
    assert_eq!(ledger.outcome, RecoveryOutcome::CleanParse);
    assert!(ledger.attempts.is_empty());
    assert_eq!(ledger.total_edits, 0);
}

#[test]
fn conformance_strict_mode_fails_malformed_input_without_recovery_attempts() {
    let ledger = run_recovery(&[semicolon_error(12)], 128, &RecoveryConfig::default());

    assert_eq!(ledger.outcome, RecoveryOutcome::StrictFailed);
    assert!(ledger.attempts.is_empty());
    assert_eq!(ledger.total_edits, 0);
    assert!(ledger.repair_diff_hash.is_none());
}

#[test]
fn conformance_single_token_malformed_input_recovers_with_insert_edit() {
    let ledger = run_recovery(&[semicolon_error(17)], 128, &diagnostic_config());
    let attempt = &ledger.attempts[0];

    assert_eq!(ledger.outcome, RecoveryOutcome::Recovered);
    assert_eq!(attempt.action, RecoveryAction::RecoverContinue);
    assert!(attempt.succeeded);
    assert_eq!(
        attempt.edits,
        vec![RepairEdit::Insert {
            offset: 17,
            token_text: ";".to_string(),
        }]
    );
}

#[test]
fn conformance_syntax_error_reporting_round_trips_message_and_position() {
    let error = semicolon_error(23);
    let json = serde_json::to_string(&error).expect("serialize syntax error");
    let restored: SyntaxError = serde_json::from_str(&json).expect("deserialize syntax error");

    assert_eq!(restored.message, "expected ';' after statement");
    assert_eq!(restored.offset, 23);
    assert_eq!(restored.tokens_before, 4);
    assert_eq!(restored.tokens_after, 6);
    assert_eq!(restored.candidates, vec![";".to_string()]);
}

#[test]
fn conformance_error_position_is_preserved_in_evidence_features() {
    let ledger = run_recovery(&[ambiguous_expression_error(41)], 256, &diagnostic_config());
    let attempt = &ledger.attempts[0];

    assert_eq!(attempt.evidence.error_offset, 41);
    assert_eq!(attempt.evidence.tokens_before_error, 9);
    assert_eq!(attempt.evidence.tokens_after_error, 5);
}

#[test]
fn conformance_insert_repair_uses_original_error_offset() {
    let ledger = run_recovery(&[semicolon_error(64)], 256, &diagnostic_config());

    match &ledger.attempts[0].edits[0] {
        RepairEdit::Insert { offset, token_text } => {
            assert_eq!(*offset, 64);
            assert_eq!(token_text, ";");
        }
        other => panic!("expected insert edit, got {other:?}"),
    }
}

#[test]
fn conformance_partial_parse_continuation_skips_at_error_offset() {
    let ledger = run_recovery(
        &[ambiguous_expression_error(88)],
        256,
        &partial_preferred_config(),
    );
    let attempt = &ledger.attempts[0];

    assert_eq!(ledger.outcome, RecoveryOutcome::Recovered);
    assert_eq!(attempt.action, RecoveryAction::PartialRecover);
    assert_eq!(
        attempt.edits,
        vec![RepairEdit::Skip {
            offset: 88,
            count: 1,
        }]
    );
}

#[test]
fn conformance_partial_recovery_continues_after_mixed_malformed_inputs() {
    let ledger = run_recovery(
        &[semicolon_error(10), unrecoverable_error(92)],
        512,
        &diagnostic_config(),
    );

    assert_eq!(ledger.outcome, RecoveryOutcome::PartiallyRecovered);
    assert_eq!(ledger.attempts.len(), 2);
    assert!(ledger.attempts[0].succeeded);
    assert!(!ledger.attempts[1].succeeded);
}

#[test]
fn conformance_attempt_dispatch_order_matches_input_error_order() {
    let ledger = run_recovery(
        &[
            semicolon_error(11),
            ambiguous_expression_error(22),
            semicolon_error(33),
        ],
        512,
        &diagnostic_config(),
    );

    let offsets: Vec<u64> = ledger
        .attempts
        .iter()
        .map(|attempt| attempt.evidence.error_offset)
        .collect();
    let indexes: Vec<u32> = ledger
        .attempts
        .iter()
        .map(|attempt| attempt.attempt_index)
        .collect();
    assert_eq!(offsets, vec![11, 22, 33]);
    assert_eq!(indexes, vec![0, 1, 2]);
}

#[test]
fn conformance_budget_exhaustion_retains_completed_attempt_prefix() {
    let config = RecoveryConfig {
        mode: RecoveryMode::Diagnostic,
        max_attempts: 2,
        ..RecoveryConfig::default()
    };
    let ledger = run_recovery(
        &[semicolon_error(1), semicolon_error(2), semicolon_error(3)],
        512,
        &config,
    );

    assert_eq!(ledger.outcome, RecoveryOutcome::BudgetExhausted);
    assert_eq!(ledger.attempts.len(), 2);
    assert_eq!(ledger.attempts[0].evidence.error_offset, 1);
    assert_eq!(ledger.attempts[1].evidence.error_offset, 2);
}

#[test]
fn conformance_evidence_emission_records_losses_and_rejected_actions() {
    let ledger = run_recovery(&[semicolon_error(19)], 256, &diagnostic_config());
    let attempt = &ledger.attempts[0];

    assert_eq!(attempt.rejected_actions.len(), 2);
    assert!(attempt.expected_losses.recover_continue <= attempt.expected_losses.partial_recover);
    assert!(attempt.expected_losses.recover_continue <= attempt.expected_losses.fail_strict);
    assert!(attempt.confidence_millionths > 0);
}

#[test]
fn conformance_replay_equivalence_for_identical_inputs() {
    let errors = [semicolon_error(31), ambiguous_expression_error(47)];
    let first: DecisionLedger = run_recovery(&errors, 1024, &diagnostic_config());
    let second: DecisionLedger = run_recovery(&errors, 1024, &diagnostic_config());
    let encoded = serde_json::to_string(&first).expect("serialize decision ledger");
    let replayed: DecisionLedger = serde_json::from_str(&encoded).expect("deserialize ledger");

    assert_eq!(first, second);
    assert_eq!(first, replayed);
}
