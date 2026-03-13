//! Enrichment integration tests for the `parser_error_recovery` module.
//!
//! Covers: RecoveryMode/ErrorState/RecoveryAction/RecoveryOutcome ordering/
//! Copy/Hash/Display/serde, StateProbabilities is_valid/most_likely/confidence/
//! default, bayesian_update evidence effects, LossMatrix default, expected_loss
//! computation, select_action, RepairEdit Display all variants, RecoveryConfig
//! default, SyntaxError serde, run_recovery clean/strict/diagnostic paths,
//! constants, Debug formatting.

#![forbid(unsafe_code)]
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
use frankenengine_engine::parser_error_recovery::{
    ErrorState, EvidenceFeatures, LossMatrix, RecoveryAction, RecoveryConfig, RecoveryMode,
    RecoveryOutcome, RepairEdit, StateProbabilities, SyntaxError,
    bayesian_update, expected_loss, run_recovery, select_action,
    COMPONENT, DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS, DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_INSERTIONS, DEFAULT_MAX_TOKEN_SKIPS, DEFAULT_PRIOR_AMBIGUOUS_MILLIONTHS,
    DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS, DEFAULT_PRIOR_UNRECOVERABLE_MILLIONTHS,
    SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_evidence() -> EvidenceFeatures {
    EvidenceFeatures {
        tokens_before_error: 10,
        tokens_after_error: 50,
        error_offset: 100,
        at_statement_boundary: false,
        single_token_fix: false,
        single_token_delete: false,
        candidate_count: 1,
        features_hash: ContentHash::compute(b"placeholder"),
    }
}

// =========================================================================
// A. RecoveryMode — ordering, Copy, Hash, Display, serde
// =========================================================================

#[test]
fn enrichment_recovery_mode_ordering() {
    assert!(RecoveryMode::Strict < RecoveryMode::Diagnostic);
    assert!(RecoveryMode::Diagnostic < RecoveryMode::Execution);
}

#[test]
fn enrichment_recovery_mode_copy() {
    let m = RecoveryMode::Diagnostic;
    let m2 = m;
    assert_eq!(m, m2);
}

#[test]
fn enrichment_recovery_mode_display_all_distinct() {
    let all = [
        RecoveryMode::Strict,
        RecoveryMode::Diagnostic,
        RecoveryMode::Execution,
    ];
    let strings: BTreeSet<String> = all.iter().map(|m| m.to_string()).collect();
    assert_eq!(strings.len(), 3);
}

#[test]
fn enrichment_recovery_mode_serde_all() {
    let all = [
        RecoveryMode::Strict,
        RecoveryMode::Diagnostic,
        RecoveryMode::Execution,
    ];
    for m in all {
        let json = serde_json::to_string(&m).unwrap();
        let restored: RecoveryMode = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }
}

// =========================================================================
// B. ErrorState — ordering, Copy, Hash, Display, serde
// =========================================================================

#[test]
fn enrichment_error_state_ordering() {
    assert!(ErrorState::Recoverable < ErrorState::Ambiguous);
    assert!(ErrorState::Ambiguous < ErrorState::Unrecoverable);
}

#[test]
fn enrichment_error_state_display_all_distinct() {
    let all = [
        ErrorState::Recoverable,
        ErrorState::Ambiguous,
        ErrorState::Unrecoverable,
    ];
    let strings: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(strings.len(), 3);
}

#[test]
fn enrichment_error_state_serde_all() {
    for s in [
        ErrorState::Recoverable,
        ErrorState::Ambiguous,
        ErrorState::Unrecoverable,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let restored: ErrorState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, restored);
    }
}

// =========================================================================
// C. RecoveryAction — ordering, Copy, Hash, Display, serde
// =========================================================================

#[test]
fn enrichment_recovery_action_ordering() {
    assert!(RecoveryAction::RecoverContinue < RecoveryAction::PartialRecover);
    assert!(RecoveryAction::PartialRecover < RecoveryAction::FailStrict);
}

#[test]
fn enrichment_recovery_action_display_all_distinct() {
    let all = [
        RecoveryAction::RecoverContinue,
        RecoveryAction::PartialRecover,
        RecoveryAction::FailStrict,
    ];
    let strings: BTreeSet<String> = all.iter().map(|a| a.to_string()).collect();
    assert_eq!(strings.len(), 3);
}

#[test]
fn enrichment_recovery_action_serde_all() {
    for a in [
        RecoveryAction::RecoverContinue,
        RecoveryAction::PartialRecover,
        RecoveryAction::FailStrict,
    ] {
        let json = serde_json::to_string(&a).unwrap();
        let restored: RecoveryAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, restored);
    }
}

// =========================================================================
// D. RecoveryOutcome — ordering, Display, serde
// =========================================================================

#[test]
fn enrichment_recovery_outcome_ordering() {
    assert!(RecoveryOutcome::CleanParse < RecoveryOutcome::Recovered);
    assert!(RecoveryOutcome::Recovered < RecoveryOutcome::PartiallyRecovered);
    assert!(RecoveryOutcome::PartiallyRecovered < RecoveryOutcome::StrictFailed);
    assert!(RecoveryOutcome::StrictFailed < RecoveryOutcome::RecoveryFailed);
    assert!(RecoveryOutcome::RecoveryFailed < RecoveryOutcome::BudgetExhausted);
}

#[test]
fn enrichment_recovery_outcome_display_all_distinct() {
    let all = [
        RecoveryOutcome::CleanParse,
        RecoveryOutcome::Recovered,
        RecoveryOutcome::PartiallyRecovered,
        RecoveryOutcome::StrictFailed,
        RecoveryOutcome::RecoveryFailed,
        RecoveryOutcome::BudgetExhausted,
    ];
    let strings: BTreeSet<String> = all.iter().map(|o| o.to_string()).collect();
    assert_eq!(strings.len(), 6);
}

#[test]
fn enrichment_recovery_outcome_serde_all() {
    let all = [
        RecoveryOutcome::CleanParse,
        RecoveryOutcome::Recovered,
        RecoveryOutcome::PartiallyRecovered,
        RecoveryOutcome::StrictFailed,
        RecoveryOutcome::RecoveryFailed,
        RecoveryOutcome::BudgetExhausted,
    ];
    for o in all {
        let json = serde_json::to_string(&o).unwrap();
        let restored: RecoveryOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, restored);
    }
}

// =========================================================================
// E. StateProbabilities — is_valid, most_likely, confidence, default
// =========================================================================

#[test]
fn enrichment_state_probabilities_default_is_valid() {
    let sp = StateProbabilities::default();
    assert!(sp.is_valid());
    assert_eq!(sp.recoverable, DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS);
    assert_eq!(sp.ambiguous, DEFAULT_PRIOR_AMBIGUOUS_MILLIONTHS);
    assert_eq!(sp.unrecoverable, DEFAULT_PRIOR_UNRECOVERABLE_MILLIONTHS);
}

#[test]
fn enrichment_state_probabilities_invalid_sum() {
    let sp = StateProbabilities {
        recoverable: 500_000,
        ambiguous: 300_000,
        unrecoverable: 100_000,
    };
    assert!(!sp.is_valid()); // sums to 900_000
}

#[test]
fn enrichment_state_probabilities_most_likely_recoverable() {
    let sp = StateProbabilities {
        recoverable: 700_000,
        ambiguous: 200_000,
        unrecoverable: 100_000,
    };
    assert_eq!(sp.most_likely(), ErrorState::Recoverable);
    assert_eq!(sp.confidence(), 700_000);
}

#[test]
fn enrichment_state_probabilities_most_likely_ambiguous() {
    let sp = StateProbabilities {
        recoverable: 200_000,
        ambiguous: 600_000,
        unrecoverable: 200_000,
    };
    assert_eq!(sp.most_likely(), ErrorState::Ambiguous);
}

#[test]
fn enrichment_state_probabilities_most_likely_unrecoverable() {
    let sp = StateProbabilities {
        recoverable: 100_000,
        ambiguous: 200_000,
        unrecoverable: 700_000,
    };
    assert_eq!(sp.most_likely(), ErrorState::Unrecoverable);
    assert_eq!(sp.confidence(), 700_000);
}

#[test]
fn enrichment_state_probabilities_serde() {
    let sp = StateProbabilities {
        recoverable: 500_000,
        ambiguous: 300_000,
        unrecoverable: 200_000,
    };
    let json = serde_json::to_string(&sp).unwrap();
    let restored: StateProbabilities = serde_json::from_str(&json).unwrap();
    assert_eq!(sp, restored);
}

// =========================================================================
// F. bayesian_update — evidence effects
// =========================================================================

#[test]
fn enrichment_bayesian_update_statement_boundary_boosts_recoverable() {
    let prior = StateProbabilities::default();
    let mut ev = default_evidence();
    ev.at_statement_boundary = true;
    let posterior = bayesian_update(&prior, &ev);
    assert!(posterior.is_valid());
    assert!(posterior.recoverable > prior.recoverable);
}

#[test]
fn enrichment_bayesian_update_single_token_fix_boosts_recoverable() {
    let prior = StateProbabilities::default();
    let mut ev = default_evidence();
    ev.single_token_fix = true;
    let posterior = bayesian_update(&prior, &ev);
    assert!(posterior.is_valid());
    assert!(posterior.recoverable > prior.recoverable);
}

#[test]
fn enrichment_bayesian_update_many_candidates_boosts_ambiguous() {
    let prior = StateProbabilities::default();
    let mut ev = default_evidence();
    ev.candidate_count = 5; // > 3
    let posterior = bayesian_update(&prior, &ev);
    assert!(posterior.is_valid());
    assert!(posterior.ambiguous > prior.ambiguous);
}

#[test]
fn enrichment_bayesian_update_zero_candidates_boosts_unrecoverable() {
    let prior = StateProbabilities::default();
    let mut ev = default_evidence();
    ev.candidate_count = 0;
    let posterior = bayesian_update(&prior, &ev);
    assert!(posterior.is_valid());
    assert!(posterior.unrecoverable > prior.unrecoverable);
}

#[test]
fn enrichment_bayesian_update_neutral_evidence_near_prior() {
    let prior = StateProbabilities::default();
    let ev = default_evidence(); // no special flags
    let posterior = bayesian_update(&prior, &ev);
    assert!(posterior.is_valid());
    // With neutral evidence, posterior should approximately equal prior.
    let delta_rec = (posterior.recoverable as i64 - prior.recoverable as i64).unsigned_abs();
    assert!(delta_rec < 50_000, "delta_rec={delta_rec}");
}

// =========================================================================
// G. expected_loss and select_action
// =========================================================================

#[test]
fn enrichment_expected_loss_values() {
    let posterior = StateProbabilities {
        recoverable: 950_000,
        ambiguous: 25_000,
        unrecoverable: 25_000,
    };
    let matrix = LossMatrix::default();

    let el_rec = expected_loss(RecoveryAction::RecoverContinue, &posterior, &matrix);
    let el_partial = expected_loss(RecoveryAction::PartialRecover, &posterior, &matrix);
    let el_fail = expected_loss(RecoveryAction::FailStrict, &posterior, &matrix);

    // With high P(recoverable), RecoverContinue should have lowest expected loss.
    assert!(el_rec < el_partial);
    assert!(el_rec < el_fail);
}

#[test]
fn enrichment_select_action_high_recoverable() {
    let posterior = StateProbabilities {
        recoverable: 950_000,
        ambiguous: 25_000,
        unrecoverable: 25_000,
    };
    let matrix = LossMatrix::default();
    assert_eq!(
        select_action(&posterior, &matrix),
        RecoveryAction::RecoverContinue
    );
}

#[test]
fn enrichment_select_action_high_unrecoverable() {
    let posterior = StateProbabilities {
        recoverable: 50_000,
        ambiguous: 100_000,
        unrecoverable: 850_000,
    };
    let matrix = LossMatrix::default();
    assert_eq!(
        select_action(&posterior, &matrix),
        RecoveryAction::FailStrict
    );
}

// =========================================================================
// H. RepairEdit Display
// =========================================================================

#[test]
fn enrichment_repair_edit_display_insert() {
    let e = RepairEdit::Insert {
        offset: 42,
        token_text: ";".into(),
    };
    let s = e.to_string();
    assert!(s.contains("insert"));
    assert!(s.contains("42"));
    assert!(s.contains(";"));
}

#[test]
fn enrichment_repair_edit_display_delete() {
    let e = RepairEdit::Delete {
        offset: 10,
        length: 5,
    };
    let s = e.to_string();
    assert!(s.contains("delete"));
    assert!(s.contains("10"));
}

#[test]
fn enrichment_repair_edit_display_replace() {
    let e = RepairEdit::Replace {
        offset: 20,
        length: 3,
        replacement: "let".into(),
    };
    let s = e.to_string();
    assert!(s.contains("replace"));
    assert!(s.contains("let"));
}

#[test]
fn enrichment_repair_edit_display_skip() {
    let e = RepairEdit::Skip {
        offset: 0,
        count: 3,
    };
    let s = e.to_string();
    assert!(s.contains("skip"));
    assert!(s.contains("3"));
}

#[test]
fn enrichment_repair_edit_serde_all_variants() {
    let variants = [
        RepairEdit::Insert {
            offset: 10,
            token_text: ";".into(),
        },
        RepairEdit::Delete {
            offset: 20,
            length: 5,
        },
        RepairEdit::Replace {
            offset: 30,
            length: 3,
            replacement: "let".into(),
        },
        RepairEdit::Skip {
            offset: 40,
            count: 2,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: RepairEdit = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// =========================================================================
// I. RecoveryConfig default
// =========================================================================

#[test]
fn enrichment_recovery_config_default_values() {
    let cfg = RecoveryConfig::default();
    assert_eq!(cfg.mode, RecoveryMode::Strict);
    assert_eq!(cfg.max_attempts, DEFAULT_MAX_ATTEMPTS);
    assert_eq!(cfg.max_token_skips, DEFAULT_MAX_TOKEN_SKIPS);
    assert_eq!(cfg.max_insertions, DEFAULT_MAX_INSERTIONS);
    assert_eq!(
        cfg.confidence_threshold_millionths,
        DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS
    );
    assert!(cfg.prior.is_valid());
}

#[test]
fn enrichment_recovery_config_serde() {
    let cfg = RecoveryConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: RecoveryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// =========================================================================
// J. run_recovery — clean parse, strict mode
// =========================================================================

#[test]
fn enrichment_run_recovery_clean_parse() {
    let cfg = RecoveryConfig::default();
    let ledger = run_recovery(&[], 100, &cfg);
    assert_eq!(ledger.outcome, RecoveryOutcome::CleanParse);
    assert!(ledger.attempts.is_empty());
    assert_eq!(ledger.total_edits, 0);
}

#[test]
fn enrichment_run_recovery_strict_mode_fails() {
    let cfg = RecoveryConfig::default(); // mode = Strict
    let errors = vec![SyntaxError {
        offset: 50,
        message: "unexpected token".into(),
        tokens_before: 10,
        tokens_after: 40,
        at_statement_boundary: false,
        candidates: vec![],
    }];
    let ledger = run_recovery(&errors, 100, &cfg);
    assert_eq!(ledger.outcome, RecoveryOutcome::StrictFailed);
}

#[test]
fn enrichment_run_recovery_diagnostic_mode() {
    let mut cfg = RecoveryConfig::default();
    cfg.mode = RecoveryMode::Diagnostic;
    let errors = vec![SyntaxError {
        offset: 50,
        message: "unexpected token".into(),
        tokens_before: 10,
        tokens_after: 40,
        at_statement_boundary: true,
        candidates: vec!["let".into()],
    }];
    let ledger = run_recovery(&errors, 100, &cfg);
    // Diagnostic mode should produce attempts.
    assert!(!ledger.attempts.is_empty());
    assert_eq!(ledger.mode, RecoveryMode::Diagnostic);
}

// =========================================================================
// K. EvidenceFeatures with_hash
// =========================================================================

#[test]
fn enrichment_evidence_features_with_hash_deterministic() {
    let ev1 = default_evidence().with_hash();
    let ev2 = default_evidence().with_hash();
    assert_eq!(ev1.features_hash, ev2.features_hash);
}

#[test]
fn enrichment_evidence_features_with_hash_changes_on_different_input() {
    let ev1 = default_evidence().with_hash();
    let mut ev2_pre = default_evidence();
    ev2_pre.candidate_count = 99;
    let ev2 = ev2_pre.with_hash();
    assert_ne!(ev1.features_hash, ev2.features_hash);
}

// =========================================================================
// L. Constants
// =========================================================================

#[test]
fn enrichment_constants_correct() {
    assert!(!COMPONENT.is_empty());
    assert!(!SCHEMA_VERSION.is_empty());
    assert_eq!(DEFAULT_MAX_ATTEMPTS, 5);
    assert_eq!(DEFAULT_MAX_TOKEN_SKIPS, 10);
    assert_eq!(DEFAULT_MAX_INSERTIONS, 3);
    assert_eq!(DEFAULT_CONFIDENCE_THRESHOLD_MILLIONTHS, 800_000);
    assert_eq!(DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS, 600_000);
    assert_eq!(DEFAULT_PRIOR_AMBIGUOUS_MILLIONTHS, 300_000);
    assert_eq!(DEFAULT_PRIOR_UNRECOVERABLE_MILLIONTHS, 100_000);
    // Priors should sum to 1_000_000.
    assert_eq!(
        DEFAULT_PRIOR_RECOVERABLE_MILLIONTHS
            + DEFAULT_PRIOR_AMBIGUOUS_MILLIONTHS
            + DEFAULT_PRIOR_UNRECOVERABLE_MILLIONTHS,
        1_000_000
    );
}

// =========================================================================
// M. Debug formatting
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", RecoveryMode::Strict).is_empty());
    assert!(!format!("{:?}", ErrorState::Recoverable).is_empty());
    assert!(!format!("{:?}", RecoveryAction::RecoverContinue).is_empty());
    assert!(!format!("{:?}", RecoveryOutcome::CleanParse).is_empty());
    assert!(!format!("{:?}", StateProbabilities::default()).is_empty());
    assert!(!format!("{:?}", LossMatrix::default()).is_empty());
    assert!(!format!("{:?}", RecoveryConfig::default()).is_empty());
}
