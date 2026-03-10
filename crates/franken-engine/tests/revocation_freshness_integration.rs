#![forbid(unsafe_code)]
//! Integration tests for the `revocation_freshness` module.
//!
//! Exercises the public API from outside the crate: state machine transitions,
//! evaluate / evaluate_with_override, override token creation and validation,
//! audit events, outcome counts, Display implementations, and serde round-trips.

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

use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::revocation_freshness::{
    DegradedDenial, DegradedModeDecisionEvent, DegradedModeOverride, FreshnessConfig,
    FreshnessDecision, FreshnessState, FreshnessStateChangeEvent, OperationType, OverrideError,
    RevocationFreshnessController,
};
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_ZONE: &str = "integration-zone";

/// Operator signing key: bytes 0xA1..=0xBE padded to 32.
fn operator_signing_key() -> SigningKey {
    SigningKey::from_bytes([
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ])
}

fn operator_verification_key() -> VerificationKey {
    operator_signing_key().verification_key()
}

/// Build a config with authorized operator "ops-admin-01" and override-eligible
/// containing ExtensionActivation and TokenAcceptance.
fn test_config() -> FreshnessConfig {
    let mut authorized = BTreeSet::new();
    authorized.insert("ops-admin-01".to_string());

    let mut override_eligible = BTreeSet::new();
    override_eligible.insert(OperationType::ExtensionActivation);
    override_eligible.insert(OperationType::TokenAcceptance);

    FreshnessConfig {
        staleness_threshold: 5,
        holdoff_ticks: 10,
        override_eligible,
        authorized_operators: authorized,
    }
}

fn make_controller() -> RevocationFreshnessController {
    RevocationFreshnessController::new(test_config(), TEST_ZONE)
}

fn make_override_token(op: OperationType, expiry_tick: u64) -> DegradedModeOverride {
    DegradedModeOverride::create(
        op,
        "ops-admin-01",
        "emergency maintenance",
        DeterministicTimestamp(expiry_tick),
        TEST_ZONE,
        &operator_signing_key(),
    )
}

/// Drive a controller into Degraded state by setting expected_head well above
/// local (which starts at 0).
fn drive_to_degraded(ctrl: &mut RevocationFreshnessController) {
    ctrl.update_expected_head(20, "t-drive-degraded");
    assert!(ctrl.is_degraded());
}

// =========================================================================
// 1. Initial state
// =========================================================================

#[test]
fn initial_state_is_fresh() {
    let ctrl = make_controller();
    assert_eq!(ctrl.state(), FreshnessState::Fresh);
    assert!(ctrl.is_fresh());
    assert!(!ctrl.is_degraded());
    assert_eq!(ctrl.staleness_gap(), 0);
    assert_eq!(ctrl.zone(), TEST_ZONE);
}

#[test]
fn initial_config_matches() {
    let ctrl = make_controller();
    let cfg = ctrl.config();
    assert_eq!(cfg.staleness_threshold, 5);
    assert_eq!(cfg.holdoff_ticks, 10);
    assert!(cfg.authorized_operators.contains("ops-admin-01"));
    assert!(
        cfg.override_eligible
            .contains(&OperationType::ExtensionActivation)
    );
    assert!(
        cfg.override_eligible
            .contains(&OperationType::TokenAcceptance)
    );
}

// =========================================================================
// 2. Staleness detection
// =========================================================================

#[test]
fn gap_within_threshold_yields_stale() {
    let mut ctrl = make_controller();
    ctrl.update_expected_head(3, "t-stale");
    assert_eq!(ctrl.state(), FreshnessState::Stale);
    assert_eq!(ctrl.staleness_gap(), 3);
}

#[test]
fn gap_exceeds_threshold_yields_degraded() {
    let mut ctrl = make_controller();
    ctrl.update_expected_head(10, "t-degraded");
    assert_eq!(ctrl.state(), FreshnessState::Degraded);
    assert!(ctrl.is_degraded());
    assert_eq!(ctrl.staleness_gap(), 10);
}

#[test]
fn gap_zero_stays_fresh() {
    let mut ctrl = make_controller();
    ctrl.update_local_head(5, "t-local");
    ctrl.update_expected_head(5, "t-expected");
    assert_eq!(ctrl.state(), FreshnessState::Fresh);
    assert_eq!(ctrl.staleness_gap(), 0);
}

#[test]
fn gap_exactly_at_threshold_is_stale_not_degraded() {
    let mut ctrl = make_controller();
    // threshold is 5, gap of exactly 5 => gap > 0 && gap <= threshold => Stale
    ctrl.update_expected_head(5, "t-boundary");
    assert_eq!(ctrl.state(), FreshnessState::Stale);
}

#[test]
fn gap_one_above_threshold_is_degraded() {
    let mut ctrl = make_controller();
    // threshold is 5, gap of 6 => Degraded
    ctrl.update_expected_head(6, "t-one-above");
    assert_eq!(ctrl.state(), FreshnessState::Degraded);
}

// =========================================================================
// 3. State machine transitions
// =========================================================================

#[test]
fn full_cycle_fresh_stale_degraded_recovering_fresh() {
    let mut ctrl = make_controller();
    ctrl.set_tick(100);

    // Fresh
    assert_eq!(ctrl.state(), FreshnessState::Fresh);

    // Fresh -> Stale (gap=3, threshold=5)
    ctrl.update_expected_head(3, "t-stale");
    assert_eq!(ctrl.state(), FreshnessState::Stale);

    // Stale -> Degraded (gap=10)
    ctrl.update_expected_head(10, "t-degraded");
    assert_eq!(ctrl.state(), FreshnessState::Degraded);

    // Degraded -> Recovering (local catches up)
    ctrl.update_local_head(10, "t-catchup");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);

    // Recovering -> Fresh (holdoff elapses: tick 100 + 10 = 110)
    ctrl.set_tick(110);
    ctrl.check_freshness("t-holdoff-done");
    assert_eq!(ctrl.state(), FreshnessState::Fresh);
    assert!(ctrl.is_fresh());

    // Verify 4 state transitions emitted
    let events = ctrl.drain_state_events();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].from_state, FreshnessState::Fresh);
    assert_eq!(events[0].to_state, FreshnessState::Stale);
    assert_eq!(events[1].from_state, FreshnessState::Stale);
    assert_eq!(events[1].to_state, FreshnessState::Degraded);
    assert_eq!(events[2].from_state, FreshnessState::Degraded);
    assert_eq!(events[2].to_state, FreshnessState::Recovering);
    assert_eq!(events[3].from_state, FreshnessState::Recovering);
    assert_eq!(events[3].to_state, FreshnessState::Fresh);
}

#[test]
fn recovery_interrupted_re_degrades() {
    let mut ctrl = make_controller();
    ctrl.set_tick(100);

    // Drive to Degraded
    ctrl.update_expected_head(10, "t-degrade");
    assert!(ctrl.is_degraded());

    // Begin recovery
    ctrl.update_local_head(10, "t-recover");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);

    // Before holdoff completes, expected advances again -> re-Degraded
    ctrl.set_tick(105);
    ctrl.update_expected_head(20, "t-re-degrade");
    assert_eq!(ctrl.state(), FreshnessState::Degraded);
}

#[test]
fn holdoff_boundary_tick() {
    let mut ctrl = make_controller();
    ctrl.set_tick(100);
    ctrl.update_expected_head(10, "t-degrade");
    ctrl.update_local_head(10, "t-recover");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);

    // Tick 109 < start(100) + holdoff(10) = 110 => still Recovering
    ctrl.set_tick(109);
    ctrl.check_freshness("t-before-holdoff");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);

    // Tick 110 == start + holdoff => should transition to Fresh
    ctrl.set_tick(110);
    ctrl.check_freshness("t-at-holdoff");
    assert_eq!(ctrl.state(), FreshnessState::Fresh);
}

#[test]
fn stale_to_fresh_when_gap_closes() {
    let mut ctrl = make_controller();
    ctrl.update_expected_head(3, "t-stale");
    assert_eq!(ctrl.state(), FreshnessState::Stale);

    // Local catches up
    ctrl.update_local_head(3, "t-catchup");
    assert_eq!(ctrl.state(), FreshnessState::Fresh);
}

#[test]
fn fresh_to_degraded_directly_on_large_gap() {
    let mut ctrl = make_controller();
    // Gap of 100 immediately from Fresh => skip Stale, go to Degraded
    ctrl.update_expected_head(100, "t-big-gap");
    assert_eq!(ctrl.state(), FreshnessState::Degraded);
}

// =========================================================================
// 4. evaluate
// =========================================================================

#[test]
fn safe_operation_proceeds_in_all_states() {
    // Fresh
    let mut ctrl = make_controller();
    let r = ctrl.evaluate(OperationType::SafeOperation, "t-fresh");
    assert_eq!(r.unwrap(), FreshnessDecision::Proceed);

    // Stale
    ctrl.update_expected_head(3, "t-stale");
    let r = ctrl.evaluate(OperationType::SafeOperation, "t-stale");
    assert_eq!(r.unwrap(), FreshnessDecision::Proceed);

    // Degraded
    ctrl.update_expected_head(20, "t-degraded");
    let r = ctrl.evaluate(OperationType::SafeOperation, "t-degraded");
    assert_eq!(r.unwrap(), FreshnessDecision::Proceed);

    // Recovering
    ctrl.update_local_head(20, "t-recover");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);
    let r = ctrl.evaluate(OperationType::SafeOperation, "t-recovering");
    assert_eq!(r.unwrap(), FreshnessDecision::Proceed);
}

#[test]
fn health_check_always_proceeds() {
    let mut ctrl = make_controller();
    drive_to_degraded(&mut ctrl);

    let r = ctrl.evaluate(OperationType::HealthCheck, "t-health");
    assert_eq!(r.unwrap(), FreshnessDecision::Proceed);
}

#[test]
fn token_acceptance_denied_in_degraded() {
    let mut ctrl = make_controller();
    drive_to_degraded(&mut ctrl);

    let r = ctrl.evaluate(OperationType::TokenAcceptance, "t-token");
    assert!(r.is_err());
    let denial = r.unwrap_err();
    assert_eq!(denial.operation_type, OperationType::TokenAcceptance);
    assert_eq!(denial.local_head_seq, 0);
    assert_eq!(denial.expected_head_seq, 20);
    assert_eq!(denial.staleness_gap, 20);
}

#[test]
fn extension_activation_denied_in_degraded() {
    let mut ctrl = make_controller();
    drive_to_degraded(&mut ctrl);

    let r = ctrl.evaluate(OperationType::ExtensionActivation, "t-ext");
    assert!(r.is_err());
    assert_eq!(
        r.unwrap_err().operation_type,
        OperationType::ExtensionActivation
    );
}

#[test]
fn high_risk_denied_in_degraded() {
    let mut ctrl = make_controller();
    drive_to_degraded(&mut ctrl);

    let r = ctrl.evaluate(OperationType::HighRiskOperation, "t-hr");
    assert!(r.is_err());
}

#[test]
fn operations_proceed_in_fresh() {
    let mut ctrl = make_controller();
    assert_eq!(
        ctrl.evaluate(OperationType::TokenAcceptance, "t1").unwrap(),
        FreshnessDecision::Proceed
    );
    assert_eq!(
        ctrl.evaluate(OperationType::ExtensionActivation, "t2")
            .unwrap(),
        FreshnessDecision::Proceed
    );
    assert_eq!(
        ctrl.evaluate(OperationType::HighRiskOperation, "t3")
            .unwrap(),
        FreshnessDecision::Proceed
    );
}

#[test]
fn operations_proceed_in_stale() {
    let mut ctrl = make_controller();
    ctrl.update_expected_head(3, "t-stale");
    assert_eq!(ctrl.state(), FreshnessState::Stale);

    assert!(ctrl.evaluate(OperationType::TokenAcceptance, "t1").is_ok());
    assert!(
        ctrl.evaluate(OperationType::ExtensionActivation, "t2")
            .is_ok()
    );
    assert!(
        ctrl.evaluate(OperationType::HighRiskOperation, "t3")
            .is_ok()
    );
}

#[test]
fn operations_proceed_in_recovering() {
    let mut ctrl = make_controller();
    ctrl.set_tick(100);
    ctrl.update_expected_head(10, "t-degrade");
    ctrl.update_local_head(10, "t-recover");
    assert_eq!(ctrl.state(), FreshnessState::Recovering);

    assert!(ctrl.evaluate(OperationType::TokenAcceptance, "t1").is_ok());
    assert!(
        ctrl.evaluate(OperationType::ExtensionActivation, "t2")
            .is_ok()
    );
}

// =========================================================================
// 5. evaluate_with_override
// =========================================================================

#[test]
fn override_success_path() {
    let mut ctrl = make_controller();
    ctrl.set_tick(1000);
    drive_to_degraded(&mut ctrl);

    let token = make_override_token(OperationType::ExtensionActivation, 2000);
    let vk = operator_verification_key();

    let result = ctrl.evaluate_with_override(
        OperationType::ExtensionActivation,
        &token,
        &vk,
        "t-override-ok",
    );
    assert!(result.is_ok());
    match result.unwrap() {
        FreshnessDecision::OverrideGranted {
            override_id,
            operator_id,
        } => {
            assert_eq!(operator_id, "ops-admin-01");
            assert_eq!(override_id, token.override_id);
        }
        other => panic!("expected OverrideGranted, got {other:?}"),
    }
}

#[test]
fn override_token_acceptance_success() {
    let mut ctrl = make_controller();
    ctrl.set_tick(500);
    drive_to_degraded(&mut ctrl);

    let token = make_override_token(OperationType::TokenAcceptance, 1000);
    let vk = operator_verification_key();

    let result = ctrl.evaluate_with_override(
        OperationType::TokenAcceptance,
        &token,
        &vk,
        "t-token-override",
    );
    assert!(result.is_ok());
    assert!(matches!(
        result.unwrap(),
        FreshnessDecision::OverrideGranted { .. }
    ));
}

#[test]
fn override_not_degraded_error() {
    let mut ctrl = make_controller();
    ctrl.set_tick(1000);
    // Controller is Fresh, not Degraded

    let token = make_override_token(OperationType::ExtensionActivation, 2000);
    let vk = operator_verification_key();

    let result = ctrl.evaluate_with_override(
        OperationType::ExtensionActivation,
        &token,
        &vk,
        "t-not-degraded",
    );
    match result {
        Err(OverrideError::NotDegraded { current_state }) => {
            assert_eq!(current_state, FreshnessState::Fresh);
        }
        other => panic!("expected NotDegraded, got {other:?}"),
    }
}

#[test]
fn override_operation_mismatch() {
    let mut ctrl = make_controller();
    ctrl.set_tick(1000);
    drive_to_degraded(&mut ctrl);

    // Token is for TokenAcceptance, but we request ExtensionActivation
    let token = make_override_token(OperationType::TokenAcceptance, 2000);
    let vk = operator_verification_key();

    let result = ctrl.evaluate_with_override(
        OperationType::ExtensionActivation,
        &token,
        &vk,
        "t-mismatch",
    );
    match result {
        Err(OverrideError::OperationMismatch {
            requested,
            override_type,
        }) => {
            assert_eq!(requested, OperationType::ExtensionActivation);
            assert_eq!(override_type, OperationType::TokenAcceptance);
        }
        other => panic!("expected OperationMismatch, got {other:?}"),
    }
}

#[test]
fn override_expired() {
    let mut ctrl = make_controller();
    ctrl.set_tick(3000);
    drive_to_degraded(&mut ctrl);

    let token = make_override_token(OperationType::ExtensionActivation, 2000);
    let vk = operator_verification_key();

    let result =
        ctrl.evaluate_with_override(OperationType::ExtensionActivation, &token, &vk, "t-expired");
    match result {
        Err(OverrideError::Expired { expiry, current }) => {
            assert_eq!(expiry, DeterministicTimestamp(2000));
            assert_eq!(current, DeterministicTimestamp(3000));
        }
        other => panic!("expected Expired, got {other:?}"),
    }
}

#[test]
fn override_unauthorized_operator() {
    let mut ctrl = make_controller();
    ctrl.set_tick(1000);
    drive_to_degraded(&mut ctrl);

    let sk = operator_signing_key();
    let token = DegradedModeOverride::create(
        OperationType::ExtensionActivation,
        "rogue-operator",
        "unauthorized attempt",
        DeterministicTimestamp(2000),
        TEST_ZONE,
        &sk,
    );
    let vk = sk.verification_key();

    let result =
        ctrl.evaluate_with_override(OperationType::ExtensionActivation, &token, &vk, "t-unauth");
    match result {
        Err(OverrideError::UnauthorizedOperator { operator_id }) => {
            assert_eq!(operator_id, "rogue-operator");
        }
        other => panic!("expected UnauthorizedOperator, got {other:?}"),
    }
}

#[test]
fn override_not_eligible_for_operation_type() {
    let mut ctrl = make_controller();
    ctrl.set_tick(1000);
    drive_to_degraded(&mut ctrl);

    // HighRiskOperation is NOT in override_eligible
    let token = make_override_token(OperationType::HighRiskOperation, 2000);
    let vk = operator_verification_key();

    let result = ctrl.evaluate_with_override(
        OperationType::HighRiskOperation,
        &token,
        &vk,
        "t-not-eligible",
    );
    // Should get OperationMismatch because HighRiskOperation is not eligible
    assert!(matches!(
        result,
        Err(OverrideError::OperationMismatch { .. })
    ));
}

#[test]
fn override_invalid_signature() {
    let mut ctrl = make_controller();
    ctrl.set_tick(1000);
    drive_to_degraded(&mut ctrl);

    let token = make_override_token(OperationType::ExtensionActivation, 2000);
    let wrong_vk = VerificationKey::from_bytes([0xFF; 32]);

    let result = ctrl.evaluate_with_override(
        OperationType::ExtensionActivation,
        &token,
        &wrong_vk,
        "t-bad-sig",
    );
    assert!(matches!(
        result,
        Err(OverrideError::SignatureInvalid { .. })
    ));
}

// =========================================================================
// 6. DegradedDenial Display and fields
// =========================================================================

#[test]
fn degraded_denial_display_format() {
    let denial = DegradedDenial {
        operation_type: OperationType::TokenAcceptance,
        local_head_seq: 50,
        expected_head_seq: 60,
        staleness_gap: 10,
    };
    let display = denial.to_string();
    assert!(display.contains("token_acceptance"));
    assert!(display.contains("50"));
    assert!(display.contains("60"));
    assert!(display.contains("10"));
    assert!(display.contains("degraded mode denial"));
}

#[test]
fn degraded_denial_fields_correct() {
    let mut ctrl = make_controller();
    ctrl.update_local_head(5, "t-local");
    ctrl.update_expected_head(20, "t-expected");
    // gap = 20 - 5 = 15, threshold = 5 => Degraded
    assert!(ctrl.is_degraded());

    let denial = ctrl
        .evaluate(OperationType::HighRiskOperation, "t-deny")
        .unwrap_err();
    assert_eq!(denial.operation_type, OperationType::HighRiskOperation);
    assert_eq!(denial.local_head_seq, 5);
    assert_eq!(denial.expected_head_seq, 20);
    assert_eq!(denial.staleness_gap, 15);
}

// =========================================================================
// 7. OverrideError Display strings
// =========================================================================

#[test]
fn override_error_expired_display() {
    let err = OverrideError::Expired {
        expiry: DeterministicTimestamp(1000),
        current: DeterministicTimestamp(2000),
    };
    let s = err.to_string();
    assert!(s.contains("expired"));
    assert!(s.contains("1000"));
    assert!(s.contains("2000"));
}

#[test]
fn override_error_operation_mismatch_display() {
    let err = OverrideError::OperationMismatch {
        requested: OperationType::TokenAcceptance,
        override_type: OperationType::ExtensionActivation,
    };
    let s = err.to_string();
    assert!(s.contains("mismatch"));
    assert!(s.contains("token_acceptance"));
    assert!(s.contains("extension_activation"));
}

#[test]
fn override_error_signature_invalid_display() {
    let err = OverrideError::SignatureInvalid {
        detail: "bad signature hash".to_string(),
    };
    assert!(err.to_string().contains("bad signature hash"));
}

#[test]
fn override_error_unauthorized_display() {
    let err = OverrideError::UnauthorizedOperator {
        operator_id: "rogue-42".to_string(),
    };
    assert!(err.to_string().contains("rogue-42"));
}

#[test]
fn override_error_not_degraded_display() {
    let err = OverrideError::NotDegraded {
        current_state: FreshnessState::Recovering,
    };
    let s = err.to_string();
    assert!(s.contains("not in degraded mode"));
    assert!(s.contains("recovering"));
}

// =========================================================================
// 8. DegradedModeOverride creation
// =========================================================================

#[test]
fn override_create_produces_signed_token() {
    let token = make_override_token(OperationType::ExtensionActivation, 5000);
    assert_eq!(token.operation_type, OperationType::ExtensionActivation);
    assert_eq!(token.operator_id, "ops-admin-01");
    assert_eq!(token.justification, "emergency maintenance");
    assert_eq!(token.expiry, DeterministicTimestamp(5000));
    assert_eq!(token.zone, TEST_ZONE);
    // Signature is not sentinel (was actually signed)
    assert!(!token.signature.is_sentinel());
}

#[test]
fn override_id_is_deterministic() {
    let t1 = make_override_token(OperationType::ExtensionActivation, 5000);
    let t2 = make_override_token(OperationType::ExtensionActivation, 5000);
    assert_eq!(t1.override_id, t2.override_id);
    assert_eq!(t1.signature, t2.signature);
}

#[test]
fn different_operations_produce_different_override_ids() {
    let t1 = make_override_token(OperationType::ExtensionActivation, 5000);
    let t2 = make_override_token(OperationType::TokenAcceptance, 5000);
    assert_ne!(t1.override_id, t2.override_id);
}

// =========================================================================
// 9. Audit events
// =========================================================================

#[test]
fn state_change_events_emitted_on_transitions() {
    let mut ctrl = make_controller();
    ctrl.update_expected_head(3, "t-stale");
    ctrl.update_expected_head(10, "t-degraded");

    let events = ctrl.drain_state_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].from_state, FreshnessState::Fresh);
    assert_eq!(events[0].to_state, FreshnessState::Stale);
    assert_eq!(events[0].trace_id, "t-stale");
    assert_eq!(events[1].from_state, FreshnessState::Stale);
    assert_eq!(events[1].to_state, FreshnessState::Degraded);
    assert_eq!(events[1].trace_id, "t-degraded");
}

#[test]
fn decision_events_emitted_on_evaluations() {
    let mut ctrl = make_controller();
    drive_to_degraded(&mut ctrl);
    ctrl.drain_decision_events(); // clear any prior

    ctrl.evaluate(OperationType::SafeOperation, "t-safe-eval")
        .unwrap();
    ctrl.evaluate(OperationType::TokenAcceptance, "t-deny-eval")
        .unwrap_err();

    let events = ctrl.drain_decision_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].operation_type, OperationType::SafeOperation);
    assert_eq!(events[0].trace_id, "t-safe-eval");
    assert_eq!(events[1].operation_type, OperationType::TokenAcceptance);
    assert_eq!(events[1].outcome, "denied");
    assert_eq!(events[1].trace_id, "t-deny-eval");
}

#[test]
fn drain_clears_events() {
    let mut ctrl = make_controller();
    ctrl.update_expected_head(10, "t-degrade");

    let events1 = ctrl.drain_state_events();
    assert!(!events1.is_empty());

    let events2 = ctrl.drain_state_events();
    assert!(events2.is_empty());

    ctrl.evaluate(OperationType::HealthCheck, "t-hc").unwrap();
    let de1 = ctrl.drain_decision_events();
    assert!(!de1.is_empty());
    let de2 = ctrl.drain_decision_events();
    assert!(de2.is_empty());
}

#[test]
fn state_change_event_has_correct_fields() {
    let mut ctrl = make_controller();
    ctrl.set_tick(42);
    ctrl.update_expected_head(10, "t-check-fields");

    let events = ctrl.drain_state_events();
    assert_eq!(events.len(), 1);
    let evt = &events[0];
    assert_eq!(evt.local_head_seq, 0);
    assert_eq!(evt.expected_head_seq, 10);
    assert_eq!(evt.staleness_gap, 10);
    assert_eq!(evt.threshold, 5);
    assert_eq!(evt.timestamp, DeterministicTimestamp(42));
}

// =========================================================================
// 10. outcome_counts
// =========================================================================

#[test]
fn outcome_counts_increments_on_deny() {
    let mut ctrl = make_controller();
    drive_to_degraded(&mut ctrl);

    for i in 0..4 {
        let _ = ctrl.evaluate(OperationType::TokenAcceptance, &format!("t-deny-{i}"));
    }
    assert_eq!(ctrl.outcome_counts().get("denied"), Some(&4));
}

#[test]
fn outcome_counts_increments_on_override_granted() {
    let mut ctrl = make_controller();
    ctrl.set_tick(1000);
    drive_to_degraded(&mut ctrl);

    let vk = operator_verification_key();
    for i in 0..3 {
        let token = make_override_token(OperationType::ExtensionActivation, 2000 + i);
        ctrl.evaluate_with_override(
            OperationType::ExtensionActivation,
            &token,
            &vk,
            &format!("t-override-{i}"),
        )
        .unwrap();
    }
    assert_eq!(ctrl.outcome_counts().get("override_granted"), Some(&3));
}

// =========================================================================
// 11. Serde roundtrips
// =========================================================================

#[test]
fn serde_freshness_state_roundtrip() {
    let states = [
        FreshnessState::Fresh,
        FreshnessState::Stale,
        FreshnessState::Degraded,
        FreshnessState::Recovering,
    ];
    for s in &states {
        let json = serde_json::to_string(s).unwrap();
        let restored: FreshnessState = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

#[test]
fn serde_operation_type_roundtrip() {
    let ops = [
        OperationType::SafeOperation,
        OperationType::TokenAcceptance,
        OperationType::ExtensionActivation,
        OperationType::HighRiskOperation,
        OperationType::HealthCheck,
    ];
    for o in &ops {
        let json = serde_json::to_string(o).unwrap();
        let restored: OperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, restored);
    }
}

#[test]
fn serde_freshness_decision_roundtrip() {
    let decisions = vec![
        FreshnessDecision::Proceed,
        FreshnessDecision::Denied(DegradedDenial {
            operation_type: OperationType::TokenAcceptance,
            local_head_seq: 50,
            expected_head_seq: 60,
            staleness_gap: 10,
        }),
    ];
    for d in &decisions {
        let json = serde_json::to_string(d).unwrap();
        let restored: FreshnessDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, restored);
    }
}

#[test]
fn serde_degraded_denial_roundtrip() {
    let denial = DegradedDenial {
        operation_type: OperationType::ExtensionActivation,
        local_head_seq: 100,
        expected_head_seq: 200,
        staleness_gap: 100,
    };
    let json = serde_json::to_string(&denial).unwrap();
    let restored: DegradedDenial = serde_json::from_str(&json).unwrap();
    assert_eq!(denial, restored);
}

#[test]
fn serde_override_error_roundtrip() {
    let errors: Vec<OverrideError> = vec![
        OverrideError::Expired {
            expiry: DeterministicTimestamp(1000),
            current: DeterministicTimestamp(2000),
        },
        OverrideError::OperationMismatch {
            requested: OperationType::TokenAcceptance,
            override_type: OperationType::ExtensionActivation,
        },
        OverrideError::SignatureInvalid {
            detail: "bad".to_string(),
        },
        OverrideError::UnauthorizedOperator {
            operator_id: "intruder".to_string(),
        },
        OverrideError::NotDegraded {
            current_state: FreshnessState::Fresh,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: OverrideError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn serde_freshness_config_roundtrip() {
    let config = test_config();
    let json = serde_json::to_string(&config).unwrap();
    let restored: FreshnessConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn serde_state_change_event_roundtrip() {
    let event = FreshnessStateChangeEvent {
        from_state: FreshnessState::Stale,
        to_state: FreshnessState::Degraded,
        local_head_seq: 10,
        expected_head_seq: 30,
        staleness_gap: 20,
        threshold: 5,
        trace_id: "t-serde-evt".to_string(),
        timestamp: DeterministicTimestamp(9999),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: FreshnessStateChangeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn serde_decision_event_roundtrip() {
    let event = DegradedModeDecisionEvent {
        operation_type: OperationType::HighRiskOperation,
        outcome: "denied".to_string(),
        local_head_seq: 5,
        expected_head_seq: 15,
        override_id: None,
        operator_id: None,
        trace_id: "t-serde-dec".to_string(),
        timestamp: DeterministicTimestamp(7777),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: DegradedModeDecisionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn serde_override_token_roundtrip() {
    let token = make_override_token(OperationType::ExtensionActivation, 5000);
    let json = serde_json::to_string(&token).unwrap();
    let restored: DegradedModeOverride = serde_json::from_str(&json).unwrap();
    assert_eq!(token, restored);
}

// =========================================================================
// 12. Display implementations
// =========================================================================

#[test]
fn display_freshness_state_all_variants() {
    assert_eq!(FreshnessState::Fresh.to_string(), "fresh");
    assert_eq!(FreshnessState::Stale.to_string(), "stale");
    assert_eq!(FreshnessState::Degraded.to_string(), "degraded");
    assert_eq!(FreshnessState::Recovering.to_string(), "recovering");
}

#[test]
fn display_operation_type_all_variants() {
    assert_eq!(OperationType::SafeOperation.to_string(), "safe_operation");
    assert_eq!(
        OperationType::TokenAcceptance.to_string(),
        "token_acceptance"
    );
    assert_eq!(
        OperationType::ExtensionActivation.to_string(),
        "extension_activation"
    );
    assert_eq!(
        OperationType::HighRiskOperation.to_string(),
        "high_risk_operation"
    );
    assert_eq!(OperationType::HealthCheck.to_string(), "health_check");
}

// =========================================================================
// Additional: Default trait, determinism, multi-scenario
// =========================================================================

#[test]
fn freshness_state_default_is_fresh() {
    let s: FreshnessState = Default::default();
    assert_eq!(s, FreshnessState::Fresh);
}

#[test]
fn freshness_config_default_values() {
    let config = FreshnessConfig::default();
    assert_eq!(config.staleness_threshold, 5);
    assert_eq!(config.holdoff_ticks, 10);
    assert!(
        config
            .override_eligible
            .contains(&OperationType::ExtensionActivation)
    );
    assert!(
        !config
            .override_eligible
            .contains(&OperationType::TokenAcceptance)
    );
    assert!(config.authorized_operators.is_empty());
}

#[test]
fn controller_deterministic_across_runs() {
    let run = || {
        let mut ctrl = make_controller();
        ctrl.set_tick(100);
        ctrl.update_expected_head(10, "t-det");
        let r1 = ctrl.evaluate(OperationType::TokenAcceptance, "t-det-1");
        ctrl.update_local_head(10, "t-det-recover");
        ctrl.set_tick(110);
        ctrl.check_freshness("t-det-fresh");
        let r2 = ctrl.evaluate(OperationType::TokenAcceptance, "t-det-2");
        let events = ctrl.drain_state_events();
        (format!("{r1:?}"), r2, events)
    };

    let (r1a, r2a, events_a) = run();
    let (r1b, r2b, events_b) = run();

    assert_eq!(r1a, r1b);
    assert_eq!(r2a, r2b);
    assert_eq!(events_a, events_b);
}

#[test]
fn check_freshness_returns_current_state() {
    let mut ctrl = make_controller();
    assert_eq!(ctrl.check_freshness("t-fresh"), FreshnessState::Fresh);

    ctrl.update_expected_head(3, "t-stale");
    assert_eq!(ctrl.check_freshness("t-check"), FreshnessState::Stale);
}

#[test]
fn multiple_denials_and_overrides_in_sequence() {
    let mut ctrl = make_controller();
    ctrl.set_tick(1000);
    drive_to_degraded(&mut ctrl);

    // 2 denials
    let _ = ctrl.evaluate(OperationType::TokenAcceptance, "t-d1");
    let _ = ctrl.evaluate(OperationType::HighRiskOperation, "t-d2");

    // 1 override
    let vk = operator_verification_key();
    let token = make_override_token(OperationType::ExtensionActivation, 5000);
    ctrl.evaluate_with_override(OperationType::ExtensionActivation, &token, &vk, "t-o1")
        .unwrap();

    let counts = ctrl.outcome_counts();
    assert_eq!(counts.get("denied"), Some(&2));
    assert_eq!(counts.get("override_granted"), Some(&1));
}
