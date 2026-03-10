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

use frankenengine_engine::capability_witness::RollbackToken;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::plas_burn_in_gate::{
    BurnInDecisionArtifact, BurnInError, BurnInFailureCode, BurnInLifecycleState, BurnInLogEvent,
    BurnInMetrics, BurnInScorecardMetrics, BurnInSession, BurnInSessionConfig, BurnInThresholds,
    ExtensionRiskClass, RollbackProofArtifacts, ShadowObservation,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn session_config() -> BurnInSessionConfig {
    BurnInSessionConfig {
        trace_id: "trace-burn-in-001".to_string(),
        decision_id: "decision-burn-in-001".to_string(),
        policy_id: "policy-burn-in-v1".to_string(),
        extension_id: "extension://plas/burn-in".to_string(),
        risk_class: ExtensionRiskClass::Standard,
        thresholds: BurnInThresholds {
            min_shadow_success_millionths: 900_000,
            max_false_deny_millionths: 100_000,
            min_shadow_duration_ns: 1_000,
            min_shadow_observations: 5,
        },
        shadow_start_timestamp_ns: 1_000_000,
    }
}

fn complete_rollback_artifacts() -> RollbackProofArtifacts {
    RollbackProofArtifacts {
        rollback_command_tested: true,
        previous_policy_snapshot_ref: Some("snapshot://policy/previous".to_string()),
        transition_receipt_signed: true,
        transition_receipt_ref: Some("receipt://transition/001".to_string()),
        rollback_token: Some(RollbackToken {
            previous_witness_hash: ContentHash::compute(b"prev-witness"),
            previous_witness_id: None,
            created_epoch: SecurityEpoch::from_raw(42),
            sequence: 7,
        }),
    }
}

fn observation(id: &str, timestamp_ns: u64, success: bool, false_deny: bool) -> ShadowObservation {
    ShadowObservation {
        observation_id: id.to_string(),
        timestamp_ns,
        success,
        false_deny,
    }
}

#[test]
fn full_lifecycle_passes_and_promotes_auto_enforcement() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::ShadowStart);

    session.begin_shadow_evaluation().unwrap();
    assert_eq!(
        session.lifecycle_state(),
        BurnInLifecycleState::ShadowEvaluation
    );

    let timestamps = [1_000_100, 1_000_200, 1_000_300, 1_000_400, 1_001_500];
    for (idx, ts) in timestamps.iter().enumerate() {
        let maybe_artifact = session
            .record_shadow_observation(observation(&format!("obs-{idx}"), *ts, true, false))
            .unwrap();
        assert!(maybe_artifact.is_none());
    }

    let artifact = session.evaluate_promotion_gate(1_002_000).unwrap();
    assert_eq!(
        session.lifecycle_state(),
        BurnInLifecycleState::AutoEnforcement
    );
    assert_eq!(
        artifact.lifecycle_state,
        BurnInLifecycleState::AutoEnforcement
    );
    assert_eq!(artifact.outcome, "pass");
    assert!(artifact.failure_codes.is_empty());
    assert!(artifact.rollback_artifacts_verified);
}

#[test]
fn early_termination_triggers_on_false_deny_envelope_breach() {
    let mut cfg = session_config();
    cfg.thresholds.max_false_deny_millionths = 0;

    let mut session = BurnInSession::new(cfg, complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    let artifact = session
        .record_shadow_observation(observation("obs-early", 1_000_100, false, true))
        .unwrap()
        .expect("expected early termination artifact");
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    assert_eq!(artifact.outcome, "fail");
    assert_eq!(
        artifact.failure_codes,
        vec![BurnInFailureCode::EarlyTerminationFalseDeny]
    );
}

#[test]
fn promotion_gate_rejects_when_success_rate_below_threshold() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    // 4/5 successes = 800_000 < 900_000
    session
        .record_shadow_observation(observation("obs-1", 1_000_100, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-2", 1_000_200, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-3", 1_000_300, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-4", 1_000_400, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-5", 1_001_500, false, false))
        .unwrap();

    let artifact = session.evaluate_promotion_gate(1_002_000).unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    assert!(
        artifact
            .failure_codes
            .contains(&BurnInFailureCode::ShadowSuccessRateBelowThreshold)
    );
}

#[test]
fn false_deny_envelope_breach_triggers_early_rejection_artifact() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    // 1/5 false denies = 200_000 > 100_000, triggering early termination.
    session
        .record_shadow_observation(observation("obs-1", 1_000_100, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-2", 1_000_200, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-3", 1_000_300, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-4", 1_000_400, true, false))
        .unwrap();
    let artifact = session
        .record_shadow_observation(observation("obs-5", 1_001_500, true, true))
        .unwrap()
        .expect("expected early rejection artifact");
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    assert_eq!(
        artifact.failure_codes,
        vec![BurnInFailureCode::EarlyTerminationFalseDeny]
    );
}

#[test]
fn promotion_gate_rejects_when_rollback_artifacts_are_incomplete() {
    let mut artifacts = complete_rollback_artifacts();
    artifacts.transition_receipt_signed = false;

    let mut session = BurnInSession::new(session_config(), artifacts).unwrap();
    session.begin_shadow_evaluation().unwrap();

    for idx in 0..5 {
        session
            .record_shadow_observation(observation(
                &format!("obs-{idx}"),
                1_000_100 + (idx as u64) * 100,
                true,
                false,
            ))
            .unwrap();
    }

    let artifact = session.evaluate_promotion_gate(1_002_000).unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    assert!(
        artifact
            .failure_codes
            .contains(&BurnInFailureCode::RollbackProofArtifactsMissing)
    );
}

#[test]
fn non_monotonic_observation_timestamp_is_rejected() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    session
        .record_shadow_observation(observation("obs-1", 1_000_200, true, false))
        .unwrap();
    let err = session
        .record_shadow_observation(observation("obs-2", 1_000_100, true, false))
        .unwrap_err();
    assert!(err.to_string().contains("non-monotonic timestamp"));
}

#[test]
fn risk_class_defaults_get_stricter_for_high_risk_extensions() {
    let low = BurnInThresholds::for_risk_class(ExtensionRiskClass::Low);
    let standard = BurnInThresholds::for_risk_class(ExtensionRiskClass::Standard);
    let high = BurnInThresholds::for_risk_class(ExtensionRiskClass::High);

    assert!(low.min_shadow_success_millionths < standard.min_shadow_success_millionths);
    assert!(high.min_shadow_success_millionths > standard.min_shadow_success_millionths);
    assert!(high.max_false_deny_millionths < standard.max_false_deny_millionths);
    assert!(high.min_shadow_observations > standard.min_shadow_observations);
}

#[test]
fn structured_log_contract_is_stable() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    let early = session
        .record_shadow_observation(observation("obs-1", 1_000_100, false, true))
        .unwrap()
        .expect("expected early termination");

    assert_eq!(early.trace_id, "trace-burn-in-001");
    assert_eq!(early.decision_id, "decision-burn-in-001");
    assert_eq!(early.policy_id, "policy-burn-in-v1");
    assert_eq!(early.outcome, "fail");
    assert!(!early.decision_hash.as_bytes().is_empty());

    let final_log = session.logs().last().unwrap();
    assert_eq!(final_log.trace_id, "trace-burn-in-001");
    assert_eq!(final_log.decision_id, "decision-burn-in-001");
    assert_eq!(final_log.policy_id, "policy-burn-in-v1");
    assert_eq!(final_log.component, "plas_burn_in_gate");
    assert_eq!(final_log.event, "shadow_evaluation");
    assert_eq!(final_log.outcome, "fail");
    assert_eq!(
        final_log.error_code.as_deref(),
        Some("early_termination_false_deny")
    );
    assert_eq!(final_log.lifecycle_state, BurnInLifecycleState::Rejection);
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn extension_risk_class_serde_round_trip_all_variants() {
    for risk_class in [
        ExtensionRiskClass::Low,
        ExtensionRiskClass::Standard,
        ExtensionRiskClass::High,
    ] {
        let json = serde_json::to_string(&risk_class).expect("serialize");
        let recovered: ExtensionRiskClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(risk_class, recovered);
        assert!(!risk_class.as_str().is_empty());
    }
}

#[test]
fn burn_in_lifecycle_state_serde_round_trip_all_variants() {
    for state in [
        BurnInLifecycleState::ShadowStart,
        BurnInLifecycleState::ShadowEvaluation,
        BurnInLifecycleState::PromotionGate,
        BurnInLifecycleState::AutoEnforcement,
        BurnInLifecycleState::Rejection,
    ] {
        let json = serde_json::to_string(&state).expect("serialize");
        let recovered: BurnInLifecycleState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, recovered);
        assert!(!state.as_str().is_empty());
    }
}

#[test]
fn burn_in_failure_code_serde_round_trip_all_variants() {
    for code in [
        BurnInFailureCode::EarlyTerminationFalseDeny,
        BurnInFailureCode::InsufficientShadowDuration,
        BurnInFailureCode::InsufficientShadowObservations,
        BurnInFailureCode::ShadowSuccessRateBelowThreshold,
        BurnInFailureCode::FalseDenyEnvelopeExceeded,
        BurnInFailureCode::RollbackProofArtifactsMissing,
    ] {
        let json = serde_json::to_string(&code).expect("serialize");
        let recovered: BurnInFailureCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(code, recovered);
        assert!(!code.error_code().is_empty());
    }
}

#[test]
fn shadow_observation_serde_round_trip() {
    let obs = observation("obs-serde", 1_000_500, true, false);
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: ShadowObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, recovered);
}

#[test]
fn burn_in_session_config_serde_round_trip() {
    let config = session_config();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: BurnInSessionConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
}

// ────────────────────────────────────────────────────────────
// Lifecycle state transitions
// ────────────────────────────────────────────────────────────

#[test]
fn lifecycle_state_is_terminal_classification() {
    assert!(!BurnInLifecycleState::ShadowStart.is_terminal());
    assert!(!BurnInLifecycleState::ShadowEvaluation.is_terminal());
    assert!(!BurnInLifecycleState::PromotionGate.is_terminal());
    assert!(BurnInLifecycleState::AutoEnforcement.is_terminal());
    assert!(BurnInLifecycleState::Rejection.is_terminal());
}

#[test]
fn begin_shadow_evaluation_requires_shadow_start() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    // Calling again from ShadowEvaluation should fail
    let err = session.begin_shadow_evaluation().expect_err("should fail");
    assert!(!err.to_string().is_empty());
}

#[test]
fn evaluate_promotion_gate_requires_shadow_evaluation() {
    let session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    // Cannot evaluate gate before beginning shadow evaluation
    // Create a mutable binding and try - the session doesn't support it from ShadowStart
    let mut session = session;
    let err = session
        .evaluate_promotion_gate(1_002_000)
        .expect_err("should fail");
    assert!(!err.to_string().is_empty());
}

// ────────────────────────────────────────────────────────────
// Metrics
// ────────────────────────────────────────────────────────────

#[test]
fn metrics_track_observations_correctly() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    session
        .record_shadow_observation(observation("obs-1", 1_000_100, true, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-2", 1_000_200, false, false))
        .unwrap();
    session
        .record_shadow_observation(observation("obs-3", 1_000_300, true, true))
        .unwrap();

    let metrics = session.metrics();
    assert!(metrics.shadow_success_rate_millionths() > 0);
    assert!(metrics.elapsed_ns() > 0);
}

#[test]
fn metrics_serde_round_trip() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(observation("obs-1", 1_000_100, true, false))
        .unwrap();
    let metrics = session.metrics().clone();
    let json = serde_json::to_string(&metrics).expect("serialize");
    let recovered: BurnInMetrics = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(metrics, recovered);
}

// ────────────────────────────────────────────────────────────
// Scorecard metrics
// ────────────────────────────────────────────────────────────

#[test]
fn scorecard_metrics_reflect_session_state() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    for idx in 0..5 {
        session
            .record_shadow_observation(observation(
                &format!("obs-{idx}"),
                1_000_100 + (idx as u64) * 100,
                true,
                false,
            ))
            .unwrap();
    }

    let scorecard = session.scorecard_metrics();
    let json = serde_json::to_string(&scorecard).expect("serialize");
    let recovered: BurnInScorecardMetrics = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(scorecard, recovered);
}

// ────────────────────────────────────────────────────────────
// Decision artifact
// ────────────────────────────────────────────────────────────

#[test]
fn decision_artifact_none_before_gate_evaluation() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    assert!(session.decision_artifact().is_none());
    session.begin_shadow_evaluation().unwrap();
    assert!(session.decision_artifact().is_none());
}

#[test]
fn decision_artifact_serde_round_trip() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    for idx in 0..5 {
        session
            .record_shadow_observation(observation(
                &format!("obs-{idx}"),
                1_000_100 + (idx as u64) * 100,
                true,
                false,
            ))
            .unwrap();
    }
    let artifact = session.evaluate_promotion_gate(1_002_000).unwrap();
    let json = serde_json::to_string(&artifact).expect("serialize");
    let recovered: BurnInDecisionArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact.outcome, recovered.outcome);
    assert_eq!(artifact.decision_hash, recovered.decision_hash);
}

#[test]
fn decision_artifact_is_deterministic() {
    let mut s1 = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    let mut s2 = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();

    for session in [&mut s1, &mut s2] {
        session.begin_shadow_evaluation().unwrap();
        for idx in 0..5 {
            session
                .record_shadow_observation(observation(
                    &format!("obs-{idx}"),
                    1_000_100 + (idx as u64) * 100,
                    true,
                    false,
                ))
                .unwrap();
        }
    }

    let a1 = s1.evaluate_promotion_gate(1_002_000).unwrap();
    let a2 = s2.evaluate_promotion_gate(1_002_000).unwrap();
    assert_eq!(a1.decision_hash, a2.decision_hash);
    assert_eq!(a1.outcome, a2.outcome);
}

// ────────────────────────────────────────────────────────────
// Log events
// ────────────────────────────────────────────────────────────

#[test]
fn logs_accumulate_during_lifecycle() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    let initial_log_count = session.logs().len();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(observation("obs-1", 1_000_100, true, false))
        .unwrap();
    assert!(session.logs().len() > initial_log_count);
}

#[test]
fn log_event_serde_round_trip() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(observation("obs-1", 1_000_100, true, false))
        .unwrap();
    let log = session.logs().last().unwrap().clone();
    let json = serde_json::to_string(&log).expect("serialize");
    let recovered: BurnInLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(log, recovered);
}

// ────────────────────────────────────────────────────────────
// Rollback proof artifacts
// ────────────────────────────────────────────────────────────

#[test]
fn rollback_artifacts_complete_is_valid() {
    let artifacts = complete_rollback_artifacts();
    assert!(artifacts.is_complete());
}

#[test]
fn rollback_artifacts_incomplete_missing_receipt() {
    let mut artifacts = complete_rollback_artifacts();
    artifacts.transition_receipt_ref = None;
    assert!(!artifacts.is_complete());
}

#[test]
fn rollback_artifacts_incomplete_missing_rollback_command() {
    let mut artifacts = complete_rollback_artifacts();
    artifacts.rollback_command_tested = false;
    assert!(!artifacts.is_complete());
}

#[test]
fn rollback_artifacts_serde_round_trip() {
    let artifacts = complete_rollback_artifacts();
    let json = serde_json::to_string(&artifacts).expect("serialize");
    let recovered: RollbackProofArtifacts = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifacts, recovered);
}

// ────────────────────────────────────────────────────────────
// BurnInThresholds
// ────────────────────────────────────────────────────────────

#[test]
fn burn_in_thresholds_serde_round_trip() {
    let thresholds = BurnInThresholds::for_risk_class(ExtensionRiskClass::High);
    let json = serde_json::to_string(&thresholds).expect("serialize");
    let recovered: BurnInThresholds = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(thresholds, recovered);
}

#[test]
fn burn_in_thresholds_for_risk_class_all_valid() {
    for risk_class in [
        ExtensionRiskClass::Low,
        ExtensionRiskClass::Standard,
        ExtensionRiskClass::High,
    ] {
        let t = BurnInThresholds::for_risk_class(risk_class);
        assert!(t.min_shadow_success_millionths <= 1_000_000);
        assert!(t.max_false_deny_millionths <= 1_000_000);
        assert!(t.min_shadow_observations > 0);
    }
}

// ────────────────────────────────────────────────────────────
// BurnInError
// ────────────────────────────────────────────────────────────

#[test]
fn burn_in_error_serde_round_trip() {
    let errors = vec![
        BurnInError::InvalidConfig {
            detail: "bad threshold".to_string(),
        },
        BurnInError::InvalidObservation {
            detail: "non-monotonic".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(&err).expect("serialize");
        let recovered: BurnInError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, &recovered);
        assert!(!err.to_string().is_empty());
    }
}

// ────────────────────────────────────────────────────────────
// Promotion gate: insufficient observations
// ────────────────────────────────────────────────────────────

#[test]
fn promotion_gate_rejects_insufficient_observations() {
    let mut session = BurnInSession::new(session_config(), complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    // Only 3 observations, need 5
    for idx in 0..3 {
        session
            .record_shadow_observation(observation(
                &format!("obs-{idx}"),
                1_000_100 + (idx as u64) * 100,
                true,
                false,
            ))
            .unwrap();
    }

    let artifact = session.evaluate_promotion_gate(1_002_000).unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    assert!(
        artifact
            .failure_codes
            .contains(&BurnInFailureCode::InsufficientShadowObservations)
    );
}

// ────────────────────────────────────────────────────────────
// Promotion gate: insufficient duration
// ────────────────────────────────────────────────────────────

#[test]
fn promotion_gate_rejects_insufficient_duration() {
    let mut cfg = session_config();
    cfg.thresholds.min_shadow_duration_ns = 1_000_000;

    let mut session = BurnInSession::new(cfg, complete_rollback_artifacts()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    // All observations within a very short window
    for idx in 0..5 {
        session
            .record_shadow_observation(observation(
                &format!("obs-{idx}"),
                1_000_001 + idx as u64,
                true,
                false,
            ))
            .unwrap();
    }

    let artifact = session.evaluate_promotion_gate(1_000_010).unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    assert!(
        artifact
            .failure_codes
            .contains(&BurnInFailureCode::InsufficientShadowDuration)
    );
}

// ────────────────────────────────────────────────────────────
// Failure code error_code uniqueness
// ────────────────────────────────────────────────────────────

#[test]
fn failure_code_error_codes_are_unique() {
    let codes = [
        BurnInFailureCode::EarlyTerminationFalseDeny,
        BurnInFailureCode::InsufficientShadowDuration,
        BurnInFailureCode::InsufficientShadowObservations,
        BurnInFailureCode::ShadowSuccessRateBelowThreshold,
        BurnInFailureCode::FalseDenyEnvelopeExceeded,
        BurnInFailureCode::RollbackProofArtifactsMissing,
    ];
    let unique: std::collections::BTreeSet<&str> = codes.iter().map(|c| c.error_code()).collect();
    assert_eq!(unique.len(), codes.len());
}
