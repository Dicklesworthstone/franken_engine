//! Enrichment integration tests for `plas_burn_in_gate` — PearlTower 2026-02-27.
//!
//! Covers JSON field-name stability, serde roundtrips from evaluate paths,
//! error Display exact messages, Debug distinctness, lifecycle state-machine
//! edge cases, metric boundary conditions, decision-hash sensitivity,
//! scorecard snapshot accuracy, config validation, whitespace normalization,
//! log-event contract, and E2E pass-then-tamper-then-fail scenarios.

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

// ── helpers ──────────────────────────────────────────────────────────────

fn base_config() -> BurnInSessionConfig {
    BurnInSessionConfig {
        trace_id: "trace-enrich-001".to_string(),
        decision_id: "decision-enrich-001".to_string(),
        policy_id: "policy-enrich-v1".to_string(),
        extension_id: "extension://plas/enrich".to_string(),
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

fn complete_rollback() -> RollbackProofArtifacts {
    RollbackProofArtifacts {
        rollback_command_tested: true,
        previous_policy_snapshot_ref: Some("snapshot://policy/prev".to_string()),
        transition_receipt_signed: true,
        transition_receipt_ref: Some("receipt://transition/001".to_string()),
        rollback_token: Some(RollbackToken {
            previous_witness_hash: ContentHash::compute(b"prev-witness-enrich"),
            previous_witness_id: None,
            created_epoch: SecurityEpoch::from_raw(42),
            sequence: 7,
        }),
    }
}

fn obs(id: &str, ts: u64, success: bool, false_deny: bool) -> ShadowObservation {
    ShadowObservation {
        observation_id: id.to_string(),
        timestamp_ns: ts,
        success,
        false_deny,
    }
}

fn success_obs(id: &str, ts: u64) -> ShadowObservation {
    obs(id, ts, true, false)
}

/// Build a session in ShadowEvaluation with `n` success observations recorded.
fn session_with_observations(n: u64) -> BurnInSession {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    for i in 0..n {
        session
            .record_shadow_observation(success_obs(&format!("obs-{i}"), 1_000_100 + i * 100))
            .unwrap();
    }
    session
}

/// Build a session that passes promotion gate.
fn passing_session() -> (BurnInSession, BurnInDecisionArtifact) {
    let mut session = session_with_observations(10);
    let artifact = session.evaluate_promotion_gate(1_002_000).unwrap();
    (session, artifact)
}

// ── 1. JSON field-name stability ─────────────────────────────────────────

#[test]
fn json_fields_decision_artifact() {
    let (_, artifact) = passing_session();
    let json = serde_json::to_string(&artifact).unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_id",
        "risk_class",
        "lifecycle_state",
        "outcome",
        "failure_codes",
        "metrics",
        "thresholds",
        "rollback_artifacts_verified",
        "diagnostic_report",
        "decision_hash",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_log_event() {
    let (session, _) = passing_session();
    let log = &session.logs()[0];
    let json = serde_json::to_string(log).unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "lifecycle_state",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_metrics() {
    let (session, _) = passing_session();
    let json = serde_json::to_string(session.metrics()).unwrap();
    for key in [
        "started_at_ns",
        "latest_timestamp_ns",
        "total_observations",
        "successful_observations",
        "false_denies",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_thresholds() {
    let t = BurnInThresholds::for_risk_class(ExtensionRiskClass::High);
    let json = serde_json::to_string(&t).unwrap();
    for key in [
        "min_shadow_success_millionths",
        "max_false_deny_millionths",
        "min_shadow_duration_ns",
        "min_shadow_observations",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_session_config() {
    let cfg = base_config();
    let json = serde_json::to_string(&cfg).unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "extension_id",
        "risk_class",
        "thresholds",
        "shadow_start_timestamp_ns",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_rollback_proof_artifacts() {
    let a = complete_rollback();
    let json = serde_json::to_string(&a).unwrap();
    for key in [
        "rollback_command_tested",
        "previous_policy_snapshot_ref",
        "transition_receipt_signed",
        "transition_receipt_ref",
        "rollback_token",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_shadow_observation() {
    let o = success_obs("obs-x", 999);
    let json = serde_json::to_string(&o).unwrap();
    for key in ["observation_id", "timestamp_ns", "success", "false_deny"] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

#[test]
fn json_fields_scorecard_metrics() {
    let (session, _) = passing_session();
    let sc = session.scorecard_metrics();
    let json = serde_json::to_string(&sc).unwrap();
    for key in [
        "shadow_success_rate_millionths",
        "false_deny_rate_millionths",
        "rollback_artifacts_verified",
        "lifecycle_state",
    ] {
        assert!(json.contains(key), "missing field: {key}");
    }
}

// ── 2. Serde roundtrips from evaluate paths ──────────────────────────────

#[test]
fn serde_roundtrip_passing_artifact() {
    let (_, artifact) = passing_session();
    let json = serde_json::to_string(&artifact).unwrap();
    let back: BurnInDecisionArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn serde_roundtrip_failing_artifact() {
    let mut cfg = base_config();
    cfg.thresholds.min_shadow_observations = 100_000; // will not reach
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(success_obs("obs-1", 1_000_100))
        .unwrap();
    let artifact = session.evaluate_promotion_gate(1_000_200).unwrap();
    assert_eq!(artifact.outcome, "fail");
    let json = serde_json::to_string(&artifact).unwrap();
    let back: BurnInDecisionArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn serde_roundtrip_early_termination_artifact() {
    let mut cfg = base_config();
    cfg.thresholds.max_false_deny_millionths = 0;
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    let artifact = session
        .record_shadow_observation(obs("obs-et", 1_000_100, false, true))
        .unwrap()
        .expect("early termination");
    let json = serde_json::to_string(&artifact).unwrap();
    let back: BurnInDecisionArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

// ── 3. Session serde at various lifecycle states ─────────────────────────

#[test]
fn session_serde_at_shadow_start() {
    let session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::ShadowStart);
    let json = serde_json::to_string(&session).unwrap();
    let back: BurnInSession = serde_json::from_str(&json).unwrap();
    assert_eq!(session, back);
}

#[test]
fn session_serde_at_shadow_evaluation() {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    let json = serde_json::to_string(&session).unwrap();
    let back: BurnInSession = serde_json::from_str(&json).unwrap();
    assert_eq!(session, back);
}

#[test]
fn session_serde_at_auto_enforcement() {
    let (session, _) = passing_session();
    assert_eq!(
        session.lifecycle_state(),
        BurnInLifecycleState::AutoEnforcement
    );
    let json = serde_json::to_string(&session).unwrap();
    let back: BurnInSession = serde_json::from_str(&json).unwrap();
    assert_eq!(session, back);
}

#[test]
fn session_serde_at_rejection() {
    let mut cfg = base_config();
    cfg.thresholds.max_false_deny_millionths = 0;
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(obs("obs-1", 1_000_100, false, true))
        .unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    let json = serde_json::to_string(&session).unwrap();
    let back: BurnInSession = serde_json::from_str(&json).unwrap();
    assert_eq!(session, back);
}

// ── 4. Error Display exact messages ──────────────────────────────────────

#[test]
fn error_display_invalid_config_exact() {
    let err = BurnInError::InvalidConfig {
        detail: "x".to_string(),
    };
    assert_eq!(format!("{err}"), "invalid burn-in config: x");
}

#[test]
fn error_display_invalid_observation_exact() {
    let err = BurnInError::InvalidObservation {
        detail: "y".to_string(),
    };
    assert_eq!(format!("{err}"), "invalid burn-in observation: y");
}

#[test]
fn error_display_invalid_transition_exact() {
    let err = BurnInError::InvalidTransition {
        from: BurnInLifecycleState::ShadowStart,
        to: BurnInLifecycleState::AutoEnforcement,
    };
    assert_eq!(
        format!("{err}"),
        "invalid burn-in lifecycle transition: shadow_start -> auto_enforcement"
    );
}

#[test]
fn error_display_non_monotonic_exact() {
    let err = BurnInError::NonMonotonicTimestamp {
        previous_ns: 500,
        observed_ns: 100,
    };
    assert_eq!(
        format!("{err}"),
        "non-monotonic timestamp: previous=500, observed=100"
    );
}

#[test]
fn error_implements_std_error() {
    let err = BurnInError::InvalidConfig {
        detail: "test".to_string(),
    };
    let e: &dyn std::error::Error = &err;
    assert!(!e.to_string().is_empty());
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let variants = vec![
        BurnInError::InvalidConfig {
            detail: "cfg".into(),
        },
        BurnInError::InvalidObservation {
            detail: "obs".into(),
        },
        BurnInError::InvalidTransition {
            from: BurnInLifecycleState::ShadowEvaluation,
            to: BurnInLifecycleState::ShadowStart,
        },
        BurnInError::NonMonotonicTimestamp {
            previous_ns: 999,
            observed_ns: 1,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: BurnInError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ── 5. Debug distinctness ────────────────────────────────────────────────

#[test]
fn debug_distinct_risk_class() {
    let variants = [
        ExtensionRiskClass::Low,
        ExtensionRiskClass::Standard,
        ExtensionRiskClass::High,
    ];
    let debugs: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn debug_distinct_lifecycle_state() {
    let variants = [
        BurnInLifecycleState::ShadowStart,
        BurnInLifecycleState::ShadowEvaluation,
        BurnInLifecycleState::PromotionGate,
        BurnInLifecycleState::AutoEnforcement,
        BurnInLifecycleState::Rejection,
    ];
    let debugs: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn debug_distinct_failure_code() {
    let variants = [
        BurnInFailureCode::EarlyTerminationFalseDeny,
        BurnInFailureCode::InsufficientShadowDuration,
        BurnInFailureCode::InsufficientShadowObservations,
        BurnInFailureCode::ShadowSuccessRateBelowThreshold,
        BurnInFailureCode::FalseDenyEnvelopeExceeded,
        BurnInFailureCode::RollbackProofArtifactsMissing,
    ];
    let debugs: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn debug_distinct_error_variants() {
    let variants: Vec<BurnInError> = vec![
        BurnInError::InvalidConfig { detail: "a".into() },
        BurnInError::InvalidObservation { detail: "a".into() },
        BurnInError::InvalidTransition {
            from: BurnInLifecycleState::ShadowStart,
            to: BurnInLifecycleState::Rejection,
        },
        BurnInError::NonMonotonicTimestamp {
            previous_ns: 1,
            observed_ns: 0,
        },
    ];
    let debugs: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

// ── 6. Serde exact values for enums ──────────────────────────────────────

#[test]
fn serde_exact_risk_class_values() {
    assert_eq!(
        serde_json::to_string(&ExtensionRiskClass::Low).unwrap(),
        "\"low\""
    );
    assert_eq!(
        serde_json::to_string(&ExtensionRiskClass::Standard).unwrap(),
        "\"standard\""
    );
    assert_eq!(
        serde_json::to_string(&ExtensionRiskClass::High).unwrap(),
        "\"high\""
    );
}

#[test]
fn serde_exact_lifecycle_state_values() {
    assert_eq!(
        serde_json::to_string(&BurnInLifecycleState::ShadowStart).unwrap(),
        "\"shadow_start\""
    );
    assert_eq!(
        serde_json::to_string(&BurnInLifecycleState::ShadowEvaluation).unwrap(),
        "\"shadow_evaluation\""
    );
    assert_eq!(
        serde_json::to_string(&BurnInLifecycleState::PromotionGate).unwrap(),
        "\"promotion_gate\""
    );
    assert_eq!(
        serde_json::to_string(&BurnInLifecycleState::AutoEnforcement).unwrap(),
        "\"auto_enforcement\""
    );
    assert_eq!(
        serde_json::to_string(&BurnInLifecycleState::Rejection).unwrap(),
        "\"rejection\""
    );
}

#[test]
fn serde_exact_failure_code_values() {
    assert_eq!(
        serde_json::to_string(&BurnInFailureCode::EarlyTerminationFalseDeny).unwrap(),
        "\"early_termination_false_deny\""
    );
    assert_eq!(
        serde_json::to_string(&BurnInFailureCode::InsufficientShadowDuration).unwrap(),
        "\"insufficient_shadow_duration\""
    );
    assert_eq!(
        serde_json::to_string(&BurnInFailureCode::InsufficientShadowObservations).unwrap(),
        "\"insufficient_shadow_observations\""
    );
    assert_eq!(
        serde_json::to_string(&BurnInFailureCode::ShadowSuccessRateBelowThreshold).unwrap(),
        "\"shadow_success_rate_below_threshold\""
    );
    assert_eq!(
        serde_json::to_string(&BurnInFailureCode::FalseDenyEnvelopeExceeded).unwrap(),
        "\"false_deny_envelope_exceeded\""
    );
    assert_eq!(
        serde_json::to_string(&BurnInFailureCode::RollbackProofArtifactsMissing).unwrap(),
        "\"rollback_proof_artifacts_missing\""
    );
}

// ── 7. Failure code Display equals error_code ────────────────────────────

#[test]
fn failure_code_display_matches_error_code_all() {
    let all = [
        BurnInFailureCode::EarlyTerminationFalseDeny,
        BurnInFailureCode::InsufficientShadowDuration,
        BurnInFailureCode::InsufficientShadowObservations,
        BurnInFailureCode::ShadowSuccessRateBelowThreshold,
        BurnInFailureCode::FalseDenyEnvelopeExceeded,
        BurnInFailureCode::RollbackProofArtifactsMissing,
    ];
    for code in &all {
        assert_eq!(format!("{code}"), code.error_code());
    }
}

// ── 8. Lifecycle is_terminal ─────────────────────────────────────────────

#[test]
fn lifecycle_is_terminal_comprehensive() {
    assert!(!BurnInLifecycleState::ShadowStart.is_terminal());
    assert!(!BurnInLifecycleState::ShadowEvaluation.is_terminal());
    assert!(!BurnInLifecycleState::PromotionGate.is_terminal());
    assert!(BurnInLifecycleState::AutoEnforcement.is_terminal());
    assert!(BurnInLifecycleState::Rejection.is_terminal());
}

// ── 9. Config validation boundary conditions ─────────────────────────────

#[test]
fn config_whitespace_only_trace_id_rejected() {
    let mut cfg = base_config();
    cfg.trace_id = "   ".to_string();
    let err = BurnInSession::new(cfg, complete_rollback()).unwrap_err();
    assert!(format!("{err}").contains("trace_id"));
}

#[test]
fn config_whitespace_only_decision_id_rejected() {
    let mut cfg = base_config();
    cfg.decision_id = "   ".to_string();
    let err = BurnInSession::new(cfg, complete_rollback()).unwrap_err();
    assert!(format!("{err}").contains("decision_id"));
}

#[test]
fn config_whitespace_only_policy_id_rejected() {
    let mut cfg = base_config();
    cfg.policy_id = "   ".to_string();
    let err = BurnInSession::new(cfg, complete_rollback()).unwrap_err();
    assert!(format!("{err}").contains("policy_id"));
}

#[test]
fn config_whitespace_only_extension_id_rejected() {
    let mut cfg = base_config();
    cfg.extension_id = "   ".to_string();
    let err = BurnInSession::new(cfg, complete_rollback()).unwrap_err();
    assert!(format!("{err}").contains("extension_id"));
}

#[test]
fn config_padded_ids_normalize_and_pass() {
    let mut cfg = base_config();
    cfg.trace_id = "  trace-padded  ".to_string();
    cfg.decision_id = "  dec-padded  ".to_string();
    cfg.policy_id = "  pol-padded  ".to_string();
    cfg.extension_id = "  ext-padded  ".to_string();
    let session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    let log = &session.logs()[0];
    assert_eq!(log.trace_id, "trace-padded");
    assert_eq!(log.decision_id, "dec-padded");
    assert_eq!(log.policy_id, "pol-padded");
}

#[test]
fn thresholds_success_at_boundary_million() {
    let cfg = BurnInSessionConfig {
        thresholds: BurnInThresholds {
            min_shadow_success_millionths: 1_000_000,
            max_false_deny_millionths: 1_000_000,
            min_shadow_duration_ns: 1,
            min_shadow_observations: 1,
        },
        ..base_config()
    };
    // Should succeed — boundary values are valid
    let _ = BurnInSession::new(cfg, complete_rollback()).unwrap();
}

#[test]
fn thresholds_success_just_over_million_rejected() {
    let mut cfg = base_config();
    cfg.thresholds.min_shadow_success_millionths = 1_000_001;
    let err = BurnInSession::new(cfg, complete_rollback()).unwrap_err();
    assert!(format!("{err}").contains("min_shadow_success_millionths"));
}

#[test]
fn thresholds_false_deny_just_over_million_rejected() {
    let mut cfg = base_config();
    cfg.thresholds.max_false_deny_millionths = 1_000_001;
    let err = BurnInSession::new(cfg, complete_rollback()).unwrap_err();
    assert!(format!("{err}").contains("max_false_deny_millionths"));
}

#[test]
fn thresholds_zero_duration_rejected() {
    let mut cfg = base_config();
    cfg.thresholds.min_shadow_duration_ns = 0;
    let err = BurnInSession::new(cfg, complete_rollback()).unwrap_err();
    assert!(format!("{err}").contains("min_shadow_duration_ns"));
}

#[test]
fn thresholds_zero_observations_rejected() {
    let mut cfg = base_config();
    cfg.thresholds.min_shadow_observations = 0;
    let err = BurnInSession::new(cfg, complete_rollback()).unwrap_err();
    assert!(format!("{err}").contains("min_shadow_observations"));
}

// ── 10. Observation validation ───────────────────────────────────────────

#[test]
fn observation_whitespace_only_id_rejected() {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    let err = session
        .record_shadow_observation(obs("   ", 1_000_100, true, false))
        .unwrap_err();
    assert!(format!("{err}").contains("observation_id"));
}

#[test]
fn observation_padded_id_normalizes() {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    // " obs-1 " normalizes to "obs-1" which is valid
    let result = session
        .record_shadow_observation(obs("  obs-1  ", 1_000_100, true, false))
        .unwrap();
    assert!(result.is_none());
}

// ── 11. State machine invalid transitions ────────────────────────────────

#[test]
fn observation_in_shadow_start_rejected() {
    let session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    let mut session = session;
    let err = session
        .record_shadow_observation(success_obs("obs-1", 2_000_000))
        .unwrap_err();
    match err {
        BurnInError::InvalidTransition { from, to } => {
            assert_eq!(from, BurnInLifecycleState::ShadowStart);
            assert_eq!(to, BurnInLifecycleState::ShadowEvaluation);
        }
        other => panic!("expected InvalidTransition, got {other:?}"),
    }
}

#[test]
fn promotion_gate_in_shadow_start_rejected() {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    let err = session.evaluate_promotion_gate(2_000_000).unwrap_err();
    match err {
        BurnInError::InvalidTransition { from, to } => {
            assert_eq!(from, BurnInLifecycleState::ShadowStart);
            assert_eq!(to, BurnInLifecycleState::PromotionGate);
        }
        other => panic!("expected InvalidTransition, got {other:?}"),
    }
}

#[test]
fn observation_after_promotion_rejected() {
    let (mut session, _) = passing_session();
    let err = session
        .record_shadow_observation(success_obs("obs-late", 9_000_000))
        .unwrap_err();
    assert!(matches!(err, BurnInError::InvalidTransition { .. }));
}

#[test]
fn promotion_gate_after_promotion_rejected() {
    let (mut session, _) = passing_session();
    let err = session.evaluate_promotion_gate(9_000_000).unwrap_err();
    assert!(matches!(err, BurnInError::InvalidTransition { .. }));
}

#[test]
fn observation_after_early_termination_rejected() {
    let mut cfg = base_config();
    cfg.thresholds.max_false_deny_millionths = 0;
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(obs("obs-1", 1_000_100, false, true))
        .unwrap();
    assert_eq!(session.lifecycle_state(), BurnInLifecycleState::Rejection);
    let err = session
        .record_shadow_observation(success_obs("obs-2", 1_000_200))
        .unwrap_err();
    assert!(matches!(err, BurnInError::InvalidTransition { .. }));
}

#[test]
fn double_begin_shadow_evaluation_rejected() {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    let err = session.begin_shadow_evaluation().unwrap_err();
    assert!(matches!(err, BurnInError::InvalidTransition { .. }));
}

// ── 12. Non-monotonic timestamps ─────────────────────────────────────────

#[test]
fn non_monotonic_observation_exact_values() {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(success_obs("obs-1", 2_000_000))
        .unwrap();
    let err = session
        .record_shadow_observation(success_obs("obs-2", 1_500_000))
        .unwrap_err();
    match err {
        BurnInError::NonMonotonicTimestamp {
            previous_ns,
            observed_ns,
        } => {
            assert_eq!(previous_ns, 2_000_000);
            assert_eq!(observed_ns, 1_500_000);
        }
        other => panic!("expected NonMonotonicTimestamp, got {other:?}"),
    }
}

#[test]
fn non_monotonic_promotion_gate_timestamp() {
    let mut session = session_with_observations(5);
    // latest is 1_000_100 + 4*100 = 1_000_500
    let err = session.evaluate_promotion_gate(1_000_000).unwrap_err();
    match err {
        BurnInError::NonMonotonicTimestamp {
            previous_ns,
            observed_ns,
        } => {
            assert_eq!(previous_ns, 1_000_500);
            assert_eq!(observed_ns, 1_000_000);
        }
        other => panic!("expected NonMonotonicTimestamp, got {other:?}"),
    }
}

#[test]
fn equal_timestamp_observation_accepted() {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(success_obs("obs-1", 1_000_100))
        .unwrap();
    // Same timestamp is NOT strictly less, so it should be accepted
    let result = session
        .record_shadow_observation(success_obs("obs-2", 1_000_100))
        .unwrap();
    assert!(result.is_none());
}

// ── 13. Risk class thresholds strictness ordering ────────────────────────

#[test]
fn risk_class_strictness_monotonic() {
    let low = BurnInThresholds::for_risk_class(ExtensionRiskClass::Low);
    let std = BurnInThresholds::for_risk_class(ExtensionRiskClass::Standard);
    let high = BurnInThresholds::for_risk_class(ExtensionRiskClass::High);

    // Higher risk → higher required success rate
    assert!(low.min_shadow_success_millionths < std.min_shadow_success_millionths);
    assert!(std.min_shadow_success_millionths < high.min_shadow_success_millionths);

    // Higher risk → lower allowed false-deny rate
    assert!(low.max_false_deny_millionths > std.max_false_deny_millionths);
    assert!(std.max_false_deny_millionths > high.max_false_deny_millionths);

    // Higher risk → longer required shadow duration
    assert!(low.min_shadow_duration_ns < std.min_shadow_duration_ns);
    assert!(std.min_shadow_duration_ns < high.min_shadow_duration_ns);

    // Higher risk → more required observations
    assert!(low.min_shadow_observations < std.min_shadow_observations);
    assert!(std.min_shadow_observations < high.min_shadow_observations);
}

// ── 14. Decision hash sensitivity ────────────────────────────────────────

#[test]
fn decision_hash_deterministic_across_runs() {
    let hash1 = {
        let (_, a) = passing_session();
        a.decision_hash
    };
    let hash2 = {
        let (_, a) = passing_session();
        a.decision_hash
    };
    assert_eq!(hash1, hash2);
}

#[test]
fn decision_hash_sensitive_to_trace_id() {
    let hash1 = {
        let (_, a) = passing_session();
        a.decision_hash
    };
    let hash2 = {
        let mut cfg = base_config();
        cfg.trace_id = "trace-enrich-002".to_string();
        let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
        session.begin_shadow_evaluation().unwrap();
        for i in 0..10u64 {
            session
                .record_shadow_observation(success_obs(&format!("obs-{i}"), 1_000_100 + i * 100))
                .unwrap();
        }
        session
            .evaluate_promotion_gate(1_002_000)
            .unwrap()
            .decision_hash
    };
    assert_ne!(hash1, hash2);
}

#[test]
fn decision_hash_sensitive_to_policy_id() {
    let hash1 = {
        let (_, a) = passing_session();
        a.decision_hash
    };
    let hash2 = {
        let mut cfg = base_config();
        cfg.policy_id = "policy-enrich-v2".to_string();
        let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
        session.begin_shadow_evaluation().unwrap();
        for i in 0..10u64 {
            session
                .record_shadow_observation(success_obs(&format!("obs-{i}"), 1_000_100 + i * 100))
                .unwrap();
        }
        session
            .evaluate_promotion_gate(1_002_000)
            .unwrap()
            .decision_hash
    };
    assert_ne!(hash1, hash2);
}

#[test]
fn decision_hash_sensitive_to_outcome() {
    let pass_hash = {
        let (_, a) = passing_session();
        a.decision_hash
    };
    let fail_hash = {
        let mut cfg = base_config();
        cfg.thresholds.min_shadow_observations = 100_000;
        let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
        session.begin_shadow_evaluation().unwrap();
        for i in 0..10u64 {
            session
                .record_shadow_observation(success_obs(&format!("obs-{i}"), 1_000_100 + i * 100))
                .unwrap();
        }
        session
            .evaluate_promotion_gate(1_002_000)
            .unwrap()
            .decision_hash
    };
    assert_ne!(pass_hash, fail_hash);
}

// ── 15. Metrics computation ──────────────────────────────────────────────

#[test]
fn metrics_after_mixed_observations() {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    // 3 successes, 1 failure (not false-deny), 1 success
    session
        .record_shadow_observation(success_obs("o1", 1_000_100))
        .unwrap();
    session
        .record_shadow_observation(success_obs("o2", 1_000_200))
        .unwrap();
    session
        .record_shadow_observation(success_obs("o3", 1_000_300))
        .unwrap();
    session
        .record_shadow_observation(obs("o4", 1_000_400, false, false))
        .unwrap();
    session
        .record_shadow_observation(success_obs("o5", 1_000_500))
        .unwrap();

    let m = session.metrics();
    assert_eq!(m.total_observations, 5);
    assert_eq!(m.successful_observations, 4);
    assert_eq!(m.false_denies, 0);
    // 4/5 = 800_000 millionths
    assert_eq!(m.shadow_success_rate_millionths(), 800_000);
    assert_eq!(m.false_deny_rate_millionths(), 0);
    assert_eq!(m.elapsed_ns(), 1_000_500 - 1_000_000);
}

#[test]
fn metrics_all_false_denies() {
    let mut cfg = base_config();
    cfg.thresholds.max_false_deny_millionths = 1_000_000; // allow all
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    for i in 0..5u64 {
        session
            .record_shadow_observation(obs(&format!("o{i}"), 1_000_100 + i * 100, false, true))
            .unwrap();
    }
    let m = session.metrics();
    assert_eq!(m.total_observations, 5);
    assert_eq!(m.successful_observations, 0);
    assert_eq!(m.false_denies, 5);
    assert_eq!(m.shadow_success_rate_millionths(), 0);
    assert_eq!(m.false_deny_rate_millionths(), 1_000_000);
}

#[test]
fn metrics_single_observation() {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(success_obs("o1", 1_000_100))
        .unwrap();
    let m = session.metrics();
    assert_eq!(m.shadow_success_rate_millionths(), 1_000_000);
    assert_eq!(m.false_deny_rate_millionths(), 0);
}

// ── 16. Scorecard metrics snapshots ──────────────────────────────────────

#[test]
fn scorecard_at_shadow_start() {
    let session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    let sc = session.scorecard_metrics();
    assert_eq!(sc.shadow_success_rate_millionths, 0);
    assert_eq!(sc.false_deny_rate_millionths, 0);
    assert!(sc.rollback_artifacts_verified);
    assert_eq!(sc.lifecycle_state, BurnInLifecycleState::ShadowStart);
}

#[test]
fn scorecard_during_evaluation() {
    let session = session_with_observations(5);
    let sc = session.scorecard_metrics();
    assert_eq!(sc.shadow_success_rate_millionths, 1_000_000);
    assert_eq!(sc.false_deny_rate_millionths, 0);
    assert!(sc.rollback_artifacts_verified);
    assert_eq!(sc.lifecycle_state, BurnInLifecycleState::ShadowEvaluation);
}

#[test]
fn scorecard_incomplete_rollback() {
    let session = BurnInSession::new(base_config(), RollbackProofArtifacts::default()).unwrap();
    let sc = session.scorecard_metrics();
    assert!(!sc.rollback_artifacts_verified);
}

#[test]
fn scorecard_serde_roundtrip() {
    let sc = BurnInScorecardMetrics {
        shadow_success_rate_millionths: 950_000,
        false_deny_rate_millionths: 5_000,
        rollback_artifacts_verified: true,
        lifecycle_state: BurnInLifecycleState::PromotionGate,
    };
    let json = serde_json::to_string(&sc).unwrap();
    let back: BurnInScorecardMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(sc, back);
}

// ── 17. RollbackProofArtifacts edge cases ────────────────────────────────

#[test]
fn rollback_normalize_whitespace_only_becomes_none() {
    let mut a = complete_rollback();
    a.previous_policy_snapshot_ref = Some("   ".to_string());
    a.transition_receipt_ref = Some("\t\n".to_string());
    // After session creation (which normalizes), these become None → incomplete
    let session = BurnInSession::new(base_config(), a).unwrap();
    assert!(!session.scorecard_metrics().rollback_artifacts_verified);
}

#[test]
fn rollback_default_is_incomplete() {
    let a = RollbackProofArtifacts::default();
    assert!(!a.is_complete());
    assert!(!a.rollback_command_tested);
    assert!(a.previous_policy_snapshot_ref.is_none());
    assert!(!a.transition_receipt_signed);
    assert!(a.transition_receipt_ref.is_none());
    assert!(a.rollback_token.is_none());
}

#[test]
fn rollback_serde_roundtrip_complete() {
    let a = complete_rollback();
    let json = serde_json::to_string(&a).unwrap();
    let back: RollbackProofArtifacts = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn rollback_serde_roundtrip_default() {
    let a = RollbackProofArtifacts::default();
    let json = serde_json::to_string(&a).unwrap();
    let back: RollbackProofArtifacts = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// ── 18. Log event contract ───────────────────────────────────────────────

#[test]
fn log_component_always_plas_burn_in_gate() {
    let (session, _) = passing_session();
    for log in session.logs() {
        assert_eq!(log.component, "plas_burn_in_gate");
    }
}

#[test]
fn log_trace_id_consistent() {
    let (session, _) = passing_session();
    for log in session.logs() {
        assert_eq!(log.trace_id, "trace-enrich-001");
    }
}

#[test]
fn log_first_event_is_shadow_start() {
    let session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    assert_eq!(session.logs().len(), 1);
    assert_eq!(session.logs()[0].event, "shadow_start");
    assert_eq!(session.logs()[0].outcome, "pass");
    assert!(session.logs()[0].error_code.is_none());
}

#[test]
fn log_second_event_is_shadow_evaluation() {
    let mut session = BurnInSession::new(base_config(), complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    assert_eq!(session.logs().len(), 2);
    assert_eq!(session.logs()[1].event, "shadow_evaluation");
    assert_eq!(session.logs()[1].outcome, "pass");
}

#[test]
fn log_observation_recorded_events() {
    let session = session_with_observations(3);
    // shadow_start + shadow_evaluation + 3 observations = 5
    assert_eq!(session.logs().len(), 5);
    for log in &session.logs()[2..5] {
        assert_eq!(log.event, "shadow_observation_recorded");
        assert_eq!(log.outcome, "pass");
        assert!(log.error_code.is_none());
    }
}

#[test]
fn log_promotion_gate_pass_event() {
    let (session, _) = passing_session();
    let last = session.logs().last().unwrap();
    assert_eq!(last.event, "promotion_gate");
    assert_eq!(last.outcome, "pass");
    assert!(last.error_code.is_none());
    assert_eq!(last.lifecycle_state, BurnInLifecycleState::AutoEnforcement);
}

#[test]
fn log_promotion_gate_fail_event_has_error_code() {
    let mut cfg = base_config();
    cfg.thresholds.min_shadow_observations = 100_000;
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(success_obs("o1", 1_000_100))
        .unwrap();
    session.evaluate_promotion_gate(1_000_200).unwrap();
    let last = session.logs().last().unwrap();
    assert_eq!(last.event, "promotion_gate");
    assert_eq!(last.outcome, "fail");
    assert!(last.error_code.is_some());
    assert_eq!(last.lifecycle_state, BurnInLifecycleState::Rejection);
}

#[test]
fn log_early_termination_event() {
    let mut cfg = base_config();
    cfg.thresholds.max_false_deny_millionths = 0;
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(obs("obs-1", 1_000_100, false, true))
        .unwrap();
    let last = session.logs().last().unwrap();
    assert_eq!(last.event, "shadow_evaluation");
    assert_eq!(last.outcome, "fail");
    assert_eq!(
        last.error_code.as_deref(),
        Some("early_termination_false_deny")
    );
    assert_eq!(last.lifecycle_state, BurnInLifecycleState::Rejection);
}

// ── 19. Multiple failure codes in gate ───────────────────────────────────

#[test]
fn multiple_failure_codes_sorted_and_deduped() {
    let mut cfg = base_config();
    cfg.thresholds = BurnInThresholds {
        min_shadow_success_millionths: 999_999,
        max_false_deny_millionths: 0,
        min_shadow_duration_ns: u64::MAX,
        min_shadow_observations: u64::MAX,
    };
    let mut session = BurnInSession::new(cfg, RollbackProofArtifacts::default()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(success_obs("o1", 1_000_100))
        .unwrap();
    let artifact = session.evaluate_promotion_gate(1_000_200).unwrap();

    // Should have multiple failure codes
    assert!(artifact.failure_codes.len() >= 3);

    // Verify sorted (Ord on BurnInFailureCode)
    for window in artifact.failure_codes.windows(2) {
        assert!(window[0] <= window[1], "failure codes not sorted");
    }
}

#[test]
fn four_gate_failure_codes_when_all_applicable_fail() {
    // FalseDenyEnvelopeExceeded is unreachable at the promotion gate:
    // if the false-deny rate exceeds the threshold during observation
    // recording, early termination fires first. So the maximum reachable
    // failure codes at the gate are 4 (duration, observations, success rate,
    // rollback artifacts).
    let mut cfg = base_config();
    cfg.thresholds = BurnInThresholds {
        min_shadow_success_millionths: 999_999,
        max_false_deny_millionths: 1_000_000, // high to avoid early termination
        min_shadow_duration_ns: u64::MAX,
        min_shadow_observations: u64::MAX,
    };
    let mut session = BurnInSession::new(cfg, RollbackProofArtifacts::default()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    session
        .record_shadow_observation(obs("o1", 1_000_100, false, false))
        .unwrap();
    let artifact = session.evaluate_promotion_gate(1_000_200).unwrap();

    assert_eq!(artifact.failure_codes.len(), 4);
    assert!(
        artifact
            .failure_codes
            .contains(&BurnInFailureCode::InsufficientShadowDuration)
    );
    assert!(
        artifact
            .failure_codes
            .contains(&BurnInFailureCode::InsufficientShadowObservations)
    );
    assert!(
        artifact
            .failure_codes
            .contains(&BurnInFailureCode::ShadowSuccessRateBelowThreshold)
    );
    assert!(
        artifact
            .failure_codes
            .contains(&BurnInFailureCode::RollbackProofArtifactsMissing)
    );
}

// ── 20. Full E2E with each risk class ────────────────────────────────────

fn run_full_lifecycle_with_risk_class(risk_class: ExtensionRiskClass) -> BurnInDecisionArtifact {
    let thresholds = BurnInThresholds::for_risk_class(risk_class);
    let obs_count = thresholds.min_shadow_observations;
    let duration_ns = thresholds.min_shadow_duration_ns;

    let cfg = BurnInSessionConfig {
        trace_id: format!("trace-{}", risk_class.as_str()),
        decision_id: format!("dec-{}", risk_class.as_str()),
        policy_id: "policy-risk-test".to_string(),
        extension_id: format!("ext-{}", risk_class.as_str()),
        risk_class,
        thresholds,
        shadow_start_timestamp_ns: 1_000,
    };
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();

    let step = duration_ns / obs_count + 1;
    for i in 0..obs_count {
        session
            .record_shadow_observation(success_obs(&format!("obs-{i}"), 1_000 + (i + 1) * step))
            .unwrap();
    }

    let eval_ts = 1_000 + (obs_count + 1) * step;
    session.evaluate_promotion_gate(eval_ts).unwrap()
}

#[test]
fn full_lifecycle_low_risk_passes() {
    let artifact = run_full_lifecycle_with_risk_class(ExtensionRiskClass::Low);
    assert_eq!(artifact.outcome, "pass");
    assert_eq!(artifact.risk_class, ExtensionRiskClass::Low);
    assert_eq!(
        artifact.lifecycle_state,
        BurnInLifecycleState::AutoEnforcement
    );
}

#[test]
fn full_lifecycle_standard_risk_passes() {
    let artifact = run_full_lifecycle_with_risk_class(ExtensionRiskClass::Standard);
    assert_eq!(artifact.outcome, "pass");
    assert_eq!(artifact.risk_class, ExtensionRiskClass::Standard);
}

#[test]
fn full_lifecycle_high_risk_passes() {
    let artifact = run_full_lifecycle_with_risk_class(ExtensionRiskClass::High);
    assert_eq!(artifact.outcome, "pass");
    assert_eq!(artifact.risk_class, ExtensionRiskClass::High);
}

// ── 21. E2E pass-then-tamper ─────────────────────────────────────────────

#[test]
fn e2e_pass_then_tamper_rollback_fails() {
    // First run passes
    let (_, artifact1) = passing_session();
    assert_eq!(artifact1.outcome, "pass");

    // Same config but with incomplete rollback → fails
    let mut session = BurnInSession::new(base_config(), RollbackProofArtifacts::default()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    for i in 0..10u64 {
        session
            .record_shadow_observation(success_obs(&format!("obs-{i}"), 1_000_100 + i * 100))
            .unwrap();
    }
    let artifact2 = session.evaluate_promotion_gate(1_002_000).unwrap();
    assert_eq!(artifact2.outcome, "fail");
    assert!(
        artifact2
            .failure_codes
            .contains(&BurnInFailureCode::RollbackProofArtifactsMissing)
    );
    assert_ne!(artifact1.decision_hash, artifact2.decision_hash);
}

// ── 22. Decision artifact field values ───────────────────────────────────

#[test]
fn passing_artifact_fields_match_config() {
    let (_, artifact) = passing_session();
    assert_eq!(artifact.trace_id, "trace-enrich-001");
    assert_eq!(artifact.decision_id, "decision-enrich-001");
    assert_eq!(artifact.policy_id, "policy-enrich-v1");
    assert_eq!(artifact.extension_id, "extension://plas/enrich");
    assert_eq!(artifact.risk_class, ExtensionRiskClass::Standard);
    assert_eq!(artifact.outcome, "pass");
    assert!(artifact.failure_codes.is_empty());
    assert!(artifact.rollback_artifacts_verified);
    assert!(artifact.diagnostic_report.is_none());
    assert!(!artifact.decision_hash.as_bytes().is_empty());
}

#[test]
fn early_termination_artifact_has_diagnostic() {
    let mut cfg = base_config();
    cfg.thresholds.max_false_deny_millionths = 0;
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    let artifact = session
        .record_shadow_observation(obs("obs-et", 1_000_100, false, true))
        .unwrap()
        .unwrap();
    assert!(artifact.diagnostic_report.is_some());
    assert!(
        artifact
            .diagnostic_report
            .as_ref()
            .unwrap()
            .contains("false-deny envelope exceeded")
    );
}

#[test]
fn failing_artifact_has_correct_metrics() {
    let mut cfg = base_config();
    cfg.thresholds.min_shadow_observations = 100_000;
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    for i in 0..5u64 {
        session
            .record_shadow_observation(success_obs(&format!("obs-{i}"), 1_000_100 + i * 100))
            .unwrap();
    }
    let artifact = session.evaluate_promotion_gate(1_000_600).unwrap();
    assert_eq!(artifact.metrics.total_observations, 5);
    assert_eq!(artifact.metrics.successful_observations, 5);
    assert_eq!(artifact.metrics.false_denies, 0);
}

// ── 23. Decision artifact accessor ───────────────────────────────────────

#[test]
fn decision_artifact_none_before_terminal() {
    let session = session_with_observations(3);
    assert!(session.decision_artifact().is_none());
}

#[test]
fn decision_artifact_some_after_promotion() {
    let (session, artifact) = passing_session();
    let stored = session.decision_artifact().unwrap();
    assert_eq!(*stored, artifact);
}

#[test]
fn decision_artifact_some_after_early_termination() {
    let mut cfg = base_config();
    cfg.thresholds.max_false_deny_millionths = 0;
    let mut session = BurnInSession::new(cfg, complete_rollback()).unwrap();
    session.begin_shadow_evaluation().unwrap();
    let returned = session
        .record_shadow_observation(obs("obs-1", 1_000_100, false, true))
        .unwrap()
        .unwrap();
    let stored = session.decision_artifact().unwrap();
    assert_eq!(*stored, returned);
}

// ── 24. Thresholds serde roundtrip for each risk class ───────────────────

#[test]
fn thresholds_serde_roundtrip_low() {
    let t = BurnInThresholds::for_risk_class(ExtensionRiskClass::Low);
    let json = serde_json::to_string(&t).unwrap();
    let back: BurnInThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn thresholds_serde_roundtrip_standard() {
    let t = BurnInThresholds::for_risk_class(ExtensionRiskClass::Standard);
    let json = serde_json::to_string(&t).unwrap();
    let back: BurnInThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn thresholds_serde_roundtrip_high() {
    let t = BurnInThresholds::for_risk_class(ExtensionRiskClass::High);
    let json = serde_json::to_string(&t).unwrap();
    let back: BurnInThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ── 25. Log event serde ──────────────────────────────────────────────────

#[test]
fn log_event_serde_with_error_code() {
    let le = BurnInLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "plas_burn_in_gate".to_string(),
        event: "shadow_evaluation".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("early_termination_false_deny".to_string()),
        lifecycle_state: BurnInLifecycleState::Rejection,
    };
    let json = serde_json::to_string(&le).unwrap();
    let back: BurnInLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(le, back);
}

#[test]
fn log_event_serde_without_error_code() {
    let le = BurnInLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "plas_burn_in_gate".to_string(),
        event: "shadow_start".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        lifecycle_state: BurnInLifecycleState::ShadowStart,
    };
    let json = serde_json::to_string(&le).unwrap();
    let back: BurnInLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(le, back);
}

// ── 26. Metrics serde ────────────────────────────────────────────────────

#[test]
fn metrics_serde_roundtrip_from_session() {
    let session = session_with_observations(7);
    let m = session.metrics().clone();
    let json = serde_json::to_string(&m).unwrap();
    let back: BurnInMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ── 27. Shadow observation serde ─────────────────────────────────────────

#[test]
fn shadow_observation_serde_success() {
    let o = success_obs("obs-serde", 42_000);
    let json = serde_json::to_string(&o).unwrap();
    let back: ShadowObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}

#[test]
fn shadow_observation_serde_false_deny() {
    let o = obs("obs-fd", 77_000, false, true);
    let json = serde_json::to_string(&o).unwrap();
    let back: ShadowObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(o, back);
}

// ── 28. Config serde ─────────────────────────────────────────────────────

#[test]
fn config_serde_roundtrip() {
    let c = base_config();
    let json = serde_json::to_string(&c).unwrap();
    let back: BurnInSessionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ── 29. Risk class as_str exact values ───────────────────────────────────

#[test]
fn risk_class_as_str_exact() {
    assert_eq!(ExtensionRiskClass::Low.as_str(), "low");
    assert_eq!(ExtensionRiskClass::Standard.as_str(), "standard");
    assert_eq!(ExtensionRiskClass::High.as_str(), "high");
}

#[test]
fn risk_class_display_equals_as_str() {
    for v in [
        ExtensionRiskClass::Low,
        ExtensionRiskClass::Standard,
        ExtensionRiskClass::High,
    ] {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

// ── 30. Lifecycle as_str exact values ────────────────────────────────────

#[test]
fn lifecycle_as_str_exact() {
    assert_eq!(BurnInLifecycleState::ShadowStart.as_str(), "shadow_start");
    assert_eq!(
        BurnInLifecycleState::ShadowEvaluation.as_str(),
        "shadow_evaluation"
    );
    assert_eq!(
        BurnInLifecycleState::PromotionGate.as_str(),
        "promotion_gate"
    );
    assert_eq!(
        BurnInLifecycleState::AutoEnforcement.as_str(),
        "auto_enforcement"
    );
    assert_eq!(BurnInLifecycleState::Rejection.as_str(), "rejection");
}

#[test]
fn lifecycle_display_equals_as_str() {
    for v in [
        BurnInLifecycleState::ShadowStart,
        BurnInLifecycleState::ShadowEvaluation,
        BurnInLifecycleState::PromotionGate,
        BurnInLifecycleState::AutoEnforcement,
        BurnInLifecycleState::Rejection,
    ] {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

// ── 31. Failure code error_code exact values ─────────────────────────────

#[test]
fn failure_code_error_code_exact() {
    assert_eq!(
        BurnInFailureCode::EarlyTerminationFalseDeny.error_code(),
        "early_termination_false_deny"
    );
    assert_eq!(
        BurnInFailureCode::InsufficientShadowDuration.error_code(),
        "insufficient_shadow_duration"
    );
    assert_eq!(
        BurnInFailureCode::InsufficientShadowObservations.error_code(),
        "insufficient_shadow_observations"
    );
    assert_eq!(
        BurnInFailureCode::ShadowSuccessRateBelowThreshold.error_code(),
        "shadow_success_rate_below_threshold"
    );
    assert_eq!(
        BurnInFailureCode::FalseDenyEnvelopeExceeded.error_code(),
        "false_deny_envelope_exceeded"
    );
    assert_eq!(
        BurnInFailureCode::RollbackProofArtifactsMissing.error_code(),
        "rollback_proof_artifacts_missing"
    );
}
