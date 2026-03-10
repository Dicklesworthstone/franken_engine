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

use frankenengine_engine::receipt_verifier_pipeline::{
    LayerResult, UnifiedReceiptVerificationVerdict, VerificationFailureClass,
};
use frankenengine_engine::safe_mode_fallback::{
    ActionTier, AttestationActionRequest, AttestationFallbackConfig, AttestationFallbackDecision,
    AttestationFallbackError, AttestationFallbackManager, AttestationFallbackState,
    AttestationHealth, AutonomousAction, attestation_health_from_verdict,
};
use frankenengine_engine::signature_preimage::SigningKey;

fn mk_manager(timeout_ns: u64) -> AttestationFallbackManager {
    AttestationFallbackManager::new(
        AttestationFallbackConfig {
            unavailable_timeout_ns: timeout_ns,
            challenge_on_fallback: true,
            sandbox_on_fallback: true,
        },
        SigningKey::from_bytes([9u8; 32]),
    )
}

fn mk_request(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    action: AutonomousAction,
    tier: ActionTier,
    timestamp_ns: u64,
) -> AttestationActionRequest {
    AttestationActionRequest {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        action,
        tier,
        timestamp_ns,
    }
}

#[test]
fn high_impact_action_is_deferred_on_failed_attestation() {
    let mut mgr = mk_manager(1_000);
    let req = mk_request(
        "trace-hi-fail",
        "decision-hi-fail",
        "policy-hi-fail",
        AutonomousAction::Terminate,
        ActionTier::HighImpact,
        100,
    );

    let decision = mgr
        .evaluate_action(req, AttestationHealth::VerificationFailed)
        .expect("fallback decision");

    match decision {
        AttestationFallbackDecision::Deferred {
            attestation_status,
            status,
            challenge_required,
            sandbox_required,
            ..
        } => {
            assert_eq!(attestation_status, "degraded");
            assert_eq!(status, "attestation-pending");
            assert!(challenge_required);
            assert!(sandbox_required);
        }
        other => panic!("expected deferred decision, got {other:?}"),
    }

    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
    assert_eq!(mgr.pending_decisions().len(), 1);
    assert_eq!(mgr.pending_decisions()[0].status, "attestation-pending");
    assert_eq!(mgr.transition_receipts().len(), 1);
    mgr.transition_receipts()[0]
        .verify()
        .expect("valid transition signature");
}

#[test]
fn standard_action_warns_but_continues_in_degraded_mode() {
    let mut mgr = mk_manager(1_000);
    let req = mk_request(
        "trace-std",
        "decision-std",
        "policy-std",
        AutonomousAction::RoutineMonitoring,
        ActionTier::Standard,
        100,
    );

    let decision = mgr
        .evaluate_action(req, AttestationHealth::EvidenceExpired)
        .expect("fallback decision");

    match decision {
        AttestationFallbackDecision::Execute {
            attestation_status,
            warning,
        } => {
            assert_eq!(attestation_status, "degraded");
            assert!(warning.is_some());
        }
        other => panic!("expected execute decision, got {other:?}"),
    }

    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
    assert!(mgr.pending_decisions().is_empty());
    let event = mgr.events().last().expect("event emitted");
    assert_eq!(event.component, "attestation_safe_mode");
    assert_eq!(event.trace_id, "trace-std");
    assert_eq!(event.decision_id, "decision-std");
    assert_eq!(event.policy_id, "policy-std");
    assert_eq!(event.event, "attestation_standard_warn");
    assert_eq!(event.outcome, "warn");
}

#[test]
fn low_impact_action_continues_without_warning() {
    let mut mgr = mk_manager(1_000);
    let req = mk_request(
        "trace-low",
        "decision-low",
        "policy-low",
        AutonomousAction::MetricsEmission,
        ActionTier::LowImpact,
        100,
    );

    let decision = mgr
        .evaluate_action(req, AttestationHealth::EvidenceUnavailable)
        .expect("fallback decision");

    match decision {
        AttestationFallbackDecision::Execute {
            attestation_status,
            warning,
        } => {
            assert_eq!(attestation_status, "unavailable");
            assert!(warning.is_none());
        }
        other => panic!("expected execute decision, got {other:?}"),
    }

    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
}

#[test]
fn prolonged_unavailability_requires_operator_review() {
    let mut mgr = mk_manager(100);

    let first = mk_request(
        "trace-timeout-1",
        "decision-timeout-1",
        "policy-timeout",
        AutonomousAction::Quarantine,
        ActionTier::HighImpact,
        1_000,
    );
    mgr.evaluate_action(first, AttestationHealth::EvidenceUnavailable)
        .expect("first decision");
    assert!(!mgr.operator_review_required());

    let second = mk_request(
        "trace-timeout-2",
        "decision-timeout-2",
        "policy-timeout",
        AutonomousAction::RoutineMonitoring,
        ActionTier::Standard,
        1_150,
    );
    mgr.evaluate_action(second, AttestationHealth::EvidenceUnavailable)
        .expect("second decision");
    assert!(mgr.operator_review_required());

    let event = mgr
        .events()
        .iter()
        .find(|event| event.event == "attestation_operator_review_required")
        .expect("escalation event");
    assert_eq!(event.outcome, "fail");
    assert_eq!(
        event.error_code.as_deref(),
        Some("attestation_unavailable_timeout")
    );
}

#[test]
fn recovery_moves_pending_backlog_and_restores_normal_state() {
    let mut mgr = mk_manager(500);

    let degraded_req = mk_request(
        "trace-recover-1",
        "decision-recover-1",
        "policy-recover",
        AutonomousAction::PolicyPromotion,
        ActionTier::HighImpact,
        100,
    );
    let first_decision = mgr
        .evaluate_action(degraded_req, AttestationHealth::EvidenceExpired)
        .expect("first decision");
    assert!(matches!(
        first_decision,
        AttestationFallbackDecision::Deferred { .. }
    ));
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);

    let restored_req = mk_request(
        "trace-recover-2",
        "decision-recover-2",
        "policy-recover",
        AutonomousAction::Quarantine,
        ActionTier::HighImpact,
        200,
    );
    let second_decision = mgr
        .evaluate_action(restored_req, AttestationHealth::Valid)
        .expect("second decision");
    assert!(matches!(
        second_decision,
        AttestationFallbackDecision::Execute { .. }
    ));

    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
    assert!(!mgr.operator_review_required());
    assert!(mgr.pending_decisions().is_empty());

    let backlog = mgr.take_recovery_backlog();
    assert_eq!(backlog.len(), 1);
    assert_eq!(backlog[0].decision_id, "decision-recover-1");
    assert_eq!(backlog[0].status, "attestation-pending");

    // normal->degraded, degraded->restoring, restoring->normal
    assert_eq!(mgr.transition_receipts().len(), 3);
    for receipt in mgr.transition_receipts() {
        receipt.verify().expect("transition signature must verify");
    }
}

fn layer(passed: bool, error_code: Option<&str>) -> LayerResult {
    LayerResult {
        passed,
        error_code: error_code.map(std::string::ToString::to_string),
        checks: Vec::new(),
    }
}

#[test]
fn verifier_verdict_maps_to_attestation_health_classes() {
    let mut verdict = UnifiedReceiptVerificationVerdict {
        receipt_id: "r-1".to_string(),
        trace_id: "trace-map".to_string(),
        decision_id: "decision-map".to_string(),
        policy_id: "policy-map".to_string(),
        verification_timestamp_ns: 1,
        passed: false,
        failure_class: Some(VerificationFailureClass::StaleData),
        exit_code: 23,
        signature: layer(true, None),
        transparency: layer(true, None),
        attestation: layer(true, None),
        warnings: vec!["attestation_policy_cache_stale".to_string()],
        logs: Vec::new(),
    };
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::EvidenceExpired
    );

    verdict.failure_class = Some(VerificationFailureClass::Attestation);
    verdict.warnings.clear();
    verdict.attestation = layer(false, Some("attestation_trust_root_missing"));
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::EvidenceUnavailable
    );

    verdict.attestation = layer(false, Some("attestation_policy_measurement_mismatch"));
    assert_eq!(
        attestation_health_from_verdict(&verdict),
        AttestationHealth::VerificationFailed
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: state lifecycle, serde, error display, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn initial_state_is_normal() {
    let mgr = mk_manager(1_000);
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
    assert!(!mgr.operator_review_required());
    assert!(mgr.pending_decisions().is_empty());
    assert!(mgr.transition_receipts().is_empty());
    assert!(mgr.events().is_empty());
}

#[test]
fn valid_health_action_executes_normally() {
    let mut mgr = mk_manager(1_000);
    let req = mk_request(
        "trace-valid",
        "decision-valid",
        "policy-valid",
        AutonomousAction::Terminate,
        ActionTier::HighImpact,
        100,
    );
    let decision = mgr
        .evaluate_action(req, AttestationHealth::Valid)
        .expect("decision");
    match decision {
        AttestationFallbackDecision::Execute {
            attestation_status,
            warning,
        } => {
            assert_eq!(attestation_status, "valid");
            assert!(warning.is_none());
        }
        other => panic!("expected execute, got {other:?}"),
    }
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);
}

#[test]
fn attestation_health_is_healthy_classification() {
    assert!(AttestationHealth::Valid.is_healthy());
    assert!(!AttestationHealth::EvidenceExpired.is_healthy());
    assert!(!AttestationHealth::EvidenceUnavailable.is_healthy());
    assert!(!AttestationHealth::VerificationFailed.is_healthy());
}

#[test]
fn autonomous_action_default_tiers() {
    assert_eq!(
        AutonomousAction::Terminate.default_tier(),
        ActionTier::HighImpact
    );
    assert_eq!(
        AutonomousAction::Quarantine.default_tier(),
        ActionTier::HighImpact
    );
    assert_eq!(
        AutonomousAction::PolicyPromotion.default_tier(),
        ActionTier::HighImpact
    );
    assert_eq!(
        AutonomousAction::RoutineMonitoring.default_tier(),
        ActionTier::Standard
    );
    assert_eq!(
        AutonomousAction::MetricsEmission.default_tier(),
        ActionTier::LowImpact
    );
}

#[test]
fn attestation_action_request_new_constructor() {
    let req = AttestationActionRequest::new("t1", "d1", "p1", AutonomousAction::Terminate, 500);
    assert_eq!(req.trace_id, "t1");
    assert_eq!(req.decision_id, "d1");
    assert_eq!(req.policy_id, "p1");
    assert_eq!(req.tier, ActionTier::HighImpact);
    assert_eq!(req.timestamp_ns, 500);
}

#[test]
fn attestation_health_serde_round_trip() {
    for health in [
        AttestationHealth::Valid,
        AttestationHealth::EvidenceExpired,
        AttestationHealth::EvidenceUnavailable,
        AttestationHealth::VerificationFailed,
    ] {
        let json = serde_json::to_string(&health).expect("serialize");
        let recovered: AttestationHealth = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(health, recovered);
    }
}

#[test]
fn attestation_fallback_state_serde_round_trip() {
    for state in [
        AttestationFallbackState::Normal,
        AttestationFallbackState::Degraded,
        AttestationFallbackState::Restoring,
    ] {
        let json = serde_json::to_string(&state).expect("serialize");
        let recovered: AttestationFallbackState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, recovered);
    }
}

#[test]
fn attestation_fallback_error_display_is_non_empty() {
    let err = AttestationFallbackError::SignatureFailure {
        detail: "bad signature".to_string(),
    };
    assert!(!err.to_string().is_empty());
    assert!(err.to_string().contains("bad signature"));
}

#[test]
fn fallback_config_serde_round_trip() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: 5_000,
        challenge_on_fallback: true,
        sandbox_on_fallback: false,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: AttestationFallbackConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        config.unavailable_timeout_ns,
        recovered.unavailable_timeout_ns
    );
    assert_eq!(
        config.challenge_on_fallback,
        recovered.challenge_on_fallback
    );
    assert_eq!(config.sandbox_on_fallback, recovered.sandbox_on_fallback);
}

#[test]
fn multiple_degraded_actions_accumulate_pending_decisions() {
    let mut mgr = mk_manager(1_000);
    for i in 0..3 {
        let req = mk_request(
            &format!("trace-multi-{i}"),
            &format!("decision-multi-{i}"),
            "policy-multi",
            AutonomousAction::Terminate,
            ActionTier::HighImpact,
            100 + i as u64,
        );
        mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
            .expect("decision");
    }
    assert_eq!(mgr.pending_decisions().len(), 3);
    assert_eq!(mgr.state(), AttestationFallbackState::Degraded);
}

#[test]
fn action_tier_serde_round_trip() {
    for tier in [
        ActionTier::LowImpact,
        ActionTier::Standard,
        ActionTier::HighImpact,
    ] {
        let json = serde_json::to_string(&tier).expect("serialize");
        let recovered: ActionTier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tier, recovered);
    }
}

#[test]
fn autonomous_action_serde_round_trip() {
    for action in [
        AutonomousAction::Terminate,
        AutonomousAction::Quarantine,
        AutonomousAction::PolicyPromotion,
        AutonomousAction::RoutineMonitoring,
        AutonomousAction::MetricsEmission,
    ] {
        let json = serde_json::to_string(&action).expect("serialize");
        let recovered: AutonomousAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(action, recovered);
    }
}

#[test]
fn attestation_fallback_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(AttestationFallbackError::SignatureFailure {
        detail: "test".to_string(),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn events_are_populated_after_evaluation() {
    let mut mgr = mk_manager(1_000);
    let req = mk_request(
        "trace-drain",
        "decision-drain",
        "policy-drain",
        AutonomousAction::RoutineMonitoring,
        ActionTier::Standard,
        100,
    );
    mgr.evaluate_action(req, AttestationHealth::EvidenceExpired)
        .expect("decision");
    assert!(!mgr.events().is_empty());
    let event = &mgr.events()[0];
    assert_eq!(event.component, "attestation_safe_mode");
}

#[test]
fn attestation_action_request_serde_round_trip() {
    let req = AttestationActionRequest::new("t1", "d1", "p1", AutonomousAction::Terminate, 500);
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: AttestationActionRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req.trace_id, recovered.trace_id);
    assert_eq!(req.decision_id, recovered.decision_id);
    assert_eq!(req.tier, recovered.tier);
}

#[test]
fn attestation_fallback_state_debug_is_nonempty() {
    for state in [
        AttestationFallbackState::Normal,
        AttestationFallbackState::Degraded,
        AttestationFallbackState::Restoring,
    ] {
        assert!(!format!("{state:?}").is_empty());
    }
}

#[test]
fn attestation_health_debug_is_nonempty() {
    for health in [
        AttestationHealth::Valid,
        AttestationHealth::EvidenceExpired,
        AttestationHealth::EvidenceUnavailable,
        AttestationHealth::VerificationFailed,
    ] {
        assert!(!format!("{health:?}").is_empty());
    }
}

#[test]
fn action_tier_debug_is_nonempty() {
    for tier in [
        ActionTier::LowImpact,
        ActionTier::Standard,
        ActionTier::HighImpact,
    ] {
        assert!(!format!("{tier:?}").is_empty());
    }
}

// ────────────────────────────────────────────────────────────
// Batch enrichment: health accessor, with_default_signing_key,
// decision serde, queued decision fields, transition receipt serde,
// event field completeness, take_recovery_backlog idempotent
// ────────────────────────────────────────────────────────────

#[test]
fn health_accessor_tracks_latest_observed_health() {
    let mut mgr = mk_manager(1_000);
    assert_eq!(mgr.health(), AttestationHealth::Valid);

    let req = mk_request(
        "trace-health",
        "decision-health",
        "policy-health",
        AutonomousAction::MetricsEmission,
        ActionTier::LowImpact,
        100,
    );
    mgr.evaluate_action(req, AttestationHealth::EvidenceExpired)
        .expect("decision");
    assert_eq!(mgr.health(), AttestationHealth::EvidenceExpired);
}

#[test]
fn with_default_signing_key_produces_working_manager() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: 5_000,
        challenge_on_fallback: false,
        sandbox_on_fallback: true,
    };
    let mut mgr = AttestationFallbackManager::with_default_signing_key(config);
    assert_eq!(mgr.state(), AttestationFallbackState::Normal);

    let req = mk_request(
        "trace-default-key",
        "decision-default-key",
        "policy-default-key",
        AutonomousAction::Terminate,
        ActionTier::HighImpact,
        50,
    );
    let decision = mgr
        .evaluate_action(req, AttestationHealth::VerificationFailed)
        .expect("decision");
    assert!(matches!(
        decision,
        AttestationFallbackDecision::Deferred { .. }
    ));
    mgr.transition_receipts()[0]
        .verify()
        .expect("default key receipt must verify");
}

#[test]
fn attestation_fallback_decision_serde_round_trip_execute() {
    let decision = AttestationFallbackDecision::Execute {
        attestation_status: "valid".to_string(),
        warning: Some("test warning".to_string()),
    };
    let json = serde_json::to_string(&decision).expect("serialize");
    let recovered: AttestationFallbackDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decision, recovered);
}

#[test]
fn attestation_fallback_decision_serde_round_trip_deferred() {
    let decision = AttestationFallbackDecision::Deferred {
        queue_id: 42,
        attestation_status: "degraded".to_string(),
        status: "attestation-pending".to_string(),
        challenge_required: true,
        sandbox_required: false,
    };
    let json = serde_json::to_string(&decision).expect("serialize");
    let recovered: AttestationFallbackDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decision, recovered);
}

#[test]
fn queued_decision_fields_populated_correctly_on_defer() {
    let mut mgr = mk_manager(1_000);
    let req = mk_request(
        "trace-queued",
        "decision-queued",
        "policy-queued",
        AutonomousAction::PolicyPromotion,
        ActionTier::HighImpact,
        555,
    );
    mgr.evaluate_action(req, AttestationHealth::VerificationFailed)
        .expect("decision");
    let queued = &mgr.pending_decisions()[0];
    assert_eq!(queued.trace_id, "trace-queued");
    assert_eq!(queued.decision_id, "decision-queued");
    assert_eq!(queued.policy_id, "policy-queued");
    assert_eq!(queued.status, "attestation-pending");
    assert!(matches!(queued.action, AutonomousAction::PolicyPromotion));
    assert_eq!(queued.queued_at_ns, 555);
}

#[test]
fn take_recovery_backlog_is_empty_after_second_call() {
    let mut mgr = mk_manager(500);
    let req = mk_request(
        "trace-backlog",
        "decision-backlog",
        "policy-backlog",
        AutonomousAction::Quarantine,
        ActionTier::HighImpact,
        100,
    );
    mgr.evaluate_action(req, AttestationHealth::EvidenceExpired)
        .expect("deferred");

    let restore_req = mk_request(
        "trace-restore",
        "decision-restore",
        "policy-restore",
        AutonomousAction::MetricsEmission,
        ActionTier::LowImpact,
        200,
    );
    mgr.evaluate_action(restore_req, AttestationHealth::Valid)
        .expect("restored");

    let first_backlog = mgr.take_recovery_backlog();
    assert_eq!(first_backlog.len(), 1);
    let second_backlog = mgr.take_recovery_backlog();
    assert!(second_backlog.is_empty(), "second call should be empty");
}

#[test]
fn deferred_decision_without_sandbox_when_config_disabled() {
    let config = AttestationFallbackConfig {
        unavailable_timeout_ns: 1_000,
        challenge_on_fallback: false,
        sandbox_on_fallback: false,
    };
    let mut mgr = AttestationFallbackManager::new(config, SigningKey::from_bytes([7u8; 32]));
    let req = mk_request(
        "trace-no-sandbox",
        "decision-no-sandbox",
        "policy-no-sandbox",
        AutonomousAction::Terminate,
        ActionTier::HighImpact,
        100,
    );
    let decision = mgr
        .evaluate_action(req, AttestationHealth::VerificationFailed)
        .expect("decision");
    match decision {
        AttestationFallbackDecision::Deferred {
            challenge_required,
            sandbox_required,
            ..
        } => {
            assert!(!challenge_required);
            assert!(!sandbox_required);
        }
        other => panic!("expected deferred, got {other:?}"),
    }
}
