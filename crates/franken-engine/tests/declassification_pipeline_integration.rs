//! Integration tests for the `declassification_pipeline` module.
//!
//! Covers the five-stage declassification pipeline, emergency pathway,
//! receipt signing/verification, event emission, statistics, deterministic
//! replay, and serde round-trips for every public type.

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

use frankenengine_engine::declassification_pipeline::{
    DeclassificationPipeline, DeclassificationRequest, EmergencyGrant, LossAssessment,
    PipelineConfig, PipelineError, PipelineEvent, PipelineStats, PolicyEvalResult,
};
use frankenengine_engine::ifc_artifacts::{
    DeclassificationDecision, DeclassificationRoute, FlowPolicy, IfcSchemaVersion, Label,
};
use frankenengine_engine::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_key() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
}

fn alt_key() -> SigningKey {
    SigningKey::from_bytes([99u8; 32])
}

fn make_policy() -> FlowPolicy {
    FlowPolicy {
        policy_id: "pol-test".to_string(),
        extension_id: "ext-test".to_string(),
        label_classes: [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
        ]
        .into_iter()
        .collect(),
        clearance_classes: [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
        ]
        .into_iter()
        .collect(),
        allowed_flows: vec![],
        prohibited_flows: vec![],
        declassification_routes: vec![
            DeclassificationRoute {
                route_id: "declass-secret-internal".to_string(),
                source_label: Label::Secret,
                target_clearance: Label::Internal,
                conditions: vec!["audit_approval".to_string()],
            },
            DeclassificationRoute {
                route_id: "declass-conf-public".to_string(),
                source_label: Label::Confidential,
                target_clearance: Label::Public,
                conditions: vec!["redaction_applied".to_string()],
            },
        ],
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    }
}

fn make_request(route_id: &str, source: Label, sink: Label) -> DeclassificationRequest {
    DeclassificationRequest {
        request_id: format!("req-{route_id}"),
        source_label: source,
        sink_clearance: sink,
        extension_id: "ext-test".to_string(),
        code_location: "module::func".to_string(),
        trace_id: "trace-001".to_string(),
        requested_route_id: route_id.to_string(),
        decision_contract_id: "decision-contract-test".to_string(),
        is_emergency: false,
        timestamp_ms: 1_700_000_000_000,
    }
}

fn low_loss() -> LossAssessment {
    LossAssessment {
        expected_loss_milli: 10_000,
        data_sensitivity_bps: 2000,
        sink_exposure_bps: 1000,
        historical_abuse_detected: false,
        summary: "low risk".to_string(),
    }
}

fn high_loss() -> LossAssessment {
    LossAssessment {
        expected_loss_milli: 500_000,
        data_sensitivity_bps: 9000,
        sink_exposure_bps: 8000,
        historical_abuse_detected: true,
        summary: "high risk".to_string(),
    }
}

fn threshold_exact_loss() -> LossAssessment {
    LossAssessment {
        expected_loss_milli: LossAssessment::DEFAULT_THRESHOLD_MILLI,
        data_sensitivity_bps: 5000,
        sink_exposure_bps: 5000,
        historical_abuse_detected: false,
        summary: "exactly at threshold".to_string(),
    }
}

fn zero_loss() -> LossAssessment {
    LossAssessment {
        expected_loss_milli: 0,
        data_sensitivity_bps: 0,
        sink_exposure_bps: 0,
        historical_abuse_detected: false,
        summary: "zero risk".to_string(),
    }
}

// ===========================================================================
// DeclassificationRequest
// ===========================================================================

#[test]
fn request_serde_roundtrip() {
    let req = make_request("route-1", Label::Secret, Label::Internal);
    let json = serde_json::to_string(&req).unwrap();
    let parsed: DeclassificationRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, parsed);
}

#[test]
fn request_fields_populated() {
    let req = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    assert_eq!(req.request_id, "req-declass-secret-internal");
    assert_eq!(req.source_label, Label::Secret);
    assert_eq!(req.sink_clearance, Label::Internal);
    assert_eq!(req.extension_id, "ext-test");
    assert_eq!(req.code_location, "module::func");
    assert_eq!(req.trace_id, "trace-001");
    assert_eq!(req.requested_route_id, "declass-secret-internal");
    assert_eq!(req.decision_contract_id, "decision-contract-test");
    assert!(!req.is_emergency);
    assert_eq!(req.timestamp_ms, 1_700_000_000_000);
}

#[test]
fn request_emergency_flag() {
    let mut req = make_request("r1", Label::Secret, Label::Public);
    assert!(!req.is_emergency);
    req.is_emergency = true;
    assert!(req.is_emergency);
}

// ===========================================================================
// PolicyEvalResult
// ===========================================================================

#[test]
fn policy_eval_route_approved_is_approved() {
    let r = PolicyEvalResult::RouteApproved {
        route_id: "r1".to_string(),
        conditions_met: vec!["c1".to_string()],
    };
    assert!(r.is_approved());
}

#[test]
fn policy_eval_conditions_not_met_not_approved() {
    let r = PolicyEvalResult::ConditionsNotMet {
        route_id: "r1".to_string(),
        failed_conditions: vec!["c2".to_string()],
    };
    assert!(!r.is_approved());
}

#[test]
fn policy_eval_no_matching_route_not_approved() {
    let r = PolicyEvalResult::NoMatchingRoute;
    assert!(!r.is_approved());
}

#[test]
fn policy_eval_policy_unavailable_not_approved() {
    let r = PolicyEvalResult::PolicyUnavailable {
        reason: "gone".to_string(),
    };
    assert!(!r.is_approved());
}

#[test]
fn policy_eval_result_serde_all_variants() {
    let variants = vec![
        PolicyEvalResult::RouteApproved {
            route_id: "r1".to_string(),
            conditions_met: vec!["c1".to_string(), "c2".to_string()],
        },
        PolicyEvalResult::ConditionsNotMet {
            route_id: "r1".to_string(),
            failed_conditions: vec!["c3".to_string()],
        },
        PolicyEvalResult::NoMatchingRoute,
        PolicyEvalResult::PolicyUnavailable {
            reason: "database down".to_string(),
        },
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let parsed: PolicyEvalResult = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }
}

// ===========================================================================
// LossAssessment
// ===========================================================================

#[test]
fn loss_below_threshold_low() {
    assert!(low_loss().below_threshold(LossAssessment::DEFAULT_THRESHOLD_MILLI));
}

#[test]
fn loss_above_threshold_high() {
    assert!(!high_loss().below_threshold(LossAssessment::DEFAULT_THRESHOLD_MILLI));
}

#[test]
fn loss_exactly_at_threshold_not_below() {
    // exactly at threshold → not below
    let loss = threshold_exact_loss();
    assert!(!loss.below_threshold(LossAssessment::DEFAULT_THRESHOLD_MILLI));
}

#[test]
fn loss_just_below_threshold() {
    let mut loss = threshold_exact_loss();
    loss.expected_loss_milli = LossAssessment::DEFAULT_THRESHOLD_MILLI - 1;
    assert!(loss.below_threshold(LossAssessment::DEFAULT_THRESHOLD_MILLI));
}

#[test]
fn loss_zero_is_below_any_threshold() {
    assert!(zero_loss().below_threshold(1));
    assert!(zero_loss().below_threshold(LossAssessment::DEFAULT_THRESHOLD_MILLI));
}

#[test]
fn loss_default_threshold_value() {
    assert_eq!(LossAssessment::DEFAULT_THRESHOLD_MILLI, 100_000);
}

#[test]
fn loss_assessment_serde_roundtrip() {
    let loss = high_loss();
    let json = serde_json::to_string(&loss).unwrap();
    let parsed: LossAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(loss, parsed);
}

// ===========================================================================
// PipelineEvent
// ===========================================================================

#[test]
fn pipeline_event_serde_roundtrip() {
    let event = PipelineEvent {
        request_id: "req-1".to_string(),
        trace_id: "trace-1".to_string(),
        stage: "policy_evaluation".to_string(),
        outcome: "route_approved".to_string(),
        component: "declassification_pipeline".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: PipelineEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

#[test]
fn pipeline_event_with_error_code_serde() {
    let event = PipelineEvent {
        request_id: "req-1".to_string(),
        trace_id: "trace-1".to_string(),
        stage: "loss_assessment".to_string(),
        outcome: "exceeds_threshold".to_string(),
        component: "declassification_pipeline".to_string(),
        error_code: Some("loss_exceeds_threshold".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: PipelineEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
    assert!(json.contains("loss_exceeds_threshold"));
}

// ===========================================================================
// PipelineError — display and serde
// ===========================================================================

#[test]
fn error_flow_already_legal_display() {
    let err = PipelineError::FlowAlreadyLegal {
        source: Label::Public,
        sink: Label::Internal,
    };
    let msg = err.to_string();
    assert!(msg.contains("already lattice-legal"));
    assert!(msg.contains("public"));
    assert!(msg.contains("internal"));
}

#[test]
fn error_policy_unavailable_display() {
    let err = PipelineError::PolicyUnavailable {
        reason: "database down".to_string(),
    };
    assert!(err.to_string().contains("database down"));
}

#[test]
fn error_no_matching_route_display() {
    let err = PipelineError::NoMatchingRoute {
        source: Label::Secret,
        sink: Label::Public,
    };
    let msg = err.to_string();
    assert!(msg.contains("no declassification route"));
    assert!(msg.contains("secret"));
    assert!(msg.contains("public"));
}

#[test]
fn error_loss_exceeds_threshold_display() {
    let err = PipelineError::LossExceedsThreshold {
        expected_loss_milli: 500_000,
        threshold_milli: 100_000,
    };
    let msg = err.to_string();
    assert!(msg.contains("500000"));
    assert!(msg.contains("100000"));
}

#[test]
fn error_emergency_expired_display() {
    let err = PipelineError::EmergencyExpired {
        request_id: "req-emg-1".to_string(),
        expiry_ms: 1_700_000_300_000,
    };
    let msg = err.to_string();
    assert!(msg.contains("req-emg-1"));
    assert!(msg.contains("expired"));
}

#[test]
fn error_signing_error_display() {
    let err = PipelineError::SigningError {
        detail: "bad key material".to_string(),
    };
    assert!(err.to_string().contains("bad key material"));
}

#[test]
fn error_validation_error_display() {
    let err = PipelineError::ValidationError(
        frankenengine_engine::ifc_artifacts::IfcValidationError::EmptyClaim {
            claim_id: "claim-1".to_string(),
        },
    );
    assert!(err.to_string().contains("validation error"));
}

#[test]
fn error_implements_std_error() {
    let err = PipelineError::FlowAlreadyLegal {
        source: Label::Public,
        sink: Label::Secret,
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let errors: Vec<PipelineError> = vec![
        PipelineError::FlowAlreadyLegal {
            source: Label::Public,
            sink: Label::Internal,
        },
        PipelineError::PolicyUnavailable {
            reason: "gone".to_string(),
        },
        PipelineError::NoMatchingRoute {
            source: Label::Secret,
            sink: Label::Public,
        },
        PipelineError::LossExceedsThreshold {
            expected_loss_milli: 500_000,
            threshold_milli: 100_000,
        },
        PipelineError::EmergencyExpired {
            request_id: "req-1".to_string(),
            expiry_ms: 999,
        },
        PipelineError::SigningError {
            detail: "bad key".to_string(),
        },
    ];
    for e in errors {
        let json = serde_json::to_string(&e).unwrap();
        let parsed: PipelineError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, parsed);
    }
}

// ===========================================================================
// PipelineConfig
// ===========================================================================

#[test]
fn config_defaults() {
    let cfg = PipelineConfig::default();
    assert_eq!(
        cfg.loss_threshold_milli,
        LossAssessment::DEFAULT_THRESHOLD_MILLI
    );
    assert_eq!(cfg.emergency_max_duration_ms, 300_000);
    assert!(cfg.emit_stage_events);
}

#[test]
fn config_serde_roundtrip() {
    let cfg = PipelineConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let parsed: PipelineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, parsed);
}

#[test]
fn config_custom_values_serde() {
    let cfg = PipelineConfig {
        loss_threshold_milli: 50_000,
        emergency_max_duration_ms: 600_000,
        emit_stage_events: false,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let parsed: PipelineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, parsed);
}

// ===========================================================================
// EmergencyGrant
// ===========================================================================

#[test]
fn emergency_grant_not_expired_before_expiry() {
    let grant = EmergencyGrant {
        grant_id: "emg-1".to_string(),
        request_id: "req-1".to_string(),
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        expiry_ms: 1_700_000_300_000,
        review_completed: false,
    };
    assert!(!grant.is_expired(1_700_000_000_000));
    assert!(!grant.is_expired(1_700_000_299_999));
}

#[test]
fn emergency_grant_expired_at_exact_expiry() {
    let grant = EmergencyGrant {
        grant_id: "emg-1".to_string(),
        request_id: "req-1".to_string(),
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        expiry_ms: 1_700_000_300_000,
        review_completed: false,
    };
    assert!(grant.is_expired(1_700_000_300_000));
}

#[test]
fn emergency_grant_expired_after_expiry() {
    let grant = EmergencyGrant {
        grant_id: "emg-1".to_string(),
        request_id: "req-1".to_string(),
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        expiry_ms: 1_700_000_300_000,
        review_completed: false,
    };
    assert!(grant.is_expired(2_000_000_000_000));
}

#[test]
fn emergency_grant_serde_roundtrip() {
    let grant = EmergencyGrant {
        grant_id: "emg-1".to_string(),
        request_id: "req-1".to_string(),
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        expiry_ms: 1_700_000_300_000,
        review_completed: false,
    };
    let json = serde_json::to_string(&grant).unwrap();
    let parsed: EmergencyGrant = serde_json::from_str(&json).unwrap();
    assert_eq!(grant, parsed);
}

// ===========================================================================
// PipelineStats
// ===========================================================================

#[test]
fn pipeline_stats_serde_roundtrip() {
    let stats = PipelineStats {
        decision_count: 10,
        allow_count: 7,
        deny_count: 3,
        emergency_grants_active: 1,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let parsed: PipelineStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, parsed);
}

// ===========================================================================
// Pipeline construction
// ===========================================================================

#[test]
fn pipeline_default_construction() {
    let pipeline = DeclassificationPipeline::default();
    assert!(pipeline.events().is_empty());
    assert!(pipeline.receipts().is_empty());
    let stats = pipeline.stats();
    assert_eq!(stats.decision_count, 0);
    assert_eq!(stats.allow_count, 0);
    assert_eq!(stats.deny_count, 0);
    assert_eq!(stats.emergency_grants_active, 0);
}

#[test]
fn pipeline_custom_config_construction() {
    let cfg = PipelineConfig {
        loss_threshold_milli: 50_000,
        emergency_max_duration_ms: 60_000,
        emit_stage_events: false,
    };
    let pipeline = DeclassificationPipeline::new(cfg);
    assert!(pipeline.events().is_empty());
    assert!(pipeline.receipts().is_empty());
}

// ===========================================================================
// Pipeline: successful allow flow
// ===========================================================================

#[test]
fn successful_allow_produces_signed_receipt() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let key = test_key();

    let receipt = pipeline
        .process(&request, &policy, &low_loss(), &key)
        .unwrap();

    assert_eq!(receipt.decision, DeclassificationDecision::Allow);
    assert_eq!(receipt.source_label, Label::Secret);
    assert_eq!(receipt.sink_clearance, Label::Internal);
    assert!(!receipt.signature.is_sentinel());
    receipt.verify(&key.verification_key()).unwrap();
}

#[test]
fn successful_allow_receipt_fields() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let key = test_key();
    let loss = low_loss();

    let receipt = pipeline.process(&request, &policy, &loss, &key).unwrap();

    assert_eq!(receipt.receipt_id, "rcpt-req-declass-secret-internal");
    assert_eq!(
        receipt.declassification_route_ref,
        "declass-secret-internal"
    );
    assert_eq!(receipt.loss_assessment_milli, loss.expected_loss_milli);
    assert_eq!(receipt.replay_linkage, "trace-001");
    assert_eq!(receipt.timestamp_ms, 1_700_000_000_000);
    assert_eq!(receipt.schema_version, IfcSchemaVersion::CURRENT);
    assert_eq!(receipt.authorized_by, key.verification_key());
}

#[test]
fn successful_allow_updates_stats() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let stats = pipeline.stats();
    assert_eq!(stats.decision_count, 1);
    assert_eq!(stats.allow_count, 1);
    assert_eq!(stats.deny_count, 0);
}

#[test]
fn successful_allow_stores_receipt() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    assert_eq!(pipeline.receipts().len(), 1);
    assert_eq!(
        pipeline.receipts()[0].decision,
        DeclassificationDecision::Allow
    );
}

// ===========================================================================
// Pipeline: event emission
// ===========================================================================

#[test]
fn allow_flow_emits_all_stages() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let stages: Vec<&str> = pipeline.events().iter().map(|e| e.stage.as_str()).collect();
    assert!(stages.contains(&"request_validation"));
    assert!(stages.contains(&"policy_evaluation"));
    assert!(stages.contains(&"loss_assessment"));
    assert!(stages.contains(&"decision"));
    assert!(stages.contains(&"signed_receipt"));
}

#[test]
fn all_events_have_stable_component() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    for event in pipeline.events() {
        assert_eq!(event.component, "declassification_pipeline");
    }
}

#[test]
fn events_carry_request_and_trace_ids() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    for event in pipeline.events() {
        assert_eq!(event.request_id, "req-declass-secret-internal");
        assert_eq!(event.trace_id, "trace-001");
    }
}

#[test]
fn events_disabled_when_configured() {
    let config = PipelineConfig {
        emit_stage_events: false,
        ..PipelineConfig::default()
    };
    let mut pipeline = DeclassificationPipeline::new(config);
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    assert!(pipeline.events().is_empty());
}

#[test]
fn drain_events_clears_buffer() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    assert!(!pipeline.events().is_empty());

    let drained = pipeline.drain_events();
    assert!(!drained.is_empty());
    assert!(pipeline.events().is_empty());
}

#[test]
fn drain_events_returns_all_events() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();

    let r1 = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    pipeline
        .process(&r1, &policy, &low_loss(), &test_key())
        .unwrap();
    let count_first = pipeline.events().len();

    let r2 = make_request("declass-conf-public", Label::Confidential, Label::Public);
    pipeline
        .process(&r2, &policy, &low_loss(), &test_key())
        .unwrap();

    let total = pipeline.events().len();
    assert!(total > count_first);

    let drained = pipeline.drain_events();
    assert_eq!(drained.len(), total);
}

// ===========================================================================
// Pipeline: denial — flow already legal
// ===========================================================================

#[test]
fn flow_already_legal_returns_error() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    // Public -> Internal is lattice-legal (level 0 -> level 1)
    let request = make_request("declass-any", Label::Public, Label::Internal);

    let err = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap_err();
    match err {
        PipelineError::FlowAlreadyLegal { source, sink } => {
            assert_eq!(source, Label::Public);
            assert_eq!(sink, Label::Internal);
        }
        other => panic!("expected FlowAlreadyLegal, got {other:?}"),
    }
}

#[test]
fn flow_already_legal_does_not_count_as_decision() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-any", Label::Public, Label::Internal);

    let _ = pipeline.process(&request, &policy, &low_loss(), &test_key());
    assert_eq!(pipeline.stats().decision_count, 0);
}

#[test]
fn same_level_flow_is_legal() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    // Internal -> Internal is lattice-legal
    let request = make_request("declass-any", Label::Internal, Label::Internal);

    let err = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap_err();
    assert!(matches!(err, PipelineError::FlowAlreadyLegal { .. }));
}

// ===========================================================================
// Pipeline: denial — no matching route
// ===========================================================================

#[test]
fn no_matching_route_returns_error() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    // Secret -> Public has no route in our policy
    let request = make_request("nonexistent-route", Label::Secret, Label::Public);

    let err = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap_err();
    assert!(matches!(err, PipelineError::NoMatchingRoute { .. }));
}

#[test]
fn wrong_route_id_no_match() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    // Correct labels but wrong route_id
    let request = make_request("wrong-route-id", Label::Secret, Label::Internal);

    let err = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap_err();
    assert!(matches!(err, PipelineError::NoMatchingRoute { .. }));
}

#[test]
fn no_route_does_not_count_as_decision() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("nonexistent", Label::Secret, Label::Public);

    let _ = pipeline.process(&request, &policy, &low_loss(), &test_key());
    assert_eq!(pipeline.stats().decision_count, 0);
}

#[test]
fn policy_extension_mismatch_returns_policy_unavailable() {
    let mut pipeline = DeclassificationPipeline::default();
    let mut policy = make_policy();
    policy.extension_id = "ext-other".to_string();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    let err = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap_err();
    match err {
        PipelineError::PolicyUnavailable { reason } => {
            assert!(reason.contains("ext-other"));
            assert!(reason.contains("ext-test"));
        }
        other => panic!("expected PolicyUnavailable, got {other:?}"),
    }
    assert!(
        pipeline
            .events()
            .iter()
            .any(|event| event.error_code.as_deref() == Some("policy_unavailable"))
    );
}

// ===========================================================================
// Pipeline: denial — loss exceeds threshold
// ===========================================================================

#[test]
fn high_loss_produces_deny_receipt() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    let receipt = pipeline
        .process(&request, &policy, &high_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Deny);
}

#[test]
fn high_loss_deny_increments_deny_count() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &high_loss(), &test_key())
        .unwrap();

    let stats = pipeline.stats();
    assert_eq!(stats.decision_count, 1);
    assert_eq!(stats.allow_count, 0);
    assert_eq!(stats.deny_count, 1);
}

#[test]
fn high_loss_emits_decision_deny_stage() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &high_loss(), &test_key())
        .unwrap();

    assert!(pipeline.events().iter().any(|event| {
        event.stage == "decision"
            && event.outcome == "deny"
            && event.error_code.as_deref() == Some("loss_exceeds_threshold")
    }));
}

#[test]
fn exactly_at_threshold_denied() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    let receipt = pipeline
        .process(&request, &policy, &threshold_exact_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Deny);
}

#[test]
fn just_below_threshold_allowed() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let mut loss = threshold_exact_loss();
    loss.expected_loss_milli -= 1;

    let receipt = pipeline
        .process(&request, &policy, &loss, &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Allow);
}

#[test]
fn custom_threshold_allows_higher_loss() {
    let config = PipelineConfig {
        loss_threshold_milli: 600_000,
        ..PipelineConfig::default()
    };
    let mut pipeline = DeclassificationPipeline::new(config);
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    // 500_000 < 600_000 threshold → allowed
    let receipt = pipeline
        .process(&request, &policy, &high_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Allow);
}

#[test]
fn zero_threshold_denies_any_nonzero_loss() {
    let config = PipelineConfig {
        loss_threshold_milli: 0,
        ..PipelineConfig::default()
    };
    let mut pipeline = DeclassificationPipeline::new(config);
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    // Even low loss (10_000) >= 0 threshold → denied
    let receipt = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Deny);
}

#[test]
fn zero_loss_with_zero_threshold_denied() {
    // 0 is not < 0
    let config = PipelineConfig {
        loss_threshold_milli: 0,
        ..PipelineConfig::default()
    };
    let mut pipeline = DeclassificationPipeline::new(config);
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    let receipt = pipeline
        .process(&request, &policy, &zero_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Deny);
}

// ===========================================================================
// Pipeline: emergency pathway
// ===========================================================================

#[test]
fn emergency_bypasses_route_check() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("nonexistent-route", Label::Secret, Label::Public);
    request.is_emergency = true;

    let receipt = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Allow);
    assert_eq!(receipt.declassification_route_ref, "emergency");
}

#[test]
fn emergency_creates_grant() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let grant = pipeline
        .check_emergency_grant(&Label::Secret, &Label::Public, request.timestamp_ms)
        .unwrap();
    assert!(!grant.review_completed);
    assert!(!grant.is_expired(request.timestamp_ms));
    assert_eq!(grant.source_label, Label::Secret);
    assert_eq!(grant.sink_clearance, Label::Public);
}

#[test]
fn emergency_grant_id_format() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let grant = pipeline
        .check_emergency_grant(&Label::Secret, &Label::Public, request.timestamp_ms)
        .unwrap();
    assert_eq!(grant.grant_id, "emg-req-bad-route");
}

#[test]
fn emergency_grant_expiry_uses_config_duration() {
    let config = PipelineConfig {
        emergency_max_duration_ms: 60_000,
        ..PipelineConfig::default()
    };
    let mut pipeline = DeclassificationPipeline::new(config);
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;
    request.timestamp_ms = 1_000_000;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let grant = pipeline
        .check_emergency_grant(&Label::Secret, &Label::Public, 1_000_000)
        .unwrap();
    assert_eq!(grant.expiry_ms, 1_060_000); // 1_000_000 + 60_000
}

#[test]
fn emergency_grant_expiry_saturates_on_overflow() {
    let config = PipelineConfig {
        emergency_max_duration_ms: 1_000,
        ..PipelineConfig::default()
    };
    let mut pipeline = DeclassificationPipeline::new(config);
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;
    request.timestamp_ms = u64::MAX - 10;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let grant = pipeline
        .check_emergency_grant(&Label::Secret, &Label::Public, u64::MAX - 1)
        .unwrap();
    assert_eq!(grant.expiry_ms, u64::MAX);
}

#[test]
fn emergency_grant_expires_at_boundary() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;
    request.timestamp_ms = 1_000_000;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let expiry = 1_000_000 + 300_000;
    // Just before
    assert!(
        pipeline
            .check_emergency_grant(&Label::Secret, &Label::Public, expiry - 1)
            .is_some()
    );
    // At expiry
    assert!(
        pipeline
            .check_emergency_grant(&Label::Secret, &Label::Public, expiry)
            .is_none()
    );
}

#[test]
fn emergency_grant_no_match_wrong_labels() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    assert!(
        pipeline
            .check_emergency_grant(&Label::Confidential, &Label::Public, request.timestamp_ms)
            .is_none()
    );
    assert!(
        pipeline
            .check_emergency_grant(&Label::Secret, &Label::Internal, request.timestamp_ms)
            .is_none()
    );
}

#[test]
fn emergency_review_completion_succeeds() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    assert!(pipeline.complete_emergency_review("emg-req-bad-route"));
}

#[test]
fn reviewed_emergency_grant_not_returned_as_active() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    assert!(
        pipeline
            .check_emergency_grant(&Label::Secret, &Label::Public, request.timestamp_ms)
            .is_some()
    );

    assert!(pipeline.complete_emergency_review("emg-req-bad-route"));
    assert!(
        pipeline
            .check_emergency_grant(&Label::Secret, &Label::Public, request.timestamp_ms)
            .is_none()
    );
}

#[test]
fn emergency_review_nonexistent_fails() {
    let mut pipeline = DeclassificationPipeline::default();
    assert!(!pipeline.complete_emergency_review("nonexistent"));
}

#[test]
fn emergency_counts_as_allow_decision() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let stats = pipeline.stats();
    assert_eq!(stats.decision_count, 1);
    assert_eq!(stats.allow_count, 1);
    assert_eq!(stats.deny_count, 0);
}

#[test]
fn emergency_active_grant_counted_in_stats() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    assert_eq!(pipeline.stats().emergency_grants_active, 1);

    // After review completion, grant is no longer "active" (review_completed = true)
    pipeline.complete_emergency_review("emg-req-bad-route");
    assert_eq!(pipeline.stats().emergency_grants_active, 0);
}

#[test]
fn emergency_emits_stage_events() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("bad-route", Label::Secret, Label::Public);
    request.is_emergency = true;

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let stages: Vec<&str> = pipeline.events().iter().map(|e| e.stage.as_str()).collect();
    assert!(stages.contains(&"emergency_pathway"));
}

#[test]
fn non_emergency_no_route_is_error() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("nonexistent-route", Label::Secret, Label::Public);
    // is_emergency = false by default

    let err = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap_err();
    assert!(matches!(err, PipelineError::NoMatchingRoute { .. }));
}

// ===========================================================================
// Pipeline: multiple routes independently evaluated
// ===========================================================================

#[test]
fn multiple_routes_independently_evaluated() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let key = test_key();

    let r1 = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let r2 = make_request("declass-conf-public", Label::Confidential, Label::Public);

    let receipt1 = pipeline.process(&r1, &policy, &low_loss(), &key).unwrap();
    let receipt2 = pipeline.process(&r2, &policy, &low_loss(), &key).unwrap();

    assert_eq!(
        receipt1.declassification_route_ref,
        "declass-secret-internal"
    );
    assert_eq!(receipt2.declassification_route_ref, "declass-conf-public");
    assert_eq!(pipeline.receipts().len(), 2);
}

#[test]
fn mixed_allow_deny_stats() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let key = test_key();

    // Allow
    let r1 = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    pipeline.process(&r1, &policy, &low_loss(), &key).unwrap();

    // Deny (high loss)
    let mut r2 = make_request("declass-conf-public", Label::Confidential, Label::Public);
    r2.request_id = "req-2".to_string();
    pipeline.process(&r2, &policy, &high_loss(), &key).unwrap();

    let stats = pipeline.stats();
    assert_eq!(stats.decision_count, 2);
    assert_eq!(stats.allow_count, 1);
    assert_eq!(stats.deny_count, 1);
}

// ===========================================================================
// Pipeline: signing and verification
// ===========================================================================

#[test]
fn receipt_signed_with_given_key() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let key = test_key();

    let receipt = pipeline
        .process(&request, &policy, &low_loss(), &key)
        .unwrap();
    receipt.verify(&key.verification_key()).unwrap();
}

#[test]
fn different_keys_produce_different_signatures() {
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    let mut p1 = DeclassificationPipeline::default();
    let r1 = p1
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let mut p2 = DeclassificationPipeline::default();
    let r2 = p2
        .process(&request, &policy, &low_loss(), &alt_key())
        .unwrap();

    assert_ne!(r1.signature, r2.signature);
    assert_ne!(r1.authorized_by, r2.authorized_by);
}

#[test]
fn deny_receipt_also_signed() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let key = test_key();

    let receipt = pipeline
        .process(&request, &policy, &high_loss(), &key)
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Deny);
    assert!(!receipt.signature.is_sentinel());
    receipt.verify(&key.verification_key()).unwrap();
}

// ===========================================================================
// Pipeline: deterministic replay
// ===========================================================================

#[test]
fn deterministic_replay_50_times() {
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let key = test_key();
    let loss = low_loss();

    let mut receipts = Vec::new();
    for _ in 0..50 {
        let mut pipeline = DeclassificationPipeline::default();
        let receipt = pipeline.process(&request, &policy, &loss, &key).unwrap();
        receipts.push(receipt);
    }

    let first = &receipts[0];
    for r in &receipts[1..] {
        assert_eq!(r.decision, first.decision);
        assert_eq!(r.source_label, first.source_label);
        assert_eq!(r.sink_clearance, first.sink_clearance);
        assert_eq!(r.loss_assessment_milli, first.loss_assessment_milli);
        assert_eq!(r.replay_linkage, first.replay_linkage);
        assert_eq!(r.signature, first.signature);
    }
}

#[test]
fn deterministic_deny_replay() {
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let key = test_key();
    let loss = high_loss();

    let mut receipts = Vec::new();
    for _ in 0..20 {
        let mut pipeline = DeclassificationPipeline::default();
        let receipt = pipeline.process(&request, &policy, &loss, &key).unwrap();
        receipts.push(receipt);
    }

    let first = &receipts[0];
    for r in &receipts[1..] {
        assert_eq!(r.decision, DeclassificationDecision::Deny);
        assert_eq!(r.signature, first.signature);
    }
}

// ===========================================================================
// Pipeline: empty policy edge cases
// ===========================================================================

#[test]
fn empty_policy_no_routes() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = FlowPolicy {
        policy_id: "pol-empty".to_string(),
        extension_id: "ext-test".to_string(),
        label_classes: BTreeSet::new(),
        clearance_classes: BTreeSet::new(),
        allowed_flows: vec![],
        prohibited_flows: vec![],
        declassification_routes: vec![],
        epoch_id: 0,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    let request = make_request("any-route", Label::Secret, Label::Internal);

    let err = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap_err();
    assert!(matches!(err, PipelineError::NoMatchingRoute { .. }));
}

// ===========================================================================
// Pipeline: second declassification route
// ===========================================================================

#[test]
fn second_route_confidential_to_public() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-conf-public", Label::Confidential, Label::Public);

    let receipt = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Allow);
    assert_eq!(receipt.declassification_route_ref, "declass-conf-public");
    assert_eq!(receipt.source_label, Label::Confidential);
    assert_eq!(receipt.sink_clearance, Label::Public);
}

// ===========================================================================
// Pipeline: batch processing stress test
// ===========================================================================

#[test]
fn stress_batch_20_decisions() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let key = test_key();

    for i in 0..20 {
        let mut req = make_request("declass-secret-internal", Label::Secret, Label::Internal);
        req.request_id = format!("req-batch-{i}");

        let loss = if i % 3 == 0 { high_loss() } else { low_loss() };
        let receipt = pipeline.process(&req, &policy, &loss, &key).unwrap();

        if i % 3 == 0 {
            assert_eq!(receipt.decision, DeclassificationDecision::Deny);
        } else {
            assert_eq!(receipt.decision, DeclassificationDecision::Allow);
        }
    }

    let stats = pipeline.stats();
    assert_eq!(stats.decision_count, 20);
    // i=0,3,6,9,12,15,18 → 7 denials, 13 allows
    assert_eq!(stats.deny_count, 7);
    assert_eq!(stats.allow_count, 13);
    assert_eq!(pipeline.receipts().len(), 20);
}

#[test]
fn stress_multiple_emergency_grants() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let key = test_key();

    for i in 0..5 {
        let mut req = make_request("bad-route", Label::Secret, Label::Public);
        req.request_id = format!("emg-req-{i}");
        req.is_emergency = true;
        req.timestamp_ms = 1_000_000 + i * 1000;

        pipeline.process(&req, &policy, &low_loss(), &key).unwrap();
    }

    assert_eq!(pipeline.stats().decision_count, 5);
    assert_eq!(pipeline.stats().allow_count, 5);
    assert_eq!(pipeline.stats().emergency_grants_active, 5);
}

// ===========================================================================
// Pipeline: receipt serde
// ===========================================================================

#[test]
fn receipt_serde_roundtrip() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    let receipt = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: frankenengine_engine::ifc_artifacts::DeclassificationReceipt =
        serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.decision, parsed.decision);
    assert_eq!(receipt.source_label, parsed.source_label);
    assert_eq!(receipt.sink_clearance, parsed.sink_clearance);
    assert_eq!(receipt.replay_linkage, parsed.replay_linkage);
    assert_eq!(receipt.signature, parsed.signature);
}

// ===========================================================================
// Pipeline: events with error codes
// ===========================================================================

#[test]
fn deny_events_contain_error_code() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &high_loss(), &test_key())
        .unwrap();

    let error_events: Vec<_> = pipeline
        .events()
        .iter()
        .filter(|e| e.error_code.is_some())
        .collect();
    assert!(!error_events.is_empty());
    assert!(
        error_events
            .iter()
            .any(|e| e.error_code.as_deref() == Some("loss_exceeds_threshold"))
    );
}

#[test]
fn no_route_events_contain_error_code() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("nonexistent", Label::Secret, Label::Public);

    let _ = pipeline.process(&request, &policy, &low_loss(), &test_key());

    let error_events: Vec<_> = pipeline
        .events()
        .iter()
        .filter(|e| e.error_code.is_some())
        .collect();
    assert!(!error_events.is_empty());
    assert!(
        error_events
            .iter()
            .any(|e| e.error_code.as_deref() == Some("no_matching_route"))
    );
}

#[test]
fn allow_events_have_no_error_codes() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);

    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();

    for event in pipeline.events() {
        assert!(
            event.error_code.is_none(),
            "unexpected error_code in stage {}",
            event.stage
        );
    }
}
