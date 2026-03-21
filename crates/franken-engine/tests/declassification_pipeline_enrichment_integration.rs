#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for the declassification_pipeline module.

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

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn declassification_request_serde_roundtrip() {
    let req = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let json = serde_json::to_string(&req).unwrap();
    let decoded: DeclassificationRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, decoded);
}

#[test]
fn policy_eval_result_serde_all_variants() {
    let variants = vec![
        PolicyEvalResult::RouteApproved {
            route_id: "r1".to_string(),
            conditions_met: vec!["c1".to_string()],
        },
        PolicyEvalResult::ConditionsNotMet {
            route_id: "r1".to_string(),
            failed_conditions: vec!["c2".to_string()],
        },
        PolicyEvalResult::NoMatchingRoute,
        PolicyEvalResult::PolicyUnavailable {
            reason: "gone".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let decoded: PolicyEvalResult = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, decoded);
    }
}

#[test]
fn loss_assessment_serde_roundtrip() {
    let loss = low_loss();
    let json = serde_json::to_string(&loss).unwrap();
    let decoded: LossAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(loss, decoded);
}

#[test]
fn pipeline_event_serde_roundtrip() {
    let event = PipelineEvent {
        request_id: "r1".to_string(),
        trace_id: "t1".to_string(),
        stage: "policy_evaluation".to_string(),
        outcome: "approved".to_string(),
        component: "declassification_pipeline".to_string(),
        error_code: Some("ec-1".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: PipelineEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn pipeline_error_serde_all_variants() {
    let errors = vec![
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
            expiry_ms: 1000,
        },
        PipelineError::SigningError {
            detail: "bad key".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let decoded: PipelineError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, decoded);
    }
}

#[test]
fn pipeline_stats_serde_roundtrip() {
    let stats = PipelineStats {
        decision_count: 10,
        allow_count: 7,
        deny_count: 3,
        emergency_grants_active: 1,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let decoded: PipelineStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, decoded);
}

#[test]
fn pipeline_config_serde_roundtrip() {
    let config = PipelineConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let decoded: PipelineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, decoded);
}

#[test]
fn emergency_grant_serde_roundtrip() {
    let grant = EmergencyGrant {
        grant_id: "emg-1".to_string(),
        request_id: "req-1".to_string(),
        extension_id: "ext-test".to_string(),
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        decision_contract_id: "decision-contract-test".to_string(),
        expiry_ms: 1_700_000_300_000,
        review_completed: false,
    };
    let json = serde_json::to_string(&grant).unwrap();
    let decoded: EmergencyGrant = serde_json::from_str(&json).unwrap();
    assert_eq!(grant, decoded);
}

// ---------------------------------------------------------------------------
// Display distinctness
// ---------------------------------------------------------------------------

#[test]
fn pipeline_error_display_all_distinct() {
    let errors = vec![
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
            expiry_ms: 1000,
        },
        PipelineError::SigningError {
            detail: "bad".to_string(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

// ---------------------------------------------------------------------------
// LossAssessment enrichment
// ---------------------------------------------------------------------------

#[test]
fn loss_below_threshold_when_equal_returns_false() {
    let loss = LossAssessment {
        expected_loss_milli: 100_000,
        data_sensitivity_bps: 0,
        sink_exposure_bps: 0,
        historical_abuse_detected: false,
        summary: "boundary".to_string(),
    };
    // below_threshold uses strict less-than
    assert!(!loss.below_threshold(100_000));
}

#[test]
fn loss_below_threshold_when_below() {
    let loss = low_loss();
    assert!(loss.below_threshold(LossAssessment::DEFAULT_THRESHOLD_MILLI));
}

#[test]
fn loss_default_threshold_value() {
    assert_eq!(LossAssessment::DEFAULT_THRESHOLD_MILLI, 100_000);
}

// ---------------------------------------------------------------------------
// PolicyEvalResult enrichment
// ---------------------------------------------------------------------------

#[test]
fn policy_eval_result_is_approved_only_for_route_approved() {
    assert!(
        PolicyEvalResult::RouteApproved {
            route_id: "r".to_string(),
            conditions_met: vec![],
        }
        .is_approved()
    );
    assert!(!PolicyEvalResult::NoMatchingRoute.is_approved());
    assert!(
        !PolicyEvalResult::ConditionsNotMet {
            route_id: "r".to_string(),
            failed_conditions: vec![],
        }
        .is_approved()
    );
    assert!(
        !PolicyEvalResult::PolicyUnavailable {
            reason: "x".to_string(),
        }
        .is_approved()
    );
}

// ---------------------------------------------------------------------------
// EmergencyGrant enrichment
// ---------------------------------------------------------------------------

#[test]
fn emergency_grant_is_expired_at_exact_expiry() {
    let grant = EmergencyGrant {
        grant_id: "emg-1".to_string(),
        request_id: "req-1".to_string(),
        extension_id: "ext-test".to_string(),
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        decision_contract_id: "decision-contract-test".to_string(),
        expiry_ms: 1000,
        review_completed: false,
    };
    assert!(grant.is_expired(1000)); // at exact expiry
    assert!(grant.is_expired(1001)); // after expiry
    assert!(!grant.is_expired(999)); // before expiry
}

// ---------------------------------------------------------------------------
// PipelineConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn pipeline_config_default_values() {
    let config = PipelineConfig::default();
    assert_eq!(
        config.loss_threshold_milli,
        LossAssessment::DEFAULT_THRESHOLD_MILLI
    );
    assert_eq!(config.emergency_max_duration_ms, 300_000);
    assert!(config.emit_stage_events);
}

// ---------------------------------------------------------------------------
// Pipeline: process enrichment
// ---------------------------------------------------------------------------

#[test]
fn pipeline_process_mismatched_extension_returns_policy_unavailable() {
    let mut pipeline = DeclassificationPipeline::default();
    let mut policy = make_policy();
    policy.extension_id = "different-ext".to_string();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let err = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap_err();
    assert!(matches!(err, PipelineError::PolicyUnavailable { .. }));
}

#[test]
fn pipeline_process_deny_with_high_loss_produces_deny_receipt() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let receipt = pipeline
        .process(&request, &policy, &high_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Deny);
}

#[test]
fn pipeline_process_allow_with_low_loss() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    let receipt = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Allow);
    assert!(!receipt.signature.is_sentinel());
}

#[test]
fn pipeline_flow_already_legal_rejected() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("any", Label::Public, Label::Internal);
    let err = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap_err();
    assert!(matches!(err, PipelineError::FlowAlreadyLegal { .. }));
}

// ---------------------------------------------------------------------------
// Pipeline: emergency pathway enrichment
// ---------------------------------------------------------------------------

#[test]
fn pipeline_emergency_bypasses_route() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("nonexistent", Label::Secret, Label::Public);
    request.is_emergency = true;
    let receipt = pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Allow);
    assert_eq!(receipt.declassification_route_ref, "emergency");
    assert_eq!(receipt.decision_contract_id, request.decision_contract_id);
    assert_eq!(
        receipt.replay_command(),
        "frankenctl replay run --trace <trace.json> --mode strict"
    );
}

#[test]
fn pipeline_emergency_grant_created_and_findable() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("nonexistent", Label::Secret, Label::Public);
    request.is_emergency = true;
    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    let grant = pipeline
        .check_emergency_grant(
            &request.extension_id,
            &Label::Secret,
            &Label::Public,
            &request.decision_contract_id,
            request.timestamp_ms,
        )
        .unwrap();
    assert!(!grant.review_completed);
}

#[test]
fn pipeline_emergency_review_completion() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let mut request = make_request("nonexistent", Label::Secret, Label::Public);
    request.is_emergency = true;
    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    let grant_id = format!("emg-{}", request.request_id);
    assert!(pipeline.complete_emergency_review(&grant_id));
    // After review, grant should not be found (reviewed = true)
    assert!(
        pipeline
            .check_emergency_grant(
                &request.extension_id,
                &Label::Secret,
                &Label::Public,
                &request.decision_contract_id,
                request.timestamp_ms,
            )
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Pipeline: events and receipts
// ---------------------------------------------------------------------------

#[test]
fn pipeline_events_contain_all_stages_on_allow() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    pipeline
        .process(&request, &policy, &low_loss(), &test_key())
        .unwrap();
    let stages: BTreeSet<String> = pipeline.events().iter().map(|e| e.stage.clone()).collect();
    assert!(stages.contains("request_validation"));
    assert!(stages.contains("policy_evaluation"));
    assert!(stages.contains("loss_assessment"));
    assert!(stages.contains("decision"));
    assert!(stages.contains("signed_receipt"));
}

#[test]
fn pipeline_drain_events_clears() {
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
fn pipeline_receipts_accumulate() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let r1 = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    pipeline
        .process(&r1, &policy, &low_loss(), &test_key())
        .unwrap();
    let mut r2 = make_request("declass-conf-public", Label::Confidential, Label::Public);
    r2.request_id = "req-2".to_string();
    pipeline
        .process(&r2, &policy, &low_loss(), &test_key())
        .unwrap();
    assert_eq!(pipeline.receipts().len(), 2);
}

// ---------------------------------------------------------------------------
// Pipeline: statistics enrichment
// ---------------------------------------------------------------------------

#[test]
fn pipeline_stats_initial() {
    let pipeline = DeclassificationPipeline::default();
    let stats = pipeline.stats();
    assert_eq!(stats.decision_count, 0);
    assert_eq!(stats.allow_count, 0);
    assert_eq!(stats.deny_count, 0);
    assert_eq!(stats.emergency_grants_active, 0);
}

#[test]
fn pipeline_stats_after_allow_and_deny() {
    let mut pipeline = DeclassificationPipeline::default();
    let policy = make_policy();
    let key = test_key();

    // Allow
    let r1 = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    pipeline.process(&r1, &policy, &low_loss(), &key).unwrap();

    // Deny (high loss)
    let mut r2 = make_request("declass-conf-public", Label::Confidential, Label::Public);
    r2.request_id = "req-deny".to_string();
    pipeline.process(&r2, &policy, &high_loss(), &key).unwrap();

    let stats = pipeline.stats();
    assert_eq!(stats.decision_count, 2);
    assert_eq!(stats.allow_count, 1);
    assert_eq!(stats.deny_count, 1);
}

// ---------------------------------------------------------------------------
// Pipeline: config with events disabled
// ---------------------------------------------------------------------------

#[test]
fn pipeline_config_no_events_disables_emission() {
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

// ---------------------------------------------------------------------------
// Deterministic replay enrichment
// ---------------------------------------------------------------------------

#[test]
fn pipeline_deterministic_50_iterations() {
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
        assert_eq!(r.signature, first.signature);
    }
}

// ---------------------------------------------------------------------------
// Pipeline: custom loss threshold
// ---------------------------------------------------------------------------

#[test]
fn pipeline_custom_loss_threshold_allows_higher_loss() {
    let config = PipelineConfig {
        loss_threshold_milli: 600_000, // high threshold
        ..PipelineConfig::default()
    };
    let mut pipeline = DeclassificationPipeline::new(config);
    let policy = make_policy();
    let request = make_request("declass-secret-internal", Label::Secret, Label::Internal);
    // high_loss has expected_loss_milli = 500_000, below 600_000 threshold
    let receipt = pipeline
        .process(&request, &policy, &high_loss(), &test_key())
        .unwrap();
    assert_eq!(receipt.decision, DeclassificationDecision::Allow);
}
