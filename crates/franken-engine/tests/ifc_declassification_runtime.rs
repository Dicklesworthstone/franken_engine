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
    DeclassificationPipeline, DeclassificationRequest, LossAssessment, PipelineConfig,
};
use frankenengine_engine::flow_lattice::{
    Clearance, DeclassificationObligation, FlowCheckResult, FlowLatticeError, Ir2FlowLattice,
    LabelClass,
};
use frankenengine_engine::ifc_artifacts::{
    DeclassificationRoute, FlowPolicy, IfcSchemaVersion, Label,
};
use frankenengine_engine::signature_preimage::{Signature, SigningKey, SIGNATURE_SENTINEL};

const RUNTIME_ROUTE_ID: &str = "declass-secret-public";

fn make_policy() -> FlowPolicy {
    FlowPolicy {
        policy_id: "policy-ifc-runtime".to_string(),
        extension_id: "ext-ifc-runtime".to_string(),
        label_classes: [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        clearance_classes: [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>(),
        allowed_flows: vec![],
        prohibited_flows: vec![],
        declassification_routes: vec![DeclassificationRoute {
            route_id: RUNTIME_ROUTE_ID.to_string(),
            source_label: Label::Secret,
            target_clearance: Label::Public,
            conditions: vec!["audit_approval".to_string()],
        }],
        epoch_id: 7,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    }
}

fn make_request() -> DeclassificationRequest {
    DeclassificationRequest {
        request_id: format!("req-{RUNTIME_ROUTE_ID}"),
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        extension_id: "ext-ifc-runtime".to_string(),
        code_location: "runtime::egress".to_string(),
        trace_id: "trace-ifc-runtime".to_string(),
        requested_route_id: RUNTIME_ROUTE_ID.to_string(),
        is_emergency: false,
        timestamp_ms: 1_700_000_010_000,
    }
}

fn low_loss() -> LossAssessment {
    LossAssessment {
        expected_loss_milli: 10_000,
        data_sensitivity_bps: 1_200,
        sink_exposure_bps: 800,
        historical_abuse_detected: false,
        summary: "low risk".to_string(),
    }
}

fn high_loss() -> LossAssessment {
    LossAssessment {
        expected_loss_milli: 500_000,
        data_sensitivity_bps: 9_200,
        sink_exposure_bps: 8_400,
        historical_abuse_detected: true,
        summary: "high risk".to_string(),
    }
}

#[test]
fn runtime_lattice_emits_receipt_linkage_for_authorized_declassification() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    lattice
        .register_obligation(DeclassificationObligation {
            obligation_id: "obl-secret-egress".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "decision-contract-ifc".to_string(),
            requires_operator_approval: true,
            max_uses: 4,
            use_count: 0,
        })
        .expect("register obligation");

    let flow_check = lattice.check_flow(
        &LabelClass::Secret,
        &Clearance::NeverSink,
        "trace-ifc-runtime",
    );
    assert_eq!(
        flow_check,
        FlowCheckResult::RequiresDeclassification {
            obligation_id: "obl-secret-egress".to_string(),
        }
    );

    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([5u8; 32]);
    let receipt = pipeline
        .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
        .expect("allow receipt");
    lattice.trust_receipt_authorizer(signing_key.verification_key());

    lattice
        .use_declassification_with_receipt("obl-secret-egress", &receipt, "trace-ifc-runtime")
        .expect("receipt-linked usage should succeed");

    let last_event = lattice.events().last().expect("event");
    assert_eq!(last_event.event, "use_declassification");
    assert_eq!(last_event.outcome, "ok");
    assert_eq!(
        last_event.obligation_id.as_deref(),
        Some("obl-secret-egress")
    );
    assert_eq!(
        last_event.decision_contract_id.as_deref(),
        Some("decision-contract-ifc")
    );
    assert_eq!(
        last_event.receipt_id.as_deref(),
        Some(receipt.receipt_id.as_str())
    );
    assert_eq!(
        last_event.receipt_replay_command.as_deref(),
        Some(receipt.replay_command().as_str())
    );
    assert_eq!(
        lattice
            .obligation("obl-secret-egress")
            .map(|ob| ob.use_count),
        Some(1)
    );
}

#[test]
fn runtime_lattice_rejects_denied_receipt_and_keeps_obligation_unused() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    lattice
        .register_obligation(DeclassificationObligation {
            obligation_id: "obl-secret-egress".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "decision-contract-ifc".to_string(),
            requires_operator_approval: true,
            max_uses: 1,
            use_count: 0,
        })
        .expect("register obligation");

    let flow_check = lattice.check_flow(
        &LabelClass::Secret,
        &Clearance::NeverSink,
        "trace-ifc-runtime",
    );
    assert!(matches!(
        flow_check,
        FlowCheckResult::RequiresDeclassification { .. }
    ));

    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([6u8; 32]);
    let denied_receipt = pipeline
        .process(&make_request(), &make_policy(), &high_loss(), &signing_key)
        .expect("pipeline returns deny receipt");
    assert_eq!(denied_receipt.decision.to_string(), "deny");
    lattice.trust_receipt_authorizer(signing_key.verification_key());

    let event_count_before = lattice.events().len();
    let err = lattice
        .use_declassification_with_receipt(
            "obl-secret-egress",
            &denied_receipt,
            "trace-ifc-runtime",
        )
        .expect_err("deny receipt must fail closed");
    assert!(matches!(err, FlowLatticeError::FlowBlocked { .. }));
    assert_eq!(lattice.events().len(), event_count_before);
    assert_eq!(
        lattice
            .obligation("obl-secret-egress")
            .map(|ob| ob.use_count),
        Some(0)
    );
}

#[test]
fn runtime_lattice_rejects_tampered_allow_receipt_signature() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    lattice
        .register_obligation(DeclassificationObligation {
            obligation_id: "obl-secret-egress".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "decision-contract-ifc".to_string(),
            requires_operator_approval: true,
            max_uses: 1,
            use_count: 0,
        })
        .expect("register obligation");

    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([7u8; 32]);
    let mut tampered_receipt = pipeline
        .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
        .expect("allow receipt");
    lattice.trust_receipt_authorizer(signing_key.verification_key());
    tampered_receipt.policy_evaluation_summary = "tampered summary".to_string();

    let event_count_before = lattice.events().len();
    let err = lattice
        .use_declassification_with_receipt(
            "obl-secret-egress",
            &tampered_receipt,
            "trace-ifc-runtime",
        )
        .expect_err("tampered receipt must fail closed");
    match err {
        FlowLatticeError::FlowBlocked { detail } => {
            assert!(
                detail.contains("failed signature verification"),
                "unexpected error detail: {detail}"
            );
        }
        other => panic!("expected FlowBlocked for tampered receipt, got {other:?}"),
    }
    assert_eq!(lattice.events().len(), event_count_before);
    assert_eq!(
        lattice
            .obligation("obl-secret-egress")
            .map(|ob| ob.use_count),
        Some(0)
    );
}

// ---------- pipeline decision variants ----------

#[test]
fn pipeline_allows_declassification_when_loss_below_threshold() {
    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([8u8; 32]);
    let receipt = pipeline
        .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
        .expect("should allow");
    assert_eq!(receipt.decision.to_string(), "allow");
    assert!(!receipt.receipt_id.is_empty());
}

#[test]
fn pipeline_denies_declassification_when_loss_above_threshold() {
    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([9u8; 32]);
    let receipt = pipeline
        .process(&make_request(), &make_policy(), &high_loss(), &signing_key)
        .expect("should deny");
    assert_eq!(receipt.decision.to_string(), "deny");
}

#[test]
fn pipeline_tracks_stats_across_decisions() {
    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([10u8; 32]);

    let _allow = pipeline
        .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
        .expect("allow");
    let _deny = pipeline
        .process(&make_request(), &make_policy(), &high_loss(), &signing_key)
        .expect("deny");

    let stats = pipeline.stats();
    assert_eq!(stats.decision_count, 2);
    assert_eq!(stats.allow_count, 1);
    assert_eq!(stats.deny_count, 1);
}

#[test]
fn pipeline_emits_events_for_allow_decision() {
    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([11u8; 32]);

    let _receipt = pipeline
        .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
        .expect("allow");

    let events = pipeline.events();
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .any(|e| e.outcome == "allow" || e.outcome == "pass"),
        "events should contain allow/pass outcome"
    );
}

#[test]
fn pipeline_receipts_accumulate() {
    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([12u8; 32]);

    for _ in 0..3 {
        let _receipt = pipeline
            .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
            .expect("allow");
    }

    assert_eq!(pipeline.receipts().len(), 3);
}

// ---------- loss assessment ----------

#[test]
fn loss_assessment_below_threshold_returns_true() {
    let loss = low_loss();
    assert!(loss.below_threshold(100_000));
}

#[test]
fn loss_assessment_above_threshold_returns_false() {
    let loss = high_loss();
    assert!(!loss.below_threshold(100_000));
}

#[test]
fn loss_assessment_at_exactly_threshold_returns_false() {
    let loss = LossAssessment {
        expected_loss_milli: 100_000,
        data_sensitivity_bps: 5_000,
        sink_exposure_bps: 5_000,
        historical_abuse_detected: false,
        summary: "borderline".to_string(),
    };
    assert!(!loss.below_threshold(100_000));
}

// ---------- obligation lifecycle ----------

#[test]
fn obligation_max_uses_enforced_after_exhaustion() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    lattice
        .register_obligation(DeclassificationObligation {
            obligation_id: "obl-limited".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "decision-contract-ifc".to_string(),
            requires_operator_approval: true,
            max_uses: 1,
            use_count: 0,
        })
        .expect("register obligation");

    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([13u8; 32]);
    let receipt = pipeline
        .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
        .expect("allow receipt");
    lattice.trust_receipt_authorizer(signing_key.verification_key());

    lattice
        .use_declassification_with_receipt("obl-limited", &receipt, "trace-use-1")
        .expect("first use");

    assert_eq!(
        lattice.obligation("obl-limited").map(|ob| ob.use_count),
        Some(1)
    );

    let receipt2 = pipeline
        .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
        .expect("second allow");
    let err = lattice
        .use_declassification_with_receipt("obl-limited", &receipt2, "trace-use-2")
        .expect_err("second use should fail");
    assert!(
        matches!(err, FlowLatticeError::ObligationExhausted { .. })
            || matches!(err, FlowLatticeError::FlowBlocked { .. }),
        "expected obligation exhausted or flow blocked, got: {err:?}"
    );
}

#[test]
fn runtime_lattice_rejects_untrusted_receipt_authorizer() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    lattice
        .register_obligation(DeclassificationObligation {
            obligation_id: "obl-secret-egress".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "decision-contract-ifc".to_string(),
            requires_operator_approval: true,
            max_uses: 1,
            use_count: 0,
        })
        .expect("register obligation");

    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([21u8; 32]);
    let receipt = pipeline
        .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
        .expect("allow receipt");

    let err = lattice
        .use_declassification_with_receipt("obl-secret-egress", &receipt, "trace-ifc-runtime")
        .expect_err("untrusted receipt authorizer must fail closed");
    match err {
        FlowLatticeError::FlowBlocked { detail } => {
            assert!(
                detail.contains("authorizer is not trusted"),
                "unexpected error detail: {detail}"
            );
        }
        other => panic!("expected FlowBlocked for untrusted authorizer, got {other:?}"),
    }
    assert_eq!(
        lattice
            .obligation("obl-secret-egress")
            .map(|ob| ob.use_count),
        Some(0)
    );
}

#[test]
fn runtime_lattice_rejects_cross_trace_receipt_replay() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    lattice
        .register_obligation(DeclassificationObligation {
            obligation_id: "obl-secret-egress".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "decision-contract-ifc".to_string(),
            requires_operator_approval: true,
            max_uses: 1,
            use_count: 0,
        })
        .expect("register obligation");

    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([22u8; 32]);
    let request = make_request();
    let receipt = pipeline
        .process(&request, &make_policy(), &low_loss(), &signing_key)
        .expect("allow receipt");
    lattice.trust_receipt_authorizer(signing_key.verification_key());

    let err = lattice
        .use_declassification_with_receipt("obl-secret-egress", &receipt, "trace-ifc-runtime-other")
        .expect_err("cross-trace replay must fail closed");
    match err {
        FlowLatticeError::FlowBlocked { detail } => {
            assert!(
                detail.contains("replay linkage does not match trace"),
                "unexpected error detail: {detail}"
            );
        }
        other => panic!("expected FlowBlocked for cross-trace replay, got {other:?}"),
    }
    assert_eq!(
        lattice
            .obligation("obl-secret-egress")
            .map(|ob| ob.use_count),
        Some(0)
    );
}

#[test]
fn runtime_lattice_rejects_receipt_with_sink_clearance_mismatch() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    lattice
        .register_obligation(DeclassificationObligation {
            obligation_id: "obl-secret-egress".to_string(),
            source_label: LabelClass::Secret,
            target_clearance: Clearance::NeverSink,
            decision_contract_id: "decision-contract-ifc".to_string(),
            requires_operator_approval: true,
            max_uses: 1,
            use_count: 0,
        })
        .expect("register obligation");

    let mut mismatch_policy = make_policy();
    mismatch_policy.declassification_routes[0].route_id = "declass-secret-internal".to_string();
    mismatch_policy.declassification_routes[0].target_clearance = Label::Internal;

    let mut request = make_request();
    request.requested_route_id = "declass-secret-internal".to_string();
    request.sink_clearance = Label::Internal;

    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([23u8; 32]);
    let receipt = pipeline
        .process(&request, &mismatch_policy, &low_loss(), &signing_key)
        .expect("allow receipt");
    lattice.trust_receipt_authorizer(signing_key.verification_key());

    let err = lattice
        .use_declassification_with_receipt("obl-secret-egress", &receipt, "trace-ifc-runtime")
        .expect_err("sink-clearance mismatch must fail closed");
    match err {
        FlowLatticeError::FlowBlocked { detail } => {
            assert!(
                detail.contains("declassified label internal cannot flow"),
                "unexpected error detail: {detail}"
            );
        }
        other => panic!("expected FlowBlocked for sink mismatch, got {other:?}"),
    }
    assert_eq!(
        lattice
            .obligation("obl-secret-egress")
            .map(|ob| ob.use_count),
        Some(0)
    );
}

#[test]
fn obligation_lookup_returns_none_for_nonexistent_id() {
    let lattice = Ir2FlowLattice::new("policy-nonexistent");
    assert!(lattice.obligation("nonexistent-obl").is_none());
}

#[test]
fn flow_check_public_to_open_sink_is_legal() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    let result = lattice.check_flow(
        &LabelClass::Public,
        &Clearance::OpenSink,
        "trace-public-flow",
    );
    assert_eq!(result, FlowCheckResult::LegalByLattice);
}

// ---------- pipeline config ----------

#[test]
fn pipeline_with_custom_threshold_allows_high_loss() {
    let config = PipelineConfig {
        loss_threshold_milli: 600_000,
        ..PipelineConfig::default()
    };
    let mut pipeline = DeclassificationPipeline::new(config);
    let signing_key = SigningKey::from_bytes([14u8; 32]);

    let receipt = pipeline
        .process(&make_request(), &make_policy(), &high_loss(), &signing_key)
        .expect("receipt");
    assert_eq!(receipt.decision.to_string(), "allow");
}

// ---------- receipt fields ----------

#[test]
fn receipt_contains_replay_command() {
    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([15u8; 32]);
    let receipt = pipeline
        .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
        .expect("allow receipt");

    let cmd = receipt.replay_command();
    assert!(!cmd.is_empty());
}

#[test]
fn receipt_policy_evaluation_summary_is_nonempty() {
    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([16u8; 32]);
    let receipt = pipeline
        .process(&make_request(), &make_policy(), &low_loss(), &signing_key)
        .expect("allow receipt");
    assert!(!receipt.policy_evaluation_summary.is_empty());
}

// ---------- lattice events ----------

#[test]
fn lattice_events_start_empty() {
    let lattice = Ir2FlowLattice::new("policy-fresh");
    assert!(lattice.events().is_empty());
}

#[test]
fn lattice_records_check_flow_event() {
    let mut lattice = Ir2FlowLattice::new("policy-ifc-runtime");
    let _result = lattice.check_flow(
        &LabelClass::Public,
        &Clearance::OpenSink,
        "trace-event-check",
    );

    assert!(
        lattice.events().iter().any(|e| e.event == "check_flow"),
        "lattice should record check_flow event"
    );
}

// ---------- serde roundtrip ----------

#[test]
fn declassification_request_serde_roundtrip() {
    let req = make_request();
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: DeclassificationRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.request_id, req.request_id);
    assert_eq!(recovered.source_label, req.source_label);
}

#[test]
fn loss_assessment_serde_roundtrip() {
    let loss = low_loss();
    let json = serde_json::to_string(&loss).expect("serialize");
    let recovered: LossAssessment = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.expected_loss_milli, loss.expected_loss_milli);
}

// ---------- label serde ----------

#[test]
fn label_serde_roundtrip_all_builtin() {
    for label in Label::all_builtin() {
        let json = serde_json::to_string(&label).expect("serialize");
        let recovered: Label = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, label);
    }
}

#[test]
fn label_custom_serde_roundtrip() {
    let label = Label::Custom {
        name: "PII".to_string(),
        level: 2,
    };
    let json = serde_json::to_string(&label).expect("serialize");
    let recovered: Label = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, label);
}

#[test]
fn label_lattice_join_meet() {
    let secret = Label::Secret;
    let public = Label::Public;
    assert_eq!(secret.join(&public), Label::Secret);
    assert_eq!(secret.meet(&public), Label::Public);
}

#[test]
fn label_can_flow_to() {
    assert!(Label::Public.can_flow_to(&Label::Secret));
    assert!(Label::Secret.can_flow_to(&Label::Secret));
    assert!(!Label::Secret.can_flow_to(&Label::Public));
}

#[test]
fn label_join_all_and_meet_all() {
    let labels = vec![Label::Public, Label::Internal, Label::Secret];
    assert_eq!(Label::join_all(labels.clone()), Some(Label::Secret));
    assert_eq!(Label::meet_all(labels), Some(Label::Public));
    assert_eq!(Label::join_all(Vec::new()), None);
}

// ---------- clearance serde ----------

#[test]
fn clearance_serde_roundtrip() {
    let variants = [Clearance::OpenSink, Clearance::NeverSink];
    for c in &variants {
        let json = serde_json::to_string(c).expect("serialize");
        let recovered: Clearance = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, c);
    }
}

#[test]
fn clearance_display() {
    assert_eq!(Clearance::OpenSink.to_string(), "open_sink");
    assert_eq!(Clearance::NeverSink.to_string(), "never_sink");
}

#[test]
fn clearance_meet_join() {
    let open = Clearance::OpenSink;
    let never = Clearance::NeverSink;
    assert_eq!(open.meet(&never), Clearance::OpenSink);
    assert_eq!(open.join(&never), Clearance::NeverSink);
}

// ---------- label_class serde ----------

#[test]
fn label_class_serde_roundtrip() {
    let classes = [
        LabelClass::Public,
        LabelClass::Secret,
        LabelClass::TopSecret,
    ];
    for lc in &classes {
        let json = serde_json::to_string(lc).expect("serialize");
        let recovered: LabelClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, lc);
    }
}

// ---------- flow_check_result serde ----------

#[test]
fn flow_check_result_serde_roundtrip() {
    let results = [
        FlowCheckResult::LegalByLattice,
        FlowCheckResult::RequiresDeclassification {
            obligation_id: "obl-1".to_string(),
        },
        FlowCheckResult::Blocked {
            source: LabelClass::Secret,
            sink: Clearance::NeverSink,
        },
    ];
    for r in &results {
        let json = serde_json::to_string(r).expect("serialize");
        let recovered: FlowCheckResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, r);
    }
}

#[test]
fn flow_check_result_predicates() {
    assert!(FlowCheckResult::LegalByLattice.is_legal());
    assert!(!FlowCheckResult::LegalByLattice.is_blocked());
    let blocked = FlowCheckResult::Blocked {
        source: LabelClass::Secret,
        sink: Clearance::NeverSink,
    };
    assert!(blocked.is_blocked());
    assert!(!blocked.is_legal());
}

// ---------- flow_lattice_error ----------

#[test]
fn flow_lattice_error_display_unique_variants() {
    let errors = [
        FlowLatticeError::ObligationExhausted {
            obligation_id: "obl-x".to_string(),
        },
        FlowLatticeError::ObligationNotFound {
            obligation_id: "obl-x".to_string(),
        },
        FlowLatticeError::DuplicateObligation {
            obligation_id: "obl-x".to_string(),
        },
        FlowLatticeError::FlowBlocked {
            detail: "test".to_string(),
        },
    ];
    let messages: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(messages.len(), errors.len());
}

#[test]
fn flow_lattice_error_is_std_error() {
    let err: &dyn std::error::Error = &FlowLatticeError::FlowBlocked {
        detail: "test".to_string(),
    };
    assert!(!err.to_string().is_empty());
}

// ---------- pipeline_config ----------

#[test]
fn pipeline_config_serde_roundtrip() {
    let config = PipelineConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: PipelineConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, config);
}

#[test]
fn pipeline_config_default_emit_stage_events() {
    let config = PipelineConfig::default();
    assert!(config.emit_stage_events);
}

// ---------- declassification_route serde ----------

#[test]
fn declassification_route_serde_roundtrip() {
    let route = DeclassificationRoute {
        route_id: "route-1".to_string(),
        source_label: Label::Secret,
        target_clearance: Label::Internal,
        conditions: vec!["audit".to_string()],
    };
    let json = serde_json::to_string(&route).expect("serialize");
    let recovered: DeclassificationRoute = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.route_id, route.route_id);
    assert_eq!(recovered.source_label, route.source_label);
}

// ---------- ifc_schema_version ----------

#[test]
fn ifc_schema_version_current_is_1_0_0() {
    let v = IfcSchemaVersion::CURRENT;
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
    assert_eq!(v.patch, 0);
    assert_eq!(v.to_string(), "1.0.0");
}

#[test]
fn ifc_schema_version_compatibility() {
    let v1_0 = IfcSchemaVersion::new(1, 0, 0);
    let v1_1 = IfcSchemaVersion::new(1, 1, 0);
    let v2_0 = IfcSchemaVersion::new(2, 0, 0);
    assert!(v1_1.is_compatible_with(&v1_0));
    assert!(!v1_0.is_compatible_with(&v1_1));
    assert!(!v2_0.is_compatible_with(&v1_0));
}

#[test]
fn ifc_schema_version_serde_roundtrip() {
    let v = IfcSchemaVersion::CURRENT;
    let json = serde_json::to_string(&v).expect("serialize");
    let recovered: IfcSchemaVersion = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, v);
}

// ---------- flow_policy serde ----------

#[test]
fn flow_policy_serde_roundtrip() {
    let policy = make_policy();
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: FlowPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.policy_id, policy.policy_id);
    assert_eq!(recovered.epoch_id, policy.epoch_id);
    assert_eq!(recovered.declassification_routes.len(), 1);
}

// ---------- duplicate obligation ----------

#[test]
fn duplicate_obligation_registration_rejected() {
    let mut lattice = Ir2FlowLattice::new("policy-dup");
    let obl = DeclassificationObligation {
        obligation_id: "obl-dup".to_string(),
        source_label: LabelClass::Secret,
        target_clearance: Clearance::NeverSink,
        decision_contract_id: "dc".to_string(),
        requires_operator_approval: false,
        max_uses: 5,
        use_count: 0,
    };
    lattice.register_obligation(obl.clone()).expect("first");
    let err = lattice
        .register_obligation(obl)
        .expect_err("duplicate should fail");
    assert!(matches!(err, FlowLatticeError::DuplicateObligation { .. }));
}

// ---------- emergency grant ----------

#[test]
fn pipeline_emergency_request_creates_grant() {
    let mut pipeline = DeclassificationPipeline::default();
    let signing_key = SigningKey::from_bytes([20u8; 32]);
    let mut req = make_request();
    req.is_emergency = true;

    let receipt = pipeline
        .process(&req, &make_policy(), &high_loss(), &signing_key)
        .expect("emergency receipt");
    // Emergency requests should produce a receipt regardless of loss
    assert!(!receipt.receipt_id.is_empty());
}
