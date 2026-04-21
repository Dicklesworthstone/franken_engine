use frankenengine_extension_host::{
    Capability, DataRef, DecisionContract, DecisionSigningKey, DecisionVerdict,
    DeclassificationDenialReason, DeclassificationEvaluationContext, DeclassificationGateway,
    DeclassificationOutcome, DeclassificationPurpose, DeclassificationRequest, DenialReason,
    FlowEnforcementContext, FlowLabel, FlowLabelLattice, HostcallDispatcher, HostcallResult,
    HostcallSinkPolicy, HostcallType, IntegrityLevel, LabelDistanceContract, Labeled,
    RateLimitContract, RequesterCapabilityContract, SecrecyLevel, SinkClearance,
};
use std::collections::BTreeSet;

fn capability_set(values: &[Capability]) -> BTreeSet<Capability> {
    values.iter().copied().collect()
}

fn test_context() -> FlowEnforcementContext<'static> {
    FlowEnforcementContext::new("trace-test", "decision-test", "policy-test")
}

// ───────────────────────────────────────────────────────────────
// SecrecyLevel
// ───────────────────────────────────────────────────────────────

#[test]
fn secrecy_level_rank_ordering_is_monotonic() {
    let levels = [
        SecrecyLevel::Public,
        SecrecyLevel::Internal,
        SecrecyLevel::Confidential,
        SecrecyLevel::Secret,
        SecrecyLevel::TopSecret,
    ];
    for window in levels.windows(2) {
        assert!(
            window[0].rank() < window[1].rank(),
            "{:?} should rank below {:?}",
            window[0],
            window[1]
        );
    }
}

// ───────────────────────────────────────────────────────────────
// IntegrityLevel
// ───────────────────────────────────────────────────────────────

#[test]
fn integrity_level_rank_ordering_is_monotonic() {
    let levels = [
        IntegrityLevel::Untrusted,
        IntegrityLevel::Validated,
        IntegrityLevel::Verified,
        IntegrityLevel::Trusted,
    ];
    for window in levels.windows(2) {
        assert!(
            window[0].rank() < window[1].rank(),
            "{:?} should rank below {:?}",
            window[0],
            window[1]
        );
    }
}

// ───────────────────────────────────────────────────────────────
// FlowLabel
// ───────────────────────────────────────────────────────────────

#[test]
fn flow_label_default_is_maximally_restrictive() {
    let label = FlowLabel::default();
    assert_eq!(label.secrecy(), SecrecyLevel::TopSecret);
    assert_eq!(label.integrity(), IntegrityLevel::Untrusted);
}

#[test]
fn flow_label_join_takes_max_secrecy_min_integrity() {
    let a = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Verified);
    let b = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated);
    let joined = a.join(b);
    assert_eq!(joined.secrecy(), SecrecyLevel::Secret);
    assert_eq!(joined.integrity(), IntegrityLevel::Validated);
}

#[test]
fn flow_label_join_is_commutative() {
    let a = FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Trusted);
    let b = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Untrusted);
    assert_eq!(a.join(b), b.join(a));
}

#[test]
fn flow_label_join_with_self_is_identity() {
    let label = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Verified);
    assert_eq!(label.join(label), label);
}

// ───────────────────────────────────────────────────────────────
// FlowLabelLattice (Bell-LaPadula + Biba)
// ───────────────────────────────────────────────────────────────

#[test]
fn lattice_allows_flow_to_same_level() {
    let label = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
    assert!(FlowLabelLattice::can_flow(&label, &label));
}

#[test]
fn lattice_allows_flow_to_higher_secrecy() {
    let low = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    let high = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Trusted);
    assert!(FlowLabelLattice::can_flow(&low, &high));
}

#[test]
fn lattice_blocks_flow_to_lower_secrecy() {
    let high = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Trusted);
    let low = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    assert!(!FlowLabelLattice::can_flow(&high, &low));
}

#[test]
fn lattice_allows_flow_to_lower_integrity() {
    let high = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    let low = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Untrusted);
    assert!(FlowLabelLattice::can_flow(&high, &low));
}

#[test]
fn lattice_blocks_flow_to_higher_integrity() {
    let low = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Untrusted);
    let high = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    assert!(!FlowLabelLattice::can_flow(&low, &high));
}

#[test]
fn lattice_sink_clearance_allows_within_bounds() {
    let label = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
    let sink = SinkClearance::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
    assert!(FlowLabelLattice::can_flow_to_sink(&label, &sink));
}

#[test]
fn lattice_sink_clearance_blocks_above_max_secrecy() {
    let label = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated);
    let sink = SinkClearance::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
    assert!(!FlowLabelLattice::can_flow_to_sink(&label, &sink));
}

#[test]
fn lattice_sink_clearance_blocks_below_min_integrity() {
    let label = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Untrusted);
    let sink = SinkClearance::new(SecrecyLevel::Internal, IntegrityLevel::Validated);
    assert!(!FlowLabelLattice::can_flow_to_sink(&label, &sink));
}

// ───────────────────────────────────────────────────────────────
// Labeled<T>
// ───────────────────────────────────────────────────────────────

#[test]
fn labeled_preserves_value_and_label() {
    let label = FlowLabel::new(SecrecyLevel::Internal, IntegrityLevel::Verified);
    let labeled = Labeled::new(42u32, label);
    assert_eq!(*labeled.value(), 42);
    assert_eq!(labeled.label(), label);
}

#[test]
fn labeled_from_trait_uses_default_maximally_restrictive_label() {
    let labeled = Labeled::from("hello");
    assert_eq!(labeled.label(), FlowLabel::default());
    assert_eq!(*labeled.value(), "hello");
}

#[test]
fn labeled_system_generated_uses_public_trusted() {
    let labeled = Labeled::<u32>::system_generated(99);
    assert_eq!(labeled.label().secrecy(), SecrecyLevel::Public);
    assert_eq!(labeled.label().integrity(), IntegrityLevel::Trusted);
    assert!(!labeled.label().is_host_trusted());
}

#[test]
fn labeled_map_preserves_label() {
    let label = FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated);
    let original = Labeled::new(10u32, label);
    let mapped = original.map(|v| v * 2);
    assert_eq!(*mapped.value(), 20);
    assert_eq!(mapped.label(), label);
}

#[test]
fn labeled_into_inner_extracts_value() {
    let labeled = Labeled::new("data".to_string(), FlowLabel::default());
    let inner = labeled.into_inner();
    assert_eq!(inner, "data");
}

// ───────────────────────────────────────────────────────────────
// HostcallType
// ───────────────────────────────────────────────────────────────

#[test]
fn hostcall_type_sink_identification() {
    assert!(HostcallType::FsWrite.is_sink());
    assert!(HostcallType::NetworkSend.is_sink());
    assert!(HostcallType::IpcSend.is_sink());
    assert!(!HostcallType::FsRead.is_sink());
    assert!(!HostcallType::NetworkRecv.is_sink());
    assert!(!HostcallType::MemAlloc.is_sink());
    assert!(!HostcallType::CryptoOp.is_sink());
}

#[test]
fn hostcall_type_as_str_matches_display() {
    let types = [
        HostcallType::FsRead,
        HostcallType::FsWrite,
        HostcallType::NetworkSend,
        HostcallType::NetworkRecv,
        HostcallType::ProcessSpawn,
        HostcallType::EnvRead,
        HostcallType::MemAlloc,
        HostcallType::TimerCreate,
        HostcallType::CryptoOp,
        HostcallType::IpcSend,
        HostcallType::IpcRecv,
    ];
    for t in types {
        assert_eq!(t.as_str(), format!("{t}"));
    }
}

// ───────────────────────────────────────────────────────────────
// HostcallDispatcher
// ───────────────────────────────────────────────────────────────

#[test]
fn dispatcher_allows_capable_non_sink_hostcall() {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let caps = capability_set(&[Capability::FsRead]);
    let arg = Labeled::system_generated("path/to/file".to_string());
    let ctx = test_context();

    let outcome = dispatcher.dispatch(
        "ext-1",
        HostcallType::FsRead,
        &caps,
        Capability::FsRead,
        arg,
        &ctx,
    );
    assert_eq!(outcome.result, HostcallResult::Success);
    assert!(outcome.output.is_some());
    assert!(dispatcher.violation_events().is_empty());
}

#[test]
fn dispatcher_denies_capability_escalation() {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let caps = capability_set(&[Capability::FsRead]);
    let arg = Labeled::system_generated("data".to_string());
    let ctx = test_context();

    let outcome = dispatcher.dispatch(
        "ext-2",
        HostcallType::FsWrite,
        &caps,
        Capability::FsWrite,
        arg,
        &ctx,
    );

    match &outcome.result {
        HostcallResult::Denied {
            reason: DenialReason::CapabilityEscalation { attempted },
        } => {
            assert_eq!(*attempted, Capability::FsWrite);
        }
        other => panic!("expected capability escalation denial, got {other:?}"),
    }
    assert!(outcome.output.is_none());
    // Capability escalation does NOT produce flow violation events
    assert!(dispatcher.violation_events().is_empty());
}

#[test]
fn dispatcher_denies_flow_violation_on_sink() {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let caps = capability_set(&[Capability::FsWrite, Capability::FsRead]);
    // Secret data trying to flow to fs_write (default max_secrecy = Internal)
    let secret_data = Labeled::new(
        "secret payload".to_string(),
        FlowLabel::new(SecrecyLevel::Secret, IntegrityLevel::Validated),
    );
    let ctx = test_context();

    let outcome = dispatcher.dispatch(
        "ext-3",
        HostcallType::FsWrite,
        &caps,
        Capability::FsWrite,
        secret_data,
        &ctx,
    );

    match &outcome.result {
        HostcallResult::Denied {
            reason: DenialReason::FlowViolation { source, sink },
        } => {
            assert_eq!(*source, FlowLabel::default());
            assert_eq!(sink.max_secrecy, SecrecyLevel::Internal);
        }
        other => panic!("expected flow violation denial, got {other:?}"),
    }
    assert!(outcome.output.is_none());
    assert_eq!(dispatcher.violation_events().len(), 1);
    assert_eq!(dispatcher.guardplane_evidence().len(), 1);
}

#[test]
fn untrusted_payload_constructors_cannot_spoof_host_trusted_sink_label() {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let caps = capability_set(&[Capability::NetClient]);
    let ctx = test_context();

    let forged_label = FlowLabel::new(SecrecyLevel::Public, IntegrityLevel::Trusted);
    assert!(!forged_label.is_host_trusted());
    let forged = Labeled::new("exfil".to_string(), forged_label);
    assert!(!forged.label().is_host_trusted());

    let outcome = dispatcher.dispatch(
        "ext-forged-label",
        HostcallType::NetworkSend,
        &caps,
        Capability::NetClient,
        forged,
        &ctx,
    );

    match &outcome.result {
        HostcallResult::Denied {
            reason: DenialReason::FlowViolation { source, sink },
        } => {
            assert_eq!(*source, FlowLabel::default());
            assert_eq!(sink.max_secrecy, SecrecyLevel::Public);
        }
        other => panic!("expected untrusted constructor spoof to be denied, got {other:?}"),
    }
    assert!(outcome.output.is_none());
    assert_eq!(dispatcher.violation_events().len(), 1);

    let system_generated = Labeled::system_generated("exfil-again".to_string());
    assert!(!system_generated.label().is_host_trusted());
    let outcome = dispatcher.dispatch(
        "ext-system-generated",
        HostcallType::NetworkSend,
        &caps,
        Capability::NetClient,
        system_generated,
        &ctx,
    );
    assert!(matches!(
        outcome.result,
        HostcallResult::Denied {
            reason: DenialReason::FlowViolation { .. }
        }
    ));
}

#[test]
fn dispatcher_tracks_multiple_violations() {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let caps = capability_set(&[
        Capability::FsWrite,
        Capability::FsRead,
        Capability::NetClient,
    ]);
    let ctx = test_context();

    let secret = FlowLabel::new(SecrecyLevel::TopSecret, IntegrityLevel::Trusted);
    for i in 0..3 {
        let arg = Labeled::new(format!("data-{i}"), secret);
        let _ = dispatcher.dispatch(
            "ext-multi",
            HostcallType::FsWrite,
            &caps,
            Capability::FsWrite,
            arg,
            &ctx,
        );
    }

    assert_eq!(dispatcher.violation_events().len(), 3);
    assert_eq!(dispatcher.guardplane_evidence().len(), 3);
}

#[test]
fn dispatcher_violation_event_has_correct_fields() {
    let mut dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    let caps = capability_set(&[Capability::NetClient]);
    let secret_data = Labeled::new(
        42u32,
        FlowLabel::new(SecrecyLevel::Confidential, IntegrityLevel::Validated),
    );
    let ctx = FlowEnforcementContext::new("t-1", "d-1", "p-1");

    let _ = dispatcher.dispatch(
        "ext-fields",
        HostcallType::NetworkSend,
        &caps,
        Capability::NetClient,
        secret_data,
        &ctx,
    );

    let event = &dispatcher.violation_events()[0];
    assert_eq!(event.trace_id, "t-1");
    assert_eq!(event.decision_id, "d-1");
    assert_eq!(event.policy_id, "p-1");
    assert_eq!(event.extension_id, "ext-fields");
    assert_eq!(event.hostcall_type, HostcallType::NetworkSend);
    assert_eq!(event.error_code, "FE-FLOW-0001");
    assert_eq!(event.outcome, "blocked");
}

// ───────────────────────────────────────────────────────────────
// DecisionContract implementations
// ───────────────────────────────────────────────────────────────

fn make_declass_request(
    current_secrecy: SecrecyLevel,
    target_secrecy: SecrecyLevel,
    purpose: DeclassificationPurpose,
) -> DeclassificationRequest {
    DeclassificationRequest {
        request_id: "req-1".to_string(),
        requester: "ext-test".to_string(),
        data_ref: DataRef::new("ns", "key"),
        current_label: FlowLabel::new(current_secrecy, IntegrityLevel::Validated),
        target_label: FlowLabel::new(target_secrecy, IntegrityLevel::Validated),
        purpose,
        justification: "test justification".to_string(),
        timestamp_ns: 1_000_000_000,
    }
}

#[test]
fn requester_capability_contract_approves_with_declassify() {
    let contract = RequesterCapabilityContract;
    let caps = capability_set(&[Capability::Declassify, Capability::FsRead]);
    let ctx = DeclassificationEvaluationContext::new(&caps, None, 1_000);
    let request = make_declass_request(
        SecrecyLevel::Secret,
        SecrecyLevel::Public,
        DeclassificationPurpose::UserConsent,
    );

    match contract.evaluate(&request, &ctx) {
        DecisionVerdict::Approved { conditions } => {
            assert!(!conditions.is_empty());
        }
        other => panic!("expected approval, got {other:?}"),
    }
}

#[test]
fn requester_capability_contract_denies_without_declassify() {
    let contract = RequesterCapabilityContract;
    let caps = capability_set(&[Capability::FsRead, Capability::FsWrite]);
    let ctx = DeclassificationEvaluationContext::new(&caps, None, 1_000);
    let request = make_declass_request(
        SecrecyLevel::Secret,
        SecrecyLevel::Public,
        DeclassificationPurpose::UserConsent,
    );

    match contract.evaluate(&request, &ctx) {
        DecisionVerdict::Denied {
            reason: DeclassificationDenialReason::MissingCapability { capability },
        } => {
            assert_eq!(capability, Capability::Declassify);
        }
        other => panic!("expected missing capability denial, got {other:?}"),
    }
}

#[test]
fn label_distance_contract_approves_small_distance() {
    let contract = LabelDistanceContract;
    let caps = capability_set(&[Capability::Declassify]);
    let ctx = DeclassificationEvaluationContext::new(&caps, None, 1_000);
    let request = make_declass_request(
        SecrecyLevel::Internal,
        SecrecyLevel::Public,
        DeclassificationPurpose::PublicApiResponse,
    );

    match contract.evaluate(&request, &ctx) {
        DecisionVerdict::Approved { .. } => {}
        other => panic!("expected approval for small distance, got {other:?}"),
    }
}

#[test]
fn label_distance_contract_denies_large_distance() {
    let contract = LabelDistanceContract;
    let caps = capability_set(&[Capability::Declassify]);
    let ctx = DeclassificationEvaluationContext::new(&caps, None, 1_000);
    let request = make_declass_request(
        SecrecyLevel::TopSecret,
        SecrecyLevel::Public,
        DeclassificationPurpose::UserConsent,
    );

    match contract.evaluate(&request, &ctx) {
        DecisionVerdict::Denied {
            reason: DeclassificationDenialReason::LabelDistanceTooLarge { .. },
        } => {}
        other => panic!("expected large distance denial, got {other:?}"),
    }
}

#[test]
fn rate_limit_contract_approves_under_threshold() {
    let contract = RateLimitContract::new(5, 60_000_000_000);
    let caps = capability_set(&[Capability::Declassify]);
    let history: Vec<u64> = vec![500, 600, 700];
    let ctx = DeclassificationEvaluationContext::new(&caps, Some(&history), 1_000);
    let request = make_declass_request(
        SecrecyLevel::Confidential,
        SecrecyLevel::Internal,
        DeclassificationPurpose::UserConsent,
    );

    match contract.evaluate(&request, &ctx) {
        DecisionVerdict::Approved { .. } => {}
        other => panic!("expected approval under rate limit, got {other:?}"),
    }
}

#[test]
fn rate_limit_contract_denies_over_threshold() {
    let contract = RateLimitContract::new(3, 60_000_000_000);
    let caps = capability_set(&[Capability::Declassify]);
    let history: Vec<u64> = vec![100, 200, 300, 400];
    let ctx = DeclassificationEvaluationContext::new(&caps, Some(&history), 500);
    let request = make_declass_request(
        SecrecyLevel::Confidential,
        SecrecyLevel::Internal,
        DeclassificationPurpose::UserConsent,
    );

    match contract.evaluate(&request, &ctx) {
        DecisionVerdict::Denied {
            reason: DeclassificationDenialReason::RateLimited { .. },
        } => {}
        other => panic!("expected rate limit denial, got {other:?}"),
    }
}

// ───────────────────────────────────────────────────────────────
// DeclassificationGateway
// ───────────────────────────────────────────────────────────────

fn make_signing_key() -> DecisionSigningKey {
    DecisionSigningKey::new([0xAB; 32])
}

#[test]
fn gateway_approves_valid_declassification() {
    let mut gateway = DeclassificationGateway::with_default_contracts(make_signing_key());
    let caps = capability_set(&[Capability::Declassify]);
    let ctx = test_context();
    let request = make_declass_request(
        SecrecyLevel::Internal,
        SecrecyLevel::Public,
        DeclassificationPurpose::PublicApiResponse,
    );

    let outcome = gateway.evaluate_request(request, &caps, 500_000, &ctx);
    match outcome {
        DeclassificationOutcome::Approved { receipt, .. } => {
            assert_ne!(receipt.signature, [0u8; 32]);
        }
        other => panic!("expected approved outcome, got {other:?}"),
    }
    assert_eq!(gateway.receipt_log().receipts().len(), 1);
}

#[test]
fn gateway_denies_empty_justification() {
    let mut gateway = DeclassificationGateway::with_default_contracts(make_signing_key());
    let caps = capability_set(&[Capability::Declassify]);
    let ctx = test_context();
    let mut request = make_declass_request(
        SecrecyLevel::Secret,
        SecrecyLevel::Public,
        DeclassificationPurpose::UserConsent,
    );
    request.justification = "".to_string();

    let outcome = gateway.evaluate_request(request, &caps, 500_000, &ctx);
    match outcome {
        DeclassificationOutcome::Denied { reason, .. } => {
            assert_eq!(reason, DeclassificationDenialReason::EmptyJustification);
        }
        other => panic!("expected denied for empty justification, got {other:?}"),
    }
}

#[test]
fn gateway_denies_when_no_declassification_needed() {
    let mut gateway = DeclassificationGateway::with_default_contracts(make_signing_key());
    let caps = capability_set(&[Capability::Declassify]);
    let ctx = test_context();
    // Same level = no declassification needed (Public -> Public is lattice-legal)
    let request = make_declass_request(
        SecrecyLevel::Public,
        SecrecyLevel::Public,
        DeclassificationPurpose::UserConsent,
    );

    let outcome = gateway.evaluate_request(request, &caps, 500_000, &ctx);
    match outcome {
        DeclassificationOutcome::Denied { reason, .. } => {
            assert_eq!(
                reason,
                DeclassificationDenialReason::NoDeclassificationRequired
            );
        }
        other => panic!("expected no-declassification-required denial, got {other:?}"),
    }
}

#[test]
fn gateway_denies_missing_declassify_capability() {
    let mut gateway = DeclassificationGateway::with_default_contracts(make_signing_key());
    let caps = capability_set(&[Capability::FsRead]);
    let ctx = test_context();
    let request = make_declass_request(
        SecrecyLevel::Secret,
        SecrecyLevel::Internal,
        DeclassificationPurpose::UserConsent,
    );

    let outcome = gateway.evaluate_request(request, &caps, 500_000, &ctx);
    match outcome {
        DeclassificationOutcome::Denied { reason, .. } => {
            assert!(matches!(
                reason,
                DeclassificationDenialReason::MissingCapability { .. }
            ));
        }
        other => panic!("expected missing capability denial, got {other:?}"),
    }
}

#[test]
fn gateway_receipt_has_nonzero_signature() {
    let mut gateway = DeclassificationGateway::with_default_contracts(make_signing_key());
    let caps = capability_set(&[Capability::Declassify]);
    let ctx = test_context();
    let request = make_declass_request(
        SecrecyLevel::Internal,
        SecrecyLevel::Public,
        DeclassificationPurpose::PublicApiResponse,
    );

    let outcome = gateway.evaluate_request(request, &caps, 500_000, &ctx);
    match outcome {
        DeclassificationOutcome::Approved { receipt, .. } => {
            assert_ne!(receipt.signature, [0u8; 32]);
            assert!(!receipt.receipt_id.is_empty());
            assert_eq!(receipt.request_id, "req-1");
        }
        other => panic!("expected approved, got {other:?}"),
    }
}

#[test]
fn gateway_denied_evidence_is_recorded() {
    let mut gateway = DeclassificationGateway::with_default_contracts(make_signing_key());
    let caps = capability_set(&[Capability::FsRead]);
    let ctx = test_context();

    for _ in 0..3 {
        let request = make_declass_request(
            SecrecyLevel::Secret,
            SecrecyLevel::Public,
            DeclassificationPurpose::UserConsent,
        );
        let _ = gateway.evaluate_request(request, &caps, 500_000, &ctx);
    }

    assert_eq!(gateway.denied_evidence().len(), 3);
    assert_eq!(gateway.events().len(), 3);
}

// ───────────────────────────────────────────────────────────────
// DeclassificationDenialReason error codes
// ───────────────────────────────────────────────────────────────

#[test]
fn denial_reason_error_codes_are_stable() {
    assert_eq!(
        DeclassificationDenialReason::MissingCapability {
            capability: Capability::Declassify
        }
        .error_code(),
        "FE-DECLASS-0001"
    );
    assert_eq!(
        DeclassificationDenialReason::LabelDistanceTooLarge {
            secrecy_distance: 3,
            integrity_distance: 0
        }
        .error_code(),
        "FE-DECLASS-0002"
    );
    assert_eq!(
        DeclassificationDenialReason::InvalidPurpose {
            purpose: DeclassificationPurpose::DiagnosticExport,
            target: SecrecyLevel::Public,
        }
        .error_code(),
        "FE-DECLASS-0003"
    );
    assert_eq!(
        DeclassificationDenialReason::RateLimited {
            max_requests: 10,
            window_ns: 1_000_000
        }
        .error_code(),
        "FE-DECLASS-0004"
    );
    assert_eq!(
        DeclassificationDenialReason::NoDeclassificationRequired.error_code(),
        "FE-DECLASS-0005"
    );
    assert_eq!(
        DeclassificationDenialReason::EmptyJustification.error_code(),
        "FE-DECLASS-0006"
    );
    assert_eq!(
        DeclassificationDenialReason::ContractRejected {
            contract_id: "x".to_string(),
            detail: "y".to_string()
        }
        .error_code(),
        "FE-DECLASS-0007"
    );
}

// ───────────────────────────────────────────────────────────────
// DeclassificationPurpose Display
// ───────────────────────────────────────────────────────────────

#[test]
fn declassification_purpose_display_variants() {
    assert_eq!(
        DeclassificationPurpose::UserConsent.to_string(),
        "user_consent"
    );
    assert_eq!(
        DeclassificationPurpose::AggregationAnonymization.to_string(),
        "aggregation_anonymization"
    );
    assert_eq!(
        DeclassificationPurpose::Custom("audit_export".to_string()).to_string(),
        "custom:audit_export"
    );
}

// ───────────────────────────────────────────────────────────────
// DeclassificationEvaluationContext
// ───────────────────────────────────────────────────────────────

#[test]
fn evaluation_context_counts_requests_in_window() {
    let caps = capability_set(&[Capability::Declassify]);
    let history: Vec<u64> = vec![100, 200, 300, 500, 700, 900];
    let ctx = DeclassificationEvaluationContext::new(&caps, Some(&history), 800);

    // Window of 500ns from timestamp 800: lower_bound = 300
    // Entries in [300, 800]: 300, 500, 700 = 3
    let count = ctx.request_count_within_window(500);
    assert_eq!(count, 3);
}

#[test]
fn evaluation_context_returns_zero_for_no_history() {
    let caps = capability_set(&[Capability::Declassify]);
    let ctx = DeclassificationEvaluationContext::new(&caps, None, 1_000);
    assert_eq!(ctx.request_count_within_window(500), 0);
}

#[test]
fn evaluation_context_has_capability_check() {
    let caps = capability_set(&[Capability::FsRead, Capability::NetClient]);
    let ctx = DeclassificationEvaluationContext::new(&caps, None, 1_000);
    assert!(ctx.has_capability(Capability::FsRead));
    assert!(ctx.has_capability(Capability::NetClient));
    assert!(!ctx.has_capability(Capability::Declassify));
    assert!(!ctx.has_capability(Capability::ProcessSpawn));
}

// ───────────────────────────────────────────────────────────────
// HostcallSinkPolicy defaults
// ───────────────────────────────────────────────────────────────

#[test]
fn default_sink_policy_has_expected_clearances() {
    let policy = HostcallSinkPolicy::default();
    assert_eq!(policy.fs_write.max_secrecy, SecrecyLevel::Internal);
    assert_eq!(policy.fs_write.min_integrity, IntegrityLevel::Validated);
    assert_eq!(policy.network_send.max_secrecy, SecrecyLevel::Public);
    assert_eq!(policy.network_send.min_integrity, IntegrityLevel::Validated);
    assert_eq!(policy.ipc_send.max_secrecy, SecrecyLevel::Secret);
    assert_eq!(policy.ipc_send.min_integrity, IntegrityLevel::Untrusted);
}

#[test]
fn sink_policy_returns_none_for_non_sink_hostcalls() {
    let policy = HostcallSinkPolicy::default();
    assert!(policy.clearance_for(HostcallType::FsRead).is_none());
    assert!(policy.clearance_for(HostcallType::NetworkRecv).is_none());
    assert!(policy.clearance_for(HostcallType::MemAlloc).is_none());
    assert!(policy.clearance_for(HostcallType::CryptoOp).is_none());
}

#[test]
fn sink_policy_returns_some_for_sink_hostcalls() {
    let policy = HostcallSinkPolicy::default();
    assert!(policy.clearance_for(HostcallType::FsWrite).is_some());
    assert!(policy.clearance_for(HostcallType::NetworkSend).is_some());
    assert!(policy.clearance_for(HostcallType::IpcSend).is_some());
}
