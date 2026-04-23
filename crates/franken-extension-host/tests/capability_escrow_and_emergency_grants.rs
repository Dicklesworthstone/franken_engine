use ed25519_dalek::{Signer, SigningKey};
use frankenengine_extension_host::{
    BudgetExhaustionPolicy, CURRENT_ENGINE_VERSION, CancellationConfig, Capability,
    CapabilityEscrowDecisionKind, CapabilityEscrowError, CapabilityEscrowReceiptQuery,
    CapabilityEscrowRoute, CapabilityEscrowState, DecisionSigningKey, DelegateCell,
    DelegateCellError, DelegateCellFactory, DelegateCellManifest, DelegateCellPolicy,
    DelegationScope, DenialReason, ExtensionManifest, ExtensionState, FlowEnforcementContext,
    HostcallResult, HostcallSinkPolicy, HostcallType, Labeled, LifecycleContext,
    LifecycleTransition, ResourceBudget, compute_content_hash,
};
use sha2::{Digest, Sha256};

/// Create proper Ed25519 signed manifest for integration tests
/// Replaces fake signatures with deterministic Ed25519 provenance
fn base_manifest(capabilities: &[Capability]) -> ExtensionManifest {
    // Use deterministic key for escrow tests
    let key_seed = {
        let mut hasher = Sha256::new();
        hasher.update(b"escrow-ext");
        hasher.update(b"1.0.0");
        hasher.update(b"dist/escrow.js");
        let hash = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[..32]);
        seed
    };

    let signing_key = SigningKey::from_bytes(&key_seed);
    let verifying_key = signing_key.verifying_key();

    let mut manifest = ExtensionManifest {
        name: "escrow-ext".to_string(),
        version: "1.0.0".to_string(),
        entrypoint: "dist/escrow.js".to_string(),
        capabilities: capabilities.iter().copied().collect(),
        publisher_signature: None,
        content_hash: [0; 32],
        trust_chain_ref: Some(bytes_to_hex(&verifying_key.to_bytes())),
        min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
    };

    manifest.content_hash = compute_content_hash(&manifest).expect("content hash");
    manifest.publisher_signature =
        Some(signing_key.sign(&manifest.content_hash).to_bytes().to_vec());
    manifest
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn delegate_manifest(capabilities: &[Capability], max_lifetime_ns: u64) -> DelegateCellManifest {
    DelegateCellManifest {
        base_manifest: base_manifest(capabilities),
        delegation_scope: DelegationScope::DiagnosticCollection,
        delegator_id: "engine-core".to_string(),
        max_lifetime_ns,
    }
}

fn lctx() -> LifecycleContext<'static> {
    LifecycleContext::new("trace-escrow", "decision-escrow", "policy-escrow")
}

fn fctx() -> FlowEnforcementContext<'static> {
    FlowEnforcementContext::new(
        "trace-escrow-flow",
        "decision-escrow-flow",
        "policy-escrow-flow",
    )
}

fn budget() -> ResourceBudget {
    ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 1_000)
}

fn factory() -> DelegateCellFactory {
    DelegateCellFactory {
        sink_policy: HostcallSinkPolicy::default(),
        cancellation_config: CancellationConfig::default(),
        policy: DelegateCellPolicy::default(),
        decision_signing_key: DecisionSigningKey::new([0xE1; 32]),
    }
}

fn make_delegate(delegate_id: &str, capabilities: &[Capability]) -> DelegateCell {
    factory()
        .create_delegate_cell(
            delegate_id,
            delegate_manifest(capabilities, 1_000_000_000_000),
            budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created")
}

fn make_low_penalty_delegate(delegate_id: &str, capabilities: &[Capability]) -> DelegateCell {
    let mut factory = factory();
    factory.policy.initial_posterior_micros = 0;
    factory.policy.capability_escalation_penalty_micros = 10_000;
    factory
        .create_delegate_cell(
            delegate_id,
            delegate_manifest(capabilities, 1_000_000_000_000),
            budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created")
}

#[test]
fn escrow_state_machine_transitions_challenge_to_approved_to_expired() {
    let mut delegate = make_delegate("escrow-state-machine", &[Capability::FsRead]);

    let blocked = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some(""),
        )
        .expect("dispatch result");

    assert!(matches!(
        blocked.result,
        HostcallResult::Denied {
            reason: DenialReason::CapabilityEscrowPending {
                attempted: Capability::ProcessSpawn,
                action: CapabilityEscrowRoute::Challenge,
                ..
            }
        }
    ));

    let (request_id, state) = delegate
        .capability_escrow_records()
        .iter()
        .next()
        .map(|(id, record)| (id.clone(), record.state))
        .expect("escrow request exists");
    assert_eq!(state, CapabilityEscrowState::Challenged);

    let approval = delegate
        .approve_capability_escrow_request(&request_id, 210, &fctx())
        .expect("approval receipt");
    assert!(approval.verify(&delegate.capability_escrow_public_key()));

    let allowed = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-allowed".to_string()),
            220,
            &fctx(),
            &lctx(),
        )
        .expect("approved hostcall should be allowed");
    assert_eq!(allowed.result, HostcallResult::Success);

    delegate
        .expire_capability_escrow(400_000_000_300, &fctx())
        .expect("expire escrow");
    assert!(
        delegate
            .capability_escrow_records()
            .values()
            .any(|record| record.request_id == request_id
                && record.state == CapabilityEscrowState::Expired)
    );
}

#[test]
fn quarantined_delegate_cannot_approve_capability_escrow_request() {
    let mut delegate = make_delegate("escrow-inactive-approval", &[Capability::FsRead]);

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some("awaiting approval"),
        )
        .expect("dispatch result");
    let request_id = delegate
        .capability_escrow_records()
        .keys()
        .next()
        .cloned()
        .expect("escrow request id");

    delegate
        .apply_transition(LifecycleTransition::Quarantine, 210, &lctx())
        .expect("quarantine");

    let err = delegate.approve_capability_escrow_request(&request_id, 211, &fctx());
    assert!(matches!(
        err,
        Err(DelegateCellError::InactiveState {
            state: ExtensionState::Quarantined,
            action: "approve_capability_escrow_request",
            ..
        })
    ));
    assert_eq!(
        delegate
            .capability_escrow_records()
            .get(&request_id)
            .expect("escrow record")
            .state,
        CapabilityEscrowState::Challenged
    );
}

#[test]
fn low_risk_hostcall_routes_to_sandbox_by_default() {
    let mut delegate = make_delegate("escrow-sandbox", &[Capability::FsRead]);

    let blocked = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::TimerCreate,
            Capability::HostCall,
            Labeled::system_generated("timer".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some("diagnostic timer request"),
        )
        .expect("dispatch result");

    assert!(matches!(
        blocked.result,
        HostcallResult::Denied {
            reason: DenialReason::CapabilityEscrowPending {
                attempted: Capability::HostCall,
                action: CapabilityEscrowRoute::Sandbox,
                ..
            }
        }
    ));

    let record = delegate
        .capability_escrow_records()
        .values()
        .next()
        .expect("escrow record");
    assert_eq!(record.state, CapabilityEscrowState::Sandboxed);

    let event = delegate
        .capability_escrow_events()
        .last()
        .expect("escrow event emitted");
    assert_eq!(event.outcome, "sandboxed");
    assert_eq!(event.error_code.as_deref(), Some("FE-ESCROW-0002"));
}

#[test]
fn emergency_grant_is_signed_bounded_and_requires_post_review() {
    let mut delegate = make_delegate("escrow-emergency", &[Capability::FsRead]);

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some("ops investigation"),
        )
        .expect("dispatch result");

    let request_id = delegate
        .capability_escrow_records()
        .keys()
        .next()
        .cloned()
        .expect("escrow request id");

    let grant = delegate
        .issue_emergency_capability_grant(
            &request_id,
            "ops@franken.engine",
            "critical outage mitigation",
            1_000,
            2,
            true,
            true,
            250,
            &fctx(),
        )
        .expect("issue emergency grant");

    assert!(grant.verify(&delegate.capability_escrow_public_key()));
    assert!(
        delegate
            .pending_emergency_post_reviews()
            .contains(grant.grant_id.as_str())
    );

    let first = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-1".to_string()),
            260,
            &fctx(),
            &lctx(),
        )
        .expect("first emergency invocation");
    assert_eq!(first.result, HostcallResult::Success);

    let second = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-2".to_string()),
            270,
            &fctx(),
            &lctx(),
        )
        .expect("second emergency invocation");
    assert_eq!(second.result, HostcallResult::Success);

    let third = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-3".to_string()),
            280,
            &fctx(),
            &lctx(),
        )
        .expect("third invocation should be denied");
    assert!(matches!(
        third.result,
        HostcallResult::Denied {
            reason: DenialReason::CapabilityEscrowPending {
                attempted: Capability::ProcessSpawn,
                action: CapabilityEscrowRoute::Challenge,
                ..
            }
        }
    ));
    assert!(delegate.active_emergency_grants().is_empty());

    delegate
        .complete_emergency_post_review(&grant.grant_id)
        .expect("complete post review");
    assert!(
        !delegate
            .pending_emergency_post_reviews()
            .contains(grant.grant_id.as_str())
    );

    let second_completion = delegate.complete_emergency_post_review(&grant.grant_id);
    assert!(matches!(
        second_completion,
        Err(DelegateCellError::CapabilityEscrow(
            CapabilityEscrowError::PostReviewNotPending { .. }
        ))
    ));
}

#[test]
fn suspended_delegate_cannot_issue_emergency_capability_grant() {
    let mut delegate = make_delegate("escrow-suspended-grant", &[Capability::FsRead]);

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some("ops investigation"),
        )
        .expect("dispatch result");
    let request_id = delegate
        .capability_escrow_records()
        .keys()
        .next()
        .cloned()
        .expect("escrow request id");

    delegate
        .apply_transition(LifecycleTransition::Suspend, 210, &lctx())
        .expect("suspend");
    delegate
        .apply_transition(LifecycleTransition::Freeze, 211, &lctx())
        .expect("freeze");

    let err = delegate.issue_emergency_capability_grant(
        &request_id,
        "ops@franken.engine",
        "should fail once frozen",
        1_000,
        1,
        true,
        true,
        212,
        &fctx(),
    );
    assert!(matches!(
        err,
        Err(DelegateCellError::InactiveState {
            state: ExtensionState::Suspended,
            action: "issue_emergency_capability_grant",
            ..
        })
    ));
    assert!(delegate.active_emergency_grants().is_empty());
}

#[test]
fn expired_emergency_grants_cannot_bypass_escrow() {
    let mut delegate = make_delegate("escrow-expired-grant", &[Capability::FsRead]);

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some("operator triage"),
        )
        .expect("dispatch result");

    let request_id = delegate
        .capability_escrow_records()
        .keys()
        .next()
        .cloned()
        .expect("escrow request id");

    let _ = delegate
        .issue_emergency_capability_grant(
            &request_id,
            "ops@franken.engine",
            "temporary escalation",
            255,
            5,
            false,
            true,
            250,
            &fctx(),
        )
        .expect("issue emergency grant");

    let blocked = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-late".to_string()),
            260,
            &fctx(),
            &lctx(),
        )
        .expect("expired grant should not authorize");

    assert!(matches!(
        blocked.result,
        HostcallResult::Denied {
            reason: DenialReason::CapabilityEscrowPending {
                attempted: Capability::ProcessSpawn,
                action: CapabilityEscrowRoute::Challenge,
                ..
            }
        }
    ));
    assert!(
        delegate
            .capability_escrow_events()
            .iter()
            .any(|event| event.error_code.as_deref() == Some("FE-ESCROW-0007"))
    );
}

#[test]
fn expired_delegate_cannot_issue_emergency_capability_grant() {
    let mut delegate = factory()
        .create_delegate_cell(
            "escrow-expired-delegate-grant",
            delegate_manifest(&[Capability::FsRead], 150),
            budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created");

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some("request before expiry"),
        )
        .expect("dispatch result");
    let request_id = delegate
        .capability_escrow_records()
        .keys()
        .next()
        .cloned()
        .expect("escrow request id");

    let err = delegate.issue_emergency_capability_grant(
        &request_id,
        "ops@franken.engine",
        "should fail after expiry",
        1_000,
        1,
        false,
        true,
        251,
        &fctx(),
    );
    assert!(matches!(
        err,
        Err(DelegateCellError::LifetimeExpired {
            delegate_id,
            expired_at_ns: 250,
        }) if delegate_id == "escrow-expired-delegate-grant"
    ));
    assert!(delegate.active_emergency_grants().is_empty());
}

#[test]
fn in_envelope_hostcalls_do_not_create_escrow_records() {
    let mut delegate = make_delegate("escrow-fast-path", &[Capability::FsRead]);

    for idx in 0..32u64 {
        let result = delegate
            .dispatch_hostcall(
                HostcallType::FsRead,
                Capability::FsRead,
                Labeled::system_generated(format!("read-{idx}")),
                200 + idx,
                &fctx(),
                &lctx(),
            )
            .expect("in-envelope hostcall");
        assert_eq!(result.result, HostcallResult::Success);
    }

    assert!(delegate.capability_escrow_records().is_empty());
    assert!(delegate.capability_escrow_events().is_empty());
    assert!(delegate.capability_escrow_receipts().is_empty());
}

#[test]
fn emergency_grant_validation_rejects_invalid_fields() {
    let mut delegate = make_delegate("escrow-grant-validation", &[Capability::FsRead]);

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some("operator note"),
        )
        .expect("dispatch result");

    let request_id = delegate
        .capability_escrow_records()
        .keys()
        .next()
        .cloned()
        .expect("escrow request id");

    let err = delegate.issue_emergency_capability_grant(
        &request_id,
        "",
        "",
        199,
        0,
        true,
        true,
        200,
        &fctx(),
    );
    assert!(matches!(
        err,
        Err(DelegateCellError::CapabilityEscrow(
            CapabilityEscrowError::InvalidEmergencyGrant { .. }
        ))
    ));
}

#[test]
fn emergency_grant_without_mandatory_post_review_leaves_no_pending_review() {
    let mut delegate = make_delegate("escrow-grant-no-post-review", &[Capability::FsRead]);

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some("ops investigation"),
        )
        .expect("dispatch result");

    let request_id = delegate
        .capability_escrow_records()
        .keys()
        .next()
        .cloned()
        .expect("escrow request id");

    let grant = delegate
        .issue_emergency_capability_grant(
            &request_id,
            "ops@franken.engine",
            "temporary mitigation without post review",
            1_000,
            1,
            false,
            true,
            250,
            &fctx(),
        )
        .expect("issue emergency grant");

    assert!(
        !delegate
            .pending_emergency_post_reviews()
            .contains(grant.grant_id.as_str())
    );

    let use_result = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-1".to_string()),
            260,
            &fctx(),
            &lctx(),
        )
        .expect("emergency invocation");
    assert_eq!(use_result.result, HostcallResult::Success);

    let second_result = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-2".to_string()),
            261,
            &fctx(),
            &lctx(),
        )
        .expect("grant exhaustion should re-escrow");
    assert!(matches!(
        second_result.result,
        HostcallResult::Denied {
            reason: DenialReason::CapabilityEscrowPending { .. }
        }
    ));
    assert!(delegate.active_emergency_grants().is_empty());

    let completion = delegate.complete_emergency_post_review(&grant.grant_id);
    assert!(matches!(
        completion,
        Err(DelegateCellError::CapabilityEscrow(
            CapabilityEscrowError::PostReviewNotPending { .. }
        ))
    ));
}

#[test]
fn escrow_receipts_expose_replay_linkage_and_index_queries() {
    let mut delegate = make_low_penalty_delegate("escrow-receipt-replay", &[Capability::FsRead]);

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some("incident triage"),
        )
        .expect("challenge dispatch");
    let process_request = delegate
        .capability_escrow_records()
        .iter()
        .find(|(_, record)| record.capability == Capability::ProcessSpawn)
        .map(|(request_id, _)| request_id.clone())
        .expect("process request id");

    let _ = delegate
        .deny_capability_escrow_request(&process_request, "policy violation", 210, &fctx())
        .expect("manual deny receipt");

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::TimerCreate,
            Capability::HostCall,
            Labeled::system_generated("timer".to_string()),
            220,
            &fctx(),
            &lctx(),
            Some("sandbox warmup"),
        )
        .expect("sandbox dispatch");
    let sandbox_request = delegate
        .capability_escrow_records()
        .iter()
        .find(|(_, record)| record.capability == Capability::HostCall)
        .map(|(request_id, _)| request_id.clone())
        .expect("sandbox request id");

    let _ = delegate
        .approve_capability_escrow_request(&sandbox_request, 230, &fctx())
        .expect("approval receipt");
    let _grant = delegate
        .issue_emergency_capability_grant(
            &sandbox_request,
            "ops@franken.engine",
            "temporary hostcall expansion",
            2_000,
            1,
            true,
            true,
            240,
            &fctx(),
        )
        .expect("emergency grant");

    let trace_ref = format!("trace:{}#decision:{}", fctx().trace_id, fctx().decision_id);
    for receipt in delegate.capability_escrow_receipts() {
        assert!(receipt.verify(&delegate.capability_escrow_public_key()));
        assert_eq!(receipt.trace_ref, trace_ref);
        assert!(receipt.replay_seed.starts_with("replay-"));
        assert_eq!(receipt.decision_id, fctx().decision_id);
        assert_eq!(receipt.policy_id, fctx().policy_id);
        assert_eq!(receipt.active_witness_ref, fctx().policy_id);

        let replay = delegate
            .capability_escrow_replay_context(&receipt.receipt_id)
            .expect("replay context");
        assert_eq!(replay.receipt.receipt_id, receipt.receipt_id);
        assert_eq!(replay.event.receipt_id, receipt.receipt_id);
        assert_eq!(replay.evidence.receipt_id, receipt.receipt_id);
        assert_eq!(replay.event.trace_ref, receipt.trace_ref);
        assert_eq!(replay.event.replay_seed, receipt.replay_seed);
        assert_eq!(replay.evidence.trace_ref, receipt.trace_ref);
        assert_eq!(replay.evidence.replay_seed, receipt.replay_seed);
    }

    let deny_query = CapabilityEscrowReceiptQuery {
        decision: Some(CapabilityEscrowDecisionKind::Deny),
        ..CapabilityEscrowReceiptQuery::default()
    };
    let deny_receipts = delegate.query_capability_escrow_receipts(&deny_query);
    assert_eq!(deny_receipts.len(), 1);
    assert_eq!(deny_receipts[0].outcome, "denied");

    let sandbox_query = CapabilityEscrowReceiptQuery {
        outcome: Some("sandboxed".to_string()),
        ..CapabilityEscrowReceiptQuery::default()
    };
    let sandbox_receipts = delegate.query_capability_escrow_receipts(&sandbox_query);
    assert_eq!(sandbox_receipts.len(), 1);
    assert_eq!(
        sandbox_receipts[0].decision,
        CapabilityEscrowDecisionKind::Sandbox
    );

    let completeness = delegate.capability_escrow_receipt_completeness();
    assert!(completeness.complete);
    assert_eq!(
        completeness.receipts,
        delegate.capability_escrow_receipts().len()
    );
    assert_eq!(
        completeness.events,
        delegate.capability_escrow_events().len()
    );
    assert!(completeness.evidence >= delegate.capability_escrow_receipts().len());
}

#[test]
fn missing_replay_context_fails_closed_without_receipt_or_state_transition() {
    let mut delegate = make_delegate("escrow-missing-replay-context", &[Capability::FsRead]);
    let empty_context = FlowEnforcementContext::new("", "", "");

    let result = delegate.dispatch_hostcall_with_escrow(
        HostcallType::ProcessSpawn,
        Capability::ProcessSpawn,
        Labeled::system_generated("spawn".to_string()),
        200,
        &empty_context,
        &lctx(),
        Some("will fail"),
    );
    assert!(matches!(
        result,
        Err(DelegateCellError::CapabilityEscrow(
            CapabilityEscrowError::ReceiptEmissionFailed { .. }
        ))
    ));
    assert!(delegate.capability_escrow_records().is_empty());
    assert!(delegate.capability_escrow_receipts().is_empty());
    assert!(delegate.capability_escrow_events().is_empty());
}
