use ed25519_dalek::{Signer, SigningKey};
use frankenengine_extension_host::{
    BudgetExhaustionPolicy, CURRENT_ENGINE_VERSION, CancellationConfig, Capability,
    CapabilityEscrowDecisionKind, CapabilityEscrowState, DecisionSigningKey, DelegateCell,
    DelegateCellFactory, DelegateCellManifest, DelegateCellPolicy, DelegationScope, DenialReason,
    EscrowFloodProtectionContract, ExtensionManifest, FlowEnforcementContext, HostcallResult,
    HostcallSinkPolicy, HostcallType, Labeled, LifecycleContext, ResourceBudget,
    compute_content_hash,
};
use sha2::{Digest, Sha256};

/// Create proper Ed25519 signed manifest for integration tests
/// Replaces fake signatures with deterministic Ed25519 provenance
fn base_manifest(capabilities: &[Capability]) -> ExtensionManifest {
    // Use deterministic key for escrow adversarial tests
    let key_seed = {
        let mut hasher = Sha256::new();
        hasher.update(b"escrow-adversarial-ext");
        hasher.update(b"1.0.0");
        hasher.update(b"dist/escrow-adversarial.js");
        let hash = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[..32]);
        seed
    };

    let signing_key = SigningKey::from_bytes(&key_seed);
    let verifying_key = signing_key.verifying_key();

    let mut manifest = ExtensionManifest {
        name: "escrow-adversarial-ext".to_string(),
        version: "1.0.0".to_string(),
        entrypoint: "dist/escrow-adversarial.js".to_string(),
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
    LifecycleContext::new(
        "trace-escrow-adv",
        "decision-escrow-adv",
        "policy-escrow-adv",
    )
}

fn fctx() -> FlowEnforcementContext<'static> {
    FlowEnforcementContext::new(
        "trace-escrow-adv-flow",
        "decision-escrow-adv-flow",
        "policy-escrow-adv-flow",
    )
}

fn budget() -> ResourceBudget {
    ResourceBudget::new(1_000_000_000, 64 * 1024 * 1024, 2_000)
}

fn factory() -> DelegateCellFactory {
    DelegateCellFactory {
        sink_policy: HostcallSinkPolicy::default(),
        cancellation_config: CancellationConfig::default(),
        policy: DelegateCellPolicy::default(),
        decision_signing_key: DecisionSigningKey::new([0xE2; 32]),
    }
}

fn make_delegate(delegate_id: &str, capabilities: &[Capability]) -> DelegateCell {
    factory()
        .create_delegate_cell(
            delegate_id,
            delegate_manifest(capabilities, 2_000_000_000_000),
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
            delegate_manifest(capabilities, 2_000_000_000_000),
            budget(),
            BudgetExhaustionPolicy::Suspend,
            100,
            &lctx(),
        )
        .expect("delegate created")
}

fn assert_pending_challenge(result: &HostcallResult, expected_capability: Capability) {
    assert!(matches!(
        result,
        HostcallResult::Denied {
            reason: DenialReason::CapabilityEscrowPending {
                attempted,
                action: _,
                escrow_id: _,
            }
        } if *attempted == expected_capability
    ));
}

#[test]
fn time_delayed_escalation_after_benign_sequence_still_requires_escrow() {
    let mut delegate = make_delegate("escrow-adv-time-delayed", &[Capability::FsRead]);

    for idx in 0..24u64 {
        let benign = delegate
            .dispatch_hostcall(
                HostcallType::FsRead,
                Capability::FsRead,
                Labeled::system_generated(format!("benign-read-{idx}")),
                10_000 + idx,
                &fctx(),
                &lctx(),
            )
            .expect("benign hostcall should succeed");
        assert_eq!(benign.result, HostcallResult::Success);
    }

    let escalation = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("delayed-spawn".to_string()),
            20_000,
            &fctx(),
            &lctx(),
            Some("appeared benign during warmup"),
        )
        .expect("escalation attempt should route through escrow");
    assert_pending_challenge(&escalation.result, Capability::ProcessSpawn);

    let retry = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("delayed-spawn-retry".to_string()),
            20_001,
            &fctx(),
            &lctx(),
        )
        .expect("retry should still route through escrow");
    assert_pending_challenge(&retry.result, Capability::ProcessSpawn);

    assert!(
        delegate
            .capability_escrow_records()
            .values()
            .all(|record| record.state != CapabilityEscrowState::Approved)
    );
    assert!(delegate.capability_escrow_receipts().iter().all(|receipt| {
        matches!(
            receipt.decision,
            CapabilityEscrowDecisionKind::Challenge
                | CapabilityEscrowDecisionKind::Sandbox
                | CapabilityEscrowDecisionKind::Deny
        )
    }));
}

#[test]
fn emergency_grant_exhaustion_does_not_convert_to_persistent_authority() {
    let mut delegate = make_delegate("escrow-adv-grant-chain", &[Capability::FsRead]);

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-initial".to_string()),
            200,
            &fctx(),
            &lctx(),
            Some("incident response"),
        )
        .expect("initial request should be escrowed");

    let request_id = delegate
        .capability_escrow_records()
        .keys()
        .next()
        .cloned()
        .expect("escrow request exists");

    let grant = delegate
        .issue_emergency_capability_grant(
            &request_id,
            "ops@franken.engine",
            "single-shot emergency escalation",
            10_000,
            1,
            true,
            true,
            220,
            &fctx(),
        )
        .expect("grant should be issued");

    let first = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-granted".to_string()),
            230,
            &fctx(),
            &lctx(),
        )
        .expect("first use should be allowed");
    assert_eq!(first.result, HostcallResult::Success);

    let second = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-after-grant".to_string()),
            231,
            &fctx(),
            &lctx(),
        )
        .expect("second use should be re-escrowed");
    assert_pending_challenge(&second.result, Capability::ProcessSpawn);

    let third = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-after-grant-2".to_string()),
            232,
            &fctx(),
            &lctx(),
        )
        .expect("persistent escalation should be blocked");
    assert_pending_challenge(&third.result, Capability::ProcessSpawn);

    assert!(delegate.active_emergency_grants().is_empty());
    assert!(
        delegate
            .capability_escrow_events()
            .iter()
            .any(|event| event.error_code.as_deref() == Some("FE-ESCROW-0008"))
    );

    delegate
        .complete_emergency_post_review(&grant.grant_id)
        .expect("post-review should complete");
}

#[test]
fn grant_expiry_boundary_fails_closed_at_expiry_timestamp() {
    let mut delegate = make_delegate("escrow-adv-expiry-boundary", &[Capability::FsRead]);

    let _ = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-initial".to_string()),
            300,
            &fctx(),
            &lctx(),
            Some("boundary probe"),
        )
        .expect("initial request should be escrowed");

    let request_id = delegate
        .capability_escrow_records()
        .keys()
        .next()
        .cloned()
        .expect("escrow request exists");

    let _grant = delegate
        .issue_emergency_capability_grant(
            &request_id,
            "ops@franken.engine",
            "grant right up to boundary",
            400,
            3,
            false,
            true,
            320,
            &fctx(),
        )
        .expect("grant should be issued");

    let just_before_expiry = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-before-expiry".to_string()),
            399,
            &fctx(),
            &lctx(),
        )
        .expect("should be authorized before expiry");
    assert_eq!(just_before_expiry.result, HostcallResult::Success);

    let at_expiry = delegate
        .dispatch_hostcall(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("spawn-at-expiry".to_string()),
            400,
            &fctx(),
            &lctx(),
        )
        .expect("must fail closed at expiry");
    assert_pending_challenge(&at_expiry.result, Capability::ProcessSpawn);

    assert!(delegate.active_emergency_grants().is_empty());
    assert!(
        delegate
            .capability_escrow_events()
            .iter()
            .any(|event| event.error_code.as_deref() == Some("FE-ESCROW-0007"))
    );
}

#[test]
fn escrow_flood_campaign_triggers_contract_denials() {
    let mut delegate = make_low_penalty_delegate("escrow-adv-flood", &[Capability::FsRead]);

    for idx in 0..48u64 {
        let result = delegate
            .dispatch_hostcall_with_escrow(
                HostcallType::ProcessSpawn,
                Capability::ProcessSpawn,
                Labeled::system_generated(format!("flood-{idx}")),
                1_000 + idx,
                &fctx(),
                &lctx(),
                Some("escrow flood campaign"),
            )
            .expect("dispatch should complete");
        assert!(matches!(result.result, HostcallResult::Denied { .. }));
    }

    let flood_denials = delegate
        .capability_escrow_receipts()
        .iter()
        .filter(|receipt| {
            receipt.decision == CapabilityEscrowDecisionKind::Deny
                && receipt.error_code.as_deref() == Some("FE-ESCROW-0003")
        })
        .count();
    assert!(flood_denials > 0, "expected flood-protection denials");

    assert!(delegate.capability_escrow_events().iter().any(|event| {
        event.outcome == "denied" && event.error_code.as_deref() == Some("FE-ESCROW-0003")
    }));
}

#[test]
fn escrow_flood_contract_holds_exact_configured_boundary() {
    let mut delegate =
        make_low_penalty_delegate("escrow-adv-flood-boundary", &[Capability::FsRead]);
    let max_open_requests =
        EscrowFloodProtectionContract::default().max_open_requests_per_extension;

    for idx in 0..max_open_requests {
        let result = delegate
            .dispatch_hostcall_with_escrow(
                HostcallType::ProcessSpawn,
                Capability::ProcessSpawn,
                Labeled::system_generated(format!("boundary-{idx}")),
                10_000 + idx as u64,
                &fctx(),
                &lctx(),
                Some("boundary flood probe"),
            )
            .expect("dispatch should complete");
        assert!(matches!(result.result, HostcallResult::Denied { .. }));
    }

    let flood_denials_before_limit = delegate
        .capability_escrow_receipts()
        .iter()
        .filter(|receipt| {
            receipt.decision == CapabilityEscrowDecisionKind::Deny
                && receipt.error_code.as_deref() == Some("FE-ESCROW-0003")
        })
        .count();
    assert_eq!(
        flood_denials_before_limit, 0,
        "flood protection should not deny before the configured limit is exceeded"
    );

    let overflow = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("boundary-overflow".to_string()),
            20_000,
            &fctx(),
            &lctx(),
            Some("boundary flood probe"),
        )
        .expect("overflow dispatch should complete");
    assert!(matches!(overflow.result, HostcallResult::Denied { .. }));

    let flood_denials_after_limit = delegate
        .capability_escrow_receipts()
        .iter()
        .filter(|receipt| {
            receipt.decision == CapabilityEscrowDecisionKind::Deny
                && receipt.error_code.as_deref() == Some("FE-ESCROW-0003")
        })
        .count();
    assert_eq!(flood_denials_after_limit, 1);
}

#[test]
fn no_indirect_hostcall_variant_bypasses_escrow_gate() {
    let mut delegate = make_delegate("escrow-adv-indirect", &[Capability::FsRead]);

    let process_attempt = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::ProcessSpawn,
            Capability::ProcessSpawn,
            Labeled::system_generated("indirect-process".to_string()),
            500,
            &fctx(),
            &lctx(),
            Some("indirect escalation attempt"),
        )
        .expect("dispatch should complete");
    assert_pending_challenge(&process_attempt.result, Capability::ProcessSpawn);

    let network_attempt = delegate
        .dispatch_hostcall_with_escrow(
            HostcallType::NetworkSend,
            Capability::NetClient,
            Labeled::system_generated("indirect-network".to_string()),
            501,
            &fctx(),
            &lctx(),
            Some("indirect egress escalation"),
        )
        .expect("dispatch should complete");
    assert!(matches!(
        network_attempt.result,
        HostcallResult::Denied {
            reason: DenialReason::CapabilityEscrowPending {
                attempted: Capability::NetClient,
                action: _,
                escrow_id: _,
            }
        }
    ));

    let tracked_capabilities = delegate
        .capability_escrow_records()
        .values()
        .map(|record| record.capability)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(tracked_capabilities.contains(&Capability::ProcessSpawn));
    assert!(tracked_capabilities.contains(&Capability::NetClient));
}
