use ed25519_dalek::{Signer, SigningKey};
use frankenengine_extension_host::{
    BudgetExhaustionPolicy, CURRENT_ENGINE_VERSION, CancellationConfig, Capability,
    ExtensionLifecycleManager, ExtensionManifest, ExtensionState, LifecycleContext,
    LifecycleTransition, ResourceBudget, compute_content_hash,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Create proper Ed25519 signed manifest for lifecycle manager integration tests
/// Replaces fake signatures with deterministic Ed25519 provenance
fn manifest() -> ExtensionManifest {
    // Use deterministic key for lifecycle manager integration tests
    let key_seed = {
        let mut hasher = Sha256::new();
        hasher.update(b"integration-ext");
        hasher.update(b"1.0.0");
        hasher.update(b"dist/main.js");
        let hash = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[..32]);
        seed
    };

    let signing_key = SigningKey::from_bytes(&key_seed);
    let verifying_key = signing_key.verifying_key();

    let mut manifest = ExtensionManifest {
        name: "integration-ext".to_string(),
        version: "1.0.0".to_string(),
        entrypoint: "dist/main.js".to_string(),
        capabilities: BTreeSet::from([Capability::FsRead, Capability::FsWrite]),
        publisher_signature: None,
        content_hash: [0; 32],
        trust_chain_ref: Some(bytes_to_hex(&verifying_key.to_bytes())),
        min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
    };

    manifest.content_hash = compute_content_hash(&manifest).expect("hash");
    let mut signed_payload = b"franken-extension-host-signed-manifest-v1:".to_vec();
    signed_payload.extend_from_slice(&manifest.content_hash);
    manifest.publisher_signature = Some(signing_key.sign(&signed_payload).to_bytes().to_vec());
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

#[test]
fn integration_full_lifecycle_with_structured_events() {
    let cx = LifecycleContext::new("trace-int", "decision-int", "policy-int");
    let mut manager = ExtensionLifecycleManager::new(
        "integration-ext",
        ResourceBudget::new(10_000_000_000, 8 * 1024 * 1024, 1_000),
        BudgetExhaustionPolicy::Suspend,
        CancellationConfig::default(),
    );
    manager
        .set_validated_manifest(manifest())
        .expect("manifest");
    manager
        .apply_transition(LifecycleTransition::Validate, 10, &cx)
        .expect("validate");
    manager
        .apply_transition(LifecycleTransition::Load, 20, &cx)
        .expect("load");
    manager
        .apply_transition(LifecycleTransition::Start, 30, &cx)
        .expect("start");
    manager
        .apply_transition(LifecycleTransition::Activate, 40, &cx)
        .expect("activate");
    manager
        .apply_transition(LifecycleTransition::Terminate, 50, &cx)
        .expect("terminate");
    manager
        .complete_termination(55, &cx, true, false)
        .expect("complete termination");

    assert_eq!(manager.state(), ExtensionState::Terminated);
    let events = manager.telemetry_events();
    assert!(!events.is_empty());
    for event in events {
        assert_eq!(event.trace_id, "trace-int");
        assert_eq!(event.decision_id, "decision-int");
        assert_eq!(event.policy_id, "policy-int");
        assert_eq!(event.component, "extension_lifecycle_manager");
        assert_eq!(event.event, "lifecycle_transition");
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn integration_budget_exhaustion_triggers_containment() {
    let cx = LifecycleContext::new("trace-budget", "decision-budget", "policy-budget");
    let mut manager = ExtensionLifecycleManager::new(
        "integration-budget",
        ResourceBudget::new(10_000_000_000, 8 * 1024 * 1024, 2),
        BudgetExhaustionPolicy::Terminate,
        CancellationConfig::default(),
    );
    manager
        .set_validated_manifest(manifest())
        .expect("manifest");
    manager
        .apply_transition(LifecycleTransition::Validate, 10, &cx)
        .expect("validate");
    manager
        .apply_transition(LifecycleTransition::Load, 20, &cx)
        .expect("load");
    manager
        .apply_transition(LifecycleTransition::Start, 30, &cx)
        .expect("start");
    manager
        .apply_transition(LifecycleTransition::Activate, 40, &cx)
        .expect("activate");

    manager.consume_hostcall(41, &cx).expect("hostcall1");
    let err = manager
        .consume_hostcall(42, &cx)
        .expect_err("budget containment");
    let rendered = err.to_string();
    assert!(rendered.contains("FE-LIFECYCLE-0003"));
    assert_eq!(manager.state(), ExtensionState::Terminating);
    assert!(manager.pending_cancel_token().is_some());
}
