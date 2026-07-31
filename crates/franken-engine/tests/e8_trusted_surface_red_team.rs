//! E8.SEC (bd-fqlfw.8.9): adversarial hardening of the NEW trusted surface.
//!
//! The agent-sandbox runs UNTRUSTED code by design, but three pieces of new
//! code are themselves trusted and an attacker will target them: the E8
//! certifier (`non_use_certificate.rs`), the data-contract parser
//! (`data_contract.rs`), and the MCP/tool-runner shim (`agent_sandbox.rs`).
//! A forgeable or bypassable non-use certificate is worse than none, so each
//! threat below is exercised at the Rust API level where the trusted surface
//! actually lives (these attacks are not JS-reachable — the certifier and the
//! shim never run inside the sandbox).
//!
//! Threats (from bd-fqlfw.8.9):
//! - (a) FORGE-A-CERTIFICATE: tamper with bundle/receipt/preimage; verify fails.
//! - (b) SMUGGLE-A-FLOW-PAST-THE-CERTIFIER: a Secret→egress flow through an
//!   unanalyzed construct yields `uncertified`, never a false non-use claim.
//! - (c) SHIM CONFUSED-DEPUTY: a malicious tool grant cannot exceed its
//!   `CapabilityProfile`; unknown/denied/unacknowledged grants fail closed.
//! - (d) CONTRACT-PARSER abuse: malformed/oversized/aliased inputs fail closed
//!   with typed errors and never panic (no DoS pivot).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::agent_sandbox::{
    AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION, AgentSandboxError, AgentSandboxManifest, AgentToolGrant,
};
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::capability::{CapabilityProfile, RuntimeCapability};
use frankenengine_engine::data_contract::{
    DATA_CONTRACT_SCHEMA_VERSION, DEFAULT_DATA_CONTRACT_PURPOSE, DataBinding, DataBindingRole,
    DataContract, DataContractError, RequestedOutputClaim, SinkBinding,
};
use frankenengine_engine::e8_analyzed_subset::scan_source;
use frankenengine_engine::evidence_ledger::{EvidenceVerificationIdentity, LabEvidenceAuthority};
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::{ClearanceClass, Label};
use frankenengine_engine::non_use_certificate::{
    CertificateBundle, CertificateStatus, CertifierInputs, ClaimEvaluation,
    E8_CERTIFIER_PRODUCER_ID, NON_USE_CERTIFICATE_FILE, NonUseCertificate,
    emit_certificate_bundle_lab,
};

// ===========================================================================
// Shared fixtures — a real orchestrated data-contract run
// ===========================================================================

const EXTENSION_ID: &str = "ext-e8sec";
const INPUT_PATH: &str = "fixtures/agent.js";

struct TrustedCertificateBundle {
    bundle: CertificateBundle,
    trusted_identity: EvidenceVerificationIdentity,
}

impl std::ops::Deref for TrustedCertificateBundle {
    type Target = CertificateBundle;

    fn deref(&self) -> &Self::Target {
        &self.bundle
    }
}

fn base_contract(source: &str, claims: Vec<RequestedOutputClaim>) -> DataContract {
    DataContract {
        schema_version: DATA_CONTRACT_SCHEMA_VERSION.to_string(),
        contract_id: "contract-e8sec".to_string(),
        extension_id: EXTENSION_ID.to_string(),
        input_bindings: vec![DataBinding {
            binding_id: "run-source".to_string(),
            object_ref: "object://run-source".to_string(),
            path: Some(INPUT_PATH.to_string()),
            label: Label::Public,
            owner: "runtime-team".to_string(),
            role: DataBindingRole::RunInput,
            allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
            content_hash_hex: Some(ContentHash::compute(source.as_bytes()).to_hex()),
        }],
        allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
        allowed_capabilities: BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]),
        allowed_sinks: vec![SinkBinding {
            sink_id: "audit-log".to_string(),
            clearance: ClearanceClass::AuditedSink,
            location: "ledger://audit".to_string(),
            allowed_labels: BTreeSet::from([Label::Public, Label::Internal]),
        }],
        required_declassification_routes: vec![],
        requested_output_claims: claims,
        metadata: BTreeMap::new(),
    }
}

/// Emit a signed certificate bundle for a real orchestrated run of `source`
/// under `contract`, exactly as `frankenctl run --data-contract` does after
/// bd-fqlfw.8.4.
fn emit_bundle(contract: DataContract, source: &str) -> TrustedCertificateBundle {
    let binding = contract
        .bind_to_run(
            EXTENSION_ID,
            INPUT_PATH,
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&ContentHash::compute(source.as_bytes())),
        )
        .expect("contract binds");
    let ingress = contract.ifc_ingress(&binding).expect("ingress derives");
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_data_contract_ingress(ingress);
    let result = orchestrator
        .execute(&ExtensionPackage {
            extension_id: EXTENSION_ID.to_string(),
            source: source.to_string(),
            source_file: Some(INPUT_PATH.to_string()),
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        })
        .expect("contracted run executes");
    let scan = scan_source(source, INPUT_PATH, ParseGoal::Script);
    let refusal_receipt = binding.preflight_receipt(
        &result.trace_id,
        Some("agent.explain.json"),
        Some(&scan),
        &[],
    );
    let replay_hash = ContentHash::compute(
        &serde_json::to_vec(&result.nondeterminism_trace).expect("trace serializes"),
    )
    .to_hex();
    let containment_action = result.containment_action.to_string();
    let granted = CapabilityProfile::engine_core().capabilities().clone();
    let inputs = CertifierInputs {
        contract: &contract,
        binding: &binding,
        flow_events: orchestrator.data_contract_flow_events(),
        host_effects: &result.host_effect_transcript,
        declassification_receipts: &[],
        refusal_receipt: &refusal_receipt,
        runtime_granted_capabilities: &granted,
        policy_id: "policy-e8sec",
        policy_epoch: result.epoch.as_u64(),
        parse_goal: "script",
        trace_id: &result.trace_id,
        decision_id: &result.decision_id,
        engine_version: env!("CARGO_PKG_VERSION"),
        containment_action: &containment_action,
        instructions_executed: result.instructions_executed,
        console_entry_count: result.console_output.len() as u64,
        execution_value: &result.execution_value,
        replay_trace_content_hash_hex: &replay_hash,
    };
    let authority = LabEvidenceAuthority::deterministic_fixture(
        E8_CERTIFIER_PRODUCER_ID,
        "e8-red-team-certificate-v2",
        frankenengine_engine::security_epoch::SecurityEpoch::GENESIS,
    )
    .expect("red-team lab certificate authority");
    let trusted_identity = authority.verification_identity();
    let bundle = emit_certificate_bundle_lab(&inputs, &authority).expect("bundle emits");
    TrustedCertificateBundle {
        bundle,
        trusted_identity,
    }
}

fn certifiable_bundle() -> TrustedCertificateBundle {
    // A fully-analyzed source with a claim that holds ⇒ certifiable.
    emit_bundle(
        base_contract(
            "const answer = 40 + 2;",
            vec![RequestedOutputClaim::NoFlow {
                claim_id: "no-secret-open-sink".to_string(),
                source_label: Label::Secret,
                sink_clearance: ClearanceClass::OpenSink,
            }],
        ),
        "const answer = 40 + 2;",
    )
}

// ===========================================================================
// (a) FORGE-A-CERTIFICATE
// ===========================================================================

/// A pristine certificate verifies; this is the control for every tamper case
/// below.
#[test]
fn a_pristine_certificate_verifies() {
    let bundle = certifiable_bundle();
    bundle
        .non_use_certificate
        .verify_with_trusted_identity(&bundle.trusted_identity)
        .expect("pristine non-use certificate verifies");
    bundle
        .use_certificate
        .verify_with_trusted_identity(&bundle.trusted_identity)
        .expect("pristine use certificate verifies");
}

/// Upgrading the certificate status after signing (the highest-value forgery:
/// turn `uncertified` into `certified`) must fail verification.
#[test]
fn a_status_upgrade_after_signing_fails_verification() {
    let bundle = certifiable_bundle();
    let mut forged = bundle.non_use_certificate.clone();
    // Whatever it was, flip it to the strongest state and re-check.
    forged.certificate_status = CertificateStatus::CertifiedWithinAnalyzedScope;
    // If it was already certified, flip a claim instead so the preimage moves.
    if forged == bundle.non_use_certificate {
        forged.certificate_status = CertificateStatus::Uncertified;
    }
    assert!(
        forged
            .verify_with_trusted_identity(&bundle.trusted_identity)
            .is_err(),
        "a post-signing status change must invalidate the signature"
    );
}

/// Rewriting a per-claim verdict from a fail-closed value to
/// `holds_within_analyzed_scope` must fail verification.
#[test]
fn a_claim_verdict_forgery_fails_verification() {
    let bundle = emit_bundle(
        base_contract(
            "for (const x of [1]) { }",
            vec![RequestedOutputClaim::OutputIndependentOf {
                claim_id: "independent".to_string(),
                binding_id: "run-source".to_string(),
            }],
        ),
        "for (const x of [1]) { }",
    );
    let mut forged = bundle.non_use_certificate.clone();
    assert!(!forged.claims.is_empty());
    forged.claims[0].evaluation = ClaimEvaluation::HoldsWithinAnalyzedScope;
    assert!(
        forged
            .verify_with_trusted_identity(&bundle.trusted_identity)
            .is_err(),
        "forging a claim verdict must invalidate the signature"
    );
}

/// Tampering with a recorded flow edge (hiding a Secret→sink edge) must fail
/// verification.
#[test]
fn a_flow_event_tampering_fails_verification() {
    let bundle = certifiable_bundle();
    let mut forged = bundle.non_use_certificate.clone();
    // Append or drop a flow event; either way the preimage moves.
    if forged.flow_events.is_empty() {
        // Nothing to drop: mutate the scope's replay hash instead.
        forged.scope.replay_trace_content_hash_hex = "deadbeef".repeat(8);
    } else {
        forged.flow_events.pop();
    }
    assert!(
        forged
            .verify_with_trusted_identity(&bundle.trusted_identity)
            .is_err()
    );
}

/// Zeroing / swapping the signature bytes must fail verification (a signature
/// is not a checksum an attacker can recompute).
#[test]
fn a_signature_substitution_fails_verification() {
    let bundle = certifiable_bundle();
    let use_sig = bundle.use_certificate.signature_envelope.signature.clone();
    let mut forged = bundle.non_use_certificate.clone();
    // Graft the use-certificate's (valid, but wrong-object) signature on.
    forged.signature_envelope.signature = use_sig;
    assert!(
        forged
            .verify_with_trusted_identity(&bundle.trusted_identity)
            .is_err(),
        "a signature from a different object must not verify here (domain + \
         schema separation)"
    );
}

/// Re-anchoring: a certificate signed by the runtime key cannot be made to
/// verify under a different verification key the attacker controls. We flip a
/// byte of the embedded key until we land on a structurally-valid but wrong
/// Ed25519 key, then confirm the runtime-key signature does not verify under
/// it.
#[test]
fn a_certificate_cannot_be_reanchored_to_another_key() {
    use frankenengine_engine::signature_preimage::VerificationKey;
    let bundle = certifiable_bundle();
    let trusted_identity = bundle.trusted_identity.clone();
    let mut key_bytes = *trusted_identity.verification_key.as_bytes();
    let mut wrong_key = None;
    for bit in 0..8u8 {
        let mut candidate = key_bytes;
        candidate[0] ^= 1 << bit;
        if let Ok(key) = VerificationKey::from_bytes(candidate) {
            wrong_key = Some(key);
            break;
        }
        key_bytes = candidate;
    }
    let wrong_key = wrong_key.expect("a valid but different Ed25519 key exists nearby");
    let mut forged = bundle.non_use_certificate.clone();
    forged.signature_envelope.verification_key = wrong_key;
    assert!(
        forged
            .verify_with_trusted_identity(&trusted_identity)
            .is_err(),
        "a claimant-embedded key must not replace the externally trusted runtime identity"
    );
}

/// The persisted JSON round-trips and still verifies — but a byte-edited JSON
/// (status string swapped) does not. This is the third-party-consumer path:
/// only the files travel, and a tampered file is detectable.
#[test]
fn a_byte_edited_persisted_certificate_json_fails_verification() {
    let bundle = certifiable_bundle();
    let bytes = &bundle
        .file(NON_USE_CERTIFICATE_FILE)
        .expect("non-use file")
        .bytes;
    let json = String::from_utf8(bytes.clone()).expect("utf8");
    // Swap whatever status is present to its opposite in the raw JSON.
    let edited = if json.contains("\"uncertified\"") {
        json.replace("\"uncertified\"", "\"certified_within_analyzed_scope\"")
    } else {
        json.replace("\"certified_within_analyzed_scope\"", "\"uncertified\"")
    };
    assert_ne!(edited, json, "the edit must actually change the JSON");
    let forged: NonUseCertificate =
        serde_json::from_str(&edited).expect("edited JSON still parses");
    assert!(
        forged
            .verify_with_trusted_identity(&bundle.trusted_identity)
            .is_err(),
        "a byte-edited persisted certificate must fail verification"
    );
}

// ===========================================================================
// (b) SMUGGLE-A-FLOW-PAST-THE-CERTIFIER
// ===========================================================================

/// A Secret ingress that reaches an open sink through an *analyzed* construct
/// is already caught by the flow model (NotAssertable/uncertified). The
/// harder case: route it through an UNANALYZED construct hoping the certifier
/// loses track. The scan must refuse the run outright, so the certificate is
/// uncertified and the Secret→sink claim never reads as non-use.
#[test]
fn b_secret_to_sink_through_unanalyzed_construct_is_uncertified() {
    let source = "const xs = [1, 2, 3];\nlet acc = 0;\nfor (const x of xs) { acc = acc + x; }";
    let contract = DataContract {
        schema_version: DATA_CONTRACT_SCHEMA_VERSION.to_string(),
        contract_id: "contract-e8sec-smuggle".to_string(),
        extension_id: EXTENSION_ID.to_string(),
        input_bindings: vec![DataBinding {
            binding_id: "run-source".to_string(),
            object_ref: "object://run-source".to_string(),
            path: Some(INPUT_PATH.to_string()),
            label: Label::Secret,
            owner: "data-owner".to_string(),
            role: DataBindingRole::RunInput,
            allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
            content_hash_hex: Some(ContentHash::compute(source.as_bytes()).to_hex()),
        }],
        allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
        allowed_capabilities: BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]),
        // OpenSink admits Secret so the ingress edge is Allowed and the run
        // executes (a Blocked edge would abort before we could test the
        // certifier). The attack is that the run *does* proceed.
        allowed_sinks: vec![SinkBinding {
            sink_id: "exfil".to_string(),
            clearance: ClearanceClass::OpenSink,
            location: "https://exfil.example".to_string(),
            allowed_labels: BTreeSet::from([Label::Public, Label::Secret]),
        }],
        required_declassification_routes: vec![],
        requested_output_claims: vec![RequestedOutputClaim::NoFlow {
            claim_id: "no-secret-exfil".to_string(),
            source_label: Label::Secret,
            sink_clearance: ClearanceClass::OpenSink,
        }],
        metadata: BTreeMap::new(),
    };
    let bundle = emit_bundle(contract, source);
    assert_eq!(
        bundle.non_use_certificate.certificate_status,
        CertificateStatus::Uncertified,
        "a run with an unanalyzed construct must never certify"
    );
    let verdict = &bundle.non_use_certificate.claims[0];
    assert_ne!(
        verdict.evaluation,
        ClaimEvaluation::HoldsWithinAnalyzedScope,
        "the Secret→open-sink claim must never read as non-use"
    );
}

// ===========================================================================
// (c) SHIM CONFUSED-DEPUTY / PRIVILEGE ESCALATION
// ===========================================================================

fn manifest(grants: Vec<AgentToolGrant>) -> AgentSandboxManifest {
    AgentSandboxManifest {
        schema_version: AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION.to_string(),
        agent_id: "agent-e8sec".to_string(),
        tool_grants: grants,
        denied_capability_tags: vec![],
        trust_level: None,
        host_io_root: None,
        host_io_max_bytes: None,
        acknowledge_unfiltered_network: false,
        purpose: None,
        metadata: BTreeMap::new(),
    }
}

fn grant(tool: &str, tag: &str) -> AgentToolGrant {
    AgentToolGrant {
        tool_name: tool.to_string(),
        capability_tag: tag.to_string(),
        description: None,
    }
}

/// An unknown capability tag must be REFUSED, never silently dropped — a
/// silent drop would let the agent believe it holds authority the membrane
/// won't honor (confused deputy).
#[test]
fn c_unknown_capability_tag_is_refused_not_dropped() {
    let m = manifest(vec![grant("sneaky", "root_all_the_things")]);
    assert!(matches!(
        m.validate(),
        Err(AgentSandboxError::UnknownCapabilityTag { .. })
    ));
    assert!(matches!(
        m.effective_runtime_capabilities(false),
        Err(AgentSandboxError::UnknownCapabilityTag { .. })
    ));
}

/// A network-egress grant without the explicit unfiltered-network
/// acknowledgement fails closed.
#[test]
fn c_network_grant_without_acknowledgement_fails_closed() {
    let m = manifest(vec![grant("http", "network_egress")]);
    assert!(matches!(
        m.validate(),
        Err(AgentSandboxError::NetworkGrantWithoutAcknowledgement { .. })
    ));
}

/// A capability both granted and denied is an ambiguous manifest — refuse it
/// rather than pick a side (fail closed).
#[test]
fn c_denied_and_granted_capability_is_ambiguous_and_refused() {
    let mut m = manifest(vec![grant("fs", "fs_read")]);
    m.denied_capability_tags = vec!["fs_read".to_string()];
    assert!(matches!(
        m.validate(),
        Err(AgentSandboxError::DeniedCapabilityAlsoGranted { .. })
    ));
}

/// The effective runtime set is exactly the granted tags plus the forced VM
/// capabilities — a grant cannot smuggle in authority beyond what its tags
/// denote, and the certificate reports that exact set.
#[test]
fn c_effective_capabilities_are_exactly_grants_plus_forced_vm() {
    let m = manifest(vec![grant("reader", "fs_read")]);
    m.validate().expect("valid manifest");
    let effective = m.effective_runtime_capabilities(false).expect("resolves");
    assert!(effective.contains(&RuntimeCapability::FsRead));
    // ProcessSpawn was never granted; it must not appear.
    assert!(!effective.contains(&RuntimeCapability::ProcessSpawn));
    // NetworkEgress was never granted; it must not appear.
    assert!(!effective.contains(&RuntimeCapability::NetworkEgress));
    // The engine-core profile is NOT subsumed just because the shim ran.
    assert!(
        !CapabilityProfile::engine_core()
            .capabilities()
            .is_subset(&effective),
        "a narrow tool grant must not inherit the full engine-core profile"
    );
}

/// Duplicate tool names fail closed (a second grant cannot shadow the first
/// to widen authority).
#[test]
fn c_duplicate_tool_names_fail_closed() {
    let m = manifest(vec![grant("tool", "fs_read"), grant("tool", "fs_write")]);
    assert!(matches!(
        m.validate(),
        Err(AgentSandboxError::DuplicateToolName { .. })
    ));
}

/// A module-goal run adds exactly `ModuleLoad` and nothing else beyond the
/// grants + forced VM set.
#[test]
fn c_module_goal_adds_only_module_load() {
    let m = manifest(vec![grant("reader", "fs_read")]);
    let script = m.effective_runtime_capabilities(false).expect("script set");
    let module = m.effective_runtime_capabilities(true).expect("module set");
    let added: BTreeSet<_> = module.difference(&script).copied().collect();
    assert_eq!(added, BTreeSet::from([RuntimeCapability::ModuleLoad]));
}

// ===========================================================================
// (d) CONTRACT-PARSER ABUSE (fail closed, never panic)
// ===========================================================================

fn valid_contract() -> DataContract {
    base_contract(
        "const a = 1;",
        vec![RequestedOutputClaim::CapabilityNotUsed {
            claim_id: "no-spawn".to_string(),
            capability: RuntimeCapability::ProcessSpawn,
        }],
    )
}

#[test]
fn d_wrong_schema_version_fails_closed() {
    let mut c = valid_contract();
    c.schema_version = "franken-engine.data-contract.v999".to_string();
    assert!(matches!(
        c.validate(),
        Err(DataContractError::UnsupportedSchema { .. })
    ));
}

#[test]
fn d_empty_required_field_fails_closed() {
    let mut c = valid_contract();
    c.contract_id = String::new();
    assert!(matches!(
        c.validate(),
        Err(DataContractError::EmptyField { .. })
    ));
}

#[test]
fn d_duplicate_binding_ids_fail_closed() {
    let mut c = valid_contract();
    let mut dup = c.input_bindings[0].clone();
    dup.object_ref = "object://other".to_string();
    dup.path = Some("fixtures/other.js".to_string());
    c.input_bindings.push(dup);
    assert!(matches!(
        c.validate(),
        Err(DataContractError::DuplicateId { .. })
    ));
}

#[test]
fn d_malformed_content_hash_hex_fails_closed() {
    let mut c = valid_contract();
    c.input_bindings[0].content_hash_hex = Some("nothex!!".to_string());
    assert!(matches!(
        c.validate(),
        Err(DataContractError::InvalidContentHashHex { .. })
    ));
}

#[test]
fn d_claim_referencing_unknown_binding_fails_closed() {
    let mut c = valid_contract();
    c.requested_output_claims
        .push(RequestedOutputClaim::OutputIndependentOf {
            claim_id: "dangling".to_string(),
            binding_id: "no-such-binding".to_string(),
        });
    assert!(matches!(
        c.validate(),
        Err(DataContractError::UnknownBindingRef { .. })
    ));
}

/// A hash-aliased run input (contract declares one hash, the run supplies
/// different bytes) must fail the bind, not silently accept the substitution.
#[test]
fn d_run_input_hash_alias_fails_closed() {
    let c = valid_contract();
    let wrong = ContentHash::compute(b"not the declared bytes");
    assert!(matches!(
        c.bind_to_run(
            EXTENSION_ID,
            INPUT_PATH,
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&wrong)
        ),
        Err(DataContractError::RunInputContentHashMismatch { .. })
    ));
}

/// Oversized / adversarial JSON input must be rejected by serde or by
/// `validate`, never panic. Deeply-nested and truncated inputs are the DoS
/// pivot to guard (cf. bd-ytaa7).
#[test]
fn d_adversarial_json_never_panics() {
    let adversarial = [
        "",
        "{",
        "null",
        "[]",
        "{\"schema_version\": 12345}",
        "{\"schema_version\": \"x\", \"contract_id\": \"y\"}",
        &format!("{}{}", "[".repeat(2000), "]".repeat(2000)),
        &format!("{{\"contract_id\":\"{}\"}}", "A".repeat(100_000)),
    ];
    for input in adversarial {
        // Must return a Result, never panic/abort.
        let parsed: Result<DataContract, _> = serde_json::from_str(input);
        if let Ok(contract) = parsed {
            // A structurally-parseable but semantically-invalid contract must
            // still fail validation fail-closed.
            let _ = contract.validate();
        }
    }
}

/// An empty capability set / empty purpose set fails closed (a contract that
/// grants nothing but claims everything must not validate into an
/// all-permissive state).
#[test]
fn d_empty_sets_fail_closed() {
    let mut c = valid_contract();
    c.allowed_capabilities = BTreeSet::new();
    assert!(matches!(
        c.validate(),
        Err(DataContractError::EmptySet { .. })
    ));
}
