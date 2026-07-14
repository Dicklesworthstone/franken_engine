//! Integration tests for the E8.T5 agent-sandbox (bd-fqlfw.8.5): an agent
//! framework declares tool authority in a manifest, runs model-generated code
//! through the real orchestrator with the guardplane armed, and receives the
//! E8 certificate bundle on exit.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::agent_sandbox::{
    AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION, AgentSandboxError, AgentSandboxManifest,
    AgentSandboxReport, AgentToolGrant, DEFAULT_AGENT_TRUST_LEVEL,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::data_contract::{
    DATA_CONTRACT_SCHEMA_VERSION, DEFAULT_DATA_CONTRACT_PURPOSE, DataBinding, DataBindingRole,
    DataContract, RequestedOutputClaim, SinkBinding,
};
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, OrchestratorConfig, OrchestratorResult,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::{ClearanceClass, Label};
use frankenengine_engine::non_use_certificate::{
    CertificateStatus, CertifierInputs, NON_USE_CERTIFICATE_FILE, NonUseCertificate,
    emit_certificate_bundle,
};

const GENERATED_SOURCE: &str = "const parts = ['4', '2']; const result = parts.join('');";
const AGENT_ID: &str = "agent-e8t5-framework";
const INPUT_PATH: &str = "generated/agent_step.js";

fn manifest() -> AgentSandboxManifest {
    AgentSandboxManifest {
        schema_version: AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION.to_string(),
        agent_id: AGENT_ID.to_string(),
        tool_grants: vec![AgentToolGrant {
            tool_name: "log".to_string(),
            capability_tag: "console".to_string(),
            description: Some("write to the sandboxed console".to_string()),
        }],
        denied_capability_tags: vec!["process_spawn".to_string(), "network".to_string()],
        trust_level: None,
        host_io_root: None,
        host_io_max_bytes: None,
        acknowledge_unfiltered_network: false,
        purpose: Some(DEFAULT_DATA_CONTRACT_PURPOSE.to_string()),
        metadata: BTreeMap::new(),
    }
}

fn contract() -> DataContract {
    DataContract {
        schema_version: DATA_CONTRACT_SCHEMA_VERSION.to_string(),
        contract_id: "contract-agent-sandbox".to_string(),
        extension_id: AGENT_ID.to_string(),
        input_bindings: vec![DataBinding {
            binding_id: "generated-source".to_string(),
            object_ref: "object://generated-source".to_string(),
            path: Some(INPUT_PATH.to_string()),
            label: Label::Public,
            owner: "agent-framework".to_string(),
            role: DataBindingRole::RunInput,
            allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
            content_hash_hex: Some(ContentHash::compute(GENERATED_SOURCE.as_bytes()).to_hex()),
        }],
        allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
        allowed_capabilities: BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Console,
        ]),
        allowed_sinks: vec![SinkBinding {
            sink_id: "framework-console".to_string(),
            clearance: ClearanceClass::RestrictedSink,
            location: "console".to_string(),
            allowed_labels: BTreeSet::from([Label::Public, Label::Internal]),
        }],
        required_declassification_routes: vec![],
        requested_output_claims: vec![
            RequestedOutputClaim::NoFlow {
                claim_id: "no-secret-egress".to_string(),
                source_label: Label::Secret,
                sink_clearance: ClearanceClass::NeverSink,
            },
            RequestedOutputClaim::CapabilityNotUsed {
                claim_id: "no-process-spawn".to_string(),
                capability: RuntimeCapability::ProcessSpawn,
            },
        ],
        metadata: BTreeMap::new(),
    }
}

struct SandboxRun {
    manifest: AgentSandboxManifest,
    result: OrchestratorResult,
    orchestrator: ExecutionOrchestrator,
}

/// Run the agent's generated source exactly as `frankenctl agent-sandbox`
/// does: manifest-derived package (guardplane armed), contract ingress bound.
fn sandbox_run() -> SandboxRun {
    let manifest = manifest();
    let contract = contract();
    let binding = contract
        .bind_to_run(
            AGENT_ID,
            INPUT_PATH,
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&ContentHash::compute(GENERATED_SOURCE.as_bytes())),
        )
        .expect("contract binds to the generated source");
    let ingress = contract.ifc_ingress(&binding).expect("ingress derives");
    let package = manifest
        .to_extension_package(
            GENERATED_SOURCE.to_string(),
            Some(INPUT_PATH.to_string()),
            "0.1.0-test",
            false,
        )
        .expect("manifest builds the extension package");
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_data_contract_ingress(ingress);
    let result = orchestrator
        .execute(&package)
        .expect("agent-generated code executes under the sandbox");
    SandboxRun {
        manifest,
        result,
        orchestrator,
    }
}

/// ACCEPTANCE (bd-fqlfw.8.5): an agent framework can run model-generated
/// code under the engine and receive the certificate bundle on exit, with
/// the certificate's runtime-granted set reflecting the agent's tool
/// authority.
#[test]
fn agent_framework_receives_certificate_bundle_on_exit() {
    let run = sandbox_run();
    let contract = contract();
    let binding = contract
        .bind_to_run(
            AGENT_ID,
            INPUT_PATH,
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&ContentHash::compute(GENERATED_SOURCE.as_bytes())),
        )
        .expect("binding rebinds");
    let refusal_receipt = binding.uncertified_preflight_receipt(&run.result.trace_id, None);
    let granted = run
        .manifest
        .effective_runtime_capabilities(false)
        .expect("effective capabilities derive");
    let replay_hash = ContentHash::compute(
        &serde_json::to_vec(&run.result.nondeterminism_trace).expect("trace serializes"),
    )
    .to_hex();
    let containment_action = run.result.containment_action.to_string();

    let inputs = CertifierInputs {
        contract: &contract,
        binding: &binding,
        flow_events: run.orchestrator.data_contract_flow_events(),
        host_effects: &run.result.host_effect_transcript,
        declassification_receipts: &[],
        refusal_receipt: &refusal_receipt,
        runtime_granted_capabilities: &granted,
        policy_id: "policy-default",
        policy_epoch: run.result.epoch.as_u64(),
        parse_goal: "script",
        trace_id: &run.result.trace_id,
        decision_id: &run.result.decision_id,
        engine_version: "0.1.0-test",
        containment_action: &containment_action,
        instructions_executed: run.result.instructions_executed,
        console_entry_count: run.result.console_output.len() as u64,
        execution_value: &run.result.execution_value,
        replay_trace_content_hash_hex: &replay_hash,
    };
    let bundle = emit_certificate_bundle(&inputs).expect("certificate bundle emits on exit");

    assert_eq!(bundle.files.len(), 6);
    assert_eq!(
        bundle.non_use_certificate.certificate_status,
        CertificateStatus::Uncertified
    );
    // The certificate reports the AGENT's authority, not a CLI default.
    assert!(
        bundle
            .non_use_certificate
            .scope
            .runtime_granted_capabilities
            .contains(&RuntimeCapability::Console)
    );
    assert!(
        !bundle
            .non_use_certificate
            .scope
            .runtime_granted_capabilities
            .contains(&RuntimeCapability::ProcessSpawn)
    );
    let parsed: NonUseCertificate = serde_json::from_slice(
        &bundle
            .file(NON_USE_CERTIFICATE_FILE)
            .expect("non-use certificate file")
            .bytes,
    )
    .expect("certificate parses");
    parsed
        .verify()
        .expect("signature verifies for the framework");
}

/// The guardplane is armed for every sandbox run: the manifest metadata
/// enables instruction hooks and the evidence stream records guardplane
/// observations of the agent's actions.
#[test]
fn guardplane_watches_agent_actions() {
    let run = sandbox_run();
    let report =
        AgentSandboxReport::from_run(&run.manifest, &run.result, false).expect("report builds");

    assert_eq!(report.agent_id, AGENT_ID);
    assert_eq!(report.trust_level, DEFAULT_AGENT_TRUST_LEVEL);
    assert!(
        report.guardplane.guardplane_evidence_entries > 0,
        "the behavior firewall must observe agent actions (got {} guardplane entries)",
        report.guardplane.guardplane_evidence_entries
    );
    assert!(!report.guardplane.containment_action.is_empty());
}

/// The sandbox report echoes the tool authority and execution facts the
/// framework needs for audit.
#[test]
fn sandbox_report_reflects_tool_authority_and_execution() {
    let run = sandbox_run();
    let report =
        AgentSandboxReport::from_run(&run.manifest, &run.result, false).expect("report builds");

    assert_eq!(report.tool_grants.len(), 1);
    assert_eq!(report.tool_grants[0].tool_name, "log");
    assert!(
        report
            .effective_capabilities
            .contains(&RuntimeCapability::Console)
    );
    assert!(
        report
            .effective_capabilities
            .contains(&RuntimeCapability::VmDispatch),
        "forced VM capabilities must be reported"
    );
    assert!(report.instructions_executed > 0);
    assert_eq!(report.trace_id, run.result.trace_id);
}

/// A report (and therefore the certificate capability input derived through
/// the same method) must refuse a manifest whose deny list contradicts the
/// VM capabilities forced by the execution context.
#[test]
fn sandbox_report_rejects_denied_forced_runtime_capability() {
    let run = sandbox_run();
    let mut contradictory = run.manifest.clone();
    contradictory
        .denied_capability_tags
        .push("vm_dispatch".to_string());

    assert!(matches!(
        AgentSandboxReport::from_run(&contradictory, &run.result, false),
        Err(AgentSandboxError::DeniedCapabilityAlsoGranted {
            capability_tag
        }) if capability_tag == "vm_dispatch"
    ));
}

/// Two sandbox runs of the same fixed inputs produce identical reports
/// (deterministic substrate, deterministic report).
#[test]
fn sandbox_report_is_deterministic_across_runs() {
    let first_run = sandbox_run();
    let second_run = sandbox_run();
    let first = AgentSandboxReport::from_run(&first_run.manifest, &first_run.result, false)
        .expect("first report");
    let second = AgentSandboxReport::from_run(&second_run.manifest, &second_run.result, false)
        .expect("second report");
    assert_eq!(first, second);
}

/// The membrane grants exactly the manifest's tool authority: a package
/// built from the manifest carries only the granted tags (the interpreter
/// force-grants its VM baseline separately).
#[test]
fn package_capabilities_match_tool_grants_exactly() {
    let package = manifest()
        .to_extension_package(GENERATED_SOURCE.to_string(), None, "0.1.0-test", false)
        .expect("package builds");
    assert_eq!(package.capabilities, vec!["console".to_string()]);
    assert_eq!(
        package
            .metadata
            .get("capability_witness.denied_capabilities"),
        Some(&"network,process_spawn".to_string())
    );
}
