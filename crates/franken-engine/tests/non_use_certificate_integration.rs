//! Integration tests for the E8.T3 certifier (bd-fqlfw.8.3): drive a real
//! data-contract run through the execution orchestrator, emit the certificate
//! bundle from the recorded evidence, and verify the acceptance criteria —
//! the bundle states its scope precisely and replays byte-identically.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::capability::{CapabilityProfile, RuntimeCapability};
use frankenengine_engine::data_contract::{
    DATA_CONTRACT_SCHEMA_VERSION, DEFAULT_DATA_CONTRACT_PURPOSE, DataBinding, DataBindingRole,
    DataContract, DataContractRunBinding, E8RefusalLedgerReceipt, RequestedOutputClaim,
    SinkBinding,
};
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorResult,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::{ClearanceClass, Label};
use frankenengine_engine::non_use_certificate::{
    AUDIT_FILE, CAPABILITY_TRACE_FILE, CertificateBundle, CertificateStatus, CertifierInputs,
    ClaimEvaluation, DECLASSIFICATION_RECEIPTS_FILE, NON_USE_CERTIFICATE_FILE, NonUseCertificate,
    REPRO_LOCK_FILE, USE_CERTIFICATE_FILE, UseCertificate, emit_certificate_bundle,
};

const SOURCE: &str = "const answer = 40 + 2;";
const EXTENSION_ID: &str = "ext-e8t3-cert";
const INPUT_PATH: &str = "fixtures/agent.js";

fn contract() -> DataContract {
    DataContract {
        schema_version: DATA_CONTRACT_SCHEMA_VERSION.to_string(),
        contract_id: "contract-e8t3-cert".to_string(),
        extension_id: EXTENSION_ID.to_string(),
        input_bindings: vec![
            DataBinding {
                binding_id: "run-source".to_string(),
                object_ref: "object://run-source".to_string(),
                path: Some(INPUT_PATH.to_string()),
                label: Label::Public,
                owner: "runtime-team".to_string(),
                role: DataBindingRole::RunInput,
                allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
                content_hash_hex: Some(ContentHash::compute(SOURCE.as_bytes()).to_hex()),
            },
            DataBinding {
                binding_id: "customer-pii".to_string(),
                object_ref: "dataset://customer-pii".to_string(),
                path: None,
                label: Label::Secret,
                owner: "data-owner".to_string(),
                role: DataBindingRole::SensitiveInput,
                allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
                content_hash_hex: None,
            },
        ],
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
        requested_output_claims: vec![
            RequestedOutputClaim::NoFlow {
                claim_id: "no-secret-open-sink".to_string(),
                source_label: Label::Secret,
                sink_clearance: ClearanceClass::OpenSink,
            },
            RequestedOutputClaim::NoFlow {
                claim_id: "no-public-audited-sink".to_string(),
                source_label: Label::Public,
                sink_clearance: ClearanceClass::AuditedSink,
            },
            RequestedOutputClaim::CapabilityNotUsed {
                claim_id: "no-process-spawn".to_string(),
                capability: RuntimeCapability::ProcessSpawn,
            },
            RequestedOutputClaim::OutputIndependentOf {
                claim_id: "output-independent-of-pii".to_string(),
                binding_id: "customer-pii".to_string(),
            },
        ],
        metadata: BTreeMap::new(),
    }
}

fn package() -> ExtensionPackage {
    ExtensionPackage {
        extension_id: EXTENSION_ID.to_string(),
        source: SOURCE.to_string(),
        source_file: Some(INPUT_PATH.to_string()),
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

struct CompletedRun {
    contract: DataContract,
    binding: DataContractRunBinding,
    refusal_receipt: E8RefusalLedgerReceipt,
    result: OrchestratorResult,
    orchestrator: ExecutionOrchestrator,
    granted: BTreeSet<RuntimeCapability>,
}

/// Execute the fixed source through a real orchestrator under the bound data
/// contract, exactly as `frankenctl run --data-contract` does.
fn completed_run() -> CompletedRun {
    let contract = contract();
    let binding = contract
        .bind_to_run(
            EXTENSION_ID,
            INPUT_PATH,
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&ContentHash::compute(SOURCE.as_bytes())),
        )
        .expect("contract binds to run");
    let ingress = contract.ifc_ingress(&binding).expect("ingress derives");
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_data_contract_ingress(ingress);
    let result = orchestrator
        .execute(&package())
        .expect("lattice-legal contracted run executes");
    let refusal_receipt = binding.uncertified_preflight_receipt(&result.trace_id, None);
    CompletedRun {
        contract,
        binding,
        refusal_receipt,
        result,
        orchestrator,
        granted: CapabilityProfile::engine_core().capabilities().clone(),
    }
}

fn emit(run: &CompletedRun) -> CertificateBundle {
    let replay_hash = ContentHash::compute(
        &serde_json::to_vec(&run.result.nondeterminism_trace)
            .expect("nondeterminism trace serializes"),
    )
    .to_hex();
    let containment_action = run.result.containment_action.to_string();
    let inputs = CertifierInputs {
        contract: &run.contract,
        binding: &run.binding,
        flow_events: run.orchestrator.data_contract_flow_events(),
        host_effects: &run.result.host_effect_transcript,
        declassification_receipts: &[],
        refusal_receipt: &run.refusal_receipt,
        runtime_granted_capabilities: &run.granted,
        policy_id: "policy-default",
        policy_epoch: run.result.epoch.as_u64(),
        parse_goal: "script",
        trace_id: &run.result.trace_id,
        decision_id: &run.result.decision_id,
        engine_version: env!("CARGO_PKG_VERSION"),
        containment_action: &containment_action,
        instructions_executed: run.result.instructions_executed,
        console_entry_count: run.result.console_output.len() as u64,
        execution_value: &run.result.execution_value,
        replay_trace_content_hash_hex: &replay_hash,
    };
    emit_certificate_bundle(&inputs).expect("bundle emits from a completed run")
}

/// ACCEPTANCE (bd-fqlfw.8.3): the bundle replays byte-identically — two
/// independent orchestrated runs of the same fixed inputs yield the same six
/// files, byte for byte.
#[test]
fn certificate_bundle_replays_byte_identically_across_real_runs() {
    let first_run = completed_run();
    let second_run = completed_run();
    let first = emit(&first_run);
    let second = emit(&second_run);

    assert_eq!(
        first.bundle_content_hash_hex,
        second.bundle_content_hash_hex
    );
    assert_eq!(first.files.len(), 6);
    for (a, b) in first.files.iter().zip(second.files.iter()) {
        assert_eq!(a.name, b.name);
        assert_eq!(
            a.bytes, b.bytes,
            "bundle file `{}` must replay byte-identically",
            a.name
        );
    }
}

/// The bundle carries exactly the declared artifact set.
#[test]
fn certificate_bundle_contains_the_declared_artifacts() {
    let run = completed_run();
    let bundle = emit(&run);
    let names: Vec<&str> = bundle.files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            NON_USE_CERTIFICATE_FILE,
            USE_CERTIFICATE_FILE,
            DECLASSIFICATION_RECEIPTS_FILE,
            CAPABILITY_TRACE_FILE,
            REPRO_LOCK_FILE,
            AUDIT_FILE,
        ]
    );
}

/// Both certificates are signed with the runtime key and verify; tampering
/// with either is detected.
#[test]
fn certificates_are_signed_and_tamper_evident() {
    let run = completed_run();
    let bundle = emit(&run);

    bundle
        .non_use_certificate
        .verify()
        .expect("non-use certificate signature verifies");
    bundle
        .use_certificate
        .verify()
        .expect("use certificate signature verifies");

    let mut tampered = bundle.non_use_certificate.clone();
    tampered.certificate_status = CertificateStatus::CertifiedWithinAnalyzedScope;
    assert!(
        tampered.verify().is_err(),
        "a certificate whose status was upgraded after signing must fail verification"
    );

    let mut tampered_use = bundle.use_certificate.clone();
    tampered_use.instructions_executed += 1;
    assert!(tampered_use.verify().is_err());
}

/// The persisted JSON files round-trip into the certificate types and still
/// verify — a third party consuming only the files can check the signatures.
#[test]
fn persisted_certificates_round_trip_and_verify() {
    let run = completed_run();
    let bundle = emit(&run);

    let non_use: NonUseCertificate = serde_json::from_slice(
        &bundle
            .file(NON_USE_CERTIFICATE_FILE)
            .expect("non-use file")
            .bytes,
    )
    .expect("non-use certificate parses");
    non_use.verify().expect("parsed non-use verifies");
    assert_eq!(non_use, bundle.non_use_certificate);

    let use_cert: UseCertificate =
        serde_json::from_slice(&bundle.file(USE_CERTIFICATE_FILE).expect("use file").bytes)
            .expect("use certificate parses");
    use_cert.verify().expect("parsed use verifies");
    assert_eq!(use_cert, bundle.use_certificate);
}

/// Claim verdicts follow the recorded evidence fail-closed:
/// - no OpenSink is declared, so "no Secret -> OpenSink" holds within scope;
/// - the Public ingress label reached the audited sink via an Allowed edge,
///   so "no Public -> AuditedSink" is NOT assertable (over-approximation);
/// - ProcessSpawn is granted by neither contract nor runtime profile, so its
///   non-use holds by fail-closed enforcement;
/// - output-independence is unanalyzed in v1 and fails closed.
#[test]
fn claim_verdicts_follow_the_recorded_evidence() {
    let run = completed_run();
    let bundle = emit(&run);
    let verdict = |claim_id: &str| {
        bundle
            .non_use_certificate
            .claims
            .iter()
            .find(|claim| claim.claim_id == claim_id)
            .unwrap_or_else(|| panic!("claim `{claim_id}` present"))
    };

    assert_eq!(
        verdict("no-secret-open-sink").evaluation,
        ClaimEvaluation::HoldsWithinAnalyzedScope
    );
    assert_eq!(
        verdict("no-public-audited-sink").evaluation,
        ClaimEvaluation::NotAssertableConservative
    );
    assert_eq!(
        verdict("no-process-spawn").evaluation,
        ClaimEvaluation::HoldsWithinAnalyzedScope
    );
    assert_eq!(
        verdict("output-independent-of-pii").evaluation,
        ClaimEvaluation::UnanalyzedFailClosed
    );
}

/// v1 posture: the refusal ledger blocks certification, so the certificate
/// status is `uncertified` and the ledger linkage is embedded.
#[test]
fn certificate_status_is_uncertified_and_linked_to_the_refusal_ledger() {
    let run = completed_run();
    let bundle = emit(&run);
    assert_eq!(
        bundle.non_use_certificate.certificate_status,
        CertificateStatus::Uncertified
    );
    assert_eq!(
        bundle.non_use_certificate.refusal_ledger_id,
        run.refusal_receipt.ledger_id
    );
    assert_eq!(
        bundle
            .non_use_certificate
            .refusal_ledger_content_hash_hex
            .len(),
        64
    );
}

/// ACCEPTANCE (bd-fqlfw.8.3): the bundle states its scope precisely — engine
/// version, policy epoch, declared host boundary, input binding, and replay
/// artifact all appear in the scope and the audit summary.
#[test]
fn scope_and_audit_state_the_binding_boundary_and_replay_artifact() {
    let run = completed_run();
    let bundle = emit(&run);
    let scope = &bundle.non_use_certificate.scope;

    assert_eq!(scope.engine_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(scope.policy_epoch, run.result.epoch.as_u64());
    assert_eq!(scope.contract_id, run.contract.contract_id);
    assert_eq!(scope.contract_hash_hex, run.binding.contract_hash_hex);
    assert_eq!(scope.run_input_binding_id, "run-source");
    assert_eq!(scope.trace_id, run.result.trace_id);
    assert_eq!(scope.declared_sinks.len(), 1);
    assert_eq!(scope.declared_sinks[0].sink_id, "audit-log");
    assert_eq!(scope.threat_model_scope, "explicit_flow_ifc_v1");
    assert_eq!(scope.replay_trace_content_hash_hex.len(), 64);

    let audit = String::from_utf8(bundle.file(AUDIT_FILE).expect("audit").bytes.clone())
        .expect("audit is utf8");
    assert!(audit.contains(&scope.engine_version));
    assert!(audit.contains(&scope.contract_hash_hex));
    assert!(audit.contains(&scope.replay_trace_content_hash_hex));
    assert!(audit.contains("EXPLICIT-FLOW ONLY"));
    assert!(audit.contains(&format!("security epoch {}", scope.policy_epoch)));
}

/// The repro.lock binds every other bundle file by digest and pins the
/// replay pointer to the nondeterminism-trace content hash.
#[test]
fn repro_lock_binds_file_digests_and_replay_pointer() {
    let run = completed_run();
    let bundle = emit(&run);

    assert_eq!(bundle.repro_lock.files.len(), 5);
    for digest in &bundle.repro_lock.files {
        let file = bundle.file(&digest.name).expect("digested file exists");
        assert_eq!(
            digest.sha256_hex,
            ContentHash::compute(&file.bytes).to_hex()
        );
    }
    let replay_hash = ContentHash::compute(
        &serde_json::to_vec(&run.result.nondeterminism_trace).expect("trace serializes"),
    )
    .to_hex();
    assert_eq!(bundle.repro_lock.replay.replay_pointer, replay_hash);
    assert_eq!(bundle.repro_lock.replay.trace_id, run.result.trace_id);
    assert!(!bundle.repro_lock.determinism.allow_wall_clock);
}

/// The use certificate records the positive over-approximation: the run-input
/// binding ingressed, the sensitive dataset did not, and the audited sink is
/// listed as potentially reached via its Allowed edge.
#[test]
fn use_certificate_records_positive_dependencies() {
    let run = completed_run();
    let bundle = emit(&run);

    let ingressed: Vec<_> = bundle
        .use_certificate
        .inputs_bound
        .iter()
        .filter(|record| record.ingressed)
        .collect();
    assert_eq!(ingressed.len(), 1);
    assert_eq!(ingressed[0].binding_id, "run-source");
    let pii = bundle
        .use_certificate
        .inputs_bound
        .iter()
        .find(|record| record.binding_id == "customer-pii")
        .expect("pii binding recorded");
    assert!(!pii.ingressed);
    assert_eq!(
        bundle.use_certificate.sinks_potentially_reached,
        vec!["audit-log".to_string()]
    );
    assert!(bundle.use_certificate.instructions_executed > 0);
}
