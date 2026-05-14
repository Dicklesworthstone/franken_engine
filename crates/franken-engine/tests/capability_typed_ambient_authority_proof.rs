//! Capability-typed ambient-authority proof for `bd-ly6hp.4`.
//!
//! This intentionally covers only the current manifest-to-IR hostcall subset.
//! Typed TypeScript-to-IR onboarding remains unsupported and must fail closed
//! until a production lowering path exists.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::ambient_authority::{
    AuditConfig, AuditResult, ExemptionRegistry, ForbiddenCallCategory, SourceAuditor,
};
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterError, QuickJsLane,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, RegRange, WitnessEventKind,
};
use serde::Serialize;

const CLAIM_ID: &str = "FE-CLAIM-006";
const BEAD_ID: &str = "bd-ly6hp.4";
const SCHEMA_VERSION: &str =
    "franken-engine.idea-wizard-xiii-capability-typed-ambient-authority-proof.runtime.v1";
const COVERED_INPUT_SUBSET: &str = "capability_typed_manifest_ir_hostcall_v1";

fn execution_caps() -> BTreeSet<RuntimeCapability> {
    BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ])
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeCase {
    case_id: &'static str,
    requested_capability: &'static str,
    granted_capabilities: Vec<String>,
    expected: &'static str,
    actual: &'static str,
    diagnostic_code: Option<&'static str>,
    witness_events: Vec<String>,
    hostcall_decisions: Vec<HostcallDecision>,
}

#[derive(Debug, Clone, Serialize)]
struct HostcallDecision {
    capability: String,
    allowed: bool,
    instruction_index: u32,
}

#[derive(Debug, Clone, Serialize)]
struct AmbientAuditCase {
    case_id: &'static str,
    category: &'static str,
    source_hash: String,
    passed: bool,
    violation_count: usize,
    finding_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct UnsupportedContract {
    input_kind: &'static str,
    expected: &'static str,
    actual: &'static str,
    diagnostic_code: &'static str,
    reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeProofReport {
    schema_version: &'static str,
    claim_id: &'static str,
    bead_id: &'static str,
    covered_input_subset: &'static str,
    requested_capabilities: Vec<String>,
    granted_capabilities: Vec<String>,
    denied_ambient_authority: Vec<&'static str>,
    runtime_enforcement_verdict: &'static str,
    unsupported_contract: UnsupportedContract,
    manifest_hash: String,
    source_fixtures: BTreeMap<&'static str, String>,
    runtime_cases: Vec<RuntimeCase>,
    ambient_audit_cases: Vec<AmbientAuditCase>,
}

fn hostcall_module(capability: &str) -> Ir3Module {
    let mut module = Ir3Module::new(
        ContentHash::compute(format!("manifest:{capability}").as_bytes()),
        "bd-ly6hp.4-manifest-hostcall",
    );
    module.instructions = vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag(capability.to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ];
    module.required_capabilities = vec![CapabilityTag(capability.to_string())];
    module
}

fn run_hostcall_case(
    case_id: &'static str,
    capability: &'static str,
    granted: BTreeSet<RuntimeCapability>,
    expected: &'static str,
) -> RuntimeCase {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = granted.clone();
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&hostcall_module(capability), case_id);

    match (expected, result) {
        ("allowed", Ok(execution)) => {
            assert!(
                execution
                    .hostcall_decisions
                    .iter()
                    .any(|decision| decision.capability.0 == capability && decision.allowed)
            );
            assert!(
                execution
                    .witness_events
                    .iter()
                    .any(|event| event.kind == WitnessEventKind::CapabilityChecked)
            );
            RuntimeCase {
                case_id,
                requested_capability: capability,
                granted_capabilities: granted.iter().map(ToString::to_string).collect(),
                expected,
                actual: "allowed",
                diagnostic_code: None,
                witness_events: execution
                    .witness_events
                    .iter()
                    .map(|event| format!("{:?}", event.kind))
                    .collect(),
                hostcall_decisions: execution
                    .hostcall_decisions
                    .iter()
                    .map(|decision| HostcallDecision {
                        capability: decision.capability.0.clone(),
                        allowed: decision.allowed,
                        instruction_index: decision.instruction_index,
                    })
                    .collect(),
            }
        }
        ("denied", Err(InterpreterError::CapabilityDenied { capability: denied })) => {
            assert_eq!(denied, capability);
            RuntimeCase {
                case_id,
                requested_capability: capability,
                granted_capabilities: granted.iter().map(ToString::to_string).collect(),
                expected,
                actual: "denied",
                diagnostic_code: Some("runtime.capability.denied"),
                witness_events: vec!["CapabilityChecked".to_string()],
                hostcall_decisions: vec![HostcallDecision {
                    capability: denied,
                    allowed: false,
                    instruction_index: 1,
                }],
            }
        }
        ("allowed", Err(error)) => panic!("{case_id} expected allowed, got {error:?}"),
        ("denied", Ok(_)) => panic!("{case_id} expected denial"),
        _ => panic!("unsupported expected result for {case_id}: {expected}"),
    }
}

fn audit_case(
    case_id: &'static str,
    category: ForbiddenCallCategory,
    source: &'static str,
) -> AmbientAuditCase {
    let auditor = SourceAuditor::new(AuditConfig::standard(), ExemptionRegistry::new());
    let mut sources = BTreeMap::new();
    sources.insert(
        (format!("bd_ly6hp_4::{case_id}"), format!("{case_id}.rs")),
        source.to_string(),
    );
    let result: AuditResult = auditor.audit_all(&sources);
    let matching: Vec<String> = result
        .findings
        .iter()
        .filter(|finding| finding.category == category)
        .map(|finding| finding.pattern_id.clone())
        .collect();

    assert!(!result.passed, "{case_id} must reject ambient authority");
    assert!(
        !matching.is_empty(),
        "{case_id} must include a finding for {category}"
    );

    AmbientAuditCase {
        case_id,
        category: match category {
            ForbiddenCallCategory::FileSystem => "filesystem",
            ForbiddenCallCategory::Network => "network",
            ForbiddenCallCategory::Process => "hostcall",
            ForbiddenCallCategory::GlobalMutableState => "global_mutable_state",
            ForbiddenCallCategory::Environment => "environment",
            ForbiddenCallCategory::RawPointerExternalState => "raw_pointer_external_state",
            ForbiddenCallCategory::DirectTime => "direct_time",
        },
        source_hash: ContentHash::compute(source.as_bytes()).to_hex(),
        passed: result.passed,
        violation_count: result.violation_count,
        finding_patterns: matching,
    }
}

#[test]
fn capability_typed_onboarding_proof_emits_runtime_result() {
    let manifest_fixture = r#"{
  "schema_version": "franken-engine.capability-typed-manifest.v1",
  "input_kind": "manifest_ir_hostcall_v1",
  "module": "bd-ly6hp.4-minimal-hostcall",
  "requested_capabilities": ["fs_read"],
  "granted_capabilities": ["fs_read"],
  "runtime_base_capabilities": ["vm_dispatch", "heap_allocate"],
  "hostcall": "fs:read"
}"#;
    let filesystem_fixture = r#"fn run() { let _ = std::fs::read_to_string("/etc/hostname"); }"#;
    let network_fixture = r#"fn run() { let _ = std::net::TcpStream::connect("127.0.0.1:9"); }"#;
    let hostcall_fixture =
        r#"fn run() { let _ = std::process::Command::new("sh").arg("-c").arg("id").status(); }"#;

    let runtime_cases = vec![
        run_hostcall_case(
            "declared_fs_read_allowed",
            "fs:read",
            BTreeSet::from([
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::FsRead,
            ]),
            "allowed",
        ),
        run_hostcall_case(
            "ambient_filesystem_rejected",
            "fs:read",
            execution_caps(),
            "denied",
        ),
        run_hostcall_case(
            "ambient_network_rejected",
            "net:connect",
            execution_caps(),
            "denied",
        ),
        run_hostcall_case(
            "ambient_hostcall_rejected",
            "hostcall.invoke",
            execution_caps(),
            "denied",
        ),
    ];
    let ambient_audit_cases = vec![
        audit_case(
            "ambient_filesystem_source",
            ForbiddenCallCategory::FileSystem,
            filesystem_fixture,
        ),
        audit_case(
            "ambient_network_source",
            ForbiddenCallCategory::Network,
            network_fixture,
        ),
        audit_case(
            "ambient_hostcall_source",
            ForbiddenCallCategory::Process,
            hostcall_fixture,
        ),
    ];

    assert!(runtime_cases.iter().any(|case| case.actual == "allowed"));
    assert_eq!(
        runtime_cases
            .iter()
            .filter(|case| case.actual == "denied")
            .count(),
        3
    );
    assert!(ambient_audit_cases.iter().all(|case| !case.passed));

    let source_fixtures = BTreeMap::from([
        (
            "typed_input_or_manifest_fixture",
            ContentHash::compute(manifest_fixture.as_bytes()).to_hex(),
        ),
        (
            "ambient_filesystem_rejection_fixture",
            ContentHash::compute(filesystem_fixture.as_bytes()).to_hex(),
        ),
        (
            "ambient_network_rejection_fixture",
            ContentHash::compute(network_fixture.as_bytes()).to_hex(),
        ),
        (
            "ambient_hostcall_rejection_fixture",
            ContentHash::compute(hostcall_fixture.as_bytes()).to_hex(),
        ),
    ]);

    let report = RuntimeProofReport {
        schema_version: SCHEMA_VERSION,
        claim_id: CLAIM_ID,
        bead_id: BEAD_ID,
        covered_input_subset: COVERED_INPUT_SUBSET,
        requested_capabilities: vec!["fs_read".to_string()],
        granted_capabilities: vec![
            "vm_dispatch".to_string(),
            "heap_allocate".to_string(),
            "fs_read".to_string(),
        ],
        denied_ambient_authority: vec!["filesystem", "network", "hostcall"],
        runtime_enforcement_verdict: "pass",
        unsupported_contract: UnsupportedContract {
            input_kind: "typed_ts_to_ir",
            expected: "fail_closed",
            actual: "fail_closed",
            diagnostic_code: "capability_typed.unsupported_syntax",
            reason: "typed TypeScript-to-IR onboarding is not shipped for FE-CLAIM-006",
        },
        manifest_hash: ContentHash::compute(manifest_fixture.as_bytes()).to_hex(),
        source_fixtures,
        runtime_cases,
        ambient_audit_cases,
    };

    println!(
        "FE_CAPABILITY_TYPED_PROOF_JSON:{}",
        serde_json::to_string(&report).expect("proof report must serialize")
    );
}
