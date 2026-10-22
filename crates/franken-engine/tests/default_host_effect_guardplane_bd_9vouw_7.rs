//! Default live host-effect guardplane coverage (bd-9vouw.7).
//!
//! Instruction heuristics are a separate policy choice. Ordinary executions
//! still observe the real capability decision before an external effect.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::{
    HookAction, InterpreterConfig, InterpreterError, LaneChoice, LaneRouter, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::expected_loss_selector::LossMatrix;
use frankenengine_engine::guardplane_adapter::{
    GuardplaneAdapter, GuardplaneExtensionContext, GuardplaneOperation,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{CapabilityTag, Ir3Instruction, Ir3Module, RegRange};
use frankenengine_engine::runtime_config::RuntimeConfig;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_extension_host::host_io::{
    EnvironmentSnapshotHostIo, HostIoRecorder, InMemoryHostIoTranscript,
};

fn package(source: &str, metadata: &[(&str, &str)]) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "default-host-guard".to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec!["builtin".to_string(), "console".to_string()],
        version: "1.0.0".to_string(),
        metadata: metadata
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
    }
}

#[test]
fn default_and_false_flags_keep_live_signed_host_observations_in_both_lanes() {
    let metadata_cases: &[&[(&str, &str)]] = &[
        &[],
        &[("guardplane.enable_instruction_hooks", "false")],
        &[("capability_witness.enable_hooks", "false")],
        &[("capability_witness.trust_level", "signed")],
    ];
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for metadata in metadata_cases {
            let mut orchestrator = ExecutionOrchestrator::new_lab(OrchestratorConfig {
                force_lane: Some(lane),
                ..OrchestratorConfig::default()
            });
            let trusted_identity = orchestrator.evidence_verification_identity();
            let result = orchestrator
                .execute(&package("console.log('observed');", metadata))
                .expect("an ordinary authorized console effect must complete");
            assert_eq!(result.console_output.len(), 1);
            assert_eq!(result.console_output[0].message, "observed");
            let primary = &result.evidence_entries[0];
            assert_eq!(
                primary.metadata.get("guardplane_hook_enabled").map(String::as_str),
                Some("true")
            );
            assert_eq!(
                primary.metadata.get("guardplane_hook_scope").map(String::as_str),
                Some("host_effects")
            );
            assert!(!primary.metadata.contains_key("hook_requested_action"));
            let effects: Vec<_> = result
                .evidence_entries
                .iter()
                .filter(|entry| {
                    entry.metadata.get("guardplane_operation").map(String::as_str)
                        == Some("hostcall")
                })
                .collect();
            assert_eq!(effects.len(), 1, "{lane:?}: {metadata:?}");
            assert_eq!(
                effects[0].metadata.get("guardplane_hostcall_capability").map(String::as_str),
                Some("console:log")
            );
            assert_eq!(
                effects[0].metadata.get("guardplane_hostcall_allowed").map(String::as_str),
                Some("true")
            );
            assert_eq!(
                effects[0].metadata.get("guardplane_action").map(String::as_str),
                Some("allow")
            );
            for entry in &result.evidence_entries {
                entry
                    .verify_with_trusted_identity(&trusted_identity)
                    .expect("the host observation is signed by the configured authority");
            }
            result
                .evidence_chain_receipt
                .verify_exact_batch(
                    &result.evidence_entries,
                    &trusted_identity,
                    orchestrator.evidence_ledger_id(),
                    &result.trace_id,
                    0,
                    None,
                )
                .expect("the default host observations are in the authenticated run chain");
        }
    }
}

#[test]
fn default_monitoring_preserves_symbol_utf16_and_ordinary_instruction_semantics() {
    let source = r#"
        const key = Symbol.iterator;
        function f() { return 1; }
        f[key] = 9;
        f["\ud800"] = 7;
        const o = { process: 3, require: 4, module: 5 };
        let total = o.process + o.require + o.module;
        for (const n of [1, 2, 3]) { total += n; }
        const iteratorMethod = "ab"[key];
        const large = new Array(1000);
        total + f[key] + f["\ud800"] +
            (typeof iteratorMethod === "function" ? 1 : 0) + large.length;
    "#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut orchestrator = ExecutionOrchestrator::new_lab(OrchestratorConfig {
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        });
        let result = orchestrator
            .execute(&package(source, &[]))
            .expect("effects-only hooks must not impose the legacy property-key ABI");
        assert_eq!(result.execution_value, "1035", "{lane:?}");
        assert_eq!(
            result.evidence_entries[0]
                .metadata
                .get("guardplane_hook_decisions")
                .map(String::as_str),
            Some("0"),
            "pure instructions must not create per-instruction risk records"
        );
        assert!(!result.evidence_entries[0].metadata.contains_key("hook_requested_action"));
    }
}

#[test]
fn declared_capability_breadth_does_not_contain_an_authorized_effect() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut input = package("console.log('broad-authority');", &[]);
        input.capabilities.extend(
            [
                "vm_dispatch",
                "heap_allocate",
                "gc_invoke",
                "ir_lowering",
                "policy_read",
                "policy_write",
                "evidence_emit",
                "decision_invoke",
                "network_egress",
                "lease_management",
                "idempotency_derive",
            ]
            .into_iter()
            .map(str::to_string),
        );
        let mut orchestrator = ExecutionOrchestrator::new_lab(OrchestratorConfig {
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        });
        let result = orchestrator.execute(&input).expect("authorized effect");
        assert_eq!(result.console_output.len(), 1, "{lane:?}");
        assert_eq!(result.console_output[0].message, "broad-authority");
        assert!(!result.evidence_entries[0].metadata.contains_key("hook_requested_action"));
        // Post-execution policy may still consider the declared authority.
        // The live hook must not treat declaration alone as an attempted abuse.
        assert!(result.evidence_entries.iter().any(|entry| {
            entry.metadata.get("guardplane_hostcall_capability").map(String::as_str)
                == Some("console:log")
                && entry.metadata.get("guardplane_action").map(String::as_str) == Some("allow")
        }));
    }
}

#[test]
fn effects_only_policy_preserves_real_authority_and_stops_witness_denied_effects() {
    let mut module = Ir3Module::new(ContentHash::compute(b"default-env-guard"), "default-env-guard");
    module.constant_pool = vec!["KEY".into()];
    module.instructions = vec![
        Ir3Instruction::LoadStr { dst: 0, pool_index: 0 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("env:read".into()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Return { value: 1 },
    ];
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for (authorized, witness_denied) in [(true, false), (true, true), (false, false)] {
            let mut grants = BTreeSet::from([
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
            ]);
            if authorized {
                grants.insert(RuntimeCapability::EnvRead);
            }
            let mut deterministic = InterpreterConfig::quickjs_defaults();
            deterministic.granted_capabilities = grants.clone();
            let mut throughput = InterpreterConfig::v8_defaults();
            throughput.granted_capabilities = grants;
            let mut router = LaneRouter::with_configs(deterministic, throughput);
            let transcript = Arc::new(InMemoryHostIoTranscript::recording());
            let recorder: Arc<dyn HostIoRecorder> = transcript.clone();
            let provider = EnvironmentSnapshotHostIo::new(BTreeMap::from([(
                "KEY".to_string(),
                "secret-value".to_string(),
            )]))
            .expect("bounded explicit host snapshot");
            router.set_host_io(Arc::new(provider), Some(recorder));
            // A claimed grant is not a live capability. It must not authorize
            // the final case, whose real interpreter grant set lacks EnvRead.
            let mut context = GuardplaneExtensionContext::new(
                "default-env-guard",
                BTreeSet::from(["env_read".to_string()]),
                BTreeMap::new(),
            );
            context.required_capabilities.insert("env_read".to_string());
            if witness_denied {
                context.denied_capabilities.insert("env_read".to_string());
            }
            let adapter = Arc::new(GuardplaneAdapter::host_effects_from_runtime_config(
                context,
                LossMatrix::balanced(),
                &RuntimeConfig::default(),
                SecurityEpoch::from_raw(1),
            ));
            assert!(!adapter.instruction_hooks_enabled());
            let result = router.execute_with_hook(
                &module,
                "default-env-guard",
                Some(lane),
                Some(adapter.clone()),
            );
            let records = adapter.decision_records();
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].operation,
                GuardplaneOperation::Hostcall {
                    capability: "env:read".to_string(),
                    allowed: authorized,
                }
            );
            if !authorized {
                assert!(matches!(result, Err(InterpreterError::CapabilityDenied { .. })));
                assert!(transcript.entries().is_empty(), "no unauthorized provider call");
            } else if witness_denied {
                let result = result.expect("containment stays a structured execution result");
                assert_ne!(records[0].action, HookAction::Allow);
                assert_eq!(result.result.requested_hook_action, Some(records[0].action.clone()));
                assert!(transcript.entries().is_empty(), "contain before the snapshot read");
            } else {
                let result = result.expect("authorized snapshot read");
                assert_eq!(records[0].action, HookAction::Allow);
                assert_eq!(result.result.value, Value::str("secret-value"));
                assert_eq!(result.result.completion_label, Label::Secret);
                assert_eq!(transcript.entries().len(), 1);
            }
        }
    }
}

#[test]
fn explicit_instruction_policy_retains_its_scope_and_containment() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut orchestrator = ExecutionOrchestrator::new_lab(OrchestratorConfig {
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        });
        let result = orchestrator
            .execute(&package(
                "const object = { value: 1 }; object.value; console.log('unreachable');",
                &[
                    ("guardplane.enable_instruction_hooks", "true"),
                    ("capability_witness.trust_level", "suspicious"),
                    ("capability_witness.confidence_millionths", "200000"),
                    ("capability_witness.denied_capabilities", "object.property"),
                ],
            ))
            .expect("full instruction containment remains a structured result");
        assert!(result.console_output.is_empty());
        assert!(result.evidence_entries[0].metadata.contains_key("hook_requested_action"));
        assert_eq!(
            result.evidence_entries[0].metadata.get("guardplane_hook_scope").map(String::as_str),
            Some("instructions_and_host_effects")
        );
    }
}
