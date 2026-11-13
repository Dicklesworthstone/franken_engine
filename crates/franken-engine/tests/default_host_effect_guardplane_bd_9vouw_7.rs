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
use frankenengine_engine::containment_executor::{ContainmentError, ContainmentState};
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use frankenengine_engine::expected_loss_selector::{ContainmentAction, LossMatrix};
use frankenengine_engine::guardplane_adapter::{
    GuardplaneAdapter, GuardplaneExtensionContext, GuardplaneOperation,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{CapabilityTag, Ir3Instruction, Ir3Module, RegRange};
use frankenengine_engine::runtime_config::RuntimeConfig;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::storage_adapter::{
    BatchPutEntry, CompareAndSwapOutcome, EventContext, InMemoryStorageAdapter, MigrationReceipt,
    StorageAdapter, StorageError, StorageEvent, StoreKind, StoreQuery, StoreRecord,
};
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
                primary
                    .metadata
                    .get("guardplane_hook_enabled")
                    .map(String::as_str),
                Some("true")
            );
            assert_eq!(
                primary
                    .metadata
                    .get("guardplane_hook_scope")
                    .map(String::as_str),
                Some("host_effects")
            );
            assert!(!primary.metadata.contains_key("hook_requested_action"));
            let effects: Vec<_> = result
                .evidence_entries
                .iter()
                .filter(|entry| {
                    entry
                        .metadata
                        .get("guardplane_operation")
                        .map(String::as_str)
                        == Some("hostcall")
                })
                .collect();
            assert_eq!(effects.len(), 1, "{lane:?}: {metadata:?}");
            assert_eq!(
                effects[0]
                    .metadata
                    .get("guardplane_hostcall_capability")
                    .map(String::as_str),
                Some("console:log")
            );
            assert_eq!(
                effects[0]
                    .metadata
                    .get("guardplane_hostcall_allowed")
                    .map(String::as_str),
                Some("true")
            );
            assert_eq!(
                effects[0]
                    .metadata
                    .get("guardplane_action")
                    .map(String::as_str),
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
        assert!(
            !result.evidence_entries[0]
                .metadata
                .contains_key("hook_requested_action")
        );
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
        assert!(
            !result.evidence_entries[0]
                .metadata
                .contains_key("hook_requested_action")
        );
        // Post-execution policy may still consider the declared authority.
        // The live hook must not treat declaration alone as an attempted abuse.
        assert!(result.evidence_entries.iter().any(|entry| {
            entry
                .metadata
                .get("guardplane_hostcall_capability")
                .map(String::as_str)
                == Some("console:log")
                && entry.metadata.get("guardplane_action").map(String::as_str) == Some("allow")
        }));
    }
}

#[test]
fn effects_only_policy_preserves_real_authority_and_stops_witness_denied_effects() {
    let mut module = Ir3Module::new(
        ContentHash::compute(b"default-env-guard"),
        "default-env-guard",
    );
    module.constant_pool = vec!["KEY".into()];
    module.instructions = vec![
        Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 0,
        },
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
                assert!(matches!(
                    result,
                    Err(InterpreterError::CapabilityDenied { .. })
                ));
                assert!(
                    transcript.entries().is_empty(),
                    "no unauthorized provider call"
                );
            } else if witness_denied {
                let result = result.expect("containment stays a structured execution result");
                assert_ne!(records[0].action, HookAction::Allow);
                assert_eq!(
                    result.result.requested_hook_action,
                    Some(records[0].action.clone())
                );
                assert!(
                    transcript.entries().is_empty(),
                    "contain before the snapshot read"
                );
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
        assert!(
            result.evidence_entries[0]
                .metadata
                .contains_key("hook_requested_action")
        );
        assert_eq!(
            result.evidence_entries[0]
                .metadata
                .get("guardplane_hook_scope")
                .map(String::as_str),
            Some("instructions_and_host_effects")
        );
    }
}

fn quarantine_orchestrator(lane: LaneChoice) -> ExecutionOrchestrator {
    // A configured high-risk prior exercises the real default host-effect
    // decision path, without test-only action overrides or instruction hooks.
    let mut runtime = RuntimeConfig::default();
    runtime.guardplane.priors.benign_millionths = 100;
    runtime.guardplane.priors.anomalous_millionths = 100;
    runtime.guardplane.priors.malicious_millionths = 999_700;
    runtime.guardplane.priors.unknown_millionths = 100;
    runtime.validate().expect("valid high-risk prior");
    ExecutionOrchestrator::new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        },
        runtime,
    )
}

fn storage_context() -> EventContext {
    EventContext::new(
        "quarantine-test",
        "quarantine-decision",
        "quarantine-policy",
    )
    .unwrap()
}

fn stored_quarantine(orchestrator: &mut ExecutionOrchestrator) -> StoreRecord {
    let mut records = orchestrator
        .storage_adapter_mut()
        .query(
            StoreKind::PolicyCache,
            &StoreQuery {
                key_prefix: Some("quarantine/v1/".to_string()),
                ..StoreQuery::default()
            },
            &storage_context(),
        )
        .expect("read quarantine authority");
    assert_eq!(records.len(), 1, "exactly one identity was quarantined");
    records.pop().unwrap()
}

fn contain_at_host_effect(orchestrator: &mut ExecutionOrchestrator) -> StoreRecord {
    let result = orchestrator
        .execute(&package("console.log('must-not-run');", &[]))
        .expect("quarantine completes only after committing its admission barrier");
    assert_eq!(result.containment_action, ContainmentAction::Quarantine);
    let receipt = result
        .containment_receipt
        .as_ref()
        .expect("quarantine receipt");
    assert_eq!(receipt.new_state, ContainmentState::Quarantined);
    assert!(receipt.success && receipt.verify_integrity());
    assert!(
        result.console_output.is_empty(),
        "contain before the host effect"
    );
    assert!(result.host_effect_transcript.is_empty());
    assert!(result.host_effect_journal.is_empty());
    let record = stored_quarantine(orchestrator);
    let payload: serde_json::Value = serde_json::from_slice(&record.value).unwrap();
    assert_eq!(payload["schema_version"], 1);
    assert_eq!(payload["trace_id"], result.trace_id);
    assert_eq!(payload["receipt"], serde_json::to_value(receipt).unwrap());
    record
}

fn assert_quarantined_before_execution(
    orchestrator: &mut ExecutionOrchestrator,
    input: &ExtensionPackage,
) {
    let attempts_before = orchestrator.execution_count();
    let error = orchestrator
        .execute(input)
        .expect_err("quarantine must survive admission");
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::Containment(ContainmentError::AlreadyContained {
                extension_id,
                current_state: ContainmentState::Quarantined,
            }) if extension_id == &input.extension_id
        ),
        "{error}"
    );
    assert_eq!(orchestrator.execution_count(), attempts_before);
    assert!(orchestrator.last_failed_trace_id().is_none());
    assert!(orchestrator.last_failed_console_output().is_empty());
    assert!(orchestrator.last_failed_host_effect_journal().is_empty());
}

fn storage_with_record(record: &StoreRecord) -> InMemoryStorageAdapter {
    let mut storage = InMemoryStorageAdapter::new();
    storage
        .put(
            record.store,
            record.key.clone(),
            record.value.clone(),
            record.metadata.clone(),
            &storage_context(),
        )
        .unwrap();
    storage
}

fn assert_failed_persistence_retains_local_quarantine_receipt(
    orchestrator: &ExecutionOrchestrator,
    error: &OrchestratorError,
) {
    let trace_id = orchestrator
        .last_failed_trace_id()
        .expect("failed run trace");
    let staged = error
        .uncommitted_evidence_chain()
        .expect("the signed run evidence must survive a later persistence failure");
    let receipt = staged
        .containment_receipt
        .as_ref()
        .expect("the completed local containment transition must retain its receipt");
    assert_eq!(receipt.action, ContainmentAction::Quarantine);
    assert_eq!(receipt.target_extension_id, "default-host-guard");
    assert_eq!(receipt.new_state, ContainmentState::Quarantined);
    assert!(receipt.success && receipt.verify_integrity());
    assert_eq!(receipt.evidence_refs, [trace_id.to_string()]);
    assert!(
        staged.saga_id.is_none(),
        "persistence failed before saga creation"
    );
    assert!(
        staged
            .quarantine_persistence_error
            .as_ref()
            .is_some_and(|error| !error.is_empty())
    );
    staged
        .verify_with_context(
            &orchestrator.evidence_verification_identity(),
            orchestrator.evidence_chain_instance_id(),
            orchestrator.evidence_ledger_id(),
            trace_id,
            0,
            None,
        )
        .expect("failure evidence and the local receipt retain their exact signed linkage");

    let mut missing_failure = staged.clone();
    missing_failure.quarantine_persistence_error = None;
    let mut blank_failure = staged.clone();
    blank_failure.quarantine_persistence_error = Some(" ".to_string());
    let mut missing_receipt = staged.clone();
    missing_receipt.containment_receipt = None;
    let mut invented_saga = staged.clone();
    invented_saga.saga_id = Some(format!("{trace_id}:saga"));
    for malformed in [
        missing_failure,
        blank_failure,
        missing_receipt,
        invented_saga,
    ] {
        assert!(
            malformed
                .verify_with_context(
                    &orchestrator.evidence_verification_identity(),
                    orchestrator.evidence_chain_instance_id(),
                    orchestrator.evidence_ledger_id(),
                    trace_id,
                    0,
                    None,
                )
                .is_err(),
            "a partial lifecycle must not be accepted as successful durability or saga creation"
        );
    }
}

#[test]
fn quarantine_admission_survives_a_new_orchestrator_and_unrelated_allowed_execution() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut original = quarantine_orchestrator(lane);
        let record = contain_at_host_effect(&mut original);
        assert_quarantined_before_execution(&mut original, &package("42;", &[]));

        // Reconstruct the adapter from its committed record. The on-disk
        // reopen test below exercises the durable backend under its feature.
        let mut restarted = ExecutionOrchestrator::new_lab(OrchestratorConfig {
            force_lane: Some(lane),
            policy_id: "a-later-policy".to_string(),
            ..OrchestratorConfig::default()
        });
        restarted.set_storage_adapter(storage_with_record(&record));
        let changed_source = package("console.log('resurrected');", &[]);
        assert_quarantined_before_execution(&mut restarted, &changed_source);
        // Admission precedes source ingestion, not just external dispatch.
        assert_quarantined_before_execution(&mut restarted, &package("const = ;", &[]));

        let mut unrelated = changed_source.clone();
        unrelated.extension_id = "another-extension".to_string();
        let result = restarted
            .execute(&unrelated)
            .expect("unrelated identity remains usable");
        assert_eq!(result.console_output[0].message, "resurrected");
        assert_eq!(stored_quarantine(&mut restarted), record);
        assert_quarantined_before_execution(&mut restarted, &changed_source);
    }
}

#[cfg(feature = "sibling-persistence")]
#[test]
fn quarantine_survives_state_db_reopen_and_is_seen_by_an_already_open_orchestrator() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let directory = tempfile::tempdir().expect("quarantine database directory");
        let path = directory.path().join("containment.db");
        let record;
        {
            let mut original = quarantine_orchestrator(lane);
            original
                .open_state_db(&path)
                .expect("open durable authority");
            let mut already_open = ExecutionOrchestrator::new_lab(OrchestratorConfig {
                force_lane: Some(lane),
                ..OrchestratorConfig::default()
            });
            already_open
                .open_state_db(&path)
                .expect("open second reader");
            // Establish a successful admission before the other instance
            // commits quarantine, so a cached 'not contained' would fail.
            already_open.execute(&package("1 + 1;", &[])).unwrap();
            record = contain_at_host_effect(&mut original);
            assert_quarantined_before_execution(
                &mut already_open,
                &package("console.log('must-stay-blocked');", &[]),
            );
        }
        let mut reopened = ExecutionOrchestrator::new_lab(OrchestratorConfig {
            force_lane: Some(lane),
            policy_id: "policy-after-restart".to_string(),
            ..OrchestratorConfig::default()
        });
        reopened
            .open_state_db(&path)
            .expect("reopen durable authority");
        assert_quarantined_before_execution(
            &mut reopened,
            &package("console.log('must-stay-blocked');", &[]),
        );
        assert_eq!(stored_quarantine(&mut reopened), record);
    }
}

#[test]
fn corrupt_or_incompatible_quarantine_records_fail_closed_before_source_ingestion() {
    let mut original = quarantine_orchestrator(LaneChoice::QuickJs);
    let record = contain_at_host_effect(&mut original);
    let payload: serde_json::Value = serde_json::from_slice(&record.value).unwrap();
    let mut invalid_records = vec![b"not JSON".to_vec()];
    for field in ["schema_version", "trace_id", "policy_id", "receipt"] {
        let mut invalid = payload.clone();
        invalid.as_object_mut().unwrap().remove(field);
        invalid_records.push(serde_json::to_vec(&invalid).unwrap());
    }
    let mut future_version = payload.clone();
    future_version["schema_version"] = 2.into();
    invalid_records.push(serde_json::to_vec(&future_version).unwrap());
    let mut forged_identity = payload.clone();
    forged_identity["receipt"]["target_extension_id"] = "somebody-else".into();
    invalid_records.push(serde_json::to_vec(&forged_identity).unwrap());
    let mut altered_receipt = payload.clone();
    altered_receipt["receipt"]["timestamp_ns"] = 999.into();
    invalid_records.push(serde_json::to_vec(&altered_receipt).unwrap());
    let mut missing_linkage = payload;
    missing_linkage["trace_id"] = "unrelated-trace".into();
    invalid_records.push(serde_json::to_vec(&missing_linkage).unwrap());

    for value in invalid_records {
        let mut invalid = record.clone();
        invalid.value = value;
        let mut orchestrator = ExecutionOrchestrator::new_lab(OrchestratorConfig::default());
        orchestrator.set_storage_adapter(storage_with_record(&invalid));
        let error = orchestrator
            .execute(&package("const = ;", &[]))
            .unwrap_err();
        assert!(
            matches!(
                error.primary_error(),
                OrchestratorError::Containment(ContainmentError::Internal { detail })
                    if detail.starts_with("invalid durable quarantine record:")
            ),
            "{error}"
        );
        assert_eq!(orchestrator.execution_count(), 0);
        assert!(orchestrator.last_failed_trace_id().is_none());
        assert!(orchestrator.last_failed_console_output().is_empty());
        assert_eq!(stored_quarantine(&mut orchestrator), invalid);
    }
}

#[test]
fn a_rejected_quarantine_commit_returns_failure_and_keeps_the_local_identity_blocked() {
    let mut orchestrator = quarantine_orchestrator(LaneChoice::QuickJs);
    orchestrator.set_storage_adapter(InMemoryStorageAdapter::new().with_fail_writes(true));
    let error = orchestrator
        .execute(&package("console.log('must-not-run');", &[]))
        .expect_err("a rejected durable commit cannot report successful quarantine");
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::Containment(ContainmentError::Internal { detail })
                if detail.starts_with("durable quarantine commit failed:")
        ),
        "{error}"
    );
    assert_failed_persistence_retains_local_quarantine_receipt(&orchestrator, &error);
    assert!(orchestrator.last_failed_console_output().is_empty());
    assert!(orchestrator.last_failed_host_effect_journal().is_empty());
    // Recovering the backend cannot resurrect the locally contained identity.
    orchestrator.set_storage_adapter(InMemoryStorageAdapter::new());
    assert_quarantined_before_execution(&mut orchestrator, &package("42;", &[]));
}

/// Faults only the storage boundary; execution, guardplane decisions, receipt
/// generation, and containment still use the production pipeline.
#[derive(Default)]
struct QuarantineStorageFaults {
    inner: InMemoryStorageAdapter,
    reject_reads: bool,
    // Publish another writer's barrier between admission and our atomic insert.
    concurrent_quarantine: Option<StoreRecord>,
}

impl StorageAdapter for QuarantineStorageFaults {
    fn backend_name(&self) -> &'static str {
        self.inner.backend_name()
    }

    fn current_schema_version(&self) -> u32 {
        self.inner.current_schema_version()
    }

    fn ensure_schema_version(&self, expected: u32) -> Result<(), StorageError> {
        self.inner.ensure_schema_version(expected)
    }

    fn migrate_to(&mut self, target: u32) -> Result<MigrationReceipt, StorageError> {
        self.inner.migrate_to(target)
    }

    fn put(
        &mut self,
        store: StoreKind,
        key: String,
        value: Vec<u8>,
        metadata: BTreeMap<String, String>,
        context: &EventContext,
    ) -> Result<StoreRecord, StorageError> {
        self.inner.put(store, key, value, metadata, context)
    }

    fn compare_and_swap(
        &mut self,
        store: StoreKind,
        key: String,
        expected_revision: Option<u64>,
        value: Vec<u8>,
        metadata: BTreeMap<String, String>,
        context: &EventContext,
    ) -> Result<CompareAndSwapOutcome, StorageError> {
        if store == StoreKind::PolicyCache && key.starts_with("quarantine/v1/") {
            assert_eq!(
                expected_revision, None,
                "quarantine must never replace an authority row"
            );
            if let Some(existing) = self.concurrent_quarantine.take() {
                assert_eq!(existing.store, store);
                assert_eq!(existing.key, key);
                self.inner.put(
                    store,
                    existing.key,
                    existing.value,
                    existing.metadata,
                    context,
                )?;
            }
        }
        self.inner
            .compare_and_swap(store, key, expected_revision, value, metadata, context)
    }

    fn get(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<Option<StoreRecord>, StorageError> {
        if self.reject_reads && store == StoreKind::PolicyCache {
            return Err(StorageError::BackendUnavailable {
                backend: "quarantine-test".to_string(),
                detail: "admission authority is temporarily unreadable".to_string(),
            });
        }
        self.inner.get(store, key, context)
    }

    fn query(
        &mut self,
        store: StoreKind,
        query: &StoreQuery,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError> {
        self.inner.query(store, query, context)
    }

    fn delete(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<bool, StorageError> {
        self.inner.delete(store, key, context)
    }

    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: Vec<BatchPutEntry>,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError> {
        self.inner.put_batch(store, entries, context)
    }

    fn events(&self) -> &[StorageEvent] {
        self.inner.events()
    }
}

#[test]
fn unreadable_quarantine_authority_blocks_admission_before_source_ingestion() {
    let mut orchestrator = ExecutionOrchestrator::new_lab(OrchestratorConfig::default());
    orchestrator.set_storage_adapter(QuarantineStorageFaults {
        reject_reads: true,
        ..QuarantineStorageFaults::default()
    });
    let error = orchestrator
        .execute(&package("const = ;", &[]))
        .unwrap_err();
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::Containment(ContainmentError::Internal { detail })
                if detail.starts_with("durable quarantine read failed:")
        ),
        "{error}"
    );
    assert_eq!(orchestrator.execution_count(), 0);
    assert!(orchestrator.last_failed_trace_id().is_none());
    assert!(orchestrator.last_failed_console_output().is_empty());
    assert!(orchestrator.last_failed_host_effect_journal().is_empty());
}

#[test]
fn racing_quarantine_commit_preserves_the_first_barrier_and_rejects_corruption() {
    let mut original = quarantine_orchestrator(LaneChoice::QuickJs);
    let record = contain_at_host_effect(&mut original);
    for corrupt in [false, true] {
        let mut competing_record = record.clone();
        if corrupt {
            competing_record.value = b"corrupt authority".to_vec();
        }
        let mut orchestrator = quarantine_orchestrator(LaneChoice::V8);
        orchestrator.set_storage_adapter(QuarantineStorageFaults {
            concurrent_quarantine: Some(competing_record.clone()),
            ..QuarantineStorageFaults::default()
        });
        let outcome = orchestrator.execute(&package("console.log('later-attempt');", &[]));
        if corrupt {
            let error = outcome.expect_err("a racing corrupt barrier must not be replaced");
            assert!(
                matches!(
                    error.primary_error(),
                    OrchestratorError::Containment(ContainmentError::Internal { detail })
                        if detail.starts_with("invalid durable quarantine record:")
                ),
                "{error}"
            );
            assert_failed_persistence_retains_local_quarantine_receipt(&orchestrator, &error);
        } else {
            let result = outcome.expect("an existing valid quarantine is already durable");
            assert_eq!(result.containment_action, ContainmentAction::Quarantine);
            assert!(result.console_output.is_empty());
        }
        assert_eq!(stored_quarantine(&mut orchestrator), competing_record);
        assert!(orchestrator.last_failed_console_output().is_empty());
        assert_quarantined_before_execution(&mut orchestrator, &package("42;", &[]));
    }
}
