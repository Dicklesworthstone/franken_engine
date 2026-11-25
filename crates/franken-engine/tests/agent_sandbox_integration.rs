//! Integration tests for the E8.T5 agent-sandbox (bd-fqlfw.8.5): an agent
//! framework declares tool authority in a manifest, runs model-generated code
//! through the real orchestrator with the guardplane armed, and receives the
//! E8 certificate bundle on exit.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[cfg(unix)]
use frankenengine_engine::agent_sandbox::AgentHostIoBudget;
use frankenengine_engine::agent_sandbox::{
    AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION, AgentSandboxError, AgentSandboxManifest,
    AgentSandboxReport, AgentToolGrant, DEFAULT_AGENT_TRUST_LEVEL,
};
#[cfg(unix)]
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::data_contract::{
    DATA_CONTRACT_SCHEMA_VERSION, DEFAULT_DATA_CONTRACT_PURPOSE, DataBinding, DataBindingRole,
    DataContract, RequestedOutputClaim, SinkBinding,
};
use frankenengine_engine::evidence_ledger::LabEvidenceAuthority;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, OrchestratorConfig, OrchestratorResult,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::{ClearanceClass, Label};
use frankenengine_engine::non_use_certificate::{
    CertificateStatus, CertifierInputs, E8_CERTIFIER_PRODUCER_ID, NON_USE_CERTIFICATE_FILE,
    NonUseCertificate, emit_certificate_bundle_lab,
};
#[cfg(unix)]
use frankenengine_extension_host::host_effect_journal::{
    HostEffectJournalAttemptRecord, HostEffectJournalEntry, HostEffectJournalLimits,
    InMemoryHostEffectJournal,
};
#[cfg(unix)]
use frankenengine_extension_host::host_io::{
    FsOperation, HostIoCapability, HostIoControl, HostIoError, HostIoExceptionProvenance,
    HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse, InMemoryHostIoTranscript,
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
        host_io_budget: None,
        network_allowlist: None,
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
    let certificate_authority = LabEvidenceAuthority::deterministic_fixture(
        E8_CERTIFIER_PRODUCER_ID,
        "agent-sandbox-integration-certificate",
        run.result.epoch,
    )
    .expect("lab certificate authority derives");
    let trusted_identity = certificate_authority.verification_identity();
    let bundle = emit_certificate_bundle_lab(&inputs, &certificate_authority)
        .expect("certificate bundle emits on exit");

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
        .verify_with_trusted_identity(&trusted_identity)
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

#[cfg(unix)]
fn host_budget_manifest(budget: AgentHostIoBudget) -> (AgentSandboxManifest, std::path::PathBuf) {
    let root = tempfile::Builder::new()
        .prefix("agent-sandbox-host-budget-")
        .tempdir()
        .expect("native sandbox root")
        .keep();
    let mut manifest = manifest();
    manifest.host_io_root = Some(root.to_str().expect("UTF-8 test path").to_string());
    manifest.host_io_budget = Some(budget);
    manifest
        .tool_grants
        .extend(
            [RuntimeCapability::FsRead, RuntimeCapability::FsWrite].map(|capability| {
                AgentToolGrant {
                    tool_name: capability.as_str().to_string(),
                    capability_tag: capability.as_str().to_string(),
                    description: None,
                }
            }),
        );
    (manifest, root)
}

#[test]
#[cfg(unix)]
fn manifest_host_budget_is_shared_across_provider_clones_before_disk_mutation() {
    let (manifest, root) = host_budget_manifest(AgentHostIoBudget {
        requests: 1,
        request_bytes: 1024,
        max_in_flight: 1,
    });
    let provider = manifest.build_host_io_provider().unwrap().unwrap();
    let first = HostIoRequest::FsWrite {
        path: "output".to_string(),
        data: b"first value".to_vec(),
    };
    assert_eq!(
        provider.perform(&first, &[HostIoCapability::FsWrite]),
        Ok(HostIoResponse::FsWrite { bytes_written: 11 })
    );
    let alias = provider.clone();
    assert_eq!(
        alias.perform(
            &HostIoRequest::FsWrite {
                path: "output".to_string(),
                data: b"replacement".to_vec(),
            },
            &[HostIoCapability::FsWrite],
        ),
        Err(HostIoError::Denied {
            reason: "HOST_IO_REQUEST_BUDGET_EXHAUSTED".to_string(),
        })
    );
    assert_eq!(std::fs::read(root.join("output")).unwrap(), b"first value");
}

#[test]
#[cfg(unix)]
fn manifest_host_budget_counts_utf8_paths_and_payloads_without_spending_refused_work() {
    let (manifest, root) = host_budget_manifest(AgentHostIoBudget {
        requests: 3,
        request_bytes: 7,
        max_in_flight: 1,
    });
    let provider = manifest.build_host_io_provider().unwrap().unwrap();
    // The two-byte path plus six-byte value cannot fit; refusal must happen
    // before creating the file or spending the request's admission credit.
    assert_eq!(
        provider.perform(
            &HostIoRequest::FsWrite {
                path: "é".to_string(),
                data: b"123456".to_vec(),
            },
            &[HostIoCapability::FsWrite],
        ),
        Err(HostIoError::Denied {
            reason: "HOST_IO_REQUEST_BYTES_EXHAUSTED".to_string(),
        })
    );
    assert!(!root.join("é").exists());
    provider
        .perform(
            &HostIoRequest::FsWrite {
                path: "é".to_string(),
                data: b"123".to_vec(),
            },
            &[HostIoCapability::FsWrite],
        )
        .unwrap();
    // Five write-request bytes plus two read-request bytes use the allowance
    // exactly. The returned three bytes are response bytes, not a new debit.
    assert_eq!(
        provider.perform(
            &HostIoRequest::FsRead {
                path: "é".to_string(),
            },
            &[HostIoCapability::FsRead],
        ),
        Ok(HostIoResponse::FsRead {
            bytes: b"123".to_vec(),
        })
    );
    assert_eq!(
        provider.perform(
            &HostIoRequest::FsRead {
                path: "é".to_string(),
            },
            &[HostIoCapability::FsRead],
        ),
        Err(HostIoError::Denied {
            reason: "HOST_IO_REQUEST_BYTES_EXHAUSTED".to_string(),
        })
    );
}

#[test]
#[cfg(unix)]
fn manifest_host_budget_counts_metadata_arguments_before_creating_directories() {
    for (request_bytes, admitted) in [(19, false), (20, true)] {
        let (manifest, root) = host_budget_manifest(AgentHostIoBudget {
            requests: 1,
            request_bytes,
            max_in_flight: 1,
        });
        let provider = manifest.build_host_io_provider().unwrap().unwrap();
        let result = provider.perform(
            &HostIoRequest::FsMeta {
                operation: FsOperation::Mkdir,
                path: "newdir".to_string(),
                arguments: vec!["recursive=true".to_string()],
                data: vec![],
            },
            &[HostIoCapability::FsWrite],
        );
        assert_eq!(root.join("newdir").is_dir(), admitted);
        if admitted {
            assert!(result.is_ok(), "exact request-byte boundary: {result:?}");
        } else {
            assert_eq!(
                result,
                Err(HostIoError::Denied {
                    reason: "HOST_IO_REQUEST_BYTES_EXHAUSTED".to_string(),
                })
            );
        }
    }
}

#[test]
#[cfg(unix)]
fn manifest_host_budget_does_not_grant_authority_or_refund_native_failures() {
    let (manifest, root) = host_budget_manifest(AgentHostIoBudget {
        requests: 1,
        request_bytes: 1024,
        max_in_flight: 1,
    });
    let provider = manifest.build_host_io_provider().unwrap().unwrap();
    let missing = HostIoRequest::FsRead {
        path: "missing".to_string(),
    };
    assert_eq!(
        provider.perform(&missing, &[]),
        Err(HostIoError::CapabilityMissing {
            capability: HostIoCapability::FsRead,
        }),
        "an admission budget never grants the missing read capability"
    );
    assert!(matches!(
        provider.perform(&missing, &[HostIoCapability::FsRead]),
        Err(HostIoError::Fs { code, .. }) if code == "ENOENT"
    ));
    assert_eq!(
        provider.perform(
            &HostIoRequest::FsWrite {
                path: "output".to_string(),
                data: b"must not be written".to_vec(),
            },
            &[HostIoCapability::FsWrite],
        ),
        Err(HostIoError::Denied {
            reason: "HOST_IO_REQUEST_BUDGET_EXHAUSTED".to_string(),
        }),
        "native failures consume their admitted work without a refund"
    );
    assert!(!root.join("output").exists());
}

#[test]
#[cfg(unix)]
fn manifest_host_budget_zero_limits_and_missing_root_deny_host_dispatch() {
    for (requests, max_in_flight, reason) in [
        (0, 1, "HOST_IO_REQUEST_BUDGET_EXHAUSTED"),
        (1, 0, "HOST_IO_CONCURRENCY_EXHAUSTED"),
    ] {
        let (manifest, root) = host_budget_manifest(AgentHostIoBudget {
            requests,
            request_bytes: 1024,
            max_in_flight,
        });
        let provider = manifest.build_host_io_provider().unwrap().unwrap();
        assert_eq!(
            provider.perform(
                &HostIoRequest::FsWrite {
                    path: "output".to_string(),
                    data: b"must not be written".to_vec(),
                },
                &[HostIoCapability::FsWrite],
            ),
            Err(HostIoError::Denied {
                reason: reason.to_string(),
            })
        );
        assert!(!root.join("output").exists());
    }
    let mut unrooted = manifest();
    unrooted.host_io_budget = Some(AgentHostIoBudget {
        requests: 1,
        request_bytes: 1024,
        max_in_flight: 1,
    });
    assert!(unrooted.build_host_io_provider().unwrap().is_none());
}

/// Observe dispatch to the real manifest-built provider without changing its
/// authority, cancellation, native results, or exception provenance.
#[cfg(unix)]
#[derive(Debug)]
struct ObservedHostIo {
    provider: Arc<dyn HostIoProvider>,
    calls: AtomicUsize,
}

#[cfg(unix)]
impl HostIoProvider for ObservedHostIo {
    fn name(&self) -> &str {
        self.provider.name()
    }

    fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        self.provider.filesystem_exception_provenance()
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.provider.perform(request, granted)
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.provider.perform_controlled(request, granted, control)
    }
}

#[cfg(unix)]
fn journal_manifest() -> (
    AgentSandboxManifest,
    std::path::PathBuf,
    Arc<ObservedHostIo>,
) {
    let (mut manifest, root) = host_budget_manifest(AgentHostIoBudget {
        requests: 32,
        request_bytes: 1024 * 1024,
        max_in_flight: 1,
    });
    manifest.denied_capability_tags = vec!["process_spawn".to_string()];
    manifest.network_allowlist = Some(vec!["127.0.0.1:9".parse().unwrap()]);
    manifest.tool_grants.extend(
        [
            RuntimeCapability::Builtin,
            RuntimeCapability::RandomRead,
            RuntimeCapability::NetworkEgress,
        ]
        .map(|capability| AgentToolGrant {
            tool_name: capability.as_str().to_string(),
            capability_tag: capability.as_str().to_string(),
            description: None,
        }),
    );
    let provider = Arc::new(ObservedHostIo {
        provider: manifest.build_host_io_provider().unwrap().unwrap(),
        calls: AtomicUsize::new(0),
    });
    (manifest, root, provider)
}

#[test]
#[cfg(unix)]
fn agent_host_effect_journal_preflights_every_host_family_in_both_lanes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for source in [
            "require('fs').readFileSync('input.txt', 'utf8');",
            "require('fs').writeFileSync('blocked.txt', 'must not be written');",
            "require('crypto').randomBytes(8);",
            "fetch('http://127.0.0.1:9/');",
        ] {
            for (limits, expected) in [
                (
                    HostEffectJournalLimits {
                        max_entries: 0,
                        max_encoded_bytes: 4096,
                    },
                    "journal entry capacity exceeded",
                ),
                (
                    HostEffectJournalLimits {
                        max_entries: 8,
                        max_encoded_bytes: 0,
                    },
                    "journal byte capacity exceeded",
                ),
            ] {
                let (manifest, root, provider) = journal_manifest();
                std::fs::write(root.join("input.txt"), b"host input").unwrap();
                let package = manifest
                    .to_extension_package(source.into(), Some(INPUT_PATH.into()), "test", false)
                    .unwrap();
                let journal = Arc::new(InMemoryHostEffectJournal::recording_with_limits(limits));
                let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig {
                    force_lane: Some(lane),
                    ..OrchestratorConfig::default()
                });
                orchestrator.set_host_io_with_journal(provider.clone(), journal.clone());
                let error = orchestrator
                    .execute(&package)
                    .expect_err("journal admission must stop execution before a live crossing");
                assert!(
                    error.to_string().contains(expected),
                    "lane={lane:?}, source={source}, expected={expected}: {error}"
                );
                assert_eq!(provider.calls.load(Ordering::Relaxed), 0, "{source}");
                assert!(!root.join("blocked.txt").exists());
                assert!(journal.entries().is_empty());
                assert_eq!(journal.retained_encoded_bytes(), 0);
            }
        }
    }
}

#[test]
#[cfg(unix)]
fn agent_host_effect_journal_retains_prefix_and_denies_next_write_before_dispatch() {
    let (manifest, root, provider) = journal_manifest();
    let package = manifest
        .to_extension_package(
            "const fs = require('fs'); fs.writeFileSync('output.txt', 'first'); \
             try { fs.writeFileSync('output.txt', 'must not overwrite'); } \
             catch (error) { console.log('must not catch'); }"
                .into(),
            Some(INPUT_PATH.into()),
            "test",
            false,
        )
        .unwrap();
    let limits = HostEffectJournalLimits {
        max_entries: 1,
        max_encoded_bytes: 4096,
    };
    let journal = Arc::new(InMemoryHostEffectJournal::recording_with_limits(limits));
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io_with_journal(provider.clone(), journal.clone());
    let error = orchestrator
        .execute(&package)
        .expect_err("second crossing refused");
    assert!(
        error
            .to_string()
            .contains("journal entry capacity exceeded")
    );
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    assert_eq!(std::fs::read(root.join("output.txt")).unwrap(), b"first");
    assert!(orchestrator.last_failed_console_output().is_empty());
    let expected = HostEffectJournalEntry::HostIo {
        request: HostIoRequest::FsWrite {
            path: "output.txt".into(),
            data: b"first".to_vec(),
        },
        outcome: Ok(HostIoResponse::FsWrite { bytes_written: 5 }),
    };
    assert_eq!(
        orchestrator.last_failed_host_effect_journal(),
        std::slice::from_ref(&expected)
    );
    assert_eq!(
        orchestrator.last_failed_host_effect_journal_records(),
        &[HostEffectJournalAttemptRecord::Completed {
            sequence: 0,
            entry: expected
        }]
    );
    assert!(journal.retained_encoded_bytes() <= limits.max_encoded_bytes);
}

#[test]
#[cfg(unix)]
fn agent_host_effect_journal_retains_uncompleted_read_when_response_exceeds_capacity() {
    let (manifest, root, provider) = journal_manifest();
    std::fs::write(root.join("input.txt"), vec![b'x'; 8192]).unwrap();
    let package = manifest
        .to_extension_package(
            "require('fs').readFileSync('input.txt', 'utf8');".into(),
            Some(INPUT_PATH.into()),
            "test",
            false,
        )
        .unwrap();
    let limits = HostEffectJournalLimits {
        max_entries: 8,
        max_encoded_bytes: 1024,
    };
    let journal = Arc::new(InMemoryHostEffectJournal::recording_with_limits(limits));
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io_with_journal(provider.clone(), journal.clone());
    let error = orchestrator
        .execute(&package)
        .expect_err("oversized response refused");
    assert!(error.to_string().contains("journal byte capacity exceeded"));
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    assert!(orchestrator.last_failed_host_effect_journal().is_empty());
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal_records(),
        [HostEffectJournalAttemptRecord::Uncompleted { sequence: 0, family, request_kind, .. }]
            if family == "host_io" && request_kind == "fs_read"
    ));
    assert!(
        orchestrator
            .last_failed_execution_replay_context()
            .is_none()
    );
    assert!(journal.retained_encoded_bytes() <= limits.max_encoded_bytes);
    orchestrator
        .execute(&package)
        .expect_err("poisoned journal cannot resume");
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
}

#[test]
#[cfg(unix)]
fn agent_host_effect_journal_projects_exact_legacy_transcript_and_replays_offline() {
    let (manifest, root, provider) = journal_manifest();
    std::fs::write(root.join("input.txt"), b"original input").unwrap();
    let package = manifest
        .to_extension_package(
            "const fs = require('fs'); fs.writeFileSync('output.txt', 'recorded'); \
             fs.readFileSync('input.txt', 'utf8'); require('crypto').randomBytes(8);"
                .into(),
            Some(INPUT_PATH.into()),
            "test",
            false,
        )
        .unwrap();
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut original = ExecutionOrchestrator::new(OrchestratorConfig::default());
    original.set_host_io_with_journal(provider.clone(), journal);
    let recorded = original
        .execute(&package)
        .expect("record real file and entropy effects");
    assert_eq!(provider.calls.load(Ordering::Relaxed), 3);
    assert_eq!(recorded.host_effect_transcript.len(), 3);
    assert_eq!(
        recorded.host_effect_journal,
        recorded
            .host_effect_transcript
            .iter()
            .map(|(request, outcome)| {
                HostEffectJournalEntry::HostIo {
                    request: request.clone(),
                    outcome: outcome.clone(),
                }
            })
            .collect::<Vec<_>>()
    );
    assert!(matches!(
        &recorded.host_effect_transcript[2],
        (HostIoRequest::RandomRead { byte_len: 8 }, Ok(HostIoResponse::RandomRead { bytes }))
            if bytes.len() == 8
    ));
    std::fs::write(root.join("input.txt"), b"changed after recording").unwrap();
    std::fs::write(root.join("output.txt"), b"must survive replay").unwrap();
    for use_journal in [true, false] {
        let mut replayed = ExecutionOrchestrator::new(OrchestratorConfig::default());
        replayed.set_host_io_with_journal(
            provider.clone(),
            Arc::new(InMemoryHostEffectJournal::replaying(
                recorded.host_effect_journal.clone(),
            )),
        );
        if !use_journal {
            // Switching to the historical transcript API must replace the
            // installed journal, as the CLI's existing report replay does.
            replayed.set_host_io(
                provider.clone(),
                Some(Arc::new(InMemoryHostIoTranscript::replaying(
                    recorded.host_effect_transcript.clone(),
                ))),
            );
        }
        let replayed = replayed
            .execute(&package)
            .expect("offline host-effect replay");
        assert_eq!(replayed.execution_value, recorded.execution_value);
        assert_eq!(
            replayed.host_effect_transcript,
            recorded.host_effect_transcript
        );
        assert_eq!(replayed.nondeterminism_trace, recorded.nondeterminism_trace);
        assert_eq!(provider.calls.load(Ordering::Relaxed), 3);
        assert_eq!(
            std::fs::read(root.join("output.txt")).unwrap(),
            b"must survive replay"
        );
    }
}
