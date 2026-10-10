//! Explicit environment reads use the ordinary capability, IFC, provider and
//! replay boundaries. No test reads or changes the test process environment.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt as _,
    OrchestratorConfig, OrchestratorError, OrchestratorResult,
};
use frankenengine_engine::hostcall_telemetry::HostcallType;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{
    AmbientAuthorityGrant, LoweringContext, LoweringPipelineError, lower_ir0_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_extension_host::host_io::{
    DenyAllHostIo, ENVIRONMENT_NAME_MAX_BYTES, ENVIRONMENT_VALUE_MAX_BYTES,
    EnvironmentSnapshotHostIo, HostIoCapability, HostIoControl, HostIoOutcome, HostIoProvider,
    HostIoRecorder, HostIoRequest, HostIoResponse, InMemoryHostIoTranscript,
};

#[derive(Debug)]
struct CountedProvider {
    inner: Arc<dyn HostIoProvider>,
    calls: AtomicUsize,
}

impl CountedProvider {
    fn snapshot() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(
                EnvironmentSnapshotHostIo::new(
                    [
                        ("NODE_ENV".to_string(), "production".to_string()),
                        ("EMPTY".to_string(), String::new()),
                        (
                            "PRIVATE_KEY".to_string(),
                            "sensitive-fixture-value".to_string(),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                )
                .expect("bounded explicit environment"),
            ),
            calls: AtomicUsize::new(0),
        })
    }
}

impl HostIoProvider for CountedProvider {
    fn name(&self) -> &str {
        "counted-explicit-environment"
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.perform(request, granted)
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.perform_controlled(request, granted, control)
    }
}

fn package(source: &str, env_read: bool) -> ExtensionPackage {
    let mut capabilities = ["vm_dispatch", "heap_allocate", "builtin", "console"]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if env_read {
        capabilities.push("env_read".to_string());
    }
    ExtensionPackage {
        extension_id: "explicit-environment-bd-omckp".to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities,
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn execute(
    source: &str,
    env_read: bool,
    provider: Arc<dyn HostIoProvider>,
    recorder: Arc<dyn HostIoRecorder>,
) -> Result<OrchestratorResult, OrchestratorError> {
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io(provider, Some(recorder));
    orchestrator.execute(&package(source, env_read))
}

fn lower(source: &str) -> Result<Ir3Module, LoweringPipelineError> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            &ParserSource {
                source,
                source_label: Some("environment-hostcalls.js"),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "environment-hostcalls.js"),
        &LoweringContext::new("env-trace", "env-decision", "env-policy")
            .with_ambient_authority_grant(AmbientAuthorityGrant::DenyAll),
    )
    .map(|output| output.ir3)
}

#[test]
fn environment_reads_and_presence_have_exact_results_and_secret_provenance_bd_omckp() {
    assert_eq!(
        HostcallType::from_capability_tag("env:read"),
        HostcallType::EnvRead
    );
    assert_eq!(
        HostcallType::from_capability_tag("env:has"),
        HostcallType::EnvRead
    );
    for (source, expected, name, value) in [
        (
            "process.env.NODE_ENV;",
            "production",
            "NODE_ENV",
            Some("production"),
        ),
        (
            "process.env['NODE_ENV'];",
            "production",
            "NODE_ENV",
            Some("production"),
        ),
        ("process.env.EMPTY;", "", "EMPTY", Some("")),
        ("process.env.ABSENT;", "undefined", "ABSENT", None),
        ("typeof process.env.ABSENT;", "undefined", "ABSENT", None),
        (
            "'NODE_ENV' in process.env;",
            "true",
            "NODE_ENV",
            Some("production"),
        ),
        ("'EMPTY' in process.env;", "true", "EMPTY", Some("")),
        ("'ABSENT' in process.env;", "false", "ABSENT", None),
        (
            "function read() { return process.env.NODE_ENV; } read();",
            "production",
            "NODE_ENV",
            Some("production"),
        ),
    ] {
        let provider = CountedProvider::snapshot();
        let result = execute(
            source,
            true,
            provider.clone(),
            Arc::new(InMemoryHostIoTranscript::recording()),
        )
        .unwrap_or_else(|error| panic!("{source}: {error}"));
        assert_eq!(result.execution_value, expected, "{source}");
        assert_eq!(result.completion_label, Label::Secret, "{source}");
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1, "{source}");
        assert_eq!(
            result.host_effect_transcript,
            vec![(
                HostIoRequest::EnvRead {
                    name: name.to_string()
                },
                Ok(HostIoResponse::EnvRead {
                    value: value.map(str::to_string)
                }),
            )],
            "{source}"
        );
        assert!(
            result
                .ir4_witness
                .hostcall_decisions
                .iter()
                .any(|decision| { decision.capability.0 == "env_read" && decision.allowed })
        );
    }
}

#[test]
fn environment_reads_require_runtime_capability_and_explicit_provider_bd_omckp() {
    for source in [
        "process.env.NODE_ENV;",
        "process.env['NODE_ENV'];",
        "'NODE_ENV' in process.env;",
    ] {
        let provider = CountedProvider::snapshot();
        let error = execute(
            source,
            false,
            provider.clone(),
            Arc::new(InMemoryHostIoTranscript::recording()),
        )
        .expect_err("ungranted EnvRead must fail before the provider");
        assert!(
            matches!(
                error.primary_error(),
                OrchestratorError::Interpreter(InterpreterError::CapabilityDenied { capability })
                    if capability == "env_read"
            ),
            "{error:?}"
        );
        assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    }
    let error = execute(
        "process.env.NODE_ENV;",
        true,
        Arc::new(DenyAllHostIo),
        Arc::new(InMemoryHostIoTranscript::recording()),
    )
    .expect_err("the EnvRead grant alone cannot read the host environment");
    assert!(matches!(
        error.primary_error(),
        OrchestratorError::Interpreter(InterpreterError::CapabilityDenied { capability })
            if capability == "env_read"
    ));
}

#[test]
fn environment_replay_uses_exact_recorded_names_and_values_without_live_reads_bd_omckp() {
    let source = "process.env.EMPTY; process.env.NODE_ENV;";
    let recorded = execute(
        source,
        true,
        CountedProvider::snapshot(),
        Arc::new(InMemoryHostIoTranscript::recording()),
    )
    .expect("recorded execution");
    let unavailable = Arc::new(CountedProvider {
        inner: Arc::new(DenyAllHostIo),
        calls: AtomicUsize::new(0),
    });
    let replayed = execute(
        source,
        true,
        unavailable.clone(),
        Arc::new(InMemoryHostIoTranscript::replaying(
            recorded.host_effect_transcript.clone(),
        )),
    )
    .expect("replay uses recorded environment, not current provider state");
    assert_eq!(replayed.execution_value, "production");
    assert_eq!(replayed.completion_label, Label::Secret);
    assert_eq!(
        replayed.host_effect_transcript,
        recorded.host_effect_transcript
    );
    assert_eq!(unavailable.calls.load(Ordering::Relaxed), 0);

    let diverged = execute(
        "process.env.NODE_ENV; process.env.EMPTY;",
        true,
        unavailable.clone(),
        Arc::new(InMemoryHostIoTranscript::replaying(
            recorded.host_effect_transcript,
        )),
    );
    assert!(
        diverged.is_err(),
        "a reordered environment transcript must not replay"
    );
    assert_eq!(unavailable.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn environment_request_and_replay_response_limits_fail_closed_bd_omckp() {
    let provider = CountedProvider::snapshot();
    let source = format!(
        "process.env['{}'];",
        "X".repeat(ENVIRONMENT_NAME_MAX_BYTES + 1)
    );
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());
    assert!(execute(&source, true, provider.clone(), recorder.clone()).is_err());
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    assert!(recorder.recorded_entries().is_empty());

    for response in [
        HostIoResponse::RandomRead { bytes: vec![7] },
        HostIoResponse::EnvRead {
            value: Some("X".repeat(ENVIRONMENT_VALUE_MAX_BYTES + 1)),
        },
        HostIoResponse::EnvRead {
            value: Some("invalid\0environment".to_string()),
        },
    ] {
        let replay = InMemoryHostIoTranscript::replaying(vec![(
            HostIoRequest::EnvRead {
                name: "NODE_ENV".to_string(),
            },
            Ok(response),
        )]);
        assert!(
            execute(
                "process.env.NODE_ENV;",
                true,
                provider.clone(),
                Arc::new(replay),
            )
            .is_err(),
            "malformed environment outcomes must not be trusted by replay"
        );
        assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn environment_values_respect_the_interpreter_string_limit_bd_omckp() {
    let provider = Arc::new(
        EnvironmentSnapshotHostIo::new(
            [("K".to_string(), "long-environment-value".to_string())]
                .into_iter()
                .collect(),
        )
        .unwrap(),
    );
    for capability in ["env:read", "env:has"] {
        let mut module = lower("0;").unwrap();
        module.instructions = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag(capability.to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
        ];
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_string_size = 8;
        config.granted_capabilities.extend([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::EnvRead,
        ]);
        let mut interpreter = InterpreterCore::new(config, "environment-string-budget");
        interpreter.set_host_io(provider.clone(), None);
        interpreter.seed_register(0, Value::str("K")).unwrap();
        let result = interpreter.execute(&module);
        if capability == "env:read" {
            assert!(matches!(
                result,
                Err(InterpreterError::StringLimitExceeded { length: 22, max: 8 })
            ));
        } else {
            let result = result.expect("presence does not materialize a guest string");
            assert_eq!(result.value, Value::Bool(true));
            assert_eq!(interpreter.get_register_label(1).unwrap(), &Label::Secret);
        }
    }
}

#[test]
fn environment_read_lowering_does_not_broaden_ambient_authority_bd_omckp() {
    for source in [
        "process.env;",
        "const env = process.env; env.NODE_ENV;",
        "Object.keys(process.env);",
        "process.exit;",
        "process.kill(1);",
        "process.env.NODE_ENV = 'changed';",
        "const key = 'NODE_ENV'; process.env[key];",
    ] {
        assert!(
            matches!(
                lower(source),
                Err(LoweringPipelineError::AmbientAuthorityViolation { .. })
            ),
            "ambient possession or mutation must remain denied: {source}"
        );
    }
    let provider = CountedProvider::snapshot();
    let result = execute(
        "const process = { env: { NODE_ENV: 'local' } }; process.env.NODE_ENV;",
        false,
        provider.clone(),
        Arc::new(InMemoryHostIoTranscript::recording()),
    )
    .expect("lexical shadows are ordinary user data");
    assert_eq!(result.execution_value, "local");
    assert_eq!(result.completion_label, Label::Public);
    assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn environment_values_and_presence_cannot_flow_to_console_bd_omckp() {
    for source in [
        "console.log(process.env.PRIVATE_KEY);",
        "console.log('PRIVATE_KEY' in process.env);",
        "console.log(typeof process.env.PRIVATE_KEY);",
    ] {
        assert!(
            matches!(
                lower(source),
                Err(LoweringPipelineError::UnauthorizedFlow { .. })
            ),
            "a secret-derived observation must not reach console: {source}"
        );
    }

    // Bypass static inference deliberately: the real EnvRead result must
    // still retain Secret at the interpreter's independent sink boundary.
    let mut module = lower("0;").unwrap();
    module.instructions = vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("env:read".to_string()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("console:log".to_string()),
            args: RegRange { start: 1, count: 1 },
            dst: 2,
        },
        Ir3Instruction::Return { value: 1 },
    ];
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::EnvRead,
        RuntimeCapability::Console,
    ]);
    let mut interpreter = InterpreterCore::new(config, "runtime-environment-ifc");
    let provider = CountedProvider::snapshot();
    interpreter.set_host_io(provider.clone(), None);
    interpreter
        .seed_register(0, Value::str("PRIVATE_KEY"))
        .unwrap();
    let error = interpreter
        .execute(&module)
        .expect_err("runtime sink refuses secret data");
    assert!(
        matches!(error, InterpreterError::CapabilityDenied { capability }
        if capability.contains("confidentiality"))
    );
    assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    assert_eq!(interpreter.get_register_label(1).unwrap(), &Label::Secret);
}
