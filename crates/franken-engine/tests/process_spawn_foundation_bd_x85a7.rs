//! bd-x85a7: authenticated lowering contract for Node `child_process` effects.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_extension_host::host_effect_journal::{
    HostEffectJournalEntry, InMemoryHostEffectJournal,
};
use frankenengine_extension_host::process_spawn::{
    ProcessExit, ProcessLaunch, ProcessSpawnCapability, ProcessSpawnError, ProcessSpawnOutcome,
    ProcessSpawnProvider, ProcessSpawnRequest, ProcessSpawnResponse, ProcessStdio,
};

#[derive(Debug)]
struct RecordingProcessSpawn {
    seen: Mutex<Vec<ProcessSpawnRequest>>,
    outcome: ProcessSpawnOutcome,
}

impl RecordingProcessSpawn {
    fn successful(stdout: &[u8]) -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            outcome: Ok(ProcessSpawnResponse::Run {
                exit: ProcessExit {
                    success: true,
                    code: Some(0),
                    signal: None,
                },
                stdout: stdout.to_vec(),
                stderr: Vec::new(),
            }),
        }
    }

    fn denying() -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            outcome: Err(ProcessSpawnError::Denied {
                reason: "test policy denied process launch".to_string(),
            }),
        }
    }
}

impl ProcessSpawnProvider for RecordingProcessSpawn {
    fn name(&self) -> &str {
        "recording-process-spawn"
    }

    fn perform(
        &self,
        request: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        assert_eq!(granted, &[ProcessSpawnCapability::Spawn]);
        self.seen
            .lock()
            .expect("recording provider mutex")
            .push(request.clone());
        match (request, &self.outcome) {
            (ProcessSpawnRequest::Spawn { .. }, Ok(ProcessSpawnResponse::Run { .. })) => {
                Ok(ProcessSpawnResponse::Spawned {
                    handle: "recorded-process-handle".to_string(),
                })
            }
            (
                ProcessSpawnRequest::Wait { .. },
                Ok(ProcessSpawnResponse::Run {
                    exit,
                    stdout,
                    stderr,
                }),
            ) => Ok(ProcessSpawnResponse::Waited {
                exit: exit.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
            }),
            _ => self.outcome.clone(),
        }
    }

    fn cleanup_handle(&self, _handle: &str) {}
}

fn process_package(source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "bd-x85a7-process-bridge".to_string(),
        source: source.to_string(),
        source_file: None,
        capabilities: vec!["process_spawn".to_string()],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn expected_run_request() -> ProcessSpawnRequest {
    ProcessSpawnRequest::Run {
        launch: expected_launch(),
        stdin: Vec::new(),
        timeout_millis: None,
    }
}

fn expected_launch() -> ProcessLaunch {
    ProcessLaunch {
        executable: "tool".to_string(),
        argv: vec!["alpha".to_string()],
        env: BTreeMap::new(),
        cwd: None,
        shell: false,
        stdio: ProcessStdio::default(),
    }
}

fn expected_async_requests() -> Vec<ProcessSpawnRequest> {
    vec![
        ProcessSpawnRequest::Spawn {
            launch: expected_launch(),
        },
        ProcessSpawnRequest::Wait {
            handle: "recorded-process-handle".to_string(),
            timeout_millis: None,
        },
    ]
}

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
        .expect("child_process specimen should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "child-process-foundation.js");
    let context = LoweringContext::new("trace-bd-x85a7", "decision-bd-x85a7", "policy-bd-x85a7");
    lower_ir0_to_ir3(&ir0, &context)
        .expect("child_process specimen should lower")
        .ir3
}

fn eval_error(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => panic!("expected eval failure for {source:?}, got {outcome:?}"),
        Err(error) => error.to_string(),
    }
}

fn assert_process_spawn_denial(source: &str) {
    let error = eval_error(source);
    assert!(
        error.contains("process_spawn") || error.contains("ProcessSpawn"),
        "authenticated child_process call must reach the typed process_spawn gate: {source:?}: {error}"
    );
}

#[test]
fn supported_child_process_calls_reach_one_typed_capability_gate() {
    for source in [
        "const cp = require('child_process'); cp.spawnSync('/bin/true');",
        "const cp = require('node:child_process'); cp.execSync('true');",
        "const cp = require('child_process'); cp.execFileSync('/bin/true', []);",
        "const cp = require('child_process'); cp.spawn('/bin/true', []);",
        "const cp = require('child_process'); cp.exec('true', () => {});",
        "const cp = require('child_process'); cp.execFile('/bin/true', [], () => {});",
        "require('node:child_process').spawnSync('/bin/true', []);",
    ] {
        assert_process_spawn_denial(source);
    }
}

#[test]
fn lowering_commits_each_operation_to_slot_zero_and_one_capability_tag() {
    for (source, expected_discriminator, expected_arg_count) in [
        (
            "require('child_process').spawnSync('true', [], { encoding: 'utf8' });",
            "\0processop:spawn_sync",
            4,
        ),
        (
            "require('child_process').execSync('true', { encoding: 'utf8' });",
            "\0processop:exec_sync",
            3,
        ),
        (
            "require('child_process').execFileSync('true', []);",
            "\0processop:exec_file_sync",
            3,
        ),
        (
            "require('child_process').spawn('true', []);",
            "\0processop:spawn",
            3,
        ),
        (
            "require('child_process').exec('true', () => {});",
            "\0processop:exec",
            3,
        ),
        (
            "require('child_process').execFile('true', [], () => {});",
            "\0processop:exec_file",
            4,
        ),
    ] {
        let ir3 = lower(source);
        let hostcalls = ir3
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Ir3Instruction::HostCall {
                    capability, args, ..
                } => Some((capability, args)),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(hostcalls.len(), 1, "one process crossing for {source:?}");
        assert_eq!(hostcalls[0].0.0, "process_spawn");
        assert_eq!(hostcalls[0].1.count, expected_arg_count);
        assert_eq!(
            ir3.required_capabilities,
            vec![frankenengine_engine::ir_contract::CapabilityTag(
                "process_spawn".to_string()
            )]
        );
        assert!(
            ir3.constant_pool
                .iter()
                .any(|value| value.as_str() == Some(expected_discriminator)),
            "private operation discriminator missing for {source:?}"
        );
    }
}

#[test]
fn authenticated_alias_survives_closure_capture_but_not_parameter_shadowing() {
    assert_process_spawn_denial(
        "const cp = require('child_process'); function run() { return cp.spawnSync('/bin/true'); } run();",
    );

    let error = eval_error(
        "const cp = require('child_process'); function local(cp) { return cp.spawnSync('/bin/true'); } local({ spawnSync: () => 7 });",
    );
    assert!(
        error.contains("require") || error.contains("ambient") || error.contains("authority"),
        "a shadowed local must not authenticate the outer module alias: {error}"
    );
}

#[test]
fn unsupported_or_escaped_child_process_aliases_remain_ambient_refused() {
    for source in [
        "const cp = require('child_process');",
        "const cp = require('child_process'); cp;",
        "let cp = require('child_process'); cp.spawnSync('/bin/true');",
        "const cp = require('child_process'); cp = {}; cp.spawnSync('/bin/true');",
        "const cp = require('child_process'); cp.spawnSync = () => {}; cp.spawnSync('/bin/true');",
        "const cp = require('child_process'); cp['spawnSync']('/bin/true');",
        "const cp = require('child_process'); cp.fork('worker.js');",
        "const cp = require('child_process'); consume(cp);",
        "const name = 'child_process'; require(name).spawnSync('/bin/true');",
        "const cp = require('child_process'); const args = []; cp.spawnSync('/bin/true', ...args);",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("require")
                || error.contains("ambient")
                || error.contains("Ambient")
                || error.contains("authority"),
            "unsupported module possession must preserve ambient denial: {source:?}: {error}"
        );
        assert!(
            !error.contains("process_spawn"),
            "rejected alias use must not be upgraded to a process effect: {source:?}: {error}"
        );
    }
}

#[test]
fn lexically_shadowed_require_remains_an_ordinary_user_call() {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(
            "const require = () => ({ spawnSync: () => 1 }); const cp = require('child_process'); cp.spawnSync('/bin/true');",
        )
        .expect("a user-defined require must not be intercepted as ambient module authority");
    assert_eq!(outcome.value, "1");
}

#[test]
fn extra_source_arguments_are_evaluated_before_the_process_gate() {
    assert_process_spawn_denial(
        "const cp = require('child_process'); cp.spawnSync('/bin/true', [], {}, 'extra');",
    );
}

#[test]
fn signed_process_authority_is_consumed_by_one_execution_attempt() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"first-only"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal);
    let package =
        process_package("const cp = require('child_process'); cp.execFileSync('tool', ['alpha']);");

    orchestrator
        .execute(&package)
        .expect("the admitted execution should reach the provider");
    let error = orchestrator
        .execute(&package)
        .expect_err("a second execution needs a fresh signed process admission");

    assert!(
        error
            .to_string()
            .contains("process_spawn provider admission")
    );
    assert_eq!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .len(),
        1,
        "reused orchestrators must not carry process authority across attempts"
    );
}

#[test]
fn child_process_overloads_and_optional_async_callbacks_are_normalized() {
    for source in [
        "const cp = require('child_process'); cp.spawnSync('tool', { encoding: 'utf8' });",
        "const cp = require('child_process'); cp.execFileSync('tool', { encoding: 'utf8' });",
        "const cp = require('child_process'); const child = cp.execFile('tool'); console.log(child.pid);",
        "const cp = require('child_process'); const child = cp.execFile('tool', { encoding: 'utf8' }); console.log(child.pid);",
        "const cp = require('child_process'); const child = cp.execFile('tool', () => {}); console.log(child.pid);",
    ] {
        let provider = Arc::new(RecordingProcessSpawn::successful(b"normalized"));
        let journal = Arc::new(InMemoryHostEffectJournal::recording());
        let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
        orchestrator.set_process_spawn(provider.clone(), journal);
        orchestrator
            .execute(&process_package(source))
            .unwrap_or_else(|error| panic!("overload should execute: {source}: {error}"));
        let expected_requests = if source.contains("const child =") {
            2
        } else {
            1
        };
        assert_eq!(
            provider
                .seen
                .lock()
                .expect("recording provider mutex")
                .len(),
            expected_requests,
            "normalized process lifecycle for {source}"
        );
    }
}

#[test]
fn orchestrator_threads_typed_provider_and_exact_journal_into_sync_execution() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"typed-process-output"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal);

    let result = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); console.log(cp.execFileSync('tool', ['alpha'], { encoding: 'utf8' }));",
        ))
        .expect("authorized process provider should execute through the full pipeline");

    assert_eq!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .as_slice(),
        &[expected_run_request()]
    );
    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].message, "typed-process-output");
    assert_eq!(result.host_effect_journal.len(), 1);
    assert!(matches!(
        &result.host_effect_journal[0],
        HostEffectJournalEntry::ProcessSpawn {
            request,
            outcome: Ok(ProcessSpawnResponse::Run { stdout, .. }),
        } if request == &expected_run_request() && stdout == b"typed-process-output"
    ));
}

#[test]
fn async_spawn_facade_delivers_stream_and_exit_events_after_registration() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"async-output"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal);

    let result = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); const child = cp.spawn('tool', ['alpha']); child.on('spawn', () => console.log('spawn')); child.stdout.on('data', chunk => console.log('data:' + chunk)); child.on('exit', code => console.log('exit:' + code)); setTimeout(() => console.log('timer'), 0);",
        ))
        .expect("completed child facade should drain registered events");

    assert_eq!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .as_slice(),
        expected_async_requests().as_slice()
    );
    assert_eq!(
        result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect::<Vec<_>>(),
        vec!["spawn", "timer", "data:async-output", "exit:0"]
    );
    assert_eq!(result.host_effect_journal.len(), 2);
}

#[test]
fn async_spawn_with_empty_output_does_not_fabricate_stream_data() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b""));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal);

    let result = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); const child = cp.spawn('tool', ['alpha']); child.stdout.on('data', () => console.log('fabricated-data')); child.on('exit', code => console.log('exit:' + code)); child.on('close', code => console.log('close:' + code));",
        ))
        .expect("an empty capture must still complete the child lifecycle");

    assert_eq!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .as_slice(),
        expected_async_requests().as_slice()
    );
    assert_eq!(
        result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect::<Vec<_>>(),
        vec!["exit:0", "close:0"],
        "an empty pipe must not emit a synthetic data event"
    );
}

#[test]
fn async_exec_callback_receives_output_in_the_requested_encoding() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"decoded-output"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal);

    let result = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFile('tool', ['alpha'], { encoding: 'utf8' }, (error, stdout, stderr) => console.log(String(error) + ':' + stdout + ':' + stderr));",
        ))
        .expect("an async execFile callback should observe decoded output");

    assert_eq!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .as_slice(),
        expected_async_requests().as_slice()
    );
    assert_eq!(result.console_output.len(), 1);
    assert_eq!(
        result.console_output[0].message, "null:decoded-output:",
        "callback stdout/stderr must not be discarded"
    );
}

#[test]
fn unhandled_async_spawn_error_escapes_the_event_loop_boundary() {
    let provider = Arc::new(RecordingProcessSpawn::denying());
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal);

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.spawn('tool', ['alpha']);",
        ))
        .expect_err("an unhandled child error must fail the execution");

    assert!(error.to_string().contains("test policy denied"));
    assert_eq!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .as_slice(),
        &[ProcessSpawnRequest::Spawn {
            launch: expected_launch(),
        }]
    );
    assert_eq!(orchestrator.last_failed_host_effect_journal().len(), 1);
}

#[test]
fn failed_execution_retains_the_denied_process_journal_prefix() {
    let provider = Arc::new(RecordingProcessSpawn::denying());
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider, journal);

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('tool', ['alpha']);",
        ))
        .expect_err("provider denial should abort an uncaught synchronous call");
    assert!(error.to_string().contains("test policy denied"));
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            request,
            outcome: Err(ProcessSpawnError::Denied { reason }),
        }] if request == &expected_run_request() && reason == "test policy denied process launch"
    ));
}

#[test]
fn replay_finalization_failure_retains_the_consumed_effect_prefix() {
    let recorded = HostEffectJournalEntry::ProcessSpawn {
        request: expected_run_request(),
        outcome: Ok(ProcessSpawnResponse::Run {
            exit: ProcessExit {
                success: true,
                code: Some(0),
                signal: None,
            },
            stdout: b"replayed".to_vec(),
            stderr: Vec::new(),
        }),
    };
    let journal = Arc::new(InMemoryHostEffectJournal::replaying(vec![
        recorded.clone(),
        recorded.clone(),
    ]));
    let provider = Arc::new(RecordingProcessSpawn::successful(b"must-not-run"));
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal);

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('tool', ['alpha']);",
        ))
        .expect_err("unused replay suffix must fail finalization");
    assert!(error.to_string().contains("unused entries"));
    assert_eq!(orchestrator.last_failed_host_effect_journal(), &[recorded]);
    assert!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .is_empty(),
        "replay finalization must never invoke the live provider"
    );
}

#[test]
fn non_public_request_data_is_blocked_before_the_provider() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"must-not-run"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal);

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('secret-tool', []);",
        ))
        .expect_err("non-public command data must fail before provider dispatch");
    assert!(error.to_string().contains("declassification"));
    assert!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .is_empty(),
        "IFC denial must occur before the native provider"
    );
    assert!(
        orchestrator.last_failed_host_effect_journal().is_empty(),
        "static IFC denial must happen before a host-effect request exists"
    );
}

#[test]
fn non_public_mutation_of_a_public_options_alias_is_blocked_at_runtime() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"must-not-run"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal);

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); const opts = {}; const alias = opts; alias.cwd = 'secret-tool'; cp.execFileSync('tool', [], opts);",
        ))
        .expect_err("mutating an aliased public options object must not launder its label");

    assert!(error.to_string().contains("FLOW_POLICY_BLOCKED"));
    assert!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .is_empty(),
        "dynamic IFC denial must occur before the native provider"
    );
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            outcome: Err(ProcessSpawnError::FlowPolicyBlocked),
            ..
        }]
    ));
}
