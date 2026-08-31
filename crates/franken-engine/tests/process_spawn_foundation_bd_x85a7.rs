//! bd-x85a7: authenticated lowering contract for Node `child_process` effects.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Barrier, Mutex};
#[cfg(unix)]
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
#[cfg(unix)]
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
#[cfg(unix)]
use frankenengine_engine::execution_cell::CellInterpreterOutcome;
use frankenengine_engine::execution_cell::{
    CellError, CellExecutionError, CellExecutionEvent, CellExecutionEventKind,
};
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
    ProcessSpawnAttemptAuthority, ProcessSpawnAttemptError,
};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineError, lower_ir0_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_extension_host::host_effect_journal::{
    HostEffectJournalAttemptRecord, HostEffectJournalEntry, InMemoryHostEffectJournal,
};
#[cfg(unix)]
use frankenengine_extension_host::process_spawn::{NativeProcessSpawn, ProcessSpawnPolicy};
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
                exit: *exit,
                stdout: stdout.clone(),
                stderr: stderr.clone(),
            }),
            _ => self.outcome.clone(),
        }
    }

    fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
        Ok(ProcessSpawnResponse::Cleaned { was_present: false })
    }
}

#[derive(Debug, Default)]
struct CleanupFailingProcessSpawn;

impl ProcessSpawnProvider for CleanupFailingProcessSpawn {
    fn name(&self) -> &str {
        "cleanup-failing-process-spawn"
    }

    fn perform(
        &self,
        request: &ProcessSpawnRequest,
        _granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        match request {
            ProcessSpawnRequest::Spawn { .. } => Ok(ProcessSpawnResponse::Spawned {
                handle: "opaque-cleanup-failure-handle".to_string(),
            }),
            ProcessSpawnRequest::Wait { .. } => Ok(ProcessSpawnResponse::StdinClosed),
            _ => Err(ProcessSpawnError::Denied {
                reason: "unexpected test process request".to_string(),
            }),
        }
    }

    fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
        Err(ProcessSpawnError::Io {
            operation: "injected cleanup".to_string(),
            detail: "injected cleanup failure".to_string(),
        })
    }
}

#[derive(Debug)]
struct CommitBoundaryProcessSpawn {
    entered: SyncSender<()>,
    release: Mutex<Receiver<()>>,
    calls: AtomicUsize,
}

impl ProcessSpawnProvider for CommitBoundaryProcessSpawn {
    fn name(&self) -> &str {
        "commit-boundary-process-spawn"
    }

    fn perform(
        &self,
        _request: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        assert_eq!(granted, &[ProcessSpawnCapability::Spawn]);
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.entered
            .send(())
            .expect("cancellation test must observe provider dispatch");
        self.release
            .lock()
            .expect("release receiver mutex")
            .recv()
            .expect("cancellation test must release provider completion");
        Ok(ProcessSpawnResponse::Run {
            exit: ProcessExit {
                success: true,
                code: Some(0),
                signal: None,
            },
            stdout: b"committed-before-cancellation".to_vec(),
            stderr: Vec::new(),
        })
    }

    fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
        Ok(ProcessSpawnResponse::Cleaned { was_present: false })
    }
}

#[derive(Debug)]
struct RevokingLifecycleProcessSpawn {
    authority: ProcessSpawnAttemptAuthority,
    calls: AtomicUsize,
}

#[derive(Debug)]
struct ExpiringLifecycleProcessSpawn {
    expires_at_unix_ms: u64,
    calls: AtomicUsize,
}

impl ProcessSpawnProvider for ExpiringLifecycleProcessSpawn {
    fn name(&self) -> &str {
        "expiring-lifecycle-process-spawn"
    }

    fn perform(
        &self,
        request: &ProcessSpawnRequest,
        _granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        self.calls.fetch_add(1, Ordering::AcqRel);
        match request {
            ProcessSpawnRequest::Spawn { .. } => {
                while unix_now_ms() < self.expires_at_unix_ms {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(ProcessSpawnResponse::Spawned {
                    handle: "expired-after-spawn".to_string(),
                })
            }
            _ => panic!("expired authority must refuse later effects before provider dispatch"),
        }
    }

    fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
        Ok(ProcessSpawnResponse::Cleaned { was_present: true })
    }
}

impl ProcessSpawnProvider for RevokingLifecycleProcessSpawn {
    fn name(&self) -> &str {
        "revoking-lifecycle-process-spawn"
    }

    fn perform(
        &self,
        request: &ProcessSpawnRequest,
        _granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        self.calls.fetch_add(1, Ordering::AcqRel);
        match request {
            ProcessSpawnRequest::Spawn { .. } => {
                self.authority.revoke();
                Ok(ProcessSpawnResponse::Spawned {
                    handle: "revoked-after-spawn".to_string(),
                })
            }
            _ => panic!("revoked authority must refuse later effects before provider dispatch"),
        }
    }

    fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
        Ok(ProcessSpawnResponse::Cleaned { was_present: true })
    }
}

#[derive(Debug, Default)]
struct PreflightRejectingProcessSpawn {
    prepares: AtomicUsize,
    performs: AtomicUsize,
}

impl ProcessSpawnProvider for PreflightRejectingProcessSpawn {
    fn name(&self) -> &str {
        "preflight-rejecting-process-spawn"
    }

    fn preflight_request(&self, _request: &ProcessSpawnRequest) -> Result<(), ProcessSpawnError> {
        Err(ProcessSpawnError::LimitExceeded {
            limit: "request_bytes".to_string(),
            actual: 2,
            maximum: 1,
        })
    }

    fn prepare_request(
        &self,
        request: &ProcessSpawnRequest,
    ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
        self.prepares.fetch_add(1, Ordering::AcqRel);
        Ok(request.clone())
    }

    fn perform(
        &self,
        _request: &ProcessSpawnRequest,
        _granted: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        self.performs.fetch_add(1, Ordering::AcqRel);
        panic!("preflight refusal must precede provider dispatch")
    }

    fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
        Ok(ProcessSpawnResponse::Cleaned { was_present: false })
    }
}

fn process_package(source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "bd-x85a7-process-bridge".to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec!["process_spawn".to_string()],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn unix_now_ms() -> u64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock must be after the Unix epoch")
        .as_millis();
    u64::try_from(now_ms).expect("test clock must fit u64 milliseconds")
}

fn test_process_authority() -> ProcessSpawnAttemptAuthority {
    let expires_at_ms = unix_now_ms().saturating_add(5 * 60 * 1_000);
    ProcessSpawnAttemptAuthority::expiring_at_unix_ms(expires_at_ms)
}

#[cfg(unix)]
fn unix_executable(candidates: &[&str]) -> PathBuf {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .and_then(|path| std::fs::canonicalize(path).ok())
        .expect("a required Unix test executable must exist")
}

#[cfg(unix)]
fn native_process_provider(
    alias: &str,
    candidates: &[&str],
    max_runtime_millis: u64,
) -> (Arc<NativeProcessSpawn>, String) {
    let executable = unix_executable(candidates);
    let mut policy = ProcessSpawnPolicy::jailed("/").expect("rooted native process policy");
    let canonical = policy
        .authorize_alias(alias, executable)
        .expect("authorize exact native process alias");
    policy.limits.max_runtime_millis = max_runtime_millis;
    policy.limits.max_children = 1;
    let provider = NativeProcessSpawn::new(policy).expect("install native process provider");
    (Arc::new(provider), canonical)
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
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());
    let package =
        process_package("const cp = require('child_process'); cp.execFileSync('tool', ['alpha']);");

    orchestrator
        .execute(&package)
        .expect("the admitted execution should reach the provider");
    let error = orchestrator
        .execute(&package)
        .expect_err("a second execution needs a fresh signed process admission");

    assert!(matches!(
        error,
        OrchestratorError::ProcessSpawnAttempt(ProcessSpawnAttemptError::AlreadyAdmitted)
    ));
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
fn expired_process_authority_fails_closed_and_remains_consumed() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"must-not-run"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(
        provider.clone(),
        journal,
        ProcessSpawnAttemptAuthority::expiring_at_unix_ms(0),
    );
    let package = process_package(
        "const cp = require('child_process'); cp.execFileSync('tool', ['expired']);",
    );

    orchestrator
        .execute(&package)
        .expect_err("expired authority must refuse the live process effect");
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            outcome: Err(ProcessSpawnError::Denied { reason }),
            ..
        }] if reason == "PROCESS_SPAWN_AUTHORITY_EXPIRED"
    ));
    assert!(matches!(
        orchestrator.execute(&package),
        Err(OrchestratorError::ProcessSpawnAttempt(
            ProcessSpawnAttemptError::AlreadyAdmitted
        ))
    ));
    assert!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .is_empty()
    );
}

#[test]
fn process_deadline_beyond_the_bounded_horizon_fails_closed_and_is_journaled() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"must-not-run"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(
        provider.clone(),
        journal,
        ProcessSpawnAttemptAuthority::expiring_at_unix_ms(u64::MAX),
    );

    orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('tool', ['overflow']);",
        ))
        .expect_err("an expiry beyond the bounded attempt horizon must fail closed");
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            outcome: Err(ProcessSpawnError::Denied { reason }),
            ..
        }] if reason == "PROCESS_SPAWN_DEADLINE_BEYOND_HORIZON"
    ));
    assert!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .is_empty()
    );
}

#[test]
fn malformed_attempt_consumes_process_authority_before_package_validation() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"must-not-run"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());
    let malformed = process_package("");

    assert!(matches!(
        orchestrator.execute(&malformed),
        Err(OrchestratorError::EmptySource)
    ));
    assert!(matches!(
        orchestrator.execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('tool');"
        )),
        Err(OrchestratorError::ProcessSpawnAttempt(
            ProcessSpawnAttemptError::AlreadyAdmitted
        ))
    ));
    assert!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .is_empty()
    );
}

#[test]
fn shared_process_authority_admits_exactly_one_concurrent_orchestrator() {
    let authority = test_process_authority();
    let provider = Arc::new(RecordingProcessSpawn::successful(b"atomic-winner"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let package = process_package(
        "const cp = require('child_process'); cp.execFileSync('tool', ['atomic']);",
    );
    let barrier = Arc::new(Barrier::new(3));
    let workers = (0..2)
        .map(|_| {
            let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
            orchestrator.set_process_spawn(provider.clone(), journal.clone(), authority.clone());
            let package = package.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                orchestrator.execute(&package)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("orchestrator worker must not panic"))
        .collect::<Vec<_>>();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                Err(OrchestratorError::ProcessSpawnAttempt(
                    ProcessSpawnAttemptError::AlreadyAdmitted
                ))
            ))
            .count(),
        1
    );
    assert_eq!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .len(),
        1
    );
}

#[test]
fn oversized_request_preflight_precedes_journal_hash_and_cell_proposal() {
    let provider = Arc::new(PreflightRejectingProcessSpawn::default());
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal.clone(), test_process_authority());

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('tool', ['oversized']);",
        ))
        .expect_err("preflight refusal must fail the guest effect");

    assert!(matches!(
        error.primary_error(),
        OrchestratorError::Interpreter(
            frankenengine_engine::baseline_interpreter::InterpreterError::HostProcess {
                code,
                ..
            }
        ) if code == "ENOBUFS"
    ));
    assert_eq!(provider.prepares.load(Ordering::Acquire), 0);
    assert_eq!(provider.performs.load(Ordering::Acquire), 0);
    assert!(journal.attempt_records().is_empty());
    let transcript = error
        .post_cell_failure()
        .expect("preflight occurs after cell creation")
        .cleanup
        .cell_execution_transcript
        .as_ref()
        .expect("failed cell must retain its transcript");
    assert!(
        transcript
            .events
            .iter()
            .all(|event| !matches!(event.kind, CellExecutionEventKind::EffectProposed { .. }))
    );
}

#[test]
fn revocation_between_spawn_and_wait_is_denied_journaled_and_cleanup_survives() {
    let authority = test_process_authority();
    let provider = Arc::new(RevokingLifecycleProcessSpawn {
        authority: authority.clone(),
        calls: AtomicUsize::new(0),
    });
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal, authority);

    orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.spawn('tool', ['revoked']);",
        ))
        .expect_err("revocation after Spawn must refuse the automatic Wait");

    assert_eq!(provider.calls.load(Ordering::Acquire), 1);
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [
            HostEffectJournalEntry::ProcessSpawn {
                request: ProcessSpawnRequest::Spawn { .. },
                outcome: Ok(ProcessSpawnResponse::Spawned { .. }),
            },
            HostEffectJournalEntry::ProcessSpawn {
                request: ProcessSpawnRequest::Wait { .. },
                outcome: Err(ProcessSpawnError::Denied { reason }),
            },
            HostEffectJournalEntry::ProcessSpawn {
                request: ProcessSpawnRequest::Cleanup { .. },
                outcome: Ok(ProcessSpawnResponse::Cleaned { was_present: true }),
            },
        ] if reason == "PROCESS_SPAWN_AUTHORITY_REVOKED"
    ));
}

#[test]
fn expiry_between_spawn_and_wait_is_denied_journaled_and_cleanup_survives() {
    let expires_at_unix_ms = unix_now_ms().saturating_add(2_000);
    let authority = ProcessSpawnAttemptAuthority::expiring_at_unix_ms(expires_at_unix_ms);
    let provider = Arc::new(ExpiringLifecycleProcessSpawn {
        expires_at_unix_ms,
        calls: AtomicUsize::new(0),
    });
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal, authority);

    orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.spawn('tool', ['expired']);",
        ))
        .expect_err("expiry after Spawn must refuse the automatic Wait");

    assert_eq!(provider.calls.load(Ordering::Acquire), 1);
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [
            HostEffectJournalEntry::ProcessSpawn {
                request: ProcessSpawnRequest::Spawn { .. },
                outcome: Ok(ProcessSpawnResponse::Spawned { .. }),
            },
            HostEffectJournalEntry::ProcessSpawn {
                request: ProcessSpawnRequest::Wait { .. },
                outcome: Err(ProcessSpawnError::Denied { reason }),
            },
            HostEffectJournalEntry::ProcessSpawn {
                request: ProcessSpawnRequest::Cleanup { .. },
                outcome: Ok(ProcessSpawnResponse::Cleaned { was_present: true }),
            }
        ] if reason == "PROCESS_SPAWN_AUTHORITY_EXPIRED"
    ));
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
        orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());
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
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());

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
    let cell_transcript = result
        .cell_execution_transcript
        .as_ref()
        .expect("successful process execution must return its finalized cell transcript");
    cell_transcript
        .verify()
        .expect("process provider crossings must form an exact cell transcript");
    let budget_settlements: Vec<_> = cell_transcript
        .events
        .iter()
        .filter_map(|event| match &event.kind {
            CellExecutionEventKind::InterpreterBudgetSettled {
                instructions_executed,
                instruction_budget,
                memory_limit_bytes,
            } => Some((
                *instructions_executed,
                *instruction_budget,
                *memory_limit_bytes,
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        budget_settlements,
        vec![(
            result.instructions_executed,
            cell_transcript.authority.instruction_budget,
            cell_transcript.authority.memory_budget_bytes,
        )],
        "real process execution must settle observed instructions under its sealed cell limits"
    );
    assert!(result.instructions_executed <= cell_transcript.authority.instruction_budget);
    assert!(cell_transcript.authority.memory_budget_bytes > 0);
    let proposals: Vec<&str> = cell_transcript
        .events
        .iter()
        .filter_map(|event| match &event.kind {
            CellExecutionEventKind::EffectProposed { request_kind, .. } => {
                Some(request_kind.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        proposals,
        vec!["run"],
        "only the real provider dispatch crosses the sealed cell permit"
    );
}

#[cfg(unix)]
#[test]
fn no_mock_native_os_process_executes_under_exact_cell_authority() {
    let (provider, canonical) =
        native_process_provider("native-printf", &["/usr/bin/printf", "/bin/printf"], 2_000);
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider, journal, test_process_authority());

    let result = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); console.log(cp.execFileSync('native-printf', ['cell-os-e2e'], { encoding: 'utf8' }));",
        ))
        .expect("the real native process provider must execute through the cell boundary");

    assert_eq!(result.console_output.len(), 1);
    assert_eq!(result.console_output[0].message, "cell-os-e2e");
    assert!(matches!(
        result.host_effect_journal.as_slice(),
        [HostEffectJournalEntry::ProcessSpawn {
            request: ProcessSpawnRequest::Run {
                launch: ProcessLaunch {
                    executable,
                    argv,
                    env,
                    cwd: None,
                    shell: false,
                    stdio: ProcessStdio { .. },
                },
                stdin,
                timeout_millis: None,
            },
            outcome: Ok(ProcessSpawnResponse::Run {
                exit: ProcessExit {
                    success: true,
                    code: Some(0),
                    signal: None,
                },
                stdout,
                stderr,
            }),
        }] if executable == &canonical
            && argv.len() == 1
            && argv[0] == "cell-os-e2e"
            && env.is_empty()
            && stdin.is_empty()
            && stdout == b"cell-os-e2e"
            && stderr.is_empty()
    ));

    let transcript = result
        .cell_execution_transcript
        .as_ref()
        .expect("a successful real process run must retain the cell transcript");
    transcript
        .verify()
        .expect("the real process transcript must replay-verify");
    assert_eq!(transcript.authority.initial_ifc_label, Label::Public);
    assert_eq!(transcript.authority.policy_epoch.as_u64(), 1);
    assert_eq!(transcript.authority.cell_id, result.trace_id);
    assert_eq!(transcript.authority.trace_id, result.trace_id);
    assert!(
        transcript
            .authority
            .capabilities
            .contains(&RuntimeCapability::VmDispatch)
    );
    assert!(
        transcript
            .authority
            .capabilities
            .contains(&RuntimeCapability::ProcessSpawn)
    );
    // bd-ifc-internal-label-cell-transcript-hplvg, aligned with the audited
    // bd-z1peg per-capability result contracts: OS stdout is engine-observed
    // external data, so the `process_spawn` contract floors the execFileSync
    // result at Internal (capability.rs `result_contract_for_authority`) and
    // the completion observation records exactly that floor. The transcript
    // must therefore prove monotonicity and a single sourced raise — Public
    // high-water until that one observation, Internal afterwards — instead of
    // an unconditional all-Public claim.
    let bound_to_run = |event: &CellExecutionEvent| {
        event.cell_id == result.trace_id
            && event.trace_id == result.trace_id
            && event.policy_epoch == result.epoch
    };
    assert!(
        transcript.events.iter().all(bound_to_run),
        "cell transcript events must stay bound to the run identity, got: {:?}",
        transcript
            .events
            .iter()
            .filter(|event| !bound_to_run(event))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        transcript
            .events
            .iter()
            .filter(|event| {
                matches!(&event.kind, CellExecutionEventKind::IfcLabelObserved { .. })
            })
            .count(),
        1,
        "exactly one IFC observation must be recorded, got: {:?}",
        transcript.events
    );
    let raise_index = transcript
        .events
        .iter()
        .position(|event| event.ifc_high_water_label != Label::Public)
        .expect("process_spawn contract must observe its Internal floor");
    assert!(
        matches!(
            &transcript.events[raise_index].kind,
            CellExecutionEventKind::IfcLabelObserved {
                label: Label::Internal
            }
        ),
        "the high-water raise must be the audited process-output observation, got: {:?}",
        transcript.events[raise_index]
    );
    assert!(
        transcript.events[..raise_index]
            .iter()
            .all(|event| event.ifc_high_water_label == Label::Public),
        "pre-observation events must carry Public high-water, got: {:?}",
        &transcript.events[..raise_index]
    );
    assert!(
        transcript.events[raise_index..]
            .iter()
            .all(|event| event.ifc_high_water_label == Label::Internal),
        "post-observation events must stay monotone at the observed floor, got: {:?}",
        &transcript.events[raise_index..]
    );
    let proposals = transcript
        .events
        .iter()
        .filter_map(|event| match &event.kind {
            CellExecutionEventKind::EffectProposed {
                family,
                request_kind,
                required_capability,
                ..
            } => Some((family.as_str(), request_kind.as_str(), *required_capability)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        proposals,
        vec![("process_spawn", "run", RuntimeCapability::ProcessSpawn,)],
        "only the OS dispatch crosses the sealed permit"
    );
}

#[cfg(unix)]
#[test]
fn no_mock_native_hang_times_out_finalizes_and_provider_recovers() {
    let (provider, _) =
        native_process_provider("native-sleep", &["/usr/bin/sleep", "/bin/sleep"], 500);
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());

    let started = Instant::now();
    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('native-sleep', ['5'], { timeout: 25 });",
        ))
        .expect_err("the real sleeping child must hit its requested timeout");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            outcome: Err(ProcessSpawnError::PartialOutputFailed { failure, .. }),
            ..
        }] if matches!(failure.as_ref(), ProcessSpawnError::TimedOut { .. })
    ));
    let failure = error
        .post_cell_failure()
        .expect("the timeout occurred after cell creation");
    assert!(failure.cleanup.close_succeeded());
    let transcript = failure
        .cleanup
        .cell_execution_transcript
        .as_ref()
        .expect("the failed attempt must retain its finalized cell transcript");
    transcript
        .verify()
        .expect("the timeout prefix and cleanup must replay-verify");
    assert!(transcript.events.iter().any(|event| matches!(
        &event.kind,
        CellExecutionEventKind::EffectCompleted { outcome, .. }
            if outcome == "provider_failed"
    )));
    assert!(transcript.events.iter().any(|event| matches!(
        &event.kind,
        CellExecutionEventKind::InterpreterTerminal {
            outcome: CellInterpreterOutcome::Failed
        }
    )));

    let recovery_journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut recovery = ExecutionOrchestrator::new(OrchestratorConfig::default());
    recovery.set_process_spawn(provider, recovery_journal, test_process_authority());
    let recovered = recovery
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('native-sleep', ['0']);",
        ))
        .expect("the same native provider must admit a fresh child after timeout teardown");
    recovered
        .cell_execution_transcript
        .as_ref()
        .expect("recovery run transcript")
        .verify()
        .expect("recovery run must replay-verify");
}

#[cfg(unix)]
#[test]
fn no_mock_native_child_signal_is_audited_and_parent_recovers() {
    let (provider, _) = native_process_provider("native-sh", &["/bin/sh", "/usr/bin/sh"], 2_000);
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('native-sh', ['-c', 'kill -SEGV $$']);",
        ))
        .expect_err("a child fatal signal must fail only the guest execution");
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            outcome: Ok(ProcessSpawnResponse::Run {
                exit: ProcessExit {
                    success: false,
                    signal: Some(_),
                    ..
                },
                ..
            }),
            ..
        }]
    ));
    let failure = error
        .post_cell_failure()
        .expect("the child crash occurred after cell creation");
    assert!(failure.cleanup.close_succeeded());
    failure
        .cleanup
        .cell_execution_transcript
        .as_ref()
        .expect("child crash transcript")
        .verify()
        .expect("child crash and parent cleanup must replay-verify");

    let recovery_journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut recovery = ExecutionOrchestrator::new(OrchestratorConfig::default());
    recovery.set_process_spawn(provider, recovery_journal, test_process_authority());
    let recovered = recovery
        .execute(&process_package(
            "const cp = require('child_process'); console.log(cp.execFileSync('native-sh', ['-c', 'printf recovered'], { encoding: 'utf8' }));",
        ))
        .expect("a fresh child must execute after the prior child crashed");
    assert_eq!(recovered.console_output[0].message, "recovered");
}

#[cfg(target_os = "linux")]
#[test]
fn no_mock_native_descendant_is_gone_before_cell_result_returns() {
    let (provider, _) = native_process_provider("native-sh", &["/bin/sh", "/usr/bin/sh"], 2_000);
    let sleep = unix_executable(&["/usr/bin/sleep", "/bin/sleep"]);
    let command = format!("{} 5 & echo $!", sleep.display());
    let command_literal = serde_json::to_string(&command).expect("encode shell command as JS text");
    let source = format!(
        "const cp = require('child_process'); cp.execFileSync('native-sh', ['-c', {command_literal}], {{ encoding: 'utf8' }});"
    );
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider, journal, test_process_authority());

    let started = Instant::now();
    let result = orchestrator
        .execute(&process_package(&source))
        .expect("the parent shell should exit while its ordinary descendant is contained");
    assert!(started.elapsed() < Duration::from_secs(2));
    let [
        HostEffectJournalEntry::ProcessSpawn {
            outcome: Ok(ProcessSpawnResponse::Run { stdout, .. }),
            ..
        },
    ] = result.host_effect_journal.as_slice()
    else {
        panic!("expected one successful real process journal entry")
    };
    let descendant = String::from_utf8(stdout.clone())
        .expect("shell descendant pid output")
        .trim()
        .parse::<u32>()
        .expect("shell descendant pid");
    let proc_entry = PathBuf::from(format!("/proc/{descendant}"));
    for _ in 0..100 {
        if !proc_entry.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        !proc_entry.exists(),
        "an ordinary descendant must not outlive the returned cell result"
    );
    result
        .cell_execution_transcript
        .as_ref()
        .expect("descendant containment transcript")
        .verify()
        .expect("descendant containment run must replay-verify");
}

#[test]
fn cancellation_during_provider_dispatch_commits_prefix_then_finalizes_once() {
    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let provider = Arc::new(CommitBoundaryProcessSpawn {
        entered: entered_tx,
        release: Mutex::new(release_rx),
        calls: AtomicUsize::new(0),
    });
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let cancellation = CancellationToken::new();
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_cancellation_token(cancellation.clone());
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());

    let worker = std::thread::spawn(move || {
        let error = orchestrator
            .execute(&process_package(
                "const cp = require('child_process'); cp.execFileSync('tool', ['commit-boundary']);",
            ))
            .expect_err("cancellation before provider return must fail the guest run");
        (orchestrator, error)
    });
    if let Err(error) = entered_rx.recv_timeout(Duration::from_secs(10)) {
        let _ = release_tx.send(());
        let _ = worker.join();
        panic!("provider dispatch was not observed: {error}");
    }
    cancellation.cancel();
    release_tx
        .send(())
        .expect("release the already-dispatched provider call");
    let (orchestrator, error) = worker.join().expect("orchestrator worker must not panic");

    assert_eq!(provider.calls.load(Ordering::Acquire), 1);
    assert!(matches!(
        error.primary_error(),
        OrchestratorError::Cell(CellError::ExecutionBoundary {
            error: CellExecutionError::Cancelled,
            ..
        })
    ));
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            outcome: Ok(ProcessSpawnResponse::Run { stdout, .. }),
            ..
        }] if stdout == b"committed-before-cancellation"
    ));
    let failure = error
        .post_cell_failure()
        .expect("the cancelled dispatch must return cell cleanup evidence");
    assert!(failure.cleanup.close_succeeded());
    assert!(failure.additional_errors.is_empty());
    let transcript = failure
        .cleanup
        .cell_execution_transcript
        .as_ref()
        .expect("the cancelled dispatch must retain its exact cell prefix");
    transcript
        .verify()
        .expect("the committed effect and cancellation cleanup must replay-verify");
    assert_eq!(
        transcript
            .events
            .iter()
            .filter(|event| matches!(&event.kind, CellExecutionEventKind::EffectProposed { .. }))
            .count(),
        1,
        "only the already-admitted dispatch may be proposed"
    );
    assert_eq!(
        transcript
            .events
            .iter()
            .filter(|event| matches!(&event.kind, CellExecutionEventKind::EffectCompleted { .. }))
            .count(),
        1,
        "the already-completed provider effect must not become commit-unknown"
    );
    assert!(!transcript.events.iter().any(|event| matches!(
        &event.kind,
        CellExecutionEventKind::InterpreterBudgetSettled { .. }
    )));
    assert_eq!(
        transcript
            .events
            .iter()
            .filter(|event| matches!(&event.kind, CellExecutionEventKind::Finalized))
            .count(),
        1,
        "cell cleanup must finalize exactly once"
    );
}

#[cfg(unix)]
#[test]
fn cancellation_reaps_a_real_blocking_child_before_the_policy_timeout() {
    let (provider, _) = native_process_provider("native-sh", &["/bin/sh", "/usr/bin/sh"], 30_000);
    let temp_dir = tempfile::tempdir().expect("create cancellation marker directory");
    let marker = temp_dir.path().join("child-started");
    let sleep = unix_executable(&["/usr/bin/sleep", "/bin/sleep"]);
    let command = format!(": > '{}'; exec '{}' 30", marker.display(), sleep.display());
    let command_literal =
        serde_json::to_string(&command).expect("encode cancellation shell command");
    let source = format!(
        "const cp = require('child_process'); cp.execFileSync('native-sh', ['-c', {command_literal}]);"
    );
    let cancellation = CancellationToken::new();
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_cancellation_token(cancellation.clone());
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());

    let worker = std::thread::spawn(move || {
        let error = orchestrator
            .execute(&process_package(&source))
            .expect_err("cancelling a live native Run must fail the guest execution");
        (orchestrator, error)
    });
    let marker_deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() && Instant::now() < marker_deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    if !marker.exists() {
        cancellation.cancel();
        let _ = worker.join();
        panic!("native child did not reach its start marker");
    }

    let cancelled_at = Instant::now();
    cancellation.cancel();
    let (orchestrator, error) = worker
        .join()
        .expect("native cancellation worker must not panic");
    assert!(
        cancelled_at.elapsed() < Duration::from_secs(2),
        "cooperative native cancellation must beat the 30 second process policy timeout"
    );
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [HostEffectJournalEntry::ProcessSpawn {
            outcome: Err(ProcessSpawnError::Denied { reason }),
            ..
        }] if reason == "PROCESS_SPAWN_EXECUTION_CANCELLED"
    ));
    error
        .post_cell_failure()
        .expect("native cancellation occurs after cell creation")
        .cleanup
        .cell_execution_transcript
        .as_ref()
        .expect("native cancellation must retain a cell transcript")
        .verify()
        .expect("native cancellation transcript must replay-verify");

    let recovery_journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut recovery = ExecutionOrchestrator::new(OrchestratorConfig::default());
    recovery.set_process_spawn(provider, recovery_journal, test_process_authority());
    recovery
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('native-sh', ['-c', 'exit 0']);",
        ))
        .expect("max_children=1 must be reusable immediately after cancellation teardown");
}

#[test]
fn async_spawn_facade_delivers_stream_and_exit_events_after_registration() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"async-output"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());
    let mut package = process_package(
        "const cp = require('child_process'); const child = cp.spawn('tool', ['alpha']); child.on('spawn', () => console.log('spawn')); child.stdout.on('data', chunk => console.log('data:' + chunk)); child.on('exit', code => console.log('exit:' + code)); setTimeout(() => console.log('timer'), 0);",
    );
    package.capabilities.push("timer".to_string());

    let result = orchestrator
        .execute(&package)
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
        vec!["spawn", "data:async-output", "exit:0", "timer"]
    );
    assert_eq!(result.host_effect_journal.len(), 2);
}

#[test]
fn async_spawn_with_empty_output_does_not_fabricate_stream_data() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b""));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());

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
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());
    let mut package = process_package(
        "const cp = require('child_process'); cp.execFile('tool', ['alpha'], { encoding: 'utf8' }, (error, stdout, stderr) => console.log(String(error) + ':' + stdout + ':' + stderr));",
    );
    package.capabilities.push("builtin".to_string());

    let result = orchestrator
        .execute(&package)
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
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.spawn('tool', ['alpha']);",
        ))
        .expect_err("an unhandled child error must fail the execution");

    assert!(
        error
            .to_string()
            .contains("process spawn denied: redacted reason")
    );
    assert!(!error.to_string().contains("test policy denied"));
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
    orchestrator.set_process_spawn(provider, journal, test_process_authority());

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('tool', ['alpha']);",
        ))
        .expect_err("provider denial should abort an uncaught synchronous call");
    assert!(
        error
            .to_string()
            .contains("process spawn denied: redacted reason")
    );
    assert!(!error.to_string().contains("test policy denied"));
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
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.execFileSync('tool', ['alpha']);",
        ))
        .expect_err("unused replay suffix must fail finalization");
    assert!(error.to_string().contains("unused entries"));
    assert_eq!(
        orchestrator.last_failed_host_effect_journal(),
        std::slice::from_ref(&recorded)
    );
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal_records(),
        [HostEffectJournalAttemptRecord::Completed {
            sequence: 0,
            entry
        }] if entry == &recorded
    ));
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
fn replay_is_independent_of_live_process_expiry_and_provider_dispatch() {
    let recorded = HostEffectJournalEntry::ProcessSpawn {
        request: expected_run_request(),
        outcome: Ok(ProcessSpawnResponse::Run {
            exit: ProcessExit {
                success: true,
                code: Some(0),
                signal: None,
            },
            stdout: b"replayed-after-expiry".to_vec(),
            stderr: Vec::new(),
        }),
    };
    let journal = Arc::new(InMemoryHostEffectJournal::replaying(vec![recorded]));
    let provider = Arc::new(RecordingProcessSpawn::successful(b"must-not-run"));
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(
        provider.clone(),
        journal,
        ProcessSpawnAttemptAuthority::expiring_at_unix_ms(0),
    );

    let result = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); console.log(cp.execFileSync('tool', ['alpha'], { encoding: 'utf8' }));",
        ))
        .expect("replay must not consult live process expiry");

    assert_eq!(result.console_output[0].message, "replayed-after-expiry");
    assert!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .is_empty(),
        "replay must never invoke the live provider"
    );
}

#[test]
fn cleanup_failure_is_typed_journaled_and_preserves_the_effect_prefix() {
    let provider = Arc::new(CleanupFailingProcessSpawn);
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider, journal, test_process_authority());

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); cp.spawn('tool', ['alpha']);",
        ))
        .expect_err("an injected cleanup failure must fail the execution");
    assert!(error.to_string().contains("cleanup"));
    assert!(matches!(
        orchestrator.last_failed_host_effect_journal(),
        [
            HostEffectJournalEntry::ProcessSpawn {
                request: ProcessSpawnRequest::Spawn { .. },
                outcome: Ok(ProcessSpawnResponse::Spawned { .. }),
            },
            HostEffectJournalEntry::ProcessSpawn {
                request: ProcessSpawnRequest::Wait { .. },
                outcome: Ok(ProcessSpawnResponse::StdinClosed),
            },
            HostEffectJournalEntry::ProcessSpawn {
                request: ProcessSpawnRequest::Cleanup { .. },
                outcome: Err(ProcessSpawnError::Io { operation, .. }),
            },
        ] if operation == "injected cleanup"
    ));
}

#[test]
fn non_public_request_data_is_blocked_before_the_provider() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"must-not-run"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());

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
fn non_public_mutation_of_a_public_options_alias_is_blocked_by_static_flow_proof() {
    let provider = Arc::new(RecordingProcessSpawn::successful(b"must-not-run"));
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider.clone(), journal, test_process_authority());

    let error = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); const opts = {}; const alias = opts; alias.cwd = 'secret-tool'; cp.execFileSync('tool', [], opts);",
        ))
        .expect_err("mutating an aliased public options object must not launder its label");

    let primary_error = error.primary_error();
    assert!(
        matches!(
            primary_error,
            OrchestratorError::Lowering(lowering_error)
                if matches!(
                    lowering_error.as_ref(),
                    LoweringPipelineError::UnauthorizedFlow {
                        source_label: Label::Secret,
                        sink_clearance: Label::Internal,
                        ..
                    }
                )
        ),
        "static IFC denial must retain its typed lowering error, got {primary_error:?}"
    );
    assert!(
        provider
            .seen
            .lock()
            .expect("recording provider mutex")
            .is_empty(),
        "static IFC denial must occur before the native provider"
    );
    assert!(
        orchestrator.last_failed_host_effect_journal().is_empty(),
        "static IFC denial must happen before a host-effect request exists"
    );
}

#[cfg(unix)]
#[test]
fn child_kill_flips_killed_flag_and_reports_exit_bd_m42c2() {
    // Mirror of franken_node compat fixture 0012.
    let (provider, _) = native_process_provider("native-sh", &["/bin/sh", "/usr/bin/sh"], 30_000);
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider, journal, test_process_authority());

    let result = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); \
             const c = cp.spawn('native-sh', ['-c', 'sleep 30'], { stdio: 'ignore' }); \
             c.on('spawn', () => { \
                 console.log('killed-before:' + c.killed); \
                 const ok = c.kill(); \
                 console.log('kill-returned:' + ok); \
                 console.log('killed-after:' + c.killed); \
             }); \
             c.on('exit', () => console.log('exited:true'));",
        ))
        .expect("kill during the spawn turn must complete the lifecycle");

    assert_eq!(
        result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect::<Vec<_>>(),
        vec![
            "killed-before:false",
            "kill-returned:true",
            "killed-after:true",
            "exited:true",
        ]
    );
}

#[cfg(unix)]
#[test]
fn child_kill_reports_sigterm_in_exit_event_bd_m42c2() {
    // Mirror of franken_node compat fixture 0022.
    let (provider, _) = native_process_provider("native-sh", &["/bin/sh", "/usr/bin/sh"], 30_000);
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider, journal, test_process_authority());

    let result = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); \
             const c = cp.spawn('native-sh', ['-c', 'sleep 30'], { stdio: 'ignore' }); \
             c.on('spawn', () => c.kill()); \
             c.on('exit', (code, signal) => { \
                 console.log('code:' + code); \
                 console.log('signal:' + signal); \
             });",
        ))
        .expect("a terminated child must report code null and signal SIGTERM");

    assert_eq!(
        result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect::<Vec<_>>(),
        vec!["code:null", "signal:SIGTERM"]
    );
}

#[cfg(unix)]
#[test]
fn child_stdin_write_and_end_round_trip_bd_m42c2() {
    // Mirror of franken_node compat fixture 0029.
    let (provider, _) =
        native_process_provider("native-cat", &["/bin/cat", "/usr/bin/cat"], 30_000);
    let journal = Arc::new(InMemoryHostEffectJournal::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_process_spawn(provider, journal, test_process_authority());

    let result = orchestrator
        .execute(&process_package(
            "const cp = require('child_process'); \
             const c = cp.spawn('native-cat'); \
             let buf = ''; \
             c.stdout.on('data', (d) => { buf += d.toString(); }); \
             c.on('close', () => console.log('roundtrip:' + buf.trim())); \
             c.stdin.write('through-stdin'); \
             c.stdin.end();",
        ))
        .expect("bounded stdin write plus end must round-trip through cat");

    assert_eq!(
        result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect::<Vec<_>>(),
        vec!["roundtrip:through-stdin"]
    );
}
