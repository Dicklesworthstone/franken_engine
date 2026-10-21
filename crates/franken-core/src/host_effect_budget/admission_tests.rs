//! Exercise the production admission decorators with controlled provider seams.
//! These tests do not claim native process isolation or completed OS teardown.

use super::*;
use crate::ast::ParseGoal;
use crate::baseline_interpreter::InterpreterConfig;
use crate::capability::RuntimeCapability;
use crate::ir_contract::{Ir0Module, Ir3Module};
use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use crate::parser::{CanonicalEs2020Parser, Es2020Parser};
use frankenengine_extension_host::host_io::HostIoResponse;
use frankenengine_extension_host::process_spawn::{
    ProcessExit, ProcessLaunch, ProcessSpawnCapability, ProcessSpawnControl, ProcessSpawnError,
    ProcessSpawnOutcome, ProcessSpawnProvider, ProcessSpawnRequest, ProcessSpawnResponse,
    ProcessStdio,
};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

const IO: &[HostIoCapability] = &[HostIoCapability::FsRead];
const PROCESS: &[ProcessSpawnCapability] = &[ProcessSpawnCapability::Spawn];
const WAIT: Duration = Duration::from_secs(5);

fn config(instructions: u64) -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = instructions;
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn module(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("admission-lifetime source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "admission-lifetime.js"),
        &LoweringContext::new("admission-lifetime", "admission-lifetime", "admission-lifetime"),
    )
    .expect("admission-lifetime source must lower")
    .ir3
}

fn effects(operations: u64, max_in_flight: usize) -> HostEffectWorkPool {
    HostEffectWorkPool::new(HostEffectLimits {
        operations,
        max_in_flight,
    })
}

fn read() -> HostIoRequest {
    HostIoRequest::FsRead {
        path: "input".into(),
    }
}

fn launch() -> ProcessLaunch {
    ProcessLaunch {
        executable: "admission-probe".into(),
        argv: Vec::new(),
        env: BTreeMap::new(),
        cwd: None,
        shell: false,
        stdio: ProcessStdio::default(),
    }
}

fn run() -> ProcessSpawnRequest {
    ProcessSpawnRequest::Run {
        launch: launch(),
        stdin: Vec::new(),
        timeout_millis: Some(1000),
    }
}

fn process_success() -> ProcessSpawnResponse {
    ProcessSpawnResponse::Run {
        exit: ProcessExit {
            success: true,
            code: Some(0),
            signal: None,
        },
        stdout: vec![7],
        stderr: Vec::new(),
    }
}

fn io_denied(result: HostIoOutcome, code: &str) {
    assert!(matches!(result, Err(HostIoError::Denied { reason }) if reason == code));
}

fn process_denied(result: ProcessSpawnOutcome) {
    assert!(matches!(
        result,
        Err(ProcessSpawnError::Denied { reason }) if reason == "HOST_EFFECT_SCOPE_REVOKED"
    ));
}

#[derive(Default)]
struct Probe {
    io_calls: AtomicUsize,
    process_calls: AtomicUsize,
    cleanups: AtomicUsize,
    io_control: Mutex<Option<Arc<dyn HostIoControl>>>,
    process_control: Mutex<Option<Arc<dyn ProcessSpawnControl>>>,
    cancel_during_call: Option<ExecutionTaskControl>,
    fail_process: bool,
}

impl fmt::Debug for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmissionProbe").finish_non_exhaustive()
    }
}

impl Probe {
    fn cancel(&self) {
        if let Some(control) = &self.cancel_during_call {
            control.cancel();
        }
    }

    fn assert_forwarded_controls_closed(&self) {
        assert!(
            self.io_control
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .checkpoint()
                .is_err()
        );
        assert!(
            self.process_control
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .checkpoint()
                .is_err()
        );
    }
}

impl HostIoProvider for Probe {
    fn name(&self) -> &str {
        "admission-io-probe"
    }

    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("the decorator must forward its live control")
    }

    fn perform_controlled(
        &self,
        _: &HostIoRequest,
        _: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        control.checkpoint()?;
        self.io_calls.fetch_add(1, Ordering::SeqCst);
        *self.io_control.lock().unwrap() = Some(control);
        self.cancel();
        Ok(HostIoResponse::FsRead { bytes: vec![7] })
    }
}

impl ProcessSpawnProvider for Probe {
    fn name(&self) -> &str {
        "admission-process-probe"
    }

    fn perform(
        &self,
        _: &ProcessSpawnRequest,
        _: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        panic!("the decorator must forward its live control")
    }

    fn perform_controlled(
        &self,
        request: &ProcessSpawnRequest,
        _: &[ProcessSpawnCapability],
        control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        control.checkpoint()?;
        self.process_calls.fetch_add(1, Ordering::SeqCst);
        *self.process_control.lock().unwrap() = Some(control);
        self.cancel();
        if self.fail_process {
            return Err(ProcessSpawnError::TimedOut { runtime_millis: 1 });
        }
        if matches!(request, ProcessSpawnRequest::Spawn { .. }) {
            Ok(ProcessSpawnResponse::Spawned {
                handle: "owned-child".into(),
            })
        } else {
            Ok(process_success())
        }
    }

    fn cleanup_handle(&self, handle: &str) -> ProcessSpawnOutcome {
        assert_eq!(handle, "owned-child");
        self.cleanups.fetch_add(1, Ordering::SeqCst);
        Ok(ProcessSpawnResponse::Cleaned { was_present: true })
    }
}

#[test]
fn discarded_queue_entry_denies_both_providers_before_any_effect_debit() {
    let work = ExecutionWorkPool::new(256);
    let job = work.reserve(128).unwrap();
    let budget = effects(3, 1);
    let inner = Arc::new(Probe::default());
    let io = budget.bind_host_io_for_admission(inner.clone(), &job);
    let process = budget.bind_process_spawn_for_admission(inner.clone(), &job);
    let escaped = job.execution_cancellation().unwrap();
    drop(job);
    escaped.reset();
    io_denied(io.perform(&read(), IO), "HOST_EFFECT_SCOPE_REVOKED");
    io_denied(io.clone().perform(&read(), IO), "HOST_EFFECT_SCOPE_REVOKED");
    process_denied(process.perform(&run(), PROCESS));
    assert_eq!(inner.io_calls.load(Ordering::SeqCst), 0);
    assert_eq!(inner.process_calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.snapshot().unwrap().remaining_operations, 3);
    assert_eq!(work.remaining(), 128);
    assert!(!work.is_revoked());
}

#[test]
fn one_task_cancellation_does_not_revoke_sibling_provider_bindings() {
    let work = ExecutionWorkPool::new(512);
    let first = work.reserve(128).unwrap();
    let sibling = work.reserve(128).unwrap();
    let budget = effects(6, 2);
    let inner = Arc::new(Probe::default());
    let first_io = budget.bind_host_io_for_admission(inner.clone(), &first);
    let first_process = budget.bind_process_spawn_for_admission(inner.clone(), &first);
    let sibling_io = budget.bind_host_io_for_admission(inner.clone(), &sibling);
    let sibling_process = budget.bind_process_spawn_for_admission(inner.clone(), &sibling);
    first_io.perform(&read(), IO).unwrap();
    first_process.perform(&run(), PROCESS).unwrap();
    first.task_control().cancel();
    inner.assert_forwarded_controls_closed();
    io_denied(first_io.perform(&read(), IO), "HOST_EFFECT_SCOPE_REVOKED");
    process_denied(first_process.perform(&run(), PROCESS));
    sibling_io.perform(&read(), IO).unwrap();
    sibling_process.perform(&run(), PROCESS).unwrap();
    assert!(!work.is_revoked());
    assert!(!sibling.task_control().is_cancelled());
    assert_eq!(budget.snapshot().unwrap().committed_operations, 4);
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
    assert_eq!(work.remaining(), 256);
}

#[test]
fn synchronous_native_completion_closes_retained_io_and_process_controls() {
    let work = ExecutionWorkPool::new(256);
    let job = work.reserve(128).unwrap();
    let budget = effects(4, 2);
    let inner = Arc::new(Probe::default());
    let io = budget.bind_host_io_for_admission(inner.clone(), &job);
    let process = budget.bind_process_spawn_for_admission(inner.clone(), &job);
    io.perform(&read(), IO).unwrap();
    process.perform(&run(), PROCESS).unwrap();
    job.execute(&module("7;"), config(128), "effect-lifetime")
        .unwrap();
    inner.assert_forwarded_controls_closed();
    io_denied(io.perform(&read(), IO), "HOST_EFFECT_SCOPE_REVOKED");
    process_denied(process.perform(&run(), PROCESS));
    assert_eq!(budget.snapshot().unwrap().committed_operations, 2);
    assert_eq!(inner.io_calls.load(Ordering::SeqCst), 1);
    assert_eq!(inner.process_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn rejection_before_vm_construction_closes_admission_bound_providers() {
    let work = ExecutionWorkPool::new(128);
    let job = work.reserve(128).unwrap();
    let budget = effects(2, 1);
    let inner = Arc::new(Probe::default());
    let io = budget.bind_host_io_for_admission(inner.clone(), &job);
    let process = budget.bind_process_spawn_for_admission(inner, &job);
    assert!(matches!(
        job.execute(&module("7;"), config(0), "effect-rejected"),
        Err(crate::execution_work_budget::WorkBudgetError::ZeroInstructionBudget)
    ));
    io_denied(io.perform(&read(), IO), "HOST_EFFECT_SCOPE_REVOKED");
    process_denied(process.perform(&run(), PROCESS));
    assert_eq!(budget.snapshot().unwrap().committed_operations, 0);
    assert_eq!(work.remaining(), 0);
}

#[test]
fn late_io_cancellation_denies_success_without_refunding_work() {
    let work = ExecutionWorkPool::new(128);
    let job = work.reserve(128).unwrap();
    let budget = effects(2, 1);
    let inner = Arc::new(Probe {
        cancel_during_call: Some(job.task_control()),
        ..Probe::default()
    });
    let io = budget.bind_host_io_for_admission(inner.clone(), &job);
    io_denied(io.perform(&read(), IO), "HOST_EFFECT_SCOPE_REVOKED");
    assert_eq!(inner.io_calls.load(Ordering::SeqCst), 1);
    assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
    io_denied(io.perform(&read(), IO), "HOST_EFFECT_SCOPE_REVOKED");
    assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
}

#[test]
fn late_process_run_cancellation_denies_success_without_refunding_work() {
    let work = ExecutionWorkPool::new(128);
    let job = work.reserve(128).unwrap();
    let budget = effects(2, 1);
    let inner = Arc::new(Probe {
        cancel_during_call: Some(job.task_control()),
        ..Probe::default()
    });
    let provider = budget.bind_process_spawn_for_admission(inner.clone(), &job);
    process_denied(provider.perform(&run(), PROCESS));
    assert_eq!(inner.process_calls.load(Ordering::SeqCst), 1);
    assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
}

#[test]
fn late_spawn_cancellation_preserves_owned_handle_and_trusted_cleanup() {
    let work = ExecutionWorkPool::new(128);
    let job = work.reserve(128).unwrap();
    let budget = effects(1, 1);
    let inner = Arc::new(Probe {
        cancel_during_call: Some(job.task_control()),
        ..Probe::default()
    });
    let provider = budget.bind_process_spawn_for_admission(inner.clone(), &job);
    let result = provider
        .perform(&ProcessSpawnRequest::Spawn { launch: launch() }, PROCESS)
        .unwrap();
    let ProcessSpawnResponse::Spawned { handle } = result else {
        panic!("the real returned handle must reach the effect journal")
    };
    assert!(job.task_control().is_cancelled());
    assert!(
        inner
            .process_control
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .checkpoint()
            .is_err()
    );
    drop(job);
    process_denied(provider.perform(&run(), PROCESS));
    assert_eq!(
        provider.cleanup_handle(&handle),
        Ok(ProcessSpawnResponse::Cleaned { was_present: true })
    );
    assert!(
        provider
            .perform(&ProcessSpawnRequest::Cleanup { handle }, PROCESS)
            .is_err()
    );
    assert_eq!(inner.cleanups.load(Ordering::SeqCst), 1);
    assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
}

#[test]
fn native_process_failure_is_not_erased_by_a_racing_task_cancellation() {
    let work = ExecutionWorkPool::new(128);
    let job = work.reserve(128).unwrap();
    let budget = effects(1, 1);
    let inner = Arc::new(Probe {
        cancel_during_call: Some(job.task_control()),
        fail_process: true,
        ..Probe::default()
    });
    let provider = budget.bind_process_spawn_for_admission(inner, &job);
    assert_eq!(
        provider.perform(&run(), PROCESS),
        Err(ProcessSpawnError::TimedOut { runtime_millis: 1 })
    );
    assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
}

#[test]
fn admission_binding_does_not_grant_missing_effect_capabilities() {
    let work = ExecutionWorkPool::new(128);
    let job = work.reserve(128).unwrap();
    let budget = effects(2, 1);
    let inner = Arc::new(Probe::default());
    let io = budget.bind_host_io_for_admission(inner.clone(), &job);
    let process = budget.bind_process_spawn_for_admission(inner.clone(), &job);
    assert!(matches!(
        io.perform(&read(), &[]),
        Err(HostIoError::CapabilityMissing { .. })
    ));
    assert!(matches!(
        process.perform(&run(), &[]),
        Err(ProcessSpawnError::CapabilityMissing { .. })
    ));
    assert_eq!(inner.io_calls.load(Ordering::SeqCst), 0);
    assert_eq!(inner.process_calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.snapshot().unwrap().committed_operations, 0);
}

#[test]
fn instruction_ancestors_and_effect_pool_still_revoke_admission_bindings() {
    for revoke_effects in [false, true] {
        let root = ExecutionWorkPool::new(256);
        let child = root.partition(128).unwrap();
        let job = child.reserve(128).unwrap();
        let budget = effects(2, 1);
        let inner = Arc::new(Probe::default());
        let io = budget.bind_host_io_for_admission(inner.clone(), &job);
        let process = budget.bind_process_spawn_for_admission(inner.clone(), &job);
        if revoke_effects {
            budget.revoke();
        } else {
            root.revoke();
        }
        io_denied(io.perform(&read(), IO), "HOST_EFFECT_SCOPE_REVOKED");
        process_denied(process.perform(&run(), PROCESS));
        assert_eq!(budget.snapshot().unwrap().committed_operations, 0);
        assert_eq!(inner.io_calls.load(Ordering::SeqCst), 0);
        assert_eq!(inner.process_calls.load(Ordering::SeqCst), 0);
    }
}

#[derive(Debug)]
struct ParkedProcess {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
}

impl ProcessSpawnProvider for ParkedProcess {
    fn name(&self) -> &str {
        "parked-admission-process"
    }

    fn perform(
        &self,
        _: &ProcessSpawnRequest,
        _: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        panic!("the decorator must forward its live control")
    }

    fn perform_controlled(
        &self,
        _: &ProcessSpawnRequest,
        _: &[ProcessSpawnCapability],
        control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        control.checkpoint()?;
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(WAIT).unwrap();
        control.checkpoint()?;
        Ok(process_success())
    }

    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome {
        panic!("a run-only probe owns no child to clean up")
    }
}

#[test]
fn cancelling_active_process_does_not_release_concurrency_before_callback_returns() {
    let work = ExecutionWorkPool::new(256);
    let job = work.reserve(128).unwrap();
    let sibling = work.reserve(128).unwrap();
    let budget = effects(3, 1);
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    let process = budget.bind_process_spawn_for_admission(
        Arc::new(ParkedProcess {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }),
        &job,
    );
    let inner = Arc::new(Probe::default());
    let io = budget.bind_host_io_for_admission(inner.clone(), &sibling);
    let worker = std::thread::spawn(move || process.perform(&run(), PROCESS).map_err(Box::new));
    entered.recv_timeout(WAIT).unwrap();
    job.task_control().cancel();
    let blocked = io.perform(&read(), IO);
    let during = budget.snapshot().unwrap();
    release.send(()).unwrap();
    let outcome = worker.join().unwrap().map_err(|error| *error);
    io_denied(blocked, "HOST_EFFECT_CONCURRENCY_LIMIT");
    process_denied(outcome);
    assert_eq!(during.in_flight, 1);
    assert_eq!(during.committed_operations, 1);
    assert_eq!(inner.io_calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
    io.perform(&read(), IO).unwrap();
    assert_eq!(budget.snapshot().unwrap().committed_operations, 2);
    assert!(!sibling.task_control().is_cancelled());
    assert!(!work.is_revoked());
}
