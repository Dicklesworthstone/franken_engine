#![forbid(unsafe_code)]
//! Live deadline propagation through the canonical core execution boundaries.
//! Host-clock cancellation is deliberately not a deterministic replay clock.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    AllocKind, FunctionRef, HookAction, HookContext, InterpreterConfig, InterpreterError,
    InterpreterHook, LaneChoice, ObjectRef, PropertyKey, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::checkpoint::{
    CancellationToken, CheckpointAction, CheckpointGuard, CheckpointReason, DensityConfig, LoopSite,
};
use frankenengine_core::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use frankenengine_core::execution_work_budget::{
    BudgetedInterpreter, ExecutionWorkPool, WorkBudgetError,
};
use frankenengine_core::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};
use frankenengine_core::runtime_config::RuntimeConfig;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn future() -> Instant {
    Instant::now().checked_add(Duration::from_secs(3600)).unwrap()
}

fn wait_until(deadline: Instant) {
    // Sleep against the absolute boundary, not a guessed scheduler delay.
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        if remaining.is_zero() {
            break;
        }
        std::thread::sleep(remaining);
    }
}

fn config(throughput: bool, budget: u64) -> InterpreterConfig {
    let mut config = if throughput {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.instruction_budget = budget;
    config.checkpoint_density = 1;
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn module(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser.parse(source, ParseGoal::Script).unwrap();
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "deadline.js"),
        &LoweringContext::new("deadline", "deadline", "deadline"),
    )
    .unwrap()
    .ir3
}

#[test]
fn children_and_links_keep_the_earliest_absolute_deadline() {
    let first = future();
    let later = first.checked_add(Duration::from_secs(60)).unwrap();
    let root = CancellationToken::new().with_deadline(first);
    let other = CancellationToken::new().with_deadline(later);
    let plain = CancellationToken::new();
    for derived in [
        root.clone(),
        root.child_token(),
        root.with_deadline(later),
        root.linked_with(&other),
        other.linked_with(&root),
        plain.linked_with(&root),
        root.linked_with(&plain),
    ] {
        assert_eq!(derived.deadline(), Some(first));
        assert!(!derived.is_cancelled());
    }
    assert_eq!(plain.deadline(), None);
    assert_eq!(other.deadline(), Some(later));
    let mut leaf = root.clone();
    for _ in 0..64 {
        leaf = leaf.linked_with(&leaf).child_token();
        assert_eq!(leaf.deadline(), Some(first));
    }
}

#[test]
fn expired_deadlines_cannot_be_reset_but_do_not_revoke_siblings() {
    let parent = CancellationToken::new();
    let sibling = parent.child_token();
    let expired = parent.with_deadline(Instant::now());
    let late = future();
    for token in [
        expired.clone(),
        expired.child_token(),
        expired.with_deadline(late),
        sibling.linked_with(&expired),
    ] {
        token.reset();
        assert!(token.is_cancelled());
        assert!(token.deadline().unwrap() < late);
    }
    assert!(!parent.is_cancelled());
    assert!(!sibling.is_cancelled());
    parent.cancel();
    assert!(sibling.is_cancelled());
    parent.reset();
    assert!(!sibling.is_cancelled(), "deadline-free reuse stays unchanged");
    assert!(expired.is_cancelled());
}

#[test]
fn caller_cancellation_stays_live_when_a_deadline_is_added() {
    let caller = CancellationToken::new();
    let scope = CancellationToken::new().with_deadline(future());
    let combined = scope.linked_with(&caller);
    caller.cancel();
    assert!(combined.is_cancelled());
    combined.reset();
    assert!(combined.is_cancelled());
    caller.reset();
    assert!(!combined.is_cancelled());
    combined.cancel();
    assert!(!caller.is_cancelled());
    assert!(!scope.is_cancelled());
    assert_eq!(combined.deadline(), scope.deadline());
}

#[test]
fn deadline_expiry_uses_existing_checkpoint_drain_and_event_precedence() {
    for explicit in [false, true] {
        let mut guard = CheckpointGuard::new(
            LoopSite::BytecodeDispatch,
            "deadline",
            "deadline-trace",
            DensityConfig { max_iterations: 1, max_total_iterations: 1 },
            CancellationToken::new().with_deadline(Instant::now()),
        );
        guard.tick();
        let action = if explicit { guard.explicit_checkpoint() } else { guard.check() };
        assert_eq!(action, CheckpointAction::Drain);
        let events = guard.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].reason, CheckpointReason::CancelPending);
        assert_eq!(events[0].timestamp_virtual, 1);
    }
}

#[test]
fn serialized_tokens_do_not_claim_to_restore_live_deadlines() {
    let token = CancellationToken::new().with_deadline(Instant::now());
    let encoded = serde_json::to_string(&token).unwrap();
    assert_eq!(encoded, "{}");
    let restored: CancellationToken = serde_json::from_str(&encoded).unwrap();
    assert_eq!(restored.deadline(), None);
    assert!(token.is_cancelled());
    // The restored token owns no original live signal or execution admission.
}

#[test]
fn pool_clones_partitions_and_queued_signals_keep_the_same_deadline() {
    let end = future();
    let root = ExecutionWorkPool::with_deadline(512, 2, end);
    let tenant = root.partition(256).unwrap();
    let cell = tenant.partition(128).unwrap();
    let job = cell.reserve(64).unwrap();
    let signal = job.execution_cancellation().unwrap();
    for pool in [&root, &tenant, &cell, &cell.clone()] {
        assert_eq!(pool.deadline(), Some(end));
        assert_eq!(pool.outstanding_admissions(), 1);
    }
    assert_eq!(signal.deadline(), Some(end));
    assert_eq!(ExecutionWorkPool::new(1).deadline(), None);
    assert_eq!(ExecutionWorkPool::with_admission_limit(1, 1).deadline(), None);
    root.revoke();
    signal.reset();
    assert!(signal.is_cancelled());
    assert_eq!(root.outstanding_admissions(), 1);
    drop(job);
    assert_eq!(root.outstanding_admissions(), 0);
    assert_eq!(cell.remaining(), 64);
}

#[test]
fn expired_roots_refuse_before_debit_capacity_or_native_initialization() {
    let pool = ExecutionWorkPool::with_deadline(128, 0, Instant::now());
    for amount in [0, 1, 128] {
        assert!(matches!(pool.reserve(amount), Err(WorkBudgetError::Revoked)));
        assert!(matches!(pool.partition(amount), Err(WorkBudgetError::Revoked)));
    }
    for throughput in [false, true] {
        assert!(matches!(
            BudgetedInterpreter::new(pool.clone(), config(throughput, 128), "expired"),
            Err(WorkBudgetError::Revoked)
        ));
    }
    assert_eq!(pool.remaining(), 128);
    assert_eq!(pool.outstanding_admissions(), 0);
}

#[test]
fn queued_expiry_does_not_renew_time_refund_fuel_or_free_a_held_slot() {
    let source = module("42;");
    let end = Instant::now().checked_add(Duration::from_millis(100)).unwrap();
    let pool = ExecutionWorkPool::with_deadline(256, 1, end);
    let job = pool.reserve(128).unwrap();
    let control = job.task_control();
    wait_until(end);
    assert!(pool.is_revoked());
    assert!(control.is_cancelled());
    assert_eq!(pool.outstanding_admissions(), 1);
    assert_eq!(pool.remaining(), 128);
    assert!(matches!(job.execute(&source, config(false, 128), "queued"), Err(WorkBudgetError::Revoked)));
    assert_eq!(pool.outstanding_admissions(), 0);
    assert_eq!(pool.remaining(), 128);
}

#[test]
fn earlier_caller_deadline_reaches_both_native_profiles_without_refund() {
    let source = module("while (true) {}");
    for throughput in [false, true] {
        let pool = ExecutionWorkPool::with_deadline(256, 1, future());
        let caller = CancellationToken::new().with_deadline(Instant::now());
        let mut current = config(throughput, 128);
        current.cancellation_token = Some(caller.clone());
        let mut vm = BudgetedInterpreter::new(pool.clone(), current, "caller-deadline").unwrap();
        assert!(matches!(vm.execute(&source), Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled))));
        assert_eq!(pool.remaining(), 128);
        assert_eq!(pool.outstanding_admissions(), 0);
        assert!(!pool.is_revoked());
        caller.reset();
        assert!(caller.is_cancelled());
    }
}

struct ExpireAtAllocation {
    deadline: Instant,
    calls: AtomicUsize,
}

impl InterpreterHook for ExpireAtAllocation {
    fn pre_property_access(&self, _: &HookContext, _: &ObjectRef, _: &PropertyKey) -> HookAction {
        HookAction::Allow
    }
    fn pre_call(&self, _: &HookContext, _: &FunctionRef, _: &[Value]) -> HookAction {
        HookAction::Allow
    }
    fn pre_allocation(&self, _: &HookContext, _: AllocKind, _: usize) -> HookAction {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            wait_until(self.deadline);
        }
        HookAction::Allow
    }
    fn pre_import(&self, _: &HookContext, _: &str) -> HookAction {
        HookAction::Allow
    }
}

#[test]
fn active_native_execution_observes_expiry_without_an_external_cancel_thread() {
    let source = module("let object = {}; while (true) {}");
    for throughput in [false, true] {
        // Parse/lower before starting the live deadline. The actual native hook
        // holds execution until expiry; no guessed loop timing or instruction
        // exhaustion stands in for the deadline check.
        let end = Instant::now().checked_add(Duration::from_secs(2)).unwrap();
        let pool = ExecutionWorkPool::with_deadline(256, 1, end);
        let hook = Arc::new(ExpireAtAllocation { deadline: end, calls: AtomicUsize::new(0) });
        let mut vm = BudgetedInterpreter::new(pool.clone(), config(throughput, 128), "active-deadline").unwrap();
        vm.set_hook(hook.clone());
        assert!(matches!(vm.execute(&source), Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled))));
        assert!(hook.calls.load(Ordering::SeqCst) > 0, "must exercise the actual native hook");
        assert!(pool.is_revoked());
        assert_eq!(pool.outstanding_admissions(), 0);
        assert_eq!(pool.remaining(), 128);
        assert!(matches!(vm.execute(&source), Err(WorkBudgetError::Revoked)));
        assert_eq!(pool.remaining(), 128);
    }
}

#[test]
fn ordinary_orchestration_preserves_cell_cleanup_after_deadline_refusal() {
    let package = ExtensionPackage {
        extension_id: "deadline-orchestrator".into(),
        source: "42;".into(),
        source_file: None,
        capabilities: Vec::new(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        let pool = ExecutionWorkPool::with_deadline(256, 1, Instant::now());
        let mut runtime = RuntimeConfig::default();
        runtime.execution.deterministic_budget = 128;
        runtime.execution.throughput_budget = 128;
        let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
            OrchestratorConfig { force_lane: lane, work_pool: Some(pool.clone()), ..OrchestratorConfig::default() },
            runtime,
        ).unwrap();
        let error = orchestrator.execute(&package).unwrap_err();
        assert!(matches!(error.primary_error(), OrchestratorError::WorkBudget(WorkBudgetError::Revoked)));
        assert!(error.post_cell_failure().unwrap().cleanup.close_succeeded());
        assert_eq!(pool.remaining(), 256);
        assert_eq!(pool.outstanding_admissions(), 0);
        assert_eq!(orchestrator.execution_count(), 0);
    }
}

mod admitted_job_deadlines {
    use super::*;
    use frankenengine_core::execution_work_budget::ExecutionTaskStartError;
    use frankenengine_core::host_effect_budget::{
        HostEffectDrainError, HostEffectLimits, HostEffectWorkPool,
    };
    use frankenengine_extension_host::host_io::{
        HostIoCapability, HostIoControl, HostIoError, HostIoOutcome, HostIoProvider,
        HostIoRequest, HostIoResponse,
    };
    use frankenengine_extension_host::process_spawn::{
        ProcessExit, ProcessLaunch, ProcessSpawnCapability, ProcessSpawnControl, ProcessSpawnError,
        ProcessSpawnOutcome, ProcessSpawnProvider, ProcessSpawnRequest, ProcessSpawnResponse,
        ProcessStdio,
    };
    use std::sync::{Mutex, mpsc};

    const WAIT: Duration = Duration::from_secs(5);
    const IO: &[HostIoCapability] = &[HostIoCapability::FsRead];
    const PROCESS: &[ProcessSpawnCapability] = &[ProcessSpawnCapability::Spawn];

    fn effects() -> HostEffectWorkPool {
        HostEffectWorkPool::new(HostEffectLimits { operations: 8, max_in_flight: 1 })
    }

    fn read() -> HostIoRequest {
        HostIoRequest::FsRead { path: "deadline-input".into() }
    }

    fn launch() -> ProcessLaunch {
        ProcessLaunch {
            executable: "deadline-probe".into(),
            argv: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            shell: false,
            stdio: ProcessStdio::default(),
        }
    }

    fn run() -> ProcessSpawnRequest {
        ProcessSpawnRequest::Run { launch: launch(), stdin: Vec::new(), timeout_millis: None }
    }

    #[test]
    fn job_deadlines_attenuate_without_changing_pool_or_peer_authority() {
        let early = future();
        let parent_end = early.checked_add(Duration::from_secs(60)).unwrap();
        let later = parent_end.checked_add(Duration::from_secs(60)).unwrap();
        let root = ExecutionWorkPool::with_deadline(512, 3, parent_end);
        let job = root.reserve_until(64, early).unwrap();
        let clamped = root.reserve_until(64, later).unwrap();
        let ordinary = root.reserve(64).unwrap();
        assert_eq!(job.deadline(), Some(early));
        assert_eq!(job.execution_cancellation().unwrap().deadline(), Some(early));
        assert_eq!(clamped.deadline(), Some(parent_end));
        assert_eq!(ordinary.deadline(), Some(parent_end));
        assert_eq!(root.deadline(), Some(parent_end));
        assert_eq!(root.remaining(), 320);
        assert_eq!(root.outstanding_admissions(), 3);
        job.task_control().cancel();
        assert!(!clamped.task_control().is_cancelled());
        assert!(!ordinary.task_control().is_cancelled());
        assert!(!root.is_revoked());
        let plain = ExecutionWorkPool::new(64).reserve(32).unwrap();
        assert_eq!(plain.deadline(), None);
    }

    #[test]
    fn expired_job_refusal_precedes_capacity_and_spending_on_a_live_pool() {
        for capacity in [0, 1] {
            let root = ExecutionWorkPool::with_admission_limit(128, capacity);
            for fuel in [0, 1, 256] {
                assert!(matches!(
                    root.reserve_until(fuel, Instant::now()),
                    Err(WorkBudgetError::Revoked)
                ));
            }
            assert!(!root.is_revoked());
            assert_eq!(root.remaining(), 128);
            assert_eq!(root.outstanding_admissions(), 0);
        }
        let root = ExecutionWorkPool::with_admission_limit(128, 1);
        assert!(matches!(root.reserve_until(0, future()), Err(WorkBudgetError::ZeroInstructionBudget)));
        assert!(matches!(root.reserve_until(129, future()), Err(WorkBudgetError::Exhausted { .. })));
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 128);
    }

    struct CountTrace(Arc<AtomicUsize>);
    impl From<CountTrace> for String {
        fn from(value: CountTrace) -> Self {
            value.0.fetch_add(1, Ordering::SeqCst);
            "deadline-dispatch".into()
        }
    }

    #[test]
    fn expired_queued_job_keeps_capacity_until_refused_dispatch_without_harming_peer() {
        let source = module("42;");
        let root = ExecutionWorkPool::with_admission_limit(256, 2);
        let end = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
        let job = root.reserve_until(128, end).unwrap();
        let peer = root.reserve(128).unwrap();
        let control = job.task_control();
        let signal = job.execution_cancellation().unwrap();
        let mut queue = std::collections::VecDeque::from([job]);
        let job = queue.pop_front().unwrap();
        queue.push_back(job);
        wait_until(end);
        signal.reset();
        assert!(control.is_cancelled() && signal.is_cancelled());
        assert!(!peer.task_control().is_cancelled());
        assert!(!root.is_revoked());
        assert_eq!(root.outstanding_admissions(), 2);
        let conversions = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            queue.pop_front().unwrap().spawn(
                source.clone(), config(false, 128), CountTrace(conversions.clone())
            ),
            Err(ExecutionTaskStartError::Admission(WorkBudgetError::Revoked))
        ));
        assert_eq!(conversions.load(Ordering::SeqCst), 0);
        assert_eq!(root.outstanding_admissions(), 1);
        let result = peer.execute(&source, config(false, 128), "peer").unwrap();
        assert_eq!(result.value.to_string(), "42");
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(root.remaining(), 0);
    }

    #[test]
    fn native_worker_deadline_uses_existing_checkpoints_without_expiring_the_pool() {
        let source = module("let object = {}; while (true) {}");
        for throughput in [false, true] {
            let root = ExecutionWorkPool::with_admission_limit(256, 1);
            let end = Instant::now().checked_add(Duration::from_secs(2)).unwrap();
            let job = root.reserve_until(128, end).unwrap();
            let hook = Arc::new(ExpireAtAllocation { deadline: end, calls: AtomicUsize::new(0) });
            let mut task = job.spawn_with_hook(
                source.clone(), config(throughput, 128), "timed-worker", Some(hook.clone())
            ).unwrap();
            assert!(matches!(
                task.join_timeout(WAIT).unwrap(),
                Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled))
            ));
            assert!(hook.calls.load(Ordering::SeqCst) > 0);
            assert!(!root.is_revoked());
            assert_eq!(root.outstanding_admissions(), 0);
            let result = root.reserve(128).unwrap()
                .execute(&module("42;"), config(throughput, 128), "untimed-peer").unwrap();
            assert_eq!(result.value.to_string(), "42");
            assert_eq!(root.remaining(), 0);
        }
    }

    // Controlled provider seams, not native filesystem/process isolation proof.
    #[derive(Default)]
    struct Provider {
        until: Option<Instant>,
        fail_process: bool,
        io_control: Mutex<Option<Arc<dyn HostIoControl>>>,
        process_control: Mutex<Option<Arc<dyn ProcessSpawnControl>>>,
        calls: AtomicUsize,
        cleanups: AtomicUsize,
    }

    impl std::fmt::Debug for Provider {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DeadlineProvider").finish_non_exhaustive()
        }
    }

    impl HostIoProvider for Provider {
        fn name(&self) -> &str { "deadline-io" }
        fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
            panic!("the live control must be forwarded")
        }
        fn perform_controlled(
            &self, _: &HostIoRequest, _: &[HostIoCapability], control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            control.checkpoint()?;
            *self.io_control.lock().unwrap() = Some(control);
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(end) = self.until { wait_until(end); }
            Ok(HostIoResponse::FsRead { bytes: vec![42] })
        }
    }

    impl ProcessSpawnProvider for Provider {
        fn name(&self) -> &str { "deadline-process" }
        fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome {
            panic!("the live control must be forwarded")
        }
        fn perform_controlled(
            &self, request: &ProcessSpawnRequest, _: &[ProcessSpawnCapability],
            control: Arc<dyn ProcessSpawnControl>,
        ) -> ProcessSpawnOutcome {
            control.checkpoint()?;
            *self.process_control.lock().unwrap() = Some(control);
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(end) = self.until { wait_until(end); }
            if self.fail_process {
                return Err(ProcessSpawnError::TimedOut { runtime_millis: 7 });
            }
            if matches!(request, ProcessSpawnRequest::Spawn { .. }) {
                Ok(ProcessSpawnResponse::Spawned { handle: "owned-deadline-child".into() })
            } else {
                Ok(ProcessSpawnResponse::Run {
                    exit: ProcessExit { success: true, code: Some(0), signal: None },
                    stdout: vec![42], stderr: Vec::new(),
                })
            }
        }
        fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome {
            self.cleanups.fetch_add(1, Ordering::SeqCst);
            Ok(ProcessSpawnResponse::Cleaned { was_present: true })
        }
    }

    #[test]
    fn job_expiry_reaches_retained_provider_controls_without_stealing_peer_authority() {
        let root = ExecutionWorkPool::with_admission_limit(128, 1);
        let end = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
        let job = root.reserve_until(8, end).unwrap();
        let effects = effects();
        let inner = Arc::new(Provider::default());
        let io = effects.bind_host_io_for_admission(inner.clone(), &job);
        let process = effects.bind_process_spawn_for_admission(inner.clone(), &job);
        io.perform(&read(), IO).unwrap();
        process.perform(&run(), PROCESS).unwrap();
        wait_until(end);
        assert!(inner.io_control.lock().unwrap().as_ref().unwrap().checkpoint().is_err());
        assert!(inner.process_control.lock().unwrap().as_ref().unwrap().checkpoint().is_err());
        assert!(matches!(io.perform(&read(), IO), Err(HostIoError::Denied { .. })));
        assert!(matches!(process.perform(&run(), PROCESS), Err(ProcessSpawnError::Denied { .. })));
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        assert_eq!(effects.snapshot().unwrap().committed_operations, 2);
        assert_eq!(root.outstanding_admissions(), 1);
        assert!(!root.is_revoked());
        assert!(!effects.is_revoked());
        drop(job);
        let peer = root.reserve(8).unwrap();
        effects.bind_host_io_for_admission(inner.clone(), &peer).perform(&read(), IO).unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 3);
        assert_eq!(root.remaining(), 112);
    }

    #[test]
    fn late_spawn_handles_and_typed_failures_survive_expiry_for_journal_and_cleanup() {
        for fail_process in [false, true] {
            let root = ExecutionWorkPool::with_admission_limit(16, 1);
            let end = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
            let job = root.reserve_until(8, end).unwrap();
            let effects = effects();
            let inner = Arc::new(Provider { until: Some(end), fail_process, ..Provider::default() });
            let process = effects.bind_process_spawn_for_admission(inner.clone(), &job);
            let outcome = process.perform(&ProcessSpawnRequest::Spawn { launch: launch() }, PROCESS);
            assert!(job.task_control().is_cancelled());
            if fail_process {
                assert_eq!(outcome, Err(ProcessSpawnError::TimedOut { runtime_millis: 7 }));
            } else {
                assert_eq!(outcome, Ok(ProcessSpawnResponse::Spawned { handle: "owned-deadline-child".into() }));
                assert_eq!(process.cleanup_handle("owned-deadline-child"),
                    Ok(ProcessSpawnResponse::Cleaned { was_present: true }));
                assert_eq!(inner.cleanups.load(Ordering::SeqCst), 1);
            }
            assert_eq!(effects.snapshot().unwrap().in_flight, 0);
            assert_eq!(effects.snapshot().unwrap().committed_operations, 1);
            assert!(!root.is_revoked());
            assert_eq!(root.remaining(), 8);
        }
    }

    #[test]
    fn late_io_and_non_resource_process_successes_are_not_published_after_expiry() {
        for process_call in [false, true] {
            let root = ExecutionWorkPool::with_admission_limit(16, 1);
            let end = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
            let job = root.reserve_until(8, end).unwrap();
            let effects = effects();
            let inner = Arc::new(Provider { until: Some(end), ..Provider::default() });
            if process_call {
                let process = effects.bind_process_spawn_for_admission(inner.clone(), &job);
                assert!(matches!(process.perform(&run(), PROCESS), Err(ProcessSpawnError::Denied { .. })));
            } else {
                let io = effects.bind_host_io_for_admission(inner.clone(), &job);
                assert!(matches!(io.perform(&read(), IO), Err(HostIoError::Denied { .. })));
            }
            assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
            assert_eq!(effects.snapshot().unwrap().committed_operations, 1);
            assert_eq!(effects.snapshot().unwrap().in_flight, 0);
            assert_eq!(root.outstanding_admissions(), 1);
        }
    }

    #[derive(Debug)]
    struct ParkedProvider {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl HostIoProvider for ParkedProvider {
        fn name(&self) -> &str { "parked-deadline-io" }
        fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome { unreachable!() }
        fn perform_controlled(
            &self, _: &HostIoRequest, _: &[HostIoCapability], control: Arc<dyn HostIoControl>,
        ) -> HostIoOutcome {
            control.checkpoint()?;
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv_timeout(WAIT).unwrap();
            control.checkpoint()?;
            Ok(HostIoResponse::FsRead { bytes: vec![42] })
        }
    }

    #[test]
    fn expiry_does_not_certify_drain_or_release_capacity_held_by_blocked_provider_work() {
        let root = ExecutionWorkPool::with_admission_limit(32, 1);
        let end = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
        let job = root.reserve_until(8, end).unwrap();
        let effects = effects();
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let io = effects.bind_host_io_for_admission(Arc::new(ParkedProvider {
            entered: entered_tx, release: Mutex::new(release_rx),
        }), &job);
        let worker = std::thread::spawn(move || io.perform(&read(), IO));
        entered.recv_timeout(WAIT).unwrap();
        wait_until(end);
        assert!(job.task_control().is_cancelled());
        assert_eq!(root.outstanding_admissions(), 1);
        assert_eq!(effects.snapshot().unwrap().in_flight, 1);
        assert!(matches!(root.reserve(8), Err(WorkBudgetError::AdmissionLimit { limit: 1 })));
        let drained = effects.revoke_and_drain(Duration::ZERO);
        // Release and join before reporting the assertion to avoid stranding the
        // controlled worker if the drain implementation regresses.
        release.send(()).unwrap();
        let outcome = worker.join().unwrap();
        assert_eq!(drained, Err(HostEffectDrainError::TimedOut { in_flight: 1 }));
        assert!(matches!(outcome, Err(HostIoError::Denied { .. })));
        assert_eq!(effects.revoke_and_drain(WAIT).unwrap().in_flight, 0);
        assert_eq!(root.outstanding_admissions(), 1);
        drop(job);
        assert_eq!(root.outstanding_admissions(), 0);
        assert!(!root.is_revoked());
        let _peer = root.reserve(8).unwrap();
        assert_eq!(root.remaining(), 16);
    }
}
