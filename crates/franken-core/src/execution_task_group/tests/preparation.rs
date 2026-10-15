use super::*;
use crate::host_effect_budget::{HostEffectLimits, HostEffectWorkPool};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
};
use frankenengine_extension_host::process_spawn::{
    ProcessExit, ProcessLaunch, ProcessSpawnCapability, ProcessSpawnControl, ProcessSpawnOutcome,
    ProcessSpawnProvider, ProcessSpawnRequest, ProcessSpawnResponse, ProcessStdio,
};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicUsize;

#[test]
fn preparation_borrows_the_actual_worker_admission_and_closes_escaped_controls() {
    let parent = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&parent, 256, 1).unwrap();
    let mut escaped = None;
    let id = group.spawn_with_preparation(
        module("42;"), config(128), "prepared", |admission, current| {
            assert_eq!(admission.instruction_limit(), 128);
            assert_eq!(current.instruction_budget, 128);
            escaped = Some(admission.task_control());
            Ok(None)
        },
    ).unwrap();
    collect(&mut group, id).unwrap().unwrap();
    assert!(escaped.unwrap().is_cancelled());
    assert!(!group.is_closed());
    assert_eq!(group.remaining_instructions(), 128);
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn preparation_cannot_broaden_fuel_and_can_tighten_current_limits() {
    let parent = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&parent, 512, 1).unwrap();
    for (reserved, changed) in [(8, 128), (128, 8)] {
        let id = group.spawn_with_preparation(
            module("while (true) {}"), config(reserved), "changed-limit", |_, current| {
                current.instruction_budget = changed;
                Ok(None)
            },
        ).unwrap();
        assert!(matches!(
            collect(&mut group, id),
            Ok(Err(WorkBudgetError::Interpreter(InterpreterError::BudgetExhausted { budget: 8, .. })))
        ));
    }
    assert_eq!(group.remaining_instructions(), 512 - 8 - 128);
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn rejected_preparation_closes_scope_without_worker_or_refund() {
    let parent = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&parent, 256, 1).unwrap();
    let mut escaped = None;
    let result = group.spawn_with_preparation(
        module("7;"), config(128), "setup-refusal", |admission, _| {
            escaped = Some(admission.task_control());
            Err(WorkBudgetError::Revoked)
        },
    );
    assert!(matches!(result, Err(ExecutionGroupStartError::Preparation(WorkBudgetError::Revoked))));
    assert!(escaped.unwrap().is_cancelled());
    assert_eq!(group.retained(), 0);
    assert_eq!(group.remaining_instructions(), 128);
    assert!(!group.is_closed());
    let id = group.spawn(module("42;"), config(128), "next-admission").unwrap();
    collect(&mut group, id).unwrap().unwrap();
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn preparation_unwind_cancels_existing_group_work_and_preserves_its_handle() {
    let parent = ExecutionWorkPool::new(4096);
    let mut group = ExecutionTaskGroup::new(&parent, 2048, 2).unwrap();
    let (hook, entered, release) = parked(false);
    let running = group.spawn_with_hook(
        module("let object = {}; while (true) {}"), config(1024), "running", Some(hook),
    ).unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let running_control = group.task_control(running).unwrap();
    let mut escaped = None;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = group.spawn_with_preparation(
            module("7;"), config(128), "setup-panic", |admission, _| {
                escaped = Some(admission.task_control());
                panic!("injected trusted setup panic");
            },
        );
    }));
    assert!(panic.is_err());
    assert!(escaped.unwrap().is_cancelled());
    assert!(running_control.is_cancelled());
    assert!(group.is_closed());
    assert_eq!(group.pending(), 1);
    assert_eq!(group.retained(), 1);
    assert_eq!(group.remaining_instructions(), 896);
    assert!(!parent.is_revoked());
    release.send(()).unwrap();
    group.close_and_join(WAIT).unwrap();
    cancelled(group.take_result(running).unwrap());
}

#[test]
fn capacity_and_closed_refusal_never_invoke_preparation_or_consume_quota() {
    let parent = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&parent, 256, 0).unwrap();
    let calls = AtomicUsize::new(0);
    let mut prepare = |_: &ExecutionAdmission, _: &mut InterpreterConfig| {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    };
    assert!(matches!(
        group.spawn_with_preparation(module("7;"), config(128), "full", &mut prepare),
        Err(ExecutionGroupStartError::Capacity { limit: 0 })
    ));
    group.close();
    assert!(matches!(
        group.spawn_with_preparation(module("7;"), config(128), "closed", prepare),
        Err(ExecutionGroupStartError::Closed)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(group.remaining_instructions(), 256);
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn revocation_during_preparation_denies_native_spawn_without_refund() {
    let parent = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&parent, 256, 1).unwrap();
    let control = group.control();
    let result = group.spawn_with_preparation(
        module("7;"), config(128), "setup-race", |_, _| {
            control.cancel();
            Ok(None)
        },
    );
    assert!(matches!(
        result,
        Err(ExecutionGroupStartError::Worker(ExecutionTaskStartError::Admission(WorkBudgetError::Revoked)))
    ));
    assert_eq!(group.retained(), 0);
    assert_eq!(group.remaining_instructions(), 128);
    group.close_and_join(Duration::ZERO).unwrap();
}

#[derive(Default)]
struct Providers {
    io_calls: AtomicUsize,
    process_calls: AtomicUsize,
    io_controls: Mutex<Vec<Arc<dyn HostIoControl>>>,
    process_controls: Mutex<Vec<Arc<dyn ProcessSpawnControl>>>,
}

impl fmt::Debug for Providers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Providers").finish_non_exhaustive()
    }
}

impl HostIoProvider for Providers {
    fn name(&self) -> &str {
        "task-group-io"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("the admission decorator must forward live control")
    }
    fn perform_controlled(
        &self, _: &HostIoRequest, _: &[HostIoCapability], control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        control.checkpoint()?;
        self.io_calls.fetch_add(1, Ordering::SeqCst);
        self.io_controls.lock().unwrap().push(control);
        Ok(HostIoResponse::FsRead { bytes: vec![7] })
    }
}

impl ProcessSpawnProvider for Providers {
    fn name(&self) -> &str {
        "task-group-process"
    }
    fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome {
        panic!("the admission decorator must forward live control")
    }
    fn perform_controlled(
        &self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability],
        control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        control.checkpoint()?;
        self.process_calls.fetch_add(1, Ordering::SeqCst);
        self.process_controls.lock().unwrap().push(control);
        Ok(ProcessSpawnResponse::Run {
            exit: ProcessExit { success: true, code: Some(0), signal: None },
            stdout: vec![7], stderr: Vec::new(),
        })
    }
    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome {
        Ok(ProcessSpawnResponse::Cleaned { was_present: false })
    }
}

struct EffectHook {
    io: Arc<dyn HostIoProvider>,
    process: Option<Arc<dyn ProcessSpawnProvider>>,
    invoked: AtomicBool,
    denied: AtomicBool,
}

impl InterpreterHook for EffectHook {
    fn pre_property_access(&self, _: &HookContext, _: &ObjectRef, _: &PropertyKey) -> HookAction {
        HookAction::Allow
    }
    fn pre_call(&self, _: &HookContext, _: &FunctionRef, _: &[Value]) -> HookAction {
        HookAction::Allow
    }
    fn pre_import(&self, _: &HookContext, _: &str) -> HookAction {
        HookAction::Allow
    }
    fn pre_allocation(&self, _: &HookContext, _: AllocKind, _: usize) -> HookAction {
        if !self.invoked.swap(true, Ordering::AcqRel) {
            let outcome = self.io.perform(
                &HostIoRequest::FsRead { path: "input".into() }, &[HostIoCapability::FsRead],
            );
            self.denied.store(outcome.is_err(), Ordering::Release);
            if let Some(process) = &self.process {
                outcome.expect("live admitted I/O should succeed");
                process.perform(
                    &ProcessSpawnRequest::Run {
                        launch: ProcessLaunch {
                            executable: "test-provider".into(), argv: Vec::new(), env: BTreeMap::new(),
                            cwd: None, shell: false, stdio: ProcessStdio::default(),
                        },
                        stdin: Vec::new(), timeout_millis: Some(1000),
                    }, &[ProcessSpawnCapability::Spawn],
                ).expect("live admitted process control should succeed");
            }
        }
        HookAction::Allow
    }
}

#[test]
fn native_dispatch_hook_binds_io_and_process_to_its_exact_admission() {
    // Actual native allocation invokes production budget decorators. The inner
    // providers are controlled probes, NOT real filesystem/process isolation.
    let parent = ExecutionWorkPool::new(512);
    let mut first = ExecutionTaskGroup::new(&parent, 256, 1).unwrap();
    let mut sibling = ExecutionTaskGroup::new(&parent, 256, 1).unwrap();
    let effects = HostEffectWorkPool::new(HostEffectLimits { operations: 4, max_in_flight: 1 });
    let providers = Arc::new(Providers::default());
    for group in [&mut first, &mut sibling] {
        let id = group.spawn_with_preparation(
            module("let object = {}; object;"), config(128), "bound-host", |admission, _| {
                let hook: Arc<dyn InterpreterHook> = Arc::new(EffectHook {
                    io: Arc::new(effects.bind_host_io_for_admission(providers.clone(), admission)),
                    process: Some(Arc::new(effects.bind_process_spawn_for_admission(providers.clone(), admission))),
                    invoked: AtomicBool::new(false), denied: AtomicBool::new(false),
                });
                Ok(Some(hook))
            },
        ).unwrap();
        collect(group, id).unwrap().unwrap();
        for control in providers.io_controls.lock().unwrap().iter() {
            assert!(control.checkpoint().is_err());
        }
        for control in providers.process_controls.lock().unwrap().iter() {
            assert!(control.checkpoint().is_err());
        }
        assert!(!effects.is_revoked(), "finished admission must not revoke sibling effects");
        group.close_and_join(Duration::ZERO).unwrap();
    }
    assert_eq!(providers.io_calls.load(Ordering::SeqCst), 2);
    assert_eq!(providers.process_calls.load(Ordering::SeqCst), 2);
    assert_eq!(effects.snapshot().unwrap().committed_operations, 4);
    assert_eq!(effects.snapshot().unwrap().in_flight, 0);
}

struct HoldingIo {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
    control: Mutex<Option<Arc<dyn HostIoControl>>>,
}

impl fmt::Debug for HoldingIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HoldingIo").finish_non_exhaustive()
    }
}

impl HostIoProvider for HoldingIo {
    fn name(&self) -> &str {
        "holding-io"
    }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        unreachable!()
    }
    fn perform_controlled(
        &self, _: &HostIoRequest, _: &[HostIoCapability], control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        *self.control.lock().unwrap() = Some(control.clone());
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(WAIT).unwrap();
        control.checkpoint()?;
        Ok(HostIoResponse::FsRead { bytes: vec![7] })
    }
}

#[test]
fn group_timeout_keeps_worker_and_effect_permit_until_native_callback_returns() {
    let parent = ExecutionWorkPool::new(2048);
    let mut group = ExecutionTaskGroup::new(&parent, 1024, 1).unwrap();
    let effects = HostEffectWorkPool::new(HostEffectLimits { operations: 2, max_in_flight: 1 });
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    let provider = Arc::new(HoldingIo {
        entered: entered_tx, release: Mutex::new(release_rx), control: Mutex::new(None),
    });
    let mut hook_owner = None;
    let id = group.spawn_with_preparation(
        module("let object = {}; while (true) {}"), config(1024), "blocked-io", |admission, _| {
            let hook = Arc::new(EffectHook {
                io: Arc::new(effects.bind_host_io_for_admission(provider.clone(), admission)),
                process: None, invoked: AtomicBool::new(false), denied: AtomicBool::new(false),
            });
            hook_owner = Some(hook.clone());
            Ok(Some(hook))
        },
    ).unwrap();
    entered.recv_timeout(WAIT).unwrap();
    assert_eq!(
        group.close_and_join(Duration::ZERO),
        Err(ExecutionTaskJoinError::TimedOut)
    );
    assert_eq!(group.pending(), 1);
    assert_eq!(effects.snapshot().unwrap().in_flight, 1);
    assert_eq!(effects.snapshot().unwrap().committed_operations, 1);
    assert!(provider.control.lock().unwrap().as_ref().unwrap().checkpoint().is_err());
    assert!(!effects.is_revoked());
    release.send(()).unwrap();
    group.close_and_join(WAIT).unwrap();
    cancelled(group.take_result(id).unwrap());
    assert!(hook_owner.unwrap().denied.load(Ordering::Acquire));
    assert_eq!(effects.snapshot().unwrap().in_flight, 0);
    assert_eq!(effects.snapshot().unwrap().remaining_operations, 1);
}

mod owned_effects;
