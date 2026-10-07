use super::*;
use crate::baseline_interpreter::{
    AllocKind, FunctionRef, HookAction, HookContext, InterpreterCore, InterpreterError, ObjectRef,
    PropertyKey, Value,
};
use crate::execution_work_budget::ExecutionWorkPool;
use crate::execution_work_budget::tests::{PanickingHook, config, module};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

const WAIT: Duration = Duration::from_secs(5);

// Synchronize with a real native allocation hook rather than guessing when
// guest execution starts. This controlled callback is not OS isolation proof.
struct ParkedHook {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
    parked: AtomicBool,
    panic_after_release: bool,
}

impl InterpreterHook for ParkedHook {
    fn pre_property_access(&self, _: &HookContext, _: &ObjectRef, _: &PropertyKey) -> HookAction {
        HookAction::Allow
    }
    fn pre_call(&self, _: &HookContext, _: &FunctionRef, _: &[Value]) -> HookAction {
        HookAction::Allow
    }
    fn pre_allocation(&self, _: &HookContext, _: AllocKind, _: usize) -> HookAction {
        if !self.parked.swap(true, Ordering::AcqRel) {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv_timeout(WAIT).unwrap();
            assert!(!self.panic_after_release, "private-native-panic-payload");
        }
        HookAction::Allow
    }
    fn pre_import(&self, _: &HookContext, _: &str) -> HookAction {
        HookAction::Allow
    }
}

fn parked_hook(panic_after_release: bool) -> (Arc<ParkedHook>, Receiver<()>, Sender<()>) {
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    (
        Arc::new(ParkedHook {
            entered: entered_tx,
            release: Mutex::new(release_rx),
            parked: AtomicBool::new(false),
            panic_after_release,
        }),
        entered,
        release,
    )
}

fn assert_cancelled(outcome: Result<ExecutionResult, WorkBudgetError>) {
    assert!(matches!(
        outcome,
        Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled))
    ));
}

#[test]
fn worker_joins_with_the_exact_native_result_and_no_second_charge() {
    let source = module("40 + 2;");
    let expected = InterpreterCore::new(config(128), "worker-result")
        .execute(&source)
        .unwrap();
    let pool = ExecutionWorkPool::new(256);
    let job = pool.reserve(128).unwrap();
    let escaped = job.execution_cancellation().unwrap();
    let mut task = job.spawn(source, config(128), "worker-result").unwrap();
    let actual = task.join_timeout(WAIT).unwrap().unwrap();
    assert_eq!(actual.value, expected.value);
    assert_eq!(actual.completion_label, expected.completion_label);
    assert_eq!(actual.instructions_executed, expected.instructions_executed);
    assert_eq!(actual.console_output, expected.console_output);
    assert!(
        escaped.is_cancelled(),
        "joined task must close its admission scope"
    );
    escaped.reset();
    assert!(
        escaped.is_cancelled(),
        "a child token cannot reset the finished admission"
    );
    assert_eq!(pool.remaining(), 128);
    assert!(!pool.is_revoked());
    assert!(task.is_finished());
    assert!(matches!(
        task.join_timeout(WAIT),
        Err(ExecutionTaskJoinError::AlreadyJoined)
    ));
}

#[test]
fn native_budget_exhaustion_uses_the_prepaid_ceiling_on_the_worker() {
    let pool = ExecutionWorkPool::new(8);
    let mut task = pool
        .reserve(8)
        .unwrap()
        .spawn(module("while (true) {}"), config(128), "clamped-worker")
        .unwrap();
    assert!(matches!(
        task.join_timeout(WAIT).unwrap(),
        Err(WorkBudgetError::Interpreter(
            InterpreterError::BudgetExhausted { budget: 8, .. }
        ))
    ));
    assert_eq!(pool.remaining(), 0);
}

#[test]
fn native_traps_and_current_capability_denial_are_not_erased() {
    let pool = ExecutionWorkPool::new(256);
    let mut throwing = pool
        .reserve(128)
        .unwrap()
        .spawn(module("throw 7;"), config(128), "throwing-worker")
        .unwrap();
    assert!(matches!(
        throwing.join_timeout(WAIT).unwrap(),
        Err(WorkBudgetError::Interpreter(
            InterpreterError::UncaughtException { .. }
        ))
    ));
    let mut denied = config(128);
    denied.granted_capabilities.clear();
    let mut task = pool
        .reserve(128)
        .unwrap()
        .spawn(module("7;"), denied, "denied-worker")
        .unwrap();
    assert!(matches!(
        task.join_timeout(WAIT).unwrap(),
        Err(WorkBudgetError::Interpreter(
            InterpreterError::CapabilityDenied { .. }
        ))
    ));
    assert_eq!(pool.remaining(), 0);
}

#[test]
fn invalid_start_closes_escaped_scope_without_refunding_or_entering_the_hook() {
    let pool = ExecutionWorkPool::new(256);
    let job = pool.reserve(128).unwrap();
    let signal = job.execution_cancellation().unwrap();
    assert!(matches!(
        job.spawn_with_hook(
            module("let object = {};"),
            config(0),
            "invalid",
            Some(Arc::new(PanickingHook))
        ),
        Err(ExecutionTaskStartError::Admission(
            WorkBudgetError::ZeroInstructionBudget
        ))
    ));
    assert!(signal.is_cancelled());
    assert!(!pool.is_revoked());
    assert_eq!(pool.remaining(), 128);
    let job = pool.reserve(128).unwrap();
    pool.revoke();
    assert!(matches!(
        job.spawn(module("7;"), config(128), "revoked"),
        Err(ExecutionTaskStartError::Admission(WorkBudgetError::Revoked))
    ));
    assert_eq!(pool.remaining(), 0);
}

#[test]
fn timeout_retains_the_real_worker_until_its_blocking_callback_returns() {
    let pool = ExecutionWorkPool::new(1024);
    let (hook, entered, release) = parked_hook(false);
    let mut task = pool
        .reserve(1024)
        .unwrap()
        .spawn_with_hook(
            module("let object = {}; while (true) {}"),
            config(1024),
            "parked",
            Some(hook),
        )
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let result = task.cancel_and_join(Duration::ZERO);
    assert!(matches!(result, Err(ExecutionTaskJoinError::TimedOut)));
    assert!(task.control().is_cancelled());
    assert!(!task.is_finished());
    assert_eq!(pool.remaining(), 0);
    release.send(()).unwrap();
    assert_cancelled(task.join_timeout(WAIT).unwrap());
    assert!(task.is_finished());
}

#[test]
fn cancellation_stops_a_native_loop_and_preserves_sibling_admissions() {
    let pool = ExecutionWorkPool::new(u64::MAX);
    let first = pool.reserve(u64::MAX - 128).unwrap();
    let sibling = pool.reserve(128).unwrap();
    let sibling_signal = sibling.execution_cancellation().unwrap();
    let (hook, entered, release) = parked_hook(false);
    let mut task = first
        .spawn_with_hook(
            module("let object = {}; while (true) {}"),
            config(u64::MAX),
            "loop",
            Some(hook),
        )
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let control = task.control();
    control.cancel();
    control.cancel();
    release.send(()).unwrap();
    assert_cancelled(task.cancel_and_join(WAIT).unwrap());
    assert!(!pool.is_revoked() && !sibling_signal.is_cancelled());
    let result = sibling
        .execute(&module("40 + 2;"), config(128), "sibling")
        .unwrap();
    assert!(result.instructions_executed > 0);
    assert_eq!(pool.remaining(), 0);
}

#[test]
fn inherited_revocation_and_original_caller_cancellation_remain_live() {
    for revoke_ancestor in [false, true] {
        let root = ExecutionWorkPool::new(1024);
        let child = root.partition(1024).unwrap();
        let caller = CancellationToken::new();
        let mut current = config(1024);
        current.cancellation_token = Some(caller.clone());
        let (hook, entered, release) = parked_hook(false);
        let mut task = child
            .reserve(1024)
            .unwrap()
            .spawn_with_hook(
                module("let object = {}; while (true) {}"),
                current,
                "inherited",
                Some(hook),
            )
            .unwrap();
        entered.recv_timeout(WAIT).unwrap();
        if revoke_ancestor {
            root.revoke();
        } else {
            caller.cancel();
        }
        release.send(()).unwrap();
        assert_cancelled(task.join_timeout(WAIT).unwrap());
        assert_eq!(caller.is_cancelled(), !revoke_ancestor);
        assert_eq!(root.is_revoked(), revoke_ancestor);
        assert_eq!(child.remaining(), 0);
    }
}

#[test]
fn invalid_join_timeout_still_cancels_and_does_not_discard_the_handle() {
    // A platform with a wider Instant range cannot exercise this refusal.
    if Instant::now().checked_add(Duration::MAX).is_some() {
        return;
    }
    let pool = ExecutionWorkPool::new(1024);
    let (hook, entered, release) = parked_hook(false);
    let mut task = pool
        .reserve(1024)
        .unwrap()
        .spawn_with_hook(
            module("let object = {}; while (true) {}"),
            config(1024),
            "deadline",
            Some(hook),
        )
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    assert!(matches!(
        task.cancel_and_join(Duration::MAX),
        Err(ExecutionTaskJoinError::InvalidTimeout)
    ));
    assert!(task.control().is_cancelled());
    release.send(()).unwrap();
    assert_cancelled(task.join_timeout(WAIT).unwrap());
}

#[test]
fn worker_unwind_is_joined_sanitized_and_closes_only_its_admission() {
    let pool = ExecutionWorkPool::new(256);
    let job = pool.reserve(128).unwrap();
    let signal = job.execution_cancellation().unwrap();
    let (hook, entered, release) = parked_hook(true);
    let mut task = job
        .spawn_with_hook(
            module("let object = {};"),
            config(128),
            "secret-trace",
            Some(hook),
        )
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    release.send(()).unwrap();
    let error = task.join_timeout(WAIT).unwrap_err();
    assert_eq!(error, ExecutionTaskJoinError::Panicked);
    assert!(!format!("{error:?} {error} {task:?}").contains("secret-trace"));
    assert!(signal.is_cancelled());
    assert!(!pool.is_revoked());
    assert_eq!(pool.remaining(), 128);
    assert!(matches!(
        task.join_timeout(WAIT),
        Err(ExecutionTaskJoinError::AlreadyJoined)
    ));
    pool.reserve(128)
        .unwrap()
        .execute(&module("7;"), config(128), "peer")
        .unwrap();
}

#[test]
fn ordinary_join_timeout_does_not_cancel_an_execution_that_can_finish() {
    let pool = ExecutionWorkPool::new(1024);
    let (hook, entered, release) = parked_hook(false);
    let mut task = pool
        .reserve(1024)
        .unwrap()
        .spawn_with_hook(
            module("let object = {}; 42;"),
            config(1024),
            "eventual-result",
            Some(hook),
        )
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    assert!(matches!(
        task.join_timeout(Duration::ZERO),
        Err(ExecutionTaskJoinError::TimedOut)
    ));
    assert!(!task.control().is_cancelled());
    release.send(()).unwrap();
    assert!(
        task.join_timeout(WAIT)
            .unwrap()
            .unwrap()
            .instructions_executed
            > 0
    );
    assert_eq!(pool.remaining(), 0);
}

#[test]
fn cancelling_a_queued_admission_never_enters_guest_code_or_cancels_its_peer() {
    let pool = ExecutionWorkPool::new(256);
    let first = pool.reserve(128).unwrap();
    let peer = pool.reserve(128).unwrap();
    let control = first.task_control();
    control.cancel();
    assert!(matches!(
        first.spawn_with_hook(
            module("let object = {};"),
            config(128),
            "cancelled-queue",
            Some(Arc::new(PanickingHook)),
        ),
        Err(ExecutionTaskStartError::Admission(WorkBudgetError::Revoked))
    ));
    assert!(!pool.is_revoked() && !peer.task_control().is_cancelled());
    peer.execute(&module("7;"), config(128), "peer").unwrap();
    assert_eq!(pool.remaining(), 0);
}
