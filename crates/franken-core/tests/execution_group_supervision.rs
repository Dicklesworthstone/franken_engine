//! Completion-driven supervision executes real native workers. Channels hold
//! selected workers in a host hook; no timing guess substitutes for readiness.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    AllocKind, FunctionRef, HookAction, HookContext, InterpreterConfig, InterpreterHook, ObjectRef,
    PropertyKey, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::execution_task_group::{ExecutionGroupStartError, ExecutionTaskGroup};
use frankenengine_core::execution_work_budget::{ExecutionTaskJoinError, ExecutionWorkPool};
use frankenengine_core::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(10);

fn module(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .unwrap();
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "group-supervision.js"),
        &LoweringContext::new(
            "group-supervision",
            "group-supervision",
            "group-supervision",
        ),
    )
    .unwrap()
    .ir3
}

fn config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = 128;
    config.checkpoint_density = 1;
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

struct Release(Option<Sender<()>>);
impl Release {
    fn open(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        self.open();
    }
}

struct Parked {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
    parked: AtomicBool,
    panic_after_release: bool,
}
impl InterpreterHook for Parked {
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
        if !self.parked.swap(true, Ordering::AcqRel) {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv_timeout(WAIT).unwrap();
            assert!(!self.panic_after_release, "injected native worker panic");
        }
        HookAction::Allow
    }
}
fn parked(panic_after_release: bool) -> (Arc<dyn InterpreterHook>, Receiver<()>, Release) {
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    (
        Arc::new(Parked {
            entered: entered_tx,
            release: Mutex::new(release_rx),
            parked: AtomicBool::new(false),
            panic_after_release,
        }),
        entered,
        Release(Some(release)),
    )
}
fn wait_joined(group: &mut ExecutionTaskGroup) {
    let deadline = Instant::now() + WAIT;
    while group.pending() != 0 {
        group.poll();
        assert!(Instant::now() < deadline, "native workers did not complete");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn empty_completion_collection_does_not_seal_or_debit_the_group() {
    let pool = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&pool, 256, 1).unwrap();
    assert!(group.take_next_result().is_none());
    assert!(group.join_next(Duration::ZERO).unwrap().is_none());
    assert_eq!(group.remaining_instructions(), 256);
    assert!(!group.is_closed());
    let id = group
        .spawn(module("42;"), config(), "empty-then-start")
        .unwrap();
    let (actual_id, outcome) = group.join_next(WAIT).unwrap().unwrap();
    assert_eq!(actual_id, id);
    assert_eq!(outcome.unwrap().unwrap().value, Value::Int(42));
    assert!(group.join_next(Duration::ZERO).unwrap().is_none());
    assert!(!group.is_closed());
}

#[test]
fn completion_collection_skips_blocked_older_workers_and_reuses_capacity() {
    let pool = ExecutionWorkPool::new(1024);
    let mut group = ExecutionTaskGroup::new(&pool, 512, 2).unwrap();
    let (hook, entered, mut release) = parked(false);
    let slow = group
        .spawn_with_hook(module("let o = {}; o;"), config(), "slow", Some(hook))
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let slow_control = group.task_control(slow).unwrap();
    let fast = group.spawn(module("42;"), config(), "fast").unwrap();
    let (id, outcome) = group.join_next(WAIT).unwrap().unwrap();
    assert_eq!(id, fast);
    assert_eq!(outcome.unwrap().unwrap().value, Value::Int(42));
    assert_eq!(group.retained(), 1);
    assert_eq!(group.pending(), 1);
    assert!(!slow_control.is_cancelled());
    let replacement = group.spawn(module("43;"), config(), "replacement").unwrap();
    assert_ne!(replacement, fast);
    let (id, outcome) = group.join_next(WAIT).unwrap().unwrap();
    assert_eq!(id, replacement);
    assert_eq!(outcome.unwrap().unwrap().value, Value::Int(43));
    assert_eq!(group.remaining_instructions(), 128);
    assert_eq!(pool.remaining(), 512);
    release.open();
    assert_eq!(group.join_next(WAIT).unwrap().unwrap().0, slow);
    assert_eq!(group.retained(), 0);
    assert!(!group.is_cancelled());
}

#[test]
fn ready_cohorts_use_admission_order_and_mix_safely_with_named_collection() {
    let pool = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&pool, 512, 3).unwrap();
    let a = group.spawn(module("1;"), config(), "one").unwrap();
    let b = group.spawn(module("2;"), config(), "two").unwrap();
    let c = group.spawn(module("3;"), config(), "three").unwrap();
    wait_joined(&mut group);
    assert_eq!(
        group.take_result(b).unwrap().unwrap().unwrap().value,
        Value::Int(2)
    );
    let (id, result) = group.take_next_result().unwrap();
    assert_eq!(id, a);
    assert_eq!(result.unwrap().unwrap().value, Value::Int(1));
    let (id, result) = group.join_next(Duration::ZERO).unwrap().unwrap();
    assert_eq!(id, c);
    assert_eq!(result.unwrap().unwrap().value, Value::Int(3));
    assert!(group.take_result(a).is_none());
    assert!(group.take_result(b).is_none());
    assert!(group.take_next_result().is_none());
}

#[test]
fn wait_timeouts_retain_ownership_without_cancelling_or_refunding() {
    let pool = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&pool, 512, 1).unwrap();
    let (hook, entered, mut release) = parked(false);
    let id = group
        .spawn_with_hook(module("let o = {}; o;"), config(), "timeout", Some(hook))
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let control = group.task_control(id).unwrap();
    for duration in [Duration::ZERO, Duration::from_millis(2)] {
        assert!(matches!(
            group.join_next(duration),
            Err(ExecutionTaskJoinError::TimedOut)
        ));
        assert_eq!(group.retained(), 1);
        assert_eq!(group.pending(), 1);
        assert!(!control.is_cancelled());
        assert!(!group.is_closed());
        assert_eq!(group.remaining_instructions(), 384);
    }
    assert!(matches!(
        group.spawn(module("1;"), config(), "full"),
        Err(ExecutionGroupStartError::Capacity { limit: 1 })
    ));
    release.open();
    let (actual, result) = group.join_next(WAIT).unwrap().unwrap();
    assert_eq!(actual, id);
    result.unwrap().unwrap();
    assert_eq!(group.remaining_instructions(), 384);
}

#[test]
fn invalid_wait_cannot_consume_an_already_joined_outcome() {
    let pool = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&pool, 256, 1).unwrap();
    let id = group
        .spawn(module("42;"), config(), "invalid-timeout")
        .unwrap();
    wait_joined(&mut group);
    assert!(matches!(
        group.join_next(Duration::MAX),
        Err(ExecutionTaskJoinError::InvalidTimeout)
    ));
    assert_eq!(group.retained(), 1);
    assert!(!group.is_closed());
    let (actual, outcome) = group.join_next(Duration::ZERO).unwrap().unwrap();
    assert_eq!(actual, id);
    assert_eq!(outcome.unwrap().unwrap().value, Value::Int(42));
}

#[test]
fn worker_panics_and_execution_errors_are_collected_not_wait_errors() {
    let pool = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&pool, 512, 2).unwrap();
    let (hook, entered, mut release) = parked(true);
    let panic_id = group
        .spawn_with_hook(module("let o = {}; o;"), config(), "panic", Some(hook))
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    release.open();
    let (id, outcome) = group.join_next(WAIT).unwrap().unwrap();
    assert_eq!(id, panic_id);
    assert!(matches!(outcome, Err(ExecutionTaskJoinError::Panicked)));
    let failed_id = group
        .spawn(module("while (true) {}"), config(), "budget")
        .unwrap();
    let (id, outcome) = group.join_next(WAIT).unwrap().unwrap();
    assert_eq!(id, failed_id);
    assert!(outcome.unwrap().is_err());
    assert_eq!(group.retained(), 0);
    assert!(
        !group.is_closed(),
        "collection alone is not a fail-fast policy"
    );
}

#[test]
fn cancelled_group_remains_collectable_and_does_not_revoke_parent() {
    let pool = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&pool, 256, 1).unwrap();
    let (hook, entered, mut release) = parked(false);
    let id = group
        .spawn_with_hook(
            module("let o = {}; while (true) {}"),
            config(),
            "cancel",
            Some(hook),
        )
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    group.close();
    assert!(matches!(
        group.join_next(Duration::ZERO),
        Err(ExecutionTaskJoinError::TimedOut)
    ));
    assert_eq!(group.retained(), 1);
    release.open();
    let (actual, result) = group.join_next(WAIT).unwrap().unwrap();
    assert_eq!(actual, id);
    assert!(result.unwrap().is_err());
    assert!(group.join_next(Duration::ZERO).unwrap().is_none());
    assert!(!pool.is_revoked());
    assert_eq!(pool.remaining(), 256);
}

#[test]
fn rolling_dispatch_never_exceeds_capacity_or_refunds_prepaid_work() {
    const JOBS: usize = 24;
    let pool = ExecutionWorkPool::new((JOBS * 128) as u64);
    let mut group = ExecutionTaskGroup::new(&pool, (JOBS * 128) as u64, 3).unwrap();
    let source = module("42;");
    let mut submitted = 0;
    let mut completed = 0;
    let mut ids = std::collections::BTreeSet::new();
    loop {
        while submitted < JOBS && group.retained() < 3 {
            let id = group.spawn(source.clone(), config(), "rolling").unwrap();
            assert!(
                ids.insert(id),
                "collected task identities must never be reused"
            );
            submitted += 1;
        }
        assert!(group.retained() <= 3);
        let Some((_, result)) = group.join_next(WAIT).unwrap() else {
            break;
        };
        assert_eq!(result.unwrap().unwrap().value, Value::Int(42));
        completed += 1;
    }
    assert_eq!((submitted, completed), (JOBS, JOBS));
    assert_eq!(group.remaining_instructions(), 0);
    assert_eq!(pool.remaining(), 0);
    assert_eq!(group.retained(), 0);
}

#[path = "execution_group_supervision/fail_fast.rs"]
mod fail_fast;
