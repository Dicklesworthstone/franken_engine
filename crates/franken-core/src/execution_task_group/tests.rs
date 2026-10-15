use super::*;
use crate::ast::ParseGoal;
use crate::baseline_interpreter::{
    AllocKind, FunctionRef, HookAction, HookContext, InterpreterCore, InterpreterError,
    ObjectRef, PropertyKey, Value,
};
use crate::capability::RuntimeCapability;
use crate::ir_contract::Ir0Module;
use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use crate::parser::{CanonicalEs2020Parser, Es2020Parser};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

const WAIT: Duration = Duration::from_secs(10);

fn module(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser.parse(source, ParseGoal::Script).unwrap();
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "task-group.js"),
        &LoweringContext::new("task-group", "task-group", "task-group"),
    ).unwrap().ir3
}

fn config(budget: u64) -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = budget;
    config.checkpoint_density = 1;
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn collect(group: &mut ExecutionTaskGroup, id: ExecutionTaskId) -> ExecutionTaskOutcome {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(outcome) = group.take_result(id) {
            return outcome;
        }
        assert!(Instant::now() < deadline, "native worker did not finish");
        thread::sleep(Duration::from_millis(1));
    }
}

fn wait_for_all(group: &mut ExecutionTaskGroup) {
    let deadline = Instant::now() + WAIT;
    while group.pending() != 0 {
        group.poll();
        assert!(Instant::now() < deadline, "native workers did not finish");
        thread::sleep(Duration::from_millis(1));
    }
}

// Synchronize with actual VM allocation rather than sleeping to guess when
// native execution started. These controlled hooks are not OS isolation proof.
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
            assert!(!self.panic_after_release, "injected worker unwind");
        }
        HookAction::Allow
    }
    fn pre_import(&self, _: &HookContext, _: &str) -> HookAction {
        HookAction::Allow
    }
}

fn parked(panic_after_release: bool) -> (Arc<ParkedHook>, Receiver<()>, Sender<()>) {
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

fn cancelled(outcome: ExecutionTaskOutcome) {
    assert!(matches!(
        outcome,
        Ok(Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled)))
    ));
}

#[test]
fn real_native_result_and_prepaid_accounting_are_preserved() {
    let parent = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&parent, 256, 2).unwrap();
    let source = module("40 + 2;");
    let expected = InterpreterCore::new(config(128), "group-result")
        .execute(&source).unwrap();
    let id = group.spawn(source, config(128), "group-result").unwrap();
    let actual = collect(&mut group, id).unwrap().unwrap();
    assert_eq!(actual.value, expected.value);
    assert_eq!(actual.completion_label, expected.completion_label);
    assert_eq!(actual.instructions_executed, expected.instructions_executed);
    assert_eq!(actual.console_output, expected.console_output);
    assert!(actual.instructions_executed > 0);
    assert_eq!(group.remaining_instructions(), 128);
    assert_eq!(parent.remaining(), 256, "partition is charged only once");
    group.close_and_join(Duration::ZERO).unwrap();
    drop(group);
    assert_eq!(parent.remaining(), 256, "unused child credits are not refunded");
}

#[test]
fn uncollected_results_hold_capacity_and_collection_does_not_reuse_ids() {
    let parent = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&parent, 512, 1).unwrap();
    let first = group.spawn(module("7;"), config(128), "first").unwrap();
    wait_for_all(&mut group);
    assert_eq!(group.retained(), 1);
    assert_eq!(group.pending(), 0);
    assert!(matches!(
        group.spawn(module("8;"), config(128), "denied"),
        Err(ExecutionGroupStartError::Capacity { limit: 1 })
    ));
    assert_eq!(group.remaining_instructions(), 384);
    group.take_result(first).unwrap().unwrap().unwrap();
    assert!(group.take_result(first).is_none());
    let second = group.spawn(module("8;"), config(128), "second").unwrap();
    assert_ne!(first, second);
    assert!(group.task_control(first).is_none());
    collect(&mut group, second).unwrap().unwrap();
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn blocked_workers_hold_capacity_until_join_and_collection() {
    let parent = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&parent, 512, 1).unwrap();
    let (hook, entered, release) = parked(false);
    let id = group.spawn_with_hook(
        module("let object = {}; object;"), config(128), "parked", Some(hook),
    ).unwrap();
    entered.recv_timeout(WAIT).unwrap();
    assert_eq!(group.poll(), 0);
    assert!(group.take_result(id).is_none());
    assert!(matches!(
        group.spawn(module("7;"), config(128), "over-capacity"),
        Err(ExecutionGroupStartError::Capacity { .. })
    ));
    assert_eq!(group.remaining_instructions(), 384);
    release.send(()).unwrap();
    collect(&mut group, id).unwrap().unwrap();
    assert_eq!(group.retained(), 0);
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn closing_cancels_every_worker_before_waiting_and_timeout_retains_ownership() {
    let parent = ExecutionWorkPool::new(4096);
    let mut group = ExecutionTaskGroup::new(&parent, 2048, 2).unwrap();
    let mut ids = Vec::new();
    let mut releases = Vec::new();
    let mut controls = Vec::new();
    for _ in 0..2 {
        let (hook, entered, release) = parked(false);
        let id = group.spawn_with_hook(
            module("let object = {}; while (true) {}"),
            config(1024), "close-all", Some(hook),
        ).unwrap();
        entered.recv_timeout(WAIT).unwrap();
        controls.push(group.task_control(id).unwrap());
        releases.push(release);
        ids.push(id);
    }
    assert_eq!(group.close_and_join(Duration::ZERO), Err(ExecutionTaskJoinError::TimedOut));
    assert!(group.is_closed());
    assert!(controls.iter().all(ExecutionTaskControl::is_cancelled));
    assert_eq!(group.pending(), 2);
    assert_eq!(group.retained(), 2);
    assert_eq!(group.remaining_instructions(), 0);
    for release in releases { release.send(()).unwrap(); }
    group.close_and_join(WAIT).unwrap();
    assert_eq!(group.pending(), 0);
    assert_eq!(group.retained(), 2, "joining must not discard outcomes");
    for id in ids { cancelled(group.take_result(id).unwrap()); }
    assert!(!parent.is_revoked());
    assert_eq!(parent.remaining(), 2048);
    assert!(matches!(
        group.spawn(module("7;"), config(1), "after-close"),
        Err(ExecutionGroupStartError::Closed)
    ));
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn cancel_only_group_control_preserves_sibling_progress() {
    let parent = ExecutionWorkPool::new(512);
    let mut first = ExecutionTaskGroup::new(&parent, 256, 1).unwrap();
    let mut second = ExecutionTaskGroup::new(&parent, 256, 1).unwrap();
    let control = first.control();
    let alias = control.clone();
    alias.cancel();
    assert!(control.is_cancelled());
    assert!(first.is_closed());
    assert!(!second.is_closed());
    assert!(!parent.is_revoked());
    assert!(matches!(
        first.spawn(module("7;"), config(128), "cancelled"),
        Err(ExecutionGroupStartError::Closed)
    ));
    let id = second.spawn(module("42;"), config(128), "sibling").unwrap();
    collect(&mut second, id).unwrap().unwrap();
    first.close_and_join(Duration::ZERO).unwrap();
    second.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn ancestor_revocation_closes_groups_even_after_parent_owner_drops() {
    let parent = ExecutionWorkPool::new(256);
    let alias = parent.clone();
    let mut group = ExecutionTaskGroup::new(&parent, 128, 1).unwrap();
    drop(parent);
    alias.revoke();
    drop(alias);
    assert!(group.control().is_cancelled());
    assert!(matches!(
        group.spawn(module("7;"), config(128), "revoked-ancestor"),
        Err(ExecutionGroupStartError::Closed)
    ));
    assert_eq!(group.remaining_instructions(), 128);
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn worker_panic_is_collected_without_losing_other_results() {
    let parent = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&parent, 512, 2).unwrap();
    let (hook, entered, release) = parked(true);
    let bad = group.spawn_with_hook(
        module("let object = {}; object;"), config(128), "panic", Some(hook),
    ).unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let good = group.spawn(module("42;"), config(128), "normal").unwrap();
    release.send(()).unwrap();
    wait_for_all(&mut group);
    group.close_and_join(Duration::ZERO).unwrap();
    assert_eq!(group.retained(), 2);
    assert!(matches!(group.take_result(bad), Some(Err(ExecutionTaskJoinError::Panicked))));
    group.take_result(good).unwrap().unwrap().unwrap();
    assert_eq!(group.remaining_instructions(), 256);
}

#[test]
fn current_capability_denial_and_guest_exceptions_are_not_join_successes() {
    let parent = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&parent, 512, 2).unwrap();
    let mut denied = config(128);
    denied.granted_capabilities.clear();
    let denied_id = group.spawn(module("7;"), denied, "capability").unwrap();
    let thrown_id = group.spawn(module("throw 7;"), config(128), "exception").unwrap();
    wait_for_all(&mut group);
    group.close_and_join(Duration::ZERO).unwrap();
    assert!(matches!(
        group.take_result(denied_id),
        Some(Ok(Err(WorkBudgetError::Interpreter(InterpreterError::CapabilityDenied { .. }))))
    ));
    assert!(matches!(
        group.take_result(thrown_id),
        Some(Ok(Err(WorkBudgetError::Interpreter(InterpreterError::UncaughtException { .. }))))
    ));
}

#[test]
fn native_budget_exhaustion_spends_the_reservation_and_retains_typed_error() {
    let parent = ExecutionWorkPool::new(16);
    let mut group = ExecutionTaskGroup::new(&parent, 8, 1).unwrap();
    let id = group.spawn(module("while (true) {}"), config(8), "fuel").unwrap();
    assert!(matches!(
        collect(&mut group, id),
        Ok(Err(WorkBudgetError::Interpreter(InterpreterError::BudgetExhausted { budget: 8, .. })))
    ));
    assert!(matches!(
        group.spawn(module("7;"), config(1), "exhausted"),
        Err(ExecutionGroupStartError::Admission(WorkBudgetError::Exhausted { .. }))
    ));
    assert_eq!(group.retained(), 0);
    assert_eq!(parent.remaining(), 8);
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn invalid_or_full_dispatch_never_debits_the_group() {
    let parent = ExecutionWorkPool::new(256);
    let mut zero = ExecutionTaskGroup::new(&parent, 128, 0).unwrap();
    assert!(matches!(
        zero.spawn(module("7;"), config(1), "zero-capacity"),
        Err(ExecutionGroupStartError::Capacity { limit: 0 })
    ));
    assert_eq!(zero.remaining_instructions(), 128);
    let mut group = ExecutionTaskGroup::new(&parent, 128, 1).unwrap();
    assert!(matches!(
        group.spawn(module("7;"), config(0), "zero-budget"),
        Err(ExecutionGroupStartError::Admission(WorkBudgetError::ZeroInstructionBudget))
    ));
    group.next_id = u64::MAX;
    assert!(matches!(
        group.spawn(module("7;"), config(1), "overflow"),
        Err(ExecutionGroupStartError::IdentityExhausted)
    ));
    assert_eq!(group.remaining_instructions(), 128);
    assert_eq!(group.retained(), 0);
    zero.close_and_join(Duration::ZERO).unwrap();
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn taking_one_task_control_does_not_cancel_another_task() {
    let parent = ExecutionWorkPool::new(2048);
    let mut group = ExecutionTaskGroup::new(&parent, 2048, 2).unwrap();
    let (hook, entered, release) = parked(false);
    let first = group.spawn_with_hook(
        module("let object = {}; while (true) {}"), config(1024), "one", Some(hook),
    ).unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let second = group.spawn(module("42;"), config(128), "two").unwrap();
    group.task_control(first).unwrap().cancel();
    assert!(!group.is_closed());
    release.send(()).unwrap();
    cancelled(collect(&mut group, first));
    collect(&mut group, second).unwrap().unwrap();
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn drop_closes_escaped_control_without_refunding_or_revoking_parent() {
    let parent = ExecutionWorkPool::new(256);
    let group = ExecutionTaskGroup::new(&parent, 128, 1).unwrap();
    let control = group.control();
    drop(group);
    assert!(control.is_cancelled());
    assert!(!parent.is_revoked());
    assert_eq!(parent.remaining(), 128);
    drop(parent.reserve(128).unwrap());
}

#[test]
fn debug_output_does_not_include_guest_source_or_trace() {
    let parent = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&parent, 256, 1).unwrap();
    let id = group.spawn(module("'private-result';"), config(128), "private-trace").unwrap();
    wait_for_all(&mut group);
    let debug = format!("{group:?}");
    assert!(!debug.contains("private-result"));
    assert!(!debug.contains("private-trace"));
    group.take_result(id).unwrap().unwrap().unwrap();
    group.close_and_join(Duration::ZERO).unwrap();
}
