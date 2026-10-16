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
