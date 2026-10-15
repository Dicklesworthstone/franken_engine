#![forbid(unsafe_code)]
//! Shared admission capacity at the existing public native entry points.
//!
//! Synchronization hooks park actual native allocations; they are not provider
//! drain or OS isolation evidence. No test treats cancellation as completion.

use frankenengine_core as runtime;

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use runtime::ast::ParseGoal;
use runtime::baseline_interpreter::{
    AllocKind, FunctionRef, HookAction, HookContext, InterpreterConfig, InterpreterError,
    InterpreterHook, LaneChoice, ObjectRef, PropertyKey, Value,
};
use runtime::capability::RuntimeCapability;
use runtime::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use runtime::execution_task_group::{
    ExecutionGroupStartError, ExecutionTaskGroup, ExecutionTaskId, ExecutionTaskOutcome,
};
use runtime::execution_work_budget::{ExecutionTaskJoinError, ExecutionWorkPool, WorkBudgetError};
use runtime::ir_contract::{Ir0Module, Ir3Module};
use runtime::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use runtime::parser::{CanonicalEs2020Parser, Es2020Parser};
use runtime::runtime_config::RuntimeConfig;

const WAIT: Duration = Duration::from_secs(10);
const BUDGET: u64 = 128;

fn package(source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "shared-admission-limit".into(),
        source: source.into(),
        source_file: None,
        capabilities: Vec::new(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    }
}

fn orchestrator(pool: &ExecutionWorkPool, lane: Option<LaneChoice>) -> ExecutionOrchestrator {
    let mut runtime = RuntimeConfig::default();
    runtime.execution.deterministic_budget = BUDGET;
    runtime.execution.throughput_budget = BUDGET;
    ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: lane,
            work_pool: Some(pool.clone()),
            ..OrchestratorConfig::default()
        },
        runtime,
    )
    .expect("valid bounded native orchestrator")
}

fn assert_cell_closed(error: &OrchestratorError) {
    assert!(
        error
            .post_cell_failure()
            .expect("post-cell refusal must retain cleanup evidence")
            .cleanup
            .close_succeeded()
    );
}

fn module(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("shared-admission source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "shared-admission.js"),
        &LoweringContext::new("shared-admission", "shared-admission", "shared-admission"),
    )
    .expect("shared-admission source must lower")
    .ir3
}

fn config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = BUDGET;
    config.checkpoint_density = 1;
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn wait_for_all(group: &mut ExecutionTaskGroup) {
    let deadline = Instant::now() + WAIT;
    while group.pending() != 0 {
        group.poll();
        assert!(Instant::now() < deadline, "native worker did not finish");
        thread::sleep(Duration::from_millis(1));
    }
}

fn collect(group: &mut ExecutionTaskGroup, id: ExecutionTaskId) -> ExecutionTaskOutcome {
    wait_for_all(group);
    group.take_result(id).expect("joined result remains owned")
}

// A real allocation hook establishes that the admitted worker has entered the
// native VM. The release channel makes cancellation-versus-completion explicit.
struct ParkedHook {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
    parked: AtomicBool,
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
        }
        HookAction::Allow
    }

    fn pre_import(&self, _: &HookContext, _: &str) -> HookAction {
        HookAction::Allow
    }
}

fn parked() -> (Arc<ParkedHook>, Receiver<()>, Sender<()>) {
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    (
        Arc::new(ParkedHook {
            entered: entered_tx,
            release: Mutex::new(release_rx),
            parked: AtomicBool::new(false),
        }),
        entered,
        release,
    )
}

#[test]
fn forced_and_adaptive_orchestrators_obey_shared_capacity_and_recover() {
    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        let pool = ExecutionWorkPool::with_admission_limit(512, 1);
        let held = pool.reserve(1).unwrap();
        let mut runtime = orchestrator(&pool, lane);
        let error = runtime.execute(&package("7;")).unwrap_err();
        assert!(matches!(
            error.primary_error(),
            OrchestratorError::WorkBudget(WorkBudgetError::AdmissionLimit { limit: 1 })
        ));
        assert_cell_closed(&error);
        assert_eq!(runtime.execution_count(), 0);
        assert_eq!(pool.remaining(), 511, "capacity denial must not debit fuel");
        assert_eq!(pool.outstanding_admissions(), 1);
        drop(held);
        let result = runtime.execute(&package("7;")).unwrap();
        assert_eq!(result.execution_value, "7");
        if let Some(lane) = lane {
            assert_eq!(result.lane, lane);
        }
        assert!(result.instructions_executed > 0);
        assert!(result.instructions_executed <= BUDGET);
        assert_eq!(runtime.execution_count(), 1);
        assert_eq!(pool.remaining(), 511 - BUDGET);
        assert_eq!(pool.outstanding_admissions(), 0);
        assert!(!pool.is_revoked());
    }
}

#[test]
fn zero_capacity_is_not_an_uncapped_orchestrator_mode() {
    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        let pool = ExecutionWorkPool::with_admission_limit(512, 0);
        let mut runtime = orchestrator(&pool, lane);
        let error = runtime.execute(&package("7;")).unwrap_err();
        assert!(matches!(
            error.primary_error(),
            OrchestratorError::WorkBudget(WorkBudgetError::AdmissionLimit { limit: 0 })
        ));
        assert_cell_closed(&error);
        assert_eq!(runtime.execution_count(), 0);
        assert_eq!(pool.remaining(), 512);
        assert_eq!(pool.outstanding_admissions(), 0);
    }
}

#[test]
fn native_orchestrator_failures_release_capacity_without_erasing_cleanup_or_spent_work() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = ExecutionWorkPool::with_admission_limit(512, 1);
        let tenant = root.partition(384).unwrap();
        let mut runtime = orchestrator(&tenant, Some(lane));
        for (source, trap) in [("throw 7;", true), ("while (true) {}", false)] {
            let error = runtime.execute(&package(source)).unwrap_err();
            if trap {
                assert!(matches!(
                    error.primary_error(),
                    OrchestratorError::Interpreter(InterpreterError::UncaughtException { .. })
                ));
            } else {
                assert!(matches!(
                    error.primary_error(),
                    OrchestratorError::Interpreter(InterpreterError::BudgetExhausted {
                        budget: BUDGET,
                        ..
                    })
                ));
            }
            assert_cell_closed(&error);
            assert_eq!(root.outstanding_admissions(), 0);
            assert_eq!(runtime.execution_count(), 0);
        }
        assert_eq!(tenant.remaining(), BUDGET);
        let result = orchestrator(&root, Some(lane)).execute(&package("42;")).unwrap();
        assert_eq!(result.execution_value, "42");
        assert_eq!(root.remaining(), 0);
        assert_eq!(root.outstanding_admissions(), 0);
        assert_eq!(tenant.remaining(), BUDGET, "sibling work cannot spend tenant credits");
    }
}

#[test]
fn cancelled_blocked_worker_still_blocks_sibling_groups_and_ordinary_orchestration() {
    let root = ExecutionWorkPool::with_admission_limit(1024, 1);
    let mut first = ExecutionTaskGroup::new(&root, 256, 1).unwrap();
    let mut second = ExecutionTaskGroup::new(&root, 256, 1).unwrap();
    // Prepare source and the other orchestrator before parking the worker.
    let blocked = module("let object = {}; while (true) {}");
    let success = module("42;");
    let mut ordinary = orchestrator(&root, Some(LaneChoice::QuickJs));
    let (hook, entered, release) = parked();
    let id = first.spawn_with_hook(blocked, config(), "blocked", Some(hook)).unwrap();
    entered.recv_timeout(WAIT).unwrap();

    // Record observations, then release/join before asserting them. A regression
    // should not leave a parked worker merely because one assertion failed.
    let timeout = first.close_and_join(Duration::ZERO);
    let occupied = root.outstanding_admissions();
    let prepared = AtomicBool::new(false);
    let refused = second.spawn_with_preparation(success, config(), "sibling", |_, _| {
        prepared.store(true, Ordering::Release);
        Ok(None)
    });
    let ordinary_refused = ordinary.execute(&package("7;"));
    let remaining = (root.remaining(), second.remaining_instructions());
    release.send(()).unwrap();
    let joined = first.close_and_join(WAIT);
    wait_for_all(&mut second);

    assert_eq!(timeout, Err(ExecutionTaskJoinError::TimedOut));
    joined.unwrap();
    assert_eq!(occupied, 1);
    assert!(!prepared.load(Ordering::Acquire));
    assert!(matches!(
        refused,
        Err(ExecutionGroupStartError::Admission(WorkBudgetError::AdmissionLimit { limit: 1 }))
    ));
    let error = ordinary_refused.unwrap_err();
    assert!(matches!(
        error.primary_error(),
        OrchestratorError::WorkBudget(WorkBudgetError::AdmissionLimit { limit: 1 })
    ));
    assert_cell_closed(&error);
    assert_eq!(remaining, (512, 256));
    assert_eq!(first.retained(), 1, "joining must retain the cancelled result");
    assert_eq!(root.outstanding_admissions(), 0);
    assert!(!second.is_closed());
    assert!(!root.is_revoked());

    let peer = second.spawn(module("42;"), config(), "after-release").unwrap();
    assert_eq!(collect(&mut second, peer).unwrap().unwrap().value.to_string(), "42");
    assert!(matches!(
        first.take_result(id).unwrap(),
        Ok(Err(WorkBudgetError::Interpreter(InterpreterError::Cancelled)))
    ));
    assert_eq!(first.remaining_instructions(), 128);
    assert_eq!(second.remaining_instructions(), 128);
    assert_eq!(root.outstanding_admissions(), 0);
    second.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn finished_results_keep_local_backpressure_without_occupying_family_admissions() {
    let root = ExecutionWorkPool::with_admission_limit(512, 1);
    let mut first = ExecutionTaskGroup::new(&root, 256, 1).unwrap();
    let mut second = ExecutionTaskGroup::new(&root, 256, 1).unwrap();
    let id = first.spawn(module("7;"), config(), "retained").unwrap();
    wait_for_all(&mut first);
    assert_eq!(root.outstanding_admissions(), 0);
    assert_eq!(first.retained(), 1);
    assert!(matches!(
        first.spawn(module("8;"), config(), "uncollected"),
        Err(ExecutionGroupStartError::Capacity { limit: 1 })
    ));
    assert_eq!(first.remaining_instructions(), 128);
    let peer = second.spawn(module("42;"), config(), "independent-retention").unwrap();
    assert_eq!(collect(&mut second, peer).unwrap().unwrap().value.to_string(), "42");
    assert_eq!(first.take_result(id).unwrap().unwrap().unwrap().value.to_string(), "7");
    assert_eq!(root.outstanding_admissions(), 0);
    first.close_and_join(Duration::ZERO).unwrap();
    second.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn trusted_preparation_holds_capacity_and_refusal_releases_only_its_slot() {
    let root = ExecutionWorkPool::with_admission_limit(512, 1);
    let mut group = ExecutionTaskGroup::new(&root, 256, 1).unwrap();
    let mut escaped = None;
    let error = group.spawn_with_preparation(module("7;"), config(), "prepare", |job, _| {
        assert_eq!(root.outstanding_admissions(), 1);
        assert!(matches!(root.reserve(1), Err(WorkBudgetError::AdmissionLimit { limit: 1 })));
        assert_eq!(root.remaining(), 256);
        escaped = Some(job.task_control());
        Err(WorkBudgetError::Revoked)
    }).unwrap_err();
    assert!(matches!(error, ExecutionGroupStartError::Preparation(WorkBudgetError::Revoked)));
    assert!(escaped.unwrap().is_cancelled());
    assert_eq!(root.outstanding_admissions(), 0);
    assert_eq!(group.retained(), 0);
    assert_eq!(group.remaining_instructions(), 128);
    assert!(!group.is_closed());
    assert!(!root.is_revoked());
    let id = group.spawn(module("7;"), config(), "retry").unwrap();
    assert_eq!(collect(&mut group, id).unwrap().unwrap().value.to_string(), "7");
    assert_eq!(root.outstanding_admissions(), 0);
    assert_eq!(group.remaining_instructions(), 0);
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn setup_unwind_closes_its_group_but_does_not_strand_shared_capacity() {
    let root = ExecutionWorkPool::with_admission_limit(512, 1);
    let mut group = ExecutionTaskGroup::new(&root, 256, 1).unwrap();
    let source = module("7;");
    let mut escaped = None;
    let unwind = catch_unwind(AssertUnwindSafe(|| {
        group.spawn_with_preparation(source, config(), "prepare-panic", |job, _| {
            assert_eq!(root.outstanding_admissions(), 1);
            escaped = Some(job.task_control());
            panic!("injected trusted preparation unwind");
        })
    }));
    assert!(unwind.is_err());
    assert!(escaped.unwrap().is_cancelled());
    assert!(group.is_closed());
    assert_eq!(group.retained(), 0);
    assert_eq!(group.remaining_instructions(), 128);
    assert_eq!(root.outstanding_admissions(), 0);
    assert!(!root.is_revoked());
    let result = orchestrator(&root, Some(LaneChoice::V8)).execute(&package("42;")).unwrap();
    assert_eq!(result.execution_value, "42");
    assert_eq!(root.remaining(), 128);
    assert_eq!(root.outstanding_admissions(), 0);
    group.close_and_join(Duration::ZERO).unwrap();
}
