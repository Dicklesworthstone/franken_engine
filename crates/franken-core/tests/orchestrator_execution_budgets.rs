#![forbid(unsafe_code)]
//! Resource limits exercised through the public parse/lower/execute boundary.

use frankenengine_core as runtime;

use std::collections::BTreeMap;

use runtime::baseline_interpreter::{InterpreterError, LaneChoice};
use runtime::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use runtime::runtime_config::RuntimeConfig;

fn package(source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "orchestrator-resource-budget".to_string(),
        source: source.to_string(),
        source_file: None,
        capabilities: Vec::new(),
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn orchestrator(lane: LaneChoice, runtime: RuntimeConfig) -> ExecutionOrchestrator {
    ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        },
        runtime,
    )
    .expect("valid lab resource configuration")
}

fn assert_closed(error: &OrchestratorError) {
    let failure = error
        .post_cell_failure()
        .expect("native refusal must retain execution-cell cleanup");
    assert!(failure.cleanup.close_succeeded());
}

#[test]
fn revocation_after_admission_interrupts_ordinary_native_dispatch() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        // The counter is the synchronization point: revocation happens only
        // after reserve has debited the run. It may race reserve's final
        // revocation check or native entry; both must refuse without refund.
        let budget = 100_000_000;
        let root = ExecutionWorkPool::new(budget * 2);
        let tenant = root.partition(budget * 2).unwrap();
        let worker_pool = tenant.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut config = RuntimeConfig::default();
            config.execution.deterministic_budget = budget;
            config.execution.throughput_budget = budget;
            let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
                OrchestratorConfig {
                    force_lane: lane,
                    work_pool: Some(worker_pool),
                    ..OrchestratorConfig::default()
                },
                config,
            )
            .unwrap();
            let error = orchestrator
                .execute(&package("while (true) {}"))
                .unwrap_err();
            assert!(
                matches!(
                    error.primary_error(),
                    OrchestratorError::Interpreter(InterpreterError::Cancelled)
                        | OrchestratorError::WorkBudget(
                            runtime::execution_orchestrator::WorkBudgetError::Revoked
                        )
                ),
                "{lane:?}: admitted execution must observe live revocation: {error:?}"
            );
            assert_closed(&error);
            assert_eq!(orchestrator.execution_count(), 0);
            done_tx.send(()).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        while tenant.committed() == 0 {
            assert!(!worker.is_finished(), "worker stopped before admission");
            assert!(
                Instant::now() < deadline,
                "worker never reserved its budget"
            );
            std::thread::yield_now();
        }
        root.revoke();
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("revoked execution must terminate, not consume its full allowance");
        worker.join().unwrap();
        assert_eq!(tenant.committed(), budget);
        assert_eq!(tenant.remaining(), budget, "cancellation is not a refund");
    }
}

#[test]
fn configured_instruction_limits_reach_both_native_profiles() {
    let package = package("while (true) {}");
    for (lane, budget) in [(LaneChoice::QuickJs, 7), (LaneChoice::V8, 11)] {
        let mut runtime = RuntimeConfig::default();
        runtime.execution.deterministic_budget = 7;
        runtime.execution.throughput_budget = 11;
        let mut orchestrator = orchestrator(lane, runtime);
        let error = orchestrator.execute(&package).expect_err("loop must stop");
        assert!(
            matches!(
                error.primary_error(),
                OrchestratorError::Interpreter(InterpreterError::BudgetExhausted {
                    executed,
                    budget: actual,
                }) if *executed == budget && *actual == budget
            ),
            "{lane}: configured {budget}, got {error:?}"
        );
        assert_closed(&error);
        assert_eq!(orchestrator.execution_count(), 0);
    }
}

#[test]
fn configured_register_limits_reach_both_native_profiles() {
    let package = package("let a = 1; let b = 2; a + b;");
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        orchestrator(lane, RuntimeConfig::default())
            .execute(&package)
            .expect("positive control must execute with the ordinary register allowance");
        let mut runtime = RuntimeConfig::default();
        runtime.execution.deterministic_max_registers = 2;
        runtime.execution.throughput_max_registers = 2;
        let error = orchestrator(lane, runtime)
            .execute(&package)
            .expect_err("configured register ceiling must be enforced");
        assert!(
            matches!(
                error.primary_error(),
                OrchestratorError::Interpreter(InterpreterError::RegisterOutOfBounds {
                    max: 2,
                    ..
                })
            ),
            "{lane}: {error:?}"
        );
        assert_closed(&error);
    }
}

#[test]
fn configured_call_depth_reaches_both_native_profiles() {
    let package = package(
        "function descend(n) { if (n === 0) { return 42; } \
         return descend(n - 1); } descend(8);",
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        orchestrator(lane, RuntimeConfig::default())
            .execute(&package)
            .expect("positive control must finish the finite recursive program");
        let mut runtime = RuntimeConfig::default();
        runtime.execution.max_call_depth = 2;
        let error = orchestrator(lane, runtime)
            .execute(&package)
            .expect_err("configured call depth must be enforced");
        assert!(
            matches!(
                error.primary_error(),
                OrchestratorError::Interpreter(InterpreterError::StackOverflow { max: 2, .. })
            ),
            "{lane}: {error:?}"
        );
        assert_closed(&error);
    }
}

#[test]
fn operator_can_grant_more_than_the_default_instruction_allowance() {
    let mut runtime = RuntimeConfig::default();
    let default_budget = runtime.execution.deterministic_budget;
    runtime.execution.deterministic_budget = 2_000_000;
    let result = orchestrator(LaneChoice::QuickJs, runtime)
        .execute(&package(
            "let count = 0; while (count < 20000) { count = count + 1; } count;",
        ))
        .expect("configured allowance must not silently revert to profile defaults");
    assert!(result.instructions_executed > default_budget);
    assert!(result.instructions_executed <= 2_000_000);
    assert_eq!(result.lane, LaneChoice::QuickJs);
}

#[test]
fn adaptive_dispatch_also_uses_the_selected_profiles_configured_limit() {
    let mut runtime = RuntimeConfig::default();
    runtime.execution.deterministic_budget = 7;
    runtime.execution.throughput_budget = 7;
    let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig::default(),
        runtime,
    )
    .expect("valid adaptive resource configuration");
    let error = orchestrator
        .execute(&package("while (true) {}"))
        .expect_err("adaptive routing cannot bypass the configured instruction ceiling");
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::Interpreter(InterpreterError::BudgetExhausted {
                executed: 7,
                budget: 7,
            })
        ),
        "{error:?}"
    );
    assert_closed(&error);
}

fn shared_orchestrator(
    pool: &runtime::execution_orchestrator::ExecutionWorkPool,
    lane: Option<LaneChoice>,
) -> ExecutionOrchestrator {
    let mut runtime = RuntimeConfig::default();
    runtime.execution.deterministic_budget = 128;
    runtime.execution.throughput_budget = 256;
    ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: lane,
            work_pool: Some(pool.clone()),
            ..OrchestratorConfig::default()
        },
        runtime,
    )
    .expect("valid shared execution configuration")
}

fn assert_shared_denial(error: &OrchestratorError, requested: u64, remaining: u64) {
    use runtime::execution_orchestrator::WorkBudgetError;
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::WorkBudget(WorkBudgetError::Exhausted {
                requested: actual_requested,
                remaining: actual_remaining,
            }) if *actual_requested == requested && *actual_remaining == remaining
        ),
        "expected shared denial {requested}/{remaining}, got {error:?}"
    );
    assert_closed(error);
}

#[test]
fn ordinary_execute_cannot_reset_the_shared_allowance() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    let pool = ExecutionWorkPool::new(256);
    let mut orchestrator = shared_orchestrator(&pool, Some(LaneChoice::QuickJs));
    for remaining in [128, 0] {
        let result = orchestrator.execute(&package("42;")).unwrap();
        assert!(result.instructions_executed > 0 && result.instructions_executed < 128);
        assert_eq!(
            pool.remaining(),
            remaining,
            "early completion is not a refund"
        );
    }
    let error = orchestrator.execute(&package("42;")).unwrap_err();
    assert_shared_denial(&error, 128, 0);
    assert_eq!(orchestrator.execution_count(), 2);
    drop(orchestrator);
    let error = shared_orchestrator(&pool, Some(LaneChoice::QuickJs))
        .execute(&package("42;"))
        .unwrap_err();
    assert_shared_denial(&error, 128, 0);
}

#[test]
fn cloned_orchestrator_configuration_shares_instead_of_minting_work() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    let pool = ExecutionWorkPool::new(128);
    let config = OrchestratorConfig {
        force_lane: Some(LaneChoice::QuickJs),
        work_pool: Some(pool.clone()),
        ..OrchestratorConfig::default()
    };
    let mut runtime = RuntimeConfig::default();
    runtime.execution.deterministic_budget = 128;
    let mut first =
        ExecutionOrchestrator::try_new_lab_with_runtime_config(config.clone(), runtime.clone())
            .unwrap();
    let mut second =
        ExecutionOrchestrator::try_new_lab_with_runtime_config(config, runtime).unwrap();
    first.execute(&package("42;")).unwrap();
    let error = second.execute(&package("42;")).unwrap_err();
    assert_shared_denial(&error, 128, 0);
    assert_eq!(second.execution_count(), 0);
}

#[test]
fn native_failure_and_budget_exhaustion_burn_the_admitted_allowance() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    for source in ["throw 7;", "while (true) {}"] {
        let pool = ExecutionWorkPool::new(128);
        let mut orchestrator = shared_orchestrator(&pool, Some(LaneChoice::QuickJs));
        let error = orchestrator.execute(&package(source)).unwrap_err();
        match source {
            "throw 7;" => assert!(matches!(
                error.primary_error(),
                OrchestratorError::Interpreter(InterpreterError::UncaughtException { .. })
            )),
            _ => assert!(matches!(
                error.primary_error(),
                OrchestratorError::Interpreter(InterpreterError::BudgetExhausted {
                    budget: 128,
                    ..
                })
            )),
        }
        assert_closed(&error);
        assert_eq!(pool.remaining(), 0);
        let retry = orchestrator.execute(&package("42;")).unwrap_err();
        assert_shared_denial(&retry, 128, 0);
    }
}

#[test]
fn validation_and_parsing_do_not_spend_native_instruction_reservations() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    let pool = ExecutionWorkPool::new(128);
    let mut orchestrator = shared_orchestrator(&pool, Some(LaneChoice::QuickJs));
    for source in ["", "let = ;"] {
        let error = orchestrator.execute(&package(source)).unwrap_err();
        assert!(!matches!(
            error.primary_error(),
            OrchestratorError::WorkBudget(_)
        ));
        assert_eq!(pool.remaining(), 128);
    }
    orchestrator.execute(&package("42;")).unwrap();
    assert_eq!(pool.remaining(), 0);
}

#[test]
fn chosen_profile_not_default_or_average_determines_admission() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    let pool = ExecutionWorkPool::new(384);
    shared_orchestrator(&pool, Some(LaneChoice::QuickJs))
        .execute(&package("42;"))
        .unwrap();
    assert_eq!(pool.remaining(), 256);
    shared_orchestrator(&pool, Some(LaneChoice::V8))
        .execute(&package("42;"))
        .unwrap();
    assert_eq!(pool.remaining(), 0);
    let error = shared_orchestrator(&pool, Some(LaneChoice::V8))
        .execute(&package("42;"))
        .unwrap_err();
    assert_shared_denial(&error, 256, 0);
}

#[test]
fn exhausted_tenant_cannot_take_a_siblings_delegated_allowance() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    let root = ExecutionWorkPool::new(384);
    let tenant_a = root.partition(128).unwrap();
    let tenant_b = root.partition(256).unwrap();
    let mut a = shared_orchestrator(&tenant_a, Some(LaneChoice::QuickJs));
    let mut b = shared_orchestrator(&tenant_b, Some(LaneChoice::V8));
    a.execute(&package("42;")).unwrap();
    assert_shared_denial(&a.execute(&package("42;")).unwrap_err(), 128, 0);
    assert_eq!(tenant_b.remaining(), 256);
    b.execute(&package("42;")).unwrap();
    assert_eq!(tenant_b.remaining(), 0);
    assert_eq!(root.remaining(), 0);
}

#[test]
fn adaptive_selection_reserves_the_profile_that_actually_executes() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    let pool = ExecutionWorkPool::new(1024);
    let result = shared_orchestrator(&pool, None)
        .execute(&package("42;"))
        .unwrap();
    let charged = match result.lane {
        LaneChoice::QuickJs => 128,
        LaneChoice::V8 => 256,
    };
    assert_eq!(pool.committed(), charged);
    assert_eq!(pool.remaining(), 1024 - charged);
}

#[test]
fn independent_workers_cannot_overcommit_one_shared_pool() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    use std::sync::{Arc, Barrier};
    let pool = ExecutionWorkPool::new(512);
    let start = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let pool = pool.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                // Construct Rc-based interpreter state on its owning thread.
                let mut orchestrator = shared_orchestrator(&pool, Some(LaneChoice::QuickJs));
                start.wait();
                match orchestrator.execute(&package("42;")) {
                    Ok(result) => {
                        assert!(result.instructions_executed > 0);
                        true
                    }
                    Err(error) => {
                        assert_shared_denial(&error, 128, 0);
                        false
                    }
                }
            })
        })
        .collect();
    let admitted = handles
        .into_iter()
        .map(|worker| usize::from(worker.join().expect("worker must not panic")))
        .sum::<usize>();
    assert_eq!(admitted, 4);
    assert_eq!(pool.committed(), 512);
    assert_eq!(pool.remaining(), 0);
}

#[test]
fn insufficient_admission_leaves_the_residual_pool_untouched() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    for available in [0, 127] {
        let pool = ExecutionWorkPool::new(available);
        let mut orchestrator = shared_orchestrator(&pool, Some(LaneChoice::QuickJs));
        let error = orchestrator.execute(&package("42;")).unwrap_err();
        assert_shared_denial(&error, 128, available);
        assert_eq!(pool.remaining(), available);
        assert_eq!(pool.committed(), 0);
        assert_eq!(orchestrator.execution_count(), 0);
    }
}

// Admission refusal through the ordinary orchestrator, including its cleanup
// path. These pre-dispatch cases do not claim in-flight orchestrator cancellation.
fn assert_scope_revoked(error: &OrchestratorError) {
    use runtime::execution_orchestrator::WorkBudgetError;
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::WorkBudget(WorkBudgetError::Revoked)
        ),
        "expected work-scope revocation, got {error:?}"
    );
    assert_closed(error);
}

#[test]
fn revoked_scope_denies_forced_and_adaptive_dispatch_with_unspent_quota() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        let pool = ExecutionWorkPool::new(512);
        let mut orchestrator = shared_orchestrator(&pool, lane);
        pool.revoke();
        let error = orchestrator.execute(&package("42;")).unwrap_err();
        assert_scope_revoked(&error);
        assert_eq!(orchestrator.execution_count(), 0);
        assert_eq!(pool.remaining(), 512);
        assert_eq!(pool.committed(), 0);
    }
}

#[test]
fn ancestor_revocation_reaches_existing_and_recreated_orchestrators() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    let root = ExecutionWorkPool::new(512);
    let tenant = root.partition(512).unwrap();
    let cell = tenant.partition(512).unwrap();
    let mut existing = shared_orchestrator(&cell, Some(LaneChoice::QuickJs));
    root.revoke();
    assert_scope_revoked(&existing.execute(&package("42;")).unwrap_err());
    drop(existing);
    for lane in [Some(LaneChoice::QuickJs), Some(LaneChoice::V8), None] {
        let mut recreated = shared_orchestrator(&cell, lane);
        assert_scope_revoked(&recreated.execute(&package("42;")).unwrap_err());
        assert_eq!(recreated.execution_count(), 0);
    }
    assert_eq!(root.remaining(), 0);
    assert_eq!(cell.remaining(), 512);
    assert!(tenant.is_revoked() && cell.is_revoked());
}

#[test]
fn tenant_revocation_stops_reuse_but_preserves_sibling_and_parent_execution() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    let root = ExecutionWorkPool::new(640);
    let tenant_a = root.partition(256).unwrap();
    let tenant_b = root.partition(256).unwrap();
    let mut a = shared_orchestrator(&tenant_a, Some(LaneChoice::QuickJs));
    let mut b = shared_orchestrator(&tenant_b, Some(LaneChoice::V8));
    a.execute(&package("42;")).unwrap();
    assert_eq!(tenant_a.remaining(), 128);
    tenant_a.revoke();
    assert_scope_revoked(&a.execute(&package("42;")).unwrap_err());
    assert_eq!(a.execution_count(), 1);
    assert_eq!(tenant_a.remaining(), 128);
    b.execute(&package("42;")).unwrap();
    shared_orchestrator(&root, Some(LaneChoice::QuickJs))
        .execute(&package("42;"))
        .unwrap();
    assert!(!tenant_b.is_revoked() && !root.is_revoked());
    assert_eq!(tenant_b.remaining(), 0);
    assert_eq!(root.remaining(), 0);
}

#[test]
fn scope_revocation_remains_typed_even_when_the_balance_is_insufficient() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    for available in [0, 127, 512] {
        let pool = ExecutionWorkPool::new(available);
        pool.revoke();
        let mut orchestrator = shared_orchestrator(&pool, Some(LaneChoice::QuickJs));
        assert_scope_revoked(&orchestrator.execute(&package("42;")).unwrap_err());
        assert_eq!(pool.remaining(), available);
        assert_eq!(pool.committed(), 0);
        assert_eq!(orchestrator.execution_count(), 0);
    }
}

#[test]
fn revocation_reaches_preconfigured_workers_before_public_dispatch() {
    use runtime::execution_orchestrator::ExecutionWorkPool;
    use std::sync::mpsc;
    use std::time::Duration;

    let pool = ExecutionWorkPool::new(2048);
    let (ready_tx, ready_rx) = mpsc::channel();
    let mut releases = Vec::new();
    let workers: Vec<_> = (0..8)
        .map(|index| {
            let pool = pool.clone();
            let ready = ready_tx.clone();
            let (release_tx, release_rx) = mpsc::channel();
            releases.push(release_tx);
            std::thread::spawn(move || {
                // Keep the native Rc-based runtime on its owning thread.
                let lane = if index % 2 == 0 {
                    LaneChoice::QuickJs
                } else {
                    LaneChoice::V8
                };
                let mut orchestrator = shared_orchestrator(&pool, Some(lane));
                ready.send(()).unwrap();
                release_rx.recv().unwrap();
                assert_scope_revoked(&orchestrator.execute(&package("42;")).unwrap_err());
                assert_eq!(orchestrator.execution_count(), 0);
            })
        })
        .collect();
    drop(ready_tx);
    for _ in 0..workers.len() {
        ready_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("worker must initialize before revocation");
    }
    pool.revoke();
    for release in releases {
        release.send(()).unwrap();
    }
    for worker in workers {
        worker
            .join()
            .expect("revoked worker must cleanly deny dispatch");
    }
    assert_eq!(pool.remaining(), 2048);
    assert_eq!(pool.committed(), 0);
}
