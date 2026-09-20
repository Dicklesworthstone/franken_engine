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
        .execute(&package("let count = 0; while (count < 20000) { count = count + 1; } count;"))
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
