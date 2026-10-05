#![forbid(unsafe_code)]

//! bd-9vouw.186: `process.nextTick` read as a value is the engine's next-tick
//! scheduler, the same hostcall the call shape lowers to. Libraries probe and
//! keep it (async: `typeof process.nextTick === 'function'`,
//! `defer = process.nextTick`); `typeof` gave "undefined" and a module with
//! such a read was refused whole as an `env.read` ambient access. Expected
//! line is Node v22.2.0's output (Bun 1.4.2 prints the same).

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn run(source: &str, lane: LaneChoice) -> Vec<String> {
    let package = ExtensionPackage {
        extension_id: "process-next-tick-value".to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec!["builtin".to_string(), "timer".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        parse_goal: ParseGoal::Script,
        ..OrchestratorConfig::default()
    })
    .execute(&package)
    .unwrap_or_else(|error| panic!("{lane:?}: {error}"))
    .console_output
    .into_iter()
    .map(|line| line.message)
    .collect()
}

/// The value runs callbacks on the next-tick queue, before promise jobs.
#[test]
fn process_next_tick_is_a_function_value() {
    let source = "const hasNextTick = typeof process === 'object' && typeof process.nextTick === 'function';\nconst defer = process.nextTick;\nconst order = [];\ndefer(() => order.push('deferred'));\nPromise.resolve().then(() => order.push('promise'));\nprocess.nextTick((a, b) => order.push('tick ' + a + b), 'x', 'y');\nconst schedule = hasNextTick ? process.nextTick : setImmediate;\nschedule(() => order.push('scheduled'));\nsetTimeout(() => console.log(hasNextTick, typeof defer, order.join()), 1);\n";
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane),
            ["true function deferred,tick xy,scheduled,promise"],
            "{lane:?}"
        );
    }
}

/// Planted negative: only `nextTick` is exempt; `process.env` stays refused.
#[test]
fn other_process_members_stay_refused() {
    let package = ExtensionPackage {
        extension_id: "process-env".to_string(),
        source: "const e = process.env; console.log(typeof e);".to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec!["builtin".to_string(), "timer".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    let error = ExecutionOrchestrator::new(OrchestratorConfig::default())
        .execute(&package)
        .expect_err("process.env must stay refused");
    assert!(error.to_string().contains("ambient authority"), "{error}");
}
