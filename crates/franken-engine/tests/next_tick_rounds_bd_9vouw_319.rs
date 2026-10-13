#![forbid(unsafe_code)]

//! bd-9vouw.319: Node runs the next-tick queue and the promise jobs in
//! rounds. All queued ticks run (ticks they queue included), then every
//! promise job (jobs they queue included), and only then the ticks those
//! jobs queued. The engine drained the tick queue before every promise
//! job, so a tick a job queued ran ahead of the jobs already waiting. The
//! program covers the main script's turn and a timer's turn. Node v22.2.0
//! gives these lines; Bun 1.4.2 agrees.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn run(source: &str, lane: LaneChoice) -> Vec<String> {
    let package = ExtensionPackage {
        extension_id: "next-tick-rounds".to_string(),
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

#[test]
fn ticks_queued_by_promise_jobs_wait_for_the_job_queue_to_drain() {
    let source = r#"const log = [];
console.log('sync');
process.nextTick(() => log.push('t1'));
Promise.resolve().then(() => { log.push('p1'); process.nextTick(() => log.push('t2')); });
Promise.resolve().then(() => log.push('p2'));
Promise.resolve().then(() => { process.nextTick(() => log.push('tickA')); log.push('p3'); }).then(() => log.push('p4')).then(() => log.push('p5'));
process.nextTick(() => { log.push('tick0'); Promise.resolve().then(() => log.push('pt')); process.nextTick(() => log.push('tick0b')); });
setTimeout(() => {
  log.push('timer');
  process.nextTick(() => log.push('tt'));
  Promise.resolve().then(() => { log.push('tp'); process.nextTick(() => log.push('tpt')); }).then(() => log.push('tp2'));
  setTimeout(() => console.log(log.join(' ')), 5);
}, 5);
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane),
            [
                "sync",
                "t1 tick0 tick0b p1 p2 p3 pt p4 p5 t2 tickA timer tt tp tp2 tpt"
            ],
            "{lane:?}"
        );
    }
}
