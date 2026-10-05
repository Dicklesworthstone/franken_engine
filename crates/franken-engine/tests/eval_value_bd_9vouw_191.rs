#![forbid(unsafe_code)]

//! bd-9vouw.191: `eval` read as a value. get-intrinsic (under qs, call-bind,
//! side-channel and so express) keeps `'%eval%': eval` in its intrinsics
//! table and never calls it; the read was an `runtime.eval` ambient access,
//! so the module was refused whole at lowering. A non-call read is now an
//! inert function named `eval` (length 1) whose every call throws a
//! catchable EvalError: no source text is compiled through it. A direct
//! `eval(src)` keeps its lowering refusal.
//!
//! The value line is Node v22.2.0's output (Bun 1.4.2 prints the same).
//! Calling the value is a deliberate deviation: Node evaluates the string.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

fn run(source: &str, lane: LaneChoice) -> Result<Vec<String>, String> {
    let package = ExtensionPackage {
        extension_id: "eval-value".to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec!["builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        parse_goal: ParseGoal::Script,
        ..OrchestratorConfig::default()
    })
    .execute(&package)
    .map(|result| {
        result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect()
    })
    .map_err(|error| error.to_string())
}

const LANES: [LaneChoice; 2] = [LaneChoice::QuickJs, LaneChoice::V8];

#[test]
fn eval_read_as_a_value_is_a_function_named_eval() {
    let source = "var I = { '%eval%': eval }\nvar stored = eval\nconsole.log(typeof I['%eval%'], I['%eval%'].name, I['%eval%'].length, typeof eval, stored === I['%eval%'])\n";
    for lane in LANES {
        assert_eq!(
            run(source, lane).unwrap_or_else(|error| panic!("{lane:?}: {error}")),
            ["function eval 1 function true"],
            "{lane:?}"
        );
    }
}

#[test]
fn calling_the_eval_value_throws_a_catchable_eval_error() {
    let source = "var e = eval\ntry { e('1 + 1'); console.log('ran') } catch (err) { console.log(err.name, err instanceof EvalError) }\ntry { (0, eval)('2'); console.log('ran') } catch (err) { console.log(err.name) }\n";
    for lane in LANES {
        assert_eq!(
            run(source, lane).unwrap_or_else(|error| panic!("{lane:?}: {error}")),
            ["EvalError true", "EvalError"],
            "{lane:?}"
        );
    }
}

#[test]
fn a_direct_eval_call_is_still_refused_at_lowering() {
    for source in ["eval('1 + 1')\n", "var x = 1; console.log(eval('x'))\n"] {
        for lane in LANES {
            let error = run(source, lane).expect_err("direct eval must be refused");
            assert!(
                error.contains("runtime.eval"),
                "{lane:?}: unexpected error for {source:?}: {error}"
            );
        }
    }
}
