#![forbid(unsafe_code)]

//! bd-9vouw.189: authority follows code across generated-code boundaries. A
//! closure of the program that `new Function` code calls back runs with the
//! program's grant, as a generated closure the program calls runs within its
//! contained grant. ejs compiles a template with `new Function` and calls its
//! own `escapeFn` from it; that `String(...)` was refused ("capability
//! denied: builtin:String") under the template's contained grant, so ejs
//! could not render. Expected lines are Node v22.2.0's output (Bun 1.4.2
//! prints the same). Containment of generated code itself stays pinned by
//! the bd-fw7zd.8 unit tests and function_constructor_conformance_bd_8enww_3_5.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

/// Runs the program as frankenctl does. Generated code itself cannot reach
/// `Function` (its realm forbids that global), so the cases alternate the
/// boundary through closures the program passes in.
fn run(source: &str, lane: LaneChoice) -> Vec<String> {
    let package = ExtensionPackage {
        extension_id: "generated-code-host-callbacks".to_string(),
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
    .unwrap_or_else(|error| panic!("{lane:?}: {error}"))
    .console_output
    .into_iter()
    .map(|line| line.message)
    .collect()
}

#[test]
fn program_closures_called_from_generated_code_keep_their_authority() {
    let source = "function escapeXML(markup) {\n  return String(markup).replace(/[&<>\"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;' })[c]);\n}\nconst template = new Function('escapeFn', 'locals', \"var out = ''; out += '<h1>' + escapeFn(locals.title) + '</h1>'; locals.items.forEach(function (i) { out += escapeFn(i) + ','; }); return out;\");\nconsole.log(template(escapeXML, { title: 'T&<x>', items: [1, 2] }));\nconst mapper = new Function('cb', 'return [1, 2].map(cb).join(\";\");');\nconsole.log(mapper(function (v) { return String(v * 2) + JSON.stringify({ v: v }) + Math.max(v, 1); }));\nconst twice = new Function('f', 'x', 'return f(f(x));');\nconst wrap = new Function('g', 'v', 'return \"[\" + g(v) + \"]\";');\nconsole.log(twice(function (v) { return wrap(function (w) { return String(w).length + w; }, v); }, 5));\n";
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane),
            [
                "<h1>T&amp;&lt;x&gt;</h1>1,2,",
                "2{\"v\":1}1;4{\"v\":2}2",
                "[3[6]]"
            ],
            "{lane:?}"
        );
    }
}
