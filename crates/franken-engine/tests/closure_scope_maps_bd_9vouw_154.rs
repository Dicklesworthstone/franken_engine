//! bd-9vouw.154: closures share their captured scope maps, and the memory
//! estimate charges each map once.
//!
//! Every closure was charged the key bytes of every binding in every frame
//! it captured, although closures hold the frames' maps by `Rc`
//! (copy-on-write). N closures over a scope with B bindings were estimated
//! at O(N x B) bytes while the process held O(N + B): 1,000 top-level
//! functions next to 1,000 top-level variables exceeded the default 64 MiB
//! budget at 85 MB RSS. The expected string is Node v22.2.0's output.
//!
//! The same held for every other holder of a frame map: each pending async
//! call's suspended activation and each call frame's saved caller chain was
//! charged the whole module scope. Each distinct map is now charged once,
//! by the cold-cell ledger or by the live-chain walk, and the holders charge
//! one slot per frame.
//!
//! No-claim: snapshots the ledger does not hold (a caller set aside during an
//! isolated call, a module's parked async evaluation) and the transient
//! budget checks before a scope clone still count per holder. Lowering N
//! top-level functions is still quadratic (bd-9vouw.153), which is why these
//! programs create their closures and calls in loops. The async case runs on
//! the deterministic (QuickJS-profile) configuration, 256 registers and 64
//! MiB: it was written while a suspended activation saved its whole register
//! window, 4,096 registers (about 268 KB per pending call) on HybridRouter's
//! throughput lane, where any `await` routes a script;
//! pending_async_register_frames_bd_9vouw_167.rs covers that lane.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value
}

/// 1,500 closures over a global scope of 2,000 bindings: under the old
/// per-closure charge this asked for about 160 MB of the 64 MiB default.
#[test]
fn many_closures_over_one_large_scope_fit_the_default_budget() {
    let mut source: String = (0..2000).map(|i| format!("var v{i} = {i};\n")).collect();
    source.push_str(
        "var fns = [];\n\
         for (var i = 0; i < 1500; i++) fns.push(function (x) { return x + v1999; });\n\
         fns.length + ' ' + fns[1499](1);",
    );
    assert_eq!(eval(&source), "1500 2000");
}

/// Recursion 800 deep in a script with 2,000 globals: every call frame's
/// saved caller chain was charged the global scope's map again.
#[test]
fn deep_recursion_beside_a_large_scope_fits_the_default_budget() {
    let mut source: String = (0..2000).map(|i| format!("var v{i} = {i};\n")).collect();
    source.push_str(
        "function depth(n) { return n === 0 ? v1999 : 1 + depth(n - 1); }\n\
         depth(800);",
    );
    assert_eq!(eval(&source), "2799");
}

/// The script's value on the deterministic (QuickJS-profile) defaults:
/// 256-register frames and the 64 MiB budget.
fn eval_deterministic(source: &str) -> String {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "closure_scope_maps.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "closure_scope_maps.js"),
        &LoweringContext::new(
            "scope-maps-trace",
            "scope-maps-decision",
            "scope-maps-policy",
        ),
    )
    .expect("source lowers")
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = 1_000_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "scope-maps");
    let result = core
        .execute(&module)
        .unwrap_or_else(|error| panic!("evaluation failed: {error:?}"));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    match result.value {
        Value::Str(text) => text.to_string(),
        other => format!("{other:?}"),
    }
}

/// 300 async calls pending at once in a script with 2,000 globals: every
/// suspended activation was charged the global scope's map again, past the
/// 64 MiB default.
#[test]
fn many_pending_async_calls_beside_a_large_scope_fit_the_budget() {
    let mut source: String = (0..2000).map(|i| format!("var v{i} = {i};\n")).collect();
    source.push_str(
        "var ps = [];\n\
         async function wait(i) { await null; return i + v1999; }\n\
         for (var i = 0; i < 300; i++) ps.push(wait(i));\n\
         ps.length + ' ' + typeof ps[299].then;",
    );
    assert_eq!(eval_deterministic(&source), "300 function");
}

/// bd-9vouw.223: 2,000 functions beside 2,000 bindings, the shape that
/// lowered in O(functions x bindings) (each function body copied every
/// enclosing lexical and capture-origin marker; bd-9vouw.153 measured 25 s at
/// 4,000 of each). A body now inherits the markers of the names its code
/// mentions, so the closures below still reach what they name through
/// functions that never name it: a counter two functions out, a shadowing
/// `console`, a class field and method, a parameter default, a block-scoped
/// and a catch-scoped shadow. Node v22.2.0 gives this value; Bun 1.4.2
/// agrees.
#[test]
fn closures_reach_outer_names_through_functions_that_never_name_them() {
    let mut source: String = (0..2000).map(|i| format!("var c{i} = {i};\n")).collect();
    source.extend((0..2000).map(|i| format!("function f{i}(x) {{ return x + c{i}; }}\n")));
    source.push_str(
        "let counter = 0;\n\
         function outer() { return function middle() { return () => ++counter; }; }\n\
         const bump = outer()();\n\
         bump(); bump();\n\
         function make() { const console = { log: () => 'mine' }; return function () { return function () { return console.log(); }; }; }\n\
         function k() { let secret = 's'; return class { f = secret; m() { return secret + this.f; } }; }\n\
         function p() { let d = 'd'; return ({ a = d } = {}) => a; }\n\
         let x = 'outer';\n\
         function b() { { let x = 'block'; } return () => x; }\n\
         let e = 'outer-e';\n\
         function c() { try { throw 'inner-e'; } catch (e) { return () => e; } }\n\
         [f0(1), f1999(1), counter, make()()(), new (k())().m(), p()(), b()(), c()(), e].join(' ');",
    );
    assert_eq!(eval(&source), "1 2000 2 mine ss d outer inner-e outer-e");
}

/// bd-9vouw.223: 16 nested functions, each with a loop and a call of the
/// next. The flow analysis summarized every nested function again on each
/// pass of its enclosing body's fixed point, and each summary ran its own
/// fixed point over the functions inside it, so compiling cost about three
/// times more per level (the gate25b frankenctl: depth 8 1.3 s, 10 9.5 s,
/// 12 102 s); a summary is now computed once per analysis for its body and
/// captures' labels. Node v22.2.0 gives this value.
#[test]
fn deeply_nested_functions_compile_once_per_summary() {
    let mut body = "return s + 1;".to_string();
    let mut declaration = String::new();
    for level in (0..16).rev() {
        declaration = format!(
            "function n{level}(a) {{ var s = 0; for (var j = 0; j < 2; j++) {{ s += a; }} {body} }}"
        );
        body = format!("{declaration} return s + n{level}(a);");
    }
    assert_eq!(eval(&format!("{declaration}\nn0(1);")), "33");
}
