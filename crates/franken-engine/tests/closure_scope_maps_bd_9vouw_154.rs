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
