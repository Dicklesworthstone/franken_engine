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
//! programs create their closures and calls in loops.

use frankenengine_engine::HybridRouter;

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

/// 2,000 async calls pending at once in a script with 3,000 globals: every
/// suspended activation was charged the global scope's map again (past
/// 512 MiB).
#[test]
fn many_pending_async_calls_beside_a_large_scope_fit_the_budget() {
    let mut source: String = (0..3000).map(|i| format!("var v{i} = {i};\n")).collect();
    source.push_str(
        "var ps = [];\n\
         async function wait(i) { await null; return i + v2999; }\n\
         for (var i = 0; i < 2000; i++) ps.push(wait(i));\n\
         ps.length + ' ' + typeof ps[1999].then;",
    );
    assert_eq!(eval(&source), "2000 function");
}
