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
//! No-claim: suspended generator / async activations and saved caller
//! chains still charge their captured maps per holder; this covers the
//! closure table only. Lowering N top-level functions is still quadratic
//! (bd-9vouw.153), which is why this program creates its closures in a loop.

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
