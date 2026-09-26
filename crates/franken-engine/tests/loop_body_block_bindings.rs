//! Every entry to a block inside a loop creates fresh let/const/class
//! bindings (ES2020 13.2.13 BlockDeclarationInstantiation).
//!
//! Closures created in different iterations of a loop body used to share one
//! binding cell for a `let`/`const` declared in the body, so each saw the
//! last iteration's value. `for (const x of xs) { const id = x.id;
//! handlers.push(() => use(id)); }` is everyday code. Loop-head bindings
//! (`for (let i ...)`) were already per iteration; body declarations were not.
//!
//! Expected strings are what Node v22.2.0 prints for `String(<program>)`, each
//! run in a fresh context.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn closures_keep_their_iterations_body_bindings() {
    check(
        "var fs1 = []; var i = 0; while (i < 2) { const v = i; fs1.push(function () { return v; }); \
         i++; } var fs2 = []; for (var j = 0; j < 2; j++) { let w = j; fs2.push(() => w); } \
         var fs3 = []; var k = 0; while (k < 2) { const {a} = {a: k}; fs3.push(() => a); k++; } \
         var fs4 = []; for (const q of [5, 6]) { const r = q * 2; fs4.push(() => r); } \
         [fs1.map(f => f()).join(), fs2.map(f => f()).join(), fs3.map(f => f()).join(), \
         fs4.map(f => f()).join()].join(' ')",
        "0,1 0,1 0,1 10,12",
    );
    check(
        "var fs = []; var i = 0; do { { let v = i; fs.push(() => v); } i++; } while (i < 2); \
         fs.map(f => f()).join()",
        "0,1",
    );
}

#[test]
fn fresh_bindings_start_in_their_temporal_dead_zone_and_stay_shared_within_an_iteration() {
    check(
        "var r = []; for (var i = 0; i < 2; i++) { try { r.push(t); } catch (e) { r.push(e.name); } \
         let t = i; } r.join()",
        "ReferenceError,ReferenceError",
    );
    // Closures from the same iteration share that iteration's cell.
    check(
        "var fs = []; for (var i = 0; i < 2; i++) { let c = i * 10; fs.push(() => ++c); \
         fs.push(() => c); } [fs[0](), fs[1](), fs[2](), fs[3](), fs[0]()].join()",
        "1,1,11,11,2",
    );
    check(
        "var out = []; for (var i = 0; i < 3; i++) { class K { v() { return i; } } out.push(K); } \
         [out[0] === out[1], new out[2]().v()].join()",
        "false,3",
    );
}
