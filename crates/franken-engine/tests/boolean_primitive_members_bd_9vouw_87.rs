//! bd-9vouw.87: property reads on boolean primitives.
//!
//! Every member read on `true`/`false` aborted the run with "type error:
//! expected object, got boolean", while numbers and strings already resolved
//! their prototype members. lodash 4.17.21 died in its preamble on
//! `freeGlobal.process` with `freeGlobal === false`. Booleans now resolve
//! `Boolean.prototype.toString`/`valueOf` and read any other key as
//! undefined. Expected strings are what Node v22.2.0 prints.
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
fn boolean_members_resolve_like_node() {
    check(
        "var f = false; [f.process, typeof f.x, f['y'], (true).toString(), f.toString(), \
         true.valueOf(), f.valueOf() === false].join(',');",
        ",undefined,,true,false,true,true",
    );
    check(
        "var t = true; var s = t.toString; typeof s + ':' + (t.nope === undefined);",
        "function:true",
    );
}

/// lodash's preamble shape when no `global` object exists.
#[test]
fn a_false_guard_value_reads_as_undefined() {
    check(
        "var freeGlobal = false; var moduleExports = true; \
         var freeProcess = moduleExports && freeGlobal.process; String(freeProcess);",
        "undefined",
    );
}
