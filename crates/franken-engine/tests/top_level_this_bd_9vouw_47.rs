//! bd-9vouw.47: script top-level `this` is an object (Node runs a script file
//! as a CommonJS module, whose top-level `this` is `module.exports`), and
//! top-level arrows capture that same object.
//!
//! Before this, top-level `this` was `undefined`, so the ubiquitous UMD
//! wrapper `(function (root, factory) { root.lib = factory(); }(this, ...))`
//! crashed with "expected object, got undefined". Expected strings are what
//! Node v22.2.0 prints for the same program run as a CommonJS module.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

#[test]
fn top_level_this_is_one_stable_object() {
    assert_eq!(
        eval_to_string(
            "[typeof this, \
             (function () { var g = this; g.x = 1; return 0; }).call(this) + this.x, \
             (() => this)() === this].join('|');"
        ),
        "object|1|true"
    );
}

#[test]
fn umd_wrapper_receives_an_object_root() {
    assert_eq!(
        eval_to_string(
            "(function (r, factory) { r.lib = factory(); return r.lib.v; }(this, \
             function () { return {v: 42}; }));"
        ),
        "42"
    );
}
