//! bd-9vouw.78: a class may extend a built-in constructor reached as a value.
//!
//! `class X extends Map` is lowered with the parent recorded by name. When the
//! parent is a runtime value instead (`const M = Map; class X extends M`, a
//! name a `typeof` check made dynamic, `extends (Base || Error)`), the parent
//! was the built-in function itself and `new X()` failed with "expected
//! constructor function, got function" (pre-existing on 2026-09-26 builds).
//! Such a parent is now recorded by its canonical name, so construction takes
//! the same built-in-parent path. Expected strings are Node v22.2.0's output.
//!
//! No-claim: built-in parents the lowering does not record by name (RegExp,
//! WeakMap, typed arrays, ...) are unchanged.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

#[test]
fn aliased_map_and_error_parents() {
    check(
        "const M = Map; class S extends M {} const s = new S(); s.set(1, 2);
         const E = Error; class T extends E { constructor(m) { super(m); this.extra = 1; } }
         const t = new T('x');
         [s.get(1), s instanceof Map, s instanceof S, t.message, t.extra, t instanceof Error,
          t instanceof T, String(t)].join(' ');",
        "2 true true x 1 true true Error: x",
    );
}

/// The feature-detection shape: a `typeof` check makes the name dynamic.
#[test]
fn typeof_guarded_parents() {
    check(
        "let out = [];
         if (typeof Map !== 'undefined') { class MyMap extends Map {} out.push(new MyMap([[1, 2]]).get(1)); }
         out.push(typeof RangeError);
         class R extends RangeError {}
         const r = new R('bad');
         out.push(r instanceof RangeError, r.name, r.message);
         out.join(' ');",
        "2 function true RangeError bad",
    );
}

#[test]
fn parent_chosen_by_an_expression() {
    check(
        "const Base = (typeof NotDefinedAnywhere !== 'undefined' && NotDefinedAnywhere) || Error;
         class MyError extends Base { constructor(m) { super(m); this.name = 'MyError'; } }
         const e = new MyError('boom');
         [e instanceof Error, e instanceof MyError, e.name, e.message, String(e)].join(' ');",
        "true true MyError boom MyError: boom",
    );
}

#[test]
fn aliased_set_parent_with_methods() {
    check(
        "const S = Set; class Tags extends S { tagged() { return [...this].map((x) => '#' + x).join(' '); } }
         [new Tags(['a', 'b']).tagged(), new Tags([1]).size].join(' ');",
        "#a #b 1",
    );
}
