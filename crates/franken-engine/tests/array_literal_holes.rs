//! Array literal elisions are holes, not `undefined` elements.
//!
//! `[1, , 3]` has length 3 but no own property "1": `1 in h` is false,
//! `Object.keys` skips the index, iteration callbacks skip it, and a read
//! falls through to `Array.prototype`. The literal lowering used to store
//! `undefined` at every elision (JS probe corpus case 27).
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
fn elisions_are_not_own_properties() {
    check(
        "var h = [1, , 3]; [1 in h, h.length, Object.keys(h).join('|'), h[1] === undefined, \
         JSON.stringify(h)].join()",
        "false,3,0|2,true,[1,null,3]",
    );
    check(
        "[[, ].length, [, , ].length, [1, , ].length, [1, ].length, 0 in [, 1]].join()",
        "1,2,2,1,false",
    );
}

#[test]
fn callbacks_skip_holes_and_reads_see_the_prototype() {
    check(
        "var c = 0; [1, , 3].forEach(function () { c++; }); \
         var m = [1, , 3].map(function (x) { return x * 2; }); \
         [c, 1 in m, JSON.stringify(m)].join()",
        "2,false,[2,null,6]",
    );
    check(
        "Array.prototype[1] = 'inherited'; var r = [1, , 3][1]; delete Array.prototype[1]; r",
        "inherited",
    );
    check(
        "var f = function (a) { return [a, , a]; }; var x = f(7); [x.length, 1 in x, x[2]].join()",
        "3,false,7",
    );
}

#[test]
fn index_of_skips_holes_but_includes_reads_them() {
    // indexOf/lastIndexOf test HasProperty first; includes reads every index
    // with Get, so a hole is `undefined` only to includes.
    check(
        "var h = [1, , 3]; [h.indexOf(undefined), h.lastIndexOf(undefined), \
         h.includes(undefined), [1, undefined, 3].indexOf(undefined), \
         [1, undefined, 3].lastIndexOf(undefined), h.indexOf(3)].join()",
        "-1,-1,true,1,1,2",
    );
}
