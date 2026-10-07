#![forbid(unsafe_code)]

//! `delete` of an identifier (ES2020 12.5.3.2): a declared binding (var,
//! function, let / const, parameter, `arguments`) is not deletable, so the
//! result is false and the binding is not read; the global object's NaN,
//! Infinity and undefined are non-configurable (false); a sloppy implicit
//! global is deleted (true); inside `with` a name the object has deletes
//! that property. Declared bindings answered true.

use frankenengine_engine::HybridRouter;

/// Expected lines are Node v22.2.0's output, captured programmatically from
/// the same source.
#[test]
fn delete_of_declared_bindings_is_false() {
    let source = r#"var x = 1;
function F() {}
let l = 2;
const c = 3;
var dx = delete x, dF = delete F, dl = delete l, dc = delete c;
console.log(dx, dF, dl, dc, x, typeof F, l, c);
function inner(p) { var v = 1; return [delete p, delete v, delete arguments, p, v]; }
console.log(JSON.stringify(inner(5)));
implicitGlobal = 7;
console.log(delete implicitGlobal, typeof implicitGlobal, delete NaN, delete Infinity, delete undefined, typeof NaN);
var o = { x: 1 };
with (o) { var dw = delete x; }
console.log(dw, Object.keys(o).length, x);
console.log(delete (NaN), delete ((Infinity)), NaN + 1, Infinity > 1, (function () { var NaN = 2; return delete NaN; })());
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "false false false false 1 function 2 3",
            "[false,false,false,5,1]",
            "true undefined false false false number",
            "true 0 1",
            "false false NaN true false",
        ]
    );
}
