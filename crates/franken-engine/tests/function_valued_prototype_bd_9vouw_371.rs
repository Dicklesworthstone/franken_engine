//! bd-9vouw.371: a function is an object, so it can be a constructor's
//! `prototype` (ES2020 9.1.14 GetPrototypeFromConstructor, 12.10.4
//! OrdinaryHasInstance; Test262 statements/function/S13.2.2_A1_T1, _T2):
//! `new F()` inherits its properties and the function's isPrototypeOf
//! holds, `instanceof F` searches for it, and Object.create(fn) is found
//! by fn.isPrototypeOf. The instance inherited from Object.prototype,
//! instanceof threw a TypeError, and isPrototypeOf missed the function's
//! link. The line is Node v22.2.0's output for the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn function_valued_constructor_prototypes_link_instances() {
    let source = r#"
var out = [];
function P() {} P.type = "m";
function F() {} F.prototype = P; var m = new F();
out.push(P.isPrototypeOf(m), m.type, Object.getPrototypeOf(m) === P, m instanceof F, typeof m);
var Q = function () {}; Q.kind = "q"; var G = function () {}; G.prototype = Q; var n = new G();
out.push(Q.isPrototypeOf(n), n.kind, n instanceof G);
var a = Object.create(P); out.push(P.isPrototypeOf(a), Object.prototype.isPrototypeOf.call(P, a));
var arrow = () => 1; arrow.tag = "t"; function H() {} H.prototype = arrow; var h = new H(); out.push(arrow.isPrototypeOf(h), h.tag, h instanceof H);
function Plain() {} var p = new Plain(); out.push(P.isPrototypeOf(p), Plain.prototype.isPrototypeOf(p));
console.log(out.join(' '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        ["true m true true object true q true true true true t true false true",]
    );
}
