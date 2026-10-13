//! bd-9vouw.325: `class C extends null` is a derived class whose prototype
//! object has a null [[Prototype]] and whose constructor inherits from
//! Function.prototype (ES2020 14.6.13 step 6.e). Every such class failed at
//! definition: the lowering read `prototype` from the null superclass. The
//! program checks the class shape, construction (a TypeError from the
//! implicit or explicit super(), a ReferenceError without a returned object,
//! a returned object used as the instance), a class expression, a heritage
//! chosen at run time, and that a superclass whose `prototype` is not an
//! object stays a TypeError and an ordinary superclass still works. Node
//! v22.2.0 gives this line; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn classes_extend_null() {
    let source = r#"
var out = [];
function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } }
class C extends null {}
out.push(Object.getPrototypeOf(C) === Function.prototype, Object.getPrototypeOf(C.prototype) === null, C.prototype.constructor === C);
out.push(attempt(function () { new C(); }));
var made;
class R extends null { constructor() { return made = Object.create(R.prototype); } }
var r = new R();
out.push(r === made, r instanceof R, Object.getPrototypeOf(R.prototype) === null);
var reached = 0;
class S extends null { constructor() { reached++; super(); reached++; } }
out.push(attempt(function () { new S(); }), reached);
class T extends null { constructor() {} }
out.push(attempt(function () { new T(); }));
var E = class extends null { m() { return 7; } };
out.push(typeof E.prototype.m, Object.getOwnPropertyNames(E.prototype).join(), Object.getPrototypeOf(E.prototype) === null);
function pick(flag) { return class extends (flag ? null : Array) {}; }
out.push(Object.getPrototypeOf(pick(true).prototype) === null, new (pick(false))() instanceof Array);
function F() {}
F.prototype = 3;
out.push(attempt(function () { class G extends F {} }));
class Base { hi() { return 'hi'; } }
class D extends Base {}
out.push(new D().hi());
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
        [
            "true true true TypeError true true true TypeError 1 ReferenceError function constructor,m true true true TypeError hi"
        ]
    );
}
