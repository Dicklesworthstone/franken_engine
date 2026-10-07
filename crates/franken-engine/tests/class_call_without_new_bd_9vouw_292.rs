#![forbid(unsafe_code)]

//! bd-9vouw.292: a class constructor called without `new` throws a
//! TypeError before its parameters or body run (ES2020 9.2.1 [[Call]]
//! step 2). The engine ran base classes, implicit derived constructors and
//! class expressions as plain calls (parameter defaults and bodies
//! included); only an explicit derived constructor failed, at its super()
//! (2 Node-passing Test262 tests in the rc-next33 merged-tree census:
//! statements/class/subclass/default-constructor{,-2}).

use frankenengine_engine::HybridRouter;

/// Plain calls of base, derived (implicit and explicit), field-bearing and
/// expression classes, with a parameter default that must not run;
/// Function.prototype.call, Reflect.apply and a bound call throw; new,
/// Reflect.construct and new of a bound class still construct. Expected
/// lines are Node v22.2.0's output, captured programmatically.
#[test]
fn class_constructor_call_without_new_throws() {
    let source = r#"function k(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } }
var ran = [];
class Base { constructor(a = ran.push('default')) { ran.push('body'); } }
class Derived extends Base {}
class Explicit extends Base { constructor() { super(); } }
class Plain {}
var Expr = class {};
var Named = class Inner { constructor() { ran.push('inner'); } };
console.log(k(function () { Derived(); }), k(function () { Explicit(); }), k(function () { Plain(); }), k(function () { Base(); }), k(function () { Expr(); }), k(function () { Named(); }), ran.join(','));
console.log(k(function () { Base.call({}); }), k(function () { Reflect.apply(Plain, null, []); }), k(function () { Plain.bind(null)(); }), k(function () { new (Plain.bind(null))(); }));
var made = [new Base(), new Derived(), new Explicit(), Reflect.construct(Plain, []), new Named()];
console.log(made.map(function (o) { return o.constructor.name; }).join(','), ran.join(','), new Expr() instanceof Expr);
class WithField { x = 1; static s = 2; }
console.log(new WithField().x, WithField.s, k(function () { WithField(); }));
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
            "TypeError TypeError TypeError TypeError TypeError TypeError ",
            "TypeError TypeError TypeError ok",
            "Base,Derived,Explicit,Plain,Inner default,body,default,body,default,body,inner true",
            "1 2 TypeError",
        ]
    );
}
