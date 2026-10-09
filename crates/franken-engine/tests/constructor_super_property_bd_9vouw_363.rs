//! bd-9vouw.363: a class constructor's `super.x`, `super.m()` and an
//! arrow's `super` inside it look up from the constructor's [[HomeObject]]
//! (the class prototype, ES2020 14.6.13 step 12) and its [[Prototype]], as
//! a method's do. The constructor frame had no HomeObject, so LoadSuper
//! read the parent constructor: `super.x` read the parent's static `x`,
//! `super.m()` called the parent's static `m`, and an arrow's `super` or a
//! base class's `super.toString` threw a TypeError. Methods, static
//! methods, field initializers and `super.y = v` are unchanged. The line is
//! Node v22.2.0's (Bun 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn super_property_in_a_constructor_reads_the_class_prototype_chain() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + '=' + f()); } catch (e) { out.push(name + '!' + e.constructor.name + ':' + e.message); } }
class B { m() { return 'proto-m'; } static m() { return 'static-m'; } }
B.prototype.x = 'proto-x';
B.x = 'static-x';
t('ctor-read', function () { var seen; class C extends B { constructor() { super(); seen = super.x; } } new C(); return seen; });
t('ctor-call', function () { var seen; class C extends B { constructor() { super(); seen = super.m(); } } new C(); return seen; });
t('ctor-arrow', function () { var seen; class C extends B { constructor() { super(); seen = (() => super.x)(); } } new C(); return seen; });
t('ctor-this', function () { var seen; class C extends B { constructor() { super(); this.v = 1; seen = super.m.call(this); } } new C(); return seen; });
t('base-ctor', function () { var seen; class A { constructor() { seen = super.toString === Object.prototype.toString; } } new A(); return seen; });
t('method', function () { class C extends B { n() { return super.x; } } return new C().n(); });
t('static', function () { class C extends B { static n() { return super.x; } } return C.n(); });
t('field-init', function () { class C extends B { f = super.x; } return new C().f; });
t('ctor-set', function () { var c; class C extends B { constructor() { super(); super.y = 5; c = this; } } new C(); return [c.y, B.prototype.y].join(); });
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
            "ctor-read=proto-x ctor-call=proto-m ctor-arrow=proto-x ctor-this=proto-m base-ctor=true method=proto-x static=static-x field-init=proto-x ctor-set=5,",
        ]
    );
}
