#![forbid(unsafe_code)]

//! ES2020 12.3.5.3 MakeSuperPropertyReference: the super base is the
//! [[HomeObject]]'s [[Prototype]]. LoadSuper read an unset prototype link as
//! null, so in an object literal method (implicit Object.prototype) and in a
//! base class's static method (home: the constructor, implicit
//! Function.prototype) every `super.x` read and `super.x = v` write threw
//! "expected object, got null" (about 12 Node-passing Test262 tests in the
//! rc-next33 merged-tree census: expressions/super/prop-*-ref-*,
//! object/method-definition/*-super-prop-*).

use frankenengine_engine::HybridRouter;

/// super reads and writes from object literal and class methods (instance
/// and static, base and derived), an explicit prototype with an accessor
/// pair, and a home object whose prototype was set to null (a TypeError).
/// Expected lines are Node v22.2.0's output, captured programmatically.
#[test]
fn super_base_is_the_implicit_prototype() {
    let source = r#"function k(f) { try { return f(); } catch (e) { return e.constructor.name; } }
var obj = { method() { super.x = 8; return [Object.prototype.hasOwnProperty.call(obj, 'x'), super.hasOwnProperty === Object.prototype.hasOwnProperty, super.constructor === Object]; } };
console.log(JSON.stringify(obj.method()), obj.x);
class A { static m() { return [super.toString === Function.prototype.toString, super.hasOwnProperty === Object.prototype.hasOwnProperty]; } m() { return super.constructor === Object; } }
console.log(JSON.stringify(A.m()), new A().m());
var proto = { get g() { return this.tag; }, set s(v) { this.seen = v; } };
var withProto = { tag: 'own', m() { super.s = 5; return [super.g, this.seen]; } };
Object.setPrototypeOf(withProto, proto);
var nulled = { m() { return super.x; } };
Object.setPrototypeOf(nulled, null);
class B extends A { static m() { return super.m().length; } }
console.log(JSON.stringify(withProto.m()), k(function () { return nulled.m(); }), B.m(), new B().m());
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
            "[true,true,true] 8",
            "[true,true] true",
            "[\"own\",5] TypeError 2 true",
        ]
    );
}
