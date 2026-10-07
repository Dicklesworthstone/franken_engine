//! bd-9vouw.318: `__proto__` is %Object.prototype%'s accessor, reached
//! only through an inherited lookup. An own `__proto__` data property
//! (JSON.parse, defineProperty, spread) is read and written as data. A
//! null-prototype object has no such accessor: it reads undefined and a
//! write defines an own property. [[Set]] of the key with a dynamic key, by
//! Object.assign or by Reflect.set runs the setter, as `o.__proto__ = p`
//! does. Each site special-cased the key and returned or set the prototype
//! link, whatever the object held. Class `extends` and a plain
//! `o.__proto__ = p` are unchanged. Not covered: a computed literal key
//! `{ ['__proto__']: v }` still sets the prototype. Node v22.2.0 gives this
//! value; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn proto_key_is_an_inherited_accessor_not_a_special_name() {
    let source = r#"
var out = [];
var j = JSON.parse('{"__proto__": 5, "a": 1}');
out.push(j.__proto__, Object.keys(j).join(','), Object.getPrototypeOf(j) === Object.prototype);
j.__proto__ = 6; out.push(j.__proto__, Object.getPrototypeOf(j) === Object.prototype);
var n = Object.create(null);
out.push(String(n.__proto__));
n.__proto__ = 7; out.push(n.__proto__, Object.keys(n).join(','), Object.getPrototypeOf(n));
var d = {}; Object.defineProperty(d, '__proto__', { value: 9, enumerable: true, writable: true, configurable: true });
out.push(d.__proto__, Object.getPrototypeOf(d) === Object.prototype);
var evil = JSON.parse('{"__proto__": {"isAdmin": true}, "name": "x"}');
out.push(Object.assign({}, evil).isAdmin);
var merged = {}; for (var k in evil) merged[k] = evil[k];
out.push(merged.isAdmin, Object.keys(merged).join(','));
var spread = { ...evil }; out.push(spread.isAdmin, Object.keys(spread).join(','));
var r = {}; out.push(Reflect.set(r, '__proto__', { tag: 'r' }), r.tag);
var plain = {}; plain.__proto__ = { tag: 'p' }; out.push(plain.tag, plain.__proto__.tag);
out.push(Object.prototype.__proto__, String(Object.create(null).__proto__));
class Base { hi() { return 'base'; } } class Derived extends Base {} out.push(new Derived().hi());
var inherits = Object.create(j); out.push(inherits.__proto__, Object.getPrototypeOf(inherits) === j);
out.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "5 __proto__,a true 6 true undefined 7 __proto__  9 true true true name  __proto__,name true r p p  undefined base 6 true"
    );
}
