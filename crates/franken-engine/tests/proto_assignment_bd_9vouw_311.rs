//! bd-9vouw.311: `obj.__proto__ = v` changes the prototype through
//! [[SetPrototypeOf]] (Annex B 2.2.1.2), so a cycle, a non-extensible
//! object, the immutable Object.prototype and a refusing Proxy trap throw a
//! TypeError, and a throwing trap's error propagates. The link was stored
//! unconditionally: `Object.prototype.__proto__ = {}` made a prototype cycle
//! after which the program died with an uncatchable internal error. A
//! permitted change, a non-object value (ignored), class `extends` and an
//! object literal's `__proto__` still work. Node v22.2.0 gives this value;
//! Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn proto_assignment_runs_set_prototype_of() {
    let source = r#"
var out = [];
function attempt(f) { try { return 'ok:' + f(); } catch (e) { return e.constructor.name; } }
var a = {}; var b = Object.create(a);
out.push(attempt(function () { a.__proto__ = b; return 'set'; }));
out.push(attempt(function () { a.__proto__ = a; return 'set'; }));
out.push(attempt(function () { Object.prototype.__proto__ = {}; return 'set'; }));
out.push(attempt(function () { Object.prototype.__proto__ = null; return 'same'; }));
var ne = Object.preventExtensions({});
out.push(attempt(function () { ne.__proto__ = {}; return 'set'; }));
out.push(attempt(function () { ne.__proto__ = Object.prototype; return 'same'; }));
var trapped = new Proxy({}, { setPrototypeOf: function () { throw new RangeError('trap'); } });
out.push(attempt(function () { trapped.__proto__ = {}; return 'set'; }));
var refusing = new Proxy({}, { setPrototypeOf: function () { return false; } });
out.push(attempt(function () { refusing.__proto__ = {}; return 'set'; }));
var c = {}; var p = { tag: 'p' };
out.push(attempt(function () { c.__proto__ = p; return c.tag; }));
out.push(attempt(function () { c.__proto__ = 5; return Object.getPrototypeOf(c) === p; }));
class Base { hi() { return 'base'; } }
class Derived extends Base {}
out.push(new Derived().hi());
var lit = { __proto__: p };
out.push(lit.tag);
out.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "TypeError TypeError TypeError ok:same TypeError ok:same RangeError TypeError ok:p ok:true base p"
    );
}
