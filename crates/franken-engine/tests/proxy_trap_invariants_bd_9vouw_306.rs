//! bd-9vouw.306: the Proxy `get`, `set`, `has`, `deleteProperty` and
//! `ownKeys` traps' results are checked against the target (ES2020
//! 9.5.7-9.5.11).
//!
//! The traps' results were returned unchecked: a proxy over a frozen object
//! reported any value for its properties, accepted any write, denied or
//! deleted them, and listed no keys. The rc-next39 frankenctl gives
//! `2 true false true 0 1 true 7 true false true 2 c 9 false true z true`
//! for the program below. Each case throws a TypeError now. The others are
//! controls a trap is allowed: the frozen value itself, an equal write, the
//! exact keys of a non-extensible target, and any answer about the
//! configurable properties of an extensible target. Node v22.2.0 gives this
//! value; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn traps_may_not_misreport_non_configurable_or_non_extensible_targets() {
    let source = r#"
var out = [];
function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var frozen = Object.freeze({ x: 1 });
var liar = new Proxy(frozen, {
  get: function () { return 2; },
  set: function () { return true; },
  has: function () { return false; },
  deleteProperty: function () { return true; },
  ownKeys: function () { return []; }
});
out.push(attempt(function () { return liar.x; }));
out.push(attempt(function () { return Reflect.set(liar, 'x', 5); }));
out.push(attempt(function () { return 'x' in liar; }));
out.push(attempt(function () { return Reflect.deleteProperty(liar, 'x'); }));
out.push(attempt(function () { return Reflect.ownKeys(liar).length; }));
var honest = new Proxy(frozen, { get: function () { return 1; }, set: function () { return true; } });
out.push(attempt(function () { return honest.x; }));
out.push(attempt(function () { return Reflect.set(honest, 'x', 1); }));
var acc = {};
Object.defineProperty(acc, 'a', { set: function () {}, configurable: false });
out.push(attempt(function () { return new Proxy(acc, { get: function () { return 7; } }).a; }));
var acc2 = {};
Object.defineProperty(acc2, 'b', { get: function () { return 1; }, configurable: false });
out.push(attempt(function () { return Reflect.set(new Proxy(acc2, { set: function () { return true; } }), 'b', 3); }));
var closed = Object.preventExtensions({ c: 1 });
out.push(attempt(function () { return 'c' in new Proxy(closed, { has: function () { return false; } }); }));
out.push(attempt(function () { return Reflect.deleteProperty(new Proxy(closed, { deleteProperty: function () { return true; } }), 'c'); }));
out.push(attempt(function () { return Reflect.ownKeys(new Proxy(closed, { ownKeys: function () { return ['c', 'd']; } })).length; }));
out.push(attempt(function () { return Reflect.ownKeys(new Proxy(closed, { ownKeys: function () { return ['c']; } })).join(); }));
var plain = { y: 1 };
var free = new Proxy(plain, {
  get: function () { return 9; },
  has: function () { return false; },
  deleteProperty: function () { return true; },
  ownKeys: function () { return ['z']; },
  set: function () { return true; }
});
out.push(attempt(function () { return free.y; }));
out.push(attempt(function () { return 'y' in free; }));
out.push(attempt(function () { return Reflect.deleteProperty(free, 'y'); }));
out.push(attempt(function () { return Reflect.ownKeys(free).join(); }));
out.push(attempt(function () { return Reflect.set(free, 'y', 4); }));
out.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "TypeError TypeError TypeError TypeError TypeError 1 true TypeError TypeError \
         TypeError TypeError TypeError c 9 false true z true"
    );
}
