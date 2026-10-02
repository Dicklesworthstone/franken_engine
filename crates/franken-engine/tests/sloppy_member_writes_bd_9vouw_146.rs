//! bd-9vouw.146: a sloppy-mode member write that [[Set]] rejects is ignored.
//!
//! PutValue (ES2020 6.2.4.9) throws a TypeError for a rejected write only in
//! strict code, but every member write threw: `o.x = 2` on a non-writable
//! `x`, a frozen array index, a getter-only property, a new property on a
//! non-extensible object, a refusing Proxy, a primitive base, a function's
//! `name` or `length`. Strict code (a 'use strict' function, a class body, an
//! arrow inside strict code, a strict Function body) must still throw.
//!
//! PROGRAM covers data properties: non-writable own and inherited, compound
//! and logical assignment, frozen arrays, getter-only accessors,
//! non-extensible objects, the assignment's value, a destructuring member
//! target, and the strict counterparts. MORE covers functions and
//! built-ins (a `static name()` method stays writable), primitive bases,
//! undefined/null bases (TypeError in both modes), a refusing Proxy, setters
//! (still called; a throwing setter still throws), a sloppy reducer writing
//! to a frozen accumulator, and the Function constructor. Both outputs are
//! Node v22.2.0's.
//!
//! No-claim: a setter that a primitive base inherits (on String.prototype or
//! Object.prototype) is not called by an assignment to the primitive.

#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

const PROGRAM: &str = r#"var o = {}; Object.defineProperty(o, 'x', { value: 1, writable: false });
o.x = 2; o['x'] = 3; o.x += 4;
console.log(o.x);
var p = Object.create(o); p.x = 5;
console.log(p.x, p.hasOwnProperty('x'));
var a = Object.freeze([1, 2]); a[0] = 9; a.push === undefined;
console.log(a[0], a.length);
var g = { get only() { return 'g'; } }; g.only = 'set';
console.log(g.only);
var n = Object.preventExtensions({}); n.fresh = 1;
console.log(n.fresh, Object.keys(n).length);
var r = (o.x = 7);
console.log(r, o.x);
var d = {}; Object.defineProperty(d, 'y', { value: 0, writable: false }); d.y ||= 5; d.y ??= 6;
console.log(d.y);
var z = {}; Object.defineProperty(z, 'k', { value: 2, writable: false }); var dz = { k: 1 }; ({ k: z.k } = dz);
console.log(z.k);
for (const [label, run] of [
  ['strict write', function () { 'use strict'; o.x = 2; }],
  ['strict compound', function () { 'use strict'; o.x += 1; }],
  ['strict inherited', function () { 'use strict'; p.x = 1; }],
  ['strict frozen index', function () { 'use strict'; a[0] = 1; }],
  ['strict getter-only', function () { 'use strict'; g.only = 1; }],
  ['strict non-extensible', function () { 'use strict'; n.fresh = 1; }],
  ['class body write', function () { class C { static m() { o.x = 5; } } C.m(); }],
]) {
  try { run(); console.log(label, 'no throw'); } catch (e) { console.log(label, e.constructor.name); }
}
console.log('done');"#;

const PROGRAM_OUTPUT: &str = r#"1
1 false
1 2
g
undefined 0
7 1
0
2
strict write TypeError
strict compound TypeError
strict inherited TypeError
strict frozen index TypeError
strict getter-only TypeError
strict non-extensible TypeError
class body write TypeError
done"#;

const MORE: &str = r#"function f() {}
f.name = 'renamed'; f.length = 9; f['name'] += '!';
console.log(f.name, f.length);
class S { static name() { return 'static'; } }
S.name = 'writable method';
console.log(S.name);
parseInt.name = 'x'; parseInt.length = 7;
console.log(parseInt.name, parseInt.length);
var str = 'abc'; str.extra = 1; str[0] = 'z'; str.length = 0; (5).y = 2; true.z = 3;
console.log(str, str.extra, str.length, (5).y);
var refused = new Proxy({}, { set() { return false; } }); refused.k = 1;
console.log('proxy', Object.keys(refused).length);
var setterCalls = []; var acc = { set v(x) { setterCalls.push(x); } }; acc.v = 1;
var thrower = { set v(x) { throw new RangeError('boom'); } };
try { thrower.v = 1; console.log('setter no throw'); } catch (e) { console.log('setter', e.name, setterCalls.join()); }
var frozenAcc = [1, 2].reduce(function (memo, x) { memo[x] = x; return memo; }, Object.freeze({}));
console.log('reduce', JSON.stringify(frozenAcc));
var sloppyFn = Function('o', 'o.q = 1; return "ok";');
var strictFn = Function('o', '"use strict"; o.q = 1; return "ok";');
var sealed = Object.seal({ q: 0 }); Object.defineProperty(sealed, 'q', { writable: false });
console.log(sloppyFn(sealed), sealed.q);
for (const [label, run] of [
  ['undefined base', function () { var u; u.x = 1; }],
  ['null base', function () { var n = null; n.x = 1; }],
  ['strict fn name', function () { 'use strict'; f.name = 1; }],
  ['strict builtin length', function () { 'use strict'; parseInt.length = 1; }],
  ['strict static method', function () { 'use strict'; S.name = 'ok'; }],
  ['strict primitive', function () { 'use strict'; str.extra = 1; }],
  ['strict proxy false', function () { 'use strict'; refused.k = 1; }],
  ['strict Function ctor', function () { strictFn(sealed); }],
  ['strict arrow', function () { 'use strict'; (() => { sealed.q = 2; })(); }],
]) {
  try { run(); console.log(label, 'no throw'); } catch (e) { console.log(label, e.constructor.name); }
}
console.log('done');"#;

const MORE_OUTPUT: &str = r#"f 0
writable method
parseInt 2
abc undefined 3 undefined
proxy 0
setter RangeError 1
reduce {}
ok 0
undefined base TypeError
null base TypeError
strict fn name TypeError
strict builtin length TypeError
strict static method no throw
strict primitive TypeError
strict proxy false TypeError
strict Function ctor TypeError
strict arrow TypeError
done"#;

fn console(source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine.eval(source).expect("the program runs");
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_node_output(source: &str, expected: &str) {
    let output = console(source);
    for (index, (actual, expected)) in output.lines().zip(expected.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), expected.lines().count(), "{output}");
}

#[test]
fn sloppy_data_property_writes_that_set_rejects_are_ignored() {
    assert_node_output(PROGRAM, PROGRAM_OUTPUT);
}

#[test]
fn sloppy_function_primitive_proxy_and_reducer_writes_match_node() {
    assert_node_output(MORE, MORE_OUTPUT);
}
