//! bd-9vouw.78: a class may extend a built-in constructor reached as a value.
//!
//! `class X extends Map` is lowered with the parent recorded by name. When the
//! parent is a runtime value instead (`const M = Map; class X extends M`, a
//! name a `typeof` check made dynamic, `extends (Base || Error)`), the parent
//! was the built-in function itself and `new X()` failed with "expected
//! constructor function, got function" (pre-existing on 2026-09-26 builds).
//! Such a parent is now recorded by its canonical name, so construction takes
//! the same built-in-parent path. Expected strings are Node v22.2.0's output.
//!
//! Built-in parents the lowering does not record by name (Date, RegExp,
//! WeakMap, WeakSet, typed arrays, ArrayBuffer, DataView, Number, String,
//! Boolean) failed the same way whenever the class had no constructor or
//! called `super(x)` without a spread; only `super(...args)` worked. They are
//! now constructed natively and given new.target's prototype, as
//! `Reflect.construct(parent, args, new.target)` is.
//!
//! No-claim: `extends Promise` and `extends Function` still fail (promises
//! and functions carry no per-instance prototype here).
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

#[test]
fn aliased_map_and_error_parents() {
    check(
        "const M = Map; class S extends M {} const s = new S(); s.set(1, 2);
         const E = Error; class T extends E { constructor(m) { super(m); this.extra = 1; } }
         const t = new T('x');
         [s.get(1), s instanceof Map, s instanceof S, t.message, t.extra, t instanceof Error,
          t instanceof T, String(t)].join(' ');",
        "2 true true x 1 true true Error: x",
    );
}

/// The feature-detection shape: a `typeof` check makes the name dynamic.
#[test]
fn typeof_guarded_parents() {
    check(
        "let out = [];
         if (typeof Map !== 'undefined') { class MyMap extends Map {} out.push(new MyMap([[1, 2]]).get(1)); }
         out.push(typeof RangeError);
         class R extends RangeError {}
         const r = new R('bad');
         out.push(r instanceof RangeError, r.name, r.message);
         out.join(' ');",
        "2 function true RangeError bad",
    );
}

#[test]
fn parent_chosen_by_an_expression() {
    check(
        "const Base = (typeof NotDefinedAnywhere !== 'undefined' && NotDefinedAnywhere) || Error;
         class MyError extends Base { constructor(m) { super(m); this.name = 'MyError'; } }
         const e = new MyError('boom');
         [e instanceof Error, e instanceof MyError, e.name, e.message, String(e)].join(' ');",
        "true true MyError boom MyError: boom",
    );
}

#[test]
fn aliased_set_parent_with_methods() {
    check(
        "const S = Set; class Tags extends S { tagged() { return [...this].map((x) => '#' + x).join(' '); } }
         [new Tags(['a', 'b']).tagged(), new Tags([1]).size].join(' ');",
        "#a #b 1",
    );
}

#[test]
fn unrecorded_builtin_parents_with_implicit_constructors() {
    check(
        "class D extends Date {} const d = new D(0);
         class U extends Uint8Array {} const u = new U([1, 2, 3]);
         class F extends Float64Array {} const f = new F(2);
         class B extends ArrayBuffer {} const b = new B(8);
         class V extends DataView {} const v = new V(new ArrayBuffer(4));
         class WM extends WeakMap {} const wm = new WM(); const k = {}; wm.set(k, 42);
         class WS extends WeakSet {} const ws = new WS(); ws.add(k);
         class R extends RegExp {} const r = new R('a+', 'g');
         [d.getTime(), d instanceof D, d instanceof Date, u.length, u[2], u instanceof U,
          u instanceof Uint8Array, f.length, b.byteLength, b instanceof B, v.byteLength,
          v instanceof V, wm.get(k), wm instanceof WM, ws.has(k), ws instanceof WS,
          r.test('caat'), r.lastIndex, r instanceof R, r.source].join(' ');",
        "0 true true 3 3 true true 2 8 true 4 true 42 true true true true 3 true a+",
    );
}

#[test]
fn unrecorded_builtin_parents_with_plain_super_calls() {
    check(
        "class D extends Date { constructor(t) { super(t); this.kind = 'd'; } year() { return this.getUTCFullYear(); } }
         class U extends Uint16Array { constructor(n) { super(n); this.kind = 'u'; } sum() { return this.reduce((a, b) => a + b, 0); } }
         class WM extends WeakMap { constructor() { super(); this.kind = 'wm'; } }
         const d = new D(86400000 * 366), u = new U(3), wm = new WM();
         u[0] = 5; u[2] = 7;
         [d.year(), d.kind, Object.getPrototypeOf(d) === D.prototype, u.sum(), u.kind, u.length,
          wm.kind, wm.has({})].join(' ');",
        "1971 d true 12 u 3 wm false",
    );
}

#[test]
fn primitive_wrapper_parents() {
    check(
        "class N extends Number {} class S extends String { shout() { return this.toUpperCase() + '!'; } }
         class Bo extends Boolean { constructor(v) { super(v); this.tag = 't'; } }
         class N2 extends Number { constructor(...a) { super(...a); } }
         const n = new N(5), s = new S('hi'), bo = new Bo(0), n2 = new N2(7);
         [n + 1, n instanceof N, n instanceof Number, typeof n, s.shout(), s.length, bo.valueOf(),
          bo.tag, bo instanceof Boolean, n2 * 2, n2 instanceof N2].join(' ');",
        "6 true true object HI! 2 false t true 14 true",
    );
}

#[test]
fn reflect_construct_of_builtins_with_new_target() {
    check(
        "function F() {} F.prototype.extra = function () { return 'x'; };
         const w = Reflect.construct(Number, [5], F), d = Reflect.construct(Date, [0], F);
         let symbolError = 'none';
         try { Reflect.construct(Symbol, [], F); } catch (e) { symbolError = e instanceof TypeError; }
         [typeof w, w instanceof F, Number.prototype.valueOf.call(Object.setPrototypeOf(w, Number.prototype)),
          d instanceof F, symbolError].join(' ');",
        "object true 5 true true",
    );
}
