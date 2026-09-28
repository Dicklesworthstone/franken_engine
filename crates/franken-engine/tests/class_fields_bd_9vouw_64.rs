//! bd-9vouw.64 step 2: ES2022 public class fields, instance and static.
//!
//! Class fields used to be dropped silently, then refused (step 1). They are
//! now parsed as `MethodKind::Field` members, lowered to initializer
//! functions recorded on the class, and run by the interpreter: a base class
//! at construction entry, a derived class when its super() returns, statics
//! once the class body is defined. Expected strings are Node v22.2.0's output
//! for the same programs.
//!
//! No-claim: private names (`#x`, `#m()`, `#x in o`) and static blocks are
//! still refused at parse time; the franken-core twin lane does not parse
//! fields.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

/// Instance fields run in declaration order with `this` = the instance; static fields run once the
/// class exists, with `this` = the class; fields are own enumerable properties of the instance,
/// statics of the class.
#[test]
fn instance_and_static_fields_initialize_in_order() {
    check(
        r#"class A { x = 1; y = this.x + 1; static s = 'S'; static t = A.s + '!'; m() { return this.x + this.y; } }
const a = new A();
[a.x, a.y, a.m(), A.s, A.t, Object.keys(a).join(), JSON.stringify(a), Object.keys(A).join(), A.prototype.hasOwnProperty('x')].join(' ');"#,
        "1 2 3 S S! x,y {\"x\":1,\"y\":2} s,t false",
    );
}

/// An arrow initializer captures the instance: each instance gets its own function bound to itself.
#[test]
fn arrow_fields_capture_each_instance() {
    check(
        r#"class C { n = 0; inc = () => ++this.n; }
const c = new C(); const f = c.inc; f(); f();
const d = new C();
[c.n, d.n, c.inc !== d.inc].join(' ');"#,
        "2 0 true",
    );
}

/// A base class initializes its fields before its constructor body; a derived class right after its
/// super() returns, including the implicit constructor.
#[test]
fn derived_fields_initialize_when_super_returns() {
    check(
        r#"const log = [];
class B { b = log.push('B field'); constructor() { log.push('B ctor'); } }
class D extends B { d = log.push('D field'); constructor() { log.push('D before super'); super(); log.push('D after super'); } }
new D();
class E extends B { e = log.push('E field'); }
new E();
log.join(', ');"#,
        "D before super, B field, B ctor, D field, D after super, B field, B ctor, E field",
    );
}

/// A field is defined (CreateDataPropertyOrThrow), so it shadows an inherited accessor instead of
/// calling it, and `super.m()` in an initializer resolves through the class home object.
#[test]
fn fields_define_own_properties_and_see_super() {
    check(
        r#"class P { get v() { return 'getter'; } hello() { return 'hi'; } }
class Q extends P { v = 'field'; greet = super.hello() + '!'; }
const q = new Q();
[q.v, q.greet, Object.getOwnPropertyDescriptor(q, 'v').writable, Object.getOwnPropertyDescriptor(q, 'v').enumerable].join(' ');"#,
        "field hi! true true",
    );
}

/// Computed keys are evaluated once at class definition; a field with no initializer ends at a line
/// break (ASI) and is present with value undefined; a static initializer sees the class as `this`.
#[test]
fn computed_keys_asi_and_static_this() {
    check(
        r#"const k = 'dyn';
class R { [k + '1'] = 1
  plain
  ['x' + 'y'] = 2
  static s2 = this.name; }
const r = new R();
[r.dyn1, 'plain' in r, r.plain, r.xy, R.s2, Object.keys(r).join()].join(' ');"#,
        "1 true  2 R dyn1,plain,xy",
    );
}

/// Class expressions from a mixin factory keep per-evaluation initializers, and a class extending a
/// builtin (Map) initializes its fields after the builtin constructor.
#[test]
fn mixins_and_builtin_parents() {
    check(
        r#"const Mix = (Base) => class extends Base { m = 'mixed'; };
class Base0 { b = 'base'; }
const obj = new (Mix(Base0))();
const obj2 = new (Mix(class { c = 'other'; }))();
class M2 extends Map { tag = 'm'; }
const m = new M2([[1, 2]]);
[obj.b, obj.m, obj2.c, obj2.m, m.tag, m.get(1), m instanceof Map].join(' ');"#,
        "base mixed other mixed m 2 true",
    );
}

/// Initializers throw catchable errors from `new` (base, implicit derived, explicit derived); they
/// resolve names in the class scope, not the constructor scope; static arrow fields close over the
/// class.
#[test]
fn initializer_scope_throws_and_static_arrows() {
    check(
        r#"class T { x = (() => { throw new Error('boom'); })(); }
let msg; try { new T(); } catch (e) { msg = e.message; }
class U extends T {}
let msg2; try { new U(); } catch (e) { msg2 = e.message; }
class V { y = 1; }
class W extends V { z = (() => { throw new TypeError('late'); })(); }
let msg3; try { new W(); } catch (e) { msg3 = e instanceof TypeError ? e.message : 'wrong'; }
const z = 'outer';
class S { f = z; constructor(z) { this.g = z; } }
const s = new S('param');
class Cnt { static count = 0; static next = () => ++Cnt.count; }
Cnt.next(); Cnt.next();
[msg, msg2, msg3, s.f, s.g, Cnt.count].join(' ');"#,
        "boom boom late outer param 2",
    );
}

/// ES2022 ClassFieldDefinitionEvaluation: an anonymous function, arrow or
/// class initializer of a non-computed field takes the field's name.
#[test]
fn anonymous_initializers_take_the_field_name() {
    check(
        r#"class N { f = () => 1; g = function () {}; static h = () => 2; k = class {}; }
const n = new N();
[n.f.name, n.g.name, N.h.name, n.k.name].join(',');"#,
        "f,g,h,k",
    );
}
