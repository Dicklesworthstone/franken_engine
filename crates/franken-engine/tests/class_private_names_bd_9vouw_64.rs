//! bd-9vouw.64 step 3: ES2022 private class elements and static blocks.
//!
//! `#x` fields, `#m()` methods, `get #x()` / `set #x()` accessors, their
//! static forms, `#x in o` brand checks and `static { }` blocks. Each class
//! evaluation creates new private names; a private element lives in the
//! object's [[PrivateElements]], never as a property. Expected strings are
//! Node v22.2.0's completion values for the same programs
//! (`vm.runInNewContext`).
//!
//! No-claim: the franken-core twin lane does not parse class fields or
//! private names; `arguments`, `await` and `return` in a static block are not
//! early errors; async private methods are not exercised here (the completion
//! value is synchronous).
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

/// Private fields, static private fields, private getters and setters: each
/// instance has its own fields, and none of them is a property.
#[test]
fn private_fields_and_accessors_hold_per_instance_state() {
    check(
        r#"class Counter { #count = 0; static #instances = 0; constructor() { Counter.#instances++; } inc() { return ++this.#count; } get #double() { return this.#count * 2; } get twice() { return this.#double; } set #value(v) { this.#count = v; } reset(v) { this.#value = v; return this; } static get instances() { return Counter.#instances; } }
const a = new Counter(); const b = new Counter(); a.inc(); a.inc(); b.inc();
[a.inc(), b.inc(), a.twice, a.reset(10).inc(), Counter.instances, Object.keys(a).length, JSON.stringify(a), Reflect.ownKeys(a).length].join(' ');"#,
        "3 2 6 11 2 0 {} 0",
    );
}

/// `#x in o` is a brand check; reading or writing a private member of an
/// object without it, `#x in` a primitive, and writing a private method all
/// throw TypeErrors.
#[test]
fn brand_checks_and_type_errors() {
    check(
        r#"class A { #x = 1; static has(o) { return #x in o; } static read(o) { return o.#x; } static write(o) { o.#x = 5; } #m() {} static callM(o) { o.#m = 1; } }
const out = [A.has(new A()), A.has({}), A.has(A)];
for (const f of [() => A.read({}), () => A.write({}), () => A.has(1), () => A.callM(new A())]) { try { f(); out.push('no'); } catch (e) { out.push(e instanceof TypeError); } }
out.join(' ');"#,
        "true false false true true true true",
    );
}

/// Private methods keep `this`, and arrow callbacks inside methods reach the
/// class's private names.
#[test]
fn private_methods_and_callbacks() {
    check(
        r#"class Stack { #items = []; #check(n) { if (n < 0) throw new RangeError('neg'); return n; } push(...xs) { xs.forEach(x => this.#items.push(this.#check(x))); return this; } sum() { return this.#items.reduce((a, b) => a + b, 0); } map(f) { return this.#items.map(x => f(x, this.#items.length)); } }
const s = new Stack().push(1, 2, 3);
let err; try { s.push(-1); } catch (e) { err = e.name; }
[s.sum(), s.map((x, n) => x * n).join(','), err].join(' ');"#,
        "6 3,6,9 RangeError",
    );
}

/// A derived instance carries its base class's private elements (reached
/// through base methods) and its own; a derived class without a constructor
/// still installs its private methods. (The field is not named `#secret`:
/// the keyword-based IFC labelling of bd-9vouw.19 refuses any class field
/// whose key contains "secret", public or private, at lowering.)
#[test]
fn derived_classes_carry_base_and_own_private_elements() {
    check(
        r#"class Base { #hidden = 'b'; reveal() { return this.#hidden; } static isBase(o) { return #hidden in o; } }
class Derived extends Base { #own = 'd'; #helper() { return this.#own + this.reveal(); } both() { return this.#helper(); } }
class NoCtor extends Base { #m() { return 'm'; } call() { return this.#m(); } }
const d = new Derived();
[d.both(), Base.isBase(d), d.reveal(), new NoCtor().call(), Base.isBase({})].join(' ');"#,
        "db true b m false",
    );
}

/// Every evaluation of a class creates new private names, so classes made by
/// one factory do not share a brand.
#[test]
fn each_class_evaluation_has_its_own_brand() {
    check(
        r#"function make() { return class { #v = 1; static has(o) { return #v in o; } }; }
const C1 = make(), C2 = make();
[C1.has(new C1()), C1.has(new C2()), C2.has(new C2())].join(' ');"#,
        "true false true",
    );
}

/// Private elements are not properties: freezing does not stop a private
/// write, keys, symbols and spread do not show them, and a Proxy has none.
#[test]
fn private_elements_are_not_properties() {
    check(
        r#"class P { #x = 1; y = 2; getX() { return this.#x; } setX(v) { this.#x = v; return this.#x; } }
const p = new P(); Object.freeze(p);
const r = [p.setX(3), Object.keys(p).join(), Object.getOwnPropertySymbols(p).length, JSON.stringify({...p}), Object.isFrozen(p)];
try { new Proxy(new P(), {}).getX(); r.push('no'); } catch (e) { r.push(e instanceof TypeError); }
r.join(' ');"#,
        "3 y 0 {\"y\":2} true true",
    );
}

/// Static private fields and methods live on the class itself, not on a
/// subclass; a static block runs with the class as `this`.
#[test]
fn static_private_elements_and_static_blocks() {
    check(
        r#"class S { static #count = 0; static #bump() { return ++S.#count; } static next() { return S.#bump(); } static { S.initial = S.#count + 10; } static read() { return this.#count; } }
class T extends S {}
S.next(); S.next();
let e; try { T.read(); } catch (x) { e = x instanceof TypeError; }
[S.next(), S.initial, S.read(), e].join(' ');"#,
        "3 10 3 true",
    );
    check(
        r#"const log = [];
class B { static a = log.push('a'); static { log.push('block1:' + this.a); } static b = log.push('b'); static { log.push('block2:' + typeof this.b); } }
log.join(' ');"#,
        "a block1:1 b block2:number",
    );
}

/// Compound, update, logical and destructuring assignments write private
/// fields.
#[test]
fn every_assignment_form_writes_private_fields() {
    check(
        r#"class N { #n = 1; #s; #o = null; run() { this.#n += 4; this.#n *= 2; this.#n++; ++this.#n; this.#s ??= 'set'; this.#o ||= {k: 1}; [this.#n] = [this.#n + 100]; return [this.#n, this.#s, this.#o.k].join(','); } }
new N().run();"#,
        "112,set,1",
    );
}

/// A getter-only accessor cannot be written and a setter-only one cannot be
/// read; object-literal methods and arrows inside a class reach its private
/// names.
#[test]
fn accessor_halves_and_nested_functions() {
    check(
        r#"class G { get #r() { return 1; } set #w(v) {} tryWrite() { this.#r = 2; } tryRead() { return this.#w; } obj() { const self = this; return { m() { return self.#r; }, a: () => this.#r }; } }
const g = new G(); const res = [];
for (const f of [() => g.tryWrite(), () => g.tryRead()]) { try { f(); res.push('no'); } catch (e) { res.push(e instanceof TypeError); } }
const o = g.obj(); res.push(o.m(), o.a());
res.join(' ');"#,
        "true true 1 1",
    );
    check(
        r#"class Outer { #x = 'outer'; make() { const self = this; return new (class Inner { #y = 'inner'; read(o) { return o.#x + '/' + this.#y; } })().read(self); } }
new Outer().make();"#,
        "outer/inner",
    );
}

/// A private method is named by its private name, as is an anonymous
/// function in a private field; a private generator method iterates.
#[test]
fn private_method_names_and_generators() {
    check(
        r#"class M { #priv() {} get #acc() { return 1; } static names(o) { return [o.#priv.name, typeof o.#priv]; } #f = () => 1; fname() { return this.#f.name; } }
[...M.names(new M()), new M().fname()].join(' ');"#,
        "#priv function #f",
    );
    check(
        r#"class Q { *#gen() { yield 1; yield 2; } list() { return [...this.#gen()]; } }
new Q().list().join(',');"#,
        "1,2",
    );
}

/// A constructor that returns an existing object lets a derived class stamp
/// its private fields on it once; a second stamp throws.
#[test]
fn stamping_an_object_twice_throws() {
    check(
        r#"class Base2 { constructor(o) { return o; } }
class Stamp extends Base2 { #tag = 't'; static has(o) { return #tag in o; } }
const obj = {}; new Stamp(obj);
let twice; try { new Stamp(obj); } catch (e) { twice = e instanceof TypeError; }
[Stamp.has(obj), twice, Object.keys(obj).length].join(' ');"#,
        "true true 0",
    );
}
