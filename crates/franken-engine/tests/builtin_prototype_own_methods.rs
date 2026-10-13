//! ES2020 17: the methods of the builtin prototypes (and their `constructor`)
//! are own data properties { writable: true, enumerable: false,
//! configurable: true } of those prototype objects. FrankenEngine serves them
//! virtually through [[Get]], but `hasOwnProperty` answered false and
//! `Object.getOwnPropertyDescriptor(Array.prototype, 'indexOf')` answered
//! undefined, so feature detection of the form
//! `Object.prototype.hasOwnProperty.call(Array.prototype, 'includes')` or
//! `Object.getOwnPropertyDescriptor(proto, name)` misread every builtin as
//! missing. Expected strings are Node v22.2.0's output.
//!
//! No-claim: `Object.getOwnPropertyNames`/`Reflect.ownKeys` of the builtin
//! prototypes still omit the virtual methods, `delete Array.prototype.map`
//! does not remove one, and static methods of the constructors
//! (`Object.getOwnPropertyDescriptor(Object, 'keys')`) are not covered.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    value.to_string()
}

#[test]
fn builtin_prototype_methods_are_own_properties_of_the_prototype_only() {
    let source = "const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);\n\
                  class M extends Map {}\n\
                  [own(Array.prototype, 'map'), own(Array.prototype, 'constructor'), own([], 'map'), \
                  own(Object.create(Array.prototype), 'map'), Array.prototype.hasOwnProperty('indexOf'), \
                  own(String.prototype, 'trim'), own(Number.prototype, 'toFixed'), own(Map.prototype, 'get'), \
                  own(M.prototype, 'get'), own(Set.prototype, 'add'), own(Date.prototype, 'getTime'), \
                  own(RegExp.prototype, 'exec'), own(Promise.prototype, 'then'), own(Function.prototype, 'call'), \
                  own(Function.prototype, 'hasOwnProperty'), own(Object.prototype, 'hasOwnProperty'), \
                  own(Object.prototype, 'toString'), own(Error.prototype, 'toString'), \
                  own(TypeError.prototype, 'toString'), own(Array.prototype, 'nope'), \
                  Array.prototype.propertyIsEnumerable('map'), Object.keys(Array.prototype).length].join(' ');";
    assert_eq!(
        eval(source),
        "true true false false true true true true false true true true true true false true true \
         true false false false 0"
    );
}

#[test]
fn builtin_prototype_methods_have_non_enumerable_data_descriptors() {
    let source = "const d = (o, k) => { const x = Object.getOwnPropertyDescriptor(o, k); \
                  return x === undefined ? 'none' : [typeof x.value, x.writable, x.enumerable, x.configurable].join(':'); };\n\
                  [d(Array.prototype, 'indexOf'), d(Date.prototype, 'getUTCMonth'), d(Function.prototype, 'toString'), \
                  d(Number.prototype, 'toString'), d(Array.prototype, 'constructor'), d(Object.prototype, 'valueOf'), \
                  d([], 'map'), d(Function.prototype, 'hasOwnProperty'), \
                  Object.getOwnPropertyDescriptor(Array.prototype, 'indexOf').value === Array.prototype.indexOf, \
                  Object.getOwnPropertyDescriptor(Array.prototype, 'constructor').value === Array].join(' ');";
    assert_eq!(
        eval(source),
        "function:true:false:true function:true:false:true function:true:false:true \
         function:true:false:true function:true:false:true function:true:false:true none none true true"
    );
}

#[test]
fn a_real_own_property_still_wins_over_the_virtual_builtin() {
    let source = "const saved = Array.prototype.includes;\n\
                  Object.defineProperty(Array.prototype, 'includes', { value: 7, writable: false, enumerable: true, configurable: true });\n\
                  const x = Object.getOwnPropertyDescriptor(Array.prototype, 'includes');\n\
                  const r = [x.value, x.writable, x.enumerable, Object.keys(Array.prototype).join(',')].join(' ');\n\
                  Object.defineProperty(Array.prototype, 'includes', { value: saved, writable: true, enumerable: false, configurable: true });\n\
                  r + ' ' + [1, 2].includes(2);";
    assert_eq!(eval(source), "7 false true includes true");
}

/// bd-9vouw.346: %Function.prototype% is a built-in function whose [[Call]]
/// ignores its receiver and arguments and returns undefined (ES2020 19.2.3).
/// These exercise both invocation and the callback IsCallable checks.
#[test]
fn function_prototype_is_a_callable_noop_in_direct_and_callback_positions() {
    let source = r#"
const noop = Function.prototype;
let evaluated = 0;
const ignored = { valueOf() { throw new Error('must not coerce'); } };
const mapped = [1, 2].map(noop);
[
    typeof noop,
    Function.prototype(++evaluated, ignored) === undefined,
    noop(ignored) === undefined,
    noop.call(ignored, 1, 2) === undefined,
    noop.apply(ignored, [1, 2]) === undefined,
    Reflect.apply(noop, ignored, [1, 2]) === undefined,
    (null || Function.prototype)(ignored) === undefined,
    mapped.length,
    mapped[0] === undefined,
    mapped[1] === undefined,
    [1, 2].filter(noop).length,
    [1, 2].every(noop),
    [1, 2].some(noop),
    evaluated,
    Object.prototype.toString.call(noop),
    noop.toString()
].join('|');
"#;
    assert_eq!(
        eval(source),
        "function|true|true|true|true|true|true|2|true|true|0|false|false|1|\
         [object Function]|function () { [native code] }"
    );
}

#[test]
fn function_prototype_callable_and_property_backing_share_canonical_identity() {
    let source = r#"
const noop = Function.prototype;
function F() {}
noop.shared = 17;
const inherited = Object.create(noop);
Object.setPrototypeOf(F, noop);
[
    Object.getPrototypeOf(Function) === noop,
    Object.getPrototypeOf(F) === noop,
    Object.getPrototypeOf(Array.prototype.map) === noop,
    Object.getPrototypeOf(Object.getPrototypeOf(function* () {})) === noop,
    Object.getPrototypeOf(noop) === Object.prototype,
    Object.getPrototypeOf(inherited) === noop,
    Object.getOwnPropertyDescriptor(Function, 'prototype').value === noop,
    noop.constructor === Function,
    Object.prototype.valueOf.call(noop) === noop,
    noop.isPrototypeOf(F),
    noop.isPrototypeOf(inherited),
    noop instanceof Object,
    noop instanceof Function,
    inherited instanceof Function,
    inherited.shared,
    F.shared,
    noop.propertyIsEnumerable('shared'),
    Object.keys(noop).join(','),
    F instanceof Function,
    Function instanceof Function
].join('|');
"#;
    assert_eq!(
        eval(source),
        "true|true|true|true|true|true|true|true|true|true|true|true|false|true|\
         17|17|true|shared|true|true"
    );
}

#[test]
fn function_prototype_own_metadata_and_symbol_properties_remain_observable() {
    let source = r#"
const noop = Function.prototype;
const length = Object.getOwnPropertyDescriptor(noop, 'length');
const name = Object.getOwnPropertyDescriptor(noop, 'name');
const names = Object.getOwnPropertyNames(noop).sort().join(',');
const hasInstance = Object.getOwnPropertyDescriptor(noop, Symbol.hasInstance);
const initial = [
    noop.length, noop.name === '',
    length.value, length.writable, length.enumerable, length.configurable,
    name.value === '', name.writable, name.enumerable, name.configurable,
    noop.hasOwnProperty('length'), noop.hasOwnProperty('name'),
    noop.hasOwnProperty('prototype'), 'prototype' in noop,
    names,
    Reflect.ownKeys(noop).length,
    hasInstance.value === noop[Symbol.hasInstance],
    hasInstance.writable, hasInstance.enumerable, hasInstance.configurable
].join('|');
Object.defineProperty(noop, Symbol.toStringTag, {
    get() { return this === noop ? 'Noop' : 'Other'; }, configurable: true
});
initial + '|' + Object.prototype.toString.call(noop) + '|' +
    Reflect.get(noop, Symbol.toStringTag, {}) + '|' +
    Object.getOwnPropertySymbols(noop).length;
"#;
    assert_eq!(
        eval(source),
        "0|true|0|false|false|true|true|false|false|true|true|true|false|false|\
         apply,arguments,bind,call,caller,constructor,length,name,toString|10|true|false|false|false|\
         [object Noop]|Other|2"
    );
}

#[test]
fn function_prototype_metadata_deletion_and_prototype_changes_use_its_real_storage() {
    let source = r#"
const noop = Function.prototype;
const removed = [delete noop.length, delete noop.name,
    noop.length === undefined, noop.name === undefined,
    Object.getOwnPropertyDescriptor(noop, 'length') === undefined,
    noop.hasOwnProperty('name')].join('|');
Object.defineProperty(noop, 'name', { value: 'empty', configurable: true });
Object.defineProperty(noop, 'length', { value: 3, configurable: true });
const parent = { extra: 9 };
Object.setPrototypeOf(noop, parent);
const changed = [noop.name, noop.length, noop.extra,
    Object.getPrototypeOf(noop) === parent, typeof noop,
    noop() === undefined].join('|');
Object.setPrototypeOf(noop, null);
removed + '|' + changed + '|' + [Object.getPrototypeOf(noop) === null,
    noop.__proto__ === undefined, 'hasOwnProperty' in noop,
    Reflect.get(noop, 'hasOwnProperty') === undefined, 'call' in noop,
    delete noop.call, 'call' in noop, typeof noop].join('|');
"#;
    assert_eq!(
        eval(source),
        "true|true|true|true|true|false|empty|3|9|true|function|true|\
         true|true|false|true|true|true|false|function"
    );
}

#[test]
fn function_prototype_is_not_a_constructor_even_when_bound_or_proxied() {
    let source = r#"
const noop = Function.prototype;
const bound = noop.bind(null, 1);
const proxied = new Proxy(noop, {});
let errors = [];
function reject(thunk) {
    try { thunk(); errors.push('accepted'); }
    catch (error) { errors.push(error.name); }
}
reject(function () { new noop(); });
reject(function () { new bound(); });
reject(function () { new proxied(); });
reject(function () { Reflect.construct(noop, []); });
reject(function () { Reflect.construct(function () {}, [], noop); });
reject(function () { return {} instanceof noop; });
errors.join(',') + '|' + [typeof bound, bound() === undefined,
    typeof proxied, proxied() === undefined,
    noop[Symbol.hasInstance](1)].join('|');
"#;
    assert_eq!(
        eval(source),
        "TypeError,TypeError,TypeError,TypeError,TypeError,TypeError|\
         function|true|function|true|false"
    );
}

#[test]
fn promise_handlers_accept_function_prototype_as_a_noop() {
    let source = r#"
Promise.resolve(41).then(Function.prototype).then(function (value) {
    console.log(value === undefined ? 'fulfilled-undefined' : 'wrong-value');
});
Promise.reject(42).catch(Function.prototype).then(function (value) {
    console.log(value === undefined ? 'recovered-undefined' : 'wrong-value');
});
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<_> = outcome
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["fulfilled-undefined", "recovered-undefined"]);
}

#[test]
fn function_prototype_keeps_callable_identity_through_proxy_prototype_traps() {
    let source = r#"
const noop = Function.prototype;
const target = Object.preventExtensions(Object.create(noop));
const proxy = new Proxy(target, { getPrototypeOf() { return noop; } });
let observed = '';
const sink = new Proxy({}, {
    setPrototypeOf(target, prototype) {
        observed = typeof prototype + ':' + (prototype === noop);
        return true;
    }
});
Object.setPrototypeOf(sink, noop);
[
    Object.getPrototypeOf(proxy) === noop,
    Reflect.getPrototypeOf(proxy) === noop,
    observed
].join('|');
"#;
    assert_eq!(eval(source), "true|true|function:true");
}

#[test]
fn function_prototype_metadata_is_visible_in_reducer_callbacks() {
    let source = r#"
const noop = Function.prototype;
[
    [1].reduce(function (total) { return total + noop.length; }, 7),
    [1].reduce(function () { return typeof noop.call; }, ''),
    [1].reduce(function () { return noop.name === ''; }, false)
].join('|');
"#;
    assert_eq!(eval(source), "7|function|true");
}

/// ES2020 20.2.1 / 17: Math's value properties exist (E, LN2, LN10, LOG2E,
/// LOG10E, SQRT1_2 and SQRT2 were undefined) and are read-only; the function
/// members of Math, JSON, Promise and Date are non-enumerable, so
/// `Object.keys(Math)` is empty (it listed 31 names) and `for...in` visits
/// nothing. A strict write to Math.E throws a TypeError. (A sloppy write
/// should be ignored but still throws: bd-9vouw.36, SetProperty carries no
/// strictness.)
#[test]
fn namespace_members_have_builtin_attributes_and_math_has_its_constants() {
    let source = r#"const d = (o, k) => { const x = Object.getOwnPropertyDescriptor(o, k); return x === undefined ? 'none' : [typeof x.value, x.writable, x.enumerable, x.configurable].join(':'); };
let visited = 0; for (const k in Math) visited++;
const r = [Math.E, Math.LN2, Math.LN10, Math.LOG2E, Math.LOG10E, Math.SQRT1_2, Math.SQRT2, Math.PI].join(',') + ' ' +
  [d(Math, 'PI'), d(Math, 'SQRT2'), d(Math, 'max'), d(JSON, 'parse'), d(Promise, 'all'), d(Date, 'now'),
   Object.keys(Math).length, Object.keys(JSON).length, Object.keys(Promise).length, Object.keys(Date).length, visited,
   JSON.stringify(Math), Math.max(1, 2), JSON.parse('[1]')[0]].join(' ');
let strict; try { (function () { 'use strict'; Math.E = 1; })(); strict = 'no throw'; } catch (e) { strict = e instanceof TypeError; }
r + ' ' + Math.PI + ' ' + strict + ' ' + Math.E;"#;
    assert_eq!(
        eval(source),
        "2.718281828459045,0.6931471805599453,2.302585092994046,1.4426950408889634,\
         0.4342944819032518,0.7071067811865476,1.4142135623730951,3.141592653589793 \
         number:false:false:false number:false:false:false function:true:false:true \
         function:true:false:true function:true:false:true function:true:false:true 0 0 0 0 0 {} 2 1 \
         3.141592653589793 true 2.718281828459045"
    );
}
