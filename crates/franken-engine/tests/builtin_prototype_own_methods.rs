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

/// ES2020 20.2.1 / 17: Math's value properties exist (E, LN2, LN10, LOG2E,
/// LOG10E, SQRT1_2 and SQRT2 were undefined) and are read-only; the function
/// members of Math, JSON, Promise and Date are non-enumerable, so
/// `Object.keys(Math)` is empty (it listed 31 names) and `for...in` visits
/// nothing. A sloppy write to Math.PI is ignored; a strict one throws.
#[test]
fn namespace_members_have_builtin_attributes_and_math_has_its_constants() {
    let source = r#"const d = (o, k) => { const x = Object.getOwnPropertyDescriptor(o, k); return x === undefined ? 'none' : [typeof x.value, x.writable, x.enumerable, x.configurable].join(':'); };
let visited = 0; for (const k in Math) visited++;
const r = [Math.E, Math.LN2, Math.LN10, Math.LOG2E, Math.LOG10E, Math.SQRT1_2, Math.SQRT2, Math.PI].join(',') + ' ' +
  [d(Math, 'PI'), d(Math, 'SQRT2'), d(Math, 'max'), d(JSON, 'parse'), d(Promise, 'all'), d(Date, 'now'),
   Object.keys(Math).length, Object.keys(JSON).length, Object.keys(Promise).length, Object.keys(Date).length, visited,
   JSON.stringify(Math), Math.max(1, 2), JSON.parse('[1]')[0]].join(' ');
Math.PI = 3;
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
