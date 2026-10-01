//! bd-9vouw.93: a canonical built-in prototype supplies its methods,
//! `constructor` and Symbol-keyed methods virtually, and they are
//! configurable, so `delete` must make them absent. `delete
//! Array.prototype.fill` answered true and left `fill` in place (every
//! Test262 `verifyProperty(..., { configurable: true })` check deletes the
//! property and expects it gone), and deleting WeakSet.prototype's
//! @@toStringTag left `Object.prototype.toString` answering
//! "[object WeakSet]". Expected strings are Node v22.2.0's output.
//!
//! No-claim: arrays still iterate natively in `for-of` and spread after
//! %Array.prototype%[@@iterator] is deleted, the Promise tag of promise values
//! does not follow a deleted Promise.prototype[@@toStringTag], and
//! `Reflect.ownKeys` lists virtual keys of %Array.prototype% only.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value
}

#[test]
fn deleting_a_virtual_method_removes_it() {
    let source = "var r = [];\n\
                  r.push(delete Array.prototype.fill, Array.prototype.hasOwnProperty('fill'), \
                  typeof [].fill, 'fill' in []);\n\
                  r.push(delete Date.prototype.getMilliseconds, \
                  Date.prototype.hasOwnProperty('getMilliseconds'), \
                  typeof new Date(0).getMilliseconds);\n\
                  r.push(Object.getOwnPropertyNames(Array.prototype).indexOf('fill'));\n\
                  r.join(' ');";
    assert_eq!(
        eval(source),
        "true false undefined false true false undefined -1"
    );
}

/// A stored property that shadows a virtual one goes with it, and a deleted
/// method is looked up further along the chain.
#[test]
fn deleting_shadowed_and_inherited_methods() {
    let source = "var r = [];\n\
                  Array.prototype.lastIndexOf = function () { return 'mine'; };\n\
                  r.push([1].lastIndexOf(1), delete Array.prototype.lastIndexOf, \
                  typeof [].lastIndexOf);\n\
                  r.push(delete Array.prototype.toString, [1, 2].toString());\n\
                  r.push(delete Object.prototype.hasOwnProperty, typeof {}.hasOwnProperty);\n\
                  r.join(' ');";
    assert_eq!(
        eval(source),
        "mine true undefined true [object Array] true undefined"
    );
}

#[test]
fn deleting_constructor_and_symbol_keyed_methods() {
    let source = "var r = [];\n\
                  r.push(delete Set.prototype.constructor, new Set().constructor === Object, \
                  Set.prototype.hasOwnProperty('constructor'));\n\
                  r.push(Object.prototype.propertyIsEnumerable.call(Array.prototype, Symbol.iterator), \
                  Map.prototype.hasOwnProperty(Symbol.iterator));\n\
                  r.push(delete Map.prototype[Symbol.iterator], typeof new Map()[Symbol.iterator], \
                  Map.prototype.hasOwnProperty(Symbol.iterator));\n\
                  r.join(' ');";
    assert_eq!(
        eval(source),
        "true true false false true true undefined false"
    );
}

/// %Array.prototype%.length is an Array's `length`: not configurable.
#[test]
fn array_prototype_length_is_not_deleted() {
    let source = "var d = Object.getOwnPropertyDescriptor(Array.prototype, 'length');\n\
                  [delete Array.prototype.length, Array.prototype.length, d.configurable, \
                  (function () { 'use strict'; try { delete Array.prototype.length; return 'no'; } \
                  catch (e) { return e instanceof TypeError; } })()].join(' ');";
    assert_eq!(eval(source), "false 0 false true");
}

/// The tags of Map, Set, WeakSet, ... are their prototypes' @@toStringTag
/// data properties, not builtinTags: a deleted one, or a chain that does not
/// reach it, leaves "[object Object]".
#[test]
fn a_deleted_or_bypassed_to_string_tag_is_gone() {
    let source = "var ts = Object.prototype.toString;\n\
                  var ws = new WeakSet(), m = new Map(), nm = new Map();\n\
                  Object.setPrototypeOf(nm, null);\n\
                  [delete WeakSet.prototype[Symbol.toStringTag], ts.call(ws), ts.call(nm), \
                  ts.call(m), ts.call(new Set())].join(' ');";
    assert_eq!(
        eval(source),
        "true [object Object] [object Object] [object Map] [object Set]"
    );
}
