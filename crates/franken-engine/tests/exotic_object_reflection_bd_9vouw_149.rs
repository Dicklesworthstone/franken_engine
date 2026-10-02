//! bd-9vouw.149: promises, generator and async generator objects and
//! iterators are objects for the reflection built-ins, and functions and those
//! values honor the integrity operations.
//!
//! Reflect.ownKeys/get/has/set/deleteProperty threw "expected object" on
//! these values, Object.getOwnPropertyNames/Symbols/entries/values and spread
//! did not see their own properties, iterators could not store any, and
//! Object.freeze/seal/isFrozen/isSealed/preventExtensions ignored or rejected
//! functions and these values. Expected strings are Node v22.2.0's output for
//! the same programs.
//!
//! No-claim: Object.setPrototypeOf on these values, assignment to a frozen
//! function's `prototype`, and sloppy-mode assignment failures (they throw,
//! as for ordinary objects: bd-9vouw.146).

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// Reflect.ownKeys and the Object key listings answer [] on a promise, generator, async generator or iterator.
#[test]
fn exotic_own_keys_of_fresh_values() {
    let source = "var kinds = { promise: function () { return Promise.resolve(1); },\n\
           generator: function () { return (function* () { yield 1; })(); },\n\
           asyncGenerator: function () { return (async function* () {})(); },\n\
           arrayIterator: function () { return [1, 2].values(); },\n\
           mapIterator: function () { return new Map([[1, 2]]).keys(); },\n\
           stringIterator: function () { return 'ab'[Symbol.iterator](); } };\n\
         Object.keys(kinds).map(function (k) { var v = kinds[k]();\n\
           return k + ':' + JSON.stringify([Reflect.ownKeys(v), Object.getOwnPropertyNames(v), Object.getOwnPropertySymbols(v).length,\n\
             Object.entries(v), Object.values(v)]); }).join(' ');";
    assert_eq!(
        eval(source),
        "promise:[[],[],0,[],[]] generator:[[],[],0,[],[]] asyncGenerator:[[],[],0,[],[]] arrayIterator:[[],[],0,[],[]] mapIterator:[[],[],0,[],[]] stringIterator:[[],[],0,[],[]]"
    );
}

/// Properties stored on these values are their own properties for every reflection path (iterators stored none before).
#[test]
fn exotic_expando_properties() {
    let source = "var kinds = { promise: function () { return Promise.resolve(1); },\n\
           generator: function () { return (function* () { yield 1; })(); },\n\
           asyncGenerator: function () { return (async function* () {})(); },\n\
           arrayIterator: function () { return [1, 2].values(); },\n\
           mapIterator: function () { return new Map([[1, 2]]).keys(); },\n\
           stringIterator: function () { return 'ab'[Symbol.iterator](); } };\n\
         function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var s = Symbol('s');\n\
         Object.keys(kinds).map(function (k) { var v = kinds[k](); v.tag = 3; v[s] = 4;\n\
           Object.defineProperty(v, 'hidden', { value: 5 });\n\
           return k + ':' + [v.tag, v.hidden, v[s], Reflect.ownKeys(v).length, Object.getOwnPropertyNames(v).join('/'),\n\
             Object.getOwnPropertySymbols(v).length, JSON.stringify(Object.entries(v)), Object.values(v).join('/'),\n\
             JSON.stringify(Object.assign({}, v)), JSON.stringify({ ...v }), v.hasOwnProperty('tag'), Object.hasOwn(v, 'hidden'),\n\
             JSON.stringify(Object.getOwnPropertyDescriptor(v, 'hidden')), 'tag' in v].join(','); }).join(' ');";
    assert_eq!(
        eval(source),
        "promise:3,5,4,3,tag/hidden,1,[[\"tag\",3]],3,{\"tag\":3},{\"tag\":3},true,true,{\"value\":5,\"writable\":false,\"enumerable\":false,\"configurable\":false},true generator:3,5,4,3,tag/hidden,1,[[\"tag\",3]],3,{\"tag\":3},{\"tag\":3},true,true,{\"value\":5,\"writable\":false,\"enumerable\":false,\"configurable\":false},true asyncGenerator:3,5,4,3,tag/hidden,1,[[\"tag\",3]],3,{\"tag\":3},{\"tag\":3},true,true,{\"value\":5,\"writable\":false,\"enumerable\":false,\"configurable\":false},true arrayIterator:3,5,4,3,tag/hidden,1,[[\"tag\",3]],3,{\"tag\":3},{\"tag\":3},true,true,{\"value\":5,\"writable\":false,\"enumerable\":false,\"configurable\":false},true mapIterator:3,5,4,3,tag/hidden,1,[[\"tag\",3]],3,{\"tag\":3},{\"tag\":3},true,true,{\"value\":5,\"writable\":false,\"enumerable\":false,\"configurable\":false},true stringIterator:3,5,4,3,tag/hidden,1,[[\"tag\",3]],3,{\"tag\":3},{\"tag\":3},true,true,{\"value\":5,\"writable\":false,\"enumerable\":false,\"configurable\":false},true"
    );
}

/// Object spread copies the enumerable own properties of these values and of functions.
#[test]
fn exotic_spread_copies_own_properties() {
    let source = "var kinds = { promise: function () { return Promise.resolve(1); },\n\
           generator: function () { return (function* () { yield 1; })(); },\n\
           asyncGenerator: function () { return (async function* () {})(); },\n\
           arrayIterator: function () { return [1, 2].values(); },\n\
           mapIterator: function () { return new Map([[1, 2]]).keys(); },\n\
           stringIterator: function () { return 'ab'[Symbol.iterator](); } };\n\
         function f() {} f.a = 1; Object.defineProperty(f, 'b', { value: 2 });\n\
         var p = kinds.promise(); p.x = 1; var it = kinds.arrayIterator(); it.y = 2;\n\
         JSON.stringify([{ ...p }, { ...it }, { ...f }, Object.values(f), Object.entries(f)]);";
    assert_eq!(
        eval(source),
        "[{\"x\":1},{\"y\":2},{\"a\":1},[1],[[\"a\",1]]]"
    );
}

/// Reflect.get/has/set/defineProperty/deleteProperty/getOwnPropertyDescriptor work on them; get and has continue on the intrinsic prototype.
#[test]
fn exotic_reflect_property_operations() {
    let source = "var kinds = { promise: function () { return Promise.resolve(1); },\n\
           generator: function () { return (function* () { yield 1; })(); },\n\
           asyncGenerator: function () { return (async function* () {})(); },\n\
           arrayIterator: function () { return [1, 2].values(); },\n\
           mapIterator: function () { return new Map([[1, 2]]).keys(); },\n\
           stringIterator: function () { return 'ab'[Symbol.iterator](); } };\n\
         Object.keys(kinds).map(function (k) { var v = kinds[k]();\n\
           return k + ':' + [Reflect.has(v, 'tag'), Reflect.set(v, 'tag', 1), Reflect.get(v, 'tag'), Reflect.has(v, 'tag'),\n\
             Reflect.defineProperty(v, 'k', { value: 2, enumerable: true }), Reflect.get(v, 'k'),\n\
             JSON.stringify(Reflect.getOwnPropertyDescriptor(v, 'k')), Reflect.deleteProperty(v, 'tag'), Reflect.has(v, 'tag'),\n\
             typeof Reflect.get(v, 'toString'), Reflect.has(v, 'hasOwnProperty'), Reflect.isExtensible(v)].join(','); }).join(' ');";
    assert_eq!(
        eval(source),
        "promise:false,true,1,true,true,2,{\"value\":2,\"writable\":false,\"enumerable\":true,\"configurable\":false},true,false,function,true,true generator:false,true,1,true,true,2,{\"value\":2,\"writable\":false,\"enumerable\":true,\"configurable\":false},true,false,function,true,true asyncGenerator:false,true,1,true,true,2,{\"value\":2,\"writable\":false,\"enumerable\":true,\"configurable\":false},true,false,function,true,true arrayIterator:false,true,1,true,true,2,{\"value\":2,\"writable\":false,\"enumerable\":true,\"configurable\":false},true,false,function,true,true mapIterator:false,true,1,true,true,2,{\"value\":2,\"writable\":false,\"enumerable\":true,\"configurable\":false},true,false,function,true,true stringIterator:false,true,1,true,true,2,{\"value\":2,\"writable\":false,\"enumerable\":true,\"configurable\":false},true,false,function,true,true"
    );
}

/// preventExtensions, seal and freeze apply to them; isExtensible/isSealed/isFrozen report it; a fresh value is extensible.
#[test]
fn exotic_integrity_of_exotic_values() {
    let source = "var kinds = { promise: function () { return Promise.resolve(1); },\n\
           generator: function () { return (function* () { yield 1; })(); },\n\
           asyncGenerator: function () { return (async function* () {})(); },\n\
           arrayIterator: function () { return [1, 2].values(); },\n\
           mapIterator: function () { return new Map([[1, 2]]).keys(); },\n\
           stringIterator: function () { return 'ab'[Symbol.iterator](); } };\n\
         Object.keys(kinds).map(function (k) {\n\
           var fresh = kinds[k](); var fresh_state = [Object.isExtensible(fresh), Object.isSealed(fresh), Object.isFrozen(fresh)].join('/');\n\
           var a = kinds[k](); a.x = 1; Object.preventExtensions(a);\n\
           var b = kinds[k](); b.x = 1; Object.seal(b);\n\
           var c = kinds[k](); c.x = 1; Object.freeze(c);\n\
           return k + ':' + [fresh_state, Reflect.set(a, 'y', 1), a.y, Reflect.set(a, 'x', 2), a.x, Object.isExtensible(a), Object.isSealed(a),\n\
             Reflect.deleteProperty(b, 'x'), b.x, Reflect.set(b, 'x', 3), b.x, Object.isSealed(b), Object.isFrozen(b),\n\
             Reflect.set(c, 'x', 4), c.x, Object.isFrozen(c), Reflect.isExtensible(c), Reflect.preventExtensions(kinds[k]())].join(','); }).join(' ');";
    assert_eq!(
        eval(source),
        "promise:true/false/false,false,,true,2,false,false,false,1,true,3,true,false,false,1,true,false,true generator:true/false/false,false,,true,2,false,false,false,1,true,3,true,false,false,1,true,false,true asyncGenerator:true/false/false,false,,true,2,false,false,false,1,true,3,true,false,false,1,true,false,true arrayIterator:true/false/false,false,,true,2,false,false,false,1,true,3,true,false,false,1,true,false,true mapIterator:true/false/false,false,,true,2,false,false,false,1,true,3,true,false,false,1,true,false,true stringIterator:true/false/false,false,,true,2,false,false,false,1,true,3,true,false,false,1,true,false,true"
    );
}

/// for-in visits their enumerable own properties, then their prototype's (it threw "expected object"; object-inspect's Promise path).
#[test]
fn exotic_for_in_enumeration() {
    let source = "var kinds = { promise: function () { return Promise.resolve(1); },\n\
           generator: function () { return (function* () { yield 1; })(); },\n\
           asyncGenerator: function () { return (async function* () {})(); },\n\
           arrayIterator: function () { return [1, 2].values(); },\n\
           mapIterator: function () { return new Map([[1, 2]]).keys(); },\n\
           stringIterator: function () { return 'ab'[Symbol.iterator](); } };\n\
         function keys(v) { var ks = []; for (var k in v) ks.push(k); return ks.join('/'); }\n\
         Promise.prototype.extra = 1;\n\
         Object.keys(kinds).map(function (k) { var v = kinds[k](); v.tag = 1; Object.defineProperty(v, 'hidden', { value: 2 });\n\
           return k + ':' + keys(v) + ':' + keys(kinds[k]()); }).join(' ');";
    assert_eq!(
        eval(source),
        "promise:tag/extra:extra generator:tag: asyncGenerator:tag: arrayIterator:tag: mapIterator:tag: stringIterator:tag:"
    );
}

/// Object.freeze/seal/isFrozen/isSealed of a Proxy run through its traps (they marked the proxy record itself).
#[test]
fn exotic_integrity_of_proxies() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var log = []; var target = { a: 1 }; Object.defineProperty(target, 'b', { get: function () { return 2; }, configurable: true });\n\
         var p = new Proxy(target, { preventExtensions: function (t) { log.push('pe'); return Reflect.preventExtensions(t); },\n\
           ownKeys: function (t) { log.push('ok'); return Reflect.ownKeys(t); },\n\
           defineProperty: function (t, k, d) { log.push('dp:' + k + ':' + JSON.stringify(d)); return Reflect.defineProperty(t, k, d); },\n\
           getOwnPropertyDescriptor: function (t, k) { log.push('gopd:' + k); return Reflect.getOwnPropertyDescriptor(t, k); },\n\
           isExtensible: function (t) { log.push('ie'); return Reflect.isExtensible(t); } });\n\
         Object.freeze(p); var freezeLog = log.join(','); log = []; var isFrozen = Object.isFrozen(p); var testLog = log.join(',');\n\
         var r = Proxy.revocable({}, {}); r.revoke(); var fn = new Proxy(function () {}, {});\n\
         [freezeLog, isFrozen, testLog, Object.isFrozen(target), Object.isSealed(new Proxy({}, {})), Object.isSealed(Object.seal(new Proxy({ x: 1 }, {}))),\n\
          attempt(() => Object.freeze(new Proxy({}, { preventExtensions: function () { return false; } }))), Object.isFrozen(Object.freeze(fn)),\n\
          attempt(() => Object.freeze(r.proxy)), attempt(() => Object.isFrozen(r.proxy))].join(' | ');";
    assert_eq!(
        eval(source),
        "pe,ok,gopd:a,dp:a:{\"writable\":false,\"configurable\":false},gopd:b,dp:b:{\"configurable\":false} | true | ie,ok,gopd:a,gopd:b | true | false | true | TypeError | true | TypeError | TypeError"
    );
}

/// Functions, classes and arrows: Object.freeze/seal/preventExtensions take effect (they were no-ops or threw).
#[test]
fn exotic_integrity_of_functions() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         function f() {} class C { static m() {} } var g = function () {}; var h = () => 1;\n\
         var fresh = [Object.isExtensible(f), Object.isSealed(f), Object.isFrozen(f), Reflect.isExtensible(h)].join('/');\n\
         Object.freeze(f); Object.seal(C); Object.preventExtensions(g);\n\
         var strict_write = attempt(function () { 'use strict'; f.x = 1; return 'written'; });\n\
         [fresh, strict_write, f.x, Reflect.set(f, 'y', 1), Object.isFrozen(f), Object.isExtensible(f),\n\
          Reflect.set(C, 'z', 1), C.z, Reflect.deleteProperty(C, 'm'), typeof C.m, Reflect.set(C, 'm', 1), C.m, Object.isSealed(C), Object.isFrozen(C),\n\
          Reflect.set(g, 'q', 1), g.q, Object.isExtensible(g), Object.isSealed(g), Reflect.preventExtensions(h), Reflect.isExtensible(h),\n\
          Reflect.defineProperty(h, 'w', { value: 1 })].join(',');";
    assert_eq!(
        eval(source),
        "true/false/false/true,TypeError,,false,true,false,false,,false,function,true,1,true,false,false,,false,false,true,false,false"
    );
}
