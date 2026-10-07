//! ES2020 23.1.3 / 23.2.3 and 19.1.2: Map and Set methods require a Map or
//! Set receiver, and Object.keys / values / entries / assign apply ToObject,
//! which throws for undefined and null. FrankenEngine answered `false` or
//! `undefined` (Map/Set `has`, `get`, `delete`, `clear` on any other
//! receiver), silently did nothing (`set`/`add` on a plain object), returned
//! `[]` for `Object.keys(undefined)` and returned the target unchanged from
//! `Object.assign(null)`: each is a TypeError in Node. Six Test262 sample
//! failures (Set.prototype.has/clear this-not-object and missing [[SetData]],
//! Object.keys 15.2.3.14-1-5, Object.assign Target-Undefined) are this.
//! String methods' search and fill arguments go through ToString, which
//! throws for a Symbol; FrankenEngine searched for `"Symbol()"` instead.
//! Expected strings are Node v22.2.0's output for the same source.
//!
//! No-claim: string arguments still give `[]` from Object.keys/values/entries
//! (Node indexes the string's code units); that is not covered here.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

const PROBE: &str = "function t(f) { try { f(); return 'no throw'; } catch (e) { \
                     return e instanceof TypeError ? 'TypeError' : 'other:' + e; } }\n";

#[test]
fn map_and_set_methods_reject_foreign_receivers() {
    let source = format!(
        "{PROBE}[\
         t(() => Set.prototype.has.call({{}}, 1)),\
         t(() => Set.prototype.has.call(undefined, 1)),\
         t(() => Set.prototype.add.call(new Map(), 1)),\
         t(() => Set.prototype.delete.call([], 1)),\
         t(() => Set.prototype.clear.call(Set.prototype)),\
         t(() => Map.prototype.get.call({{}}, 1)),\
         t(() => Map.prototype.set.call(new Set(), 1, 2)),\
         t(() => Map.prototype.has.call(null, 1)),\
         t(() => Map.prototype.delete.call('m', 1)),\
         t(() => Map.prototype.clear.call(Object.create(Map.prototype)))\
         ].join(',');"
    );
    assert_eq!(eval(&source), ["TypeError"; 10].join(","));
}

#[test]
fn map_and_set_methods_keep_working_on_real_and_subclassed_collections() {
    assert_eq!(
        eval(
            "class S extends Set {} class M extends Map {}\n\
             var s = new S([1, 2]); var m = new M([['k', 1]]);\n\
             var first = [Set.prototype.has.call(s, 2), Map.prototype.get.call(m, 'k'), \
             s.add(3).size, m.set('j', 2).size, s.delete(1), m.delete('k')].join(' ');\n\
             s.clear(); m.clear(); first + '|' + s.size + ' ' + m.size;"
        ),
        "true 1 3 2 true true|0 0"
    );
}

#[test]
fn object_keys_values_entries_and_assign_apply_to_object() {
    let source = format!(
        "{PROBE}[\
         t(() => Object.keys(undefined)),\
         t(() => Object.values(null)),\
         t(() => Object.entries()),\
         t(() => Object.assign(undefined, {{a: 1}})),\
         t(() => Object.assign(null))\
         ].join(',');"
    );
    assert_eq!(eval(&source), ["TypeError"; 5].join(","));
    assert_eq!(
        eval(
            "Object.keys({a: 1, b: 2}).join('') + ' ' + \
             JSON.stringify(Object.assign({x: 1}, null, {y: 2})) + ' ' + \
             Object.entries({q: 3}).join();"
        ),
        "ab {\"x\":1,\"y\":2} q,3"
    );
}

#[test]
fn string_method_arguments_reject_symbols() {
    let source = format!(
        "{PROBE}[\
         t(() => 'a'.endsWith(Symbol())),\
         t(() => 'a'.startsWith(Symbol())),\
         t(() => 'a'.includes(Symbol())),\
         t(() => 'a'.indexOf(Symbol())),\
         t(() => 'a'.lastIndexOf(Symbol())),\
         t(() => 'a'.padEnd(5, Symbol())),\
         t(() => 'a'.padStart(5, Symbol()))\
         ].join(',');"
    );
    assert_eq!(eval(&source), ["TypeError"; 7].join(","));
    assert_eq!(
        eval(
            "String(Symbol('x')) + ' ' + 'ab'.padEnd(4, 'z') + ' ' + 'abc'.includes('b') + \
             ' ' + 'a1'.padStart(3, 1);"
        ),
        "Symbol(x) abzz true 1a1"
    );
}

#[test]
fn object_from_entries_iterates_its_argument() {
    // It read any object as array-like, so a Map or Set gave `{}`, a
    // generator threw, an array-like `{length: 1, 0: [...]}` (not iterable)
    // was accepted and a missing argument returned undefined.
    let source = "function t(f) { try { return JSON.stringify(f()); } catch (e) { \
                  return e instanceof TypeError ? 'TypeError' : 'other:' + e; } }\n\
                  [t(() => Object.fromEntries(new Map([['a', 1], ['b', 2]]))), \
                  t(() => Object.fromEntries([['x', 1], ['y', 2]])), \
                  t(() => Object.fromEntries((function* () { yield ['g', 7]; })())), \
                  t(() => Object.fromEntries(new Set([['s', 3]]))), \
                  t(() => Object.fromEntries()), t(() => Object.fromEntries(null)), \
                  t(() => Object.fromEntries({length: 1, 0: ['z', 1]})), \
                  t(() => Object.fromEntries([1]))].join(' | ');";
    assert_eq!(
        eval(source),
        "{\"a\":1,\"b\":2} | {\"x\":1,\"y\":2} | {\"g\":7} | {\"s\":3} | TypeError | TypeError | \
         TypeError | TypeError"
    );
}

/// bd-9vouw.108: a property read or write on null or undefined throws a
/// TypeError with Node's (V8's) message, "Cannot read properties of null
/// (reading 'x')" / "Cannot set properties of null (setting 'k')", which
/// programs log and tests match. It was the host diagnostic "type error:
/// expected object, got null". A strict write to a primitive keeps its
/// TypeError. Expected value is Node v22.2.0's for the same source (Bun
/// prints JavaScriptCore's wording). Not covered: V8's special wording for
/// `undefined[Symbol.iterator]` ("is not iterable"), "x is not a function".
#[test]
fn property_access_on_null_or_undefined_has_nodes_message_bd_9vouw_108() {
    let source = "function m(f) { try { f(); return 'no throw'; } catch (e) { return e.constructor.name + ': ' + e.message; } }\n[m(() => null.x), m(() => { var u; return u.y; }), m(() => { var o = null; o.k = 1; }), m(() => undefined[Symbol('k')]), m(() => null[0]), m(() => { var u; u.f(); }), m(() => { 'use strict'; var s = 'str'; s.p = 1; }).split(':')[0]].join(' | ');";
    assert_eq!(
        eval(source),
        "TypeError: Cannot read properties of null (reading 'x') | TypeError: Cannot read properties of undefined (reading 'y') | TypeError: Cannot set properties of null (setting 'k') | TypeError: Cannot read properties of undefined (reading 'Symbol(k)') | TypeError: Cannot read properties of null (reading '0') | TypeError: Cannot read properties of undefined (reading 'f') | TypeError"
    );
}

/// bd-9vouw.239: a String.prototype method called with a Symbol `this`
/// throws a TypeError (ToString of a Symbol, and thisStringValue for
/// toString / valueOf); slice, padEnd and trimStart returned the symbol's
/// internal name. Number and boolean receivers still convert. Node v22.2.0
/// gives this value; Bun 1.4.2 agrees.
#[test]
fn string_methods_reject_a_symbol_this_bd_9vouw_239() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\nvar s = Symbol('q'), P = String.prototype;\n[attempt(() => P.slice.call(s)), attempt(() => P.codePointAt.call(s, 0)), attempt(() => P.padEnd.call(s, 3)),\n attempt(() => P.toLowerCase.call(s)), attempt(() => P.trimStart.call(s)), attempt(() => P.valueOf.call(s)),\n attempt(() => P.toString.call(s)), attempt(() => P.includes.call(s, 'q')),\n attempt(() => P.slice.call(12345, 1, 3)), attempt(() => P.toUpperCase.call(true)), attempt(() => s.toString()),\n attempt(() => s.description)].join(' ');\n";
    assert_eq!(
        eval(source),
        "TypeError TypeError TypeError TypeError TypeError TypeError TypeError TypeError 23 TRUE Symbol(q) q"
    );
}

/// bd-9vouw.239: Symbol.prototype[@@toPrimitive] (name "[Symbol.toPrimitive]",
/// length 1, non-writable, configurable) answers the symbol of a symbol or
/// wrapper `this`, so ToString of a Symbol wrapper throws as for the symbol
/// (String(), `+ ''`, a template, join, a String.prototype method), while its
/// toString and description still work. Node v22.2.0 gives this value; Bun
/// 1.4.2 agrees.
#[test]
fn symbol_wrappers_convert_through_symbol_to_primitive_bd_9vouw_239() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\nvar w = Object(Symbol('q')), tp = Symbol.prototype[Symbol.toPrimitive];\nvar d = Object.getOwnPropertyDescriptor(Symbol.prototype, Symbol.toPrimitive);\n[typeof tp, tp.name, tp.length, d.writable, d.enumerable, d.configurable,\n attempt(() => tp.call(Symbol('a')).toString()), attempt(() => tp.call(w).description), attempt(() => tp.call({})),\n attempt(() => String(w)), attempt(() => w + ''), attempt(() => `${w}`), attempt(() => [w].join()),\n attempt(() => String.prototype.slice.call(w)), attempt(() => w.toString()), attempt(() => w.description)].join(' ');\n";
    assert_eq!(
        eval(source),
        "function [Symbol.toPrimitive] 1 false false true Symbol(a) q TypeError TypeError TypeError TypeError TypeError TypeError Symbol(q) q"
    );
}
