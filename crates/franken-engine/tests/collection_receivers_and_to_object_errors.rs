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
