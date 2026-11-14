//! bd-9vouw.150: built-in brands are engine-private, not `__type`
//! properties.
//!
//! The engine marked Map, Set, Date, RegExp, WeakMap, WeakRef, Proxy records,
//! typed arrays, TextEncoder/Decoder and its Node host objects with an
//! ordinary `__type` property, so any guest object carrying one (JSON data
//! included) was taken for that built-in by its methods,
//! Object.prototype.toString, structuredClone and util.types, a forged Proxy
//! record failed inside the engine, and reflection listed `__type` on real
//! built-ins. Expected strings are Node v22.2.0's output for the same
//! programs.
//!
//! Map, Set, Date, RegExp, WeakRef and FinalizationRegistry also store their
//! state in private heap slots. WeakSet uses private weak entries.
//! The collection regressions cover reflection, guest properties with the
//! former storage names, integrity levels, constructors, cloning and GC.
//! Weak-object regressions prevent guest access to the former `__values`,
//! `__target` and `__tokens` slots and cover integrity levels and receiver brands.

use frankenengine_engine::{
    HybridRouter, JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine,
};

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

fn assert_profile_value(source: &str, expected: &str) {
    for (profile, result) in [
        ("baseline", QuickJsInspiredNativeEngine.eval(source)),
        ("throughput", V8InspiredNativeEngine.eval(source)),
    ] {
        let result = result.unwrap_or_else(|error| panic!("{profile}: {error}\n{source}"));
        assert_eq!(result.value, expected, "{profile}\n{source}");
    }
}

/// The former backing keys are ordinary guest property names. Neither data
/// properties nor accessors with those names may replace [[MapData]] or
/// [[SetData]]. Expected outputs are checked against Node v24.22.1.
#[test]
fn collection_storage_is_private_across_guest_property_operations() {
    assert_profile_value(
        r#"var m = new Map([['a', 1]]), s = new Set(['x']);
var out = [Reflect.ownKeys(m).length, Object.getOwnPropertyNames(s).length,
           '__entries' in m, '__values' in s, '__size' in m,
           String(m.__entries), String(s.__values), String(m.__size)];
m.__entries = {a: 'tampered'}; m.__size = 700;
s.__values = {}; s.__size = 800;
out.push(m.get('a'), m.size, s.has('x'), s.size, m.__entries.a, m.__size, s.__size,
         Reflect.ownKeys(m).join(','), Reflect.ownKeys(s).join(','));
for (var pair of [[m, '__entries'], [m, '__size'], [s, '__values'], [s, '__size']]) {
    Object.defineProperty(pair[0], pair[1], {
        get() { throw 'guest storage read'; },
        set(v) { throw 'guest storage write'; }, configurable: true
    });
}
out.push(m.set('b', 2) === m, s.add('y') === s, m.size, s.size,
         m.get('b'), s.has('y'), m.delete('a'), s.delete('x'));
out.push(Array.from(m).join(':'), Array.from(s).join(':'), m.size, s.size);
m.clear(); s.clear();
out.push(m.size, s.size, delete m.__entries, delete m.__size,
         delete s.__values, delete s.__size,
         Reflect.ownKeys(m).length, Reflect.ownKeys(s).length);
out.join('|');"#,
        "0|0|false|false|false|undefined|undefined|undefined|1|1|true|1|tampered|700|800|__entries,__size|__values,__size|true|true|2|2|2|true|true|true|b,2|y|1|1|0|0|true|true|true|true|0|0",
    );
}

#[test]
fn collection_contents_remain_mutable_under_object_integrity_levels() {
    assert_profile_value(
        r#"var out = [];
for (var transform of [Object.freeze, Object.seal, Object.preventExtensions]) {
    var m = transform(new Map([['a', 1]])), s = transform(new Set([1]));
    out.push(m.set('b', 2) === m, m.get('b'), m.size,
             s.add(2) === s, s.has(2), s.size,
             m.delete('a'), s.delete(1), m.size, s.size);
    m.clear(); s.clear();
    out.push(m.size, s.size, Reflect.ownKeys(m).length, Reflect.ownKeys(s).length);
}
out.join('|');"#,
        "true|2|2|true|true|2|true|true|1|1|0|0|0|0|true|2|2|true|true|2|true|true|1|1|0|0|0|0|true|2|2|true|true|2|true|true|1|1|0|0|0|0",
    );
}

#[test]
fn subclass_and_reflect_construction_install_private_collection_storage() {
    assert_profile_value(
        r#"class M extends Map { get count() { return this.size; } }
class S extends Set { get count() { return this.size; } }
Object.defineProperty(M.prototype, '__entries', {
    get() { throw 'prototype entries read'; }, set(v) { throw 'prototype entries write'; }
});
Object.defineProperty(S.prototype, '__values', {
    get() { throw 'prototype values read'; }, set(v) { throw 'prototype values write'; }
});
var m = new M([['a', 1]]), s = new S([2]);
var rm = Reflect.construct(Map, [[['b', 3]]], M);
var rs = Reflect.construct(Set, [[4]], S);
function attempt(f) { try { return f(); } catch (e) { return e.name; } }
[m instanceof M, s instanceof S, rm instanceof M, rs instanceof S,
 m.count, s.count, rm.get('b'), rs.has(4),
 Reflect.ownKeys(m).length, Reflect.ownKeys(s).length,
 Reflect.ownKeys(rm).length, Reflect.ownKeys(rs).length,
 attempt(() => Map.prototype.get.call(Object.create(m), 'a')),
 attempt(() => Set.prototype.has.call(new Proxy(s, {}), 2))].join('|');"#,
        "true|true|true|true|1|1|3|true|0|0|0|0|TypeError|TypeError",
    );
}

#[test]
fn structured_clone_copies_private_collection_graphs_without_guest_slot_reads() {
    assert_profile_value(
        r#"var key = {id: 7}, value = {n: 11};
var m = new Map([[key, value]]), s = new Set([key, m]);
m.set('self', m);
for (var pair of [[m, '__entries'], [m, '__size'], [s, '__values'], [s, '__size']]) {
    Object.defineProperty(pair[0], pair[1], {
        get() { throw 'clone read guest slot'; }, enumerable: true
    });
}
var copy = structuredClone({key, value, m, s});
var iter = copy.m.keys();
[copy.key !== key, copy.value !== value, copy.m !== m, copy.s !== s,
 copy.m.get(copy.key) === copy.value, copy.m.get('self') === copy.m,
 copy.s.has(copy.key), copy.s.has(copy.m), iter.next().value === copy.key,
 iter.next().value, iter.next().done, copy.m.size, copy.s.size,
 Reflect.ownKeys(copy.m).length, Reflect.ownKeys(copy.s).length].join('|');"#,
        "true|true|true|true|true|true|true|true|true|self|true|2|2|0|0",
    );
}

#[test]
fn collection_iterators_keep_live_storage_after_guest_slots_are_replaced() {
    assert_profile_value(
        r#"var m = new Map([['a', 1], ['b', 2]]), s = new Set([1, 2]);
var mi = m.entries(), si = s.values();
var out = [mi.next().value.join(':'), si.next().value];
m.__entries = {}; s.__values = {}; m.__size = 50; s.__size = 60;
m.delete('b'); s.delete(2); m.set('c', 3); s.add(3);
out.push(mi.next().value.join(':'), si.next().value);
var seen = [];
m.forEach((value, key) => { seen.push(key + value); if (key === 'a') m.set('d', 4); });
s.forEach(value => { seen.push(value); if (value === 1) s.add(4); });
out.push(seen.join(','), mi.next().value.join(':'), si.next().value,
         mi.next().done, si.next().done, m.size, s.size);
out.join('|');"#,
        "a:1|1|c:3|3|a1,c3,d4,1,3,4|d:4|4|true|true|3|3",
    );
}

#[test]
fn weak_collection_storage_is_private_across_guest_property_operations() {
    assert_profile_value(
        r#"var key = {}, other = {}, token = {};
var set = new WeakSet([key]), registry = new FinalizationRegistry(() => {});
registry.register(key, 'held', token);
var out = [Reflect.ownKeys(set).length, Reflect.ownKeys(registry).length,
           '__values' in set, '__tokens' in registry,
           String(set.__values), String(registry.__tokens)];
set.__values = {}; registry.__tokens = {};
out.push(set.has(key), registry.unregister(token), registry.unregister(token),
         Reflect.ownKeys(set).join(), Reflect.ownKeys(registry).join());
for (var pair of [[set, '__values'], [registry, '__tokens']]) {
    Object.defineProperty(pair[0], pair[1], {
        get() { throw 'guest slot read'; }, set(v) { throw 'guest slot write'; },
        configurable: true
    });
}
out.push(set.add(other) === set, set.has(other), set.delete(key), set.has(key));
registry.register(other, 7, token);
out.push(registry.unregister(token), delete set.__values, delete registry.__tokens,
         Reflect.ownKeys(set).length, Reflect.ownKeys(registry).length);
out.join('|');"#,
        "0|0|false|false|undefined|undefined|true|true|false|__values|__tokens|true|true|true|false|true|true|true|0|0",
    );
}

#[test]
fn weak_collections_ignore_inherited_slot_accessors_and_integrity_levels() {
    assert_profile_value(
        r#"class W extends WeakSet {}
class F extends FinalizationRegistry {}
Object.defineProperty(W.prototype, '__values', {
    get() { throw 'inherited values read'; }, set(v) { throw 'inherited values write'; }
});
Object.defineProperty(F.prototype, '__tokens', {
    get() { throw 'inherited tokens read'; }, set(v) { throw 'inherited tokens write'; }
});
var out = [];
for (var transform of [Object.freeze, Object.seal, Object.preventExtensions]) {
    var first = {}, second = {}, token = {};
    var set = transform(new W([first])), registry = transform(new F(() => {}));
    registry.register(first, 'held', token);
    registry.register(second, 'also held', token);
    out.push(set instanceof W, registry instanceof F, set.has(first),
             set.add(second) === set, set.delete(first), set.has(second),
             registry.unregister(token), registry.unregister(token),
             Reflect.ownKeys(set).length, Reflect.ownKeys(registry).length);
}
function attempt(f) { try { return f(); } catch (e) { return e.name; } }
out.push(attempt(() => WeakSet.prototype.has.call({__values: {}}, {})),
         attempt(() => FinalizationRegistry.prototype.unregister.call({__tokens: {}}, {})),
         attempt(() => WeakSet.prototype.has.call(new Proxy(new W(), {}), {})));
out.join('|');"#,
        "true|true|true|true|true|true|true|false|0|0|true|true|true|true|true|true|true|false|0|0|true|true|true|true|true|true|true|false|0|0|TypeError|TypeError|TypeError",
    );
}

#[test]
fn weak_ref_target_is_private_and_survives_guest_slot_mutations() {
    assert_profile_value(
        r#"var target = {n: 7}, other = {n: 99}, ref = new WeakRef(target);
var out = [Reflect.ownKeys(ref).length, '__target' in ref,
           String(ref.__target), ref.deref() === target];
ref.__target = other;
out.push(ref.deref().n, ref.__target === other, Reflect.ownKeys(ref).join());
Object.defineProperty(ref, '__target', {
    get() { throw 'guest target read'; }, set(v) { throw 'guest target write'; },
    configurable: true
});
out.push(ref.deref() === target, delete ref.__target, ref.deref() === target,
         Reflect.ownKeys(ref).length);
for (var transform of [Object.freeze, Object.seal, Object.preventExtensions]) {
    out.push(transform(new WeakRef(target)).deref() === target);
}
class W extends WeakRef {}
Object.defineProperty(W.prototype, '__target', {
    get() { throw 'inherited target read'; }, set(v) { throw 'inherited target write'; }
});
var derived = Reflect.construct(WeakRef, [target], W);
out.push(derived instanceof W, derived.deref() === target, Reflect.ownKeys(derived).length);
function attempt(f) { try { return f(); } catch (e) { return e.name; } }
out.push(attempt(() => WeakRef.prototype.deref.call({__target: target})),
         attempt(() => WeakRef.prototype.deref.call(new Proxy(ref, {}))));
out.join('|');"#,
        "0|false|undefined|true|7|true|__target|true|true|true|0|true|true|true|true|true|0|TypeError|TypeError",
    );
}

/// Keys, values and closures are reachable only through the private storage
/// edge after build() returns. Collecting at every safe point must retain
/// those edges without retaining short-lived garbage or drifting accounting.
#[test]
fn private_collection_storage_is_traced_and_accounted_under_gc_stress() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = r#"function build() {
    const key = {id: 7}, value = {n: 11}, captured = {n: 13};
    const m = new Map([[key, value]]), s = new Set([key, value]);
    m.set('closure', () => captured.n);
    m.set('self', m);
    return [m, s];
}
var pair = build(), m = pair[0], s = pair[1];
m.__entries = {}; s.__values = {};
for (let i = 0; i < 40; i++) { const garbage = {i}; }
var first = m.entries().next().value;
[first[0].id, first[1].n, m.get('closure')(), m.get('self') === m,
 s.has(first[0]), s.has(first[1]), m.size, s.size].join('|');"#;
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "private-collection-gc.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("collection program parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "private-collection-gc.js"),
        &LoweringContext::new("collection-gc", "collection-decision", "collection-policy"),
    )
    .expect("collection program lowers")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "collection-gc");
        core.set_gc_stress_interval(Some(1));
        let result = core.execute(&module).expect("private storage survives GC");
        assert_eq!(result.value, Value::str("7|11|13|true|true|true|3|2"));
        let stats = core.gc_stats();
        assert!(stats.collections > 0, "forced collection must actually run");
        assert!(stats.reclaimed_objects > 0, "garbage must be reclaimable");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "private storage must have exact incremental memory accounting"
        );
    }
}

/// [[DateValue]] is absent from reflection and cannot be intercepted or
/// corrupted by an ordinary property with the former storage key. Expected
/// outputs of these Date tests were captured from Node v24.22.1.
#[test]
fn date_value_is_private_across_guest_property_operations() {
    assert_profile_value(
        r#"var d = new Date(5);
var out = [Reflect.ownKeys(d).length, Object.getOwnPropertyNames(d).length,
           d.hasOwnProperty('__timestamp'), '__timestamp' in d, String(d.__timestamp)];
d.__timestamp = 99;
out.push(d.getTime(), d.__timestamp, Reflect.ownKeys(d).join());
Object.defineProperty(d, '__timestamp', {
    get() { throw 'guest read'; }, set(v) { throw 'guest write'; }, configurable: true
});
out.push(d.getTime(), d.setTime(8), d.getTime());
out.push(delete d.__timestamp, Reflect.ownKeys(d).length);
out.join('|');"#,
        "0|0|false|false|undefined|5|99|__timestamp|5|8|8|true|0",
    );
}

#[test]
fn date_constructor_and_structured_clone_copy_private_value() {
    assert_profile_value(
        r#"var d = new Date(86400007);
Object.defineProperty(d, '__timestamp', {
    get() { throw 'private slot read'; }, set(v) { throw 'private slot write'; }
});
d.valueOf = function () { throw 'copy invoked valueOf'; };
Object.defineProperty(d, Symbol.toPrimitive, {
    value: function () { throw 'copy invoked conversion'; }
});
var copy = new Date(d);
var clone = structuredClone(d);
var invalid = structuredClone(new Date(NaN));
[copy.getTime(), clone.getTime(), Object.getOwnPropertyNames(clone).length,
 clone instanceof Date, copy.toISOString(), clone.getUTCDate(),
 Number.isNaN(invalid.getTime()), invalid.toString(),
 new Date(-0).getTime() === 0, 1 / new Date(-0).getTime()].join('|');"#,
        "86400007|86400007|0|true|1970-01-02T00:00:00.007Z|2|true|Invalid Date|true|Infinity",
    );
}

#[test]
fn date_private_value_remains_mutable_under_object_integrity_levels() {
    assert_profile_value(
        r#"var out = [];
for (var transform of [Object.freeze, Object.seal, Object.preventExtensions]) {
    var d = new Date(0);
    transform(d);
    out.push(d.setTime(7), d.getTime(), d.setUTCFullYear(2000),
             d.toISOString(), Reflect.ownKeys(d).length);
}
var invalid = Object.freeze(new Date(NaN));
out.push(invalid.setTime(0), invalid.toISOString());
out.join('|');"#,
        "7|7|946684800007|2000-01-01T00:00:00.007Z|0|7|7|946684800007|2000-01-01T00:00:00.007Z|0|7|7|946684800007|2000-01-01T00:00:00.007Z|0|0|1970-01-01T00:00:00.000Z",
    );
}

#[test]
fn intl_date_format_converts_objects_instead_of_reading_guest_storage_keys() {
    assert_profile_value(
        r#"var calls = [];
var format = new Intl.DateTimeFormat('en-US', {
    timeZone: 'UTC', year: 'numeric', month: '2-digit', day: '2-digit'
});
var date = new Date(0);
Object.defineProperty(date, '__timestamp', {get() { throw 'guest timestamp'; }});
date.valueOf = function () { calls.push('date'); return 172800000; };
var first = format.format(date);
var fake = {__timestamp: 0, valueOf() { calls.push('object'); return 259200000; }};
var second = format.format(fake);
Object.defineProperty(date, Symbol.toPrimitive, {
    value: function(hint) { calls.push(hint); return 345600000; }
});
var third = format.format(date);
[first, second, third, calls.join(',')].join('|');"#,
        "01/03/1970|01/04/1970|01/05/1970|date,object,number",
    );
}

#[test]
fn date_inspection_and_conversion_use_the_private_value_and_exact_receiver() {
    assert_profile_value(
        r#"var util = require('util');
function attempt(f) { try { return f(); } catch (e) { return e.name; } }
var d = new Date(5);
d.__timestamp = 99;
var found = util.inspect(d).includes('1970-01-01T00:00:00.005Z');
var guestProperty = util.inspect(d).includes('__timestamp: 99');
delete d.__timestamp;
var inspected = util.inspect(d);
[util.types.isDate(d), found, guestProperty, inspected, JSON.stringify(d), +d,
 attempt(() => Date.prototype.getTime.call(Object.create(d))),
 attempt(() => Date.prototype.getTime.call(new Proxy(d, {}))),
 attempt(() => Date.prototype.getTime.call({__timestamp: 1})),
 attempt(() => Date.prototype.getTime.call(Date.prototype))].join('|');"#,
        "true|true|true|1970-01-01T00:00:00.005Z|\"1970-01-01T00:00:00.005Z\"|5|TypeError|TypeError|TypeError|TypeError",
    );
}

/// A guest object with a `__type` property is not a Date, Map or Set to their methods or to Object.prototype.toString.
#[test]
fn brand_forged_date_map_set() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var date = JSON.parse('{\"__type\":\"Date\",\"__timestamp\":7}');\n\
         var map = { __type: 'Map', __entries: [], __size: 0 };\n\
         [attempt(() => Date.prototype.getTime.call(date)), Object.prototype.toString.call(date), attempt(() => String(Object.assign({}, date)) === String(date)),\n\
          attempt(() => Map.prototype.get.call(map, 1)), Object.prototype.toString.call(map), attempt(() => Set.prototype.has.call({ __type: 'Set', __values: {} }, 1)),\n\
          attempt(() => WeakMap.prototype.has.call({ __type: 'WeakMap' }, {})), attempt(() => WeakRef.prototype.deref.call({ __type: 'WeakRef', __target: {} }))].join(' ');";
    assert_eq!(
        eval(source),
        "TypeError [object Object] true TypeError [object Object] TypeError TypeError TypeError"
    );
}

/// Nor a RegExp, a Number or a String wrapper, and typeof of a guest object is never 'symbol'.
#[test]
fn brand_forged_regexp_and_wrappers() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var regexp = { __type: 'RegExp', source: 'zz', flags: 'g', lastIndex: 0 };\n\
         [attempt(() => RegExp.prototype.exec.call(regexp, 'zz')), String(new RegExp(regexp)), attempt(() => Number.prototype.toFixed.call({ __type: 'Number', __value: 5 }, 2)),\n\
          attempt(() => typeof Object.prototype.valueOf.call({ __type: 'String', __value: 'x' })), typeof Object.assign(Object.create(null), { __type: 'symbol' }),\n\
          attempt(() => new Number(1.25).toFixed(1)), attempt(() => typeof Object.prototype.valueOf.call(new String('s')))].join(' ');";
    assert_eq!(
        eval(source),
        "TypeError /[object Object]/ TypeError object object 1.3 object"
    );
}

/// A guest object shaped like the engine's Proxy record is an ordinary object (it was taken for a Proxy and failed inside the engine).
#[test]
fn brand_forged_proxy_record() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var fake = { __type: 'Proxy', __proxy_target: {}, __proxy_handler: { get: function () { return 'trapped'; } }, __proxy_revoked: false };\n\
         [attempt(() => fake.x), attempt(() => 'y' in fake), attempt(() => Object.keys(fake).length), attempt(() => new Proxy({}, { get: function () { return 'real'; } }).x)].join(' ');";
    assert_eq!(eval(source), "undefined false 4 real");
}

/// structuredClone copies a guest `__type` object as plain data, and util.types sees only real built-ins.
#[test]
fn brand_structured_clone_and_util_types() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var u = require('util');\n\
         [JSON.stringify(structuredClone({ __type: 'Date', __timestamp: 0 })), structuredClone({ __type: 'Set', __values: {} }) instanceof Set,\n\
          u.types.isDate({ __type: 'Date', __timestamp: 1 }), u.types.isMap({ __type: 'Map', __entries: {} }), u.types.isRegExp({ __type: 'RegExp', source: 'a', flags: '' }),\n\
          u.types.isDate(new Date(1)), u.types.isMap(new Map()), structuredClone(new Date(5)).getTime(), structuredClone(new Set([1, 2])).size].join(' ');";
    assert_eq!(
        eval(source),
        "{\"__type\":\"Date\",\"__timestamp\":0} false false false false true true 5 2"
    );
}

/// The brand is not an own property of built-in objects, and a guest `__type` write neither changes nor breaks one.
#[test]
fn brand_brand_is_not_a_property() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var r = /a/g; r.__type = 'Object'; var m = new Map([[1, 2]]); m.__type = 'Set'; var d = new Date(5); d.__type = 'Map';\n\
         [Reflect.ownKeys(new WeakMap()).length, '__type' in new Map(), new Set().hasOwnProperty('__type'), String(new Date(0).__type),\n\
          Object.getOwnPropertyNames(/a/).indexOf('__type'), Reflect.ownKeys(new TextEncoder()).indexOf('__type'),\n\
          r.test('a'), Object.prototype.toString.call(r), m.get(1), Object.prototype.toString.call(m), d.getTime(), r.__type, delete m.__type, m.size].join(' ');";
    assert_eq!(
        eval(source),
        "0 false false undefined -1 -1 true [object RegExp] 2 [object Map] 5 Object true 1"
    );
}

/// bd-9vouw.234: a DataView inherits from DataView.prototype (instanceof,
/// constructor, added members, @@toStringTag), a Symbol wrapper's valueOf is
/// Symbol.prototype.valueOf (the symbol, as is-symbol checks), and an
/// arguments object's builtinTag is Arguments (is-arguments), strict or not.
/// Node v22.2.0 gives this value; Bun 1.4.2 agrees.
#[test]
fn data_view_symbol_wrapper_and_arguments_brands() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\nvar ts = Object.prototype.toString;\nvar dv = new DataView(new ArrayBuffer(2));\nDataView.prototype.extra = function () { return 'x' + this.byteLength; };\nvar sym = Symbol('q');\nvar boxed = Object(sym);\nvar args = (function () { return arguments; })(1, 'b');\nvar strictArgs = (function () { 'use strict'; return arguments; })();\n[dv instanceof DataView, Object.getPrototypeOf(dv) === DataView.prototype, dv.constructor === DataView, dv.extra(), ts.call(dv), dv[Symbol.toStringTag],\n typeof boxed.valueOf(), boxed.valueOf() === sym, Symbol.prototype.valueOf.call(boxed) === sym, Symbol.prototype.hasOwnProperty('valueOf'),\n Symbol.prototype.valueOf.name + Symbol.prototype.valueOf.length, attempt(() => Symbol.prototype.valueOf.call({})), sym.valueOf() === sym,\n ts.call(args), ts.call(strictArgs), JSON.stringify(args), args.length, Array.prototype.slice.call(args).join('-')].join(' ');\n";
    assert_eq!(
        eval(source),
        "true true true x2 [object DataView] DataView symbol true true true valueOf0 TypeError true [object Arguments] [object Arguments] {\"0\":1,\"1\":\"b\"} 2 1-b"
    );
}

/// bd-9vouw.150 phase 2 (RegExp): a RegExp's pattern and flags are
/// engine-private slots. They were the own properties `source` and `flags`:
/// reflection listed them (Node: only `lastIndex`), a guest assignment
/// rewrote the pattern (`r.source = 'x'` made `/a/g` test as `/x/y`), and
/// `flags` read that property, so an own `global` getter or a
/// RegExp.prototype flag getter override did not show. `flags` is now the
/// generic getter for every receiver, and RegExp.prototype.toString reads
/// `source` and `flags` through [[Get]] on any object. Expected lines are
/// Node v22.2.0's output, captured programmatically.
#[test]
fn regexp_source_and_flags_are_internal_slots_bd_9vouw_150() {
    let source = r#"var r = /a/g;
console.log(Object.getOwnPropertyNames(r).join(), r.hasOwnProperty('source'), r.hasOwnProperty('flags'), Reflect.ownKeys(r).join(), 'source' in r);
r.source = 'x';
r.flags = 'y';
console.log(r.source, r.flags, r.test('ba'), String(r), r.lastIndex);
Object.defineProperty(r, 'source', { value: 'own', configurable: true });
console.log(r.source, String(r), r.test('ba'), Object.getOwnPropertyNames(r).join());
var q = /b/i;
Object.defineProperty(q, 'global', { get() { return true; } });
console.log(q.flags, q.global, /c/.flags, /c/dgimsuy.flags, String(q));
console.log(structuredClone(/e\/f/gi).source, structuredClone(/e/gi).flags, new RegExp(/x/y).flags, new RegExp(/x/y, 'g').flags, JSON.stringify(/z/), Object.keys(/z/g).length);
var saved = Object.getOwnPropertyDescriptor(RegExp.prototype, 'sticky');
Object.defineProperty(RegExp.prototype, 'sticky', { get() { return true; }, configurable: true });
console.log(/d/m.flags, String(/d/m), RegExp.prototype.toString.call({ source: 's', flags: 'f' }));
Object.defineProperty(RegExp.prototype, 'sticky', saved);
console.log(/d/m.flags, /d/y.sticky, String(/d/m));"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            r#"lastIndex false false lastIndex true"#,
            r#"a g true /a/g 2"#,
            r#"own /own/g false lastIndex,source"#,
            r#"gi true  dgimsuy /b/gi"#,
            r#"e\/f gi y g {} 0"#,
            r#"my /d/my /s/f"#,
            r#"m true /d/m"#,
        ]
    );
}

#[test]
fn weakset_membership_is_private_under_guest_writes_and_integrity_levels() {
    assert_profile_value(
        r#"var first = {}, second = {}, third = {};
var set = new WeakSet([first]);
var out = [Reflect.ownKeys(set).length, '__values' in set, String(set.__values)];
set.__values = {};
out.push(set.has(first));
Object.defineProperty(set, '__values', {
    get() { throw 'guest storage read'; },
    set(v) { throw 'guest storage write'; }, configurable: true
});
out.push(set.add(second) === set, set.has(second), set.delete(first), set.has(first));
delete set.__values;
Object.freeze(set);
out.push(set.add(third) === set, set.has(third), set.delete(second),
         Reflect.ownKeys(set).length, Object.isFrozen(set));
out.join('|');"#,
        "0|false|undefined|true|true|true|true|false|true|true|true|0|true",
    );
}

#[test]
fn weakset_keys_use_carrier_identity_without_sharing_weakmap_brands() {
    assert_profile_value(
        r#"function f() {}
var p = Promise.resolve(1), iterator = [1, 2].values(), proxy = new Proxy({}, {});
var set = new WeakSet([f, p, iterator, proxy, Object.keys]);
var out = [set.has(f), set.has(p), set.has(iterator), set.has(proxy), set.has(Object.keys),
           set.has(function() {}), set.has({}), set.delete(p), set.has(p)];
out.push(set.add(p) === set, set.has(p));
function attempt(fn) { try { return fn(); } catch (e) { return e.name; } }
out.push(attempt(() => WeakMap.prototype.has.call(set, f)),
         attempt(() => WeakSet.prototype.has.call(new WeakMap(), f)),
         attempt(() => WeakSet.prototype.has.call(Object.create(set), f)),
         attempt(() => WeakSet.prototype.has.call(new Proxy(set, {}), f)),
         attempt(() => WeakSet.prototype.add.call({__values: {}}, f)),
         attempt(() => set.add(1)), set.has(1), set.delete(1));
out.join('|');"#,
        "true|true|true|true|true|false|false|true|false|true|true|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|false|false",
    );
}

#[test]
fn weakset_constructor_closes_bad_iterators_without_rolling_back_guest_effects() {
    assert_profile_value(
        r#"var key = {}, observed = [], saved, retained;
var nativeAdd = WeakSet.prototype.add;
WeakSet.prototype.add = function(value) {
    saved = this;
    observed.push('add');
    return nativeAdd.call(this, value);
};
var iterable = {
    [Symbol.iterator]() {
        var step = 0;
        return {
            next() {
                retained = { step: step };
                return { value: step++ === 0 ? key : 1, done: false };
            },
            return() { observed.push('close'); return {}; }
        };
    }
};
try { new WeakSet(iterable); } catch (e) { observed.push(e.name); }
WeakSet.prototype.add = nativeAdd;
[observed.join(','), saved.has(key), retained.step,
 Reflect.ownKeys(saved).length].join('|');"#,
        "add,add,close,TypeError|true|1|0",
    );
}
