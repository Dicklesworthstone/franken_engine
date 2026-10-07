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
//! No-claim: the other internal slots (`__entries`, `__values`, `__size`,
//! `__timestamp`, `__target`, ...) are still non-enumerable own properties of
//! the real objects; reflection lists them and guest writes reach them.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
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
