//! bd-9vouw.34: every object's [[Prototype]] chain reaches `Object.prototype`.
//!
//! Before this, ordinary objects and arrays carried no prototype link, so
//! `({}) instanceof Object` and `[] instanceof Object` were false,
//! `Object.getPrototypeOf({})` was null, methods added to `Array.prototype` or
//! `Object.prototype` were invisible, and functions were not
//! `instanceof Function`. An unset link now means the realm's
//! `Array.prototype` / `Object.prototype`, and an explicit null
//! (`Object.create(null)`, `setPrototypeOf(o, null)`, `__proto__: null`) still
//! ends the chain. Expected strings are what Node v22.2.0 prints for
//! `String(eval(source))`.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn every_object_kind_is_instanceof_object() {
    check(
        "[{} instanceof Object, [] instanceof Object, (function () {}) instanceof Object, \
         (() => 1) instanceof Function, new Map() instanceof Object, \
         new Error('x') instanceof Object, Promise.resolve(1) instanceof Object, \
         new Set() instanceof Object].join()",
        "true,true,true,true,true,true,true,true",
    );
    check(
        "class A {} class B extends A {} [new A() instanceof Object, new B() instanceof Object, \
         B instanceof Function, B instanceof Object, \
         Object.getPrototypeOf(A.prototype) === Object.prototype].join()",
        "true,true,true,true,true",
    );
}

#[test]
fn get_prototype_of_reports_the_default_intrinsics() {
    check(
        "[Object.getPrototypeOf({}) === Object.prototype, \
         Object.getPrototypeOf([]) === Array.prototype, \
         Object.getPrototypeOf(Array.prototype) === Object.prototype, \
         Object.getPrototypeOf(Object.prototype), \
         ({}).__proto__ === Object.prototype].join()",
        "true,true,true,,true",
    );
}

#[test]
fn builtin_prototypes_chain_to_object_prototype() {
    check(
        "[Object.getPrototypeOf(Array.prototype) === Object.prototype, \
         Object.getPrototypeOf(String.prototype) === Object.prototype, \
         Object.getPrototypeOf(Number.prototype) === Object.prototype, \
         Object.getPrototypeOf(Boolean.prototype) === Object.prototype, \
         Object.getPrototypeOf(Error.prototype) === Object.prototype, \
         Object.getPrototypeOf(Map.prototype) === Object.prototype, \
         Object.getPrototypeOf(Set.prototype) === Object.prototype, \
         Object.getPrototypeOf(Function.prototype) === Object.prototype, \
         Object.getPrototypeOf(TypeError.prototype) === Error.prototype].join()",
        "true,true,true,true,true,true,true,true,true",
    );
}

#[test]
fn explicit_null_prototypes_end_the_chain() {
    check(
        "var n = Object.create(null); var o = {}; Object.setPrototypeOf(o, null); \
         [Object.getPrototypeOf(n), n instanceof Object, o instanceof Object, \
         Object.getPrototypeOf(o), ({ __proto__: null }) instanceof Object].join()",
        ",false,false,,false",
    );
}

#[test]
fn methods_added_to_builtin_prototypes_are_inherited() {
    check(
        "Array.prototype.sumAll = function () { var t = 0; \
         for (var i = 0; i < this.length; i++) t += this[i]; return t; }; \
         Object.prototype.tag = 'T'; class K {} \
         [[1, 2, 3].sumAll(), ({}).tag, [].tag, new K().tag, \
         typeof Object.create(null).tag].join()",
        "6,T,T,T,undefined",
    );
    // for-in visits inherited enumerable properties; delete removes them.
    check(
        "Object.prototype.inherited = 1; var keys = []; for (var k in { own: 2 }) keys.push(k); \
         delete Object.prototype.inherited; keys.join() + '|' + ('inherited' in {})",
        "own,inherited|false",
    );
}

#[test]
fn constructor_and_in_see_the_builtin_methods() {
    check(
        "[({}).constructor === Object, [].constructor === Array, 'hasOwnProperty' in {}, \
         'push' in [], 'toString' in Object.create(null), ({}).hasOwnProperty('x')].join()",
        "true,true,true,true,false,false",
    );
}

#[test]
fn is_prototype_of_walks_objects_and_functions() {
    check(
        "class P {} class Q extends P {} [Object.prototype.isPrototypeOf([]), \
         Array.prototype.isPrototypeOf([]), Array.prototype.isPrototypeOf({}), \
         P.prototype.isPrototypeOf(new Q()), P.isPrototypeOf(Q), \
         Object.prototype.isPrototypeOf(1), Function.prototype.isPrototypeOf(P)].join()",
        "true,true,false,true,true,false,true",
    );
}

#[test]
fn date_promise_and_regexp_have_intrinsic_prototypes() {
    // Before this, `x instanceof Date` / `x instanceof Promise` threw
    // "expected function, got function" and `RegExp` was not a value.
    check(
        "[new Date(0) instanceof Date, new Date(0) instanceof Object, \
         Promise.resolve(1) instanceof Promise, /x/ instanceof RegExp, \
         new RegExp('a') instanceof RegExp, typeof RegExp, RegExp('a', 'g').flags, \
         /x/ instanceof Object].join()",
        "true,true,true,true,true,function,g,true",
    );
    check(
        "[Object.getPrototypeOf(new Date(0)) === Date.prototype, \
         Object.getPrototypeOf(Date.prototype) === Object.prototype, \
         Object.getPrototypeOf(Promise.resolve(1)) === Promise.prototype, \
         Object.getPrototypeOf(Promise.prototype) === Object.prototype, \
         Object.getPrototypeOf(/x/) === RegExp.prototype, \
         Object.getPrototypeOf(RegExp.prototype) === Object.prototype].join()",
        "true,true,true,true,true,true",
    );
    check(
        "[typeof Date.prototype.getTime, Date.prototype.getTime.call(new Date(5)), \
         RegExp.prototype.test.call(/a/, 'cat'), typeof Promise.prototype.then].join()",
        "function,5,true,function",
    );
    check(
        "Date.prototype.addDays = function (n) { return new Date(this.getTime() + n * 864e5); }; \
         RegExp.prototype.twice = function (s) { return this.test(s) && this.test(s); }; \
         [new Date(0).addDays(1).getTime(), /a/.twice('a')].join()",
        "86400000,true",
    );
}

#[test]
fn literals_initialize_past_inherited_read_only_properties_and_setters() {
    // Array and object literals define their own properties
    // (CreateDataProperty): an inherited read-only index, getter-only
    // accessor or setter on the default prototypes must neither reject nor
    // observe literal construction (Test262 11.1.4_5-6-1,
    // Array/prototype/map/15.4.4.19-8-c-i-6).
    check(
        "Object.defineProperty(Array.prototype, '1', {value: 100, writable: false, \
         configurable: true}); var arr = [101, 12]; \
         var r = arr.hasOwnProperty('1') + ',' + arr[1]; delete Array.prototype[1]; r",
        "true,12",
    );
    check(
        "var calls = 0; Object.defineProperty(Object.prototype, 'x', {set: function (v) { \
         calls++; }, configurable: true}); var o = {x: 1}; \
         var r = calls + ',' + o.hasOwnProperty('x') + ',' + o.x; delete Object.prototype.x; r",
        "0,true,1",
    );
    check(
        "Object.defineProperty(Array.prototype, '0', {get: function () { return 9; }, \
         configurable: true}); var t = ['abc'].map(function (v) { return v === 'abc'; }); \
         var r = t[0]; delete Array.prototype[0]; r",
        "true",
    );
}

#[test]
fn ordinary_writes_honor_read_only_implicit_prototype_properties_bd_9vouw_280() {
    check(
        r#"
        Object.defineProperty(Object.prototype, 'locked', {
            value: 1001, writable: false, configurable: true
        });
        var object = {};
        object.locked = 2;
        JSON.locked = 3;
        Math.locked = 4;
        var strictError = '';
        try { (function () { 'use strict'; object.locked = 5; })(); }
        catch (error) { strictError = error.name; }
        var result = [object.locked, JSON.locked, Math.locked,
            object.hasOwnProperty('locked'), JSON.hasOwnProperty('locked'),
            Reflect.set(object, 'locked', 6), strictError].join(',');
        delete Object.prototype.locked;
        result;
        "#,
        "1001,1001,1001,false,false,false,TypeError",
    );
}

#[test]
fn inherited_setters_keep_the_receiver_and_literal_definitions_bypass_them_bd_9vouw_280() {
    check(
        r#"
        var calls = 0;
        var receiver;
        var seen;
        Object.defineProperty(Object.prototype, 'slot', {
            set(value) { calls++; receiver = this; seen = value; }, configurable: true
        });
        var object = {};
        object.slot = 7;
        var first = calls === 1 && receiver === object && seen === 7;
        var explicitReceiver = {};
        var reflected = Reflect.set(object, 'slot', 8, explicitReceiver);
        var second = calls === 2 && receiver === explicitReceiver && seen === 8;
        function make() { return { slot: 11, get extra() { return 12; } }; }
        var literal = make();
        var result = [first, second, reflected, object.hasOwnProperty('slot'),
            explicitReceiver.hasOwnProperty('slot'), calls, literal.slot,
            literal.hasOwnProperty('slot'), literal.extra].join(',');
        delete Object.prototype.slot;
        result;
        "#,
        "true,true,true,false,false,2,11,true,12",
    );
}

#[test]
fn inherited_setters_accept_explicit_primitive_receivers_bd_9vouw_280() {
    check(
        r#"
        var seen;
        var total = 0;
        var object = {
            set item(value) { 'use strict'; seen = this; total += value; }
        };
        var first = Reflect.set(object, 'item', 2, 17);
        var number = seen === 17;
        var second = Reflect.set(object, 'item', 3, null);
        [first, number, second, seen === null, total].join(',');
        "#,
        "true,true,true,true,5",
    );
}

#[test]
fn reflect_inherited_setters_keep_backed_callable_receivers_bd_9vouw_280() {
    check(
        r#"
        var EventEmitter = require('events');
        var emitter = new EventEmitter();
        emitter.once('signal', function listener() {});
        var wrapper = emitter.rawListeners('signal')[0];
        function ordinary() {}
        var seen;
        var received;
        var symbol = Symbol('backedSlot');
        Object.defineProperty(Object.prototype, 'backedSlot', {
            set(value) { seen = this; received = value; }, configurable: true
        });
        Object.defineProperty(Array.prototype, symbol, {
            set(value) { seen = this; received = value; }, configurable: true
        });
        var first = Reflect.set({}, 'backedSlot', 11, EventEmitter);
        var constructorReceiver = seen === EventEmitter && received === 11;
        var second = Reflect.set({}, 'backedSlot', 12, wrapper);
        var wrapperReceiver = seen === wrapper && received === 12;
        var third = Reflect.set([], symbol, 13, wrapper);
        var arrayReceiver = seen === wrapper && received === 13;
        var fourth = Reflect.set({}, 'backedSlot', 15, ordinary);
        var ordinaryReceiver = seen === ordinary && received === 15;
        var fifth = Reflect.set({}, 'backedSlot', 16, Promise);
        var promiseReceiver = seen === Promise && received === 16;
        var absent = Object.getOwnPropertyDescriptor(wrapper, 'backedSlot') === undefined &&
            Object.getOwnPropertyDescriptor(EventEmitter, 'backedSlot') === undefined;
        var target = { backedSlot: 1 };
        var data = Reflect.set(target, 'backedSlot', 14, wrapper);
        var dataOwn = Object.getOwnPropertyDescriptor(wrapper, 'backedSlot').value === 14 &&
            target.backedSlot === 1;
        delete Object.prototype.backedSlot;
        delete Array.prototype[symbol];
        [first, constructorReceiver, second, wrapperReceiver, third, arrayReceiver,
            fourth, ordinaryReceiver, fifth, promiseReceiver, absent, data, dataOwn].join(',');
        "#,
        "true,true,true,true,true,true,true,true,true,true,true,true,true",
    );
}

#[test]
fn ordinary_inherited_setters_keep_function_receivers_bd_9vouw_280() {
    check(
        r#"
        var EventEmitter = require('events');
        var emitter = new EventEmitter();
        emitter.once('signal', function listener() {});
        var wrapper = emitter.rawListeners('signal')[0];
        function ordinary() {}
        var seen;
        var received;
        Object.defineProperty(Object.prototype, 'callableSlot', {
            set(value) { seen = this; received = value; }, configurable: true
        });
        EventEmitter.callableSlot = 1;
        var constructorReceiver = seen === EventEmitter && received === 1;
        ordinary.callableSlot = 2;
        var ordinaryReceiver = seen === ordinary && received === 2;
        Promise.callableSlot = 3;
        var promiseReceiver = seen === Promise && received === 3;
        wrapper.callableSlot = 4;
        var wrapperReceiver = seen === wrapper && received === 4;
        var absent = Object.getOwnPropertyDescriptor(EventEmitter, 'callableSlot') === undefined &&
            Object.getOwnPropertyDescriptor(ordinary, 'callableSlot') === undefined &&
            Object.getOwnPropertyDescriptor(Promise, 'callableSlot') === undefined &&
            Object.getOwnPropertyDescriptor(wrapper, 'callableSlot') === undefined;
        delete Object.prototype.callableSlot;
        [constructorReceiver, ordinaryReceiver, promiseReceiver, wrapperReceiver, absent].join(',');
        "#,
        "true,true,true,true,true",
    );
}

#[test]
fn array_assignment_honors_inherited_index_descriptors_bd_9vouw_280() {
    check(
        r#"
        var calls = 0;
        var receiver;
        var seen;
        Object.defineProperty(Array.prototype, '0', {
            set(value) { calls++; receiver = this; seen = value; }, configurable: true
        });
        var assigned = [];
        assigned[0] = 3;
        var literal = [4];
        var spread = [...literal, 5];
        var result = calls + ',' + (receiver === assigned) + ',' + seen + ',' +
            assigned.length + ',' + assigned.hasOwnProperty('0') + ',' +
            literal.length + ',' + literal[0] + ',' + spread.length + ',' + spread[0];
        delete Array.prototype[0];
        result;
        "#,
        "1,true,3,0,false,1,4,2,4",
    );
    check(
        r#"
        Object.defineProperty(Array.prototype, '0', {
            value: 19, writable: false, configurable: true
        });
        var assigned = [];
        assigned[0] = 7;
        var literal = [8];
        var result = assigned.length + ',' + assigned[0] + ',' +
            assigned.hasOwnProperty('0') + ',' + Reflect.set(assigned, '0', 9) + ',' +
            literal.length + ',' + literal[0] + ',' + literal.hasOwnProperty('0');
        delete Array.prototype[0];
        result;
        "#,
        "0,19,false,false,1,8,true",
    );
}

#[test]
fn literal_proto_entries_differ_from_computed_and_shorthand_data_bd_9vouw_280() {
    check(
        r#"
        var parent = { inherited: 9 };
        var linked = { before: 1, __proto__: parent, after: 2 };
        var empty = { __proto__: null, own: 3 };
        var computed = { ['__proto__']: parent };
        var __proto__ = 5;
        var shorthand = { __proto__ };
        var descriptor = Object.getOwnPropertyDescriptor(computed, '__proto__');
        var ownRead = computed.__proto__ === parent && shorthand.__proto__ === 5;
        computed.__proto__ = 7;
        [linked.inherited, linked.before, linked.after, linked.hasOwnProperty('__proto__'),
            Object.getPrototypeOf(linked) === parent, Object.getPrototypeOf(empty) === null,
            empty.own, Object.getPrototypeOf(computed) === Object.prototype,
            descriptor.value === parent, descriptor.writable, descriptor.enumerable,
            descriptor.configurable, Object.getOwnPropertyDescriptor(shorthand, '__proto__').value,
            ownRead, computed.__proto__, Object.getPrototypeOf(computed) === Object.prototype].join(',');
        "#,
        "9,1,2,false,true,true,3,true,true,true,true,true,5,true,7,true",
    );
}

#[test]
fn inherited_setter_abrupt_completion_is_catchable_bd_9vouw_280() {
    check(
        r#"
        Object.defineProperty(Object.prototype, 'blocked', {
            set(value) { throw 'setter:' + value; }, configurable: true
        });
        var object = {};
        var caught = '';
        try { object.blocked = 8; caught = 'missed'; }
        catch (error) { caught = error; }
        var literal = { blocked: 9 };
        var result = caught + ',' + object.hasOwnProperty('blocked') + ',' + literal.blocked;
        delete Object.prototype.blocked;
        result;
        "#,
        "setter:8,false,9",
    );
}

#[test]
fn incremental_object_data_definitions_replace_accessors_without_calls_bd_9vouw_280() {
    check(
        r#"
        var calls = 0;
        Object.defineProperty(Object.prototype, 'entry', {
            set(value) { calls++; }, configurable: true
        });
        var symbol = Symbol('entry');
        Object.defineProperty(Object.prototype, symbol, {
            value: 10, writable: false, configurable: true
        });
        function make() {
            return { get entry() { calls++; return 1; }, entry: 2,
                [symbol]: 3, ...{ extra: 4 }, method() { return this.entry; } };
        }
        var object = make();
        var descriptor = Object.getOwnPropertyDescriptor(object, 'entry');
        var result = [calls, object.entry, object[symbol], object.extra, object.method(),
            descriptor.value, descriptor.writable, descriptor.enumerable,
            descriptor.configurable, descriptor.get === undefined].join(',');
        delete Object.prototype.entry;
        delete Object.prototype[symbol];
        result;
        "#,
        "0,2,3,4,2,2,true,true,true,true",
    );
}

#[test]
fn large_literals_and_late_prototype_changes_keep_define_and_set_distinct_bd_9vouw_280() {
    let properties = (0..80)
        .map(|index| format!("field{index}: {index}"))
        .collect::<Vec<_>>()
        .join(",");
    let elements = (0..80)
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        r#"
        Object.defineProperty(Object.prototype, 'field17', {{
            value: 999, writable: false, configurable: true
        }});
        Object.defineProperty(Array.prototype, '17', {{
            value: 999, writable: false, configurable: true
        }});
        function make() {{ return [{{ {properties} }}, [{elements}]]; }}
        var values = make();
        var object = {{}};
        var array = [];
        object.field17 = 5;
        array[17] = 6;
        var result = values[0].field17 + ',' + values[1][17] + ',' + values[1].length + ',' +
            object.field17 + ',' + array[17] + ',' + array.length;
        delete Object.prototype.field17;
        delete Array.prototype[17];
        object.field17 = 5;
        array[17] = 6;
        result + '|' + object.field17 + ',' + array[17] + ',' + array.length;
        "#,
    );
    check(&source, "17,17,80,999,999,0|5,6,18");
}

#[test]
fn cyclic_prototypes_and_missing_create_argument_throw() {
    // `[]` inherits from Array.prototype, so making it Array.prototype's
    // prototype would close a cycle.
    check(
        "var r; try { Object.setPrototypeOf(Array.prototype, []); r = 'no error'; } \
         catch (e) { r = e instanceof TypeError; } \
         var s; try { Object.create(); s = 'no error'; } catch (e) { s = e instanceof TypeError; } \
         r + ',' + s",
        "true,true",
    );
}

#[test]
fn function_prototypes_point_back_to_their_constructor() {
    // MakeConstructor (ES2020 9.2.5): `F.prototype.constructor === F`, a
    // writable, non-enumerable, configurable data property. Before this, user
    // functions and classes had none, so `e.constructor` fell through to
    // Object and Test262's assert.throws reported "Expected a Test262Error but
    // got a Object".
    check(
        "class A {} class B extends A {} var f = function () {}; \
         [new A().constructor === A, new B().constructor === B, \
         A.prototype.hasOwnProperty('constructor'), f.prototype.constructor === f, \
         Object.keys(f.prototype).length, (function g() {}).prototype.constructor.name].join()",
        "true,true,true,true,0,g",
    );
    check(
        "function E(m) { this.m = m; } var e = new E(1); \
         var d = Object.getOwnPropertyDescriptor(E.prototype, 'constructor'); \
         [e.constructor === E, d.writable, d.enumerable, d.configurable, JSON.stringify(e)].join()",
        r#"true,true,false,true,{"m":1}"#,
    );
    // Replacing the prototype object drops the link, as in Node.
    check(
        "function F() {} F.prototype = { hi: 1 }; \
         [new F().constructor === Object, new F().constructor === F].join()",
        "true,false",
    );
    check(
        "function T(m) { this.message = m; } function thrower() { throw new T('x'); } \
         var r; try { thrower(); } catch (e) { r = e.constructor === T; } r",
        "true",
    );
}

#[test]
fn symbol_has_instance_decides_instanceof() {
    // ES2020 12.10.4 InstanceofOperator: a user `Symbol.hasInstance` (a static
    // class method or an object's method) is called with the target as
    // `this`, and ToBoolean of its result is the answer (JS probe corpus case
    // 32). Without one, the prototype walk is unchanged.
    check(
        "class Even { static [Symbol.hasInstance](n) { return n % 2 === 0; } } \
         [2 instanceof Even, 3 instanceof Even].join()",
        "true,false",
    );
    check(
        "var o = { [Symbol.hasInstance](v) { return v === 1; } }; \
         var T = { [Symbol.hasInstance]() { return 'yes'; } }; \
         [1 instanceof o, 2 instanceof o, 0 instanceof T].join()",
        "true,false,true",
    );
    check(
        "var seen; var U = { [Symbol.hasInstance](v) { seen = this === U; return false; } }; \
         var r = 1 instanceof U; [r, seen].join()",
        "false,true",
    );
    // A non-callable handler is a TypeError; a throwing handler propagates.
    check(
        "var B = { [Symbol.hasInstance]: 1 }; \
         var C = { [Symbol.hasInstance]() { throw new RangeError('x'); } }; var a, b; \
         try { 1 instanceof B; a = 'no'; } catch (e) { a = e instanceof TypeError; } \
         try { 1 instanceof C; b = 'no'; } catch (e) { b = e instanceof RangeError; } [a, b].join()",
        "true,true",
    );
    check(
        "class A {} class D extends A {} \
         [new A() instanceof A, ({}) instanceof A, new D() instanceof A].join()",
        "true,false,true",
    );
}

/// `Date` and `Promise` are materialized constructors (a builtin with its own
/// property object), not standard-constructor builtins, so a date's
/// `constructor` walked on to Object.prototype and was `Object`; `new
/// d.constructor(d)` still happened to work. rfdc keys its clone handlers by
/// `o.constructor`, so every Date was cloned as a plain object.
#[test]
fn date_constructor_is_the_date_global() {
    check(
        "var d = new Date(0); var m = new Map; m.set(Date, 1); \
         [d.constructor === Date, Date.prototype.constructor === Date, m.get(d.constructor), \
         Object.getPrototypeOf(d).constructor.name].join()",
        "true,true,1,Date",
    );
}
