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

#[test]
fn proxy_handlers_preserve_all_object_kind_identities() {
    assert_profile_value(
        r#"var handlers = [
  function () {}, () => {}, function* () {}, async function () {},
  async function* () {}, Math.abs, Promise.resolve(1),
  (function* () { yield 1; })(), (async function* () { yield 1; })(),
  [1].values()
];
var out = [];
for (var handler of handlers) {
  var events = [];
  var target = { x: 7 };
  var proxy;
  Object.defineProperty(handler, 'get', {
    configurable: true,
    get() {
      events.push(this === handler);
      return function (t, k, r) {
        events.push(this === handler, t === target, r === proxy);
        return Reflect.get(t, k, r);
      };
    }
  });
  proxy = new Proxy(target, handler);
  var before = events.length;
  var value = proxy.x;
  out.push(before + ':' + value + ':' + events.join(','));
  delete handler.get;
}
out.join('|');"#,
        "0:7:true,true,true,true|0:7:true,true,true,true|0:7:true,true,true,true|0:7:true,true,true,true|0:7:true,true,true,true|0:7:true,true,true,true|0:7:true,true,true,true|0:7:true,true,true,true|0:7:true,true,true,true|0:7:true,true,true,true",
    );
}

#[test]
fn proxy_handler_inherited_traps_keep_original_receivers() {
    assert_profile_value(
        r#"var handlers = [
  function () {}, Promise.resolve(1), (function* () { yield 1; })(),
  (async function* () { yield 1; })(), [1].values()
];
var out = [];
for (var handler of handlers) {
  var events = [];
  var target = { x: 9 };
  var prototype = {
    get get() {
      events.push(this === handler);
      return function (t, k) {
        events.push(this === handler, t === target);
        return t[k];
      };
    }
  };
  Object.setPrototypeOf(handler, prototype);
  var pair = Proxy.revocable(target, handler);
  out.push(pair.proxy.x, events.join(','));
  pair.revoke();
  try { pair.proxy.x; out.push('accepted'); }
  catch (e) { out.push(e.name); }
}
out.join('|');"#,
        "9|true,true,true|TypeError|9|true,true,true|TypeError|9|true,true,true|TypeError|9|true,true,true|TypeError|9|true,true,true|TypeError",
    );
}

#[test]
fn proxy_handler_getmethod_preserves_abrupt_completion_and_revocation() {
    assert_profile_value(
        r#"function attempt(f) {
  try { return String(f()); } catch (e) { return e.name; }
}
var out = [];
for (var invalid of [undefined, null, true, 0, 'x', Symbol('x'), 1n]) {
  out.push(attempt(() => new Proxy({}, invalid)));
  out.push(attempt(() => Proxy.revocable({}, invalid)));
}
function handler() {}
var marker = {};
Object.defineProperty(handler, 'get', {
  configurable: true, get() { throw marker; }
});
var pair = Proxy.revocable({ x: 3 }, handler);
try { pair.proxy.x; out.push('accepted'); } catch (e) { out.push(e === marker); }
Object.defineProperty(handler, 'get', { value: 1, configurable: true });
out.push(attempt(() => pair.proxy.x));
Object.defineProperty(handler, 'get', { value: null, configurable: true });
out.push(pair.proxy.x);
Object.defineProperty(handler, 'get', { value: undefined, configurable: true });
out.push(pair.proxy.x);
pair.revoke();
out.push(attempt(() => pair.proxy.x));
var revoked = Proxy.revocable(function () {}, {});
revoked.revoke();
var outer = new Proxy({}, revoked.proxy);
out.push(typeof outer, attempt(() => outer.x));
out.join('|');"#,
        "TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|TypeError|true|TypeError|3|3|TypeError|object|TypeError",
    );
}

#[test]
fn proxy_callable_handler_proxies_preserve_getter_and_trap_receivers() {
    assert_profile_value(
        r#"var events = [];
function carrier() {}
var handler = new Proxy(carrier, {
  get(t, key, receiver) {
    events.push(key + ':' + (t === carrier) + ':' + (receiver === handler));
    if (key === 'get') return function (target, name, proxy) {
      events.push('trap:' + (this === handler) + ':' + (target === subject) + ':' + (proxy === outer));
      return target[name];
    };
    return Reflect.get(t, key, receiver);
  }
});
var subject = { x: 11 };
var outer = new Proxy(subject, handler);
var value = outer.x;
[value, events.join('|')].join(':');"#,
        "11:get:true:true|trap:true:true:true",
    );
}

#[test]
fn proxy_traps_accept_generator_and_async_callable_values() {
    assert_profile_value(
        r#"var out = [];
var generator = new Proxy({}, {
  get: function* (target, key) { yield key; }
}).answer;
out.push(generator.next().value, generator.next().done);
var promise = new Proxy({}, {
  get: async function (target, key) { return key; }
}).answer;
out.push(promise instanceof Promise);
var asyncGenerator = new Proxy({}, {
  get: async function* (target, key) { yield key; }
}).answer;
out.push(asyncGenerator.next() instanceof Promise);
out.join('|');"#,
        "answer|true|true|true",
    );
}

#[test]
fn proxy_handler_apply_construct_and_descriptors_keep_identity() {
    assert_profile_value(
        r#"var log = [];
function handler() {}
Object.defineProperty(handler, 'apply', {
  get() {
    log.push('get-apply:' + (this === handler));
    return function (target, receiver, args) {
      log.push('apply:' + (this === handler));
      return Reflect.apply(target, receiver, args);
    };
  }
});
handler.construct = function (target, args, newTarget) {
  log.push('construct:' + (this === handler) + ':' + (newTarget === callable));
  return Reflect.construct(target, args, newTarget);
};
handler.getOwnPropertyDescriptor = function (target, key) {
  log.push('descriptor:' + (this === handler));
  return Reflect.getOwnPropertyDescriptor(target, key);
};
handler.defineProperty = function (target, key, descriptor) {
  log.push('define:' + (this === handler));
  return Reflect.defineProperty(target, key, descriptor);
};
function C(x) { this.x = x; return x + 1; }
var callable = new Proxy(C, handler);
var receiver = {};
var result = callable.call(receiver, 2);
var instance = new callable(4);
Object.defineProperty(callable, 'n', { value: 6, configurable: true });
var descriptor = Object.getOwnPropertyDescriptor(callable, 'n');
[result, receiver.x, instance.x, instance instanceof C, descriptor.value, log.join('|')].join(':');"#,
        "3:2:4:true:6:get-apply:true|apply:true|construct:true:true|define:true|descriptor:true",
    );
}

/// A Proxy's handler slot retains the original exotic value across GC, not
/// only its property backing. Promise.prototype.then checks the live identity.
#[test]
fn proxy_handler_values_survive_gc_with_exact_memory_accounting() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = r#"function make() {
  var handler = Promise.resolve(5);
  handler.marker = 23;
  handler.get = function (target, key) {
    this.then(function () {});
    return this.marker + target[key];
  };
  return new Proxy({ x: 7 }, handler);
}
var proxy = make();
for (var i = 0; i < 30; i++) { var garbage = { i: i }; }
proxy.x;"#;
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "proxy-handler-gc.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("proxy handler GC program parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "proxy-handler-gc.js"),
        &LoweringContext::new("proxy-handler-gc", "proxy-decision", "proxy-policy"),
    )
    .expect("proxy handler GC program lowers")
    .ir3;
    for base_config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        for interval in [None, Some(1), Some(7)] {
            let mut config = base_config.clone();
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "proxy-handler-gc");
            core.set_gc_stress_interval(interval);
            let result = core.execute(&module).expect("proxy handler survives GC");
            assert_eq!(result.value, Value::Int(30), "interval={interval:?}");
            if interval.is_some() {
                assert!(core.gc_stats().collections > 0);
            }
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "proxy handler accounting: interval={interval:?}"
            );
        }
    }
}

#[test]
fn exotic_prototype_mutations_preserve_identity_and_observable_properties() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(name, value) { if (!value) failures.push(name); }
  const factories = [
    ['promise', function () { return Promise.resolve(1); }],
    ['generator', function () { return (function* () { yield 2; })(); }],
    ['iterator', function () { return [3].values(); }],
    ['async-generator', function () { return (async function* () { yield 4; })(); }]
  ];
  for (const pair of factories) {
    for (const warm of [false, true]) {
      const name = pair[0] + ':' + warm;
      const value = pair[1]();
      const original = Object.getPrototypeOf(value);
      const methodName = pair[0] === 'promise' ? 'then' : 'next';
      const method = value[methodName];
      if (warm) Object.defineProperty(value, 'retained', {value: 17, configurable: true});
      const parent = Object.create(original);
      const symbol = Symbol('self');
      Object.defineProperty(parent, 'self', {get() { return this; }});
      Object.defineProperty(parent, symbol, {get() { return this; }});
      Object.defineProperty(parent, 'assigned', {set(value) { this.seen = value; }});
      parent.echo = function () { return this; };
      function Match() {}
      Match.prototype = parent;
      check(name + ':set-result', Object.setPrototypeOf(value, parent) === value);
      check(name + ':prototype', Object.getPrototypeOf(value) === parent && Reflect.getPrototypeOf(value) === parent);
      check(name + ':get-receiver', value.self === value && value[symbol] === value && value.echo() === value);
      check(name + ':inherited-method', value[methodName] === method);
      check(name + ':has', 'self' in value && symbol in value && !Object.prototype.hasOwnProperty.call(value, 'self'));
      const alternate = {};
      check(name + ':reflect-get', Reflect.get(value, 'self', alternate) === alternate && Reflect.get(value, symbol, alternate) === alternate);
      check(name + ':reflect-set', Reflect.set(value, 'assigned', 23, alternate) && alternate.seen === 23 && value.seen === undefined);
      value.assigned = 29;
      check(name + ':setter', value.seen === 29 && parent.seen === undefined);
      check(name + ':instanceof', value instanceof Match);
      Object.defineProperty(value, 'ownSelf', {get() { return this; }, configurable: true});
      const child = Object.create(value);
      check(name + ':create-identity', Object.getPrototypeOf(child) === value && Reflect.getPrototypeOf(child) === value);
      function Constructor() {}
      Constructor.prototype = value;
      const constructed = new Constructor();
      check(name + ':constructor-identity', Object.getPrototypeOf(constructed) === value && constructed instanceof Constructor && child instanceof Constructor);
      function* makeGenerator() {}
      async function* makeAsyncGenerator() {}
      makeGenerator.prototype = value;
      makeAsyncGenerator.prototype = value;
      const generated = makeGenerator();
      const generatedAsync = makeAsyncGenerator();
      check(name + ':generator-prototype-identity', Object.getPrototypeOf(generated) === value && generated instanceof makeGenerator);
      check(name + ':async-generator-prototype-identity', Object.getPrototypeOf(generatedAsync) === value && generatedAsync instanceof makeAsyncGenerator);
      check(name + ':child-get', child.self === child && child[symbol] === child && child.ownSelf === child);
      check(name + ':own-reflect-get', Reflect.get(value, 'ownSelf', alternate) === alternate);
      const adopted = {};
      check(name + ':adopt-result', Reflect.setPrototypeOf(adopted, value));
      check(name + ':adopt-identity', Object.getPrototypeOf(adopted) === value && adopted.self === adopted);
      check(name + ':cycle', Reflect.setPrototypeOf(value, child) === false && Object.getPrototypeOf(value) === parent);
      if (warm) check(name + ':own-descriptor', Object.getOwnPropertyDescriptor(value, 'retained').value === 17);
      check(name + ':restore', Object.setPrototypeOf(value, original) === value && Object.getPrototypeOf(value) === original);
      check(name + ':restored-lookup', value.self === undefined && child.self === undefined && value[methodName] === method && !(value instanceof Match));
    }
  }
  return failures.length ? failures.join('|') : 'ok';
})()"#,
        "ok",
    );
}

#[test]
fn exotic_null_prototypes_and_non_extensibility_are_authoritative() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(name, value) { if (!value) failures.push(name); }
  function typeError(step) { try { step(); return false; } catch (error) { return error.name === 'TypeError'; } }
  const factories = [
    ['promise', function () { return Promise.resolve(1); }],
    ['generator', function () { return (function* () { yield 2; })(); }],
    ['iterator', function () { return [3].values(); }],
    ['async-generator', function () { return (async function* () { yield 4; })(); }]
  ];
  for (const pair of factories) {
    for (const warm of [false, true]) {
      const name = pair[0] + ':' + warm;
      const value = pair[1]();
      const original = Object.getPrototypeOf(value);
      if (warm) value.before = 11;
      check(name + ':null-set', Reflect.setPrototypeOf(value, null));
      check(name + ':null-get', Object.getPrototypeOf(value) === null && Reflect.getPrototypeOf(value) === null);
      check(name + ':removed-lookups', value.then === undefined && value.next === undefined && value[Symbol.iterator] === undefined && value[Symbol.asyncIterator] === undefined);
      check(name + ':removed-has', !('toString' in value) && !('next' in value) && !(value instanceof Object));
      check(name + ':null-tag', Object.prototype.toString.call(value) === '[object Object]');
      Object.defineProperty(value, 'own', {value: 42, enumerable: true, writable: true, configurable: true});
      value.after = 43;
      check(name + ':null-survives-own', Object.getPrototypeOf(value) === null && value.own === 42 && value.after === 43);
      check(name + ':own-descriptor', Object.getOwnPropertyDescriptor(value, 'own').value === 42 && Object.keys(value).includes('own'));
      if (warm) check(name + ':old-own', value.before === 11);
      check(name + ':prevent-result', Object.preventExtensions(value) === value && !Reflect.isExtensible(value));
      check(name + ':same-null', Reflect.setPrototypeOf(value, null) && Object.setPrototypeOf(value, null) === value);
      check(name + ':different-refused', Reflect.setPrototypeOf(value, original) === false);
      check(name + ':different-throws', typeError(function () { Object.setPrototypeOf(value, original); }));
      check(name + ':still-null', Object.getPrototypeOf(value) === null);
      check(name + ':new-own-refused', Reflect.defineProperty(value, 'newOwn', {value: 1}) === false);
    }
    const fresh = pair[1]();
    const original = Object.getPrototypeOf(fresh);
    check(pair[0] + ':fresh-prevent', Reflect.preventExtensions(fresh) && !Object.isExtensible(fresh));
    check(pair[0] + ':fresh-prototype', Object.getPrototypeOf(fresh) === original);
    check(pair[0] + ':fresh-same', Reflect.setPrototypeOf(fresh, original));
    check(pair[0] + ':fresh-change', Reflect.setPrototypeOf(fresh, null) === false && Object.getPrototypeOf(fresh) === original);
  }
  return failures.length ? failures.join('|') : 'ok';
})()"#,
        "ok",
    );
}

#[test]
fn exotic_prototype_changes_preserve_native_receiver_brands() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(name, value) { if (!value) failures.push(name); }
  function typeError(step) { try { step(); return false; } catch (error) { return error.name === 'TypeError'; } }
  const promise = Promise.resolve(1);
  const then = promise.then;
  Object.setPrototypeOf(promise, Object.create(Object.getPrototypeOf(promise)));
  check('promise-inherited', promise.then === then);
  Object.setPrototypeOf(promise, null);
  check('promise-borrowed', then.call(promise) instanceof Promise);
  check('promise-brand', typeError(function () { then.call({}); }));

  const generator = (function* () { yield 7; })();
  const otherGenerator = (function* () { yield 8; })();
  const nextGenerator = generator.next;
  Object.setPrototypeOf(generator, Object.create(Object.getPrototypeOf(generator)));
  check('generator-inherited', generator.next === nextGenerator);
  Object.setPrototypeOf(otherGenerator, null);
  check('generator-borrowed', nextGenerator.call(otherGenerator).value === 8 && nextGenerator.call(generator).value === 7);
  check('generator-brand', typeError(function () { nextGenerator.call({}); }));

  const iterator = [9].values();
  const otherIterator = [10].values();
  const nextIterator = iterator.next;
  Object.setPrototypeOf(iterator, Object.create(Object.getPrototypeOf(iterator)));
  check('iterator-inherited', iterator.next === nextIterator && otherIterator.next === nextIterator);
  Object.setPrototypeOf(otherIterator, null);
  check('iterator-borrowed', nextIterator.call(otherIterator).value === 10 && nextIterator.call(iterator).value === 9);
  check('iterator-brand', typeError(function () { nextIterator.call({}); }));
  const map = new Map([['a', 13]]).values();
  const set = new Set([14]).values();
  const mapNext = map.next;
  const setNext = set.next;
  check('iterator-method-identities', nextIterator !== mapNext && mapNext !== setNext && mapNext === new Map().values().next);
  check('array-map-brand', typeError(function () { nextIterator.call(map); }));
  check('array-set-brand', typeError(function () { nextIterator.call(set); }));
  check('map-set-brand', typeError(function () { mapNext.call(set); }));
  check('set-map-brand', typeError(function () { setNext.call(map); }));
  check('map-array-brand', typeError(function () { mapNext.call([].values()); }));
  check('set-array-brand', typeError(function () { setNext.call([].values()); }));
  check('map-borrowed', mapNext.call(new Map([['b', 15]]).values()).value === 15 && mapNext.call(map).value === 13);
  check('set-borrowed', setNext.call(new Set([16]).values()).value === 16 && setNext.call(set).value === 14);

  const entered = [0, 0];
  const asynchronous = (async function* () { entered[0]++; yield 11; })();
  const otherAsynchronous = (async function* () { entered[1]++; yield 12; })();
  const nextAsynchronous = asynchronous.next;
  Object.setPrototypeOf(asynchronous, Object.create(Object.getPrototypeOf(asynchronous)));
  check('async-generator-inherited', asynchronous.next === nextAsynchronous);
  Object.setPrototypeOf(otherAsynchronous, null);
  const otherResult = nextAsynchronous.call(otherAsynchronous);
  check('async-generator-borrowed', otherResult instanceof Promise && entered[0] === 0 && entered[1] === 1);
  const result = nextAsynchronous.call(asynchronous);
  check('async-generator-original', result instanceof Promise && entered[0] === 1 && entered[1] === 1);
  return failures.length ? failures.join('|') : 'ok';
})()"#,
        "ok",
    );
}

#[test]
fn generator_instance_prototypes_survive_late_backing_materialization() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(name, value) { if (!value) failures.push(name); }
  function* generate() { yield 1; }
  async function* generateAsync() { yield 2; }
  for (const pair of [['generator', generate], ['async-generator', generateAsync]]) {
    const name = pair[0];
    const make = pair[1];
    const original = make.prototype;
    const cold = make();
    const warm = make();
    Object.defineProperty(warm, 'retained', {value: 17, configurable: true});
    const replacement = {marker: 'new'};
    make.prototype = replacement;
    check(name + ':cold-snapshot', Object.getPrototypeOf(cold) === original && Reflect.getPrototypeOf(cold) === original);
    check(name + ':warm-snapshot', Object.getPrototypeOf(warm) === original);
    check(name + ':old-lookup', cold.marker === undefined && warm.marker === undefined && typeof cold.next === 'function');
    cold.materialized = 19;
    check(name + ':materialize-snapshot', Object.getPrototypeOf(cold) === original && cold.materialized === 19);
    check(name + ':retained', warm.retained === 17);
    const later = make();
    check(name + ':later-prototype', Object.getPrototypeOf(later) === replacement);
    check(name + ':later-lookup', later.marker === 'new' && later.next === undefined);
  }
  return failures.length ? failures.join('|') : 'ok';
})()"#,
        "ok",
    );
}

#[test]
fn exotic_prototype_observations_preserve_mutation_labels() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let cases = [
        ("value instanceof Promise;", false),
        ("'then' in value;", false),
        ("Object.getPrototypeOf(value) === null;", true),
        ("value.then === undefined;", true),
    ];
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
        for (observation, expected) in cases {
            let source = format!(
                "var value = Promise.resolve(1); \
                 Object.setPrototypeOf(value, 'prototype-label-marker'); {observation}"
            );
            let tree = CanonicalEs2020Parser
                .parse_with_options(
                    ParserSource {
                        label: "exotic-prototype-label.js".into(),
                        text: source.clone(),
                    },
                    ParseGoal::Script,
                    &ParserOptions::default(),
                )
                .expect("exotic prototype label program parses");
            let mut module = lower_ir0_to_ir3(
                &Ir0Module::from_syntax_tree(tree, "exotic-prototype-label.js"),
                &LoweringContext::new(
                    "exotic-prototype-label",
                    "prototype-decision",
                    "prototype-policy",
                ),
            )
            .expect("exotic prototype label program lowers")
            .ir3;
            let input_register = config.max_registers - 1;
            let pool_index = module
                .constant_pool
                .iter()
                .position(|text| text == "prototype-label-marker")
                .expect("unique labelled prototype input") as u32;
            let mut replacements = 0;
            for instruction in &mut module.instructions {
                if let Ir3Instruction::LoadStr {
                    dst,
                    pool_index: index,
                } = instruction
                    && *index == pool_index
                {
                    *instruction = Ir3Instruction::Move {
                        dst: *dst,
                        src: input_register,
                    };
                    replacements += 1;
                }
            }
            assert_eq!(replacements, 1, "only the prototype input is labelled");
            for interval in [None, Some(1), Some(7)] {
                let mut core = InterpreterCore::new(config.clone(), "exotic-prototype-label");
                core.seed_register(input_register, Value::Null).unwrap();
                core.set_register_label(input_register, Label::Secret)
                    .unwrap();
                core.set_gc_stress_interval(interval);
                let result = core
                    .execute(&module)
                    .expect("exotic prototype label program executes");
                assert_eq!(result.value, Value::Bool(expected), "{source}");
                assert_eq!(
                    result.completion_label.join(&Label::Secret),
                    result.completion_label,
                    "prototype mutation label must reach the observation: {source}"
                );
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes(),
                    "interval={interval:?}: {source}"
                );
            }
        }
    }
}

/// An ordinary object's prototype can be the only root retaining a
/// generator, its suspended invocation and its captured heap values.
#[test]
fn exotic_prototype_identity_retains_captures_across_gc() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = r#"function make() {
  const payload = { value: 3 };
  const generator = (function* () { yield payload.value; })();
  return Object.create(generator);
}
var holder = make();
for (var i = 0; i < 30; i++) { var garbage = { i: i }; }
Object.getPrototypeOf(holder).next().value;"#;
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "exotic-prototype-gc.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("exotic prototype GC program parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "exotic-prototype-gc.js"),
        &LoweringContext::new("exotic-prototype-gc", "proxy-decision", "proxy-policy"),
    )
    .expect("exotic prototype GC program lowers")
    .ir3;
    for base_config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        for interval in [None, Some(1), Some(7)] {
            let mut config = base_config.clone();
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "exotic-prototype-gc");
            core.set_gc_stress_interval(interval);
            let result = core
                .execute(&module)
                .expect("prototype carrier survives GC");
            assert_eq!(result.value, Value::Int(3), "interval={interval:?}");
            if interval.is_some() {
                assert!(core.gc_stats().collections > 0);
            }
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "exotic prototype accounting: interval={interval:?}"
            );
        }
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

/// TextEncoder and TextDecoder keep `encoding`, `fatal`, `ignoreBOM`, and
/// streaming state in engine-private slots accessed through prototype getters
/// rather than own properties. Expected baseline output captured from Node v26.3.0.
#[test]
fn text_codec_slots_are_private_and_prototype_getters_match_node() {
    assert_profile_value(
        r#"function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
var te = new TextEncoder();
var td = new TextDecoder('latin1', { fatal: true, ignoreBOM: true });
var out = [
  Object.getOwnPropertyNames(te).length,
  Object.getOwnPropertyNames(td).length,
  te.hasOwnProperty('encoding'),
  td.hasOwnProperty('encoding'),
  td.hasOwnProperty('fatal'),
  td.hasOwnProperty('ignoreBOM'),
  '__textDecoderState' in td,
  String(td.__textDecoderState),
  te.encoding, td.encoding, td.fatal, td.ignoreBOM,
  attempt(() => Object.getOwnPropertyDescriptor(TextEncoder.prototype, 'encoding').get.call({})),
  attempt(() => Object.getOwnPropertyDescriptor(TextDecoder.prototype, 'encoding').get.call({})),
  attempt(() => Object.getOwnPropertyDescriptor(TextDecoder.prototype, 'fatal').get.call(te)),
  attempt(() => Object.getOwnPropertyDescriptor(TextDecoder.prototype, 'ignoreBOM').get.call({})),
];
td.encoding = 'utf-8'; td.fatal = false; td.ignoreBOM = false; td.__textDecoderState = 99;
out.push(td.encoding, td.fatal, td.ignoreBOM, td.decode(new Uint8Array([0xE9])));
var streamTd = new TextDecoder('utf-8');
streamTd.__textDecoderState = 12345;
out.push(
  streamTd.decode(new Uint8Array([0xE2, 0x82]), { stream: true }),
  streamTd.decode(new Uint8Array([0xAC])),
);
out.join('|');"#,
        "0|0|false|false|false|false|false|undefined|utf-8|windows-1252|true|true|TypeError|TypeError|TypeError|TypeError|windows-1252|true|true|é||€",
    );

    // Private streaming state also survives Object.freeze on the decoder.
    assert_profile_value(
        r#"var frozen = Object.freeze(new TextDecoder('utf-8'));
[frozen.decode(new Uint8Array([0xE2, 0x82]), { stream: true }),
 frozen.decode(new Uint8Array([0xAC])),
 Object.getOwnPropertyNames(frozen).length].join('|');"#,
        "|€|0",
    );
}

/// Intl.* resolved options live in a private heap slot traced by GC and
/// immune to guest `__resolved` writes and deletions. Expected output
/// captured from Node v26.3.0.
#[test]
fn intl_resolved_options_slot_is_private_and_survives_gc_stress() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = r#"var nf = new Intl.NumberFormat('en-US');
var dtf = new Intl.DateTimeFormat('en-US', { timeZone: 'UTC', year: 'numeric' });
var out = [
  '__resolved' in nf,
  '__resolved' in dtf,
  String(nf.__resolved),
  Object.getOwnPropertyNames(nf).includes('__resolved'),
  Object.getOwnPropertyNames(dtf).includes('__resolved'),
];
nf.__resolved = { locale: 'evil' };
dtf.__resolved = {};
for (let i = 0; i < 30; i++) { const garbage = { i }; }
out.push(nf.resolvedOptions().locale, nf.format(1234), dtf.format(new Date(Date.UTC(2024, 0, 1))));
delete nf.__resolved;
out.push(nf.resolvedOptions().locale, nf.format(42));
out.join('|');"#;

    assert_profile_value(
        source,
        "false|false|undefined|false|false|en-US|1,234|2024|en-US|42",
    );

    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "intl-private-gc.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("intl program parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "intl-private-gc.js"),
        &LoweringContext::new("intl-gc", "intl-decision", "intl-policy"),
    )
    .expect("intl program lowers")
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
        let mut core = InterpreterCore::new(config, "intl-gc");
        core.set_gc_stress_interval(Some(1));
        let result = core
            .execute(&module)
            .expect("Intl private slot survives GC");
        assert_eq!(
            result.value,
            Value::str("false|false|undefined|false|false|en-US|1,234|2024|en-US|42")
        );
        assert!(core.gc_stats().collections > 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "HostObjectSlots::IntlResolved must keep exact memory accounting"
        );
    }
}

/// Timer handles store their timer id in a private host slot: `__timerId` is
/// absent from reflection, forged `{ __timerId: 1 }` objects cannot cancel a
/// real timer, and guest writes to `handle.__timerId` do not corrupt
/// `clearTimeout` / `ref` / `unref` / `hasRef`.
#[test]
fn timer_handle_id_slot_is_private_and_cannot_be_forged_or_corrupted() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = r#"var fired = [];
var h1 = setTimeout(() => { fired.push('t1'); }, 5);
var h2 = setTimeout(() => { fired.push('t2'); }, 10);
var leaked = ['__timerId' in h1, Object.getOwnPropertyNames(h1).includes('__timerId'), String(h1.__timerId)];
clearTimeout({ __timerId: 1 });
clearTimeout({ __timerId: 2 });
h2.__timerId = 99999;
var refCheck = [h2.hasRef(), h2.unref() === h2, h2.hasRef(), h2.ref() === h2, h2.hasRef()];
clearTimeout(h2);
[leaked.join(','), refCheck.join(','), h2.hasRef(), h1.hasRef()].join('|');"#;

    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "timer-private.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("timer program parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "timer-private.js"),
        &LoweringContext::new("timer-slot", "timer-decision", "timer-policy"),
    )
    .expect("timer program lowers")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Timer,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "timer-slot");
        let result = core.execute(&module).expect("timer slot checks execute");
        assert_eq!(
            result.value,
            Value::str("false,false,undefined|true,true,false,true,true|false|true")
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "HostObjectSlots::TimerHandle must keep exact memory accounting"
        );
    }
}

/// EventEmitter maxListeners lives in an engine-private weak side table:
/// `__maxListeners` is absent from reflection, guest writes do not corrupt
/// `getMaxListeners()`, `setMaxListeners()` works on frozen emitters, and
/// GC reclaims entries of collected emitters with exact memory accounting.
#[test]
fn event_emitter_max_listeners_is_private_and_survives_freeze() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = r#"const { EventEmitter } = require('events');
const ee = new EventEmitter();
const leaked = ['__maxListeners' in ee, Object.getOwnPropertyNames(ee).includes('__maxListeners'), String(ee.__maxListeners), ee.getMaxListeners()];
ee.__maxListeners = 999;
const afterGuestWrite = [ee.getMaxListeners(), ee.__maxListeners];
delete ee.__maxListeners;
Object.freeze(ee);
ee.setMaxListeners(25);
for (let i = 0; i < 20; i++) {
  const tmp = new EventEmitter();
  tmp.setMaxListeners(i + 1);
}
[leaked.join(','), afterGuestWrite.join(','), ee.getMaxListeners(), Object.getOwnPropertyNames(ee).includes('__maxListeners')].join('|');"#;

    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "emitter-private-max-listeners.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("emitter program parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "emitter-private-max-listeners.js"),
        &LoweringContext::new("emitter-slot", "emitter-decision", "emitter-policy"),
    )
    .expect("emitter program lowers")
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
        let mut core = InterpreterCore::new(config, "emitter-slot");
        core.set_gc_stress_interval(Some(1));
        let result = core.execute(&module).expect("emitter slot checks execute");
        assert_eq!(
            result.value,
            Value::str("false,false,undefined,10|10,999|25|false")
        );
        assert!(core.gc_stats().collections > 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "event_max_listeners must keep exact memory accounting across GC"
        );
    }
}

/// IteratorHelper, WrapForValidIterator, and RegExpStringIterator store their
/// state in engine-private `HostObjectSlots`: no `__*` own keys leak, forged
/// objects with legacy slot names throw TypeError, guest writes/deletes do not
/// corrupt iteration, frozen iterators still advance, and GC preserves held
/// callbacks/iterators with exact memory accounting (bd-9vouw.150).
#[test]
fn iterator_helpers_and_regexp_string_iterators_use_private_host_slots() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = r#"function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
const helper = [1, 2, 3].values().map(x => x * 10);
const wrapper = Iterator.from({
  i: 0,
  next() { return this.i < 2 ? { value: ++this.i, done: false } : { value: undefined, done: true }; }
});
const rsi = 'a1b2'.matchAll(/[a-z](\d)/g);

const helperProto = Object.getPrototypeOf(helper);
const wrapperProto = Object.getPrototypeOf(wrapper);
const rsiProto = Object.getPrototypeOf(rsi);

const leak = [
  Reflect.ownKeys(helper).length,
  Reflect.ownKeys(wrapper).length,
  Reflect.ownKeys(rsi).length,
  '__iteratorHelperKind' in helper,
  '__iteratorHelperIterated' in wrapper,
  '__regexpStringIteratorRegExp' in rsi,
  String(helper.__iteratorHelperKind),
  String(rsi.__regexpStringIteratorString),
];

const forge = [
  attempt(() => helperProto.next.call({ __iteratorHelperKind: 'map', __iteratorHelperIterated: [1].values(), __iteratorHelperNext: () => ({ value: 1, done: false }), __iteratorHelperCallback: x => x, __iteratorHelperCounter: 0, __iteratorHelperDone: false, __iteratorHelperRunning: false })),
  attempt(() => wrapperProto.next.call({ __iteratorHelperKind: 'wrap', __iteratorHelperIterated: {}, __iteratorHelperNext: () => ({ value: 1, done: false }) })),
  attempt(() => rsiProto.next.call({ __regexpStringIteratorRegExp: /a/g, __regexpStringIteratorString: 'a', __regexpStringIteratorGlobal: true, __regexpStringIteratorUnicode: false, __regexpStringIteratorDone: false })),
];

helper.__iteratorHelperKind = 'drop';
helper.__iteratorHelperDone = true;
delete helper.__iteratorHelperKind;
rsi.__regexpStringIteratorDone = true;
rsi.__regexpStringIteratorString = 'corrupted';
delete rsi.__regexpStringIteratorDone;

Object.freeze(helper);
Object.freeze(wrapper);
Object.freeze(rsi);

for (let i = 0; i < 30; i++) { const garbage = { i }; }

const results = [
  helper.next().value,
  helper.next().value,
  wrapper.next().value,
  wrapper.next().value,
  rsi.next().value[0],
  rsi.next().value[0],
  rsi.next().done,
];

[leak.join(','), forge.join(','), results.join(',')].join('|');"#;

    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "iterator-private-slots.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("iterator slot program parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "iterator-private-slots.js"),
        &LoweringContext::new("iter-slot", "iter-decision", "iter-policy"),
    )
    .expect("iterator slot program lowers")
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
        let mut core = InterpreterCore::new(config, "iter-slot");
        core.set_gc_stress_interval(Some(1));
        let result = core.execute(&module).expect("iterator slot checks execute");
        assert_eq!(
            result.value,
            Value::str(
                "0,0,0,false,false,false,undefined,undefined|TypeError,TypeError,TypeError|10,20,1,2,a1,b2,true"
            )
        );
        assert!(core.gc_stats().collections > 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "IteratorHelper/RegExpStringIterator slots must keep exact memory accounting"
        );
    }
}

/// EventTarget, Event, CustomEvent, AbortController, AbortSignal, and
/// TypedArray (`__typedArrayKind`) keep their internal state outside guest
/// properties: zero `__*` leakage, forged receivers throw TypeError, guest
/// writes/deletes do not corrupt state, frozen instances continue working, and
/// GC preserves internal references with exact memory accounting (bd-9vouw.150).
#[test]
fn event_target_family_and_typed_array_slots_are_private_and_unforgeable() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = r#"function attempt(f) { try { return String(f()); } catch (e) { return e.name; } }
const et = new EventTarget();
const ev = new CustomEvent('ping', { cancelable: true, detail: { n: 7 } });
const ac = new AbortController();
const sig = ac.signal;
const ta = new Uint8Array([4, 5]);

const leak = [
  '__eventTargetListeners' in et,
  '__eventType' in ev,
  '__eventDetail' in ev,
  '__controllerSignal' in ac,
  '__signalAborted' in sig,
  '__typedArrayKind' in ta,
  String(ta.__typedArrayKind),
  Object.getOwnPropertyNames(et).length,
  Object.getOwnPropertyNames(ac).length,
  Object.getOwnPropertyNames(ta).join(','),
];

const forge = [
  attempt(() => EventTarget.prototype.dispatchEvent.call({ __eventTargetListeners: [] }, ev)),
  attempt(() => Event.prototype.preventDefault.call({ __eventType: 'x', __eventCancelable: true, __eventDefaultPrevented: false })),
  attempt(() => AbortController.prototype.abort.call({ __controllerSignal: sig })),
  attempt(() => AbortSignal.prototype.throwIfAborted.call({ __signalAborted: true, __signalReason: 'forged' })),
  attempt(() => AbortSignal.any([{ __signalAborted: false }])),
];

et.__eventTargetListeners = 'corrupted';
ev.__eventType = 'forged';
ev.__eventCancelable = false;
ac.__controllerSignal = null;
sig.__signalAborted = true;
ta.__typedArrayKind = 'Float64Array';
delete et.__eventTargetListeners;
delete ev.__eventType;
delete ac.__controllerSignal;
delete sig.__signalAborted;
delete ta.__typedArrayKind;

Object.freeze(et);
Object.freeze(ev);
Object.freeze(ac);

let seen = [];
et.addEventListener('ping', (e) => {
  seen.push(e.type + ':' + e.detail.n);
  e.preventDefault();
});
const notCanceled = et.dispatchEvent(ev);
const combined = AbortSignal.any([sig]);
for (let i = 0; i < 30; i++) { const garbage = { i }; }
ac.abort('stop');

const behavior = [
  seen.join(','),
  notCanceled,
  ev.defaultPrevented,
  sig.aborted,
  combined.aborted,
  combined.reason,
  Object.prototype.toString.call(ta),
  ta[0] + ta[1],
];

[leak.join(','), forge.join(','), behavior.join(',')].join('|');"#;

    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "event-target-private-slots.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("event target slot program parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "event-target-private-slots.js"),
        &LoweringContext::new("et-slot", "et-decision", "et-policy"),
    )
    .expect("event target slot program lowers")
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
        let mut core = InterpreterCore::new(config, "et-slot");
        core.set_gc_stress_interval(Some(1));
        let result = core
            .execute(&module)
            .expect("event target slot checks execute");
        assert_eq!(
            result.value,
            Value::str(
                "false,false,false,false,false,false,undefined,0,0,0,1|TypeError,TypeError,TypeError,TypeError,TypeError|ping:7,false,true,true,true,stop,[object Uint8Array],9"
            )
        );
        assert!(core.gc_stats().collections > 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "EventTarget/Event/AbortController/AbortSignal slots must keep exact memory accounting"
        );
    }
}

#[test]
fn exotic_proxy_targets_preserve_identity_and_forward_properties() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(ok, detail) { if (!ok) failures.push(detail); }
  const factories = [
    ['promise', () => Promise.resolve(1)],
    ['generator', () => (function* () { yield 2; })()],
    ['async-generator', () => (async function* () { yield 3; })()],
    ['array-iterator', () => [4, 5].values()],
    ['map-iterator', () => new Map([['a', 6]]).values()],
    ['set-iterator', () => new Set([7]).values()],
    ['string-iterator', () => 'ab'[Symbol.iterator]()],
    ['typed-array-iterator', () => new Uint8Array([8, 9]).values()]
  ];
  for (const [kind, create] of factories) {
    const target = create();
    const originalPrototype = Object.getPrototypeOf(target);
    const parent = Object.create(originalPrototype);
    const symbol = Symbol(kind);
    let getterCalls = 0;
    Object.defineProperty(target, 'value', {
      value: 11, writable: true, enumerable: true, configurable: true
    });
    Object.defineProperty(target, 'self', {
      get() { getterCalls++; return this; }, enumerable: true, configurable: true
    });
    Object.defineProperty(parent, 'inheritedSelf', {
      get() { return this; }, configurable: true
    });
    Object.defineProperty(parent, 'assigned', {
      set(value) { this.saved = value; }, configurable: true
    });
    Object.setPrototypeOf(target, parent);
    const calls = [];
    const lookups = [];
    let handler;
    function entered(name, actual, receiver) {
      calls.push(name);
      check(actual === target, kind + ':' + name + ':target');
      check(receiver === handler, kind + ':' + name + ':handler');
    }
    const traps = {
      get(actual, key, receiver) {
        entered('get', actual, this);
        return Reflect.get(actual, key, receiver);
      },
      set(actual, key, value, receiver) {
        entered('set', actual, this);
        return Reflect.set(actual, key, value, receiver);
      },
      has(actual, key) {
        entered('has', actual, this);
        return Reflect.has(actual, key);
      },
      deleteProperty(actual, key) {
        entered('deleteProperty', actual, this);
        return Reflect.deleteProperty(actual, key);
      },
      ownKeys(actual) {
        entered('ownKeys', actual, this);
        return Reflect.ownKeys(actual);
      },
      getOwnPropertyDescriptor(actual, key) {
        entered('getOwnPropertyDescriptor', actual, this);
        return Reflect.getOwnPropertyDescriptor(actual, key);
      },
      defineProperty(actual, key, descriptor) {
        entered('defineProperty', actual, this);
        return Reflect.defineProperty(actual, key, descriptor);
      },
      getPrototypeOf(actual) {
        entered('getPrototypeOf', actual, this);
        return Reflect.getPrototypeOf(actual);
      },
      setPrototypeOf(actual, prototype) {
        entered('setPrototypeOf', actual, this);
        return Reflect.setPrototypeOf(actual, prototype);
      },
      isExtensible(actual) {
        entered('isExtensible', actual, this);
        return Reflect.isExtensible(actual);
      },
      preventExtensions(actual) {
        entered('preventExtensions', actual, this);
        return Reflect.preventExtensions(actual);
      }
    };
    handler = new Proxy(traps, {
      get(actual, key, receiver) {
        lookups.push(key);
        return Reflect.get(actual, key, receiver);
      }
    });
    const proxy = new Proxy(target, handler);
    check(calls.length === 0 && lookups.length === 0 && getterCalls === 0,
      kind + ':construction-does-not-read');
    check(typeof proxy === 'object', kind + ':non-callable');
    check(proxy.value === 11 && proxy.self === proxy && proxy.inheritedSelf === proxy,
      kind + ':get-receiver');
    const alternate = {};
    check(Reflect.get(proxy, 'self', alternate) === alternate && getterCalls === 2,
      kind + ':explicit-get-receiver');
    check(Reflect.set(proxy, 'assigned', 12, alternate)
      && alternate.saved === 12 && target.saved === undefined, kind + ':explicit-set-receiver');
    check(Reflect.set(proxy, 'written', 13) && target.written === 13, kind + ':set');
    check(Reflect.defineProperty(proxy, symbol, {
      value: 14, writable: true, enumerable: true, configurable: true
    }) && target[symbol] === 14, kind + ':define-symbol');
    check('value' in proxy && 'inheritedSelf' in proxy && symbol in proxy, kind + ':has');
    check(Object.getOwnPropertyDescriptor(proxy, symbol).value === 14, kind + ':descriptor');
    const transparent = new Proxy(target, {});
    check(transparent.value === 11 && transparent.inheritedSelf === transparent
      && Reflect.get(transparent, 'self', alternate) === alternate,
      kind + ':transparent-get-receiver');
    check(Reflect.set(transparent, 'transparent', 17) && target.transparent === 17
      && Reflect.deleteProperty(transparent, 'transparent')
      && !('transparent' in target), kind + ':transparent-storage');
    check(Object.getPrototypeOf(transparent) === parent
      && Object.getOwnPropertyDescriptor(transparent, symbol).value === 14,
      kind + ':transparent-reflection');
    const keys = Reflect.ownKeys(proxy);
    check(keys.includes('value') && keys.includes('self') && keys.includes(symbol)
      && keys.length === Reflect.ownKeys(target).length, kind + ':own-keys');
    check(Reflect.deleteProperty(proxy, 'written') && !('written' in target), kind + ':delete');
    check(Object.getPrototypeOf(proxy) === parent, kind + ':prototype');
    const replacement = Object.create(originalPrototype);
    check(Reflect.setPrototypeOf(proxy, replacement)
      && Object.getPrototypeOf(target) === replacement, kind + ':set-prototype');
    check(Reflect.isExtensible(proxy), kind + ':extensible');
    check(Reflect.preventExtensions(proxy) && !Object.isExtensible(target)
      && !Reflect.isExtensible(proxy), kind + ':prevent-extensions');
    check(!Reflect.set(proxy, 'missing', 15) && Reflect.set(proxy, 'value', 16)
      && target.value === 16, kind + ':non-extensible-storage');
    for (const name of Object.keys(traps)) {
      check(calls.includes(name), kind + ':unvisited-' + name);
    }
  }
  return failures.join('|') || 'ok';
})()"#,
        "ok",
    );
}

#[test]
fn exotic_proxy_targets_preserve_revocation_and_short_circuits() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(ok, detail) { if (!ok) failures.push(detail); }
  function typeError(step) {
    try { step(); return false; } catch (error) { return error instanceof TypeError; }
  }
  const factories = [
    ['promise', () => Promise.resolve(1)],
    ['generator', () => (function* () { yield 2; })()],
    ['iterator', () => [3].values()],
    ['async-generator', () => (async function* () { yield 4; })()]
  ];
  const operations = [
    ['get', proxy => proxy.value],
    ['set', proxy => Reflect.set(proxy, 'value', 8)],
    ['has', proxy => 'value' in proxy],
    ['deleteProperty', proxy => Reflect.deleteProperty(proxy, 'value')],
    ['ownKeys', proxy => Reflect.ownKeys(proxy)],
    ['getOwnPropertyDescriptor', proxy => Reflect.getOwnPropertyDescriptor(proxy, 'value')],
    ['defineProperty', proxy => Reflect.defineProperty(proxy, 'other', { value: 8 })],
    ['getPrototypeOf', proxy => Reflect.getPrototypeOf(proxy)],
    ['setPrototypeOf', proxy => Reflect.setPrototypeOf(proxy, null)],
    ['isExtensible', proxy => Reflect.isExtensible(proxy)],
    ['preventExtensions', proxy => Reflect.preventExtensions(proxy)]
  ];
  const shortcuts = [
    ['set', false, proxy => Reflect.set(proxy, 'value', 8)],
    ['has', true, proxy => 'value' in proxy],
    ['deleteProperty', false, proxy => Reflect.deleteProperty(proxy, 'value')],
    ['defineProperty', false, proxy => Reflect.defineProperty(proxy, 'value', { value: 8 })],
    ['setPrototypeOf', false, proxy => Reflect.setPrototypeOf(proxy, null)],
    ['preventExtensions', false, proxy => Reflect.preventExtensions(proxy)]
  ];
  for (const [kind, create] of factories) {
    const target = create();
    target.value = 7;
    let lookups = 0;
    const handler = new Proxy({}, {
      get() { lookups++; return undefined; }
    });
    const pair = Proxy.revocable(target, handler);
    check(lookups === 0, kind + ':construction');
    check(pair.revoke() === undefined && pair.revoke() === undefined, kind + ':idempotent-revoke');
    check(typeof pair.proxy === 'object', kind + ':revoked-typeof');
    for (const [name, operate] of operations) {
      check(typeError(() => operate(pair.proxy)), kind + ':revoked-' + name);
    }
    check(lookups === 0 && target.value === 7, kind + ':revoke-before-handler');

    for (const [trapName, answer, operate] of shortcuts) {
      let calls = 0;
      const outerHandler = {};
      outerHandler[trapName] = function (actual) {
        calls++;
        check(actual === pair.proxy && this === outerHandler,
          kind + ':outer-' + trapName + ':identity');
        return answer;
      };
      const outer = new Proxy(pair.proxy, outerHandler);
      check(calls === 0, kind + ':outer-' + trapName + ':construction');
      check(operate(outer) === answer && calls === 1,
        kind + ':outer-' + trapName + ':short-circuit');
    }

    let calls = 0;
    const outer = new Proxy(pair.proxy, {
      get(actual) { calls++; check(actual === pair.proxy, kind + ':outer-get-target'); return 9; }
    });
    check(typeError(() => outer.value) && calls === 1, kind + ':get-then-target-invariant');
    check(typeError(() => new Proxy(pair.proxy, {}).value), kind + ':transparent-revoked-target');

    const marker = {};
    let trapReads = 0;
    const abrupt = new Proxy(pair.proxy, {
      get get() { trapReads++; throw marker; }
    });
    let caught;
    try { abrupt.value; } catch (error) { caught = error; }
    check(caught === marker && trapReads === 1, kind + ':getmethod-before-target-invariant');

    const liveTarget = create();
    liveTarget.value = 10;
    let live;
    let trapCalls = 0;
    const revokingHandler = {
      get get() {
        live.revoke();
        return function (actual) {
          trapCalls++;
          check(actual === liveTarget && this === revokingHandler,
            kind + ':in-flight-identity');
          return actual.value;
        };
      }
    };
    live = Proxy.revocable(liveTarget, revokingHandler);
    check(live.proxy.value === 10 && trapCalls === 1, kind + ':in-flight-get');
    check(typeError(() => live.proxy.value) && trapCalls === 1, kind + ':subsequent-get');
  }
  return failures.join('|') || 'ok';
})()"#,
        "ok",
    );
}

#[test]
fn exotic_proxy_targets_enforce_internal_method_invariants() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(ok, detail) { if (!ok) failures.push(detail); }
  const factories = [
    ['promise', () => Promise.resolve(1)],
    ['generator', () => (function* () { yield 1; })()],
    ['iterator', () => [1].values()],
    ['async-generator', () => (async function* () { yield 1; })()]
  ];
  const rows = [
    ['get', false, () => 8, proxy => proxy.fixed],
    ['set', false, () => true, proxy => Reflect.set(proxy, 'fixed', 8)],
    ['has', false, () => false, proxy => 'fixed' in proxy],
    ['deleteProperty', false, () => true, proxy => Reflect.deleteProperty(proxy, 'fixed')],
    ['ownKeys', false, () => [], proxy => Reflect.ownKeys(proxy)],
    ['getOwnPropertyDescriptor', false, () => undefined,
      proxy => Object.getOwnPropertyDescriptor(proxy, 'fixed')],
    ['defineProperty', false, () => true,
      proxy => Reflect.defineProperty(proxy, 'fixed', { value: 8 })],
    ['isExtensible', false, () => false, proxy => Reflect.isExtensible(proxy)],
    ['preventExtensions', false, () => true, proxy => Reflect.preventExtensions(proxy)],
    ['getPrototypeOf', true, () => null, proxy => Reflect.getPrototypeOf(proxy)],
    ['setPrototypeOf', true, () => true, proxy => Reflect.setPrototypeOf(proxy, null)],
    ['ownKeys', true, () => ['fixed', 'invented'], proxy => Reflect.ownKeys(proxy)],
    ['defineProperty', true, () => true,
      proxy => Reflect.defineProperty(proxy, 'invented', { value: 9 })],
    ['getOwnPropertyDescriptor', false,
      () => ({ value: 9, writable: true, enumerable: true, configurable: false }),
      proxy => Object.getOwnPropertyDescriptor(proxy, 'invented')]
  ];
  for (const [kind, create] of factories) {
    for (let index = 0; index < rows.length; index++) {
      const [trapName, preventExtensions, result, operate] = rows[index];
      const target = create();
      Object.defineProperty(target, 'fixed', {
        value: 7, writable: false, enumerable: true, configurable: false
      });
      if (preventExtensions) Object.preventExtensions(target);
      const label = kind + ':' + index + ':' + trapName;
      let calls = 0;
      const handler = {};
      handler[trapName] = function (actualTarget) {
        calls++;
        check(actualTarget === target, label + ':target');
        check(this === handler, label + ':handler');
        return result();
      };
      const proxy = new Proxy(target, handler);
      let error;
      try { operate(proxy); } catch (caught) { error = caught; }
      check(error instanceof TypeError, label + ':invariant');
      check(calls === 1, label + ':calls');
      check(target.fixed === 7, label + ':protected-value');
    }
    const target = create();
    let reads = 0;
    const handler = {
      get apply() { reads++; return function () {}; },
      get construct() { reads++; return function () {}; }
    };
    const proxy = new Proxy(target, handler);
    let callError;
    let constructError;
    try { Reflect.apply(proxy, null, []); } catch (caught) { callError = caught; }
    try { Reflect.construct(proxy, []); } catch (caught) { constructError = caught; }
    check(callError instanceof TypeError && constructError instanceof TypeError,
      kind + ':non-callable');
    check(reads === 0 && typeof proxy === 'object', kind + ':callable-traps');
  }
  return failures.join('|') || 'ok';
})()"#,
        "ok",
    );
}

#[test]
fn exotic_proxy_targets_preserve_native_receiver_brands() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(ok, detail) { if (!ok) failures.push(detail); }
  function typeError(step) {
    try { step(); return false; } catch (error) { return error instanceof TypeError; }
  }
  const promise = Promise.resolve(1);
  const promiseProxy = new Proxy(promise, {});
  check(promiseProxy.then === promise.then, 'promise:method-identity');
  check(typeError(() => promiseProxy.then()), 'promise:receiver-brand');
  check(promiseProxy.then.call(promise) instanceof Promise, 'promise:borrowed-method');

  let entered = 0;
  const generator = (function* () { entered++; yield 2; })();
  const generatorProxy = new Proxy(generator, {});
  check(generatorProxy.next === generator.next, 'generator:method-identity');
  check(generatorProxy[Symbol.iterator]() === generatorProxy, 'generator:iterator-self');
  check(typeError(() => generatorProxy.next()) && typeError(() => Array.from(generatorProxy))
    && entered === 0, 'generator:receiver-brand');
  const otherGenerator = (function* () { yield 3; })();
  check(generatorProxy.next.call(otherGenerator).value === 3 && entered === 0,
    'generator:unbound-method');
  check(generatorProxy.next.call(generator).value === 2 && entered === 1,
    'generator:borrowed-method');

  const factories = [
    ['array', () => [4, 5].values(), 4],
    ['map', () => new Map([['a', 6], ['b', 7]]).values(), 6],
    ['set', () => new Set([8, 9]).values(), 8],
    ['string', () => 'cd'[Symbol.iterator](), 'c'],
    ['typed-array', () => new Uint8Array([10, 11]).values(), 10]
  ];
  for (const [kind, create, expected] of factories) {
    const target = create();
    const other = create();
    const proxy = new Proxy(target, {});
    check(proxy.next === target.next && proxy.next === other.next, kind + ':method-identity');
    check(proxy[Symbol.iterator]() === proxy, kind + ':iterator-self');
    check(typeError(() => proxy.next()) && typeError(() => Array.from(proxy)),
      kind + ':receiver-brand');
    check(proxy.next.call(other).value === expected, kind + ':unbound-method');
    check(proxy.next.call(target).value === expected, kind + ':unadvanced-original');
  }

  const entries = [0, 0];
  const asynchronous = (async function* () { entries[0]++; yield 12; })();
  const otherAsynchronous = (async function* () { entries[1]++; yield 13; })();
  const asyncProxy = new Proxy(asynchronous, {});
  check(asyncProxy.next === asynchronous.next
    && asyncProxy.return === asynchronous.return
    && asyncProxy.throw === asynchronous.throw, 'async-generator:method-identity');
  check(asyncProxy[Symbol.asyncIterator]() === asyncProxy, 'async-generator:iterator-self');
  let nextResult;
  let returnResult;
  let throwResult;
  let synchronousError;
  try {
    nextResult = asyncProxy.next();
    returnResult = asyncProxy.return(14);
    throwResult = asyncProxy.throw(15);
  } catch (error) { synchronousError = error; }
  check(synchronousError === undefined && nextResult instanceof Promise
    && returnResult instanceof Promise && throwResult instanceof Promise
    && entries[0] === 0, 'async-generator:rejection-boundary');
  if (nextResult instanceof Promise) nextResult.catch(function () {});
  if (returnResult instanceof Promise) returnResult.catch(function () {});
  if (throwResult instanceof Promise) throwResult.catch(function () {});
  const otherResult = asyncProxy.next.call(otherAsynchronous);
  check(otherResult instanceof Promise && entries[0] === 0 && entries[1] === 1,
    'async-generator:unbound-method');
  const originalResult = asyncProxy.next.call(asynchronous);
  check(originalResult instanceof Promise && entries[0] === 1 && entries[1] === 1,
    'async-generator:borrowed-method');
  return failures.join('|') || 'ok';
})()"#,
        "ok",
    );
}
