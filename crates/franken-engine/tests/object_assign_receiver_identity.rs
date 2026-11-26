#![forbid(unsafe_code)]

//! Object.assign must preserve the original target identity through ordinary
//! [[Set]], including callable Proxy records and native object carriers.

use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine};

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
fn assign_setters_receive_the_original_callable_and_native_target() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(ok, detail) { if (!ok) failures.push(detail); }
  const factories = [
    ['object', () => ({})],
    ['function', () => function () {}],
    ['arrow', () => () => 0],
    ['bound', () => (function () {}).bind(null)],
    ['builtin', () => Math.abs],
    ['constructor', () => Array],
    ['date-constructor', () => Date],
    ['promise-constructor', () => Promise],
    ['function-prototype', () => Function.prototype],
    ['promise', () => Promise.resolve(1)],
    ['generator', () => (function* () { yield 1; })()],
    ['iterator', () => [1].values()],
    ['async-generator', () => (async function* () { yield 1; })()]
  ];
  for (const [name, create] of factories) {
    const target = create();
    const originalPrototype = Object.getPrototypeOf(target);
    const prototype = Object.create(originalPrototype);
    const symbol = Symbol(name);
    const events = [];
    const ownSetter = function (value) {
      events.push('own:' + value + ':' + (this === target));
    };
    Object.defineProperty(target, 'own', { set: ownSetter, configurable: true });
    Object.defineProperty(target, '0', {
      set(value) { events.push('zero:' + value + ':' + (this === target)); },
      configurable: true
    });
    Object.defineProperty(prototype, 'inherited', {
      set(value) { events.push('inherited:' + value + ':' + (this === target)); }
    });
    Object.defineProperty(prototype, '1', {
      set(value) { events.push('one:' + value + ':' + (this === target)); }
    });
    Object.defineProperty(prototype, symbol, {
      set(value) { events.push('symbol:' + value + ':' + (this === target)); }
    });
    Object.setPrototypeOf(target, prototype);
    const source = { own: 3, inherited: 4, data: 5 };
    source[symbol] = 6;
    check(Object.assign(target, source, 'ab') === target, name + ':return');
    check(events.join('|') === 'own:3:true|inherited:4:true|symbol:6:true|zero:a:true|one:b:true',
      name + ':receivers:' + events.join('|'));
    check(target.data === 5, name + ':data');
    check(Object.getOwnPropertyDescriptor(target, 'own').set === ownSetter, name + ':setter');
    check(!Object.hasOwn(target, 'inherited') && !Object.hasOwn(target, '1')
      && !Object.hasOwn(target, symbol), name + ':inherited');
    Object.setPrototypeOf(target, originalPrototype);
  }
  return failures.join('|') || 'ok';
})()"#,
        "ok",
    );
}

#[test]
fn object_assign_callback_effects_preserve_selection_labels() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let cases = [
        (
            "source-getter",
            "var observed = 0; function target() {} \
             const source = { get copied() { observed = 41; return 1; } }; \
             const selected = 'object-assign-label-marker'; \
             Object.assign(target, selected ? source : {}); observed;",
            41,
        ),
        (
            "target-setter",
            "var observed = 0; function target() {} function alternate() {} \
             Object.defineProperty(target, 'copied', { \
                 set(value) { observed = 42; } \
             }); \
             const selected = 'object-assign-label-marker'; \
             Object.assign(selected ? target : alternate, { copied: 1 }); observed;",
            42,
        ),
        (
            "target-proxy-trap",
            "var observed = 0; function alternate() {} \
             const target = new Proxy(function () {}, { \
                 set() { observed = 43; return true; } \
             }); \
             const selected = 'object-assign-label-marker'; \
             Object.assign(selected ? target : alternate, { copied: 1 }); observed;",
            43,
        ),
        (
            "throwing-source-getter",
            "var observed = 0; function target() {} \
             const source = { get copied() { observed = 44; throw 'stop'; } }; \
             const selected = 'object-assign-label-marker'; \
             try { Object.assign(target, selected ? source : {}); } catch (error) {} \
             observed;",
            44,
        ),
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
        for (name, source, expected) in cases {
            let tree = CanonicalEs2020Parser
                .parse_with_options(
                    ParserSource {
                        label: "object-assign-label.js".into(),
                        text: source.into(),
                    },
                    ParseGoal::Script,
                    &ParserOptions::default(),
                )
                .expect("Object.assign label fixture parses");
            let mut module = lower_ir0_to_ir3(
                &Ir0Module::from_syntax_tree(tree, "object-assign-label.js"),
                &LoweringContext::new("assign-label", "assign-decision", "assign-policy"),
            )
            .expect("Object.assign label fixture lowers")
            .ir3;
            let input_register = config.max_registers - 1;
            let pool_index = module
                .constant_pool
                .iter()
                .position(|text| text == "object-assign-label-marker")
                .expect("unique labelled selector") as u32;
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
            assert_eq!(replacements, 1, "{name}: only selector is labelled");
            let mut core = InterpreterCore::new(config.clone(), "assign-label");
            core.seed_register(input_register, Value::Bool(true))
                .unwrap();
            core.set_register_label(input_register, Label::Secret)
                .unwrap();
            let result = core
                .execute(&module)
                .expect("Object.assign label fixture executes");
            assert_eq!(result.value, Value::Int(expected), "{name}");
            assert_eq!(
                result.completion_label.join(&Label::Secret),
                result.completion_label,
                "{name}: a callback's constant effect must retain selection provenance"
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "{name}: observation scope accounting"
            );
        }
    }
}

#[test]
fn assign_preserves_proxy_set_and_define_traps_for_callable_and_native_targets() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(ok, detail) { if (!ok) failures.push(detail); }
  const factories = [
    ['object', () => ({})],
    ['function', () => function () {}],
    ['bound', () => (function () {}).bind(null)],
    ['builtin', () => Math.abs],
    ['promise', () => Promise.resolve(1)],
    ['generator', () => (function* () { yield 1; })()],
    ['iterator', () => [1].values()],
    ['async-generator', () => (async function* () { yield 1; })()]
  ];
  for (const [name, create] of factories) {
    const target = create();
    const originalPrototype = Object.getPrototypeOf(target);
    const prototype = Object.create(originalPrototype);
    const events = [];
    let proxy;
    Object.defineProperty(prototype, 'accepted', {
      set(value) { events.push('setter:' + value + ':' + (this === proxy)); }
    });
    Object.setPrototypeOf(target, prototype);
    const handler = {
      set(object, key, value, receiver) {
        events.push('set:' + key + ':' + (object === target) + ':' + (receiver === proxy));
        return Reflect.set(object, key, value, receiver);
      },
      defineProperty(object, key, descriptor) {
        events.push('define:' + key + ':' + (object === target) + ':' + descriptor.value
          + ':' + descriptor.writable + ':' + descriptor.enumerable + ':' + descriptor.configurable);
        return Reflect.defineProperty(object, key, descriptor);
      }
    };
    proxy = new Proxy(target, handler);
    check(Object.assign(proxy, { copied: 1, accepted: 2 }, 'a') === proxy, name + ':return');
    check(events.join('|') ===
      'set:copied:true:true|define:copied:true:1:true:true:true|set:accepted:true:true|setter:2:true|set:0:true:true|define:0:true:a:true:true:true',
      name + ':traps:' + events.join('|'));
    check(target.copied === 1 && target[0] === 'a' && !Object.hasOwn(target, 'accepted'),
      name + ':storage');
    check(typeof proxy === typeof target, name + ':kind');
    Object.setPrototypeOf(target, originalPrototype);
  }
  return failures.join('|') || 'ok';
})()"#,
        "ok",
    );
}

#[test]
fn assign_preserves_abrupt_completion_and_the_completed_copy_prefix() {
    assert_profile_value(
        r#"(function () {
  const failures = [];
  function check(ok, detail) { if (!ok) failures.push(detail); }
  const factories = [
    ['object', () => ({})],
    ['function', () => function () {}],
    ['promise', () => Promise.resolve(1)],
    ['generator', () => (function* () { yield 1; })()],
    ['iterator', () => [1].values()],
    ['async-generator', () => (async function* () { yield 1; })()]
  ];
  for (const [name, create] of factories) {
    const target = create();
    const sentinel = {};
    const events = [];
    Object.defineProperty(target, 'stop', {
      set(value) {
        events.push('stop:' + value + ':' + (this === target));
        throw sentinel;
      }
    });
    const source = {
      get first() { events.push('first'); return 1; },
      get stop() { events.push('read-stop'); return 2; },
      get after() { events.push('after'); return 3; }
    };
    let error;
    try { Object.assign(target, source, { later: 4 }); } catch (caught) { error = caught; }
    check(error === sentinel, name + ':error');
    check(events.join('|') === 'first|read-stop|stop:2:true', name + ':order');
    check(target.first === 1 && !Object.hasOwn(target, 'after')
      && !Object.hasOwn(target, 'later'), name + ':partial');

    const stringTarget = create();
    let stringReceiver = false;
    Object.defineProperty(stringTarget, '1', {
      set(value) {
        stringReceiver = this === stringTarget && value === 'b';
        throw sentinel;
      }
    });
    error = undefined;
    try { Object.assign(stringTarget, 'abc', { later: 4 }); } catch (caught) { error = caught; }
    check(error === sentinel && stringReceiver, name + ':string-error');
    check(stringTarget[0] === 'a' && !Object.hasOwn(stringTarget, '2')
      && !Object.hasOwn(stringTarget, 'later'), name + ':string-partial');
  }

  const functionTarget = function () {};
  const events = [];
  const proxy = new Proxy(functionTarget, {
    set(target, key, value, receiver) {
      events.push('set:' + key);
      return key !== 'stop' && Reflect.set(target, key, value, receiver);
    },
    defineProperty(target, key, descriptor) {
      events.push('define:' + key);
      return Reflect.defineProperty(target, key, descriptor);
    }
  });
  let error;
  try { Object.assign(proxy, { first: 1, stop: 2, after: 3 }); } catch (caught) { error = caught; }
  check(error instanceof TypeError, 'proxy:error');
  check(events.join('|') === 'set:first|define:first|set:stop', 'proxy:order');
  check(functionTarget.first === 1 && !Object.hasOwn(functionTarget, 'stop')
    && !Object.hasOwn(functionTarget, 'after'), 'proxy:partial');

  const copyingSource = {
    get first() {
      delete this.removed;
      Object.defineProperty(this, 'hidden', { enumerable: false });
      this.added = 4;
      return 1;
    },
    removed: 2,
    hidden: 3
  };
  const copy = Object.assign(Promise.resolve(1), copyingSource);
  check(copy.first === 1 && !Object.hasOwn(copy, 'removed')
    && !Object.hasOwn(copy, 'hidden') && !Object.hasOwn(copy, 'added'), 'source:snapshot');
  return failures.join('|') || 'ok';
})()"#,
        "ok",
    );
}
