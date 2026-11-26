//! First-class timer modules must use the existing native scheduler and authority.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn execute(source: &str, goal: ParseGoal, allow_timer: bool) -> Result<String, String> {
    execute_with_options(source, goal, allow_timer, false, false)
}

fn execute_with_options(
    source: &str,
    goal: ParseGoal,
    allow_timer: bool,
    throughput: bool,
    stress_gc: bool,
) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "timers-module.js".into(),
                text: source.into(),
            },
            goal,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "timers-module.js"),
        &LoweringContext::new("timers-module", "timer-module-load", "caller-authority"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3;
    let mut config = if throughput {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    if allow_timer {
        config.granted_capabilities.insert(RuntimeCapability::Timer);
    }
    let mut core = InterpreterCore::new(config, "timers-module");
    core.set_gc_stress_interval(stress_gc.then_some(1));
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    result
        .map(|result| {
            result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .map_err(|error| format!("execute: {error}"))
}

fn check(source: &str, expected: &str) {
    assert_eq!(
        execute(source, ParseGoal::Script, true).as_deref(),
        Ok(expected)
    );
}

const IDENTITY: &str = r#"
const timers = require('timers');
const promises = require('timers/promises');
console.log(timers === require('node:timers'), promises === require('node:timers/promises'));
console.log(timers.promises === promises, timers.setTimeout === setTimeout,
  timers.clearTimeout === clearTimeout, timers.setInterval === setInterval,
  timers.clearInterval === clearInterval, timers.setImmediate === setImmediate,
  timers.clearImmediate === clearImmediate);
function keep(value) { return value; }
console.log(keep(timers) === timers, (() => require('timers'))() === timers);
const descriptor = Object.getOwnPropertyDescriptor(timers, 'promises');
console.log(typeof descriptor.get, descriptor.enumerable, descriptor.configurable);
"#;

#[test]
fn native_identities_and_aliases_survive_materialization() {
    check(
        IDENTITY,
        "true true\ntrue true true true true true true\ntrue true\nfunction true true",
    );
}

const CALLBACKS: &str = r#"
(async () => {
  var timers = require('timers');
  let schedule = timers['setImmediate'];
  console.log(typeof schedule);
  await new Promise(resolve => schedule((a, b) => {
    console.log(a, b);
    resolve();
  }, 'xml2js', 42));
  const pending = timers.setTimeout(() => console.log('wrong'), 1000);
  timers.clearTimeout(pending);
  await new Promise(resolve => timers.setTimeout(resolve, 1));
  console.log('cleared');
})()
"#;

#[test]
fn computed_and_saved_callback_functions_preserve_arguments_and_cancellation() {
    check(CALLBACKS, "function\nxml2js 42\ncleared");
}

const PROMISES: &str = r#"
(async () => {
  const { setTimeout: sleep, setImmediate: immediate } = require('timers/promises');
  const payload = { answer: 42 };
  console.log((await sleep(1, payload)) === payload);
  console.log((await immediate(payload)) === payload);
  console.log((await sleep()) === undefined);
  const alias = (() => require('node:timers/promises'))();
  console.log((await alias['setTimeout'](1, 'nested')));
})()
"#;

#[test]
fn destructured_promise_functions_preserve_values_and_defaults() {
    check(PROMISES, "true\ntrue\ntrue\nnested");
}

const INTERVAL: &str = r#"
(async () => {
  const { setInterval: every } = require('node:timers/promises');
  const payload = { value: 7 };
  let count = 0;
  for await (const value of every(1, payload)) {
    console.log(value === payload);
    if (++count === 2) break;
  }
  console.log('closed', count);
})()
"#;

#[test]
fn saved_interval_function_uses_native_iterator_and_closes_on_break() {
    check(INTERVAL, "true\ntrue\nclosed 2");
}

const ORDER: &str = r#"
(async () => {
  const { setTimeout: sleep } = require('timers/promises');
  const order = [];
  const pending = sleep(1, 'timer').then(value => order.push(value));
  Promise.resolve().then(() => order.push('promise'));
  queueMicrotask(() => order.push('microtask'));
  order.push('sync');
  await pending;
  console.log(order.join(','));
})()
"#;

#[test]
fn promise_module_does_not_change_scheduler_reaction_order() {
    check(ORDER, "sync,promise,microtask,timer");
}

const SHADOWS: &str = r#"
const { setTimeout, clearTimeout, setImmediate } = require('timers');
const Object = 'guest Object';
const setInterval = 'guest interval';
const clearInterval = 'guest clear';
const clearImmediate = 'guest immediate';
const promises = require('timers/promises');
(async () => {
  await new Promise(resolve => setImmediate(resolve));
  const pending = setTimeout(() => console.log('wrong'), 1000);
  clearTimeout(pending);
  console.log(Object, setInterval, clearInterval, clearImmediate);
  console.log(await promises.setTimeout(1, 'native'));
})()
"#;

#[test]
fn module_prelude_does_not_capture_guest_globals_or_destructuring_bindings() {
    check(
        SHADOWS,
        "guest Object guest interval guest clear guest immediate\nnative",
    );
}

const HANDLES: &str = r#"
const timers = require('timers');
const pending = timers.setTimeout(() => console.log('wrong'), 1000);
console.log(typeof pending, pending.hasRef());
console.log(pending.unref() === pending, pending.hasRef());
console.log(pending.ref() === pending, pending.hasRef());
timers.clearTimeout(pending);
"#;

#[test]
fn callback_module_returns_native_ref_counted_handles() {
    check(HANDLES, "object true\ntrue false\ntrue true");
}

const ESM: &str = r#"
import timers, { setImmediate as schedule } from 'node:timers';
import promises, { setTimeout as sleep, setInterval as every } from 'node:timers/promises';
(async () => {
  console.log(schedule === timers.setImmediate, sleep === promises.setTimeout);
  await new Promise(resolve => schedule(resolve));
  console.log(await sleep(1, 'esm'));
  for await (const value of every(1, 'tick')) {
    console.log(value);
    break;
  }
})()
"#;

#[test]
fn esm_named_imports_are_real_function_values_not_call_site_rewrites() {
    assert_eq!(
        execute(ESM, ParseGoal::Module, true).as_deref(),
        Ok("true true\nesm\ntick")
    );
}

#[test]
fn loading_timer_modules_schedules_nothing_and_needs_no_timer_authority() {
    assert_eq!(
        execute(IDENTITY, ParseGoal::Script, false).as_deref(),
        Ok("true true\ntrue true true true true true true\ntrue true\nfunction true true")
    );
}

#[test]
fn first_class_invocation_does_not_grant_timer_authority() {
    for source in [
        "const t = require('timers'); const run = t.setTimeout; run(() => {}, 1);",
        "const t = require('timers'); const run = t.setImmediate; run(() => {});",
        "const t = require('timers/promises'); const run = t.setTimeout; run(1);",
        "const t = require('timers/promises'); const run = t.setImmediate; run();",
        "const t = require('timers/promises'); const run = t.setInterval; run(1);",
    ] {
        let error = match execute(source, ParseGoal::Script, false) {
            Err(error) => error,
            Ok(output) => panic!("Timer grant is required: {source}; got {output:?}"),
        };
        assert!(
            error.to_lowercase().contains("capability"),
            "{source}: {error}"
        );
    }
}

#[test]
fn timer_promisify_getters_are_nonconstructible_without_timer_authority() {
    let source = r#"
const timers=require('node:timers'), promises=require('node:timers/promises');
const custom=Symbol.for('nodejs.util.promisify.custom');
for(const name of ['setTimeout','setImmediate']) {
 const descriptor=Object.getOwnPropertyDescriptor(timers[name],custom), get=descriptor.get;
 let construction=false, newTarget=false;
 try{Reflect.construct(get,[]);}catch(error){construction=error instanceof TypeError;}
 try{Reflect.construct(function(){},[],get);}catch(error){newTarget=error instanceof TypeError;}
 console.log('GETTER',name,get.name==='get',get.length===0,
  !Object.prototype.hasOwnProperty.call(get,'prototype'),
  descriptor.enumerable && !descriptor.configurable && descriptor.set===undefined,
  get.call(null)===promises[name],construction,newTarget);
}
"#;
    assert_eq!(
        execute(source, ParseGoal::Script, false).as_deref(),
        Ok(
            "GETTER setTimeout true true true true true true true\nGETTER setImmediate true true true true true true true"
        )
    );
}

#[test]
fn scheduler_exports_share_native_timer_operations() {
    check(
        r#"
const timers = require('node:timers');
const promises = require('node:timers/promises');
const custom = Symbol.for('nodejs.util.promisify.custom');
(async () => {
  console.log(promises.scheduler === timers.promises.scheduler);
  console.log(timers.setTimeout[custom] === promises.setTimeout,
    timers.setImmediate[custom] === promises.setImmediate,
    timers.setInterval[custom] === undefined);
  const payload = { answer: 42 };
  console.log((await timers.setTimeout[custom](1, payload)) === payload);
  console.log((await timers.setImmediate[custom](payload)) === payload);
  console.log((await promises.scheduler.wait(1)) === undefined);
  console.log((await promises.scheduler.yield()) === undefined);
})()
"#,
        "true\ntrue true true\ntrue\ntrue\ntrue\ntrue",
    );
}

#[test]
fn scheduler_invocation_retains_timer_capability_boundary() {
    let shape = r#"
const timers = require('timers');
const custom = Symbol.for('nodejs.util.promisify.custom');
console.log(typeof timers.promises.scheduler.wait,
  typeof timers.promises.scheduler.yield,
  typeof timers.setTimeout[custom],
  typeof timers.setImmediate[custom]);
"#;
    assert_eq!(
        execute(shape, ParseGoal::Script, false).as_deref(),
        Ok("function function function function")
    );
    for source in [
        "require('timers/promises').scheduler.wait(1);",
        "require('timers/promises').scheduler.yield();",
        "require('timers').setTimeout[Symbol.for('nodejs.util.promisify.custom')](1);",
        "require('timers').setImmediate[Symbol.for('nodejs.util.promisify.custom')]();",
    ] {
        let error = match execute(source, ParseGoal::Script, false) {
            Err(error) => error,
            Ok(output) => panic!("timer authority remains required: {source}; got {output:?}"),
        };
        assert!(
            error.to_lowercase().contains("capability"),
            "{source}: {error}"
        );
    }
}

fn check_promise_resolution(source: &str, expected: &str) {
    for throughput in [false, true] {
        for stress_gc in [false, true] {
            assert_eq!(
                execute_with_options(source, ParseGoal::Script, true, throughput, stress_gc)
                    .as_deref(),
                Ok(expected),
                "throughput={throughput}, stress_gc={stress_gc}"
            );
        }
    }
}

#[test]
fn promise_timers_preserve_exact_primitive_and_callable_values() {
    check_promise_resolution(
        r#"
(async () => {
  const { setTimeout: sleep, setImmediate: immediate } = require('timers/promises');
  const closure = function marker() { return 17; };
  const payload = { answer: 42 };
  const values = [
    123456789012345678901234567890n, '\ud800x\udfff',
    closure, closure.bind(payload), Math.abs,
    (function* () { yield payload; })(),
    (async function* () { yield payload; })(),
    [payload].values(), 'x'[Symbol.iterator](),
    payload, Symbol('timer'), undefined, null, NaN, -0
  ];
  for (const schedule of [value => sleep(1, value), value => immediate(value)]) {
    let exact = 0;
    for (const value of values) {
      if (Object.is(await schedule(value), value)) exact++;
    }
    console.log(exact, values.length);
  }
})()
"#,
        "15 15\n15 15",
    );
}

#[test]
fn promise_timers_observe_then_at_delivery_and_settle_once() {
    check_promise_resolution(
        r#"
(async () => {
  const { setTimeout: sleep, setImmediate: immediate } = require('timers/promises');
  for (const schedule of [value => sleep(1, value), value => immediate(value)]) {
    const trace = [];
    const payload = function () { return 'ready'; };
    let reads = 0;
    const value = Object.defineProperty({}, 'then', {
      get() {
        reads++;
        trace.push('get');
        return function (resolve, reject) {
          trace.push(this === value ? 'receiver' : 'wrong-receiver');
          resolve(payload);
          reject('ignored rejection');
          resolve('ignored resolution');
          throw 'ignored throw';
        };
      }
    });
    const pending = schedule(value);
    trace.push('scheduled');
    Promise.resolve().then(() => trace.push('micro'));
    console.log(reads);
    const result = await pending;
    console.log(trace.join(','), reads, result === payload, result());
  }
})()
"#,
        "0\nscheduled,micro,get,receiver 1 true ready\n0\nscheduled,micro,get,receiver 1 true ready",
    );
}

#[test]
fn promise_timers_adopt_promises_and_preserve_abrupt_resolution() {
    check_promise_resolution(
        r#"
(async () => {
  const { setTimeout: sleep, setImmediate: immediate } = require('timers/promises');
  for (const schedule of [value => sleep(1, value), value => immediate(value)]) {
    const payload = function () { return 42; };
    console.log('fulfilled', (await schedule(Promise.resolve(payload))) === payload);
    let settle;
    const input = new Promise(resolve => { settle = resolve; });
    const output = schedule(input);
    setTimeout(() => settle(payload), 2);
    console.log('pending', (await output) === payload);

    const reason = function rejected() {};
    const rejected = Promise.reject(reason);
    rejected.catch(() => {});
    try { await schedule(rejected); } catch (error) {
      console.log('rejected', error === reason);
    }
    const getterFailure = Object.defineProperty({}, 'then', {
      get() { throw reason; }
    });
    try { await schedule(getterFailure); } catch (error) {
      console.log('getter', error === reason);
    }
    try { await schedule({ then() { throw reason; } }); } catch (error) {
      console.log('method', error === reason);
    }
    const plain = { then: 7 };
    console.log('noncallable', (await schedule(plain)) === plain);
    const overridden = Promise.resolve('original');
    overridden.then = function (resolve) {
      console.log('override receiver', this === overridden);
      resolve(payload);
    };
    console.log('override', (await schedule(overridden)) === payload);
    let cyclic;
    cyclic = schedule({ then(resolve) { resolve(cyclic); } });
    try { await cyclic; } catch (error) {
      console.log('cycle', error instanceof TypeError);
    }
  }
})()
"#,
        "fulfilled true\npending true\nrejected true\ngetter true\nmethod true\nnoncallable true\noverride receiver true\noverride true\ncycle true\nfulfilled true\npending true\nrejected true\ngetter true\nmethod true\nnoncallable true\noverride receiver true\noverride true\ncycle true",
    );
}

#[test]
fn promise_timers_keep_queued_values_alive_through_observable_getters() {
    check_promise_resolution(
        r#"
(async () => {
  const { setTimeout: sleep, setImmediate: immediate } = require('timers/promises');
  for (const schedule of [value => sleep(1, value), value => immediate(value)]) {
    const trace = [];
    function churn() {
      const garbage = [];
      for (let i = 0; i < 24; i++) garbage.push({ index: i, nested: [i] });
      return garbage.length;
    }
    function enqueueCallable() {
      const callable = function () { return 'live callable'; };
      callable.payload = { answer: 42 };
      Object.defineProperty(callable, 'then', {
        get() {
          churn();
          trace.push('callable ' + this.payload.answer);
          return undefined;
        }
      });
      return schedule(callable);
    }
    const callable = await enqueueCallable();
    console.log(callable(), callable.payload.answer, trace.join(','));
    trace.length = 0;
    function enqueuePromise() {
      const payload = function () { return 'live promise'; };
      const input = Promise.resolve(payload);
      Object.defineProperty(input, 'then', {
        get() {
          churn();
          trace.push('then');
          return Promise.prototype.then;
        }
      });
      Object.defineProperty(input, 'constructor', {
        get() {
          churn();
          trace.push('constructor');
          return {
            get [Symbol.species]() {
              churn();
              trace.push('species');
              return Promise;
            }
          };
        }
      });
      return schedule(input);
    }
    const payload = await enqueuePromise();
    console.log(payload(), trace.join(','));
  }
})()
"#,
        "live callable 42 callable 42\nlive promise then,constructor,species\nlive callable 42 callable 42\nlive promise then,constructor,species",
    );
}
