//! First-class timer modules must use the existing native scheduler and authority.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn execute(source: &str, goal: ParseGoal, allow_timer: bool) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource { label: "timers-module.js".into(), text: source.into() },
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
    let mut config = InterpreterConfig::quickjs_defaults();
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
    let result = core.execute(&module);
    assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    result
        .map(|result| result.console_output.iter().map(|entry| entry.message.as_str())
            .collect::<Vec<_>>().join("\n"))
        .map_err(|error| format!("execute: {error}"))
}

fn check(source: &str, expected: &str) {
    assert_eq!(execute(source, ParseGoal::Script, true).as_deref(), Ok(expected));
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
    check(IDENTITY, "true true\ntrue true true true true true true\ntrue true\nfunction true true");
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
    check(SHADOWS, "guest Object guest interval guest clear guest immediate\nnative");
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
    assert_eq!(execute(ESM, ParseGoal::Module, true).as_deref(), Ok("true true\nesm\ntick"));
}

#[test]
fn loading_timer_modules_schedules_nothing_and_needs_no_timer_authority() {
    assert_eq!(execute(IDENTITY, ParseGoal::Script, false).as_deref(),
        Ok("true true\ntrue true true true true true true\ntrue true\nfunction true true"));
}

#[test]
fn first_class_invocation_does_not_grant_timer_authority() {
    for source in [
        "const t = require('timers'); const run = t.setTimeout; run(() => {}, 1);",
        "const t = require('timers'); const run = t.setImmediate; run(() => {});",
        "const t = require('timers/promises'); const run = t.setTimeout; run(1);",
    ] {
        let error = execute(source, ParseGoal::Script, false).expect_err("Timer grant is required");
        assert!(error.to_lowercase().contains("capability"), "{source}: {error}");
    }
}
