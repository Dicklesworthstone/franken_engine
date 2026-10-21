//! Event delivery retains its initialized realm Promise operations.
//! scripts/test_events_promise_intrinsics.cjs also runs these exact programs
//! against live Node and the production factory on Node transport primitives.

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn check(source: &str, expected: &str) {
    let tree = parse_script(source).expect("event fixture parses");
    let lowered = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "events-promises.js"),
        &LoweringContext::new("events-promises", "intrinsic-regression", "builtin-only"),
    )
    .expect("event fixture lowers");
    for throughput in [false, true] {
        for stress in [None, Some(1), Some(7)] {
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
            let mut core = InterpreterCore::new(config, "events-promises");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&lowered.ir3).expect("event fixture executes");
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
            let actual = result.console_output.iter()
                .map(|entry| entry.message.as_str()).collect::<Vec<_>>().join("\n");
            assert_eq!(actual, expected, "throughput={throughput}, GC={stress:?}");
        }
    }
}

const BUFFERED_SOURCE: &str = r#"
const E = require('events');
const P = Promise, resolve = P.resolve, reject = P.reject;
(async () => {
  for (const mode of ['constructor', 'resolve', 'reject']) {
    const e = new E(), it = E.on(e, 'data');
    const value = {identity: true}, failure = new Error('original');
    let calls = 0, first, second, done, returned;
    function poison() { calls++; throw Error('replaced Promise'); }
    e.emit('data', value, undefined); e.emit('error', failure);
    try {
      if (mode === 'constructor') globalThis.Promise = poison;
      if (mode === 'resolve') P.resolve = poison;
      if (mode === 'reject') P.reject = poison;
      first = it.next();
      second = it.next().then(() => false, error => error === failure);
      done = it.next(); returned = it.return();
    } finally {
      globalThis.Promise = P; P.resolve = resolve; P.reject = reject;
    }
    const item = await first;
    console.log(mode, calls, item.value[0] === value, item.value[1] === undefined,
      await second, (await done).done, (await returned).done, e.eventNames().length);
  }
})().catch(error => console.log('FAIL', error.message));
"#;
const BUFFERED_EXPECTED: &str = r#"constructor 0 true true true true true 0
resolve 0 true true true true true 0
reject 0 true true true true true 0"#;

#[test]
fn replaced_helpers_cannot_lose_buffered_values_or_terminal_errors() {
    check(BUFFERED_SOURCE, BUFFERED_EXPECTED);
}

const PENDING_SOURCE: &str = r#"
const E = require('node:events');
const P = Promise, resolve = P.resolve, reject = P.reject;
const e = new E(), it = E.on(e, 'data');
const failure = new Error('failure'), marker = {identity: true};
const waits = [];
let calls = 0, once, onceError;
function poison() { calls++; throw Error('replaced Promise'); }
try {
  globalThis.Promise = poison; P.resolve = poison; P.reject = poison;
  for (let i = 0; i < 65; i++) {
    waits.push(it.next().then(item => item.done ? 'done' : item.value,
      error => error === failure ? 'error' : 'wrong'));
  }
  once = E.once(e, 'once'); e.emit('once', marker, undefined);
  onceError = E.once(e, 'failure').then(() => false, error => error === failure);
  for (let i = 0; i < 33; i++) e.emit('data', i, marker);
  e.emit('error', failure);
} finally {
  globalThis.Promise = P; P.resolve = resolve; P.reject = reject;
}
(async () => {
  let sum = 0, errors = 0, done = 0;
  for (let i = 0; i < waits.length; i++) {
    const value = await waits[i];
    if (value === 'error') errors++;
    else if (value === 'done') done++;
    else {
      if (value[0] !== i || value[1] !== marker) throw Error('FIFO or identity');
      sum += value[0];
    }
  }
  const item = await once;
  console.log('pending', calls, sum, errors, done, item[0] === marker,
    item[1] === undefined, await onceError, e.eventNames().length);
})().catch(error => console.log('FAIL', error.message));
"#;
const PENDING_EXPECTED: &str = r#"pending 0 528 1 31 true true true 0"#;

#[test]
fn replaced_constructor_cannot_intercept_waiters_once_or_error_cleanup() {
    check(PENDING_SOURCE, PENDING_EXPECTED);
}
