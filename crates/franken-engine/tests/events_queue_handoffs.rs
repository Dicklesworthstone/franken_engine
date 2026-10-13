//! Event iterator handoffs and backpressure through the native execution path.
//! The JavaScript fixtures are also run against Node and the exact prelude by
//! scripts/tests/events_queue.cjs. Those host runs do not execute these tests.

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn assert_events(source: &str, expected: &str) {
    let tree = parse_script(source).expect("events source parses");
    let lowered = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "events-queue-handoffs.js"),
        &LoweringContext::new("events-queue", "handoff-regression", "builtin-only"),
    )
    .expect("events source lowers");
    for throughput in [false, true] {
        for stress in [None, Some(7)] {
            let mut config = if throughput {
                InterpreterConfig::v8_defaults()
            } else {
                InterpreterConfig::quickjs_defaults()
            };
            config.instruction_budget = 100_000_000;
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "events-queue");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&lowered.ir3).expect("events source executes");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "throughput={throughput}, GC={stress:?}: memory accounting"
            );
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(actual, expected, "throughput={throughput}, GC={stress:?}");
        }
    }
}

const SINGLE_SOURCE: &str = r#"
const E = require('events'); const e = new E();
const it = E.on(e, 'data', {close: ['end']}); const marker = {kept: true};
(async () => {
  let sum = 0;
  for (let i = 0; i < 256; i++) {
    const wait = it.next(); e.emit('data', i, marker, undefined);
    const item = await wait;
    if (item.done || item.value[1] !== marker || item.value[2] !== undefined) throw Error('handoff');
    sum += item.value[0];
  }
  e.emit('end');
  console.log(sum, (await it.next()).done, e.listenerCount('data'), e.listenerCount('error'));
})().catch(error => console.log('FAIL', error.message));
"#;
const SINGLE_EXPECTED: &str = r#"32640 true 0 0"#;

#[test]
fn single_pending_reads_preserve_payloads_and_memory_accounting() {
    assert_events(SINGLE_SOURCE, SINGLE_EXPECTED);
}

const OVERFLOW_SOURCE: &str = r#"
const E = require('node:events'); const e = new E();
const it = E.on(e, 'data', {close: ['end']}); const waits = [];
for (let i = 0; i < 65; i++) waits.push(it.next());
for (let i = 0; i < 33; i++) e.emit('data', i);
for (let i = 0; i < 33; i++) waits.push(it.next());
for (let i = 33; i < 98; i++) e.emit('data', i);
e.emit('end');
(async () => {
  let sum = 0;
  for (let i = 0; i < waits.length; i++) {
    const item = await waits[i];
    if (item.done || item.value[0] !== i) throw Error('FIFO');
    sum += item.value[0];
  }
  console.log(waits.length, sum, (await it.next()).done, e.eventNames().length);
})().catch(error => console.log('FAIL', error.message));
"#;
const OVERFLOW_EXPECTED: &str = r#"98 4753 true 0"#;

#[test]
fn concurrent_reads_keep_overflow_before_new_waiters() {
    assert_events(OVERFLOW_SOURCE, OVERFLOW_EXPECTED);
}

const TERMINALS_SOURCE: &str = r#"
const E = require('events');
(async () => {
  for (const mode of ['return', 'close', 'error', 'abort', 'throw']) {
    const e = new E(); const controller = new AbortController();
    const error = new Error('terminal'); const waits = [];
    const it = E.on(e, 'data', {signal: controller.signal, close: ['end']});
    for (let i = 0; i < 33; i++) {
      waits.push(it.next().then(item => item.done ? 'done' : 'value', failure => {
        if (mode === 'abort' ? failure.cause !== error : failure !== error) throw Error('identity');
        return 'error';
      }));
    }
    e.emit('data', 7);
    if (mode === 'return') await it.return();
    if (mode === 'close') e.emit('end');
    if (mode === 'error') e.emit('error', error);
    if (mode === 'abort') controller.abort(error);
    if (mode === 'throw') it.throw(error);
    let values = 0, errors = 0, done = 0;
    for (const wait of waits) {
      const item = await wait;
      if (item === 'value') values++;
      if (item === 'error') errors++;
      if (item === 'done') done++;
    }
    console.log(mode, values, errors, done, e.eventNames().length);
  }
})().catch(error => console.log('FAIL', error.message));
"#;
const TERMINALS_EXPECTED: &str = r#"return 1 0 32 0
close 1 0 32 0
error 1 1 31 0
abort 1 1 31 0
throw 1 1 31 0"#;

#[test]
fn termination_settles_inline_and_overflow_waiters_once() {
    assert_events(TERMINALS_SOURCE, TERMINALS_EXPECTED);
}

const REENTRY_SOURCE: &str = r#"
const E = require('events'); const e = new E(); const calls = []; let resumed = false;
e.pause = () => calls.push('pause');
e.resume = () => {
  calls.push('resume');
  if (!resumed) { resumed = true; for (let i = 65; i < 130; i++) e.emit('data', i); }
};
const it = E.on(e, 'data', {highWaterMark: 32, lowWaterMark: 16});
for (let i = 0; i < 65; i++) e.emit('data', i);
(async () => {
  let sum = 0;
  for (let i = 0; i < 130; i++) {
    const item = await it.next();
    if (item.value[0] !== i) throw Error('reentrant FIFO');
    sum += item.value[0];
  }
  await it.return();
  console.log(sum, calls.join(':'), e.eventNames().length);
})().catch(error => console.log('FAIL', error.message));
"#;
const REENTRY_EXPECTED: &str = r#"8385 pause:resume 0"#;

#[test]
fn resume_can_produce_without_nested_pause_transitions() {
    assert_events(REENTRY_SOURCE, REENTRY_EXPECTED);
}

const RESUME_ERROR_SOURCE: &str = r#"
const E = require('events'); const e = new E(); const error = new Error('resume');
const calls = []; let attempts = 0;
e.pause = () => calls.push('pause');
e.resume = () => { calls.push('resume'); if (++attempts === 1) throw error; };
const it = E.on(e, 'data', {highWaterMark: 1, lowWaterMark: 2});
for (let i = 0; i < 3; i++) e.emit('data', i);
(async () => {
  const first = await it.next(); let same = false;
  try { await it.next(); } catch (failure) { same = failure === error; }
  const last = await it.next(); await it.return();
  console.log(first.value[0], same, last.value[0], attempts, calls.join(':'), e.eventNames().length);
})().catch(error => console.log('FAIL', error.message));
"#;
const RESUME_ERROR_EXPECTED: &str = r#"0 true 2 2 pause:resume:resume 0"#;

#[test]
fn failed_resume_retains_paused_state_for_retry() {
    assert_events(RESUME_ERROR_SOURCE, RESUME_ERROR_EXPECTED);
}
