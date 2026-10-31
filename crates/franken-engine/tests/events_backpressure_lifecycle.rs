//! Backpressure and cancellation through the real events-module lowering.
//! These fixtures deliberately strengthen Node 22's reentrant-resume behavior:
//! a synchronous producer must observe a new pause before resume() returns.
#![forbid(unsafe_code)]

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn assert_events(source: &str, expected: &str) {
    let tree = parse_script(source).expect("backpressure fixture parses");
    let lowered = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "events-backpressure.js"),
        &LoweringContext::new("events-backpressure", "bd-305gi", "builtin-only"),
    )
    .expect("events lowering requires no filesystem or module-load grant");
    for throughput in [false, true] {
        for stress in [None, Some(7)] {
            let mut config = if throughput {
                InterpreterConfig::v8_defaults()
            } else {
                InterpreterConfig::quickjs_defaults()
            };
            config.instruction_budget = 20_000_000;
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "events-backpressure");
            core.set_gc_stress_interval(stress);
            let output = core.execute(&lowered.ir3).expect("native events execution");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "throughput={throughput}, stress={stress:?}"
            );
            assert_eq!(
                output
                    .console_output
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
                expected,
                "throughput={throughput}, stress={stress:?}"
            );
        }
    }
}

const SYNCHRONOUS_REFILL: &str = r#"
const E = require('events'); const e = new E();
let produced = 0, consumed = 0, paused = false, peak = 0;
e.pause = function () { paused = true; };
e.resume = function () {
  paused = false;
  while (!paused && produced < 96) {
    const value = produced++;
    peak = Math.max(peak, produced - consumed);
    e.emit('data', value);
  }
  if (produced === 96) e.emit('end');
};
const it = E.on(e, 'data', { highWaterMark: 2, lowWaterMark: 1, close: ['end'] });
e.resume();
(async () => {
  let count = 0, sum = 0;
  while (true) {
    consumed++;
    const step = await it.next();
    if (step.done) break;
    if (step.value[0] !== count) throw new Error('out-of-order event');
    sum += step.value[0]; count++;
  }
  if (peak !== 3) throw new Error('lost backpressure');
  if (e.listenerCount('data') !== 0 || e.listenerCount('error') !== 0)
    throw new Error('listeners retained');
  console.log('fifo', count, sum, peak);
})();
"#;

#[test]
fn synchronous_producers_remain_bounded_in_both_profiles_and_gc_modes() {
    assert_events(SYNCHRONOUS_REFILL, "fifo 96 4560 3");
}

const TERMINAL_AND_FAILURE: &str = r#"
const E = require('node:events');
(async () => {
  for (const mode of ['return', 'end', 'abort']) {
    const e = new E(), c = new AbortController(); let resumes = 0;
    e.pause = function () {};
    e.resume = function () { resumes++; };
    const it = E.on(e, 'data', { highWaterMark: 1, lowWaterMark: 1,
      close: ['end'], signal: c.signal });
    e.emit('data', 1); e.emit('data', 2);
    if (mode === 'return') await it.return();
    else if (mode === 'end') e.emit('end');
    else c.abort('stop');
    const first = await it.next(), second = await it.next();
    if (mode === 'abort') {
      let refused = false;
      try { await it.next(); } catch (error) {
        refused = error.code === 'ABORT_ERR' && error.cause === 'stop';
      }
      if (!refused) throw new Error('cancellation was lost');
    }
    const done = await it.next();
    console.log('terminal', mode, first.value[0] * 10 + second.value[0], resumes, done.done);
  }
  for (const failure of [false, null, undefined]) {
    const e = new E(); e.pause = function () {};
    e.resume = function () { throw failure; };
    const it = E.on(e, 'data', { highWaterMark: 1, lowWaterMark: 1 });
    e.emit('data', 1); e.emit('data', 2);
    const first = await it.next(), second = await it.next();
    let caught = false;
    try { await it.next(); } catch (error) { caught = error === failure; }
    const done = await it.next();
    console.log('failure', String(failure), first.value[0] * 10 + second.value[0], caught, done.done);
    if (e.listenerCount('data') || e.listenerCount('error')) throw new Error('failed owner retained');
  }
})();
"#;

#[test]
fn closed_consumers_do_not_restart_sources_or_lose_reserved_events() {
    assert_events(
        TERMINAL_AND_FAILURE,
        "terminal return 12 0 true\nterminal end 12 0 true\nterminal abort 12 0 true\n\
         failure false 12 true true\nfailure null 12 true true\n\
         failure undefined 12 true true",
    );
}

const REENTRANT_DEMAND: &str = r#"
const E = require('events'); const e = new E();
const pending = []; let it, produced = 0, paused = false, depth = 0, peakDepth = 0;
e.pause = function () {
  paused = true;
  if (produced < 96) for (let i = 0; i < 4; i++) pending.push(it.next());
};
e.resume = function () {
  depth++; peakDepth = Math.max(peakDepth, depth); paused = false;
  while (!paused && produced < 96) e.emit('data', produced++);
  if (produced === 96) e.emit('end');
  depth--;
};
it = E.on(e, 'data', { highWaterMark: 2, lowWaterMark: 1, close: ['end'] });
e.resume();
(async () => {
  let count = 0, sum = 0;
  for (const step of await Promise.all(pending)) {
    if (step.done) continue;
    if (step.value[0] !== count) throw new Error('reentrant order');
    count++; sum += step.value[0];
  }
  for await (const values of it) {
    if (values[0] !== count) throw new Error('drain order');
    count++; sum += values[0];
  }
  if (produced !== 96 || peakDepth > 2) throw new Error('reentrant producer');
  console.log('reentry', count, sum, peakDepth, e.listenerCount('data'));
})();
"#;

#[test]
fn reentrant_consumers_cannot_strand_demand_or_recurse_through_resume() {
    assert_events(REENTRANT_DEMAND, "reentry 96 4560 2 0");
}

const INVERTED_WATERMARKS: &str = r#"
const E = require('events'); const e = new E(); const calls = [];
e.pause = function () { calls.push('pause'); };
e.resume = function () { calls.push('resume'); };
const it = E.on(e, 'data', { highWaterMark: 2, lowWaterMark: 4 });
for (let i = 0; i < 5; i++) e.emit('data', i);
console.log('buffered', calls.join(':'));
(async () => {
  console.log('first', (await it.next()).value[0], calls.join(':'));
  console.log('second', (await it.next()).value[0], calls.join(':'));
  await it.return();
  let sum = 0;
  for await (const values of it) sum += values[0];
  console.log('closed', sum, calls.join(':'), e.listenerCount('data'));
})().catch(error => console.log('FAIL', error.message));
"#;

#[test]
fn low_watermark_above_high_resumes_only_after_consumption() {
    assert_events(
        INVERTED_WATERMARKS,
        "buffered pause\nfirst 0 pause\nsecond 1 pause:resume\nclosed 9 pause:resume 0",
    );
}
