//! Error-monitor delivery through the real parser, lowerer and native emitter.
//! Reference output is checked separately; these tests require native execution.

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn assert_events(source: &str, expected: &str) {
    let tree = parse_script(source).expect("events source parses");
    let lowered = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "events-error-monitor.js"),
        &LoweringContext::new("events-error-monitor", "error-monitor", "builtin-only"),
    )
    .expect("events source lowers without filesystem authority");
    for v8_profile in [false, true] {
        for stress in [None, Some(7)] {
            let mut config = if v8_profile {
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
            let mut core = InterpreterCore::new(config, "events-error-monitor");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&lowered.ir3).expect("events source executes");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "v8={v8_profile}, GC={stress:?}"
            );
            let output = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(output, expected, "v8={v8_profile}, GC={stress:?}");
        }
    }
}

const ORDER: &str = r#"
const E = require('node:events');
const emitter = new E();
const original = new Error('original');
const marker = {};
emitter.on('error', function (value, extra) {
  console.log('error', this === emitter, value === original, extra === marker);
});
emitter.on(E.errorMonitor, function (value, extra) {
  console.log('monitor', this === emitter, value === original, extra === marker);
});
console.log('result', emitter.emit('error', original, marker));
"#;

#[test]
fn monitors_run_first_with_the_original_receiver_and_arguments() {
    assert_events(ORDER, "monitor true true true\nerror true true true\nresult true");
}

const UNHANDLED: &str = r#"
const E = require('events');
const emitter = new E();
const original = new Error('original');
emitter.on(E.errorMonitor, error => console.log('monitor', error === original));
try { emitter.emit('error', original); }
catch (error) { console.log('unhandled', error === original); }
console.log('missing', emitter.emit('missing'));
"#;

#[test]
fn monitors_never_consume_unhandled_errors() {
    assert_events(UNHANDLED, "monitor true\nunhandled true\nmissing false");
}

const NESTED: &str = r#"
const E = require('events');
class Derived extends E {}
const emitter = new Derived();
const originalEmit = emitter.emit;
emitter.emit = function (name, value) {
  console.log('emit', name === E.errorMonitor ? 'monitor' : name, value);
  return originalEmit.call(this, name, value);
};
emitter.on(E.errorMonitor, value => {
  console.log('monitor', value);
  if (value === 'outer') { emitter.emit('error', 'inner'); }
});
emitter.on('error', value => console.log('error', value));
emitter.listenerCount = () => { throw new Error('must not call this override'); };
emitter.emit('error', 'outer');
console.log(emitter instanceof E, emitter instanceof Derived);
"#;

#[test]
fn nested_monitors_honor_emit_overrides_and_native_listener_storage() {
    assert_events(NESTED, "emit error outer\nemit monitor outer\nmonitor outer\nemit error inner\nemit monitor inner\nmonitor inner\nerror inner\nerror outer\ntrue true");
}

const ONCE: &str = r#"
const E = require('events');
const emitter = new E();
const original = new Error('original');
emitter.once(E.errorMonitor, () => console.log('monitor'));
E.once(emitter, 'ready').catch(error => console.log('same', error === original));
emitter.emit('error', original);
console.log(emitter.listenerCount(E.errorMonitor), emitter.listenerCount('ready'), emitter.listenerCount('error'));
"#;

#[test]
fn once_monitors_and_once_waiters_are_removed_on_error() {
    assert_events(ONCE, "monitor\n0 0 0\nsame true");
}

const MONITOR_THROW: &str = r#"
const E = require('events');
const emitter = new E();
const original = new Error('monitor failed');
emitter.on(E.errorMonitor, () => { console.log('monitor'); throw original; });
emitter.on('error', () => console.log('must not run'));
try { emitter.emit('error', new Error('trigger')); }
catch (error) { console.log('same', error === original); }
"#;

#[test]
fn monitor_exceptions_stop_error_delivery_and_preserve_identity() {
    assert_events(MONITOR_THROW, "monitor\nsame true");
}

const KEY: &str = r#"
const E = require('events');
const emitter = new E();
const key = E.errorMonitor;
emitter.on(key, () => console.log('original-key'));
E.errorMonitor = Symbol('replacement');
emitter.on(E.errorMonitor, () => console.log('must not run'));
emitter.on('error', () => console.log('error'));
emitter.emit('error', 7);
E.errorMonitor = key;
"#;

#[test]
fn exported_property_mutation_does_not_retarget_error_monitoring() {
    assert_events(KEY, "original-key\nerror");
}
