//! Observable events.once registration (bd-9vouw.489), native execution only.
//! Both interpreter profiles run with and without allocation-triggered GC.

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn assert_events(source: &str, expected: &str) {
    // A constructor alias that also reads E.once already selected the full
    // module. Separate or destructured once imports used to take a different
    // native wait shortcut, bypassing all observable registration and adoption.
    for (shape, source) in [
        ("constructor", source.to_string()),
        (
            "destructured",
            source
                .replace(
                    "const E = require(",
                    "const { EventEmitter: E, once: wait } = require(",
                )
                .replace("E.once(", "wait("),
        ),
        (
            "namespace",
            source
                .replace(
                    "const E = require(",
                    "const events = require('events'); const { EventEmitter: E } = require(",
                )
                .replace("E.once(", "events.once("),
        ),
    ] {
        assert_events_shape(&source, expected, shape);
    }
}

fn assert_events_shape(source: &str, expected: &str, shape: &str) {
    let tree = parse_script(source).expect("events source parses");
    let lowered = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "events-once-registration.js"),
        &LoweringContext::new("events-once", "bd-9vouw.489", "builtin-only"),
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
            let mut core = InterpreterCore::new(config, "events-once");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&lowered.ir3).expect("events source executes");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "{shape}, v8={v8_profile}, GC={stress:?}"
            );
            let output = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(output, expected, "{shape}, v8={v8_profile}, GC={stress:?}");
        }
    }
}

const REGISTRATION: &str = r#"
const E = require('node:events');
const emitter = new E();
const name = Symbol('ready');
const seen = [];
emitter.on('newListener', (event, listener) => {
  seen.push((event === name ? 'ready' : event) + ':' + typeof listener);
});
const pending = E.once(emitter, name);
console.log(seen.join(','));
const raw = emitter.rawListeners(name)[0];
console.log(raw !== emitter.listeners(name)[0], raw.listener === emitter.listeners(name)[0]);
const marker = {};
pending.then(values => console.log(values.length, values[0] === marker, values[1]));
emitter.emit(name, marker, 42);
emitter.emit(name, 'ignored');
console.log(emitter.listenerCount(name), emitter.listenerCount('error'));
"#;

#[test]
fn once_notifies_new_listener_and_installs_native_one_shot_wrappers() {
    assert_events(
        REGISTRATION,
        "ready:function,error:function\ntrue true\n0 0\n2 true 42",
    );
}

const OVERRIDE: &str = r#"
const E = require('events');
const emitter = new E();
const original = emitter.once;
emitter.once = function (name, listener) {
  console.log('register', name, this === emitter);
  return original.call(this, name, listener);
};
E.once(emitter, 'ready').then(values => console.log(values[0]));
emitter.emit('ready', 7);
"#;

#[test]
fn once_honors_instance_registration_overrides() {
    assert_events(OVERRIDE, "register ready true\nregister error true\n7");
}

const REJECTION: &str = r#"
const E = require('events');
const emitter = new E();
E.once(emitter, 'ready').catch(error => console.log('rejected', error === undefined));
emitter.emit('error', undefined);
E.once(emitter, 'error').then(values => console.log('resolved', values[0] === false, values[1]));
emitter.emit('error', false, 9);
console.log(emitter.listenerCount('ready'), emitter.listenerCount('error'));
"#;

#[test]
fn falsey_errors_reject_without_confusing_success_and_failure() {
    assert_events(REJECTION, "0 0\nrejected true\nresolved true 9");
}

const ORDERING: &str = r#"
const E = require('events');
const emitter = new E();
E.once(emitter, 'ready').then(() => console.log('once'));
Promise.resolve().then(() => console.log('before'));
emitter.emit('ready');
Promise.resolve().then(() => console.log('after')).then(() => console.log('after2'));
console.log('sync');
"#;

#[test]
fn once_adopts_its_event_promise_with_node_reaction_ordering() {
    assert_events(ORDERING, "sync\nbefore\nafter\nafter2\nonce");
}

const EVENT_TARGET: &str = r#"
const E = require('events');
const target = new EventTarget();
const original = target.addEventListener;
target.addEventListener = function (name, listener, options) {
  console.log('register', name, options.once);
  return original.call(this, name, listener, options);
};
const event = new Event('ready');
E.once(target, 'ready').then(values => console.log(values.length, values[0] === event));
console.log(target.dispatchEvent(event));
target.dispatchEvent(new Event('ready'));
"#;

#[test]
fn once_supports_event_targets_through_public_one_shot_registration() {
    assert_events(EVENT_TARGET, "register ready true\ntrue\n1 true");
}

const INVALID_EMITTER: &str = r#"
const E = require('events');
let synchronous = false;
try {
  E.once(42, 'ready').catch(error => console.log(error.name, error.code));
} catch (error) { synchronous = true; }
console.log('sync', synchronous);
"#;

#[test]
fn invalid_emitter_rejects_the_async_helper_without_throwing_synchronously() {
    assert_events(
        INVALID_EMITTER,
        "sync false\nTypeError ERR_INVALID_ARG_TYPE",
    );
}

// These cleanup contracts deliberately exceed Node's behavior when registration
// reenters completion or throws. They must not leave a half-installed listener.
const REENTRANT: &str = r#"
const E = require('events');
const emitter = new E();
emitter.on('newListener', name => {
  if (name === 'error') { emitter.emit('ready', 42); }
});
E.once(emitter, 'ready').then(values => console.log('complete', values[0]));
console.log('clean', emitter.listenerCount('ready'), emitter.listenerCount('error'));
const broken = new E();
const failure = new Error('registration failed');
broken.on('newListener', name => { if (name === 'error') { throw failure; } });
E.once(broken, 'ready').catch(error => console.log('same', error === failure));
console.log('rollback', broken.listenerCount('ready'), broken.listenerCount('error'));
"#;

#[test]
fn reentrant_completion_and_registration_failure_release_every_listener() {
    assert_events(REENTRANT, "clean 0 0\nrollback 0 0\ncomplete 42\nsame true");
}

const CANCELLED: &str = r#"
const E = require('events');
const emitter = new E();
const controller = new AbortController();
controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
E.once(emitter, 'ready', { signal: controller.signal }).catch(error => {
  console.log(error.name, error.code, error.cause === 'stop');
});
controller.abort('stop');
console.log(emitter.listenerCount('ready'), emitter.listenerCount('error'));
"#;

#[test]
fn observable_once_retains_authenticated_abort_cleanup() {
    assert_events(CANCELLED, "0 0\nAbortError ABORT_ERR true");
}
