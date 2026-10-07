//! bd-9vouw.165: the default `require('events')` import and class heritage
//! `extends EventEmitter` are supported EventEmitter shapes.
//!
//! `events` is lowering-only (bd-2dmnn): a pre-scan confirms the require
//! shapes it supports and every other require keeps the ambient-authority
//! refusal. It confirmed only `const { EventEmitter } = require('events')` and
//! `require('events').EventEmitter` used by `new`, call, typeof, instanceof,
//! `===`, `.prototype` and `.defaultMaxListeners`, so the default import
//! (Node's module.exports is the constructor) and `class X extends
//! EventEmitter`, the way most libraries use it, were refused. Both are now
//! confirmed: the binding is the real constructor value
//! (builtin:EventEmitterConstructorRef, bd-dspwz). Expected strings are Node
//! v22.2.0's console output for the same programs.
//!
//! bd-305gi also materializes the native constructor as a first-class module
//! value. The final regression now requires passing and aliasing that value
//! to execute correctly rather than preserving the former refusal.

use frankenengine_engine::HybridRouter;

fn console_output(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// `require('events')` is the EventEmitter constructor (Node's module.exports).
#[test]
fn events_default_import() {
    let source = "const EventEmitter = require('events');\n\
         const e = new EventEmitter();\n\
         e.on('x', (v) => console.log('got', v));\n\
         e.emit('x', 1);\n\
         console.log(typeof EventEmitter, e instanceof EventEmitter);";
    assert_eq!(console_output(source), "got 1\nfunction true");
}

/// A class extends the default `node:events` import.
#[test]
fn events_node_events_class_extends() {
    let source = "const EventEmitter = require('node:events');\n\
         class S extends EventEmitter { hi() { this.emit('h', 'hi'); } }\n\
         const s = new S();\n\
         s.on('h', (v) => console.log('h', v));\n\
         s.hi();\n\
         console.log(s instanceof S, s instanceof EventEmitter, Object.getPrototypeOf(S) === EventEmitter);";
    assert_eq!(console_output(source), "h hi\ntrue true true");
}

/// A class extends the destructured EventEmitter and calls super().
#[test]
fn events_destructured_class_extends() {
    let source = "const { EventEmitter } = require('events');\n\
         class T extends EventEmitter { constructor() { super(); this.n = 1; } }\n\
         const t = new T();\n\
         t.once('o', () => console.log('once', t.n));\n\
         t.emit('o'); t.emit('o');\n\
         console.log(t.listenerCount('o'), t.n);";
    assert_eq!(console_output(source), "once 1\n0 1");
}

/// A class extends `require('events').EventEmitter`.
#[test]
fn events_member_class_extends() {
    let source = "const EventEmitter = require('events').EventEmitter;\n\
         class U extends EventEmitter {}\n\
         const u = new U();\n\
         u.on('u', (v) => console.log('u', v));\n\
         u.emit('u', 7);";
    assert_eq!(console_output(source), "u 7");
}

/// Module values retain the native constructor identity through user calls.
#[test]
fn events_default_import_as_a_value_preserves_native_identity() {
    let source = "const E = require('events');\n\
         function keep(x) { return x; }\n\
         const Saved = keep(E);\n\
         const e = new Saved();\n\
         e.on('x', (value) => console.log(value));\n\
         e.emit('x', 42);\n\
         console.log(Saved === E, e instanceof E, E.EventEmitter === E);";
    assert_eq!(console_output(source), "42\ntrue true true");
}

/// Exercise the real parser/lowerer/interpreter with no filesystem or module
/// loading grant, and reconcile memory after every event lifecycle scenario.
fn assert_native_events(source: &str, expected: &str, module: bool) {
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser_api_stability::{parse_module, parse_script};

    let tree = if module {
        parse_module(source)
    } else {
        parse_script(source)
    }
    .expect("events source parses");
    let lowered = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "first-class-events.js"),
        &LoweringContext::new("events-module", "bd-305gi", "builtin-only"),
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
            let mut core = InterpreterCore::new(config, "events-module");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&lowered.ir3).expect("events source executes");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "v8={v8_profile}, GC={stress:?}"
            );
            assert_eq!(
                result
                    .console_output
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
                expected,
                "v8={v8_profile}, GC={stress:?}"
            );
        }
    }
}

const MODULE_VALUES: &str = r#"
var E = require('events'); let other = require('node:events');
function load() { return require('events'); }
const Saved = ((value) => value)(load());
const e = new Saved();
const wait = E['once'];
wait(...[e, 'x']).then((args) => console.log(args.join(':')));
e.emit('x', 'ready', 42);
console.log(E === other, E === load(), E.EventEmitter === E, e instanceof E);
console.log(typeof E.on, typeof E.once, E.once.length, E.on.length);
"#;

#[test]
fn first_class_events_support_nested_mutable_destructured_and_computed_forms() {
    assert_native_events(MODULE_VALUES, "true true true true\nfunction function 2 2\nready:42", false);
}

const ITERATOR_QUEUE: &str = r#"
const E = require('events'); const e = new E();
const it = E.on(e, 'data', {close:['end']});
console.log(it[Symbol.asyncIterator]() === it);
e.emit('data', 1); e.emit('data', 2, 3); e.emit('end');
console.log(e.listenerCount('data'), e.listenerCount('error'), e.listenerCount('end'));
(async () => {
  console.log((await it.next()).value.join(':'));
  console.log((await it.next()).value.join(':'));
  console.log((await it.next()).done);
})();
"#;

#[test]
fn async_iterator_drains_queued_events_before_close() {
    assert_native_events(ITERATOR_QUEUE, "true\n0 0 0\n1\n2:3\ntrue", false);
}

const ITERATOR_WAITERS: &str = r#"
const E = require('events'); const e = new E(); const it = E.on(e, 'x');
it.next().then((r) => console.log('a', r.value[0]));
it.next().then((r) => console.log('b', r.value[0]));
it.next().then((r) => console.log('done', r.done));
e.emit('x', 10); e.emit('x', 20); it.return();
console.log(e.listenerCount('x'), e.listenerCount('error'));
"#;

#[test]
fn concurrent_iterator_waiters_are_fifo_and_return_settles_the_rest() {
    assert_native_events(ITERATOR_WAITERS, "0 0\na 10\nb 20\ndone true", false);
}

const ITERATOR_ERROR: &str = r#"
const E = require('events'); const e = new E(); const it = E.on(e, 'x');
const error = new Error('failure');
e.emit('x', 7); e.emit('error', error);
(async () => {
  console.log((await it.next()).value[0]);
  try { await it.next(); } catch (caught) { console.log(caught === error); }
  console.log((await it.next()).done, e.listenerCount('x'), e.listenerCount('error'));
})();
"#;

#[test]
fn buffered_events_precede_the_original_error_and_error_is_consumed_once() {
    assert_native_events(ITERATOR_ERROR, "7\ntrue\ntrue 0 0", false);
}

const ITERATOR_ABORT: &str = r#"
const E = require('events'); const e = new E(); const c = new AbortController();
const it = E.on(e, 'x', {signal:c.signal});
it.next().catch((error) => console.log(error.name, error.code, error.cause));
it.next().then((result) => console.log(result.done));
c.abort('stop');
console.log(e.listenerCount('x'), e.listenerCount('error'));
"#;

#[test]
fn iterator_abort_rejects_first_waiter_and_cleans_up_all_listeners() {
    assert_native_events(ITERATOR_ABORT, "0 0\nAbortError ABORT_ERR stop\ntrue", false);
}

const ONCE_ABORT: &str = r#"
const E = require('events'); const e = new E(); const c = new AbortController();
const wait = E.once;
wait(e, 'x', {signal:c.signal}).catch((error) => console.log(error.name, error.code, error.cause));
c.abort('cancel');
console.log(e.listenerCount('x'), e.listenerCount('error'));
"#;

#[test]
fn first_class_once_supports_abort_without_retaining_native_waiters() {
    assert_native_events(ONCE_ABORT, "0 0\nAbortError ABORT_ERR cancel", false);
}

const ITERATOR_BACKPRESSURE: &str = r#"
const E = require('events'); const e = new E(); const calls = [];
e.pause = () => calls.push('pause'); e.resume = () => calls.push('resume');
const it = E.on(e, 'x', {highWaterMark:2, lowWaterMark:1});
e.emit('x', 1); e.emit('x', 2); e.emit('x', 3);
console.log(calls.join(','));
(async () => {
  console.log((await it.next()).value[0], (await it.next()).value[0], (await it.next()).value[0]);
  console.log(calls.join(',')); await it.return();
  console.log(e.listenerCount('x'), e.listenerCount('error'));
})();
"#;

#[test]
fn high_and_low_watermarks_pause_and_resume_the_producer() {
    assert_native_events(ITERATOR_BACKPRESSURE, "pause\n1 2 3\npause,resume\n0 0", false);
}

const ERROR_AS_DATA: &str = r#"
const E = require('events'); const e = new E(); const it = E.on(e, 'error');
const error = new Error('observed');
it.next().then((r) => console.log(r.value[0] === error));
e.emit('error', error); it.return();
console.log(e.listenerCount('error'));
"#;

#[test]
fn iterating_error_events_yields_errors_as_data() {
    assert_native_events(ERROR_AS_DATA, "0\ntrue", false);
}

const LOOP_BREAK: &str = r#"
const E = require('events'); const e = new E(); const it = E.on(e, 'x');
e.emit('x', 1); e.emit('x', 2);
(async () => {
  for await (const args of it) { console.log(args[0]); break; }
  console.log(e.listenerCount('x'), e.listenerCount('error'));
})();
"#;

#[test]
fn for_await_break_closes_the_native_subscription() {
    assert_native_events(LOOP_BREAK, "1\n0 0", false);
}

const REQUIRE_SHADOWING: &str = r#"
function use(require) { return require('events'); }
console.log(use((name) => 'local:' + name));
for (const require of [(name) => 'loop:' + name]) { console.log(require('events')); }
{ const require = (name) => 'block:' + name; console.log(require('events')); }
const E = require('events'); console.log(typeof E, E === require('node:events'));
"#;

#[test]
fn source_owned_require_bindings_are_not_replaced_with_native_modules() {
    assert_native_events(REQUIRE_SHADOWING, "local:events\nloop:events\nblock:events\nfunction true", false);
}

const ESM_EXPORTS: &str = r#"
import E, { once as wait, on as iterate, EventEmitter } from 'node:events';
const e = new EventEmitter(); const saved = wait;
console.log(E === EventEmitter, typeof saved, typeof iterate);
saved(e, 'ready').then((args) => console.log(args[0])); e.emit('ready', 42);
"#;

#[test]
fn esm_default_and_named_exports_are_first_class_native_values() {
    assert_native_events(ESM_EXPORTS, "true function function\n42", true);
}

const GLOBAL_SHADOWING: &str = r#"
const Array = 0, Error = 0, Object = 0, Promise = 0, RangeError = 0, Symbol = 0, TypeError = 0;
const AbortController = 0, AbortSignal = 0, EventTarget = 0, Reflect = 0;
const E = require('events'); const e = new E(); const it = E.on(e, 'x');
it.next().then((r) => console.log(r.value[0], Array, Promise)); e.emit('x', 7); it.return();
"#;

#[test]
fn module_globals_are_not_captured_by_guest_lexical_declarations() {
    assert_native_events(GLOBAL_SHADOWING, "7 0 0", false);
}

const STOPPED_ABORT: &str = r#"
const E = require('events');
const controller = new AbortController();
const first = new E(); const second = new E();
const reason = { cancellation: true };
controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
E.once(first, 'ready', { signal: controller.signal }).catch(error => {
  console.log('once', error.name, error.code, error.cause === reason);
});
const iterator = E.on(second, 'data', { signal: controller.signal });
iterator.next().catch(error => console.log('on', error.cause === reason));
iterator.next().then(result => console.log('done', result.done));
controller.signal.addEventListener('abort', () => console.log('wrong public listener'));
controller.abort(reason);
console.log(first.listenerCount('ready'), first.listenerCount('error'),
  second.listenerCount('data'), second.listenerCount('error'));
"#;

#[test]
fn stopped_public_abort_events_cannot_keep_once_or_iterator_waits_pending() {
    assert_native_events(STOPPED_ABORT, "0 0 0 0\non true\ndone true\nonce AbortError ABORT_ERR true", false);
}

const STOPPED_COMPOSED_ABORT: &str = r#"
const E = require('events');
const root = new AbortController();
const middle = AbortSignal.any([root.signal]);
const nested = AbortSignal.any([middle]);
const emitter = new E();
root.signal.addEventListener('abort', event => event.stopImmediatePropagation());
middle.addEventListener('abort', event => event.stopImmediatePropagation());
nested.addEventListener('abort', event => event.stopImmediatePropagation());
const iterator = E.on(emitter, 'data', { signal: nested });
iterator.next().catch(error => console.log(error.name, error.code, error.cause === false));
root.abort(false);
console.log(root.signal.aborted, nested.aborted, emitter.listenerCount('data'), emitter.listenerCount('error'));
"#;

#[test]
fn private_cancellation_flattens_nested_signals_and_preserves_falsy_reasons() {
    assert_native_events(STOPPED_COMPOSED_ABORT, "true true 0 0\nAbortError ABORT_ERR true", false);
}

const COMPLETED_ABORT_WAIT: &str = r#"
const E = require('events');
const root = new AbortController();
const emitter = new E();
const original = new Error('original');
let completed = 0;
E.once(emitter, 'success', { signal: root.signal }).then(values => {
  console.log('success', values[0]); completed++;
});
emitter.emit('success', 42);
E.once(emitter, 'failure', { signal: root.signal }).catch(error => {
  console.log('failure', error === original); completed++;
});
emitter.emit('error', original);
const iterator = E.on(emitter, 'data', { signal: root.signal });
iterator.next().then(result => { console.log('return', result.done); completed++; });
iterator.return();
console.log(root.signal.aborted, emitter.eventNames().length);
root.abort('later');
Promise.resolve().then(() => console.log('completed', completed));
"#;

#[test]
fn successful_and_closed_waits_do_not_cancel_the_caller_signal() {
    assert_native_events(COMPLETED_ABORT_WAIT, "false 0\nreturn true\ncompleted 1\nsuccess 42\nfailure true", false);
}

// These cases exercise protected native state rather than emulating mutable
// public signal properties. They intentionally do not claim Node parity for
// synthetic abort dispatch or guest-replaced signal APIs.
const PROTECTED_METHODS: &str = r#"
const E = require('events');
const controller = new AbortController();
const emitter = new E();
const signal = controller.signal;
const reason = { real: true };
const fail = () => { throw new Error('guest signal method was called'); };
signal.addEventListener = fail;
signal.removeEventListener = fail;
Object.defineProperty(signal, 'aborted', { value: false });
Object.defineProperty(signal, 'reason', { value: 'forged' });
E.once(emitter, 'ready', { signal }).catch(error => console.log(error.cause === reason));
controller.abort(reason);
console.log(emitter.listenerCount('ready'), emitter.listenerCount('error'));
"#;

#[test]
fn signal_method_replacement_cannot_hijack_cancellation_or_its_reason() {
    assert_native_events(PROTECTED_METHODS, "0 0\ntrue", false);
}

const PROTECTED_SYNTHETIC: &str = r#"
const E = require('events');
const controller = new AbortController(); const emitter = new E();
const iterator = E.on(emitter, 'data', { signal: controller.signal });
iterator.next().then(result => console.log('value', result.value[0]));
controller.signal.dispatchEvent(new Event('abort'));
emitter.emit('data', 42);
console.log(controller.signal.aborted, emitter.listenerCount('data'));
iterator.next().catch(error => console.log('abort', error.cause));
controller.abort('real');
console.log(emitter.listenerCount('data'), emitter.listenerCount('error'));
"#;

#[test]
fn synthetic_abort_event_is_not_a_native_cancellation_transition() {
    assert_native_events(PROTECTED_SYNTHETIC, "false 1\n0 0\nvalue 42\nabort real", false);
}

const PROTECTED_PROTOTYPES: &str = r#"
const E = require('events');
const controller = new AbortController(); const emitter = new E();
const signal = controller.signal;
const abort = AbortController.prototype.abort;
const apply = Reflect.apply;
const fail = () => { throw new Error('guest replacement'); };
AbortSignal.any = fail;
AbortController.prototype.abort = fail;
EventTarget.prototype.addEventListener = fail;
EventTarget.prototype.removeEventListener = fail;
Reflect.apply = fail;
Object.defineProperty = fail;
Object.create = fail;
Array.prototype[Symbol.iterator] = fail;
E.once(emitter, 'ready', { signal }).catch(error => console.log(error.code, error.cause));
apply(abort, controller, ['cancel']);
console.log(emitter.listenerCount('ready'), emitter.listenerCount('error'));
"#;

#[test]
fn captured_native_signal_operations_survive_guest_prototype_replacement() {
    assert_native_events(PROTECTED_PROTOTYPES, "0 0\nABORT_ERR cancel", false);
}

const PROTECTED_REENTRANT: &str = r#"
const E = require('events'); const controller = new AbortController();
const first = new E(); const second = new E(); const reason = { stop: true };
controller.signal.addEventListener('abort', () => {
  first.emit('ready', 'stale');
  second.emit('data', 'stale');
  console.log(first.listenerCount('ready'), first.listenerCount('error'),
    second.listenerCount('data'), second.listenerCount('error'));
});
E.once(first, 'ready', { signal: controller.signal }).then(
  () => console.log('wrong success'), error => console.log('once', error.cause === reason));
const iterator = E.on(second, 'data', { signal: controller.signal });
iterator.next().then(() => console.log('wrong data'), error => console.log('on', error.cause === reason));
controller.abort(reason);
console.log('aborted', controller.signal.aborted);
"#;

#[test]
fn reentrant_public_abort_listener_cannot_publish_success_after_cancellation() {
    assert_native_events(PROTECTED_REENTRANT, "0 0 0 0\naborted true\non true\nonce true", false);
}
