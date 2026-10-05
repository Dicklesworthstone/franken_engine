#![forbid(unsafe_code)]

//! `EventTarget`, `Event`, `CustomEvent`, `AbortController`, `AbortSignal`
//! and `DOMException` as Node v22 globals (bd-9vouw.170). The expected lines
//! are Node v22.2.0's output for the same programs, captured
//! programmatically. Each program runs on both interpreter profiles, as
//! written and with a collection at every seventh safe point, and the
//! memory-accounting oracle must hold after each run.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn console_lines(source: &str, v8_profile: bool, stress_interval: Option<u64>) -> Vec<String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "events.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "events.js"),
        &LoweringContext::new("events-trace", "events-decision", "events-policy"),
    )
    .expect("source lowers")
    .ir3;
    let mut config = if v8_profile {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.instruction_budget = 1_000_000_000;
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
        // AbortSignal.timeout schedules on the timer queue.
        RuntimeCapability::Timer,
    ]);
    let mut core = InterpreterCore::new(config, "events");
    core.set_gc_stress_interval(stress_interval);
    let result = core
        .execute(&module)
        .unwrap_or_else(|error| panic!("program failed: {error:?}"));
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift (v8 profile {v8_profile}, stress {stress_interval:?})"
    );
    result
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

fn assert_lines(source: &str, expected: &[&str]) {
    for v8_profile in [false, true] {
        for stress_interval in [None, Some(7)] {
            assert_eq!(
                console_lines(source, v8_profile, stress_interval),
                expected,
                "v8 profile {v8_profile}, stress {stress_interval:?}"
            );
        }
    }
}

/// The four constructors and DOMException are globals with Node's names,
/// lengths and tags.
#[test]
fn globals_and_shape() {
    assert_lines(
        "console.log(typeof EventTarget, typeof Event, typeof AbortController, typeof AbortSignal, typeof DOMException, typeof CustomEvent);\nconsole.log(EventTarget.length, Event.length, AbortController.length, CustomEvent.length, EventTarget.name, Event.name);\nconst et = new EventTarget(); const ev = new Event('ping');\nconsole.log(Object.prototype.toString.call(et), Object.prototype.toString.call(ev), Object.prototype.toString.call(new AbortController()), Object.prototype.toString.call(new AbortController().signal));\nconsole.log(ev.type, ev.bubbles, ev.cancelable, ev.composed, ev.defaultPrevented, ev.eventPhase, ev.isTrusted, ev.target, ev.currentTarget, typeof ev.timeStamp);\nconsole.log(Event.NONE, Event.CAPTURING_PHASE, Event.AT_TARGET, Event.BUBBLING_PHASE);\n",
        &[
            "function function function function function function",
            "0 1 0 1 EventTarget Event",
            "[object EventTarget] [object Event] [object AbortController] [object AbortSignal]",
            "ping false false false false 0 false null null number",
            "0 1 2 3",
        ],
    );
}

/// Listeners run in order with the event as argument and the target as this;
/// once and removeEventListener remove them; duplicates are ignored.
#[test]
fn dispatch_order_once_and_removal() {
    assert_lines(
        "const et = new EventTarget();\nconst log = [];\nfunction a(e) { log.push('a:' + e.type + ':' + (this === et) + ':' + (e.target === et) + ':' + (e.currentTarget === et) + ':' + e.eventPhase); }\nconst b = (e) => log.push('b');\net.addEventListener('x', a);\net.addEventListener('x', a);\net.addEventListener('x', b, { once: true });\net.addEventListener('x', { handleEvent(e) { log.push('obj:' + (this !== et)); } });\nconsole.log(et.dispatchEvent(new Event('x')));\net.dispatchEvent(new Event('x'));\net.removeEventListener('x', a);\net.dispatchEvent(new Event('x'));\net.dispatchEvent(new Event('y'));\nconsole.log(log.join(' '));\nconst ev = new Event('z');\net.addEventListener('z', () => {});\net.dispatchEvent(ev);\nconsole.log(ev.target === et, ev.currentTarget, ev.eventPhase);\n",
        &[
            "true",
            "a:x:true:true:true:2 b obj:true a:x:true:true:true:2 obj:true obj:true",
            "true EventTarget {} 0",
        ],
    );
}

/// The capture flag is part of a listener's identity; stopImmediatePropagation
/// skips the rest.
#[test]
fn capture_flag_and_stop_immediate() {
    assert_lines(
        "const et = new EventTarget();\nconst log = [];\nconst f = () => log.push('f');\net.addEventListener('x', f, true);\net.addEventListener('x', f, false);\net.dispatchEvent(new Event('x'));\net.removeEventListener('x', f, { capture: true });\net.dispatchEvent(new Event('x'));\net.addEventListener('y', (e) => { log.push('first'); e.stopImmediatePropagation(); });\net.addEventListener('y', () => log.push('second'));\net.dispatchEvent(new Event('y'));\nconsole.log(log.join(' '));\n",
        &["f f f first"],
    );
}

/// preventDefault only acts on a cancelable event and not from a passive
/// listener; dispatchEvent reports it. The passive line is the DOM spec's and
/// Bun 1.4.2's ("true false"): Node v22.2.0 lets a passive listener cancel
/// ("false true"), as V8 12.4's Array.fromAsync departs from ES2024 in the
/// bd-9vouw.172 test.
#[test]
fn prevent_default() {
    assert_lines(
        "const et = new EventTarget();\net.addEventListener('c', (e) => e.preventDefault());\nconst c1 = new Event('c', { cancelable: true });\nconst c2 = new Event('c');\nconsole.log(et.dispatchEvent(c1), c1.defaultPrevented, et.dispatchEvent(c2), c2.defaultPrevented);\nconst et2 = new EventTarget();\net2.addEventListener('p', (e) => e.preventDefault(), { passive: true });\nconst p = new Event('p', { cancelable: true });\nconsole.log(et2.dispatchEvent(p), p.defaultPrevented);\nconsole.log(new Event('r', { cancelable: true }).returnValue);\n",
        &["false true true false", "true false", "true"],
    );
}

/// EventTarget and Event can be subclassed; CustomEvent carries detail.
#[test]
fn subclass_and_custom_event() {
    assert_lines(
        "class Emitter extends EventTarget { fire(n) { this.dispatchEvent(new CustomEvent('n', { detail: n })); } }\nconst em = new Emitter();\nem.addEventListener('n', (e) => console.log('detail', e.detail, e instanceof CustomEvent, e instanceof Event));\nem.fire(42);\nconsole.log(em instanceof EventTarget, em instanceof Emitter);\nclass Ping extends Event { constructor() { super('ping'); this.extra = 1; } }\nconst t = new EventTarget(); t.addEventListener('ping', (e) => console.log('ping', e.extra, e instanceof Ping));\nt.dispatchEvent(new Ping());\n",
        &["detail 42 true true", "true true", "ping 1 true"],
    );
}

/// abort() aborts the signal once with a DOMException AbortError reason,
/// dispatches 'abort' and calls onabort.
#[test]
fn abort_controller() {
    assert_lines(
        "const ac = new AbortController();\nconst s = ac.signal;\nconsole.log(s.aborted, s.reason, s === ac.signal, s instanceof EventTarget, s instanceof AbortSignal);\ns.onabort = (e) => console.log('onabort', e.type, e.target === s);\ns.addEventListener('abort', () => console.log('listener', s.aborted));\nac.abort();\nconsole.log(s.aborted, s.reason instanceof DOMException, s.reason.name, s.reason.message, s.reason.code, s.reason instanceof Error);\nac.abort('again');\nconsole.log(s.reason.name);\nconst ac2 = new AbortController(); ac2.abort('why'); console.log(ac2.signal.reason);\ntry { ac2.signal.throwIfAborted(); } catch (e) { console.log('threw', e); }\nnew AbortController().signal.throwIfAborted(); console.log('not aborted: no throw');\n",
        &[
            "false undefined true true true",
            "onabort abort true",
            "listener true",
            "true true AbortError This operation was aborted 20 true",
            "AbortError",
            "why",
            "threw why",
            "not aborted: no throw",
        ],
    );
}

/// A listener added with an aborted signal is never added; aborting the signal
/// removes it. AbortSignal.abort and AbortSignal.any.
#[test]
fn signal_option_and_statics() {
    assert_lines(
        "const et = new EventTarget();\nconst ac = new AbortController();\net.addEventListener('x', () => console.log('signalled listener'), { signal: ac.signal });\net.dispatchEvent(new Event('x'));\nac.abort();\net.dispatchEvent(new Event('x'));\net.addEventListener('x', () => console.log('never'), { signal: ac.signal });\net.dispatchEvent(new Event('x'));\nconst pre = AbortSignal.abort();\nconsole.log(pre.aborted, pre.reason.name);\nconst a = new AbortController(); const b = new AbortController();\nconst any = AbortSignal.any([a.signal, b.signal]);\nany.addEventListener('abort', () => console.log('any aborted', any.reason));\nconsole.log(any.aborted);\nb.abort('from b');\na.abort('from a');\nconsole.log(any.reason);\nconsole.log(AbortSignal.any([AbortSignal.abort('early')]).reason);\n",
        &[
            "signalled listener",
            "true AbortError",
            "false",
            "any aborted from b",
            "from b",
            "early",
        ],
    );
}

/// DOMException has name, message, legacy code and is an Error.
#[test]
fn dom_exception() {
    assert_lines(
        "const e = new DOMException('boom', 'AbortError');\nconsole.log(e.name, e.message, e.code, e instanceof Error, e instanceof DOMException, String(e), Object.prototype.toString.call(e));\nconst d = new DOMException();\nconsole.log(JSON.stringify(d.name), JSON.stringify(d.message), d.code);\nconsole.log(new DOMException('t', 'TimeoutError').code, new DOMException('x', 'DataCloneError').code, new DOMException('x', 'NotAName').code);\n",
        &[
            "AbortError boom 20 true true AbortError: boom [object DOMException]",
            "\"Error\" \"\" 0",
            "23 25 0",
        ],
    );
}

/// AbortSignal.timeout aborts with a TimeoutError on the timer queue.
#[test]
fn timeout_signal() {
    assert_lines(
        "const s = AbortSignal.timeout(5);\nconsole.log(s.aborted);\ns.addEventListener('abort', () => console.log('timed out', s.reason.name, s.reason.message));\nsetTimeout(() => console.log('after', s.aborted), 20);\n",
        &[
            "false",
            "timed out TimeoutError The operation was aborted due to timeout",
            "after true",
        ],
    );
}

/// Bad arguments are TypeErrors.
#[test]
fn errors() {
    assert_lines(
        "const show = (fn) => { try { fn(); return 'ok'; } catch (e) { return e.constructor.name; } };\nconsole.log(show(() => new EventTarget().dispatchEvent({ type: 'x' })));\nconsole.log(show(() => new Event()));\nconsole.log(show(() => EventTarget()));\nconsole.log(show(() => new AbortSignal()));\nconsole.log(show(() => AbortSignal.any([1])));\nconsole.log(show(() => new EventTarget().addEventListener('x', null)));\n",
        &[
            "TypeError",
            "TypeError",
            "TypeError",
            "TypeError",
            "TypeError",
            "ok",
        ],
    );
}
