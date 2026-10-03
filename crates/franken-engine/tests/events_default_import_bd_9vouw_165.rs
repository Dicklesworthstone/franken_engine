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
//! No-claim: `var`/`let` requires, `EventEmitter.call(this)` (ES5
//! inheritance), member reads other than `prototype`/`defaultMaxListeners`
//! on the binding, and the binding used as an ordinary value (an argument,
//! an alias) stay refused, as the last test pins; Node accepts them all.

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

/// The binding used as an ordinary value stays on the ambient-authority
/// refusal (Node runs it): the boundary this change keeps.
#[test]
fn events_default_import_as_a_value_stays_refused() {
    let source = "const E = require('events');\n\
         function keep(x) { return x; }\n\
         keep(E);";
    let error = HybridRouter::default()
        .eval(source)
        .expect_err("an events require used as a value stays refused");
    assert!(error.to_string().contains("ambient authority"), "{error}");
}
