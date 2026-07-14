//! bd-2dmnn: Node-compatible `EventEmitter` core through `HybridRouter::eval`.
//!
//! The engine already used an emitter listener table for HTTP request/response
//! streams. This suite pins the standalone `require('events')` lowering and the
//! shared receiver-aware runtime semantics that franken_node's compatibility
//! corpus exercises. Promise-backed module `once`, lexical arrow `this`, and
//! callable `rawListeners` wrappers are intentionally separate follow-ups.

use frankenengine_engine::HybridRouter;

fn eval_console(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|error| panic!("eval failed for {src:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn eval_error(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(outcome) => panic!("expected eval failure for {src:?}, got {outcome:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn ordered_emit_repetition_boolean_and_arguments() {
    let src = r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        const out = [];
        e.on('tick', () => out.push('a'));
        e.on('args', (a, b, c) => console.log(a + '|' + b + '|' + String(c)));
        console.log(e.emit('tick'));
        console.log(e.emit('tick'));
        console.log(out.join(','));
        e.emit('args', 'x', 7, true);
        e.emit('args', 'only');
        console.log(e.emit('nobody'));
    "#;
    assert_eq!(
        eval_console(src),
        "true\ntrue\na,a\nx|7|true\nonly|undefined|undefined\nfalse"
    );
}

#[test]
fn registration_order_once_prepend_and_chaining() {
    let src = r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        e.on('ordered', () => console.log('second'));
        e.prependListener('ordered', () => console.log('first'));
        e.prependOnceListener('ordered', () => console.log('front-once'));
        console.log(e.on('a', () => {}) === e);
        console.log(e.once('b', () => {}) === e);
        console.log(e.prependListener('c', () => {}) === e);
        e.emit('ordered');
        e.emit('ordered');
        console.log(e.listenerCount('ordered'));
    "#;
    assert_eq!(
        eval_console(src),
        "true\ntrue\ntrue\nfront-once\nfirst\nsecond\nfirst\nsecond\n2"
    );
}

#[test]
fn selective_duplicate_and_bulk_removal() {
    let src = r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        const duplicate = () => console.log('duplicate');
        const removed = () => console.log('wrong');
        e.on('d', duplicate);
        e.on('d', duplicate);
        e.on('x', removed);
        e.off('x', removed);
        e.removeListener('d', duplicate);
        console.log(e.listenerCount('d'));
        console.log(e.emit('x'));
        e.emit('d');
        e.on('keep', () => console.log('kept'));
        e.on('drop', () => console.log('wrong'));
        e.removeAllListeners('drop');
        e.emit('drop');
        e.emit('keep');
        console.log(e.removeAllListeners() === e);
        console.log(e.eventNames().length);
    "#;
    assert_eq!(eval_console(src), "1\nfalse\nduplicate\nkept\ntrue\n0");
}

#[test]
fn emit_uses_a_listener_snapshot() {
    let src = r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        const second = () => console.log('second');
        e.on('r', () => {
          console.log('first');
          e.removeListener('r', second);
        });
        e.on('r', second);
        e.emit('r');
        console.log('count:' + e.listenerCount('r'));
        e.emit('r');
    "#;
    assert_eq!(eval_console(src), "first\nsecond\ncount:1\nfirst");
}

#[test]
fn listener_introspection_returns_detached_arrays() {
    let src = r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        e.on('zeta', () => {});
        e.on('alpha', () => console.log('fired'));
        e.once('mid', () => {});
        console.log(e.eventNames().slice().sort().join(','));
        console.log(e.eventNames().length);
        const copy = e.listeners('alpha');
        copy.length = 0;
        console.log(e.listenerCount('alpha'));
        e.emit('alpha');
    "#;
    assert_eq!(eval_console(src), "alpha,mid,zeta\n3\n1\nfired");
}

#[test]
fn once_removes_before_invocation_and_forwards_all_arguments() {
    let src = r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        e.once('hit', () => console.log('hit'));
        e.once('cfg', (host, port) => console.log(host + ':' + port));
        e.emit('hit');
        e.emit('hit');
        e.emit('hit');
        e.emit('cfg', 'localhost', 8080);
        e.emit('cfg', 'other', 9999);
        console.log(e.listenerCount('hit'));
    "#;
    assert_eq!(eval_console(src), "hit\nlocalhost:8080\n0");
}

#[test]
fn callable_string_global_is_shadow_aware() {
    assert_eq!(
        eval_console("console.log(String()); console.log(String(true)); console.log(String(7));"),
        "\ntrue\n7"
    );
    assert_eq!(
        eval_console("const String = (value) => 'local:' + value; console.log(String('x'));"),
        "local:x"
    );
}

#[test]
fn meta_events_observe_before_add_and_after_remove() {
    let src = r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        const gone = () => {};
        e.once('newListener', (name) => {
          console.log('new:' + String(name) + ':' + e.listenerCount(name));
        });
        e.on('removeListener', (name, listener) => {
          if (name === 'gone') console.log('removed:' + (listener === gone));
        });
        e.on('gone', gone);
        console.log('after:' + e.listenerCount('gone'));
        e.off('gone', gone);
    "#;
    assert_eq!(
        eval_console(src),
        "new:removeListener:0\nafter:1\nremoved:true"
    );
}

#[test]
fn max_listener_and_module_constants_match_node_defaults() {
    let src = r#"
        const { EventEmitter } = require('events');
        const events = require('node:events');
        const e = new EventEmitter();
        console.log(e.getMaxListeners());
        console.log(e.setMaxListeners(25) === e);
        console.log(e.getMaxListeners());
        console.log(EventEmitter.defaultMaxListeners);
        console.log(typeof EventEmitter.defaultMaxListeners);
        console.log(events.captureRejections === false);
        console.log(typeof events.captureRejections);
    "#;
    assert_eq!(eval_console(src), "10\ntrue\n25\n10\nnumber\ntrue\nboolean");
}

#[test]
fn handled_error_emits_and_unhandled_error_throws_original_value() {
    let src = r#"
        const { EventEmitter } = require('events');
        const handled = new EventEmitter();
        handled.on('error', (error) => console.log('handled:' + error.message));
        console.log(handled.emit('error', new Error('soft')));
        const unhandled = new EventEmitter();
        try {
          unhandled.emit('error', new Error('boom'));
          console.log('no-throw');
        } catch (error) {
          console.log('threw:' + error.message);
        }
    "#;
    assert_eq!(eval_console(src), "handled:soft\ntrue\nthrew:boom");
}

#[test]
fn unused_events_require_remains_ambient_refused() {
    for source in [
        "const events = require('events'); console.log('unreachable');",
        "const { EventEmitter, once } = require('events'); new EventEmitter(); console.log(once);",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("ambient authority violation"),
            "unsupported or unused require('events') must stay ambient-refused, got: {error}"
        );
    }
}
