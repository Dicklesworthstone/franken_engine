//! Regression tests for bd-asw4m.3 — arrow functions keep their lexical
//! `this` under every invocation form, while ordinary functions keep the
//! dynamic receiver.
//!
//! Before the fix neither runtime carried an arrow bit at call time: IR3 had
//! only `CreateClosure`, `CallMethod` unconditionally bound the receiver, and
//! a plain `Call` of an escaped arrow inherited the CALLER's live `this`.
//! Arrows now lower to `CreateArrowClosure` / `CreateAsyncArrowClosure`,
//! whose run-loop arms capture the creating frame's `this`
//! (`arrow_lexical_this` side map), and every Call/CallMethod path binds that
//! captured value through `clone_closure_lexical_this_binding`.
//!
//! EventEmitter is exercised WITHOUT any emitter-specific heuristics: the
//! emitter already invokes listeners with `this = emitter`; these tests pin
//! that ordinary listeners see it while arrow listeners do not.

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

/// Fixture-0022 semantics: an ordinary function listener is called with
/// `this = emitter`; an arrow listener installed from inside a method keeps
/// that method's `this`.
#[test]
fn emitter_listeners_ordinary_gets_emitter_arrow_keeps_lexical_this() {
    let src = r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        e.on('a', function () { console.log('fn:' + (this === e)); });
        const holder = {
            tag: 'H',
            install(target) { target.on('b', () => { console.log('arrow:' + this.tag); }); }
        };
        holder.install(e);
        e.emit('a');
        e.emit('b');
    "#;
    assert_eq!(eval_console(src), "fn:true\narrow:H");
}

/// An escaped arrow keeps its defining `this` both when invoked as a method
/// of an unrelated object and when invoked as a bare call (the bare call
/// previously inherited the CALLER's live `this` — a second latent bug).
#[test]
fn escaped_arrow_keeps_lexical_this_under_method_and_bare_call() {
    let src = r#"
        const maker = { tag: 'M', make() { return () => this.tag; } };
        const escaped = maker.make();
        const other = { tag: 'O', m: escaped };
        console.log(other.m());
        console.log(escaped());
    "#;
    assert_eq!(eval_console(src), "M\nM");
}

/// Ordinary function expressions keep today's dynamic-receiver behavior.
#[test]
fn ordinary_function_still_binds_the_receiver() {
    let src = r#"
        const obj = { tag: 'R', m: function () { return this.tag; } };
        const shorthand = { tag: 'S', m() { return this.tag; } };
        console.log(obj.m());
        console.log(shorthand.m());
    "#;
    assert_eq!(eval_console(src), "R\nS");
}

/// A top-level arrow captures the module frame's `this` (undefined), and
/// method invocation must not rebind it.
#[test]
fn top_level_arrow_this_stays_undefined_under_method_invocation() {
    let src = r#"
        const probe = () => String(this === undefined);
        const carrier = { tag: 'C', m: probe };
        console.log(carrier.m());
    "#;
    assert_eq!(eval_console(src), "true");
}

/// Async arrows keep lexical `this`, including across an `await` suspension.
#[test]
fn async_arrow_keeps_lexical_this_across_await() {
    let src = r#"
        const holder = {
            tag: 'A',
            make() { return async () => { const v = await 1; return this.tag + ':' + v; }; }
        };
        const fn = holder.make();
        const carrier = { tag: 'X', m: fn };
        console.log(await carrier.m());
    "#;
    assert_eq!(eval_console(src), "A:1");
}
