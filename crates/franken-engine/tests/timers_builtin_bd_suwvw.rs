//! bd-suwvw: Node-compat timers breadth through `HybridRouter::eval`.
//!
//! Covers the deterministic timer machinery end to end: setTimeout extra
//! args + delay coercion/clamping, object timer handles (`typeof`,
//! `clearTimeout(handle)`, `hasRef`/`ref`/`unref` + the unref'd-timers-don't-
//! keep-the-loop-alive exit rule), setInterval re-scheduling + cancellation,
//! setImmediate/clearImmediate (immediate lane drains before due timers at
//! the same virtual time; nested immediates run after already-queued ones),
//! queueMicrotask ordering against promise jobs and macrotasks,
//! `require('timers')` / `require('node:timers')` module aliasing (the module
//! exports ARE the injected globals — identity holds), and
//! `require('timers/promises')` (promise `setTimeout(ms, value)`,
//! `setImmediate`, and the `for await … of setInterval(ms)` deterministic
//! iterable). Behaviors are pinned against `bun` 1.3.14 runs of the compat
//! corpus at
//! `franken_node/crates/franken-node/tests/fixtures/compat_corpus/timers/`.
//!
//! Fail-closed contracts kept: a bare/unused `require('timers')` or
//! `require('timers/promises')` still hits the ambient-authority denial, and
//! a user binding shadowing a timer global is never reinterpreted as the
//! builtin.
//!
//! franken-core mirror: none. Core has no timer machinery at all (no
//! `builtin:SetTimeout` dispatch and no bare-global timer call lowering), so
//! adding the module-alias recognizers there would map onto nonexistent
//! builtins and turn a clean fail-closed refusal into a runtime fault. The
//! timers family lands engine-side only.
//!
//! Also pins two engine-level fixes this breadth work required:
//! - the leading-dot method-chain logical-line merge in the parser
//!   (`Promise.resolve()\n  .then(cb)\n  .then(cb)`), and
//! - the exact child-captured-locals mirroring in the deferred IR3 body pass
//!   (the old positional heuristic could shadow a captured variable with an
//!   internal temp's value, breaking nested closures like corpus 0026).

use frankenengine_engine::HybridRouter;

/// Evaluate `src` and return the console output messages joined by newlines
/// (one line per `console.log`, args joined by single spaces — matching bun).
fn eval_console(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Evaluate `src` expecting an eval-time error; returns its display string.
fn eval_err(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(outcome) => panic!("expected eval error for {src:?}, got {outcome:?}"),
        Err(e) => format!("{e}"),
    }
}

// -------------------------------------------------------------------------
// setTimeout: extra args, delay coercion, ordering
// -------------------------------------------------------------------------

#[test]
fn set_timeout_forwards_extra_arguments() {
    // Corpus 0002.
    let src = r#"
        setTimeout((a, b, c) => { console.log(a + ',' + b + ',' + c); }, 10, 'x', 7, true);
    "#;
    assert_eq!(eval_console(src), "x,7,true");
}

#[test]
fn set_timeout_string_delay_coerces_to_number() {
    // Corpus 0018: '20' sorts after 5.
    let src = r#"
        const order = [];
        setTimeout(() => { order.push('string20'); console.log(order.join(',')); }, '20');
        setTimeout(() => { order.push('number5'); }, 5);
    "#;
    assert_eq!(eval_console(src), "number5,string20");
}

#[test]
fn set_timeout_negative_and_nan_delays_clamp_and_fire() {
    // Corpus 0019/0020 stdout behavior (bun also prints a warning on stderr
    // whose text embeds an absolute sandbox path — see the corpus notes; the
    // engine intentionally emits nothing on stderr).
    let src = r#"
        setTimeout(() => { console.log('negative-delay-fired'); }, -1);
    "#;
    assert_eq!(eval_console(src), "negative-delay-fired");
    let src = r#"
        setTimeout(() => { console.log('nan-delay-fired'); }, NaN);
    "#;
    assert_eq!(eval_console(src), "nan-delay-fired");
}

#[test]
fn clamped_delays_still_order_after_microtasks() {
    // Corpus 0030 shape: 0ms clamps to 1ms and still fires after the whole
    // microtask chain.
    let src = r#"
        const order = [];
        setTimeout(() => { order.push('timer'); console.log(order.join(',')); }, 0);
        Promise.resolve()
          .then(() => { order.push('then1'); })
          .then(() => { order.push('then2'); });
    "#;
    assert_eq!(eval_console(src), "then1,then2,timer");
}

// -------------------------------------------------------------------------
// Timer handles: typeof, clearTimeout(handle), hasRef/ref/unref
// -------------------------------------------------------------------------

#[test]
fn set_timeout_returns_object_handle() {
    // Corpus 0007.
    let src = r#"
        const t = setTimeout(() => {}, 10);
        console.log(typeof t);
        console.log(t === null);
        clearTimeout(t);
        console.log('cleared');
    "#;
    assert_eq!(eval_console(src), "object\nfalse\ncleared");
}

#[test]
fn clear_timeout_cancels_pending_timer() {
    // Corpus 0006.
    let src = r#"
        let fired = false;
        const t = setTimeout(() => { fired = true; }, 10);
        clearTimeout(t);
        setTimeout(() => { console.log('cancelled-fired:' + fired); }, 30);
    "#;
    assert_eq!(eval_console(src), "cancelled-fired:false");
}

#[test]
fn clear_timeout_tolerates_undefined_null_and_garbage() {
    // Corpus 0021 + garbage arm.
    let src = r#"
        const t = setTimeout(() => {
          console.log('fired-once');
          clearTimeout(t);
          clearTimeout(undefined);
          clearTimeout(null);
          clearTimeout('nonsense');
          console.log('clears-ok');
        }, 10);
    "#;
    assert_eq!(eval_console(src), "fired-once\nclears-ok");
}

#[test]
fn handle_has_ref_unref_ref_roundtrip_and_still_fires() {
    // Corpus 0017.
    let src = r#"
        const t = setTimeout(() => { console.log('still-fired'); }, 10);
        console.log('hasRef:' + t.hasRef());
        t.unref();
        console.log('afterUnref:' + t.hasRef());
        t.ref();
        console.log('afterRef:' + t.hasRef());
    "#;
    assert_eq!(
        eval_console(src),
        "hasRef:true\nafterUnref:false\nafterRef:true\nstill-fired"
    );
}

#[test]
fn unrefd_timer_does_not_keep_the_loop_alive() {
    // Node semantics: an unref'd timer never fires if the loop would
    // otherwise exit. The ref'd 5ms timer fires; the unref'd 50ms one must
    // not.
    let src = r#"
        const t = setTimeout(() => { console.log('should-not-fire'); }, 50);
        t.unref();
        setTimeout(() => { console.log('refd-fired'); }, 5);
    "#;
    assert_eq!(eval_console(src), "refd-fired");
}

#[test]
fn unref_and_ref_return_the_handle_for_chaining() {
    let src = r#"
        const t = setTimeout(() => {}, 10);
        console.log(t.unref() === t);
        console.log(t.ref() === t);
        clearTimeout(t);
    "#;
    assert_eq!(eval_console(src), "true\ntrue");
}

// -------------------------------------------------------------------------
// setInterval / clearInterval
// -------------------------------------------------------------------------

#[test]
fn set_interval_repeats_until_cleared() {
    // Corpus 0008.
    let src = r#"
        let n = 0;
        const iv = setInterval(() => {
          n++;
          console.log('tick' + n);
          if (n === 3) { clearInterval(iv); console.log('stopped'); }
        }, 10);
    "#;
    assert_eq!(eval_console(src), "tick1\ntick2\ntick3\nstopped");
}

#[test]
fn set_interval_zero_delay_clamps_and_repeats() {
    // Corpus 0025.
    let src = r#"
        let n = 0;
        const iv = setInterval(() => {
          n++;
          if (n === 3) { clearInterval(iv); console.log('zero-interval-count:' + n); }
        }, 0);
    "#;
    assert_eq!(eval_console(src), "zero-interval-count:3");
}

#[test]
fn interval_ticks_interleave_with_other_timers_fifo() {
    // A 10ms interval and a 15ms timeout: tick@10, timeout@15, tick@20.
    let src = r#"
        const order = [];
        let n = 0;
        const iv = setInterval(() => {
          n++;
          order.push('tick' + n);
          if (n === 2) { clearInterval(iv); console.log(order.join(',')); }
        }, 10);
        setTimeout(() => { order.push('timeout'); }, 15);
    "#;
    assert_eq!(eval_console(src), "tick1,timeout,tick2");
}

// -------------------------------------------------------------------------
// setImmediate / clearImmediate
// -------------------------------------------------------------------------

#[test]
fn set_immediate_runs_after_sync_code() {
    // Corpus 0009.
    let src = r#"
        console.log('sync1');
        setImmediate(() => { console.log('immediate'); });
        console.log('sync2');
    "#;
    assert_eq!(eval_console(src), "sync1\nsync2\nimmediate");
}

#[test]
fn immediate_scheduled_in_timer_callback_beats_zero_timeout() {
    // Corpus 0010 (Node check-phase ordering).
    let src = r#"
        setTimeout(() => {
          const order = [];
          setImmediate(() => { order.push('immediate'); });
          setTimeout(() => { order.push('timeout'); console.log(order.join(',')); }, 0);
        }, 5);
    "#;
    assert_eq!(eval_console(src), "immediate,timeout");
}

#[test]
fn nested_immediate_runs_after_already_queued_immediates() {
    // Corpus 0026.
    let src = r#"
        const order = [];
        setImmediate(() => {
          order.push('A');
          setImmediate(() => { order.push('C'); console.log(order.join(',')); });
        });
        setImmediate(() => { order.push('B'); });
    "#;
    assert_eq!(eval_console(src), "A,B,C");
}

#[test]
fn clear_immediate_cancels_pending_immediate() {
    // Corpus 0011.
    let src = r#"
        let ran = false;
        const im = setImmediate(() => { ran = true; });
        clearImmediate(im);
        setTimeout(() => { console.log('immediate-ran:' + ran); }, 20);
    "#;
    assert_eq!(eval_console(src), "immediate-ran:false");
}

// -------------------------------------------------------------------------
// queueMicrotask
// -------------------------------------------------------------------------

#[test]
fn queue_microtask_runs_before_macrotasks() {
    // Corpus 0012.
    let src = r#"
        const order = [];
        setTimeout(() => { order.push('macro'); console.log(order.join(',')); }, 0);
        queueMicrotask(() => { order.push('micro'); });
        console.log('sync');
    "#;
    assert_eq!(eval_console(src), "sync\nmicro,macro");
}

#[test]
fn queue_microtask_fifo_ordering() {
    // Corpus 0022.
    let src = r#"
        const order = [];
        queueMicrotask(() => { order.push('m1'); });
        queueMicrotask(() => { order.push('m2'); });
        queueMicrotask(() => { console.log(order.join(',')); });
        console.log('sync-first');
    "#;
    assert_eq!(eval_console(src), "sync-first\nm1,m2");
}

#[test]
fn queue_microtask_inside_timer_drains_before_next_timer() {
    // Corpus 0023.
    let src = r#"
        setTimeout(() => {
          console.log('timerA');
          queueMicrotask(() => { console.log('microA'); });
        }, 5);
        setTimeout(() => { console.log('timerB'); }, 25);
    "#;
    assert_eq!(eval_console(src), "timerA\nmicroA\ntimerB");
}

#[test]
fn queue_microtask_interleaves_fifo_with_promise_jobs() {
    let src = r#"
        const order = [];
        Promise.resolve().then(() => { order.push('p1'); });
        queueMicrotask(() => { order.push('q1'); });
        Promise.resolve().then(() => { order.push('p2'); });
        setTimeout(() => { console.log(order.join(',')); }, 0);
    "#;
    assert_eq!(eval_console(src), "p1,q1,p2");
}

// -------------------------------------------------------------------------
// Globals as first-class values
// -------------------------------------------------------------------------

#[test]
fn timer_globals_are_typeof_function() {
    // Corpus 0028.
    let src = r#"
        console.log(typeof setTimeout === 'function');
        console.log(typeof clearTimeout === 'function');
        console.log(typeof setInterval === 'function');
        console.log(typeof clearInterval === 'function');
        console.log(typeof setImmediate === 'function');
        console.log(typeof queueMicrotask === 'function');
    "#;
    assert_eq!(eval_console(src), "true\ntrue\ntrue\ntrue\ntrue\ntrue");
}

#[test]
fn stored_timer_global_is_callable() {
    let src = r#"
        const st = setTimeout;
        const handle = st(() => { console.log('via-alias'); }, 5);
        console.log(typeof handle);
    "#;
    assert_eq!(eval_console(src), "object\nvia-alias");
}

#[test]
fn shadowed_timer_global_is_not_reinterpreted() {
    // Fail-closed shadowing contract (bd-1lw7r.13): a user binding wins.
    let src = r#"
        let setTimeout = 5;
        console.log(typeof setTimeout);
    "#;
    assert_eq!(eval_console(src), "number");
}

// -------------------------------------------------------------------------
// require('timers') / require('node:timers')
// -------------------------------------------------------------------------

#[test]
fn timers_module_exports_are_the_globals() {
    // Corpus 0014: identity holds because both lower to the same
    // first-class BuiltinFunction value.
    let src = r#"
        const timers = require('timers');
        console.log(timers.setTimeout === setTimeout);
        console.log(timers.clearTimeout === clearTimeout);
        console.log(timers.setInterval === setInterval);
        timers.setTimeout(() => { console.log('module-fired'); }, 10);
    "#;
    assert_eq!(eval_console(src), "true\ntrue\ntrue\nmodule-fired");
}

#[test]
fn node_prefixed_timers_specifier_is_recognized() {
    let src = r#"
        const timers = require('node:timers');
        timers.setTimeout(() => { console.log('node-prefixed-fired'); }, 5);
    "#;
    assert_eq!(eval_console(src), "node-prefixed-fired");
}

#[test]
fn timers_module_clear_timeout_cancels() {
    // Corpus 0029.
    let src = r#"
        const timers = require('timers');
        let fired = false;
        const t = timers.setTimeout(() => { fired = true; }, 10);
        timers.clearTimeout(t);
        setTimeout(() => { console.log('module-clear-fired:' + fired); }, 30);
    "#;
    assert_eq!(eval_console(src), "module-clear-fired:false");
}

#[test]
fn unused_timers_require_stays_ambient_refused() {
    // Fail-closed: a bare/unused alias keeps the ambient-authority denial.
    let err = eval_err("const timers = require('timers'); console.log('x');");
    assert!(
        err.contains("ambient authority violation"),
        "unused require('timers') must stay ambient-refused, got: {err}"
    );
}

// -------------------------------------------------------------------------
// require('timers/promises')
// -------------------------------------------------------------------------

#[test]
fn timers_promises_set_timeout_resolves_after_delay() {
    // Corpus 0015.
    let src = r#"
        const tp = require('timers/promises');
        tp.setTimeout(10).then(() => { console.log('promise-timer-resolved'); });
        console.log('scheduled');
    "#;
    assert_eq!(eval_console(src), "scheduled\npromise-timer-resolved");
}

#[test]
fn timers_promises_set_timeout_resolves_with_value() {
    // Corpus 0016.
    let src = r#"
        const tp = require('timers/promises');
        tp.setTimeout(10, 'payload').then((v) => { console.log('value:' + v); });
    "#;
    assert_eq!(eval_console(src), "value:payload");
}

#[test]
fn timers_promises_set_immediate_resolves() {
    let src = r#"
        const tp = require('timers/promises');
        tp.setImmediate('now').then((v) => { console.log('immediate:' + v); });
    "#;
    assert_eq!(eval_console(src), "immediate:now");
}

#[test]
fn timers_promises_set_interval_for_await_break() {
    // Corpus 0027: the deterministic async iterable; `break` terminates it.
    let src = r#"
        const tp = require('timers/promises');
        (async () => {
          let n = 0;
          for await (const _ of tp.setInterval(10)) {
            n++;
            if (n === 2) break;
          }
          console.log('iterations:' + n);
        })();
    "#;
    assert_eq!(eval_console(src), "iterations:2");
}

#[test]
fn timers_promises_set_interval_yields_value() {
    let src = r#"
        const tp = require('timers/promises');
        (async () => {
          for await (const v of tp.setInterval(5, 'tick')) {
            console.log('got:' + v);
            break;
          }
        })();
    "#;
    assert_eq!(eval_console(src), "got:tick");
}

#[test]
fn unused_timers_promises_require_stays_ambient_refused() {
    let err = eval_err("const tp = require('timers/promises'); console.log('x');");
    assert!(
        err.contains("ambient authority violation"),
        "unused require('timers/promises') must stay ambient-refused, got: {err}"
    );
}

#[test]
fn timers_promises_usage_inside_function_body_confirms_alias() {
    // The deep usage scan + body-lookup sentinel seeding: the only usage
    // lives inside a function body.
    let src = r#"
        const tp = require('timers/promises');
        function go() {
          tp.setTimeout(5, 'deep').then((v) => { console.log('deep:' + v); });
        }
        go();
    "#;
    assert_eq!(eval_console(src), "deep:deep");
}

// -------------------------------------------------------------------------
// Micro-vs-macro contracts kept (corpus 0013 regression guard)
// -------------------------------------------------------------------------

#[test]
fn promise_then_runs_before_zero_timeout() {
    let src = r#"
        const order = [];
        setTimeout(() => { order.push('timeout'); console.log(order.join(',')); }, 0);
        Promise.resolve('p').then((v) => { order.push('then:' + v); });
    "#;
    assert_eq!(eval_console(src), "then:p,timeout");
}

// -------------------------------------------------------------------------
// Engine-level fixes required by the breadth work
// -------------------------------------------------------------------------

#[test]
fn leading_dot_method_chain_lines_parse() {
    // Parser logical-line merge (corpus 0030 shape, and the general
    // formatter layout).
    let src = "const p = Promise.resolve('x');\np\n  .then(() => { console.log('t1'); })\n  .then(() => { console.log('t2'); });";
    assert_eq!(eval_console(src), "t1\nt2");
}

#[test]
fn leading_dot_merge_does_not_swallow_numeric_literals() {
    // `.5` starts a numeric literal, not a method-chain continuation.
    let src = "const x = 1;\nconsole.log(x + .5);";
    assert_eq!(eval_console(src), "1.5");
}

#[test]
fn nested_closure_method_call_on_captured_top_level_binding() {
    // The exact child-captured-locals shadowing bug (corpus 0026 family):
    // outer references `order`, the nested closure member-calls it later.
    let src = r#"
        const order = [];
        setTimeout(() => {
          order.push('A');
          setTimeout(() => {
            order.push('C');
            console.log(order.join(','));
          }, 5);
        }, 5);
        setTimeout(() => { order.push('B'); }, 10);
    "#;
    assert_eq!(eval_console(src), "A,B,C");
}

#[test]
fn sync_nested_closure_method_call_on_captured_binding() {
    // Pure-sync arm of the same fix: no timers involved.
    let src = r#"
        const arr = ['q'];
        function outer() {
          console.log('outer:' + arr.join(','));
          function inner() { console.log('inner:' + arr.join(',')); }
          inner();
        }
        outer();
    "#;
    assert_eq!(eval_console(src), "outer:q\ninner:q");
}
