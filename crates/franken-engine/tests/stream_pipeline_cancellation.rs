//! Native execution regressions for stream pipeline and finished cancellation.
#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

fn console(source: &str) -> Vec<String> {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("native stream evaluation failed: {error}"));
    outcome
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

#[test]
fn function_stages_share_a_run_signal_and_return_the_destination_value() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            let first;
            stream.promises.pipeline(
              ({signal}) => { first = signal; return [1, 2, 3]; },
              async function* (input, {signal}) {
                console.log(signal === first, signal.aborted);
                for await (const value of input) yield value * 2;
              },
              async (input, {signal}) => {
                console.log(signal === first);
                let total = 0;
                for await (const value of input) total += value;
                return total;
              }
            ).then(value => console.log(value, first.aborted));
            "#,
        ),
        ["true", "true false", "12 true"]
    );
}

#[test]
fn external_abort_destroys_every_stream_stage() {
    assert_eq!(
        console(
            r#"
            const stream = require('node:stream');
            const controller = new AbortController();
            const source = new stream.Readable({read() {}});
            const middle = new stream.PassThrough();
            const destination = new stream.Writable({write(chunk, encoding, done) {done();}});
            stream.promises.pipeline(source, middle, destination, {signal: controller.signal})
              .catch(error => console.log(error.code, error.cause,
                source.destroyed, middle.destroyed, destination.destroyed));
            controller.abort('stop');
            "#,
        ),
        ["ABORT_ERR stop true true true"]
    );
}

#[test]
fn stopped_public_abort_events_do_not_suppress_pipeline_cleanup() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            const controller = new AbortController();
            controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
            const source = new stream.Readable({read() {}});
            const destination = new stream.Writable({write(chunk, encoding, done) {done();}});
            stream.promises.pipeline(source, destination, {signal: controller.signal})
              .catch(error => console.log(error.code, source.destroyed, destination.destroyed));
            controller.abort();
            "#,
        ),
        ["ABORT_ERR true true"]
    );
}

#[test]
fn late_iterator_output_is_blocked_and_return_is_awaited() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            const controller = new AbortController();
            let release;
            let written = 0;
            let returned = 0;
            const source = {
              [Symbol.asyncIterator]() { return this; },
              next() { return new Promise(resolve => { release = resolve; }); },
              return() { returned++; return Promise.resolve({done: true}); }
            };
            const destination = new stream.Writable({objectMode: true,
              write(chunk, encoding, done) { written++; done(); }});
            stream.promises.pipeline(source, destination, {signal: controller.signal})
              .catch(error => console.log(error.code, written, returned));
            controller.abort();
            release({value: 'late', done: false});
            "#,
        ),
        ["ABORT_ERR 0 1"]
    );
}

#[test]
fn stage_failure_aborts_the_run_signal_and_preserves_the_error() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            const failure = new Error('stage failed');
            let signal;
            let cleaned = false;
            async function* source(options) {
              signal = options.signal;
              try { yield 1; yield 2; } finally { cleaned = true; }
            }
            async function* transform(input) {
              for await (const value of input) throw failure;
            }
            const destination = new stream.Writable({objectMode: true,
              write(chunk, encoding, done) {done();}});
            stream.promises.pipeline(source, transform, destination).catch(error => {
              console.log(error === failure, cleaned, signal.aborted, destination.destroyed);
            });
            "#,
        ),
        ["true true true true"]
    );
}

#[test]
fn end_false_preserves_successful_destination_ownership() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            let total = 0;
            const destination = new stream.Writable({objectMode: true,
              write(value, encoding, done) {total += value; done();}});
            stream.promises.pipeline(stream.Readable.from([1, 2, 3]), destination, {end: false})
              .then(() => {
                console.log(total, destination.writableEnded, destination.destroyed);
                destination.end();
              });
            "#,
        ),
        ["6 false false"]
    );
}

#[test]
fn new_cancellation_helpers_are_protected_from_guest_lexical_shadowing() {
    assert_eq!(
        console(
            r#"
            const AbortController = 'guest';
            const AbortSignal = 'guest';
            const EventTarget = 'guest';
            const Reflect = 'guest';
            const stream = require('stream');
            const controller = new globalThis.AbortController();
            controller.abort('before');
            let written = 0;
            const destination = new stream.Writable({objectMode: true,
              write(value, encoding, done) {written++; done();}});
            stream.promises.pipeline([1, 2], destination, {signal: controller.signal})
              .catch(error => console.log(error.code, error.cause, written));
            "#,
        ),
        ["ABORT_ERR before 0"]
    );
}

#[test]
fn cancelling_finished_stops_waiting_without_destroying_the_stream() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            const controller = new AbortController();
            const source = new stream.Readable({read() {}});
            stream.promises.finished(source, {signal: controller.signal, cleanup: true})
              .catch(error => {
                console.log(error.code, source.destroyed, source.listenerCount('error'));
                source.destroy();
              });
            controller.abort();
            "#,
        ),
        ["ABORT_ERR false 0"]
    );
}

#[test]
fn finished_cleanup_true_removes_successful_waiters() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            const source = stream.Readable.from(['done']);
            stream.promises.finished(source, {cleanup: true}).then(() => {
              console.log(source.listenerCount('end'), source.listenerCount('close'),
                source.listenerCount('error'));
            });
            source.resume();
            "#,
        ),
        ["0 0 0"]
    );
}
