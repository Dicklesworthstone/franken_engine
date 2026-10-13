//! Execute the engine-owned stream composition layer through the native VM.
//! Run: cargo test -p frankenengine-engine --test stream_composition
#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

fn console(source: &str) -> Vec<String> {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("native stream composition failed: {error}"));
    outcome
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

#[test]
fn composed_transforms_are_a_reusable_duplex() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            const first = new stream.Transform({objectMode: true,
              transform(value, encoding, done) { done(null, value * 2); }});
            const last = new stream.Transform({objectMode: true,
              transform(value, encoding, done) { done(null, value + 1); }});
            const combined = stream.compose(first, last);
            console.log(combined instanceof stream.Duplex, combined.readable, combined.writable);
            combined.on('data', value => console.log(value));
            combined.write(2);
            combined.end(4);
            "#,
        ),
        ["true true true", "5", "9"]
    );
}

#[test]
fn generator_functions_compose_over_shared_input_and_signal() {
    assert_eq!(
        console(
            r#"
            const stream = require('node:stream');
            let first;
            const combined = stream.compose(
              async function* (input, {signal}) {
                first = signal;
                for await (const value of input) yield value * 2;
              },
              async function* (input, {signal}) {
                for await (const value of input) {
                  console.log(signal === first);
                  yield value + 1;
                }
              });
            combined.on('data', value => console.log(value));
            combined.end(3);
            "#,
        ),
        ["true", "7"]
    );
}

#[test]
fn readable_compose_delivers_transformed_values_and_has_no_writable_input() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            const source = stream.Readable.from([2, 3]);
            const combined = source.compose(async function* (input) {
              for await (const value of input) yield value * 3;
            });
            console.log(combined.writable);
            combined.on('data', value => console.log(value));
            "#,
        ),
        ["false", "6", "9"]
    );
}

#[test]
fn sink_composition_waits_for_all_input_before_finish() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            let total = 0;
            const sink = stream.compose(async input => {
              for await (const value of input) total += value;
            });
            console.log(sink.readable, sink.writable);
            sink.write(2);
            sink.end(5, () => console.log(total));
            "#,
        ),
        ["false true", "7"]
    );
}

#[test]
fn stage_error_preserves_identity_and_destroys_the_composition() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            const failure = new Error('failed');
            const head = new stream.Transform({objectMode: true,
              transform(value, encoding, done) { done(failure); }});
            const tail = new stream.PassThrough({objectMode: true});
            const combined = stream.compose(head, tail);
            combined.on('error', error => console.log(error === failure,
              head.destroyed, tail.destroyed, combined.destroyed));
            combined.end(1);
            "#,
        ),
        ["true true true true"]
    );
}

#[test]
fn signal_cancellation_destroys_the_outer_duplex_and_its_stages() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            const controller = new AbortController();
            const source = new stream.Readable({read() {}});
            const tail = new stream.PassThrough();
            const combined = source.compose(tail, {signal: controller.signal});
            combined.on('error', error => console.log(error.code, error.cause,
              source.destroyed, tail.destroyed, combined.destroyed));
            controller.abort('stop');
            "#,
        ),
        ["ABORT_ERR stop true true true"]
    );
}

#[test]
fn invalid_composition_never_starts_a_stage_factory() {
    assert_eq!(
        console(
            r#"
            const stream = require('stream');
            let called = 0;
            try { stream.compose(() => { called++; return []; }, {}); }
            catch (error) { console.log(error.code, called); }
            "#,
        ),
        ["ERR_INVALID_ARG_TYPE 0"]
    );
}

#[test]
fn a_single_duplex_preserves_identity_and_the_prototype_operator_is_available() {
    assert_eq!(
        console(
            r#"
            const stream = require('node:stream');
            const passthrough = new stream.PassThrough();
            console.log(stream.compose(passthrough) === passthrough,
              typeof stream.Readable.prototype.compose);
            passthrough.end();
            passthrough.resume();
            "#,
        ),
        ["true function"]
    );
}
