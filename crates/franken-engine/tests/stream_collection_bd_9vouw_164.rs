//! bd-9vouw.164: a live stream or pipeline no longer disables garbage
//! collection.
//!
//! The collector refused to run while any stream, pipeline or cluster facade
//! state existed (host state "not traced yet"), so a program that created
//! one stream died at the 100,000-object budget. Live stream state is now
//! traced as a root while its entry exists (write/final/read callbacks,
//! queued chunks and their callbacks, end callbacks, errors, pipeline stages
//! and completions, pipe links, scheduled emissions); a terminal state with
//! nothing pending is weak and purged when its stream is reclaimed. Each
//! program runs on the default QuickJS lane (100,000 heap objects, asserted)
//! with 250,000 short-lived objects. Expected strings are Node v22.2.0's
//! console output for the same programs.
//!
//! No-claim: an unfinished stream's live state is a root, so a stream nothing
//! references is not reclaimed until it finishes or is destroyed and its
//! ticks have run; http, loopback and child-process state still block
//! collection.

#![forbid(unsafe_code)]

use frankenengine_engine::{EngineKind, HybridRouter};

fn console_output(source: &str) -> String {
    let outcome = HybridRouter::default()
        .eval_with_instruction_budget(source, 1_000_000_000)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"));
    assert_eq!(outcome.engine, EngineKind::QuickJsInspiredNative);
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// A PassThrough with a data listener keeps working after 250,000 short-lived objects.
#[test]
fn stream_collection_passthrough_survives_collection() {
    let source = "const { PassThrough } = require('stream');\n\
         const p = new PassThrough(); const got = [];\n\
         p.on('data', (chunk) => got.push(String(chunk)));\n\
         p.on('end', () => console.log('end', got.join('+'), s));\n\
         let s = 0; for (let i = 0; i < 250000; i++) { const o = { a: i }; s += o.a & 1; }\n\
         p.write('a'); p.end('b');";
    assert_eq!(console_output(source), "end a+b 125000");
}

/// A Writable's write implementation, queued write callback and end callback survive collection.
#[test]
fn stream_collection_writable_callbacks_survive_collection() {
    let source = "const { Writable } = require('stream');\n\
         const seen = [];\n\
         const w = new Writable({ write(chunk, encoding, callback) { seen.push(String(chunk)); callback(); } });\n\
         w.write('x', () => console.log('written', seen.join('')));\n\
         let s = 0; for (let i = 0; i < 250000; i++) { const o = { a: i }; s += o.a & 1; }\n\
         w.write('y');\n\
         w.end(() => console.log('finished', seen.join(''), s));";
    assert_eq!(console_output(source), "written xy\nfinished xy 125000");
}

/// A pipeline started before the garbage completes after it.
#[test]
fn stream_collection_pipeline_survives_collection() {
    let source = "const { pipeline, Readable, PassThrough, Writable } = require('stream');\n\
         const out = [];\n\
         pipeline(Readable.from(['a', 'b', 'c']), new PassThrough(),\n\
           new Writable({ write(chunk, encoding, callback) { out.push(String(chunk)); callback(); } }),\n\
           (error) => console.log('pipeline', error === undefined ? 'ok' : String(error), out.join('')));\n\
         let s = 0; for (let i = 0; i < 250000; i++) { const o = { a: i }; s += o.a & 1; }";
    assert_eq!(console_output(source), "pipeline ok abc");
}
