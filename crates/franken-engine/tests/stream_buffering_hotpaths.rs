//! Stream queue regressions through real source lowering and execution.
//! Source-level Node tests live in scripts/tests/stream_buffering.cjs.
use frankenengine_engine::HybridRouter;

// Match the existing stream-module regression target's execution envelope.
const INSTRUCTION_BUDGET: u64 = 200_000_000;

fn console_lines(source: &str) -> String {
    let outcome = HybridRouter::default()
        .eval_with_instruction_budget(source, INSTRUCTION_BUDGET)
        .unwrap_or_else(|error| panic!("stream buffering probe failed: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn steady_readable_preserves_fifo_prepend_and_eof() {
    assert_eq!(
        console_lines(include_str!("fixtures/stream_buffering/steady_readable.js")),
        "fifo 8128512 0"
    );
}

#[test]
fn partial_reads_preserve_exact_strings_and_bytes() {
    assert_eq!(
        console_lines(include_str!("fixtures/stream_buffering/partial_readable.js")),
        "text 4538275 44\nbytes 00100111021203 feff13041405 1506160717081809190a1a0b1b0c1c0d1d0e1e0f1f"
    );
}

#[test]
fn steady_readable_storage_is_bounded_by_backlog_not_total_reads() {
    let source = r#"
const stream = require('stream');
const r = new stream.Readable({objectMode: true, read() {}});
for (let i = 0; i < 32; i++) r.push({i: i});
for (let i = 0; i < 4096; i++) { r.read(); r.push({i: i}); }
const buffer = r._readableState.buffer;
if (buffer.size() !== 32 || buffer.chunks.length > 64) throw new Error('unbounded queue');
console.log('bounded');
r.destroy();
"#;
    assert_eq!(console_lines(source), "bounded");
}

#[test]
fn buffered_writes_preserve_callbacks_backpressure_and_finish_order() {
    assert_eq!(
        console_lines(include_str!("fixtures/stream_buffering/buffered_writable.js")),
        "write 2048 2048 2096128 drain,end-callback,finish"
    );
}
