//! Blob sources use the actual module lowerer, Blob object and stream owners.
//! Host JavaScript tests are not evidence that these native probes pass.
#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

fn run(source: &str, expected: &str) {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("native Blob stream failed: {error}"));
    let output = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(output, expected);
}

#[test]
fn blob_and_file_deliver_one_array_buffer_even_when_empty() {
    run(
        r#"
const stream = require('node:stream');
const binary = require('node:buffer');
const Blob = 'guest binding';
(async function () {
  const inputs = [new binary.Blob(['café']), new binary.Blob([]),
    new binary.File(['file'], 'input.txt', { lastModified: 0 })];
  for (const input of inputs) {
    const source = stream.Duplex.from(input);
    let count = 0, text = '';
    for await (const value of source) {
      if (!(value instanceof ArrayBuffer)) throw new Error('not an ArrayBuffer');
      count++; text += Buffer.from(value).toString();
    }
    console.log(count, source.writable, source.readableObjectMode, text);
  }
  console.log('blob sources complete');
})();
"#,
        "1 false true café\n1 false true \n1 false true file\nblob sources complete",
    );
}

#[test]
fn blob_pipeline_and_composition_use_the_canonical_stream_lifecycle() {
    run(
        r#"
const stream = require('stream');
(async function () {
  let output = '';
  function convert() {
    return new stream.Transform({ objectMode: true,
      transform(value, encoding, done) { done(null, Buffer.from(value)); } });
  }
  const sink = new stream.Writable({
    write(value, encoding, done) { output += value.toString(); done(); } });
  await stream.promises.pipeline(new Blob(['pipeline-é']), convert(), sink);
  let composed = '';
  for await (const value of stream.compose(new Blob(['compose']), convert())) composed += value.toString();
  console.log(output, sink.writableFinished, composed);
})();
"#,
        "pipeline-é true compose",
    );
}

#[test]
fn blob_failure_never_becomes_a_successful_pipeline() {
    run(
        r#"
const stream = require('stream');
(async function () {
  const reason = new Error('cannot snapshot');
  const blob = new Blob(['unused']);
  blob.arrayBuffer = function () { return Promise.reject(reason); };
  let writes = 0, finals = 0;
  const sink = new stream.Writable({ objectMode: true,
    write(value, encoding, done) { writes++; done(); },
    final(done) { finals++; done(); } });
  try { await stream.promises.pipeline(blob, sink); throw new Error('false success'); }
  catch (error) {
    if (error !== reason) throw error;
    console.log(error.message, writes, finals, sink.destroyed);
  }
})();
"#,
        "cannot snapshot 0 0 true",
    );
}

#[test]
fn cancelled_blob_conversion_cannot_publish_late_data() {
    // Deliberately stronger than Node 22.16's pending-Blob pipeline behavior.
    run(
        r#"
const stream = require('stream');
(async function () {
  let release;
  const blob = new Blob(['unused']);
  blob.arrayBuffer = function () { return new Promise(resolve => { release = resolve; }); };
  let writes = 0, finals = 0;
  const sink = new stream.Writable({ objectMode: true,
    write(value, encoding, done) { writes++; done(); },
    final(done) { finals++; done(); } });
  const controller = new AbortController();
  const task = stream.promises.pipeline(blob, sink, { signal: controller.signal });
  controller.abort('stop');
  try { await task; throw new Error('false success'); }
  catch (error) {
    if (error.code !== 'ABORT_ERR') throw error;
    release(new Uint8Array([88]).buffer);
    await Promise.resolve(); await Promise.resolve();
    console.log(error.code, writes, finals, sink.destroyed);
  }
})();
"#,
        "ABORT_ERR 0 0 true",
    );
}
