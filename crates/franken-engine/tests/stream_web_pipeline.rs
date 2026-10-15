//! Actual native pipeline tests. Host bridge tests do not establish these results.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};

fn run(source: &str, lane: LaneChoice) -> Vec<String> {
    let mut engine = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    let package = ExtensionPackage {
        extension_id: "stream-web-pipeline".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    engine
        .execute(&package)
        .expect("native pipeline completes")
        .console_output
        .into_iter()
        .map(|line| line.message)
        .collect()
}

const MIXED: &str = r#"
const s = require('node:stream'), web = require('node:stream/web');
const Array = 'guest', Symbol = 'guest', Reflect = 'guest', Promise = 'guest';
const out = [];
const source = web.ReadableStream.from([1, 2, 3]);
const transform = new web.TransformStream({transform(value, c) { c.enqueue(value * 2); }});
const middle = new s.Transform({objectMode:true, transform(value, encoding, done) { done(null, value + 1); }});
const sink = new web.WritableStream({write(value) { out.push(value); }});
s.promises.pipeline([source, transform, middle, sink]).then(function () {
  console.log('MIXED_PIPELINE', out.join(','), source.locked, sink.locked);
});
"#;

#[test]
fn mixed_web_and_node_stages_use_one_native_pipeline_on_both_lanes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(MIXED, lane), ["MIXED_PIPELINE 3,5,7 false true"]);
    }
}

const CALLBACK: &str = r#"
const { pipeline } = require('stream'), web = require('stream/web');
const out = [], sink = new web.WritableStream({write(value) { out.push(value); }});
const returned = pipeline(web.ReadableStream.from(['a', 'b']), sink, function (error) {
  if (error) throw error;
  console.log('CALLBACK_PIPELINE', returned === sink, out.join(','));
});
"#;

#[test]
fn callback_completion_retains_the_original_web_destination() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(CALLBACK, lane), ["CALLBACK_PIPELINE true a,b"]);
    }
}

// Candidate cleanup regression: Node 22 raw Web pipeline can leave this
// no-chunk cancellation unresolved; the bridge host suite checks completion.
const ABORT: &str = r#"
const s = require('stream'), web = require('stream/web');
const controller = new AbortController(), events = [];
const source = new web.ReadableStream({cancel() { events.push('cancel'); }}, {highWaterMark:0});
const sink = new web.WritableStream({abort() { events.push('abort'); }});
const done = s.promises.pipeline(source, sink, {signal:controller.signal});
controller.abort('stop');
done.catch(function (error) {
  console.log('ABORT_PIPELINE', error.code, events.sort().join(','), source.locked);
});
"#;

#[test]
fn cancellation_finishes_both_endpoints_without_waiting_for_a_source_chunk() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(ABORT, lane), ["ABORT_PIPELINE ABORT_ERR abort,cancel false"]);
    }
}

const ESM: &str = r#"
import { pipeline } from 'node:stream/promises';
import { ReadableStream, TransformStream, WritableStream } from 'node:stream/web';
const output = [];
pipeline(ReadableStream.from([20, 22]),
  new TransformStream({transform(value, c) { c.enqueue(value * 2); }}),
  new WritableStream({write(value) { output.push(value); }}))
  .then(() => console.log('ESM_PIPELINE', output.join(',')));
"#;

#[test]
fn esm_named_imports_share_the_native_promise_pipeline() {
    let root = tempfile::tempdir().expect("temporary project");
    let entry = root.path().join("main.mjs");
    std::fs::write(&entry, ESM).expect("write source");
    let report = root.path().join("report.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input"])
        .arg(&entry)
        .args(["--goal", "module", "--extension-id", "web-pipeline-esm", "--out"])
        .arg(&report)
        .output()
        .expect("execute native engine");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let payload: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).expect("read report")).expect("report JSON");
    let lines: Vec<_> = payload["console_output"]
        .as_array()
        .expect("console output")
        .iter()
        .map(|line| line["message"].as_str().expect("console message"))
        .collect();
    assert_eq!(lines, ["ESM_PIPELINE 40,44"]);
}

#[test]
fn generic_duplex_from_adopts_a_web_transform_on_the_shared_pipeline() {
    let source = r#"
const s = require('node:stream'), web = require('stream/web');
const t = new web.TransformStream({transform(chunk, c) { c.enqueue(chunk); }});
const d = s.Duplex.from(t), chunks = [];
s.promises.pipeline(s.Readable.from(['ab', 'cd']), d,
  new s.Writable({write(chunk, encoding, done) { chunks.push(chunk.toString()); done(); }}))
  .then(function () {
    console.log('GENERIC_TRANSFORM', chunks.join(''), d.readableObjectMode,
      d.writableObjectMode, t.readable.locked, t.writable.locked);
  });
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane),
            ["GENERIC_TRANSFORM abcd false false true true"]
        );
    }
}

#[test]
fn generic_duplex_from_adopts_a_web_writer_and_waits_for_its_close() {
    let source = r#"
const s = require('stream'), web = require('node:stream/web'), events = [];
const sink = new web.WritableStream({
  write(chunk) { events.push(chunk.toString('hex')); },
  async close() { await Promise.resolve(); events.push('closed'); }
});
const d = s.Duplex.from(sink);
const done = s.promises.finished(d);
d.write('A'); d.end('B');
done.then(function () {
  console.log('GENERIC_WRITER', events.join(','), d.readable, d.writableObjectMode, sink.locked);
});
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(source, lane),
            ["GENERIC_WRITER 41,42,closed false false true"]
        );
    }
}
