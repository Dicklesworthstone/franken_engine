//! Native composition across the canonical Node/Web module boundary.
//! The host bridge suite is separate and cannot establish these results.
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
        extension_id: "web-composition".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    engine.execute(&package).expect("native composition completes")
        .console_output.into_iter().map(|line| line.message).collect()
}

const REUSABLE_CHAIN: &str = r#"
const { compose: chain } = require('stream');
const { Readable: R, Writable: W, promises } = require('node:stream');
const { TransformStream: T } = require('node:stream/web');
const Object = 'guest', Reflect = 'guest', Array = 'guest';
const a = new T({ transform(value, c) { c.enqueue({ text: String(value).toUpperCase() }); } });
const b = new T({ transform(value, c) { c.enqueue(value.text); }, flush(c) { c.enqueue('!'); } });
const reusable = chain(a, b);
const output = [];
promises.pipeline(R.from(['alpha', 'beta']), reusable,
  new W({ write(chunk, encoding, done) { output.push(chunk.toString()); done(); } }))
  .then(() => console.log('COMPOSE_COMPLETE', output.join(''), reusable.readableObjectMode, reusable.writableObjectMode));
"#;

#[test]
fn reusable_web_chain_uses_the_existing_pipeline_and_protected_globals() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(REUSABLE_CHAIN, lane), ["COMPOSE_COMPLETE ALPHABETA! false false"]);
    }
}

const READABLE_OPERATOR: &str = r#"
const { Readable } = require('node:stream');
const { TransformStream } = require('stream/web');
const transformed = Readable.from(['ab', 'cd']).compose(new TransformStream({
  async transform(value, c) { await 0; c.enqueue(String(value).toUpperCase()); }
}));
(async function () {
  let text = '';
  for await (const chunk of transformed) text += chunk.toString();
  console.log('OPERATOR_COMPLETE', text);
})();
"#;

#[test]
fn separately_imported_readable_from_values_keep_the_complete_composition_path() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(READABLE_OPERATOR, lane), ["OPERATOR_COMPLETE ABCD"]);
    }
}

const CLEANUP: &str = r#"
const s = require('stream'), w = require('stream/web');
const released = [];
const pair = {
  readable: new w.ReadableStream({ async cancel() { await 0; released.push('read'); } }, { highWaterMark: 0 }),
  writable: new w.WritableStream({ async abort() { await 0; released.push('write'); } })
};
const out = s.compose(pair, new s.PassThrough());
out.on('error', function () {});
out.on('close', function () { console.log('COMPOSE_CLEANUP', released.sort().join(',')); });
out.destroy(Error('stop'));
"#;

#[test]
fn explicit_destroy_waits_for_both_adopted_web_halves() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(CLEANUP, lane), ["COMPOSE_CLEANUP read,write"]);
    }
}

#[test]
fn esm_named_composition_imports_execute_the_native_cli() {
    let root = tempfile::tempdir().expect("temporary project");
    let entry = root.path().join("main.mjs");
    let source = r#"
import { compose, Readable, Writable, promises } from 'node:stream';
import { TransformStream } from 'node:stream/web';
const out = [];
const reusable = compose(new TransformStream({ transform(x, c) { c.enqueue(String(x).toUpperCase()); } }),
  new TransformStream({ transform(x, c) { c.enqueue(x); } }));
promises.pipeline(Readable.from(['esm']), reusable,
  new Writable({ write(x, e, cb) { out.push(x.toString()); cb(); } }))
  .then(() => console.log('ESM_COMPOSE_COMPLETE', out.join('')));
"#;
    std::fs::write(&entry, source).expect("write source");
    let report = root.path().join("report.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input"]).arg(&entry)
        .args(["--goal", "module", "--extension-id", "web-compose-esm", "--out"])
        .arg(&report).output().expect("execute native frankenctl");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let data: serde_json::Value = serde_json::from_slice(
        &std::fs::read(report).expect("read native report"),
    ).expect("report JSON");
    let lines: Vec<_> = data["console_output"].as_array().expect("console array")
        .iter().map(|line| line["message"].as_str().expect("console message")).collect();
    assert_eq!(lines, ["ESM_COMPOSE_COMPLETE ESM"]);
}
