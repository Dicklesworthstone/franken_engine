//! Text transforms through the actual native engine, not the Node-host factory.
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
        extension_id: "web-text-streams".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    engine.execute(&package).expect("native text-stream completion")
        .console_output.into_iter().map(|line| line.message).collect()
}

#[test]
fn native_encoder_decoder_and_tee_share_pipeline_state_and_realm_codecs() {
    let source = r#"
const web = require('node:stream/web');
const alias = require('stream/web');
const TextEncoder = 'guest', TextDecoder = 'guest', String = 'guest';
const input = web.ReadableStream.from(['A', '\ud83d', '', '\ude00', 'é', '\ud800']);
const encoding = new web.TextEncoderStream();
const [a, b] = input.pipeThrough(encoding).tee();
const bytes = [], text = [];
Promise.all([
  a.pipeTo(new web.WritableStream({write(value){for (const byte of value) bytes.push(byte);}})),
  b.pipeThrough(new alias.TextDecoderStream()).pipeTo(new web.WritableStream({write(value){text.push(value);}}))
]).then(function () {
  console.log('TEXT_PIPE', bytes.join(','), JSON.stringify(text.join('')), encoding.encoding, web === alias);
});
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), [
            "TEXT_PIPE 65,240,159,152,128,195,169,239,191,189 \"A😀é�\" utf-8 true",
        ]);
    }
}

#[test]
fn native_decoder_stream_preserves_view_offsets_bom_state_and_fatal_eof() {
    let source = r#"
const web = require('stream/web');
(async function () {
  const d = new web.TextDecoderStream('UTF8'); const output = [];
  const p = d.readable.pipeTo(new web.WritableStream({write(value){output.push(value);}}));
  const w = d.writable.getWriter();
  const bytes = new Uint8Array([9, 239, 187, 8]);
  await w.write(new DataView(bytes.buffer, 1, 2)); bytes.fill(0);
  await w.write(new Uint8Array([191, 226, 130]));
  await w.write(new Uint8Array([172])); await w.close(); await p;
  console.log('TEXT_DECODE', output.join(''), d.encoding, d.fatal, d.ignoreBOM);
  const fatal = new web.TextDecoderStream('utf-8', {fatal:true});
  const reading = fatal.readable.pipeTo(new web.WritableStream()).then(()=>'wrong',e=>e instanceof TypeError);
  const writer = fatal.writable.getWriter(); await writer.write(new Uint8Array([226]));
  const closing = await writer.close().then(()=>'wrong',e=>e instanceof TypeError);
  console.log('TEXT_EOF', closing, await reading);
})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), [
            "TEXT_DECODE € utf-8 false false", "TEXT_EOF true true",
        ]);
    }
}

#[test]
fn native_text_conversion_waits_for_demand_and_cancels_without_conversion() {
    let source = r#"
const web = require('stream/web');
(async function () {
  const stream = new web.TextEncoderStream(); const writer = stream.writable.getWriter();
  let calls = 0; const reason = {cancel:true};
  const pending = writer.write({toString(){calls++;return 'not converted';}}).then(()=>'wrong',e=>e===reason);
  await Promise.resolve(); await Promise.resolve();
  console.log('TEXT_PRESSURE', calls, writer.desiredSize);
  await stream.readable.cancel(reason); console.log('TEXT_CANCEL', await pending, calls);
  writer.releaseLock();
})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), ["TEXT_PRESSURE 0 0", "TEXT_CANCEL true 0"]);
    }
}

#[test]
fn native_cli_esm_text_stream_exports_reach_the_canonical_codecs() {
    let root = tempfile::tempdir().expect("temporary project");
    let source = r#"
import {ReadableStream, WritableStream, TextEncoderStream, TextDecoderStream} from 'node:stream/web';
const chunks = [];
ReadableStream.from(['hello ', '\ud83d', '\ude00']).pipeThrough(new TextEncoderStream())
  .pipeThrough(new TextDecoderStream()).pipeTo(new WritableStream({write(value){chunks.push(value);}}))
  .then(() => console.log('ESM_TEXT', chunks.join('')));
"#;
    let entry = root.path().join("main.mjs");
    std::fs::write(&entry, source).expect("write ESM input");
    let report = root.path().join("report.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input"]).arg(&entry)
        .args(["--goal", "module", "--extension-id", "web-text-streams-esm", "--out"])
        .arg(&report).output().expect("execute native engine");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let payload: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    let lines: Vec<_> = payload["console_output"].as_array().unwrap().iter()
        .map(|line| line["message"].as_str().unwrap()).collect();
    assert_eq!(lines, ["ESM_TEXT hello 😀"]);
}
