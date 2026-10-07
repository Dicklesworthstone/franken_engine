//! bd-9vouw.226: the WHATWG File API `Blob` global (Node v18+). sqids
//! refused every alphabet because `new Blob([alphabet]).size` threw "Blob is
//! not defined". The expected line is Node v22.2.0's output for the same
//! program (Bun 1.4.2 agrees).
//!
//! No-claim: `stream()`, `bytes()`, `File`, `endings: 'native'`, structured
//! cloning and util.inspect of a blob.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

/// Runs `source` as a script on both lanes and returns its console lines.
fn run(source: &str) -> Vec<String> {
    let mut outputs = [LaneChoice::QuickJs, LaneChoice::V8].map(|lane| {
        let package = ExtensionPackage {
            extension_id: "blob".to_string(),
            source: source.to_string(),
            source_file: None,
            module_root: None,
            capabilities: vec!["builtin".to_string()],
            version: "1.0.0".to_string(),
            metadata: Default::default(),
        };
        ExecutionOrchestrator::new(OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Script,
            ..OrchestratorConfig::default()
        })
        .execute(&package)
        .unwrap_or_else(|error| panic!("{lane:?}: {error}"))
        .console_output
        .into_iter()
        .map(|line| line.message)
        .collect::<Vec<_>>()
    });
    assert_eq!(outputs[0], outputs[1], "lanes disagree");
    std::mem::take(&mut outputs[0])
}

/// Parts of every kind (a multibyte string, a lone surrogate as U+FFFD, a
/// typed array view's range, a DataView, a blob, a number, an object), the
/// type lowercased or dropped when not printable ASCII, size / type
/// accessors on Blob.prototype with their brand check, slice with relative
/// indices and a type, text() and arrayBuffer() promises, `new` required and
/// a string is not a part sequence.
#[test]
fn blobs_hold_bytes_and_a_type() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\nvar u8 = new Uint8Array([104, 105, 33, 63]);\nvar parts = ['é', '\\ud800', u8.subarray(1, 3), new DataView(u8.buffer, 0, 1), new Blob(['xy']), 7, {}];\nvar b = new Blob(parts, { type: 'Text/Plain;Charset=UTF-8' });\nvar out = [b.size, b.type, Object.prototype.toString.call(b), b instanceof Blob, typeof Blob, Blob.length,\n  new Blob().size, new Blob([], { type: 'ä/b' }).type, attempt(() => Blob([])), attempt(() => new Blob('abc')),\n  typeof Object.getOwnPropertyDescriptor(Blob.prototype, 'size').get, attempt(() => Object.getOwnPropertyDescriptor(Blob.prototype, 'size').get.call({})),\n  b.slice(2, 5).size, b.slice(-3).size, b.slice(1, 2, 'A/B').type, new Blob(['multibyte: ü']).size, new Blob(['abc']).size === 'abc'.length];\nPromise.all([b.text(), b.slice(0, 2).arrayBuffer(), new Blob(['q']).text()]).then(([text, buffer, q]) => {\n  out.push(JSON.stringify(text), buffer instanceof ArrayBuffer, buffer.byteLength, new Uint8Array(buffer).join('-'), q);\n  console.log(out.join(' | '));\n});\n";
    assert_eq!(
        run(source),
        [
            "26 | text/plain;charset=utf-8 | [object Blob] | true | function | 0 | 0 |  | TypeError | TypeError | function | TypeError | 3 | 3 | a/b | 13 | true | \"é�i!hxy7[object Object]\" | true | 2 | 195-169 | q"
        ]
    );
}
