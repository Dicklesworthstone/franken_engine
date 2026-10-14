//! bd-9vouw.226: the WHATWG File API `Blob` global (Node v18+). sqids
//! refused every alphabet because `new Blob([alphabet]).size` threw "Blob is
//! not defined". The expected line is Node v22.2.0's output for the same
//! program (Bun 1.4.2 agrees).
//!
//! No-claim: `stream()`, `File`, `endings: 'native'`, structured
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

/// New byte-read cases use independently checked Node 22.16.0 expectations,
/// not a regenerated output from either native lane. The two lane names are
/// internal native engine choices, not executions of upstream V8/QuickJS.
#[test]
fn blob_bytes_are_promised_exact_and_independently_mutable() {
    let source = r#"
const source = new Uint8Array([99, 0, 255, 65, 88]);
const blob = new Blob([source.subarray(1, 4)], {type:'APPLICATION/OCTET-STREAM'});
source.fill(7);
const pending = blob.bytes();
console.log(pending instanceof Promise);
(async function () {
  const first = await pending;
  const second = await blob.bytes();
  const raw = await blob.arrayBuffer();
  console.log(first instanceof Uint8Array, first.byteOffset, first.length, first.join(','));
  console.log(first !== second, first.buffer !== second.buffer, first.buffer !== raw);
  first.fill(8);
  console.log(second.join(','), new Uint8Array(raw).join(','), blob.size, blob.type);
  console.log((await blob.bytes()).join(','));
})();
"#;
    assert_eq!(run(source), [
        "true",
        "true 0 3 0,255,65",
        "true true true",
        "0,255,65 0,255,65 3 application/octet-stream",
        "0,255,65",
    ]);
}

#[test]
fn blob_binary_reads_preserve_bom_invalid_utf8_and_nested_slice_boundaries() {
    let source = r#"
const input = new Uint8Array([9, 239, 187, 191, 255, 0, 65, 8]);
const view = new DataView(input.buffer, 1, 6);
const inner = new Blob([view]);
const blob = new Blob([inner, 'é', '\ud800']);
input.fill(0);
(async function () {
  console.log((await blob.bytes()).join(','));
  console.log((await blob.slice(3, -2).bytes()).join(','));
  console.log(JSON.stringify(await inner.text()));
  console.log((await new Blob().bytes()).length, (await new Blob().arrayBuffer()).byteLength);
})();
"#;
    assert_eq!(run(source), [
        "239,187,191,255,0,65,195,169,239,191,189",
        "255,0,65,195,169,239",
        "\"�\\u0000A\"",
        "0 0",
    ]);
}

#[test]
fn borrowed_blob_bytes_keep_brand_checks_and_do_not_consume_source() {
    let source = r#"
const read = Blob.prototype.bytes;
(async function () {
  for (const receiver of [null, {}, new Uint8Array([1])]) {
    try { await read.call(receiver); console.log('wrong receiver accepted'); }
    catch (error) { console.log(error.name); }
  }
  const blob = new Blob(['AB']);
  console.log((await read.call(blob)).join(','));
  console.log((await blob.bytes()).join(','));
})();
"#;
    assert_eq!(run(source), ["TypeError", "TypeError", "TypeError", "65,66", "65,66"]);
}

#[test]
fn blob_binary_read_callbacks_are_not_synchronous_and_results_never_alias() {
    let source = r#"
const blob = new Blob(['ok']);
const order = ['start'];
const first = blob.bytes().then(bytes => { order.push('bytes'); return bytes; });
const second = blob.arrayBuffer().then(bytes => { order.push('buffer'); return bytes; });
order.push('sync');
Promise.all([first, second]).then(([bytes, buffer]) => {
  console.log(order.join(','));
  bytes[0] = 0;
  console.log(new Uint8Array(buffer).join(','), blob.size);
});
"#;
    assert_eq!(run(source), ["start,sync,buffer,bytes", "111,107 2"]);
}

#[test]
fn blob_snapshots_each_iterated_binary_part_before_next_mutates_it() {
    let source = r#"
const source = new Uint8Array([65]);
function* parts() {
  yield source;
  source[0] = 66;
  yield source;
  source[0] = 67;
  yield new Blob(['D']);
}
const blob = new Blob(parts());
blob.bytes().then(bytes => console.log(bytes.join(','), source[0], blob.size));
"#;
    assert_eq!(run(source), ["65,66,68 67 3"]);
}
