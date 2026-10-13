//! TextEncoder byte copies through the production CLI.
//! Console oracles were executed under Node v22.16.0; that is not native Rust
//! validation or an engine-versus-V8 benchmark.

use std::process::Command;

const ENCODING: &str = r#"var encoder = new TextEncoder();
var texts = ['', 'ascii\0\n', 'é€😀', '\ud800x\udc00', '\ud83d\ude00', '\ud800\ud800\udc00'];
var rows = [];
for (var t = 0; t < texts.length; t++) {
  rows.push(Array.from(encoder.encode(texts[t])).join(','));
}
console.log(JSON.stringify(rows));
var checks = 0;
var digest = 0;
for (var i = 0; i < texts.length; i++) {
  for (var size = 0; size <= 16; size++) {
    var storage = new Uint8Array(size + 8).fill(165);
    var view = new Uint8Array(storage.buffer, 4, size);
    var progress = encoder.encodeInto(texts[i], view);
    for (var k = 0; k < 4; k++) if (storage[k] !== 165) throw 'prefix overwritten';
    for (var n = 4 + progress.written; n < storage.length; n++) if (storage[n] !== 165) throw 'suffix overwritten';
    digest = (Math.imul(digest, 31) + progress.read) >>> 0;
    digest = (Math.imul(digest, 31) + progress.written) >>> 0;
    for (var b = 0; b < storage.length; b++) digest = (Math.imul(digest, 31) + storage[b]) >>> 0;
    checks++;
  }
}
console.log(checks, digest);
var rope = '';
for (var r = 0; r < 2000; r++) rope += 'aé€😀';
rope += '\ud800z';
var encoded = encoder.encode(rope);
var destination = new Uint8Array(encoded.length + 1).fill(165);
var totalRead = 0;
var totalWritten = 0;
for (var round = 0; round < 12; round++) {
  var copied = encoder.encodeInto(rope, destination);
  totalRead += copied.read;
  totalWritten += copied.written;
}
var byteSum = 0;
for (var p = 0; p < encoded.length; p++) {
  if (destination[p] !== encoded[p]) throw 'encoding mismatch';
  byteSum += destination[p];
}
console.log(rope.length, encoded.length, totalRead, totalWritten, byteSum, destination[encoded.length]);
console.log(JSON.stringify(new TextDecoder().decode(encoded).slice(-8)));
"#;

const ENCODING_EXPECTED: &[&str] = &[
    r#"["","97,115,99,105,105,0,10","195,169,226,130,172,240,159,152,128","239,191,189,120,239,191,189","240,159,152,128","239,191,189,240,144,128,128"]"#,
    r#"102 2450790944"#,
    r#"10002 20004 120024 240048 3336741 165"#,
    r#""\ude00aé€😀�z""#,
];

const VIEWS: &str = r#"var encoder = new TextEncoder();
var backing = new Uint8Array(16).fill(165);
var view = new Uint8Array(backing.buffer, 4, 8);
var result = encoder.encodeInto('a€😀b', view);
console.log(result.read, result.written, Array.from(backing).join(','));
var short = new Uint8Array(3).fill(165);
var fn = encoder.encodeInto;
var skipped = fn.call(encoder, '😀', short);
console.log(skipped.read, skipped.written, short.join(','));
var errors = [];
for (var invalid of [new Uint16Array(2), new DataView(new ArrayBuffer(2)), new ArrayBuffer(2), {}]) {
  try { encoder.encodeInto('x', invalid); errors.push('accepted'); }
  catch (error) { errors.push(error.name); }
}
try { encoder.encode.call({encoding:'utf-8'}, 'x'); errors.push('accepted'); }
catch (error) { errors.push(error.name); }
console.log(errors.join(','));
var shared = new Uint8Array(new SharedArrayBuffer(12), 2, 8);
var sharedResult = encoder.encodeInto('é😀xy!', shared);
console.log(sharedResult.read, sharedResult.written, Array.from(shared).join(','));
var movable = new ArrayBuffer(12);
var stale = new Uint8Array(movable, 4, 8);
movable.transfer();
var empty = encoder.encodeInto('abc', stale);
console.log(empty.read, empty.written);
var resizable = new ArrayBuffer(24, {maxByteLength:32});
var fixed = new Uint8Array(resizable, 16, 8);
resizable.resize(8);
var outOfBounds = encoder.encodeInto('abc', fixed);
resizable.resize(32);
var restored = encoder.encodeInto('é😀xy!', fixed);
console.log(outOfBounds.read, outOfBounds.written, restored.read, restored.written, fixed.join(','));
"#;

const VIEWS_EXPECTED: &[&str] = &[
    r#"4 8 165,165,165,165,97,226,130,172,240,159,152,128,165,165,165,165"#,
    r#"0 0 165,165,165"#,
    r#"TypeError,TypeError,TypeError,TypeError,TypeError"#,
    r#"5 8 195,169,240,159,152,128,120,121"#,
    r#"0 0"#,
    r#"0 0 5 8 195,169,240,159,152,128,120,121"#,
];

fn run(source: &str, expected: &[&str]) {
    let root = tempfile::tempdir().expect("temporary directory");
    let entry = root.path().join("text_encoder.js");
    let report = root.path().join("report.json");
    std::fs::write(&entry, source).expect("write source");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("UTF-8 path"),
            "--extension-id",
            "direct-text-encoding",
            "--instruction-budget",
            "2000000000",
            "--out",
            report.to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run frankenctl");
    assert!(
        output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).expect("read report")).expect("JSON report");
    let actual = report["console_output"]
        .as_array()
        .expect("console output")
        .iter()
        .map(|entry| entry["message"].as_str().expect("console message"))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn exact_strings_and_repeated_rope_encoding_match_node() {
    run(ENCODING, ENCODING_EXPECTED);
}

#[test]
fn typed_destinations_and_buffer_lifecycle_match_node() {
    run(VIEWS, VIEWS_EXPECTED);
}
