//! Runtime-string decoder output through frankenctl. The console oracles
//! are checked with Node; that reference run does not execute the Rust VM.

use std::process::Command;

const WHOLE: &str = r#"function bytesFor(text, encoding) {
  if (encoding === 'utf-8') return new TextEncoder().encode(text);
  var bytes = new Uint8Array(text.length * 2);
  for (var i = 0; i < text.length; i++) {
    var unit = text.charCodeAt(i);
    bytes[i * 2 + (encoding === 'utf-16be' ? 1 : 0)] = unit & 255;
    bytes[i * 2 + (encoding === 'utf-16be' ? 0 : 1)] = unit >> 8;
  }
  return bytes;
}
var source = '\ufeff' + 'Aé日😀\u0000\ud7ff\ue000'.repeat(512) + '\ufeff';
for (var encoding of ['utf-8', 'utf-16le', 'utf-16be']) {
  var checks = 0;
  for (var fatal of [false, true]) {
    for (var ignoreBOM of [false, true]) {
      var data = bytesFor(source, encoding);
      var framed = new Uint8Array(data.length + 8).fill(165);
      framed.set(data, 4);
      var view = new DataView(framed.buffer, 4, data.length);
      Object.defineProperty(view, 'byteOffset', {value:0});
      Object.defineProperty(view, 'byteLength', {value:1});
      var decoder = new TextDecoder(encoding, {fatal:fatal, ignoreBOM:ignoreBOM});
      var output = decoder.decode(view);
      var expected = ignoreBOM ? source : source.slice(1);
      if (output !== expected) throw 'wrong decoded text';
      framed.fill(0);
      if (output !== expected) throw 'retained mutable input';
      if (decoder.decode(bytesFor('Z', encoding)) !== 'Z') throw 'decoder not reusable';
      if (decoder.decode() !== '') throw 'unexpected final output';
      checks += 4;
    }
  }
  console.log(encoding, source.length, checks);
}
// Node 22.16.0's one-shot windows-1252 fast path treats C1 as Latin-1.
// Its streaming path, the engine's established mapping, and WHATWG agree.
var singleByte = new TextDecoder('windows-1252');
var mapped = singleByte.decode(new Uint8Array([65,128,130,159,255]), {stream:true}) + singleByte.decode();
console.log(mapped.length, mapped.charCodeAt(1), mapped.charCodeAt(2), mapped.charCodeAt(3), mapped.charCodeAt(4));
"#;

const CHUNKS: &str = r#"function bytesFor(text, encoding) {
  if (encoding === 'utf-8') return new TextEncoder().encode(text);
  var bytes = new Uint8Array(text.length * 2);
  for (var i = 0; i < text.length; i++) {
    var unit = text.charCodeAt(i);
    bytes[i * 2 + (encoding === 'utf-16be' ? 1 : 0)] = unit & 255;
    bytes[i * 2 + (encoding === 'utf-16be' ? 0 : 1)] = unit >> 8;
  }
  return bytes;
}
var source = '\ufeff' + 'Aé日😀'.repeat(257) + '\ufeffZ';
for (var encoding of ['utf-8', 'utf-16le', 'utf-16be']) {
  var checks = 0;
  var bytes = bytesFor(source, encoding);
  for (var width of [1,2,3,7,64,4096]) {
    for (var ignoreBOM of [false,true]) {
      var decoder = new TextDecoder(encoding, {fatal:true, ignoreBOM:ignoreBOM});
      var output = '';
      for (var i = 0; i < bytes.length; i += width) {
        var chunk = bytes.slice(i, i+width);
        output += decoder.decode(chunk, {stream:true});
        chunk.fill(0); // No retained view may alter the next decode's carry.
      }
      output += decoder.decode();
      if (output !== (ignoreBOM ? source : source.slice(1))) throw 'chunk mismatch';
      if (decoder.decode(bytesFor('Q', encoding)) !== 'Q') throw 'reset mismatch';
      checks += 2;
    }
  }
  console.log(encoding, checks, source.length);
}
for (var encoding of ['utf-16le','utf-16be']) {
  var bad = encoding === 'utf-16le' ? [0,216,65] : [216,0,65];
  var replace = new TextDecoder(encoding);
  var text = replace.decode(new Uint8Array(bad), {stream:true}) + replace.decode();
  var strict = new TextDecoder(encoding, {fatal:true});
  strict.decode(new Uint8Array(bad), {stream:true});
  var error;
  try { strict.decode(); error = 'accepted'; } catch (caught) { error = caught.name; }
  console.log(encoding, text.length, text.charCodeAt(0), error, strict.decode(bytesFor('R', encoding)));
}
"#;

fn run(source: &str, expected: &[&str]) {
    let root = tempfile::tempdir().expect("temporary directory");
    let entry = root.path().join("decoder-storage.js");
    let report = root.path().join("report.json");
    std::fs::write(&entry, source).expect("write source");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run", "--input", entry.to_str().expect("UTF-8 path"),
            "--extension-id", "decoder-storage", "--instruction-budget", "2000000000",
            "--out", report.to_str().expect("UTF-8 path"),
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
fn unicode_decoder_returns_owned_text_for_exact_view_ranges() {
    run(WHOLE, &[
        "utf-8 4098 16", "utf-16le 4098 16", "utf-16be 4098 16",
        "5 8364 8218 376 255",
    ]);
}

#[test]
fn every_streamed_piece_and_surrogate_flush_preserves_decoding() {
    run(CHUNKS, &[
        "utf-8 24 1288", "utf-16le 24 1288", "utf-16be 24 1288",
        "utf-16le 1 65533 TypeError R", "utf-16be 1 65533 TypeError R",
    ]);
}

const BORROWING: &str = r#"var decoder = new TextDecoder('utf-8', {fatal:true});
// Reenter an active stream, rather than Node's separate stateless fast path.
decoder.decode(new Uint8Array(), {stream:true});
var input = new Uint8Array([165,172,66,165]);
var trace = [];
var output = decoder.decode(new DataView(input.buffer, 1, 2), {
  get stream() {
    trace.push('get');
    trace.push(decoder.decode(new Uint8Array([226,130]), {stream:true}));
    input[2] = 67;
    return false;
  }
});
input.fill(0);
console.log(output, output.length, trace.join('|'));
var failure = new Error('option getter');
decoder.decode(new Uint8Array([226]), {stream:true});
var caught;
try {
  decoder.decode(new Uint8Array([65]), {get stream() {throw failure;}});
} catch (error) { caught = error === failure; }
console.log(caught, decoder.decode(new Uint8Array([130,172])));
var shared = new SharedArrayBuffer(8);
var view = new Uint8Array(shared, 2, 2);
view.set([88,89]);
var sharedText = decoder.decode(view);
view.fill(0);
console.log(sharedText, sharedText.slice(0));
var large = new Uint8Array(131073).fill(65);
large[0] = 128;
decoder.decode(new Uint8Array([240,159,152]), {stream:true});
var joined = decoder.decode(large);
large.fill(0);
console.log(joined.length, joined.codePointAt(0), joined.charCodeAt(joined.length-1));
"#;

#[test]
fn borrowed_decode_preserves_reentry_carry_and_shared_input_independence() {
    run(BORROWING, &["€C 2 get|", "true €", "XY XY", "131074 128512 65"]);
}
