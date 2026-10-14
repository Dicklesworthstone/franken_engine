//! Streaming UTF-8 tail selection through the production CLI.
//! These console oracles ran in Node v22.16.0; Rust execution is separate.

use std::process::Command;

const TRACES: &str = r#"var sequences = [
  [[239], [187], [191, 65, 226], [130], [172], []],
  [[237, 160], [128, 65, 226], [130, 172], []],
  [[240, 144, 128], [128, 224, 160], [128], []],
  [[255, 240, 144], [128], [128], []],
  [[244, 144, 128], [128, 239, 187], [191, 66], []],
  [[194], [], [65], [239, 187, 191, 90], []]
];
for (var fatal of [false, true]) {
  for (var ignoreBOM of [false, true]) {
    var traces = [];
    for (var chunks of sequences) {
      var decoder = new TextDecoder('utf-8', {fatal:fatal, ignoreBOM:ignoreBOM});
      var trace = [];
      for (var i = 0; i < chunks.length; i++) {
        var framed = new Uint8Array(chunks[i].length + 4).fill(165);
        framed.set(chunks[i], 2);
        var input = new DataView(framed.buffer, 2, chunks[i].length);
        try { trace.push(decoder.decode(input, {stream:i !== chunks.length-1})); }
        catch (error) { trace.push(error.name); }
      }
      trace.push(decoder.decode(new Uint8Array([239,187,191,81])));
      traces.push(trace);
    }
    console.log(fatal, ignoreBOM, JSON.stringify(traces));
  }
}
"#;

const TRACES_EXPECTED: &[&str] = &[
    "false false [[\"\",\"\",\"A\",\"\",\"€\",\"\",\"Q\"],[\"��\",\"�A\",\"€\",\"\",\"Q\"],[\"\",\"𐀀\",\"ࠀ\",\"\",\"Q\"],[\"�\",\"\",\"𐀀\",\"\",\"Q\"],[\"���\",\"�\",\"\u{feff}B\",\"\",\"Q\"],[\"\",\"\",\"�A\",\"\u{feff}Z\",\"\",\"Q\"]]",
    "false true [[\"\",\"\",\"\u{feff}A\",\"\",\"€\",\"\",\"\u{feff}Q\"],[\"��\",\"�A\",\"€\",\"\",\"\u{feff}Q\"],[\"\",\"𐀀\",\"ࠀ\",\"\",\"\u{feff}Q\"],[\"�\",\"\",\"𐀀\",\"\",\"\u{feff}Q\"],[\"���\",\"�\",\"\u{feff}B\",\"\",\"\u{feff}Q\"],[\"\",\"\",\"�A\",\"\u{feff}Z\",\"\",\"\u{feff}Q\"]]",
    "true false [[\"\",\"\",\"A\",\"\",\"€\",\"\",\"Q\"],[\"TypeError\",\"TypeError\",\"TypeError\",\"\",\"Q\"],[\"\",\"𐀀\",\"ࠀ\",\"\",\"Q\"],[\"TypeError\",\"TypeError\",\"TypeError\",\"\",\"Q\"],[\"TypeError\",\"TypeError\",\"TypeError\",\"\",\"Q\"],[\"\",\"\",\"TypeError\",\"Z\",\"\",\"Q\"]]",
    "true true [[\"\",\"\",\"\u{feff}A\",\"\",\"€\",\"\",\"\u{feff}Q\"],[\"TypeError\",\"TypeError\",\"TypeError\",\"\",\"\u{feff}Q\"],[\"\",\"𐀀\",\"ࠀ\",\"\",\"\u{feff}Q\"],[\"TypeError\",\"TypeError\",\"TypeError\",\"\",\"\u{feff}Q\"],[\"TypeError\",\"TypeError\",\"TypeError\",\"\",\"\u{feff}Q\"],[\"\",\"\",\"TypeError\",\"\u{feff}Z\",\"\",\"\u{feff}Q\"]]",
];

const LONG_STREAMS: &str = r#"var text = '\ufeff' + 'Aé€😀'.repeat(257) + '\ufffd';
var input = new TextEncoder().encode(text);
for (var width of [1,2,3,7,64,4096]) {
  var decoder = new TextDecoder('utf-8', {fatal:true});
  var output = '';
  var calls = 0;
  var empty = 0;
  for (var i = 0; i < input.length; i += width) {
    var part = decoder.decode(input.subarray(i, i+width), {stream:true});
    if (part.length === 0) empty++;
    output += part;
    calls++;
  }
  output += decoder.decode();
  if (output !== text.slice(1)) throw 'stream mismatch';
  console.log(width, calls, empty, output.length, output.codePointAt(output.length-3));
}
var malformed = new Uint8Array(32772).fill(65);
malformed[32768] = 255;
malformed[32769] = 240;
malformed[32770] = 144;
malformed[32771] = 128;
var strict = new TextDecoder('utf-8', {fatal:true});
var failure;
try { strict.decode(malformed, {stream:true}); failure = 'accepted'; }
catch (error) { failure = error.name; }
console.log(failure, strict.decode(new Uint8Array([239,187,191,90])));
var replacement = new TextDecoder('utf-8');
var before = replacement.decode(malformed, {stream:true});
var after = replacement.decode();
console.log(before.length, before.charCodeAt(before.length-1), after.length, after.charCodeAt(0));
"#;

const LONG_STREAMS_EXPECTED: &[&str] = &[
    r#"1 2576 1547 1286 128512"#,
    r#"2 1288 515 1286 128512"#,
    r#"3 859 87 1286 128512"#,
    r#"7 368 0 1286 128512"#,
    r#"64 41 0 1286 128512"#,
    r#"4096 1 0 1286 128512"#,
    r#"TypeError Z"#,
    r#"32769 65533 1 65533"#,
];

fn run(source: &str, expected: &[&str]) {
    let root = tempfile::tempdir().expect("temporary directory");
    let entry = root.path().join("text_decoder_tail.js");
    let report = root.path().join("report.json");
    std::fs::write(&entry, source).expect("write source");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("UTF-8 path"),
            "--extension-id",
            "utf8-streaming-tail",
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
fn each_streaming_result_preserves_bom_errors_and_recovery() {
    run(TRACES, TRACES_EXPECTED);
}

#[test]
fn long_streams_and_invalid_prefixes_keep_their_original_behavior() {
    run(LONG_STREAMS, LONG_STREAMS_EXPECTED);
}
