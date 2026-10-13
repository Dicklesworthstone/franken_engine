//! bd-9vouw.485: JSON.stringify of a cycle throws Node's TypeError message,
//! "Converting circular structure to JSON" (it was the host diagnostic "type
//! error: expected acyclic JSON value, got circular structure"). Node goes on to
//! name the property path that closes the circle; that path can carry labeled
//! keys, so the engine keeps only the first line. This pins Node v22.2.0's first
//! lines for object, array and indented-replacer cycles, a shared acyclic value,
//! and a safe-stringify helper that matches on the text.

use std::process::Command;

const PROGRAM: &str = r#"var a = {}; a.self = a;
try { JSON.stringify(a); } catch (e) { console.log(e.name, e instanceof TypeError, e.message.split("\n")[0], /circular structure/i.test(e.message)); }
var arr = [1]; arr.push([arr]);
try { JSON.stringify(arr); } catch (e) { console.log(e.message.split("\n")[0], e.message.startsWith("Converting circular structure to JSON")); }
var deep = { x: { y: {} } }; deep.x.y.back = deep.x;
try { JSON.stringify({ wrap: deep }, null, 2); } catch (e) { console.log(e.constructor.name, e.message.split("\n")[0]); }
var shared = { s: 1 }; console.log(JSON.stringify({ a: shared, b: [shared, shared] }));
function safeStringify(value) { try { return JSON.stringify(value); } catch (e) { return /circular/i.test(e.message) ? "[Circular]" : "[Error]"; } }
console.log(safeStringify(a), safeStringify({ ok: true }));
"#;

const EXPECTED: &[&str] = &[
    "TypeError true Converting circular structure to JSON true",
    "Converting circular structure to JSON true",
    "TypeError Converting circular structure to JSON",
    "{\"a\":{\"s\":1},\"b\":[{\"s\":1},{\"s\":1}]}",
    "[Circular] {\"ok\":true}",
];

#[test]
fn json_circular_messages_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("json_circular_message_bd_9vouw_485.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "json-circular-message",
            "--instruction-budget",
            "2000000000",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    let printed: Vec<&str> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(printed, EXPECTED);
}
