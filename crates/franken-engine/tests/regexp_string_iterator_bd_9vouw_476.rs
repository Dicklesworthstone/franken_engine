//! bd-9vouw.476: String.prototype.matchAll returns a lazy
//! %RegExpStringIteratorPrototype% iterator that runs one exec per next, so a
//! for-of over 5,000 matches of a 29 KB string keeps one match alive instead of
//! all of them (they exceeded the 64 MiB budget). This pins Node v22.2.0's
//! output for that loop, the iterator's tag, prototype chain, next name and
//! length, exhaustion, the argument's untouched lastIndex, empty matches with u
//! (past a surrogate pair) and without u, a next on a non-iterator, and
//! iterator helpers' hidden slots. An empty non-u match inside a surrogate
//! pair is not pinned here: non-u patterns still match Unicode scalars, not
//! code units (bd-9vouw.458; Node indexes "a😀b" 0,1,2,3,4, the engine 0,1,3,4).

use std::process::Command;

const PROGRAM: &str = r#"var s = ""; for (var i = 0; i < 5000; i++) s += "x" + i + " ";
var n = 0, sum = 0; for (const m of s.matchAll(/x(\d+)/g)) { n++; sum += +m[1]; }
console.log(s.length, n, sum);
var it = "a1b2c3".matchAll(/[a-z](\d)/g);
var proto = Object.getPrototypeOf(it);
var iteratorPrototype = Object.getPrototypeOf(Object.getPrototypeOf([][Symbol.iterator]()));
console.log(Object.prototype.toString.call(it), it[Symbol.toStringTag], it[Symbol.iterator]() === it, Object.getPrototypeOf(proto) === iteratorPrototype);
console.log(JSON.stringify(it.next().value), it.next().value[0], [...it].length, JSON.stringify(it.next()));
console.log(Reflect.ownKeys(it).length, Object.getOwnPropertyNames(proto).join(), proto.next.length, proto.next.name);
var re = /o/g; re.lastIndex = 1; var it2 = "foo boo".matchAll(re); console.log(re.lastIndex, it2.next().value.index, re.lastIndex);
console.log([..."a😀b".matchAll(/(?:)/gu)].map(m => m.index).join(), [..."abc".matchAll(/(?:)/g)].map(m => m.index).join());
try { proto.next.call({}); } catch (e) { console.log(e.constructor.name); }
var h = [1, 2, 3].values().map(x => x * 2); console.log(Reflect.ownKeys(h).length, Object.getOwnPropertyNames(h).length, [...h].join());
"#;

const EXPECTED: &[&str] = &[
    "28890 5000 12497500",
    "[object RegExp String Iterator] RegExp String Iterator true true",
    "[\"a1\",\"1\"] b2 1 {\"done\":true}",
    "0 next 0 next",
    "1 1 1",
    "0,1,3,4 0,1,2,3",
    "TypeError",
    "0 0 2,4,6",
];

#[test]
fn regexp_string_iterator_matches_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("regexp_string_iterator_bd_9vouw_476.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "regexp-string-iterator",
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
