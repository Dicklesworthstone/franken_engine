//! bd-9vouw.456: Array.prototype.toSorted checks its comparator before
//! anything else (ES2023 23.1.3.34 step 1): a comparator that is neither
//! undefined nor callable is a TypeError even when the array has fewer
//! than two elements, and before the receiver's `length` is read. It was
//! only checked when the comparator was first called, so `[].toSorted(null)`
//! returned []. Expected lines are Node v22.2.0's.

use std::process::Command;

const PROGRAM: &str = r#"const getLengthThrow = {
  get length() {
    throw new Error('length was read before the comparator was checked');
  },
};
const lines = [];
for (const comparator of [null, true, '', 42, 42n, [], {}, Symbol('s')]) {
  const shown = typeof comparator === 'symbol' ? 'symbol' : JSON.stringify(comparator, (k, v) => (typeof v === 'bigint' ? v + 'n' : v));
  const results = [[], [1], getLengthThrow].map((receiver) => {
    try {
      Array.prototype.toSorted.call(receiver, comparator);
      return 'ok';
    } catch (e) {
      return e.constructor.name;
    }
  });
  lines.push(shown + ' ' + results.join(' '));
}
lines.push(JSON.stringify([[3, 1, 2].toSorted(), [3, 1, 2].toSorted(undefined), [3, 1, 2].toSorted((a, b) => b - a)]));
console.log(lines.join('\n'));
"#;

const EXPECTED: &[&str] = &[
    "null TypeError TypeError TypeError",
    "true TypeError TypeError TypeError",
    "\"\" TypeError TypeError TypeError",
    "42 TypeError TypeError TypeError",
    "\"42n\" TypeError TypeError TypeError",
    "[] TypeError TypeError TypeError",
    "{} TypeError TypeError TypeError",
    "symbol TypeError TypeError TypeError",
    "[[1,2,3],[1,2,3],[3,2,1]]",
];

#[test]
fn to_sorted_rejects_a_non_callable_comparator_first() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("to_sorted.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "array-to-sorted-comparator",
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
        .flat_map(|message| message.split('\n'))
        .collect();
    assert_eq!(printed, EXPECTED);
}
