//! bd-9vouw.479: the Promise combinators' memory estimate is a running total,
//! not a re-sum of every tracker per Promise operation. This pins the
//! combinators' results to Node v22.2.0 across the paths that change it:
//! Promise.all over 3,000 mixed inputs (pending, resolved, plain values),
//! allSettled over 1,000 with rejections, any rejected by all 500 inputs
//! (AggregateError) and won by one, race, an all short-circuited by a
//! rejection, nested combinators and an empty all.

use std::process::Command;

const PROGRAM: &str = r#"var log = [];
function later(value, fail) {
  return new Promise(function (resolve, reject) {
    queueMicrotask(function () { (fail ? reject : resolve)(value); });
  });
}
var mixed = [];
for (var i = 0; i < 3000; i++) mixed.push(i % 3 === 0 ? later(i) : i % 3 === 1 ? Promise.resolve(i) : i);
Promise.all(mixed).then(function (values) {
  var sum = 0;
  for (var k = 0; k < values.length; k++) sum += values[k];
  log.push("all " + values.length + " " + sum + " " + values[2999]);
});
var settled = [];
for (var j = 0; j < 1000; j++) settled.push(later("v" + j, j % 4 === 0));
Promise.allSettled(settled).then(function (outcomes) {
  var rejected = outcomes.filter(function (o) { return o.status === "rejected"; }).length;
  log.push("allSettled " + outcomes.length + " " + rejected + " " + outcomes[3].value + " " + outcomes[4].reason);
});
var anyInputs = [];
for (var a = 0; a < 500; a++) anyInputs.push(later("r" + a, true));
Promise.any(anyInputs).catch(function (error) {
  log.push("any " + error.constructor.name + " " + error.errors.length + " " + error.errors[499]);
});
Promise.any([later("x", true), later("winner"), later("y", true)]).then(function (v) { log.push("any-win " + v); });
Promise.race([later("slow"), Promise.resolve("fast"), later("slower")]).then(function (v) { log.push("race " + v); });
var short = [later(1), later("boom", true), later(3)];
Promise.all(short).catch(function (e) { log.push("all-reject " + e); });
Promise.all([Promise.all([later(1), later(2)]), Promise.allSettled([later(3, true)])]).then(function (v) {
  log.push("nested " + JSON.stringify(v));
});
Promise.all([]).then(function (v) { log.push("empty " + v.length); });
setTimeout(function () { log.sort(); log.forEach(function (line) { console.log(line); }); }, 0);
"#;

const EXPECTED: &[&str] = &[
    "all 3000 4498500 2999",
    "all-reject boom",
    "allSettled 1000 250 v3 v4",
    "any AggregateError 500 r499",
    "any-win winner",
    "empty 0",
    "nested [[1,2],[{\"status\":\"rejected\",\"reason\":3}]]",
    "race fast",
];

#[test]
fn promise_combinators_match_node_with_running_totals() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root
        .path()
        .join("promise_combinator_running_totals_bd_9vouw_479.js");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "promise-combinator-totals",
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
