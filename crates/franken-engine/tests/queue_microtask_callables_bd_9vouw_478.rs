//! bd-9vouw.478: queueMicrotask takes any callable, as Promise reactions do: a
//! promise's resolve function, a bound console.log, Math.max and an async
//! function run as microtasks; non-callables are TypeErrors. The callback is
//! called with no arguments (a bound console.log printed a trailing
//! "undefined"), and the microtask checkpoint drains every queued job before
//! a timer runs: it stopped after 10,000 jobs, so the timer below saw fewer
//! than the 12,000 reactions queued on one promise, and ran ahead of the 5,000
//! promises resolved through queueMicrotask. Output and order are pinned to
//! Node v22.2.0. The program aborted on the first builtin callback before
//! ("expected function, got function").
//!
//! A callback that throws ends the run with that uncaught exception before
//! the next job runs (Node exits 1 with the error). It used to reject a
//! promise nobody held, so a later job's `process.exit(0)` still ran and the
//! run exited 0.

use std::process::Command;

const PROGRAM: &str = r#"var order = [];
new Promise(function (resolve) { queueMicrotask(resolve); }).then(function () { order.push("resolved"); });
queueMicrotask(console.log.bind(console, "bound log runs"));
queueMicrotask(function () { console.log("callback arguments", arguments.length); });
queueMicrotask(Math.max);
async function asyncTask() { order.push("async ran"); }
queueMicrotask(asyncTask);
queueMicrotask(function () { order.push("closure"); });
Promise.resolve().then(function () { order.push("reaction"); });
var many = 0;
var pending = [];
for (var i = 0; i < 5000; i++) {
  pending.push(new Promise(function (resolve) { queueMicrotask(resolve); }).then(function () { many++; }));
}
Promise.all(pending).then(function () { console.log("many", many); });
var reactions = 0;
var settled = Promise.resolve();
for (var j = 0; j < 12000; j++) { settled.then(function () { reactions++; }); }
[1, "s", null, undefined, {}].forEach(function (value) {
  try { queueMicrotask(value); console.log("accepted", String(value)); }
  catch (e) { console.log(e.constructor.name, value === null ? "null" : typeof value); }
});
setTimeout(function () { console.log(order.join(","), "reactions before the timer", reactions); }, 0);
"#;

const EXPECTED: &[&str] = &[
    "TypeError number",
    "TypeError string",
    "TypeError null",
    "TypeError undefined",
    "TypeError object",
    "bound log runs",
    "callback arguments 0",
    "many 5000",
    "async ran,closure,reaction,resolved reactions before the timer 12000",
];

const THROWING_PROGRAM: &str = r#"queueMicrotask(function () { throw new Error("thrown in a microtask"); });
queueMicrotask(function () { process.exit(0); });
"#;

fn run_frankenctl(
    root: &std::path::Path,
    source: &str,
) -> (std::process::Output, std::path::PathBuf) {
    let entry = root.join("queue_microtask_callables_bd_9vouw_478.js");
    std::fs::write(&entry, source).expect("write program");
    let report = root.join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--extension-id",
            "queue-microtask-callables",
            "--instruction-budget",
            "2000000000",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    (output, report)
}

#[test]
fn a_throwing_callback_ends_the_run_before_the_next_job() {
    let root = tempfile::tempdir().expect("temp dir");
    let (output, _) = run_frankenctl(root.path(), THROWING_PROGRAM);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "the second job's process.exit(0) ran after the throw: {stderr}"
    );
    assert!(
        stderr.contains("uncaught exception") && stderr.contains("thrown in a microtask"),
        "expected the callback's error as the run's failure: {stderr}"
    );
}

#[test]
fn queue_microtask_takes_any_callable_like_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let (output, report) = run_frankenctl(root.path(), PROGRAM);
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
