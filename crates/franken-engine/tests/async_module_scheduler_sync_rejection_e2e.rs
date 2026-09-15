#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

#[test]
fn synchronous_throw_rejects_tla_dependent_and_clears_scheduler_work() {
    let scenario = r#"{
        "modules": [
            {"specifier":"root.mjs"},
            {"specifier":"child.mjs","has_top_level_await":true,"dependencies":["root.mjs"]}
        ],
        "operations": [
            {"kind":"dispatch","save_as":"root"},
            {"kind":"reject","task":"root","reason":{"Str":"sync boom"},"label":"Secret"}
        ]
    }"#;

    let mut child = Command::new(env!("CARGO_BIN_EXE_franken_async_module_scheduler"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn async module scheduler");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(scenario.as_bytes())
        .expect("write scenario");
    let output = child.wait_with_output().expect("scheduler output");
    assert!(
        output.status.success(),
        "scheduler failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: Value = serde_json::from_slice(&output.stdout).expect("scheduler JSON");
    assert_eq!(json["module_phases"]["root.mjs"], "rejected");
    assert_eq!(json["module_phases"]["child.mjs"], "rejected");
    assert_eq!(json["snapshot"]["ready_tasks"], 0);
    assert_eq!(json["snapshot"]["in_flight_tasks"], 0);
    assert_eq!(json["snapshot"]["dispatched_tasks"], 1);
}
