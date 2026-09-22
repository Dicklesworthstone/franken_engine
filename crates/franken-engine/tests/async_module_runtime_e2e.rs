#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn run_runtime(input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_franken_async_module_runtime"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn async module runtime");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write scenario");
    child.wait_with_output().expect("runtime output")
}

fn successful_json(input: &str) -> Value {
    let output = run_runtime(input);
    assert!(
        output.status.success(),
        "runtime failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("runtime JSON")
}

#[test]
fn arbitrary_discovery_order_is_registered_and_executed_dependency_first() {
    let json = successful_json(
        r#"{
            "modules": [
                {"specifier":"app.mjs","dependencies":["lib.mjs"]},
                {"specifier":"base.mjs","has_top_level_await":true},
                {"specifier":"lib.mjs","dependencies":["base.mjs"]}
            ],
            "operations": [
                {"kind":"dispatch","save_as":"base"},
                {"kind":"complete","task":"base"},
                {"kind":"dispatch","save_as":"lib"},
                {"kind":"complete","task":"lib"},
                {"kind":"dispatch","save_as":"app"},
                {"kind":"complete","task":"app"}
            ]
        }"#,
    );

    assert_eq!(
        json["graph_plan"]["registration_order"],
        serde_json::json!(["base.mjs", "lib.mjs", "app.mjs"])
    );
    assert_eq!(json["dispatched"][0]["module_specifier"], "base.mjs");
    assert_eq!(json["dispatched"][1]["module_specifier"], "lib.mjs");
    assert_eq!(json["dispatched"][2]["module_specifier"], "app.mjs");
    assert_eq!(json["module_phases"]["app.mjs"], "settled");
    assert_eq!(json["snapshot"]["ready_tasks"], 0);
    assert_eq!(json["snapshot"]["in_flight_tasks"], 0);
}

#[test]
fn pending_top_level_await_resumes_with_new_generation() {
    let json = successful_json(
        r#"{
            "modules": [{"specifier":"app.mjs","has_top_level_await":true}],
            "pending_promises": ["inner"],
            "operations": [
                {"kind":"dispatch","save_as":"start"},
                {"kind":"suspend","task":"start","promise":"inner"},
                {"kind":"fulfill_awaited","promise":"inner","value":{"Int":42}},
                {"kind":"dispatch","save_as":"resume"},
                {"kind":"complete","task":"resume"}
            ]
        }"#,
    );

    let start_generation = json["dispatched"][0]["generation"]
        .as_u64()
        .expect("start generation");
    let resume_generation = json["dispatched"][1]["generation"]
        .as_u64()
        .expect("resume generation");
    assert!(resume_generation > start_generation);
    assert_eq!(json["dispatched"][0]["kind"], "start");
    assert_eq!(json["dispatched"][1]["kind"], "resume");
    assert_eq!(json["module_phases"]["app.mjs"], "settled");
}

#[test]
fn synchronous_throw_rejects_tla_dependent_and_clears_work() {
    let json = successful_json(
        r#"{
            "modules": [
                {"specifier":"child.mjs","has_top_level_await":true,"dependencies":["root.mjs"]},
                {"specifier":"root.mjs"}
            ],
            "operations": [
                {"kind":"dispatch","save_as":"root"},
                {"kind":"reject","task":"root","reason":{"Str":"sync boom"},"label":"Secret"}
            ]
        }"#,
    );

    assert_eq!(json["module_phases"]["root.mjs"], "rejected");
    assert_eq!(json["module_phases"]["child.mjs"], "rejected");
    assert_eq!(json["snapshot"]["ready_tasks"], 0);
    assert_eq!(json["snapshot"]["in_flight_tasks"], 0);
}

#[test]
fn cycle_is_rejected_before_any_task_can_dispatch() {
    let output = run_runtime(
        r#"{
            "modules": [
                {"specifier":"a.mjs","dependencies":["b.mjs"]},
                {"specifier":"b.mjs","dependencies":["a.mjs"]}
            ],
            "operations": [{"kind":"dispatch","save_as":"never"}]
        }"#,
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dependency cycle"),
        "unexpected stderr: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn unknown_dependency_is_rejected_before_any_task_can_dispatch() {
    let output = run_runtime(
        r#"{
            "modules": [{"specifier":"app.mjs","dependencies":["missing.mjs"]}],
            "operations": [{"kind":"dispatch","save_as":"never"}]
        }"#,
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("depends on unknown module"),
        "unexpected stderr: {stderr}"
    );
    assert!(output.stdout.is_empty());
}
