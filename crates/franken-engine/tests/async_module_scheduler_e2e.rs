#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn run_scheduler(input: &str) -> Output {
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
        .write_all(input.as_bytes())
        .expect("write scenario");
    child.wait_with_output().expect("scheduler output")
}

fn successful_json(input: &str) -> Value {
    let output = run_scheduler(input);
    assert!(
        output.status.success(),
        "scheduler failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("scheduler JSON")
}

#[test]
fn synchronous_dependency_chain_dispatches_in_dependency_order() {
    let json = successful_json(
        r#"{
            "modules": [
                {"specifier":"dep.mjs"},
                {"specifier":"app.mjs","dependencies":["dep.mjs"]}
            ],
            "operations": [
                {"kind":"dispatch","save_as":"dep"},
                {"kind":"complete","task":"dep"},
                {"kind":"dispatch","save_as":"app"},
                {"kind":"complete","task":"app"}
            ]
        }"#,
    );

    assert_eq!(json["dispatched"][0]["module_specifier"], "dep.mjs");
    assert_eq!(json["dispatched"][1]["module_specifier"], "app.mjs");
    assert_eq!(json["module_phases"]["dep.mjs"], "settled");
    assert_eq!(json["module_phases"]["app.mjs"], "settled");
    assert_eq!(json["snapshot"]["ready_tasks"], 0);
    assert_eq!(json["snapshot"]["in_flight_tasks"], 0);
}

#[test]
fn pending_promise_requeues_exactly_one_new_generation() {
    let json = successful_json(
        r#"{
            "modules": [
                {"specifier":"app.mjs","has_top_level_await":true}
            ],
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

    let first = json["dispatched"][0]["generation"]
        .as_u64()
        .expect("generation");
    let second = json["dispatched"][1]["generation"]
        .as_u64()
        .expect("generation");
    assert!(second > first);
    assert_eq!(json["dispatched"][0]["kind"], "start");
    assert_eq!(json["dispatched"][1]["kind"], "resume");
    assert_eq!(json["module_phases"]["app.mjs"], "settled");
    assert_eq!(json["snapshot"]["dispatched_tasks"], 2);
}

#[test]
fn awaited_rejection_removes_transitively_rejected_dependents_from_queue() {
    let json = successful_json(
        r#"{
            "modules": [
                {"specifier":"root.mjs","has_top_level_await":true},
                {"specifier":"child.mjs","has_top_level_await":true,"dependencies":["root.mjs"]}
            ],
            "pending_promises": ["inner"],
            "operations": [
                {"kind":"dispatch","save_as":"root"},
                {"kind":"suspend","task":"root","promise":"inner"},
                {"kind":"reject_awaited","promise":"inner","reason":{"Str":"boom"}}
            ]
        }"#,
    );

    assert_eq!(json["module_phases"]["root.mjs"], "rejected");
    assert_eq!(json["module_phases"]["child.mjs"], "rejected");
    assert_eq!(json["snapshot"]["ready_tasks"], 0);
    assert_eq!(json["snapshot"]["in_flight_tasks"], 0);
}

#[test]
fn dispatch_budget_exhaustion_is_fail_closed() {
    let output = run_scheduler(
        r#"{
            "config":{"max_dispatched_tasks":1},
            "modules":[{"specifier":"a.mjs"},{"specifier":"b.mjs"}],
            "operations":[
                {"kind":"dispatch","save_as":"a"},
                {"kind":"dispatch","save_as":"b"}
            ]
        }"#,
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("dispatch budget 1 exhausted"),
        "unexpected stderr: {stderr}"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn dispatch_without_ready_work_is_fail_closed() {
    let output = run_scheduler(
        r#"{
            "modules":[
                {"specifier":"dep.mjs","has_top_level_await":true},
                {"specifier":"app.mjs","dependencies":["dep.mjs"]}
            ],
            "operations":[
                {"kind":"dispatch","save_as":"dep"},
                {"kind":"dispatch","save_as":"app-too-early"}
            ]
        }"#,
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no ready module task"));
}
