#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn run_bridge(input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_franken_async_module_promise_bridge"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn async-module Promise bridge");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write scenario");
    child.wait_with_output().expect("bridge output")
}

fn successful_json(input: &str) -> Value {
    let output = run_bridge(input);
    assert!(
        output.status.success(),
        "bridge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("bridge JSON output")
}

#[test]
fn fulfilled_module_promise_wakes_declared_dependent() {
    let json = successful_json(
        r#"{
            "modules": [
                {"specifier":"dep.mjs","has_top_level_await":true},
                {"specifier":"app.mjs","dependencies":["dep.mjs"]}
            ],
            "settlements": [
                {"kind":"fulfill","module":"dep.mjs","value":{"Int":42}}
            ]
        }"#,
    );

    assert_eq!(json["module_phases"]["dep.mjs"], "settled");
    assert_eq!(json["dependency_ready"], serde_json::json!(["app.mjs"]));
    assert_eq!(json["updates"][0]["status"], "fulfilled");
    assert!(json["witness_event_count"].as_u64().unwrap_or(0) >= 2);
}

#[test]
fn pending_top_level_await_fulfillment_returns_continuation_without_settling_module() {
    let json = successful_json(
        r#"{
            "modules": [
                {"specifier":"app.mjs","has_top_level_await":true}
            ],
            "pending_promises": ["fetch-result"],
            "settlements": [
                {"kind":"suspend_on_promise","module":"app.mjs","promise":"fetch-result"},
                {"kind":"fulfill_awaited","promise":"fetch-result","value":{"Int":42}}
            ]
        }"#,
    );

    assert_eq!(json["continuation_ready"], serde_json::json!(["app.mjs"]));
    assert_eq!(json["module_phases"]["app.mjs"], "suspended");
    assert_eq!(json["active_awaits"], serde_json::json!({}));
    assert!(json["updates"].as_array().is_some_and(Vec::is_empty));
}

#[test]
fn resumed_top_level_await_can_then_settle_module_and_wake_dependent() {
    let json = successful_json(
        r#"{
            "modules": [
                {"specifier":"dep.mjs","has_top_level_await":true},
                {"specifier":"app.mjs","dependencies":["dep.mjs"]}
            ],
            "pending_promises": ["inner"],
            "settlements": [
                {"kind":"suspend_on_promise","module":"dep.mjs","promise":"inner"},
                {"kind":"fulfill_awaited","promise":"inner","value":{"Int":7}},
                {"kind":"fulfill","module":"dep.mjs","value":"Undefined"}
            ]
        }"#,
    );

    assert_eq!(json["continuation_ready"], serde_json::json!(["dep.mjs"]));
    assert_eq!(json["module_phases"]["dep.mjs"], "settled");
    assert_eq!(json["dependency_ready"], serde_json::json!(["app.mjs"]));
}

#[test]
fn rejected_awaited_promise_rejects_module_graph_transitively() {
    let json = successful_json(
        r#"{
            "modules": [
                {"specifier":"root.mjs","has_top_level_await":true},
                {"specifier":"mid.mjs","has_top_level_await":true,"dependencies":["root.mjs"]},
                {"specifier":"leaf.mjs","has_top_level_await":true,"dependencies":["mid.mjs"]}
            ],
            "pending_promises": ["inner"],
            "settlements": [
                {"kind":"suspend_on_promise","module":"root.mjs","promise":"inner"},
                {"kind":"reject_awaited","promise":"inner","reason":{"Str":"boom"}}
            ]
        }"#,
    );

    assert_eq!(json["module_phases"]["root.mjs"], "rejected");
    assert_eq!(json["module_phases"]["mid.mjs"], "rejected");
    assert_eq!(json["module_phases"]["leaf.mjs"], "rejected");
    assert_eq!(json["updates"][0]["status"], "rejected");
    assert_eq!(json["active_awaits"], serde_json::json!({}));
}

#[test]
fn rejected_module_promise_propagates_rejection_transitively() {
    let json = successful_json(
        r#"{
            "modules": [
                {"specifier":"root.mjs","has_top_level_await":true},
                {"specifier":"mid.mjs","has_top_level_await":true,"dependencies":["root.mjs"]},
                {"specifier":"leaf.mjs","has_top_level_await":true,"dependencies":["mid.mjs"]}
            ],
            "settlements": [
                {"kind":"reject","module":"root.mjs","reason":{"Str":"boom"}}
            ]
        }"#,
    );

    assert_eq!(json["module_phases"]["root.mjs"], "rejected");
    assert_eq!(json["module_phases"]["mid.mjs"], "rejected");
    assert_eq!(json["module_phases"]["leaf.mjs"], "rejected");
    assert_eq!(json["updates"][0]["status"], "rejected");
    let closure = json["updates"][0]["rejection_linkage"]["transitive_closure"]
        .as_array()
        .expect("transitive closure");
    assert!(closure.iter().any(|value| value == "mid.mjs"));
    assert!(closure.iter().any(|value| value == "leaf.mjs"));
}

#[test]
fn module_cannot_settle_while_inner_await_is_pending() {
    let output = run_bridge(
        r#"{
            "modules": [
                {"specifier":"app.mjs","has_top_level_await":true}
            ],
            "pending_promises": ["inner"],
            "settlements": [
                {"kind":"suspend_on_promise","module":"app.mjs","promise":"inner"},
                {"kind":"fulfill","module":"app.mjs","value":"Undefined"}
            ]
        }"#,
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("still suspended"), "unexpected stderr: {stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn invalid_registration_fails_closed_at_process_boundary() {
    let output = run_bridge(
        r#"{
            "modules": [
                {"specifier":"same.mjs"},
                {"specifier":"same.mjs"}
            ]
        }"#,
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("already registered"), "unexpected stderr: {stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn unknown_named_promise_fails_closed_at_process_boundary() {
    let output = run_bridge(
        r#"{
            "modules": [
                {"specifier":"app.mjs","has_top_level_await":true}
            ],
            "settlements": [
                {"kind":"suspend_on_promise","module":"app.mjs","promise":"missing"}
            ]
        }"#,
    );

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown named Promise"), "unexpected stderr: {stderr}");
    assert!(output.stdout.is_empty());
}
