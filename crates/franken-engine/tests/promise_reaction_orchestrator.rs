//! Regression tests for Promise/async then-handlers on the orchestrated
//! `frankenctl run` path (bd-sxh8o.1).
//!
//! bd-25il9 was closed claiming reaction handlers execute, but on 2026-08-20
//! the live CLI still failed `f().then(console.log)` with "expected
//! closure-backed Promise reaction onFulfilled handler, got callable handler
//! without schedulable closure state". These tests shell the real `frankenctl`
//! binary (the same `ExecutionOrchestrator` path the shipped CLI uses) so the
//! advertised "Async functions | Executed" surface is proven on the
//! orchestrated path, not only in isolated `promise_model` unit tests.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}", std::process::id(), nonce));
    fs::create_dir_all(&path).expect("temp dir should be creatable");
    path
}

/// Run `frankenctl run` on `source`, returning (exit success, stderr, parsed
/// run report JSON if the report file was written).
fn run_frankenctl(
    test_name: &str,
    extension_id: &str,
    source: &str,
) -> (bool, String, Option<serde_json::Value>) {
    let dir = temp_dir(test_name);
    let input = dir.join("input.js");
    let out = dir.join("run.json");
    fs::write(&input, source).expect("source should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8 path"),
            "--extension-id",
            extension_id,
            "--out",
            out.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl run should execute");

    let report = fs::read(&out)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        report,
    )
}

fn console_messages(report: &serde_json::Value) -> Vec<String> {
    report["console_output"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry["message"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The exact program from bd-sxh8o.1: an async function whose result flows
/// through `await` and is delivered to `console.log` used directly as a
/// then-handler (a builtin callable, not an interpreter closure).
#[test]
fn async_await_then_console_log_prints_42_bd_sxh8o_1() {
    let (success, stderr, report) = run_frankenctl(
        "fe_sxh8o1_async_await",
        "bd-sxh8o1-async",
        "async function f(){ return 1 + await Promise.resolve(41); }\nf().then(console.log);\n",
    );
    assert!(success, "frankenctl run should exit 0; stderr: {stderr}");
    let report = report.expect("run report should be written");
    let messages = console_messages(&report);
    assert!(
        messages.iter().any(|m| m.contains("42")),
        "console_output should contain 42; got {messages:?}"
    );
}

/// `.then(x => x + 1)` on an already-resolved Promise: interpreter-closure
/// handler shape, chained into a second closure that surfaces the value.
#[test]
fn then_closure_handler_transforms_resolved_value_bd_sxh8o_1() {
    let (success, stderr, report) = run_frankenctl(
        "fe_sxh8o1_closure_chain",
        "bd-sxh8o1-closure",
        "Promise.resolve(41).then(x => x + 1).then(v => console.log(v));\n",
    );
    assert!(success, "frankenctl run should exit 0; stderr: {stderr}");
    let report = report.expect("run report should be written");
    let messages = console_messages(&report);
    assert!(
        messages.iter().any(|m| m.contains("42")),
        "console_output should contain 42; got {messages:?}"
    );
}

/// `console.log` passed directly as a then-handler (builtin callable shape).
#[test]
fn then_builtin_console_log_handler_bd_sxh8o_1() {
    let (success, stderr, report) = run_frankenctl(
        "fe_sxh8o1_builtin_handler",
        "bd-sxh8o1-builtin",
        "Promise.resolve(7).then(console.log);\n",
    );
    assert!(success, "frankenctl run should exit 0; stderr: {stderr}");
    let report = report.expect("run report should be written");
    let messages = console_messages(&report);
    assert!(
        messages.iter().any(|m| m.contains('7')),
        "console_output should contain 7; got {messages:?}"
    );
}

/// A throwing fulfillment handler must reject the derived Promise; the
/// rejection is observable through `.catch`.
#[test]
fn throwing_handler_rejects_derived_promise_bd_sxh8o_1() {
    let (success, stderr, report) = run_frankenctl(
        "fe_sxh8o1_throwing_handler",
        "bd-sxh8o1-throwing",
        "Promise.resolve(1)\n  .then(x => { throw 'boom'; })\n  .then(v => console.log('fulfilled', v), e => console.log('rejected', e));\n",
    );
    assert!(success, "frankenctl run should exit 0; stderr: {stderr}");
    let report = report.expect("run report should be written");
    let messages = console_messages(&report);
    assert!(
        messages.iter().any(|m| m.contains("rejected")),
        "derived promise should reject into the onRejected handler; got {messages:?}"
    );
    assert!(
        !messages.iter().any(|m| m.contains("fulfilled")),
        "throwing handler must not fulfill the derived promise; got {messages:?}"
    );
}

/// A missing fulfillment handler preserves the settled value (identity),
/// while a later closure handler still observes it.
#[test]
fn missing_handler_preserves_identity_bd_sxh8o_1() {
    let (success, stderr, report) = run_frankenctl(
        "fe_sxh8o1_identity",
        "bd-sxh8o1-identity",
        "Promise.resolve(5).then(undefined).then(v => console.log(v));\n",
    );
    assert!(success, "frankenctl run should exit 0; stderr: {stderr}");
    let report = report.expect("run report should be written");
    let messages = console_messages(&report);
    assert!(
        messages.iter().any(|m| m.contains('5')),
        "identity fulfillment should preserve 5; got {messages:?}"
    );
}
