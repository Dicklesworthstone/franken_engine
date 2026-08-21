//! Regression tests for the Node-compatible `process.nextTick` job queue on
//! the orchestrated `frankenctl run` path (bd-8nrud).
//!
//! The queue must give true next-tick-before-Promise ordering without
//! exposing raw `process` authority: only the statically recognized,
//! unshadowed `process.nextTick(cb, ...args)` call shape is granted; bare
//! `process` loads and every other member stay denied at lowering.

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

/// Run `frankenctl run` on `source`; return (exit success, stderr, console
/// messages from the run report when one was written).
fn run_frankenctl(
    test_name: &str,
    extension_id: &str,
    source: &str,
) -> (bool, String, Vec<String>) {
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

    let messages = fs::read(&out)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|report| {
            report["console_output"].as_array().map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry["message"].as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
        })
        .unwrap_or_default();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        messages,
    )
}

/// Node's canonical interleaving: sync body first, then the tick queue, then
/// Promise microtasks, and a tick enqueued by a microtask runs before any
/// later microtask work.
#[test]
fn next_tick_runs_before_promise_microtasks_bd_8nrud() {
    let (success, stderr, messages) = run_frankenctl(
        "fe_8nrud_ordering",
        "bd-8nrud-ordering",
        "process.nextTick(() => console.log('t1'));\n\
         Promise.resolve().then(() => { console.log('p1'); process.nextTick(() => console.log('t2')); });\n\
         console.log('sync');\n",
    );
    assert!(success, "frankenctl run should exit 0; stderr: {stderr}");
    assert_eq!(
        messages,
        vec!["sync", "t1", "p1", "t2"],
        "Node ordering: sync body, tick queue, promise job, tick from promise"
    );
}

/// The tick queue drains to exhaustion — ticks enqueued by tick callbacks run
/// before the first Promise microtask.
#[test]
fn tick_enqueued_by_tick_precedes_promises_bd_8nrud() {
    let (success, stderr, messages) = run_frankenctl(
        "fe_8nrud_reentrant",
        "bd-8nrud-reentrant",
        "Promise.resolve().then(() => console.log('p1'));\n\
         process.nextTick(() => { console.log('t1'); process.nextTick(() => console.log('t2')); });\n",
    );
    assert!(success, "frankenctl run should exit 0; stderr: {stderr}");
    assert_eq!(
        messages,
        vec!["t1", "t2", "p1"],
        "tick queue drains fully (including reentrant ticks) before promises"
    );
}

/// `process.nextTick(cb, ...args)` forwards the extra arguments to the
/// callback, and ticks run before timer macrotasks.
#[test]
fn next_tick_forwards_args_and_precedes_timers_bd_8nrud() {
    let (success, stderr, messages) = run_frankenctl(
        "fe_8nrud_args_timer",
        "bd-8nrud-args",
        "setTimeout(() => console.log('timer'), 0);\n\
         process.nextTick((a, b) => console.log(a + b), 40, 2);\n",
    );
    assert!(success, "frankenctl run should exit 0; stderr: {stderr}");
    assert_eq!(
        messages,
        vec!["42", "timer"],
        "forwarded args reach the callback; ticks run before timer macrotasks"
    );
}

/// A lexical `process` binding shadows the recognizer: the member call is
/// ordinary user data, not the builtin queue.
#[test]
fn shadowed_process_binding_is_user_data_bd_8nrud() {
    let (success, stderr, messages) = run_frankenctl(
        "fe_8nrud_shadow",
        "bd-8nrud-shadow",
        "const process = { nextTick: (cb) => { console.log('shadow'); cb(); } };\n\
         process.nextTick(() => console.log('cb'));\n",
    );
    assert!(success, "frankenctl run should exit 0; stderr: {stderr}");
    assert_eq!(
        messages,
        vec!["shadow", "cb"],
        "a shadowed `process` must resolve to the user object, not the builtin queue"
    );
}

/// The recognizer grants exactly the nextTick call: every other `process`
/// surface stays denied at lowering, so no raw process authority leaks.
#[test]
fn raw_process_authority_stays_denied_bd_8nrud() {
    let (exit_success, stderr, _) = run_frankenctl(
        "fe_8nrud_exit_denied",
        "bd-8nrud-denied",
        "process.exit(0);\n",
    );
    assert!(
        !exit_success,
        "process.exit must stay denied; stderr: {stderr}"
    );

    let (alias_success, alias_stderr, _) = run_frankenctl(
        "fe_8nrud_alias_denied",
        "bd-8nrud-alias",
        "const p = process;\np.nextTick(() => console.log('laundered'));\n",
    );
    assert!(
        !alias_success,
        "aliasing the raw process object must stay denied; stderr: {alias_stderr}"
    );
}

/// A non-callable callback is a typed error, not a silent drop.
#[test]
fn non_function_callback_is_typed_error_bd_8nrud() {
    let (success, stderr, _) = run_frankenctl(
        "fe_8nrud_bad_callback",
        "bd-8nrud-badcb",
        "process.nextTick(42);\n",
    );
    assert!(
        !success,
        "a non-function nextTick callback must fail typed; stderr: {stderr}"
    );
    assert!(
        stderr.contains("nextTick") || stderr.contains("type error"),
        "failure should name the callback type error; stderr: {stderr}"
    );
}
