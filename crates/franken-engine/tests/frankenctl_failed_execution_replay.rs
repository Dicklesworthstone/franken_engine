//! Failed executions retain a signed, exact prefix without certifying success
//! or repeating host effects. These tests drive the actual CLI and filesystem.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use frankenengine_engine::execution_orchestrator::FailedExecutionReplayContext;
use serde_json::Value;
#[cfg(unix)]
use serde_json::json;

fn directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fe_failed_replay_{label}_{}_{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("directory");
    dir
}

fn cli(dir: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .current_dir(dir)
        .args(arguments)
        .output()
        .expect("execute frankenctl")
}

#[cfg(unix)]
fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).expect("JSON")).expect("write JSON");
}

fn failure_report(output: &Output, path: &Path) -> Value {
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let report: Value =
        serde_json::from_slice(&fs::read(path).expect("failure report")).expect("report JSON");
    assert_eq!(
        report,
        serde_json::from_slice::<Value>(&output.stdout).expect("stdout JSON")
    );
    assert!(report["committed_evidence_chain"].is_object());
    assert!(report["replay_input_signature"].is_object());
    assert!(report["replay_input"]["execution"].is_object());
    assert!(report.get("ir4_witness").is_none());
    report
}

fn replay(dir: &Path, path: &Path, original: &Value, authenticated: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_frankenctl"));
    command.current_dir(dir).args([
        "replay",
        "run",
        "--trace",
        path.to_str().expect("path"),
        "--mode",
        "strict",
    ]);
    if authenticated {
        command
            .arg("--trust-snapshot")
            .arg(dir.join("trust.json"))
            .args([
                "--expected-trust-digest",
                original["evidence_trust_snapshot_digest"]
                    .as_str()
                    .expect("independent pin"),
            ]);
    }
    command.output().expect("replay CLI")
}

fn assert_exact_replay(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("replay report");
    assert_eq!(report["complete"], true);
    assert_eq!(report["decisions_match"], true);
    assert_eq!(report["failed_execution_content_match"], true);
    assert_eq!(report["ir3_hash_match"], true);
    assert_eq!(report["randomness_transcript_match"], true);
    assert_eq!(report["divergence_count"], 0);
    assert!(report.get("unsigned_execution_content_match").is_none());
    report
}

#[cfg(unix)]
fn quota_failure(dir: &Path) -> (PathBuf, Value) {
    fs::create_dir(dir.join("root")).expect("sandbox root");
    write_json(
        &dir.join("manifest.json"),
        &json!({
            "schema_version": "franken-engine.agent-sandbox-manifest.v1",
            "agent_id": "failed-replay-agent",
            "tool_grants": [
                {"tool_name": "write_file", "capability_tag": "fs_write"},
                {"tool_name": "js_builtins", "capability_tag": "builtin"}
            ],
            "host_io_root": dir.join("root"),
            "host_io_budget": {"requests": 1, "request_bytes": 4096, "max_in_flight": 1}
        }),
    );
    fs::write(
        dir.join("agent.js"),
        "const fs = require('fs'); console.log('before', Math.random(), Date.now()); \
         fs.writeFileSync('output.txt', 'authorized prefix'); \
         try { fs.writeFileSync('output.txt', 'must not overwrite'); } \
         catch (e) { console.log('must not catch'); } console.log('must not continue');",
    )
    .expect("source");
    let output = cli(
        dir,
        &[
            "agent-sandbox",
            "--manifest",
            "manifest.json",
            "--input",
            "agent.js",
            "--emit-evidence-trust",
            "trust.json",
            "--out",
            "failure.json",
        ],
    );
    let path = dir.join("failure.json");
    let report = failure_report(&output, &path);
    assert_eq!(report["outcome"], "execution_failed");
    assert_eq!(report["command"], "agent-sandbox");
    let execution = &report["replay_input"]["execution"];
    assert!(
        execution["error"]["InternalError"]["details"]
            .as_str()
            .expect("typed quota error")
            .contains("HOST_IO_REQUEST_BUDGET_EXHAUSTED")
    );
    assert_eq!(
        execution["console_output"]
            .as_array()
            .expect("console")
            .len(),
        1
    );
    assert!(
        execution["console_output"][0]["message"]
            .as_str()
            .expect("prefix")
            .starts_with("before ")
    );
    assert!(
        execution["instructions_executed"]
            .as_u64()
            .expect("instructions")
            > 0
    );
    assert_eq!(
        execution["host_effect_transcript"]
            .as_array()
            .expect("effects")
            .len(),
        2
    );
    assert_eq!(
        fs::read_to_string(dir.join("root/output.txt")).expect("real write"),
        "authorized prefix"
    );
    (path, report)
}

#[test]
#[cfg(unix)]
fn quota_failure_replays_with_pinned_trust_without_reopening_the_live_root() {
    let dir = directory("quota");
    let (path, report) = quota_failure(&dir);
    fs::rename(dir.join("root"), dir.join("retained-root")).expect("retain original root");
    fs::create_dir(dir.join("root")).expect("replacement root");
    fs::write(dir.join("root/output.txt"), "replacement canary").expect("canary");
    let replayed = assert_exact_replay(&replay(&dir, &path, &report, true));
    assert_eq!(replayed["evidence_authenticated"], true);
    assert_eq!(
        fs::read_to_string(dir.join("root/output.txt")).expect("replacement"),
        "replacement canary"
    );
    assert_eq!(
        fs::read_to_string(dir.join("retained-root/output.txt")).expect("original"),
        "authorized prefix"
    );

    // The root can also be entirely absent: replay needs only recorded effects.
    fs::rename(dir.join("root"), dir.join("retained-canary")).expect("retain replacement");
    assert_exact_replay(&replay(&dir, &path, &report, true));
    assert!(!dir.join("root").exists());
}

#[test]
#[cfg(unix)]
fn authenticated_failure_replay_rejects_changed_effects_error_console_and_authority() {
    let dir = directory("tampering");
    let (_, report) = quota_failure(&dir);
    let mut variants = Vec::new();
    let mut changed = report.clone();
    changed["replay_input"]["execution"]["host_effect_transcript"]
        .as_array_mut()
        .expect("effects")
        .pop();
    variants.push(changed);
    let mut changed = report.clone();
    changed["replay_input"]["execution"]["error"]["InternalError"]["details"] =
        json!("a different failure");
    variants.push(changed);
    let mut changed = report.clone();
    changed["replay_input"]["execution"]["console_output"][0]["message"] = json!("forged prefix");
    variants.push(changed);
    let mut changed = report.clone();
    changed["replay_input"]["agent_sandbox_manifest"]["host_io_budget"]["requests"] = json!(100);
    variants.push(changed);
    let mut changed = report.clone();
    changed["replay_input"]["capabilities"]
        .as_array_mut()
        .expect("grants")
        .push(json!("net"));
    variants.push(changed);
    for (index, variant) in variants.iter().enumerate() {
        let path = dir.join(format!("tampered-{index}.json"));
        write_json(&path, variant);
        let output = replay(&dir, &path, &report, true);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("authentication failed before re-execution"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        fs::read_to_string(dir.join("root/output.txt")).expect("retained write"),
        "authorized prefix"
    );
}

#[test]
#[cfg(unix)]
fn matching_primary_error_does_not_hide_an_unconsumed_recorded_effect() {
    let dir = directory("leftover");
    let (_, report) = quota_failure(&dir);
    let mut changed = report.clone();
    let effects = changed["replay_input"]["execution"]["host_effect_transcript"]
        .as_array_mut()
        .expect("effects");
    effects.push(effects[0].clone());
    let execution: FailedExecutionReplayContext =
        serde_json::from_value(changed["replay_input"]["execution"].clone())
            .expect("typed context");
    // Deliberately exercise unauthenticated strict re-execution. Rebind the
    // claimant's commitment so only exact recorder finalization can reject it.
    changed["committed_evidence_chain"]["entries"][0]["metadata"]["failed_execution_context_hash"] =
        json!(execution.content_hash().expect("context hash").to_hex());
    let path = dir.join("extra-effect.json");
    write_json(&path, &changed);
    let output = replay(&dir, &path, &report, false);
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("strict re-execution divergence"), "{error}");
    assert!(error.contains("exact failure prefix"), "{error}");
    assert_eq!(
        fs::read_to_string(dir.join("root/output.txt")).expect("unchanged write"),
        "authorized prefix"
    );
}

#[test]
fn instruction_budget_failure_replays_the_partial_clock_randomness_and_console_trace() {
    let dir = directory("instructions");
    fs::write(
        dir.join("budget.js"),
        "console.log('prefix', Date.now(), Math.random()); while (true) {}",
    )
    .expect("source");
    let output = cli(
        &dir,
        &[
            "run",
            "--input",
            "budget.js",
            "--extension-id",
            "failed-budget",
            "--instruction-budget",
            "5000",
            "--clock-epoch",
            "12345000",
            "--emit-evidence-trust",
            "trust.json",
            "--out",
            "failure.json",
        ],
    );
    let path = dir.join("failure.json");
    let report = failure_report(&output, &path);
    assert!(report["replay_input"]["execution"]["error"]["BudgetExhausted"].is_object());
    assert_eq!(report["replay_input"]["clock_epoch_ms"], 12345000);
    let replayed = assert_exact_replay(&replay(&dir, &path, &report, true));
    assert_eq!(replayed["evidence_authenticated"], true);
    assert!(replayed["event_count"].as_u64().expect("events") >= 2);
}

#[test]
fn failed_commonjs_replay_detects_changed_consumed_module_bytes() {
    let dir = directory("modules");
    fs::write(dir.join("dep.cjs"), "module.exports = 7;").expect("dependency");
    fs::write(
        dir.join("main.cjs"),
        "console.log(require('./dep.cjs')); throw new Error('terminal');",
    )
    .expect("entry");
    let output = cli(
        &dir,
        &[
            "run",
            "--input",
            "main.cjs",
            "--extension-id",
            "failed-module",
            "--goal",
            "commonjs",
            "--module-root",
            ".",
            "--emit-evidence-trust",
            "trust.json",
            "--out",
            "failure.json",
        ],
    );
    let path = dir.join("failure.json");
    let report = failure_report(&output, &path);
    assert!(
        report["replay_input"]["execution"]["imported_module_hashes"]
            .as_object()
            .expect("module hashes")
            .keys()
            .any(|path| path.ends_with("dep.cjs"))
    );
    assert_exact_replay(&replay(&dir, &path, &report, true));
    fs::write(dir.join("dep.cjs"), "module.exports = 8;").expect("change imported bytes");
    let rejected = replay(&dir, &path, &report, true);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("strict re-execution divergence"));
}
