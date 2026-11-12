//! bd-9vouw.61: a run the capability membrane terminates must leave a
//! structured failure report carrying signed, chained evidence of the denial.
//!
//! Before the change `fetch(...)` under `frankenctl run` (no network grant)
//! ended with exit 2 and a stderr line only: no report file, no evidence
//! entry, although a denied attempt to reach the network is the event an
//! operator most needs recorded. The CLI already verifies and emits an
//! uncommitted evidence chain for post-cell failures; the orchestrator now
//! attaches a signed denial entry to capability-denial failures, which the
//! CLI verifies against the run's identity before writing it out.
//! Lowering-time rejections (e.g. `process.env`) happen before an execution
//! cell exists, so there is no execution evidence to chain; they now write a
//! rejection report naming the refused access, its required effect and span.
//! No-claim: that rejection report is not a signed evidence entry.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn scratch_dir() -> PathBuf {
    let stamp_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("fe_denial61_{}_{stamp_nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
fn denied_fetch_writes_a_failure_report_with_signed_denial_evidence() {
    let dir = scratch_dir();
    let input = dir.join("exfil.js");
    let report = dir.join("exfil.report.json");
    let trust = dir.join("exfil.trust.json");
    fs::write(
        &input,
        "console.log('before'); fetch('http://198.51.100.7/ping'); console.log('after');\n",
    )
    .expect("program");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8"),
            "--extension-id",
            "denial61",
            "--emit-evidence-trust",
            trust.to_str().expect("utf8"),
            "--out",
            report.to_str().expect("utf8"),
        ])
        .output()
        .expect("frankenctl should execute");

    assert_eq!(output.status.code(), Some(2), "a denial fails the run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("capability denied"), "{stderr}");
    assert!(
        stderr.contains("classification: capability_denied"),
        "{stderr}"
    );

    let written: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).expect("failure report written"))
            .expect("report json");
    let stdout: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout carries the same report");
    assert_eq!(written, stdout);
    assert_eq!(written["outcome"], "capability_denied");
    assert_eq!(written["classification"], "capability_denied");
    assert_eq!(written["exit_code"], 2);

    let artifact = &written["committed_evidence_chain"];
    let entries = artifact["entries"].as_array().expect("evidence entries");
    let denial = entries
        .iter()
        .find(|entry| entry["metadata"]["outcome"] == "capability_denied")
        .expect("a signed capability-denial entry");
    let denied = denial["metadata"]["denied_capability"]
        .as_str()
        .expect("denied capability named");
    assert!(
        denied.contains("net"),
        "the denied capability must be the network request, got {denied}"
    );
    assert_eq!(denial["metadata"]["extension_id"], "denial61");
    assert_eq!(denial["chosen_action"]["action_name"], "terminate");
    assert!(
        denial["signed_envelope"]["signature"].is_object(),
        "the denial entry is signed"
    );
    assert!(
        artifact["receipt"]["head_chain_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()),
        "the denial is chained under a receipt"
    );

    let digest = written["evidence_trust_snapshot_digest"]
        .as_str()
        .expect("trust digest emitted");
    let replay_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            report.to_str().expect("utf8"),
            "--mode",
            "strict",
            "--trust-snapshot",
            trust.to_str().expect("utf8"),
            "--expected-trust-digest",
            digest,
        ])
        .output()
        .expect("strict replay should execute");
    assert!(
        replay_output.status.success(),
        "strict replay of capability-denied run must succeed: {}",
        String::from_utf8_lossy(&replay_output.stderr)
    );
    let replay_json: serde_json::Value =
        serde_json::from_slice(&replay_output.stdout).expect("replay json");
    assert_eq!(replay_json["complete"], true);
    assert_eq!(replay_json["decisions_match"], true);
    assert_eq!(replay_json["evidence_authenticated"], true);
    assert_eq!(replay_json["divergence_count"], 0);
}

fn run(dir: &std::path::Path, name: &str, source: &str) -> (std::process::Output, PathBuf) {
    let input = dir.join(format!("{name}.js"));
    let report = dir.join(format!("{name}.report.json"));
    fs::write(&input, source).expect("program");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8"),
            "--extension-id",
            "denial61",
            "--out",
            report.to_str().expect("utf8"),
        ])
        .output()
        .expect("frankenctl should execute");
    (output, report)
}

#[test]
fn lowering_time_rejection_writes_a_rejection_report() {
    let dir = scratch_dir();
    let (output, report) = run(
        &dir,
        "env",
        "console.log(Object.keys(process.env).length);\n",
    );
    assert_eq!(output.status.code(), Some(2), "the rejection fails the run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ambient authority violation"), "{stderr}");
    assert!(
        stderr.contains("classification: rejected_at_lowering"),
        "{stderr}"
    );
    let written: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).expect("rejection report written"))
            .expect("report json");
    let stdout: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout carries the same report");
    assert_eq!(written, stdout);
    assert_eq!(
        written["schema_version"],
        "franken-engine.frankenctl.lowering-rejection.v1"
    );
    assert_eq!(written["outcome"], "rejected_at_lowering");
    assert_eq!(written["classification"], "rejected_at_lowering");
    assert_eq!(written["exit_code"], 2);
    let rejection = &written["rejection"];
    assert_eq!(rejection["kind"], "ambient_authority");
    assert_eq!(rejection["accessor"], "process.env");
    assert_eq!(rejection["required_effect"], "env.read");
    assert_eq!(rejection["span"]["start_line"], 1);
    let entries = written["evidence_chain_artifact"]["entries"]
        .as_array()
        .expect("signed lowering rejection entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["metadata"]["outcome"], "rejected_at_lowering");
    assert_eq!(entries[0]["chosen_action"]["action_name"], "terminate");
    assert!(entries[0]["signed_envelope"]["signature"].is_object());
    assert!(
        written["evidence_chain_head"]
            .as_str()
            .is_some_and(|head| !head.is_empty())
    );

    // A lowering failure that is not a security refusal keeps its old shape:
    // no rejection report.
    let (output, report) = run(&dir, "syntax", "let x = ;\n");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        !report.exists(),
        "a syntax error is not a rejection: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn capability_denial_terminates_unrecoverably_even_inside_try_catch() {
    let dir = scratch_dir();
    let (output, report) = run(
        &dir,
        "try_catch_fetch",
        "try { fetch('http://198.51.100.7/ping'); console.log('escaped'); } catch (e) { console.log('caught'); }\n",
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "capability denial is a non-catchable membrane termination"
    );
    let written: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).expect("failure report written"))
            .expect("report json");
    assert_eq!(written["outcome"], "capability_denied");
}

#[test]
fn capability_denial_evidence_smoke_script_passes_end_to_end() {
    let dir = scratch_dir();
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();
    let script = repo_root.join("scripts/e2e/capability_denial_evidence_smoke.sh");
    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&repo_root)
        .env("FRANKENCTL_BIN", env!("CARGO_BIN_EXE_frankenctl"))
        .env(
            "CAPABILITY_DENIAL_ARTIFACT_ROOT",
            dir.join("artifacts").to_str().expect("utf8"),
        )
        .output()
        .expect("smoke script executes");
    assert!(
        output.status.success(),
        "capability_denial_evidence_smoke.sh failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("smoke summary json");
    assert_eq!(summary["pass"], true);
    assert_eq!(summary["case_count"], 3);
}
