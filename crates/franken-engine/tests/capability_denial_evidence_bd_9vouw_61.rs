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
//! No-claim: lowering-time rejections (e.g. `process.env`) happen before an
//! execution cell exists and still report only through stderr.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn scratch_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_denial61_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
fn denied_fetch_writes_a_failure_report_with_signed_denial_evidence() {
    let dir = scratch_dir();
    let input = dir.join("exfil.js");
    let report = dir.join("exfil.report.json");
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
    assert_eq!(written["classification"], "capability_denied");
    assert_eq!(written["exit_code"], 2);

    let chain = &written["uncommitted_evidence_chain"];
    assert_eq!(chain["commit_state"], "uncommitted");
    let entries = chain["artifact"]["entries"]
        .as_array()
        .expect("evidence entries");
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
    assert!(
        denial["signed_envelope"]["signature"].is_object(),
        "the denial entry is signed"
    );
    assert!(
        chain["artifact"]["receipt"]["head_chain_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()),
        "the denial is chained under a receipt"
    );
}
