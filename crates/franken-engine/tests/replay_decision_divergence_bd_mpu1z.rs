//! bd-mpu1z (first slice): strict replay re-derives a run report's decisions.
//!
//! Reality check 2026-09-27 (clean main 3a690ee62): forging a run report's
//! evidence entry `chosen_action` (allow -> quarantine) or its top-level
//! `containment_action` left `frankenctl replay run --mode strict` at exit 0
//! with divergence_count 0. Replay compared only the IR3 hash, the unsigned
//! execution content and the randomness transcript. Re-execution is
//! deterministic, so every decision can be re-derived and compared without
//! trusting any key the report carries. Authenticity of the signed chain
//! against an external trust anchor is still open on bd-mpu1z.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn scratch_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_mpu1z_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn run_report(dir: &Path) -> PathBuf {
    let input = dir.join("program.js");
    let report = dir.join("program.report.json");
    fs::write(&input, "const answer = 40 + 2;\nconsole.log(answer);\n").expect("program");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8"),
            "--extension-id",
            "replay-decisions",
            "--out",
            report.to_str().expect("utf8"),
        ])
        .output()
        .expect("frankenctl run should execute");
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    report
}

fn replay(report: &Path, mode: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            report.to_str().expect("utf8"),
            "--mode",
            mode,
        ])
        .output()
        .expect("frankenctl replay should execute")
}

fn tamper(report: &Path, edit: impl FnOnce(&mut serde_json::Value)) -> PathBuf {
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(report).expect("report")).expect("json");
    edit(&mut value);
    let forged = report.with_extension("forged.json");
    fs::write(&forged, serde_json::to_vec_pretty(&value).expect("json")).expect("forged report");
    forged
}

fn other_action(action: &str) -> &'static str {
    if action == "quarantine" {
        "allow"
    } else {
        "quarantine"
    }
}

#[test]
fn untampered_report_replays_with_matching_decisions() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let output = replay(&report, "strict");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(summary["decisions_match"], true);
    assert_eq!(summary["divergence_count"], 0);
}

#[test]
fn forged_evidence_decision_is_a_strict_divergence() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let forged = tamper(&report, |value| {
        let chosen = &mut value["evidence_chain_artifact"]["entries"][0]["chosen_action"];
        let original = chosen["action_name"]
            .as_str()
            .expect("action name")
            .to_string();
        chosen["action_name"] = serde_json::Value::from(other_action(&original));
    });
    let output = replay(&forged, "strict");
    assert!(
        !output.status.success(),
        "a forged decision must not replay"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("strict re-execution divergence: evidence entry 0"),
        "{stderr}"
    );
}

#[test]
fn forged_containment_action_is_a_strict_divergence() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let forged = tamper(&report, |value| {
        let original = value["containment_action"]
            .as_str()
            .expect("containment action")
            .to_string();
        value["containment_action"] = serde_json::Value::from(other_action(&original));
    });
    let output = replay(&forged, "strict");
    assert!(
        !output.status.success(),
        "a forged containment action must not replay"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("re-executed containment action"),
        "{stderr}"
    );
}

#[test]
fn best_effort_replay_reports_the_decision_divergence() {
    let dir = scratch_dir();
    let report = run_report(&dir);
    let forged = tamper(&report, |value| {
        let chosen = &mut value["evidence_chain_artifact"]["entries"][0]["chosen_action"];
        chosen["expected_loss_millionths"] = serde_json::Value::from(123_456_789_i64);
    });
    let output = replay(&forged, "best-effort");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(summary["decisions_match"], false);
    assert_eq!(summary["complete"], false);
    assert!(summary["divergence_count"].as_u64().expect("count") >= 1);
}
