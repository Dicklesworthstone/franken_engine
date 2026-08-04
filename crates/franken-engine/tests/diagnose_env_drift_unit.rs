//! Unit tests for the N.4 environment-drift diagnostician
//! `runbooks/scripts/diagnose_env_drift.sh` (Track N, bead `bd-cixqu.14.4`).
//!
//! These drive the real shell script via `std::process::Command` on synthetic
//! `env.json` / `repro.lock` fixtures — no mocks. Each test isolates one
//! classification decision (platform vs toolchain vs dependency drift, aligned,
//! and the CLI error surfaces). The script's "current" environment is supplied
//! explicitly with `--current` so every assertion is hermetic and deterministic.
//!
//! Tests skip gracefully (with an eprintln) when `bash` / `jq` / `python3` or
//! the repo script are unavailable, so the suite is portable.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

// --- harness ----------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("repo root")
}

fn tool_ok(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Skip-guard: returns false (and logs) when the shell pipeline cannot run.
fn prereqs(root: &Path) -> bool {
    for t in ["bash", "jq", "python3"] {
        if !tool_ok(t) {
            eprintln!("[diagnose-unit] skip: {t} unavailable");
            return false;
        }
    }
    if !root
        .join("runbooks/scripts/diagnose_env_drift.sh")
        .is_file()
    {
        eprintln!("[diagnose-unit] skip: diagnose_env_drift.sh not present");
        return false;
    }
    true
}

fn unique_dir(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("diag_env_{tag}_{pid}_{nanos}"));
    std::fs::create_dir_all(&dir).expect("mk tmp");
    dir
}

fn write_json(path: &Path, v: &Value) {
    std::fs::write(path, serde_json::to_string_pretty(v).expect("ser")).expect("write json");
}

fn write_raw(path: &Path, s: &str) {
    std::fs::write(path, s).expect("write raw");
}

fn base_env() -> Value {
    json!({
        "host": {
            "architecture": "x86_64",
            "kernel": "6.17.0-22-generic",
            "os_version": "Ubuntu 22.04 LTS",
            "platform": "linux"
        },
        "toolchain": {
            "cargo_version": "1.81.0",
            "rust_version": "1.81.0-nightly",
            "rustc_target": "x86_64-unknown-linux-gnu"
        },
        "project": { "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
        "schema_version": "frankenengine.reproducibility.env.v1"
    })
}

/// Run the diagnostician against recorded/current snapshots (+ optional lock).
/// Returns `(exit_code, verdict_json)`. The verdict is read from `--json-out`,
/// which the script writes for both aligned (exit 0) and drift (exit 1) runs.
fn run_diagnose(
    tag: &str,
    recorded: &Value,
    current: &Value,
    lock: Option<&Value>,
) -> (i32, Value) {
    let root = repo_root();
    let work = unique_dir(tag);
    let rec = work.join("recorded.json");
    let cur = work.join("current.json");
    let out = work.join("verdict.json");
    write_json(&rec, recorded);
    write_json(&cur, current);

    let mut cmd = Command::new("bash");
    cmd.arg(root.join("runbooks/scripts/diagnose_env_drift.sh"))
        .arg("diagnose")
        .arg("--recorded")
        .arg(&rec)
        .arg("--current")
        .arg(&cur)
        .arg("--json-out")
        .arg(&out)
        .arg("--artifact-root")
        .arg(work.join("art"))
        .arg("--quiet")
        .current_dir(&root);
    if let Some(l) = lock {
        let lp = work.join("repro.lock");
        write_json(&lp, l);
        cmd.arg("--lock").arg(&lp);
    }
    let status = cmd.output().expect("run diagnose");
    let code = status.status.code().unwrap_or(-1);
    let verdict = std::fs::read_to_string(&out)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
    (code, verdict)
}

fn class_count(v: &Value, class: &str) -> i64 {
    v["drift_class_count"][class].as_i64().unwrap_or(-1)
}

// --- aligned baseline -------------------------------------------------------

#[test]
fn identical_env_is_aligned() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let (code, v) = run_diagnose("identical", &base_env(), &base_env(), None);
    assert_eq!(code, 0, "identical env should exit 0");
    assert_eq!(v["verdict"], "aligned");
    assert_eq!(v["drift_detected"], json!(false));
}

#[test]
fn aligned_class_counts_all_zero() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let (_c, v) = run_diagnose("aligned_counts", &base_env(), &base_env(), None);
    assert_eq!(class_count(&v, "platform"), 0);
    assert_eq!(class_count(&v, "toolchain"), 0);
    assert_eq!(class_count(&v, "dependency"), 0);
}

// --- platform drift ---------------------------------------------------------

#[test]
fn kernel_change_is_platform_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["host"]["kernel"] = json!("6.17.0-35-generic");
    let (code, v) = run_diagnose("kernel", &base_env(), &cur, None);
    assert_eq!(code, 1, "drift should exit 1");
    assert_eq!(class_count(&v, "platform"), 1);
    assert_eq!(class_count(&v, "toolchain"), 0);
}

#[test]
fn architecture_change_is_platform_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["host"]["architecture"] = json!("aarch64");
    let (_c, v) = run_diagnose("arch", &base_env(), &cur, None);
    assert_eq!(class_count(&v, "platform"), 1);
}

#[test]
fn os_version_change_is_platform_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["host"]["os_version"] = json!("Ubuntu 24.04 LTS");
    let (_c, v) = run_diagnose("os", &base_env(), &cur, None);
    assert_eq!(class_count(&v, "platform"), 1);
}

#[test]
fn platform_change_is_platform_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["host"]["platform"] = json!("darwin");
    let (_c, v) = run_diagnose("plat", &base_env(), &cur, None);
    assert_eq!(class_count(&v, "platform"), 1);
}

#[test]
fn two_platform_fields_count_two() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["host"]["kernel"] = json!("9.9.9-generic");
    cur["host"]["architecture"] = json!("aarch64");
    let (_c, v) = run_diagnose("two_plat", &base_env(), &cur, None);
    assert_eq!(class_count(&v, "platform"), 2);
}

// --- toolchain drift --------------------------------------------------------

#[test]
fn cargo_version_change_is_toolchain_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["toolchain"]["cargo_version"] = json!("1.83.0");
    let (_c, v) = run_diagnose("cargo", &base_env(), &cur, None);
    assert_eq!(class_count(&v, "toolchain"), 1);
    assert_eq!(class_count(&v, "platform"), 0);
}

#[test]
fn rust_version_change_is_toolchain_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["toolchain"]["rust_version"] = json!("1.83.0-nightly");
    let (_c, v) = run_diagnose("rustv", &base_env(), &cur, None);
    assert_eq!(class_count(&v, "toolchain"), 1);
}

#[test]
fn rustc_target_change_is_toolchain_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["toolchain"]["rustc_target"] = json!("aarch64-apple-darwin");
    let (_c, v) = run_diagnose("target", &base_env(), &cur, None);
    assert_eq!(class_count(&v, "toolchain"), 1);
}

// --- dependency drift -------------------------------------------------------

#[test]
fn commit_change_is_dependency_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["project"]["commit"] = json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let (_c, v) = run_diagnose("commit", &base_env(), &cur, None);
    assert_eq!(class_count(&v, "dependency"), 1);
    assert_eq!(class_count(&v, "platform"), 0);
}

#[test]
fn lock_primary_artifact_hash_mismatch_is_dependency_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    // A real file with a known-wrong recorded hash → dependency drift.
    let work = unique_dir("primary_hash");
    let artifact = work.join("primary.txt");
    write_raw(&artifact, "real-bytes-on-disk");
    let lock = json!({
        "schema_version": "frankenengine.reproducibility.lock.v1",
        "inputs": {
            "primary_artifact": {
                "path": artifact.to_string_lossy(),
                "hash": "0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    });
    let (_c, v) = run_diagnose("primary_hash", &base_env(), &base_env(), Some(&lock));
    assert_eq!(
        class_count(&v, "dependency"),
        1,
        "wrong primary hash is dependency drift"
    );
    assert_eq!(v["lock_checked"], json!(true));
}

#[test]
fn lock_missing_dependency_file_is_dependency_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let lock = json!({
        "schema_version": "frankenengine.reproducibility.lock.v1",
        "inputs": { "dependencies": ["/nonexistent/path/does-not-exist-xyz"] }
    });
    let (_c, v) = run_diagnose("missing_dep", &base_env(), &base_env(), Some(&lock));
    assert_eq!(
        class_count(&v, "dependency"),
        1,
        "missing dependency file is dependency drift"
    );
}

// --- combined ---------------------------------------------------------------

#[test]
fn combined_all_three_classes() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["host"]["platform"] = json!("darwin");
    cur["toolchain"]["rust_version"] = json!("1.99.0");
    cur["project"]["commit"] = json!("cccccccccccccccccccccccccccccccccccccccc");
    let (code, v) = run_diagnose("all3", &base_env(), &cur, None);
    assert_eq!(code, 1);
    assert_eq!(class_count(&v, "platform"), 1);
    assert_eq!(class_count(&v, "toolchain"), 1);
    assert_eq!(class_count(&v, "dependency"), 1);
}

#[test]
fn recorded_field_present_current_absent_is_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["host"].as_object_mut().unwrap().remove("kernel");
    let (_c, v) = run_diagnose("absent_cur", &base_env(), &cur, None);
    assert_eq!(
        class_count(&v, "platform"),
        1,
        "field present in recorded but not current drifts"
    );
}

// --- verdict shape ----------------------------------------------------------

#[test]
fn verdict_has_schema_version() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let (_c, v) = run_diagnose("schema", &base_env(), &base_env(), None);
    assert_eq!(v["schema_version"], "franken-engine.env-drift-diagnosis.v1");
}

#[test]
fn verdict_lists_recorded_and_current_values() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["host"]["kernel"] = json!("6.17.0-35-generic");
    let (_c, v) = run_diagnose("values", &base_env(), &cur, None);
    let drifts = v["drifts"].as_array().expect("drifts array");
    let kernel = drifts
        .iter()
        .find(|d| d["field"] == "host.kernel")
        .expect("kernel drift entry");
    assert_eq!(kernel["recorded"], "6.17.0-22-generic");
    assert_eq!(kernel["current"], "6.17.0-35-generic");
    assert_eq!(kernel["class"], "platform");
}

#[test]
fn drift_detected_false_when_aligned() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let (_c, v) = run_diagnose("dd_false", &base_env(), &base_env(), None);
    assert_eq!(v["drift_detected"], json!(false));
}

#[test]
fn drift_detected_true_when_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["toolchain"]["cargo_version"] = json!("2.0.0");
    let (_c, v) = run_diagnose("dd_true", &base_env(), &cur, None);
    assert_eq!(v["drift_detected"], json!(true));
}

#[test]
fn json_out_written_on_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let mut cur = base_env();
    cur["project"]["commit"] = json!("dddddddddddddddddddddddddddddddddddddddd");
    let (code, v) = run_diagnose("jsonout", &base_env(), &cur, None);
    assert_eq!(code, 1);
    assert!(
        v.is_object(),
        "json-out must be written even on drift exit 1"
    );
}

// --- CLI error surfaces -----------------------------------------------------

#[test]
fn missing_recorded_file_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/diagnose_env_drift.sh"))
        .args(["diagnose", "--recorded", "/nonexistent/env.json", "--quiet"])
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing recorded file is CLI error"
    );
}

#[test]
fn malformed_recorded_json_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("malformed_rec");
    let rec = work.join("bad.json");
    write_raw(&rec, "this is not json {{{");
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/diagnose_env_drift.sh"))
        .arg("diagnose")
        .arg("--recorded")
        .arg(&rec)
        .arg("--quiet")
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn malformed_current_json_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("malformed_cur");
    let rec = work.join("env.json");
    let cur = work.join("bad_cur.json");
    write_json(&rec, &base_env());
    write_raw(&cur, "}{ not json");
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/diagnose_env_drift.sh"))
        .arg("diagnose")
        .arg("--recorded")
        .arg(&rec)
        .arg("--current")
        .arg(&cur)
        .arg("--quiet")
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn missing_required_recorded_flag_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/diagnose_env_drift.sh"))
        .args(["diagnose", "--quiet"])
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2), "--recorded is required");
}

#[test]
fn unknown_mode_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/diagnose_env_drift.sh"))
        .arg("frobnicate")
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
}

// --- meta -------------------------------------------------------------------

#[test]
fn help_exits_zero() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/diagnose_env_drift.sh"))
        .arg("--help")
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn selftest_passes() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/diagnose_env_drift.sh"))
        .arg("selftest")
        .current_dir(&root)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "selftest must pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn real_evidence_env_against_itself_is_aligned() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let env = root.join("docs/evidence/FE-CLAIM-001/env.json");
    if !env.is_file() {
        eprintln!("[diagnose-unit] skip: FE-CLAIM-001/env.json absent");
        return;
    }
    // A real recorded env compared against itself must be perfectly aligned.
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/diagnose_env_drift.sh"))
        .arg("diagnose")
        .arg("--recorded")
        .arg(&env)
        .arg("--current")
        .arg(&env)
        .arg("--json-out")
        .arg(unique_dir("real_self").join("v.json"))
        .arg("--quiet")
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0), "real env vs itself is aligned");
}
