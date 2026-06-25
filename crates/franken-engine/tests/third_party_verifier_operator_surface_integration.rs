//! Integration tests for the N.4 third-party reproducibility verifier operator
//! surface `runbooks/scripts/run_third_party_verifier.sh` (Track N, bead
//! `bd-cixqu.14.4`).
//!
//! These drive the real wrapper via `std::process::Command` — no mocks — over
//! both *real* published claim-evidence bundles under `docs/evidence/` and
//! *synthetic* bundles constructed in temp dirs. The wrapper composes the N.2
//! single-source-of-truth checker (`scripts/third_party_repro_lock_verifier.sh`)
//! with the N.4 drift diagnostician (`runbooks/scripts/diagnose_env_drift.sh`),
//! so these tests exercise the full operator round-trip end-to-end.
//!
//! Every drift-sensitive test pins the "current" environment with `--current-env`
//! so the verified/env_drift classification is deterministic and host-independent.
//! Tests skip gracefully (eprintln) when `bash` / `jq` / `python3` or the repo
//! scripts are unavailable.

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

fn prereqs(root: &Path) -> bool {
    for t in ["bash", "jq", "python3"] {
        if !tool_ok(t) {
            eprintln!("[tpv-it] skip: {t} unavailable");
            return false;
        }
    }
    let scripts = [
        "runbooks/scripts/run_third_party_verifier.sh",
        "runbooks/scripts/diagnose_env_drift.sh",
        "scripts/third_party_repro_lock_verifier.sh",
    ];
    for s in scripts {
        if !root.join(s).is_file() {
            eprintln!("[tpv-it] skip: {s} not present");
            return false;
        }
    }
    true
}

fn unique_dir(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("tpv_it_{tag}_{pid}_{nanos}"));
    std::fs::create_dir_all(&dir).expect("mk tmp");
    dir
}

fn write_json(path: &Path, v: &Value) {
    std::fs::write(path, serde_json::to_string_pretty(v).expect("ser")).expect("write json");
}

fn valid_lock() -> Value {
    json!({
        "schema_version": "frankenengine.reproducibility.lock.v1",
        "source_commit": "0000000000000000000000000000000000000000",
        "determinism": { "mode": "strict", "reproducible_builds": true, "seed_control": "fixed" },
        "replay": { "command_sequence": ["echo deterministic-replay-ok"] },
        "inputs": { "dependencies": ["Cargo.toml"] }
    })
}

fn valid_env() -> Value {
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
        "project": { "commit": "0000000000000000000000000000000000000000" },
        "schema_version": "frankenengine.reproducibility.env.v1"
    })
}

/// Build a bundle directory under `work`. `lock`/`env` are written when `Some`;
/// `manifest` toggles manifest.json presence (N.1 triple completeness).
fn make_bundle(
    work: &Path,
    name: &str,
    lock: Option<&Value>,
    env: Option<&Value>,
    manifest: bool,
) -> PathBuf {
    let dir = work.join(name);
    std::fs::create_dir_all(&dir).expect("mk bundle");
    if let Some(l) = lock {
        write_json(&dir.join("repro.lock"), l);
    }
    if let Some(e) = env {
        write_json(&dir.join("env.json"), e);
    }
    if manifest {
        write_json(
            &dir.join("manifest.json"),
            &json!({ "manifest_id": "test" }),
        );
    }
    dir
}

/// Run the wrapper. Returns `(exit_code, operator_verdict_json, run_dir)`.
/// The verdict is read from `--json-out`; `run_dir` is the single timestamped
/// run-bundle directory under the artifact root.
fn run_verify(tag: &str, target: &Path, extra: &[&str]) -> (i32, Value, PathBuf) {
    let root = repo_root();
    let work = unique_dir(tag);
    let out = work.join("verdict.json");
    let art = work.join("art");
    let mut cmd = Command::new("bash");
    cmd.arg(root.join("runbooks/scripts/run_third_party_verifier.sh"))
        .arg("verify")
        .arg(target)
        .arg("--json-out")
        .arg(&out)
        .arg("--artifact-root")
        .arg(&art)
        .current_dir(&root);
    for a in extra {
        cmd.arg(a);
    }
    let status = cmd.output().expect("run wrapper");
    let code = status.status.code().unwrap_or(-1);
    let verdict = std::fs::read_to_string(&out)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
    let run_dir = std::fs::read_dir(&art)
        .ok()
        .and_then(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .max_by_key(|p| p.file_name().map(|n| n.to_os_string()).unwrap_or_default())
        })
        .unwrap_or_else(|| art.clone());
    (code, verdict, run_dir)
}

fn classification(v: &Value) -> String {
    v["classification"].as_str().unwrap_or("<none>").to_string()
}

// --- real published bundles -------------------------------------------------

fn first_complete_evidence_bundle(root: &Path) -> Option<PathBuf> {
    let ev = root.join("docs/evidence");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&ev)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.join("repro.lock").is_file()
                && p.join("env.json").is_file()
                && p.join("manifest.json").is_file()
        })
        .collect();
    dirs.sort();
    dirs.into_iter().next()
}

#[test]
fn real_bundle_lock_validates_when_env_aligned() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let Some(bundle) = first_complete_evidence_bundle(&root) else {
        eprintln!("[tpv-it] skip: no complete docs/evidence bundle");
        return;
    };
    let env = bundle.join("env.json");
    // Pin current==recorded so the run is deterministically "verified".
    let (code, v, _rd) = run_verify(
        "real_aligned",
        &bundle,
        &["--current-env", env.to_str().unwrap()],
    );
    assert_eq!(classification(&v), "verified");
    assert_eq!(code, 0);
    assert_eq!(v["verifier_verdict"], "planned");
}

#[test]
fn real_bundle_plan_only_command_count_positive() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let Some(bundle) = first_complete_evidence_bundle(&root) else {
        return;
    };
    let env = bundle.join("env.json");
    let (_c, v, _rd) = run_verify(
        "real_cc",
        &bundle,
        &["--current-env", env.to_str().unwrap()],
    );
    assert!(
        v["command_count"].as_i64().unwrap_or(0) >= 1,
        "plan derives >=1 command"
    );
}

#[test]
fn real_bundle_reports_complete_triple() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let Some(bundle) = first_complete_evidence_bundle(&root) else {
        return;
    };
    let env = bundle.join("env.json");
    let (_c, v, _rd) = run_verify(
        "real_triple",
        &bundle,
        &["--current-env", env.to_str().unwrap()],
    );
    assert_eq!(v["bundle_complete"], json!(true));
    assert_eq!(v["triple_missing"].as_array().map(|a| a.len()), Some(0));
}

#[test]
fn real_bundle_live_host_diagnoses_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let Some(bundle) = first_complete_evidence_bundle(&root) else {
        return;
    };
    // No --current-env: the wrapper captures the live host. Either verified
    // (host matches) or env_drift (host differs) — both diagnose drift.
    let (code, v, _rd) = run_verify("real_live", &bundle, &[]);
    let cls = classification(&v);
    assert!(cls == "verified" || cls == "env_drift", "got {cls}");
    assert_eq!(v["env_drift"]["diagnosed"], json!(true));
    assert!(code == 0, "verified/advisory-drift both exit 0");
}

#[test]
fn real_lock_direct_target_verified() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let Some(bundle) = first_complete_evidence_bundle(&root) else {
        return;
    };
    let lock = bundle.join("repro.lock");
    let (code, v, _rd) = run_verify("real_lock", &lock, &["--no-diagnose"]);
    assert_eq!(classification(&v), "verified");
    assert_eq!(code, 0);
}

#[test]
fn corpus_sweep_all_complete_bundles_validate() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let ev = root.join("docs/evidence");
    let Ok(rd) = std::fs::read_dir(&ev) else {
        eprintln!("[tpv-it] skip: no docs/evidence");
        return;
    };
    let mut checked = 0usize;
    for entry in rd.filter_map(Result::ok) {
        let p = entry.path();
        if !(p.is_dir()
            && p.join("repro.lock").is_file()
            && p.join("env.json").is_file()
            && p.join("manifest.json").is_file())
        {
            continue;
        }
        // --no-diagnose isolates lock-validation universality from the orthogonal
        // env/dependency drift advisory (a published bundle's recorded input
        // hashes may legitimately differ from the current tree).
        let (code, v, _rd) = run_verify("sweep", &p, &["--no-diagnose"]);
        let cls = classification(&v);
        assert_eq!(
            cls,
            "verified",
            "bundle {:?} lock should validate, got {cls}",
            p.file_name()
        );
        assert_eq!(v["verifier_verdict"], "planned");
        assert_eq!(code, 0);
        checked += 1;
        if checked >= 8 {
            break; // a representative sweep; the N.3 gate covers the full corpus
        }
    }
    assert!(
        checked >= 1,
        "expected at least one complete evidence bundle"
    );
}

// --- synthetic classification matrix ---------------------------------------

#[test]
fn synthetic_aligned_bundle_verified() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("syn_ok");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (code, v, _rd) = run_verify("syn_ok_run", &b, &["--current-env", env.to_str().unwrap()]);
    assert_eq!(classification(&v), "verified");
    assert_eq!(code, 0);
}

#[test]
fn drifted_env_classified_env_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("syn_drift");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let mut drifted = valid_env();
    drifted["toolchain"]["cargo_version"] = json!("1.99.0");
    let cur = work.join("cur.json");
    write_json(&cur, &drifted);
    let (code, v, _rd) = run_verify(
        "syn_drift_run",
        &b,
        &["--current-env", cur.to_str().unwrap()],
    );
    assert_eq!(classification(&v), "env_drift");
    assert_eq!(code, 0, "env_drift is advisory by default");
    assert_eq!(v["env_drift"]["verdict"], "drift");
}

#[test]
fn env_drift_strict_promotes_exit_two() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("syn_strict");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let mut drifted = valid_env();
    drifted["host"]["kernel"] = json!("9.9.9-generic");
    let cur = work.join("cur.json");
    write_json(&cur, &drifted);
    let (code, v, _rd) = run_verify(
        "syn_strict_run",
        &b,
        &["--current-env", cur.to_str().unwrap(), "--strict-drift"],
    );
    assert_eq!(classification(&v), "env_drift");
    assert_eq!(code, 2, "--strict-drift promotes env_drift to exit 2");
}

#[test]
fn tampered_lock_verification_failed() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("syn_tamper");
    let b = make_bundle(&work, "b", None, Some(&valid_env()), true);
    std::fs::write(b.join("repro.lock"), "this is not valid json {{").expect("write");
    let env = b.join("env.json");
    let (code, v, _rd) = run_verify(
        "syn_tamper_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    assert_eq!(classification(&v), "verification_failed");
    assert_eq!(code, 1, "verification_failed is fail-closed exit 1");
}

#[test]
fn lock_without_determinism_policy_failed() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("syn_nodeterm");
    let mut lock = valid_lock();
    lock.as_object_mut().unwrap().remove("determinism");
    let b = make_bundle(&work, "b", Some(&lock), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (code, v, _rd) = run_verify(
        "syn_nodeterm_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    assert_eq!(classification(&v), "verification_failed");
    assert_eq!(code, 1);
}

#[test]
fn non_repro_schema_failed() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("syn_schema");
    let mut lock = valid_lock();
    lock["schema_version"] = json!("franken-engine.some-other-thing.v1");
    let b = make_bundle(&work, "b", Some(&lock), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (code, v, _rd) = run_verify(
        "syn_schema_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    assert_eq!(classification(&v), "verification_failed");
    assert_eq!(code, 1);
}

#[test]
fn empty_command_sequence_failed() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("syn_nocmd");
    let mut lock = valid_lock();
    lock["replay"]["command_sequence"] = json!([]);
    lock.as_object_mut().unwrap().remove("commands");
    let b = make_bundle(&work, "b", Some(&lock), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (code, v, _rd) = run_verify(
        "syn_nocmd_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    assert_eq!(classification(&v), "verification_failed");
    assert_eq!(code, 1);
}

#[test]
fn incomplete_triple_missing_manifest_bundle_incomplete() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("syn_nomani");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), false);
    let env = b.join("env.json");
    let (code, v, _rd) = run_verify(
        "syn_nomani_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    assert_eq!(classification(&v), "bundle_incomplete");
    assert_eq!(code, 1);
}

#[test]
fn incomplete_triple_missing_env_bundle_incomplete() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("syn_noenv");
    let b = make_bundle(&work, "b", Some(&valid_lock()), None, true);
    let (code, v, _rd) = run_verify("syn_noenv_run", &b, &[]);
    assert_eq!(classification(&v), "bundle_incomplete");
    assert_eq!(code, 1);
}

#[test]
fn bundle_incomplete_lists_missing_member() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("syn_listmiss");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), false);
    let env = b.join("env.json");
    let (_c, v, _rd) = run_verify(
        "syn_listmiss_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    let missing = v["triple_missing"].as_array().expect("array");
    assert!(
        missing.iter().any(|m| m == "manifest.json"),
        "missing manifest.json should be listed: {missing:?}"
    );
}

// --- verdict shape + provenance --------------------------------------------

#[test]
fn verdict_has_operator_schema_version() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("v_schema");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, v, _rd) = run_verify(
        "v_schema_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    assert_eq!(
        v["schema_version"],
        "franken-engine.third-party-verifier-operator-verdict.v1"
    );
}

#[test]
fn verdict_has_classification_field() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("v_cls");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, v, _rd) = run_verify("v_cls_run", &b, &["--current-env", env.to_str().unwrap()]);
    assert!(v["classification"].is_string());
}

#[test]
fn verdict_has_next_action() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("v_na");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, v, _rd) = run_verify("v_na_run", &b, &["--current-env", env.to_str().unwrap()]);
    assert!(
        v["next_action"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    );
}

#[test]
fn verdict_records_via_local_and_mode_plan_only() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("v_via");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, v, _rd) = run_verify("v_via_run", &b, &["--current-env", env.to_str().unwrap()]);
    assert_eq!(v["via"], "local");
    assert_eq!(v["mode"], "plan-only");
}

#[test]
fn verdict_echoes_lock_schema_and_source_commit() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("v_prov");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, v, _rd) = run_verify("v_prov_run", &b, &["--current-env", env.to_str().unwrap()]);
    assert_eq!(
        v["lock_schema_version"],
        "frankenengine.reproducibility.lock.v1"
    );
    assert_eq!(
        v["source_commit"],
        "0000000000000000000000000000000000000000"
    );
}

#[test]
fn no_diagnose_skips_drift() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("v_nodiag");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let (_c, v, _rd) = run_verify("v_nodiag_run", &b, &["--no-diagnose"]);
    assert_eq!(v["env_drift"]["verdict"], "skipped");
    assert_eq!(classification(&v), "verified");
}

// --- logging discipline (bd-cixqu.45) --------------------------------------

#[test]
fn run_bundle_emits_events_jsonl() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("log_events");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, _v, run_dir) = run_verify(
        "log_events_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    let events = run_dir.join("events.jsonl");
    assert!(events.is_file(), "events.jsonl must exist at {events:?}");
    let body = std::fs::read_to_string(&events).unwrap_or_default();
    assert!(!body.trim().is_empty(), "events.jsonl must be non-empty");
    // Each line must be valid JSON carrying the evidence-record schema id.
    for line in body.lines() {
        let rec: Value = serde_json::from_str(line).expect("event line is JSON");
        assert_eq!(rec["schema_id"], "franken-engine.evidence-record.v1");
    }
}

#[test]
fn run_bundle_emits_commands_txt() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("log_cmds");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, _v, run_dir) = run_verify(
        "log_cmds_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    assert!(run_dir.join("commands.txt").is_file());
}

#[test]
fn run_bundle_emits_manifest_with_sha256() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("log_mani");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, _v, run_dir) = run_verify(
        "log_mani_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    let manifest = run_dir.join("run_manifest.json");
    assert!(manifest.is_file(), "run_manifest.json must exist");
    let m: Value = serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap_or_default())
        .expect("manifest JSON");
    let verdict_sha = m["artifacts"]["operator_verdict.json"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        verdict_sha.len(),
        64,
        "sha256 hex is 64 chars, got {verdict_sha:?}"
    );
    assert_eq!(m["bead_id"], "bd-cixqu.14.4");
}

#[test]
fn run_bundle_embeds_n2_report() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("log_n2");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, _v, run_dir) = run_verify("log_n2_run", &b, &["--current-env", env.to_str().unwrap()]);
    let report = run_dir.join("n2_verifier_report.json");
    assert!(report.is_file(), "raw N.2 verifier report must be saved");
    let r: Value = serde_json::from_str(&std::fs::read_to_string(&report).unwrap_or_default())
        .expect("report JSON");
    assert_eq!(r["verdict"], "planned");
}

#[test]
fn run_bundle_saves_env_drift_verdict() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("log_drift");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, _v, run_dir) = run_verify(
        "log_drift_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    assert!(run_dir.join("env_drift_verdict.json").is_file());
}

// --- CLI error surfaces -----------------------------------------------------

#[test]
fn missing_target_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/run_third_party_verifier.sh"))
        .arg("verify")
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3), "missing target is CLI error");
}

#[test]
fn nonexistent_target_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/run_third_party_verifier.sh"))
        .args(["verify", "/nonexistent/bundle/path"])
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn unknown_flag_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("unk_flag");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/run_third_party_verifier.sh"))
        .arg("verify")
        .arg(&b)
        .arg("--frobnicate")
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn invalid_via_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("bad_via");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/run_third_party_verifier.sh"))
        .arg("verify")
        .arg(&b)
        .args(["--via", "telepathy"])
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn docker_without_image_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("docker_noimg");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    // --via docker with no --image and no $THIRD_PARTY_VERIFIER_IMAGE: must fail
    // closed with a CLI error before any verification.
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/run_third_party_verifier.sh"))
        .arg("verify")
        .arg(&b)
        .args(["--via", "docker"])
        .env_remove("THIRD_PARTY_VERIFIER_IMAGE")
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
}

// --- meta -------------------------------------------------------------------

#[test]
fn selftest_passes() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/run_third_party_verifier.sh"))
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
fn help_exits_zero() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/run_third_party_verifier.sh"))
        .arg("--help")
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn unknown_mode_is_cli_error() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let out = Command::new("bash")
        .arg(root.join("runbooks/scripts/run_third_party_verifier.sh"))
        .arg("frobnicate")
        .current_dir(&root)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn verified_run_writes_operator_verdict_file() {
    let root = repo_root();
    if !prereqs(&root) {
        return;
    }
    let work = unique_dir("opverdict");
    let b = make_bundle(&work, "b", Some(&valid_lock()), Some(&valid_env()), true);
    let env = b.join("env.json");
    let (_c, _v, run_dir) = run_verify(
        "opverdict_run",
        &b,
        &["--current-env", env.to_str().unwrap()],
    );
    assert!(run_dir.join("operator_verdict.json").is_file());
}
