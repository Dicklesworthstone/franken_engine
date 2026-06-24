//! Y.4 operator proof-bundle verification surface — integration tests.
//!
//! Track Y, bead `bd-cixqu.25.4`. Two layers, both no-mock:
//!
//! * **Real pipeline e2e** — drive the actual Y.1 exporter
//!   (`scripts/export_proof_bundle.sh`) and the Y.4 operator wrapper
//!   (`runbooks/scripts/verify_proof_bundle.sh`) via `std::process::Command` on
//!   real fixture bundles, then feed their genuine `operator_verdict.json` into
//!   the [`ProofBundleStatusPanel`]. Covers the proof-recheck round-trip and the
//!   recheck-failure modes (tamper → regression, toolchain → drift).
//! * **Panel composition** — exercise the operator panel data contract through
//!   the public crate boundary (multi-release histories, health transitions,
//!   serde round-trips, verdict ingestion shapes).
//!
//! The shell layer uses `--via local` (python3 only) so the suite is portable;
//! the docker clean-room path is covered by
//! `scripts/run_y4_proof_bundle_operator_surface.sh`. Shell tests skip gracefully
//! (with an eprintln) when python3 or the repo scripts are unavailable.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use frankenengine_engine::proof_bundle_status_panel::{
    PanelHealth, ProofBundleStatusPanel, ProofBundleVerificationRecord, VerificationClassification,
    VersionStatus,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// --- shared helpers ---------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("repo root")
}

fn have_python3() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn scripts_present(root: &Path) -> bool {
    root.join("scripts/export_proof_bundle.sh").is_file()
        && root
            .join("runbooks/scripts/verify_proof_bundle.sh")
            .is_file()
}

/// Skip-guard: returns false (and logs) when the shell pipeline cannot run.
fn pipeline_available(root: &Path) -> bool {
    if !have_python3() {
        eprintln!("[y4-it] skip: python3 unavailable");
        return false;
    }
    if !scripts_present(root) {
        eprintln!("[y4-it] skip: Y.1/Y.4 scripts not present");
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
    let dir = std::env::temp_dir().join(format!("y4_it_{tag}_{pid}_{nanos}"));
    std::fs::create_dir_all(&dir).expect("mk tmp");
    dir
}

const FIXTURE_PY: &str = r#"
import hashlib, json, os, sys
d = sys.argv[1]
os.makedirs(d, exist_ok=True)
for cid in ("FE-CLAIM-016", "FE-CLAIM-020"):
    p = {
        "schema_version": "franken-engine.theorem-backed-compiler.proof.v1",
        "claim_id": cid, "track": "G.7", "proof_kind": "theorem-backed-compiler",
        "verdict": "proven", "generated_utc": "2026-01-01T00:00:00Z",
        "source_module": "y4-it-fixture",
    }
    body = {k: v for k, v in p.items() if k != "content_hash"}
    enc = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    p["content_hash"] = "sha256:" + hashlib.sha256(enc).hexdigest()
    with open(os.path.join(d, cid + ".proof.json"), "w", encoding="utf-8") as fh:
        json.dump(p, fh, indent=2, sort_keys=True)
        fh.write("\n")
"#;

const TAMPER_PY: &str = r#"
import json, os, sys, glob
stage = sys.argv[1]
victim = sorted(glob.glob(os.path.join(stage, "**", "*.proof.json"), recursive=True))[0]
with open(victim, encoding="utf-8") as fh:
    proof = json.load(fh)
proof["source_module"] = "tampered-after-export"
with open(victim, "w", encoding="utf-8") as fh:
    json.dump(proof, fh, indent=2, sort_keys=True)
    fh.write("\n")
"#;

/// Export a valid Y.1 bundle into `work`. Returns the tar path.
fn make_valid_bundle(root: &Path, work: &Path) -> PathBuf {
    let src = work.join("src");
    let out = work.join("export");
    let py = Command::new("python3")
        .arg("-c")
        .arg(FIXTURE_PY)
        .arg(&src)
        .status()
        .expect("fixture py");
    assert!(py.success(), "fixture generation failed");
    let st = Command::new("bash")
        .arg(root.join("scripts/export_proof_bundle.sh"))
        .arg("export")
        .arg(&src)
        .arg(&out)
        .current_dir(root)
        .status()
        .expect("export");
    assert!(st.success(), "export_proof_bundle.sh export failed");
    let tar = out.join("proof_bundle.tar.gz");
    assert!(tar.is_file(), "no exported tar at {tar:?}");
    tar
}

/// Produce a tampered copy of `valid_tar` (mutate a proof body, re-pack). Returns the tar.
fn make_tampered_bundle(valid_tar: &Path, work: &Path) -> PathBuf {
    let stage = work.join("tamper_stage");
    std::fs::create_dir_all(&stage).expect("mk stage");
    let untar = Command::new("tar")
        .arg("-xzf")
        .arg(valid_tar)
        .arg("-C")
        .arg(&stage)
        .status()
        .expect("untar");
    assert!(untar.success());
    let tp = Command::new("python3")
        .arg("-c")
        .arg(TAMPER_PY)
        .arg(&stage)
        .status()
        .expect("tamper py");
    assert!(tp.success());
    // Find the single bundle root dir under the stage.
    let broot = std::fs::read_dir(&stage)
        .expect("read stage")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .expect("bundle root");
    let tar = work.join("proof_bundle_tampered.tar.gz");
    let pack = Command::new("tar")
        .args([
            "--sort=name",
            "--mtime=UTC 1970-01-01",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "-czf",
        ])
        .arg(&tar)
        .arg(broot.file_name().expect("name"))
        .current_dir(&stage)
        .status()
        .expect("pack");
    assert!(pack.success());
    tar
}

/// Run the operator wrapper. Returns (exit_code, operator_verdict.json string).
fn run_wrapper(root: &Path, work: &Path, bundle: &Path, extra: &[&str]) -> (i32, String) {
    let verdict = work.join(format!(
        "verdict_{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let art = work.join("artifacts");
    let mut cmd = Command::new("bash");
    cmd.arg(root.join("runbooks/scripts/verify_proof_bundle.sh"))
        .arg("verify")
        .arg(bundle)
        .arg("--via")
        .arg("local")
        .arg("--json-out")
        .arg(&verdict)
        .arg("--artifact-root")
        .arg(&art)
        .current_dir(root);
    for a in extra {
        cmd.arg(a);
    }
    let out = cmd.output().expect("run wrapper");
    let code = out.status.code().unwrap_or(-1);
    let json = std::fs::read_to_string(&verdict).unwrap_or_default();
    (code, json)
}

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn rec(
    release: &str,
    class: VerificationClassification,
    vstatus: VersionStatus,
    at: u64,
) -> ProofBundleVerificationRecord {
    ProofBundleVerificationRecord::new(
        release,
        "proof_bundle.tar.gz",
        "local",
        class,
        vstatus,
        2,
        epoch(at),
    )
    .expect("valid record")
}

// =====================================================================
// Layer 1 — real pipeline e2e (Command-driven, no mocks)
// =====================================================================

#[test]
fn e2e_export_produces_a_bundle() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let work = unique_dir("export");
    let tar = make_valid_bundle(&root, &work);
    assert!(tar.is_file());
}

#[test]
fn e2e_valid_bundle_verifies_aligned() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let work = unique_dir("verify_ok");
    let tar = make_valid_bundle(&root, &work);
    let (code, json) = run_wrapper(
        &root,
        &work,
        &tar,
        &["--installed-lean", "4.9.0", "--installed-coq", "8.19.2"],
    );
    assert_eq!(code, 0, "verified bundle should exit 0; verdict={json}");
    let r = ProofBundleVerificationRecord::from_operator_verdict_json(&json, "v1.0.0", epoch(1))
        .expect("ingest real verdict");
    assert_eq!(r.classification, VerificationClassification::Verified);
    assert_eq!(r.version_status, VersionStatus::Aligned);
    assert!(r.is_trusted());
    assert!(r.digest_matches());
    assert_eq!(r.claim_count, 2);
}

#[test]
fn e2e_real_verdict_feeds_healthy_panel() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let work = unique_dir("panel_ok");
    let tar = make_valid_bundle(&root, &work);
    let (_code, json) = run_wrapper(&root, &work, &tar, &["--installed-lean", "4.9.0"]);
    let mut panel = ProofBundleStatusPanel::new("ops");
    panel.record(
        ProofBundleVerificationRecord::from_operator_verdict_json(&json, "v1.0.0", epoch(5))
            .expect("ingest"),
    );
    assert_eq!(panel.health(), PanelHealth::Healthy);
    assert_eq!(panel.trusted_release_count(), 1);
}

#[test]
fn e2e_toolchain_drift_is_advisory() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let work = unique_dir("drift");
    let tar = make_valid_bundle(&root, &work);
    // Bundle pins lean v4.9.0; operator runs v4.7.0 => drift, advisory exit 0.
    let (code, json) = run_wrapper(&root, &work, &tar, &["--installed-lean", "4.7.0"]);
    assert_eq!(code, 0, "drift is advisory (exit 0); verdict={json}");
    let r = ProofBundleVerificationRecord::from_operator_verdict_json(&json, "v1.0.0", epoch(1))
        .expect("ingest");
    assert_eq!(r.classification, VerificationClassification::VersionDrift);
    assert!(r.version_status.is_drifted());
    // Drift never invalidates content: the digest still reproduces.
    assert!(r.digest_matches());
}

#[test]
fn e2e_strict_version_promotes_drift_to_exit_2() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let work = unique_dir("strict");
    let tar = make_valid_bundle(&root, &work);
    let (code, json) = run_wrapper(
        &root,
        &work,
        &tar,
        &["--installed-lean", "4.7.0", "--strict-version"],
    );
    assert_eq!(code, 2, "strict drift should exit 2; verdict={json}");
    let r = ProofBundleVerificationRecord::from_operator_verdict_json(&json, "v1.0.0", epoch(1))
        .expect("ingest");
    assert_eq!(r.classification, VerificationClassification::VersionDrift);
}

#[test]
fn e2e_expected_pin_mismatch_is_drift() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let work = unique_dir("expmismatch");
    let tar = make_valid_bundle(&root, &work);
    // Bundle pins v4.9.0 but operator EXPECTED v4.7.0 => expected_mismatch.
    let (code, json) = run_wrapper(
        &root,
        &work,
        &tar,
        &["--expected-lean", "4.7.0", "--installed-lean", "4.9.0"],
    );
    assert_eq!(code, 0);
    let r = ProofBundleVerificationRecord::from_operator_verdict_json(&json, "v1.0.0", epoch(1))
        .expect("ingest");
    assert_eq!(r.version_status, VersionStatus::ExpectedMismatch);
    assert_eq!(r.classification, VerificationClassification::VersionDrift);
}

#[test]
fn e2e_tampered_bundle_is_proof_regression() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let work = unique_dir("tamper");
    let valid = make_valid_bundle(&root, &work);
    let tampered = make_tampered_bundle(&valid, &work);
    let (code, json) = run_wrapper(&root, &work, &tampered, &["--installed-lean", "4.9.0"]);
    assert_eq!(
        code, 1,
        "tampered bundle should fail closed (exit 1); verdict={json}"
    );
    let r = ProofBundleVerificationRecord::from_operator_verdict_json(&json, "v1.0.0", epoch(1))
        .expect("ingest");
    assert!(r.classification.is_regression());
    assert!(!r.digest_matches());
    assert!(
        !r.failing_claims.is_empty(),
        "regression should name failing claims; verdict={json}"
    );
}

#[test]
fn e2e_regression_drives_panel_compromised() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let work = unique_dir("compromised");
    let valid = make_valid_bundle(&root, &work);
    let tampered = make_tampered_bundle(&valid, &work);
    let (_c1, ok_json) = run_wrapper(&root, &work, &valid, &["--installed-lean", "4.9.0"]);
    let (_c2, bad_json) = run_wrapper(&root, &work, &tampered, &["--installed-lean", "4.9.0"]);
    let mut panel = ProofBundleStatusPanel::new("ops");
    panel.record(
        ProofBundleVerificationRecord::from_operator_verdict_json(&ok_json, "v1.0.0", epoch(1))
            .unwrap(),
    );
    panel.record(
        ProofBundleVerificationRecord::from_operator_verdict_json(&bad_json, "v1.1.0", epoch(2))
            .unwrap(),
    );
    assert_eq!(panel.health(), PanelHealth::Compromised);
    assert_eq!(panel.regressed_releases().len(), 1);
}

#[test]
fn e2e_two_releases_mixed_is_drifting() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let work = unique_dir("mixed");
    let tar = make_valid_bundle(&root, &work);
    let (_a, verified) = run_wrapper(&root, &work, &tar, &["--installed-lean", "4.9.0"]);
    let (_b, drifted) = run_wrapper(&root, &work, &tar, &["--installed-lean", "4.7.0"]);
    let panel = ProofBundleStatusPanel::default()
        .with_record(
            ProofBundleVerificationRecord::from_operator_verdict_json(
                &verified,
                "v1.0.0",
                epoch(1),
            )
            .unwrap(),
        )
        .with_record(
            ProofBundleVerificationRecord::from_operator_verdict_json(&drifted, "v2.0.0", epoch(2))
                .unwrap(),
        );
    assert_eq!(panel.health(), PanelHealth::Drifting);
}

#[test]
fn e2e_wrapper_selftest_passes() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let st = Command::new("bash")
        .arg(root.join("runbooks/scripts/verify_proof_bundle.sh"))
        .arg("selftest")
        .current_dir(&root)
        .output()
        .expect("selftest");
    assert!(
        st.status.success(),
        "wrapper selftest failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
}

#[test]
fn e2e_wrapper_help_exits_zero() {
    let root = repo_root();
    if !scripts_present(&root) {
        return;
    }
    let st = Command::new("bash")
        .arg(root.join("runbooks/scripts/verify_proof_bundle.sh"))
        .arg("--help")
        .output()
        .expect("help");
    assert!(st.status.success());
}

#[test]
fn e2e_missing_bundle_is_cli_error() {
    let root = repo_root();
    if !scripts_present(&root) {
        return;
    }
    let st = Command::new("bash")
        .arg(root.join("runbooks/scripts/verify_proof_bundle.sh"))
        .arg("verify")
        .arg("/no/such/bundle.tar.gz")
        .arg("--via")
        .arg("local")
        .current_dir(&root)
        .output()
        .expect("missing");
    assert_eq!(st.status.code(), Some(3), "missing bundle => exit 3");
}

#[test]
fn e2e_verify_extracted_dir_path() {
    let root = repo_root();
    if !pipeline_available(&root) {
        return;
    }
    let work = unique_dir("dirpath");
    let _tar = make_valid_bundle(&root, &work);
    // The exporter also stages an unpacked bundle dir at export/bundle/.
    let bundle_dir = work.join("export").join("bundle");
    assert!(bundle_dir.is_dir(), "staged bundle dir should exist");
    let (code, json) = run_wrapper(&root, &work, &bundle_dir, &["--installed-lean", "4.9.0"]);
    assert_eq!(code, 0, "dir-path verify should pass; verdict={json}");
    let r = ProofBundleVerificationRecord::from_operator_verdict_json(&json, "v1.0.0", epoch(1))
        .expect("ingest");
    assert_eq!(r.classification, VerificationClassification::Verified);
}

// =====================================================================
// Layer 2 — panel composition through the public crate boundary
// =====================================================================

#[test]
fn panel_default_is_unknown_health() {
    assert_eq!(
        ProofBundleStatusPanel::default().health(),
        PanelHealth::Unknown
    );
}

#[test]
fn panel_single_verified_is_healthy() {
    let p = ProofBundleStatusPanel::default().with_record(rec(
        "v1",
        VerificationClassification::Verified,
        VersionStatus::Aligned,
        1,
    ));
    assert_eq!(p.health(), PanelHealth::Healthy);
}

#[test]
fn panel_single_drift_is_drifting() {
    let p = ProofBundleStatusPanel::default().with_record(rec(
        "v1",
        VerificationClassification::VersionDrift,
        VersionStatus::Drift,
        1,
    ));
    assert_eq!(p.health(), PanelHealth::Drifting);
}

#[test]
fn panel_single_regression_is_compromised() {
    let p = ProofBundleStatusPanel::default().with_record(rec(
        "v1",
        VerificationClassification::ProofRegression,
        VersionStatus::Aligned,
        1,
    ));
    assert_eq!(p.health(), PanelHealth::Compromised);
}

#[test]
fn panel_latest_per_release_collapses_history() {
    let p = ProofBundleStatusPanel::default()
        .with_record(rec(
            "v1",
            VerificationClassification::ProofRegression,
            VersionStatus::Aligned,
            1,
        ))
        .with_record(rec(
            "v1",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            2,
        ))
        .with_record(rec(
            "v2",
            VerificationClassification::Verified,
            VersionStatus::Absent,
            3,
        ));
    assert_eq!(p.latest_per_release().len(), 2);
    assert_eq!(p.health(), PanelHealth::Healthy);
}

#[test]
fn panel_regression_then_fix_recovers() {
    let p = ProofBundleStatusPanel::default()
        .with_record(rec(
            "v1",
            VerificationClassification::ProofRegression,
            VersionStatus::Aligned,
            1,
        ))
        .with_record(rec(
            "v1",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            2,
        ));
    assert_eq!(p.health(), PanelHealth::Healthy);
    assert!(p.regressed_releases().is_empty());
}

#[test]
fn panel_trusted_count_counts_releases_not_records() {
    let p = ProofBundleStatusPanel::default()
        .with_record(rec(
            "v1",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            1,
        ))
        .with_record(rec(
            "v1",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            2,
        ))
        .with_record(rec(
            "v2",
            VerificationClassification::VersionDrift,
            VersionStatus::Drift,
            3,
        ));
    assert_eq!(p.trusted_release_count(), 1);
}

#[test]
fn panel_latest_returns_last_recorded() {
    let p = ProofBundleStatusPanel::default()
        .with_record(rec(
            "v1",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            1,
        ))
        .with_record(rec(
            "v2",
            VerificationClassification::VersionDrift,
            VersionStatus::Drift,
            2,
        ));
    assert_eq!(p.latest().unwrap().release_id, "v2");
}

#[test]
fn panel_latest_for_specific_release() {
    let p = ProofBundleStatusPanel::default()
        .with_record(rec(
            "v1",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            1,
        ))
        .with_record(rec(
            "v2",
            VerificationClassification::ProofRegression,
            VersionStatus::Aligned,
            2,
        ));
    assert_eq!(
        p.latest_for_release("v1").unwrap().classification,
        VerificationClassification::Verified
    );
    assert!(p.latest_for_release("v9").is_none());
}

#[test]
fn panel_serde_roundtrip_preserves_health() {
    let p = ProofBundleStatusPanel::default()
        .with_record(
            rec(
                "v1",
                VerificationClassification::Verified,
                VersionStatus::Aligned,
                1,
            )
            .with_digests("aa", "aa"),
        )
        .with_record(rec(
            "v2",
            VerificationClassification::VersionDrift,
            VersionStatus::Drift,
            2,
        ));
    let json = serde_json::to_string(&p).expect("ser");
    let back: ProofBundleStatusPanel = serde_json::from_str(&json).expect("de");
    assert_eq!(p, back);
    assert_eq!(back.health(), PanelHealth::Drifting);
}

#[test]
fn ingest_verified_json_shape() {
    let json = r#"{
      "schema_version":"franken-engine.proof-bundle-operator-verdict.v1",
      "classification":"verified","version_status":"aligned","claim_count":4,
      "source":"proof_bundle.tar.gz","via":"docker",
      "recomputed_recheck_digest":"ff","expected_recheck_digest":"ff","failing_claims":[]
    }"#;
    let r =
        ProofBundleVerificationRecord::from_operator_verdict_json(json, "rel", epoch(1)).unwrap();
    assert!(r.is_trusted());
    assert_eq!(r.claim_count, 4);
    assert_eq!(r.via, "docker");
}

#[test]
fn ingest_regression_json_shape() {
    let json = r#"{
      "schema_version":"franken-engine.proof-bundle-operator-verdict.v1",
      "classification":"proof_regression","version_status":"absent","claim_count":3,
      "source":"t.tar.gz","via":"local",
      "recomputed_recheck_digest":"11","expected_recheck_digest":"22",
      "failing_claims":["FE-CLAIM-019","FE-CLAIM-020"]
    }"#;
    let r =
        ProofBundleVerificationRecord::from_operator_verdict_json(json, "rel", epoch(1)).unwrap();
    assert!(r.classification.is_regression());
    assert_eq!(r.failing_claims.len(), 2);
    assert!(!r.digest_matches());
}

#[test]
fn ingest_rejects_wrong_schema() {
    let json = r#"{"schema_version":"x.y.z","classification":"verified"}"#;
    assert!(
        ProofBundleVerificationRecord::from_operator_verdict_json(json, "r", epoch(1)).is_err()
    );
}

#[test]
fn ingest_rejects_malformed() {
    assert!(
        ProofBundleVerificationRecord::from_operator_verdict_json("nope", "r", epoch(1)).is_err()
    );
}

#[test]
fn classification_actions_guide_operator() {
    assert!(
        VerificationClassification::ProofRegression
            .recommended_action()
            .contains("Escalate")
    );
    assert!(
        VerificationClassification::VersionDrift
            .recommended_action()
            .contains("Update")
    );
    assert!(
        VerificationClassification::Verified
            .recommended_action()
            .contains("Rely")
    );
}

#[test]
fn record_validation_rejects_empty_identifiers() {
    assert!(
        ProofBundleVerificationRecord::new(
            "",
            "b",
            "local",
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            1,
            epoch(1)
        )
        .is_err()
    );
}

#[test]
fn record_digest_match_predicate() {
    let m = rec(
        "v",
        VerificationClassification::Verified,
        VersionStatus::Aligned,
        1,
    )
    .with_digests("deadbeef", "deadbeef");
    assert!(m.digest_matches());
    let n = rec(
        "v",
        VerificationClassification::ProofRegression,
        VersionStatus::Aligned,
        1,
    )
    .with_digests("deadbeef", "feedface");
    assert!(!n.digest_matches());
}

#[test]
fn version_status_drift_predicates() {
    assert!(VersionStatus::Drift.is_drifted());
    assert!(VersionStatus::ExpectedMismatch.is_drifted());
    assert!(!VersionStatus::Aligned.is_drifted());
    assert!(!VersionStatus::Absent.is_drifted());
}

#[test]
fn error_record_yields_unknown_health() {
    let p = ProofBundleStatusPanel::default().with_record(rec(
        "v1",
        VerificationClassification::Error,
        VersionStatus::Absent,
        1,
    ));
    assert_eq!(p.health(), PanelHealth::Unknown);
}

#[test]
fn many_releases_all_verified_scales_healthy() {
    let mut p = ProofBundleStatusPanel::new("fleet");
    for i in 0..12u64 {
        p.record(rec(
            &format!("v{i}"),
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            i,
        ));
    }
    assert_eq!(p.latest_per_release().len(), 12);
    assert_eq!(p.trusted_release_count(), 12);
    assert_eq!(p.health(), PanelHealth::Healthy);
}

#[test]
fn one_regression_among_many_is_compromised() {
    let mut p = ProofBundleStatusPanel::new("fleet");
    for i in 0..10u64 {
        p.record(rec(
            &format!("v{i}"),
            VerificationClassification::Verified,
            VersionStatus::Aligned,
            i,
        ));
    }
    p.record(rec(
        "v-bad",
        VerificationClassification::ProofRegression,
        VersionStatus::Aligned,
        99,
    ));
    assert_eq!(p.health(), PanelHealth::Compromised);
    assert_eq!(p.regressed_releases().len(), 1);
}

#[test]
fn panel_new_sets_title() {
    let p = ProofBundleStatusPanel::new("My Console");
    assert_eq!(p.title, "My Console");
    assert!(p.history.is_empty());
}
