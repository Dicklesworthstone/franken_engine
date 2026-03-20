#![allow(clippy::needless_borrows_for_generic_args)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::control_plane_policy_diagnostics::DiagnosticReport;
use frankenengine_engine::operator_diagnostic_contract::{
    BoundaryPolicyMappingContract, InternalFailureKind,
};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    env::temp_dir().join(format!(
        "frankenengine-control-plane-policy-diagnostics-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn assert_required_files(out_dir: &Path) {
    for file in [
        "boundary_policy_mapping_contract.json",
        "operator_diagnostic_contract.json",
        "user_error_translation_matrix.json",
        "remediation_linkage_index.json",
        "control_plane_policy_diagnostics_report.json",
        "trace_ids.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "summary.md",
        "env.json",
        "repro.lock",
    ] {
        assert!(
            out_dir.join(file).exists(),
            "missing required artifact {}",
            out_dir.join(file).display()
        );
    }
    assert!(
        out_dir
            .join("step_logs")
            .join("step_001_generate.log")
            .exists()
    );
}

#[test]
fn binary_emits_expected_artifact_bundle() {
    let out_dir = unique_temp_dir("bundle");

    let output = Command::new(env!(
        "CARGO_BIN_EXE_franken_control_plane_policy_diagnostics"
    ))
    .args(["--out-dir", out_dir.to_str().unwrap()])
    .output()
    .expect("run control plane policy diagnostics binary");

    assert!(
        output.status.success(),
        "binary failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_required_files(&out_dir);

    let contract: BoundaryPolicyMappingContract = serde_json::from_slice(
        &fs::read(out_dir.join("boundary_policy_mapping_contract.json")).expect("read contract"),
    )
    .expect("deserialize contract");
    assert!(contract.verify_integrity());
    assert_eq!(contract.coverage_count(), InternalFailureKind::all().len());

    let report: DiagnosticReport = serde_json::from_slice(
        &fs::read(out_dir.join("control_plane_policy_diagnostics_report.json"))
            .expect("read report"),
    )
    .expect("deserialize report");
    assert_eq!(report.total_diagnostics, 8);
    assert!(report.release_blocked);

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("run_manifest.json")).expect("read manifest"),
    )
    .expect("deserialize manifest");
    assert_eq!(manifest["operator_mapping_count"].as_u64(), Some(9));
    assert_eq!(manifest["operator_diagnostic_count"].as_u64(), Some(9));
    assert_eq!(manifest["control_plane_diagnostic_count"].as_u64(), Some(8));
    assert_eq!(
        manifest["release_blocked_in_sample_report"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["artifact_paths"]["boundary_policy_mapping_contract"],
        "boundary_policy_mapping_contract.json"
    );

    let translation_matrix: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("user_error_translation_matrix.json"))
            .expect("read translation matrix"),
    )
    .expect("deserialize translation matrix");
    assert_eq!(
        translation_matrix["operator_rows"]
            .as_array()
            .unwrap()
            .len(),
        9
    );
    assert_eq!(
        translation_matrix["control_plane_rows"]
            .as_array()
            .unwrap()
            .len(),
        8
    );

    let remediation_index: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("remediation_linkage_index.json"))
            .expect("read remediation linkage index"),
    )
    .expect("deserialize remediation linkage index");
    let replay_links: Vec<&serde_json::Value> = remediation_index["operator_links"]
        .as_array()
        .expect("operator_links must be an array")
        .iter()
        .filter(|link| link["replay_available"].as_bool() == Some(true))
        .collect();
    assert!(
        !replay_links.is_empty(),
        "expected replay-capable operator links"
    );
    for link in replay_links {
        let sample = link["sample_replay_ref"]
            .as_str()
            .expect("replay-capable link must include sample_replay_ref");
        assert!(
            sample.starts_with("frankenctl replay run --trace "),
            "sample replay ref must use shipped replay run syntax: {sample}"
        );
        assert!(
            sample.ends_with(" --mode strict"),
            "sample replay ref must pin strict mode: {sample}"
        );
        assert!(
            !sample.contains("frankenctl replay --trace "),
            "sample replay ref must not use phantom top-level replay syntax: {sample}"
        );
    }

    let events_jsonl = fs::read_to_string(out_dir.join("events.jsonl")).expect("read events");
    assert_eq!(events_jsonl.lines().count(), 10);

    let stdout_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid JSON");
    assert_eq!(stdout_json["operator_mapping_count"].as_u64(), Some(9));
    assert_eq!(
        stdout_json["control_plane_diagnostic_count"].as_u64(),
        Some(8)
    );
}

#[test]
fn binary_honors_custom_epoch() {
    let out_dir = unique_temp_dir("epoch");

    let output = Command::new(env!(
        "CARGO_BIN_EXE_franken_control_plane_policy_diagnostics"
    ))
    .args(["--out-dir", out_dir.to_str().unwrap()])
    .args(["--epoch", "42"])
    .output()
    .expect("run control plane policy diagnostics binary with custom epoch");

    assert!(
        output.status.success(),
        "binary failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let contract: BoundaryPolicyMappingContract = serde_json::from_slice(
        &fs::read(out_dir.join("boundary_policy_mapping_contract.json")).expect("read contract"),
    )
    .expect("deserialize contract");
    assert_eq!(contract.epoch.as_u64(), 42);

    let report: DiagnosticReport = serde_json::from_slice(
        &fs::read(out_dir.join("control_plane_policy_diagnostics_report.json"))
            .expect("read report"),
    )
    .expect("deserialize report");
    assert_eq!(report.epoch.as_u64(), 42);

    let trace_ids: serde_json::Value =
        serde_json::from_slice(&fs::read(out_dir.join("trace_ids.json")).expect("read trace ids"))
            .expect("deserialize trace ids");
    assert_eq!(trace_ids["epoch_raw"].as_u64(), Some(42));
}
