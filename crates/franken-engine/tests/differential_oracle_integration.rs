#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}.{}", std::process::id(), nonce, ext));
    path
}

fn backend<'a>(report: &'a serde_json::Value, backend: &str) -> &'a serde_json::Value {
    report["backends"]
        .as_array()
        .expect("backends should be an array")
        .iter()
        .find(|receipt| receipt["backend"].as_str() == Some(backend))
        .unwrap_or_else(|| panic!("missing backend receipt `{backend}`"))
}

#[test]
fn frankenctl_differential_oracle_run_emits_four_backend_receipts() {
    let source_path = temp_path("differential_oracle_fixture", "js");
    let report_path = temp_path("differential_oracle_report", "json");
    fs::write(&source_path, "1 + 1;\n").expect("fixture should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "differential-oracle",
            "run",
            "--input",
            source_path
                .to_str()
                .expect("temp source path should be utf8"),
            "--case-id",
            "integration-basic-arithmetic",
            "--timeout-ms",
            "1000",
            "--out",
            report_path
                .to_str()
                .expect("temp report path should be utf8"),
        ])
        .output()
        .expect("frankenctl differential-oracle should execute");

    assert!(
        output.status.success(),
        "frankenctl should succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout_report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should contain JSON report");
    let file_report: serde_json::Value = serde_json::from_slice(
        fs::read(&report_path)
            .expect("report file should exist")
            .as_slice(),
    )
    .expect("report file should contain JSON");

    assert_eq!(
        stdout_report["schema_version"].as_str(),
        Some("franken-engine.differential-oracle.v1")
    );
    assert_eq!(
        stdout_report["case_id"].as_str(),
        Some("integration-basic-arithmetic")
    );
    assert_eq!(stdout_report["backends"].as_array().unwrap().len(), 4);
    assert_eq!(
        stdout_report["canonicalization"]["schema_version"].as_str(),
        Some("franken-engine.differential-oracle.canonicalization.v1")
    );
    assert_eq!(
        stdout_report["canonicalization"]["observations"]
            .as_array()
            .expect("canonical observations should be an array")
            .len(),
        4
    );
    assert!(
        stdout_report["canonicalization"]["comparisons"]
            .as_array()
            .expect("canonical comparisons should be an array")
            .iter()
            .any(|comparison| comparison["mode"].as_str() == Some("structured_value"))
    );
    assert_eq!(
        stdout_report["divergence_taxonomy"]["schema_version"].as_str(),
        Some("franken-engine.differential-oracle.divergence-taxonomy.v2")
    );
    assert!(
        stdout_report["divergence_taxonomy"]["findings"]
            .as_array()
            .is_some()
    );
    assert_eq!(
        file_report["schema_version"],
        stdout_report["schema_version"]
    );

    let node = backend(&stdout_report, "node_lts");
    assert!(matches!(
        node["status"].as_str(),
        Some("completed" | "failed" | "unavailable" | "timeout")
    ));
    assert!(node["command"].as_array().is_some());

    let bun = backend(&stdout_report, "bun_stable");
    assert!(matches!(
        bun["status"].as_str(),
        Some("completed" | "failed" | "unavailable" | "timeout")
    ));
    assert!(bun["command"].as_array().is_some());

    let franken_engine = backend(&stdout_report, "franken_engine");
    assert_eq!(franken_engine["status"].as_str(), Some("completed"));
    assert_eq!(franken_engine["value"].as_str(), Some("2"));
    assert_eq!(franken_engine["exit_code"].as_i64(), Some(0));

    let franken_core = backend(&stdout_report, "franken_core");
    assert_eq!(franken_core["status"].as_str(), Some("completed"));
    assert_eq!(franken_core["value"].as_str(), Some("2"));
    assert_eq!(franken_core["exit_code"].as_i64(), Some(0));
    assert!(
        franken_core["command"]
            .as_array()
            .expect("franken-core command should be an array")
            .iter()
            .any(|entry| entry
                .as_str()
                .unwrap_or_default()
                .contains("frankenengine_core::baseline_interpreter::QuickJsLane::execute"))
    );
    assert!(
        franken_core["diagnostics"]
            .as_array()
            .expect("franken-core diagnostics should be an array")
            .iter()
            .any(|entry| entry
                .as_str()
                .unwrap_or_default()
                .contains("frankenengine-core path dependency executed"))
    );
}
