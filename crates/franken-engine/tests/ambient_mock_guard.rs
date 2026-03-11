#![allow(clippy::needless_borrows_for_generic_args)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use frankenengine_engine::control_plane_mock_inventory::AmbientMockGuardReport;

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "frankenengine-ambient-mock-guard-it-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn write_fixture_file(root: &Path, relative_path: &str, contents: &str) {
    let path = root.join(relative_path);
    fs::create_dir_all(path.parent().expect("fixture file must have parent"))
        .expect("create fixture parent");
    fs::write(path, contents).expect("write fixture file");
}

fn read_report(out_dir: &Path) -> AmbientMockGuardReport {
    serde_json::from_slice(
        &fs::read(out_dir.join("ambient_mock_guard_report.json")).expect("read report"),
    )
    .expect("deserialize report")
}

#[test]
fn binary_passes_for_test_only_fixture() {
    let fixture_root = unique_temp_dir("pass-root");
    let out_dir = unique_temp_dir("pass-out");
    write_fixture_file(
        &fixture_root,
        "crates/franken-engine/src/lib.rs",
        r#"
#[cfg(test)]
mod tests {
    use crate::control_plane::mocks::{MockBudget, MockCx};

    #[test]
    fn helper() {
        let _cx = MockCx::new(crate::control_plane::mocks::trace_id_from_seed(1), MockBudget::new(10));
    }
}
"#,
    );

    let status = Command::new(env!("CARGO_BIN_EXE_franken_ambient_mock_guard"))
        .args(["--out-dir", out_dir.to_str().unwrap()])
        .args(["--scan-root", fixture_root.to_str().unwrap()])
        .status()
        .expect("run ambient mock guard");

    assert!(status.success());
    let report = read_report(&out_dir);
    assert_eq!(report.outcome.as_str(), "pass");
    assert!(out_dir.join("run_manifest.json").exists());
    assert!(out_dir.join("events.jsonl").exists());
    assert!(out_dir.join("commands.txt").exists());
    assert!(out_dir.join("step_logs/step_001_scan.log").exists());
    assert!(out_dir.join("summary.md").exists());
    assert!(out_dir.join("env.json").exists());
    assert!(out_dir.join("repro.lock").exists());

    let _ = fs::remove_dir_all(fixture_root);
    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn binary_fails_closed_for_production_mock_fixture() {
    let fixture_root = unique_temp_dir("fail-root");
    let out_dir = unique_temp_dir("fail-out");
    write_fixture_file(
        &fixture_root,
        "crates/franken-engine/src/lib.rs",
        r#"
use crate::control_plane::mocks::{MockBudget, MockCx};

fn make_mock() -> MockCx {
    MockCx::new(trace_id_from_seed(7), MockBudget::new(50))
}
"#,
    );

    let status = Command::new(env!("CARGO_BIN_EXE_franken_ambient_mock_guard"))
        .args(["--out-dir", out_dir.to_str().unwrap()])
        .args(["--scan-root", fixture_root.to_str().unwrap()])
        .status()
        .expect("run ambient mock guard");

    assert_eq!(status.code(), Some(2));
    let report = read_report(&out_dir);
    assert_eq!(report.outcome.as_str(), "fail_closed");
    assert!(
        report
            .violations
            .iter()
            .any(|violation| violation.diagnostic_code == "AMG-PROD-MOCK-MODULE-REFERENCE")
    );
    assert!(
        report
            .violations
            .iter()
            .any(|violation| violation.diagnostic_code == "AMG-PROD-MOCK-CX")
    );

    let _ = fs::remove_dir_all(fixture_root);
    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn binary_ignores_comment_and_string_only_mentions() {
    let fixture_root = unique_temp_dir("boundary-root");
    let out_dir = unique_temp_dir("boundary-out");
    write_fixture_file(
        &fixture_root,
        "crates/franken-engine/src/lib.rs",
        r#"
fn doc_only() {
    let note = "MockCx should stay in strings";
    // crate::control_plane::mocks::MockCx is mentioned here as documentation only.
    let _ = note;
}
"#,
    );

    let status = Command::new(env!("CARGO_BIN_EXE_franken_ambient_mock_guard"))
        .args(["--out-dir", out_dir.to_str().unwrap()])
        .args(["--scan-root", fixture_root.to_str().unwrap()])
        .status()
        .expect("run ambient mock guard");

    assert!(status.success());
    let report = read_report(&out_dir);
    assert_eq!(report.outcome.as_str(), "pass");
    assert!(report.violations.is_empty());

    let _ = fs::remove_dir_all(fixture_root);
    let _ = fs::remove_dir_all(out_dir);
}
