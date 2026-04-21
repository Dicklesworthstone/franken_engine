use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn write_high_water_mark(path: &Path, total_tests: usize, passed_tests: usize) {
    fs::write(
        path,
        format!(
            r#"schema_version = "franken-engine.test262-high-water-mark.v1"
measurement_date = "2026-04-20T00:00:00Z"
es_profile = "ES2020"
created_by = "test"

[pass_counts]
total_tests = {total_tests}
passed_tests = {passed_tests}
failed_tests = {failed_tests}
skipped_tests = 0
waived_tests = 0

[chapter_breakdown]
chapter_8_types_pass_rate = 0.50
chapter_12_expressions_pass_rate = 0.50
chapter_13_statements_pass_rate = 0.50
chapter_14_functions_pass_rate = 0.50

[regression_policy]
allow_pass_rate_decrease = false
min_pass_rate_threshold = 0.10
regression_acknowledgment_required = true
"#,
            failed_tests = total_tests.saturating_sub(passed_tests),
        ),
    )
    .expect("write high-water mark");
}

fn write_stub_cargo(path: &Path, total_tests: usize, passed_tests: usize, blocked_failures: usize) {
    let script = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

output_root=""
hwm_path=""
args=("$@")
for ((idx = 0; idx < ${{#args[@]}}; idx++)); do
  case "${{args[$idx]}}" in
    --output-root)
      output_root="${{args[$((idx + 1))]}}"
      ;;
    --high-water-mark)
      hwm_path="${{args[$((idx + 1))]}}"
      ;;
  esac
done

if [[ -z "$output_root" || -z "$hwm_path" ]]; then
  echo "missing runner paths" >&2
  exit 2
fi

run_dir="$output_root/stub-run"
mkdir -p "$run_dir"
manifest="$run_dir/run_manifest.json"
evidence="$run_dir/evidence.jsonl"
runner_hwm="$run_dir/test262_hwm.json"

cat > "$manifest" <<JSON
{{
  "run_id": "stub-run",
  "total_profile_tests": {total_tests},
  "passed": {passed_tests},
  "failed": {failed_tests},
  "waived": 0,
  "timed_out": 0,
  "crashed": 0,
  "blocked_failures": {blocked_failures},
  "profile_hash": "profile-stub",
  "waiver_hash": "waiver-stub",
  "pin_hash": "pin-stub",
  "env_fingerprint": "env-stub",
  "pass_regression_warning": null
}}
JSON

printf '%s\n' '{{"schema_version":"franken-engine.test262-evidence.v1","run_id":"stub-run"}}' > "$evidence"

cat > "$runner_hwm" <<JSON
{{
  "schema_version": "franken-engine.test262-high-water-mark.v1",
  "profile_hash": "profile-stub",
  "pass_count": {passed_tests},
  "recorded_at_utc": "2026-04-21T00:00:00Z"
}}
JSON
cp "$runner_hwm" "$hwm_path"

echo "test262 run_manifest=$manifest"
echo "test262 evidence=$evidence"
echo "test262 high_water_mark=$runner_hwm"
echo "test262 canonical_high_water_mark=$hwm_path"
"#,
        failed_tests = total_tests.saturating_sub(passed_tests),
    );

    fs::write(path, script).expect("write cargo stub");
    let mut permissions = fs::metadata(path).expect("stub metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod cargo stub");
}

fn run_update_with_stub(
    hwm_path: &Path,
    artifacts_dir: &Path,
    stub_dir: &Path,
) -> std::process::Output {
    let path = format!(
        "{}:{}",
        stub_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    Command::new(repo_root().join("scripts/test262_regression_gate.sh"))
        .arg("update")
        .env("PATH", path)
        .env("TEST262_GATE_HIGH_WATER_MARK_FILE", hwm_path)
        .env("TEST262_GATE_ARTIFACTS_DIR", artifacts_dir)
        .env("TEST262_GATE_RUN_DATE", "2026-04-21")
        .output()
        .expect("run update gate")
}

#[test]
fn update_mode_runs_runner_and_persists_validated_high_water_mark() {
    let temp = tempfile::tempdir().expect("tempdir");
    let hwm_path = temp.path().join("test262_high_water_mark.toml");
    let artifacts_dir = temp.path().join("artifacts");
    let stub_dir = temp.path().join("bin");
    fs::create_dir_all(&stub_dir).expect("stub dir");
    write_high_water_mark(&hwm_path, 10, 5);
    write_stub_cargo(&stub_dir.join("cargo"), 4, 3, 0);

    let output = run_update_with_stub(&hwm_path, &artifacts_dir, &stub_dir);

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let updated = fs::read_to_string(&hwm_path).expect("updated hwm");
    assert!(updated.contains("created_by = \"test262_regression_gate.sh update\""));
    assert!(updated.contains("total_tests = 4"));
    assert!(updated.contains("passed_tests = 3"));
    assert!(updated.contains("profile_hash = \"profile-stub\""));
    assert!(artifacts_dir.join("update_report.json").exists());
}

#[test]
fn update_mode_rejects_unacknowledged_pass_rate_regression() {
    let temp = tempfile::tempdir().expect("tempdir");
    let hwm_path = temp.path().join("test262_high_water_mark.toml");
    let artifacts_dir = temp.path().join("artifacts");
    let stub_dir = temp.path().join("bin");
    fs::create_dir_all(&stub_dir).expect("stub dir");
    write_high_water_mark(&hwm_path, 10, 9);
    write_stub_cargo(&stub_dir.join("cargo"), 4, 2, 0);
    let original = fs::read_to_string(&hwm_path).expect("original hwm");

    let output = run_update_with_stub(&hwm_path, &artifacts_dir, &stub_dir);

    assert!(
        !output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("regressed below high-water rate"));
    assert_eq!(
        fs::read_to_string(&hwm_path).expect("unchanged hwm"),
        original
    );
}
