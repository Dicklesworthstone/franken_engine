#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn temp_path(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    path.push(format!("{}_{}_{}.{}", name, std::process::id(), nonce, ext));
    path
}

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    path.push(format!("{}_{}_{}", name, std::process::id(), nonce));
    fs::create_dir_all(&path).expect("temporary directory should be created");
    path
}

fn write_fixture_catalog(path: &Path) -> String {
    let source = "let value = 41 + 1;";
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(source, ParseGoal::Script)
        .expect("fixture source should parse");
    let expected_hash = tree.canonical_hash();

    let catalog = serde_json::json!({
        "schema_version": "franken-engine.parser-phase0.semantic-fixtures.v1",
        "parser_mode": "scalar_reference",
        "fixtures": [
            {
                "id": "lockstep-fixture-1",
                "family_id": "statement.expression",
                "goal": "script",
                "source": source,
                "expected_hash": expected_hash
            }
        ]
    });

    fs::write(
        path,
        serde_json::to_vec_pretty(&catalog).expect("fixture catalog should serialize"),
    )
    .expect("fixture catalog should be written");

    expected_hash
}

fn write_runtime_specs(path: &Path, expected_hash: &str) {
    let toml = runtime_specs_content(expected_hash, &["node", "bun"]);
    write_runtime_specs_content(path, toml.as_str());
}

fn write_runtime_specs_with_expected_hash(path: &Path, hash: &str) {
    let toml = runtime_specs_content(hash, &["node", "bun"]);
    write_runtime_specs_content(path, toml.as_str());
}

fn write_runtime_specs_with_runtime_ids(path: &Path, expected_hash: &str, runtime_ids: &[&str]) {
    let toml = runtime_specs_content(expected_hash, runtime_ids);
    write_runtime_specs_content(path, toml.as_str());
}

fn write_runtime_specs_content(path: &Path, content: &str) {
    fs::write(path, content).expect("runtime spec file should be written");
}

fn write_runtime_specs_using_script(path: &Path, script_path: &Path) {
    let script = script_path
        .to_str()
        .expect("script path should be valid utf8")
        .replace('\\', "\\\\");
    let toml = format!(
        r#"schema_version = "franken-engine.lockstep-runtimes.v1"

[[runtimes]]
runtime_id = "node"
display_name = "node flaky adapter"
version_pin = "node@test"
command = "{script}"
args = []

[[runtimes]]
runtime_id = "bun"
display_name = "bun flaky adapter"
version_pin = "bun@test"
command = "{script}"
args = []
"#
    );
    write_runtime_specs_content(path, toml.as_str());
}

fn write_runtime_specs_with_runtime_command(path: &Path, command: &str) {
    let escaped_command = command.replace('\\', "\\\\");
    let toml = format!(
        r#"schema_version = "franken-engine.lockstep-runtimes.v1"

[[runtimes]]
runtime_id = "node"
display_name = "node suffix lookup adapter"
version_pin = "node@test"
command = "{escaped_command}"
args = []

[[runtimes]]
runtime_id = "bun"
display_name = "bun suffix lookup adapter"
version_pin = "bun@test"
command = "{escaped_command}"
args = []
"#
    );
    write_runtime_specs_content(path, toml.as_str());
}

fn runtime_specs_content(expected_hash: &str, runtime_ids: &[&str]) -> String {
    let mut toml = String::from("schema_version = \"franken-engine.lockstep-runtimes.v1\"\n");
    for runtime_id in runtime_ids {
        toml.push_str(
            format!(
                "
[[runtimes]]
runtime_id = \"{runtime_id}\"
display_name = \"{runtime_id} test adapter\"
version_pin = \"{runtime_id}@test\"
command = \"sh\"
args = ['-c', 'cat >/dev/null; echo \"{{\\\"hash\\\":\\\"{expected_hash}\\\"}}\"']
"
            )
            .as_str(),
        );
    }
    toml
}

fn write_script(path: &Path, content: &str) {
    fs::write(path, content).expect("script should be written");
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(path)
            .expect("script metadata should be available")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("script should be executable");
    }
}

fn write_flaky_once_script(path: &Path, counter_path: &Path, expected_hash: &str) {
    let bad_hash = format!("sha256:{:064x}", 0_u8);
    let script = format!(
        r#"#!/bin/sh
set -eu
cat >/dev/null
counter_file='{counter}'
count=0
if [ -f "$counter_file" ]; then
  count=$(cat "$counter_file")
fi
count=$((count + 1))
printf "%s" "$count" > "$counter_file"
if [ "$count" -eq 1 ]; then
  hash="{bad_hash}"
else
  hash="{expected_hash}"
fi
printf '{{"hash":"%s"}}' "$hash"
"#,
        counter = counter_path
            .to_str()
            .expect("counter path should be valid utf8")
            .replace('\'', "'\"'\"'"),
        bad_hash = bad_hash,
        expected_hash = expected_hash,
    );
    write_script(path, script.as_str());
}

fn write_always_flaky_script(path: &Path, counter_path: &Path, expected_hash: &str) {
    let bad_hash = format!("sha256:{:064x}", 1_u8);
    let script = format!(
        r#"#!/bin/sh
set -eu
cat >/dev/null
counter_file='{counter}'
count=0
if [ -f "$counter_file" ]; then
  count=$(cat "$counter_file")
fi
count=$((count + 1))
printf "%s" "$count" > "$counter_file"
if [ $((count % 2)) -eq 0 ]; then
  hash="{expected_hash}"
else
  hash="{bad_hash}"
fi
printf '{{"hash":"%s"}}' "$hash"
"#,
        counter = counter_path
            .to_str()
            .expect("counter path should be valid utf8")
            .replace('\'', "'\"'\"'"),
        expected_hash = expected_hash,
        bad_hash = bad_hash,
    );
    write_script(path, script.as_str());
}

fn write_invalid_schema_runtime_specs(path: &Path) {
    let toml = r#"schema_version = "franken-engine.lockstep-runtimes.v0"

[[runtimes]]
runtime_id = "node"
display_name = "Node.js test adapter"
version_pin = "node@test"
command = "sh"
args = ['-c', 'echo "{\"hash\":\"sha256:invalid\"}"']
"#;
    write_runtime_specs_content(path, toml);
}

fn write_duplicate_runtime_id_specs(path: &Path) {
    let toml = r#"schema_version = "franken-engine.lockstep-runtimes.v1"

[[runtimes]]
runtime_id = "node"
display_name = "Node.js test adapter"
version_pin = "node@test"
command = "sh"
args = ['-c', 'echo "{\"hash\":\"sha256:one\"}"']

[[runtimes]]
runtime_id = "node"
display_name = "Node.js duplicate adapter"
version_pin = "node@duplicate"
command = "sh"
args = ['-c', 'echo "{\"hash\":\"sha256:two\"}"']
"#;
    fs::write(path, toml).expect("runtime spec file should be written");
}

fn write_missing_command_runtime_specs(path: &Path) {
    let toml = r#"schema_version = "franken-engine.lockstep-runtimes.v1"

[[runtimes]]
runtime_id = "node"
display_name = "Node.js missing command"
version_pin = "node@test"
command = "franken_lockstep_missing_runtime_command"
args = []

[[runtimes]]
runtime_id = "bun"
display_name = "Bun shell adapter"
version_pin = "bun@test"
command = "sh"
args = ['-c', 'echo "{\"hash\":\"sha256:abc\"}"']
"#;
    fs::write(path, toml).expect("runtime spec file should be written");
}

fn write_missing_script_runtime_specs(path: &Path) {
    let toml = r#"schema_version = "franken-engine.lockstep-runtimes.v1"

[[runtimes]]
runtime_id = "node"
display_name = "Node.js script-path adapter"
version_pin = "node@test"
command = "sh"
args = ["./scripts/lockstep_runtime_adapter_node_missing.mjs"]

[[runtimes]]
runtime_id = "bun"
display_name = "Bun shell adapter"
version_pin = "bun@test"
command = "sh"
args = ['-c', 'echo "{\"hash\":\"sha256:def\"}"']
"#;
    fs::write(path, toml).expect("runtime spec file should be written");
}

fn write_engine_specs(path: &Path) {
    let payload = serde_json::json!([
        {
            "engine_id": "franken_canonical",
            "display_name": "FrankenEngine Canonical Parser",
            "kind": "franken_canonical",
            "version_pin": "frankenengine-engine@workspace"
        },
        {
            "engine_id": "fixture_expected_hash",
            "display_name": "Fixture Expected Hash Baseline",
            "kind": "fixture_expected_hash",
            "version_pin": "fixture-catalog@phase0-v1"
        }
    ]);
    fs::write(
        path,
        serde_json::to_vec_pretty(&payload).expect("engine spec json should serialize"),
    )
    .expect("engine spec file should write");
}

fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
    let contents = fs::read_to_string(path).expect("jsonl file should exist");
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("jsonl line should parse as json"))
        .collect()
}

#[test]
fn lockstep_runner_help_exits_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .arg("--help")
        .output()
        .expect("help command should execute");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("franken_lockstep_runner"));
    assert!(stdout.contains("--fixture-catalog"));
    assert!(stdout.contains("--runtime-specs"));
    assert!(stdout.contains("--evidence-jsonl"));
    assert!(stdout.contains("--preflight-only"));
}

#[test]
fn lockstep_runner_unknown_argument_exits_nonzero() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .arg("--definitely-unknown")
        .output()
        .expect("command should execute");

    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("unknown argument"));
}

#[test]
fn lockstep_runner_generates_report_with_lockstep_replay_command() {
    let catalog_path = temp_path("franken_lockstep_runner_fixture_catalog", "json");
    let report_path = temp_path("franken_lockstep_runner_report", "json");
    let engine_specs_path = temp_path("franken_lockstep_runner_engine_specs", "json");
    write_fixture_catalog(&catalog_path);
    write_engine_specs(&engine_specs_path);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--fixture-limit",
            "1",
            "--seed",
            "17",
            "--engine-specs",
            engine_specs_path
                .to_str()
                .expect("engine specs path should be valid utf8"),
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report_bytes = fs::read(&report_path).expect("report file should exist");
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report should be valid json");

    assert_eq!(report["fixture_count"].as_u64(), Some(1));
    assert_eq!(report["summary"]["equivalent_fixtures"].as_u64(), Some(1));

    let replay = report["fixture_results"][0]["replay_command"]
        .as_str()
        .expect("replay command should be a string");
    assert!(replay.contains("franken_lockstep_runner"));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(report_path);
    let _ = fs::remove_file(engine_specs_path);
}

#[test]
fn lockstep_runner_loads_runtime_specs_as_external_engines() {
    let catalog_path = temp_path("franken_lockstep_runner_runtime_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_runtime_specs", "toml");
    let report_path = temp_path("franken_lockstep_runner_runtime_report", "json");
    let expected_hash = write_fixture_catalog(&catalog_path);
    write_runtime_specs(&runtime_specs_path, expected_hash.as_str());

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--fixture-limit",
            "1",
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report_bytes = fs::read(&report_path).expect("report file should exist");
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report should be valid json");
    assert_eq!(report["summary"]["equivalent_fixtures"].as_u64(), Some(1));

    let engine_specs = report["engine_specs"]
        .as_array()
        .expect("engine_specs should be an array");
    assert_eq!(engine_specs.len(), 3);
    assert_eq!(
        engine_specs[0]["engine_id"].as_str(),
        Some("franken_canonical")
    );
    assert_eq!(engine_specs[1]["engine_id"].as_str(), Some("node"));
    assert_eq!(engine_specs[1]["version_pin"].as_str(), Some("node@test"));
    assert_eq!(engine_specs[2]["engine_id"].as_str(), Some("bun"));
    assert_eq!(engine_specs[2]["version_pin"].as_str(), Some("bun@test"));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn lockstep_runner_emits_evidence_jsonl_with_deterministic_runtime_order() {
    let catalog_path = temp_path("franken_lockstep_runner_evidence_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_evidence_specs", "toml");
    let report_path = temp_path("franken_lockstep_runner_evidence_report", "json");
    let evidence_path = temp_path("franken_lockstep_runner_evidence", "jsonl");
    let expected_hash = write_fixture_catalog(&catalog_path);
    write_runtime_specs(&runtime_specs_path, expected_hash.as_str());

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--fixture-limit",
            "1",
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
            "--evidence-jsonl",
            evidence_path
                .to_str()
                .expect("evidence path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(&report_path).expect("report should exist for evidence linkage checks"),
    )
    .expect("report should parse");
    let evidence_records = read_jsonl(&evidence_path);
    assert_eq!(evidence_records.len(), 1);
    let evidence = &evidence_records[0];

    assert_eq!(
        evidence["schema_version"].as_str(),
        Some("franken-engine.lockstep-evidence.v1")
    );
    assert_eq!(evidence["run_id"], report["run_id"]);
    assert_eq!(evidence["trace_id"], report["trace_id"]);
    assert_eq!(evidence["decision_id"], report["decision_id"]);
    assert_eq!(evidence["policy_id"], report["policy_id"]);
    assert_eq!(
        evidence["fixture_catalog_hash"],
        report["fixture_catalog_hash"]
    );

    let runtime_versions = evidence["runtime_versions"]
        .as_array()
        .expect("runtime_versions should be an array");
    let runtime_ids = runtime_versions
        .iter()
        .map(|entry| {
            entry["engine_id"]
                .as_str()
                .expect("runtime entry should include engine_id")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        runtime_ids,
        vec!["bun", "franken_canonical", "node"],
        "runtime versions must be sorted deterministically by engine_id"
    );

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
    let _ = fs::remove_file(report_path);
    let _ = fs::remove_file(evidence_path);
}

#[test]
fn lockstep_runner_loads_default_runtime_specs_when_present() {
    let catalog_path = temp_path("franken_lockstep_runner_default_specs_catalog", "json");
    let report_path = temp_path("franken_lockstep_runner_default_specs_report", "json");
    let workdir = temp_dir("franken_lockstep_runner_default_specs_workspace");
    let runtime_specs_path = workdir
        .join("crates")
        .join("franken-engine")
        .join("tests")
        .join("fixtures")
        .join("lockstep_runtimes.toml");
    let runtime_specs_parent = runtime_specs_path
        .parent()
        .expect("runtime specs path should have parent");
    fs::create_dir_all(runtime_specs_parent).expect("runtime specs directory should be created");

    let expected_hash = write_fixture_catalog(&catalog_path);
    write_runtime_specs(&runtime_specs_path, expected_hash.as_str());

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .current_dir(&workdir)
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--fixture-limit",
            "1",
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report_bytes = fs::read(&report_path).expect("report file should exist");
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report should be valid json");
    assert_eq!(report["summary"]["equivalent_fixtures"].as_u64(), Some(1));

    let engine_specs = report["engine_specs"]
        .as_array()
        .expect("engine_specs should be an array");
    assert_eq!(engine_specs.len(), 3);
    assert_eq!(engine_specs[1]["engine_id"].as_str(), Some("node"));
    assert_eq!(engine_specs[2]["engine_id"].as_str(), Some("bun"));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(report_path);
    let _ = fs::remove_dir_all(workdir);
}

#[test]
fn lockstep_runner_rejects_runtime_specs_and_engine_specs_combination() {
    let catalog_path = temp_path("franken_lockstep_runner_runtime_conflict_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_runtime_conflict_specs", "toml");
    let engine_specs_path = temp_path(
        "franken_lockstep_runner_runtime_conflict_engine_specs",
        "json",
    );
    let expected_hash = write_fixture_catalog(&catalog_path);
    write_runtime_specs(&runtime_specs_path, expected_hash.as_str());
    write_engine_specs(&engine_specs_path);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--engine-specs",
            engine_specs_path
                .to_str()
                .expect("engine specs path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("cannot combine --engine-specs with --runtime-specs"));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
    let _ = fs::remove_file(engine_specs_path);
}

#[test]
fn lockstep_runner_rejects_runtime_specs_with_invalid_schema_version() {
    let catalog_path = temp_path("franken_lockstep_runner_invalid_schema_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_invalid_schema_specs", "toml");
    write_fixture_catalog(&catalog_path);
    write_invalid_schema_runtime_specs(&runtime_specs_path);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("schema_version"));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
}

#[test]
fn lockstep_runner_rejects_runtime_specs_with_duplicate_runtime_id() {
    let catalog_path = temp_path(
        "franken_lockstep_runner_duplicate_runtime_id_catalog",
        "json",
    );
    let runtime_specs_path =
        temp_path("franken_lockstep_runner_duplicate_runtime_id_specs", "toml");
    write_fixture_catalog(&catalog_path);
    write_duplicate_runtime_id_specs(&runtime_specs_path);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("appears more than once"));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
}

#[test]
fn lockstep_runner_rejects_runtime_specs_missing_required_runtime_ids() {
    let catalog_path = temp_path(
        "franken_lockstep_runner_missing_required_ids_catalog",
        "json",
    );
    let runtime_specs_path =
        temp_path("franken_lockstep_runner_missing_required_ids_specs", "toml");
    let expected_hash = write_fixture_catalog(&catalog_path);
    write_runtime_specs_with_runtime_ids(&runtime_specs_path, expected_hash.as_str(), &["node"]);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("must include enabled runtime_id entries for bun"));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
}

#[test]
fn lockstep_runner_preflight_only_passes_for_valid_runtime_specs() {
    let catalog_path = temp_path("franken_lockstep_runner_preflight_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_preflight_specs", "toml");
    let expected_hash = write_fixture_catalog(&catalog_path);
    write_runtime_specs(&runtime_specs_path, expected_hash.as_str());

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--preflight-only",
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should contain preflight JSON");
    assert_eq!(
        report["schema_version"].as_str(),
        Some("franken-engine.lockstep-preflight.v1")
    );
    assert_eq!(report["preflight_passed"].as_bool(), Some(true));
    assert_eq!(
        report["checked_external_engines"].as_u64(),
        Some(2),
        "preflight should evaluate both external runtimes"
    );
    assert!(
        report["checks"]
            .as_array()
            .expect("checks should be an array")
            .iter()
            .all(|entry| entry["outcome"] == "pass"),
        "all checks should pass for valid runtime specs"
    );

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
}

#[test]
fn lockstep_runner_preflight_only_accepts_pathext_command_lookup() {
    let catalog_path = temp_path("franken_lockstep_runner_preflight_suffix_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_preflight_suffix_specs", "toml");
    let command_dir = temp_dir("franken_lockstep_runner_preflight_suffix_cmds");
    let command_stem = "franken_lockstep_fake_runtime";
    let command_path = command_dir.join(format!("{command_stem}.exe"));
    write_fixture_catalog(&catalog_path);
    write_runtime_specs_with_runtime_command(&runtime_specs_path, command_stem);
    fs::write(&command_path, b"#!/bin/sh\necho noop\n").expect("command stub should be written");

    let mut combined_paths = vec![command_dir.clone()];
    if let Some(existing_path) = std::env::var_os("PATH") {
        combined_paths.extend(std::env::split_paths(&existing_path));
    }
    let combined_path =
        std::env::join_paths(combined_paths).expect("combined PATH should serialize");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .env("PATH", combined_path)
        .env("PATHEXT", ".EXE;.CMD;.BAT")
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--preflight-only",
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should contain preflight JSON");
    assert_eq!(report["preflight_passed"].as_bool(), Some(true));
    assert_eq!(
        report["checked_external_engines"].as_u64(),
        Some(2),
        "preflight should evaluate both external runtimes"
    );

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
    let _ = fs::remove_file(command_path);
    let _ = fs::remove_dir(command_dir);
}

#[test]
fn lockstep_runner_preflight_only_rejects_missing_command() {
    let catalog_path = temp_path(
        "franken_lockstep_runner_preflight_missing_cmd_catalog",
        "json",
    );
    let runtime_specs_path = temp_path("franken_lockstep_runner_preflight_missing_cmd", "toml");
    write_fixture_catalog(&catalog_path);
    write_missing_command_runtime_specs(&runtime_specs_path);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--preflight-only",
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(4));

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should contain preflight JSON");
    assert_eq!(report["preflight_passed"].as_bool(), Some(false));
    assert_eq!(
        report["error_code"].as_str(),
        Some("FE-LOCKSTEP-PREFLIGHT-0001")
    );
    assert!(
        report["error_message"]
            .as_str()
            .expect("error message should be present")
            .contains("not found in PATH")
    );

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
}

#[test]
fn lockstep_runner_preflight_only_rejects_missing_script_path() {
    let catalog_path = temp_path(
        "franken_lockstep_runner_preflight_missing_script_catalog",
        "json",
    );
    let runtime_specs_path = temp_path(
        "franken_lockstep_runner_preflight_missing_script_specs",
        "toml",
    );
    write_fixture_catalog(&catalog_path);
    write_missing_script_runtime_specs(&runtime_specs_path);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--preflight-only",
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(4));

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should contain preflight JSON");
    assert_eq!(report["preflight_passed"].as_bool(), Some(false));
    assert_eq!(
        report["error_code"].as_str(),
        Some("FE-LOCKSTEP-PREFLIGHT-0002")
    );
    assert!(
        report["error_message"]
            .as_str()
            .expect("error message should be present")
            .contains("expected script path")
    );

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
}

#[test]
fn lockstep_suite_script_contract_tracks_timeout_logs_and_replay_metadata() {
    let script = fs::read_to_string("scripts/run_lockstep_runner_suite.sh")
        .expect("lockstep suite script should be readable");

    for expected in [
        "RCH_EXEC_TIMEOUT_SECONDS",
        "step_logs_dir=\"${run_dir}/step_logs\"",
        "\"rch_timeout_seconds\": ${rch_exec_timeout_seconds}",
        "\"step_logs_dir\": \"${step_logs_dir}\"",
        "remote-exit=missing/process-exit=",
        "timeout=${rch_exec_timeout_seconds}s/process-exit=",
        "./scripts/e2e/lockstep_runner_replay.sh report",
    ] {
        assert!(
            script.contains(expected),
            "suite script should contain contract fragment `{expected}`"
        );
    }
}

#[test]
fn lockstep_replay_wrapper_defaults_to_report_mode() {
    let script = fs::read_to_string("scripts/e2e/lockstep_runner_replay.sh")
        .expect("lockstep replay wrapper should be readable");

    assert!(
        script.contains("mode=\"${1:-report}\""),
        "replay wrapper should default to report mode"
    );
    assert!(
        script.contains("\"${root_dir}/scripts/run_lockstep_runner_suite.sh\" \"${mode}\""),
        "replay wrapper should delegate to the suite script with the selected mode"
    );
}

#[test]
fn lockstep_runner_fails_closed_on_critical_drift_by_default() {
    let catalog_path = temp_path("franken_lockstep_runner_critical_gate_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_critical_gate_specs", "toml");
    write_fixture_catalog(&catalog_path);
    write_runtime_specs_with_expected_hash(
        &runtime_specs_path,
        "sha256:0000000000000000000000000000000000000000000000000000000000000001",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(3));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
}

#[test]
fn lockstep_runner_allows_critical_drift_with_explicit_override() {
    let catalog_path = temp_path("franken_lockstep_runner_allow_critical_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_allow_critical_specs", "toml");
    let report_path = temp_path("franken_lockstep_runner_allow_critical_report", "json");
    let governance_path = temp_path("franken_lockstep_runner_allow_critical_governance", "json");
    write_fixture_catalog(&catalog_path);
    write_runtime_specs_with_expected_hash(
        &runtime_specs_path,
        "sha256:0000000000000000000000000000000000000000000000000000000000000001",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--allow-critical-drift",
            "--governance-actions-out",
            governance_path
                .to_str()
                .expect("governance path should be valid utf8"),
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report should exist"))
            .expect("report should parse");
    assert_eq!(report["summary"]["divergent_fixtures"].as_u64(), Some(1));
    assert_eq!(
        report["summary"]["drift_critical_fixtures"].as_u64(),
        Some(1)
    );

    let governance: serde_json::Value = serde_json::from_slice(
        &fs::read(&governance_path).expect("governance report should exist"),
    )
    .expect("governance report should parse");
    let actions = governance["actions"]
        .as_array()
        .expect("governance actions should be an array");
    assert!(!actions.is_empty());
    assert_eq!(
        actions[0]["severity"].as_str(),
        Some("critical"),
        "critical drift should be routed as critical governance action"
    );
    assert!(actions[0]["owner_hint"].as_str().is_some());

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
    let _ = fs::remove_file(report_path);
    let _ = fs::remove_file(governance_path);
}

#[test]
fn lockstep_runner_retries_flaky_runtime_and_records_retry_metadata() {
    let catalog_path = temp_path("franken_lockstep_runner_retry_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_retry_specs", "toml");
    let report_path = temp_path("franken_lockstep_runner_retry_report", "json");
    let evidence_path = temp_path("franken_lockstep_runner_retry_evidence", "jsonl");
    let script_path = temp_path("franken_lockstep_runner_retry_adapter", "sh");
    let counter_path = temp_path("franken_lockstep_runner_retry_counter", "txt");
    let expected_hash = write_fixture_catalog(&catalog_path);
    write_flaky_once_script(&script_path, &counter_path, expected_hash.as_str());
    write_runtime_specs_using_script(&runtime_specs_path, &script_path);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--max-retries",
            "1",
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
            "--evidence-jsonl",
            evidence_path
                .to_str()
                .expect("evidence path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report should exist"))
            .expect("report should parse");
    assert_eq!(
        report["summary"]["fixtures_with_nondeterminism"].as_u64(),
        Some(0)
    );
    assert_eq!(report["summary"]["equivalent_fixtures"].as_u64(), Some(1));

    let evidence_records = read_jsonl(&evidence_path);
    assert_eq!(evidence_records.len(), 1);
    let evidence = &evidence_records[0];
    assert_eq!(evidence["retry_attempts"].as_u64(), Some(1));
    assert_eq!(evidence["max_retries"].as_u64(), Some(1));
    let observed_flaky_fixture_ids = evidence["observed_flaky_fixture_ids"]
        .as_array()
        .expect("observed_flaky_fixture_ids should be an array");
    assert_eq!(observed_flaky_fixture_ids.len(), 1);
    assert_eq!(
        observed_flaky_fixture_ids[0].as_str(),
        Some("lockstep-fixture-1")
    );

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
    let _ = fs::remove_file(report_path);
    let _ = fs::remove_file(evidence_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_file(counter_path);
}

#[test]
fn lockstep_runner_quarantines_flaky_fixtures_for_divergence_gate() {
    let catalog_path = temp_path("franken_lockstep_runner_quarantine_catalog", "json");
    let runtime_specs_path = temp_path("franken_lockstep_runner_quarantine_specs", "toml");
    let report_path = temp_path("franken_lockstep_runner_quarantine_report", "json");
    let script_path = temp_path("franken_lockstep_runner_quarantine_adapter", "sh");
    let counter_path = temp_path("franken_lockstep_runner_quarantine_counter", "txt");
    let expected_hash = write_fixture_catalog(&catalog_path);
    write_always_flaky_script(&script_path, &counter_path, expected_hash.as_str());
    write_runtime_specs_using_script(&runtime_specs_path, &script_path);

    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            catalog_path
                .to_str()
                .expect("fixture path should be valid utf8"),
            "--runtime-specs",
            runtime_specs_path
                .to_str()
                .expect("runtime specs path should be valid utf8"),
            "--fail-on-divergence",
            "--quarantine-flaky",
            "--allow-critical-drift",
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("lockstep runner should execute");

    assert!(
        output.status.success(),
        "command failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report should exist"))
            .expect("report should parse");
    assert_eq!(
        report["summary"]["fixtures_with_nondeterminism"].as_u64(),
        Some(1)
    );
    assert_eq!(report["summary"]["divergent_fixtures"].as_u64(), Some(1));

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(runtime_specs_path);
    let _ = fs::remove_file(report_path);
    let _ = fs::remove_file(script_path);
    let _ = fs::remove_file(counter_path);
}

#[test]
fn temp_path_produces_unique_paths() {
    let a = temp_path("test", "json");
    let b = temp_path("test", "json");
    assert_ne!(a, b);
}

#[test]
fn temp_dir_creates_directory() {
    let d = temp_dir("lockstep-check");
    assert!(d.is_dir());
    let _ = fs::remove_dir_all(d);
}

#[test]
fn canonical_parser_parses_simple_expression() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42", ParseGoal::Script).expect("parse");
    assert!(!tree.body.is_empty());
}

#[test]
fn write_fixture_catalog_returns_sha256_prefixed_hash() {
    let path = temp_path("franken_lockstep_runner_hash_check_catalog", "json");
    let hash = write_fixture_catalog(&path);
    assert!(
        hash.starts_with("sha256:"),
        "expected sha256 prefix, got {hash}"
    );
    assert!(hash.len() > 10);
    let _ = fs::remove_file(path);
}

#[test]
fn runtime_specs_content_includes_schema_version() {
    let content = runtime_specs_content("sha256:test", &["node", "bun"]);
    assert!(content.contains("franken-engine.lockstep-runtimes.v1"));
    assert!(content.contains("node"));
    assert!(content.contains("bun"));
}

#[test]
fn canonical_parser_hash_is_deterministic() {
    let parser = CanonicalEs2020Parser;
    let h1 = parser
        .parse("42", ParseGoal::Script)
        .expect("parse")
        .canonical_hash();
    let h2 = parser
        .parse("42", ParseGoal::Script)
        .expect("parse")
        .canonical_hash();
    assert_eq!(h1, h2);
}

#[test]
fn write_fixture_catalog_produces_valid_json_with_expected_schema() {
    let path = temp_path("lockstep_catalog_json_check", "json");
    write_fixture_catalog(&path);
    let bytes = fs::read(&path).expect("read fixture catalog");
    let catalog: serde_json::Value =
        serde_json::from_slice(&bytes).expect("fixture catalog must be valid json");
    assert_eq!(
        catalog["schema_version"].as_str(),
        Some("franken-engine.parser-phase0.semantic-fixtures.v1")
    );
    assert!(
        !catalog["fixtures"]
            .as_array()
            .expect("fixtures array")
            .is_empty(),
        "catalog must contain at least one fixture"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn write_engine_specs_produces_array_with_two_entries() {
    let path = temp_path("lockstep_engine_specs_check", "json");
    write_engine_specs(&path);
    let bytes = fs::read(&path).expect("read engine specs");
    let specs: serde_json::Value =
        serde_json::from_slice(&bytes).expect("engine specs must be valid json");
    let arr = specs.as_array().expect("engine specs should be an array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["engine_id"].as_str(), Some("franken_canonical"));
    assert_eq!(arr[1]["engine_id"].as_str(), Some("fixture_expected_hash"));
    let _ = fs::remove_file(path);
}

#[test]
fn read_jsonl_on_empty_file_returns_empty_vec() {
    let path = temp_path("lockstep_empty_jsonl", "jsonl");
    fs::write(&path, "").expect("write empty file");
    let records = read_jsonl(&path);
    assert!(records.is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn read_jsonl_on_single_line_returns_one_record() {
    let path = temp_path("lockstep_single_jsonl", "jsonl");
    fs::write(&path, "{\"key\":\"value\"}\n").expect("write single-line jsonl");
    let records = read_jsonl(&path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["key"].as_str(), Some("value"));
    let _ = fs::remove_file(path);
}

#[test]
fn runtime_specs_content_with_single_runtime_includes_one_block() {
    let content = runtime_specs_content("sha256:abc", &["deno"]);
    assert!(content.contains("franken-engine.lockstep-runtimes.v1"));
    assert!(content.contains("deno"));
    let deno_count = content.matches("runtime_id").count();
    assert_eq!(deno_count, 1, "single runtime should produce one block");
}

#[test]
fn lockstep_runner_missing_fixture_catalog_exits_nonzero() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .args([
            "--fixture-catalog",
            "/tmp/franken_lockstep_nonexistent_catalog_42.json",
        ])
        .output()
        .expect("command should execute");
    assert!(!output.status.success());
}

#[test]
fn fixture_catalog_json_roundtrips_through_serde() {
    let path = temp_path("lockstep_serde_roundtrip_catalog", "json");
    write_fixture_catalog(&path);
    let bytes = fs::read(&path).expect("catalog should be readable");
    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes).expect("catalog should parse as json");
    let reserialized = serde_json::to_vec_pretty(&parsed).expect("reserialization should succeed");
    let reparsed: serde_json::Value =
        serde_json::from_slice(&reserialized).expect("re-parse should succeed");
    assert_eq!(parsed, reparsed, "serde roundtrip must be identity");
    let _ = fs::remove_file(path);
}

#[test]
fn fixture_catalog_fixture_entry_has_expected_field_count() {
    let path = temp_path("lockstep_field_count_catalog", "json");
    write_fixture_catalog(&path);
    let bytes = fs::read(&path).expect("catalog should be readable");
    let catalog: serde_json::Value = serde_json::from_slice(&bytes).expect("catalog should parse");
    let fixture = &catalog["fixtures"][0];
    let obj = fixture.as_object().expect("fixture should be an object");
    assert_eq!(
        obj.len(),
        5,
        "fixture entry should have exactly 5 fields (id, family_id, goal, source, expected_hash)"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn engine_specs_json_roundtrips_through_serde() {
    let path = temp_path("lockstep_engine_specs_serde_roundtrip", "json");
    write_engine_specs(&path);
    let bytes = fs::read(&path).expect("engine specs should be readable");
    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes).expect("engine specs should parse");
    let reserialized = serde_json::to_vec_pretty(&parsed).expect("reserialization should succeed");
    let reparsed: serde_json::Value =
        serde_json::from_slice(&reserialized).expect("re-parse should succeed");
    assert_eq!(parsed, reparsed, "serde roundtrip must be identity");
    let _ = fs::remove_file(path);
}

#[test]
fn engine_specs_entries_each_have_four_fields() {
    let path = temp_path("lockstep_engine_specs_field_count", "json");
    write_engine_specs(&path);
    let bytes = fs::read(&path).expect("engine specs should be readable");
    let specs: serde_json::Value =
        serde_json::from_slice(&bytes).expect("engine specs should parse");
    for entry in specs.as_array().expect("specs should be an array") {
        let obj = entry.as_object().expect("entry should be an object");
        assert_eq!(
            obj.len(),
            4,
            "each engine spec should have 4 fields (engine_id, display_name, kind, version_pin)"
        );
    }
    let _ = fs::remove_file(path);
}

#[test]
fn runtime_specs_content_with_empty_runtime_list_produces_only_header() {
    let content = runtime_specs_content("sha256:test", &[]);
    assert!(content.contains("franken-engine.lockstep-runtimes.v1"));
    assert_eq!(
        content.matches("[[runtimes]]").count(),
        0,
        "empty runtime list should produce no runtime blocks"
    );
}

#[test]
fn runtime_specs_content_with_three_runtimes_produces_three_blocks() {
    let content = runtime_specs_content("sha256:abc", &["node", "bun", "deno"]);
    assert_eq!(
        content.matches("[[runtimes]]").count(),
        3,
        "three runtimes should produce three runtime blocks"
    );
    assert_eq!(
        content.matches("runtime_id").count(),
        3,
        "three runtimes should produce three runtime_id fields"
    );
}

#[test]
fn read_jsonl_on_multiple_lines_returns_all_records() {
    let path = temp_path("lockstep_multi_jsonl", "jsonl");
    let content = "{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n";
    fs::write(&path, content).expect("write multi-line jsonl");
    let records = read_jsonl(&path);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["a"].as_u64(), Some(1));
    assert_eq!(records[1]["b"].as_u64(), Some(2));
    assert_eq!(records[2]["c"].as_u64(), Some(3));
    let _ = fs::remove_file(path);
}

#[test]
fn read_jsonl_ignores_blank_lines_between_records() {
    let path = temp_path("lockstep_blank_lines_jsonl", "jsonl");
    let content = "{\"x\":10}\n\n\n{\"y\":20}\n\n";
    fs::write(&path, content).expect("write jsonl with blank lines");
    let records = read_jsonl(&path);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["x"].as_u64(), Some(10));
    assert_eq!(records[1]["y"].as_u64(), Some(20));
    let _ = fs::remove_file(path);
}

#[test]
fn canonical_parser_different_sources_produce_different_hashes() {
    let parser = CanonicalEs2020Parser;
    let h1 = parser
        .parse("42", ParseGoal::Script)
        .expect("parse")
        .canonical_hash();
    let h2 = parser
        .parse("43", ParseGoal::Script)
        .expect("parse")
        .canonical_hash();
    assert_ne!(h1, h2, "different source must produce different hashes");
}

#[test]
fn lockstep_suite_script_has_no_todo_or_fixme_markers() {
    let script = fs::read_to_string("scripts/run_lockstep_runner_suite.sh")
        .expect("lockstep suite script should be readable");
    let upper = script.to_uppercase();
    assert!(
        !upper.contains("TODO"),
        "suite script should have no TODO markers"
    );
    assert!(
        !upper.contains("FIXME"),
        "suite script should have no FIXME markers"
    );
}

#[test]
fn lockstep_suite_script_mode_variants_are_documented() {
    let script = fs::read_to_string("scripts/run_lockstep_runner_suite.sh")
        .expect("lockstep suite script should be readable");
    for mode_variant in ["check)", "test)", "clippy)", "report)", "ci)"] {
        assert!(
            script.contains(mode_variant),
            "suite script should contain case pattern `{mode_variant}`"
        );
    }
}

#[test]
fn lockstep_suite_script_references_all_artifact_paths() {
    let script = fs::read_to_string("scripts/run_lockstep_runner_suite.sh")
        .expect("lockstep suite script should be readable");
    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "report.json",
        "lockstep_evidence.jsonl",
        "governance_actions.json",
        "repro_packs",
    ] {
        assert!(
            script.contains(artifact),
            "suite script should reference artifact `{artifact}`"
        );
    }
}

#[test]
fn lockstep_replay_wrapper_has_no_todo_or_fixme_markers() {
    let script = fs::read_to_string("scripts/e2e/lockstep_runner_replay.sh")
        .expect("lockstep replay wrapper should be readable");
    let upper = script.to_uppercase();
    assert!(
        !upper.contains("TODO"),
        "replay wrapper should have no TODO markers"
    );
    assert!(
        !upper.contains("FIXME"),
        "replay wrapper should have no FIXME markers"
    );
}

#[test]
fn lockstep_runner_help_lists_all_documented_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
        .arg("--help")
        .output()
        .expect("help command should execute");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    for flag in [
        "--fixture-catalog",
        "--fixture-limit",
        "--fixture-id",
        "--seed",
        "--trace-id",
        "--decision-id",
        "--policy-id",
        "--locale",
        "--timezone",
        "--engine-specs",
        "--runtime-specs",
        "--fail-on-divergence",
        "--allow-critical-drift",
        "--max-retries",
        "--quarantine-flaky",
        "--preflight-only",
        "--out",
        "--evidence-jsonl",
        "--governance-actions-out",
    ] {
        assert!(
            stdout.contains(flag),
            "help output should list flag `{flag}`"
        );
    }
}

#[test]
fn lockstep_runner_report_fields_are_deterministic_across_seeds() {
    let catalog_path = temp_path("lockstep_deterministic_fields_catalog", "json");
    let engine_specs_path = temp_path("lockstep_deterministic_fields_engine_specs", "json");
    let report_path_a = temp_path("lockstep_deterministic_fields_report_a", "json");
    let report_path_b = temp_path("lockstep_deterministic_fields_report_b", "json");
    write_fixture_catalog(&catalog_path);
    write_engine_specs(&engine_specs_path);

    for (seed, report_path) in [("99", &report_path_a), ("99", &report_path_b)] {
        let output = Command::new(env!("CARGO_BIN_EXE_franken_lockstep_runner"))
            .args([
                "--fixture-catalog",
                catalog_path
                    .to_str()
                    .expect("fixture path should be valid utf8"),
                "--fixture-limit",
                "1",
                "--seed",
                seed,
                "--engine-specs",
                engine_specs_path
                    .to_str()
                    .expect("engine specs path should be valid utf8"),
                "--out",
                report_path
                    .to_str()
                    .expect("report path should be valid utf8"),
            ])
            .output()
            .expect("lockstep runner should execute");
        assert!(
            output.status.success(),
            "command failed with stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let report_a: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path_a).expect("report a should exist"))
            .expect("report a should parse");
    let report_b: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path_b).expect("report b should exist"))
            .expect("report b should parse");

    assert_eq!(
        report_a["fixture_count"], report_b["fixture_count"],
        "fixture_count must be deterministic for same seed"
    );
    assert_eq!(
        report_a["summary"]["equivalent_fixtures"], report_b["summary"]["equivalent_fixtures"],
        "equivalent_fixtures must be deterministic for same seed"
    );
    assert_eq!(
        report_a["seed"], report_b["seed"],
        "seed must match across runs"
    );

    let _ = fs::remove_file(catalog_path);
    let _ = fs::remove_file(engine_specs_path);
    let _ = fs::remove_file(report_path_a);
    let _ = fs::remove_file(report_path_b);
}

#[test]
fn lockstep_suite_script_schema_version_matches_manifest_contract() {
    let script = fs::read_to_string("scripts/run_lockstep_runner_suite.sh")
        .expect("lockstep suite script should be readable");
    assert!(
        script.contains("franken-engine.lockstep-runner-suite.run-manifest.v1"),
        "suite script should embed the manifest schema version"
    );
    assert!(
        script.contains("franken-engine.parser-log-event.v1"),
        "suite script should embed the parser log event schema version"
    );
}
