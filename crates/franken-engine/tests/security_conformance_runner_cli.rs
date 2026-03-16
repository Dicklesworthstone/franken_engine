#![forbid(unsafe_code)]
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
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        let unique = format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct CorpusFixture {
    _guard: TestTempDir,
    labels_root: PathBuf,
    output_root: PathBuf,
    observations_jsonl: PathBuf,
    policy_snapshot_hash: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn write_file(path: &Path, content: &str) {
    let parent = path.parent().expect("file has parent");
    fs::create_dir_all(parent).expect("create file parent");
    fs::write(path, content).expect("write file");
}

fn build_fixture() -> CorpusFixture {
    let guard = TestTempDir::new("security-conformance-runner-cli");
    let labels_root = guard.path.join("labels");
    let output_root = guard.path.join("artifacts");
    let observations_jsonl = guard.path.join("observations.jsonl");
    let policy_snapshot_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let benign_rel = PathBuf::from("benign/echo_read/workload_label.toml");
    let malicious_rel = PathBuf::from("malicious/credential_exfil/workload_label.toml");
    let benign_path = labels_root.join(&benign_rel);
    let malicious_path = labels_root.join(&malicious_rel);

    let benign_label = r#"workload_id = "benign-echo-read"
corpus = "benign"
expected_outcome = "allow"
expected_detection_latency_bound_ms = 10
hostcall_sequence_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
semantic_domain = "filesystem/read"
"#;
    let malicious_label = r#"workload_id = "malicious-credential-exfil"
corpus = "malicious"
attack_taxonomy = "exfil"
expected_outcome = "contain"
expected_detection_latency_bound_ms = 25
hostcall_sequence_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
semantic_domain = "network/exfiltration"
"#;

    write_file(&benign_path, benign_label);
    write_file(&malicious_path, malicious_label);

    let benign_hash = sha256_hex(benign_label.as_bytes());
    let malicious_hash = sha256_hex(malicious_label.as_bytes());
    let manifest = format!(
        r#"schema_version = "franken-engine.security-conformance-corpus-manifest.v1"
corpus_version = "v1"
generated_at_utc = "2026-03-02T00:00:00Z"

[[entries]]
workload_id = "benign-echo-read"
corpus = "benign"
label_path = "{benign_rel}"
label_sha256 = "{benign_hash}"

[[entries]]
workload_id = "malicious-credential-exfil"
corpus = "malicious"
label_path = "{malicious_rel}"
label_sha256 = "{malicious_hash}"
"#,
        benign_rel = benign_rel.display(),
        benign_hash = benign_hash,
        malicious_rel = malicious_rel.display(),
        malicious_hash = malicious_hash,
    );
    write_file(&labels_root.join("corpus_manifest.toml"), &manifest);

    let observations = [
        json!({
            "workload_id": "benign-echo-read",
            "actual_outcome": "allow",
            "detection_latency_us": 4000,
            "sentinel_posterior": 0.02,
            "policy_action": "allow",
            "containment_action": "none",
            "error_code": Value::Null
        }),
        json!({
            "workload_id": "malicious-credential-exfil",
            "actual_outcome": "contain",
            "detection_latency_us": 15000,
            "sentinel_posterior": 0.99,
            "policy_action": "contain",
            "containment_action": "sandbox",
            "error_code": Value::Null
        }),
    ];
    let mut observations_text = String::new();
    for observation in observations {
        observations_text.push_str(
            &serde_json::to_string(&observation).expect("serialize security observation"),
        );
        observations_text.push('\n');
    }
    write_file(&observations_jsonl, &observations_text);

    CorpusFixture {
        _guard: guard,
        labels_root,
        output_root,
        observations_jsonl,
        policy_snapshot_hash: policy_snapshot_hash.to_string(),
    }
}

fn runner_command(fixture: &CorpusFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_franken_security_conformance_runner"));
    command
        .arg("--labels-root")
        .arg(&fixture.labels_root)
        .arg("--output-root")
        .arg(&fixture.output_root)
        .arg("--observations-jsonl")
        .arg(&fixture.observations_jsonl)
        .arg("--policy-snapshot-hash")
        .arg(&fixture.policy_snapshot_hash);
    command
}

fn parse_evidence_path(stdout: &str) -> PathBuf {
    let evidence_line = stdout
        .lines()
        .find(|line| line.starts_with("security evidence="))
        .expect("runner should print security evidence path");
    PathBuf::from(
        evidence_line
            .trim_start_matches("security evidence=")
            .trim(),
    )
}

fn normalize_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .expect("current dir")
            .join(path)
            .to_path_buf()
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn runner_writes_summary_and_workload_evidence_lines() {
    let fixture = build_fixture();
    let output = runner_command(&fixture)
        .arg("--allow-small-corpus")
        .output()
        .expect("run security conformance runner");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let evidence_path = normalize_path(parse_evidence_path(&stdout));
    assert!(
        evidence_path.exists(),
        "missing evidence: {}",
        evidence_path.display()
    );

    let evidence_text = fs::read_to_string(&evidence_path).expect("read evidence");
    let evidence_lines = evidence_text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("parse JSONL line"))
        .collect::<Vec<_>>();
    assert_eq!(
        evidence_lines.len(),
        3,
        "expect 1 summary + 2 workload lines"
    );

    let summary = &evidence_lines[0];
    assert_eq!(
        summary["schema_version"],
        "franken-engine.security-conformance-evidence.v1"
    );
    assert_eq!(summary["component"], "security_conformance_runner");
    assert_eq!(summary["event"], "summary");
    // With a tiny corpus (enabled only by --allow-small-corpus), CI bounds are
    // intentionally strict and the aggregate gate should fail closed.
    assert_eq!(summary["outcome"], "fail");
    assert_eq!(
        summary["policy_snapshot_hash"],
        fixture.policy_snapshot_hash
    );
    assert_eq!(summary["error_code"], "FE-SECURITY-CONFORMANCE-GATE");
    assert!(
        summary["gate_failure_reasons"]
            .as_array()
            .expect("summary gate_failure_reasons array")
            .iter()
            .any(|reason| reason.as_str().unwrap_or_default().contains("TPR")),
        "expected TPR-related gate failure in tiny-corpus run: {:?}",
        summary["gate_failure_reasons"]
    );
    assert!(
        summary["trace_id"]
            .as_str()
            .expect("summary trace_id")
            .starts_with("trace-")
    );

    let workload_lines = &evidence_lines[1..];
    for workload in workload_lines {
        assert_eq!(workload["event"], "workload_result");
        assert_eq!(workload["component"], "security_conformance_runner");
        assert_eq!(workload["outcome"], "pass");
        assert!(
            workload["trace_id"]
                .as_str()
                .expect("workload trace_id")
                .starts_with("trace-")
        );
    }
}

#[test]
fn runner_can_fail_closed_after_emitting_red_evidence() {
    let fixture = build_fixture();
    let output = runner_command(&fixture)
        .arg("--allow-small-corpus")
        .arg("--fail-on-gate-failure")
        .output()
        .expect("run security conformance runner");
    assert!(
        !output.status.success(),
        "runner unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let evidence_path = normalize_path(parse_evidence_path(&stdout));
    assert!(
        evidence_path.exists(),
        "missing evidence after fail-closed run: {}",
        evidence_path.display()
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("security conformance gate failed"),
        "stderr missing fail-closed message:\n{stderr}"
    );

    let evidence_text = fs::read_to_string(&evidence_path).expect("read evidence");
    let summary: Value = serde_json::from_str(
        evidence_text
            .lines()
            .next()
            .expect("summary line present in evidence"),
    )
    .expect("parse summary line");
    assert_eq!(summary["event"], "summary");
    assert_eq!(summary["outcome"], "fail");
    assert!(
        summary["gate_failure_reasons"]
            .as_array()
            .expect("gate failure reasons array")
            .iter()
            .any(|reason| reason.as_str().unwrap_or_default().contains("TPR")),
        "expected TPR-related failure reasons in summary: {:?}",
        summary["gate_failure_reasons"]
    );
}

#[test]
fn runner_fails_without_allow_small_corpus_flag() {
    let fixture = build_fixture();
    let output = runner_command(&fixture)
        .output()
        .expect("run security conformance runner");
    assert!(
        !output.status.success(),
        "runner unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("security corpus size below release thresholds"),
        "stderr missing threshold failure message:\n{stderr}"
    );
}

#[test]
fn runner_fails_on_manifest_hash_tamper() {
    let fixture = build_fixture();
    let tampered_manifest = r#"schema_version = "franken-engine.security-conformance-corpus-manifest.v1"
corpus_version = "v1"
generated_at_utc = "2026-03-02T00:00:00Z"

[[entries]]
workload_id = "benign-echo-read"
corpus = "benign"
label_path = "benign/echo_read/workload_label.toml"
label_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

[[entries]]
workload_id = "malicious-credential-exfil"
corpus = "malicious"
label_path = "malicious/credential_exfil/workload_label.toml"
label_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
"#;
    write_file(
        &fixture.labels_root.join("corpus_manifest.toml"),
        tampered_manifest,
    );

    let output = runner_command(&fixture)
        .arg("--allow-small-corpus")
        .output()
        .expect("run security conformance runner");
    assert!(
        !output.status.success(),
        "runner unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("ManifestLabelHashMismatch")
            || stderr.contains("corpus manifest hash mismatch"),
        "stderr missing manifest mismatch:\n{stderr}"
    );
}

// ---------- sha256_hex ----------

#[test]
fn sha256_hex_deterministic() {
    let a = sha256_hex(b"hello world");
    let b = sha256_hex(b"hello world");
    assert_eq!(a, b);
}

#[test]
fn sha256_hex_different_inputs_differ() {
    assert_ne!(sha256_hex(b"hello"), sha256_hex(b"world"));
}

#[test]
fn sha256_hex_empty_input() {
    let result = sha256_hex(b"");
    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn sha256_hex_known_value() {
    // SHA-256 of empty string is well-known
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(sha256_hex(b""), expected);
}

// ---------- parse_evidence_path ----------

#[test]
fn parse_evidence_path_extracts_path() {
    let stdout = "some output\nsecurity evidence=/tmp/evidence.jsonl\nmore output\n";
    let path = parse_evidence_path(stdout);
    assert_eq!(path, PathBuf::from("/tmp/evidence.jsonl"));
}

// ---------- normalize_path ----------

#[test]
fn normalize_path_absolute_stays_absolute() {
    let path = PathBuf::from("/absolute/path");
    let result = normalize_path(path.clone());
    assert_eq!(result, path);
}

#[test]
fn normalize_path_relative_becomes_absolute() {
    let path = PathBuf::from("relative/path");
    let result = normalize_path(path);
    assert!(result.is_absolute());
}

// ---------- TestTempDir ----------

#[test]
fn test_temp_dir_creates_directory() {
    let guard = TestTempDir::new("temp-dir-test");
    assert!(guard.path.exists());
    assert!(guard.path.is_dir());
}

#[test]
fn test_temp_dir_unique_paths() {
    let a = TestTempDir::new("uniq-a");
    let b = TestTempDir::new("uniq-b");
    assert_ne!(a.path, b.path);
}

// ---------- write_file ----------

#[test]
fn write_file_creates_and_writes() {
    let guard = TestTempDir::new("write-file-test");
    let path = guard.path.join("subdir/test.txt");
    write_file(&path, "hello");
    assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
}

// ---------- build_fixture ----------

#[test]
fn build_fixture_creates_corpus_manifest() {
    let fixture = build_fixture();
    let manifest_path = fixture.labels_root.join("corpus_manifest.toml");
    assert!(manifest_path.exists());
    let content = fs::read_to_string(&manifest_path).unwrap();
    assert!(content.contains("franken-engine.security-conformance-corpus-manifest.v1"));
}

#[test]
fn build_fixture_creates_observations_jsonl() {
    let fixture = build_fixture();
    assert!(fixture.observations_jsonl.exists());
    let content = fs::read_to_string(&fixture.observations_jsonl).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2);
}

// ---------- fixture labels are valid TOML ----------

#[test]
fn build_fixture_labels_are_valid_toml() {
    let fixture = build_fixture();
    let benign_label = fixture
        .labels_root
        .join("benign/echo_read/workload_label.toml");
    let content = fs::read_to_string(&benign_label).unwrap();
    let parsed: toml::Value = toml::from_str(&content).expect("valid toml");
    assert_eq!(parsed["workload_id"].as_str(), Some("benign-echo-read"));
}

// ---------- fixture observations are valid JSON ----------

#[test]
fn build_fixture_observations_are_valid_json() {
    let fixture = build_fixture();
    let content = fs::read_to_string(&fixture.observations_jsonl).unwrap();
    for line in content.lines() {
        let parsed: Value = serde_json::from_str(line).expect("valid JSON");
        assert!(parsed["workload_id"].as_str().is_some());
    }
}

// ---------- policy snapshot hash has expected length ----------

#[test]
fn build_fixture_policy_hash_has_correct_length() {
    let fixture = build_fixture();
    assert_eq!(fixture.policy_snapshot_hash.len(), 64);
    assert!(
        fixture
            .policy_snapshot_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    );
}

#[test]
fn sha256_hex_produces_64_char_string() {
    let hash = sha256_hex(b"test data");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn sha256_hex_is_deterministic() {
    let a = sha256_hex(b"deterministic");
    let b = sha256_hex(b"deterministic");
    assert_eq!(a, b);
}

#[test]
fn sha256_hex_distinct_inputs_produce_distinct_hashes() {
    let a = sha256_hex(b"input-alpha");
    let b = sha256_hex(b"input-beta");
    assert_ne!(a, b);
}

#[test]
fn build_fixture_malicious_label_is_valid_toml() {
    let fixture = build_fixture();
    let malicious_label = fixture
        .labels_root
        .join("malicious/credential_exfil/workload_label.toml");
    let content = fs::read_to_string(&malicious_label).unwrap();
    let parsed: toml::Value = toml::from_str(&content).expect("valid toml");
    assert_eq!(
        parsed["workload_id"].as_str(),
        Some("malicious-credential-exfil")
    );
}

#[test]
fn sha256_hex_is_lowercase_hex_only() {
    let hash = sha256_hex(b"lowercase check");
    assert!(
        hash.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    );
}

#[test]
fn write_file_overwrites_existing_content() {
    let guard = TestTempDir::new("overwrite-test");
    let path = guard.path.join("overwrite.txt");
    write_file(&path, "first");
    write_file(&path, "second");
    assert_eq!(fs::read_to_string(&path).unwrap(), "second");
}

#[test]
fn sha256_hex_single_byte() {
    let hash = sha256_hex(&[0x42]);
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    // Different from empty
    assert_ne!(hash, sha256_hex(b""));
}

#[test]
fn normalize_path_absolute_with_trailing_component() {
    let path = PathBuf::from("/foo/bar/baz.json");
    let result = normalize_path(path.clone());
    assert_eq!(result, path);
    assert!(result.is_absolute());
}

#[test]
fn parse_evidence_path_ignores_other_lines() {
    let stdout =
        "info: initializing\nstatus: ok\nsecurity evidence=/output/evidence.jsonl\ndone.\n";
    let path = parse_evidence_path(stdout);
    assert_eq!(path, PathBuf::from("/output/evidence.jsonl"));
}

#[test]
fn test_temp_dir_cleaned_on_drop() {
    let path_copy;
    {
        let guard = TestTempDir::new("drop-test");
        path_copy = guard.path.clone();
        assert!(path_copy.exists());
    }
    // After drop, directory should be removed
    assert!(!path_copy.exists());
}

#[test]
fn build_fixture_benign_label_contains_expected_fields() {
    let fixture = build_fixture();
    let benign_path = fixture
        .labels_root
        .join("benign/echo_read/workload_label.toml");
    let content = fs::read_to_string(&benign_path).unwrap();
    assert!(content.contains("corpus = \"benign\""));
    assert!(content.contains("expected_outcome = \"allow\""));
    assert!(content.contains("semantic_domain"));
}

#[test]
fn build_fixture_malicious_label_contains_attack_taxonomy() {
    let fixture = build_fixture();
    let malicious_path = fixture
        .labels_root
        .join("malicious/credential_exfil/workload_label.toml");
    let content = fs::read_to_string(&malicious_path).unwrap();
    assert!(content.contains("attack_taxonomy = \"exfil\""));
    assert!(content.contains("corpus = \"malicious\""));
}

#[test]
fn build_fixture_observations_contain_both_workloads() {
    let fixture = build_fixture();
    let content = fs::read_to_string(&fixture.observations_jsonl).unwrap();
    assert!(content.contains("benign-echo-read"));
    assert!(content.contains("malicious-credential-exfil"));
}

#[test]
fn security_conformance_suite_script_uses_replay_wrapper_contract() {
    let script = fs::read_to_string(repo_root().join("scripts/run_security_conformance_runner.sh"))
        .expect("security conformance suite script should be readable");

    for expected in [
        "replay_command=\"./scripts/e2e/security_conformance_runner_replay.sh ${mode}\"",
        "\"cat \" + $manifest",
        "\"cat \" + $events",
        "\"cat \" + $commands",
        "\"cat \" + $stdout",
        "\"ls -R \" + $output_root",
        "$replay",
    ] {
        assert!(
            script.contains(expected),
            "suite script should contain contract fragment `{expected}`"
        );
    }
}

#[test]
fn security_conformance_replay_wrapper_defaults_to_run_mode() {
    let script =
        fs::read_to_string(repo_root().join("scripts/e2e/security_conformance_runner_replay.sh"))
            .expect("security conformance replay wrapper should be readable");

    assert!(
        script.contains("mode=\"${1:-run}\""),
        "replay wrapper should default to run mode"
    );
    assert!(
        script.contains("\"${root_dir}/scripts/run_security_conformance_runner.sh\" \"${mode}\""),
        "replay wrapper should delegate to the suite script with the selected mode"
    );
}

#[test]
fn security_conformance_replay_wrapper_selects_latest_complete_bundle() {
    let script =
        fs::read_to_string(repo_root().join("scripts/e2e/security_conformance_runner_replay.sh"))
            .expect("security conformance replay wrapper should be readable");

    for expected in [
        "latest_complete_run_dir()",
        "\"${candidate}/run_manifest.json\"",
        "\"${candidate}/events.jsonl\"",
        "\"${candidate}/commands.txt\"",
        "\"${candidate}/runner.stdout.log\"",
        "latest_artifact_dir_path",
        "newest directory ${latest_artifact_dir_path} is incomplete",
        "using latest complete run directory ${latest_run_dir}",
        "missing_bundle_exit_code",
    ] {
        assert!(
            script.contains(expected),
            "replay wrapper should contain complete-bundle contract fragment `{expected}`"
        );
    }
}

#[test]
fn security_conformance_replay_wrapper_prints_canonical_artifacts() {
    let script =
        fs::read_to_string(repo_root().join("scripts/e2e/security_conformance_runner_replay.sh"))
            .expect("security conformance replay wrapper should be readable");

    for expected in [
        "[security-conformance] latest manifest:",
        "cat \"${latest_run_dir}/run_manifest.json\"",
        "[security-conformance] latest events:",
        "cat \"${latest_run_dir}/events.jsonl\"",
        "[security-conformance] latest commands:",
        "cat \"${latest_run_dir}/commands.txt\"",
        "[security-conformance] latest runner stdout:",
        "cat \"${latest_run_dir}/runner.stdout.log\"",
        "[security-conformance] latest runner output tree:",
        "ls -R \"${runner_output_dir}\"",
    ] {
        assert!(
            script.contains(expected),
            "replay wrapper should print canonical artifact fragment `{expected}`"
        );
    }
}

// ---------- sha256_hex edge cases ----------

#[test]
fn sha256_hex_all_zeros_byte() {
    let hash = sha256_hex(&[0x00]);
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    // Must differ from empty-input hash
    assert_ne!(hash, sha256_hex(b""));
}

#[test]
fn sha256_hex_large_input() {
    let input = vec![0xABu8; 1024];
    let hash = sha256_hex(&input);
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn sha256_hex_differs_by_single_bit_flip() {
    let base = b"security conformance test payload";
    let mut flipped = base.to_vec();
    flipped[0] ^= 0x01;
    assert_ne!(sha256_hex(base), sha256_hex(&flipped));
}

#[test]
fn sha256_hex_output_is_all_lowercase() {
    // No uppercase hex digits — verify lowercase invariant for all printable ASCII
    for byte in 32u8..=126u8 {
        let hash = sha256_hex(&[byte]);
        assert!(
            hash.chars().all(|c| !c.is_ascii_uppercase()),
            "sha256_hex produced uppercase character for input byte {byte:#04x}: {hash}"
        );
    }
}

#[test]
fn sha256_hex_binary_input_stable() {
    let input = [0x00u8, 0xFF, 0x80, 0x7F, 0x01, 0xFE];
    let first = sha256_hex(&input);
    let second = sha256_hex(&input);
    assert_eq!(first, second);
}

// ---------- parse_evidence_path edge cases ----------

#[test]
fn parse_evidence_path_first_matching_line_wins() {
    // Only the first matching line should be used
    let stdout = "security evidence=/first/path.jsonl\nsecurity evidence=/second/path.jsonl\n";
    let path = parse_evidence_path(stdout);
    assert_eq!(path, PathBuf::from("/first/path.jsonl"));
}

#[test]
fn parse_evidence_path_trims_trailing_whitespace() {
    let stdout = "security evidence=/tmp/trimmed.jsonl   \n";
    let path = parse_evidence_path(stdout);
    assert_eq!(path, PathBuf::from("/tmp/trimmed.jsonl"));
}

#[test]
fn parse_evidence_path_nested_directory() {
    let stdout = "prelude\nsecurity evidence=/a/b/c/evidence.jsonl\n";
    let path = parse_evidence_path(stdout);
    assert_eq!(path, PathBuf::from("/a/b/c/evidence.jsonl"));
}

// ---------- normalize_path edge cases ----------

#[test]
fn normalize_path_deeply_nested_absolute() {
    let path = PathBuf::from("/a/b/c/d/e/f.jsonl");
    let result = normalize_path(path.clone());
    assert_eq!(result, path);
    assert!(result.is_absolute());
}

#[test]
fn normalize_path_preserves_extension() {
    let path = PathBuf::from("/outputs/evidence.jsonl");
    let result = normalize_path(path.clone());
    assert_eq!(result.extension().and_then(|e| e.to_str()), Some("jsonl"));
}

// ---------- TestTempDir ----------

#[test]
fn test_temp_dir_counter_increments_across_instances() {
    let a = TestTempDir::new("counter-check");
    let b = TestTempDir::new("counter-check");
    // Paths must be different even with identical prefix
    assert_ne!(a.path, b.path);
}

#[test]
fn test_temp_dir_subdirectory_can_be_created() {
    let guard = TestTempDir::new("subdir-test");
    let sub = guard.path.join("nested").join("level");
    fs::create_dir_all(&sub).expect("create nested subdirectory");
    assert!(sub.exists() && sub.is_dir());
}

// ---------- write_file ----------

#[test]
fn write_file_deeply_nested_path() {
    let guard = TestTempDir::new("deep-write");
    let path = guard.path.join("a/b/c/d/test.txt");
    write_file(&path, "deep content");
    assert_eq!(fs::read_to_string(&path).unwrap(), "deep content");
}

#[test]
fn write_file_empty_content() {
    let guard = TestTempDir::new("empty-write");
    let path = guard.path.join("empty.txt");
    write_file(&path, "");
    assert_eq!(fs::read_to_string(&path).unwrap(), "");
}

// ---------- build_fixture ----------

#[test]
fn build_fixture_benign_label_has_valid_hostcall_hash() {
    let fixture = build_fixture();
    let benign_path = fixture
        .labels_root
        .join("benign/echo_read/workload_label.toml");
    let content = fs::read_to_string(&benign_path).unwrap();
    let parsed: toml::Value = toml::from_str(&content).expect("valid toml");
    let hash = parsed["hostcall_sequence_hash"]
        .as_str()
        .expect("hostcall_sequence_hash present");
    assert_eq!(hash.len(), 64, "hostcall_sequence_hash must be 64 chars");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "hostcall_sequence_hash must be hex"
    );
}

#[test]
fn build_fixture_malicious_label_has_valid_latency_bound() {
    let fixture = build_fixture();
    let malicious_path = fixture
        .labels_root
        .join("malicious/credential_exfil/workload_label.toml");
    let content = fs::read_to_string(&malicious_path).unwrap();
    let parsed: toml::Value = toml::from_str(&content).expect("valid toml");
    let latency_bound = parsed["expected_detection_latency_bound_ms"]
        .as_integer()
        .expect("expected_detection_latency_bound_ms present");
    assert!(
        latency_bound > 0,
        "detection latency bound must be positive"
    );
}

#[test]
fn build_fixture_observations_each_have_sentinel_posterior() {
    let fixture = build_fixture();
    let content = fs::read_to_string(&fixture.observations_jsonl).unwrap();
    for line in content.lines() {
        let parsed: Value = serde_json::from_str(line).expect("valid JSON");
        let posterior = parsed["sentinel_posterior"]
            .as_f64()
            .expect("sentinel_posterior present");
        assert!(
            (0.0..=1.0).contains(&posterior),
            "sentinel_posterior {posterior} out of [0,1] for line: {line}"
        );
    }
}

#[test]
fn build_fixture_observations_have_non_null_actual_outcome() {
    let fixture = build_fixture();
    let content = fs::read_to_string(&fixture.observations_jsonl).unwrap();
    for line in content.lines() {
        let parsed: Value = serde_json::from_str(line).expect("valid JSON");
        assert!(
            parsed["actual_outcome"].is_string(),
            "actual_outcome must be a string in: {line}"
        );
    }
}

#[test]
fn build_fixture_manifest_lists_both_corpus_types() {
    let fixture = build_fixture();
    let manifest_path = fixture.labels_root.join("corpus_manifest.toml");
    let content = fs::read_to_string(&manifest_path).unwrap();
    // Both corpora represented
    assert!(
        content.contains("corpus = \"benign\""),
        "manifest missing benign corpus entry"
    );
    assert!(
        content.contains("corpus = \"malicious\""),
        "manifest missing malicious corpus entry"
    );
}

#[test]
fn build_fixture_output_root_distinct_from_labels_root() {
    let fixture = build_fixture();
    assert_ne!(
        fixture.output_root, fixture.labels_root,
        "output_root and labels_root must be distinct paths"
    );
}

#[test]
fn sha256_hex_two_consecutive_calls_same_slice_agree() {
    let data = b"consensus check payload";
    let h1 = sha256_hex(data);
    let h2 = sha256_hex(data);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
}

#[test]
fn build_fixture_benign_label_detection_latency_nonzero() {
    let fixture = build_fixture();
    let benign_path = fixture
        .labels_root
        .join("benign/echo_read/workload_label.toml");
    let content = fs::read_to_string(&benign_path).unwrap();
    let parsed: toml::Value = toml::from_str(&content).expect("valid toml");
    let bound = parsed["expected_detection_latency_bound_ms"]
        .as_integer()
        .expect("field present");
    assert!(bound > 0, "benign latency bound must be positive");
}

#[test]
fn build_fixture_policy_hash_is_hex_only() {
    let fixture = build_fixture();
    assert!(
        fixture
            .policy_snapshot_hash
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "policy_snapshot_hash must contain only hex digits"
    );
}

#[test]
fn runner_outputs_security_evidence_path_on_stdout() {
    let fixture = build_fixture();
    let output = runner_command(&fixture)
        .arg("--allow-small-corpus")
        .output()
        .expect("run security conformance runner");
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(
        stdout.lines().any(|l| l.starts_with("security evidence=")),
        "stdout must contain 'security evidence=...' line"
    );
}
