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
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/adversarial_campaign_gate_input_v1.json")
}

fn unique_temp_path(prefix: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{now}.json", std::process::id()))
}

#[test]
fn suppression_gate_cli_passes_with_fixture_input_and_writes_report() {
    let out_path = unique_temp_path("franken-adv-gate-pass");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_adversarial_campaign_gate"))
        .arg("--input")
        .arg(fixture_path())
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("should execute suppression gate CLI");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid json report");
    assert_eq!(
        stdout_json["schema_version"],
        "franken-engine.adversarial-campaign-gate-report.v1"
    );
    assert_eq!(
        stdout_json["result"]["passed"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(
        stdout_json["result"]["release_candidate_id"],
        "rc-adversarial-gate-v1"
    );

    let report_bytes = fs::read(&out_path).expect("report should be written");
    let report_json: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report file should be valid json");
    assert_eq!(
        report_json["result"]["passed"],
        serde_json::Value::Bool(true)
    );

    let _ = fs::remove_file(out_path);
}

#[test]
fn suppression_gate_cli_returns_exit_two_when_gate_fails() {
    let mut input_json: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture_path()).expect("fixture should be readable"))
            .expect("fixture JSON should parse");

    input_json["continuous_run"] = serde_json::Value::Bool(false);
    input_json["trend_points"] = serde_json::json!([
      {
        "release_candidate_id": "rc-only-one",
        "timestamp_ns": 1700000000000000000u64,
        "samples_evaluated": 1500u64
      }
    ]);

    let failing_input_path = unique_temp_path("franken-adv-gate-fail-input");
    fs::write(
        &failing_input_path,
        serde_json::to_vec_pretty(&input_json).expect("failing input should encode"),
    )
    .expect("failing input should be writable");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_adversarial_campaign_gate"))
        .arg("--input")
        .arg(&failing_input_path)
        .output()
        .expect("should execute suppression gate CLI");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected gate-failure exit code, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid json report");
    assert_eq!(
        stdout_json["result"]["passed"],
        serde_json::Value::Bool(false)
    );
    assert!(
        stdout_json["result"]["failures"]
            .as_array()
            .is_some_and(|failures| !failures.is_empty())
    );

    let _ = fs::remove_file(failing_input_path);
}

#[test]
fn adversarial_gate_fixture_exists_and_parses() {
    let path = fixture_path();
    let bytes = fs::read(&path)
        .unwrap_or_else(|err| panic!("cannot read fixture at {}: {err}", path.display()));
    let fixture: serde_json::Value =
        serde_json::from_slice(&bytes).expect("fixture must be valid JSON");
    assert!(fixture.is_object(), "fixture must be a JSON object");
}

#[test]
fn adversarial_gate_fixture_has_required_top_level_fields() {
    let path = fixture_path();
    let fixture: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read fixture"))
            .expect("parse fixture JSON");
    let obj = fixture.as_object().expect("fixture must be object");
    for key in [
        "release_candidate_id",
        "continuous_run",
        "trend_points",
        "samples",
    ] {
        assert!(
            obj.contains_key(key),
            "fixture missing required field: {key}"
        );
    }
}

#[test]
fn adversarial_gate_unique_temp_path_produces_unique_paths() {
    let a = unique_temp_path("test-unique-a");
    let b = unique_temp_path("test-unique-b");
    assert_ne!(a, b);
    assert!(a.to_string_lossy().contains("test-unique-a"));
    assert!(b.to_string_lossy().contains("test-unique-b"));
}

#[test]
fn adversarial_gate_unique_temp_path_is_in_temp_dir() {
    let path = unique_temp_path("test-temp-check");
    let temp = std::env::temp_dir();
    assert!(
        path.starts_with(&temp),
        "temp path should be under system temp dir"
    );
}

#[test]
fn adversarial_gate_fixture_trend_points_are_nonempty() {
    let path = fixture_path();
    let fixture: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read fixture"))
            .expect("parse fixture JSON");
    let trend_points = fixture["trend_points"]
        .as_array()
        .expect("trend_points must be array");
    assert!(
        !trend_points.is_empty(),
        "fixture trend_points must not be empty"
    );
    for point in trend_points {
        assert!(
            point["release_candidate_id"].is_string(),
            "trend point must have release_candidate_id"
        );
        assert!(
            point["timestamp_ns"].is_number(),
            "trend point must have timestamp_ns"
        );
        assert!(
            point["samples_evaluated"].is_number(),
            "trend point must have samples_evaluated"
        );
    }
}

#[test]
fn adversarial_gate_fixture_samples_are_nonempty() {
    let path = fixture_path();
    let fixture: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read fixture"))
            .expect("parse fixture JSON");
    let samples = fixture["samples"]
        .as_array()
        .expect("samples must be array");
    assert!(!samples.is_empty(), "fixture samples must not be empty");
}

#[test]
fn adversarial_gate_fixture_release_candidate_id_is_nonempty_string() {
    let path = fixture_path();
    let fixture: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read fixture"))
            .expect("parse fixture JSON");
    let rc_id = fixture["release_candidate_id"]
        .as_str()
        .expect("release_candidate_id must be a string");
    assert!(
        !rc_id.trim().is_empty(),
        "release_candidate_id must not be empty"
    );
}

#[test]
fn adversarial_gate_fixture_continuous_run_is_boolean() {
    let path = fixture_path();
    let fixture: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read fixture"))
            .expect("parse fixture JSON");
    assert!(
        fixture["continuous_run"].is_boolean(),
        "continuous_run must be a boolean"
    );
}

#[test]
fn adversarial_gate_fixture_deterministic_double_parse() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let a: serde_json::Value = serde_json::from_slice(&bytes).expect("parse first");
    let b: serde_json::Value = serde_json::from_slice(&bytes).expect("parse second");
    assert_eq!(a, b);
}

#[test]
fn adversarial_gate_fixture_samples_have_expected_fields() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let samples = fixture["samples"]
        .as_array()
        .expect("samples must be array");
    for sample in samples {
        assert!(
            sample["campaign_id"].is_string(),
            "sample must have campaign_id"
        );
        assert!(
            sample["attack_category"].is_string(),
            "sample must have attack_category"
        );
        assert!(
            sample["attempt_count"].is_number(),
            "sample must have attempt_count"
        );
    }
}

#[test]
fn adversarial_gate_fixture_has_escalations_field() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    assert!(
        fixture.get("escalations").is_some(),
        "fixture must have escalations field"
    );
}

#[test]
fn adversarial_gate_fixture_all_samples_have_raw_log_ref() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let samples = fixture["samples"].as_array().expect("samples array");
    for sample in samples {
        assert!(
            sample["raw_log_ref"].is_string(),
            "sample must have raw_log_ref"
        );
    }
}

#[test]
fn adversarial_gate_fixture_all_trend_points_have_positive_timestamp() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let points = fixture["trend_points"]
        .as_array()
        .expect("trend_points array");
    for point in points {
        assert!(
            point["timestamp_ns"].as_u64().unwrap_or(0) > 0,
            "timestamp must be positive"
        );
    }
}

#[test]
fn adversarial_gate_fixture_is_a_json_object() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    assert!(fixture.is_object());
    assert!(fixture.as_object().unwrap().len() >= 4);
}

#[test]
fn adversarial_gate_fixture_escalations_is_array() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    assert!(
        fixture["escalations"].is_array(),
        "escalations must be an array"
    );
}

#[test]
fn adversarial_gate_fixture_samples_have_attack_category() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let samples = fixture["samples"].as_array().expect("samples array");
    for sample in samples {
        let cat = sample["attack_category"]
            .as_str()
            .expect("attack_category string");
        assert!(!cat.trim().is_empty(), "attack_category must be non-empty");
    }
}

#[test]
fn adversarial_gate_fixture_has_at_least_five_fields() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    assert!(fixture.as_object().unwrap().len() >= 5);
}

#[test]
fn adversarial_gate_fixture_path_ends_with_json() {
    let path = fixture_path();
    assert_eq!(path.extension().and_then(|e| e.to_str()), Some("json"));
}

#[test]
fn unique_temp_path_contains_prefix() {
    let path = unique_temp_path("test-prefix");
    let filename = path.file_name().unwrap().to_str().unwrap();
    assert!(filename.starts_with("test-prefix-"));
}

#[test]
fn adversarial_gate_fixture_top_level_is_object() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    assert!(fixture.is_object(), "fixture must be a JSON object");
}

#[test]
fn adversarial_gate_fixture_has_nonempty_release_candidate_id() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let rc = fixture["release_candidate_id"]
        .as_str()
        .expect("release_candidate_id");
    assert!(!rc.trim().is_empty());
}

#[test]
fn adversarial_gate_fixture_deterministic_double_read() {
    let a = fs::read(fixture_path()).expect("read fixture");
    let b = fs::read(fixture_path()).expect("read fixture");
    assert_eq!(a, b);
}

#[test]
fn unique_temp_path_generates_distinct_paths() {
    let a = unique_temp_path("test-distinct-a");
    let b = unique_temp_path("test-distinct-b");
    assert_ne!(a, b);
}

// ---------- CLI error handling and fixture invariants ----------

#[test]
fn suppression_gate_cli_exits_nonzero_for_missing_input_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_adversarial_campaign_gate"))
        .arg("--input")
        .arg("/tmp/nonexistent_adversarial_input_999999.json")
        .output()
        .expect("should execute suppression gate CLI");

    assert!(
        !output.status.success(),
        "CLI must fail when input file does not exist"
    );
}

#[test]
fn suppression_gate_cli_exits_nonzero_for_invalid_json_input() {
    let bad_input_path = unique_temp_path("franken-adv-bad-json");
    fs::write(&bad_input_path, b"{ this is not valid json }").expect("write bad json");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_adversarial_campaign_gate"))
        .arg("--input")
        .arg(&bad_input_path)
        .output()
        .expect("should execute suppression gate CLI");

    assert!(
        !output.status.success(),
        "CLI must fail on malformed JSON input"
    );

    let _ = fs::remove_file(bad_input_path);
}

#[test]
fn adversarial_gate_fixture_serde_roundtrip_preserves_structure() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let re_encoded = serde_json::to_vec_pretty(&parsed).expect("re-encode fixture");
    let re_parsed: serde_json::Value =
        serde_json::from_slice(&re_encoded).expect("re-parse fixture");
    assert_eq!(parsed, re_parsed, "serde roundtrip must preserve fixture");
}

#[test]
fn adversarial_gate_fixture_escalations_reference_existing_campaigns() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");

    let sample_ids: std::collections::BTreeSet<String> = fixture["samples"]
        .as_array()
        .expect("samples array")
        .iter()
        .map(|s| s["campaign_id"].as_str().unwrap().to_string())
        .collect();

    let escalations = fixture["escalations"]
        .as_array()
        .expect("escalations array");
    for esc in escalations {
        let esc_campaign_id = esc["campaign_id"].as_str().expect("escalation campaign_id");
        assert!(
            sample_ids.contains(esc_campaign_id),
            "escalation references unknown campaign_id: {esc_campaign_id}"
        );
    }
}

#[test]
fn adversarial_gate_fixture_all_attempt_counts_are_positive() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let samples = fixture["samples"].as_array().expect("samples array");
    for sample in samples {
        let attempt_count = sample["attempt_count"].as_u64().expect("attempt_count u64");
        assert!(
            attempt_count > 0,
            "attempt_count must be positive for campaign {}",
            sample["campaign_id"]
        );
        let success_count = sample["success_count"].as_u64().expect("success_count u64");
        assert!(
            success_count <= attempt_count,
            "success_count must not exceed attempt_count for campaign {}",
            sample["campaign_id"]
        );
    }
}

#[test]
fn adversarial_gate_fixture_raw_length_exceeds_100() {
    let raw = fs::read_to_string(fixture_path()).expect("read fixture");
    assert!(
        raw.len() > 100,
        "fixture raw length should be >100 bytes, got {}",
        raw.len()
    );
}

#[test]
fn fixture_path_parent_directory_exists() {
    let path = fixture_path();
    let parent = path.parent().expect("fixture path must have parent");
    assert!(parent.exists(), "fixture parent directory must exist");
}

#[test]
fn adversarial_gate_fixture_pretty_printed_is_deterministic() {
    let raw = fs::read_to_string(fixture_path()).expect("read fixture");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("parse");
    let a = serde_json::to_string_pretty(&value).expect("first");
    let b = serde_json::to_string_pretty(&value).expect("second");
    assert_eq!(a, b);
}

// ---------- enrichment: structural / cross-reference / CLI ----------

#[test]
fn adversarial_gate_fixture_campaign_ids_are_globally_unique() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let samples = fixture["samples"].as_array().expect("samples array");
    let mut seen = std::collections::BTreeSet::new();
    for sample in samples {
        let id = sample["campaign_id"].as_str().expect("campaign_id string");
        assert!(
            seen.insert(id.to_string()),
            "duplicate campaign_id found: {id}"
        );
    }
}

#[test]
fn adversarial_gate_fixture_samples_cover_three_runtimes() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let samples = fixture["samples"].as_array().expect("samples array");
    let runtimes: std::collections::BTreeSet<String> = samples
        .iter()
        .map(|s| {
            s["target_runtime"]
                .as_str()
                .expect("target_runtime")
                .to_string()
        })
        .collect();
    assert!(
        runtimes.len() >= 3,
        "expected at least 3 distinct runtimes, got {runtimes:?}"
    );
}

#[test]
fn adversarial_gate_fixture_samples_cover_at_least_four_attack_categories() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let samples = fixture["samples"].as_array().expect("samples array");
    let categories: std::collections::BTreeSet<String> = samples
        .iter()
        .map(|s| {
            s["attack_category"]
                .as_str()
                .expect("attack_category")
                .to_string()
        })
        .collect();
    assert!(
        categories.len() >= 4,
        "expected at least 4 attack categories, got {categories:?}"
    );
}

#[test]
fn adversarial_gate_fixture_escalations_all_have_required_fields() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let escalations = fixture["escalations"]
        .as_array()
        .expect("escalations array");
    for esc in escalations {
        assert!(
            esc["campaign_id"].is_string(),
            "escalation must have campaign_id"
        );
        assert!(
            esc["attack_category"].is_string(),
            "escalation must have attack_category"
        );
        assert!(
            esc["target_runtime"].is_string(),
            "escalation must have target_runtime"
        );
        assert!(
            esc["successful_exploit"].is_boolean(),
            "escalation must have successful_exploit boolean"
        );
        assert!(
            esc["escalation_triggered"].is_boolean(),
            "escalation must have escalation_triggered boolean"
        );
        assert!(
            esc["escalation_latency_seconds"].is_number(),
            "escalation must have escalation_latency_seconds number"
        );
    }
}

#[test]
fn adversarial_gate_fixture_escalation_latencies_are_positive() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let escalations = fixture["escalations"]
        .as_array()
        .expect("escalations array");
    for esc in escalations {
        let latency = esc["escalation_latency_seconds"]
            .as_u64()
            .expect("escalation_latency_seconds u64");
        assert!(
            latency > 0,
            "escalation_latency_seconds must be positive for campaign {}",
            esc["campaign_id"]
        );
    }
}

#[test]
fn adversarial_gate_fixture_all_samples_have_repro_script_ref() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let samples = fixture["samples"].as_array().expect("samples array");
    for sample in samples {
        let repro = sample["repro_script_ref"]
            .as_str()
            .expect("repro_script_ref string");
        assert!(
            !repro.trim().is_empty(),
            "repro_script_ref must be non-empty for campaign {}",
            sample["campaign_id"]
        );
    }
}

#[test]
fn adversarial_gate_fixture_sample_field_count_is_seven() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let samples = fixture["samples"].as_array().expect("samples array");
    for sample in samples {
        let obj = sample.as_object().expect("sample must be object");
        assert_eq!(
            obj.len(),
            7,
            "each sample should have exactly 7 fields, got {} for campaign {}",
            obj.len(),
            sample["campaign_id"]
        );
    }
}

#[test]
fn adversarial_gate_fixture_trend_points_have_distinct_timestamps() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let points = fixture["trend_points"]
        .as_array()
        .expect("trend_points array");
    let timestamps: std::collections::BTreeSet<u64> = points
        .iter()
        .map(|p| p["timestamp_ns"].as_u64().expect("timestamp_ns"))
        .collect();
    assert_eq!(
        timestamps.len(),
        points.len(),
        "trend_points must have distinct timestamps"
    );
}

#[test]
fn adversarial_gate_fixture_trend_points_are_chronologically_ordered() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let points = fixture["trend_points"]
        .as_array()
        .expect("trend_points array");
    let timestamps: Vec<u64> = points
        .iter()
        .map(|p| p["timestamp_ns"].as_u64().expect("timestamp_ns"))
        .collect();
    for window in timestamps.windows(2) {
        assert!(
            window[0] <= window[1],
            "trend_points timestamps must be non-decreasing: {} > {}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn adversarial_gate_fixture_no_null_values_in_samples() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let samples = fixture["samples"].as_array().expect("samples array");
    for sample in samples {
        let obj = sample.as_object().expect("sample must be object");
        for (key, val) in obj {
            assert!(
                !val.is_null(),
                "sample field '{key}' must not be null in campaign {}",
                sample["campaign_id"]
            );
        }
    }
}

#[test]
fn adversarial_gate_fixture_compact_serde_roundtrip() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let compact = serde_json::to_string(&parsed).expect("compact encode");
    let re_parsed: serde_json::Value = serde_json::from_str(&compact).expect("re-parse compact");
    assert_eq!(
        parsed, re_parsed,
        "compact serde roundtrip must preserve fixture"
    );
}

#[test]
fn adversarial_gate_fixture_escalations_only_reference_frankenengine_runtime() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let escalations = fixture["escalations"]
        .as_array()
        .expect("escalations array");
    for esc in escalations {
        let runtime = esc["target_runtime"].as_str().expect("target_runtime");
        assert_eq!(
            runtime, "FrankenEngine",
            "escalations should only reference FrankenEngine runtime, got {runtime}"
        );
    }
}

#[test]
fn suppression_gate_cli_summary_mode_prints_key_value_lines() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_adversarial_campaign_gate"))
        .arg("--input")
        .arg(fixture_path())
        .arg("--summary")
        .output()
        .expect("should execute suppression gate CLI");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("suppression_gate.passed=true"),
        "summary output must contain passed=true, got: {stdout}"
    );
    assert!(
        stdout.contains("suppression_gate.schema_version="),
        "summary output must contain schema_version key"
    );
    assert!(
        stdout.contains("suppression_gate.release_candidate_id="),
        "summary output must contain release_candidate_id key"
    );
}

#[test]
fn suppression_gate_cli_exits_nonzero_for_no_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_adversarial_campaign_gate"))
        .output()
        .expect("should execute suppression gate CLI");

    assert!(
        !output.status.success(),
        "CLI must fail when no arguments are provided"
    );
}

#[test]
fn adversarial_gate_fixture_clone_independence() {
    let bytes = fs::read(fixture_path()).expect("read fixture");
    let original: serde_json::Value = serde_json::from_slice(&bytes).expect("parse fixture");
    let mut cloned = original.clone();
    cloned["release_candidate_id"] = serde_json::Value::String("mutated-id".to_string());
    assert_ne!(
        original["release_candidate_id"], cloned["release_candidate_id"],
        "mutating clone must not affect original"
    );
    assert_eq!(
        original["release_candidate_id"], "rc-adversarial-gate-v1",
        "original must be unchanged after clone mutation"
    );
}
