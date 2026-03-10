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

use std::{collections::BTreeSet, fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json(path: &str) -> Value {
    let full = repo_root().join(path);
    let raw = fs::read_to_string(&full)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", full.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {} as JSON: {err}", full.display()))
}

fn read_text(path: &str) -> String {
    let full = repo_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", full.display()))
}

fn require_string_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .unwrap_or_else(|| panic!("missing `{field}`"))
        .as_str()
        .unwrap_or_else(|| panic!("`{field}` must be a string"))
}

fn require_u64_field(value: &Value, field: &str) -> u64 {
    value
        .get(field)
        .unwrap_or_else(|| panic!("missing `{field}`"))
        .as_u64()
        .unwrap_or_else(|| panic!("`{field}` must be an unsigned integer"))
}

fn require_bool_field(value: &Value, field: &str) -> bool {
    value
        .get(field)
        .unwrap_or_else(|| panic!("missing `{field}`"))
        .as_bool()
        .unwrap_or_else(|| panic!("`{field}` must be a bool"))
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[test]
fn workload_matrix_declares_required_families_profiles_and_hash_contract() {
    let matrix = read_json("docs/extension_heavy_workload_matrix_v1.json");

    assert_eq!(
        require_string_field(&matrix, "schema_version"),
        "franken-engine.extension-heavy-workload-matrix.v1"
    );

    let profile_defaults = matrix
        .get("profile_defaults")
        .and_then(Value::as_object)
        .expect("profile_defaults must be an object");

    let expected_defaults = [
        ("S", 10_u64, 1_000_u64, 200_u64, "baseline"),
        ("M", 100_u64, 10_000_u64, 2_000_u64, "hardened"),
        ("L", 1_000_u64, 50_000_u64, 20_000_u64, "stress"),
    ];
    for (profile, extensions, event_rate, edges, tier) in expected_defaults {
        let value = profile_defaults
            .get(profile)
            .unwrap_or_else(|| panic!("missing profile default `{profile}`"));
        assert_eq!(require_u64_field(value, "extension_count"), extensions);
        assert_eq!(require_u64_field(value, "event_rate_per_sec"), event_rate);
        assert_eq!(require_u64_field(value, "dependency_graph_edges"), edges);
        assert_eq!(require_string_field(value, "policy_complexity_tier"), tier);
    }

    let families = matrix
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");
    assert_eq!(
        families.len(),
        5,
        "exactly five benchmark families are required"
    );

    let expected_families: BTreeSet<&str> = [
        "boot-storm",
        "capability-churn",
        "mixed-cpu-io-agent-mesh",
        "reload-revoke-churn",
        "adversarial-noise-under-load",
    ]
    .into_iter()
    .collect();

    let observed_families: BTreeSet<&str> = families
        .iter()
        .map(|family| require_string_field(family, "family_id"))
        .collect();
    assert_eq!(observed_families, expected_families);

    let cases = matrix
        .get("cases")
        .and_then(Value::as_array)
        .expect("cases must be an array");
    assert_eq!(
        cases.len(),
        15,
        "workload matrix must contain 15 S/M/L cases"
    );

    let mut workload_ids = BTreeSet::new();
    let mut family_profile_pairs = BTreeSet::new();

    for case in cases {
        let workload_id = require_string_field(case, "workload_id");
        assert!(
            workload_ids.insert(workload_id.to_string()),
            "duplicate workload_id: {workload_id}"
        );

        let family_id = require_string_field(case, "family_id");
        assert!(
            expected_families.contains(family_id),
            "unknown family id in case {workload_id}: {family_id}"
        );

        let profile = require_string_field(case, "profile");
        assert!(
            matches!(profile, "S" | "M" | "L"),
            "invalid profile: {profile}"
        );
        assert!(
            family_profile_pairs.insert(format!("{family_id}:{profile}")),
            "duplicate family/profile pair: {family_id}:{profile}"
        );

        let expected_suffix = profile.to_ascii_lowercase();
        assert!(
            workload_id.ends_with(&format!("-{expected_suffix}")),
            "workload id/profile mismatch for {workload_id}"
        );

        let dataset_checksum = require_string_field(case, "dataset_checksum_sha256");
        assert!(
            is_sha256_hex(dataset_checksum),
            "invalid dataset checksum for {workload_id}"
        );

        let seed_checksum = require_string_field(case, "seed_transcript_sha256");
        assert!(
            is_sha256_hex(seed_checksum),
            "invalid seed transcript checksum for {workload_id}"
        );

        assert_eq!(require_string_field(case, "baseline_engine"), "node_lts");
        assert_eq!(
            require_string_field(case, "candidate_engine"),
            "franken_engine_main"
        );

        let comparison_targets = case
            .get("comparison_targets")
            .and_then(Value::as_array)
            .expect("comparison_targets must be an array");
        let comparison_set: BTreeSet<&str> = comparison_targets
            .iter()
            .map(|target| {
                target
                    .as_str()
                    .unwrap_or_else(|| panic!("comparison target in {workload_id} must be string"))
            })
            .collect();
        assert_eq!(
            comparison_set,
            BTreeSet::from(["bun_stable", "node_lts"]),
            "comparison targets must include node and bun for {workload_id}"
        );

        let golden_output_id = require_string_field(case, "golden_output_id");
        assert!(
            golden_output_id.starts_with("golden-") && golden_output_id.ends_with("-v1"),
            "golden_output_id format is invalid for {workload_id}: {golden_output_id}"
        );
    }

    let expected_pairs: BTreeSet<String> = expected_families
        .iter()
        .flat_map(|family| {
            ["S", "M", "L"]
                .into_iter()
                .map(move |profile| format!("{family}:{profile}"))
        })
        .collect();
    assert_eq!(family_profile_pairs, expected_pairs);
}

#[test]
fn golden_output_manifest_covers_all_workloads_with_behavior_equivalence_contract() {
    let matrix = read_json("docs/extension_heavy_workload_matrix_v1.json");
    let golden = read_json("docs/extension_heavy_golden_outputs_v1.json");

    assert_eq!(
        require_string_field(&golden, "schema_version"),
        "franken-engine.extension-heavy-golden-outputs.v1"
    );

    let matrix_cases = matrix
        .get("cases")
        .and_then(Value::as_array)
        .expect("matrix cases must be array");
    let matrix_workload_ids: BTreeSet<String> = matrix_cases
        .iter()
        .map(|case| require_string_field(case, "workload_id").to_string())
        .collect();
    let matrix_golden_ids: BTreeSet<String> = matrix_cases
        .iter()
        .map(|case| require_string_field(case, "golden_output_id").to_string())
        .collect();

    let entries = golden
        .get("entries")
        .and_then(Value::as_array)
        .expect("golden entries must be an array");
    assert_eq!(
        entries.len(),
        15,
        "golden manifest must cover all 15 workloads"
    );

    let mut seen_workloads = BTreeSet::new();
    let mut seen_golden_ids = BTreeSet::new();

    for entry in entries {
        let workload_id = require_string_field(entry, "workload_id");
        assert!(seen_workloads.insert(workload_id.to_string()));

        let golden_output_id = require_string_field(entry, "golden_output_id");
        assert!(seen_golden_ids.insert(golden_output_id.to_string()));

        let correctness_digest = require_string_field(entry, "correctness_digest_sha256");
        assert!(is_sha256_hex(correctness_digest));

        let result_digest = require_string_field(entry, "result_digest_sha256");
        assert!(is_sha256_hex(result_digest));

        let canonical_output = entry
            .get("canonical_output")
            .expect("missing canonical_output object");
        assert_eq!(
            require_string_field(canonical_output, "behavior_equivalence_verdict"),
            "pass"
        );
        let external_digest = require_string_field(canonical_output, "external_output_digest");
        assert!(
            external_digest.starts_with("sha256:") && is_sha256_hex(&external_digest[7..]),
            "external output digest must be sha256-prefixed"
        );

        let side_effects = canonical_output
            .get("side_effect_trace_class")
            .and_then(Value::as_object)
            .expect("side_effect_trace_class must be object");
        let side_effect_keys: BTreeSet<&str> = side_effects.keys().map(String::as_str).collect();
        assert_eq!(
            side_effect_keys,
            BTreeSet::from(["fs", "network", "policy", "process"]),
            "side_effect_trace_class must include fs/network/process/policy"
        );
        for key in ["fs", "network", "process", "policy"] {
            assert!(
                side_effects
                    .get(key)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty()),
                "side effect class value `{key}` must be non-empty"
            );
        }

        assert_eq!(
            require_string_field(canonical_output, "error_class_semantics"),
            "equivalent"
        );
        assert!(!require_bool_field(canonical_output, "work_drop_detected"));
        assert!(!require_bool_field(canonical_output, "durability_relaxed"));
        assert!(!require_bool_field(
            canonical_output,
            "policy_checks_disabled"
        ));

        let envelope = entry
            .get("security_envelope")
            .expect("security_envelope must be present");
        assert!(matches!(
            require_string_field(envelope, "profile"),
            "S" | "M" | "L"
        ));
        assert_eq!(require_u64_field(envelope, "time_to_detect_ms_budget"), 250);
        assert_eq!(
            require_u64_field(envelope, "time_to_contain_ms_budget"),
            250
        );
        assert_eq!(
            require_u64_field(envelope, "false_positive_envelope_ppm"),
            1000
        );
        assert_eq!(
            require_u64_field(envelope, "false_negative_envelope_ppm"),
            100
        );
    }

    assert_eq!(seen_workloads, matrix_workload_ids);
    assert_eq!(seen_golden_ids, matrix_golden_ids);
}

#[test]
fn benchmark_spec_links_machine_readable_manifests() {
    let spec = read_text("docs/EXTENSION_HEAVY_BENCHMARK_SUITE_V1.md");

    let required_mentions = [
        "docs/extension_heavy_workload_matrix_v1.json",
        "docs/extension_heavy_golden_outputs_v1.json",
        "15",
        "dataset_checksum_sha256",
        "seed_transcript_sha256",
    ];

    for mention in required_mentions {
        assert!(
            spec.contains(mention),
            "benchmark spec must mention machine-readable manifest contract fragment: {mention}"
        );
    }
}

// ---------- helper functions ----------

#[test]
fn require_string_field_returns_value() {
    let value = serde_json::json!({"name": "test"});
    assert_eq!(require_string_field(&value, "name"), "test");
}

#[test]
#[should_panic(expected = "missing")]
fn require_string_field_panics_on_missing() {
    let value = serde_json::json!({});
    require_string_field(&value, "missing_field");
}

#[test]
fn require_u64_field_returns_value() {
    let value = serde_json::json!({"count": 42});
    assert_eq!(require_u64_field(&value, "count"), 42);
}

#[test]
#[should_panic(expected = "missing")]
fn require_u64_field_panics_on_missing() {
    let value = serde_json::json!({});
    require_u64_field(&value, "missing_field");
}

#[test]
fn require_bool_field_returns_value() {
    let value = serde_json::json!({"active": true});
    assert!(require_bool_field(&value, "active"));
}

#[test]
#[should_panic(expected = "missing")]
fn require_bool_field_panics_on_missing() {
    let value = serde_json::json!({});
    require_bool_field(&value, "missing_field");
}

#[test]
fn is_sha256_hex_accepts_valid_hex() {
    let valid = "a".repeat(64);
    assert!(is_sha256_hex(&valid));
}

#[test]
fn is_sha256_hex_rejects_short_string() {
    assert!(!is_sha256_hex("abc123"));
}

#[test]
fn is_sha256_hex_rejects_non_hex_chars() {
    let invalid = "z".repeat(64);
    assert!(!is_sha256_hex(&invalid));
}

#[test]
fn is_sha256_hex_rejects_empty() {
    assert!(!is_sha256_hex(""));
}

// ---------- read_json / read_text ----------

#[test]
fn read_json_returns_object_for_workload_matrix() {
    let value = read_json("docs/extension_heavy_workload_matrix_v1.json");
    assert!(value.is_object());
}

#[test]
fn read_text_returns_nonempty_for_spec() {
    let text = read_text("docs/EXTENSION_HEAVY_BENCHMARK_SUITE_V1.md");
    assert!(!text.is_empty());
}

// ---------- fixture structure ----------

#[test]
fn workload_matrix_has_five_families() {
    let matrix = read_json("docs/extension_heavy_workload_matrix_v1.json");
    let families = matrix["family_definitions"].as_array().expect("array");
    assert_eq!(families.len(), 5);
}

#[test]
fn golden_output_manifest_has_fifteen_entries() {
    let golden = read_json("docs/extension_heavy_golden_outputs_v1.json");
    let entries = golden["entries"].as_array().expect("array");
    assert_eq!(entries.len(), 15);
}

#[test]
fn workload_matrix_has_schema_version() {
    let matrix = read_json("docs/extension_heavy_workload_matrix_v1.json");
    let sv = require_string_field(&matrix, "schema_version");
    assert!(!sv.is_empty());
}

#[test]
fn golden_output_manifest_entry_ids_are_unique() {
    let golden = read_json("docs/extension_heavy_golden_outputs_v1.json");
    let entries = golden["entries"].as_array().expect("array");
    let mut seen = BTreeSet::new();
    for entry in entries {
        let wid = require_string_field(entry, "workload_id");
        assert!(seen.insert(wid.to_string()), "duplicate workload_id: {wid}");
    }
}

#[test]
fn workload_matrix_cases_have_nonempty_workload_ids() {
    let matrix = read_json("docs/extension_heavy_workload_matrix_v1.json");
    let cases = matrix["cases"].as_array().expect("cases array");
    for case in cases {
        let wid = require_string_field(case, "workload_id");
        assert!(!wid.trim().is_empty());
    }
}

#[test]
fn workload_matrix_deterministic_double_parse() {
    let a = read_json("docs/extension_heavy_workload_matrix_v1.json");
    let b = read_json("docs/extension_heavy_workload_matrix_v1.json");
    assert_eq!(a, b);
}

#[test]
fn golden_output_deterministic_double_parse() {
    let a = read_json("docs/extension_heavy_golden_outputs_v1.json");
    let b = read_json("docs/extension_heavy_golden_outputs_v1.json");
    assert_eq!(a, b);
}

#[test]
fn workload_matrix_is_a_json_object() {
    let matrix = read_json("docs/extension_heavy_workload_matrix_v1.json");
    assert!(matrix.is_object());
}

#[test]
fn golden_output_manifest_is_a_json_object() {
    let golden = read_json("docs/extension_heavy_golden_outputs_v1.json");
    assert!(golden.is_object());
}

#[test]
fn workload_matrix_json_file_exists() {
    let path = repo_root().join("docs/extension_heavy_workload_matrix_v1.json");
    assert!(path.exists(), "workload matrix JSON must exist");
}

#[test]
fn golden_output_json_file_exists() {
    let path = repo_root().join("docs/extension_heavy_golden_outputs_v1.json");
    assert!(path.exists(), "golden output JSON must exist");
}

#[test]
fn workload_matrix_profile_defaults_has_three_profiles() {
    let matrix = read_json("docs/extension_heavy_workload_matrix_v1.json");
    let profile_defaults = matrix
        .get("profile_defaults")
        .and_then(Value::as_object)
        .expect("profile_defaults must be an object");
    assert_eq!(
        profile_defaults.len(),
        3,
        "must have exactly 3 profile defaults (S, M, L)"
    );
    for profile in ["S", "M", "L"] {
        assert!(
            profile_defaults.contains_key(profile),
            "missing profile default: {profile}"
        );
    }
}

#[test]
fn workload_matrix_family_ids_are_nonempty_and_unique() {
    let matrix = read_json("docs/extension_heavy_workload_matrix_v1.json");
    let families = matrix["family_definitions"].as_array().expect("array");
    let mut seen = BTreeSet::new();
    for family in families {
        let fid = require_string_field(family, "family_id");
        assert!(!fid.trim().is_empty(), "family_id must be non-empty");
        assert!(seen.insert(fid.to_string()), "duplicate family_id: {fid}");
    }
}

#[test]
fn golden_output_entries_all_have_security_envelope() {
    let golden = read_json("docs/extension_heavy_golden_outputs_v1.json");
    let entries = golden["entries"].as_array().expect("array");
    for entry in entries {
        let envelope = entry.get("security_envelope");
        assert!(
            envelope.is_some(),
            "entry {} missing security_envelope",
            require_string_field(entry, "workload_id")
        );
    }
}

#[test]
fn is_sha256_hex_rejects_65_char_string() {
    let too_long = "a".repeat(65);
    assert!(
        !is_sha256_hex(&too_long),
        "65-char string should be rejected"
    );
}

#[test]
fn is_sha256_hex_rejects_63_char_string() {
    let too_short = "a".repeat(63);
    assert!(
        !is_sha256_hex(&too_short),
        "63-char string should be rejected"
    );
}

#[test]
fn is_sha256_hex_accepts_mixed_case_hex() {
    let mixed = "aAbBcCdDeEfF001122334455667788990011aabbccddeeff0011223344556677".to_string();
    assert_eq!(mixed.len(), 64);
    assert!(
        is_sha256_hex(&mixed),
        "mixed-case valid hex of length 64 should be accepted"
    );
}

#[test]
fn golden_output_entries_have_nonempty_golden_output_ids() {
    let golden = read_json("docs/extension_heavy_golden_outputs_v1.json");
    let entries = golden["entries"].as_array().expect("array");
    for entry in entries {
        let gid = require_string_field(entry, "golden_output_id");
        assert!(!gid.trim().is_empty(), "golden_output_id must be non-empty");
    }
}
