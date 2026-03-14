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

use serde_json::Value;
use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_file(path: &str) -> String {
    let file_path = repo_root().join(path);
    fs::read_to_string(&file_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", file_path.display()))
}

fn parse_json_file(path: &str) -> Value {
    let raw = read_file(path);
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("{path} must be valid JSON template: {err}"))
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    let mut current = value;
    for segment in path {
        current = current
            .get(*segment)
            .unwrap_or_else(|| panic!("missing required path `{}`", path.join(".")));
    }
    current
}

fn assert_string_field(value: &Value, path: &[&str]) {
    assert!(
        value_at_path(value, path).as_str().is_some(),
        "expected string at `{}`",
        path.join(".")
    );
}

fn assert_bool_field(value: &Value, path: &[&str]) {
    assert!(
        value_at_path(value, path).as_bool().is_some(),
        "expected bool at `{}`",
        path.join(".")
    );
}

fn assert_array_field(value: &Value, path: &[&str]) {
    assert!(
        value_at_path(value, path).as_array().is_some(),
        "expected array at `{}`",
        path.join(".")
    );
}

fn canonicalize_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => {
            if *flag {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(number) => number.to_string(),
        Value::String(text) => serde_json::to_string(text).expect("json string serialization"),
        Value::Array(items) => {
            let canonical_items: Vec<String> = items.iter().map(canonicalize_json).collect();
            format!("[{}]", canonical_items.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();

            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                let key_json = serde_json::to_string(key).expect("json key serialization");
                let value_json = canonicalize_json(map.get(key).expect("key from map.keys exists"));
                parts.push(format!("{key_json}:{value_json}"));
            }
            format!("{{{}}}", parts.join(","))
        }
    }
}

#[test]
fn reproducibility_contract_doc_contains_required_sections() {
    let doc = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    let required_sections = [
        "## Artifact Schema Contracts",
        "## Version Compatibility Policy",
        "## Canonical Serialization and Hash Boundaries",
        "## Provenance Linkage Rules",
        "## Deterministic Validation CLI/API Contract",
        "## Fail-Closed and Degraded Mode Policy",
        "## CI Publication Gate Contract",
        "## Neutral Verifier Flow",
        "## Retention and Rotation Policy",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "reproducibility contract doc must include section: {section}"
        );
    }
}

#[test]
fn reproducibility_contract_doc_declares_stable_error_codes() {
    let doc = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    let required_codes = [
        "FE-REPRO-0001",
        "FE-REPRO-0002",
        "FE-REPRO-0003",
        "FE-REPRO-0004",
        "FE-REPRO-0005",
        "FE-REPRO-0006",
        "FE-REPRO-0007",
        "FE-REPRO-0008",
    ];

    for code in required_codes {
        assert!(
            doc.contains(code),
            "reproducibility contract must include stable error code: {code}"
        );
    }
}

#[test]
fn template_guide_declares_validator_and_ci_gate_behavior() {
    let guide = read_file("docs/REPRODUCIBILITY_CONTRACT_TEMPLATE.md");
    let required_clauses = [
        "frankenctl repro verify --bundle",
        "## Validator Contract (Deterministic)",
        "## CI Gate Contract",
        "## Fail-Closed and Degraded Mode",
        "## Schema Compatibility Rules",
    ];

    for clause in required_clauses {
        assert!(
            guide.contains(clause),
            "template guide must include clause: {clause}"
        );
    }
}

#[test]
fn env_template_has_required_contract_fields() {
    let env = parse_json_file("docs/templates/env.json.template");

    assert_eq!(
        value_at_path(&env, &["schema_version"])
            .as_str()
            .expect("schema_version is string"),
        "franken-engine.env.v1"
    );

    assert_string_field(&env, &["schema_hash"]);
    assert_string_field(&env, &["captured_at_utc"]);
    assert_string_field(&env, &["project", "name"]);
    assert_string_field(&env, &["project", "commit"]);
    assert_string_field(&env, &["host", "arch"]);
    assert_string_field(&env, &["toolchain", "rustc"]);
    assert_string_field(&env, &["runtime", "mode"]);
    assert_bool_field(&env, &["runtime", "safe_mode_enabled"]);
    assert_array_field(&env, &["runtime", "feature_flags"]);
    assert_string_field(&env, &["policy", "policy_id"]);
    assert_string_field(&env, &["policy", "policy_digest_sha256"]);
}

#[test]
fn manifest_template_has_provenance_and_retention_fields() {
    let manifest = parse_json_file("docs/templates/manifest.json.template");

    assert_eq!(
        value_at_path(&manifest, &["schema_version"])
            .as_str()
            .expect("schema_version is string"),
        "franken-engine.manifest.v1"
    );

    assert_string_field(&manifest, &["schema_hash"]);
    assert_string_field(&manifest, &["manifest_id"]);
    assert_string_field(&manifest, &["claim", "claim_id"]);
    assert_string_field(&manifest, &["claim", "class"]);
    assert_string_field(&manifest, &["provenance", "trace_id"]);
    assert_string_field(&manifest, &["provenance", "decision_id"]);
    assert_string_field(&manifest, &["provenance", "policy_id"]);
    assert_string_field(&manifest, &["provenance", "replay_pointer"]);
    assert_string_field(&manifest, &["provenance", "evidence_pointer"]);
    assert_array_field(&manifest, &["provenance", "receipt_ids"]);
    assert_string_field(&manifest, &["canonicalization", "hash_algorithm"]);
    assert_string_field(&manifest, &["validation", "validator"]);
    assert_string_field(&manifest, &["validation", "error_taxonomy"]);
    assert_string_field(&manifest, &["retention", "rotation_policy"]);
}

#[test]
fn repro_lock_template_has_deterministic_verifier_contract_fields() {
    let lock = parse_json_file("docs/templates/repro.lock.template");

    assert_eq!(
        value_at_path(&lock, &["schema_version"])
            .as_str()
            .expect("schema_version is string"),
        "franken-engine.repro-lock.v1"
    );

    assert_string_field(&lock, &["schema_hash"]);
    assert_string_field(&lock, &["lock_id"]);
    assert_string_field(&lock, &["manifest_id"]);
    assert_bool_field(&lock, &["determinism", "allow_network"]);
    assert_bool_field(&lock, &["determinism", "allow_wall_clock"]);
    assert_bool_field(&lock, &["determinism", "allow_randomness"]);
    assert_array_field(&lock, &["commands"]);
    assert_array_field(&lock, &["inputs"]);
    assert_array_field(&lock, &["expected_outputs"]);
    assert_string_field(&lock, &["replay", "trace_id"]);
    assert_string_field(&lock, &["replay", "replay_pointer"]);
    assert_string_field(&lock, &["verification", "command"]);
    assert_string_field(&lock, &["verification", "expected_verdict"]);

    let verify_command = value_at_path(&lock, &["verification", "command"])
        .as_str()
        .expect("verification.command is string");
    assert!(
        verify_command.contains("frankenctl repro verify --bundle"),
        "verification command must use one-command verifier flow"
    );
}

#[test]
fn json_templates_are_canonicalization_stable() {
    let template_paths = [
        "docs/templates/env.json.template",
        "docs/templates/manifest.json.template",
        "docs/templates/repro.lock.template",
    ];

    for path in template_paths {
        let value = parse_json_file(path);
        let canonical_once = canonicalize_json(&value);
        let reparsed: Value = serde_json::from_str(&canonical_once)
            .unwrap_or_else(|err| panic!("canonical JSON for {path} must parse: {err}"));
        let canonical_twice = canonicalize_json(&reparsed);
        assert_eq!(
            canonical_once, canonical_twice,
            "canonicalization must be stable for {path}"
        );
    }
}

// ---------- read_file helper ----------

#[test]
fn read_file_returns_nonempty() {
    let content = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    assert!(!content.is_empty());
}

// ---------- parse_json_file helper ----------

#[test]
fn parse_json_file_returns_valid_value() {
    let value = parse_json_file("docs/templates/env.json.template");
    assert!(value.is_object());
}

// ---------- value_at_path ----------

#[test]
fn value_at_path_navigates_nested() {
    let value: Value = serde_json::json!({
        "a": { "b": { "c": "deep" } }
    });
    let result = value_at_path(&value, &["a", "b", "c"]);
    assert_eq!(result.as_str(), Some("deep"));
}

// ---------- canonicalize_json ----------

#[test]
fn canonicalize_json_null() {
    assert_eq!(canonicalize_json(&Value::Null), "null");
}

#[test]
fn canonicalize_json_bool() {
    assert_eq!(canonicalize_json(&Value::Bool(true)), "true");
    assert_eq!(canonicalize_json(&Value::Bool(false)), "false");
}

#[test]
fn canonicalize_json_string() {
    let val = Value::String("hello".to_string());
    assert_eq!(canonicalize_json(&val), "\"hello\"");
}

#[test]
fn canonicalize_json_array() {
    let val: Value = serde_json::json!([1, 2, 3]);
    let result = canonicalize_json(&val);
    assert_eq!(result, "[1,2,3]");
}

#[test]
fn canonicalize_json_object_sorts_keys() {
    let val: Value = serde_json::json!({"z": 1, "a": 2});
    let result = canonicalize_json(&val);
    assert!(result.starts_with("{\"a\":2"));
}

#[test]
fn canonicalize_json_is_idempotent() {
    let val: Value = serde_json::json!({"b": [1, null], "a": true});
    let once = canonicalize_json(&val);
    let reparsed: Value = serde_json::from_str(&once).expect("parse");
    let twice = canonicalize_json(&reparsed);
    assert_eq!(once, twice);
}

// ---------- assert helpers ----------

#[test]
fn assert_string_field_passes_for_string() {
    let val: Value = serde_json::json!({"key": "value"});
    assert_string_field(&val, &["key"]);
}

#[test]
fn assert_bool_field_passes_for_bool() {
    let val: Value = serde_json::json!({"flag": true});
    assert_bool_field(&val, &["flag"]);
}

#[test]
fn assert_array_field_passes_for_array() {
    let val: Value = serde_json::json!({"items": [1, 2]});
    assert_array_field(&val, &["items"]);
}

#[test]
fn canonicalize_json_deterministic_for_same_input() {
    let val: Value = serde_json::json!({"b": 2, "a": 1});
    let a = canonicalize_json(&val);
    let b = canonicalize_json(&val);
    assert_eq!(a, b);
}

#[test]
fn read_file_returns_nonempty_for_contract() {
    let content = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    assert!(!content.is_empty());
}

#[test]
fn parse_json_template_returns_object() {
    let val = parse_json_file("docs/templates/env.json.template");
    assert!(val.is_object());
}

// ---------- canonicalize_json: number values ----------

#[test]
fn canonicalize_json_number_integer_and_float() {
    let int_val: Value = serde_json::json!(42);
    assert_eq!(canonicalize_json(&int_val), "42");

    let neg_val: Value = serde_json::json!(-7);
    assert_eq!(canonicalize_json(&neg_val), "-7");

    let float_val: Value = serde_json::json!(42.42);
    let canon = canonicalize_json(&float_val);
    // Must round-trip as a number, not quoted
    assert!(
        !canon.starts_with('"'),
        "number must not be quoted: {canon}"
    );
    let reparsed: Value = serde_json::from_str(&canon).expect("reparsed");
    assert!(reparsed.is_number());

    let zero_val: Value = serde_json::json!(0);
    assert_eq!(canonicalize_json(&zero_val), "0");
}

// ---------- canonicalize_json: deeply nested objects ----------

#[test]
fn canonicalize_json_deeply_nested_objects() {
    let val: Value = serde_json::json!({
        "level1": {
            "level2": {
                "level3": {
                    "level4": "deep_value"
                }
            }
        }
    });
    let canon = canonicalize_json(&val);
    // Keys sorted at every level; nested structure preserved
    assert!(canon.contains("\"level1\""), "must contain level1 key");
    assert!(canon.contains("\"deep_value\""), "must contain leaf value");
    // Idempotent
    let reparsed: Value = serde_json::from_str(&canon).expect("reparsed");
    assert_eq!(canon, canonicalize_json(&reparsed));
}

// ---------- canonicalize_json: mixed arrays ----------

#[test]
fn canonicalize_json_mixed_array_objects_and_primitives() {
    let val: Value = serde_json::json!([
        {"b": 2, "a": 1},
        "hello",
        42,
        null,
        true,
        [3, 4]
    ]);
    let canon = canonicalize_json(&val);
    // Object inside array must have sorted keys
    assert!(
        canon.contains("{\"a\":1,\"b\":2}"),
        "inner object keys sorted"
    );
    // Primitives preserved in order
    assert!(canon.contains("\"hello\""), "string preserved");
    assert!(canon.contains("null"), "null preserved");
    assert!(canon.contains("[3,4]"), "nested array preserved");
    // Round-trip stable
    let reparsed: Value = serde_json::from_str(&canon).expect("reparsed");
    assert_eq!(canon, canonicalize_json(&reparsed));
}

// ---------- canonicalize_json: empty object and empty array ----------

#[test]
fn canonicalize_json_empty_object_and_empty_array() {
    let empty_obj: Value = serde_json::json!({});
    assert_eq!(canonicalize_json(&empty_obj), "{}");

    let empty_arr: Value = serde_json::json!([]);
    assert_eq!(canonicalize_json(&empty_arr), "[]");

    // Nested empties
    let nested: Value = serde_json::json!({"a": {}, "b": []});
    let canon = canonicalize_json(&nested);
    assert_eq!(canon, "{\"a\":{},\"b\":[]}");
}

// ---------- template schema_hash fields are non-empty ----------

#[test]
fn template_schema_hash_fields_are_nonempty_strings() {
    let template_paths = [
        "docs/templates/env.json.template",
        "docs/templates/manifest.json.template",
        "docs/templates/repro.lock.template",
    ];

    for path in template_paths {
        let val = parse_json_file(path);
        let hash = value_at_path(&val, &["schema_hash"])
            .as_str()
            .unwrap_or_else(|| panic!("schema_hash must be a string in {path}"));
        assert!(!hash.is_empty(), "schema_hash must not be empty in {path}");
        assert!(
            hash.len() > 1,
            "schema_hash must be a substantial string in {path}, got: {hash}"
        );
    }
}

// ---------- manifest provenance receipt_ids array ----------

#[test]
fn manifest_template_provenance_receipt_ids_is_nonempty_string_array() {
    let manifest = parse_json_file("docs/templates/manifest.json.template");
    let receipt_ids = value_at_path(&manifest, &["provenance", "receipt_ids"])
        .as_array()
        .expect("receipt_ids must be an array");
    assert!(
        !receipt_ids.is_empty(),
        "receipt_ids array must have at least one placeholder entry"
    );
    for (i, entry) in receipt_ids.iter().enumerate() {
        assert!(
            entry.as_str().is_some(),
            "receipt_ids[{i}] must be a string"
        );
    }
}

// ---------- repro lock commands array is non-empty ----------

#[test]
fn repro_lock_template_commands_array_is_nonempty() {
    let lock = parse_json_file("docs/templates/repro.lock.template");
    let commands = value_at_path(&lock, &["commands"])
        .as_array()
        .expect("commands must be an array");
    assert!(
        !commands.is_empty(),
        "repro lock commands must contain at least one command placeholder"
    );
    for (i, cmd) in commands.iter().enumerate() {
        assert!(cmd.as_str().is_some(), "commands[{i}] must be a string");
    }
}

// ---------- repro lock inputs and expected_outputs typed correctly ----------

#[test]
fn repro_lock_template_inputs_and_expected_outputs_are_object_arrays() {
    let lock = parse_json_file("docs/templates/repro.lock.template");

    for field_name in &["inputs", "expected_outputs"] {
        let arr = value_at_path(&lock, &[field_name])
            .as_array()
            .unwrap_or_else(|| panic!("{field_name} must be an array"));
        assert!(!arr.is_empty(), "{field_name} must have at least one entry");
        for (i, entry) in arr.iter().enumerate() {
            assert!(entry.is_object(), "{field_name}[{i}] must be an object");
            // Each entry must have path and sha256 string fields
            let path_val = entry
                .get("path")
                .unwrap_or_else(|| panic!("{field_name}[{i}] must have a 'path' field"));
            assert!(
                path_val.as_str().is_some(),
                "{field_name}[{i}].path must be a string"
            );
            let sha_val = entry
                .get("sha256")
                .unwrap_or_else(|| panic!("{field_name}[{i}] must have a 'sha256' field"));
            assert!(
                sha_val.as_str().is_some(),
                "{field_name}[{i}].sha256 must be a string"
            );
        }
    }
}

// ---------- value_at_path with single-element path ----------

#[test]
fn value_at_path_single_element_path() {
    let val: Value = serde_json::json!({"top": "leaf"});
    let result = value_at_path(&val, &["top"]);
    assert_eq!(result.as_str(), Some("leaf"));
}

// ---------- contract doc minimum word count ----------

#[test]
fn contract_doc_has_minimum_word_count() {
    let doc = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    let word_count = doc.split_whitespace().count();
    // The contract doc should be substantive — at least 200 words
    assert!(
        word_count >= 200,
        "reproducibility contract doc must have at least 200 words, found {word_count}"
    );
}

// ---------- all templates share consistent schema_hash format ----------

#[test]
fn all_templates_share_consistent_schema_hash_format() {
    let template_paths = [
        "docs/templates/env.json.template",
        "docs/templates/manifest.json.template",
        "docs/templates/repro.lock.template",
    ];

    let mut hash_prefixes = std::collections::BTreeSet::new();
    for path in template_paths {
        let val = parse_json_file(path);
        let hash = value_at_path(&val, &["schema_hash"])
            .as_str()
            .unwrap_or_else(|| panic!("schema_hash must be a string in {path}"));
        // Extract the prefix before the first colon (e.g., "sha256")
        let prefix = hash.split(':').next().unwrap_or("");
        hash_prefixes.insert(prefix.to_string());
    }
    // All templates should use the same hash algorithm prefix
    assert_eq!(
        hash_prefixes.len(),
        1,
        "all templates must use the same schema_hash prefix format, found: {hash_prefixes:?}"
    );
    // And it should be "sha256"
    assert!(
        hash_prefixes.contains("sha256"),
        "schema_hash prefix must be sha256, found: {hash_prefixes:?}"
    );
}

// ---------- canonicalize_json: string with special chars ----------

#[test]
fn canonicalize_json_string_with_special_characters() {
    let val = Value::String("line1\nline2\ttab\"quote\\back".to_string());
    let canon = canonicalize_json(&val);
    // Must produce valid JSON that round-trips
    let reparsed: Value = serde_json::from_str(&canon).expect("reparsed special string");
    assert_eq!(reparsed.as_str(), Some("line1\nline2\ttab\"quote\\back"));
}

// ---------- canonicalize_json: nested arrays of objects ----------

#[test]
fn canonicalize_json_nested_array_of_objects_sorts_inner_keys() {
    let val: Value = serde_json::json!([
        {"z": 1, "a": 2},
        {"m": 3, "b": 4}
    ]);
    let canon = canonicalize_json(&val);
    // Each inner object must have sorted keys
    assert!(
        canon.contains("{\"a\":2,\"z\":1}"),
        "first object keys sorted"
    );
    assert!(
        canon.contains("{\"b\":4,\"m\":3}"),
        "second object keys sorted"
    );
}

// ---------- env template: project fields ----------

#[test]
fn env_template_project_has_repo_url_and_dirty_flag() {
    let env = parse_json_file("docs/templates/env.json.template");
    assert_string_field(&env, &["project", "repo_url"]);
    assert_bool_field(&env, &["project", "dirty"]);
}

// ---------- env template: host fields ----------

#[test]
fn env_template_host_has_os_and_kernel_fields() {
    let env = parse_json_file("docs/templates/env.json.template");
    assert_string_field(&env, &["host", "os"]);
    assert_string_field(&env, &["host", "kernel"]);
    assert_string_field(&env, &["host", "cpu_model"]);
    // Numeric fields should be present
    let cores = value_at_path(&env, &["host", "cpu_cores_logical"]);
    assert!(cores.is_number(), "cpu_cores_logical must be a number");
    let mem = value_at_path(&env, &["host", "memory_bytes"]);
    assert!(mem.is_number(), "memory_bytes must be a number");
}

// ---------- env template: toolchain fields ----------

#[test]
fn env_template_toolchain_has_cargo_llvm_target_and_profile() {
    let env = parse_json_file("docs/templates/env.json.template");
    assert_string_field(&env, &["toolchain", "cargo"]);
    assert_string_field(&env, &["toolchain", "llvm"]);
    assert_string_field(&env, &["toolchain", "target_triple"]);
    assert_string_field(&env, &["toolchain", "profile"]);
}

// ---------- manifest template: source_revision fields ----------

#[test]
fn manifest_template_source_revision_has_repo_branch_commit() {
    let manifest = parse_json_file("docs/templates/manifest.json.template");
    assert_string_field(&manifest, &["source_revision", "repo"]);
    assert_string_field(&manifest, &["source_revision", "branch"]);
    assert_string_field(&manifest, &["source_revision", "commit"]);
}

// ---------- manifest template: artifacts sub-objects ----------

#[test]
fn manifest_template_artifacts_have_path_and_sha256() {
    let manifest = parse_json_file("docs/templates/manifest.json.template");
    let artifact_keys = ["env", "lock", "commands", "results"];
    for key in artifact_keys {
        let artifact = value_at_path(&manifest, &["artifacts", key]);
        assert!(artifact.is_object(), "artifacts.{key} must be an object");
        let path = artifact
            .get("path")
            .unwrap_or_else(|| panic!("artifacts.{key} must have path"));
        assert!(
            path.as_str().is_some(),
            "artifacts.{key}.path must be a string"
        );
        let sha = artifact
            .get("sha256")
            .unwrap_or_else(|| panic!("artifacts.{key} must have sha256"));
        assert!(
            sha.as_str().is_some(),
            "artifacts.{key}.sha256 must be a string"
        );
    }
}

// ---------- manifest template: canonicalization sub-fields ----------

#[test]
fn manifest_template_canonicalization_specifies_lexicographic_and_lf() {
    let manifest = parse_json_file("docs/templates/manifest.json.template");
    let key_order = value_at_path(&manifest, &["canonicalization", "key_order"])
        .as_str()
        .expect("key_order must be a string");
    assert_eq!(
        key_order, "lexicographic",
        "key_order must be lexicographic"
    );

    let newline = value_at_path(&manifest, &["canonicalization", "newline"])
        .as_str()
        .expect("newline must be a string");
    assert_eq!(newline, "lf", "newline must be lf");

    let format = value_at_path(&manifest, &["canonicalization", "format"])
        .as_str()
        .expect("format must be a string");
    assert_eq!(format, "json", "format must be json");
}

// ---------- manifest template: retention min_days ----------

#[test]
fn manifest_template_retention_min_days_are_positive() {
    let manifest = parse_json_file("docs/templates/manifest.json.template");
    let min_days = value_at_path(&manifest, &["retention", "min_days"])
        .as_u64()
        .expect("min_days must be a number");
    assert!(
        min_days >= 365,
        "min_days must be at least 365, got {min_days}"
    );

    let high_impact_min = value_at_path(&manifest, &["retention", "high_impact_min_days"])
        .as_u64()
        .expect("high_impact_min_days must be a number");
    assert!(
        high_impact_min >= 730,
        "high_impact_min_days must be at least 730, got {high_impact_min}"
    );
    assert!(
        high_impact_min >= min_days,
        "high_impact_min_days must be >= min_days"
    );
}

// ---------- repro lock: determinism max_clock_skew_seconds ----------

#[test]
fn repro_lock_determinism_max_clock_skew_is_zero() {
    let lock = parse_json_file("docs/templates/repro.lock.template");
    let skew = value_at_path(&lock, &["determinism", "max_clock_skew_seconds"])
        .as_u64()
        .expect("max_clock_skew_seconds must be a number");
    assert_eq!(skew, 0, "deterministic lock must have zero clock skew");
}

// ---------- repro lock: determinism booleans all false ----------

#[test]
fn repro_lock_determinism_booleans_all_false_by_default() {
    let lock = parse_json_file("docs/templates/repro.lock.template");
    let fields = ["allow_network", "allow_wall_clock", "allow_randomness"];
    for field in fields {
        let val = value_at_path(&lock, &["determinism", field])
            .as_bool()
            .unwrap_or_else(|| panic!("determinism.{field} must be a bool"));
        assert!(
            !val,
            "determinism.{field} must default to false for strict reproducibility"
        );
    }
}

// ---------- repro lock: verification expected_verdict ----------

#[test]
fn repro_lock_verification_expected_verdict_is_pass() {
    let lock = parse_json_file("docs/templates/repro.lock.template");
    let verdict = value_at_path(&lock, &["verification", "expected_verdict"])
        .as_str()
        .expect("expected_verdict must be a string");
    assert_eq!(verdict, "pass", "default expected_verdict must be 'pass'");
}

// ---------- contract doc: error code descriptions ----------

#[test]
fn contract_doc_error_codes_have_descriptions() {
    let doc = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    let code_descriptions = [
        ("FE-REPRO-0001", "missing required file"),
        ("FE-REPRO-0002", "schema validation failure"),
        ("FE-REPRO-0003", "canonicalization mismatch"),
        ("FE-REPRO-0004", "digest mismatch"),
        ("FE-REPRO-0005", "provenance link"),
        ("FE-REPRO-0006", "replay command failed"),
        ("FE-REPRO-0007", "stale policy"),
        ("FE-REPRO-0008", "override"),
    ];
    for (code, keyword) in code_descriptions {
        // Find the line containing the code and verify it has the expected keyword nearby
        let code_pos = doc.find(code).unwrap_or_else(|| panic!("missing {code}"));
        // Take a window of text after the code to check for description
        let window_end = (code_pos + 80).min(doc.len());
        let window = &doc[code_pos..window_end];
        assert!(
            window.to_lowercase().contains(keyword),
            "error code {code} should have description containing '{keyword}', found: {window}"
        );
    }
}

// ---------- contract doc: sections match template guide ----------

#[test]
fn contract_doc_and_template_guide_agree_on_core_file_list() {
    let contract = read_file("docs/REPRODUCIBILITY_CONTRACT.md");
    let guide = read_file("docs/REPRODUCIBILITY_CONTRACT_TEMPLATE.md");
    let core_files = ["env.json", "manifest.json", "repro.lock"];
    for file in core_files {
        assert!(
            contract.contains(file),
            "contract doc must reference core file: {file}"
        );
        assert!(
            guide.contains(file),
            "template guide must reference core file: {file}"
        );
    }
}

// ---------- canonicalize_json: single-key object ----------

#[test]
fn canonicalize_json_single_key_object() {
    let val: Value = serde_json::json!({"only": 99});
    let canon = canonicalize_json(&val);
    assert_eq!(canon, "{\"only\":99}");
}

// ---------- all templates have generated_at_utc ----------

#[test]
fn all_templates_have_generated_at_utc_or_captured_at_utc() {
    // env uses captured_at_utc, manifest and lock use generated_at_utc
    let env = parse_json_file("docs/templates/env.json.template");
    assert!(
        env.get("captured_at_utc").is_some(),
        "env template must have captured_at_utc"
    );
    assert!(
        env.get("captured_at_utc").unwrap().as_str().is_some(),
        "captured_at_utc must be a string"
    );

    let manifest = parse_json_file("docs/templates/manifest.json.template");
    assert!(
        manifest.get("generated_at_utc").is_some(),
        "manifest template must have generated_at_utc"
    );

    let lock = parse_json_file("docs/templates/repro.lock.template");
    assert!(
        lock.get("generated_at_utc").is_some(),
        "repro lock template must have generated_at_utc"
    );
}
