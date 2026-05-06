/*!
 * Proof Artifact Contract Conformance Harness
 *
 * Validates that proof-artifact bundles produced by gates conform to the
 * cd3d2b4d contract specification. Tests real bundles from different gates.
 */

use frankenengine_engine::proof_artifact::{
    PROOF_MANIFEST_SCHEMA_VERSION, REDACTION_POLICY_SCHEMA_VERSION, validate_events_jsonl_file,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Sample proof-artifact bundles from different gates for conformance testing
const SAMPLE_BUNDLES: &[&str] = &[
    "artifacts/containment_latency_metric/20260501T053342Z/pass",
    "artifacts/containment_latency_metric/20260501T053342Z/fail_closed",
    "artifacts/replay_coverage_metric/20260501T095307Z/pass",
    "artifacts/red_team_compromise_rate_metric/20260501T051810Z/pass",
];

/// Expected artifact roles per cd3d2b4d contract
const REQUIRED_ARTIFACT_ROLES: &[&str] = &[
    "command_transcript",
    "structured_events",
    "source_machine_report",
    "redaction_policy",
];

#[derive(Debug)]
struct ConformanceResult {
    bundle_path: String,
    passed: bool,
    errors: Vec<String>,
}

#[test]
fn proof_artifact_contract_conformance() {
    let mut results = Vec::new();
    let mut total_passed = 0;
    let mut total_tested = 0;

    for bundle_path in SAMPLE_BUNDLES {
        total_tested += 1;
        let result = validate_proof_bundle(bundle_path);

        println!(
            "Bundle: {} - {}",
            bundle_path,
            if result.passed {
                "✓ PASS"
            } else {
                "✗ FAIL"
            }
        );

        for error in &result.errors {
            println!("  ERROR: {}", error);
        }

        if result.passed {
            total_passed += 1;
        }

        results.push(result);
    }

    println!("\nProof Artifact Contract Conformance Summary:");
    println!("  Tested: {} bundles", total_tested);
    println!("  Passed: {} bundles", total_passed);
    println!("  Failed: {} bundles", total_tested - total_passed);

    if total_passed == total_tested {
        println!("🎉 CONFORMANCE HARNESS SHIPS CLEAN — proof-artifact contract is robust");
    } else {
        println!("⚠ CONFORMANCE FAILURES DETECTED — filing beads for contract gaps");

        // Print detailed failure summary for bead filing
        println!("\nDetailed failures for bead filing:");
        for result in &results {
            if !result.passed {
                println!("Bundle: {}", result.bundle_path);
                for error in &result.errors {
                    println!("  - {}", error);
                }
            }
        }

        panic!(
            "Proof artifact contract conformance failures detected. See output for bead filing details."
        );
    }
}

fn validate_proof_bundle(bundle_path: &str) -> ConformanceResult {
    let mut errors = Vec::new();
    let path = Path::new(bundle_path);

    if !path.exists() {
        errors.push(format!("Bundle directory does not exist: {}", bundle_path));
        return ConformanceResult {
            bundle_path: bundle_path.to_string(),
            passed: false,
            errors,
        };
    }

    // 1. Validate manifest.json against cd3d2b4d schema
    if let Err(e) = validate_manifest_schema(&path.join("manifest.json")) {
        errors.push(format!("Manifest schema validation failed: {}", e));
    }

    // 2. Validate events.jsonl using bd-22d01 validator
    if let Err(e) = validate_events_jsonl(&path.join("events.jsonl")) {
        errors.push(format!("Events JSONL validation failed: {}", e));
    }

    // 3. Check hash chain integrity
    if let Err(e) = validate_hash_chain_integrity(path) {
        errors.push(format!("Hash chain integrity check failed: {}", e));
    }

    // 4. Confirm all required fields present
    if let Err(e) = validate_required_fields(&path.join("manifest.json")) {
        errors.push(format!("Required fields validation failed: {}", e));
    }

    // 5. Verify redaction rules applied (bd-29n87)
    if let Err(e) = validate_redaction_compliance(path) {
        errors.push(format!("Redaction compliance validation failed: {}", e));
    }

    ConformanceResult {
        bundle_path: bundle_path.to_string(),
        passed: errors.is_empty(),
        errors,
    }
}

/// Validates manifest.json against the cd3d2b4d contract schema
fn validate_manifest_schema(manifest_path: &Path) -> Result<(), String> {
    if !manifest_path.exists() {
        return Err("manifest.json not found".to_string());
    }

    let content =
        fs::read_to_string(manifest_path).map_err(|e| format!("Failed to read manifest: {}", e))?;

    let manifest: Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON in manifest: {}", e))?;

    // Validate schema version
    let schema_version = manifest
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or("Missing or invalid schema_version")?;

    if schema_version != PROOF_MANIFEST_SCHEMA_VERSION {
        return Err(format!(
            "Invalid schema version: expected '{}', got '{}'",
            PROOF_MANIFEST_SCHEMA_VERSION, schema_version
        ));
    }

    // Validate required top-level fields
    let required_fields = &[
        "bundle_id",
        "gate_name",
        "status",
        "generated_utc",
        "source_revision",
        "artifact_paths",
        "generated_artifacts",
    ];

    for field in required_fields {
        if manifest.get(field).is_none() {
            return Err(format!("Missing required field: {}", field));
        }
    }

    // Validate artifact_paths structure
    let artifact_paths = manifest
        .get("artifact_paths")
        .ok_or("Missing artifact_paths")?;

    let required_artifact_paths = &[
        "run_dir",
        "manifest_json",
        "commands_txt",
        "events_jsonl",
        "report_json",
        "report_md",
    ];

    for path_field in required_artifact_paths {
        if artifact_paths.get(path_field).is_none() {
            return Err(format!("Missing artifact path: {}", path_field));
        }
    }

    Ok(())
}

/// Validates events.jsonl using the existing validator from bd-22d01
fn validate_events_jsonl(events_path: &Path) -> Result<(), String> {
    if !events_path.exists() {
        return Err("events.jsonl not found".to_string());
    }

    let summary = validate_events_jsonl_file(events_path)
        .map_err(|e| format!("Events JSONL validation error: {}", e))?;

    if summary.is_empty() {
        return Err("Events JSONL file is empty".to_string());
    }

    Ok(())
}

/// Validates hash chain integrity across bundle artifacts
fn validate_hash_chain_integrity(bundle_path: &Path) -> Result<(), String> {
    let manifest_path = bundle_path.join("manifest.json");
    let manifest_content = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Failed to read manifest: {}", e))?;

    let manifest: Value = serde_json::from_str(&manifest_content)
        .map_err(|e| format!("Invalid JSON in manifest: {}", e))?;

    let generated_artifacts = manifest
        .get("generated_artifacts")
        .and_then(|v| v.as_array())
        .ok_or("Missing or invalid generated_artifacts array")?;

    for (i, artifact) in generated_artifacts.iter().enumerate() {
        let path = artifact
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("Artifact {} missing path", i))?;

        let expected_sha256 = artifact.get("sha256").and_then(|v| v.as_str());

        if expected_sha256.is_none() {
            continue; // Some artifacts (like redaction policy) may have null hashes
        }

        let expected_sha256 = expected_sha256.unwrap();

        // Calculate actual hash
        let artifact_path = Path::new(path);
        let actual_sha256 = calculate_file_sha256(artifact_path)
            .map_err(|e| format!("Failed to hash {}: {}", path, e))?;

        if actual_sha256 != expected_sha256 {
            return Err(format!(
                "Hash mismatch for {}: expected {}, got {}",
                path, expected_sha256, actual_sha256
            ));
        }
    }

    Ok(())
}

/// Validates that all required fields are present in manifest
fn validate_required_fields(manifest_path: &Path) -> Result<(), String> {
    let content =
        fs::read_to_string(manifest_path).map_err(|e| format!("Failed to read manifest: {}", e))?;

    let manifest: Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON in manifest: {}", e))?;

    // Check that generated_artifacts contain all required roles
    let generated_artifacts = manifest
        .get("generated_artifacts")
        .and_then(|v| v.as_array())
        .ok_or("Missing generated_artifacts")?;

    let mut found_roles = HashMap::new();

    for artifact in generated_artifacts {
        if let Some(role) = artifact.get("role").and_then(|v| v.as_str()) {
            found_roles.insert(role, true);
        }
    }

    for required_role in REQUIRED_ARTIFACT_ROLES {
        if !found_roles.contains_key(required_role) {
            return Err(format!("Missing required artifact role: {}", required_role));
        }
    }

    // Validate freshness structure
    let freshness = manifest
        .get("freshness")
        .ok_or("Missing freshness object")?;

    let required_freshness_fields = &["generated_utc", "freshness_days", "max_freshness_days"];
    for field in required_freshness_fields {
        if freshness.get(field).is_none() {
            return Err(format!("Missing freshness field: {}", field));
        }
    }

    Ok(())
}

/// Validates redaction compliance per bd-29n87 rules
fn validate_redaction_compliance(bundle_path: &Path) -> Result<(), String> {
    let redaction_policy_path = bundle_path.join("redaction_policy.json");

    if !redaction_policy_path.exists() {
        return Err("redaction_policy.json not found".to_string());
    }

    let content = fs::read_to_string(&redaction_policy_path)
        .map_err(|e| format!("Failed to read redaction policy: {}", e))?;

    let policy: Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON in redaction policy: {}", e))?;

    // Validate schema version
    let schema_version = policy
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or("Missing schema_version in redaction policy")?;

    if schema_version != REDACTION_POLICY_SCHEMA_VERSION {
        return Err(format!(
            "Invalid redaction policy schema version: expected '{}', got '{}'",
            REDACTION_POLICY_SCHEMA_VERSION, schema_version
        ));
    }

    // Validate required redaction fields
    let replacement = policy
        .get("replacement")
        .and_then(|v| v.as_str())
        .ok_or("Missing replacement field in redaction policy")?;

    if replacement != "<redacted>" {
        return Err(format!(
            "Invalid replacement value: expected '<redacted>', got '{}'",
            replacement
        ));
    }

    let env_key_fragments = policy
        .get("env_key_fragments")
        .and_then(|v| v.as_array())
        .ok_or("Missing env_key_fragments array")?;

    // Check that standard sensitive patterns are included
    let required_patterns = &["TOKEN", "SECRET", "PASSWORD", "KEY", "AUTH"];
    let fragments_str: Vec<String> = env_key_fragments
        .iter()
        .filter_map(|v| v.as_str())
        .map(|s| s.to_string())
        .collect();

    for pattern in required_patterns {
        if !fragments_str.iter().any(|f| f.contains(pattern)) {
            return Err(format!("Missing required redaction pattern: {}", pattern));
        }
    }

    // Validate that commands.txt and manifest.json don't contain obvious secrets
    validate_no_secrets_in_file(&bundle_path.join("commands.txt"))?;
    validate_no_secrets_in_file(&bundle_path.join("manifest.json"))?;

    Ok(())
}

/// Checks that a file doesn't contain obvious unredacted secrets
fn validate_no_secrets_in_file(file_path: &Path) -> Result<(), String> {
    if !file_path.exists() {
        return Ok(()); // File might not exist in all bundles
    }

    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("Failed to read {}: {}", file_path.display(), e))?;

    // Check for obvious unredacted secret patterns
    let secret_patterns = &[
        "Bearer ey",         // JWT tokens
        "sk-[a-zA-Z0-9]",    // OpenAI API keys
        "TOKEN=[a-zA-Z0-9]", // Environment variables
        "SECRET=[a-zA-Z0-9]",
        "PASSWORD=[a-zA-Z0-9]",
    ];

    for pattern in secret_patterns {
        if content.contains(&pattern[..6]) {
            // Simple substring check
            return Err(format!(
                "File {} contains potential unredacted secret matching pattern: {}",
                file_path.display(),
                pattern
            ));
        }
    }

    Ok(())
}

/// Calculates SHA256 hash of a file
fn calculate_file_sha256(path: &Path) -> Result<String, String> {
    let content = fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hasher.finalize();

    Ok(format!("{:x}", hash))
}

#[cfg(test)]
mod conformance_unit_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_manifest_schema_validation() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");

        // Valid manifest
        let valid_manifest = serde_json::json!({
            "schema_version": "franken-engine.proof-artifact-manifest.v1",
            "bundle_id": "test-bundle",
            "gate_name": "test_gate",
            "status": "pass",
            "generated_utc": "2026-05-01T10:00:00Z",
            "source_revision": "abc123",
            "artifact_paths": {
                "run_dir": "test/dir",
                "manifest_json": "test/manifest.json",
                "commands_txt": "test/commands.txt",
                "events_jsonl": "test/events.jsonl",
                "report_json": "test/report.json",
                "report_md": "test/report.md"
            },
            "generated_artifacts": []
        });

        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&valid_manifest).unwrap(),
        )
        .unwrap();
        assert!(validate_manifest_schema(&manifest_path).is_ok());

        // Invalid schema version
        let invalid_manifest = serde_json::json!({
            "schema_version": "invalid-version",
            "bundle_id": "test-bundle"
        });

        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&invalid_manifest).unwrap(),
        )
        .unwrap();
        assert!(validate_manifest_schema(&manifest_path).is_err());
    }

    #[test]
    fn test_redaction_validation() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("redaction_policy.json");

        let valid_policy = serde_json::json!({
            "schema_version": "franken-engine.proof-artifact-redaction-policy.v1",
            "replacement": "<redacted>",
            "env_key_fragments": ["TOKEN", "SECRET", "PASSWORD", "KEY", "AUTH"],
            "literal_patterns": []
        });

        fs::write(
            &policy_path,
            serde_json::to_string_pretty(&valid_policy).unwrap(),
        )
        .unwrap();

        // Create empty commands.txt to avoid file not found error
        fs::write(temp_dir.path().join("commands.txt"), "").unwrap();
        fs::write(temp_dir.path().join("manifest.json"), "{}").unwrap();

        assert!(validate_redaction_compliance(temp_dir.path()).is_ok());
    }
}
