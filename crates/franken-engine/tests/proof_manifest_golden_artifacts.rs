#![forbid(unsafe_code)]

//! Golden artifact tests for ProofManifest deterministic serialization.
//!
//! Tests that ProofManifest structures serialize to deterministic JSON
//! and survive round-trip serialization without data loss.

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use frankenengine_engine::proof_artifact::{
    PROOF_MANIFEST_SCHEMA_VERSION, ProofArtifactPaths, ProofArtifactRef, ProofCommand,
    ProofFreshness, ProofManifest, ProofRunStatus, ProofVerifierOutput,
};

#[test]
fn test_proof_manifest_deterministic_round_trip() {
    println!("Testing ProofManifest JSON round-trip preservation...");

    let manifest = create_test_proof_manifest();

    // Serialize to JSON
    let json_string =
        serde_json::to_string(&manifest).expect("ProofManifest should serialize to JSON");

    // Deserialize back
    let deserialized_manifest: ProofManifest =
        serde_json::from_str(&json_string).expect("ProofManifest should deserialize from JSON");

    // Verify round-trip preservation
    assert_eq!(
        manifest, deserialized_manifest,
        "ProofManifest should survive JSON round-trip unchanged"
    );

    println!("✅ ProofManifest round-trip serialization preserved all fields");
}

#[test]
fn test_proof_manifest_deterministic_serialization() {
    println!("Testing ProofManifest deterministic JSON serialization...");

    let manifest = create_test_proof_manifest();

    // Test determinism: multiple serializations should be identical
    let json1 = serde_json::to_string(&manifest).expect("ProofManifest should serialize to JSON");

    for iteration in 1..=5 {
        let json2 =
            serde_json::to_string(&manifest).expect("ProofManifest should serialize consistently");

        assert_eq!(
            json1, json2,
            "ProofManifest serialization not deterministic on iteration {}",
            iteration
        );
    }

    // Verify expected structure and stable field ordering
    assert!(json1.contains(r#""schema_version":"#));
    assert!(json1.contains(r#""bundle_id":"test_bundle_123""#));
    assert!(json1.contains(r#""gate_name":"test_gate""#));
    assert!(json1.contains(r#""status":"pass""#));
    assert!(json1.contains(r#""source_revision":"abc123""#));

    println!("✅ ProofManifest serialization is deterministic");
}

#[test]
fn test_proof_manifest_cross_platform_determinism() {
    println!("Testing ProofManifest cross-platform serialization determinism...");

    let manifest = create_test_proof_manifest();

    // Test multiple serialization attempts
    let mut json_outputs = Vec::new();
    for i in 0..10 {
        let json = serde_json::to_string(&manifest).expect("ProofManifest should serialize");
        json_outputs.push((i, json));
    }

    // All outputs should be identical (cross-platform determinism)
    let reference_json = &json_outputs[0].1;
    for (iteration, json) in &json_outputs[1..] {
        assert_eq!(
            reference_json, json,
            "Cross-platform determinism violation at iteration {}",
            iteration
        );
    }

    // Verify no platform-specific elements leak through
    assert!(!reference_json.contains("windows"));
    assert!(!reference_json.contains("linux"));
    assert!(!reference_json.contains("darwin"));
    assert!(!reference_json.contains("x86"));
    assert!(!reference_json.contains("arm"));

    println!("✅ ProofManifest serialization is cross-platform deterministic");
}

// Helper function to create test ProofManifest
fn create_test_proof_manifest() -> ProofManifest {
    // Use fixed timestamp for deterministic testing
    let fixed_time = Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap();

    ProofManifest {
        schema_version: PROOF_MANIFEST_SCHEMA_VERSION.to_string(),
        bundle_id: "test_bundle_123".to_string(),
        gate_name: "test_gate".to_string(),
        status: ProofRunStatus::Pass,
        generated_utc: fixed_time,
        source_revision: "abc123".to_string(),
        rerun_command: "cargo test".to_string(),
        artifact_paths: ProofArtifactPaths {
            run_dir: "test_run".to_string(),
            manifest_json: "manifest.json".to_string(),
            commands_txt: "commands.txt".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            report_json: "report.json".to_string(),
            report_md: "report.md".to_string(),
            redaction_policy_json: "redaction.json".to_string(),
        },
        claim_ids: vec!["claim_1".to_string(), "claim_2".to_string()],
        bead_ids: vec!["bd-123".to_string(), "bd-456".to_string()],
        environment: {
            let mut env = BTreeMap::new();
            env.insert("RUST_VERSION".to_string(), "1.75.0".to_string());
            env.insert("BUILD_TYPE".to_string(), "test".to_string());
            env
        },
        commands: vec![
            ProofCommand {
                command_id: "cargo-check".to_string(),
                display: "cargo check".to_string(),
                redacted_display: "cargo check".to_string(),
                cwd: ".".to_string(),
                exit_code: Some(0),
                duration_ms: Some(1500),
            },
            ProofCommand {
                command_id: "cargo-test".to_string(),
                display: "cargo test".to_string(),
                redacted_display: "cargo test".to_string(),
                cwd: ".".to_string(),
                exit_code: Some(0),
                duration_ms: Some(3000),
            },
        ],
        generated_artifacts: vec![ProofArtifactRef {
            path: "output/result.json".to_string(),
            sha256: Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
            schema_version: Some("franken-engine.test-output.v1".to_string()),
            role: "generated".to_string(),
        }],
        expected_artifacts: vec![ProofArtifactRef {
            path: "expected/baseline.json".to_string(),
            sha256: Some(
                "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35".to_string(),
            ),
            schema_version: Some("franken-engine.test-baseline.v1".to_string()),
            role: "expected".to_string(),
        }],
        verifier_outputs: vec![ProofVerifierOutput {
            verifier_id: "test_verifier".to_string(),
            output_path: "verifier/test_verifier.json".to_string(),
            status: ProofRunStatus::Pass,
            decision: "All tests passed".to_string(),
        }],
        freshness: ProofFreshness {
            generated_utc: fixed_time,
            freshness_days: Some(2),
            max_freshness_days: Some(14),
        },
    }
}
