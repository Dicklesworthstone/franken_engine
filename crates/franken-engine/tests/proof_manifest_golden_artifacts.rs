#![forbid(unsafe_code)]

//! Golden artifact tests for ProofManifest deterministic serialization.
//!
//! Tests that ProofManifest structures serialize to canonical JSON and
//! survive round-trip serialization without data loss.

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use frankenengine_engine::proof_artifact::{
    PROOF_MANIFEST_SCHEMA_VERSION, ProofArtifactPaths, ProofArtifactRef, ProofCommand,
    ProofFreshness, ProofManifest, ProofRunStatus, ProofVerifierOutput,
};

#[test]
fn test_proof_manifest_deterministic_round_trip() {
    println!("[proof-manifest-golden] checking JSON round-trip preservation");

    let manifest = create_test_proof_manifest();
    manifest
        .validate()
        .expect("golden ProofManifest should satisfy the production validator");

    let json_string =
        serde_json::to_string(&manifest).expect("ProofManifest should serialize to JSON");

    let deserialized_manifest: ProofManifest =
        serde_json::from_str(&json_string).expect("ProofManifest should deserialize from JSON");

    assert_eq!(
        manifest, deserialized_manifest,
        "ProofManifest should survive JSON round-trip unchanged"
    );

    println!("[proof-manifest-golden] round-trip serialization preserved all fields");
}

#[test]
fn test_proof_manifest_deterministic_serialization() {
    println!("[proof-manifest-golden] checking deterministic JSON serialization");

    let manifest = create_test_proof_manifest();

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

    assert_eq!(
        json1,
        expected_manifest_json(),
        "ProofManifest canonical JSON drifted; update this test only when the manifest schema intentionally changes"
    );

    println!("[proof-manifest-golden] deterministic serialization matches the golden fixture");
}

#[test]
fn test_proof_manifest_cross_platform_determinism() {
    println!("[proof-manifest-golden] checking cross-platform JSON determinism");

    let manifest = create_test_proof_manifest();

    let mut json_outputs = Vec::new();
    for i in 0..10 {
        let json = serde_json::to_string(&manifest).expect("ProofManifest should serialize");
        json_outputs.push((i, json));
    }

    let reference_json = &json_outputs[0].1;
    for (iteration, json) in &json_outputs[1..] {
        assert_eq!(
            reference_json, json,
            "Cross-platform determinism violation at iteration {}",
            iteration
        );
    }

    assert_eq!(
        reference_json,
        expected_manifest_json(),
        "ProofManifest must not include host-specific ordering, paths, or timestamps"
    );
    assert!(!reference_json.contains("windows"));
    assert!(!reference_json.contains("linux"));
    assert!(!reference_json.contains("darwin"));
    assert!(!reference_json.contains("x86"));
    assert!(!reference_json.contains("arm"));

    println!("[proof-manifest-golden] cross-platform deterministic serialization verified");
}

fn create_test_proof_manifest() -> ProofManifest {
    let fixed_time = Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap();

    ProofManifest {
        schema_version: PROOF_MANIFEST_SCHEMA_VERSION.to_string(),
        bundle_id: "test_bundle_123".to_string(),
        gate_name: "test_gate".to_string(),
        status: ProofRunStatus::Pass,
        generated_utc: fixed_time,
        source_revision: "abc1234".to_string(),
        rerun_command:
            "cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts -- --nocapture"
                .to_string(),
        artifact_paths: ProofArtifactPaths::standard("artifacts/proof_manifest_golden/run")
            .expect("standard proof-manifest golden paths should be valid"),
        claim_ids: vec!["claim_1".to_string(), "claim_2".to_string()],
        bead_ids: vec!["bd-123".to_string(), "bd-456".to_string()],
        environment: {
            let mut env = BTreeMap::new();
            env.insert("RUST_VERSION".to_string(), "1.89.0".to_string());
            env.insert("BUILD_TYPE".to_string(), "test".to_string());
            env
        },
        commands: vec![
            ProofCommand {
                command_id: "cargo-check".to_string(),
                display: "cargo check".to_string(),
                redacted_display: "cargo check".to_string(),
                cwd: "artifacts/proof_manifest_golden/run".to_string(),
                exit_code: Some(0),
                duration_ms: Some(1500),
            },
            ProofCommand {
                command_id: "cargo-test".to_string(),
                display: "cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts -- --nocapture".to_string(),
                redacted_display: "cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts -- --nocapture".to_string(),
                cwd: "artifacts/proof_manifest_golden/run".to_string(),
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

fn expected_manifest_json() -> &'static str {
    concat!(
        r#"{"schema_version":"franken-engine.proof-artifact-manifest.v1","#,
        r#""bundle_id":"test_bundle_123","#,
        r#""gate_name":"test_gate","#,
        r#""status":"pass","#,
        r#""generated_utc":"2026-05-01T12:00:00Z","#,
        r#""source_revision":"abc1234","#,
        r#""rerun_command":"cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts -- --nocapture","#,
        r#""artifact_paths":{"run_dir":"artifacts/proof_manifest_golden/run","#,
        r#""manifest_json":"artifacts/proof_manifest_golden/run/manifest.json","#,
        r#""commands_txt":"artifacts/proof_manifest_golden/run/commands.txt","#,
        r#""events_jsonl":"artifacts/proof_manifest_golden/run/events.jsonl","#,
        r#""report_json":"artifacts/proof_manifest_golden/run/report.json","#,
        r#""report_md":"artifacts/proof_manifest_golden/run/report.md","#,
        r#""redaction_policy_json":"artifacts/proof_manifest_golden/run/redaction_policy.json"},"#,
        r#""claim_ids":["claim_1","claim_2"],"#,
        r#""bead_ids":["bd-123","bd-456"],"#,
        r#""environment":{"BUILD_TYPE":"test","RUST_VERSION":"1.89.0"},"#,
        r#""commands":[{"command_id":"cargo-check","#,
        r#""display":"cargo check","#,
        r#""redacted_display":"cargo check","#,
        r#""cwd":"artifacts/proof_manifest_golden/run","#,
        r#""exit_code":0,"#,
        r#""duration_ms":1500},"#,
        r#"{"command_id":"cargo-test","#,
        r#""display":"cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts -- --nocapture","#,
        r#""redacted_display":"cargo test -p frankenengine-engine --test proof_manifest_golden_artifacts -- --nocapture","#,
        r#""cwd":"artifacts/proof_manifest_golden/run","#,
        r#""exit_code":0,"#,
        r#""duration_ms":3000}],"#,
        r#""generated_artifacts":[{"path":"output/result.json","#,
        r#""sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","#,
        r#""schema_version":"franken-engine.test-output.v1","#,
        r#""role":"generated"}],"#,
        r#""expected_artifacts":[{"path":"expected/baseline.json","#,
        r#""sha256":"d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35","#,
        r#""schema_version":"franken-engine.test-baseline.v1","#,
        r#""role":"expected"}],"#,
        r#""verifier_outputs":[{"verifier_id":"test_verifier","#,
        r#""output_path":"verifier/test_verifier.json","#,
        r#""status":"pass","#,
        r#""decision":"All tests passed"}],"#,
        r#""freshness":{"generated_utc":"2026-05-01T12:00:00Z","#,
        r#""freshness_days":2,"#,
        r#""max_freshness_days":14}}"#
    )
}
