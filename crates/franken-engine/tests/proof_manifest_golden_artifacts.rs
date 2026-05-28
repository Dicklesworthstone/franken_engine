#![forbid(unsafe_code)]

//! Golden artifact tests for ProofManifest deterministic serialization.
//!
//! Tests that ProofManifest structures serialize to canonical JSON and
//! survive round-trip serialization without data loss. The expected JSON
//! lives in `tests/golden/proof_manifest_v1.json` and is regenerated via
//! `UPDATE_GOLDENS=1` (bd-ub6x8.5) — no more hand-editing a multi-line
//! `concat!()` literal in this file.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use frankenengine_engine::proof_artifact::{
    PROOF_MANIFEST_SCHEMA_VERSION, ProofArtifactPaths, ProofArtifactRef, ProofCommand,
    ProofFreshness, ProofManifest, ProofRunStatus, ProofVerifierOutput,
};

const GOLDEN_RELATIVE_PATH: &str = "tests/golden/proof_manifest_v1.json";

fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_RELATIVE_PATH)
}

/// Compare `actual` against the on-disk golden fixture, honoring the
/// project-wide `UPDATE_GOLDENS=1` regen convention (see
/// `tests/golden/PROVENANCE.md`).
fn assert_matches_golden(actual: &str, test_name: &str) {
    let path = golden_path();
    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        fs::write(&path, actual).expect("golden fixture should be writable");
        return;
    }

    let expected = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "{test_name}: golden fixture missing or unreadable at {}: {err}\n\
             Run with UPDATE_GOLDENS=1 to (re)generate it.",
            path.display()
        )
    });

    if actual != expected {
        let actual_path = path.with_extension("actual");
        let _ = fs::write(&actual_path, actual);
        panic!(
            "{test_name}: ProofManifest canonical JSON drifted from golden.\n\
             Expected: {}\n\
             Actual:   {}\n\
             To update: UPDATE_GOLDENS=1 cargo test -p frankenengine-engine \
             --test proof_manifest_golden_artifacts -- {test_name}",
            path.display(),
            actual_path.display(),
        );
    }

    // Sweep stale .actual sibling once we're green (bd-ub6x8.7).
    let _ = fs::remove_file(path.with_extension("actual"));
}

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

    assert_matches_golden(&json1, "test_proof_manifest_deterministic_serialization");

    println!("[proof-manifest-golden] deterministic serialization matches the golden fixture");
}

#[test]
fn test_proof_manifest_no_host_specific_tokens_in_serialization() {
    // Renamed from test_proof_manifest_cross_platform_determinism: the
    // single-process loop below proves only intra-process determinism,
    // not cross-platform behavior, so the new name describes what the
    // test actually asserts — that the canonical JSON matches the golden
    // and carries no host-architecture or OS tokens (bd-ub6x8.5).
    println!("[proof-manifest-golden] checking serialization is host-token-free");

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
            "Single-process determinism violation at iteration {}",
            iteration
        );
    }

    assert_matches_golden(
        reference_json,
        "test_proof_manifest_no_host_specific_tokens_in_serialization",
    );
    assert!(!reference_json.contains("windows"));
    assert!(!reference_json.contains("linux"));
    assert!(!reference_json.contains("darwin"));
    assert!(!reference_json.contains("x86"));
    assert!(!reference_json.contains("arm"));

    println!("[proof-manifest-golden] serialization contains no host-specific tokens");
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

// `expected_manifest_json()` removed: the canonical expected JSON now
// lives at `tests/golden/proof_manifest_v1.json`. `assert_matches_golden`
// reads it from disk and supports the project-wide `UPDATE_GOLDENS=1`
// regen flow (bd-ub6x8.5).
