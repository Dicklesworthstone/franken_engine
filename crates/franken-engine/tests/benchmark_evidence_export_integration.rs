//! Integration tests for benchmark evidence export functionality.
//!
//! Tests the binary integration between evidence bundles, the export binary,
//! and cc_2's benchmark gate for publication-grade evidence with provenance.

#![allow(clippy::needless_borrows_for_generic_args)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::process::Command;
use tempfile::TempDir;

use frankenengine_engine::benchmark_evidence_bundle::{
    BenchmarkRun, BundleConfig, EnvironmentSnapshot, EvidenceBundle, ParityTarget, ParityVerdict,
    WorkloadCategory, WorkloadProvenance, export_bundle_json, export_bundle_toml,
    export_report_json, export_report_toml, generate_report,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn test_environment() -> EnvironmentSnapshot {
    EnvironmentSnapshot::new(
        "linux".into(),
        "x86_64".into(),
        16,
        64_000_000_000,
        "node 22.1.0".into(),
        "franken 0.1.0".into(),
        BTreeMap::new(),
    )
}

fn test_provenance(id: &str, category: WorkloadCategory) -> WorkloadProvenance {
    WorkloadProvenance {
        workload_id: id.into(),
        name: format!("Test workload {id}"),
        category,
        source: "test-corpus".into(),
        pinned_version: "abc123".into(),
        content_hash: ContentHash::compute(id.as_bytes()),
        provenance_epoch: epoch(1),
        tags: BTreeSet::new(),
    }
}

fn test_run(id: &str, workload_id: &str, duration_us: u64, iteration: u32) -> BenchmarkRun {
    BenchmarkRun {
        run_id: id.into(),
        workload_id: workload_id.into(),
        duration_us,
        peak_memory_bytes: 1024,
        gc_pause_us: 0,
        is_warmup: false,
        iteration,
        environment: test_environment(),
        run_epoch: epoch(5),
    }
}

fn test_parity_verdict(workload_id: &str, target: ParityTarget, ratio: u64) -> ParityVerdict {
    ParityVerdict {
        workload_id: workload_id.into(),
        target,
        output_equivalent: true,
        performance_ratio_millionths: ratio,
        behavioral_differences: 0,
        difference_details: Vec::new(),
        evidence_hash: ContentHash::compute(workload_id.as_bytes()),
    }
}

fn create_test_bundle() -> EvidenceBundle {
    let mut bundle = EvidenceBundle::new("test-bundle-001".into(), epoch(5));

    // Add workload provenance
    bundle
        .add_provenance(test_provenance("micro-1", WorkloadCategory::Micro))
        .unwrap();
    bundle
        .add_provenance(test_provenance("app-1", WorkloadCategory::Application))
        .unwrap();

    // Add benchmark runs
    for i in 0..5 {
        bundle
            .add_run(test_run(
                &format!("run-micro-{i}"),
                "micro-1",
                1000 + i * 10,
                i as u32,
            ))
            .unwrap();
        bundle
            .add_run(test_run(
                &format!("run-app-{i}"),
                "app-1",
                5000 + i * 50,
                i as u32,
            ))
            .unwrap();
    }

    // Add parity verdicts
    bundle
        .add_parity_verdict(test_parity_verdict(
            "micro-1",
            ParityTarget::NodeJs,
            980_000,
        ))
        .unwrap();
    bundle
        .add_parity_verdict(test_parity_verdict("app-1", ParityTarget::Bun, 950_000))
        .unwrap();

    // Seal the bundle
    bundle.seal().unwrap();

    bundle
}

fn create_gate_manifest() -> serde_json::Value {
    serde_json::json!({
        "timestamp": "2026-04-20T06:12:00Z",
        "engine": "node",
        "results": [
            {
                "test_name": "micro-1",
                "value": 1.0,
                "unit": "ms",
                "metadata": {}
            },
            {
                "test_name": "app-1",
                "value": 5.2,
                "unit": "ms",
                "metadata": {}
            }
        ]
    })
}

// ---------------------------------------------------------------------------
// Export Function Tests
// ---------------------------------------------------------------------------

#[test]
fn export_bundle_json_produces_valid_json() {
    let bundle = create_test_bundle();
    let json = export_bundle_json(&bundle).unwrap();

    // Verify it's valid JSON by parsing it back
    let parsed: EvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle.bundle_id, parsed.bundle_id);
    assert_eq!(bundle.runs.len(), parsed.runs.len());
    assert_eq!(bundle.provenances.len(), parsed.provenances.len());
}

#[test]
fn export_bundle_toml_produces_valid_toml() {
    let bundle = create_test_bundle();
    let toml_str = export_bundle_toml(&bundle).unwrap();

    // Verify it's valid TOML by parsing it back
    let parsed: EvidenceBundle = toml::from_str(&toml_str).unwrap();
    assert_eq!(bundle.bundle_id, parsed.bundle_id);
    assert_eq!(bundle.runs.len(), parsed.runs.len());
    assert_eq!(bundle.provenances.len(), parsed.provenances.len());
}

#[test]
fn export_report_json_contains_expected_fields() {
    let bundle = create_test_bundle();
    let config = BundleConfig::default();
    let report = generate_report(&bundle, &config);
    let json = export_report_json(&report).unwrap();

    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["bundle_id"], "test-bundle-001");
    assert_eq!(parsed["total_workloads"], 2);
    assert_eq!(parsed["total_effective_runs"], 10);
}

#[test]
fn export_report_toml_contains_expected_fields() {
    let bundle = create_test_bundle();
    let config = BundleConfig::default();
    let report = generate_report(&bundle, &config);
    let toml_str = export_report_toml(&report).unwrap();

    let parsed: toml::Value = toml::from_str(&toml_str).unwrap();
    assert_eq!(
        parsed["bundle_id"],
        toml::Value::String("test-bundle-001".into())
    );
    assert_eq!(parsed["total_workloads"], toml::Value::Integer(2));
    assert_eq!(parsed["total_effective_runs"], toml::Value::Integer(10));
}

// ---------------------------------------------------------------------------
// Binary Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn binary_exports_bundle_to_json() {
    let temp_dir = TempDir::new().unwrap();
    let bundle = create_test_bundle();

    // Write input bundle
    let input_path = temp_dir.path().join("input.json");
    let bundle_json = serde_json::to_string_pretty(&bundle).unwrap();
    fs::write(&input_path, bundle_json).unwrap();

    // Export via binary
    let output_path = temp_dir.path().join("output.json");
    let status = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "franken-benchmark-evidence-export",
            "--",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "-f",
            "json",
            "-t",
            "bundle",
        ])
        .current_dir("crates/franken-engine")
        .status()
        .unwrap();

    assert!(status.success(), "Binary execution failed");

    // Verify output
    let output_content = fs::read_to_string(&output_path).unwrap();
    let parsed: EvidenceBundle = serde_json::from_str(&output_content).unwrap();
    assert_eq!(parsed.bundle_id, "test-bundle-001");
}

#[test]
fn binary_exports_bundle_to_toml() {
    let temp_dir = TempDir::new().unwrap();
    let bundle = create_test_bundle();

    // Write input bundle
    let input_path = temp_dir.path().join("input.json");
    let bundle_json = serde_json::to_string_pretty(&bundle).unwrap();
    fs::write(&input_path, bundle_json).unwrap();

    // Export via binary
    let output_path = temp_dir.path().join("output.toml");
    let status = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "franken-benchmark-evidence-export",
            "--",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "-f",
            "toml",
            "-t",
            "bundle",
        ])
        .current_dir("crates/franken-engine")
        .status()
        .unwrap();

    assert!(status.success(), "Binary execution failed");

    // Verify output
    let output_content = fs::read_to_string(&output_path).unwrap();
    let parsed: EvidenceBundle = toml::from_str(&output_content).unwrap();
    assert_eq!(parsed.bundle_id, "test-bundle-001");
}

#[test]
fn binary_exports_report_to_json() {
    let temp_dir = TempDir::new().unwrap();
    let bundle = create_test_bundle();

    // Write input bundle
    let input_path = temp_dir.path().join("input.json");
    let bundle_json = serde_json::to_string_pretty(&bundle).unwrap();
    fs::write(&input_path, bundle_json).unwrap();

    // Export via binary
    let output_path = temp_dir.path().join("report.json");
    let status = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "franken-benchmark-evidence-export",
            "--",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "-f",
            "json",
            "-t",
            "report",
        ])
        .current_dir("crates/franken-engine")
        .status()
        .unwrap();

    assert!(status.success(), "Binary execution failed");

    // Verify output
    let output_content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output_content).unwrap();
    assert_eq!(parsed["bundle_id"], "test-bundle-001");
    assert_eq!(parsed["total_workloads"], 2);
}

#[test]
fn binary_integrates_with_gate_manifest() {
    let temp_dir = TempDir::new().unwrap();
    let mut bundle = create_test_bundle();

    // Remove existing parity verdicts to test gate integration
    bundle.parity_verdicts.clear();

    // Write input bundle
    let input_path = temp_dir.path().join("input.json");
    let bundle_json = serde_json::to_string_pretty(&bundle).unwrap();
    fs::write(&input_path, bundle_json).unwrap();

    // Write gate manifest
    let gate_path = temp_dir.path().join("gate.json");
    let gate_manifest = create_gate_manifest();
    fs::write(
        &gate_path,
        serde_json::to_string_pretty(&gate_manifest).unwrap(),
    )
    .unwrap();

    // Export with gate integration
    let output_path = temp_dir.path().join("output.json");
    let status = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "franken-benchmark-evidence-export",
            "--",
            "-i",
            input_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
            "-f",
            "json",
            "-t",
            "bundle",
            "--gate-integration",
            gate_path.to_str().unwrap(),
        ])
        .current_dir("crates/franken-engine")
        .status()
        .unwrap();

    assert!(
        status.success(),
        "Binary execution with gate integration failed"
    );

    // Verify gate integration added parity verdicts
    let output_content = fs::read_to_string(&output_path).unwrap();
    let parsed: EvidenceBundle = serde_json::from_str(&output_content).unwrap();
    assert!(
        !parsed.parity_verdicts.is_empty(),
        "Gate integration should add parity verdicts"
    );
}

// ---------------------------------------------------------------------------
// Provenance Hash Verification
// ---------------------------------------------------------------------------

#[test]
fn exported_bundles_preserve_provenance_hashes() {
    let bundle = create_test_bundle();
    let original_hash = bundle.bundle_hash;

    // Export to JSON and back
    let json = export_bundle_json(&bundle).unwrap();
    let json_bundle: EvidenceBundle = serde_json::from_str(&json).unwrap();

    // Export to TOML and back
    let toml_str = export_bundle_toml(&bundle).unwrap();
    let toml_bundle: EvidenceBundle = toml::from_str(&toml_str).unwrap();

    // All hashes should be identical
    assert_eq!(original_hash, json_bundle.bundle_hash);
    assert_eq!(original_hash, toml_bundle.bundle_hash);
}

#[test]
fn report_hashes_are_deterministic() {
    let bundle = create_test_bundle();
    let config = BundleConfig::default();

    let report1 = generate_report(&bundle, &config);
    let report2 = generate_report(&bundle, &config);

    assert_eq!(report1.report_hash, report2.report_hash);
}

// ---------------------------------------------------------------------------
// Cross-Format Compatibility
// ---------------------------------------------------------------------------

#[test]
fn json_and_toml_exports_are_equivalent() {
    let bundle = create_test_bundle();

    let json = export_bundle_json(&bundle).unwrap();
    let toml_str = export_bundle_toml(&bundle).unwrap();

    let from_json: EvidenceBundle = serde_json::from_str(&json).unwrap();
    let from_toml: EvidenceBundle = toml::from_str(&toml_str).unwrap();

    // Key fields should be identical
    assert_eq!(from_json.bundle_id, from_toml.bundle_id);
    assert_eq!(from_json.bundle_hash, from_toml.bundle_hash);
    assert_eq!(from_json.runs.len(), from_toml.runs.len());
    assert_eq!(from_json.provenances.len(), from_toml.provenances.len());
    assert_eq!(
        from_json.parity_verdicts.len(),
        from_toml.parity_verdicts.len()
    );
}
