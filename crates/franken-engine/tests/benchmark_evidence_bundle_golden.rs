//! Golden snapshot test for benchmark_evidence_bundle::generate_report function.
//!
//! This test captures the exact JSON output format of BundleReport to detect
//! unintended schema changes that could break benchmark analysis tools.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use frankenengine_engine::benchmark_evidence_bundle::{
    BenchmarkRun, BundleConfig, EnvironmentSnapshot, EvidenceBundle, ParityTarget, ParityVerdict,
    WorkloadCategory, WorkloadProvenance, generate_report,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// golden_diag lives under tests/_support/ (bd-ub6x8.18); pulled in via #[path]
// so cargo does not compile it as a standalone integration-test binary.
#[path = "_support/golden_diag.rs"]
mod golden_diag;

// Inline assert_golden + summarize_golden_diff replaced by the shared
// GoldenDiag helper (bd-ub6x8.3).

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn deterministic_environment() -> EnvironmentSnapshot {
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

fn create_workload_provenance(id: &str, category: WorkloadCategory) -> WorkloadProvenance {
    WorkloadProvenance {
        workload_id: id.into(),
        name: format!("Workload {id}"),
        category,
        source: "test-corpus".into(),
        pinned_version: "abc123".into(),
        content_hash: ContentHash::compute(id.as_bytes()),
        provenance_epoch: epoch(42),
        tags: BTreeSet::new(),
    }
}

fn create_benchmark_run(
    run_id: &str,
    workload_id: &str,
    duration_us: u64,
    iteration: u32,
) -> BenchmarkRun {
    BenchmarkRun {
        run_id: run_id.into(),
        workload_id: workload_id.into(),
        duration_us,
        peak_memory_bytes: 2_097_152, // 2MB deterministic
        gc_pause_us: 50,
        is_warmup: false,
        iteration,
        environment: deterministic_environment(),
        run_epoch: epoch(42),
    }
}

fn create_parity_verdict(
    workload_id: &str,
    target: ParityTarget,
    ratio_millionths: u64,
) -> ParityVerdict {
    ParityVerdict {
        workload_id: workload_id.into(),
        target,
        output_equivalent: true,
        performance_ratio_millionths: ratio_millionths,
        behavioral_differences: 0,
        difference_details: Vec::new(),
        evidence_hash: ContentHash::compute(format!("{workload_id}:{target:?}").as_bytes()),
    }
}

fn create_deterministic_bundle() -> EvidenceBundle {
    let mut bundle = EvidenceBundle::new("test-bundle-001".into(), epoch(42));

    // Add workload provenances in deterministic order
    bundle
        .add_provenance(create_workload_provenance(
            "micro-001",
            WorkloadCategory::Micro,
        ))
        .unwrap();
    bundle
        .add_provenance(create_workload_provenance(
            "app-001",
            WorkloadCategory::Application,
        ))
        .unwrap();

    // Add benchmark runs in deterministic order
    bundle
        .add_run(create_benchmark_run("run-001", "micro-001", 1500, 1))
        .unwrap();
    bundle
        .add_run(create_benchmark_run("run-002", "micro-001", 1450, 2))
        .unwrap();
    bundle
        .add_run(create_benchmark_run("run-003", "app-001", 15000, 1))
        .unwrap();
    bundle
        .add_run(create_benchmark_run("run-004", "app-001", 14800, 2))
        .unwrap();

    // Add parity verdicts
    bundle
        .add_parity_verdict(create_parity_verdict(
            "micro-001",
            ParityTarget::NodeJs,
            950_000, // 0.95 ratio
        ))
        .unwrap();
    bundle
        .add_parity_verdict(create_parity_verdict(
            "app-001",
            ParityTarget::Deno,
            1_050_000, // 1.05 ratio
        ))
        .unwrap();

    // Seal bundle to prevent further modifications
    bundle.seal().unwrap();
    bundle
}

fn create_deterministic_config() -> BundleConfig {
    BundleConfig {
        min_runs_per_workload: 2,
        max_cv_millionths: 100_000, // 0.1
        min_parity_ratio: 900_000,  // 0.9
        max_environment_drift: 0,
        required_categories: BTreeSet::new(),
        required_parity_targets: BTreeSet::new(),
        min_verification_epoch: epoch(40),
    }
}

// ---------------------------------------------------------------------------
// Golden snapshot test
// ---------------------------------------------------------------------------

#[test]
fn golden_bundle_report_deterministic_output() {
    // Create deterministic test fixtures
    let bundle = create_deterministic_bundle();
    let config = create_deterministic_config();

    // Generate report
    let report = generate_report(&bundle, &config);

    // Serialize to JSON with consistent formatting
    let report_json =
        serde_json::to_string_pretty(&report).expect("BundleReport should be JSON serializable");

    // Assert against golden snapshot via shared GoldenDiag helper.
    let test_name = "bundle_report_output";
    let fixture_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/golden/{test_name}.golden"));
    golden_diag::GoldenDiag {
        framework_name: "Benchmark evidence bundle golden",
        regen_env_var: "UPDATE_GOLDENS",
    }
    .assert_golden_match(&report_json, &fixture_path, test_name, None);
}
