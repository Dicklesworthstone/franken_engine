//! Integration tests for the benchmark E2E suite.
//!
//! Tests all 5 benchmark families across 3 scale profiles (15 cases total),
//! plus regression detection, score computation, evidence artifact production,
//! and determinism verification.

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

use std::collections::BTreeMap;
use std::path::PathBuf;

use frankenengine_engine::benchmark_e2e::{
    BenchmarkFamily, BenchmarkMeasurement, BenchmarkSuiteConfig, LatencyDistribution,
    RegressionThresholds, ScaleProfile, Xorshift64, detect_regression, measurements_to_cases,
    run_adversarial_noise_under_load, run_benchmark, run_benchmark_suite,
    run_benchmark_suite_with_regression, run_boot_storm, run_capability_churn,
    run_mixed_cpu_io_agent_mesh, run_reload_revoke_churn, write_evidence_artifacts,
};

fn artifact_dir() -> PathBuf {
    let unique = format!(
        "benchmark-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("artifacts")
        .join("benchmark_e2e")
        .join(unique)
}

// ============================================================================
// Boot-storm family
// ============================================================================

#[test]
fn boot_storm_small() {
    let m = run_boot_storm(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::BootStorm);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert_eq!(m.invariant_violations, 0);
    assert!(m.latency.sample_count > 0);
    assert!(m.latency.p50_us <= m.latency.p95_us);
    assert!(m.latency.p95_us <= m.latency.p99_us);
    assert!(m.latency.min_us <= m.latency.p50_us);
    assert!(m.latency.p99_us <= m.latency.max_us);
}

#[test]
fn boot_storm_medium() {
    let m = run_boot_storm(ScaleProfile::Medium, 42);
    assert_eq!(m.family, BenchmarkFamily::BootStorm);
    assert_eq!(m.profile, ScaleProfile::Medium);
    assert!(m.total_operations > 0);
    assert_eq!(m.invariant_violations, 0);
}

#[test]
fn boot_storm_large() {
    let m = run_boot_storm(ScaleProfile::Large, 42);
    assert_eq!(m.family, BenchmarkFamily::BootStorm);
    assert_eq!(m.profile, ScaleProfile::Large);
    assert!(m.total_operations > 0);
    assert_eq!(m.invariant_violations, 0);
    assert!(m.peak_extensions_alive > 0);
}

// ============================================================================
// Capability-churn family
// ============================================================================

#[test]
fn capability_churn_small() {
    let m = run_capability_churn(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::CapabilityChurn);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert_eq!(m.invariant_violations, 0);
    assert!(m.latency.sample_count > 0);
}

#[test]
fn capability_churn_medium() {
    let m = run_capability_churn(ScaleProfile::Medium, 42);
    assert_eq!(m.family, BenchmarkFamily::CapabilityChurn);
    assert!(m.total_operations > 0);
    assert_eq!(m.invariant_violations, 0);
}

#[test]
fn capability_churn_large() {
    let m = run_capability_churn(ScaleProfile::Large, 42);
    assert_eq!(m.family, BenchmarkFamily::CapabilityChurn);
    assert!(m.total_operations > 0);
    assert_eq!(m.invariant_violations, 0);
}

// ============================================================================
// Mixed CPU/IO agent mesh family
// ============================================================================

#[test]
fn mixed_cpu_io_mesh_small() {
    let m = run_mixed_cpu_io_agent_mesh(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::MixedCpuIoAgentMesh);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert_eq!(m.invariant_violations, 0);
    assert!(m.latency.sample_count > 0);
}

#[test]
fn mixed_cpu_io_mesh_medium() {
    let m = run_mixed_cpu_io_agent_mesh(ScaleProfile::Medium, 42);
    assert_eq!(m.family, BenchmarkFamily::MixedCpuIoAgentMesh);
    assert!(m.total_operations > 0);
    assert_eq!(m.invariant_violations, 0);
}

#[test]
fn mixed_cpu_io_mesh_large() {
    let m = run_mixed_cpu_io_agent_mesh(ScaleProfile::Large, 42);
    assert_eq!(m.family, BenchmarkFamily::MixedCpuIoAgentMesh);
    assert!(m.total_operations > 0);
    assert_eq!(m.invariant_violations, 0);
}

// ============================================================================
// Reload-revoke-churn family
// ============================================================================

#[test]
fn reload_revoke_churn_small() {
    let m = run_reload_revoke_churn(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::ReloadRevokeChurn);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert_eq!(m.invariant_violations, 0);
    assert!(m.latency.sample_count > 0);
}

#[test]
fn reload_revoke_churn_medium() {
    let m = run_reload_revoke_churn(ScaleProfile::Medium, 42);
    assert_eq!(m.family, BenchmarkFamily::ReloadRevokeChurn);
    assert!(m.total_operations > 0);
    assert_eq!(m.invariant_violations, 0);
}

#[test]
fn reload_revoke_churn_large() {
    let m = run_reload_revoke_churn(ScaleProfile::Large, 42);
    assert_eq!(m.family, BenchmarkFamily::ReloadRevokeChurn);
    assert!(m.total_operations > 0);
    assert_eq!(m.invariant_violations, 0);
}

// ============================================================================
// Adversarial-noise-under-load family
// ============================================================================

#[test]
fn adversarial_noise_small() {
    let m = run_adversarial_noise_under_load(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::AdversarialNoiseUnderLoad);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert_eq!(m.invariant_violations, 0);
    assert!(m.latency.sample_count > 0);
    // Adversarial extensions should trigger security events
    assert!(
        m.security_events > 0,
        "adversarial workload should produce security events"
    );
}

#[test]
fn adversarial_noise_medium() {
    let m = run_adversarial_noise_under_load(ScaleProfile::Medium, 42);
    assert_eq!(m.family, BenchmarkFamily::AdversarialNoiseUnderLoad);
    assert!(m.total_operations > 0);
    assert_eq!(m.invariant_violations, 0);
}

#[test]
fn adversarial_noise_large() {
    let m = run_adversarial_noise_under_load(ScaleProfile::Large, 42);
    assert_eq!(m.family, BenchmarkFamily::AdversarialNoiseUnderLoad);
    assert!(m.total_operations > 0);
    assert_eq!(m.invariant_violations, 0);
}

// ============================================================================
// Full suite runner
// ============================================================================

#[test]
fn full_suite_runs_all_15_cases() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![
            ScaleProfile::Small,
            ScaleProfile::Medium,
            ScaleProfile::Large,
        ],
        families: BenchmarkFamily::all().to_vec(),
        run_id: "test-full-suite".to_string(),
        ..BenchmarkSuiteConfig::default()
    };

    let result = run_benchmark_suite(&config);

    assert_eq!(
        result.measurements.len(),
        15,
        "5 families x 3 profiles = 15 benchmark cases"
    );
    assert_eq!(result.events.len(), 15);
    assert_eq!(result.invariant_violations, 0);
    assert!(result.total_operations > 0);
    assert!(result.total_duration_us > 0);

    // Verify each family is represented
    let mut family_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for m in &result.measurements {
        *family_counts.entry(m.family.as_str()).or_default() += 1;
    }
    assert_eq!(family_counts.len(), 5);
    for count in family_counts.values() {
        assert_eq!(*count, 3, "each family should have 3 profiles");
    }
}

#[test]
fn suite_events_have_required_structured_fields() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        run_id: "test-events".to_string(),
        ..BenchmarkSuiteConfig::default()
    };

    let result = run_benchmark_suite(&config);

    for evt in &result.events {
        assert!(!evt.trace_id.is_empty(), "trace_id must be non-empty");
        assert!(!evt.decision_id.is_empty(), "decision_id must be non-empty");
        assert!(!evt.policy_id.is_empty(), "policy_id must be non-empty");
        assert_eq!(evt.component, "benchmark_e2e");
        assert_eq!(evt.event, "benchmark_case_completed");
        assert!(
            evt.outcome == "pass" || evt.outcome == "fail",
            "outcome must be pass or fail"
        );
        assert!(evt.family.is_some());
        assert!(evt.profile.is_some());
    }
}

// ============================================================================
// Regression detection
// ============================================================================

#[test]
fn regression_detects_throughput_degradation() {
    let baseline = BenchmarkMeasurement {
        family: BenchmarkFamily::BootStorm,
        profile: ScaleProfile::Small,
        throughput_ops_per_sec: 10_000.0,
        latency: LatencyDistribution {
            p50_us: 50,
            p95_us: 100,
            p99_us: 200,
            min_us: 10,
            max_us: 500,
            sample_count: 1000,
        },
        total_operations: 1000,
        duration_us: 100_000,
        correctness_digest: "baseline".to_string(),
        invariant_violations: 0,
        security_events: 0,
        peak_extensions_alive: 10,
    };

    // 10% throughput regression
    let current = BenchmarkMeasurement {
        throughput_ops_per_sec: 9_000.0,
        correctness_digest: "current".to_string(),
        ..baseline.clone()
    };

    let thresholds = RegressionThresholds::default();
    let result = detect_regression(&current, &baseline, &thresholds);

    assert!(result.blocked, "10% throughput regression should block");
    assert!(result.throughput_delta_pct > 5.0);
    assert!(!result.blockers.is_empty());
}

#[test]
fn regression_allows_within_threshold() {
    let baseline = BenchmarkMeasurement {
        family: BenchmarkFamily::BootStorm,
        profile: ScaleProfile::Small,
        throughput_ops_per_sec: 10_000.0,
        latency: LatencyDistribution {
            p50_us: 50,
            p95_us: 100,
            p99_us: 200,
            min_us: 10,
            max_us: 500,
            sample_count: 1000,
        },
        total_operations: 1000,
        duration_us: 100_000,
        correctness_digest: "baseline".to_string(),
        invariant_violations: 0,
        security_events: 0,
        peak_extensions_alive: 10,
    };

    // 2% throughput regression — within threshold
    let current = BenchmarkMeasurement {
        throughput_ops_per_sec: 9_800.0,
        correctness_digest: "current".to_string(),
        ..baseline.clone()
    };

    let thresholds = RegressionThresholds::default();
    let result = detect_regression(&current, &baseline, &thresholds);

    assert!(!result.blocked, "2% regression should be within threshold");
    assert!(result.blockers.is_empty());
}

#[test]
fn regression_detects_p95_latency_degradation() {
    let baseline = BenchmarkMeasurement {
        family: BenchmarkFamily::CapabilityChurn,
        profile: ScaleProfile::Medium,
        throughput_ops_per_sec: 10_000.0,
        latency: LatencyDistribution {
            p50_us: 50,
            p95_us: 100,
            p99_us: 200,
            min_us: 10,
            max_us: 500,
            sample_count: 1000,
        },
        total_operations: 1000,
        duration_us: 100_000,
        correctness_digest: "baseline".to_string(),
        invariant_violations: 0,
        security_events: 0,
        peak_extensions_alive: 50,
    };

    // 20% p95 latency regression
    let current = BenchmarkMeasurement {
        latency: LatencyDistribution {
            p95_us: 120,
            ..baseline.latency.clone()
        },
        correctness_digest: "current".to_string(),
        ..baseline.clone()
    };

    let thresholds = RegressionThresholds::default();
    let result = detect_regression(&current, &baseline, &thresholds);

    assert!(result.blocked, "20% p95 regression should block");
    assert!(result.p95_delta_pct > 10.0);
}

#[test]
fn suite_with_regression_comparison() {
    // Use generous thresholds since wall-clock latency is inherently noisy.
    // The purpose of this test is to verify the regression pipeline wiring,
    // not to assert tight timing stability.
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        run_id: "regression-test".to_string(),
        thresholds: RegressionThresholds {
            throughput_regression_pct: 50.0,
            p95_latency_regression_pct: 200.0,
            p99_latency_regression_pct: 200.0,
        },
        ..BenchmarkSuiteConfig::default()
    };

    // Run once to get baseline
    let baseline_result = run_benchmark_suite(&config);
    assert!(!baseline_result.measurements.is_empty());

    // Run again with same config — should not regress given generous thresholds
    let result = run_benchmark_suite_with_regression(&config, &baseline_result.measurements);

    // Verify regression results were populated
    assert!(
        !result.regressions.is_empty(),
        "regression comparison should produce results"
    );
    for r in &result.regressions {
        assert!(
            !r.blocked,
            "same seed/config with generous thresholds should not regress: {:?}",
            r.blockers
        );
    }
}

// ============================================================================
// Score computation (weighted geometric mean)
// ============================================================================

#[test]
fn measurements_convert_to_benchmark_cases() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm, BenchmarkFamily::CapabilityChurn],
        run_id: "score-test".to_string(),
        ..BenchmarkSuiteConfig::default()
    };
    let result = run_benchmark_suite(&config);

    let cases = measurements_to_cases(&result.measurements, 3.5);
    assert_eq!(cases.len(), 2);

    for case in &cases {
        assert!(case.throughput_franken_tps > 0.0);
        assert!(case.throughput_baseline_tps > 0.0);
        assert!(case.behavior_equivalent);
        assert!(case.weight.unwrap() > 0.0);
    }
}

// ============================================================================
// Determinism verification
// ============================================================================

#[test]
fn deterministic_seed_produces_identical_results() {
    let seed = 12345;
    let m1 = run_boot_storm(ScaleProfile::Small, seed);
    let m2 = run_boot_storm(ScaleProfile::Small, seed);

    assert_eq!(m1.correctness_digest, m2.correctness_digest);
    assert_eq!(m1.total_operations, m2.total_operations);
    assert_eq!(m1.invariant_violations, m2.invariant_violations);
}

#[test]
fn different_seeds_produce_different_digests() {
    let m1 = run_boot_storm(ScaleProfile::Small, 111);
    let m2 = run_boot_storm(ScaleProfile::Small, 222);

    assert_ne!(m1.correctness_digest, m2.correctness_digest);
}

#[test]
fn determinism_across_all_families() {
    let seed = 999;
    for family in BenchmarkFamily::all() {
        let m1 = run_benchmark(*family, ScaleProfile::Small, seed);
        let m2 = run_benchmark(*family, ScaleProfile::Small, seed);

        assert_eq!(
            m1.correctness_digest,
            m2.correctness_digest,
            "family {} must be deterministic",
            family.as_str()
        );
        assert_eq!(m1.total_operations, m2.total_operations);
        assert_eq!(m1.invariant_violations, m2.invariant_violations);
    }
}

// ============================================================================
// Xorshift64 PRNG
// ============================================================================

#[test]
fn xorshift64_is_deterministic() {
    let mut rng1 = Xorshift64::new(42);
    let mut rng2 = Xorshift64::new(42);

    let seq1: Vec<u64> = (0..100).map(|_| rng1.next_u64()).collect();
    let seq2: Vec<u64> = (0..100).map(|_| rng2.next_u64()).collect();
    assert_eq!(seq1, seq2);
}

#[test]
fn xorshift64_zero_seed_is_adjusted() {
    let mut rng = Xorshift64::new(0);
    let v = rng.next_u64();
    assert_ne!(
        v, 0,
        "zero seed should be adjusted to avoid degenerate sequence"
    );
}

#[test]
fn xorshift64_next_usize_respects_bound() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..1000 {
        let v = rng.next_usize(10);
        assert!(v < 10);
    }
}

// ============================================================================
// Scale profiles
// ============================================================================

#[test]
fn scale_profiles_are_ordered() {
    assert!(ScaleProfile::Small.extension_count() < ScaleProfile::Medium.extension_count());
    assert!(ScaleProfile::Medium.extension_count() < ScaleProfile::Large.extension_count());
    assert!(ScaleProfile::Small.iterations() < ScaleProfile::Medium.iterations());
    assert!(ScaleProfile::Medium.iterations() < ScaleProfile::Large.iterations());
}

#[test]
fn scale_profile_labels() {
    assert_eq!(ScaleProfile::Small.as_str(), "S");
    assert_eq!(ScaleProfile::Medium.as_str(), "M");
    assert_eq!(ScaleProfile::Large.as_str(), "L");
}

// ============================================================================
// Benchmark family metadata
// ============================================================================

#[test]
fn family_weights_sum_to_one() {
    let total: f64 = BenchmarkFamily::all()
        .iter()
        .map(|f| f.default_weight())
        .sum();
    assert!(
        (total - 1.0).abs() < 1e-10,
        "family weights must sum to 1.0, got {total}"
    );
}

#[test]
fn family_labels_are_unique() {
    let labels: Vec<&str> = BenchmarkFamily::all().iter().map(|f| f.as_str()).collect();
    let mut dedup = labels.clone();
    dedup.sort_unstable();
    dedup.dedup();
    assert_eq!(labels.len(), dedup.len(), "family labels must be unique");
}

#[test]
fn all_families_are_five() {
    assert_eq!(BenchmarkFamily::all().len(), 5);
}

// ============================================================================
// Evidence artifacts
// ============================================================================

#[test]
fn evidence_artifacts_are_written_correctly() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm, BenchmarkFamily::CapabilityChurn],
        run_id: "evidence-test".to_string(),
        ..BenchmarkSuiteConfig::default()
    };

    let result = run_benchmark_suite(&config);
    let output_dir = artifact_dir();
    let artifacts = write_evidence_artifacts(&result, &output_dir).expect("write artifacts");

    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.evidence_path.exists());
    assert!(artifacts.summary_path.exists());

    // Verify manifest
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.run_manifest_path).unwrap())
            .unwrap();
    assert_eq!(manifest["run_id"], "evidence-test");
    assert_eq!(manifest["seed"], 42);
    assert_eq!(manifest["blocked"], false);

    // Verify evidence JSONL
    let evidence = std::fs::read_to_string(&artifacts.evidence_path).unwrap();
    let lines: Vec<&str> = evidence.lines().collect();
    assert!(lines.len() >= 2, "should have at least 2 measurement lines");
    for line in &lines {
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            entry.get("event").is_some(),
            "each line must have event field"
        );
    }

    // Verify summary
    let summary: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.summary_path).unwrap()).unwrap();
    assert_eq!(summary["measurement_count"], 2);
}

#[test]
fn evidence_contains_benchmark_case_evaluated() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        run_id: "evidence-content-test".to_string(),
        ..BenchmarkSuiteConfig::default()
    };

    let result = run_benchmark_suite(&config);
    let output_dir = artifact_dir();
    let artifacts = write_evidence_artifacts(&result, &output_dir).expect("write artifacts");

    let evidence = std::fs::read_to_string(&artifacts.evidence_path).unwrap();
    assert!(evidence.contains("benchmark_case_evaluated"));
    assert!(evidence.contains("boot-storm"));
    assert!(evidence.contains("throughput_ops_per_sec"));
    assert!(evidence.contains("p95_us"));
    assert!(evidence.contains("correctness_digest"));
}

// ============================================================================
// Latency distribution edge cases
// ============================================================================

#[test]
fn latency_distribution_single_sample() {
    let mut samples = vec![42];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.p50_us, 42);
    assert_eq!(dist.min_us, 42);
    assert_eq!(dist.max_us, 42);
    assert_eq!(dist.sample_count, 1);
}

#[test]
fn latency_distribution_sorted() {
    let mut samples = vec![100, 50, 200, 10, 500, 300, 150, 250, 80, 400];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert!(dist.min_us <= dist.p50_us);
    assert!(dist.p50_us <= dist.p95_us);
    assert!(dist.p95_us <= dist.p99_us);
    assert!(dist.p99_us <= dist.max_us);
    assert_eq!(dist.sample_count, 10);
}

// ============================================================================
// Cross-family invariant: no benchmark produces invariant violations
// ============================================================================

#[test]
fn no_family_produces_invariant_violations() {
    for family in BenchmarkFamily::all() {
        let m = run_benchmark(*family, ScaleProfile::Small, 42);
        assert_eq!(
            m.invariant_violations,
            0,
            "family {} must produce zero invariant violations",
            family.as_str()
        );
    }
}

// ============================================================================
// Scale proportionality: larger profiles do more work
// ============================================================================

#[test]
fn larger_profile_does_more_operations() {
    let small = run_boot_storm(ScaleProfile::Small, 42);
    let medium = run_boot_storm(ScaleProfile::Medium, 42);
    let large = run_boot_storm(ScaleProfile::Large, 42);

    assert!(
        small.total_operations < medium.total_operations,
        "medium should do more operations than small"
    );
    assert!(
        medium.total_operations < large.total_operations,
        "large should do more operations than medium"
    );
}
