//! Comprehensive integration tests for `frankenengine_engine::benchmark_e2e`.
//!
//! Exercises every public type, function, and constant in the benchmark E2E
//! framework from the crate boundary. Coverage includes:
//!   - ScaleProfile enum variants and methods
//!   - BenchmarkFamily enum variants, as_str, all(), default_weight
//!   - LatencyDistribution construction and invariants
//!   - BenchmarkMeasurement field access
//!   - run_benchmark dispatch for each family
//!   - run_benchmark_suite with various configs
//!   - run_benchmark_suite_with_regression and regression detection
//!   - BenchmarkSuiteConfig construction and defaults
//!   - BenchmarkSuiteResult population
//!   - BenchmarkEvidenceArtifacts via write_evidence_artifacts
//!   - Determinism: same seed => same measurements
//!   - Serde roundtrips for all serializable types
//!   - Constants are non-empty and valid
//!   - Xorshift64 PRNG properties
//!   - Harness contract validation
//!   - LatencyDistribution p50 <= p95 <= p99 invariants

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

use std::collections::BTreeSet;

use frankenengine_engine::benchmark_e2e::{
    BENCHMARK_E2E_COMPONENT, BENCHMARK_E2E_SCHEMA_VERSION, BENCHMARK_ENV_SCHEMA_VERSION,
    BenchmarkEnvironmentManifest, BenchmarkFairnessPolicy, BenchmarkFamily,
    BenchmarkHarnessContract, BenchmarkHarnessContractError, BenchmarkMeasurement,
    BenchmarkRuntimePins, BenchmarkSuiteConfig, LatencyDistribution, MIN_START_BUDGET_MILLIONTHS,
    RegressionThresholds, ScaleProfile, Xorshift64, detect_regression, measurements_to_cases,
    run_adversarial_noise_under_load, run_benchmark, run_benchmark_suite,
    run_benchmark_suite_with_regression, run_boot_storm, run_capability_churn,
    run_mixed_cpu_io_agent_mesh, run_reload_revoke_churn, validate_harness_contract,
    write_evidence_artifacts,
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn make_measurement(
    family: BenchmarkFamily,
    profile: ScaleProfile,
    throughput: f64,
    p50: u64,
    p95: u64,
    p99: u64,
) -> BenchmarkMeasurement {
    BenchmarkMeasurement {
        family,
        profile,
        throughput_ops_per_sec: throughput,
        latency: LatencyDistribution {
            p50_us: p50,
            p95_us: p95,
            p99_us: p99,
            min_us: 5,
            max_us: p99 + 200,
            sample_count: 100,
        },
        total_operations: 1000,
        duration_us: 100_000,
        correctness_digest: format!("test-digest-{}", family.as_str()),
        invariant_violations: 0,
        security_events: 0,
        peak_extensions_alive: 10,
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn constants_are_non_empty() {
    assert!(!BENCHMARK_E2E_COMPONENT.is_empty());
    assert!(!BENCHMARK_E2E_SCHEMA_VERSION.is_empty());
    assert!(!BENCHMARK_ENV_SCHEMA_VERSION.is_empty());
}

#[test]
fn constant_component_value() {
    assert_eq!(BENCHMARK_E2E_COMPONENT, "benchmark_e2e");
}

#[test]
fn constant_schema_version_contains_benchmark() {
    assert!(BENCHMARK_E2E_SCHEMA_VERSION.contains("benchmark"));
}

#[test]
fn constant_env_schema_version_contains_env() {
    assert!(BENCHMARK_ENV_SCHEMA_VERSION.contains("benchmark-env"));
}

#[test]
fn constant_min_start_budget_positive() {
    assert!(MIN_START_BUDGET_MILLIONTHS > 0);
    assert_eq!(MIN_START_BUDGET_MILLIONTHS, 1_000);
}

// ===========================================================================
// 2. ScaleProfile
// ===========================================================================

#[test]
fn scale_profile_small_as_str() {
    assert_eq!(ScaleProfile::Small.as_str(), "S");
}

#[test]
fn scale_profile_medium_as_str() {
    assert_eq!(ScaleProfile::Medium.as_str(), "M");
}

#[test]
fn scale_profile_large_as_str() {
    assert_eq!(ScaleProfile::Large.as_str(), "L");
}

#[test]
fn scale_profile_as_str_all_distinct() {
    let all = [
        ScaleProfile::Small,
        ScaleProfile::Medium,
        ScaleProfile::Large,
    ];
    let set: BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn scale_profile_extension_count_monotonic() {
    assert!(ScaleProfile::Small.extension_count() < ScaleProfile::Medium.extension_count());
    assert!(ScaleProfile::Medium.extension_count() < ScaleProfile::Large.extension_count());
}

#[test]
fn scale_profile_extension_count_values() {
    assert_eq!(ScaleProfile::Small.extension_count(), 10);
    assert_eq!(ScaleProfile::Medium.extension_count(), 50);
    assert_eq!(ScaleProfile::Large.extension_count(), 200);
}

#[test]
fn scale_profile_iterations_monotonic() {
    assert!(ScaleProfile::Small.iterations() < ScaleProfile::Medium.iterations());
    assert!(ScaleProfile::Medium.iterations() < ScaleProfile::Large.iterations());
}

#[test]
fn scale_profile_iterations_values() {
    assert_eq!(ScaleProfile::Small.iterations(), 100);
    assert_eq!(ScaleProfile::Medium.iterations(), 500);
    assert_eq!(ScaleProfile::Large.iterations(), 2_000);
}

#[test]
fn scale_profile_eq_and_copy() {
    let s = ScaleProfile::Small;
    let c = s;
    assert_eq!(s, c);
    assert_ne!(ScaleProfile::Small, ScaleProfile::Large);
    assert_ne!(ScaleProfile::Small, ScaleProfile::Medium);
    assert_ne!(ScaleProfile::Medium, ScaleProfile::Large);
}

#[test]
fn scale_profile_debug_non_empty() {
    let all = [
        ScaleProfile::Small,
        ScaleProfile::Medium,
        ScaleProfile::Large,
    ];
    for p in &all {
        let dbg = format!("{p:?}");
        assert!(!dbg.is_empty());
    }
}

#[test]
fn scale_profile_debug_distinct() {
    let all = [
        ScaleProfile::Small,
        ScaleProfile::Medium,
        ScaleProfile::Large,
    ];
    let set: BTreeSet<String> = all.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// 3. BenchmarkFamily
// ===========================================================================

#[test]
fn benchmark_family_all_returns_five() {
    assert_eq!(BenchmarkFamily::all().len(), 5);
}

#[test]
fn benchmark_family_as_str_values() {
    assert_eq!(BenchmarkFamily::BootStorm.as_str(), "boot-storm");
    assert_eq!(
        BenchmarkFamily::CapabilityChurn.as_str(),
        "capability-churn"
    );
    assert_eq!(
        BenchmarkFamily::MixedCpuIoAgentMesh.as_str(),
        "mixed-cpu-io-agent-mesh"
    );
    assert_eq!(
        BenchmarkFamily::ReloadRevokeChurn.as_str(),
        "reload-revoke-churn"
    );
    assert_eq!(
        BenchmarkFamily::AdversarialNoiseUnderLoad.as_str(),
        "adversarial-noise-under-load"
    );
}

#[test]
fn benchmark_family_as_str_all_distinct() {
    let set: BTreeSet<&str> = BenchmarkFamily::all().iter().map(|f| f.as_str()).collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn benchmark_family_default_weights_sum_to_one() {
    let sum: f64 = BenchmarkFamily::all()
        .iter()
        .map(|f| f.default_weight())
        .sum();
    assert!(
        (sum - 1.0).abs() < 1e-9,
        "weights should sum to 1.0, got {sum}"
    );
}

#[test]
fn benchmark_family_default_weights_all_positive() {
    for family in BenchmarkFamily::all() {
        assert!(
            family.default_weight() > 0.0,
            "{:?} has non-positive weight",
            family
        );
    }
}

#[test]
fn benchmark_family_default_weight_specific_values() {
    assert!((BenchmarkFamily::BootStorm.default_weight() - 0.25).abs() < 1e-9);
    assert!((BenchmarkFamily::CapabilityChurn.default_weight() - 0.20).abs() < 1e-9);
    assert!((BenchmarkFamily::MixedCpuIoAgentMesh.default_weight() - 0.25).abs() < 1e-9);
    assert!((BenchmarkFamily::ReloadRevokeChurn.default_weight() - 0.15).abs() < 1e-9);
    assert!((BenchmarkFamily::AdversarialNoiseUnderLoad.default_weight() - 0.15).abs() < 1e-9);
}

#[test]
fn benchmark_family_debug_distinct() {
    let set: BTreeSet<String> = BenchmarkFamily::all()
        .iter()
        .map(|f| format!("{f:?}"))
        .collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn benchmark_family_clone_and_eq() {
    let a = BenchmarkFamily::BootStorm;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(BenchmarkFamily::BootStorm, BenchmarkFamily::CapabilityChurn);
}

// ===========================================================================
// 4. LatencyDistribution
// ===========================================================================

#[test]
fn latency_distribution_from_sorted_samples() {
    let mut samples: Vec<u64> = (1..=100).collect();
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 1);
    assert_eq!(dist.max_us, 100);
    assert_eq!(dist.sample_count, 100);
    // p50 is median
    assert_eq!(dist.p50_us, 51); // samples[50]
}

#[test]
fn latency_distribution_from_unsorted_samples() {
    let mut samples = vec![500, 100, 300, 200, 400, 600, 700, 800, 900, 1000];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 100);
    assert_eq!(dist.max_us, 1000);
    assert_eq!(dist.sample_count, 10);
}

#[test]
fn latency_distribution_single_sample() {
    let mut samples = vec![42];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 42);
    assert_eq!(dist.max_us, 42);
    assert_eq!(dist.p50_us, 42);
    assert_eq!(dist.p95_us, 42);
    assert_eq!(dist.p99_us, 42);
    assert_eq!(dist.sample_count, 1);
}

#[test]
fn latency_distribution_two_samples() {
    let mut samples = vec![10, 90];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 10);
    assert_eq!(dist.max_us, 90);
    assert_eq!(dist.sample_count, 2);
}

#[test]
fn latency_distribution_p50_lte_p95_lte_p99() {
    let mut samples: Vec<u64> = (1..=1000).collect();
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert!(
        dist.p50_us <= dist.p95_us,
        "p50 ({}) should be <= p95 ({})",
        dist.p50_us,
        dist.p95_us
    );
    assert!(
        dist.p95_us <= dist.p99_us,
        "p95 ({}) should be <= p99 ({})",
        dist.p95_us,
        dist.p99_us
    );
}

#[test]
fn latency_distribution_min_lte_p50_and_p99_lte_max() {
    let mut samples: Vec<u64> = (10..=500).collect();
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert!(dist.min_us <= dist.p50_us);
    assert!(dist.p99_us <= dist.max_us);
}

#[test]
#[should_panic(expected = "cannot compute distribution from empty samples")]
fn latency_distribution_empty_panics() {
    let mut samples: Vec<u64> = Vec::new();
    LatencyDistribution::from_samples(&mut samples);
}

#[test]
fn latency_distribution_clone_and_debug() {
    let mut samples = vec![100, 200, 300];
    let dist = LatencyDistribution::from_samples(&mut samples);
    let cloned = dist.clone();
    assert_eq!(cloned.p50_us, dist.p50_us);
    assert_eq!(cloned.sample_count, dist.sample_count);
    assert!(!format!("{dist:?}").is_empty());
}

// ===========================================================================
// 5. BenchmarkMeasurement fields
// ===========================================================================

#[test]
fn benchmark_measurement_field_access() {
    let m = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        50,
        100,
        200,
    );
    assert_eq!(m.family, BenchmarkFamily::BootStorm);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!((m.throughput_ops_per_sec - 1000.0).abs() < 1e-9);
    assert_eq!(m.latency.p50_us, 50);
    assert_eq!(m.latency.p95_us, 100);
    assert_eq!(m.latency.p99_us, 200);
    assert_eq!(m.total_operations, 1000);
    assert_eq!(m.duration_us, 100_000);
    assert!(!m.correctness_digest.is_empty());
    assert_eq!(m.invariant_violations, 0);
    assert_eq!(m.security_events, 0);
    assert_eq!(m.peak_extensions_alive, 10);
}

#[test]
fn benchmark_measurement_clone_preserves_fields() {
    let m = make_measurement(
        BenchmarkFamily::CapabilityChurn,
        ScaleProfile::Medium,
        500.0,
        30,
        80,
        150,
    );
    let cloned = m.clone();
    assert_eq!(cloned.family, m.family);
    assert_eq!(cloned.profile, m.profile);
    assert!((cloned.throughput_ops_per_sec - m.throughput_ops_per_sec).abs() < 1e-9);
    assert_eq!(cloned.correctness_digest, m.correctness_digest);
}

#[test]
fn benchmark_measurement_debug_non_empty() {
    let m = make_measurement(
        BenchmarkFamily::ReloadRevokeChurn,
        ScaleProfile::Large,
        200.0,
        10,
        20,
        30,
    );
    assert!(!format!("{m:?}").is_empty());
}

// ===========================================================================
// 6. run_benchmark dispatches to each family
// ===========================================================================

#[test]
fn run_benchmark_boot_storm() {
    let m = run_benchmark(BenchmarkFamily::BootStorm, ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::BootStorm);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert!(m.duration_us > 0);
    assert!(m.latency.sample_count > 0);
    assert!(!m.correctness_digest.is_empty());
}

#[test]
fn run_benchmark_capability_churn() {
    let m = run_benchmark(BenchmarkFamily::CapabilityChurn, ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::CapabilityChurn);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
}

#[test]
fn run_benchmark_mixed_cpu_io_agent_mesh() {
    let m = run_benchmark(
        BenchmarkFamily::MixedCpuIoAgentMesh,
        ScaleProfile::Small,
        42,
    );
    assert_eq!(m.family, BenchmarkFamily::MixedCpuIoAgentMesh);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
}

#[test]
fn run_benchmark_reload_revoke_churn() {
    let m = run_benchmark(BenchmarkFamily::ReloadRevokeChurn, ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::ReloadRevokeChurn);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
}

#[test]
fn run_benchmark_adversarial_noise_under_load() {
    let m = run_benchmark(
        BenchmarkFamily::AdversarialNoiseUnderLoad,
        ScaleProfile::Small,
        42,
    );
    assert_eq!(m.family, BenchmarkFamily::AdversarialNoiseUnderLoad);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
}

#[test]
fn run_benchmark_dispatches_all_families() {
    for family in BenchmarkFamily::all() {
        let m = run_benchmark(*family, ScaleProfile::Small, 7);
        assert_eq!(m.family, *family);
        assert_eq!(m.profile, ScaleProfile::Small);
        assert!(m.total_operations > 0);
        assert!(!m.correctness_digest.is_empty());
    }
}

// ===========================================================================
// 7. Each benchmark family produces non-zero measurements
// ===========================================================================

#[test]
fn boot_storm_small_produces_non_zero() {
    let m = run_boot_storm(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::BootStorm);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.duration_us > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert!(m.latency.sample_count > 0);
    assert!(m.peak_extensions_alive > 0);
    assert_eq!(m.invariant_violations, 0);
    assert_eq!(m.security_events, 0);
}

#[test]
fn capability_churn_small_produces_non_zero() {
    let m = run_capability_churn(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::CapabilityChurn);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert!(m.latency.sample_count > 0);
    assert_eq!(m.invariant_violations, 0);
    assert_eq!(
        m.peak_extensions_alive,
        ScaleProfile::Small.extension_count()
    );
}

#[test]
fn mixed_cpu_io_agent_mesh_small_produces_non_zero() {
    let m = run_mixed_cpu_io_agent_mesh(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::MixedCpuIoAgentMesh);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert!(m.latency.sample_count > 0);
    assert_eq!(m.invariant_violations, 0);
    assert_eq!(
        m.peak_extensions_alive,
        ScaleProfile::Small.extension_count()
    );
}

#[test]
fn reload_revoke_churn_small_produces_non_zero() {
    let m = run_reload_revoke_churn(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::ReloadRevokeChurn);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert!(m.latency.sample_count > 0);
    assert_eq!(m.invariant_violations, 0);
    assert_eq!(m.security_events, 0);
}

#[test]
fn adversarial_noise_under_load_small_produces_non_zero() {
    let m = run_adversarial_noise_under_load(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::AdversarialNoiseUnderLoad);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert!(m.latency.sample_count > 0);
    assert_eq!(m.invariant_violations, 0);
    // Adversarial extensions should trigger security events
    assert!(m.security_events > 0);
}

// ===========================================================================
// 8. Determinism: same seed produces same measurements
// ===========================================================================

#[test]
fn boot_storm_deterministic_same_seed() {
    let m1 = run_boot_storm(ScaleProfile::Small, 42);
    let m2 = run_boot_storm(ScaleProfile::Small, 42);
    assert_eq!(m1.correctness_digest, m2.correctness_digest);
    assert_eq!(m1.total_operations, m2.total_operations);
    assert_eq!(m1.invariant_violations, m2.invariant_violations);
    assert_eq!(m1.security_events, m2.security_events);
}

#[test]
fn capability_churn_deterministic_same_seed() {
    let m1 = run_capability_churn(ScaleProfile::Small, 77);
    let m2 = run_capability_churn(ScaleProfile::Small, 77);
    assert_eq!(m1.correctness_digest, m2.correctness_digest);
    assert_eq!(m1.total_operations, m2.total_operations);
    assert_eq!(m1.security_events, m2.security_events);
}

#[test]
fn mixed_mesh_deterministic_same_seed() {
    let m1 = run_mixed_cpu_io_agent_mesh(ScaleProfile::Small, 99);
    let m2 = run_mixed_cpu_io_agent_mesh(ScaleProfile::Small, 99);
    assert_eq!(m1.correctness_digest, m2.correctness_digest);
    assert_eq!(m1.security_events, m2.security_events);
}

#[test]
fn reload_churn_deterministic_same_seed() {
    let m1 = run_reload_revoke_churn(ScaleProfile::Small, 55);
    let m2 = run_reload_revoke_churn(ScaleProfile::Small, 55);
    assert_eq!(m1.correctness_digest, m2.correctness_digest);
    assert_eq!(m1.total_operations, m2.total_operations);
}

#[test]
fn adversarial_deterministic_same_seed() {
    let m1 = run_adversarial_noise_under_load(ScaleProfile::Small, 13);
    let m2 = run_adversarial_noise_under_load(ScaleProfile::Small, 13);
    assert_eq!(m1.correctness_digest, m2.correctness_digest);
    assert_eq!(m1.security_events, m2.security_events);
}

#[test]
fn different_seeds_produce_different_digests() {
    let m1 = run_boot_storm(ScaleProfile::Small, 1);
    let m2 = run_boot_storm(ScaleProfile::Small, 999);
    assert_ne!(m1.correctness_digest, m2.correctness_digest);
}

// ===========================================================================
// 9. RegressionThresholds
// ===========================================================================

#[test]
fn regression_thresholds_default_values() {
    let t = RegressionThresholds::default();
    assert!((t.throughput_regression_pct - 5.0).abs() < 1e-9);
    assert!((t.p95_latency_regression_pct - 10.0).abs() < 1e-9);
    assert!((t.p99_latency_regression_pct - 15.0).abs() < 1e-9);
}

#[test]
fn regression_thresholds_all_positive() {
    let t = RegressionThresholds::default();
    assert!(t.throughput_regression_pct > 0.0);
    assert!(t.p95_latency_regression_pct > 0.0);
    assert!(t.p99_latency_regression_pct > 0.0);
}

#[test]
fn regression_thresholds_debug_non_empty() {
    let t = RegressionThresholds::default();
    assert!(!format!("{t:?}").is_empty());
}

// ===========================================================================
// 10. detect_regression
// ===========================================================================

#[test]
fn detect_regression_no_regression_same_values() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(!result.blocked);
    assert!(result.blockers.is_empty());
    assert!((result.throughput_delta_pct).abs() < 1e-9);
    assert!((result.p95_delta_pct).abs() < 1e-9);
    assert!((result.p99_delta_pct).abs() < 1e-9);
}

#[test]
fn detect_regression_throughput_regression() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    // 50% throughput regression
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        500.0,
        100,
        500,
        1000,
    );
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
    assert!(result.blockers.iter().any(|b| b.contains("throughput")));
}

#[test]
fn detect_regression_p95_latency_regression() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    // 100% p95 regression (500 -> 1000)
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        1000,
        1000,
    );
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
    assert!(result.blockers.iter().any(|b| b.contains("p95")));
}

#[test]
fn detect_regression_p99_latency_regression() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    // 100% p99 regression (1000 -> 2000)
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        2000,
    );
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
    assert!(result.blockers.iter().any(|b| b.contains("p99")));
}

#[test]
fn detect_regression_improvement_not_blocked() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    // Better throughput and lower latency
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        2000.0,
        50,
        200,
        400,
    );
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(!result.blocked);
    assert!(result.blockers.is_empty());
}

#[test]
fn detect_regression_multiple_blockers() {
    let baseline = make_measurement(
        BenchmarkFamily::CapabilityChurn,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    // Everything regressed severely
    let current = make_measurement(
        BenchmarkFamily::CapabilityChurn,
        ScaleProfile::Small,
        200.0,
        100,
        1500,
        3000,
    );
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
    assert!(result.blockers.len() >= 3);
    assert!(result.blockers.iter().any(|b| b.contains("throughput")));
    assert!(result.blockers.iter().any(|b| b.contains("p95")));
    assert!(result.blockers.iter().any(|b| b.contains("p99")));
}

#[test]
fn detect_regression_zero_baseline_throughput() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        0.0,
        100,
        500,
        1000,
    );
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!((result.throughput_delta_pct).abs() < 1e-9);
    assert!(!result.blocked);
}

#[test]
fn detect_regression_zero_baseline_latency() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        0,
        0,
        0,
    );
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        50,
        100,
        200,
    );
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!((result.p95_delta_pct).abs() < 1e-9);
    assert!((result.p99_delta_pct).abs() < 1e-9);
}

#[test]
fn detect_regression_exactly_at_threshold_not_blocked() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    // 5% throughput regression: (1000 - 950) / 1000 = 5.0% == threshold
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        950.0,
        100,
        500,
        1000,
    );
    let thresholds = RegressionThresholds::default();
    let result = detect_regression(&current, &baseline, &thresholds);
    // 5.0% == 5.0% threshold: not strictly greater => not blocked
    assert!(!result.blocked);
}

#[test]
fn detect_regression_just_over_threshold_blocked() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    // 5.1% throughput regression
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        949.0,
        100,
        500,
        1000,
    );
    let thresholds = RegressionThresholds::default();
    let result = detect_regression(&current, &baseline, &thresholds);
    assert!(result.blocked);
}

#[test]
fn detect_regression_custom_thresholds() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        100,
        500,
        1000,
    );
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        900.0,
        100,
        500,
        1000,
    );
    let thresholds = RegressionThresholds {
        throughput_regression_pct: 15.0,
        p95_latency_regression_pct: 10.0,
        p99_latency_regression_pct: 15.0,
    };
    let result = detect_regression(&current, &baseline, &thresholds);
    // 10% < 15% threshold
    assert!(!result.blocked);
}

#[test]
fn regression_result_fields() {
    let baseline = make_measurement(
        BenchmarkFamily::ReloadRevokeChurn,
        ScaleProfile::Medium,
        1000.0,
        50,
        200,
        400,
    );
    let current = make_measurement(
        BenchmarkFamily::ReloadRevokeChurn,
        ScaleProfile::Medium,
        1000.0,
        50,
        200,
        400,
    );
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert_eq!(result.family, BenchmarkFamily::ReloadRevokeChurn);
    assert_eq!(result.profile, ScaleProfile::Medium);
    assert!(!result.blocked);
}

#[test]
fn regression_result_clone_and_debug() {
    let baseline = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        50,
        200,
        400,
    );
    let current = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        800.0,
        50,
        300,
        500,
    );
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    let cloned = result.clone();
    assert_eq!(cloned.family, result.family);
    assert_eq!(cloned.blocked, result.blocked);
    assert_eq!(cloned.blockers.len(), result.blockers.len());
    assert!(!format!("{result:?}").is_empty());
}

// ===========================================================================
// 11. Xorshift64
// ===========================================================================

#[test]
fn xorshift64_deterministic_same_seed() {
    let mut rng1 = Xorshift64::new(42);
    let mut rng2 = Xorshift64::new(42);
    for _ in 0..100 {
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }
}

#[test]
fn xorshift64_different_seeds_differ() {
    let mut rng1 = Xorshift64::new(42);
    let mut rng2 = Xorshift64::new(43);
    let same = (0..10).all(|_| rng1.next_u64() == rng2.next_u64());
    assert!(!same);
}

#[test]
fn xorshift64_zero_seed_becomes_one() {
    let mut rng_zero = Xorshift64::new(0);
    let mut rng_one = Xorshift64::new(1);
    assert_eq!(rng_zero.next_u64(), rng_one.next_u64());
}

#[test]
fn xorshift64_next_usize_bounded() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..1000 {
        let val = rng.next_usize(10);
        assert!(val < 10);
    }
}

#[test]
fn xorshift64_next_bool_zero_always_false() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..100 {
        assert!(!rng.next_bool(0));
    }
}

#[test]
fn xorshift64_next_bool_hundred_always_true() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..100 {
        assert!(rng.next_bool(100));
    }
}

#[test]
fn xorshift64_next_bool_distribution_reasonable() {
    let mut rng = Xorshift64::new(42);
    let mut trues = 0usize;
    let mut falses = 0usize;
    for _ in 0..1000 {
        if rng.next_bool(50) {
            trues += 1;
        } else {
            falses += 1;
        }
    }
    assert!(trues > 100, "expected many trues, got {trues}");
    assert!(falses > 100, "expected many falses, got {falses}");
}

#[test]
fn xorshift64_never_produces_zero() {
    let mut rng = Xorshift64::new(42);
    // xorshift64 with non-zero state should never produce zero
    for _ in 0..10_000 {
        assert_ne!(rng.next_u64(), 0);
    }
}

// ===========================================================================
// 12. BenchmarkSuiteConfig
// ===========================================================================

#[test]
fn benchmark_suite_config_default() {
    let config = BenchmarkSuiteConfig::default();
    assert_eq!(config.seed, 42);
    assert_eq!(config.profiles.len(), 3);
    assert_eq!(config.families.len(), 5);
    assert_eq!(config.run_id, "benchmark-run-default");
    assert_eq!(config.run_date, "2026-02-22");
}

#[test]
fn benchmark_suite_config_custom() {
    let config = BenchmarkSuiteConfig {
        seed: 123,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "custom-run".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    assert_eq!(config.seed, 123);
    assert_eq!(config.profiles.len(), 1);
    assert_eq!(config.families.len(), 1);
}

#[test]
fn benchmark_suite_config_debug_non_empty() {
    let config = BenchmarkSuiteConfig::default();
    assert!(!format!("{config:?}").is_empty());
}

// ===========================================================================
// 13. run_benchmark_suite
// ===========================================================================

#[test]
fn run_benchmark_suite_single_family_single_profile() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-suite-single".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    assert_eq!(result.measurements.len(), 1);
    assert_eq!(result.events.len(), 1);
    assert!(result.total_operations > 0);
    assert!(result.total_duration_us > 0);
    assert_eq!(result.invariant_violations, 0);
    assert!(!result.blocked);
    assert!(result.regressions.is_empty());
}

#[test]
fn run_benchmark_suite_two_families_two_profiles() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small, ScaleProfile::Medium],
        families: vec![BenchmarkFamily::BootStorm, BenchmarkFamily::CapabilityChurn],
        thresholds: RegressionThresholds::default(),
        run_id: "test-suite-2x2".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    assert_eq!(result.measurements.len(), 4);
    assert_eq!(result.events.len(), 4);
}

#[test]
fn run_benchmark_suite_events_have_correct_metadata() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-evt-meta".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let evt = &result.events[0];
    assert_eq!(evt.component, BENCHMARK_E2E_COMPONENT);
    assert_eq!(evt.event, "benchmark_case_completed");
    assert_eq!(evt.outcome, "pass");
    assert_eq!(evt.trace_id, "test-evt-meta");
    assert!(evt.family.is_some());
    assert!(evt.profile.is_some());
    assert_eq!(evt.family.as_deref(), Some("boot-storm"));
    assert_eq!(evt.profile.as_deref(), Some("S"));
}

// ===========================================================================
// 14. BenchmarkSuiteResult population
// ===========================================================================

#[test]
fn benchmark_suite_result_accumulates_operations() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm, BenchmarkFamily::CapabilityChurn],
        thresholds: RegressionThresholds::default(),
        run_id: "test-accum".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let sum_ops: u64 = result.measurements.iter().map(|m| m.total_operations).sum();
    assert_eq!(result.total_operations, sum_ops);
}

#[test]
fn benchmark_suite_result_accumulates_duration() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-dur".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let sum_dur: u64 = result.measurements.iter().map(|m| m.duration_us).sum();
    assert_eq!(result.total_duration_us, sum_dur);
}

#[test]
fn benchmark_suite_result_debug_non_empty() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-dbg".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    assert!(!format!("{result:?}").is_empty());
}

// ===========================================================================
// 15. run_benchmark_suite_with_regression
// ===========================================================================

#[test]
fn suite_with_regression_no_baseline_no_regressions() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-no-baseline".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite_with_regression(&config, &[]);
    assert!(result.regressions.is_empty());
}

#[test]
fn suite_with_regression_matching_baseline_produces_regressions() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds {
            throughput_regression_pct: 99.0,
            p95_latency_regression_pct: 99.0,
            p99_latency_regression_pct: 99.0,
        },
        run_id: "test-with-baseline".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let baseline_result = run_benchmark_suite(&config);
    let result = run_benchmark_suite_with_regression(&config, &baseline_result.measurements);
    assert_eq!(result.regressions.len(), 1);
    assert_eq!(result.regressions[0].family, BenchmarkFamily::BootStorm);
    assert_eq!(result.regressions[0].profile, ScaleProfile::Small);
    // With 99% thresholds and same seed, timing variance won't trigger a block
    assert!(!result.regressions[0].blocked);
}

#[test]
fn suite_with_regression_self_comparison_not_blocked() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-self-compare".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let baseline_result = run_benchmark_suite(&config);
    let baselines = baseline_result.measurements.clone();
    let result = run_benchmark_suite_with_regression(&config, &baselines);
    for r in &result.regressions {
        assert!(!r.blocked, "self-comparison should never block");
    }
}

#[test]
fn suite_with_regression_uses_btreemap_for_baseline_lookup() {
    // Verifying that unmatched baselines are silently skipped
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-unmatched".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    // Create a baseline for a different family
    let unmatched = make_measurement(
        BenchmarkFamily::CapabilityChurn,
        ScaleProfile::Large,
        5000.0,
        10,
        20,
        30,
    );
    let result = run_benchmark_suite_with_regression(&config, &[unmatched]);
    // No matching baseline for BootStorm/Small => no regressions
    assert!(result.regressions.is_empty());
}

// ===========================================================================
// 16. measurements_to_cases
// ===========================================================================

#[test]
fn measurements_to_cases_basic() {
    let m = run_boot_storm(ScaleProfile::Small, 42);
    let throughput = m.throughput_ops_per_sec;
    let cases = measurements_to_cases(&[m], 1.0);
    assert_eq!(cases.len(), 1);
    assert!((cases[0].throughput_franken_tps - throughput).abs() < 1e-6);
    assert!((cases[0].throughput_baseline_tps - throughput).abs() < 1e-6);
    assert!(cases[0].behavior_equivalent);
}

#[test]
fn measurements_to_cases_baseline_multiplier() {
    let m = run_boot_storm(ScaleProfile::Small, 42);
    let throughput = m.throughput_ops_per_sec;
    let cases = measurements_to_cases(&[m], 2.0);
    let expected_baseline = throughput / 2.0;
    assert!((cases[0].throughput_baseline_tps - expected_baseline).abs() < 1e-6);
}

#[test]
fn measurements_to_cases_invariant_violations_not_equivalent() {
    let mut m = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        50,
        100,
        200,
    );
    m.invariant_violations = 5;
    let cases = measurements_to_cases(&[m], 1.0);
    assert!(!cases[0].behavior_equivalent);
}

#[test]
fn measurements_to_cases_empty_input() {
    let cases = measurements_to_cases(&[], 1.0);
    assert!(cases.is_empty());
}

#[test]
fn measurements_to_cases_workload_id_contains_family_and_profile() {
    let m = make_measurement(
        BenchmarkFamily::MixedCpuIoAgentMesh,
        ScaleProfile::Large,
        1000.0,
        10,
        20,
        30,
    );
    let cases = measurements_to_cases(&[m], 1.0);
    assert!(cases[0].workload_id.contains("mixed-cpu-io-agent-mesh"));
    assert!(cases[0].workload_id.contains("L"));
}

// ===========================================================================
// 17. BenchmarkRuntimePins
// ===========================================================================

#[test]
fn benchmark_runtime_pins_default_non_empty() {
    let pins = BenchmarkRuntimePins::default();
    assert!(!pins.franken_engine.is_empty());
    assert!(!pins.node_lts.is_empty());
    assert!(!pins.bun_stable.is_empty());
}

#[test]
fn benchmark_runtime_pins_franken_engine_starts_with_prefix() {
    let pins = BenchmarkRuntimePins::default();
    assert!(pins.franken_engine.starts_with("franken-engine-"));
}

#[test]
fn benchmark_runtime_pins_serde_roundtrip() {
    let pins = BenchmarkRuntimePins::default();
    let json = serde_json::to_string(&pins).expect("serialize");
    let deserialized: BenchmarkRuntimePins = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(pins, deserialized);
}

#[test]
fn benchmark_runtime_pins_clone_eq() {
    let pins = BenchmarkRuntimePins::default();
    let cloned = pins.clone();
    assert_eq!(pins, cloned);
}

// ===========================================================================
// 18. BenchmarkFairnessPolicy
// ===========================================================================

#[test]
fn benchmark_fairness_policy_default_values() {
    let policy = BenchmarkFairnessPolicy::default();
    assert_eq!(policy.warmup_runs, 2);
    assert_eq!(policy.sample_count, 7);
    assert_eq!(policy.case_timeout_ms, 30_000);
}

#[test]
fn benchmark_fairness_policy_serde_roundtrip() {
    let policy = BenchmarkFairnessPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let deserialized: BenchmarkFairnessPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, deserialized);
}

// ===========================================================================
// 19. BenchmarkHarnessContract
// ===========================================================================

#[test]
fn benchmark_harness_contract_default_valid() {
    let contract = BenchmarkHarnessContract::default();
    assert!(validate_harness_contract(&contract).is_ok());
}

#[test]
fn benchmark_harness_contract_serde_roundtrip() {
    let contract = BenchmarkHarnessContract::default();
    let json = serde_json::to_string(&contract).expect("serialize");
    let deserialized: BenchmarkHarnessContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(contract, deserialized);
}

// ===========================================================================
// 20. validate_harness_contract error paths
// ===========================================================================

#[test]
fn validate_harness_contract_empty_franken_engine_pin() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.runtime_pins.franken_engine = String::new();
    let err = validate_harness_contract(&contract).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::EmptyRuntimePin {
            runtime: "franken_engine"
        }
    ));
    let msg = err.to_string();
    assert!(msg.contains("franken_engine"));
    assert!(msg.contains("non-empty"));
}

#[test]
fn validate_harness_contract_whitespace_only_node_lts() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.runtime_pins.node_lts = "   ".to_string();
    let err = validate_harness_contract(&contract).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::EmptyRuntimePin {
            runtime: "node_lts"
        }
    ));
}

#[test]
fn validate_harness_contract_empty_bun_stable() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.runtime_pins.bun_stable = String::new();
    let err = validate_harness_contract(&contract).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::EmptyRuntimePin {
            runtime: "bun_stable"
        }
    ));
}

#[test]
fn validate_harness_contract_invalid_warmup_runs() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.fairness_policy.warmup_runs = 0;
    let err = validate_harness_contract(&contract).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::InvalidWarmupRuns { .. }
    ));
    let msg = err.to_string();
    assert!(msg.contains("warmup_runs"));
}

#[test]
fn validate_harness_contract_invalid_sample_count() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.fairness_policy.sample_count = 1;
    let err = validate_harness_contract(&contract).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::InvalidSampleCount { .. }
    ));
    let msg = err.to_string();
    assert!(msg.contains("sample_count"));
}

#[test]
fn validate_harness_contract_invalid_case_timeout_ms() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.fairness_policy.case_timeout_ms = 0;
    let err = validate_harness_contract(&contract).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::InvalidCaseTimeoutMs { .. }
    ));
    let msg = err.to_string();
    assert!(msg.contains("case_timeout_ms"));
}

#[test]
fn harness_contract_error_is_std_error() {
    let err = BenchmarkHarnessContractError::EmptyRuntimePin {
        runtime: "franken_engine",
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

// ===========================================================================
// 21. BenchmarkEnvironmentManifest serde roundtrip
// ===========================================================================

#[test]
fn benchmark_environment_manifest_serde_roundtrip() {
    let manifest = BenchmarkEnvironmentManifest {
        schema_version: BENCHMARK_ENV_SCHEMA_VERSION.to_string(),
        run_id: "test-manifest-001".to_string(),
        run_date: "2026-03-18".to_string(),
        seed: 42,
        locale: "en_US.UTF-8".to_string(),
        timezone: "UTC".to_string(),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        runtime_pins: BenchmarkRuntimePins::default(),
        fairness_policy: BenchmarkFairnessPolicy::default(),
    };
    let json = serde_json::to_string_pretty(&manifest).expect("serialize");
    let deserialized: BenchmarkEnvironmentManifest =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(manifest, deserialized);
}

#[test]
fn benchmark_environment_manifest_fields() {
    let manifest = BenchmarkEnvironmentManifest {
        schema_version: BENCHMARK_ENV_SCHEMA_VERSION.to_string(),
        run_id: "field-check".to_string(),
        run_date: "2026-03-18".to_string(),
        seed: 99,
        locale: "C".to_string(),
        timezone: "America/New_York".to_string(),
        os: "linux".to_string(),
        arch: "aarch64".to_string(),
        runtime_pins: BenchmarkRuntimePins::default(),
        fairness_policy: BenchmarkFairnessPolicy::default(),
    };
    assert_eq!(manifest.run_id, "field-check");
    assert_eq!(manifest.seed, 99);
    assert_eq!(manifest.os, "linux");
    assert_eq!(manifest.arch, "aarch64");
}

// ===========================================================================
// 22. BenchmarkSuiteEvent
// ===========================================================================

#[test]
fn benchmark_suite_event_constructed_by_suite_runner() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "event-check".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    assert_eq!(result.events.len(), 1);
    let evt = &result.events[0];
    assert_eq!(evt.trace_id, "event-check");
    assert_eq!(evt.policy_id, "benchmark-e2e");
    assert_eq!(evt.component, BENCHMARK_E2E_COMPONENT);
    assert_eq!(evt.event, "benchmark_case_completed");
    assert!(evt.error_code.is_none());
    assert_eq!(evt.family.as_deref(), Some("boot-storm"));
    assert_eq!(evt.profile.as_deref(), Some("S"));
}

#[test]
fn benchmark_suite_event_clone_and_debug() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "clone-debug-evt".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let evt = &result.events[0];
    let cloned = evt.clone();
    assert_eq!(cloned.trace_id, evt.trace_id);
    assert!(!format!("{evt:?}").is_empty());
}

// ===========================================================================
// 23. write_evidence_artifacts
// ===========================================================================

#[test]
fn write_evidence_artifacts_creates_all_files() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-evidence-files".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_evidence");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_evidence_artifacts(&result, &dir).unwrap();
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.evidence_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(artifacts.benchmark_env_manifest_path.exists());
    assert!(artifacts.raw_results_archive_path.exists());
    assert!(artifacts.summary_path.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_evidence_artifacts_manifest_valid_json() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-manifest-json".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_manifest");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_evidence_artifacts(&result, &dir).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.run_manifest_path).unwrap())
            .unwrap();
    assert_eq!(manifest["schema_version"], BENCHMARK_E2E_SCHEMA_VERSION);
    assert_eq!(manifest["run_id"], "test-manifest-json");
    assert_eq!(manifest["seed"], 42);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_evidence_artifacts_evidence_jsonl_valid() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-jsonl".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_jsonl");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_evidence_artifacts(&result, &dir).unwrap();
    let evidence = std::fs::read_to_string(&artifacts.evidence_path).unwrap();
    assert!(!evidence.is_empty());
    for line in evidence.lines() {
        let _: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("invalid JSON line: {e}"));
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_evidence_artifacts_env_manifest_valid() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-env-manifest".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_env_manifest");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_evidence_artifacts(&result, &dir).unwrap();
    let env_manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&artifacts.benchmark_env_manifest_path).unwrap(),
    )
    .unwrap();
    assert_eq!(env_manifest["schema_version"], BENCHMARK_ENV_SCHEMA_VERSION);
    assert!(
        env_manifest["runtime_pins"]["franken_engine"]
            .as_str()
            .unwrap()
            .starts_with("franken-engine-")
    );
    assert_eq!(env_manifest["fairness_policy"]["warmup_runs"], 2);
    assert_eq!(env_manifest["fairness_policy"]["sample_count"], 7);
    assert_eq!(env_manifest["fairness_policy"]["case_timeout_ms"], 30_000);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_evidence_artifacts_raw_results_archive_valid() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-raw-archive".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_raw");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_evidence_artifacts(&result, &dir).unwrap();
    let raw_archive: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&artifacts.raw_results_archive_path).unwrap(),
    )
    .unwrap();
    assert_eq!(
        raw_archive["schema_version"],
        "franken-engine.benchmark-e2e.raw-results.v1"
    );
    assert!(
        raw_archive["measurements"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_evidence_artifacts_summary_valid() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm, BenchmarkFamily::CapabilityChurn],
        thresholds: RegressionThresholds::default(),
        run_id: "test-summary".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_summary");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_evidence_artifacts(&result, &dir).unwrap();
    let summary: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&artifacts.summary_path).unwrap()).unwrap();
    assert_eq!(summary["schema_version"], BENCHMARK_E2E_SCHEMA_VERSION);
    assert_eq!(summary["run_id"], "test-summary");
    let families = summary["families"].as_array().unwrap();
    assert_eq!(families.len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_evidence_artifacts_events_file_valid_json() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-events-json".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_events");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_evidence_artifacts(&result, &dir).unwrap();
    let events = std::fs::read_to_string(&artifacts.events_path).unwrap();
    assert!(events.lines().all(|line| {
        serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| v.get("trace_id").cloned())
            .is_some()
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_evidence_artifacts_commands_file() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-commands".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_commands");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_evidence_artifacts(&result, &dir).unwrap();
    let commands = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert!(commands.contains("scripts/run_benchmark_e2e_suite.sh report"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn write_evidence_artifacts_with_regressions() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-reg-evidence".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let baseline = run_benchmark_suite(&config);
    let result = run_benchmark_suite_with_regression(&config, &baseline.measurements);

    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_reg_evidence");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = write_evidence_artifacts(&result, &dir).unwrap();

    let evidence = std::fs::read_to_string(&artifacts.evidence_path).unwrap();
    let lines: Vec<&str> = evidence.lines().collect();
    // Should have measurement + regression + event lines
    assert!(lines.len() >= 3);

    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 24. BenchmarkEvidenceArtifacts struct accessibility
// ===========================================================================

#[test]
fn benchmark_evidence_artifacts_paths_are_under_output_dir() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-paths".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_paths");
    let _ = std::fs::remove_dir_all(&dir);

    let artifacts = write_evidence_artifacts(&result, &dir).unwrap();
    assert!(artifacts.run_manifest_path.starts_with(&dir));
    assert!(artifacts.evidence_path.starts_with(&dir));
    assert!(artifacts.events_path.starts_with(&dir));
    assert!(artifacts.commands_path.starts_with(&dir));
    assert!(artifacts.benchmark_env_manifest_path.starts_with(&dir));
    assert!(artifacts.raw_results_archive_path.starts_with(&dir));
    assert!(artifacts.summary_path.starts_with(&dir));

    assert!(!format!("{artifacts:?}").is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 25. Medium profile sanity checks
// ===========================================================================

#[test]
fn boot_storm_medium_completes() {
    let m = run_boot_storm(ScaleProfile::Medium, 42);
    assert_eq!(m.profile, ScaleProfile::Medium);
    assert!(m.total_operations > 0);
    assert!(m.peak_extensions_alive > 0);
}

// ===========================================================================
// 26. LatencyDistribution invariants from real benchmark runs
// ===========================================================================

#[test]
fn boot_storm_latency_p50_lte_p95_lte_p99() {
    let m = run_boot_storm(ScaleProfile::Small, 42);
    assert!(
        m.latency.p50_us <= m.latency.p95_us,
        "boot storm: p50 ({}) > p95 ({})",
        m.latency.p50_us,
        m.latency.p95_us
    );
    assert!(
        m.latency.p95_us <= m.latency.p99_us,
        "boot storm: p95 ({}) > p99 ({})",
        m.latency.p95_us,
        m.latency.p99_us
    );
}

#[test]
fn capability_churn_latency_invariants() {
    let m = run_capability_churn(ScaleProfile::Small, 42);
    assert!(m.latency.min_us <= m.latency.p50_us);
    assert!(m.latency.p50_us <= m.latency.p95_us);
    assert!(m.latency.p95_us <= m.latency.p99_us);
    assert!(m.latency.p99_us <= m.latency.max_us);
}

#[test]
fn all_families_latency_invariants() {
    for family in BenchmarkFamily::all() {
        let m = run_benchmark(*family, ScaleProfile::Small, 42);
        assert!(
            m.latency.min_us <= m.latency.p50_us,
            "{:?}: min ({}) > p50 ({})",
            family,
            m.latency.min_us,
            m.latency.p50_us
        );
        assert!(
            m.latency.p50_us <= m.latency.p95_us,
            "{:?}: p50 ({}) > p95 ({})",
            family,
            m.latency.p50_us,
            m.latency.p95_us
        );
        assert!(
            m.latency.p95_us <= m.latency.p99_us,
            "{:?}: p95 ({}) > p99 ({})",
            family,
            m.latency.p95_us,
            m.latency.p99_us
        );
    }
}

// ===========================================================================
// 27. Cross-family correctness digest uniqueness
// ===========================================================================

#[test]
fn different_families_produce_different_digests() {
    let m1 = run_boot_storm(ScaleProfile::Small, 42);
    let m2 = run_capability_churn(ScaleProfile::Small, 42);
    assert_ne!(m1.correctness_digest, m2.correctness_digest);
}

// ===========================================================================
// 28. Script artifact bridge (env-gated)
// ===========================================================================

#[test]
fn benchmark_e2e_script_emits_artifacts_to_env_dir() {
    let Some(raw_dir) = std::env::var_os("FRANKEN_BENCH_E2E_OUTPUT_DIR") else {
        return;
    };
    let output_dir = std::path::PathBuf::from(raw_dir);
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![
            BenchmarkFamily::BootStorm,
            BenchmarkFamily::MixedCpuIoAgentMesh,
        ],
        thresholds: RegressionThresholds::default(),
        run_id: "script-report-run".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let artifacts = write_evidence_artifacts(&result, &output_dir)
        .expect("script report run should emit benchmark artifacts");
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.evidence_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(artifacts.benchmark_env_manifest_path.exists());
    assert!(artifacts.raw_results_archive_path.exists());
    assert!(artifacts.summary_path.exists());
}

// ===========================================================================
// 29. Full lifecycle: suite + regression + evidence
// ===========================================================================

#[test]
fn full_lifecycle_suite_regression_and_evidence() {
    // 1. Run a baseline suite
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "full-lifecycle".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let baseline_result = run_benchmark_suite(&config);
    assert_eq!(baseline_result.measurements.len(), 1);

    // 2. Compare baseline against itself -- no regression
    let regression = detect_regression(
        &baseline_result.measurements[0],
        &baseline_result.measurements[0],
        &config.thresholds,
    );
    assert!(!regression.blocked);

    // 3. Run suite with regression detection
    let result_with_reg =
        run_benchmark_suite_with_regression(&config, &baseline_result.measurements);
    assert!(!result_with_reg.regressions.is_empty());

    // 4. Write evidence artifacts
    let dir = std::env::temp_dir().join("franken_bench_e2e_integ_full_lifecycle");
    let _ = std::fs::remove_dir_all(&dir);
    let artifacts = write_evidence_artifacts(&result_with_reg, &dir).unwrap();
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.summary_path.exists());

    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 30. Serde roundtrips for all serializable types (collected)
// ===========================================================================

#[test]
fn serde_roundtrip_benchmark_runtime_pins() {
    let original = BenchmarkRuntimePins::default();
    let json = serde_json::to_string(&original).unwrap();
    let restored: BenchmarkRuntimePins = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn serde_roundtrip_benchmark_fairness_policy() {
    let original = BenchmarkFairnessPolicy::default();
    let json = serde_json::to_string(&original).unwrap();
    let restored: BenchmarkFairnessPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn serde_roundtrip_benchmark_harness_contract() {
    let original = BenchmarkHarnessContract::default();
    let json = serde_json::to_string(&original).unwrap();
    let restored: BenchmarkHarnessContract = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn serde_roundtrip_benchmark_environment_manifest() {
    let original = BenchmarkEnvironmentManifest {
        schema_version: BENCHMARK_ENV_SCHEMA_VERSION.to_string(),
        run_id: "serde-test".to_string(),
        run_date: "2026-03-18".to_string(),
        seed: 42,
        locale: "C".to_string(),
        timezone: "UTC".to_string(),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        runtime_pins: BenchmarkRuntimePins::default(),
        fairness_policy: BenchmarkFairnessPolicy::default(),
    };
    let json = serde_json::to_string_pretty(&original).unwrap();
    let restored: BenchmarkEnvironmentManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(original, restored);
}

// ===========================================================================
// 31. Misc edge cases
// ===========================================================================

#[test]
fn suite_config_empty_families_produces_empty_result() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![],
        thresholds: RegressionThresholds::default(),
        run_id: "empty-families".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    assert!(result.measurements.is_empty());
    assert!(result.events.is_empty());
    assert_eq!(result.total_operations, 0);
}

#[test]
fn suite_config_empty_profiles_produces_empty_result() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "empty-profiles".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    assert!(result.measurements.is_empty());
    assert!(result.events.is_empty());
}

#[test]
fn multiple_families_suite_events_decision_ids_unique() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: BenchmarkFamily::all().to_vec(),
        thresholds: RegressionThresholds::default(),
        run_id: "decision-id-check".to_string(),
        run_date: "2026-03-18".to_string(),
    };
    let result = run_benchmark_suite(&config);
    let decision_ids: BTreeSet<&str> = result
        .events
        .iter()
        .map(|e| e.decision_id.as_str())
        .collect();
    assert_eq!(decision_ids.len(), result.events.len());
}

#[test]
fn measurements_to_cases_weight_uses_family_weight_divided_by_three() {
    let m = make_measurement(
        BenchmarkFamily::BootStorm,
        ScaleProfile::Small,
        1000.0,
        50,
        100,
        200,
    );
    let cases = measurements_to_cases(&[m], 1.0);
    let expected_weight = BenchmarkFamily::BootStorm.default_weight() / 3.0;
    assert!(
        (cases[0].weight.unwrap() - expected_weight).abs() < 1e-12,
        "expected weight {expected_weight}, got {:?}",
        cases[0].weight
    );
}
