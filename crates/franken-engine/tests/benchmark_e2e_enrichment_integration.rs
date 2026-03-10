#![forbid(unsafe_code)]
//! Enrichment integration tests for `benchmark_e2e`.
//!
//! Adds as_str exactness, Debug distinctness, default values, PRNG
//! determinism, regression detection, and benchmark runner coverage
//! beyond the existing 29 integration tests.

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
    BenchmarkFairnessPolicy, BenchmarkFamily, BenchmarkHarnessContract,
    BenchmarkHarnessContractError, BenchmarkRuntimePins, BenchmarkSuiteConfig, LatencyDistribution,
    MIN_START_BUDGET_MILLIONTHS, RegressionThresholds, ScaleProfile, Xorshift64, detect_regression,
    run_benchmark, run_benchmark_suite, run_benchmark_suite_with_regression,
    validate_harness_contract,
};

// ===========================================================================
// 1) ScaleProfile — exact as_str
// ===========================================================================

#[test]
fn scale_profile_as_str_exact() {
    assert_eq!(ScaleProfile::Small.as_str(), "S");
    assert_eq!(ScaleProfile::Medium.as_str(), "M");
    assert_eq!(ScaleProfile::Large.as_str(), "L");
}

#[test]
fn scale_profile_extension_count() {
    assert_eq!(ScaleProfile::Small.extension_count(), 10);
    assert_eq!(ScaleProfile::Medium.extension_count(), 50);
    assert_eq!(ScaleProfile::Large.extension_count(), 200);
}

#[test]
fn scale_profile_iterations() {
    assert_eq!(ScaleProfile::Small.iterations(), 100);
    assert_eq!(ScaleProfile::Medium.iterations(), 500);
    assert_eq!(ScaleProfile::Large.iterations(), 2_000);
}

// ===========================================================================
// 2) BenchmarkFamily — exact as_str / all()
// ===========================================================================

#[test]
fn benchmark_family_as_str_all_distinct() {
    let all = BenchmarkFamily::all();
    let strs: Vec<&str> = all.iter().map(|f| f.as_str()).collect();
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), all.len());
}

#[test]
fn benchmark_family_all_count() {
    assert_eq!(BenchmarkFamily::all().len(), 5);
}

#[test]
fn benchmark_family_default_weights_sum_to_one() {
    let total: f64 = BenchmarkFamily::all()
        .iter()
        .map(|f| f.default_weight())
        .sum();
    assert!(
        (total - 1.0).abs() < 0.001,
        "weights should sum to ~1.0, got {total}"
    );
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_scale_profile() {
    let variants = [
        format!("{:?}", ScaleProfile::Small),
        format!("{:?}", ScaleProfile::Medium),
        format!("{:?}", ScaleProfile::Large),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_benchmark_family() {
    let variants: Vec<String> = BenchmarkFamily::all()
        .iter()
        .map(|f| format!("{f:?}"))
        .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 4) Constants stability
// ===========================================================================

#[test]
fn constants_stable() {
    assert_eq!(BENCHMARK_E2E_COMPONENT, "benchmark_e2e");
    assert_eq!(
        BENCHMARK_E2E_SCHEMA_VERSION,
        "franken-engine.benchmark-e2e.v1"
    );
    assert_eq!(MIN_START_BUDGET_MILLIONTHS, 1_000);
}

// ===========================================================================
// 5) RegressionThresholds — default
// ===========================================================================

#[test]
fn regression_thresholds_default() {
    let t = RegressionThresholds::default();
    assert!((t.throughput_regression_pct - 5.0).abs() < 0.001);
    assert!((t.p95_latency_regression_pct - 10.0).abs() < 0.001);
    assert!((t.p99_latency_regression_pct - 15.0).abs() < 0.001);
}

// ===========================================================================
// 6) BenchmarkSuiteConfig — default
// ===========================================================================

#[test]
fn suite_config_default() {
    let config = BenchmarkSuiteConfig::default();
    assert_eq!(config.seed, 42);
    assert_eq!(config.profiles.len(), 3);
    assert_eq!(config.families.len(), 5);
}

// ===========================================================================
// 7) Xorshift64 — determinism
// ===========================================================================

#[test]
fn xorshift64_same_seed_same_sequence() {
    let mut rng1 = Xorshift64::new(42);
    let mut rng2 = Xorshift64::new(42);
    for _ in 0..20 {
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }
}

#[test]
fn xorshift64_zero_seed_works() {
    let mut rng = Xorshift64::new(0);
    let v = rng.next_u64();
    assert_ne!(v, 0);
}

#[test]
fn xorshift64_different_seeds_differ() {
    let mut rng1 = Xorshift64::new(1);
    let mut rng2 = Xorshift64::new(2);
    let v1 = rng1.next_u64();
    let v2 = rng2.next_u64();
    assert_ne!(v1, v2);
}

#[test]
fn xorshift64_next_usize_in_bound() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..100 {
        let v = rng.next_usize(10);
        assert!(v < 10);
    }
}

// ===========================================================================
// 8) LatencyDistribution — from_samples
// ===========================================================================

#[test]
fn latency_distribution_from_samples() {
    let mut samples = vec![100, 200, 300, 400, 500];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 100);
    assert_eq!(dist.max_us, 500);
    assert_eq!(dist.sample_count, 5);
}

#[test]
fn latency_distribution_single_sample() {
    let mut samples = vec![42];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 42);
    assert_eq!(dist.max_us, 42);
    assert_eq!(dist.p50_us, 42);
}

// ===========================================================================
// 9) run_benchmark — produces measurements
// ===========================================================================

#[test]
fn run_benchmark_produces_measurement() {
    let m = run_benchmark(BenchmarkFamily::BootStorm, ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::BootStorm);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.duration_us > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
}

#[test]
fn run_benchmark_deterministic() {
    let m1 = run_benchmark(BenchmarkFamily::CapabilityChurn, ScaleProfile::Small, 42);
    let m2 = run_benchmark(BenchmarkFamily::CapabilityChurn, ScaleProfile::Small, 42);
    assert_eq!(m1.correctness_digest, m2.correctness_digest);
    assert_eq!(m1.total_operations, m2.total_operations);
}

// ===========================================================================
// 10) detect_regression
// ===========================================================================

#[test]
fn detect_regression_no_regression() {
    let m1 = run_benchmark(BenchmarkFamily::BootStorm, ScaleProfile::Small, 42);
    let m2 = m1.clone();
    let thresholds = RegressionThresholds::default();
    let result = detect_regression(&m2, &m1, &thresholds);
    assert!(!result.blocked);
    assert!(result.blockers.is_empty());
}

// ===========================================================================
// 11) run_benchmark_suite
// ===========================================================================

#[test]
fn run_suite_default_config() {
    let config = BenchmarkSuiteConfig {
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        ..BenchmarkSuiteConfig::default()
    };
    let result = run_benchmark_suite(&config);
    assert!(!result.measurements.is_empty());
    assert!(result.total_operations > 0);
    assert!(!result.events.is_empty());
}

// ===========================================================================
// 12) Harness contract validation
// ===========================================================================

#[test]
fn validate_harness_contract_default_passes() {
    let contract = BenchmarkHarnessContract::default();
    validate_harness_contract(&contract).expect("default contract must validate");
}

#[test]
fn validate_harness_contract_rejects_empty_runtime_pin() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.runtime_pins.franken_engine = String::new();
    let err = validate_harness_contract(&contract).expect_err("should reject");
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::EmptyRuntimePin { .. }
    ));
}

#[test]
fn validate_harness_contract_rejects_empty_node_pin() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.runtime_pins.node_lts = String::new();
    let err = validate_harness_contract(&contract).expect_err("should reject");
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::EmptyRuntimePin { .. }
    ));
}

#[test]
fn validate_harness_contract_rejects_empty_bun_pin() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.runtime_pins.bun_stable = String::new();
    let err = validate_harness_contract(&contract).expect_err("should reject");
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::EmptyRuntimePin { .. }
    ));
}

#[test]
fn validate_harness_contract_rejects_zero_warmup_runs() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.fairness_policy.warmup_runs = 0;
    let err = validate_harness_contract(&contract).expect_err("should reject");
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::InvalidWarmupRuns { .. }
    ));
}

#[test]
fn validate_harness_contract_rejects_low_sample_count() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.fairness_policy.sample_count = 2;
    let err = validate_harness_contract(&contract).expect_err("should reject");
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::InvalidSampleCount { .. }
    ));
}

#[test]
fn validate_harness_contract_rejects_zero_timeout() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.fairness_policy.case_timeout_ms = 0;
    let err = validate_harness_contract(&contract).expect_err("should reject");
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::InvalidCaseTimeoutMs { .. }
    ));
}

#[test]
fn harness_contract_error_display_non_empty() {
    let errors: Vec<BenchmarkHarnessContractError> = vec![
        BenchmarkHarnessContractError::EmptyRuntimePin {
            runtime: "franken_engine",
        },
        BenchmarkHarnessContractError::InvalidWarmupRuns { min: 1, actual: 0 },
        BenchmarkHarnessContractError::InvalidSampleCount { min: 3, actual: 1 },
        BenchmarkHarnessContractError::InvalidCaseTimeoutMs {
            min: 1000,
            actual: 50,
        },
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty(), "display empty: {err:?}");
    }
}

#[test]
fn harness_contract_error_is_std_error() {
    let err = BenchmarkHarnessContractError::EmptyRuntimePin {
        runtime: "node_lts",
    };
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

// ===========================================================================
// 13) Serde round-trips for harness types
// ===========================================================================

#[test]
fn runtime_pins_serde_round_trip() {
    let pins = BenchmarkRuntimePins::default();
    let json = serde_json::to_string(&pins).expect("serialize");
    let recovered: BenchmarkRuntimePins = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(pins, recovered);
}

#[test]
fn fairness_policy_serde_round_trip() {
    let policy = BenchmarkFairnessPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: BenchmarkFairnessPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, recovered);
}

#[test]
fn harness_contract_serde_round_trip() {
    let contract = BenchmarkHarnessContract::default();
    let json = serde_json::to_string(&contract).expect("serialize");
    let recovered: BenchmarkHarnessContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(contract, recovered);
}

// ===========================================================================
// 14) Run each benchmark family individually
// ===========================================================================

#[test]
fn run_each_family_small() {
    for family in BenchmarkFamily::all() {
        let m = run_benchmark(*family, ScaleProfile::Small, 99);
        assert_eq!(m.family, *family);
        assert_eq!(m.profile, ScaleProfile::Small);
        assert!(m.total_operations > 0);
        assert!(!m.correctness_digest.is_empty());
    }
}

#[test]
fn run_benchmark_medium_profile() {
    let m = run_benchmark(
        BenchmarkFamily::MixedCpuIoAgentMesh,
        ScaleProfile::Medium,
        42,
    );
    assert_eq!(m.profile, ScaleProfile::Medium);
    assert!(m.total_operations > 0);
}

// ===========================================================================
// 15) Regression detection edge cases
// ===========================================================================

#[test]
fn detect_regression_throughput_drop_is_blocked() {
    let baseline = run_benchmark(BenchmarkFamily::BootStorm, ScaleProfile::Small, 42);
    let mut current = baseline.clone();
    // Simulate severe throughput regression
    current.throughput_ops_per_sec = baseline.throughput_ops_per_sec * 0.5;
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
    assert!(!result.blockers.is_empty());
}

#[test]
fn detect_regression_p95_spike_is_blocked() {
    let baseline = run_benchmark(BenchmarkFamily::BootStorm, ScaleProfile::Small, 42);
    let mut current = baseline.clone();
    // Simulate p95 latency spike
    current.latency.p95_us = baseline.latency.p95_us * 3;
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
}

#[test]
fn detect_regression_p99_spike_is_blocked() {
    let baseline = run_benchmark(BenchmarkFamily::BootStorm, ScaleProfile::Small, 42);
    let mut current = baseline.clone();
    current.latency.p99_us = baseline.latency.p99_us * 3;
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
}

#[test]
fn detect_regression_result_family_and_profile_match() {
    let m = run_benchmark(BenchmarkFamily::ReloadRevokeChurn, ScaleProfile::Small, 42);
    let result = detect_regression(&m, &m, &RegressionThresholds::default());
    assert_eq!(result.family, BenchmarkFamily::ReloadRevokeChurn);
    assert_eq!(result.profile, ScaleProfile::Small);
}

// ===========================================================================
// 16) Suite with regression baselines
// ===========================================================================

#[test]
fn suite_with_regression_no_blockers_when_identical() {
    let config = BenchmarkSuiteConfig {
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        ..BenchmarkSuiteConfig::default()
    };
    let baseline_result = run_benchmark_suite(&config);
    let result = run_benchmark_suite_with_regression(&config, &baseline_result.measurements);
    assert!(!result.blocked);
}

#[test]
fn suite_events_have_component_field() {
    let config = BenchmarkSuiteConfig {
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        ..BenchmarkSuiteConfig::default()
    };
    let result = run_benchmark_suite(&config);
    for event in &result.events {
        assert_eq!(event.component, BENCHMARK_E2E_COMPONENT);
    }
}

#[test]
fn suite_events_contain_case_completed() {
    let config = BenchmarkSuiteConfig {
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        ..BenchmarkSuiteConfig::default()
    };
    let result = run_benchmark_suite(&config);
    assert!(
        result
            .events
            .iter()
            .any(|e| e.event == "benchmark_case_completed")
    );
}

// ===========================================================================
// 17) Constants and schema stability
// ===========================================================================

#[test]
fn benchmark_env_schema_version_stable() {
    assert_eq!(
        BENCHMARK_ENV_SCHEMA_VERSION,
        "franken-engine.benchmark-env-manifest.v1"
    );
}

// ===========================================================================
// 18) PRNG edge cases
// ===========================================================================

#[test]
fn xorshift64_next_bool_at_boundary() {
    let mut rng = Xorshift64::new(42);
    // 0% should always be false
    for _ in 0..20 {
        assert!(!rng.next_bool(0));
    }
    // 100% should always be true
    for _ in 0..20 {
        assert!(rng.next_bool(100));
    }
}

// ===========================================================================
// 19) LatencyDistribution edge cases
// ===========================================================================

#[test]
fn latency_distribution_percentiles_ordered() {
    let mut samples: Vec<u64> = (1..=100).collect();
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert!(dist.p50_us <= dist.p95_us);
    assert!(dist.p95_us <= dist.p99_us);
    assert!(dist.min_us <= dist.p50_us);
    assert!(dist.p99_us <= dist.max_us);
}

#[test]
fn latency_distribution_identical_samples() {
    let mut samples = vec![500; 50];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 500);
    assert_eq!(dist.max_us, 500);
    assert_eq!(dist.p50_us, 500);
    assert_eq!(dist.p95_us, 500);
    assert_eq!(dist.p99_us, 500);
}

// ===========================================================================
// 20) Suite determinism
// ===========================================================================

#[test]
fn suite_deterministic_same_config() {
    let config = BenchmarkSuiteConfig {
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        ..BenchmarkSuiteConfig::default()
    };
    let r1 = run_benchmark_suite(&config);
    let r2 = run_benchmark_suite(&config);
    assert_eq!(r1.total_operations, r2.total_operations);
    assert_eq!(r1.measurements.len(), r2.measurements.len());
    for (m1, m2) in r1.measurements.iter().zip(r2.measurements.iter()) {
        assert_eq!(m1.correctness_digest, m2.correctness_digest);
    }
}
