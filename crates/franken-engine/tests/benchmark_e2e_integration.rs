//! Integration tests for `frankenengine_engine::benchmark_e2e`.
//!
//! Exercises the benchmark E2E framework from the public crate boundary:
//! ScaleProfile, BenchmarkFamily, LatencyDistribution, BenchmarkMeasurement,
//! RegressionThresholds, RegressionResult, detect_regression, Xorshift64,
//! run_boot_storm, run_capability_churn, run_mixed_cpu_io_agent_mesh,
//! run_reload_revoke_churn, run_adversarial_noise_under_load, run_benchmark,
//! BenchmarkSuiteConfig, run_benchmark_suite, measurements_to_cases.

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

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn constants_non_empty() {
    assert!(!BENCHMARK_E2E_COMPONENT.is_empty());
    assert!(!BENCHMARK_E2E_SCHEMA_VERSION.is_empty());
    const { assert!(MIN_START_BUDGET_MILLIONTHS > 0) };
}

// ── ScaleProfile ────────────────────────────────────────────────────────

#[test]
fn scale_profile_as_str() {
    assert_eq!(ScaleProfile::Small.as_str(), "S");
    assert_eq!(ScaleProfile::Medium.as_str(), "M");
    assert_eq!(ScaleProfile::Large.as_str(), "L");
}

#[test]
fn scale_profile_extension_count_monotonic() {
    assert!(ScaleProfile::Small.extension_count() < ScaleProfile::Medium.extension_count());
    assert!(ScaleProfile::Medium.extension_count() < ScaleProfile::Large.extension_count());
}

#[test]
fn scale_profile_iterations_monotonic() {
    assert!(ScaleProfile::Small.iterations() < ScaleProfile::Medium.iterations());
    assert!(ScaleProfile::Medium.iterations() < ScaleProfile::Large.iterations());
}

// ── BenchmarkFamily ─────────────────────────────────────────────────────

#[test]
fn benchmark_family_as_str() {
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
fn benchmark_family_all_has_five() {
    assert_eq!(BenchmarkFamily::all().len(), 5);
}

#[test]
fn benchmark_family_weights_sum_to_one() {
    let sum: f64 = BenchmarkFamily::all()
        .iter()
        .map(|f| f.default_weight())
        .sum();
    assert!((sum - 1.0).abs() < 1e-9);
}

// ── LatencyDistribution ─────────────────────────────────────────────────

#[test]
fn latency_distribution_from_samples() {
    let mut samples = vec![100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 100);
    assert_eq!(dist.max_us, 1000);
    assert_eq!(dist.sample_count, 10);
    assert!(dist.p50_us >= 100 && dist.p50_us <= 1000);
    assert!(dist.p95_us >= dist.p50_us);
    assert!(dist.p99_us >= dist.p95_us);
}

#[test]
fn latency_distribution_single_sample() {
    let mut samples = vec![42];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert_eq!(dist.min_us, 42);
    assert_eq!(dist.max_us, 42);
    assert_eq!(dist.p50_us, 42);
    assert_eq!(dist.sample_count, 1);
}

// ── RegressionThresholds ────────────────────────────────────────────────

#[test]
fn regression_thresholds_default() {
    let t = RegressionThresholds::default();
    assert!(t.throughput_regression_pct > 0.0);
    assert!(t.p95_latency_regression_pct > 0.0);
    assert!(t.p99_latency_regression_pct > 0.0);
}

// ── detect_regression ───────────────────────────────────────────────────

fn make_measurement(
    family: BenchmarkFamily,
    throughput: f64,
    p95: u64,
    p99: u64,
) -> BenchmarkMeasurement {
    BenchmarkMeasurement {
        family,
        profile: ScaleProfile::Small,
        throughput_ops_per_sec: throughput,
        latency: LatencyDistribution {
            p50_us: 100,
            p95_us: p95,
            p99_us: p99,
            min_us: 10,
            max_us: p99 + 100,
            sample_count: 100,
        },
        total_operations: 1000,
        duration_us: 100_000,
        correctness_digest: "test-digest".to_string(),
        invariant_violations: 0,
        security_events: 0,
        peak_extensions_alive: 10,
    }
}

#[test]
fn no_regression_when_performance_same() {
    let baseline = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 500, 1000);
    let current = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 500, 1000);
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(!result.blocked);
    assert!(result.blockers.is_empty());
}

#[test]
fn throughput_regression_detected() {
    let baseline = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 500, 1000);
    // 50% throughput regression
    let current = make_measurement(BenchmarkFamily::BootStorm, 500.0, 500, 1000);
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
    assert!(result.blockers.iter().any(|b| b.contains("throughput")));
}

#[test]
fn p95_latency_regression_detected() {
    let baseline = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 500, 1000);
    // 100% p95 regression
    let current = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 1000, 1000);
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
    assert!(result.blockers.iter().any(|b| b.contains("p95")));
}

#[test]
fn p99_latency_regression_detected() {
    let baseline = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 500, 1000);
    // 100% p99 regression
    let current = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 500, 2000);
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
    assert!(result.blockers.iter().any(|b| b.contains("p99")));
}

#[test]
fn improvement_not_blocked() {
    let baseline = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 500, 1000);
    // Better throughput, lower latency
    let current = make_measurement(BenchmarkFamily::BootStorm, 2000.0, 250, 500);
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(!result.blocked);
}

// ── Xorshift64 ──────────────────────────────────────────────────────────

#[test]
fn xorshift64_deterministic() {
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
    // Very unlikely to produce same sequence
    let same = (0..10).all(|_| rng1.next_u64() == rng2.next_u64());
    assert!(!same);
}

#[test]
fn xorshift64_zero_seed_handled() {
    let mut rng = Xorshift64::new(0);
    // Should not produce all zeros
    let v = rng.next_u64();
    assert_ne!(v, 0);
}

#[test]
fn xorshift64_next_usize_bounded() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..100 {
        let v = rng.next_usize(10);
        assert!(v < 10);
    }
}

#[test]
fn xorshift64_next_bool_always_false_at_zero_pct() {
    let mut rng = Xorshift64::new(42);
    for _ in 0..100 {
        assert!(!rng.next_bool(0));
    }
}

// ── Benchmark runners (small profile) ───────────────────────────────────

#[test]
fn run_boot_storm_small_produces_valid_measurement() {
    let m = run_boot_storm(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::BootStorm);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.duration_us > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert!(m.latency.sample_count > 0);
    assert!(!m.correctness_digest.is_empty());
}

#[test]
fn run_capability_churn_small_produces_valid_measurement() {
    let m = run_capability_churn(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::CapabilityChurn);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
}

#[test]
fn run_benchmark_dispatches_correctly() {
    let m = run_benchmark(BenchmarkFamily::BootStorm, ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::BootStorm);
    assert_eq!(m.profile, ScaleProfile::Small);
}

#[test]
fn run_boot_storm_deterministic_digest() {
    let m1 = run_boot_storm(ScaleProfile::Small, 42);
    let m2 = run_boot_storm(ScaleProfile::Small, 42);
    assert_eq!(m1.correctness_digest, m2.correctness_digest);
    assert_eq!(m1.total_operations, m2.total_operations);
}

// ── Suite runner ────────────────────────────────────────────────────────

#[test]
fn benchmark_suite_small_boot_storm_only() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "test-run".to_string(),
        run_date: "2026-02-26".to_string(),
    };
    let result = run_benchmark_suite(&config);
    assert_eq!(result.measurements.len(), 1);
    assert!(result.total_operations > 0);
    assert!(!result.events.is_empty());
    assert_eq!(result.events[0].family.as_deref(), Some("boot-storm"));
    assert_eq!(result.events[0].profile.as_deref(), Some("S"));
}

#[test]
fn benchmark_suite_default_config() {
    // BenchmarkSuiteConfig::default() has all 5 families x 3 profiles = 15 cases
    let config = BenchmarkSuiteConfig::default();
    assert_eq!(config.families.len(), 5);
    assert_eq!(config.profiles.len(), 3);
}

// ── measurements_to_cases ───────────────────────────────────────────────

#[test]
fn measurements_to_cases_produces_correct_count() {
    let m = run_boot_storm(ScaleProfile::Small, 42);
    let cases = measurements_to_cases(&[m], 1.0);
    assert_eq!(cases.len(), 1);
    assert!(cases[0].throughput_franken_tps > 0.0);
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

// ── Full lifecycle ──────────────────────────────────────────────────────

#[test]
fn full_lifecycle_run_and_regression_check() {
    // Run a small suite as baseline.
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "baseline-run".to_string(),
        run_date: "2026-02-26".to_string(),
    };
    let baseline_result = run_benchmark_suite(&config);
    assert_eq!(baseline_result.measurements.len(), 1);

    // Compare baseline measurement against itself — guaranteed no regression.
    let regression = detect_regression(
        &baseline_result.measurements[0],
        &baseline_result.measurements[0],
        &config.thresholds,
    );
    // Same measurement compared against itself → zero regression → not blocked.
    assert!(!regression.blocked);
}

#[test]
fn benchmark_e2e_script_emits_artifacts_to_env_dir() {
    fn maybe_emit_artifact_bridge(path: &std::path::Path) {
        if std::env::var_os("FRANKEN_BENCH_E2E_ARTIFACT_BRIDGE").is_none() {
            return;
        }

        let Ok(contents) = std::fs::read_to_string(path) else {
            return;
        };

        println!("__BENCH_ARTIFACT_BEGIN__:{}", path.display());
        print!("{contents}");
        if !contents.ends_with('\n') {
            println!();
        }
        println!("__BENCH_ARTIFACT_END__:{}", path.display());
    }

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
        run_date: "2026-03-04".to_string(),
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

    maybe_emit_artifact_bridge(&artifacts.run_manifest_path);
    maybe_emit_artifact_bridge(&artifacts.evidence_path);
    maybe_emit_artifact_bridge(&artifacts.events_path);
    maybe_emit_artifact_bridge(&artifacts.commands_path);
    maybe_emit_artifact_bridge(&artifacts.benchmark_env_manifest_path);
    maybe_emit_artifact_bridge(&artifacts.raw_results_archive_path);
    maybe_emit_artifact_bridge(&artifacts.summary_path);
}

#[test]
fn scale_profile_debug_is_nonempty() {
    let profile = ScaleProfile::Small;
    assert!(!format!("{profile:?}").is_empty());
}

#[test]
fn regression_thresholds_debug_is_nonempty() {
    let t = RegressionThresholds::default();
    assert!(!format!("{t:?}").is_empty());
}

#[test]
fn latency_distribution_debug_is_nonempty() {
    let mut samples = vec![100u64, 200, 300];
    let dist = LatencyDistribution::from_samples(&mut samples);
    assert!(!format!("{dist:?}").is_empty());
}

// ── Additional benchmark runner families ─────────────────────────────

#[test]
fn run_mixed_cpu_io_agent_mesh_small_produces_valid_measurement() {
    let m = run_mixed_cpu_io_agent_mesh(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::MixedCpuIoAgentMesh);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.duration_us > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert!(m.latency.sample_count > 0);
    assert!(!m.correctness_digest.is_empty());
}

#[test]
fn run_reload_revoke_churn_small_produces_valid_measurement() {
    let m = run_reload_revoke_churn(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::ReloadRevokeChurn);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert!(m.latency.sample_count > 0);
}

#[test]
fn run_adversarial_noise_under_load_small_produces_valid_measurement() {
    let m = run_adversarial_noise_under_load(ScaleProfile::Small, 42);
    assert_eq!(m.family, BenchmarkFamily::AdversarialNoiseUnderLoad);
    assert_eq!(m.profile, ScaleProfile::Small);
    assert!(m.total_operations > 0);
    assert!(m.throughput_ops_per_sec > 0.0);
    assert!(m.latency.sample_count > 0);
    assert!(!m.correctness_digest.is_empty());
}

// ── BenchmarkRuntimePins ────────────────────────────────────────────

#[test]
fn benchmark_runtime_pins_default_non_empty() {
    let pins = BenchmarkRuntimePins::default();
    assert!(!pins.franken_engine.is_empty());
    assert!(!pins.node_lts.is_empty());
    assert!(!pins.bun_stable.is_empty());
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

// ── BenchmarkFairnessPolicy ─────────────────────────────────────────

#[test]
fn benchmark_fairness_policy_default_values() {
    let policy = BenchmarkFairnessPolicy::default();
    assert!(policy.warmup_runs >= 1);
    assert!(policy.sample_count >= 3);
    assert!(policy.case_timeout_ms >= 1);
}

#[test]
fn benchmark_fairness_policy_serde_roundtrip() {
    let policy = BenchmarkFairnessPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let deserialized: BenchmarkFairnessPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, deserialized);
}

// ── BenchmarkHarnessContract ────────────────────────────────────────

#[test]
fn validate_harness_contract_default_passes() {
    let contract = BenchmarkHarnessContract::default();
    assert!(validate_harness_contract(&contract).is_ok());
}

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
    // Verify Display impl
    let msg = err.to_string();
    assert!(msg.contains("franken_engine"));
    assert!(msg.contains("non-empty"));
}

#[test]
fn validate_harness_contract_empty_node_lts_pin() {
    let mut contract = BenchmarkHarnessContract::default();
    contract.runtime_pins.node_lts = "   ".to_string(); // whitespace-only
    let err = validate_harness_contract(&contract).unwrap_err();
    assert!(matches!(
        err,
        BenchmarkHarnessContractError::EmptyRuntimePin {
            runtime: "node_lts"
        }
    ));
}

#[test]
fn validate_harness_contract_empty_bun_stable_pin() {
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

// ── BenchmarkEnvironmentManifest ────────────────────────────────────

#[test]
fn benchmark_environment_manifest_serde_roundtrip() {
    let manifest = BenchmarkEnvironmentManifest {
        schema_version: BENCHMARK_ENV_SCHEMA_VERSION.to_string(),
        run_id: "test-run-001".to_string(),
        run_date: "2026-03-11".to_string(),
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

// ── run_benchmark_suite_with_regression ──────────────────────────────

#[test]
fn suite_with_regression_detects_no_regression_against_self() {
    let config = BenchmarkSuiteConfig {
        seed: 42,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm],
        thresholds: RegressionThresholds::default(),
        run_id: "regression-test".to_string(),
        run_date: "2026-03-11".to_string(),
    };
    let baseline_result = run_benchmark_suite(&config);
    let baselines = baseline_result.measurements.clone();

    let result = run_benchmark_suite_with_regression(&config, &baselines);
    // Same seed => same measurements => no regression.
    assert!(!result.regressions.is_empty());
    for r in &result.regressions {
        assert!(!r.blocked, "self-comparison should never block");
        assert!(r.blockers.is_empty());
    }
}

// ── detect_regression edge cases ────────────────────────────────────

#[test]
fn detect_regression_multiple_blockers() {
    let baseline = make_measurement(BenchmarkFamily::CapabilityChurn, 1000.0, 500, 1000);
    // 80% throughput regression + 200% p95 + 200% p99
    let current = make_measurement(BenchmarkFamily::CapabilityChurn, 200.0, 1500, 3000);
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    assert!(result.blocked);
    assert!(
        result.blockers.len() >= 3,
        "expected at least 3 blockers, got {}",
        result.blockers.len()
    );
    assert!(result.blockers.iter().any(|b| b.contains("throughput")));
    assert!(result.blockers.iter().any(|b| b.contains("p95")));
    assert!(result.blockers.iter().any(|b| b.contains("p99")));
}

#[test]
fn detect_regression_zero_baseline_throughput() {
    let baseline = make_measurement(BenchmarkFamily::BootStorm, 0.0, 500, 1000);
    let current = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 500, 1000);
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    // Zero baseline throughput => throughput_delta_pct = 0.0 => not blocked for throughput.
    assert!(!result.blocked);
    assert!((result.throughput_delta_pct).abs() < 1e-9);
}

// ── measurements_to_cases edge cases ────────────────────────────────

#[test]
fn measurements_to_cases_with_invariant_violations_not_behavior_equivalent() {
    let mut m = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 500, 1000);
    m.invariant_violations = 5;
    let cases = measurements_to_cases(&[m], 1.0);
    assert_eq!(cases.len(), 1);
    assert!(!cases[0].behavior_equivalent);
}

// ── BENCHMARK_ENV_SCHEMA_VERSION constant ───────────────────────────

#[test]
fn benchmark_env_schema_version_non_empty() {
    assert!(!BENCHMARK_ENV_SCHEMA_VERSION.is_empty());
    assert!(BENCHMARK_ENV_SCHEMA_VERSION.contains("benchmark-env"));
}

// ── BenchmarkHarnessContractError Display coverage ──────────────────

#[test]
fn harness_contract_error_is_std_error() {
    let err = BenchmarkHarnessContractError::EmptyRuntimePin {
        runtime: "franken_engine",
    };
    // Verify it implements std::error::Error (the trait object cast compiles).
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

// ── BenchmarkSuiteConfig multiple families and profiles ─────────────

#[test]
fn suite_multiple_families_produces_correct_event_count() {
    let config = BenchmarkSuiteConfig {
        seed: 99,
        profiles: vec![ScaleProfile::Small],
        families: vec![BenchmarkFamily::BootStorm, BenchmarkFamily::CapabilityChurn],
        thresholds: RegressionThresholds::default(),
        run_id: "multi-family".to_string(),
        run_date: "2026-03-11".to_string(),
    };
    let result = run_benchmark_suite(&config);
    // 2 families x 1 profile = 2 measurements and 2 events.
    assert_eq!(result.measurements.len(), 2);
    assert_eq!(result.events.len(), 2);
    assert_eq!(result.measurements[0].family, BenchmarkFamily::BootStorm);
    assert_eq!(
        result.measurements[1].family,
        BenchmarkFamily::CapabilityChurn
    );
}

// ── RegressionResult clone and debug ────────────────────────────────

#[test]
fn regression_result_clone_and_debug() {
    let baseline = make_measurement(BenchmarkFamily::BootStorm, 1000.0, 500, 1000);
    let current = make_measurement(BenchmarkFamily::BootStorm, 900.0, 600, 1100);
    let result = detect_regression(&current, &baseline, &RegressionThresholds::default());
    let cloned = result.clone();
    assert_eq!(cloned.family, result.family);
    assert_eq!(cloned.profile, result.profile);
    assert_eq!(cloned.blocked, result.blocked);
    assert_eq!(cloned.blockers.len(), result.blockers.len());
    assert!(!format!("{result:?}").is_empty());
}

// ── BenchmarkHarnessContract serde roundtrip ────────────────────────

#[test]
fn benchmark_harness_contract_serde_roundtrip() {
    let contract = BenchmarkHarnessContract::default();
    let json = serde_json::to_string(&contract).expect("serialize");
    let deserialized: BenchmarkHarnessContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(contract, deserialized);
}

// ── run_benchmark dispatches all families ───────────────────────────

#[test]
fn run_benchmark_dispatches_all_five_families() {
    for family in BenchmarkFamily::all() {
        let m = run_benchmark(*family, ScaleProfile::Small, 7);
        assert_eq!(m.family, *family);
        assert_eq!(m.profile, ScaleProfile::Small);
        assert!(m.total_operations > 0);
        assert!(!m.correctness_digest.is_empty());
    }
}
