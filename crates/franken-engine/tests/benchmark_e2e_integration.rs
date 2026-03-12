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
    BENCHMARK_E2E_COMPONENT, BENCHMARK_E2E_SCHEMA_VERSION, BenchmarkFamily, BenchmarkMeasurement,
    BenchmarkSuiteConfig, LatencyDistribution, MIN_START_BUDGET_MILLIONTHS, RegressionThresholds,
    ScaleProfile, Xorshift64, detect_regression, measurements_to_cases, run_benchmark,
    run_benchmark_suite, run_boot_storm, run_capability_churn, write_evidence_artifacts,
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
