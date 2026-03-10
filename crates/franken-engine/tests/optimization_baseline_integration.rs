#![forbid(unsafe_code)]

//! Integration tests for the `optimization_baseline` module (FRX-06.1).
//!
//! Covers: BenchmarkEnvironment, LatencySample, PercentileStats,
//! ThroughputMeasurement, MemorySnapshot, ProfileKind, ProfileArtifact,
//! Hotspot, BenchmarkResult, ComparisonDirection, MetricComparison,
//! SignificanceThreshold, compare_metric, BaselineComparison,
//! OptimizationOpportunity, OpportunityStatus, OpportunityMatrix,
//! BaselineRegistry.

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

use frankenengine_engine::optimization_baseline::{
    BaselineComparison, BaselineRegistry, BenchmarkEnvironment, BenchmarkResult,
    ComparisonDirection, Hotspot, LatencySample, MemorySnapshot, OpportunityMatrix,
    OpportunityStatus, OptimizationOpportunity, PercentileStats, ProfileArtifact, ProfileKind,
    SignificanceThreshold, ThroughputMeasurement, compare_metric,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_samples(count: u64, base_ns: u64, stride: u64) -> Vec<LatencySample> {
    (0..count)
        .map(|i| LatencySample {
            latency_ns: base_ns + i * stride,
            iteration: i as u32,
            is_warmup: false,
        })
        .collect()
}

fn make_warmup_samples(count: u64, base_ns: u64) -> Vec<LatencySample> {
    (0..count)
        .map(|i| LatencySample {
            latency_ns: base_ns + i * 100,
            iteration: i as u32,
            is_warmup: true,
        })
        .collect()
}

fn make_opportunity(
    id: &str,
    impact: i64,
    effort: u8,
    risk: u8,
    status: OpportunityStatus,
) -> OptimizationOpportunity {
    OptimizationOpportunity {
        id: id.to_string(),
        description: format!("Opportunity {id}"),
        component: "test_component".to_string(),
        estimated_impact_millionths: impact,
        effort,
        risk,
        evidence_profile_kinds: vec![],
        status,
    }
}

fn default_threshold() -> SignificanceThreshold {
    SignificanceThreshold::default_threshold()
}

fn make_env(name: &str) -> BenchmarkEnvironment {
    BenchmarkEnvironment::default_env(name)
}

// ---------------------------------------------------------------------------
// 1. BenchmarkEnvironment
// ---------------------------------------------------------------------------

#[test]
fn env_default_has_correct_defaults() {
    let env = BenchmarkEnvironment::default_env("bench-alpha");
    assert_eq!(env.env_id, "bench-alpha");
    assert_eq!(env.warmup_iterations, 10);
    assert_eq!(env.measurement_iterations, 100);
    assert_eq!(env.max_iteration_us, 10_000_000);
    assert!(!env.pin_to_core);
    assert!(!env.disable_gc);
    assert!(env.tags.is_empty());
}

#[test]
fn env_validate_valid_config() {
    let env = make_env("valid");
    assert!(env.validate().is_empty());
}

#[test]
fn env_validate_empty_id() {
    let env = BenchmarkEnvironment::default_env("");
    let errors = env.validate();
    assert!(errors.iter().any(|e| e.contains("env_id")));
}

#[test]
fn env_validate_zero_measurement_iterations() {
    let mut env = make_env("test");
    env.measurement_iterations = 0;
    let errors = env.validate();
    assert!(errors.iter().any(|e| e.contains("measurement_iterations")));
}

#[test]
fn env_validate_zero_max_iteration_us() {
    let mut env = make_env("test");
    env.max_iteration_us = 0;
    let errors = env.validate();
    assert!(errors.iter().any(|e| e.contains("max_iteration_us")));
}

#[test]
fn env_validate_multiple_errors() {
    let mut env = BenchmarkEnvironment::default_env("");
    env.measurement_iterations = 0;
    env.max_iteration_us = 0;
    let errors = env.validate();
    assert_eq!(errors.len(), 3);
}

#[test]
fn env_derive_id_deterministic() {
    let e1 = make_env("stable-id");
    let e2 = make_env("stable-id");
    assert_eq!(e1.derive_id(), e2.derive_id());
}

#[test]
fn env_derive_id_different_for_different_names() {
    let e1 = make_env("alpha");
    let e2 = make_env("beta");
    assert_ne!(e1.derive_id(), e2.derive_id());
}

#[test]
fn env_serde_roundtrip() {
    let mut env = make_env("serde-test");
    env.pin_to_core = true;
    env.disable_gc = true;
    env.tags = vec!["fast".to_string(), "nightly".to_string()];
    let json = serde_json::to_string(&env).unwrap();
    let back: BenchmarkEnvironment = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

#[test]
fn env_clone_equality() {
    let env = make_env("clone-test");
    let cloned = env.clone();
    assert_eq!(env, cloned);
}

#[test]
fn env_debug_output_contains_id() {
    let env = make_env("debug-check");
    let dbg = format!("{:?}", env);
    assert!(dbg.contains("debug-check"));
}

// ---------------------------------------------------------------------------
// 2. LatencySample and PercentileStats
// ---------------------------------------------------------------------------

#[test]
fn pstats_empty_samples_returns_none() {
    assert!(PercentileStats::from_samples(&[]).is_none());
}

#[test]
fn pstats_all_warmup_returns_none() {
    let samples = make_warmup_samples(10, 1000);
    assert!(PercentileStats::from_samples(&samples).is_none());
}

#[test]
fn pstats_single_sample() {
    let samples = make_samples(1, 5000, 0);
    let stats = PercentileStats::from_samples(&samples).unwrap();
    assert_eq!(stats.p50_ns, 5000);
    assert_eq!(stats.min_ns, 5000);
    assert_eq!(stats.max_ns, 5000);
    assert_eq!(stats.mean_ns, 5000);
    assert_eq!(stats.sample_count, 1);
    assert_eq!(stats.jitter_ns(), 0);
}

#[test]
fn pstats_warmup_filtered_out() {
    let mut samples = make_warmup_samples(5, 10_000);
    samples.extend(make_samples(10, 1000, 100));
    let stats = PercentileStats::from_samples(&samples).unwrap();
    assert_eq!(stats.sample_count, 10);
    // Warmup samples had base 10_000; measurement max is 1000+9*100=1900
    assert!(stats.max_ns <= 1900);
}

#[test]
fn pstats_percentile_ordering() {
    let samples = make_samples(200, 100, 10);
    let stats = PercentileStats::from_samples(&samples).unwrap();
    assert!(stats.min_ns <= stats.p50_ns);
    assert!(stats.p50_ns <= stats.p90_ns);
    assert!(stats.p90_ns <= stats.p95_ns);
    assert!(stats.p95_ns <= stats.p99_ns);
    assert!(stats.p99_ns <= stats.p999_ns);
    assert!(stats.p999_ns <= stats.max_ns);
}

#[test]
fn pstats_jitter_positive_for_spread() {
    let samples = make_samples(100, 100, 100);
    let stats = PercentileStats::from_samples(&samples).unwrap();
    assert!(stats.jitter_ns() > 0);
}

#[test]
fn pstats_jitter_zero_for_constant() {
    let samples: Vec<_> = (0..50)
        .map(|i| LatencySample {
            latency_ns: 1000,
            iteration: i,
            is_warmup: false,
        })
        .collect();
    let stats = PercentileStats::from_samples(&samples).unwrap();
    assert_eq!(stats.jitter_ns(), 0);
}

#[test]
fn pstats_cv_millionths_zero_mean() {
    // Cannot create zero-mean from real samples, but construct directly
    let stats = PercentileStats {
        p50_ns: 0,
        p90_ns: 0,
        p95_ns: 0,
        p99_ns: 0,
        p999_ns: 0,
        min_ns: 0,
        max_ns: 0,
        mean_ns: 0,
        sample_count: 1,
    };
    assert_eq!(stats.cv_millionths(), 0);
}

#[test]
fn pstats_cv_millionths_normal() {
    let samples = make_samples(100, 1000, 10);
    let stats = PercentileStats::from_samples(&samples).unwrap();
    let cv = stats.cv_millionths();
    assert!(cv >= 0);
}

#[test]
fn pstats_derive_id_deterministic() {
    let samples = make_samples(50, 500, 20);
    let s1 = PercentileStats::from_samples(&samples).unwrap();
    let s2 = PercentileStats::from_samples(&samples).unwrap();
    assert_eq!(s1.derive_id(), s2.derive_id());
}

#[test]
fn pstats_serde_roundtrip() {
    let samples = make_samples(100, 200, 5);
    let stats = PercentileStats::from_samples(&samples).unwrap();
    let json = serde_json::to_string(&stats).unwrap();
    let back: PercentileStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
}

#[test]
fn latency_sample_serde_roundtrip() {
    let sample = LatencySample {
        latency_ns: 42_000,
        iteration: 7,
        is_warmup: true,
    };
    let json = serde_json::to_string(&sample).unwrap();
    let back: LatencySample = serde_json::from_str(&json).unwrap();
    assert_eq!(sample, back);
}

// ---------------------------------------------------------------------------
// 3. ThroughputMeasurement
// ---------------------------------------------------------------------------

#[test]
fn throughput_basic_calculation() {
    // 1000 ops in 1 second = 1000 ops/sec
    let t = ThroughputMeasurement::new(1000, 1_000_000_000);
    // ops_per_sec_millionths = 1000 * 1e9 * 1e6 / 1e9 = 1000 * 1e6 = 1_000_000_000
    assert_eq!(t.ops_per_sec_millionths, 1_000_000_000);
    assert_eq!(t.total_ops, 1000);
    assert_eq!(t.duration_ns, 1_000_000_000);
    assert!(t.bytes_processed.is_none());
}

#[test]
fn throughput_zero_duration() {
    let t = ThroughputMeasurement::new(1000, 0);
    assert_eq!(t.ops_per_sec_millionths, 0);
}

#[test]
fn throughput_zero_ops() {
    let t = ThroughputMeasurement::new(0, 1_000_000_000);
    assert_eq!(t.ops_per_sec_millionths, 0);
}

#[test]
fn throughput_with_bytes() {
    let t = ThroughputMeasurement::new(1000, 1_000_000_000).with_bytes(1_048_576);
    assert_eq!(t.bytes_processed, Some(1_048_576));
    let bps = t.bytes_per_sec_millionths().unwrap();
    assert!(bps > 0);
}

#[test]
fn throughput_bytes_per_sec_no_bytes() {
    let t = ThroughputMeasurement::new(1000, 1_000_000_000);
    assert!(t.bytes_per_sec_millionths().is_none());
}

#[test]
fn throughput_bytes_per_sec_zero_duration() {
    let t = ThroughputMeasurement::new(0, 0).with_bytes(1000);
    assert_eq!(t.bytes_per_sec_millionths(), Some(0));
}

#[test]
fn throughput_serde_roundtrip() {
    let t = ThroughputMeasurement::new(5000, 3_000_000_000).with_bytes(2_000_000);
    let json = serde_json::to_string(&t).unwrap();
    let back: ThroughputMeasurement = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ---------------------------------------------------------------------------
// 4. MemorySnapshot
// ---------------------------------------------------------------------------

#[test]
fn memory_empty_all_zeros() {
    let m = MemorySnapshot::empty();
    assert_eq!(m.heap_bytes, 0);
    assert_eq!(m.stack_bytes, 0);
    assert_eq!(m.peak_heap_bytes, 0);
    assert_eq!(m.live_allocations, 0);
    assert_eq!(m.total_allocations, 0);
    assert_eq!(m.total_deallocations, 0);
}

#[test]
fn memory_allocation_churn_positive() {
    let m = MemorySnapshot {
        heap_bytes: 4096,
        stack_bytes: 1024,
        peak_heap_bytes: 8192,
        live_allocations: 10,
        total_allocations: 200,
        total_deallocations: 190,
    };
    assert_eq!(m.allocation_churn(), 10);
}

#[test]
fn memory_allocation_churn_negative() {
    // More deallocs than allocs (unusual but possible in accounting)
    let m = MemorySnapshot {
        heap_bytes: 0,
        stack_bytes: 0,
        peak_heap_bytes: 0,
        live_allocations: 0,
        total_allocations: 50,
        total_deallocations: 60,
    };
    assert_eq!(m.allocation_churn(), -10);
}

#[test]
fn memory_potential_leak_true() {
    let m = MemorySnapshot {
        heap_bytes: 512,
        stack_bytes: 0,
        peak_heap_bytes: 512,
        live_allocations: 3,
        total_allocations: 100,
        total_deallocations: 97,
    };
    assert!(m.potential_leak());
}

#[test]
fn memory_potential_leak_false_zero_live() {
    let m = MemorySnapshot {
        heap_bytes: 0,
        stack_bytes: 0,
        peak_heap_bytes: 1024,
        live_allocations: 0,
        total_allocations: 100,
        total_deallocations: 100,
    };
    assert!(!m.potential_leak());
}

#[test]
fn memory_potential_leak_false_all_deallocated() {
    // live_allocations > 0 but deallocs >= allocs -> not a leak
    let m = MemorySnapshot {
        heap_bytes: 100,
        stack_bytes: 0,
        peak_heap_bytes: 100,
        live_allocations: 1,
        total_allocations: 50,
        total_deallocations: 50,
    };
    assert!(!m.potential_leak());
}

#[test]
fn memory_serde_roundtrip() {
    let m = MemorySnapshot {
        heap_bytes: 65536,
        stack_bytes: 8192,
        peak_heap_bytes: 131072,
        live_allocations: 42,
        total_allocations: 9999,
        total_deallocations: 9957,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: MemorySnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ---------------------------------------------------------------------------
// 5. ProfileKind and ProfileArtifact
// ---------------------------------------------------------------------------

#[test]
fn profile_kind_all_has_five_variants() {
    assert_eq!(ProfileKind::ALL.len(), 5);
}

#[test]
fn profile_kind_as_str_all_distinct() {
    let mut seen = std::collections::BTreeSet::new();
    for k in ProfileKind::ALL {
        assert!(seen.insert(k.as_str()), "duplicate as_str for {:?}", k);
    }
}

#[test]
fn profile_kind_serde_roundtrip_all() {
    for k in ProfileKind::ALL {
        let json = serde_json::to_string(&k).unwrap();
        let back: ProfileKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

#[test]
fn profile_artifact_new_defaults() {
    let pa = ProfileArtifact::new(ProfileKind::SyscallTrace, "bench-42");
    assert_eq!(pa.kind, ProfileKind::SyscallTrace);
    assert_eq!(pa.benchmark_id, "bench-42");
    assert!(pa.data.is_empty());
    assert!(pa.hotspots.is_empty());
}

#[test]
fn profile_artifact_with_hotspot_chaining() {
    let pa = ProfileArtifact::new(ProfileKind::CpuFlamegraph, "bench-1")
        .with_hotspot(Hotspot {
            symbol: "fn_a".to_string(),
            percentage_millionths: 400_000,
            samples: 4000,
            module_path: "mod_a".to_string(),
        })
        .with_hotspot(Hotspot {
            symbol: "fn_b".to_string(),
            percentage_millionths: 200_000,
            samples: 2000,
            module_path: "mod_b".to_string(),
        });
    assert_eq!(pa.hotspots.len(), 2);
}

#[test]
fn profile_artifact_derive_id_deterministic() {
    let p1 = ProfileArtifact::new(ProfileKind::CacheMissProfile, "bench-x");
    let p2 = ProfileArtifact::new(ProfileKind::CacheMissProfile, "bench-x");
    assert_eq!(p1.derive_id(), p2.derive_id());
}

#[test]
fn profile_artifact_derive_id_differs_by_kind() {
    let p1 = ProfileArtifact::new(ProfileKind::CpuFlamegraph, "bench-x");
    let p2 = ProfileArtifact::new(ProfileKind::AllocationFlamegraph, "bench-x");
    assert_ne!(p1.derive_id(), p2.derive_id());
}

#[test]
fn hotspot_serde_roundtrip() {
    let hs = Hotspot {
        symbol: "core::sort".to_string(),
        percentage_millionths: 150_000,
        samples: 1500,
        module_path: "alloc/slice.rs".to_string(),
    };
    let json = serde_json::to_string(&hs).unwrap();
    let back: Hotspot = serde_json::from_str(&json).unwrap();
    assert_eq!(hs, back);
}

#[test]
fn profile_artifact_serde_roundtrip() {
    let pa = ProfileArtifact::new(ProfileKind::BranchMispredictionProfile, "bench-serde")
        .with_hotspot(Hotspot {
            symbol: "predict_branch".to_string(),
            percentage_millionths: 300_000,
            samples: 3000,
            module_path: "cpu_model.rs".to_string(),
        });
    let json = serde_json::to_string(&pa).unwrap();
    let back: ProfileArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(pa, back);
}

// ---------------------------------------------------------------------------
// 6. BenchmarkResult
// ---------------------------------------------------------------------------

#[test]
fn bench_result_new_defaults() {
    let env = make_env("env-1");
    let r = BenchmarkResult::new("bench-1", env.clone());
    assert_eq!(r.benchmark_id, "bench-1");
    assert_eq!(r.environment, env);
    assert!(r.latency.is_none());
    assert!(r.throughput.is_none());
    assert!(r.memory.is_none());
    assert!(r.profiles.is_empty());
    assert!(r.metadata.is_empty());
}

#[test]
fn bench_result_builder_chaining() {
    let env = make_env("env-2");
    let samples = make_samples(50, 1000, 20);
    let stats = PercentileStats::from_samples(&samples).unwrap();
    let r = BenchmarkResult::new("bench-2", env)
        .with_latency(stats.clone())
        .with_throughput(ThroughputMeasurement::new(500, 1_000_000_000))
        .with_memory(MemorySnapshot::empty());
    assert!(r.latency.is_some());
    assert!(r.throughput.is_some());
    assert!(r.memory.is_some());
}

#[test]
fn bench_result_add_profile() {
    let env = make_env("env-3");
    let mut r = BenchmarkResult::new("bench-3", env);
    r.add_profile(ProfileArtifact::new(ProfileKind::CpuFlamegraph, "bench-3"));
    r.add_profile(ProfileArtifact::new(
        ProfileKind::AllocationFlamegraph,
        "bench-3",
    ));
    assert_eq!(r.profiles.len(), 2);
}

#[test]
fn bench_result_metadata() {
    let env = make_env("env-meta");
    let mut r = BenchmarkResult::new("bench-meta", env);
    r.metadata
        .insert("commit".to_string(), "abc123".to_string());
    r.metadata.insert("branch".to_string(), "main".to_string());
    assert_eq!(r.metadata.len(), 2);
    assert_eq!(r.metadata.get("commit").unwrap(), "abc123");
}

#[test]
fn bench_result_derive_id_deterministic() {
    let env = make_env("env-id");
    let r1 = BenchmarkResult::new("bench-id", env.clone());
    let r2 = BenchmarkResult::new("bench-id", env);
    assert_eq!(r1.derive_id(), r2.derive_id());
}

#[test]
fn bench_result_serde_roundtrip_full() {
    let env = make_env("env-serde");
    let samples = make_samples(30, 500, 10);
    let mut r = BenchmarkResult::new("bench-serde", env)
        .with_latency(PercentileStats::from_samples(&samples).unwrap())
        .with_throughput(ThroughputMeasurement::new(1000, 2_000_000_000).with_bytes(500_000))
        .with_memory(MemorySnapshot {
            heap_bytes: 4096,
            stack_bytes: 2048,
            peak_heap_bytes: 8192,
            live_allocations: 0,
            total_allocations: 100,
            total_deallocations: 100,
        });
    r.add_profile(ProfileArtifact::new(
        ProfileKind::CpuFlamegraph,
        "bench-serde",
    ));
    r.metadata.insert("key".to_string(), "val".to_string());
    let json = serde_json::to_string(&r).unwrap();
    let back: BenchmarkResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// 7. ComparisonDirection, SignificanceThreshold, compare_metric
// ---------------------------------------------------------------------------

#[test]
fn comparison_direction_serde_roundtrip() {
    for d in [
        ComparisonDirection::Improvement,
        ComparisonDirection::Regression,
        ComparisonDirection::Neutral,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: ComparisonDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

#[test]
fn significance_threshold_defaults() {
    let t = SignificanceThreshold::default_threshold();
    assert_eq!(t.min_change_millionths, 50_000);
    assert_eq!(t.min_samples, 30);
}

#[test]
fn significance_threshold_serde_roundtrip() {
    let t = SignificanceThreshold {
        min_change_millionths: 100_000,
        min_samples: 50,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: SignificanceThreshold = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn compare_metric_neutral_small_change() {
    let t = default_threshold();
    let cmp = compare_metric("m", 1000, 1010, &t);
    assert_eq!(cmp.direction, ComparisonDirection::Neutral);
    assert_eq!(cmp.metric_name, "m");
    assert_eq!(cmp.baseline_value, 1000);
    assert_eq!(cmp.candidate_value, 1010);
}

#[test]
fn compare_metric_improvement_lower_is_better() {
    let t = default_threshold();
    let cmp = compare_metric("latency", 1000, 800, &t);
    assert_eq!(cmp.direction, ComparisonDirection::Improvement);
    // change should be negative: (800 - 1000) * 1e6 / 1000 = -200_000
    assert_eq!(cmp.change_millionths, -200_000);
}

#[test]
fn compare_metric_regression() {
    let t = default_threshold();
    let cmp = compare_metric("latency", 1000, 1200, &t);
    assert_eq!(cmp.direction, ComparisonDirection::Regression);
    assert_eq!(cmp.change_millionths, 200_000);
}

#[test]
fn compare_metric_zero_baseline_nonzero_candidate() {
    let t = default_threshold();
    let cmp = compare_metric("mem", 0, 500, &t);
    assert_eq!(cmp.change_millionths, 1_000_000);
    assert_eq!(cmp.direction, ComparisonDirection::Regression);
}

#[test]
fn compare_metric_zero_baseline_zero_candidate() {
    let t = default_threshold();
    let cmp = compare_metric("mem", 0, 0, &t);
    assert_eq!(cmp.change_millionths, 0);
    assert_eq!(cmp.direction, ComparisonDirection::Neutral);
}

#[test]
fn compare_metric_exact_threshold_boundary() {
    // Default threshold is 50_000 (5%). A 5% change exactly -> abs(50_000) < 50_000 is false
    // so it should NOT be neutral.
    let t = default_threshold();
    // 5% of 1_000_000 = 50_000_000_000 / 1_000_000 = 50_000
    let cmp = compare_metric("x", 1_000_000, 1_050_000, &t);
    // change = (1_050_000 - 1_000_000) * 1_000_000 / 1_000_000 = 50_000
    // 50_000.abs() < 50_000 is false => Regression
    assert_eq!(cmp.direction, ComparisonDirection::Regression);
}

#[test]
fn compare_metric_just_below_threshold() {
    let t = default_threshold();
    // change of 49_999 millionths => Neutral
    // baseline = 1_000_000, candidate needs to give change < 50_000
    // change = (c - b) * 1e6 / b => c = b + 49_999 * b / 1e6 = 1_000_000 + 49
    // Actually: (1_000_049 - 1_000_000) * 1_000_000 / 1_000_000 = 49_000
    let cmp = compare_metric("x", 1_000_000, 1_000_049, &t);
    assert_eq!(cmp.direction, ComparisonDirection::Neutral);
}

// ---------------------------------------------------------------------------
// 8. BaselineComparison
// ---------------------------------------------------------------------------

#[test]
fn baseline_comparison_new_defaults() {
    let bc = BaselineComparison::new("base-1", "cand-1");
    assert_eq!(bc.baseline_id, "base-1");
    assert_eq!(bc.candidate_id, "cand-1");
    assert!(bc.comparisons.is_empty());
    assert_eq!(bc.overall_direction, ComparisonDirection::Neutral);
    assert_eq!(bc.regression_count(), 0);
    assert_eq!(bc.improvement_count(), 0);
}

#[test]
fn baseline_comparison_overall_improvement() {
    let t = default_threshold();
    let mut bc = BaselineComparison::new("b", "c");
    bc.add_comparison(compare_metric("m1", 1000, 800, &t));
    bc.add_comparison(compare_metric("m2", 1000, 700, &t));
    assert_eq!(bc.overall_direction, ComparisonDirection::Improvement);
    assert_eq!(bc.improvement_count(), 2);
    assert_eq!(bc.regression_count(), 0);
}

#[test]
fn baseline_comparison_overall_regression() {
    let t = default_threshold();
    let mut bc = BaselineComparison::new("b", "c");
    bc.add_comparison(compare_metric("m1", 1000, 1300, &t));
    bc.add_comparison(compare_metric("m2", 1000, 1500, &t));
    assert_eq!(bc.overall_direction, ComparisonDirection::Regression);
}

#[test]
fn baseline_comparison_overall_neutral_tie() {
    let t = default_threshold();
    let mut bc = BaselineComparison::new("b", "c");
    bc.add_comparison(compare_metric("m1", 1000, 800, &t)); // improvement
    bc.add_comparison(compare_metric("m2", 1000, 1300, &t)); // regression
    assert_eq!(bc.overall_direction, ComparisonDirection::Neutral);
    assert_eq!(bc.improvement_count(), 1);
    assert_eq!(bc.regression_count(), 1);
}

#[test]
fn baseline_comparison_derive_id_deterministic() {
    let b1 = BaselineComparison::new("alpha", "beta");
    let b2 = BaselineComparison::new("alpha", "beta");
    assert_eq!(b1.derive_id(), b2.derive_id());
}

#[test]
fn baseline_comparison_derive_id_differs() {
    let b1 = BaselineComparison::new("alpha", "beta");
    let b2 = BaselineComparison::new("alpha", "gamma");
    assert_ne!(b1.derive_id(), b2.derive_id());
}

// ---------------------------------------------------------------------------
// 9. OpportunityStatus and OptimizationOpportunity
// ---------------------------------------------------------------------------

#[test]
fn opportunity_status_as_str_all_variants() {
    let pairs = [
        (OpportunityStatus::Identified, "identified"),
        (OpportunityStatus::Evaluating, "evaluating"),
        (OpportunityStatus::Approved, "approved"),
        (OpportunityStatus::Implemented, "implemented"),
        (OpportunityStatus::Rejected, "rejected"),
    ];
    for (status, expected) in pairs {
        assert_eq!(status.as_str(), expected);
    }
}

#[test]
fn opportunity_status_serde_roundtrip() {
    for s in [
        OpportunityStatus::Identified,
        OpportunityStatus::Evaluating,
        OpportunityStatus::Approved,
        OpportunityStatus::Implemented,
        OpportunityStatus::Rejected,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: OpportunityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn opportunity_score_basic() {
    let opp = make_opportunity("o1", 300_000, 2, 1, OpportunityStatus::Identified);
    // score = 300_000 / (2 * 1) = 150_000
    assert_eq!(opp.score_millionths(), 150_000);
}

#[test]
fn opportunity_score_zero_effort_clamped() {
    let opp = make_opportunity("o2", 500_000, 0, 3, OpportunityStatus::Identified);
    // effort clamped to 1: score = 500_000 / (1 * 3) = 166_666
    assert_eq!(opp.score_millionths(), 166_666);
}

#[test]
fn opportunity_score_zero_risk_clamped() {
    let opp = make_opportunity("o3", 400_000, 2, 0, OpportunityStatus::Identified);
    // risk clamped to 1: score = 400_000 / (2 * 1) = 200_000
    assert_eq!(opp.score_millionths(), 200_000);
}

#[test]
fn opportunity_score_high_effort_and_risk() {
    let opp = make_opportunity("o4", 1_000_000, 5, 5, OpportunityStatus::Identified);
    // score = 1_000_000 / 25 = 40_000
    assert_eq!(opp.score_millionths(), 40_000);
}

#[test]
fn opportunity_derive_id_deterministic() {
    let o1 = make_opportunity("stable", 100_000, 1, 1, OpportunityStatus::Approved);
    let o2 = make_opportunity("stable", 100_000, 1, 1, OpportunityStatus::Approved);
    assert_eq!(o1.derive_id(), o2.derive_id());
}

#[test]
fn opportunity_serde_roundtrip() {
    let opp = OptimizationOpportunity {
        id: "opt-serde".to_string(),
        description: "Test serde".to_string(),
        component: "engine".to_string(),
        estimated_impact_millionths: 750_000,
        effort: 3,
        risk: 2,
        evidence_profile_kinds: vec![ProfileKind::CpuFlamegraph, ProfileKind::SyscallTrace],
        status: OpportunityStatus::Evaluating,
    };
    let json = serde_json::to_string(&opp).unwrap();
    let back: OptimizationOpportunity = serde_json::from_str(&json).unwrap();
    assert_eq!(opp, back);
}

// ---------------------------------------------------------------------------
// 10. OpportunityMatrix
// ---------------------------------------------------------------------------

#[test]
fn matrix_new_empty() {
    let m = OpportunityMatrix::new("empty-matrix");
    assert_eq!(m.matrix_id, "empty-matrix");
    assert!(m.opportunities.is_empty());
}

#[test]
fn matrix_add_and_count() {
    let mut m = OpportunityMatrix::new("m1");
    m.add(make_opportunity(
        "a",
        100_000,
        1,
        1,
        OpportunityStatus::Identified,
    ));
    m.add(make_opportunity(
        "b",
        200_000,
        2,
        1,
        OpportunityStatus::Approved,
    ));
    assert_eq!(m.opportunities.len(), 2);
}

#[test]
fn matrix_ranked_descending_score() {
    let mut m = OpportunityMatrix::new("ranked");
    m.add(make_opportunity(
        "low",
        100_000,
        3,
        3,
        OpportunityStatus::Identified,
    )); // score = 11_111
    m.add(make_opportunity(
        "high",
        900_000,
        1,
        1,
        OpportunityStatus::Identified,
    )); // score = 900_000
    m.add(make_opportunity(
        "mid",
        500_000,
        2,
        1,
        OpportunityStatus::Identified,
    )); // score = 250_000
    let ranked = m.ranked();
    assert_eq!(ranked[0].id, "high");
    assert_eq!(ranked[1].id, "mid");
    assert_eq!(ranked[2].id, "low");
}

#[test]
fn matrix_top_n_returns_correct_count() {
    let mut m = OpportunityMatrix::new("top");
    for i in 0..5 {
        m.add(make_opportunity(
            &format!("o{i}"),
            (i + 1) as i64 * 100_000,
            1,
            1,
            OpportunityStatus::Identified,
        ));
    }
    let top2 = m.top_n(2);
    assert_eq!(top2.len(), 2);
    assert_eq!(top2[0].id, "o4"); // highest impact
    assert_eq!(top2[1].id, "o3");
}

#[test]
fn matrix_top_n_exceeds_count() {
    let mut m = OpportunityMatrix::new("small");
    m.add(make_opportunity(
        "only",
        100_000,
        1,
        1,
        OpportunityStatus::Identified,
    ));
    let top10 = m.top_n(10);
    assert_eq!(top10.len(), 1);
}

#[test]
fn matrix_by_status_filters() {
    let mut m = OpportunityMatrix::new("filter");
    m.add(make_opportunity(
        "a",
        100_000,
        1,
        1,
        OpportunityStatus::Identified,
    ));
    m.add(make_opportunity(
        "b",
        200_000,
        1,
        1,
        OpportunityStatus::Approved,
    ));
    m.add(make_opportunity(
        "c",
        300_000,
        1,
        1,
        OpportunityStatus::Approved,
    ));
    m.add(make_opportunity(
        "d",
        400_000,
        1,
        1,
        OpportunityStatus::Rejected,
    ));

    assert_eq!(m.by_status(OpportunityStatus::Approved).len(), 2);
    assert_eq!(m.by_status(OpportunityStatus::Identified).len(), 1);
    assert_eq!(m.by_status(OpportunityStatus::Rejected).len(), 1);
    assert_eq!(m.by_status(OpportunityStatus::Implemented).len(), 0);
}

#[test]
fn matrix_approved_impact_sum() {
    let mut m = OpportunityMatrix::new("impact");
    m.add(make_opportunity(
        "a",
        300_000,
        1,
        1,
        OpportunityStatus::Approved,
    ));
    m.add(make_opportunity(
        "b",
        200_000,
        1,
        1,
        OpportunityStatus::Approved,
    ));
    m.add(make_opportunity(
        "c",
        500_000,
        1,
        1,
        OpportunityStatus::Identified,
    )); // not approved
    assert_eq!(m.approved_impact_millionths(), 500_000);
}

#[test]
fn matrix_approved_impact_none_approved() {
    let mut m = OpportunityMatrix::new("no-approved");
    m.add(make_opportunity(
        "a",
        300_000,
        1,
        1,
        OpportunityStatus::Identified,
    ));
    assert_eq!(m.approved_impact_millionths(), 0);
}

#[test]
fn matrix_derive_id_deterministic() {
    let m1 = OpportunityMatrix::new("m-det");
    let m2 = OpportunityMatrix::new("m-det");
    assert_eq!(m1.derive_id(), m2.derive_id());
}

#[test]
fn matrix_derive_id_changes_with_size() {
    let mut m = OpportunityMatrix::new("m-size");
    let id_empty = m.derive_id();
    m.add(make_opportunity(
        "x",
        100_000,
        1,
        1,
        OpportunityStatus::Identified,
    ));
    let id_one = m.derive_id();
    assert_ne!(id_empty, id_one);
}

#[test]
fn matrix_serde_roundtrip() {
    let mut m = OpportunityMatrix::new("m-serde");
    m.add(make_opportunity(
        "a",
        100_000,
        1,
        1,
        OpportunityStatus::Identified,
    ));
    m.add(make_opportunity(
        "b",
        200_000,
        2,
        2,
        OpportunityStatus::Approved,
    ));
    let json = serde_json::to_string(&m).unwrap();
    let back: OpportunityMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ---------------------------------------------------------------------------
// 11. BaselineRegistry
// ---------------------------------------------------------------------------

#[test]
fn registry_new_empty() {
    let reg = BaselineRegistry::new();
    assert_eq!(reg.count(), 0);
    assert!(reg.get("any").is_none());
}

#[test]
fn registry_default_same_as_new() {
    let def = BaselineRegistry::default();
    let new = BaselineRegistry::new();
    assert_eq!(def, new);
}

#[test]
fn registry_register_and_get() {
    let mut reg = BaselineRegistry::new();
    let env = make_env("e1");
    reg.register(BenchmarkResult::new("b1", env));
    assert_eq!(reg.count(), 1);
    assert!(reg.get("b1").is_some());
    assert!(reg.get("b2").is_none());
}

#[test]
fn registry_register_overwrites_same_id() {
    let mut reg = BaselineRegistry::new();
    let env = make_env("e1");
    reg.register(BenchmarkResult::new("b1", env.clone()).with_memory(MemorySnapshot::empty()));
    reg.register(BenchmarkResult::new("b1", env));
    assert_eq!(reg.count(), 1);
    // Second registration should have overwritten: no memory
    assert!(reg.get("b1").unwrap().memory.is_none());
}

#[test]
fn registry_compare_latency_improvement() {
    let mut reg = BaselineRegistry::new();
    let env = make_env("e-lat");

    let baseline_samples = make_samples(100, 2000, 10);
    let baseline = BenchmarkResult::new("lat-bench", env.clone())
        .with_latency(PercentileStats::from_samples(&baseline_samples).unwrap());
    reg.register(baseline);

    let candidate_samples = make_samples(100, 1000, 10);
    let candidate = BenchmarkResult::new("lat-bench-v2", env)
        .with_latency(PercentileStats::from_samples(&candidate_samples).unwrap());

    let cmp = reg.compare("lat-bench", &candidate).unwrap();
    assert!(cmp.improvement_count() > 0);
}

#[test]
fn registry_compare_throughput_improvement() {
    let mut reg = BaselineRegistry::new();
    let env = make_env("e-thr");

    // Baseline: 1000 ops/sec
    let baseline = BenchmarkResult::new("thr-bench", env.clone())
        .with_throughput(ThroughputMeasurement::new(1000, 1_000_000_000));
    reg.register(baseline);

    // Candidate: 2000 ops/sec (better throughput)
    let candidate = BenchmarkResult::new("thr-bench-v2", env)
        .with_throughput(ThroughputMeasurement::new(2000, 1_000_000_000));

    let cmp = reg.compare("thr-bench", &candidate).unwrap();
    // Throughput is inverted: higher = improvement
    assert!(cmp.improvement_count() > 0);
}

#[test]
fn registry_compare_memory_regression() {
    let mut reg = BaselineRegistry::new();
    let env = make_env("e-mem");

    let baseline = BenchmarkResult::new("mem-bench", env.clone()).with_memory(MemorySnapshot {
        heap_bytes: 1024,
        stack_bytes: 0,
        peak_heap_bytes: 1024,
        live_allocations: 0,
        total_allocations: 10,
        total_deallocations: 10,
    });
    reg.register(baseline);

    let candidate = BenchmarkResult::new("mem-bench-v2", env).with_memory(MemorySnapshot {
        heap_bytes: 10240, // 10x more heap
        stack_bytes: 0,
        peak_heap_bytes: 10240,
        live_allocations: 0,
        total_allocations: 50,
        total_deallocations: 50,
    });

    let cmp = reg.compare("mem-bench", &candidate).unwrap();
    assert!(cmp.regression_count() > 0);
}

#[test]
fn registry_compare_missing_baseline_returns_none() {
    let reg = BaselineRegistry::new();
    let env = make_env("e1");
    let candidate = BenchmarkResult::new("b1", env);
    assert!(reg.compare("nonexistent", &candidate).is_none());
}

#[test]
fn registry_compare_no_overlapping_metrics() {
    let mut reg = BaselineRegistry::new();
    let env = make_env("e-none");
    // Baseline with only latency
    let samples = make_samples(50, 1000, 10);
    let baseline = BenchmarkResult::new("b-lat", env.clone())
        .with_latency(PercentileStats::from_samples(&samples).unwrap());
    reg.register(baseline);
    // Candidate with only memory (no latency overlap)
    let candidate = BenchmarkResult::new("b-mem", env).with_memory(MemorySnapshot::empty());
    let cmp = reg.compare("b-lat", &candidate).unwrap();
    // No latency overlap (candidate has no latency), no throughput, no memory overlap
    assert_eq!(cmp.comparisons.len(), 0);
    assert_eq!(cmp.overall_direction, ComparisonDirection::Neutral);
}

#[test]
fn registry_derive_id_deterministic() {
    let r1 = BaselineRegistry::new();
    let r2 = BaselineRegistry::new();
    assert_eq!(r1.derive_id(), r2.derive_id());
}

#[test]
fn registry_derive_id_changes_with_count() {
    let mut reg = BaselineRegistry::new();
    let id_empty = reg.derive_id();
    reg.register(BenchmarkResult::new("b1", make_env("e1")));
    let id_one = reg.derive_id();
    assert_ne!(id_empty, id_one);
}

#[test]
fn registry_serde_roundtrip() {
    let mut reg = BaselineRegistry::new();
    let env = make_env("e-serde");
    let samples = make_samples(30, 500, 5);
    let result = BenchmarkResult::new("bench-ser", env)
        .with_latency(PercentileStats::from_samples(&samples).unwrap())
        .with_throughput(ThroughputMeasurement::new(800, 2_000_000_000))
        .with_memory(MemorySnapshot {
            heap_bytes: 2048,
            stack_bytes: 512,
            peak_heap_bytes: 4096,
            live_allocations: 2,
            total_allocations: 40,
            total_deallocations: 38,
        });
    reg.register(result);
    let json = serde_json::to_string(&reg).unwrap();
    let back: BaselineRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
}

// ---------------------------------------------------------------------------
// 12. End-to-end pipeline
// ---------------------------------------------------------------------------

#[test]
fn e2e_full_optimization_pipeline() {
    // Step 1: Create environment
    let env = BenchmarkEnvironment::default_env("parser-flush");
    assert!(env.validate().is_empty());

    // Step 2: Collect samples with warmup
    let mut samples = Vec::new();
    for i in 0..10 {
        samples.push(LatencySample {
            latency_ns: 5000 + i * 200,
            iteration: i as u32,
            is_warmup: true,
        });
    }
    for i in 10..110 {
        samples.push(LatencySample {
            latency_ns: 2000 + (i % 20) * 50,
            iteration: i as u32,
            is_warmup: false,
        });
    }
    let stats = PercentileStats::from_samples(&samples).unwrap();
    assert_eq!(stats.sample_count, 100);

    // Step 3: Build baseline result
    let mut baseline = BenchmarkResult::new("parser-flush-v1", env.clone())
        .with_latency(stats)
        .with_throughput(ThroughputMeasurement::new(10_000, 2_000_000_000))
        .with_memory(MemorySnapshot {
            heap_bytes: 1_048_576,
            stack_bytes: 65_536,
            peak_heap_bytes: 2_097_152,
            live_allocations: 0,
            total_allocations: 50_000,
            total_deallocations: 50_000,
        });
    baseline.add_profile(
        ProfileArtifact::new(ProfileKind::CpuFlamegraph, "parser-flush-v1").with_hotspot(Hotspot {
            symbol: "Parser::flush_dirty".to_string(),
            percentage_millionths: 420_000,
            samples: 4200,
            module_path: "parser_core".to_string(),
        }),
    );

    // Step 4: Register baseline
    let mut registry = BaselineRegistry::new();
    registry.register(baseline);
    assert_eq!(registry.count(), 1);

    // Step 5: Build opportunity matrix
    let mut matrix = OpportunityMatrix::new("parser-flush-opts");
    matrix.add(OptimizationOpportunity {
        id: "batch-flush".to_string(),
        description: "Batch dirty propagation".to_string(),
        component: "parser_core".to_string(),
        estimated_impact_millionths: 350_000,
        effort: 2,
        risk: 1,
        evidence_profile_kinds: vec![ProfileKind::CpuFlamegraph],
        status: OpportunityStatus::Approved,
    });
    matrix.add(OptimizationOpportunity {
        id: "arena-alloc".to_string(),
        description: "Arena allocator for AST nodes".to_string(),
        component: "parser_core".to_string(),
        estimated_impact_millionths: 200_000,
        effort: 3,
        risk: 2,
        evidence_profile_kinds: vec![ProfileKind::AllocationFlamegraph],
        status: OpportunityStatus::Identified,
    });
    let ranked = matrix.ranked();
    assert_eq!(ranked[0].id, "batch-flush");
    assert_eq!(matrix.approved_impact_millionths(), 350_000);

    // Step 6: Run candidate (improved)
    let candidate_samples = make_samples(100, 1500, 5);
    let candidate = BenchmarkResult::new("parser-flush-v2", env)
        .with_latency(PercentileStats::from_samples(&candidate_samples).unwrap())
        .with_throughput(ThroughputMeasurement::new(15_000, 2_000_000_000))
        .with_memory(MemorySnapshot {
            heap_bytes: 524_288,
            stack_bytes: 65_536,
            peak_heap_bytes: 1_048_576,
            live_allocations: 0,
            total_allocations: 30_000,
            total_deallocations: 30_000,
        });

    // Step 7: Compare
    let comparison = registry.compare("parser-flush-v1", &candidate).unwrap();
    assert!(
        comparison.improvement_count() > 0,
        "expected at least one improvement"
    );

    // Validate serde of the whole comparison
    let json = serde_json::to_string(&comparison).unwrap();
    let back: BaselineComparison = serde_json::from_str(&json).unwrap();
    assert_eq!(comparison, back);
}

#[test]
fn e2e_metric_comparison_serde_roundtrip() {
    let t = default_threshold();
    let mc = compare_metric("test_metric", 5000, 3000, &t);
    let json = serde_json::to_string(&mc).unwrap();
    let back: frankenengine_engine::optimization_baseline::MetricComparison =
        serde_json::from_str(&json).unwrap();
    assert_eq!(mc, back);
}
