//! Enrichment integration tests for `optimization_baseline` (FRX-06.1).
//!
//! Covers: JSON field-name stability, serde roundtrips, Display/as_str exact
//! values, Debug distinctness, BenchmarkEnvironment defaults/validation,
//! PercentileStats computation, ThroughputMeasurement, MemorySnapshot,
//! ProfileKind, compare_metric semantics, BaselineComparison, and
//! OpportunityStatus.

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

use frankenengine_engine::optimization_baseline::*;

// ── BenchmarkEnvironment ───────────────────────────────────────────────

#[test]
fn env_default_warmup_10() {
    let env = BenchmarkEnvironment::default_env("bench-1");
    assert_eq!(env.warmup_iterations, 10);
}

#[test]
fn env_default_measurement_100() {
    let env = BenchmarkEnvironment::default_env("bench-1");
    assert_eq!(env.measurement_iterations, 100);
}

#[test]
fn env_default_max_iteration_us() {
    let env = BenchmarkEnvironment::default_env("bench-1");
    assert_eq!(env.max_iteration_us, 10_000_000);
}

#[test]
fn env_default_pin_to_core_false() {
    let env = BenchmarkEnvironment::default_env("bench-1");
    assert!(!env.pin_to_core);
}

#[test]
fn env_default_disable_gc_false() {
    let env = BenchmarkEnvironment::default_env("bench-1");
    assert!(!env.disable_gc);
}

#[test]
fn env_validate_valid() {
    let env = BenchmarkEnvironment::default_env("bench-1");
    assert!(env.validate().is_empty());
}

#[test]
fn env_validate_empty_id() {
    let env = BenchmarkEnvironment::default_env("");
    let errs = env.validate();
    assert!(!errs.is_empty());
    assert!(errs.iter().any(|e| e.contains("env_id")));
}

#[test]
fn env_validate_zero_iterations() {
    let mut env = BenchmarkEnvironment::default_env("bench-1");
    env.measurement_iterations = 0;
    let errs = env.validate();
    assert!(errs.iter().any(|e| e.contains("measurement_iterations")));
}

#[test]
fn env_validate_zero_max_iteration() {
    let mut env = BenchmarkEnvironment::default_env("bench-1");
    env.max_iteration_us = 0;
    let errs = env.validate();
    assert!(errs.iter().any(|e| e.contains("max_iteration_us")));
}

#[test]
fn env_derive_id_deterministic() {
    let env = BenchmarkEnvironment::default_env("bench-det");
    let id1 = env.derive_id();
    let id2 = env.derive_id();
    assert_eq!(id1, id2);
}

#[test]
fn env_json_fields() {
    let env = BenchmarkEnvironment::default_env("bench-jf");
    let v: serde_json::Value = serde_json::to_value(&env).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("env_id"));
    assert!(obj.contains_key("warmup_iterations"));
    assert!(obj.contains_key("measurement_iterations"));
    assert!(obj.contains_key("max_iteration_us"));
    assert!(obj.contains_key("pin_to_core"));
    assert!(obj.contains_key("disable_gc"));
    assert!(obj.contains_key("tags"));
}

#[test]
fn env_serde_roundtrip() {
    let env = BenchmarkEnvironment::default_env("bench-rt");
    let json = serde_json::to_vec(&env).unwrap();
    let back: BenchmarkEnvironment = serde_json::from_slice(&json).unwrap();
    assert_eq!(env, back);
}

// ── LatencySample ──────────────────────────────────────────────────────

#[test]
fn latency_sample_json_fields() {
    let s = LatencySample {
        latency_ns: 1000,
        iteration: 5,
        is_warmup: false,
    };
    let v: serde_json::Value = serde_json::to_value(&s).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("latency_ns"));
    assert!(obj.contains_key("iteration"));
    assert!(obj.contains_key("is_warmup"));
}

#[test]
fn latency_sample_serde_roundtrip() {
    let s = LatencySample {
        latency_ns: 5000,
        iteration: 10,
        is_warmup: true,
    };
    let json = serde_json::to_vec(&s).unwrap();
    let back: LatencySample = serde_json::from_slice(&json).unwrap();
    assert_eq!(s, back);
}

// ── PercentileStats ────────────────────────────────────────────────────

#[test]
fn percentile_stats_from_empty_returns_none() {
    assert!(PercentileStats::from_samples(&[]).is_none());
}

#[test]
fn percentile_stats_from_warmup_only_returns_none() {
    let samples = vec![
        LatencySample {
            latency_ns: 100,
            iteration: 0,
            is_warmup: true,
        },
        LatencySample {
            latency_ns: 200,
            iteration: 1,
            is_warmup: true,
        },
    ];
    assert!(PercentileStats::from_samples(&samples).is_none());
}

#[test]
fn percentile_stats_from_samples_basic() {
    let mut samples = Vec::new();
    for i in 0..100 {
        samples.push(LatencySample {
            latency_ns: (i + 1) * 100,
            iteration: i as u32,
            is_warmup: false,
        });
    }
    let stats = PercentileStats::from_samples(&samples).unwrap();
    assert_eq!(stats.sample_count, 100);
    assert_eq!(stats.min_ns, 100);
    assert_eq!(stats.max_ns, 10_000);
    assert!(stats.p50_ns > 0);
    assert!(stats.p99_ns >= stats.p95_ns);
    assert!(stats.p95_ns >= stats.p90_ns);
    assert!(stats.p90_ns >= stats.p50_ns);
}

#[test]
fn percentile_stats_filters_warmup() {
    let samples = vec![
        LatencySample {
            latency_ns: 999_999,
            iteration: 0,
            is_warmup: true,
        },
        LatencySample {
            latency_ns: 100,
            iteration: 1,
            is_warmup: false,
        },
        LatencySample {
            latency_ns: 200,
            iteration: 2,
            is_warmup: false,
        },
    ];
    let stats = PercentileStats::from_samples(&samples).unwrap();
    assert_eq!(stats.sample_count, 2);
    assert_eq!(stats.min_ns, 100);
    assert_eq!(stats.max_ns, 200);
}

#[test]
fn percentile_stats_jitter() {
    let stats = PercentileStats {
        p50_ns: 1000,
        p90_ns: 1500,
        p95_ns: 1800,
        p99_ns: 2000,
        p999_ns: 2500,
        min_ns: 500,
        max_ns: 3000,
        mean_ns: 1200,
        sample_count: 100,
    };
    assert_eq!(stats.jitter_ns(), 1000); // p99 - p50
}

#[test]
fn percentile_stats_cv_millionths() {
    let stats = PercentileStats {
        p50_ns: 1000,
        p90_ns: 1500,
        p95_ns: 1800,
        p99_ns: 2000,
        p999_ns: 2500,
        min_ns: 500,
        max_ns: 3000,
        mean_ns: 1200,
        sample_count: 100,
    };
    let cv = stats.cv_millionths();
    assert!(cv > 0);
}

#[test]
fn percentile_stats_cv_zero_mean() {
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
fn percentile_stats_derive_id_deterministic() {
    let stats = PercentileStats {
        p50_ns: 500,
        p90_ns: 800,
        p95_ns: 900,
        p99_ns: 1000,
        p999_ns: 1100,
        min_ns: 100,
        max_ns: 1200,
        mean_ns: 600,
        sample_count: 50,
    };
    assert_eq!(stats.derive_id(), stats.derive_id());
}

#[test]
fn percentile_stats_json_fields() {
    let stats = PercentileStats {
        p50_ns: 100,
        p90_ns: 200,
        p95_ns: 300,
        p99_ns: 400,
        p999_ns: 500,
        min_ns: 50,
        max_ns: 600,
        mean_ns: 250,
        sample_count: 10,
    };
    let v: serde_json::Value = serde_json::to_value(&stats).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("p50_ns"));
    assert!(obj.contains_key("p90_ns"));
    assert!(obj.contains_key("p95_ns"));
    assert!(obj.contains_key("p99_ns"));
    assert!(obj.contains_key("p999_ns"));
    assert!(obj.contains_key("min_ns"));
    assert!(obj.contains_key("max_ns"));
    assert!(obj.contains_key("mean_ns"));
    assert!(obj.contains_key("sample_count"));
}

#[test]
fn percentile_stats_serde_roundtrip() {
    let stats = PercentileStats {
        p50_ns: 100,
        p90_ns: 200,
        p95_ns: 300,
        p99_ns: 400,
        p999_ns: 500,
        min_ns: 50,
        max_ns: 600,
        mean_ns: 250,
        sample_count: 10,
    };
    let json = serde_json::to_vec(&stats).unwrap();
    let back: PercentileStats = serde_json::from_slice(&json).unwrap();
    assert_eq!(stats, back);
}

// ── ThroughputMeasurement ──────────────────────────────────────────────

#[test]
fn throughput_new_computes_ops_per_sec() {
    let t = ThroughputMeasurement::new(1000, 1_000_000_000); // 1000 ops in 1s
    assert_eq!(t.ops_per_sec_millionths, 1000 * 1_000_000); // 1000.0 ops/s
}

#[test]
fn throughput_new_zero_duration() {
    let t = ThroughputMeasurement::new(100, 0);
    assert_eq!(t.ops_per_sec_millionths, 0);
}

#[test]
fn throughput_bytes_per_sec_none_without_bytes() {
    let t = ThroughputMeasurement::new(100, 1_000_000_000);
    assert!(t.bytes_per_sec_millionths().is_none());
}

#[test]
fn throughput_bytes_per_sec_with_bytes() {
    let t = ThroughputMeasurement::new(100, 1_000_000_000).with_bytes(1024);
    let bps = t.bytes_per_sec_millionths().unwrap();
    assert!(bps > 0);
}

#[test]
fn throughput_json_fields() {
    let t = ThroughputMeasurement::new(500, 2_000_000_000).with_bytes(2048);
    let v: serde_json::Value = serde_json::to_value(&t).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("ops_per_sec_millionths"));
    assert!(obj.contains_key("total_ops"));
    assert!(obj.contains_key("duration_ns"));
    assert!(obj.contains_key("bytes_processed"));
}

#[test]
fn throughput_serde_roundtrip() {
    let t = ThroughputMeasurement::new(500, 2_000_000_000).with_bytes(2048);
    let json = serde_json::to_vec(&t).unwrap();
    let back: ThroughputMeasurement = serde_json::from_slice(&json).unwrap();
    assert_eq!(t, back);
}

// ── MemorySnapshot ─────────────────────────────────────────────────────

#[test]
fn memory_snapshot_empty() {
    let m = MemorySnapshot::empty();
    assert_eq!(m.heap_bytes, 0);
    assert_eq!(m.allocation_churn(), 0);
    assert!(!m.potential_leak());
}

#[test]
fn memory_snapshot_positive_churn() {
    let m = MemorySnapshot {
        heap_bytes: 1024,
        stack_bytes: 256,
        peak_heap_bytes: 2048,
        live_allocations: 10,
        total_allocations: 100,
        total_deallocations: 90,
    };
    assert_eq!(m.allocation_churn(), 10);
    assert!(m.potential_leak()); // live > 0 and deallocs < allocs
}

#[test]
fn memory_snapshot_no_leak_when_balanced() {
    let m = MemorySnapshot {
        heap_bytes: 0,
        stack_bytes: 0,
        peak_heap_bytes: 100,
        live_allocations: 0,
        total_allocations: 50,
        total_deallocations: 50,
    };
    assert!(!m.potential_leak());
}

#[test]
fn memory_snapshot_json_fields() {
    let m = MemorySnapshot::empty();
    let v: serde_json::Value = serde_json::to_value(&m).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("heap_bytes"));
    assert!(obj.contains_key("stack_bytes"));
    assert!(obj.contains_key("peak_heap_bytes"));
    assert!(obj.contains_key("live_allocations"));
    assert!(obj.contains_key("total_allocations"));
    assert!(obj.contains_key("total_deallocations"));
}

#[test]
fn memory_snapshot_serde_roundtrip() {
    let m = MemorySnapshot {
        heap_bytes: 1024,
        stack_bytes: 256,
        peak_heap_bytes: 4096,
        live_allocations: 5,
        total_allocations: 50,
        total_deallocations: 45,
    };
    let json = serde_json::to_vec(&m).unwrap();
    let back: MemorySnapshot = serde_json::from_slice(&json).unwrap();
    assert_eq!(m, back);
}

// ── ProfileKind ────────────────────────────────────────────────────────

#[test]
fn profile_kind_as_str_exact() {
    assert_eq!(ProfileKind::CpuFlamegraph.as_str(), "cpu_flamegraph");
    assert_eq!(
        ProfileKind::AllocationFlamegraph.as_str(),
        "allocation_flamegraph"
    );
    assert_eq!(ProfileKind::SyscallTrace.as_str(), "syscall_trace");
    assert_eq!(ProfileKind::CacheMissProfile.as_str(), "cache_miss_profile");
    assert_eq!(
        ProfileKind::BranchMispredictionProfile.as_str(),
        "branch_misprediction_profile"
    );
}

#[test]
fn profile_kind_all_has_five() {
    assert_eq!(ProfileKind::ALL.len(), 5);
}

#[test]
fn profile_kind_debug_distinct() {
    let mut dbgs = BTreeSet::new();
    for k in &ProfileKind::ALL {
        dbgs.insert(format!("{k:?}"));
    }
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn profile_kind_serde_roundtrip_all() {
    for k in &ProfileKind::ALL {
        let json = serde_json::to_vec(k).unwrap();
        let back: ProfileKind = serde_json::from_slice(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ── Hotspot ────────────────────────────────────────────────────────────

#[test]
fn hotspot_json_fields() {
    let h = Hotspot {
        symbol: "hot_function".to_string(),
        percentage_millionths: 250_000,
        samples: 1000,
        module_path: "engine::core".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&h).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("symbol"));
    assert!(obj.contains_key("percentage_millionths"));
    assert!(obj.contains_key("samples"));
    assert!(obj.contains_key("module_path"));
}

#[test]
fn hotspot_serde_roundtrip() {
    let h = Hotspot {
        symbol: "alloc".to_string(),
        percentage_millionths: 100_000,
        samples: 500,
        module_path: "std::alloc".to_string(),
    };
    let json = serde_json::to_vec(&h).unwrap();
    let back: Hotspot = serde_json::from_slice(&json).unwrap();
    assert_eq!(h, back);
}

// ── ProfileArtifact ────────────────────────────────────────────────────

#[test]
fn profile_artifact_new() {
    let pa = ProfileArtifact::new(ProfileKind::CpuFlamegraph, "bench-1");
    assert_eq!(pa.kind, ProfileKind::CpuFlamegraph);
    assert_eq!(pa.benchmark_id, "bench-1");
    assert!(pa.hotspots.is_empty());
}

#[test]
fn profile_artifact_with_hotspot() {
    let pa = ProfileArtifact::new(ProfileKind::SyscallTrace, "bench-2").with_hotspot(Hotspot {
        symbol: "syscall".to_string(),
        percentage_millionths: 300_000,
        samples: 2000,
        module_path: "kernel".to_string(),
    });
    assert_eq!(pa.hotspots.len(), 1);
}

#[test]
fn profile_artifact_derive_id_deterministic() {
    let pa = ProfileArtifact::new(ProfileKind::CacheMissProfile, "bench-det");
    assert_eq!(pa.derive_id(), pa.derive_id());
}

#[test]
fn profile_artifact_serde_roundtrip() {
    let pa =
        ProfileArtifact::new(ProfileKind::AllocationFlamegraph, "bench-rt").with_hotspot(Hotspot {
            symbol: "malloc".to_string(),
            percentage_millionths: 150_000,
            samples: 800,
            module_path: "libc".to_string(),
        });
    let json = serde_json::to_vec(&pa).unwrap();
    let back: ProfileArtifact = serde_json::from_slice(&json).unwrap();
    assert_eq!(pa, back);
}

// ── ComparisonDirection ────────────────────────────────────────────────

#[test]
fn comparison_direction_debug_distinct() {
    let dirs = [
        ComparisonDirection::Improvement,
        ComparisonDirection::Regression,
        ComparisonDirection::Neutral,
    ];
    let mut dbgs = BTreeSet::new();
    for d in &dirs {
        dbgs.insert(format!("{d:?}"));
    }
    assert_eq!(dbgs.len(), 3);
}

#[test]
fn comparison_direction_serde_roundtrip_all() {
    for d in [
        ComparisonDirection::Improvement,
        ComparisonDirection::Regression,
        ComparisonDirection::Neutral,
    ] {
        let json = serde_json::to_vec(&d).unwrap();
        let back: ComparisonDirection = serde_json::from_slice(&json).unwrap();
        assert_eq!(d, back);
    }
}

// ── compare_metric ─────────────────────────────────────────────────────

#[test]
fn compare_metric_neutral_within_threshold() {
    let t = SignificanceThreshold::default_threshold();
    let c = compare_metric("latency_p50", 1000, 1010, &t);
    assert_eq!(c.direction, ComparisonDirection::Neutral);
}

#[test]
fn compare_metric_regression_above_threshold() {
    let t = SignificanceThreshold::default_threshold();
    let c = compare_metric("latency_p50", 1000, 1200, &t); // 20% increase
    assert_eq!(c.direction, ComparisonDirection::Regression);
    assert!(c.change_millionths > 0);
}

#[test]
fn compare_metric_improvement_below_threshold() {
    let t = SignificanceThreshold::default_threshold();
    let c = compare_metric("latency_p50", 1000, 800, &t); // 20% decrease
    assert_eq!(c.direction, ComparisonDirection::Improvement);
    assert!(c.change_millionths < 0);
}

#[test]
fn compare_metric_zero_baseline() {
    let t = SignificanceThreshold::default_threshold();
    let c = compare_metric("ops", 0, 100, &t);
    assert_eq!(c.change_millionths, 1_000_000);
}

#[test]
fn compare_metric_both_zero() {
    let t = SignificanceThreshold::default_threshold();
    let c = compare_metric("ops", 0, 0, &t);
    assert_eq!(c.change_millionths, 0);
    assert_eq!(c.direction, ComparisonDirection::Neutral);
}

// ── SignificanceThreshold ──────────────────────────────────────────────

#[test]
fn significance_threshold_default_values() {
    let t = SignificanceThreshold::default_threshold();
    assert_eq!(t.min_change_millionths, 50_000); // 5%
    assert_eq!(t.min_samples, 30);
}

#[test]
fn significance_threshold_serde_roundtrip() {
    let t = SignificanceThreshold::default_threshold();
    let json = serde_json::to_vec(&t).unwrap();
    let back: SignificanceThreshold = serde_json::from_slice(&json).unwrap();
    assert_eq!(t, back);
}

// ── MetricComparison ───────────────────────────────────────────────────

#[test]
fn metric_comparison_json_fields() {
    let t = SignificanceThreshold::default_threshold();
    let c = compare_metric("latency_p99", 1000, 1300, &t);
    let v: serde_json::Value = serde_json::to_value(&c).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("metric_name"));
    assert!(obj.contains_key("baseline_value"));
    assert!(obj.contains_key("candidate_value"));
    assert!(obj.contains_key("change_millionths"));
    assert!(obj.contains_key("direction"));
}

#[test]
fn metric_comparison_serde_roundtrip() {
    let t = SignificanceThreshold::default_threshold();
    let c = compare_metric("throughput", 5000, 4000, &t);
    let json = serde_json::to_vec(&c).unwrap();
    let back: MetricComparison = serde_json::from_slice(&json).unwrap();
    assert_eq!(c, back);
}

// ── BaselineComparison ─────────────────────────────────────────────────

#[test]
fn baseline_comparison_new_is_neutral() {
    let bc = BaselineComparison::new("base-1", "cand-1");
    assert_eq!(bc.overall_direction, ComparisonDirection::Neutral);
    assert!(bc.comparisons.is_empty());
    assert_eq!(bc.regression_count(), 0);
    assert_eq!(bc.improvement_count(), 0);
}

#[test]
fn baseline_comparison_adds_regression() {
    let t = SignificanceThreshold::default_threshold();
    let mut bc = BaselineComparison::new("base-1", "cand-1");
    bc.add_comparison(compare_metric("latency", 1000, 1500, &t));
    assert_eq!(bc.regression_count(), 1);
    assert_eq!(bc.overall_direction, ComparisonDirection::Regression);
}

#[test]
fn baseline_comparison_adds_improvement() {
    let t = SignificanceThreshold::default_threshold();
    let mut bc = BaselineComparison::new("base-1", "cand-1");
    bc.add_comparison(compare_metric("latency", 1000, 500, &t));
    assert_eq!(bc.improvement_count(), 1);
    assert_eq!(bc.overall_direction, ComparisonDirection::Improvement);
}

#[test]
fn baseline_comparison_mixed_is_neutral() {
    let t = SignificanceThreshold::default_threshold();
    let mut bc = BaselineComparison::new("base-1", "cand-1");
    bc.add_comparison(compare_metric("latency", 1000, 1500, &t)); // regression
    bc.add_comparison(compare_metric("throughput", 1000, 500, &t)); // improvement
    assert_eq!(bc.overall_direction, ComparisonDirection::Neutral);
}

#[test]
fn baseline_comparison_derive_id_deterministic() {
    let bc = BaselineComparison::new("base-1", "cand-1");
    assert_eq!(bc.derive_id(), bc.derive_id());
}

#[test]
fn baseline_comparison_json_fields() {
    let bc = BaselineComparison::new("base-jf", "cand-jf");
    let v: serde_json::Value = serde_json::to_value(&bc).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("baseline_id"));
    assert!(obj.contains_key("candidate_id"));
    assert!(obj.contains_key("comparisons"));
    assert!(obj.contains_key("overall_direction"));
}

#[test]
fn baseline_comparison_serde_roundtrip() {
    let t = SignificanceThreshold::default_threshold();
    let mut bc = BaselineComparison::new("base-rt", "cand-rt");
    bc.add_comparison(compare_metric("latency", 1000, 1200, &t));
    let json = serde_json::to_vec(&bc).unwrap();
    let back: BaselineComparison = serde_json::from_slice(&json).unwrap();
    assert_eq!(bc, back);
}

// ── OpportunityStatus ──────────────────────────────────────────────────

#[test]
fn opportunity_status_debug_distinct() {
    let statuses = [
        OpportunityStatus::Identified,
        OpportunityStatus::Evaluating,
        OpportunityStatus::Approved,
        OpportunityStatus::Implemented,
        OpportunityStatus::Rejected,
    ];
    let mut dbgs = BTreeSet::new();
    for s in &statuses {
        dbgs.insert(format!("{s:?}"));
    }
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn opportunity_status_serde_roundtrip_all() {
    for s in [
        OpportunityStatus::Identified,
        OpportunityStatus::Evaluating,
        OpportunityStatus::Approved,
        OpportunityStatus::Implemented,
        OpportunityStatus::Rejected,
    ] {
        let json = serde_json::to_vec(&s).unwrap();
        let back: OpportunityStatus = serde_json::from_slice(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ── BenchmarkResult ────────────────────────────────────────────────────

#[test]
fn benchmark_result_new_empty() {
    let env = BenchmarkEnvironment::default_env("bench-1");
    let br = BenchmarkResult::new("result-1", env);
    assert!(br.latency.is_none());
    assert!(br.throughput.is_none());
    assert!(br.memory.is_none());
    assert!(br.profiles.is_empty());
}

#[test]
fn benchmark_result_with_latency() {
    let env = BenchmarkEnvironment::default_env("bench-1");
    let stats = PercentileStats {
        p50_ns: 100,
        p90_ns: 200,
        p95_ns: 300,
        p99_ns: 400,
        p999_ns: 500,
        min_ns: 50,
        max_ns: 600,
        mean_ns: 250,
        sample_count: 10,
    };
    let br = BenchmarkResult::new("result-lat", env).with_latency(stats);
    assert!(br.latency.is_some());
}

#[test]
fn benchmark_result_derive_id_deterministic() {
    let env = BenchmarkEnvironment::default_env("bench-det");
    let br = BenchmarkResult::new("result-det", env);
    assert_eq!(br.derive_id(), br.derive_id());
}

#[test]
fn benchmark_result_serde_roundtrip() {
    let env = BenchmarkEnvironment::default_env("bench-rt");
    let br = BenchmarkResult::new("result-rt", env)
        .with_throughput(ThroughputMeasurement::new(1000, 1_000_000_000))
        .with_memory(MemorySnapshot::empty());
    let json = serde_json::to_vec(&br).unwrap();
    let back: BenchmarkResult = serde_json::from_slice(&json).unwrap();
    assert_eq!(br, back);
}

// ── OptimizationOpportunity ────────────────────────────────────────────

#[test]
fn optimization_opportunity_serde_roundtrip() {
    let opp = OptimizationOpportunity {
        id: "opp-1".to_string(),
        description: "reduce allocations".to_string(),
        component: "parser".to_string(),
        estimated_impact_millionths: 200_000,
        effort: 2,
        risk: 1,
        evidence_profile_kinds: vec![ProfileKind::AllocationFlamegraph],
        status: OpportunityStatus::Identified,
    };
    let json = serde_json::to_vec(&opp).unwrap();
    let back: OptimizationOpportunity = serde_json::from_slice(&json).unwrap();
    assert_eq!(opp, back);
}

#[test]
fn optimization_opportunity_json_fields() {
    let opp = OptimizationOpportunity {
        id: "opp-jf".to_string(),
        description: "test".to_string(),
        component: "core".to_string(),
        estimated_impact_millionths: 100_000,
        effort: 3,
        risk: 2,
        evidence_profile_kinds: vec![],
        status: OpportunityStatus::Approved,
    };
    let v: serde_json::Value = serde_json::to_value(&opp).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("id"));
    assert!(obj.contains_key("description"));
    assert!(obj.contains_key("component"));
    assert!(obj.contains_key("estimated_impact_millionths"));
    assert!(obj.contains_key("effort"));
    assert!(obj.contains_key("risk"));
    assert!(obj.contains_key("evidence_profile_kinds"));
    assert!(obj.contains_key("status"));
}
