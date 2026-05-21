#![forbid(unsafe_code)]

//! Criterion benchmark for denominator scoring path performance.
//!
//! This benchmark validates that the weighted-geometric-mean computation
//! in benchmark_denominator.rs is sufficiently fast such that scoring
//! does not dominate workload measurement overhead.
//!
//! Target: scoring operations should complete in microseconds, not milliseconds.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use frankenengine_engine::benchmark_denominator::{
    BaselineEngine, BenchmarkCase, PublicationContext, PublicationGateInput,
    NativeCoveragePoint, evaluate_publication_gate, weighted_geometric_mean,
};

/// Creates a typical benchmark case for performance testing.
fn create_benchmark_case(
    workload_id: &str,
    franken_tps: f64,
    baseline_tps: f64,
    weight: Option<f64>,
) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: workload_id.to_string(),
        throughput_franken_tps: franken_tps,
        throughput_baseline_tps: baseline_tps,
        weight,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
        execution_authentic: true,
    }
}

/// Creates a small set of benchmark cases (typical workload).
fn small_case_set() -> Vec<BenchmarkCase> {
    vec![
        create_benchmark_case("async_basics", 4500.0, 1000.0, None),
        create_benchmark_case("array_ops", 5200.0, 1200.0, None),
        create_benchmark_case("object_manipulation", 3800.0, 950.0, None),
        create_benchmark_case("string_processing", 4100.0, 1100.0, None),
        create_benchmark_case("json_parsing", 3900.0, 800.0, None),
    ]
}

/// Creates a medium set of benchmark cases (realistic production workload).
fn medium_case_set() -> Vec<BenchmarkCase> {
    let mut cases = Vec::with_capacity(25);
    let workloads = [
        ("async_await", 4500.0, 1000.0),
        ("promise_chain", 4200.0, 900.0),
        ("array_map", 5200.0, 1200.0),
        ("array_filter", 4800.0, 1100.0),
        ("array_reduce", 4600.0, 1050.0),
        ("object_assign", 3800.0, 950.0),
        ("object_keys", 4300.0, 1000.0),
        ("object_values", 4100.0, 980.0),
        ("string_concat", 4100.0, 1100.0),
        ("string_replace", 3900.0, 900.0),
        ("string_split", 4000.0, 1000.0),
        ("json_parse", 3900.0, 800.0),
        ("json_stringify", 3700.0, 750.0),
        ("regex_test", 3500.0, 850.0),
        ("regex_replace", 3600.0, 900.0),
        ("dom_query", 4200.0, 1000.0),
        ("dom_manipulation", 3800.0, 900.0),
        ("event_handling", 4500.0, 1200.0),
        ("fetch_request", 3200.0, 800.0),
        ("websocket_message", 3800.0, 950.0),
        ("crypto_hash", 2800.0, 700.0),
        ("crypto_random", 3100.0, 800.0),
        ("file_system_read", 2900.0, 750.0),
        ("database_query", 2600.0, 650.0),
        ("compression_gzip", 2400.0, 600.0),
    ];

    for (i, (name, franken, baseline)) in workloads.iter().enumerate() {
        cases.push(create_benchmark_case(
            &format!("{name}_{i}"),
            *franken,
            *baseline,
            None,
        ));
    }
    cases
}

/// Creates a large set of benchmark cases (stress test scenario).
fn large_case_set() -> Vec<BenchmarkCase> {
    let mut cases = Vec::with_capacity(100);
    let base_workloads = medium_case_set();

    // Replicate and vary the medium set to create 100 cases
    for i in 0..100 {
        let base = &base_workloads[i % base_workloads.len()];
        let variation_factor = 1.0 + (i as f64 * 0.01); // slight variations
        cases.push(create_benchmark_case(
            &format!("{}_var_{}", base.workload_id, i),
            base.throughput_franken_tps * variation_factor,
            base.throughput_baseline_tps * variation_factor,
            None,
        ));
    }
    cases
}

/// Creates benchmark cases with explicit weights (more complex computation).
fn weighted_case_set() -> Vec<BenchmarkCase> {
    vec![
        create_benchmark_case("critical_path", 4500.0, 1000.0, Some(0.4)),
        create_benchmark_case("common_ops", 4200.0, 1100.0, Some(0.3)),
        create_benchmark_case("edge_cases", 3800.0, 900.0, Some(0.2)),
        create_benchmark_case("legacy_compat", 3500.0, 950.0, Some(0.1)),
    ]
}

/// Creates test context for publication gate benchmarks.
fn test_context() -> PublicationContext {
    PublicationContext::new("bench-trace-123", "bench-dec-456", "bench-pol-789")
}

/// Creates test publication gate input for benchmarking.
fn test_publication_input_small() -> PublicationGateInput {
    PublicationGateInput {
        node_cases: small_case_set(),
        bun_cases: small_case_set(),
        native_coverage_progression: vec![
            NativeCoveragePoint {
                recorded_at_utc: "2026-05-21T00:00:00Z".to_string(),
                native_slots: 85,
                total_slots: 100,
            }
        ],
        replacement_lineage_ids: vec!["bench-lineage-001".to_string()],
    }
}

/// Creates medium-sized publication gate input for benchmarking.
fn test_publication_input_medium() -> PublicationGateInput {
    PublicationGateInput {
        node_cases: medium_case_set(),
        bun_cases: medium_case_set(),
        native_coverage_progression: vec![
            NativeCoveragePoint {
                recorded_at_utc: "2026-05-21T00:00:00Z".to_string(),
                native_slots: 85,
                total_slots: 100,
            }
        ],
        replacement_lineage_ids: vec!["bench-lineage-001".to_string()],
    }
}

/// Main benchmark function for denominator scoring performance.
fn bench_denominator_scoring(c: &mut Criterion) {
    let mut group = c.benchmark_group("denominator_scoring");

    // ── Weighted geometric mean benchmarks ─────────────────────────────

    group.bench_function("geometric_mean_small_uniform", |b| {
        let cases = small_case_set();
        b.iter(|| {
            black_box(
                weighted_geometric_mean(&cases, BaselineEngine::Node)
                    .expect("small uniform cases should succeed")
            );
        });
    });

    group.bench_function("geometric_mean_medium_uniform", |b| {
        let cases = medium_case_set();
        b.iter(|| {
            black_box(
                weighted_geometric_mean(&cases, BaselineEngine::Node)
                    .expect("medium uniform cases should succeed")
            );
        });
    });

    group.bench_function("geometric_mean_large_uniform", |b| {
        let cases = large_case_set();
        b.iter(|| {
            black_box(
                weighted_geometric_mean(&cases, BaselineEngine::Node)
                    .expect("large uniform cases should succeed")
            );
        });
    });

    group.bench_function("geometric_mean_small_weighted", |b| {
        let cases = weighted_case_set();
        b.iter(|| {
            black_box(
                weighted_geometric_mean(&cases, BaselineEngine::Bun)
                    .expect("small weighted cases should succeed")
            );
        });
    });

    // ── Publication gate evaluation benchmarks ─────────────────────────

    group.bench_function("publication_gate_small", |b| {
        let input = test_publication_input_small();
        let ctx = test_context();
        b.iter(|| {
            black_box(
                evaluate_publication_gate(&input, &ctx)
                    .expect("small publication gate should succeed")
            );
        });
    });

    group.bench_function("publication_gate_medium", |b| {
        let input = test_publication_input_medium();
        let ctx = test_context();
        b.iter(|| {
            black_box(
                evaluate_publication_gate(&input, &ctx)
                    .expect("medium publication gate should succeed")
            );
        });
    });

    // ── Combined baseline comparison benchmarks ─────────────────────────

    group.bench_function("dual_baseline_scoring_small", |b| {
        let cases = small_case_set();
        b.iter(|| {
            let node_score = weighted_geometric_mean(&cases, BaselineEngine::Node)
                .expect("node scoring should succeed");
            let bun_score = weighted_geometric_mean(&cases, BaselineEngine::Bun)
                .expect("bun scoring should succeed");
            black_box((node_score, bun_score));
        });
    });

    group.bench_function("dual_baseline_scoring_medium", |b| {
        let cases = medium_case_set();
        b.iter(|| {
            let node_score = weighted_geometric_mean(&cases, BaselineEngine::Node)
                .expect("node scoring should succeed");
            let bun_score = weighted_geometric_mean(&cases, BaselineEngine::Bun)
                .expect("bun scoring should succeed");
            black_box((node_score, bun_score));
        });
    });

    // ── Computation overhead stress test ───────────────────────────────

    group.bench_function("repeated_scoring_overhead", |b| {
        let small_cases = small_case_set();
        let medium_cases = medium_case_set();
        b.iter(|| {
            // Simulate multiple rounds of scoring as might happen
            // during continuous benchmarking
            for _ in 0..10 {
                let _score1 = weighted_geometric_mean(&small_cases, BaselineEngine::Node)
                    .expect("repeated scoring should succeed");
                let _score2 = weighted_geometric_mean(&medium_cases, BaselineEngine::Bun)
                    .expect("repeated scoring should succeed");
            }
            black_box(());
        });
    });

    group.finish();
}

criterion_group!(denominator_scoring, bench_denominator_scoring);
criterion_main!(denominator_scoring);