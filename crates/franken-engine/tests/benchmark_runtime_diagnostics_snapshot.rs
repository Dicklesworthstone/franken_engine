#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use frankenengine_engine::benchmark_evidence_bundle::{
    BenchmarkRun, BundleConfig, EnvironmentSnapshot, EvidenceBundle, ParityTarget, ParityVerdict,
    WorkloadCategory, WorkloadProvenance, generate_report,
};
use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_diagnostics_cli::{
    GcPressureSample, RuntimeExtensionState, RuntimeStateInput, SchedulerLaneSample,
    collect_runtime_diagnostics, render_diagnostics_summary,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::Serialize;

const GOLDEN_RELATIVE_PATH: &str = "tests/golden_vectors/benchmark_diagnostics_output_v1.json";
const EXPECTED: &str = include_str!("golden_vectors/benchmark_diagnostics_output_v1.json");

#[derive(Debug, Serialize)]
struct BenchmarkDiagnosticsGolden {
    coverage_gap: &'static str,
    benchmark_report: frankenengine_engine::benchmark_evidence_bundle::BundleReport,
    runtime_diagnostics: frankenengine_engine::runtime_diagnostics_cli::RuntimeDiagnosticsOutput,
    runtime_diagnostics_summary: String,
}

fn epoch(value: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(value)
}

fn benchmark_environment() -> EnvironmentSnapshot {
    let mut extra = BTreeMap::new();
    extra.insert("kernel".to_string(), "6.8.0-test".to_string());
    extra.insert("runner".to_string(), "golden-fixture".to_string());
    EnvironmentSnapshot::new(
        "linux".to_string(),
        "x86_64 deterministic runner".to_string(),
        16,
        64_000_000_000,
        "node 22.1.0".to_string(),
        "franken-engine 0.1.0".to_string(),
        extra,
    )
}

fn workload(id: &str, category: WorkloadCategory) -> WorkloadProvenance {
    WorkloadProvenance {
        workload_id: id.to_string(),
        name: format!("{id} fixture"),
        category,
        source: "tests/fixtures/benchmark-diagnostics".to_string(),
        pinned_version: "fixture-v1".to_string(),
        content_hash: ContentHash::compute(id.as_bytes()),
        provenance_epoch: epoch(7),
        tags: BTreeSet::from(["golden".to_string(), category.as_str().to_string()]),
    }
}

fn run(run_id: &str, workload_id: &str, duration_us: u64, iteration: u32) -> BenchmarkRun {
    BenchmarkRun {
        run_id: run_id.to_string(),
        workload_id: workload_id.to_string(),
        duration_us,
        peak_memory_bytes: 4_096,
        gc_pause_us: 12,
        is_warmup: false,
        iteration,
        environment: benchmark_environment(),
        run_epoch: epoch(8),
    }
}

fn parity(workload_id: &str, target: ParityTarget, ratio: u64) -> ParityVerdict {
    ParityVerdict {
        workload_id: workload_id.to_string(),
        target,
        output_equivalent: true,
        performance_ratio_millionths: ratio,
        behavioral_differences: 0,
        difference_details: Vec::new(),
        evidence_hash: ContentHash::compute(format!("{workload_id}:{target}").as_bytes()),
    }
}

fn benchmark_bundle() -> EvidenceBundle {
    let mut bundle = EvidenceBundle::new("benchmark-diagnostics-golden-v1".to_string(), epoch(8));
    bundle
        .add_provenance(workload("startup-smoke", WorkloadCategory::ColdStart))
        .expect("startup provenance should be accepted");
    bundle
        .add_provenance(workload("diagnostic-render", WorkloadCategory::Application))
        .expect("diagnostic provenance should be accepted");

    for (idx, duration) in [1_000_u64, 1_010, 1_020, 1_030, 1_040]
        .iter()
        .copied()
        .enumerate()
    {
        bundle
            .add_run(run(
                &format!("startup-{idx}"),
                "startup-smoke",
                duration,
                idx as u32,
            ))
            .expect("startup run should be accepted");
    }

    for (idx, duration) in [2_000_u64, 2_020, 2_040, 2_060, 2_080]
        .iter()
        .copied()
        .enumerate()
    {
        bundle
            .add_run(run(
                &format!("diagnostic-{idx}"),
                "diagnostic-render",
                duration,
                idx as u32,
            ))
            .expect("diagnostic run should be accepted");
    }

    bundle
        .add_parity_verdict(parity("startup-smoke", ParityTarget::NodeJs, 1_010_000))
        .expect("startup parity should be accepted");
    bundle
        .add_parity_verdict(parity("diagnostic-render", ParityTarget::NodeJs, 980_000))
        .expect("diagnostic parity should be accepted");
    bundle.seal().expect("bundle should seal");
    bundle
}

fn runtime_state() -> RuntimeStateInput {
    RuntimeStateInput {
        snapshot_timestamp_ns: 123_456_789,
        loaded_extensions: vec![
            RuntimeExtensionState {
                extension_id: "ext-zeta".to_string(),
                containment_state: ContainmentState::Running,
            },
            RuntimeExtensionState {
                extension_id: "ext-alpha".to_string(),
                containment_state: ContainmentState::Sandboxed,
            },
        ],
        active_policies: vec![
            "policy-runtime".to_string(),
            "policy-diagnostics".to_string(),
            "policy-runtime".to_string(),
        ],
        security_epoch: epoch(42),
        gc_pressure: vec![
            GcPressureSample {
                extension_id: "ext-zeta".to_string(),
                used_bytes: 768,
                budget_bytes: 1_024,
            },
            GcPressureSample {
                extension_id: "ext-alpha".to_string(),
                used_bytes: 1_536,
                budget_bytes: 1_024,
            },
        ],
        scheduler_lanes: vec![
            SchedulerLaneSample {
                lane: "ready".to_string(),
                queue_depth: 8,
                max_depth: 32,
                tasks_submitted: 144,
                tasks_scheduled: 140,
                tasks_completed: 132,
                tasks_timed_out: 2,
            },
            SchedulerLaneSample {
                lane: "io".to_string(),
                queue_depth: 3,
                max_depth: 12,
                tasks_submitted: 64,
                tasks_scheduled: 64,
                tasks_completed: 63,
                tasks_timed_out: 0,
            },
        ],
    }
}

fn golden_snapshot() -> BenchmarkDiagnosticsGolden {
    let bundle = benchmark_bundle();
    let config = BundleConfig::default();
    let runtime_diagnostics = collect_runtime_diagnostics(
        &runtime_state(),
        "trace-benchmark-diagnostics-golden",
        "decision-benchmark-diagnostics-golden",
        "policy-benchmark-diagnostics-golden",
    );
    let runtime_diagnostics_summary = render_diagnostics_summary(&runtime_diagnostics);

    BenchmarkDiagnosticsGolden {
        coverage_gap: "benchmark and runtime diagnostics output golden surface",
        benchmark_report: generate_report(&bundle, &config),
        runtime_diagnostics,
        runtime_diagnostics_summary,
    }
}

fn update_goldens_enabled() -> bool {
    std::env::var_os("UPDATE_GOLDENS").is_some()
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_RELATIVE_PATH)
}

#[test]
fn benchmark_and_runtime_diagnostics_outputs_match_golden() {
    let actual = format!(
        "{}\n",
        serde_json::to_string_pretty(&golden_snapshot()).expect("golden serialization should work")
    );

    if update_goldens_enabled() {
        std::fs::write(golden_path(), &actual).expect("golden update should write fixture");
    }

    assert_eq!(actual, EXPECTED);
}
