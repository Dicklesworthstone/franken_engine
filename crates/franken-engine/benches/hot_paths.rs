//! Real-runtime hot path performance benchmarks.
//!
//! These workloads intentionally exercise shipped FrankenEngine structures.
//! They are not claim-bearing external parity evidence, but they do provide
//! non-mock targets for local optimization and smoke validation.

#![forbid(unsafe_code)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use frankenengine_engine::baseline_interpreter::{LaneChoice, LaneRouter, Value};
use frankenengine_engine::benchmark_evidence_bundle::{
    BenchmarkRun, EnvironmentSnapshot, EvidenceBundle, WorkloadCategory, WorkloadProvenance,
    export_bundle_json,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, Constraint, DecisionType, EvidenceEmitter, EvidenceEntryBuilder,
    InMemoryLedger, Witness,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::iterator_protocol::{
    IterationKind, IterationTrace, IteratorResult, IteratorSymbolKind, IteratorValue,
    collect_spread_values, make_get_iterator_event, make_next_event, render_iteration_summary,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_engine::parser_arena::{ArenaBudget, ParserArena};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::transport_certificate_ledger::{
    ArtifactKind, HardwareCell, TransportCertificate, evaluate_transport,
};
use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine};

const REAL_RUNTIME_SOURCE: &str = r#"
const hotPathValue = 42;
hotPathValue;
"#;

fn parse_real_source() -> Ir0Module {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(
            REAL_RUNTIME_SOURCE,
            frankenengine_engine::ast::ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("real runtime hot-path source should parse");
    Ir0Module::from_syntax_tree(tree, "hot_paths_real_runtime.js")
}

fn real_runtime_parser_arena_digest() -> ContentHash {
    let ir0 = parse_real_source();
    let arena = ParserArena::from_syntax_tree(&ir0.tree, ArenaBudget::default())
        .expect("real parser arena materialization should succeed");
    let restored = arena
        .to_syntax_tree()
        .expect("parser arena should restore syntax tree");
    let mut hash_input = restored.canonical_bytes();
    hash_input.extend_from_slice(&arena.bytes_used().to_le_bytes());
    hash_input.extend_from_slice(&(arena.statement_handles().len() as u64).to_le_bytes());
    ContentHash::compute(&hash_input)
}

fn real_runtime_lowering_digest() -> ContentHash {
    let ir0 = parse_real_source();
    let context = LoweringContext::new(
        "trace-hot-path-lowering",
        "decision-hot-path-lowering",
        "policy-hot-path-lowering",
    );
    let output = lower_ir0_to_ir3(&ir0, &context).expect("real source should lower to IR3");
    let mut hash_input = output.ir3.canonical_bytes();
    hash_input.extend_from_slice(&(output.witnesses.len() as u64).to_le_bytes());
    hash_input.extend_from_slice(&(output.events.len() as u64).to_le_bytes());
    ContentHash::compute(&hash_input)
}

fn real_runtime_baseline_interpreter_digest() -> ContentHash {
    let mut quickjs = QuickJsInspiredNativeEngine;
    let quickjs_outcome = quickjs
        .eval(REAL_RUNTIME_SOURCE)
        .expect("quickjs-inspired native eval should execute");
    let mut v8 = V8InspiredNativeEngine;
    let v8_outcome = v8
        .eval(REAL_RUNTIME_SOURCE)
        .expect("v8-inspired native eval should execute");

    let ir0 = parse_real_source();
    let context = LoweringContext::new(
        "trace-hot-path-router",
        "decision-hot-path-router",
        "policy-hot-path-router",
    );
    let output = lower_ir0_to_ir3(&ir0, &context).expect("router workload should lower");
    let routed = LaneRouter::new()
        .execute(
            &output.ir3,
            "trace-hot-path-router",
            Some(LaneChoice::QuickJs),
        )
        .expect("lane router should execute lowered IR3");

    let digest_input = format!(
        "quickjs={};v8={};lane={};instructions={}",
        quickjs_outcome.value,
        v8_outcome.value,
        routed.lane.stable_label(),
        routed.result.instructions_executed
    );
    ContentHash::compute(digest_input.as_bytes())
}

fn baseline_value_string_clone_digest() -> ContentHash {
    let payload = "frankenengine-string-hot-path:".repeat(128);
    let values = (0..256)
        .map(|idx| Value::Str(format!("{payload}{idx}").into()))
        .collect::<Vec<_>>();

    let mut clones = Vec::with_capacity(values.len() * 32);
    for value in &values {
        for _ in 0..32 {
            clones.push(value.clone());
        }
    }

    let total_bytes = clones
        .iter()
        .map(|value| match value {
            Value::Str(text) => text.len(),
            _ => 0,
        })
        .sum::<usize>();
    ContentHash::compute(
        format!(
            "values={};clones={};bytes={}",
            values.len(),
            clones.len(),
            total_bytes
        )
        .as_bytes(),
    )
}

fn deterministic_object_id(seed: u8) -> EngineObjectId {
    EngineObjectId([seed; 32])
}

fn real_runtime_iterator_protocol_digest() -> ContentHash {
    let record_id = deterministic_object_id(1);
    let mut trace = IterationTrace::new(
        deterministic_object_id(2),
        record_id.clone(),
        IterationKind::ArraySpread,
    );
    trace.record_event(make_get_iterator_event(
        record_id.clone(),
        0,
        IteratorSymbolKind::Iterator,
        deterministic_object_id(3),
    ));
    for (step, value) in [11_i64, 13, 17, 19].into_iter().enumerate() {
        trace.record_event(make_next_event(
            record_id.clone(),
            step as u64 + 1,
            IteratorResult::value(IteratorValue::Integer(value)),
        ));
    }
    trace.record_event(make_next_event(record_id, 5, IteratorResult::done()));

    let values = collect_spread_values(&trace);
    let summary = render_iteration_summary(&trace);
    ContentHash::compute(format!("{}:{values:?}", summary).as_bytes())
}

fn real_runtime_scheduler_digest() -> ContentHash {
    use frankenengine_engine::deterministic_sim_scheduler::{
        SchedulerPolicy, SimEventKind, SimPriority, SimScheduler,
    };

    let policy = SchedulerPolicy {
        max_ticks: 128,
        max_events_per_tick: 16,
        drain_microtasks_first: true,
        gc_interval_ticks: 0,
        enable_timer_coalescing: true,
        deterministic_tie_break: true,
    };
    let mut scheduler = SimScheduler::new(policy, SecurityEpoch::from_raw(7));
    for i in 0..64_u64 {
        let priority = match i % 4 {
            0 => SimPriority::Microtask,
            1 => SimPriority::HighPriority,
            2 => SimPriority::Normal,
            _ => SimPriority::Idle,
        };
        let kind = match i % 3 {
            0 => SimEventKind::PromiseSettle,
            1 => SimEventKind::TimerFire,
            _ => SimEventKind::HostcallInvoke,
        };
        scheduler.schedule(kind, priority, i % 11, "hot-path-scheduler", i);
    }
    let summary = scheduler.run_to_completion();
    let replay_json = serde_json::to_string(&scheduler.replay_log)
        .expect("scheduler replay log should serialize");
    ContentHash::compute(
        format!(
            "ticks={};dispatched={};hash={};{}",
            summary.total_ticks, summary.total_events, summary.content_hash, replay_json
        )
        .as_bytes(),
    )
}

fn evidence_environment() -> EnvironmentSnapshot {
    EnvironmentSnapshot::new(
        "linux".to_string(),
        "deterministic-rch-worker".to_string(),
        8,
        16 * 1024 * 1024 * 1024,
        "frankenengine-native".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
        BTreeMap::from([
            ("bench".to_string(), "hot_paths".to_string()),
            ("mode".to_string(), "real_runtime".to_string()),
        ]),
    )
}

fn real_runtime_evidence_digest() -> ContentHash {
    let epoch = SecurityEpoch::from_raw(9);
    let mut ledger = InMemoryLedger::new();
    let entry = EvidenceEntryBuilder::new(
        "trace-hot-path-evidence",
        "decision-hot-path-evidence",
        "policy-hot-path-evidence",
        epoch,
        DecisionType::ContractEvaluation,
    )
    .timestamp_ns(1_700_000_000_000_000_001)
    .candidate(CandidateAction::new(
        "publish-real-runtime-hot-path",
        10_000,
    ))
    .candidate(CandidateAction::filtered(
        "publish-fixture-hot-path",
        900_000,
        "fixture workloads are not claim-bearing",
    ))
    .constraint(Constraint {
        constraint_id: "claim-bearing-workloads-must-be-real".to_string(),
        description: "hot-path evidence must execute shipped runtime code".to_string(),
        active: true,
    })
    .chosen(ChosenAction {
        action_name: "publish-real-runtime-hot-path".to_string(),
        expected_loss_millionths: 10_000,
        rationale: "real parser/lowering/eval/scheduler/evidence paths executed".to_string(),
    })
    .witness(Witness {
        witness_id: "hot-path-bench-target".to_string(),
        witness_type: "cargo-bench".to_string(),
        value: "crates/franken-engine/benches/hot_paths.rs".to_string(),
    })
    .meta("bead", "bd-t5k40.2")
    .build()
    .expect("evidence ledger entry should build");
    ledger
        .emit(entry)
        .expect("ledger should accept unique entry");

    let mut bundle = EvidenceBundle::new("hot-path-real-runtime-bundle".to_string(), epoch);
    let workload_id = "hot-path-real-runtime";
    bundle
        .add_provenance(WorkloadProvenance {
            workload_id: workload_id.to_string(),
            name: "Real runtime hot-path Criterion smoke".to_string(),
            category: WorkloadCategory::Micro,
            source: "crates/franken-engine/benches/hot_paths.rs".to_string(),
            pinned_version: "workspace-main".to_string(),
            content_hash: ContentHash::compute(REAL_RUNTIME_SOURCE.as_bytes()),
            provenance_epoch: epoch,
            tags: BTreeSet::from([
                "real-runtime".to_string(),
                "criterion".to_string(),
                "not-external-parity".to_string(),
            ]),
        })
        .expect("workload provenance should be unique");
    bundle
        .add_run(BenchmarkRun {
            run_id: "hot-path-real-runtime-run-0001".to_string(),
            workload_id: workload_id.to_string(),
            duration_us: 1,
            peak_memory_bytes: 0,
            gc_pause_us: 0,
            is_warmup: false,
            iteration: 1,
            environment: evidence_environment(),
            run_epoch: epoch,
        })
        .expect("benchmark run should reference provenance");

    let bundle_json = export_bundle_json(&bundle).expect("bundle should serialize");
    ContentHash::compute(
        format!(
            "ledger_entries={};bundle_hash={};{}",
            ledger.len(),
            bundle.bundle_hash,
            bundle_json
        )
        .as_bytes(),
    )
}

fn real_runtime_certificate_digest() -> ContentHash {
    let source = HardwareCell::new("rch-x86-source", "x86_64", "zen4", 256, 64);
    let target = HardwareCell::new("rch-x86-target", "x86_64", "zen4", 256, 64);
    let artifact_hash = ContentHash::compute(REAL_RUNTIME_SOURCE.as_bytes());
    let certificate = evaluate_transport(
        ArtifactKind::AotModule,
        artifact_hash,
        &source,
        &target,
        1_000_000,
        990_000,
    )
    .expect("transport certificate should evaluate");
    let json = serde_json::to_string(&certificate).expect("transport certificate should serialize");
    let decoded: TransportCertificate =
        serde_json::from_str(&json).expect("transport certificate should deserialize");
    ContentHash::compute(
        format!(
            "{}:{}:{}:{}",
            decoded.certificate_id, decoded.outcome, decoded.residual_fraction_millionths, json
        )
        .as_bytes(),
    )
}

fn bench_real_runtime_hot_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("real_runtime_hot_paths");

    group.bench_function("parser_arena_materialization", |b| {
        b.iter(|| black_box(real_runtime_parser_arena_digest()));
    });

    group.bench_function("lowering_pipeline_ir3", |b| {
        b.iter(|| black_box(real_runtime_lowering_digest()));
    });

    group.bench_function("baseline_interpreter_eval", |b| {
        b.iter(|| black_box(real_runtime_baseline_interpreter_digest()));
    });

    group.bench_function("baseline_value_string_clone", |b| {
        b.iter(|| black_box(baseline_value_string_clone_digest()));
    });

    group.bench_function("iterator_protocol_trace", |b| {
        b.iter(|| black_box(real_runtime_iterator_protocol_digest()));
    });

    group.bench_function("scheduler_queue_commit", |b| {
        b.iter(|| black_box(real_runtime_scheduler_digest()));
    });

    group.bench_function("evidence_ledger_bundle", |b| {
        b.iter(|| black_box(real_runtime_evidence_digest()));
    });

    group.bench_function("transport_certificate_serialization", |b| {
        b.iter(|| black_box(real_runtime_certificate_digest()));
    });

    group.finish();
}

criterion_group!(hot_paths, bench_real_runtime_hot_paths);
criterion_main!(hot_paths);
