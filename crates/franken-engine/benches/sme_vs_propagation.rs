#![forbid(unsafe_code)]

//! Secure multi-execution versus label-propagation benchmark lane.
//!
//! The benchmark compares the shipped SME kernel/lockstep coordinator against
//! the existing IR2 flow lattice on the same workload classes. When
//! `SME_VS_PROPAGATION_REPORT_DIR` is set, the harness also writes a signed
//! JSON report plus the standard summary/events/fingerprint artifact files.

use std::env;
use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use frankenengine_engine::flow_lattice::{
    DataSource, FlowCheckResult, Ir2FlowLattice, LabelClass, SinkKind, assign_label, sink_clearance,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::secure_multi_execution_kernel::{
    HostcallInvocation, SecurityLevel, SmeHostcallKind,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, sign_preimage};
use frankenengine_engine::sme::lockstep_coordinator::{
    LockstepBarrierKind, LockstepInstruction, SmeLockstepCoordinator,
};
use serde::Serialize;

const REPORT_SCHEMA_VERSION: &str = "franken-engine.sme-vs-propagation-report.v1";
const REPORT_RUNS: usize = 10;

#[derive(Debug, Clone)]
struct Workload {
    id: &'static str,
    class: &'static str,
    instruction_count: u64,
    hostcall_count: u64,
    levels: Vec<SecurityLevel>,
    hostcall_kind: SmeHostcallKind,
    hostcall_caller: SecurityLevel,
    propagation_sources: Vec<DataSource>,
    propagation_sink: SinkKind,
}

#[derive(Debug, Clone, Serialize)]
struct StrategyMeasurement {
    duration_ns: u128,
    digest: String,
}

#[derive(Debug, Clone, Serialize)]
struct WorkloadMeasurement {
    workload_id: String,
    workload_class: String,
    instruction_count: u64,
    hostcall_count: u64,
    sme_runs: Vec<StrategyMeasurement>,
    propagation_runs: Vec<StrategyMeasurement>,
}

#[derive(Debug, Clone, Serialize)]
struct UnsignedReport {
    schema_version: String,
    generated_at_utc: String,
    benchmark: String,
    run_count_per_strategy: usize,
    methodology: Vec<String>,
    workloads: Vec<WorkloadMeasurement>,
}

#[derive(Debug, Clone, Serialize)]
struct SignedReport {
    unsigned_report: UnsignedReport,
    unsigned_report_hash: String,
    signing_key_id: String,
    verification_key: String,
    signature_hex: String,
}

fn workloads() -> Vec<Workload> {
    vec![
        Workload {
            id: "pure_cpu_four_level",
            class: "pure_cpu",
            instruction_count: 96,
            hostcall_count: 0,
            levels: SecurityLevel::all().iter().copied().collect(),
            hostcall_kind: SmeHostcallKind::ClockRead,
            hostcall_caller: SecurityLevel::Public,
            propagation_sources: vec![
                DataSource::Literal,
                DataSource::Computed {
                    input_labels: vec![LabelClass::Public, LabelClass::Internal],
                },
                DataSource::GeneralFileRead,
            ],
            propagation_sink: SinkKind::LoggingRedacted,
        },
        Workload {
            id: "hostcall_heavy_three_level",
            class: "hostcall_heavy",
            instruction_count: 72,
            hostcall_count: 24,
            levels: vec![
                SecurityLevel::Public,
                SecurityLevel::Internal,
                SecurityLevel::Confidential,
            ],
            hostcall_kind: SmeHostcallKind::FsRead,
            hostcall_caller: SecurityLevel::Internal,
            propagation_sources: vec![
                DataSource::EnvironmentVariable,
                DataSource::HostcallReturn {
                    clearance: frankenengine_engine::flow_lattice::Clearance::RestrictedSink,
                },
                DataSource::Computed {
                    input_labels: vec![LabelClass::Internal, LabelClass::Confidential],
                },
            ],
            propagation_sink: SinkKind::MetricsExport,
        },
        Workload {
            id: "real_runtime_hot_paths_four_level",
            class: "real_runtime_hot_paths",
            instruction_count: 128,
            hostcall_count: 16,
            levels: SecurityLevel::all().iter().copied().collect(),
            hostcall_kind: SmeHostcallKind::PolicyRequest,
            hostcall_caller: SecurityLevel::Public,
            propagation_sources: vec![
                DataSource::Literal,
                DataSource::PolicyProtectedArtifact,
                DataSource::GeneralFileRead,
                DataSource::Computed {
                    input_labels: vec![
                        LabelClass::Public,
                        LabelClass::Internal,
                        LabelClass::Confidential,
                    ],
                },
            ],
            propagation_sink: SinkKind::PersistenceExport,
        },
    ]
}

fn instruction(workload: &Workload, step: u64) -> LockstepInstruction {
    let id = format!("{}:{step:04}", workload.id);
    let opcode = format!(
        "{}:{}:{}",
        workload.class,
        workload.hostcall_count,
        step % 11
    );
    let input = format!(
        "{}:{}:{}",
        workload.instruction_count,
        workload.levels.len(),
        step
    );
    LockstepInstruction::new(id, opcode.as_bytes(), input.as_bytes())
}

fn hostcall_output(workload: &Workload, ordinal: u64) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        workload.id,
        workload.class,
        workload.hostcall_kind.stable_name(),
        ordinal
    )
    .into_bytes()
}

fn run_secure_multi_execution(workload: &Workload) -> ContentHash {
    let epoch = SecurityEpoch::from_raw(39);
    let mut coordinator = SmeLockstepCoordinator::new(workload.levels.iter().copied(), epoch)
        .expect("benchmark workload must configure at least one SME runtime");
    coordinator.register_standard_hostcalls();

    let mut digest_input = Vec::new();
    let mut emitted_hostcalls = 0_u64;
    let hostcall_interval = if workload.hostcall_count == 0 {
        u64::MAX
    } else {
        (workload.instruction_count / workload.hostcall_count).max(1)
    };

    for step in 0..workload.instruction_count {
        let should_emit_hostcall =
            emitted_hostcalls < workload.hostcall_count && step % hostcall_interval == 0;
        if should_emit_hostcall {
            let invocation_id = format!("{}:hostcall:{emitted_hostcalls:04}", workload.id);
            let invocation = HostcallInvocation::new(
                invocation_id,
                workload.hostcall_kind.clone(),
                workload.hostcall_caller,
                &step.to_be_bytes(),
            );
            let receipt = coordinator
                .execute_hostcall_at_barrier(
                    instruction(workload, step),
                    invocation,
                    hostcall_output(workload, emitted_hostcalls),
                )
                .expect("SME hostcall benchmark operation should execute");
            digest_input.extend_from_slice(receipt.lockstep.barrier_hash.as_bytes());
            digest_input.extend_from_slice(receipt.sme.receipt_hash.as_bytes());
            digest_input.extend_from_slice(&(receipt.sme.delivered_to.len() as u64).to_be_bytes());
            digest_input
                .extend_from_slice(&(receipt.sme.suppressed_from.len() as u64).to_be_bytes());
            emitted_hostcalls += 1;
        } else if step % 13 == 0 {
            let receipt = coordinator
                .synchronize_barrier(
                    format!("{}:sync:{step:04}", workload.id),
                    LockstepBarrierKind::Synchronization,
                )
                .expect("SME synchronization barrier should execute");
            digest_input.extend_from_slice(receipt.barrier_hash.as_bytes());
        } else {
            let receipt = coordinator
                .execute_instruction(instruction(workload, step))
                .expect("SME instruction benchmark operation should execute");
            digest_input.extend_from_slice(receipt.barrier_hash.as_bytes());
        }
    }

    digest_input.extend_from_slice(&(coordinator.runtime_count() as u64).to_be_bytes());
    digest_input.extend_from_slice(&(coordinator.step_count() as u64).to_be_bytes());
    digest_input.push(u8::from(coordinator.is_synchronized()));
    ContentHash::compute(&digest_input)
}

fn run_label_propagation(workload: &Workload) -> ContentHash {
    let mut lattice = Ir2FlowLattice::with_decision_id(
        format!("policy-sme-vs-propagation-{}", workload.id),
        format!("decision-sme-vs-propagation-{}", workload.id),
    );
    let sink = sink_clearance(&workload.propagation_sink);
    let mut current_label = LabelClass::Public;
    let mut digest_input = Vec::new();
    let mut legal = 0_u64;
    let mut declass = 0_u64;
    let mut blocked = 0_u64;

    for step in 0..workload.instruction_count {
        let source =
            &workload.propagation_sources[step as usize % workload.propagation_sources.len()];
        let source_label = assign_label(source);
        current_label = current_label.join(&source_label);
        digest_input.extend_from_slice(current_label.to_string().as_bytes());

        if workload.hostcall_count > 0 || step % 3 == 0 {
            let trace_id = format!("trace-sme-vs-propagation-{}-{step:04}", workload.id);
            match lattice.check_flow(&current_label, &sink, &trace_id) {
                FlowCheckResult::LegalByLattice => legal += 1,
                FlowCheckResult::RequiresDeclassification { obligation_id } => {
                    declass += 1;
                    digest_input.extend_from_slice(obligation_id.as_bytes());
                }
                FlowCheckResult::Blocked { source, sink } => {
                    blocked += 1;
                    digest_input.extend_from_slice(source.to_string().as_bytes());
                    digest_input.extend_from_slice(sink.to_string().as_bytes());
                }
            }
        }
    }

    digest_input.extend_from_slice(&legal.to_be_bytes());
    digest_input.extend_from_slice(&declass.to_be_bytes());
    digest_input.extend_from_slice(&blocked.to_be_bytes());
    digest_input.extend_from_slice(&(lattice.events().len() as u64).to_be_bytes());
    ContentHash::compute(&digest_input)
}

fn measure_strategy(
    workload: &Workload,
    strategy: fn(&Workload) -> ContentHash,
) -> StrategyMeasurement {
    let started = Instant::now();
    let digest = strategy(workload);
    StrategyMeasurement {
        duration_ns: started.elapsed().as_nanos(),
        digest: digest.to_hex(),
    }
}

fn build_unsigned_report(workloads: &[Workload]) -> UnsignedReport {
    let workload_reports = workloads
        .iter()
        .map(|workload| WorkloadMeasurement {
            workload_id: workload.id.to_string(),
            workload_class: workload.class.to_string(),
            instruction_count: workload.instruction_count,
            hostcall_count: workload.hostcall_count,
            sme_runs: (0..REPORT_RUNS)
                .map(|_| measure_strategy(workload, run_secure_multi_execution))
                .collect(),
            propagation_runs: (0..REPORT_RUNS)
                .map(|_| measure_strategy(workload, run_label_propagation))
                .collect(),
        })
        .collect();

    UnsignedReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        generated_at_utc: "2026-06-14T00:00:00Z".to_string(),
        benchmark: "sme_vs_propagation".to_string(),
        run_count_per_strategy: REPORT_RUNS,
        methodology: vec![
            "Criterion benchmark target: crates/franken-engine/benches/sme_vs_propagation.rs"
                .to_string(),
            "SME path uses SmeLockstepCoordinator plus SecureMultiExecutionKernel receipts"
                .to_string(),
            "Label-propagation path uses Ir2FlowLattice joins and sink flow checks".to_string(),
            "Three workload classes: pure_cpu, hostcall_heavy, real_runtime_hot_paths".to_string(),
        ],
        workloads: workload_reports,
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([0x39; 32]).expect("benchmark report signing key must be valid")
}

fn sign_report(unsigned_report: UnsignedReport) -> SignedReport {
    let unsigned_bytes =
        serde_json::to_vec(&unsigned_report).expect("unsigned SME report should serialize");
    let unsigned_report_hash = ContentHash::compute(&unsigned_bytes).to_hex();
    let key = signing_key();
    let signature = sign_preimage(&key, &unsigned_bytes)
        .expect("benchmark report signature should be produced");

    SignedReport {
        unsigned_report,
        unsigned_report_hash,
        signing_key_id: "sme-vs-propagation-benchmark-fixed-key-v1".to_string(),
        verification_key: key.verification_key().to_hex(),
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

fn write_report_artifacts(output_dir: &Path, report: &SignedReport) {
    fs::create_dir_all(output_dir).expect("SME benchmark artifact dir should be writable");

    let report_json =
        serde_json::to_string_pretty(report).expect("signed SME report should serialize");
    fs::write(output_dir.join("report.json"), report_json)
        .expect("signed SME report should be writable");

    let fingerprint = serde_json::json!({
        "schema_version": "franken-engine.artifact-fingerprint.v1",
        "bundle": "sme_vs_propagation",
        "report_hash": &report.unsigned_report_hash,
        "signature_hex": &report.signature_hex,
        "verification_key": &report.verification_key,
    });
    fs::write(
        output_dir.join("fingerprint.json"),
        serde_json::to_string_pretty(&fingerprint)
            .expect("SME benchmark fingerprint should serialize"),
    )
    .expect("SME benchmark fingerprint should be writable");

    let mut events = String::new();
    for workload in &report.unsigned_report.workloads {
        events.push_str(
            &serde_json::json!({
                "schema_version": "franken-engine.sme-vs-propagation-event.v1",
                "component": "sme_vs_propagation",
                "event": "workload_measured",
                "outcome": "pass",
                "workload_id": &workload.workload_id,
                "workload_class": &workload.workload_class,
                "sme_runs": workload.sme_runs.len(),
                "propagation_runs": workload.propagation_runs.len(),
            })
            .to_string(),
        );
        events.push('\n');
    }
    fs::write(output_dir.join("events.jsonl"), events)
        .expect("SME benchmark events should be writable");

    let summary = format!(
        "# SME vs Label-Propagation Benchmark Report\n\n\
         - Schema: `{}`\n\
         - Benchmark: `{}`\n\
         - Workload classes: pure_cpu, hostcall_heavy, real_runtime_hot_paths\n\
         - Runs per strategy per workload: `{}`\n\
         - Unsigned report hash: `{}`\n\
         - Verification key: `{}`\n\
         - Signature: `{}`\n",
        report.unsigned_report.schema_version,
        report.unsigned_report.benchmark,
        report.unsigned_report.run_count_per_strategy,
        report.unsigned_report_hash,
        report.verification_key,
        report.signature_hex
    );
    fs::write(output_dir.join("summary.md"), summary)
        .expect("SME benchmark summary should be writable");
}

fn maybe_emit_report(workloads: &[Workload]) {
    let Some(output_dir) = env::var_os("SME_VS_PROPAGATION_REPORT_DIR") else {
        return;
    };
    let unsigned = build_unsigned_report(workloads);
    let signed = sign_report(unsigned);
    write_report_artifacts(Path::new(&output_dir), &signed);
}

fn bench_sme_vs_propagation(c: &mut Criterion) {
    let workloads = workloads();
    maybe_emit_report(&workloads);

    for workload in &workloads {
        let mut group = c.benchmark_group(format!("sme_vs_propagation/{}", workload.id));
        group.sample_size(REPORT_RUNS);
        group.bench_with_input(
            BenchmarkId::new("secure_multi_execution", workload.class),
            workload,
            |b, workload| b.iter(|| black_box(run_secure_multi_execution(workload))),
        );
        group.bench_with_input(
            BenchmarkId::new("label_propagation", workload.class),
            workload,
            |b, workload| b.iter(|| black_box(run_label_propagation(workload))),
        );
        group.finish();
    }
}

criterion_group! {
    name = sme_vs_propagation;
    config = Criterion::default().sample_size(REPORT_RUNS);
    targets = bench_sme_vs_propagation
}
criterion_main!(sme_vs_propagation);
