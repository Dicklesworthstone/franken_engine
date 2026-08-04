#![forbid(unsafe_code)]

//! Bandwidth comparison benchmark: erasure-coded vs full-replication gossip
//! (`bd-cixqu.35.3`, Track II.3).
//!
//! Two things happen here:
//!
//! 1. **Criterion timing lanes** measure the real coding overhead — encoding a
//!    payload into shards and reconstructing it — so the "does the coding
//!    overhead exceed the transmission savings" question has a measured answer,
//!    not just an analytical one.
//! 2. When `ERASURE_VS_REPLICATION_REPORT_DIR` is set, the harness writes the
//!    signed, deterministic bandwidth-efficiency report plus the standard
//!    summary/events/fingerprint artifact files. The byte accounting lives in
//!    [`frankenengine_engine::erasure_bandwidth_accounting`] and is honest about
//!    the shipped XOR single-parity scheme — it never fabricates Reed–Solomon
//!    behavior.

use std::env;
use std::fs;
use std::hint::black_box;
use std::path::Path;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use frankenengine_engine::erasure_bandwidth_accounting::{
    BandwidthComparisonConfig, SignedBandwidthReport, build_signed_report,
};
use frankenengine_engine::fleet_immune_protocol::{
    ErasureCodingPlan, NodeId, encode_erasure_shards, reconstruct_erasure_payload,
};

/// Fleet sizes exercised by the Criterion timing lanes (a representative subset;
/// the full sweep lives in the emitted report).
const TIMING_FLEET_SIZES: [u64; 3] = [10, 100, 1000];
/// Payload sizes exercised by the Criterion timing lanes.
const TIMING_PAYLOAD_SIZES: [u64; 2] = [10_240, 1_048_576];

fn deterministic_payload(len: u64) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn encode(
    fleet_size: u64,
    payload: &[u8],
) -> Vec<frankenengine_engine::fleet_immune_protocol::ErasureShard> {
    let plan = ErasureCodingPlan::tuned(fleet_size as usize, 0);
    encode_erasure_shards(
        "bandwidth-set",
        NodeId::new("bandwidth-origin"),
        1,
        1_000_000,
        payload,
        plan,
    )
    .expect("tuned plan must encode")
}

fn write_report_artifacts(output_dir: &Path, report: &SignedBandwidthReport) {
    fs::create_dir_all(output_dir).expect("bandwidth benchmark artifact dir should be writable");

    let report_json =
        serde_json::to_string_pretty(report).expect("signed bandwidth report should serialize");
    fs::write(output_dir.join("report.json"), report_json)
        .expect("signed bandwidth report should be writable");

    let fingerprint = serde_json::json!({
        "schema_version": "franken-engine.artifact-fingerprint.v1",
        "bundle": "erasure_vs_replication",
        "report_hash": &report.report_hash,
        "signature_hex": &report.signature_hex,
        "verification_key": &report.verification_key,
    });
    fs::write(
        output_dir.join("fingerprint.json"),
        serde_json::to_string_pretty(&fingerprint)
            .expect("bandwidth benchmark fingerprint should serialize"),
    )
    .expect("bandwidth benchmark fingerprint should be writable");

    let mut events = String::new();
    for cell in &report.report.cells {
        events.push_str(
            &serde_json::json!({
                "schema_version": "franken-engine.erasure-bandwidth-event.v1",
                "component": "erasure_vs_replication",
                "event": "cell_measured",
                "outcome": "pass",
                "fleet_size": cell.fleet_size,
                "payload_bytes": cell.payload_bytes,
                "data_shards": cell.data_shards,
                "savings_ratio_millionths": cell.savings_ratio_millionths,
                "overhead_exceeds_savings": cell.overhead_exceeds_savings,
            })
            .to_string(),
        );
        events.push('\n');
    }
    fs::write(output_dir.join("events.jsonl"), events)
        .expect("bandwidth benchmark events should be writable");

    let summary = format!(
        "# Erasure vs Full-Replication Bandwidth Report\n\n\
         - Schema: `{}`\n\
         - Coding scheme: `{}` (fault tolerance: {} erasure)\n\
         - Cells: `{}`\n\
         - Report hash: `{}`\n\
         - Verification key: `{}`\n\
         - Signature: `{}`\n\n\
         Honest note: the shipped scheme is XOR single-parity; the \
         fault-tolerance-normalized savings ceiling is (k-1)/(2k) (~50%), not the \
         60-70% attributed to tunable Reed-Solomon.\n",
        report.report.schema_version,
        report.report.coding_scheme,
        report.report.scheme_fault_tolerance_erasures,
        report.report.cells.len(),
        report.report_hash,
        report.verification_key,
        report.signature_hex
    );
    fs::write(output_dir.join("summary.md"), summary)
        .expect("bandwidth benchmark summary should be writable");
}

fn maybe_emit_report() {
    let Some(output_dir) = env::var_os("ERASURE_VS_REPLICATION_REPORT_DIR") else {
        return;
    };
    let signed = build_signed_report(&BandwidthComparisonConfig::default())
        .expect("bandwidth report should build");
    write_report_artifacts(Path::new(&output_dir), &signed);
}

fn bench_erasure_vs_replication(c: &mut Criterion) {
    maybe_emit_report();

    for &payload_bytes in &TIMING_PAYLOAD_SIZES {
        let payload = deterministic_payload(payload_bytes);
        for &fleet_size in &TIMING_FLEET_SIZES {
            let mut group =
                c.benchmark_group(format!("erasure_vs_replication/payload_{payload_bytes}"));
            group.throughput(criterion::Throughput::Bytes(payload_bytes));

            // Erasure encode lane: split into shards + XOR parity.
            group.bench_with_input(
                BenchmarkId::new("erasure_encode", fleet_size),
                &fleet_size,
                |b, &fleet_size| b.iter(|| black_box(encode(fleet_size, black_box(&payload)))),
            );

            // Erasure reconstruct lane: rebuild the payload from the data shards.
            let shards = encode(fleet_size, &payload);
            let data: Vec<_> = shards.iter().filter(|s| s.is_data()).cloned().collect();
            group.bench_with_input(
                BenchmarkId::new("erasure_reconstruct", fleet_size),
                &data,
                |b, data| {
                    b.iter(|| black_box(reconstruct_erasure_payload(black_box(data)).unwrap()))
                },
            );

            // Full-replication lane: a single (1,1) copy of the whole payload.
            group.bench_with_input(
                BenchmarkId::new("full_replication_copy", fleet_size),
                &payload,
                |b, payload| {
                    let plan = ErasureCodingPlan::new(1, 1).unwrap();
                    b.iter(|| {
                        black_box(
                            encode_erasure_shards(
                                "bandwidth-set",
                                NodeId::new("bandwidth-origin"),
                                1,
                                1_000_000,
                                black_box(payload),
                                plan,
                            )
                            .unwrap(),
                        )
                    })
                },
            );

            group.finish();
        }
    }
}

criterion_group! {
    name = erasure_vs_replication;
    config = Criterion::default().sample_size(20);
    targets = bench_erasure_vs_replication
}
criterion_main!(erasure_vs_replication);
