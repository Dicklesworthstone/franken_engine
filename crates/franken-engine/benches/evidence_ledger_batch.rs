//! Session-scale evidence-ledger signing benchmarks.
//!
//! The legacy path signs every evidence entry independently. The Merkle-batch
//! path signs one root over the same unsigned entries and emits inclusion
//! proofs, so this benchmark scales both paths over realistic batch sizes.

#![forbid(unsafe_code)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceEntry, EvidenceEntryBuilder, Witness,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::session_signing_batch::{BatchId, SessionSigningBatch};
use frankenengine_engine::signature_preimage::SigningKey;

const PRODUCER_ID: &str = "evidence-ledger-batch-bench";
const TIMESTAMP_NS: u64 = 1_800_000_000_000_000_000;
const BATCH_SIZES: [usize; 5] = [1, 10, 50, 100, 500];

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([0x5a; 32]).expect("benchmark signing key must be valid")
}

fn entry_template(index: usize) -> EvidenceEntry {
    let mut entry = EvidenceEntryBuilder::new(
        format!("trace-evidence-batch-{index:04}"),
        format!("decision-evidence-batch-{index:04}"),
        "policy-evidence-batch",
        SecurityEpoch::from_raw(91),
        DecisionType::ContractEvaluation,
    )
    .timestamp_ns(TIMESTAMP_NS + index as u64)
    .candidate(CandidateAction::new("publish-entry", 10_000))
    .candidate(CandidateAction::filtered(
        "reject-entry",
        900_000,
        "benchmark candidate retained for deterministic shape",
    ))
    .chosen(ChosenAction {
        action_name: "publish-entry".to_string(),
        expected_loss_millionths: 10_000,
        rationale: "session-scale signing benchmark".to_string(),
    })
    .witness(Witness {
        witness_id: format!("bench-witness-{index:04}"),
        witness_type: "cargo-bench".to_string(),
        value: "crates/franken-engine/benches/evidence_ledger_batch.rs".to_string(),
    })
    .meta("bead", "bd-o4cbn.9.5")
    .meta("batch_size_source", "criterion_input")
    .build()
    .expect("benchmark evidence entry should build");

    entry.signed_envelope = None;
    entry
}

fn unsigned_entries(count: usize) -> Vec<EvidenceEntry> {
    (0..count).map(entry_template).collect()
}

fn sign_entries_individually(entries: &[EvidenceEntry], key: &SigningKey) -> Vec<EvidenceEntry> {
    let mut signed = entries.to_vec();
    for entry in &mut signed {
        entry
            .sign_with(PRODUCER_ID, key)
            .expect("per-entry benchmark signature should succeed");
    }
    signed
}

fn sign_entries_as_merkle_batch(
    entries: &[EvidenceEntry],
    key: &SigningKey,
    count: usize,
) -> Vec<frankenengine_engine::session_signing_batch::MerkleSignedEnvelope> {
    let mut batch = SessionSigningBatch::new(
        PRODUCER_ID,
        key.clone(),
        BatchId::new(count as u128),
        ContentHash::compute(b"franken-engine.evidence-entry.batch-bench.v1"),
        TIMESTAMP_NS,
    );
    for entry in entries {
        batch.add_entry(entry.clone());
    }
    batch
        .finalize()
        .expect("merkle batch benchmark signature should succeed")
}

fn bench_evidence_ledger_batch_signing(c: &mut Criterion) {
    let key = signing_key();
    let mut group = c.benchmark_group("evidence_ledger_per_entry");

    for count in BATCH_SIZES {
        group.bench_with_input(BenchmarkId::new("per_entry_sig", count), &count, |b, _| {
            b.iter_batched(
                || unsigned_entries(count),
                |entries| black_box(sign_entries_individually(&entries, &key)),
                BatchSize::SmallInput,
            );
        });
        group.bench_with_input(BenchmarkId::new("merkle_batch", count), &count, |b, _| {
            b.iter_batched(
                || unsigned_entries(count),
                |entries| black_box(sign_entries_as_merkle_batch(&entries, &key, count)),
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(evidence_ledger_batch, bench_evidence_ledger_batch_signing);
criterion_main!(evidence_ledger_batch);
