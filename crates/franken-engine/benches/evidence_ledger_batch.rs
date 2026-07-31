//! Session-scale evidence-ledger signing benchmarks.
//!
//! Schema-v2 evidence entries are always authenticated individually. This
//! benchmark measures mandatory entry construction/signing and the additional
//! cost of wrapping those authenticated entries in a Merkle batch.

#![forbid(unsafe_code)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceEntry, EvidenceEntryBuilder,
    LabEvidenceAuthority, Witness,
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

fn entry_authority() -> LabEvidenceAuthority {
    LabEvidenceAuthority::deterministic_fixture(
        PRODUCER_ID,
        "evidence-ledger-batch-benchmark-v2",
        SecurityEpoch::from_raw(91),
    )
    .expect("benchmark lab authority must be valid")
}

fn entry_template(index: usize, authority: &LabEvidenceAuthority) -> EvidenceEntry {
    EvidenceEntryBuilder::new_with_lab_authority(
        format!("trace-evidence-batch-{index:04}"),
        format!("decision-evidence-batch-{index:04}"),
        "policy-evidence-batch",
        SecurityEpoch::from_raw(91),
        DecisionType::ContractEvaluation,
        authority,
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
    .expect("benchmark evidence entry should build")
}

fn authenticated_entries(count: usize, authority: &LabEvidenceAuthority) -> Vec<EvidenceEntry> {
    (0..count)
        .map(|index| entry_template(index, authority))
        .collect()
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
    let authority = entry_authority();
    let mut group = c.benchmark_group("evidence_ledger_per_entry");

    for count in BATCH_SIZES {
        group.bench_with_input(
            BenchmarkId::new("mandatory_entry_auth", count),
            &count,
            |b, _| {
                b.iter(|| black_box(authenticated_entries(count, &authority)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("additional_merkle_batch", count),
            &count,
            |b, _| {
                b.iter_batched(
                    || authenticated_entries(count, &authority),
                    |entries| black_box(sign_entries_as_merkle_batch(&entries, &key, count)),
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(evidence_ledger_batch, bench_evidence_ledger_batch_signing);
criterion_main!(evidence_ledger_batch);
