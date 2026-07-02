#![forbid(unsafe_code)]
//! Integration tests for reconstruction-proof signed receipts (`bd-cixqu.35.2`).
//!
//! Covers the full Track-II reconstruction-receipt surface end to end:
//! generation via [`FleetProtocolState::reconstruct_gossip_payload_with_receipt`],
//! cross-node verification without access to the original data, parity-recovery
//! receipts, the append-only [`ReconstructionReceiptLedger`] audit ledger,
//! tamper detection across every committed field, serde persistence, and
//! deterministic content-hash stability. The committed schema contract is
//! `docs/schemas/reconstruction_receipt_v1.json`.

use frankenengine_engine::erasure_reconstruction_receipts::{
    RECONSTRUCTION_RECEIPT_SCHEMA_ID, ReceiptError, ReconstructionReceipt,
    ReconstructionReceiptLedger, XOR_SINGLE_PARITY_SCHEME, reconstruct_with_receipt,
};
use frankenengine_engine::fleet_immune_protocol::{
    ErasureCodingPlan, ErasureShard, ErasureShardRole, FleetProtocolState, GossipConfig, NodeId,
    encode_erasure_shards,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};

// ── helpers ────────────────────────────────────────────────────────────────

fn node(id: &str) -> NodeId {
    NodeId::new(id)
}

fn fresh_state(id: &str) -> FleetProtocolState {
    FleetProtocolState::new(node(id), GossipConfig::default())
}

fn encode(payload: &[u8], data_shards: u16, total_shards: u16, origin: &str) -> Vec<ErasureShard> {
    let plan = ErasureCodingPlan::new(data_shards, total_shards).unwrap();
    encode_erasure_shards(
        format!("set-{origin}"),
        node(origin),
        1_000,
        50_000,
        payload,
        plan,
    )
    .unwrap()
}

fn data_shards(shards: &[ErasureShard]) -> Vec<ErasureShard> {
    shards.iter().filter(|s| s.is_data()).cloned().collect()
}

fn drop_index(shards: &[ErasureShard], idx: u16) -> Vec<ErasureShard> {
    shards
        .iter()
        .filter(|s| s.shard_index != idx)
        .cloned()
        .collect()
}

// ── fleet-state integration ─────────────────────────────────────────────────

#[test]
fn fleet_state_reconstructs_and_signs_receipt() {
    let state = fresh_state("node-alpha");
    let shards = encode(b"fleet gossip evidence payload", 3, 4, "origin-a");
    let (payload, receipt) = state
        .reconstruct_gossip_payload_with_receipt(&data_shards(&shards), 60_000)
        .unwrap();
    assert_eq!(payload, b"fleet gossip evidence payload");
    assert_eq!(receipt.reconstructing_node, node("node-alpha"));
    assert_eq!(receipt.schema_id, RECONSTRUCTION_RECEIPT_SCHEMA_ID);
    assert_eq!(receipt.coding_scheme, XOR_SINGLE_PARITY_SCHEME);
    receipt.verify().unwrap();
}

#[test]
fn fleet_state_receipt_signer_is_local_node() {
    let state = fresh_state("node-bravo");
    let shards = encode(b"signer attribution", 2, 3, "origin-b");
    let (_p, receipt) = state
        .reconstruct_gossip_payload_with_receipt(&data_shards(&shards), 61_000)
        .unwrap();
    assert_eq!(receipt.signature.signer, node("node-bravo"));
    assert_eq!(receipt.reconstructing_node, receipt.signature.signer);
}

#[test]
fn fleet_state_reconstruct_is_read_only() {
    let state = fresh_state("node-charlie");
    let before = state.local_sequence;
    let shards = encode(b"read only check", 2, 3, "origin-c");
    let _ = state
        .reconstruct_gossip_payload_with_receipt(&data_shards(&shards), 62_000)
        .unwrap();
    assert_eq!(
        state.local_sequence, before,
        "reconstruction must not mutate state"
    );
}

#[test]
fn fleet_state_rejects_empty_shards() {
    let state = fresh_state("node-delta");
    let err = state
        .reconstruct_gossip_payload_with_receipt(&[], 63_000)
        .unwrap_err();
    assert_eq!(err, ReceiptError::EmptyShardSet);
}

// ── cross-node verification (no shards, no payload) ──────────────────────────

#[test]
fn other_node_verifies_receipt_without_shards() {
    let producer = fresh_state("producer");
    let shards = encode(b"cross-node verification payload", 3, 4, "origin-x");
    let (_p, receipt) = producer
        .reconstruct_gossip_payload_with_receipt(&data_shards(&shards), 64_000)
        .unwrap();
    // A different node holds only the receipt — no shards, no original data.
    let json = serde_json::to_string(&receipt).unwrap();
    let received: ReconstructionReceipt = serde_json::from_str(&json).unwrap();
    received
        .verify()
        .expect("independent node can verify receipt");
}

#[test]
fn cross_node_verification_survives_transport_round_trip() {
    let producer = fresh_state("producer-2");
    let shards = encode(b"transport round trip", 4, 5, "origin-y");
    let (_p, receipt) = producer
        .reconstruct_gossip_payload_with_receipt(&data_shards(&shards), 65_000)
        .unwrap();
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let received: ReconstructionReceipt = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(received, receipt);
    received.verify().unwrap();
}

// ── parity recovery ─────────────────────────────────────────────────────────

#[test]
fn recovery_receipt_records_recovered_index() {
    let shards = encode(b"recover a missing data shard end to end", 3, 4, "origin-r");
    let available = drop_index(&shards, 1);
    let (payload, receipt) = reconstruct_with_receipt(&available, node("recon"), 66_000).unwrap();
    assert_eq!(payload, b"recover a missing data shard end to end");
    assert_eq!(receipt.recovered_shard_index, Some(1));
    receipt.verify().unwrap();
    receipt.verify_against_shards(&available, true).unwrap();
}

#[test]
fn recovery_of_each_data_index_is_provable() {
    let payload = b"prove recovery of any single data slot works fine";
    for missing in 0u16..3 {
        let shards = encode(payload, 3, 4, "origin-each");
        let available = drop_index(&shards, missing);
        let (recovered, receipt) =
            reconstruct_with_receipt(&available, node("recon-each"), 67_000).unwrap();
        assert_eq!(recovered, payload);
        assert_eq!(receipt.recovered_shard_index, Some(missing));
        receipt.verify().unwrap();
    }
}

#[test]
fn two_missing_data_shards_yields_no_receipt() {
    let shards = encode(b"two gone", 4, 5, "origin-two");
    let available: Vec<ErasureShard> = shards
        .iter()
        .filter(|s| s.shard_index != 0 && s.shard_index != 1)
        .cloned()
        .collect();
    let err = reconstruct_with_receipt(&available, node("recon-two"), 68_000).unwrap_err();
    match err {
        ReceiptError::ReconstructionFailed { .. } => {}
        other => panic!("expected ReconstructionFailed, got {other:?}"),
    }
}

// ── verify_against_shards ────────────────────────────────────────────────────

#[test]
fn verify_against_shards_reconstructs_and_confirms_payload_hash() {
    let shards = encode(b"strong verification path", 3, 4, "origin-strong");
    let (_p, receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-s"), 69_000).unwrap();
    receipt.verify_against_shards(&shards, true).unwrap();
}

#[test]
fn verify_against_shards_detects_a_swapped_shard_set() {
    let shards_a = encode(b"payload A", 2, 3, "origin-a1");
    let shards_b = encode(b"payload B distinct", 2, 3, "origin-b1");
    let (_p, receipt) =
        reconstruct_with_receipt(&data_shards(&shards_a), node("recon-swap"), 70_000).unwrap();
    // Verifying against a different set's shards must fail.
    match receipt.verify_against_shards(&shards_b, false).unwrap_err() {
        ReceiptError::MissingShardForVerification { .. }
        | ReceiptError::ShardCommitmentMismatch { .. } => {}
        other => panic!("expected shard mismatch/missing, got {other:?}"),
    }
}

#[test]
fn verify_against_shards_detects_missing_committed_shard() {
    let shards = encode(b"missing committed shard", 3, 4, "origin-miss");
    let (_p, receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-miss"), 71_000).unwrap();
    let subset: Vec<ErasureShard> = shards
        .iter()
        .filter(|s| s.shard_index == 0)
        .cloned()
        .collect();
    match receipt.verify_against_shards(&subset, false).unwrap_err() {
        ReceiptError::MissingShardForVerification { .. } => {}
        other => panic!("expected MissingShardForVerification, got {other:?}"),
    }
}

#[test]
fn verify_against_shards_detects_corrupted_shard_payload() {
    let shards = encode(b"corrupted shard payload bytes", 3, 4, "origin-corrupt");
    let (_p, receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-corrupt"), 72_000).unwrap();
    let mut mutated = shards.clone();
    if let Some(b) = mutated[0].shard_payload.first_mut() {
        *b ^= 0xAA;
    }
    match receipt.verify_against_shards(&mutated, false).unwrap_err() {
        ReceiptError::ShardCommitmentMismatch { .. } => {}
        other => panic!("expected ShardCommitmentMismatch, got {other:?}"),
    }
}

// ── tamper detection (end to end) ────────────────────────────────────────────

#[test]
fn tampering_payload_hash_is_detected() {
    let shards = encode(b"tamper payload hash", 2, 3, "origin-tph");
    let (_p, mut receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-tph"), 73_000).unwrap();
    receipt.payload_hash = ContentHash::from_bytes([7u8; 32]);
    assert_eq!(
        receipt.verify().unwrap_err(),
        ReceiptError::CommitmentMismatch
    );
}

#[test]
fn tampering_plan_is_detected() {
    let shards = encode(b"tamper the coding plan", 3, 4, "origin-plan");
    let (_p, mut receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-plan"), 74_000).unwrap();
    receipt.plan = ErasureCodingPlan::new(2, 4).unwrap();
    // Structural check runs before commitment recompute; a plan that no longer
    // matches the contributions is rejected as inconsistent or a commitment
    // mismatch, never accepted.
    assert!(receipt.verify().is_err());
}

#[test]
fn tampering_reconstructing_node_is_detected() {
    let shards = encode(b"tamper reconstructing node", 2, 3, "origin-node");
    let (_p, mut receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-node"), 75_000).unwrap();
    receipt.reconstructing_node = node("impostor");
    // signer no longer equals reconstructing_node.
    assert_eq!(receipt.verify().unwrap_err(), ReceiptError::SignerMismatch);
}

#[test]
fn forging_signature_and_signer_still_fails_commitment_binding() {
    let shards = encode(b"forge both signer and signature", 2, 3, "origin-forge");
    let (_p, mut receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-forge"), 76_000).unwrap();
    // Attacker rewrites the reconstructing node and re-signs with that identity,
    // but cannot reproduce the original commitment which binds the true node.
    receipt.reconstructing_node = node("attacker");
    receipt.signature.signer = node("attacker");
    receipt.signature.hash =
        AuthenticityHash::compute_keyed(b"attacker", receipt.receipt_commitment.as_bytes());
    // The committed reconstructing_node no longer matches the fields, so the
    // recomputed commitment diverges.
    assert_eq!(
        receipt.verify().unwrap_err(),
        ReceiptError::CommitmentMismatch
    );
}

#[test]
fn tampering_contributing_shard_hash_is_detected() {
    let shards = encode(b"tamper a contributing shard hash", 3, 4, "origin-csh");
    let (_p, mut receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-csh"), 77_000).unwrap();
    receipt.contributing_shards[0].shard_hash = ContentHash::from_bytes([3u8; 32]);
    assert_eq!(
        receipt.verify().unwrap_err(),
        ReceiptError::CommitmentMismatch
    );
}

// ── audit ledger ─────────────────────────────────────────────────────────────

#[test]
fn ledger_accumulates_receipts_across_shard_sets() {
    let mut ledger = ReconstructionReceiptLedger::new();
    for i in 0u16..5 {
        let payload = format!("distinct payload number {i}");
        let shards = encode(payload.as_bytes(), 2, 3, &format!("origin-{i}"));
        let (_p, receipt) = reconstruct_with_receipt(
            &data_shards(&shards),
            node("recon-acc"),
            78_000 + u64::from(i),
        )
        .unwrap();
        assert!(ledger.record(receipt).unwrap());
    }
    assert_eq!(ledger.len(), 5);
    assert_eq!(ledger.receipts().len(), 5);
}

#[test]
fn ledger_dedups_identical_receipts_across_calls() {
    let shards = encode(b"ledger dedup end to end", 2, 3, "origin-dedup");
    let (_p, receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-dedup"), 79_000).unwrap();
    let mut ledger = ReconstructionReceiptLedger::new();
    assert!(ledger.record(receipt.clone()).unwrap());
    assert!(!ledger.record(receipt.clone()).unwrap());
    assert!(!ledger.record(receipt).unwrap());
    assert_eq!(ledger.len(), 1);
}

#[test]
fn ledger_rejects_unverifiable_receipt_and_stays_clean() {
    let shards = encode(b"ledger rejects bad receipt", 2, 3, "origin-bad");
    let (_p, mut receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-bad"), 80_000).unwrap();
    receipt.signature.hash = AuthenticityHash::compute_keyed(b"x", b"y");
    let mut ledger = ReconstructionReceiptLedger::new();
    assert!(ledger.record(receipt).is_err());
    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);
}

#[test]
fn ledger_summary_hash_is_order_sensitive_and_stable() {
    let make = |seed: &str, ts: u64| {
        let shards = encode(seed.as_bytes(), 2, 3, seed);
        reconstruct_with_receipt(&data_shards(&shards), node("recon-sum"), ts)
            .unwrap()
            .1
    };
    let r1 = make("aaa", 81_000);
    let r2 = make("bbb", 82_000);

    let mut ledger_a = ReconstructionReceiptLedger::new();
    ledger_a.record(r1.clone()).unwrap();
    ledger_a.record(r2.clone()).unwrap();

    let mut ledger_b = ReconstructionReceiptLedger::new();
    ledger_b.record(r2).unwrap();
    ledger_b.record(r1).unwrap();

    // Same receipts, different insertion order → different summary chain.
    assert_ne!(ledger_a.summary_hash(), ledger_b.summary_hash());
    // Stable for a fixed state.
    assert_eq!(ledger_a.summary_hash(), ledger_a.summary_hash());
}

#[test]
fn ledger_persists_and_reindexes() {
    let shards = encode(b"persist and reindex the ledger", 3, 4, "origin-persist");
    let (_p, receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-persist"), 83_000).unwrap();
    let mut ledger = ReconstructionReceiptLedger::new();
    ledger.record(receipt.clone()).unwrap();
    let summary_before = ledger.summary_hash();

    let json = serde_json::to_string(&ledger).unwrap();
    let mut restored: ReconstructionReceiptLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.len(), 1);
    assert_eq!(restored.summary_hash(), summary_before);
    // Every persisted receipt still verifies.
    for r in restored.receipts() {
        r.verify().unwrap();
    }
    restored.reindex();
    // Dedup semantics are restored post-reindex.
    assert!(!restored.record(receipt).unwrap());
    assert_eq!(restored.len(), 1);
}

#[test]
fn ledger_from_multiple_nodes_coexist() {
    let mut ledger = ReconstructionReceiptLedger::new();
    for who in ["node-1", "node-2", "node-3"] {
        let shards = encode(b"shared payload same bytes", 2, 3, "origin-shared");
        let state = fresh_state(who);
        let (_p, receipt) = state
            .reconstruct_gossip_payload_with_receipt(&data_shards(&shards), 84_000)
            .unwrap();
        assert!(ledger.record(receipt).unwrap());
    }
    // Same payload, distinct reconstructing nodes → distinct commitments.
    assert_eq!(ledger.len(), 3);
}

// ── determinism / content-hash stability ─────────────────────────────────────

#[test]
fn receipt_commitment_is_reproducible() {
    let shards = encode(b"reproducible commitment", 3, 4, "origin-repro");
    let (_p1, a) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-repro"), 85_000).unwrap();
    let (_p2, b) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-repro"), 85_000).unwrap();
    assert_eq!(a.receipt_commitment, b.receipt_commitment);
    assert_eq!(a.signature.hash, b.signature.hash);
    assert_eq!(a, b);
}

#[test]
fn recomputed_commitment_matches_stored() {
    let shards = encode(b"stored equals recomputed", 3, 4, "origin-eq");
    let (_p, receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-eq"), 86_000).unwrap();
    assert!(
        receipt
            .compute_commitment()
            .constant_time_eq(&receipt.receipt_commitment)
    );
}

#[test]
fn distinct_payloads_produce_distinct_commitments() {
    let s1 = encode(b"first distinct payload", 2, 3, "origin-d1");
    let s2 = encode(b"second distinct payload", 2, 3, "origin-d2");
    let (_a, r1) = reconstruct_with_receipt(&data_shards(&s1), node("recon-d"), 87_000).unwrap();
    let (_b, r2) = reconstruct_with_receipt(&data_shards(&s2), node("recon-d"), 87_000).unwrap();
    assert_ne!(r1.receipt_commitment, r2.receipt_commitment);
}

// ── varied fleet sizes & payloads ────────────────────────────────────────────

#[test]
fn scales_across_shard_counts_and_payload_sizes() {
    let sizes = [0usize, 1, 7, 64, 1000, 4096];
    let plans = [(1u16, 2u16), (2, 3), (3, 4), (4, 5), (8, 10)];
    for &size in &sizes {
        for &(k, n) in &plans {
            let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let shards = encode(&payload, k, n, "origin-scale");
            let (recovered, receipt) =
                reconstruct_with_receipt(&data_shards(&shards), node("recon-scale"), 88_000)
                    .unwrap();
            assert_eq!(recovered, payload, "size={size} k={k} n={n}");
            receipt
                .verify()
                .unwrap_or_else(|e| panic!("size={size} k={k} n={n}: {e}"));
            assert_eq!(receipt.payload_len as usize, size);
        }
    }
}

#[test]
fn large_payload_recovery_receipt_verifies() {
    let payload: Vec<u8> = (0..8192u32)
        .map(|i| (i.wrapping_mul(31) % 256) as u8)
        .collect();
    let shards = encode(&payload, 5, 6, "origin-large");
    let available = drop_index(&shards, 3);
    let (recovered, receipt) =
        reconstruct_with_receipt(&available, node("recon-large"), 89_000).unwrap();
    assert_eq!(recovered, payload);
    assert_eq!(receipt.recovered_shard_index, Some(3));
    receipt.verify_against_shards(&available, true).unwrap();
}

// ── boundary plans ───────────────────────────────────────────────────────────

#[test]
fn single_data_single_parity_end_to_end() {
    let shards = encode(b"k1 n2 end to end", 1, 2, "origin-k1");
    let (recovered, receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-k1"), 90_000).unwrap();
    assert_eq!(recovered, b"k1 n2 end to end");
    receipt.verify().unwrap();
    // Recover the single data shard from parity alone.
    let parity_only: Vec<ErasureShard> = shards.iter().filter(|s| s.is_parity()).cloned().collect();
    let (recovered2, receipt2) =
        reconstruct_with_receipt(&parity_only, node("recon-k1"), 90_500).unwrap();
    assert_eq!(recovered2, b"k1 n2 end to end");
    assert_eq!(receipt2.recovered_shard_index, Some(0));
    receipt2.verify().unwrap();
}

#[test]
fn no_parity_plan_end_to_end() {
    let shards = encode(b"k3 n3 all data", 3, 3, "origin-k3");
    assert!(shards.iter().all(|s| s.is_data()));
    let (recovered, receipt) = reconstruct_with_receipt(&shards, node("recon-k3"), 91_000).unwrap();
    assert_eq!(recovered, b"k3 n3 all data");
    assert_eq!(receipt.recovered_shard_index, None);
    assert_eq!(receipt.contributing_shards.len(), 3);
    receipt.verify().unwrap();
}

// ── schema contract ──────────────────────────────────────────────────────────

#[test]
fn schema_file_exists_and_declares_the_scheme() {
    let schema = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/schemas/reconstruction_receipt_v1.json"
    ))
    .expect("schema file present");
    let doc: serde_json::Value = serde_json::from_str(&schema).expect("schema parses");
    assert_eq!(
        doc["schema_version"],
        serde_json::Value::from(RECONSTRUCTION_RECEIPT_SCHEMA_ID)
    );
    assert_eq!(
        doc["coding_scheme"]["id"],
        serde_json::Value::from(XOR_SINGLE_PARITY_SCHEME)
    );
    assert_eq!(doc["bead_id"], serde_json::Value::from("bd-cixqu.35.2"));
}

// ── extension binding + unknown scheme/schema paths ──────────────────────────

#[test]
fn extension_fields_change_the_commitment() {
    let shards = encode(b"extension binding integration", 2, 3, "origin-ext");
    let (_p, mut receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-ext"), 92_000).unwrap();
    let base = receipt.receipt_commitment;
    receipt
        .extensions
        .insert("region".to_string(), "us-east".to_string());
    let updated = receipt.compute_commitment();
    assert_ne!(base, updated);
    // A receipt whose commitment predates the extension no longer verifies.
    assert_eq!(
        receipt.verify().unwrap_err(),
        ReceiptError::CommitmentMismatch
    );
}

#[test]
fn unknown_scheme_and_schema_are_rejected_end_to_end() {
    let shards = encode(b"scheme and schema guard", 2, 3, "origin-guard");
    let (_p, base) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-guard"), 93_000).unwrap();

    let mut wrong_scheme = base.clone();
    wrong_scheme.coding_scheme = "reed-solomon-gf256".to_string();
    assert!(matches!(
        wrong_scheme.verify().unwrap_err(),
        ReceiptError::UnknownScheme { .. }
    ));

    let mut wrong_schema = base;
    wrong_schema.schema_id = "some.other.schema.v9".to_string();
    assert!(matches!(
        wrong_schema.verify().unwrap_err(),
        ReceiptError::UnknownSchema { .. }
    ));
}

#[test]
fn contributing_shard_roles_are_consistent_with_indices() {
    let shards = encode(b"roles consistent with indices", 3, 4, "origin-roles");
    let available = drop_index(&shards, 0);
    let (_p, receipt) = reconstruct_with_receipt(&available, node("recon-roles"), 94_000).unwrap();
    for c in &receipt.contributing_shards {
        match c.role {
            ErasureShardRole::Data => assert!(c.shard_index < receipt.plan.data_shards),
            ErasureShardRole::Parity => assert!(c.shard_index >= receipt.plan.data_shards),
        }
    }
    receipt.verify().unwrap();
}

#[test]
fn duplicate_shards_in_input_do_not_double_commit() {
    let shards = encode(b"duplicate shards should collapse", 3, 4, "origin-dup");
    let mut with_dupes = data_shards(&shards);
    // Append an exact duplicate of shard 0.
    with_dupes.push(with_dupes[0].clone());
    let (payload, receipt) =
        reconstruct_with_receipt(&with_dupes, node("recon-dup"), 95_000).unwrap();
    assert_eq!(payload, b"duplicate shards should collapse");
    // The commitment lists each distinct index once.
    let mut indices: Vec<u16> = receipt
        .contributing_shards
        .iter()
        .map(|c| c.shard_index)
        .collect();
    let unique = {
        indices.sort_unstable();
        indices.dedup();
        indices.len()
    };
    assert_eq!(unique, receipt.contributing_shards.len());
    receipt.verify().unwrap();
}

#[test]
fn conflicting_duplicate_data_shard_is_rejected() {
    let shards = encode(b"conflicting duplicate is fatal", 3, 4, "origin-conflict");
    let mut tampered = data_shards(&shards);
    // Same index, different payload → reconstruction must fail, no receipt.
    let mut clash = tampered[0].clone();
    if let Some(b) = clash.shard_payload.first_mut() {
        *b ^= 0x01;
    }
    tampered.push(clash);
    let err = reconstruct_with_receipt(&tampered, node("recon-conflict"), 96_000).unwrap_err();
    match err {
        ReceiptError::ReconstructionFailed { .. } => {}
        other => panic!("expected ReconstructionFailed, got {other:?}"),
    }
}

#[test]
fn receipt_payload_len_matches_reconstructed_length() {
    for size in [0usize, 3, 40, 400] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 97) as u8).collect();
        let shards = encode(&payload, 2, 3, "origin-len");
        let (recovered, receipt) =
            reconstruct_with_receipt(&data_shards(&shards), node("recon-len"), 97_000).unwrap();
        assert_eq!(recovered.len(), size);
        assert_eq!(receipt.payload_len as usize, size);
    }
}

#[test]
fn payload_hash_binds_reconstructed_bytes() {
    let payload = b"payload hash binds these exact bytes strongly";
    let shards = encode(payload, 3, 4, "origin-bind");
    let (recovered, receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-bind"), 98_000).unwrap();
    assert!(
        ContentHash::compute(&recovered).constant_time_eq(&receipt.payload_hash),
        "receipt payload_hash must equal the hash of the reconstructed bytes"
    );
}

#[test]
fn receipt_json_is_self_describing_snake_case() {
    let shards = encode(b"self describing json", 2, 3, "origin-json");
    let (_p, receipt) =
        reconstruct_with_receipt(&data_shards(&shards), node("recon-json"), 99_000).unwrap();
    let value: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    for key in [
        "schema_id",
        "shard_set_id",
        "payload_hash",
        "payload_len",
        "coding_scheme",
        "plan",
        "contributing_shards",
        "recovered_shard_index",
        "reconstructing_node",
        "reconstruction_timestamp_ns",
        "receipt_commitment",
        "signature",
        "protocol_version",
        "extensions",
    ] {
        assert!(
            value.get(key).is_some(),
            "missing field {key} in receipt JSON"
        );
    }
}
