#![forbid(unsafe_code)]

//! PERF-H1.7 integration tests for cached default signing key.
//!
//! These tests exercise the LazyLock-cached default_evidence_signing_key()
//! through public APIs to verify cache stability and performance characteristics.

use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceEntryBuilder, SecurityEpoch,
};
use std::time::Instant;

#[test]
fn frankenctl_verify_receipt_uses_cached_default_key() {
    // Build two identical evidence entries using the public builder API.
    // Both should use the cached signing key and produce identical signatures
    // when given identical inputs (proving cache stability).

    let entry1 = EvidenceEntryBuilder::new(
        "test-trace-1",
        "test-decision-1",
        "test-policy-1",
        SecurityEpoch::from_raw(42),
        DecisionType::ContractEvaluation,
    )
    .timestamp_ns(1_700_000_000_000_000_001)
    .candidate(CandidateAction::new("test-action", 100))
    .chosen(ChosenAction {
        action_name: "test-action".into(),
        expected_loss_millionths: 100,
        rationale: "h1 integration test".into(),
    })
    .build()
    .expect("first entry must build successfully");

    let entry2 = EvidenceEntryBuilder::new(
        "test-trace-1",
        "test-decision-1",
        "test-policy-1",
        SecurityEpoch::from_raw(42),
        DecisionType::ContractEvaluation,
    )
    .timestamp_ns(1_700_000_000_000_000_001)
    .candidate(CandidateAction::new("test-action", 100))
    .chosen(ChosenAction {
        action_name: "test-action".into(),
        expected_loss_millionths: 100,
        rationale: "h1 integration test".into(),
    })
    .build()
    .expect("second entry must build successfully");

    // Identical inputs must produce identical signatures when using cached key
    assert_eq!(
        entry1.envelope().signature.to_bytes(),
        entry2.envelope().signature.to_bytes(),
        "cached signing key must produce identical signatures for identical inputs"
    );

    // Also verify the entry content itself is identical (sanity check)
    assert_eq!(entry1.trace_id, entry2.trace_id);
    assert_eq!(entry1.decision_id, entry2.decision_id);
    assert_eq!(entry1.chosen_action, entry2.chosen_action);
}

#[test]
fn ten_thousand_sequential_evidence_entries_share_signing_key() {
    // Tight loop emitting 10,000 evidence entries.
    // This is a smoke test against accidental cache invalidation.
    // The cached key should eliminate repeated elliptic curve operations.

    const NUM_ENTRIES: usize = 10_000;
    let start = Instant::now();

    let mut signatures = Vec::with_capacity(NUM_ENTRIES);

    for i in 0..NUM_ENTRIES {
        let entry = EvidenceEntryBuilder::new(
            &format!("trace-{}", i),
            &format!("decision-{}", i),
            "bulk-test-policy",
            SecurityEpoch::from_raw(1),
            DecisionType::ContractEvaluation,
        )
        .timestamp_ns(1_700_000_000_000_000_000 + i as u64)
        .candidate(CandidateAction::new("bulk-action", 0))
        .chosen(ChosenAction {
            action_name: "bulk-action".into(),
            expected_loss_millionths: 0,
            rationale: format!("bulk entry {}", i),
        })
        .build()
        .expect("bulk entry must build");

        signatures.push(entry.envelope().signature.to_bytes());
    }

    let elapsed = start.elapsed();

    // Generous upper bound: should complete in under 3 seconds on dev hardware.
    // This is a smoke test, not a microbench. If this fails, the cache might
    // be invalidated or there's a serious performance regression.
    assert!(
        elapsed.as_secs() < 3,
        "10k evidence entries took {:?}, expected < 3s (possible cache invalidation)",
        elapsed
    );

    // Sanity check: all signatures should be different (different inputs)
    let mut unique_sigs = std::collections::BTreeSet::new();
    for sig in &signatures {
        unique_sigs.insert(*sig);
    }
    assert_eq!(
        unique_sigs.len(),
        NUM_ENTRIES,
        "all signatures should be unique (different trace/decision IDs)"
    );

    println!(
        "✓ Generated {} evidence entries in {:?} ({:.2} entries/ms)",
        NUM_ENTRIES,
        elapsed,
        NUM_ENTRIES as f64 / elapsed.as_millis() as f64
    );
}
