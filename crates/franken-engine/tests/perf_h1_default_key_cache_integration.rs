#![forbid(unsafe_code)]

//! PERF-H1.7 integration tests for prepared explicit signing authority reuse.
//!
//! The historical public default key no longer exists. These tests retain the
//! original hot-path contract while supplying one explicitly lab-scoped
//! authority for the full workload.

use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceAuthorityClass, EvidenceEntryBuilder,
    LabEvidenceAuthority,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::time::Instant;

#[test]
fn explicit_lab_authority_is_reused_across_entries() {
    let authority = LabEvidenceAuthority::deterministic_fixture(
        "perf-h1-explicit-authority",
        "perf-h1-explicit-authority-v2",
        SecurityEpoch::GENESIS,
    )
    .expect("lab authority");

    let entry1 = EvidenceEntryBuilder::new_with_lab_authority(
        "test-trace-1",
        "test-decision-1",
        "test-policy-1",
        SecurityEpoch::from_raw(42),
        DecisionType::ContractEvaluation,
        &authority,
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

    let entry2 = EvidenceEntryBuilder::new_with_lab_authority(
        "test-trace-1",
        "test-decision-1",
        "test-policy-1",
        SecurityEpoch::from_raw(42),
        DecisionType::ContractEvaluation,
        &authority,
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

    assert_eq!(entry1.signed_envelope(), entry2.signed_envelope());
    assert_eq!(
        entry1.signed_envelope().key_provenance.authority_class,
        EvidenceAuthorityClass::LabFixture
    );
    assert_eq!(entry1.trace_id, entry2.trace_id);
    assert_eq!(entry1.decision_id, entry2.decision_id);
    assert_eq!(entry1.chosen_action, entry2.chosen_action);
}

#[test]
fn ten_thousand_sequential_evidence_entries_share_explicit_authority() {
    // Tight loop emitting 10,000 evidence entries.
    // This is a smoke test against accidental key preparation on every entry.

    const NUM_ENTRIES: usize = 10_000;
    let authority = LabEvidenceAuthority::deterministic_fixture(
        "perf-h1-explicit-authority",
        "perf-h1-explicit-authority-v2",
        SecurityEpoch::GENESIS,
    )
    .expect("lab authority");
    let start = Instant::now();

    let mut entry_ids = Vec::with_capacity(NUM_ENTRIES);

    for i in 0..NUM_ENTRIES {
        let entry = EvidenceEntryBuilder::new_with_lab_authority(
            format!("trace-{}", i),
            format!("decision-{}", i),
            "bulk-test-policy",
            SecurityEpoch::from_raw(1),
            DecisionType::ContractEvaluation,
            &authority,
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

        assert!(
            !entry.signed_envelope().producer_id.is_empty(),
            "entry {i} must be signed by the explicit evidence producer"
        );
        entry_ids.push(entry.entry_id);
    }

    let elapsed = start.elapsed();

    // Generous upper bound: should complete in under 3 seconds on dev hardware.
    // This is a smoke test, not a microbench. If this fails, the authority may
    // be getting re-prepared or there is a serious performance regression.
    assert!(
        elapsed.as_secs() < 3,
        "10k evidence entries took {:?}, expected < 3s (possible authority re-preparation)",
        elapsed
    );

    let unique_entry_ids = entry_ids.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        unique_entry_ids.len(),
        NUM_ENTRIES,
        "all evidence entries should be unique (different trace/decision IDs)"
    );

    let entries_per_ms = NUM_ENTRIES as f64 / (elapsed.as_secs_f64().max(f64::EPSILON) * 1_000.0);
    println!(
        "✓ Generated {} evidence entries in {:?} ({:.2} entries/ms)",
        NUM_ENTRIES, elapsed, entries_per_ms
    );
}
