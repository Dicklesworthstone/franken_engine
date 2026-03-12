#![forbid(unsafe_code)]
//! Enrichment integration tests for `frankenengine_engine::evidence_replay_checker`.
//!
//! Covers all public types, enum variants, Display impls, serde roundtrips,
//! determinism properties, builder patterns, field access, workflows, error
//! conditions, and edge cases.  All test names are prefixed with `enrichment_`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::control_plane::{EvidenceLedger, EvidenceLedgerBuilder};
use frankenengine_engine::evidence_emission::{
    ActionCategory, CanonicalEvidenceEntry, EvidenceEntryId,
};
use frankenengine_engine::evidence_replay_checker::{
    DecisionReplayFn, EvidenceReplayChecker, PolicyVersionRecord, ReplayConfig, ReplayDiagnostics,
    ReplayErrorCode, ReplayEvent, ReplayEvidenceArtifact, ReplayManifest, ReplayResult,
    ReplayViolation, ReplayViolationType, ReplayedOutcome, SchemaMigrationRecord,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_ledger_entry(seq: u64) -> EvidenceLedger {
    EvidenceLedgerBuilder::new()
        .ts_unix_ms(1_700_000_000_000 + seq * 1000)
        .component("enrichment-component")
        .action(format!("action_{seq}"))
        .posterior(vec![0.7, 0.3])
        .expected_loss("allow", 0.1)
        .expected_loss("deny", 0.9)
        .chosen_expected_loss(0.1)
        .calibration_score(0.85)
        .fallback_active(false)
        .build()
        .expect("valid evidence")
}

fn compute_chain_hash(prev: Option<&ContentHash>, current: &ContentHash) -> ContentHash {
    let mut input = Vec::with_capacity(64);
    match prev {
        Some(p) => input.extend_from_slice(p.as_bytes()),
        None => input.extend_from_slice(b"genesis"),
    }
    input.extend_from_slice(current.as_bytes());
    ContentHash::compute(&input)
}

fn build_valid_entry(
    seq: u64,
    ts: u64,
    policy_id: &str,
    schema_version: &str,
    epoch: u64,
    prev_chain_hash: Option<&ContentHash>,
) -> CanonicalEvidenceEntry {
    let ledger = make_ledger_entry(seq);
    let payload = serde_json::to_vec(&ledger).unwrap();
    let artifact_hash = ContentHash::compute(&payload);
    let chain_hash = compute_chain_hash(prev_chain_hash, &artifact_hash);
    CanonicalEvidenceEntry {
        entry_id: EvidenceEntryId::new(format!("ev-{seq}")),
        sequence: seq,
        category: ActionCategory::DecisionContract,
        action_name: format!("action_{seq}"),
        trace_id: "trace-enrich".to_string(),
        decision_id: "dec-enrich".to_string(),
        policy_id: policy_id.to_string(),
        schema_version: schema_version.to_string(),
        ts_unix_ms: ts,
        epoch: SecurityEpoch::from_raw(epoch),
        artifact_hash,
        ledger_entry: ledger,
        chain_hash,
        metadata: BTreeMap::new(),
    }
}

fn build_ledger(n: usize) -> Vec<CanonicalEvidenceEntry> {
    let mut entries = Vec::with_capacity(n);
    let mut prev_chain: Option<ContentHash> = None;
    for i in 0..n {
        let ts = 1_700_000_000_000 + (i as u64) * 1000;
        let entry = build_valid_entry(i as u64, ts, "policy-v1", "1.0.0", 1, prev_chain.as_ref());
        prev_chain = Some(entry.chain_hash);
        entries.push(entry);
    }
    entries
}

fn build_ledger_with_traces(n: usize, traces: &[&str]) -> Vec<CanonicalEvidenceEntry> {
    let mut entries = build_ledger(n);
    for (i, entry) in entries.iter_mut().enumerate() {
        entry.trace_id = traces[i % traces.len()].to_string();
    }
    entries
}

fn build_ledger_with_decisions(n: usize, decisions: &[&str]) -> Vec<CanonicalEvidenceEntry> {
    let mut entries = build_ledger(n);
    for (i, entry) in entries.iter_mut().enumerate() {
        entry.decision_id = decisions[i % decisions.len()].to_string();
    }
    entries
}

fn identity_replay() -> DecisionReplayFn {
    Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
        action: entry.ledger_entry.action.clone(),
        chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
        calibration_score: entry.ledger_entry.calibration_score,
        fallback_active: entry.ledger_entry.fallback_active,
        expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
    })
}

fn diverging_action_replay() -> DecisionReplayFn {
    Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
        action: format!("WRONG_{}", entry.ledger_entry.action),
        chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
        calibration_score: entry.ledger_entry.calibration_score,
        fallback_active: entry.ledger_entry.fallback_active,
        expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
    })
}

fn make_violation(
    seq: u64,
    vtype: ReplayViolationType,
    ecode: ReplayErrorCode,
) -> ReplayViolation {
    ReplayViolation {
        sequence: seq,
        entry_id: format!("ev-{seq}"),
        violation_type: vtype,
        error_code: ecode,
        detail: "enrichment test violation".to_string(),
        expected: Some("expected_val".to_string()),
        actual: Some("actual_val".to_string()),
    }
}

// ===========================================================================
// ReplayErrorCode -- Display
// ===========================================================================

#[test]
fn enrichment_error_code_display_hash_mismatch() {
    assert_eq!(ReplayErrorCode::HashMismatch.to_string(), "HASH_MISMATCH");
}

#[test]
fn enrichment_error_code_display_chain_broken() {
    assert_eq!(ReplayErrorCode::ChainBroken.to_string(), "CHAIN_BROKEN");
}

#[test]
fn enrichment_error_code_display_entry_truncated() {
    assert_eq!(
        ReplayErrorCode::EntryTruncated.to_string(),
        "ENTRY_TRUNCATED"
    );
}

#[test]
fn enrichment_error_code_display_sequence_gap() {
    assert_eq!(ReplayErrorCode::SequenceGap.to_string(), "SEQUENCE_GAP");
}

#[test]
fn enrichment_error_code_display_timestamp_monotonicity() {
    assert_eq!(
        ReplayErrorCode::TimestampMonotonicityViolation.to_string(),
        "TIMESTAMP_MONOTONICITY_VIOLATION"
    );
}

#[test]
fn enrichment_error_code_display_outcome_divergence() {
    assert_eq!(
        ReplayErrorCode::OutcomeDivergence.to_string(),
        "OUTCOME_DIVERGENCE"
    );
}

#[test]
fn enrichment_error_code_display_calibration_divergence() {
    assert_eq!(
        ReplayErrorCode::CalibrationDivergence.to_string(),
        "CALIBRATION_DIVERGENCE"
    );
}

#[test]
fn enrichment_error_code_display_expected_loss_divergence() {
    assert_eq!(
        ReplayErrorCode::ExpectedLossDivergence.to_string(),
        "EXPECTED_LOSS_DIVERGENCE"
    );
}

#[test]
fn enrichment_error_code_display_fallback_divergence() {
    assert_eq!(
        ReplayErrorCode::FallbackDivergence.to_string(),
        "FALLBACK_DIVERGENCE"
    );
}

#[test]
fn enrichment_error_code_display_schema_migration_detected() {
    assert_eq!(
        ReplayErrorCode::SchemaMigrationDetected.to_string(),
        "SCHEMA_MIGRATION_DETECTED"
    );
}

#[test]
fn enrichment_error_code_display_policy_version_discontinuity() {
    assert_eq!(
        ReplayErrorCode::PolicyVersionDiscontinuity.to_string(),
        "POLICY_VERSION_DISCONTINUITY"
    );
}

#[test]
fn enrichment_error_code_display_epoch_regression() {
    assert_eq!(
        ReplayErrorCode::EpochRegression.to_string(),
        "EPOCH_REGRESSION"
    );
}

// ===========================================================================
// ReplayErrorCode -- serde per variant
// ===========================================================================

#[test]
fn enrichment_error_code_serde_hash_mismatch() {
    let v = ReplayErrorCode::HashMismatch;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_chain_broken() {
    let v = ReplayErrorCode::ChainBroken;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_entry_truncated() {
    let v = ReplayErrorCode::EntryTruncated;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_sequence_gap() {
    let v = ReplayErrorCode::SequenceGap;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_timestamp_monotonicity() {
    let v = ReplayErrorCode::TimestampMonotonicityViolation;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_outcome_divergence() {
    let v = ReplayErrorCode::OutcomeDivergence;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_calibration_divergence() {
    let v = ReplayErrorCode::CalibrationDivergence;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_expected_loss_divergence() {
    let v = ReplayErrorCode::ExpectedLossDivergence;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_fallback_divergence() {
    let v = ReplayErrorCode::FallbackDivergence;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_schema_migration_detected() {
    let v = ReplayErrorCode::SchemaMigrationDetected;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_policy_version_discontinuity() {
    let v = ReplayErrorCode::PolicyVersionDiscontinuity;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_error_code_serde_epoch_regression() {
    let v = ReplayErrorCode::EpochRegression;
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ===========================================================================
// ReplayErrorCode -- ordering
// ===========================================================================

#[test]
fn enrichment_error_code_ord_full_chain() {
    let ordered = [
        ReplayErrorCode::HashMismatch,
        ReplayErrorCode::ChainBroken,
        ReplayErrorCode::EntryTruncated,
        ReplayErrorCode::SequenceGap,
        ReplayErrorCode::TimestampMonotonicityViolation,
        ReplayErrorCode::OutcomeDivergence,
        ReplayErrorCode::CalibrationDivergence,
        ReplayErrorCode::ExpectedLossDivergence,
        ReplayErrorCode::FallbackDivergence,
        ReplayErrorCode::SchemaMigrationDetected,
        ReplayErrorCode::PolicyVersionDiscontinuity,
        ReplayErrorCode::EpochRegression,
    ];
    for w in ordered.windows(2) {
        assert!(w[0] < w[1], "{:?} should be < {:?}", w[0], w[1]);
    }
}

#[test]
fn enrichment_error_code_clone_eq() {
    let code = ReplayErrorCode::CalibrationDivergence;
    let cloned = code.clone();
    assert_eq!(code, cloned);
}

#[test]
fn enrichment_error_code_all_distinct_display_strings() {
    let codes = [
        ReplayErrorCode::HashMismatch,
        ReplayErrorCode::ChainBroken,
        ReplayErrorCode::EntryTruncated,
        ReplayErrorCode::SequenceGap,
        ReplayErrorCode::TimestampMonotonicityViolation,
        ReplayErrorCode::OutcomeDivergence,
        ReplayErrorCode::CalibrationDivergence,
        ReplayErrorCode::ExpectedLossDivergence,
        ReplayErrorCode::FallbackDivergence,
        ReplayErrorCode::SchemaMigrationDetected,
        ReplayErrorCode::PolicyVersionDiscontinuity,
        ReplayErrorCode::EpochRegression,
    ];
    let mut set = BTreeSet::new();
    for c in &codes {
        assert!(set.insert(c.to_string()), "duplicate: {c}");
    }
    assert_eq!(set.len(), 12);
}

// ===========================================================================
// ReplayViolationType -- Display per variant
// ===========================================================================

#[test]
fn enrichment_violation_type_display_outcome_divergence() {
    assert_eq!(
        ReplayViolationType::OutcomeDivergence.to_string(),
        "outcome_divergence"
    );
}

#[test]
fn enrichment_violation_type_display_artifact_hash_mismatch() {
    assert_eq!(
        ReplayViolationType::ArtifactHashMismatch.to_string(),
        "artifact_hash_mismatch"
    );
}

#[test]
fn enrichment_violation_type_display_chain_hash_mismatch() {
    assert_eq!(
        ReplayViolationType::ChainHashMismatch.to_string(),
        "chain_hash_mismatch"
    );
}

#[test]
fn enrichment_violation_type_display_sequence_gap() {
    assert_eq!(
        ReplayViolationType::SequenceGap.to_string(),
        "sequence_gap"
    );
}

#[test]
fn enrichment_violation_type_display_timestamp_monotonicity() {
    assert_eq!(
        ReplayViolationType::TimestampMonotonicityViolation.to_string(),
        "timestamp_monotonicity_violation"
    );
}

#[test]
fn enrichment_violation_type_display_entry_truncated() {
    assert_eq!(
        ReplayViolationType::EntryTruncated.to_string(),
        "entry_truncated"
    );
}

#[test]
fn enrichment_violation_type_display_calibration_divergence() {
    assert_eq!(
        ReplayViolationType::CalibrationDivergence.to_string(),
        "calibration_divergence"
    );
}

#[test]
fn enrichment_violation_type_display_expected_loss_divergence() {
    assert_eq!(
        ReplayViolationType::ExpectedLossDivergence.to_string(),
        "expected_loss_divergence"
    );
}

#[test]
fn enrichment_violation_type_display_fallback_divergence() {
    assert_eq!(
        ReplayViolationType::FallbackDivergence.to_string(),
        "fallback_divergence"
    );
}

#[test]
fn enrichment_violation_type_display_schema_migration() {
    assert_eq!(
        ReplayViolationType::SchemaMigration.to_string(),
        "schema_migration"
    );
}

#[test]
fn enrichment_violation_type_display_policy_version_change() {
    assert_eq!(
        ReplayViolationType::PolicyVersionChange.to_string(),
        "policy_version_change"
    );
}

#[test]
fn enrichment_violation_type_display_epoch_regression() {
    assert_eq!(
        ReplayViolationType::EpochRegression.to_string(),
        "epoch_regression"
    );
}

// ===========================================================================
// ReplayViolationType -- serde per variant
// ===========================================================================

#[test]
fn enrichment_violation_type_serde_all_twelve() {
    let types = [
        ReplayViolationType::OutcomeDivergence,
        ReplayViolationType::ArtifactHashMismatch,
        ReplayViolationType::ChainHashMismatch,
        ReplayViolationType::SequenceGap,
        ReplayViolationType::TimestampMonotonicityViolation,
        ReplayViolationType::EntryTruncated,
        ReplayViolationType::CalibrationDivergence,
        ReplayViolationType::ExpectedLossDivergence,
        ReplayViolationType::FallbackDivergence,
        ReplayViolationType::SchemaMigration,
        ReplayViolationType::PolicyVersionChange,
        ReplayViolationType::EpochRegression,
    ];
    for vt in &types {
        let json = serde_json::to_string(vt).unwrap();
        let back: ReplayViolationType = serde_json::from_str(&json).unwrap();
        assert_eq!(*vt, back);
    }
}

// ===========================================================================
// ReplayViolationType -- ordering
// ===========================================================================

#[test]
fn enrichment_violation_type_ord_full_chain() {
    let ordered = [
        ReplayViolationType::OutcomeDivergence,
        ReplayViolationType::ArtifactHashMismatch,
        ReplayViolationType::ChainHashMismatch,
        ReplayViolationType::SequenceGap,
        ReplayViolationType::TimestampMonotonicityViolation,
        ReplayViolationType::EntryTruncated,
        ReplayViolationType::CalibrationDivergence,
        ReplayViolationType::ExpectedLossDivergence,
        ReplayViolationType::FallbackDivergence,
        ReplayViolationType::SchemaMigration,
        ReplayViolationType::PolicyVersionChange,
        ReplayViolationType::EpochRegression,
    ];
    for w in ordered.windows(2) {
        assert!(w[0] < w[1], "{:?} should be < {:?}", w[0], w[1]);
    }
}

#[test]
fn enrichment_violation_type_all_distinct_display_strings() {
    let types = [
        ReplayViolationType::OutcomeDivergence,
        ReplayViolationType::ArtifactHashMismatch,
        ReplayViolationType::ChainHashMismatch,
        ReplayViolationType::SequenceGap,
        ReplayViolationType::TimestampMonotonicityViolation,
        ReplayViolationType::EntryTruncated,
        ReplayViolationType::CalibrationDivergence,
        ReplayViolationType::ExpectedLossDivergence,
        ReplayViolationType::FallbackDivergence,
        ReplayViolationType::SchemaMigration,
        ReplayViolationType::PolicyVersionChange,
        ReplayViolationType::EpochRegression,
    ];
    let mut set = BTreeSet::new();
    for vt in &types {
        assert!(set.insert(vt.to_string()), "duplicate: {vt}");
    }
    assert_eq!(set.len(), 12);
}

// ===========================================================================
// ReplayViolation -- serde and fields
// ===========================================================================

#[test]
fn enrichment_violation_serde_with_both_options_some() {
    let v = make_violation(
        42,
        ReplayViolationType::OutcomeDivergence,
        ReplayErrorCode::OutcomeDivergence,
    );
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
    assert_eq!(back.sequence, 42);
    assert_eq!(back.entry_id, "ev-42");
}

#[test]
fn enrichment_violation_serde_with_none_options() {
    let v = ReplayViolation {
        sequence: 0,
        entry_id: "ev-0".to_string(),
        violation_type: ReplayViolationType::ArtifactHashMismatch,
        error_code: ReplayErrorCode::HashMismatch,
        detail: "hash failed".to_string(),
        expected: None,
        actual: None,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayViolation = serde_json::from_str(&json).unwrap();
    assert!(back.expected.is_none());
    assert!(back.actual.is_none());
}

#[test]
fn enrichment_violation_clone_preserves_all_fields() {
    let v = make_violation(
        99,
        ReplayViolationType::EpochRegression,
        ReplayErrorCode::EpochRegression,
    );
    let cloned = v.clone();
    assert_eq!(v, cloned);
    assert_eq!(cloned.detail, "enrichment test violation");
}

#[test]
fn enrichment_violation_json_contains_expected_keys() {
    let v = make_violation(
        7,
        ReplayViolationType::SequenceGap,
        ReplayErrorCode::SequenceGap,
    );
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("sequence"));
    assert!(json.contains("entry_id"));
    assert!(json.contains("violation_type"));
    assert!(json.contains("error_code"));
    assert!(json.contains("detail"));
    assert!(json.contains("expected"));
    assert!(json.contains("actual"));
}

// ===========================================================================
// ReplayedOutcome -- serde and fields
// ===========================================================================

#[test]
fn enrichment_replayed_outcome_serde_roundtrip() {
    let mut losses = BTreeMap::new();
    losses.insert("allow".to_string(), 0.1);
    losses.insert("deny".to_string(), 0.9);
    let outcome = ReplayedOutcome {
        action: "allow".to_string(),
        chosen_expected_loss: 0.1,
        calibration_score: 0.85,
        fallback_active: false,
        expected_losses: losses,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ReplayedOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

#[test]
fn enrichment_replayed_outcome_empty_losses() {
    let outcome = ReplayedOutcome {
        action: "noop".to_string(),
        chosen_expected_loss: 0.0,
        calibration_score: 0.0,
        fallback_active: true,
        expected_losses: BTreeMap::new(),
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ReplayedOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
    assert!(back.fallback_active);
    assert!(back.expected_losses.is_empty());
}

#[test]
fn enrichment_replayed_outcome_many_actions() {
    let mut losses = BTreeMap::new();
    for i in 0..50 {
        losses.insert(format!("action_{i}"), (i as f64) * 0.01);
    }
    let outcome = ReplayedOutcome {
        action: "action_0".to_string(),
        chosen_expected_loss: 0.0,
        calibration_score: 0.5,
        fallback_active: false,
        expected_losses: losses.clone(),
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ReplayedOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back.expected_losses.len(), 50);
}

#[test]
fn enrichment_replayed_outcome_clone_eq() {
    let outcome = ReplayedOutcome {
        action: "a".to_string(),
        chosen_expected_loss: 1.5,
        calibration_score: 0.99,
        fallback_active: true,
        expected_losses: BTreeMap::new(),
    };
    assert_eq!(outcome, outcome.clone());
}

// ===========================================================================
// ReplayEvent -- serde and fields
// ===========================================================================

#[test]
fn enrichment_replay_event_serde_with_error_code() {
    let ev = ReplayEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "evidence-replay-checker".to_string(),
        event: "artifact_integrity_fail".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("HASH_MISMATCH".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: ReplayEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_replay_event_serde_without_error_code() {
    let ev = ReplayEvent {
        trace_id: "t-2".to_string(),
        decision_id: "d-2".to_string(),
        policy_id: "p-2".to_string(),
        component: "checker".to_string(),
        event: "replay_complete".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: ReplayEvent = serde_json::from_str(&json).unwrap();
    assert!(back.error_code.is_none());
}

#[test]
fn enrichment_replay_event_clone_eq() {
    let ev = ReplayEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: None,
    };
    assert_eq!(ev, ev.clone());
}

// ===========================================================================
// SchemaMigrationRecord -- serde and fields
// ===========================================================================

#[test]
fn enrichment_schema_migration_record_serde() {
    let rec = SchemaMigrationRecord {
        at_sequence: 100,
        from_version: "1.0.0".to_string(),
        to_version: "2.0.0".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: SchemaMigrationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn enrichment_schema_migration_record_clone_eq() {
    let rec = SchemaMigrationRecord {
        at_sequence: 0,
        from_version: "a".to_string(),
        to_version: "b".to_string(),
    };
    assert_eq!(rec, rec.clone());
}

#[test]
fn enrichment_schema_migration_record_json_fields() {
    let rec = SchemaMigrationRecord {
        at_sequence: 5,
        from_version: "v1".to_string(),
        to_version: "v2".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    assert!(json.contains("at_sequence"));
    assert!(json.contains("from_version"));
    assert!(json.contains("to_version"));
}

// ===========================================================================
// PolicyVersionRecord -- serde and fields
// ===========================================================================

#[test]
fn enrichment_policy_version_record_serde() {
    let rec = PolicyVersionRecord {
        at_sequence: 50,
        from_policy: "pol-v1".to_string(),
        to_policy: "pol-v2".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: PolicyVersionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn enrichment_policy_version_record_clone_eq() {
    let rec = PolicyVersionRecord {
        at_sequence: 0,
        from_policy: "a".to_string(),
        to_policy: "b".to_string(),
    };
    assert_eq!(rec, rec.clone());
}

// ===========================================================================
// ReplayConfig -- default, custom, serde
// ===========================================================================

#[test]
fn enrichment_config_default_calibration_tolerance() {
    let cfg = ReplayConfig::default();
    assert!((cfg.calibration_tolerance - 1e-9).abs() < 1e-15);
}

#[test]
fn enrichment_config_default_loss_tolerance() {
    let cfg = ReplayConfig::default();
    assert!((cfg.loss_tolerance - 1e-9).abs() < 1e-15);
}

#[test]
fn enrichment_config_default_allow_gaps_false() {
    assert!(!ReplayConfig::default().allow_gaps);
}

#[test]
fn enrichment_config_default_halt_on_first_false() {
    assert!(!ReplayConfig::default().halt_on_first);
}

#[test]
fn enrichment_config_default_progress_interval_1000() {
    assert_eq!(ReplayConfig::default().progress_interval, 1000);
}

#[test]
fn enrichment_config_default_track_schema_migrations_true() {
    assert!(ReplayConfig::default().track_schema_migrations);
}

#[test]
fn enrichment_config_default_track_policy_versions_true() {
    assert!(ReplayConfig::default().track_policy_versions);
}

#[test]
fn enrichment_config_default_detect_epoch_regression_true() {
    assert!(ReplayConfig::default().detect_epoch_regression);
}

#[test]
fn enrichment_config_default_policy_discontinuity_not_violation() {
    assert!(!ReplayConfig::default().policy_discontinuity_is_violation);
}

#[test]
fn enrichment_config_default_schema_migration_not_violation() {
    assert!(!ReplayConfig::default().schema_migration_is_violation);
}

#[test]
fn enrichment_config_default_allowed_policy_ids_empty() {
    assert!(ReplayConfig::default().allowed_policy_ids.is_empty());
}

#[test]
fn enrichment_config_serde_default() {
    let cfg = ReplayConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ReplayConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn enrichment_config_serde_custom_all_fields() {
    let mut ids = BTreeSet::new();
    ids.insert("p1".to_string());
    ids.insert("p2".to_string());
    ids.insert("p3".to_string());
    let cfg = ReplayConfig {
        calibration_tolerance: 0.05,
        loss_tolerance: 0.01,
        allow_gaps: true,
        halt_on_first: true,
        progress_interval: 500,
        track_schema_migrations: false,
        track_policy_versions: false,
        detect_epoch_regression: false,
        policy_discontinuity_is_violation: true,
        schema_migration_is_violation: true,
        allowed_policy_ids: ids,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ReplayConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
    assert_eq!(back.allowed_policy_ids.len(), 3);
}

#[test]
fn enrichment_config_clone_eq() {
    let cfg = ReplayConfig::default();
    assert_eq!(cfg, cfg.clone());
}

// ===========================================================================
// ReplayDiagnostics -- default, serde, fields
// ===========================================================================

#[test]
fn enrichment_diagnostics_default_is_empty() {
    let diag = ReplayDiagnostics::default();
    assert!(diag.schema_versions_seen.is_empty());
    assert!(diag.schema_migrations.is_empty());
    assert!(diag.policy_versions_seen.is_empty());
    assert!(diag.policy_transitions.is_empty());
    assert_eq!(diag.distinct_trace_ids, 0);
    assert_eq!(diag.distinct_decision_ids, 0);
    assert!(diag.first_ts.is_none());
    assert!(diag.last_ts.is_none());
    assert!(diag.epoch_range.is_none());
}

#[test]
fn enrichment_diagnostics_serde_default() {
    let diag = ReplayDiagnostics::default();
    let json = serde_json::to_string(&diag).unwrap();
    let back: ReplayDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn enrichment_diagnostics_serde_with_data() {
    let diag = ReplayDiagnostics {
        schema_versions_seen: ["1.0.0".to_string(), "2.0.0".to_string()]
            .into_iter()
            .collect(),
        schema_migrations: vec![SchemaMigrationRecord {
            at_sequence: 10,
            from_version: "1.0.0".to_string(),
            to_version: "2.0.0".to_string(),
        }],
        policy_versions_seen: ["pol-v1".to_string()].into_iter().collect(),
        policy_transitions: vec![PolicyVersionRecord {
            at_sequence: 5,
            from_policy: "pol-v1".to_string(),
            to_policy: "pol-v2".to_string(),
        }],
        distinct_trace_ids: 10,
        distinct_decision_ids: 3,
        first_ts: Some(1_700_000_000_000),
        last_ts: Some(1_700_000_010_000),
        epoch_range: Some((1, 5)),
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: ReplayDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn enrichment_diagnostics_clone_eq() {
    let diag = ReplayDiagnostics::default();
    assert_eq!(diag, diag.clone());
}

// ===========================================================================
// ReplayManifest -- serde and fields
// ===========================================================================

#[test]
fn enrichment_manifest_serde_passing() {
    let manifest = ReplayManifest {
        config: ReplayConfig::default(),
        source_entry_count: 100,
        first_entry_hash: Some(ContentHash::compute(b"first")),
        last_entry_hash: Some(ContentHash::compute(b"last")),
        final_rolling_hash: ContentHash::compute(b"rolling"),
        passed: true,
        violation_count: 0,
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ReplayManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn enrichment_manifest_serde_failing() {
    let manifest = ReplayManifest {
        config: ReplayConfig::default(),
        source_entry_count: 50,
        first_entry_hash: Some(ContentHash::compute(b"f")),
        last_entry_hash: Some(ContentHash::compute(b"l")),
        final_rolling_hash: ContentHash::compute(b"r"),
        passed: false,
        violation_count: 7,
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ReplayManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
    assert!(!back.passed);
    assert_eq!(back.violation_count, 7);
}

#[test]
fn enrichment_manifest_serde_empty_hashes() {
    let manifest = ReplayManifest {
        config: ReplayConfig::default(),
        source_entry_count: 0,
        first_entry_hash: None,
        last_entry_hash: None,
        final_rolling_hash: ContentHash::compute(b"empty"),
        passed: true,
        violation_count: 0,
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ReplayManifest = serde_json::from_str(&json).unwrap();
    assert!(back.first_entry_hash.is_none());
    assert!(back.last_entry_hash.is_none());
}

#[test]
fn enrichment_manifest_clone_eq() {
    let manifest = ReplayManifest {
        config: ReplayConfig::default(),
        source_entry_count: 1,
        first_entry_hash: None,
        last_entry_hash: None,
        final_rolling_hash: ContentHash::compute(b"x"),
        passed: true,
        violation_count: 0,
    };
    assert_eq!(manifest, manifest.clone());
}

// ===========================================================================
// ReplayEvidenceArtifact -- serde and fields
// ===========================================================================

#[test]
fn enrichment_artifact_serde_passing() {
    let artifact = ReplayEvidenceArtifact {
        manifest: ReplayManifest {
            config: ReplayConfig::default(),
            source_entry_count: 5,
            first_entry_hash: None,
            last_entry_hash: None,
            final_rolling_hash: ContentHash::compute(b"art"),
            passed: true,
            violation_count: 0,
        },
        diagnostics: ReplayDiagnostics::default(),
        violations: vec![],
        events: vec![],
        gate_passed: true,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: ReplayEvidenceArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
    assert!(back.gate_passed);
}

#[test]
fn enrichment_artifact_serde_with_violations_and_events() {
    let artifact = ReplayEvidenceArtifact {
        manifest: ReplayManifest {
            config: ReplayConfig::default(),
            source_entry_count: 3,
            first_entry_hash: None,
            last_entry_hash: None,
            final_rolling_hash: ContentHash::compute(b"f"),
            passed: false,
            violation_count: 2,
        },
        diagnostics: ReplayDiagnostics::default(),
        violations: vec![
            make_violation(
                0,
                ReplayViolationType::OutcomeDivergence,
                ReplayErrorCode::OutcomeDivergence,
            ),
            make_violation(
                1,
                ReplayViolationType::SequenceGap,
                ReplayErrorCode::SequenceGap,
            ),
        ],
        events: vec![ReplayEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "replay_complete".to_string(),
            outcome: "fail".to_string(),
            error_code: None,
        }],
        gate_passed: false,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: ReplayEvidenceArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
    assert!(!back.gate_passed);
    assert_eq!(back.violations.len(), 2);
    assert_eq!(back.events.len(), 1);
}

// ===========================================================================
// ReplayResult -- serde, methods, queries
// ===========================================================================

#[test]
fn enrichment_result_serde_roundtrip_passing() {
    let result = ReplayResult {
        entries_processed: 10,
        entries_skipped: 0,
        violations: vec![],
        passed: true,
        final_rolling_hash: ContentHash::compute(b"rr"),
        epoch: SecurityEpoch::from_raw(1),
        diagnostics: ReplayDiagnostics::default(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_result_serde_roundtrip_failing() {
    let result = ReplayResult {
        entries_processed: 5,
        entries_skipped: 2,
        violations: vec![make_violation(
            3,
            ReplayViolationType::EpochRegression,
            ReplayErrorCode::EpochRegression,
        )],
        passed: false,
        final_rolling_hash: ContentHash::compute(b"fail"),
        epoch: SecurityEpoch::from_raw(42),
        diagnostics: ReplayDiagnostics::default(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_result_violation_counts_empty() {
    let result = ReplayResult {
        entries_processed: 0,
        entries_skipped: 0,
        violations: vec![],
        passed: true,
        final_rolling_hash: ContentHash::compute(b"e"),
        epoch: SecurityEpoch::from_raw(0),
        diagnostics: ReplayDiagnostics::default(),
    };
    assert!(result.violation_counts().is_empty());
}

#[test]
fn enrichment_result_violation_counts_multiple_types() {
    let result = ReplayResult {
        entries_processed: 10,
        entries_skipped: 0,
        violations: vec![
            make_violation(0, ReplayViolationType::OutcomeDivergence, ReplayErrorCode::OutcomeDivergence),
            make_violation(1, ReplayViolationType::OutcomeDivergence, ReplayErrorCode::OutcomeDivergence),
            make_violation(2, ReplayViolationType::SequenceGap, ReplayErrorCode::SequenceGap),
            make_violation(3, ReplayViolationType::EpochRegression, ReplayErrorCode::EpochRegression),
            make_violation(4, ReplayViolationType::EpochRegression, ReplayErrorCode::EpochRegression),
            make_violation(5, ReplayViolationType::EpochRegression, ReplayErrorCode::EpochRegression),
        ],
        passed: false,
        final_rolling_hash: ContentHash::compute(b"m"),
        epoch: SecurityEpoch::from_raw(1),
        diagnostics: ReplayDiagnostics::default(),
    };
    let counts = result.violation_counts();
    assert_eq!(counts[&ReplayViolationType::OutcomeDivergence], 2);
    assert_eq!(counts[&ReplayViolationType::SequenceGap], 1);
    assert_eq!(counts[&ReplayViolationType::EpochRegression], 3);
}

#[test]
fn enrichment_result_has_violation_true() {
    let result = ReplayResult {
        entries_processed: 1,
        entries_skipped: 0,
        violations: vec![make_violation(
            0,
            ReplayViolationType::FallbackDivergence,
            ReplayErrorCode::FallbackDivergence,
        )],
        passed: false,
        final_rolling_hash: ContentHash::compute(b"x"),
        epoch: SecurityEpoch::from_raw(0),
        diagnostics: ReplayDiagnostics::default(),
    };
    assert!(result.has_violation(&ReplayViolationType::FallbackDivergence));
    assert!(!result.has_violation(&ReplayViolationType::SequenceGap));
}

#[test]
fn enrichment_result_has_error_code_true() {
    let result = ReplayResult {
        entries_processed: 1,
        entries_skipped: 0,
        violations: vec![make_violation(
            0,
            ReplayViolationType::CalibrationDivergence,
            ReplayErrorCode::CalibrationDivergence,
        )],
        passed: false,
        final_rolling_hash: ContentHash::compute(b"x"),
        epoch: SecurityEpoch::from_raw(0),
        diagnostics: ReplayDiagnostics::default(),
    };
    assert!(result.has_error_code(&ReplayErrorCode::CalibrationDivergence));
    assert!(!result.has_error_code(&ReplayErrorCode::HashMismatch));
}

#[test]
fn enrichment_result_violations_at_multiple_at_same_seq() {
    let result = ReplayResult {
        entries_processed: 3,
        entries_skipped: 0,
        violations: vec![
            make_violation(1, ReplayViolationType::OutcomeDivergence, ReplayErrorCode::OutcomeDivergence),
            make_violation(1, ReplayViolationType::CalibrationDivergence, ReplayErrorCode::CalibrationDivergence),
            make_violation(2, ReplayViolationType::SequenceGap, ReplayErrorCode::SequenceGap),
        ],
        passed: false,
        final_rolling_hash: ContentHash::compute(b"va"),
        epoch: SecurityEpoch::from_raw(0),
        diagnostics: ReplayDiagnostics::default(),
    };
    let at1 = result.violations_at(1);
    assert_eq!(at1.len(), 2);
    let at2 = result.violations_at(2);
    assert_eq!(at2.len(), 1);
    let at99 = result.violations_at(99);
    assert!(at99.is_empty());
}

#[test]
fn enrichment_result_manifest_from_empty_ledger() {
    let result = ReplayResult {
        entries_processed: 0,
        entries_skipped: 0,
        violations: vec![],
        passed: true,
        final_rolling_hash: ContentHash::compute(b"evidence-genesis"),
        epoch: SecurityEpoch::from_raw(0),
        diagnostics: ReplayDiagnostics::default(),
    };
    let config = ReplayConfig::default();
    let manifest = result.manifest(&config, &[]);
    assert!(manifest.passed);
    assert_eq!(manifest.source_entry_count, 0);
    assert_eq!(manifest.violation_count, 0);
    assert!(manifest.first_entry_hash.is_none());
    assert!(manifest.last_entry_hash.is_none());
}

#[test]
fn enrichment_result_manifest_captures_hashes() {
    let ledger = build_ledger(5);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    let config = ReplayConfig::default();
    let manifest = result.manifest(&config, &ledger);
    assert!(manifest.first_entry_hash.is_some());
    assert!(manifest.last_entry_hash.is_some());
    assert_ne!(manifest.first_entry_hash, manifest.last_entry_hash);
    assert_eq!(manifest.source_entry_count, 5);
    assert_eq!(manifest.final_rolling_hash, result.final_rolling_hash);
}

// ===========================================================================
// EvidenceReplayChecker -- construction
// ===========================================================================

#[test]
fn enrichment_checker_new_default_config() {
    let checker = EvidenceReplayChecker::new(ReplayConfig::default());
    assert_eq!(*checker.config(), ReplayConfig::default());
    assert!(checker.events().is_empty());
}

#[test]
fn enrichment_checker_set_epoch() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.set_epoch(SecurityEpoch::from_raw(42));
    let result = checker.replay(&[], None);
    assert_eq!(result.epoch, SecurityEpoch::from_raw(42));
}

#[test]
fn enrichment_checker_serde_roundtrip() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.set_epoch(SecurityEpoch::from_raw(99));
    let json = serde_json::to_string(&checker).unwrap();
    let back: EvidenceReplayChecker = serde_json::from_str(&json).unwrap();
    assert_eq!(checker.config(), back.config());
}

#[test]
fn enrichment_checker_config_accessor() {
    let cfg = ReplayConfig {
        progress_interval: 777,
        ..ReplayConfig::default()
    };
    let checker = EvidenceReplayChecker::new(cfg.clone());
    assert_eq!(checker.config().progress_interval, 777);
}

// ===========================================================================
// EvidenceReplayChecker -- empty ledger
// ===========================================================================

#[test]
fn enrichment_checker_empty_ledger_passes_structural() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&[], None);
    assert!(result.passed);
    assert_eq!(result.entries_processed, 0);
    assert_eq!(result.entries_skipped, 0);
    assert!(result.violations.is_empty());
}

#[test]
fn enrichment_checker_empty_ledger_passes_with_replay() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let replay = identity_replay();
    let result = checker.replay(&[], Some(&replay));
    assert!(result.passed);
}

// ===========================================================================
// EvidenceReplayChecker -- single entry
// ===========================================================================

#[test]
fn enrichment_checker_single_entry_structural() {
    let ledger = build_ledger(1);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.passed);
    assert_eq!(result.entries_processed, 1);
}

#[test]
fn enrichment_checker_single_entry_with_replay() {
    let ledger = build_ledger(1);
    let replay = identity_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(result.passed);
}

// ===========================================================================
// EvidenceReplayChecker -- valid ledger
// ===========================================================================

#[test]
fn enrichment_checker_valid_five_entries() {
    let ledger = build_ledger(5);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.passed);
    assert_eq!(result.entries_processed, 5);
    assert_eq!(result.violations.len(), 0);
}

#[test]
fn enrichment_checker_valid_ledger_identity_replay() {
    let ledger = build_ledger(10);
    let replay = identity_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(result.passed);
    assert_eq!(result.entries_processed, 10);
}

// ===========================================================================
// Artifact hash tamper
// ===========================================================================

#[test]
fn enrichment_tampered_artifact_detected() {
    let mut ledger = build_ledger(3);
    ledger[1].ledger_entry.ts_unix_ms = 999;
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.has_violation(&ReplayViolationType::ArtifactHashMismatch));
    assert!(result.has_error_code(&ReplayErrorCode::HashMismatch));
}

#[test]
fn enrichment_tampered_artifact_violation_detail() {
    let mut ledger = build_ledger(3);
    ledger[0].ledger_entry.ts_unix_ms = 1;
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    let v = result
        .violations
        .iter()
        .find(|v| v.violation_type == ReplayViolationType::ArtifactHashMismatch)
        .unwrap();
    assert_eq!(v.sequence, 0);
    assert!(!v.detail.is_empty());
}

// ===========================================================================
// Chain hash tamper
// ===========================================================================

#[test]
fn enrichment_tampered_chain_hash_detected() {
    let mut ledger = build_ledger(3);
    ledger[1].chain_hash = ContentHash::compute(b"tampered-chain");
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.has_violation(&ReplayViolationType::ChainHashMismatch));
    assert!(result.has_error_code(&ReplayErrorCode::ChainBroken));
}

// ===========================================================================
// Sequence gap
// ===========================================================================

#[test]
fn enrichment_sequence_gap_detected() {
    let mut ledger = build_ledger(3);
    ledger[1].sequence = 5;
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.has_violation(&ReplayViolationType::SequenceGap));
    let gap_v = result
        .violations
        .iter()
        .find(|v| v.violation_type == ReplayViolationType::SequenceGap)
        .unwrap();
    assert_eq!(gap_v.expected.as_deref(), Some("1"));
    assert_eq!(gap_v.actual.as_deref(), Some("5"));
}

#[test]
fn enrichment_sequence_gap_allowed_skips_counted() {
    let mut ledger = build_ledger(3);
    ledger[1].sequence = 5;
    let config = ReplayConfig {
        allow_gaps: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::SequenceGap));
    assert_eq!(result.entries_skipped, 4);
}

#[test]
fn enrichment_sequence_gap_backward_detected() {
    let mut ledger = build_ledger(3);
    ledger[1].sequence = 0; // backward
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
}

// ===========================================================================
// Timestamp monotonicity
// ===========================================================================

#[test]
fn enrichment_timestamp_regression_detected() {
    let mut ledger = build_ledger(3);
    ledger[2].ts_unix_ms = ledger[0].ts_unix_ms - 1;
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.has_violation(&ReplayViolationType::TimestampMonotonicityViolation));
}

#[test]
fn enrichment_timestamp_equal_allowed() {
    let mut ledger = build_ledger(3);
    let same_ts = ledger[0].ts_unix_ms;
    ledger[1].ts_unix_ms = same_ts;
    ledger[2].ts_unix_ms = same_ts;
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::TimestampMonotonicityViolation));
}

#[test]
fn enrichment_all_zero_timestamps_no_violation() {
    let mut ledger = build_ledger(3);
    for e in &mut ledger {
        e.ts_unix_ms = 0;
    }
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::TimestampMonotonicityViolation));
}

// ===========================================================================
// Outcome divergence
// ===========================================================================

#[test]
fn enrichment_action_divergence_all_entries() {
    let ledger = build_ledger(5);
    let replay = diverging_action_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(!result.passed);
    let counts = result.violation_counts();
    assert_eq!(counts[&ReplayViolationType::OutcomeDivergence], 5);
}

#[test]
fn enrichment_calibration_divergence_detected() {
    let ledger = build_ledger(1);
    let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
        action: entry.ledger_entry.action.clone(),
        chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
        calibration_score: entry.ledger_entry.calibration_score + 1.0,
        fallback_active: entry.ledger_entry.fallback_active,
        expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
    });
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(result.has_violation(&ReplayViolationType::CalibrationDivergence));
}

#[test]
fn enrichment_calibration_within_tolerance_no_violation() {
    let ledger = build_ledger(1);
    let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
        action: entry.ledger_entry.action.clone(),
        chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
        calibration_score: entry.ledger_entry.calibration_score + 1e-12,
        fallback_active: entry.ledger_entry.fallback_active,
        expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
    });
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(!result.has_violation(&ReplayViolationType::CalibrationDivergence));
}

#[test]
fn enrichment_expected_loss_divergence_detected() {
    let ledger = build_ledger(1);
    let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
        action: entry.ledger_entry.action.clone(),
        chosen_expected_loss: 999.0,
        calibration_score: entry.ledger_entry.calibration_score,
        fallback_active: entry.ledger_entry.fallback_active,
        expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
    });
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(result.has_violation(&ReplayViolationType::ExpectedLossDivergence));
}

#[test]
fn enrichment_expected_loss_within_tolerance_no_violation() {
    let ledger = build_ledger(1);
    let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
        action: entry.ledger_entry.action.clone(),
        chosen_expected_loss: entry.ledger_entry.chosen_expected_loss + 1e-12,
        calibration_score: entry.ledger_entry.calibration_score,
        fallback_active: entry.ledger_entry.fallback_active,
        expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
    });
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(!result.has_violation(&ReplayViolationType::ExpectedLossDivergence));
}

#[test]
fn enrichment_fallback_divergence_detected() {
    let ledger = build_ledger(1);
    let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
        action: entry.ledger_entry.action.clone(),
        chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
        calibration_score: entry.ledger_entry.calibration_score,
        fallback_active: !entry.ledger_entry.fallback_active,
        expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
    });
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(result.has_violation(&ReplayViolationType::FallbackDivergence));
}

#[test]
fn enrichment_custom_calibration_tolerance() {
    let ledger = build_ledger(1);
    let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
        action: entry.ledger_entry.action.clone(),
        chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
        calibration_score: entry.ledger_entry.calibration_score + 0.01,
        fallback_active: entry.ledger_entry.fallback_active,
        expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
    });
    let config = ReplayConfig {
        calibration_tolerance: 0.1,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, Some(&replay));
    assert!(!result.has_violation(&ReplayViolationType::CalibrationDivergence));
}

#[test]
fn enrichment_custom_loss_tolerance() {
    let ledger = build_ledger(1);
    let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
        action: entry.ledger_entry.action.clone(),
        chosen_expected_loss: entry.ledger_entry.chosen_expected_loss + 0.01,
        calibration_score: entry.ledger_entry.calibration_score,
        fallback_active: entry.ledger_entry.fallback_active,
        expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
    });
    let config = ReplayConfig {
        loss_tolerance: 0.1,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, Some(&replay));
    assert!(!result.has_violation(&ReplayViolationType::ExpectedLossDivergence));
}

// ===========================================================================
// Epoch regression
// ===========================================================================

#[test]
fn enrichment_epoch_regression_detected() {
    let mut ledger = build_ledger(3);
    ledger[1].epoch = SecurityEpoch::from_raw(5);
    ledger[2].epoch = SecurityEpoch::from_raw(0);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.has_violation(&ReplayViolationType::EpochRegression));
    assert!(result.has_error_code(&ReplayErrorCode::EpochRegression));
}

#[test]
fn enrichment_epoch_regression_disabled() {
    let mut ledger = build_ledger(3);
    ledger[1].epoch = SecurityEpoch::from_raw(5);
    ledger[2].epoch = SecurityEpoch::from_raw(0);
    let config = ReplayConfig {
        detect_epoch_regression: false,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::EpochRegression));
}

#[test]
fn enrichment_epoch_forward_no_violation() {
    let mut ledger = build_ledger(3);
    ledger[0].epoch = SecurityEpoch::from_raw(1);
    ledger[1].epoch = SecurityEpoch::from_raw(2);
    ledger[2].epoch = SecurityEpoch::from_raw(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::EpochRegression));
}

#[test]
fn enrichment_epoch_equal_no_regression() {
    let mut ledger = build_ledger(3);
    ledger[0].epoch = SecurityEpoch::from_raw(5);
    ledger[1].epoch = SecurityEpoch::from_raw(5);
    ledger[2].epoch = SecurityEpoch::from_raw(5);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::EpochRegression));
}

// ===========================================================================
// Schema migration
// ===========================================================================

#[test]
fn enrichment_schema_migration_tracked_not_violated_by_default() {
    let mut ledger = build_ledger(3);
    ledger[2].schema_version = "2.0.0".to_string();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::SchemaMigration));
    assert_eq!(result.diagnostics.schema_migrations.len(), 1);
    assert_eq!(result.diagnostics.schema_versions_seen.len(), 2);
}

#[test]
fn enrichment_schema_migration_is_violation_when_configured() {
    let mut ledger = build_ledger(3);
    ledger[2].schema_version = "2.0.0".to_string();
    let config = ReplayConfig {
        schema_migration_is_violation: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(result.has_violation(&ReplayViolationType::SchemaMigration));
    assert!(result.has_error_code(&ReplayErrorCode::SchemaMigrationDetected));
}

#[test]
fn enrichment_multiple_schema_migrations_tracked() {
    let mut ledger = build_ledger(5);
    ledger[1].schema_version = "2.0.0".to_string();
    ledger[2].schema_version = "2.0.0".to_string();
    ledger[3].schema_version = "3.0.0".to_string();
    ledger[4].schema_version = "3.0.0".to_string();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert_eq!(result.diagnostics.schema_migrations.len(), 2);
    assert_eq!(result.diagnostics.schema_versions_seen.len(), 3);
}

#[test]
fn enrichment_schema_migration_not_tracked_when_disabled() {
    let mut ledger = build_ledger(3);
    ledger[2].schema_version = "2.0.0".to_string();
    let config = ReplayConfig {
        track_schema_migrations: false,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(result.diagnostics.schema_migrations.is_empty());
}

// ===========================================================================
// Policy version tracking
// ===========================================================================

#[test]
fn enrichment_policy_discontinuity_tracked_not_violated_by_default() {
    let mut ledger = build_ledger(3);
    ledger[1].policy_id = "policy-v2".to_string();
    ledger[2].policy_id = "policy-v2".to_string();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::PolicyVersionChange));
    assert_eq!(result.diagnostics.policy_transitions.len(), 1);
    assert_eq!(result.diagnostics.policy_versions_seen.len(), 2);
}

#[test]
fn enrichment_policy_discontinuity_is_violation_when_configured() {
    let mut ledger = build_ledger(3);
    ledger[1].policy_id = "policy-v2".to_string();
    let config = ReplayConfig {
        policy_discontinuity_is_violation: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(result.has_violation(&ReplayViolationType::PolicyVersionChange));
    assert!(result.has_error_code(&ReplayErrorCode::PolicyVersionDiscontinuity));
}

#[test]
fn enrichment_policy_allowed_ids_approved_not_violated() {
    let mut ledger = build_ledger(3);
    let original = ledger[0].policy_id.clone();
    ledger[1].policy_id = "approved-v2".to_string();
    ledger[2].policy_id = "approved-v2".to_string();
    let mut allowed = BTreeSet::new();
    allowed.insert(original);
    allowed.insert("approved-v2".to_string());
    let config = ReplayConfig {
        allowed_policy_ids: allowed,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::PolicyVersionChange));
}

#[test]
fn enrichment_policy_allowed_ids_unapproved_violated() {
    let mut ledger = build_ledger(3);
    let original = ledger[0].policy_id.clone();
    ledger[1].policy_id = "approved-v2".to_string();
    ledger[2].policy_id = "UNAPPROVED".to_string();
    let mut allowed = BTreeSet::new();
    allowed.insert(original);
    allowed.insert("approved-v2".to_string());
    let config = ReplayConfig {
        allowed_policy_ids: allowed,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    let policy_vs: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.violation_type == ReplayViolationType::PolicyVersionChange)
        .collect();
    assert_eq!(policy_vs.len(), 1);
    assert_eq!(policy_vs[0].actual.as_deref(), Some("UNAPPROVED"));
}

#[test]
fn enrichment_multiple_policy_transitions_tracked() {
    let mut ledger = build_ledger(5);
    ledger[1].policy_id = "pol-v2".to_string();
    ledger[2].policy_id = "pol-v2".to_string();
    ledger[3].policy_id = "pol-v3".to_string();
    ledger[4].policy_id = "pol-v3".to_string();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert_eq!(result.diagnostics.policy_transitions.len(), 2);
    assert_eq!(result.diagnostics.policy_versions_seen.len(), 3);
}

#[test]
fn enrichment_policy_not_tracked_when_disabled() {
    let mut ledger = build_ledger(3);
    ledger[2].policy_id = "new-pol".to_string();
    let config = ReplayConfig {
        track_policy_versions: false,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(result.diagnostics.policy_transitions.is_empty());
}

// ===========================================================================
// Halt on first
// ===========================================================================

#[test]
fn enrichment_halt_on_first_stops_early_action_divergence() {
    let ledger = build_ledger(5);
    let replay = diverging_action_replay();
    let config = ReplayConfig {
        halt_on_first: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, Some(&replay));
    assert!(!result.passed);
    assert_eq!(result.violations.len(), 1);
    assert!(result.entries_processed < 5);
}

#[test]
fn enrichment_halt_on_first_stops_at_sequence_gap() {
    let mut ledger = build_ledger(5);
    ledger[2].sequence = 100;
    let config = ReplayConfig {
        halt_on_first: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.entries_processed <= 3);
}

#[test]
fn enrichment_halt_on_first_stops_at_epoch_regression() {
    let mut ledger = build_ledger(5);
    ledger[1].epoch = SecurityEpoch::from_raw(10);
    ledger[2].epoch = SecurityEpoch::from_raw(1);
    let config = ReplayConfig {
        halt_on_first: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.entries_processed < 5);
}

#[test]
fn enrichment_halt_on_first_stops_at_policy_discontinuity() {
    let mut ledger = build_ledger(5);
    ledger[1].policy_id = "new-pol".to_string();
    let config = ReplayConfig {
        halt_on_first: true,
        policy_discontinuity_is_violation: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.entries_processed < 5);
}

#[test]
fn enrichment_halt_on_first_stops_at_schema_migration_violation() {
    let mut ledger = build_ledger(5);
    ledger[1].schema_version = "2.0.0".to_string();
    let config = ReplayConfig {
        halt_on_first: true,
        schema_migration_is_violation: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.entries_processed < 5);
}

// ===========================================================================
// Events
// ===========================================================================

#[test]
fn enrichment_replay_complete_pass_event() {
    let ledger = build_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.passed);
    assert!(!checker.events().is_empty());
    let last = checker.events().last().unwrap();
    assert_eq!(last.event, "replay_complete");
    assert_eq!(last.outcome, "pass");
    assert_eq!(last.component, "evidence-replay-checker");
}

#[test]
fn enrichment_replay_complete_fail_event() {
    let ledger = build_ledger(3);
    let replay = diverging_action_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.replay(&ledger, Some(&replay));
    let last = checker.events().last().unwrap();
    assert_eq!(last.event, "replay_complete");
    assert_eq!(last.outcome, "fail");
}

#[test]
fn enrichment_clear_events() {
    let ledger = build_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.replay(&ledger, None);
    assert!(!checker.events().is_empty());
    checker.clear_events();
    assert!(checker.events().is_empty());
}

#[test]
fn enrichment_events_accumulate_between_replays() {
    let ledger = build_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.replay(&ledger, None);
    let count1 = checker.events().len();
    checker.replay(&ledger, None);
    let count2 = checker.events().len();
    assert!(count2 > count1);
}

#[test]
fn enrichment_schema_migration_boundary_info_event() {
    let mut ledger = build_ledger(3);
    ledger[2].schema_version = "2.0.0".to_string();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.replay(&ledger, None);
    let events = checker.events();
    let migration_events: Vec<_> = events
        .iter()
        .filter(|e| e.event == "schema_migration_boundary")
        .collect();
    assert_eq!(migration_events.len(), 1);
    assert_eq!(migration_events[0].outcome, "info");
}

#[test]
fn enrichment_schema_migration_violation_event() {
    let mut ledger = build_ledger(3);
    ledger[2].schema_version = "2.0.0".to_string();
    let config = ReplayConfig {
        schema_migration_is_violation: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    checker.replay(&ledger, None);
    let events = checker.events();
    let vs: Vec<_> = events
        .iter()
        .filter(|e| e.event == "schema_migration_violation")
        .collect();
    assert_eq!(vs.len(), 1);
    assert_eq!(vs[0].outcome, "fail");
    assert_eq!(
        vs[0].error_code.as_deref(),
        Some("SCHEMA_MIGRATION_DETECTED")
    );
}

#[test]
fn enrichment_policy_discontinuity_violation_event() {
    let mut ledger = build_ledger(3);
    ledger[1].policy_id = "pol-v2".to_string();
    ledger[2].policy_id = "pol-v2".to_string();
    let config = ReplayConfig {
        policy_discontinuity_is_violation: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    checker.replay(&ledger, None);
    let events = checker.events();
    let vs: Vec<_> = events
        .iter()
        .filter(|e| e.event == "policy_version_discontinuity")
        .collect();
    assert_eq!(vs.len(), 1);
    assert_eq!(vs[0].outcome, "fail");
}

#[test]
fn enrichment_policy_transition_info_event() {
    let mut ledger = build_ledger(3);
    ledger[1].policy_id = "pol-v2".to_string();
    ledger[2].policy_id = "pol-v2".to_string();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.replay(&ledger, None);
    let events = checker.events();
    let vs: Vec<_> = events
        .iter()
        .filter(|e| e.event == "policy_version_transition")
        .collect();
    assert_eq!(vs.len(), 1);
    assert_eq!(vs[0].outcome, "info");
}

// ===========================================================================
// Diagnostics
// ===========================================================================

#[test]
fn enrichment_diagnostics_trace_ids_counted() {
    let ledger = build_ledger_with_traces(6, &["t1", "t2", "t3"]);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert_eq!(result.diagnostics.distinct_trace_ids, 3);
}

#[test]
fn enrichment_diagnostics_decision_ids_counted() {
    let ledger = build_ledger_with_decisions(6, &["d1", "d2"]);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert_eq!(result.diagnostics.distinct_decision_ids, 2);
}

#[test]
fn enrichment_diagnostics_timestamp_range() {
    let ledger = build_ledger(5);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.diagnostics.first_ts.is_some());
    assert!(result.diagnostics.last_ts.is_some());
    assert!(result.diagnostics.first_ts.unwrap() <= result.diagnostics.last_ts.unwrap());
}

#[test]
fn enrichment_diagnostics_epoch_range() {
    let mut ledger = build_ledger(3);
    ledger[0].epoch = SecurityEpoch::from_raw(2);
    ledger[1].epoch = SecurityEpoch::from_raw(5);
    ledger[2].epoch = SecurityEpoch::from_raw(7);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    let (lo, hi) = result.diagnostics.epoch_range.unwrap();
    assert_eq!(lo, 2);
    assert_eq!(hi, 7);
}

#[test]
fn enrichment_diagnostics_empty_ledger() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&[], None);
    assert!(result.diagnostics.first_ts.is_none());
    assert!(result.diagnostics.last_ts.is_none());
    assert!(result.diagnostics.epoch_range.is_none());
    assert_eq!(result.diagnostics.distinct_trace_ids, 0);
    assert_eq!(result.diagnostics.distinct_decision_ids, 0);
}

// ===========================================================================
// Manifest generation
// ===========================================================================

#[test]
fn enrichment_manifest_from_valid_replay() {
    let ledger = build_ledger(5);
    let replay = identity_replay();
    let config = ReplayConfig::default();
    let mut checker = EvidenceReplayChecker::new(config.clone());
    let result = checker.replay(&ledger, Some(&replay));
    let manifest = result.manifest(&config, &ledger);
    assert!(manifest.passed);
    assert_eq!(manifest.source_entry_count, 5);
    assert_eq!(manifest.violation_count, 0);
    assert!(manifest.first_entry_hash.is_some());
    assert!(manifest.last_entry_hash.is_some());
    assert_ne!(manifest.first_entry_hash, manifest.last_entry_hash);
}

#[test]
fn enrichment_manifest_from_failed_replay() {
    let ledger = build_ledger(3);
    let replay = diverging_action_replay();
    let config = ReplayConfig::default();
    let mut checker = EvidenceReplayChecker::new(config.clone());
    let result = checker.replay(&ledger, Some(&replay));
    let manifest = result.manifest(&config, &ledger);
    assert!(!manifest.passed);
    assert_eq!(manifest.violation_count, 3);
}

#[test]
fn enrichment_manifest_serde_roundtrip() {
    let ledger = build_ledger(3);
    let config = ReplayConfig::default();
    let mut checker = EvidenceReplayChecker::new(config.clone());
    let result = checker.replay(&ledger, None);
    let manifest = result.manifest(&config, &ledger);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ReplayManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ===========================================================================
// replay_and_collect
// ===========================================================================

#[test]
fn enrichment_replay_and_collect_passing() {
    let ledger = build_ledger(5);
    let replay = identity_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let artifact = checker.replay_and_collect(&ledger, Some(&replay));
    assert!(artifact.gate_passed);
    assert_eq!(artifact.manifest.source_entry_count, 5);
    assert!(artifact.manifest.passed);
    assert!(artifact.violations.is_empty());
    assert!(!artifact.events.is_empty());
}

#[test]
fn enrichment_replay_and_collect_failing() {
    let ledger = build_ledger(3);
    let replay = diverging_action_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let artifact = checker.replay_and_collect(&ledger, Some(&replay));
    assert!(!artifact.gate_passed);
    assert!(!artifact.manifest.passed);
    assert_eq!(artifact.violations.len(), 3);
}

#[test]
fn enrichment_replay_and_collect_clears_events_between_runs() {
    let ledger = build_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let art1 = checker.replay_and_collect(&ledger, None);
    let art2 = checker.replay_and_collect(&ledger, None);
    assert_eq!(art1.events.len(), art2.events.len());
}

#[test]
fn enrichment_replay_and_collect_serde_roundtrip() {
    let ledger = build_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let artifact = checker.replay_and_collect(&ledger, None);
    let json = serde_json::to_string(&artifact).unwrap();
    let back: ReplayEvidenceArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

// ===========================================================================
// Cross-machine determinism
// ===========================================================================

#[test]
fn enrichment_cross_machine_determinism_empty() {
    assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
        &ReplayConfig::default(),
        &[],
        None,
    ));
}

#[test]
fn enrichment_cross_machine_determinism_structural() {
    let ledger = build_ledger(10);
    assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
        &ReplayConfig::default(),
        &ledger,
        None,
    ));
}

#[test]
fn enrichment_cross_machine_determinism_with_replay() {
    let ledger = build_ledger(10);
    let replay = identity_replay();
    assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
        &ReplayConfig::default(),
        &ledger,
        Some(&replay),
    ));
}

#[test]
fn enrichment_deterministic_replay_identical_results() {
    let run = || {
        let ledger = build_ledger(5);
        let replay = identity_replay();
        let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
        checker.set_epoch(SecurityEpoch::from_raw(1));
        checker.replay(&ledger, Some(&replay))
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1, r2);
}

#[test]
fn enrichment_rolling_hash_changes_with_each_entry() {
    let ledger1 = build_ledger(1);
    let ledger3 = build_ledger(3);
    let mut c1 = EvidenceReplayChecker::new(ReplayConfig::default());
    let mut c3 = EvidenceReplayChecker::new(ReplayConfig::default());
    let r1 = c1.replay(&ledger1, None);
    let r3 = c3.replay(&ledger3, None);
    assert_ne!(r1.final_rolling_hash, r3.final_rolling_hash);
}

// ===========================================================================
// Multiple violation types in one run
// ===========================================================================

#[test]
fn enrichment_multiple_violations_tamper_and_gap() {
    let mut ledger = build_ledger(3);
    ledger[0].ledger_entry.ts_unix_ms = 999; // tamper
    ledger[2].sequence = 10; // gap
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.has_violation(&ReplayViolationType::ArtifactHashMismatch));
    assert!(result.has_violation(&ReplayViolationType::SequenceGap));
}

#[test]
fn enrichment_violation_plus_outcome_divergence() {
    let mut ledger = build_ledger(3);
    ledger[1].ledger_entry.ts_unix_ms = 999; // tamper
    let replay = diverging_action_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(!result.passed);
    assert!(result.has_violation(&ReplayViolationType::ArtifactHashMismatch));
    assert!(result.has_violation(&ReplayViolationType::OutcomeDivergence));
}

// ===========================================================================
// Adversarial / edge cases
// ===========================================================================

#[test]
fn enrichment_adversarial_empty_entry_id() {
    let mut ledger = build_ledger(1);
    ledger[0].entry_id = EvidenceEntryId::new("");
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert_eq!(result.entries_processed, 1);
}

#[test]
fn enrichment_adversarial_max_epoch_no_panic() {
    let mut ledger = build_ledger(1);
    ledger[0].epoch = SecurityEpoch::from_raw(u64::MAX);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert_eq!(result.entries_processed, 1);
}

#[test]
fn enrichment_adversarial_very_large_gap_with_allow() {
    let mut ledger = build_ledger(2);
    ledger[1].sequence = u64::MAX;
    let config = ReplayConfig {
        allow_gaps: true,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    assert!(result.entries_skipped > 0);
}

#[test]
fn enrichment_adversarial_duplicate_sequence() {
    let mut ledger = build_ledger(3);
    ledger[1].sequence = 0; // duplicate of entry 0
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
}

#[test]
fn enrichment_single_entry_no_sequence_check() {
    // First entry has no predecessor, so no sequence gap check.
    let ledger = build_ledger(1);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::SequenceGap));
}

#[test]
fn enrichment_single_entry_no_epoch_regression() {
    let ledger = build_ledger(1);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::EpochRegression));
}

#[test]
fn enrichment_single_entry_no_timestamp_violation() {
    let ledger = build_ledger(1);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::TimestampMonotonicityViolation));
}

// ===========================================================================
// Epoch propagation to result
// ===========================================================================

#[test]
fn enrichment_epoch_propagated_to_result() {
    let ledger = build_ledger(1);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.set_epoch(SecurityEpoch::from_raw(77));
    let result = checker.replay(&ledger, None);
    assert_eq!(result.epoch, SecurityEpoch::from_raw(77));
}

#[test]
fn enrichment_epoch_default_zero() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&[], None);
    assert_eq!(result.epoch, SecurityEpoch::from_raw(0));
}

// ===========================================================================
// Full lifecycle
// ===========================================================================

#[test]
fn enrichment_full_lifecycle_structural_and_replay() {
    let ledger = build_ledger(10);
    let config = ReplayConfig::default();
    let replay = identity_replay();

    let mut checker = EvidenceReplayChecker::new(config.clone());
    checker.set_epoch(SecurityEpoch::from_raw(1));
    let result = checker.replay(&ledger, Some(&replay));
    assert!(result.passed);
    assert_eq!(result.entries_processed, 10);
    assert_eq!(result.entries_skipped, 0);

    let manifest = result.manifest(&config, &ledger);
    assert!(manifest.passed);
    assert_eq!(manifest.source_entry_count, 10);
    assert_eq!(manifest.violation_count, 0);

    assert!(result.diagnostics.first_ts.is_some());
    assert!(result.diagnostics.last_ts.is_some());
    assert!(result.diagnostics.epoch_range.is_some());
    assert!(result.diagnostics.distinct_trace_ids > 0);

    assert!(!checker.events().is_empty());
    let last_event = checker.events().last().unwrap();
    assert_eq!(last_event.event, "replay_complete");
    assert_eq!(last_event.outcome, "pass");

    assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
        &config,
        &ledger,
        Some(&replay),
    ));

    let mut checker2 = EvidenceReplayChecker::new(config);
    let artifact = checker2.replay_and_collect(&ledger, Some(&replay));
    assert!(artifact.gate_passed);
    let artifact_json = serde_json::to_string(&artifact).unwrap();
    let artifact_back: ReplayEvidenceArtifact = serde_json::from_str(&artifact_json).unwrap();
    assert_eq!(artifact, artifact_back);
}

#[test]
fn enrichment_full_lifecycle_failing_with_diagnostics() {
    let mut ledger = build_ledger(5);
    // Entry 1 and beyond use pol-v2 so there is exactly 1 policy transition.
    ledger[1].policy_id = "pol-v2".to_string();
    ledger[2].policy_id = "pol-v2".to_string();
    ledger[3].policy_id = "pol-v2".to_string();
    ledger[4].policy_id = "pol-v2".to_string();
    // Entry 2 onwards use schema 2.0.0 so there is exactly 1 schema migration.
    ledger[2].schema_version = "2.0.0".to_string();
    ledger[3].schema_version = "2.0.0".to_string();
    ledger[4].schema_version = "2.0.0".to_string();
    ledger[3].epoch = SecurityEpoch::from_raw(10);
    ledger[4].epoch = SecurityEpoch::from_raw(1); // regression

    let config = ReplayConfig {
        policy_discontinuity_is_violation: true,
        schema_migration_is_violation: true,
        ..ReplayConfig::default()
    };
    let replay = diverging_action_replay();
    let mut checker = EvidenceReplayChecker::new(config.clone());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(!result.passed);

    // Should have multiple violation types.
    assert!(result.has_violation(&ReplayViolationType::OutcomeDivergence));
    assert!(result.has_violation(&ReplayViolationType::PolicyVersionChange));
    assert!(result.has_violation(&ReplayViolationType::SchemaMigration));
    assert!(result.has_violation(&ReplayViolationType::EpochRegression));

    // Diagnostics populated.
    assert_eq!(result.diagnostics.policy_transitions.len(), 1);
    assert_eq!(result.diagnostics.schema_migrations.len(), 1);

    // Serde roundtrip on result.
    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ===========================================================================
// Fixed-point / determinism checks using millionths
// ===========================================================================

#[test]
fn enrichment_fixed_point_millionths_calibration() {
    // Using fixed-point millionths: 1_000_000 = 1.0
    let calibration_millionths: u64 = 850_000; // 0.85
    let score = calibration_millionths as f64 / 1_000_000.0;
    assert!((score - 0.85).abs() < 1e-12);
}

#[test]
fn enrichment_fixed_point_millionths_loss() {
    let loss_millionths: u64 = 100_000; // 0.1
    let loss = loss_millionths as f64 / 1_000_000.0;
    assert!((loss - 0.1).abs() < 1e-12);
}

#[test]
fn enrichment_fixed_point_identity_replay_preserves_precision() {
    let ledger = build_ledger(1);
    let replay = identity_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    // Identity replay should preserve exact values => no divergence.
    assert!(result.passed);
    assert!(!result.has_violation(&ReplayViolationType::CalibrationDivergence));
    assert!(!result.has_violation(&ReplayViolationType::ExpectedLossDivergence));
}

// ===========================================================================
// ContentHash determinism
// ===========================================================================

#[test]
fn enrichment_content_hash_deterministic() {
    let h1 = ContentHash::compute(b"evidence-genesis");
    let h2 = ContentHash::compute(b"evidence-genesis");
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_content_hash_different_inputs() {
    let h1 = ContentHash::compute(b"a");
    let h2 = ContentHash::compute(b"b");
    assert_ne!(h1, h2);
}

// ===========================================================================
// SecurityEpoch determinism
// ===========================================================================

#[test]
fn enrichment_security_epoch_round_trip() {
    let epoch = SecurityEpoch::from_raw(42);
    assert_eq!(epoch.as_u64(), 42);
}

#[test]
fn enrichment_security_epoch_zero() {
    let epoch = SecurityEpoch::from_raw(0);
    assert_eq!(epoch.as_u64(), 0);
}

#[test]
fn enrichment_security_epoch_max() {
    let epoch = SecurityEpoch::from_raw(u64::MAX);
    assert_eq!(epoch.as_u64(), u64::MAX);
}
