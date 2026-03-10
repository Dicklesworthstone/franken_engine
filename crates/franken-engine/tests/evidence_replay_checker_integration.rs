//! Integration tests for `frankenengine_engine::evidence_replay_checker`.
//!
//! Exercises the evidence replay checker from the public crate boundary:
//! EvidenceReplayChecker, ReplayConfig, ReplayResult, ReplayViolation,
//! ReplayViolationType, ReplayErrorCode, ReplayEvent, ReplayDiagnostics,
//! ReplayManifest, ReplayEvidenceArtifact, SchemaMigrationRecord,
//! PolicyVersionRecord, ReplayedOutcome, DecisionReplayFn.

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

// ── Helpers ─────────────────────────────────────────────────────────────

fn make_ledger_entry(seq: u64) -> EvidenceLedger {
    EvidenceLedgerBuilder::new()
        .ts_unix_ms(1_700_000_000_000 + seq * 1000)
        .component("test-component")
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

/// Compute chain hash matching the private algorithm in evidence_emission.
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
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
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
        prev_chain = Some(entry.chain_hash.clone());
        entries.push(entry);
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

// ── ReplayErrorCode ─────────────────────────────────────────────────────

#[test]
fn error_code_display_all_variants() {
    assert_eq!(ReplayErrorCode::HashMismatch.to_string(), "HASH_MISMATCH");
    assert_eq!(ReplayErrorCode::ChainBroken.to_string(), "CHAIN_BROKEN");
    assert_eq!(
        ReplayErrorCode::EntryTruncated.to_string(),
        "ENTRY_TRUNCATED"
    );
    assert_eq!(ReplayErrorCode::SequenceGap.to_string(), "SEQUENCE_GAP");
    assert_eq!(
        ReplayErrorCode::TimestampMonotonicityViolation.to_string(),
        "TIMESTAMP_MONOTONICITY_VIOLATION"
    );
    assert_eq!(
        ReplayErrorCode::OutcomeDivergence.to_string(),
        "OUTCOME_DIVERGENCE"
    );
    assert_eq!(
        ReplayErrorCode::CalibrationDivergence.to_string(),
        "CALIBRATION_DIVERGENCE"
    );
    assert_eq!(
        ReplayErrorCode::ExpectedLossDivergence.to_string(),
        "EXPECTED_LOSS_DIVERGENCE"
    );
    assert_eq!(
        ReplayErrorCode::FallbackDivergence.to_string(),
        "FALLBACK_DIVERGENCE"
    );
    assert_eq!(
        ReplayErrorCode::SchemaMigrationDetected.to_string(),
        "SCHEMA_MIGRATION_DETECTED"
    );
    assert_eq!(
        ReplayErrorCode::PolicyVersionDiscontinuity.to_string(),
        "POLICY_VERSION_DISCONTINUITY"
    );
    assert_eq!(
        ReplayErrorCode::EpochRegression.to_string(),
        "EPOCH_REGRESSION"
    );
}

#[test]
fn error_code_serde_roundtrip() {
    let code = ReplayErrorCode::ChainBroken;
    let json = serde_json::to_string(&code).unwrap();
    let back: ReplayErrorCode = serde_json::from_str(&json).unwrap();
    assert_eq!(code, back);
}

// ── ReplayViolationType ─────────────────────────────────────────────────

#[test]
fn violation_type_display_all_variants() {
    assert_eq!(
        ReplayViolationType::OutcomeDivergence.to_string(),
        "outcome_divergence"
    );
    assert_eq!(
        ReplayViolationType::ArtifactHashMismatch.to_string(),
        "artifact_hash_mismatch"
    );
    assert_eq!(
        ReplayViolationType::ChainHashMismatch.to_string(),
        "chain_hash_mismatch"
    );
    assert_eq!(ReplayViolationType::SequenceGap.to_string(), "sequence_gap");
    assert_eq!(
        ReplayViolationType::TimestampMonotonicityViolation.to_string(),
        "timestamp_monotonicity_violation"
    );
    assert_eq!(
        ReplayViolationType::EntryTruncated.to_string(),
        "entry_truncated"
    );
    assert_eq!(
        ReplayViolationType::CalibrationDivergence.to_string(),
        "calibration_divergence"
    );
    assert_eq!(
        ReplayViolationType::ExpectedLossDivergence.to_string(),
        "expected_loss_divergence"
    );
    assert_eq!(
        ReplayViolationType::FallbackDivergence.to_string(),
        "fallback_divergence"
    );
    assert_eq!(
        ReplayViolationType::SchemaMigration.to_string(),
        "schema_migration"
    );
    assert_eq!(
        ReplayViolationType::PolicyVersionChange.to_string(),
        "policy_version_change"
    );
    assert_eq!(
        ReplayViolationType::EpochRegression.to_string(),
        "epoch_regression"
    );
}

#[test]
fn violation_type_serde_roundtrip() {
    let vt = ReplayViolationType::ChainHashMismatch;
    let json = serde_json::to_string(&vt).unwrap();
    let back: ReplayViolationType = serde_json::from_str(&json).unwrap();
    assert_eq!(vt, back);
}

// ── ReplayViolation ─────────────────────────────────────────────────────

#[test]
fn violation_serde_roundtrip() {
    let v = ReplayViolation {
        sequence: 42,
        entry_id: "ev-42".to_string(),
        violation_type: ReplayViolationType::OutcomeDivergence,
        error_code: ReplayErrorCode::OutcomeDivergence,
        detail: "action mismatch".to_string(),
        expected: Some("allow".to_string()),
        actual: Some("deny".to_string()),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ReplayViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ── ReplayConfig ────────────────────────────────────────────────────────

#[test]
fn config_default_values() {
    let cfg = ReplayConfig::default();
    assert!(!cfg.allow_gaps);
    assert!(!cfg.halt_on_first);
    assert_eq!(cfg.progress_interval, 1000);
    assert!(cfg.track_schema_migrations);
    assert!(cfg.track_policy_versions);
    assert!(cfg.detect_epoch_regression);
    assert!(!cfg.policy_discontinuity_is_violation);
    assert!(!cfg.schema_migration_is_violation);
    assert!(cfg.allowed_policy_ids.is_empty());
}

#[test]
fn config_serde_roundtrip() {
    let cfg = ReplayConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ReplayConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ── ReplayEvent ─────────────────────────────────────────────────────────

#[test]
fn replay_event_serde_roundtrip() {
    let e = ReplayEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ReplayEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ── SchemaMigrationRecord ───────────────────────────────────────────────

#[test]
fn schema_migration_record_serde_roundtrip() {
    let rec = SchemaMigrationRecord {
        at_sequence: 5,
        from_version: "1.0.0".to_string(),
        to_version: "2.0.0".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: SchemaMigrationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

// ── PolicyVersionRecord ─────────────────────────────────────────────────

#[test]
fn policy_version_record_serde_roundtrip() {
    let rec = PolicyVersionRecord {
        at_sequence: 3,
        from_policy: "policy-v1".to_string(),
        to_policy: "policy-v2".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: PolicyVersionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

// ── ReplayedOutcome ─────────────────────────────────────────────────────

#[test]
fn replayed_outcome_serde_roundtrip() {
    let outcome = ReplayedOutcome {
        action: "allow".to_string(),
        chosen_expected_loss: 0.1,
        calibration_score: 0.85,
        fallback_active: false,
        expected_losses: {
            let mut m = BTreeMap::new();
            m.insert("allow".to_string(), 0.1);
            m.insert("deny".to_string(), 0.9);
            m
        },
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ReplayedOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

// ── EvidenceReplayChecker: basic replay ─────────────────────────────────

#[test]
fn empty_ledger_passes() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&[], None);
    assert!(result.passed);
    assert_eq!(result.entries_processed, 0);
    assert_eq!(result.violations.len(), 0);
}

#[test]
fn single_entry_structural_passes() {
    let ledger = build_ledger(1);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.passed);
    assert_eq!(result.entries_processed, 1);
}

#[test]
fn valid_ledger_structural_passes() {
    let ledger = build_ledger(5);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.passed);
    assert_eq!(result.entries_processed, 5);
    assert_eq!(result.violations.len(), 0);
}

#[test]
fn valid_ledger_identity_replay_passes() {
    let ledger = build_ledger(5);
    let replay = identity_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(result.passed);
    assert_eq!(result.entries_processed, 5);
}

// ── Artifact hash mismatch ──────────────────────────────────────────────

#[test]
fn tampered_artifact_detected() {
    let mut ledger = build_ledger(3);
    // Tamper the ledger entry so artifact hash doesn't match.
    ledger[1].ledger_entry.ts_unix_ms = 999;
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.has_violation(&ReplayViolationType::ArtifactHashMismatch));
    assert!(result.has_error_code(&ReplayErrorCode::HashMismatch));
}

// ── Chain hash mismatch ─────────────────────────────────────────────────

#[test]
fn tampered_chain_hash_detected() {
    let mut ledger = build_ledger(3);
    ledger[1].chain_hash = ContentHash::compute(b"tampered");
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.has_violation(&ReplayViolationType::ChainHashMismatch));
    assert!(result.has_error_code(&ReplayErrorCode::ChainBroken));
}

// ── Sequence gap ────────────────────────────────────────────────────────

#[test]
fn sequence_gap_detected() {
    let mut ledger = build_ledger(3);
    ledger[1].sequence = 5; // expected 1, got 5
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
fn sequence_gap_allowed_when_configured() {
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

// ── Timestamp monotonicity ──────────────────────────────────────────────

#[test]
fn timestamp_out_of_order_detected() {
    let mut ledger = build_ledger(3);
    ledger[2].ts_unix_ms = ledger[0].ts_unix_ms - 1;
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.has_violation(&ReplayViolationType::TimestampMonotonicityViolation));
}

// ── Outcome divergence ──────────────────────────────────────────────────

#[test]
fn action_name_divergence_detected() {
    let ledger = build_ledger(3);
    let replay = diverging_action_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(!result.passed);
    assert_eq!(
        result.violation_counts()[&ReplayViolationType::OutcomeDivergence],
        3
    );
}

#[test]
fn calibration_divergence_detected() {
    let ledger = build_ledger(1);
    let replay: DecisionReplayFn = Box::new(|entry: &CanonicalEvidenceEntry| ReplayedOutcome {
        action: entry.ledger_entry.action.clone(),
        chosen_expected_loss: entry.ledger_entry.chosen_expected_loss,
        calibration_score: entry.ledger_entry.calibration_score + 0.5,
        fallback_active: entry.ledger_entry.fallback_active,
        expected_losses: entry.ledger_entry.expected_loss_by_action.clone(),
    });
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    assert!(result.has_violation(&ReplayViolationType::CalibrationDivergence));
}

#[test]
fn expected_loss_divergence_detected() {
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
fn fallback_divergence_detected() {
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

// ── Halt on first ───────────────────────────────────────────────────────

#[test]
fn halt_on_first_stops_early() {
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

// ── Epoch regression ────────────────────────────────────────────────────

#[test]
fn epoch_regression_detected() {
    let mut ledger = build_ledger(3);
    ledger[1].epoch = SecurityEpoch::from_raw(5);
    ledger[2].epoch = SecurityEpoch::from_raw(0);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.has_violation(&ReplayViolationType::EpochRegression));
    assert!(result.has_error_code(&ReplayErrorCode::EpochRegression));
}

#[test]
fn epoch_regression_disabled_when_configured() {
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

// ── Schema migration detection ──────────────────────────────────────────

#[test]
fn schema_migration_tracked_not_violated_by_default() {
    let mut ledger = build_ledger(3);
    ledger[2].schema_version = "2.0.0".to_string();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.has_violation(&ReplayViolationType::SchemaMigration));
    assert_eq!(result.diagnostics.schema_migrations.len(), 1);
    assert_eq!(result.diagnostics.schema_versions_seen.len(), 2);
}

#[test]
fn schema_migration_is_violation_when_configured() {
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

// ── Policy version tracking ─────────────────────────────────────────────

#[test]
fn policy_discontinuity_logged_not_violated_by_default() {
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
fn policy_discontinuity_is_violation_when_configured() {
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
fn policy_allowed_ids_filter_violations() {
    let mut ledger = build_ledger(3);
    let original = ledger[0].policy_id.clone();
    ledger[1].policy_id = "policy-approved".to_string();
    ledger[2].policy_id = "policy-unapproved".to_string();
    let mut allowed = BTreeSet::new();
    allowed.insert(original);
    allowed.insert("policy-approved".to_string());
    let config = ReplayConfig {
        allowed_policy_ids: allowed,
        ..ReplayConfig::default()
    };
    let mut checker = EvidenceReplayChecker::new(config);
    let result = checker.replay(&ledger, None);
    let policy_violations: Vec<_> = result
        .violations
        .iter()
        .filter(|v| v.violation_type == ReplayViolationType::PolicyVersionChange)
        .collect();
    assert_eq!(policy_violations.len(), 1);
    assert_eq!(
        policy_violations[0].actual.as_deref(),
        Some("policy-unapproved")
    );
}

// ── ReplayResult queries ────────────────────────────────────────────────

#[test]
fn violation_counts_aggregated() {
    let ledger = build_ledger(3);
    let replay = diverging_action_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    let counts = result.violation_counts();
    assert_eq!(counts[&ReplayViolationType::OutcomeDivergence], 3);
}

#[test]
fn violations_at_returns_correct_entries() {
    let ledger = build_ledger(3);
    let replay = diverging_action_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, Some(&replay));
    let at_0 = result.violations_at(0);
    assert_eq!(at_0.len(), 1);
    assert_eq!(
        at_0[0].violation_type,
        ReplayViolationType::OutcomeDivergence
    );
}

// ── Epoch propagation ───────────────────────────────────────────────────

#[test]
fn epoch_propagated_to_result() {
    let ledger = build_ledger(1);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.set_epoch(SecurityEpoch::from_raw(99));
    let result = checker.replay(&ledger, None);
    assert_eq!(result.epoch, SecurityEpoch::from_raw(99));
}

// ── Events ──────────────────────────────────────────────────────────────

#[test]
fn replay_complete_event_emitted() {
    let ledger = build_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.passed);
    assert!(!checker.events().is_empty());
    let last = checker.events().last().unwrap();
    assert_eq!(last.event, "replay_complete");
    assert_eq!(last.outcome, "pass");
}

#[test]
fn replay_fail_event_emitted() {
    let ledger = build_ledger(3);
    let replay = diverging_action_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.replay(&ledger, Some(&replay));
    let last = checker.events().last().unwrap();
    assert_eq!(last.event, "replay_complete");
    assert_eq!(last.outcome, "fail");
}

#[test]
fn clear_events_empties() {
    let ledger = build_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.replay(&ledger, None);
    assert!(!checker.events().is_empty());
    checker.clear_events();
    assert!(checker.events().is_empty());
}

// ── Diagnostics ─────────────────────────────────────────────────────────

#[test]
fn diagnostics_track_trace_and_decision_ids() {
    let ledger = build_ledger(5);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.diagnostics.distinct_trace_ids > 0);
    assert!(result.diagnostics.distinct_decision_ids > 0);
}

#[test]
fn diagnostics_track_timestamp_range() {
    let ledger = build_ledger(5);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.diagnostics.first_ts.is_some());
    assert!(result.diagnostics.last_ts.is_some());
    assert!(result.diagnostics.first_ts.unwrap() <= result.diagnostics.last_ts.unwrap());
}

#[test]
fn diagnostics_track_epoch_range() {
    let ledger = build_ledger(5);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.diagnostics.epoch_range.is_some());
    let (lo, hi) = result.diagnostics.epoch_range.unwrap();
    assert!(lo <= hi);
}

#[test]
fn diagnostics_serde_roundtrip() {
    let diag = ReplayDiagnostics::default();
    let json = serde_json::to_string(&diag).unwrap();
    let back: ReplayDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

// ── Manifest ────────────────────────────────────────────────────────────

#[test]
fn manifest_reflects_replay_result() {
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
}

#[test]
fn manifest_serde_roundtrip() {
    let ledger = build_ledger(3);
    let config = ReplayConfig::default();
    let mut checker = EvidenceReplayChecker::new(config.clone());
    let result = checker.replay(&ledger, None);
    let manifest = result.manifest(&config, &ledger);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ReplayManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ── Evidence artifact ───────────────────────────────────────────────────

#[test]
fn replay_and_collect_produces_passing_artifact() {
    let ledger = build_ledger(5);
    let replay = identity_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let artifact = checker.replay_and_collect(&ledger, Some(&replay));
    assert!(artifact.gate_passed);
    assert_eq!(artifact.manifest.source_entry_count, 5);
    assert!(artifact.manifest.passed);
    assert_eq!(artifact.violations.len(), 0);
    assert!(!artifact.events.is_empty());
}

#[test]
fn replay_and_collect_failing_artifact() {
    let ledger = build_ledger(3);
    let replay = diverging_action_replay();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let artifact = checker.replay_and_collect(&ledger, Some(&replay));
    assert!(!artifact.gate_passed);
    assert!(!artifact.manifest.passed);
    assert_eq!(artifact.violations.len(), 3);
}

#[test]
fn evidence_artifact_serde_roundtrip() {
    let ledger = build_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let artifact = checker.replay_and_collect(&ledger, None);
    let json = serde_json::to_string(&artifact).unwrap();
    let back: ReplayEvidenceArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

// ── Cross-machine determinism ───────────────────────────────────────────

#[test]
fn cross_machine_determinism_passes() {
    let ledger = build_ledger(10);
    let replay = identity_replay();
    let config = ReplayConfig::default();
    assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
        &config,
        &ledger,
        Some(&replay),
    ));
}

#[test]
fn cross_machine_determinism_structural_only() {
    let ledger = build_ledger(10);
    let config = ReplayConfig::default();
    assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
        &config, &ledger, None,
    ));
}

#[test]
fn deterministic_replay_identical_runs() {
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

// ── Multiple violation types ────────────────────────────────────────────

#[test]
fn multiple_violation_types_detected() {
    let mut ledger = build_ledger(3);
    // Tamper artifact hash of entry 0.
    ledger[0].ledger_entry.ts_unix_ms = 999;
    // Create sequence gap for entry 2.
    ledger[2].sequence = 10;
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.has_violation(&ReplayViolationType::ArtifactHashMismatch));
    assert!(result.has_violation(&ReplayViolationType::SequenceGap));
}

// ── ReplayResult serde ──────────────────────────────────────────────────

#[test]
fn replay_result_serde_roundtrip() {
    let ledger = build_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    let json = serde_json::to_string(&result).unwrap();
    let back: ReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ── Checker serde ───────────────────────────────────────────────────────

#[test]
fn checker_serde_roundtrip() {
    let checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let json = serde_json::to_string(&checker).unwrap();
    let back: EvidenceReplayChecker = serde_json::from_str(&json).unwrap();
    assert_eq!(checker.config(), back.config());
}

// ── Full lifecycle ──────────────────────────────────────────────────────

#[test]
fn full_lifecycle_structural_and_replay() {
    // Build a valid ledger.
    let ledger = build_ledger(10);
    let config = ReplayConfig::default();
    let replay = identity_replay();

    // Run structural + replay verification.
    let mut checker = EvidenceReplayChecker::new(config.clone());
    checker.set_epoch(SecurityEpoch::from_raw(1));
    let result = checker.replay(&ledger, Some(&replay));
    assert!(result.passed);
    assert_eq!(result.entries_processed, 10);
    assert_eq!(result.entries_skipped, 0);

    // Manifest captures the result.
    let manifest = result.manifest(&config, &ledger);
    assert!(manifest.passed);
    assert_eq!(manifest.source_entry_count, 10);
    assert_eq!(manifest.violation_count, 0);

    // Diagnostics are populated.
    assert!(result.diagnostics.first_ts.is_some());
    assert!(result.diagnostics.last_ts.is_some());
    assert!(result.diagnostics.epoch_range.is_some());
    assert!(result.diagnostics.distinct_trace_ids > 0);

    // Events recorded.
    assert!(!checker.events().is_empty());
    let last_event = checker.events().last().unwrap();
    assert_eq!(last_event.event, "replay_complete");
    assert_eq!(last_event.outcome, "pass");

    // Cross-machine check passes.
    assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
        &config,
        &ledger,
        Some(&replay),
    ));

    // Evidence artifact is self-consistent.
    let mut checker2 = EvidenceReplayChecker::new(config);
    let artifact = checker2.replay_and_collect(&ledger, Some(&replay));
    assert!(artifact.gate_passed);
    let artifact_json = serde_json::to_string(&artifact).unwrap();
    let artifact_back: ReplayEvidenceArtifact = serde_json::from_str(&artifact_json).unwrap();
    assert_eq!(artifact, artifact_back);
}
