//! Integration tests for `evidence_replay_checker` — violation types, error
//! codes, config, diagnostics, replay results, and checker construction.

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

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::control_plane::EvidenceLedgerBuilder;
use frankenengine_engine::evidence_emission::{
    ActionCategory, CanonicalEvidenceEntry, EvidenceEntryId,
};
use frankenengine_engine::evidence_replay_checker::{
    EvidenceReplayChecker, PolicyVersionRecord, ReplayConfig, ReplayDiagnostics, ReplayErrorCode,
    ReplayEvent, ReplayEvidenceArtifact, ReplayManifest, ReplayResult, ReplayViolation,
    ReplayViolationType, ReplayedOutcome, SchemaMigrationRecord,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── helpers ──────────────────────────────────────────────────────────────

fn make_ledger_entry(seq: u64, ts: u64, action: &str) -> CanonicalEvidenceEntry {
    let ledger = EvidenceLedgerBuilder::new()
        .ts_unix_ms(ts)
        .component("test-component")
        .action(action)
        .chosen_expected_loss(0.1)
        .calibration_score(0.85)
        .fallback_active(false)
        .posterior(vec![0.7, 0.3])
        .expected_loss("allow", 0.1)
        .expected_loss("deny", 0.9)
        .top_feature("severity", 0.6)
        .build()
        .unwrap();

    let payload = serde_json::to_vec(&ledger).unwrap();
    let artifact_hash = ContentHash::compute(&payload);

    CanonicalEvidenceEntry {
        entry_id: EvidenceEntryId::new(format!("ev-{seq}")),
        sequence: seq,
        category: ActionCategory::DecisionContract,
        action_name: action.into(),
        trace_id: "trace-001".into(),
        decision_id: "decision-001".into(),
        policy_id: "policy-v1".into(),
        schema_version: "1.0.0".into(),
        ts_unix_ms: ts,
        epoch: SecurityEpoch::from_raw(1),
        artifact_hash,
        ledger_entry: ledger,
        chain_hash: ContentHash::compute(b"placeholder"),
        metadata: BTreeMap::new(),
    }
}

/// Build a ledger with correct chain hashes for N entries.
fn build_chained_ledger(n: usize) -> Vec<CanonicalEvidenceEntry> {
    let mut entries = Vec::new();
    for i in 0..n {
        let ts = 1_700_000_000_000 + (i as u64) * 1000;
        let mut entry = make_ledger_entry(i as u64, ts, &format!("action_{i}"));

        // Compute chain hash from previous entry.
        // Must match compute_chain_hash: None → prefix "genesis", Some → prev hash bytes.
        let prev_chain_hash = entries
            .last()
            .map(|e: &CanonicalEvidenceEntry| &e.chain_hash);
        let mut chain_input = Vec::new();
        match prev_chain_hash {
            Some(prev) => chain_input.extend_from_slice(prev.as_bytes()),
            None => chain_input.extend_from_slice(b"genesis"),
        }
        chain_input.extend_from_slice(entry.artifact_hash.as_bytes());
        entry.chain_hash = ContentHash::compute(&chain_input);
        entries.push(entry);
    }
    entries
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayErrorCode — serde, Display, ordering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn error_code_serde_all_variants() {
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
    for code in &codes {
        let json = serde_json::to_string(code).unwrap();
        let parsed: ReplayErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, parsed);
    }
}

#[test]
fn error_code_display_screaming_snake_case() {
    assert_eq!(ReplayErrorCode::HashMismatch.to_string(), "HASH_MISMATCH");
    assert_eq!(ReplayErrorCode::ChainBroken.to_string(), "CHAIN_BROKEN");
    assert_eq!(
        ReplayErrorCode::EpochRegression.to_string(),
        "EPOCH_REGRESSION"
    );
}

#[test]
fn error_code_ordering() {
    assert!(ReplayErrorCode::HashMismatch < ReplayErrorCode::ChainBroken);
    assert!(ReplayErrorCode::ChainBroken < ReplayErrorCode::EntryTruncated);
}

#[test]
fn error_code_hash_distinct() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
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
    for code in codes {
        set.insert(code);
    }
    assert_eq!(set.len(), 12);
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayViolationType — serde, Display, ordering
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn violation_type_serde_all_variants() {
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
    for vtype in &types {
        let json = serde_json::to_string(vtype).unwrap();
        let parsed: ReplayViolationType = serde_json::from_str(&json).unwrap();
        assert_eq!(*vtype, parsed);
    }
}

#[test]
fn violation_type_display_snake_case() {
    assert_eq!(
        ReplayViolationType::OutcomeDivergence.to_string(),
        "outcome_divergence"
    );
    assert_eq!(
        ReplayViolationType::SchemaMigration.to_string(),
        "schema_migration"
    );
    assert_eq!(
        ReplayViolationType::PolicyVersionChange.to_string(),
        "policy_version_change"
    );
}

#[test]
fn violation_type_ordering() {
    assert!(ReplayViolationType::OutcomeDivergence < ReplayViolationType::ArtifactHashMismatch);
    assert!(ReplayViolationType::SequenceGap < ReplayViolationType::EntryTruncated);
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayViolation — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn violation_serde_with_expected_and_actual() {
    let v = ReplayViolation {
        sequence: 42,
        entry_id: "ev-42".into(),
        violation_type: ReplayViolationType::OutcomeDivergence,
        error_code: ReplayErrorCode::OutcomeDivergence,
        detail: "action mismatch".into(),
        expected: Some("allow".into()),
        actual: Some("deny".into()),
    };
    let json = serde_json::to_string(&v).unwrap();
    let parsed: ReplayViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, parsed);
}

#[test]
fn violation_serde_with_none_values() {
    let v = ReplayViolation {
        sequence: 0,
        entry_id: "ev-0".into(),
        violation_type: ReplayViolationType::ArtifactHashMismatch,
        error_code: ReplayErrorCode::HashMismatch,
        detail: "hash failed".into(),
        expected: None,
        actual: None,
    };
    let json = serde_json::to_string(&v).unwrap();
    let parsed: ReplayViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, parsed);
    assert!(parsed.expected.is_none());
    assert!(parsed.actual.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayConfig — Default, custom, serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn config_default_values() {
    let cfg = ReplayConfig::default();
    assert!((cfg.calibration_tolerance - 1e-9).abs() < 1e-15);
    assert!((cfg.loss_tolerance - 1e-9).abs() < 1e-15);
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
fn config_custom_serde() {
    let mut policy_ids = BTreeSet::new();
    policy_ids.insert("pol-v1".into());
    policy_ids.insert("pol-v2".into());
    let cfg = ReplayConfig {
        calibration_tolerance: 0.01,
        loss_tolerance: 0.05,
        allow_gaps: true,
        halt_on_first: true,
        progress_interval: 500,
        track_schema_migrations: false,
        track_policy_versions: false,
        detect_epoch_regression: false,
        policy_discontinuity_is_violation: true,
        schema_migration_is_violation: true,
        allowed_policy_ids: policy_ids,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let parsed: ReplayConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayDiagnostics — Default, serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn diagnostics_default_is_empty() {
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
fn diagnostics_serde_with_data() {
    let diag = ReplayDiagnostics {
        schema_versions_seen: ["1.0.0".into(), "2.0.0".into()].into_iter().collect(),
        schema_migrations: vec![SchemaMigrationRecord {
            at_sequence: 10,
            from_version: "1.0.0".into(),
            to_version: "2.0.0".into(),
        }],
        policy_versions_seen: ["pol-v1".into()].into_iter().collect(),
        policy_transitions: vec![],
        distinct_trace_ids: 5,
        distinct_decision_ids: 3,
        first_ts: Some(1000),
        last_ts: Some(5000),
        epoch_range: Some((1, 3)),
    };
    let json = serde_json::to_string(&diag).unwrap();
    let parsed: ReplayDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// SchemaMigrationRecord & PolicyVersionRecord — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn schema_migration_record_serde() {
    let rec = SchemaMigrationRecord {
        at_sequence: 42,
        from_version: "1.0.0".into(),
        to_version: "2.0.0".into(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let parsed: SchemaMigrationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, parsed);
}

#[test]
fn policy_version_record_serde() {
    let rec = PolicyVersionRecord {
        at_sequence: 99,
        from_policy: "pol-v1".into(),
        to_policy: "pol-v2".into(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let parsed: PolicyVersionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayEvent — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn replay_event_serde_with_error_code() {
    let ev = ReplayEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: "evidence-replay-checker".into(),
        event: "artifact_integrity_fail".into(),
        outcome: "fail".into(),
        error_code: Some("HASH_MISMATCH".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let parsed: ReplayEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, parsed);
}

#[test]
fn replay_event_serde_without_error_code() {
    let ev = ReplayEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: "checker".into(),
        event: "replay_complete".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let parsed: ReplayEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, parsed);
    assert!(parsed.error_code.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayedOutcome — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn replayed_outcome_serde() {
    let mut losses = BTreeMap::new();
    losses.insert("allow".into(), 0.1);
    losses.insert("deny".into(), 0.9);
    let outcome = ReplayedOutcome {
        action: "allow".into(),
        chosen_expected_loss: 0.1,
        calibration_score: 0.85,
        fallback_active: false,
        expected_losses: losses,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let parsed: ReplayedOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayManifest — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn replay_manifest_serde() {
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
    let parsed: ReplayManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, parsed);
}

#[test]
fn replay_manifest_serde_empty_hashes() {
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
    let parsed: ReplayManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, parsed);
    assert!(parsed.first_entry_hash.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayResult — methods with manually constructed violations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn result_violation_counts_empty() {
    let result = ReplayResult {
        entries_processed: 5,
        entries_skipped: 0,
        violations: vec![],
        passed: true,
        final_rolling_hash: ContentHash::compute(b"test"),
        epoch: SecurityEpoch::from_raw(1),
        diagnostics: ReplayDiagnostics::default(),
    };
    assert!(result.violation_counts().is_empty());
    assert!(!result.has_violation(&ReplayViolationType::OutcomeDivergence));
    assert!(!result.has_error_code(&ReplayErrorCode::HashMismatch));
    assert!(result.violations_at(0).is_empty());
}

#[test]
fn result_violation_counts_aggregated() {
    let violations = vec![
        ReplayViolation {
            sequence: 0,
            entry_id: "ev-0".into(),
            violation_type: ReplayViolationType::OutcomeDivergence,
            error_code: ReplayErrorCode::OutcomeDivergence,
            detail: "test".into(),
            expected: None,
            actual: None,
        },
        ReplayViolation {
            sequence: 1,
            entry_id: "ev-1".into(),
            violation_type: ReplayViolationType::OutcomeDivergence,
            error_code: ReplayErrorCode::OutcomeDivergence,
            detail: "test".into(),
            expected: None,
            actual: None,
        },
        ReplayViolation {
            sequence: 1,
            entry_id: "ev-1".into(),
            violation_type: ReplayViolationType::SequenceGap,
            error_code: ReplayErrorCode::SequenceGap,
            detail: "test".into(),
            expected: None,
            actual: None,
        },
    ];
    let result = ReplayResult {
        entries_processed: 2,
        entries_skipped: 0,
        violations,
        passed: false,
        final_rolling_hash: ContentHash::compute(b"test"),
        epoch: SecurityEpoch::from_raw(1),
        diagnostics: ReplayDiagnostics::default(),
    };
    let counts = result.violation_counts();
    assert_eq!(counts[&ReplayViolationType::OutcomeDivergence], 2);
    assert_eq!(counts[&ReplayViolationType::SequenceGap], 1);
    assert!(result.has_violation(&ReplayViolationType::OutcomeDivergence));
    assert!(result.has_error_code(&ReplayErrorCode::SequenceGap));
    assert_eq!(result.violations_at(1).len(), 2);
    assert_eq!(result.violations_at(0).len(), 1);
    assert_eq!(result.violations_at(99).len(), 0);
}

#[test]
fn result_serde_roundtrip() {
    let result = ReplayResult {
        entries_processed: 10,
        entries_skipped: 2,
        violations: vec![ReplayViolation {
            sequence: 5,
            entry_id: "ev-5".into(),
            violation_type: ReplayViolationType::EpochRegression,
            error_code: ReplayErrorCode::EpochRegression,
            detail: "epoch 1 < 5".into(),
            expected: Some(">= 5".into()),
            actual: Some("1".into()),
        }],
        passed: false,
        final_rolling_hash: ContentHash::compute(b"hash"),
        epoch: SecurityEpoch::from_raw(42),
        diagnostics: ReplayDiagnostics::default(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let parsed: ReplayResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayEvidenceArtifact — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn evidence_artifact_serde() {
    let artifact = ReplayEvidenceArtifact {
        manifest: ReplayManifest {
            config: ReplayConfig::default(),
            source_entry_count: 3,
            first_entry_hash: None,
            last_entry_hash: None,
            final_rolling_hash: ContentHash::compute(b"test"),
            passed: true,
            violation_count: 0,
        },
        diagnostics: ReplayDiagnostics::default(),
        violations: vec![],
        events: vec![],
        gate_passed: true,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let parsed: ReplayEvidenceArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════
// EvidenceReplayChecker — construction & empty replay
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn checker_new_has_default_epoch() {
    let checker = EvidenceReplayChecker::new(ReplayConfig::default());
    assert_eq!(checker.config(), &ReplayConfig::default());
    assert!(checker.events().is_empty());
}

#[test]
fn checker_set_epoch() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.set_epoch(SecurityEpoch::from_raw(99));
    let result = checker.replay(&[], None);
    assert_eq!(result.epoch, SecurityEpoch::from_raw(99));
}

#[test]
fn checker_empty_ledger_passes() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&[], None);
    assert!(result.passed);
    assert_eq!(result.entries_processed, 0);
    assert_eq!(result.entries_skipped, 0);
    assert!(result.violations.is_empty());
}

#[test]
fn checker_clear_events() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let ledger = build_chained_ledger(1);
    checker.replay(&ledger, None);
    assert!(!checker.events().is_empty());
    checker.clear_events();
    assert!(checker.events().is_empty());
}

#[test]
fn checker_serde_roundtrip() {
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    checker.set_epoch(SecurityEpoch::from_raw(42));
    let json = serde_json::to_string(&checker).unwrap();
    let parsed: EvidenceReplayChecker = serde_json::from_str(&json).unwrap();
    assert_eq!(checker.config(), parsed.config());
}

// ═══════════════════════════════════════════════════════════════════════════
// EvidenceReplayChecker — replay with constructed entries
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn checker_single_entry_structural_checks() {
    let ledger = build_chained_ledger(1);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.passed);
    assert_eq!(result.entries_processed, 1);
}

#[test]
fn checker_multiple_entries_pass_structural() {
    let ledger = build_chained_ledger(5);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.passed, "violations: {:?}", result.violations);
    assert_eq!(result.entries_processed, 5);
}

#[test]
fn checker_tampered_artifact_detected() {
    let mut ledger = build_chained_ledger(3);
    // Tamper with the ledger entry (changing ts makes artifact hash fail)
    ledger[1].ledger_entry = EvidenceLedgerBuilder::new()
        .ts_unix_ms(999)
        .component("tampered")
        .action("tampered_action")
        .chosen_expected_loss(0.0)
        .calibration_score(0.0)
        .fallback_active(false)
        .posterior(vec![0.5, 0.5])
        .expected_loss("x", 0.0)
        .build()
        .unwrap();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(!result.passed);
    assert!(result.has_violation(&ReplayViolationType::ArtifactHashMismatch));
}

#[test]
fn checker_sequence_gap_detected() {
    let mut ledger = build_chained_ledger(3);
    ledger[1].sequence = 5; // gap: expected 1, got 5
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.has_violation(&ReplayViolationType::SequenceGap));
}

#[test]
fn checker_timestamp_regression_detected() {
    let mut ledger = build_chained_ledger(3);
    ledger[2].ts_unix_ms = ledger[0].ts_unix_ms - 1;
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.has_violation(&ReplayViolationType::TimestampMonotonicityViolation));
}

#[test]
fn checker_epoch_regression_detected() {
    let mut ledger = build_chained_ledger(3);
    ledger[1].epoch = SecurityEpoch::from_raw(10);
    ledger[2].epoch = SecurityEpoch::from_raw(1);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.has_violation(&ReplayViolationType::EpochRegression));
}

#[test]
fn checker_schema_migration_tracked() {
    let mut ledger = build_chained_ledger(3);
    ledger[2].schema_version = "2.0.0".into();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert_eq!(result.diagnostics.schema_migrations.len(), 1);
    assert_eq!(result.diagnostics.schema_versions_seen.len(), 2);
    // Not a violation by default
    assert!(!result.has_violation(&ReplayViolationType::SchemaMigration));
}

#[test]
fn checker_policy_transition_tracked() {
    let mut ledger = build_chained_ledger(3);
    ledger[1].policy_id = "policy-v2".into();
    ledger[2].policy_id = "policy-v2".into();
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert_eq!(result.diagnostics.policy_transitions.len(), 1);
    assert_eq!(result.diagnostics.policy_versions_seen.len(), 2);
}

#[test]
fn checker_halt_on_first_stops_early() {
    let mut ledger = build_chained_ledger(5);
    ledger[1].sequence = 10; // gap
    ledger[2].sequence = 20; // another gap
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
fn checker_replay_and_collect_produces_artifact() {
    let ledger = build_chained_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let artifact = checker.replay_and_collect(&ledger, None);
    assert_eq!(artifact.manifest.source_entry_count, 3);
    assert!(!artifact.events.is_empty());
}

#[test]
fn cross_machine_determinism_empty_ledger() {
    assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
        &ReplayConfig::default(),
        &[],
        None,
    ));
}

#[test]
fn cross_machine_determinism_with_entries() {
    let ledger = build_chained_ledger(5);
    assert!(EvidenceReplayChecker::verify_cross_machine_determinism(
        &ReplayConfig::default(),
        &ledger,
        None,
    ));
}

#[test]
fn diagnostics_timestamp_range_tracked() {
    let ledger = build_chained_ledger(5);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.diagnostics.first_ts.is_some());
    assert!(result.diagnostics.last_ts.is_some());
    let first = result.diagnostics.first_ts.unwrap();
    let last = result.diagnostics.last_ts.unwrap();
    assert!(first <= last);
}

#[test]
fn diagnostics_epoch_range_tracked() {
    let ledger = build_chained_ledger(3);
    let mut checker = EvidenceReplayChecker::new(ReplayConfig::default());
    let result = checker.replay(&ledger, None);
    assert!(result.diagnostics.epoch_range.is_some());
    let (lo, hi) = result.diagnostics.epoch_range.unwrap();
    assert!(lo <= hi);
}
