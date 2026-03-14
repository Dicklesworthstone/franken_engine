//! Integration tests for cross_workload_transfer (RGC-612B).
//!
//! Tests the full transfer pipeline: candidate evaluation, drift detection,
//! rollback enforcement, and report generation.

use frankenengine_engine::cross_workload_transfer::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn session_at_epoch(epoch: u64) -> TransferSession {
    TransferSession::new(
        "integration-session".to_string(),
        ContentHash::compute(b"recipient-workload"),
        SecurityEpoch::from_raw(epoch),
        TransferConfig::default(),
    )
}

fn candidate(key: &str, kind: TransferableKind, proximity: i64) -> TransferCandidate {
    TransferCandidate {
        candidate_key: key.to_string(),
        kind,
        donor_embedding_hash: ContentHash::compute(format!("donor-{key}").as_bytes()),
        prior_hash: ContentHash::compute(format!("prior-{key}").as_bytes()),
        proximity_score: proximity,
        donor_performance_estimate: 150_000,
        donor_epoch: SecurityEpoch::from_raw(3),
        donor_label: format!("donor-{key}"),
    }
}

fn drift(kind: DriftKind, magnitude: i64, confident: bool) -> DriftSignal {
    DriftSignal {
        kind,
        magnitude_millionths: magnitude,
        observation_count: 50,
        confident,
        evidence_hash: ContentHash::compute(format!("evidence-{kind}-{magnitude}").as_bytes()),
    }
}

// ---------------------------------------------------------------------------
// Pipeline integration
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_accept_monitor_rollback() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 2;

    // Accept a candidate.
    let c = candidate("full", TransferableKind::RewritePack, 900_000);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Accepted);

    // Record some clean observations.
    for _ in 0..5 {
        session.record_clean_observation("full");
    }
    assert!(session.enforce_drift_guards().is_empty());

    // Now record a significant drift.
    session.record_drift(
        "full",
        drift(DriftKind::PerformanceRegression, 250_000, true),
    );

    let rollbacks = session.enforce_drift_guards();
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].candidate_key, "full");
    assert!(!rollbacks[0].trigger_signals.is_empty());

    // Verify report.
    let report = session.build_report();
    assert_eq!(report.accepted, 1);
    assert_eq!(report.rolled_back_count, 1);
    assert_eq!(report.active_count, 0);
}

#[test]
fn multi_kind_pipeline() {
    let mut session = session_at_epoch(5);

    // Accept one of each kind.
    for (i, kind) in TransferableKind::ALL.iter().enumerate() {
        let c = candidate(&format!("mk{i}"), *kind, 850_000);
        let d = session.evaluate_candidate(&c);
        assert_eq!(
            d.verdict,
            TransferVerdict::Accepted,
            "kind {kind:?} should be accepted"
        );
    }

    assert_eq!(session.active_transfers.len(), TransferableKind::ALL.len());

    let report = session.build_report();
    assert_eq!(report.accepted, TransferableKind::ALL.len() as u64);
    assert!(report.is_healthy());
}

#[test]
fn mixed_verdict_pipeline() {
    let mut session = session_at_epoch(5);

    // Good candidate.
    let c1 = candidate("good", TransferableKind::RewritePack, 900_000);
    assert_eq!(
        session.evaluate_candidate(&c1).verdict,
        TransferVerdict::Accepted
    );

    // Low proximity.
    let c2 = candidate("low", TransferableKind::CacheHint, 100_000);
    assert_eq!(
        session.evaluate_candidate(&c2).verdict,
        TransferVerdict::Rejected
    );

    // Blocked kind.
    session
        .config
        .blocked_kinds
        .insert(TransferableKind::AotArtifact);
    let c3 = candidate("blocked", TransferableKind::AotArtifact, 900_000);
    assert_eq!(
        session.evaluate_candidate(&c3).verdict,
        TransferVerdict::Rejected
    );

    let report = session.build_report();
    assert_eq!(report.total_candidates, 3);
    assert_eq!(report.accepted, 1);
    assert_eq!(report.rejected, 2);
}

#[test]
fn epoch_gap_enforcement() {
    let mut session = session_at_epoch(20);
    session.config.max_epoch_gap = 5;

    // Donor at epoch 3 → gap = 17 > 5.
    let c = candidate("stale", TransferableKind::TieringPrior, 900_000);
    let d = session.evaluate_candidate(&c);
    assert_eq!(d.verdict, TransferVerdict::Rejected);
    assert_eq!(d.reason, Some(TransferRejectionReason::EpochGapTooLarge));
}

#[test]
fn epoch_gap_within_tolerance() {
    let mut session = session_at_epoch(5);
    session.config.max_epoch_gap = 5;

    // Donor at epoch 3 → gap = 2 ≤ 5.
    let c = candidate("fresh", TransferableKind::TieringPrior, 900_000);
    let d = session.evaluate_candidate(&c);
    assert_eq!(d.verdict, TransferVerdict::Accepted);
}

#[test]
fn rollback_cooldown_prevents_re_transfer() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;
    session.config.rollback_cooldown_epochs = 3;

    // Accept → drift → rollback.
    let c1 = candidate("c1", TransferableKind::CacheHint, 900_000);
    session.evaluate_candidate(&c1);
    session.record_drift("c1", drift(DriftKind::CachePollution, 300_000, true));
    session.record_clean_observation("c1");
    session.enforce_drift_guards();

    // Now try to transfer another CacheHint — should be deferred.
    let c2 = candidate("c2", TransferableKind::CacheHint, 900_000);
    let d = session.evaluate_candidate(&c2);
    assert_eq!(d.verdict, TransferVerdict::Deferred);
    assert_eq!(d.reason, Some(TransferRejectionReason::RecentRollback));

    // Other kinds still work.
    let c3 = candidate("c3", TransferableKind::RewritePack, 900_000);
    assert_eq!(
        session.evaluate_candidate(&c3).verdict,
        TransferVerdict::Accepted
    );
}

#[test]
fn already_present_prior_rejected() {
    let mut session = session_at_epoch(5);
    let c = candidate("existing", TransferableKind::RewritePack, 900_000);
    session.local_prior_hashes.insert(c.prior_hash);

    let d = session.evaluate_candidate(&c);
    assert_eq!(d.verdict, TransferVerdict::Rejected);
    assert_eq!(d.reason, Some(TransferRejectionReason::AlreadyPresent));
}

#[test]
fn budget_exhaustion_defers() {
    let mut session = session_at_epoch(5);
    session.config.max_active_transfers = 2;

    let c1 = candidate("c1", TransferableKind::RewritePack, 900_000);
    let c2 = candidate("c2", TransferableKind::CacheHint, 900_000);
    let c3 = candidate("c3", TransferableKind::TieringPrior, 900_000);

    assert_eq!(
        session.evaluate_candidate(&c1).verdict,
        TransferVerdict::Accepted
    );
    assert_eq!(
        session.evaluate_candidate(&c2).verdict,
        TransferVerdict::Accepted
    );
    assert_eq!(
        session.evaluate_candidate(&c3).verdict,
        TransferVerdict::Deferred
    );
}

#[test]
fn negative_performance_estimate_rejected() {
    let mut session = session_at_epoch(5);
    let mut c = candidate("negative", TransferableKind::RewritePack, 900_000);
    c.donor_performance_estimate = -10_000;

    let d = session.evaluate_candidate(&c);
    assert_eq!(d.verdict, TransferVerdict::Rejected);
    assert_eq!(
        d.reason,
        Some(TransferRejectionReason::InsufficientEvidence)
    );
}

#[test]
fn drift_kinds_all_detected() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;

    for kind in DriftKind::ALL {
        let key = format!("d-{kind}");
        let c = candidate(&key, TransferableKind::RewritePack, 900_000);
        session.evaluate_candidate(&c);
        session.record_drift(&key, drift(*kind, 200_000, true));
        session.record_clean_observation(&key);
    }

    let rollbacks = session.enforce_drift_guards();
    assert_eq!(rollbacks.len(), DriftKind::ALL.len());
}

#[test]
fn drift_not_confident_does_not_trigger_rollback() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;

    let c = candidate("c1", TransferableKind::SpecializationGuard, 900_000);
    session.evaluate_candidate(&c);

    // High magnitude but not confident.
    session.record_drift("c1", drift(DriftKind::TypeFeedbackMismatch, 500_000, false));
    session.record_clean_observation("c1");

    assert!(session.enforce_drift_guards().is_empty());
    assert!(!session.active_transfers[0].rolled_back);
}

#[test]
fn drift_below_tolerance_does_not_trigger_rollback() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;

    let c = candidate("c1", TransferableKind::RewritePack, 900_000);
    session.evaluate_candidate(&c);

    // Below default tolerance of 150_000.
    session.record_drift("c1", drift(DriftKind::PerformanceRegression, 100_000, true));
    session.record_clean_observation("c1");

    assert!(session.enforce_drift_guards().is_empty());
}

#[test]
fn multiple_drift_signals_on_same_transfer() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;

    let c = candidate("multi", TransferableKind::CacheHint, 900_000);
    session.evaluate_candidate(&c);

    session.record_drift("multi", drift(DriftKind::CachePollution, 80_000, true));
    session.record_drift(
        "multi",
        drift(DriftKind::PerformanceRegression, 200_000, true),
    );
    session.record_clean_observation("multi");

    let rollbacks = session.enforce_drift_guards();
    assert_eq!(rollbacks.len(), 1);
    // Trigger signals should include the one exceeding tolerance.
    assert!(
        rollbacks[0]
            .trigger_signals
            .iter()
            .any(|s| s.kind == DriftKind::PerformanceRegression)
    );
}

#[test]
fn rollback_history_truncation() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;

    for i in 0..20 {
        let c = candidate(&format!("trunc{i}"), TransferableKind::RewritePack, 900_000);
        session.evaluate_candidate(&c);
        session.record_drift(
            &format!("trunc{i}"),
            drift(DriftKind::CorrectnessDivergence, 400_000, true),
        );
        session.record_clean_observation(&format!("trunc{i}"));
        session.enforce_drift_guards();
        session.kind_rollback_epochs.clear(); // Reset cooldown for next.
    }

    assert!(session.rollback_history.len() <= MAX_ROLLBACK_HISTORY);
}

#[test]
fn allowlist_restricts_kinds() {
    let mut session = session_at_epoch(5);
    session
        .config
        .allowed_kinds
        .insert(TransferableKind::CacheHint);

    let c1 = candidate("allowed", TransferableKind::CacheHint, 900_000);
    assert_eq!(
        session.evaluate_candidate(&c1).verdict,
        TransferVerdict::Accepted
    );

    let c2 = candidate("not-allowed", TransferableKind::RewritePack, 900_000);
    assert_eq!(
        session.evaluate_candidate(&c2).verdict,
        TransferVerdict::Rejected
    );
}

#[test]
fn blocklist_takes_precedence() {
    let mut session = session_at_epoch(5);
    session
        .config
        .allowed_kinds
        .insert(TransferableKind::CacheHint);
    session
        .config
        .blocked_kinds
        .insert(TransferableKind::CacheHint);

    let c = candidate("conflict", TransferableKind::CacheHint, 900_000);
    let d = session.evaluate_candidate(&c);
    assert_eq!(d.verdict, TransferVerdict::Rejected);
    assert_eq!(d.reason, Some(TransferRejectionReason::KindBlocked));
}

#[test]
fn report_kind_stats() {
    let mut session = session_at_epoch(5);

    let c1 = candidate("rw", TransferableKind::RewritePack, 900_000);
    let c2 = candidate("ch", TransferableKind::CacheHint, 900_000);
    let c3 = candidate("rw2", TransferableKind::RewritePack, 100_000); // rejected

    session.evaluate_candidate(&c1);
    session.evaluate_candidate(&c2);
    session.evaluate_candidate(&c3);

    let report = session.build_report();
    if let Some(rw_stats) = report.kind_stats.get(&TransferableKind::RewritePack) {
        assert_eq!(rw_stats.accepted, 1);
        // c3 is rejected but we can only track kind for accepted candidates
        // since rejected ones don't enter active_transfers.
    }
}

#[test]
fn decision_hash_is_content_addressed() {
    let mut s1 = session_at_epoch(5);
    let mut s2 = session_at_epoch(5);
    let c = candidate("deterministic", TransferableKind::RewritePack, 900_000);

    let d1 = s1.evaluate_candidate(&c);
    let d2 = s2.evaluate_candidate(&c);

    assert_eq!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn different_sessions_different_report_hashes() {
    let mut s1 = session_at_epoch(5);
    let mut s2 = session_at_epoch(6);
    let c = candidate("diff", TransferableKind::RewritePack, 900_000);
    s1.evaluate_candidate(&c);
    s2.evaluate_candidate(&c);

    let r1 = s1.build_report();
    let r2 = s2.build_report();
    assert_ne!(r1.report_hash, r2.report_hash);
}

#[test]
fn render_decision_summary_all_verdicts() {
    let accepted = TransferDecision {
        candidate_key: "a".to_string(),
        verdict: TransferVerdict::Accepted,
        reason: None,
        decision_hash: ContentHash::compute(b"a"),
        epoch: SecurityEpoch::from_raw(1),
    };
    assert!(render_decision_summary(&accepted).contains("[ACCEPTED]"));

    let rejected = TransferDecision {
        candidate_key: "r".to_string(),
        verdict: TransferVerdict::Rejected,
        reason: Some(TransferRejectionReason::KindBlocked),
        decision_hash: ContentHash::compute(b"r"),
        epoch: SecurityEpoch::from_raw(1),
    };
    let s = render_decision_summary(&rejected);
    assert!(s.contains("[REJECTED]"));
    assert!(s.contains("kind_blocked"));

    let deferred = TransferDecision {
        candidate_key: "d".to_string(),
        verdict: TransferVerdict::Deferred,
        reason: Some(TransferRejectionReason::BudgetExhausted),
        decision_hash: ContentHash::compute(b"d"),
        epoch: SecurityEpoch::from_raw(1),
    };
    let s = render_decision_summary(&deferred);
    assert!(s.contains("[DEFERRED]"));
    assert!(s.contains("budget_exhausted"));
}

#[test]
fn render_rollback_summary_with_multiple_triggers() {
    let rollback = TransferRollback {
        candidate_key: "multi".to_string(),
        kind: TransferableKind::SpecializationGuard,
        rollback_epoch: SecurityEpoch::from_raw(10),
        trigger_signals: vec![
            drift(DriftKind::TypeFeedbackMismatch, 300_000, true),
            drift(DriftKind::PerformanceRegression, 200_000, true),
        ],
        prior_hash: ContentHash::compute(b"multi"),
        rollback_hash: ContentHash::compute(b"rollback-multi"),
    };
    let s = render_rollback_summary(&rollback);
    assert!(s.contains("specialization_guard"));
    assert!(s.contains("type_feedback_mismatch"));
    assert!(s.contains("performance_regression"));
}

#[test]
fn session_full_serde_roundtrip() {
    let mut session = session_at_epoch(7);
    session.config.min_drift_observations = 1;

    let c1 = candidate("s1", TransferableKind::RewritePack, 900_000);
    session.evaluate_candidate(&c1);
    session.record_drift("s1", drift(DriftKind::CachePollution, 50_000, true));
    session.record_clean_observation("s1");

    let json = serde_json::to_string(&session).unwrap();
    let back: TransferSession = serde_json::from_str(&json).unwrap();
    assert_eq!(session, back);
}

#[test]
fn report_full_serde_roundtrip() {
    let mut session = session_at_epoch(5);
    let c = candidate("rser", TransferableKind::CacheHint, 900_000);
    session.evaluate_candidate(&c);
    let report = session.build_report();

    let json = serde_json::to_string(&report).unwrap();
    let back: TransferReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn clean_session_report_rates() {
    let session = session_at_epoch(5);
    let report = session.build_report();
    assert_eq!(report.acceptance_rate_millionths(), 0);
    assert_eq!(report.rollback_rate_millionths(), 0);
}

#[test]
fn report_acceptance_rate_computation() {
    let mut session = session_at_epoch(5);
    for i in 0..5 {
        let c = candidate(&format!("r{i}"), TransferableKind::RewritePack, 900_000);
        session.evaluate_candidate(&c);
    }
    let c_bad = candidate("bad", TransferableKind::RewritePack, 100_000);
    session.evaluate_candidate(&c_bad);

    let report = session.build_report();
    // 5 accepted out of 6 = ~833_333 millionths.
    assert!(report.acceptance_rate_millionths() > 800_000);
    assert!(report.acceptance_rate_millionths() < 850_000);
}

#[test]
fn concurrent_transfers_independent_drift() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;

    let c1 = candidate("ind1", TransferableKind::RewritePack, 900_000);
    let c2 = candidate("ind2", TransferableKind::CacheHint, 900_000);
    session.evaluate_candidate(&c1);
    session.evaluate_candidate(&c2);

    // Drift on c1 only.
    session.record_drift(
        "ind1",
        drift(DriftKind::PerformanceRegression, 300_000, true),
    );
    session.record_clean_observation("ind1");
    session.record_clean_observation("ind2");
    session.record_clean_observation("ind2");

    let rollbacks = session.enforce_drift_guards();
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].candidate_key, "ind1");

    // c2 still active.
    assert!(!session.active_transfers[1].rolled_back);
}

#[test]
fn proximity_boundary_values() {
    let mut session = session_at_epoch(5);

    // Exactly at threshold.
    let c_at = candidate("at", TransferableKind::RewritePack, MIN_PROXIMITY_SCORE);
    assert_eq!(
        session.evaluate_candidate(&c_at).verdict,
        TransferVerdict::Accepted
    );

    // Just below.
    let c_below = candidate(
        "below",
        TransferableKind::CacheHint,
        MIN_PROXIMITY_SCORE - 1,
    );
    assert_eq!(
        session.evaluate_candidate(&c_below).verdict,
        TransferVerdict::Rejected
    );
}

#[test]
fn max_epoch_gap_boundary() {
    let mut session = session_at_epoch(13);
    session.config.max_epoch_gap = 10;

    // donor at 3 → gap = 10, exactly at limit.
    let c_at = candidate("at", TransferableKind::RewritePack, 900_000);
    assert_eq!(
        session.evaluate_candidate(&c_at).verdict,
        TransferVerdict::Accepted
    );

    // donor at 2 → gap = 11, over limit.
    let mut c_over = candidate("over", TransferableKind::CacheHint, 900_000);
    c_over.donor_epoch = SecurityEpoch::from_raw(2);
    assert_eq!(
        session.evaluate_candidate(&c_over).verdict,
        TransferVerdict::Rejected
    );
}

#[test]
fn config_serde_roundtrip_with_kinds() {
    let mut config = TransferConfig::default();
    config.allowed_kinds.insert(TransferableKind::CacheHint);
    config.blocked_kinds.insert(TransferableKind::AotArtifact);
    config.max_epoch_gap = 20;
    config.drift_tolerance = 200_000;

    let json = serde_json::to_string(&config).unwrap();
    let back: TransferConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn transfer_report_display_format() {
    let mut session = session_at_epoch(5);
    let c = candidate("disp", TransferableKind::RewritePack, 900_000);
    session.evaluate_candidate(&c);

    let report = session.build_report();
    let display = format!("{report}");
    assert!(display.contains("TransferReport"));
    assert!(display.contains("integration-session"));
    assert!(display.contains("accepted=1"));
}

#[test]
fn schema_version_stable() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.cross-workload-transfer.v1");
    assert_eq!(COMPONENT, "cross_workload_transfer");
    assert_eq!(BEAD_ID, "bd-1lsy.7.12.2");
    assert_eq!(POLICY_ID, "RGC-612B");
}

#[test]
fn constants_reasonable() {
    const {
        assert!(MAX_TRANSFER_CANDIDATES > 0);
        assert!(MAX_ACTIVE_TRANSFERS >= MAX_TRANSFER_CANDIDATES);
        assert!(DEFAULT_DRIFT_TOLERANCE > 0);
        assert!(MIN_PROXIMITY_SCORE > 0);
        assert!(MIN_DRIFT_OBSERVATIONS > 0);
        assert!(MAX_ROLLBACK_HISTORY > 0);
    }
}

#[test]
fn kind_transfer_stats_roundtrip() {
    let stats = KindTransferStats {
        total: 20,
        accepted: 15,
        rejected: 3,
        deferred: 2,
    };
    assert_eq!(stats.acceptance_rate_millionths(), 750_000);

    let json = serde_json::to_string(&stats).unwrap();
    let back: KindTransferStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
}

#[test]
fn active_transfer_confident_drift_kind_count() {
    let transfer = ActiveTransfer {
        candidate_key: "kinds".to_string(),
        kind: TransferableKind::RewritePack,
        prior_hash: ContentHash::compute(b"kinds"),
        accepted_epoch: SecurityEpoch::from_raw(1),
        drift_signals: vec![
            drift(DriftKind::PerformanceRegression, 100_000, true),
            drift(DriftKind::CachePollution, 80_000, true),
            drift(DriftKind::TypeFeedbackMismatch, 50_000, false), // not confident
            drift(DriftKind::PerformanceRegression, 120_000, true), // duplicate kind
        ],
        observation_count: 50,
        rolled_back: false,
        decision_hash: ContentHash::compute(b"d"),
    };
    // 2 confident distinct kinds: PerformanceRegression, CachePollution.
    assert_eq!(transfer.confident_drift_kind_count(), 2);
}

#[test]
fn record_clean_observation_returns_false_for_unknown() {
    let mut session = session_at_epoch(5);
    assert!(!session.record_clean_observation("nonexistent"));
}

#[test]
fn record_clean_observation_increments_count() {
    let mut session = session_at_epoch(5);
    let c = candidate("obs", TransferableKind::RewritePack, 900_000);
    session.evaluate_candidate(&c);

    for _ in 0..10 {
        session.record_clean_observation("obs");
    }
    assert_eq!(session.active_transfers[0].observation_count, 10);
}

#[test]
fn specimen_helpers_valid() {
    let c = specimen_candidate("test", TransferableKind::AotArtifact, 500_000);
    assert_eq!(c.kind, TransferableKind::AotArtifact);
    assert_eq!(c.proximity_score, 500_000);

    let s = specimen_drift_signal(DriftKind::EpochDrift, 100_000, true);
    assert_eq!(s.kind, DriftKind::EpochDrift);
    assert!(s.confident);

    let session = specimen_session();
    assert_eq!(session.epoch, SecurityEpoch::from_raw(5));
}

#[test]
fn stress_many_candidates() {
    let mut session = session_at_epoch(5);
    session.config.max_active_transfers = 200;

    for i in 0..100 {
        let kind = TransferableKind::ALL[i % TransferableKind::ALL.len()];
        let c = candidate(&format!("stress{i}"), kind, 900_000);
        let d = session.evaluate_candidate(&c);
        assert_eq!(d.verdict, TransferVerdict::Accepted);
    }

    let report = session.build_report();
    assert_eq!(report.accepted, 100);
    assert_eq!(report.active_count, 100);
    assert!(report.is_healthy());
}

#[test]
fn drift_signal_exceeds_tolerance_boundary() {
    // magnitude exactly at tolerance → does NOT exceed.
    let at = drift(
        DriftKind::PerformanceRegression,
        DEFAULT_DRIFT_TOLERANCE,
        true,
    );
    assert!(!at.exceeds_tolerance(DEFAULT_DRIFT_TOLERANCE));

    // one above → exceeds.
    let above = drift(
        DriftKind::PerformanceRegression,
        DEFAULT_DRIFT_TOLERANCE + 1,
        true,
    );
    assert!(above.exceeds_tolerance(DEFAULT_DRIFT_TOLERANCE));
}

#[test]
fn transfer_session_new_stores_all_fields() {
    let session = TransferSession::new(
        "my-session".to_string(),
        ContentHash::compute(b"emb"),
        SecurityEpoch::from_raw(7),
        TransferConfig::default(),
    );
    assert_eq!(session.session_key, "my-session");
    assert_eq!(session.epoch.as_u64(), 7);
    assert!(session.decisions.is_empty());
    assert!(session.active_transfers.is_empty());
    assert!(session.local_prior_hashes.is_empty());
    assert!(session.kind_rollback_epochs.is_empty());
}

// ---------------------------------------------------------------------------
// Additional edge-case / API coverage tests (15+)
// ---------------------------------------------------------------------------

#[test]
fn test_transferable_kind_all_length() {
    // ALL contains exactly 5 variants.
    assert_eq!(TransferableKind::ALL.len(), 5);
}

#[test]
fn test_drift_kind_all_length() {
    assert_eq!(DriftKind::ALL.len(), 5);
}

#[test]
fn test_transferable_kind_display_values() {
    assert_eq!(format!("{}", TransferableKind::RewritePack), "rewrite_pack");
    assert_eq!(
        format!("{}", TransferableKind::TieringPrior),
        "tiering_prior"
    );
    assert_eq!(format!("{}", TransferableKind::CacheHint), "cache_hint");
    assert_eq!(format!("{}", TransferableKind::AotArtifact), "aot_artifact");
    assert_eq!(
        format!("{}", TransferableKind::SpecializationGuard),
        "specialization_guard"
    );
}

#[test]
fn test_drift_kind_display_values() {
    assert_eq!(
        format!("{}", DriftKind::PerformanceRegression),
        "performance_regression"
    );
    assert_eq!(
        format!("{}", DriftKind::CorrectnessDivergence),
        "correctness_divergence"
    );
    assert_eq!(
        format!("{}", DriftKind::TypeFeedbackMismatch),
        "type_feedback_mismatch"
    );
    assert_eq!(format!("{}", DriftKind::CachePollution), "cache_pollution");
    assert_eq!(format!("{}", DriftKind::EpochDrift), "epoch_drift");
}

#[test]
fn test_transfer_verdict_display_values() {
    assert_eq!(format!("{}", TransferVerdict::Accepted), "accepted");
    assert_eq!(format!("{}", TransferVerdict::Rejected), "rejected");
    assert_eq!(format!("{}", TransferVerdict::Deferred), "deferred");
}

#[test]
fn test_rejection_reason_display_all_variants() {
    use std::collections::BTreeSet;
    let variants = [
        TransferRejectionReason::ProximityTooLow,
        TransferRejectionReason::BudgetExhausted,
        TransferRejectionReason::KindBlocked,
        TransferRejectionReason::EpochGapTooLarge,
        TransferRejectionReason::AlreadyPresent,
        TransferRejectionReason::RecentRollback,
        TransferRejectionReason::InsufficientEvidence,
    ];
    // All display strings are distinct non-empty strings.
    let strs: BTreeSet<String> = variants.iter().map(|r| format!("{r}")).collect();
    assert_eq!(strs.len(), variants.len());
    for s in &strs {
        assert!(!s.is_empty());
    }
}

#[test]
fn test_rejection_reason_serde_all_variants() {
    let variants = [
        TransferRejectionReason::ProximityTooLow,
        TransferRejectionReason::BudgetExhausted,
        TransferRejectionReason::KindBlocked,
        TransferRejectionReason::EpochGapTooLarge,
        TransferRejectionReason::AlreadyPresent,
        TransferRejectionReason::RecentRollback,
        TransferRejectionReason::InsufficientEvidence,
    ];
    for r in &variants {
        let json = serde_json::to_string(r).unwrap();
        let back: TransferRejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn test_drift_signal_exceeds_tolerance_not_confident() {
    // A signal that is not confident never exceeds tolerance, regardless of magnitude.
    let signal = DriftSignal {
        kind: DriftKind::PerformanceRegression,
        magnitude_millionths: 1_000_000, // extremely high
        observation_count: 100,
        confident: false,
        evidence_hash: ContentHash::compute(b"not-confident"),
    };
    assert!(!signal.exceeds_tolerance(100_000));
    assert!(!signal.exceeds_tolerance(0));
}

#[test]
fn test_drift_signal_exceeds_tolerance_zero_magnitude() {
    // Zero magnitude with confident = true still does not exceed a positive tolerance.
    let signal = DriftSignal {
        kind: DriftKind::CachePollution,
        magnitude_millionths: 0,
        observation_count: 10,
        confident: true,
        evidence_hash: ContentHash::compute(b"zero-mag"),
    };
    assert!(!signal.exceeds_tolerance(1));
    assert!(!signal.exceeds_tolerance(0));
}

#[test]
fn test_active_transfer_worst_drift_no_signals() {
    let transfer = ActiveTransfer {
        candidate_key: "empty".to_string(),
        kind: TransferableKind::CacheHint,
        prior_hash: ContentHash::compute(b"empty"),
        accepted_epoch: SecurityEpoch::from_raw(1),
        drift_signals: vec![],
        observation_count: 0,
        rolled_back: false,
        decision_hash: ContentHash::compute(b"d"),
    };
    assert_eq!(transfer.worst_drift_millionths(), 0);
    assert!(!transfer.exceeds_tolerance(DEFAULT_DRIFT_TOLERANCE));
    assert_eq!(transfer.confident_drift_kind_count(), 0);
}

#[test]
fn test_active_transfer_worst_drift_only_non_confident() {
    // Only non-confident signals — worst_drift_millionths should return 0 (filter for confident).
    let transfer = ActiveTransfer {
        candidate_key: "nc".to_string(),
        kind: TransferableKind::RewritePack,
        prior_hash: ContentHash::compute(b"nc"),
        accepted_epoch: SecurityEpoch::from_raw(2),
        drift_signals: vec![
            drift(DriftKind::PerformanceRegression, 500_000, false),
            drift(DriftKind::CachePollution, 800_000, false),
        ],
        observation_count: 20,
        rolled_back: false,
        decision_hash: ContentHash::compute(b"d"),
    };
    assert_eq!(transfer.worst_drift_millionths(), 0);
    assert!(!transfer.exceeds_tolerance(100_000));
    assert_eq!(transfer.confident_drift_kind_count(), 0);
}

#[test]
fn test_active_transfer_worst_drift_mixed_confidence() {
    let transfer = ActiveTransfer {
        candidate_key: "mixed".to_string(),
        kind: TransferableKind::TieringPrior,
        prior_hash: ContentHash::compute(b"mixed"),
        accepted_epoch: SecurityEpoch::from_raw(3),
        drift_signals: vec![
            drift(DriftKind::PerformanceRegression, 200_000, true),
            drift(DriftKind::CachePollution, 900_000, false), // not confident
            drift(DriftKind::EpochDrift, 300_000, true),
        ],
        observation_count: 30,
        rolled_back: false,
        decision_hash: ContentHash::compute(b"d"),
    };
    // Worst confident = 300_000.
    assert_eq!(transfer.worst_drift_millionths(), 300_000);
    assert!(transfer.exceeds_tolerance(250_000));
    assert!(!transfer.exceeds_tolerance(300_000)); // not strictly greater
    // Two confident distinct kinds: PerformanceRegression, EpochDrift.
    assert_eq!(transfer.confident_drift_kind_count(), 2);
}

#[test]
fn test_kind_transfer_stats_default_zero() {
    let stats = KindTransferStats::default();
    assert_eq!(stats.total, 0);
    assert_eq!(stats.accepted, 0);
    assert_eq!(stats.rejected, 0);
    assert_eq!(stats.deferred, 0);
    assert_eq!(stats.acceptance_rate_millionths(), 0);
}

#[test]
fn test_kind_transfer_stats_full_acceptance() {
    let stats = KindTransferStats {
        total: 10,
        accepted: 10,
        rejected: 0,
        deferred: 0,
    };
    assert_eq!(stats.acceptance_rate_millionths(), 1_000_000);
}

#[test]
fn test_kind_transfer_stats_zero_accepted() {
    let stats = KindTransferStats {
        total: 5,
        accepted: 0,
        rejected: 5,
        deferred: 0,
    };
    assert_eq!(stats.acceptance_rate_millionths(), 0);
}

#[test]
fn test_transfer_report_is_healthy_no_transfers() {
    let session = session_at_epoch(5);
    let report = session.build_report();
    // No candidates, no drift — healthy.
    assert!(report.is_healthy());
}

#[test]
fn test_transfer_report_not_healthy_high_rollback_rate() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;

    // Accept 3 candidates then roll all back → rollback_rate = 100%.
    for i in 0..3u32 {
        let c = candidate(&format!("rb{i}"), TransferableKind::RewritePack, 900_000);
        session.evaluate_candidate(&c);
        session.record_drift(
            &format!("rb{i}"),
            drift(DriftKind::CorrectnessDivergence, 500_000, true),
        );
        session.record_clean_observation(&format!("rb{i}"));
        session.enforce_drift_guards();
        // Reset cooldown so next kind can be accepted.
        session.kind_rollback_epochs.clear();
    }

    let report = session.build_report();
    // rollback_rate = 3/3 = 1_000_000 which is >= 300_000 → not healthy.
    assert!(!report.is_healthy());
}

#[test]
fn test_transfer_report_rollback_rate_computation() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;

    // Accept 4, roll back 1.
    for i in 0..4u32 {
        let c = candidate(&format!("rr{i}"), TransferableKind::CacheHint, 900_000);
        session.evaluate_candidate(&c);
    }
    session.record_drift(
        "rr0",
        drift(DriftKind::PerformanceRegression, 400_000, true),
    );
    session.record_clean_observation("rr0");
    session.enforce_drift_guards();

    let report = session.build_report();
    // rollback_rate = 1/4 = 250_000.
    assert_eq!(report.rollback_rate_millionths(), 250_000);
}

#[test]
fn test_record_drift_on_rolled_back_transfer_returns_false() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;

    let c = candidate("rolled", TransferableKind::RewritePack, 900_000);
    session.evaluate_candidate(&c);
    session.record_drift(
        "rolled",
        drift(DriftKind::PerformanceRegression, 500_000, true),
    );
    session.record_clean_observation("rolled");
    session.enforce_drift_guards();

    // Transfer is now rolled_back = true; further drift recording should fail.
    assert!(!session.record_drift("rolled", drift(DriftKind::CachePollution, 200_000, true)));
}

#[test]
fn test_record_drift_unknown_key_returns_false() {
    let mut session = session_at_epoch(5);
    assert!(!session.record_drift("no-such-key", drift(DriftKind::EpochDrift, 100_000, true)));
}

#[test]
fn test_config_kind_allowed_blocked_takes_priority_over_allowed() {
    let mut config = TransferConfig::default();
    // Even if a kind is in the allowed list, blocked takes precedence.
    config.allowed_kinds.insert(TransferableKind::TieringPrior);
    config.blocked_kinds.insert(TransferableKind::TieringPrior);
    assert!(!config.kind_allowed(TransferableKind::TieringPrior));
}

#[test]
fn test_config_kind_allowed_not_in_allowlist_when_allowlist_nonempty() {
    let mut config = TransferConfig::default();
    config.allowed_kinds.insert(TransferableKind::AotArtifact);
    // All other kinds should be rejected when allowlist is non-empty.
    for kind in TransferableKind::ALL {
        if *kind == TransferableKind::AotArtifact {
            assert!(config.kind_allowed(*kind));
        } else {
            assert!(!config.kind_allowed(*kind));
        }
    }
}

#[test]
fn test_transfer_candidate_clone_and_eq() {
    let c = candidate("clone-test", TransferableKind::CacheHint, 750_000);
    let c2 = c.clone();
    assert_eq!(c, c2);
    assert_eq!(c.candidate_key, c2.candidate_key);
    assert_eq!(c.kind, c2.kind);
    assert_eq!(c.proximity_score, c2.proximity_score);
}

#[test]
fn test_transfer_candidate_serde_roundtrip() {
    let c = TransferCandidate {
        candidate_key: "serde-cand".to_string(),
        kind: TransferableKind::AotArtifact,
        donor_embedding_hash: ContentHash::compute(b"emb"),
        prior_hash: ContentHash::compute(b"prior"),
        proximity_score: 800_000,
        donor_performance_estimate: 50_000,
        donor_epoch: SecurityEpoch::from_raw(4),
        donor_label: "donor-x".to_string(),
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: TransferCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn test_drift_signal_serde_roundtrip() {
    let s = DriftSignal {
        kind: DriftKind::TypeFeedbackMismatch,
        magnitude_millionths: 123_456,
        observation_count: 42,
        confident: true,
        evidence_hash: ContentHash::compute(b"ev"),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: DriftSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn test_transfer_decision_serde_roundtrip() {
    let d = TransferDecision {
        candidate_key: "dec-serde".to_string(),
        verdict: TransferVerdict::Rejected,
        reason: Some(TransferRejectionReason::ProximityTooLow),
        decision_hash: ContentHash::compute(b"dec"),
        epoch: SecurityEpoch::from_raw(9),
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: TransferDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn test_transfer_rollback_serde_roundtrip() {
    let rb = TransferRollback {
        candidate_key: "rb-serde".to_string(),
        kind: TransferableKind::SpecializationGuard,
        rollback_epoch: SecurityEpoch::from_raw(11),
        trigger_signals: vec![drift(DriftKind::EpochDrift, 200_000, true)],
        prior_hash: ContentHash::compute(b"prior"),
        rollback_hash: ContentHash::compute(b"rb"),
    };
    let json = serde_json::to_string(&rb).unwrap();
    let back: TransferRollback = serde_json::from_str(&json).unwrap();
    assert_eq!(rb, back);
}

#[test]
fn test_active_transfer_serde_roundtrip() {
    let at = ActiveTransfer {
        candidate_key: "at-serde".to_string(),
        kind: TransferableKind::TieringPrior,
        prior_hash: ContentHash::compute(b"prior"),
        accepted_epoch: SecurityEpoch::from_raw(3),
        drift_signals: vec![drift(DriftKind::CachePollution, 80_000, false)],
        observation_count: 7,
        rolled_back: false,
        decision_hash: ContentHash::compute(b"d"),
    };
    let json = serde_json::to_string(&at).unwrap();
    let back: ActiveTransfer = serde_json::from_str(&json).unwrap();
    assert_eq!(at, back);
}

#[test]
fn test_render_decision_summary_accepted_no_reason() {
    let d = TransferDecision {
        candidate_key: "acc-no-reason".to_string(),
        verdict: TransferVerdict::Accepted,
        reason: None,
        decision_hash: ContentHash::compute(b"x"),
        epoch: SecurityEpoch::from_raw(2),
    };
    let s = render_decision_summary(&d);
    assert!(s.contains("[ACCEPTED]"));
    assert!(s.contains("acc-no-reason"));
    assert!(s.contains("2")); // epoch
}

#[test]
fn test_render_decision_summary_rejected_with_reason() {
    let d = TransferDecision {
        candidate_key: "rej".to_string(),
        verdict: TransferVerdict::Rejected,
        reason: Some(TransferRejectionReason::EpochGapTooLarge),
        decision_hash: ContentHash::compute(b"r"),
        epoch: SecurityEpoch::from_raw(5),
    };
    let s = render_decision_summary(&d);
    assert!(s.contains("[REJECTED]"));
    assert!(s.contains("epoch_gap_too_large"));
}

#[test]
fn test_render_decision_summary_deferred_recent_rollback() {
    let d = TransferDecision {
        candidate_key: "def-rb".to_string(),
        verdict: TransferVerdict::Deferred,
        reason: Some(TransferRejectionReason::RecentRollback),
        decision_hash: ContentHash::compute(b"rb"),
        epoch: SecurityEpoch::from_raw(7),
    };
    let s = render_decision_summary(&d);
    assert!(s.contains("[DEFERRED]"));
    assert!(s.contains("recent_rollback"));
}

#[test]
fn test_render_rollback_summary_format() {
    let rb = TransferRollback {
        candidate_key: "render-rb".to_string(),
        kind: TransferableKind::AotArtifact,
        rollback_epoch: SecurityEpoch::from_raw(8),
        trigger_signals: vec![drift(DriftKind::CorrectnessDivergence, 400_000, true)],
        prior_hash: ContentHash::compute(b"p"),
        rollback_hash: ContentHash::compute(b"rh"),
    };
    let s = render_rollback_summary(&rb);
    assert!(s.contains("[ROLLBACK]"));
    assert!(s.contains("render-rb"));
    assert!(s.contains("aot_artifact"));
    assert!(s.contains("8"));
    assert!(s.contains("correctness_divergence"));
    assert!(s.contains("400000"));
}

#[test]
fn test_donor_epoch_newer_than_recipient_still_checked() {
    // Donor in the future (epoch > recipient epoch): gap computed by abs difference.
    let mut session = session_at_epoch(3);
    session.config.max_epoch_gap = 2;

    // Donor epoch = 3 (same) → gap 0 → accepted.
    let mut c_same = candidate("same", TransferableKind::CacheHint, 900_000);
    c_same.donor_epoch = SecurityEpoch::from_raw(3);
    assert_eq!(
        session.evaluate_candidate(&c_same).verdict,
        TransferVerdict::Accepted
    );

    // Donor epoch = 6 → gap = 3 > 2 → rejected.
    let mut c_future = candidate("future", TransferableKind::CacheHint, 900_000);
    c_future.donor_epoch = SecurityEpoch::from_raw(6);
    assert_eq!(
        session.evaluate_candidate(&c_future).verdict,
        TransferVerdict::Rejected
    );
}

#[test]
fn test_rollback_cooldown_boundary_exact() {
    // Rollback cooldown = 3. After exactly 3 epochs, should still be in cooldown.
    // After more than 3 epochs, should be out.
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;
    session.config.rollback_cooldown_epochs = 3;

    let c = candidate("cooldown-boundary", TransferableKind::AotArtifact, 900_000);
    session.evaluate_candidate(&c);
    session.record_drift(
        "cooldown-boundary",
        drift(DriftKind::CachePollution, 300_000, true),
    );
    session.record_clean_observation("cooldown-boundary");
    session.enforce_drift_guards();
    // kind_rollback_epochs[AotArtifact] = epoch 5.

    // At epoch 5, gap = 0 < 3 → still in cooldown.
    let c2 = candidate("c2", TransferableKind::AotArtifact, 900_000);
    assert_eq!(
        session.evaluate_candidate(&c2).verdict,
        TransferVerdict::Deferred
    );
}

#[test]
fn test_max_transfer_candidates_constant_gte_min_proximity() {
    // Sanity check: constants are in plausible fixed-point range.
    const {
        assert!(MIN_PROXIMITY_SCORE > 0);
        assert!(MIN_PROXIMITY_SCORE < 1_000_000);
        assert!(DEFAULT_DRIFT_TOLERANCE > 0);
        assert!(DEFAULT_DRIFT_TOLERANCE < 1_000_000);
    }
}

#[test]
fn test_specimen_candidate_fields() {
    let c = specimen_candidate("sp", TransferableKind::TieringPrior, 700_000);
    assert_eq!(c.candidate_key, "sp");
    assert_eq!(c.kind, TransferableKind::TieringPrior);
    assert_eq!(c.proximity_score, 700_000);
    assert!(c.donor_performance_estimate >= 0);
    assert_eq!(c.donor_label, "donor-sp");
}

#[test]
fn test_specimen_drift_signal_fields() {
    let s = specimen_drift_signal(DriftKind::EpochDrift, 50_000, false);
    assert_eq!(s.kind, DriftKind::EpochDrift);
    assert_eq!(s.magnitude_millionths, 50_000);
    assert!(!s.confident);
    assert_eq!(s.observation_count, 32);
}

#[test]
fn test_specimen_session_fields() {
    let s = specimen_session();
    assert_eq!(s.session_key, "test-session");
    assert_eq!(s.epoch.as_u64(), 5);
    assert!(s.decisions.is_empty());
    assert!(s.active_transfers.is_empty());
    assert!(s.rollback_history.is_empty());
}

#[test]
fn test_evaluate_candidate_zero_proximity() {
    let mut session = session_at_epoch(5);
    let mut c = candidate("zero-prox", TransferableKind::RewritePack, 0);
    c.proximity_score = 0;
    let d = session.evaluate_candidate(&c);
    assert_eq!(d.verdict, TransferVerdict::Rejected);
    assert_eq!(d.reason, Some(TransferRejectionReason::ProximityTooLow));
}

#[test]
fn test_session_decisions_accumulate_correctly() {
    let mut session = session_at_epoch(5);

    let c1 = candidate("acc1", TransferableKind::RewritePack, 900_000);
    let c2 = candidate("rej1", TransferableKind::CacheHint, 0); // will be rejected
    let c3 = candidate("acc2", TransferableKind::TieringPrior, 900_000);

    session.evaluate_candidate(&c1);
    session.evaluate_candidate(&c2);
    session.evaluate_candidate(&c3);

    assert_eq!(session.decisions.len(), 3);
    assert_eq!(session.decisions[0].verdict, TransferVerdict::Accepted);
    assert_eq!(session.decisions[1].verdict, TransferVerdict::Rejected);
    assert_eq!(session.decisions[2].verdict, TransferVerdict::Accepted);
}

#[test]
fn test_report_worst_drift_reflects_active_transfers() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 0; // no minimum so drift is tracked

    let c1 = candidate("d1", TransferableKind::RewritePack, 900_000);
    let c2 = candidate("d2", TransferableKind::CacheHint, 900_000);
    session.evaluate_candidate(&c1);
    session.evaluate_candidate(&c2);

    session.record_drift("d1", drift(DriftKind::PerformanceRegression, 80_000, true));
    session.record_drift("d2", drift(DriftKind::CachePollution, 120_000, true));

    let report = session.build_report();
    // worst_drift = max of worst_drift_millionths across active transfers = 120_000.
    assert_eq!(report.worst_drift_millionths, 120_000);
}

#[test]
fn test_report_deferred_count_matches_decisions() {
    let mut session = session_at_epoch(5);
    session.config.max_active_transfers = 1;

    let c1 = candidate("ac", TransferableKind::RewritePack, 900_000);
    let c2 = candidate("df1", TransferableKind::CacheHint, 900_000);
    let c3 = candidate("df2", TransferableKind::TieringPrior, 900_000);

    session.evaluate_candidate(&c1); // accepted
    session.evaluate_candidate(&c2); // deferred (budget)
    session.evaluate_candidate(&c3); // deferred (budget)

    let report = session.build_report();
    assert_eq!(report.accepted, 1);
    assert_eq!(report.deferred, 2);
    assert_eq!(report.rejected, 0);
    assert_eq!(report.total_candidates, 3);
}

#[test]
fn test_decision_epoch_matches_session_epoch() {
    let mut session = session_at_epoch(42);
    let c = candidate("epoch-check", TransferableKind::AotArtifact, 900_000);
    let d = session.evaluate_candidate(&c);
    assert_eq!(d.epoch.as_u64(), 42);
}

#[test]
fn test_rollback_record_contains_correct_kind() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 1;

    let c = candidate("kind-check", TransferableKind::SpecializationGuard, 900_000);
    session.evaluate_candidate(&c);
    session.record_drift(
        "kind-check",
        drift(DriftKind::TypeFeedbackMismatch, 300_000, true),
    );
    session.record_clean_observation("kind-check");

    let rollbacks = session.enforce_drift_guards();
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].kind, TransferableKind::SpecializationGuard);
    assert_eq!(rollbacks[0].rollback_epoch.as_u64(), 5);
    assert!(!rollbacks[0].trigger_signals.is_empty());
}

#[test]
fn test_enforce_drift_guards_below_min_observations_no_rollback() {
    let mut session = session_at_epoch(5);
    session.config.min_drift_observations = 100;

    let c = candidate("low-obs", TransferableKind::RewritePack, 900_000);
    session.evaluate_candidate(&c);
    session.record_drift(
        "low-obs",
        drift(DriftKind::PerformanceRegression, 500_000, true),
    );
    // Only 1 observation (drift record counts too), needs 100.
    assert!(session.enforce_drift_guards().is_empty());
}

#[test]
fn test_transfer_config_serde_with_empty_sets() {
    let config = TransferConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: TransferConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
    assert!(back.allowed_kinds.is_empty());
    assert!(back.blocked_kinds.is_empty());
}

#[test]
fn test_local_prior_hashes_prevent_duplicate_transfer() {
    let mut session = session_at_epoch(5);
    let c = candidate("dup", TransferableKind::TieringPrior, 900_000);

    // Accept once.
    let d1 = session.evaluate_candidate(&c);
    assert_eq!(d1.verdict, TransferVerdict::Accepted);

    // Manually add the prior hash to the local set to simulate it now being present.
    session.local_prior_hashes.insert(c.prior_hash);

    // Same candidate again → AlreadyPresent.
    let d2 = session.evaluate_candidate(&c);
    assert_eq!(d2.verdict, TransferVerdict::Rejected);
    assert_eq!(d2.reason, Some(TransferRejectionReason::AlreadyPresent));
}
