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
