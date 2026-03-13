//! Enrichment integration tests for `cross_workload_transfer` module.
//!
//! Covers Display uniqueness, serde roundtrips, method behavior, edge cases,
//! deterministic hashing, config logic, session lifecycle, drift/rollback,
//! report correctness, and render helpers.

use std::collections::BTreeSet;

use frankenengine_engine::cross_workload_transfer::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_session() -> TransferSession {
    specimen_session()
}

fn make_candidate(key: &str, kind: TransferableKind) -> TransferCandidate {
    specimen_candidate(key, kind, 800_000)
}

fn make_active_transfer(key: &str, kind: TransferableKind) -> ActiveTransfer {
    ActiveTransfer {
        candidate_key: key.to_string(),
        kind,
        prior_hash: ContentHash::compute(format!("prior-{key}").as_bytes()),
        accepted_epoch: SecurityEpoch::from_raw(5),
        drift_signals: Vec::new(),
        observation_count: 0,
        rolled_back: false,
        decision_hash: ContentHash::compute(format!("decision-{key}").as_bytes()),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_component_name_matches_module() {
    assert_eq!(COMPONENT, "cross_workload_transfer");
}

#[test]
fn enrichment_bead_id_non_empty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_policy_id_non_empty() {
    assert!(!POLICY_ID.is_empty());
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn enrichment_default_constants_sane() {
    const {
        assert!(MAX_TRANSFER_CANDIDATES > 0);
        assert!(MAX_ACTIVE_TRANSFERS > 0);
        assert!(DEFAULT_DRIFT_TOLERANCE > 0);
        assert!(MIN_PROXIMITY_SCORE > 0);
        assert!(MIN_DRIFT_OBSERVATIONS > 0);
        assert!(MAX_ROLLBACK_HISTORY > 0);
        // Drift tolerance should be well under 1.0 (1_000_000)
        assert!(DEFAULT_DRIFT_TOLERANCE < 1_000_000);
        // Proximity score should be between 0 and 1.0
        assert!(MIN_PROXIMITY_SCORE < 1_000_000);
    }
}

// ---------------------------------------------------------------------------
// TransferableKind — Display uniqueness & serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transferable_kind_display_all_unique() {
    let displays: BTreeSet<String> = TransferableKind::ALL
        .iter()
        .map(|k| format!("{k}"))
        .collect();
    assert_eq!(displays.len(), TransferableKind::ALL.len());
}

#[test]
fn enrichment_transferable_kind_all_has_five_variants() {
    assert_eq!(TransferableKind::ALL.len(), 5);
}

#[test]
fn enrichment_transferable_kind_serde_roundtrip_all() {
    for kind in TransferableKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: TransferableKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
        // snake_case serde: json should contain underscore form
        let display = format!("{kind}");
        assert!(json.contains(&display), "serde mismatch for {kind:?}");
    }
}

#[test]
fn enrichment_transferable_kind_display_contains_no_whitespace() {
    for kind in TransferableKind::ALL {
        let s = format!("{kind}");
        assert!(!s.contains(' '), "Display for {kind:?} contains whitespace");
    }
}

#[test]
fn enrichment_transferable_kind_ord_is_deterministic() {
    let mut kinds = TransferableKind::ALL.to_vec();
    let original = kinds.clone();
    kinds.sort();
    // ALL should already be sorted if variants are in declaration order
    assert_eq!(kinds, original);
}

#[test]
fn enrichment_transferable_kind_clone_eq() {
    for kind in TransferableKind::ALL {
        let cloned = *kind;
        assert_eq!(*kind, cloned);
    }
}

// ---------------------------------------------------------------------------
// DriftKind — Display uniqueness & serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_drift_kind_display_all_unique() {
    let displays: BTreeSet<String> = DriftKind::ALL.iter().map(|k| format!("{k}")).collect();
    assert_eq!(displays.len(), DriftKind::ALL.len());
}

#[test]
fn enrichment_drift_kind_all_has_five_variants() {
    assert_eq!(DriftKind::ALL.len(), 5);
}

#[test]
fn enrichment_drift_kind_serde_roundtrip_all() {
    for kind in DriftKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: DriftKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn enrichment_drift_kind_display_contains_no_whitespace() {
    for kind in DriftKind::ALL {
        let s = format!("{kind}");
        assert!(!s.contains(' '), "Display for {kind:?} contains whitespace");
    }
}

// ---------------------------------------------------------------------------
// TransferVerdict — Display uniqueness & serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transfer_verdict_display_all_unique() {
    let verdicts = [
        TransferVerdict::Accepted,
        TransferVerdict::Deferred,
        TransferVerdict::Rejected,
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_transfer_verdict_serde_roundtrip() {
    let verdicts = [
        TransferVerdict::Accepted,
        TransferVerdict::Deferred,
        TransferVerdict::Rejected,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: TransferVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_transfer_verdict_display_values() {
    assert_eq!(format!("{}", TransferVerdict::Accepted), "accepted");
    assert_eq!(format!("{}", TransferVerdict::Deferred), "deferred");
    assert_eq!(format!("{}", TransferVerdict::Rejected), "rejected");
}

// ---------------------------------------------------------------------------
// TransferRejectionReason — Display uniqueness & serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rejection_reason_display_all_unique() {
    let reasons = [
        TransferRejectionReason::ProximityTooLow,
        TransferRejectionReason::BudgetExhausted,
        TransferRejectionReason::KindBlocked,
        TransferRejectionReason::EpochGapTooLarge,
        TransferRejectionReason::AlreadyPresent,
        TransferRejectionReason::RecentRollback,
        TransferRejectionReason::InsufficientEvidence,
    ];
    let displays: BTreeSet<String> = reasons.iter().map(|r| format!("{r}")).collect();
    assert_eq!(displays.len(), 7);
}

#[test]
fn enrichment_rejection_reason_serde_roundtrip_all() {
    let reasons = [
        TransferRejectionReason::ProximityTooLow,
        TransferRejectionReason::BudgetExhausted,
        TransferRejectionReason::KindBlocked,
        TransferRejectionReason::EpochGapTooLarge,
        TransferRejectionReason::AlreadyPresent,
        TransferRejectionReason::RecentRollback,
        TransferRejectionReason::InsufficientEvidence,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: TransferRejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn enrichment_rejection_reason_display_specific_values() {
    assert_eq!(
        format!("{}", TransferRejectionReason::ProximityTooLow),
        "proximity_too_low"
    );
    assert_eq!(
        format!("{}", TransferRejectionReason::BudgetExhausted),
        "budget_exhausted"
    );
    assert_eq!(
        format!("{}", TransferRejectionReason::KindBlocked),
        "kind_blocked"
    );
    assert_eq!(
        format!("{}", TransferRejectionReason::EpochGapTooLarge),
        "epoch_gap_too_large"
    );
    assert_eq!(
        format!("{}", TransferRejectionReason::AlreadyPresent),
        "already_present"
    );
    assert_eq!(
        format!("{}", TransferRejectionReason::RecentRollback),
        "recent_rollback"
    );
    assert_eq!(
        format!("{}", TransferRejectionReason::InsufficientEvidence),
        "insufficient_evidence"
    );
}

// ---------------------------------------------------------------------------
// DriftSignal
// ---------------------------------------------------------------------------

#[test]
fn enrichment_drift_signal_exceeds_tolerance_confident_above() {
    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
    assert!(signal.exceeds_tolerance(150_000));
}

#[test]
fn enrichment_drift_signal_does_not_exceed_tolerance_confident_below() {
    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 100_000, true);
    assert!(!signal.exceeds_tolerance(150_000));
}

#[test]
fn enrichment_drift_signal_does_not_exceed_tolerance_not_confident() {
    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 999_999, false);
    assert!(!signal.exceeds_tolerance(1));
}

#[test]
fn enrichment_drift_signal_at_exact_tolerance_does_not_exceed() {
    let signal = specimen_drift_signal(DriftKind::CachePollution, 150_000, true);
    // exceeds_tolerance uses > not >=
    assert!(!signal.exceeds_tolerance(150_000));
}

#[test]
fn enrichment_drift_signal_serde_roundtrip() {
    let signal = specimen_drift_signal(DriftKind::TypeFeedbackMismatch, 350_000, true);
    let json = serde_json::to_string(&signal).unwrap();
    let back: DriftSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(signal, back);
}

#[test]
fn enrichment_drift_signal_zero_magnitude() {
    let signal = specimen_drift_signal(DriftKind::EpochDrift, 0, true);
    assert!(!signal.exceeds_tolerance(0));
    assert!(!signal.exceeds_tolerance(1));
}

// ---------------------------------------------------------------------------
// TransferCandidate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transfer_candidate_serde_roundtrip_all_kinds() {
    for kind in TransferableKind::ALL {
        let candidate = specimen_candidate(&format!("cand-{kind}"), *kind, 750_000);
        let json = serde_json::to_string(&candidate).unwrap();
        let back: TransferCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(candidate, back);
    }
}

#[test]
fn enrichment_transfer_candidate_specimen_defaults() {
    let c = specimen_candidate("xyz", TransferableKind::AotArtifact, 650_000);
    assert_eq!(c.candidate_key, "xyz");
    assert_eq!(c.kind, TransferableKind::AotArtifact);
    assert_eq!(c.proximity_score, 650_000);
    assert_eq!(c.donor_performance_estimate, 100_000);
    assert_eq!(c.donor_epoch, SecurityEpoch::from_raw(1));
    assert_eq!(c.donor_label, "donor-xyz");
}

#[test]
fn enrichment_transfer_candidate_different_keys_have_different_hashes() {
    let c1 = specimen_candidate("alpha", TransferableKind::RewritePack, 800_000);
    let c2 = specimen_candidate("beta", TransferableKind::RewritePack, 800_000);
    assert_ne!(c1.donor_embedding_hash, c2.donor_embedding_hash);
    assert_ne!(c1.prior_hash, c2.prior_hash);
}

// ---------------------------------------------------------------------------
// TransferConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transfer_config_default_values() {
    let config = TransferConfig::default();
    assert_eq!(config.max_active_transfers, MAX_ACTIVE_TRANSFERS);
    assert_eq!(config.max_candidates, MAX_TRANSFER_CANDIDATES);
    assert_eq!(config.drift_tolerance, DEFAULT_DRIFT_TOLERANCE);
    assert_eq!(config.min_proximity_score, MIN_PROXIMITY_SCORE);
    assert_eq!(config.max_epoch_gap, 10);
    assert!(config.allowed_kinds.is_empty());
    assert!(config.blocked_kinds.is_empty());
    assert_eq!(config.min_drift_observations, MIN_DRIFT_OBSERVATIONS);
    assert_eq!(config.rollback_cooldown_epochs, 3);
}

#[test]
fn enrichment_transfer_config_serde_roundtrip() {
    let mut config = TransferConfig::default();
    config.blocked_kinds.insert(TransferableKind::AotArtifact);
    config
        .allowed_kinds
        .insert(TransferableKind::SpecializationGuard);
    let json = serde_json::to_string(&config).unwrap();
    let back: TransferConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_config_kind_allowed_default_allows_everything() {
    let config = TransferConfig::default();
    for kind in TransferableKind::ALL {
        assert!(config.kind_allowed(*kind));
    }
}

#[test]
fn enrichment_config_kind_blocked_takes_precedence_over_allowed() {
    let mut config = TransferConfig::default();
    config.allowed_kinds.insert(TransferableKind::CacheHint);
    config.blocked_kinds.insert(TransferableKind::CacheHint);
    // blocked_kinds checked first, so blocked wins
    assert!(!config.kind_allowed(TransferableKind::CacheHint));
}

#[test]
fn enrichment_config_whitelist_only_allows_listed() {
    let mut config = TransferConfig::default();
    config.allowed_kinds.insert(TransferableKind::RewritePack);
    config.allowed_kinds.insert(TransferableKind::TieringPrior);
    assert!(config.kind_allowed(TransferableKind::RewritePack));
    assert!(config.kind_allowed(TransferableKind::TieringPrior));
    assert!(!config.kind_allowed(TransferableKind::CacheHint));
    assert!(!config.kind_allowed(TransferableKind::AotArtifact));
    assert!(!config.kind_allowed(TransferableKind::SpecializationGuard));
}

// ---------------------------------------------------------------------------
// ActiveTransfer
// ---------------------------------------------------------------------------

#[test]
fn enrichment_active_transfer_worst_drift_no_signals() {
    let transfer = make_active_transfer("a1", TransferableKind::CacheHint);
    assert_eq!(transfer.worst_drift_millionths(), 0);
}

#[test]
fn enrichment_active_transfer_worst_drift_only_non_confident() {
    let mut transfer = make_active_transfer("a2", TransferableKind::RewritePack);
    transfer
        .drift_signals
        .push(specimen_drift_signal(DriftKind::CachePollution, 500_000, false));
    transfer
        .drift_signals
        .push(specimen_drift_signal(DriftKind::EpochDrift, 300_000, false));
    // No confident signals, so worst drift is 0
    assert_eq!(transfer.worst_drift_millionths(), 0);
}

#[test]
fn enrichment_active_transfer_worst_drift_mixed_confidence() {
    let mut transfer = make_active_transfer("a3", TransferableKind::TieringPrior);
    transfer.drift_signals.push(specimen_drift_signal(
        DriftKind::PerformanceRegression,
        50_000,
        true,
    ));
    transfer.drift_signals.push(specimen_drift_signal(
        DriftKind::CachePollution,
        900_000,
        false, // not confident, should not count
    ));
    transfer.drift_signals.push(specimen_drift_signal(
        DriftKind::TypeFeedbackMismatch,
        120_000,
        true,
    ));
    assert_eq!(transfer.worst_drift_millionths(), 120_000);
}

#[test]
fn enrichment_active_transfer_exceeds_tolerance_no_signals() {
    let transfer = make_active_transfer("a4", TransferableKind::AotArtifact);
    assert!(!transfer.exceeds_tolerance(DEFAULT_DRIFT_TOLERANCE));
}

#[test]
fn enrichment_active_transfer_exceeds_tolerance_with_confident_signal() {
    let mut transfer = make_active_transfer("a5", TransferableKind::RewritePack);
    transfer.drift_signals.push(specimen_drift_signal(
        DriftKind::CorrectnessDivergence,
        200_000,
        true,
    ));
    assert!(transfer.exceeds_tolerance(150_000));
    assert!(!transfer.exceeds_tolerance(200_000)); // equal, not exceeding
}

#[test]
fn enrichment_active_transfer_confident_drift_kind_count_empty() {
    let transfer = make_active_transfer("a6", TransferableKind::CacheHint);
    assert_eq!(transfer.confident_drift_kind_count(), 0);
}

#[test]
fn enrichment_active_transfer_confident_drift_kind_count_deduplicates() {
    let mut transfer = make_active_transfer("a7", TransferableKind::RewritePack);
    // Same kind twice, confident
    transfer.drift_signals.push(specimen_drift_signal(
        DriftKind::PerformanceRegression,
        100_000,
        true,
    ));
    transfer.drift_signals.push(specimen_drift_signal(
        DriftKind::PerformanceRegression,
        200_000,
        true,
    ));
    // Different kind, confident
    transfer
        .drift_signals
        .push(specimen_drift_signal(DriftKind::CachePollution, 80_000, true));
    // Different kind, not confident (should not count)
    transfer
        .drift_signals
        .push(specimen_drift_signal(DriftKind::EpochDrift, 50_000, false));
    assert_eq!(transfer.confident_drift_kind_count(), 2);
}

#[test]
fn enrichment_active_transfer_serde_roundtrip() {
    let mut transfer = make_active_transfer("a8", TransferableKind::SpecializationGuard);
    transfer.drift_signals.push(specimen_drift_signal(
        DriftKind::TypeFeedbackMismatch,
        75_000,
        true,
    ));
    transfer.observation_count = 42;
    let json = serde_json::to_string(&transfer).unwrap();
    let back: ActiveTransfer = serde_json::from_str(&json).unwrap();
    assert_eq!(transfer, back);
}

// ---------------------------------------------------------------------------
// TransferDecision
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transfer_decision_serde_roundtrip_accepted() {
    let decision = TransferDecision {
        candidate_key: "d1".to_string(),
        verdict: TransferVerdict::Accepted,
        reason: None,
        decision_hash: ContentHash::compute(b"decision-d1"),
        epoch: SecurityEpoch::from_raw(7),
    };
    let json = serde_json::to_string(&decision).unwrap();
    let back: TransferDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_transfer_decision_serde_roundtrip_rejected() {
    let decision = TransferDecision {
        candidate_key: "d2".to_string(),
        verdict: TransferVerdict::Rejected,
        reason: Some(TransferRejectionReason::EpochGapTooLarge),
        decision_hash: ContentHash::compute(b"decision-d2"),
        epoch: SecurityEpoch::from_raw(3),
    };
    let json = serde_json::to_string(&decision).unwrap();
    let back: TransferDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_transfer_decision_serde_roundtrip_deferred() {
    let decision = TransferDecision {
        candidate_key: "d3".to_string(),
        verdict: TransferVerdict::Deferred,
        reason: Some(TransferRejectionReason::RecentRollback),
        decision_hash: ContentHash::compute(b"decision-d3"),
        epoch: SecurityEpoch::from_raw(10),
    };
    let json = serde_json::to_string(&decision).unwrap();
    let back: TransferDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

// ---------------------------------------------------------------------------
// TransferRollback
// ---------------------------------------------------------------------------

#[test]
fn enrichment_transfer_rollback_serde_roundtrip() {
    let rollback = TransferRollback {
        candidate_key: "rb1".to_string(),
        kind: TransferableKind::TieringPrior,
        rollback_epoch: SecurityEpoch::from_raw(8),
        trigger_signals: vec![
            specimen_drift_signal(DriftKind::PerformanceRegression, 250_000, true),
            specimen_drift_signal(DriftKind::CachePollution, 180_000, true),
        ],
        prior_hash: ContentHash::compute(b"prior-rb1"),
        rollback_hash: ContentHash::compute(b"rollback-rb1"),
    };
    let json = serde_json::to_string(&rollback).unwrap();
    let back: TransferRollback = serde_json::from_str(&json).unwrap();
    assert_eq!(rollback, back);
}

#[test]
fn enrichment_transfer_rollback_empty_trigger_signals() {
    let rollback = TransferRollback {
        candidate_key: "rb2".to_string(),
        kind: TransferableKind::CacheHint,
        rollback_epoch: SecurityEpoch::from_raw(1),
        trigger_signals: Vec::new(),
        prior_hash: ContentHash::compute(b"prior-rb2"),
        rollback_hash: ContentHash::compute(b"rollback-rb2"),
    };
    let json = serde_json::to_string(&rollback).unwrap();
    let back: TransferRollback = serde_json::from_str(&json).unwrap();
    assert_eq!(rollback, back);
}

// ---------------------------------------------------------------------------
// KindTransferStats
// ---------------------------------------------------------------------------

#[test]
fn enrichment_kind_transfer_stats_default_is_zero() {
    let stats = KindTransferStats::default();
    assert_eq!(stats.total, 0);
    assert_eq!(stats.accepted, 0);
    assert_eq!(stats.rejected, 0);
    assert_eq!(stats.deferred, 0);
    assert_eq!(stats.acceptance_rate_millionths(), 0);
}

#[test]
fn enrichment_kind_transfer_stats_full_acceptance() {
    let stats = KindTransferStats {
        total: 5,
        accepted: 5,
        rejected: 0,
        deferred: 0,
    };
    assert_eq!(stats.acceptance_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_kind_transfer_stats_partial_acceptance() {
    let stats = KindTransferStats {
        total: 4,
        accepted: 1,
        rejected: 2,
        deferred: 1,
    };
    assert_eq!(stats.acceptance_rate_millionths(), 250_000); // 25%
}

#[test]
fn enrichment_kind_transfer_stats_no_accepted() {
    let stats = KindTransferStats {
        total: 10,
        accepted: 0,
        rejected: 10,
        deferred: 0,
    };
    assert_eq!(stats.acceptance_rate_millionths(), 0);
}

#[test]
fn enrichment_kind_transfer_stats_serde_roundtrip() {
    let stats = KindTransferStats {
        total: 20,
        accepted: 15,
        rejected: 3,
        deferred: 2,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let back: KindTransferStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
}

// ---------------------------------------------------------------------------
// TransferSession — construction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_session_new_has_empty_collections() {
    let session = make_session();
    assert!(session.decisions.is_empty());
    assert!(session.active_transfers.is_empty());
    assert!(session.rollback_history.is_empty());
    assert!(session.local_prior_hashes.is_empty());
    assert!(session.kind_rollback_epochs.is_empty());
}

#[test]
fn enrichment_session_preserves_config() {
    let config = TransferConfig {
        max_active_transfers: 42,
        drift_tolerance: 99_000,
        ..Default::default()
    };
    let session = TransferSession::new(
        "s1".to_string(),
        ContentHash::compute(b"recip"),
        SecurityEpoch::from_raw(10),
        config.clone(),
    );
    assert_eq!(session.config, config);
    assert_eq!(session.epoch, SecurityEpoch::from_raw(10));
}

// ---------------------------------------------------------------------------
// TransferSession — evaluate_candidate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_accepts_good_candidate_and_adds_active() {
    let mut session = make_session();
    let c = make_candidate("good1", TransferableKind::TieringPrior);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Accepted);
    assert!(decision.reason.is_none());
    assert_eq!(session.active_transfers.len(), 1);
    assert_eq!(session.active_transfers[0].candidate_key, "good1");
    assert_eq!(session.decisions.len(), 1);
}

#[test]
fn enrichment_evaluate_rejects_proximity_too_low() {
    let mut session = make_session();
    let c = specimen_candidate("low", TransferableKind::RewritePack, MIN_PROXIMITY_SCORE - 1);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Rejected);
    assert_eq!(decision.reason, Some(TransferRejectionReason::ProximityTooLow));
    assert!(session.active_transfers.is_empty());
}

#[test]
fn enrichment_evaluate_rejects_at_exact_min_proximity() {
    let mut session = make_session();
    // At exactly MIN_PROXIMITY_SCORE, candidate should be accepted (not < threshold)
    let c = specimen_candidate("exact", TransferableKind::RewritePack, MIN_PROXIMITY_SCORE);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Accepted);
}

#[test]
fn enrichment_evaluate_rejects_blocked_kind() {
    let mut session = make_session();
    session
        .config
        .blocked_kinds
        .insert(TransferableKind::SpecializationGuard);
    let c = make_candidate("blocked", TransferableKind::SpecializationGuard);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Rejected);
    assert_eq!(decision.reason, Some(TransferRejectionReason::KindBlocked));
}

#[test]
fn enrichment_evaluate_rejects_already_present_prior() {
    let mut session = make_session();
    let c = make_candidate("present", TransferableKind::CacheHint);
    session.local_prior_hashes.insert(c.prior_hash);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Rejected);
    assert_eq!(decision.reason, Some(TransferRejectionReason::AlreadyPresent));
}

#[test]
fn enrichment_evaluate_defers_budget_exhausted() {
    let mut session = make_session();
    session.config.max_active_transfers = 0;
    let c = make_candidate("budgeted", TransferableKind::RewritePack);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Deferred);
    assert_eq!(decision.reason, Some(TransferRejectionReason::BudgetExhausted));
}

#[test]
fn enrichment_evaluate_rejects_epoch_gap_too_large() {
    let mut session = make_session();
    session.config.max_epoch_gap = 2;
    // Session epoch = 5, donor epoch = 1, gap = 4 > 2
    let c = make_candidate("epoch-gap", TransferableKind::AotArtifact);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Rejected);
    assert_eq!(
        decision.reason,
        Some(TransferRejectionReason::EpochGapTooLarge)
    );
}

#[test]
fn enrichment_evaluate_epoch_gap_exact_boundary_accepted() {
    let mut session = make_session();
    session.config.max_epoch_gap = 4;
    // Session epoch = 5, donor epoch = 1, gap = 4, not > 4
    let c = make_candidate("epoch-exact", TransferableKind::RewritePack);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Accepted);
}

#[test]
fn enrichment_evaluate_defers_rollback_cooldown() {
    let mut session = make_session();
    // Session epoch = 5, cooldown = 3, last rollback epoch = 4 => gap = 1 < 3
    session
        .kind_rollback_epochs
        .insert(TransferableKind::CacheHint, SecurityEpoch::from_raw(4));
    let c = make_candidate("cooled", TransferableKind::CacheHint);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Deferred);
    assert_eq!(decision.reason, Some(TransferRejectionReason::RecentRollback));
}

#[test]
fn enrichment_evaluate_accepts_after_cooldown_expires() {
    let mut session = make_session();
    // Session epoch = 5, cooldown = 3, last rollback epoch = 1 => gap = 4 >= 3
    session
        .kind_rollback_epochs
        .insert(TransferableKind::CacheHint, SecurityEpoch::from_raw(1));
    let c = make_candidate("after-cooldown", TransferableKind::CacheHint);
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Accepted);
}

#[test]
fn enrichment_evaluate_rejects_negative_performance_estimate() {
    let mut session = make_session();
    let mut c = make_candidate("neg-perf", TransferableKind::RewritePack);
    c.donor_performance_estimate = -1;
    let decision = session.evaluate_candidate(&c);
    assert_eq!(decision.verdict, TransferVerdict::Rejected);
    assert_eq!(
        decision.reason,
        Some(TransferRejectionReason::InsufficientEvidence)
    );
}

#[test]
fn enrichment_evaluate_accepts_zero_performance_estimate() {
    let mut session = make_session();
    let mut c = make_candidate("zero-perf", TransferableKind::RewritePack);
    c.donor_performance_estimate = 0;
    let decision = session.evaluate_candidate(&c);
    // 0 is not < 0, so it should pass this check
    assert_eq!(decision.verdict, TransferVerdict::Accepted);
}

// ---------------------------------------------------------------------------
// TransferSession — record_drift / record_clean_observation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_record_drift_increments_observation_count() {
    let mut session = make_session();
    let c = make_candidate("obs1", TransferableKind::RewritePack);
    session.evaluate_candidate(&c);
    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 100_000, true);
    session.record_drift("obs1", signal);
    assert_eq!(session.active_transfers[0].observation_count, 1);
    assert_eq!(session.active_transfers[0].drift_signals.len(), 1);
}

#[test]
fn enrichment_record_clean_observation_no_drift_signal() {
    let mut session = make_session();
    let c = make_candidate("clean1", TransferableKind::TieringPrior);
    session.evaluate_candidate(&c);
    assert!(session.record_clean_observation("clean1"));
    assert!(session.record_clean_observation("clean1"));
    assert_eq!(session.active_transfers[0].observation_count, 2);
    assert!(session.active_transfers[0].drift_signals.is_empty());
}

#[test]
fn enrichment_record_drift_unknown_key_returns_false() {
    let mut session = make_session();
    let signal = specimen_drift_signal(DriftKind::EpochDrift, 50_000, true);
    assert!(!session.record_drift("nonexistent", signal));
}

#[test]
fn enrichment_record_clean_observation_unknown_key_returns_false() {
    let mut session = make_session();
    assert!(!session.record_clean_observation("nonexistent"));
}

#[test]
fn enrichment_record_drift_on_rolled_back_transfer_fails() {
    let mut session = make_session();
    session.config.min_drift_observations = 1;
    let c = make_candidate("rb-drift", TransferableKind::RewritePack);
    session.evaluate_candidate(&c);

    let signal = specimen_drift_signal(DriftKind::CorrectnessDivergence, 300_000, true);
    session.record_drift("rb-drift", signal);
    session.record_clean_observation("rb-drift");
    session.enforce_drift_guards();

    // Transfer is now rolled back; further drift recording should fail
    let signal2 = specimen_drift_signal(DriftKind::CachePollution, 100_000, true);
    assert!(!session.record_drift("rb-drift", signal2));
}

#[test]
fn enrichment_record_clean_observation_on_rolled_back_fails() {
    let mut session = make_session();
    session.config.min_drift_observations = 1;
    let c = make_candidate("rb-clean", TransferableKind::CacheHint);
    session.evaluate_candidate(&c);

    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
    session.record_drift("rb-clean", signal);
    session.record_clean_observation("rb-clean");
    session.enforce_drift_guards();

    assert!(!session.record_clean_observation("rb-clean"));
}

// ---------------------------------------------------------------------------
// TransferSession — enforce_drift_guards
// ---------------------------------------------------------------------------

#[test]
fn enrichment_enforce_drift_no_active_transfers() {
    let mut session = make_session();
    let rollbacks = session.enforce_drift_guards();
    assert!(rollbacks.is_empty());
}

#[test]
fn enrichment_enforce_drift_below_min_observations() {
    let mut session = make_session();
    // Default min_drift_observations = 16
    let c = make_candidate("below-obs", TransferableKind::RewritePack);
    session.evaluate_candidate(&c);
    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 999_999, true);
    session.record_drift("below-obs", signal);
    // Only 1 observation, need 16
    let rollbacks = session.enforce_drift_guards();
    assert!(rollbacks.is_empty());
}

#[test]
fn enrichment_enforce_drift_rollback_sets_kind_epoch() {
    let mut session = make_session();
    session.config.min_drift_observations = 1;
    let c = make_candidate("kind-epoch", TransferableKind::AotArtifact);
    session.evaluate_candidate(&c);
    let signal = specimen_drift_signal(DriftKind::CorrectnessDivergence, 500_000, true);
    session.record_drift("kind-epoch", signal);
    session.record_clean_observation("kind-epoch");
    session.enforce_drift_guards();

    assert_eq!(
        session.kind_rollback_epochs.get(&TransferableKind::AotArtifact),
        Some(&SecurityEpoch::from_raw(5))
    );
}

#[test]
fn enrichment_enforce_drift_rollback_adds_to_history() {
    let mut session = make_session();
    session.config.min_drift_observations = 1;
    let c = make_candidate("hist1", TransferableKind::TieringPrior);
    session.evaluate_candidate(&c);
    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
    session.record_drift("hist1", signal);
    session.record_clean_observation("hist1");
    let rollbacks = session.enforce_drift_guards();
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(session.rollback_history.len(), 1);
    assert_eq!(session.rollback_history[0].candidate_key, "hist1");
}

#[test]
fn enrichment_enforce_drift_idempotent_after_rollback() {
    let mut session = make_session();
    session.config.min_drift_observations = 1;
    let c = make_candidate("idem1", TransferableKind::RewritePack);
    session.evaluate_candidate(&c);
    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
    session.record_drift("idem1", signal);
    session.record_clean_observation("idem1");
    let rb1 = session.enforce_drift_guards();
    assert_eq!(rb1.len(), 1);
    // Second enforcement should produce no new rollbacks
    let rb2 = session.enforce_drift_guards();
    assert!(rb2.is_empty());
}

#[test]
fn enrichment_enforce_drift_multiple_transfers_selective_rollback() {
    let mut session = make_session();
    session.config.min_drift_observations = 1;

    let c1 = make_candidate("sel1", TransferableKind::RewritePack);
    session.evaluate_candidate(&c1);
    let c2 = make_candidate("sel2", TransferableKind::CacheHint);
    session.evaluate_candidate(&c2);

    // Only c1 has drift exceeding tolerance
    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
    session.record_drift("sel1", signal);
    session.record_clean_observation("sel1");
    // c2 gets clean observations only
    session.record_clean_observation("sel2");
    session.record_clean_observation("sel2");

    let rollbacks = session.enforce_drift_guards();
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].candidate_key, "sel1");
    assert!(!session.active_transfers[1].rolled_back);
}

#[test]
fn enrichment_enforce_drift_rollback_history_trimmed_to_max() {
    let mut session = make_session();
    session.config.min_drift_observations = 1;

    for i in 0..(MAX_ROLLBACK_HISTORY + 3) {
        let key = format!("trim{i}");
        let c = make_candidate(&key, TransferableKind::RewritePack);
        session.evaluate_candidate(&c);
        let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
        session.record_drift(&key, signal);
        session.record_clean_observation(&key);
        session.enforce_drift_guards();
        // Reset cooldown for next iteration
        session.kind_rollback_epochs.clear();
    }

    assert!(session.rollback_history.len() <= MAX_ROLLBACK_HISTORY);
}

// ---------------------------------------------------------------------------
// TransferSession — build_report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_report_empty_session() {
    let session = make_session();
    let report = session.build_report();
    assert_eq!(report.total_candidates, 0);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.rejected, 0);
    assert_eq!(report.deferred, 0);
    assert_eq!(report.active_count, 0);
    assert_eq!(report.rolled_back_count, 0);
    assert_eq!(report.worst_drift_millionths, 0);
    assert!(report.kind_stats.is_empty());
}

#[test]
fn enrichment_build_report_acceptance_rate_zero_candidates() {
    let session = make_session();
    let report = session.build_report();
    assert_eq!(report.acceptance_rate_millionths(), 0);
}

#[test]
fn enrichment_build_report_counts_correct() {
    let mut session = make_session();
    // 3 accepted
    for i in 0..3 {
        let c = make_candidate(&format!("a{i}"), TransferableKind::RewritePack);
        session.evaluate_candidate(&c);
    }
    // 2 rejected (low proximity)
    for i in 0..2 {
        let c = specimen_candidate(&format!("r{i}"), TransferableKind::CacheHint, 100_000);
        session.evaluate_candidate(&c);
    }

    let report = session.build_report();
    assert_eq!(report.total_candidates, 5);
    assert_eq!(report.accepted, 3);
    assert_eq!(report.rejected, 2);
    assert_eq!(report.deferred, 0);
    assert_eq!(report.active_count, 3);
}

// ---------------------------------------------------------------------------
// TransferReport
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_acceptance_rate_100_percent() {
    let mut session = make_session();
    let c = make_candidate("full", TransferableKind::RewritePack);
    session.evaluate_candidate(&c);
    let report = session.build_report();
    assert_eq!(report.acceptance_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_report_rollback_rate_zero_when_no_accepted() {
    let mut session = make_session();
    // Reject a candidate (low proximity)
    let c = specimen_candidate("rejected", TransferableKind::RewritePack, 100_000);
    session.evaluate_candidate(&c);
    let report = session.build_report();
    assert_eq!(report.rollback_rate_millionths(), 0);
}

#[test]
fn enrichment_report_rollback_rate_calculated() {
    let mut session = make_session();
    session.config.min_drift_observations = 1;
    // Accept 4 candidates
    for i in 0..4 {
        let c = make_candidate(&format!("rr{i}"), TransferableKind::RewritePack);
        session.evaluate_candidate(&c);
    }
    // Roll back 1
    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
    session.record_drift("rr0", signal);
    session.record_clean_observation("rr0");
    session.enforce_drift_guards();

    let report = session.build_report();
    assert_eq!(report.rollback_rate_millionths(), 250_000); // 1/4 = 25%
}

#[test]
fn enrichment_report_is_healthy_true_for_clean_session() {
    let session = make_session();
    let report = session.build_report();
    assert!(report.is_healthy());
}

#[test]
fn enrichment_report_is_healthy_false_high_rollback() {
    let mut session = make_session();
    session.config.min_drift_observations = 1;
    let c = make_candidate("unhealthy", TransferableKind::RewritePack);
    session.evaluate_candidate(&c);
    let signal = specimen_drift_signal(DriftKind::CorrectnessDivergence, 500_000, true);
    session.record_drift("unhealthy", signal);
    session.record_clean_observation("unhealthy");
    session.enforce_drift_guards();

    let report = session.build_report();
    // 100% rollback rate and high drift
    assert!(!report.is_healthy());
}

#[test]
fn enrichment_report_display_contains_key_fields() {
    let mut session = make_session();
    let c = make_candidate("disp1", TransferableKind::RewritePack);
    session.evaluate_candidate(&c);
    let report = session.build_report();
    let s = format!("{report}");
    assert!(s.contains("TransferReport"));
    assert!(s.contains("test-session"));
    assert!(s.contains("candidates=1"));
    assert!(s.contains("accepted=1"));
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let mut session = make_session();
    let c = make_candidate("sr1", TransferableKind::CacheHint);
    session.evaluate_candidate(&c);
    let report = session.build_report();
    let json = serde_json::to_string(&report).unwrap();
    let back: TransferReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// Deterministic hashing
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_hash_deterministic_across_sessions() {
    let mut s1 = make_session();
    let mut s2 = make_session();
    let c = make_candidate("det1", TransferableKind::TieringPrior);
    let d1 = s1.evaluate_candidate(&c);
    let d2 = s2.evaluate_candidate(&c);
    assert_eq!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn enrichment_decision_hash_differs_for_different_candidates() {
    let mut session = make_session();
    let c1 = make_candidate("diff1", TransferableKind::RewritePack);
    let c2 = make_candidate("diff2", TransferableKind::RewritePack);
    let d1 = session.evaluate_candidate(&c1);
    let d2 = session.evaluate_candidate(&c2);
    assert_ne!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn enrichment_report_hash_deterministic() {
    let s1 = make_session();
    let s2 = make_session();
    let r1 = s1.build_report();
    let r2 = s2.build_report();
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn enrichment_report_hash_differs_after_activity() {
    let s1 = make_session();
    let mut s2 = make_session();
    let c = make_candidate("activity", TransferableKind::RewritePack);
    s2.evaluate_candidate(&c);
    let r1 = s1.build_report();
    let r2 = s2.build_report();
    assert_ne!(r1.report_hash, r2.report_hash);
}

// ---------------------------------------------------------------------------
// Session serde roundtrip with state
// ---------------------------------------------------------------------------

#[test]
fn enrichment_session_serde_roundtrip_with_decisions_and_active() {
    let mut session = make_session();
    let c1 = make_candidate("s1", TransferableKind::RewritePack);
    session.evaluate_candidate(&c1);
    let c2 = specimen_candidate("s2", TransferableKind::CacheHint, 100_000);
    session.evaluate_candidate(&c2); // rejected

    let json = serde_json::to_string(&session).unwrap();
    let back: TransferSession = serde_json::from_str(&json).unwrap();
    assert_eq!(session, back);
}

#[test]
fn enrichment_session_serde_roundtrip_with_rollback_history() {
    let mut session = make_session();
    session.config.min_drift_observations = 1;
    let c = make_candidate("sr-rb", TransferableKind::TieringPrior);
    session.evaluate_candidate(&c);
    let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
    session.record_drift("sr-rb", signal);
    session.record_clean_observation("sr-rb");
    session.enforce_drift_guards();

    let json = serde_json::to_string(&session).unwrap();
    let back: TransferSession = serde_json::from_str(&json).unwrap();
    assert_eq!(session, back);
}

// ---------------------------------------------------------------------------
// render helpers
// ---------------------------------------------------------------------------

#[test]
fn enrichment_render_decision_summary_accepted_format() {
    let decision = TransferDecision {
        candidate_key: "render-a".to_string(),
        verdict: TransferVerdict::Accepted,
        reason: None,
        decision_hash: ContentHash::compute(b"render-a"),
        epoch: SecurityEpoch::from_raw(7),
    };
    let summary = render_decision_summary(&decision);
    assert!(summary.contains("[ACCEPTED]"));
    assert!(summary.contains("render-a"));
    assert!(summary.contains("7"));
}

#[test]
fn enrichment_render_decision_summary_rejected_format() {
    let decision = TransferDecision {
        candidate_key: "render-r".to_string(),
        verdict: TransferVerdict::Rejected,
        reason: Some(TransferRejectionReason::BudgetExhausted),
        decision_hash: ContentHash::compute(b"render-r"),
        epoch: SecurityEpoch::from_raw(3),
    };
    let summary = render_decision_summary(&decision);
    assert!(summary.contains("[REJECTED]"));
    assert!(summary.contains("budget_exhausted"));
}

#[test]
fn enrichment_render_decision_summary_deferred_format() {
    let decision = TransferDecision {
        candidate_key: "render-d".to_string(),
        verdict: TransferVerdict::Deferred,
        reason: Some(TransferRejectionReason::RecentRollback),
        decision_hash: ContentHash::compute(b"render-d"),
        epoch: SecurityEpoch::from_raw(9),
    };
    let summary = render_decision_summary(&decision);
    assert!(summary.contains("[DEFERRED]"));
    assert!(summary.contains("recent_rollback"));
}

#[test]
fn enrichment_render_decision_summary_rejected_no_reason() {
    let decision = TransferDecision {
        candidate_key: "render-nr".to_string(),
        verdict: TransferVerdict::Rejected,
        reason: None,
        decision_hash: ContentHash::compute(b"render-nr"),
        epoch: SecurityEpoch::from_raw(2),
    };
    let summary = render_decision_summary(&decision);
    assert!(summary.contains("[REJECTED]"));
    assert!(summary.contains("unknown"));
}

#[test]
fn enrichment_render_rollback_summary_format() {
    let rollback = TransferRollback {
        candidate_key: "rrb1".to_string(),
        kind: TransferableKind::AotArtifact,
        rollback_epoch: SecurityEpoch::from_raw(6),
        trigger_signals: vec![
            specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true),
            specimen_drift_signal(DriftKind::CachePollution, 180_000, true),
        ],
        prior_hash: ContentHash::compute(b"rrb1-prior"),
        rollback_hash: ContentHash::compute(b"rrb1-rollback"),
    };
    let summary = render_rollback_summary(&rollback);
    assert!(summary.contains("[ROLLBACK]"));
    assert!(summary.contains("rrb1"));
    assert!(summary.contains("aot_artifact"));
    assert!(summary.contains("performance_regression"));
    assert!(summary.contains("cache_pollution"));
    assert!(summary.contains("200000"));
    assert!(summary.contains("180000"));
}

#[test]
fn enrichment_render_rollback_summary_no_triggers() {
    let rollback = TransferRollback {
        candidate_key: "rrb-empty".to_string(),
        kind: TransferableKind::CacheHint,
        rollback_epoch: SecurityEpoch::from_raw(1),
        trigger_signals: Vec::new(),
        prior_hash: ContentHash::compute(b"rrb-empty-prior"),
        rollback_hash: ContentHash::compute(b"rrb-empty-rollback"),
    };
    let summary = render_rollback_summary(&rollback);
    assert!(summary.contains("[ROLLBACK]"));
    assert!(summary.contains("triggers: []"));
}

// ---------------------------------------------------------------------------
// Specimen helpers
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_candidate_fields() {
    let c = specimen_candidate("spec", TransferableKind::SpecializationGuard, 900_000);
    assert_eq!(c.candidate_key, "spec");
    assert_eq!(c.kind, TransferableKind::SpecializationGuard);
    assert_eq!(c.proximity_score, 900_000);
    assert_eq!(c.donor_performance_estimate, 100_000);
    assert_eq!(c.donor_epoch, SecurityEpoch::from_raw(1));
    assert_eq!(c.donor_label, "donor-spec");
}

#[test]
fn enrichment_specimen_drift_signal_fields() {
    let s = specimen_drift_signal(DriftKind::TypeFeedbackMismatch, 75_000, false);
    assert_eq!(s.kind, DriftKind::TypeFeedbackMismatch);
    assert_eq!(s.magnitude_millionths, 75_000);
    assert_eq!(s.observation_count, 32);
    assert!(!s.confident);
}

#[test]
fn enrichment_specimen_session_fields() {
    let session = specimen_session();
    assert_eq!(session.session_key, "test-session");
    assert_eq!(session.epoch, SecurityEpoch::from_raw(5));
    assert_eq!(session.config, TransferConfig::default());
}

// ---------------------------------------------------------------------------
// Full pipeline: evaluate -> drift -> rollback -> report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_pipeline_lifecycle() {
    let mut session = make_session();
    session.config.min_drift_observations = 2;

    // Phase 1: Accept multiple candidates
    for kind in TransferableKind::ALL {
        let c = make_candidate(&format!("pipe-{kind}"), *kind);
        let d = session.evaluate_candidate(&c);
        assert_eq!(d.verdict, TransferVerdict::Accepted);
    }
    assert_eq!(session.active_transfers.len(), 5);

    // Phase 2: Record drift on two transfers
    let signal_high = specimen_drift_signal(DriftKind::PerformanceRegression, 300_000, true);
    session.record_drift("pipe-rewrite_pack", signal_high);
    session.record_clean_observation("pipe-rewrite_pack");
    session.record_clean_observation("pipe-rewrite_pack");

    let signal_low = specimen_drift_signal(DriftKind::CachePollution, 50_000, true);
    session.record_drift("pipe-cache_hint", signal_low);
    session.record_clean_observation("pipe-cache_hint");
    session.record_clean_observation("pipe-cache_hint");

    // Phase 3: Enforce drift guards
    let rollbacks = session.enforce_drift_guards();
    // Only rewrite_pack should be rolled back (300_000 > 150_000)
    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].candidate_key, "pipe-rewrite_pack");

    // Phase 4: Build report
    let report = session.build_report();
    assert_eq!(report.total_candidates, 5);
    assert_eq!(report.accepted, 5);
    assert_eq!(report.rolled_back_count, 1);
    assert_eq!(report.active_count, 4);
    // Worst drift is 300_000 (from the rolled-back transfer)
    assert_eq!(report.worst_drift_millionths, 300_000);
    assert!(!report.is_healthy()); // worst drift 300_000 >= DEFAULT_DRIFT_TOLERANCE (150_000)
}

#[test]
fn enrichment_pipeline_all_rejected() {
    let mut session = make_session();
    session
        .config
        .blocked_kinds
        .insert(TransferableKind::RewritePack);
    session
        .config
        .blocked_kinds
        .insert(TransferableKind::TieringPrior);
    session
        .config
        .blocked_kinds
        .insert(TransferableKind::CacheHint);
    session
        .config
        .blocked_kinds
        .insert(TransferableKind::AotArtifact);
    session
        .config
        .blocked_kinds
        .insert(TransferableKind::SpecializationGuard);

    for kind in TransferableKind::ALL {
        let c = make_candidate(&format!("blocked-{kind}"), *kind);
        let d = session.evaluate_candidate(&c);
        assert_eq!(d.verdict, TransferVerdict::Rejected);
        assert_eq!(d.reason, Some(TransferRejectionReason::KindBlocked));
    }

    let report = session.build_report();
    assert_eq!(report.total_candidates, 5);
    assert_eq!(report.accepted, 0);
    assert_eq!(report.rejected, 5);
    assert_eq!(report.acceptance_rate_millionths(), 0);
}
