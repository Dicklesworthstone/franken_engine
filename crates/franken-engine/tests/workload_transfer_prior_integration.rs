//! Integration tests for workload_transfer_prior (RGC-612B).
//!
//! Tests the cross-workload transfer engine: prior registration, eligibility
//! checks with neighborhood certificates, drift monitoring with budget
//! enforcement, revocation receipts, and evidence inventory generation.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::workload_transfer_prior::*;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn hash(label: &str) -> ContentHash {
    ContentHash::compute(label.as_bytes())
}

fn prior(id: &str, kind: TransferKind, ep: u64, confidence: i64, rules: usize) -> PriorEntry {
    PriorEntry {
        prior_id: id.to_string(),
        kind,
        source_embedding_id: format!("emb-{}", id),
        source_epoch: epoch(ep),
        confidence_millionths: confidence,
        observation_count: 100,
        rule_keys: (0..rules).map(|i| format!("r{}", i)).collect(),
        rule_count: rules,
        revoked: false,
        artifact_hash: hash(id),
    }
}

fn engine_default(ep: u64) -> TransferEngine {
    TransferEngine::with_defaults(epoch(ep))
}

fn tinput<'a>(
    transfer_id: &'a str,
    prior_id: &'a str,
    target_embedding_id: &'a str,
    certificate_id: &'a str,
) -> ExecuteTransferInput<'a> {
    ExecuteTransferInput {
        transfer_id,
        prior_id,
        target_embedding_id,
        certificate_id,
        certificate_near: true,
        certificate_marginal: false,
        certificate_abstained: false,
    }
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_is_stable() {
    assert_eq!(
        TRANSFER_PRIOR_SCHEMA_VERSION,
        "franken-engine.workload-transfer-prior.v1"
    );
}

#[test]
fn default_constants_are_reasonable() {
    const {
        assert!(MAX_TRANSFERRED_RULES >= 64);
        assert!(DEFAULT_DRIFT_BUDGET_MILLIONTHS > 0);
        assert!(DEFAULT_CONFIDENCE_FLOOR_MILLIONTHS > 0);
        assert!(DEFAULT_MAX_PRIOR_AGE_EPOCHS >= 1);
    }
}

// ---------------------------------------------------------------------------
// TransferKind coverage
// ---------------------------------------------------------------------------

#[test]
fn transfer_kind_all_variants_display() {
    let kinds = [
        TransferKind::RewritePack,
        TransferKind::TieringPrior,
        TransferKind::CacheHint,
        TransferKind::ShapePrior,
        TransferKind::GcTuningPrior,
        TransferKind::SchedulerPrior,
    ];
    for kind in &kinds {
        let s = kind.to_string();
        assert!(!s.is_empty());
    }
    // All distinct
    let strings: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
    for (i, a) in strings.iter().enumerate() {
        for (j, b) in strings.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn transfer_kind_serde_roundtrip_all() {
    let kinds = [
        TransferKind::RewritePack,
        TransferKind::TieringPrior,
        TransferKind::CacheHint,
        TransferKind::ShapePrior,
        TransferKind::GcTuningPrior,
        TransferKind::SchedulerPrior,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: TransferKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// TransferDenialReason coverage
// ---------------------------------------------------------------------------

#[test]
fn denial_reason_all_variants_display() {
    let reasons = [
        TransferDenialReason::DistantWorkloads,
        TransferDenialReason::CertificateAbstained,
        TransferDenialReason::StalePrior,
        TransferDenialReason::RevokedPrior,
        TransferDenialReason::InsufficientConfidence,
        TransferDenialReason::KindNotPermitted,
        TransferDenialReason::DriftBudgetExhausted,
        TransferDenialReason::RuleLimitExceeded,
        TransferDenialReason::EpochIncompatible,
        TransferDenialReason::InvalidSourceEmbedding,
    ];
    for reason in &reasons {
        assert!(!reason.to_string().is_empty());
    }
}

#[test]
fn denial_reason_serde_roundtrip_all() {
    let reasons = [
        TransferDenialReason::DistantWorkloads,
        TransferDenialReason::CertificateAbstained,
        TransferDenialReason::StalePrior,
        TransferDenialReason::RevokedPrior,
        TransferDenialReason::InsufficientConfidence,
        TransferDenialReason::KindNotPermitted,
        TransferDenialReason::DriftBudgetExhausted,
        TransferDenialReason::RuleLimitExceeded,
        TransferDenialReason::EpochIncompatible,
        TransferDenialReason::InvalidSourceEmbedding,
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: TransferDenialReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

// ---------------------------------------------------------------------------
// TransferEligibility
// ---------------------------------------------------------------------------

#[test]
fn eligibility_eligible_properties() {
    let e = TransferEligibility::Eligible {
        confidence_millionths: 850_000,
        marginal: false,
    };
    assert!(e.is_eligible());
    assert!(!e.is_marginal());
    assert_eq!(e.confidence(), Some(850_000));
    assert!(e.to_string().contains("eligible"));
}

#[test]
fn eligibility_marginal_properties() {
    let e = TransferEligibility::Eligible {
        confidence_millionths: 700_000,
        marginal: true,
    };
    assert!(e.is_eligible());
    assert!(e.is_marginal());
    assert_eq!(e.confidence(), Some(700_000));
}

#[test]
fn eligibility_denied_properties() {
    let e = TransferEligibility::Denied {
        reason: TransferDenialReason::DistantWorkloads,
    };
    assert!(!e.is_eligible());
    assert!(!e.is_marginal());
    assert_eq!(e.confidence(), None);
    assert!(e.to_string().contains("denied"));
}

// ---------------------------------------------------------------------------
// TransferPolicy
// ---------------------------------------------------------------------------

#[test]
fn default_policy_permits_all_kinds() {
    let p = TransferPolicy::default();
    assert!(p.permitted_kinds.contains(&TransferKind::RewritePack));
    assert!(p.permitted_kinds.contains(&TransferKind::TieringPrior));
    assert!(p.permitted_kinds.contains(&TransferKind::CacheHint));
    assert!(p.permitted_kinds.contains(&TransferKind::ShapePrior));
    assert!(p.permitted_kinds.contains(&TransferKind::GcTuningPrior));
    assert!(p.permitted_kinds.contains(&TransferKind::SchedulerPrior));
}

#[test]
fn policy_hash_deterministic() {
    let h1 = TransferPolicy::default().content_hash();
    let h2 = TransferPolicy::default().content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn policy_hash_sensitive_to_changes() {
    let h1 = TransferPolicy::default().content_hash();
    let mut p = TransferPolicy::default();
    p.max_prior_age_epochs = 999;
    assert_ne!(h1, p.content_hash());
}

#[test]
fn policy_serde_roundtrip() {
    let p = TransferPolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    let back: TransferPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// PriorEntry
// ---------------------------------------------------------------------------

#[test]
fn prior_freshness_boundary() {
    let p = prior("p1", TransferKind::RewritePack, 5, 900_000, 10);
    // max_age=10: epoch 5..15 is fresh
    assert!(p.is_fresh(epoch(5), 10));
    assert!(p.is_fresh(epoch(15), 10));
    assert!(!p.is_fresh(epoch(16), 10));
}

#[test]
fn prior_confidence_boundary() {
    let p = prior("p1", TransferKind::RewritePack, 5, 700_000, 10);
    assert!(p.meets_confidence(700_000));
    assert!(!p.meets_confidence(700_001));
}

#[test]
fn prior_serde_roundtrip() {
    let p = prior("p1", TransferKind::CacheHint, 3, 850_000, 7);
    let json = serde_json::to_string(&p).unwrap();
    let back: PriorEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// TransferStatus
// ---------------------------------------------------------------------------

#[test]
fn status_active_classification() {
    assert!(TransferStatus::Active.is_active());
    assert!(TransferStatus::Probationary.is_active());
    assert!(!TransferStatus::RevokedDrift.is_active());
    assert!(!TransferStatus::RevokedStale.is_active());
    assert!(!TransferStatus::RevokedManual.is_active());
    assert!(!TransferStatus::Completed.is_active());
}

#[test]
fn status_revoked_classification() {
    assert!(!TransferStatus::Active.is_revoked());
    assert!(!TransferStatus::Probationary.is_revoked());
    assert!(TransferStatus::RevokedDrift.is_revoked());
    assert!(TransferStatus::RevokedStale.is_revoked());
    assert!(TransferStatus::RevokedManual.is_revoked());
    assert!(!TransferStatus::Completed.is_revoked());
}

#[test]
fn status_display_all_variants() {
    let statuses = [
        TransferStatus::Active,
        TransferStatus::Probationary,
        TransferStatus::RevokedDrift,
        TransferStatus::RevokedStale,
        TransferStatus::RevokedManual,
        TransferStatus::Completed,
    ];
    for s in &statuses {
        assert!(!s.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// DriftObservation
// ---------------------------------------------------------------------------

#[test]
fn drift_observation_auto_divergence() {
    let obs = DriftObservation::new("t1", "gc_pressure", 400_000, 600_000, epoch(5), 1);
    assert_eq!(obs.divergence_millionths, 200_000);
}

#[test]
fn drift_observation_negative_direction() {
    let obs = DriftObservation::new("t1", "exec_time", 600_000, 400_000, epoch(5), 1);
    assert_eq!(obs.divergence_millionths, 200_000); // abs value
}

#[test]
fn drift_observation_budget_check() {
    let obs = DriftObservation::new("t1", "exec_time", 500_000, 510_000, epoch(5), 1);
    assert!(!obs.exceeds_budget(100_000));
    assert!(obs.exceeds_budget(5_000));
}

#[test]
fn drift_observation_serde_roundtrip() {
    let obs = DriftObservation::new("t1", "exec_time", 500_000, 510_000, epoch(5), 1);
    let json = serde_json::to_string(&obs).unwrap();
    let back: DriftObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

// ---------------------------------------------------------------------------
// DriftVerdict
// ---------------------------------------------------------------------------

#[test]
fn drift_verdict_display_within_budget() {
    let v = DriftVerdict::WithinBudget {
        accumulated_millionths: 30_000,
        remaining_millionths: 70_000,
    };
    assert!(v.to_string().contains("within_budget"));
}

#[test]
fn drift_verdict_display_exceeded() {
    let v = DriftVerdict::BudgetExceeded {
        accumulated_millionths: 150_000,
        budget_millionths: 100_000,
        trigger_metric: "exec_time".to_string(),
    };
    assert!(v.to_string().contains("budget_exceeded"));
    assert!(v.to_string().contains("exec_time"));
}

#[test]
fn drift_verdict_display_insufficient() {
    let v = DriftVerdict::InsufficientData {
        observations: 2,
        minimum_required: 10,
    };
    assert!(v.to_string().contains("insufficient_data"));
}

#[test]
fn drift_verdict_serde_roundtrip() {
    let v = DriftVerdict::BudgetExceeded {
        accumulated_millionths: 150_000,
        budget_millionths: 100_000,
        trigger_metric: "gc_rate".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: DriftVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// TransferError
// ---------------------------------------------------------------------------

#[test]
fn transfer_error_display_variants() {
    let errors: Vec<TransferError> = vec![
        TransferError::PriorNotFound {
            prior_id: "p1".into(),
        },
        TransferError::TransferNotFound {
            transfer_id: "t1".into(),
        },
        TransferError::TransferNotActive {
            transfer_id: "t1".into(),
            status: TransferStatus::Completed,
        },
        TransferError::PolicyViolation {
            reason: TransferDenialReason::StalePrior,
        },
        TransferError::DuplicateTransfer {
            transfer_id: "t1".into(),
        },
        TransferError::DuplicatePrior {
            prior_id: "p1".into(),
        },
        TransferError::CertificateRejection {
            certificate_id: "c1".into(),
        },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// RevocationReceipt
// ---------------------------------------------------------------------------

#[test]
fn revocation_receipt_sign_verify() {
    let key = b"secret-key-42";
    let receipt = RevocationReceipt {
        transfer_id: "t1".to_string(),
        reason: TransferStatus::RevokedManual,
        drift_verdict: None,
        revocation_epoch: epoch(10),
        tick: 99,
        content_hash: hash("t1"),
        signature: hash("unsigned"),
    };
    let signed = receipt.sign(key);
    assert!(signed.verify_signature(key));
    assert!(!signed.verify_signature(b"wrong-key"));
}

#[test]
fn revocation_receipt_with_drift_verdict() {
    let receipt = RevocationReceipt {
        transfer_id: "t1".to_string(),
        reason: TransferStatus::RevokedDrift,
        drift_verdict: Some(DriftVerdict::BudgetExceeded {
            accumulated_millionths: 200_000,
            budget_millionths: 100_000,
            trigger_metric: "alloc_rate".to_string(),
        }),
        revocation_epoch: epoch(10),
        tick: 99,
        content_hash: hash("t1"),
        signature: hash("unsigned"),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: RevocationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// TransferRecord
// ---------------------------------------------------------------------------

#[test]
fn transfer_record_hash_deterministic() {
    let record = TransferRecord {
        transfer_id: "t1".to_string(),
        prior_id: "p1".to_string(),
        source_embedding_id: "src".to_string(),
        target_embedding_id: "tgt".to_string(),
        certificate_id: "cert1".to_string(),
        kind: TransferKind::TieringPrior,
        status: TransferStatus::Probationary,
        eligibility: TransferEligibility::Eligible {
            confidence_millionths: 800_000,
            marginal: true,
        },
        transfer_epoch: epoch(5),
        rules_transferred: 8,
        accumulated_drift_millionths: 0,
        drift_observations: 0,
        content_hash: hash("t1"),
    };
    assert_eq!(record.compute_hash(), record.compute_hash());
}

// ---------------------------------------------------------------------------
// TransferEngine: registration
// ---------------------------------------------------------------------------

#[test]
fn engine_register_prior_success() {
    let mut engine = engine_default(5);
    let p = prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
    engine.register_prior(p).unwrap();
    assert_eq!(engine.prior_count(), 1);
    assert!(engine.get_prior("p1").is_some());
}

#[test]
fn engine_register_duplicate_fails() {
    let mut engine = engine_default(5);
    let p = prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
    engine.register_prior(p.clone()).unwrap();
    assert!(engine.register_prior(p).is_err());
}

#[test]
fn engine_register_multiple_priors() {
    let mut engine = engine_default(5);
    for i in 0..5 {
        let p = prior(&format!("p{}", i), TransferKind::RewritePack, 3, 900_000, 5);
        engine.register_prior(p).unwrap();
    }
    assert_eq!(engine.prior_count(), 5);
}

// ---------------------------------------------------------------------------
// TransferEngine: eligibility checks
// ---------------------------------------------------------------------------

#[test]
fn eligibility_near_certificate_allowed() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();

    let e = engine
        .check_eligibility("p1", "tgt1", true, false, false)
        .unwrap();
    assert!(e.is_eligible());
    assert!(!e.is_marginal());
    assert_eq!(e.confidence(), Some(900_000));
}

#[test]
fn eligibility_marginal_certificate_discounted() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();

    let e = engine
        .check_eligibility("p1", "tgt1", false, true, false)
        .unwrap();
    assert!(e.is_eligible());
    assert!(e.is_marginal());
    assert_eq!(e.confidence(), Some(700_000)); // 900k - 200k
}

#[test]
fn eligibility_marginal_below_floor_denied() {
    let mut engine = engine_default(5);
    // Confidence at 800k, marginal discount 200k -> 600k < 700k floor
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 800_000, 10))
        .unwrap();

    let e = engine
        .check_eligibility("p1", "tgt1", false, true, false)
        .unwrap();
    assert!(!e.is_eligible());
}

#[test]
fn eligibility_distant_denied() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();

    let e = engine
        .check_eligibility("p1", "tgt1", false, false, false)
        .unwrap();
    assert!(matches!(
        e,
        TransferEligibility::Denied {
            reason: TransferDenialReason::DistantWorkloads
        }
    ));
}

#[test]
fn eligibility_abstained_denied() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();

    let e = engine
        .check_eligibility("p1", "tgt1", false, false, true)
        .unwrap();
    assert!(matches!(
        e,
        TransferEligibility::Denied {
            reason: TransferDenialReason::CertificateAbstained
        }
    ));
}

#[test]
fn eligibility_stale_prior_denied() {
    let mut engine = engine_default(100);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();

    let e = engine
        .check_eligibility("p1", "tgt1", true, false, false)
        .unwrap();
    assert!(matches!(
        e,
        TransferEligibility::Denied {
            reason: TransferDenialReason::StalePrior
        }
    ));
}

#[test]
fn eligibility_revoked_prior_denied() {
    let mut engine = engine_default(5);
    let mut p = prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
    p.revoked = true;
    engine.register_prior(p).unwrap();

    let e = engine
        .check_eligibility("p1", "tgt1", true, false, false)
        .unwrap();
    assert!(matches!(
        e,
        TransferEligibility::Denied {
            reason: TransferDenialReason::RevokedPrior
        }
    ));
}

#[test]
fn eligibility_low_confidence_denied() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 500_000, 10))
        .unwrap();

    let e = engine
        .check_eligibility("p1", "tgt1", true, false, false)
        .unwrap();
    assert!(matches!(
        e,
        TransferEligibility::Denied {
            reason: TransferDenialReason::InsufficientConfidence
        }
    ));
}

#[test]
fn eligibility_kind_not_permitted() {
    let mut policy = TransferPolicy::default();
    policy.permitted_kinds.remove(&TransferKind::GcTuningPrior);
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(prior("p1", TransferKind::GcTuningPrior, 3, 900_000, 10))
        .unwrap();

    let e = engine
        .check_eligibility("p1", "tgt1", true, false, false)
        .unwrap();
    assert!(matches!(
        e,
        TransferEligibility::Denied {
            reason: TransferDenialReason::KindNotPermitted
        }
    ));
}

#[test]
fn eligibility_prior_not_found() {
    let engine = engine_default(5);
    assert!(
        engine
            .check_eligibility("nope", "tgt1", true, false, false)
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// TransferEngine: execute transfer
// ---------------------------------------------------------------------------

#[test]
fn execute_transfer_success_probationary() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();

    let r = engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    assert_eq!(r.status, TransferStatus::Probationary);
    assert_eq!(r.rules_transferred, 10);
    assert_eq!(engine.active_transfer_count(), 1);
}

#[test]
fn execute_transfer_no_monitoring_active() {
    let mut policy = TransferPolicy::default();
    policy.require_drift_monitoring = false;
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();

    let r = engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    assert_eq!(r.status, TransferStatus::Active);
}

#[test]
fn execute_transfer_duplicate_fails() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    assert!(
        engine
            .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
            .is_err()
    );
}

#[test]
fn execute_transfer_policy_violation() {
    let mut engine = engine_default(100); // prior will be stale
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();

    assert!(
        engine
            .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// TransferEngine: drift monitoring
// ---------------------------------------------------------------------------

#[test]
fn drift_monitoring_within_budget() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    let obs = DriftObservation::new("t1", "exec_time", 500_000, 510_000, epoch(5), 1);
    let v = engine.record_drift(obs).unwrap();
    assert!(matches!(v, DriftVerdict::WithinBudget { .. }));
}

#[test]
fn drift_monitoring_budget_exceeded_revokes() {
    let mut policy = TransferPolicy::default();
    policy.drift_budget_millionths = 50_000;
    policy.require_drift_monitoring = false;
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    let obs = DriftObservation::new("t1", "exec_time", 500_000, 700_000, epoch(5), 1);
    let v = engine.record_drift(obs).unwrap();
    assert!(matches!(v, DriftVerdict::BudgetExceeded { .. }));

    let t = engine.get_transfer("t1").unwrap();
    assert_eq!(t.status, TransferStatus::RevokedDrift);
    assert!(engine.get_revocation("t1").is_some());
}

#[test]
fn drift_monitoring_not_active_fails() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    engine.revoke_transfer("t1").unwrap();

    let obs = DriftObservation::new("t1", "exec_time", 500_000, 510_000, epoch(5), 1);
    assert!(engine.record_drift(obs).is_err());
}

#[test]
fn drift_monitoring_multiple_observations() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    for i in 0..10 {
        let obs = DriftObservation::new("t1", "exec_time", 500_000, 505_000, epoch(5), i);
        let v = engine.record_drift(obs).unwrap();
        assert!(matches!(v, DriftVerdict::WithinBudget { .. }));
    }

    let t = engine.get_transfer("t1").unwrap();
    assert_eq!(t.drift_observations, 10);
    assert!(t.accumulated_drift_millionths < DEFAULT_DRIFT_BUDGET_MILLIONTHS);
}

// ---------------------------------------------------------------------------
// TransferEngine: promote
// ---------------------------------------------------------------------------

#[test]
fn promote_probationary_to_active() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    assert_eq!(
        engine.get_transfer("t1").unwrap().status,
        TransferStatus::Probationary
    );
    engine.promote_transfer("t1").unwrap();
    assert_eq!(
        engine.get_transfer("t1").unwrap().status,
        TransferStatus::Active
    );
}

#[test]
fn promote_active_fails() {
    let mut policy = TransferPolicy::default();
    policy.require_drift_monitoring = false;
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    assert!(engine.promote_transfer("t1").is_err()); // already Active
}

// ---------------------------------------------------------------------------
// TransferEngine: revoke
// ---------------------------------------------------------------------------

#[test]
fn manual_revoke_produces_receipt() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    let receipt = engine.revoke_transfer("t1").unwrap();
    assert_eq!(receipt.reason, TransferStatus::RevokedManual);
    assert_eq!(engine.revoked_transfer_count(), 1);
}

#[test]
fn revoke_already_revoked_fails() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    engine.revoke_transfer("t1").unwrap();

    assert!(engine.revoke_transfer("t1").is_err());
}

// ---------------------------------------------------------------------------
// TransferEngine: complete
// ---------------------------------------------------------------------------

#[test]
fn complete_transfer_success() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    engine.complete_transfer("t1").unwrap();
    assert_eq!(
        engine.get_transfer("t1").unwrap().status,
        TransferStatus::Completed
    );
    assert_eq!(engine.active_transfer_count(), 0);
}

#[test]
fn complete_revoked_transfer_fails() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    engine.revoke_transfer("t1").unwrap();

    assert!(engine.complete_transfer("t1").is_err());
}

// ---------------------------------------------------------------------------
// TransferEngine: expire stale
// ---------------------------------------------------------------------------

#[test]
fn expire_stale_priors_revokes() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    engine.advance_epoch(epoch(100));
    let expired = engine.expire_stale_priors();
    assert_eq!(expired, vec!["t1"]);
    assert_eq!(
        engine.get_transfer("t1").unwrap().status,
        TransferStatus::RevokedStale
    );
}

#[test]
fn expire_stale_skips_fresh() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    engine.advance_epoch(epoch(6));
    let expired = engine.expire_stale_priors();
    assert!(expired.is_empty());
}

// ---------------------------------------------------------------------------
// TransferEngine: summary
// ---------------------------------------------------------------------------

#[test]
fn summary_counts_by_status() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .register_prior(prior("p2", TransferKind::CacheHint, 3, 800_000, 5))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    engine
        .execute_transfer(&tinput("t2", "p2", "tgt1", "c2"))
        .unwrap();
    engine.revoke_transfer("t1").unwrap();

    let s = engine.summarize_target("tgt1");
    assert_eq!(s.probationary_count, 1);
    assert_eq!(s.revoked_count, 1);
    assert_eq!(s.active_rules, 5); // only t2's rules
}

#[test]
fn summary_empty_target() {
    let engine = engine_default(5);
    let s = engine.summarize_target("nonexistent");
    assert_eq!(s.active_count, 0);
    assert_eq!(s.active_rules, 0);
}

#[test]
fn summary_kind_breakdown() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .register_prior(prior("p2", TransferKind::TieringPrior, 3, 800_000, 5))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    engine
        .execute_transfer(&tinput("t2", "p2", "tgt1", "c2"))
        .unwrap();

    let s = engine.summarize_target("tgt1");
    assert_eq!(s.kind_breakdown.len(), 2);
    assert_eq!(*s.kind_breakdown.get("rewrite_pack").unwrap(), 1);
    assert_eq!(*s.kind_breakdown.get("tiering_prior").unwrap(), 1);
}

// ---------------------------------------------------------------------------
// TransferEngine: active transfers query
// ---------------------------------------------------------------------------

#[test]
fn active_transfers_for_target() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .register_prior(prior("p2", TransferKind::CacheHint, 3, 800_000, 5))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    engine
        .execute_transfer(&tinput("t2", "p2", "tgt1", "c2"))
        .unwrap();
    engine
        .execute_transfer(&tinput("t3", "p1", "tgt2", "c3"))
        .unwrap();

    assert_eq!(engine.active_transfers_for("tgt1").len(), 2);
    assert_eq!(engine.active_transfers_for("tgt2").len(), 1);
    assert_eq!(engine.active_transfers_for("tgt3").len(), 0);
}

// ---------------------------------------------------------------------------
// TransferEngine: evidence inventory
// ---------------------------------------------------------------------------

#[test]
fn evidence_inventory_counts() {
    let mut engine = engine_default(5);
    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    engine.revoke_transfer("t1").unwrap();

    let inv = engine.evidence_inventory();
    assert_eq!(inv.total_priors, 1);
    assert_eq!(inv.total_transfers, 1);
    assert_eq!(inv.total_revocations, 1);
    assert_eq!(inv.schema_version, TRANSFER_PRIOR_SCHEMA_VERSION);
}

#[test]
fn evidence_inventory_serde_roundtrip() {
    let inv = TransferEvidenceInventory {
        schema_version: TRANSFER_PRIOR_SCHEMA_VERSION.to_string(),
        total_priors: 3,
        total_transfers: 2,
        total_revocations: 1,
        by_kind: BTreeMap::new(),
        by_status: BTreeMap::new(),
        policy_hash: hash("policy"),
        epoch: epoch(10),
    };
    let json = serde_json::to_string(&inv).unwrap();
    let back: TransferEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ---------------------------------------------------------------------------
// TransferEngine: full lifecycle pipeline
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_register_transfer_monitor_promote_complete() {
    let mut engine = engine_default(5);
    let p = prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
    engine.register_prior(p).unwrap();

    // Transfer
    let r = engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    assert_eq!(r.status, TransferStatus::Probationary);

    // Monitor drift
    for i in 0..5 {
        let obs = DriftObservation::new("t1", "exec_time", 500_000, 502_000, epoch(5), i);
        let v = engine.record_drift(obs).unwrap();
        assert!(matches!(v, DriftVerdict::WithinBudget { .. }));
    }

    // Promote
    engine.promote_transfer("t1").unwrap();
    assert_eq!(
        engine.get_transfer("t1").unwrap().status,
        TransferStatus::Active
    );

    // Complete
    engine.complete_transfer("t1").unwrap();
    assert_eq!(
        engine.get_transfer("t1").unwrap().status,
        TransferStatus::Completed
    );
    assert_eq!(engine.active_transfer_count(), 0);
}

#[test]
fn full_lifecycle_drift_revocation_then_new_transfer() {
    let mut policy = TransferPolicy::default();
    policy.drift_budget_millionths = 30_000;
    policy.require_drift_monitoring = false;
    let mut engine = TransferEngine::new(policy, epoch(5));

    let p1 = prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
    let p2 = prior("p2", TransferKind::CacheHint, 3, 900_000, 5);
    engine.register_prior(p1).unwrap();
    engine.register_prior(p2).unwrap();

    // First transfer, drift exceeds budget
    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();
    let obs = DriftObservation::new("t1", "exec_time", 500_000, 600_000, epoch(5), 1);
    let v = engine.record_drift(obs).unwrap();
    assert!(matches!(v, DriftVerdict::BudgetExceeded { .. }));

    // Second transfer with different prior still works (rule budget reclaimed)
    let r2 = engine
        .execute_transfer(&tinput("t2", "p2", "tgt1", "c2"))
        .unwrap();
    assert_eq!(r2.status, TransferStatus::Active);
}

#[test]
fn rule_budget_accounting_across_transfers() {
    let mut policy = TransferPolicy::default();
    policy.max_transferred_rules = 20;
    let mut engine = TransferEngine::new(policy, epoch(5));

    engine
        .register_prior(prior("p1", TransferKind::RewritePack, 3, 900_000, 15))
        .unwrap();
    engine
        .register_prior(prior("p2", TransferKind::CacheHint, 3, 900_000, 10))
        .unwrap();

    engine
        .execute_transfer(&tinput("t1", "p1", "tgt1", "c1"))
        .unwrap();

    // 15 + 10 = 25 > 20
    assert!(
        engine
            .execute_transfer(&tinput("t2", "p2", "tgt1", "c2"))
            .is_err()
    );

    // Revoke t1, freeing 15
    engine.revoke_transfer("t1").unwrap();

    // Now 0 + 10 = 10 ≤ 20
    engine
        .execute_transfer(&tinput("t2", "p2", "tgt1", "c2"))
        .unwrap();
}

// ---------------------------------------------------------------------------
// TransferSummary serde
// ---------------------------------------------------------------------------

#[test]
fn transfer_summary_serde_roundtrip() {
    let mut kind_breakdown = BTreeMap::new();
    kind_breakdown.insert("rewrite_pack".to_string(), 3);
    kind_breakdown.insert("cache_hint".to_string(), 2);

    let s = TransferSummary {
        target_embedding_id: "tgt1".to_string(),
        active_count: 3,
        probationary_count: 2,
        revoked_count: 1,
        completed_count: 0,
        active_rules: 25,
        kind_breakdown,
        max_drift_millionths: 40_000,
        summary_epoch: epoch(10),
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: TransferSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}
