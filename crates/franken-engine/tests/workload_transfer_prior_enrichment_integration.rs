#![forbid(unsafe_code)]

//! Enrichment integration tests for `workload_transfer_prior` module.
//! Covers Display uniqueness, serde roundtrips, method behavior, edge cases,
//! deterministic hash behavior, and full engine lifecycle scenarios.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::workload_transfer_prior::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn hash(label: &str) -> ContentHash {
    ContentHash::compute(label.as_bytes())
}

fn make_prior(
    id: &str,
    kind: TransferKind,
    ep: u64,
    confidence: i64,
    rules: usize,
) -> PriorEntry {
    PriorEntry {
        prior_id: id.to_string(),
        kind,
        source_embedding_id: format!("emb-src-{}", id),
        source_epoch: epoch(ep),
        confidence_millionths: confidence,
        observation_count: 100,
        rule_keys: (0..rules).map(|i| format!("rule-{}", i)).collect(),
        rule_count: rules,
        revoked: false,
        artifact_hash: hash(id),
    }
}

fn default_engine(ep: u64) -> TransferEngine {
    TransferEngine::with_defaults(epoch(ep))
}

fn near_input<'a>(
    transfer_id: &'a str,
    prior_id: &'a str,
    target: &'a str,
    cert: &'a str,
) -> ExecuteTransferInput<'a> {
    ExecuteTransferInput {
        transfer_id,
        prior_id,
        target_embedding_id: target,
        certificate_id: cert,
        certificate_near: true,
        certificate_marginal: false,
        certificate_abstained: false,
    }
}

fn marginal_input<'a>(
    transfer_id: &'a str,
    prior_id: &'a str,
    target: &'a str,
    cert: &'a str,
) -> ExecuteTransferInput<'a> {
    ExecuteTransferInput {
        transfer_id,
        prior_id,
        target_embedding_id: target,
        certificate_id: cert,
        certificate_near: false,
        certificate_marginal: true,
        certificate_abstained: false,
    }
}

// =========================================================================
// Display uniqueness tests
// =========================================================================

#[test]
fn enrichment_transfer_kind_display_all_unique() {
    let kinds = [
        TransferKind::RewritePack,
        TransferKind::TieringPrior,
        TransferKind::CacheHint,
        TransferKind::ShapePrior,
        TransferKind::GcTuningPrior,
        TransferKind::SchedulerPrior,
    ];
    let mut seen = BTreeSet::new();
    for k in &kinds {
        let s = k.to_string();
        assert!(!s.is_empty(), "Display must not be empty for {:?}", k);
        assert!(seen.insert(s.clone()), "Duplicate Display for {:?}: {}", k, s);
    }
    assert_eq!(seen.len(), 6);
}

#[test]
fn enrichment_transfer_kind_display_values() {
    assert_eq!(TransferKind::RewritePack.to_string(), "rewrite_pack");
    assert_eq!(TransferKind::TieringPrior.to_string(), "tiering_prior");
    assert_eq!(TransferKind::CacheHint.to_string(), "cache_hint");
    assert_eq!(TransferKind::ShapePrior.to_string(), "shape_prior");
    assert_eq!(TransferKind::GcTuningPrior.to_string(), "gc_tuning_prior");
    assert_eq!(TransferKind::SchedulerPrior.to_string(), "scheduler_prior");
}

#[test]
fn enrichment_transfer_denial_reason_display_all_unique() {
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
    let mut seen = BTreeSet::new();
    for r in &reasons {
        let s = r.to_string();
        assert!(!s.is_empty());
        assert!(seen.insert(s.clone()), "Duplicate Display for {:?}: {}", r, s);
    }
    assert_eq!(seen.len(), 10);
}

#[test]
fn enrichment_transfer_status_display_all_unique() {
    let statuses = [
        TransferStatus::Active,
        TransferStatus::Probationary,
        TransferStatus::RevokedDrift,
        TransferStatus::RevokedStale,
        TransferStatus::RevokedManual,
        TransferStatus::Completed,
    ];
    let mut seen = BTreeSet::new();
    for s in &statuses {
        let display = s.to_string();
        assert!(!display.is_empty());
        assert!(seen.insert(display.clone()), "Duplicate Display: {}", display);
    }
    assert_eq!(seen.len(), 6);
}

#[test]
fn enrichment_transfer_status_display_values() {
    assert_eq!(TransferStatus::Active.to_string(), "active");
    assert_eq!(TransferStatus::Probationary.to_string(), "probationary");
    assert_eq!(TransferStatus::RevokedDrift.to_string(), "revoked_drift");
    assert_eq!(TransferStatus::RevokedStale.to_string(), "revoked_stale");
    assert_eq!(TransferStatus::RevokedManual.to_string(), "revoked_manual");
    assert_eq!(TransferStatus::Completed.to_string(), "completed");
}

#[test]
fn enrichment_drift_verdict_display_all_variants() {
    let wb = DriftVerdict::WithinBudget {
        accumulated_millionths: 10_000,
        remaining_millionths: 90_000,
    };
    assert!(wb.to_string().contains("within_budget"));
    assert!(wb.to_string().contains("10000"));
    assert!(wb.to_string().contains("90000"));

    let be = DriftVerdict::BudgetExceeded {
        accumulated_millionths: 200_000,
        budget_millionths: 100_000,
        trigger_metric: "gc_pressure".to_string(),
    };
    assert!(be.to_string().contains("budget_exceeded"));
    assert!(be.to_string().contains("gc_pressure"));

    let id = DriftVerdict::InsufficientData {
        observations: 3,
        minimum_required: 10,
    };
    assert!(id.to_string().contains("insufficient_data"));
    assert!(id.to_string().contains("3"));
    assert!(id.to_string().contains("10"));
}

#[test]
fn enrichment_transfer_eligibility_display_eligible() {
    let e = TransferEligibility::Eligible {
        confidence_millionths: 850_000,
        marginal: true,
    };
    let s = e.to_string();
    assert!(s.contains("eligible"));
    assert!(s.contains("850000"));
    assert!(s.contains("true"));
}

#[test]
fn enrichment_transfer_eligibility_display_denied() {
    let e = TransferEligibility::Denied {
        reason: TransferDenialReason::EpochIncompatible,
    };
    let s = e.to_string();
    assert!(s.contains("denied"));
    assert!(s.contains("epoch_incompatible"));
}

#[test]
fn enrichment_transfer_error_display_all_variants() {
    let variants: Vec<TransferError> = vec![
        TransferError::PriorNotFound {
            prior_id: "pX".to_string(),
        },
        TransferError::TransferNotFound {
            transfer_id: "tX".to_string(),
        },
        TransferError::TransferNotActive {
            transfer_id: "tY".to_string(),
            status: TransferStatus::Completed,
        },
        TransferError::PolicyViolation {
            reason: TransferDenialReason::RuleLimitExceeded,
        },
        TransferError::DuplicateTransfer {
            transfer_id: "tZ".to_string(),
        },
        TransferError::DuplicatePrior {
            prior_id: "pZ".to_string(),
        },
        TransferError::CertificateRejection {
            certificate_id: "cR".to_string(),
        },
    ];
    let mut displays = BTreeSet::new();
    for v in &variants {
        let s = v.to_string();
        assert!(!s.is_empty());
        displays.insert(s);
    }
    assert_eq!(displays.len(), variants.len(), "All TransferError Display must be unique");
}

// =========================================================================
// Serde roundtrip tests
// =========================================================================

#[test]
fn enrichment_serde_roundtrip_transfer_kind_all_variants() {
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

#[test]
fn enrichment_serde_roundtrip_denial_reason_all_variants() {
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

#[test]
fn enrichment_serde_roundtrip_transfer_status_all_variants() {
    let statuses = [
        TransferStatus::Active,
        TransferStatus::Probationary,
        TransferStatus::RevokedDrift,
        TransferStatus::RevokedStale,
        TransferStatus::RevokedManual,
        TransferStatus::Completed,
    ];
    for status in &statuses {
        let json = serde_json::to_string(status).unwrap();
        let back: TransferStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, back);
    }
}

#[test]
fn enrichment_serde_roundtrip_eligibility_eligible() {
    let e = TransferEligibility::Eligible {
        confidence_millionths: 750_000,
        marginal: false,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: TransferEligibility = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_serde_roundtrip_eligibility_marginal() {
    let e = TransferEligibility::Eligible {
        confidence_millionths: 700_000,
        marginal: true,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: TransferEligibility = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_serde_roundtrip_eligibility_denied() {
    let e = TransferEligibility::Denied {
        reason: TransferDenialReason::InvalidSourceEmbedding,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: TransferEligibility = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_serde_roundtrip_transfer_policy() {
    let policy = TransferPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: TransferPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_serde_roundtrip_prior_entry_with_many_rules() {
    let prior = PriorEntry {
        prior_id: "large-prior".to_string(),
        kind: TransferKind::ShapePrior,
        source_embedding_id: "emb-large".to_string(),
        source_epoch: epoch(42),
        confidence_millionths: 999_999,
        observation_count: 1_000_000,
        rule_keys: (0..100).map(|i| format!("key-{}", i)).collect(),
        rule_count: 100,
        revoked: false,
        artifact_hash: hash("large-artifact"),
    };
    let json = serde_json::to_string(&prior).unwrap();
    let back: PriorEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(prior, back);
}

#[test]
fn enrichment_serde_roundtrip_drift_observation() {
    let obs = DriftObservation::new("t-serde", "latency", 100_000, 300_000, epoch(7), 99);
    let json = serde_json::to_string(&obs).unwrap();
    let back: DriftObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, back);
}

#[test]
fn enrichment_serde_roundtrip_drift_verdict_within_budget() {
    let v = DriftVerdict::WithinBudget {
        accumulated_millionths: 5_000,
        remaining_millionths: 95_000,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: DriftVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_serde_roundtrip_drift_verdict_insufficient_data() {
    let v = DriftVerdict::InsufficientData {
        observations: 2,
        minimum_required: 50,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: DriftVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_serde_roundtrip_revocation_receipt_with_drift_verdict() {
    let receipt = RevocationReceipt {
        transfer_id: "t-rev".to_string(),
        reason: TransferStatus::RevokedDrift,
        drift_verdict: Some(DriftVerdict::BudgetExceeded {
            accumulated_millionths: 200_000,
            budget_millionths: 100_000,
            trigger_metric: "heap_fragmentation".to_string(),
        }),
        revocation_epoch: epoch(20),
        tick: 777,
        content_hash: hash("rev-content"),
        signature: hash("rev-sig"),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: RevocationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_serde_roundtrip_revocation_receipt_without_drift_verdict() {
    let receipt = RevocationReceipt {
        transfer_id: "t-manual".to_string(),
        reason: TransferStatus::RevokedManual,
        drift_verdict: None,
        revocation_epoch: epoch(15),
        tick: 50,
        content_hash: hash("manual-content"),
        signature: hash("manual-sig"),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: RevocationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_serde_roundtrip_transfer_summary_with_breakdown() {
    let mut breakdown = BTreeMap::new();
    breakdown.insert("rewrite_pack".to_string(), 3);
    breakdown.insert("cache_hint".to_string(), 1);
    let summary = TransferSummary {
        target_embedding_id: "tgt-summ".to_string(),
        active_count: 3,
        probationary_count: 1,
        revoked_count: 2,
        completed_count: 5,
        active_rules: 42,
        kind_breakdown: breakdown,
        max_drift_millionths: 75_000,
        summary_epoch: epoch(30),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: TransferSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrichment_serde_roundtrip_transfer_evidence_inventory() {
    let mut by_kind = BTreeMap::new();
    by_kind.insert("rewrite_pack".to_string(), 5);
    let mut by_status = BTreeMap::new();
    by_status.insert("active".to_string(), 3);
    by_status.insert("revoked_drift".to_string(), 2);
    let inv = TransferEvidenceInventory {
        schema_version: TRANSFER_PRIOR_SCHEMA_VERSION.to_string(),
        total_priors: 10,
        total_transfers: 8,
        total_revocations: 2,
        by_kind,
        by_status,
        policy_hash: hash("policy-hash"),
        epoch: epoch(50),
    };
    let json = serde_json::to_string(&inv).unwrap();
    let back: TransferEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn enrichment_serde_roundtrip_transfer_error_all_variants() {
    let variants: Vec<TransferError> = vec![
        TransferError::PriorNotFound { prior_id: "pA".to_string() },
        TransferError::TransferNotFound { transfer_id: "tA".to_string() },
        TransferError::TransferNotActive {
            transfer_id: "tB".to_string(),
            status: TransferStatus::RevokedStale,
        },
        TransferError::PolicyViolation {
            reason: TransferDenialReason::DriftBudgetExhausted,
        },
        TransferError::DuplicateTransfer { transfer_id: "tC".to_string() },
        TransferError::DuplicatePrior { prior_id: "pC".to_string() },
        TransferError::CertificateRejection { certificate_id: "cA".to_string() },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: TransferError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// =========================================================================
// Constants
// =========================================================================

#[test]
fn enrichment_constants_values() {
    assert_eq!(TRANSFER_PRIOR_SCHEMA_VERSION, "franken-engine.workload-transfer-prior.v1");
    assert_eq!(MAX_TRANSFERRED_RULES, 512);
    assert_eq!(DEFAULT_DRIFT_BUDGET_MILLIONTHS, 100_000);
    assert_eq!(DEFAULT_CONFIDENCE_FLOOR_MILLIONTHS, 700_000);
    assert_eq!(DEFAULT_MAX_PRIOR_AGE_EPOCHS, 10);
}

// =========================================================================
// TransferEligibility method tests
// =========================================================================

#[test]
fn enrichment_eligibility_is_eligible_true_for_eligible() {
    let e = TransferEligibility::Eligible {
        confidence_millionths: 1_000_000,
        marginal: false,
    };
    assert!(e.is_eligible());
}

#[test]
fn enrichment_eligibility_is_eligible_false_for_denied() {
    let e = TransferEligibility::Denied {
        reason: TransferDenialReason::StalePrior,
    };
    assert!(!e.is_eligible());
}

#[test]
fn enrichment_eligibility_is_marginal_false_when_not_marginal() {
    let e = TransferEligibility::Eligible {
        confidence_millionths: 900_000,
        marginal: false,
    };
    assert!(!e.is_marginal());
}

#[test]
fn enrichment_eligibility_is_marginal_false_for_denied() {
    let e = TransferEligibility::Denied {
        reason: TransferDenialReason::DistantWorkloads,
    };
    assert!(!e.is_marginal());
}

#[test]
fn enrichment_eligibility_confidence_returns_some_for_eligible() {
    let e = TransferEligibility::Eligible {
        confidence_millionths: 123_456,
        marginal: true,
    };
    assert_eq!(e.confidence(), Some(123_456));
}

#[test]
fn enrichment_eligibility_confidence_returns_none_for_denied() {
    let e = TransferEligibility::Denied {
        reason: TransferDenialReason::KindNotPermitted,
    };
    assert_eq!(e.confidence(), None);
}

// =========================================================================
// TransferStatus method tests
// =========================================================================

#[test]
fn enrichment_status_is_active_includes_probationary() {
    assert!(TransferStatus::Active.is_active());
    assert!(TransferStatus::Probationary.is_active());
    assert!(!TransferStatus::RevokedDrift.is_active());
    assert!(!TransferStatus::RevokedStale.is_active());
    assert!(!TransferStatus::RevokedManual.is_active());
    assert!(!TransferStatus::Completed.is_active());
}

#[test]
fn enrichment_status_is_revoked_all_revoked_variants() {
    assert!(TransferStatus::RevokedDrift.is_revoked());
    assert!(TransferStatus::RevokedStale.is_revoked());
    assert!(TransferStatus::RevokedManual.is_revoked());
    assert!(!TransferStatus::Active.is_revoked());
    assert!(!TransferStatus::Probationary.is_revoked());
    assert!(!TransferStatus::Completed.is_revoked());
}

// =========================================================================
// PriorEntry method tests
// =========================================================================

#[test]
fn enrichment_prior_is_fresh_exact_boundary() {
    let prior = make_prior("p-boundary", TransferKind::CacheHint, 10, 900_000, 5);
    // Epoch 20, max_age 10 => gap = 10 <= 10 => fresh
    assert!(prior.is_fresh(epoch(20), 10));
    // Epoch 21, max_age 10 => gap = 11 > 10 => stale
    assert!(!prior.is_fresh(epoch(21), 10));
}

#[test]
fn enrichment_prior_is_fresh_zero_age() {
    let prior = make_prior("p-zero", TransferKind::RewritePack, 5, 900_000, 1);
    // max_age=0 means only same epoch is allowed
    assert!(prior.is_fresh(epoch(5), 0));
    assert!(!prior.is_fresh(epoch(6), 0));
}

#[test]
fn enrichment_prior_is_fresh_saturating_sub_no_underflow() {
    let prior = make_prior("p-sat", TransferKind::RewritePack, 100, 900_000, 1);
    // Current epoch < source epoch => saturating_sub gives 0, which is <= any max_age
    assert!(prior.is_fresh(epoch(50), 10));
}

#[test]
fn enrichment_prior_meets_confidence_exact_floor() {
    let prior = make_prior("p-exact", TransferKind::ShapePrior, 5, 700_000, 1);
    assert!(prior.meets_confidence(700_000));
    assert!(!prior.meets_confidence(700_001));
}

#[test]
fn enrichment_prior_meets_confidence_zero_floor() {
    let prior = make_prior("p-zero-conf", TransferKind::RewritePack, 5, 0, 1);
    assert!(prior.meets_confidence(0));
    assert!(!prior.meets_confidence(1));
}

// =========================================================================
// DriftObservation tests
// =========================================================================

#[test]
fn enrichment_drift_observation_computes_abs_divergence() {
    let obs = DriftObservation::new("t1", "metric_a", 500_000, 700_000, epoch(5), 1);
    assert_eq!(obs.divergence_millionths, 200_000);
}

#[test]
fn enrichment_drift_observation_negative_direction() {
    let obs = DriftObservation::new("t1", "metric_b", 700_000, 500_000, epoch(5), 2);
    assert_eq!(obs.divergence_millionths, 200_000);
}

#[test]
fn enrichment_drift_observation_zero_divergence() {
    let obs = DriftObservation::new("t1", "metric_c", 500_000, 500_000, epoch(5), 3);
    assert_eq!(obs.divergence_millionths, 0);
    assert!(!obs.exceeds_budget(0));
}

#[test]
fn enrichment_drift_observation_exceeds_budget_boundary() {
    let obs = DriftObservation::new("t1", "metric_d", 0, 100_000, epoch(5), 4);
    assert_eq!(obs.divergence_millionths, 100_000);
    // Budget = 100_000, divergence = 100_000 => NOT exceeded (> not >=)
    assert!(!obs.exceeds_budget(100_000));
    assert!(obs.exceeds_budget(99_999));
}

#[test]
fn enrichment_drift_observation_stores_fields() {
    let obs = DriftObservation::new("transfer-42", "throughput", 100, 200, epoch(99), 55);
    assert_eq!(obs.transfer_id, "transfer-42");
    assert_eq!(obs.metric_name, "throughput");
    assert_eq!(obs.expected_millionths, 100);
    assert_eq!(obs.observed_millionths, 200);
    assert_eq!(obs.observation_epoch, epoch(99));
    assert_eq!(obs.tick, 55);
}

// =========================================================================
// TransferPolicy tests
// =========================================================================

#[test]
fn enrichment_default_policy_all_kinds_permitted() {
    let policy = TransferPolicy::default();
    assert!(policy.permitted_kinds.contains(&TransferKind::RewritePack));
    assert!(policy.permitted_kinds.contains(&TransferKind::TieringPrior));
    assert!(policy.permitted_kinds.contains(&TransferKind::CacheHint));
    assert!(policy.permitted_kinds.contains(&TransferKind::ShapePrior));
    assert!(policy.permitted_kinds.contains(&TransferKind::GcTuningPrior));
    assert!(policy.permitted_kinds.contains(&TransferKind::SchedulerPrior));
    assert_eq!(policy.permitted_kinds.len(), 6);
}

#[test]
fn enrichment_default_policy_field_values() {
    let policy = TransferPolicy::default();
    assert_eq!(policy.schema_version, TRANSFER_PRIOR_SCHEMA_VERSION);
    assert_eq!(policy.max_prior_age_epochs, DEFAULT_MAX_PRIOR_AGE_EPOCHS);
    assert_eq!(policy.confidence_floor_millionths, DEFAULT_CONFIDENCE_FLOOR_MILLIONTHS);
    assert_eq!(policy.drift_budget_millionths, DEFAULT_DRIFT_BUDGET_MILLIONTHS);
    assert_eq!(policy.max_transferred_rules, MAX_TRANSFERRED_RULES);
    assert!(policy.allow_marginal_transfer);
    assert_eq!(policy.marginal_discount_millionths, 200_000);
    assert!(policy.require_drift_monitoring);
}

#[test]
fn enrichment_policy_content_hash_deterministic() {
    let p1 = TransferPolicy::default();
    let p2 = TransferPolicy::default();
    assert_eq!(p1.content_hash(), p2.content_hash());
    // Call again to confirm pure function
    assert_eq!(p1.content_hash(), p1.content_hash());
}

#[test]
fn enrichment_policy_content_hash_changes_with_different_fields() {
    let base = TransferPolicy::default();
    let changed_age = TransferPolicy {
        max_prior_age_epochs: 999,
        ..TransferPolicy::default()
    };
    let changed_budget = TransferPolicy {
        drift_budget_millionths: 999_999,
        ..TransferPolicy::default()
    };
    let changed_marginal = TransferPolicy {
        allow_marginal_transfer: false,
        ..TransferPolicy::default()
    };
    let changed_monitoring = TransferPolicy {
        require_drift_monitoring: false,
        ..TransferPolicy::default()
    };
    assert_ne!(base.content_hash(), changed_age.content_hash());
    assert_ne!(base.content_hash(), changed_budget.content_hash());
    assert_ne!(base.content_hash(), changed_marginal.content_hash());
    assert_ne!(base.content_hash(), changed_monitoring.content_hash());
}

#[test]
fn enrichment_policy_content_hash_sensitive_to_permitted_kinds() {
    let full = TransferPolicy::default();
    let mut reduced_kinds = BTreeSet::new();
    reduced_kinds.insert(TransferKind::RewritePack);
    let reduced = TransferPolicy {
        permitted_kinds: reduced_kinds,
        ..TransferPolicy::default()
    };
    assert_ne!(full.content_hash(), reduced.content_hash());
}

// =========================================================================
// TransferRecord hash tests
// =========================================================================

#[test]
fn enrichment_transfer_record_compute_hash_deterministic() {
    let record = TransferRecord {
        transfer_id: "det-t1".to_string(),
        prior_id: "det-p1".to_string(),
        source_embedding_id: "src-det".to_string(),
        target_embedding_id: "tgt-det".to_string(),
        certificate_id: "cert-det".to_string(),
        kind: TransferKind::TieringPrior,
        status: TransferStatus::Probationary,
        eligibility: TransferEligibility::Eligible {
            confidence_millionths: 800_000,
            marginal: true,
        },
        transfer_epoch: epoch(10),
        rules_transferred: 7,
        accumulated_drift_millionths: 5_000,
        drift_observations: 3,
        content_hash: hash("det-t1"),
    };
    let h1 = record.compute_hash();
    let h2 = record.compute_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_transfer_record_compute_hash_varies_with_status() {
    let mut r1 = TransferRecord {
        transfer_id: "status-test".to_string(),
        prior_id: "p1".to_string(),
        source_embedding_id: "src".to_string(),
        target_embedding_id: "tgt".to_string(),
        certificate_id: "cert".to_string(),
        kind: TransferKind::CacheHint,
        status: TransferStatus::Active,
        eligibility: TransferEligibility::Eligible {
            confidence_millionths: 900_000,
            marginal: false,
        },
        transfer_epoch: epoch(5),
        rules_transferred: 10,
        accumulated_drift_millionths: 0,
        drift_observations: 0,
        content_hash: hash("status-test"),
    };
    let h_active = r1.compute_hash();
    r1.status = TransferStatus::RevokedDrift;
    let h_revoked = r1.compute_hash();
    assert_ne!(h_active, h_revoked);
}

// =========================================================================
// RevocationReceipt sign/verify tests
// =========================================================================

#[test]
fn enrichment_revocation_receipt_sign_and_verify() {
    let key = b"my-secret-key";
    let receipt = RevocationReceipt {
        transfer_id: "t-sign-test".to_string(),
        reason: TransferStatus::RevokedDrift,
        drift_verdict: Some(DriftVerdict::BudgetExceeded {
            accumulated_millionths: 150_000,
            budget_millionths: 100_000,
            trigger_metric: "cpu_usage".to_string(),
        }),
        revocation_epoch: epoch(15),
        tick: 100,
        content_hash: hash("t-sign-test"),
        signature: hash("unsigned"),
    };
    let signed = receipt.sign(key);
    assert!(signed.verify_signature(key));
    assert!(!signed.verify_signature(b"wrong-key"));
    assert!(!signed.verify_signature(b""));
}

#[test]
fn enrichment_revocation_receipt_sign_is_deterministic() {
    let key = b"det-key";
    let make_receipt = || RevocationReceipt {
        transfer_id: "t-det-sign".to_string(),
        reason: TransferStatus::RevokedManual,
        drift_verdict: None,
        revocation_epoch: epoch(20),
        tick: 200,
        content_hash: hash("t-det-sign"),
        signature: hash("unsigned"),
    };
    let sig1 = make_receipt().sign(key).signature;
    let sig2 = make_receipt().sign(key).signature;
    assert_eq!(sig1, sig2);
}

#[test]
fn enrichment_revocation_receipt_different_keys_different_signatures() {
    let receipt = RevocationReceipt {
        transfer_id: "t-diff".to_string(),
        reason: TransferStatus::RevokedStale,
        drift_verdict: None,
        revocation_epoch: epoch(25),
        tick: 300,
        content_hash: hash("t-diff"),
        signature: hash("unsigned"),
    };
    let sig_a = receipt.clone().sign(b"key-a").signature;
    let sig_b = receipt.sign(b"key-b").signature;
    assert_ne!(sig_a, sig_b);
}

// =========================================================================
// TransferEngine construction and basic accessors
// =========================================================================

#[test]
fn enrichment_engine_new_with_defaults() {
    let engine = default_engine(10);
    assert_eq!(engine.prior_count(), 0);
    assert_eq!(engine.active_transfer_count(), 0);
    assert_eq!(engine.revoked_transfer_count(), 0);
    assert_eq!(engine.policy().schema_version, TRANSFER_PRIOR_SCHEMA_VERSION);
}

#[test]
fn enrichment_engine_advance_epoch() {
    let mut engine = default_engine(5);
    engine.advance_epoch(epoch(20));
    // After advancing, a prior at epoch 5 with max_age 10 should be stale at epoch 20
    let prior = make_prior("p1", TransferKind::RewritePack, 5, 900_000, 10);
    engine.register_prior(prior).unwrap();
    let result = engine
        .check_eligibility("p1", "tgt1", true, false, false)
        .unwrap();
    assert!(matches!(
        result,
        TransferEligibility::Denied {
            reason: TransferDenialReason::StalePrior
        }
    ));
}

#[test]
fn enrichment_engine_set_policy() {
    let mut engine = default_engine(5);
    let new_policy = TransferPolicy {
        max_prior_age_epochs: 999,
        ..TransferPolicy::default()
    };
    engine.set_policy(new_policy.clone());
    assert_eq!(engine.policy().max_prior_age_epochs, 999);
}

// =========================================================================
// TransferEngine registration tests
// =========================================================================

#[test]
fn enrichment_engine_register_and_get_prior() {
    let mut engine = default_engine(5);
    let prior = make_prior("p-get", TransferKind::GcTuningPrior, 3, 800_000, 5);
    engine.register_prior(prior.clone()).unwrap();
    let retrieved = engine.get_prior("p-get").unwrap();
    assert_eq!(retrieved.prior_id, "p-get");
    assert_eq!(retrieved.kind, TransferKind::GcTuningPrior);
    assert_eq!(retrieved.rule_count, 5);
}

#[test]
fn enrichment_engine_get_prior_nonexistent() {
    let engine = default_engine(5);
    assert!(engine.get_prior("nonexistent").is_none());
}

#[test]
fn enrichment_engine_register_duplicate_prior_error() {
    let mut engine = default_engine(5);
    let prior = make_prior("dup", TransferKind::RewritePack, 3, 900_000, 10);
    engine.register_prior(prior.clone()).unwrap();
    let err = engine.register_prior(prior).unwrap_err();
    assert!(matches!(err, TransferError::DuplicatePrior { prior_id } if prior_id == "dup"));
}

// =========================================================================
// TransferEngine eligibility checks
// =========================================================================

#[test]
fn enrichment_eligibility_near_certificate_full_confidence() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 950_000, 10))
        .unwrap();
    let result = engine
        .check_eligibility("p1", "tgt1", true, false, false)
        .unwrap();
    assert!(result.is_eligible());
    assert!(!result.is_marginal());
    assert_eq!(result.confidence(), Some(950_000));
}

#[test]
fn enrichment_eligibility_marginal_certificate_discounts_confidence() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::CacheHint, 3, 900_000, 5))
        .unwrap();
    let result = engine
        .check_eligibility("p1", "tgt1", false, true, false)
        .unwrap();
    assert!(result.is_eligible());
    assert!(result.is_marginal());
    // 900_000 - 200_000 (marginal discount) = 700_000
    assert_eq!(result.confidence(), Some(700_000));
}

#[test]
fn enrichment_eligibility_marginal_below_floor_after_discount() {
    let mut engine = default_engine(5);
    // Confidence 800_000, discount 200_000 => 600_000 < 700_000 floor
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 800_000, 5))
        .unwrap();
    let result = engine
        .check_eligibility("p1", "tgt1", false, true, false)
        .unwrap();
    assert!(matches!(
        result,
        TransferEligibility::Denied {
            reason: TransferDenialReason::InsufficientConfidence
        }
    ));
}

#[test]
fn enrichment_eligibility_drift_budget_exhausted() {
    let policy = TransferPolicy {
        drift_budget_millionths: 50_000,
        require_drift_monitoring: false,
        ..TransferPolicy::default()
    };
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 5))
        .unwrap();
    engine
        .register_prior(make_prior("p2", TransferKind::CacheHint, 3, 900_000, 5))
        .unwrap();

    // Execute first transfer
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    // Record large drift to exhaust budget
    let obs = DriftObservation::new("t1", "exec", 0, 200_000, epoch(5), 1);
    let _ = engine.record_drift(obs);

    // Now the drift budget for tgt1 should be exhausted (or close to)
    // After auto-revocation, try to check eligibility for another transfer
    let result = engine
        .check_eligibility("p2", "tgt1", true, false, false)
        .unwrap();
    // Drift budget used >= budget (200_000 >= 50_000)
    assert!(matches!(
        result,
        TransferEligibility::Denied {
            reason: TransferDenialReason::DriftBudgetExhausted
        }
    ));
}

// =========================================================================
// TransferEngine execute tests
// =========================================================================

#[test]
fn enrichment_execute_transfer_probationary_with_monitoring() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    let record = engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    // Default policy has require_drift_monitoring = true
    assert_eq!(record.status, TransferStatus::Probationary);
}

#[test]
fn enrichment_execute_transfer_active_without_monitoring() {
    let policy = TransferPolicy {
        require_drift_monitoring: false,
        ..TransferPolicy::default()
    };
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    let record = engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    assert_eq!(record.status, TransferStatus::Active);
}

#[test]
fn enrichment_execute_transfer_marginal_always_probationary() {
    let policy = TransferPolicy {
        require_drift_monitoring: false,
        ..TransferPolicy::default()
    };
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    let record = engine
        .execute_transfer(&marginal_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    // Marginal transfers are always probationary
    assert_eq!(record.status, TransferStatus::Probationary);
}

#[test]
fn enrichment_execute_transfer_duplicate_error() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    let err = engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap_err();
    assert!(matches!(err, TransferError::DuplicateTransfer { .. }));
}

#[test]
fn enrichment_execute_transfer_denied_returns_policy_violation() {
    let mut engine = default_engine(100);
    // Prior at epoch 3 is stale at epoch 100
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    let err = engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap_err();
    assert!(matches!(
        err,
        TransferError::PolicyViolation {
            reason: TransferDenialReason::StalePrior
        }
    ));
}

#[test]
fn enrichment_execute_transfer_records_epoch_and_rules() {
    let mut engine = default_engine(7);
    engine
        .register_prior(make_prior("p1", TransferKind::ShapePrior, 5, 900_000, 3))
        .unwrap();
    let record = engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    assert_eq!(record.transfer_epoch, epoch(7));
    assert_eq!(record.rules_transferred, 3);
    assert_eq!(record.accumulated_drift_millionths, 0);
    assert_eq!(record.drift_observations, 0);
}

// =========================================================================
// TransferEngine drift monitoring
// =========================================================================

#[test]
fn enrichment_drift_within_budget_returns_remaining() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();

    let obs = DriftObservation::new("t1", "latency", 500_000, 510_000, epoch(5), 1);
    let verdict = engine.record_drift(obs).unwrap();
    if let DriftVerdict::WithinBudget {
        accumulated_millionths,
        remaining_millionths,
    } = verdict
    {
        assert!(accumulated_millionths > 0);
        assert!(remaining_millionths > 0);
        assert_eq!(
            accumulated_millionths + remaining_millionths,
            DEFAULT_DRIFT_BUDGET_MILLIONTHS
        );
    } else {
        panic!("Expected WithinBudget verdict");
    }
}

#[test]
fn enrichment_drift_exceeds_budget_auto_revokes() {
    let policy = TransferPolicy {
        drift_budget_millionths: 10_000,
        require_drift_monitoring: false,
        ..TransferPolicy::default()
    };
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();

    let obs = DriftObservation::new("t1", "exec", 0, 500_000, epoch(5), 1);
    let verdict = engine.record_drift(obs).unwrap();
    assert!(matches!(verdict, DriftVerdict::BudgetExceeded { .. }));

    let transfer = engine.get_transfer("t1").unwrap();
    assert_eq!(transfer.status, TransferStatus::RevokedDrift);
    assert!(engine.get_revocation("t1").is_some());
}

#[test]
fn enrichment_drift_on_non_active_transfer_errors() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    engine.complete_transfer("t1").unwrap();

    let obs = DriftObservation::new("t1", "latency", 100, 200, epoch(5), 1);
    let err = engine.record_drift(obs).unwrap_err();
    assert!(matches!(err, TransferError::TransferNotActive { .. }));
}

#[test]
fn enrichment_drift_on_nonexistent_transfer_errors() {
    let mut engine = default_engine(5);
    let obs = DriftObservation::new("no-such-transfer", "latency", 100, 200, epoch(5), 1);
    let err = engine.record_drift(obs).unwrap_err();
    assert!(matches!(err, TransferError::TransferNotFound { .. }));
}

// =========================================================================
// TransferEngine promote
// =========================================================================

#[test]
fn enrichment_promote_probationary_to_active() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
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
fn enrichment_promote_already_active_fails() {
    let policy = TransferPolicy {
        require_drift_monitoring: false,
        ..TransferPolicy::default()
    };
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    let err = engine.promote_transfer("t1").unwrap_err();
    assert!(matches!(err, TransferError::TransferNotActive { .. }));
}

#[test]
fn enrichment_promote_nonexistent_fails() {
    let mut engine = default_engine(5);
    let err = engine.promote_transfer("no-such").unwrap_err();
    assert!(matches!(err, TransferError::TransferNotFound { .. }));
}

// =========================================================================
// TransferEngine revoke
// =========================================================================

#[test]
fn enrichment_revoke_active_transfer() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();

    let receipt = engine.revoke_transfer("t1").unwrap();
    assert_eq!(receipt.reason, TransferStatus::RevokedManual);
    assert!(receipt.drift_verdict.is_none());
    assert_eq!(engine.get_transfer("t1").unwrap().status, TransferStatus::RevokedManual);
    assert_eq!(engine.revoked_transfer_count(), 1);
    assert_eq!(engine.active_transfer_count(), 0);
}

#[test]
fn enrichment_revoke_already_revoked_fails() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    engine.revoke_transfer("t1").unwrap();
    let err = engine.revoke_transfer("t1").unwrap_err();
    assert!(matches!(err, TransferError::TransferNotActive { .. }));
}

#[test]
fn enrichment_revoke_completed_fails() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    engine.complete_transfer("t1").unwrap();
    let err = engine.revoke_transfer("t1").unwrap_err();
    assert!(matches!(err, TransferError::TransferNotActive { .. }));
}

// =========================================================================
// TransferEngine complete
// =========================================================================

#[test]
fn enrichment_complete_active_transfer() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    engine.complete_transfer("t1").unwrap();
    assert_eq!(
        engine.get_transfer("t1").unwrap().status,
        TransferStatus::Completed
    );
    assert_eq!(engine.active_transfer_count(), 0);
}

#[test]
fn enrichment_complete_revoked_fails() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    engine.revoke_transfer("t1").unwrap();
    let err = engine.complete_transfer("t1").unwrap_err();
    assert!(matches!(err, TransferError::TransferNotActive { .. }));
}

#[test]
fn enrichment_complete_nonexistent_fails() {
    let mut engine = default_engine(5);
    let err = engine.complete_transfer("no-such").unwrap_err();
    assert!(matches!(err, TransferError::TransferNotFound { .. }));
}

// =========================================================================
// TransferEngine expire stale priors
// =========================================================================

#[test]
fn enrichment_expire_stale_priors_marks_revoked_stale() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();

    engine.advance_epoch(epoch(100));
    let expired = engine.expire_stale_priors();
    assert_eq!(expired, vec!["t1".to_string()]);
    assert_eq!(
        engine.get_transfer("t1").unwrap().status,
        TransferStatus::RevokedStale
    );
}

#[test]
fn enrichment_expire_stale_priors_does_not_touch_already_revoked() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    engine.revoke_transfer("t1").unwrap();

    engine.advance_epoch(epoch(100));
    let expired = engine.expire_stale_priors();
    assert!(expired.is_empty());
    // Status remains RevokedManual, not changed to RevokedStale
    assert_eq!(
        engine.get_transfer("t1").unwrap().status,
        TransferStatus::RevokedManual
    );
}

#[test]
fn enrichment_expire_stale_priors_none_when_fresh() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    // Still within max_prior_age_epochs (10)
    engine.advance_epoch(epoch(13));
    let expired = engine.expire_stale_priors();
    assert!(expired.is_empty());
}

// =========================================================================
// TransferEngine summary
// =========================================================================

#[test]
fn enrichment_summarize_target_comprehensive() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .register_prior(make_prior("p2", TransferKind::CacheHint, 3, 800_000, 5))
        .unwrap();
    engine
        .register_prior(make_prior("p3", TransferKind::TieringPrior, 3, 850_000, 3))
        .unwrap();

    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    engine
        .execute_transfer(&near_input("t2", "p2", "tgt1", "cert2"))
        .unwrap();
    engine
        .execute_transfer(&near_input("t3", "p3", "tgt1", "cert3"))
        .unwrap();

    // Promote one, complete another, leave third probationary
    engine.promote_transfer("t1").unwrap();
    engine.complete_transfer("t2").unwrap();

    let summary = engine.summarize_target("tgt1");
    assert_eq!(summary.target_embedding_id, "tgt1");
    assert_eq!(summary.active_count, 1);
    assert_eq!(summary.probationary_count, 1);
    assert_eq!(summary.completed_count, 1);
    assert_eq!(summary.revoked_count, 0);
    // Active rules = t1(10) + t3(3) = 13, t2 completed so not counted
    assert_eq!(summary.active_rules, 13);
    assert_eq!(summary.summary_epoch, epoch(5));
}

#[test]
fn enrichment_summarize_target_empty() {
    let engine = default_engine(5);
    let summary = engine.summarize_target("empty-target");
    assert_eq!(summary.active_count, 0);
    assert_eq!(summary.probationary_count, 0);
    assert_eq!(summary.revoked_count, 0);
    assert_eq!(summary.completed_count, 0);
    assert_eq!(summary.active_rules, 0);
    assert!(summary.kind_breakdown.is_empty());
    assert_eq!(summary.max_drift_millionths, 0);
}

#[test]
fn enrichment_summarize_target_only_counts_matching_target() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .register_prior(make_prior("p2", TransferKind::CacheHint, 3, 800_000, 5))
        .unwrap();

    engine
        .execute_transfer(&near_input("t1", "p1", "tgt-A", "cert1"))
        .unwrap();
    engine
        .execute_transfer(&near_input("t2", "p2", "tgt-B", "cert2"))
        .unwrap();

    let summary_a = engine.summarize_target("tgt-A");
    assert_eq!(summary_a.probationary_count, 1);
    assert_eq!(summary_a.active_rules, 10);

    let summary_b = engine.summarize_target("tgt-B");
    assert_eq!(summary_b.probationary_count, 1);
    assert_eq!(summary_b.active_rules, 5);
}

// =========================================================================
// TransferEngine active_transfers_for
// =========================================================================

#[test]
fn enrichment_active_transfers_for_filters_by_target() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .register_prior(make_prior("p2", TransferKind::CacheHint, 3, 800_000, 5))
        .unwrap();

    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    engine
        .execute_transfer(&near_input("t2", "p2", "tgt2", "cert2"))
        .unwrap();

    let active_tgt1 = engine.active_transfers_for("tgt1");
    assert_eq!(active_tgt1.len(), 1);
    assert_eq!(active_tgt1[0], "t1");

    let active_tgt2 = engine.active_transfers_for("tgt2");
    assert_eq!(active_tgt2.len(), 1);
}

#[test]
fn enrichment_active_transfers_for_excludes_revoked_and_completed() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .register_prior(make_prior("p2", TransferKind::CacheHint, 3, 800_000, 5))
        .unwrap();
    engine
        .register_prior(make_prior("p3", TransferKind::ShapePrior, 3, 850_000, 3))
        .unwrap();

    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    engine
        .execute_transfer(&near_input("t2", "p2", "tgt1", "cert2"))
        .unwrap();
    engine
        .execute_transfer(&near_input("t3", "p3", "tgt1", "cert3"))
        .unwrap();

    engine.revoke_transfer("t1").unwrap();
    engine.complete_transfer("t2").unwrap();

    let active = engine.active_transfers_for("tgt1");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0], "t3");
}

// =========================================================================
// TransferEngine evidence_inventory
// =========================================================================

#[test]
fn enrichment_evidence_inventory_counts() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .register_prior(make_prior("p2", TransferKind::CacheHint, 3, 800_000, 5))
        .unwrap();

    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    engine
        .execute_transfer(&near_input("t2", "p2", "tgt1", "cert2"))
        .unwrap();
    engine.revoke_transfer("t1").unwrap();

    let inv = engine.evidence_inventory();
    assert_eq!(inv.schema_version, TRANSFER_PRIOR_SCHEMA_VERSION);
    assert_eq!(inv.total_priors, 2);
    assert_eq!(inv.total_transfers, 2);
    assert_eq!(inv.total_revocations, 1);
    assert_eq!(inv.epoch, epoch(5));
    // by_kind should have entries for both kinds
    assert!(inv.by_kind.contains_key("rewrite_pack"));
    assert!(inv.by_kind.contains_key("cache_hint"));
    // by_status should have both probationary and revoked_manual
    assert!(inv.by_status.contains_key("probationary"));
    assert!(inv.by_status.contains_key("revoked_manual"));
}

#[test]
fn enrichment_evidence_inventory_empty_engine() {
    let engine = default_engine(5);
    let inv = engine.evidence_inventory();
    assert_eq!(inv.total_priors, 0);
    assert_eq!(inv.total_transfers, 0);
    assert_eq!(inv.total_revocations, 0);
    assert!(inv.by_kind.is_empty());
    assert!(inv.by_status.is_empty());
}

// =========================================================================
// Rule budget accounting
// =========================================================================

#[test]
fn enrichment_rule_budget_reclaimed_on_revoke() {
    let policy = TransferPolicy {
        max_transferred_rules: 15,
        ..TransferPolicy::default()
    };
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .register_prior(make_prior("p2", TransferKind::CacheHint, 3, 900_000, 10))
        .unwrap();

    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    // Second transfer would exceed limit (10 + 10 = 20 > 15)
    let err = engine
        .execute_transfer(&near_input("t2", "p2", "tgt1", "cert2"))
        .unwrap_err();
    assert!(matches!(
        err,
        TransferError::PolicyViolation {
            reason: TransferDenialReason::RuleLimitExceeded
        }
    ));

    // Revoke first, freeing 10 rules
    engine.revoke_transfer("t1").unwrap();

    // Now second should succeed (0 + 10 <= 15)
    let record = engine
        .execute_transfer(&near_input("t2", "p2", "tgt1", "cert2"))
        .unwrap();
    assert_eq!(record.rules_transferred, 10);
}

#[test]
fn enrichment_rule_budget_reclaimed_on_complete() {
    let policy = TransferPolicy {
        max_transferred_rules: 12,
        ..TransferPolicy::default()
    };
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 8))
        .unwrap();
    engine
        .register_prior(make_prior("p2", TransferKind::CacheHint, 3, 900_000, 8))
        .unwrap();

    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();
    // 8 + 8 = 16 > 12
    let err = engine
        .execute_transfer(&near_input("t2", "p2", "tgt1", "cert2"))
        .unwrap_err();
    assert!(matches!(err, TransferError::PolicyViolation { .. }));

    engine.complete_transfer("t1").unwrap();
    // Budget freed
    let record = engine
        .execute_transfer(&near_input("t2", "p2", "tgt1", "cert2"))
        .unwrap();
    assert_eq!(record.rules_transferred, 8);
}

#[test]
fn enrichment_rule_budget_reclaimed_on_stale_expiry() {
    let policy = TransferPolicy {
        max_transferred_rules: 12,
        ..TransferPolicy::default()
    };
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();

    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();

    // Advance past staleness for p1
    engine.advance_epoch(epoch(100));
    let expired = engine.expire_stale_priors();
    assert!(!expired.is_empty());

    // Register fresh p2 at current epoch so it is not stale
    engine
        .register_prior(make_prior("p2", TransferKind::CacheHint, 100, 900_000, 8))
        .unwrap();

    // Budget freed by expiry, second transfer should work
    let record = engine
        .execute_transfer(&near_input("t2", "p2", "tgt1", "cert2"))
        .unwrap();
    assert_eq!(record.rules_transferred, 8);
}

// =========================================================================
// Full lifecycle scenarios
// =========================================================================

#[test]
fn enrichment_full_lifecycle_register_execute_drift_promote_complete() {
    let mut engine = default_engine(5);
    let prior = make_prior("p-life", TransferKind::SchedulerPrior, 3, 950_000, 7);
    engine.register_prior(prior).unwrap();

    // Execute
    let record = engine
        .execute_transfer(&near_input("t-life", "p-life", "tgt-life", "cert-life"))
        .unwrap();
    assert_eq!(record.status, TransferStatus::Probationary);
    assert_eq!(engine.active_transfer_count(), 1);

    // Record small drift
    let obs = DriftObservation::new("t-life", "throughput", 1_000_000, 1_005_000, epoch(5), 1);
    let verdict = engine.record_drift(obs).unwrap();
    assert!(matches!(verdict, DriftVerdict::WithinBudget { .. }));

    // Promote
    engine.promote_transfer("t-life").unwrap();
    assert_eq!(
        engine.get_transfer("t-life").unwrap().status,
        TransferStatus::Active
    );

    // Complete
    engine.complete_transfer("t-life").unwrap();
    assert_eq!(
        engine.get_transfer("t-life").unwrap().status,
        TransferStatus::Completed
    );
    assert_eq!(engine.active_transfer_count(), 0);
}

#[test]
fn enrichment_full_lifecycle_register_execute_drift_revoke_auto() {
    let policy = TransferPolicy {
        drift_budget_millionths: 5_000,
        require_drift_monitoring: false,
        ..TransferPolicy::default()
    };
    let mut engine = TransferEngine::new(policy, epoch(5));
    engine
        .register_prior(make_prior("p-auto", TransferKind::GcTuningPrior, 3, 900_000, 4))
        .unwrap();
    engine
        .execute_transfer(&near_input("t-auto", "p-auto", "tgt-auto", "cert-auto"))
        .unwrap();

    // Large drift triggers auto-revocation
    let obs = DriftObservation::new("t-auto", "gc_pressure", 100_000, 500_000, epoch(5), 1);
    let verdict = engine.record_drift(obs).unwrap();
    assert!(matches!(verdict, DriftVerdict::BudgetExceeded { .. }));
    assert_eq!(
        engine.get_transfer("t-auto").unwrap().status,
        TransferStatus::RevokedDrift
    );
    assert!(engine.get_revocation("t-auto").is_some());
}

#[test]
fn enrichment_multiple_priors_multiple_targets() {
    let mut engine = default_engine(5);
    let kinds = [
        TransferKind::RewritePack,
        TransferKind::TieringPrior,
        TransferKind::CacheHint,
        TransferKind::ShapePrior,
    ];

    // Register 4 priors of different kinds
    for (i, kind) in kinds.iter().enumerate() {
        let id = format!("p-multi-{}", i);
        engine
            .register_prior(make_prior(&id, *kind, 3, 900_000, 5))
            .unwrap();
    }
    assert_eq!(engine.prior_count(), 4);

    // Execute transfers to two different targets
    for (i, _kind) in kinds.iter().enumerate() {
        let transfer_id = format!("t-multi-{}", i);
        let prior_id = format!("p-multi-{}", i);
        let target = if i < 2 { "tgt-alpha" } else { "tgt-beta" };
        let cert = format!("cert-{}", i);
        engine
            .execute_transfer(&near_input(&transfer_id, &prior_id, target, &cert))
            .unwrap();
    }

    let active_alpha = engine.active_transfers_for("tgt-alpha");
    assert_eq!(active_alpha.len(), 2);
    let active_beta = engine.active_transfers_for("tgt-beta");
    assert_eq!(active_beta.len(), 2);

    let summary_alpha = engine.summarize_target("tgt-alpha");
    assert_eq!(summary_alpha.probationary_count, 2);
    assert_eq!(summary_alpha.active_rules, 10);

    let inv = engine.evidence_inventory();
    assert_eq!(inv.total_priors, 4);
    assert_eq!(inv.total_transfers, 4);
}

// =========================================================================
// Edge cases
// =========================================================================

#[test]
fn enrichment_zero_rule_prior() {
    let mut engine = default_engine(5);
    let prior = make_prior("p-zero-rules", TransferKind::RewritePack, 3, 900_000, 0);
    engine.register_prior(prior).unwrap();
    let record = engine
        .execute_transfer(&near_input("t-zero", "p-zero-rules", "tgt1", "cert1"))
        .unwrap();
    assert_eq!(record.rules_transferred, 0);
}

#[test]
fn enrichment_max_confidence_millionths() {
    let mut engine = default_engine(5);
    let prior = make_prior("p-max", TransferKind::RewritePack, 3, 1_000_000, 1);
    engine.register_prior(prior).unwrap();
    let result = engine
        .check_eligibility("p-max", "tgt1", true, false, false)
        .unwrap();
    assert_eq!(result.confidence(), Some(1_000_000));
}

#[test]
fn enrichment_transfer_error_is_std_error() {
    let err = TransferError::PriorNotFound {
        prior_id: "p1".to_string(),
    };
    // Verify it implements std::error::Error
    let _: &dyn std::error::Error = &err;
}

#[test]
fn enrichment_serde_roundtrip_transfer_engine() {
    let mut engine = default_engine(5);
    engine
        .register_prior(make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10))
        .unwrap();
    engine
        .execute_transfer(&near_input("t1", "p1", "tgt1", "cert1"))
        .unwrap();

    let json = serde_json::to_string(&engine).unwrap();
    let back: TransferEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(back.prior_count(), 1);
    assert_eq!(back.active_transfer_count(), 1);
    assert_eq!(back.policy().schema_version, TRANSFER_PRIOR_SCHEMA_VERSION);
}

#[test]
fn enrichment_get_transfer_returns_none_for_nonexistent() {
    let engine = default_engine(5);
    assert!(engine.get_transfer("nonexistent").is_none());
}

#[test]
fn enrichment_get_revocation_returns_none_for_nonexistent() {
    let engine = default_engine(5);
    assert!(engine.get_revocation("nonexistent").is_none());
}
