//! Enrichment integration tests for `synthesis_kernel_promotion` module.
//!
//! Tests advanced gate evaluation, batch processing, ledger lifecycle,
//! demotion scenarios, report aggregation, and edge cases.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::synthesis_kernel_promotion::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch { SecurityEpoch::from_raw(1000) }
fn epoch2() -> SecurityEpoch { SecurityEpoch::from_raw(2000) }
fn baseline_target() -> BTreeSet<PromotionTarget> { BTreeSet::from([PromotionTarget::BaselineHotPath]) }
fn aot_target() -> BTreeSet<PromotionTarget> { BTreeSet::from([PromotionTarget::AotArtifact]) }
fn all_targets() -> BTreeSet<PromotionTarget> { PromotionTarget::ALL.iter().copied().collect() }

fn good_evidence() -> PromotionEvidence {
    PromotionEvidence::verified(960_000, 150_000, 950_000, baseline_target())
}

fn weak_evidence() -> PromotionEvidence {
    PromotionEvidence::partial(PartialEvidenceInput {
        proof_verified: true,
        coverage: 960_000,
        speedup: 150_000,
        counterexamples: 0,
        max_severity: 0,
        regression_confidence: 500_000,
        aot_compiled: false,
        targets: baseline_target(),
    })
}

fn bad_evidence() -> PromotionEvidence {
    PromotionEvidence::partial(PartialEvidenceInput {
        proof_verified: false,
        coverage: 100_000,
        speedup: 10_000,
        counterexamples: 5,
        max_severity: 500_000,
        regression_confidence: 100_000,
        aot_compiled: false,
        targets: BTreeSet::new(),
    })
}

// ---------------------------------------------------------------------------
// 1. Gate: all checks pass
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_good_evidence_promoted() {
    let gate = PromotionGate::with_defaults();
    let decision = gate.evaluate("k1", &good_evidence());
    assert!(decision.is_promoted());
    assert_eq!(decision.kernel_id(), "k1");
}

// ---------------------------------------------------------------------------
// 2. Gate: proof not verified
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_proof_not_verified_rejected() {
    let gate = PromotionGate::with_defaults();
    let mut ev = good_evidence();
    ev.proof_verified = false;
    let decision = gate.evaluate("k2", &ev);
    assert!(decision.is_rejected());
    if let PromotionDecision::Rejected { reasons, .. } = &decision {
        assert!(reasons.iter().any(|r| r.tag() == "proof_not_verified"));
    }
}

// ---------------------------------------------------------------------------
// 3. Gate: insufficient coverage
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_insufficient_coverage_rejected() {
    let gate = PromotionGate::with_defaults();
    let mut ev = good_evidence();
    ev.proof_coverage_millionths = 100_000;
    assert!(gate.evaluate("k3", &ev).is_rejected());
}

// ---------------------------------------------------------------------------
// 4. Gate: insufficient speedup
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_insufficient_speedup_rejected() {
    let gate = PromotionGate::with_defaults();
    let mut ev = good_evidence();
    ev.speedup_millionths = 10_000;
    assert!(gate.evaluate("k4", &ev).is_rejected());
}

// ---------------------------------------------------------------------------
// 5. Gate: active counterexamples
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_active_counterexamples_rejected() {
    let gate = PromotionGate::with_defaults();
    let mut ev = good_evidence();
    ev.active_counterexamples = 1;
    assert!(gate.evaluate("k5", &ev).is_rejected());
}

// ---------------------------------------------------------------------------
// 6. Gate: counterexample severity
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_counterexample_severity_rejected() {
    let gate = PromotionGate::with_defaults();
    let mut ev = good_evidence();
    ev.max_counterexample_severity_millionths = 100;
    assert!(gate.evaluate("k6", &ev).is_rejected());
}

// ---------------------------------------------------------------------------
// 7. Gate: soft rejection -> deferred
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_weak_evidence_deferred() {
    let gate = PromotionGate::with_defaults();
    let decision = gate.evaluate("k7", &weak_evidence());
    assert!(decision.is_deferred());
}

// ---------------------------------------------------------------------------
// 8. Gate: multiple hard rejections
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_multiple_hard_rejections() {
    let gate = PromotionGate::with_defaults();
    let decision = gate.evaluate("k8", &bad_evidence());
    assert!(decision.is_rejected());
    if let PromotionDecision::Rejected { reasons, .. } = &decision {
        assert!(reasons.len() >= 3);
    }
}

// ---------------------------------------------------------------------------
// 9. Gate: empty targets rejected
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_empty_targets_rejected() {
    let gate = PromotionGate::with_defaults();
    let ev = PromotionEvidence::verified(960_000, 150_000, 950_000, BTreeSet::new());
    assert!(gate.evaluate("k9", &ev).is_rejected());
}

// ---------------------------------------------------------------------------
// 10. Batch evaluation
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_batch_mixed_results() {
    let gate = PromotionGate::with_defaults();
    let candidates = vec![
        ("good".into(), good_evidence()),
        ("weak".into(), weak_evidence()),
        ("bad".into(), bad_evidence()),
    ];
    let decisions = gate.evaluate_batch(&candidates);
    assert_eq!(decisions.len(), 3);
    assert!(decisions[0].is_promoted());
    assert!(decisions[1].is_deferred());
    assert!(decisions[2].is_rejected());
}

// ---------------------------------------------------------------------------
// 11. Permissive config
// ---------------------------------------------------------------------------

#[test]
fn enrich_permissive_gate_promotes_weak() {
    let gate = PromotionGate::with_config(PromotionGateConfig::permissive());
    let ev = PromotionEvidence::partial(PartialEvidenceInput {
        proof_verified: true, coverage: 10_000, speedup: 0,
        counterexamples: 100, max_severity: 999_999,
        regression_confidence: 0, aot_compiled: false, targets: baseline_target(),
    });
    assert!(gate.evaluate("permissive", &ev).is_promoted());
}

// ---------------------------------------------------------------------------
// 12. PromotionDecision Display
// ---------------------------------------------------------------------------

#[test]
fn enrich_promotion_decision_display_all_variants() {
    let promoted = PromotionDecision::Promoted {
        kernel_id: "k1".into(), targets: baseline_target(),
        content_hash: ContentHash::compute(b"test"),
    };
    assert!(promoted.to_string().contains("PROMOTED"));

    let rejected = PromotionDecision::Rejected {
        kernel_id: "k2".into(), reasons: vec![RejectionReason::ProofNotVerified],
    };
    assert!(rejected.to_string().contains("REJECTED"));

    let deferred = PromotionDecision::Deferred {
        kernel_id: "k3".into(), pending_reasons: vec![RejectionReason::NoAotReceipt],
    };
    assert!(deferred.to_string().contains("DEFERRED"));
}

// ---------------------------------------------------------------------------
// 13. PromotedKernel lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enrich_promoted_kernel_new_is_active() {
    let pk = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    assert!(pk.is_active());
    assert_eq!(pk.status, PromotionStatus::Active);
}

#[test]
fn enrich_promoted_kernel_demote() {
    let mut pk = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let receipt = DemotionReceipt::new("k1", DemotionCause::PerformanceRegression, epoch2(), baseline_target(), "reg");
    pk.demote(receipt);
    assert!(!pk.is_active());
    assert_eq!(pk.status, PromotionStatus::Demoted);
    assert!(pk.active_targets.is_empty());
}

#[test]
fn enrich_promoted_kernel_supersede() {
    let mut pk = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    pk.supersede("k2", epoch2());
    assert_eq!(pk.status, PromotionStatus::Superseded);
    assert!(pk.active_targets.is_empty());
}

// ---------------------------------------------------------------------------
// 14. PromotedKernel hash deterministic
// ---------------------------------------------------------------------------

#[test]
fn enrich_promoted_kernel_hash_deterministic() {
    let pk1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let pk2 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    assert_eq!(pk1.content_hash, pk2.content_hash);
}

#[test]
fn enrich_promoted_kernel_hash_varies_with_kernel_id() {
    let pk1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let pk2 = PromotedKernel::new("k2", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    assert_ne!(pk1.content_hash, pk2.content_hash);
}

// ---------------------------------------------------------------------------
// 15. Ledger operations
// ---------------------------------------------------------------------------

#[test]
fn enrich_ledger_record_and_count() {
    let mut ledger = PromotionLedger::new();
    ledger.record_promotion(PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000));
    ledger.record_promotion(PromotedKernel::new("k2", "orig2", aot_target(), epoch(), 200_000, 970_000));
    assert_eq!(ledger.active_count(), 2);
}

#[test]
fn enrich_ledger_demote_kernel() {
    let mut ledger = PromotionLedger::new();
    ledger.record_promotion(PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000));
    let receipt = DemotionReceipt::new("k1", DemotionCause::HardwareFailure, epoch2(), baseline_target(), "GPU fail");
    assert!(ledger.demote_kernel("k1", receipt));
    assert_eq!(ledger.active_count(), 0);
    assert_eq!(ledger.demoted_count(), 1);
}

#[test]
fn enrich_ledger_demote_nonexistent_returns_false() {
    let mut ledger = PromotionLedger::new();
    let receipt = DemotionReceipt::new("nope", DemotionCause::PolicyChange, epoch(), BTreeSet::new(), "test");
    assert!(!ledger.demote_kernel("nope", receipt));
}

#[test]
fn enrich_ledger_supersede_kernel() {
    let mut ledger = PromotionLedger::new();
    ledger.record_promotion(PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000));
    assert!(ledger.supersede_kernel("k1", "k2", epoch2()));
    assert_eq!(ledger.superseded_count(), 1);
}

// ---------------------------------------------------------------------------
// 16. Ledger get_kernel
// ---------------------------------------------------------------------------

#[test]
fn enrich_ledger_get_kernel_found() {
    let mut ledger = PromotionLedger::new();
    ledger.record_promotion(PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000));
    assert!(ledger.get_kernel("k1").is_some());
}

#[test]
fn enrich_ledger_get_kernel_not_found() {
    let ledger = PromotionLedger::new();
    assert!(ledger.get_kernel("nonexistent").is_none());
}

// ---------------------------------------------------------------------------
// 17. Ledger active_for_target
// ---------------------------------------------------------------------------

#[test]
fn enrich_ledger_active_for_target() {
    let mut ledger = PromotionLedger::new();
    ledger.record_promotion(PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000));
    ledger.record_promotion(PromotedKernel::new("k2", "orig2", aot_target(), epoch(), 200_000, 970_000));
    let baseline_kernels = ledger.active_for_target(PromotionTarget::BaselineHotPath);
    assert_eq!(baseline_kernels.len(), 1);
}

// ---------------------------------------------------------------------------
// 18. Ledger demotion_receipts
// ---------------------------------------------------------------------------

#[test]
fn enrich_ledger_demotion_receipts() {
    let mut ledger = PromotionLedger::new();
    ledger.record_promotion(PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000));
    let receipt = DemotionReceipt::new("k1", DemotionCause::CounterexampleFound, epoch2(), baseline_target(), "CE");
    ledger.demote_kernel("k1", receipt);
    assert_eq!(ledger.demotion_receipts().len(), 1);
}

// ---------------------------------------------------------------------------
// 19. PromotionReport
// ---------------------------------------------------------------------------

#[test]
fn enrich_report_from_decisions() {
    let gate = PromotionGate::with_defaults();
    let decisions = vec![
        gate.evaluate("k1", &good_evidence()),
        gate.evaluate("k2", &weak_evidence()),
        gate.evaluate("k3", &bad_evidence()),
    ];
    let report = PromotionReport::new(epoch(), decisions);
    assert_eq!(report.total_count(), 3);
    assert_eq!(report.promoted_count, 1);
    assert_eq!(report.deferred_count, 1);
    assert_eq!(report.rejected_count, 1);
}

#[test]
fn enrich_report_all_promoted() {
    let gate = PromotionGate::with_defaults();
    let decisions = vec![gate.evaluate("k1", &good_evidence()), gate.evaluate("k2", &good_evidence())];
    let report = PromotionReport::new(epoch(), decisions);
    assert!(report.all_promoted());
    assert_eq!(report.promotion_rate(), 1_000_000);
}

#[test]
fn enrich_report_empty() {
    let report = PromotionReport::new(epoch(), vec![]);
    assert_eq!(report.total_count(), 0);
    assert_eq!(report.promotion_rate(), 0);
    assert!(!report.all_promoted());
}

// ---------------------------------------------------------------------------
// 20. Report hash deterministic
// ---------------------------------------------------------------------------

#[test]
fn enrich_report_hash_deterministic() {
    let gate = PromotionGate::with_defaults();
    let d1 = vec![gate.evaluate("k1", &good_evidence())];
    let d2 = vec![gate.evaluate("k1", &good_evidence())];
    let r1 = PromotionReport::new(epoch(), d1);
    let r2 = PromotionReport::new(epoch(), d2);
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// 21. Report serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_report_serde_roundtrip() {
    let gate = PromotionGate::with_defaults();
    let decisions = vec![gate.evaluate("k1", &good_evidence())];
    let report = PromotionReport::new(epoch(), decisions);
    let json = serde_json::to_string(&report).unwrap();
    let back: PromotionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// 22. DemotionReceipt hash
// ---------------------------------------------------------------------------

#[test]
fn enrich_demotion_receipt_hash_deterministic() {
    let r1 = DemotionReceipt::new("k1", DemotionCause::PolicyChange, epoch(), baseline_target(), "policy");
    let r2 = DemotionReceipt::new("k1", DemotionCause::PolicyChange, epoch(), baseline_target(), "policy");
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrich_demotion_receipt_hash_varies_with_cause() {
    let r1 = DemotionReceipt::new("k1", DemotionCause::PolicyChange, epoch(), baseline_target(), "test");
    let r2 = DemotionReceipt::new("k1", DemotionCause::CompileFailure, epoch(), baseline_target(), "test");
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// 23. DemotionCause all
// ---------------------------------------------------------------------------

#[test]
fn enrich_demotion_cause_display_and_serde() {
    for cause in DemotionCause::ALL {
        assert_eq!(cause.to_string(), cause.as_str());
        let json = serde_json::to_string(cause).unwrap();
        let back: DemotionCause = serde_json::from_str(&json).unwrap();
        assert_eq!(*cause, back);
    }
}

// ---------------------------------------------------------------------------
// 24. PromotionStatus names unique
// ---------------------------------------------------------------------------

#[test]
fn enrich_promotion_status_all_names_unique() {
    let names: BTreeSet<&str> = PromotionStatus::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(names.len(), 4);
}

// ---------------------------------------------------------------------------
// 25. RejectionReason display and tags
// ---------------------------------------------------------------------------

#[test]
fn enrich_rejection_reason_display_all_non_empty() {
    let reasons = vec![
        RejectionReason::ProofNotVerified,
        RejectionReason::InsufficientProofCoverage { coverage_millionths: 100, threshold_millionths: 900 },
        RejectionReason::InsufficientSpeedup { speedup_millionths: 10, threshold_millionths: 100 },
        RejectionReason::ActiveCounterexamples { count: 3 },
        RejectionReason::CounterexampleSeverity { max_severity_millionths: 500, threshold_millionths: 0 },
        RejectionReason::RegressionGateFailure { confidence_millionths: 100, threshold_millionths: 900 },
        RejectionReason::NoAotReceipt,
        RejectionReason::TargetIneligible { target: PromotionTarget::AotArtifact },
    ];
    for r in &reasons {
        assert!(!r.to_string().is_empty());
        assert!(!r.tag().is_empty());
    }
}

// ---------------------------------------------------------------------------
// 26. RejectionReason serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_rejection_reason_all_serde_roundtrip() {
    let reasons = vec![
        RejectionReason::ProofNotVerified,
        RejectionReason::NoAotReceipt,
        RejectionReason::ActiveCounterexamples { count: 3 },
        RejectionReason::TargetIneligible { target: PromotionTarget::SupportSurface },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// 27. Constants
// ---------------------------------------------------------------------------

#[test]
fn enrich_constants_valid() {
    assert!(SCHEMA_VERSION.contains("synthesis-kernel-promotion"));
    assert_eq!(COMPONENT, "synthesis_kernel_promotion");
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
    assert!(MIN_PROMOTION_SPEEDUP > 0);
    assert!(MIN_PROOF_COVERAGE > 0);
    assert_eq!(MAX_ACTIVE_COUNTEREXAMPLES, 0);
}

// ---------------------------------------------------------------------------
// 28. PromotionTarget names unique
// ---------------------------------------------------------------------------

#[test]
fn enrich_promotion_target_all_names_unique() {
    let names: BTreeSet<&str> = PromotionTarget::ALL.iter().map(|t| t.as_str()).collect();
    assert_eq!(names.len(), 5);
}

// ---------------------------------------------------------------------------
// 29. Gate schema version
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_schema_version_matches_constant() {
    let gate = PromotionGate::with_defaults();
    assert_eq!(gate.schema_version, SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// 30. Gate config default matches default_config
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_config_default_matches_default_config() {
    let d1 = PromotionGateConfig::default();
    let d2 = PromotionGateConfig::default_config();
    assert_eq!(d1, d2);
}

// ---------------------------------------------------------------------------
// 31. Evidence verified fields
// ---------------------------------------------------------------------------

#[test]
fn enrich_evidence_verified_fields() {
    let ev = PromotionEvidence::verified(900_000, 200_000, 950_000, all_targets());
    assert!(ev.proof_verified);
    assert!(ev.aot_compiled);
    assert_eq!(ev.eligible_targets.len(), 5);
}

// ---------------------------------------------------------------------------
// 32. Evidence partial fields
// ---------------------------------------------------------------------------

#[test]
fn enrich_evidence_partial_fields() {
    let input = PartialEvidenceInput {
        proof_verified: false, coverage: 500_000, speedup: 50_000,
        counterexamples: 2, max_severity: 100_000,
        regression_confidence: 300_000, aot_compiled: false, targets: aot_target(),
    };
    let ev = PromotionEvidence::partial(input);
    assert!(!ev.proof_verified);
    assert_eq!(ev.active_counterexamples, 2);
}

// ---------------------------------------------------------------------------
// 33. Ledger default
// ---------------------------------------------------------------------------

#[test]
fn enrich_ledger_default_is_empty() {
    let ledger = PromotionLedger::default();
    assert_eq!(ledger.active_count(), 0);
    assert_eq!(ledger.entries.len(), 0);
    assert_eq!(ledger.schema_version, SCHEMA_VERSION);
}
