//! Integration tests for `synthesis_kernel_promotion` module.
//!
//! Validates public API, serde contracts, determinism, gate evaluation logic,
//! batch processing, promotion lifecycle, ledger operations, report aggregation,
//! and edge cases.

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

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::synthesis_kernel_promotion::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1000)
}

fn epoch2() -> SecurityEpoch {
    SecurityEpoch::from_raw(2000)
}

fn baseline_target() -> BTreeSet<PromotionTarget> {
    BTreeSet::from([PromotionTarget::BaselineHotPath])
}

fn aot_target() -> BTreeSet<PromotionTarget> {
    BTreeSet::from([PromotionTarget::AotArtifact])
}

fn router_target() -> BTreeSet<PromotionTarget> {
    BTreeSet::from([PromotionTarget::AdaptiveRouter])
}

fn all_targets() -> BTreeSet<PromotionTarget> {
    PromotionTarget::ALL.iter().copied().collect()
}

fn good_evidence() -> PromotionEvidence {
    PromotionEvidence::verified(960_000, 150_000, 950_000, baseline_target())
}

fn good_evidence_aot() -> PromotionEvidence {
    PromotionEvidence::verified(980_000, 200_000, 980_000, aot_target())
}

fn good_evidence_all_targets() -> PromotionEvidence {
    PromotionEvidence::verified(990_000, 250_000, 990_000, all_targets())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_prefix() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("synthesis-kernel-promotion"));
}

#[test]
fn component_name_matches() {
    assert_eq!(COMPONENT, "synthesis_kernel_promotion");
}

#[test]
fn bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn min_promotion_speedup_positive() {
    assert!(MIN_PROMOTION_SPEEDUP > 0);
    assert!(MIN_PROMOTION_SPEEDUP <= 1_000_000);
}

#[test]
fn min_proof_coverage_range() {
    assert!(MIN_PROOF_COVERAGE > 0);
    assert!(MIN_PROOF_COVERAGE <= 1_000_000);
}

#[test]
fn max_active_counterexamples_zero() {
    assert_eq!(MAX_ACTIVE_COUNTEREXAMPLES, 0);
}

#[test]
fn max_counterexample_severity_zero() {
    assert_eq!(MAX_COUNTEREXAMPLE_SEVERITY, 0);
}

#[test]
fn min_regression_confidence_positive() {
    assert!(MIN_REGRESSION_CONFIDENCE > 0);
    assert!(MIN_REGRESSION_CONFIDENCE <= 1_000_000);
}

// ---------------------------------------------------------------------------
// PromotionTarget
// ---------------------------------------------------------------------------

#[test]
fn target_all_count() {
    assert_eq!(PromotionTarget::ALL.len(), 5);
}

#[test]
fn target_names_unique() {
    let names: BTreeSet<&str> = PromotionTarget::ALL.iter().map(|t| t.as_str()).collect();
    assert_eq!(names.len(), PromotionTarget::ALL.len());
}

#[test]
fn target_display_matches_as_str() {
    for t in PromotionTarget::ALL {
        assert_eq!(t.to_string(), t.as_str());
    }
}

#[test]
fn target_baseline_hot_path_name() {
    assert_eq!(
        PromotionTarget::BaselineHotPath.as_str(),
        "baseline_hot_path"
    );
}

#[test]
fn target_aot_artifact_name() {
    assert_eq!(PromotionTarget::AotArtifact.as_str(), "aot_artifact");
}

#[test]
fn target_adaptive_router_name() {
    assert_eq!(PromotionTarget::AdaptiveRouter.as_str(), "adaptive_router");
}

#[test]
fn target_supremacy_evidence_name() {
    assert_eq!(
        PromotionTarget::SupremacyEvidence.as_str(),
        "supremacy_evidence"
    );
}

#[test]
fn target_support_surface_name() {
    assert_eq!(PromotionTarget::SupportSurface.as_str(), "support_surface");
}

#[test]
fn target_serde_roundtrip_all() {
    for t in PromotionTarget::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: PromotionTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

// ---------------------------------------------------------------------------
// PromotionStatus
// ---------------------------------------------------------------------------

#[test]
fn status_all_count() {
    assert_eq!(PromotionStatus::ALL.len(), 4);
}

#[test]
fn status_names_unique() {
    let names: BTreeSet<&str> = PromotionStatus::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(names.len(), PromotionStatus::ALL.len());
}

#[test]
fn status_display_matches_as_str() {
    for s in PromotionStatus::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn status_active_classification() {
    assert!(PromotionStatus::Active.is_active());
    assert!(!PromotionStatus::Pending.is_active());
    assert!(!PromotionStatus::Demoted.is_active());
    assert!(!PromotionStatus::Superseded.is_active());
}

#[test]
fn status_terminal_classification() {
    assert!(PromotionStatus::Demoted.is_terminal());
    assert!(PromotionStatus::Superseded.is_terminal());
    assert!(!PromotionStatus::Active.is_terminal());
    assert!(!PromotionStatus::Pending.is_terminal());
}

#[test]
fn status_serde_roundtrip_all() {
    for s in PromotionStatus::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: PromotionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// DemotionCause
// ---------------------------------------------------------------------------

#[test]
fn demotion_cause_all_count() {
    assert_eq!(DemotionCause::ALL.len(), 7);
}

#[test]
fn demotion_cause_names_unique() {
    let names: BTreeSet<&str> = DemotionCause::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(names.len(), DemotionCause::ALL.len());
}

#[test]
fn demotion_cause_display_matches_as_str() {
    for c in DemotionCause::ALL {
        assert_eq!(c.to_string(), c.as_str());
    }
}

#[test]
fn demotion_cause_serde_roundtrip_all() {
    for c in DemotionCause::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: DemotionCause = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ---------------------------------------------------------------------------
// RejectionReason
// ---------------------------------------------------------------------------

#[test]
fn rejection_tags_unique() {
    let reasons = vec![
        RejectionReason::ProofNotVerified,
        RejectionReason::InsufficientProofCoverage {
            coverage_millionths: 0,
            threshold_millionths: 0,
        },
        RejectionReason::InsufficientSpeedup {
            speedup_millionths: 0,
            threshold_millionths: 0,
        },
        RejectionReason::ActiveCounterexamples { count: 0 },
        RejectionReason::CounterexampleSeverity {
            max_severity_millionths: 0,
            threshold_millionths: 0,
        },
        RejectionReason::RegressionGateFailure {
            confidence_millionths: 0,
            threshold_millionths: 0,
        },
        RejectionReason::NoAotReceipt,
        RejectionReason::TargetIneligible {
            target: PromotionTarget::BaselineHotPath,
        },
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 8);
}

#[test]
fn rejection_display_proof_not_verified() {
    let r = RejectionReason::ProofNotVerified;
    let s = r.to_string();
    assert!(s.contains("proof"));
    assert!(!s.is_empty());
}

#[test]
fn rejection_display_insufficient_coverage_contains_values() {
    let r = RejectionReason::InsufficientProofCoverage {
        coverage_millionths: 800_000,
        threshold_millionths: 950_000,
    };
    let s = r.to_string();
    assert!(s.contains("800000"));
    assert!(s.contains("950000"));
}

#[test]
fn rejection_display_insufficient_speedup_contains_values() {
    let r = RejectionReason::InsufficientSpeedup {
        speedup_millionths: 50_000,
        threshold_millionths: 100_000,
    };
    let s = r.to_string();
    assert!(s.contains("50000"));
    assert!(s.contains("100000"));
}

#[test]
fn rejection_display_active_counterexamples() {
    let r = RejectionReason::ActiveCounterexamples { count: 3 };
    let s = r.to_string();
    assert!(s.contains("3"));
}

#[test]
fn rejection_display_counterexample_severity() {
    let r = RejectionReason::CounterexampleSeverity {
        max_severity_millionths: 200_000,
        threshold_millionths: 0,
    };
    let s = r.to_string();
    assert!(s.contains("200000"));
}

#[test]
fn rejection_display_regression_gate_failure() {
    let r = RejectionReason::RegressionGateFailure {
        confidence_millionths: 600_000,
        threshold_millionths: 900_000,
    };
    let s = r.to_string();
    assert!(s.contains("600000"));
    assert!(s.contains("900000"));
}

#[test]
fn rejection_display_no_aot_receipt() {
    let r = RejectionReason::NoAotReceipt;
    let s = r.to_string();
    assert!(s.contains("AOT"));
}

#[test]
fn rejection_display_target_ineligible() {
    let r = RejectionReason::TargetIneligible {
        target: PromotionTarget::AotArtifact,
    };
    let s = r.to_string();
    assert!(s.contains("aot_artifact"));
}

#[test]
fn rejection_serde_roundtrip_all_variants() {
    let reasons = vec![
        RejectionReason::ProofNotVerified,
        RejectionReason::InsufficientProofCoverage {
            coverage_millionths: 500_000,
            threshold_millionths: 950_000,
        },
        RejectionReason::InsufficientSpeedup {
            speedup_millionths: 30_000,
            threshold_millionths: 100_000,
        },
        RejectionReason::ActiveCounterexamples { count: 5 },
        RejectionReason::CounterexampleSeverity {
            max_severity_millionths: 100_000,
            threshold_millionths: 0,
        },
        RejectionReason::RegressionGateFailure {
            confidence_millionths: 700_000,
            threshold_millionths: 900_000,
        },
        RejectionReason::NoAotReceipt,
        RejectionReason::TargetIneligible {
            target: PromotionTarget::AdaptiveRouter,
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// PromotionEvidence
// ---------------------------------------------------------------------------

#[test]
fn evidence_verified_properties() {
    let e = good_evidence();
    assert!(e.proof_verified);
    assert!(e.aot_compiled);
    assert_eq!(e.active_counterexamples, 0);
    assert_eq!(e.max_counterexample_severity_millionths, 0);
    assert_eq!(e.proof_coverage_millionths, 960_000);
    assert_eq!(e.speedup_millionths, 150_000);
    assert_eq!(e.regression_confidence_millionths, 950_000);
    assert!(
        e.eligible_targets
            .contains(&PromotionTarget::BaselineHotPath)
    );
}

#[test]
fn evidence_partial_properties() {
    let e = PromotionEvidence::partial(PartialEvidenceInput {
        proof_verified: false,
        coverage: 500_000,
        speedup: 50_000,
        counterexamples: 2,
        max_severity: 100_000,
        regression_confidence: 800_000,
        aot_compiled: false,
        targets: BTreeSet::new(),
    });
    assert!(!e.proof_verified);
    assert!(!e.aot_compiled);
    assert_eq!(e.active_counterexamples, 2);
    assert_eq!(e.max_counterexample_severity_millionths, 100_000);
    assert_eq!(e.proof_coverage_millionths, 500_000);
    assert_eq!(e.speedup_millionths, 50_000);
    assert_eq!(e.regression_confidence_millionths, 800_000);
    assert!(e.eligible_targets.is_empty());
}

#[test]
fn evidence_verified_serde_roundtrip() {
    let e = good_evidence();
    let json = serde_json::to_string(&e).unwrap();
    let back: PromotionEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn evidence_partial_serde_roundtrip() {
    let e = PromotionEvidence::partial(PartialEvidenceInput {
        proof_verified: false,
        coverage: 400_000,
        speedup: 20_000,
        counterexamples: 10,
        max_severity: 300_000,
        regression_confidence: 600_000,
        aot_compiled: false,
        targets: BTreeSet::from([PromotionTarget::SupremacyEvidence]),
    });
    let json = serde_json::to_string(&e).unwrap();
    let back: PromotionEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn evidence_verified_with_all_targets() {
    let e = PromotionEvidence::verified(1_000_000, 500_000, 1_000_000, all_targets());
    assert_eq!(e.eligible_targets.len(), 5);
    assert!(e.proof_verified);
    assert!(e.aot_compiled);
}

#[test]
fn evidence_partial_zero_values() {
    let e = PromotionEvidence::partial(PartialEvidenceInput {
        proof_verified: true,
        coverage: 0,
        speedup: 0,
        counterexamples: 0,
        max_severity: 0,
        regression_confidence: 0,
        aot_compiled: true,
        targets: baseline_target(),
    });
    assert_eq!(e.proof_coverage_millionths, 0);
    assert_eq!(e.speedup_millionths, 0);
    assert_eq!(e.regression_confidence_millionths, 0);
}

// ---------------------------------------------------------------------------
// PromotionGateConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_matches_constants() {
    let c = PromotionGateConfig::default_config();
    assert_eq!(c.min_speedup, MIN_PROMOTION_SPEEDUP);
    assert_eq!(c.min_proof_coverage, MIN_PROOF_COVERAGE);
    assert_eq!(c.max_counterexamples, MAX_ACTIVE_COUNTEREXAMPLES);
    assert_eq!(c.max_counterexample_severity, MAX_COUNTEREXAMPLE_SEVERITY);
    assert_eq!(c.min_regression_confidence, MIN_REGRESSION_CONFIDENCE);
    assert!(c.require_aot);
}

#[test]
fn config_default_trait_equals_default_config() {
    assert_eq!(
        PromotionGateConfig::default(),
        PromotionGateConfig::default_config()
    );
}

#[test]
fn config_permissive_values() {
    let c = PromotionGateConfig::permissive();
    assert_eq!(c.min_speedup, 0);
    assert_eq!(c.min_proof_coverage, 0);
    assert_eq!(c.max_counterexamples, usize::MAX);
    assert_eq!(c.max_counterexample_severity, 1_000_000);
    assert_eq!(c.min_regression_confidence, 0);
    assert!(!c.require_aot);
}

#[test]
fn config_serde_roundtrip_default() {
    let c = PromotionGateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: PromotionGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn config_serde_roundtrip_permissive() {
    let c = PromotionGateConfig::permissive();
    let json = serde_json::to_string(&c).unwrap();
    let back: PromotionGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// PromotionGate — basic evaluation
// ---------------------------------------------------------------------------

#[test]
fn gate_promotes_good_candidate() {
    let gate = PromotionGate::with_defaults();
    let d = gate.evaluate("k1", &good_evidence());
    assert!(d.is_promoted());
    assert_eq!(d.kernel_id(), "k1");
    assert_eq!(d.tag(), "promoted");
}

#[test]
fn gate_rejects_unverified_proof() {
    let gate = PromotionGate::with_defaults();
    let mut e = good_evidence();
    e.proof_verified = false;
    let d = gate.evaluate("k1", &e);
    assert!(d.is_rejected());
}

#[test]
fn gate_rejects_low_proof_coverage() {
    let gate = PromotionGate::with_defaults();
    let mut e = good_evidence();
    e.proof_coverage_millionths = 500_000;
    let d = gate.evaluate("k1", &e);
    assert!(d.is_rejected());
}

#[test]
fn gate_rejects_low_speedup() {
    let gate = PromotionGate::with_defaults();
    let mut e = good_evidence();
    e.speedup_millionths = 10_000;
    let d = gate.evaluate("k1", &e);
    assert!(d.is_rejected());
}

#[test]
fn gate_rejects_active_counterexamples() {
    let gate = PromotionGate::with_defaults();
    let mut e = good_evidence();
    e.active_counterexamples = 1;
    let d = gate.evaluate("k1", &e);
    assert!(d.is_rejected());
}

#[test]
fn gate_rejects_counterexample_severity() {
    let gate = PromotionGate::with_defaults();
    let mut e = good_evidence();
    e.max_counterexample_severity_millionths = 1;
    let d = gate.evaluate("k1", &e);
    assert!(d.is_rejected());
}

#[test]
fn gate_rejects_empty_targets() {
    let gate = PromotionGate::with_defaults();
    let mut e = good_evidence();
    e.eligible_targets.clear();
    let d = gate.evaluate("k1", &e);
    assert!(d.is_rejected());
}

#[test]
fn gate_defers_low_regression_confidence() {
    let gate = PromotionGate::with_defaults();
    let mut e = good_evidence();
    e.regression_confidence_millionths = 500_000;
    let d = gate.evaluate("k1", &e);
    assert!(d.is_deferred());
    assert_eq!(d.tag(), "deferred");
}

#[test]
fn gate_defers_no_aot() {
    let gate = PromotionGate::with_defaults();
    let mut e = good_evidence();
    e.aot_compiled = false;
    let d = gate.evaluate("k1", &e);
    assert!(d.is_deferred());
}

#[test]
fn gate_hard_rejection_overrides_soft() {
    // When both hard and soft rejections present, result should be Rejected not Deferred.
    let gate = PromotionGate::with_defaults();
    let mut e = good_evidence();
    e.proof_verified = false; // hard rejection
    e.aot_compiled = false; // soft rejection
    let d = gate.evaluate("k1", &e);
    assert!(d.is_rejected());
    assert!(!d.is_deferred());
}

#[test]
fn gate_multiple_soft_rejections_defers() {
    let gate = PromotionGate::with_defaults();
    let mut e = good_evidence();
    e.regression_confidence_millionths = 100_000; // soft
    e.aot_compiled = false; // soft
    let d = gate.evaluate("k1", &e);
    assert!(d.is_deferred());
}

// ---------------------------------------------------------------------------
// PromotionGate — permissive config
// ---------------------------------------------------------------------------

#[test]
fn permissive_promotes_weak_candidate() {
    let gate = PromotionGate::with_config(PromotionGateConfig::permissive());
    let e = PromotionEvidence::partial(PartialEvidenceInput {
        proof_verified: false,
        coverage: 0,
        speedup: 0,
        counterexamples: 100,
        max_severity: 500_000,
        regression_confidence: 0,
        aot_compiled: false,
        targets: baseline_target(),
    });
    let d = gate.evaluate("k1", &e);
    assert!(d.is_promoted());
}

#[test]
fn permissive_still_rejects_empty_targets() {
    // Even permissive config rejects empty targets (hard rejection: TargetIneligible).
    let gate = PromotionGate::with_config(PromotionGateConfig::permissive());
    let e = PromotionEvidence::partial(PartialEvidenceInput {
        proof_verified: false,
        coverage: 0,
        speedup: 0,
        counterexamples: 100,
        max_severity: 500_000,
        regression_confidence: 0,
        aot_compiled: false,
        targets: BTreeSet::new(),
    });
    let d = gate.evaluate("k1", &e);
    assert!(d.is_rejected());
}

// ---------------------------------------------------------------------------
// PromotionGate — boundary values
// ---------------------------------------------------------------------------

#[test]
fn gate_boundary_speedup_exactly_at_threshold() {
    let gate = PromotionGate::with_defaults();
    let e = PromotionEvidence::verified(
        960_000,
        MIN_PROMOTION_SPEEDUP, // exactly at threshold
        950_000,
        baseline_target(),
    );
    let d = gate.evaluate("k1", &e);
    assert!(d.is_promoted());
}

#[test]
fn gate_boundary_speedup_one_below_threshold() {
    let gate = PromotionGate::with_defaults();
    let e = PromotionEvidence::verified(
        960_000,
        MIN_PROMOTION_SPEEDUP - 1, // one below threshold
        950_000,
        baseline_target(),
    );
    let d = gate.evaluate("k1", &e);
    assert!(d.is_rejected());
}

#[test]
fn gate_boundary_coverage_exactly_at_threshold() {
    let gate = PromotionGate::with_defaults();
    let e = PromotionEvidence::verified(
        MIN_PROOF_COVERAGE, // exactly at threshold
        150_000,
        950_000,
        baseline_target(),
    );
    let d = gate.evaluate("k1", &e);
    assert!(d.is_promoted());
}

#[test]
fn gate_boundary_coverage_one_below_threshold() {
    let gate = PromotionGate::with_defaults();
    let e = PromotionEvidence::verified(
        MIN_PROOF_COVERAGE - 1, // one below
        150_000,
        950_000,
        baseline_target(),
    );
    let d = gate.evaluate("k1", &e);
    assert!(d.is_rejected());
}

#[test]
fn gate_boundary_regression_exactly_at_threshold() {
    let gate = PromotionGate::with_defaults();
    let e = PromotionEvidence::verified(
        960_000,
        150_000,
        MIN_REGRESSION_CONFIDENCE, // exactly at threshold
        baseline_target(),
    );
    let d = gate.evaluate("k1", &e);
    assert!(d.is_promoted());
}

#[test]
fn gate_boundary_regression_one_below_threshold() {
    let gate = PromotionGate::with_defaults();
    let e = PromotionEvidence::verified(
        960_000,
        150_000,
        MIN_REGRESSION_CONFIDENCE - 1, // one below
        baseline_target(),
    );
    let d = gate.evaluate("k1", &e);
    assert!(d.is_deferred());
}

// ---------------------------------------------------------------------------
// Batch evaluation
// ---------------------------------------------------------------------------

#[test]
fn batch_empty() {
    let gate = PromotionGate::with_defaults();
    let results = gate.evaluate_batch(&[]);
    assert!(results.is_empty());
}

#[test]
fn batch_all_promoted() {
    let gate = PromotionGate::with_defaults();
    let candidates = vec![
        ("k1".to_string(), good_evidence()),
        ("k2".to_string(), good_evidence_aot()),
    ];
    let results = gate.evaluate_batch(&candidates);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|d| d.is_promoted()));
}

#[test]
fn batch_mixed_results() {
    let gate = PromotionGate::with_defaults();
    let mut bad_evidence = good_evidence();
    bad_evidence.proof_verified = false;

    let mut deferred_evidence = good_evidence();
    deferred_evidence.aot_compiled = false;

    let candidates = vec![
        ("k1".to_string(), good_evidence()),
        ("k2".to_string(), bad_evidence),
        ("k3".to_string(), deferred_evidence),
    ];
    let results = gate.evaluate_batch(&candidates);
    assert_eq!(results.len(), 3);
    assert!(results[0].is_promoted());
    assert!(results[1].is_rejected());
    assert!(results[2].is_deferred());
}

#[test]
fn batch_preserves_order() {
    let gate = PromotionGate::with_defaults();
    let candidates = vec![
        ("alpha".to_string(), good_evidence()),
        ("beta".to_string(), good_evidence()),
        ("gamma".to_string(), good_evidence()),
    ];
    let results = gate.evaluate_batch(&candidates);
    assert_eq!(results[0].kernel_id(), "alpha");
    assert_eq!(results[1].kernel_id(), "beta");
    assert_eq!(results[2].kernel_id(), "gamma");
}

// ---------------------------------------------------------------------------
// PromotionDecision
// ---------------------------------------------------------------------------

#[test]
fn decision_promoted_properties() {
    let d = PromotionDecision::Promoted {
        kernel_id: "k1".into(),
        targets: baseline_target(),
        content_hash: ContentHash::compute(b"test"),
    };
    assert!(d.is_promoted());
    assert!(!d.is_rejected());
    assert!(!d.is_deferred());
    assert_eq!(d.kernel_id(), "k1");
    assert_eq!(d.tag(), "promoted");
}

#[test]
fn decision_rejected_properties() {
    let d = PromotionDecision::Rejected {
        kernel_id: "k2".into(),
        reasons: vec![RejectionReason::ProofNotVerified],
    };
    assert!(!d.is_promoted());
    assert!(d.is_rejected());
    assert!(!d.is_deferred());
    assert_eq!(d.kernel_id(), "k2");
    assert_eq!(d.tag(), "rejected");
}

#[test]
fn decision_deferred_properties() {
    let d = PromotionDecision::Deferred {
        kernel_id: "k3".into(),
        pending_reasons: vec![RejectionReason::NoAotReceipt],
    };
    assert!(!d.is_promoted());
    assert!(!d.is_rejected());
    assert!(d.is_deferred());
    assert_eq!(d.kernel_id(), "k3");
    assert_eq!(d.tag(), "deferred");
}

#[test]
fn decision_display_promoted() {
    let d = PromotionDecision::Promoted {
        kernel_id: "k1".into(),
        targets: baseline_target(),
        content_hash: ContentHash::compute(b"test"),
    };
    let s = d.to_string();
    assert!(s.contains("PROMOTED"));
    assert!(s.contains("k1"));
    assert!(s.contains("1 target"));
}

#[test]
fn decision_display_rejected() {
    let d = PromotionDecision::Rejected {
        kernel_id: "k2".into(),
        reasons: vec![
            RejectionReason::ProofNotVerified,
            RejectionReason::NoAotReceipt,
        ],
    };
    let s = d.to_string();
    assert!(s.contains("REJECTED"));
    assert!(s.contains("k2"));
    assert!(s.contains("2 reason"));
}

#[test]
fn decision_display_deferred() {
    let d = PromotionDecision::Deferred {
        kernel_id: "k3".into(),
        pending_reasons: vec![RejectionReason::NoAotReceipt],
    };
    let s = d.to_string();
    assert!(s.contains("DEFERRED"));
    assert!(s.contains("k3"));
    assert!(s.contains("1 pending"));
}

#[test]
fn decision_serde_promoted_roundtrip() {
    let d = PromotionDecision::Promoted {
        kernel_id: "k1".into(),
        targets: all_targets(),
        content_hash: ContentHash::compute(b"serde-test"),
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: PromotionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn decision_serde_rejected_roundtrip() {
    let d = PromotionDecision::Rejected {
        kernel_id: "k2".into(),
        reasons: vec![
            RejectionReason::ProofNotVerified,
            RejectionReason::InsufficientSpeedup {
                speedup_millionths: 50_000,
                threshold_millionths: 100_000,
            },
        ],
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: PromotionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn decision_serde_deferred_roundtrip() {
    let d = PromotionDecision::Deferred {
        kernel_id: "k3".into(),
        pending_reasons: vec![
            RejectionReason::NoAotReceipt,
            RejectionReason::RegressionGateFailure {
                confidence_millionths: 700_000,
                threshold_millionths: 900_000,
            },
        ],
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: PromotionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// DemotionReceipt
// ---------------------------------------------------------------------------

#[test]
fn demotion_receipt_creation() {
    let r = DemotionReceipt::new(
        "k1",
        DemotionCause::PerformanceRegression,
        epoch(),
        baseline_target(),
        "regression detected",
    );
    assert_eq!(r.kernel_id, "k1");
    assert_eq!(r.cause, DemotionCause::PerformanceRegression);
    assert_eq!(r.epoch, epoch());
    assert!(r.removed_from.contains(&PromotionTarget::BaselineHotPath));
    assert_eq!(r.description, "regression detected");
}

#[test]
fn demotion_receipt_hash_deterministic() {
    let r1 = DemotionReceipt::new(
        "k1",
        DemotionCause::PerformanceRegression,
        epoch(),
        baseline_target(),
        "regression found",
    );
    let r2 = DemotionReceipt::new(
        "k1",
        DemotionCause::PerformanceRegression,
        epoch(),
        baseline_target(),
        "regression found",
    );
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn demotion_receipt_different_cause_different_hash() {
    let r1 = DemotionReceipt::new(
        "k1",
        DemotionCause::PerformanceRegression,
        epoch(),
        baseline_target(),
        "problem",
    );
    let r2 = DemotionReceipt::new(
        "k1",
        DemotionCause::HardwareFailure,
        epoch(),
        baseline_target(),
        "problem",
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn demotion_receipt_different_epoch_different_hash() {
    let r1 = DemotionReceipt::new(
        "k1",
        DemotionCause::PolicyChange,
        epoch(),
        baseline_target(),
        "policy change",
    );
    let r2 = DemotionReceipt::new(
        "k1",
        DemotionCause::PolicyChange,
        epoch2(),
        baseline_target(),
        "policy change",
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn demotion_receipt_serde_roundtrip() {
    let r = DemotionReceipt::new(
        "k1",
        DemotionCause::CounterexampleFound,
        epoch(),
        all_targets(),
        "counterexample discovered",
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: DemotionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// PromotedKernel
// ---------------------------------------------------------------------------

#[test]
fn promoted_kernel_new_is_active() {
    let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    assert!(k.is_active());
    assert_eq!(k.status, PromotionStatus::Active);
    assert!(k.demotion.is_none());
    assert_eq!(k.kernel_id, "k1");
    assert_eq!(k.original_kernel_id, "orig1");
    assert_eq!(k.speedup_at_promotion, 150_000);
    assert_eq!(k.proof_coverage_at_promotion, 960_000);
    assert_eq!(k.promotion_epoch, epoch());
    assert!(k.active_targets.contains(&PromotionTarget::BaselineHotPath));
}

#[test]
fn promoted_kernel_demote_lifecycle() {
    let mut k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let receipt = DemotionReceipt::new(
        "k1",
        DemotionCause::PerformanceRegression,
        epoch(),
        baseline_target(),
        "regressed",
    );
    k.demote(receipt);
    assert!(!k.is_active());
    assert_eq!(k.status, PromotionStatus::Demoted);
    assert!(k.status.is_terminal());
    assert!(k.active_targets.is_empty());
    assert!(k.demotion.is_some());
    assert_eq!(
        k.demotion.as_ref().unwrap().cause,
        DemotionCause::PerformanceRegression
    );
}

#[test]
fn promoted_kernel_supersede_lifecycle() {
    let mut k = PromotedKernel::new("k1", "orig1", all_targets(), epoch(), 150_000, 960_000);
    k.supersede("k2", epoch2());
    assert!(!k.is_active());
    assert_eq!(k.status, PromotionStatus::Superseded);
    assert!(k.status.is_terminal());
    assert!(k.active_targets.is_empty());
    assert!(k.demotion.is_some());
    let receipt = k.demotion.as_ref().unwrap();
    assert_eq!(receipt.cause, DemotionCause::Superseded);
    assert!(receipt.description.contains("k2"));
}

#[test]
fn promoted_kernel_hash_deterministic() {
    let k1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let k2 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    assert_eq!(k1.content_hash, k2.content_hash);
}

#[test]
fn promoted_kernel_different_id_different_hash() {
    let k1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let k2 = PromotedKernel::new("k2", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    assert_ne!(k1.content_hash, k2.content_hash);
}

#[test]
fn promoted_kernel_different_targets_different_hash() {
    let k1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let k2 = PromotedKernel::new("k1", "orig1", aot_target(), epoch(), 150_000, 960_000);
    assert_ne!(k1.content_hash, k2.content_hash);
}

#[test]
fn promoted_kernel_serde_roundtrip() {
    let k = PromotedKernel::new("k1", "orig1", all_targets(), epoch(), 200_000, 980_000);
    let json = serde_json::to_string(&k).unwrap();
    let back: PromotedKernel = serde_json::from_str(&json).unwrap();
    assert_eq!(k, back);
}

#[test]
fn promoted_kernel_demoted_serde_roundtrip() {
    let mut k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let receipt = DemotionReceipt::new(
        "k1",
        DemotionCause::CompileFailure,
        epoch(),
        baseline_target(),
        "compile failure",
    );
    k.demote(receipt);
    let json = serde_json::to_string(&k).unwrap();
    let back: PromotedKernel = serde_json::from_str(&json).unwrap();
    assert_eq!(k, back);
}

// ---------------------------------------------------------------------------
// PromotionLedger
// ---------------------------------------------------------------------------

#[test]
fn ledger_new_is_empty() {
    let ledger = PromotionLedger::new();
    assert_eq!(ledger.active_count(), 0);
    assert_eq!(ledger.demoted_count(), 0);
    assert_eq!(ledger.superseded_count(), 0);
    assert!(ledger.demotion_receipts().is_empty());
    assert_eq!(ledger.schema_version, SCHEMA_VERSION);
}

#[test]
fn ledger_default_equals_new() {
    let a = PromotionLedger::new();
    let b = PromotionLedger::default();
    assert_eq!(a, b);
}

#[test]
fn ledger_record_and_count() {
    let mut ledger = PromotionLedger::new();
    let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    ledger.record_promotion(k);
    assert_eq!(ledger.active_count(), 1);
    assert_eq!(ledger.entries.len(), 1);
}

#[test]
fn ledger_record_multiple() {
    let mut ledger = PromotionLedger::new();
    let k1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let k2 = PromotedKernel::new("k2", "orig2", aot_target(), epoch(), 200_000, 980_000);
    let k3 = PromotedKernel::new("k3", "orig3", router_target(), epoch(), 300_000, 990_000);
    ledger.record_promotion(k1);
    ledger.record_promotion(k2);
    ledger.record_promotion(k3);
    assert_eq!(ledger.active_count(), 3);
}

#[test]
fn ledger_demote_kernel() {
    let mut ledger = PromotionLedger::new();
    let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    ledger.record_promotion(k);

    let receipt = DemotionReceipt::new(
        "k1",
        DemotionCause::HardwareFailure,
        epoch(),
        baseline_target(),
        "hw fail",
    );
    assert!(ledger.demote_kernel("k1", receipt));
    assert_eq!(ledger.active_count(), 0);
    assert_eq!(ledger.demoted_count(), 1);
}

#[test]
fn ledger_demote_nonexistent_returns_false() {
    let mut ledger = PromotionLedger::new();
    let receipt = DemotionReceipt::new(
        "k999",
        DemotionCause::PolicyChange,
        epoch(),
        BTreeSet::new(),
        "nope",
    );
    assert!(!ledger.demote_kernel("k999", receipt));
}

#[test]
fn ledger_demote_already_demoted_returns_false() {
    let mut ledger = PromotionLedger::new();
    let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    ledger.record_promotion(k);

    let receipt1 = DemotionReceipt::new(
        "k1",
        DemotionCause::PerformanceRegression,
        epoch(),
        baseline_target(),
        "regressed",
    );
    assert!(ledger.demote_kernel("k1", receipt1));

    let receipt2 = DemotionReceipt::new(
        "k1",
        DemotionCause::PolicyChange,
        epoch(),
        BTreeSet::new(),
        "second demotion",
    );
    assert!(!ledger.demote_kernel("k1", receipt2));
}

#[test]
fn ledger_supersede_kernel() {
    let mut ledger = PromotionLedger::new();
    let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    ledger.record_promotion(k);
    assert!(ledger.supersede_kernel("k1", "k2", epoch2()));
    assert_eq!(ledger.superseded_count(), 1);
    assert_eq!(ledger.active_count(), 0);
}

#[test]
fn ledger_supersede_nonexistent_returns_false() {
    let mut ledger = PromotionLedger::new();
    assert!(!ledger.supersede_kernel("k999", "k2", epoch()));
}

#[test]
fn ledger_get_kernel_found() {
    let mut ledger = PromotionLedger::new();
    let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    ledger.record_promotion(k);
    let found = ledger.get_kernel("k1");
    assert!(found.is_some());
    assert_eq!(found.unwrap().kernel_id, "k1");
}

#[test]
fn ledger_get_kernel_not_found() {
    let ledger = PromotionLedger::new();
    assert!(ledger.get_kernel("k999").is_none());
}

#[test]
fn ledger_active_for_target() {
    let mut ledger = PromotionLedger::new();
    let k1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let k2 = PromotedKernel::new(
        "k2",
        "orig2",
        BTreeSet::from([PromotionTarget::AotArtifact]),
        epoch(),
        200_000,
        980_000,
    );
    let k3 = PromotedKernel::new("k3", "orig3", baseline_target(), epoch(), 180_000, 970_000);
    ledger.record_promotion(k1);
    ledger.record_promotion(k2);
    ledger.record_promotion(k3);

    let baseline = ledger.active_for_target(PromotionTarget::BaselineHotPath);
    assert_eq!(baseline.len(), 2);
    assert!(baseline.iter().any(|k| k.kernel_id == "k1"));
    assert!(baseline.iter().any(|k| k.kernel_id == "k3"));

    let aot = ledger.active_for_target(PromotionTarget::AotArtifact);
    assert_eq!(aot.len(), 1);
    assert_eq!(aot[0].kernel_id, "k2");

    let router = ledger.active_for_target(PromotionTarget::AdaptiveRouter);
    assert!(router.is_empty());
}

#[test]
fn ledger_active_for_target_excludes_demoted() {
    let mut ledger = PromotionLedger::new();
    let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    ledger.record_promotion(k);
    let receipt = DemotionReceipt::new(
        "k1",
        DemotionCause::PerformanceRegression,
        epoch(),
        baseline_target(),
        "regressed",
    );
    ledger.demote_kernel("k1", receipt);
    let baseline = ledger.active_for_target(PromotionTarget::BaselineHotPath);
    assert!(baseline.is_empty());
}

#[test]
fn ledger_demotion_receipts() {
    let mut ledger = PromotionLedger::new();
    let k1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let k2 = PromotedKernel::new("k2", "orig2", aot_target(), epoch(), 200_000, 980_000);
    ledger.record_promotion(k1);
    ledger.record_promotion(k2);

    let receipt = DemotionReceipt::new(
        "k1",
        DemotionCause::PerformanceRegression,
        epoch(),
        baseline_target(),
        "regressed",
    );
    ledger.demote_kernel("k1", receipt);
    ledger.supersede_kernel("k2", "k3", epoch2());

    let receipts = ledger.demotion_receipts();
    assert_eq!(receipts.len(), 2);
}

#[test]
fn ledger_serde_roundtrip_empty() {
    let ledger = PromotionLedger::new();
    let json = serde_json::to_string(&ledger).unwrap();
    let back: PromotionLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

#[test]
fn ledger_serde_roundtrip_populated() {
    let mut ledger = PromotionLedger::new();
    let k1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    let k2 = PromotedKernel::new("k2", "orig2", aot_target(), epoch(), 200_000, 980_000);
    ledger.record_promotion(k1);
    ledger.record_promotion(k2);

    let receipt = DemotionReceipt::new(
        "k1",
        DemotionCause::OperatorOverride,
        epoch(),
        baseline_target(),
        "operator override",
    );
    ledger.demote_kernel("k1", receipt);

    let json = serde_json::to_string(&ledger).unwrap();
    let back: PromotionLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

// ---------------------------------------------------------------------------
// PromotionReport
// ---------------------------------------------------------------------------

#[test]
fn report_empty() {
    let r = PromotionReport::new(epoch(), Vec::new());
    assert_eq!(r.total_count(), 0);
    assert_eq!(r.promoted_count, 0);
    assert_eq!(r.rejected_count, 0);
    assert_eq!(r.deferred_count, 0);
    assert_eq!(r.promotion_rate(), 0);
    assert!(!r.all_promoted());
    assert!(!r.has_rejections());
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

#[test]
fn report_all_promoted() {
    let gate = PromotionGate::with_defaults();
    let d1 = gate.evaluate("k1", &good_evidence());
    let d2 = gate.evaluate("k2", &good_evidence_aot());
    let r = PromotionReport::new(epoch(), vec![d1, d2]);
    assert!(r.all_promoted());
    assert_eq!(r.promoted_count, 2);
    assert_eq!(r.promotion_rate(), 1_000_000);
    assert!(!r.has_rejections());
}

#[test]
fn report_mixed_decisions() {
    let decisions = vec![
        PromotionDecision::Promoted {
            kernel_id: "k1".into(),
            targets: baseline_target(),
            content_hash: ContentHash::compute(b"k1"),
        },
        PromotionDecision::Rejected {
            kernel_id: "k2".into(),
            reasons: vec![RejectionReason::ProofNotVerified],
        },
        PromotionDecision::Deferred {
            kernel_id: "k3".into(),
            pending_reasons: vec![RejectionReason::NoAotReceipt],
        },
    ];
    let r = PromotionReport::new(epoch(), decisions);
    assert_eq!(r.total_count(), 3);
    assert_eq!(r.promoted_count, 1);
    assert_eq!(r.rejected_count, 1);
    assert_eq!(r.deferred_count, 1);
    assert!(r.has_rejections());
    assert!(!r.all_promoted());
}

#[test]
fn report_promotion_rate_half() {
    let decisions = vec![
        PromotionDecision::Promoted {
            kernel_id: "k1".into(),
            targets: baseline_target(),
            content_hash: ContentHash::compute(b"k1"),
        },
        PromotionDecision::Rejected {
            kernel_id: "k2".into(),
            reasons: vec![RejectionReason::ProofNotVerified],
        },
    ];
    let r = PromotionReport::new(epoch(), decisions);
    assert_eq!(r.promotion_rate(), 500_000);
}

#[test]
fn report_hash_deterministic() {
    let d = vec![PromotionDecision::Promoted {
        kernel_id: "k1".into(),
        targets: baseline_target(),
        content_hash: ContentHash::compute(b"k1"),
    }];
    let r1 = PromotionReport::new(epoch(), d.clone());
    let r2 = PromotionReport::new(epoch(), d);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_different_epoch_different_hash() {
    let d = vec![PromotionDecision::Promoted {
        kernel_id: "k1".into(),
        targets: baseline_target(),
        content_hash: ContentHash::compute(b"k1"),
    }];
    let r1 = PromotionReport::new(epoch(), d.clone());
    let r2 = PromotionReport::new(epoch2(), d);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_serde_roundtrip() {
    let decisions = vec![
        PromotionDecision::Promoted {
            kernel_id: "k1".into(),
            targets: baseline_target(),
            content_hash: ContentHash::compute(b"k1"),
        },
        PromotionDecision::Deferred {
            kernel_id: "k2".into(),
            pending_reasons: vec![RejectionReason::NoAotReceipt],
        },
        PromotionDecision::Rejected {
            kernel_id: "k3".into(),
            reasons: vec![
                RejectionReason::ProofNotVerified,
                RejectionReason::InsufficientSpeedup {
                    speedup_millionths: 10_000,
                    threshold_millionths: 100_000,
                },
            ],
        },
    ];
    let r = PromotionReport::new(epoch(), decisions);
    let json = serde_json::to_string(&r).unwrap();
    let back: PromotionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// PromotionGate serde
// ---------------------------------------------------------------------------

#[test]
fn gate_serde_roundtrip_default() {
    let g = PromotionGate::with_defaults();
    let json = serde_json::to_string(&g).unwrap();
    let back: PromotionGate = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

#[test]
fn gate_serde_roundtrip_permissive() {
    let g = PromotionGate::with_config(PromotionGateConfig::permissive());
    let json = serde_json::to_string(&g).unwrap();
    let back: PromotionGate = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

#[test]
fn gate_schema_version_set() {
    let g = PromotionGate::with_defaults();
    assert_eq!(g.schema_version, SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// End-to-end workflows
// ---------------------------------------------------------------------------

#[test]
fn full_promotion_lifecycle() {
    // Evaluate candidate, record promotion, then demote.
    let gate = PromotionGate::with_defaults();
    let d = gate.evaluate("k1", &good_evidence());
    assert!(d.is_promoted());

    let mut ledger = PromotionLedger::new();
    let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    ledger.record_promotion(k);
    assert_eq!(ledger.active_count(), 1);

    let receipt = DemotionReceipt::new(
        "k1",
        DemotionCause::PerformanceRegression,
        epoch2(),
        baseline_target(),
        "production regression detected",
    );
    assert!(ledger.demote_kernel("k1", receipt));
    assert_eq!(ledger.active_count(), 0);
    assert_eq!(ledger.demoted_count(), 1);
    assert_eq!(ledger.demotion_receipts().len(), 1);
}

#[test]
fn full_supersession_lifecycle() {
    let mut ledger = PromotionLedger::new();
    let k1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
    ledger.record_promotion(k1);

    let k2 = PromotedKernel::new("k2", "orig1", baseline_target(), epoch2(), 300_000, 990_000);
    ledger.record_promotion(k2);

    assert!(ledger.supersede_kernel("k1", "k2", epoch2()));
    assert_eq!(ledger.active_count(), 1);
    assert_eq!(ledger.superseded_count(), 1);

    let still_active = ledger.active_for_target(PromotionTarget::BaselineHotPath);
    assert_eq!(still_active.len(), 1);
    assert_eq!(still_active[0].kernel_id, "k2");
}

#[test]
fn full_gate_with_report() {
    let gate = PromotionGate::with_defaults();

    let mut bad_evidence = good_evidence();
    bad_evidence.proof_verified = false;

    let mut deferred_evidence = good_evidence();
    deferred_evidence.aot_compiled = false;

    let candidates = vec![
        ("k1".to_string(), good_evidence()),
        ("k2".to_string(), bad_evidence),
        ("k3".to_string(), deferred_evidence),
        ("k4".to_string(), good_evidence_all_targets()),
    ];
    let decisions = gate.evaluate_batch(&candidates);
    let report = PromotionReport::new(epoch(), decisions);

    assert_eq!(report.total_count(), 4);
    assert_eq!(report.promoted_count, 2); // k1, k4
    assert_eq!(report.rejected_count, 1); // k2
    assert_eq!(report.deferred_count, 1); // k3
    assert!(report.has_rejections());
    assert!(!report.all_promoted());
    assert_eq!(report.promotion_rate(), 500_000);
}

#[test]
fn multiple_targets_in_ledger() {
    let mut ledger = PromotionLedger::new();
    let k1 = PromotedKernel::new("k1", "orig1", all_targets(), epoch(), 250_000, 990_000);
    let k2 = PromotedKernel::new("k2", "orig2", baseline_target(), epoch(), 150_000, 960_000);
    let k3 = PromotedKernel::new("k3", "orig3", aot_target(), epoch(), 200_000, 970_000);
    ledger.record_promotion(k1);
    ledger.record_promotion(k2);
    ledger.record_promotion(k3);

    // k1 is active in all targets
    let baseline = ledger.active_for_target(PromotionTarget::BaselineHotPath);
    assert_eq!(baseline.len(), 2); // k1 + k2
    let aot = ledger.active_for_target(PromotionTarget::AotArtifact);
    assert_eq!(aot.len(), 2); // k1 + k3
    let supremacy = ledger.active_for_target(PromotionTarget::SupremacyEvidence);
    assert_eq!(supremacy.len(), 1); // k1 only
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn evidence_max_millionths() {
    let e = PromotionEvidence::verified(1_000_000, 1_000_000, 1_000_000, baseline_target());
    assert_eq!(e.proof_coverage_millionths, 1_000_000);
    assert_eq!(e.speedup_millionths, 1_000_000);
    assert_eq!(e.regression_confidence_millionths, 1_000_000);
}

#[test]
fn evidence_zero_millionths() {
    let e = PromotionEvidence::partial(PartialEvidenceInput {
        proof_verified: true,
        coverage: 0,
        speedup: 0,
        counterexamples: 0,
        max_severity: 0,
        regression_confidence: 0,
        aot_compiled: true,
        targets: baseline_target(),
    });
    assert_eq!(e.proof_coverage_millionths, 0);
    assert_eq!(e.speedup_millionths, 0);
}

#[test]
fn promotion_decision_hash_deterministic_via_gate() {
    let gate = PromotionGate::with_defaults();
    let d1 = gate.evaluate("k1", &good_evidence());
    let d2 = gate.evaluate("k1", &good_evidence());
    if let (
        PromotionDecision::Promoted {
            content_hash: h1, ..
        },
        PromotionDecision::Promoted {
            content_hash: h2, ..
        },
    ) = (&d1, &d2)
    {
        assert_eq!(h1, h2);
    } else {
        panic!("expected both promoted");
    }
}

#[test]
fn demotion_receipt_empty_removed_from() {
    let r = DemotionReceipt::new(
        "k1",
        DemotionCause::OperatorOverride,
        epoch(),
        BTreeSet::new(),
        "override",
    );
    assert!(r.removed_from.is_empty());
}

#[test]
fn ledger_counts_after_mixed_operations() {
    let mut ledger = PromotionLedger::new();
    for i in 0..5 {
        let k = PromotedKernel::new(
            format!("k{i}"),
            format!("orig{i}"),
            baseline_target(),
            epoch(),
            150_000 + i as u64 * 10_000,
            960_000,
        );
        ledger.record_promotion(k);
    }
    assert_eq!(ledger.active_count(), 5);

    // Demote k0
    let receipt = DemotionReceipt::new(
        "k0",
        DemotionCause::PerformanceRegression,
        epoch(),
        baseline_target(),
        "regressed",
    );
    ledger.demote_kernel("k0", receipt);

    // Supersede k1
    ledger.supersede_kernel("k1", "k5", epoch2());

    assert_eq!(ledger.active_count(), 3);
    assert_eq!(ledger.demoted_count(), 1);
    assert_eq!(ledger.superseded_count(), 1);
    assert_eq!(ledger.entries.len(), 5);
    assert_eq!(ledger.demotion_receipts().len(), 2);
}
