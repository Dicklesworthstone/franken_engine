//! Integration tests for `causal_uplift_evidence_gate` module.
//!
//! Validates public API, serde contracts, determinism, gate evaluation logic,
//! batch processing, report aggregation, and rejection reason coverage.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::causal_uplift_evidence_gate::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(800)
}

fn good_backing(category: ClaimCategory) -> CausalBacking {
    CausalBacking {
        method: IdentificationMethod::Backdoor,
        effect_millionths: 50_000,
        ci_lower_millionths: 20_000,
        ci_upper_millionths: 80_000,
        confidence_millionths: 900_000,
        adjustment_variables: BTreeSet::from(["workload_type".to_string()]),
        evidence_category: category,
        identified: true,
        certificate_hash: ContentHash::compute(b"test-cert"),
    }
}

fn strong_backing(category: ClaimCategory) -> CausalBacking {
    CausalBacking {
        method: IdentificationMethod::Randomized,
        effect_millionths: 100_000,
        ci_lower_millionths: 60_000,
        ci_upper_millionths: 140_000,
        confidence_millionths: 950_000,
        adjustment_variables: BTreeSet::new(),
        evidence_category: category,
        identified: true,
        certificate_hash: ContentHash::compute(b"strong-cert"),
    }
}

fn weak_backing(category: ClaimCategory) -> CausalBacking {
    CausalBacking {
        method: IdentificationMethod::ExpertAssertion,
        effect_millionths: 5_000,
        ci_lower_millionths: -2_000,
        ci_upper_millionths: 12_000,
        confidence_millionths: 600_000,
        adjustment_variables: BTreeSet::from(["x".to_string()]),
        evidence_category: category,
        identified: true,
        certificate_hash: ContentHash::compute(b"weak-cert"),
    }
}

fn regression_claim() -> UpliftClaim {
    UpliftClaim {
        claim_id: "reg-1".into(),
        category: ClaimCategory::Regression,
        description: "10% latency regression".into(),
        claimed_effect_millionths: 100_000,
        surface: "latency-p99".into(),
        min_evidence_strength: 2,
    }
}

fn supremacy_claim() -> UpliftClaim {
    UpliftClaim {
        claim_id: "sup-1".into(),
        category: ClaimCategory::Supremacy,
        description: "Dominates competitor on throughput".into(),
        claimed_effect_millionths: 200_000,
        surface: "throughput".into(),
        min_evidence_strength: 3,
    }
}

fn transfer_claim() -> UpliftClaim {
    UpliftClaim {
        claim_id: "xfer-1".into(),
        category: ClaimCategory::Transfer,
        description: "Win transfers to ARM".into(),
        claimed_effect_millionths: 80_000,
        surface: "latency-p50".into(),
        min_evidence_strength: 3,
    }
}

fn rollout_claim() -> UpliftClaim {
    UpliftClaim {
        claim_id: "roll-1".into(),
        category: ClaimCategory::Rollout,
        description: "Safe to ship tiering change".into(),
        claimed_effect_millionths: 50_000,
        surface: "latency-p99".into(),
        min_evidence_strength: 2,
    }
}

fn optimization_claim() -> UpliftClaim {
    UpliftClaim {
        claim_id: "opt-1".into(),
        category: ClaimCategory::Optimization,
        description: "Loop unrolling 5% throughput gain".into(),
        claimed_effect_millionths: 50_000,
        surface: "throughput".into(),
        min_evidence_strength: 1,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("causal-uplift"));
}

#[test]
fn component_name() {
    assert_eq!(COMPONENT, "causal_uplift_evidence_gate");
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
fn threshold_invariants() {
    assert!(MIN_EFFECT_THRESHOLD > 0);
    assert!(MIN_IDENTIFICATION_CONFIDENCE > 0);
    assert!(MIN_IDENTIFICATION_CONFIDENCE <= 1_000_000);
    assert!(MAX_RELATIVE_CI_WIDTH > 0);
    assert!(DEFAULT_MAX_BATCH_SIZE > 0);
}

// ---------------------------------------------------------------------------
// ClaimCategory
// ---------------------------------------------------------------------------

#[test]
fn category_all_count() {
    assert_eq!(ClaimCategory::ALL.len(), 5);
}

#[test]
fn category_names_unique() {
    let names: BTreeSet<&str> = ClaimCategory::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(names.len(), ClaimCategory::ALL.len());
}

#[test]
fn category_display_matches_as_str() {
    for c in ClaimCategory::ALL {
        assert_eq!(c.to_string(), c.as_str());
    }
}

#[test]
fn category_serde_all() {
    for c in ClaimCategory::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: ClaimCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ---------------------------------------------------------------------------
// IdentificationMethod
// ---------------------------------------------------------------------------

#[test]
fn method_all_count() {
    assert_eq!(IdentificationMethod::ALL.len(), 6);
}

#[test]
fn method_names_unique() {
    let names: BTreeSet<&str> = IdentificationMethod::ALL.iter().map(|m| m.as_str()).collect();
    assert_eq!(names.len(), IdentificationMethod::ALL.len());
}

#[test]
fn method_display_matches_as_str() {
    for m in IdentificationMethod::ALL {
        assert_eq!(m.to_string(), m.as_str());
    }
}

#[test]
fn method_serde_all() {
    for m in IdentificationMethod::ALL {
        let json = serde_json::to_string(m).unwrap();
        let back: IdentificationMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, back);
    }
}

#[test]
fn method_strength_ranks_valid() {
    for m in IdentificationMethod::ALL {
        assert!(m.strength_rank() >= 1);
        assert!(m.strength_rank() <= 5);
    }
}

#[test]
fn method_randomized_strongest() {
    for m in IdentificationMethod::ALL {
        assert!(IdentificationMethod::Randomized.strength_rank() >= m.strength_rank());
    }
}

#[test]
fn method_expert_weakest() {
    for m in IdentificationMethod::ALL {
        assert!(IdentificationMethod::ExpertAssertion.strength_rank() <= m.strength_rank());
    }
}

// ---------------------------------------------------------------------------
// RejectionReason
// ---------------------------------------------------------------------------

#[test]
fn rejection_tags_unique() {
    let reasons = vec![
        RejectionReason::IdentificationAbstained,
        RejectionReason::EffectBelowThreshold {
            effect_millionths: 0,
            threshold_millionths: 0,
        },
        RejectionReason::IntervalSpansZero {
            lower_millionths: 0,
            upper_millionths: 0,
        },
        RejectionReason::IntervalTooWide {
            width_millionths: 0,
            effect_millionths: 0,
        },
        RejectionReason::LowConfidence {
            confidence_millionths: 0,
            threshold_millionths: 0,
        },
        RejectionReason::CategoryMismatch {
            claim: ClaimCategory::Regression,
            evidence: ClaimCategory::Transfer,
        },
        RejectionReason::NoAdjustmentPath,
        RejectionReason::WeakEvidence {
            method: IdentificationMethod::ExpertAssertion,
            min_strength: 3,
        },
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 8);
}

#[test]
fn rejection_serde_all_variants() {
    let reasons = vec![
        RejectionReason::IdentificationAbstained,
        RejectionReason::EffectBelowThreshold {
            effect_millionths: 5_000,
            threshold_millionths: 10_000,
        },
        RejectionReason::IntervalSpansZero {
            lower_millionths: -10_000,
            upper_millionths: 5_000,
        },
        RejectionReason::IntervalTooWide {
            width_millionths: 100_000,
            effect_millionths: 20_000,
        },
        RejectionReason::LowConfidence {
            confidence_millionths: 500_000,
            threshold_millionths: 800_000,
        },
        RejectionReason::CategoryMismatch {
            claim: ClaimCategory::Supremacy,
            evidence: ClaimCategory::Optimization,
        },
        RejectionReason::NoAdjustmentPath,
        RejectionReason::WeakEvidence {
            method: IdentificationMethod::DifferenceInDifferences,
            min_strength: 3,
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn rejection_display_contains_values() {
    let r = RejectionReason::LowConfidence {
        confidence_millionths: 500_000,
        threshold_millionths: 800_000,
    };
    let s = r.to_string();
    assert!(s.contains("500000"));
    assert!(s.contains("800000"));
}

// ---------------------------------------------------------------------------
// CausalBacking
// ---------------------------------------------------------------------------

#[test]
fn backing_ci_width() {
    let b = good_backing(ClaimCategory::Regression);
    assert_eq!(b.ci_width(), 60_000);
}

#[test]
fn backing_ci_not_spanning_zero() {
    let b = good_backing(ClaimCategory::Regression);
    assert!(!b.ci_spans_zero());
}

#[test]
fn backing_ci_spanning_zero() {
    let b = weak_backing(ClaimCategory::Regression);
    assert!(b.ci_spans_zero());
}

#[test]
fn backing_positive_effect() {
    let b = good_backing(ClaimCategory::Regression);
    assert!(b.effect_is_positive());
}

#[test]
fn backing_negative_effect() {
    let mut b = good_backing(ClaimCategory::Regression);
    b.effect_millionths = -20_000;
    assert!(!b.effect_is_positive());
}

#[test]
fn backing_serde_roundtrip() {
    let b = good_backing(ClaimCategory::Supremacy);
    let json = serde_json::to_string(&b).unwrap();
    let back: CausalBacking = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_admitted_properties() {
    let v = GateVerdict::Admitted {
        claim_id: "x".into(),
        method: IdentificationMethod::Backdoor,
        effect_millionths: 50_000,
        confidence_millionths: 900_000,
    };
    assert!(v.is_admitted());
    assert!(!v.is_rejected());
    assert_eq!(v.claim_id(), "x");
    assert_eq!(v.tag(), "admitted");
}

#[test]
fn verdict_rejected_properties() {
    let v = GateVerdict::Rejected {
        claim_id: "y".into(),
        reasons: vec![RejectionReason::IdentificationAbstained],
    };
    assert!(v.is_rejected());
    assert!(!v.is_admitted());
    assert_eq!(v.tag(), "rejected");
}

#[test]
fn verdict_no_backing_properties() {
    let v = GateVerdict::NoBacking {
        claim_id: "z".into(),
    };
    assert!(!v.is_admitted());
    assert!(!v.is_rejected());
    assert_eq!(v.tag(), "no_backing");
}

#[test]
fn verdict_display_admitted() {
    let v = GateVerdict::Admitted {
        claim_id: "test".into(),
        method: IdentificationMethod::Randomized,
        effect_millionths: 100_000,
        confidence_millionths: 950_000,
    };
    assert!(v.to_string().contains("ADMITTED"));
}

#[test]
fn verdict_display_rejected() {
    let v = GateVerdict::Rejected {
        claim_id: "test".into(),
        reasons: vec![RejectionReason::IdentificationAbstained],
    };
    assert!(v.to_string().contains("REJECTED"));
}

#[test]
fn verdict_display_no_backing() {
    let v = GateVerdict::NoBacking {
        claim_id: "test".into(),
    };
    assert!(v.to_string().contains("NO_BACKING"));
}

#[test]
fn verdict_serde_admitted() {
    let v = GateVerdict::Admitted {
        claim_id: "x".into(),
        method: IdentificationMethod::FrontDoor,
        effect_millionths: 40_000,
        confidence_millionths: 850_000,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn verdict_serde_rejected() {
    let v = GateVerdict::Rejected {
        claim_id: "y".into(),
        reasons: vec![
            RejectionReason::IdentificationAbstained,
            RejectionReason::NoAdjustmentPath,
        ],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let c = GateConfig::default_config();
    assert_eq!(c.min_effect_threshold, MIN_EFFECT_THRESHOLD);
    assert_eq!(c.min_confidence, MIN_IDENTIFICATION_CONFIDENCE);
    assert!(c.strict_category_match);
    assert_eq!(c.category_min_strength.len(), 5);
}

#[test]
fn config_default_trait_matches() {
    assert_eq!(GateConfig::default(), GateConfig::default_config());
}

#[test]
fn config_permissive() {
    let c = GateConfig::permissive();
    assert_eq!(c.min_effect_threshold, 0);
    assert_eq!(c.min_confidence, 0);
    assert!(!c.strict_category_match);
    assert!(c.category_min_strength.is_empty());
}

#[test]
fn config_serde_roundtrip() {
    let c = GateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn config_permissive_serde_roundtrip() {
    let c = GateConfig::permissive();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// EvidenceGate — basic evaluation
// ---------------------------------------------------------------------------

#[test]
fn gate_admits_good_regression_evidence() {
    let gate = EvidenceGate::with_defaults();
    let v = gate.evaluate(&regression_claim(), Some(&good_backing(ClaimCategory::Regression)));
    assert!(v.is_admitted());
}

#[test]
fn gate_admits_good_supremacy_evidence() {
    let gate = EvidenceGate::with_defaults();
    let v = gate.evaluate(&supremacy_claim(), Some(&strong_backing(ClaimCategory::Supremacy)));
    assert!(v.is_admitted());
}

#[test]
fn gate_admits_good_transfer_evidence() {
    let gate = EvidenceGate::with_defaults();
    let backing = CausalBacking {
        method: IdentificationMethod::FrontDoor,
        effect_millionths: 80_000,
        ci_lower_millionths: 30_000,
        ci_upper_millionths: 130_000,
        confidence_millionths: 880_000,
        adjustment_variables: BTreeSet::from(["hw".to_string()]),
        evidence_category: ClaimCategory::Transfer,
        identified: true,
        certificate_hash: ContentHash::compute(b"xfer"),
    };
    let v = gate.evaluate(&transfer_claim(), Some(&backing));
    assert!(v.is_admitted());
}

#[test]
fn gate_admits_good_rollout_evidence() {
    let gate = EvidenceGate::with_defaults();
    let v = gate.evaluate(&rollout_claim(), Some(&good_backing(ClaimCategory::Rollout)));
    assert!(v.is_admitted());
}

#[test]
fn gate_admits_good_optimization_evidence() {
    let gate = EvidenceGate::with_defaults();
    let mut backing = good_backing(ClaimCategory::Optimization);
    backing.method = IdentificationMethod::ExpertAssertion; // strength 1, ok for optimization
    let v = gate.evaluate(&optimization_claim(), Some(&backing));
    assert!(v.is_admitted());
}

#[test]
fn gate_rejects_no_backing() {
    let gate = EvidenceGate::with_defaults();
    let v = gate.evaluate(&regression_claim(), None);
    assert!(matches!(v, GateVerdict::NoBacking { .. }));
}

// ---------------------------------------------------------------------------
// EvidenceGate — rejection paths
// ---------------------------------------------------------------------------

#[test]
fn gate_rejects_unidentified() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Regression);
    b.identified = false;
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_negative_effect() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Regression);
    b.effect_millionths = -20_000;
    b.ci_lower_millionths = -40_000;
    b.ci_upper_millionths = -5_000;
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_zero_effect() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Regression);
    b.effect_millionths = 0;
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_below_threshold_effect() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Regression);
    b.effect_millionths = 5_000; // < MIN_EFFECT_THRESHOLD (10_000)
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_ci_spans_zero() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Regression);
    b.ci_lower_millionths = -5_000;
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_low_confidence() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Regression);
    b.confidence_millionths = 500_000; // 50% < 80% threshold
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_category_mismatch() {
    let gate = EvidenceGate::with_defaults();
    let b = good_backing(ClaimCategory::Transfer); // evidence = Transfer
    let v = gate.evaluate(&regression_claim(), Some(&b)); // claim = Regression
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_no_adjustment_path() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Regression);
    b.adjustment_variables.clear();
    b.method = IdentificationMethod::DifferenceInDifferences;
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_rejected());
}

#[test]
fn gate_rejects_weak_evidence_for_supremacy() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Supremacy);
    b.method = IdentificationMethod::DifferenceInDifferences; // strength 2 < 3 required
    let v = gate.evaluate(&supremacy_claim(), Some(&b));
    assert!(v.is_rejected());
}

// ---------------------------------------------------------------------------
// EvidenceGate — special method handling
// ---------------------------------------------------------------------------

#[test]
fn gate_randomized_no_adjustment_ok() {
    let gate = EvidenceGate::with_defaults();
    let b = strong_backing(ClaimCategory::Regression); // Randomized, no adj vars
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_admitted());
}

#[test]
fn gate_instrumental_no_adjustment_ok() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Regression);
    b.method = IdentificationMethod::InstrumentalVariable;
    b.adjustment_variables.clear();
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_admitted());
}

// ---------------------------------------------------------------------------
// EvidenceGate — permissive config
// ---------------------------------------------------------------------------

#[test]
fn permissive_admits_mismatched_category() {
    let gate = EvidenceGate::with_config(GateConfig::permissive());
    let b = good_backing(ClaimCategory::Optimization);
    // Permissive: no category match requirement, but we need adjustment path for non-randomized
    let v = gate.evaluate(&supremacy_claim(), Some(&b));
    assert!(v.is_admitted());
}

#[test]
fn permissive_admits_low_confidence() {
    let gate = EvidenceGate::with_config(GateConfig::permissive());
    let mut b = good_backing(ClaimCategory::Regression);
    b.confidence_millionths = 100_000;
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_admitted());
}

// ---------------------------------------------------------------------------
// EvidenceGate — batch evaluation
// ---------------------------------------------------------------------------

#[test]
fn batch_empty() {
    let gate = EvidenceGate::with_defaults();
    let results = gate.evaluate_batch(&[], &BTreeMap::new());
    assert!(results.is_empty());
}

#[test]
fn batch_all_admitted() {
    let gate = EvidenceGate::with_defaults();
    let claims = vec![regression_claim(), rollout_claim()];
    let mut backings = BTreeMap::new();
    backings.insert("reg-1".to_string(), good_backing(ClaimCategory::Regression));
    backings.insert("roll-1".to_string(), good_backing(ClaimCategory::Rollout));
    let results = gate.evaluate_batch(&claims, &backings);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|v| v.is_admitted()));
}

#[test]
fn batch_mixed_results() {
    let gate = EvidenceGate::with_defaults();
    let claims = vec![regression_claim(), supremacy_claim(), transfer_claim()];
    let mut backings = BTreeMap::new();
    backings.insert("reg-1".to_string(), good_backing(ClaimCategory::Regression));
    // sup-1 has no backing
    backings.insert("xfer-1".to_string(), weak_backing(ClaimCategory::Transfer)); // will be rejected
    let results = gate.evaluate_batch(&claims, &backings);
    assert_eq!(results.len(), 3);
    assert!(results[0].is_admitted());
    assert!(matches!(results[1], GateVerdict::NoBacking { .. }));
    assert!(results[2].is_rejected());
}

#[test]
fn batch_preserves_order() {
    let gate = EvidenceGate::with_defaults();
    let claims = vec![
        regression_claim(),
        supremacy_claim(),
        optimization_claim(),
    ];
    let results = gate.evaluate_batch(&claims, &BTreeMap::new());
    assert_eq!(results[0].claim_id(), "reg-1");
    assert_eq!(results[1].claim_id(), "sup-1");
    assert_eq!(results[2].claim_id(), "opt-1");
}

// ---------------------------------------------------------------------------
// GateReport
// ---------------------------------------------------------------------------

#[test]
fn report_empty() {
    let r = GateReport::new(epoch(), Vec::new());
    assert_eq!(r.total_count(), 0);
    assert_eq!(r.admission_rate(), 0);
    assert!(!r.all_admitted());
    assert!(!r.has_rejections());
}

#[test]
fn report_schema_version() {
    let r = GateReport::new(epoch(), Vec::new());
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

#[test]
fn report_epoch_preserved() {
    let e = SecurityEpoch::from_raw(999);
    let r = GateReport::new(e, Vec::new());
    assert_eq!(r.epoch, e);
}

#[test]
fn report_all_admitted() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "a".into(),
            method: IdentificationMethod::Randomized,
            effect_millionths: 50_000,
            confidence_millionths: 900_000,
        },
        GateVerdict::Admitted {
            claim_id: "b".into(),
            method: IdentificationMethod::Backdoor,
            effect_millionths: 30_000,
            confidence_millionths: 850_000,
        },
    ];
    let r = GateReport::new(epoch(), verdicts);
    assert!(r.all_admitted());
    assert!(!r.has_rejections());
    assert_eq!(r.admission_rate(), 1_000_000);
    assert_eq!(r.admitted_count, 2);
}

#[test]
fn report_mixed_verdicts() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "a".into(),
            method: IdentificationMethod::Randomized,
            effect_millionths: 50_000,
            confidence_millionths: 900_000,
        },
        GateVerdict::Rejected {
            claim_id: "b".into(),
            reasons: vec![RejectionReason::IdentificationAbstained],
        },
        GateVerdict::NoBacking {
            claim_id: "c".into(),
        },
    ];
    let r = GateReport::new(epoch(), verdicts);
    assert_eq!(r.total_count(), 3);
    assert_eq!(r.admitted_count, 1);
    assert_eq!(r.rejected_count, 1);
    assert_eq!(r.no_backing_count, 1);
    assert!(!r.all_admitted());
    assert!(r.has_rejections());
}

#[test]
fn report_admission_rate_half() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "a".into(),
            method: IdentificationMethod::Randomized,
            effect_millionths: 50_000,
            confidence_millionths: 900_000,
        },
        GateVerdict::Rejected {
            claim_id: "b".into(),
            reasons: vec![RejectionReason::IdentificationAbstained],
        },
    ];
    let r = GateReport::new(epoch(), verdicts);
    assert_eq!(r.admission_rate(), 500_000);
}

#[test]
fn report_hash_deterministic() {
    let verdicts = vec![GateVerdict::Admitted {
        claim_id: "a".into(),
        method: IdentificationMethod::Randomized,
        effect_millionths: 50_000,
        confidence_millionths: 900_000,
    }];
    let r1 = GateReport::new(epoch(), verdicts.clone());
    let r2 = GateReport::new(epoch(), verdicts);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_different_epoch_different_hash() {
    let verdicts = vec![GateVerdict::Admitted {
        claim_id: "a".into(),
        method: IdentificationMethod::Randomized,
        effect_millionths: 50_000,
        confidence_millionths: 900_000,
    }];
    let r1 = GateReport::new(SecurityEpoch::from_raw(100), verdicts.clone());
    let r2 = GateReport::new(SecurityEpoch::from_raw(200), verdicts);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn report_serde_roundtrip() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "a".into(),
            method: IdentificationMethod::Randomized,
            effect_millionths: 50_000,
            confidence_millionths: 900_000,
        },
        GateVerdict::Rejected {
            claim_id: "b".into(),
            reasons: vec![
                RejectionReason::IdentificationAbstained,
                RejectionReason::NoAdjustmentPath,
            ],
        },
        GateVerdict::NoBacking {
            claim_id: "c".into(),
        },
    ];
    let r = GateReport::new(epoch(), verdicts);
    let json = serde_json::to_string(&r).unwrap();
    let back: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// End-to-end workflow
// ---------------------------------------------------------------------------

#[test]
fn full_gate_evaluation_workflow() {
    let gate = EvidenceGate::with_defaults();

    // Build claims
    let claims = vec![
        regression_claim(),
        supremacy_claim(),
        transfer_claim(),
        rollout_claim(),
        optimization_claim(),
    ];

    // Build backings
    let mut backings = BTreeMap::new();
    backings.insert("reg-1".to_string(), good_backing(ClaimCategory::Regression));
    backings.insert(
        "sup-1".to_string(),
        strong_backing(ClaimCategory::Supremacy),
    );
    // xfer-1 has weak backing (will fail)
    backings.insert("xfer-1".to_string(), weak_backing(ClaimCategory::Transfer));
    backings.insert("roll-1".to_string(), good_backing(ClaimCategory::Rollout));
    // opt-1 has no backing

    let verdicts = gate.evaluate_batch(&claims, &backings);
    let report = GateReport::new(epoch(), verdicts);

    assert_eq!(report.total_count(), 5);
    assert_eq!(report.admitted_count, 3); // reg, sup, roll
    assert_eq!(report.rejected_count, 1); // xfer (weak)
    assert_eq!(report.no_backing_count, 1); // opt
    assert!(report.has_rejections());
    assert!(!report.all_admitted());
}

#[test]
fn gate_serde_roundtrip() {
    let gate = EvidenceGate::with_defaults();
    let json = serde_json::to_string(&gate).unwrap();
    let back: EvidenceGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, back);
}

#[test]
fn gate_custom_config_serde() {
    let gate = EvidenceGate::with_config(GateConfig::permissive());
    let json = serde_json::to_string(&gate).unwrap();
    let back: EvidenceGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, back);
}
