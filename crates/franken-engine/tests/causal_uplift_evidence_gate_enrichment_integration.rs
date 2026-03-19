//! Enrichment integration tests for `causal_uplift_evidence_gate` module.
//!
//! Deep coverage of serde roundtrips, Display distinctness, deterministic hashing,
//! rejection path coverage, gate configuration, and batch processing.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::causal_uplift_evidence_gate::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(900)
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
        certificate_hash: ContentHash::compute(b"enrich-cert"),
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
        certificate_hash: ContentHash::compute(b"strong-enrich"),
    }
}

fn regression_claim() -> UpliftClaim {
    UpliftClaim {
        claim_id: "reg-e1".into(),
        category: ClaimCategory::Regression,
        description: "10% latency regression".into(),
        claimed_effect_millionths: 100_000,
        surface: "latency-p99".into(),
        min_evidence_strength: 2,
    }
}

fn supremacy_claim() -> UpliftClaim {
    UpliftClaim {
        claim_id: "sup-e1".into(),
        category: ClaimCategory::Supremacy,
        description: "throughput dominance".into(),
        claimed_effect_millionths: 200_000,
        surface: "throughput".into(),
        min_evidence_strength: 3,
    }
}

fn optimization_claim() -> UpliftClaim {
    UpliftClaim {
        claim_id: "opt-e1".into(),
        category: ClaimCategory::Optimization,
        description: "loop unrolling gain".into(),
        claimed_effect_millionths: 50_000,
        surface: "throughput".into(),
        min_evidence_strength: 1,
    }
}

// ---------------------------------------------------------------------------
// ClaimCategory — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_category_display_distinct() {
    let displays: BTreeSet<String> = ClaimCategory::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), ClaimCategory::ALL.len());
}

#[test]
fn enrich_category_ord_consistent() {
    assert!(ClaimCategory::Regression < ClaimCategory::Transfer);
    assert!(ClaimCategory::Transfer < ClaimCategory::Supremacy);
}

#[test]
fn enrich_category_clone_eq() {
    for c in ClaimCategory::ALL {
        let cloned = *c;
        assert_eq!(*c, cloned);
    }
}

// ---------------------------------------------------------------------------
// IdentificationMethod — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_method_display_distinct() {
    let displays: BTreeSet<String> =
        IdentificationMethod::ALL.iter().map(|m| m.to_string()).collect();
    assert_eq!(displays.len(), IdentificationMethod::ALL.len());
}

#[test]
fn enrich_method_strength_monotonic() {
    // Randomized should be strictly strongest
    assert_eq!(IdentificationMethod::Randomized.strength_rank(), 5);
    assert_eq!(IdentificationMethod::ExpertAssertion.strength_rank(), 1);
}

#[test]
fn enrich_method_backdoor_and_frontdoor_equal_strength() {
    assert_eq!(
        IdentificationMethod::Backdoor.strength_rank(),
        IdentificationMethod::FrontDoor.strength_rank()
    );
}

#[test]
fn enrich_method_serde_snake_case() {
    let json = serde_json::to_string(&IdentificationMethod::DifferenceInDifferences).unwrap();
    assert_eq!(json, "\"difference_in_differences\"");
}

// ---------------------------------------------------------------------------
// RejectionReason — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_rejection_display_identification_abstained() {
    let r = RejectionReason::IdentificationAbstained;
    assert!(r.to_string().contains("abstained"));
}

#[test]
fn enrich_rejection_display_no_adjustment_path() {
    let r = RejectionReason::NoAdjustmentPath;
    assert!(r.to_string().contains("adjustment"));
}

#[test]
fn enrich_rejection_display_category_mismatch() {
    let r = RejectionReason::CategoryMismatch {
        claim: ClaimCategory::Regression,
        evidence: ClaimCategory::Transfer,
    };
    let s = r.to_string();
    assert!(s.contains("regression"));
    assert!(s.contains("transfer"));
}

#[test]
fn enrich_rejection_display_weak_evidence() {
    let r = RejectionReason::WeakEvidence {
        method: IdentificationMethod::ExpertAssertion,
        min_strength: 3,
    };
    let s = r.to_string();
    assert!(s.contains("expert_assertion"));
    assert!(s.contains("3"));
}

#[test]
fn enrich_rejection_display_interval_too_wide() {
    let r = RejectionReason::IntervalTooWide {
        width_millionths: 200_000,
        effect_millionths: 50_000,
    };
    let s = r.to_string();
    assert!(s.contains("200000"));
    assert!(s.contains("50000"));
}

#[test]
fn enrich_rejection_display_effect_below_threshold() {
    let r = RejectionReason::EffectBelowThreshold {
        effect_millionths: 5_000,
        threshold_millionths: 10_000,
    };
    let s = r.to_string();
    assert!(s.contains("5000"));
    assert!(s.contains("10000"));
}

#[test]
fn enrich_rejection_tag_no_duplicates() {
    let reasons = vec![
        RejectionReason::IdentificationAbstained,
        RejectionReason::EffectBelowThreshold { effect_millionths: 0, threshold_millionths: 0 },
        RejectionReason::IntervalSpansZero { lower_millionths: 0, upper_millionths: 0 },
        RejectionReason::IntervalTooWide { width_millionths: 0, effect_millionths: 0 },
        RejectionReason::LowConfidence { confidence_millionths: 0, threshold_millionths: 0 },
        RejectionReason::CategoryMismatch { claim: ClaimCategory::Regression, evidence: ClaimCategory::Transfer },
        RejectionReason::NoAdjustmentPath,
        RejectionReason::WeakEvidence { method: IdentificationMethod::ExpertAssertion, min_strength: 1 },
    ];
    let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
    assert_eq!(tags.len(), 8);
}

// ---------------------------------------------------------------------------
// CausalBacking — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_backing_ci_width_exact() {
    let mut b = good_backing(ClaimCategory::Regression);
    b.ci_lower_millionths = 10_000;
    b.ci_upper_millionths = 90_000;
    assert_eq!(b.ci_width(), 80_000);
}

#[test]
fn enrich_backing_ci_spans_zero_exact_boundary() {
    let mut b = good_backing(ClaimCategory::Regression);
    b.ci_lower_millionths = 0;
    b.ci_upper_millionths = 100_000;
    // Lower == 0 means it does span zero
    assert!(b.ci_spans_zero());
}

#[test]
fn enrich_backing_effect_zero_not_positive() {
    let mut b = good_backing(ClaimCategory::Regression);
    b.effect_millionths = 0;
    assert!(!b.effect_is_positive());
}

#[test]
fn enrich_backing_serde_preserves_all_fields() {
    let b = CausalBacking {
        method: IdentificationMethod::InstrumentalVariable,
        effect_millionths: 75_000,
        ci_lower_millionths: 30_000,
        ci_upper_millionths: 120_000,
        confidence_millionths: 870_000,
        adjustment_variables: BTreeSet::from(["hw".to_string(), "load".to_string()]),
        evidence_category: ClaimCategory::Transfer,
        identified: true,
        certificate_hash: ContentHash::compute(b"iv-cert"),
    };
    let json = serde_json::to_string(&b).unwrap();
    let back: CausalBacking = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
    assert_eq!(back.adjustment_variables.len(), 2);
}

// ---------------------------------------------------------------------------
// UpliftClaim — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_uplift_claim_serde_roundtrip() {
    let c = regression_claim();
    let json = serde_json::to_string(&c).unwrap();
    let back: UpliftClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrich_uplift_claim_debug_contains_id() {
    let c = supremacy_claim();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("sup-e1"));
}

// ---------------------------------------------------------------------------
// GateVerdict — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_verdict_admitted_display_contains_method() {
    let v = GateVerdict::Admitted {
        claim_id: "x".into(),
        method: IdentificationMethod::FrontDoor,
        effect_millionths: 40_000,
        confidence_millionths: 850_000,
    };
    let s = v.to_string();
    assert!(s.contains("front_door"));
}

#[test]
fn enrich_verdict_rejected_display_reason_count() {
    let v = GateVerdict::Rejected {
        claim_id: "y".into(),
        reasons: vec![
            RejectionReason::IdentificationAbstained,
            RejectionReason::NoAdjustmentPath,
            RejectionReason::LowConfidence {
                confidence_millionths: 100,
                threshold_millionths: 800_000,
            },
        ],
    };
    let s = v.to_string();
    assert!(s.contains("3 reason(s)"));
}

#[test]
fn enrich_verdict_serde_no_backing() {
    let v = GateVerdict::NoBacking { claim_id: "z".into() };
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
    assert_eq!(back.claim_id(), "z");
}

// ---------------------------------------------------------------------------
// GateConfig — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_config_default_has_all_categories() {
    let c = GateConfig::default_config();
    assert_eq!(c.category_min_strength.len(), 5);
    for cat in ClaimCategory::ALL {
        assert!(c.category_min_strength.contains_key(cat));
    }
}

#[test]
fn enrich_config_permissive_has_no_strength_requirements() {
    let c = GateConfig::permissive();
    assert!(c.category_min_strength.is_empty());
    assert_eq!(c.min_effect_threshold, 0);
    assert_eq!(c.min_confidence, 0);
    assert_eq!(c.max_relative_ci_width, u64::MAX);
}

#[test]
fn enrich_config_debug_format() {
    let c = GateConfig::default();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("min_effect_threshold"));
}

// ---------------------------------------------------------------------------
// EvidenceGate — enrichment evaluation
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_admits_instrumental_no_adjustment() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Regression);
    b.method = IdentificationMethod::InstrumentalVariable;
    b.adjustment_variables.clear();
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_admitted());
}

#[test]
fn enrich_gate_rejects_expert_for_supremacy() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Supremacy);
    b.method = IdentificationMethod::ExpertAssertion; // strength 1 < 3 required
    let v = gate.evaluate(&supremacy_claim(), Some(&b));
    assert!(v.is_rejected());
}

#[test]
fn enrich_gate_admits_expert_for_optimization() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Optimization);
    b.method = IdentificationMethod::ExpertAssertion; // strength 1 >= 1 required
    let v = gate.evaluate(&optimization_claim(), Some(&b));
    assert!(v.is_admitted());
}

#[test]
fn enrich_gate_rejects_multiple_reasons() {
    let gate = EvidenceGate::with_defaults();
    let mut b = good_backing(ClaimCategory::Regression);
    b.identified = false;
    b.effect_millionths = -5_000;
    b.ci_lower_millionths = -20_000;
    b.ci_upper_millionths = 10_000;
    b.confidence_millionths = 100_000;
    b.adjustment_variables.clear();
    b.method = IdentificationMethod::ExpertAssertion;
    let v = gate.evaluate(&regression_claim(), Some(&b));
    match v {
        GateVerdict::Rejected { reasons, .. } => {
            assert!(reasons.len() >= 3, "expected multiple rejection reasons, got {}", reasons.len());
        }
        _ => panic!("expected Rejected verdict"),
    }
}

#[test]
fn enrich_gate_permissive_admits_low_effect() {
    let gate = EvidenceGate::with_config(GateConfig::permissive());
    let mut b = good_backing(ClaimCategory::Regression);
    b.effect_millionths = 1; // very low but permissive threshold is 0
    let v = gate.evaluate(&regression_claim(), Some(&b));
    assert!(v.is_admitted());
}

// ---------------------------------------------------------------------------
// EvidenceGate — batch enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_batch_preserves_order() {
    let gate = EvidenceGate::with_defaults();
    let claims = vec![regression_claim(), supremacy_claim(), optimization_claim()];
    let results = gate.evaluate_batch(&claims, &BTreeMap::new());
    assert_eq!(results[0].claim_id(), "reg-e1");
    assert_eq!(results[1].claim_id(), "sup-e1");
    assert_eq!(results[2].claim_id(), "opt-e1");
}

#[test]
fn enrich_batch_all_no_backing() {
    let gate = EvidenceGate::with_defaults();
    let claims = vec![regression_claim(), supremacy_claim()];
    let results = gate.evaluate_batch(&claims, &BTreeMap::new());
    assert!(results.iter().all(|v| matches!(v, GateVerdict::NoBacking { .. })));
}

#[test]
fn enrich_batch_mixed_results() {
    let gate = EvidenceGate::with_defaults();
    let claims = vec![regression_claim(), supremacy_claim()];
    let mut backings = BTreeMap::new();
    backings.insert("reg-e1".to_string(), good_backing(ClaimCategory::Regression));
    // sup-e1 has no backing
    let results = gate.evaluate_batch(&claims, &backings);
    assert!(results[0].is_admitted());
    assert!(matches!(results[1], GateVerdict::NoBacking { .. }));
}

// ---------------------------------------------------------------------------
// GateReport — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_report_all_no_backing_not_admitted() {
    let verdicts = vec![
        GateVerdict::NoBacking { claim_id: "a".into() },
        GateVerdict::NoBacking { claim_id: "b".into() },
    ];
    let r = GateReport::new(epoch(), verdicts);
    assert_eq!(r.total_count(), 2);
    assert_eq!(r.no_backing_count, 2);
    assert_eq!(r.admitted_count, 0);
    assert!(!r.all_admitted());
    assert!(!r.has_rejections());
}

#[test]
fn enrich_report_single_admitted() {
    let verdicts = vec![GateVerdict::Admitted {
        claim_id: "x".into(),
        method: IdentificationMethod::Randomized,
        effect_millionths: 100_000,
        confidence_millionths: 950_000,
    }];
    let r = GateReport::new(epoch(), verdicts);
    assert!(r.all_admitted());
    assert_eq!(r.admission_rate(), 1_000_000);
}

#[test]
fn enrich_report_hash_changes_with_different_verdicts() {
    let v1 = vec![GateVerdict::Admitted {
        claim_id: "a".into(),
        method: IdentificationMethod::Randomized,
        effect_millionths: 100_000,
        confidence_millionths: 950_000,
    }];
    let v2 = vec![GateVerdict::Rejected {
        claim_id: "a".into(),
        reasons: vec![RejectionReason::IdentificationAbstained],
    }];
    let r1 = GateReport::new(epoch(), v1);
    let r2 = GateReport::new(epoch(), v2);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrich_report_serde_preserves_counts() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "a".into(),
            method: IdentificationMethod::Backdoor,
            effect_millionths: 50_000,
            confidence_millionths: 900_000,
        },
        GateVerdict::Rejected {
            claim_id: "b".into(),
            reasons: vec![RejectionReason::IdentificationAbstained],
        },
        GateVerdict::NoBacking { claim_id: "c".into() },
    ];
    let r = GateReport::new(epoch(), verdicts);
    let json = serde_json::to_string(&r).unwrap();
    let back: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.admitted_count, 1);
    assert_eq!(back.rejected_count, 1);
    assert_eq!(back.no_backing_count, 1);
    assert_eq!(back.total_count(), 3);
}

// ---------------------------------------------------------------------------
// EvidenceGate — serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_gate_serde_roundtrip() {
    let gate = EvidenceGate::with_defaults();
    let json = serde_json::to_string(&gate).unwrap();
    let back: EvidenceGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, back);
}

#[test]
fn enrich_gate_permissive_serde_roundtrip() {
    let gate = EvidenceGate::with_config(GateConfig::permissive());
    let json = serde_json::to_string(&gate).unwrap();
    let back: EvidenceGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, back);
}

// ---------------------------------------------------------------------------
// Constants — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_min_effect_threshold_positive() {
    assert!(MIN_EFFECT_THRESHOLD > 0);
}

#[test]
fn enrich_min_confidence_in_range() {
    assert!(MIN_IDENTIFICATION_CONFIDENCE > 0);
    assert!(MIN_IDENTIFICATION_CONFIDENCE <= 1_000_000);
}

#[test]
fn enrich_max_relative_ci_width_positive() {
    assert!(MAX_RELATIVE_CI_WIDTH > 0);
}

#[test]
fn enrich_default_max_batch_size_positive() {
    assert!(DEFAULT_MAX_BATCH_SIZE > 0);
}
