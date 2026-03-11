//! Integration tests for the `controller_composition_stability_gate` module.
//!
//! Validates constants, enums (ClaimCategory, SignalSeverity), evidence types,
//! gate evaluation logic, batch processing, report aggregation, serde contracts,
//! and end-to-end scenarios with realistic evidence chains.

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

use frankenengine_engine::controller_composition_stability_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::timescale_separation_certificate::{
    CertificateBundle, ControllerPairId, ControllerTimescaleProfile, RatioBasis, SeparationVerdict,
    StabilityAssessment, TimescaleRatio, TimescaleSeparationCertificate,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_pair(fast: &str, slow: &str) -> ControllerPairId {
    ControllerPairId {
        fast_controller: fast.to_string(),
        slow_controller: slow.to_string(),
    }
}

fn make_profile(id: &str) -> ControllerTimescaleProfile {
    ControllerTimescaleProfile {
        controller_id: id.to_string(),
        observation_interval_millionths: 1_000_000,
        write_interval_millionths: 2_000_000,
        sample_count: 100,
        measured_epoch: 42,
    }
}

fn make_cert(fast: &str, slow: &str, verdict: SeparationVerdict) -> TimescaleSeparationCertificate {
    TimescaleSeparationCertificate {
        schema_version: "test-v1".to_string(),
        bead_id: "test-bead".to_string(),
        certificate_id: format!("{fast}-{slow}"),
        pair: make_pair(fast, slow),
        ratio: TimescaleRatio {
            pair: make_pair(fast, slow),
            ratio_millionths: 10_000_000,
            ratio_basis: RatioBasis::Observation,
        },
        verdict,
        sufficient_threshold_millionths: 10_000_000,
        marginal_threshold_millionths: 3_000_000,
        fast_profile: make_profile(fast),
        slow_profile: make_profile(slow),
        issued_epoch: 42,
        evidence_ids: vec!["ev-1".to_string()],
    }
}

fn make_bundle(certs: Vec<TimescaleSeparationCertificate>) -> CertificateBundle {
    let sufficient_count = certs
        .iter()
        .filter(|c| c.verdict == SeparationVerdict::Sufficient)
        .count();
    let marginal_count = certs
        .iter()
        .filter(|c| c.verdict == SeparationVerdict::Marginal)
        .count();
    let insufficient_count = certs
        .iter()
        .filter(|c| c.verdict == SeparationVerdict::Insufficient)
        .count();
    let overall_verdict = if insufficient_count > 0 {
        SeparationVerdict::Insufficient
    } else if marginal_count > 0 {
        SeparationVerdict::Marginal
    } else {
        SeparationVerdict::Sufficient
    };
    CertificateBundle {
        schema_version: "test-v1".to_string(),
        bead_id: "test-bead".to_string(),
        certificates: certs,
        overall_verdict,
        bundle_epoch: 42,
        pair_count: sufficient_count + marginal_count + insufficient_count,
        sufficient_count,
        marginal_count,
        insufficient_count,
    }
}

fn make_signal(id: &str, severity: SignalSeverity) -> InstabilitySignal {
    InstabilitySignal {
        signal_id: id.to_string(),
        controller_ids: vec!["ctrl-a".to_string(), "ctrl-b".to_string()],
        severity,
        description: format!("test signal {id}"),
        risk_score_millionths: 500_000,
    }
}

fn make_claim(id: &str, category: ClaimCategory, comp: &str) -> StabilityClaim {
    StabilityClaim {
        claim_id: id.to_string(),
        category,
        composition_id: comp.to_string(),
        description: format!("test claim {id}"),
    }
}

fn make_evidence(comp_id: &str) -> CompositionEvidence {
    CompositionEvidence {
        composition_id: comp_id.to_string(),
        controller_count: 3,
        separation_bundle: None,
        stability_assessment: Some(StabilityAssessment::Stable),
        signals: Vec::new(),
        confidence_millionths: 950_000,
        evidence_epoch: 42,
    }
}

fn stable_evidence_with_bundle(comp_id: &str) -> CompositionEvidence {
    let mut ev = make_evidence(comp_id);
    ev.separation_bundle = Some(make_bundle(vec![
        make_cert("ctrl-a", "ctrl-b", SeparationVerdict::Sufficient),
        make_cert("ctrl-a", "ctrl-c", SeparationVerdict::Sufficient),
        make_cert("ctrl-b", "ctrl-c", SeparationVerdict::Sufficient),
    ]));
    ev
}

// ===========================================================================
// Constants validation
// ===========================================================================

#[test]
fn constants_schema_version_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("controller-composition-stability-gate"));
}

#[test]
fn constants_component_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert_eq!(COMPONENT, "controller_composition_stability_gate");
}

#[test]
fn constants_bead_id_non_empty() {
    assert!(!BEAD_ID.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn constants_policy_id_non_empty() {
    assert!(!POLICY_ID.is_empty());
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn constants_default_thresholds_valid() {
    const {
        assert!(DEFAULT_MIN_CONFIDENCE_MILLIONTHS > 0);
        assert!(DEFAULT_MIN_CONFIDENCE_MILLIONTHS <= 1_000_000);
    }
    assert_eq!(DEFAULT_MAX_CRITICAL_SIGNALS, 0);
    const { assert!(DEFAULT_MAX_WARNING_SIGNALS > 0) };
    const { assert!(DEFAULT_MAX_MARGINAL_PAIRS >= 1) };
    assert_eq!(DEFAULT_MAX_INSUFFICIENT_PAIRS, 0);
    const { assert!(DEFAULT_MIN_SEPARATION_RATIO_MILLIONTHS > 0) };
}

// ===========================================================================
// ClaimCategory enum
// ===========================================================================

#[test]
fn claim_category_all_variants_count() {
    assert_eq!(ClaimCategory::ALL.len(), 5);
}

#[test]
fn claim_category_display_all_variants() {
    let expected = [
        (ClaimCategory::AdaptivePerformance, "adaptive_performance"),
        (ClaimCategory::Supremacy, "supremacy"),
        (ClaimCategory::Rollout, "rollout"),
        (ClaimCategory::Regression, "regression"),
        (ClaimCategory::Documentation, "documentation"),
    ];
    for (cat, label) in &expected {
        assert_eq!(format!("{cat}"), *label);
        assert_eq!(cat.tag(), *label);
    }
}

#[test]
fn claim_category_tags_unique() {
    let tags: Vec<&str> = ClaimCategory::ALL.iter().map(|c| c.tag()).collect();
    for (i, a) in tags.iter().enumerate() {
        for b in &tags[i + 1..] {
            assert_ne!(a, b, "duplicate tag found");
        }
    }
}

#[test]
fn claim_category_serde_roundtrip() {
    for cat in ClaimCategory::ALL {
        let json = serde_json::to_string(cat).unwrap();
        let back: ClaimCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

#[test]
fn claim_category_serde_snake_case() {
    let json = serde_json::to_string(&ClaimCategory::AdaptivePerformance).unwrap();
    assert_eq!(json, "\"adaptive_performance\"");
}

// ===========================================================================
// SignalSeverity enum
// ===========================================================================

#[test]
fn signal_severity_display() {
    assert_eq!(format!("{}", SignalSeverity::Info), "info");
    assert_eq!(format!("{}", SignalSeverity::Warning), "warning");
    assert_eq!(format!("{}", SignalSeverity::Critical), "critical");
}

#[test]
fn signal_severity_serde_roundtrip() {
    for sev in [
        SignalSeverity::Info,
        SignalSeverity::Warning,
        SignalSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: SignalSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

// ===========================================================================
// InstabilitySignal
// ===========================================================================

#[test]
fn instability_signal_display_contains_severity_and_id() {
    let s = make_signal("sig-42", SignalSeverity::Warning);
    let d = format!("{s}");
    assert!(d.contains("warning"), "display should contain severity");
    assert!(d.contains("sig-42"), "display should contain signal_id");
    assert!(
        d.contains("test signal sig-42"),
        "display should contain description"
    );
}

#[test]
fn instability_signal_serde_roundtrip() {
    let s = make_signal("sig-1", SignalSeverity::Critical);
    let json = serde_json::to_string(&s).unwrap();
    let back: InstabilitySignal = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ===========================================================================
// CompositionEvidence
// ===========================================================================

#[test]
fn evidence_signal_counts_empty() {
    let ev = make_evidence("comp-1");
    assert_eq!(ev.signal_counts(), (0, 0, 0));
}

#[test]
fn evidence_signal_counts_mixed() {
    let mut ev = make_evidence("comp-1");
    ev.signals = vec![
        make_signal("i1", SignalSeverity::Info),
        make_signal("w1", SignalSeverity::Warning),
        make_signal("w2", SignalSeverity::Warning),
        make_signal("c1", SignalSeverity::Critical),
        make_signal("i2", SignalSeverity::Info),
    ];
    let (info, warning, critical) = ev.signal_counts();
    assert_eq!(info, 2);
    assert_eq!(warning, 2);
    assert_eq!(critical, 1);
}

#[test]
fn evidence_separation_counts_no_bundle() {
    let ev = make_evidence("comp-1");
    assert_eq!(ev.separation_counts(), (0, 0, 0));
}

#[test]
fn evidence_separation_counts_mixed() {
    let mut ev = make_evidence("comp-1");
    ev.separation_bundle = Some(make_bundle(vec![
        make_cert("a", "b", SeparationVerdict::Sufficient),
        make_cert("a", "c", SeparationVerdict::Marginal),
        make_cert("b", "c", SeparationVerdict::Insufficient),
    ]));
    let (suf, mar, ins) = ev.separation_counts();
    assert_eq!(suf, 1);
    assert_eq!(mar, 1);
    assert_eq!(ins, 1);
}

#[test]
fn evidence_content_hash_deterministic() {
    let a = make_evidence("comp-1");
    let b = make_evidence("comp-1");
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn evidence_content_hash_differs_on_comp_id() {
    let a = make_evidence("comp-1");
    let b = make_evidence("comp-2");
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn evidence_content_hash_differs_on_confidence() {
    let mut a = make_evidence("comp-1");
    let mut b = make_evidence("comp-1");
    a.confidence_millionths = 900_000;
    b.confidence_millionths = 800_000;
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn evidence_serde_roundtrip() {
    let ev = stable_evidence_with_bundle("comp-1");
    let json = serde_json::to_string(&ev).unwrap();
    let back: CompositionEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ===========================================================================
// StabilityClaim
// ===========================================================================

#[test]
fn stability_claim_display() {
    let c = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let d = format!("{c}");
    assert!(d.contains("supremacy"));
    assert!(d.contains("cl-1"));
}

#[test]
fn stability_claim_serde_roundtrip() {
    let c = make_claim("cl-99", ClaimCategory::Rollout, "comp-2");
    let json = serde_json::to_string(&c).unwrap();
    let back: StabilityClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// RejectionReason
// ===========================================================================

#[test]
fn rejection_reason_no_evidence_display() {
    let r = RejectionReason::NoEvidence;
    assert_eq!(format!("{r}"), "no composition evidence provided");
}

#[test]
fn rejection_reason_insufficient_separation_display() {
    let r = RejectionReason::InsufficientSeparation {
        insufficient_pairs: 3,
        max_allowed: 0,
    };
    let d = format!("{r}");
    assert!(d.contains("3"));
    assert!(d.contains("max 0"));
}

#[test]
fn rejection_reason_too_many_marginal_display() {
    let r = RejectionReason::TooManyMarginalPairs {
        marginal_pairs: 5,
        max_allowed: 1,
    };
    let d = format!("{r}");
    assert!(d.contains("5"));
    assert!(d.contains("marginal"));
}

#[test]
fn rejection_reason_critical_signals_display() {
    let r = RejectionReason::CriticalSignalsActive {
        count: 2,
        max_allowed: 0,
    };
    let d = format!("{r}");
    assert!(d.contains("2"));
    assert!(d.contains("critical"));
}

#[test]
fn rejection_reason_too_many_warnings_display() {
    let r = RejectionReason::TooManyWarnings {
        count: 10,
        max_allowed: 3,
    };
    let d = format!("{r}");
    assert!(d.contains("10"));
    assert!(d.contains("warning"));
}

#[test]
fn rejection_reason_assessment_too_severe_display() {
    let r = RejectionReason::AssessmentTooSevere {
        assessment: StabilityAssessment::ImmediateActionRequired,
    };
    let d = format!("{r}");
    assert!(d.contains("severe"));
}

#[test]
fn rejection_reason_insufficient_confidence_display() {
    let r = RejectionReason::InsufficientConfidence {
        confidence_millionths: 400_000,
        minimum_millionths: 850_000,
    };
    let d = format!("{r}");
    assert!(d.contains("400000"));
    assert!(d.contains("850000"));
}

#[test]
fn rejection_reason_category_not_allowed_display() {
    let r = RejectionReason::CategoryNotAllowed {
        category: ClaimCategory::Documentation,
    };
    let d = format!("{r}");
    assert!(d.contains("documentation"));
    assert!(d.contains("strict mode"));
}

#[test]
fn rejection_reason_all_variants_serde_roundtrip() {
    let reasons = vec![
        RejectionReason::NoEvidence,
        RejectionReason::InsufficientSeparation {
            insufficient_pairs: 2,
            max_allowed: 0,
        },
        RejectionReason::TooManyMarginalPairs {
            marginal_pairs: 4,
            max_allowed: 1,
        },
        RejectionReason::CriticalSignalsActive {
            count: 1,
            max_allowed: 0,
        },
        RejectionReason::TooManyWarnings {
            count: 6,
            max_allowed: 3,
        },
        RejectionReason::AssessmentTooSevere {
            assessment: StabilityAssessment::InterventionRecommended,
        },
        RejectionReason::InsufficientConfidence {
            confidence_millionths: 200_000,
            minimum_millionths: 850_000,
        },
        RejectionReason::CategoryNotAllowed {
            category: ClaimCategory::Regression,
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// GateVerdict
// ===========================================================================

#[test]
fn verdict_admitted_properties() {
    let v = GateVerdict::Admitted {
        claim_id: "c-1".to_string(),
        composition_id: "comp-1".to_string(),
        confidence_millionths: 950_000,
    };
    assert!(v.is_admitted());
    assert!(!v.is_rejected());
    assert_eq!(v.tag(), "admitted");
    assert_eq!(v.claim_id(), "c-1");
    assert_eq!(v.composition_id(), "comp-1");
}

#[test]
fn verdict_rejected_properties() {
    let v = GateVerdict::Rejected {
        claim_id: "c-2".to_string(),
        composition_id: "comp-2".to_string(),
        reasons: vec![RejectionReason::NoEvidence],
    };
    assert!(!v.is_admitted());
    assert!(v.is_rejected());
    assert_eq!(v.tag(), "rejected");
    assert_eq!(v.claim_id(), "c-2");
    assert_eq!(v.composition_id(), "comp-2");
}

#[test]
fn verdict_no_evidence_properties() {
    let v = GateVerdict::NoEvidence {
        claim_id: "c-3".to_string(),
        composition_id: "comp-3".to_string(),
    };
    assert!(!v.is_admitted());
    assert!(!v.is_rejected());
    assert_eq!(v.tag(), "no_evidence");
    assert_eq!(v.claim_id(), "c-3");
    assert_eq!(v.composition_id(), "comp-3");
}

#[test]
fn verdict_admitted_display() {
    let v = GateVerdict::Admitted {
        claim_id: "c-1".to_string(),
        composition_id: "comp-1".to_string(),
        confidence_millionths: 950_000,
    };
    let d = format!("{v}");
    assert!(d.contains("ADMITTED"));
    assert!(d.contains("c-1"));
    assert!(d.contains("950000"));
}

#[test]
fn verdict_rejected_display() {
    let v = GateVerdict::Rejected {
        claim_id: "c-2".to_string(),
        composition_id: "comp-2".to_string(),
        reasons: vec![RejectionReason::NoEvidence, RejectionReason::NoEvidence],
    };
    let d = format!("{v}");
    assert!(d.contains("REJECTED"));
    assert!(d.contains("c-2"));
    assert!(d.contains("2")); // reasons count
}

#[test]
fn verdict_no_evidence_display() {
    let v = GateVerdict::NoEvidence {
        claim_id: "c-3".to_string(),
        composition_id: "comp-3".to_string(),
    };
    let d = format!("{v}");
    assert!(d.contains("NO_EVIDENCE"));
    assert!(d.contains("c-3"));
}

#[test]
fn verdict_serde_roundtrip_all_variants() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "a".to_string(),
            composition_id: "comp".to_string(),
            confidence_millionths: 900_000,
        },
        GateVerdict::Rejected {
            claim_id: "b".to_string(),
            composition_id: "comp".to_string(),
            reasons: vec![RejectionReason::NoEvidence],
        },
        GateVerdict::NoEvidence {
            claim_id: "c".to_string(),
            composition_id: "comp".to_string(),
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// GateConfig
// ===========================================================================

#[test]
fn gate_config_default_values() {
    let c = GateConfig::default();
    assert_eq!(
        c.min_confidence_millionths,
        DEFAULT_MIN_CONFIDENCE_MILLIONTHS
    );
    assert_eq!(c.max_critical_signals, DEFAULT_MAX_CRITICAL_SIGNALS);
    assert_eq!(c.max_warning_signals, DEFAULT_MAX_WARNING_SIGNALS);
    assert_eq!(c.max_marginal_pairs, DEFAULT_MAX_MARGINAL_PAIRS);
    assert_eq!(c.max_insufficient_pairs, DEFAULT_MAX_INSUFFICIENT_PAIRS);
    assert_eq!(
        c.min_separation_ratio_millionths,
        DEFAULT_MIN_SEPARATION_RATIO_MILLIONTHS
    );
    assert!(!c.strict_category_mode);
    assert!(c.allowed_categories.is_empty());
    assert!(c.fail_closed_on_missing);
}

#[test]
fn gate_config_default_config_matches_default() {
    let a = GateConfig::default();
    let b = GateConfig::default_config();
    assert_eq!(a, b);
}

#[test]
fn gate_config_permissive_is_lenient() {
    let c = GateConfig::permissive();
    assert_eq!(c.min_confidence_millionths, 0);
    assert!(c.max_critical_signals >= 100);
    assert!(c.max_warning_signals >= 100);
    assert!(c.max_marginal_pairs >= 100);
    assert!(c.max_insufficient_pairs >= 100);
    assert_eq!(c.min_separation_ratio_millionths, 0);
    assert!(!c.strict_category_mode);
    assert!(!c.fail_closed_on_missing);
}

#[test]
fn gate_config_serde_roundtrip() {
    let c = GateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn gate_config_permissive_serde_roundtrip() {
    let c = GateConfig::permissive();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// CompositionStabilityGate — core evaluation
// ===========================================================================

#[test]
fn gate_admits_stable_composition() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let evidence = make_evidence("comp-1");
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());
    assert_eq!(verdict.claim_id(), "cl-1");
    assert_eq!(verdict.composition_id(), "comp-1");
}

#[test]
fn gate_rejects_no_evidence_fail_closed() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let verdict = gate.evaluate(&claim, None);
    assert!(verdict.is_rejected());
    if let GateVerdict::Rejected { reasons, .. } = &verdict {
        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0], RejectionReason::NoEvidence);
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn gate_returns_no_evidence_when_fail_open() {
    let config = GateConfig {
        fail_closed_on_missing: false,
        ..GateConfig::default()
    };
    let gate = CompositionStabilityGate::with_config(config);
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let verdict = gate.evaluate(&claim, None);
    assert_eq!(verdict.tag(), "no_evidence");
    assert!(!verdict.is_admitted());
    assert!(!verdict.is_rejected());
}

#[test]
fn gate_rejects_low_confidence() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.confidence_millionths = 100_000; // well below 850_000
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_rejected());
    if let GateVerdict::Rejected { reasons, .. } = &verdict {
        let has_confidence = reasons
            .iter()
            .any(|r| matches!(r, RejectionReason::InsufficientConfidence { .. }));
        assert!(has_confidence);
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn gate_rejects_critical_signals() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.signals = vec![make_signal("crit-1", SignalSeverity::Critical)];
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_rejected());
    if let GateVerdict::Rejected { reasons, .. } = &verdict {
        let has_critical = reasons
            .iter()
            .any(|r| matches!(r, RejectionReason::CriticalSignalsActive { .. }));
        assert!(has_critical);
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn gate_rejects_too_many_warnings() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    // Default max is 3, so 4 should trigger rejection.
    evidence.signals = vec![
        make_signal("w1", SignalSeverity::Warning),
        make_signal("w2", SignalSeverity::Warning),
        make_signal("w3", SignalSeverity::Warning),
        make_signal("w4", SignalSeverity::Warning),
    ];
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_rejected());
}

#[test]
fn gate_admits_within_warning_budget() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    // 2 warnings <= 3 max
    evidence.signals = vec![
        make_signal("w1", SignalSeverity::Warning),
        make_signal("w2", SignalSeverity::Warning),
    ];
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());
}

#[test]
fn gate_admits_exactly_at_warning_budget() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    // Exactly 3 warnings == 3 max (not strictly greater, so should admit).
    evidence.signals = vec![
        make_signal("w1", SignalSeverity::Warning),
        make_signal("w2", SignalSeverity::Warning),
        make_signal("w3", SignalSeverity::Warning),
    ];
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());
}

#[test]
fn gate_info_signals_dont_block() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.signals = vec![
        make_signal("i1", SignalSeverity::Info),
        make_signal("i2", SignalSeverity::Info),
        make_signal("i3", SignalSeverity::Info),
        make_signal("i4", SignalSeverity::Info),
        make_signal("i5", SignalSeverity::Info),
    ];
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());
}

#[test]
fn gate_rejects_severe_stability_assessment() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.stability_assessment = Some(StabilityAssessment::ImmediateActionRequired);
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_rejected());
}

#[test]
fn gate_rejects_intervention_recommended_assessment() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.stability_assessment = Some(StabilityAssessment::InterventionRecommended);
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_rejected());
}

#[test]
fn gate_admits_monitoring_recommended_assessment() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.stability_assessment = Some(StabilityAssessment::MonitoringRecommended);
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());
}

#[test]
fn gate_assessment_none_does_not_block() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.stability_assessment = None;
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());
}

#[test]
fn gate_rejects_insufficient_separation() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.separation_bundle = Some(make_bundle(vec![make_cert(
        "a",
        "b",
        SeparationVerdict::Insufficient,
    )]));
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_rejected());
    if let GateVerdict::Rejected { reasons, .. } = &verdict {
        let has_insuf = reasons
            .iter()
            .any(|r| matches!(r, RejectionReason::InsufficientSeparation { .. }));
        assert!(has_insuf);
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn gate_admits_sufficient_separation() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.separation_bundle = Some(make_bundle(vec![
        make_cert("a", "b", SeparationVerdict::Sufficient),
        make_cert("a", "c", SeparationVerdict::Sufficient),
    ]));
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());
}

#[test]
fn gate_rejects_too_many_marginal_pairs() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    // Default max marginal is 1, so 2 should reject.
    evidence.separation_bundle = Some(make_bundle(vec![
        make_cert("a", "b", SeparationVerdict::Marginal),
        make_cert("a", "c", SeparationVerdict::Marginal),
    ]));
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_rejected());
}

#[test]
fn gate_one_marginal_pair_allowed_by_default() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.separation_bundle = Some(make_bundle(vec![
        make_cert("a", "b", SeparationVerdict::Sufficient),
        make_cert("a", "c", SeparationVerdict::Marginal),
    ]));
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());
}

#[test]
fn gate_strict_category_rejects_unlisted() {
    let config = GateConfig {
        strict_category_mode: true,
        allowed_categories: vec![ClaimCategory::Supremacy, ClaimCategory::Rollout],
        ..GateConfig::default()
    };
    let gate = CompositionStabilityGate::with_config(config);
    let claim = make_claim("cl-1", ClaimCategory::Documentation, "comp-1");
    let evidence = make_evidence("comp-1");
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_rejected());
    if let GateVerdict::Rejected { reasons, .. } = &verdict {
        let has_cat = reasons
            .iter()
            .any(|r| matches!(r, RejectionReason::CategoryNotAllowed { .. }));
        assert!(has_cat);
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn gate_strict_category_admits_listed() {
    let config = GateConfig {
        strict_category_mode: true,
        allowed_categories: vec![ClaimCategory::Supremacy],
        ..GateConfig::default()
    };
    let gate = CompositionStabilityGate::with_config(config);
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let evidence = make_evidence("comp-1");
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());
}

#[test]
fn gate_permissive_admits_everything() {
    let gate = CompositionStabilityGate::with_config(GateConfig::permissive());
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.confidence_millionths = 0;
    evidence.stability_assessment = Some(StabilityAssessment::ImmediateActionRequired);
    evidence.signals = vec![
        make_signal("c1", SignalSeverity::Critical),
        make_signal("c2", SignalSeverity::Critical),
    ];
    evidence.separation_bundle = Some(make_bundle(vec![
        make_cert("a", "b", SeparationVerdict::Insufficient),
        make_cert("a", "c", SeparationVerdict::Insufficient),
    ]));
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());
}

#[test]
fn gate_multiple_rejection_reasons_accumulated() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.confidence_millionths = 100_000;
    evidence.stability_assessment = Some(StabilityAssessment::ImmediateActionRequired);
    evidence.signals = vec![make_signal("c1", SignalSeverity::Critical)];
    evidence.separation_bundle = Some(make_bundle(vec![make_cert(
        "a",
        "b",
        SeparationVerdict::Insufficient,
    )]));
    let verdict = gate.evaluate(&claim, Some(&evidence));
    if let GateVerdict::Rejected { reasons, .. } = &verdict {
        // Should have at least: InsufficientConfidence, AssessmentTooSevere,
        // CriticalSignalsActive, InsufficientSeparation
        assert!(
            reasons.len() >= 4,
            "expected >= 4 reasons, got {}",
            reasons.len()
        );
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn gate_with_defaults_schema_version() {
    let gate = CompositionStabilityGate::with_defaults();
    assert_eq!(gate.schema_version, SCHEMA_VERSION);
}

#[test]
fn gate_with_config_schema_version() {
    let gate = CompositionStabilityGate::with_config(GateConfig::permissive());
    assert_eq!(gate.schema_version, SCHEMA_VERSION);
}

// ===========================================================================
// Batch evaluation
// ===========================================================================

#[test]
fn batch_evaluation_maps_claims_to_evidence() {
    let gate = CompositionStabilityGate::with_defaults();
    let claims = vec![
        make_claim("cl-1", ClaimCategory::Supremacy, "comp-1"),
        make_claim("cl-2", ClaimCategory::Rollout, "comp-2"),
        make_claim("cl-3", ClaimCategory::Regression, "comp-3"),
    ];
    let mut evidence_map = BTreeMap::new();
    evidence_map.insert("comp-1".to_string(), make_evidence("comp-1"));
    evidence_map.insert("comp-3".to_string(), make_evidence("comp-3"));
    // comp-2 has no evidence

    let verdicts = gate.evaluate_batch(&claims, &evidence_map);
    assert_eq!(verdicts.len(), 3);
    assert!(verdicts[0].is_admitted(), "comp-1 should be admitted");
    assert!(
        verdicts[1].is_rejected(),
        "comp-2 should be rejected (no evidence)"
    );
    assert!(verdicts[2].is_admitted(), "comp-3 should be admitted");
}

#[test]
fn batch_evaluation_empty() {
    let gate = CompositionStabilityGate::with_defaults();
    let verdicts = gate.evaluate_batch(&[], &BTreeMap::new());
    assert!(verdicts.is_empty());
}

#[test]
fn batch_evaluation_all_missing_evidence() {
    let gate = CompositionStabilityGate::with_defaults();
    let claims = vec![
        make_claim("cl-1", ClaimCategory::Supremacy, "comp-1"),
        make_claim("cl-2", ClaimCategory::Rollout, "comp-2"),
    ];
    let verdicts = gate.evaluate_batch(&claims, &BTreeMap::new());
    assert_eq!(verdicts.len(), 2);
    assert!(verdicts.iter().all(|v| v.is_rejected()));
}

#[test]
fn batch_evaluation_shares_evidence_across_claims() {
    let gate = CompositionStabilityGate::with_defaults();
    // Two claims on the same composition
    let claims = vec![
        make_claim("cl-1", ClaimCategory::Supremacy, "comp-1"),
        make_claim("cl-2", ClaimCategory::Rollout, "comp-1"),
    ];
    let mut evidence_map = BTreeMap::new();
    evidence_map.insert("comp-1".to_string(), make_evidence("comp-1"));

    let verdicts = gate.evaluate_batch(&claims, &evidence_map);
    assert_eq!(verdicts.len(), 2);
    assert!(verdicts[0].is_admitted());
    assert!(verdicts[1].is_admitted());
}

// ===========================================================================
// GateReport
// ===========================================================================

#[test]
fn report_empty() {
    let report = GateReport::new(epoch(100), vec![]);
    assert_eq!(report.total_count(), 0);
    assert!(report.all_admitted());
    assert_eq!(report.admission_rate_millionths(), 1_000_000);
    assert_eq!(report.admitted_count, 0);
    assert_eq!(report.rejected_count, 0);
    assert_eq!(report.no_evidence_count, 0);
}

#[test]
fn report_counts_correct() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "a".to_string(),
            composition_id: "comp".to_string(),
            confidence_millionths: 900_000,
        },
        GateVerdict::Rejected {
            claim_id: "b".to_string(),
            composition_id: "comp".to_string(),
            reasons: vec![RejectionReason::NoEvidence],
        },
        GateVerdict::NoEvidence {
            claim_id: "c".to_string(),
            composition_id: "comp".to_string(),
        },
    ];
    let report = GateReport::new(epoch(100), verdicts);
    assert_eq!(report.admitted_count, 1);
    assert_eq!(report.rejected_count, 1);
    assert_eq!(report.no_evidence_count, 1);
    assert_eq!(report.total_count(), 3);
    assert!(!report.all_admitted());
}

#[test]
fn report_all_admitted_true_when_all_pass() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "a".to_string(),
            composition_id: "comp".to_string(),
            confidence_millionths: 900_000,
        },
        GateVerdict::Admitted {
            claim_id: "b".to_string(),
            composition_id: "comp".to_string(),
            confidence_millionths: 950_000,
        },
    ];
    let report = GateReport::new(epoch(100), verdicts);
    assert!(report.all_admitted());
    assert_eq!(report.admission_rate_millionths(), 1_000_000);
}

#[test]
fn report_admission_rate_half() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "a".to_string(),
            composition_id: "comp".to_string(),
            confidence_millionths: 900_000,
        },
        GateVerdict::Rejected {
            claim_id: "b".to_string(),
            composition_id: "comp".to_string(),
            reasons: vec![RejectionReason::NoEvidence],
        },
    ];
    let report = GateReport::new(epoch(100), verdicts);
    assert_eq!(report.admission_rate_millionths(), 500_000);
}

#[test]
fn report_content_hash_deterministic() {
    let verdicts = || {
        vec![
            GateVerdict::Admitted {
                claim_id: "a".to_string(),
                composition_id: "comp".to_string(),
                confidence_millionths: 900_000,
            },
            GateVerdict::Rejected {
                claim_id: "b".to_string(),
                composition_id: "comp".to_string(),
                reasons: vec![RejectionReason::NoEvidence],
            },
        ]
    };
    let a = GateReport::new(epoch(100), verdicts());
    let b = GateReport::new(epoch(100), verdicts());
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn report_content_hash_differs_on_epoch() {
    let verdicts = || {
        vec![GateVerdict::Admitted {
            claim_id: "a".to_string(),
            composition_id: "comp".to_string(),
            confidence_millionths: 900_000,
        }]
    };
    let a = GateReport::new(epoch(100), verdicts());
    let b = GateReport::new(epoch(200), verdicts());
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn report_display() {
    let report = GateReport::new(epoch(42), vec![]);
    let d = format!("{report}");
    assert!(d.contains("GateReport"));
    assert!(d.contains("admitted=0"));
    assert!(d.contains("rejected=0"));
}

#[test]
fn report_serde_roundtrip() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "a".to_string(),
            composition_id: "comp".to_string(),
            confidence_millionths: 900_000,
        },
        GateVerdict::Rejected {
            claim_id: "b".to_string(),
            composition_id: "comp".to_string(),
            reasons: vec![RejectionReason::NoEvidence],
        },
    ];
    let report = GateReport::new(epoch(42), verdicts);
    let json = serde_json::to_string(&report).unwrap();
    let back: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn report_schema_and_bead() {
    let report = GateReport::new(epoch(42), vec![]);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.epoch, epoch(42));
}

// ===========================================================================
// End-to-end scenarios
// ===========================================================================

#[test]
fn e2e_three_controller_stable_composition_admitted() {
    let gate = CompositionStabilityGate::with_defaults();

    let evidence = stable_evidence_with_bundle("comp-stable");

    let claim = make_claim("cl-perf", ClaimCategory::AdaptivePerformance, "comp-stable");
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());

    // Verify that we can build a report from this
    let report = GateReport::new(epoch(42), vec![verdict]);
    assert!(report.all_admitted());
    assert_eq!(report.admission_rate_millionths(), 1_000_000);
}

#[test]
fn e2e_mixed_batch_with_report() {
    let gate = CompositionStabilityGate::with_defaults();

    let mut good_evidence = make_evidence("comp-good");
    good_evidence.separation_bundle = Some(make_bundle(vec![make_cert(
        "a",
        "b",
        SeparationVerdict::Sufficient,
    )]));

    let mut bad_evidence = make_evidence("comp-bad");
    bad_evidence.confidence_millionths = 100_000;
    bad_evidence.signals = vec![make_signal("crit-1", SignalSeverity::Critical)];

    let claims = vec![
        make_claim("cl-1", ClaimCategory::Supremacy, "comp-good"),
        make_claim("cl-2", ClaimCategory::Rollout, "comp-bad"),
        make_claim("cl-3", ClaimCategory::Documentation, "comp-missing"),
    ];
    let mut evidence_map = BTreeMap::new();
    evidence_map.insert("comp-good".to_string(), good_evidence);
    evidence_map.insert("comp-bad".to_string(), bad_evidence);

    let verdicts = gate.evaluate_batch(&claims, &evidence_map);
    assert_eq!(verdicts.len(), 3);

    let report = GateReport::new(epoch(50), verdicts);
    assert_eq!(report.admitted_count, 1);
    assert_eq!(report.rejected_count, 2);
    assert!(!report.all_admitted());
    // 1 out of 3 = 333_333
    assert_eq!(report.admission_rate_millionths(), 333_333);
}

#[test]
fn e2e_strict_category_with_full_evidence() {
    let config = GateConfig {
        strict_category_mode: true,
        allowed_categories: vec![ClaimCategory::AdaptivePerformance, ClaimCategory::Supremacy],
        ..GateConfig::default()
    };
    let gate = CompositionStabilityGate::with_config(config);

    let evidence = stable_evidence_with_bundle("comp-1");

    // Allowed category -- should admit
    let claim_ok = make_claim("cl-ok", ClaimCategory::Supremacy, "comp-1");
    assert!(gate.evaluate(&claim_ok, Some(&evidence)).is_admitted());

    // Disallowed category -- should reject
    let claim_bad = make_claim("cl-bad", ClaimCategory::Documentation, "comp-1");
    let verdict = gate.evaluate(&claim_bad, Some(&evidence));
    assert!(verdict.is_rejected());
}

#[test]
fn e2e_gate_serde_roundtrip() {
    let gate = CompositionStabilityGate::with_defaults();
    let json = serde_json::to_string(&gate).unwrap();
    let back: CompositionStabilityGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate.config, back.config);
    assert_eq!(gate.schema_version, back.schema_version);
}

#[test]
fn e2e_confidence_boundary_exact_threshold() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");

    // Exactly at threshold should pass
    let mut evidence = make_evidence("comp-1");
    evidence.confidence_millionths = DEFAULT_MIN_CONFIDENCE_MILLIONTHS;
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted());

    // One below threshold should fail
    let mut evidence_low = make_evidence("comp-1");
    evidence_low.confidence_millionths = DEFAULT_MIN_CONFIDENCE_MILLIONTHS - 1;
    let verdict_low = gate.evaluate(&claim, Some(&evidence_low));
    assert!(verdict_low.is_rejected());
}

#[test]
fn e2e_all_categories_admitted_when_not_strict() {
    let gate = CompositionStabilityGate::with_defaults();
    let evidence = make_evidence("comp-1");

    for cat in ClaimCategory::ALL {
        let claim = make_claim("cl", *cat, "comp-1");
        let verdict = gate.evaluate(&claim, Some(&evidence));
        assert!(
            verdict.is_admitted(),
            "category {:?} should be admitted in non-strict mode",
            cat
        );
    }
}

#[test]
fn e2e_report_with_no_evidence_verdicts() {
    let config = GateConfig {
        fail_closed_on_missing: false,
        ..GateConfig::default()
    };
    let gate = CompositionStabilityGate::with_config(config);

    let claims = vec![
        make_claim("cl-1", ClaimCategory::Supremacy, "comp-1"),
        make_claim("cl-2", ClaimCategory::Rollout, "comp-2"),
    ];
    let verdicts = gate.evaluate_batch(&claims, &BTreeMap::new());

    let report = GateReport::new(epoch(1), verdicts);
    assert_eq!(report.no_evidence_count, 2);
    assert_eq!(report.admitted_count, 0);
    assert_eq!(report.rejected_count, 0);
    assert!(!report.all_admitted()); // no_evidence_count > 0
}

#[test]
fn e2e_custom_config_relaxed_warning_budget() {
    let config = GateConfig {
        max_warning_signals: 10,
        ..GateConfig::default()
    };
    let gate = CompositionStabilityGate::with_config(config);
    let claim = make_claim("cl-1", ClaimCategory::Supremacy, "comp-1");
    let mut evidence = make_evidence("comp-1");
    evidence.signals = (0..8)
        .map(|i| make_signal(&format!("w{i}"), SignalSeverity::Warning))
        .collect();
    let verdict = gate.evaluate(&claim, Some(&evidence));
    assert!(verdict.is_admitted(), "8 warnings within budget of 10");
}

#[test]
fn e2e_content_hash_stability_across_serialize_deserialize() {
    let ev = stable_evidence_with_bundle("comp-hash");
    let hash_before = ev.content_hash();
    let json = serde_json::to_string(&ev).unwrap();
    let back: CompositionEvidence = serde_json::from_str(&json).unwrap();
    let hash_after = back.content_hash();
    assert_eq!(hash_before, hash_after);
}
