#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for `controller_composition_stability_gate`.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

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
    let pair_count = sufficient_count + marginal_count + insufficient_count;
    CertificateBundle {
        schema_version: "test-v1".to_string(),
        bead_id: "test-bead".to_string(),
        certificates: certs,
        overall_verdict,
        bundle_epoch: 42,
        pair_count,
        sufficient_count,
        marginal_count,
        insufficient_count,
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
        controller_count: 2,
        separation_bundle: None,
        stability_assessment: Some(StabilityAssessment::Stable),
        signals: Vec::new(),
        confidence_millionths: 900_000,
        evidence_epoch: 42,
    }
}

fn make_signal(id: &str, severity: SignalSeverity) -> InstabilitySignal {
    InstabilitySignal {
        signal_id: id.to_string(),
        controller_ids: vec!["ctrl-1".to_string()],
        severity,
        description: format!("signal {id}"),
        risk_score_millionths: 500_000,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_contains_name() {
    assert!(SCHEMA_VERSION.contains("controller-composition-stability-gate"));
}

#[test]
fn enrichment_component_name() {
    assert_eq!(COMPONENT, "controller_composition_stability_gate");
}

#[test]
fn enrichment_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.14.3");
}

#[test]
fn enrichment_policy_id() {
    assert_eq!(POLICY_ID, "RGC-614C");
}

#[test]
fn enrichment_default_confidence_is_850k() {
    assert_eq!(DEFAULT_MIN_CONFIDENCE_MILLIONTHS, 850_000);
}

#[test]
fn enrichment_default_max_critical_is_zero() {
    assert_eq!(DEFAULT_MAX_CRITICAL_SIGNALS, 0);
}

#[test]
fn enrichment_default_max_warning_is_three() {
    assert_eq!(DEFAULT_MAX_WARNING_SIGNALS, 3);
}

#[test]
fn enrichment_default_max_marginal_is_one() {
    assert_eq!(DEFAULT_MAX_MARGINAL_PAIRS, 1);
}

#[test]
fn enrichment_default_max_insufficient_is_zero() {
    assert_eq!(DEFAULT_MAX_INSUFFICIENT_PAIRS, 0);
}

#[test]
fn enrichment_default_min_separation_ratio() {
    assert_eq!(DEFAULT_MIN_SEPARATION_RATIO_MILLIONTHS, 5_000_000);
}

// ---------------------------------------------------------------------------
// ClaimCategory
// ---------------------------------------------------------------------------

#[test]
fn enrichment_claim_category_all_has_5() {
    assert_eq!(ClaimCategory::ALL.len(), 5);
}

#[test]
fn enrichment_claim_category_display_distinct() {
    let displays: BTreeSet<String> = ClaimCategory::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), ClaimCategory::ALL.len());
}

#[test]
fn enrichment_claim_category_tag_matches_display() {
    for c in ClaimCategory::ALL {
        assert_eq!(c.tag(), c.to_string());
    }
}

#[test]
fn enrichment_claim_category_serde_roundtrip() {
    for c in ClaimCategory::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: ClaimCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ---------------------------------------------------------------------------
// SignalSeverity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_signal_severity_display_distinct() {
    let sevs = [
        SignalSeverity::Info,
        SignalSeverity::Warning,
        SignalSeverity::Critical,
    ];
    let displays: BTreeSet<String> = sevs.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), sevs.len());
}

#[test]
fn enrichment_signal_severity_serde_roundtrip() {
    for s in &[
        SignalSeverity::Info,
        SignalSeverity::Warning,
        SignalSeverity::Critical,
    ] {
        let json = serde_json::to_string(s).unwrap();
        let back: SignalSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// InstabilitySignal
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instability_signal_display() {
    let sig = make_signal("sig-1", SignalSeverity::Critical);
    let display = format!("{sig}");
    assert!(display.contains("sig-1"));
    assert!(display.contains("critical"));
}

#[test]
fn enrichment_instability_signal_serde_roundtrip() {
    let sig = make_signal("sig-2", SignalSeverity::Warning);
    let json = serde_json::to_string(&sig).unwrap();
    let back: InstabilitySignal = serde_json::from_str(&json).unwrap();
    assert_eq!(sig, back);
}

// ---------------------------------------------------------------------------
// CompositionEvidence
// ---------------------------------------------------------------------------

#[test]
fn enrichment_composition_evidence_signal_counts_empty() {
    let ev = make_evidence("comp-1");
    let (info, warning, critical) = ev.signal_counts();
    assert_eq!(info, 0);
    assert_eq!(warning, 0);
    assert_eq!(critical, 0);
}

#[test]
fn enrichment_composition_evidence_signal_counts_mixed() {
    let mut ev = make_evidence("comp-1");
    ev.signals.push(make_signal("s1", SignalSeverity::Info));
    ev.signals.push(make_signal("s2", SignalSeverity::Warning));
    ev.signals.push(make_signal("s3", SignalSeverity::Critical));
    ev.signals.push(make_signal("s4", SignalSeverity::Warning));
    let (info, warning, critical) = ev.signal_counts();
    assert_eq!(info, 1);
    assert_eq!(warning, 2);
    assert_eq!(critical, 1);
}

#[test]
fn enrichment_composition_evidence_separation_counts_none() {
    let ev = make_evidence("comp-1");
    let (suf, mar, insuf) = ev.separation_counts();
    assert_eq!(suf, 0);
    assert_eq!(mar, 0);
    assert_eq!(insuf, 0);
}

#[test]
fn enrichment_composition_evidence_separation_counts_with_bundle() {
    let mut ev = make_evidence("comp-1");
    ev.separation_bundle = Some(make_bundle(vec![
        make_cert("fast", "slow", SeparationVerdict::Sufficient),
        make_cert("fast2", "slow2", SeparationVerdict::Marginal),
    ]));
    let (suf, mar, insuf) = ev.separation_counts();
    assert_eq!(suf, 1);
    assert_eq!(mar, 1);
    assert_eq!(insuf, 0);
}

#[test]
fn enrichment_composition_evidence_content_hash_deterministic() {
    let ev1 = make_evidence("comp-1");
    let ev2 = make_evidence("comp-1");
    assert_eq!(ev1.content_hash(), ev2.content_hash());
}

#[test]
fn enrichment_composition_evidence_serde_roundtrip() {
    let ev = make_evidence("comp-1");
    let json = serde_json::to_string(&ev).unwrap();
    let back: CompositionEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// StabilityClaim
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stability_claim_display() {
    let c = make_claim("c-1", ClaimCategory::Supremacy, "comp-1");
    let display = format!("{c}");
    assert!(display.contains("c-1"));
    assert!(display.contains("supremacy"));
}

#[test]
fn enrichment_stability_claim_serde_roundtrip() {
    let c = make_claim("c-1", ClaimCategory::AdaptivePerformance, "comp-1");
    let json = serde_json::to_string(&c).unwrap();
    let back: StabilityClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// RejectionReason
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rejection_reason_display_noevidence() {
    let r = RejectionReason::NoEvidence;
    let display = format!("{r}");
    assert!(display.contains("no composition evidence"));
}

#[test]
fn enrichment_rejection_reason_display_insufficient_separation() {
    let r = RejectionReason::InsufficientSeparation {
        insufficient_pairs: 2,
        max_allowed: 0,
    };
    let display = format!("{r}");
    assert!(display.contains("2"));
}

#[test]
fn enrichment_rejection_reason_display_too_many_marginal() {
    let r = RejectionReason::TooManyMarginalPairs {
        marginal_pairs: 3,
        max_allowed: 1,
    };
    let display = format!("{r}");
    assert!(display.contains("3"));
}

#[test]
fn enrichment_rejection_reason_display_critical_signals() {
    let r = RejectionReason::CriticalSignalsActive {
        count: 1,
        max_allowed: 0,
    };
    let display = format!("{r}");
    assert!(display.contains("1"));
}

#[test]
fn enrichment_rejection_reason_serde_roundtrip() {
    let reasons = [
        RejectionReason::NoEvidence,
        RejectionReason::InsufficientSeparation {
            insufficient_pairs: 1,
            max_allowed: 0,
        },
        RejectionReason::TooManyMarginalPairs {
            marginal_pairs: 2,
            max_allowed: 1,
        },
        RejectionReason::CriticalSignalsActive {
            count: 1,
            max_allowed: 0,
        },
        RejectionReason::TooManyWarnings {
            count: 4,
            max_allowed: 3,
        },
        RejectionReason::InsufficientConfidence {
            confidence_millionths: 500_000,
            minimum_millionths: 850_000,
        },
        RejectionReason::CategoryNotAllowed {
            category: ClaimCategory::Documentation,
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_verdict_admitted() {
    let v = GateVerdict::Admitted {
        claim_id: "c1".into(),
        composition_id: "comp1".into(),
        confidence_millionths: 900_000,
    };
    assert!(v.is_admitted());
    assert!(!v.is_rejected());
    assert_eq!(v.tag(), "admitted");
    assert_eq!(v.claim_id(), "c1");
    assert_eq!(v.composition_id(), "comp1");
}

#[test]
fn enrichment_gate_verdict_rejected() {
    let v = GateVerdict::Rejected {
        claim_id: "c2".into(),
        composition_id: "comp2".into(),
        reasons: vec![RejectionReason::NoEvidence],
    };
    assert!(!v.is_admitted());
    assert!(v.is_rejected());
    assert_eq!(v.tag(), "rejected");
}

#[test]
fn enrichment_gate_verdict_no_evidence() {
    let v = GateVerdict::NoEvidence {
        claim_id: "c3".into(),
        composition_id: "comp3".into(),
    };
    assert!(!v.is_admitted());
    assert!(!v.is_rejected());
    assert_eq!(v.tag(), "no_evidence");
}

#[test]
fn enrichment_gate_verdict_display_distinct() {
    let verdicts = [
        GateVerdict::Admitted {
            claim_id: "c".into(),
            composition_id: "co".into(),
            confidence_millionths: 900_000,
        },
        GateVerdict::Rejected {
            claim_id: "c".into(),
            composition_id: "co".into(),
            reasons: vec![RejectionReason::NoEvidence],
        },
        GateVerdict::NoEvidence {
            claim_id: "c".into(),
            composition_id: "co".into(),
        },
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), verdicts.len());
}

#[test]
fn enrichment_gate_verdict_serde_roundtrip() {
    let v = GateVerdict::Admitted {
        claim_id: "c1".into(),
        composition_id: "comp1".into(),
        confidence_millionths: 900_000,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_config_default() {
    let c = GateConfig::default();
    assert_eq!(
        c.min_confidence_millionths,
        DEFAULT_MIN_CONFIDENCE_MILLIONTHS
    );
    assert_eq!(c.max_critical_signals, DEFAULT_MAX_CRITICAL_SIGNALS);
    assert_eq!(c.max_warning_signals, DEFAULT_MAX_WARNING_SIGNALS);
    assert_eq!(c.max_marginal_pairs, DEFAULT_MAX_MARGINAL_PAIRS);
    assert_eq!(c.max_insufficient_pairs, DEFAULT_MAX_INSUFFICIENT_PAIRS);
    assert!(!c.strict_category_mode);
    assert!(c.fail_closed_on_missing);
}

#[test]
fn enrichment_gate_config_permissive() {
    let c = GateConfig::permissive();
    assert_eq!(c.min_confidence_millionths, 0);
    assert!(!c.fail_closed_on_missing);
    assert_eq!(c.max_critical_signals, 100);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let c = GateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// CompositionStabilityGate: evaluate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_admits_stable_claim() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("c1", ClaimCategory::AdaptivePerformance, "comp1");
    let ev = make_evidence("comp1");
    let verdict = gate.evaluate(&claim, Some(&ev));
    assert!(verdict.is_admitted());
}

#[test]
fn enrichment_gate_rejects_no_evidence_fail_closed() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("c1", ClaimCategory::AdaptivePerformance, "comp1");
    let verdict = gate.evaluate(&claim, None);
    assert!(verdict.is_rejected());
}

#[test]
fn enrichment_gate_no_evidence_open_when_permissive() {
    let gate = CompositionStabilityGate::with_config(GateConfig::permissive());
    let claim = make_claim("c1", ClaimCategory::AdaptivePerformance, "comp1");
    let verdict = gate.evaluate(&claim, None);
    assert!(!verdict.is_admitted());
    assert!(!verdict.is_rejected());
    assert_eq!(verdict.tag(), "no_evidence");
}

#[test]
fn enrichment_gate_rejects_low_confidence() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("c1", ClaimCategory::AdaptivePerformance, "comp1");
    let mut ev = make_evidence("comp1");
    ev.confidence_millionths = 100_000; // below 850_000 threshold
    let verdict = gate.evaluate(&claim, Some(&ev));
    assert!(verdict.is_rejected());
}

#[test]
fn enrichment_gate_rejects_critical_signals() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("c1", ClaimCategory::AdaptivePerformance, "comp1");
    let mut ev = make_evidence("comp1");
    ev.signals
        .push(make_signal("crit-1", SignalSeverity::Critical));
    let verdict = gate.evaluate(&claim, Some(&ev));
    assert!(verdict.is_rejected());
}

#[test]
fn enrichment_gate_rejects_too_many_warnings() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("c1", ClaimCategory::AdaptivePerformance, "comp1");
    let mut ev = make_evidence("comp1");
    for i in 0..4 {
        ev.signals
            .push(make_signal(&format!("warn-{i}"), SignalSeverity::Warning));
    }
    let verdict = gate.evaluate(&claim, Some(&ev));
    assert!(verdict.is_rejected());
}

#[test]
fn enrichment_gate_rejects_insufficient_separation() {
    let gate = CompositionStabilityGate::with_defaults();
    let claim = make_claim("c1", ClaimCategory::AdaptivePerformance, "comp1");
    let mut ev = make_evidence("comp1");
    ev.separation_bundle = Some(make_bundle(vec![make_cert(
        "fast",
        "slow",
        SeparationVerdict::Insufficient,
    )]));
    let verdict = gate.evaluate(&claim, Some(&ev));
    assert!(verdict.is_rejected());
}

#[test]
fn enrichment_gate_strict_category_rejects_unlisted() {
    let mut config = GateConfig::default();
    config.strict_category_mode = true;
    config.allowed_categories = vec![ClaimCategory::AdaptivePerformance];
    let gate = CompositionStabilityGate::with_config(config);
    let claim = make_claim("c1", ClaimCategory::Documentation, "comp1");
    let ev = make_evidence("comp1");
    let verdict = gate.evaluate(&claim, Some(&ev));
    assert!(verdict.is_rejected());
}

#[test]
fn enrichment_gate_strict_category_admits_listed() {
    let mut config = GateConfig::default();
    config.strict_category_mode = true;
    config.allowed_categories = vec![ClaimCategory::AdaptivePerformance];
    let gate = CompositionStabilityGate::with_config(config);
    let claim = make_claim("c1", ClaimCategory::AdaptivePerformance, "comp1");
    let ev = make_evidence("comp1");
    let verdict = gate.evaluate(&claim, Some(&ev));
    assert!(verdict.is_admitted());
}

// ---------------------------------------------------------------------------
// evaluate_batch
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_batch() {
    let gate = CompositionStabilityGate::with_defaults();
    let claims = vec![
        make_claim("c1", ClaimCategory::AdaptivePerformance, "comp1"),
        make_claim("c2", ClaimCategory::Supremacy, "comp2"),
    ];
    let mut evidence_map = BTreeMap::new();
    evidence_map.insert("comp1".to_string(), make_evidence("comp1"));
    // comp2 has no evidence => rejected (fail-closed)
    let verdicts = gate.evaluate_batch(&claims, &evidence_map);
    assert_eq!(verdicts.len(), 2);
    assert!(verdicts[0].is_admitted());
    assert!(verdicts[1].is_rejected());
}

// ---------------------------------------------------------------------------
// GateReport
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_report_all_admitted() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "c1".into(),
            composition_id: "co1".into(),
            confidence_millionths: 900_000,
        },
        GateVerdict::Admitted {
            claim_id: "c2".into(),
            composition_id: "co2".into(),
            confidence_millionths: 950_000,
        },
    ];
    let report = GateReport::new(epoch(10), verdicts);
    assert_eq!(report.admitted_count, 2);
    assert_eq!(report.rejected_count, 0);
    assert_eq!(report.no_evidence_count, 0);
    assert!(report.all_admitted());
    assert_eq!(report.total_count(), 2);
    assert_eq!(report.admission_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_gate_report_mixed() {
    let verdicts = vec![
        GateVerdict::Admitted {
            claim_id: "c1".into(),
            composition_id: "co1".into(),
            confidence_millionths: 900_000,
        },
        GateVerdict::Rejected {
            claim_id: "c2".into(),
            composition_id: "co2".into(),
            reasons: vec![RejectionReason::NoEvidence],
        },
    ];
    let report = GateReport::new(epoch(10), verdicts);
    assert_eq!(report.admitted_count, 1);
    assert_eq!(report.rejected_count, 1);
    assert!(!report.all_admitted());
    assert_eq!(report.admission_rate_millionths(), 500_000);
}

#[test]
fn enrichment_gate_report_empty() {
    let report = GateReport::new(epoch(10), vec![]);
    assert_eq!(report.total_count(), 0);
    assert!(report.all_admitted());
    assert_eq!(report.admission_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_gate_report_content_hash_deterministic() {
    let verdicts = vec![GateVerdict::Admitted {
        claim_id: "c1".into(),
        composition_id: "co1".into(),
        confidence_millionths: 900_000,
    }];
    let r1 = GateReport::new(epoch(10), verdicts.clone());
    let r2 = GateReport::new(epoch(10), verdicts);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_gate_report_display() {
    let verdicts = vec![GateVerdict::Admitted {
        claim_id: "c1".into(),
        composition_id: "co1".into(),
        confidence_millionths: 900_000,
    }];
    let report = GateReport::new(epoch(10), verdicts);
    let display = format!("{report}");
    assert!(display.contains("GateReport"));
    assert!(display.contains("admitted=1"));
}

#[test]
fn enrichment_gate_report_serde_roundtrip() {
    let verdicts = vec![GateVerdict::Admitted {
        claim_id: "c1".into(),
        composition_id: "co1".into(),
        confidence_millionths: 900_000,
    }];
    let report = GateReport::new(epoch(10), verdicts);
    let json = serde_json::to_string(&report).unwrap();
    let back: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}
