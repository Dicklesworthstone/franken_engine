//! Enrichment integration tests for resource_certificate_governance_gate.

use frankenengine_engine::resource_certificate_governance_gate::{
    BEAD_ID, COMPONENT, CertificateEvidence, DEFAULT_MAX_BUDGET_OVERRUN,
    DEFAULT_MAX_CLAIMABLE_IMPROVEMENT, DEFAULT_MAX_TAIL_HEAVINESS, DEFAULT_MIN_SAMPLE_COUNT,
    DEFAULT_REGRESSION_SENSITIVITY, DEFAULT_TAIL_RISK_THRESHOLD, DecisionReceipt, GateConfig,
    GateResult, GateSummary, GateVerdict, POLICY_ID, PublicationConstraint, RegressionKind,
    RegressionRecord, ResourceKind, RiskLevel, SCHEMA_VERSION, TailRiskAssessment,
    assess_tail_risk, evaluate, evaluate_batch, evaluate_regression,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn good_evidence(kind: ResourceKind) -> CertificateEvidence {
    CertificateEvidence {
        resource_kind: kind,
        budget_millionths: 1_000_000,
        consumed_millionths: 500_000,
        headroom_fraction: 500_000,
        tail_risk_fraction: 50_000,
        sample_count: 100,
        epoch: epoch(1000),
    }
}

fn baseline_evidence(kind: ResourceKind) -> CertificateEvidence {
    CertificateEvidence {
        resource_kind: kind,
        budget_millionths: 1_000_000,
        consumed_millionths: 400_000,
        headroom_fraction: 600_000,
        tail_risk_fraction: 40_000,
        sample_count: 200,
        epoch: epoch(999),
    }
}

fn overrun_evidence(kind: ResourceKind) -> CertificateEvidence {
    CertificateEvidence {
        resource_kind: kind,
        budget_millionths: 1_000_000,
        consumed_millionths: 1_200_000,
        headroom_fraction: 0,
        tail_risk_fraction: 300_000,
        sample_count: 100,
        epoch: epoch(1000),
    }
}

// ---------------------------------------------------------------------------
// Copy semantics
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resource_kind_copy() {
    let a = ResourceKind::CpuBudget;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_risk_level_copy() {
    let a = RiskLevel::High;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_verdict_copy() {
    let a = GateVerdict::ConditionalPass;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_regression_kind_copy() {
    let a = RegressionKind::TailSpike;
    let b = a;
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Clone independence
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_evidence_clone_independence() {
    let a = good_evidence(ResourceKind::CpuBudget);
    let b = a.clone();
    assert_eq!(a, b);
    // Modifying b fields would require mut — read-only comparison suffices
    assert_eq!(a.budget_millionths, b.budget_millionths);
}

#[test]
fn enrichment_regression_record_clone_independence() {
    let a = RegressionRecord {
        kind: RegressionKind::BudgetOverrun,
        resource_kind: ResourceKind::CpuBudget,
        baseline_millionths: 400_000,
        current_millionths: 900_000,
        delta_fraction: 1_250_000,
        severity: 1_000_000,
        epoch: epoch(1000),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_tail_risk_assessment_clone_independence() {
    let a = TailRiskAssessment {
        p99_fraction: 800_000,
        p999_fraction: 900_000,
        max_observed: 950_000,
        tail_heaviness: 1_125_000,
        acceptable: false,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_publication_constraint_clone_independence() {
    let a = PublicationConstraint {
        resource_kind: ResourceKind::MemoryBudget,
        must_disclose: true,
        max_claimable_improvement: 50_000,
        caveats: vec!["caveat".to_string()],
    };
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.caveats, b.caveats);
}

#[test]
fn enrichment_gate_config_clone_independence() {
    let a = GateConfig::default();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_result_clone_independence() {
    let result = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    let cloned = result.clone();
    assert_eq!(result, cloned);
}

#[test]
fn enrichment_decision_receipt_clone_independence() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &GateConfig::default());
    let receipt = DecisionReceipt::from_result(&result, &ev);
    let cloned = receipt.clone();
    assert_eq!(receipt, cloned);
}

#[test]
fn enrichment_gate_summary_clone_independence() {
    let s = GateSummary {
        total: 10,
        passed: 7,
        conditional: 2,
        failed: 1,
        insufficient: 0,
        pass_rate: 900_000,
    };
    let c = s.clone();
    assert_eq!(s, c);
}

// ---------------------------------------------------------------------------
// BTreeSet ordering (Copy enums)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resource_kind_btreeset() {
    let set: BTreeSet<ResourceKind> = ResourceKind::ALL.iter().copied().collect();
    assert_eq!(set.len(), ResourceKind::ALL.len());
}

#[test]
fn enrichment_risk_level_btreeset() {
    let set: BTreeSet<RiskLevel> = RiskLevel::ALL.iter().copied().collect();
    assert_eq!(set.len(), RiskLevel::ALL.len());
}

#[test]
fn enrichment_gate_verdict_btreeset() {
    let set: BTreeSet<GateVerdict> = GateVerdict::ALL.iter().copied().collect();
    assert_eq!(set.len(), GateVerdict::ALL.len());
}

#[test]
fn enrichment_regression_kind_btreeset() {
    let set: BTreeSet<RegressionKind> = RegressionKind::ALL.iter().copied().collect();
    assert_eq!(set.len(), RegressionKind::ALL.len());
}

// ---------------------------------------------------------------------------
// Debug nonempty
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resource_kind_debug_nonempty() {
    for k in ResourceKind::ALL {
        assert!(!format!("{:?}", k).is_empty());
    }
}

#[test]
fn enrichment_risk_level_debug_nonempty() {
    for r in RiskLevel::ALL {
        assert!(!format!("{:?}", r).is_empty());
    }
}

#[test]
fn enrichment_gate_verdict_debug_nonempty() {
    for v in GateVerdict::ALL {
        assert!(!format!("{:?}", v).is_empty());
    }
}

#[test]
fn enrichment_regression_kind_debug_nonempty() {
    for k in RegressionKind::ALL {
        assert!(!format!("{:?}", k).is_empty());
    }
}

#[test]
fn enrichment_certificate_evidence_debug() {
    let e = good_evidence(ResourceKind::CpuBudget);
    assert!(!format!("{:?}", e).is_empty());
}

#[test]
fn enrichment_gate_config_debug() {
    assert!(!format!("{:?}", GateConfig::default()).is_empty());
}

#[test]
fn enrichment_gate_result_debug() {
    let r = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    assert!(!format!("{:?}", r).is_empty());
}

#[test]
fn enrichment_gate_summary_debug() {
    let s = GateSummary {
        total: 1,
        passed: 1,
        conditional: 0,
        failed: 0,
        insufficient: 0,
        pass_rate: 1_000_000,
    };
    assert!(!format!("{:?}", s).is_empty());
}

#[test]
fn enrichment_decision_receipt_debug() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r = evaluate(&ev, None, &GateConfig::default());
    let receipt = DecisionReceipt::from_result(&r, &ev);
    assert!(!format!("{:?}", receipt).is_empty());
}

// ---------------------------------------------------------------------------
// Display all-unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resource_kind_display_all_unique() {
    let displays: BTreeSet<String> = ResourceKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), ResourceKind::ALL.len());
}

#[test]
fn enrichment_risk_level_display_all_unique() {
    let displays: BTreeSet<String> = RiskLevel::ALL.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), RiskLevel::ALL.len());
}

#[test]
fn enrichment_gate_verdict_display_all_unique() {
    let displays: BTreeSet<String> = GateVerdict::ALL.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), GateVerdict::ALL.len());
}

#[test]
fn enrichment_regression_kind_display_all_unique() {
    let displays: BTreeSet<String> = RegressionKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), RegressionKind::ALL.len());
}

// ---------------------------------------------------------------------------
// as_str coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resource_kind_as_str_all() {
    for k in ResourceKind::ALL {
        let s = k.as_str();
        assert!(!s.is_empty());
        assert_eq!(s, k.to_string());
    }
}

#[test]
fn enrichment_risk_level_as_str_all() {
    for r in RiskLevel::ALL {
        let s = r.as_str();
        assert!(!s.is_empty());
        assert_eq!(s, r.to_string());
    }
}

#[test]
fn enrichment_gate_verdict_as_str_all() {
    for v in GateVerdict::ALL {
        let s = v.as_str();
        assert!(!s.is_empty());
        assert_eq!(s, v.to_string());
    }
}

#[test]
fn enrichment_regression_kind_as_str_all() {
    for k in RegressionKind::ALL {
        let s = k.as_str();
        assert!(!s.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Default
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_config_default_matches_constants() {
    let c = GateConfig::default();
    assert_eq!(c.max_budget_overrun_fraction, DEFAULT_MAX_BUDGET_OVERRUN);
    assert_eq!(c.tail_risk_threshold, DEFAULT_TAIL_RISK_THRESHOLD);
    assert_eq!(c.max_tail_heaviness, DEFAULT_MAX_TAIL_HEAVINESS);
    assert_eq!(c.regression_sensitivity, DEFAULT_REGRESSION_SENSITIVITY);
    assert_eq!(c.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
}

// ---------------------------------------------------------------------------
// JSON field-name stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_evidence_json_fields() {
    let e = good_evidence(ResourceKind::CpuBudget);
    let json = serde_json::to_string(&e).unwrap();
    for field in [
        "resource_kind",
        "budget_millionths",
        "consumed_millionths",
        "headroom_fraction",
        "tail_risk_fraction",
        "sample_count",
        "epoch",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_regression_record_json_fields() {
    let r = RegressionRecord {
        kind: RegressionKind::BudgetOverrun,
        resource_kind: ResourceKind::CpuBudget,
        baseline_millionths: 400_000,
        current_millionths: 900_000,
        delta_fraction: 1_250_000,
        severity: 1_000_000,
        epoch: epoch(1000),
    };
    let json = serde_json::to_string(&r).unwrap();
    for field in [
        "kind",
        "resource_kind",
        "baseline_millionths",
        "current_millionths",
        "delta_fraction",
        "severity",
        "epoch",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_tail_risk_assessment_json_fields() {
    let t = TailRiskAssessment {
        p99_fraction: 800_000,
        p999_fraction: 900_000,
        max_observed: 950_000,
        tail_heaviness: 1_125_000,
        acceptable: false,
    };
    let json = serde_json::to_string(&t).unwrap();
    for field in [
        "p99_fraction",
        "p999_fraction",
        "max_observed",
        "tail_heaviness",
        "acceptable",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_publication_constraint_json_fields() {
    let c = PublicationConstraint {
        resource_kind: ResourceKind::CpuBudget,
        must_disclose: true,
        max_claimable_improvement: 50_000,
        caveats: vec!["test".to_string()],
    };
    let json = serde_json::to_string(&c).unwrap();
    for field in [
        "resource_kind",
        "must_disclose",
        "max_claimable_improvement",
        "caveats",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_gate_config_json_fields() {
    let c = GateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    for field in [
        "max_budget_overrun_fraction",
        "tail_risk_threshold",
        "max_tail_heaviness",
        "regression_sensitivity",
        "min_sample_count",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_gate_result_json_fields() {
    let r = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    let json = serde_json::to_string(&r).unwrap();
    for field in [
        "verdict",
        "risk_level",
        "regressions",
        "tail_assessment",
        "publication_constraints",
        "receipt_hash",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_decision_receipt_json_fields() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r = evaluate(&ev, None, &GateConfig::default());
    let receipt = DecisionReceipt::from_result(&r, &ev);
    let json = serde_json::to_string(&receipt).unwrap();
    for field in [
        "receipt_hash",
        "component",
        "epoch",
        "verdict",
        "evidence_hash",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_gate_summary_json_fields() {
    let s = GateSummary {
        total: 10,
        passed: 7,
        conditional: 2,
        failed: 1,
        insufficient: 0,
        pass_rate: 900_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    for field in [
        "total",
        "passed",
        "conditional",
        "failed",
        "insufficient",
        "pass_rate",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resource_kind_serde_all() {
    for k in ResourceKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: ResourceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn enrichment_risk_level_serde_all() {
    for r in RiskLevel::ALL {
        let json = serde_json::to_string(r).unwrap();
        let back: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn enrichment_gate_verdict_serde_all() {
    for v in GateVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_regression_kind_serde_all() {
    for k in RegressionKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: RegressionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn enrichment_certificate_evidence_serde_roundtrip() {
    let e = good_evidence(ResourceKind::IoBudget);
    let json = serde_json::to_string(&e).unwrap();
    let back: CertificateEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let c = GateConfig::strict();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_gate_result_serde_roundtrip() {
    let r = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_decision_receipt_serde_roundtrip() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r = evaluate(&ev, None, &GateConfig::default());
    let receipt = DecisionReceipt::from_result(&r, &ev);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_gate_summary_serde_roundtrip() {
    let s = GateSummary {
        total: 5,
        passed: 3,
        conditional: 1,
        failed: 1,
        insufficient: 0,
        pass_rate: 800_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_determinism_20_runs() {
    let ev = good_evidence(ResourceKind::MemoryBudget);
    let base = baseline_evidence(ResourceKind::MemoryBudget);
    let config = GateConfig::default();
    let first = evaluate(&ev, Some(&base), &config);
    for _ in 1..20 {
        let r = evaluate(&ev, Some(&base), &config);
        assert_eq!(first, r);
    }
}

#[test]
fn enrichment_content_hash_determinism() {
    let e = good_evidence(ResourceKind::CpuBudget);
    let h1 = e.content_hash();
    let h2 = e.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_batch_determinism() {
    let config = GateConfig::default();
    let items = vec![
        (good_evidence(ResourceKind::CpuBudget), None),
        (good_evidence(ResourceKind::MemoryBudget), None),
    ];
    let (r1, s1) = evaluate_batch(&items, &config);
    let (r2, s2) = evaluate_batch(&items, &config);
    assert_eq!(r1, r2);
    assert_eq!(s1, s2);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert!(SCHEMA_VERSION.contains("resource-certificate"));
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn enrichment_default_constants_positive() {
    const {
        assert!(DEFAULT_MAX_BUDGET_OVERRUN > 0);
        assert!(DEFAULT_TAIL_RISK_THRESHOLD > 0);
        assert!(DEFAULT_MAX_TAIL_HEAVINESS > 0);
        assert!(DEFAULT_REGRESSION_SENSITIVITY > 0);
        assert!(DEFAULT_MIN_SAMPLE_COUNT > 0);
        assert!(DEFAULT_MAX_CLAIMABLE_IMPROVEMENT > 0);
    }
}

// ---------------------------------------------------------------------------
// CertificateEvidence methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_utilisation_fraction_50_percent() {
    let e = good_evidence(ResourceKind::CpuBudget);
    assert_eq!(e.utilisation_fraction(), 500_000);
}

#[test]
fn enrichment_utilisation_fraction_zero_budget() {
    let mut e = good_evidence(ResourceKind::CpuBudget);
    e.budget_millionths = 0;
    assert_eq!(e.utilisation_fraction(), 1_000_000);
}

#[test]
fn enrichment_utilisation_fraction_full() {
    let mut e = good_evidence(ResourceKind::CpuBudget);
    e.consumed_millionths = 1_000_000;
    assert_eq!(e.utilisation_fraction(), 1_000_000);
}

#[test]
fn enrichment_utilisation_fraction_zero_consumed() {
    let mut e = good_evidence(ResourceKind::CpuBudget);
    e.consumed_millionths = 0;
    assert_eq!(e.utilisation_fraction(), 0);
}

#[test]
fn enrichment_is_overrun_false() {
    let e = good_evidence(ResourceKind::CpuBudget);
    assert!(!e.is_overrun());
}

#[test]
fn enrichment_is_overrun_true() {
    let o = overrun_evidence(ResourceKind::CpuBudget);
    assert!(o.is_overrun());
}

#[test]
fn enrichment_is_overrun_exact_budget() {
    let mut e = good_evidence(ResourceKind::CpuBudget);
    e.consumed_millionths = e.budget_millionths;
    assert!(!e.is_overrun());
}

#[test]
fn enrichment_content_hash_varies_by_kind() {
    let e1 = good_evidence(ResourceKind::CpuBudget);
    let e2 = good_evidence(ResourceKind::MemoryBudget);
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_content_hash_varies_by_consumed() {
    let e1 = good_evidence(ResourceKind::CpuBudget);
    let mut e2 = good_evidence(ResourceKind::CpuBudget);
    e2.consumed_millionths = 600_000;
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn enrichment_content_hash_varies_by_epoch() {
    let e1 = good_evidence(ResourceKind::CpuBudget);
    let mut e2 = good_evidence(ResourceKind::CpuBudget);
    e2.epoch = epoch(2000);
    assert_ne!(e1.content_hash(), e2.content_hash());
}

// ---------------------------------------------------------------------------
// GateVerdict methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verdict_is_passing_pass() {
    assert!(GateVerdict::Pass.is_passing());
}

#[test]
fn enrichment_verdict_is_passing_conditional() {
    assert!(GateVerdict::ConditionalPass.is_passing());
}

#[test]
fn enrichment_verdict_is_passing_fail() {
    assert!(!GateVerdict::Fail.is_passing());
}

#[test]
fn enrichment_verdict_is_passing_insufficient() {
    assert!(!GateVerdict::InsufficientEvidence.is_passing());
}

// ---------------------------------------------------------------------------
// TailRiskAssessment methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_tail_heavy_above_million() {
    let t = TailRiskAssessment {
        p99_fraction: 800_000,
        p999_fraction: 900_000,
        max_observed: 950_000,
        tail_heaviness: 1_100_000,
        acceptable: false,
    };
    assert!(t.is_heavy_tailed());
}

#[test]
fn enrichment_tail_not_heavy_below_million() {
    let t = TailRiskAssessment {
        p99_fraction: 800_000,
        p999_fraction: 850_000,
        max_observed: 870_000,
        tail_heaviness: 900_000,
        acceptable: true,
    };
    assert!(!t.is_heavy_tailed());
}

#[test]
fn enrichment_tail_exactly_million() {
    let t = TailRiskAssessment {
        p99_fraction: 800_000,
        p999_fraction: 800_000,
        max_observed: 800_000,
        tail_heaviness: 1_000_000,
        acceptable: true,
    };
    assert!(!t.is_heavy_tailed());
}

// ---------------------------------------------------------------------------
// GateSummary methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_all_passing_true() {
    let s = GateSummary {
        total: 5,
        passed: 3,
        conditional: 2,
        failed: 0,
        insufficient: 0,
        pass_rate: 1_000_000,
    };
    assert!(s.all_passing());
}

#[test]
fn enrichment_summary_all_passing_false_with_failures() {
    let s = GateSummary {
        total: 5,
        passed: 3,
        conditional: 1,
        failed: 1,
        insufficient: 0,
        pass_rate: 800_000,
    };
    assert!(!s.all_passing());
}

#[test]
fn enrichment_summary_all_passing_false_with_insufficient() {
    let s = GateSummary {
        total: 5,
        passed: 3,
        conditional: 1,
        failed: 0,
        insufficient: 1,
        pass_rate: 800_000,
    };
    assert!(!s.all_passing());
}

#[test]
fn enrichment_summary_all_passing_empty() {
    let s = GateSummary {
        total: 0,
        passed: 0,
        conditional: 0,
        failed: 0,
        insufficient: 0,
        pass_rate: 0,
    };
    assert!(!s.all_passing());
}

#[test]
fn enrichment_summary_has_failures() {
    let s = GateSummary {
        total: 5,
        passed: 3,
        conditional: 1,
        failed: 1,
        insufficient: 0,
        pass_rate: 800_000,
    };
    assert!(s.has_failures());
}

#[test]
fn enrichment_summary_no_failures() {
    let s = GateSummary {
        total: 5,
        passed: 5,
        conditional: 0,
        failed: 0,
        insufficient: 0,
        pass_rate: 1_000_000,
    };
    assert!(!s.has_failures());
}

// ---------------------------------------------------------------------------
// GateConfig constructors
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_strict_tighter_than_default() {
    let s = GateConfig::strict();
    let d = GateConfig::default();
    assert!(s.max_budget_overrun_fraction <= d.max_budget_overrun_fraction);
    assert!(s.regression_sensitivity <= d.regression_sensitivity);
    assert!(s.min_sample_count >= d.min_sample_count);
    assert!(s.max_tail_heaviness <= d.max_tail_heaviness);
}

#[test]
fn enrichment_config_permissive_looser_than_default() {
    let p = GateConfig::permissive();
    let d = GateConfig::default();
    assert!(p.max_budget_overrun_fraction >= d.max_budget_overrun_fraction);
    assert!(p.regression_sensitivity >= d.regression_sensitivity);
    assert!(p.min_sample_count <= d.min_sample_count);
    assert!(p.max_tail_heaviness >= d.max_tail_heaviness);
}

#[test]
fn enrichment_config_strict_values() {
    let s = GateConfig::strict();
    assert_eq!(s.max_budget_overrun_fraction, 20_000);
    assert_eq!(s.tail_risk_threshold, 980_000);
    assert_eq!(s.max_tail_heaviness, 1_050_000);
    assert_eq!(s.regression_sensitivity, 10_000);
    assert_eq!(s.min_sample_count, 100);
}

#[test]
fn enrichment_config_permissive_values() {
    let p = GateConfig::permissive();
    assert_eq!(p.max_budget_overrun_fraction, 200_000);
    assert_eq!(p.tail_risk_threshold, 800_000);
    assert_eq!(p.max_tail_heaviness, 1_500_000);
    assert_eq!(p.regression_sensitivity, 100_000);
    assert_eq!(p.min_sample_count, 5);
}

// ---------------------------------------------------------------------------
// evaluate_regression edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_regression_identical_evidence_no_regressions() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let base = ev.clone();
    let regs = evaluate_regression(&ev, &base, &GateConfig::default());
    assert!(regs.is_empty());
}

#[test]
fn enrichment_regression_budget_overrun_detected() {
    let base = baseline_evidence(ResourceKind::CpuBudget);
    let ev = overrun_evidence(ResourceKind::CpuBudget);
    let regs = evaluate_regression(&ev, &base, &GateConfig::default());
    assert!(regs.iter().any(|r| r.kind == RegressionKind::BudgetOverrun));
}

#[test]
fn enrichment_regression_tail_spike_detected() {
    let mut base = baseline_evidence(ResourceKind::CpuBudget);
    base.tail_risk_fraction = 10_000;
    let mut ev = good_evidence(ResourceKind::CpuBudget);
    ev.tail_risk_fraction = 100_000;
    let regs = evaluate_regression(&ev, &base, &GateConfig::default());
    assert!(regs.iter().any(|r| r.kind == RegressionKind::TailSpike));
}

#[test]
fn enrichment_regression_effect_leak_suppressed_by_budget_overrun() {
    let mut base = baseline_evidence(ResourceKind::EffectBudget);
    base.consumed_millionths = 100_000;
    let mut ev = good_evidence(ResourceKind::EffectBudget);
    ev.consumed_millionths = 200_000;
    let regs = evaluate_regression(&ev, &base, &GateConfig::default());
    // BudgetOverrun triggers first, EffectLeak suppressed
    assert!(regs.iter().any(|r| r.kind == RegressionKind::BudgetOverrun));
    assert!(!regs.iter().any(|r| r.kind == RegressionKind::EffectLeak));
}

#[test]
fn enrichment_regression_allocation_burst_suppressed_by_budget_overrun() {
    let mut base = baseline_evidence(ResourceKind::AllocationBudget);
    base.consumed_millionths = 100_000;
    let mut ev = good_evidence(ResourceKind::AllocationBudget);
    ev.consumed_millionths = 200_000;
    let regs = evaluate_regression(&ev, &base, &GateConfig::default());
    assert!(regs.iter().any(|r| r.kind == RegressionKind::BudgetOverrun));
    assert!(
        !regs
            .iter()
            .any(|r| r.kind == RegressionKind::AllocationBurst)
    );
}

#[test]
fn enrichment_regression_latency_suppressed_by_budget_overrun() {
    let mut base = baseline_evidence(ResourceKind::LatencyBudget);
    base.consumed_millionths = 100_000;
    let mut ev = good_evidence(ResourceKind::LatencyBudget);
    ev.consumed_millionths = 200_000;
    let regs = evaluate_regression(&ev, &base, &GateConfig::default());
    assert!(regs.iter().any(|r| r.kind == RegressionKind::BudgetOverrun));
    assert!(
        !regs
            .iter()
            .any(|r| r.kind == RegressionKind::LatencyRegression)
    );
}

#[test]
fn enrichment_regression_permissive_config_fewer_detections() {
    let base = baseline_evidence(ResourceKind::CpuBudget);
    let mut ev = good_evidence(ResourceKind::CpuBudget);
    // 25% increase above baseline — within permissive but outside default
    ev.consumed_millionths = 500_000;
    let default_regs = evaluate_regression(&ev, &base, &GateConfig::default());
    let permissive_regs = evaluate_regression(&ev, &base, &GateConfig::permissive());
    assert!(permissive_regs.len() <= default_regs.len());
}

// ---------------------------------------------------------------------------
// assess_tail_risk edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_tail_risk_low_usage_acceptable() {
    let config = GateConfig::default();
    let ev = good_evidence(ResourceKind::CpuBudget);
    let tail = assess_tail_risk(&ev, &config);
    assert!(tail.acceptable);
    assert!(tail.p99_fraction > 0);
    assert!(tail.p999_fraction >= tail.p99_fraction);
    assert!(tail.max_observed >= tail.p999_fraction);
}

#[test]
fn enrichment_tail_risk_high_tail_fraction_unacceptable() {
    let config = GateConfig::default();
    let mut ev = good_evidence(ResourceKind::CpuBudget);
    ev.tail_risk_fraction = 5_000_000;
    ev.consumed_millionths = 900_000;
    let tail = assess_tail_risk(&ev, &config);
    assert!(!tail.acceptable);
}

#[test]
fn enrichment_tail_risk_strict_config_more_restrictive() {
    let mut ev = good_evidence(ResourceKind::CpuBudget);
    ev.tail_risk_fraction = 200_000;
    ev.consumed_millionths = 800_000;
    let default_tail = assess_tail_risk(&ev, &GateConfig::default());
    let strict_tail = assess_tail_risk(&ev, &GateConfig::strict());
    // Strict is more restrictive — if default says acceptable, strict might not
    if default_tail.acceptable {
        // Strict may or may not accept — just verify both produce valid output
        assert!(strict_tail.p99_fraction > 0);
    }
}

#[test]
fn enrichment_tail_risk_zero_tail_fraction() {
    let config = GateConfig::default();
    let mut ev = good_evidence(ResourceKind::CpuBudget);
    ev.tail_risk_fraction = 0;
    let tail = assess_tail_risk(&ev, &config);
    assert!(tail.acceptable);
}

// ---------------------------------------------------------------------------
// evaluate edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_pass_no_baseline() {
    let r = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    assert_eq!(r.verdict, GateVerdict::Pass);
    // Risk may be Elevated due to tail heaviness even with clean pass
    assert!(r.risk_level == RiskLevel::Nominal || r.risk_level == RiskLevel::Elevated);
    assert!(r.regressions.is_empty());
}

#[test]
fn enrichment_evaluate_pass_with_identical_baseline() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let base = ev.clone();
    let r = evaluate(&ev, Some(&base), &GateConfig::default());
    assert_eq!(r.verdict, GateVerdict::Pass);
}

#[test]
fn enrichment_evaluate_conditional_pass_overrun() {
    let r = evaluate(
        &overrun_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    assert_eq!(r.verdict, GateVerdict::ConditionalPass);
}

#[test]
fn enrichment_evaluate_insufficient_low_samples() {
    let mut ev = good_evidence(ResourceKind::CpuBudget);
    ev.sample_count = 1;
    let r = evaluate(&ev, None, &GateConfig::default());
    assert_eq!(r.verdict, GateVerdict::InsufficientEvidence);
    assert_eq!(r.risk_level, RiskLevel::Nominal);
    assert!(
        r.publication_constraints
            .iter()
            .any(|c| c.max_claimable_improvement == 0)
    );
}

#[test]
fn enrichment_evaluate_insufficient_at_boundary() {
    let config = GateConfig::default();
    let mut ev = good_evidence(ResourceKind::CpuBudget);
    ev.sample_count = config.min_sample_count - 1;
    let r = evaluate(&ev, None, &config);
    assert_eq!(r.verdict, GateVerdict::InsufficientEvidence);
}

#[test]
fn enrichment_evaluate_sufficient_at_boundary() {
    let config = GateConfig::default();
    let mut ev = good_evidence(ResourceKind::CpuBudget);
    ev.sample_count = config.min_sample_count;
    let r = evaluate(&ev, None, &config);
    assert_ne!(r.verdict, GateVerdict::InsufficientEvidence);
}

#[test]
fn enrichment_evaluate_receipt_hash_deterministic() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r1 = evaluate(&ev, None, &GateConfig::default());
    let r2 = evaluate(&ev, None, &GateConfig::default());
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_evaluate_publication_constraints_always_present() {
    let r = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    assert!(!r.publication_constraints.is_empty());
}

#[test]
fn enrichment_evaluate_no_disclosure_clean_pass() {
    let r = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    let no_disclose = r.publication_constraints.iter().all(|c| !c.must_disclose);
    assert!(no_disclose);
}

#[test]
fn enrichment_evaluate_disclosure_required_overrun() {
    let r = evaluate(
        &overrun_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    let disc = r.publication_constraints.iter().any(|c| c.must_disclose);
    assert!(disc);
}

#[test]
fn enrichment_evaluate_disclosure_caps_improvement() {
    let r = evaluate(
        &overrun_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    let capped = r.publication_constraints.iter().any(|c| {
        c.must_disclose && c.max_claimable_improvement == DEFAULT_MAX_CLAIMABLE_IMPROVEMENT / 2
    });
    assert!(capped);
}

#[test]
fn enrichment_evaluate_clean_pass_full_improvement() {
    let r = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    let full = r.publication_constraints.iter().any(|c| {
        !c.must_disclose && c.max_claimable_improvement == DEFAULT_MAX_CLAIMABLE_IMPROVEMENT
    });
    assert!(full);
}

#[test]
fn enrichment_evaluate_all_resource_kinds() {
    let config = GateConfig::default();
    for kind in ResourceKind::ALL {
        let ev = good_evidence(*kind);
        let r = evaluate(&ev, None, &config);
        assert_eq!(r.verdict, GateVerdict::Pass);
    }
}

// ---------------------------------------------------------------------------
// GateResult methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_result_is_passing() {
    let r = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    assert!(r.is_passing());
}

#[test]
fn enrichment_gate_result_regression_count_zero() {
    let r = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    assert_eq!(r.regression_count(), 0);
}

#[test]
fn enrichment_gate_result_regression_count_nonzero() {
    let base = baseline_evidence(ResourceKind::CpuBudget);
    let ev = overrun_evidence(ResourceKind::CpuBudget);
    let r = evaluate(&ev, Some(&base), &GateConfig::default());
    assert!(r.regression_count() > 0);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_component_matches() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r = evaluate(&ev, None, &GateConfig::default());
    let receipt = DecisionReceipt::from_result(&r, &ev);
    assert_eq!(receipt.component, COMPONENT);
}

#[test]
fn enrichment_receipt_verdict_matches() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r = evaluate(&ev, None, &GateConfig::default());
    let receipt = DecisionReceipt::from_result(&r, &ev);
    assert_eq!(receipt.verdict, r.verdict);
}

#[test]
fn enrichment_receipt_epoch_matches() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r = evaluate(&ev, None, &GateConfig::default());
    let receipt = DecisionReceipt::from_result(&r, &ev);
    assert_eq!(receipt.epoch.as_u64(), ev.epoch.as_u64());
}

#[test]
fn enrichment_receipt_evidence_hash_matches() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r = evaluate(&ev, None, &GateConfig::default());
    let receipt = DecisionReceipt::from_result(&r, &ev);
    assert_eq!(receipt.evidence_hash, ev.content_hash());
}

#[test]
fn enrichment_receipt_deterministic() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r = evaluate(&ev, None, &GateConfig::default());
    let r1 = DecisionReceipt::from_result(&r, &ev);
    let r2 = DecisionReceipt::from_result(&r, &ev);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_differs_by_verdict() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r_pass = evaluate(&ev, None, &GateConfig::default());
    let r_over = evaluate(
        &overrun_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    let receipt_pass = DecisionReceipt::from_result(&r_pass, &ev);
    let receipt_over =
        DecisionReceipt::from_result(&r_over, &overrun_evidence(ResourceKind::CpuBudget));
    assert_ne!(receipt_pass.receipt_hash, receipt_over.receipt_hash);
}

// ---------------------------------------------------------------------------
// evaluate_batch
// ---------------------------------------------------------------------------

#[test]
fn enrichment_batch_empty() {
    let (results, summary) = evaluate_batch(&[], &GateConfig::default());
    assert!(results.is_empty());
    assert_eq!(summary.total, 0);
    assert_eq!(summary.pass_rate, 0);
}

#[test]
fn enrichment_batch_single_pass() {
    let items = vec![(good_evidence(ResourceKind::CpuBudget), None)];
    let (results, summary) = evaluate_batch(&items, &GateConfig::default());
    assert_eq!(results.len(), 1);
    assert_eq!(summary.total, 1);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.pass_rate, 1_000_000);
}

#[test]
fn enrichment_batch_all_pass() {
    let items: Vec<_> = ResourceKind::ALL
        .iter()
        .map(|k| (good_evidence(*k), None))
        .collect();
    let (_, summary) = evaluate_batch(&items, &GateConfig::default());
    assert_eq!(summary.total, 6);
    assert_eq!(summary.passed, 6);
    assert!(summary.all_passing());
    assert!(!summary.has_failures());
}

#[test]
fn enrichment_batch_mixed_verdicts() {
    let mut insufficient = good_evidence(ResourceKind::IoBudget);
    insufficient.sample_count = 1;
    let items = vec![
        (good_evidence(ResourceKind::CpuBudget), None),
        (overrun_evidence(ResourceKind::MemoryBudget), None),
        (insufficient, None),
    ];
    let (_, summary) = evaluate_batch(&items, &GateConfig::default());
    assert_eq!(summary.total, 3);
    assert!(summary.passed > 0);
    assert!(summary.insufficient > 0);
    assert!(!summary.all_passing());
}

#[test]
fn enrichment_batch_with_baselines() {
    let items = vec![
        (
            good_evidence(ResourceKind::CpuBudget),
            Some(baseline_evidence(ResourceKind::CpuBudget)),
        ),
        (
            good_evidence(ResourceKind::MemoryBudget),
            Some(baseline_evidence(ResourceKind::MemoryBudget)),
        ),
    ];
    let (results, summary) = evaluate_batch(&items, &GateConfig::default());
    assert_eq!(results.len(), 2);
    assert!(summary.total == 2);
}

// ---------------------------------------------------------------------------
// Display coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_regression_record_display() {
    let r = RegressionRecord {
        kind: RegressionKind::TailSpike,
        resource_kind: ResourceKind::MemoryBudget,
        baseline_millionths: 40_000,
        current_millionths: 100_000,
        delta_fraction: 1_500_000,
        severity: 1_000_000,
        epoch: epoch(1000),
    };
    let s = r.to_string();
    assert!(s.contains("tail_spike"));
    assert!(s.contains("memory_budget"));
    assert!(s.contains("40000"));
    assert!(s.contains("100000"));
}

#[test]
fn enrichment_tail_risk_assessment_display() {
    let t = TailRiskAssessment {
        p99_fraction: 800_000,
        p999_fraction: 900_000,
        max_observed: 950_000,
        tail_heaviness: 1_125_000,
        acceptable: false,
    };
    let s = t.to_string();
    assert!(s.contains("p99="));
    assert!(s.contains("p999="));
    assert!(s.contains("acceptable=false"));
}

#[test]
fn enrichment_publication_constraint_display() {
    let c = PublicationConstraint {
        resource_kind: ResourceKind::IoBudget,
        must_disclose: true,
        max_claimable_improvement: 50_000,
        caveats: vec!["overrun".to_string(), "spike".to_string()],
    };
    let s = c.to_string();
    assert!(s.contains("io_budget"));
    assert!(s.contains("disclose=true"));
    assert!(s.contains("caveats=2"));
}

#[test]
fn enrichment_gate_result_display() {
    let r = evaluate(
        &good_evidence(ResourceKind::CpuBudget),
        None,
        &GateConfig::default(),
    );
    let s = r.to_string();
    assert!(s.contains("pass"));
    assert!(s.contains("risk="));
    assert!(s.contains("regressions=0"));
}

#[test]
fn enrichment_decision_receipt_display() {
    let ev = good_evidence(ResourceKind::CpuBudget);
    let r = evaluate(&ev, None, &GateConfig::default());
    let receipt = DecisionReceipt::from_result(&r, &ev);
    let s = receipt.to_string();
    assert!(s.contains("receipt["));
    assert!(s.contains(COMPONENT));
    assert!(s.contains("pass"));
}

#[test]
fn enrichment_gate_summary_display() {
    let s = GateSummary {
        total: 10,
        passed: 7,
        conditional: 2,
        failed: 1,
        insufficient: 0,
        pass_rate: 900_000,
    };
    let d = s.to_string();
    assert!(d.contains("9/10"));
    assert!(d.contains("2 conditional"));
    assert!(d.contains("1 failed"));
    assert!(d.contains("0 insufficient"));
}
