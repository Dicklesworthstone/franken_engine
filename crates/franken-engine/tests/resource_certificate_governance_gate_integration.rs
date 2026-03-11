//! Integration tests for resource_certificate_governance_gate module.

use frankenengine_engine::resource_certificate_governance_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn baseline_evidence(kind: ResourceKind) -> CertificateEvidence {
    CertificateEvidence {
        resource_kind: kind,
        budget_millionths: 1_000_000,
        consumed_millionths: 500_000,
        headroom_fraction: 500_000,
        tail_risk_fraction: 100_000,
        sample_count: 100,
        epoch: epoch(10),
    }
}

fn good_evidence(kind: ResourceKind) -> CertificateEvidence {
    CertificateEvidence {
        resource_kind: kind,
        budget_millionths: 1_000_000,
        consumed_millionths: 520_000,
        headroom_fraction: 480_000,
        tail_risk_fraction: 110_000,
        sample_count: 100,
        epoch: epoch(11),
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
        epoch: epoch(11),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_value() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.resource-certificate-governance-gate.v1"
    );
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "resource_certificate_governance_gate");
}

#[test]
fn test_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.25.3");
}

#[test]
fn test_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-625C");
}

#[test]
fn test_default_max_budget_overrun() {
    assert_eq!(DEFAULT_MAX_BUDGET_OVERRUN, 50_000);
}

#[test]
fn test_default_tail_risk_threshold() {
    assert_eq!(DEFAULT_TAIL_RISK_THRESHOLD, 950_000);
}

#[test]
fn test_default_max_tail_heaviness() {
    assert_eq!(DEFAULT_MAX_TAIL_HEAVINESS, 200_000);
}

#[test]
fn test_default_regression_sensitivity() {
    assert_eq!(DEFAULT_REGRESSION_SENSITIVITY, 30_000);
}

#[test]
fn test_default_min_sample_count() {
    assert_eq!(DEFAULT_MIN_SAMPLE_COUNT, 30);
}

#[test]
fn test_default_max_claimable_improvement() {
    assert_eq!(DEFAULT_MAX_CLAIMABLE_IMPROVEMENT, 100_000);
}

// ---------------------------------------------------------------------------
// ResourceKind
// ---------------------------------------------------------------------------

#[test]
fn test_resource_kind_all_has_six_variants() {
    assert_eq!(ResourceKind::ALL.len(), 6);
}

#[test]
fn test_resource_kind_serde_roundtrip() {
    for k in ResourceKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: ResourceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn test_resource_kind_display_matches_as_str() {
    for k in ResourceKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

#[test]
fn test_resource_kind_cpu_budget_str() {
    assert_eq!(ResourceKind::CpuBudget.as_str(), "cpu_budget");
}

#[test]
fn test_resource_kind_allocation_budget_str() {
    assert_eq!(ResourceKind::AllocationBudget.as_str(), "allocation_budget");
}

// ---------------------------------------------------------------------------
// RiskLevel
// ---------------------------------------------------------------------------

#[test]
fn test_risk_level_all_has_four_variants() {
    assert_eq!(RiskLevel::ALL.len(), 4);
}

#[test]
fn test_risk_level_serde_roundtrip() {
    for r in RiskLevel::ALL {
        let json = serde_json::to_string(r).unwrap();
        let back: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn test_risk_level_display_matches_as_str() {
    for r in RiskLevel::ALL {
        assert_eq!(r.to_string(), r.as_str());
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_gate_verdict_all_has_four_variants() {
    assert_eq!(GateVerdict::ALL.len(), 4);
}

#[test]
fn test_gate_verdict_is_passing() {
    assert!(GateVerdict::Pass.is_passing());
    assert!(GateVerdict::ConditionalPass.is_passing());
    assert!(!GateVerdict::Fail.is_passing());
    assert!(!GateVerdict::InsufficientEvidence.is_passing());
}

#[test]
fn test_gate_verdict_serde_roundtrip() {
    for v in GateVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn test_gate_verdict_display_matches_as_str() {
    for v in GateVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

// ---------------------------------------------------------------------------
// RegressionKind
// ---------------------------------------------------------------------------

#[test]
fn test_regression_kind_all_has_five_variants() {
    assert_eq!(RegressionKind::ALL.len(), 5);
}

#[test]
fn test_regression_kind_serde_roundtrip() {
    for rk in RegressionKind::ALL {
        let json = serde_json::to_string(rk).unwrap();
        let back: RegressionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*rk, back);
    }
}

#[test]
fn test_regression_kind_display_matches_as_str() {
    for rk in RegressionKind::ALL {
        assert_eq!(rk.to_string(), rk.as_str());
    }
}

// ---------------------------------------------------------------------------
// CertificateEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_certificate_evidence_utilisation_fraction() {
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    assert_eq!(ev.utilisation_fraction(), 500_000);
}

#[test]
fn test_certificate_evidence_utilisation_zero_budget() {
    let ev = CertificateEvidence {
        resource_kind: ResourceKind::CpuBudget,
        budget_millionths: 0,
        consumed_millionths: 100,
        headroom_fraction: 0,
        tail_risk_fraction: 0,
        sample_count: 50,
        epoch: epoch(1),
    };
    assert_eq!(ev.utilisation_fraction(), 1_000_000);
}

#[test]
fn test_certificate_evidence_is_overrun_false() {
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    assert!(!ev.is_overrun());
}

#[test]
fn test_certificate_evidence_is_overrun_true() {
    let ev = overrun_evidence(ResourceKind::CpuBudget);
    assert!(ev.is_overrun());
}

#[test]
fn test_certificate_evidence_content_hash_deterministic() {
    let ev = baseline_evidence(ResourceKind::MemoryBudget);
    let h1 = ev.content_hash();
    let h2 = ev.content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn test_certificate_evidence_content_hash_32_bytes() {
    let ev = baseline_evidence(ResourceKind::IoBudget);
    assert_eq!(ev.content_hash().as_bytes().len(), 32);
}

#[test]
fn test_certificate_evidence_serde_roundtrip() {
    let ev = baseline_evidence(ResourceKind::EffectBudget);
    let json = serde_json::to_string(&ev).unwrap();
    let back: CertificateEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// evaluate_regression
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_regression_no_regression_for_small_delta() {
    let cfg = GateConfig::default();
    let base = baseline_evidence(ResourceKind::CpuBudget);
    let current = good_evidence(ResourceKind::CpuBudget);
    let regs = evaluate_regression(&current, &base, &cfg);
    assert!(regs.is_empty());
}

#[test]
fn test_evaluate_regression_budget_overrun_detected() {
    let cfg = GateConfig::default();
    let base = baseline_evidence(ResourceKind::CpuBudget);
    let current = overrun_evidence(ResourceKind::CpuBudget);
    let regs = evaluate_regression(&current, &base, &cfg);
    assert!(regs.iter().any(|r| r.kind == RegressionKind::BudgetOverrun));
}

#[test]
fn test_evaluate_regression_tail_spike_detected() {
    let cfg = GateConfig::default();
    let base = baseline_evidence(ResourceKind::CpuBudget);
    let mut current = good_evidence(ResourceKind::CpuBudget);
    current.tail_risk_fraction = 200_000;
    let regs = evaluate_regression(&current, &base, &cfg);
    assert!(regs.iter().any(|r| r.kind == RegressionKind::TailSpike));
}

#[test]
fn test_evaluate_regression_effect_leak_for_effect_budget() {
    let cfg = GateConfig::default();
    let mut base = baseline_evidence(ResourceKind::EffectBudget);
    base.consumed_millionths = 100_000;
    let mut current = good_evidence(ResourceKind::EffectBudget);
    current.consumed_millionths = 140_000;
    let regs = evaluate_regression(&current, &base, &cfg);
    assert!(regs.iter().any(|r| r.kind == RegressionKind::EffectLeak));
}

#[test]
fn test_evaluate_regression_allocation_burst_for_allocation_budget() {
    let cfg = GateConfig::default();
    let mut base = baseline_evidence(ResourceKind::AllocationBudget);
    base.consumed_millionths = 100_000;
    let mut current = good_evidence(ResourceKind::AllocationBudget);
    current.consumed_millionths = 140_000;
    let regs = evaluate_regression(&current, &base, &cfg);
    assert!(
        regs.iter()
            .any(|r| r.kind == RegressionKind::AllocationBurst)
    );
}

#[test]
fn test_evaluate_regression_latency_regression_for_latency_budget() {
    let cfg = GateConfig::default();
    let mut base = baseline_evidence(ResourceKind::LatencyBudget);
    base.consumed_millionths = 100_000;
    let mut current = good_evidence(ResourceKind::LatencyBudget);
    current.consumed_millionths = 140_000;
    let regs = evaluate_regression(&current, &base, &cfg);
    assert!(
        regs.iter()
            .any(|r| r.kind == RegressionKind::LatencyRegression)
    );
}

#[test]
fn test_regression_record_display_contains_kind() {
    let cfg = GateConfig::default();
    let base = baseline_evidence(ResourceKind::CpuBudget);
    let current = overrun_evidence(ResourceKind::CpuBudget);
    let regs = evaluate_regression(&current, &base, &cfg);
    let r = &regs[0];
    let s = r.to_string();
    assert!(s.contains("budget_overrun") || s.contains("cpu_budget"));
}

// ---------------------------------------------------------------------------
// assess_tail_risk
// ---------------------------------------------------------------------------

#[test]
fn test_assess_tail_risk_acceptable_for_low_risk() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let assessment = assess_tail_risk(&ev, &cfg);
    assert!(assessment.acceptable);
}

#[test]
fn test_assess_tail_risk_heavy_tailed_high_fraction() {
    let cfg = GateConfig::default();
    let mut ev = baseline_evidence(ResourceKind::CpuBudget);
    ev.tail_risk_fraction = 900_000;
    ev.consumed_millionths = 900_000;
    let assessment = assess_tail_risk(&ev, &cfg);
    assert!(assessment.is_heavy_tailed() || !assessment.acceptable);
}

#[test]
fn test_tail_risk_assessment_display_contains_p99() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let assessment = assess_tail_risk(&ev, &cfg);
    let s = assessment.to_string();
    assert!(s.contains("p99="));
}

#[test]
fn test_tail_risk_assessment_serde_roundtrip() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let assessment = assess_tail_risk(&ev, &cfg);
    let json = serde_json::to_string(&assessment).unwrap();
    let back: TailRiskAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(assessment, back);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn test_gate_config_default_values() {
    let cfg = GateConfig::default();
    assert_eq!(cfg.max_budget_overrun_fraction, DEFAULT_MAX_BUDGET_OVERRUN);
    assert_eq!(cfg.tail_risk_threshold, DEFAULT_TAIL_RISK_THRESHOLD);
    assert_eq!(cfg.max_tail_heaviness, DEFAULT_MAX_TAIL_HEAVINESS);
    assert_eq!(cfg.regression_sensitivity, DEFAULT_REGRESSION_SENSITIVITY);
    assert_eq!(cfg.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
}

#[test]
fn test_gate_config_strict() {
    let cfg = GateConfig::strict();
    assert_eq!(cfg.max_budget_overrun_fraction, 20_000);
    assert_eq!(cfg.min_sample_count, 100);
}

#[test]
fn test_gate_config_permissive() {
    let cfg = GateConfig::permissive();
    assert_eq!(cfg.max_budget_overrun_fraction, 200_000);
    assert_eq!(cfg.min_sample_count, 5);
}

#[test]
fn test_gate_config_serde_roundtrip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// evaluate (main)
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_pass_no_baseline() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    assert_eq!(result.verdict, GateVerdict::Pass);
    assert!(result.is_passing());
}

#[test]
fn test_evaluate_pass_with_baseline_small_delta() {
    let cfg = GateConfig::default();
    let base = baseline_evidence(ResourceKind::CpuBudget);
    let current = good_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&current, Some(&base), &cfg);
    assert_eq!(result.verdict, GateVerdict::Pass);
    assert!(result.regressions.is_empty());
}

#[test]
fn test_evaluate_insufficient_evidence_low_samples() {
    let cfg = GateConfig::default();
    let mut ev = baseline_evidence(ResourceKind::CpuBudget);
    ev.sample_count = 5;
    let result = evaluate(&ev, None, &cfg);
    assert_eq!(result.verdict, GateVerdict::InsufficientEvidence);
}

#[test]
fn test_evaluate_conditional_pass_with_regressions() {
    let cfg = GateConfig::default();
    let base = baseline_evidence(ResourceKind::CpuBudget);
    let current = overrun_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&current, Some(&base), &cfg);
    assert!(result.verdict == GateVerdict::ConditionalPass || result.verdict == GateVerdict::Fail);
    assert!(!result.regressions.is_empty());
}

#[test]
fn test_evaluate_conditional_pass_overrun_no_baseline() {
    let cfg = GateConfig::default();
    let ev = overrun_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    assert_eq!(result.verdict, GateVerdict::ConditionalPass);
}

#[test]
fn test_evaluate_fail_critical_regression() {
    let cfg = GateConfig::strict();
    let mut base = baseline_evidence(ResourceKind::CpuBudget);
    base.consumed_millionths = 100_000;
    let mut current = overrun_evidence(ResourceKind::CpuBudget);
    current.tail_risk_fraction = 5_000_000;
    let result = evaluate(&current, Some(&base), &cfg);
    assert_eq!(result.verdict, GateVerdict::Fail);
    assert_eq!(result.risk_level, RiskLevel::Critical);
}

// ---------------------------------------------------------------------------
// GateResult accessors
// ---------------------------------------------------------------------------

#[test]
fn test_gate_result_regression_count() {
    let cfg = GateConfig::default();
    let base = baseline_evidence(ResourceKind::CpuBudget);
    let current = overrun_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&current, Some(&base), &cfg);
    assert!(result.regression_count() > 0);
}

#[test]
fn test_gate_result_display_contains_verdict() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    let s = result.to_string();
    assert!(s.contains("pass"));
}

#[test]
fn test_gate_result_serde_roundtrip() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// PublicationConstraint
// ---------------------------------------------------------------------------

#[test]
fn test_publication_constraint_no_regressions_full_claim() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    let pc = &result.publication_constraints[0];
    assert!(!pc.must_disclose);
    assert_eq!(
        pc.max_claimable_improvement,
        DEFAULT_MAX_CLAIMABLE_IMPROVEMENT
    );
}

#[test]
fn test_publication_constraint_overrun_requires_disclosure() {
    let cfg = GateConfig::default();
    let ev = overrun_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    let pc = &result.publication_constraints[0];
    assert!(pc.must_disclose);
    assert!(pc.max_claimable_improvement < DEFAULT_MAX_CLAIMABLE_IMPROVEMENT);
}

#[test]
fn test_publication_constraint_display_contains_resource() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::MemoryBudget);
    let result = evaluate(&ev, None, &cfg);
    let pc = &result.publication_constraints[0];
    let s = pc.to_string();
    assert!(s.contains("memory_budget"));
}

#[test]
fn test_publication_constraint_serde_roundtrip() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    let pc = &result.publication_constraints[0];
    let json = serde_json::to_string(pc).unwrap();
    let back: PublicationConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(*pc, back);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_decision_receipt_from_result() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    let receipt = DecisionReceipt::from_result(&result, &ev);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.verdict, result.verdict);
    assert_eq!(receipt.epoch, ev.epoch);
}

#[test]
fn test_decision_receipt_deterministic_hash() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    let r1 = DecisionReceipt::from_result(&result, &ev);
    let r2 = DecisionReceipt::from_result(&result, &ev);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_decision_receipt_display_contains_component() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    let receipt = DecisionReceipt::from_result(&result, &ev);
    let s = receipt.to_string();
    assert!(s.contains(COMPONENT));
}

#[test]
fn test_decision_receipt_serde_roundtrip() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    let receipt = DecisionReceipt::from_result(&result, &ev);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// Receipt hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_hash_deterministic() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let r1 = evaluate(&ev, None, &cfg);
    let r2 = evaluate(&ev, None, &cfg);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_differs_for_different_resource_kinds() {
    let cfg = GateConfig::default();
    let ev_cpu = baseline_evidence(ResourceKind::CpuBudget);
    let ev_mem = baseline_evidence(ResourceKind::MemoryBudget);
    let r1 = evaluate(&ev_cpu, None, &cfg);
    let r2 = evaluate(&ev_mem, None, &cfg);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_is_32_bytes() {
    let cfg = GateConfig::default();
    let ev = baseline_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    assert_eq!(result.receipt_hash.as_bytes().len(), 32);
}

// ---------------------------------------------------------------------------
// evaluate_batch
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_batch_all_pass() {
    let cfg = GateConfig::default();
    let pairs: Vec<(CertificateEvidence, Option<CertificateEvidence>)> = ResourceKind::ALL
        .iter()
        .map(|k| (baseline_evidence(*k), None))
        .collect();
    let (results, summary) = evaluate_batch(&pairs, &cfg);
    assert_eq!(results.len(), 6);
    assert_eq!(summary.total, 6);
    assert!(summary.all_passing());
    assert!(!summary.has_failures());
}

#[test]
fn test_evaluate_batch_mixed() {
    let cfg = GateConfig::default();
    let good = (baseline_evidence(ResourceKind::CpuBudget), None);
    let mut bad_ev = baseline_evidence(ResourceKind::MemoryBudget);
    bad_ev.sample_count = 1;
    let bad = (bad_ev, None);
    let (results, summary) = evaluate_batch(&[good, bad], &cfg);
    assert_eq!(results.len(), 2);
    assert_eq!(summary.total, 2);
    assert!(summary.passed > 0);
    assert!(summary.insufficient > 0);
}

#[test]
fn test_evaluate_batch_empty() {
    let cfg = GateConfig::default();
    let (results, summary) = evaluate_batch(&[], &cfg);
    assert!(results.is_empty());
    assert_eq!(summary.total, 0);
    assert_eq!(summary.pass_rate, 0);
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

#[test]
fn test_gate_summary_all_passing_true() {
    let cfg = GateConfig::default();
    let pairs: Vec<(CertificateEvidence, Option<CertificateEvidence>)> =
        vec![(baseline_evidence(ResourceKind::CpuBudget), None)];
    let (_, summary) = evaluate_batch(&pairs, &cfg);
    assert!(summary.all_passing());
}

#[test]
fn test_gate_summary_has_failures_false_on_pass() {
    let cfg = GateConfig::default();
    let pairs = vec![(baseline_evidence(ResourceKind::CpuBudget), None)];
    let (_, summary) = evaluate_batch(&pairs, &cfg);
    assert!(!summary.has_failures());
}

#[test]
fn test_gate_summary_display_contains_total() {
    let cfg = GateConfig::default();
    let pairs = vec![(baseline_evidence(ResourceKind::CpuBudget), None)];
    let (_, summary) = evaluate_batch(&pairs, &cfg);
    let s = summary.to_string();
    assert!(s.contains("1"));
}

#[test]
fn test_gate_summary_serde_roundtrip() {
    let cfg = GateConfig::default();
    let pairs = vec![(baseline_evidence(ResourceKind::CpuBudget), None)];
    let (_, summary) = evaluate_batch(&pairs, &cfg);
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn test_gate_summary_pass_rate_calculation() {
    let cfg = GateConfig::default();
    let good = (baseline_evidence(ResourceKind::CpuBudget), None);
    let mut bad_ev = baseline_evidence(ResourceKind::MemoryBudget);
    bad_ev.sample_count = 1;
    let bad = (bad_ev, None);
    let (_, summary) = evaluate_batch(&[good, bad], &cfg);
    assert_eq!(summary.pass_rate, 500_000);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_permissive_config_passes_bad_evidence() {
    let cfg = GateConfig::permissive();
    let ev = overrun_evidence(ResourceKind::CpuBudget);
    let result = evaluate(&ev, None, &cfg);
    assert!(result.is_passing());
}

#[test]
fn test_evaluate_all_resource_kinds_no_baseline() {
    let cfg = GateConfig::default();
    for kind in ResourceKind::ALL {
        let ev = baseline_evidence(*kind);
        let result = evaluate(&ev, None, &cfg);
        assert_eq!(result.verdict, GateVerdict::Pass, "failed for {:?}", kind);
    }
}

#[test]
fn test_certificate_evidence_full_utilisation() {
    let ev = CertificateEvidence {
        resource_kind: ResourceKind::CpuBudget,
        budget_millionths: 1_000_000,
        consumed_millionths: 1_000_000,
        headroom_fraction: 0,
        tail_risk_fraction: 100_000,
        sample_count: 100,
        epoch: epoch(1),
    };
    assert_eq!(ev.utilisation_fraction(), 1_000_000);
    assert!(!ev.is_overrun());
}
