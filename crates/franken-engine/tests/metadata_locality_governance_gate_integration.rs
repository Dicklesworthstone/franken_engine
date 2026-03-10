#![forbid(unsafe_code)]

//! Integration tests for the metadata_locality_governance_gate module.

use frankenengine_engine::metadata_locality_governance_gate::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn good_cache() -> CacheMissEvidence {
    CacheMissEvidence::new("hot_path", 10_000, 30_000, 50_000, 5_000, 100, test_epoch())
}

fn bad_cache() -> CacheMissEvidence {
    CacheMissEvidence::new("cold_path", 200_000, 500_000, 800_000, 100_000, 100, test_epoch())
}

fn marginal_cache() -> CacheMissEvidence {
    // L1 just above threshold (50_000) but below 1.5x (75_000)
    CacheMissEvidence::new("marginal", 60_000, 50_000, 100_000, 10_000, 100, test_epoch())
}

fn good_numa() -> NumaEvidence {
    NumaEvidence::new(0, 900_000, 100_000, 500_000, 50_000, test_epoch())
}

fn bad_numa() -> NumaEvidence {
    NumaEvidence::new(0, 300_000, 700_000, 900_000, 500_000, test_epoch())
}

fn good_portability() -> PortabilityEvidence {
    PortabilityEvidence::new("x86_64", "aarch64", 900_000, vec![], test_epoch())
}

fn degraded_portability() -> PortabilityEvidence {
    PortabilityEvidence::new(
        "x86_64",
        "aarch64",
        800_000,
        vec!["vector width mismatch".into()],
        test_epoch(),
    )
}

fn bad_portability() -> PortabilityEvidence {
    PortabilityEvidence::new("x86_64", "aarch64", 300_000, vec!["no AVX".into()], test_epoch())
}

fn good_observability() -> ObservabilityImpact {
    ObservabilityImpact::new(20_000, 5_000, true)
}

fn bad_observability() -> ObservabilityImpact {
    ObservabilityImpact::new(200_000, 5_000, false)
}

fn default_config() -> GateConfig {
    GateConfig::default()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_value() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.metadata-locality-governance-gate.v1"
    );
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "metadata_locality_governance_gate");
}

#[test]
fn test_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.26.3");
}

#[test]
fn test_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-626C");
}

#[test]
fn test_default_max_l1_miss_rate() {
    assert_eq!(DEFAULT_MAX_L1_MISS_RATE, 50_000);
}

#[test]
fn test_default_max_l2_miss_rate() {
    assert_eq!(DEFAULT_MAX_L2_MISS_RATE, 100_000);
}

#[test]
fn test_default_max_l3_miss_rate() {
    assert_eq!(DEFAULT_MAX_L3_MISS_RATE, 200_000);
}

#[test]
fn test_default_max_tlb_miss_rate() {
    assert_eq!(DEFAULT_MAX_TLB_MISS_RATE, 20_000);
}

#[test]
fn test_default_min_local_access_fraction() {
    assert_eq!(DEFAULT_MIN_LOCAL_ACCESS_FRACTION, 800_000);
}

#[test]
fn test_default_max_observability_overhead() {
    assert_eq!(DEFAULT_MAX_OBSERVABILITY_OVERHEAD, 50_000);
}

#[test]
fn test_default_min_portability_fraction() {
    assert_eq!(DEFAULT_MIN_PORTABILITY_FRACTION, 700_000);
}

#[test]
fn test_min_sample_count() {
    assert_eq!(MIN_SAMPLE_COUNT, 10);
}

// ---------------------------------------------------------------------------
// LocalityDomain
// ---------------------------------------------------------------------------

#[test]
fn test_locality_domain_all_variants() {
    assert_eq!(LocalityDomain::ALL.len(), 6);
}

#[test]
fn test_locality_domain_serde_roundtrip() {
    for variant in LocalityDomain::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: LocalityDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_locality_domain_display() {
    assert_eq!(LocalityDomain::CacheLine.to_string(), "cache_line");
    assert_eq!(LocalityDomain::RemoteMemory.to_string(), "remote_memory");
    assert_eq!(LocalityDomain::NumaNode.to_string(), "numa_node");
}

#[test]
fn test_locality_domain_latency_ordering() {
    let weights: Vec<u64> = LocalityDomain::ALL.iter().map(|d| d.latency_weight()).collect();
    for i in 1..weights.len() {
        assert!(weights[i] >= weights[i - 1]);
    }
}

#[test]
fn test_locality_domain_latency_weight_range() {
    for variant in LocalityDomain::ALL {
        let w = variant.latency_weight();
        assert!(w > 0 && w <= 1_000_000);
    }
}

// ---------------------------------------------------------------------------
// PortabilityVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_portability_verdict_all_variants() {
    assert_eq!(PortabilityVerdict::ALL.len(), 4);
}

#[test]
fn test_portability_verdict_serde_roundtrip() {
    for variant in PortabilityVerdict::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: PortabilityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_portability_verdict_display() {
    assert_eq!(PortabilityVerdict::Portable.to_string(), "portable");
    assert_eq!(PortabilityVerdict::MachineSpecific.to_string(), "machine_specific");
    assert_eq!(PortabilityVerdict::Unknown.to_string(), "unknown");
}

#[test]
fn test_portability_verdict_permits_deployment() {
    assert!(PortabilityVerdict::Portable.permits_deployment());
    assert!(PortabilityVerdict::ConditionallyPortable.permits_deployment());
    assert!(!PortabilityVerdict::MachineSpecific.permits_deployment());
    assert!(!PortabilityVerdict::Unknown.permits_deployment());
}

// ---------------------------------------------------------------------------
// GovernanceDecision
// ---------------------------------------------------------------------------

#[test]
fn test_governance_decision_all_variants() {
    assert_eq!(GovernanceDecision::ALL.len(), 4);
}

#[test]
fn test_governance_decision_serde_roundtrip() {
    for variant in GovernanceDecision::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: GovernanceDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_governance_decision_display() {
    assert_eq!(GovernanceDecision::Approve.to_string(), "approve");
    assert_eq!(GovernanceDecision::Reject.to_string(), "reject");
    assert_eq!(GovernanceDecision::ConditionalApprove.to_string(), "conditional_approve");
    assert_eq!(GovernanceDecision::RequireEvidence.to_string(), "require_evidence");
}

#[test]
fn test_governance_decision_allows_deployment() {
    assert!(GovernanceDecision::Approve.allows_deployment());
    assert!(GovernanceDecision::ConditionalApprove.allows_deployment());
    assert!(!GovernanceDecision::Reject.allows_deployment());
    assert!(!GovernanceDecision::RequireEvidence.allows_deployment());
}

// ---------------------------------------------------------------------------
// NumaPolicy
// ---------------------------------------------------------------------------

#[test]
fn test_numa_policy_all_variants() {
    assert_eq!(NumaPolicy::ALL.len(), 4);
}

#[test]
fn test_numa_policy_serde_roundtrip() {
    for variant in NumaPolicy::ALL {
        let json = serde_json::to_string(variant).unwrap();
        let back: NumaPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, back);
    }
}

#[test]
fn test_numa_policy_display() {
    assert_eq!(NumaPolicy::FirstTouch.to_string(), "first_touch");
    assert_eq!(NumaPolicy::Interleave.to_string(), "interleave");
    assert_eq!(NumaPolicy::Bind.to_string(), "bind");
    assert_eq!(NumaPolicy::Preferred.to_string(), "preferred");
}

// ---------------------------------------------------------------------------
// CacheMissEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_cache_miss_evidence_new() {
    let ev = good_cache();
    assert_eq!(ev.domain, "hot_path");
    assert_eq!(ev.l1_miss_rate, 10_000);
    assert_eq!(ev.sample_count, 100);
    assert!(ev.has_sufficient_samples());
}

#[test]
fn test_cache_miss_evidence_insufficient_samples() {
    let ev = CacheMissEvidence::new("x", 10_000, 20_000, 30_000, 5_000, 3, test_epoch());
    assert!(!ev.has_sufficient_samples());
}

#[test]
fn test_cache_miss_evidence_content_hash_deterministic() {
    let a = good_cache();
    let b = good_cache();
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn test_cache_miss_evidence_content_hash_differs_for_different_data() {
    let a = good_cache();
    let b = bad_cache();
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn test_cache_miss_evidence_dominant_domain_l1_zero() {
    let ev = CacheMissEvidence::new("x", 0, 10_000, 20_000, 5_000, 100, test_epoch());
    assert_eq!(ev.dominant_domain(), LocalityDomain::CacheLine);
}

#[test]
fn test_cache_miss_evidence_dominant_domain_l2_zero() {
    let ev = CacheMissEvidence::new("x", 10_000, 0, 20_000, 5_000, 100, test_epoch());
    assert_eq!(ev.dominant_domain(), LocalityDomain::TlbPage);
}

#[test]
fn test_cache_miss_evidence_dominant_domain_l3_zero() {
    let ev = CacheMissEvidence::new("x", 10_000, 20_000, 0, 5_000, 100, test_epoch());
    assert_eq!(ev.dominant_domain(), LocalityDomain::NumaNode);
}

#[test]
fn test_cache_miss_evidence_dominant_domain_all_nonzero() {
    let ev = CacheMissEvidence::new("x", 10_000, 20_000, 30_000, 5_000, 100, test_epoch());
    assert_eq!(ev.dominant_domain(), LocalityDomain::CrossSocket);
}

#[test]
fn test_cache_miss_evidence_display() {
    let ev = good_cache();
    let s = ev.to_string();
    assert!(s.contains("CacheMiss"));
    assert!(s.contains("hot_path"));
}

#[test]
fn test_cache_miss_evidence_serde_roundtrip() {
    let ev = good_cache();
    let json = serde_json::to_string(&ev).unwrap();
    let back: CacheMissEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// NumaEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_numa_evidence_new() {
    let ev = good_numa();
    assert_eq!(ev.node_id, 0);
    assert_eq!(ev.local_access_fraction, 900_000);
}

#[test]
fn test_numa_evidence_content_hash_deterministic() {
    let a = good_numa();
    let b = good_numa();
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn test_numa_evidence_is_local_dominant() {
    let ev = good_numa();
    assert!(ev.is_local_dominant(800_000));
    assert!(!ev.is_local_dominant(950_000));
}

#[test]
fn test_numa_evidence_effective_latency_multiplier() {
    let ev = good_numa();
    // 1_000_000 + 50_000 = 1_050_000
    assert_eq!(ev.effective_latency_multiplier(), 1_050_000);
}

#[test]
fn test_numa_evidence_display() {
    let ev = good_numa();
    let s = ev.to_string();
    assert!(s.contains("NUMA"));
    assert!(s.contains("node=0"));
}

#[test]
fn test_numa_evidence_serde_roundtrip() {
    let ev = good_numa();
    let json = serde_json::to_string(&ev).unwrap();
    let back: NumaEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// PortabilityEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_portability_evidence_new() {
    let ev = good_portability();
    assert_eq!(ev.source_topology, "x86_64");
    assert_eq!(ev.target_topology, "aarch64");
    assert_eq!(ev.transferable_fraction, 900_000);
    assert!(!ev.has_degradation());
    assert_eq!(ev.degradation_count(), 0);
}

#[test]
fn test_portability_evidence_with_degradation() {
    let ev = degraded_portability();
    assert!(ev.has_degradation());
    assert_eq!(ev.degradation_count(), 1);
}

#[test]
fn test_portability_evidence_content_hash_deterministic() {
    let a = good_portability();
    let b = good_portability();
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn test_portability_evidence_display() {
    let ev = good_portability();
    let s = ev.to_string();
    assert!(s.contains("Portability"));
    assert!(s.contains("x86_64"));
    assert!(s.contains("aarch64"));
}

#[test]
fn test_portability_evidence_serde_roundtrip() {
    let ev = degraded_portability();
    let json = serde_json::to_string(&ev).unwrap();
    let back: PortabilityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// ObservabilityImpact
// ---------------------------------------------------------------------------

#[test]
fn test_observability_impact_new() {
    let oi = good_observability();
    assert_eq!(oi.instrumented_overhead, 20_000);
    assert_eq!(oi.uninstrumented_baseline, 5_000);
    assert_eq!(oi.delta_fraction, 15_000);
    assert!(oi.acceptable);
}

#[test]
fn test_observability_impact_exceeds_threshold() {
    let oi = bad_observability();
    assert!(oi.exceeds_threshold(50_000));
    assert!(!good_observability().exceeds_threshold(50_000));
}

#[test]
fn test_observability_impact_overhead_ratio() {
    let oi = ObservabilityImpact::new(100_000, 50_000, true);
    // ratio = 100_000 * 1_000_000 / 50_000 = 2_000_000
    assert_eq!(oi.overhead_ratio(), 2_000_000);
}

#[test]
fn test_observability_impact_overhead_ratio_zero_baseline() {
    let oi = ObservabilityImpact::new(100_000, 0, true);
    // base = 1 because baseline is 0
    assert_eq!(oi.overhead_ratio(), 100_000 * 1_000_000);
}

#[test]
fn test_observability_impact_display() {
    let oi = good_observability();
    let s = oi.to_string();
    assert!(s.contains("Observability"));
    assert!(s.contains("delta="));
}

#[test]
fn test_observability_impact_serde_roundtrip() {
    let oi = good_observability();
    let json = serde_json::to_string(&oi).unwrap();
    let back: ObservabilityImpact = serde_json::from_str(&json).unwrap();
    assert_eq!(oi, back);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn test_gate_config_default() {
    let cfg = default_config();
    assert_eq!(cfg.max_l1_miss_rate, DEFAULT_MAX_L1_MISS_RATE);
    assert_eq!(cfg.max_l2_miss_rate, DEFAULT_MAX_L2_MISS_RATE);
    assert_eq!(cfg.max_l3_miss_rate, DEFAULT_MAX_L3_MISS_RATE);
    assert_eq!(cfg.max_tlb_miss_rate, DEFAULT_MAX_TLB_MISS_RATE);
    assert_eq!(cfg.min_local_access_fraction, DEFAULT_MIN_LOCAL_ACCESS_FRACTION);
    assert_eq!(cfg.max_observability_overhead, DEFAULT_MAX_OBSERVABILITY_OVERHEAD);
    assert_eq!(cfg.min_portability_fraction, DEFAULT_MIN_PORTABILITY_FRACTION);
}

#[test]
fn test_gate_config_display() {
    let cfg = default_config();
    let s = cfg.to_string();
    assert!(s.contains("GateConfig"));
    assert!(s.contains("L1<="));
}

#[test]
fn test_gate_config_serde_roundtrip() {
    let cfg = default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// evaluate_cache_locality
// ---------------------------------------------------------------------------

#[test]
fn test_eval_cache_approve() {
    let decision = evaluate_cache_locality(&good_cache(), &default_config());
    assert_eq!(decision, GovernanceDecision::Approve);
}

#[test]
fn test_eval_cache_reject() {
    let decision = evaluate_cache_locality(&bad_cache(), &default_config());
    assert_eq!(decision, GovernanceDecision::Reject);
}

#[test]
fn test_eval_cache_conditional() {
    let decision = evaluate_cache_locality(&marginal_cache(), &default_config());
    assert_eq!(decision, GovernanceDecision::ConditionalApprove);
}

#[test]
fn test_eval_cache_insufficient_samples() {
    let ev = CacheMissEvidence::new("x", 10_000, 20_000, 30_000, 5_000, 3, test_epoch());
    let decision = evaluate_cache_locality(&ev, &default_config());
    assert_eq!(decision, GovernanceDecision::RequireEvidence);
}

// ---------------------------------------------------------------------------
// evaluate_numa
// ---------------------------------------------------------------------------

#[test]
fn test_eval_numa_approve() {
    let decision = evaluate_numa(&good_numa(), &default_config());
    assert_eq!(decision, GovernanceDecision::Approve);
}

#[test]
fn test_eval_numa_reject() {
    let decision = evaluate_numa(&bad_numa(), &default_config());
    assert_eq!(decision, GovernanceDecision::Reject);
}

#[test]
fn test_eval_numa_conditional() {
    // Conditional band: 80% of 800_000 = 640_000
    let ev = NumaEvidence::new(0, 700_000, 300_000, 500_000, 100_000, test_epoch());
    let decision = evaluate_numa(&ev, &default_config());
    assert_eq!(decision, GovernanceDecision::ConditionalApprove);
}

// ---------------------------------------------------------------------------
// evaluate_portability
// ---------------------------------------------------------------------------

#[test]
fn test_eval_portability_portable() {
    let verdict = evaluate_portability(&good_portability(), &default_config());
    assert_eq!(verdict, PortabilityVerdict::Portable);
}

#[test]
fn test_eval_portability_conditionally_portable() {
    let verdict = evaluate_portability(&degraded_portability(), &default_config());
    assert_eq!(verdict, PortabilityVerdict::ConditionallyPortable);
}

#[test]
fn test_eval_portability_machine_specific() {
    let verdict = evaluate_portability(&bad_portability(), &default_config());
    assert_eq!(verdict, PortabilityVerdict::MachineSpecific);
}

#[test]
fn test_eval_portability_unknown_pathological() {
    let ev = PortabilityEvidence::new("x86_64", "x86_64", 0, vec![], test_epoch());
    let verdict = evaluate_portability(&ev, &default_config());
    assert_eq!(verdict, PortabilityVerdict::Unknown);
}

// ---------------------------------------------------------------------------
// evaluate (full gate)
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_no_evidence() {
    let result = evaluate(None, None, None, None, &default_config());
    assert_eq!(result.decision, GovernanceDecision::RequireEvidence);
    assert!(!result.is_approved());
    assert!(!result.blocking_reasons.is_empty());
}

#[test]
fn test_evaluate_all_good() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        Some(&good_observability()),
        &default_config(),
    );
    assert_eq!(result.decision, GovernanceDecision::Approve);
    assert!(result.is_approved());
    assert_eq!(result.blocking_count(), 0);
}

#[test]
fn test_evaluate_bad_cache_rejects() {
    let result = evaluate(
        Some(&bad_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        Some(&good_observability()),
        &default_config(),
    );
    assert_eq!(result.decision, GovernanceDecision::Reject);
    assert!(!result.is_approved());
}

#[test]
fn test_evaluate_bad_numa_rejects() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&bad_numa()),
        Some(&good_portability()),
        None,
        &default_config(),
    );
    assert_eq!(result.decision, GovernanceDecision::Reject);
}

#[test]
fn test_evaluate_bad_portability_rejects() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&bad_portability()),
        None,
        &default_config(),
    );
    assert_eq!(result.decision, GovernanceDecision::Reject);
}

#[test]
fn test_evaluate_bad_observability_rejects() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        Some(&bad_observability()),
        &default_config(),
    );
    assert_eq!(result.decision, GovernanceDecision::Reject);
}

#[test]
fn test_evaluate_marginal_cache_conditional() {
    let result = evaluate(
        Some(&marginal_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        Some(&good_observability()),
        &default_config(),
    );
    assert_eq!(result.decision, GovernanceDecision::ConditionalApprove);
    assert!(result.is_approved());
}

#[test]
fn test_evaluate_receipt_hash_deterministic() {
    let a = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        Some(&good_observability()),
        &default_config(),
    );
    let b = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        Some(&good_observability()),
        &default_config(),
    );
    assert_eq!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_evaluate_cache_only() {
    let result = evaluate(
        Some(&good_cache()),
        None,
        None,
        None,
        &default_config(),
    );
    // Approve for cache, but missing portability -> Unknown (recommendations but not blocking)
    assert!(result.decision.allows_deployment());
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

#[test]
fn test_gate_result_display() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        None,
        &default_config(),
    );
    let s = result.to_string();
    assert!(s.contains("GateResult"));
}

#[test]
fn test_gate_result_serde_roundtrip() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        None,
        &default_config(),
    );
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_decision_receipt_new() {
    let ev_hash = ContentHash::compute(b"test");
    let receipt = DecisionReceipt::new(COMPONENT, test_epoch(), GovernanceDecision::Approve, ev_hash.clone());
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.epoch, test_epoch());
    assert_eq!(receipt.decision, GovernanceDecision::Approve);
    assert_eq!(receipt.evidence_hash, ev_hash);
}

#[test]
fn test_decision_receipt_hash_deterministic() {
    let ev_hash = ContentHash::compute(b"test");
    let a = DecisionReceipt::new(COMPONENT, test_epoch(), GovernanceDecision::Approve, ev_hash.clone());
    let b = DecisionReceipt::new(COMPONENT, test_epoch(), GovernanceDecision::Approve, ev_hash);
    assert_eq!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_decision_receipt_different_decisions_differ() {
    let ev_hash = ContentHash::compute(b"test");
    let a = DecisionReceipt::new(COMPONENT, test_epoch(), GovernanceDecision::Approve, ev_hash.clone());
    let b = DecisionReceipt::new(COMPONENT, test_epoch(), GovernanceDecision::Reject, ev_hash);
    assert_ne!(a.receipt_hash, b.receipt_hash);
}

#[test]
fn test_decision_receipt_display() {
    let ev_hash = ContentHash::compute(b"test");
    let receipt = DecisionReceipt::new(COMPONENT, test_epoch(), GovernanceDecision::Reject, ev_hash);
    let s = receipt.to_string();
    assert!(s.contains("Receipt"));
    assert!(s.contains("reject"));
    assert!(s.contains("epoch=42"));
}

#[test]
fn test_decision_receipt_serde_roundtrip() {
    let ev_hash = ContentHash::compute(b"test");
    let receipt = DecisionReceipt::new(COMPONENT, test_epoch(), GovernanceDecision::Approve, ev_hash);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// build_receipt
// ---------------------------------------------------------------------------

#[test]
fn test_build_receipt_from_gate_result() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        Some(&good_observability()),
        &default_config(),
    );
    let receipt = build_receipt(&result, test_epoch());
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.decision, GovernanceDecision::Approve);
    assert_eq!(receipt.epoch, test_epoch());
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

#[test]
fn test_gate_summary_new() {
    let summary = GateSummary::new();
    assert_eq!(summary.total_evaluated, 0);
    assert_eq!(summary.approved, 0);
    assert_eq!(summary.pass_rate, 0);
}

#[test]
fn test_gate_summary_default() {
    let summary = GateSummary::default();
    assert_eq!(summary.total_evaluated, 0);
}

#[test]
fn test_gate_summary_record() {
    let mut summary = GateSummary::new();
    summary.record(GovernanceDecision::Approve);
    summary.record(GovernanceDecision::ConditionalApprove);
    summary.record(GovernanceDecision::Reject);
    assert_eq!(summary.total_evaluated, 3);
    assert_eq!(summary.approved, 1);
    assert_eq!(summary.conditional, 1);
    assert_eq!(summary.rejected, 1);
    assert!(!summary.all_passed());
}

#[test]
fn test_gate_summary_all_passed() {
    let mut summary = GateSummary::new();
    summary.record(GovernanceDecision::Approve);
    summary.record(GovernanceDecision::ConditionalApprove);
    assert!(summary.all_passed());
    assert_eq!(summary.pass_rate, 1_000_000);
}

#[test]
fn test_gate_summary_failure_rate() {
    let mut summary = GateSummary::new();
    summary.record(GovernanceDecision::Approve);
    summary.record(GovernanceDecision::Reject);
    assert_eq!(summary.failure_rate(), 500_000);
}

#[test]
fn test_gate_summary_display() {
    let summary = GateSummary::new();
    let s = summary.to_string();
    assert!(s.contains("GateSummary"));
}

#[test]
fn test_gate_summary_serde_roundtrip() {
    let mut summary = GateSummary::new();
    summary.record(GovernanceDecision::Approve);
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// build_canonical_evidence
// ---------------------------------------------------------------------------

#[test]
fn test_build_canonical_evidence() {
    let evidence = build_canonical_evidence();
    assert!(!evidence.is_empty());
    for ev in &evidence {
        assert!(!ev.domain.is_empty());
        assert!(ev.sample_count > 0);
    }
}
