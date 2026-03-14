#![forbid(unsafe_code)]

//! Enrichment integration tests for metadata_locality_governance_gate module.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::metadata_locality_governance_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn good_cache() -> CacheMissEvidence {
    CacheMissEvidence::new("hot_path", 10_000, 30_000, 50_000, 5_000, 100, epoch())
}

fn good_numa() -> NumaEvidence {
    NumaEvidence::new(0, 900_000, 100_000, 500_000, 50_000, epoch())
}

fn good_portability() -> PortabilityEvidence {
    PortabilityEvidence::new("x86_64", "aarch64", 900_000, vec![], epoch())
}

fn good_observability() -> ObservabilityImpact {
    ObservabilityImpact::new(20_000, 5_000, true)
}

fn default_cfg() -> GateConfig {
    GateConfig::default()
}

// ── LocalityDomain ──────────────────────────────────────────────────────

#[test]
fn enrichment_locality_domain_copy_semantics() {
    let a = LocalityDomain::CacheLine;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_locality_domain_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in LocalityDomain::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 6);
    for v in LocalityDomain::ALL {
        assert!(!set.insert(*v));
    }
}

#[test]
fn enrichment_locality_domain_debug_all_unique() {
    let debugs: BTreeSet<String> = LocalityDomain::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_locality_domain_display_all_unique() {
    let displays: BTreeSet<String> = LocalityDomain::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_locality_domain_as_str_matches_display() {
    for v in LocalityDomain::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

#[test]
fn enrichment_locality_domain_latency_weight_strictly_positive() {
    for v in LocalityDomain::ALL {
        assert!(v.latency_weight() > 0);
        assert!(v.latency_weight() <= 1_000_000);
    }
}

// ── PortabilityVerdict ──────────────────────────────────────────────────

#[test]
fn enrichment_portability_verdict_copy_semantics() {
    let a = PortabilityVerdict::Portable;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_portability_verdict_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in PortabilityVerdict::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_portability_verdict_debug_all_unique() {
    let debugs: BTreeSet<String> = PortabilityVerdict::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_portability_verdict_display_all_unique() {
    let displays: BTreeSet<String> = PortabilityVerdict::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_portability_verdict_as_str_matches_display() {
    for v in PortabilityVerdict::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

#[test]
fn enrichment_portability_verdict_exactly_two_permit_deploy() {
    let count = PortabilityVerdict::ALL
        .iter()
        .filter(|v| v.permits_deployment())
        .count();
    assert_eq!(count, 2);
}

// ── GovernanceDecision ──────────────────────────────────────────────────

#[test]
fn enrichment_governance_decision_copy_semantics() {
    let a = GovernanceDecision::Approve;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_governance_decision_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in GovernanceDecision::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_governance_decision_debug_all_unique() {
    let debugs: BTreeSet<String> = GovernanceDecision::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_governance_decision_display_all_unique() {
    let displays: BTreeSet<String> = GovernanceDecision::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_governance_decision_as_str_matches_display() {
    for v in GovernanceDecision::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

#[test]
fn enrichment_governance_decision_exactly_two_allow_deploy() {
    let count = GovernanceDecision::ALL
        .iter()
        .filter(|v| v.allows_deployment())
        .count();
    assert_eq!(count, 2);
}

// ── NumaPolicy ──────────────────────────────────────────────────────────

#[test]
fn enrichment_numa_policy_copy_semantics() {
    let a = NumaPolicy::Bind;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_numa_policy_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in NumaPolicy::ALL {
        assert!(set.insert(*v));
    }
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_numa_policy_debug_all_unique() {
    let debugs: BTreeSet<String> = NumaPolicy::ALL.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_numa_policy_display_all_unique() {
    let displays: BTreeSet<String> = NumaPolicy::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_numa_policy_as_str_matches_display() {
    for v in NumaPolicy::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

// ── CacheMissEvidence ───────────────────────────────────────────────────

#[test]
fn enrichment_cache_miss_clone_independence() {
    let a = good_cache();
    let b = a.clone();
    assert_eq!(a, b);
    let json_a = serde_json::to_string(&a).unwrap();
    let json_b = serde_json::to_string(&b).unwrap();
    assert_eq!(json_a, json_b);
}

#[test]
fn enrichment_cache_miss_json_field_names() {
    let ev = good_cache();
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "domain",
        "l1_miss_rate",
        "l2_miss_rate",
        "l3_miss_rate",
        "tlb_miss_rate",
        "sample_count",
        "epoch",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 7);
}

#[test]
fn enrichment_cache_miss_debug_nonempty() {
    let ev = good_cache();
    let d = format!("{ev:?}");
    assert!(!d.is_empty());
    assert!(d.contains("CacheMissEvidence"));
}

#[test]
fn enrichment_cache_miss_display_contains_all_rates() {
    let ev = good_cache();
    let s = ev.to_string();
    assert!(s.contains("10000"));
    assert!(s.contains("30000"));
    assert!(s.contains("50000"));
    assert!(s.contains("5000"));
}

#[test]
fn enrichment_cache_miss_boundary_exactly_at_min_samples() {
    let ev = CacheMissEvidence::new("boundary", 10_000, 20_000, 30_000, 5_000, 10, epoch());
    assert!(ev.has_sufficient_samples());
}

#[test]
fn enrichment_cache_miss_boundary_one_below_min_samples() {
    let ev = CacheMissEvidence::new("boundary", 10_000, 20_000, 30_000, 5_000, 9, epoch());
    assert!(!ev.has_sufficient_samples());
}

#[test]
fn enrichment_cache_miss_dominant_domain_l2_zero() {
    let ev = CacheMissEvidence::new("x", 10_000, 0, 20_000, 5_000, 100, epoch());
    assert_eq!(ev.dominant_domain(), LocalityDomain::TlbPage);
}

#[test]
fn enrichment_cache_miss_dominant_domain_l3_zero() {
    let ev = CacheMissEvidence::new("x", 10_000, 20_000, 0, 5_000, 100, epoch());
    assert_eq!(ev.dominant_domain(), LocalityDomain::NumaNode);
}

#[test]
fn enrichment_cache_miss_content_hash_differs_on_domain() {
    let a = CacheMissEvidence::new("alpha", 10_000, 20_000, 30_000, 5_000, 100, epoch());
    let b = CacheMissEvidence::new("beta", 10_000, 20_000, 30_000, 5_000, 100, epoch());
    assert_ne!(a.content_hash(), b.content_hash());
}

// ── NumaEvidence ────────────────────────────────────────────────────────

#[test]
fn enrichment_numa_evidence_clone_independence() {
    let a = good_numa();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_numa_evidence_json_field_names() {
    let ev = good_numa();
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "node_id",
        "local_access_fraction",
        "cross_socket_fraction",
        "bandwidth_utilization",
        "latency_penalty",
        "epoch",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 6);
}

#[test]
fn enrichment_numa_evidence_debug_nonempty() {
    let ev = good_numa();
    let d = format!("{ev:?}");
    assert!(!d.is_empty());
    assert!(d.contains("NumaEvidence"));
}

#[test]
fn enrichment_numa_evidence_is_local_dominant_exact_threshold() {
    let ev = NumaEvidence::new(0, 800_000, 200_000, 500_000, 50_000, epoch());
    assert!(ev.is_local_dominant(800_000));
}

#[test]
fn enrichment_numa_evidence_is_local_dominant_one_below() {
    let ev = NumaEvidence::new(0, 799_999, 200_001, 500_000, 50_000, epoch());
    assert!(!ev.is_local_dominant(800_000));
}

#[test]
fn enrichment_numa_evidence_content_hash_differs_on_node() {
    let a = NumaEvidence::new(0, 900_000, 100_000, 500_000, 50_000, epoch());
    let b = NumaEvidence::new(1, 900_000, 100_000, 500_000, 50_000, epoch());
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn enrichment_numa_evidence_latency_multiplier_zero_penalty() {
    let ev = NumaEvidence::new(0, 900_000, 100_000, 500_000, 0, epoch());
    assert_eq!(ev.effective_latency_multiplier(), 1_000_000);
}

// ── PortabilityEvidence ─────────────────────────────────────────────────

#[test]
fn enrichment_portability_evidence_clone_independence() {
    let a = good_portability();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_portability_evidence_json_field_names() {
    let ev = good_portability();
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "source_topology",
        "target_topology",
        "transferable_fraction",
        "degradation_factors",
        "epoch",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 5);
}

#[test]
fn enrichment_portability_evidence_debug_nonempty() {
    let ev = good_portability();
    let d = format!("{ev:?}");
    assert!(!d.is_empty());
    assert!(d.contains("PortabilityEvidence"));
}

#[test]
fn enrichment_portability_evidence_multiple_degradation_factors() {
    let ev = PortabilityEvidence::new(
        "x86_64",
        "riscv64",
        750_000,
        vec![
            "vector_width".into(),
            "cache_line_size".into(),
            "atomics_model".into(),
        ],
        epoch(),
    );
    assert!(ev.has_degradation());
    assert_eq!(ev.degradation_count(), 3);
}

#[test]
fn enrichment_portability_evidence_content_hash_differs_on_topology() {
    let a = PortabilityEvidence::new("x86_64", "aarch64", 900_000, vec![], epoch());
    let b = PortabilityEvidence::new("x86_64", "riscv64", 900_000, vec![], epoch());
    assert_ne!(a.content_hash(), b.content_hash());
}

// ── ObservabilityImpact ─────────────────────────────────────────────────

#[test]
fn enrichment_observability_clone_independence() {
    let a = good_observability();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_observability_json_field_names() {
    let oi = good_observability();
    let v: serde_json::Value = serde_json::to_value(&oi).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "instrumented_overhead",
        "uninstrumented_baseline",
        "delta_fraction",
        "acceptable",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 4);
}

#[test]
fn enrichment_observability_debug_nonempty() {
    let oi = good_observability();
    let d = format!("{oi:?}");
    assert!(!d.is_empty());
    assert!(d.contains("ObservabilityImpact"));
}

#[test]
fn enrichment_observability_delta_computed_correctly() {
    let oi = ObservabilityImpact::new(100_000, 30_000, true);
    assert_eq!(oi.delta_fraction, 70_000);
}

#[test]
fn enrichment_observability_delta_saturates_at_zero() {
    let oi = ObservabilityImpact::new(10_000, 50_000, true);
    assert_eq!(oi.delta_fraction, 0);
}

#[test]
fn enrichment_observability_exceeds_exact_threshold() {
    let oi = ObservabilityImpact::new(100_000, 50_000, true);
    // delta = 50_000, threshold = 50_000 => not exceeds (> not >=)
    assert!(!oi.exceeds_threshold(50_000));
}

#[test]
fn enrichment_observability_exceeds_one_above_threshold() {
    let oi = ObservabilityImpact::new(100_001, 50_000, true);
    // delta = 50_001, threshold = 50_000 => exceeds
    assert!(oi.exceeds_threshold(50_000));
}

// ── GateConfig ──────────────────────────────────────────────────────────

#[test]
fn enrichment_gate_config_clone_independence() {
    let a = default_cfg();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_config_json_field_names() {
    let cfg = default_cfg();
    let v: serde_json::Value = serde_json::to_value(&cfg).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "max_l1_miss_rate",
        "max_l2_miss_rate",
        "max_l3_miss_rate",
        "max_tlb_miss_rate",
        "min_local_access_fraction",
        "max_observability_overhead",
        "min_portability_fraction",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 7);
}

#[test]
fn enrichment_gate_config_debug_nonempty() {
    let cfg = default_cfg();
    let d = format!("{cfg:?}");
    assert!(!d.is_empty());
    assert!(d.contains("GateConfig"));
}

#[test]
fn enrichment_gate_config_custom_changes_cache_decision() {
    let mut cfg = default_cfg();
    cfg.max_l1_miss_rate = 5_000; // Tighten L1 threshold
    let ev = CacheMissEvidence::new("x", 10_000, 20_000, 30_000, 5_000, 100, epoch());
    let decision = evaluate_cache_locality(&ev, &cfg);
    // 10_000 > 5_000 but < 1.5 * 5_000 = 7_500 ... no, 10_000 > 7_500 => Reject
    assert_eq!(decision, GovernanceDecision::Reject);
}

#[test]
fn enrichment_gate_config_custom_changes_numa_decision() {
    let mut cfg = default_cfg();
    cfg.min_local_access_fraction = 950_000; // Tighten
    let ev = NumaEvidence::new(0, 900_000, 100_000, 500_000, 50_000, epoch());
    let decision = evaluate_numa(&ev, &cfg);
    // 900_000 < 950_000, floor = 950_000 * 0.8 = 760_000, 900_000 >= 760_000 => Conditional
    assert_eq!(decision, GovernanceDecision::ConditionalApprove);
}

#[test]
fn enrichment_gate_config_custom_changes_portability_verdict() {
    let mut cfg = default_cfg();
    cfg.min_portability_fraction = 950_000; // Tighten
    let ev = PortabilityEvidence::new("x86_64", "aarch64", 900_000, vec![], epoch());
    let verdict = evaluate_portability(&ev, &cfg);
    // 900_000 < 950_000 => MachineSpecific
    assert_eq!(verdict, PortabilityVerdict::MachineSpecific);
}

// ── GateResult ──────────────────────────────────────────────────────────

#[test]
fn enrichment_gate_result_clone_independence() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        Some(&good_observability()),
        &default_cfg(),
    );
    let cloned = result.clone();
    assert_eq!(result, cloned);
}

#[test]
fn enrichment_gate_result_json_field_names() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        None,
        None,
        &default_cfg(),
    );
    let v: serde_json::Value = serde_json::to_value(&result).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "decision",
        "locality_verdict",
        "portability_verdict",
        "blocking_reasons",
        "recommendations",
        "receipt_hash",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 6);
}

#[test]
fn enrichment_gate_result_debug_nonempty() {
    let result = evaluate(Some(&good_cache()), None, None, None, &default_cfg());
    let d = format!("{result:?}");
    assert!(!d.is_empty());
    assert!(d.contains("GateResult"));
}

#[test]
fn enrichment_gate_result_blocking_count_matches_reasons() {
    let bad_cache = CacheMissEvidence::new("bad", 200_000, 500_000, 800_000, 100_000, 100, epoch());
    let result = evaluate(Some(&bad_cache), None, None, None, &default_cfg());
    assert_eq!(result.blocking_count(), result.blocking_reasons.len());
    assert!(result.blocking_count() > 0);
}

// ── DecisionReceipt ─────────────────────────────────────────────────────

#[test]
fn enrichment_decision_receipt_clone_independence() {
    let hash = ContentHash::compute(b"test");
    let a = DecisionReceipt::new(COMPONENT, epoch(), GovernanceDecision::Approve, hash);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_decision_receipt_json_field_names() {
    let hash = ContentHash::compute(b"test");
    let receipt = DecisionReceipt::new(COMPONENT, epoch(), GovernanceDecision::Approve, hash);
    let v: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "receipt_hash",
        "component",
        "epoch",
        "decision",
        "evidence_hash",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 5);
}

#[test]
fn enrichment_decision_receipt_debug_nonempty() {
    let hash = ContentHash::compute(b"test");
    let receipt = DecisionReceipt::new(COMPONENT, epoch(), GovernanceDecision::Approve, hash);
    let d = format!("{receipt:?}");
    assert!(!d.is_empty());
    assert!(d.contains("DecisionReceipt"));
}

#[test]
fn enrichment_decision_receipt_different_epochs_differ() {
    let hash = ContentHash::compute(b"test");
    let a = DecisionReceipt::new(
        COMPONENT,
        SecurityEpoch::from_raw(1),
        GovernanceDecision::Approve,
        hash,
    );
    let b = DecisionReceipt::new(
        COMPONENT,
        SecurityEpoch::from_raw(2),
        GovernanceDecision::Approve,
        hash,
    );
    assert_ne!(a.receipt_hash, b.receipt_hash);
}

// ── GateSummary ─────────────────────────────────────────────────────────

#[test]
fn enrichment_gate_summary_clone_independence() {
    let mut a = GateSummary::new();
    a.record(GovernanceDecision::Approve);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_summary_json_field_names() {
    let summary = GateSummary::new();
    let v: serde_json::Value = serde_json::to_value(&summary).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "total_evaluated",
        "approved",
        "conditional",
        "rejected",
        "insufficient",
        "pass_rate",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 6);
}

#[test]
fn enrichment_gate_summary_debug_nonempty() {
    let s = GateSummary::new();
    let d = format!("{s:?}");
    assert!(!d.is_empty());
    assert!(d.contains("GateSummary"));
}

#[test]
fn enrichment_gate_summary_empty_not_all_passed() {
    let s = GateSummary::new();
    assert!(!s.all_passed());
}

#[test]
fn enrichment_gate_summary_all_conditional_passes() {
    let mut s = GateSummary::new();
    s.record(GovernanceDecision::ConditionalApprove);
    s.record(GovernanceDecision::ConditionalApprove);
    assert!(s.all_passed());
    assert_eq!(s.pass_rate, 1_000_000);
}

#[test]
fn enrichment_gate_summary_insufficient_prevents_all_passed() {
    let mut s = GateSummary::new();
    s.record(GovernanceDecision::Approve);
    s.record(GovernanceDecision::RequireEvidence);
    assert!(!s.all_passed());
}

#[test]
fn enrichment_gate_summary_failure_rate_complement() {
    let mut s = GateSummary::new();
    s.record(GovernanceDecision::Approve);
    s.record(GovernanceDecision::Reject);
    s.record(GovernanceDecision::Reject);
    // pass_rate = 1/3 * 1_000_000 = 333_333
    assert_eq!(s.pass_rate + s.failure_rate(), 1_000_000);
}

#[test]
fn enrichment_gate_summary_serde_roundtrip() {
    let mut s = GateSummary::new();
    s.record(GovernanceDecision::Approve);
    s.record(GovernanceDecision::Reject);
    let json = serde_json::to_string(&s).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ── evaluate_cache_locality boundaries ──────────────────────────────────

#[test]
fn enrichment_cache_locality_exact_l1_threshold_approves() {
    let ev = CacheMissEvidence::new("x", 50_000, 10_000, 10_000, 5_000, 100, epoch());
    let decision = evaluate_cache_locality(&ev, &default_cfg());
    assert_eq!(decision, GovernanceDecision::Approve);
}

#[test]
fn enrichment_cache_locality_one_above_l1_threshold_conditional() {
    let ev = CacheMissEvidence::new("x", 50_001, 10_000, 10_000, 5_000, 100, epoch());
    let decision = evaluate_cache_locality(&ev, &default_cfg());
    assert_eq!(decision, GovernanceDecision::ConditionalApprove);
}

#[test]
fn enrichment_cache_locality_l1_at_conditional_upper_approves_conditional() {
    // Upper bound = 50_000 * 1_500_000 / 1_000_000 = 75_000
    let ev = CacheMissEvidence::new("x", 75_000, 10_000, 10_000, 5_000, 100, epoch());
    let decision = evaluate_cache_locality(&ev, &default_cfg());
    assert_eq!(decision, GovernanceDecision::ConditionalApprove);
}

#[test]
fn enrichment_cache_locality_l1_above_conditional_upper_rejects() {
    // Upper bound = 75_000, 75_001 > 75_000 => Reject
    let ev = CacheMissEvidence::new("x", 75_001, 10_000, 10_000, 5_000, 100, epoch());
    let decision = evaluate_cache_locality(&ev, &default_cfg());
    assert_eq!(decision, GovernanceDecision::Reject);
}

#[test]
fn enrichment_cache_locality_tlb_boundary() {
    // TLB threshold = 20_000, upper = 30_000
    let ev = CacheMissEvidence::new("x", 10_000, 10_000, 10_000, 20_001, 100, epoch());
    let decision = evaluate_cache_locality(&ev, &default_cfg());
    assert_eq!(decision, GovernanceDecision::ConditionalApprove);
}

// ── evaluate_numa boundaries ────────────────────────────────────────────

#[test]
fn enrichment_numa_exact_threshold_approves() {
    let ev = NumaEvidence::new(0, 800_000, 200_000, 500_000, 50_000, epoch());
    let decision = evaluate_numa(&ev, &default_cfg());
    assert_eq!(decision, GovernanceDecision::Approve);
}

#[test]
fn enrichment_numa_one_below_threshold_conditional() {
    let ev = NumaEvidence::new(0, 799_999, 200_001, 500_000, 50_000, epoch());
    let decision = evaluate_numa(&ev, &default_cfg());
    // conditional floor = 800_000 * 800_000 / 1_000_000 = 640_000
    // 799_999 >= 640_000 => ConditionalApprove
    assert_eq!(decision, GovernanceDecision::ConditionalApprove);
}

#[test]
fn enrichment_numa_at_conditional_floor_conditional() {
    // conditional floor = 640_000
    let ev = NumaEvidence::new(0, 640_000, 360_000, 500_000, 50_000, epoch());
    let decision = evaluate_numa(&ev, &default_cfg());
    assert_eq!(decision, GovernanceDecision::ConditionalApprove);
}

#[test]
fn enrichment_numa_below_conditional_floor_rejects() {
    // conditional floor = 640_000
    let ev = NumaEvidence::new(0, 639_999, 360_001, 500_000, 50_000, epoch());
    let decision = evaluate_numa(&ev, &default_cfg());
    assert_eq!(decision, GovernanceDecision::Reject);
}

// ── evaluate_portability boundaries ─────────────────────────────────────

#[test]
fn enrichment_portability_exact_threshold_portable() {
    let ev = PortabilityEvidence::new("x86_64", "aarch64", 700_000, vec![], epoch());
    let verdict = evaluate_portability(&ev, &default_cfg());
    assert_eq!(verdict, PortabilityVerdict::Portable);
}

#[test]
fn enrichment_portability_one_below_threshold_machine_specific() {
    let ev = PortabilityEvidence::new("x86_64", "aarch64", 699_999, vec![], epoch());
    let verdict = evaluate_portability(&ev, &default_cfg());
    assert_eq!(verdict, PortabilityVerdict::MachineSpecific);
}

#[test]
fn enrichment_portability_at_threshold_with_degradation_conditional() {
    let ev = PortabilityEvidence::new(
        "x86_64",
        "aarch64",
        700_000,
        vec!["cache_line_size".into()],
        epoch(),
    );
    let verdict = evaluate_portability(&ev, &default_cfg());
    assert_eq!(verdict, PortabilityVerdict::ConditionallyPortable);
}

#[test]
fn enrichment_portability_different_topologies_zero_transfer_machine_specific() {
    let ev = PortabilityEvidence::new("x86_64", "aarch64", 0, vec![], epoch());
    let verdict = evaluate_portability(&ev, &default_cfg());
    // Different topologies with zero transfer => MachineSpecific (not Unknown)
    assert_eq!(verdict, PortabilityVerdict::MachineSpecific);
}

// ── evaluate (combined) cross-cutting ───────────────────────────────────

#[test]
fn enrichment_evaluate_observability_unacceptable_but_within_threshold() {
    let obs = ObservabilityImpact::new(30_000, 10_000, false);
    // delta = 20_000, threshold = 50_000 => within threshold but acceptable = false
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        Some(&obs),
        &default_cfg(),
    );
    assert_eq!(result.decision, GovernanceDecision::ConditionalApprove);
    assert!(result.is_approved());
}

#[test]
fn enrichment_evaluate_no_cache_uses_numa_node_locality() {
    let result = evaluate(
        None,
        Some(&good_numa()),
        Some(&good_portability()),
        None,
        &default_cfg(),
    );
    assert_eq!(result.locality_verdict, LocalityDomain::NumaNode);
}

#[test]
fn enrichment_evaluate_no_portability_uses_unknown_verdict() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        None,
        None,
        &default_cfg(),
    );
    assert_eq!(result.portability_verdict, PortabilityVerdict::Unknown);
}

#[test]
fn enrichment_evaluate_recommendations_on_missing_evidence() {
    let result = evaluate(Some(&good_cache()), None, None, None, &default_cfg());
    assert!(
        result
            .recommendations
            .iter()
            .any(|r| r.contains("portability"))
    );
}

#[test]
fn enrichment_evaluate_receipt_hash_differs_for_different_evidence() {
    let a = evaluate(Some(&good_cache()), None, None, None, &default_cfg());
    let b = evaluate(None, Some(&good_numa()), None, None, &default_cfg());
    assert_ne!(a.receipt_hash, b.receipt_hash);
}

// ── build_canonical_evidence ────────────────────────────────────────────

#[test]
fn enrichment_canonical_evidence_domains_all_unique() {
    let profiles = build_canonical_evidence();
    let domains: BTreeSet<&str> = profiles.iter().map(|p| p.domain.as_str()).collect();
    assert_eq!(domains.len(), profiles.len());
}

#[test]
fn enrichment_canonical_evidence_all_sufficient_samples() {
    for ev in &build_canonical_evidence() {
        assert!(
            ev.has_sufficient_samples(),
            "{} has insufficient samples",
            ev.domain
        );
    }
}

#[test]
fn enrichment_canonical_evidence_content_hashes_all_unique() {
    let profiles = build_canonical_evidence();
    let hashes: BTreeSet<Vec<u8>> = profiles
        .iter()
        .map(|p| p.content_hash().as_bytes().to_vec())
        .collect();
    assert_eq!(hashes.len(), profiles.len());
}

// ── build_receipt ───────────────────────────────────────────────────────

#[test]
fn enrichment_build_receipt_matches_result_decision() {
    let result = evaluate(
        Some(&good_cache()),
        Some(&good_numa()),
        Some(&good_portability()),
        Some(&good_observability()),
        &default_cfg(),
    );
    let receipt = build_receipt(&result, epoch());
    assert_eq!(receipt.decision, result.decision);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.epoch, epoch());
}

#[test]
fn enrichment_build_receipt_rejected_result() {
    let bad_cache = CacheMissEvidence::new("bad", 200_000, 500_000, 800_000, 100_000, 100, epoch());
    let result = evaluate(Some(&bad_cache), None, None, None, &default_cfg());
    let receipt = build_receipt(&result, epoch());
    assert_eq!(receipt.decision, GovernanceDecision::Reject);
}

// ── Five-run determinism ────────────────────────────────────────────────

#[test]
fn enrichment_five_run_determinism_full_evaluate() {
    let results: Vec<_> = (0..5)
        .map(|_| {
            evaluate(
                Some(&good_cache()),
                Some(&good_numa()),
                Some(&good_portability()),
                Some(&good_observability()),
                &default_cfg(),
            )
        })
        .collect();
    for r in &results[1..] {
        assert_eq!(results[0], *r);
    }
}

#[test]
fn enrichment_five_run_determinism_content_hashes() {
    let hashes: Vec<_> = (0..5).map(|_| good_cache().content_hash()).collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_receipt() {
    let receipts: Vec<_> = (0..5)
        .map(|_| {
            let result = evaluate(
                Some(&good_cache()),
                Some(&good_numa()),
                None,
                None,
                &default_cfg(),
            );
            build_receipt(&result, epoch())
        })
        .collect();
    for r in &receipts[1..] {
        assert_eq!(receipts[0].receipt_hash, r.receipt_hash);
    }
}

// ── Constants stability ─────────────────────────────────────────────────

#[test]
fn enrichment_constants_stable() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.metadata-locality-governance-gate.v1"
    );
    assert_eq!(COMPONENT, "metadata_locality_governance_gate");
    assert_eq!(BEAD_ID, "bd-1lsy.7.26.3");
    assert_eq!(POLICY_ID, "RGC-626C");
    assert_eq!(DEFAULT_MAX_L1_MISS_RATE, 50_000);
    assert_eq!(DEFAULT_MAX_L2_MISS_RATE, 100_000);
    assert_eq!(DEFAULT_MAX_L3_MISS_RATE, 200_000);
    assert_eq!(DEFAULT_MAX_TLB_MISS_RATE, 20_000);
    assert_eq!(DEFAULT_MIN_LOCAL_ACCESS_FRACTION, 800_000);
    assert_eq!(DEFAULT_MAX_OBSERVABILITY_OVERHEAD, 50_000);
    assert_eq!(DEFAULT_MIN_PORTABILITY_FRACTION, 700_000);
    assert_eq!(MIN_SAMPLE_COUNT, 10);
}
