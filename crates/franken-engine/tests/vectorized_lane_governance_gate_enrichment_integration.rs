#![forbid(unsafe_code)]

//! Enrichment integration tests for the `vectorized_lane_governance_gate` module.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::vectorized_lane_governance_gate::{
    BEAD_ID, BuiltinFamily, COMPONENT, ColdStartImpact, ColdStartRecord, DecisionReceipt,
    GateConfig, GateResult, GateSummary, LaneVerdict, POLICY_ID, ParityEvidence, SCHEMA_VERSION,
    SkewKind, SkewRecord, TailRiskRecord, evaluate, evaluate_batch, evaluate_cold_start,
    evaluate_parity, evaluate_skew,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn good_parity() -> ParityEvidence {
    ParityEvidence {
        builtin_family: BuiltinFamily::ArrayMap,
        scalar_throughput: 1_000_000,
        vectorized_throughput: 2_000_000,
        speedup_fraction: 2_000_000,
        parity_violations: 0,
        sample_count: 100,
        epoch: epoch(),
    }
}

fn clean_skew() -> Vec<SkewRecord> {
    vec![SkewRecord {
        kind: SkewKind::InputSize,
        measured_skew: 50_000,
        threshold: 200_000,
        explanation: "within bounds".to_string(),
    }]
}

// ===========================================================================
// BuiltinFamily — Copy, BTreeSet, Debug/Display unique, as_str matches Display
// ===========================================================================

#[test]
fn enrichment_builtin_family_copy_semantics() {
    let a = BuiltinFamily::ArrayMap;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_builtin_family_btreeset_dedup_9() {
    let mut set = BTreeSet::new();
    for v in BuiltinFamily::ALL {
        set.insert(*v);
    }
    set.insert(BuiltinFamily::ArrayMap);
    assert_eq!(set.len(), 9);
}

#[test]
fn enrichment_builtin_family_debug_all_unique() {
    let strs: BTreeSet<String> = BuiltinFamily::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 9);
}

#[test]
fn enrichment_builtin_family_display_all_unique() {
    let strs: BTreeSet<String> = BuiltinFamily::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 9);
}

#[test]
fn enrichment_builtin_family_as_str_matches_display() {
    for v in BuiltinFamily::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_builtin_family_serde_all() {
    for v in BuiltinFamily::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: BuiltinFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// LaneVerdict — Copy, BTreeSet, Debug/Display unique, as_str, allows_lane
// ===========================================================================

#[test]
fn enrichment_lane_verdict_copy_semantics() {
    let a = LaneVerdict::Approved;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_lane_verdict_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    for v in LaneVerdict::ALL {
        set.insert(*v);
    }
    set.insert(LaneVerdict::Approved);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_lane_verdict_debug_all_unique() {
    let strs: BTreeSet<String> = LaneVerdict::ALL.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_lane_verdict_display_all_unique() {
    let strs: BTreeSet<String> = LaneVerdict::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_lane_verdict_as_str_matches_display() {
    for v in LaneVerdict::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_lane_verdict_allows_lane_exactly_two() {
    let allowed: Vec<_> = LaneVerdict::ALL
        .iter()
        .filter(|v| v.allows_lane())
        .collect();
    assert_eq!(allowed.len(), 2);
    assert!(LaneVerdict::Approved.allows_lane());
    assert!(LaneVerdict::ConditionalApproval.allows_lane());
    assert!(!LaneVerdict::Rejected.allows_lane());
    assert!(!LaneVerdict::FallbackRequired.allows_lane());
}

// ===========================================================================
// SkewKind — Copy, BTreeSet, Debug/Display unique, as_str
// ===========================================================================

#[test]
fn enrichment_skew_kind_copy_semantics() {
    let a = SkewKind::InputSize;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_skew_kind_btreeset_dedup_5() {
    let mut set = BTreeSet::new();
    for v in SkewKind::ALL {
        set.insert(*v);
    }
    set.insert(SkewKind::Alignment);
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_skew_kind_debug_all_unique() {
    let strs: BTreeSet<String> = SkewKind::ALL.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn enrichment_skew_kind_display_all_unique() {
    let strs: BTreeSet<String> = SkewKind::ALL.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 5);
}

#[test]
fn enrichment_skew_kind_as_str_matches_display() {
    for v in SkewKind::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

// ===========================================================================
// ColdStartImpact — Copy, BTreeSet, Debug/Display unique, as_str, is_acceptable
// ===========================================================================

#[test]
fn enrichment_cold_start_impact_copy_semantics() {
    let a = ColdStartImpact::Negligible;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_cold_start_impact_btreeset_dedup_4() {
    let mut set = BTreeSet::new();
    for v in ColdStartImpact::ALL {
        set.insert(*v);
    }
    set.insert(ColdStartImpact::Negligible);
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_cold_start_impact_debug_all_unique() {
    let strs: BTreeSet<String> = ColdStartImpact::ALL
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_cold_start_impact_display_all_unique() {
    let strs: BTreeSet<String> = ColdStartImpact::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_cold_start_impact_as_str_matches_display() {
    for v in ColdStartImpact::ALL {
        assert_eq!(v.as_str(), format!("{v}"));
    }
}

#[test]
fn enrichment_cold_start_impact_acceptable_exactly_two() {
    let acceptable: Vec<_> = ColdStartImpact::ALL
        .iter()
        .filter(|v| v.is_acceptable())
        .collect();
    assert_eq!(acceptable.len(), 2);
    assert!(ColdStartImpact::Negligible.is_acceptable());
    assert!(ColdStartImpact::Moderate.is_acceptable());
    assert!(!ColdStartImpact::Severe.is_acceptable());
    assert!(!ColdStartImpact::Prohibitive.is_acceptable());
}

// ===========================================================================
// ParityEvidence — Clone, Debug, Display, JSON fields, serde, methods
// ===========================================================================

#[test]
fn enrichment_parity_evidence_clone_independence() {
    let a = good_parity();
    let mut b = a.clone();
    b.parity_violations = 99;
    assert_ne!(a.parity_violations, b.parity_violations);
}

#[test]
fn enrichment_parity_evidence_debug_nonempty() {
    let pe = good_parity();
    let dbg = format!("{pe:?}");
    assert!(dbg.contains("ParityEvidence"));
}

#[test]
fn enrichment_parity_evidence_display_contains_family() {
    let pe = good_parity();
    let disp = format!("{pe}");
    assert!(!disp.is_empty());
}

#[test]
fn enrichment_parity_evidence_json_field_names() {
    let pe = good_parity();
    let json = serde_json::to_string(&pe).unwrap();
    for field in &[
        "builtin_family",
        "scalar_throughput",
        "vectorized_throughput",
        "speedup_fraction",
        "parity_violations",
        "sample_count",
        "epoch",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_parity_evidence_serde_roundtrip() {
    let pe = good_parity();
    let json = serde_json::to_string(&pe).unwrap();
    let back: ParityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(pe, back);
}

#[test]
fn enrichment_parity_evidence_is_faster_true() {
    let pe = good_parity();
    assert!(pe.is_faster());
}

#[test]
fn enrichment_parity_evidence_is_faster_false() {
    let mut pe = good_parity();
    pe.vectorized_throughput = 500_000; // slower than scalar
    pe.scalar_throughput = 1_000_000;
    assert!(!pe.is_faster());
}

#[test]
fn enrichment_parity_evidence_computed_speedup_zero_scalar() {
    let mut pe = good_parity();
    pe.scalar_throughput = 0;
    let speedup = pe.computed_speedup();
    assert_eq!(speedup, 0); // zero scalar → 0 speedup
}

// ===========================================================================
// SkewRecord — Clone, Debug, Display, JSON fields, methods
// ===========================================================================

#[test]
fn enrichment_skew_record_clone_independence() {
    let mut a = SkewRecord {
        kind: SkewKind::InputSize,
        measured_skew: 100_000,
        threshold: 200_000,
        explanation: "test".to_string(),
    };
    let b = a.clone();
    a.explanation = "changed".to_string();
    assert_ne!(a.explanation, b.explanation);
}

#[test]
fn enrichment_skew_record_debug_nonempty() {
    let sr = SkewRecord {
        kind: SkewKind::Density,
        measured_skew: 50_000,
        threshold: 100_000,
        explanation: "ok".to_string(),
    };
    let dbg = format!("{sr:?}");
    assert!(dbg.contains("SkewRecord"));
}

#[test]
fn enrichment_skew_record_is_failing_boundary() {
    let sr_pass = SkewRecord {
        kind: SkewKind::InputSize,
        measured_skew: 200_000,
        threshold: 200_000,
        explanation: "at threshold".to_string(),
    };
    assert!(!sr_pass.is_failing()); // equal → not failing

    let sr_fail = SkewRecord {
        kind: SkewKind::InputSize,
        measured_skew: 200_001,
        threshold: 200_000,
        explanation: "above threshold".to_string(),
    };
    assert!(sr_fail.is_failing());
}

#[test]
fn enrichment_skew_record_json_field_names() {
    let sr = SkewRecord {
        kind: SkewKind::Distribution,
        measured_skew: 100_000,
        threshold: 200_000,
        explanation: "test".to_string(),
    };
    let json = serde_json::to_string(&sr).unwrap();
    for field in &["kind", "measured_skew", "threshold", "explanation"] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

// ===========================================================================
// ColdStartRecord — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_cold_start_record_clone_independence() {
    let a = ColdStartRecord {
        builtin_family: BuiltinFamily::ArrayMap,
        warmup_iterations: 10,
        cold_penalty_fraction: 100_000,
        impact: ColdStartImpact::Negligible,
        epoch: epoch(),
    };
    let mut b = a.clone();
    b.warmup_iterations = 99;
    assert_ne!(a.warmup_iterations, b.warmup_iterations);
}

#[test]
fn enrichment_cold_start_record_debug_nonempty() {
    let csr = ColdStartRecord {
        builtin_family: BuiltinFamily::JsonParse,
        warmup_iterations: 5,
        cold_penalty_fraction: 200_000,
        impact: ColdStartImpact::Moderate,
        epoch: epoch(),
    };
    let dbg = format!("{csr:?}");
    assert!(dbg.contains("ColdStartRecord"));
}

#[test]
fn enrichment_cold_start_record_json_field_names() {
    let csr = ColdStartRecord {
        builtin_family: BuiltinFamily::SetOperation,
        warmup_iterations: 8,
        cold_penalty_fraction: 350_000,
        impact: ColdStartImpact::Severe,
        epoch: epoch(),
    };
    let json = serde_json::to_string(&csr).unwrap();
    for field in &[
        "builtin_family",
        "warmup_iterations",
        "cold_penalty_fraction",
        "impact",
        "epoch",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_cold_start_record_serde_roundtrip() {
    let csr = ColdStartRecord {
        builtin_family: BuiltinFamily::MapOperation,
        warmup_iterations: 3,
        cold_penalty_fraction: 50_000,
        impact: ColdStartImpact::Negligible,
        epoch: epoch(),
    };
    let json = serde_json::to_string(&csr).unwrap();
    let back: ColdStartRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(csr, back);
}

// ===========================================================================
// TailRiskRecord — Clone, Debug, JSON fields, serde, methods
// ===========================================================================

#[test]
fn enrichment_tail_risk_record_clone_independence() {
    let a = TailRiskRecord {
        p50: 100,
        p99: 200,
        p999: 300,
        max: 500,
        tail_ratio: 2_000_000,
    };
    let mut b = a.clone();
    b.max = 999;
    assert_ne!(a.max, b.max);
}

#[test]
fn enrichment_tail_risk_record_debug_nonempty() {
    let tr = TailRiskRecord {
        p50: 50,
        p99: 150,
        p999: 250,
        max: 400,
        tail_ratio: 3_000_000,
    };
    let dbg = format!("{tr:?}");
    assert!(dbg.contains("TailRiskRecord"));
}

#[test]
fn enrichment_tail_risk_record_json_field_names() {
    let tr = TailRiskRecord {
        p50: 100,
        p99: 200,
        p999: 300,
        max: 500,
        tail_ratio: 2_000_000,
    };
    let json = serde_json::to_string(&tr).unwrap();
    for field in &["p50", "p99", "p999", "max", "tail_ratio"] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_tail_risk_record_is_acceptable_boundary() {
    let tr = TailRiskRecord {
        p50: 100,
        p99: 200,
        p999: 300,
        max: 500,
        tail_ratio: 3_000_000,
    };
    assert!(tr.is_acceptable(3_000_000)); // equal → acceptable
    assert!(!tr.is_acceptable(2_999_999)); // below → not acceptable
}

#[test]
fn enrichment_tail_risk_record_serde_roundtrip() {
    let tr = TailRiskRecord {
        p50: 100,
        p99: 200,
        p999: 300,
        max: 500,
        tail_ratio: 2_000_000,
    };
    let json = serde_json::to_string(&tr).unwrap();
    let back: TailRiskRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(tr, back);
}

// ===========================================================================
// GateConfig — Clone, Debug, JSON fields, default/strict/permissive
// ===========================================================================

#[test]
fn enrichment_gate_config_clone_independence() {
    let mut a = GateConfig::default();
    let b = a.clone();
    a.min_sample_count = 999;
    assert_ne!(a.min_sample_count, b.min_sample_count);
}

#[test]
fn enrichment_gate_config_debug_nonempty() {
    let cfg = GateConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("GateConfig"));
}

#[test]
fn enrichment_gate_config_json_field_names() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    for field in &[
        "min_speedup_fraction",
        "max_parity_violations",
        "max_skew_fraction",
        "max_cold_penalty",
        "max_tail_ratio",
        "min_sample_count",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_gate_config_strict_stricter_than_default() {
    let def = GateConfig::default();
    let strict = GateConfig::strict();
    assert!(strict.min_speedup_fraction >= def.min_speedup_fraction);
    assert!(strict.min_sample_count >= def.min_sample_count);
}

#[test]
fn enrichment_gate_config_permissive_looser_than_default() {
    let def = GateConfig::default();
    let perm = GateConfig::permissive();
    assert!(perm.max_parity_violations >= def.max_parity_violations);
    assert!(perm.max_tail_ratio >= def.max_tail_ratio);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let cfg = GateConfig::strict();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// GateResult — Clone, Debug, JSON fields, serde, methods
// ===========================================================================

#[test]
fn enrichment_gate_result_clone_independence() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    let mut cloned = result.clone();
    cloned.blocking_reasons.push("extra".to_string());
    assert_ne!(result.blocking_reasons.len(), cloned.blocking_reasons.len());
}

#[test]
fn enrichment_gate_result_debug_nonempty() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    let dbg = format!("{result:?}");
    assert!(dbg.contains("GateResult"));
}

#[test]
fn enrichment_gate_result_json_field_names() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    let json = serde_json::to_string(&result).unwrap();
    for field in &[
        "verdict",
        "parity_ok",
        "skew_records",
        "cold_start",
        "tail_risk",
        "blocking_reasons",
        "receipt_hash",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_gate_result_serde_roundtrip() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_gate_result_is_approved_when_clean() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    assert!(result.is_approved());
    assert!(!result.has_blockers());
}

// ===========================================================================
// DecisionReceipt — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_decision_receipt_clone_independence() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    let receipt = DecisionReceipt::new(epoch(), result.verdict, result.receipt_hash);
    let mut cloned = receipt.clone();
    cloned.component = "changed".to_string();
    assert_ne!(receipt.component, cloned.component);
}

#[test]
fn enrichment_decision_receipt_debug_nonempty() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    let receipt = DecisionReceipt::new(epoch(), result.verdict, result.receipt_hash);
    let dbg = format!("{receipt:?}");
    assert!(dbg.contains("DecisionReceipt"));
}

#[test]
fn enrichment_decision_receipt_json_field_names() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    let receipt = DecisionReceipt::new(epoch(), result.verdict, result.receipt_hash);
    let json = serde_json::to_string(&receipt).unwrap();
    for field in &[
        "receipt_hash",
        "component",
        "epoch",
        "verdict",
        "evidence_hash",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_decision_receipt_component_matches_constant() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    let receipt = DecisionReceipt::new(epoch(), result.verdict, result.receipt_hash);
    assert_eq!(receipt.component, COMPONENT);
}

#[test]
fn enrichment_decision_receipt_serde_roundtrip() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    let receipt = DecisionReceipt::new(epoch(), result.verdict, result.receipt_hash);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ===========================================================================
// GateSummary — Clone, Debug, JSON fields, serde, methods
// ===========================================================================

#[test]
fn enrichment_gate_summary_clone_independence() {
    let items: Vec<_> = vec![(good_parity(), clean_skew(), None, None)];
    let (_, summary) = evaluate_batch(&items, &GateConfig::default());
    let mut cloned = summary.clone();
    cloned.approved = 999;
    assert_ne!(summary.approved, cloned.approved);
}

#[test]
fn enrichment_gate_summary_debug_nonempty() {
    let (_, summary) = evaluate_batch(&[], &GateConfig::default());
    let dbg = format!("{summary:?}");
    assert!(dbg.contains("GateSummary"));
}

#[test]
fn enrichment_gate_summary_json_field_names() {
    let (_, summary) = evaluate_batch(&[], &GateConfig::default());
    let json = serde_json::to_string(&summary).unwrap();
    for field in &[
        "total",
        "approved",
        "conditional",
        "rejected",
        "fallback",
        "pass_rate",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

#[test]
fn enrichment_gate_summary_empty_no_pass() {
    let (_, summary) = evaluate_batch(&[], &GateConfig::default());
    assert!(!summary.all_passed());
    assert!(!summary.has_rejections());
}

#[test]
fn enrichment_gate_summary_serde_roundtrip() {
    let items: Vec<_> = vec![(good_parity(), clean_skew(), None, None)];
    let (_, summary) = evaluate_batch(&items, &GateConfig::default());
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ===========================================================================
// evaluate_parity — property tests
// ===========================================================================

#[test]
fn enrichment_evaluate_parity_good_passes() {
    assert!(evaluate_parity(&good_parity(), &GateConfig::default()));
}

#[test]
fn enrichment_evaluate_parity_low_samples_fails() {
    let mut pe = good_parity();
    pe.sample_count = 1;
    assert!(!evaluate_parity(&pe, &GateConfig::default()));
}

// ===========================================================================
// evaluate_skew — property tests
// ===========================================================================

#[test]
fn enrichment_evaluate_skew_clean_returns_empty() {
    let failing = evaluate_skew(&good_parity(), &clean_skew(), &GateConfig::default());
    assert!(failing.is_empty());
}

#[test]
fn enrichment_evaluate_skew_bad_returns_nonempty() {
    let bad_skew = vec![SkewRecord {
        kind: SkewKind::InputSize,
        measured_skew: 500_000,
        threshold: 100_000,
        explanation: "way above".to_string(),
    }];
    let failing = evaluate_skew(&good_parity(), &bad_skew, &GateConfig::default());
    assert!(!failing.is_empty());
}

// ===========================================================================
// evaluate_cold_start — boundary tests
// ===========================================================================

#[test]
fn enrichment_evaluate_cold_start_negligible() {
    let csr = ColdStartRecord {
        builtin_family: BuiltinFamily::ArrayMap,
        warmup_iterations: 2,
        cold_penalty_fraction: 50_000,
        impact: ColdStartImpact::Negligible,
        epoch: epoch(),
    };
    let impact = evaluate_cold_start(&csr, &GateConfig::default());
    assert!(impact.is_acceptable());
}

#[test]
fn enrichment_evaluate_cold_start_prohibitive() {
    let csr = ColdStartRecord {
        builtin_family: BuiltinFamily::ArrayMap,
        warmup_iterations: 100,
        cold_penalty_fraction: 900_000,
        impact: ColdStartImpact::Prohibitive,
        epoch: epoch(),
    };
    let impact = evaluate_cold_start(&csr, &GateConfig::default());
    assert!(!impact.is_acceptable());
}

// ===========================================================================
// 5-run determinism
// ===========================================================================

#[test]
fn enrichment_five_run_determinism_evaluate() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let result = evaluate(
                &good_parity(),
                &clean_skew(),
                None,
                None,
                &GateConfig::default(),
            );
            result.receipt_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_receipt() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let result = evaluate(
                &good_parity(),
                &clean_skew(),
                None,
                None,
                &GateConfig::default(),
            );
            let receipt = DecisionReceipt::new(epoch(), result.verdict, result.receipt_hash);
            receipt.receipt_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_batch() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let items = vec![(good_parity(), clean_skew(), None, None)];
            let (results, _) = evaluate_batch(&items, &GateConfig::default());
            results[0].receipt_hash
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

// ===========================================================================
// Constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stability() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.vectorized-lane-governance-gate.v1"
    );
    assert_eq!(COMPONENT, "vectorized_lane_governance_gate");
    assert_eq!(BEAD_ID, "bd-1lsy.7.24.3");
    assert_eq!(POLICY_ID, "RGC-624C");
}

// ===========================================================================
// Cross-cutting
// ===========================================================================

#[test]
fn enrichment_cross_cutting_permissive_approves() {
    let result = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::permissive(),
    );
    assert!(result.is_approved());
}

#[test]
fn enrichment_cross_cutting_batch_single_matches_evaluate() {
    let items = vec![(good_parity(), clean_skew(), None, None)];
    let (results, summary) = evaluate_batch(&items, &GateConfig::default());
    assert_eq!(results.len(), 1);
    assert_eq!(summary.total, 1);
    let single = evaluate(
        &good_parity(),
        &clean_skew(),
        None,
        None,
        &GateConfig::default(),
    );
    assert_eq!(results[0].verdict, single.verdict);
}

#[test]
fn enrichment_cross_cutting_all_families_evaluated() {
    let items: Vec<_> = BuiltinFamily::ALL
        .iter()
        .map(|f| {
            let mut pe = good_parity();
            pe.builtin_family = *f;
            (pe, clean_skew(), None, None)
        })
        .collect();
    let (results, summary) = evaluate_batch(&items, &GateConfig::default());
    assert_eq!(results.len(), 9);
    assert_eq!(summary.total, 9);
}
