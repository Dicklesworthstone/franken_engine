//! Integration tests for vectorized_lane_governance_gate module.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::vectorized_lane_governance_gate::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn good_parity(family: BuiltinFamily) -> ParityEvidence {
    ParityEvidence {
        builtin_family: family,
        scalar_throughput: 1_000_000,
        vectorized_throughput: 1_500_000,
        speedup_fraction: 1_500_000, // 1.5x
        parity_violations: 0,
        sample_count: 100,
        epoch: epoch(10),
    }
}

fn slow_parity(family: BuiltinFamily) -> ParityEvidence {
    ParityEvidence {
        builtin_family: family,
        scalar_throughput: 1_000_000,
        vectorized_throughput: 800_000,
        speedup_fraction: 800_000, // 0.8x slower
        parity_violations: 10,
        sample_count: 100,
        epoch: epoch(10),
    }
}

fn clean_skew() -> SkewRecord {
    SkewRecord {
        kind: SkewKind::InputSize,
        measured_skew: 50_000, // 5%
        threshold: 200_000,
        explanation: "minor input size skew".into(),
    }
}

fn bad_skew() -> SkewRecord {
    SkewRecord {
        kind: SkewKind::Distribution,
        measured_skew: 350_000, // 35%
        threshold: 200_000,
        explanation: "severe distribution skew".into(),
    }
}

fn mild_cold_start(family: BuiltinFamily) -> ColdStartRecord {
    ColdStartRecord {
        builtin_family: family,
        warmup_iterations: 10,
        cold_penalty_fraction: 80_000, // 8%
        impact: ColdStartImpact::Negligible,
        epoch: epoch(10),
    }
}

fn severe_cold_start(family: BuiltinFamily) -> ColdStartRecord {
    ColdStartRecord {
        builtin_family: family,
        warmup_iterations: 500,
        cold_penalty_fraction: 550_000, // 55%
        impact: ColdStartImpact::Severe,
        epoch: epoch(10),
    }
}

fn good_tail() -> TailRiskRecord {
    TailRiskRecord {
        p50: 100,
        p99: 200,
        p999: 400,
        max: 800,
        tail_ratio: 2_000_000, // 2.0x
    }
}

fn bad_tail() -> TailRiskRecord {
    TailRiskRecord {
        p50: 100,
        p99: 500,
        p999: 2_000,
        max: 10_000,
        tail_ratio: 5_000_000, // 5.0x
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_value() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.vectorized-lane-governance-gate.v1"
    );
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "vectorized_lane_governance_gate");
}

#[test]
fn test_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.24.3");
}

#[test]
fn test_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-624C");
}

// ---------------------------------------------------------------------------
// BuiltinFamily
// ---------------------------------------------------------------------------

#[test]
fn test_builtin_family_all_has_nine_variants() {
    assert_eq!(BuiltinFamily::ALL.len(), 9);
}

#[test]
fn test_builtin_family_serde_roundtrip() {
    for f in BuiltinFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: BuiltinFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

#[test]
fn test_builtin_family_display_matches_as_str() {
    for f in BuiltinFamily::ALL {
        assert_eq!(f.to_string(), f.as_str());
    }
}

#[test]
fn test_builtin_family_array_map_str() {
    assert_eq!(BuiltinFamily::ArrayMap.as_str(), "array_map");
}

#[test]
fn test_builtin_family_json_parse_str() {
    assert_eq!(BuiltinFamily::JsonParse.as_str(), "json_parse");
}

#[test]
fn test_builtin_family_map_operation_str() {
    assert_eq!(BuiltinFamily::MapOperation.as_str(), "map_operation");
}

// ---------------------------------------------------------------------------
// LaneVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_lane_verdict_all_has_four_variants() {
    assert_eq!(LaneVerdict::ALL.len(), 4);
}

#[test]
fn test_lane_verdict_allows_lane() {
    assert!(LaneVerdict::Approved.allows_lane());
    assert!(LaneVerdict::ConditionalApproval.allows_lane());
    assert!(!LaneVerdict::Rejected.allows_lane());
    assert!(!LaneVerdict::FallbackRequired.allows_lane());
}

#[test]
fn test_lane_verdict_serde_roundtrip() {
    for v in LaneVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: LaneVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn test_lane_verdict_display_matches_as_str() {
    for v in LaneVerdict::ALL {
        assert_eq!(v.to_string(), v.as_str());
    }
}

// ---------------------------------------------------------------------------
// SkewKind
// ---------------------------------------------------------------------------

#[test]
fn test_skew_kind_all_has_five_variants() {
    assert_eq!(SkewKind::ALL.len(), 5);
}

#[test]
fn test_skew_kind_serde_roundtrip() {
    for k in SkewKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: SkewKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn test_skew_kind_display_matches_as_str() {
    for k in SkewKind::ALL {
        assert_eq!(k.to_string(), k.as_str());
    }
}

// ---------------------------------------------------------------------------
// ColdStartImpact
// ---------------------------------------------------------------------------

#[test]
fn test_cold_start_impact_all_has_four_variants() {
    assert_eq!(ColdStartImpact::ALL.len(), 4);
}

#[test]
fn test_cold_start_impact_is_acceptable() {
    assert!(ColdStartImpact::Negligible.is_acceptable());
    assert!(ColdStartImpact::Moderate.is_acceptable());
    assert!(!ColdStartImpact::Severe.is_acceptable());
    assert!(!ColdStartImpact::Prohibitive.is_acceptable());
}

#[test]
fn test_cold_start_impact_serde_roundtrip() {
    for c in ColdStartImpact::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: ColdStartImpact = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn test_cold_start_impact_display_matches_as_str() {
    for c in ColdStartImpact::ALL {
        assert_eq!(c.to_string(), c.as_str());
    }
}

// ---------------------------------------------------------------------------
// ParityEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_parity_evidence_computed_speedup() {
    let p = good_parity(BuiltinFamily::ArrayMap);
    assert_eq!(p.computed_speedup(), 1_500_000);
}

#[test]
fn test_parity_evidence_computed_speedup_zero_scalar() {
    let p = ParityEvidence {
        builtin_family: BuiltinFamily::ArrayMap,
        scalar_throughput: 0,
        vectorized_throughput: 1_000_000,
        speedup_fraction: 0,
        parity_violations: 0,
        sample_count: 100,
        epoch: epoch(1),
    };
    assert_eq!(p.computed_speedup(), 0);
}

#[test]
fn test_parity_evidence_is_faster_true() {
    let p = good_parity(BuiltinFamily::ArrayFilter);
    assert!(p.is_faster());
}

#[test]
fn test_parity_evidence_is_faster_false() {
    let p = slow_parity(BuiltinFamily::JsonParse);
    assert!(!p.is_faster());
}

#[test]
fn test_parity_evidence_display_contains_family() {
    let p = good_parity(BuiltinFamily::StringConcat);
    let s = p.to_string();
    assert!(s.contains("string_concat"));
}

#[test]
fn test_parity_evidence_serde_roundtrip() {
    let p = good_parity(BuiltinFamily::ArrayReduce);
    let json = serde_json::to_string(&p).unwrap();
    let back: ParityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// SkewRecord
// ---------------------------------------------------------------------------

#[test]
fn test_skew_record_is_failing_true() {
    let s = bad_skew();
    assert!(s.is_failing());
}

#[test]
fn test_skew_record_is_failing_false() {
    let s = clean_skew();
    assert!(!s.is_failing());
}

#[test]
fn test_skew_record_display_contains_kind() {
    let s = clean_skew();
    let disp = s.to_string();
    assert!(disp.contains("input_size"));
    assert!(disp.contains("ok"));
}

#[test]
fn test_skew_record_serde_roundtrip() {
    let s = bad_skew();
    let json = serde_json::to_string(&s).unwrap();
    let back: SkewRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// ColdStartRecord
// ---------------------------------------------------------------------------

#[test]
fn test_cold_start_record_display_contains_family() {
    let cs = mild_cold_start(BuiltinFamily::ArrayMap);
    let s = cs.to_string();
    assert!(s.contains("array_map"));
}

#[test]
fn test_cold_start_record_serde_roundtrip() {
    let cs = severe_cold_start(BuiltinFamily::JsonStringify);
    let json = serde_json::to_string(&cs).unwrap();
    let back: ColdStartRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(cs, back);
}

// ---------------------------------------------------------------------------
// TailRiskRecord
// ---------------------------------------------------------------------------

#[test]
fn test_tail_risk_record_computed_tail_ratio() {
    let t = good_tail();
    assert_eq!(t.computed_tail_ratio(), 2_000_000);
}

#[test]
fn test_tail_risk_record_computed_ratio_zero_p50() {
    let t = TailRiskRecord {
        p50: 0,
        p99: 100,
        p999: 200,
        max: 300,
        tail_ratio: 0,
    };
    assert_eq!(t.computed_tail_ratio(), 0);
}

#[test]
fn test_tail_risk_record_is_acceptable_true() {
    let t = good_tail();
    assert!(t.is_acceptable(3_000_000));
}

#[test]
fn test_tail_risk_record_is_acceptable_false() {
    let t = bad_tail();
    assert!(!t.is_acceptable(3_000_000));
}

#[test]
fn test_tail_risk_record_display_contains_p50() {
    let t = good_tail();
    let s = t.to_string();
    assert!(s.contains("p50="));
}

#[test]
fn test_tail_risk_record_serde_roundtrip() {
    let t = bad_tail();
    let json = serde_json::to_string(&t).unwrap();
    let back: TailRiskRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn test_gate_config_default_values() {
    let cfg = GateConfig::default();
    assert_eq!(cfg.min_speedup_fraction, 1_050_000);
    assert_eq!(cfg.max_parity_violations, 5);
    assert_eq!(cfg.max_skew_fraction, 200_000);
    assert_eq!(cfg.max_cold_penalty, 500_000);
    assert_eq!(cfg.max_tail_ratio, 3_000_000);
    assert_eq!(cfg.min_sample_count, 30);
}

#[test]
fn test_gate_config_strict() {
    let cfg = GateConfig::strict();
    assert_eq!(cfg.min_speedup_fraction, 1_200_000);
    assert_eq!(cfg.max_parity_violations, 0);
    assert_eq!(cfg.min_sample_count, 100);
}

#[test]
fn test_gate_config_permissive() {
    let cfg = GateConfig::permissive();
    assert_eq!(cfg.min_speedup_fraction, 0);
    assert_eq!(cfg.max_parity_violations, u64::MAX);
    assert_eq!(cfg.min_sample_count, 0);
}

#[test]
fn test_gate_config_display_contains_speedup() {
    let cfg = GateConfig::default();
    let s = cfg.to_string();
    assert!(s.contains("1050000"));
}

#[test]
fn test_gate_config_serde_roundtrip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// evaluate_parity
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_parity_good() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    assert!(evaluate_parity(&p, &cfg));
}

#[test]
fn test_evaluate_parity_insufficient_samples() {
    let cfg = GateConfig::default();
    let mut p = good_parity(BuiltinFamily::ArrayMap);
    p.sample_count = 10;
    assert!(!evaluate_parity(&p, &cfg));
}

#[test]
fn test_evaluate_parity_too_many_violations() {
    let cfg = GateConfig::default();
    let mut p = good_parity(BuiltinFamily::ArrayMap);
    p.parity_violations = 10;
    assert!(!evaluate_parity(&p, &cfg));
}

#[test]
fn test_evaluate_parity_speedup_below_minimum() {
    let cfg = GateConfig::default();
    let mut p = good_parity(BuiltinFamily::ArrayMap);
    p.speedup_fraction = 1_000_000;
    assert!(!evaluate_parity(&p, &cfg));
}

// ---------------------------------------------------------------------------
// evaluate_skew
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_skew_clean_returns_empty() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let result = evaluate_skew(&p, &[clean_skew()], &cfg);
    assert!(result.is_empty());
}

#[test]
fn test_evaluate_skew_bad_returns_failing() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let result = evaluate_skew(&p, &[bad_skew()], &cfg);
    assert_eq!(result.len(), 1);
}

// ---------------------------------------------------------------------------
// evaluate_cold_start
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_cold_start_negligible() {
    let cfg = GateConfig::default();
    let cs = mild_cold_start(BuiltinFamily::ArrayMap);
    assert_eq!(evaluate_cold_start(&cs, &cfg), ColdStartImpact::Negligible);
}

#[test]
fn test_evaluate_cold_start_severe() {
    let cfg = GateConfig::default();
    let cs = severe_cold_start(BuiltinFamily::JsonStringify);
    let impact = evaluate_cold_start(&cs, &cfg);
    assert!(!impact.is_acceptable());
}

#[test]
fn test_evaluate_cold_start_prohibitive() {
    let cfg = GateConfig::default();
    let cs = ColdStartRecord {
        builtin_family: BuiltinFamily::ArrayReduce,
        warmup_iterations: 1000,
        cold_penalty_fraction: 700_000, // 70%
        impact: ColdStartImpact::Prohibitive,
        epoch: epoch(10),
    };
    assert_eq!(evaluate_cold_start(&cs, &cfg), ColdStartImpact::Prohibitive);
}

// ---------------------------------------------------------------------------
// evaluate (main)
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_all_good_approved() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let result = evaluate(
        &p,
        &[clean_skew()],
        Some(&mild_cold_start(BuiltinFamily::ArrayMap)),
        Some(&good_tail()),
        &cfg,
    );
    assert_eq!(result.verdict, LaneVerdict::Approved);
    assert!(result.is_approved());
    assert!(!result.has_blockers());
}

#[test]
fn test_evaluate_bad_parity_rejected() {
    let cfg = GateConfig::default();
    let p = slow_parity(BuiltinFamily::JsonParse);
    let result = evaluate(&p, &[], None, None, &cfg);
    assert!(!result.is_approved());
}

#[test]
fn test_evaluate_slow_vectorized_fallback_required() {
    let cfg = GateConfig::default();
    let p = slow_parity(BuiltinFamily::JsonParse);
    let result = evaluate(&p, &[], None, None, &cfg);
    assert_eq!(result.verdict, LaneVerdict::FallbackRequired);
}

#[test]
fn test_evaluate_bad_skew_conditional() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let result = evaluate(&p, &[bad_skew()], None, None, &cfg);
    assert_eq!(result.verdict, LaneVerdict::ConditionalApproval);
}

#[test]
fn test_evaluate_bad_tail_conditional() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let result = evaluate(&p, &[], None, Some(&bad_tail()), &cfg);
    assert_eq!(result.verdict, LaneVerdict::ConditionalApproval);
}

#[test]
fn test_evaluate_severe_cold_start_adds_blocker() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let cs = severe_cold_start(BuiltinFamily::ArrayMap);
    let result = evaluate(&p, &[], Some(&cs), None, &cfg);
    assert!(result.has_blockers());
    assert!(
        result
            .blocking_reasons
            .iter()
            .any(|r| r.contains("cold-start"))
    );
}

#[test]
fn test_evaluate_multiple_blockers_rejected() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let cs = severe_cold_start(BuiltinFamily::ArrayMap);
    let result = evaluate(&p, &[bad_skew()], Some(&cs), Some(&bad_tail()), &cfg);
    assert_eq!(result.verdict, LaneVerdict::Rejected);
}

#[test]
fn test_evaluate_no_skew_no_cold_no_tail_approved() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::StringSearch);
    let result = evaluate(&p, &[], None, None, &cfg);
    assert_eq!(result.verdict, LaneVerdict::Approved);
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

#[test]
fn test_gate_result_display_contains_verdict() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let result = evaluate(&p, &[], None, None, &cfg);
    let s = result.to_string();
    assert!(s.contains("approved"));
}

#[test]
fn test_gate_result_serde_roundtrip() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let result = evaluate(
        &p,
        &[clean_skew()],
        Some(&mild_cold_start(BuiltinFamily::ArrayMap)),
        Some(&good_tail()),
        &cfg,
    );
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// Receipt hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_hash_deterministic() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let r1 = evaluate(&p, &[], None, None, &cfg);
    let r2 = evaluate(&p, &[], None, None, &cfg);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_differs_for_different_families() {
    let cfg = GateConfig::default();
    let p1 = good_parity(BuiltinFamily::ArrayMap);
    let p2 = good_parity(BuiltinFamily::JsonParse);
    let r1 = evaluate(&p1, &[], None, None, &cfg);
    let r2 = evaluate(&p2, &[], None, None, &cfg);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_is_32_bytes() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let result = evaluate(&p, &[], None, None, &cfg);
    assert_eq!(result.receipt_hash.as_bytes().len(), 32);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_decision_receipt_new() {
    let evidence_hash = ContentHash::compute(b"test evidence");
    let receipt = DecisionReceipt::new(epoch(10), LaneVerdict::Approved, evidence_hash.clone());
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.epoch, epoch(10));
    assert_eq!(receipt.verdict, LaneVerdict::Approved);
    assert_eq!(receipt.evidence_hash, evidence_hash);
}

#[test]
fn test_decision_receipt_deterministic_hash() {
    let evidence_hash = ContentHash::compute(b"same data");
    let r1 = DecisionReceipt::new(epoch(10), LaneVerdict::Approved, evidence_hash.clone());
    let r2 = DecisionReceipt::new(epoch(10), LaneVerdict::Approved, evidence_hash);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_decision_receipt_display_contains_verdict() {
    let evidence_hash = ContentHash::compute(b"data");
    let receipt = DecisionReceipt::new(epoch(5), LaneVerdict::Rejected, evidence_hash);
    let s = receipt.to_string();
    assert!(s.contains("rejected"));
}

#[test]
fn test_decision_receipt_serde_roundtrip() {
    let evidence_hash = ContentHash::compute(b"roundtrip");
    let receipt = DecisionReceipt::new(epoch(7), LaneVerdict::ConditionalApproval, evidence_hash);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// evaluate_batch
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_batch_all_approved() {
    let cfg = GateConfig::default();
    let items: Vec<_> = BuiltinFamily::ALL
        .iter()
        .map(|f| (good_parity(*f), vec![], None, None))
        .collect();
    let (results, summary) = evaluate_batch(&items, &cfg);
    assert_eq!(results.len(), 9);
    assert_eq!(summary.total, 9);
    assert!(summary.all_passed());
    assert!(!summary.has_rejections());
}

#[test]
fn test_evaluate_batch_mixed() {
    let cfg = GateConfig::default();
    let good = (good_parity(BuiltinFamily::ArrayMap), vec![], None, None);
    let bad = (slow_parity(BuiltinFamily::JsonParse), vec![], None, None);
    let (results, summary) = evaluate_batch(&[good, bad], &cfg);
    assert_eq!(results.len(), 2);
    assert!(!summary.all_passed());
    assert!(summary.has_rejections() || summary.fallback > 0);
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
fn test_gate_summary_all_passed_true() {
    let cfg = GateConfig::default();
    let items = vec![(good_parity(BuiltinFamily::ArrayMap), vec![], None, None)];
    let (_, summary) = evaluate_batch(&items, &cfg);
    assert!(summary.all_passed());
}

#[test]
fn test_gate_summary_has_rejections_false() {
    let cfg = GateConfig::default();
    let items = vec![(good_parity(BuiltinFamily::ArrayMap), vec![], None, None)];
    let (_, summary) = evaluate_batch(&items, &cfg);
    assert!(!summary.has_rejections());
}

#[test]
fn test_gate_summary_pass_rate_single_pass() {
    let cfg = GateConfig::default();
    let items = vec![(good_parity(BuiltinFamily::ArrayMap), vec![], None, None)];
    let (_, summary) = evaluate_batch(&items, &cfg);
    assert_eq!(summary.pass_rate, 1_000_000);
}

#[test]
fn test_gate_summary_display_contains_total() {
    let cfg = GateConfig::default();
    let items = vec![(good_parity(BuiltinFamily::ArrayMap), vec![], None, None)];
    let (_, summary) = evaluate_batch(&items, &cfg);
    let s = summary.to_string();
    assert!(s.contains("total=1"));
}

#[test]
fn test_gate_summary_serde_roundtrip() {
    let cfg = GateConfig::default();
    let items = vec![(good_parity(BuiltinFamily::ArrayMap), vec![], None, None)];
    let (_, summary) = evaluate_batch(&items, &cfg);
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_permissive_approves_bad_evidence() {
    let cfg = GateConfig::permissive();
    let p = slow_parity(BuiltinFamily::JsonParse);
    let result = evaluate(
        &p,
        &[bad_skew()],
        Some(&severe_cold_start(BuiltinFamily::JsonParse)),
        Some(&bad_tail()),
        &cfg,
    );
    assert_eq!(result.verdict, LaneVerdict::Approved);
}

#[test]
fn test_evaluate_all_builtin_families_good_parity() {
    let cfg = GateConfig::default();
    for f in BuiltinFamily::ALL {
        let p = good_parity(*f);
        let result = evaluate(&p, &[], None, None, &cfg);
        assert_eq!(result.verdict, LaneVerdict::Approved, "failed for {:?}", f);
    }
}

#[test]
fn test_evaluate_two_blockers_conditional_with_good_parity() {
    let cfg = GateConfig::default();
    let p = good_parity(BuiltinFamily::ArrayMap);
    let result = evaluate(
        &p,
        &[bad_skew()],
        Some(&severe_cold_start(BuiltinFamily::ArrayMap)),
        None,
        &cfg,
    );
    assert_eq!(result.verdict, LaneVerdict::ConditionalApproval);
}
