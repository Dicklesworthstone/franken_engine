//! Integration tests for regexp_string_governance_gate module.

use frankenengine_engine::regexp_string_governance_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn good_string_ev(surface: StringSurface) -> StringParityEvidence {
    StringParityEvidence::new(surface, 200, 196, vec![], epoch(10))
}

fn good_regexp_ev(surface: RegExpSurface) -> RegExpParityEvidence {
    RegExpParityEvidence::new(
        surface,
        200,
        196,
        500,
        UnicodeCompliance::FullCompliant,
        epoch(10),
    )
}

fn good_bench(name: &str) -> BenchmarkEvidence {
    BenchmarkEvidence::new(name, 2_000_000, 1_500_000, 100_000, 500_000, 200, epoch(10))
}

fn good_tail(name: &str) -> TailRiskRecord {
    TailRiskRecord::new(name, 100, 150, 300)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_value() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.regexp-string-governance-gate.v1");
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "regexp_string_governance_gate");
}

#[test]
fn test_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.4.12.3");
}

#[test]
fn test_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-312C");
}

#[test]
fn test_fixed_one_value() {
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn test_default_min_parity_fraction() {
    assert_eq!(DEFAULT_MIN_PARITY_FRACTION, 950_000);
}

#[test]
fn test_default_max_tail_ratio() {
    assert_eq!(DEFAULT_MAX_TAIL_RATIO, 2_000_000);
}

#[test]
fn test_default_min_test_count() {
    assert_eq!(DEFAULT_MIN_TEST_COUNT, 100);
}

#[test]
fn test_default_min_speedup_for_claim() {
    assert_eq!(DEFAULT_MIN_SPEEDUP_FOR_CLAIM, 50_000);
}

#[test]
fn test_default_max_known_gaps() {
    assert_eq!(DEFAULT_MAX_KNOWN_GAPS, 3);
}

// ---------------------------------------------------------------------------
// StringSurface
// ---------------------------------------------------------------------------

#[test]
fn test_string_surface_all_has_eight_variants() {
    assert_eq!(StringSurface::ALL.len(), 8);
}

#[test]
fn test_string_surface_as_str_matches_display() {
    for s in StringSurface::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn test_string_surface_serde_roundtrip() {
    for s in StringSurface::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: StringSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn test_string_surface_concat_str() {
    assert_eq!(StringSurface::Concat.as_str(), "concat");
}

#[test]
fn test_string_surface_normalize_str() {
    assert_eq!(StringSurface::Normalize.as_str(), "normalize");
}

// ---------------------------------------------------------------------------
// RegExpSurface
// ---------------------------------------------------------------------------

#[test]
fn test_regexp_surface_all_has_eight_variants() {
    assert_eq!(RegExpSurface::ALL.len(), 8);
}

#[test]
fn test_regexp_surface_serde_roundtrip() {
    for s in RegExpSurface::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: RegExpSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn test_regexp_surface_display_matches_as_str() {
    for s in RegExpSurface::ALL {
        assert_eq!(s.to_string(), s.as_str());
    }
}

#[test]
fn test_regexp_surface_named_group_str() {
    assert_eq!(RegExpSurface::NamedGroup.as_str(), "named_group");
}

// ---------------------------------------------------------------------------
// ParityVerdict
// ---------------------------------------------------------------------------

#[test]
fn test_parity_verdict_allows_ship_full() {
    assert!(ParityVerdict::FullParity.allows_ship());
}

#[test]
fn test_parity_verdict_allows_ship_partial() {
    assert!(ParityVerdict::PartialParity.allows_ship());
}

#[test]
fn test_parity_verdict_blocks_known_gap() {
    assert!(!ParityVerdict::KnownGap.allows_ship());
}

#[test]
fn test_parity_verdict_blocks_fail_open() {
    assert!(!ParityVerdict::FailOpen.allows_ship());
}

#[test]
fn test_parity_verdict_serde_roundtrip() {
    let v = ParityVerdict::PartialParity;
    let json = serde_json::to_string(&v).unwrap();
    let back: ParityVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn test_parity_verdict_display() {
    assert_eq!(ParityVerdict::FullParity.to_string(), "full_parity");
    assert_eq!(ParityVerdict::KnownGap.to_string(), "known_gap");
    assert_eq!(ParityVerdict::FailOpen.to_string(), "fail_open");
}

// ---------------------------------------------------------------------------
// UnicodeCompliance
// ---------------------------------------------------------------------------

#[test]
fn test_unicode_compliance_rank_ordering() {
    assert!(UnicodeCompliance::FullCompliant.rank() > UnicodeCompliance::Bmp.rank());
    assert!(UnicodeCompliance::Bmp.rank() > UnicodeCompliance::AsciiOnly.rank());
    assert!(UnicodeCompliance::AsciiOnly.rank() > UnicodeCompliance::NonCompliant.rank());
}

#[test]
fn test_unicode_compliance_meets_minimum_true() {
    assert!(UnicodeCompliance::FullCompliant.meets_minimum(UnicodeCompliance::Bmp));
    assert!(UnicodeCompliance::Bmp.meets_minimum(UnicodeCompliance::Bmp));
}

#[test]
fn test_unicode_compliance_meets_minimum_false() {
    assert!(!UnicodeCompliance::AsciiOnly.meets_minimum(UnicodeCompliance::Bmp));
    assert!(!UnicodeCompliance::NonCompliant.meets_minimum(UnicodeCompliance::AsciiOnly));
}

#[test]
fn test_unicode_compliance_serde_roundtrip() {
    for uc in [
        UnicodeCompliance::FullCompliant,
        UnicodeCompliance::Bmp,
        UnicodeCompliance::AsciiOnly,
        UnicodeCompliance::NonCompliant,
    ] {
        let json = serde_json::to_string(&uc).unwrap();
        let back: UnicodeCompliance = serde_json::from_str(&json).unwrap();
        assert_eq!(uc, back);
    }
}

#[test]
fn test_unicode_compliance_display() {
    assert_eq!(UnicodeCompliance::Bmp.to_string(), "bmp");
    assert_eq!(UnicodeCompliance::AsciiOnly.to_string(), "ascii_only");
}

// ---------------------------------------------------------------------------
// GateDecision
// ---------------------------------------------------------------------------

#[test]
fn test_gate_decision_allows_proceed() {
    assert!(GateDecision::Ship.allows_proceed());
    assert!(GateDecision::ConditionalShip.allows_proceed());
    assert!(!GateDecision::Block.allows_proceed());
    assert!(!GateDecision::RequireEvidence.allows_proceed());
}

#[test]
fn test_gate_decision_serde_roundtrip() {
    let d = GateDecision::ConditionalShip;
    let json = serde_json::to_string(&d).unwrap();
    let back: GateDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn test_gate_decision_display() {
    assert_eq!(GateDecision::Ship.to_string(), "ship");
    assert_eq!(GateDecision::Block.to_string(), "block");
    assert_eq!(GateDecision::RequireEvidence.to_string(), "require_evidence");
}

// ---------------------------------------------------------------------------
// StringParityEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_string_parity_evidence_computes_fraction() {
    let ev = StringParityEvidence::new(StringSurface::Concat, 200, 190, vec![], epoch(1));
    assert_eq!(ev.parity_fraction, 950_000);
}

#[test]
fn test_string_parity_evidence_zero_tests_fraction_zero() {
    let ev = StringParityEvidence::new(StringSurface::Slice, 0, 0, vec![], epoch(1));
    assert_eq!(ev.parity_fraction, 0);
}

#[test]
fn test_string_parity_evidence_display_contains_surface() {
    let ev = StringParityEvidence::new(StringSurface::Search, 100, 95, vec!["g".into()], epoch(1));
    let s = ev.to_string();
    assert!(s.contains("search"));
}

#[test]
fn test_string_parity_evidence_serde_roundtrip() {
    let ev = StringParityEvidence::new(StringSurface::Replace, 100, 99, vec![], epoch(5));
    let json = serde_json::to_string(&ev).unwrap();
    let back: StringParityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// RegExpParityEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_regexp_parity_evidence_computes_fraction() {
    let ev = RegExpParityEvidence::new(
        RegExpSurface::Literal, 200, 198, 300, UnicodeCompliance::FullCompliant, epoch(1),
    );
    assert_eq!(ev.parity_fraction, 990_000);
}

#[test]
fn test_regexp_parity_evidence_zero_tests_fraction_zero() {
    let ev = RegExpParityEvidence::new(
        RegExpSurface::CharClass, 0, 0, 0, UnicodeCompliance::Bmp, epoch(1),
    );
    assert_eq!(ev.parity_fraction, 0);
}

#[test]
fn test_regexp_parity_evidence_display_contains_surface() {
    let ev = RegExpParityEvidence::new(
        RegExpSurface::Backreference, 100, 90, 200, UnicodeCompliance::AsciiOnly, epoch(1),
    );
    let s = ev.to_string();
    assert!(s.contains("backreference"));
    assert!(s.contains("ascii_only"));
}

#[test]
fn test_regexp_parity_evidence_serde_roundtrip() {
    let ev = RegExpParityEvidence::new(
        RegExpSurface::Lookahead, 150, 140, 100, UnicodeCompliance::Bmp, epoch(3),
    );
    let json = serde_json::to_string(&ev).unwrap();
    let back: RegExpParityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// BenchmarkEvidence
// ---------------------------------------------------------------------------

#[test]
fn test_benchmark_evidence_claims_speedup_true() {
    let ev = BenchmarkEvidence::new("concat", 2_000_000, 1_500_000, 100_000, 500_000, 200, epoch(1));
    assert!(ev.claims_speedup());
}

#[test]
fn test_benchmark_evidence_claims_speedup_false_zero() {
    let ev = BenchmarkEvidence::new("search", 1_000_000, 1_000_000, 0, 300_000, 100, epoch(1));
    assert!(!ev.claims_speedup());
}

#[test]
fn test_benchmark_evidence_display_contains_name() {
    let ev = good_bench("template");
    let s = ev.to_string();
    assert!(s.contains("template"));
}

#[test]
fn test_benchmark_evidence_serde_roundtrip() {
    let ev = good_bench("slice");
    let json = serde_json::to_string(&ev).unwrap();
    let back: BenchmarkEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// TailRiskRecord
// ---------------------------------------------------------------------------

#[test]
fn test_tail_risk_record_computes_ratio() {
    let tr = TailRiskRecord::new("search", 100, 150, 300);
    assert_eq!(tr.tail_ratio, 1_500_000);
}

#[test]
fn test_tail_risk_record_zero_p99_ratio_zero() {
    let tr = TailRiskRecord::new("zero", 0, 0, 0);
    assert_eq!(tr.tail_ratio, 0);
}

#[test]
fn test_tail_risk_record_acceptable_within_default() {
    let tr = TailRiskRecord::new("ok", 100, 180, 300);
    assert!(tr.acceptable);
}

#[test]
fn test_tail_risk_record_unacceptable_exceeds_default() {
    let tr = TailRiskRecord::new("bad", 100, 300, 500);
    assert!(!tr.acceptable);
}

#[test]
fn test_tail_risk_record_within_limit_custom() {
    let tr = TailRiskRecord::new("custom", 100, 150, 300);
    assert!(tr.within_limit(2_000_000));
    assert!(!tr.within_limit(1_000_000));
}

#[test]
fn test_tail_risk_record_display_contains_name() {
    let tr = good_tail("concat");
    let s = tr.to_string();
    assert!(s.contains("concat"));
}

#[test]
fn test_tail_risk_record_serde_roundtrip() {
    let tr = good_tail("roundtrip");
    let json = serde_json::to_string(&tr).unwrap();
    let back: TailRiskRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(tr, back);
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

#[test]
fn test_gate_config_default_values() {
    let cfg = GateConfig::default();
    assert_eq!(cfg.min_parity_fraction, DEFAULT_MIN_PARITY_FRACTION);
    assert_eq!(cfg.max_tail_ratio, DEFAULT_MAX_TAIL_RATIO);
    assert_eq!(cfg.min_test_count, DEFAULT_MIN_TEST_COUNT);
    assert_eq!(cfg.min_speedup_for_claim, DEFAULT_MIN_SPEEDUP_FOR_CLAIM);
    assert_eq!(cfg.max_known_gaps, DEFAULT_MAX_KNOWN_GAPS);
    assert_eq!(cfg.min_unicode_compliance, UnicodeCompliance::Bmp);
}

#[test]
fn test_gate_config_strict() {
    let cfg = GateConfig::strict();
    assert_eq!(cfg.min_parity_fraction, 990_000);
    assert_eq!(cfg.min_unicode_compliance, UnicodeCompliance::FullCompliant);
    assert_eq!(cfg.max_known_gaps, 0);
}

#[test]
fn test_gate_config_permissive() {
    let cfg = GateConfig::permissive();
    assert_eq!(cfg.min_parity_fraction, 0);
    assert_eq!(cfg.min_unicode_compliance, UnicodeCompliance::NonCompliant);
    assert_eq!(cfg.max_known_gaps, usize::MAX);
}

#[test]
fn test_gate_config_serde_roundtrip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// evaluate_string_parity
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_string_parity_full_parity() {
    let ev = StringParityEvidence::new(StringSurface::Concat, 200, 196, vec![], epoch(1));
    let cfg = GateConfig::default();
    assert_eq!(evaluate_string_parity(&ev, &cfg), ParityVerdict::FullParity);
}

#[test]
fn test_evaluate_string_parity_insufficient_tests() {
    let ev = StringParityEvidence::new(StringSurface::Concat, 50, 50, vec![], epoch(1));
    let cfg = GateConfig::default();
    assert_eq!(evaluate_string_parity(&ev, &cfg), ParityVerdict::FailOpen);
}

#[test]
fn test_evaluate_string_parity_too_many_gaps() {
    let gaps = vec!["a".into(), "b".into(), "c".into(), "d".into()];
    let ev = StringParityEvidence::new(StringSurface::Replace, 200, 196, gaps, epoch(1));
    let cfg = GateConfig::default();
    assert_eq!(evaluate_string_parity(&ev, &cfg), ParityVerdict::KnownGap);
}

#[test]
fn test_evaluate_string_parity_partial_with_gaps() {
    let ev = StringParityEvidence::new(StringSurface::Split, 200, 196, vec!["g".into()], epoch(1));
    let cfg = GateConfig::default();
    assert_eq!(evaluate_string_parity(&ev, &cfg), ParityVerdict::PartialParity);
}

#[test]
fn test_evaluate_string_parity_below_threshold_with_gaps() {
    let ev = StringParityEvidence::new(StringSurface::Template, 200, 170, vec!["g".into()], epoch(1));
    let cfg = GateConfig::default();
    assert_eq!(evaluate_string_parity(&ev, &cfg), ParityVerdict::KnownGap);
}

#[test]
fn test_evaluate_string_parity_close_threshold_no_gaps() {
    // 91% = 910_000, within 5% of 950_000 threshold
    let ev = StringParityEvidence::new(StringSurface::Compare, 200, 182, vec![], epoch(1));
    let cfg = GateConfig::default();
    assert_eq!(evaluate_string_parity(&ev, &cfg), ParityVerdict::PartialParity);
}

// ---------------------------------------------------------------------------
// evaluate_regexp_parity
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_regexp_parity_full_with_unicode() {
    let ev = RegExpParityEvidence::new(
        RegExpSurface::Literal, 200, 196, 500, UnicodeCompliance::FullCompliant, epoch(1),
    );
    let cfg = GateConfig::default();
    assert_eq!(evaluate_regexp_parity(&ev, &cfg), ParityVerdict::FullParity);
}

#[test]
fn test_evaluate_regexp_parity_insufficient_tests() {
    let ev = RegExpParityEvidence::new(
        RegExpSurface::Literal, 50, 50, 100, UnicodeCompliance::Bmp, epoch(1),
    );
    let cfg = GateConfig::default();
    assert_eq!(evaluate_regexp_parity(&ev, &cfg), ParityVerdict::FailOpen);
}

#[test]
fn test_evaluate_regexp_parity_partial_unicode_below() {
    let ev = RegExpParityEvidence::new(
        RegExpSurface::UnicodeProperty, 200, 196, 300, UnicodeCompliance::AsciiOnly, epoch(1),
    );
    let cfg = GateConfig::default();
    assert_eq!(evaluate_regexp_parity(&ev, &cfg), ParityVerdict::PartialParity);
}

// ---------------------------------------------------------------------------
// evaluate_unicode
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_unicode_returns_evidence_level() {
    let ev = RegExpParityEvidence::new(
        RegExpSurface::CharClass, 200, 196, 100, UnicodeCompliance::Bmp, epoch(1),
    );
    let cfg = GateConfig::default();
    let uc = evaluate_unicode(&ev, &cfg);
    assert_eq!(uc, UnicodeCompliance::Bmp);
}

// ---------------------------------------------------------------------------
// Main evaluate
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_all_good_evidence_ships() {
    let cfg = GateConfig::default();
    let string_ev: Vec<StringParityEvidence> = StringSurface::ALL.iter()
        .map(|s| good_string_ev(*s))
        .collect();
    let regexp_ev: Vec<RegExpParityEvidence> = RegExpSurface::ALL.iter()
        .map(|s| good_regexp_ev(*s))
        .collect();
    let bench_ev = vec![good_bench("concat")];
    let tail_ev = vec![good_tail("concat")];

    let result = evaluate(&string_ev, &regexp_ev, &bench_ev, &tail_ev, &cfg);
    assert_eq!(result.decision, GateDecision::Ship);
    assert!(result.allows_proceed());
    assert!(result.blocking_reasons.is_empty());
}

#[test]
fn test_evaluate_no_evidence_requires_evidence() {
    let cfg = GateConfig::default();
    let result = evaluate(&[], &[], &[], &[], &cfg);
    assert_eq!(result.decision, GateDecision::RequireEvidence);
}

#[test]
fn test_evaluate_tail_risk_exceeds_blocks() {
    let cfg = GateConfig::default();
    let string_ev = vec![good_string_ev(StringSurface::Concat)];
    let regexp_ev = vec![good_regexp_ev(RegExpSurface::Literal)];
    let bad_tail = vec![TailRiskRecord::new("bad", 100, 300, 500)];

    let result = evaluate(&string_ev, &regexp_ev, &[], &bad_tail, &cfg);
    assert_eq!(result.decision, GateDecision::Block);
    assert!(!result.tail_risk_ok);
}

#[test]
fn test_evaluate_known_gap_blocks() {
    let cfg = GateConfig::default();
    let gaps: Vec<String> = (0..5).map(|i| format!("gap_{i}")).collect();
    let string_ev = vec![
        StringParityEvidence::new(StringSurface::Concat, 200, 196, gaps, epoch(10)),
    ];

    let result = evaluate(&string_ev, &[], &[], &[], &cfg);
    assert_eq!(result.decision, GateDecision::Block);
}

#[test]
fn test_evaluate_fail_open_requires_evidence() {
    let cfg = GateConfig::default();
    let string_ev = vec![
        StringParityEvidence::new(StringSurface::Concat, 10, 10, vec![], epoch(10)),
    ];

    let result = evaluate(&string_ev, &[], &[], &[], &cfg);
    assert_eq!(result.decision, GateDecision::RequireEvidence);
}

#[test]
fn test_evaluate_benchmark_speedup_below_min_conditional() {
    let cfg = GateConfig::default();
    let string_ev = vec![good_string_ev(StringSurface::Concat)];
    let bench = vec![BenchmarkEvidence::new("concat", 1_100_000, 1_000_000, 10_000, 200_000, 200, epoch(10))];

    let result = evaluate(&string_ev, &[], &bench, &[], &cfg);
    assert_eq!(result.decision, GateDecision::ConditionalShip);
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

#[test]
fn test_gate_result_display_contains_decision() {
    let cfg = GateConfig::default();
    let result = evaluate(&[], &[], &[], &[], &cfg);
    let s = result.to_string();
    assert!(s.contains("require_evidence"));
}

#[test]
fn test_gate_result_serde_roundtrip() {
    let cfg = GateConfig::default();
    let string_ev = vec![good_string_ev(StringSurface::Concat)];
    let result = evaluate(&string_ev, &[], &[], &[], &cfg);
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
    let string_ev = vec![good_string_ev(StringSurface::Concat)];
    let r1 = evaluate(&string_ev, &[], &[], &[], &cfg);
    let r2 = evaluate(&string_ev, &[], &[], &[], &cfg);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_differs_for_different_inputs() {
    let cfg = GateConfig::default();
    let ev_a = vec![good_string_ev(StringSurface::Concat)];
    let ev_b = vec![good_string_ev(StringSurface::Slice)];
    let r1 = evaluate(&ev_a, &[], &[], &[], &cfg);
    let r2 = evaluate(&ev_b, &[], &[], &[], &cfg);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_decision_receipt_from_result() {
    let cfg = GateConfig::default();
    let string_ev = vec![good_string_ev(StringSurface::Concat)];
    let result = evaluate(&string_ev, &[], &[], &[], &cfg);
    let receipt = DecisionReceipt::from_result(&result, epoch(10));
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.epoch, epoch(10));
    assert_eq!(receipt.decision, result.decision);
}

#[test]
fn test_decision_receipt_display_contains_component() {
    let cfg = GateConfig::default();
    let result = evaluate(&[], &[], &[], &[], &cfg);
    let receipt = DecisionReceipt::from_result(&result, epoch(5));
    let s = receipt.to_string();
    assert!(s.contains(COMPONENT));
}

#[test]
fn test_decision_receipt_deterministic_hash() {
    let cfg = GateConfig::default();
    let ev = vec![good_string_ev(StringSurface::Concat)];
    let r = evaluate(&ev, &[], &[], &[], &cfg);
    let rcpt1 = DecisionReceipt::from_result(&r, epoch(10));
    let rcpt2 = DecisionReceipt::from_result(&r, epoch(10));
    assert_eq!(rcpt1.receipt_hash, rcpt2.receipt_hash);
}

#[test]
fn test_decision_receipt_serde_roundtrip() {
    let cfg = GateConfig::default();
    let ev = vec![good_string_ev(StringSurface::Concat)];
    let r = evaluate(&ev, &[], &[], &[], &cfg);
    let rcpt = DecisionReceipt::from_result(&r, epoch(10));
    let json = serde_json::to_string(&rcpt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(rcpt, back);
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

#[test]
fn test_gate_summary_from_ship_results() {
    let cfg = GateConfig::default();
    let ev = vec![good_string_ev(StringSurface::Concat)];
    let r = evaluate(&ev, &[], &[], &[], &cfg);
    let summary = GateSummary::from_results(&[r]);
    assert_eq!(summary.total, 1);
    assert_eq!(summary.shipped, 1);
    assert_eq!(summary.blocked, 0);
}

#[test]
fn test_gate_summary_from_empty() {
    let summary = GateSummary::from_results(&[]);
    assert_eq!(summary.total, 0);
    assert_eq!(summary.pass_rate, 0);
}

#[test]
fn test_gate_summary_mixed_results() {
    let cfg = GateConfig::default();
    let good = evaluate(&[good_string_ev(StringSurface::Concat)], &[], &[], &[], &cfg);
    let bad = evaluate(&[], &[], &[], &[], &cfg);
    let summary = GateSummary::from_results(&[good, bad]);
    assert_eq!(summary.total, 2);
    assert_eq!(summary.shipped, 1);
    assert_eq!(summary.insufficient, 1);
    assert_eq!(summary.pass_rate, 500_000);
}

#[test]
fn test_gate_summary_display_contains_total() {
    let summary = GateSummary::from_results(&[]);
    let s = summary.to_string();
    assert!(s.contains("total=0"));
}

#[test]
fn test_gate_summary_serde_roundtrip() {
    let summary = GateSummary::from_results(&[]);
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// Edge cases and combined scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_permissive_config_ships_everything() {
    let cfg = GateConfig::permissive();
    let ev = StringParityEvidence::new(StringSurface::Concat, 1, 0, vec!["bad".into()], epoch(1));
    let result = evaluate(&[ev], &[], &[], &[], &cfg);
    assert!(result.decision.allows_proceed());
}

#[test]
fn test_evaluate_strict_config_blocks_partial() {
    let cfg = GateConfig::strict();
    let ev = StringParityEvidence::new(
        StringSurface::Concat, 200, 196, vec!["gap".into()], epoch(1),
    );
    let result = evaluate(&[ev], &[], &[], &[], &cfg);
    assert_eq!(result.decision, GateDecision::Block);
}

#[test]
fn test_evaluate_multiple_surfaces_worst_wins() {
    let cfg = GateConfig::default();
    let good = good_string_ev(StringSurface::Concat);
    let bad = StringParityEvidence::new(StringSurface::Slice, 10, 10, vec![], epoch(10));
    let result = evaluate(&[good, bad], &[], &[], &[], &cfg);
    assert_eq!(result.parity_verdict, ParityVerdict::FailOpen);
}

#[test]
fn test_evaluate_unicode_below_min_adds_blocking_reason() {
    let cfg = GateConfig::default();
    let regexp_ev = vec![RegExpParityEvidence::new(
        RegExpSurface::UnicodeProperty, 200, 196, 300, UnicodeCompliance::NonCompliant, epoch(10),
    )];
    let result = evaluate(&[], &regexp_ev, &[], &[], &cfg);
    assert!(result.blocking_reasons.iter().any(|r| r.contains("unicode")));
}

#[test]
fn test_content_hash_is_32_bytes() {
    let cfg = GateConfig::default();
    let ev = vec![good_string_ev(StringSurface::Concat)];
    let result = evaluate(&ev, &[], &[], &[], &cfg);
    assert_eq!(result.receipt_hash.as_bytes().len(), 32);
}
