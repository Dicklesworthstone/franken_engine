#![forbid(unsafe_code)]

//! Enrichment integration tests for the `regexp_string_governance_gate` module.
//!
//! Covers Clone independence, BTreeSet ordering, Debug/Default, serde
//! field-name stability, determinism, and edge cases.

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

use frankenengine_engine::regexp_string_governance_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn sample_string_evidence() -> StringParityEvidence {
    StringParityEvidence::new(
        StringSurface::Concat,
        200,
        190,
        vec!["minor gap".to_string()],
        epoch(1),
    )
}

fn sample_regexp_evidence() -> RegExpParityEvidence {
    RegExpParityEvidence::new(
        RegExpSurface::Literal,
        200,
        195,
        500,
        UnicodeCompliance::Bmp,
        epoch(1),
    )
}

fn sample_benchmark() -> BenchmarkEvidence {
    BenchmarkEvidence::new(
        "concat",
        2_000_000,
        1_000_000,
        100_000,
        500_000,
        1000,
        epoch(1),
    )
}

fn sample_tail_risk() -> TailRiskRecord {
    TailRiskRecord::new("concat", 500, 800, 1500)
}

// ===========================================================================
// Copy semantics
// ===========================================================================

#[test]
fn enrichment_string_surface_copy() {
    let a = StringSurface::Concat;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_regexp_surface_copy() {
    let a = RegExpSurface::Literal;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_parity_verdict_copy() {
    let a = ParityVerdict::FullParity;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_unicode_compliance_copy() {
    let a = UnicodeCompliance::FullCompliant;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_gate_decision_copy() {
    let a = GateDecision::Ship;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// Clone independence
// ===========================================================================

#[test]
fn enrichment_string_evidence_clone_independence() {
    let original = sample_string_evidence();
    let mut cloned = original.clone();
    cloned.known_gaps.push("extra".to_string());
    assert_eq!(original.known_gaps.len(), 1);
    assert_eq!(cloned.known_gaps.len(), 2);
}

#[test]
fn enrichment_regexp_evidence_clone_independence() {
    let original = sample_regexp_evidence();
    let cloned = original.clone();
    assert_eq!(original.automata_states_tested, 500);
    assert_eq!(
        cloned.automata_states_tested,
        original.automata_states_tested
    );
}

#[test]
fn enrichment_benchmark_evidence_clone_independence() {
    let original = sample_benchmark();
    let mut cloned = original.clone();
    cloned.surface_name = "mutated".to_string();
    assert_eq!(original.surface_name, "concat");
}

#[test]
fn enrichment_tail_risk_record_clone_independence() {
    let original = sample_tail_risk();
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_gate_config_clone_independence() {
    let original = GateConfig::default();
    let cloned = original.clone();
    assert_eq!(original.max_known_gaps, DEFAULT_MAX_KNOWN_GAPS);
    assert_eq!(cloned.max_known_gaps, original.max_known_gaps);
}

// ===========================================================================
// BTreeSet ordering
// ===========================================================================

#[test]
fn enrichment_string_surface_btreeset_ordering() {
    let set: BTreeSet<StringSurface> = StringSurface::ALL.iter().copied().collect();
    assert_eq!(set.len(), StringSurface::ALL.len());
    let first = *set.iter().next().unwrap();
    assert_eq!(first, StringSurface::Concat);
}

#[test]
fn enrichment_regexp_surface_btreeset_ordering() {
    let set: BTreeSet<RegExpSurface> = RegExpSurface::ALL.iter().copied().collect();
    assert_eq!(set.len(), RegExpSurface::ALL.len());
    let first = *set.iter().next().unwrap();
    assert_eq!(first, RegExpSurface::Literal);
}

#[test]
fn enrichment_parity_verdict_btreeset() {
    let variants = [
        ParityVerdict::FullParity,
        ParityVerdict::PartialParity,
        ParityVerdict::KnownGap,
        ParityVerdict::FailOpen,
    ];
    let set: BTreeSet<ParityVerdict> = variants.into_iter().collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_gate_decision_btreeset() {
    let variants = [
        GateDecision::Ship,
        GateDecision::ConditionalShip,
        GateDecision::Block,
        GateDecision::RequireEvidence,
    ];
    let set: BTreeSet<GateDecision> = variants.into_iter().collect();
    assert_eq!(set.len(), 4);
}

// ===========================================================================
// Debug nonempty
// ===========================================================================

#[test]
fn enrichment_string_surface_debug() {
    for s in StringSurface::ALL {
        assert!(!format!("{:?}", s).is_empty());
    }
}

#[test]
fn enrichment_regexp_surface_debug() {
    for s in RegExpSurface::ALL {
        assert!(!format!("{:?}", s).is_empty());
    }
}

#[test]
fn enrichment_parity_verdict_debug() {
    let dbg = format!("{:?}", ParityVerdict::FullParity);
    assert!(dbg.contains("FullParity"));
}

#[test]
fn enrichment_unicode_compliance_debug() {
    let dbg = format!("{:?}", UnicodeCompliance::Bmp);
    assert!(dbg.contains("Bmp"));
}

#[test]
fn enrichment_gate_decision_debug() {
    let dbg = format!("{:?}", GateDecision::Block);
    assert!(dbg.contains("Block"));
}

#[test]
fn enrichment_gate_config_debug() {
    let dbg = format!("{:?}", GateConfig::default());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("GateConfig"));
}

#[test]
fn enrichment_gate_result_debug() {
    let result = evaluate(
        &[sample_string_evidence()],
        &[sample_regexp_evidence()],
        &[sample_benchmark()],
        &[sample_tail_risk()],
        &GateConfig::permissive(),
    );
    let dbg = format!("{:?}", result);
    assert!(dbg.contains("GateResult"));
}

// ===========================================================================
// Display coverage — all variants unique
// ===========================================================================

#[test]
fn enrichment_string_surface_display_all_unique() {
    let displays: BTreeSet<String> = StringSurface::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), StringSurface::ALL.len());
}

#[test]
fn enrichment_regexp_surface_display_all_unique() {
    let displays: BTreeSet<String> = RegExpSurface::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), RegExpSurface::ALL.len());
}

#[test]
fn enrichment_parity_verdict_display_all_unique() {
    let variants = [
        ParityVerdict::FullParity,
        ParityVerdict::PartialParity,
        ParityVerdict::KnownGap,
        ParityVerdict::FailOpen,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_unicode_compliance_display_all_unique() {
    let variants = [
        UnicodeCompliance::FullCompliant,
        UnicodeCompliance::Bmp,
        UnicodeCompliance::AsciiOnly,
        UnicodeCompliance::NonCompliant,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_gate_decision_display_all_unique() {
    let variants = [
        GateDecision::Ship,
        GateDecision::ConditionalShip,
        GateDecision::Block,
        GateDecision::RequireEvidence,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

// ===========================================================================
// as_str coverage
// ===========================================================================

#[test]
fn enrichment_string_surface_as_str_all() {
    let strs: BTreeSet<&str> = StringSurface::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(strs.len(), StringSurface::ALL.len());
}

#[test]
fn enrichment_regexp_surface_as_str_all() {
    let strs: BTreeSet<&str> = RegExpSurface::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(strs.len(), RegExpSurface::ALL.len());
}

#[test]
fn enrichment_parity_verdict_as_str_all() {
    let variants = [
        ParityVerdict::FullParity,
        ParityVerdict::PartialParity,
        ParityVerdict::KnownGap,
        ParityVerdict::FailOpen,
    ];
    let strs: BTreeSet<&str> = variants.iter().map(|v| v.as_str()).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_gate_decision_as_str_all() {
    let variants = [
        GateDecision::Ship,
        GateDecision::ConditionalShip,
        GateDecision::Block,
        GateDecision::RequireEvidence,
    ];
    let strs: BTreeSet<&str> = variants.iter().map(|v| v.as_str()).collect();
    assert_eq!(strs.len(), 4);
}

// ===========================================================================
// Default
// ===========================================================================

#[test]
fn enrichment_gate_config_default_values() {
    let c = GateConfig::default();
    assert_eq!(c.min_parity_fraction, DEFAULT_MIN_PARITY_FRACTION);
    assert_eq!(c.max_tail_ratio, DEFAULT_MAX_TAIL_RATIO);
    assert_eq!(c.min_test_count, DEFAULT_MIN_TEST_COUNT);
    assert_eq!(c.min_speedup_for_claim, DEFAULT_MIN_SPEEDUP_FOR_CLAIM);
    assert_eq!(c.max_known_gaps, DEFAULT_MAX_KNOWN_GAPS);
}

// ===========================================================================
// JSON field-name stability
// ===========================================================================

#[test]
fn enrichment_string_evidence_json_field_names() {
    let e = sample_string_evidence();
    let json = serde_json::to_value(&e).unwrap();
    let obj = json.as_object().unwrap();
    for field in [
        "surface",
        "test_count",
        "pass_count",
        "parity_fraction",
        "known_gaps",
        "epoch",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_regexp_evidence_json_field_names() {
    let e = sample_regexp_evidence();
    let json = serde_json::to_value(&e).unwrap();
    let obj = json.as_object().unwrap();
    for field in [
        "surface",
        "test_count",
        "pass_count",
        "parity_fraction",
        "automata_states_tested",
        "unicode_coverage",
        "epoch",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_benchmark_evidence_json_field_names() {
    let e = sample_benchmark();
    let json = serde_json::to_value(&e).unwrap();
    let obj = json.as_object().unwrap();
    for field in [
        "surface_name",
        "throughput_millionths",
        "baseline_throughput",
        "speedup_fraction",
        "tail_risk_fraction",
        "sample_count",
        "epoch",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_tail_risk_record_json_field_names() {
    let r = sample_tail_risk();
    let json = serde_json::to_value(&r).unwrap();
    let obj = json.as_object().unwrap();
    for field in [
        "surface_name",
        "p99_latency",
        "p999_latency",
        "max_latency",
        "tail_ratio",
        "acceptable",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_gate_config_json_field_names() {
    let c = GateConfig::default();
    let json = serde_json::to_value(&c).unwrap();
    let obj = json.as_object().unwrap();
    for field in [
        "min_parity_fraction",
        "min_unicode_compliance",
        "max_tail_ratio",
        "min_test_count",
        "min_speedup_for_claim",
        "max_known_gaps",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_gate_result_json_field_names() {
    let result = evaluate(
        &[sample_string_evidence()],
        &[sample_regexp_evidence()],
        &[sample_benchmark()],
        &[sample_tail_risk()],
        &GateConfig::permissive(),
    );
    let json = serde_json::to_value(&result).unwrap();
    let obj = json.as_object().unwrap();
    for field in [
        "decision",
        "parity_verdict",
        "unicode_compliance",
        "tail_risk_ok",
        "blocking_reasons",
        "receipt_hash",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

// ===========================================================================
// Serde roundtrips
// ===========================================================================

#[test]
fn enrichment_string_surface_serde_all() {
    let jsons: BTreeSet<String> = StringSurface::ALL
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
    assert_eq!(jsons.len(), StringSurface::ALL.len());
    for json in &jsons {
        let _: StringSurface = serde_json::from_str(json).unwrap();
    }
}

#[test]
fn enrichment_regexp_surface_serde_all() {
    let jsons: BTreeSet<String> = RegExpSurface::ALL
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
    assert_eq!(jsons.len(), RegExpSurface::ALL.len());
    for json in &jsons {
        let _: RegExpSurface = serde_json::from_str(json).unwrap();
    }
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let c = GateConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_gate_config_strict_serde_roundtrip() {
    let c = GateConfig::strict();
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn enrichment_evaluate_determinism_20_runs() {
    let string_ev = vec![sample_string_evidence()];
    let regexp_ev = vec![sample_regexp_evidence()];
    let bench_ev = vec![sample_benchmark()];
    let tail_ev = vec![sample_tail_risk()];
    let config = GateConfig::permissive();

    let mut hashes = BTreeSet::new();
    for _ in 0..20 {
        let result = evaluate(&string_ev, &regexp_ev, &bench_ev, &tail_ev, &config);
        hashes.insert(format!("{:?}", result.receipt_hash));
    }
    assert_eq!(hashes.len(), 1, "evaluate must be deterministic");
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert_eq!(FIXED_ONE, 1_000_000);
}

// ===========================================================================
// UnicodeCompliance methods
// ===========================================================================

#[test]
fn enrichment_unicode_compliance_rank_ordering() {
    assert!(UnicodeCompliance::FullCompliant.rank() > UnicodeCompliance::Bmp.rank());
    assert!(UnicodeCompliance::Bmp.rank() > UnicodeCompliance::AsciiOnly.rank());
    assert!(UnicodeCompliance::AsciiOnly.rank() > UnicodeCompliance::NonCompliant.rank());
}

#[test]
fn enrichment_unicode_compliance_meets_minimum() {
    assert!(UnicodeCompliance::FullCompliant.meets_minimum(UnicodeCompliance::Bmp));
    assert!(UnicodeCompliance::Bmp.meets_minimum(UnicodeCompliance::Bmp));
    assert!(!UnicodeCompliance::AsciiOnly.meets_minimum(UnicodeCompliance::Bmp));
}

// ===========================================================================
// ParityVerdict methods
// ===========================================================================

#[test]
fn enrichment_parity_verdict_allows_ship() {
    assert!(ParityVerdict::FullParity.allows_ship());
    assert!(ParityVerdict::PartialParity.allows_ship());
    assert!(!ParityVerdict::KnownGap.allows_ship());
    assert!(!ParityVerdict::FailOpen.allows_ship());
}

// ===========================================================================
// GateDecision methods
// ===========================================================================

#[test]
fn enrichment_gate_decision_allows_proceed() {
    assert!(GateDecision::Ship.allows_proceed());
    assert!(GateDecision::ConditionalShip.allows_proceed());
    assert!(!GateDecision::Block.allows_proceed());
    assert!(!GateDecision::RequireEvidence.allows_proceed());
}

// ===========================================================================
// BenchmarkEvidence methods
// ===========================================================================

#[test]
fn enrichment_benchmark_claims_speedup_positive() {
    let b = sample_benchmark();
    assert!(b.claims_speedup());
}

#[test]
fn enrichment_benchmark_claims_speedup_zero() {
    let b = BenchmarkEvidence::new("x", 1_000_000, 1_000_000, 0, 0, 100, epoch(1));
    assert!(!b.claims_speedup());
}

// ===========================================================================
// TailRiskRecord methods
// ===========================================================================

#[test]
fn enrichment_tail_risk_within_limit() {
    let r = sample_tail_risk();
    assert!(r.within_limit(5_000_000)); // generous limit
}

#[test]
fn enrichment_tail_risk_exceeds_limit() {
    let r = TailRiskRecord::new("x", 100, 1000, 2000); // ratio = 10x
    assert!(!r.within_limit(2_000_000));
}

#[test]
fn enrichment_tail_risk_zero_p99() {
    let r = TailRiskRecord::new("x", 0, 100, 200);
    assert_eq!(r.tail_ratio, 0); // checked_div returns 0 for division by 0
}

// ===========================================================================
// DecisionReceipt
// ===========================================================================

#[test]
fn enrichment_decision_receipt_from_result() {
    let result = evaluate(
        &[sample_string_evidence()],
        &[sample_regexp_evidence()],
        &[],
        &[],
        &GateConfig::permissive(),
    );
    let receipt = DecisionReceipt::from_result(&result, epoch(1));
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.decision, result.decision);
}

#[test]
fn enrichment_decision_receipt_determinism() {
    let result = evaluate(
        &[sample_string_evidence()],
        &[sample_regexp_evidence()],
        &[],
        &[],
        &GateConfig::permissive(),
    );
    let r1 = DecisionReceipt::from_result(&result, epoch(1));
    let r2 = DecisionReceipt::from_result(&result, epoch(1));
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

// ===========================================================================
// GateSummary
// ===========================================================================

#[test]
fn enrichment_gate_summary_from_empty() {
    let summary = GateSummary::from_results(&[]);
    assert_eq!(summary.total, 0);
    assert_eq!(summary.pass_rate, 0);
}

#[test]
fn enrichment_gate_summary_all_passing() {
    let result = evaluate(
        &[sample_string_evidence()],
        &[sample_regexp_evidence()],
        &[],
        &[],
        &GateConfig::permissive(),
    );
    let summary = GateSummary::from_results(&[result.clone(), result]);
    assert_eq!(summary.total, 2);
    assert!(summary.pass_rate > 0);
}
