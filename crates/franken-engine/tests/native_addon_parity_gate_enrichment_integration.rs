//! Enrichment integration tests for `native_addon_parity_gate`.
//!
//! Covers: serde round-trips for all enum and struct types, GateEvaluator
//! lifecycle, verdict computation, violation detection, receipt sealing
//! and determinism, config builders, summary statistics, and boundary
//! conditions.

#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;

use frankenengine_engine::native_addon_parity_gate::{
    AddonCohort, BEAD_ID, COMPONENT, DEFAULT_MAX_SECURITY_FINDINGS,
    DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS, DEFAULT_MIN_PARITY_MILLIONTHS,
    DEFAULT_MIN_SAMPLE_COUNT, DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS, FindingCategory,
    FindingSeverity, GateAxis, GateConfig, GateEvaluator, GateSummary, GateVerdict,
    MILLIONTHS, POLICY_ID, ParityEntry, SCHEMA_VERSION, SecurityFinding, SupportSurfaceEntry,
    ThroughputEntry, Violation, native_addon_parity_gate_manifest,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ===========================================================================
// Serde round-trip tests
// ===========================================================================

#[test]
fn integ_addon_cohort_serde_all() {
    for c in AddonCohort::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: AddonCohort = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn integ_gate_axis_serde_all() {
    for a in GateAxis::ALL {
        let json = serde_json::to_string(a).unwrap();
        let back: GateAxis = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, back);
    }
}

#[test]
fn integ_finding_severity_serde_all() {
    for s in FindingSeverity::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: FindingSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn integ_finding_category_serde_all() {
    for c in FindingCategory::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: FindingCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn integ_gate_verdict_serde_all() {
    for v in [
        GateVerdict::Approved,
        GateVerdict::ParityViolation,
        GateVerdict::SecurityBlocking,
        GateVerdict::ThroughputExceeded,
        GateVerdict::SupportInsufficient,
        GateVerdict::MultipleViolations,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn integ_gate_config_serde_roundtrip() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn integ_gate_config_strict_serde_roundtrip() {
    let config = GateConfig::strict();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn integ_gate_config_permissive_serde_roundtrip() {
    let config = GateConfig::permissive();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn integ_violation_serde_roundtrip() {
    let v = Violation::new(GateAxis::Security, Some(AddonCohort::Crypto), "CVE found");
    let json = serde_json::to_string(&v).unwrap();
    let back: Violation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn integ_gate_summary_serde_roundtrip() {
    let s = GateSummary {
        total_evaluations: 10,
        approved_count: 7,
        denied_count: 3,
        parity_entries: 20,
        security_findings: 2,
        throughput_entries: 15,
        support_surface_entries: 5,
        approval_rate_millionths: 700_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ===========================================================================
// Display tests
// ===========================================================================

#[test]
fn integ_addon_cohort_display_all_unique() {
    let mut displays = BTreeSet::new();
    for c in AddonCohort::ALL {
        displays.insert(c.to_string());
    }
    assert_eq!(displays.len(), 8);
}

#[test]
fn integ_gate_axis_display_all_unique() {
    let mut displays = BTreeSet::new();
    for a in GateAxis::ALL {
        displays.insert(a.to_string());
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn integ_finding_severity_display_all_unique() {
    let mut displays = BTreeSet::new();
    for s in FindingSeverity::ALL {
        displays.insert(s.to_string());
    }
    assert_eq!(displays.len(), 4);
}

#[test]
fn integ_finding_category_display_all_unique() {
    let mut displays = BTreeSet::new();
    for c in FindingCategory::ALL {
        displays.insert(c.to_string());
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn integ_gate_verdict_display_all_unique() {
    let verdicts = [
        GateVerdict::Approved,
        GateVerdict::ParityViolation,
        GateVerdict::SecurityBlocking,
        GateVerdict::ThroughputExceeded,
        GateVerdict::SupportInsufficient,
        GateVerdict::MultipleViolations,
    ];
    let mut displays = BTreeSet::new();
    for v in &verdicts {
        displays.insert(v.to_string());
    }
    assert_eq!(displays.len(), 6);
}

// ===========================================================================
// GateVerdict properties
// ===========================================================================

#[test]
fn integ_verdict_approved_properties() {
    assert!(GateVerdict::Approved.is_approved());
    assert!(!GateVerdict::Approved.is_blocking());
}

#[test]
fn integ_verdict_blocking_properties() {
    for v in [
        GateVerdict::ParityViolation,
        GateVerdict::SecurityBlocking,
        GateVerdict::ThroughputExceeded,
        GateVerdict::SupportInsufficient,
        GateVerdict::MultipleViolations,
    ] {
        assert!(!v.is_approved());
        assert!(v.is_blocking());
    }
}

// ===========================================================================
// FindingSeverity properties
// ===========================================================================

#[test]
fn integ_finding_severity_blocking() {
    assert!(FindingSeverity::Critical.is_blocking());
    assert!(FindingSeverity::High.is_blocking());
    assert!(!FindingSeverity::Medium.is_blocking());
    assert!(!FindingSeverity::Low.is_blocking());
}

// ===========================================================================
// SecurityFinding
// ===========================================================================

#[test]
fn integ_security_finding_deterministic_hash() {
    let a = SecurityFinding::new(FindingSeverity::High, FindingCategory::UseAfterFree, "addon-a", "uaf");
    let b = SecurityFinding::new(FindingSeverity::High, FindingCategory::UseAfterFree, "addon-a", "uaf");
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn integ_security_finding_blocking_flag() {
    let f = SecurityFinding::new(FindingSeverity::Critical, FindingCategory::BufferOverflow, "x", "desc");
    assert!(f.is_blocking());
    let f2 = SecurityFinding::new(FindingSeverity::Low, FindingCategory::InfoLeak, "x", "desc");
    assert!(!f2.is_blocking());
}

// ===========================================================================
// ThroughputEntry
// ===========================================================================

#[test]
fn integ_throughput_entry_no_overhead() {
    let e = ThroughputEntry::new(AddonCohort::Crypto, "fast", 1_000_000, 1_000_000, DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS);
    assert_eq!(e.overhead_millionths, 0);
    assert!(e.within_budget);
}

#[test]
fn integ_throughput_entry_over_budget() {
    let e = ThroughputEntry::new(AddonCohort::Database, "slow", 1_000_000, 800_000, DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS);
    assert_eq!(e.overhead_millionths, 200_000);
    assert!(!e.within_budget);
}

#[test]
fn integ_throughput_entry_zero_native() {
    let e = ThroughputEntry::new(AddonCohort::Networking, "tls", 0, 100, DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS);
    assert_eq!(e.overhead_millionths, 0);
    assert!(e.within_budget);
}

// ===========================================================================
// ParityEntry
// ===========================================================================

#[test]
fn integ_parity_entry_passes() {
    let e = ParityEntry::new(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50, DEFAULT_MIN_PARITY_MILLIONTHS, DEFAULT_MIN_SAMPLE_COUNT);
    assert!(e.passes);
}

#[test]
fn integ_parity_entry_fails_low_parity() {
    let e = ParityEntry::new(AddonCohort::Crypto, "aes", GateAxis::Parity, 900_000, 50, DEFAULT_MIN_PARITY_MILLIONTHS, DEFAULT_MIN_SAMPLE_COUNT);
    assert!(!e.passes);
}

#[test]
fn integ_parity_entry_fails_low_samples() {
    let e = ParityEntry::new(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 5, DEFAULT_MIN_PARITY_MILLIONTHS, DEFAULT_MIN_SAMPLE_COUNT);
    assert!(!e.passes);
}

// ===========================================================================
// SupportSurfaceEntry
// ===========================================================================

#[test]
fn integ_support_surface_full_coverage() {
    let e = SupportSurfaceEntry::new(AddonCohort::MediaCodec, 100, 100);
    assert_eq!(e.coverage_millionths, MILLIONTHS);
    assert!(e.meets_minimum(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS));
}

#[test]
fn integ_support_surface_half_coverage() {
    let e = SupportSurfaceEntry::new(AddonCohort::Database, 50, 100);
    assert_eq!(e.coverage_millionths, 500_000);
    assert!(!e.meets_minimum(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS));
}

#[test]
fn integ_support_surface_zero_total() {
    let e = SupportSurfaceEntry::new(AddonCohort::Networking, 0, 0);
    assert_eq!(e.coverage_millionths, 0);
}

// ===========================================================================
// GateEvaluator lifecycle
// ===========================================================================

#[test]
fn integ_evaluator_new_empty_state() {
    let g = GateEvaluator::with_defaults(ep(1));
    assert_eq!(g.evaluation_count(), 0);
    assert_eq!(g.approved_count(), 0);
    assert_eq!(g.denied_count(), 0);
    assert!(g.last_receipt().is_none());
}

#[test]
fn integ_evaluator_approved_all_pass() {
    let mut g = GateEvaluator::with_defaults(ep(1));
    g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
    g.add_throughput(AddonCohort::Crypto, "aes", 1_000_000, 950_000);
    g.add_support_surface(AddonCohort::Crypto, 90, 100);
    let receipt = g.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::Approved);
    assert!(receipt.violations.is_empty());
    assert_eq!(g.approved_count(), 1);
}

#[test]
fn integ_evaluator_parity_violation() {
    let mut g = GateEvaluator::with_defaults(ep(1));
    g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 900_000, 50);
    let receipt = g.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::ParityViolation);
    assert_eq!(receipt.violations.len(), 1);
}

#[test]
fn integ_evaluator_security_blocking() {
    let mut g = GateEvaluator::with_defaults(ep(1));
    g.add_security_finding(FindingSeverity::Critical, FindingCategory::BufferOverflow, "x", "heap overflow");
    let receipt = g.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::SecurityBlocking);
    assert_eq!(receipt.blocking_finding_count(), 1);
}

#[test]
fn integ_evaluator_throughput_exceeded() {
    let mut g = GateEvaluator::with_defaults(ep(1));
    g.add_throughput(AddonCohort::Database, "pg", 1_000_000, 700_000);
    let receipt = g.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::ThroughputExceeded);
}

#[test]
fn integ_evaluator_support_insufficient() {
    let mut g = GateEvaluator::with_defaults(ep(1));
    g.add_support_surface(AddonCohort::MediaCodec, 30, 100);
    let receipt = g.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::SupportInsufficient);
}

#[test]
fn integ_evaluator_multiple_violations() {
    let mut g = GateEvaluator::with_defaults(ep(1));
    g.add_parity(AddonCohort::Crypto, "x", GateAxis::Parity, 800_000, 50);
    g.add_throughput(AddonCohort::Crypto, "x", 1_000_000, 700_000);
    let receipt = g.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::MultipleViolations);
}

#[test]
fn integ_evaluator_missing_required_cohort() {
    let config = GateConfig::default()
        .with_required_cohort(AddonCohort::Crypto)
        .with_required_cohort(AddonCohort::Compression);
    let mut g = GateEvaluator::new(config, ep(1));
    g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
    let receipt = g.evaluate();
    assert!(!receipt.is_approved());
    assert!(receipt.missing_cohorts.contains(&AddonCohort::Compression));
}

#[test]
fn integ_evaluator_clear_resets_evidence() {
    let mut g = GateEvaluator::with_defaults(ep(1));
    g.add_parity(AddonCohort::Crypto, "x", GateAxis::Parity, MILLIONTHS, 50);
    g.add_security_finding(FindingSeverity::Low, FindingCategory::InfoLeak, "x", "info");
    g.add_throughput(AddonCohort::Crypto, "x", 1000, 900);
    g.add_support_surface(AddonCohort::Crypto, 80, 100);
    g.clear();
    assert_eq!(g.parity_entry_count(), 0);
    assert_eq!(g.security_finding_count(), 0);
    assert_eq!(g.throughput_entry_count(), 0);
    assert_eq!(g.support_surface_entry_count(), 0);
}

// ===========================================================================
// Receipt determinism
// ===========================================================================

#[test]
fn integ_receipt_hash_deterministic() {
    let mut g1 = GateEvaluator::with_defaults(ep(1));
    g1.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
    let r1 = g1.evaluate();

    let mut g2 = GateEvaluator::with_defaults(ep(1));
    g2.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
    let r2 = g2.evaluate();

    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn integ_receipt_hash_differs_on_change() {
    let mut g1 = GateEvaluator::with_defaults(ep(1));
    g1.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
    let r1 = g1.evaluate();

    let mut g2 = GateEvaluator::with_defaults(ep(1));
    g2.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 900_000, 50);
    let r2 = g2.evaluate();

    assert_ne!(r1.content_hash, r2.content_hash);
}

// ===========================================================================
// Config builder tests
// ===========================================================================

#[test]
fn integ_config_builder_chain() {
    let c = GateConfig::default()
        .with_min_parity(980_000)
        .with_max_overhead(50_000)
        .with_max_security_findings(2)
        .with_min_support_coverage(900_000)
        .with_min_samples(100)
        .with_required_cohort(AddonCohort::Crypto)
        .fail_open();
    assert_eq!(c.min_parity_millionths, 980_000);
    assert_eq!(c.max_throughput_overhead_millionths, 50_000);
    assert_eq!(c.max_security_findings, 2);
    assert_eq!(c.min_support_coverage_millionths, 900_000);
    assert_eq!(c.min_sample_count, 100);
    assert!(c.required_cohorts.contains(&AddonCohort::Crypto));
    assert!(!c.fail_closed);
}

// ===========================================================================
// Summary and counters
// ===========================================================================

#[test]
fn integ_approval_rate_calculations() {
    let mut g = GateEvaluator::with_defaults(ep(1));
    g.evaluate(); // approved
    g.clear();
    g.add_parity(AddonCohort::Crypto, "x", GateAxis::Parity, 100_000, 50);
    g.evaluate(); // denied
    assert_eq!(g.approval_rate_millionths(), 500_000);
}

#[test]
fn integ_summary_fields() {
    let mut g = GateEvaluator::with_defaults(ep(1));
    g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
    g.add_security_finding(FindingSeverity::Low, FindingCategory::InfoLeak, "x", "y");
    g.evaluate();
    let s = g.summary();
    assert_eq!(s.total_evaluations, 1);
    assert_eq!(s.approved_count, 1);
    assert_eq!(s.parity_entries, 1);
    assert_eq!(s.security_findings, 1);
}

// ===========================================================================
// Manifest and constants
// ===========================================================================

#[test]
fn integ_manifest_contains_expected_keys() {
    let m = native_addon_parity_gate_manifest();
    assert_eq!(m.get("schema_version").unwrap(), SCHEMA_VERSION);
    assert_eq!(m.get("component").unwrap(), COMPONENT);
    assert_eq!(m.get("bead_id").unwrap(), BEAD_ID);
    assert_eq!(m.get("policy_id").unwrap(), POLICY_ID);
}

#[test]
fn integ_constants_correct() {
    assert_eq!(MILLIONTHS, 1_000_000);
    assert_eq!(DEFAULT_MIN_PARITY_MILLIONTHS, 950_000);
    assert_eq!(DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS, 100_000);
    assert_eq!(DEFAULT_MAX_SECURITY_FINDINGS, 0);
    assert_eq!(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS, 800_000);
    assert_eq!(DEFAULT_MIN_SAMPLE_COUNT, 30);
}

// ===========================================================================
// Evaluator serde
// ===========================================================================

#[test]
fn integ_evaluator_serde_roundtrip() {
    let mut g = GateEvaluator::with_defaults(ep(1));
    g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
    g.evaluate();
    let json = serde_json::to_string(&g).unwrap();
    let back: GateEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(back.evaluation_count(), 1);
    assert_eq!(back.approved_count(), 1);
}

// ===========================================================================
// Deterministic replay
// ===========================================================================

#[test]
fn integ_deterministic_multi_cohort_evaluation() {
    let run = || {
        let config = GateConfig::default()
            .with_required_cohort(AddonCohort::Crypto)
            .with_required_cohort(AddonCohort::Compression);
        let mut g = GateEvaluator::new(config, ep(1));
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        g.add_parity(AddonCohort::Compression, "zstd", GateAxis::Parity, MILLIONTHS, 50);
        g.add_throughput(AddonCohort::Crypto, "aes", 1_000_000, 950_000);
        g.add_throughput(AddonCohort::Compression, "zstd", 1_000_000, 960_000);
        g.add_support_surface(AddonCohort::Crypto, 95, 100);
        g.add_support_surface(AddonCohort::Compression, 85, 100);
        g.evaluate()
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.verdict, r2.verdict);
}
