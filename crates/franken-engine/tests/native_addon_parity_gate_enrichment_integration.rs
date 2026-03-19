//! Enrichment integration tests for `native_addon_parity_gate` (RGC-407C).
//!
//! Exercises the GateEvaluator lifecycle, ParityEntry / ThroughputEntry /
//! SupportSurfaceEntry constructors, SecurityFinding::new, GateConfig builders,
//! Violation construction, GateReceipt sealing, verdict logic, and serde
//! fidelity across all public types.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::native_addon_parity_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn ep() -> SecurityEpoch {
    SecurityEpoch::from_raw(55)
}

// ===========================================================================
// Section 1: Constants
// ===========================================================================

#[test]
fn enrich_constants_schema_version() {
    assert!(SCHEMA_VERSION.contains("native-addon-parity-gate"));
    assert!(SCHEMA_VERSION.contains("v1"));
}

#[test]
fn enrich_constants_component() {
    assert_eq!(COMPONENT, "native_addon_parity_gate");
}

#[test]
fn enrich_constants_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.5.9.3");
}

#[test]
fn enrich_constants_policy_id() {
    assert_eq!(POLICY_ID, "RGC-407C");
}

#[test]
fn enrich_constants_millionths() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn enrich_constants_default_thresholds() {
    assert_eq!(DEFAULT_MIN_PARITY_MILLIONTHS, 950_000);
    assert_eq!(DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS, 100_000);
    assert_eq!(DEFAULT_MAX_SECURITY_FINDINGS, 0);
    assert_eq!(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS, 800_000);
    assert_eq!(DEFAULT_MIN_SAMPLE_COUNT, 30);
}

// ===========================================================================
// Section 2: AddonCohort
// ===========================================================================

#[test]
fn enrich_addon_cohort_all_count() {
    assert_eq!(AddonCohort::ALL.len(), 8);
}

#[test]
fn enrich_addon_cohort_display_uniqueness() {
    let set: BTreeSet<String> = AddonCohort::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(set.len(), 8);
}

#[test]
fn enrich_addon_cohort_as_str_matches_display() {
    for c in AddonCohort::ALL {
        assert_eq!(c.as_str(), &c.to_string());
    }
}

#[test]
fn enrich_addon_cohort_serde_roundtrip() {
    for c in AddonCohort::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: AddonCohort = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ===========================================================================
// Section 3: GateAxis
// ===========================================================================

#[test]
fn enrich_gate_axis_all_count() {
    assert_eq!(GateAxis::ALL.len(), 5);
}

#[test]
fn enrich_gate_axis_display_uniqueness() {
    let set: BTreeSet<String> = GateAxis::ALL.iter().map(|a| a.to_string()).collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn enrich_gate_axis_serde_roundtrip() {
    for a in GateAxis::ALL {
        let json = serde_json::to_string(a).unwrap();
        let back: GateAxis = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, back);
    }
}

// ===========================================================================
// Section 4: FindingSeverity
// ===========================================================================

#[test]
fn enrich_finding_severity_all_count() {
    assert_eq!(FindingSeverity::ALL.len(), 4);
}

#[test]
fn enrich_finding_severity_blocking() {
    assert!(FindingSeverity::Critical.is_blocking());
    assert!(FindingSeverity::High.is_blocking());
    assert!(!FindingSeverity::Medium.is_blocking());
    assert!(!FindingSeverity::Low.is_blocking());
}

#[test]
fn enrich_finding_severity_serde_roundtrip() {
    for s in FindingSeverity::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: FindingSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ===========================================================================
// Section 5: FindingCategory
// ===========================================================================

#[test]
fn enrich_finding_category_all_count() {
    assert_eq!(FindingCategory::ALL.len(), 5);
}

#[test]
fn enrich_finding_category_display_uniqueness() {
    let set: BTreeSet<String> = FindingCategory::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn enrich_finding_category_serde_roundtrip() {
    for c in FindingCategory::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: FindingCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ===========================================================================
// Section 6: GateVerdict
// ===========================================================================

#[test]
fn enrich_gate_verdict_approved_is_approved() {
    assert!(GateVerdict::Approved.is_approved());
    assert!(!GateVerdict::Approved.is_blocking());
}

#[test]
fn enrich_gate_verdict_parity_violation_is_blocking() {
    assert!(!GateVerdict::ParityViolation.is_approved());
    assert!(GateVerdict::ParityViolation.is_blocking());
}

#[test]
fn enrich_gate_verdict_all_variants_display_unique() {
    let variants = [
        GateVerdict::Approved,
        GateVerdict::ParityViolation,
        GateVerdict::SecurityBlocking,
        GateVerdict::ThroughputExceeded,
        GateVerdict::SupportInsufficient,
        GateVerdict::MultipleViolations,
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrich_gate_verdict_serde_roundtrip() {
    let variants = [
        GateVerdict::Approved,
        GateVerdict::ParityViolation,
        GateVerdict::SecurityBlocking,
        GateVerdict::ThroughputExceeded,
        GateVerdict::SupportInsufficient,
        GateVerdict::MultipleViolations,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// Section 7: SecurityFinding::new
// ===========================================================================

#[test]
fn enrich_security_finding_new_fields() {
    let f = SecurityFinding::new(
        FindingSeverity::Critical,
        FindingCategory::BufferOverflow,
        "my-addon",
        "stack buffer overflow in parse",
    );
    assert_eq!(f.severity, FindingSeverity::Critical);
    assert_eq!(f.category, FindingCategory::BufferOverflow);
    assert_eq!(f.addon_name, "my-addon");
    assert_eq!(f.description, "stack buffer overflow in parse");
    assert!(f.is_blocking());
}

#[test]
fn enrich_security_finding_new_content_hash_deterministic() {
    let f1 = SecurityFinding::new(
        FindingSeverity::Medium,
        FindingCategory::InfoLeak,
        "addon-x",
        "side channel leak",
    );
    let f2 = SecurityFinding::new(
        FindingSeverity::Medium,
        FindingCategory::InfoLeak,
        "addon-x",
        "side channel leak",
    );
    assert_eq!(f1.content_hash, f2.content_hash);
}

#[test]
fn enrich_security_finding_different_addons_different_hash() {
    let f1 = SecurityFinding::new(
        FindingSeverity::High,
        FindingCategory::UseAfterFree,
        "addon-a",
        "same desc",
    );
    let f2 = SecurityFinding::new(
        FindingSeverity::High,
        FindingCategory::UseAfterFree,
        "addon-b",
        "same desc",
    );
    assert_ne!(f1.content_hash, f2.content_hash);
}

#[test]
fn enrich_security_finding_serde_roundtrip() {
    let f = SecurityFinding::new(
        FindingSeverity::Low,
        FindingCategory::Injection,
        "addon-z",
        "test desc",
    );
    let json = serde_json::to_string(&f).unwrap();
    let back: SecurityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ===========================================================================
// Section 8: ThroughputEntry::new
// ===========================================================================

#[test]
fn enrich_throughput_entry_overhead_computation() {
    let entry = ThroughputEntry::new(
        AddonCohort::Crypto,
        "crypto-addon",
        1_000_000,  // native
        900_000,    // membrane
        100_000,    // max overhead
    );
    // Overhead = (1M - 900K) * 1M / 1M = 100_000
    assert_eq!(entry.overhead_millionths, 100_000);
    assert!(entry.within_budget);
}

#[test]
fn enrich_throughput_entry_exceeds_budget() {
    let entry = ThroughputEntry::new(
        AddonCohort::Compression,
        "zlib-addon",
        1_000_000,
        800_000,
        100_000,
    );
    // Overhead = 200_000 > 100_000 budget
    assert_eq!(entry.overhead_millionths, 200_000);
    assert!(!entry.within_budget);
}

#[test]
fn enrich_throughput_entry_zero_native_no_panic() {
    let entry = ThroughputEntry::new(
        AddonCohort::Database,
        "db-addon",
        0,
        0,
        100_000,
    );
    assert_eq!(entry.overhead_millionths, 0);
    assert!(entry.within_budget);
}

#[test]
fn enrich_throughput_entry_serde_roundtrip() {
    let entry = ThroughputEntry::new(
        AddonCohort::Networking,
        "net-addon",
        500_000,
        480_000,
        100_000,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: ThroughputEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrich_throughput_entry_content_hash_deterministic() {
    let e1 = ThroughputEntry::new(AddonCohort::Crypto, "a", 1000, 900, 200);
    let e2 = ThroughputEntry::new(AddonCohort::Crypto, "a", 1000, 900, 200);
    assert_eq!(e1.content_hash, e2.content_hash);
}

// ===========================================================================
// Section 9: ParityEntry::new
// ===========================================================================

#[test]
fn enrich_parity_entry_passes_when_above_threshold() {
    let entry = ParityEntry::new(
        AddonCohort::Crypto,
        "addon",
        GateAxis::Parity,
        960_000,    // above 950_000
        50,         // above 30
        950_000,
        30,
    );
    assert!(entry.passes);
}

#[test]
fn enrich_parity_entry_fails_below_threshold() {
    let entry = ParityEntry::new(
        AddonCohort::Crypto,
        "addon",
        GateAxis::Parity,
        940_000,    // below 950_000
        50,
        950_000,
        30,
    );
    assert!(!entry.passes);
}

#[test]
fn enrich_parity_entry_fails_low_samples() {
    let entry = ParityEntry::new(
        AddonCohort::Crypto,
        "addon",
        GateAxis::Parity,
        999_000,    // above threshold
        10,         // below 30
        950_000,
        30,
    );
    assert!(!entry.passes);
}

#[test]
fn enrich_parity_entry_serde_roundtrip() {
    let entry = ParityEntry::new(
        AddonCohort::ImageProcessing,
        "img-addon",
        GateAxis::MemorySafety,
        980_000,
        100,
        950_000,
        30,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: ParityEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrich_parity_entry_content_hash_deterministic() {
    let e1 = ParityEntry::new(AddonCohort::Crypto, "a", GateAxis::Parity, 950_000, 30, 950_000, 30);
    let e2 = ParityEntry::new(AddonCohort::Crypto, "a", GateAxis::Parity, 950_000, 30, 950_000, 30);
    assert_eq!(e1.content_hash, e2.content_hash);
}

// ===========================================================================
// Section 10: SupportSurfaceEntry
// ===========================================================================

#[test]
fn enrich_support_surface_coverage_computation() {
    let entry = SupportSurfaceEntry::new(AddonCohort::Crypto, 80, 100);
    assert_eq!(entry.coverage_millionths, 800_000);
    assert!(entry.meets_minimum(800_000));
    assert!(!entry.meets_minimum(900_000));
}

#[test]
fn enrich_support_surface_zero_total() {
    let entry = SupportSurfaceEntry::new(AddonCohort::Database, 0, 0);
    assert_eq!(entry.coverage_millionths, 0);
    assert!(!entry.meets_minimum(1));
}

#[test]
fn enrich_support_surface_serde_roundtrip() {
    let entry = SupportSurfaceEntry::new(AddonCohort::MediaCodec, 45, 50);
    let json = serde_json::to_string(&entry).unwrap();
    let back: SupportSurfaceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// Section 11: GateConfig
// ===========================================================================

#[test]
fn enrich_gate_config_default() {
    let cfg = GateConfig::default();
    assert_eq!(cfg.min_parity_millionths, DEFAULT_MIN_PARITY_MILLIONTHS);
    assert_eq!(cfg.max_throughput_overhead_millionths, DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS);
    assert_eq!(cfg.max_security_findings, DEFAULT_MAX_SECURITY_FINDINGS);
    assert_eq!(cfg.min_support_coverage_millionths, DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS);
    assert_eq!(cfg.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
    assert!(cfg.required_cohorts.is_empty());
    assert!(cfg.fail_closed);
}

#[test]
fn enrich_gate_config_builder_chain() {
    let cfg = GateConfig::default()
        .with_min_parity(900_000)
        .with_max_overhead(50_000)
        .with_max_security_findings(2)
        .with_min_support_coverage(700_000)
        .with_min_samples(100)
        .with_required_cohort(AddonCohort::Crypto)
        .fail_open();

    assert_eq!(cfg.min_parity_millionths, 900_000);
    assert_eq!(cfg.max_throughput_overhead_millionths, 50_000);
    assert_eq!(cfg.max_security_findings, 2);
    assert_eq!(cfg.min_support_coverage_millionths, 700_000);
    assert_eq!(cfg.min_sample_count, 100);
    assert!(cfg.required_cohorts.contains(&AddonCohort::Crypto));
    assert!(!cfg.fail_closed);
}

#[test]
fn enrich_gate_config_strict() {
    let cfg = GateConfig::strict();
    assert_eq!(cfg.min_parity_millionths, 990_000);
    assert_eq!(cfg.max_throughput_overhead_millionths, 50_000);
    assert_eq!(cfg.max_security_findings, 0);
    assert_eq!(cfg.min_support_coverage_millionths, 900_000);
    assert_eq!(cfg.min_sample_count, 50);
    assert_eq!(cfg.required_cohorts.len(), AddonCohort::ALL.len());
    assert!(cfg.fail_closed);
}

#[test]
fn enrich_gate_config_permissive() {
    let cfg = GateConfig::permissive();
    assert_eq!(cfg.min_parity_millionths, 0);
    assert_eq!(cfg.max_security_findings, usize::MAX);
    assert!(!cfg.fail_closed);
}

#[test]
fn enrich_gate_config_serde_roundtrip() {
    let cfg = GateConfig::strict();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// Section 12: Violation
// ===========================================================================

#[test]
fn enrich_violation_new_fields() {
    let v = Violation::new(GateAxis::Security, Some(AddonCohort::Crypto), "test violation");
    assert_eq!(v.axis, GateAxis::Security);
    assert_eq!(v.cohort, Some(AddonCohort::Crypto));
    assert_eq!(v.description, "test violation");
}

#[test]
fn enrich_violation_no_cohort() {
    let v = Violation::new(GateAxis::Parity, None, "global violation");
    assert!(v.cohort.is_none());
}

#[test]
fn enrich_violation_serde_roundtrip() {
    let v = Violation::new(GateAxis::Throughput, Some(AddonCohort::Database), "overhead too high");
    let json = serde_json::to_string(&v).unwrap();
    let back: Violation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ===========================================================================
// Section 13: GateEvaluator
// ===========================================================================

#[test]
fn enrich_evaluator_new_defaults() {
    let eval = GateEvaluator::with_defaults(ep());
    assert_eq!(eval.evaluation_count(), 0);
    assert_eq!(eval.approved_count(), 0);
    assert_eq!(eval.denied_count(), 0);
    assert_eq!(eval.parity_entry_count(), 0);
    assert_eq!(eval.security_finding_count(), 0);
    assert_eq!(eval.throughput_entry_count(), 0);
    assert_eq!(eval.support_surface_entry_count(), 0);
    assert!(eval.last_receipt().is_none());
}

#[test]
fn enrich_evaluator_add_parity_increments_count() {
    let mut eval = GateEvaluator::with_defaults(ep());
    eval.add_parity(AddonCohort::Crypto, "addon-a", GateAxis::Parity, 960_000, 50);
    assert_eq!(eval.parity_entry_count(), 1);
}

#[test]
fn enrich_evaluator_add_security_finding_increments_count() {
    let mut eval = GateEvaluator::with_defaults(ep());
    eval.add_security_finding(
        FindingSeverity::High,
        FindingCategory::BufferOverflow,
        "addon-b",
        "overflow in parse",
    );
    assert_eq!(eval.security_finding_count(), 1);
}

#[test]
fn enrich_evaluator_add_throughput_increments_count() {
    let mut eval = GateEvaluator::with_defaults(ep());
    eval.add_throughput(AddonCohort::Compression, "zlib", 1_000_000, 950_000);
    assert_eq!(eval.throughput_entry_count(), 1);
}

#[test]
fn enrich_evaluator_add_support_surface_increments_count() {
    let mut eval = GateEvaluator::with_defaults(ep());
    eval.add_support_surface(AddonCohort::Database, 80, 100);
    assert_eq!(eval.support_surface_entry_count(), 1);
}

#[test]
fn enrich_evaluator_clear_resets_all() {
    let mut eval = GateEvaluator::with_defaults(ep());
    eval.add_parity(AddonCohort::Crypto, "a", GateAxis::Parity, 960_000, 50);
    eval.add_security_finding(FindingSeverity::Low, FindingCategory::InfoLeak, "a", "d");
    eval.add_throughput(AddonCohort::Crypto, "a", 1000, 900);
    eval.add_support_surface(AddonCohort::Crypto, 80, 100);
    eval.clear();
    assert_eq!(eval.parity_entry_count(), 0);
    assert_eq!(eval.security_finding_count(), 0);
    assert_eq!(eval.throughput_entry_count(), 0);
    assert_eq!(eval.support_surface_entry_count(), 0);
}

#[test]
fn enrich_evaluator_evaluate_empty_is_approved() {
    // Empty evidence with default (fail_closed) config
    let mut eval = GateEvaluator::with_defaults(ep());
    let receipt = eval.evaluate();
    // No violations from empty evidence => approved
    assert_eq!(receipt.verdict, GateVerdict::Approved);
    assert_eq!(eval.evaluation_count(), 1);
    assert_eq!(eval.approved_count(), 1);
}

#[test]
fn enrich_evaluator_evaluate_with_good_evidence() {
    let mut eval = GateEvaluator::new(
        GateConfig::default().with_min_parity(900_000).with_min_samples(10),
        ep(),
    );
    eval.add_parity(AddonCohort::Crypto, "addon", GateAxis::Parity, 960_000, 50);
    let receipt = eval.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::Approved);
    assert!(receipt.violations.is_empty());
}

#[test]
fn enrich_evaluator_evaluate_parity_failure() {
    let mut eval = GateEvaluator::new(
        GateConfig::default().with_min_parity(990_000).with_min_samples(10),
        ep(),
    );
    eval.add_parity(AddonCohort::Crypto, "addon", GateAxis::Parity, 500_000, 50);
    let receipt = eval.evaluate();
    assert!(receipt.verdict.is_blocking());
    assert!(!receipt.violations.is_empty());
}

#[test]
fn enrich_evaluator_config_accessor() {
    let cfg = GateConfig::strict();
    let eval = GateEvaluator::new(cfg.clone(), ep());
    assert_eq!(*eval.config(), cfg);
}

#[test]
fn enrich_evaluator_epoch_accessor() {
    let eval = GateEvaluator::with_defaults(ep());
    assert_eq!(*eval.epoch(), ep());
}

#[test]
fn enrich_evaluator_last_receipt_after_evaluate() {
    let mut eval = GateEvaluator::with_defaults(ep());
    assert!(eval.last_receipt().is_none());
    let receipt = eval.evaluate();
    let stored = eval.last_receipt().unwrap();
    assert_eq!(*stored, receipt);
}

// ===========================================================================
// Section 14: GateReceipt
// ===========================================================================

#[test]
fn enrich_gate_receipt_seal_deterministic() {
    let mut eval = GateEvaluator::with_defaults(ep());
    eval.add_parity(AddonCohort::Crypto, "a", GateAxis::Parity, 960_000, 50);
    let mut r1 = eval.evaluate();
    let hash1 = r1.content_hash.clone();
    r1.seal();
    assert_eq!(r1.content_hash, hash1); // Sealing again produces same hash.
}

#[test]
fn enrich_gate_receipt_serde_roundtrip() {
    let mut eval = GateEvaluator::with_defaults(ep());
    eval.add_parity(AddonCohort::Crypto, "a", GateAxis::Parity, 960_000, 50);
    let receipt = eval.evaluate();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GateReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrich_gate_receipt_violation_count() {
    let mut eval = GateEvaluator::new(
        GateConfig::default().with_min_parity(990_000).with_min_samples(10),
        ep(),
    );
    eval.add_parity(AddonCohort::Crypto, "a", GateAxis::Parity, 500_000, 50);
    eval.add_parity(AddonCohort::Database, "b", GateAxis::Parity, 400_000, 50);
    let receipt = eval.evaluate();
    assert_eq!(receipt.violation_count(), 2);
}

#[test]
fn enrich_gate_receipt_blocking_finding_count() {
    let mut eval = GateEvaluator::with_defaults(ep());
    eval.add_security_finding(FindingSeverity::Critical, FindingCategory::BufferOverflow, "a", "d1");
    eval.add_security_finding(FindingSeverity::Low, FindingCategory::InfoLeak, "a", "d2");
    eval.add_security_finding(FindingSeverity::High, FindingCategory::UseAfterFree, "a", "d3");
    let receipt = eval.evaluate();
    assert_eq!(receipt.blocking_finding_count(), 2);
}
