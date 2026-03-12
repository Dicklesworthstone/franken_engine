//! Integration tests for `native_addon_parity_gate` (RGC-407C, bd-1lsy.5.9.3).

#![forbid(unsafe_code)]
#![allow(
    clippy::too_many_arguments,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::native_addon_parity_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn ep() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ============================================================================
// Constants
// ============================================================================

#[test]
fn test_schema_version_contains_module_name() {
    assert!(SCHEMA_VERSION.contains("native-addon-parity-gate"));
}

#[test]
fn test_schema_version_v1() {
    assert!(SCHEMA_VERSION.contains("v1"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "native_addon_parity_gate");
}

#[test]
fn test_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.5.9.3");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-407C");
}

#[test]
fn test_millionths_value() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn test_default_parity_threshold() {
    assert_eq!(DEFAULT_MIN_PARITY_MILLIONTHS, 950_000);
}

#[test]
fn test_default_throughput_overhead() {
    assert_eq!(DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS, 100_000);
}

#[test]
fn test_default_security_findings() {
    assert_eq!(DEFAULT_MAX_SECURITY_FINDINGS, 0);
}

#[test]
fn test_default_support_coverage() {
    assert_eq!(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS, 800_000);
}

#[test]
fn test_default_sample_count() {
    assert_eq!(DEFAULT_MIN_SAMPLE_COUNT, 30);
}

// ============================================================================
// AddonCohort
// ============================================================================

#[test]
fn test_addon_cohort_all_count() {
    assert_eq!(AddonCohort::ALL.len(), 8);
}

#[test]
fn test_addon_cohort_display_matches_as_str() {
    for c in AddonCohort::ALL {
        assert_eq!(format!("{c}"), c.as_str());
    }
}

#[test]
fn test_addon_cohort_ordering() {
    assert!(AddonCohort::Crypto < AddonCohort::Networking);
}

#[test]
fn test_addon_cohort_serde_roundtrip() {
    for c in AddonCohort::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: AddonCohort = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ============================================================================
// GateAxis
// ============================================================================

#[test]
fn test_gate_axis_all_count() {
    assert_eq!(GateAxis::ALL.len(), 5);
}

#[test]
fn test_gate_axis_display_matches_as_str() {
    for a in GateAxis::ALL {
        assert_eq!(format!("{a}"), a.as_str());
    }
}

#[test]
fn test_gate_axis_serde_roundtrip() {
    for a in GateAxis::ALL {
        let json = serde_json::to_string(a).unwrap();
        let back: GateAxis = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, back);
    }
}

// ============================================================================
// FindingSeverity
// ============================================================================

#[test]
fn test_finding_severity_all_count() {
    assert_eq!(FindingSeverity::ALL.len(), 4);
}

#[test]
fn test_finding_severity_blocking() {
    assert!(FindingSeverity::Critical.is_blocking());
    assert!(FindingSeverity::High.is_blocking());
    assert!(!FindingSeverity::Medium.is_blocking());
    assert!(!FindingSeverity::Low.is_blocking());
}

#[test]
fn test_finding_severity_display() {
    assert_eq!(format!("{}", FindingSeverity::Critical), "critical");
    assert_eq!(format!("{}", FindingSeverity::Low), "low");
}

// ============================================================================
// FindingCategory
// ============================================================================

#[test]
fn test_finding_category_all_count() {
    assert_eq!(FindingCategory::ALL.len(), 5);
}

#[test]
fn test_finding_category_display() {
    for c in FindingCategory::ALL {
        assert_eq!(format!("{c}"), c.as_str());
    }
}

// ============================================================================
// SecurityFinding
// ============================================================================

#[test]
fn test_security_finding_constructor() {
    let f = SecurityFinding::new(
        FindingSeverity::Critical,
        FindingCategory::BufferOverflow,
        "libcrypto",
        "heap overflow in EVP_Decrypt",
    );
    assert_eq!(f.severity, FindingSeverity::Critical);
    assert_eq!(f.category, FindingCategory::BufferOverflow);
    assert_eq!(f.addon_name, "libcrypto");
    assert!(f.is_blocking());
}

#[test]
fn test_security_finding_non_blocking() {
    let f = SecurityFinding::new(
        FindingSeverity::Low,
        FindingCategory::InfoLeak,
        "libimg",
        "minor info leak",
    );
    assert!(!f.is_blocking());
}

#[test]
fn test_security_finding_content_hash_deterministic() {
    let a = SecurityFinding::new(
        FindingSeverity::High,
        FindingCategory::UseAfterFree,
        "addon1",
        "uaf desc",
    );
    let b = SecurityFinding::new(
        FindingSeverity::High,
        FindingCategory::UseAfterFree,
        "addon1",
        "uaf desc",
    );
    assert_eq!(a.content_hash, b.content_hash);
}

// ============================================================================
// ThroughputEntry
// ============================================================================

#[test]
fn test_throughput_entry_within_budget() {
    let e = ThroughputEntry::new(AddonCohort::Crypto, "aes256", 10_000, 9_500, 100_000);
    assert!(e.within_budget);
    assert_eq!(e.overhead_millionths, 50_000);
}

#[test]
fn test_throughput_entry_over_budget() {
    let e = ThroughputEntry::new(AddonCohort::Compression, "zstd", 10_000, 5_000, 100_000);
    assert!(!e.within_budget);
    assert_eq!(e.overhead_millionths, 500_000);
}

#[test]
fn test_throughput_entry_zero_native() {
    let e = ThroughputEntry::new(AddonCohort::Database, "pg", 0, 0, 100_000);
    assert_eq!(e.overhead_millionths, 0);
    assert!(e.within_budget);
}

#[test]
fn test_throughput_entry_content_hash_deterministic() {
    let a = ThroughputEntry::new(AddonCohort::Crypto, "rsa", 1000, 900, 100_000);
    let b = ThroughputEntry::new(AddonCohort::Crypto, "rsa", 1000, 900, 100_000);
    assert_eq!(a.content_hash, b.content_hash);
}

// ============================================================================
// ParityEntry
// ============================================================================

#[test]
fn test_parity_entry_passes() {
    let e = ParityEntry::new(
        AddonCohort::Crypto,
        "sha256",
        GateAxis::Parity,
        980_000,
        50,
        950_000,
        30,
    );
    assert!(e.passes);
}

#[test]
fn test_parity_entry_fails_low_parity() {
    let e = ParityEntry::new(
        AddonCohort::Crypto,
        "sha256",
        GateAxis::Parity,
        900_000,
        50,
        950_000,
        30,
    );
    assert!(!e.passes);
}

#[test]
fn test_parity_entry_fails_low_samples() {
    let e = ParityEntry::new(
        AddonCohort::Crypto,
        "sha256",
        GateAxis::Parity,
        980_000,
        10,
        950_000,
        30,
    );
    assert!(!e.passes);
}

// ============================================================================
// SupportSurfaceEntry
// ============================================================================

#[test]
fn test_support_surface_entry_coverage() {
    let e = SupportSurfaceEntry::new(AddonCohort::ImageProcessing, 80, 100);
    assert_eq!(e.coverage_millionths, 800_000);
    assert!(e.meets_minimum(800_000));
    assert!(!e.meets_minimum(900_000));
}

#[test]
fn test_support_surface_entry_zero_total() {
    let e = SupportSurfaceEntry::new(AddonCohort::MediaCodec, 0, 0);
    assert_eq!(e.coverage_millionths, 0);
}

// ============================================================================
// GateConfig
// ============================================================================

#[test]
fn test_gate_config_default() {
    let c = GateConfig::default();
    assert_eq!(c.min_parity_millionths, DEFAULT_MIN_PARITY_MILLIONTHS);
    assert_eq!(
        c.max_throughput_overhead_millionths,
        DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS
    );
    assert_eq!(c.max_security_findings, DEFAULT_MAX_SECURITY_FINDINGS);
    assert_eq!(
        c.min_support_coverage_millionths,
        DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS
    );
    assert_eq!(c.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
    assert!(c.fail_closed);
}

#[test]
fn test_gate_config_strict() {
    let c = GateConfig::strict();
    assert_eq!(c.min_parity_millionths, 990_000);
    assert_eq!(c.max_security_findings, 0);
    assert_eq!(c.required_cohorts.len(), AddonCohort::ALL.len());
}

#[test]
fn test_gate_config_permissive() {
    let c = GateConfig::permissive();
    assert_eq!(c.min_parity_millionths, 0);
    assert!(!c.fail_closed);
    assert!(c.required_cohorts.is_empty());
}

#[test]
fn test_gate_config_builders() {
    let c = GateConfig::default()
        .with_min_parity(800_000)
        .with_max_overhead(200_000)
        .with_max_security_findings(2)
        .with_min_support_coverage(600_000)
        .with_min_samples(10)
        .with_required_cohort(AddonCohort::Crypto)
        .fail_open();
    assert_eq!(c.min_parity_millionths, 800_000);
    assert_eq!(c.max_throughput_overhead_millionths, 200_000);
    assert_eq!(c.max_security_findings, 2);
    assert_eq!(c.min_support_coverage_millionths, 600_000);
    assert_eq!(c.min_sample_count, 10);
    assert!(c.required_cohorts.contains(&AddonCohort::Crypto));
    assert!(!c.fail_closed);
}

// ============================================================================
// GateVerdict
// ============================================================================

#[test]
fn test_gate_verdict_approved() {
    assert!(GateVerdict::Approved.is_approved());
    assert!(!GateVerdict::Approved.is_blocking());
}

#[test]
fn test_gate_verdict_non_approved() {
    let verdicts = [
        GateVerdict::ParityViolation,
        GateVerdict::SecurityBlocking,
        GateVerdict::ThroughputExceeded,
        GateVerdict::SupportInsufficient,
        GateVerdict::MultipleViolations,
    ];
    for v in &verdicts {
        assert!(!v.is_approved());
        assert!(v.is_blocking());
    }
}

#[test]
fn test_gate_verdict_display() {
    assert_eq!(format!("{}", GateVerdict::Approved), "approved");
    assert_eq!(
        format!("{}", GateVerdict::SecurityBlocking),
        "security_blocking"
    );
}

#[test]
fn test_gate_verdict_serde_roundtrip() {
    let v = GateVerdict::ThroughputExceeded;
    let json = serde_json::to_string(&v).unwrap();
    let back: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ============================================================================
// GateEvaluator lifecycle
// ============================================================================

#[test]
fn test_evaluator_new_with_defaults() {
    let ev = GateEvaluator::with_defaults(ep());
    assert_eq!(*ev.epoch(), ep());
    assert_eq!(ev.evaluation_count(), 0);
    assert_eq!(ev.approved_count(), 0);
    assert_eq!(ev.denied_count(), 0);
    assert!(ev.last_receipt().is_none());
    assert_eq!(ev.parity_entry_count(), 0);
    assert_eq!(ev.security_finding_count(), 0);
    assert_eq!(ev.throughput_entry_count(), 0);
    assert_eq!(ev.support_surface_entry_count(), 0);
}

#[test]
fn test_evaluator_add_parity_and_approve() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    let receipt = ev.evaluate();
    assert!(receipt.is_approved());
    assert_eq!(ev.approved_count(), 1);
    assert_eq!(receipt.violation_count(), 0);
}

#[test]
fn test_evaluator_parity_violation() {
    let cfg = GateConfig::default().with_min_samples(1);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 500_000, 50);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::ParityViolation);
    assert_eq!(ev.denied_count(), 1);
}

#[test]
fn test_evaluator_security_blocking() {
    let cfg = GateConfig::permissive().with_max_security_findings(0);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_security_finding(
        FindingSeverity::Critical,
        FindingCategory::BufferOverflow,
        "libcrypto",
        "heap overflow",
    );
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::SecurityBlocking);
    assert_eq!(receipt.blocking_finding_count(), 1);
}

#[test]
fn test_evaluator_throughput_exceeded() {
    let cfg = GateConfig::permissive().with_max_overhead(50_000);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_throughput(AddonCohort::Compression, "zstd", 10_000, 5_000);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::ThroughputExceeded);
}

#[test]
fn test_evaluator_support_insufficient() {
    let cfg = GateConfig::permissive().with_min_support_coverage(900_000);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_support_surface(AddonCohort::Database, 50, 100);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::SupportInsufficient);
}

#[test]
fn test_evaluator_multiple_violations() {
    let cfg = GateConfig::default()
        .with_min_samples(1)
        .with_min_support_coverage(900_000);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 100_000, 50);
    ev.add_support_surface(AddonCohort::Database, 10, 100);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::MultipleViolations);
}

#[test]
fn test_evaluator_missing_required_cohort() {
    let cfg = GateConfig::default()
        .with_required_cohort(AddonCohort::Crypto)
        .with_required_cohort(AddonCohort::Database);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    let receipt = ev.evaluate();
    assert!(!receipt.is_approved());
    assert!(receipt.missing_cohorts.contains(&AddonCohort::Database));
}

#[test]
fn test_evaluator_clear_resets() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    ev.add_security_finding(FindingSeverity::Low, FindingCategory::InfoLeak, "x", "y");
    assert_eq!(ev.parity_entry_count(), 1);
    assert_eq!(ev.security_finding_count(), 1);
    ev.clear();
    assert_eq!(ev.parity_entry_count(), 0);
    assert_eq!(ev.security_finding_count(), 0);
    assert_eq!(ev.throughput_entry_count(), 0);
    assert_eq!(ev.support_surface_entry_count(), 0);
}

#[test]
fn test_evaluator_approval_rate() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    ev.evaluate();
    ev.clear();
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    ev.evaluate();
    assert_eq!(ev.approval_rate_millionths(), MILLIONTHS);
}

#[test]
fn test_evaluator_summary() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    ev.add_throughput(AddonCohort::Compression, "zstd", 10_000, 9_500);
    ev.add_support_surface(AddonCohort::Database, 80, 100);
    ev.evaluate();
    let s = ev.summary();
    assert_eq!(s.total_evaluations, 1);
    assert_eq!(s.parity_entries, 1);
    assert_eq!(s.throughput_entries, 1);
    assert_eq!(s.support_surface_entries, 1);
}

// ============================================================================
// GateReceipt
// ============================================================================

#[test]
fn test_receipt_schema_fields() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    let receipt = ev.evaluate();
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.bead_id, BEAD_ID);
    assert_eq!(receipt.policy_id, POLICY_ID);
    assert_eq!(receipt.epoch, ep());
}

#[test]
fn test_receipt_observed_cohorts() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    ev.add_throughput(AddonCohort::Database, "pg", 10_000, 9_000);
    let receipt = ev.evaluate();
    assert!(receipt.observed_cohorts.contains(&AddonCohort::Crypto));
    assert!(receipt.observed_cohorts.contains(&AddonCohort::Database));
}

// ============================================================================
// Content hash determinism
// ============================================================================

#[test]
fn test_content_hash_deterministic() {
    let build = || {
        let cfg = GateConfig::permissive();
        let mut ev = GateEvaluator::new(cfg, ep());
        ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
        ev.evaluate()
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_content_hash_changes_with_evidence() {
    let cfg = GateConfig::permissive();
    let mut ev1 = GateEvaluator::new(cfg.clone(), ep());
    ev1.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    let r1 = ev1.evaluate();

    let mut ev2 = GateEvaluator::new(cfg, ep());
    ev2.add_parity(AddonCohort::Crypto, "rsa", GateAxis::Parity, 980_000, 50);
    let r2 = ev2.evaluate();

    assert_ne!(r1.content_hash, r2.content_hash);
}

// ============================================================================
// E2E scenarios
// ============================================================================

#[test]
fn test_e2e_all_axes_passing() {
    let cfg = GateConfig::default().with_min_samples(5);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    ev.add_throughput(AddonCohort::Crypto, "aes", 10_000, 9_500);
    ev.add_support_surface(AddonCohort::Crypto, 90, 100);
    let receipt = ev.evaluate();
    assert!(receipt.is_approved());
}

#[test]
fn test_e2e_low_severity_findings_allowed() {
    let cfg = GateConfig::default().with_max_security_findings(0);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_security_finding(
        FindingSeverity::Low,
        FindingCategory::InfoLeak,
        "addon1",
        "minor leak",
    );
    ev.add_security_finding(
        FindingSeverity::Medium,
        FindingCategory::TypeConfusion,
        "addon2",
        "type issue",
    );
    let receipt = ev.evaluate();
    // Low and Medium are not blocking
    assert!(receipt.is_approved());
    assert_eq!(receipt.blocking_finding_count(), 0);
}

#[test]
fn test_e2e_manifest() {
    let m = native_addon_parity_gate_manifest();
    assert_eq!(m.get("schema_version").unwrap(), SCHEMA_VERSION);
    assert_eq!(m.get("component").unwrap(), COMPONENT);
    assert_eq!(m.get("bead_id").unwrap(), BEAD_ID);
    assert_eq!(m.get("policy_id").unwrap(), POLICY_ID);
}

#[test]
fn test_e2e_serde_roundtrip_receipt() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    let receipt = ev.evaluate();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GateReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.verdict, back.verdict);
    assert_eq!(receipt.content_hash, back.content_hash);
}

#[test]
fn test_e2e_last_receipt_stored() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    assert!(ev.last_receipt().is_none());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    ev.evaluate();
    assert!(ev.last_receipt().is_some());
    assert!(ev.last_receipt().unwrap().is_approved());
}

#[test]
fn test_e2e_strict_requires_all_cohorts() {
    let cfg = GateConfig::strict();
    let mut ev = GateEvaluator::new(cfg, ep());
    // Only provide Crypto evidence
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 990_000, 100);
    let receipt = ev.evaluate();
    assert!(!receipt.is_approved());
    assert!(!receipt.missing_cohorts.is_empty());
}
