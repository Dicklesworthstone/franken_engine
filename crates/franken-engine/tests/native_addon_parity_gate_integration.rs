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

// ============================================================================
// Enrichment tests — AddonCohort exhaustive
// ============================================================================

#[test]
fn enrichment_addon_cohort_crypto_as_str() {
    assert_eq!(AddonCohort::Crypto.as_str(), "crypto");
}

#[test]
fn enrichment_addon_cohort_image_processing_as_str() {
    assert_eq!(AddonCohort::ImageProcessing.as_str(), "image_processing");
}

#[test]
fn enrichment_addon_cohort_compression_as_str() {
    assert_eq!(AddonCohort::Compression.as_str(), "compression");
}

#[test]
fn enrichment_addon_cohort_database_as_str() {
    assert_eq!(AddonCohort::Database.as_str(), "database");
}

#[test]
fn enrichment_addon_cohort_machine_learning_as_str() {
    assert_eq!(AddonCohort::MachineLearning.as_str(), "machine_learning");
}

#[test]
fn enrichment_addon_cohort_system_integration_as_str() {
    assert_eq!(AddonCohort::SystemIntegration.as_str(), "system_integration");
}

#[test]
fn enrichment_addon_cohort_media_codec_as_str() {
    assert_eq!(AddonCohort::MediaCodec.as_str(), "media_codec");
}

#[test]
fn enrichment_addon_cohort_networking_as_str() {
    assert_eq!(AddonCohort::Networking.as_str(), "networking");
}

#[test]
fn enrichment_addon_cohort_clone() {
    let c = AddonCohort::Database;
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn enrichment_addon_cohort_debug() {
    let dbg = format!("{:?}", AddonCohort::MachineLearning);
    assert!(dbg.contains("MachineLearning"));
}

#[test]
fn enrichment_addon_cohort_ord_all_sorted() {
    let mut sorted = AddonCohort::ALL.to_vec();
    sorted.sort();
    assert_eq!(sorted, AddonCohort::ALL);
}

#[test]
fn enrichment_addon_cohort_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for c in AddonCohort::ALL {
        assert!(set.insert(*c));
    }
    for c in AddonCohort::ALL {
        assert!(!set.insert(*c));
    }
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_addon_cohort_serde_json_field_names() {
    let json = serde_json::to_string(&AddonCohort::ImageProcessing).unwrap();
    assert_eq!(json, "\"image_processing\"");
    let json2 = serde_json::to_string(&AddonCohort::MachineLearning).unwrap();
    assert_eq!(json2, "\"machine_learning\"");
    let json3 = serde_json::to_string(&AddonCohort::SystemIntegration).unwrap();
    assert_eq!(json3, "\"system_integration\"");
    let json4 = serde_json::to_string(&AddonCohort::MediaCodec).unwrap();
    assert_eq!(json4, "\"media_codec\"");
}

#[test]
fn enrichment_addon_cohort_serde_all_variants_roundtrip() {
    for c in AddonCohort::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: AddonCohort = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
        // Also ensure the JSON value matches as_str
        assert_eq!(json, format!("\"{}\"", c.as_str()));
    }
}

#[test]
fn enrichment_addon_cohort_invalid_json_rejected() {
    let result: Result<AddonCohort, _> = serde_json::from_str("\"nonexistent\"");
    assert!(result.is_err());
}

// ============================================================================
// Enrichment tests — GateAxis exhaustive
// ============================================================================

#[test]
fn enrichment_gate_axis_parity_as_str() {
    assert_eq!(GateAxis::Parity.as_str(), "parity");
}

#[test]
fn enrichment_gate_axis_security_as_str() {
    assert_eq!(GateAxis::Security.as_str(), "security");
}

#[test]
fn enrichment_gate_axis_throughput_as_str() {
    assert_eq!(GateAxis::Throughput.as_str(), "throughput");
}

#[test]
fn enrichment_gate_axis_support_surface_as_str() {
    assert_eq!(GateAxis::SupportSurface.as_str(), "support_surface");
}

#[test]
fn enrichment_gate_axis_memory_safety_as_str() {
    assert_eq!(GateAxis::MemorySafety.as_str(), "memory_safety");
}

#[test]
fn enrichment_gate_axis_debug() {
    let dbg = format!("{:?}", GateAxis::MemorySafety);
    assert!(dbg.contains("MemorySafety"));
}

#[test]
fn enrichment_gate_axis_clone() {
    let a = GateAxis::SupportSurface;
    let a2 = a.clone();
    assert_eq!(a, a2);
}

#[test]
fn enrichment_gate_axis_ord() {
    let mut sorted = GateAxis::ALL.to_vec();
    sorted.sort();
    assert_eq!(sorted, GateAxis::ALL);
}

#[test]
fn enrichment_gate_axis_serde_field_names() {
    let json = serde_json::to_string(&GateAxis::SupportSurface).unwrap();
    assert_eq!(json, "\"support_surface\"");
    let json2 = serde_json::to_string(&GateAxis::MemorySafety).unwrap();
    assert_eq!(json2, "\"memory_safety\"");
}

#[test]
fn enrichment_gate_axis_invalid_json_rejected() {
    let result: Result<GateAxis, _> = serde_json::from_str("\"not_an_axis\"");
    assert!(result.is_err());
}

// ============================================================================
// Enrichment tests — FindingSeverity exhaustive
// ============================================================================

#[test]
fn enrichment_finding_severity_as_str_all() {
    assert_eq!(FindingSeverity::Critical.as_str(), "critical");
    assert_eq!(FindingSeverity::High.as_str(), "high");
    assert_eq!(FindingSeverity::Medium.as_str(), "medium");
    assert_eq!(FindingSeverity::Low.as_str(), "low");
}

#[test]
fn enrichment_finding_severity_clone() {
    let s = FindingSeverity::Medium;
    let s2 = s.clone();
    assert_eq!(s, s2);
}

#[test]
fn enrichment_finding_severity_debug() {
    let dbg = format!("{:?}", FindingSeverity::High);
    assert!(dbg.contains("High"));
}

#[test]
fn enrichment_finding_severity_serde_all_roundtrip() {
    for s in FindingSeverity::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: FindingSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
        assert_eq!(json, format!("\"{}\"", s.as_str()));
    }
}

#[test]
fn enrichment_finding_severity_ord() {
    // Critical < High < Medium < Low by derive order
    assert!(FindingSeverity::Critical < FindingSeverity::High);
    assert!(FindingSeverity::High < FindingSeverity::Medium);
    assert!(FindingSeverity::Medium < FindingSeverity::Low);
}

#[test]
fn enrichment_finding_severity_display_matches_as_str() {
    for s in FindingSeverity::ALL {
        assert_eq!(format!("{s}"), s.as_str());
    }
}

// ============================================================================
// Enrichment tests — FindingCategory exhaustive
// ============================================================================

#[test]
fn enrichment_finding_category_as_str_all() {
    assert_eq!(FindingCategory::BufferOverflow.as_str(), "buffer_overflow");
    assert_eq!(FindingCategory::UseAfterFree.as_str(), "use_after_free");
    assert_eq!(FindingCategory::TypeConfusion.as_str(), "type_confusion");
    assert_eq!(FindingCategory::Injection.as_str(), "injection");
    assert_eq!(FindingCategory::InfoLeak.as_str(), "info_leak");
}

#[test]
fn enrichment_finding_category_clone() {
    let c = FindingCategory::Injection;
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn enrichment_finding_category_debug() {
    let dbg = format!("{:?}", FindingCategory::TypeConfusion);
    assert!(dbg.contains("TypeConfusion"));
}

#[test]
fn enrichment_finding_category_serde_all_roundtrip() {
    for c in FindingCategory::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: FindingCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

#[test]
fn enrichment_finding_category_ord() {
    assert!(FindingCategory::BufferOverflow < FindingCategory::InfoLeak);
}

// ============================================================================
// Enrichment tests — SecurityFinding
// ============================================================================

#[test]
fn enrichment_security_finding_serde_roundtrip() {
    let f = SecurityFinding::new(
        FindingSeverity::Medium,
        FindingCategory::TypeConfusion,
        "addon-tc",
        "type confusion in handler",
    );
    let json = serde_json::to_string(&f).unwrap();
    let back: SecurityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn enrichment_security_finding_clone() {
    let f = SecurityFinding::new(
        FindingSeverity::Critical,
        FindingCategory::Injection,
        "addon-inj",
        "sql injection",
    );
    let f2 = f.clone();
    assert_eq!(f, f2);
    assert_eq!(f.content_hash, f2.content_hash);
}

#[test]
fn enrichment_security_finding_debug_format() {
    let f = SecurityFinding::new(
        FindingSeverity::Low,
        FindingCategory::InfoLeak,
        "addon-dbg",
        "test",
    );
    let dbg = format!("{:?}", f);
    assert!(dbg.contains("addon-dbg"));
    assert!(dbg.contains("Low"));
    assert!(dbg.contains("InfoLeak"));
}

#[test]
fn enrichment_security_finding_empty_strings() {
    let f = SecurityFinding::new(
        FindingSeverity::Low,
        FindingCategory::InfoLeak,
        "",
        "",
    );
    assert_eq!(f.addon_name, "");
    assert_eq!(f.description, "");
    assert!(!f.is_blocking());
}

#[test]
fn enrichment_security_finding_hash_differs_on_severity_change() {
    let a = SecurityFinding::new(
        FindingSeverity::Critical,
        FindingCategory::BufferOverflow,
        "addon",
        "desc",
    );
    let b = SecurityFinding::new(
        FindingSeverity::Low,
        FindingCategory::BufferOverflow,
        "addon",
        "desc",
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_security_finding_hash_differs_on_category_change() {
    let a = SecurityFinding::new(
        FindingSeverity::High,
        FindingCategory::BufferOverflow,
        "addon",
        "desc",
    );
    let b = SecurityFinding::new(
        FindingSeverity::High,
        FindingCategory::UseAfterFree,
        "addon",
        "desc",
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_security_finding_hash_differs_on_addon_name_change() {
    let a = SecurityFinding::new(
        FindingSeverity::High,
        FindingCategory::Injection,
        "addon-a",
        "same desc",
    );
    let b = SecurityFinding::new(
        FindingSeverity::High,
        FindingCategory::Injection,
        "addon-b",
        "same desc",
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_security_finding_high_is_blocking() {
    let f = SecurityFinding::new(
        FindingSeverity::High,
        FindingCategory::UseAfterFree,
        "addon",
        "desc",
    );
    assert!(f.is_blocking());
}

#[test]
fn enrichment_security_finding_medium_not_blocking() {
    let f = SecurityFinding::new(
        FindingSeverity::Medium,
        FindingCategory::TypeConfusion,
        "addon",
        "desc",
    );
    assert!(!f.is_blocking());
}

// ============================================================================
// Enrichment tests — ThroughputEntry
// ============================================================================

#[test]
fn enrichment_throughput_entry_serde_roundtrip() {
    let e = ThroughputEntry::new(AddonCohort::Networking, "quic", 100_000, 95_000, 100_000);
    let json = serde_json::to_string(&e).unwrap();
    let back: ThroughputEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_throughput_entry_clone() {
    let e = ThroughputEntry::new(AddonCohort::Crypto, "rsa", 50_000, 48_000, 100_000);
    let e2 = e.clone();
    assert_eq!(e, e2);
}

#[test]
fn enrichment_throughput_entry_debug() {
    let e = ThroughputEntry::new(AddonCohort::Compression, "brotli", 10_000, 9_000, 100_000);
    let dbg = format!("{:?}", e);
    assert!(dbg.contains("brotli"));
    assert!(dbg.contains("Compression"));
}

#[test]
fn enrichment_throughput_entry_membrane_faster_than_native() {
    // If membrane is faster, overhead should be 0 (saturating_sub)
    let e = ThroughputEntry::new(AddonCohort::Crypto, "aes", 10_000, 15_000, 100_000);
    assert_eq!(e.overhead_millionths, 0);
    assert!(e.within_budget);
}

#[test]
fn enrichment_throughput_entry_exact_budget_boundary() {
    // 10% overhead exactly at 10% budget
    let e = ThroughputEntry::new(AddonCohort::Database, "pg", 100_000, 90_000, 100_000);
    assert_eq!(e.overhead_millionths, 100_000);
    assert!(e.within_budget); // <= budget, so within
}

#[test]
fn enrichment_throughput_entry_just_over_budget() {
    let e = ThroughputEntry::new(AddonCohort::Database, "pg", 100_000, 89_999, 100_000);
    assert!(e.overhead_millionths > 100_000);
    assert!(!e.within_budget);
}

#[test]
fn enrichment_throughput_entry_zero_membrane() {
    let e = ThroughputEntry::new(AddonCohort::MediaCodec, "opus", 10_000, 0, 100_000);
    assert_eq!(e.overhead_millionths, MILLIONTHS); // 100% overhead
    assert!(!e.within_budget);
}

#[test]
fn enrichment_throughput_entry_both_zero() {
    let e = ThroughputEntry::new(AddonCohort::SystemIntegration, "ipc", 0, 0, 100_000);
    assert_eq!(e.overhead_millionths, 0);
    assert!(e.within_budget);
}

#[test]
fn enrichment_throughput_entry_hash_differs_on_cohort() {
    let a = ThroughputEntry::new(AddonCohort::Crypto, "aes", 10_000, 9_000, 100_000);
    let b = ThroughputEntry::new(AddonCohort::Database, "aes", 10_000, 9_000, 100_000);
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_throughput_entry_hash_differs_on_name() {
    let a = ThroughputEntry::new(AddonCohort::Crypto, "aes", 10_000, 9_000, 100_000);
    let b = ThroughputEntry::new(AddonCohort::Crypto, "rsa", 10_000, 9_000, 100_000);
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn enrichment_throughput_entry_budget_boundary_zero_overhead() {
    let e = ThroughputEntry::new(AddonCohort::Crypto, "aes", 10_000, 10_000, 0);
    assert_eq!(e.overhead_millionths, 0);
    assert!(e.within_budget); // 0 <= 0
}

// ============================================================================
// Enrichment tests — ParityEntry
// ============================================================================

#[test]
fn enrichment_parity_entry_serde_roundtrip() {
    let e = ParityEntry::new(
        AddonCohort::ImageProcessing,
        "resize",
        GateAxis::Parity,
        960_000,
        40,
        950_000,
        30,
    );
    let json = serde_json::to_string(&e).unwrap();
    let back: ParityEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_parity_entry_clone() {
    let e = ParityEntry::new(
        AddonCohort::Crypto,
        "sha512",
        GateAxis::Parity,
        990_000,
        100,
        950_000,
        30,
    );
    let e2 = e.clone();
    assert_eq!(e, e2);
}

#[test]
fn enrichment_parity_entry_debug() {
    let e = ParityEntry::new(
        AddonCohort::Networking,
        "tls",
        GateAxis::Security,
        980_000,
        50,
        950_000,
        30,
    );
    let dbg = format!("{:?}", e);
    assert!(dbg.contains("tls"));
    assert!(dbg.contains("Networking"));
}

#[test]
fn enrichment_parity_entry_exact_threshold() {
    let e = ParityEntry::new(
        AddonCohort::Crypto,
        "aes",
        GateAxis::Parity,
        950_000, // exactly at threshold
        30,      // exactly at min
        950_000,
        30,
    );
    assert!(e.passes);
}

#[test]
fn enrichment_parity_entry_just_below_parity_threshold() {
    let e = ParityEntry::new(
        AddonCohort::Crypto,
        "aes",
        GateAxis::Parity,
        949_999,
        50,
        950_000,
        30,
    );
    assert!(!e.passes);
}

#[test]
fn enrichment_parity_entry_just_below_sample_threshold() {
    let e = ParityEntry::new(
        AddonCohort::Crypto,
        "aes",
        GateAxis::Parity,
        980_000,
        29,
        950_000,
        30,
    );
    assert!(!e.passes);
}

#[test]
fn enrichment_parity_entry_zero_parity_zero_samples() {
    let e = ParityEntry::new(
        AddonCohort::Crypto,
        "aes",
        GateAxis::Parity,
        0,
        0,
        950_000,
        30,
    );
    assert!(!e.passes);
}

#[test]
fn enrichment_parity_entry_perfect_parity() {
    let e = ParityEntry::new(
        AddonCohort::Compression,
        "zstd",
        GateAxis::Parity,
        MILLIONTHS,
        1000,
        950_000,
        30,
    );
    assert!(e.passes);
    assert_eq!(e.parity_millionths, MILLIONTHS);
}

#[test]
fn enrichment_parity_entry_passes_only_when_both_met() {
    // High parity but low samples
    let e1 = ParityEntry::new(
        AddonCohort::Crypto,
        "x",
        GateAxis::Parity,
        990_000,
        5,
        950_000,
        30,
    );
    assert!(!e1.passes);
    // Low parity but high samples
    let e2 = ParityEntry::new(
        AddonCohort::Crypto,
        "x",
        GateAxis::Parity,
        800_000,
        100,
        950_000,
        30,
    );
    assert!(!e2.passes);
    // Both met
    let e3 = ParityEntry::new(
        AddonCohort::Crypto,
        "x",
        GateAxis::Parity,
        960_000,
        50,
        950_000,
        30,
    );
    assert!(e3.passes);
}

#[test]
fn enrichment_parity_entry_hash_differs_on_axis() {
    let a = ParityEntry::new(
        AddonCohort::Crypto,
        "aes",
        GateAxis::Parity,
        990_000,
        50,
        950_000,
        30,
    );
    let b = ParityEntry::new(
        AddonCohort::Crypto,
        "aes",
        GateAxis::Throughput,
        990_000,
        50,
        950_000,
        30,
    );
    assert_ne!(a.content_hash, b.content_hash);
}

// ============================================================================
// Enrichment tests — SupportSurfaceEntry
// ============================================================================

#[test]
fn enrichment_support_surface_entry_serde_roundtrip() {
    let e = SupportSurfaceEntry::new(AddonCohort::Database, 75, 100);
    let json = serde_json::to_string(&e).unwrap();
    let back: SupportSurfaceEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_support_surface_entry_clone() {
    let e = SupportSurfaceEntry::new(AddonCohort::Crypto, 90, 100);
    let e2 = e.clone();
    assert_eq!(e, e2);
}

#[test]
fn enrichment_support_surface_entry_debug() {
    let e = SupportSurfaceEntry::new(AddonCohort::MediaCodec, 60, 80);
    let dbg = format!("{:?}", e);
    assert!(dbg.contains("MediaCodec"));
}

#[test]
fn enrichment_support_surface_entry_full_coverage() {
    let e = SupportSurfaceEntry::new(AddonCohort::Networking, 200, 200);
    assert_eq!(e.coverage_millionths, MILLIONTHS);
    assert!(e.meets_minimum(MILLIONTHS));
}

#[test]
fn enrichment_support_surface_entry_one_api() {
    let e = SupportSurfaceEntry::new(AddonCohort::Crypto, 1, 1);
    assert_eq!(e.coverage_millionths, MILLIONTHS);
}

#[test]
fn enrichment_support_surface_entry_supported_exceeds_total() {
    // Logically shouldn't happen but test the arithmetic
    let e = SupportSurfaceEntry::new(AddonCohort::Crypto, 200, 100);
    // 200 * 1_000_000 / 100 = 2_000_000
    assert_eq!(e.coverage_millionths, 2_000_000);
    assert!(e.meets_minimum(MILLIONTHS));
}

#[test]
fn enrichment_support_surface_entry_meets_minimum_boundary() {
    let e = SupportSurfaceEntry::new(AddonCohort::Crypto, 80, 100);
    assert!(e.meets_minimum(800_000));  // exactly at minimum
    assert!(!e.meets_minimum(800_001)); // just above
}

#[test]
fn enrichment_support_surface_entry_zero_supported_nonzero_total() {
    let e = SupportSurfaceEntry::new(AddonCohort::MachineLearning, 0, 50);
    assert_eq!(e.coverage_millionths, 0);
    assert!(!e.meets_minimum(1));
    assert!(e.meets_minimum(0));
}

// ============================================================================
// Enrichment tests — GateConfig
// ============================================================================

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let c = GateConfig::default()
        .with_min_parity(800_000)
        .with_required_cohort(AddonCohort::Crypto)
        .with_required_cohort(AddonCohort::Database);
    let json = serde_json::to_string(&c).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_gate_config_clone() {
    let c = GateConfig::strict();
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn enrichment_gate_config_debug() {
    let dbg = format!("{:?}", GateConfig::default());
    assert!(dbg.contains("min_parity_millionths"));
    assert!(dbg.contains("fail_closed"));
}

#[test]
fn enrichment_gate_config_strict_has_all_cohorts() {
    let c = GateConfig::strict();
    for cohort in AddonCohort::ALL {
        assert!(c.required_cohorts.contains(cohort));
    }
}

#[test]
fn enrichment_gate_config_strict_values() {
    let c = GateConfig::strict();
    assert_eq!(c.min_parity_millionths, 990_000);
    assert_eq!(c.max_throughput_overhead_millionths, 50_000);
    assert_eq!(c.max_security_findings, 0);
    assert_eq!(c.min_support_coverage_millionths, 900_000);
    assert_eq!(c.min_sample_count, 50);
    assert!(c.fail_closed);
}

#[test]
fn enrichment_gate_config_permissive_values() {
    let c = GateConfig::permissive();
    assert_eq!(c.min_parity_millionths, 0);
    assert_eq!(c.max_throughput_overhead_millionths, MILLIONTHS);
    assert_eq!(c.max_security_findings, usize::MAX);
    assert_eq!(c.min_support_coverage_millionths, 0);
    assert_eq!(c.min_sample_count, 0);
    assert!(c.required_cohorts.is_empty());
    assert!(!c.fail_closed);
}

#[test]
fn enrichment_gate_config_builder_chaining_idempotent() {
    let c = GateConfig::default()
        .with_min_parity(123_456)
        .with_min_parity(789_000);
    // Last call wins
    assert_eq!(c.min_parity_millionths, 789_000);
}

#[test]
fn enrichment_gate_config_multiple_required_cohorts() {
    let c = GateConfig::default()
        .with_required_cohort(AddonCohort::Crypto)
        .with_required_cohort(AddonCohort::Crypto) // duplicate insert
        .with_required_cohort(AddonCohort::Database);
    assert_eq!(c.required_cohorts.len(), 2);
}

#[test]
fn enrichment_gate_config_fail_open_then_default_is_open() {
    let c = GateConfig::default().fail_open();
    assert!(!c.fail_closed);
}

// ============================================================================
// Enrichment tests — GateVerdict exhaustive
// ============================================================================

#[test]
fn enrichment_gate_verdict_as_str_all() {
    assert_eq!(GateVerdict::Approved.as_str(), "approved");
    assert_eq!(GateVerdict::ParityViolation.as_str(), "parity_violation");
    assert_eq!(GateVerdict::SecurityBlocking.as_str(), "security_blocking");
    assert_eq!(GateVerdict::ThroughputExceeded.as_str(), "throughput_exceeded");
    assert_eq!(GateVerdict::SupportInsufficient.as_str(), "support_insufficient");
    assert_eq!(GateVerdict::MultipleViolations.as_str(), "multiple_violations");
}

#[test]
fn enrichment_gate_verdict_clone() {
    let v = GateVerdict::MultipleViolations;
    let v2 = v.clone();
    assert_eq!(v, v2);
}

#[test]
fn enrichment_gate_verdict_debug() {
    let dbg = format!("{:?}", GateVerdict::SupportInsufficient);
    assert!(dbg.contains("SupportInsufficient"));
}

#[test]
fn enrichment_gate_verdict_serde_all_roundtrip() {
    let all = [
        GateVerdict::Approved,
        GateVerdict::ParityViolation,
        GateVerdict::SecurityBlocking,
        GateVerdict::ThroughputExceeded,
        GateVerdict::SupportInsufficient,
        GateVerdict::MultipleViolations,
    ];
    for v in &all {
        let json = serde_json::to_string(v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
        assert_eq!(json, format!("\"{}\"", v.as_str()));
    }
}

#[test]
fn enrichment_gate_verdict_display_matches_as_str() {
    let all = [
        GateVerdict::Approved,
        GateVerdict::ParityViolation,
        GateVerdict::SecurityBlocking,
        GateVerdict::ThroughputExceeded,
        GateVerdict::SupportInsufficient,
        GateVerdict::MultipleViolations,
    ];
    for v in &all {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

#[test]
fn enrichment_gate_verdict_is_approved_iff_approved() {
    let all = [
        GateVerdict::Approved,
        GateVerdict::ParityViolation,
        GateVerdict::SecurityBlocking,
        GateVerdict::ThroughputExceeded,
        GateVerdict::SupportInsufficient,
        GateVerdict::MultipleViolations,
    ];
    for v in &all {
        if *v == GateVerdict::Approved {
            assert!(v.is_approved());
            assert!(!v.is_blocking());
        } else {
            assert!(!v.is_approved());
            assert!(v.is_blocking());
        }
    }
}

// ============================================================================
// Enrichment tests — Violation
// ============================================================================

#[test]
fn enrichment_violation_serde_roundtrip() {
    let v = Violation::new(GateAxis::Parity, Some(AddonCohort::Crypto), "below threshold");
    let json = serde_json::to_string(&v).unwrap();
    let back: Violation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_violation_clone() {
    let v = Violation::new(GateAxis::Throughput, None, "too slow");
    let v2 = v.clone();
    assert_eq!(v, v2);
}

#[test]
fn enrichment_violation_debug() {
    let v = Violation::new(GateAxis::Security, Some(AddonCohort::Database), "vuln");
    let dbg = format!("{:?}", v);
    assert!(dbg.contains("Security"));
    assert!(dbg.contains("Database"));
    assert!(dbg.contains("vuln"));
}

#[test]
fn enrichment_violation_none_cohort() {
    let v = Violation::new(GateAxis::Security, None, "general vuln");
    assert!(v.cohort.is_none());
    assert_eq!(v.axis, GateAxis::Security);
}

#[test]
fn enrichment_violation_empty_description() {
    let v = Violation::new(GateAxis::MemorySafety, None, "");
    assert_eq!(v.description, "");
}

// ============================================================================
// Enrichment tests — GateReceipt
// ============================================================================

#[test]
fn enrichment_receipt_serde_roundtrip_with_violations() {
    let cfg = GateConfig::default().with_min_samples(1);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 500_000, 50);
    ev.add_security_finding(
        FindingSeverity::Critical,
        FindingCategory::BufferOverflow,
        "vuln-addon",
        "heap overflow",
    );
    let receipt = ev.evaluate();
    assert!(!receipt.is_approved());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GateReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.verdict, back.verdict);
    assert_eq!(receipt.violations.len(), back.violations.len());
    assert_eq!(receipt.content_hash, back.content_hash);
}

#[test]
fn enrichment_receipt_clone() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    let receipt = ev.evaluate();
    let r2 = receipt.clone();
    assert_eq!(receipt, r2);
}

#[test]
fn enrichment_receipt_debug() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    let receipt = ev.evaluate();
    let dbg = format!("{:?}", receipt);
    assert!(dbg.contains("schema_version"));
    assert!(dbg.contains("Approved"));
}

#[test]
fn enrichment_receipt_blocking_finding_count_zero_when_no_findings() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    let receipt = ev.evaluate();
    assert_eq!(receipt.blocking_finding_count(), 0);
}

#[test]
fn enrichment_receipt_blocking_finding_count_filters_non_blocking() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_security_finding(FindingSeverity::Low, FindingCategory::InfoLeak, "a", "x");
    ev.add_security_finding(FindingSeverity::Medium, FindingCategory::Injection, "b", "y");
    ev.add_security_finding(FindingSeverity::Critical, FindingCategory::BufferOverflow, "c", "z");
    ev.add_security_finding(FindingSeverity::High, FindingCategory::UseAfterFree, "d", "w");
    let receipt = ev.evaluate();
    assert_eq!(receipt.blocking_finding_count(), 2); // Critical + High
}

#[test]
fn enrichment_receipt_violation_count_matches_violations_len() {
    let cfg = GateConfig::default().with_min_samples(1);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "a", GateAxis::Parity, 100_000, 50);
    ev.add_parity(AddonCohort::Database, "b", GateAxis::Parity, 200_000, 50);
    let receipt = ev.evaluate();
    assert_eq!(receipt.violation_count(), receipt.violations.len());
    assert!(receipt.violation_count() >= 2);
}

#[test]
fn enrichment_receipt_seal_produces_consistent_hash() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg.clone(), ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    let r1 = ev.evaluate();
    let mut r1_clone = r1.clone();
    r1_clone.seal();
    assert_eq!(r1.content_hash, r1_clone.content_hash);
}

#[test]
fn enrichment_receipt_seal_changes_hash_when_verdict_modified() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    let r = ev.evaluate();
    let mut modified = r.clone();
    modified.verdict = GateVerdict::SecurityBlocking;
    modified.seal();
    assert_ne!(r.content_hash, modified.content_hash);
}

#[test]
fn enrichment_receipt_observed_cohorts_from_all_evidence_types() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    ev.add_throughput(AddonCohort::Database, "pg", 10_000, 9_000);
    ev.add_support_surface(AddonCohort::MediaCodec, 80, 100);
    let receipt = ev.evaluate();
    assert!(receipt.observed_cohorts.contains(&AddonCohort::Crypto));
    assert!(receipt.observed_cohorts.contains(&AddonCohort::Database));
    assert!(receipt.observed_cohorts.contains(&AddonCohort::MediaCodec));
    assert_eq!(receipt.observed_cohorts.len(), 3);
}

#[test]
fn enrichment_receipt_missing_cohorts_empty_when_none_required() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    let receipt = ev.evaluate();
    assert!(receipt.missing_cohorts.is_empty());
}

// ============================================================================
// Enrichment tests — GateEvaluator
// ============================================================================

#[test]
fn enrichment_evaluator_config_accessor() {
    let cfg = GateConfig::default().with_min_parity(777_000);
    let ev = GateEvaluator::new(cfg, ep());
    assert_eq!(ev.config().min_parity_millionths, 777_000);
}

#[test]
fn enrichment_evaluator_epoch_accessor() {
    let ev = GateEvaluator::with_defaults(SecurityEpoch::from_raw(99));
    assert_eq!(ev.epoch().as_u64(), 99);
}

#[test]
fn enrichment_evaluator_serde_roundtrip() {
    let mut ev = GateEvaluator::with_defaults(ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 990_000, 50);
    ev.add_throughput(AddonCohort::Compression, "zstd", 10_000, 9_500);
    ev.evaluate();
    let json = serde_json::to_string(&ev).unwrap();
    let back: GateEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(back.evaluation_count(), 1);
    assert_eq!(back.parity_entry_count(), 1);
    assert_eq!(back.throughput_entry_count(), 1);
}

#[test]
fn enrichment_evaluator_clone() {
    let mut ev = GateEvaluator::with_defaults(ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 990_000, 50);
    ev.evaluate();
    let ev2 = ev.clone();
    assert_eq!(ev2.evaluation_count(), 1);
    assert_eq!(ev2.parity_entry_count(), 1);
}

#[test]
fn enrichment_evaluator_debug() {
    let ev = GateEvaluator::with_defaults(ep());
    let dbg = format!("{:?}", ev);
    assert!(dbg.contains("GateEvaluator"));
}

#[test]
fn enrichment_evaluator_clear_preserves_counters() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    ev.evaluate();
    let evals_before = ev.evaluation_count();
    let approved_before = ev.approved_count();
    ev.clear();
    // Counters are NOT reset by clear
    assert_eq!(ev.evaluation_count(), evals_before);
    assert_eq!(ev.approved_count(), approved_before);
    // But evidence is cleared
    assert_eq!(ev.parity_entry_count(), 0);
}

#[test]
fn enrichment_evaluator_multiple_evaluations_accumulate_counters() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    for _ in 0..5 {
        ev.evaluate();
        ev.clear();
    }
    assert_eq!(ev.evaluation_count(), 5);
    assert_eq!(ev.approved_count(), 5);
    assert_eq!(ev.denied_count(), 0);
}

#[test]
fn enrichment_evaluator_approval_rate_zero_evals() {
    let ev = GateEvaluator::with_defaults(ep());
    assert_eq!(ev.approval_rate_millionths(), 0);
}

#[test]
fn enrichment_evaluator_approval_rate_one_third() {
    let mut ev = GateEvaluator::with_defaults(ep());
    // 1 approved
    ev.evaluate();
    ev.clear();
    // 2 denied
    ev.add_parity(AddonCohort::Crypto, "x", GateAxis::Parity, 100_000, 50);
    ev.evaluate();
    ev.clear();
    ev.add_parity(AddonCohort::Crypto, "x", GateAxis::Parity, 100_000, 50);
    ev.evaluate();
    // 1/3 = 333_333
    assert_eq!(ev.approval_rate_millionths(), 333_333);
}

#[test]
fn enrichment_evaluator_summary_after_mixed() {
    let cfg = GateConfig::default().with_min_samples(1);
    let mut ev = GateEvaluator::new(cfg, ep());
    // First: approved
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
    ev.add_throughput(AddonCohort::Crypto, "aes", 10_000, 9_500);
    ev.evaluate();
    ev.clear();
    // Second: denied
    ev.add_parity(AddonCohort::Database, "pg", GateAxis::Parity, 100_000, 50);
    ev.evaluate();
    let s = ev.summary();
    assert_eq!(s.total_evaluations, 2);
    assert_eq!(s.approved_count, 1);
    assert_eq!(s.denied_count, 1);
    assert_eq!(s.approval_rate_millionths, 500_000);
}

#[test]
fn enrichment_evaluator_last_receipt_updates_on_each_evaluation() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    assert!(ev.last_receipt().is_none());
    ev.evaluate();
    let r1_hash = ev.last_receipt().unwrap().content_hash.clone();
    ev.clear();
    ev.add_parity(AddonCohort::Database, "pg", GateAxis::Parity, 990_000, 50);
    ev.evaluate();
    let r2_hash = ev.last_receipt().unwrap().content_hash.clone();
    assert_ne!(r1_hash, r2_hash);
}

// ============================================================================
// Enrichment tests — GateSummary
// ============================================================================

#[test]
fn enrichment_summary_serde_roundtrip() {
    let s = GateSummary {
        total_evaluations: 10,
        approved_count: 7,
        denied_count: 3,
        parity_entries: 20,
        security_findings: 5,
        throughput_entries: 15,
        support_surface_entries: 8,
        approval_rate_millionths: 700_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_summary_clone() {
    let s = GateSummary {
        total_evaluations: 1,
        approved_count: 1,
        denied_count: 0,
        parity_entries: 1,
        security_findings: 0,
        throughput_entries: 0,
        support_surface_entries: 0,
        approval_rate_millionths: MILLIONTHS,
    };
    let s2 = s.clone();
    assert_eq!(s, s2);
}

#[test]
fn enrichment_summary_debug() {
    let s = GateSummary {
        total_evaluations: 0,
        approved_count: 0,
        denied_count: 0,
        parity_entries: 0,
        security_findings: 0,
        throughput_entries: 0,
        support_surface_entries: 0,
        approval_rate_millionths: 0,
    };
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("total_evaluations"));
}

// ============================================================================
// Enrichment tests — Manifest
// ============================================================================

#[test]
fn enrichment_manifest_has_exactly_four_keys() {
    let m = native_addon_parity_gate_manifest();
    assert_eq!(m.len(), 4);
}

#[test]
fn enrichment_manifest_key_stability() {
    let m = native_addon_parity_gate_manifest();
    assert!(m.contains_key("schema_version"));
    assert!(m.contains_key("component"));
    assert!(m.contains_key("bead_id"));
    assert!(m.contains_key("policy_id"));
}

#[test]
fn enrichment_manifest_deterministic() {
    let m1 = native_addon_parity_gate_manifest();
    let m2 = native_addon_parity_gate_manifest();
    assert_eq!(m1, m2);
}

// ============================================================================
// Enrichment tests — Determinism
// ============================================================================

#[test]
fn enrichment_determinism_full_evaluation_twice() {
    let build = || {
        let cfg = GateConfig::default()
            .with_min_samples(5)
            .with_required_cohort(AddonCohort::Crypto);
        let mut ev = GateEvaluator::new(cfg, ep());
        ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 980_000, 50);
        ev.add_throughput(AddonCohort::Crypto, "aes", 10_000, 9_500);
        ev.add_support_surface(AddonCohort::Crypto, 90, 100);
        ev.add_security_finding(FindingSeverity::Low, FindingCategory::InfoLeak, "a", "b");
        ev.evaluate()
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.verdict, r2.verdict);
    assert_eq!(r1.violations.len(), r2.violations.len());
}

#[test]
fn enrichment_determinism_parity_entry_hash_stable() {
    for _ in 0..3 {
        let e = ParityEntry::new(
            AddonCohort::Compression,
            "zstd",
            GateAxis::Parity,
            970_000,
            40,
            950_000,
            30,
        );
        let e2 = ParityEntry::new(
            AddonCohort::Compression,
            "zstd",
            GateAxis::Parity,
            970_000,
            40,
            950_000,
            30,
        );
        assert_eq!(e.content_hash, e2.content_hash);
    }
}

// ============================================================================
// Enrichment tests — E2E edge cases
// ============================================================================

#[test]
fn enrichment_e2e_empty_evidence_approved_with_defaults() {
    let mut ev = GateEvaluator::with_defaults(ep());
    let receipt = ev.evaluate();
    assert!(receipt.is_approved());
    assert_eq!(receipt.violation_count(), 0);
    assert!(receipt.observed_cohorts.is_empty());
}

#[test]
fn enrichment_e2e_fail_closed_missing_required_cohort() {
    let cfg = GateConfig::default()
        .with_required_cohort(AddonCohort::Crypto);
    let mut ev = GateEvaluator::new(cfg, ep());
    // No evidence at all
    let receipt = ev.evaluate();
    assert!(!receipt.is_approved());
    assert!(receipt.missing_cohorts.contains(&AddonCohort::Crypto));
}

#[test]
fn enrichment_e2e_fail_open_missing_required_cohort() {
    let cfg = GateConfig::default()
        .with_required_cohort(AddonCohort::Crypto)
        .fail_open();
    let mut ev = GateEvaluator::new(cfg, ep());
    // No evidence at all — but fail_open so missing cohorts don't cause violations
    let receipt = ev.evaluate();
    assert!(receipt.is_approved());
    assert!(receipt.missing_cohorts.contains(&AddonCohort::Crypto));
}

#[test]
fn enrichment_e2e_only_throughput_observed_cohort() {
    let cfg = GateConfig::permissive()
        .with_required_cohort(AddonCohort::Database);
    let mut ev = GateEvaluator::new(cfg, ep());
    // Provide only throughput evidence for Database
    ev.add_throughput(AddonCohort::Database, "pg", 10_000, 9_500);
    let receipt = ev.evaluate();
    assert!(receipt.is_approved());
    assert!(receipt.observed_cohorts.contains(&AddonCohort::Database));
    assert!(receipt.missing_cohorts.is_empty());
}

#[test]
fn enrichment_e2e_only_support_surface_observed_cohort() {
    let cfg = GateConfig::permissive()
        .with_required_cohort(AddonCohort::MediaCodec);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_support_surface(AddonCohort::MediaCodec, 90, 100);
    let receipt = ev.evaluate();
    assert!(receipt.is_approved());
    assert!(receipt.observed_cohorts.contains(&AddonCohort::MediaCodec));
}

#[test]
fn enrichment_e2e_security_findings_at_max_allowed() {
    let cfg = GateConfig::default().with_max_security_findings(2);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_security_finding(FindingSeverity::Critical, FindingCategory::BufferOverflow, "a", "d1");
    ev.add_security_finding(FindingSeverity::High, FindingCategory::UseAfterFree, "b", "d2");
    let receipt = ev.evaluate();
    // 2 blocking findings <= max 2 -> approved
    assert!(receipt.is_approved());
}

#[test]
fn enrichment_e2e_security_findings_over_max_allowed() {
    let cfg = GateConfig::default().with_max_security_findings(1);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_security_finding(FindingSeverity::Critical, FindingCategory::BufferOverflow, "a", "d1");
    ev.add_security_finding(FindingSeverity::High, FindingCategory::UseAfterFree, "b", "d2");
    let receipt = ev.evaluate();
    // 2 blocking findings > max 1 -> denied
    assert_eq!(receipt.verdict, GateVerdict::SecurityBlocking);
}

#[test]
fn enrichment_e2e_parity_violation_message_contains_addon_name() {
    let cfg = GateConfig::default().with_min_samples(1);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "special-aes-256", GateAxis::Parity, 500_000, 50);
    let receipt = ev.evaluate();
    assert!(receipt.violations[0].description.contains("special-aes-256"));
}

#[test]
fn enrichment_e2e_parity_insufficient_samples_message() {
    let cfg = GateConfig::default(); // min_sample_count = 30
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 990_000, 5);
    let receipt = ev.evaluate();
    assert_eq!(receipt.verdict, GateVerdict::ParityViolation);
    assert!(receipt.violations[0].description.contains("insufficient samples"));
}

#[test]
fn enrichment_e2e_throughput_violation_message_contains_addon_name() {
    let cfg = GateConfig::default().with_max_overhead(50_000);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_throughput(AddonCohort::Compression, "custom-zstd", 10_000, 5_000);
    let receipt = ev.evaluate();
    assert!(receipt.violations[0].description.contains("custom-zstd"));
}

#[test]
fn enrichment_e2e_support_violation_message_contains_cohort_name() {
    let cfg = GateConfig::default().with_min_support_coverage(900_000);
    let mut ev = GateEvaluator::new(cfg, ep());
    ev.add_support_surface(AddonCohort::MachineLearning, 50, 100);
    let receipt = ev.evaluate();
    assert!(receipt.violations[0].description.contains("machine_learning"));
}

#[test]
fn enrichment_e2e_missing_cohort_violation_message() {
    let cfg = GateConfig::default()
        .with_required_cohort(AddonCohort::Networking);
    let mut ev = GateEvaluator::new(cfg, ep());
    let receipt = ev.evaluate();
    let net_violations: Vec<_> = receipt.violations.iter()
        .filter(|v| v.description.contains("networking"))
        .collect();
    assert!(!net_violations.is_empty());
}

#[test]
fn enrichment_e2e_receipt_json_canonical_fields() {
    let cfg = GateConfig::permissive();
    let mut ev = GateEvaluator::new(cfg, ep());
    let receipt = ev.evaluate();
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"bead_id\""));
    assert!(json.contains("\"policy_id\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"content_hash\""));
    assert!(json.contains("\"violations\""));
    assert!(json.contains("\"observed_cohorts\""));
    assert!(json.contains("\"missing_cohorts\""));
}

#[test]
fn enrichment_e2e_all_cohorts_strict_all_pass() {
    let cfg = GateConfig::strict();
    let mut ev = GateEvaluator::new(cfg, ep());
    for cohort in AddonCohort::ALL {
        ev.add_parity(*cohort, "addon", GateAxis::Parity, 995_000, 100);
        ev.add_throughput(*cohort, "addon", 100_000, 98_000);
        ev.add_support_surface(*cohort, 95, 100);
    }
    let receipt = ev.evaluate();
    assert!(receipt.is_approved());
    assert_eq!(receipt.observed_cohorts.len(), 8);
    assert!(receipt.missing_cohorts.is_empty());
}

#[test]
fn enrichment_e2e_strict_one_cohort_failing_parity() {
    let cfg = GateConfig::strict();
    let mut ev = GateEvaluator::new(cfg, ep());
    for (i, cohort) in AddonCohort::ALL.iter().enumerate() {
        let parity = if i == 0 { 500_000 } else { 995_000 }; // first cohort fails
        ev.add_parity(*cohort, "addon", GateAxis::Parity, parity, 100);
        ev.add_throughput(*cohort, "addon", 100_000, 98_000);
        ev.add_support_surface(*cohort, 95, 100);
    }
    let receipt = ev.evaluate();
    assert!(!receipt.is_approved());
}

// ============================================================================
// Enrichment tests — Constants cross-validation
// ============================================================================

#[test]
fn enrichment_constants_schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrichment_constants_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(BEAD_ID.contains('.'));
}

#[test]
fn enrichment_constants_policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn enrichment_constants_default_thresholds_relative() {
    // Parity threshold (95%) > support coverage (80%)
    const {
        assert!(DEFAULT_MIN_PARITY_MILLIONTHS > DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS);
        // All thresholds < MILLIONTHS
        assert!(DEFAULT_MIN_PARITY_MILLIONTHS <= MILLIONTHS);
        assert!(DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS <= MILLIONTHS);
        assert!(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS <= MILLIONTHS);
    }
}
