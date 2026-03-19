//! Enrichment integration tests for `native_addon_cohort_gate`.
//!
//! Covers: serde round-trips for all enum and struct types, verdict evaluation
//! functions, governance action derivation, tier coverage computation,
//! receipt determinism, cohort gate evaluation, boundary conditions, and
//! stress scenarios.

#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::native_addon_cohort_gate::{
    AddonDescriptor, BEAD_ID, COMPONENT, CohortTier,
    GateConfig, GateVerdict, GovernanceAction, ParityDimension,
    ParityFinding, POLICY_ID, SCHEMA_VERSION, SecurityClass, SecurityFinding, SecurityVerdict,
    ThroughputMetric, ThroughputSample, compute_parity_verdict, compute_receipt,
    compute_security_verdict, compute_throughput_verdict, compute_tier_coverage,
    derive_governance_action, evaluate_addon, evaluate_cohort_gate,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

const MILLIONTHS: u64 = 1_000_000;

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_addon(name: &str, tier: CohortTier) -> AddonDescriptor {
    AddonDescriptor {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        tier,
        napi_version: 8,
        node_api_calls: 42,
        has_worker_threads: false,
        has_async_hooks: false,
    }
}

fn make_parity(addon: &str, dim: ParityDimension, achieved: bool) -> ParityFinding {
    ParityFinding {
        dimension: dim,
        addon_name: addon.to_string(),
        is_parity_achieved: achieved,
        divergence_count: if achieved { 0 } else { 5 },
        total_checks: 100,
        detail: format!("{} on {}", dim, addon),
    }
}

fn make_security(addon: &str, class: SecurityClass, verdict: SecurityVerdict) -> SecurityFinding {
    SecurityFinding {
        class,
        addon_name: addon.to_string(),
        verdict,
        vulnerability_count: if verdict == SecurityVerdict::Vulnerable { 1 } else { 0 },
        detail: format!("{} on {}", class, addon),
        content_hash: ContentHash::compute(addon.as_bytes()),
    }
}

fn make_throughput(addon: &str, metric: ThroughputMetric, baseline: u64, candidate: u64) -> ThroughputSample {
    ThroughputSample {
        metric,
        addon_name: addon.to_string(),
        baseline_millionths: baseline,
        candidate_millionths: candidate,
        sample_count: 30,
        epoch: ep(1),
    }
}

// ===========================================================================
// Serde round-trip tests
// ===========================================================================

#[test]
fn integ_cohort_tier_serde_all_variants() {
    for tier in CohortTier::ALL {
        let json = serde_json::to_string(tier).unwrap();
        let back: CohortTier = serde_json::from_str(&json).unwrap();
        assert_eq!(*tier, back);
    }
}

#[test]
fn integ_parity_dimension_serde_all_variants() {
    for dim in ParityDimension::ALL {
        let json = serde_json::to_string(dim).unwrap();
        let back: ParityDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back);
    }
}

#[test]
fn integ_security_class_serde_all_variants() {
    for class in SecurityClass::ALL {
        let json = serde_json::to_string(class).unwrap();
        let back: SecurityClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*class, back);
    }
}

#[test]
fn integ_throughput_metric_serde_all_variants() {
    for metric in ThroughputMetric::ALL {
        let json = serde_json::to_string(metric).unwrap();
        let back: ThroughputMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(*metric, back);
    }
}

#[test]
fn integ_gate_verdict_serde_all_variants() {
    for verdict in [
        GateVerdict::Pass,
        GateVerdict::ConditionalPass,
        GateVerdict::Fail,
        GateVerdict::InsufficientEvidence,
    ] {
        let json = serde_json::to_string(&verdict).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, back);
    }
}

#[test]
fn integ_security_verdict_serde_all_variants() {
    for sv in [
        SecurityVerdict::Secure,
        SecurityVerdict::ConditionallySecure,
        SecurityVerdict::Vulnerable,
        SecurityVerdict::Unassessed,
    ] {
        let json = serde_json::to_string(&sv).unwrap();
        let back: SecurityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(sv, back);
    }
}

#[test]
fn integ_addon_descriptor_serde_roundtrip() {
    let addon = make_addon("sharp", CohortTier::Critical);
    let json = serde_json::to_string(&addon).unwrap();
    let back: AddonDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(addon, back);
}

#[test]
fn integ_gate_config_serde_roundtrip() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// Display tests
// ===========================================================================

#[test]
fn integ_cohort_tier_display_all_unique() {
    let mut displays = BTreeSet::new();
    for tier in CohortTier::ALL {
        displays.insert(tier.to_string());
    }
    assert_eq!(displays.len(), 6);
}

#[test]
fn integ_parity_dimension_display_all_unique() {
    let mut displays = BTreeSet::new();
    for dim in ParityDimension::ALL {
        displays.insert(dim.to_string());
    }
    assert_eq!(displays.len(), 6);
}

#[test]
fn integ_security_class_display_all_unique() {
    let mut displays = BTreeSet::new();
    for class in SecurityClass::ALL {
        displays.insert(class.to_string());
    }
    assert_eq!(displays.len(), 6);
}

#[test]
fn integ_throughput_metric_display_all_unique() {
    let mut displays = BTreeSet::new();
    for metric in ThroughputMetric::ALL {
        displays.insert(metric.to_string());
    }
    assert_eq!(displays.len(), 6);
}

#[test]
fn integ_gate_verdict_adoptability() {
    assert!(GateVerdict::Pass.is_adoptable());
    assert!(GateVerdict::ConditionalPass.is_adoptable());
    assert!(!GateVerdict::Fail.is_adoptable());
    assert!(!GateVerdict::InsufficientEvidence.is_adoptable());
}

// ===========================================================================
// Parity verdict tests
// ===========================================================================

#[test]
fn integ_parity_verdict_empty_is_insufficient() {
    assert_eq!(compute_parity_verdict(&[], 800_000), GateVerdict::InsufficientEvidence);
}

#[test]
fn integ_parity_verdict_all_pass() {
    let findings: Vec<ParityFinding> = ParityDimension::ALL
        .iter()
        .map(|d| make_parity("test", *d, true))
        .collect();
    assert_eq!(compute_parity_verdict(&findings, 800_000), GateVerdict::Pass);
}

#[test]
fn integ_parity_verdict_below_threshold_fails() {
    let findings: Vec<ParityFinding> = ParityDimension::ALL
        .iter()
        .enumerate()
        .map(|(i, d)| make_parity("test", *d, i < 2))
        .collect();
    assert_eq!(compute_parity_verdict(&findings, 800_000), GateVerdict::Fail);
}

#[test]
fn integ_parity_verdict_conditional_at_half_threshold() {
    let findings: Vec<ParityFinding> = ParityDimension::ALL
        .iter()
        .enumerate()
        .map(|(i, d)| make_parity("test", *d, i < 3))
        .collect();
    assert_eq!(compute_parity_verdict(&findings, 800_000), GateVerdict::ConditionalPass);
}

// ===========================================================================
// Security verdict tests
// ===========================================================================

#[test]
fn integ_security_verdict_empty_is_unassessed() {
    assert_eq!(compute_security_verdict(&[]), SecurityVerdict::Unassessed);
}

#[test]
fn integ_security_verdict_all_secure() {
    let findings: Vec<SecurityFinding> = SecurityClass::ALL
        .iter()
        .map(|c| make_security("test", *c, SecurityVerdict::Secure))
        .collect();
    assert_eq!(compute_security_verdict(&findings), SecurityVerdict::Secure);
}

#[test]
fn integ_security_verdict_one_vulnerable_overrides() {
    let findings = vec![
        make_security("test", SecurityClass::MemoryIsolation, SecurityVerdict::Secure),
        make_security("test", SecurityClass::InputValidation, SecurityVerdict::Vulnerable),
    ];
    assert_eq!(compute_security_verdict(&findings), SecurityVerdict::Vulnerable);
}

#[test]
fn integ_security_verdict_conditionally_secure() {
    let findings = vec![
        make_security("test", SecurityClass::MemoryIsolation, SecurityVerdict::Secure),
        make_security("test", SecurityClass::OutputSanitization, SecurityVerdict::ConditionallySecure),
    ];
    assert_eq!(compute_security_verdict(&findings), SecurityVerdict::ConditionallySecure);
}

// ===========================================================================
// Throughput verdict tests
// ===========================================================================

#[test]
fn integ_throughput_verdict_empty_is_insufficient() {
    assert_eq!(compute_throughput_verdict(&[], 100_000, 30), GateVerdict::InsufficientEvidence);
}

#[test]
fn integ_throughput_verdict_no_regression_passes() {
    let samples = vec![make_throughput("test", ThroughputMetric::CallLatency, MILLIONTHS, MILLIONTHS)];
    assert_eq!(compute_throughput_verdict(&samples, 100_000, 30), GateVerdict::Pass);
}

#[test]
fn integ_throughput_verdict_regression_above_threshold_fails() {
    let samples = vec![make_throughput("test", ThroughputMetric::CallLatency, MILLIONTHS, 1_200_000)];
    assert_eq!(compute_throughput_verdict(&samples, 100_000, 30), GateVerdict::Fail);
}

#[test]
fn integ_throughput_verdict_regression_between_half_and_full_conditional() {
    let samples = vec![make_throughput("test", ThroughputMetric::CallLatency, MILLIONTHS, 1_070_000)];
    assert_eq!(compute_throughput_verdict(&samples, 100_000, 30), GateVerdict::ConditionalPass);
}

#[test]
fn integ_throughput_verdict_insufficient_samples() {
    let mut sample = make_throughput("test", ThroughputMetric::CallLatency, MILLIONTHS, 1_200_000);
    sample.sample_count = 5;
    assert_eq!(compute_throughput_verdict(&[sample], 100_000, 30), GateVerdict::InsufficientEvidence);
}

#[test]
fn integ_throughput_zero_baseline_skipped() {
    let samples = vec![make_throughput("test", ThroughputMetric::CallLatency, 0, 1_200_000)];
    assert_eq!(compute_throughput_verdict(&samples, 100_000, 30), GateVerdict::Pass);
}

// ===========================================================================
// Governance action tests
// ===========================================================================

#[test]
fn integ_governance_pass_secure_allows() {
    assert_eq!(
        derive_governance_action(&GateVerdict::Pass, &SecurityVerdict::Secure, &CohortTier::Medium),
        GovernanceAction::AllowAdoption
    );
}

#[test]
fn integ_governance_vulnerable_critical_blocks() {
    assert_eq!(
        derive_governance_action(&GateVerdict::Pass, &SecurityVerdict::Vulnerable, &CohortTier::Critical),
        GovernanceAction::BlockAdoption
    );
}

#[test]
fn integ_governance_vulnerable_low_remediates() {
    assert_eq!(
        derive_governance_action(&GateVerdict::Pass, &SecurityVerdict::Vulnerable, &CohortTier::Low),
        GovernanceAction::RequireRemediation
    );
}

#[test]
fn integ_governance_fail_medium_remediates() {
    assert_eq!(
        derive_governance_action(&GateVerdict::Fail, &SecurityVerdict::Secure, &CohortTier::Medium),
        GovernanceAction::RequireRemediation
    );
}

#[test]
fn integ_governance_fail_low_downgrades() {
    assert_eq!(
        derive_governance_action(&GateVerdict::Fail, &SecurityVerdict::Secure, &CohortTier::Low),
        GovernanceAction::DowngradeTier
    );
}

#[test]
fn integ_governance_unassessed_high_audits() {
    assert_eq!(
        derive_governance_action(&GateVerdict::Pass, &SecurityVerdict::Unassessed, &CohortTier::High),
        GovernanceAction::RequireAudit
    );
}

// ===========================================================================
// Receipt tests
// ===========================================================================

#[test]
fn integ_receipt_determinism() {
    let hash = ContentHash::compute(b"test-input");
    let r1 = compute_receipt(hash, &GateVerdict::Pass, ep(5));
    let r2 = compute_receipt(hash, &GateVerdict::Pass, ep(5));
    assert_eq!(r1.verdict_hash, r2.verdict_hash);
    assert_eq!(r1.schema_version, SCHEMA_VERSION);
    assert_eq!(r1.component, COMPONENT);
}

#[test]
fn integ_receipt_different_verdicts_differ() {
    let hash = ContentHash::compute(b"test-input");
    let r1 = compute_receipt(hash, &GateVerdict::Pass, ep(5));
    let r2 = compute_receipt(hash, &GateVerdict::Fail, ep(5));
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn integ_receipt_different_epochs_differ() {
    let hash = ContentHash::compute(b"test-input");
    let r1 = compute_receipt(hash, &GateVerdict::Pass, ep(1));
    let r2 = compute_receipt(hash, &GateVerdict::Pass, ep(2));
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

// ===========================================================================
// Full cohort gate evaluation tests
// ===========================================================================

#[test]
fn integ_empty_cohort_insufficient_evidence() {
    let config = GateConfig::default();
    let report = evaluate_cohort_gate(&config, &[], &[], &[], &[], ep(1));
    assert_eq!(report.overall_verdict, GateVerdict::InsufficientEvidence);
    assert_eq!(report.total_addons, 0);
}

#[test]
fn integ_single_addon_all_pass() {
    let config = GateConfig::default();
    let addon = make_addon("good", CohortTier::Medium);
    let parity: Vec<_> = ParityDimension::ALL.iter().map(|d| make_parity("good", *d, true)).collect();
    let security: Vec<_> = SecurityClass::ALL.iter().map(|c| make_security("good", *c, SecurityVerdict::Secure)).collect();
    let throughput: Vec<_> = ThroughputMetric::ALL.iter().map(|m| make_throughput("good", *m, MILLIONTHS, MILLIONTHS)).collect();
    let report = evaluate_cohort_gate(&config, &[addon], &parity, &security, &throughput, ep(1));
    assert_eq!(report.overall_verdict, GateVerdict::Pass);
    assert_eq!(report.passing_addons, 1);
    assert_eq!(report.failing_addons, 0);
}

#[test]
fn integ_critical_failure_propagates() {
    let config = GateConfig::default();
    let addon = make_addon("vuln", CohortTier::Critical);
    let security = vec![make_security("vuln", SecurityClass::MemoryIsolation, SecurityVerdict::Vulnerable)];
    let report = evaluate_cohort_gate(&config, &[addon], &[], &security, &[], ep(1));
    assert_eq!(report.overall_verdict, GateVerdict::Fail);
    assert_eq!(report.governance_action, GovernanceAction::BlockAdoption);
}

// ===========================================================================
// Tier coverage tests
// ===========================================================================

#[test]
fn integ_tier_coverage_empty() {
    let coverage = compute_tier_coverage(&[]);
    assert!(coverage.is_empty());
}

#[test]
fn integ_tier_coverage_all_pass_is_100_percent() {
    let config = GateConfig::default();
    let addon = make_addon("a1", CohortTier::Medium);
    let parity: Vec<_> = ParityDimension::ALL.iter().map(|d| make_parity("a1", *d, true)).collect();
    let security: Vec<_> = SecurityClass::ALL.iter().map(|c| make_security("a1", *c, SecurityVerdict::Secure)).collect();
    let throughput: Vec<_> = ThroughputMetric::ALL.iter().map(|m| make_throughput("a1", *m, MILLIONTHS, MILLIONTHS)).collect();
    let result = evaluate_addon(&addon, &parity, &security, &throughput, &config);
    let coverage = compute_tier_coverage(&[result]);
    assert_eq!(coverage.len(), 1);
    assert_eq!(coverage[0].1, MILLIONTHS);
}

// ===========================================================================
// Constants tests
// ===========================================================================

#[test]
fn integ_constants_non_empty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
}

// ===========================================================================
// Config defaults
// ===========================================================================

#[test]
fn integ_config_defaults() {
    let config = GateConfig::default();
    assert_eq!(config.min_parity_coverage_millionths, 800_000);
    assert_eq!(config.max_throughput_regression_millionths, 100_000);
    assert!(config.require_security_audit);
    assert!(config.required_tiers.is_empty());
    assert_eq!(config.min_sample_count, 30);
}
