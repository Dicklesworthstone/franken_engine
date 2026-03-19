//! Enrichment integration tests for `native_addon_cohort_gate` (bd-1lsy.5.9.3).
//!
//! Exercises advanced gate evaluation paths, governance derivation, tier
//! coverage computation, receipt tamper evidence, serde fidelity, and
//! edge-case interactions across the public API.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::native_addon_cohort_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(20)
}

fn hash(tag: &[u8]) -> ContentHash {
    ContentHash::compute(tag)
}

fn addon(name: &str, tier: CohortTier) -> AddonDescriptor {
    AddonDescriptor {
        name: String::from(name),
        version: String::from("2.0.0"),
        tier,
        napi_version: 8,
        node_api_calls: 25,
        has_worker_threads: false,
        has_async_hooks: false,
    }
}

fn parity_finding(name: &str, dim: ParityDimension, achieved: bool) -> ParityFinding {
    ParityFinding {
        dimension: dim,
        addon_name: String::from(name),
        is_parity_achieved: achieved,
        divergence_count: if achieved { 0 } else { 2 },
        total_checks: 10,
        detail: String::from("enrichment parity finding"),
    }
}

fn security_finding(
    name: &str,
    class: SecurityClass,
    verdict: SecurityVerdict,
) -> SecurityFinding {
    SecurityFinding {
        class,
        addon_name: String::from(name),
        verdict,
        vulnerability_count: if matches!(verdict, SecurityVerdict::Vulnerable) {
            1
        } else {
            0
        },
        detail: String::from("enrichment security finding"),
        content_hash: hash(name.as_bytes()),
    }
}

fn throughput_sample(name: &str, baseline: u64, candidate: u64) -> ThroughputSample {
    ThroughputSample {
        metric: ThroughputMetric::CallLatency,
        addon_name: String::from(name),
        baseline_millionths: baseline,
        candidate_millionths: candidate,
        sample_count: 50,
        epoch: epoch(),
    }
}

// ===========================================================================
// Section 1: Constants
// ===========================================================================

#[test]
fn enrich_schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrich_component_is_module_name() {
    assert_eq!(COMPONENT, "native_addon_cohort_gate");
}

#[test]
fn enrich_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrich_policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

// ===========================================================================
// Section 2: CohortTier
// ===========================================================================

#[test]
fn enrich_cohort_tier_all_has_six_variants() {
    assert_eq!(CohortTier::ALL.len(), 6);
}

#[test]
fn enrich_cohort_tier_display_uniqueness() {
    let set: BTreeSet<String> = CohortTier::ALL.iter().map(|t| t.to_string()).collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrich_cohort_tier_as_str_matches_display() {
    for tier in CohortTier::ALL {
        assert_eq!(tier.as_str(), &tier.to_string());
    }
}

#[test]
fn enrich_cohort_tier_serde_roundtrip_all() {
    for tier in CohortTier::ALL {
        let json = serde_json::to_string(tier).unwrap();
        let restored: CohortTier = serde_json::from_str(&json).unwrap();
        assert_eq!(*tier, restored);
    }
}

// ===========================================================================
// Section 3: ParityDimension
// ===========================================================================

#[test]
fn enrich_parity_dimension_all_has_six() {
    assert_eq!(ParityDimension::ALL.len(), 6);
}

#[test]
fn enrich_parity_dimension_display_uniqueness() {
    let set: BTreeSet<String> = ParityDimension::ALL.iter().map(|d| d.to_string()).collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrich_parity_dimension_serde_roundtrip_all() {
    for dim in ParityDimension::ALL {
        let json = serde_json::to_string(dim).unwrap();
        let restored: ParityDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, restored);
    }
}

// ===========================================================================
// Section 4: SecurityClass
// ===========================================================================

#[test]
fn enrich_security_class_all_has_six() {
    assert_eq!(SecurityClass::ALL.len(), 6);
}

#[test]
fn enrich_security_class_display_uniqueness() {
    let set: BTreeSet<String> = SecurityClass::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrich_security_class_serde_roundtrip_all() {
    for class in SecurityClass::ALL {
        let json = serde_json::to_string(class).unwrap();
        let restored: SecurityClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*class, restored);
    }
}

// ===========================================================================
// Section 5: ThroughputMetric
// ===========================================================================

#[test]
fn enrich_throughput_metric_all_has_six() {
    assert_eq!(ThroughputMetric::ALL.len(), 6);
}

#[test]
fn enrich_throughput_metric_display_uniqueness() {
    let set: BTreeSet<String> = ThroughputMetric::ALL.iter().map(|m| m.to_string()).collect();
    assert_eq!(set.len(), 6);
}

// ===========================================================================
// Section 6: GateVerdict
// ===========================================================================

#[test]
fn enrich_gate_verdict_pass_is_adoptable() {
    assert!(GateVerdict::Pass.is_adoptable());
}

#[test]
fn enrich_gate_verdict_conditional_pass_is_adoptable() {
    assert!(GateVerdict::ConditionalPass.is_adoptable());
}

#[test]
fn enrich_gate_verdict_fail_not_adoptable() {
    assert!(!GateVerdict::Fail.is_adoptable());
}

#[test]
fn enrich_gate_verdict_insufficient_not_adoptable() {
    assert!(!GateVerdict::InsufficientEvidence.is_adoptable());
}

#[test]
fn enrich_gate_verdict_display_uniqueness() {
    let verdicts = [
        GateVerdict::Pass,
        GateVerdict::ConditionalPass,
        GateVerdict::Fail,
        GateVerdict::InsufficientEvidence,
    ];
    let set: BTreeSet<String> = verdicts.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), 4);
}

// ===========================================================================
// Section 7: SecurityVerdict
// ===========================================================================

#[test]
fn enrich_security_verdict_serde_roundtrip_all() {
    let verdicts = [
        SecurityVerdict::Secure,
        SecurityVerdict::ConditionallySecure,
        SecurityVerdict::Vulnerable,
        SecurityVerdict::Unassessed,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let restored: SecurityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn enrich_security_verdict_display_uniqueness() {
    let set: BTreeSet<String> = [
        SecurityVerdict::Secure,
        SecurityVerdict::ConditionallySecure,
        SecurityVerdict::Vulnerable,
        SecurityVerdict::Unassessed,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(set.len(), 4);
}

// ===========================================================================
// Section 8: GovernanceAction
// ===========================================================================

#[test]
fn enrich_governance_action_display_uniqueness() {
    let actions = [
        GovernanceAction::AllowAdoption,
        GovernanceAction::ConditionalAdoption,
        GovernanceAction::BlockAdoption,
        GovernanceAction::RequireAudit,
        GovernanceAction::DowngradeTier,
        GovernanceAction::RequireRemediation,
    ];
    let set: BTreeSet<String> = actions.iter().map(|a| a.to_string()).collect();
    assert_eq!(set.len(), 6);
}

// ===========================================================================
// Section 9: compute_parity_verdict
// ===========================================================================

#[test]
fn enrich_parity_verdict_empty_is_insufficient() {
    let v = compute_parity_verdict(&[], 800_000);
    assert_eq!(v, GateVerdict::InsufficientEvidence);
}

#[test]
fn enrich_parity_verdict_all_achieved_is_pass() {
    let findings = vec![
        parity_finding("a", ParityDimension::ApiSurface, true),
        parity_finding("a", ParityDimension::MemorySafety, true),
    ];
    let v = compute_parity_verdict(&findings, 800_000);
    assert_eq!(v, GateVerdict::Pass);
}

#[test]
fn enrich_parity_verdict_none_achieved_is_fail() {
    let findings = vec![
        parity_finding("a", ParityDimension::ApiSurface, false),
        parity_finding("a", ParityDimension::MemorySafety, false),
    ];
    let v = compute_parity_verdict(&findings, 800_000);
    assert_eq!(v, GateVerdict::Fail);
}

#[test]
fn enrich_parity_verdict_partial_is_conditional() {
    // 1 of 2 achieved = 500_000 coverage, which is >= 800_000/2 = 400_000
    let findings = vec![
        parity_finding("a", ParityDimension::ApiSurface, true),
        parity_finding("a", ParityDimension::MemorySafety, false),
    ];
    let v = compute_parity_verdict(&findings, 800_000);
    assert_eq!(v, GateVerdict::ConditionalPass);
}

// ===========================================================================
// Section 10: compute_security_verdict
// ===========================================================================

#[test]
fn enrich_security_verdict_empty_is_unassessed() {
    let v = compute_security_verdict(&[]);
    assert_eq!(v, SecurityVerdict::Unassessed);
}

#[test]
fn enrich_security_verdict_all_secure() {
    let findings = vec![
        security_finding("a", SecurityClass::MemoryIsolation, SecurityVerdict::Secure),
        security_finding("a", SecurityClass::InputValidation, SecurityVerdict::Secure),
    ];
    let v = compute_security_verdict(&findings);
    assert_eq!(v, SecurityVerdict::Secure);
}

#[test]
fn enrich_security_verdict_any_vulnerable_yields_vulnerable() {
    let findings = vec![
        security_finding("a", SecurityClass::MemoryIsolation, SecurityVerdict::Secure),
        security_finding(
            "a",
            SecurityClass::InputValidation,
            SecurityVerdict::Vulnerable,
        ),
    ];
    let v = compute_security_verdict(&findings);
    assert_eq!(v, SecurityVerdict::Vulnerable);
}

#[test]
fn enrich_security_verdict_conditional_without_vulnerable() {
    let findings = vec![
        security_finding("a", SecurityClass::MemoryIsolation, SecurityVerdict::Secure),
        security_finding(
            "a",
            SecurityClass::InputValidation,
            SecurityVerdict::ConditionallySecure,
        ),
    ];
    let v = compute_security_verdict(&findings);
    assert_eq!(v, SecurityVerdict::ConditionallySecure);
}

// ===========================================================================
// Section 11: compute_throughput_verdict
// ===========================================================================

#[test]
fn enrich_throughput_verdict_empty_is_insufficient() {
    let v = compute_throughput_verdict(&[], 100_000, 30);
    assert_eq!(v, GateVerdict::InsufficientEvidence);
}

#[test]
fn enrich_throughput_verdict_no_regression_is_pass() {
    let samples = vec![throughput_sample("a", 1_000_000, 900_000)];
    // Regression = 100_000/1_000_000 * 1M = 100_000. Max = 200_000. Pass.
    let v = compute_throughput_verdict(&samples, 200_000, 30);
    assert_eq!(v, GateVerdict::Pass);
}

#[test]
fn enrich_throughput_verdict_high_regression_is_fail() {
    let samples = vec![throughput_sample("a", 1_000_000, 2_000_000)];
    // Candidate > baseline => regression. delta = 1M, regression = 1M.
    let v = compute_throughput_verdict(&samples, 100_000, 30);
    assert_eq!(v, GateVerdict::Fail);
}

#[test]
fn enrich_throughput_verdict_low_samples_is_insufficient() {
    let mut sample = throughput_sample("a", 1_000_000, 900_000);
    sample.sample_count = 5; // below min of 30
    let v = compute_throughput_verdict(&[sample], 200_000, 30);
    assert_eq!(v, GateVerdict::InsufficientEvidence);
}

// ===========================================================================
// Section 12: derive_governance_action
// ===========================================================================

#[test]
fn enrich_governance_vulnerable_critical_blocks() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Vulnerable,
        &CohortTier::Critical,
    );
    assert_eq!(action, GovernanceAction::BlockAdoption);
}

#[test]
fn enrich_governance_vulnerable_low_requires_remediation() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Vulnerable,
        &CohortTier::Low,
    );
    assert_eq!(action, GovernanceAction::RequireRemediation);
}

#[test]
fn enrich_governance_unassessed_critical_requires_audit() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Unassessed,
        &CohortTier::Critical,
    );
    assert_eq!(action, GovernanceAction::RequireAudit);
}

#[test]
fn enrich_governance_pass_secure_allows() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Secure,
        &CohortTier::Medium,
    );
    assert_eq!(action, GovernanceAction::AllowAdoption);
}

#[test]
fn enrich_governance_pass_conditional_secure() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::ConditionallySecure,
        &CohortTier::Medium,
    );
    assert_eq!(action, GovernanceAction::ConditionalAdoption);
}

#[test]
fn enrich_governance_fail_critical_blocks() {
    let action = derive_governance_action(
        &GateVerdict::Fail,
        &SecurityVerdict::Secure,
        &CohortTier::Critical,
    );
    assert_eq!(action, GovernanceAction::BlockAdoption);
}

#[test]
fn enrich_governance_fail_medium_requires_remediation() {
    let action = derive_governance_action(
        &GateVerdict::Fail,
        &SecurityVerdict::Secure,
        &CohortTier::Medium,
    );
    assert_eq!(action, GovernanceAction::RequireRemediation);
}

#[test]
fn enrich_governance_fail_low_downgrades() {
    let action = derive_governance_action(
        &GateVerdict::Fail,
        &SecurityVerdict::Secure,
        &CohortTier::Low,
    );
    assert_eq!(action, GovernanceAction::DowngradeTier);
}

// ===========================================================================
// Section 13: evaluate_cohort_gate — empty addons
// ===========================================================================

#[test]
fn enrich_evaluate_cohort_gate_empty_addons() {
    let config = GateConfig::default();
    let report = evaluate_cohort_gate(&config, &[], &[], &[], &[], epoch());
    assert_eq!(report.overall_verdict, GateVerdict::InsufficientEvidence);
    assert_eq!(report.total_addons, 0);
    assert_eq!(report.passing_addons, 0);
    assert_eq!(report.failing_addons, 0);
}

// ===========================================================================
// Section 14: evaluate_cohort_gate — single addon pass
// ===========================================================================

#[test]
fn enrich_evaluate_cohort_gate_single_addon_pass() {
    let config = GateConfig::default();
    let addons = vec![addon("crypto-a", CohortTier::High)];

    let parity = vec![
        parity_finding("crypto-a", ParityDimension::ApiSurface, true),
        parity_finding("crypto-a", ParityDimension::MemorySafety, true),
        parity_finding("crypto-a", ParityDimension::ThreadSafety, true),
    ];
    let security = vec![
        security_finding(
            "crypto-a",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::Secure,
        ),
    ];
    let throughput = vec![throughput_sample("crypto-a", 1_000_000, 950_000)];

    let report = evaluate_cohort_gate(
        &config,
        &addons,
        &parity,
        &security,
        &throughput,
        epoch(),
    );

    assert_eq!(report.total_addons, 1);
    assert!(report.passing_addons >= 1 || report.overall_verdict == GateVerdict::Pass);
}

// ===========================================================================
// Section 15: compute_tier_coverage
// ===========================================================================

#[test]
fn enrich_compute_tier_coverage_empty_results() {
    let coverage = compute_tier_coverage(&[]);
    assert!(coverage.is_empty());
}

// ===========================================================================
// Section 16: compute_receipt determinism
// ===========================================================================

#[test]
fn enrich_compute_receipt_deterministic() {
    let input_hash = ContentHash::compute(b"test-input");
    let r1 = compute_receipt(input_hash.clone(), &GateVerdict::Pass, epoch());
    let r2 = compute_receipt(input_hash, &GateVerdict::Pass, epoch());
    assert_eq!(r1.verdict_hash, r2.verdict_hash);
    assert_eq!(r1.schema_version, SCHEMA_VERSION);
    assert_eq!(r1.component, COMPONENT);
    assert_eq!(r1.bead_id, BEAD_ID);
    assert_eq!(r1.policy_id, POLICY_ID);
}

#[test]
fn enrich_compute_receipt_different_verdicts_different_hash() {
    let input_hash = ContentHash::compute(b"test-input");
    let r1 = compute_receipt(input_hash.clone(), &GateVerdict::Pass, epoch());
    let r2 = compute_receipt(input_hash, &GateVerdict::Fail, epoch());
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

// ===========================================================================
// Section 17: AddonDescriptor serde
// ===========================================================================

#[test]
fn enrich_addon_descriptor_serde_roundtrip() {
    let a = addon("test-addon", CohortTier::Critical);
    let json = serde_json::to_string(&a).unwrap();
    let restored: AddonDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(a, restored);
}

#[test]
fn enrich_addon_descriptor_with_worker_threads() {
    let mut a = addon("wt-addon", CohortTier::Medium);
    a.has_worker_threads = true;
    a.has_async_hooks = true;
    let json = serde_json::to_string(&a).unwrap();
    let restored: AddonDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(a, restored);
}

// ===========================================================================
// Section 18: ParityFinding serde
// ===========================================================================

#[test]
fn enrich_parity_finding_serde_roundtrip() {
    let f = parity_finding("a", ParityDimension::ErrorSemantics, true);
    let json = serde_json::to_string(&f).unwrap();
    let restored: ParityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, restored);
}

// ===========================================================================
// Section 19: SecurityFinding serde
// ===========================================================================

#[test]
fn enrich_security_finding_serde_roundtrip() {
    let f = security_finding(
        "b",
        SecurityClass::SandboxEscapePrevention,
        SecurityVerdict::Secure,
    );
    let json = serde_json::to_string(&f).unwrap();
    let restored: SecurityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, restored);
}

// ===========================================================================
// Section 20: ThroughputSample serde
// ===========================================================================

#[test]
fn enrich_throughput_sample_serde_roundtrip() {
    let s = throughput_sample("c", 500_000, 480_000);
    let json = serde_json::to_string(&s).unwrap();
    let restored: ThroughputSample = serde_json::from_str(&json).unwrap();
    assert_eq!(s, restored);
}

// ===========================================================================
// Section 21: GateConfig default and serde
// ===========================================================================

#[test]
fn enrich_gate_config_default_values() {
    let cfg = GateConfig::default();
    assert_eq!(cfg.min_parity_coverage_millionths, 800_000);
    assert_eq!(cfg.max_throughput_regression_millionths, 100_000);
    assert!(cfg.require_security_audit);
    assert!(cfg.required_tiers.is_empty());
    assert_eq!(cfg.min_sample_count, 30);
}

#[test]
fn enrich_gate_config_serde_roundtrip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ===========================================================================
// Section 22: DecisionReceipt serde
// ===========================================================================

#[test]
fn enrich_decision_receipt_serde_roundtrip() {
    let receipt = compute_receipt(ContentHash::compute(b"data"), &GateVerdict::Pass, epoch());
    let json = serde_json::to_string(&receipt).unwrap();
    let restored: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, restored);
}

// ===========================================================================
// Section 23: GateReport serde
// ===========================================================================

#[test]
fn enrich_gate_report_empty_serde_roundtrip() {
    let config = GateConfig::default();
    let report = evaluate_cohort_gate(&config, &[], &[], &[], &[], epoch());
    let json = serde_json::to_string(&report).unwrap();
    let restored: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// ===========================================================================
// Section 24: CohortResult serde
// ===========================================================================

#[test]
fn enrich_cohort_result_serde_roundtrip() {
    let config = GateConfig::default();
    let addons = vec![addon("test-addon", CohortTier::Medium)];
    let parity = vec![parity_finding("test-addon", ParityDimension::ApiSurface, true)];
    let security = vec![security_finding(
        "test-addon",
        SecurityClass::MemoryIsolation,
        SecurityVerdict::Secure,
    )];
    let throughput = vec![throughput_sample("test-addon", 1_000_000, 950_000)];

    let result = evaluate_addon(&addons[0], &parity, &security, &throughput, &config);
    let json = serde_json::to_string(&result).unwrap();
    let restored: CohortResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// ===========================================================================
// Section 25: evaluate_addon with no evidence
// ===========================================================================

#[test]
fn enrich_evaluate_addon_no_evidence_yields_insufficient() {
    let config = GateConfig::default();
    let a = addon("empty-addon", CohortTier::Low);
    let result = evaluate_addon(&a, &[], &[], &[], &config);
    assert_eq!(result.parity_verdict, GateVerdict::InsufficientEvidence);
    assert_eq!(result.security_verdict, SecurityVerdict::Unassessed);
    assert_eq!(result.throughput_verdict, GateVerdict::InsufficientEvidence);
}
