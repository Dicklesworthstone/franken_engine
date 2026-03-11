//! Integration tests for native_addon_cohort_gate (bd-1lsy.5.9.3 [RGC-407C]).
//!
//! Exercises the native-addon cohort gate through public API entry points.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::native_addon_cohort_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(10)
}

fn hash(tag: &[u8]) -> ContentHash {
    ContentHash::compute(tag)
}

fn addon(name: &str, tier: CohortTier) -> AddonDescriptor {
    AddonDescriptor {
        name: String::from(name),
        version: String::from("1.0.0"),
        tier,
        napi_version: 8,
        node_api_calls: 15,
        has_worker_threads: false,
        has_async_hooks: false,
    }
}

fn parity_finding(name: &str, dim: ParityDimension, achieved: bool) -> ParityFinding {
    ParityFinding {
        dimension: dim,
        addon_name: String::from(name),
        is_parity_achieved: achieved,
        divergence_count: if achieved { 0 } else { 3 },
        total_checks: 10,
        detail: String::from("test parity"),
    }
}

fn security_finding(name: &str, class: SecurityClass, verdict: SecurityVerdict) -> SecurityFinding {
    SecurityFinding {
        class,
        addon_name: String::from(name),
        verdict,
        vulnerability_count: if matches!(verdict, SecurityVerdict::Vulnerable) {
            2
        } else {
            0
        },
        detail: String::from("test security"),
        content_hash: hash(b"evidence"),
    }
}

fn throughput_sample(
    name: &str,
    metric: ThroughputMetric,
    baseline: u64,
    candidate: u64,
) -> ThroughputSample {
    ThroughputSample {
        metric,
        addon_name: String::from(name),
        baseline_millionths: baseline,
        candidate_millionths: candidate,
        sample_count: 50,
        epoch: epoch(),
    }
}

fn default_config() -> GateConfig {
    GateConfig::default()
}

// ---------------------------------------------------------------------------
// Empty / minimal
// ---------------------------------------------------------------------------

#[test]
fn empty_addons_yields_insufficient_evidence() {
    let config = default_config();
    let result = evaluate_cohort_gate(&config, &[], &[], &[], &[], epoch());
    assert_eq!(result.overall_verdict, GateVerdict::InsufficientEvidence);
}

#[test]
fn single_addon_passing_all() {
    let config = default_config();
    let addons = vec![addon("sharp", CohortTier::Critical)];
    let parity = vec![
        parity_finding("sharp", ParityDimension::ApiSurface, true),
        parity_finding("sharp", ParityDimension::MemorySafety, true),
        parity_finding("sharp", ParityDimension::ThreadSafety, true),
        parity_finding("sharp", ParityDimension::ErrorSemantics, true),
        parity_finding("sharp", ParityDimension::LifecycleCompliance, true),
        parity_finding("sharp", ParityDimension::AbiStability, true),
    ];
    let security = vec![
        security_finding(
            "sharp",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::Secure,
        ),
        security_finding(
            "sharp",
            SecurityClass::ResourceBounding,
            SecurityVerdict::Secure,
        ),
    ];
    let throughput = vec![throughput_sample(
        "sharp",
        ThroughputMetric::CallLatency,
        1_000_000,
        1_000_000,
    )];
    let result = evaluate_cohort_gate(&config, &addons, &parity, &security, &throughput, epoch());
    assert_eq!(result.overall_verdict, GateVerdict::Pass);
    assert_eq!(result.governance_action, GovernanceAction::AllowAdoption);
}

// ---------------------------------------------------------------------------
// Parity verdict
// ---------------------------------------------------------------------------

#[test]
fn parity_all_achieved_passes() {
    let findings = vec![
        parity_finding("addon-a", ParityDimension::ApiSurface, true),
        parity_finding("addon-a", ParityDimension::MemorySafety, true),
    ];
    let verdict = compute_parity_verdict(&findings, 800_000);
    assert_eq!(verdict, GateVerdict::Pass);
}

#[test]
fn parity_below_threshold_fails() {
    let findings = vec![
        parity_finding("addon-a", ParityDimension::ApiSurface, true),
        parity_finding("addon-a", ParityDimension::MemorySafety, false),
        parity_finding("addon-a", ParityDimension::ThreadSafety, false),
        parity_finding("addon-a", ParityDimension::ErrorSemantics, false),
        parity_finding("addon-a", ParityDimension::LifecycleCompliance, false),
    ];
    let verdict = compute_parity_verdict(&findings, 800_000);
    assert_eq!(verdict, GateVerdict::Fail);
}

#[test]
fn parity_empty_findings_insufficient() {
    let verdict = compute_parity_verdict(&[], 800_000);
    assert_eq!(verdict, GateVerdict::InsufficientEvidence);
}

// ---------------------------------------------------------------------------
// Security verdict
// ---------------------------------------------------------------------------

#[test]
fn security_all_secure_passes() {
    let findings = vec![
        security_finding(
            "addon-a",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::Secure,
        ),
        security_finding(
            "addon-a",
            SecurityClass::ResourceBounding,
            SecurityVerdict::Secure,
        ),
    ];
    let verdict = compute_security_verdict(&findings);
    assert_eq!(verdict, SecurityVerdict::Secure);
}

#[test]
fn security_one_vulnerable_is_vulnerable() {
    let findings = vec![
        security_finding(
            "addon-a",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::Secure,
        ),
        security_finding(
            "addon-a",
            SecurityClass::SandboxEscapePrevention,
            SecurityVerdict::Vulnerable,
        ),
    ];
    let verdict = compute_security_verdict(&findings);
    assert_eq!(verdict, SecurityVerdict::Vulnerable);
}

#[test]
fn security_conditionally_secure() {
    let findings = vec![security_finding(
        "addon-a",
        SecurityClass::InputValidation,
        SecurityVerdict::ConditionallySecure,
    )];
    let verdict = compute_security_verdict(&findings);
    assert_eq!(verdict, SecurityVerdict::ConditionallySecure);
}

#[test]
fn security_empty_unassessed() {
    let verdict = compute_security_verdict(&[]);
    assert_eq!(verdict, SecurityVerdict::Unassessed);
}

// ---------------------------------------------------------------------------
// Throughput verdict
// ---------------------------------------------------------------------------

#[test]
fn throughput_no_regression_passes() {
    let samples = vec![throughput_sample(
        "addon-a",
        ThroughputMetric::CallLatency,
        1_000_000,
        1_000_000,
    )];
    let verdict = compute_throughput_verdict(&samples, 100_000, 30);
    assert_eq!(verdict, GateVerdict::Pass);
}

#[test]
fn throughput_regression_above_threshold_fails() {
    let samples = vec![throughput_sample(
        "addon-a",
        ThroughputMetric::CallLatency,
        1_000_000,
        1_200_000,
    )];
    let verdict = compute_throughput_verdict(&samples, 100_000, 30);
    assert_eq!(verdict, GateVerdict::Fail);
}

#[test]
fn throughput_insufficient_samples() {
    let samples = vec![ThroughputSample {
        metric: ThroughputMetric::CallLatency,
        addon_name: String::from("addon-a"),
        baseline_millionths: 1_000_000,
        candidate_millionths: 1_200_000,
        sample_count: 5,
        epoch: epoch(),
    }];
    let verdict = compute_throughput_verdict(&samples, 100_000, 30);
    assert_eq!(verdict, GateVerdict::InsufficientEvidence);
}

#[test]
fn throughput_empty_insufficient() {
    let verdict = compute_throughput_verdict(&[], 100_000, 30);
    assert_eq!(verdict, GateVerdict::InsufficientEvidence);
}

// ---------------------------------------------------------------------------
// Governance action derivation
// ---------------------------------------------------------------------------

#[test]
fn governance_pass_secure_critical_allows() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Secure,
        &CohortTier::Critical,
    );
    assert_eq!(action, GovernanceAction::AllowAdoption);
}

#[test]
fn governance_fail_blocks() {
    let action = derive_governance_action(
        &GateVerdict::Fail,
        &SecurityVerdict::Secure,
        &CohortTier::Critical,
    );
    assert_eq!(action, GovernanceAction::BlockAdoption);
}

#[test]
fn governance_vulnerable_requires_audit() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Vulnerable,
        &CohortTier::Critical,
    );
    assert!(matches!(
        action,
        GovernanceAction::BlockAdoption | GovernanceAction::RequireAudit
    ));
}

#[test]
fn governance_insufficient_evidence() {
    let action = derive_governance_action(
        &GateVerdict::InsufficientEvidence,
        &SecurityVerdict::Unassessed,
        &CohortTier::Critical,
    );
    assert!(matches!(action, GovernanceAction::RequireAudit));
}

#[test]
fn governance_conditional_medium_tier() {
    let action = derive_governance_action(
        &GateVerdict::ConditionalPass,
        &SecurityVerdict::ConditionallySecure,
        &CohortTier::Medium,
    );
    assert_eq!(action, GovernanceAction::ConditionalAdoption);
}

// ---------------------------------------------------------------------------
// Tier coverage
// ---------------------------------------------------------------------------

#[test]
fn tier_coverage_single_addon() {
    let config = default_config();
    let addons = vec![addon("test-addon", CohortTier::High)];
    let result = evaluate_cohort_gate(&config, &addons, &[], &[], &[], epoch());
    let coverage = compute_tier_coverage(&result.cohort_results);
    assert!(!coverage.is_empty());
}

#[test]
fn tier_coverage_multiple_tiers() {
    let config = default_config();
    let addons = vec![
        addon("critical-addon", CohortTier::Critical),
        addon("high-addon", CohortTier::High),
        addon("medium-addon", CohortTier::Medium),
    ];
    let result = evaluate_cohort_gate(&config, &addons, &[], &[], &[], epoch());
    let coverage = compute_tier_coverage(&result.cohort_results);
    assert!(coverage.len() >= 3);
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

#[test]
fn receipt_fields_populated() {
    let receipt = compute_receipt(hash(b"input"), &GateVerdict::Pass, epoch());
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.bead_id, BEAD_ID);
    assert_eq!(receipt.policy_id, POLICY_ID);
}

#[test]
fn receipt_deterministic() {
    let r1 = compute_receipt(hash(b"same"), &GateVerdict::Pass, epoch());
    let r2 = compute_receipt(hash(b"same"), &GateVerdict::Pass, epoch());
    assert_eq!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_differs_by_verdict() {
    let r1 = compute_receipt(hash(b"input"), &GateVerdict::Pass, epoch());
    let r2 = compute_receipt(hash(b"input"), &GateVerdict::Fail, epoch());
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

// ---------------------------------------------------------------------------
// Enum display strings
// ---------------------------------------------------------------------------

#[test]
fn cohort_tier_display() {
    assert_eq!(CohortTier::Critical.as_str(), "critical");
    assert_eq!(CohortTier::High.as_str(), "high");
    assert_eq!(format!("{}", CohortTier::Experimental), "experimental");
}

#[test]
fn parity_dimension_display() {
    assert_eq!(ParityDimension::ApiSurface.as_str(), "api_surface");
    assert_eq!(ParityDimension::AbiStability.as_str(), "abi_stability");
    assert_eq!(
        format!("{}", ParityDimension::ThreadSafety),
        "thread_safety"
    );
}

#[test]
fn security_class_display() {
    assert_eq!(SecurityClass::MemoryIsolation.as_str(), "memory_isolation");
    assert_eq!(
        SecurityClass::SandboxEscapePrevention.as_str(),
        "sandbox_escape_prevention"
    );
    assert_eq!(
        format!("{}", SecurityClass::OutputSanitization),
        "output_sanitization"
    );
}

#[test]
fn throughput_metric_display() {
    assert_eq!(ThroughputMetric::CallLatency.as_str(), "call_latency");
    assert_eq!(ThroughputMetric::GcPressure.as_str(), "gc_pressure");
    assert_eq!(
        format!("{}", ThroughputMetric::StartupPenalty),
        "startup_penalty"
    );
}

#[test]
fn gate_verdict_display() {
    assert_eq!(GateVerdict::Pass.as_str(), "pass");
    assert_eq!(GateVerdict::Fail.as_str(), "fail");
    assert_eq!(
        format!("{}", GateVerdict::ConditionalPass),
        "conditional_pass"
    );
}

#[test]
fn security_verdict_display() {
    assert_eq!(SecurityVerdict::Secure.as_str(), "secure");
    assert_eq!(SecurityVerdict::Vulnerable.as_str(), "vulnerable");
    assert_eq!(format!("{}", SecurityVerdict::Unassessed), "unassessed");
}

#[test]
fn governance_action_display() {
    assert_eq!(GovernanceAction::AllowAdoption.as_str(), "allow_adoption");
    assert_eq!(GovernanceAction::BlockAdoption.as_str(), "block_adoption");
    assert_eq!(
        format!("{}", GovernanceAction::RequireRemediation),
        "require_remediation"
    );
}

// ---------------------------------------------------------------------------
// Serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn gate_report_serde_roundtrip() {
    let config = default_config();
    let addons = vec![addon("test", CohortTier::Medium)];
    let result = evaluate_cohort_gate(&config, &addons, &[], &[], &[], epoch());
    let json = serde_json::to_string(&result).expect("serialize");
    let deser: GateReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deser.overall_verdict, result.overall_verdict);
    assert_eq!(deser.cohort_results.len(), result.cohort_results.len());
}

#[test]
fn config_serde_roundtrip() {
    let config = default_config();
    let json = serde_json::to_string(&config).expect("serialize");
    let deser: GateConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        deser.min_parity_coverage_millionths,
        config.min_parity_coverage_millionths
    );
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let config = GateConfig::default();
    assert_eq!(config.min_parity_coverage_millionths, 800_000);
    assert_eq!(config.max_throughput_regression_millionths, 100_000);
    assert!(config.require_security_audit);
    assert_eq!(config.min_sample_count, 30);
}

// ---------------------------------------------------------------------------
// Multi-addon end-to-end
// ---------------------------------------------------------------------------

#[test]
fn multi_addon_mixed_results() {
    let config = default_config();
    let addons = vec![
        addon("sharp", CohortTier::Critical),
        addon("bcrypt", CohortTier::High),
    ];
    let parity = vec![
        parity_finding("sharp", ParityDimension::ApiSurface, true),
        parity_finding("sharp", ParityDimension::MemorySafety, true),
        parity_finding("bcrypt", ParityDimension::ApiSurface, false),
    ];
    let security = vec![
        security_finding(
            "sharp",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::Secure,
        ),
        security_finding(
            "bcrypt",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::ConditionallySecure,
        ),
    ];
    let throughput = vec![
        throughput_sample("sharp", ThroughputMetric::CallLatency, 1_000_000, 1_000_000),
        throughput_sample(
            "bcrypt",
            ThroughputMetric::CallLatency,
            1_000_000,
            1_050_000,
        ),
    ];
    let result = evaluate_cohort_gate(&config, &addons, &parity, &security, &throughput, epoch());
    assert_eq!(result.total_addons, 2);
}

#[test]
fn addon_descriptor_fields() {
    let a = addon("test-addon", CohortTier::Low);
    assert_eq!(a.name, "test-addon");
    assert_eq!(a.version, "1.0.0");
    assert_eq!(a.tier, CohortTier::Low);
    assert_eq!(a.napi_version, 8);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn module_constants_populated() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert_eq!(BEAD_ID, "bd-1lsy.5.9.3");
    assert_eq!(POLICY_ID, "RGC-407C");
}

// ---------------------------------------------------------------------------
// Evaluate addon
// ---------------------------------------------------------------------------

#[test]
fn evaluate_addon_with_no_evidence() {
    let config = default_config();
    let a = addon("no-evidence", CohortTier::Low);
    let result = evaluate_addon(&a, &[], &[], &[], &config);
    assert_eq!(result.overall_verdict, GateVerdict::InsufficientEvidence);
}

#[test]
fn evaluate_addon_critical_tier_with_vulnerability() {
    let config = default_config();
    let a = addon("vulnerable-addon", CohortTier::Critical);
    let security = vec![security_finding(
        "vulnerable-addon",
        SecurityClass::SandboxEscapePrevention,
        SecurityVerdict::Vulnerable,
    )];
    let result = evaluate_addon(&a, &[], &security, &[], &config);
    assert_eq!(result.security_verdict, SecurityVerdict::Vulnerable);
    assert!(matches!(
        result.governance_action,
        GovernanceAction::BlockAdoption | GovernanceAction::RequireAudit
    ));
}
