//! Integration tests for native_addon_cohort_gate (bd-1lsy.5.9.3 [RGC-407C]).
//!
//! Exercises the native-addon cohort gate through public API entry points.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::native_addon_cohort_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

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

// ---------------------------------------------------------------------------
// Enum serde roundtrips — CohortTier (all variants)
// ---------------------------------------------------------------------------

#[test]
fn serde_cohort_tier_critical() {
    let json = serde_json::to_string(&CohortTier::Critical).unwrap();
    assert_eq!(json, "\"critical\"");
    let parsed: CohortTier = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, CohortTier::Critical);
}

#[test]
fn serde_cohort_tier_high() {
    let json = serde_json::to_string(&CohortTier::High).unwrap();
    assert_eq!(json, "\"high\"");
    let parsed: CohortTier = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, CohortTier::High);
}

#[test]
fn serde_cohort_tier_medium() {
    let json = serde_json::to_string(&CohortTier::Medium).unwrap();
    assert_eq!(json, "\"medium\"");
    let parsed: CohortTier = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, CohortTier::Medium);
}

#[test]
fn serde_cohort_tier_low() {
    let json = serde_json::to_string(&CohortTier::Low).unwrap();
    assert_eq!(json, "\"low\"");
    let parsed: CohortTier = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, CohortTier::Low);
}

#[test]
fn serde_cohort_tier_experimental() {
    let json = serde_json::to_string(&CohortTier::Experimental).unwrap();
    assert_eq!(json, "\"experimental\"");
    let parsed: CohortTier = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, CohortTier::Experimental);
}

#[test]
fn serde_cohort_tier_unknown() {
    let json = serde_json::to_string(&CohortTier::Unknown).unwrap();
    assert_eq!(json, "\"unknown\"");
    let parsed: CohortTier = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, CohortTier::Unknown);
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips — ParityDimension (all variants)
// ---------------------------------------------------------------------------

#[test]
fn serde_parity_dimension_api_surface() {
    let json = serde_json::to_string(&ParityDimension::ApiSurface).unwrap();
    assert_eq!(json, "\"api_surface\"");
    let parsed: ParityDimension = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ParityDimension::ApiSurface);
}

#[test]
fn serde_parity_dimension_memory_safety() {
    let json = serde_json::to_string(&ParityDimension::MemorySafety).unwrap();
    assert_eq!(json, "\"memory_safety\"");
    let parsed: ParityDimension = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ParityDimension::MemorySafety);
}

#[test]
fn serde_parity_dimension_thread_safety() {
    let json = serde_json::to_string(&ParityDimension::ThreadSafety).unwrap();
    assert_eq!(json, "\"thread_safety\"");
    let parsed: ParityDimension = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ParityDimension::ThreadSafety);
}

#[test]
fn serde_parity_dimension_error_semantics() {
    let json = serde_json::to_string(&ParityDimension::ErrorSemantics).unwrap();
    assert_eq!(json, "\"error_semantics\"");
    let parsed: ParityDimension = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ParityDimension::ErrorSemantics);
}

#[test]
fn serde_parity_dimension_lifecycle_compliance() {
    let json = serde_json::to_string(&ParityDimension::LifecycleCompliance).unwrap();
    assert_eq!(json, "\"lifecycle_compliance\"");
    let parsed: ParityDimension = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ParityDimension::LifecycleCompliance);
}

#[test]
fn serde_parity_dimension_abi_stability() {
    let json = serde_json::to_string(&ParityDimension::AbiStability).unwrap();
    assert_eq!(json, "\"abi_stability\"");
    let parsed: ParityDimension = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ParityDimension::AbiStability);
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips — SecurityClass (all variants)
// ---------------------------------------------------------------------------

#[test]
fn serde_security_class_memory_isolation() {
    let json = serde_json::to_string(&SecurityClass::MemoryIsolation).unwrap();
    assert_eq!(json, "\"memory_isolation\"");
    let parsed: SecurityClass = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SecurityClass::MemoryIsolation);
}

#[test]
fn serde_security_class_resource_bounding() {
    let json = serde_json::to_string(&SecurityClass::ResourceBounding).unwrap();
    assert_eq!(json, "\"resource_bounding\"");
    let parsed: SecurityClass = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SecurityClass::ResourceBounding);
}

#[test]
fn serde_security_class_capability_restriction() {
    let json = serde_json::to_string(&SecurityClass::CapabilityRestriction).unwrap();
    assert_eq!(json, "\"capability_restriction\"");
    let parsed: SecurityClass = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SecurityClass::CapabilityRestriction);
}

#[test]
fn serde_security_class_sandbox_escape() {
    let json = serde_json::to_string(&SecurityClass::SandboxEscapePrevention).unwrap();
    assert_eq!(json, "\"sandbox_escape_prevention\"");
    let parsed: SecurityClass = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SecurityClass::SandboxEscapePrevention);
}

#[test]
fn serde_security_class_input_validation() {
    let json = serde_json::to_string(&SecurityClass::InputValidation).unwrap();
    assert_eq!(json, "\"input_validation\"");
    let parsed: SecurityClass = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SecurityClass::InputValidation);
}

#[test]
fn serde_security_class_output_sanitization() {
    let json = serde_json::to_string(&SecurityClass::OutputSanitization).unwrap();
    assert_eq!(json, "\"output_sanitization\"");
    let parsed: SecurityClass = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SecurityClass::OutputSanitization);
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips — ThroughputMetric (all variants)
// ---------------------------------------------------------------------------

#[test]
fn serde_throughput_metric_call_latency() {
    let json = serde_json::to_string(&ThroughputMetric::CallLatency).unwrap();
    assert_eq!(json, "\"call_latency\"");
    let parsed: ThroughputMetric = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ThroughputMetric::CallLatency);
}

#[test]
fn serde_throughput_metric_batch_throughput() {
    let json = serde_json::to_string(&ThroughputMetric::BatchThroughput).unwrap();
    assert_eq!(json, "\"batch_throughput\"");
    let parsed: ThroughputMetric = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ThroughputMetric::BatchThroughput);
}

#[test]
fn serde_throughput_metric_memory_overhead() {
    let json = serde_json::to_string(&ThroughputMetric::MemoryOverhead).unwrap();
    assert_eq!(json, "\"memory_overhead\"");
    let parsed: ThroughputMetric = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ThroughputMetric::MemoryOverhead);
}

#[test]
fn serde_throughput_metric_gc_pressure() {
    let json = serde_json::to_string(&ThroughputMetric::GcPressure).unwrap();
    assert_eq!(json, "\"gc_pressure\"");
    let parsed: ThroughputMetric = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ThroughputMetric::GcPressure);
}

#[test]
fn serde_throughput_metric_context_switch_cost() {
    let json = serde_json::to_string(&ThroughputMetric::ContextSwitchCost).unwrap();
    assert_eq!(json, "\"context_switch_cost\"");
    let parsed: ThroughputMetric = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ThroughputMetric::ContextSwitchCost);
}

#[test]
fn serde_throughput_metric_startup_penalty() {
    let json = serde_json::to_string(&ThroughputMetric::StartupPenalty).unwrap();
    assert_eq!(json, "\"startup_penalty\"");
    let parsed: ThroughputMetric = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ThroughputMetric::StartupPenalty);
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips — GateVerdict (all variants)
// ---------------------------------------------------------------------------

#[test]
fn serde_gate_verdict_pass() {
    let json = serde_json::to_string(&GateVerdict::Pass).unwrap();
    assert_eq!(json, "\"pass\"");
    let parsed: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, GateVerdict::Pass);
}

#[test]
fn serde_gate_verdict_conditional_pass() {
    let json = serde_json::to_string(&GateVerdict::ConditionalPass).unwrap();
    assert_eq!(json, "\"conditional_pass\"");
    let parsed: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, GateVerdict::ConditionalPass);
}

#[test]
fn serde_gate_verdict_fail() {
    let json = serde_json::to_string(&GateVerdict::Fail).unwrap();
    assert_eq!(json, "\"fail\"");
    let parsed: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, GateVerdict::Fail);
}

#[test]
fn serde_gate_verdict_insufficient_evidence() {
    let json = serde_json::to_string(&GateVerdict::InsufficientEvidence).unwrap();
    assert_eq!(json, "\"insufficient_evidence\"");
    let parsed: GateVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, GateVerdict::InsufficientEvidence);
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips — SecurityVerdict (all variants)
// ---------------------------------------------------------------------------

#[test]
fn serde_security_verdict_secure() {
    let json = serde_json::to_string(&SecurityVerdict::Secure).unwrap();
    assert_eq!(json, "\"secure\"");
    let parsed: SecurityVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SecurityVerdict::Secure);
}

#[test]
fn serde_security_verdict_conditionally_secure() {
    let json = serde_json::to_string(&SecurityVerdict::ConditionallySecure).unwrap();
    assert_eq!(json, "\"conditionally_secure\"");
    let parsed: SecurityVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SecurityVerdict::ConditionallySecure);
}

#[test]
fn serde_security_verdict_vulnerable() {
    let json = serde_json::to_string(&SecurityVerdict::Vulnerable).unwrap();
    assert_eq!(json, "\"vulnerable\"");
    let parsed: SecurityVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SecurityVerdict::Vulnerable);
}

#[test]
fn serde_security_verdict_unassessed() {
    let json = serde_json::to_string(&SecurityVerdict::Unassessed).unwrap();
    assert_eq!(json, "\"unassessed\"");
    let parsed: SecurityVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SecurityVerdict::Unassessed);
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips — GovernanceAction (all variants)
// ---------------------------------------------------------------------------

#[test]
fn serde_governance_action_allow_adoption() {
    let json = serde_json::to_string(&GovernanceAction::AllowAdoption).unwrap();
    assert_eq!(json, "\"allow_adoption\"");
    let parsed: GovernanceAction = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, GovernanceAction::AllowAdoption);
}

#[test]
fn serde_governance_action_conditional_adoption() {
    let json = serde_json::to_string(&GovernanceAction::ConditionalAdoption).unwrap();
    assert_eq!(json, "\"conditional_adoption\"");
    let parsed: GovernanceAction = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, GovernanceAction::ConditionalAdoption);
}

#[test]
fn serde_governance_action_block_adoption() {
    let json = serde_json::to_string(&GovernanceAction::BlockAdoption).unwrap();
    assert_eq!(json, "\"block_adoption\"");
    let parsed: GovernanceAction = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, GovernanceAction::BlockAdoption);
}

#[test]
fn serde_governance_action_require_audit() {
    let json = serde_json::to_string(&GovernanceAction::RequireAudit).unwrap();
    assert_eq!(json, "\"require_audit\"");
    let parsed: GovernanceAction = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, GovernanceAction::RequireAudit);
}

#[test]
fn serde_governance_action_downgrade_tier() {
    let json = serde_json::to_string(&GovernanceAction::DowngradeTier).unwrap();
    assert_eq!(json, "\"downgrade_tier\"");
    let parsed: GovernanceAction = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, GovernanceAction::DowngradeTier);
}

#[test]
fn serde_governance_action_require_remediation() {
    let json = serde_json::to_string(&GovernanceAction::RequireRemediation).unwrap();
    assert_eq!(json, "\"require_remediation\"");
    let parsed: GovernanceAction = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, GovernanceAction::RequireRemediation);
}

// ---------------------------------------------------------------------------
// Struct serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn serde_addon_descriptor_roundtrip() {
    let a = AddonDescriptor {
        name: String::from("sharp"),
        version: String::from("0.33.0"),
        tier: CohortTier::Critical,
        napi_version: 9,
        node_api_calls: 127,
        has_worker_threads: true,
        has_async_hooks: true,
    };
    let json = serde_json::to_string(&a).unwrap();
    let deser: AddonDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(deser, a);
}

#[test]
fn serde_parity_finding_roundtrip() {
    let f = parity_finding("test-addon", ParityDimension::ThreadSafety, true);
    let json = serde_json::to_string(&f).unwrap();
    let deser: ParityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(deser, f);
}

#[test]
fn serde_security_finding_roundtrip() {
    let f = security_finding(
        "test-addon",
        SecurityClass::CapabilityRestriction,
        SecurityVerdict::ConditionallySecure,
    );
    let json = serde_json::to_string(&f).unwrap();
    let deser: SecurityFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(deser, f);
}

#[test]
fn serde_throughput_sample_roundtrip() {
    let s = throughput_sample("test-addon", ThroughputMetric::GcPressure, 500_000, 600_000);
    let json = serde_json::to_string(&s).unwrap();
    let deser: ThroughputSample = serde_json::from_str(&json).unwrap();
    assert_eq!(deser, s);
}

#[test]
fn serde_decision_receipt_roundtrip() {
    let r = compute_receipt(
        hash(b"receipt-test"),
        &GateVerdict::ConditionalPass,
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    let deser: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(deser, r);
}

#[test]
fn serde_cohort_result_roundtrip() {
    let config = default_config();
    let a = addon("serde-addon", CohortTier::Medium);
    let parity = vec![parity_finding(
        "serde-addon",
        ParityDimension::ApiSurface,
        true,
    )];
    let result = evaluate_addon(&a, &parity, &[], &[], &config);
    let json = serde_json::to_string(&result).unwrap();
    let deser: CohortResult = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.addon, result.addon);
    assert_eq!(deser.overall_verdict, result.overall_verdict);
    assert_eq!(deser.governance_action, result.governance_action);
}

#[test]
fn serde_gate_report_full_roundtrip() {
    let config = default_config();
    let addons = vec![
        addon("a1", CohortTier::Critical),
        addon("a2", CohortTier::Low),
    ];
    let parity = vec![
        parity_finding("a1", ParityDimension::ApiSurface, true),
        parity_finding("a2", ParityDimension::MemorySafety, false),
    ];
    let security = vec![
        security_finding(
            "a1",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::Secure,
        ),
        security_finding(
            "a2",
            SecurityClass::InputValidation,
            SecurityVerdict::ConditionallySecure,
        ),
    ];
    let throughput = vec![
        throughput_sample("a1", ThroughputMetric::CallLatency, 1_000_000, 1_000_000),
        throughput_sample("a2", ThroughputMetric::MemoryOverhead, 500_000, 700_000),
    ];
    let report = evaluate_cohort_gate(&config, &addons, &parity, &security, &throughput, epoch());
    let json = serde_json::to_string(&report).unwrap();
    let deser: GateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.overall_verdict, report.overall_verdict);
    assert_eq!(deser.total_addons, report.total_addons);
    assert_eq!(deser.passing_addons, report.passing_addons);
    assert_eq!(deser.failing_addons, report.failing_addons);
    assert_eq!(deser.coverage_by_tier.len(), report.coverage_by_tier.len());
}

#[test]
fn serde_gate_config_roundtrip() {
    let config = GateConfig {
        min_parity_coverage_millionths: 900_000,
        max_throughput_regression_millionths: 50_000,
        require_security_audit: false,
        min_sample_count: 100,
        required_tiers: [CohortTier::Critical, CohortTier::High]
            .into_iter()
            .collect(),
    };
    let json = serde_json::to_string(&config).unwrap();
    let deser: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deser, config);
}

// ---------------------------------------------------------------------------
// Display completeness — remaining variants
// ---------------------------------------------------------------------------

#[test]
fn cohort_tier_display_low() {
    assert_eq!(format!("{}", CohortTier::Low), "low");
}

#[test]
fn cohort_tier_display_medium() {
    assert_eq!(format!("{}", CohortTier::Medium), "medium");
}

#[test]
fn cohort_tier_display_unknown() {
    assert_eq!(format!("{}", CohortTier::Unknown), "unknown");
}

#[test]
fn parity_dimension_display_memory_safety() {
    assert_eq!(
        format!("{}", ParityDimension::MemorySafety),
        "memory_safety"
    );
}

#[test]
fn parity_dimension_display_error_semantics() {
    assert_eq!(
        format!("{}", ParityDimension::ErrorSemantics),
        "error_semantics"
    );
}

#[test]
fn parity_dimension_display_lifecycle_compliance() {
    assert_eq!(
        format!("{}", ParityDimension::LifecycleCompliance),
        "lifecycle_compliance"
    );
}

#[test]
fn security_class_display_resource_bounding() {
    assert_eq!(
        format!("{}", SecurityClass::ResourceBounding),
        "resource_bounding"
    );
}

#[test]
fn security_class_display_capability_restriction() {
    assert_eq!(
        format!("{}", SecurityClass::CapabilityRestriction),
        "capability_restriction"
    );
}

#[test]
fn security_class_display_input_validation() {
    assert_eq!(
        format!("{}", SecurityClass::InputValidation),
        "input_validation"
    );
}

#[test]
fn throughput_metric_display_batch_throughput() {
    assert_eq!(
        format!("{}", ThroughputMetric::BatchThroughput),
        "batch_throughput"
    );
}

#[test]
fn throughput_metric_display_memory_overhead() {
    assert_eq!(
        format!("{}", ThroughputMetric::MemoryOverhead),
        "memory_overhead"
    );
}

#[test]
fn throughput_metric_display_context_switch_cost() {
    assert_eq!(
        format!("{}", ThroughputMetric::ContextSwitchCost),
        "context_switch_cost"
    );
}

#[test]
fn gate_verdict_display_insufficient_evidence() {
    assert_eq!(
        format!("{}", GateVerdict::InsufficientEvidence),
        "insufficient_evidence"
    );
}

#[test]
fn security_verdict_display_conditionally_secure() {
    assert_eq!(
        format!("{}", SecurityVerdict::ConditionallySecure),
        "conditionally_secure"
    );
}

#[test]
fn governance_action_display_conditional_adoption() {
    assert_eq!(
        format!("{}", GovernanceAction::ConditionalAdoption),
        "conditional_adoption"
    );
}

#[test]
fn governance_action_display_require_audit() {
    assert_eq!(
        format!("{}", GovernanceAction::RequireAudit),
        "require_audit"
    );
}

#[test]
fn governance_action_display_downgrade_tier() {
    assert_eq!(
        format!("{}", GovernanceAction::DowngradeTier),
        "downgrade_tier"
    );
}

// ---------------------------------------------------------------------------
// ALL constants — exhaustive coverage
// ---------------------------------------------------------------------------

#[test]
fn cohort_tier_all_has_six_variants() {
    assert_eq!(CohortTier::ALL.len(), 6);
    assert_eq!(CohortTier::ALL[0], CohortTier::Critical);
    assert_eq!(CohortTier::ALL[5], CohortTier::Unknown);
}

#[test]
fn parity_dimension_all_has_six_variants() {
    assert_eq!(ParityDimension::ALL.len(), 6);
    assert_eq!(ParityDimension::ALL[0], ParityDimension::ApiSurface);
    assert_eq!(ParityDimension::ALL[5], ParityDimension::AbiStability);
}

#[test]
fn security_class_all_has_six_variants() {
    assert_eq!(SecurityClass::ALL.len(), 6);
    assert_eq!(SecurityClass::ALL[0], SecurityClass::MemoryIsolation);
    assert_eq!(SecurityClass::ALL[5], SecurityClass::OutputSanitization);
}

#[test]
fn throughput_metric_all_has_six_variants() {
    assert_eq!(ThroughputMetric::ALL.len(), 6);
    assert_eq!(ThroughputMetric::ALL[0], ThroughputMetric::CallLatency);
    assert_eq!(ThroughputMetric::ALL[5], ThroughputMetric::StartupPenalty);
}

// ---------------------------------------------------------------------------
// GateVerdict::is_adoptable
// ---------------------------------------------------------------------------

#[test]
fn gate_verdict_pass_is_adoptable() {
    assert!(GateVerdict::Pass.is_adoptable());
}

#[test]
fn gate_verdict_conditional_pass_is_adoptable() {
    assert!(GateVerdict::ConditionalPass.is_adoptable());
}

#[test]
fn gate_verdict_fail_is_not_adoptable() {
    assert!(!GateVerdict::Fail.is_adoptable());
}

#[test]
fn gate_verdict_insufficient_evidence_is_not_adoptable() {
    assert!(!GateVerdict::InsufficientEvidence.is_adoptable());
}

// ---------------------------------------------------------------------------
// Governance action edge cases
// ---------------------------------------------------------------------------

#[test]
fn governance_vulnerable_medium_remediates() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Vulnerable,
        &CohortTier::Medium,
    );
    assert_eq!(action, GovernanceAction::RequireRemediation);
}

#[test]
fn governance_vulnerable_experimental_remediates() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Vulnerable,
        &CohortTier::Experimental,
    );
    assert_eq!(action, GovernanceAction::RequireRemediation);
}

#[test]
fn governance_vulnerable_unknown_remediates() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Vulnerable,
        &CohortTier::Unknown,
    );
    assert_eq!(action, GovernanceAction::RequireRemediation);
}

#[test]
fn governance_vulnerable_high_blocks() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Vulnerable,
        &CohortTier::High,
    );
    assert_eq!(action, GovernanceAction::BlockAdoption);
}

#[test]
fn governance_unassessed_critical_requires_audit() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Unassessed,
        &CohortTier::Critical,
    );
    assert_eq!(action, GovernanceAction::RequireAudit);
}

#[test]
fn governance_unassessed_medium_not_blocked() {
    // Unassessed on medium/low/experimental: falls through to match on overall
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Unassessed,
        &CohortTier::Medium,
    );
    // Unassessed medium with Pass overall => AllowAdoption (unassessed check only for critical/high)
    assert_eq!(action, GovernanceAction::AllowAdoption);
}

#[test]
fn governance_fail_high_blocks() {
    let action = derive_governance_action(
        &GateVerdict::Fail,
        &SecurityVerdict::Secure,
        &CohortTier::High,
    );
    assert_eq!(action, GovernanceAction::BlockAdoption);
}

#[test]
fn governance_fail_unknown_downgrades() {
    let action = derive_governance_action(
        &GateVerdict::Fail,
        &SecurityVerdict::Secure,
        &CohortTier::Unknown,
    );
    assert_eq!(action, GovernanceAction::DowngradeTier);
}

#[test]
fn governance_fail_low_downgrades() {
    let action = derive_governance_action(
        &GateVerdict::Fail,
        &SecurityVerdict::Secure,
        &CohortTier::Low,
    );
    assert_eq!(action, GovernanceAction::DowngradeTier);
}

#[test]
fn governance_fail_experimental_downgrades() {
    let action = derive_governance_action(
        &GateVerdict::Fail,
        &SecurityVerdict::Secure,
        &CohortTier::Experimental,
    );
    assert_eq!(action, GovernanceAction::DowngradeTier);
}

#[test]
fn governance_insufficient_low_conditional() {
    let action = derive_governance_action(
        &GateVerdict::InsufficientEvidence,
        &SecurityVerdict::Secure,
        &CohortTier::Low,
    );
    assert_eq!(action, GovernanceAction::ConditionalAdoption);
}

#[test]
fn governance_insufficient_high_audit() {
    let action = derive_governance_action(
        &GateVerdict::InsufficientEvidence,
        &SecurityVerdict::Secure,
        &CohortTier::High,
    );
    assert_eq!(action, GovernanceAction::RequireAudit);
}

#[test]
fn governance_pass_secure_low_allows() {
    let action = derive_governance_action(
        &GateVerdict::Pass,
        &SecurityVerdict::Secure,
        &CohortTier::Low,
    );
    assert_eq!(action, GovernanceAction::AllowAdoption);
}

#[test]
fn governance_conditional_pass_secure_experimental() {
    let action = derive_governance_action(
        &GateVerdict::ConditionalPass,
        &SecurityVerdict::Secure,
        &CohortTier::Experimental,
    );
    assert_eq!(action, GovernanceAction::ConditionalAdoption);
}

#[test]
fn governance_fail_medium_remediates() {
    let action = derive_governance_action(
        &GateVerdict::Fail,
        &SecurityVerdict::Secure,
        &CohortTier::Medium,
    );
    assert_eq!(action, GovernanceAction::RequireRemediation);
}

// ---------------------------------------------------------------------------
// Throughput edge cases
// ---------------------------------------------------------------------------

#[test]
fn throughput_zero_baseline_skipped_no_regression() {
    let samples = vec![throughput_sample(
        "zero-base",
        ThroughputMetric::BatchThroughput,
        0,
        5_000_000,
    )];
    let verdict = compute_throughput_verdict(&samples, 100_000, 30);
    // Zero baseline is skipped, so no regression detected => Pass
    assert_eq!(verdict, GateVerdict::Pass);
}

#[test]
fn throughput_candidate_better_than_baseline() {
    let samples = vec![throughput_sample(
        "faster",
        ThroughputMetric::CallLatency,
        1_000_000,
        800_000,
    )];
    let verdict = compute_throughput_verdict(&samples, 100_000, 30);
    assert_eq!(verdict, GateVerdict::Pass);
}

#[test]
fn throughput_exactly_at_threshold_conditional() {
    // 10% regression at exactly 10% threshold
    let samples = vec![throughput_sample(
        "exact",
        ThroughputMetric::CallLatency,
        1_000_000,
        1_100_000,
    )];
    let verdict = compute_throughput_verdict(&samples, 100_000, 30);
    // regression = 100_000, threshold = 100_000, not > threshold => conditional
    assert_eq!(verdict, GateVerdict::ConditionalPass);
}

#[test]
fn throughput_multiple_metrics_worst_wins() {
    let samples = vec![
        throughput_sample("multi", ThroughputMetric::CallLatency, 1_000_000, 1_000_000),
        throughput_sample(
            "multi",
            ThroughputMetric::MemoryOverhead,
            1_000_000,
            1_300_000,
        ),
    ];
    let verdict = compute_throughput_verdict(&samples, 100_000, 30);
    // Second metric has 30% regression, exceeds threshold => Fail
    assert_eq!(verdict, GateVerdict::Fail);
}

#[test]
fn throughput_conditional_range() {
    // 7% regression: above half-threshold (5%) but below full threshold (10%)
    let samples = vec![throughput_sample(
        "mid",
        ThroughputMetric::StartupPenalty,
        1_000_000,
        1_070_000,
    )];
    let verdict = compute_throughput_verdict(&samples, 100_000, 30);
    assert_eq!(verdict, GateVerdict::ConditionalPass);
}

// ---------------------------------------------------------------------------
// Parity boundary conditions
// ---------------------------------------------------------------------------

#[test]
fn parity_single_achieved_at_100_percent_threshold_passes() {
    let findings = vec![parity_finding("x", ParityDimension::AbiStability, true)];
    let verdict = compute_parity_verdict(&findings, 1_000_000);
    assert_eq!(verdict, GateVerdict::Pass);
}

#[test]
fn parity_single_not_achieved_at_high_threshold_fails() {
    let findings = vec![parity_finding("x", ParityDimension::AbiStability, false)];
    let verdict = compute_parity_verdict(&findings, 800_000);
    assert_eq!(verdict, GateVerdict::Fail);
}

#[test]
fn parity_half_achieved_conditional() {
    // 3 of 6 = 500_000. Half of 800_000 = 400_000. 500_000 >= 400_000 => ConditionalPass
    let findings = vec![
        parity_finding("a", ParityDimension::ApiSurface, true),
        parity_finding("a", ParityDimension::MemorySafety, true),
        parity_finding("a", ParityDimension::ThreadSafety, true),
        parity_finding("a", ParityDimension::ErrorSemantics, false),
        parity_finding("a", ParityDimension::LifecycleCompliance, false),
        parity_finding("a", ParityDimension::AbiStability, false),
    ];
    let verdict = compute_parity_verdict(&findings, 800_000);
    assert_eq!(verdict, GateVerdict::ConditionalPass);
}

#[test]
fn parity_one_of_six_fails() {
    // 1 of 6 = 166_666. Half of 800_000 = 400_000. 166_666 < 400_000 => Fail
    let findings = vec![
        parity_finding("a", ParityDimension::ApiSurface, true),
        parity_finding("a", ParityDimension::MemorySafety, false),
        parity_finding("a", ParityDimension::ThreadSafety, false),
        parity_finding("a", ParityDimension::ErrorSemantics, false),
        parity_finding("a", ParityDimension::LifecycleCompliance, false),
        parity_finding("a", ParityDimension::AbiStability, false),
    ];
    let verdict = compute_parity_verdict(&findings, 800_000);
    assert_eq!(verdict, GateVerdict::Fail);
}

// ---------------------------------------------------------------------------
// Security verdict edge cases
// ---------------------------------------------------------------------------

#[test]
fn security_mixed_secure_and_unassessed() {
    let findings = vec![
        security_finding("a", SecurityClass::MemoryIsolation, SecurityVerdict::Secure),
        security_finding(
            "a",
            SecurityClass::ResourceBounding,
            SecurityVerdict::Unassessed,
        ),
    ];
    let verdict = compute_security_verdict(&findings);
    assert_eq!(verdict, SecurityVerdict::Unassessed);
}

#[test]
fn security_vulnerable_trumps_conditional() {
    let findings = vec![
        security_finding(
            "a",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::ConditionallySecure,
        ),
        security_finding(
            "a",
            SecurityClass::InputValidation,
            SecurityVerdict::Vulnerable,
        ),
    ];
    let verdict = compute_security_verdict(&findings);
    assert_eq!(verdict, SecurityVerdict::Vulnerable);
}

#[test]
fn security_all_conditionally_secure() {
    let findings = vec![
        security_finding(
            "a",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::ConditionallySecure,
        ),
        security_finding(
            "a",
            SecurityClass::ResourceBounding,
            SecurityVerdict::ConditionallySecure,
        ),
    ];
    let verdict = compute_security_verdict(&findings);
    assert_eq!(verdict, SecurityVerdict::ConditionallySecure);
}

#[test]
fn security_conditional_trumps_unassessed() {
    let findings = vec![
        security_finding(
            "a",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::ConditionallySecure,
        ),
        security_finding(
            "a",
            SecurityClass::ResourceBounding,
            SecurityVerdict::Unassessed,
        ),
    ];
    let verdict = compute_security_verdict(&findings);
    // Conditional check comes before unassessed check in the implementation
    assert_eq!(verdict, SecurityVerdict::ConditionallySecure);
}

// ---------------------------------------------------------------------------
// evaluate_addon: addon name filtering
// ---------------------------------------------------------------------------

#[test]
fn evaluate_addon_filters_by_name() {
    let config = default_config();
    let a = addon("target", CohortTier::Medium);
    let parity = vec![
        parity_finding("target", ParityDimension::ApiSurface, true),
        parity_finding("other", ParityDimension::ApiSurface, false),
    ];
    let security = vec![
        security_finding(
            "target",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::Secure,
        ),
        security_finding(
            "other",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::Vulnerable,
        ),
    ];
    let throughput = vec![
        throughput_sample(
            "target",
            ThroughputMetric::CallLatency,
            1_000_000,
            1_000_000,
        ),
        throughput_sample("other", ThroughputMetric::CallLatency, 1_000_000, 2_000_000),
    ];
    let result = evaluate_addon(&a, &parity, &security, &throughput, &config);
    // Only "target" findings should be counted
    assert_eq!(result.parity_findings.len(), 1);
    assert_eq!(result.security_findings.len(), 1);
    assert_eq!(result.throughput_samples.len(), 1);
    assert_eq!(result.security_verdict, SecurityVerdict::Secure);
}

// ---------------------------------------------------------------------------
// Receipt edge cases
// ---------------------------------------------------------------------------

#[test]
fn receipt_different_input_hashes_differ() {
    let r1 = compute_receipt(hash(b"input-a"), &GateVerdict::Pass, epoch());
    let r2 = compute_receipt(hash(b"input-b"), &GateVerdict::Pass, epoch());
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_different_epochs_differ() {
    let r1 = compute_receipt(
        hash(b"same"),
        &GateVerdict::Pass,
        SecurityEpoch::from_raw(1),
    );
    let r2 = compute_receipt(
        hash(b"same"),
        &GateVerdict::Pass,
        SecurityEpoch::from_raw(2),
    );
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_conditional_pass_vs_pass_differ() {
    let r1 = compute_receipt(hash(b"same"), &GateVerdict::Pass, epoch());
    let r2 = compute_receipt(hash(b"same"), &GateVerdict::ConditionalPass, epoch());
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_timestamp_is_zero() {
    let r = compute_receipt(hash(b"ts"), &GateVerdict::Pass, epoch());
    assert_eq!(r.timestamp_micros, 0);
}

// ---------------------------------------------------------------------------
// Config custom values
// ---------------------------------------------------------------------------

#[test]
fn config_custom_parity_threshold() {
    let config = GateConfig {
        min_parity_coverage_millionths: 500_000,
        ..GateConfig::default()
    };
    // 3 of 6 = 500_000 which meets the lowered threshold
    let findings = vec![
        parity_finding("a", ParityDimension::ApiSurface, true),
        parity_finding("a", ParityDimension::MemorySafety, true),
        parity_finding("a", ParityDimension::ThreadSafety, true),
        parity_finding("a", ParityDimension::ErrorSemantics, false),
        parity_finding("a", ParityDimension::LifecycleCompliance, false),
        parity_finding("a", ParityDimension::AbiStability, false),
    ];
    let verdict = compute_parity_verdict(&findings, config.min_parity_coverage_millionths);
    assert_eq!(verdict, GateVerdict::Pass);
}

#[test]
fn config_custom_throughput_threshold() {
    let config = GateConfig {
        max_throughput_regression_millionths: 200_000,
        ..GateConfig::default()
    };
    // 15% regression which would fail at default 10% but passes at custom 20%
    let samples = vec![throughput_sample(
        "a",
        ThroughputMetric::CallLatency,
        1_000_000,
        1_150_000,
    )];
    let verdict = compute_throughput_verdict(
        &samples,
        config.max_throughput_regression_millionths,
        config.min_sample_count,
    );
    assert_eq!(verdict, GateVerdict::ConditionalPass);
}

#[test]
fn config_custom_min_sample_count() {
    let config = GateConfig {
        min_sample_count: 10,
        ..GateConfig::default()
    };
    // 15 samples: insufficient at default 30 but sufficient at custom 10
    let samples = vec![ThroughputSample {
        metric: ThroughputMetric::CallLatency,
        addon_name: String::from("a"),
        baseline_millionths: 1_000_000,
        candidate_millionths: 1_000_000,
        sample_count: 15,
        epoch: epoch(),
    }];
    let verdict = compute_throughput_verdict(
        &samples,
        config.max_throughput_regression_millionths,
        config.min_sample_count,
    );
    assert_eq!(verdict, GateVerdict::Pass);
}

#[test]
fn config_required_tiers_field() {
    let mut config = GateConfig::default();
    assert!(config.required_tiers.is_empty());
    config.required_tiers.insert(CohortTier::Critical);
    config.required_tiers.insert(CohortTier::High);
    assert_eq!(config.required_tiers.len(), 2);
    assert!(config.required_tiers.contains(&CohortTier::Critical));
    assert!(config.required_tiers.contains(&CohortTier::High));
}

// ---------------------------------------------------------------------------
// Tier coverage edge cases
// ---------------------------------------------------------------------------

#[test]
fn tier_coverage_empty_results_vec() {
    let coverage = compute_tier_coverage(&[]);
    assert!(coverage.is_empty());
}

#[test]
fn tier_coverage_multiple_tiers_sorted() {
    let config = default_config();
    let a1 = addon("crit", CohortTier::Critical);
    let a2 = addon("med", CohortTier::Medium);
    let a3 = addon("low", CohortTier::Low);
    let r1 = evaluate_addon(&a1, &[], &[], &[], &config);
    let r2 = evaluate_addon(&a2, &[], &[], &[], &config);
    let r3 = evaluate_addon(&a3, &[], &[], &[], &config);
    let coverage = compute_tier_coverage(&[r1, r2, r3]);
    assert_eq!(coverage.len(), 3);
    // Should be sorted by tier (Critical < Medium < Low in Ord)
    assert_eq!(coverage[0].0, CohortTier::Critical);
}

// ---------------------------------------------------------------------------
// evaluate_cohort_gate: cohort-level aggregation
// ---------------------------------------------------------------------------

#[test]
fn cohort_all_insufficient_yields_insufficient() {
    let config = default_config();
    let addons = vec![
        addon("a1", CohortTier::Medium),
        addon("a2", CohortTier::Low),
    ];
    let result = evaluate_cohort_gate(&config, &addons, &[], &[], &[], epoch());
    // All addons have no evidence => none pass => InsufficientEvidence overall
    assert_eq!(result.overall_verdict, GateVerdict::InsufficientEvidence);
    assert_eq!(result.passing_addons, 0);
}

#[test]
fn cohort_critical_fail_propagates_even_if_others_pass() {
    let config = default_config();
    let addons = vec![
        addon("good-med", CohortTier::Medium),
        addon("bad-crit", CohortTier::Critical),
    ];
    // good-med: all passing parity, security, throughput
    let parity: Vec<ParityFinding> = ParityDimension::ALL
        .iter()
        .map(|d| parity_finding("good-med", *d, true))
        .collect();
    let security = vec![security_finding(
        "good-med",
        SecurityClass::MemoryIsolation,
        SecurityVerdict::Secure,
    )];
    let throughput = vec![throughput_sample(
        "good-med",
        ThroughputMetric::CallLatency,
        1_000_000,
        1_000_000,
    )];
    // bad-crit: security vulnerable
    let mut all_security = security;
    all_security.push(security_finding(
        "bad-crit",
        SecurityClass::MemoryIsolation,
        SecurityVerdict::Vulnerable,
    ));
    let result = evaluate_cohort_gate(
        &config,
        &addons,
        &parity,
        &all_security,
        &throughput,
        epoch(),
    );
    assert_eq!(result.overall_verdict, GateVerdict::Fail);
}

#[test]
fn cohort_non_critical_fail_yields_conditional() {
    let config = default_config();
    let addons = vec![addon("failing-low", CohortTier::Low)];
    // Parity all failing
    let parity: Vec<ParityFinding> = ParityDimension::ALL
        .iter()
        .map(|d| parity_finding("failing-low", *d, false))
        .collect();
    let security = vec![security_finding(
        "failing-low",
        SecurityClass::MemoryIsolation,
        SecurityVerdict::Secure,
    )];
    let throughput = vec![throughput_sample(
        "failing-low",
        ThroughputMetric::CallLatency,
        1_000_000,
        1_000_000,
    )];
    let result = evaluate_cohort_gate(&config, &addons, &parity, &security, &throughput, epoch());
    // Low tier failure => ConditionalPass at cohort level (not critical/high)
    assert_eq!(result.overall_verdict, GateVerdict::ConditionalPass);
    assert_eq!(result.failing_addons, 1);
}

// ---------------------------------------------------------------------------
// AddonDescriptor edge cases
// ---------------------------------------------------------------------------

#[test]
fn addon_descriptor_with_worker_threads_and_async_hooks() {
    let a = AddonDescriptor {
        name: String::from("complex-addon"),
        version: String::from("2.0.0-beta.1"),
        tier: CohortTier::Experimental,
        napi_version: 10,
        node_api_calls: 200,
        has_worker_threads: true,
        has_async_hooks: true,
    };
    assert!(a.has_worker_threads);
    assert!(a.has_async_hooks);
    assert_eq!(a.napi_version, 10);
    assert_eq!(a.node_api_calls, 200);
    assert_eq!(a.tier, CohortTier::Experimental);
}

#[test]
fn addon_descriptor_clone() {
    let a = addon("clone-test", CohortTier::High);
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.name, b.name);
    assert_eq!(a.tier, b.tier);
}

#[test]
fn addon_descriptor_debug() {
    let a = addon("debug-test", CohortTier::Low);
    let debug = format!("{:?}", a);
    assert!(debug.contains("debug-test"));
    assert!(debug.contains("Low"));
}

// ---------------------------------------------------------------------------
// Struct field coverage
// ---------------------------------------------------------------------------

#[test]
fn parity_finding_field_coverage() {
    let f = ParityFinding {
        dimension: ParityDimension::ErrorSemantics,
        addon_name: String::from("field-test"),
        is_parity_achieved: false,
        divergence_count: 42,
        total_checks: 100,
        detail: String::from("detailed finding"),
    };
    assert_eq!(f.dimension, ParityDimension::ErrorSemantics);
    assert_eq!(f.addon_name, "field-test");
    assert!(!f.is_parity_achieved);
    assert_eq!(f.divergence_count, 42);
    assert_eq!(f.total_checks, 100);
    assert_eq!(f.detail, "detailed finding");
}

#[test]
fn security_finding_field_coverage() {
    let h = hash(b"evidence-data");
    let f = SecurityFinding {
        class: SecurityClass::SandboxEscapePrevention,
        addon_name: String::from("sec-test"),
        verdict: SecurityVerdict::Vulnerable,
        vulnerability_count: 7,
        detail: String::from("sandbox escape detected"),
        content_hash: h,
    };
    assert_eq!(f.class, SecurityClass::SandboxEscapePrevention);
    assert_eq!(f.addon_name, "sec-test");
    assert_eq!(f.verdict, SecurityVerdict::Vulnerable);
    assert_eq!(f.vulnerability_count, 7);
    assert_eq!(f.content_hash, h);
}

#[test]
fn throughput_sample_field_coverage() {
    let s = ThroughputSample {
        metric: ThroughputMetric::ContextSwitchCost,
        addon_name: String::from("tput-test"),
        baseline_millionths: 250_000,
        candidate_millionths: 275_000,
        sample_count: 100,
        epoch: SecurityEpoch::from_raw(42),
    };
    assert_eq!(s.metric, ThroughputMetric::ContextSwitchCost);
    assert_eq!(s.addon_name, "tput-test");
    assert_eq!(s.baseline_millionths, 250_000);
    assert_eq!(s.candidate_millionths, 275_000);
    assert_eq!(s.sample_count, 100);
    assert_eq!(s.epoch, SecurityEpoch::from_raw(42));
}

#[test]
fn cohort_result_subverdicts_populated() {
    let config = default_config();
    let a = addon("sub-v", CohortTier::High);
    let parity: Vec<ParityFinding> = ParityDimension::ALL
        .iter()
        .map(|d| parity_finding("sub-v", *d, true))
        .collect();
    let security = vec![security_finding(
        "sub-v",
        SecurityClass::MemoryIsolation,
        SecurityVerdict::Secure,
    )];
    let throughput = vec![throughput_sample(
        "sub-v",
        ThroughputMetric::CallLatency,
        1_000_000,
        1_000_000,
    )];
    let result = evaluate_addon(&a, &parity, &security, &throughput, &config);
    assert_eq!(result.parity_verdict, GateVerdict::Pass);
    assert_eq!(result.security_verdict, SecurityVerdict::Secure);
    assert_eq!(result.throughput_verdict, GateVerdict::Pass);
    assert_eq!(result.overall_verdict, GateVerdict::Pass);
    assert_eq!(result.governance_action, GovernanceAction::AllowAdoption);
    assert_eq!(result.addon.name, "sub-v");
}

// ---------------------------------------------------------------------------
// GateReport field coverage
// ---------------------------------------------------------------------------

#[test]
fn gate_report_coverage_by_tier_populated() {
    let config = default_config();
    let addons = vec![
        addon("ct-a", CohortTier::Critical),
        addon("ct-b", CohortTier::High),
        addon("ct-c", CohortTier::Medium),
    ];
    let result = evaluate_cohort_gate(&config, &addons, &[], &[], &[], epoch());
    assert_eq!(result.total_addons, 3);
    assert!(!result.coverage_by_tier.is_empty());
}

#[test]
fn gate_report_receipt_has_correct_epoch() {
    let e = SecurityEpoch::from_raw(99);
    let config = default_config();
    let addons = vec![addon("ep-test", CohortTier::Low)];
    let result = evaluate_cohort_gate(&config, &addons, &[], &[], &[], e);
    assert_eq!(result.receipt.epoch, e);
}

#[test]
fn gate_report_empty_cohort_receipt() {
    let config = default_config();
    let result = evaluate_cohort_gate(&config, &[], &[], &[], &[], epoch());
    assert_eq!(result.receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(result.receipt.component, COMPONENT);
    assert_eq!(result.receipt.bead_id, BEAD_ID);
    assert_eq!(result.receipt.policy_id, POLICY_ID);
    assert_eq!(result.governance_action, GovernanceAction::RequireAudit);
}

// ---------------------------------------------------------------------------
// Debug trait checks
// ---------------------------------------------------------------------------

#[test]
fn gate_config_debug() {
    let config = default_config();
    let debug = format!("{:?}", config);
    assert!(debug.contains("GateConfig"));
    assert!(debug.contains("800000"));
}

#[test]
fn gate_verdict_debug() {
    let debug = format!("{:?}", GateVerdict::ConditionalPass);
    assert_eq!(debug, "ConditionalPass");
}

#[test]
fn security_verdict_debug() {
    let debug = format!("{:?}", SecurityVerdict::ConditionallySecure);
    assert_eq!(debug, "ConditionallySecure");
}

#[test]
fn governance_action_debug() {
    let debug = format!("{:?}", GovernanceAction::DowngradeTier);
    assert_eq!(debug, "DowngradeTier");
}

#[test]
fn decision_receipt_debug() {
    let r = compute_receipt(hash(b"debug"), &GateVerdict::Pass, epoch());
    let debug = format!("{:?}", r);
    assert!(debug.contains("DecisionReceipt"));
}

#[test]
fn gate_report_debug() {
    let config = default_config();
    let addons = vec![addon("dbg", CohortTier::Low)];
    let report = evaluate_cohort_gate(&config, &addons, &[], &[], &[], epoch());
    let debug = format!("{:?}", report);
    assert!(debug.contains("GateReport"));
}
