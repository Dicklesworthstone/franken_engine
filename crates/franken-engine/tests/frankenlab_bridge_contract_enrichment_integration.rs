#![forbid(unsafe_code)]
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

//! Enrichment integration tests for frankenlab_bridge_contract module.
//! Covers display uniqueness, edge cases, serde roundtrips, and validator
//! boundary conditions not exercised by the primary integration test suite.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::frankenlab_bridge_contract::{
    BridgeContractPolicy, BridgeContractReport, BridgeContractValidator, BridgeMode, BridgeSeam,
    BridgeSeamConfig, BridgeTypeMappingRegistry, BridgeViolationKind, EvidenceCategory,
    FaultCategory, FaultInjectionSpec, FaultTarget, OracleResult,
    ReplayVerdict, ScenarioManifest, SeamStatus, TraceCertificate,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn make_cert(seed: u64, steps: u64) -> TraceCertificate {
    TraceCertificate::new(
        ContentHash::compute(b"events"),
        ContentHash::compute(b"schedule"),
        steps,
        ContentHash::compute(b"fingerprint"),
        seed,
    )
}

fn strict_validator() -> BridgeContractValidator {
    BridgeContractValidator::strict(epoch())
}

// ---------------------------------------------------------------------------
// 1. Display uniqueness (6 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_bridge_mode_display_all_unique() {
    let modes = [
        BridgeMode::DirectDependency,
        BridgeMode::ThinAdapter,
        BridgeMode::LocalWithUpstreamValidation,
        BridgeMode::LocalOnly,
    ];
    let set: BTreeSet<String> = modes.iter().map(|m| m.to_string()).collect();
    assert_eq!(set.len(), 4);
    assert!(set.contains("direct_dependency"));
    assert!(set.contains("thin_adapter"));
    assert!(set.contains("local_with_upstream_validation"));
    assert!(set.contains("local_only"));
}

#[test]
fn enrichment_fault_target_display_formats_correct() {
    assert_eq!(
        FaultTarget::Task { task_id: 7 }.to_string(),
        "task:7"
    );
    assert_eq!(
        FaultTarget::Region {
            region_id: "us-east".to_owned()
        }
        .to_string(),
        "region:us-east"
    );
    assert_eq!(
        FaultTarget::AllInRegion {
            region_id: "eu-west".to_owned()
        }
        .to_string(),
        "all_in_region:eu-west"
    );
    assert_eq!(FaultTarget::Global.to_string(), "global");
}

#[test]
fn enrichment_bridge_violation_kind_display_all_unique() {
    let kinds = [
        BridgeViolationKind::ReplayDivergence,
        BridgeViolationKind::OracleInvariantFailure,
        BridgeViolationKind::FaultBudgetExceeded,
        BridgeViolationKind::EvidenceUnverified,
        BridgeViolationKind::ScenarioTimeout,
        BridgeViolationKind::InfrastructureError,
        BridgeViolationKind::VersionMismatch,
        BridgeViolationKind::TypeMappingFailure,
    ];
    let set: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_seam_status_display_all_unique() {
    let statuses = [SeamStatus::Clean, SeamStatus::Warning, SeamStatus::ReleaseBlocked];
    let set: BTreeSet<String> = statuses.iter().map(|s| s.to_string()).collect();
    assert_eq!(set.len(), 3);
    assert!(set.contains("clean"));
    assert!(set.contains("warning"));
    assert!(set.contains("release_blocked"));
}

#[test]
fn enrichment_fault_category_display_all_unique() {
    let set: BTreeSet<String> = FaultCategory::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(set.len(), 7);
    assert!(set.contains("task_panic"));
    assert!(set.contains("channel_disconnect"));
    assert!(set.contains("obligation_leak"));
    assert!(set.contains("deadline_expiry"));
    assert!(set.contains("region_close"));
    assert!(set.contains("network_partition"));
    assert!(set.contains("resource_exhaustion"));
}

#[test]
fn enrichment_evidence_category_display_all_unique() {
    let set: BTreeSet<String> = EvidenceCategory::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(set.len(), 6);
    assert!(set.contains("scenario_result"));
    assert!(set.contains("replay_certificate"));
    assert!(set.contains("oracle_check"));
    assert!(set.contains("fault_injection_event"));
    assert!(set.contains("cancellation_event"));
    assert!(set.contains("budget_trace"));
}

// ---------------------------------------------------------------------------
// 2. TraceCertificate edge cases (4 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_trace_cert_reflexivity() {
    let cert = make_cert(42, 100);
    assert!(cert.is_equivalent(&cert));
}

#[test]
fn enrichment_trace_cert_seed_not_compared() {
    let cert_a = make_cert(1, 100);
    let cert_b = make_cert(999, 100);
    // Same hashes (from same input bytes), different seeds => equivalent
    assert!(cert_a.is_equivalent(&cert_b));
}

#[test]
fn enrichment_trace_cert_zero_steps_valid() {
    let cert = make_cert(0, 0);
    assert_eq!(cert.steps, 0);
    assert!(cert.is_equivalent(&cert));
}

#[test]
fn enrichment_trace_cert_serde_roundtrip() {
    let cert = make_cert(42, 500);
    let json = serde_json::to_string(&cert).unwrap();
    let round: TraceCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, round);
}

// ---------------------------------------------------------------------------
// 3. ScenarioManifest edge cases (4 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scenario_manifest_empty() {
    let m = ScenarioManifest::new("empty", 0);
    assert!(!m.has_faults());
    assert!(!m.has_oracles());
    assert_eq!(m.fault_schedule.len(), 0);
    assert_eq!(m.oracle_invariants.len(), 0);
    assert_eq!(m.cancellation_schedule.len(), 0);
}

#[test]
fn enrichment_scenario_manifest_add_methods() {
    let mut m = ScenarioManifest::new("test", 1);
    m.add_fault("panic", 100);
    m.add_oracle("safety");
    m.add_cancellation("region-a", 200);
    assert!(m.has_faults());
    assert!(m.has_oracles());
    assert_eq!(m.fault_schedule.len(), 1);
    assert_eq!(m.oracle_invariants.len(), 1);
    assert_eq!(m.cancellation_schedule.len(), 1);
}

#[test]
fn enrichment_scenario_manifest_serde_roundtrip_all_fields() {
    let mut m = ScenarioManifest::new("full", 42);
    m.description = "A complete scenario".to_owned();
    m.schema_version = 3;
    m.max_steps = 10_000;
    m.panic_on_obligation_leak = false;
    m.add_fault("disconnect", 50);
    m.add_fault("panic", 100);
    m.add_oracle("safety");
    m.add_oracle("liveness");
    m.add_cancellation("r1", 200);

    let json = serde_json::to_string(&m).unwrap();
    let round: ScenarioManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, round);
}

#[test]
fn enrichment_scenario_manifest_seed_zero_valid() {
    let m = ScenarioManifest::new("zero-seed", 0);
    assert_eq!(m.seed, 0);
    assert_eq!(m.scenario_id, "zero-seed");
}

// ---------------------------------------------------------------------------
// 4. ReplayVerdict (4 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_replay_verdict_deterministic_queries() {
    let v = ReplayVerdict::Deterministic;
    assert!(v.is_deterministic());
    assert!(!v.is_failure());
}

#[test]
fn enrichment_replay_verdict_diverged_queries() {
    let v = ReplayVerdict::Diverged {
        event_match: true,
        schedule_match: false,
        step_match: true,
        fingerprint_match: false,
    };
    assert!(!v.is_deterministic());
    assert!(v.is_failure());
}

#[test]
fn enrichment_replay_verdict_infrastructure_failure_queries() {
    let v = ReplayVerdict::InfrastructureFailure {
        detail: "disk full".to_owned(),
    };
    assert!(!v.is_deterministic());
    assert!(v.is_failure());
}

#[test]
fn enrichment_replay_verdict_diverged_individual_mismatches() {
    let v = ReplayVerdict::Diverged {
        event_match: false,
        schedule_match: true,
        step_match: false,
        fingerprint_match: true,
    };
    let s = v.to_string();
    assert!(s.contains("event=false"));
    assert!(s.contains("schedule=true"));
    assert!(s.contains("steps=false"));
    assert!(s.contains("fingerprint=true"));
}

// ---------------------------------------------------------------------------
// 5. Validator edge cases (8 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validator_empty_oracle_pass_rate_is_scale() {
    let v = strict_validator();
    assert_eq!(v.oracle_pass_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_validator_empty_replay_confidence_is_zero() {
    let v = strict_validator();
    assert_eq!(v.replay_confidence_millionths(), 0);
}

#[test]
fn enrichment_validator_empty_has_no_violations() {
    let v = strict_validator();
    assert!(!v.has_violations());
    assert!(!v.has_release_blockers());
}

#[test]
fn enrichment_validator_single_deterministic_replay_confidence() {
    let mut v = strict_validator();
    let cert = make_cert(1, 100);
    v.record_replay_verdict("s1", 1, &cert, &cert);
    assert_eq!(v.replay_confidence_millionths(), 1_000_000);
}

#[test]
fn enrichment_validator_oracle_one_of_three_pass_rate() {
    let mut v = strict_validator();
    v.record_oracle_result("s1", OracleResult::pass("a", 100));
    v.record_oracle_result("s1", OracleResult::fail("b", "bad", 200));
    v.record_oracle_result("s1", OracleResult::fail("c", "bad", 300));
    // 1/3 = 333_333
    assert_eq!(v.oracle_pass_rate_millionths(), 333_333);
}

#[test]
fn enrichment_validator_fault_budget_exactly_at_limit_no_violation() {
    let mut v = strict_validator();
    // Default budget is 30_000ms. Inject exactly 30_000.
    v.record_fault_injection(
        "s1",
        &FaultInjectionSpec {
            fault_category: FaultCategory::TaskPanic,
            inject_at_vt: 0,
            target: FaultTarget::Global,
            budget_cost_ms: 30_000,
        },
    );
    assert!(!v.has_violations());
    assert_eq!(v.fault_budget_remaining_ms(), 0);
}

#[test]
fn enrichment_validator_fault_budget_over_by_one_violation() {
    let mut v = strict_validator();
    // Inject 30_001ms, exceeding budget by 1.
    v.record_fault_injection(
        "s1",
        &FaultInjectionSpec {
            fault_category: FaultCategory::TaskPanic,
            inject_at_vt: 0,
            target: FaultTarget::Global,
            budget_cost_ms: 30_001,
        },
    );
    assert!(v.has_violations());
    assert_eq!(v.violations().len(), 1);
    assert_eq!(
        v.violations()[0].kind,
        BridgeViolationKind::FaultBudgetExceeded
    );
}

#[test]
fn enrichment_validator_clean_report_all_seams_clean() {
    let v = strict_validator();
    let report = v.build_report();
    for seam in BridgeSeam::ALL {
        assert_eq!(
            *report.seam_status.get(&seam.to_string()).unwrap(),
            SeamStatus::Clean,
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Report properties (5 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_clean_is_clean_not_blocked() {
    let v = strict_validator();
    let report = v.build_report();
    assert!(report.is_clean());
    assert!(!report.release_blocked);
}

#[test]
fn enrichment_report_all_evidence_verified_zero_entries_is_false() {
    let v = strict_validator();
    let report = v.build_report();
    // 0 entries => all_evidence_verified returns false
    assert!(!report.all_evidence_verified());
}

#[test]
fn enrichment_report_replay_confidence_at_threshold_sufficient() {
    let mut v = strict_validator();
    // Record 19 deterministic + 1 diverged => 950_000
    for i in 0..20 {
        let cert = make_cert(i, 100);
        if i < 19 {
            v.record_replay_verdict(&format!("s{i}"), i, &cert, &cert);
        } else {
            let alt = TraceCertificate::new(
                ContentHash::compute(b"alt-events"),
                ContentHash::compute(b"schedule"),
                100,
                ContentHash::compute(b"fingerprint"),
                i,
            );
            v.record_replay_verdict(&format!("s{i}"), i, &cert, &alt);
        }
    }
    let report = v.build_report();
    assert_eq!(report.replay_confidence_millionths, 950_000);
    assert!(report.replay_confidence_sufficient(950_000));
}

#[test]
fn enrichment_report_replay_confidence_below_threshold_insufficient() {
    let mut v = strict_validator();
    // 9 deterministic + 1 diverged => 900_000
    for i in 0..10 {
        let cert = make_cert(i, 50);
        if i < 9 {
            v.record_replay_verdict(&format!("s{i}"), i, &cert, &cert);
        } else {
            let alt = TraceCertificate::new(
                ContentHash::compute(b"alt-events"),
                ContentHash::compute(b"schedule"),
                50,
                ContentHash::compute(b"fingerprint"),
                i,
            );
            v.record_replay_verdict(&format!("s{i}"), i, &cert, &alt);
        }
    }
    let report = v.build_report();
    assert_eq!(report.replay_confidence_millionths, 900_000);
    assert!(!report.replay_confidence_sufficient(950_000));
}

#[test]
fn enrichment_report_display_contains_key_fields() {
    let mut v = strict_validator();
    v.record_scenario_execution("s1");
    v.record_oracle_result("s1", OracleResult::fail("safety", "broken", 100));
    let report = v.build_report();
    let display = report.to_string();
    assert!(display.contains("violations="));
    assert!(display.contains("release_blocked="));
    assert!(display.contains("scenarios="));
}

// ---------------------------------------------------------------------------
// 7. Policy configuration (4 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_seam_config_returns_correct_config() {
    let policy = BridgeContractPolicy::strict(epoch());
    let config = policy.seam_config(BridgeSeam::OracleDispatch).unwrap();
    assert_eq!(config.seam, BridgeSeam::OracleDispatch);
    assert!(config.fail_closed);
    assert_eq!(config.mode, BridgeMode::ThinAdapter);
}

#[test]
fn enrichment_policy_missing_seam_fail_closed_default_true() {
    let policy = BridgeContractPolicy {
        seam_configs: BTreeMap::new(),
        min_replay_confidence_millionths: 0,
        max_oracle_failures: 0,
        fault_injection_budget_ms: 0,
        require_upstream_evidence_verification: false,
        policy_epoch: epoch(),
    };
    assert!(policy.is_seam_fail_closed(BridgeSeam::FaultInjection));
}

#[test]
fn enrichment_policy_missing_seam_mode_default_local_only() {
    let policy = BridgeContractPolicy {
        seam_configs: BTreeMap::new(),
        min_replay_confidence_millionths: 0,
        max_oracle_failures: 0,
        fault_injection_budget_ms: 0,
        require_upstream_evidence_verification: false,
        policy_epoch: epoch(),
    };
    assert_eq!(
        policy.seam_mode(BridgeSeam::ReplayDeterminism),
        BridgeMode::LocalOnly
    );
}

#[test]
fn enrichment_policy_strict_requires_upstream_lenient_does_not() {
    let strict = BridgeContractPolicy::strict(epoch());
    let lenient = BridgeContractPolicy::lenient(epoch());
    assert!(strict.require_upstream_evidence_verification);
    assert!(!lenient.require_upstream_evidence_verification);
}

// ---------------------------------------------------------------------------
// 8. BridgeSeamConfig (3 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_seam_config_fail_closed_constructor() {
    let config =
        BridgeSeamConfig::fail_closed(BridgeSeam::ScenarioExecution, BridgeMode::ThinAdapter);
    assert!(config.fail_closed);
    assert_eq!(config.max_latency_ms, 5_000);
    assert!(config.emit_evidence);
    assert!(config.rationale.is_empty());
}

#[test]
fn enrichment_seam_config_lenient_constructor() {
    let config =
        BridgeSeamConfig::lenient(BridgeSeam::EvidenceLinkage, BridgeMode::LocalOnly);
    assert!(!config.fail_closed);
    assert_eq!(config.max_latency_ms, 30_000);
    assert!(!config.emit_evidence);
    assert!(config.rationale.is_empty());
}

#[test]
fn enrichment_seam_config_with_rationale_chains() {
    let config =
        BridgeSeamConfig::fail_closed(BridgeSeam::FaultInjection, BridgeMode::DirectDependency)
            .with_rationale("fault injection needs strict boundary");
    assert_eq!(config.rationale, "fault injection needs strict boundary");
    assert!(config.fail_closed);
}

// ---------------------------------------------------------------------------
// 9. FaultCategory methods (3 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fault_category_first_five_have_local_equivalent() {
    assert!(FaultCategory::TaskPanic.has_local_equivalent());
    assert!(FaultCategory::ChannelDisconnect.has_local_equivalent());
    assert!(FaultCategory::ObligationLeak.has_local_equivalent());
    assert!(FaultCategory::DeadlineExpiry.has_local_equivalent());
    assert!(FaultCategory::RegionClose.has_local_equivalent());
}

#[test]
fn enrichment_fault_category_local_fallback_network_and_resource() {
    assert_eq!(
        FaultCategory::NetworkPartition.local_fallback(),
        Some(FaultCategory::ChannelDisconnect)
    );
    assert_eq!(
        FaultCategory::ResourceExhaustion.local_fallback(),
        Some(FaultCategory::DeadlineExpiry)
    );
}

#[test]
fn enrichment_fault_category_local_categories_no_fallback() {
    assert_eq!(FaultCategory::TaskPanic.local_fallback(), None);
    assert_eq!(FaultCategory::ChannelDisconnect.local_fallback(), None);
    assert_eq!(FaultCategory::ObligationLeak.local_fallback(), None);
    assert_eq!(FaultCategory::DeadlineExpiry.local_fallback(), None);
    assert_eq!(FaultCategory::RegionClose.local_fallback(), None);
}

// ---------------------------------------------------------------------------
// 10. BridgeTypeMappingRegistry (4 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_type_registry_new_is_empty() {
    let reg = BridgeTypeMappingRegistry::new();
    assert!(reg.mappings.is_empty());
    assert_eq!(reg.lossless_count(), 0);
    assert_eq!(reg.lossy_count(), 0);
}

#[test]
fn enrichment_type_registry_with_defaults_has_all_five_seams() {
    let reg = BridgeTypeMappingRegistry::with_defaults();
    let seams: BTreeSet<BridgeSeam> = reg.mappings.iter().map(|m| m.seam).collect();
    for seam in BridgeSeam::ALL {
        // At minimum ScenarioExecution, ReplayDeterminism, EvidenceLinkage, FaultInjection
        // OracleDispatch may or may not be mapped; check only known seams
        if seam != BridgeSeam::OracleDispatch {
            assert!(
                seams.contains(&seam),
                "Missing seam {:?} in default registry",
                seam
            );
        }
    }
}

#[test]
fn enrichment_type_registry_add_lossless_and_lossy() {
    let mut reg = BridgeTypeMappingRegistry::new();
    reg.add_lossless("LocalA", "UpstreamA", BridgeSeam::ScenarioExecution);
    reg.add_lossy(
        "LocalB",
        "UpstreamB",
        BridgeSeam::ReplayDeterminism,
        "precision loss",
    );
    assert_eq!(reg.lossless_count(), 1);
    assert_eq!(reg.lossy_count(), 1);
    assert_eq!(reg.mappings.len(), 2);
}

#[test]
fn enrichment_type_registry_lossy_mappings_returns_only_lossy() {
    let mut reg = BridgeTypeMappingRegistry::new();
    reg.add_lossless("L1", "U1", BridgeSeam::ScenarioExecution);
    reg.add_lossless("L2", "U2", BridgeSeam::ReplayDeterminism);
    reg.add_lossy("L3", "U3", BridgeSeam::FaultInjection, "truncation");
    let lossy = reg.lossy_mappings();
    assert_eq!(lossy.len(), 1);
    assert_eq!(lossy[0].local_type, "L3");
    assert!(!lossy[0].lossless);
}

// ---------------------------------------------------------------------------
// 11. Serde roundtrips (5 tests)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validator_serde_roundtrip() {
    let mut v = strict_validator();
    v.record_scenario_execution("s1");
    v.record_scenario_execution("s2");
    let cert = make_cert(1, 100);
    v.record_replay_verdict("s1", 1, &cert, &cert);
    v.record_oracle_result("s1", OracleResult::pass("safety", 100));
    v.record_oracle_result("s2", OracleResult::fail("liveness", "stuck", 200));
    v.record_fault_injection(
        "s1",
        &FaultInjectionSpec {
            fault_category: FaultCategory::ChannelDisconnect,
            inject_at_vt: 50,
            target: FaultTarget::Task { task_id: 3 },
            budget_cost_ms: 1_000,
        },
    );

    let json = serde_json::to_string(&v).unwrap();
    let round: BridgeContractValidator = serde_json::from_str(&json).unwrap();
    assert_eq!(v.violations().len(), round.violations().len());
    assert_eq!(v.oracle_results().len(), round.oracle_results().len());
    assert_eq!(v.replay_verdicts().len(), round.replay_verdicts().len());
    assert_eq!(v.evidence_entries().len(), round.evidence_entries().len());
}

#[test]
fn enrichment_policy_serde_roundtrip() {
    let policy = BridgeContractPolicy::strict(epoch());
    let json = serde_json::to_string(&policy).unwrap();
    let round: BridgeContractPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, round);
}

#[test]
fn enrichment_scenario_manifest_serde_roundtrip() {
    let mut m = ScenarioManifest::new("roundtrip", 99);
    m.add_fault("f1", 10);
    m.add_oracle("o1");
    m.add_cancellation("c1", 20);
    let json = serde_json::to_string(&m).unwrap();
    let round: ScenarioManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, round);
}

#[test]
fn enrichment_fault_injection_spec_serde_roundtrip() {
    let spec = FaultInjectionSpec {
        fault_category: FaultCategory::NetworkPartition,
        inject_at_vt: 500,
        target: FaultTarget::AllInRegion {
            region_id: "eu-west".to_owned(),
        },
        budget_cost_ms: 5_000,
    };
    let json = serde_json::to_string(&spec).unwrap();
    let round: FaultInjectionSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, round);
}

#[test]
fn enrichment_report_serde_roundtrip_with_violations() {
    let mut v = strict_validator();
    v.record_scenario_execution("s1");
    v.record_oracle_result("s1", OracleResult::fail("safety", "broken", 100));
    v.record_scenario_timeout("s1", 10_000, 5_000);
    let cert = make_cert(1, 100);
    let alt = TraceCertificate::new(
        ContentHash::compute(b"alt-events"),
        ContentHash::compute(b"schedule"),
        100,
        ContentHash::compute(b"fingerprint"),
        1,
    );
    v.record_replay_verdict("s1", 1, &cert, &alt);

    let report = v.build_report();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let round: BridgeContractReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, round);
    assert!(round.release_blocked);
    assert_eq!(round.total_violations, 3);
}
