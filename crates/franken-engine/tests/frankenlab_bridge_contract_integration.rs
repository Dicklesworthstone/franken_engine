//! Integration tests for frankenlab_bridge_contract module.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::frankenlab_bridge_contract::{
    BRIDGE_CONTRACT_BEAD_ID, BRIDGE_CONTRACT_SCHEMA_VERSION, BridgeContractPolicy,
    BridgeContractReport, BridgeContractValidator, BridgeMode, BridgeSeam, BridgeSeamConfig,
    BridgeTypeMappingRegistry, BridgeViolation, BridgeViolationKind, EvidenceCategory,
    EvidenceLinkageEntry, FaultCategory, FaultInjectionSpec, FaultTarget, OracleResult,
    ReplayVerdict, ScenarioManifest, SeamStatus, TraceCertificate,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(200)
}

fn hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

fn make_cert(label: &str, seed: u64, steps: u64) -> TraceCertificate {
    TraceCertificate::new(
        hash(format!("events-{label}").as_bytes()),
        hash(format!("schedule-{label}").as_bytes()),
        steps,
        hash(format!("fingerprint-{label}").as_bytes()),
        seed,
    )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version_present() {
    assert!(!BRIDGE_CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(BRIDGE_CONTRACT_SCHEMA_VERSION.contains("frankenlab-bridge-contract"));
}

#[test]
fn integration_bead_id_present() {
    assert_eq!(BRIDGE_CONTRACT_BEAD_ID, "bd-3nr.1.4.1");
}

// ---------------------------------------------------------------------------
// BridgeMode coverage
// ---------------------------------------------------------------------------

#[test]
fn integration_bridge_mode_ordering() {
    assert!(BridgeMode::DirectDependency < BridgeMode::ThinAdapter);
    assert!(BridgeMode::ThinAdapter < BridgeMode::LocalWithUpstreamValidation);
    assert!(BridgeMode::LocalWithUpstreamValidation < BridgeMode::LocalOnly);
}

#[test]
fn integration_bridge_mode_round_trip_all() {
    let modes = [
        BridgeMode::DirectDependency,
        BridgeMode::ThinAdapter,
        BridgeMode::LocalWithUpstreamValidation,
        BridgeMode::LocalOnly,
    ];
    for mode in &modes {
        let json = serde_json::to_string(mode).unwrap();
        let round: BridgeMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, round);
    }
}

// ---------------------------------------------------------------------------
// BridgeSeam coverage
// ---------------------------------------------------------------------------

#[test]
fn integration_bridge_seam_all_unique() {
    let set: BTreeSet<BridgeSeam> = BridgeSeam::ALL.iter().copied().collect();
    assert_eq!(set.len(), BridgeSeam::ALL.len());
}

#[test]
fn integration_bridge_seam_display_no_empty() {
    for seam in BridgeSeam::ALL {
        let s = seam.to_string();
        assert!(!s.is_empty(), "seam display empty for {:?}", seam);
    }
}

// ---------------------------------------------------------------------------
// ScenarioManifest
// ---------------------------------------------------------------------------

#[test]
fn integration_scenario_manifest_deterministic_seed() {
    let m1 = ScenarioManifest::new("test", 42);
    let m2 = ScenarioManifest::new("test", 42);
    let j1 = serde_json::to_string(&m1).unwrap();
    let j2 = serde_json::to_string(&m2).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn integration_scenario_manifest_complex() {
    let mut m = ScenarioManifest::new("complex", 999);
    m.description = "A complex lifecycle scenario".to_owned();
    m.schema_version = 2;
    m.max_steps = 50_000;
    m.panic_on_obligation_leak = false;

    m.add_fault("panic", 100);
    m.add_fault("disconnect", 500);
    m.add_fault("deadline", 1000);
    m.add_oracle("safety");
    m.add_oracle("liveness");
    m.add_oracle("fairness");
    m.add_cancellation("region-a", 200);
    m.add_cancellation("region-b", 700);

    assert_eq!(m.fault_schedule.len(), 3);
    assert_eq!(m.oracle_invariants.len(), 3);
    assert_eq!(m.cancellation_schedule.len(), 2);

    let json = serde_json::to_string_pretty(&m).unwrap();
    let round: ScenarioManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, round);
}

#[test]
fn integration_scenario_manifest_dedup_oracles() {
    let mut m = ScenarioManifest::new("dedup", 1);
    m.add_oracle("safety");
    m.add_oracle("safety");
    m.add_oracle("safety");
    assert_eq!(m.oracle_invariants.len(), 1);
}

// ---------------------------------------------------------------------------
// TraceCertificate
// ---------------------------------------------------------------------------

#[test]
fn integration_trace_cert_same_seed_equivalent() {
    let cert_a = make_cert("run1", 42, 100);
    let cert_b = make_cert("run1", 42, 100);
    assert!(cert_a.is_equivalent(&cert_b));
}

#[test]
fn integration_trace_cert_different_steps_not_equivalent() {
    let cert_a = make_cert("run1", 42, 100);
    let cert_b = TraceCertificate::new(
        cert_a.event_hash.clone(),
        cert_a.schedule_hash.clone(),
        101,
        cert_a.trace_fingerprint.clone(),
        42,
    );
    assert!(!cert_a.is_equivalent(&cert_b));
}

#[test]
fn integration_trace_cert_different_events_not_equivalent() {
    let cert_a = make_cert("run1", 42, 100);
    let cert_b = make_cert("run2", 42, 100);
    assert!(!cert_a.is_equivalent(&cert_b));
}

// ---------------------------------------------------------------------------
// ReplayVerdict
// ---------------------------------------------------------------------------

#[test]
fn integration_replay_verdict_all_variants_serde() {
    let verdicts = vec![
        ReplayVerdict::Deterministic,
        ReplayVerdict::Diverged {
            event_match: true,
            schedule_match: false,
            step_match: true,
            fingerprint_match: false,
        },
        ReplayVerdict::InfrastructureFailure {
            detail: "disk full".to_owned(),
        },
    ];

    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let round: ReplayVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, round);
    }
}

#[test]
fn integration_replay_verdict_display_coverage() {
    let v1 = ReplayVerdict::Deterministic;
    assert_eq!(v1.to_string(), "deterministic");

    let v2 = ReplayVerdict::Diverged {
        event_match: true,
        schedule_match: false,
        step_match: true,
        fingerprint_match: false,
    };
    let s = v2.to_string();
    assert!(s.contains("diverged"));
    assert!(s.contains("schedule=false"));

    let v3 = ReplayVerdict::InfrastructureFailure {
        detail: "oom".to_owned(),
    };
    assert!(v3.to_string().contains("oom"));
}

// ---------------------------------------------------------------------------
// FaultCategory
// ---------------------------------------------------------------------------

#[test]
fn integration_fault_category_all_unique() {
    let set: BTreeSet<FaultCategory> = FaultCategory::ALL.iter().copied().collect();
    assert_eq!(set.len(), FaultCategory::ALL.len());
}

#[test]
fn integration_fault_category_local_vs_upstream() {
    let local_count = FaultCategory::ALL
        .iter()
        .filter(|c| c.has_local_equivalent())
        .count();
    let upstream_only = FaultCategory::ALL
        .iter()
        .filter(|c| !c.has_local_equivalent())
        .count();
    assert_eq!(local_count, 5);
    assert_eq!(upstream_only, 2);
}

#[test]
fn integration_fault_category_fallback_consistency() {
    for cat in FaultCategory::ALL {
        if cat.has_local_equivalent() {
            assert_eq!(cat.local_fallback(), None);
        } else {
            let fallback = cat.local_fallback().unwrap();
            assert!(fallback.has_local_equivalent());
        }
    }
}

// ---------------------------------------------------------------------------
// OracleResult
// ---------------------------------------------------------------------------

#[test]
fn integration_oracle_result_serde_pass() {
    let r = OracleResult::pass("determinism", 500);
    let json = serde_json::to_string(&r).unwrap();
    let round: OracleResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, round);
    assert!(round.passed);
}

#[test]
fn integration_oracle_result_serde_fail() {
    let r = OracleResult::fail("safety", "invariant broken at step 42", 500);
    let json = serde_json::to_string(&r).unwrap();
    let round: OracleResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, round);
    assert!(!round.passed);
}

// ---------------------------------------------------------------------------
// EvidenceCategory
// ---------------------------------------------------------------------------

#[test]
fn integration_evidence_category_all_unique() {
    let set: BTreeSet<EvidenceCategory> = EvidenceCategory::ALL.iter().copied().collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn integration_evidence_category_display() {
    for cat in EvidenceCategory::ALL {
        let s = cat.to_string();
        assert!(!s.is_empty());
        // All should be snake_case
        assert!(!s.contains(char::is_uppercase));
    }
}

// ---------------------------------------------------------------------------
// BridgeContractPolicy
// ---------------------------------------------------------------------------

#[test]
fn integration_strict_policy_covers_all_seams() {
    let policy = BridgeContractPolicy::strict(epoch());
    assert_eq!(policy.seam_configs.len(), BridgeSeam::ALL.len());
    for seam in BridgeSeam::ALL {
        assert!(policy.seam_config(seam).is_some());
    }
}

#[test]
fn integration_strict_vs_lenient_policy() {
    let strict = BridgeContractPolicy::strict(epoch());
    let lenient = BridgeContractPolicy::lenient(epoch());

    // Strict has higher thresholds
    assert!(strict.min_replay_confidence_millionths > lenient.min_replay_confidence_millionths);
    assert!(strict.max_oracle_failures < lenient.max_oracle_failures);
    assert!(strict.require_upstream_evidence_verification);
    assert!(!lenient.require_upstream_evidence_verification);
}

#[test]
fn integration_policy_missing_seam_defaults() {
    let policy = BridgeContractPolicy {
        seam_configs: BTreeMap::new(),
        min_replay_confidence_millionths: 0,
        max_oracle_failures: 0,
        fault_injection_budget_ms: 0,
        require_upstream_evidence_verification: false,
        policy_epoch: epoch(),
    };
    // Missing seam defaults to fail-closed + LocalOnly
    assert!(policy.is_seam_fail_closed(BridgeSeam::ScenarioExecution));
    assert_eq!(
        policy.seam_mode(BridgeSeam::ScenarioExecution),
        BridgeMode::LocalOnly
    );
}

// ---------------------------------------------------------------------------
// BridgeContractValidator — comprehensive lifecycle
// ---------------------------------------------------------------------------

#[test]
fn integration_validator_full_lifecycle() {
    let mut v = BridgeContractValidator::strict(epoch());

    // Execute 3 scenarios
    for i in 0..3 {
        let id = format!("scenario-{i}");
        v.record_scenario_execution(&id);

        // Deterministic replay
        let cert = make_cert(&id, i as u64, 100 + i as u64);
        v.record_replay_verdict(&id, i as u64, &cert, &cert);

        // Passing oracles
        v.record_oracle_result(&id, OracleResult::pass("safety", 100));
        v.record_oracle_result(&id, OracleResult::pass("liveness", 200));

        // Verified evidence
        v.record_evidence_linkage(EvidenceLinkageEntry {
            scenario_id: id.clone(),
            seed: i as u64,
            artifact_hash: hash(id.as_bytes()),
            evidence_category: EvidenceCategory::ScenarioResult,
            trace_id_hex: format!("trace-{i}"),
            captured_at_vt: 100,
            upstream_verified: true,
        });

        // Small fault injection
        v.record_fault_injection(
            &id,
            &FaultInjectionSpec {
                fault_category: FaultCategory::TaskPanic,
                inject_at_vt: 50,
                target: FaultTarget::Task { task_id: 1 },
                budget_cost_ms: 1_000,
            },
        );
    }

    let report = v.build_report();
    assert!(report.is_clean());
    assert!(!report.release_blocked);
    assert_eq!(report.scenarios_executed, 3);
    assert_eq!(report.replay_confidence_millionths, 1_000_000);
    assert_eq!(report.oracle_pass_rate_millionths, 1_000_000);
    assert!(report.all_evidence_verified());
    assert_eq!(report.fault_budget_consumed_ms, 3_000);
}

#[test]
fn integration_validator_mixed_oracle_results() {
    let mut v = BridgeContractValidator::strict(epoch());

    v.record_oracle_result("s1", OracleResult::pass("safety", 100));
    v.record_oracle_result("s1", OracleResult::pass("liveness", 200));
    v.record_oracle_result("s1", OracleResult::fail("fairness", "starvation", 300));

    assert!(v.has_violations());
    assert_eq!(v.oracle_failure_count(), 1);
    // 2 out of 3 passed
    assert_eq!(v.oracle_pass_rate_millionths(), 666_666);
}

#[test]
fn integration_validator_multiple_replay_divergences() {
    let mut v = BridgeContractValidator::strict(epoch());

    // 5 replays: 3 deterministic, 2 diverged
    for i in 0..5 {
        let cert_a = make_cert(&format!("run-{i}"), i, 100);
        if i < 3 {
            v.record_replay_verdict(&format!("s{i}"), i, &cert_a, &cert_a);
        } else {
            let cert_b = make_cert(&format!("run-{i}-alt"), i, 100);
            v.record_replay_verdict(&format!("s{i}"), i, &cert_a, &cert_b);
        }
    }

    assert!(v.has_violations());
    assert_eq!(v.replay_verdicts().len(), 5);
    assert_eq!(v.replay_confidence_millionths(), 600_000); // 3/5
    assert_eq!(v.violations().len(), 2);
}

#[test]
fn integration_validator_fault_budget_cumulative() {
    let mut v = BridgeContractValidator::strict(epoch());
    let _budget_limit = 30_000u64;

    // Inject faults that stay within budget
    for i in 0..6 {
        v.record_fault_injection(
            "s1",
            &FaultInjectionSpec {
                fault_category: FaultCategory::ChannelDisconnect,
                inject_at_vt: i * 100,
                target: FaultTarget::Global,
                budget_cost_ms: 5_000,
            },
        );
    }

    // 6 * 5000 = 30000, exactly at limit
    assert!(!v.has_violations());
    assert_eq!(v.fault_budget_remaining_ms(), 0);

    // One more pushes over
    v.record_fault_injection(
        "s1",
        &FaultInjectionSpec {
            fault_category: FaultCategory::RegionClose,
            inject_at_vt: 700,
            target: FaultTarget::Region {
                region_id: "r1".to_owned(),
            },
            budget_cost_ms: 1,
        },
    );
    assert!(v.has_violations());
}

#[test]
fn integration_validator_infrastructure_errors_per_seam() {
    let mut v = BridgeContractValidator::strict(epoch());

    for seam in BridgeSeam::ALL {
        v.record_infrastructure_error(seam, &format!("{seam} failed"));
    }

    assert_eq!(v.violations().len(), 5);
    let report = v.build_report();

    for seam in BridgeSeam::ALL {
        assert_eq!(
            *report.seam_status.get(&seam.to_string()).unwrap(),
            SeamStatus::ReleaseBlocked,
        );
    }
}

// ---------------------------------------------------------------------------
// Report quality
// ---------------------------------------------------------------------------

#[test]
fn integration_report_violation_counts() {
    let mut v = BridgeContractValidator::strict(epoch());

    // 2 oracle failures
    v.record_oracle_result("s1", OracleResult::fail("a", "bad", 100));
    v.record_oracle_result("s1", OracleResult::fail("b", "bad", 200));

    // 1 timeout
    v.record_scenario_timeout("s1", 10_000, 5_000);

    let report = v.build_report();
    assert_eq!(report.total_violations, 3);
    assert_eq!(report.release_blocking_violations, 3);
    assert_eq!(
        *report
            .violation_counts
            .get("oracle_invariant_failure")
            .unwrap(),
        2
    );
    assert_eq!(*report.violation_counts.get("scenario_timeout").unwrap(), 1);
}

#[test]
fn integration_report_evidence_verification_tracking() {
    let mut v = BridgeContractValidator::new(BridgeContractPolicy::lenient(epoch()));

    // 3 verified, 2 unverified
    for i in 0..5 {
        v.record_evidence_linkage(EvidenceLinkageEntry {
            scenario_id: format!("s{i}"),
            seed: i,
            artifact_hash: hash(format!("a{i}").as_bytes()),
            evidence_category: EvidenceCategory::ScenarioResult,
            trace_id_hex: format!("t{i}"),
            captured_at_vt: i * 100,
            upstream_verified: i < 3,
        });
    }

    let report = v.build_report();
    assert_eq!(report.evidence_entries_total, 5);
    assert_eq!(report.evidence_entries_verified, 3);
    assert!(!report.all_evidence_verified());
}

#[test]
fn integration_report_json_roundtrip() {
    let mut v = BridgeContractValidator::strict(epoch());
    v.record_scenario_execution("s1");
    let cert = make_cert("run", 42, 100);
    v.record_replay_verdict("s1", 42, &cert, &cert);
    v.record_oracle_result("s1", OracleResult::pass("safety", 100));

    let report = v.build_report();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let round: BridgeContractReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, round);
}

#[test]
fn integration_report_hash_deterministic() {
    let make = || {
        let mut v = BridgeContractValidator::strict(epoch());
        v.record_oracle_result("s1", OracleResult::pass("x", 100));
        v.record_oracle_result("s1", OracleResult::fail("y", "bad", 200));
        v.build_report()
    };
    let r1 = make();
    let r2 = make();
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn integration_report_replay_confidence_threshold() {
    let mut v = BridgeContractValidator::strict(epoch());

    // 9 deterministic, 1 diverged → 90% confidence
    for i in 0..10 {
        let cert = make_cert(&format!("r{i}"), i, 50);
        if i < 9 {
            v.record_replay_verdict(&format!("s{i}"), i, &cert, &cert);
        } else {
            let alt = make_cert(&format!("r{i}-alt"), i, 50);
            v.record_replay_verdict(&format!("s{i}"), i, &cert, &alt);
        }
    }

    let report = v.build_report();
    assert_eq!(report.replay_confidence_millionths, 900_000);
    assert!(report.replay_confidence_sufficient(900_000));
    assert!(!report.replay_confidence_sufficient(950_000));
}

// ---------------------------------------------------------------------------
// BridgeTypeMappingRegistry
// ---------------------------------------------------------------------------

#[test]
fn integration_type_registry_defaults_has_all_seams() {
    let reg = BridgeTypeMappingRegistry::with_defaults();
    let seams: BTreeSet<BridgeSeam> = reg.mappings.iter().map(|m| m.seam).collect();
    // At least scenario, replay, evidence, and fault seams should be covered
    assert!(seams.contains(&BridgeSeam::ScenarioExecution));
    assert!(seams.contains(&BridgeSeam::ReplayDeterminism));
    assert!(seams.contains(&BridgeSeam::EvidenceLinkage));
    assert!(seams.contains(&BridgeSeam::FaultInjection));
}

#[test]
fn integration_type_registry_lossy_have_descriptions() {
    let reg = BridgeTypeMappingRegistry::with_defaults();
    for m in reg.lossy_mappings() {
        assert!(
            !m.loss_description.is_empty(),
            "lossy mapping {} -> {} missing loss description",
            m.local_type,
            m.upstream_type,
        );
    }
}

#[test]
fn integration_type_registry_counts_consistent() {
    let reg = BridgeTypeMappingRegistry::with_defaults();
    assert_eq!(reg.lossless_count() + reg.lossy_count(), reg.mappings.len());
}

#[test]
fn integration_type_registry_serde_roundtrip() {
    let reg = BridgeTypeMappingRegistry::with_defaults();
    let json = serde_json::to_string_pretty(&reg).unwrap();
    let round: BridgeTypeMappingRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, round);
}

// ---------------------------------------------------------------------------
// BridgeSeamConfig
// ---------------------------------------------------------------------------

#[test]
fn integration_seam_config_serde_roundtrip() {
    let config = BridgeSeamConfig::fail_closed(BridgeSeam::OracleDispatch, BridgeMode::ThinAdapter)
        .with_rationale("oracle dispatch needs upstream validation");
    let json = serde_json::to_string(&config).unwrap();
    let round: BridgeSeamConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, round);
}

// ---------------------------------------------------------------------------
// FaultTarget
// ---------------------------------------------------------------------------

#[test]
fn integration_fault_target_all_variants_serde() {
    let targets = vec![
        FaultTarget::Task { task_id: 42 },
        FaultTarget::Region {
            region_id: "r1".to_owned(),
        },
        FaultTarget::AllInRegion {
            region_id: "r2".to_owned(),
        },
        FaultTarget::Global,
    ];

    for t in &targets {
        let json = serde_json::to_string(t).unwrap();
        let round: FaultTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, round);
    }
}

// ---------------------------------------------------------------------------
// E2E: Scenario → Validator → Report → Release decision
// ---------------------------------------------------------------------------

#[test]
fn integration_e2e_release_gate_pass() {
    let mut v = BridgeContractValidator::strict(epoch());

    // Build manifests
    let scenario_ids = ["startup", "shutdown", "cancel", "quarantine"];
    for id in &scenario_ids {
        let mut manifest = ScenarioManifest::new(id, 42);
        manifest.add_oracle("safety");
        manifest.add_oracle("liveness");

        v.record_scenario_execution(id);

        // Deterministic replay
        let cert = make_cert(id, 42, 200);
        v.record_replay_verdict(id, 42, &cert, &cert);

        // Passing oracles
        for oracle in &manifest.oracle_invariants {
            v.record_oracle_result(id, OracleResult::pass(oracle, 500));
        }

        // Verified evidence
        v.record_evidence_linkage(EvidenceLinkageEntry {
            scenario_id: id.to_string(),
            seed: 42,
            artifact_hash: hash(id.as_bytes()),
            evidence_category: EvidenceCategory::ScenarioResult,
            trace_id_hex: format!("trace-{id}"),
            captured_at_vt: 500,
            upstream_verified: true,
        });
    }

    let report = v.build_report();
    assert!(report.is_clean());
    assert!(!report.release_blocked);
    assert_eq!(report.scenarios_executed, 4);
    assert_eq!(report.replay_confidence_millionths, 1_000_000);
    assert_eq!(report.oracle_pass_rate_millionths, 1_000_000);
    assert!(report.all_evidence_verified());
    assert!(report.replay_confidence_sufficient(950_000));
}

#[test]
fn integration_e2e_release_gate_fail_divergence() {
    let mut v = BridgeContractValidator::strict(epoch());

    v.record_scenario_execution("startup");

    // Divergent replay
    let cert_a = make_cert("run-a", 42, 100);
    let cert_b = make_cert("run-b", 42, 100);
    v.record_replay_verdict("startup", 42, &cert_a, &cert_b);

    let report = v.build_report();
    assert!(!report.is_clean());
    assert!(report.release_blocked);
    assert_eq!(report.replay_confidence_millionths, 0);
}

#[test]
fn integration_e2e_release_gate_fail_oracle() {
    let mut v = BridgeContractValidator::strict(epoch());
    v.record_scenario_execution("startup");

    let cert = make_cert("run", 42, 100);
    v.record_replay_verdict("startup", 42, &cert, &cert);

    v.record_oracle_result(
        "startup",
        OracleResult::fail("safety", "obligation leaked", 100),
    );

    let report = v.build_report();
    assert!(report.release_blocked);
    assert!(
        report
            .violation_counts
            .contains_key("oracle_invariant_failure")
    );
}

#[test]
fn integration_e2e_lenient_policy_passes_with_issues() {
    let mut v = BridgeContractValidator::new(BridgeContractPolicy::lenient(epoch()));

    v.record_scenario_execution("s1");

    // Unverified evidence — lenient doesn't block
    v.record_evidence_linkage(EvidenceLinkageEntry {
        scenario_id: "s1".to_owned(),
        seed: 1,
        artifact_hash: hash(b"a"),
        evidence_category: EvidenceCategory::ScenarioResult,
        trace_id_hex: "t1".to_owned(),
        captured_at_vt: 100,
        upstream_verified: false,
    });

    let report = v.build_report();
    assert!(report.is_clean());
    assert!(!report.release_blocked);
}

// ---------------------------------------------------------------------------
// Validator serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_validator_serde_roundtrip() {
    let mut v = BridgeContractValidator::strict(epoch());
    v.record_scenario_execution("s1");
    v.record_oracle_result("s1", OracleResult::pass("safety", 100));

    let json = serde_json::to_string(&v).unwrap();
    let round: BridgeContractValidator = serde_json::from_str(&json).unwrap();
    assert_eq!(v.violations().len(), round.violations().len());
    assert_eq!(v.oracle_results().len(), round.oracle_results().len());
}

// ---------------------------------------------------------------------------
// BridgeViolation
// ---------------------------------------------------------------------------

#[test]
fn integration_violation_kind_all_serde() {
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

    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let round: BridgeViolationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, round);
    }
}

#[test]
fn integration_violation_serde_roundtrip() {
    let v = BridgeViolation {
        seam: BridgeSeam::ReplayDeterminism,
        kind: BridgeViolationKind::ReplayDivergence,
        description: "events diverged at step 42".to_owned(),
        release_blocking: true,
        scenario_id: Some("startup".to_owned()),
        seed: Some(42),
    };
    let json = serde_json::to_string(&v).unwrap();
    let round: BridgeViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, round);
}

// ---------------------------------------------------------------------------
// SeamStatus
// ---------------------------------------------------------------------------

#[test]
fn integration_seam_status_ordering() {
    assert!(SeamStatus::Clean < SeamStatus::Warning);
    assert!(SeamStatus::Warning < SeamStatus::ReleaseBlocked);
}
