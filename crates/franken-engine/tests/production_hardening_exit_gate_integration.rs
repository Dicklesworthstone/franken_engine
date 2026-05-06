#![forbid(unsafe_code)]
//! Integration coverage for the current production hardening exit gate surface.

use frankenengine_engine::production_hardening_exit_gate::{
    ProductionHardeningGateExecution, ProductionReadinessStatus, ValidationStatus,
};

fn production_hardening_source() -> &'static str {
    include_str!("../src/production_hardening_exit_gate.rs")
}

fn assert_close(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < 1e-6,
        "expected {expected}, got {actual}"
    );
}

fn insert_passing_evidence(gate: &mut ProductionHardeningGateExecution) {
    for (attack_vector, actual_containment_ms) in [
        ("memory-corruption", 90_u64),
        ("capability-escalation", 180),
        ("code-injection", 120),
        ("policy-bypass", 40),
    ] {
        gate.evidence_artifacts.insert(
            format!("security:{attack_vector}"),
            format!(
                "actual_containment_ms={actual_containment_ms};evidence_file=/evidence/security/{attack_vector}.json"
            ),
        );
    }

    for (target, cpu_hours, coverage_pct) in [
        ("parser", 24, 81.0),
        ("ir", 25, 86.0),
        ("execution", 26, 76.0),
        ("hostcall", 27, 91.0),
        ("policy", 28, 96.0),
        ("evidence", 29, 92.0),
    ] {
        gate.evidence_artifacts.insert(
            format!("fuzz:{target}"),
            format!("cpu_hours={cpu_hours};coverage_pct={coverage_pct};crash_count=0"),
        );
    }

    for (key, test_cases, success_rate_pct) in [
        ("property:parser:parser_invariants", 10000, 99.91),
        ("property:ir:ir_invariants", 5000, 99.97),
        ("property:execution:execution_invariants", 8000, 99.92),
        ("property:policy:policy_monotonicity", 3000, 100.0),
        ("property:evidence:evidence_determinism", 2000, 100.0),
    ] {
        gate.evidence_artifacts.insert(
            key.to_string(),
            format!("test_cases={test_cases};success_rate_pct={success_rate_pct}"),
        );
    }

    for (transformation, test_cases) in [
        ("optimization-level", 2000),
        ("policy-merge-order", 1000),
        ("code-reordering", 3000),
    ] {
        gate.evidence_artifacts.insert(
            format!("metamorphic:{transformation}"),
            format!("test_cases={test_cases};preservation_validated=true"),
        );
    }

    for (stage, error_rate_pct, latency_p99_ms) in [
        ("shadow", 0.005, 95),
        ("canary", 0.05, 180),
        ("ramp", 0.4, 250),
        ("default", 0.8, 450),
    ] {
        gate.evidence_artifacts.insert(
            format!("rollout:{stage}"),
            format!("error_rate_pct={error_rate_pct};latency_p99_ms={latency_p99_ms}"),
        );
    }

    for (fault, recovery_time_mins) in [
        ("network_partition", 4),
        ("node_failure", 2),
        ("key_compromise", 1),
        ("stale_revocation", 8),
        ("clock_skew", 4),
    ] {
        gate.evidence_artifacts.insert(
            format!("fault:{fault}"),
            format!("recovery_time_mins={recovery_time_mins};system_recovered=true"),
        );
    }

    for (extension, containment_time_mins, convergence_time_mins, fleet_contained) in [
        ("cpu-bomb", 2, 5, true),
        ("memory-exhaustion", 1, 3, true),
        ("privilege-escalation", 1, 2, true),
    ] {
        gate.evidence_artifacts.insert(
            format!("quarantine:{extension}"),
            format!(
                "containment_time_mins={containment_time_mins};convergence_time_mins={convergence_time_mins};fleet_contained={fleet_contained}"
            ),
        );
    }

    for (severity, environment, success_rate_pct) in [
        ("high", "canary", 100.0),
        ("critical", "canary", 100.0),
        ("high", "production", 97.0),
    ] {
        gate.evidence_artifacts.insert(
            format!("replay:{severity}:{environment}"),
            format!("success_rate_pct={success_rate_pct}"),
        );
    }

    gate.evidence_artifacts.insert(
        "e2e:deployment".to_string(),
        "deployment_successful=true;fault_injection_recovery=true;containment_validated=true;evidence_audit_passed=true".to_string(),
    );
}

#[test]
fn test_production_hardening_gate_initialization() {
    let gate = ProductionHardeningGateExecution::new("integration-test-001".to_string())
        .expect("gate construction should succeed");

    assert_eq!(gate.gate_id, "integration-test-001");
    assert_eq!(gate.status, ProductionReadinessStatus::NotStarted);
    assert!(gate.started_at > 0);
    assert!(gate.completed_at.is_none());
    assert!(gate.operational_readiness_report.is_none());
    assert_eq!(gate.e2e_deployment_status, ValidationStatus::Pending);
}

#[test]
fn test_production_hardening_gate_initializes_required_collections() {
    let gate = ProductionHardeningGateExecution::new("integration-test-002".to_string())
        .expect("gate construction should succeed");

    assert!(!gate.security_matrix.is_empty());
    assert!(!gate.fuzz_campaigns.is_empty());
    assert!(!gate.property_tests.is_empty());
    assert!(!gate.metamorphic_tests.is_empty());
    assert!(!gate.rollout_validation.is_empty());
    assert!(!gate.fault_injection_drills.is_empty());
    assert!(!gate.quarantine_drills.is_empty());
    assert!(!gate.replay_audits.is_empty());
}

#[test]
fn test_production_hardening_source_exports_report_shapes() {
    let source = production_hardening_source();
    assert!(source.contains("pub struct OperationalReadinessReport"));
    assert!(source.contains("pub struct SecurityAssessment"));
    assert!(source.contains("pub struct PerformanceAssessment"));
    assert!(source.contains("pub struct ReliabilityAssessment"));
    assert!(source.contains("pub struct OperationalAssessment"));
    assert!(source.contains("pub struct RiskSummary"));
    assert!(source.contains("pub struct GoNoGoDecision"));
}

#[test]
fn test_production_hardening_source_exposes_gate_methods() {
    let source = production_hardening_source();
    assert!(source.contains("pub fn execute_production_hardening_gate(&mut self)"));
    assert!(source.contains("fn generate_operational_readiness_report(&self)"));
    assert!(source.contains("pub fn all_validations_passed(&self) -> bool"));
    assert!(source.contains("fn get_failed_validations(&self) -> Vec<String>"));
}

#[test]
fn test_production_hardening_source_tracks_evidence_and_status() {
    let source = production_hardening_source();
    assert!(source.contains("pub evidence_artifacts: BTreeMap<String, String>"));
    assert!(source.contains("pub status: ProductionReadinessStatus"));
    assert!(
        source.contains("pub operational_readiness_report: Option<OperationalReadinessReport>")
    );
    assert!(source.contains("pub e2e_deployment_status: ValidationStatus"));
}

#[test]
fn test_production_hardening_source_covers_validation_domains() {
    let source = production_hardening_source();
    assert!(source.contains("pub security_matrix: Vec<SecurityRegressionEntry>"));
    assert!(source.contains("pub fuzz_campaigns: Vec<FuzzCampaignConfig>"));
    assert!(source.contains("pub property_tests: Vec<PropertyTestConfig>"));
    assert!(source.contains("pub metamorphic_tests: Vec<MetamorphicTestConfig>"));
    assert!(source.contains("pub rollout_validation: Vec<RolloutValidationConfig>"));
    assert!(source.contains("pub fault_injection_drills: Vec<FaultInjectionConfig>"));
    assert!(source.contains("pub quarantine_drills: Vec<QuarantineDrillConfig>"));
    assert!(source.contains("pub replay_audits: Vec<ReplayAuditConfig>"));
}

#[test]
fn test_production_hardening_gate_records_evidence_derived_metrics() {
    let mut gate = ProductionHardeningGateExecution::new("integration-test-metrics".to_string())
        .expect("gate construction should succeed");
    insert_passing_evidence(&mut gate);

    gate.execute_production_hardening_gate()
        .expect("gate should accept complete passing evidence");

    let report = gate
        .operational_readiness_report
        .as_ref()
        .expect("report should exist after a successful run");

    assert_close(report.performance_assessment.fuzz_coverage_pct, 87.0);
    assert_eq!(report.performance_assessment.fuzz_cpu_hours_total, 159);
    assert_close(
        report.performance_assessment.property_test_coverage_pct,
        99.96,
    );
    assert_close(
        report
            .performance_assessment
            .metamorphic_preservation_rate_pct,
        100.0,
    );
    assert_close(
        report.reliability_assessment.replay_audit_success_rate_pct,
        99.0,
    );
    assert_close(report.operational_assessment.monitoring_coverage_pct, 100.0);
    assert_close(
        report.operational_assessment.logging_completeness_pct,
        100.0,
    );
    assert!(
        gate.fuzz_campaigns
            .iter()
            .all(|campaign| campaign.actual_coverage_pct.is_some())
    );
    assert!(
        gate.replay_audits
            .iter()
            .all(|audit| audit.actual_success_rate_pct.is_some())
    );
}
