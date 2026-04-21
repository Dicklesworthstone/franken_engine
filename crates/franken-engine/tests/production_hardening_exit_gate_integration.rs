#![forbid(unsafe_code)]
//! Integration coverage for the current production hardening exit gate surface.

use frankenengine_engine::production_hardening_exit_gate::{
    ProductionHardeningGateExecution, ProductionReadinessStatus, ValidationStatus,
};

fn production_hardening_source() -> &'static str {
    include_str!("../src/production_hardening_exit_gate.rs")
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
    assert!(source.contains("pub operational_readiness_report: Option<OperationalReadinessReport>"));
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
