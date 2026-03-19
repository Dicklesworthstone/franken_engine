#![forbid(unsafe_code)]
//! Enrichment integration tests for `governance_scorecard`.
//!
//! Tests GovernanceScorecardOutcome Display/serde/as_str, Thresholds default values,
//! Thresholds validate() edge cases, serde roundtrips, error type Display,
//! constant values, and publish lifecycle.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::dp_budget_accountant::{AccountantConfig, BudgetAccountant};
use frankenengine_engine::governance_scorecard::{
    AttestedReceiptObservation, CrossRepoConformanceInput, GOVERNANCE_SCORECARD_COMPONENT,
    GOVERNANCE_SCORECARD_SCHEMA_VERSION, GovernanceScorecardError, GovernanceScorecardOutcome,
    GovernanceScorecardRequest, GovernanceScorecardThresholds, GovernanceScorecardTrendPoint,
    MoonshotGovernorHealthInput, PrivacyBudgetHealthInput, publish_governance_scorecard,
    verify_governance_scorecard_signature,
};
use frankenengine_engine::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceLedgerConfig, GovernanceReport,
};
use frankenengine_engine::privacy_learning_contract::CompositionMethod;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::version_matrix_lane::MatrixHealthSummary;

// ===========================================================================
// helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn test_accountant() -> BudgetAccountant {
    BudgetAccountant::new(AccountantConfig {
        zone: "test-zone".to_string(),
        epsilon_per_epoch_millionths: 1_000_000,
        delta_per_epoch_millionths: 1_000_000,
        lifetime_epsilon_budget_millionths: 10_000_000,
        lifetime_delta_budget_millionths: 10_000_000,
        composition_method: CompositionMethod::Basic,
        epoch: ep(1),
        now_ns: 1_000_000_000,
    })
    .unwrap()
}

fn test_privacy_budget() -> PrivacyBudgetHealthInput {
    PrivacyBudgetHealthInput {
        accountant: test_accountant(),
        overrun_incidents: 0,
        measurement_window_ns: 3_600_000_000_000,
        measurement_end_ns: 1_000_000_000,
    }
}

fn test_governance_report() -> GovernanceReport {
    GovernanceReport {
        total_decisions: 100,
        override_count: 5,
        kill_count: 10,
        override_frequency_millionths: 50_000,
        kill_rate_millionths: 100_000,
        mean_time_to_decision_ns: Some(86_400_000_000_000),
        portfolio_health_trend: Vec::new(),
    }
}

fn test_moonshot_governor() -> MoonshotGovernorHealthInput {
    MoonshotGovernorHealthInput {
        governance_report: test_governance_report(),
        active_moonshots: 3,
        paused_moonshots: 1,
        killed_moonshots: 2,
    }
}

fn test_matrix_health() -> MatrixHealthSummary {
    MatrixHealthSummary {
        total_cells: 100,
        passed_cells: 98,
        failed_cells: 2,
        universal_failures: 0,
        version_specific_failures: 2,
    }
}

fn test_conformance() -> CrossRepoConformanceInput {
    CrossRepoConformanceInput {
        release_id: "rel-001".to_string(),
        matrix_health: test_matrix_health(),
        failure_class_distribution: BTreeMap::new(),
        outstanding_exemptions: 0,
    }
}

fn test_receipts() -> Vec<AttestedReceiptObservation> {
    vec![
        AttestedReceiptObservation {
            receipt_id: "r-1".to_string(),
            high_impact: true,
            attestation_binding_valid: true,
            timestamp_ns: 1_000,
        },
        AttestedReceiptObservation {
            receipt_id: "r-2".to_string(),
            high_impact: true,
            attestation_binding_valid: true,
            timestamp_ns: 2_000,
        },
        AttestedReceiptObservation {
            receipt_id: "r-3".to_string(),
            high_impact: false,
            attestation_binding_valid: false,
            timestamp_ns: 3_000,
        },
    ]
}

fn test_request() -> GovernanceScorecardRequest {
    GovernanceScorecardRequest {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        scorecard_run_id: "run-001".to_string(),
        generated_at_ns: 1_000_000_000,
        attested_receipts: test_receipts(),
        privacy_budget: test_privacy_budget(),
        moonshot_governor: test_moonshot_governor(),
        conformance: test_conformance(),
        historical: Vec::new(),
        thresholds: None,
    }
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes([42u8; 32])
}

fn test_ledger() -> GovernanceAuditLedger {
    GovernanceAuditLedger::new(GovernanceLedgerConfig::default()).unwrap()
}

fn test_actor() -> GovernanceActor {
    GovernanceActor::System("governance-scorecard-test".to_string())
}

// ===========================================================================
// GovernanceScorecardOutcome as_str
// ===========================================================================

#[test]
fn enrichment_outcome_as_str_healthy() {
    assert_eq!(GovernanceScorecardOutcome::Healthy.as_str(), "healthy");
}

#[test]
fn enrichment_outcome_as_str_warning() {
    assert_eq!(GovernanceScorecardOutcome::Warning.as_str(), "warning");
}

#[test]
fn enrichment_outcome_as_str_critical() {
    assert_eq!(GovernanceScorecardOutcome::Critical.as_str(), "critical");
}

#[test]
fn enrichment_outcome_as_str_all_unique() {
    let all = [
        GovernanceScorecardOutcome::Healthy,
        GovernanceScorecardOutcome::Warning,
        GovernanceScorecardOutcome::Critical,
    ];
    let set: BTreeSet<&str> = all.iter().map(|o| o.as_str()).collect();
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// GovernanceScorecardOutcome serde
// ===========================================================================

#[test]
fn enrichment_outcome_serde_roundtrip_all() {
    for outcome in [
        GovernanceScorecardOutcome::Healthy,
        GovernanceScorecardOutcome::Warning,
        GovernanceScorecardOutcome::Critical,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: GovernanceScorecardOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, outcome);
    }
}

#[test]
fn enrichment_outcome_serde_tags_distinct() {
    let tags: BTreeSet<String> = [
        GovernanceScorecardOutcome::Healthy,
        GovernanceScorecardOutcome::Warning,
        GovernanceScorecardOutcome::Critical,
    ]
    .iter()
    .map(|o| serde_json::to_string(o).unwrap())
    .collect();
    assert_eq!(tags.len(), 3);
}

#[test]
fn enrichment_outcome_serde_snake_case() {
    let json = serde_json::to_string(&GovernanceScorecardOutcome::Healthy).unwrap();
    assert_eq!(json, "\"healthy\"");
    let json = serde_json::to_string(&GovernanceScorecardOutcome::Warning).unwrap();
    assert_eq!(json, "\"warning\"");
    let json = serde_json::to_string(&GovernanceScorecardOutcome::Critical).unwrap();
    assert_eq!(json, "\"critical\"");
}

// ===========================================================================
// GovernanceScorecardOutcome ordering
// ===========================================================================

#[test]
fn enrichment_outcome_ordering() {
    assert!(GovernanceScorecardOutcome::Healthy < GovernanceScorecardOutcome::Warning);
    assert!(GovernanceScorecardOutcome::Warning < GovernanceScorecardOutcome::Critical);
}

// ===========================================================================
// GovernanceScorecardThresholds default values
// ===========================================================================

#[test]
fn enrichment_thresholds_default_values() {
    let t = GovernanceScorecardThresholds::default();
    assert_eq!(t.min_attested_receipt_coverage_millionths, 950_000);
    assert_eq!(t.max_privacy_overrun_incidents, 0);
    assert_eq!(t.max_privacy_epoch_consumption_millionths, 900_000);
    assert!(t.warn_privacy_exhaustion_within_ns.is_some());
    assert_eq!(t.max_moonshot_override_frequency_millionths, 200_000);
    assert_eq!(t.max_moonshot_kill_rate_millionths, 250_000);
    assert!(t.max_moonshot_mean_time_to_decision_ns.is_some());
    assert_eq!(t.min_conformance_pass_rate_millionths, 950_000);
    assert_eq!(t.max_universal_failures, 0);
    assert_eq!(t.max_version_specific_failures, 5);
    assert_eq!(t.max_outstanding_exemptions, 0);
    assert!(!t.fail_on_trend_regression);
}

#[test]
fn enrichment_thresholds_default_serde_roundtrip() {
    let t = GovernanceScorecardThresholds::default();
    let json = serde_json::to_string(&t).unwrap();
    let back: GovernanceScorecardThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

// ===========================================================================
// GovernanceScorecardThresholds validate() edge cases
// ===========================================================================

#[test]
fn enrichment_thresholds_validate_receipt_coverage_over_million() {
    let mut req = test_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        min_attested_receipt_coverage_millionths: 1_000_001,
        ..GovernanceScorecardThresholds::default()
    });
    let result =
        publish_governance_scorecard(&req, &test_signing_key(), &mut test_ledger(), test_actor());
    assert!(result.is_err());
    if let Err(GovernanceScorecardError::InvalidInput { field, .. }) = &result {
        assert!(field.contains("min_attested_receipt_coverage"));
    }
}

#[test]
fn enrichment_thresholds_validate_privacy_consumption_over_million() {
    let mut req = test_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_privacy_epoch_consumption_millionths: 1_000_001,
        ..GovernanceScorecardThresholds::default()
    });
    let result =
        publish_governance_scorecard(&req, &test_signing_key(), &mut test_ledger(), test_actor());
    assert!(result.is_err());
    if let Err(GovernanceScorecardError::InvalidInput { field, .. }) = &result {
        assert!(field.contains("max_privacy_epoch_consumption"));
    }
}

#[test]
fn enrichment_thresholds_validate_moonshot_override_over_million() {
    let mut req = test_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_moonshot_override_frequency_millionths: 1_000_001,
        ..GovernanceScorecardThresholds::default()
    });
    let result =
        publish_governance_scorecard(&req, &test_signing_key(), &mut test_ledger(), test_actor());
    assert!(result.is_err());
}

#[test]
fn enrichment_thresholds_validate_moonshot_kill_rate_over_million() {
    let mut req = test_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_moonshot_kill_rate_millionths: 1_000_001,
        ..GovernanceScorecardThresholds::default()
    });
    let result =
        publish_governance_scorecard(&req, &test_signing_key(), &mut test_ledger(), test_actor());
    assert!(result.is_err());
}

#[test]
fn enrichment_thresholds_validate_conformance_pass_rate_over_million() {
    let mut req = test_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        min_conformance_pass_rate_millionths: 1_000_001,
        ..GovernanceScorecardThresholds::default()
    });
    let result =
        publish_governance_scorecard(&req, &test_signing_key(), &mut test_ledger(), test_actor());
    assert!(result.is_err());
}

#[test]
fn enrichment_thresholds_validate_at_boundary_million() {
    let mut req = test_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        min_attested_receipt_coverage_millionths: 1_000_000,
        max_privacy_epoch_consumption_millionths: 1_000_000,
        max_moonshot_override_frequency_millionths: 1_000_000,
        max_moonshot_kill_rate_millionths: 1_000_000,
        min_conformance_pass_rate_millionths: 1_000_000,
        ..GovernanceScorecardThresholds::default()
    });
    let result =
        publish_governance_scorecard(&req, &test_signing_key(), &mut test_ledger(), test_actor());
    assert!(result.is_ok());
}

// ===========================================================================
// GovernanceScorecardError Display
// ===========================================================================

#[test]
fn enrichment_error_display_invalid_input() {
    let err = GovernanceScorecardError::InvalidInput {
        field: "test_field".into(),
        detail: "test_detail".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("test_field"));
    assert!(msg.contains("test_detail"));
}

#[test]
fn enrichment_error_display_serialization_failure() {
    let err = GovernanceScorecardError::SerializationFailure("ser_msg".into());
    let msg = format!("{err}");
    assert!(msg.contains("ser_msg"));
}

#[test]
fn enrichment_error_display_signature_failure() {
    let err = GovernanceScorecardError::SignatureFailure("sig_msg".into());
    let msg = format!("{err}");
    assert!(msg.contains("sig_msg"));
}

#[test]
fn enrichment_error_display_ledger_write_failure() {
    let err = GovernanceScorecardError::LedgerWriteFailure("ledger_msg".into());
    let msg = format!("{err}");
    assert!(msg.contains("ledger_msg"));
}

// ===========================================================================
// GovernanceScorecardError stable_code
// ===========================================================================

#[test]
fn enrichment_error_stable_codes() {
    assert_eq!(
        GovernanceScorecardError::InvalidInput {
            field: "f".into(),
            detail: "d".into()
        }
        .stable_code(),
        "FE-GOV-SCORE-3001"
    );
    assert_eq!(
        GovernanceScorecardError::SerializationFailure("x".into()).stable_code(),
        "FE-GOV-SCORE-3002"
    );
    assert_eq!(
        GovernanceScorecardError::SignatureFailure("x".into()).stable_code(),
        "FE-GOV-SCORE-3003"
    );
    assert_eq!(
        GovernanceScorecardError::LedgerWriteFailure("x".into()).stable_code(),
        "FE-GOV-SCORE-3004"
    );
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_constant_component() {
    assert_eq!(GOVERNANCE_SCORECARD_COMPONENT, "governance_scorecard");
}

#[test]
fn enrichment_constant_schema_version() {
    assert!(!GOVERNANCE_SCORECARD_SCHEMA_VERSION.is_empty());
    assert!(GOVERNANCE_SCORECARD_SCHEMA_VERSION.starts_with("franken-engine."));
}

// ===========================================================================
// Serde roundtrips for subordinate types
// ===========================================================================

#[test]
fn enrichment_receipt_observation_serde_roundtrip() {
    let r = AttestedReceiptObservation {
        receipt_id: "r-100".into(),
        high_impact: true,
        attestation_binding_valid: true,
        timestamp_ns: 42_000,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: AttestedReceiptObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn enrichment_trend_point_serde_roundtrip() {
    let tp = GovernanceScorecardTrendPoint {
        scorecard_id: "sc-001".into(),
        generated_at_ns: 100_000,
        attested_receipt_coverage_millionths: 960_000,
        privacy_epoch_consumption_millionths: 200_000,
        moonshot_override_frequency_millionths: 50_000,
        conformance_pass_rate_millionths: 980_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    };
    let json = serde_json::to_string(&tp).unwrap();
    let back: GovernanceScorecardTrendPoint = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tp);
}

#[test]
fn enrichment_request_serde_roundtrip() {
    let req = test_request();
    let json = serde_json::to_string(&req).unwrap();
    let back: GovernanceScorecardRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, req);
}

// ===========================================================================
// Publish lifecycle
// ===========================================================================

#[test]
fn enrichment_publish_healthy_scorecard() {
    let req = test_request();
    let pub_result =
        publish_governance_scorecard(&req, &test_signing_key(), &mut test_ledger(), test_actor());
    assert!(pub_result.is_ok());
    let publication = pub_result.unwrap();
    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Healthy);
    assert!(!publication.artifact_hash_hex.is_empty());
    assert!(publication.blockers.is_empty());
}

#[test]
fn enrichment_publish_signature_verifies() {
    let req = test_request();
    let publication =
        publish_governance_scorecard(&req, &test_signing_key(), &mut test_ledger(), test_actor())
            .unwrap();
    assert!(verify_governance_scorecard_signature(&publication).is_ok());
}

#[test]
fn enrichment_publish_deterministic() {
    let req = test_request();
    let key = test_signing_key();
    let pub1 = publish_governance_scorecard(&req, &key, &mut test_ledger(), test_actor()).unwrap();
    let pub2 = publish_governance_scorecard(&req, &key, &mut test_ledger(), test_actor()).unwrap();
    assert_eq!(pub1.scorecard_id, pub2.scorecard_id);
    assert_eq!(pub1.artifact_hash_hex, pub2.artifact_hash_hex);
}

#[test]
fn enrichment_publish_critical_low_coverage() {
    let mut req = test_request();
    for r in &mut req.attested_receipts {
        if r.high_impact {
            r.attestation_binding_valid = false;
        }
    }
    let publication =
        publish_governance_scorecard(&req, &test_signing_key(), &mut test_ledger(), test_actor())
            .unwrap();
    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
    assert!(!publication.blockers.is_empty());
}
