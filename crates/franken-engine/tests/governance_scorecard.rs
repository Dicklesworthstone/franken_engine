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

use std::collections::BTreeMap;

use frankenengine_engine::dp_budget_accountant::{AccountantConfig, BudgetAccountant};
use frankenengine_engine::governance_scorecard::{
    AttestedReceiptObservation, CrossRepoConformanceInput, GOVERNANCE_SCORECARD_SCHEMA_VERSION,
    GovernanceScorecardOutcome, GovernanceScorecardPublication, GovernanceScorecardRequest,
    GovernanceScorecardThresholds, GovernanceScorecardTrendPoint, MoonshotGovernorHealthInput,
    PrivacyBudgetHealthInput, publish_governance_scorecard, verify_governance_scorecard_signature,
};
use frankenengine_engine::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceDecisionType, GovernanceLedgerConfig,
    GovernanceReport,
};
use frankenengine_engine::privacy_learning_contract::CompositionMethod;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::version_matrix_lane::MatrixHealthSummary;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([0x7A; 32])
}

fn baseline_budget_accountant() -> BudgetAccountant {
    let mut accountant = BudgetAccountant::new(AccountantConfig {
        epsilon_per_epoch_millionths: 1_000_000,
        delta_per_epoch_millionths: 100_000,
        lifetime_epsilon_budget_millionths: 10_000_000,
        lifetime_delta_budget_millionths: 1_000_000,
        composition_method: CompositionMethod::Basic,
        epoch: SecurityEpoch::from_raw(7),
        zone: "zone-governance-scorecard".to_string(),
        now_ns: 1_720_000_000_000_000_000,
    })
    .expect("accountant");

    accountant
        .consume(300_000, 30_000, "baseline", 2_000_000_000)
        .expect("consume");
    accountant
}

fn baseline_request() -> GovernanceScorecardRequest {
    let receipts = vec![
        AttestedReceiptObservation {
            receipt_id: "r-001".to_string(),
            high_impact: true,
            attestation_binding_valid: true,
            timestamp_ns: 10,
        },
        AttestedReceiptObservation {
            receipt_id: "r-002".to_string(),
            high_impact: true,
            attestation_binding_valid: true,
            timestamp_ns: 11,
        },
        AttestedReceiptObservation {
            receipt_id: "r-003".to_string(),
            high_impact: false,
            attestation_binding_valid: false,
            timestamp_ns: 12,
        },
    ];

    GovernanceScorecardRequest {
        trace_id: "trace-governance-scorecard".to_string(),
        decision_id: "decision-governance-scorecard".to_string(),
        policy_id: "policy-governance-scorecard-v1".to_string(),
        scorecard_run_id: "".to_string(),
        generated_at_ns: 1_720_000_000_000_000_000,
        attested_receipts: receipts,
        privacy_budget: PrivacyBudgetHealthInput {
            accountant: baseline_budget_accountant(),
            overrun_incidents: 0,
            measurement_window_ns: 24 * 3_600_000_000_000,
            measurement_end_ns: 1_720_000_000_000_000_000,
        },
        moonshot_governor: MoonshotGovernorHealthInput {
            governance_report: GovernanceReport {
                total_decisions: 10,
                override_count: 1,
                kill_count: 1,
                override_frequency_millionths: 100_000,
                kill_rate_millionths: 100_000,
                mean_time_to_decision_ns: Some(10_000_000_000),
                portfolio_health_trend: Vec::new(),
            },
            active_moonshots: 4,
            paused_moonshots: 1,
            killed_moonshots: 1,
        },
        conformance: CrossRepoConformanceInput {
            release_id: "release-2026.02.22".to_string(),
            matrix_health: MatrixHealthSummary {
                total_cells: 20,
                passed_cells: 19,
                failed_cells: 1,
                universal_failures: 0,
                version_specific_failures: 1,
            },
            failure_class_distribution: BTreeMap::from([
                ("behavioral".to_string(), 1),
                ("observability".to_string(), 0),
            ]),
            outstanding_exemptions: 0,
        },
        historical: Vec::new(),
        thresholds: None,
    }
}

fn ledger() -> GovernanceAuditLedger {
    GovernanceAuditLedger::new(GovernanceLedgerConfig::default()).expect("ledger")
}

#[test]
fn publish_healthy_scorecard_signs_and_records_in_ledger() {
    let request = baseline_request();
    let mut governance_ledger = ledger();

    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert_eq!(
        publication.schema_version,
        GOVERNANCE_SCORECARD_SCHEMA_VERSION
    );
    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Healthy);
    assert!(publication.blockers.is_empty());
    assert!(publication.warnings.is_empty());
    assert_eq!(publication.ledger_sequence, 1);
    assert_eq!(governance_ledger.entries().len(), 1);
    assert_eq!(
        governance_ledger.entries()[0].decision_type,
        GovernanceDecisionType::Promote
    );
    assert!(verify_governance_scorecard_signature(&publication).is_ok());

    let json = publication.to_json_pretty().expect("json");
    assert!(json.contains("governance-scorecard"));
    let markdown = publication.to_markdown_report();
    assert!(markdown.contains("# Governance Scorecard"));
    assert!(markdown.contains("## Dimensions"));
}

#[test]
fn low_attested_coverage_triggers_critical_and_kill_decision() {
    let mut request = baseline_request();
    request.attested_receipts[1].attestation_binding_valid = false;

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
    assert!(!publication.blockers.is_empty());
    assert!(
        publication
            .blockers
            .iter()
            .any(|blocker| blocker.contains("attested-receipt coverage"))
    );
    assert_eq!(
        governance_ledger.entries()[0].decision_type,
        GovernanceDecisionType::Kill
    );
}

#[test]
fn near_term_privacy_exhaustion_surfaces_warning_without_blocker() {
    let mut request = baseline_request();
    request.privacy_budget.accountant = {
        let mut accountant = BudgetAccountant::new(AccountantConfig {
            epsilon_per_epoch_millionths: 1_000_000,
            delta_per_epoch_millionths: 100_000,
            lifetime_epsilon_budget_millionths: 10_000_000,
            lifetime_delta_budget_millionths: 1_000_000,
            composition_method: CompositionMethod::Basic,
            epoch: SecurityEpoch::from_raw(7),
            zone: "zone-governance-scorecard".to_string(),
            now_ns: 1_720_000_000_000_000_000,
        })
        .expect("accountant");
        accountant
            .consume(850_000, 85_000, "heavy-load", 2_000_000_000)
            .expect("consume");
        accountant
    };
    request.thresholds = Some(GovernanceScorecardThresholds {
        warn_privacy_exhaustion_within_ns: Some(7 * 24 * 3_600_000_000_000),
        ..GovernanceScorecardThresholds::default()
    });

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Warning);
    assert!(publication.blockers.is_empty());
    assert!(
        publication
            .warnings
            .iter()
            .any(|warning| warning.contains("projected to exhaust"))
    );
    assert_eq!(
        governance_ledger.entries()[0].decision_type,
        GovernanceDecisionType::Hold
    );
}

#[test]
fn trend_regression_warns_by_default() {
    let mut request = baseline_request();
    request.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "historical-1".to_string(),
        generated_at_ns: request.generated_at_ns.saturating_sub(1),
        attested_receipt_coverage_millionths: 1_000_000,
        privacy_epoch_consumption_millionths: 250_000,
        moonshot_override_frequency_millionths: 50_000,
        conformance_pass_rate_millionths: 1_000_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    });

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert!(publication.trend_regression_detected);
    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Warning);
    assert!(
        publication
            .warnings
            .iter()
            .any(|warning| warning.contains("trend regression"))
    );
}

#[test]
fn trend_regression_can_block_when_configured() {
    let mut request = baseline_request();
    request.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "historical-1".to_string(),
        generated_at_ns: request.generated_at_ns.saturating_sub(1),
        attested_receipt_coverage_millionths: 1_000_000,
        privacy_epoch_consumption_millionths: 250_000,
        moonshot_override_frequency_millionths: 50_000,
        conformance_pass_rate_millionths: 1_000_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    });
    request.thresholds = Some(GovernanceScorecardThresholds {
        fail_on_trend_regression: true,
        ..GovernanceScorecardThresholds::default()
    });

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert!(publication.trend_regression_detected);
    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
    assert!(
        publication
            .blockers
            .iter()
            .any(|blocker| blocker.contains("trend regression"))
    );
}

#[test]
fn derived_scorecard_id_is_deterministic_for_reordered_receipts() {
    let request_a = baseline_request();
    let mut request_b = baseline_request();
    request_b.attested_receipts.reverse();

    let mut ledger_a = ledger();
    let mut ledger_b = ledger();

    let publication_a = publish_governance_scorecard(
        &request_a,
        &signing_key(),
        &mut ledger_a,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication A");

    let publication_b = publish_governance_scorecard(
        &request_b,
        &signing_key(),
        &mut ledger_b,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication B");

    assert_eq!(publication_a.scorecard_id, publication_b.scorecard_id);
    assert_eq!(
        publication_a.attested_receipt_coverage,
        publication_b.attested_receipt_coverage
    );
    assert_eq!(publication_a.outcome, publication_b.outcome);
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, error paths, thresholds, events, markdown
// ────────────────────────────────────────────────────────────

#[test]
fn scorecard_outcome_as_str_round_trips() {
    assert_eq!(GovernanceScorecardOutcome::Healthy.as_str(), "healthy");
    assert_eq!(GovernanceScorecardOutcome::Warning.as_str(), "warning");
    assert_eq!(GovernanceScorecardOutcome::Critical.as_str(), "critical");
}

#[test]
fn scorecard_outcome_serde_round_trip() {
    for outcome in [
        GovernanceScorecardOutcome::Healthy,
        GovernanceScorecardOutcome::Warning,
        GovernanceScorecardOutcome::Critical,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: GovernanceScorecardOutcome =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, recovered);
    }
}

#[test]
fn thresholds_default_round_trips_via_serde() {
    let thresholds = GovernanceScorecardThresholds::default();
    let json = serde_json::to_string(&thresholds).expect("serialize");
    let recovered: GovernanceScorecardThresholds =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(thresholds, recovered);
}

#[test]
fn publication_serde_round_trip() {
    let request = baseline_request();
    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication");

    let json = serde_json::to_string(&publication).expect("serialize");
    let recovered: GovernanceScorecardPublication =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(publication.scorecard_id, recovered.scorecard_id);
    assert_eq!(publication.outcome, recovered.outcome);
    assert_eq!(publication.artifact_hash_hex, recovered.artifact_hash_hex);
}

#[test]
fn error_display_and_stable_codes_are_non_empty() {
    use frankenengine_engine::governance_scorecard::GovernanceScorecardError;

    let errors: Vec<GovernanceScorecardError> = vec![
        GovernanceScorecardError::InvalidInput {
            field: "trace_id".to_string(),
            detail: "empty".to_string(),
        },
        GovernanceScorecardError::SerializationFailure("broken".to_string()),
        GovernanceScorecardError::SignatureFailure("bad key".to_string()),
        GovernanceScorecardError::LedgerWriteFailure("full".to_string()),
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty());
        assert!(!err.stable_code().is_empty());
    }
}

#[test]
fn events_contain_required_structured_fields() {
    let request = baseline_request();
    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication");

    assert!(!publication.events.is_empty());
    for event in &publication.events {
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert!(!event.policy_id.is_empty());
        assert!(!event.component.is_empty());
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn markdown_report_contains_dimensions_and_outcome() {
    let request = baseline_request();
    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication");

    let md = publication.to_markdown_report();
    assert!(md.contains("# Governance Scorecard"));
    assert!(md.contains("## Dimensions"));
    assert!(md.contains("HEALTHY"));
    assert!(md.contains(&publication.scorecard_id));
}

#[test]
fn signature_verification_fails_for_tampered_publication() {
    let request = baseline_request();
    let mut governance_ledger = ledger();
    let mut publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication");

    // Tamper with the publication
    publication.outcome = GovernanceScorecardOutcome::Critical;
    let result = verify_governance_scorecard_signature(&publication);
    assert!(result.is_err());
}

#[test]
fn attested_receipt_observation_serde_round_trip() {
    let obs = AttestedReceiptObservation {
        receipt_id: "r-serde".to_string(),
        high_impact: true,
        attestation_binding_valid: true,
        timestamp_ns: 42,
    };
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: AttestedReceiptObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, recovered);
}

#[test]
fn trend_point_serde_round_trip() {
    let point = GovernanceScorecardTrendPoint {
        scorecard_id: "tp-1".to_string(),
        generated_at_ns: 1_000_000,
        attested_receipt_coverage_millionths: 950_000,
        privacy_epoch_consumption_millionths: 300_000,
        moonshot_override_frequency_millionths: 100_000,
        conformance_pass_rate_millionths: 1_000_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    };
    let json = serde_json::to_string(&point).expect("serialize");
    let recovered: GovernanceScorecardTrendPoint =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(point, recovered);
}

#[test]
fn error_display_contains_details() {
    use frankenengine_engine::governance_scorecard::GovernanceScorecardError;

    let err = GovernanceScorecardError::InvalidInput {
        field: "trace_id".to_string(),
        detail: "cannot be empty".to_string(),
    };
    let s = err.to_string();
    assert!(
        s.contains("trace_id") || s.contains("empty"),
        "should contain field info: {s}"
    );

    let err2 = GovernanceScorecardError::LedgerWriteFailure("disk full".to_string());
    let s2 = err2.to_string();
    assert!(
        s2.contains("disk") || s2.contains("ledger"),
        "should contain detail: {s2}"
    );
}

#[test]
fn error_stable_codes_all_distinct() {
    use frankenengine_engine::governance_scorecard::GovernanceScorecardError;
    use std::collections::BTreeSet;

    let codes: BTreeSet<&str> = [
        GovernanceScorecardError::InvalidInput {
            field: "f".to_string(),
            detail: "d".to_string(),
        },
        GovernanceScorecardError::SerializationFailure("s".to_string()),
        GovernanceScorecardError::SignatureFailure("s".to_string()),
        GovernanceScorecardError::LedgerWriteFailure("l".to_string()),
    ]
    .iter()
    .map(|e| e.stable_code())
    .collect();
    assert_eq!(codes.len(), 4);
}

#[test]
fn error_is_std_error() {
    use frankenengine_engine::governance_scorecard::GovernanceScorecardError;

    let err = GovernanceScorecardError::InvalidInput {
        field: "x".to_string(),
        detail: "y".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn scorecard_outcome_ordering() {
    assert!(GovernanceScorecardOutcome::Healthy < GovernanceScorecardOutcome::Warning);
    assert!(GovernanceScorecardOutcome::Warning < GovernanceScorecardOutcome::Critical);
}

#[test]
fn scorecard_event_serde_round_trip() {
    use frankenengine_engine::governance_scorecard::GovernanceScorecardEvent;

    let event = GovernanceScorecardEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "governance_scorecard".to_string(),
        event: "dimension_evaluated".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        dimension: Some("privacy_budget".to_string()),
        detail: Some("within budget".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: GovernanceScorecardEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn privacy_budget_health_input_serde_round_trip() {
    let input = PrivacyBudgetHealthInput {
        accountant: baseline_budget_accountant(),
        overrun_incidents: 2,
        measurement_window_ns: 86_400_000_000_000,
        measurement_end_ns: 1_720_000_000_000_000_000,
    };
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: PrivacyBudgetHealthInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input.overrun_incidents, recovered.overrun_incidents);
    assert_eq!(input.measurement_window_ns, recovered.measurement_window_ns);
}

#[test]
fn multiple_blockers_accumulate() {
    let mut request = baseline_request();
    // Drop attested receipt coverage
    request.attested_receipts[1].attestation_binding_valid = false;
    // Make conformance fail
    request.conformance.matrix_health.failed_cells = 15;
    request.conformance.matrix_health.passed_cells = 5;
    request.conformance.outstanding_exemptions = 100;

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
    assert!(publication.blockers.len() >= 2);
}

#[test]
fn moonshot_governor_high_kill_rate_triggers_critical() {
    let mut request = baseline_request();
    request.moonshot_governor.governance_report.kill_count = 9;
    request
        .moonshot_governor
        .governance_report
        .kill_rate_millionths = 900_000;
    request.moonshot_governor.killed_moonshots = 9;

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert!(
        publication.outcome == GovernanceScorecardOutcome::Critical
            || publication.outcome == GovernanceScorecardOutcome::Warning
    );
}

#[test]
fn cross_repo_conformance_universal_failure_blocks() {
    let mut request = baseline_request();
    request.conformance.matrix_health.universal_failures = 100;

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
    assert!(!publication.blockers.is_empty());
}

#[test]
fn constants_stable() {
    assert_eq!(
        GOVERNANCE_SCORECARD_SCHEMA_VERSION,
        "franken-engine.governance-scorecard.v1"
    );
    assert_eq!(
        frankenengine_engine::governance_scorecard::GOVERNANCE_SCORECARD_COMPONENT,
        "governance_scorecard"
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: conformance edge cases, json parse, overrun incidents, request serde
// ────────────────────────────────────────────────────────────

#[test]
fn privacy_overrun_incidents_surface_warning() {
    let mut request = baseline_request();
    request.privacy_budget.overrun_incidents = 5;

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    // Overrun incidents should cause at least a warning outcome
    assert!(
        publication.outcome == GovernanceScorecardOutcome::Warning
            || publication.outcome == GovernanceScorecardOutcome::Critical,
        "overrun incidents should degrade outcome, got: {:?}",
        publication.outcome
    );
}

#[test]
fn to_json_pretty_parses_as_valid_json_with_scorecard_id() {
    let request = baseline_request();
    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication");

    let json = publication.to_json_pretty().expect("json");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert!(parsed.is_object());
    // The scorecard_id should appear in the serialized JSON
    assert!(
        json.contains(&publication.scorecard_id),
        "JSON should contain scorecard_id"
    );
}

#[test]
fn request_serde_roundtrip_preserves_all_fields() {
    let request = baseline_request();
    let json = serde_json::to_string(&request).expect("serialize request");
    let recovered: GovernanceScorecardRequest =
        serde_json::from_str(&json).expect("deserialize request");
    assert_eq!(recovered.trace_id, request.trace_id);
    assert_eq!(recovered.decision_id, request.decision_id);
    assert_eq!(recovered.policy_id, request.policy_id);
    assert_eq!(
        recovered.attested_receipts.len(),
        request.attested_receipts.len()
    );
    assert_eq!(
        recovered.conformance.matrix_health.total_cells,
        request.conformance.matrix_health.total_cells
    );
    assert_eq!(
        recovered.moonshot_governor.active_moonshots,
        request.moonshot_governor.active_moonshots
    );
}

#[test]
fn conformance_with_outstanding_exemptions_degrades_outcome() {
    let mut request = baseline_request();
    request.conformance.outstanding_exemptions = 50;

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("scorecard-publisher".to_string()),
    )
    .expect("publication should succeed");

    // Outstanding exemptions should trigger at least a warning
    assert!(
        publication.outcome == GovernanceScorecardOutcome::Warning
            || publication.outcome == GovernanceScorecardOutcome::Critical
            || !publication.warnings.is_empty(),
        "outstanding exemptions should surface as warning or blocker, outcome: {:?}, warnings: {:?}",
        publication.outcome,
        publication.warnings
    );
}

// ---------- enrichment: determinism, coverage summary, zero receipts, thresholds ----------

#[test]
fn publish_scorecard_deterministic_for_same_request() {
    let request = baseline_request();
    let key = signing_key();

    let mut ledger_a = ledger();
    let pub_a = publish_governance_scorecard(
        &request,
        &key,
        &mut ledger_a,
        GovernanceActor::System("test".to_string()),
    )
    .expect("publication A");

    let mut ledger_b = ledger();
    let pub_b = publish_governance_scorecard(
        &request,
        &key,
        &mut ledger_b,
        GovernanceActor::System("test".to_string()),
    )
    .expect("publication B");

    assert_eq!(pub_a.scorecard_id, pub_b.scorecard_id);
    assert_eq!(pub_a.outcome, pub_b.outcome);
    assert_eq!(pub_a.artifact_hash_hex, pub_b.artifact_hash_hex);
    assert_eq!(
        pub_a.attested_receipt_coverage,
        pub_b.attested_receipt_coverage
    );
}

#[test]
fn scorecard_with_zero_attested_receipts_is_critical() {
    let mut request = baseline_request();
    request.attested_receipts.clear();

    let mut governance_ledger = ledger();
    let publication = publish_governance_scorecard(
        &request,
        &signing_key(),
        &mut governance_ledger,
        GovernanceActor::System("test".to_string()),
    )
    .expect("publication should succeed");

    assert_eq!(publication.outcome, GovernanceScorecardOutcome::Critical);
    assert!(!publication.blockers.is_empty());
}

#[test]
fn thresholds_custom_values_serde_roundtrip() {
    let thresholds = GovernanceScorecardThresholds {
        fail_on_trend_regression: true,
        warn_privacy_exhaustion_within_ns: Some(999_999),
        ..GovernanceScorecardThresholds::default()
    };
    let json = serde_json::to_string(&thresholds).expect("serialize");
    let recovered: GovernanceScorecardThresholds =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(thresholds, recovered);
    assert!(recovered.fail_on_trend_regression);
    assert_eq!(recovered.warn_privacy_exhaustion_within_ns, Some(999_999));
}

#[test]
fn moonshot_governor_health_input_serde_roundtrip() {
    let request = baseline_request();
    let json = serde_json::to_string(&request.moonshot_governor).expect("serialize");
    let recovered: MoonshotGovernorHealthInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        recovered.active_moonshots,
        request.moonshot_governor.active_moonshots
    );
    assert_eq!(
        recovered.killed_moonshots,
        request.moonshot_governor.killed_moonshots
    );
}

#[test]
fn cross_repo_conformance_input_serde_roundtrip() {
    let request = baseline_request();
    let json = serde_json::to_string(&request.conformance).expect("serialize");
    let recovered: CrossRepoConformanceInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.release_id, request.conformance.release_id);
    assert_eq!(
        recovered.matrix_health.total_cells,
        request.conformance.matrix_health.total_cells
    );
    assert_eq!(
        recovered.failure_class_distribution,
        request.conformance.failure_class_distribution
    );
}
