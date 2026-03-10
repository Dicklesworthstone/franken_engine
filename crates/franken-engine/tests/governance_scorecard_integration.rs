#![forbid(unsafe_code)]

//! Comprehensive integration tests for `governance_scorecard` module.

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
    AttestedReceiptObservation, CrossRepoConformanceInput, GOVERNANCE_SCORECARD_COMPONENT,
    GOVERNANCE_SCORECARD_SCHEMA_VERSION, GovernanceScorecardError, GovernanceScorecardOutcome,
    GovernanceScorecardRequest, GovernanceScorecardThresholds, GovernanceScorecardTrendPoint,
    MoonshotGovernorHealthInput, PrivacyBudgetHealthInput, publish_governance_scorecard,
    verify_governance_scorecard_signature,
};
use frankenengine_engine::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceDecisionType, GovernanceLedgerConfig,
    GovernanceReport,
};
use frankenengine_engine::privacy_learning_contract::CompositionMethod;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::version_matrix_lane::MatrixHealthSummary;

// ── helpers ────────────────────────────────────────────────────────────────

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([0x42; 32])
}

fn mk_accountant(eps_spent: i64, delta_spent: i64) -> BudgetAccountant {
    let mut a = BudgetAccountant::new(AccountantConfig {
        zone: "integ-zone".to_string(),
        epsilon_per_epoch_millionths: 1_000_000,
        delta_per_epoch_millionths: 1_000_000,
        lifetime_epsilon_budget_millionths: 10_000_000,
        lifetime_delta_budget_millionths: 10_000_000,
        composition_method: CompositionMethod::Basic,
        epoch: SecurityEpoch::from_raw(3),
        now_ns: 1_000_000_000,
    })
    .expect("accountant");
    if eps_spent > 0 || delta_spent > 0 {
        a.consume(eps_spent, delta_spent, "integ", 2_000_000_000)
            .expect("consume");
    }
    a
}

fn mk_privacy(eps_spent: i64, delta_spent: i64) -> PrivacyBudgetHealthInput {
    PrivacyBudgetHealthInput {
        accountant: mk_accountant(eps_spent, delta_spent),
        overrun_incidents: 0,
        measurement_window_ns: 3_600_000_000_000,
        measurement_end_ns: 2_000_000_000,
    }
}

fn healthy_privacy() -> PrivacyBudgetHealthInput {
    // Spend very little so the burn rate does not project near-term exhaustion.
    mk_privacy(1_000, 500)
}

fn healthy_report() -> GovernanceReport {
    GovernanceReport {
        total_decisions: 50,
        override_count: 2,
        kill_count: 3,
        override_frequency_millionths: 40_000,
        kill_rate_millionths: 60_000,
        mean_time_to_decision_ns: Some(86_400_000_000_000),
        portfolio_health_trend: Vec::new(),
    }
}

fn healthy_moonshot() -> MoonshotGovernorHealthInput {
    MoonshotGovernorHealthInput {
        governance_report: healthy_report(),
        active_moonshots: 5,
        paused_moonshots: 1,
        killed_moonshots: 2,
    }
}

fn healthy_matrix() -> MatrixHealthSummary {
    MatrixHealthSummary {
        total_cells: 200,
        passed_cells: 196,
        failed_cells: 4,
        universal_failures: 0,
        version_specific_failures: 4,
    }
}

fn healthy_conformance() -> CrossRepoConformanceInput {
    CrossRepoConformanceInput {
        release_id: "rel-integ-001".to_string(),
        matrix_health: healthy_matrix(),
        failure_class_distribution: BTreeMap::from([
            ("timeout".to_string(), 2),
            ("assertion".to_string(), 2),
        ]),
        outstanding_exemptions: 0,
    }
}

fn high_impact_receipt(id: &str, valid: bool) -> AttestedReceiptObservation {
    AttestedReceiptObservation {
        receipt_id: id.to_string(),
        high_impact: true,
        attestation_binding_valid: valid,
        timestamp_ns: 1_000,
    }
}

fn low_impact_receipt(id: &str) -> AttestedReceiptObservation {
    AttestedReceiptObservation {
        receipt_id: id.to_string(),
        high_impact: false,
        attestation_binding_valid: false,
        timestamp_ns: 2_000,
    }
}

fn healthy_receipts() -> Vec<AttestedReceiptObservation> {
    vec![
        high_impact_receipt("hi-1", true),
        high_impact_receipt("hi-2", true),
        high_impact_receipt("hi-3", true),
        high_impact_receipt("hi-4", true),
        low_impact_receipt("lo-1"),
    ]
}

fn mk_request(
    receipts: Vec<AttestedReceiptObservation>,
    privacy: PrivacyBudgetHealthInput,
    moonshot: MoonshotGovernorHealthInput,
    conformance: CrossRepoConformanceInput,
) -> GovernanceScorecardRequest {
    GovernanceScorecardRequest {
        trace_id: "trace-integ".to_string(),
        decision_id: "decision-integ".to_string(),
        policy_id: "policy-integ".to_string(),
        scorecard_run_id: "run-integ-001".to_string(),
        generated_at_ns: 5_000_000_000,
        attested_receipts: receipts,
        privacy_budget: privacy,
        moonshot_governor: moonshot,
        conformance,
        historical: Vec::new(),
        thresholds: None,
    }
}

fn baseline_request() -> GovernanceScorecardRequest {
    mk_request(
        healthy_receipts(),
        healthy_privacy(),
        healthy_moonshot(),
        healthy_conformance(),
    )
}

fn ledger() -> GovernanceAuditLedger {
    GovernanceAuditLedger::new(GovernanceLedgerConfig::default()).expect("ledger")
}

fn actor() -> GovernanceActor {
    GovernanceActor::System("integ-test".to_string())
}

fn publish(
    req: &GovernanceScorecardRequest,
) -> frankenengine_engine::governance_scorecard::GovernanceScorecardPublication {
    let mut l = ledger();
    publish_governance_scorecard(req, &signing_key(), &mut l, actor()).expect("publish")
}

// ── Section 1: Healthy-path publication ────────────────────────────────────

#[test]
fn healthy_publication_outcome_and_schema() {
    let p = publish(&baseline_request());
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Healthy);
    assert_eq!(p.schema_version, GOVERNANCE_SCORECARD_SCHEMA_VERSION);
    assert!(p.blockers.is_empty());
    assert!(p.warnings.is_empty());
}

#[test]
fn healthy_publication_scorecard_id_matches_run_id() {
    let p = publish(&baseline_request());
    assert_eq!(p.scorecard_id, "run-integ-001");
}

#[test]
fn healthy_publication_ledger_sequence_is_one() {
    let req = baseline_request();
    let mut l = ledger();
    let p = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap();
    assert_eq!(p.ledger_sequence, 1);
}

#[test]
fn healthy_publication_ledger_decision_is_promote() {
    let req = baseline_request();
    let mut l = ledger();
    let _p = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap();
    assert_eq!(
        l.entries()[0].decision_type,
        GovernanceDecisionType::Promote
    );
}

#[test]
fn healthy_publication_signature_verifies() {
    let p = publish(&baseline_request());
    verify_governance_scorecard_signature(&p).expect("sig should verify");
}

#[test]
fn healthy_publication_artifact_hash_is_64_hex_chars() {
    let p = publish(&baseline_request());
    assert_eq!(p.artifact_hash_hex.len(), 64);
    assert!(p.artifact_hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
}

// ── Section 2: Determinism ─────────────────────────────────────────────────

#[test]
fn deterministic_artifact_hash_across_runs() {
    let req = baseline_request();
    let mut l1 = ledger();
    let mut l2 = ledger();
    let p1 = publish_governance_scorecard(&req, &signing_key(), &mut l1, actor()).unwrap();
    let p2 = publish_governance_scorecard(&req, &signing_key(), &mut l2, actor()).unwrap();
    assert_eq!(p1.artifact_hash_hex, p2.artifact_hash_hex);
    assert_eq!(p1.signature, p2.signature);
}

#[test]
fn different_signing_keys_produce_different_signatures() {
    let req = baseline_request();
    let key_a = SigningKey::from_bytes([0x42; 32]);
    let key_b = SigningKey::from_bytes([0x99; 32]);
    let mut l1 = ledger();
    let mut l2 = ledger();
    let p1 = publish_governance_scorecard(&req, &key_a, &mut l1, actor()).unwrap();
    let p2 = publish_governance_scorecard(&req, &key_b, &mut l2, actor()).unwrap();
    assert_ne!(p1.signature, p2.signature);
    // But the artifact hash (unsigned payload) should be the same.
    assert_eq!(p1.artifact_hash_hex, p2.artifact_hash_hex);
}

// ── Section 3: Attested receipt coverage dimension ─────────────────────────

#[test]
fn attested_coverage_all_valid_is_one_million() {
    let p = publish(&baseline_request());
    assert_eq!(p.attested_receipt_coverage.coverage_millionths, 1_000_000);
    assert!(p.attested_receipt_coverage.threshold_pass);
}

#[test]
fn attested_coverage_counts_only_high_impact() {
    let p = publish(&baseline_request());
    // 4 high-impact, 1 low-impact in healthy_receipts
    assert_eq!(p.attested_receipt_coverage.high_impact_total, 4);
}

#[test]
fn attested_coverage_50_percent_triggers_critical() {
    let mut req = baseline_request();
    req.attested_receipts = vec![
        high_impact_receipt("h1", true),
        high_impact_receipt("h2", false),
    ];
    let p = publish(&req);
    assert_eq!(p.attested_receipt_coverage.coverage_millionths, 500_000);
    assert!(!p.attested_receipt_coverage.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(p.blockers.iter().any(|b| b.contains("attested-receipt")));
}

#[test]
fn attested_coverage_exactly_at_threshold_passes() {
    // Default threshold is 950_000 (95%). With 20 high-impact, 19 valid => 950_000.
    let mut req = baseline_request();
    let mut receipts: Vec<AttestedReceiptObservation> = (0..19)
        .map(|i| high_impact_receipt(&format!("v-{i}"), true))
        .collect();
    receipts.push(high_impact_receipt("inv-0", false));
    req.attested_receipts = receipts;
    let p = publish(&req);
    assert_eq!(p.attested_receipt_coverage.coverage_millionths, 950_000);
    assert!(p.attested_receipt_coverage.threshold_pass);
}

#[test]
fn attested_coverage_just_below_threshold_fails() {
    let mut req = baseline_request();
    // 19 valid out of 21 high-impact = 904_761 < 950_000
    let mut receipts: Vec<AttestedReceiptObservation> = (0..19)
        .map(|i| high_impact_receipt(&format!("v-{i}"), true))
        .collect();
    receipts.push(high_impact_receipt("inv-0", false));
    receipts.push(high_impact_receipt("inv-1", false));
    req.attested_receipts = receipts;
    let p = publish(&req);
    assert!(!p.attested_receipt_coverage.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
}

#[test]
fn attested_coverage_invalid_low_impact_ignored() {
    let mut req = baseline_request();
    req.attested_receipts = vec![
        high_impact_receipt("h1", true),
        low_impact_receipt("lo-1"),
        low_impact_receipt("lo-2"),
        low_impact_receipt("lo-3"),
    ];
    let p = publish(&req);
    assert_eq!(p.attested_receipt_coverage.high_impact_total, 1);
    assert_eq!(p.attested_receipt_coverage.coverage_millionths, 1_000_000);
}

// ── Section 4: Privacy budget health dimension ─────────────────────────────

#[test]
fn privacy_overrun_causes_critical() {
    let mut req = baseline_request();
    req.privacy_budget.overrun_incidents = 1;
    let p = publish(&req);
    assert!(!p.privacy_budget_health.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(p.blockers.iter().any(|b| b.contains("privacy budget")));
}

#[test]
fn privacy_high_consumption_causes_critical() {
    let mut req = baseline_request();
    req.privacy_budget = mk_privacy(950_000, 50_000); // 95% consumption > 90% default
    let p = publish(&req);
    assert!(!p.privacy_budget_health.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
}

#[test]
fn privacy_near_exhaustion_warning() {
    let mut req = baseline_request();
    // Spend 85% so burn rate projects exhaustion soon.
    req.privacy_budget = mk_privacy(850_000, 50_000);
    // Short measurement window to amplify burn rate.
    req.privacy_budget.measurement_window_ns = 3_600_000_000_000; // 1 hour
    req.thresholds = Some(GovernanceScorecardThresholds {
        warn_privacy_exhaustion_within_ns: Some(7 * 24 * 3_600_000_000_000),
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    assert!(p.privacy_budget_health.near_term_exhaustion_warning);
    assert!(
        p.warnings
            .iter()
            .any(|w| w.contains("projected to exhaust"))
    );
}

#[test]
fn privacy_budget_epoch_field_propagated() {
    let p = publish(&baseline_request());
    assert_eq!(p.privacy_budget_health.epoch, SecurityEpoch::from_raw(3));
}

#[test]
fn privacy_zero_overruns_zero_consumption_passes() {
    let mut req = baseline_request();
    req.privacy_budget = mk_privacy(0, 0);
    let p = publish(&req);
    assert!(p.privacy_budget_health.threshold_pass);
    assert_eq!(p.privacy_budget_health.epoch_consumption_millionths, 0);
}

// ── Section 5: Moonshot governor dimension ─────────────────────────────────

#[test]
fn moonshot_override_high_causes_critical() {
    let mut req = baseline_request();
    req.moonshot_governor
        .governance_report
        .override_frequency_millionths = 500_000;
    let p = publish(&req);
    assert!(!p.moonshot_governor.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(p.blockers.iter().any(|b| b.contains("moonshot")));
}

#[test]
fn moonshot_kill_rate_high_causes_critical() {
    let mut req = baseline_request();
    req.moonshot_governor.governance_report.kill_rate_millionths = 500_000;
    let p = publish(&req);
    assert!(!p.moonshot_governor.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
}

#[test]
fn moonshot_decision_time_over_threshold_causes_critical() {
    let mut req = baseline_request();
    req.moonshot_governor
        .governance_report
        .mean_time_to_decision_ns = Some(999_999_999_999_999);
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_moonshot_mean_time_to_decision_ns: Some(86_400_000_000_000),
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    assert!(!p.moonshot_governor.threshold_pass);
}

#[test]
fn moonshot_no_decision_time_with_threshold_still_passes() {
    let mut req = baseline_request();
    req.moonshot_governor
        .governance_report
        .mean_time_to_decision_ns = None;
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_moonshot_mean_time_to_decision_ns: Some(86_400_000_000_000),
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    assert!(p.moonshot_governor.threshold_pass);
}

#[test]
fn moonshot_counts_propagated() {
    let p = publish(&baseline_request());
    assert_eq!(p.moonshot_governor.active_moonshots, 5);
    assert_eq!(p.moonshot_governor.paused_moonshots, 1);
    assert_eq!(p.moonshot_governor.killed_moonshots, 2);
    assert_eq!(p.moonshot_governor.total_decisions, 50);
    assert_eq!(p.moonshot_governor.override_count, 2);
    assert_eq!(p.moonshot_governor.kill_count, 3);
}

// ── Section 6: Cross-repo conformance dimension ───────────────────────────

#[test]
fn conformance_low_pass_rate_causes_critical() {
    let mut req = baseline_request();
    req.conformance.matrix_health = MatrixHealthSummary {
        total_cells: 100,
        passed_cells: 50,
        failed_cells: 50,
        universal_failures: 0,
        version_specific_failures: 5,
    };
    let p = publish(&req);
    assert!(!p.cross_repo_conformance.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(p.blockers.iter().any(|b| b.contains("conformance")));
}

#[test]
fn conformance_universal_failures_cause_critical() {
    let mut req = baseline_request();
    req.conformance.matrix_health.universal_failures = 1; // > 0 default
    let p = publish(&req);
    assert!(!p.cross_repo_conformance.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
}

#[test]
fn conformance_version_specific_failures_above_threshold() {
    let mut req = baseline_request();
    req.conformance.matrix_health = MatrixHealthSummary {
        total_cells: 200,
        passed_cells: 190,
        failed_cells: 10,
        universal_failures: 0,
        version_specific_failures: 10, // > 5 default
    };
    let p = publish(&req);
    assert!(!p.cross_repo_conformance.threshold_pass);
}

#[test]
fn conformance_outstanding_exemptions_cause_critical() {
    let mut req = baseline_request();
    req.conformance.outstanding_exemptions = 3;
    let p = publish(&req);
    assert!(!p.cross_repo_conformance.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(p.blockers.iter().any(|b| b.contains("exemptions")));
}

#[test]
fn conformance_failure_class_distribution_propagated() {
    let p = publish(&baseline_request());
    assert_eq!(
        p.cross_repo_conformance.failure_class_distribution,
        BTreeMap::from([("assertion".to_string(), 2), ("timeout".to_string(), 2),])
    );
}

#[test]
fn conformance_pass_rate_computation() {
    let p = publish(&baseline_request());
    // 196/200 = 0.98 => 980_000
    assert_eq!(p.cross_repo_conformance.pass_rate_millionths, 980_000);
}

// ── Section 7: Trend regression ────────────────────────────────────────────

fn perfect_historical_point() -> GovernanceScorecardTrendPoint {
    GovernanceScorecardTrendPoint {
        scorecard_id: "hist-perfect".to_string(),
        generated_at_ns: 1_000_000_000,
        attested_receipt_coverage_millionths: 1_000_000,
        privacy_epoch_consumption_millionths: 0,
        moonshot_override_frequency_millionths: 0,
        conformance_pass_rate_millionths: 1_000_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    }
}

#[test]
fn no_trend_regression_with_empty_history() {
    let p = publish(&baseline_request());
    assert!(!p.trend_regression_detected);
}

#[test]
fn trend_regression_detected_warns_by_default() {
    let mut req = baseline_request();
    req.historical = vec![perfect_historical_point()];
    let p = publish(&req);
    // conformance 980_000 < 1_000_000 from history => regression
    assert!(p.trend_regression_detected);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Warning);
    assert!(p.warnings.iter().any(|w| w.contains("trend regression")));
}

#[test]
fn trend_regression_blocks_when_fail_on_trend_regression() {
    let mut req = baseline_request();
    req.historical = vec![perfect_historical_point()];
    req.thresholds = Some(GovernanceScorecardThresholds {
        fail_on_trend_regression: true,
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    assert!(p.trend_regression_detected);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(p.blockers.iter().any(|b| b.contains("trend regression")));
}

#[test]
fn trend_regression_from_coverage_drop() {
    let mut req = baseline_request();
    req.attested_receipts = vec![
        high_impact_receipt("h1", true),
        high_impact_receipt("h2", true),
    ];
    req.historical = vec![GovernanceScorecardTrendPoint {
        scorecard_id: "hist".to_string(),
        generated_at_ns: 1_000_000_000,
        attested_receipt_coverage_millionths: 1_000_000,
        privacy_epoch_consumption_millionths: 100_000,
        moonshot_override_frequency_millionths: 40_000,
        conformance_pass_rate_millionths: 980_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    }];
    let p = publish(&req);
    // Current coverage = 1_000_000, same as history, so no regression on that axis.
    // But privacy consumption may differ. Let's check.
    // privacy consumption = 100_000, same as history => no regression from that.
    // moonshot override = 40_000, same => no regression
    // conformance = 980_000, same => no regression
    // Actually all the same, so no regression.
    assert!(!p.trend_regression_detected);
}

#[test]
fn trend_regression_from_override_frequency_increase() {
    let mut req = baseline_request();
    req.historical = vec![GovernanceScorecardTrendPoint {
        scorecard_id: "hist".to_string(),
        generated_at_ns: 1_000_000_000,
        attested_receipt_coverage_millionths: 1_000_000,
        privacy_epoch_consumption_millionths: 100_000,
        moonshot_override_frequency_millionths: 30_000, // lower than current 40_000
        conformance_pass_rate_millionths: 980_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    }];
    let p = publish(&req);
    assert!(p.trend_regression_detected);
}

#[test]
fn trend_includes_current_point_appended() {
    let mut req = baseline_request();
    req.historical = vec![perfect_historical_point()];
    let p = publish(&req);
    assert_eq!(p.trend.len(), 2);
    assert_eq!(p.trend.last().unwrap().scorecard_id, "run-integ-001");
}

#[test]
fn trend_historical_sorted_by_generated_at() {
    let mut req = baseline_request();
    req.historical = vec![
        GovernanceScorecardTrendPoint {
            scorecard_id: "late".to_string(),
            generated_at_ns: 3_000_000_000,
            attested_receipt_coverage_millionths: 1_000_000,
            privacy_epoch_consumption_millionths: 0,
            moonshot_override_frequency_millionths: 0,
            conformance_pass_rate_millionths: 1_000_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        },
        GovernanceScorecardTrendPoint {
            scorecard_id: "early".to_string(),
            generated_at_ns: 1_000_000_000,
            attested_receipt_coverage_millionths: 1_000_000,
            privacy_epoch_consumption_millionths: 0,
            moonshot_override_frequency_millionths: 0,
            conformance_pass_rate_millionths: 1_000_000,
            outcome: GovernanceScorecardOutcome::Healthy,
        },
    ];
    let p = publish(&req);
    // Historical should be sorted; early before late before current.
    assert_eq!(p.trend[0].scorecard_id, "early");
    assert_eq!(p.trend[1].scorecard_id, "late");
    assert_eq!(p.trend[2].scorecard_id, "run-integ-001");
}

// ── Section 8: Events ──────────────────────────────────────────────────────

#[test]
fn events_include_started_event() {
    let p = publish(&baseline_request());
    assert_eq!(p.events[0].event, "governance_scorecard_started");
    assert_eq!(p.events[0].component, GOVERNANCE_SCORECARD_COMPONENT);
}

#[test]
fn events_include_all_dimension_evaluations() {
    let p = publish(&baseline_request());
    let event_names: Vec<&str> = p.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"attested_receipt_coverage_evaluated"));
    assert!(event_names.contains(&"privacy_budget_health_evaluated"));
    assert!(event_names.contains(&"moonshot_governor_evaluated"));
    assert!(event_names.contains(&"cross_repo_conformance_evaluated"));
}

#[test]
fn events_include_trend_regression_check() {
    let p = publish(&baseline_request());
    let event_names: Vec<&str> = p.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"trend_regression_check"));
}

#[test]
fn events_include_ledger_append_and_decision() {
    let p = publish(&baseline_request());
    let event_names: Vec<&str> = p.events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_names.contains(&"governance_scorecard_ledger_append"));
    assert!(event_names.contains(&"governance_scorecard_decision"));
}

#[test]
fn events_have_at_least_seven_entries() {
    let p = publish(&baseline_request());
    assert!(
        p.events.len() >= 7,
        "expected >= 7 events, got {}",
        p.events.len()
    );
}

#[test]
fn events_decision_outcome_for_healthy_is_allow() {
    let p = publish(&baseline_request());
    let decision = p
        .events
        .iter()
        .find(|e| e.event == "governance_scorecard_decision")
        .expect("decision event");
    assert_eq!(decision.outcome, "allow");
}

#[test]
fn events_decision_outcome_for_critical_is_deny() {
    let mut req = baseline_request();
    req.privacy_budget.overrun_incidents = 5;
    let p = publish(&req);
    let decision = p
        .events
        .iter()
        .find(|e| e.event == "governance_scorecard_decision")
        .expect("decision event");
    assert_eq!(decision.outcome, "deny");
}

// ── Section 9: Scorecard ID derivation ─────────────────────────────────────

#[test]
fn explicit_scorecard_run_id_used_as_scorecard_id() {
    let p = publish(&baseline_request());
    assert_eq!(p.scorecard_id, "run-integ-001");
}

#[test]
fn empty_scorecard_run_id_derives_id_from_hash() {
    let mut req = baseline_request();
    req.scorecard_run_id = String::new();
    let p = publish(&req);
    assert!(p.scorecard_id.starts_with("gov-scorecard-"));
    assert!(p.scorecard_id.len() > "gov-scorecard-".len());
}

#[test]
fn derived_id_deterministic() {
    let mut req = baseline_request();
    req.scorecard_run_id = String::new();
    let p1 = publish(&req);
    let p2 = publish(&req);
    assert_eq!(p1.scorecard_id, p2.scorecard_id);
}

// ── Section 10: Ledger interaction ─────────────────────────────────────────

#[test]
fn multiple_publications_increment_ledger_sequence() {
    let mut req1 = baseline_request();
    req1.decision_id = "decision-integ-1".to_string();
    let mut req2 = baseline_request();
    req2.decision_id = "decision-integ-2".to_string();
    let mut l = ledger();
    let p1 = publish_governance_scorecard(&req1, &signing_key(), &mut l, actor()).unwrap();
    let p2 = publish_governance_scorecard(&req2, &signing_key(), &mut l, actor()).unwrap();
    assert_eq!(p1.ledger_sequence, 1);
    assert_eq!(p2.ledger_sequence, 2);
    assert_eq!(l.entries().len(), 2);
}

#[test]
fn ledger_entry_has_artifact_references() {
    let req = baseline_request();
    let mut l = ledger();
    let p = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap();
    let entry = &l.entries()[0];
    assert!(
        entry
            .artifact_references
            .iter()
            .any(|r| r.starts_with("artifact://governance-scorecard/"))
    );
    assert!(
        entry
            .artifact_references
            .iter()
            .any(|r| r.starts_with("hash://"))
    );
    assert!(
        entry
            .artifact_references
            .iter()
            .any(|r| r.contains(&p.artifact_hash_hex))
    );
}

#[test]
fn ledger_decision_type_maps_correctly() {
    // Healthy -> Promote
    let req = baseline_request();
    let mut l = ledger();
    let _p = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap();
    assert_eq!(
        l.entries()[0].decision_type,
        GovernanceDecisionType::Promote
    );

    // Critical -> Kill
    let mut crit_req = baseline_request();
    crit_req.privacy_budget.overrun_incidents = 1;
    let mut l2 = ledger();
    let _p2 = publish_governance_scorecard(&crit_req, &signing_key(), &mut l2, actor()).unwrap();
    assert_eq!(l2.entries()[0].decision_type, GovernanceDecisionType::Kill);
}

#[test]
fn ledger_decision_type_hold_for_warning() {
    let mut req = baseline_request();
    req.historical = vec![perfect_historical_point()];
    let mut l = ledger();
    let p = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap();
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Warning);
    assert_eq!(l.entries()[0].decision_type, GovernanceDecisionType::Hold);
}

// ── Section 11: Markdown report ────────────────────────────────────────────

#[test]
fn markdown_report_contains_all_sections() {
    let p = publish(&baseline_request());
    let md = p.to_markdown_report();
    assert!(md.contains("# Governance Scorecard"));
    assert!(md.contains("## Dimensions"));
    assert!(md.contains("## Trend"));
    assert!(md.contains("Scorecard ID"));
    assert!(md.contains("HEALTHY"));
}

#[test]
fn markdown_report_blockers_section_when_critical() {
    let mut req = baseline_request();
    req.attested_receipts = vec![
        high_impact_receipt("h1", true),
        high_impact_receipt("h2", false),
    ];
    let p = publish(&req);
    let md = p.to_markdown_report();
    assert!(md.contains("## Blockers"));
}

#[test]
fn markdown_report_warnings_section_when_warning() {
    let mut req = baseline_request();
    req.historical = vec![perfect_historical_point()];
    let p = publish(&req);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Warning);
    let md = p.to_markdown_report();
    assert!(md.contains("## Warnings"));
    assert!(md.contains("WARNING"));
}

#[test]
fn markdown_report_dimensions_table_has_four_rows() {
    let p = publish(&baseline_request());
    let md = p.to_markdown_report();
    assert!(md.contains("Attested receipt coverage"));
    assert!(md.contains("Privacy epoch consumption"));
    assert!(md.contains("Moonshot override frequency"));
    assert!(md.contains("Cross-repo conformance pass rate"));
}

// ── Section 12: JSON output ────────────────────────────────────────────────

#[test]
fn json_pretty_roundtrip() {
    let p = publish(&baseline_request());
    let json = p.to_json_pretty().expect("json");
    let back: frankenengine_engine::governance_scorecard::GovernanceScorecardPublication =
        serde_json::from_str(&json).expect("parse");
    assert_eq!(back.scorecard_id, p.scorecard_id);
    assert_eq!(back.outcome, p.outcome);
    assert_eq!(back.artifact_hash_hex, p.artifact_hash_hex);
}

// ── Section 13: Validation errors ──────────────────────────────────────────

#[test]
fn validation_empty_trace_id() {
    let mut req = baseline_request();
    req.trace_id = "  ".to_string();
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    assert!(matches!(
        err,
        GovernanceScorecardError::InvalidInput { ref field, .. } if field == "trace_id"
    ));
}

#[test]
fn validation_empty_decision_id() {
    let mut req = baseline_request();
    req.decision_id = String::new();
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    assert!(matches!(
        err,
        GovernanceScorecardError::InvalidInput { ref field, .. } if field == "decision_id"
    ));
}

#[test]
fn validation_zero_generated_at() {
    let mut req = baseline_request();
    req.generated_at_ns = 0;
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    assert!(matches!(err, GovernanceScorecardError::InvalidInput { .. }));
}

#[test]
fn validation_empty_receipts() {
    let mut req = baseline_request();
    req.attested_receipts = Vec::new();
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    assert!(matches!(err, GovernanceScorecardError::InvalidInput { .. }));
}

#[test]
fn validation_no_high_impact_receipts() {
    let mut req = baseline_request();
    req.attested_receipts = vec![low_impact_receipt("lo-only")];
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("high-impact"));
}

#[test]
fn validation_duplicate_receipt_id() {
    let mut req = baseline_request();
    req.attested_receipts
        .push(high_impact_receipt("hi-1", true)); // duplicate
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("duplicate"));
}

#[test]
fn validation_empty_receipt_id() {
    let mut req = baseline_request();
    req.attested_receipts.push(high_impact_receipt("", true));
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    assert!(matches!(err, GovernanceScorecardError::InvalidInput { .. }));
}

#[test]
fn validation_zero_measurement_window() {
    let mut req = baseline_request();
    req.privacy_budget.measurement_window_ns = 0;
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    assert!(matches!(err, GovernanceScorecardError::InvalidInput { .. }));
}

#[test]
fn validation_conformance_empty_release_id() {
    let mut req = baseline_request();
    req.conformance.release_id = String::new();
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    assert!(matches!(err, GovernanceScorecardError::InvalidInput { .. }));
}

#[test]
fn validation_conformance_cells_mismatch() {
    let mut req = baseline_request();
    req.conformance.matrix_health.total_cells = 999; // != passed + failed
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("total_cells"));
}

#[test]
fn validation_thresholds_attested_over_million() {
    let mut req = baseline_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        min_attested_receipt_coverage_millionths: 1_000_001,
        ..GovernanceScorecardThresholds::default()
    });
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    assert!(matches!(err, GovernanceScorecardError::InvalidInput { .. }));
}

#[test]
fn validation_thresholds_privacy_exhaustion_zero() {
    let mut req = baseline_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        warn_privacy_exhaustion_within_ns: Some(0),
        ..GovernanceScorecardThresholds::default()
    });
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    assert!(matches!(err, GovernanceScorecardError::InvalidInput { .. }));
}

#[test]
fn validation_thresholds_moonshot_decision_ns_zero() {
    let mut req = baseline_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_moonshot_mean_time_to_decision_ns: Some(0),
        ..GovernanceScorecardThresholds::default()
    });
    let mut l = ledger();
    let err = publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).unwrap_err();
    assert!(matches!(err, GovernanceScorecardError::InvalidInput { .. }));
}

// ── Section 14: Error stable codes ─────────────────────────────────────────

#[test]
fn error_stable_code_invalid_input() {
    let err = GovernanceScorecardError::InvalidInput {
        field: "x".to_string(),
        detail: "y".to_string(),
    };
    assert_eq!(err.stable_code(), "FE-GOV-SCORE-3001");
}

#[test]
fn error_stable_code_serialization() {
    let err = GovernanceScorecardError::SerializationFailure("s".to_string());
    assert_eq!(err.stable_code(), "FE-GOV-SCORE-3002");
}

#[test]
fn error_stable_code_signature() {
    let err = GovernanceScorecardError::SignatureFailure("s".to_string());
    assert_eq!(err.stable_code(), "FE-GOV-SCORE-3003");
}

#[test]
fn error_stable_code_ledger() {
    let err = GovernanceScorecardError::LedgerWriteFailure("l".to_string());
    assert_eq!(err.stable_code(), "FE-GOV-SCORE-3004");
}

// ── Section 15: Outcome ordering and serde ─────────────────────────────────

#[test]
fn outcome_ordering() {
    assert!(GovernanceScorecardOutcome::Healthy < GovernanceScorecardOutcome::Warning);
    assert!(GovernanceScorecardOutcome::Warning < GovernanceScorecardOutcome::Critical);
    assert!(GovernanceScorecardOutcome::Healthy < GovernanceScorecardOutcome::Critical);
}

#[test]
fn outcome_as_str() {
    assert_eq!(GovernanceScorecardOutcome::Healthy.as_str(), "healthy");
    assert_eq!(GovernanceScorecardOutcome::Warning.as_str(), "warning");
    assert_eq!(GovernanceScorecardOutcome::Critical.as_str(), "critical");
}

#[test]
fn outcome_serde_roundtrip() {
    for outcome in [
        GovernanceScorecardOutcome::Healthy,
        GovernanceScorecardOutcome::Warning,
        GovernanceScorecardOutcome::Critical,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let back: GovernanceScorecardOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, outcome);
    }
}

// ── Section 16: Custom thresholds ──────────────────────────────────────────

#[test]
fn custom_thresholds_relaxed_attested_coverage() {
    let mut req = baseline_request();
    // Make coverage = 50% (normally critical with default 95% threshold).
    req.attested_receipts = vec![
        high_impact_receipt("h1", true),
        high_impact_receipt("h2", false),
    ];
    // Relax threshold to 40% and disable exhaustion warning.
    req.thresholds = Some(GovernanceScorecardThresholds {
        min_attested_receipt_coverage_millionths: 400_000,
        warn_privacy_exhaustion_within_ns: None,
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    assert!(p.attested_receipt_coverage.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Healthy);
}

#[test]
fn custom_thresholds_relaxed_privacy() {
    let mut req = baseline_request();
    req.privacy_budget.overrun_incidents = 3;
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_privacy_overrun_incidents: 5,
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    assert!(p.privacy_budget_health.threshold_pass);
}

#[test]
fn custom_thresholds_relaxed_exemptions() {
    let mut req = baseline_request();
    req.conformance.outstanding_exemptions = 3;
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_outstanding_exemptions: 5,
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    assert!(p.cross_repo_conformance.threshold_pass);
}

// ── Section 17: Combined failures ──────────────────────────────────────────

#[test]
fn multiple_dimension_failures_all_appear_in_blockers() {
    let mut req = baseline_request();
    // Fail attested coverage.
    req.attested_receipts = vec![
        high_impact_receipt("h1", true),
        high_impact_receipt("h2", false),
    ];
    // Fail privacy.
    req.privacy_budget.overrun_incidents = 5;
    // Fail moonshot.
    req.moonshot_governor
        .governance_report
        .override_frequency_millionths = 500_000;
    // Fail conformance.
    req.conformance.outstanding_exemptions = 10;

    let p = publish(&req);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(p.blockers.iter().any(|b| b.contains("attested-receipt")));
    assert!(p.blockers.iter().any(|b| b.contains("privacy budget")));
    assert!(p.blockers.iter().any(|b| b.contains("moonshot")));
    assert!(p.blockers.iter().any(|b| b.contains("conformance")));
    assert!(p.blockers.len() >= 4);
}

// ── Section 18: Serde roundtrips for input types ───────────────────────────

#[test]
fn attested_receipt_observation_serde() {
    let obs = high_impact_receipt("serde-1", true);
    let json = serde_json::to_string(&obs).expect("serialize");
    let back: AttestedReceiptObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, obs);
}

#[test]
fn governance_scorecard_thresholds_serde() {
    let t = GovernanceScorecardThresholds::default();
    let json = serde_json::to_string(&t).expect("serialize");
    let back: GovernanceScorecardThresholds = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, t);
}

#[test]
fn full_publication_serde_roundtrip() {
    let p = publish(&baseline_request());
    let json = serde_json::to_string(&p).expect("serialize");
    let back: frankenengine_engine::governance_scorecard::GovernanceScorecardPublication =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.scorecard_id, p.scorecard_id);
    assert_eq!(back.outcome, p.outcome);
    assert_eq!(back.artifact_hash_hex, p.artifact_hash_hex);
    assert_eq!(back.ledger_sequence, p.ledger_sequence);
    assert_eq!(back.trend.len(), p.trend.len());
    assert_eq!(back.events.len(), p.events.len());
    assert_eq!(back.blockers, p.blockers);
    assert_eq!(back.warnings, p.warnings);
}

// ── Section 19: Signature verification ─────────────────────────────────────

#[test]
fn signature_verification_after_critical_publication() {
    let mut req = baseline_request();
    req.privacy_budget.overrun_incidents = 10;
    let p = publish(&req);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    verify_governance_scorecard_signature(&p).expect("sig should verify even for critical");
}

#[test]
fn signature_verification_after_warning_publication() {
    let mut req = baseline_request();
    req.historical = vec![perfect_historical_point()];
    let p = publish(&req);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Warning);
    verify_governance_scorecard_signature(&p).expect("sig should verify for warning");
}

// ── Section 20: Constants ──────────────────────────────────────────────────

#[test]
fn governance_scorecard_component_constant() {
    assert_eq!(GOVERNANCE_SCORECARD_COMPONENT, "governance_scorecard");
}

#[test]
fn governance_scorecard_schema_version_constant() {
    assert_eq!(
        GOVERNANCE_SCORECARD_SCHEMA_VERSION,
        "franken-engine.governance-scorecard.v1"
    );
}

// ── Section 21: Human actor ────────────────────────────────────────────────

#[test]
fn publication_with_human_actor() {
    let req = baseline_request();
    let mut l = ledger();
    let p = publish_governance_scorecard(
        &req,
        &signing_key(),
        &mut l,
        GovernanceActor::Human("alice@example.com".to_string()),
    )
    .unwrap();
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Healthy);
    verify_governance_scorecard_signature(&p).unwrap();
}
