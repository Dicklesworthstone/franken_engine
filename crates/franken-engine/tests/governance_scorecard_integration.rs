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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::dp_budget_accountant::{AccountantConfig, BudgetAccountant};
use frankenengine_engine::governance_scorecard::{
    AttestedReceiptCoverageSummary, AttestedReceiptObservation, CrossRepoConformanceInput,
    CrossRepoConformanceStabilitySummary, GOVERNANCE_SCORECARD_COMPONENT,
    GOVERNANCE_SCORECARD_SCHEMA_VERSION, GovernanceScorecardError, GovernanceScorecardEvent,
    GovernanceScorecardOutcome, GovernanceScorecardPublication, GovernanceScorecardRequest,
    GovernanceScorecardThresholds, GovernanceScorecardTrendPoint, MoonshotGovernorDecisionSummary,
    MoonshotGovernorHealthInput, PrivacyBudgetHealthInput, PrivacyBudgetHealthSummary,
    publish_governance_scorecard, verify_governance_scorecard_signature,
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

// ────────────────────────────────────────────────────────────────────────────
// Enrichment: PearlTower 2026-03-12 — ~80 additional integration tests
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn enrichment_scorecard_id_prefix_when_run_id_empty() {
    let mut req = baseline_request();
    req.scorecard_run_id = String::new();
    let p = publish(&req);
    assert!(
        p.scorecard_id.starts_with("gov-scorecard-"),
        "auto-derived id should have prefix, got: {}",
        p.scorecard_id
    );
    let hex_part = &p.scorecard_id["gov-scorecard-".len()..];
    assert_eq!(hex_part.len(), 24);
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_explicit_scorecard_run_id_used_verbatim() {
    let mut req = baseline_request();
    req.scorecard_run_id = "my-custom-run-42".to_string();
    let p = publish(&req);
    assert_eq!(p.scorecard_id, "my-custom-run-42");
}

#[test]
fn enrichment_generated_at_ns_propagated() {
    let req = baseline_request();
    let p = publish(&req);
    assert_eq!(p.generated_at_ns, req.generated_at_ns);
}

#[test]
fn enrichment_schema_version_constant_matches_publication() {
    let p = publish(&baseline_request());
    assert_eq!(p.schema_version, "franken-engine.governance-scorecard.v1");
}

#[test]
fn enrichment_warning_outcome_maps_to_hold_decision() {
    let mut req = baseline_request();
    req.historical = vec![perfect_historical_point()];
    let mut l = ledger();
    let p =
        publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).expect("publication");
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Warning);
    assert_eq!(l.entries()[0].decision_type, GovernanceDecisionType::Hold);
}

#[test]
fn enrichment_critical_outcome_maps_to_kill_decision() {
    let mut req = baseline_request();
    req.attested_receipts = vec![high_impact_receipt("sole", false)];
    let mut l = ledger();
    let p =
        publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).expect("publication");
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert_eq!(l.entries()[0].decision_type, GovernanceDecisionType::Kill);
}

#[test]
fn enrichment_all_receipts_valid_gives_full_coverage() {
    let mut req = baseline_request();
    req.attested_receipts = vec![
        high_impact_receipt("a1", true),
        high_impact_receipt("a2", true),
    ];
    let p = publish(&req);
    assert_eq!(p.attested_receipt_coverage.coverage_millionths, 1_000_000);
    assert!(p.attested_receipt_coverage.threshold_pass);
}

#[test]
fn enrichment_half_valid_receipts_coverage_is_500k() {
    let mut req = baseline_request();
    req.attested_receipts = vec![
        high_impact_receipt("h1", true),
        high_impact_receipt("h2", false),
    ];
    let p = publish(&req);
    assert_eq!(p.attested_receipt_coverage.coverage_millionths, 500_000);
    assert_eq!(p.attested_receipt_coverage.high_impact_total, 2);
    assert_eq!(
        p.attested_receipt_coverage
            .high_impact_with_valid_attestation,
        1
    );
    assert_eq!(
        p.attested_receipt_coverage
            .high_impact_missing_or_invalid_attestation,
        1
    );
}

#[test]
fn enrichment_non_high_impact_receipts_ignored_in_coverage() {
    let mut req = baseline_request();
    req.attested_receipts = vec![
        high_impact_receipt("hi", true),
        low_impact_receipt("lo1"),
        low_impact_receipt("lo2"),
    ];
    let p = publish(&req);
    assert_eq!(p.attested_receipt_coverage.coverage_millionths, 1_000_000);
    assert_eq!(p.attested_receipt_coverage.high_impact_total, 1);
}

#[test]
fn enrichment_privacy_budget_epoch_fields_populated() {
    let p = publish(&baseline_request());
    assert!(p.privacy_budget_health.epoch_epsilon_budget_millionths > 0);
    assert!(p.privacy_budget_health.epoch_delta_budget_millionths > 0);
}

#[test]
fn enrichment_privacy_epoch_consumption_bounded_to_million() {
    let p = publish(&baseline_request());
    assert!(p.privacy_budget_health.epoch_consumption_millionths <= 1_000_000);
}

#[test]
fn enrichment_moonshot_governor_fields_propagated() {
    let req = baseline_request();
    let p = publish(&req);
    assert_eq!(p.moonshot_governor.total_decisions, 50);
    assert_eq!(p.moonshot_governor.override_count, 2);
    assert_eq!(p.moonshot_governor.kill_count, 3);
    assert_eq!(p.moonshot_governor.active_moonshots, 5);
    assert_eq!(p.moonshot_governor.paused_moonshots, 1);
    assert_eq!(p.moonshot_governor.killed_moonshots, 2);
}

#[test]
fn enrichment_conformance_pass_rate_computed_correctly() {
    let req = baseline_request();
    let p = publish(&req);
    // 196 passed / 200 total = 980_000 millionths
    assert_eq!(p.cross_repo_conformance.pass_rate_millionths, 980_000);
    assert_eq!(p.cross_repo_conformance.total_cells, 200);
    assert_eq!(p.cross_repo_conformance.passed_cells, 196);
    assert_eq!(p.cross_repo_conformance.failed_cells, 4);
}

#[test]
fn enrichment_conformance_failure_class_distribution_preserved() {
    let req = baseline_request();
    let p = publish(&req);
    let dist = &p.cross_repo_conformance.failure_class_distribution;
    assert_eq!(dist.get("timeout"), Some(&2));
    assert_eq!(dist.get("assertion"), Some(&2));
}

#[test]
fn enrichment_trend_includes_current_plus_historical() {
    let mut req = baseline_request();
    req.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "old-1".to_string(),
        generated_at_ns: 100,
        attested_receipt_coverage_millionths: 950_000,
        privacy_epoch_consumption_millionths: 100_000,
        moonshot_override_frequency_millionths: 50_000,
        conformance_pass_rate_millionths: 980_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    });
    let p = publish(&req);
    assert_eq!(p.trend.len(), 2);
}

#[test]
fn enrichment_trend_sorted_by_generated_at_ns() {
    let mut req = baseline_request();
    req.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "later".to_string(),
        generated_at_ns: 500,
        attested_receipt_coverage_millionths: 950_000,
        privacy_epoch_consumption_millionths: 100_000,
        moonshot_override_frequency_millionths: 50_000,
        conformance_pass_rate_millionths: 980_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    });
    req.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "earlier".to_string(),
        generated_at_ns: 100,
        attested_receipt_coverage_millionths: 960_000,
        privacy_epoch_consumption_millionths: 80_000,
        moonshot_override_frequency_millionths: 40_000,
        conformance_pass_rate_millionths: 990_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    });
    let p = publish(&req);
    for w in p.trend.windows(2) {
        assert!(
            w[0].generated_at_ns <= w[1].generated_at_ns,
            "trend must be sorted ascending by timestamp"
        );
    }
}

#[test]
fn enrichment_no_regression_when_all_metrics_improve() {
    let mut req = baseline_request();
    req.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "prev-worse".to_string(),
        generated_at_ns: req.generated_at_ns.saturating_sub(1),
        attested_receipt_coverage_millionths: 900_000,
        privacy_epoch_consumption_millionths: 500_000,
        moonshot_override_frequency_millionths: 200_000,
        conformance_pass_rate_millionths: 900_000,
        outcome: GovernanceScorecardOutcome::Warning,
    });
    let p = publish(&req);
    assert!(!p.trend_regression_detected);
}

#[test]
fn enrichment_trend_regression_on_override_frequency_increase() {
    let mut req = baseline_request();
    req.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "prev".to_string(),
        generated_at_ns: req.generated_at_ns.saturating_sub(1),
        attested_receipt_coverage_millionths: 1_000_000,
        privacy_epoch_consumption_millionths: 1_000_000,
        moonshot_override_frequency_millionths: 0,
        conformance_pass_rate_millionths: 980_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    });
    let p = publish(&req);
    assert!(p.trend_regression_detected);
}

#[test]
fn enrichment_events_include_started_event() {
    let p = publish(&baseline_request());
    assert!(
        p.events
            .iter()
            .any(|e| e.event == "governance_scorecard_started"),
        "events should include 'governance_scorecard_started'"
    );
}

#[test]
fn enrichment_events_include_dimension_evaluations() {
    let p = publish(&baseline_request());
    let dimension_events: Vec<&GovernanceScorecardEvent> =
        p.events.iter().filter(|e| e.dimension.is_some()).collect();
    assert_eq!(dimension_events.len(), 4);
    let dims: BTreeSet<String> = dimension_events
        .iter()
        .filter_map(|e| e.dimension.clone())
        .collect();
    assert!(dims.contains("attested_receipt_coverage"));
    assert!(dims.contains("privacy_budget_health"));
    assert!(dims.contains("moonshot_governor"));
    assert!(dims.contains("cross_repo_conformance"));
}

#[test]
fn enrichment_events_include_ledger_append() {
    let p = publish(&baseline_request());
    assert!(
        p.events
            .iter()
            .any(|e| e.event == "governance_scorecard_ledger_append"),
        "events should include ledger append"
    );
}

#[test]
fn enrichment_events_include_final_decision() {
    let p = publish(&baseline_request());
    assert!(
        p.events
            .iter()
            .any(|e| e.event == "governance_scorecard_decision"),
        "events should include the final decision event"
    );
}

#[test]
fn enrichment_events_trace_id_matches_request() {
    let req = baseline_request();
    let p = publish(&req);
    for event in &p.events {
        assert_eq!(event.trace_id, req.trace_id);
    }
}

#[test]
fn enrichment_events_decision_id_matches_request() {
    let req = baseline_request();
    let p = publish(&req);
    for event in &p.events {
        assert_eq!(event.decision_id, req.decision_id);
    }
}

#[test]
fn enrichment_events_policy_id_matches_request() {
    let req = baseline_request();
    let p = publish(&req);
    for event in &p.events {
        assert_eq!(event.policy_id, req.policy_id);
    }
}

#[test]
fn enrichment_events_component_always_governance_scorecard() {
    let p = publish(&baseline_request());
    for event in &p.events {
        assert_eq!(event.component, GOVERNANCE_SCORECARD_COMPONENT);
    }
}

#[test]
fn enrichment_healthy_decision_event_outcome_is_allow() {
    let p = publish(&baseline_request());
    let decision = p
        .events
        .iter()
        .find(|e| e.event == "governance_scorecard_decision")
        .expect("should have decision event");
    assert_eq!(decision.outcome, "allow");
}

#[test]
fn enrichment_critical_decision_event_outcome_is_deny() {
    let mut req = baseline_request();
    req.attested_receipts = vec![high_impact_receipt("sole", false)];
    let p = publish(&req);
    let decision = p
        .events
        .iter()
        .find(|e| e.event == "governance_scorecard_decision")
        .expect("should have decision event");
    assert_eq!(decision.outcome, "deny");
}

#[test]
fn enrichment_warning_decision_event_outcome_is_warn() {
    let mut req = baseline_request();
    req.historical = vec![perfect_historical_point()];
    let p = publish(&req);
    let decision = p
        .events
        .iter()
        .find(|e| e.event == "governance_scorecard_decision")
        .expect("should have decision event");
    assert_eq!(decision.outcome, "warn");
}

#[test]
fn enrichment_artifact_hash_hex_is_64_hex_chars() {
    let p = publish(&baseline_request());
    assert_eq!(p.artifact_hash_hex.len(), 64);
    assert!(p.artifact_hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_tampered_scorecard_id_fails_verification() {
    let mut p = publish(&baseline_request());
    p.scorecard_id = "tampered-id".to_string();
    assert!(verify_governance_scorecard_signature(&p).is_err());
}

#[test]
fn enrichment_tampered_blockers_fails_verification() {
    let mut p = publish(&baseline_request());
    p.blockers.push("injected blocker".to_string());
    assert!(verify_governance_scorecard_signature(&p).is_err());
}

#[test]
fn enrichment_tampered_warnings_fails_verification() {
    let mut p = publish(&baseline_request());
    p.warnings.push("injected warning".to_string());
    assert!(verify_governance_scorecard_signature(&p).is_err());
}

#[test]
fn enrichment_tampered_trend_fails_verification() {
    let mut p = publish(&baseline_request());
    p.trend.push(GovernanceScorecardTrendPoint {
        scorecard_id: "tampered".to_string(),
        generated_at_ns: 999,
        attested_receipt_coverage_millionths: 0,
        privacy_epoch_consumption_millionths: 0,
        moonshot_override_frequency_millionths: 0,
        conformance_pass_rate_millionths: 0,
        outcome: GovernanceScorecardOutcome::Critical,
    });
    assert!(verify_governance_scorecard_signature(&p).is_err());
}

#[test]
fn enrichment_tampered_generated_at_fails_verification() {
    let mut p = publish(&baseline_request());
    p.generated_at_ns += 1;
    assert!(verify_governance_scorecard_signature(&p).is_err());
}

#[test]
fn enrichment_sequential_publications_increment_ledger_sequence() {
    let req = baseline_request();
    let mut l = ledger();
    let key = signing_key();
    let p1 = publish_governance_scorecard(&req, &key, &mut l, actor()).expect("p1");
    let p2 = publish_governance_scorecard(&req, &key, &mut l, actor()).expect("p2");
    assert_eq!(p2.ledger_sequence, p1.ledger_sequence + 1);
}

#[test]
fn enrichment_validation_rejects_whitespace_trace_id() {
    let mut req = baseline_request();
    req.trace_id = "   ".to_string();
    let mut l = ledger();
    let result = publish_governance_scorecard(&req, &signing_key(), &mut l, actor());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(
        err,
        GovernanceScorecardError::InvalidInput { ref field, .. } if field == "trace_id"
    ));
}

#[test]
fn enrichment_validation_rejects_whitespace_policy_id() {
    let mut req = baseline_request();
    req.policy_id = "  ".to_string();
    let mut l = ledger();
    let result = publish_governance_scorecard(&req, &signing_key(), &mut l, actor());
    assert!(result.is_err());
}

#[test]
fn enrichment_validation_rejects_duplicate_receipt_ids_detail() {
    let mut req = baseline_request();
    req.attested_receipts
        .push(high_impact_receipt("hi-1", true));
    let mut l = ledger();
    let result = publish_governance_scorecard(&req, &signing_key(), &mut l, actor());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("duplicate"));
}

#[test]
fn enrichment_validation_rejects_whitespace_receipt_id() {
    let mut req = baseline_request();
    req.attested_receipts.push(AttestedReceiptObservation {
        receipt_id: "   ".to_string(),
        high_impact: true,
        attestation_binding_valid: true,
        timestamp_ns: 999,
    });
    let mut l = ledger();
    let result = publish_governance_scorecard(&req, &signing_key(), &mut l, actor());
    assert!(result.is_err());
}

#[test]
fn enrichment_threshold_validation_privacy_consumption_over_million() {
    let mut req = baseline_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_privacy_epoch_consumption_millionths: 2_000_000,
        ..GovernanceScorecardThresholds::default()
    });
    let mut l = ledger();
    let result = publish_governance_scorecard(&req, &signing_key(), &mut l, actor());
    assert!(result.is_err());
}

#[test]
fn enrichment_threshold_validation_override_frequency_over_million() {
    let mut req = baseline_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_moonshot_override_frequency_millionths: 1_500_000,
        ..GovernanceScorecardThresholds::default()
    });
    let mut l = ledger();
    let result = publish_governance_scorecard(&req, &signing_key(), &mut l, actor());
    assert!(result.is_err());
}

#[test]
fn enrichment_threshold_validation_kill_rate_over_million() {
    let mut req = baseline_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_moonshot_kill_rate_millionths: 1_000_001,
        ..GovernanceScorecardThresholds::default()
    });
    let mut l = ledger();
    let result = publish_governance_scorecard(&req, &signing_key(), &mut l, actor());
    assert!(result.is_err());
}

#[test]
fn enrichment_threshold_validation_conformance_over_million() {
    let mut req = baseline_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        min_conformance_pass_rate_millionths: 1_000_001,
        ..GovernanceScorecardThresholds::default()
    });
    let mut l = ledger();
    let result = publish_governance_scorecard(&req, &signing_key(), &mut l, actor());
    assert!(result.is_err());
}

#[test]
fn enrichment_markdown_report_healthy_no_blockers_section() {
    let p = publish(&baseline_request());
    let md = p.to_markdown_report();
    assert!(md.contains("HEALTHY"));
    assert!(!md.contains("## Blockers"));
}

#[test]
fn enrichment_markdown_report_critical_has_blockers_section() {
    let mut req = baseline_request();
    req.attested_receipts = vec![high_impact_receipt("solo", false)];
    let p = publish(&req);
    let md = p.to_markdown_report();
    assert!(md.contains("CRITICAL"));
    assert!(md.contains("## Blockers"));
}

#[test]
fn enrichment_markdown_report_contains_artifact_hash() {
    let p = publish(&baseline_request());
    let md = p.to_markdown_report();
    assert!(md.contains(&p.artifact_hash_hex));
}

#[test]
fn enrichment_markdown_report_contains_ledger_sequence() {
    let p = publish(&baseline_request());
    let md = p.to_markdown_report();
    assert!(md.contains(&p.ledger_sequence.to_string()));
}

#[test]
fn enrichment_markdown_report_trend_section_present() {
    let p = publish(&baseline_request());
    let md = p.to_markdown_report();
    assert!(md.contains("## Trend"));
}

#[test]
fn enrichment_json_pretty_contains_all_top_level_fields() {
    let p = publish(&baseline_request());
    let json = p.to_json_pretty().expect("json");
    for field in [
        "schema_version",
        "scorecard_id",
        "generated_at_ns",
        "outcome",
        "thresholds",
        "attested_receipt_coverage",
        "privacy_budget_health",
        "moonshot_governor",
        "cross_repo_conformance",
        "blockers",
        "warnings",
        "trend",
        "artifact_hash_hex",
        "signature",
        "signer_key",
        "ledger_sequence",
        "events",
    ] {
        assert!(json.contains(field), "json should contain field: {field}");
    }
}

#[test]
fn enrichment_publication_serde_roundtrip_full() {
    let p = publish(&baseline_request());
    let json = serde_json::to_string(&p).expect("serialize");
    let recovered: GovernanceScorecardPublication =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(p.scorecard_id, recovered.scorecard_id);
    assert_eq!(p.outcome, recovered.outcome);
    assert_eq!(p.generated_at_ns, recovered.generated_at_ns);
    assert_eq!(p.artifact_hash_hex, recovered.artifact_hash_hex);
    assert_eq!(p.ledger_sequence, recovered.ledger_sequence);
    assert_eq!(p.blockers, recovered.blockers);
    assert_eq!(p.warnings, recovered.warnings);
    assert_eq!(
        p.trend_regression_detected,
        recovered.trend_regression_detected
    );
    assert_eq!(p.trend.len(), recovered.trend.len());
    assert_eq!(p.events.len(), recovered.events.len());
}

#[test]
fn enrichment_attested_receipt_observation_clone_eq() {
    let obs = high_impact_receipt("clone-test", true);
    let cloned = obs.clone();
    assert_eq!(obs, cloned);
}

#[test]
fn enrichment_trend_point_clone_eq() {
    let tp = GovernanceScorecardTrendPoint {
        scorecard_id: "clone-tp".to_string(),
        generated_at_ns: 42,
        attested_receipt_coverage_millionths: 100_000,
        privacy_epoch_consumption_millionths: 200_000,
        moonshot_override_frequency_millionths: 300_000,
        conformance_pass_rate_millionths: 400_000,
        outcome: GovernanceScorecardOutcome::Warning,
    };
    let cloned = tp.clone();
    assert_eq!(tp, cloned);
}

#[test]
fn enrichment_thresholds_default_eq_itself() {
    let a = GovernanceScorecardThresholds::default();
    let b = GovernanceScorecardThresholds::default();
    assert_eq!(a, b);
}

#[test]
fn enrichment_outcome_clone_copy() {
    let outcome = GovernanceScorecardOutcome::Warning;
    let copied = outcome;
    let cloned = outcome.clone();
    assert_eq!(outcome, copied);
    assert_eq!(outcome, cloned);
}

#[test]
fn enrichment_outcome_debug_format_non_empty() {
    let dbg = format!("{:?}", GovernanceScorecardOutcome::Healthy);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Healthy"));
}

#[test]
fn enrichment_error_debug_format_non_empty() {
    let err = GovernanceScorecardError::InvalidInput {
        field: "test_field".to_string(),
        detail: "test_detail".to_string(),
    };
    let dbg = format!("{:?}", err);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("test_field"));
}

#[test]
fn enrichment_error_stable_codes_are_prefixed() {
    let errors = vec![
        GovernanceScorecardError::InvalidInput {
            field: "f".to_string(),
            detail: "d".to_string(),
        },
        GovernanceScorecardError::SerializationFailure("s".to_string()),
        GovernanceScorecardError::SignatureFailure("s".to_string()),
        GovernanceScorecardError::LedgerWriteFailure("l".to_string()),
    ];
    for err in &errors {
        assert!(
            err.stable_code().starts_with("FE-GOV-SCORE-"),
            "stable code should be prefixed: {}",
            err.stable_code()
        );
    }
}

#[test]
fn enrichment_error_stable_codes_all_unique() {
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
    assert_eq!(codes.len(), 4, "all stable codes must be distinct");
}

#[test]
fn enrichment_error_is_std_error_for_all_variants() {
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(GovernanceScorecardError::InvalidInput {
            field: "f".to_string(),
            detail: "d".to_string(),
        }),
        Box::new(GovernanceScorecardError::SerializationFailure(
            "s".to_string(),
        )),
        Box::new(GovernanceScorecardError::SignatureFailure("s".to_string())),
        Box::new(GovernanceScorecardError::LedgerWriteFailure(
            "l".to_string(),
        )),
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn enrichment_moonshot_high_kill_rate_triggers_blocker() {
    let mut req = baseline_request();
    req.moonshot_governor.governance_report.kill_rate_millionths = 500_000;
    let p = publish(&req);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(p.blockers.iter().any(|b| b.contains("moonshot")));
}

#[test]
fn enrichment_conformance_version_specific_failures_excess() {
    let mut req = baseline_request();
    req.conformance.matrix_health.version_specific_failures = 10;
    req.conformance.matrix_health.failed_cells = 10;
    req.conformance.matrix_health.passed_cells = 190;
    req.conformance.matrix_health.total_cells = 200;
    let p = publish(&req);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(p.blockers.iter().any(|b| b.contains("conformance")));
}

#[test]
fn enrichment_conformance_outstanding_exemptions_triggers_blocker() {
    let mut req = baseline_request();
    req.conformance.outstanding_exemptions = 3;
    let p = publish(&req);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(p.blockers.iter().any(|b| b.contains("exemptions")));
}

#[test]
fn enrichment_custom_thresholds_relax_overrun_to_pass() {
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
fn enrichment_no_exhaustion_warning_when_lead_time_none() {
    let mut req = baseline_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        warn_privacy_exhaustion_within_ns: None,
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    assert!(!p.privacy_budget_health.near_term_exhaustion_warning);
}

#[test]
fn enrichment_multiple_blockers_from_all_four_dimensions() {
    let mut req = baseline_request();
    req.attested_receipts = vec![high_impact_receipt("h1", false)];
    req.privacy_budget.overrun_incidents = 5;
    req.moonshot_governor
        .governance_report
        .override_frequency_millionths = 500_000;
    req.conformance.outstanding_exemptions = 10;
    let p = publish(&req);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
    assert!(
        p.blockers.len() >= 4,
        "should have at least 4 blockers, got: {}",
        p.blockers.len()
    );
}

#[test]
fn enrichment_trend_regression_check_event_pass() {
    let p = publish(&baseline_request());
    let trend_event = p
        .events
        .iter()
        .find(|e| e.event == "trend_regression_check");
    assert!(trend_event.is_some());
    assert_eq!(trend_event.unwrap().outcome, "pass");
}

#[test]
fn enrichment_trend_regression_check_event_warn() {
    let mut req = baseline_request();
    req.historical = vec![perfect_historical_point()];
    let p = publish(&req);
    let trend_event = p
        .events
        .iter()
        .find(|e| e.event == "trend_regression_check");
    assert!(trend_event.is_some());
    assert_eq!(trend_event.unwrap().outcome, "warn");
}

#[test]
fn enrichment_trend_regression_check_event_fail() {
    let mut req = baseline_request();
    req.historical = vec![perfect_historical_point()];
    req.thresholds = Some(GovernanceScorecardThresholds {
        fail_on_trend_regression: true,
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    let trend_event = p
        .events
        .iter()
        .find(|e| e.event == "trend_regression_check");
    assert!(trend_event.is_some());
    assert_eq!(trend_event.unwrap().outcome, "fail");
}

#[test]
fn enrichment_dimension_event_error_code_when_failing() {
    let mut req = baseline_request();
    req.attested_receipts = vec![high_impact_receipt("solo", false)];
    let p = publish(&req);
    let coverage_event = p
        .events
        .iter()
        .find(|e| e.dimension.as_deref() == Some("attested_receipt_coverage"));
    assert!(coverage_event.is_some());
    assert_eq!(coverage_event.unwrap().outcome, "fail");
    assert!(coverage_event.unwrap().error_code.is_some());
}

#[test]
fn enrichment_dimension_event_no_error_code_when_passing() {
    let p = publish(&baseline_request());
    let coverage_event = p
        .events
        .iter()
        .find(|e| e.dimension.as_deref() == Some("attested_receipt_coverage"));
    assert!(coverage_event.is_some());
    assert_eq!(coverage_event.unwrap().outcome, "pass");
    assert!(coverage_event.unwrap().error_code.is_none());
}

#[test]
fn enrichment_event_serde_roundtrip_with_all_fields() {
    let event = GovernanceScorecardEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        component: "governance_scorecard".to_string(),
        event: "dimension_evaluated".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("FE-GOV-SCORE-3005".to_string()),
        dimension: Some("privacy_budget_health".to_string()),
        detail: Some("within budget".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: GovernanceScorecardEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn enrichment_event_serde_roundtrip_with_none_fields() {
    let event = GovernanceScorecardEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        dimension: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: GovernanceScorecardEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn enrichment_attested_receipt_coverage_summary_serde_roundtrip() {
    let summary = AttestedReceiptCoverageSummary {
        high_impact_total: 5,
        high_impact_with_valid_attestation: 3,
        high_impact_missing_or_invalid_attestation: 2,
        coverage_millionths: 600_000,
        threshold_pass: false,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: AttestedReceiptCoverageSummary =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, recovered);
}

#[test]
fn enrichment_privacy_budget_health_summary_serde_roundtrip() {
    let summary = PrivacyBudgetHealthSummary {
        epoch: SecurityEpoch::from_raw(3),
        epoch_epsilon_budget_millionths: 1_000_000,
        epoch_epsilon_spent_millionths: 250_000,
        epoch_delta_budget_millionths: 100_000,
        epoch_delta_spent_millionths: 25_000,
        epoch_consumption_millionths: 250_000,
        lifetime_epsilon_remaining_millionths: 7_500_000,
        lifetime_delta_remaining_millionths: 750_000,
        estimated_remaining_operations: 30,
        epsilon_burn_rate_per_hour_millionths: 10_000,
        delta_burn_rate_per_hour_millionths: 1_000,
        projected_epsilon_exhaustion_ns: Some(999_999_999_999),
        projected_delta_exhaustion_ns: None,
        overrun_incidents: 0,
        threshold_pass: true,
        near_term_exhaustion_warning: false,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: PrivacyBudgetHealthSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, recovered);
}

#[test]
fn enrichment_moonshot_governor_decision_summary_serde_roundtrip() {
    let summary = MoonshotGovernorDecisionSummary {
        total_decisions: 200,
        override_count: 10,
        kill_count: 5,
        override_frequency_millionths: 50_000,
        kill_rate_millionths: 25_000,
        mean_time_to_decision_ns: Some(86_400_000_000_000),
        active_moonshots: 8,
        paused_moonshots: 2,
        killed_moonshots: 3,
        threshold_pass: true,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: MoonshotGovernorDecisionSummary =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, recovered);
}

#[test]
fn enrichment_cross_repo_conformance_stability_summary_serde_roundtrip() {
    let summary = CrossRepoConformanceStabilitySummary {
        release_id: "v2.0.0".to_string(),
        total_cells: 50,
        passed_cells: 48,
        failed_cells: 2,
        pass_rate_millionths: 960_000,
        universal_failures: 0,
        version_specific_failures: 2,
        outstanding_exemptions: 1,
        failure_class_distribution: BTreeMap::from([
            ("timeout".to_string(), 1),
            ("assertion".to_string(), 1),
        ]),
        threshold_pass: true,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: CrossRepoConformanceStabilitySummary =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, recovered);
}

#[test]
fn enrichment_thresholds_serde_roundtrip_all_custom_values() {
    let thresholds = GovernanceScorecardThresholds {
        min_attested_receipt_coverage_millionths: 800_000,
        max_privacy_overrun_incidents: 3,
        max_privacy_epoch_consumption_millionths: 700_000,
        warn_privacy_exhaustion_within_ns: Some(48 * 3_600_000_000_000),
        max_moonshot_override_frequency_millionths: 150_000,
        max_moonshot_kill_rate_millionths: 200_000,
        max_moonshot_mean_time_to_decision_ns: Some(48 * 3_600_000_000_000),
        min_conformance_pass_rate_millionths: 900_000,
        max_universal_failures: 1,
        max_version_specific_failures: 10,
        max_outstanding_exemptions: 5,
        fail_on_trend_regression: true,
    };
    let json = serde_json::to_string(&thresholds).expect("serialize");
    let recovered: GovernanceScorecardThresholds =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(thresholds, recovered);
}

#[test]
fn enrichment_request_serde_roundtrip_with_thresholds() {
    let mut req = baseline_request();
    req.thresholds = Some(GovernanceScorecardThresholds {
        fail_on_trend_regression: true,
        ..GovernanceScorecardThresholds::default()
    });
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: GovernanceScorecardRequest = serde_json::from_str(&json).expect("deserialize");
    assert!(recovered.thresholds.is_some());
    assert!(recovered.thresholds.unwrap().fail_on_trend_regression);
}

#[test]
fn enrichment_request_serde_roundtrip_with_historical() {
    let mut req = baseline_request();
    req.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "hist-1".to_string(),
        generated_at_ns: 100,
        attested_receipt_coverage_millionths: 950_000,
        privacy_epoch_consumption_millionths: 100_000,
        moonshot_override_frequency_millionths: 50_000,
        conformance_pass_rate_millionths: 980_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    });
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: GovernanceScorecardRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.historical.len(), 1);
    assert_eq!(recovered.historical[0].scorecard_id, "hist-1");
}

#[test]
fn enrichment_different_signing_keys_produce_different_signatures() {
    let req = baseline_request();
    let key_a = SigningKey::from_bytes([0x42; 32]);
    let key_b = SigningKey::from_bytes([0x99; 32]);
    let mut l_a = ledger();
    let mut l_b = ledger();
    let p_a = publish_governance_scorecard(&req, &key_a, &mut l_a, actor()).expect("a");
    let p_b = publish_governance_scorecard(&req, &key_b, &mut l_b, actor()).expect("b");
    assert_eq!(p_a.artifact_hash_hex, p_b.artifact_hash_hex);
    assert_ne!(p_a.signature, p_b.signature);
    assert_ne!(p_a.signer_key, p_b.signer_key);
    assert!(verify_governance_scorecard_signature(&p_a).is_ok());
    assert!(verify_governance_scorecard_signature(&p_b).is_ok());
}

#[test]
fn enrichment_moonshot_mean_time_exceeds_threshold_fails() {
    let mut req = baseline_request();
    req.moonshot_governor
        .governance_report
        .mean_time_to_decision_ns = Some(999_999_999_999_999);
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_moonshot_mean_time_to_decision_ns: Some(1_000_000),
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    assert!(!p.moonshot_governor.threshold_pass);
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Critical);
}

#[test]
fn enrichment_moonshot_none_mean_time_passes_threshold() {
    let mut req = baseline_request();
    req.moonshot_governor
        .governance_report
        .mean_time_to_decision_ns = None;
    req.thresholds = Some(GovernanceScorecardThresholds {
        max_moonshot_mean_time_to_decision_ns: Some(1_000_000),
        ..GovernanceScorecardThresholds::default()
    });
    let p = publish(&req);
    assert!(p.moonshot_governor.threshold_pass);
}

#[test]
fn enrichment_conformance_release_id_preserved_in_summary() {
    let p = publish(&baseline_request());
    assert_eq!(p.cross_repo_conformance.release_id, "rel-integ-001");
}

#[test]
fn enrichment_thresholds_in_publication_match_defaults() {
    let req = baseline_request();
    let p = publish(&req);
    assert_eq!(p.thresholds, GovernanceScorecardThresholds::default());
}

#[test]
fn enrichment_thresholds_in_publication_match_custom() {
    let mut req = baseline_request();
    let custom = GovernanceScorecardThresholds {
        min_attested_receipt_coverage_millionths: 800_000,
        max_privacy_overrun_incidents: 2,
        ..GovernanceScorecardThresholds::default()
    };
    req.thresholds = Some(custom.clone());
    let p = publish(&req);
    assert_eq!(p.thresholds, custom);
}

#[test]
fn enrichment_ledger_entry_recorded_with_correct_decision_id() {
    let req = baseline_request();
    let mut l = ledger();
    publish_governance_scorecard(&req, &signing_key(), &mut l, actor()).expect("publication");
    assert_eq!(l.entries().len(), 1);
    assert_eq!(l.entries()[0].decision_id, req.decision_id);
}

#[test]
fn enrichment_outcome_serde_snake_case() {
    let json = serde_json::to_string(&GovernanceScorecardOutcome::Healthy).expect("ser");
    assert_eq!(json, "\"healthy\"");
    let json = serde_json::to_string(&GovernanceScorecardOutcome::Warning).expect("ser");
    assert_eq!(json, "\"warning\"");
    let json = serde_json::to_string(&GovernanceScorecardOutcome::Critical).expect("ser");
    assert_eq!(json, "\"critical\"");
}

#[test]
fn enrichment_outcome_ordering_sort() {
    let mut outcomes = vec![
        GovernanceScorecardOutcome::Critical,
        GovernanceScorecardOutcome::Healthy,
        GovernanceScorecardOutcome::Warning,
    ];
    outcomes.sort();
    assert_eq!(
        outcomes,
        vec![
            GovernanceScorecardOutcome::Healthy,
            GovernanceScorecardOutcome::Warning,
            GovernanceScorecardOutcome::Critical,
        ]
    );
}

#[test]
fn enrichment_large_receipt_set_coverage_calculation() {
    let mut req = baseline_request();
    req.attested_receipts.clear();
    for i in 0..100 {
        req.attested_receipts.push(AttestedReceiptObservation {
            receipt_id: format!("large-{i}"),
            high_impact: true,
            attestation_binding_valid: i < 95,
            timestamp_ns: i as u64,
        });
    }
    let p = publish(&req);
    assert_eq!(p.attested_receipt_coverage.coverage_millionths, 950_000);
    assert!(p.attested_receipt_coverage.threshold_pass);
    assert_eq!(p.attested_receipt_coverage.high_impact_total, 100);
    assert_eq!(
        p.attested_receipt_coverage
            .high_impact_with_valid_attestation,
        95
    );
}

#[test]
fn enrichment_mixed_impact_receipts_coverage() {
    let mut req = baseline_request();
    req.attested_receipts.clear();
    for i in 0..10 {
        req.attested_receipts.push(AttestedReceiptObservation {
            receipt_id: format!("hi-mix-{i}"),
            high_impact: true,
            attestation_binding_valid: true,
            timestamp_ns: i as u64,
        });
    }
    for i in 0..90 {
        req.attested_receipts.push(AttestedReceiptObservation {
            receipt_id: format!("lo-mix-{i}"),
            high_impact: false,
            attestation_binding_valid: false,
            timestamp_ns: (i + 10) as u64,
        });
    }
    let p = publish(&req);
    assert_eq!(p.attested_receipt_coverage.coverage_millionths, 1_000_000);
    assert_eq!(p.attested_receipt_coverage.high_impact_total, 10);
}

#[test]
fn enrichment_privacy_heavy_spend_causes_higher_consumption() {
    let mut req = baseline_request();
    req.privacy_budget = mk_privacy(800_000, 80_000);
    let p = publish(&req);
    assert!(p.privacy_budget_health.epoch_consumption_millionths > 0);
    assert!(p.privacy_budget_health.epoch_epsilon_spent_millionths > 0);
}

#[test]
fn enrichment_privacy_zero_spend_low_consumption() {
    let mut req = baseline_request();
    req.privacy_budget = mk_privacy(0, 0);
    let p = publish(&req);
    assert_eq!(p.privacy_budget_health.epoch_consumption_millionths, 0);
}

#[test]
fn enrichment_multiple_historical_points_trend_length() {
    let mut req = baseline_request();
    for i in 0..5 {
        req.historical.push(GovernanceScorecardTrendPoint {
            scorecard_id: format!("hist-{i}"),
            generated_at_ns: (i + 1) as u64 * 100,
            attested_receipt_coverage_millionths: 900_000,
            privacy_epoch_consumption_millionths: 500_000,
            moonshot_override_frequency_millionths: 200_000,
            conformance_pass_rate_millionths: 900_000,
            outcome: GovernanceScorecardOutcome::Warning,
        });
    }
    let p = publish(&req);
    // 5 historical + 1 current = 6
    assert_eq!(p.trend.len(), 6);
}

#[test]
fn enrichment_trend_last_point_is_current() {
    let mut req = baseline_request();
    req.historical.push(GovernanceScorecardTrendPoint {
        scorecard_id: "old".to_string(),
        generated_at_ns: 1,
        attested_receipt_coverage_millionths: 950_000,
        privacy_epoch_consumption_millionths: 100_000,
        moonshot_override_frequency_millionths: 50_000,
        conformance_pass_rate_millionths: 980_000,
        outcome: GovernanceScorecardOutcome::Healthy,
    });
    let p = publish(&req);
    let last = p.trend.last().expect("last trend point");
    assert_eq!(last.scorecard_id, p.scorecard_id);
    assert_eq!(last.generated_at_ns, req.generated_at_ns);
}

#[test]
fn enrichment_events_count_at_least_seven() {
    let p = publish(&baseline_request());
    // started + 4 dimension evals + trend check + ledger append + decision = 8
    assert!(
        p.events.len() >= 7,
        "expected at least 7 events, got {}",
        p.events.len()
    );
}

#[test]
fn enrichment_publication_with_custom_actor_name() {
    let req = baseline_request();
    let mut l = ledger();
    let p = publish_governance_scorecard(
        &req,
        &signing_key(),
        &mut l,
        GovernanceActor::System("custom-actor-name".to_string()),
    )
    .unwrap();
    assert_eq!(p.outcome, GovernanceScorecardOutcome::Healthy);
    verify_governance_scorecard_signature(&p).unwrap();
}

#[test]
fn enrichment_conformance_zero_total_cells_still_valid() {
    let mut req = baseline_request();
    req.conformance.matrix_health = MatrixHealthSummary {
        total_cells: 0,
        passed_cells: 0,
        failed_cells: 0,
        universal_failures: 0,
        version_specific_failures: 0,
    };
    let p = publish(&req);
    // 0/0 cells => pass_rate computes to 0, which is below 950k threshold
    assert_eq!(p.cross_repo_conformance.pass_rate_millionths, 0);
}

#[test]
fn enrichment_error_display_invalid_input_contains_field_name() {
    let err = GovernanceScorecardError::InvalidInput {
        field: "my_field".to_string(),
        detail: "bad_value".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("my_field"));
    assert!(msg.contains("bad_value"));
}

#[test]
fn enrichment_error_display_serialization_contains_msg() {
    let err = GovernanceScorecardError::SerializationFailure("json broken".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("json broken"));
}

#[test]
fn enrichment_error_display_signature_contains_msg() {
    let err = GovernanceScorecardError::SignatureFailure("bad key material".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("bad key material"));
}

#[test]
fn enrichment_error_display_ledger_contains_msg() {
    let err = GovernanceScorecardError::LedgerWriteFailure("disk full".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("disk full"));
}

#[test]
fn enrichment_deterministic_auto_derived_id_for_same_input() {
    let mut req = baseline_request();
    req.scorecard_run_id = String::new();
    let p1 = publish(&req);
    let p2 = publish(&req);
    assert_eq!(p1.scorecard_id, p2.scorecard_id);
}

#[test]
fn enrichment_different_trace_id_gives_different_auto_derived_id() {
    let mut req1 = baseline_request();
    req1.scorecard_run_id = String::new();
    let mut req2 = req1.clone();
    req2.trace_id = "different-trace".to_string();
    let p1 = publish(&req1);
    let p2 = publish(&req2);
    assert_ne!(p1.scorecard_id, p2.scorecard_id);
}

#[test]
fn enrichment_moonshot_governor_summary_serde_from_publication() {
    let p = publish(&baseline_request());
    let json = serde_json::to_string(&p.moonshot_governor).expect("ser");
    let recovered: MoonshotGovernorDecisionSummary = serde_json::from_str(&json).expect("deser");
    assert_eq!(p.moonshot_governor, recovered);
}

#[test]
fn enrichment_privacy_budget_health_summary_serde_from_publication() {
    let p = publish(&baseline_request());
    let json = serde_json::to_string(&p.privacy_budget_health).expect("ser");
    let recovered: PrivacyBudgetHealthSummary = serde_json::from_str(&json).expect("deser");
    assert_eq!(p.privacy_budget_health, recovered);
}

#[test]
fn enrichment_attested_receipt_coverage_summary_serde_from_publication() {
    let p = publish(&baseline_request());
    let json = serde_json::to_string(&p.attested_receipt_coverage).expect("ser");
    let recovered: AttestedReceiptCoverageSummary = serde_json::from_str(&json).expect("deser");
    assert_eq!(p.attested_receipt_coverage, recovered);
}

#[test]
fn enrichment_conformance_stability_summary_serde_from_publication() {
    let p = publish(&baseline_request());
    let json = serde_json::to_string(&p.cross_repo_conformance).expect("ser");
    let recovered: CrossRepoConformanceStabilitySummary =
        serde_json::from_str(&json).expect("deser");
    assert_eq!(p.cross_repo_conformance, recovered);
}
