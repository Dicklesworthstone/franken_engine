#![forbid(unsafe_code)]
//! Enrichment integration tests for `incentive_governance_mechanism` module.
//!
//! Covers: Display uniqueness for all enums, serde roundtrips for every public type,
//! method behavior and edge cases, deterministic hash/ID computation, builder fluent
//! API, canonical mechanism validation, report generation, and incentive-compatibility
//! property verification.

use std::collections::BTreeSet;

use frankenengine_engine::incentive_governance_mechanism::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn test_epoch() -> SecurityEpoch {
    epoch(42)
}

fn make_payoff_entry(
    role: GovernanceRole,
    action: GovernanceAction,
    condition: &str,
    payoff: i64,
) -> PayoffEntry {
    PayoffEntry {
        role,
        action,
        condition: condition.into(),
        payoff_millionths: payoff,
        rationale: format!("test-{condition}"),
    }
}

fn make_scenario(
    id: &str,
    behavior: StrategicBehavior,
    role: GovernanceRole,
    expected: i64,
    honest: i64,
) -> StrategicScenario {
    StrategicScenario {
        scenario_id: id.into(),
        name: format!("scenario-{id}"),
        behavior,
        role,
        description: format!("test scenario {id}"),
        expected_payoff_millionths: expected,
        honest_alternative_payoff_millionths: honest,
    }
}

fn make_enforcement_rule(
    id: &str,
    trigger: GovernanceAction,
    role: GovernanceRole,
    enforcement: GovernanceAction,
    penalty: i64,
    reward: i64,
    cooldown: u64,
) -> EnforcementRule {
    EnforcementRule {
        rule_id: id.into(),
        trigger_action: trigger,
        trigger_role: role,
        condition: format!("cond-{id}"),
        enforcement_action: enforcement,
        penalty_millionths: penalty,
        reward_millionths: reward,
        cooldown_epochs: cooldown,
    }
}

fn make_verification(
    prop: IncentiveProperty,
    status: VerificationStatus,
) -> PropertyVerification {
    PropertyVerification {
        property: prop,
        status,
        assumptions: vec!["assumption-1".into()],
        evidence: format!("{} check", prop),
        counterexample: if status == VerificationStatus::Falsified {
            Some("counterexample-1".into())
        } else {
            None
        },
    }
}

/// Build a sound mechanism with all properties verified and budget-balanced payoffs.
fn make_sound_mechanism() -> MechanismSpec {
    MechanismBuilder::new("sound-mech")
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Reward,
            "good",
            50_000,
            "reward",
        )
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Slash,
            "bad",
            -200_000,
            "penalty",
        )
        .verify_property(make_verification(
            IncentiveProperty::TruthfulReporting,
            VerificationStatus::Verified,
        ))
        .verify_property(make_verification(
            IncentiveProperty::BudgetBalance,
            VerificationStatus::Verified,
        ))
        .scenario(make_scenario(
            "s1",
            StrategicBehavior::FalseReport,
            GovernanceRole::Publisher,
            -200_000,
            50_000,
        ))
        .build(test_epoch())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("incentive-governance"));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrichment_default_publisher_bond_positive() {
    const { assert!(DEFAULT_PUBLISHER_BOND > 0) };
    assert_eq!(DEFAULT_PUBLISHER_BOND, 100_000);
}

#[test]
fn enrichment_default_challenge_window_positive() {
    const { assert!(DEFAULT_CHALLENGE_WINDOW_EPOCHS > 0) };
    assert_eq!(DEFAULT_CHALLENGE_WINDOW_EPOCHS, 10);
}

// ---------------------------------------------------------------------------
// GovernanceRole — Display, serde, ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_governance_role_display_all_unique() {
    let mut seen = BTreeSet::new();
    for role in GovernanceRole::ALL {
        let s = role.to_string();
        assert!(!s.is_empty());
        assert!(seen.insert(s), "duplicate display for {role:?}");
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn enrichment_governance_role_display_exact_strings() {
    assert_eq!(GovernanceRole::Publisher.to_string(), "publisher");
    assert_eq!(GovernanceRole::Operator.to_string(), "operator");
    assert_eq!(GovernanceRole::Challenger.to_string(), "challenger");
    assert_eq!(GovernanceRole::Arbitrator.to_string(), "arbitrator");
    assert_eq!(GovernanceRole::ControlPlane.to_string(), "control_plane");
}

#[test]
fn enrichment_governance_role_serde_roundtrip_all() {
    for role in GovernanceRole::ALL {
        let json = serde_json::to_string(&role).unwrap();
        let back: GovernanceRole = serde_json::from_str(&json).unwrap();
        assert_eq!(role, back);
    }
}

#[test]
fn enrichment_governance_role_serde_snake_case() {
    let json = serde_json::to_string(&GovernanceRole::ControlPlane).unwrap();
    assert_eq!(json, "\"control_plane\"");
}

#[test]
fn enrichment_governance_role_all_count() {
    assert_eq!(GovernanceRole::ALL.len(), 5);
}

#[test]
fn enrichment_governance_role_ordering() {
    assert!(GovernanceRole::Publisher < GovernanceRole::Operator);
    assert!(GovernanceRole::Operator < GovernanceRole::Challenger);
    assert!(GovernanceRole::Challenger < GovernanceRole::Arbitrator);
    assert!(GovernanceRole::Arbitrator < GovernanceRole::ControlPlane);
}

// ---------------------------------------------------------------------------
// GovernanceAction — Display, serde, ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_governance_action_display_all_unique() {
    let mut seen = BTreeSet::new();
    for action in GovernanceAction::ALL {
        let s = action.to_string();
        assert!(!s.is_empty());
        assert!(seen.insert(s), "duplicate display for {action:?}");
    }
    assert_eq!(seen.len(), 8);
}

#[test]
fn enrichment_governance_action_display_exact_strings() {
    assert_eq!(GovernanceAction::Report.to_string(), "report");
    assert_eq!(GovernanceAction::Challenge.to_string(), "challenge");
    assert_eq!(GovernanceAction::Quarantine.to_string(), "quarantine");
    assert_eq!(GovernanceAction::Reinstate.to_string(), "reinstate");
    assert_eq!(GovernanceAction::Slash.to_string(), "slash");
    assert_eq!(GovernanceAction::Reward.to_string(), "reward");
    assert_eq!(GovernanceAction::Escalate.to_string(), "escalate");
    assert_eq!(GovernanceAction::Appeal.to_string(), "appeal");
}

#[test]
fn enrichment_governance_action_serde_roundtrip_all() {
    for action in GovernanceAction::ALL {
        let json = serde_json::to_string(&action).unwrap();
        let back: GovernanceAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }
}

#[test]
fn enrichment_governance_action_all_count() {
    assert_eq!(GovernanceAction::ALL.len(), 8);
}

#[test]
fn enrichment_governance_action_ordering() {
    assert!(GovernanceAction::Report < GovernanceAction::Challenge);
    assert!(GovernanceAction::Escalate < GovernanceAction::Appeal);
}

// ---------------------------------------------------------------------------
// IncentiveProperty — Display, serde, ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_incentive_property_display_all_unique() {
    let mut seen = BTreeSet::new();
    for prop in IncentiveProperty::ALL {
        let s = prop.to_string();
        assert!(!s.is_empty());
        assert!(seen.insert(s), "duplicate display for {prop:?}");
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn enrichment_incentive_property_display_exact_strings() {
    assert_eq!(
        IncentiveProperty::TruthfulReporting.to_string(),
        "truthful_reporting"
    );
    assert_eq!(
        IncentiveProperty::TimelyRemediation.to_string(),
        "timely_remediation"
    );
    assert_eq!(
        IncentiveProperty::FalseChallengeUnprofitable.to_string(),
        "false_challenge_unprofitable"
    );
    assert_eq!(
        IncentiveProperty::HonestOperatorDominance.to_string(),
        "honest_operator_dominance"
    );
    assert_eq!(
        IncentiveProperty::BudgetBalance.to_string(),
        "budget_balance"
    );
}

#[test]
fn enrichment_incentive_property_serde_roundtrip_all() {
    for prop in IncentiveProperty::ALL {
        let json = serde_json::to_string(&prop).unwrap();
        let back: IncentiveProperty = serde_json::from_str(&json).unwrap();
        assert_eq!(prop, back);
    }
}

#[test]
fn enrichment_incentive_property_all_count() {
    assert_eq!(IncentiveProperty::ALL.len(), 5);
}

#[test]
fn enrichment_incentive_property_ordering() {
    assert!(IncentiveProperty::TruthfulReporting < IncentiveProperty::TimelyRemediation);
    assert!(IncentiveProperty::HonestOperatorDominance < IncentiveProperty::BudgetBalance);
}

// ---------------------------------------------------------------------------
// StrategicBehavior — Display, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_strategic_behavior_display_all_unique() {
    let behaviors = [
        StrategicBehavior::TruthfulReport,
        StrategicBehavior::FalseReport,
        StrategicBehavior::DelayedRemediation,
        StrategicBehavior::ImmediateRemediation,
        StrategicBehavior::FrivolousChallenge,
        StrategicBehavior::LegitimateChallenge,
        StrategicBehavior::CollaborativeAttack,
        StrategicBehavior::SybilAttack,
    ];
    let mut seen = BTreeSet::new();
    for b in behaviors {
        let s = b.to_string();
        assert!(!s.is_empty());
        assert!(seen.insert(s), "duplicate display for {b:?}");
    }
    assert_eq!(seen.len(), 8);
}

#[test]
fn enrichment_strategic_behavior_display_exact_strings() {
    assert_eq!(StrategicBehavior::TruthfulReport.to_string(), "truthful_report");
    assert_eq!(StrategicBehavior::FalseReport.to_string(), "false_report");
    assert_eq!(
        StrategicBehavior::DelayedRemediation.to_string(),
        "delayed_remediation"
    );
    assert_eq!(
        StrategicBehavior::ImmediateRemediation.to_string(),
        "immediate_remediation"
    );
    assert_eq!(
        StrategicBehavior::FrivolousChallenge.to_string(),
        "frivolous_challenge"
    );
    assert_eq!(
        StrategicBehavior::LegitimateChallenge.to_string(),
        "legitimate_challenge"
    );
    assert_eq!(
        StrategicBehavior::CollaborativeAttack.to_string(),
        "collaborative_attack"
    );
    assert_eq!(StrategicBehavior::SybilAttack.to_string(), "sybil_attack");
}

#[test]
fn enrichment_strategic_behavior_serde_roundtrip_all() {
    let behaviors = [
        StrategicBehavior::TruthfulReport,
        StrategicBehavior::FalseReport,
        StrategicBehavior::DelayedRemediation,
        StrategicBehavior::ImmediateRemediation,
        StrategicBehavior::FrivolousChallenge,
        StrategicBehavior::LegitimateChallenge,
        StrategicBehavior::CollaborativeAttack,
        StrategicBehavior::SybilAttack,
    ];
    for b in behaviors {
        let json = serde_json::to_string(&b).unwrap();
        let back: StrategicBehavior = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }
}

// ---------------------------------------------------------------------------
// VerificationStatus — Display, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verification_status_display_all_unique() {
    let statuses = [
        VerificationStatus::Verified,
        VerificationStatus::Falsified,
        VerificationStatus::Inconclusive,
    ];
    let mut seen = BTreeSet::new();
    for s in statuses {
        let d = s.to_string();
        assert!(!d.is_empty());
        assert!(seen.insert(d), "duplicate display for {s:?}");
    }
    assert_eq!(seen.len(), 3);
}

#[test]
fn enrichment_verification_status_display_exact_strings() {
    assert_eq!(VerificationStatus::Verified.to_string(), "verified");
    assert_eq!(VerificationStatus::Falsified.to_string(), "falsified");
    assert_eq!(VerificationStatus::Inconclusive.to_string(), "inconclusive");
}

#[test]
fn enrichment_verification_status_serde_roundtrip_all() {
    for s in [
        VerificationStatus::Verified,
        VerificationStatus::Falsified,
        VerificationStatus::Inconclusive,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: VerificationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// PayoffEntry — construction, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_payoff_entry_construction_and_fields() {
    let entry = make_payoff_entry(
        GovernanceRole::Publisher,
        GovernanceAction::Report,
        "truth",
        50_000,
    );
    assert_eq!(entry.role, GovernanceRole::Publisher);
    assert_eq!(entry.action, GovernanceAction::Report);
    assert_eq!(entry.condition, "truth");
    assert_eq!(entry.payoff_millionths, 50_000);
    assert_eq!(entry.rationale, "test-truth");
}

#[test]
fn enrichment_payoff_entry_serde_roundtrip() {
    let entry = make_payoff_entry(
        GovernanceRole::Arbitrator,
        GovernanceAction::Appeal,
        "contested",
        -25_000,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: PayoffEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// PayoffTable — compute_id, total_payoff_for_role, is_budget_balanced, entries_for_action
// ---------------------------------------------------------------------------

#[test]
fn enrichment_payoff_table_compute_id_deterministic() {
    let mk = || {
        let mut t = PayoffTable {
            table_id: String::new(),
            entries: vec![make_payoff_entry(
                GovernanceRole::Publisher,
                GovernanceAction::Report,
                "truth",
                50_000,
            )],
            epoch: test_epoch(),
        };
        t.table_id = t.compute_id();
        t
    };
    assert_eq!(mk().table_id, mk().table_id);
}

#[test]
fn enrichment_payoff_table_compute_id_prefix() {
    let t = PayoffTable {
        table_id: String::new(),
        entries: vec![],
        epoch: test_epoch(),
    };
    assert!(t.compute_id().starts_with("pt-"));
}

#[test]
fn enrichment_payoff_table_compute_id_changes_with_epoch() {
    let mk = |e: u64| {
        PayoffTable {
            table_id: String::new(),
            entries: vec![make_payoff_entry(
                GovernanceRole::Publisher,
                GovernanceAction::Report,
                "c",
                10_000,
            )],
            epoch: epoch(e),
        }
        .compute_id()
    };
    assert_ne!(mk(1), mk(2));
}

#[test]
fn enrichment_payoff_table_compute_id_changes_with_payoff() {
    let mk = |p: i64| {
        PayoffTable {
            table_id: String::new(),
            entries: vec![make_payoff_entry(
                GovernanceRole::Publisher,
                GovernanceAction::Report,
                "c",
                p,
            )],
            epoch: test_epoch(),
        }
        .compute_id()
    };
    assert_ne!(mk(10_000), mk(20_000));
}

#[test]
fn enrichment_payoff_table_total_payoff_for_role_single_role() {
    let table = PayoffTable {
        table_id: "t".into(),
        entries: vec![
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Reward, "a", 50_000),
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Slash, "b", -200_000),
        ],
        epoch: test_epoch(),
    };
    assert_eq!(
        table.total_payoff_for_role(GovernanceRole::Publisher),
        -150_000
    );
}

#[test]
fn enrichment_payoff_table_total_payoff_for_role_absent() {
    let table = PayoffTable {
        table_id: "t".into(),
        entries: vec![make_payoff_entry(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "c",
            50_000,
        )],
        epoch: test_epoch(),
    };
    assert_eq!(table.total_payoff_for_role(GovernanceRole::Operator), 0);
}

#[test]
fn enrichment_payoff_table_total_payoff_for_role_empty() {
    let table = PayoffTable {
        table_id: "t".into(),
        entries: vec![],
        epoch: test_epoch(),
    };
    assert_eq!(
        table.total_payoff_for_role(GovernanceRole::Publisher),
        0
    );
}

#[test]
fn enrichment_payoff_table_budget_balanced_equal() {
    let table = PayoffTable {
        table_id: "t".into(),
        entries: vec![
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Reward, "a", 100_000),
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Slash, "b", -100_000),
        ],
        epoch: test_epoch(),
    };
    assert!(table.is_budget_balanced());
}

#[test]
fn enrichment_payoff_table_budget_balanced_penalties_exceed_rewards() {
    let table = PayoffTable {
        table_id: "t".into(),
        entries: vec![
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Reward, "a", 50_000),
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Slash, "b", -200_000),
        ],
        epoch: test_epoch(),
    };
    assert!(table.is_budget_balanced());
}

#[test]
fn enrichment_payoff_table_not_budget_balanced_rewards_exceed() {
    let table = PayoffTable {
        table_id: "t".into(),
        entries: vec![
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Reward, "a", 300_000),
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Slash, "b", -100_000),
        ],
        epoch: test_epoch(),
    };
    assert!(!table.is_budget_balanced());
}

#[test]
fn enrichment_payoff_table_budget_balanced_empty() {
    let table = PayoffTable {
        table_id: "t".into(),
        entries: vec![],
        epoch: test_epoch(),
    };
    assert!(table.is_budget_balanced());
}

#[test]
fn enrichment_payoff_table_budget_balanced_all_negative() {
    let table = PayoffTable {
        table_id: "t".into(),
        entries: vec![
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Slash, "a", -50_000),
            make_payoff_entry(GovernanceRole::Operator, GovernanceAction::Slash, "b", -30_000),
        ],
        epoch: test_epoch(),
    };
    assert!(table.is_budget_balanced());
}

#[test]
fn enrichment_payoff_table_entries_for_action_match() {
    let table = PayoffTable {
        table_id: "t".into(),
        entries: vec![
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Report, "a", 50_000),
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Report, "b", -200_000),
            make_payoff_entry(GovernanceRole::Challenger, GovernanceAction::Challenge, "c", 100_000),
        ],
        epoch: test_epoch(),
    };
    assert_eq!(table.entries_for_action(GovernanceAction::Report).len(), 2);
    assert_eq!(table.entries_for_action(GovernanceAction::Challenge).len(), 1);
    assert_eq!(table.entries_for_action(GovernanceAction::Quarantine).len(), 0);
}

#[test]
fn enrichment_payoff_table_serde_roundtrip() {
    let table = PayoffTable {
        table_id: "pt-test".into(),
        entries: vec![
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Report, "a", 50_000),
            make_payoff_entry(GovernanceRole::Challenger, GovernanceAction::Slash, "b", -100_000),
        ],
        epoch: test_epoch(),
    };
    let json = serde_json::to_string(&table).unwrap();
    let back: PayoffTable = serde_json::from_str(&json).unwrap();
    assert_eq!(table, back);
}

// ---------------------------------------------------------------------------
// StrategicScenario — honest_dominates, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_strategic_scenario_honest_dominates_true() {
    let s = make_scenario(
        "s1",
        StrategicBehavior::FalseReport,
        GovernanceRole::Publisher,
        -200_000,
        50_000,
    );
    assert!(s.honest_dominates());
}

#[test]
fn enrichment_strategic_scenario_honest_dominates_equal() {
    let s = make_scenario(
        "s-tie",
        StrategicBehavior::FalseReport,
        GovernanceRole::Publisher,
        50_000,
        50_000,
    );
    assert!(s.honest_dominates(), "equal payoffs means honest dominates");
}

#[test]
fn enrichment_strategic_scenario_dishonest_profitable() {
    let s = make_scenario(
        "s-exploit",
        StrategicBehavior::CollaborativeAttack,
        GovernanceRole::Publisher,
        200_000,
        50_000,
    );
    assert!(!s.honest_dominates());
}

#[test]
fn enrichment_strategic_scenario_both_negative_honest_dominates() {
    let s = make_scenario(
        "s-both-neg",
        StrategicBehavior::FrivolousChallenge,
        GovernanceRole::Challenger,
        -300_000,
        -50_000,
    );
    assert!(s.honest_dominates());
}

#[test]
fn enrichment_strategic_scenario_both_zero() {
    let s = make_scenario(
        "s-zero",
        StrategicBehavior::TruthfulReport,
        GovernanceRole::Publisher,
        0,
        0,
    );
    assert!(s.honest_dominates());
}

#[test]
fn enrichment_strategic_scenario_serde_roundtrip() {
    let s = make_scenario(
        "s1",
        StrategicBehavior::SybilAttack,
        GovernanceRole::Operator,
        -50_000,
        30_000,
    );
    let json = serde_json::to_string(&s).unwrap();
    let back: StrategicScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_strategic_scenario_field_access() {
    let s = make_scenario(
        "s-field",
        StrategicBehavior::LegitimateChallenge,
        GovernanceRole::Challenger,
        100_000,
        100_000,
    );
    assert_eq!(s.scenario_id, "s-field");
    assert_eq!(s.behavior, StrategicBehavior::LegitimateChallenge);
    assert_eq!(s.role, GovernanceRole::Challenger);
    assert_eq!(s.expected_payoff_millionths, 100_000);
    assert_eq!(s.honest_alternative_payoff_millionths, 100_000);
}

// ---------------------------------------------------------------------------
// StrategicStressTest — compute_id, honest_dominance_rate, exploitable_scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stress_test_compute_id_prefix() {
    let sst = StrategicStressTest {
        test_id: String::new(),
        scenarios: vec![],
        epoch: test_epoch(),
    };
    assert!(sst.compute_id().starts_with("sst-"));
}

#[test]
fn enrichment_stress_test_compute_id_deterministic() {
    let mk = || StrategicStressTest {
        test_id: String::new(),
        scenarios: vec![make_scenario(
            "s1",
            StrategicBehavior::FalseReport,
            GovernanceRole::Publisher,
            -100_000,
            50_000,
        )],
        epoch: test_epoch(),
    };
    assert_eq!(mk().compute_id(), mk().compute_id());
}

#[test]
fn enrichment_stress_test_compute_id_changes_with_epoch() {
    let mk = |e: u64| {
        StrategicStressTest {
            test_id: String::new(),
            scenarios: vec![],
            epoch: epoch(e),
        }
        .compute_id()
    };
    assert_ne!(mk(1), mk(2));
}

#[test]
fn enrichment_stress_test_empty_scenarios_returns_million() {
    let sst = StrategicStressTest {
        test_id: "t".into(),
        scenarios: vec![],
        epoch: test_epoch(),
    };
    assert_eq!(sst.honest_dominance_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_stress_test_all_honest_is_million() {
    let sst = StrategicStressTest {
        test_id: "t".into(),
        scenarios: vec![
            make_scenario("s1", StrategicBehavior::FalseReport, GovernanceRole::Publisher, -100_000, 50_000),
            make_scenario("s2", StrategicBehavior::FrivolousChallenge, GovernanceRole::Challenger, -50_000, 20_000),
        ],
        epoch: test_epoch(),
    };
    assert_eq!(sst.honest_dominance_rate_millionths(), 1_000_000);
    assert!(sst.exploitable_scenarios().is_empty());
}

#[test]
fn enrichment_stress_test_half_honest_rate() {
    let sst = StrategicStressTest {
        test_id: "t".into(),
        scenarios: vec![
            make_scenario("s1", StrategicBehavior::FalseReport, GovernanceRole::Publisher, -100_000, 50_000),
            make_scenario("s2", StrategicBehavior::CollaborativeAttack, GovernanceRole::Publisher, 200_000, 50_000),
        ],
        epoch: test_epoch(),
    };
    assert_eq!(sst.honest_dominance_rate_millionths(), 500_000);
    assert_eq!(sst.exploitable_scenarios().len(), 1);
}

#[test]
fn enrichment_stress_test_all_exploitable() {
    let sst = StrategicStressTest {
        test_id: "t".into(),
        scenarios: vec![
            make_scenario("s1", StrategicBehavior::CollaborativeAttack, GovernanceRole::Publisher, 200_000, 50_000),
            make_scenario("s2", StrategicBehavior::SybilAttack, GovernanceRole::Challenger, 300_000, 0),
        ],
        epoch: test_epoch(),
    };
    assert_eq!(sst.honest_dominance_rate_millionths(), 0);
    assert_eq!(sst.exploitable_scenarios().len(), 2);
}

#[test]
fn enrichment_stress_test_one_of_three_exploitable() {
    let sst = StrategicStressTest {
        test_id: "t".into(),
        scenarios: vec![
            make_scenario("s1", StrategicBehavior::FalseReport, GovernanceRole::Publisher, -100_000, 50_000),
            make_scenario("s2", StrategicBehavior::FrivolousChallenge, GovernanceRole::Challenger, -50_000, 20_000),
            make_scenario("s3", StrategicBehavior::SybilAttack, GovernanceRole::Challenger, 300_000, 0),
        ],
        epoch: test_epoch(),
    };
    // 2 out of 3 honest
    assert_eq!(sst.honest_dominance_rate_millionths(), 666_666);
    assert_eq!(sst.exploitable_scenarios().len(), 1);
}

#[test]
fn enrichment_stress_test_serde_roundtrip() {
    let sst = StrategicStressTest {
        test_id: "sst-test".into(),
        scenarios: vec![make_scenario(
            "s1",
            StrategicBehavior::FalseReport,
            GovernanceRole::Publisher,
            -100_000,
            50_000,
        )],
        epoch: test_epoch(),
    };
    let json = serde_json::to_string(&sst).unwrap();
    let back: StrategicStressTest = serde_json::from_str(&json).unwrap();
    assert_eq!(sst, back);
}

// ---------------------------------------------------------------------------
// PropertyVerification — serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_property_verification_serde_roundtrip_with_counterexample() {
    let pv = PropertyVerification {
        property: IncentiveProperty::BudgetBalance,
        status: VerificationStatus::Falsified,
        assumptions: vec!["a1".into(), "a2".into()],
        evidence: "fail".into(),
        counterexample: Some("counter-1".into()),
    };
    let json = serde_json::to_string(&pv).unwrap();
    let back: PropertyVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(pv, back);
}

#[test]
fn enrichment_property_verification_serde_roundtrip_no_counterexample() {
    let pv = PropertyVerification {
        property: IncentiveProperty::TruthfulReporting,
        status: VerificationStatus::Verified,
        assumptions: vec!["rational actors".into()],
        evidence: "ok".into(),
        counterexample: None,
    };
    let json = serde_json::to_string(&pv).unwrap();
    let back: PropertyVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(pv, back);
}

// ---------------------------------------------------------------------------
// EnforcementRule — construction, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_enforcement_rule_construction_and_fields() {
    let rule = make_enforcement_rule(
        "r1",
        GovernanceAction::Report,
        GovernanceRole::Publisher,
        GovernanceAction::Quarantine,
        0,
        50_000,
        0,
    );
    assert_eq!(rule.rule_id, "r1");
    assert_eq!(rule.trigger_action, GovernanceAction::Report);
    assert_eq!(rule.trigger_role, GovernanceRole::Publisher);
    assert_eq!(rule.enforcement_action, GovernanceAction::Quarantine);
    assert_eq!(rule.penalty_millionths, 0);
    assert_eq!(rule.reward_millionths, 50_000);
    assert_eq!(rule.cooldown_epochs, 0);
}

#[test]
fn enrichment_enforcement_rule_serde_roundtrip() {
    let rule = make_enforcement_rule(
        "r-test",
        GovernanceAction::Challenge,
        GovernanceRole::Challenger,
        GovernanceAction::Slash,
        150_000,
        0,
        3,
    );
    let json = serde_json::to_string(&rule).unwrap();
    let back: EnforcementRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

// ---------------------------------------------------------------------------
// EnforcementPolicy — compute_id, rules_for_trigger, max_total_penalty, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_enforcement_policy_compute_id_prefix() {
    let p = EnforcementPolicy {
        policy_id: String::new(),
        rules: vec![],
        challenge_window_epochs: 10,
        publisher_bond_millionths: 100_000,
        epoch: test_epoch(),
    };
    assert!(p.compute_id().starts_with("ep-"));
}

#[test]
fn enrichment_enforcement_policy_compute_id_deterministic() {
    let mk = || {
        EnforcementPolicy {
            policy_id: String::new(),
            rules: vec![make_enforcement_rule(
                "r1",
                GovernanceAction::Report,
                GovernanceRole::Publisher,
                GovernanceAction::Quarantine,
                0,
                50_000,
                0,
            )],
            challenge_window_epochs: 10,
            publisher_bond_millionths: 100_000,
            epoch: test_epoch(),
        }
        .compute_id()
    };
    assert_eq!(mk(), mk());
}

#[test]
fn enrichment_enforcement_policy_compute_id_changes_with_bond() {
    let mk = |bond| {
        EnforcementPolicy {
            policy_id: String::new(),
            rules: vec![],
            challenge_window_epochs: 10,
            publisher_bond_millionths: bond,
            epoch: test_epoch(),
        }
        .compute_id()
    };
    assert_ne!(mk(100_000), mk(200_000));
}

#[test]
fn enrichment_enforcement_policy_compute_id_changes_with_window() {
    let mk = |window| {
        EnforcementPolicy {
            policy_id: String::new(),
            rules: vec![],
            challenge_window_epochs: window,
            publisher_bond_millionths: 100_000,
            epoch: test_epoch(),
        }
        .compute_id()
    };
    assert_ne!(mk(5), mk(20));
}

#[test]
fn enrichment_enforcement_policy_rules_for_trigger_filters() {
    let policy = EnforcementPolicy {
        policy_id: "p".into(),
        rules: vec![
            make_enforcement_rule("r1", GovernanceAction::Report, GovernanceRole::Publisher, GovernanceAction::Quarantine, 0, 50_000, 0),
            make_enforcement_rule("r2", GovernanceAction::Report, GovernanceRole::Publisher, GovernanceAction::Slash, 200_000, 0, 5),
            make_enforcement_rule("r3", GovernanceAction::Challenge, GovernanceRole::Challenger, GovernanceAction::Reward, 0, 100_000, 0),
        ],
        challenge_window_epochs: 10,
        publisher_bond_millionths: 100_000,
        epoch: test_epoch(),
    };
    assert_eq!(policy.rules_for_trigger(GovernanceAction::Report).len(), 2);
    assert_eq!(policy.rules_for_trigger(GovernanceAction::Challenge).len(), 1);
    assert_eq!(policy.rules_for_trigger(GovernanceAction::Quarantine).len(), 0);
}

#[test]
fn enrichment_enforcement_policy_max_total_penalty_sums_all() {
    let policy = EnforcementPolicy {
        policy_id: "p".into(),
        rules: vec![
            make_enforcement_rule("r1", GovernanceAction::Report, GovernanceRole::Publisher, GovernanceAction::Slash, 200_000, 0, 5),
            make_enforcement_rule("r2", GovernanceAction::Challenge, GovernanceRole::Challenger, GovernanceAction::Slash, 150_000, 0, 3),
        ],
        challenge_window_epochs: 10,
        publisher_bond_millionths: 100_000,
        epoch: test_epoch(),
    };
    assert_eq!(policy.max_total_penalty(), 350_000);
}

#[test]
fn enrichment_enforcement_policy_max_total_penalty_empty() {
    let policy = EnforcementPolicy {
        policy_id: "p".into(),
        rules: vec![],
        challenge_window_epochs: 10,
        publisher_bond_millionths: 100_000,
        epoch: test_epoch(),
    };
    assert_eq!(policy.max_total_penalty(), 0);
}

#[test]
fn enrichment_enforcement_policy_serde_roundtrip() {
    let policy = EnforcementPolicy {
        policy_id: "ep-test".into(),
        rules: vec![make_enforcement_rule(
            "r1",
            GovernanceAction::Report,
            GovernanceRole::Publisher,
            GovernanceAction::Quarantine,
            0,
            50_000,
            0,
        )],
        challenge_window_epochs: 15,
        publisher_bond_millionths: 250_000,
        epoch: test_epoch(),
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: EnforcementPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// ---------------------------------------------------------------------------
// MechanismSpec — compute_id, verified_property_count, is_sound, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mechanism_spec_compute_id_prefix() {
    let spec = MechanismBuilder::new("test").build(test_epoch());
    assert!(spec.spec_id.starts_with("ms-"));
}

#[test]
fn enrichment_mechanism_spec_compute_id_deterministic() {
    let mk = || {
        MechanismBuilder::new("test")
            .payoff(GovernanceRole::Publisher, GovernanceAction::Report, "c", 10_000, "r")
            .build(test_epoch())
    };
    assert_eq!(mk().spec_id, mk().spec_id);
}

#[test]
fn enrichment_mechanism_spec_compute_id_changes_with_name() {
    let mk = |name| {
        MechanismBuilder::new(name)
            .payoff(GovernanceRole::Publisher, GovernanceAction::Slash, "c", -100_000, "r")
            .build(test_epoch())
    };
    assert_ne!(mk("alpha").spec_id, mk("beta").spec_id);
}

#[test]
fn enrichment_mechanism_spec_verified_property_count_zero() {
    let spec = MechanismBuilder::new("no-props").build(test_epoch());
    assert_eq!(spec.verified_property_count(), 0);
}

#[test]
fn enrichment_mechanism_spec_verified_property_count_partial() {
    let spec = MechanismBuilder::new("partial")
        .verify_property(make_verification(
            IncentiveProperty::TruthfulReporting,
            VerificationStatus::Verified,
        ))
        .verify_property(make_verification(
            IncentiveProperty::BudgetBalance,
            VerificationStatus::Falsified,
        ))
        .verify_property(make_verification(
            IncentiveProperty::HonestOperatorDominance,
            VerificationStatus::Inconclusive,
        ))
        .build(test_epoch());
    assert_eq!(spec.verified_property_count(), 1);
}

#[test]
fn enrichment_mechanism_spec_is_sound_requires_all_verified() {
    let spec = MechanismBuilder::new("mixed")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Slash, "bad", -100_000, "r")
        .verify_property(make_verification(
            IncentiveProperty::TruthfulReporting,
            VerificationStatus::Verified,
        ))
        .verify_property(make_verification(
            IncentiveProperty::BudgetBalance,
            VerificationStatus::Falsified,
        ))
        .scenario(make_scenario("s1", StrategicBehavior::FalseReport, GovernanceRole::Publisher, -100_000, 50_000))
        .build(test_epoch());
    assert!(!spec.is_sound());
}

#[test]
fn enrichment_mechanism_spec_is_sound_requires_budget_balance() {
    let spec = MechanismBuilder::new("unbalanced")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Reward, "good", 500_000, "r")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Slash, "bad", -100_000, "r")
        .verify_property(make_verification(
            IncentiveProperty::TruthfulReporting,
            VerificationStatus::Verified,
        ))
        .scenario(make_scenario("s1", StrategicBehavior::FalseReport, GovernanceRole::Publisher, -100_000, 50_000))
        .build(test_epoch());
    assert!(!spec.is_sound());
}

#[test]
fn enrichment_mechanism_spec_is_sound_requires_all_honest_dominate() {
    let spec = MechanismBuilder::new("exploit")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Slash, "bad", -100_000, "r")
        .verify_property(make_verification(
            IncentiveProperty::TruthfulReporting,
            VerificationStatus::Verified,
        ))
        .scenario(make_scenario("s1", StrategicBehavior::CollaborativeAttack, GovernanceRole::Publisher, 200_000, 50_000))
        .build(test_epoch());
    assert!(!spec.is_sound());
}

#[test]
fn enrichment_mechanism_spec_is_sound_all_conditions_met() {
    let spec = make_sound_mechanism();
    assert!(spec.is_sound());
}

#[test]
fn enrichment_mechanism_spec_is_sound_no_scenarios_no_properties() {
    // No properties => all() is vacuously true.
    // No scenarios => empty => dominance = MILLION.
    // Budget balanced => empty entries => 0 <= 0.
    let spec = MechanismBuilder::new("vacuous").build(test_epoch());
    assert!(spec.is_sound());
}

#[test]
fn enrichment_mechanism_spec_serde_roundtrip() {
    let spec = make_sound_mechanism();
    let json = serde_json::to_string(&spec).unwrap();
    let back: MechanismSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ---------------------------------------------------------------------------
// MechanismBuilder — fluent API
// ---------------------------------------------------------------------------

#[test]
fn enrichment_builder_defaults_match_constants() {
    let spec = MechanismBuilder::new("defaults").build(test_epoch());
    assert_eq!(spec.enforcement_policy.publisher_bond_millionths, DEFAULT_PUBLISHER_BOND);
    assert_eq!(spec.enforcement_policy.challenge_window_epochs, DEFAULT_CHALLENGE_WINDOW_EPOCHS);
}

#[test]
fn enrichment_builder_custom_bond() {
    let spec = MechanismBuilder::new("custom-bond")
        .publisher_bond(500_000)
        .build(test_epoch());
    assert_eq!(spec.enforcement_policy.publisher_bond_millionths, 500_000);
}

#[test]
fn enrichment_builder_custom_challenge_window() {
    let spec = MechanismBuilder::new("custom-window")
        .challenge_window(25)
        .build(test_epoch());
    assert_eq!(spec.enforcement_policy.challenge_window_epochs, 25);
}

#[test]
fn enrichment_builder_multiple_payoffs() {
    let spec = MechanismBuilder::new("multi-payoff")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Report, "truth", 50_000, "r")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Report, "false", -200_000, "p")
        .payoff(GovernanceRole::Challenger, GovernanceAction::Challenge, "legit", 100_000, "r")
        .build(test_epoch());
    assert_eq!(spec.payoff_table.entries.len(), 3);
}

#[test]
fn enrichment_builder_multiple_rules() {
    let spec = MechanismBuilder::new("multi-rule")
        .enforcement_rule(make_enforcement_rule("r1", GovernanceAction::Report, GovernanceRole::Publisher, GovernanceAction::Quarantine, 0, 50_000, 0))
        .enforcement_rule(make_enforcement_rule("r2", GovernanceAction::Challenge, GovernanceRole::Challenger, GovernanceAction::Slash, 150_000, 0, 3))
        .build(test_epoch());
    assert_eq!(spec.enforcement_policy.rules.len(), 2);
}

#[test]
fn enrichment_builder_multiple_properties() {
    let spec = MechanismBuilder::new("multi-prop")
        .verify_property(make_verification(IncentiveProperty::TruthfulReporting, VerificationStatus::Verified))
        .verify_property(make_verification(IncentiveProperty::BudgetBalance, VerificationStatus::Verified))
        .verify_property(make_verification(IncentiveProperty::TimelyRemediation, VerificationStatus::Inconclusive))
        .build(test_epoch());
    assert_eq!(spec.property_verifications.len(), 3);
    assert_eq!(spec.verified_property_count(), 2);
}

#[test]
fn enrichment_builder_multiple_scenarios() {
    let spec = MechanismBuilder::new("multi-scenario")
        .scenario(make_scenario("s1", StrategicBehavior::FalseReport, GovernanceRole::Publisher, -200_000, 50_000))
        .scenario(make_scenario("s2", StrategicBehavior::SybilAttack, GovernanceRole::Challenger, -300_000, 0))
        .build(test_epoch());
    assert_eq!(spec.stress_test.scenarios.len(), 2);
}

#[test]
fn enrichment_builder_sets_computed_ids() {
    let spec = MechanismBuilder::new("check-ids")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Report, "c", 10_000, "r")
        .enforcement_rule(make_enforcement_rule("r1", GovernanceAction::Report, GovernanceRole::Publisher, GovernanceAction::Quarantine, 0, 0, 0))
        .scenario(make_scenario("s1", StrategicBehavior::FalseReport, GovernanceRole::Publisher, -100_000, 50_000))
        .build(test_epoch());
    assert!(spec.spec_id.starts_with("ms-"));
    assert!(spec.payoff_table.table_id.starts_with("pt-"));
    assert!(spec.enforcement_policy.policy_id.starts_with("ep-"));
    assert!(spec.stress_test.test_id.starts_with("sst-"));
}

#[test]
fn enrichment_builder_empty_build_succeeds() {
    let spec = MechanismBuilder::new("empty").build(test_epoch());
    assert_eq!(spec.name, "empty");
    assert!(spec.payoff_table.entries.is_empty());
    assert!(spec.enforcement_policy.rules.is_empty());
    assert!(spec.property_verifications.is_empty());
    assert!(spec.stress_test.scenarios.is_empty());
    assert_eq!(spec.epoch, test_epoch());
}

#[test]
fn enrichment_builder_epoch_propagates() {
    let e = epoch(99);
    let spec = MechanismBuilder::new("epoch-test").build(e);
    assert_eq!(spec.epoch, e);
    assert_eq!(spec.payoff_table.epoch, e);
    assert_eq!(spec.enforcement_policy.epoch, e);
    assert_eq!(spec.stress_test.epoch, e);
}

// ---------------------------------------------------------------------------
// GovernanceReport — generate_report, compute_hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_from_sound_mechanism() {
    let spec = canonical_governance_mechanism(test_epoch());
    let report = generate_report(&spec);
    assert!(report.is_sound);
    assert!(report.report_id.starts_with("gr-"));
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.spec_id, spec.spec_id);
    assert_eq!(report.verified_properties, 5);
    assert_eq!(report.total_properties, 5);
    assert_eq!(report.honest_dominance_rate_millionths, 1_000_000);
    assert!(report.budget_balanced);
    assert!(report.exploitable_scenarios.is_empty());
    assert!(!report.content_hash.is_empty());
}

#[test]
fn enrichment_report_hash_deterministic() {
    let spec = canonical_governance_mechanism(test_epoch());
    let h1 = generate_report(&spec).content_hash;
    let h2 = generate_report(&spec).content_hash;
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_report_id_derived_from_hash() {
    let spec = canonical_governance_mechanism(test_epoch());
    let report = generate_report(&spec);
    let expected_prefix = format!("gr-{}", &report.content_hash[..32]);
    assert_eq!(report.report_id, expected_prefix);
}

#[test]
fn enrichment_report_with_exploitable_scenarios() {
    let spec = MechanismBuilder::new("exploit-report")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Slash, "bad", -100_000, "r")
        .verify_property(make_verification(IncentiveProperty::TruthfulReporting, VerificationStatus::Verified))
        .scenario(make_scenario("exploit-1", StrategicBehavior::SybilAttack, GovernanceRole::Challenger, 300_000, 0))
        .scenario(make_scenario("exploit-2", StrategicBehavior::CollaborativeAttack, GovernanceRole::Publisher, 200_000, 50_000))
        .build(test_epoch());
    let report = generate_report(&spec);
    assert!(!report.is_sound);
    assert_eq!(report.exploitable_scenarios.len(), 2);
    assert!(report.exploitable_scenarios.contains(&"exploit-1".to_string()));
    assert!(report.exploitable_scenarios.contains(&"exploit-2".to_string()));
}

#[test]
fn enrichment_report_not_sound_falsified() {
    let spec = MechanismBuilder::new("falsified-report")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Slash, "bad", -100_000, "r")
        .verify_property(make_verification(IncentiveProperty::TruthfulReporting, VerificationStatus::Falsified))
        .build(test_epoch());
    let report = generate_report(&spec);
    assert!(!report.is_sound);
    assert_eq!(report.verified_properties, 0);
    assert_eq!(report.total_properties, 1);
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let spec = canonical_governance_mechanism(test_epoch());
    let report = generate_report(&spec);
    let json = serde_json::to_string(&report).unwrap();
    let back: GovernanceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_report_compute_hash_changes_with_spec() {
    let spec1 = canonical_governance_mechanism(epoch(1));
    let spec2 = canonical_governance_mechanism(epoch(2));
    let r1 = generate_report(&spec1);
    let r2 = generate_report(&spec2);
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// canonical_governance_mechanism — structural checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_canonical_mechanism_is_sound() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert!(spec.is_sound());
}

#[test]
fn enrichment_canonical_mechanism_has_five_verified_properties() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert_eq!(spec.verified_property_count(), 5);
    assert_eq!(spec.property_verifications.len(), 5);
}

#[test]
fn enrichment_canonical_mechanism_budget_balanced() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert!(spec.payoff_table.is_budget_balanced());
}

#[test]
fn enrichment_canonical_mechanism_four_scenarios() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert_eq!(spec.stress_test.scenarios.len(), 4);
}

#[test]
fn enrichment_canonical_mechanism_no_exploitable_scenarios() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert!(spec.stress_test.exploitable_scenarios().is_empty());
    assert_eq!(spec.stress_test.honest_dominance_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_canonical_mechanism_eight_payoffs() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert_eq!(spec.payoff_table.entries.len(), 8);
}

#[test]
fn enrichment_canonical_mechanism_four_enforcement_rules() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert_eq!(spec.enforcement_policy.rules.len(), 4);
}

#[test]
fn enrichment_canonical_mechanism_report_entries_by_action() {
    let spec = canonical_governance_mechanism(test_epoch());
    let report_entries = spec.payoff_table.entries_for_action(GovernanceAction::Report);
    assert_eq!(report_entries.len(), 2);
    let challenge_entries = spec.payoff_table.entries_for_action(GovernanceAction::Challenge);
    assert_eq!(challenge_entries.len(), 2);
    let reinstate_entries = spec.payoff_table.entries_for_action(GovernanceAction::Reinstate);
    assert_eq!(reinstate_entries.len(), 2);
    let quarantine_entries = spec.payoff_table.entries_for_action(GovernanceAction::Quarantine);
    assert_eq!(quarantine_entries.len(), 1);
    let slash_entries = spec.payoff_table.entries_for_action(GovernanceAction::Slash);
    assert_eq!(slash_entries.len(), 1);
}

#[test]
fn enrichment_canonical_mechanism_max_total_penalty_positive() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert!(spec.enforcement_policy.max_total_penalty() > 0);
}

#[test]
fn enrichment_canonical_mechanism_publisher_role_payoff() {
    let spec = canonical_governance_mechanism(test_epoch());
    let pub_payoff = spec.payoff_table.total_payoff_for_role(GovernanceRole::Publisher);
    // truthful (50k) + false (-200k) = -150k
    assert_eq!(pub_payoff, -150_000);
}

#[test]
fn enrichment_canonical_mechanism_challenger_role_payoff() {
    let spec = canonical_governance_mechanism(test_epoch());
    let ch_payoff = spec.payoff_table.total_payoff_for_role(GovernanceRole::Challenger);
    // legitimate (100k) + frivolous (-150k) = -50k
    assert_eq!(ch_payoff, -50_000);
}

#[test]
fn enrichment_canonical_mechanism_operator_role_payoff() {
    let spec = canonical_governance_mechanism(test_epoch());
    let op_payoff = spec.payoff_table.total_payoff_for_role(GovernanceRole::Operator);
    // immediate (30k) + delayed (-80k) = -50k
    assert_eq!(op_payoff, -50_000);
}

#[test]
fn enrichment_canonical_mechanism_control_plane_payoff() {
    let spec = canonical_governance_mechanism(test_epoch());
    let cp_payoff = spec.payoff_table.total_payoff_for_role(GovernanceRole::ControlPlane);
    // quarantine (0) + slash (-500k) = -500k
    assert_eq!(cp_payoff, -500_000);
}

#[test]
fn enrichment_canonical_mechanism_arbitrator_payoff_zero() {
    let spec = canonical_governance_mechanism(test_epoch());
    let arb_payoff = spec.payoff_table.total_payoff_for_role(GovernanceRole::Arbitrator);
    assert_eq!(arb_payoff, 0);
}

#[test]
fn enrichment_canonical_mechanism_deterministic_across_calls() {
    let s1 = canonical_governance_mechanism(test_epoch());
    let s2 = canonical_governance_mechanism(test_epoch());
    assert_eq!(s1, s2);
    assert_eq!(s1.spec_id, s2.spec_id);
}

// ---------------------------------------------------------------------------
// Edge cases and boundary tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_payoff_table_single_zero_entry_budget_balanced() {
    let table = PayoffTable {
        table_id: "zero".into(),
        entries: vec![make_payoff_entry(
            GovernanceRole::ControlPlane,
            GovernanceAction::Quarantine,
            "mandatory",
            0,
        )],
        epoch: test_epoch(),
    };
    assert!(table.is_budget_balanced());
}

#[test]
fn enrichment_payoff_table_all_positive_not_budget_balanced() {
    let table = PayoffTable {
        table_id: "all-pos".into(),
        entries: vec![
            make_payoff_entry(GovernanceRole::Publisher, GovernanceAction::Reward, "a", 50_000),
            make_payoff_entry(GovernanceRole::Challenger, GovernanceAction::Reward, "b", 30_000),
        ],
        epoch: test_epoch(),
    };
    assert!(!table.is_budget_balanced());
}

#[test]
fn enrichment_stress_test_single_exploit_scenario() {
    let sst = StrategicStressTest {
        test_id: "single-exploit".into(),
        scenarios: vec![make_scenario(
            "s1",
            StrategicBehavior::CollaborativeAttack,
            GovernanceRole::Publisher,
            200_000,
            50_000,
        )],
        epoch: test_epoch(),
    };
    assert_eq!(sst.honest_dominance_rate_millionths(), 0);
    assert_eq!(sst.exploitable_scenarios().len(), 1);
}

#[test]
fn enrichment_enforcement_policy_max_penalty_includes_zero_penalty_rules() {
    let policy = EnforcementPolicy {
        policy_id: "p".into(),
        rules: vec![
            make_enforcement_rule("r1", GovernanceAction::Report, GovernanceRole::Publisher, GovernanceAction::Quarantine, 0, 50_000, 0),
            make_enforcement_rule("r2", GovernanceAction::Report, GovernanceRole::Publisher, GovernanceAction::Slash, 200_000, 0, 5),
        ],
        challenge_window_epochs: 10,
        publisher_bond_millionths: 100_000,
        epoch: test_epoch(),
    };
    assert_eq!(policy.max_total_penalty(), 200_000);
}

#[test]
fn enrichment_mechanism_spec_name_propagates() {
    let spec = MechanismBuilder::new("my-mechanism-name").build(test_epoch());
    assert_eq!(spec.name, "my-mechanism-name");
}

#[test]
fn enrichment_governance_report_compute_hash_not_empty() {
    let spec = canonical_governance_mechanism(test_epoch());
    let report = generate_report(&spec);
    assert!(!report.compute_hash().is_empty());
    // Hash should be a valid hex string
    assert!(report.compute_hash().chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_governance_report_budget_balanced_propagated() {
    let spec = MechanismBuilder::new("unbalanced-report")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Reward, "good", 500_000, "r")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Slash, "bad", -100_000, "r")
        .build(test_epoch());
    let report = generate_report(&spec);
    assert!(!report.budget_balanced);
}

#[test]
fn enrichment_governance_report_honest_dominance_propagated() {
    let spec = MechanismBuilder::new("partial-honest")
        .payoff(GovernanceRole::Publisher, GovernanceAction::Slash, "bad", -100_000, "r")
        .scenario(make_scenario("s1", StrategicBehavior::FalseReport, GovernanceRole::Publisher, -100_000, 50_000))
        .scenario(make_scenario("s2", StrategicBehavior::CollaborativeAttack, GovernanceRole::Publisher, 200_000, 50_000))
        .build(test_epoch());
    let report = generate_report(&spec);
    assert_eq!(report.honest_dominance_rate_millionths, 500_000);
}
