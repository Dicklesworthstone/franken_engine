#![forbid(unsafe_code)]
//! Integration tests for the `incentive_governance_mechanism` module.
//!
//! Exercises GovernanceRole, GovernanceAction, IncentiveProperty, PayoffTable,
//! StrategicBehavior, StrategicScenario, StrategicStressTest, VerificationStatus,
//! PropertyVerification, EnforcementRule, EnforcementPolicy, MechanismSpec,
//! MechanismBuilder, GovernanceReport, canonical_governance_mechanism, and
//! generate_report.

use frankenengine_engine::incentive_governance_mechanism::{
    DEFAULT_CHALLENGE_WINDOW_EPOCHS, DEFAULT_PUBLISHER_BOND, EnforcementPolicy, EnforcementRule,
    GovernanceAction, GovernanceReport, GovernanceRole, IncentiveProperty, MechanismBuilder,
    MechanismSpec, PayoffEntry, PayoffTable, PropertyVerification, SCHEMA_VERSION,
    StrategicBehavior, StrategicScenario, StrategicStressTest, VerificationStatus,
    canonical_governance_mechanism, generate_report,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(10)
}

fn make_truthful_scenario() -> StrategicScenario {
    StrategicScenario {
        scenario_id: "ss-truthful".into(),
        name: "Truthful Reporting".into(),
        behavior: StrategicBehavior::TruthfulReport,
        role: GovernanceRole::Publisher,
        description: "publisher truthfully reports".into(),
        expected_payoff_millionths: -100_000,
        honest_alternative_payoff_millionths: 50_000,
    }
}

fn make_false_scenario() -> StrategicScenario {
    StrategicScenario {
        scenario_id: "ss-false".into(),
        name: "False Reporting".into(),
        behavior: StrategicBehavior::FalseReport,
        role: GovernanceRole::Publisher,
        description: "publisher files false report".into(),
        expected_payoff_millionths: -200_000,
        honest_alternative_payoff_millionths: 50_000,
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_version_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("incentive-governance"));
}

#[test]
fn default_publisher_bond_positive() {
    const { assert!(DEFAULT_PUBLISHER_BOND > 0) };
}

#[test]
fn default_challenge_window_positive() {
    const { assert!(DEFAULT_CHALLENGE_WINDOW_EPOCHS > 0) };
}

// ===========================================================================
// 2. GovernanceRole
// ===========================================================================

#[test]
fn governance_role_all_has_five() {
    assert_eq!(GovernanceRole::ALL.len(), 5);
}

#[test]
fn governance_role_display() {
    assert_eq!(GovernanceRole::Publisher.to_string(), "publisher");
    assert_eq!(GovernanceRole::Operator.to_string(), "operator");
    assert_eq!(GovernanceRole::Challenger.to_string(), "challenger");
    assert_eq!(GovernanceRole::Arbitrator.to_string(), "arbitrator");
    assert_eq!(GovernanceRole::ControlPlane.to_string(), "control_plane");
}

#[test]
fn governance_role_serde() {
    for role in &GovernanceRole::ALL {
        let json = serde_json::to_string(role).unwrap();
        let back: GovernanceRole = serde_json::from_str(&json).unwrap();
        assert_eq!(*role, back);
    }
}

// ===========================================================================
// 3. GovernanceAction
// ===========================================================================

#[test]
fn governance_action_all_has_eight() {
    assert_eq!(GovernanceAction::ALL.len(), 8);
}

#[test]
fn governance_action_display() {
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
fn governance_action_serde() {
    for action in &GovernanceAction::ALL {
        let json = serde_json::to_string(action).unwrap();
        let back: GovernanceAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, back);
    }
}

// ===========================================================================
// 4. IncentiveProperty
// ===========================================================================

#[test]
fn incentive_property_all_has_five() {
    assert_eq!(IncentiveProperty::ALL.len(), 5);
}

#[test]
fn incentive_property_display() {
    assert_eq!(
        IncentiveProperty::TruthfulReporting.to_string(),
        "truthful_reporting"
    );
    assert_eq!(
        IncentiveProperty::BudgetBalance.to_string(),
        "budget_balance"
    );
}

#[test]
fn incentive_property_serde() {
    for prop in &IncentiveProperty::ALL {
        let json = serde_json::to_string(prop).unwrap();
        let back: IncentiveProperty = serde_json::from_str(&json).unwrap();
        assert_eq!(*prop, back);
    }
}

// ===========================================================================
// 5. PayoffTable
// ===========================================================================

#[test]
fn payoff_table_total_for_role() {
    let table = PayoffTable {
        table_id: "test".into(),
        entries: vec![
            PayoffEntry {
                role: GovernanceRole::Publisher,
                action: GovernanceAction::Report,
                condition: "truthful".into(),
                payoff_millionths: 50_000,
                rationale: "reward".into(),
            },
            PayoffEntry {
                role: GovernanceRole::Publisher,
                action: GovernanceAction::Report,
                condition: "false".into(),
                payoff_millionths: -200_000,
                rationale: "penalty".into(),
            },
            PayoffEntry {
                role: GovernanceRole::Challenger,
                action: GovernanceAction::Challenge,
                condition: "legit".into(),
                payoff_millionths: 100_000,
                rationale: "reward".into(),
            },
        ],
        epoch: test_epoch(),
    };

    assert_eq!(
        table.total_payoff_for_role(GovernanceRole::Publisher),
        -150_000
    );
    assert_eq!(
        table.total_payoff_for_role(GovernanceRole::Challenger),
        100_000
    );
    assert_eq!(table.total_payoff_for_role(GovernanceRole::Operator), 0);
}

#[test]
fn payoff_table_budget_balanced() {
    let table = PayoffTable {
        table_id: "test".into(),
        entries: vec![
            PayoffEntry {
                role: GovernanceRole::Publisher,
                action: GovernanceAction::Report,
                condition: "truthful".into(),
                payoff_millionths: 50_000,
                rationale: "reward".into(),
            },
            PayoffEntry {
                role: GovernanceRole::Publisher,
                action: GovernanceAction::Report,
                condition: "false".into(),
                payoff_millionths: -200_000,
                rationale: "penalty".into(),
            },
        ],
        epoch: test_epoch(),
    };
    // rewards (50k) <= penalties (200k)
    assert!(table.is_budget_balanced());
}

#[test]
fn payoff_table_not_budget_balanced() {
    let table = PayoffTable {
        table_id: "test".into(),
        entries: vec![
            PayoffEntry {
                role: GovernanceRole::Publisher,
                action: GovernanceAction::Reward,
                condition: "big-reward".into(),
                payoff_millionths: 500_000,
                rationale: "reward".into(),
            },
            PayoffEntry {
                role: GovernanceRole::Publisher,
                action: GovernanceAction::Slash,
                condition: "small-penalty".into(),
                payoff_millionths: -100_000,
                rationale: "penalty".into(),
            },
        ],
        epoch: test_epoch(),
    };
    assert!(!table.is_budget_balanced());
}

#[test]
fn payoff_table_compute_id_deterministic() {
    let table = PayoffTable {
        table_id: "t1".into(),
        entries: vec![PayoffEntry {
            role: GovernanceRole::Publisher,
            action: GovernanceAction::Report,
            condition: "test".into(),
            payoff_millionths: 100_000,
            rationale: "r".into(),
        }],
        epoch: test_epoch(),
    };
    let id1 = table.compute_id();
    let id2 = table.compute_id();
    assert_eq!(id1, id2);
    assert!(id1.starts_with("pt-"));
}

#[test]
fn payoff_table_entries_for_action() {
    let table = PayoffTable {
        table_id: "t1".into(),
        entries: vec![
            PayoffEntry {
                role: GovernanceRole::Publisher,
                action: GovernanceAction::Report,
                condition: "c1".into(),
                payoff_millionths: 50_000,
                rationale: "r".into(),
            },
            PayoffEntry {
                role: GovernanceRole::Challenger,
                action: GovernanceAction::Challenge,
                condition: "c2".into(),
                payoff_millionths: 100_000,
                rationale: "r".into(),
            },
        ],
        epoch: test_epoch(),
    };
    assert_eq!(table.entries_for_action(GovernanceAction::Report).len(), 1);
    assert_eq!(table.entries_for_action(GovernanceAction::Slash).len(), 0);
}

#[test]
fn payoff_table_serde() {
    let table = PayoffTable {
        table_id: "t1".into(),
        entries: vec![PayoffEntry {
            role: GovernanceRole::Publisher,
            action: GovernanceAction::Report,
            condition: "c".into(),
            payoff_millionths: 50_000,
            rationale: "r".into(),
        }],
        epoch: test_epoch(),
    };
    let json = serde_json::to_string(&table).unwrap();
    let back: PayoffTable = serde_json::from_str(&json).unwrap();
    assert_eq!(back, table);
}

// ===========================================================================
// 6. StrategicBehavior
// ===========================================================================

#[test]
fn strategic_behavior_serde() {
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
    for b in &behaviors {
        let json = serde_json::to_string(b).unwrap();
        let back: StrategicBehavior = serde_json::from_str(&json).unwrap();
        assert_eq!(*b, back);
    }
}

#[test]
fn strategic_behavior_display() {
    assert_eq!(
        StrategicBehavior::TruthfulReport.to_string(),
        "truthful_report"
    );
    assert_eq!(StrategicBehavior::SybilAttack.to_string(), "sybil_attack");
}

// ===========================================================================
// 7. StrategicScenario
// ===========================================================================

#[test]
fn strategic_scenario_honest_dominates() {
    let s = make_false_scenario();
    // honest (50k) >= dishonest (-200k), so honest dominates
    assert!(s.honest_dominates());
}

#[test]
fn strategic_scenario_honest_does_not_dominate() {
    let s = StrategicScenario {
        scenario_id: "ss-exploit".into(),
        name: "Exploit".into(),
        behavior: StrategicBehavior::CollaborativeAttack,
        role: GovernanceRole::Challenger,
        description: "exploit".into(),
        expected_payoff_millionths: 500_000,
        honest_alternative_payoff_millionths: 100_000,
    };
    assert!(!s.honest_dominates());
}

#[test]
fn strategic_scenario_serde() {
    let s = make_truthful_scenario();
    let json = serde_json::to_string(&s).unwrap();
    let back: StrategicScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

// ===========================================================================
// 8. StrategicStressTest
// ===========================================================================

#[test]
fn stress_test_honest_dominance_rate_all_honest() {
    let test = StrategicStressTest {
        test_id: "sst-1".into(),
        scenarios: vec![make_false_scenario(), make_truthful_scenario()],
        epoch: test_epoch(),
    };
    assert_eq!(test.honest_dominance_rate_millionths(), 1_000_000);
}

#[test]
fn stress_test_exploitable_scenarios_none() {
    let test = StrategicStressTest {
        test_id: "sst-1".into(),
        scenarios: vec![make_false_scenario()],
        epoch: test_epoch(),
    };
    assert!(test.exploitable_scenarios().is_empty());
}

#[test]
fn stress_test_exploitable_scenarios_one() {
    let exploit = StrategicScenario {
        scenario_id: "ss-exploit".into(),
        name: "Exploit".into(),
        behavior: StrategicBehavior::CollaborativeAttack,
        role: GovernanceRole::Challenger,
        description: "exploit".into(),
        expected_payoff_millionths: 500_000,
        honest_alternative_payoff_millionths: 100_000,
    };
    let test = StrategicStressTest {
        test_id: "sst-1".into(),
        scenarios: vec![make_false_scenario(), exploit],
        epoch: test_epoch(),
    };
    assert_eq!(test.exploitable_scenarios().len(), 1);
    assert_eq!(test.honest_dominance_rate_millionths(), 500_000);
}

#[test]
fn stress_test_empty_scenarios() {
    let test = StrategicStressTest {
        test_id: "sst-empty".into(),
        scenarios: vec![],
        epoch: test_epoch(),
    };
    assert_eq!(test.honest_dominance_rate_millionths(), 1_000_000);
    assert!(test.exploitable_scenarios().is_empty());
}

#[test]
fn stress_test_compute_id_deterministic() {
    let test = StrategicStressTest {
        test_id: "sst-1".into(),
        scenarios: vec![make_false_scenario()],
        epoch: test_epoch(),
    };
    let id1 = test.compute_id();
    let id2 = test.compute_id();
    assert_eq!(id1, id2);
    assert!(id1.starts_with("sst-"));
}

// ===========================================================================
// 9. VerificationStatus
// ===========================================================================

#[test]
fn verification_status_serde() {
    for s in [
        VerificationStatus::Verified,
        VerificationStatus::Falsified,
        VerificationStatus::Inconclusive,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: VerificationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn verification_status_display() {
    assert_eq!(VerificationStatus::Verified.to_string(), "verified");
    assert_eq!(VerificationStatus::Falsified.to_string(), "falsified");
    assert_eq!(VerificationStatus::Inconclusive.to_string(), "inconclusive");
}

// ===========================================================================
// 10. EnforcementPolicy
// ===========================================================================

#[test]
fn enforcement_policy_compute_id_deterministic() {
    let policy = EnforcementPolicy {
        policy_id: "ep-1".into(),
        rules: vec![EnforcementRule {
            rule_id: "er-1".into(),
            trigger_action: GovernanceAction::Report,
            trigger_role: GovernanceRole::Publisher,
            condition: "test".into(),
            enforcement_action: GovernanceAction::Quarantine,
            penalty_millionths: 0,
            reward_millionths: 50_000,
            cooldown_epochs: 0,
        }],
        challenge_window_epochs: 10,
        publisher_bond_millionths: 100_000,
        epoch: test_epoch(),
    };
    let id1 = policy.compute_id();
    let id2 = policy.compute_id();
    assert_eq!(id1, id2);
    assert!(id1.starts_with("ep-"));
}

#[test]
fn enforcement_policy_rules_for_trigger() {
    let policy = EnforcementPolicy {
        policy_id: "ep-1".into(),
        rules: vec![
            EnforcementRule {
                rule_id: "er-report".into(),
                trigger_action: GovernanceAction::Report,
                trigger_role: GovernanceRole::Publisher,
                condition: "test".into(),
                enforcement_action: GovernanceAction::Quarantine,
                penalty_millionths: 0,
                reward_millionths: 50_000,
                cooldown_epochs: 0,
            },
            EnforcementRule {
                rule_id: "er-challenge".into(),
                trigger_action: GovernanceAction::Challenge,
                trigger_role: GovernanceRole::Challenger,
                condition: "test".into(),
                enforcement_action: GovernanceAction::Reward,
                penalty_millionths: 0,
                reward_millionths: 100_000,
                cooldown_epochs: 0,
            },
        ],
        challenge_window_epochs: 10,
        publisher_bond_millionths: 100_000,
        epoch: test_epoch(),
    };

    assert_eq!(policy.rules_for_trigger(GovernanceAction::Report).len(), 1);
    assert_eq!(
        policy.rules_for_trigger(GovernanceAction::Challenge).len(),
        1
    );
    assert_eq!(policy.rules_for_trigger(GovernanceAction::Slash).len(), 0);
}

#[test]
fn enforcement_policy_max_total_penalty() {
    let policy = EnforcementPolicy {
        policy_id: "ep-1".into(),
        rules: vec![
            EnforcementRule {
                rule_id: "er-1".into(),
                trigger_action: GovernanceAction::Report,
                trigger_role: GovernanceRole::Publisher,
                condition: "c".into(),
                enforcement_action: GovernanceAction::Slash,
                penalty_millionths: 200_000,
                reward_millionths: 0,
                cooldown_epochs: 0,
            },
            EnforcementRule {
                rule_id: "er-2".into(),
                trigger_action: GovernanceAction::Challenge,
                trigger_role: GovernanceRole::Challenger,
                condition: "c".into(),
                enforcement_action: GovernanceAction::Slash,
                penalty_millionths: 150_000,
                reward_millionths: 0,
                cooldown_epochs: 0,
            },
        ],
        challenge_window_epochs: 10,
        publisher_bond_millionths: 100_000,
        epoch: test_epoch(),
    };
    assert_eq!(policy.max_total_penalty(), 350_000);
}

#[test]
fn enforcement_policy_serde() {
    let policy = EnforcementPolicy {
        policy_id: "ep-1".into(),
        rules: vec![EnforcementRule {
            rule_id: "er-1".into(),
            trigger_action: GovernanceAction::Report,
            trigger_role: GovernanceRole::Publisher,
            condition: "c".into(),
            enforcement_action: GovernanceAction::Quarantine,
            penalty_millionths: 0,
            reward_millionths: 50_000,
            cooldown_epochs: 0,
        }],
        challenge_window_epochs: 10,
        publisher_bond_millionths: 100_000,
        epoch: test_epoch(),
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: EnforcementPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, policy);
}

// ===========================================================================
// 11. MechanismBuilder + MechanismSpec
// ===========================================================================

#[test]
fn mechanism_builder_minimal() {
    let spec = MechanismBuilder::new("Test Mechanism")
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "truthful",
            50_000,
            "reward",
        )
        .build(test_epoch());

    assert_eq!(spec.name, "Test Mechanism");
    assert!(!spec.spec_id.is_empty());
    assert!(spec.spec_id.starts_with("ms-"));
    assert_eq!(spec.epoch, test_epoch());
}

#[test]
fn mechanism_builder_with_enforcement() {
    let spec = MechanismBuilder::new("Test")
        .enforcement_rule(EnforcementRule {
            rule_id: "er-1".into(),
            trigger_action: GovernanceAction::Report,
            trigger_role: GovernanceRole::Publisher,
            condition: "test".into(),
            enforcement_action: GovernanceAction::Quarantine,
            penalty_millionths: 0,
            reward_millionths: 50_000,
            cooldown_epochs: 0,
        })
        .build(test_epoch());

    assert_eq!(spec.enforcement_policy.rules.len(), 1);
}

#[test]
fn mechanism_builder_with_properties_and_scenarios() {
    let spec = MechanismBuilder::new("Full")
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "truthful",
            50_000,
            "reward",
        )
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "false",
            -200_000,
            "penalty",
        )
        .verify_property(PropertyVerification {
            property: IncentiveProperty::TruthfulReporting,
            status: VerificationStatus::Verified,
            assumptions: vec!["rational actors".into()],
            evidence: "truthful > false".into(),
            counterexample: None,
        })
        .verify_property(PropertyVerification {
            property: IncentiveProperty::BudgetBalance,
            status: VerificationStatus::Verified,
            assumptions: vec!["closed system".into()],
            evidence: "rewards < penalties".into(),
            counterexample: None,
        })
        .scenario(make_false_scenario())
        .build(test_epoch());

    assert_eq!(spec.verified_property_count(), 2);
    assert_eq!(spec.property_verifications.len(), 2);
}

#[test]
fn mechanism_builder_custom_bond_and_window() {
    let spec = MechanismBuilder::new("Custom")
        .publisher_bond(500_000)
        .challenge_window(20)
        .build(test_epoch());

    assert_eq!(spec.enforcement_policy.publisher_bond_millionths, 500_000);
    assert_eq!(spec.enforcement_policy.challenge_window_epochs, 20);
}

#[test]
fn mechanism_spec_is_sound_all_verified() {
    let spec = MechanismBuilder::new("Sound")
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "truthful",
            50_000,
            "reward",
        )
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "false",
            -200_000,
            "penalty",
        )
        .verify_property(PropertyVerification {
            property: IncentiveProperty::TruthfulReporting,
            status: VerificationStatus::Verified,
            assumptions: vec![],
            evidence: "e".into(),
            counterexample: None,
        })
        .scenario(make_false_scenario())
        .build(test_epoch());

    assert!(spec.is_sound());
}

#[test]
fn mechanism_spec_not_sound_if_falsified() {
    let spec = MechanismBuilder::new("Unsound")
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "truthful",
            50_000,
            "reward",
        )
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "false",
            -200_000,
            "penalty",
        )
        .verify_property(PropertyVerification {
            property: IncentiveProperty::TruthfulReporting,
            status: VerificationStatus::Falsified,
            assumptions: vec![],
            evidence: "e".into(),
            counterexample: Some("counterexample".into()),
        })
        .scenario(make_false_scenario())
        .build(test_epoch());

    assert!(!spec.is_sound());
}

#[test]
fn mechanism_spec_compute_id_deterministic() {
    let spec = MechanismBuilder::new("Test")
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "c",
            50_000,
            "r",
        )
        .build(test_epoch());

    let id1 = spec.compute_id();
    let id2 = spec.compute_id();
    assert_eq!(id1, id2);
}

#[test]
fn mechanism_spec_serde() {
    let spec = MechanismBuilder::new("Serde Test")
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "c",
            50_000,
            "r",
        )
        .scenario(make_false_scenario())
        .verify_property(PropertyVerification {
            property: IncentiveProperty::BudgetBalance,
            status: VerificationStatus::Verified,
            assumptions: vec![],
            evidence: "e".into(),
            counterexample: None,
        })
        .build(test_epoch());

    let json = serde_json::to_string(&spec).unwrap();
    let back: MechanismSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);
}

// ===========================================================================
// 12. canonical_governance_mechanism
// ===========================================================================

#[test]
fn canonical_mechanism_is_sound() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert!(
        spec.is_sound(),
        "canonical mechanism should be sound: {} verified out of {} properties",
        spec.verified_property_count(),
        spec.property_verifications.len()
    );
}

#[test]
fn canonical_mechanism_has_all_five_properties() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert_eq!(spec.property_verifications.len(), 5);
    assert_eq!(spec.verified_property_count(), 5);
}

#[test]
fn canonical_mechanism_has_scenarios() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert!(!spec.stress_test.scenarios.is_empty());
    assert!(spec.stress_test.exploitable_scenarios().is_empty());
}

#[test]
fn canonical_mechanism_has_enforcement_rules() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert!(!spec.enforcement_policy.rules.is_empty());
}

#[test]
fn canonical_mechanism_budget_balanced() {
    let spec = canonical_governance_mechanism(test_epoch());
    assert!(spec.payoff_table.is_budget_balanced());
}

#[test]
fn canonical_mechanism_serde() {
    let spec = canonical_governance_mechanism(test_epoch());
    let json = serde_json::to_string(&spec).unwrap();
    let back: MechanismSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);
}

// ===========================================================================
// 13. GovernanceReport + generate_report
// ===========================================================================

#[test]
fn generate_report_from_canonical() {
    let spec = canonical_governance_mechanism(test_epoch());
    let report = generate_report(&spec);

    assert!(report.is_sound);
    assert_eq!(report.verified_properties, 5);
    assert_eq!(report.total_properties, 5);
    assert!(report.budget_balanced);
    assert!(report.exploitable_scenarios.is_empty());
    assert!(!report.report_id.is_empty());
    assert!(!report.content_hash.is_empty());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn generate_report_deterministic_hash() {
    let spec = canonical_governance_mechanism(test_epoch());
    let r1 = generate_report(&spec);
    let r2 = generate_report(&spec);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn generate_report_unsound() {
    let spec = MechanismBuilder::new("Unsound")
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "c",
            50_000,
            "r",
        )
        .verify_property(PropertyVerification {
            property: IncentiveProperty::TruthfulReporting,
            status: VerificationStatus::Falsified,
            assumptions: vec![],
            evidence: "e".into(),
            counterexample: Some("c".into()),
        })
        .build(test_epoch());

    let report = generate_report(&spec);
    assert!(!report.is_sound);
    assert_eq!(report.verified_properties, 0);
}

#[test]
fn governance_report_serde() {
    let spec = canonical_governance_mechanism(test_epoch());
    let report = generate_report(&spec);
    let json = serde_json::to_string(&report).unwrap();
    let back: GovernanceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

// ===========================================================================
// 14. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_build_verify_report() {
    // 1. Build mechanism
    let spec = MechanismBuilder::new("Lifecycle Test")
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "truthful_vulnerability_report",
            50_000,
            "reward for truthful self-report",
        )
        .payoff(
            GovernanceRole::Publisher,
            GovernanceAction::Report,
            "false_report",
            -200_000,
            "penalty for false report",
        )
        .payoff(
            GovernanceRole::Challenger,
            GovernanceAction::Challenge,
            "legitimate_challenge",
            100_000,
            "reward for finding real issue",
        )
        .payoff(
            GovernanceRole::Challenger,
            GovernanceAction::Challenge,
            "frivolous_challenge",
            -150_000,
            "penalty for wasting resources",
        )
        .enforcement_rule(EnforcementRule {
            rule_id: "er-quarantine".into(),
            trigger_action: GovernanceAction::Report,
            trigger_role: GovernanceRole::Publisher,
            condition: "vulnerability_confirmed".into(),
            enforcement_action: GovernanceAction::Quarantine,
            penalty_millionths: 0,
            reward_millionths: 50_000,
            cooldown_epochs: 0,
        })
        .verify_property(PropertyVerification {
            property: IncentiveProperty::TruthfulReporting,
            status: VerificationStatus::Verified,
            assumptions: vec!["rational actors".into()],
            evidence: "truthful (50k) > false (-200k)".into(),
            counterexample: None,
        })
        .verify_property(PropertyVerification {
            property: IncentiveProperty::FalseChallengeUnprofitable,
            status: VerificationStatus::Verified,
            assumptions: vec!["correct arbitration".into()],
            evidence: "frivolous (-150k) < legit (+100k)".into(),
            counterexample: None,
        })
        .verify_property(PropertyVerification {
            property: IncentiveProperty::BudgetBalance,
            status: VerificationStatus::Verified,
            assumptions: vec!["closed system".into()],
            evidence: "rewards (200k) < penalties (350k)".into(),
            counterexample: None,
        })
        .scenario(StrategicScenario {
            scenario_id: "ss-false-report".into(),
            name: "False Report".into(),
            behavior: StrategicBehavior::FalseReport,
            role: GovernanceRole::Publisher,
            description: "files false report".into(),
            expected_payoff_millionths: -200_000,
            honest_alternative_payoff_millionths: 50_000,
        })
        .scenario(StrategicScenario {
            scenario_id: "ss-frivolous-challenge".into(),
            name: "Frivolous Challenge".into(),
            behavior: StrategicBehavior::FrivolousChallenge,
            role: GovernanceRole::Challenger,
            description: "files frivolous challenge".into(),
            expected_payoff_millionths: -150_000,
            honest_alternative_payoff_millionths: 100_000,
        })
        .publisher_bond(100_000)
        .challenge_window(10)
        .build(test_epoch());

    // 2. Verify soundness
    assert!(spec.is_sound());
    assert_eq!(spec.verified_property_count(), 3);
    assert!(spec.payoff_table.is_budget_balanced());
    assert!(spec.stress_test.exploitable_scenarios().is_empty());

    // 3. Generate report
    let report = generate_report(&spec);
    assert!(report.is_sound);
    assert!(report.budget_balanced);
    assert!(report.exploitable_scenarios.is_empty());

    // 4. Serde round-trip
    let json = serde_json::to_string(&spec).unwrap();
    let back: MechanismSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);

    let report_json = serde_json::to_string(&report).unwrap();
    let report_back: GovernanceReport = serde_json::from_str(&report_json).unwrap();
    assert_eq!(report_back, report);
}
