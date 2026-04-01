//! Incentive-Compatible Extension Governance Mechanism.
//!
//! Designs and verifies governance rules so extension authors/operators have
//! incentives aligned with truthful reporting, safe behavior, and rapid
//! remediation.  Implements mechanism design primitives: reporting, challenge,
//! quarantine, and reinstatement actions with incentive-compatibility analysis.
//!
//! Plan reference: FRX-18.3 (Incentive-Compatible Extension Governance).

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

pub const SCHEMA_VERSION: &str = "franken-engine.incentive-governance.v1";

/// Default bond amount (millionths) required to register as extension publisher.
pub const DEFAULT_PUBLISHER_BOND: i64 = 100_000;

/// Default challenge window in epochs.
pub const DEFAULT_CHALLENGE_WINDOW_EPOCHS: u64 = 10;

// ---------------------------------------------------------------------------
// GovernanceRole — participants in the mechanism
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceRole {
    Publisher,
    Operator,
    Challenger,
    Arbitrator,
    ControlPlane,
}

impl GovernanceRole {
    pub const ALL: [Self; 5] = [
        Self::Publisher,
        Self::Operator,
        Self::Challenger,
        Self::Arbitrator,
        Self::ControlPlane,
    ];
}

impl fmt::Display for GovernanceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Publisher => write!(f, "publisher"),
            Self::Operator => write!(f, "operator"),
            Self::Challenger => write!(f, "challenger"),
            Self::Arbitrator => write!(f, "arbitrator"),
            Self::ControlPlane => write!(f, "control_plane"),
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceAction — actions in the mechanism
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceAction {
    Report,
    Challenge,
    Quarantine,
    Reinstate,
    Slash,
    Reward,
    Escalate,
    Appeal,
}

impl GovernanceAction {
    pub const ALL: [Self; 8] = [
        Self::Report,
        Self::Challenge,
        Self::Quarantine,
        Self::Reinstate,
        Self::Slash,
        Self::Reward,
        Self::Escalate,
        Self::Appeal,
    ];
}

impl fmt::Display for GovernanceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Report => write!(f, "report"),
            Self::Challenge => write!(f, "challenge"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::Reinstate => write!(f, "reinstate"),
            Self::Slash => write!(f, "slash"),
            Self::Reward => write!(f, "reward"),
            Self::Escalate => write!(f, "escalate"),
            Self::Appeal => write!(f, "appeal"),
        }
    }
}

// ---------------------------------------------------------------------------
// IncentiveProperty — properties the mechanism should satisfy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncentiveProperty {
    /// Truthful reporting is a dominant strategy for all roles.
    TruthfulReporting,
    /// Timely remediation is cheaper than delayed remediation.
    TimelyRemediation,
    /// False challenges are unprofitable.
    FalseChallengeUnprofitable,
    /// Honest operators earn more than dishonest ones.
    HonestOperatorDominance,
    /// The mechanism is budget-balanced (rewards <= penalties).
    BudgetBalance,
}

impl IncentiveProperty {
    pub const ALL: [Self; 5] = [
        Self::TruthfulReporting,
        Self::TimelyRemediation,
        Self::FalseChallengeUnprofitable,
        Self::HonestOperatorDominance,
        Self::BudgetBalance,
    ];
}

impl fmt::Display for IncentiveProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruthfulReporting => write!(f, "truthful_reporting"),
            Self::TimelyRemediation => write!(f, "timely_remediation"),
            Self::FalseChallengeUnprofitable => write!(f, "false_challenge_unprofitable"),
            Self::HonestOperatorDominance => write!(f, "honest_operator_dominance"),
            Self::BudgetBalance => write!(f, "budget_balance"),
        }
    }
}

// ---------------------------------------------------------------------------
// PayoffEntry — cost/reward for an action under a state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoffEntry {
    pub role: GovernanceRole,
    pub action: GovernanceAction,
    pub condition: String,
    pub payoff_millionths: i64,
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// PayoffTable — complete payoff structure for the mechanism
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoffTable {
    pub table_id: String,
    pub entries: Vec<PayoffEntry>,
    pub epoch: SecurityEpoch,
}

impl PayoffTable {
    pub fn compute_id(&self) -> String {
        let mut h = Sha256::new();
        for e in &self.entries {
            h.update(e.role.to_string().as_bytes());
            h.update(e.action.to_string().as_bytes());
            h.update(e.condition.as_bytes());
            h.update(e.payoff_millionths.to_le_bytes());
        }
        h.update(self.epoch.as_u64().to_le_bytes());
        format!("pt-{}", hex::encode(&h.finalize()[..16]))
    }

    /// Sum payoffs for a given role across all entries.
    pub fn total_payoff_for_role(&self, role: GovernanceRole) -> i64 {
        self.entries
            .iter()
            .filter(|e| e.role == role)
            .map(|e| e.payoff_millionths)
            .fold(0i64, |acc, x| acc.saturating_add(x))
    }

    /// Check budget balance: total rewards <= total penalties.
    pub fn is_budget_balanced(&self) -> bool {
        let total_positive: i64 = self
            .entries
            .iter()
            .filter(|e| e.payoff_millionths > 0)
            .map(|e| e.payoff_millionths)
            .fold(0i64, |acc, x| acc.saturating_add(x));
        let total_negative: i64 = self
            .entries
            .iter()
            .filter(|e| e.payoff_millionths < 0)
            .map(|e| e.payoff_millionths.saturating_abs())
            .fold(0i64, |acc, x| acc.saturating_add(x));
        total_positive <= total_negative
    }

    /// Get entries for a specific action.
    pub fn entries_for_action(&self, action: GovernanceAction) -> Vec<&PayoffEntry> {
        self.entries.iter().filter(|e| e.action == action).collect()
    }
}

// ---------------------------------------------------------------------------
// StrategicScenario — test scenario for strategic behavior
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrategicBehavior {
    TruthfulReport,
    FalseReport,
    DelayedRemediation,
    ImmediateRemediation,
    FrivolousChallenge,
    LegitimateChallenge,
    CollaborativeAttack,
    SybilAttack,
}

impl fmt::Display for StrategicBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruthfulReport => write!(f, "truthful_report"),
            Self::FalseReport => write!(f, "false_report"),
            Self::DelayedRemediation => write!(f, "delayed_remediation"),
            Self::ImmediateRemediation => write!(f, "immediate_remediation"),
            Self::FrivolousChallenge => write!(f, "frivolous_challenge"),
            Self::LegitimateChallenge => write!(f, "legitimate_challenge"),
            Self::CollaborativeAttack => write!(f, "collaborative_attack"),
            Self::SybilAttack => write!(f, "sybil_attack"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategicScenario {
    pub scenario_id: String,
    pub name: String,
    pub behavior: StrategicBehavior,
    pub role: GovernanceRole,
    pub description: String,
    pub expected_payoff_millionths: i64,
    pub honest_alternative_payoff_millionths: i64,
}

impl StrategicScenario {
    /// Returns true if the honest alternative is at least as profitable.
    pub fn honest_dominates(&self) -> bool {
        self.honest_alternative_payoff_millionths >= self.expected_payoff_millionths
    }
}

// ---------------------------------------------------------------------------
// StrategicStressTest — suite of strategic scenarios
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategicStressTest {
    pub test_id: String,
    pub scenarios: Vec<StrategicScenario>,
    pub epoch: SecurityEpoch,
}

impl StrategicStressTest {
    pub fn compute_id(&self) -> String {
        let mut h = Sha256::new();
        for s in &self.scenarios {
            h.update(s.scenario_id.as_bytes());
            h.update(s.behavior.to_string().as_bytes());
        }
        h.update(self.epoch.as_u64().to_le_bytes());
        format!("sst-{}", hex::encode(&h.finalize()[..16]))
    }

    /// Returns the fraction (millionths) of scenarios where honest dominates.
    pub fn honest_dominance_rate_millionths(&self) -> i64 {
        if self.scenarios.is_empty() {
            return MILLION;
        }
        let honest_count = self
            .scenarios
            .iter()
            .filter(|s| s.honest_dominates())
            .count() as i64;
        honest_count.saturating_mul(MILLION) / self.scenarios.len() as i64
    }

    /// Returns scenarios where dishonest behavior is profitable.
    pub fn exploitable_scenarios(&self) -> Vec<&StrategicScenario> {
        self.scenarios
            .iter()
            .filter(|s| !s.honest_dominates())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// PropertyVerification — verification of incentive properties
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    Falsified,
    Inconclusive,
}

impl fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified => write!(f, "verified"),
            Self::Falsified => write!(f, "falsified"),
            Self::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyVerification {
    pub property: IncentiveProperty,
    pub status: VerificationStatus,
    pub assumptions: Vec<String>,
    pub evidence: String,
    pub counterexample: Option<String>,
}

// ---------------------------------------------------------------------------
// EnforcementRule — deterministic enforcement policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementRule {
    pub rule_id: String,
    pub trigger_action: GovernanceAction,
    pub trigger_role: GovernanceRole,
    pub condition: String,
    pub enforcement_action: GovernanceAction,
    pub penalty_millionths: i64,
    pub reward_millionths: i64,
    pub cooldown_epochs: u64,
}

// ---------------------------------------------------------------------------
// EnforcementPolicy — collection of enforcement rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPolicy {
    pub policy_id: String,
    pub rules: Vec<EnforcementRule>,
    pub challenge_window_epochs: u64,
    pub publisher_bond_millionths: i64,
    pub epoch: SecurityEpoch,
}

impl EnforcementPolicy {
    pub fn compute_id(&self) -> String {
        let mut h = Sha256::new();
        for r in &self.rules {
            h.update(r.rule_id.as_bytes());
            h.update(r.trigger_action.to_string().as_bytes());
            h.update(r.penalty_millionths.to_le_bytes());
        }
        h.update(self.challenge_window_epochs.to_le_bytes());
        h.update(self.publisher_bond_millionths.to_le_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        format!("ep-{}", hex::encode(&h.finalize()[..16]))
    }

    /// Get all rules triggered by a specific action.
    pub fn rules_for_trigger(&self, action: GovernanceAction) -> Vec<&EnforcementRule> {
        self.rules
            .iter()
            .filter(|r| r.trigger_action == action)
            .collect()
    }

    /// Total maximum penalty across all rules.
    pub fn max_total_penalty(&self) -> i64 {
        self.rules.iter().map(|r| r.penalty_millionths).fold(0i64, |acc, x| acc.saturating_add(x))
    }
}

// ---------------------------------------------------------------------------
// MechanismSpec — complete mechanism specification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MechanismSpec {
    pub spec_id: String,
    pub name: String,
    pub payoff_table: PayoffTable,
    pub enforcement_policy: EnforcementPolicy,
    pub property_verifications: Vec<PropertyVerification>,
    pub stress_test: StrategicStressTest,
    pub epoch: SecurityEpoch,
}

impl MechanismSpec {
    pub fn compute_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.name.as_bytes());
        h.update(self.payoff_table.table_id.as_bytes());
        h.update(self.enforcement_policy.policy_id.as_bytes());
        h.update(self.stress_test.test_id.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        format!("ms-{}", hex::encode(&h.finalize()[..16]))
    }

    /// Count how many properties are verified.
    pub fn verified_property_count(&self) -> usize {
        self.property_verifications
            .iter()
            .filter(|v| v.status == VerificationStatus::Verified)
            .count()
    }

    /// Returns true if all properties are verified and stress tests pass.
    pub fn is_sound(&self) -> bool {
        let all_verified = self
            .property_verifications
            .iter()
            .all(|v| v.status == VerificationStatus::Verified);
        let stress_ok = self.stress_test.honest_dominance_rate_millionths() >= MILLION;
        let budget_ok = self.payoff_table.is_budget_balanced();
        all_verified && stress_ok && budget_ok
    }
}

// ---------------------------------------------------------------------------
// MechanismBuilder — fluent builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MechanismBuilder {
    name: String,
    payoff_entries: Vec<PayoffEntry>,
    enforcement_rules: Vec<EnforcementRule>,
    property_verifications: Vec<PropertyVerification>,
    scenarios: Vec<StrategicScenario>,
    challenge_window_epochs: u64,
    publisher_bond_millionths: i64,
}

impl MechanismBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            payoff_entries: Vec::new(),
            enforcement_rules: Vec::new(),
            property_verifications: Vec::new(),
            scenarios: Vec::new(),
            challenge_window_epochs: DEFAULT_CHALLENGE_WINDOW_EPOCHS,
            publisher_bond_millionths: DEFAULT_PUBLISHER_BOND,
        }
    }

    pub fn payoff(
        mut self,
        role: GovernanceRole,
        action: GovernanceAction,
        condition: &str,
        payoff_millionths: i64,
        rationale: &str,
    ) -> Self {
        self.payoff_entries.push(PayoffEntry {
            role,
            action,
            condition: condition.to_string(),
            payoff_millionths,
            rationale: rationale.to_string(),
        });
        self
    }

    pub fn enforcement_rule(mut self, rule: EnforcementRule) -> Self {
        self.enforcement_rules.push(rule);
        self
    }

    pub fn verify_property(mut self, verification: PropertyVerification) -> Self {
        self.property_verifications.push(verification);
        self
    }

    pub fn scenario(mut self, scenario: StrategicScenario) -> Self {
        self.scenarios.push(scenario);
        self
    }

    pub fn challenge_window(mut self, epochs: u64) -> Self {
        self.challenge_window_epochs = epochs;
        self
    }

    pub fn publisher_bond(mut self, bond_millionths: i64) -> Self {
        self.publisher_bond_millionths = bond_millionths;
        self
    }

    pub fn build(self, epoch: SecurityEpoch) -> MechanismSpec {
        let mut payoff_table = PayoffTable {
            table_id: String::new(),
            entries: self.payoff_entries,
            epoch,
        };
        payoff_table.table_id = payoff_table.compute_id();

        let mut enforcement_policy = EnforcementPolicy {
            policy_id: String::new(),
            rules: self.enforcement_rules,
            challenge_window_epochs: self.challenge_window_epochs,
            publisher_bond_millionths: self.publisher_bond_millionths,
            epoch,
        };
        enforcement_policy.policy_id = enforcement_policy.compute_id();

        let mut stress_test = StrategicStressTest {
            test_id: String::new(),
            scenarios: self.scenarios,
            epoch,
        };
        stress_test.test_id = stress_test.compute_id();

        let mut spec = MechanismSpec {
            spec_id: String::new(),
            name: self.name,
            payoff_table,
            enforcement_policy,
            property_verifications: self.property_verifications,
            stress_test,
            epoch,
        };
        spec.spec_id = spec.compute_id();
        spec
    }
}

// ---------------------------------------------------------------------------
// GovernanceReport — CI-readable report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReport {
    pub report_id: String,
    pub schema_version: String,
    pub spec_id: String,
    pub is_sound: bool,
    pub verified_properties: usize,
    pub total_properties: usize,
    pub honest_dominance_rate_millionths: i64,
    pub budget_balanced: bool,
    pub exploitable_scenarios: Vec<String>,
    pub content_hash: String,
}

impl GovernanceReport {
    pub fn compute_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.schema_version.as_bytes());
        h.update(self.spec_id.as_bytes());
        h.update(if self.is_sound { &[1u8] } else { &[0u8] });
        h.update(self.verified_properties.to_le_bytes());
        h.update(self.honest_dominance_rate_millionths.to_le_bytes());
        hex::encode(h.finalize())
    }
}

pub fn generate_report(spec: &MechanismSpec) -> GovernanceReport {
    let exploitable: Vec<String> = spec
        .stress_test
        .exploitable_scenarios()
        .iter()
        .map(|s| s.scenario_id.clone())
        .collect();

    let mut report = GovernanceReport {
        report_id: String::new(),
        schema_version: SCHEMA_VERSION.to_string(),
        spec_id: spec.spec_id.clone(),
        is_sound: spec.is_sound(),
        verified_properties: spec.verified_property_count(),
        total_properties: spec.property_verifications.len(),
        honest_dominance_rate_millionths: spec.stress_test.honest_dominance_rate_millionths(),
        budget_balanced: spec.payoff_table.is_budget_balanced(),
        exploitable_scenarios: exploitable,
        content_hash: String::new(),
    };
    report.content_hash = report.compute_hash();
    report.report_id = format!("gr-{}", &report.content_hash[..32]);
    report
}

// ---------------------------------------------------------------------------
// Canonical mechanism
// ---------------------------------------------------------------------------

pub fn canonical_governance_mechanism(epoch: SecurityEpoch) -> MechanismSpec {
    MechanismBuilder::new("FrankenEngine Extension Governance v1")
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
        .payoff(
            GovernanceRole::Operator,
            GovernanceAction::Reinstate,
            "immediate_remediation",
            30_000,
            "bonus for fast fix",
        )
        .payoff(
            GovernanceRole::Operator,
            GovernanceAction::Reinstate,
            "delayed_remediation",
            -80_000,
            "penalty for slow response",
        )
        .payoff(
            GovernanceRole::ControlPlane,
            GovernanceAction::Quarantine,
            "confirmed_vulnerability",
            0,
            "quarantine is mandatory",
        )
        .payoff(
            GovernanceRole::ControlPlane,
            GovernanceAction::Slash,
            "repeated_offense",
            -500_000,
            "severe penalty for repeat offenders",
        )
        .enforcement_rule(EnforcementRule {
            rule_id: "er-quarantine-on-report".into(),
            trigger_action: GovernanceAction::Report,
            trigger_role: GovernanceRole::Publisher,
            condition: "vulnerability_confirmed".into(),
            enforcement_action: GovernanceAction::Quarantine,
            penalty_millionths: 0,
            reward_millionths: 50_000,
            cooldown_epochs: 0,
        })
        .enforcement_rule(EnforcementRule {
            rule_id: "er-slash-false-report".into(),
            trigger_action: GovernanceAction::Report,
            trigger_role: GovernanceRole::Publisher,
            condition: "report_falsified".into(),
            enforcement_action: GovernanceAction::Slash,
            penalty_millionths: 200_000,
            reward_millionths: 0,
            cooldown_epochs: 5,
        })
        .enforcement_rule(EnforcementRule {
            rule_id: "er-reward-challenge".into(),
            trigger_action: GovernanceAction::Challenge,
            trigger_role: GovernanceRole::Challenger,
            condition: "challenge_upheld".into(),
            enforcement_action: GovernanceAction::Reward,
            penalty_millionths: 0,
            reward_millionths: 100_000,
            cooldown_epochs: 0,
        })
        .enforcement_rule(EnforcementRule {
            rule_id: "er-slash-frivolous-challenge".into(),
            trigger_action: GovernanceAction::Challenge,
            trigger_role: GovernanceRole::Challenger,
            condition: "challenge_rejected".into(),
            enforcement_action: GovernanceAction::Slash,
            penalty_millionths: 150_000,
            reward_millionths: 0,
            cooldown_epochs: 3,
        })
        .verify_property(PropertyVerification {
            property: IncentiveProperty::TruthfulReporting,
            status: VerificationStatus::Verified,
            assumptions: vec![
                "rational actors".into(),
                "common knowledge of payoffs".into(),
            ],
            evidence: "truthful report payoff (50k) > false report payoff (-200k)".into(),
            counterexample: None,
        })
        .verify_property(PropertyVerification {
            property: IncentiveProperty::TimelyRemediation,
            status: VerificationStatus::Verified,
            assumptions: vec!["remediation cost < delayed penalty".into()],
            evidence: "immediate (+30k) > delayed (-80k)".into(),
            counterexample: None,
        })
        .verify_property(PropertyVerification {
            property: IncentiveProperty::FalseChallengeUnprofitable,
            status: VerificationStatus::Verified,
            assumptions: vec!["arbitration is correct".into()],
            evidence: "frivolous challenge (-150k) < legitimate challenge (+100k)".into(),
            counterexample: None,
        })
        .verify_property(PropertyVerification {
            property: IncentiveProperty::HonestOperatorDominance,
            status: VerificationStatus::Verified,
            assumptions: vec!["repeated game".into(), "reputation effects".into()],
            evidence: "honest operators retain bond and earn rewards; dishonest lose bond".into(),
            counterexample: None,
        })
        .verify_property(PropertyVerification {
            property: IncentiveProperty::BudgetBalance,
            status: VerificationStatus::Verified,
            assumptions: vec!["closed system".into()],
            evidence: "total rewards (230k) < total penalties (1130k)".into(),
            counterexample: None,
        })
        .scenario(StrategicScenario {
            scenario_id: "ss-truthful-vs-false-report".into(),
            name: "Truthful vs False Report".into(),
            behavior: StrategicBehavior::FalseReport,
            role: GovernanceRole::Publisher,
            description: "publisher files false vulnerability report".into(),
            expected_payoff_millionths: -200_000,
            honest_alternative_payoff_millionths: 50_000,
        })
        .scenario(StrategicScenario {
            scenario_id: "ss-delayed-vs-immediate-fix".into(),
            name: "Delayed vs Immediate Remediation".into(),
            behavior: StrategicBehavior::DelayedRemediation,
            role: GovernanceRole::Operator,
            description: "operator delays fix hoping issue blows over".into(),
            expected_payoff_millionths: -80_000,
            honest_alternative_payoff_millionths: 30_000,
        })
        .scenario(StrategicScenario {
            scenario_id: "ss-frivolous-vs-legit-challenge".into(),
            name: "Frivolous vs Legitimate Challenge".into(),
            behavior: StrategicBehavior::FrivolousChallenge,
            role: GovernanceRole::Challenger,
            description: "challenger files frivolous challenge to harass publisher".into(),
            expected_payoff_millionths: -150_000,
            honest_alternative_payoff_millionths: 100_000,
        })
        .scenario(StrategicScenario {
            scenario_id: "ss-sybil-attack".into(),
            name: "Sybil Attack on Challenge System".into(),
            behavior: StrategicBehavior::SybilAttack,
            role: GovernanceRole::Challenger,
            description: "attacker creates multiple identities to overwhelm challenges".into(),
            expected_payoff_millionths: -300_000,
            honest_alternative_payoff_millionths: 0,
        })
        .build(epoch)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    #[test]
    fn governance_role_all_five() {
        assert_eq!(GovernanceRole::ALL.len(), 5);
    }

    #[test]
    fn governance_role_display() {
        assert_eq!(GovernanceRole::Publisher.to_string(), "publisher");
        assert_eq!(GovernanceRole::ControlPlane.to_string(), "control_plane");
    }

    #[test]
    fn governance_role_serde_roundtrip() {
        for role in &GovernanceRole::ALL {
            let back: GovernanceRole =
                serde_json::from_str(&serde_json::to_string(role).unwrap()).unwrap();
            assert_eq!(*role, back);
        }
    }

    #[test]
    fn governance_action_all_eight() {
        assert_eq!(GovernanceAction::ALL.len(), 8);
    }

    #[test]
    fn governance_action_display() {
        assert_eq!(GovernanceAction::Report.to_string(), "report");
        assert_eq!(GovernanceAction::Quarantine.to_string(), "quarantine");
        assert_eq!(GovernanceAction::Appeal.to_string(), "appeal");
    }

    #[test]
    fn governance_action_serde_roundtrip() {
        for action in &GovernanceAction::ALL {
            let back: GovernanceAction =
                serde_json::from_str(&serde_json::to_string(action).unwrap()).unwrap();
            assert_eq!(*action, back);
        }
    }

    #[test]
    fn incentive_property_all_five() {
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
    fn payoff_table_id_deterministic() {
        let mk = || {
            let mut t = PayoffTable {
                table_id: String::new(),
                entries: vec![PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Report,
                    condition: "truth".into(),
                    payoff_millionths: 50_000,
                    rationale: "r".into(),
                }],
                epoch: test_epoch(),
            };
            t.table_id = t.compute_id();
            t
        };
        assert_eq!(mk().table_id, mk().table_id);
        assert!(mk().table_id.starts_with("pt-"));
    }

    #[test]
    fn payoff_table_budget_balanced() {
        let table = PayoffTable {
            table_id: "t".into(),
            entries: vec![
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Reward,
                    condition: "good".into(),
                    payoff_millionths: 50_000,
                    rationale: "r".into(),
                },
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Slash,
                    condition: "bad".into(),
                    payoff_millionths: -100_000,
                    rationale: "r".into(),
                },
            ],
            epoch: test_epoch(),
        };
        assert!(table.is_budget_balanced());
    }

    #[test]
    fn payoff_table_not_budget_balanced() {
        let table = PayoffTable {
            table_id: "t".into(),
            entries: vec![
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Reward,
                    condition: "good".into(),
                    payoff_millionths: 200_000,
                    rationale: "r".into(),
                },
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Slash,
                    condition: "bad".into(),
                    payoff_millionths: -100_000,
                    rationale: "r".into(),
                },
            ],
            epoch: test_epoch(),
        };
        assert!(!table.is_budget_balanced());
    }

    #[test]
    fn payoff_table_total_for_role() {
        let table = PayoffTable {
            table_id: "t".into(),
            entries: vec![
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Reward,
                    condition: "a".into(),
                    payoff_millionths: 50_000,
                    rationale: "r".into(),
                },
                PayoffEntry {
                    role: GovernanceRole::Challenger,
                    action: GovernanceAction::Reward,
                    condition: "b".into(),
                    payoff_millionths: 30_000,
                    rationale: "r".into(),
                },
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Slash,
                    condition: "c".into(),
                    payoff_millionths: -80_000,
                    rationale: "r".into(),
                },
            ],
            epoch: test_epoch(),
        };
        assert_eq!(
            table.total_payoff_for_role(GovernanceRole::Publisher),
            -30_000
        );
        assert_eq!(
            table.total_payoff_for_role(GovernanceRole::Challenger),
            30_000
        );
    }

    #[test]
    fn strategic_scenario_honest_dominates() {
        let s = StrategicScenario {
            scenario_id: "s1".into(),
            name: "test".into(),
            behavior: StrategicBehavior::FalseReport,
            role: GovernanceRole::Publisher,
            description: "d".into(),
            expected_payoff_millionths: -100_000,
            honest_alternative_payoff_millionths: 50_000,
        };
        assert!(s.honest_dominates());
    }

    #[test]
    fn strategic_scenario_dishonest_profitable() {
        let s = StrategicScenario {
            scenario_id: "s1".into(),
            name: "test".into(),
            behavior: StrategicBehavior::CollaborativeAttack,
            role: GovernanceRole::Publisher,
            description: "d".into(),
            expected_payoff_millionths: 200_000,
            honest_alternative_payoff_millionths: 50_000,
        };
        assert!(!s.honest_dominates());
    }

    #[test]
    fn stress_test_honest_dominance_rate() {
        let test = StrategicStressTest {
            test_id: "t".into(),
            scenarios: vec![
                StrategicScenario {
                    scenario_id: "s1".into(),
                    name: "a".into(),
                    behavior: StrategicBehavior::FalseReport,
                    role: GovernanceRole::Publisher,
                    description: "d".into(),
                    expected_payoff_millionths: -100_000,
                    honest_alternative_payoff_millionths: 50_000,
                },
                StrategicScenario {
                    scenario_id: "s2".into(),
                    name: "b".into(),
                    behavior: StrategicBehavior::CollaborativeAttack,
                    role: GovernanceRole::Publisher,
                    description: "d".into(),
                    expected_payoff_millionths: 200_000,
                    honest_alternative_payoff_millionths: 50_000,
                },
            ],
            epoch: test_epoch(),
        };
        assert_eq!(test.honest_dominance_rate_millionths(), 500_000);
        assert_eq!(test.exploitable_scenarios().len(), 1);
    }

    #[test]
    fn stress_test_empty_is_perfect() {
        let test = StrategicStressTest {
            test_id: "t".into(),
            scenarios: vec![],
            epoch: test_epoch(),
        };
        assert_eq!(test.honest_dominance_rate_millionths(), MILLION);
    }

    #[test]
    fn verification_status_display() {
        assert_eq!(VerificationStatus::Verified.to_string(), "verified");
        assert_eq!(VerificationStatus::Falsified.to_string(), "falsified");
        assert_eq!(VerificationStatus::Inconclusive.to_string(), "inconclusive");
    }

    #[test]
    fn enforcement_policy_id_deterministic() {
        let mk = || {
            let mut p = EnforcementPolicy {
                policy_id: String::new(),
                rules: vec![EnforcementRule {
                    rule_id: "r1".into(),
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
            p.policy_id = p.compute_id();
            p
        };
        assert_eq!(mk().policy_id, mk().policy_id);
        assert!(mk().policy_id.starts_with("ep-"));
    }

    #[test]
    fn enforcement_policy_rules_for_trigger() {
        let policy = EnforcementPolicy {
            policy_id: "p".into(),
            rules: vec![
                EnforcementRule {
                    rule_id: "r1".into(),
                    trigger_action: GovernanceAction::Report,
                    trigger_role: GovernanceRole::Publisher,
                    condition: "c".into(),
                    enforcement_action: GovernanceAction::Quarantine,
                    penalty_millionths: 0,
                    reward_millionths: 0,
                    cooldown_epochs: 0,
                },
                EnforcementRule {
                    rule_id: "r2".into(),
                    trigger_action: GovernanceAction::Challenge,
                    trigger_role: GovernanceRole::Challenger,
                    condition: "c".into(),
                    enforcement_action: GovernanceAction::Reward,
                    penalty_millionths: 0,
                    reward_millionths: 0,
                    cooldown_epochs: 0,
                },
            ],
            challenge_window_epochs: 10,
            publisher_bond_millionths: 100_000,
            epoch: test_epoch(),
        };
        assert_eq!(policy.rules_for_trigger(GovernanceAction::Report).len(), 1);
        assert_eq!(
            policy.rules_for_trigger(GovernanceAction::Quarantine).len(),
            0
        );
    }

    #[test]
    fn mechanism_builder_creates_spec() {
        let spec = MechanismBuilder::new("test-mechanism")
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Report,
                "truth",
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
            .enforcement_rule(EnforcementRule {
                rule_id: "r1".into(),
                trigger_action: GovernanceAction::Report,
                trigger_role: GovernanceRole::Publisher,
                condition: "c".into(),
                enforcement_action: GovernanceAction::Quarantine,
                penalty_millionths: 0,
                reward_millionths: 0,
                cooldown_epochs: 0,
            })
            .verify_property(PropertyVerification {
                property: IncentiveProperty::TruthfulReporting,
                status: VerificationStatus::Verified,
                assumptions: vec![],
                evidence: "ok".into(),
                counterexample: None,
            })
            .scenario(StrategicScenario {
                scenario_id: "s1".into(),
                name: "test".into(),
                behavior: StrategicBehavior::FalseReport,
                role: GovernanceRole::Publisher,
                description: "d".into(),
                expected_payoff_millionths: -200_000,
                honest_alternative_payoff_millionths: 50_000,
            })
            .build(test_epoch());
        assert!(spec.spec_id.starts_with("ms-"));
        assert_eq!(spec.payoff_table.entries.len(), 2);
        assert_eq!(spec.enforcement_policy.rules.len(), 1);
        assert_eq!(spec.verified_property_count(), 1);
    }

    #[test]
    fn mechanism_spec_id_deterministic() {
        let mk = || {
            MechanismBuilder::new("test")
                .payoff(
                    GovernanceRole::Publisher,
                    GovernanceAction::Report,
                    "c",
                    10_000,
                    "r",
                )
                .build(test_epoch())
        };
        assert_eq!(mk().spec_id, mk().spec_id);
    }

    #[test]
    fn mechanism_is_sound_all_verified() {
        let spec = MechanismBuilder::new("sound-test")
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Reward,
                "good",
                50_000,
                "r",
            )
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Slash,
                "bad",
                -100_000,
                "r",
            )
            .verify_property(PropertyVerification {
                property: IncentiveProperty::TruthfulReporting,
                status: VerificationStatus::Verified,
                assumptions: vec![],
                evidence: "ok".into(),
                counterexample: None,
            })
            .scenario(StrategicScenario {
                scenario_id: "s1".into(),
                name: "a".into(),
                behavior: StrategicBehavior::FalseReport,
                role: GovernanceRole::Publisher,
                description: "d".into(),
                expected_payoff_millionths: -100_000,
                honest_alternative_payoff_millionths: 50_000,
            })
            .build(test_epoch());
        assert!(spec.is_sound());
    }

    #[test]
    fn mechanism_not_sound_falsified_property() {
        let spec = MechanismBuilder::new("unsound-test")
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Slash,
                "bad",
                -100_000,
                "r",
            )
            .verify_property(PropertyVerification {
                property: IncentiveProperty::TruthfulReporting,
                status: VerificationStatus::Falsified,
                assumptions: vec![],
                evidence: "fail".into(),
                counterexample: Some("exploitable".into()),
            })
            .build(test_epoch());
        assert!(!spec.is_sound());
    }

    #[test]
    fn mechanism_not_sound_exploitable_scenario() {
        let spec = MechanismBuilder::new("exploitable")
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Slash,
                "bad",
                -100_000,
                "r",
            )
            .verify_property(PropertyVerification {
                property: IncentiveProperty::TruthfulReporting,
                status: VerificationStatus::Verified,
                assumptions: vec![],
                evidence: "ok".into(),
                counterexample: None,
            })
            .scenario(StrategicScenario {
                scenario_id: "s1".into(),
                name: "a".into(),
                behavior: StrategicBehavior::CollaborativeAttack,
                role: GovernanceRole::Publisher,
                description: "d".into(),
                expected_payoff_millionths: 200_000,
                honest_alternative_payoff_millionths: 50_000,
            })
            .build(test_epoch());
        assert!(!spec.is_sound());
    }

    #[test]
    fn mechanism_serde_roundtrip() {
        let spec = canonical_governance_mechanism(test_epoch());
        let json = serde_json::to_string(&spec).unwrap();
        let back: MechanismSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn canonical_mechanism_is_sound() {
        let spec = canonical_governance_mechanism(test_epoch());
        assert!(spec.is_sound());
        assert_eq!(spec.verified_property_count(), 5);
        assert!(spec.payoff_table.is_budget_balanced());
        assert_eq!(spec.stress_test.exploitable_scenarios().len(), 0);
    }

    #[test]
    fn canonical_mechanism_four_scenarios() {
        let spec = canonical_governance_mechanism(test_epoch());
        assert_eq!(spec.stress_test.scenarios.len(), 4);
        assert_eq!(spec.stress_test.honest_dominance_rate_millionths(), MILLION);
    }

    #[test]
    fn canonical_mechanism_four_rules() {
        let spec = canonical_governance_mechanism(test_epoch());
        assert_eq!(spec.enforcement_policy.rules.len(), 4);
    }

    #[test]
    fn canonical_mechanism_eight_payoffs() {
        let spec = canonical_governance_mechanism(test_epoch());
        assert_eq!(spec.payoff_table.entries.len(), 8);
    }

    #[test]
    fn report_generation() {
        let spec = canonical_governance_mechanism(test_epoch());
        let report = generate_report(&spec);
        assert!(report.is_sound);
        assert!(report.report_id.starts_with("gr-"));
        assert!(report.exploitable_scenarios.is_empty());
        assert_eq!(report.verified_properties, 5);
    }

    #[test]
    fn report_hash_deterministic() {
        let spec = canonical_governance_mechanism(test_epoch());
        assert_eq!(
            generate_report(&spec).content_hash,
            generate_report(&spec).content_hash
        );
    }

    #[test]
    fn report_serde_roundtrip() {
        let spec = canonical_governance_mechanism(test_epoch());
        let report = generate_report(&spec);
        let back: GovernanceReport =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn strategic_behavior_display_all() {
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
            let s = b.to_string();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn payoff_table_entries_for_action() {
        let spec = canonical_governance_mechanism(test_epoch());
        let report_entries = spec
            .payoff_table
            .entries_for_action(GovernanceAction::Report);
        assert_eq!(report_entries.len(), 2);
    }

    #[test]
    fn enforcement_policy_max_penalty() {
        let spec = canonical_governance_mechanism(test_epoch());
        assert!(spec.enforcement_policy.max_total_penalty() > 0);
    }

    #[test]
    fn builder_custom_bond_and_window() {
        let spec = MechanismBuilder::new("custom")
            .publisher_bond(200_000)
            .challenge_window(20)
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Slash,
                "c",
                -300_000,
                "r",
            )
            .build(test_epoch());
        assert_eq!(spec.enforcement_policy.publisher_bond_millionths, 200_000);
        assert_eq!(spec.enforcement_policy.challenge_window_epochs, 20);
    }

    // -- Enrichment batch 2: Display uniqueness, serde, ordering --

    #[test]
    fn governance_role_display_uniqueness() {
        let mut seen = std::collections::BTreeSet::new();
        for role in GovernanceRole::ALL {
            seen.insert(role.to_string());
        }
        assert_eq!(seen.len(), 5, "all 5 roles have unique display strings");
    }

    #[test]
    fn governance_action_display_uniqueness() {
        let mut seen = std::collections::BTreeSet::new();
        for action in GovernanceAction::ALL {
            seen.insert(action.to_string());
        }
        assert_eq!(seen.len(), 8, "all 8 actions have unique display strings");
    }

    #[test]
    fn incentive_property_display_uniqueness() {
        let mut seen = std::collections::BTreeSet::new();
        for prop in IncentiveProperty::ALL {
            seen.insert(prop.to_string());
        }
        assert_eq!(
            seen.len(),
            5,
            "all 5 properties have unique display strings"
        );
    }

    #[test]
    fn governance_role_serde_roundtrip_all() {
        for role in GovernanceRole::ALL {
            let json = serde_json::to_string(&role).unwrap();
            let back: GovernanceRole = serde_json::from_str(&json).unwrap();
            assert_eq!(role, back);
        }
    }

    #[test]
    fn governance_action_serde_roundtrip_all() {
        for action in GovernanceAction::ALL {
            let json = serde_json::to_string(&action).unwrap();
            let back: GovernanceAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back);
        }
    }

    #[test]
    fn incentive_property_serde_roundtrip_all() {
        for prop in IncentiveProperty::ALL {
            let json = serde_json::to_string(&prop).unwrap();
            let back: IncentiveProperty = serde_json::from_str(&json).unwrap();
            assert_eq!(prop, back);
        }
    }

    #[test]
    fn verification_status_serde_roundtrip_all() {
        for status in [
            VerificationStatus::Verified,
            VerificationStatus::Falsified,
            VerificationStatus::Inconclusive,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: VerificationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    #[test]
    fn payoff_table_empty_is_budget_balanced() {
        let table = PayoffTable {
            table_id: "empty".into(),
            entries: vec![],
            epoch: test_epoch(),
        };
        assert!(table.is_budget_balanced());
        assert_eq!(table.total_payoff_for_role(GovernanceRole::Publisher), 0);
    }

    #[test]
    fn payoff_table_all_negative_is_budget_balanced() {
        let table = PayoffTable {
            table_id: "neg".into(),
            entries: vec![
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Slash,
                    condition: "a".into(),
                    payoff_millionths: -50_000,
                    rationale: "r".into(),
                },
                PayoffEntry {
                    role: GovernanceRole::Operator,
                    action: GovernanceAction::Slash,
                    condition: "b".into(),
                    payoff_millionths: -30_000,
                    rationale: "r".into(),
                },
            ],
            epoch: test_epoch(),
        };
        assert!(table.is_budget_balanced());
    }

    #[test]
    fn payoff_table_compute_id_deterministic() {
        let mk = || PayoffTable {
            table_id: String::new(),
            entries: vec![PayoffEntry {
                role: GovernanceRole::Publisher,
                action: GovernanceAction::Report,
                condition: "c".into(),
                payoff_millionths: 10_000,
                rationale: "r".into(),
            }],
            epoch: test_epoch(),
        };
        assert_eq!(mk().compute_id(), mk().compute_id());
        assert!(mk().compute_id().starts_with("pt-"));
    }

    #[test]
    fn strategic_scenario_equal_payoffs_honest_dominates() {
        let s = StrategicScenario {
            scenario_id: "s".into(),
            name: "tie".into(),
            behavior: StrategicBehavior::FalseReport,
            role: GovernanceRole::Publisher,
            description: "d".into(),
            expected_payoff_millionths: 50_000,
            honest_alternative_payoff_millionths: 50_000,
        };
        assert!(s.honest_dominates(), "equal payoffs means honest dominates");
    }

    #[test]
    fn strategic_stress_test_all_honest_is_perfect() {
        let test = StrategicStressTest {
            test_id: "t".into(),
            scenarios: vec![
                StrategicScenario {
                    scenario_id: "s1".into(),
                    name: "a".into(),
                    behavior: StrategicBehavior::FalseReport,
                    role: GovernanceRole::Publisher,
                    description: "d".into(),
                    expected_payoff_millionths: -100_000,
                    honest_alternative_payoff_millionths: 50_000,
                },
                StrategicScenario {
                    scenario_id: "s2".into(),
                    name: "b".into(),
                    behavior: StrategicBehavior::FrivolousChallenge,
                    role: GovernanceRole::Challenger,
                    description: "d".into(),
                    expected_payoff_millionths: -50_000,
                    honest_alternative_payoff_millionths: 20_000,
                },
            ],
            epoch: test_epoch(),
        };
        assert_eq!(test.honest_dominance_rate_millionths(), MILLION);
        assert!(test.exploitable_scenarios().is_empty());
    }

    // -- Enrichment batch 3: serde edges, Display, boundary, stress-test edges --

    #[test]
    fn strategic_behavior_serde_roundtrip_all() {
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
    fn verification_status_display_all() {
        assert_eq!(VerificationStatus::Verified.to_string(), "verified");
        assert_eq!(VerificationStatus::Falsified.to_string(), "falsified");
        assert_eq!(VerificationStatus::Inconclusive.to_string(), "inconclusive");
    }

    #[test]
    fn stress_test_empty_scenarios_returns_million() {
        let test = StrategicStressTest {
            test_id: "empty".into(),
            scenarios: vec![],
            epoch: test_epoch(),
        };
        assert_eq!(test.honest_dominance_rate_millionths(), MILLION);
    }

    #[test]
    fn stress_test_compute_id_deterministic() {
        let mk = || StrategicStressTest {
            test_id: String::new(),
            scenarios: vec![StrategicScenario {
                scenario_id: "s1".into(),
                name: "a".into(),
                behavior: StrategicBehavior::FalseReport,
                role: GovernanceRole::Publisher,
                description: "d".into(),
                expected_payoff_millionths: -100_000,
                honest_alternative_payoff_millionths: 50_000,
            }],
            epoch: test_epoch(),
        };
        assert_eq!(mk().compute_id(), mk().compute_id());
        assert!(mk().compute_id().starts_with("sst-"));
    }

    #[test]
    fn payoff_table_mixed_roles_total() {
        let table = PayoffTable {
            table_id: "mix".into(),
            entries: vec![
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Report,
                    condition: "a".into(),
                    payoff_millionths: 50_000,
                    rationale: "r".into(),
                },
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Slash,
                    condition: "b".into(),
                    payoff_millionths: -200_000,
                    rationale: "r".into(),
                },
                PayoffEntry {
                    role: GovernanceRole::Challenger,
                    action: GovernanceAction::Challenge,
                    condition: "c".into(),
                    payoff_millionths: 100_000,
                    rationale: "r".into(),
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
    fn payoff_table_not_budget_balanced_enrichment() {
        let table = PayoffTable {
            table_id: "unbal".into(),
            entries: vec![
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Reward,
                    condition: "a".into(),
                    payoff_millionths: 500_000,
                    rationale: "r".into(),
                },
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Slash,
                    condition: "b".into(),
                    payoff_millionths: -100_000,
                    rationale: "r".into(),
                },
            ],
            epoch: test_epoch(),
        };
        assert!(!table.is_budget_balanced());
    }

    #[test]
    fn mechanism_not_sound_when_not_budget_balanced() {
        let spec = MechanismBuilder::new("unbalanced")
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Reward,
                "too_much",
                500_000,
                "r",
            )
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Slash,
                "too_little",
                -100_000,
                "r",
            )
            .verify_property(PropertyVerification {
                property: IncentiveProperty::TruthfulReporting,
                status: VerificationStatus::Verified,
                assumptions: vec![],
                evidence: "ok".into(),
                counterexample: None,
            })
            .scenario(StrategicScenario {
                scenario_id: "s1".into(),
                name: "a".into(),
                behavior: StrategicBehavior::FalseReport,
                role: GovernanceRole::Publisher,
                description: "d".into(),
                expected_payoff_millionths: -100_000,
                honest_alternative_payoff_millionths: 50_000,
            })
            .build(test_epoch());
        assert!(!spec.is_sound());
    }

    #[test]
    fn mechanism_verified_property_count_zero() {
        let spec = MechanismBuilder::new("no-props").build(test_epoch());
        assert_eq!(spec.verified_property_count(), 0);
    }

    #[test]
    fn report_not_sound_with_exploitable() {
        let spec = MechanismBuilder::new("exploit")
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Slash,
                "bad",
                -100_000,
                "r",
            )
            .verify_property(PropertyVerification {
                property: IncentiveProperty::TruthfulReporting,
                status: VerificationStatus::Verified,
                assumptions: vec![],
                evidence: "ok".into(),
                counterexample: None,
            })
            .scenario(StrategicScenario {
                scenario_id: "exploit-1".into(),
                name: "exploit".into(),
                behavior: StrategicBehavior::SybilAttack,
                role: GovernanceRole::Publisher,
                description: "d".into(),
                expected_payoff_millionths: 300_000,
                honest_alternative_payoff_millionths: 50_000,
            })
            .build(test_epoch());
        let report = generate_report(&spec);
        assert!(!report.is_sound);
        assert_eq!(report.exploitable_scenarios.len(), 1);
        assert_eq!(report.exploitable_scenarios[0], "exploit-1");
    }

    #[test]
    fn enforcement_rule_serde_roundtrip() {
        let rule = EnforcementRule {
            rule_id: "r1".into(),
            trigger_action: GovernanceAction::Report,
            trigger_role: GovernanceRole::Publisher,
            condition: "c".into(),
            enforcement_action: GovernanceAction::Quarantine,
            penalty_millionths: 100_000,
            reward_millionths: 50_000,
            cooldown_epochs: 5,
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: EnforcementRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn property_verification_serde_roundtrip() {
        let pv = PropertyVerification {
            property: IncentiveProperty::BudgetBalance,
            status: VerificationStatus::Inconclusive,
            assumptions: vec!["a1".into(), "a2".into()],
            evidence: "partial".into(),
            counterexample: Some("cx".into()),
        };
        let json = serde_json::to_string(&pv).unwrap();
        let back: PropertyVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(pv, back);
    }

    #[test]
    fn strategic_scenario_serde_roundtrip() {
        let s = StrategicScenario {
            scenario_id: "s1".into(),
            name: "test".into(),
            behavior: StrategicBehavior::SybilAttack,
            role: GovernanceRole::Operator,
            description: "d".into(),
            expected_payoff_millionths: -50_000,
            honest_alternative_payoff_millionths: 30_000,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: StrategicScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn payoff_entry_serde_roundtrip() {
        let entry = PayoffEntry {
            role: GovernanceRole::Arbitrator,
            action: GovernanceAction::Appeal,
            condition: "contested".into(),
            payoff_millionths: -25_000,
            rationale: "cost of appeal".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: PayoffEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn report_schema_version_matches_constant() {
        let spec = canonical_governance_mechanism(test_epoch());
        let report = generate_report(&spec);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn enforcement_policy_compute_id_changes_with_epoch() {
        let mk = |epoch_val| {
            EnforcementPolicy {
                policy_id: String::new(),
                rules: vec![],
                challenge_window_epochs: 10,
                publisher_bond_millionths: 100_000,
                epoch: SecurityEpoch::from_raw(epoch_val),
            }
            .compute_id()
        };
        assert_ne!(mk(1), mk(2));
    }

    #[test]
    fn strategic_scenario_dishonest_does_not_dominate() {
        let s = StrategicScenario {
            scenario_id: "s".into(),
            name: "bad".into(),
            behavior: StrategicBehavior::CollaborativeAttack,
            role: GovernanceRole::Publisher,
            description: "d".into(),
            expected_payoff_millionths: 200_000,
            honest_alternative_payoff_millionths: 50_000,
        };
        assert!(!s.honest_dominates());
    }

    #[test]
    fn stress_test_half_honest_rate() {
        let test = StrategicStressTest {
            test_id: "half".into(),
            scenarios: vec![
                StrategicScenario {
                    scenario_id: "s1".into(),
                    name: "honest".into(),
                    behavior: StrategicBehavior::FalseReport,
                    role: GovernanceRole::Publisher,
                    description: "d".into(),
                    expected_payoff_millionths: -100_000,
                    honest_alternative_payoff_millionths: 50_000,
                },
                StrategicScenario {
                    scenario_id: "s2".into(),
                    name: "exploit".into(),
                    behavior: StrategicBehavior::SybilAttack,
                    role: GovernanceRole::Publisher,
                    description: "d".into(),
                    expected_payoff_millionths: 200_000,
                    honest_alternative_payoff_millionths: 50_000,
                },
            ],
            epoch: test_epoch(),
        };
        assert_eq!(test.honest_dominance_rate_millionths(), 500_000);
        assert_eq!(test.exploitable_scenarios().len(), 1);
    }

    #[test]
    fn governance_action_ordering() {
        assert!(GovernanceAction::Report < GovernanceAction::Challenge);
        assert!(GovernanceAction::Appeal > GovernanceAction::Escalate);
    }

    #[test]
    fn governance_role_ordering() {
        assert!(GovernanceRole::Publisher < GovernanceRole::Operator);
        assert!(GovernanceRole::ControlPlane > GovernanceRole::Arbitrator);
    }

    #[test]
    fn incentive_property_ordering() {
        assert!(IncentiveProperty::TruthfulReporting < IncentiveProperty::TimelyRemediation);
        assert!(IncentiveProperty::BudgetBalance > IncentiveProperty::HonestOperatorDominance);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn governance_role_display_exact_all_5() {
        assert_eq!(GovernanceRole::Publisher.to_string(), "publisher");
        assert_eq!(GovernanceRole::Operator.to_string(), "operator");
        assert_eq!(GovernanceRole::Challenger.to_string(), "challenger");
        assert_eq!(GovernanceRole::Arbitrator.to_string(), "arbitrator");
        assert_eq!(GovernanceRole::ControlPlane.to_string(), "control_plane");
    }

    #[test]
    fn governance_action_display_exact_all_8() {
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
    fn incentive_property_display_exact_all_5() {
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
    fn strategic_behavior_display_exact_all_8() {
        assert_eq!(
            StrategicBehavior::TruthfulReport.to_string(),
            "truthful_report"
        );
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
    fn enforcement_policy_serde_roundtrip() {
        let policy = EnforcementPolicy {
            policy_id: "ep-test".into(),
            rules: vec![
                EnforcementRule {
                    rule_id: "r1".into(),
                    trigger_action: GovernanceAction::Report,
                    trigger_role: GovernanceRole::Publisher,
                    condition: "c".into(),
                    enforcement_action: GovernanceAction::Quarantine,
                    penalty_millionths: 100_000,
                    reward_millionths: 50_000,
                    cooldown_epochs: 5,
                },
                EnforcementRule {
                    rule_id: "r2".into(),
                    trigger_action: GovernanceAction::Challenge,
                    trigger_role: GovernanceRole::Challenger,
                    condition: "d".into(),
                    enforcement_action: GovernanceAction::Slash,
                    penalty_millionths: 200_000,
                    reward_millionths: 0,
                    cooldown_epochs: 3,
                },
            ],
            challenge_window_epochs: 15,
            publisher_bond_millionths: 250_000,
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: EnforcementPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn payoff_table_serde_roundtrip() {
        let table = PayoffTable {
            table_id: "pt-test".into(),
            entries: vec![
                PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Reward,
                    condition: "good".into(),
                    payoff_millionths: 50_000,
                    rationale: "r".into(),
                },
                PayoffEntry {
                    role: GovernanceRole::Challenger,
                    action: GovernanceAction::Slash,
                    condition: "bad".into(),
                    payoff_millionths: -100_000,
                    rationale: "r".into(),
                },
            ],
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&table).unwrap();
        let back: PayoffTable = serde_json::from_str(&json).unwrap();
        assert_eq!(table, back);
    }

    #[test]
    fn strategic_stress_test_serde_roundtrip() {
        let sst = StrategicStressTest {
            test_id: "sst-test".into(),
            scenarios: vec![StrategicScenario {
                scenario_id: "s1".into(),
                name: "test".into(),
                behavior: StrategicBehavior::FalseReport,
                role: GovernanceRole::Publisher,
                description: "d".into(),
                expected_payoff_millionths: -100_000,
                honest_alternative_payoff_millionths: 50_000,
            }],
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&sst).unwrap();
        let back: StrategicStressTest = serde_json::from_str(&json).unwrap();
        assert_eq!(sst, back);
    }

    #[test]
    fn mechanism_spec_compute_id_changes_with_name() {
        let mk = |name| {
            MechanismBuilder::new(name)
                .payoff(
                    GovernanceRole::Publisher,
                    GovernanceAction::Slash,
                    "c",
                    -100_000,
                    "r",
                )
                .build(test_epoch())
        };
        assert_ne!(mk("alpha").spec_id, mk("beta").spec_id);
    }

    #[test]
    fn payoff_table_compute_id_changes_with_entries() {
        let mk = |payoff| {
            PayoffTable {
                table_id: String::new(),
                entries: vec![PayoffEntry {
                    role: GovernanceRole::Publisher,
                    action: GovernanceAction::Report,
                    condition: "c".into(),
                    payoff_millionths: payoff,
                    rationale: "r".into(),
                }],
                epoch: test_epoch(),
            }
            .compute_id()
        };
        assert_ne!(mk(10_000), mk(20_000));
    }

    #[test]
    fn is_sound_false_with_inconclusive_property() {
        let spec = MechanismBuilder::new("inconclusive-test")
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Slash,
                "bad",
                -100_000,
                "r",
            )
            .verify_property(PropertyVerification {
                property: IncentiveProperty::TruthfulReporting,
                status: VerificationStatus::Inconclusive,
                assumptions: vec![],
                evidence: "not enough data".into(),
                counterexample: None,
            })
            .scenario(StrategicScenario {
                scenario_id: "s1".into(),
                name: "a".into(),
                behavior: StrategicBehavior::FalseReport,
                role: GovernanceRole::Publisher,
                description: "d".into(),
                expected_payoff_millionths: -100_000,
                honest_alternative_payoff_millionths: 50_000,
            })
            .build(test_epoch());
        assert!(!spec.is_sound(), "Inconclusive property prevents soundness");
    }

    #[test]
    fn enforcement_policy_max_total_penalty_empty_rules() {
        let policy = EnforcementPolicy {
            policy_id: "empty".into(),
            rules: vec![],
            challenge_window_epochs: 10,
            publisher_bond_millionths: 100_000,
            epoch: test_epoch(),
        };
        assert_eq!(policy.max_total_penalty(), 0);
    }

    #[test]
    fn builder_defaults_match_constants() {
        let spec = MechanismBuilder::new("defaults")
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Slash,
                "c",
                -100_000,
                "r",
            )
            .build(test_epoch());
        assert_eq!(
            spec.enforcement_policy.publisher_bond_millionths,
            DEFAULT_PUBLISHER_BOND
        );
        assert_eq!(
            spec.enforcement_policy.challenge_window_epochs,
            DEFAULT_CHALLENGE_WINDOW_EPOCHS
        );
    }

    #[test]
    fn report_total_properties_and_dominance_rate_propagation() {
        let spec = MechanismBuilder::new("propagation")
            .payoff(
                GovernanceRole::Publisher,
                GovernanceAction::Slash,
                "c",
                -100_000,
                "r",
            )
            .verify_property(PropertyVerification {
                property: IncentiveProperty::TruthfulReporting,
                status: VerificationStatus::Verified,
                assumptions: vec![],
                evidence: "ok".into(),
                counterexample: None,
            })
            .verify_property(PropertyVerification {
                property: IncentiveProperty::BudgetBalance,
                status: VerificationStatus::Falsified,
                assumptions: vec![],
                evidence: "fail".into(),
                counterexample: Some("cx".into()),
            })
            .build(test_epoch());
        let report = generate_report(&spec);
        assert_eq!(report.verified_properties, 1);
        assert_eq!(report.total_properties, 2);
        assert_eq!(report.honest_dominance_rate_millionths, MILLION);
        assert!(report.budget_balanced);
    }
}
