#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-claim-envelope-contract.v1";
pub const CLAIM_ENVELOPE_CONTRACT_COMPONENT: &str = "rgc_claim_envelope_contract";
pub const CLAIM_ENVELOPE_CONTRACT_POLICY_ID: &str = "policy-rgc-claim-envelope-contract-v1";
pub const CLAIM_ENVELOPE_CONTRACT_JSON: &str =
    include_str!("../../../docs/rgc_claim_envelope_contract_v1.json");
pub const MAX_PUBLISHABLE_STALENESS_HOURS: u64 = 168;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimEnvelopeContract {
    pub schema_version: String,
    pub contract_version: String,
    pub bead_id: String,
    pub generated_by: String,
    pub generated_at_utc: String,
    pub track: ContractTrack,
    pub required_artifacts: Vec<String>,
    pub required_structured_log_fields: Vec<String>,
    pub contract_inputs: Vec<ContractInput>,
    pub claim_classes: Vec<ClaimClassSpec>,
    pub board_linkage: BoardLinkage,
    pub downgrade_rules: Vec<DowngradeRule>,
    pub consumer_channels: Vec<ConsumerChannel>,
    pub operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractTrack {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInput {
    pub input_id: String,
    pub bead_id: String,
    pub contract_doc: String,
    pub contract_json: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimClassSpec {
    pub class_id: String,
    pub tier: ClaimEnvelopeTier,
    pub publishable: bool,
    pub description: String,
    pub required_qualifier_terms: Vec<String>,
    pub allowed_surfaces: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimEnvelopeTier {
    FrontierObjective,
    PublishableUniversal,
    PublishableScoped,
    Target,
    Hypothesis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardLinkage {
    pub supremacy_contract_doc: String,
    pub supremacy_contract_json: String,
    pub react_contract_doc: String,
    pub react_contract_json: String,
    pub declared_board_dimensions: Vec<String>,
    pub declared_board_families: Vec<String>,
    pub frontier_gap_artifact: String,
    pub frontier_gap_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DowngradeRule {
    pub rule_id: String,
    pub when_condition: String,
    pub resulting_class: ClaimEnvelopeTier,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerChannel {
    pub channel_id: String,
    pub consumer_bead: String,
    pub allowed_classes: Vec<String>,
    pub requires_artifacts: Vec<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimEnvelopeScenario {
    pub scenario_id: String,
    pub requested_class: ClaimEnvelopeTier,
    pub phrase_text: String,
    pub declared_scope_complete: bool,
    pub declared_board_complete: bool,
    pub evidence_complete: bool,
    pub shipped_path: bool,
    pub frontier_gap_open: bool,
    pub stale_contract_hours: u64,
    pub replay_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimEnvelopeVerdict {
    AllowRequested,
    DowngradeToScoped,
    DowngradeToTarget,
    DowngradeToHypothesis,
    Forbid,
}

impl ClaimEnvelopeContract {
    pub fn from_embedded_json() -> Self {
        serde_json::from_str(CLAIM_ENVELOPE_CONTRACT_JSON)
            .expect("embedded claim envelope contract must parse")
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION {
            errors.push(format!(
                "unexpected schema_version `{}`",
                self.schema_version
            ));
        }
        if self.track.id != "RGC-016C" {
            errors.push(format!("unexpected track id `{}`", self.track.id));
        }

        let input_ids = collect_unique_ids(
            self.contract_inputs
                .iter()
                .map(|input| input.input_id.as_str()),
            "contract input",
            &mut errors,
        );
        let class_ids = collect_unique_ids(
            self.claim_classes
                .iter()
                .map(|class| class.class_id.as_str()),
            "claim class",
            &mut errors,
        );
        collect_unique_ids(
            self.consumer_channels
                .iter()
                .map(|channel| channel.channel_id.as_str()),
            "consumer channel",
            &mut errors,
        );
        collect_unique_ids(
            self.downgrade_rules
                .iter()
                .map(|rule| rule.rule_id.as_str()),
            "downgrade rule",
            &mut errors,
        );

        if input_ids.is_empty() {
            errors.push("missing contract inputs".to_string());
        }

        for tier in [
            ClaimEnvelopeTier::FrontierObjective,
            ClaimEnvelopeTier::PublishableUniversal,
            ClaimEnvelopeTier::PublishableScoped,
            ClaimEnvelopeTier::Target,
            ClaimEnvelopeTier::Hypothesis,
        ] {
            if self.class_for_tier(tier).is_none() {
                errors.push(format!("missing claim class for tier `{tier:?}`"));
            }
        }

        for artifact in [
            "claim_envelope_contract.json",
            "run_manifest.json",
            "events.jsonl",
            "commands.txt",
            "trace_ids.json",
        ] {
            if !self
                .required_artifacts
                .iter()
                .any(|value| value == artifact)
            {
                errors.push(format!("missing required artifact `{artifact}`"));
            }
        }

        for field in [
            "schema_version",
            "scenario_id",
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "event",
            "outcome",
            "error_code",
            "requested_class",
            "verdict",
        ] {
            if !self
                .required_structured_log_fields
                .iter()
                .any(|value| value == field)
            {
                errors.push(format!("missing structured log field `{field}`"));
            }
        }

        if !self
            .contract_inputs
            .iter()
            .any(|input| input.bead_id == "bd-1lsy.1.6.1")
        {
            errors.push("missing React capability contract input".to_string());
        }
        if !self
            .contract_inputs
            .iter()
            .any(|input| input.bead_id == "bd-1lsy.1.6.2")
        {
            errors.push("missing V8 supremacy contract input".to_string());
        }

        for family in [
            "parse_compile",
            "react_compile",
            "react_ssr",
            "react_client",
            "macro_workloads",
            "tail_latency",
            "memory",
        ] {
            if !self
                .board_linkage
                .declared_board_families
                .iter()
                .any(|value| value == family)
            {
                errors.push(format!("missing declared board family `{family}`"));
            }
        }

        for dimension in [
            "workload_cell",
            "environment",
            "entry_mode",
            "warm_state",
            "measurement_family",
        ] {
            if !self
                .board_linkage
                .declared_board_dimensions
                .iter()
                .any(|value| value == dimension)
            {
                errors.push(format!("missing declared board dimension `{dimension}`"));
            }
        }

        for channel in &self.consumer_channels {
            for allowed_class in &channel.allowed_classes {
                if !class_ids.contains(allowed_class.as_str()) {
                    errors.push(format!(
                        "consumer `{}` references unknown class `{}`",
                        channel.channel_id, allowed_class
                    ));
                }
            }
        }

        if self.operator_verification.is_empty() {
            errors.push("missing operator verification commands".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn evaluate(&self, scenario: &ClaimEnvelopeScenario) -> ClaimEnvelopeVerdict {
        if !self.phrase_satisfies_class(scenario.phrase_text.as_str(), scenario.requested_class) {
            return ClaimEnvelopeVerdict::Forbid;
        }

        let contract_is_fresh = scenario.stale_contract_hours <= MAX_PUBLISHABLE_STALENESS_HOURS;
        let publishable_scoped_ready = scenario.declared_scope_complete
            && scenario.evidence_complete
            && scenario.shipped_path
            && contract_is_fresh;
        let publishable_universal_ready = publishable_scoped_ready
            && scenario.declared_board_complete
            && !scenario.frontier_gap_open;

        match scenario.requested_class {
            ClaimEnvelopeTier::FrontierObjective => ClaimEnvelopeVerdict::AllowRequested,
            ClaimEnvelopeTier::PublishableUniversal => {
                if publishable_universal_ready {
                    ClaimEnvelopeVerdict::AllowRequested
                } else if publishable_scoped_ready {
                    ClaimEnvelopeVerdict::DowngradeToScoped
                } else if contract_is_fresh {
                    ClaimEnvelopeVerdict::DowngradeToTarget
                } else {
                    ClaimEnvelopeVerdict::DowngradeToHypothesis
                }
            }
            ClaimEnvelopeTier::PublishableScoped => {
                if publishable_scoped_ready {
                    ClaimEnvelopeVerdict::AllowRequested
                } else if contract_is_fresh {
                    ClaimEnvelopeVerdict::DowngradeToTarget
                } else {
                    ClaimEnvelopeVerdict::DowngradeToHypothesis
                }
            }
            ClaimEnvelopeTier::Target => ClaimEnvelopeVerdict::AllowRequested,
            ClaimEnvelopeTier::Hypothesis => ClaimEnvelopeVerdict::AllowRequested,
        }
    }

    fn class_for_tier(&self, tier: ClaimEnvelopeTier) -> Option<&ClaimClassSpec> {
        self.claim_classes.iter().find(|class| class.tier == tier)
    }

    fn phrase_satisfies_class(&self, phrase: &str, tier: ClaimEnvelopeTier) -> bool {
        let Some(class) = self.class_for_tier(tier) else {
            return false;
        };
        if class.required_qualifier_terms.is_empty() {
            return true;
        }
        class
            .required_qualifier_terms
            .iter()
            .all(|term| phrase_contains_required_term(phrase, term))
    }
}

fn collect_unique_ids<'a, I>(ids: I, kind: &str, errors: &mut Vec<String>) -> BTreeSet<&'a str>
where
    I: Iterator<Item = &'a str>,
{
    let mut unique = BTreeSet::new();
    for id in ids {
        if !unique.insert(id) {
            errors.push(format!("duplicate {kind} id `{id}`"));
        }
    }
    unique
}

fn phrase_contains_required_term(phrase: &str, term: &str) -> bool {
    phrase
        .to_ascii_lowercase()
        .contains(&term.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_contract() -> ClaimEnvelopeContract {
        ClaimEnvelopeContract {
            schema_version: CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION.to_string(),
            contract_version: "v1-test".to_string(),
            bead_id: "bd-test".to_string(),
            generated_by: "test".to_string(),
            generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            track: ContractTrack {
                id: "RGC-016C".to_string(),
                name: "claim envelope".to_string(),
            },
            required_artifacts: vec![
                "claim_envelope_contract.json".to_string(),
                "run_manifest.json".to_string(),
                "events.jsonl".to_string(),
                "commands.txt".to_string(),
                "trace_ids.json".to_string(),
            ],
            required_structured_log_fields: vec![
                "schema_version".to_string(),
                "scenario_id".to_string(),
                "trace_id".to_string(),
                "decision_id".to_string(),
                "policy_id".to_string(),
                "component".to_string(),
                "event".to_string(),
                "outcome".to_string(),
                "error_code".to_string(),
                "requested_class".to_string(),
                "verdict".to_string(),
            ],
            contract_inputs: vec![
                ContractInput {
                    input_id: "input-react".to_string(),
                    bead_id: "bd-1lsy.1.6.1".to_string(),
                    contract_doc: "react.md".to_string(),
                    contract_json: "react.json".to_string(),
                    role: "react capability".to_string(),
                },
                ContractInput {
                    input_id: "input-v8".to_string(),
                    bead_id: "bd-1lsy.1.6.2".to_string(),
                    contract_doc: "v8.md".to_string(),
                    contract_json: "v8.json".to_string(),
                    role: "v8 supremacy".to_string(),
                },
            ],
            claim_classes: vec![
                ClaimClassSpec {
                    class_id: "frontier".to_string(),
                    tier: ClaimEnvelopeTier::FrontierObjective,
                    publishable: false,
                    description: "frontier objective".to_string(),
                    required_qualifier_terms: vec![],
                    allowed_surfaces: vec!["internal".to_string()],
                },
                ClaimClassSpec {
                    class_id: "universal".to_string(),
                    tier: ClaimEnvelopeTier::PublishableUniversal,
                    publishable: true,
                    description: "universal".to_string(),
                    required_qualifier_terms: vec!["universal".to_string()],
                    allowed_surfaces: vec!["docs".to_string()],
                },
                ClaimClassSpec {
                    class_id: "scoped".to_string(),
                    tier: ClaimEnvelopeTier::PublishableScoped,
                    publishable: true,
                    description: "scoped".to_string(),
                    required_qualifier_terms: vec!["scoped".to_string()],
                    allowed_surfaces: vec!["docs".to_string()],
                },
                ClaimClassSpec {
                    class_id: "target".to_string(),
                    tier: ClaimEnvelopeTier::Target,
                    publishable: false,
                    description: "target".to_string(),
                    required_qualifier_terms: vec![],
                    allowed_surfaces: vec!["internal".to_string()],
                },
                ClaimClassSpec {
                    class_id: "hypothesis".to_string(),
                    tier: ClaimEnvelopeTier::Hypothesis,
                    publishable: false,
                    description: "hypothesis".to_string(),
                    required_qualifier_terms: vec![],
                    allowed_surfaces: vec!["internal".to_string()],
                },
            ],
            board_linkage: BoardLinkage {
                supremacy_contract_doc: "supremacy.md".to_string(),
                supremacy_contract_json: "supremacy.json".to_string(),
                react_contract_doc: "react.md".to_string(),
                react_contract_json: "react.json".to_string(),
                declared_board_dimensions: vec![
                    "workload_cell".to_string(),
                    "environment".to_string(),
                    "entry_mode".to_string(),
                    "warm_state".to_string(),
                    "measurement_family".to_string(),
                ],
                declared_board_families: vec![
                    "parse_compile".to_string(),
                    "react_compile".to_string(),
                    "react_ssr".to_string(),
                    "react_client".to_string(),
                    "macro_workloads".to_string(),
                    "tail_latency".to_string(),
                    "memory".to_string(),
                ],
                frontier_gap_artifact: "frontier_gaps.json".to_string(),
                frontier_gap_bead: "bd-frontier".to_string(),
            },
            downgrade_rules: vec![DowngradeRule {
                rule_id: "stale-downgrade".to_string(),
                when_condition: "stale > 168h".to_string(),
                resulting_class: ClaimEnvelopeTier::Hypothesis,
                rationale: "stale contracts downgrade".to_string(),
            }],
            consumer_channels: vec![ConsumerChannel {
                channel_id: "docs-channel".to_string(),
                consumer_bead: "bd-docs".to_string(),
                allowed_classes: vec!["universal".to_string(), "scoped".to_string()],
                requires_artifacts: vec!["claim_envelope_contract.json".to_string()],
                rationale: "docs consumption".to_string(),
            }],
            operator_verification: vec!["verify-a".to_string()],
        }
    }

    fn scenario_all_ready(tier: ClaimEnvelopeTier, phrase: &str) -> ClaimEnvelopeScenario {
        ClaimEnvelopeScenario {
            scenario_id: "ready".to_string(),
            requested_class: tier,
            phrase_text: phrase.to_string(),
            declared_scope_complete: true,
            declared_board_complete: true,
            evidence_complete: true,
            shipped_path: true,
            frontier_gap_open: false,
            stale_contract_hours: 0,
            replay_command: "test".to_string(),
        }
    }

    #[test]
    fn schema_constants_nonempty() {
        assert!(!CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION.is_empty());
        assert!(!CLAIM_ENVELOPE_CONTRACT_COMPONENT.is_empty());
        assert!(!CLAIM_ENVELOPE_CONTRACT_POLICY_ID.is_empty());
    }

    #[test]
    fn max_staleness_is_one_week() {
        assert_eq!(MAX_PUBLISHABLE_STALENESS_HOURS, 168);
    }

    #[test]
    fn embedded_contract_loads() {
        let contract = ClaimEnvelopeContract::from_embedded_json();
        assert_eq!(
            contract.schema_version,
            CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION
        );
        assert_eq!(contract.track.id, "RGC-016C");
    }

    #[test]
    fn embedded_contract_validates() {
        let contract = ClaimEnvelopeContract::from_embedded_json();
        contract.validate().expect("embedded contract should validate");
    }

    #[test]
    fn minimal_contract_validates() {
        let contract = minimal_contract();
        contract.validate().expect("minimal contract should validate");
    }

    #[test]
    fn validate_rejects_wrong_schema_version() {
        let mut contract = minimal_contract();
        contract.schema_version = "wrong".to_string();
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("schema_version")));
    }

    #[test]
    fn validate_rejects_wrong_track_id() {
        let mut contract = minimal_contract();
        contract.track.id = "RGC-999".to_string();
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("track id")));
    }

    #[test]
    fn validate_rejects_empty_inputs() {
        let mut contract = minimal_contract();
        contract.contract_inputs.clear();
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("missing contract inputs")
            || e.contains("React capability")
            || e.contains("V8 supremacy")));
    }

    #[test]
    fn validate_rejects_duplicate_class_ids() {
        let mut contract = minimal_contract();
        let dup = contract.claim_classes[0].clone();
        contract.claim_classes.push(dup);
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("duplicate")));
    }

    #[test]
    fn validate_rejects_missing_required_artifact() {
        let mut contract = minimal_contract();
        contract.required_artifacts.retain(|a| a != "events.jsonl");
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("events.jsonl")));
    }

    #[test]
    fn validate_rejects_missing_log_field() {
        let mut contract = minimal_contract();
        contract
            .required_structured_log_fields
            .retain(|f| f != "trace_id");
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("trace_id")));
    }

    #[test]
    fn validate_rejects_missing_board_family() {
        let mut contract = minimal_contract();
        contract
            .board_linkage
            .declared_board_families
            .retain(|f| f != "react_ssr");
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("react_ssr")));
    }

    #[test]
    fn validate_rejects_missing_board_dimension() {
        let mut contract = minimal_contract();
        contract
            .board_linkage
            .declared_board_dimensions
            .retain(|d| d != "warm_state");
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("warm_state")));
    }

    #[test]
    fn validate_rejects_channel_referencing_unknown_class() {
        let mut contract = minimal_contract();
        contract.consumer_channels[0]
            .allowed_classes
            .push("nonexistent".to_string());
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("unknown class")));
    }

    #[test]
    fn validate_rejects_empty_operator_verification() {
        let mut contract = minimal_contract();
        contract.operator_verification.clear();
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("operator verification")));
    }

    #[test]
    fn evaluate_frontier_always_allowed() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(ClaimEnvelopeTier::FrontierObjective, "frontier goal");
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::AllowRequested);
    }

    #[test]
    fn evaluate_target_always_allowed() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(ClaimEnvelopeTier::Target, "target goal");
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::AllowRequested);
    }

    #[test]
    fn evaluate_hypothesis_always_allowed() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(ClaimEnvelopeTier::Hypothesis, "hypothesis");
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::AllowRequested);
    }

    #[test]
    fn evaluate_universal_allowed_when_all_ready() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(
            ClaimEnvelopeTier::PublishableUniversal,
            "universal claim",
        );
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::AllowRequested);
    }

    #[test]
    fn evaluate_universal_downgrades_to_scoped_when_board_incomplete() {
        let contract = minimal_contract();
        let mut scenario = scenario_all_ready(
            ClaimEnvelopeTier::PublishableUniversal,
            "universal claim",
        );
        scenario.declared_board_complete = false;
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::DowngradeToScoped);
    }

    #[test]
    fn evaluate_universal_downgrades_to_scoped_when_frontier_gap_open() {
        let contract = minimal_contract();
        let mut scenario = scenario_all_ready(
            ClaimEnvelopeTier::PublishableUniversal,
            "universal claim",
        );
        scenario.frontier_gap_open = true;
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::DowngradeToScoped);
    }

    #[test]
    fn evaluate_universal_downgrades_to_target_when_evidence_incomplete() {
        let contract = minimal_contract();
        let mut scenario = scenario_all_ready(
            ClaimEnvelopeTier::PublishableUniversal,
            "universal claim",
        );
        scenario.evidence_complete = false;
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::DowngradeToTarget);
    }

    #[test]
    fn evaluate_universal_downgrades_to_hypothesis_when_stale() {
        let contract = minimal_contract();
        let mut scenario = scenario_all_ready(
            ClaimEnvelopeTier::PublishableUniversal,
            "universal claim",
        );
        scenario.evidence_complete = false;
        scenario.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS + 1;
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::DowngradeToHypothesis);
    }

    #[test]
    fn evaluate_scoped_allowed_when_ready() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(
            ClaimEnvelopeTier::PublishableScoped,
            "scoped claim",
        );
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::AllowRequested);
    }

    #[test]
    fn evaluate_scoped_downgrades_to_target_when_not_shipped() {
        let contract = minimal_contract();
        let mut scenario = scenario_all_ready(
            ClaimEnvelopeTier::PublishableScoped,
            "scoped claim",
        );
        scenario.shipped_path = false;
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::DowngradeToTarget);
    }

    #[test]
    fn evaluate_forbids_when_phrase_missing_qualifier() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(
            ClaimEnvelopeTier::PublishableUniversal,
            "this phrase lacks the qualifier",
        );
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::Forbid);
    }

    #[test]
    fn phrase_matching_is_case_insensitive() {
        assert!(phrase_contains_required_term("Universal Claim", "universal"));
        assert!(phrase_contains_required_term("UNIVERSAL CLAIM", "universal"));
        assert!(phrase_contains_required_term("universal claim", "UNIVERSAL"));
    }

    #[test]
    fn tier_serde_round_trip() {
        for tier in [
            ClaimEnvelopeTier::FrontierObjective,
            ClaimEnvelopeTier::PublishableUniversal,
            ClaimEnvelopeTier::PublishableScoped,
            ClaimEnvelopeTier::Target,
            ClaimEnvelopeTier::Hypothesis,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize");
            let restored: ClaimEnvelopeTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, tier);
        }
    }

    #[test]
    fn verdict_serde_round_trip() {
        for verdict in [
            ClaimEnvelopeVerdict::AllowRequested,
            ClaimEnvelopeVerdict::DowngradeToScoped,
            ClaimEnvelopeVerdict::DowngradeToTarget,
            ClaimEnvelopeVerdict::DowngradeToHypothesis,
            ClaimEnvelopeVerdict::Forbid,
        ] {
            let json = serde_json::to_string(&verdict).expect("serialize");
            let restored: ClaimEnvelopeVerdict = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, verdict);
        }
    }

    #[test]
    fn contract_serde_round_trip() {
        let contract = minimal_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let restored: ClaimEnvelopeContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, contract);
    }

    #[test]
    fn scenario_serde_round_trip() {
        let scenario = scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal test");
        let json = serde_json::to_string(&scenario).expect("serialize");
        let restored: ClaimEnvelopeScenario = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, scenario);
    }

    #[test]
    fn evaluate_deterministic_across_runs() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(
            ClaimEnvelopeTier::PublishableUniversal,
            "universal claim",
        );
        let v1 = contract.evaluate(&scenario);
        let v2 = contract.evaluate(&scenario);
        assert_eq!(v1, v2);
    }

    #[test]
    fn staleness_boundary_at_168_hours() {
        let contract = minimal_contract();

        let mut fresh = scenario_all_ready(
            ClaimEnvelopeTier::PublishableScoped,
            "scoped claim",
        );
        fresh.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS;
        assert_eq!(contract.evaluate(&fresh), ClaimEnvelopeVerdict::AllowRequested);

        let mut stale = scenario_all_ready(
            ClaimEnvelopeTier::PublishableScoped,
            "scoped claim",
        );
        stale.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS + 1;
        stale.evidence_complete = false;
        assert_eq!(contract.evaluate(&stale), ClaimEnvelopeVerdict::DowngradeToHypothesis);
    }
}
