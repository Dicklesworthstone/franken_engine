#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-claim-envelope-contract.v1";
pub const CLAIM_ENVELOPE_CONTRACT_COMPONENT: &str = "rgc_claim_envelope_contract";
pub const CLAIM_ENVELOPE_CONTRACT_POLICY_ID: &str = "policy-rgc-claim-envelope-contract-v1";
pub const REACT_CAPABILITY_CONTRACT_POLICY_ID: &str = "policy-rgc-react-capability-contract-v1";
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
    pub contract_policy_id: Option<String>,
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
    pub react_contract_policy_id: String,
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
        collect_unique_ids(
            self.contract_inputs
                .iter()
                .map(|input| input.bead_id.as_str()),
            "contract input bead",
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
        if let Some(react_input) = self
            .contract_inputs
            .iter()
            .find(|input| input.bead_id == "bd-1lsy.1.6.1")
        {
            match react_input.contract_policy_id.as_deref() {
                Some(REACT_CAPABILITY_CONTRACT_POLICY_ID) => {}
                Some(other) => errors.push(format!(
                    "unexpected React contract input policy id `{other}`"
                )),
                None => errors.push("missing React contract input policy id linkage".to_string()),
            }
        }
        if !self
            .contract_inputs
            .iter()
            .any(|input| input.bead_id == "bd-1lsy.1.6.2")
        {
            errors.push("missing V8 supremacy contract input".to_string());
        }
        if self
            .board_linkage
            .react_contract_policy_id
            .trim()
            .is_empty()
        {
            errors.push("missing React contract policy id linkage".to_string());
        } else if self.board_linkage.react_contract_policy_id != REACT_CAPABILITY_CONTRACT_POLICY_ID
        {
            errors.push(format!(
                "unexpected React contract policy id `{}`",
                self.board_linkage.react_contract_policy_id
            ));
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
                    contract_policy_id: Some(REACT_CAPABILITY_CONTRACT_POLICY_ID.to_string()),
                    role: "react capability".to_string(),
                },
                ContractInput {
                    input_id: "input-v8".to_string(),
                    bead_id: "bd-1lsy.1.6.2".to_string(),
                    contract_doc: "v8.md".to_string(),
                    contract_json: "v8.json".to_string(),
                    contract_policy_id: None,
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
                react_contract_policy_id: REACT_CAPABILITY_CONTRACT_POLICY_ID.to_string(),
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
        contract
            .validate()
            .expect("embedded contract should validate");
    }

    #[test]
    fn minimal_contract_validates() {
        let contract = minimal_contract();
        contract
            .validate()
            .expect("minimal contract should validate");
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
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::AllowRequested
        );
    }

    #[test]
    fn evaluate_target_always_allowed() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(ClaimEnvelopeTier::Target, "target goal");
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::AllowRequested
        );
    }

    #[test]
    fn evaluate_hypothesis_always_allowed() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(ClaimEnvelopeTier::Hypothesis, "hypothesis");
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::AllowRequested
        );
    }

    #[test]
    fn evaluate_universal_allowed_when_all_ready() {
        let contract = minimal_contract();
        let scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::AllowRequested
        );
    }

    #[test]
    fn evaluate_universal_downgrades_to_scoped_when_board_incomplete() {
        let contract = minimal_contract();
        let mut scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        scenario.declared_board_complete = false;
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToScoped
        );
    }

    #[test]
    fn evaluate_universal_downgrades_to_scoped_when_frontier_gap_open() {
        let contract = minimal_contract();
        let mut scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        scenario.frontier_gap_open = true;
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToScoped
        );
    }

    #[test]
    fn evaluate_universal_downgrades_to_target_when_evidence_incomplete() {
        let contract = minimal_contract();
        let mut scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        scenario.evidence_complete = false;
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToTarget
        );
    }

    #[test]
    fn evaluate_universal_downgrades_to_hypothesis_when_stale() {
        let contract = minimal_contract();
        let mut scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        scenario.evidence_complete = false;
        scenario.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS + 1;
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToHypothesis
        );
    }

    #[test]
    fn evaluate_scoped_allowed_when_ready() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(ClaimEnvelopeTier::PublishableScoped, "scoped claim");
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::AllowRequested
        );
    }

    #[test]
    fn evaluate_scoped_downgrades_to_target_when_not_shipped() {
        let contract = minimal_contract();
        let mut scenario = scenario_all_ready(ClaimEnvelopeTier::PublishableScoped, "scoped claim");
        scenario.shipped_path = false;
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToTarget
        );
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
        assert!(phrase_contains_required_term(
            "Universal Claim",
            "universal"
        ));
        assert!(phrase_contains_required_term(
            "UNIVERSAL CLAIM",
            "universal"
        ));
        assert!(phrase_contains_required_term(
            "universal claim",
            "UNIVERSAL"
        ));
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
        let scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal test");
        let json = serde_json::to_string(&scenario).expect("serialize");
        let restored: ClaimEnvelopeScenario = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, scenario);
    }

    #[test]
    fn evaluate_deterministic_across_runs() {
        let contract = minimal_contract();
        let scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        let v1 = contract.evaluate(&scenario);
        let v2 = contract.evaluate(&scenario);
        assert_eq!(v1, v2);
    }

    #[test]
    fn staleness_boundary_at_168_hours() {
        let contract = minimal_contract();

        let mut fresh = scenario_all_ready(ClaimEnvelopeTier::PublishableScoped, "scoped claim");
        fresh.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS;
        assert_eq!(
            contract.evaluate(&fresh),
            ClaimEnvelopeVerdict::AllowRequested
        );

        let mut stale = scenario_all_ready(ClaimEnvelopeTier::PublishableScoped, "scoped claim");
        stale.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS + 1;
        stale.evidence_complete = false;
        assert_eq!(
            contract.evaluate(&stale),
            ClaimEnvelopeVerdict::DowngradeToHypothesis
        );
    }

    #[test]
    fn validate_rejects_duplicate_input_ids() {
        let mut contract = minimal_contract();
        let dup = contract.contract_inputs[0].clone();
        contract.contract_inputs.push(dup);
        let errors = contract.validate().expect_err("should fail");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("duplicate contract input"))
        );
    }

    #[test]
    fn validate_rejects_duplicate_input_bead_ids() {
        let mut contract = minimal_contract();
        contract.contract_inputs[1].bead_id = contract.contract_inputs[0].bead_id.clone();
        let errors = contract.validate().expect_err("should fail");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("duplicate contract input bead"))
        );
    }

    #[test]
    fn validate_rejects_duplicate_channel_ids() {
        let mut contract = minimal_contract();
        let dup = contract.consumer_channels[0].clone();
        contract.consumer_channels.push(dup);
        let errors = contract.validate().expect_err("should fail");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("duplicate consumer channel"))
        );
    }

    #[test]
    fn validate_rejects_duplicate_downgrade_rule_ids() {
        let mut contract = minimal_contract();
        let dup = contract.downgrade_rules[0].clone();
        contract.downgrade_rules.push(dup);
        let errors = contract.validate().expect_err("should fail");
        assert!(
            errors
                .iter()
                .any(|e| e.contains("duplicate downgrade rule"))
        );
    }

    #[test]
    fn validate_rejects_missing_react_input_specifically() {
        let mut contract = minimal_contract();
        contract
            .contract_inputs
            .retain(|i| i.bead_id != "bd-1lsy.1.6.1");
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("React capability")));
    }

    #[test]
    fn validate_rejects_missing_v8_input_specifically() {
        let mut contract = minimal_contract();
        contract
            .contract_inputs
            .retain(|i| i.bead_id != "bd-1lsy.1.6.2");
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("V8 supremacy")));
    }

    #[test]
    fn validate_rejects_missing_claim_class_for_each_tier() {
        for tier in [
            ClaimEnvelopeTier::FrontierObjective,
            ClaimEnvelopeTier::PublishableUniversal,
            ClaimEnvelopeTier::PublishableScoped,
            ClaimEnvelopeTier::Target,
            ClaimEnvelopeTier::Hypothesis,
        ] {
            let mut contract = minimal_contract();
            contract.claim_classes.retain(|c| c.tier != tier);
            let errors = contract
                .validate()
                .expect_err("should fail for missing tier");
            assert!(
                errors
                    .iter()
                    .any(|e| e.contains("missing claim class for tier"))
            );
        }
    }

    #[test]
    fn validate_accumulates_multiple_errors() {
        let mut contract = minimal_contract();
        contract.schema_version = "wrong".to_string();
        contract.track.id = "wrong".to_string();
        contract.operator_verification.clear();
        let errors = contract.validate().expect_err("should fail");
        assert!(
            errors.len() >= 3,
            "expected at least 3 errors, got {}",
            errors.len()
        );
        assert!(errors.iter().any(|e| e.contains("schema_version")));
        assert!(errors.iter().any(|e| e.contains("track id")));
        assert!(errors.iter().any(|e| e.contains("operator verification")));
    }

    #[test]
    fn tier_ordering_matches_declaration_order() {
        assert!(ClaimEnvelopeTier::FrontierObjective < ClaimEnvelopeTier::PublishableUniversal);
        assert!(ClaimEnvelopeTier::PublishableUniversal < ClaimEnvelopeTier::PublishableScoped);
        assert!(ClaimEnvelopeTier::PublishableScoped < ClaimEnvelopeTier::Target);
        assert!(ClaimEnvelopeTier::Target < ClaimEnvelopeTier::Hypothesis);
    }

    #[test]
    fn tier_serde_uses_snake_case() {
        let json = serde_json::to_string(&ClaimEnvelopeTier::FrontierObjective).unwrap();
        assert_eq!(json, "\"frontier_objective\"");
        let json = serde_json::to_string(&ClaimEnvelopeTier::PublishableUniversal).unwrap();
        assert_eq!(json, "\"publishable_universal\"");
        let json = serde_json::to_string(&ClaimEnvelopeTier::PublishableScoped).unwrap();
        assert_eq!(json, "\"publishable_scoped\"");
        let json = serde_json::to_string(&ClaimEnvelopeTier::Target).unwrap();
        assert_eq!(json, "\"target\"");
        let json = serde_json::to_string(&ClaimEnvelopeTier::Hypothesis).unwrap();
        assert_eq!(json, "\"hypothesis\"");
    }

    #[test]
    fn verdict_serde_uses_snake_case() {
        let json = serde_json::to_string(&ClaimEnvelopeVerdict::AllowRequested).unwrap();
        assert_eq!(json, "\"allow_requested\"");
        let json = serde_json::to_string(&ClaimEnvelopeVerdict::DowngradeToScoped).unwrap();
        assert_eq!(json, "\"downgrade_to_scoped\"");
        let json = serde_json::to_string(&ClaimEnvelopeVerdict::DowngradeToTarget).unwrap();
        assert_eq!(json, "\"downgrade_to_target\"");
        let json = serde_json::to_string(&ClaimEnvelopeVerdict::DowngradeToHypothesis).unwrap();
        assert_eq!(json, "\"downgrade_to_hypothesis\"");
        let json = serde_json::to_string(&ClaimEnvelopeVerdict::Forbid).unwrap();
        assert_eq!(json, "\"forbid\"");
    }

    #[test]
    fn phrase_empty_string_matches_empty_term() {
        assert!(phrase_contains_required_term("", ""));
    }

    #[test]
    fn phrase_nonempty_matches_empty_term() {
        assert!(phrase_contains_required_term("anything at all", ""));
    }

    #[test]
    fn phrase_empty_does_not_match_nonempty_term() {
        assert!(!phrase_contains_required_term("", "required"));
    }

    #[test]
    fn phrase_partial_substring_match() {
        assert!(phrase_contains_required_term(
            "this is a universally accepted claim",
            "universal"
        ));
    }

    #[test]
    fn evaluate_scoped_downgrades_to_hypothesis_when_stale_and_not_ready() {
        let contract = minimal_contract();
        let mut scenario = scenario_all_ready(ClaimEnvelopeTier::PublishableScoped, "scoped claim");
        scenario.shipped_path = false;
        scenario.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS + 1;
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToHypothesis
        );
    }

    #[test]
    fn evaluate_universal_downgrades_to_target_when_scope_incomplete() {
        let contract = minimal_contract();
        let mut scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        scenario.declared_scope_complete = false;
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToTarget
        );
    }

    #[test]
    fn evaluate_universal_downgrades_to_target_when_shipped_path_false() {
        let contract = minimal_contract();
        let mut scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        scenario.shipped_path = false;
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToTarget
        );
    }

    #[test]
    fn evaluate_frontier_allowed_with_any_phrase() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(
            ClaimEnvelopeTier::FrontierObjective,
            "completely unrelated words",
        );
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::AllowRequested
        );
    }

    #[test]
    fn evaluate_target_allowed_with_any_phrase() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(ClaimEnvelopeTier::Target, "completely unrelated words");
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::AllowRequested
        );
    }

    #[test]
    fn evaluate_hypothesis_allowed_with_any_phrase() {
        let contract = minimal_contract();
        let scenario =
            scenario_all_ready(ClaimEnvelopeTier::Hypothesis, "completely unrelated words");
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::AllowRequested
        );
    }

    #[test]
    fn evaluate_forbids_scoped_when_phrase_lacks_qualifier() {
        let contract = minimal_contract();
        let scenario = scenario_all_ready(
            ClaimEnvelopeTier::PublishableScoped,
            "this has no matching qualifier",
        );
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::Forbid);
    }

    #[test]
    fn class_for_tier_returns_none_when_missing() {
        let mut contract = minimal_contract();
        contract
            .claim_classes
            .retain(|c| c.tier != ClaimEnvelopeTier::Target);
        assert!(contract.class_for_tier(ClaimEnvelopeTier::Target).is_none());
    }

    #[test]
    fn phrase_satisfies_class_returns_false_when_tier_missing() {
        let mut contract = minimal_contract();
        contract.claim_classes.clear();
        assert!(!contract.phrase_satisfies_class("anything", ClaimEnvelopeTier::Target));
    }

    #[test]
    fn evaluate_forbids_when_all_classes_removed() {
        let mut contract = minimal_contract();
        contract.claim_classes.clear();
        let scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        assert_eq!(contract.evaluate(&scenario), ClaimEnvelopeVerdict::Forbid);
    }

    #[test]
    fn evaluate_staleness_boundary_exact_for_universal() {
        let contract = minimal_contract();
        let mut at_boundary =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        at_boundary.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS;
        assert_eq!(
            contract.evaluate(&at_boundary),
            ClaimEnvelopeVerdict::AllowRequested
        );

        let mut over_boundary =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        over_boundary.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS + 1;
        over_boundary.evidence_complete = false;
        assert_eq!(
            contract.evaluate(&over_boundary),
            ClaimEnvelopeVerdict::DowngradeToHypothesis
        );
    }

    #[test]
    fn evaluate_zero_staleness_hours() {
        let contract = minimal_contract();
        let mut scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        scenario.stale_contract_hours = 0;
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::AllowRequested
        );
    }

    #[test]
    fn evaluate_max_u64_staleness_hours_downgrades() {
        let contract = minimal_contract();
        let mut scenario = scenario_all_ready(ClaimEnvelopeTier::PublishableScoped, "scoped claim");
        scenario.stale_contract_hours = u64::MAX;
        scenario.shipped_path = false;
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToHypothesis
        );
    }

    #[test]
    fn collect_unique_ids_empty_iterator_no_errors() {
        let mut errors = Vec::new();
        let result = collect_unique_ids(std::iter::empty(), "test", &mut errors);
        assert!(result.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn collect_unique_ids_single_item() {
        let mut errors = Vec::new();
        let result = collect_unique_ids(["alpha"].into_iter(), "test", &mut errors);
        assert_eq!(result.len(), 1);
        assert!(result.contains("alpha"));
        assert!(errors.is_empty());
    }

    #[test]
    fn collect_unique_ids_reports_all_duplicates() {
        let mut errors = Vec::new();
        let ids = vec!["a", "b", "a", "c", "b"];
        let result = collect_unique_ids(ids.into_iter(), "item", &mut errors);
        assert_eq!(result.len(), 3);
        assert_eq!(errors.len(), 2);
        assert!(errors.iter().any(|e| e.contains("duplicate item id `a`")));
        assert!(errors.iter().any(|e| e.contains("duplicate item id `b`")));
    }

    #[test]
    fn multiple_qualifier_terms_must_all_match() {
        let mut contract = minimal_contract();
        for class in &mut contract.claim_classes {
            if class.tier == ClaimEnvelopeTier::PublishableUniversal {
                class.required_qualifier_terms =
                    vec!["universal".to_string(), "verified".to_string()];
            }
        }
        let scenario_both = scenario_all_ready(
            ClaimEnvelopeTier::PublishableUniversal,
            "universal verified claim",
        );
        assert_eq!(
            contract.evaluate(&scenario_both),
            ClaimEnvelopeVerdict::AllowRequested
        );

        let scenario_one_only = scenario_all_ready(
            ClaimEnvelopeTier::PublishableUniversal,
            "universal claim only",
        );
        assert_eq!(
            contract.evaluate(&scenario_one_only),
            ClaimEnvelopeVerdict::Forbid
        );
    }

    #[test]
    fn validate_missing_both_react_and_v8_with_other_inputs() {
        let mut contract = minimal_contract();
        contract.contract_inputs = vec![ContractInput {
            input_id: "input-other".to_string(),
            bead_id: "bd-other".to_string(),
            contract_doc: "other.md".to_string(),
            contract_json: "other.json".to_string(),
            contract_policy_id: None,
            role: "other".to_string(),
        }];
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("React capability")));
        assert!(errors.iter().any(|e| e.contains("V8 supremacy")));
    }

    #[test]
    fn validate_all_required_artifacts_missing() {
        let mut contract = minimal_contract();
        contract.required_artifacts.clear();
        let errors = contract.validate().expect_err("should fail");
        for artifact in [
            "claim_envelope_contract.json",
            "run_manifest.json",
            "events.jsonl",
            "commands.txt",
            "trace_ids.json",
        ] {
            assert!(
                errors.iter().any(|e| e.contains(artifact)),
                "missing error for artifact `{artifact}`"
            );
        }
    }

    #[test]
    fn validate_all_required_log_fields_missing() {
        let mut contract = minimal_contract();
        contract.required_structured_log_fields.clear();
        let errors = contract.validate().expect_err("should fail");
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
            assert!(
                errors.iter().any(|e| e.contains(field)),
                "missing error for log field `{field}`"
            );
        }
    }

    #[test]
    fn validate_all_board_families_missing() {
        let mut contract = minimal_contract();
        contract.board_linkage.declared_board_families.clear();
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.len() >= 7, "expected errors for all 7 families");
    }

    #[test]
    fn validate_all_board_dimensions_missing() {
        let mut contract = minimal_contract();
        contract.board_linkage.declared_board_dimensions.clear();
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.len() >= 5, "expected errors for all 5 dimensions");
    }

    #[test]
    fn validate_react_contract_policy_linkage_missing_or_drifted() {
        let mut contract = minimal_contract();
        contract.contract_inputs[0].contract_policy_id = None;
        let errors = contract.validate().expect_err("should fail");
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing React contract input policy id linkage"))
        );

        contract.contract_inputs[0].contract_policy_id = Some("policy-react-other".to_string());
        let errors = contract.validate().expect_err("should fail");
        assert!(
            errors
                .iter()
                .any(|error| error.contains("unexpected React contract input policy id"))
        );

        contract.contract_inputs[0].contract_policy_id =
            Some(REACT_CAPABILITY_CONTRACT_POLICY_ID.to_string());
        contract.board_linkage.react_contract_policy_id.clear();
        let errors = contract.validate().expect_err("should fail");
        assert!(
            errors
                .iter()
                .any(|error| error.contains("missing React contract policy id linkage"))
        );

        contract.board_linkage.react_contract_policy_id = "policy-react-other".to_string();
        let errors = contract.validate().expect_err("should fail");
        assert!(
            errors
                .iter()
                .any(|error| error.contains("unexpected React contract policy id"))
        );
    }

    #[test]
    fn contract_input_serde_round_trip() {
        let input = ContractInput {
            input_id: "test-input".to_string(),
            bead_id: "bd-test".to_string(),
            contract_doc: "doc.md".to_string(),
            contract_json: "contract.json".to_string(),
            contract_policy_id: Some("policy-test".to_string()),
            role: "test role".to_string(),
        };
        let json = serde_json::to_string(&input).expect("serialize");
        let restored: ContractInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, input);
    }

    #[test]
    fn board_linkage_serde_round_trip() {
        let linkage = BoardLinkage {
            supremacy_contract_doc: "s.md".to_string(),
            supremacy_contract_json: "s.json".to_string(),
            react_contract_doc: "r.md".to_string(),
            react_contract_json: "r.json".to_string(),
            react_contract_policy_id: "policy-react-v1".to_string(),
            declared_board_dimensions: vec!["dim1".to_string()],
            declared_board_families: vec!["fam1".to_string()],
            frontier_gap_artifact: "gap.json".to_string(),
            frontier_gap_bead: "bd-gap".to_string(),
        };
        let json = serde_json::to_string(&linkage).expect("serialize");
        let restored: BoardLinkage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, linkage);
    }

    #[test]
    fn downgrade_rule_serde_round_trip() {
        let rule = DowngradeRule {
            rule_id: "test-rule".to_string(),
            when_condition: "always".to_string(),
            resulting_class: ClaimEnvelopeTier::Hypothesis,
            rationale: "because".to_string(),
        };
        let json = serde_json::to_string(&rule).expect("serialize");
        let restored: DowngradeRule = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, rule);
    }

    #[test]
    fn consumer_channel_serde_round_trip() {
        let channel = ConsumerChannel {
            channel_id: "ch-1".to_string(),
            consumer_bead: "bd-consumer".to_string(),
            allowed_classes: vec!["universal".to_string(), "scoped".to_string()],
            requires_artifacts: vec!["artifact.json".to_string()],
            rationale: "testing".to_string(),
        };
        let json = serde_json::to_string(&channel).expect("serialize");
        let restored: ConsumerChannel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, channel);
    }

    #[test]
    fn claim_class_spec_serde_round_trip() {
        let spec = ClaimClassSpec {
            class_id: "test-class".to_string(),
            tier: ClaimEnvelopeTier::PublishableScoped,
            publishable: true,
            description: "test".to_string(),
            required_qualifier_terms: vec!["alpha".to_string(), "beta".to_string()],
            allowed_surfaces: vec!["docs".to_string()],
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let restored: ClaimClassSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, spec);
    }

    #[test]
    fn contract_track_serde_round_trip() {
        let track = ContractTrack {
            id: "RGC-016C".to_string(),
            name: "claim envelope".to_string(),
        };
        let json = serde_json::to_string(&track).expect("serialize");
        let restored: ContractTrack = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, track);
    }

    #[test]
    fn tier_debug_format() {
        assert_eq!(
            format!("{:?}", ClaimEnvelopeTier::FrontierObjective),
            "FrontierObjective"
        );
        assert_eq!(
            format!("{:?}", ClaimEnvelopeTier::PublishableUniversal),
            "PublishableUniversal"
        );
    }

    #[test]
    fn verdict_debug_format() {
        assert_eq!(
            format!("{:?}", ClaimEnvelopeVerdict::AllowRequested),
            "AllowRequested"
        );
        assert_eq!(format!("{:?}", ClaimEnvelopeVerdict::Forbid), "Forbid");
    }

    #[test]
    fn contract_clone_is_independent() {
        let contract = minimal_contract();
        let mut cloned = contract.clone();
        cloned.schema_version = "modified".to_string();
        assert_ne!(contract.schema_version, cloned.schema_version);
        assert_eq!(
            contract.schema_version,
            CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION
        );
    }

    #[test]
    fn evaluate_universal_stale_but_all_else_ready_downgrades_to_hypothesis() {
        let contract = minimal_contract();
        let mut scenario =
            scenario_all_ready(ClaimEnvelopeTier::PublishableUniversal, "universal claim");
        scenario.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS + 100;
        // All other flags are true, but contract_is_fresh is false.
        // publishable_scoped_ready requires contract_is_fresh, so it's false.
        // Falls through to DowngradeToHypothesis.
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToHypothesis
        );
    }

    #[test]
    fn evaluate_scoped_stale_but_all_else_ready_downgrades_to_hypothesis() {
        let contract = minimal_contract();
        let mut scenario = scenario_all_ready(ClaimEnvelopeTier::PublishableScoped, "scoped claim");
        scenario.stale_contract_hours = MAX_PUBLISHABLE_STALENESS_HOURS + 1;
        // contract_is_fresh is false, so publishable_scoped_ready is false,
        // and contract_is_fresh branch also false -> DowngradeToHypothesis
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToHypothesis
        );
    }

    #[test]
    fn validate_consumer_channel_with_all_unknown_classes() {
        let mut contract = minimal_contract();
        contract.consumer_channels = vec![ConsumerChannel {
            channel_id: "bad-ch".to_string(),
            consumer_bead: "bd-x".to_string(),
            allowed_classes: vec!["fake1".to_string(), "fake2".to_string()],
            requires_artifacts: vec![],
            rationale: "test".to_string(),
        }];
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("fake1")));
        assert!(errors.iter().any(|e| e.contains("fake2")));
    }

    #[test]
    fn validate_consumer_channel_empty_allowed_classes_passes() {
        let mut contract = minimal_contract();
        contract.consumer_channels = vec![ConsumerChannel {
            channel_id: "empty-ch".to_string(),
            consumer_bead: "bd-y".to_string(),
            allowed_classes: vec![],
            requires_artifacts: vec![],
            rationale: "test".to_string(),
        }];
        // Empty allowed_classes does not reference any unknown class, so no error from that check.
        contract.validate().expect("should pass");
    }

    #[test]
    fn validate_no_consumer_channels_passes() {
        let mut contract = minimal_contract();
        contract.consumer_channels.clear();
        contract.validate().expect("no channels is still valid");
    }

    #[test]
    fn validate_no_downgrade_rules_passes() {
        let mut contract = minimal_contract();
        contract.downgrade_rules.clear();
        contract
            .validate()
            .expect("no downgrade rules is still valid");
    }

    #[test]
    fn tier_copy_semantics() {
        let tier = ClaimEnvelopeTier::PublishableUniversal;
        let copied = tier;
        assert_eq!(tier, copied);
    }

    #[test]
    fn verdict_copy_semantics() {
        let verdict = ClaimEnvelopeVerdict::DowngradeToScoped;
        let copied = verdict;
        assert_eq!(verdict, copied);
    }

    #[test]
    fn evaluate_universal_all_flags_false_downgrades_to_hypothesis_when_stale() {
        let contract = minimal_contract();
        let scenario = ClaimEnvelopeScenario {
            scenario_id: "all-false".to_string(),
            requested_class: ClaimEnvelopeTier::PublishableUniversal,
            phrase_text: "universal claim".to_string(),
            declared_scope_complete: false,
            declared_board_complete: false,
            evidence_complete: false,
            shipped_path: false,
            frontier_gap_open: true,
            stale_contract_hours: MAX_PUBLISHABLE_STALENESS_HOURS + 1,
            replay_command: "none".to_string(),
        };
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToHypothesis
        );
    }

    #[test]
    fn evaluate_universal_all_flags_false_but_fresh_downgrades_to_target() {
        let contract = minimal_contract();
        let scenario = ClaimEnvelopeScenario {
            scenario_id: "fresh-but-incomplete".to_string(),
            requested_class: ClaimEnvelopeTier::PublishableUniversal,
            phrase_text: "universal claim".to_string(),
            declared_scope_complete: false,
            declared_board_complete: false,
            evidence_complete: false,
            shipped_path: false,
            frontier_gap_open: true,
            stale_contract_hours: 0,
            replay_command: "none".to_string(),
        };
        assert_eq!(
            contract.evaluate(&scenario),
            ClaimEnvelopeVerdict::DowngradeToTarget
        );
    }

    #[test]
    fn embedded_contract_json_is_nonempty() {
        assert!(
            !CLAIM_ENVELOPE_CONTRACT_JSON.is_empty(),
            "embedded contract JSON should not be empty"
        );
    }

    #[test]
    fn embedded_contract_json_parses_as_valid_json() {
        let value: serde_json::Value =
            serde_json::from_str(CLAIM_ENVELOPE_CONTRACT_JSON).expect("should parse as JSON");
        assert!(value.is_object(), "top-level must be a JSON object");
    }
}
