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
