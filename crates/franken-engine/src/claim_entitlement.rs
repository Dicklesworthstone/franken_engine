#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

pub const CLAIM_ENTITLEMENT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-claim-entitlement-algebra.v1";
pub const CLAIM_ENTITLEMENT_COMPONENT: &str = "rgc_claim_entitlement_algebra";
pub const CLAIM_ENTITLEMENT_POLICY_ID: &str = "policy-rgc-claim-entitlement-algebra-v1";
pub const CLAIM_ENTITLEMENT_CONTRACT_JSON: &str =
    include_str!("../../../docs/rgc_claim_entitlement_algebra_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimEntitlementContract {
    pub schema_version: String,
    pub contract_version: String,
    pub bead_id: String,
    pub generated_by: String,
    pub generated_at_utc: String,
    pub track: ContractTrack,
    pub required_artifacts: Vec<String>,
    pub required_structured_log_fields: Vec<String>,
    pub claim_atom_catalog: ClaimAtomCatalog,
    pub evidence_morphism_catalog: EvidenceMorphismCatalog,
    pub side_constraint_lattice: SideConstraintLattice,
    pub disqualifier_rules: DisqualifierRuleSet,
    pub operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractTrack {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAtomCatalog {
    pub schema_version: String,
    pub atoms: Vec<ClaimAtom>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAtom {
    pub atom_id: String,
    pub domain: ClaimDomain,
    pub tier: ClaimTier,
    pub statement_class: String,
    pub surface: String,
    pub description: String,
    pub source_documents: Vec<String>,
    pub owning_beads: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimDomain {
    Compatibility,
    ShippedSurface,
    React,
    Supremacy,
    Rollout,
    Ga,
    SupportSurface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimTier {
    ShippedFact,
    ScopedObserved,
    FrontierAmbition,
    UnsupportedSurface,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceMorphismCatalog {
    pub schema_version: String,
    pub morphisms: Vec<EvidenceMorphism>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceMorphism {
    pub morphism_id: String,
    pub evidence_kind: String,
    pub effect: MorphismEffect,
    pub target_atoms: Vec<String>,
    pub requires_side_constraints: Vec<String>,
    pub blocked_by_rules: Vec<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphismEffect {
    Supports,
    Constrains,
    Disqualifies,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideConstraintLattice {
    pub schema_version: String,
    pub top_constraint_id: String,
    pub bottom_constraint_id: String,
    pub constraints: Vec<SideConstraint>,
    pub cover_relations: Vec<ConstraintRelation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideConstraint {
    pub constraint_id: String,
    pub constraint_class: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintRelation {
    pub lower_constraint_id: String,
    pub higher_constraint_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisqualifierRuleSet {
    pub schema_version: String,
    pub precedence_order: Vec<String>,
    pub rules: Vec<DisqualifierRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisqualifierRule {
    pub rule_id: String,
    pub precedence: u64,
    pub evidence_kind: String,
    pub condition: String,
    pub target_atoms: Vec<String>,
    pub verdict: DisqualifierVerdict,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisqualifierVerdict {
    Forbid,
    DowngradeToScoped,
    DowngradeToTarget,
    RequireOperatorGuidance,
}

impl ClaimEntitlementContract {
    pub fn from_embedded_json() -> Self {
        serde_json::from_str(CLAIM_ENTITLEMENT_CONTRACT_JSON)
            .expect("embedded claim entitlement contract must parse")
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != CLAIM_ENTITLEMENT_SCHEMA_VERSION {
            errors.push(format!(
                "unexpected schema_version `{}`",
                self.schema_version
            ));
        }

        if self.track.id != "RGC-017" {
            errors.push(format!("unexpected track id `{}`", self.track.id));
        }

        let atom_ids = collect_unique_ids(
            self.claim_atom_catalog
                .atoms
                .iter()
                .map(|atom| atom.atom_id.as_str()),
            "claim atom",
            &mut errors,
        );
        let constraint_ids = collect_unique_ids(
            self.side_constraint_lattice
                .constraints
                .iter()
                .map(|constraint| constraint.constraint_id.as_str()),
            "side constraint",
            &mut errors,
        );
        let rule_ids = collect_unique_ids(
            self.disqualifier_rules
                .rules
                .iter()
                .map(|rule| rule.rule_id.as_str()),
            "disqualifier rule",
            &mut errors,
        );

        collect_unique_ids(
            self.evidence_morphism_catalog
                .morphisms
                .iter()
                .map(|morphism| morphism.morphism_id.as_str()),
            "evidence morphism",
            &mut errors,
        );

        if !constraint_ids.contains(self.side_constraint_lattice.top_constraint_id.as_str()) {
            errors.push(format!(
                "top constraint `{}` is missing from constraint catalog",
                self.side_constraint_lattice.top_constraint_id
            ));
        }
        if !constraint_ids.contains(self.side_constraint_lattice.bottom_constraint_id.as_str()) {
            errors.push(format!(
                "bottom constraint `{}` is missing from constraint catalog",
                self.side_constraint_lattice.bottom_constraint_id
            ));
        }

        let has_shipped_fact = self
            .claim_atom_catalog
            .atoms
            .iter()
            .any(|atom| atom.tier == ClaimTier::ShippedFact);
        let has_frontier = self
            .claim_atom_catalog
            .atoms
            .iter()
            .any(|atom| atom.tier == ClaimTier::FrontierAmbition);
        let has_unsupported = self
            .claim_atom_catalog
            .atoms
            .iter()
            .any(|atom| atom.tier == ClaimTier::UnsupportedSurface);

        if !has_shipped_fact {
            errors.push("missing shipped_fact claim atoms".to_string());
        }
        if !has_frontier {
            errors.push("missing frontier_ambition claim atoms".to_string());
        }
        if !has_unsupported {
            errors.push("missing unsupported_surface claim atoms".to_string());
        }

        for morphism in &self.evidence_morphism_catalog.morphisms {
            for atom_id in &morphism.target_atoms {
                if !atom_ids.contains(atom_id.as_str()) {
                    errors.push(format!(
                        "morphism `{}` references unknown atom `{}`",
                        morphism.morphism_id, atom_id
                    ));
                }
            }
            for constraint_id in &morphism.requires_side_constraints {
                if !constraint_ids.contains(constraint_id.as_str()) {
                    errors.push(format!(
                        "morphism `{}` references unknown side constraint `{}`",
                        morphism.morphism_id, constraint_id
                    ));
                }
            }
            for rule_id in &morphism.blocked_by_rules {
                if !rule_ids.contains(rule_id.as_str()) {
                    errors.push(format!(
                        "morphism `{}` references unknown disqualifier rule `{}`",
                        morphism.morphism_id, rule_id
                    ));
                }
            }
        }

        for relation in &self.side_constraint_lattice.cover_relations {
            if !constraint_ids.contains(relation.lower_constraint_id.as_str()) {
                errors.push(format!(
                    "cover relation references unknown lower constraint `{}`",
                    relation.lower_constraint_id
                ));
            }
            if !constraint_ids.contains(relation.higher_constraint_id.as_str()) {
                errors.push(format!(
                    "cover relation references unknown higher constraint `{}`",
                    relation.higher_constraint_id
                ));
            }
            if relation.lower_constraint_id == relation.higher_constraint_id {
                errors.push(format!(
                    "cover relation `{}` is self-referential",
                    relation.lower_constraint_id
                ));
            }
        }

        if lattice_has_cycle(&self.side_constraint_lattice) {
            errors.push("side-constraint lattice contains a cycle".to_string());
        }

        let mut precedence_values = BTreeSet::new();
        for rule in &self.disqualifier_rules.rules {
            if !precedence_values.insert(rule.precedence) {
                errors.push(format!(
                    "duplicate disqualifier precedence `{}`",
                    rule.precedence
                ));
            }
            for atom_id in &rule.target_atoms {
                if !atom_ids.contains(atom_id.as_str()) {
                    errors.push(format!(
                        "disqualifier rule `{}` references unknown atom `{}`",
                        rule.rule_id, atom_id
                    ));
                }
            }
        }

        let precedence_order = self
            .disqualifier_rules
            .rules
            .iter()
            .map(|rule| (rule.precedence, rule.rule_id.as_str()))
            .collect::<BTreeMap<_, _>>();
        let expected_precedence_order = precedence_order
            .values()
            .map(|rule_id| (*rule_id).to_string())
            .collect::<Vec<_>>();
        if self.disqualifier_rules.precedence_order != expected_precedence_order {
            errors.push("precedence_order does not match numeric rule precedence".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn collect_unique_ids<'a, I>(items: I, label: &str, errors: &mut Vec<String>) -> BTreeSet<&'a str>
where
    I: Iterator<Item = &'a str>,
{
    let mut ids = BTreeSet::new();
    for id in items {
        if !ids.insert(id) {
            errors.push(format!("duplicate {label} id `{id}`"));
        }
    }
    ids
}

fn lattice_has_cycle(lattice: &SideConstraintLattice) -> bool {
    let mut indegree = lattice
        .constraints
        .iter()
        .map(|constraint| (constraint.constraint_id.clone(), 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut adjacency = lattice
        .constraints
        .iter()
        .map(|constraint| (constraint.constraint_id.clone(), Vec::<String>::new()))
        .collect::<BTreeMap<_, _>>();

    for relation in &lattice.cover_relations {
        if let Some(outgoing) = adjacency.get_mut(&relation.lower_constraint_id) {
            outgoing.push(relation.higher_constraint_id.clone());
        }
        if let Some(count) = indegree.get_mut(&relation.higher_constraint_id) {
            *count += 1;
        }
    }

    let mut queue = indegree
        .iter()
        .filter_map(|(constraint_id, degree)| {
            if *degree == 0 {
                Some(constraint_id.clone())
            } else {
                None
            }
        })
        .collect::<VecDeque<_>>();

    let mut visited = 0usize;
    while let Some(constraint_id) = queue.pop_front() {
        visited += 1;
        if let Some(outgoing) = adjacency.get(&constraint_id) {
            for next_id in outgoing {
                if let Some(next_degree) = indegree.get_mut(next_id) {
                    *next_degree -= 1;
                    if *next_degree == 0 {
                        queue.push_back(next_id.clone());
                    }
                }
            }
        }
    }

    visited != lattice.constraints.len()
}
