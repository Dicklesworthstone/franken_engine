#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

pub const CLAIM_ENTITLEMENT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-claim-entitlement-algebra.v1";
pub const CLAIM_ENTITLEMENT_COMPONENT: &str = "rgc_claim_entitlement_algebra";
pub const CLAIM_ENTITLEMENT_POLICY_ID: &str = "policy-rgc-claim-entitlement-algebra-v1";
pub const CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION: &str =
    "franken-engine.rgc-claim-entitlement-scenarios.v1";
pub const CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-claim-entitlement-report.v1";
pub const CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION: &str =
    "franken-engine.rgc-claim-entitlement-cutsets.v1";
pub const CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION: &str =
    "franken-engine.rgc-claim-entitlement-impossibility.v1";
pub const CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION: &str =
    "franken-engine.rgc-claim-counterexample-ledger.v1";
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Fresh,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimEvaluationScenarioSet {
    pub schema_version: String,
    pub scenario_version: String,
    pub scenarios: Vec<ClaimEvaluationScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimEvaluationScenario {
    pub scenario_id: String,
    pub description: String,
    pub evaluated_at_utc: String,
    pub observed_evidence: Vec<ObservedEvidence>,
    pub satisfied_constraints: Vec<String>,
    pub expected_outcomes: Vec<ExpectedClaimOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedEvidence {
    pub evidence_kind: String,
    pub state: EvidenceState,
    pub triggered_rule_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedClaimOutcome {
    pub atom_id: String,
    pub state: ClaimVerdictState,
    pub minimal_morphism_id: Option<String>,
    pub impossible_rule_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerdictState {
    Entitled,
    NotYetProven,
    BlockedByMissingEvidence,
    CurrentlyFalseUnderActiveCounterexample,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimEvaluationOutputs {
    pub claim_entitlement_report: ClaimEntitlementReport,
    pub missing_evidence_cutsets: MissingEvidenceCutsetReport,
    pub impossibility_certificates: ImpossibilityCertificateReport,
    pub claim_counterexample_ledger: ClaimCounterexampleLedger,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimEntitlementReport {
    pub schema_version: String,
    pub contract_version: String,
    pub evaluated_scenarios: Vec<ScenarioVerdictReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioVerdictReport {
    pub scenario_id: String,
    pub evaluated_at_utc: String,
    pub verdicts: Vec<ClaimVerdict>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimVerdict {
    pub atom_id: String,
    pub state: ClaimVerdictState,
    pub supporting_morphism_ids: Vec<String>,
    pub active_rule_ids: Vec<String>,
    pub minimal_cutset_ids: Vec<String>,
    pub impossibility_certificate_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingEvidenceCutsetReport {
    pub schema_version: String,
    pub contract_version: String,
    pub evaluated_scenarios: Vec<ScenarioMissingEvidenceCutsets>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioMissingEvidenceCutsets {
    pub scenario_id: String,
    pub cutsets: Vec<MissingEvidenceCutset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingEvidenceCutset {
    pub cutset_id: String,
    pub atom_id: String,
    pub supporting_morphism_id: String,
    pub missing_evidence_kinds: Vec<String>,
    pub missing_constraint_ids: Vec<String>,
    pub blocking_rule_ids: Vec<String>,
    pub cost: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpossibilityCertificateReport {
    pub schema_version: String,
    pub contract_version: String,
    pub evaluated_scenarios: Vec<ScenarioImpossibilityCertificates>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioImpossibilityCertificates {
    pub scenario_id: String,
    pub certificates: Vec<ImpossibilityCertificate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpossibilityCertificate {
    pub certificate_id: String,
    pub atom_id: String,
    pub blocking_rule_id: String,
    pub evidence_kind: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimCounterexampleLedger {
    pub schema_version: String,
    pub contract_version: String,
    pub evaluated_scenarios: Vec<ScenarioCounterexampleLedger>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioCounterexampleLedger {
    pub scenario_id: String,
    pub entries: Vec<CounterexampleLedgerEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterexampleLedgerEntry {
    pub entry_id: String,
    pub atom_id: String,
    pub blocking_rule_id: String,
    pub evidence_kind: String,
    pub remediation: String,
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

    pub fn evaluate_scenarios(
        &self,
        scenarios: &ClaimEvaluationScenarioSet,
    ) -> Result<ClaimEvaluationOutputs, Vec<String>> {
        let mut errors = Vec::new();
        if let Err(validation_errors) = self.validate() {
            errors.extend(validation_errors);
        }

        let atom_ids = self
            .claim_atom_catalog
            .atoms
            .iter()
            .map(|atom| atom.atom_id.as_str())
            .collect::<BTreeSet<_>>();
        let morphism_ids = self
            .evidence_morphism_catalog
            .morphisms
            .iter()
            .map(|morphism| morphism.morphism_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut evidence_kinds: BTreeSet<&str> = self
            .evidence_morphism_catalog
            .morphisms
            .iter()
            .map(|morphism| morphism.evidence_kind.as_str())
            .collect();
        for rule in &self.disqualifier_rules.rules {
            evidence_kinds.insert(rule.evidence_kind.as_str());
        }
        let constraint_ids = self
            .side_constraint_lattice
            .constraints
            .iter()
            .map(|constraint| constraint.constraint_id.as_str())
            .collect::<BTreeSet<_>>();
        let rule_lookup = self
            .disqualifier_rules
            .rules
            .iter()
            .map(|rule| (rule.rule_id.as_str(), rule))
            .collect::<BTreeMap<_, _>>();

        if scenarios.schema_version != CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION {
            errors.push(format!(
                "unexpected scenario schema_version `{}`",
                scenarios.schema_version
            ));
        }

        let mut scenario_ids = BTreeSet::new();
        for scenario in &scenarios.scenarios {
            if !scenario_ids.insert(scenario.scenario_id.as_str()) {
                errors.push(format!("duplicate scenario id `{}`", scenario.scenario_id));
            }

            for evidence in &scenario.observed_evidence {
                if !evidence_kinds.contains(evidence.evidence_kind.as_str()) {
                    errors.push(format!(
                        "scenario `{}` references unknown evidence_kind `{}`",
                        scenario.scenario_id, evidence.evidence_kind
                    ));
                }
                for rule_id in &evidence.triggered_rule_ids {
                    if !rule_lookup.contains_key(rule_id.as_str()) {
                        errors.push(format!(
                            "scenario `{}` triggers unknown rule `{}`",
                            scenario.scenario_id, rule_id
                        ));
                    }
                }
            }

            for constraint_id in &scenario.satisfied_constraints {
                if !constraint_ids.contains(constraint_id.as_str()) {
                    errors.push(format!(
                        "scenario `{}` references unknown satisfied constraint `{}`",
                        scenario.scenario_id, constraint_id
                    ));
                }
            }

            for expected in &scenario.expected_outcomes {
                if !atom_ids.contains(expected.atom_id.as_str()) {
                    errors.push(format!(
                        "scenario `{}` references unknown expected atom `{}`",
                        scenario.scenario_id, expected.atom_id
                    ));
                }
                if let Some(morphism_id) = expected.minimal_morphism_id.as_deref()
                    && !morphism_ids.contains(morphism_id)
                {
                    errors.push(format!(
                        "scenario `{}` references unknown expected morphism `{}`",
                        scenario.scenario_id, morphism_id
                    ));
                }
                if let Some(rule_id) = expected.impossible_rule_id.as_deref()
                    && !rule_lookup.contains_key(rule_id)
                {
                    errors.push(format!(
                        "scenario `{}` references unknown expected rule `{}`",
                        scenario.scenario_id, rule_id
                    ));
                }
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        let target_morphisms = self
            .claim_atom_catalog
            .atoms
            .iter()
            .map(|atom| {
                let morphisms = self
                    .evidence_morphism_catalog
                    .morphisms
                    .iter()
                    .filter(|morphism| {
                        morphism.effect != MorphismEffect::Disqualifies
                            && morphism.target_atoms.contains(&atom.atom_id)
                    })
                    .collect::<Vec<_>>();
                (atom.atom_id.as_str(), morphisms)
            })
            .collect::<BTreeMap<_, _>>();

        let mut scenario_reports = Vec::new();
        let mut scenario_cutsets = Vec::new();
        let mut scenario_certificates = Vec::new();
        let mut scenario_ledgers = Vec::new();

        for scenario in &scenarios.scenarios {
            let fresh_evidence = scenario
                .observed_evidence
                .iter()
                .filter(|evidence| evidence.state == EvidenceState::Fresh)
                .map(|evidence| evidence.evidence_kind.as_str())
                .collect::<BTreeSet<_>>();
            let observed_evidence = scenario
                .observed_evidence
                .iter()
                .map(|evidence| evidence.evidence_kind.as_str())
                .collect::<BTreeSet<_>>();
            let satisfied_constraints = scenario
                .satisfied_constraints
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let active_rule_ids = scenario
                .observed_evidence
                .iter()
                .flat_map(|evidence| evidence.triggered_rule_ids.iter().map(String::as_str))
                .collect::<BTreeSet<_>>();

            let mut verdicts = Vec::new();
            let mut cutsets = Vec::new();
            let mut certificates = Vec::new();
            let mut counterexample_entries = Vec::new();

            for atom in &self.claim_atom_catalog.atoms {
                let forbidding_rules = self
                    .disqualifier_rules
                    .rules
                    .iter()
                    .filter(|rule| {
                        active_rule_ids.contains(rule.rule_id.as_str())
                            && rule.verdict == DisqualifierVerdict::Forbid
                            && rule.target_atoms.contains(&atom.atom_id)
                    })
                    .collect::<Vec<_>>();

                if !forbidding_rules.is_empty() {
                    let certificate_ids = forbidding_rules
                        .iter()
                        .map(|rule| {
                            format!(
                                "{}::{}::{}",
                                scenario.scenario_id, atom.atom_id, rule.rule_id
                            )
                        })
                        .collect::<Vec<_>>();

                    for rule in &forbidding_rules {
                        let certificate_id = format!(
                            "{}::{}::{}",
                            scenario.scenario_id, atom.atom_id, rule.rule_id
                        );
                        certificates.push(ImpossibilityCertificate {
                            certificate_id: certificate_id.clone(),
                            atom_id: atom.atom_id.clone(),
                            blocking_rule_id: rule.rule_id.clone(),
                            evidence_kind: rule.evidence_kind.clone(),
                            remediation: rule.remediation.clone(),
                        });
                        counterexample_entries.push(CounterexampleLedgerEntry {
                            entry_id: certificate_id,
                            atom_id: atom.atom_id.clone(),
                            blocking_rule_id: rule.rule_id.clone(),
                            evidence_kind: rule.evidence_kind.clone(),
                            remediation: rule.remediation.clone(),
                        });
                    }

                    verdicts.push(ClaimVerdict {
                        atom_id: atom.atom_id.clone(),
                        state: ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample,
                        supporting_morphism_ids: Vec::new(),
                        active_rule_ids: forbidding_rules
                            .iter()
                            .map(|rule| rule.rule_id.clone())
                            .collect(),
                        minimal_cutset_ids: Vec::new(),
                        impossibility_certificate_ids: certificate_ids,
                    });
                    continue;
                }

                let atom_morphisms = target_morphisms
                    .get(atom.atom_id.as_str())
                    .cloned()
                    .unwrap_or_default();

                let satisfying_morphisms = atom_morphisms
                    .iter()
                    .filter(|morphism| {
                        fresh_evidence.contains(morphism.evidence_kind.as_str())
                            && morphism
                                .requires_side_constraints
                                .iter()
                                .all(|constraint_id| {
                                    satisfied_constraints.contains(constraint_id.as_str())
                                })
                            && morphism.blocked_by_rules.iter().all(|rule_id| {
                                !active_rule_ids.contains(rule_id.as_str())
                                    || rule_lookup.get(rule_id.as_str()).is_some_and(|rule| {
                                        rule.verdict == DisqualifierVerdict::Forbid
                                    })
                            })
                    })
                    .map(|morphism| morphism.morphism_id.clone())
                    .collect::<Vec<_>>();

                if !satisfying_morphisms.is_empty() {
                    verdicts.push(ClaimVerdict {
                        atom_id: atom.atom_id.clone(),
                        state: ClaimVerdictState::Entitled,
                        supporting_morphism_ids: satisfying_morphisms,
                        active_rule_ids: Vec::new(),
                        minimal_cutset_ids: Vec::new(),
                        impossibility_certificate_ids: Vec::new(),
                    });
                    continue;
                }

                let mut candidates = atom_morphisms
                    .iter()
                    .map(|morphism| {
                        let missing_evidence_kinds =
                            if fresh_evidence.contains(morphism.evidence_kind.as_str()) {
                                Vec::new()
                            } else {
                                vec![morphism.evidence_kind.clone()]
                            };
                        let missing_constraint_ids = morphism
                            .requires_side_constraints
                            .iter()
                            .filter(|constraint_id| {
                                !satisfied_constraints.contains(constraint_id.as_str())
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        let blocking_rule_ids = morphism
                            .blocked_by_rules
                            .iter()
                            .filter(|rule_id| active_rule_ids.contains(rule_id.as_str()))
                            .filter(|rule_id| {
                                rule_lookup
                                    .get(rule_id.as_str())
                                    .is_some_and(|rule| rule.verdict != DisqualifierVerdict::Forbid)
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        MissingEvidenceCutset {
                            cutset_id: format!(
                                "{}::{}::{}",
                                scenario.scenario_id, atom.atom_id, morphism.morphism_id
                            ),
                            atom_id: atom.atom_id.clone(),
                            supporting_morphism_id: morphism.morphism_id.clone(),
                            cost: missing_evidence_kinds.len()
                                + missing_constraint_ids.len()
                                + blocking_rule_ids.len(),
                            missing_evidence_kinds,
                            missing_constraint_ids,
                            blocking_rule_ids,
                        }
                    })
                    .collect::<Vec<_>>();
                candidates.sort_by(|left, right| {
                    (
                        left.cost,
                        left.supporting_morphism_id.as_str(),
                        left.atom_id.as_str(),
                    )
                        .cmp(&(
                            right.cost,
                            right.supporting_morphism_id.as_str(),
                            right.atom_id.as_str(),
                        ))
                });

                let minimal_cost = candidates
                    .first()
                    .map(|candidate| candidate.cost)
                    .unwrap_or(0);
                let minimal_candidates = candidates
                    .into_iter()
                    .filter(|candidate| candidate.cost == minimal_cost)
                    .collect::<Vec<_>>();
                let minimal_cutset_ids = minimal_candidates
                    .iter()
                    .map(|candidate| candidate.cutset_id.clone())
                    .collect::<Vec<_>>();
                let active_rule_ids = minimal_candidates
                    .iter()
                    .flat_map(|candidate| candidate.blocking_rule_ids.iter().cloned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let has_partial_signal = atom_morphisms
                    .iter()
                    .any(|morphism| observed_evidence.contains(morphism.evidence_kind.as_str()));

                cutsets.extend(minimal_candidates);
                verdicts.push(ClaimVerdict {
                    atom_id: atom.atom_id.clone(),
                    state: if has_partial_signal {
                        ClaimVerdictState::BlockedByMissingEvidence
                    } else {
                        ClaimVerdictState::NotYetProven
                    },
                    supporting_morphism_ids: Vec::new(),
                    active_rule_ids,
                    minimal_cutset_ids,
                    impossibility_certificate_ids: Vec::new(),
                });
            }

            scenario_reports.push(ScenarioVerdictReport {
                scenario_id: scenario.scenario_id.clone(),
                evaluated_at_utc: scenario.evaluated_at_utc.clone(),
                verdicts,
            });
            scenario_cutsets.push(ScenarioMissingEvidenceCutsets {
                scenario_id: scenario.scenario_id.clone(),
                cutsets,
            });
            scenario_certificates.push(ScenarioImpossibilityCertificates {
                scenario_id: scenario.scenario_id.clone(),
                certificates,
            });
            scenario_ledgers.push(ScenarioCounterexampleLedger {
                scenario_id: scenario.scenario_id.clone(),
                entries: counterexample_entries,
            });
        }

        Ok(ClaimEvaluationOutputs {
            claim_entitlement_report: ClaimEntitlementReport {
                schema_version: CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION.to_string(),
                contract_version: self.contract_version.clone(),
                evaluated_scenarios: scenario_reports,
            },
            missing_evidence_cutsets: MissingEvidenceCutsetReport {
                schema_version: CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION.to_string(),
                contract_version: self.contract_version.clone(),
                evaluated_scenarios: scenario_cutsets,
            },
            impossibility_certificates: ImpossibilityCertificateReport {
                schema_version: CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION.to_string(),
                contract_version: self.contract_version.clone(),
                evaluated_scenarios: scenario_certificates,
            },
            claim_counterexample_ledger: ClaimCounterexampleLedger {
                schema_version: CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION.to_string(),
                contract_version: self.contract_version.clone(),
                evaluated_scenarios: scenario_ledgers,
            },
        })
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

pub fn lattice_has_cycle(lattice: &SideConstraintLattice) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_contract() -> ClaimEntitlementContract {
        ClaimEntitlementContract {
            schema_version: CLAIM_ENTITLEMENT_SCHEMA_VERSION.to_string(),
            contract_version: "v1-test".to_string(),
            bead_id: "bd-test".to_string(),
            generated_by: "test".to_string(),
            generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            track: ContractTrack {
                id: "RGC-017".to_string(),
                name: "test track".to_string(),
            },
            required_artifacts: vec!["artifact-a".to_string()],
            required_structured_log_fields: vec!["field-a".to_string()],
            claim_atom_catalog: ClaimAtomCatalog {
                schema_version: "v1".to_string(),
                atoms: vec![
                    ClaimAtom {
                        atom_id: "atom-shipped".to_string(),
                        domain: ClaimDomain::Compatibility,
                        tier: ClaimTier::ShippedFact,
                        statement_class: "class-a".to_string(),
                        surface: "docs".to_string(),
                        description: "shipped fact atom".to_string(),
                        source_documents: vec![],
                        owning_beads: vec![],
                    },
                    ClaimAtom {
                        atom_id: "atom-frontier".to_string(),
                        domain: ClaimDomain::Supremacy,
                        tier: ClaimTier::FrontierAmbition,
                        statement_class: "class-b".to_string(),
                        surface: "supremacy".to_string(),
                        description: "frontier atom".to_string(),
                        source_documents: vec![],
                        owning_beads: vec![],
                    },
                    ClaimAtom {
                        atom_id: "atom-unsupported".to_string(),
                        domain: ClaimDomain::SupportSurface,
                        tier: ClaimTier::UnsupportedSurface,
                        statement_class: "class-c".to_string(),
                        surface: "advisory".to_string(),
                        description: "unsupported surface atom".to_string(),
                        source_documents: vec![],
                        owning_beads: vec![],
                    },
                ],
            },
            evidence_morphism_catalog: EvidenceMorphismCatalog {
                schema_version: "v1".to_string(),
                morphisms: vec![EvidenceMorphism {
                    morphism_id: "morph-compat".to_string(),
                    evidence_kind: "compatibility_test_suite".to_string(),
                    effect: MorphismEffect::Supports,
                    target_atoms: vec!["atom-shipped".to_string()],
                    requires_side_constraints: vec!["constraint-top".to_string()],
                    blocked_by_rules: vec![],
                    rationale: "test suite evidence".to_string(),
                }],
            },
            side_constraint_lattice: SideConstraintLattice {
                schema_version: "v1".to_string(),
                top_constraint_id: "constraint-top".to_string(),
                bottom_constraint_id: "constraint-bottom".to_string(),
                constraints: vec![
                    SideConstraint {
                        constraint_id: "constraint-top".to_string(),
                        constraint_class: "universal".to_string(),
                        description: "top constraint".to_string(),
                    },
                    SideConstraint {
                        constraint_id: "constraint-bottom".to_string(),
                        constraint_class: "minimal".to_string(),
                        description: "bottom constraint".to_string(),
                    },
                ],
                cover_relations: vec![ConstraintRelation {
                    lower_constraint_id: "constraint-bottom".to_string(),
                    higher_constraint_id: "constraint-top".to_string(),
                }],
            },
            disqualifier_rules: DisqualifierRuleSet {
                schema_version: "v1".to_string(),
                precedence_order: vec!["rule-forbid".to_string()],
                rules: vec![DisqualifierRule {
                    rule_id: "rule-forbid".to_string(),
                    precedence: 1,
                    evidence_kind: "counterexample_suite".to_string(),
                    condition: "regression found".to_string(),
                    target_atoms: vec!["atom-shipped".to_string()],
                    verdict: DisqualifierVerdict::Forbid,
                    remediation: "fix the regression".to_string(),
                }],
            },
            operator_verification: vec!["check-a".to_string()],
        }
    }

    fn minimal_scenario_set() -> ClaimEvaluationScenarioSet {
        ClaimEvaluationScenarioSet {
            schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
            scenario_version: "v1".to_string(),
            scenarios: vec![ClaimEvaluationScenario {
                scenario_id: "scenario-happy".to_string(),
                description: "all evidence fresh".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![ObservedEvidence {
                    evidence_kind: "compatibility_test_suite".to_string(),
                    state: EvidenceState::Fresh,
                    triggered_rule_ids: vec![],
                }],
                satisfied_constraints: vec!["constraint-top".to_string()],
                expected_outcomes: vec![ExpectedClaimOutcome {
                    atom_id: "atom-shipped".to_string(),
                    state: ClaimVerdictState::Entitled,
                    minimal_morphism_id: Some("morph-compat".to_string()),
                    impossible_rule_id: None,
                }],
            }],
        }
    }

    #[test]
    fn schema_constants_nonempty() {
        assert!(!CLAIM_ENTITLEMENT_SCHEMA_VERSION.is_empty());
        assert!(!CLAIM_ENTITLEMENT_COMPONENT.is_empty());
        assert!(!CLAIM_ENTITLEMENT_POLICY_ID.is_empty());
        assert!(!CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.is_empty());
        assert!(!CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION.is_empty());
        assert!(!CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION.is_empty());
        assert!(!CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION.is_empty());
        assert!(!CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION.is_empty());
    }

    #[test]
    fn embedded_contract_loads() {
        let contract = ClaimEntitlementContract::from_embedded_json();
        assert_eq!(contract.schema_version, CLAIM_ENTITLEMENT_SCHEMA_VERSION);
        assert_eq!(contract.track.id, "RGC-017");
        assert!(!contract.claim_atom_catalog.atoms.is_empty());
        assert!(!contract.evidence_morphism_catalog.morphisms.is_empty());
    }

    #[test]
    fn embedded_contract_validates() {
        let contract = ClaimEntitlementContract::from_embedded_json();
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
        contract.schema_version = "wrong-version".to_string();
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
    fn validate_rejects_duplicate_atom_ids() {
        let mut contract = minimal_contract();
        let dup = contract.claim_atom_catalog.atoms[0].clone();
        contract.claim_atom_catalog.atoms.push(dup);
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("duplicate") && e.contains("claim atom")));
    }

    #[test]
    fn validate_rejects_missing_top_constraint() {
        let mut contract = minimal_contract();
        contract.side_constraint_lattice.top_constraint_id = "nonexistent".to_string();
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("top constraint")));
    }

    #[test]
    fn validate_rejects_missing_bottom_constraint() {
        let mut contract = minimal_contract();
        contract.side_constraint_lattice.bottom_constraint_id = "nonexistent".to_string();
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("bottom constraint")));
    }

    #[test]
    fn validate_rejects_morphism_referencing_unknown_atom() {
        let mut contract = minimal_contract();
        contract.evidence_morphism_catalog.morphisms[0]
            .target_atoms
            .push("atom-nonexistent".to_string());
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("unknown atom")));
    }

    #[test]
    fn validate_rejects_morphism_referencing_unknown_constraint() {
        let mut contract = minimal_contract();
        contract.evidence_morphism_catalog.morphisms[0]
            .requires_side_constraints
            .push("constraint-nonexistent".to_string());
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("unknown side constraint")));
    }

    #[test]
    fn validate_rejects_self_referential_cover_relation() {
        let mut contract = minimal_contract();
        contract
            .side_constraint_lattice
            .cover_relations
            .push(ConstraintRelation {
                lower_constraint_id: "constraint-top".to_string(),
                higher_constraint_id: "constraint-top".to_string(),
            });
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("self-referential")));
    }

    #[test]
    fn validate_rejects_duplicate_precedence() {
        let mut contract = minimal_contract();
        contract.disqualifier_rules.rules.push(DisqualifierRule {
            rule_id: "rule-dup".to_string(),
            precedence: 1,
            evidence_kind: "counterexample_suite".to_string(),
            condition: "dup".to_string(),
            target_atoms: vec!["atom-shipped".to_string()],
            verdict: DisqualifierVerdict::Forbid,
            remediation: "fix".to_string(),
        });
        contract
            .disqualifier_rules
            .precedence_order
            .push("rule-dup".to_string());
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("duplicate") && e.contains("precedence")));
    }

    #[test]
    fn validate_rejects_missing_shipped_fact_tier() {
        let mut contract = minimal_contract();
        contract
            .claim_atom_catalog
            .atoms
            .retain(|a| a.tier != ClaimTier::ShippedFact);
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("shipped_fact")));
    }

    #[test]
    fn validate_rejects_missing_frontier_tier() {
        let mut contract = minimal_contract();
        contract
            .claim_atom_catalog
            .atoms
            .retain(|a| a.tier != ClaimTier::FrontierAmbition);
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("frontier_ambition")));
    }

    #[test]
    fn validate_rejects_missing_unsupported_tier() {
        let mut contract = minimal_contract();
        contract
            .claim_atom_catalog
            .atoms
            .retain(|a| a.tier != ClaimTier::UnsupportedSurface);
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("unsupported_surface")));
    }

    #[test]
    fn lattice_cycle_detection_acyclic() {
        let lattice = SideConstraintLattice {
            schema_version: "v1".to_string(),
            top_constraint_id: "a".to_string(),
            bottom_constraint_id: "c".to_string(),
            constraints: vec![
                SideConstraint {
                    constraint_id: "a".to_string(),
                    constraint_class: "top".to_string(),
                    description: "".to_string(),
                },
                SideConstraint {
                    constraint_id: "b".to_string(),
                    constraint_class: "mid".to_string(),
                    description: "".to_string(),
                },
                SideConstraint {
                    constraint_id: "c".to_string(),
                    constraint_class: "bot".to_string(),
                    description: "".to_string(),
                },
            ],
            cover_relations: vec![
                ConstraintRelation {
                    lower_constraint_id: "c".to_string(),
                    higher_constraint_id: "b".to_string(),
                },
                ConstraintRelation {
                    lower_constraint_id: "b".to_string(),
                    higher_constraint_id: "a".to_string(),
                },
            ],
        };
        assert!(!lattice_has_cycle(&lattice));
    }

    #[test]
    fn lattice_cycle_detection_cyclic() {
        let lattice = SideConstraintLattice {
            schema_version: "v1".to_string(),
            top_constraint_id: "a".to_string(),
            bottom_constraint_id: "b".to_string(),
            constraints: vec![
                SideConstraint {
                    constraint_id: "a".to_string(),
                    constraint_class: "top".to_string(),
                    description: "".to_string(),
                },
                SideConstraint {
                    constraint_id: "b".to_string(),
                    constraint_class: "bot".to_string(),
                    description: "".to_string(),
                },
            ],
            cover_relations: vec![
                ConstraintRelation {
                    lower_constraint_id: "a".to_string(),
                    higher_constraint_id: "b".to_string(),
                },
                ConstraintRelation {
                    lower_constraint_id: "b".to_string(),
                    higher_constraint_id: "a".to_string(),
                },
            ],
        };
        assert!(lattice_has_cycle(&lattice));
    }

    #[test]
    fn evaluate_entitled_scenario() {
        let contract = minimal_contract();
        let scenarios = minimal_scenario_set();
        let outputs = contract.evaluate_scenarios(&scenarios).expect("should succeed");
        let verdicts = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
        let shipped = verdicts.iter().find(|v| v.atom_id == "atom-shipped").unwrap();
        assert_eq!(shipped.state, ClaimVerdictState::Entitled);
        assert!(shipped.supporting_morphism_ids.contains(&"morph-compat".to_string()));
    }

    #[test]
    fn evaluate_not_yet_proven_when_no_evidence() {
        let contract = minimal_contract();
        let scenarios = ClaimEvaluationScenarioSet {
            schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
            scenario_version: "v1".to_string(),
            scenarios: vec![ClaimEvaluationScenario {
                scenario_id: "no-evidence".to_string(),
                description: "no evidence".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![],
                satisfied_constraints: vec![],
                expected_outcomes: vec![],
            }],
        };
        let outputs = contract.evaluate_scenarios(&scenarios).expect("should succeed");
        let verdicts = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
        let shipped = verdicts.iter().find(|v| v.atom_id == "atom-shipped").unwrap();
        assert_eq!(shipped.state, ClaimVerdictState::NotYetProven);
    }

    #[test]
    fn evaluate_blocked_when_stale_evidence() {
        let contract = minimal_contract();
        let scenarios = ClaimEvaluationScenarioSet {
            schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
            scenario_version: "v1".to_string(),
            scenarios: vec![ClaimEvaluationScenario {
                scenario_id: "stale".to_string(),
                description: "stale evidence".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![ObservedEvidence {
                    evidence_kind: "compatibility_test_suite".to_string(),
                    state: EvidenceState::Stale,
                    triggered_rule_ids: vec![],
                }],
                satisfied_constraints: vec!["constraint-top".to_string()],
                expected_outcomes: vec![],
            }],
        };
        let outputs = contract.evaluate_scenarios(&scenarios).expect("should succeed");
        let verdicts = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
        let shipped = verdicts.iter().find(|v| v.atom_id == "atom-shipped").unwrap();
        assert_eq!(shipped.state, ClaimVerdictState::BlockedByMissingEvidence);
    }

    #[test]
    fn evaluate_counterexample_forbids_atom() {
        let contract = minimal_contract();
        let scenarios = ClaimEvaluationScenarioSet {
            schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
            scenario_version: "v1".to_string(),
            scenarios: vec![ClaimEvaluationScenario {
                scenario_id: "counterexample".to_string(),
                description: "forbid rule triggered".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![ObservedEvidence {
                    evidence_kind: "counterexample_suite".to_string(),
                    state: EvidenceState::Fresh,
                    triggered_rule_ids: vec!["rule-forbid".to_string()],
                }],
                satisfied_constraints: vec![],
                expected_outcomes: vec![],
            }],
        };
        let outputs = contract.evaluate_scenarios(&scenarios).expect("should succeed");
        let verdicts = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
        let shipped = verdicts.iter().find(|v| v.atom_id == "atom-shipped").unwrap();
        assert_eq!(
            shipped.state,
            ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample
        );
        assert!(shipped.active_rule_ids.contains(&"rule-forbid".to_string()));
        assert!(!shipped.impossibility_certificate_ids.is_empty());
    }

    #[test]
    fn evaluate_counterexample_produces_impossibility_certificate() {
        let contract = minimal_contract();
        let scenarios = ClaimEvaluationScenarioSet {
            schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
            scenario_version: "v1".to_string(),
            scenarios: vec![ClaimEvaluationScenario {
                scenario_id: "cx".to_string(),
                description: "forbid rule".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![ObservedEvidence {
                    evidence_kind: "counterexample_suite".to_string(),
                    state: EvidenceState::Fresh,
                    triggered_rule_ids: vec!["rule-forbid".to_string()],
                }],
                satisfied_constraints: vec![],
                expected_outcomes: vec![],
            }],
        };
        let outputs = contract.evaluate_scenarios(&scenarios).expect("should succeed");
        let certs = &outputs.impossibility_certificates.evaluated_scenarios[0].certificates;
        assert!(!certs.is_empty());
        assert_eq!(certs[0].blocking_rule_id, "rule-forbid");
        assert_eq!(certs[0].atom_id, "atom-shipped");
    }

    #[test]
    fn evaluate_counterexample_produces_ledger_entry() {
        let contract = minimal_contract();
        let scenarios = ClaimEvaluationScenarioSet {
            schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
            scenario_version: "v1".to_string(),
            scenarios: vec![ClaimEvaluationScenario {
                scenario_id: "cx-ledger".to_string(),
                description: "forbid rule".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![ObservedEvidence {
                    evidence_kind: "counterexample_suite".to_string(),
                    state: EvidenceState::Fresh,
                    triggered_rule_ids: vec!["rule-forbid".to_string()],
                }],
                satisfied_constraints: vec![],
                expected_outcomes: vec![],
            }],
        };
        let outputs = contract.evaluate_scenarios(&scenarios).expect("should succeed");
        let entries = &outputs
            .claim_counterexample_ledger
            .evaluated_scenarios[0]
            .entries;
        assert!(!entries.is_empty());
        assert_eq!(entries[0].blocking_rule_id, "rule-forbid");
    }

    #[test]
    fn evaluate_missing_constraint_produces_cutset() {
        let contract = minimal_contract();
        let scenarios = ClaimEvaluationScenarioSet {
            schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
            scenario_version: "v1".to_string(),
            scenarios: vec![ClaimEvaluationScenario {
                scenario_id: "missing-constraint".to_string(),
                description: "evidence present but constraint not satisfied".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![ObservedEvidence {
                    evidence_kind: "compatibility_test_suite".to_string(),
                    state: EvidenceState::Fresh,
                    triggered_rule_ids: vec![],
                }],
                satisfied_constraints: vec![],
                expected_outcomes: vec![],
            }],
        };
        let outputs = contract.evaluate_scenarios(&scenarios).expect("should succeed");
        let cutsets = &outputs.missing_evidence_cutsets.evaluated_scenarios[0].cutsets;
        let shipped_cutset = cutsets.iter().find(|c| c.atom_id == "atom-shipped");
        assert!(shipped_cutset.is_some());
        let cs = shipped_cutset.unwrap();
        assert!(cs.missing_constraint_ids.contains(&"constraint-top".to_string()));
    }

    #[test]
    fn evaluate_rejects_unknown_evidence_kind_in_scenario() {
        let contract = minimal_contract();
        let scenarios = ClaimEvaluationScenarioSet {
            schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
            scenario_version: "v1".to_string(),
            scenarios: vec![ClaimEvaluationScenario {
                scenario_id: "bad-evidence".to_string(),
                description: "unknown evidence kind".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![ObservedEvidence {
                    evidence_kind: "nonexistent_suite".to_string(),
                    state: EvidenceState::Fresh,
                    triggered_rule_ids: vec![],
                }],
                satisfied_constraints: vec![],
                expected_outcomes: vec![],
            }],
        };
        let errors = contract
            .evaluate_scenarios(&scenarios)
            .expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("unknown evidence_kind")));
    }

    #[test]
    fn evaluate_rejects_wrong_scenario_schema_version() {
        let contract = minimal_contract();
        let scenarios = ClaimEvaluationScenarioSet {
            schema_version: "wrong".to_string(),
            scenario_version: "v1".to_string(),
            scenarios: vec![],
        };
        let errors = contract
            .evaluate_scenarios(&scenarios)
            .expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("scenario schema_version")));
    }

    #[test]
    fn evaluate_output_schema_versions_correct() {
        let contract = minimal_contract();
        let scenarios = minimal_scenario_set();
        let outputs = contract.evaluate_scenarios(&scenarios).expect("should succeed");
        assert_eq!(
            outputs.claim_entitlement_report.schema_version,
            CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION
        );
        assert_eq!(
            outputs.missing_evidence_cutsets.schema_version,
            CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION
        );
        assert_eq!(
            outputs.impossibility_certificates.schema_version,
            CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION
        );
        assert_eq!(
            outputs.claim_counterexample_ledger.schema_version,
            CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION
        );
    }

    #[test]
    fn claim_domain_serde_round_trip() {
        for domain in [
            ClaimDomain::Compatibility,
            ClaimDomain::ShippedSurface,
            ClaimDomain::React,
            ClaimDomain::Supremacy,
            ClaimDomain::Rollout,
            ClaimDomain::Ga,
            ClaimDomain::SupportSurface,
        ] {
            let json = serde_json::to_string(&domain).expect("serialize");
            let restored: ClaimDomain = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, domain);
        }
    }

    #[test]
    fn claim_tier_serde_round_trip() {
        for tier in [
            ClaimTier::ShippedFact,
            ClaimTier::ScopedObserved,
            ClaimTier::FrontierAmbition,
            ClaimTier::UnsupportedSurface,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize");
            let restored: ClaimTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, tier);
        }
    }

    #[test]
    fn morphism_effect_serde_round_trip() {
        for effect in [
            MorphismEffect::Supports,
            MorphismEffect::Constrains,
            MorphismEffect::Disqualifies,
        ] {
            let json = serde_json::to_string(&effect).expect("serialize");
            let restored: MorphismEffect = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, effect);
        }
    }

    #[test]
    fn disqualifier_verdict_serde_round_trip() {
        for verdict in [
            DisqualifierVerdict::Forbid,
            DisqualifierVerdict::DowngradeToScoped,
            DisqualifierVerdict::DowngradeToTarget,
            DisqualifierVerdict::RequireOperatorGuidance,
        ] {
            let json = serde_json::to_string(&verdict).expect("serialize");
            let restored: DisqualifierVerdict = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, verdict);
        }
    }

    #[test]
    fn evidence_state_serde_round_trip() {
        for state in [EvidenceState::Fresh, EvidenceState::Stale] {
            let json = serde_json::to_string(&state).expect("serialize");
            let restored: EvidenceState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, state);
        }
    }

    #[test]
    fn claim_verdict_state_serde_round_trip() {
        for state in [
            ClaimVerdictState::Entitled,
            ClaimVerdictState::NotYetProven,
            ClaimVerdictState::BlockedByMissingEvidence,
            ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample,
        ] {
            let json = serde_json::to_string(&state).expect("serialize");
            let restored: ClaimVerdictState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, state);
        }
    }

    #[test]
    fn contract_serde_round_trip() {
        let contract = minimal_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let restored: ClaimEntitlementContract =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, contract);
    }

    #[test]
    fn evaluation_outputs_serde_round_trip() {
        let contract = minimal_contract();
        let scenarios = minimal_scenario_set();
        let outputs = contract.evaluate_scenarios(&scenarios).expect("should succeed");
        let json = serde_json::to_string(&outputs).expect("serialize");
        let restored: ClaimEvaluationOutputs = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, outputs);
    }

    #[test]
    fn evaluate_deterministic_across_runs() {
        let contract = minimal_contract();
        let scenarios = minimal_scenario_set();
        let out1 = serde_json::to_string(
            &contract.evaluate_scenarios(&scenarios).expect("run 1"),
        )
        .unwrap();
        let out2 = serde_json::to_string(
            &contract.evaluate_scenarios(&scenarios).expect("run 2"),
        )
        .unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn validate_rejects_lattice_cycle() {
        let mut contract = minimal_contract();
        contract
            .side_constraint_lattice
            .cover_relations
            .push(ConstraintRelation {
                lower_constraint_id: "constraint-top".to_string(),
                higher_constraint_id: "constraint-bottom".to_string(),
            });
        let errors = contract.validate().expect_err("should detect cycle");
        assert!(errors.iter().any(|e| e.contains("cycle")));
    }

    #[test]
    fn validate_rejects_mismatched_precedence_order() {
        let mut contract = minimal_contract();
        contract.disqualifier_rules.precedence_order = vec!["wrong-order".to_string()];
        let errors = contract.validate().expect_err("should fail");
        assert!(errors.iter().any(|e| e.contains("precedence_order")));
    }
}
