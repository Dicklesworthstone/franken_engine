//! Deterministic theorem-mining substrate over counterexamples and evidence.
//!
//! This module turns replayable failure artifacts into machine-rankable law
//! candidates instead of leaving the same semantic patterns buried in logs.
//! It is intentionally conservative: it produces scoped candidate hypotheses
//! with explicit provenance, not accepted laws.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::counterexample_synthesizer::SynthesizedCounterexample;
use crate::evidence_ledger::EvidenceEntry;
use crate::hash_tiers::ContentHash;
use crate::policy_theorem_compiler::FormalProperty;

pub const LAW_MINING_SCHEMA_VERSION: &str = "franken-engine.law-mining.v1";
pub const LAW_MINING_BEAD_ID: &str = "bd-1lsy.9.10";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CandidateKind {
    Invariant,
    SideCondition,
    NormalForm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProvenanceSourceKind {
    Counterexample,
    EvidenceEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawProvenanceSource {
    pub source_kind: ProvenanceSourceKind,
    pub source_id: String,
    pub policy_ids: Vec<String>,
    pub formal_properties: Vec<FormalProperty>,
    pub decision_types: Vec<String>,
    pub support_summary: String,
    pub source_hash: ContentHash,
}

impl LawProvenanceSource {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(format!("{:?}", self.source_kind).as_bytes());
        data.extend_from_slice(self.source_id.as_bytes());
        push_strings(&mut data, &self.policy_ids);
        for property in &self.formal_properties {
            data.extend_from_slice(property.to_string().as_bytes());
        }
        push_strings(&mut data, &self.decision_types);
        data.extend_from_slice(self.support_summary.as_bytes());
        self.source_hash = ContentHash::compute(&data);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawProvenanceRecord {
    pub provenance_id: String,
    pub candidate_id: String,
    pub sources: Vec<LawProvenanceSource>,
    pub provenance_hash: ContentHash,
}

impl LawProvenanceRecord {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.provenance_id.as_bytes());
        data.extend_from_slice(self.candidate_id.as_bytes());
        for source in &self.sources {
            data.extend_from_slice(source.source_hash.as_bytes());
        }
        self.provenance_hash = ContentHash::compute(&data);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateScopeHypothesis {
    pub scope_id: String,
    pub policy_ids: Vec<String>,
    pub formal_properties: Vec<FormalProperty>,
    pub decision_types: Vec<String>,
    pub capability_names: Vec<String>,
    pub condition_keys: Vec<String>,
    pub frontier_only: bool,
    pub scope_hash: ContentHash,
}

impl CandidateScopeHypothesis {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.scope_id.as_bytes());
        push_strings(&mut data, &self.policy_ids);
        for property in &self.formal_properties {
            data.extend_from_slice(property.to_string().as_bytes());
        }
        push_strings(&mut data, &self.decision_types);
        push_strings(&mut data, &self.capability_names);
        push_strings(&mut data, &self.condition_keys);
        data.push(u8::from(self.frontier_only));
        self.scope_hash = ContentHash::compute(&data);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawCandidate {
    pub candidate_id: String,
    pub kind: CandidateKind,
    pub statement: String,
    pub rank_millionths: u64,
    pub ranking_rationale: String,
    pub scope_hypothesis_id: String,
    pub provenance_id: String,
    pub supporting_source_ids: Vec<String>,
    pub candidate_hash: ContentHash,
}

impl LawCandidate {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.candidate_id.as_bytes());
        data.extend_from_slice(format!("{:?}", self.kind).as_bytes());
        data.extend_from_slice(self.statement.as_bytes());
        data.extend_from_slice(&self.rank_millionths.to_le_bytes());
        data.extend_from_slice(self.ranking_rationale.as_bytes());
        data.extend_from_slice(self.scope_hypothesis_id.as_bytes());
        data.extend_from_slice(self.provenance_id.as_bytes());
        push_strings(&mut data, &self.supporting_source_ids);
        self.candidate_hash = ContentHash::compute(&data);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantSeed {
    pub seed_id: String,
    pub statement: String,
    pub derived_candidate_id: String,
    pub scope_hypothesis_id: String,
    pub supporting_source_ids: Vec<String>,
    pub seed_hash: ContentHash,
}

impl InvariantSeed {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.seed_id.as_bytes());
        data.extend_from_slice(self.statement.as_bytes());
        data.extend_from_slice(self.derived_candidate_id.as_bytes());
        data.extend_from_slice(self.scope_hypothesis_id.as_bytes());
        push_strings(&mut data, &self.supporting_source_ids);
        self.seed_hash = ContentHash::compute(&data);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalFormHypothesis {
    pub hypothesis_id: String,
    pub canonical_form: String,
    pub merge_shapes: Vec<String>,
    pub derived_candidate_id: String,
    pub scope_hypothesis_id: String,
    pub supporting_source_ids: Vec<String>,
    pub hypothesis_hash: ContentHash,
}

impl NormalFormHypothesis {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.hypothesis_id.as_bytes());
        data.extend_from_slice(self.canonical_form.as_bytes());
        push_strings(&mut data, &self.merge_shapes);
        data.extend_from_slice(self.derived_candidate_id.as_bytes());
        data.extend_from_slice(self.scope_hypothesis_id.as_bytes());
        push_strings(&mut data, &self.supporting_source_ids);
        self.hypothesis_hash = ContentHash::compute(&data);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawMiningCatalog {
    pub schema_version: String,
    pub bead_id: String,
    pub generated_epoch: u64,
    pub candidates: Vec<LawCandidate>,
    pub invariant_seed_ledger: Vec<InvariantSeed>,
    pub normal_form_hypotheses: Vec<NormalFormHypothesis>,
    pub provenance_index: Vec<LawProvenanceRecord>,
    pub scope_hypotheses: Vec<CandidateScopeHypothesis>,
    pub catalog_hash: ContentHash,
}

impl LawMiningCatalog {
    pub fn from_sources(
        generated_epoch: u64,
        counterexamples: &[SynthesizedCounterexample],
        evidence_entries: &[EvidenceEntry],
    ) -> Self {
        let mut accumulators = BTreeMap::<(CandidateKind, String), CandidateAccumulator>::new();

        for counterexample in counterexamples {
            accumulate_counterexample(&mut accumulators, counterexample);
        }
        for entry in evidence_entries {
            accumulate_evidence_entry(&mut accumulators, entry);
        }

        let mut candidates = Vec::new();
        let mut invariant_seed_ledger = Vec::new();
        let mut normal_form_hypotheses = Vec::new();
        let mut provenance_index = Vec::new();
        let mut scope_hypotheses = Vec::new();

        for (_, accumulator) in accumulators {
            let scope_signature = accumulator.scope_signature();
            let scope_id = hashed_id("scope", &[&accumulator.statement, &scope_signature]);
            let mut scope = CandidateScopeHypothesis {
                scope_id: scope_id.clone(),
                policy_ids: accumulator.policy_ids.iter().cloned().collect(),
                formal_properties: accumulator.formal_properties.iter().cloned().collect(),
                decision_types: accumulator.decision_types.iter().cloned().collect(),
                capability_names: accumulator.capability_names.iter().cloned().collect(),
                condition_keys: accumulator.condition_keys.iter().cloned().collect(),
                frontier_only: accumulator.saw_counterexample && !accumulator.saw_evidence,
                scope_hash: ContentHash::compute(b"law_mining_scope"),
            };
            scope.recompute_hash();

            let kind_tag = format!("{:?}", accumulator.kind);
            let candidate_id = hashed_id("law", &[&kind_tag, &accumulator.statement]);
            let provenance_id = hashed_id("prov", &[&candidate_id]);
            let supporting_source_ids = accumulator
                .source_records
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            let rank_millionths = accumulator.rank_millionths();
            let ranking_rationale = accumulator.ranking_rationale();

            let mut provenance = LawProvenanceRecord {
                provenance_id: provenance_id.clone(),
                candidate_id: candidate_id.clone(),
                sources: accumulator
                    .source_records
                    .into_values()
                    .collect::<Vec<LawProvenanceSource>>(),
                provenance_hash: ContentHash::compute(b"law_mining_provenance"),
            };
            provenance.recompute_hash();

            let mut candidate = LawCandidate {
                candidate_id: candidate_id.clone(),
                kind: accumulator.kind,
                statement: accumulator.statement.clone(),
                rank_millionths,
                ranking_rationale,
                scope_hypothesis_id: scope_id.clone(),
                provenance_id: provenance_id.clone(),
                supporting_source_ids: supporting_source_ids.clone(),
                candidate_hash: ContentHash::compute(b"law_mining_candidate"),
            };
            candidate.recompute_hash();

            if accumulator.kind == CandidateKind::NormalForm {
                let canonical_form = accumulator
                    .merge_shapes
                    .iter()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| accumulator.statement.clone());
                let mut hypothesis = NormalFormHypothesis {
                    hypothesis_id: hashed_id("normal-form", &[&candidate_id, &canonical_form]),
                    canonical_form,
                    merge_shapes: accumulator.merge_shapes.iter().cloned().collect(),
                    derived_candidate_id: candidate_id.clone(),
                    scope_hypothesis_id: scope_id.clone(),
                    supporting_source_ids: supporting_source_ids.clone(),
                    hypothesis_hash: ContentHash::compute(b"law_mining_normal_form"),
                };
                hypothesis.recompute_hash();
                normal_form_hypotheses.push(hypothesis);
            } else {
                let mut seed = InvariantSeed {
                    seed_id: hashed_id("seed", &[&candidate_id, &accumulator.statement]),
                    statement: accumulator.statement.clone(),
                    derived_candidate_id: candidate_id.clone(),
                    scope_hypothesis_id: scope_id.clone(),
                    supporting_source_ids: supporting_source_ids.clone(),
                    seed_hash: ContentHash::compute(b"law_mining_seed"),
                };
                seed.recompute_hash();
                invariant_seed_ledger.push(seed);
            }

            candidates.push(candidate);
            provenance_index.push(provenance);
            scope_hypotheses.push(scope);
        }

        candidates.sort_by(|left, right| {
            right
                .rank_millionths
                .cmp(&left.rank_millionths)
                .then_with(|| left.statement.cmp(&right.statement))
                .then_with(|| left.candidate_id.cmp(&right.candidate_id))
        });
        invariant_seed_ledger.sort_by(|left, right| left.seed_id.cmp(&right.seed_id));
        normal_form_hypotheses.sort_by(|left, right| left.hypothesis_id.cmp(&right.hypothesis_id));
        provenance_index.sort_by(|left, right| left.provenance_id.cmp(&right.provenance_id));
        scope_hypotheses.sort_by(|left, right| left.scope_id.cmp(&right.scope_id));

        let mut catalog = Self {
            schema_version: LAW_MINING_SCHEMA_VERSION.to_string(),
            bead_id: LAW_MINING_BEAD_ID.to_string(),
            generated_epoch,
            candidates,
            invariant_seed_ledger,
            normal_form_hypotheses,
            provenance_index,
            scope_hypotheses,
            catalog_hash: ContentHash::compute(b"law_mining_catalog"),
        };
        catalog.recompute_hash();
        catalog
    }

    pub fn candidate(&self, candidate_id: &str) -> Option<&LawCandidate> {
        self.candidates
            .iter()
            .find(|candidate| candidate.candidate_id == candidate_id)
    }

    pub fn validate(&self) -> LawMiningValidation {
        let mut warnings = Vec::new();
        let mut candidate_ids = BTreeSet::new();
        let mut provenance_ids = BTreeSet::new();
        let scope_ids = self
            .scope_hypotheses
            .iter()
            .map(|scope| scope.scope_id.clone())
            .collect::<BTreeSet<_>>();

        for candidate in &self.candidates {
            if !candidate_ids.insert(candidate.candidate_id.clone()) {
                warnings.push(format!(
                    "duplicate candidate id: {}",
                    candidate.candidate_id
                ));
            }
            if candidate.supporting_source_ids.is_empty() {
                warnings.push(format!(
                    "candidate missing supporting sources: {}",
                    candidate.candidate_id
                ));
            }
            if !scope_ids.contains(&candidate.scope_hypothesis_id) {
                warnings.push(format!(
                    "candidate references missing scope: {}",
                    candidate.candidate_id
                ));
            }
            if self
                .provenance_index
                .iter()
                .all(|record| record.provenance_id != candidate.provenance_id)
            {
                warnings.push(format!(
                    "candidate references missing provenance: {}",
                    candidate.candidate_id
                ));
            }
        }

        for record in &self.provenance_index {
            if !provenance_ids.insert(record.provenance_id.clone()) {
                warnings.push(format!("duplicate provenance id: {}", record.provenance_id));
            }
            if record.sources.is_empty() {
                warnings.push(format!(
                    "provenance record missing sources: {}",
                    record.provenance_id
                ));
            }
            if !candidate_ids.contains(&record.candidate_id) {
                warnings.push(format!(
                    "provenance record references missing candidate: {}",
                    record.provenance_id
                ));
            }
        }

        let mut sorted_candidates = self.candidates.clone();
        sorted_candidates.sort_by(|left, right| {
            right
                .rank_millionths
                .cmp(&left.rank_millionths)
                .then_with(|| left.statement.cmp(&right.statement))
                .then_with(|| left.candidate_id.cmp(&right.candidate_id))
        });
        if sorted_candidates != self.candidates {
            warnings.push("candidates are not sorted deterministically".to_string());
        }

        LawMiningValidation {
            is_valid: warnings.is_empty(),
            candidate_count: self.candidates.len(),
            provenance_count: self.provenance_index.len(),
            scope_count: self.scope_hypotheses.len(),
            warnings,
        }
    }

    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.schema_version.as_bytes());
        data.extend_from_slice(self.bead_id.as_bytes());
        data.extend_from_slice(&self.generated_epoch.to_le_bytes());
        for candidate in &self.candidates {
            data.extend_from_slice(candidate.candidate_hash.as_bytes());
        }
        for seed in &self.invariant_seed_ledger {
            data.extend_from_slice(seed.seed_hash.as_bytes());
        }
        for hypothesis in &self.normal_form_hypotheses {
            data.extend_from_slice(hypothesis.hypothesis_hash.as_bytes());
        }
        for provenance in &self.provenance_index {
            data.extend_from_slice(provenance.provenance_hash.as_bytes());
        }
        for scope in &self.scope_hypotheses {
            data.extend_from_slice(scope.scope_hash.as_bytes());
        }
        self.catalog_hash = ContentHash::compute(&data);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawMiningValidation {
    pub is_valid: bool,
    pub candidate_count: usize,
    pub provenance_count: usize,
    pub scope_count: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct CandidateAccumulator {
    kind: CandidateKind,
    statement: String,
    policy_ids: BTreeSet<String>,
    formal_properties: BTreeSet<FormalProperty>,
    decision_types: BTreeSet<String>,
    capability_names: BTreeSet<String>,
    condition_keys: BTreeSet<String>,
    merge_shapes: BTreeSet<String>,
    source_records: BTreeMap<String, LawProvenanceSource>,
    saw_counterexample: bool,
    saw_evidence: bool,
}

impl CandidateAccumulator {
    fn new(kind: CandidateKind, statement: String) -> Self {
        Self {
            kind,
            statement,
            policy_ids: BTreeSet::new(),
            formal_properties: BTreeSet::new(),
            decision_types: BTreeSet::new(),
            capability_names: BTreeSet::new(),
            condition_keys: BTreeSet::new(),
            merge_shapes: BTreeSet::new(),
            source_records: BTreeMap::new(),
            saw_counterexample: false,
            saw_evidence: false,
        }
    }

    fn add_provenance(&mut self, mut source: LawProvenanceSource) {
        source.recompute_hash();
        self.source_records.insert(source.source_id.clone(), source);
    }

    fn scope_signature(&self) -> String {
        let mut parts = Vec::new();
        parts.extend(self.policy_ids.iter().cloned());
        parts.extend(
            self.formal_properties
                .iter()
                .map(|property| property.to_string()),
        );
        parts.extend(self.decision_types.iter().cloned());
        parts.extend(self.capability_names.iter().cloned());
        parts.extend(self.condition_keys.iter().cloned());
        parts.join("|")
    }

    fn rank_millionths(&self) -> u64 {
        let kind_bias = match self.kind {
            CandidateKind::Invariant => 250_000,
            CandidateKind::SideCondition => 175_000,
            CandidateKind::NormalForm => 125_000,
        };
        let support = self.source_records.len() as u64 * 150_000;
        let policy_breadth = self.policy_ids.len() as u64 * 45_000;
        let property_breadth = self.formal_properties.len() as u64 * 35_000;
        let decision_breadth = self.decision_types.len() as u64 * 25_000;
        let capability_breadth = self.capability_names.len() as u64 * 12_000;
        let condition_breadth = self.condition_keys.len() as u64 * 8_000;
        let frontier_bonus = u64::from(self.saw_counterexample && !self.saw_evidence) * 20_000;
        (kind_bias
            + support
            + policy_breadth
            + property_breadth
            + decision_breadth
            + capability_breadth
            + condition_breadth
            + frontier_bonus)
            .min(1_000_000)
    }

    fn ranking_rationale(&self) -> String {
        format!(
            "{} sources; {} policies; {} properties; {} decision surfaces",
            self.source_records.len(),
            self.policy_ids.len(),
            self.formal_properties.len(),
            self.decision_types.len()
        )
    }
}

fn accumulate_counterexample(
    accumulators: &mut BTreeMap<(CandidateKind, String), CandidateAccumulator>,
    counterexample: &SynthesizedCounterexample,
) {
    let source_id = format!("counterexample:{}", counterexample.conflict_id);
    let policy_ids = counterexample
        .policy_ids
        .iter()
        .map(|policy_id| policy_id.to_string())
        .collect::<Vec<_>>();
    let capabilities = counterexample
        .concrete_scenario
        .capabilities
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let conditions = counterexample
        .concrete_scenario
        .conditions
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let merge_shape = if counterexample.merge_path.is_empty() {
        None
    } else {
        Some(counterexample.merge_path.join(" -> "))
    };

    let invariant_statement = if capabilities.is_empty() {
        format!(
            "candidate invariant: {} across policies [{}]",
            counterexample.property_violated,
            policy_ids.join(", ")
        )
    } else {
        format!(
            "candidate invariant: {} for capability set [{}]",
            counterexample.property_violated,
            capabilities.join(", ")
        )
    };
    let invariant_summary = format!(
        "{} violated via merge path [{}]",
        counterexample.property_violated,
        counterexample.merge_path.join(" -> ")
    );
    let invariant = accumulators
        .entry((CandidateKind::Invariant, invariant_statement.clone()))
        .or_insert_with(|| {
            CandidateAccumulator::new(CandidateKind::Invariant, invariant_statement)
        });
    invariant.policy_ids.extend(policy_ids.iter().cloned());
    invariant
        .formal_properties
        .insert(counterexample.property_violated);
    invariant
        .capability_names
        .extend(capabilities.iter().cloned());
    invariant.condition_keys.extend(conditions.iter().cloned());
    if let Some(shape) = &merge_shape {
        invariant.merge_shapes.insert(shape.clone());
    }
    invariant.saw_counterexample = true;
    invariant.add_provenance(LawProvenanceSource {
        source_kind: ProvenanceSourceKind::Counterexample,
        source_id: source_id.clone(),
        policy_ids: policy_ids.clone(),
        formal_properties: vec![counterexample.property_violated],
        decision_types: Vec::new(),
        support_summary: invariant_summary,
        source_hash: ContentHash::compute(b"law_mining_source"),
    });

    if !conditions.is_empty() {
        let side_condition_statement = format!(
            "candidate side-condition: {} only when [{}]",
            counterexample.property_violated,
            conditions.join(", ")
        );
        let side_condition = accumulators
            .entry((
                CandidateKind::SideCondition,
                side_condition_statement.clone(),
            ))
            .or_insert_with(|| {
                CandidateAccumulator::new(CandidateKind::SideCondition, side_condition_statement)
            });
        side_condition.policy_ids.extend(policy_ids.iter().cloned());
        side_condition
            .formal_properties
            .insert(counterexample.property_violated);
        side_condition
            .condition_keys
            .extend(conditions.iter().cloned());
        side_condition
            .capability_names
            .extend(capabilities.iter().cloned());
        side_condition.saw_counterexample = true;
        side_condition.add_provenance(LawProvenanceSource {
            source_kind: ProvenanceSourceKind::Counterexample,
            source_id: source_id.clone(),
            policy_ids: policy_ids.clone(),
            formal_properties: vec![counterexample.property_violated],
            decision_types: Vec::new(),
            support_summary: format!(
                "conditioned by [{}] with resolution hint {}",
                conditions.join(", "),
                counterexample.resolution_hint
            ),
            source_hash: ContentHash::compute(b"law_mining_source"),
        });
    }

    if let Some(shape) = merge_shape {
        let normal_form_statement = format!(
            "candidate normal-form: {} via merge path [{}]",
            counterexample.property_violated, shape
        );
        let normal_form = accumulators
            .entry((CandidateKind::NormalForm, normal_form_statement.clone()))
            .or_insert_with(|| {
                CandidateAccumulator::new(CandidateKind::NormalForm, normal_form_statement)
            });
        normal_form.policy_ids.extend(policy_ids);
        normal_form
            .formal_properties
            .insert(counterexample.property_violated);
        normal_form.capability_names.extend(capabilities);
        normal_form.condition_keys.extend(conditions);
        normal_form.merge_shapes.insert(shape.clone());
        normal_form.saw_counterexample = true;
        let normal_form_policy_ids = normal_form.policy_ids.iter().cloned().collect::<Vec<_>>();
        normal_form.add_provenance(LawProvenanceSource {
            source_kind: ProvenanceSourceKind::Counterexample,
            source_id,
            policy_ids: normal_form_policy_ids,
            formal_properties: vec![counterexample.property_violated],
            decision_types: Vec::new(),
            support_summary: format!("merge-shape candidate from {}", shape),
            source_hash: ContentHash::compute(b"law_mining_source"),
        });
    }
}

fn accumulate_evidence_entry(
    accumulators: &mut BTreeMap<(CandidateKind, String), CandidateAccumulator>,
    entry: &EvidenceEntry,
) {
    let constraint_ids = entry
        .constraints
        .iter()
        .filter(|constraint| constraint.active)
        .map(|constraint| constraint.constraint_id.clone())
        .collect::<Vec<_>>();
    let witness_types = entry
        .witnesses
        .iter()
        .map(|witness| witness.witness_type.clone())
        .collect::<Vec<_>>();
    let source_id = format!("evidence:{}", entry.entry_id);

    let statement = if constraint_ids.is_empty() {
        format!(
            "candidate side-condition: {} chooses {} with witnesses [{}]",
            entry.decision_type,
            entry.chosen_action.action_name,
            witness_types.join(", ")
        )
    } else {
        format!(
            "candidate side-condition: {} chooses {} under constraints [{}]",
            entry.decision_type,
            entry.chosen_action.action_name,
            constraint_ids.join(", ")
        )
    };

    let accumulator = accumulators
        .entry((CandidateKind::SideCondition, statement.clone()))
        .or_insert_with(|| CandidateAccumulator::new(CandidateKind::SideCondition, statement));
    accumulator.policy_ids.insert(entry.policy_id.clone());
    accumulator
        .decision_types
        .insert(entry.decision_type.to_string());
    accumulator
        .condition_keys
        .extend(constraint_ids.iter().cloned());
    accumulator
        .capability_names
        .extend(witness_types.iter().cloned());
    accumulator.saw_evidence = true;
    accumulator.add_provenance(LawProvenanceSource {
        source_kind: ProvenanceSourceKind::EvidenceEntry,
        source_id,
        policy_ids: vec![entry.policy_id.clone()],
        formal_properties: Vec::new(),
        decision_types: vec![entry.decision_type.to_string()],
        support_summary: format!(
            "chosen={} expected_loss={} witnesses={}",
            entry.chosen_action.action_name,
            entry.chosen_action.expected_loss_millionths,
            witness_types.join(", ")
        ),
        source_hash: ContentHash::compute(b"law_mining_source"),
    });
}

fn hashed_id(prefix: &str, parts: &[&str]) -> String {
    let mut data = Vec::new();
    for part in parts {
        data.extend_from_slice(part.as_bytes());
        data.push(0xff);
    }
    let hash = ContentHash::compute(&data).to_hex();
    format!("{prefix}-{}", &hash[..12])
}

fn push_strings(data: &mut Vec<u8>, values: &[String]) {
    for value in values {
        data.extend_from_slice(value.as_bytes());
        data.push(0xff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, BTreeSet};

    use crate::counterexample_synthesizer::{
        ConcreteScenario, SynthesisOutcome, SynthesisStrategy, SynthesizedCounterexample,
    };
    use crate::engine_object_id::EngineObjectId;
    use crate::evidence_ledger::{
        CandidateAction, ChosenAction, Constraint, DecisionType, EvidenceEntryBuilder, Witness,
    };
    use crate::policy_theorem_compiler::{FormalProperty, PolicyId};
    use crate::security_epoch::SecurityEpoch;

    fn sample_counterexample(
        byte: u8,
        property: FormalProperty,
        capabilities: &[&str],
        conditions: &[(&str, &str)],
        merge_path: &[&str],
    ) -> SynthesizedCounterexample {
        let mut condition_map = BTreeMap::new();
        for (key, value) in conditions {
            condition_map.insert((*key).to_string(), (*value).to_string());
        }
        SynthesizedCounterexample {
            conflict_id: EngineObjectId([byte; 32]),
            property_violated: property,
            policy_ids: vec![PolicyId::new(format!("policy-{byte}"))],
            merge_path: merge_path.iter().map(|item| (*item).to_string()).collect(),
            concrete_scenario: ConcreteScenario {
                subjects: BTreeSet::from([format!("subject-{byte}")]),
                capabilities: capabilities
                    .iter()
                    .map(|item| (*item).to_string())
                    .collect(),
                conditions: condition_map,
                merge_ordering: merge_path.iter().map(|item| (*item).to_string()).collect(),
                input_state: BTreeMap::from([("mode".to_string(), "test".to_string())]),
            },
            expected_outcome: "expected".to_string(),
            actual_outcome: "actual".to_string(),
            minimality_evidence: crate::counterexample_synthesizer::MinimalityEvidence {
                rounds: 2,
                elements_removed: 1,
                starting_size: 4,
                final_size: 3,
                is_fixed_point: true,
            },
            strategy: SynthesisStrategy::Enumeration,
            outcome: SynthesisOutcome::Complete,
            compute_time_ns: 1_000,
            content_hash: ContentHash([byte; 32]),
            epoch: SecurityEpoch::from_raw(byte as u64),
            resolution_hint: "stabilize merge ordering".to_string(),
        }
    }

    fn sample_evidence_entry(
        trace_id: &str,
        decision_type: DecisionType,
        policy_id: &str,
        constraint_ids: &[&str],
        witness_types: &[&str],
    ) -> EvidenceEntry {
        let builder = EvidenceEntryBuilder::new(
            trace_id,
            format!("decision-{trace_id}"),
            policy_id,
            SecurityEpoch::from_raw(9),
            decision_type,
        )
        .timestamp_ns(1_000)
        .candidate(CandidateAction::new("allow", 10))
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 10,
            rationale: "best".to_string(),
        });

        let builder = constraint_ids
            .iter()
            .fold(builder, |builder, constraint_id| {
                builder.constraint(Constraint {
                    constraint_id: (*constraint_id).to_string(),
                    description: "constraint".to_string(),
                    active: true,
                })
            });
        let builder = witness_types.iter().fold(builder, |builder, witness_type| {
            builder.witness(Witness {
                witness_id: format!("witness-{witness_type}"),
                witness_type: (*witness_type).to_string(),
                value: "1".to_string(),
            })
        });
        builder.build().expect("evidence entry")
    }

    #[test]
    fn candidate_extraction_is_deterministic_across_input_order() {
        let a = sample_counterexample(
            1,
            FormalProperty::MergeDeterminism,
            &["fs.read", "net.send"],
            &[("region", "alpha")],
            &["merge-a", "merge-b"],
        );
        let b = sample_counterexample(
            2,
            FormalProperty::MergeDeterminism,
            &["fs.read", "net.send"],
            &[("region", "alpha")],
            &["merge-a", "merge-b"],
        );
        let evidence = sample_evidence_entry(
            "trace-a",
            DecisionType::SecurityAction,
            "policy-a",
            &["quorum"],
            &["posterior"],
        );

        let first = LawMiningCatalog::from_sources(
            7,
            &[a.clone(), b.clone()],
            std::slice::from_ref(&evidence),
        );
        let second = LawMiningCatalog::from_sources(7, &[b, a], &[evidence]);
        assert_eq!(first, second);
    }

    #[test]
    fn duplicate_candidates_merge_and_retain_provenance() {
        let a = sample_counterexample(
            3,
            FormalProperty::Monotonicity,
            &["fs.read"],
            &[("scope", "strict")],
            &["merge-x"],
        );
        let b = sample_counterexample(
            4,
            FormalProperty::Monotonicity,
            &["fs.read"],
            &[("scope", "strict")],
            &["merge-x"],
        );

        let catalog = LawMiningCatalog::from_sources(11, &[a, b], &[]);
        let candidate = catalog
            .candidates
            .iter()
            .find(|candidate| candidate.kind == CandidateKind::Invariant)
            .expect("invariant candidate");
        assert_eq!(candidate.supporting_source_ids.len(), 2);
        let provenance = catalog
            .provenance_index
            .iter()
            .find(|record| record.provenance_id == candidate.provenance_id)
            .expect("provenance record");
        assert_eq!(provenance.sources.len(), 2);
    }

    #[test]
    fn scope_hypotheses_are_sorted_and_deduplicated() {
        let counterexample = sample_counterexample(
            5,
            FormalProperty::NonInterference,
            &["net.send", "fs.read", "fs.read"],
            &[("beta", "1"), ("alpha", "1")],
            &["merge-a"],
        );
        let catalog = LawMiningCatalog::from_sources(13, &[counterexample], &[]);
        let scope = catalog
            .scope_hypotheses
            .iter()
            .find(|scope| !scope.capability_names.is_empty())
            .expect("scope");
        assert_eq!(
            scope.capability_names,
            vec!["fs.read".to_string(), "net.send".to_string()]
        );
        assert_eq!(
            scope.condition_keys,
            vec!["alpha".to_string(), "beta".to_string()]
        );
    }

    #[test]
    fn ranking_prefers_broader_support() {
        let broad_a = sample_counterexample(
            6,
            FormalProperty::PrecedenceStability,
            &["sched.tick"],
            &[("region", "wide")],
            &["merge-a", "merge-b"],
        );
        let broad_b = sample_counterexample(
            7,
            FormalProperty::PrecedenceStability,
            &["sched.tick"],
            &[("region", "wide")],
            &["merge-a", "merge-b"],
        );
        let narrow = sample_evidence_entry(
            "trace-narrow",
            DecisionType::PolicyUpdate,
            "policy-narrow",
            &["policy-floor"],
            &["delta"],
        );

        let catalog = LawMiningCatalog::from_sources(17, &[broad_a, broad_b], &[narrow]);
        assert!(catalog.candidates.len() >= 2);
        assert!(catalog.candidates[0].rank_millionths >= catalog.candidates[1].rank_millionths);
        assert!(
            catalog.candidates[0].ranking_rationale.contains("sources"),
            "ranking rationale should explain breadth"
        );
    }

    #[test]
    fn validation_passes_for_sorted_reference_catalog() {
        let counterexample = sample_counterexample(
            8,
            FormalProperty::MergeDeterminism,
            &["cache.lookup"],
            &[("board", "declared")],
            &["merge-a", "merge-b"],
        );
        let evidence = sample_evidence_entry(
            "trace-validate",
            DecisionType::ContractEvaluation,
            "policy-contract",
            &["schema-ready"],
            &["fixture"],
        );
        let catalog = LawMiningCatalog::from_sources(19, &[counterexample], &[evidence]);
        assert!(catalog.validate().is_valid);
    }
}
