//! Deterministic theorem-mining substrate over counterexamples and evidence.
//!
//! This module turns replayable failure artifacts into machine-rankable law
//! candidates instead of leaving the same semantic patterns buried in logs.
//! It is intentionally conservative: it produces scoped candidate hypotheses
//! with explicit provenance, not accepted laws.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::counterexample_synthesizer::{
    ConcreteScenario, MinimalityEvidence, SynthesisOutcome, SynthesisStrategy,
    SynthesizedCounterexample,
};
use crate::engine_object_id::EngineObjectId;
use crate::evidence_ledger::{
    CandidateAction, ChosenAction, Constraint, DecisionType, EvidenceEntry, EvidenceEntryBuilder,
    Witness,
};
use crate::hash_tiers::ContentHash;
use crate::policy_theorem_compiler::{FormalProperty, PolicyId};
use crate::security_epoch::SecurityEpoch;

pub const LAW_MINING_SCHEMA_VERSION: &str = "franken-engine.law-mining.v1";
pub const LAW_MINING_BEAD_ID: &str = "bd-1lsy.9.10";
pub const LAW_MINING_COMPONENT: &str = "law_mining";
pub const CANDIDATE_LAW_CATALOG_SCHEMA_VERSION: &str =
    "franken-engine.law-mining.candidate-law-catalog.v1";
pub const INVARIANT_SEED_LEDGER_SCHEMA_VERSION: &str =
    "franken-engine.law-mining.invariant-seed-ledger.v1";
pub const NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION: &str =
    "franken-engine.law-mining.normal-form-hypotheses.v1";
pub const LAW_PROVENANCE_INDEX_SCHEMA_VERSION: &str =
    "franken-engine.law-mining.provenance-index.v1";
pub const CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION: &str =
    "franken-engine.law-mining.scope-hypotheses.v1";
pub const LAW_MINING_TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.law-mining.trace-ids.v1";
pub const LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.law-mining.run-manifest.v1";
pub const LAW_MINING_ENV_SCHEMA_VERSION: &str = "franken-engine.law-mining.env.v1";
pub const LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION: &str =
    "franken-engine.law-mining.artifact-index.v1";
pub const LAW_MINING_EVENT_STREAM_SCHEMA_VERSION: &str = "franken-engine.law-mining.events.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LawMiningFixture {
    pub generated_epoch: u64,
    pub counterexamples: Vec<SynthesizedCounterexample>,
    pub evidence_entries: Vec<EvidenceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateLawCatalogArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub generated_epoch: u64,
    pub catalog_hash: ContentHash,
    pub candidates: Vec<LawCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantSeedLedgerArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub generated_epoch: u64,
    pub catalog_hash: ContentHash,
    pub invariant_seed_ledger: Vec<InvariantSeed>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalFormHypothesesArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub generated_epoch: u64,
    pub catalog_hash: ContentHash,
    pub normal_form_hypotheses: Vec<NormalFormHypothesis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawProvenanceIndexArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub generated_epoch: u64,
    pub catalog_hash: ContentHash,
    pub provenance_index: Vec<LawProvenanceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateScopeHypothesesArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub generated_epoch: u64,
    pub catalog_hash: ContentHash,
    pub scope_hypotheses: Vec<CandidateScopeHypothesis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceIdsArtifact {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawMiningEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactHashRecord {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawMiningEnvArtifact {
    pub schema_version: String,
    pub run_id: String,
    pub generated_at_utc: String,
    pub source_commit: String,
    pub toolchain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawMiningArtifactIndex {
    pub schema_version: String,
    pub bead_id: String,
    pub run_id: String,
    pub artifacts: Vec<ArtifactHashRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LawMiningRunManifest {
    pub schema_version: String,
    pub bead_id: String,
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub generated_at_utc: String,
    pub source_commit: String,
    pub toolchain: String,
    pub generated_epoch: u64,
    pub catalog_hash: ContentHash,
    pub command_invocation: String,
    pub artifact_hashes: Vec<ArtifactHashRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactContext {
    pub artifact_dir: PathBuf,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub run_id: String,
    pub generated_at_utc: String,
    pub source_commit: String,
    pub toolchain: String,
    pub command_invocation: String,
}

impl ArtifactContext {
    pub fn new(artifact_dir: impl Into<PathBuf>) -> Self {
        Self {
            artifact_dir: artifact_dir.into(),
            trace_id: "trace.rgc.810".to_string(),
            decision_id: "decision.rgc.810".to_string(),
            policy_id: "policy.rgc.810".to_string(),
            run_id: "run-rgc-810".to_string(),
            generated_at_utc: "1970-01-01T00:00:00Z".to_string(),
            source_commit: "unknown".to_string(),
            toolchain: "nightly".to_string(),
            command_invocation: "cargo run -p frankenengine-engine --bin franken_law_mining -- --artifact-dir <path>".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleWriteReport {
    pub artifact_dir: PathBuf,
    pub candidate_law_catalog_path: PathBuf,
    pub invariant_seed_ledger_path: PathBuf,
    pub normal_form_hypotheses_path: PathBuf,
    pub provenance_index_path: PathBuf,
    pub scope_hypotheses_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub env_path: PathBuf,
    pub artifact_index_path: PathBuf,
    pub repro_lock_path: PathBuf,
    pub summary_path: PathBuf,
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
        let this_policy_ids = policy_ids.clone();
        normal_form.policy_ids.extend(policy_ids);
        normal_form
            .formal_properties
            .insert(counterexample.property_violated);
        normal_form.capability_names.extend(capabilities);
        normal_form.condition_keys.extend(conditions);
        normal_form.merge_shapes.insert(shape.clone());
        normal_form.saw_counterexample = true;
        normal_form.add_provenance(LawProvenanceSource {
            source_kind: ProvenanceSourceKind::Counterexample,
            source_id,
            policy_ids: this_policy_ids,
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

pub fn default_fixture() -> LawMiningFixture {
    LawMiningFixture {
        generated_epoch: 27,
        counterexamples: vec![
            sample_counterexample_fixture(
                0x41,
                FormalProperty::MergeDeterminism,
                &["fs.read", "net.send"],
                &[("board", "declared"), ("runtime", "franken")],
                &["alpha", "beta"],
                "canonicalize merge ordering",
            ),
            sample_counterexample_fixture(
                0x51,
                FormalProperty::Monotonicity,
                &["cache.lookup", "cache.store"],
                &[("cache_lane", "main"), ("mode", "promotion")],
                &["seed", "promote"],
                "stabilize promotion boundary",
            ),
        ],
        evidence_entries: vec![
            sample_evidence_entry_fixture(
                "trace-law-mining-fixture-a",
                DecisionType::ContractEvaluation,
                "policy-catalog",
                &["schema-ready", "replayable"],
                &["fixture", "posterior"],
            ),
            sample_evidence_entry_fixture(
                "trace-law-mining-fixture-b",
                DecisionType::SecurityAction,
                "policy-guard",
                &["epoch-green"],
                &["counterexample", "constraint"],
            ),
        ],
    }
}

pub fn emit_default_law_mining_bundle(context: &ArtifactContext) -> io::Result<BundleWriteReport> {
    emit_law_mining_bundle(context, &default_fixture())
}

pub fn emit_law_mining_bundle(
    context: &ArtifactContext,
    fixture: &LawMiningFixture,
) -> io::Result<BundleWriteReport> {
    fs::create_dir_all(&context.artifact_dir)?;

    let catalog = LawMiningCatalog::from_sources(
        fixture.generated_epoch,
        &fixture.counterexamples,
        &fixture.evidence_entries,
    );
    let catalog_hash = catalog.catalog_hash;
    let candidate_catalog = CandidateLawCatalogArtifact {
        schema_version: CANDIDATE_LAW_CATALOG_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: fixture.generated_epoch,
        catalog_hash,
        candidates: catalog.candidates.clone(),
    };
    let invariant_seed_ledger = InvariantSeedLedgerArtifact {
        schema_version: INVARIANT_SEED_LEDGER_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: fixture.generated_epoch,
        catalog_hash,
        invariant_seed_ledger: catalog.invariant_seed_ledger.clone(),
    };
    let normal_form_hypotheses = NormalFormHypothesesArtifact {
        schema_version: NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: fixture.generated_epoch,
        catalog_hash,
        normal_form_hypotheses: catalog.normal_form_hypotheses.clone(),
    };
    let provenance_index = LawProvenanceIndexArtifact {
        schema_version: LAW_PROVENANCE_INDEX_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: fixture.generated_epoch,
        catalog_hash,
        provenance_index: catalog.provenance_index.clone(),
    };
    let scope_hypotheses = CandidateScopeHypothesesArtifact {
        schema_version: CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: fixture.generated_epoch,
        catalog_hash,
        scope_hypotheses: catalog.scope_hypotheses.clone(),
    };
    let trace_ids = TraceIdsArtifact {
        schema_version: LAW_MINING_TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        run_id: context.run_id.clone(),
    };
    let events = vec![
        LawMiningEvent {
            schema_version: LAW_MINING_EVENT_STREAM_SCHEMA_VERSION.to_string(),
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: LAW_MINING_COMPONENT.to_string(),
            event: "catalog_mined".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            detail: format!(
                "catalog_hash={} candidates={} counterexamples={} evidence_entries={}",
                catalog_hash.to_hex(),
                catalog.candidates.len(),
                fixture.counterexamples.len(),
                fixture.evidence_entries.len()
            ),
        },
        LawMiningEvent {
            schema_version: LAW_MINING_EVENT_STREAM_SCHEMA_VERSION.to_string(),
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: LAW_MINING_COMPONENT.to_string(),
            event: "bundle_written".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            detail: format!(
                "invariants={} normal_forms={} scopes={}",
                catalog.invariant_seed_ledger.len(),
                catalog.normal_form_hypotheses.len(),
                catalog.scope_hypotheses.len()
            ),
        },
    ];
    let env = LawMiningEnvArtifact {
        schema_version: LAW_MINING_ENV_SCHEMA_VERSION.to_string(),
        run_id: context.run_id.clone(),
        generated_at_utc: context.generated_at_utc.clone(),
        source_commit: context.source_commit.clone(),
        toolchain: context.toolchain.clone(),
    };

    let mut artifact_hashes = Vec::new();
    let candidate_law_catalog_path = write_json_artifact(
        &context.artifact_dir,
        "candidate_law_catalog.json",
        &candidate_catalog,
        &mut artifact_hashes,
    )?;
    let invariant_seed_ledger_path = write_json_artifact(
        &context.artifact_dir,
        "invariant_seed_ledger.json",
        &invariant_seed_ledger,
        &mut artifact_hashes,
    )?;
    let normal_form_hypotheses_path = write_json_artifact(
        &context.artifact_dir,
        "normal_form_hypotheses.json",
        &normal_form_hypotheses,
        &mut artifact_hashes,
    )?;
    let provenance_index_path = write_json_artifact(
        &context.artifact_dir,
        "law_provenance_index.json",
        &provenance_index,
        &mut artifact_hashes,
    )?;
    let scope_hypotheses_path = write_json_artifact(
        &context.artifact_dir,
        "candidate_scope_hypotheses.json",
        &scope_hypotheses,
        &mut artifact_hashes,
    )?;
    let trace_ids_path = write_json_artifact(
        &context.artifact_dir,
        "trace_ids.json",
        &trace_ids,
        &mut artifact_hashes,
    )?;
    let events_path = write_jsonl_artifact(
        &context.artifact_dir,
        "events.jsonl",
        &events,
        &mut artifact_hashes,
    )?;
    let commands_path = write_text_artifact(
        &context.artifact_dir,
        "commands.txt",
        &format!("{}\n", context.command_invocation),
        &mut artifact_hashes,
    )?;
    let env_path = write_json_artifact(
        &context.artifact_dir,
        "env.json",
        &env,
        &mut artifact_hashes,
    )?;
    let summary_path = write_text_artifact(
        &context.artifact_dir,
        "summary.md",
        &render_summary(&catalog),
        &mut artifact_hashes,
    )?;
    let repro_lock_path = write_text_artifact(
        &context.artifact_dir,
        "repro.lock",
        &render_repro_lock(context, &catalog),
        &mut artifact_hashes,
    )?;

    let artifact_index = LawMiningArtifactIndex {
        schema_version: LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        run_id: context.run_id.clone(),
        artifacts: artifact_hashes.clone(),
    };
    let artifact_index_path = write_json_artifact(
        &context.artifact_dir,
        "manifest.json",
        &artifact_index,
        &mut artifact_hashes,
    )?;

    let run_manifest = LawMiningRunManifest {
        schema_version: LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        run_id: context.run_id.clone(),
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        generated_at_utc: context.generated_at_utc.clone(),
        source_commit: context.source_commit.clone(),
        toolchain: context.toolchain.clone(),
        generated_epoch: fixture.generated_epoch,
        catalog_hash: catalog.catalog_hash,
        command_invocation: context.command_invocation.clone(),
        artifact_hashes,
    };
    let run_manifest_path = write_json_artifact_without_index(
        &context.artifact_dir,
        "run_manifest.json",
        &run_manifest,
    )?;

    Ok(BundleWriteReport {
        artifact_dir: context.artifact_dir.clone(),
        candidate_law_catalog_path,
        invariant_seed_ledger_path,
        normal_form_hypotheses_path,
        provenance_index_path,
        scope_hypotheses_path,
        trace_ids_path,
        run_manifest_path,
        events_path,
        commands_path,
        env_path,
        artifact_index_path,
        repro_lock_path,
        summary_path,
    })
}

pub fn render_summary(catalog: &LawMiningCatalog) -> String {
    let mut lines = vec![
        "# Law Mining Summary".to_string(),
        format!("bead_id: {}", catalog.bead_id),
        format!("generated_epoch: {}", catalog.generated_epoch),
        format!("catalog_hash: {}", catalog.catalog_hash.to_hex()),
        format!("candidates: {}", catalog.candidates.len()),
        format!("invariant_seeds: {}", catalog.invariant_seed_ledger.len()),
        format!(
            "normal_form_hypotheses: {}",
            catalog.normal_form_hypotheses.len()
        ),
        format!("provenance_records: {}", catalog.provenance_index.len()),
        format!("scope_hypotheses: {}", catalog.scope_hypotheses.len()),
    ];

    if let Some(candidate) = catalog.candidates.first() {
        lines.push(String::new());
        lines.push("## Top Candidate".to_string());
        lines.push(format!("candidate_id: {}", candidate.candidate_id));
        lines.push(format!("kind: {:?}", candidate.kind));
        lines.push(format!("rank_millionths: {}", candidate.rank_millionths));
        lines.push(format!("statement: {}", candidate.statement));
        lines.push(format!("rationale: {}", candidate.ranking_rationale));
    }

    lines.join("\n")
}

fn render_repro_lock(context: &ArtifactContext, catalog: &LawMiningCatalog) -> String {
    [
        "# law-mining repro lock",
        &format!("run_id={}", context.run_id),
        &format!("trace_id={}", context.trace_id),
        &format!("decision_id={}", context.decision_id),
        &format!("policy_id={}", context.policy_id),
        &format!("catalog_hash={}", catalog.catalog_hash.to_hex()),
        &format!("command={}", context.command_invocation),
    ]
    .join("\n")
}

fn sample_counterexample_fixture(
    byte: u8,
    property: FormalProperty,
    capabilities: &[&str],
    conditions: &[(&str, &str)],
    merge_path: &[&str],
    resolution_hint: &str,
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
            input_state: BTreeMap::from([("mode".to_string(), "fixture".to_string())]),
        },
        expected_outcome: "stable".to_string(),
        actual_outcome: "unstable".to_string(),
        minimality_evidence: MinimalityEvidence {
            rounds: 3,
            elements_removed: 2,
            starting_size: 6,
            final_size: 4,
            is_fixed_point: true,
        },
        strategy: SynthesisStrategy::TimeBounded,
        outcome: SynthesisOutcome::Complete,
        compute_time_ns: 9_000,
        content_hash: ContentHash([byte; 32]),
        epoch: SecurityEpoch::from_raw(byte as u64),
        resolution_hint: resolution_hint.to_string(),
    }
}

fn sample_evidence_entry_fixture(
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
        SecurityEpoch::from_raw(12),
        decision_type,
    )
    .timestamp_ns(12_345)
    .candidate(CandidateAction::new("allow", 10))
    .chosen(ChosenAction {
        action_name: "allow".to_string(),
        expected_loss_millionths: 10,
        rationale: "fixture".to_string(),
    });

    let builder = constraint_ids
        .iter()
        .fold(builder, |builder, constraint_id| {
            builder.constraint(Constraint {
                constraint_id: (*constraint_id).to_string(),
                description: "fixture constraint".to_string(),
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
    builder
        .build()
        .expect("fixture evidence entry should build")
}

fn write_json_artifact<T: Serialize>(
    artifact_dir: &Path,
    file_name: &str,
    value: &T,
    artifact_hashes: &mut Vec<ArtifactHashRecord>,
) -> io::Result<PathBuf> {
    let path = write_json_artifact_without_index(artifact_dir, file_name, value)?;
    let bytes = fs::read(&path)?;
    artifact_hashes.push(ArtifactHashRecord {
        path: file_name.to_string(),
        sha256: ContentHash::compute(&bytes).to_hex(),
    });
    Ok(path)
}

fn write_json_artifact_without_index<T: Serialize>(
    artifact_dir: &Path,
    file_name: &str,
    value: &T,
) -> io::Result<PathBuf> {
    let path = artifact_dir.join(file_name);
    let bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    fs::write(&path, bytes)?;
    Ok(path)
}

fn write_jsonl_artifact<T: Serialize>(
    artifact_dir: &Path,
    file_name: &str,
    values: &[T],
    artifact_hashes: &mut Vec<ArtifactHashRecord>,
) -> io::Result<PathBuf> {
    let path = artifact_dir.join(file_name);
    let mut buffer = String::new();
    for value in values {
        buffer.push_str(&serde_json::to_string(value).map_err(io::Error::other)?);
        buffer.push('\n');
    }
    fs::write(&path, buffer.as_bytes())?;
    artifact_hashes.push(ArtifactHashRecord {
        path: file_name.to_string(),
        sha256: ContentHash::compute(buffer.as_bytes()).to_hex(),
    });
    Ok(path)
}

fn write_text_artifact(
    artifact_dir: &Path,
    file_name: &str,
    value: &str,
    artifact_hashes: &mut Vec<ArtifactHashRecord>,
) -> io::Result<PathBuf> {
    let path = artifact_dir.join(file_name);
    fs::write(&path, value.as_bytes())?;
    artifact_hashes.push(ArtifactHashRecord {
        path: file_name.to_string(),
        sha256: ContentHash::compute(value.as_bytes()).to_hex(),
    });
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

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
    fn all_schema_versions_are_distinct_and_non_empty() {
        let versions = [
            LAW_MINING_SCHEMA_VERSION,
            CANDIDATE_LAW_CATALOG_SCHEMA_VERSION,
            INVARIANT_SEED_LEDGER_SCHEMA_VERSION,
            NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION,
            LAW_PROVENANCE_INDEX_SCHEMA_VERSION,
            CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION,
            LAW_MINING_TRACE_IDS_SCHEMA_VERSION,
            LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION,
            LAW_MINING_ENV_SCHEMA_VERSION,
            LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION,
            LAW_MINING_EVENT_STREAM_SCHEMA_VERSION,
        ];
        let unique: BTreeSet<&str> = versions.iter().copied().collect();
        assert_eq!(unique.len(), versions.len());
        for version in &versions {
            assert!(!version.is_empty());
            assert!(version.starts_with("franken-engine."));
        }
    }

    #[test]
    fn provenance_source_kind_serde_round_trip() {
        for kind in [
            ProvenanceSourceKind::Counterexample,
            ProvenanceSourceKind::EvidenceEntry,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ProvenanceSourceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
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

    fn temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        path.push(format!("franken-law-mining-{label}-{nonce}"));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    #[test]
    fn default_bundle_writes_required_artifacts() {
        let artifact_dir = temp_dir("bundle");
        let mut context = ArtifactContext::new(&artifact_dir);
        context.command_invocation = "law-mining-test".to_string();

        let report = emit_default_law_mining_bundle(&context).expect("bundle should write");

        for path in [
            &report.candidate_law_catalog_path,
            &report.invariant_seed_ledger_path,
            &report.normal_form_hypotheses_path,
            &report.provenance_index_path,
            &report.scope_hypotheses_path,
            &report.trace_ids_path,
            &report.run_manifest_path,
            &report.events_path,
            &report.commands_path,
            &report.env_path,
            &report.artifact_index_path,
            &report.repro_lock_path,
            &report.summary_path,
        ] {
            assert!(path.exists(), "missing artifact {}", path.display());
        }

        let manifest: LawMiningRunManifest = serde_json::from_slice(
            &fs::read(&report.run_manifest_path).expect("read run manifest"),
        )
        .expect("decode run manifest");
        assert_eq!(
            manifest.schema_version,
            LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(manifest.bead_id, LAW_MINING_BEAD_ID);
        assert!(
            manifest
                .artifact_hashes
                .iter()
                .any(|artifact| artifact.path == "candidate_law_catalog.json")
        );
    }

    #[test]
    fn render_summary_mentions_top_candidate() {
        let fixture = default_fixture();
        let catalog = LawMiningCatalog::from_sources(
            fixture.generated_epoch,
            &fixture.counterexamples,
            &fixture.evidence_entries,
        );
        let summary = render_summary(&catalog);
        assert!(summary.contains("# Law Mining Summary"));
        assert!(summary.contains("## Top Candidate"));
        assert!(summary.contains("candidate_id:"));
    }

    // ── schema constants ────────────────────────────────────────────

    #[test]
    fn all_schema_versions_start_with_franken_engine() {
        let versions = [
            LAW_MINING_SCHEMA_VERSION,
            CANDIDATE_LAW_CATALOG_SCHEMA_VERSION,
            INVARIANT_SEED_LEDGER_SCHEMA_VERSION,
            NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION,
            LAW_PROVENANCE_INDEX_SCHEMA_VERSION,
            CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION,
            LAW_MINING_TRACE_IDS_SCHEMA_VERSION,
            LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION,
            LAW_MINING_ENV_SCHEMA_VERSION,
            LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION,
            LAW_MINING_EVENT_STREAM_SCHEMA_VERSION,
        ];
        for version in versions {
            assert!(version.starts_with("franken-engine."), "bad: {version}");
        }
    }

    #[test]
    fn bead_id_and_component_non_empty() {
        assert!(!LAW_MINING_BEAD_ID.is_empty());
        assert!(!LAW_MINING_COMPONENT.is_empty());
    }

    // ── CandidateKind serde ─────────────────────────────────────────

    #[test]
    fn candidate_kind_serde_round_trip() {
        for kind in [
            CandidateKind::Invariant,
            CandidateKind::SideCondition,
            CandidateKind::NormalForm,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: CandidateKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // ── empty inputs ────────────────────────────────────────────────

    #[test]
    fn empty_sources_produce_empty_catalog() {
        let catalog = LawMiningCatalog::from_sources(1, &[], &[]);
        assert!(catalog.candidates.is_empty());
        assert!(catalog.provenance_index.is_empty());
        assert!(catalog.scope_hypotheses.is_empty());
    }

    #[test]
    fn empty_catalog_validates() {
        let catalog = LawMiningCatalog::from_sources(1, &[], &[]);
        assert!(catalog.validate().is_valid);
    }

    // ── candidate properties ────────────────────────────────────────

    #[test]
    fn candidates_have_unique_ids() {
        let a = sample_counterexample(
            10,
            FormalProperty::MergeDeterminism,
            &["fs.read"],
            &[("r", "a")],
            &["m"],
        );
        let b = sample_counterexample(
            11,
            FormalProperty::Monotonicity,
            &["net.send"],
            &[("r", "b")],
            &["n"],
        );
        let catalog = LawMiningCatalog::from_sources(5, &[a, b], &[]);
        let ids: BTreeSet<_> = catalog.candidates.iter().map(|c| &c.candidate_id).collect();
        assert_eq!(ids.len(), catalog.candidates.len());
    }

    #[test]
    fn candidates_are_ranked_descending() {
        let a = sample_counterexample(
            20,
            FormalProperty::MergeDeterminism,
            &["fs.read", "net.send"],
            &[("x", "1")],
            &["m-a", "m-b"],
        );
        let b = sample_counterexample(
            21,
            FormalProperty::MergeDeterminism,
            &["fs.read", "net.send"],
            &[("x", "1")],
            &["m-a", "m-b"],
        );
        let evidence = sample_evidence_entry(
            "trace-rank",
            DecisionType::SecurityAction,
            "policy-rank",
            &["quorum"],
            &["posterior"],
        );
        let catalog = LawMiningCatalog::from_sources(5, &[a, b], &[evidence]);
        for window in catalog.candidates.windows(2) {
            assert!(
                window[0].rank_millionths >= window[1].rank_millionths,
                "candidates should be ranked descending"
            );
        }
    }

    // ── validation error cases ──────────────────────────────────────

    #[test]
    fn validation_catches_empty_candidate_id() {
        let mut catalog = LawMiningCatalog::from_sources(
            1,
            &[sample_counterexample(
                30,
                FormalProperty::MergeDeterminism,
                &["x"],
                &[("k", "v")],
                &["m"],
            )],
            &[],
        );
        if let Some(first) = catalog.candidates.first_mut() {
            first.candidate_id = String::new();
        }
        assert!(!catalog.validate().is_valid);
    }

    // ── provenance index ────────────────────────────────────────────

    #[test]
    fn provenance_records_reference_valid_candidates() {
        let cx = sample_counterexample(
            40,
            FormalProperty::NonInterference,
            &["fs.read"],
            &[("r", "v")],
            &["m"],
        );
        let catalog = LawMiningCatalog::from_sources(7, &[cx], &[]);
        let candidate_ids: BTreeSet<_> = catalog
            .candidates
            .iter()
            .map(|c| &c.provenance_id)
            .collect();
        for record in &catalog.provenance_index {
            assert!(
                candidate_ids.contains(&record.provenance_id),
                "orphan provenance: {}",
                record.provenance_id
            );
        }
    }

    // ── serde round-trips ───────────────────────────────────────────

    #[test]
    fn catalog_serde_round_trip() {
        let cx = sample_counterexample(
            50,
            FormalProperty::MergeDeterminism,
            &["cache.lookup"],
            &[("board", "declared")],
            &["m-a"],
        );
        let catalog = LawMiningCatalog::from_sources(9, &[cx], &[]);
        let json = serde_json::to_string(&catalog).unwrap();
        let back: LawMiningCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(catalog, back);
    }

    // ── artifact context ────────────────────────────────────────────

    #[test]
    fn artifact_context_defaults_are_reasonable() {
        let ctx = ArtifactContext::new("/tmp/test-law-mining");
        assert!(ctx.run_id.starts_with("run-"));
        assert!(!ctx.trace_id.is_empty());
        assert!(!ctx.decision_id.is_empty());
        assert!(!ctx.command_invocation.is_empty());
    }

    // ── CandidateKind variant count and ordering ─────────────────────

    #[test]
    fn candidate_kind_has_three_variants() {
        let variants = [
            CandidateKind::Invariant,
            CandidateKind::SideCondition,
            CandidateKind::NormalForm,
        ];
        let unique: BTreeSet<CandidateKind> = variants.iter().copied().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn candidate_kind_debug_contains_variant_name() {
        assert_eq!(format!("{:?}", CandidateKind::Invariant), "Invariant");
        assert_eq!(
            format!("{:?}", CandidateKind::SideCondition),
            "SideCondition"
        );
        assert_eq!(format!("{:?}", CandidateKind::NormalForm), "NormalForm");
    }

    #[test]
    fn candidate_kind_ord_is_declaration_order() {
        assert!(CandidateKind::Invariant < CandidateKind::SideCondition);
        assert!(CandidateKind::SideCondition < CandidateKind::NormalForm);
    }

    // ── ProvenanceSourceKind properties ──────────────────────────────

    #[test]
    fn provenance_source_kind_has_two_variants() {
        let variants = [
            ProvenanceSourceKind::Counterexample,
            ProvenanceSourceKind::EvidenceEntry,
        ];
        let unique: BTreeSet<ProvenanceSourceKind> = variants.iter().copied().collect();
        assert_eq!(unique.len(), 2);
    }

    #[test]
    fn provenance_source_kind_debug_format() {
        assert_eq!(
            format!("{:?}", ProvenanceSourceKind::Counterexample),
            "Counterexample"
        );
        assert_eq!(
            format!("{:?}", ProvenanceSourceKind::EvidenceEntry),
            "EvidenceEntry"
        );
    }

    // ── hashed_id determinism ────────────────────────────────────────

    #[test]
    fn hashed_id_is_deterministic_for_same_input() {
        let first = hashed_id("test", &["alpha", "beta"]);
        let second = hashed_id("test", &["alpha", "beta"]);
        assert_eq!(first, second);
    }

    #[test]
    fn hashed_id_starts_with_prefix() {
        let result = hashed_id("scope", &["some-data"]);
        assert!(result.starts_with("scope-"), "got: {result}");
    }

    #[test]
    fn hashed_id_differs_for_different_inputs() {
        let id_a = hashed_id("law", &["invariant", "statement-a"]);
        let id_b = hashed_id("law", &["invariant", "statement-b"]);
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn hashed_id_differs_for_different_prefixes() {
        let id_a = hashed_id("law", &["data"]);
        let id_b = hashed_id("prov", &["data"]);
        assert_ne!(id_a, id_b);
    }

    // ── LawMiningValidation serde ────────────────────────────────────

    #[test]
    fn law_mining_validation_serde_round_trip() {
        let validation = LawMiningValidation {
            is_valid: true,
            candidate_count: 5,
            provenance_count: 3,
            scope_count: 2,
            warnings: vec!["test warning".to_string()],
        };
        let json = serde_json::to_string(&validation).unwrap();
        let back: LawMiningValidation = serde_json::from_str(&json).unwrap();
        assert_eq!(validation, back);
    }

    // ── LawMiningEvent serde ─────────────────────────────────────────

    #[test]
    fn law_mining_event_serde_round_trip() {
        let event = LawMiningEvent {
            schema_version: LAW_MINING_EVENT_STREAM_SCHEMA_VERSION.to_string(),
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: "policy-1".to_string(),
            component: LAW_MINING_COMPONENT.to_string(),
            event: "catalog_mined".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            detail: "test detail".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: LawMiningEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn law_mining_event_with_error_code_serde_round_trip() {
        let event = LawMiningEvent {
            schema_version: LAW_MINING_EVENT_STREAM_SCHEMA_VERSION.to_string(),
            trace_id: "trace-err".to_string(),
            decision_id: "decision-err".to_string(),
            policy_id: "policy-err".to_string(),
            component: LAW_MINING_COMPONENT.to_string(),
            event: "mining_failed".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("E_HASH_MISMATCH".to_string()),
            detail: "hash did not match".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: LawMiningEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.error_code, Some("E_HASH_MISMATCH".to_string()));
    }

    // ── TraceIdsArtifact serde ───────────────────────────────────────

    #[test]
    fn trace_ids_artifact_serde_round_trip() {
        let trace_ids = TraceIdsArtifact {
            schema_version: LAW_MINING_TRACE_IDS_SCHEMA_VERSION.to_string(),
            trace_id: "trace-42".to_string(),
            decision_id: "decision-42".to_string(),
            policy_id: "policy-42".to_string(),
            run_id: "run-42".to_string(),
        };
        let json = serde_json::to_string(&trace_ids).unwrap();
        let back: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(trace_ids, back);
    }

    // ── LawMiningEnvArtifact serde ───────────────────────────────────

    #[test]
    fn law_mining_env_artifact_serde_round_trip() {
        let env_artifact = LawMiningEnvArtifact {
            schema_version: LAW_MINING_ENV_SCHEMA_VERSION.to_string(),
            run_id: "run-env-1".to_string(),
            generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            source_commit: "abc123".to_string(),
            toolchain: "nightly-2026-01-01".to_string(),
        };
        let json = serde_json::to_string(&env_artifact).unwrap();
        let back: LawMiningEnvArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(env_artifact, back);
    }

    // ── ArtifactHashRecord serde ─────────────────────────────────────

    #[test]
    fn artifact_hash_record_serde_round_trip() {
        let record = ArtifactHashRecord {
            path: "candidate_law_catalog.json".to_string(),
            sha256: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ArtifactHashRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    // ── LawMiningFixture serde ───────────────────────────────────────

    #[test]
    fn default_fixture_has_counterexamples_and_evidence() {
        let fixture = default_fixture();
        assert!(!fixture.counterexamples.is_empty());
        assert!(!fixture.evidence_entries.is_empty());
        assert!(fixture.generated_epoch > 0);
    }

    // ── catalog.candidate lookup ─────────────────────────────────────

    #[test]
    fn catalog_candidate_lookup_returns_none_for_missing_id() {
        let catalog = LawMiningCatalog::from_sources(1, &[], &[]);
        assert!(catalog.candidate("nonexistent-id").is_none());
    }

    #[test]
    fn catalog_candidate_lookup_returns_some_for_existing_id() {
        let cx = sample_counterexample(
            60,
            FormalProperty::MergeDeterminism,
            &["fs.read"],
            &[("k", "v")],
            &["m"],
        );
        let catalog = LawMiningCatalog::from_sources(9, &[cx], &[]);
        let first_id = &catalog.candidates[0].candidate_id;
        assert!(catalog.candidate(first_id).is_some());
    }

    // ── normal form hypothesis generation ────────────────────────────

    #[test]
    fn counterexample_with_merge_path_produces_normal_form_hypothesis() {
        let cx = sample_counterexample(
            70,
            FormalProperty::MergeDeterminism,
            &["fs.read"],
            &[("region", "eu")],
            &["step-a", "step-b"],
        );
        let catalog = LawMiningCatalog::from_sources(11, &[cx], &[]);
        assert!(
            !catalog.normal_form_hypotheses.is_empty(),
            "merge-path counterexample should produce a normal-form hypothesis"
        );
        let nfh = &catalog.normal_form_hypotheses[0];
        assert!(!nfh.canonical_form.is_empty());
        assert!(!nfh.merge_shapes.is_empty());
        // Round-trip the hypothesis
        let json = serde_json::to_string(&nfh).unwrap();
        let back: NormalFormHypothesis = serde_json::from_str(&json).unwrap();
        assert_eq!(*nfh, back);
    }

    // ── invariant seed generation ────────────────────────────────────

    #[test]
    fn counterexample_produces_invariant_seed() {
        let cx = sample_counterexample(
            80,
            FormalProperty::Monotonicity,
            &["net.send"],
            &[("zone", "internal")],
            &["path-x"],
        );
        let catalog = LawMiningCatalog::from_sources(13, &[cx], &[]);
        assert!(
            !catalog.invariant_seed_ledger.is_empty(),
            "counterexample should produce at least one invariant seed"
        );
        let seed = &catalog.invariant_seed_ledger[0];
        assert!(!seed.statement.is_empty());
        // Round-trip the seed
        let json = serde_json::to_string(&seed).unwrap();
        let back: InvariantSeed = serde_json::from_str(&json).unwrap();
        assert_eq!(*seed, back);
    }

    // ── scope hypothesis frontier_only flag ──────────────────────────

    #[test]
    fn scope_hypothesis_frontier_only_true_when_only_counterexamples() {
        let cx = sample_counterexample(
            90,
            FormalProperty::NonInterference,
            &["cache.store"],
            &[("tier", "hot")],
            &["merge-1"],
        );
        let catalog = LawMiningCatalog::from_sources(15, &[cx], &[]);
        // All scope hypotheses from pure counterexample input should be frontier_only
        for scope in &catalog.scope_hypotheses {
            assert!(
                scope.frontier_only,
                "scope {} should be frontier_only when only counterexamples are present",
                scope.scope_id
            );
        }
    }

    #[test]
    fn scope_hypothesis_frontier_only_false_when_evidence_present() {
        let evidence = sample_evidence_entry(
            "trace-frontier",
            DecisionType::ContractEvaluation,
            "policy-frontier",
            &["constraint-a"],
            &["witness-a"],
        );
        let catalog = LawMiningCatalog::from_sources(15, &[], &[evidence]);
        for scope in &catalog.scope_hypotheses {
            assert!(
                !scope.frontier_only,
                "scope {} should not be frontier_only when evidence is present",
                scope.scope_id
            );
        }
    }

    // ── render_summary for empty catalog ─────────────────────────────

    #[test]
    fn render_summary_for_empty_catalog_omits_top_candidate() {
        let catalog = LawMiningCatalog::from_sources(1, &[], &[]);
        let summary = render_summary(&catalog);
        assert!(summary.contains("# Law Mining Summary"));
        assert!(summary.contains("candidates: 0"));
        assert!(!summary.contains("## Top Candidate"));
    }

    // ── push_strings helper ──────────────────────────────────────────

    #[test]
    fn push_strings_appends_with_separator() {
        let mut data = Vec::new();
        push_strings(&mut data, &["alpha".to_string(), "beta".to_string()]);
        // Each string followed by 0xff separator
        assert!(data.contains(&0xff));
        assert!(data.starts_with(b"alpha"));
    }

    #[test]
    fn push_strings_empty_input_produces_empty_output() {
        let mut data = Vec::new();
        push_strings(&mut data, &[]);
        assert!(data.is_empty());
    }

    // ── validation detects unsorted candidates ───────────────────────

    #[test]
    fn validation_detects_unsorted_candidates() {
        let cx_a = sample_counterexample(
            100,
            FormalProperty::MergeDeterminism,
            &["fs.read", "net.send"],
            &[("r", "a")],
            &["m-a", "m-b"],
        );
        let cx_b = sample_counterexample(
            101,
            FormalProperty::MergeDeterminism,
            &["fs.read", "net.send"],
            &[("r", "a")],
            &["m-a", "m-b"],
        );
        let mut catalog = LawMiningCatalog::from_sources(5, &[cx_a, cx_b], &[]);
        // Reverse the candidates to break sort order
        catalog.candidates.reverse();
        // Only flag unsorted if the reversed order is actually different
        if catalog.candidates.len() >= 2
            && catalog.candidates[0].rank_millionths < catalog.candidates[1].rank_millionths
        {
            let validation = catalog.validate();
            assert!(
                !validation.is_valid || validation.warnings.iter().any(|w| w.contains("sorted")),
                "validation should detect unsorted candidates"
            );
        }
    }

    // ── BundleWriteReport serde ──────────────────────────────────────

    #[test]
    fn bundle_write_report_serde_round_trip() {
        let report = BundleWriteReport {
            artifact_dir: PathBuf::from("/tmp/test"),
            candidate_law_catalog_path: PathBuf::from("/tmp/test/catalog.json"),
            invariant_seed_ledger_path: PathBuf::from("/tmp/test/seeds.json"),
            normal_form_hypotheses_path: PathBuf::from("/tmp/test/normal.json"),
            provenance_index_path: PathBuf::from("/tmp/test/prov.json"),
            scope_hypotheses_path: PathBuf::from("/tmp/test/scope.json"),
            trace_ids_path: PathBuf::from("/tmp/test/trace.json"),
            run_manifest_path: PathBuf::from("/tmp/test/manifest.json"),
            events_path: PathBuf::from("/tmp/test/events.jsonl"),
            commands_path: PathBuf::from("/tmp/test/commands.txt"),
            env_path: PathBuf::from("/tmp/test/env.json"),
            artifact_index_path: PathBuf::from("/tmp/test/index.json"),
            repro_lock_path: PathBuf::from("/tmp/test/repro.lock"),
            summary_path: PathBuf::from("/tmp/test/summary.md"),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: BundleWriteReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // ── LawMiningArtifactIndex serde ─────────────────────────────────

    #[test]
    fn law_mining_artifact_index_serde_round_trip() {
        let index = LawMiningArtifactIndex {
            schema_version: LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION.to_string(),
            bead_id: LAW_MINING_BEAD_ID.to_string(),
            run_id: "run-test-idx".to_string(),
            artifacts: vec![
                ArtifactHashRecord {
                    path: "catalog.json".to_string(),
                    sha256: "aabbcc".to_string(),
                },
                ArtifactHashRecord {
                    path: "seeds.json".to_string(),
                    sha256: "ddeeff".to_string(),
                },
            ],
        };
        let json = serde_json::to_string(&index).unwrap();
        let back: LawMiningArtifactIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(index, back);
    }

    // ── LawProvenanceSource recompute_hash determinism ───────────────

    #[test]
    fn law_provenance_source_recompute_hash_is_deterministic() {
        let mut source_a = LawProvenanceSource {
            source_kind: ProvenanceSourceKind::Counterexample,
            source_id: "src-1".to_string(),
            policy_ids: vec!["pol-a".to_string()],
            formal_properties: vec![FormalProperty::MergeDeterminism],
            decision_types: vec![],
            support_summary: "summary".to_string(),
            source_hash: ContentHash::compute(b"placeholder"),
        };
        let mut source_b = source_a.clone();
        source_a.recompute_hash();
        source_b.recompute_hash();
        assert_eq!(source_a.source_hash, source_b.source_hash);
    }

    // ── LawCandidate serde ───────────────────────────────────────────

    #[test]
    fn law_candidate_serde_round_trip() {
        let cx = sample_counterexample(
            110,
            FormalProperty::PrecedenceStability,
            &["sched.tick"],
            &[("region", "west")],
            &["merge-q"],
        );
        let catalog = LawMiningCatalog::from_sources(17, &[cx], &[]);
        for candidate in &catalog.candidates {
            let json = serde_json::to_string(candidate).unwrap();
            let back: LawCandidate = serde_json::from_str(&json).unwrap();
            assert_eq!(*candidate, back);
        }
    }

    // ── LawProvenanceRecord serde ────────────────────────────────────

    #[test]
    fn law_provenance_record_serde_round_trip() {
        let cx = sample_counterexample(
            120,
            FormalProperty::MergeDeterminism,
            &["io.read"],
            &[("env", "staging")],
            &["path-1"],
        );
        let catalog = LawMiningCatalog::from_sources(19, &[cx], &[]);
        for record in &catalog.provenance_index {
            let json = serde_json::to_string(record).unwrap();
            let back: LawProvenanceRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(*record, back);
        }
    }

    // ── CandidateScopeHypothesis serde ───────────────────────────────

    #[test]
    fn candidate_scope_hypothesis_serde_round_trip() {
        let cx = sample_counterexample(
            130,
            FormalProperty::Monotonicity,
            &["cache.evict"],
            &[("lane", "hot")],
            &["step-1"],
        );
        let catalog = LawMiningCatalog::from_sources(21, &[cx], &[]);
        for scope in &catalog.scope_hypotheses {
            let json = serde_json::to_string(scope).unwrap();
            let back: CandidateScopeHypothesis = serde_json::from_str(&json).unwrap();
            assert_eq!(*scope, back);
        }
    }
}
