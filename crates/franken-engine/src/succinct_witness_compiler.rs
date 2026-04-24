//! Succinct Witness Compiler and Merklized Evidence Packing.
//!
//! Compiles full-fidelity runtime/compiler evidence into compact witness
//! objects that remain sufficient for replay, verification, and legal/audit
//! review.  Implements merklized packing with chunk-level inclusion proofs
//! and deterministic reconstruction from witness packs + referenced artifacts.
//!
//! Plan reference: FRX-17.3 (Succinct Witness Compiler).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::proof_obligations::ObligationCategory;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

pub const SCHEMA_VERSION: &str = "franken-engine.succinct-witness.v1";
pub const DEFAULT_MAX_CHUNK_BYTES: usize = 4096;
pub const MIN_SUFFICIENCY_SCORE: i64 = 800_000;

// ---------------------------------------------------------------------------
// SufficiencyDimension
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SufficiencyDimension {
    ReplayCompleteness,
    VerificationCoverage,
    LegalRetention,
    CausalOrdering,
    ProvenanceBinding,
}

impl SufficiencyDimension {
    pub const ALL: [Self; 5] = [
        Self::ReplayCompleteness,
        Self::VerificationCoverage,
        Self::LegalRetention,
        Self::CausalOrdering,
        Self::ProvenanceBinding,
    ];
}

impl fmt::Display for SufficiencyDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReplayCompleteness => write!(f, "replay_completeness"),
            Self::VerificationCoverage => write!(f, "verification_coverage"),
            Self::LegalRetention => write!(f, "legal_retention"),
            Self::CausalOrdering => write!(f, "causal_ordering"),
            Self::ProvenanceBinding => write!(f, "provenance_binding"),
        }
    }
}

// ---------------------------------------------------------------------------
// SufficiencyConstraint
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SufficiencyConstraint {
    pub dimension: SufficiencyDimension,
    pub min_score_millionths: i64,
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// WitnessSchema
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSchema {
    pub schema_id: String,
    pub name: String,
    pub payload_families: BTreeSet<String>,
    pub constraints: Vec<SufficiencyConstraint>,
    pub required_fields: BTreeSet<String>,
    pub obligation_categories: BTreeSet<String>,
    pub epoch: SecurityEpoch,
}

impl WitnessSchema {
    pub fn compute_id(&self) -> String {
        let mut h = Sha256::new();
        // Length-prefix all variable-length fields to prevent hash collisions
        // between distinct schemas that produce the same byte concatenation.
        let lp = |h: &mut Sha256, s: &[u8]| {
            h.update((s.len() as u64).to_le_bytes());
            h.update(s);
        };
        lp(&mut h, self.name.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update((self.payload_families.len() as u64).to_le_bytes());
        for fam in &self.payload_families {
            lp(&mut h, fam.as_bytes());
        }
        h.update((self.constraints.len() as u64).to_le_bytes());
        for c in &self.constraints {
            lp(&mut h, c.dimension.to_string().as_bytes());
            h.update(c.min_score_millionths.to_le_bytes());
        }
        h.update((self.required_fields.len() as u64).to_le_bytes());
        for f in &self.required_fields {
            lp(&mut h, f.as_bytes());
        }
        format!("ws-{}", hex::encode(&h.finalize()[..16]))
    }

    pub fn validate_sufficiency(&self, cert: &SufficiencyCertificate) -> SufficiencyResult {
        let mut failing = Vec::new();
        let mut min_score = MILLION;
        for constraint in &self.constraints {
            let score = cert
                .dimension_scores
                .get(&constraint.dimension.to_string())
                .copied()
                .unwrap_or(0);
            if score < constraint.min_score_millionths {
                failing.push(SufficiencyViolation {
                    dimension: constraint.dimension,
                    required_millionths: constraint.min_score_millionths,
                    actual_millionths: score,
                });
            }
            if score < min_score {
                min_score = score;
            }
        }
        SufficiencyResult {
            satisfied: failing.is_empty(),
            min_score_millionths: min_score,
            violations: failing,
        }
    }
}

// ---------------------------------------------------------------------------
// SufficiencyCertificate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SufficiencyCertificate {
    pub certificate_id: String,
    pub witness_pack_id: String,
    pub schema_id: String,
    pub dimension_scores: BTreeMap<String, i64>,
    pub overall_score_millionths: i64,
    pub all_satisfied: bool,
    pub epoch: SecurityEpoch,
}

impl SufficiencyCertificate {
    pub fn compute_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.witness_pack_id.as_bytes());
        h.update(self.schema_id.as_bytes());
        for (dim, score) in &self.dimension_scores {
            h.update(dim.as_bytes());
            h.update(score.to_le_bytes());
        }
        format!("sc-{}", hex::encode(&h.finalize()[..16]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SufficiencyResult {
    pub satisfied: bool,
    pub min_score_millionths: i64,
    pub violations: Vec<SufficiencyViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SufficiencyViolation {
    pub dimension: SufficiencyDimension,
    pub required_millionths: i64,
    pub actual_millionths: i64,
}

// ---------------------------------------------------------------------------
// EvidenceChunk
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceChunk {
    pub index: usize,
    pub content_hash: String,
    pub payload_family: String,
    pub size_bytes: usize,
    pub payload: Vec<u8>,
}

impl EvidenceChunk {
    pub fn new(index: usize, payload_family: &str, payload: Vec<u8>) -> Self {
        let content_hash = {
            let mut h = Sha256::new();
            h.update(&payload);
            hex::encode(h.finalize())
        };
        let size_bytes = payload.len();
        Self {
            index,
            content_hash,
            payload_family: payload_family.to_string(),
            size_bytes,
            payload,
        }
    }

    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"leaf:");
        h.update(self.index.to_le_bytes());
        h.update(self.content_hash.as_bytes());
        h.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Merkle helpers
// ---------------------------------------------------------------------------

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"node:");
    h.update(left);
    h.update(right);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// MerkleTree
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleTree {
    pub leaf_count: usize,
    pub levels: Vec<Vec<[u8; 32]>>,
    pub root_hash: [u8; 32],
}

impl MerkleTree {
    pub fn build(leaves: &[[u8; 32]]) -> Self {
        if leaves.is_empty() {
            return Self {
                leaf_count: 0,
                levels: vec![vec![]],
                root_hash: [0u8; 32],
            };
        }
        let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
        levels.push(leaves.to_vec());
        let mut current = leaves.to_vec();
        while current.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(hash_pair(&current[i], &current[i + 1]));
                } else {
                    next.push(current[i]);
                }
                i += 2;
            }
            levels.push(next.clone());
            current = next;
        }
        Self {
            leaf_count: leaves.len(),
            levels,
            root_hash: current[0],
        }
    }

    pub fn inclusion_proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaf_count {
            return None;
        }
        let mut siblings = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            if sibling_idx < level.len() {
                siblings.push(ProofStep {
                    hash: level[sibling_idx],
                    is_right: idx.is_multiple_of(2),
                });
            }
            idx /= 2;
        }
        Some(InclusionProof {
            leaf_index: index,
            leaf_hash: self.levels[0][index],
            siblings,
            root_hash: self.root_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// InclusionProof / ProofStep
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    pub hash: [u8; 32],
    pub is_right: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: usize,
    pub leaf_hash: [u8; 32],
    pub siblings: Vec<ProofStep>,
    pub root_hash: [u8; 32],
}

impl InclusionProof {
    pub fn verify(&self) -> bool {
        self.verify_against(&self.root_hash)
    }

    pub fn verify_against(&self, root: &[u8; 32]) -> bool {
        let mut current = self.leaf_hash;
        for step in &self.siblings {
            current = if step.is_right {
                hash_pair(&current, &step.hash)
            } else {
                hash_pair(&step.hash, &current)
            };
        }
        current == *root
    }
}

// ---------------------------------------------------------------------------
// ProvenanceAttachment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceAttachment {
    pub toolchain_hash: String,
    pub git_hash: String,
    pub environment_hash: String,
    pub collection_epoch: SecurityEpoch,
    pub packed_at: String,
    pub legal_summary: Option<String>,
}

impl ProvenanceAttachment {
    pub fn content_hash(&self) -> String {
        let mut h = Sha256::new();
        let lp = |h: &mut Sha256, s: &[u8]| {
            h.update((s.len() as u64).to_le_bytes());
            h.update(s);
        };
        lp(&mut h, self.toolchain_hash.as_bytes());
        lp(&mut h, self.git_hash.as_bytes());
        lp(&mut h, self.environment_hash.as_bytes());
        h.update(self.collection_epoch.as_u64().to_le_bytes());
        lp(&mut h, self.packed_at.as_bytes());
        match &self.legal_summary {
            Some(ls) => {
                h.update([1u8]);
                lp(&mut h, ls.as_bytes());
            }
            None => h.update([0u8]),
        }
        hex::encode(h.finalize())
    }
}

// ---------------------------------------------------------------------------
// ReconstructionKind / ReconstructionHint
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconstructionKind {
    Inline,
    ContentAddressed,
    DeterministicReplay,
    Hybrid,
}

impl fmt::Display for ReconstructionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline => write!(f, "inline"),
            Self::ContentAddressed => write!(f, "content_addressed"),
            Self::DeterministicReplay => write!(f, "deterministic_replay"),
            Self::Hybrid => write!(f, "hybrid"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructionHint {
    pub chunk_index: usize,
    pub kind: ReconstructionKind,
    pub artifact_hash: Option<String>,
    pub replay_session_id: Option<String>,
}

// ---------------------------------------------------------------------------
// WitnessPack / ChunkManifestEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessPack {
    pub pack_id: String,
    pub schema_id: String,
    pub epoch: SecurityEpoch,
    pub merkle_root: String,
    pub chunk_count: usize,
    pub total_bytes: usize,
    pub chunk_manifest: Vec<ChunkManifestEntry>,
    pub provenance: ProvenanceAttachment,
    pub reconstruction_hints: Vec<ReconstructionHint>,
    pub payload_families: BTreeSet<String>,
    pub sufficiency_certificate: Option<SufficiencyCertificate>,
    pub obligation_categories: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkManifestEntry {
    pub index: usize,
    pub content_hash: String,
    pub payload_family: String,
    pub size_bytes: usize,
    pub leaf_hash: String,
}

impl WitnessPack {
    pub fn compute_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.merkle_root.as_bytes());
        h.update(self.schema_id.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update(self.provenance.content_hash().as_bytes());
        format!("wp-{}", hex::encode(&h.finalize()[..16]))
    }

    pub fn families(&self) -> Vec<String> {
        self.payload_families.iter().cloned().collect()
    }

    pub fn covers_obligation(&self, category: &ObligationCategory) -> bool {
        self.obligation_categories
            .contains(&format!("{category:?}"))
    }
}

// ---------------------------------------------------------------------------
// WitnessCompiler
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct WitnessCompiler {
    schema: WitnessSchema,
    max_chunk_bytes: usize,
    chunks: Vec<EvidenceChunk>,
    provenance: Option<ProvenanceAttachment>,
    hints: Vec<ReconstructionHint>,
    obligation_categories: BTreeSet<String>,
}

impl WitnessCompiler {
    pub fn new(schema: WitnessSchema) -> Self {
        Self {
            schema,
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            chunks: Vec::new(),
            provenance: None,
            hints: Vec::new(),
            obligation_categories: BTreeSet::new(),
        }
    }

    pub fn max_chunk_bytes(mut self, max: usize) -> Self {
        self.max_chunk_bytes = max;
        self
    }

    pub fn add_chunk(mut self, payload_family: &str, payload: Vec<u8>) -> Self {
        let index = self.chunks.len();
        self.chunks
            .push(EvidenceChunk::new(index, payload_family, payload));
        self
    }

    pub fn with_reconstruction(mut self, kind: ReconstructionKind) -> Self {
        let index = self.chunks.len().saturating_sub(1);
        self.hints.push(ReconstructionHint {
            chunk_index: index,
            kind,
            artifact_hash: None,
            replay_session_id: None,
        });
        self
    }

    pub fn with_content_addressed_reconstruction(mut self, artifact_hash: &str) -> Self {
        let index = self.chunks.len().saturating_sub(1);
        self.hints.push(ReconstructionHint {
            chunk_index: index,
            kind: ReconstructionKind::ContentAddressed,
            artifact_hash: Some(artifact_hash.to_string()),
            replay_session_id: None,
        });
        self
    }

    pub fn provenance(mut self, provenance: ProvenanceAttachment) -> Self {
        self.provenance = Some(provenance);
        self
    }

    pub fn obligation_category(mut self, category: ObligationCategory) -> Self {
        self.obligation_categories.insert(format!("{category:?}"));
        self
    }

    pub fn compile(self, epoch: SecurityEpoch) -> Result<CompilationResult, CompilationError> {
        if self.chunks.is_empty() {
            return Err(CompilationError::NoEvidence);
        }
        let provenance = self.provenance.ok_or(CompilationError::MissingProvenance)?;
        for chunk in &self.chunks {
            if chunk.size_bytes > self.max_chunk_bytes {
                return Err(CompilationError::ChunkTooLarge {
                    index: chunk.index,
                    size: chunk.size_bytes,
                    max: self.max_chunk_bytes,
                });
            }
        }

        let leaf_hashes: Vec<[u8; 32]> = self.chunks.iter().map(|c| c.leaf_hash()).collect();
        let tree = MerkleTree::build(&leaf_hashes);
        let merkle_root = hex::encode(tree.root_hash);

        let chunk_manifest: Vec<ChunkManifestEntry> = self
            .chunks
            .iter()
            .map(|c| ChunkManifestEntry {
                index: c.index,
                content_hash: c.content_hash.clone(),
                payload_family: c.payload_family.clone(),
                size_bytes: c.size_bytes,
                leaf_hash: hex::encode(c.leaf_hash()),
            })
            .collect();

        let payload_families: BTreeSet<String> = self
            .chunks
            .iter()
            .map(|c| c.payload_family.clone())
            .collect();
        let total_bytes: usize = self.chunks.iter().map(|c| c.size_bytes).sum();

        let mut pack = WitnessPack {
            pack_id: String::new(),
            schema_id: self.schema.schema_id.clone(),
            epoch,
            merkle_root,
            chunk_count: self.chunks.len(),
            total_bytes,
            chunk_manifest,
            provenance,
            reconstruction_hints: self.hints,
            payload_families,
            sufficiency_certificate: None,
            obligation_categories: self.obligation_categories,
        };
        pack.pack_id = pack.compute_id();

        let inclusion_proofs: Vec<InclusionProof> = (0..self.chunks.len())
            .filter_map(|i| tree.inclusion_proof(i))
            .collect();

        Ok(CompilationResult {
            pack,
            tree,
            inclusion_proofs,
            chunks: self.chunks,
        })
    }
}

// ---------------------------------------------------------------------------
// CompilationResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationResult {
    pub pack: WitnessPack,
    pub tree: MerkleTree,
    pub inclusion_proofs: Vec<InclusionProof>,
    pub chunks: Vec<EvidenceChunk>,
}

impl CompilationResult {
    pub fn proof_for_chunk(&self, index: usize) -> Option<&InclusionProof> {
        self.inclusion_proofs.get(index)
    }

    pub fn verify_all_proofs(&self) -> bool {
        self.inclusion_proofs
            .iter()
            .all(|p| p.verify_against(&self.tree.root_hash))
    }

    pub fn certify_sufficiency(
        &self,
        schema: &WitnessSchema,
        dimension_scores: BTreeMap<String, i64>,
    ) -> SufficiencyCertificate {
        let overall = dimension_scores.values().copied().min().unwrap_or(0);
        let all_satisfied = schema.constraints.iter().all(|c| {
            dimension_scores
                .get(&c.dimension.to_string())
                .copied()
                .unwrap_or(0)
                >= c.min_score_millionths
        });
        let mut cert = SufficiencyCertificate {
            certificate_id: String::new(),
            witness_pack_id: self.pack.pack_id.clone(),
            schema_id: schema.schema_id.clone(),
            dimension_scores,
            overall_score_millionths: overall,
            all_satisfied,
            epoch: self.pack.epoch,
        };
        cert.certificate_id = cert.compute_id();
        cert
    }
}

// ---------------------------------------------------------------------------
// CompilationError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompilationError {
    NoEvidence,
    MissingProvenance,
    ChunkTooLarge {
        index: usize,
        size: usize,
        max: usize,
    },
}

impl fmt::Display for CompilationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEvidence => write!(f, "no evidence chunks provided"),
            Self::MissingProvenance => write!(f, "missing provenance attachment"),
            Self::ChunkTooLarge { index, size, max } => {
                write!(f, "chunk {index} is {size} bytes, max is {max}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PackVerifier
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PackVerifier;

impl PackVerifier {
    pub fn verify_result(result: &CompilationResult) -> PackVerificationResult {
        let mut issues = Vec::new();
        if result.pack.merkle_root != hex::encode(result.tree.root_hash) {
            issues.push("merkle root mismatch".to_string());
        }
        for (i, proof) in result.inclusion_proofs.iter().enumerate() {
            if !proof.verify_against(&result.tree.root_hash) {
                issues.push(format!("inclusion proof {i} failed verification"));
            }
        }
        if result.pack.chunk_count != result.chunks.len() {
            issues.push(format!(
                "chunk count mismatch: pack={}, actual={}",
                result.pack.chunk_count,
                result.chunks.len()
            ));
        }
        for (i, entry) in result.pack.chunk_manifest.iter().enumerate() {
            if i < result.chunks.len() && entry.content_hash != result.chunks[i].content_hash {
                issues.push(format!("manifest entry {i} content hash mismatch"));
            }
        }
        if result.pack.pack_id != result.pack.compute_id() {
            issues.push("pack_id is not deterministic".to_string());
        }
        PackVerificationResult {
            valid: issues.is_empty(),
            issues,
        }
    }

    pub fn verify_inclusion(proof: &InclusionProof, root: &str) -> bool {
        let Ok(b) = hex::decode(root) else {
            return false;
        };
        if b.len() != 32 {
            return false;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b);
        proof.verify_against(&arr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackVerificationResult {
    pub valid: bool,
    pub issues: Vec<String>,
}

// ---------------------------------------------------------------------------
// WitnessPackReport
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessPackReport {
    pub report_id: String,
    pub schema_version: String,
    pub pack_ids: Vec<String>,
    pub total_chunks: usize,
    pub total_bytes: usize,
    pub all_valid: bool,
    pub pack_results: Vec<PackReportEntry>,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackReportEntry {
    pub pack_id: String,
    pub chunk_count: usize,
    pub total_bytes: usize,
    pub payload_families: Vec<String>,
    pub valid: bool,
    pub issues: Vec<String>,
    pub sufficiency_score: Option<i64>,
}

impl WitnessPackReport {
    pub fn compute_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.schema_version.as_bytes());
        for id in &self.pack_ids {
            h.update(id.as_bytes());
        }
        h.update(self.total_chunks.to_le_bytes());
        h.update(self.total_bytes.to_le_bytes());
        h.update(if self.all_valid { &[1u8] } else { &[0u8] });
        hex::encode(h.finalize())
    }
}

pub fn generate_report(results: &[&CompilationResult]) -> WitnessPackReport {
    let mut pack_ids = Vec::new();
    let mut total_chunks = 0usize;
    let mut total_bytes = 0usize;
    let mut all_valid = true;
    let mut pack_results = Vec::new();

    for result in results {
        let v = PackVerifier::verify_result(result);
        if !v.valid {
            all_valid = false;
        }
        pack_ids.push(result.pack.pack_id.clone());
        total_chunks += result.pack.chunk_count;
        total_bytes += result.pack.total_bytes;
        pack_results.push(PackReportEntry {
            pack_id: result.pack.pack_id.clone(),
            chunk_count: result.pack.chunk_count,
            total_bytes: result.pack.total_bytes,
            payload_families: result.pack.families(),
            valid: v.valid,
            issues: v.issues,
            sufficiency_score: result
                .pack
                .sufficiency_certificate
                .as_ref()
                .map(|c| c.overall_score_millionths),
        });
    }

    let mut report = WitnessPackReport {
        report_id: String::new(),
        schema_version: SCHEMA_VERSION.to_string(),
        pack_ids,
        total_chunks,
        total_bytes,
        all_valid,
        pack_results,
        content_hash: String::new(),
    };
    report.content_hash = report.compute_hash();
    report.report_id = format!("wpr-{}", &report.content_hash[..32]);
    report
}

// ---------------------------------------------------------------------------
// Canonical witness schemas
// ---------------------------------------------------------------------------

pub fn canonical_witness_schemas(epoch: SecurityEpoch) -> Vec<WitnessSchema> {
    [
        ("Decision Witness Schema", "decision"),
        ("Replay Witness Schema", "replay"),
        ("Optimization Witness Schema", "optimization"),
        ("Security Witness Schema", "security"),
        ("Legal Provenance Witness Schema", "legal_provenance"),
    ]
    .iter()
    .map(|(name, family)| {
        let mut schema = WitnessSchema {
            schema_id: String::new(),
            name: name.to_string(),
            payload_families: {
                let mut s = BTreeSet::new();
                s.insert(family.to_string());
                s
            },
            constraints: vec![
                SufficiencyConstraint {
                    dimension: SufficiencyDimension::ReplayCompleteness,
                    min_score_millionths: MIN_SUFFICIENCY_SCORE,
                    rationale: "witness must support replay".into(),
                },
                SufficiencyConstraint {
                    dimension: SufficiencyDimension::VerificationCoverage,
                    min_score_millionths: 700_000,
                    rationale: "formal verification coverage".into(),
                },
                SufficiencyConstraint {
                    dimension: SufficiencyDimension::CausalOrdering,
                    min_score_millionths: 900_000,
                    rationale: "causal order preserved".into(),
                },
                SufficiencyConstraint {
                    dimension: SufficiencyDimension::ProvenanceBinding,
                    min_score_millionths: 850_000,
                    rationale: "provenance metadata required".into(),
                },
                SufficiencyConstraint {
                    dimension: SufficiencyDimension::LegalRetention,
                    min_score_millionths: 750_000,
                    rationale: "legal retention requirements".into(),
                },
            ],
            required_fields: {
                let mut s = BTreeSet::new();
                s.insert("epoch".into());
                s.insert("merkle_root".into());
                s.insert("provenance".into());
                s
            },
            obligation_categories: BTreeSet::new(),
            epoch,
        };
        schema.schema_id = schema.compute_id();
        schema
    })
    .collect()
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

    fn test_provenance() -> ProvenanceAttachment {
        ProvenanceAttachment {
            toolchain_hash: "abc123".into(),
            git_hash: "def456".into(),
            environment_hash: "ghi789".into(),
            collection_epoch: test_epoch(),
            packed_at: "2026-02-25T00:00:00Z".into(),
            legal_summary: None,
        }
    }

    fn test_schema() -> WitnessSchema {
        let mut schema = WitnessSchema {
            schema_id: String::new(),
            name: "test-schema".into(),
            payload_families: {
                let mut s = BTreeSet::new();
                s.insert("decision".into());
                s
            },
            constraints: vec![
                SufficiencyConstraint {
                    dimension: SufficiencyDimension::ReplayCompleteness,
                    min_score_millionths: 800_000,
                    rationale: "test".into(),
                },
                SufficiencyConstraint {
                    dimension: SufficiencyDimension::VerificationCoverage,
                    min_score_millionths: 700_000,
                    rationale: "test".into(),
                },
            ],
            required_fields: {
                let mut s = BTreeSet::new();
                s.insert("epoch".into());
                s
            },
            obligation_categories: BTreeSet::new(),
            epoch: test_epoch(),
        };
        schema.schema_id = schema.compute_id();
        schema
    }

    #[test]
    fn sufficiency_dimension_all_five() {
        assert_eq!(SufficiencyDimension::ALL.len(), 5);
    }

    #[test]
    fn sufficiency_dimension_display() {
        assert_eq!(
            SufficiencyDimension::ReplayCompleteness.to_string(),
            "replay_completeness"
        );
        assert_eq!(
            SufficiencyDimension::ProvenanceBinding.to_string(),
            "provenance_binding"
        );
    }

    #[test]
    fn sufficiency_dimension_serde_roundtrip() {
        for dim in &SufficiencyDimension::ALL {
            let json = serde_json::to_string(dim).expect("serde deserialization should succeed");
            let back: SufficiencyDimension =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*dim, back);
        }
    }

    #[test]
    fn schema_id_deterministic() {
        let s1 = test_schema();
        let s2 = test_schema();
        assert_eq!(s1.schema_id, s2.schema_id);
        assert!(s1.schema_id.starts_with("ws-"));
    }

    #[test]
    fn schema_validate_sufficiency_pass() {
        let schema = test_schema();
        let mut scores = BTreeMap::new();
        scores.insert("replay_completeness".into(), 900_000);
        scores.insert("verification_coverage".into(), 800_000);
        let cert = SufficiencyCertificate {
            certificate_id: String::new(),
            witness_pack_id: "wp-test".into(),
            schema_id: schema.schema_id.clone(),
            dimension_scores: scores,
            overall_score_millionths: 800_000,
            all_satisfied: true,
            epoch: test_epoch(),
        };
        let result = schema.validate_sufficiency(&cert);
        assert!(result.satisfied);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn schema_validate_sufficiency_fail() {
        let schema = test_schema();
        let mut scores = BTreeMap::new();
        scores.insert("replay_completeness".into(), 500_000);
        scores.insert("verification_coverage".into(), 800_000);
        let cert = SufficiencyCertificate {
            certificate_id: String::new(),
            witness_pack_id: "wp-test".into(),
            schema_id: schema.schema_id.clone(),
            dimension_scores: scores,
            overall_score_millionths: 500_000,
            all_satisfied: false,
            epoch: test_epoch(),
        };
        let result = schema.validate_sufficiency(&cert);
        assert!(!result.satisfied);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0].dimension,
            SufficiencyDimension::ReplayCompleteness
        );
    }

    #[test]
    fn schema_serde_roundtrip() {
        let schema = test_schema();
        let json = serde_json::to_string(&schema).expect("serde deserialization should succeed");
        let back: WitnessSchema =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(schema, back);
    }

    #[test]
    fn evidence_chunk_new() {
        let chunk = EvidenceChunk::new(0, "decision", b"hello world".to_vec());
        assert_eq!(chunk.index, 0);
        assert_eq!(chunk.payload_family, "decision");
        assert_eq!(chunk.size_bytes, 11);
        assert!(!chunk.content_hash.is_empty());
    }

    #[test]
    fn evidence_chunk_leaf_hash_deterministic() {
        let c1 = EvidenceChunk::new(0, "decision", b"test".to_vec());
        let c2 = EvidenceChunk::new(0, "decision", b"test".to_vec());
        assert_eq!(c1.leaf_hash(), c2.leaf_hash());
    }

    #[test]
    fn evidence_chunk_different_payload_different_hash() {
        let c1 = EvidenceChunk::new(0, "decision", b"alpha".to_vec());
        let c2 = EvidenceChunk::new(0, "decision", b"beta".to_vec());
        assert_ne!(c1.leaf_hash(), c2.leaf_hash());
    }

    #[test]
    fn merkle_tree_empty() {
        let tree = MerkleTree::build(&[]);
        assert_eq!(tree.leaf_count, 0);
        assert_eq!(tree.root_hash, [0u8; 32]);
    }

    #[test]
    fn merkle_tree_single_leaf() {
        let leaf = EvidenceChunk::new(0, "decision", b"only".to_vec()).leaf_hash();
        let tree = MerkleTree::build(&[leaf]);
        assert_eq!(tree.leaf_count, 1);
        assert_eq!(tree.root_hash, leaf);
    }

    #[test]
    fn merkle_tree_two_leaves() {
        let l1 = EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash();
        let l2 = EvidenceChunk::new(1, "b", b"two".to_vec()).leaf_hash();
        let tree = MerkleTree::build(&[l1, l2]);
        assert_eq!(tree.root_hash, hash_pair(&l1, &l2));
    }

    #[test]
    fn merkle_tree_odd_leaves() {
        let l1 = EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash();
        let l2 = EvidenceChunk::new(1, "b", b"two".to_vec()).leaf_hash();
        let l3 = EvidenceChunk::new(2, "c", b"three".to_vec()).leaf_hash();
        let tree = MerkleTree::build(&[l1, l2, l3]);
        assert_eq!(tree.root_hash, hash_pair(&hash_pair(&l1, &l2), &l3));
    }

    #[test]
    fn merkle_tree_four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| EvidenceChunk::new(i, "x", format!("data{i}").into_bytes()).leaf_hash())
            .collect();
        let tree = MerkleTree::build(&leaves);
        assert_eq!(
            tree.root_hash,
            hash_pair(
                &hash_pair(&leaves[0], &leaves[1]),
                &hash_pair(&leaves[2], &leaves[3])
            )
        );
    }

    #[test]
    fn merkle_tree_deterministic() {
        let leaves: Vec<[u8; 32]> = (0..5)
            .map(|i| EvidenceChunk::new(i, "t", vec![i as u8; 10]).leaf_hash())
            .collect();
        assert_eq!(
            MerkleTree::build(&leaves).root_hash,
            MerkleTree::build(&leaves).root_hash
        );
    }

    #[test]
    fn inclusion_proof_single_leaf() {
        let leaf = EvidenceChunk::new(0, "a", b"only".to_vec()).leaf_hash();
        let tree = MerkleTree::build(&[leaf]);
        let proof = tree
            .inclusion_proof(0)
            .expect("serde deserialization should succeed");
        assert!(proof.verify());
    }

    #[test]
    fn inclusion_proof_two_leaves() {
        let l1 = EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash();
        let l2 = EvidenceChunk::new(1, "b", b"two".to_vec()).leaf_hash();
        let tree = MerkleTree::build(&[l1, l2]);
        assert!(
            tree.inclusion_proof(0)
                .expect("serde deserialization should succeed")
                .verify()
        );
        assert!(
            tree.inclusion_proof(1)
                .expect("serde deserialization should succeed")
                .verify()
        );
    }

    #[test]
    fn inclusion_proof_four_leaves_all_verify() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| EvidenceChunk::new(i, "x", format!("d{i}").into_bytes()).leaf_hash())
            .collect();
        let tree = MerkleTree::build(&leaves);
        for i in 0..4 {
            assert!(
                tree.inclusion_proof(i)
                    .expect("serde deserialization should succeed")
                    .verify(),
                "proof for leaf {i} failed"
            );
        }
    }

    #[test]
    fn inclusion_proof_out_of_bounds() {
        let tree = MerkleTree::build(&[EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash()]);
        assert!(tree.inclusion_proof(1).is_none());
    }

    #[test]
    fn inclusion_proof_wrong_root_fails() {
        let l1 = EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash();
        let l2 = EvidenceChunk::new(1, "b", b"two".to_vec()).leaf_hash();
        let tree = MerkleTree::build(&[l1, l2]);
        assert!(
            !tree
                .inclusion_proof(0)
                .expect("serde deserialization should succeed")
                .verify_against(&[0xFFu8; 32])
        );
    }

    #[test]
    fn inclusion_proof_serde_roundtrip() {
        let l1 = EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash();
        let l2 = EvidenceChunk::new(1, "b", b"two".to_vec()).leaf_hash();
        let tree = MerkleTree::build(&[l1, l2]);
        let proof = tree
            .inclusion_proof(0)
            .expect("serde deserialization should succeed");
        let back: InclusionProof = serde_json::from_str(
            &serde_json::to_string(&proof).expect("serde deserialization should succeed"),
        )
        .expect("serde deserialization should succeed");
        assert_eq!(proof, back);
        assert!(back.verify());
    }

    #[test]
    fn provenance_content_hash_deterministic() {
        assert_eq!(
            test_provenance().content_hash(),
            test_provenance().content_hash()
        );
    }

    #[test]
    fn provenance_content_hash_changes_with_data() {
        let mut p2 = test_provenance();
        p2.toolchain_hash = "different".into();
        assert_ne!(test_provenance().content_hash(), p2.content_hash());
    }

    #[test]
    fn provenance_serde_roundtrip() {
        let prov = test_provenance();
        let back: ProvenanceAttachment = serde_json::from_str(
            &serde_json::to_string(&prov).expect("serde deserialization should succeed"),
        )
        .expect("serde deserialization should succeed");
        assert_eq!(prov, back);
    }

    #[test]
    fn reconstruction_kind_display() {
        assert_eq!(ReconstructionKind::Inline.to_string(), "inline");
        assert_eq!(
            ReconstructionKind::ContentAddressed.to_string(),
            "content_addressed"
        );
        assert_eq!(
            ReconstructionKind::DeterministicReplay.to_string(),
            "deterministic_replay"
        );
        assert_eq!(ReconstructionKind::Hybrid.to_string(), "hybrid");
    }

    #[test]
    fn reconstruction_kind_serde_roundtrip() {
        for kind in [
            ReconstructionKind::Inline,
            ReconstructionKind::ContentAddressed,
            ReconstructionKind::DeterministicReplay,
            ReconstructionKind::Hybrid,
        ] {
            let back: ReconstructionKind = serde_json::from_str(
                &serde_json::to_string(&kind).expect("serde deserialization should succeed"),
            )
            .expect("serde deserialization should succeed");
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn compiler_single_chunk() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"evidence data".to_vec())
            .with_reconstruction(ReconstructionKind::Inline)
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        assert_eq!(result.pack.chunk_count, 1);
        assert!(result.pack.pack_id.starts_with("wp-"));
        assert!(result.verify_all_proofs());
    }

    #[test]
    fn compiler_multiple_chunks() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"chunk one".to_vec())
            .add_chunk("replay", b"chunk two".to_vec())
            .add_chunk("security", b"chunk three".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        assert_eq!(result.pack.chunk_count, 3);
        assert_eq!(result.inclusion_proofs.len(), 3);
        assert!(result.verify_all_proofs());
    }

    #[test]
    fn compiler_no_evidence_fails() {
        assert_eq!(
            WitnessCompiler::new(test_schema())
                .provenance(test_provenance())
                .compile(test_epoch())
                .unwrap_err(),
            CompilationError::NoEvidence
        );
    }

    #[test]
    fn compiler_missing_provenance_fails() {
        assert_eq!(
            WitnessCompiler::new(test_schema())
                .add_chunk("decision", b"data".to_vec())
                .compile(test_epoch())
                .unwrap_err(),
            CompilationError::MissingProvenance
        );
    }

    #[test]
    fn compiler_chunk_too_large_fails() {
        let err = WitnessCompiler::new(test_schema())
            .max_chunk_bytes(50)
            .add_chunk("decision", vec![0u8; 100])
            .provenance(test_provenance())
            .compile(test_epoch())
            .unwrap_err();
        assert!(matches!(err, CompilationError::ChunkTooLarge { .. }));
    }

    #[test]
    fn compiler_pack_id_deterministic() {
        let build = || {
            WitnessCompiler::new(test_schema())
                .add_chunk("decision", b"same data".to_vec())
                .provenance(test_provenance())
                .compile(test_epoch())
                .expect("serde deserialization should succeed")
        };
        assert_eq!(build().pack.pack_id, build().pack.pack_id);
    }

    #[test]
    fn compiler_content_addressed_reconstruction() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"evidence".to_vec())
            .with_content_addressed_reconstruction("abc123def456")
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        assert_eq!(result.pack.reconstruction_hints.len(), 1);
        assert_eq!(
            result.pack.reconstruction_hints[0].kind,
            ReconstructionKind::ContentAddressed
        );
        assert_eq!(
            result.pack.reconstruction_hints[0].artifact_hash.as_deref(),
            Some("abc123def456")
        );
    }

    #[test]
    fn compiler_obligation_categories() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"data".to_vec())
            .obligation_category(ObligationCategory::Safety)
            .obligation_category(ObligationCategory::BehavioralPreservation)
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        assert!(result.pack.covers_obligation(&ObligationCategory::Safety));
        assert!(
            result
                .pack
                .covers_obligation(&ObligationCategory::BehavioralPreservation)
        );
        assert!(!result.pack.covers_obligation(&ObligationCategory::Liveness));
    }

    #[test]
    fn compiler_payload_families_collected() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"d".to_vec())
            .add_chunk("replay", b"r".to_vec())
            .add_chunk("decision", b"d2".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        assert_eq!(result.pack.families(), vec!["decision", "replay"]);
    }

    #[test]
    fn witness_pack_serde_roundtrip() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"data".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let back: WitnessPack = serde_json::from_str(
            &serde_json::to_string(&result.pack).expect("serde deserialization should succeed"),
        )
        .expect("serde deserialization should succeed");
        assert_eq!(result.pack, back);
    }

    #[test]
    fn verifier_valid_result() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"hello".to_vec())
            .add_chunk("replay", b"world".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let v = PackVerifier::verify_result(&result);
        assert!(v.valid);
        assert!(v.issues.is_empty());
    }

    #[test]
    fn verifier_inclusion_against_hex_root() {
        let l1 = EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash();
        let l2 = EvidenceChunk::new(1, "b", b"two".to_vec()).leaf_hash();
        let tree = MerkleTree::build(&[l1, l2]);
        let proof = tree
            .inclusion_proof(0)
            .expect("serde deserialization should succeed");
        assert!(PackVerifier::verify_inclusion(
            &proof,
            &hex::encode(tree.root_hash)
        ));
        assert!(!PackVerifier::verify_inclusion(&proof, "badhex"));
    }

    #[test]
    fn certificate_id_deterministic() {
        let cert = SufficiencyCertificate {
            certificate_id: String::new(),
            witness_pack_id: "wp-test".into(),
            schema_id: "ws-test".into(),
            dimension_scores: {
                let mut m = BTreeMap::new();
                m.insert("replay_completeness".into(), 900_000);
                m
            },
            overall_score_millionths: 900_000,
            all_satisfied: true,
            epoch: test_epoch(),
        };
        assert_eq!(cert.compute_id(), cert.compute_id());
        assert!(cert.compute_id().starts_with("sc-"));
    }

    #[test]
    fn certify_sufficiency_from_result() {
        let schema = test_schema();
        let result = WitnessCompiler::new(schema.clone())
            .add_chunk("decision", b"data".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let mut scores = BTreeMap::new();
        scores.insert("replay_completeness".into(), 950_000);
        scores.insert("verification_coverage".into(), 800_000);
        let cert = result.certify_sufficiency(&schema, scores);
        assert!(cert.all_satisfied);
        assert_eq!(cert.overall_score_millionths, 800_000);
    }

    #[test]
    fn compilation_error_display() {
        assert_eq!(
            CompilationError::NoEvidence.to_string(),
            "no evidence chunks provided"
        );
        assert_eq!(
            CompilationError::MissingProvenance.to_string(),
            "missing provenance attachment"
        );
        assert_eq!(
            CompilationError::ChunkTooLarge {
                index: 3,
                size: 8000,
                max: 4096
            }
            .to_string(),
            "chunk 3 is 8000 bytes, max is 4096"
        );
    }

    #[test]
    fn report_empty() {
        let report = generate_report(&[]);
        assert!(report.all_valid);
        assert_eq!(report.total_chunks, 0);
        assert!(report.report_id.starts_with("wpr-"));
    }

    #[test]
    fn report_single_pack() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"evidence".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let report = generate_report(&[&result]);
        assert!(report.all_valid);
        assert_eq!(report.total_chunks, 1);
    }

    #[test]
    fn report_multiple_packs() {
        let r1 = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"pack one".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let r2 = WitnessCompiler::new(test_schema())
            .add_chunk("replay", b"pack two a".to_vec())
            .add_chunk("security", b"pack two b".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let report = generate_report(&[&r1, &r2]);
        assert!(report.all_valid);
        assert_eq!(report.total_chunks, 3);
    }

    #[test]
    fn report_hash_deterministic() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"data".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        assert_eq!(
            generate_report(&[&result]).content_hash,
            generate_report(&[&result]).content_hash
        );
    }

    #[test]
    fn report_serde_roundtrip() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"data".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let report = generate_report(&[&result]);
        let back: WitnessPackReport = serde_json::from_str(
            &serde_json::to_string(&report).expect("serde deserialization should succeed"),
        )
        .expect("serde deserialization should succeed");
        assert_eq!(report, back);
    }

    #[test]
    fn canonical_schemas_five_families() {
        let schemas = canonical_witness_schemas(test_epoch());
        assert_eq!(schemas.len(), 5);
        for s in &schemas {
            assert!(s.schema_id.starts_with("ws-"));
            assert_eq!(s.constraints.len(), 5);
        }
    }

    #[test]
    fn canonical_schema_ids_unique() {
        let schemas = canonical_witness_schemas(test_epoch());
        let ids: BTreeSet<String> = schemas.iter().map(|s| s.schema_id.clone()).collect();
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn merkle_tree_32_leaves_all_proofs_verify() {
        let leaves: Vec<[u8; 32]> = (0..32)
            .map(|i| EvidenceChunk::new(i, "x", vec![i as u8; 20]).leaf_hash())
            .collect();
        let tree = MerkleTree::build(&leaves);
        for i in 0..32 {
            assert!(
                tree.inclusion_proof(i)
                    .expect("serde deserialization should succeed")
                    .verify(),
                "proof for leaf {i} failed"
            );
        }
    }

    #[test]
    fn full_compilation_and_verification_pipeline() {
        let schema = test_schema();
        let result = WitnessCompiler::new(schema.clone())
            .add_chunk("decision", b"routing evidence".to_vec())
            .with_reconstruction(ReconstructionKind::Inline)
            .add_chunk("replay", b"replay transcript".to_vec())
            .with_reconstruction(ReconstructionKind::DeterministicReplay)
            .add_chunk("security", b"capability grant log".to_vec())
            .with_content_addressed_reconstruction("hash-of-full-log")
            .obligation_category(ObligationCategory::Safety)
            .obligation_category(ObligationCategory::BehavioralPreservation)
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        assert!(result.verify_all_proofs());
        assert!(PackVerifier::verify_result(&result).valid);
        let mut scores = BTreeMap::new();
        for dim in &SufficiencyDimension::ALL {
            scores.insert(dim.to_string(), 900_000);
        }
        let cert = result.certify_sufficiency(&schema, scores);
        assert!(cert.all_satisfied);
        assert!(schema.validate_sufficiency(&cert).satisfied);
        let report = generate_report(&[&result]);
        assert!(report.all_valid);
        assert_eq!(report.total_chunks, 3);
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn sufficiency_dimension_display_all_unique() {
        let displays: BTreeSet<String> = SufficiencyDimension::ALL
            .iter()
            .map(|d| d.to_string())
            .collect();
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn reconstruction_kind_display_all_unique() {
        let displays: BTreeSet<String> = [
            ReconstructionKind::Inline,
            ReconstructionKind::ContentAddressed,
            ReconstructionKind::DeterministicReplay,
            ReconstructionKind::Hybrid,
        ]
        .iter()
        .map(|k| k.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    // ── Enrichment: compilation error serde roundtrip ───────────

    #[test]
    fn compilation_error_serde_all_variants() {
        let variants = [
            CompilationError::NoEvidence,
            CompilationError::MissingProvenance,
            CompilationError::ChunkTooLarge {
                index: 0,
                size: 9999,
                max: 4096,
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let back: CompilationError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*v, back);
        }
    }

    // ── Enrichment: compilation error Display all distinct ──────

    #[test]
    fn compilation_error_display_all_distinct() {
        let errors = [
            CompilationError::NoEvidence,
            CompilationError::MissingProvenance,
            CompilationError::ChunkTooLarge {
                index: 0,
                size: 999,
                max: 512,
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), 3, "all variants produce distinct Display");
    }

    // ── Enrichment: merkle tree with large number of leaves ─────

    #[test]
    fn merkle_tree_63_leaves_all_proofs_verify() {
        let leaves: Vec<[u8; 32]> = (0..63)
            .map(|i| EvidenceChunk::new(i, "x", vec![i as u8; 15]).leaf_hash())
            .collect();
        let tree = MerkleTree::build(&leaves);
        for i in 0..63 {
            assert!(
                tree.inclusion_proof(i)
                    .expect("serde deserialization should succeed")
                    .verify(),
                "proof for leaf {i} failed"
            );
        }
    }

    // ── Enrichment: sufficiency certificate overall score ───────

    #[test]
    fn certify_sufficiency_uses_minimum_score_as_overall() {
        let schema = test_schema();
        let result = WitnessCompiler::new(schema.clone())
            .add_chunk("decision", b"data".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let mut scores = BTreeMap::new();
        scores.insert("replay_completeness".into(), 900_000);
        scores.insert("verification_coverage".into(), 700_000);
        let cert = result.certify_sufficiency(&schema, scores);
        assert_eq!(cert.overall_score_millionths, 700_000);
    }

    // ── Enrichment: provenance with legal_summary ───────────────

    #[test]
    fn provenance_with_legal_summary_serde_roundtrip() {
        let mut prov = test_provenance();
        prov.legal_summary = Some("Retained per 7-year policy".into());
        let json = serde_json::to_string(&prov).expect("serde deserialization should succeed");
        let back: ProvenanceAttachment =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(prov, back);
        assert_eq!(
            back.legal_summary,
            Some("Retained per 7-year policy".into())
        );
    }

    // ── Enrichment: evidence chunk size calculation ──────────────

    #[test]
    fn evidence_chunk_size_bytes_matches_data_length() {
        let data = vec![0u8; 512];
        let chunk = EvidenceChunk::new(0, "test", data.clone());
        assert_eq!(chunk.size_bytes, 512);
    }

    // ── Enrichment: schema version constant ─────────────────────

    #[test]
    fn schema_version_constant_matches() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.succinct-witness.v1");
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    // ── Serde roundtrips for remaining types ─────────────────────

    #[test]
    fn sufficiency_constraint_serde_roundtrip() {
        let sc = SufficiencyConstraint {
            dimension: SufficiencyDimension::CausalOrdering,
            min_score_millionths: 850_000,
            rationale: "causal chain must be intact".into(),
        };
        let json = serde_json::to_string(&sc).expect("serde deserialization should succeed");
        let back: SufficiencyConstraint =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(sc, back);
    }

    #[test]
    fn sufficiency_result_serde_roundtrip() {
        let sr = SufficiencyResult {
            satisfied: false,
            min_score_millionths: 400_000,
            violations: vec![SufficiencyViolation {
                dimension: SufficiencyDimension::LegalRetention,
                required_millionths: 750_000,
                actual_millionths: 400_000,
            }],
        };
        let json = serde_json::to_string(&sr).expect("serde deserialization should succeed");
        let back: SufficiencyResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(sr, back);
    }

    #[test]
    fn sufficiency_violation_serde_roundtrip() {
        let sv = SufficiencyViolation {
            dimension: SufficiencyDimension::ProvenanceBinding,
            required_millionths: 850_000,
            actual_millionths: 0,
        };
        let json = serde_json::to_string(&sv).expect("serde deserialization should succeed");
        let back: SufficiencyViolation =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(sv, back);
    }

    #[test]
    fn evidence_chunk_serde_roundtrip() {
        let chunk = EvidenceChunk::new(7, "security", b"payload bytes".to_vec());
        let json = serde_json::to_string(&chunk).expect("serde deserialization should succeed");
        let back: EvidenceChunk =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(chunk, back);
    }

    #[test]
    fn merkle_tree_serde_roundtrip() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| EvidenceChunk::new(i, "x", vec![i as u8; 10]).leaf_hash())
            .collect();
        let tree = MerkleTree::build(&leaves);
        let json = serde_json::to_string(&tree).expect("serde deserialization should succeed");
        let back: MerkleTree =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(tree, back);
    }

    #[test]
    fn proof_step_serde_roundtrip() {
        let step = ProofStep {
            hash: [0xAB; 32],
            is_right: true,
        };
        let json = serde_json::to_string(&step).expect("serde deserialization should succeed");
        let back: ProofStep =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(step, back);
    }

    #[test]
    fn reconstruction_hint_serde_roundtrip() {
        let hint = ReconstructionHint {
            chunk_index: 3,
            kind: ReconstructionKind::Hybrid,
            artifact_hash: Some("abc123".into()),
            replay_session_id: Some("sess-99".into()),
        };
        let json = serde_json::to_string(&hint).expect("serde deserialization should succeed");
        let back: ReconstructionHint =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(hint, back);
    }

    #[test]
    fn chunk_manifest_entry_serde_roundtrip() {
        let entry = ChunkManifestEntry {
            index: 2,
            content_hash: "deadbeef".into(),
            payload_family: "decision".into(),
            size_bytes: 256,
            leaf_hash: "cafebabe".into(),
        };
        let json = serde_json::to_string(&entry).expect("serde deserialization should succeed");
        let back: ChunkManifestEntry =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(entry, back);
    }

    #[test]
    fn pack_report_entry_serde_roundtrip() {
        let entry = PackReportEntry {
            pack_id: "wp-test".into(),
            chunk_count: 3,
            total_bytes: 1024,
            payload_families: vec!["decision".into(), "replay".into()],
            valid: true,
            issues: vec![],
            sufficiency_score: Some(900_000),
        };
        let json = serde_json::to_string(&entry).expect("serde deserialization should succeed");
        let back: PackReportEntry =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(entry, back);
    }

    #[test]
    fn pack_verification_result_serde_roundtrip() {
        let pvr = PackVerificationResult {
            valid: false,
            issues: vec!["merkle root mismatch".into()],
        };
        let json = serde_json::to_string(&pvr).expect("serde deserialization should succeed");
        let back: PackVerificationResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(pvr, back);
    }

    #[test]
    fn sufficiency_certificate_serde_roundtrip() {
        let mut scores = BTreeMap::new();
        scores.insert("replay_completeness".into(), 950_000_i64);
        scores.insert("causal_ordering".into(), 880_000);
        let cert = SufficiencyCertificate {
            certificate_id: "sc-abc".into(),
            witness_pack_id: "wp-xyz".into(),
            schema_id: "ws-test".into(),
            dimension_scores: scores,
            overall_score_millionths: 880_000,
            all_satisfied: true,
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&cert).expect("serde deserialization should succeed");
        let back: SufficiencyCertificate =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(cert, back);
    }

    #[test]
    fn compilation_result_serde_roundtrip() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"data".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: CompilationResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
        assert!(back.verify_all_proofs());
    }

    // ── Clone independence ───────────────────────────────────────

    #[test]
    fn witness_schema_clone_independence() {
        let s1 = test_schema();
        let mut s2 = s1.clone();
        s2.name = "mutated".into();
        assert_ne!(s1.name, s2.name);
        assert_eq!(s1.name, "test-schema");
    }

    #[test]
    fn evidence_chunk_clone_independence() {
        let c1 = EvidenceChunk::new(0, "decision", b"original".to_vec());
        let mut c2 = c1.clone();
        c2.payload = b"modified".to_vec();
        assert_eq!(c1.payload, b"original");
        assert_ne!(c1.payload, c2.payload);
    }

    #[test]
    fn provenance_attachment_clone_independence() {
        let p1 = test_provenance();
        let mut p2 = p1.clone();
        p2.git_hash = "changed".into();
        assert_eq!(p1.git_hash, "def456");
        assert_ne!(p1.git_hash, p2.git_hash);
    }

    #[test]
    fn witness_pack_clone_independence() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"data".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let mut pack2 = result.pack.clone();
        pack2.merkle_root = "tampered".into();
        assert_ne!(result.pack.merkle_root, pack2.merkle_root);
    }

    #[test]
    fn compilation_error_clone_independence() {
        let e1 = CompilationError::ChunkTooLarge {
            index: 0,
            size: 5000,
            max: 4096,
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    // ── Ordering / BTreeSet insertion ────────────────────────────

    #[test]
    fn sufficiency_dimension_ord_all_insertable_in_btreeset() {
        let set: BTreeSet<SufficiencyDimension> =
            SufficiencyDimension::ALL.iter().copied().collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn sufficiency_dimension_ord_is_stable() {
        let mut dims = SufficiencyDimension::ALL.to_vec();
        dims.sort();
        let mut dims2 = dims.clone();
        dims2.sort();
        assert_eq!(dims, dims2);
    }

    #[test]
    fn reconstruction_kind_ord_all_insertable_in_btreeset() {
        let set: BTreeSet<ReconstructionKind> = [
            ReconstructionKind::Inline,
            ReconstructionKind::ContentAddressed,
            ReconstructionKind::DeterministicReplay,
            ReconstructionKind::Hybrid,
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn reconstruction_kind_ord_is_stable() {
        let mut kinds = vec![
            ReconstructionKind::Hybrid,
            ReconstructionKind::Inline,
            ReconstructionKind::DeterministicReplay,
            ReconstructionKind::ContentAddressed,
        ];
        kinds.sort();
        let mut kinds2 = kinds.clone();
        kinds2.sort();
        assert_eq!(kinds, kinds2);
    }

    // ── Error handling edge cases ────────────────────────────────

    #[test]
    fn compiler_chunk_exactly_at_max_succeeds() {
        let result = WitnessCompiler::new(test_schema())
            .max_chunk_bytes(64)
            .add_chunk("decision", vec![0u8; 64])
            .provenance(test_provenance())
            .compile(test_epoch());
        assert!(result.is_ok());
    }

    #[test]
    fn compiler_chunk_one_byte_over_max_fails() {
        let err = WitnessCompiler::new(test_schema())
            .max_chunk_bytes(64)
            .add_chunk("decision", vec![0u8; 65])
            .provenance(test_provenance())
            .compile(test_epoch())
            .unwrap_err();
        match err {
            CompilationError::ChunkTooLarge { index, size, max } => {
                assert_eq!(index, 0);
                assert_eq!(size, 65);
                assert_eq!(max, 64);
            }
            _ => panic!("expected ChunkTooLarge"),
        }
    }

    #[test]
    fn compiler_second_chunk_too_large_reports_correct_index() {
        let err = WitnessCompiler::new(test_schema())
            .max_chunk_bytes(100)
            .add_chunk("decision", vec![0u8; 50])
            .add_chunk("replay", vec![0u8; 200])
            .provenance(test_provenance())
            .compile(test_epoch())
            .unwrap_err();
        match err {
            CompilationError::ChunkTooLarge { index, .. } => assert_eq!(index, 1),
            _ => panic!("expected ChunkTooLarge"),
        }
    }

    #[test]
    fn validate_sufficiency_missing_dimension_scores_treated_as_zero() {
        let schema = test_schema();
        let cert = SufficiencyCertificate {
            certificate_id: String::new(),
            witness_pack_id: "wp-test".into(),
            schema_id: schema.schema_id.clone(),
            dimension_scores: BTreeMap::new(),
            overall_score_millionths: 0,
            all_satisfied: false,
            epoch: test_epoch(),
        };
        let result = schema.validate_sufficiency(&cert);
        assert!(!result.satisfied);
        assert_eq!(result.violations.len(), 2);
    }

    #[test]
    fn verifier_inclusion_bad_hex_returns_false() {
        let l1 = EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash();
        let tree = MerkleTree::build(&[l1]);
        let proof = tree
            .inclusion_proof(0)
            .expect("serde deserialization should succeed");
        assert!(!PackVerifier::verify_inclusion(&proof, "not-hex!!"));
    }

    #[test]
    fn verifier_inclusion_wrong_length_hex_returns_false() {
        let l1 = EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash();
        let tree = MerkleTree::build(&[l1]);
        let proof = tree
            .inclusion_proof(0)
            .expect("serde deserialization should succeed");
        // Valid hex but only 16 bytes (not 32)
        assert!(!PackVerifier::verify_inclusion(
            &proof,
            &hex::encode([0u8; 16])
        ));
    }

    // ── Stress scenarios ─────────────────────────────────────────

    #[test]
    fn merkle_tree_128_leaves_stress() {
        let leaves: Vec<[u8; 32]> = (0..128)
            .map(|i| EvidenceChunk::new(i, "s", vec![(i & 0xFF) as u8; 8]).leaf_hash())
            .collect();
        let tree = MerkleTree::build(&leaves);
        assert_eq!(tree.leaf_count, 128);
        // Spot-check first, middle, last
        for &idx in &[0, 63, 127] {
            assert!(
                tree.inclusion_proof(idx)
                    .expect("serde deserialization should succeed")
                    .verify(),
                "proof for leaf {idx} failed"
            );
        }
    }

    #[test]
    fn compiler_many_chunks_stress() {
        let mut compiler = WitnessCompiler::new(test_schema());
        for i in 0..50 {
            compiler = compiler.add_chunk("stress", format!("chunk-{i}").into_bytes());
        }
        let result = compiler
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        assert_eq!(result.pack.chunk_count, 50);
        assert!(result.verify_all_proofs());
        assert!(PackVerifier::verify_result(&result).valid);
    }

    #[test]
    fn report_many_packs_stress() {
        let results: Vec<CompilationResult> = (0..10)
            .map(|i| {
                WitnessCompiler::new(test_schema())
                    .add_chunk("decision", format!("pack-{i}").into_bytes())
                    .provenance(test_provenance())
                    .compile(test_epoch())
                    .expect("serde deserialization should succeed")
            })
            .collect();
        let refs: Vec<&CompilationResult> = results.iter().collect();
        let report = generate_report(&refs);
        assert!(report.all_valid);
        assert_eq!(report.total_chunks, 10);
        assert_eq!(report.pack_results.len(), 10);
    }

    // ── Deterministic replay ─────────────────────────────────────

    #[test]
    fn full_pipeline_deterministic_replay() {
        let build = || {
            let schema = test_schema();
            let result = WitnessCompiler::new(schema.clone())
                .add_chunk("decision", b"evidence-a".to_vec())
                .add_chunk("replay", b"evidence-b".to_vec())
                .with_reconstruction(ReconstructionKind::DeterministicReplay)
                .obligation_category(ObligationCategory::Safety)
                .provenance(test_provenance())
                .compile(test_epoch())
                .expect("serde deserialization should succeed");
            let mut scores = BTreeMap::new();
            scores.insert("replay_completeness".into(), 900_000_i64);
            scores.insert("verification_coverage".into(), 800_000);
            let cert = result.certify_sufficiency(&schema, scores);
            let report = generate_report(&[&result]);
            (result, cert, report)
        };
        let (r1, c1, rpt1) = build();
        let (r2, c2, rpt2) = build();
        assert_eq!(r1.pack.pack_id, r2.pack.pack_id);
        assert_eq!(r1.pack.merkle_root, r2.pack.merkle_root);
        assert_eq!(c1.certificate_id, c2.certificate_id);
        assert_eq!(rpt1.content_hash, rpt2.content_hash);
        assert_eq!(rpt1.report_id, rpt2.report_id);
    }

    #[test]
    fn merkle_root_changes_with_different_data() {
        let r1 = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"alpha".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let r2 = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"beta".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        assert_ne!(r1.pack.merkle_root, r2.pack.merkle_root);
    }

    #[test]
    fn certificate_id_changes_with_different_scores() {
        let schema = test_schema();
        let result = WitnessCompiler::new(schema.clone())
            .add_chunk("decision", b"data".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let mut s1 = BTreeMap::new();
        s1.insert("replay_completeness".into(), 900_000_i64);
        let mut s2 = BTreeMap::new();
        s2.insert("replay_completeness".into(), 800_000_i64);
        let c1 = result.certify_sufficiency(&schema, s1);
        let c2 = result.certify_sufficiency(&schema, s2);
        assert_ne!(c1.certificate_id, c2.certificate_id);
    }

    // ── Default/empty states ─────────────────────────────────────

    #[test]
    fn merkle_tree_empty_inclusion_proof_is_none() {
        let tree = MerkleTree::build(&[]);
        assert!(tree.inclusion_proof(0).is_none());
    }

    #[test]
    fn evidence_chunk_empty_payload() {
        let chunk = EvidenceChunk::new(0, "empty", Vec::new());
        assert_eq!(chunk.size_bytes, 0);
        assert!(!chunk.content_hash.is_empty());
        // Hash of empty data is still deterministic
        let chunk2 = EvidenceChunk::new(0, "empty", Vec::new());
        assert_eq!(chunk.content_hash, chunk2.content_hash);
    }

    #[test]
    fn schema_no_constraints_sufficiency_always_satisfied() {
        let schema = WitnessSchema {
            schema_id: "ws-no-constraints".into(),
            name: "no-constraints".into(),
            payload_families: BTreeSet::new(),
            constraints: vec![],
            required_fields: BTreeSet::new(),
            obligation_categories: BTreeSet::new(),
            epoch: test_epoch(),
        };
        let cert = SufficiencyCertificate {
            certificate_id: String::new(),
            witness_pack_id: "wp-test".into(),
            schema_id: schema.schema_id.clone(),
            dimension_scores: BTreeMap::new(),
            overall_score_millionths: 0,
            all_satisfied: true,
            epoch: test_epoch(),
        };
        let result = schema.validate_sufficiency(&cert);
        assert!(result.satisfied);
        assert!(result.violations.is_empty());
        // min_score defaults to MILLION when no constraints
        assert_eq!(result.min_score_millionths, MILLION);
    }

    #[test]
    fn provenance_no_legal_summary_hash_differs_from_with() {
        let without = test_provenance();
        let mut with_summary = test_provenance();
        with_summary.legal_summary = Some("some legal note".into());
        assert_ne!(without.content_hash(), with_summary.content_hash());
    }

    // ── Schema compute_id sensitivity ────────────────────────────

    #[test]
    fn schema_id_changes_with_name() {
        let s1 = test_schema();
        let mut s2 = test_schema();
        s2.name = "different-name".into();
        s2.schema_id = s2.compute_id();
        assert_ne!(s1.schema_id, s2.schema_id);
    }

    #[test]
    fn schema_id_changes_with_payload_families() {
        let s1 = test_schema();
        let mut s2 = test_schema();
        s2.payload_families.insert("extra_family".into());
        s2.schema_id = s2.compute_id();
        assert_ne!(s1.schema_id, s2.schema_id);
    }

    // ── WitnessPack helpers ──────────────────────────────────────

    #[test]
    fn witness_pack_covers_all_obligation_categories() {
        let mut compiler = WitnessCompiler::new(test_schema()).add_chunk("decision", b"d".to_vec());
        for cat in &ObligationCategory::ALL {
            compiler = compiler.obligation_category(*cat);
        }
        let result = compiler
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        for cat in &ObligationCategory::ALL {
            assert!(result.pack.covers_obligation(cat), "missing {cat:?}");
        }
    }

    #[test]
    fn witness_pack_families_returns_sorted() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("zebra", b"z".to_vec())
            .add_chunk("alpha", b"a".to_vec())
            .add_chunk("middle", b"m".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let fams = result.pack.families();
        assert_eq!(fams, vec!["alpha", "middle", "zebra"]);
    }

    // ── proof_for_chunk ──────────────────────────────────────────

    #[test]
    fn proof_for_chunk_returns_correct_leaf() {
        let result = WitnessCompiler::new(test_schema())
            .add_chunk("a", b"alpha".to_vec())
            .add_chunk("b", b"beta".to_vec())
            .add_chunk("c", b"gamma".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        for i in 0..3 {
            let proof = result
                .proof_for_chunk(i)
                .expect("serde deserialization should succeed");
            assert_eq!(proof.leaf_index, i);
            assert!(proof.verify());
        }
        assert!(result.proof_for_chunk(3).is_none());
    }

    // ── Canonical schemas additional checks ──────────────────────

    #[test]
    fn canonical_schemas_required_fields_include_epoch_and_provenance() {
        let schemas = canonical_witness_schemas(test_epoch());
        for s in &schemas {
            assert!(s.required_fields.contains("epoch"));
            assert!(s.required_fields.contains("merkle_root"));
            assert!(s.required_fields.contains("provenance"));
        }
    }

    #[test]
    fn canonical_schemas_deterministic_across_calls() {
        let s1 = canonical_witness_schemas(test_epoch());
        let s2 = canonical_witness_schemas(test_epoch());
        for (a, b) in s1.iter().zip(s2.iter()) {
            assert_eq!(a.schema_id, b.schema_id);
        }
    }

    // ── hash_pair symmetry / asymmetry ───────────────────────────

    #[test]
    fn hash_pair_is_not_commutative() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(hash_pair(&a, &b), hash_pair(&b, &a));
    }

    #[test]
    fn hash_pair_deterministic() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        assert_eq!(hash_pair(&a, &b), hash_pair(&a, &b));
    }

    // ── Evidence chunk index sensitivity ─────────────────────────

    #[test]
    fn evidence_chunk_different_index_different_leaf_hash() {
        let c0 = EvidenceChunk::new(0, "x", b"same".to_vec());
        let c1 = EvidenceChunk::new(1, "x", b"same".to_vec());
        assert_ne!(c0.leaf_hash(), c1.leaf_hash());
    }

    // ── Report content_hash sensitivity ──────────────────────────

    #[test]
    fn report_content_hash_changes_with_different_packs() {
        let r1 = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"aaa".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let r2 = WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"bbb".to_vec())
            .provenance(test_provenance())
            .compile(test_epoch())
            .expect("serde deserialization should succeed");
        let rpt1 = generate_report(&[&r1]);
        let rpt2 = generate_report(&[&r2]);
        assert_ne!(rpt1.content_hash, rpt2.content_hash);
    }

    // ── Sufficiency violation details ────────────────────────────

    #[test]
    fn sufficiency_violation_captures_exact_scores() {
        let schema = test_schema();
        let mut scores = BTreeMap::new();
        scores.insert("replay_completeness".into(), 799_999_i64);
        scores.insert("verification_coverage".into(), 700_000);
        let cert = SufficiencyCertificate {
            certificate_id: String::new(),
            witness_pack_id: "wp-test".into(),
            schema_id: schema.schema_id.clone(),
            dimension_scores: scores,
            overall_score_millionths: 700_000,
            all_satisfied: false,
            epoch: test_epoch(),
        };
        let result = schema.validate_sufficiency(&cert);
        assert!(!result.satisfied);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].required_millionths, 800_000);
        assert_eq!(result.violations[0].actual_millionths, 799_999);
    }
}
