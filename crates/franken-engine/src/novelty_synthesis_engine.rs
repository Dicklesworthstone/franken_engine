#![forbid(unsafe_code)]

//! Novelty synthesis engine: minimal high-novelty program synthesis for
//! board expansion.
//!
//! Bead: bd-1lsy.8.7.2 [RGC-707B]
//!
//! Synthesizes minimal high-novelty programs, packages, and React apps for
//! board expansion.  This module is the artifact factory for dark matter —
//! creating candidates that are small enough to understand, rich enough to
//! matter, and faithful to ecosystem reality.
//!
//! # Design decisions
//!
//! - Every synthesized candidate is content-addressed: its `content_hash` is
//!   computed deterministically from the serialized source text and metadata
//!   so that identical candidates always produce the same hash.
//! - `SynthesisConstraint` gates candidate admission: AST node budget, byte
//!   budget, minimum novelty threshold, required features, and forbidden
//!   patterns.
//! - `SynthesisBatch` aggregates candidates under a `SecurityEpoch`, tracking
//!   strategy distribution and total novelty yield.
//! - `SynthesisReceipt` records the outcome of a batch, including acceptance
//!   rate and coverage improvement for audit trails.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-707B]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the novelty synthesis engine.
pub const SCHEMA_VERSION: &str = "franken-engine.novelty-synthesis-engine.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.8.7.2";

/// Component name.
pub const COMPONENT: &str = "novelty_synthesis_engine";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-707B";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLIONTHS: u64 = 1_000_000;

/// Default maximum AST nodes per candidate.
pub const DEFAULT_MAX_AST_NODES: u64 = 256;

/// Default maximum source bytes per candidate.
pub const DEFAULT_MAX_BYTES: u64 = 4_096;

/// Default minimum novelty threshold (millionths).  30% = 300_000.
pub const DEFAULT_MIN_NOVELTY: u64 = 300_000;

/// Maximum candidates per batch.
pub const MAX_BATCH_SIZE: usize = 1_024;

/// Number of strategy variants.
pub const STRATEGY_COUNT: usize = 5;

/// Number of program-kind variants.
pub const KIND_COUNT: usize = 6;

// ---------------------------------------------------------------------------
// SynthesisStrategy
// ---------------------------------------------------------------------------

/// How a candidate program was synthesized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynthesisStrategy {
    /// Grammar-guided enumeration from production rules.
    GrammarGuided,
    /// Mutation of an existing seed program.
    MutationBased,
    /// Recombination of fragments from multiple seeds.
    RecombinationBased,
    /// Instantiation of a known template with fresh parameters.
    TemplateDriven,
    /// Targeted synthesis aimed at obstruction-detected coverage gaps.
    ObstructionTargeted,
}

impl SynthesisStrategy {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::GrammarGuided,
        Self::MutationBased,
        Self::RecombinationBased,
        Self::TemplateDriven,
        Self::ObstructionTargeted,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GrammarGuided => "grammar_guided",
            Self::MutationBased => "mutation_based",
            Self::RecombinationBased => "recombination_based",
            Self::TemplateDriven => "template_driven",
            Self::ObstructionTargeted => "obstruction_targeted",
        }
    }

    /// Base novelty multiplier for this strategy (millionths).
    ///
    /// Grammar-guided and obstruction-targeted tend to produce higher
    /// novelty because they explore previously uncovered regions.
    const fn base_novelty_multiplier(self) -> u64 {
        match self {
            Self::GrammarGuided => 800_000,
            Self::MutationBased => 500_000,
            Self::RecombinationBased => 600_000,
            Self::TemplateDriven => 400_000,
            Self::ObstructionTargeted => 900_000,
        }
    }
}

impl fmt::Display for SynthesisStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ProgramKind
// ---------------------------------------------------------------------------

/// Classification of the synthesized program artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramKind {
    /// Plain JavaScript module or script.
    PlainJs,
    /// TypeScript source file.
    TypeScript,
    /// A single React component (function or class).
    ReactComponent,
    /// A multi-file React application skeleton.
    ReactApp,
    /// A Node.js package with `package.json`.
    NodePackage,
    /// A Bun-specific package with `bunfig.toml`.
    BunPackage,
}

impl ProgramKind {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::PlainJs,
        Self::TypeScript,
        Self::ReactComponent,
        Self::ReactApp,
        Self::NodePackage,
        Self::BunPackage,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlainJs => "plain_js",
            Self::TypeScript => "typescript",
            Self::ReactComponent => "react_component",
            Self::ReactApp => "react_app",
            Self::NodePackage => "node_package",
            Self::BunPackage => "bun_package",
        }
    }

    /// Typical minimum AST node count for this kind.
    const fn typical_min_nodes(self) -> u64 {
        match self {
            Self::PlainJs => 3,
            Self::TypeScript => 5,
            Self::ReactComponent => 8,
            Self::ReactApp => 20,
            Self::NodePackage => 10,
            Self::BunPackage => 10,
        }
    }

    /// File extension hint for the primary source file.
    pub const fn file_extension(self) -> &'static str {
        match self {
            Self::PlainJs => ".js",
            Self::TypeScript => ".ts",
            Self::ReactComponent | Self::ReactApp => ".tsx",
            Self::NodePackage | Self::BunPackage => ".js",
        }
    }
}

impl fmt::Display for ProgramKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SynthesisConstraint
// ---------------------------------------------------------------------------

/// Budget and quality constraints for candidate synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisConstraint {
    /// Maximum AST nodes permitted in the candidate.
    pub max_ast_nodes: u64,
    /// Maximum source bytes permitted.
    pub max_bytes: u64,
    /// Minimum novelty score (millionths) to accept the candidate.
    pub min_novelty_millionths: u64,
    /// Feature keywords that must appear in the candidate.
    pub required_features: BTreeSet<String>,
    /// Pattern strings that must NOT appear in the candidate.
    pub forbidden_patterns: BTreeSet<String>,
}

impl SynthesisConstraint {
    /// Create a new constraint with the given limits and no feature/pattern
    /// restrictions.
    pub fn new(max_ast_nodes: u64, max_bytes: u64, min_novelty_millionths: u64) -> Self {
        Self {
            max_ast_nodes,
            max_bytes,
            min_novelty_millionths,
            required_features: BTreeSet::new(),
            forbidden_patterns: BTreeSet::new(),
        }
    }

    /// Add a required feature.
    pub fn require_feature(&mut self, feature: impl Into<String>) {
        self.required_features.insert(feature.into());
    }

    /// Add a forbidden pattern.
    pub fn forbid_pattern(&mut self, pattern: impl Into<String>) {
        self.forbidden_patterns.insert(pattern.into());
    }

    /// Whether `ast_node_count` fits within the budget.
    pub fn nodes_within_budget(&self, ast_node_count: u64) -> bool {
        ast_node_count <= self.max_ast_nodes
    }

    /// Whether `byte_count` fits within the budget.
    pub fn bytes_within_budget(&self, byte_count: u64) -> bool {
        byte_count <= self.max_bytes
    }

    /// Whether a novelty score meets the threshold.
    pub fn novelty_sufficient(&self, novelty_millionths: u64) -> bool {
        novelty_millionths >= self.min_novelty_millionths
    }

    /// Check if a source text contains any forbidden patterns.
    pub fn contains_forbidden(&self, source: &str) -> Option<String> {
        for p in &self.forbidden_patterns {
            if source.contains(p.as_str()) {
                return Some(p.clone());
            }
        }
        None
    }

    /// Check if a source text satisfies all required features.
    pub fn missing_features(&self, source: &str) -> Vec<String> {
        self.required_features
            .iter()
            .filter(|f| !source.contains(f.as_str()))
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// SynthesizedCandidate
// ---------------------------------------------------------------------------

/// A synthesized program candidate with novelty and coverage metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedCandidate {
    /// Unique identifier for this candidate.
    pub candidate_id: String,
    /// What kind of program this is.
    pub kind: ProgramKind,
    /// How the candidate was synthesized.
    pub strategy: SynthesisStrategy,
    /// The source text of the synthesized program.
    pub source_text: String,
    /// Number of AST nodes in the program.
    pub ast_node_count: u64,
    /// Novelty score (millionths).  Higher is more novel.
    pub novelty_score_millionths: u64,
    /// Estimated coverage delta if this candidate is accepted (millionths).
    pub coverage_delta_millionths: u64,
    /// Board cells this candidate targets.
    pub target_cells: Vec<String>,
    /// Content hash over the candidate metadata.
    pub content_hash: ContentHash,
}

impl SynthesizedCandidate {
    /// Compute a deterministic content hash from the candidate's fields.
    fn compute_hash(
        candidate_id: &str,
        kind: ProgramKind,
        strategy: SynthesisStrategy,
        source_text: &str,
    ) -> ContentHash {
        let mut h = Sha256::new();
        h.update(b"novelty-synthesis-candidate-v1:");
        h.update(candidate_id.as_bytes());
        h.update(b":");
        h.update(kind.as_str().as_bytes());
        h.update(b":");
        h.update(strategy.as_str().as_bytes());
        h.update(b":");
        h.update(source_text.as_bytes());
        ContentHash::compute(&h.finalize())
    }

    /// Whether the candidate's source length is within the given byte limit.
    pub fn source_byte_count(&self) -> u64 {
        self.source_text.len() as u64
    }

    /// Whether the candidate's novelty exceeds the threshold (millionths).
    pub fn exceeds_novelty(&self, threshold: u64) -> bool {
        self.novelty_score_millionths >= threshold
    }
}

// ---------------------------------------------------------------------------
// SynthesisBatch
// ---------------------------------------------------------------------------

/// A batch of synthesized candidates under a single security epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisBatch {
    /// Unique identifier for this batch.
    pub batch_id: String,
    /// Security epoch under which this batch was produced.
    pub epoch: SecurityEpoch,
    /// The candidates in this batch.
    pub candidates: Vec<SynthesizedCandidate>,
    /// Distribution of strategies used (strategy -> count).
    pub strategy_distribution: BTreeMap<SynthesisStrategy, u64>,
    /// Total novelty across all candidates (millionths).
    pub total_novelty_millionths: u64,
}

impl SynthesisBatch {
    /// Number of candidates in this batch.
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Average novelty per candidate (millionths).  Returns 0 if empty.
    pub fn average_novelty_millionths(&self) -> u64 {
        if self.candidates.is_empty() {
            return 0;
        }
        self.total_novelty_millionths
            .checked_div(self.candidates.len() as u64)
            .unwrap_or(0)
    }

    /// Compute the content hash over the entire batch.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(b"novelty-synthesis-batch-v1:");
        h.update(self.batch_id.as_bytes());
        h.update(b":");
        h.update(self.epoch.as_u64().to_le_bytes());
        for c in &self.candidates {
            h.update(c.content_hash.as_bytes());
        }
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// SynthesisReceipt
// ---------------------------------------------------------------------------

/// Receipt recording the outcome of a synthesis batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisReceipt {
    /// Batch this receipt covers.
    pub batch_id: String,
    /// Epoch at which the receipt was issued.
    pub timestamp_epoch: SecurityEpoch,
    /// Number of candidates proposed in the batch.
    pub candidates_proposed: u64,
    /// Number of candidates accepted after filtering.
    pub candidates_accepted: u64,
    /// Total novelty yield of accepted candidates (millionths).
    pub novelty_yield_millionths: u64,
    /// Coverage improvement contributed by accepted candidates (millionths).
    pub coverage_improvement_millionths: u64,
    /// Content hash over the receipt metadata.
    pub content_hash: ContentHash,
}

impl SynthesisReceipt {
    /// Acceptance rate (millionths).  Returns 0 if none proposed.
    pub fn acceptance_rate_millionths(&self) -> u64 {
        self.candidates_accepted
            .saturating_mul(MILLIONTHS)
            .checked_div(self.candidates_proposed)
            .unwrap_or(0)
    }

    /// Whether all candidates were accepted.
    pub fn all_accepted(&self) -> bool {
        self.candidates_proposed > 0 && self.candidates_accepted == self.candidates_proposed
    }

    /// Whether no candidates were accepted.
    pub fn none_accepted(&self) -> bool {
        self.candidates_accepted == 0
    }
}

// ---------------------------------------------------------------------------
// SynthesisDenialReason
// ---------------------------------------------------------------------------

/// Reason a candidate was denied admission to the board.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynthesisDenialReason {
    /// Candidate's novelty score is below the minimum threshold.
    InsufficientNovelty,
    /// Candidate exceeds the AST node or byte budget.
    TooComplex,
    /// Candidate source contains a forbidden pattern.
    ForbiddenPattern,
    /// Candidate is a content-hash duplicate of an existing artifact.
    DuplicateCandidate,
    /// Candidate's coverage delta is zero — it covers nothing new.
    CoverageRedundant,
    /// The synthesis budget (time or candidate count) is exhausted.
    BudgetExhausted,
    /// The selected strategy has been exhausted for this kind.
    StrategyExhausted,
    /// Candidate targets an ecosystem kind that doesn't match constraints.
    EcosystemMismatch,
}

impl SynthesisDenialReason {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::InsufficientNovelty,
        Self::TooComplex,
        Self::ForbiddenPattern,
        Self::DuplicateCandidate,
        Self::CoverageRedundant,
        Self::BudgetExhausted,
        Self::StrategyExhausted,
        Self::EcosystemMismatch,
    ];

    /// Stable string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InsufficientNovelty => "insufficient_novelty",
            Self::TooComplex => "too_complex",
            Self::ForbiddenPattern => "forbidden_pattern",
            Self::DuplicateCandidate => "duplicate_candidate",
            Self::CoverageRedundant => "coverage_redundant",
            Self::BudgetExhausted => "budget_exhausted",
            Self::StrategyExhausted => "strategy_exhausted",
            Self::EcosystemMismatch => "ecosystem_mismatch",
        }
    }
}

impl fmt::Display for SynthesisDenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SynthesisError
// ---------------------------------------------------------------------------

/// Errors that can occur during novelty synthesis operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SynthesisError {
    /// The constraint parameters are invalid (e.g. zero max nodes).
    InvalidConstraint,
    /// The computed novelty is below the required threshold.
    NoveltyBelowThreshold,
    /// Adding more candidates would exceed the batch size limit.
    BatchOverflow,
    /// The selected strategy is not applicable to the given program kind.
    StrategyNotApplicable,
    /// An internal error with a descriptive message.
    InternalError(String),
}

impl fmt::Display for SynthesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConstraint => write!(f, "invalid synthesis constraint"),
            Self::NoveltyBelowThreshold => write!(f, "novelty below required threshold"),
            Self::BatchOverflow => write!(f, "batch size limit exceeded"),
            Self::StrategyNotApplicable => {
                write!(f, "strategy not applicable to this program kind")
            }
            Self::InternalError(msg) => write!(f, "internal synthesis error: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Core Functions
// ---------------------------------------------------------------------------

/// Build a `SynthesisConstraint` from the given program kind and limits.
///
/// Returns `Err(InvalidConstraint)` if `max_nodes` is zero.
pub fn build_constraints(
    kind: ProgramKind,
    max_nodes: u64,
    min_novelty: u64,
) -> SynthesisConstraint {
    let min_nodes = kind.typical_min_nodes();
    let effective_max = if max_nodes < min_nodes {
        min_nodes
    } else {
        max_nodes
    };

    SynthesisConstraint {
        max_ast_nodes: effective_max,
        max_bytes: effective_max.saturating_mul(16), // ~16 bytes per AST node heuristic
        min_novelty_millionths: min_novelty,
        required_features: BTreeSet::new(),
        forbidden_patterns: BTreeSet::new(),
    }
}

/// Synthesize a single candidate program.
///
/// Uses `seed` bytes for deterministic pseudo-random generation so that
/// identical seeds always produce identical candidates.
pub fn synthesize_candidate(
    kind: ProgramKind,
    strategy: SynthesisStrategy,
    constraint: &SynthesisConstraint,
    seed: &[u8],
) -> Result<SynthesizedCandidate, SynthesisError> {
    if constraint.max_ast_nodes == 0 {
        return Err(SynthesisError::InvalidConstraint);
    }

    // Derive a deterministic pseudo-random value from the seed.
    let seed_hash = {
        let mut h = Sha256::new();
        h.update(b"novelty-seed-v1:");
        h.update(seed);
        h.update(kind.as_str().as_bytes());
        h.update(strategy.as_str().as_bytes());
        let out = h.finalize();
        // Take first 8 bytes as a u64.
        u64::from_le_bytes([
            out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
        ])
    };

    // Generate source text deterministically from seed and kind.
    let source_text = generate_source(kind, strategy, seed_hash);

    // Check byte budget.
    let byte_count = source_text.len() as u64;
    if byte_count > constraint.max_bytes {
        return Err(SynthesisError::StrategyNotApplicable);
    }

    // Estimate AST node count from source size — deterministic heuristic.
    let ast_node_count = estimate_ast_nodes(&source_text, kind);
    if ast_node_count > constraint.max_ast_nodes {
        return Err(SynthesisError::StrategyNotApplicable);
    }

    // Check forbidden patterns.
    if constraint.contains_forbidden(&source_text).is_some() {
        return Err(SynthesisError::StrategyNotApplicable);
    }

    // Compute novelty from strategy multiplier and seed entropy.
    let raw_novelty = strategy.base_novelty_multiplier();
    let entropy_bonus = (seed_hash % 200_001).min(200_000); // 0..200_000
    let novelty_score = raw_novelty.saturating_add(entropy_bonus).min(MILLIONTHS);

    if novelty_score < constraint.min_novelty_millionths {
        return Err(SynthesisError::NoveltyBelowThreshold);
    }

    // Coverage delta is proportional to novelty and inversely proportional
    // to complexity.
    let coverage_delta = novelty_score
        .saturating_mul(MILLIONTHS)
        .checked_div(ast_node_count.max(1).saturating_mul(MILLIONTHS))
        .unwrap_or(0)
        .min(MILLIONTHS);

    // Build candidate ID deterministically.
    let candidate_id = format!(
        "nse-{}-{}-{:016x}",
        kind.as_str(),
        strategy.as_str(),
        seed_hash
    );

    // Target cells from seed bits.
    let target_cells = derive_target_cells(seed_hash, kind);

    let content_hash =
        SynthesizedCandidate::compute_hash(&candidate_id, kind, strategy, &source_text);

    Ok(SynthesizedCandidate {
        candidate_id,
        kind,
        strategy,
        source_text,
        ast_node_count,
        novelty_score_millionths: novelty_score,
        coverage_delta_millionths: coverage_delta,
        target_cells,
        content_hash,
    })
}

/// Build a `SynthesisBatch` from a set of candidates.
///
/// Returns `Err(BatchOverflow)` if the candidate count exceeds `MAX_BATCH_SIZE`.
pub fn build_batch(
    epoch: SecurityEpoch,
    candidates: Vec<SynthesizedCandidate>,
) -> Result<SynthesisBatch, SynthesisError> {
    if candidates.len() > MAX_BATCH_SIZE {
        return Err(SynthesisError::BatchOverflow);
    }

    let mut strategy_distribution: BTreeMap<SynthesisStrategy, u64> = BTreeMap::new();
    let mut total_novelty: u64 = 0;

    for c in &candidates {
        *strategy_distribution.entry(c.strategy).or_insert(0) += 1;
        total_novelty = total_novelty.saturating_add(c.novelty_score_millionths);
    }

    // Build a deterministic batch ID from epoch and candidate hashes.
    let batch_id = {
        let mut h = Sha256::new();
        h.update(b"novelty-batch-v1:");
        h.update(epoch.as_u64().to_le_bytes());
        for c in &candidates {
            h.update(c.content_hash.as_bytes());
        }
        let out = h.finalize();
        format!(
            "batch-{:016x}",
            u64::from_le_bytes([
                out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
            ])
        )
    };

    Ok(SynthesisBatch {
        batch_id,
        epoch,
        candidates,
        strategy_distribution,
        total_novelty_millionths: total_novelty,
    })
}

/// Evaluate the novelty of a candidate relative to existing content hashes.
///
/// Returns `MILLIONTHS` (full novelty) if the candidate hash is not in the
/// set, or 0 if it is a duplicate.  For near-duplicates (same prefix),
/// returns a proportionally reduced score.
pub fn evaluate_candidate_novelty(
    candidate: &SynthesizedCandidate,
    existing_hashes: &BTreeSet<ContentHash>,
) -> u64 {
    // Exact duplicate detection.
    if existing_hashes.contains(&candidate.content_hash) {
        return 0;
    }

    // Check for near-duplicates by prefix similarity.
    let candidate_bytes = candidate.content_hash.as_bytes();
    let mut best_prefix_match: u32 = 0;

    for existing in existing_hashes {
        let existing_bytes = existing.as_bytes();
        let mut prefix_len: u32 = 0;
        for i in 0..32 {
            if candidate_bytes[i] == existing_bytes[i] {
                prefix_len += 1;
            } else {
                break;
            }
        }
        if prefix_len > best_prefix_match {
            best_prefix_match = prefix_len;
        }
    }

    // Each matching prefix byte reduces novelty proportionally.
    // 32 matching bytes = 0 novelty.  0 matching bytes = full novelty.
    let remaining = 32_u64.saturating_sub(best_prefix_match as u64);
    remaining
        .saturating_mul(MILLIONTHS)
        .checked_div(32)
        .unwrap_or(0)
}

/// Filter candidates against constraints, returning accepted and denied
/// with reasons.
pub fn filter_candidates(
    candidates: Vec<SynthesizedCandidate>,
    constraint: &SynthesisConstraint,
) -> (
    Vec<SynthesizedCandidate>,
    Vec<(SynthesizedCandidate, SynthesisDenialReason)>,
) {
    let mut accepted = Vec::new();
    let mut denied: Vec<(SynthesizedCandidate, SynthesisDenialReason)> = Vec::new();
    let mut seen_hashes: BTreeSet<ContentHash> = BTreeSet::new();

    for candidate in candidates {
        // Check for duplicates first.
        if seen_hashes.contains(&candidate.content_hash) {
            denied.push((candidate, SynthesisDenialReason::DuplicateCandidate));
            continue;
        }

        // Check complexity: AST nodes.
        if candidate.ast_node_count > constraint.max_ast_nodes {
            denied.push((candidate, SynthesisDenialReason::TooComplex));
            continue;
        }

        // Check complexity: bytes.
        if candidate.source_byte_count() > constraint.max_bytes {
            denied.push((candidate, SynthesisDenialReason::TooComplex));
            continue;
        }

        // Check forbidden patterns.
        if constraint
            .contains_forbidden(&candidate.source_text)
            .is_some()
        {
            denied.push((candidate, SynthesisDenialReason::ForbiddenPattern));
            continue;
        }

        // Check novelty threshold.
        if candidate.novelty_score_millionths < constraint.min_novelty_millionths {
            denied.push((candidate, SynthesisDenialReason::InsufficientNovelty));
            continue;
        }

        // Check coverage redundancy.
        if candidate.coverage_delta_millionths == 0 {
            denied.push((candidate, SynthesisDenialReason::CoverageRedundant));
            continue;
        }

        // Accepted.
        seen_hashes.insert(candidate.content_hash);
        accepted.push(candidate);
    }

    (accepted, denied)
}

/// Build a receipt from a completed batch and the number of accepted
/// candidates.
pub fn build_receipt(batch: &SynthesisBatch, accepted: u64) -> SynthesisReceipt {
    let proposed = batch.candidates.len() as u64;
    let clamped_accepted = accepted.min(proposed);

    // Sum novelty of the first `clamped_accepted` candidates as an
    // approximation of yield.
    let novelty_yield: u64 = batch
        .candidates
        .iter()
        .take(clamped_accepted as usize)
        .map(|c| c.novelty_score_millionths)
        .fold(0u64, |acc, n| acc.saturating_add(n));

    // Coverage improvement: sum of coverage deltas of accepted candidates.
    let coverage_improvement: u64 = batch
        .candidates
        .iter()
        .take(clamped_accepted as usize)
        .map(|c| c.coverage_delta_millionths)
        .fold(0u64, |acc, d| acc.saturating_add(d));

    // Compute receipt content hash.
    let content_hash = {
        let mut h = Sha256::new();
        h.update(b"novelty-receipt-v1:");
        h.update(batch.batch_id.as_bytes());
        h.update(b":");
        h.update(proposed.to_le_bytes());
        h.update(b":");
        h.update(clamped_accepted.to_le_bytes());
        h.update(b":");
        h.update(novelty_yield.to_le_bytes());
        h.update(b":");
        h.update(coverage_improvement.to_le_bytes());
        ContentHash::compute(&h.finalize())
    };

    SynthesisReceipt {
        batch_id: batch.batch_id.clone(),
        timestamp_epoch: batch.epoch,
        candidates_proposed: proposed,
        candidates_accepted: clamped_accepted,
        novelty_yield_millionths: novelty_yield,
        coverage_improvement_millionths: coverage_improvement,
        content_hash,
    }
}

/// Canonical synthesis manifest: a pre-built batch containing one candidate
/// per (kind, strategy) pair, using default constraints and epoch 1.
pub fn franken_engine_synthesis_manifest() -> SynthesisBatch {
    let epoch = SecurityEpoch::from_raw(1);
    let constraint = SynthesisConstraint::new(
        DEFAULT_MAX_AST_NODES,
        DEFAULT_MAX_BYTES,
        0, // Accept all novelty levels for the manifest.
    );

    let mut candidates = Vec::new();
    let mut seed_counter: u64 = 0;

    for kind in ProgramKind::ALL {
        for strategy in SynthesisStrategy::ALL {
            let seed = seed_counter.to_le_bytes();
            seed_counter += 1;

            if let Ok(c) = synthesize_candidate(*kind, *strategy, &constraint, &seed) {
                candidates.push(c);
            }
        }
    }

    // This should not fail since we control the count.
    build_batch(epoch, candidates).unwrap_or_else(|_| SynthesisBatch {
        batch_id: "manifest-fallback".into(),
        epoch,
        candidates: Vec::new(),
        strategy_distribution: BTreeMap::new(),
        total_novelty_millionths: 0,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Generate deterministic source text for a given kind and strategy.
fn generate_source(kind: ProgramKind, strategy: SynthesisStrategy, seed: u64) -> String {
    match strategy {
        SynthesisStrategy::GrammarGuided => generate_grammar_guided(kind, seed),
        SynthesisStrategy::MutationBased => generate_mutation_based(kind, seed),
        SynthesisStrategy::RecombinationBased => generate_recombination(kind, seed),
        SynthesisStrategy::TemplateDriven => generate_template_driven(kind, seed),
        SynthesisStrategy::ObstructionTargeted => generate_obstruction_targeted(kind, seed),
    }
}

/// Grammar-guided source generation: builds from production rules.
fn generate_grammar_guided(kind: ProgramKind, seed: u64) -> String {
    let var_name = format!("v{}", seed % 1000);
    let val = seed % 100;
    match kind {
        ProgramKind::PlainJs => {
            format!(
                "// Grammar-guided plain JS (seed {seed:016x})\n\
                 const {var_name} = {val};\n\
                 function compute_{var_name}(x) {{\n  \
                   return x + {var_name};\n\
                 }}\n\
                 module.exports = {{ compute_{var_name} }};\n"
            )
        }
        ProgramKind::TypeScript => {
            format!(
                "// Grammar-guided TypeScript (seed {seed:016x})\n\
                 interface Config_{var_name} {{\n  \
                   value: number;\n  \
                   label: string;\n\
                 }}\n\
                 export function create_{var_name}(cfg: Config_{var_name}): number {{\n  \
                   return cfg.value + {val};\n\
                 }}\n"
            )
        }
        ProgramKind::ReactComponent => {
            format!(
                "// Grammar-guided React component (seed {seed:016x})\n\
                 import React from 'react';\n\
                 interface Props_{var_name} {{\n  \
                   count: number;\n\
                 }}\n\
                 export const Component_{var_name}: React.FC<Props_{var_name}> = ({{ count }}) => {{\n  \
                   return <div>{{count + {val}}}</div>;\n\
                 }};\n"
            )
        }
        ProgramKind::ReactApp => {
            format!(
                "// Grammar-guided React app (seed {seed:016x})\n\
                 import React from 'react';\n\
                 import ReactDOM from 'react-dom/client';\n\
                 function App_{var_name}() {{\n  \
                   const [state, setState] = React.useState({val});\n  \
                   return (\n    \
                     <div className=\"app-{var_name}\">\n      \
                       <h1>{{state}}</h1>\n      \
                       <button onClick={{() => setState(s => s + 1)}}>+</button>\n    \
                     </div>\n  \
                   );\n\
                 }}\n\
                 export default App_{var_name};\n"
            )
        }
        ProgramKind::NodePackage => {
            format!(
                "// Grammar-guided Node package (seed {seed:016x})\n\
                 const {var_name} = require('path');\n\
                 function resolve_{var_name}(base, rel) {{\n  \
                   return {var_name}.resolve(base, rel);\n\
                 }}\n\
                 module.exports = {{ resolve_{var_name} }};\n"
            )
        }
        ProgramKind::BunPackage => {
            format!(
                "// Grammar-guided Bun package (seed {seed:016x})\n\
                 import {{ serve }} from 'bun';\n\
                 const port_{var_name} = {val} + 3000;\n\
                 export function start_{var_name}() {{\n  \
                   return serve({{\n    \
                     port: port_{var_name},\n    \
                     fetch(req) {{\n      \
                       return new Response('ok');\n    \
                     }},\n  \
                   }});\n\
                 }}\n"
            )
        }
    }
}

/// Mutation-based: small perturbation of a base template.
fn generate_mutation_based(kind: ProgramKind, seed: u64) -> String {
    let idx = seed % 50;
    let op = if seed.is_multiple_of(3) {
        "+"
    } else if seed % 3 == 1 {
        "-"
    } else {
        "*"
    };
    match kind {
        ProgramKind::PlainJs | ProgramKind::NodePackage | ProgramKind::BunPackage => {
            format!(
                "// Mutation-based JS (seed {seed:016x})\n\
                 function mutated_{idx}(a, b) {{\n  \
                   return a {op} b;\n\
                 }}\n\
                 module.exports = {{ mutated_{idx} }};\n"
            )
        }
        ProgramKind::TypeScript => {
            format!(
                "// Mutation-based TS (seed {seed:016x})\n\
                 export function mutated_{idx}(a: number, b: number): number {{\n  \
                   return a {op} b;\n\
                 }}\n"
            )
        }
        ProgramKind::ReactComponent | ProgramKind::ReactApp => {
            format!(
                "// Mutation-based React (seed {seed:016x})\n\
                 import React from 'react';\n\
                 export const Mutated_{idx}: React.FC<{{a: number; b: number}}> = ({{a, b}}) => {{\n  \
                   return <span>{{a {op} b}}</span>;\n\
                 }};\n"
            )
        }
    }
}

/// Recombination: merges fragments from two conceptual parents.
fn generate_recombination(kind: ProgramKind, seed: u64) -> String {
    let frag_a = seed % 30;
    let frag_b = (seed / 30) % 30;
    match kind {
        ProgramKind::PlainJs | ProgramKind::NodePackage | ProgramKind::BunPackage => {
            format!(
                "// Recombination JS (seed {seed:016x})\n\
                 function frag_a_{frag_a}(x) {{ return x * 2; }}\n\
                 function frag_b_{frag_b}(x) {{ return x + 1; }}\n\
                 function combined_{frag_a}_{frag_b}(x) {{\n  \
                   return frag_b_{frag_b}(frag_a_{frag_a}(x));\n\
                 }}\n\
                 module.exports = {{ combined_{frag_a}_{frag_b} }};\n"
            )
        }
        ProgramKind::TypeScript => {
            format!(
                "// Recombination TS (seed {seed:016x})\n\
                 export function frag_a_{frag_a}(x: number): number {{ return x * 2; }}\n\
                 export function frag_b_{frag_b}(x: number): number {{ return x + 1; }}\n\
                 export function combined_{frag_a}_{frag_b}(x: number): number {{\n  \
                   return frag_b_{frag_b}(frag_a_{frag_a}(x));\n\
                 }}\n"
            )
        }
        ProgramKind::ReactComponent | ProgramKind::ReactApp => {
            format!(
                "// Recombination React (seed {seed:016x})\n\
                 import React from 'react';\n\
                 const FragA_{frag_a}: React.FC<{{x: number}}> = ({{x}}) => <b>{{x * 2}}</b>;\n\
                 const FragB_{frag_b}: React.FC<{{x: number}}> = ({{x}}) => <i>{{x + 1}}</i>;\n\
                 export const Combined_{frag_a}_{frag_b}: React.FC<{{x: number}}> = ({{x}}) => (\n  \
                   <div><FragA_{frag_a} x={{x}} /><FragB_{frag_b} x={{x}} /></div>\n\
                 );\n"
            )
        }
    }
}

/// Template-driven: fill in a well-known template pattern.
fn generate_template_driven(kind: ProgramKind, seed: u64) -> String {
    let tag = seed % 100;
    match kind {
        ProgramKind::PlainJs | ProgramKind::NodePackage | ProgramKind::BunPackage => {
            format!(
                "// Template-driven JS (seed {seed:016x})\n\
                 class Service_{tag} {{\n  \
                   constructor(name) {{\n    \
                     this.name = name;\n    \
                     this.id = {tag};\n  \
                   }}\n  \
                   run() {{ return this.id; }}\n\
                 }}\n\
                 module.exports = {{ Service_{tag} }};\n"
            )
        }
        ProgramKind::TypeScript => {
            format!(
                "// Template-driven TS (seed {seed:016x})\n\
                 export class Service_{tag} {{\n  \
                   readonly id = {tag};\n  \
                   constructor(public name: string) {{}}\n  \
                   run(): number {{ return this.id; }}\n\
                 }}\n"
            )
        }
        ProgramKind::ReactComponent | ProgramKind::ReactApp => {
            format!(
                "// Template-driven React (seed {seed:016x})\n\
                 import React from 'react';\n\
                 import {{ useEffect, useState }} from 'react';\n\
                 export function useService_{tag}() {{\n  \
                   const [data, setData] = useState<number>({tag});\n  \
                   useEffect(() => {{\n    \
                     setData(d => d + 1);\n  \
                   }}, []);\n  \
                   return data;\n\
                 }}\n"
            )
        }
    }
}

/// Obstruction-targeted: exercises known coverage gap patterns.
fn generate_obstruction_targeted(kind: ProgramKind, seed: u64) -> String {
    let gap_id = seed % 20;
    match kind {
        ProgramKind::PlainJs | ProgramKind::NodePackage | ProgramKind::BunPackage => {
            format!(
                "// Obstruction-targeted JS gap-{gap_id} (seed {seed:016x})\n\
                 function gap_{gap_id}_handler(input) {{\n  \
                   if (typeof input === 'undefined') throw new TypeError('gap_{gap_id}');\n  \
                   const result = Object.create(null);\n  \
                   result.gap = {gap_id};\n  \
                   result.value = input;\n  \
                   return Object.freeze(result);\n\
                 }}\n\
                 module.exports = {{ gap_{gap_id}_handler }};\n"
            )
        }
        ProgramKind::TypeScript => {
            format!(
                "// Obstruction-targeted TS gap-{gap_id} (seed {seed:016x})\n\
                 type GapResult_{gap_id} = Readonly<{{ gap: {gap_id}; value: unknown }}>;\n\
                 export function gap_{gap_id}_handler(input: unknown): GapResult_{gap_id} {{\n  \
                   if (input === undefined) throw new TypeError('gap_{gap_id}');\n  \
                   return Object.freeze({{ gap: {gap_id}, value: input }}) as GapResult_{gap_id};\n\
                 }}\n"
            )
        }
        ProgramKind::ReactComponent | ProgramKind::ReactApp => {
            format!(
                "// Obstruction-targeted React gap-{gap_id} (seed {seed:016x})\n\
                 import React from 'react';\n\
                 interface GapProps_{gap_id} {{ value: unknown }}\n\
                 export class ErrorBoundary_{gap_id} extends React.Component<GapProps_{gap_id}> {{\n  \
                   state = {{ hasError: false }};\n  \
                   static getDerivedStateFromError() {{ return {{ hasError: true }}; }}\n  \
                   render() {{\n    \
                     if (this.state.hasError) return <div>Gap {gap_id} error</div>;\n    \
                     return <div>{{String(this.props.value)}}</div>;\n  \
                   }}\n\
                 }}\n"
            )
        }
    }
}

/// Estimate the number of AST nodes from source text and kind.
fn estimate_ast_nodes(source: &str, kind: ProgramKind) -> u64 {
    // Heuristic: count significant tokens.
    let base_count = source
        .split_whitespace()
        .filter(|t| {
            // Count keywords, identifiers, and operators as nodes.
            t.len() > 1
                || t.chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric() || c == '{' || c == '}')
        })
        .count() as u64;

    // Different kinds have different node density.
    let multiplier = match kind {
        ProgramKind::PlainJs => 80,
        ProgramKind::TypeScript => 90,
        ProgramKind::ReactComponent | ProgramKind::ReactApp => 100,
        ProgramKind::NodePackage | ProgramKind::BunPackage => 85,
    };

    // Scale: base_count * multiplier / 100, with minimum from kind.
    let scaled = base_count
        .saturating_mul(multiplier)
        .checked_div(100)
        .unwrap_or(0);
    scaled.max(kind.typical_min_nodes())
}

/// Derive target cell names deterministically from seed and kind.
fn derive_target_cells(seed: u64, kind: ProgramKind) -> Vec<String> {
    let cell_count = ((seed % 3) + 1) as usize; // 1..3 cells
    let kind_prefix = kind.as_str();
    (0..cell_count)
        .map(|i| {
            let cell_id = (seed.wrapping_add(i as u64)).wrapping_mul(2654435761) % 10000;
            format!("{kind_prefix}-cell-{cell_id:04}")
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
        SecurityEpoch::from_raw(1)
    }

    fn default_constraint() -> SynthesisConstraint {
        SynthesisConstraint::new(
            DEFAULT_MAX_AST_NODES,
            DEFAULT_MAX_BYTES,
            DEFAULT_MIN_NOVELTY,
        )
    }

    fn make_candidate(
        id: &str,
        kind: ProgramKind,
        strategy: SynthesisStrategy,
    ) -> SynthesizedCandidate {
        let source = format!("// test candidate {id}");
        let content_hash = SynthesizedCandidate::compute_hash(id, kind, strategy, &source);
        SynthesizedCandidate {
            candidate_id: id.into(),
            kind,
            strategy,
            source_text: source,
            ast_node_count: 10,
            novelty_score_millionths: 500_000,
            coverage_delta_millionths: 100_000,
            target_cells: vec!["cell-0001".into()],
            content_hash,
        }
    }

    fn make_candidate_with_novelty(id: &str, novelty: u64) -> SynthesizedCandidate {
        let source = format!("// test candidate {id} novelty={novelty}");
        let kind = ProgramKind::PlainJs;
        let strategy = SynthesisStrategy::GrammarGuided;
        let content_hash = SynthesizedCandidate::compute_hash(id, kind, strategy, &source);
        SynthesizedCandidate {
            candidate_id: id.into(),
            kind,
            strategy,
            source_text: source,
            ast_node_count: 10,
            novelty_score_millionths: novelty,
            coverage_delta_millionths: if novelty > 0 { 50_000 } else { 0 },
            target_cells: vec!["cell-0001".into()],
            content_hash,
        }
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.novelty-synthesis-engine.v1");
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.8.7.2");
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "novelty_synthesis_engine");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-707B");
    }

    #[test]
    fn test_millionths_constant() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // SynthesisStrategy serde + display
    // -----------------------------------------------------------------------

    #[test]
    fn test_strategy_serde_roundtrip() {
        for s in SynthesisStrategy::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: SynthesisStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn test_strategy_display() {
        assert_eq!(
            SynthesisStrategy::GrammarGuided.to_string(),
            "grammar_guided"
        );
        assert_eq!(
            SynthesisStrategy::MutationBased.to_string(),
            "mutation_based"
        );
        assert_eq!(
            SynthesisStrategy::RecombinationBased.to_string(),
            "recombination_based"
        );
        assert_eq!(
            SynthesisStrategy::TemplateDriven.to_string(),
            "template_driven"
        );
        assert_eq!(
            SynthesisStrategy::ObstructionTargeted.to_string(),
            "obstruction_targeted"
        );
    }

    #[test]
    fn test_strategy_all_count() {
        assert_eq!(SynthesisStrategy::ALL.len(), STRATEGY_COUNT);
    }

    #[test]
    fn test_strategy_base_novelty() {
        // ObstructionTargeted should have highest base novelty.
        let ot = SynthesisStrategy::ObstructionTargeted.base_novelty_multiplier();
        let td = SynthesisStrategy::TemplateDriven.base_novelty_multiplier();
        assert!(
            ot > td,
            "obstruction_targeted should have higher base novelty than template_driven"
        );
    }

    // -----------------------------------------------------------------------
    // ProgramKind serde + display
    // -----------------------------------------------------------------------

    #[test]
    fn test_kind_serde_roundtrip() {
        for k in ProgramKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: ProgramKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    #[test]
    fn test_kind_display() {
        assert_eq!(ProgramKind::PlainJs.to_string(), "plain_js");
        assert_eq!(ProgramKind::TypeScript.to_string(), "typescript");
        assert_eq!(ProgramKind::ReactComponent.to_string(), "react_component");
        assert_eq!(ProgramKind::ReactApp.to_string(), "react_app");
        assert_eq!(ProgramKind::NodePackage.to_string(), "node_package");
        assert_eq!(ProgramKind::BunPackage.to_string(), "bun_package");
    }

    #[test]
    fn test_kind_all_count() {
        assert_eq!(ProgramKind::ALL.len(), KIND_COUNT);
    }

    #[test]
    fn test_kind_file_extensions() {
        assert_eq!(ProgramKind::PlainJs.file_extension(), ".js");
        assert_eq!(ProgramKind::TypeScript.file_extension(), ".ts");
        assert_eq!(ProgramKind::ReactComponent.file_extension(), ".tsx");
        assert_eq!(ProgramKind::ReactApp.file_extension(), ".tsx");
        assert_eq!(ProgramKind::NodePackage.file_extension(), ".js");
        assert_eq!(ProgramKind::BunPackage.file_extension(), ".js");
    }

    // -----------------------------------------------------------------------
    // SynthesisDenialReason serde + display
    // -----------------------------------------------------------------------

    #[test]
    fn test_denial_reason_serde_roundtrip() {
        for r in SynthesisDenialReason::ALL {
            let json = serde_json::to_string(r).unwrap();
            let back: SynthesisDenialReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, back);
        }
    }

    #[test]
    fn test_denial_reason_display() {
        assert_eq!(
            SynthesisDenialReason::InsufficientNovelty.to_string(),
            "insufficient_novelty"
        );
        assert_eq!(SynthesisDenialReason::TooComplex.to_string(), "too_complex");
        assert_eq!(
            SynthesisDenialReason::ForbiddenPattern.to_string(),
            "forbidden_pattern"
        );
        assert_eq!(
            SynthesisDenialReason::DuplicateCandidate.to_string(),
            "duplicate_candidate"
        );
        assert_eq!(
            SynthesisDenialReason::CoverageRedundant.to_string(),
            "coverage_redundant"
        );
        assert_eq!(
            SynthesisDenialReason::BudgetExhausted.to_string(),
            "budget_exhausted"
        );
        assert_eq!(
            SynthesisDenialReason::StrategyExhausted.to_string(),
            "strategy_exhausted"
        );
        assert_eq!(
            SynthesisDenialReason::EcosystemMismatch.to_string(),
            "ecosystem_mismatch"
        );
    }

    #[test]
    fn test_denial_reason_all_count() {
        assert_eq!(SynthesisDenialReason::ALL.len(), 8);
    }

    // -----------------------------------------------------------------------
    // SynthesisError display
    // -----------------------------------------------------------------------

    #[test]
    fn test_error_display_invalid_constraint() {
        let e = SynthesisError::InvalidConstraint;
        assert_eq!(e.to_string(), "invalid synthesis constraint");
    }

    #[test]
    fn test_error_display_novelty_below() {
        let e = SynthesisError::NoveltyBelowThreshold;
        assert_eq!(e.to_string(), "novelty below required threshold");
    }

    #[test]
    fn test_error_display_batch_overflow() {
        let e = SynthesisError::BatchOverflow;
        assert_eq!(e.to_string(), "batch size limit exceeded");
    }

    #[test]
    fn test_error_display_strategy_not_applicable() {
        let e = SynthesisError::StrategyNotApplicable;
        assert_eq!(
            e.to_string(),
            "strategy not applicable to this program kind"
        );
    }

    #[test]
    fn test_error_display_internal() {
        let e = SynthesisError::InternalError("oops".into());
        assert_eq!(e.to_string(), "internal synthesis error: oops");
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let errors = vec![
            SynthesisError::InvalidConstraint,
            SynthesisError::NoveltyBelowThreshold,
            SynthesisError::BatchOverflow,
            SynthesisError::StrategyNotApplicable,
            SynthesisError::InternalError("test msg".into()),
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: SynthesisError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    // -----------------------------------------------------------------------
    // SynthesisConstraint
    // -----------------------------------------------------------------------

    #[test]
    fn test_constraint_new() {
        let c = SynthesisConstraint::new(100, 2000, 300_000);
        assert_eq!(c.max_ast_nodes, 100);
        assert_eq!(c.max_bytes, 2000);
        assert_eq!(c.min_novelty_millionths, 300_000);
        assert!(c.required_features.is_empty());
        assert!(c.forbidden_patterns.is_empty());
    }

    #[test]
    fn test_constraint_require_feature() {
        let mut c = SynthesisConstraint::new(100, 2000, 300_000);
        c.require_feature("async");
        c.require_feature("generator");
        assert_eq!(c.required_features.len(), 2);
        assert!(c.required_features.contains("async"));
    }

    #[test]
    fn test_constraint_forbid_pattern() {
        let mut c = SynthesisConstraint::new(100, 2000, 300_000);
        c.forbid_pattern("eval(");
        assert_eq!(c.forbidden_patterns.len(), 1);
    }

    #[test]
    fn test_constraint_nodes_within_budget() {
        let c = SynthesisConstraint::new(100, 2000, 0);
        assert!(c.nodes_within_budget(100));
        assert!(c.nodes_within_budget(50));
        assert!(!c.nodes_within_budget(101));
    }

    #[test]
    fn test_constraint_bytes_within_budget() {
        let c = SynthesisConstraint::new(100, 2000, 0);
        assert!(c.bytes_within_budget(2000));
        assert!(!c.bytes_within_budget(2001));
    }

    #[test]
    fn test_constraint_novelty_sufficient() {
        let c = SynthesisConstraint::new(100, 2000, 300_000);
        assert!(c.novelty_sufficient(300_000));
        assert!(c.novelty_sufficient(500_000));
        assert!(!c.novelty_sufficient(299_999));
    }

    #[test]
    fn test_constraint_forbidden_detection() {
        let mut c = SynthesisConstraint::new(100, 2000, 0);
        c.forbid_pattern("eval(");
        c.forbid_pattern("document.write");

        assert!(c.contains_forbidden("let x = eval('1')").is_some());
        assert_eq!(c.contains_forbidden("let x = eval('1')").unwrap(), "eval(");
        assert!(c.contains_forbidden("let x = 1 + 2").is_none());
    }

    #[test]
    fn test_constraint_missing_features() {
        let mut c = SynthesisConstraint::new(100, 2000, 0);
        c.require_feature("async");
        c.require_feature("await");

        let missing = c.missing_features("async function f() { return 1; }");
        assert_eq!(missing, vec!["await"]);

        let none_missing = c.missing_features("async function f() { await fetch(); }");
        assert!(none_missing.is_empty());
    }

    #[test]
    fn test_constraint_serde() {
        let mut c = SynthesisConstraint::new(256, 4096, 300_000);
        c.require_feature("import");
        c.forbid_pattern("eval");
        let json = serde_json::to_string(&c).unwrap();
        let back: SynthesisConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // -----------------------------------------------------------------------
    // build_constraints
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_constraints_plain_js() {
        let c = build_constraints(ProgramKind::PlainJs, 100, 300_000);
        assert_eq!(c.max_ast_nodes, 100);
        assert_eq!(c.max_bytes, 1600); // 100 * 16
        assert_eq!(c.min_novelty_millionths, 300_000);
    }

    #[test]
    fn test_build_constraints_enforces_minimum_nodes() {
        // ReactApp has typical_min_nodes = 20.  If we pass 5, it bumps to 20.
        let c = build_constraints(ProgramKind::ReactApp, 5, 0);
        assert_eq!(c.max_ast_nodes, 20);
    }

    #[test]
    fn test_build_constraints_respects_large_max() {
        let c = build_constraints(ProgramKind::TypeScript, 500, 100_000);
        assert_eq!(c.max_ast_nodes, 500);
    }

    // -----------------------------------------------------------------------
    // synthesize_candidate
    // -----------------------------------------------------------------------

    #[test]
    fn test_synthesize_candidate_plain_js_grammar() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let result = synthesize_candidate(
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            &constraint,
            b"seed-1",
        );
        let c = result.unwrap();
        assert_eq!(c.kind, ProgramKind::PlainJs);
        assert_eq!(c.strategy, SynthesisStrategy::GrammarGuided);
        assert!(!c.source_text.is_empty());
        assert!(c.source_text.contains("Grammar-guided plain JS"));
        assert!(c.ast_node_count > 0);
        assert!(c.novelty_score_millionths > 0);
    }

    #[test]
    fn test_synthesize_candidate_typescript_mutation() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let result = synthesize_candidate(
            ProgramKind::TypeScript,
            SynthesisStrategy::MutationBased,
            &constraint,
            b"seed-2",
        );
        let c = result.unwrap();
        assert_eq!(c.kind, ProgramKind::TypeScript);
        assert!(c.source_text.contains("Mutation-based TS"));
    }

    #[test]
    fn test_synthesize_candidate_react_recombination() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let result = synthesize_candidate(
            ProgramKind::ReactComponent,
            SynthesisStrategy::RecombinationBased,
            &constraint,
            b"seed-3",
        );
        let c = result.unwrap();
        assert_eq!(c.kind, ProgramKind::ReactComponent);
        assert!(c.source_text.contains("Recombination React"));
    }

    #[test]
    fn test_synthesize_candidate_react_app_template() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let result = synthesize_candidate(
            ProgramKind::ReactApp,
            SynthesisStrategy::TemplateDriven,
            &constraint,
            b"seed-4",
        );
        let c = result.unwrap();
        assert_eq!(c.kind, ProgramKind::ReactApp);
        assert!(c.source_text.contains("Template-driven React"));
    }

    #[test]
    fn test_synthesize_candidate_obstruction_targeted() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let result = synthesize_candidate(
            ProgramKind::NodePackage,
            SynthesisStrategy::ObstructionTargeted,
            &constraint,
            b"seed-5",
        );
        let c = result.unwrap();
        assert_eq!(c.strategy, SynthesisStrategy::ObstructionTargeted);
        assert!(c.source_text.contains("Obstruction-targeted"));
    }

    #[test]
    fn test_synthesize_candidate_bun_package() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let result = synthesize_candidate(
            ProgramKind::BunPackage,
            SynthesisStrategy::GrammarGuided,
            &constraint,
            b"seed-6",
        );
        let c = result.unwrap();
        assert_eq!(c.kind, ProgramKind::BunPackage);
        assert!(c.source_text.contains("Bun package"));
    }

    #[test]
    fn test_synthesize_candidate_deterministic() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let c1 = synthesize_candidate(
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            &constraint,
            b"same-seed",
        )
        .unwrap();
        let c2 = synthesize_candidate(
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            &constraint,
            b"same-seed",
        )
        .unwrap();
        assert_eq!(c1.candidate_id, c2.candidate_id);
        assert_eq!(c1.source_text, c2.source_text);
        assert_eq!(c1.content_hash, c2.content_hash);
        assert_eq!(c1.novelty_score_millionths, c2.novelty_score_millionths);
    }

    #[test]
    fn test_synthesize_candidate_different_seeds() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let c1 = synthesize_candidate(
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            &constraint,
            b"seed-a",
        )
        .unwrap();
        let c2 = synthesize_candidate(
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            &constraint,
            b"seed-b",
        )
        .unwrap();
        assert_ne!(c1.candidate_id, c2.candidate_id);
        assert_ne!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn test_synthesize_candidate_zero_max_nodes_error() {
        let constraint = SynthesisConstraint::new(0, 0, 0);
        let result = synthesize_candidate(
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            &constraint,
            b"seed",
        );
        assert_eq!(result.unwrap_err(), SynthesisError::InvalidConstraint);
    }

    #[test]
    fn test_synthesize_candidate_high_novelty_threshold_error() {
        // Set threshold to maximum — only seeds with very high entropy pass.
        let constraint = SynthesisConstraint::new(256, 4096, MILLIONTHS);
        let result = synthesize_candidate(
            ProgramKind::PlainJs,
            SynthesisStrategy::TemplateDriven, // base 400_000 + max 200_000 = 600_000 < 1_000_000
            &constraint,
            b"seed-low",
        );
        assert_eq!(result.unwrap_err(), SynthesisError::NoveltyBelowThreshold);
    }

    #[test]
    fn test_synthesize_candidate_has_target_cells() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let c = synthesize_candidate(
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            &constraint,
            b"cells-seed",
        )
        .unwrap();
        assert!(!c.target_cells.is_empty());
        assert!(c.target_cells.len() <= 3);
        for cell in &c.target_cells {
            assert!(cell.starts_with("plain_js-cell-"));
        }
    }

    #[test]
    fn test_synthesize_candidate_source_byte_count() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let c = synthesize_candidate(
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            &constraint,
            b"byte-count-seed",
        )
        .unwrap();
        assert_eq!(c.source_byte_count(), c.source_text.len() as u64);
    }

    // -----------------------------------------------------------------------
    // SynthesizedCandidate methods
    // -----------------------------------------------------------------------

    #[test]
    fn test_candidate_exceeds_novelty() {
        let c = make_candidate_with_novelty("c1", 500_000);
        assert!(c.exceeds_novelty(300_000));
        assert!(c.exceeds_novelty(500_000));
        assert!(!c.exceeds_novelty(500_001));
    }

    #[test]
    fn test_candidate_serde() {
        let c = make_candidate("c1", ProgramKind::PlainJs, SynthesisStrategy::GrammarGuided);
        let json = serde_json::to_string(&c).unwrap();
        let back: SynthesizedCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn test_candidate_hash_deterministic() {
        let h1 = SynthesizedCandidate::compute_hash(
            "id1",
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            "const x = 1;",
        );
        let h2 = SynthesizedCandidate::compute_hash(
            "id1",
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            "const x = 1;",
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_candidate_hash_differs_for_different_source() {
        let h1 = SynthesizedCandidate::compute_hash(
            "id1",
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            "const x = 1;",
        );
        let h2 = SynthesizedCandidate::compute_hash(
            "id1",
            ProgramKind::PlainJs,
            SynthesisStrategy::GrammarGuided,
            "const x = 2;",
        );
        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // build_batch
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_batch_empty() {
        let batch = build_batch(test_epoch(), Vec::new()).unwrap();
        assert!(batch.is_empty());
        assert_eq!(batch.candidate_count(), 0);
        assert_eq!(batch.total_novelty_millionths, 0);
        assert!(batch.strategy_distribution.is_empty());
    }

    #[test]
    fn test_build_batch_single() {
        let c = make_candidate("c1", ProgramKind::PlainJs, SynthesisStrategy::GrammarGuided);
        let batch = build_batch(test_epoch(), vec![c.clone()]).unwrap();
        assert_eq!(batch.candidate_count(), 1);
        assert_eq!(batch.total_novelty_millionths, 500_000);
        assert_eq!(
            *batch
                .strategy_distribution
                .get(&SynthesisStrategy::GrammarGuided)
                .unwrap(),
            1
        );
    }

    #[test]
    fn test_build_batch_multiple_strategies() {
        let c1 = make_candidate("c1", ProgramKind::PlainJs, SynthesisStrategy::GrammarGuided);
        let c2 = make_candidate(
            "c2",
            ProgramKind::TypeScript,
            SynthesisStrategy::MutationBased,
        );
        let c3 = make_candidate("c3", ProgramKind::PlainJs, SynthesisStrategy::GrammarGuided);
        let batch = build_batch(test_epoch(), vec![c1, c2, c3]).unwrap();
        assert_eq!(batch.candidate_count(), 3);
        assert_eq!(
            *batch
                .strategy_distribution
                .get(&SynthesisStrategy::GrammarGuided)
                .unwrap(),
            2
        );
        assert_eq!(
            *batch
                .strategy_distribution
                .get(&SynthesisStrategy::MutationBased)
                .unwrap(),
            1
        );
    }

    #[test]
    fn test_build_batch_overflow() {
        // Create more than MAX_BATCH_SIZE candidates.
        let candidates: Vec<SynthesizedCandidate> = (0..MAX_BATCH_SIZE + 1)
            .map(|i| {
                make_candidate(
                    &format!("c{i}"),
                    ProgramKind::PlainJs,
                    SynthesisStrategy::GrammarGuided,
                )
            })
            .collect();
        let result = build_batch(test_epoch(), candidates);
        assert_eq!(result.unwrap_err(), SynthesisError::BatchOverflow);
    }

    #[test]
    fn test_build_batch_epoch() {
        let epoch = SecurityEpoch::from_raw(42);
        let batch = build_batch(epoch, Vec::new()).unwrap();
        assert_eq!(batch.epoch, epoch);
    }

    #[test]
    fn test_batch_average_novelty() {
        let c1 = make_candidate_with_novelty("c1", 600_000);
        let c2 = make_candidate_with_novelty("c2", 400_000);
        let batch = build_batch(test_epoch(), vec![c1, c2]).unwrap();
        assert_eq!(batch.average_novelty_millionths(), 500_000);
    }

    #[test]
    fn test_batch_average_novelty_empty() {
        let batch = build_batch(test_epoch(), Vec::new()).unwrap();
        assert_eq!(batch.average_novelty_millionths(), 0);
    }

    #[test]
    fn test_batch_content_hash_deterministic() {
        let c1 = make_candidate("c1", ProgramKind::PlainJs, SynthesisStrategy::GrammarGuided);
        let batch1 = build_batch(test_epoch(), vec![c1.clone()]).unwrap();
        let batch2 = build_batch(test_epoch(), vec![c1]).unwrap();
        assert_eq!(batch1.content_hash(), batch2.content_hash());
    }

    #[test]
    fn test_batch_serde() {
        let c = make_candidate("c1", ProgramKind::PlainJs, SynthesisStrategy::GrammarGuided);
        let batch = build_batch(test_epoch(), vec![c]).unwrap();
        let json = serde_json::to_string(&batch).unwrap();
        let back: SynthesisBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(batch, back);
    }

    // -----------------------------------------------------------------------
    // evaluate_candidate_novelty
    // -----------------------------------------------------------------------

    #[test]
    fn test_novelty_zero_for_duplicate() {
        let c = make_candidate("c1", ProgramKind::PlainJs, SynthesisStrategy::GrammarGuided);
        let mut existing = BTreeSet::new();
        existing.insert(c.content_hash);
        assert_eq!(evaluate_candidate_novelty(&c, &existing), 0);
    }

    #[test]
    fn test_novelty_full_for_unique() {
        let c = make_candidate("c1", ProgramKind::PlainJs, SynthesisStrategy::GrammarGuided);
        let existing: BTreeSet<ContentHash> = BTreeSet::new();
        assert_eq!(evaluate_candidate_novelty(&c, &existing), MILLIONTHS);
    }

    #[test]
    fn test_novelty_reduced_for_near_duplicate() {
        let c = make_candidate("c1", ProgramKind::PlainJs, SynthesisStrategy::GrammarGuided);
        // Insert a hash with the same first byte to simulate a near-duplicate.
        let mut near = c.content_hash.as_bytes().to_owned();
        // Change byte 1 onwards to make it different but keep byte 0 the same.
        near[1] ^= 0xFF;
        let mut existing = BTreeSet::new();
        existing.insert(ContentHash(near));
        let novelty = evaluate_candidate_novelty(&c, &existing);
        // 31/32 of MILLIONTHS since 1 prefix byte matches.
        assert_eq!(novelty, 31 * MILLIONTHS / 32);
    }

    // -----------------------------------------------------------------------
    // filter_candidates
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_all_accepted() {
        let constraint = default_constraint();
        let c1 = make_candidate_with_novelty("c1", 500_000);
        let c2 = make_candidate_with_novelty("c2", 600_000);
        let (accepted, denied) = filter_candidates(vec![c1, c2], &constraint);
        assert_eq!(accepted.len(), 2);
        assert!(denied.is_empty());
    }

    #[test]
    fn test_filter_insufficient_novelty() {
        let constraint = SynthesisConstraint::new(256, 4096, 500_000);
        let c = make_candidate_with_novelty("c1", 100_000); // below 500_000
        let (accepted, denied) = filter_candidates(vec![c], &constraint);
        assert!(accepted.is_empty());
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].1, SynthesisDenialReason::InsufficientNovelty);
    }

    #[test]
    fn test_filter_too_complex_nodes() {
        let constraint = SynthesisConstraint::new(5, 4096, 0);
        let mut c = make_candidate_with_novelty("c1", 500_000);
        c.ast_node_count = 10; // exceeds max 5
        let (accepted, denied) = filter_candidates(vec![c], &constraint);
        assert!(accepted.is_empty());
        assert_eq!(denied[0].1, SynthesisDenialReason::TooComplex);
    }

    #[test]
    fn test_filter_too_complex_bytes() {
        let constraint = SynthesisConstraint::new(256, 5, 0); // only 5 bytes max
        let c = make_candidate_with_novelty("c1", 500_000); // source > 5 bytes
        let (accepted, denied) = filter_candidates(vec![c], &constraint);
        assert!(accepted.is_empty());
        assert_eq!(denied[0].1, SynthesisDenialReason::TooComplex);
    }

    #[test]
    fn test_filter_forbidden_pattern() {
        let mut constraint = SynthesisConstraint::new(256, 4096, 0);
        constraint.forbid_pattern("test candidate");
        let c = make_candidate_with_novelty("c1", 500_000); // source contains "test candidate"
        let (accepted, denied) = filter_candidates(vec![c], &constraint);
        assert!(accepted.is_empty());
        assert_eq!(denied[0].1, SynthesisDenialReason::ForbiddenPattern);
    }

    #[test]
    fn test_filter_duplicate() {
        let c1 = make_candidate_with_novelty("c1", 500_000);
        let c2 = c1.clone(); // exact duplicate
        let constraint = default_constraint();
        let (accepted, denied) = filter_candidates(vec![c1, c2], &constraint);
        assert_eq!(accepted.len(), 1);
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].1, SynthesisDenialReason::DuplicateCandidate);
    }

    #[test]
    fn test_filter_coverage_redundant() {
        let mut c = make_candidate_with_novelty("c1", 500_000);
        c.coverage_delta_millionths = 0; // zero coverage
        let constraint = default_constraint();
        let (accepted, denied) = filter_candidates(vec![c], &constraint);
        assert!(accepted.is_empty());
        assert_eq!(denied[0].1, SynthesisDenialReason::CoverageRedundant);
    }

    #[test]
    fn test_filter_mixed_accepted_denied() {
        let constraint = SynthesisConstraint::new(256, 4096, 400_000);
        let c_ok = make_candidate_with_novelty("ok", 500_000);
        let c_low = make_candidate_with_novelty("low", 100_000); // below threshold
        let (accepted, denied) = filter_candidates(vec![c_ok, c_low], &constraint);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].candidate_id, "ok");
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].0.candidate_id, "low");
    }

    // -----------------------------------------------------------------------
    // build_receipt
    // -----------------------------------------------------------------------

    #[test]
    fn test_receipt_all_accepted() {
        let c1 = make_candidate_with_novelty("c1", 500_000);
        let c2 = make_candidate_with_novelty("c2", 400_000);
        let batch = build_batch(test_epoch(), vec![c1, c2]).unwrap();
        let receipt = build_receipt(&batch, 2);
        assert_eq!(receipt.candidates_proposed, 2);
        assert_eq!(receipt.candidates_accepted, 2);
        assert!(receipt.all_accepted());
        assert!(!receipt.none_accepted());
        assert_eq!(receipt.acceptance_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn test_receipt_none_accepted() {
        let c1 = make_candidate_with_novelty("c1", 500_000);
        let batch = build_batch(test_epoch(), vec![c1]).unwrap();
        let receipt = build_receipt(&batch, 0);
        assert_eq!(receipt.candidates_accepted, 0);
        assert!(receipt.none_accepted());
        assert!(!receipt.all_accepted());
        assert_eq!(receipt.acceptance_rate_millionths(), 0);
    }

    #[test]
    fn test_receipt_partial_accepted() {
        let c1 = make_candidate_with_novelty("c1", 600_000);
        let c2 = make_candidate_with_novelty("c2", 400_000);
        let batch = build_batch(test_epoch(), vec![c1, c2]).unwrap();
        let receipt = build_receipt(&batch, 1);
        assert_eq!(receipt.candidates_proposed, 2);
        assert_eq!(receipt.candidates_accepted, 1);
        assert_eq!(receipt.acceptance_rate_millionths(), 500_000);
        assert_eq!(receipt.novelty_yield_millionths, 600_000); // first candidate
    }

    #[test]
    fn test_receipt_clamps_accepted_to_proposed() {
        let c1 = make_candidate_with_novelty("c1", 500_000);
        let batch = build_batch(test_epoch(), vec![c1]).unwrap();
        let receipt = build_receipt(&batch, 100); // way more than proposed
        assert_eq!(receipt.candidates_accepted, 1); // clamped
    }

    #[test]
    fn test_receipt_content_hash_deterministic() {
        let c1 = make_candidate_with_novelty("c1", 500_000);
        let batch = build_batch(test_epoch(), vec![c1]).unwrap();
        let r1 = build_receipt(&batch, 1);
        let r2 = build_receipt(&batch, 1);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_receipt_serde() {
        let c1 = make_candidate_with_novelty("c1", 500_000);
        let batch = build_batch(test_epoch(), vec![c1]).unwrap();
        let receipt = build_receipt(&batch, 1);
        let json = serde_json::to_string(&receipt).unwrap();
        let back: SynthesisReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn test_receipt_batch_id_matches() {
        let c1 = make_candidate_with_novelty("c1", 500_000);
        let batch = build_batch(test_epoch(), vec![c1]).unwrap();
        let receipt = build_receipt(&batch, 1);
        assert_eq!(receipt.batch_id, batch.batch_id);
    }

    #[test]
    fn test_receipt_epoch_matches() {
        let epoch = SecurityEpoch::from_raw(42);
        let batch = build_batch(epoch, Vec::new()).unwrap();
        let receipt = build_receipt(&batch, 0);
        assert_eq!(receipt.timestamp_epoch, epoch);
    }

    // -----------------------------------------------------------------------
    // franken_engine_synthesis_manifest
    // -----------------------------------------------------------------------

    #[test]
    fn test_manifest_non_empty() {
        let manifest = franken_engine_synthesis_manifest();
        assert!(!manifest.is_empty(), "manifest should contain candidates");
    }

    #[test]
    fn test_manifest_epoch() {
        let manifest = franken_engine_synthesis_manifest();
        assert_eq!(manifest.epoch, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn test_manifest_has_multiple_strategies() {
        let manifest = franken_engine_synthesis_manifest();
        // Should have at least some strategy diversity.
        assert!(
            manifest.strategy_distribution.len() >= 2,
            "manifest should use multiple strategies"
        );
    }

    #[test]
    fn test_manifest_has_multiple_kinds() {
        let manifest = franken_engine_synthesis_manifest();
        let mut kinds: BTreeSet<ProgramKind> = BTreeSet::new();
        for c in &manifest.candidates {
            kinds.insert(c.kind);
        }
        assert!(
            kinds.len() >= 2,
            "manifest should cover multiple program kinds"
        );
    }

    #[test]
    fn test_manifest_all_candidates_have_hashes() {
        let manifest = franken_engine_synthesis_manifest();
        for c in &manifest.candidates {
            assert_ne!(
                c.content_hash,
                ContentHash::default(),
                "candidate {} should have a non-default hash",
                c.candidate_id
            );
        }
    }

    #[test]
    fn test_manifest_unique_candidate_ids() {
        let manifest = franken_engine_synthesis_manifest();
        let mut ids: BTreeSet<&str> = BTreeSet::new();
        for c in &manifest.candidates {
            assert!(
                ids.insert(&c.candidate_id),
                "duplicate candidate id: {}",
                c.candidate_id
            );
        }
    }

    #[test]
    fn test_manifest_deterministic() {
        let m1 = franken_engine_synthesis_manifest();
        let m2 = franken_engine_synthesis_manifest();
        assert_eq!(m1.batch_id, m2.batch_id);
        assert_eq!(m1.candidates.len(), m2.candidates.len());
        assert_eq!(m1.total_novelty_millionths, m2.total_novelty_millionths);
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn test_manifest_total_novelty_positive() {
        let manifest = franken_engine_synthesis_manifest();
        assert!(
            manifest.total_novelty_millionths > 0,
            "manifest total novelty should be positive"
        );
    }

    // -----------------------------------------------------------------------
    // Edge cases and integration
    // -----------------------------------------------------------------------

    #[test]
    fn test_end_to_end_synthesize_filter_receipt() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let mut candidates = Vec::new();
        for i in 0..5u64 {
            let seed = i.to_le_bytes();
            if let Ok(c) = synthesize_candidate(
                ProgramKind::PlainJs,
                SynthesisStrategy::GrammarGuided,
                &constraint,
                &seed,
            ) {
                candidates.push(c);
            }
        }
        assert!(!candidates.is_empty());

        let (accepted, denied) = filter_candidates(candidates, &constraint);
        let total = accepted.len() + denied.len();
        assert!(total > 0);

        let batch = build_batch(test_epoch(), accepted.clone()).unwrap();
        let receipt = build_receipt(&batch, accepted.len() as u64);
        assert_eq!(receipt.candidates_proposed, accepted.len() as u64);
        assert_eq!(receipt.candidates_accepted, accepted.len() as u64);
    }

    #[test]
    fn test_all_kind_strategy_combinations() {
        let constraint = SynthesisConstraint::new(256, 4096, 0);
        let mut success_count = 0u64;
        for kind in ProgramKind::ALL {
            for strategy in SynthesisStrategy::ALL {
                let seed = format!("{}-{}", kind.as_str(), strategy.as_str());
                if synthesize_candidate(*kind, *strategy, &constraint, seed.as_bytes()).is_ok() {
                    success_count += 1;
                }
            }
        }
        // All 30 combinations should succeed with a generous constraint.
        assert_eq!(
            success_count,
            (KIND_COUNT * STRATEGY_COUNT) as u64,
            "all kind+strategy combinations should succeed"
        );
    }

    #[test]
    fn test_estimate_ast_nodes_nonzero() {
        for kind in ProgramKind::ALL {
            let nodes = estimate_ast_nodes("function f() { return 1; }", *kind);
            assert!(
                nodes >= kind.typical_min_nodes(),
                "nodes for {kind} should be >= typical minimum"
            );
        }
    }

    #[test]
    fn test_derive_target_cells_deterministic() {
        let cells1 = derive_target_cells(12345, ProgramKind::PlainJs);
        let cells2 = derive_target_cells(12345, ProgramKind::PlainJs);
        assert_eq!(cells1, cells2);
    }

    #[test]
    fn test_derive_target_cells_bounded() {
        for seed in 0..20u64 {
            let cells = derive_target_cells(seed, ProgramKind::TypeScript);
            assert!(!cells.is_empty());
            assert!(cells.len() <= 3);
        }
    }
}
