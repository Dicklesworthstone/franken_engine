#![forbid(unsafe_code)]

//! Law promotion pack: promotes accepted laws into rewrite packs, synthesis
//! lanes, support atlases, and frontier ledgers.
//!
//! Bead: bd-1lsy.9.10.3 [RGC-810C]
//!
//! Accepted laws from the theorem-mining pipeline (`law_mining`) are
//! promoted into durable runtime assets so that theorem mining compounds
//! across optimization, support truth, synthesis, and future frontier
//! expansion.
//!
//! # Design decisions
//!
//! - Promotion is one-way and content-addressed: a law can only be
//!   promoted, never silently demoted, and each promotion carries a
//!   receipt linking the accepted law to the target asset.
//! - Four promotion targets are defined: rewrite packs (optimizer rules),
//!   synthesis lanes (code generation seeds), support atlases (semantic
//!   coverage maps), and frontier ledgers (expansion priority queues).
//! - Each promotion produces a `PromotionReceipt` that records the law,
//!   target, epoch, and rationale so operators can audit the promotion
//!   chain.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the law promotion pack module.
pub const LAW_PROMOTION_SCHEMA_VERSION: &str = "franken-engine.law-promotion-pack.v1";

/// Bead identifier for this module.
pub const LAW_PROMOTION_BEAD_ID: &str = "bd-1lsy.9.10.3";

/// Component name.
pub const COMPONENT: &str = "law_promotion_pack";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// PromotionTarget
// ---------------------------------------------------------------------------

/// The asset class a law is being promoted into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionTarget {
    /// Rewrite pack: optimizer rewrite rules derived from laws.
    RewritePack,
    /// Synthesis lane: code generation seeds from invariants.
    SynthesisLane,
    /// Support atlas: semantic coverage map entries.
    SupportAtlas,
    /// Frontier ledger: expansion priority queue entries.
    FrontierLedger,
}

impl PromotionTarget {
    /// All promotion targets in canonical order.
    pub const ALL: &[Self] = &[
        Self::RewritePack,
        Self::SynthesisLane,
        Self::SupportAtlas,
        Self::FrontierLedger,
    ];
}

impl fmt::Display for PromotionTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::RewritePack => "rewrite_pack",
            Self::SynthesisLane => "synthesis_lane",
            Self::SupportAtlas => "support_atlas",
            Self::FrontierLedger => "frontier_ledger",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// LawStrength
// ---------------------------------------------------------------------------

/// Confidence tier for an accepted law.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LawStrength {
    /// Formally proved via solver or replay.
    Proved,
    /// Empirically validated over large campaign.
    Empirical,
    /// Conditionally valid under stated assumptions.
    Conditional,
    /// Heuristic — useful but not guaranteed.
    Heuristic,
}

impl LawStrength {
    /// All strengths in canonical order.
    pub const ALL: &[Self] = &[
        Self::Proved,
        Self::Empirical,
        Self::Conditional,
        Self::Heuristic,
    ];

    /// Weight used for priority scoring (millionths).
    pub fn weight_millionths(self) -> u64 {
        match self {
            Self::Proved => MILLION,
            Self::Empirical => 750_000,
            Self::Conditional => 500_000,
            Self::Heuristic => 250_000,
        }
    }
}

impl fmt::Display for LawStrength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Proved => "proved",
            Self::Empirical => "empirical",
            Self::Conditional => "conditional",
            Self::Heuristic => "heuristic",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// PromotionStatus
// ---------------------------------------------------------------------------

/// Status of a law promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionStatus {
    /// Pending review before promotion.
    Pending,
    /// Actively promoted and in use.
    Promoted,
    /// Superseded by a stronger or more general law.
    Superseded,
    /// Revoked due to counterexample or regression.
    Revoked,
    /// Expired — promotion epoch has lapsed.
    Expired,
}

impl PromotionStatus {
    /// All statuses in canonical order.
    pub const ALL: &[Self] = &[
        Self::Pending,
        Self::Promoted,
        Self::Superseded,
        Self::Revoked,
        Self::Expired,
    ];

    /// Whether this status represents an active promotion.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Promoted | Self::Pending)
    }
}

impl fmt::Display for PromotionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Pending => "pending",
            Self::Promoted => "promoted",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// AcceptedLaw
// ---------------------------------------------------------------------------

/// An accepted law ready for promotion, linking back to its mining
/// candidate and proof/refutation evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AcceptedLaw {
    /// Unique identifier for this accepted law.
    pub law_id: String,
    /// The original candidate law ID from law_mining.
    pub candidate_id: String,
    /// Human-readable law statement.
    pub statement: String,
    /// Strength of the acceptance evidence.
    pub strength: LawStrength,
    /// Scope of applicability (policy IDs, feature domains, etc.).
    pub scope_tags: Vec<String>,
    /// Rank from the mining pipeline (millionths).
    pub mining_rank_millionths: u64,
    /// Epoch at which the law was accepted.
    pub accepted_epoch: SecurityEpoch,
    /// IDs of supporting evidence (counterexamples, replays, proofs).
    pub evidence_ids: Vec<String>,
    /// Content hash of this accepted law.
    pub law_hash: ContentHash,
}

impl AcceptedLaw {
    /// Create a new accepted law.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        law_id: &str,
        candidate_id: &str,
        statement: &str,
        strength: LawStrength,
        scope_tags: Vec<String>,
        mining_rank_millionths: u64,
        epoch: SecurityEpoch,
        evidence_ids: Vec<String>,
    ) -> Self {
        let mut law = Self {
            law_id: law_id.to_string(),
            candidate_id: candidate_id.to_string(),
            statement: statement.to_string(),
            strength,
            scope_tags,
            mining_rank_millionths,
            accepted_epoch: epoch,
            evidence_ids,
            law_hash: ContentHash::compute(b"placeholder"),
        };
        law.recompute_hash();
        law
    }

    /// Compute the promotion priority (millionths) based on strength and rank.
    pub fn promotion_priority_millionths(&self) -> u64 {
        let strength_weight = self.strength.weight_millionths();
        // Weighted average: 60% strength, 40% mining rank
        let priority =
            (strength_weight * 600_000 + self.mining_rank_millionths * 400_000) / MILLION;
        priority.min(MILLION)
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.law_id.as_bytes());
        data.extend_from_slice(self.candidate_id.as_bytes());
        data.extend_from_slice(self.statement.as_bytes());
        data.extend_from_slice(format!("{:?}", self.strength).as_bytes());
        for tag in &self.scope_tags {
            data.extend_from_slice(tag.as_bytes());
        }
        data.extend_from_slice(&self.mining_rank_millionths.to_le_bytes());
        data.extend_from_slice(&self.accepted_epoch.as_u64().to_le_bytes());
        for eid in &self.evidence_ids {
            data.extend_from_slice(eid.as_bytes());
        }
        self.law_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for AcceptedLaw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AcceptedLaw({} strength={} rank={} scope={})",
            self.law_id,
            self.strength,
            self.mining_rank_millionths,
            self.scope_tags.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// RewriteRule
// ---------------------------------------------------------------------------

/// A rewrite rule derived from an accepted law for the optimizer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RewriteRule {
    /// Unique rule ID.
    pub rule_id: String,
    /// The accepted law this rule was derived from.
    pub source_law_id: String,
    /// Pattern to match (human-readable).
    pub match_pattern: String,
    /// Replacement expression (human-readable).
    pub replacement: String,
    /// Applicability guard (conditions under which the rewrite is safe).
    pub guard: String,
    /// Estimated speedup from applying this rule (millionths, 1.0 = no change).
    pub speedup_estimate_millionths: u64,
    /// Whether this rule preserves observable semantics.
    pub semantics_preserving: bool,
    /// Content hash of this rule.
    pub rule_hash: ContentHash,
}

impl RewriteRule {
    /// Create a new rewrite rule from an accepted law.
    pub fn from_law(
        rule_id: &str,
        law: &AcceptedLaw,
        match_pattern: &str,
        replacement: &str,
        guard: &str,
        speedup_estimate_millionths: u64,
    ) -> Self {
        let mut rule = Self {
            rule_id: rule_id.to_string(),
            source_law_id: law.law_id.clone(),
            match_pattern: match_pattern.to_string(),
            replacement: replacement.to_string(),
            guard: guard.to_string(),
            speedup_estimate_millionths,
            semantics_preserving: true,
            rule_hash: ContentHash::compute(b"placeholder"),
        };
        rule.recompute_hash();
        rule
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let canonical = format!(
            "rewrite:{}:{}:{}:{}:{}:{}:{}",
            self.rule_id,
            self.source_law_id,
            self.match_pattern,
            self.replacement,
            self.guard,
            self.speedup_estimate_millionths,
            self.semantics_preserving,
        );
        self.rule_hash = ContentHash::compute(canonical.as_bytes());
    }
}

impl fmt::Display for RewriteRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RewriteRule({} from={} speedup={})",
            self.rule_id, self.source_law_id, self.speedup_estimate_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// RewritePack
// ---------------------------------------------------------------------------

/// A collection of rewrite rules promoted from accepted laws.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewritePack {
    /// Pack identifier.
    pub pack_id: String,
    /// Epoch at which this pack was assembled.
    pub assembled_epoch: SecurityEpoch,
    /// Rewrite rules in this pack.
    pub rules: Vec<RewriteRule>,
    /// Schema version.
    pub schema_version: String,
    /// Content hash of the pack.
    pub pack_hash: ContentHash,
}

impl RewritePack {
    /// Create a new empty rewrite pack.
    pub fn new(pack_id: &str, epoch: SecurityEpoch) -> Self {
        let mut pack = Self {
            pack_id: pack_id.to_string(),
            assembled_epoch: epoch,
            rules: Vec::new(),
            schema_version: LAW_PROMOTION_SCHEMA_VERSION.to_string(),
            pack_hash: ContentHash::compute(b"placeholder"),
        };
        pack.recompute_hash();
        pack
    }

    /// Add a rewrite rule to the pack.
    pub fn add_rule(&mut self, rule: RewriteRule) {
        self.rules.push(rule);
        self.recompute_hash();
    }

    /// Number of rules in the pack.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.pack_id.as_bytes());
        data.extend_from_slice(&self.assembled_epoch.as_u64().to_le_bytes());
        data.extend_from_slice(self.schema_version.as_bytes());
        for rule in &self.rules {
            data.extend_from_slice(rule.rule_hash.as_bytes());
        }
        self.pack_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for RewritePack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RewritePack({} rules={} epoch={})",
            self.pack_id,
            self.rules.len(),
            self.assembled_epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// SynthesisSeed
// ---------------------------------------------------------------------------

/// A code generation seed derived from an accepted law.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SynthesisSeed {
    /// Unique seed ID.
    pub seed_id: String,
    /// The accepted law this seed was derived from.
    pub source_law_id: String,
    /// Template expression for code generation.
    pub template: String,
    /// Parameter names that the template expects.
    pub parameters: Vec<String>,
    /// Expected output pattern (for validation).
    pub expected_pattern: String,
    /// Priority for synthesis scheduling (millionths).
    pub priority_millionths: u64,
    /// Content hash of this seed.
    pub seed_hash: ContentHash,
}

impl SynthesisSeed {
    /// Create a new synthesis seed from an accepted law.
    pub fn from_law(
        seed_id: &str,
        law: &AcceptedLaw,
        template: &str,
        parameters: Vec<String>,
        expected_pattern: &str,
    ) -> Self {
        let priority = law.promotion_priority_millionths();
        let mut seed = Self {
            seed_id: seed_id.to_string(),
            source_law_id: law.law_id.clone(),
            template: template.to_string(),
            parameters,
            expected_pattern: expected_pattern.to_string(),
            priority_millionths: priority,
            seed_hash: ContentHash::compute(b"placeholder"),
        };
        seed.recompute_hash();
        seed
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.seed_id.as_bytes());
        data.extend_from_slice(self.source_law_id.as_bytes());
        data.extend_from_slice(self.template.as_bytes());
        for param in &self.parameters {
            data.extend_from_slice(param.as_bytes());
        }
        data.extend_from_slice(self.expected_pattern.as_bytes());
        data.extend_from_slice(&self.priority_millionths.to_le_bytes());
        self.seed_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for SynthesisSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SynthesisSeed({} from={} priority={})",
            self.seed_id, self.source_law_id, self.priority_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// SynthesisLane
// ---------------------------------------------------------------------------

/// A collection of synthesis seeds for code generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisLane {
    /// Lane identifier.
    pub lane_id: String,
    /// Epoch at which this lane was assembled.
    pub assembled_epoch: SecurityEpoch,
    /// Synthesis seeds in this lane.
    pub seeds: Vec<SynthesisSeed>,
    /// Schema version.
    pub schema_version: String,
    /// Content hash of the lane.
    pub lane_hash: ContentHash,
}

impl SynthesisLane {
    /// Create a new empty synthesis lane.
    pub fn new(lane_id: &str, epoch: SecurityEpoch) -> Self {
        let mut lane = Self {
            lane_id: lane_id.to_string(),
            assembled_epoch: epoch,
            seeds: Vec::new(),
            schema_version: LAW_PROMOTION_SCHEMA_VERSION.to_string(),
            lane_hash: ContentHash::compute(b"placeholder"),
        };
        lane.recompute_hash();
        lane
    }

    /// Add a synthesis seed.
    pub fn add_seed(&mut self, seed: SynthesisSeed) {
        self.seeds.push(seed);
        self.recompute_hash();
    }

    /// Number of seeds.
    pub fn seed_count(&self) -> usize {
        self.seeds.len()
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.lane_id.as_bytes());
        data.extend_from_slice(&self.assembled_epoch.as_u64().to_le_bytes());
        data.extend_from_slice(self.schema_version.as_bytes());
        for seed in &self.seeds {
            data.extend_from_slice(seed.seed_hash.as_bytes());
        }
        self.lane_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for SynthesisLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SynthesisLane({} seeds={} epoch={})",
            self.lane_id,
            self.seeds.len(),
            self.assembled_epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// SupportAtlasEntry
// ---------------------------------------------------------------------------

/// An entry in the support atlas, recording semantic coverage from a law.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SupportAtlasEntry {
    /// Entry identifier.
    pub entry_id: String,
    /// The accepted law providing this coverage.
    pub source_law_id: String,
    /// Semantic domain covered (e.g., "string.prototype.split", "module.resolution").
    pub domain: String,
    /// Coverage depth (millionths, 1_000_000 = full coverage).
    pub coverage_depth_millionths: u64,
    /// Scope tags inherited from the law.
    pub scope_tags: Vec<String>,
    /// Whether this entry has been validated against a real workload.
    pub workload_validated: bool,
    /// Content hash of this entry.
    pub entry_hash: ContentHash,
}

impl SupportAtlasEntry {
    /// Create a new atlas entry from an accepted law.
    pub fn from_law(
        entry_id: &str,
        law: &AcceptedLaw,
        domain: &str,
        coverage_depth_millionths: u64,
    ) -> Self {
        let mut entry = Self {
            entry_id: entry_id.to_string(),
            source_law_id: law.law_id.clone(),
            domain: domain.to_string(),
            coverage_depth_millionths,
            scope_tags: law.scope_tags.clone(),
            workload_validated: false,
            entry_hash: ContentHash::compute(b"placeholder"),
        };
        entry.recompute_hash();
        entry
    }

    /// Mark as workload-validated.
    pub fn validate(&mut self) {
        self.workload_validated = true;
        self.recompute_hash();
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.entry_id.as_bytes());
        data.extend_from_slice(self.source_law_id.as_bytes());
        data.extend_from_slice(self.domain.as_bytes());
        data.extend_from_slice(&self.coverage_depth_millionths.to_le_bytes());
        for tag in &self.scope_tags {
            data.extend_from_slice(tag.as_bytes());
        }
        data.push(u8::from(self.workload_validated));
        self.entry_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for SupportAtlasEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SupportAtlasEntry({} domain={} coverage={} validated={})",
            self.entry_id, self.domain, self.coverage_depth_millionths, self.workload_validated,
        )
    }
}

// ---------------------------------------------------------------------------
// SupportAtlas
// ---------------------------------------------------------------------------

/// A collection of support atlas entries recording semantic coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportAtlas {
    /// Atlas identifier.
    pub atlas_id: String,
    /// Epoch at which this atlas was assembled.
    pub assembled_epoch: SecurityEpoch,
    /// Coverage entries.
    pub entries: Vec<SupportAtlasEntry>,
    /// Schema version.
    pub schema_version: String,
    /// Content hash of the atlas.
    pub atlas_hash: ContentHash,
}

impl SupportAtlas {
    /// Create a new empty support atlas.
    pub fn new(atlas_id: &str, epoch: SecurityEpoch) -> Self {
        let mut atlas = Self {
            atlas_id: atlas_id.to_string(),
            assembled_epoch: epoch,
            entries: Vec::new(),
            schema_version: LAW_PROMOTION_SCHEMA_VERSION.to_string(),
            atlas_hash: ContentHash::compute(b"placeholder"),
        };
        atlas.recompute_hash();
        atlas
    }

    /// Add a coverage entry.
    pub fn add_entry(&mut self, entry: SupportAtlasEntry) {
        self.entries.push(entry);
        self.recompute_hash();
    }

    /// Number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Unique domains covered.
    pub fn covered_domains(&self) -> BTreeSet<String> {
        self.entries.iter().map(|e| e.domain.clone()).collect()
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.atlas_id.as_bytes());
        data.extend_from_slice(&self.assembled_epoch.as_u64().to_le_bytes());
        data.extend_from_slice(self.schema_version.as_bytes());
        for entry in &self.entries {
            data.extend_from_slice(entry.entry_hash.as_bytes());
        }
        self.atlas_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for SupportAtlas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SupportAtlas({} entries={} domains={} epoch={})",
            self.atlas_id,
            self.entries.len(),
            self.covered_domains().len(),
            self.assembled_epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// FrontierEntry
// ---------------------------------------------------------------------------

/// An entry in the frontier ledger, recording expansion priority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FrontierEntry {
    /// Entry identifier.
    pub entry_id: String,
    /// The accepted law motivating this frontier expansion.
    pub source_law_id: String,
    /// Frontier region to explore (human-readable description).
    pub frontier_region: String,
    /// Priority for expansion (millionths; higher = more urgent).
    pub priority_millionths: u64,
    /// Expected information gain from exploring this region (millionths).
    pub expected_gain_millionths: u64,
    /// Whether this frontier has been explored.
    pub explored: bool,
    /// Content hash of this entry.
    pub entry_hash: ContentHash,
}

impl FrontierEntry {
    /// Create a new frontier entry from an accepted law.
    pub fn from_law(
        entry_id: &str,
        law: &AcceptedLaw,
        frontier_region: &str,
        expected_gain_millionths: u64,
    ) -> Self {
        let priority = law.promotion_priority_millionths();
        let mut entry = Self {
            entry_id: entry_id.to_string(),
            source_law_id: law.law_id.clone(),
            frontier_region: frontier_region.to_string(),
            priority_millionths: priority,
            expected_gain_millionths,
            explored: false,
            entry_hash: ContentHash::compute(b"placeholder"),
        };
        entry.recompute_hash();
        entry
    }

    /// Mark as explored.
    pub fn mark_explored(&mut self) {
        self.explored = true;
        self.recompute_hash();
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.entry_id.as_bytes());
        data.extend_from_slice(self.source_law_id.as_bytes());
        data.extend_from_slice(self.frontier_region.as_bytes());
        data.extend_from_slice(&self.priority_millionths.to_le_bytes());
        data.extend_from_slice(&self.expected_gain_millionths.to_le_bytes());
        data.push(u8::from(self.explored));
        self.entry_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for FrontierEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FrontierEntry({} region={} priority={} explored={})",
            self.entry_id, self.frontier_region, self.priority_millionths, self.explored,
        )
    }
}

// ---------------------------------------------------------------------------
// FrontierLedger
// ---------------------------------------------------------------------------

/// A ledger of frontier entries for expansion priority tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierLedger {
    /// Ledger identifier.
    pub ledger_id: String,
    /// Epoch at which this ledger was assembled.
    pub assembled_epoch: SecurityEpoch,
    /// Frontier entries.
    pub entries: Vec<FrontierEntry>,
    /// Schema version.
    pub schema_version: String,
    /// Content hash of the ledger.
    pub ledger_hash: ContentHash,
}

impl FrontierLedger {
    /// Create a new empty frontier ledger.
    pub fn new(ledger_id: &str, epoch: SecurityEpoch) -> Self {
        let mut ledger = Self {
            ledger_id: ledger_id.to_string(),
            assembled_epoch: epoch,
            entries: Vec::new(),
            schema_version: LAW_PROMOTION_SCHEMA_VERSION.to_string(),
            ledger_hash: ContentHash::compute(b"placeholder"),
        };
        ledger.recompute_hash();
        ledger
    }

    /// Add a frontier entry.
    pub fn add_entry(&mut self, entry: FrontierEntry) {
        self.entries.push(entry);
        self.recompute_hash();
    }

    /// Number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of unexplored frontiers.
    pub fn unexplored_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.explored).count()
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.ledger_id.as_bytes());
        data.extend_from_slice(&self.assembled_epoch.as_u64().to_le_bytes());
        data.extend_from_slice(self.schema_version.as_bytes());
        for entry in &self.entries {
            data.extend_from_slice(entry.entry_hash.as_bytes());
        }
        self.ledger_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for FrontierLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FrontierLedger({} entries={} unexplored={} epoch={})",
            self.ledger_id,
            self.entries.len(),
            self.unexplored_count(),
            self.assembled_epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// PromotionReceipt
// ---------------------------------------------------------------------------

/// Receipt recording the promotion of an accepted law to a target asset.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PromotionReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// The law that was promoted.
    pub law_id: String,
    /// The target asset class.
    pub target: PromotionTarget,
    /// The generated asset ID in the target.
    pub asset_id: String,
    /// Epoch of promotion.
    pub promotion_epoch: SecurityEpoch,
    /// Status of the promotion.
    pub status: PromotionStatus,
    /// Human-readable rationale for the promotion.
    pub rationale: String,
    /// Content hash of this receipt.
    pub receipt_hash: ContentHash,
}

impl PromotionReceipt {
    /// Create a new promotion receipt.
    pub fn new(
        receipt_id: &str,
        law_id: &str,
        target: PromotionTarget,
        asset_id: &str,
        epoch: SecurityEpoch,
        rationale: &str,
    ) -> Self {
        let mut receipt = Self {
            receipt_id: receipt_id.to_string(),
            law_id: law_id.to_string(),
            target,
            asset_id: asset_id.to_string(),
            promotion_epoch: epoch,
            status: PromotionStatus::Promoted,
            rationale: rationale.to_string(),
            receipt_hash: ContentHash::compute(b"placeholder"),
        };
        receipt.recompute_hash();
        receipt
    }

    /// Revoke this promotion.
    pub fn revoke(&mut self, reason: &str) {
        self.status = PromotionStatus::Revoked;
        self.rationale = format!("REVOKED: {reason}");
        self.recompute_hash();
    }

    /// Supersede this promotion.
    pub fn supersede(&mut self, superseding_law_id: &str) {
        self.status = PromotionStatus::Superseded;
        self.rationale = format!("Superseded by {superseding_law_id}");
        self.recompute_hash();
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let canonical = format!(
            "promotion:{}:{}:{}:{}:{}:{}",
            self.receipt_id,
            self.law_id,
            self.target,
            self.asset_id,
            self.promotion_epoch.as_u64(),
            self.status,
        );
        self.receipt_hash = ContentHash::compute(canonical.as_bytes());
    }
}

impl fmt::Display for PromotionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PromotionReceipt({} law={} target={} status={})",
            self.receipt_id, self.law_id, self.target, self.status,
        )
    }
}

// ---------------------------------------------------------------------------
// PromotionPipeline
// ---------------------------------------------------------------------------

/// Orchestrates the promotion of accepted laws into the four target assets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionPipeline {
    /// The rewrite pack being assembled.
    pub rewrite_pack: RewritePack,
    /// The synthesis lane being assembled.
    pub synthesis_lane: SynthesisLane,
    /// The support atlas being assembled.
    pub support_atlas: SupportAtlas,
    /// The frontier ledger being assembled.
    pub frontier_ledger: FrontierLedger,
    /// All promotion receipts.
    pub receipts: Vec<PromotionReceipt>,
    /// Epoch at which the pipeline was created.
    pub pipeline_epoch: SecurityEpoch,
    /// Schema version.
    pub schema_version: String,
    /// Content hash of the pipeline state.
    pub pipeline_hash: ContentHash,
}

impl PromotionPipeline {
    /// Create a new promotion pipeline.
    pub fn new(pipeline_id: &str, epoch: SecurityEpoch) -> Self {
        let mut pipeline = Self {
            rewrite_pack: RewritePack::new(&format!("{pipeline_id}-rewrite"), epoch),
            synthesis_lane: SynthesisLane::new(&format!("{pipeline_id}-synthesis"), epoch),
            support_atlas: SupportAtlas::new(&format!("{pipeline_id}-atlas"), epoch),
            frontier_ledger: FrontierLedger::new(&format!("{pipeline_id}-frontier"), epoch),
            receipts: Vec::new(),
            pipeline_epoch: epoch,
            schema_version: LAW_PROMOTION_SCHEMA_VERSION.to_string(),
            pipeline_hash: ContentHash::compute(b"placeholder"),
        };
        pipeline.recompute_hash();
        pipeline
    }

    /// Promote a law to a rewrite pack rule.
    pub fn promote_to_rewrite(
        &mut self,
        law: &AcceptedLaw,
        match_pattern: &str,
        replacement: &str,
        guard: &str,
        speedup_estimate_millionths: u64,
    ) -> PromotionReceipt {
        let rule_id = format!("rw-{}", law.law_id);
        let rule = RewriteRule::from_law(
            &rule_id,
            law,
            match_pattern,
            replacement,
            guard,
            speedup_estimate_millionths,
        );
        self.rewrite_pack.add_rule(rule);

        let receipt_id = format!("pr-rw-{}", law.law_id);
        let receipt = PromotionReceipt::new(
            &receipt_id,
            &law.law_id,
            PromotionTarget::RewritePack,
            &rule_id,
            self.pipeline_epoch,
            &format!("Promoted {} to rewrite pack", law.law_id),
        );
        self.receipts.push(receipt.clone());
        self.recompute_hash();
        receipt
    }

    /// Promote a law to a synthesis lane seed.
    pub fn promote_to_synthesis(
        &mut self,
        law: &AcceptedLaw,
        template: &str,
        parameters: Vec<String>,
        expected_pattern: &str,
    ) -> PromotionReceipt {
        let seed_id = format!("syn-{}", law.law_id);
        let seed = SynthesisSeed::from_law(&seed_id, law, template, parameters, expected_pattern);
        self.synthesis_lane.add_seed(seed);

        let receipt_id = format!("pr-syn-{}", law.law_id);
        let receipt = PromotionReceipt::new(
            &receipt_id,
            &law.law_id,
            PromotionTarget::SynthesisLane,
            &seed_id,
            self.pipeline_epoch,
            &format!("Promoted {} to synthesis lane", law.law_id),
        );
        self.receipts.push(receipt.clone());
        self.recompute_hash();
        receipt
    }

    /// Promote a law to a support atlas entry.
    pub fn promote_to_atlas(
        &mut self,
        law: &AcceptedLaw,
        domain: &str,
        coverage_depth_millionths: u64,
    ) -> PromotionReceipt {
        let entry_id = format!("atlas-{}", law.law_id);
        let entry = SupportAtlasEntry::from_law(&entry_id, law, domain, coverage_depth_millionths);
        self.support_atlas.add_entry(entry);

        let receipt_id = format!("pr-atlas-{}", law.law_id);
        let receipt = PromotionReceipt::new(
            &receipt_id,
            &law.law_id,
            PromotionTarget::SupportAtlas,
            &entry_id,
            self.pipeline_epoch,
            &format!("Promoted {} to support atlas", law.law_id),
        );
        self.receipts.push(receipt.clone());
        self.recompute_hash();
        receipt
    }

    /// Promote a law to a frontier ledger entry.
    pub fn promote_to_frontier(
        &mut self,
        law: &AcceptedLaw,
        frontier_region: &str,
        expected_gain_millionths: u64,
    ) -> PromotionReceipt {
        let entry_id = format!("front-{}", law.law_id);
        let entry =
            FrontierEntry::from_law(&entry_id, law, frontier_region, expected_gain_millionths);
        self.frontier_ledger.add_entry(entry);

        let receipt_id = format!("pr-front-{}", law.law_id);
        let receipt = PromotionReceipt::new(
            &receipt_id,
            &law.law_id,
            PromotionTarget::FrontierLedger,
            &entry_id,
            self.pipeline_epoch,
            &format!("Promoted {} to frontier ledger", law.law_id),
        );
        self.receipts.push(receipt.clone());
        self.recompute_hash();
        receipt
    }

    /// Total number of promoted assets.
    pub fn total_promotions(&self) -> usize {
        self.receipts.len()
    }

    /// Number of active (non-revoked) promotions.
    pub fn active_promotions(&self) -> usize {
        self.receipts
            .iter()
            .filter(|r| r.status.is_active())
            .count()
    }

    /// Compute a summary report.
    pub fn summary_report(&self) -> PromotionSummaryReport {
        PromotionSummaryReport {
            total_promotions: self.total_promotions(),
            active_promotions: self.active_promotions(),
            rewrite_rules: self.rewrite_pack.rule_count(),
            synthesis_seeds: self.synthesis_lane.seed_count(),
            atlas_entries: self.support_atlas.entry_count(),
            frontier_entries: self.frontier_ledger.entry_count(),
            unexplored_frontiers: self.frontier_ledger.unexplored_count(),
            covered_domains: self.support_atlas.covered_domains().len(),
            epoch: self.pipeline_epoch,
        }
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.schema_version.as_bytes());
        data.extend_from_slice(&self.pipeline_epoch.as_u64().to_le_bytes());
        data.extend_from_slice(self.rewrite_pack.pack_hash.as_bytes());
        data.extend_from_slice(self.synthesis_lane.lane_hash.as_bytes());
        data.extend_from_slice(self.support_atlas.atlas_hash.as_bytes());
        data.extend_from_slice(self.frontier_ledger.ledger_hash.as_bytes());
        for receipt in &self.receipts {
            data.extend_from_slice(receipt.receipt_hash.as_bytes());
        }
        self.pipeline_hash = ContentHash::compute(&data);
    }
}

impl fmt::Display for PromotionPipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PromotionPipeline(promotions={} rewrites={} seeds={} atlas={} frontier={} epoch={})",
            self.total_promotions(),
            self.rewrite_pack.rule_count(),
            self.synthesis_lane.seed_count(),
            self.support_atlas.entry_count(),
            self.frontier_ledger.entry_count(),
            self.pipeline_epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// PromotionSummaryReport
// ---------------------------------------------------------------------------

/// Summary report of the promotion pipeline state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionSummaryReport {
    /// Total number of promotions.
    pub total_promotions: usize,
    /// Number of active promotions.
    pub active_promotions: usize,
    /// Number of rewrite rules.
    pub rewrite_rules: usize,
    /// Number of synthesis seeds.
    pub synthesis_seeds: usize,
    /// Number of atlas entries.
    pub atlas_entries: usize,
    /// Number of frontier entries.
    pub frontier_entries: usize,
    /// Number of unexplored frontiers.
    pub unexplored_frontiers: usize,
    /// Number of unique domains covered.
    pub covered_domains: usize,
    /// Pipeline epoch.
    pub epoch: SecurityEpoch,
}

impl fmt::Display for PromotionSummaryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PromotionSummary(promotions={}/{} rewrites={} seeds={} atlas={} frontier={}/{})",
            self.active_promotions,
            self.total_promotions,
            self.rewrite_rules,
            self.synthesis_seeds,
            self.atlas_entries,
            self.unexplored_frontiers,
            self.frontier_entries,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn test_law() -> AcceptedLaw {
        AcceptedLaw::new(
            "law-001",
            "cand-001",
            "typeof x === 'string' => x.length >= 0",
            LawStrength::Proved,
            vec!["string-ops".to_string(), "type-guard".to_string()],
            800_000,
            test_epoch(),
            vec!["ev-001".to_string(), "ev-002".to_string()],
        )
    }

    fn test_law_empirical() -> AcceptedLaw {
        AcceptedLaw::new(
            "law-002",
            "cand-002",
            "Array.isArray(x) => x.length is non-negative integer",
            LawStrength::Empirical,
            vec!["array-ops".to_string()],
            600_000,
            test_epoch(),
            vec!["ev-003".to_string()],
        )
    }

    // --- PromotionTarget ---

    #[test]
    fn test_target_display() {
        assert_eq!(PromotionTarget::RewritePack.to_string(), "rewrite_pack");
        assert_eq!(PromotionTarget::SynthesisLane.to_string(), "synthesis_lane");
        assert_eq!(PromotionTarget::SupportAtlas.to_string(), "support_atlas");
        assert_eq!(
            PromotionTarget::FrontierLedger.to_string(),
            "frontier_ledger"
        );
    }

    #[test]
    fn test_target_all() {
        assert_eq!(PromotionTarget::ALL.len(), 4);
    }

    #[test]
    fn test_target_serde_roundtrip() {
        for target in PromotionTarget::ALL {
            let json = serde_json::to_string(target).unwrap();
            let back: PromotionTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(*target, back);
        }
    }

    // --- LawStrength ---

    #[test]
    fn test_strength_display() {
        assert_eq!(LawStrength::Proved.to_string(), "proved");
        assert_eq!(LawStrength::Empirical.to_string(), "empirical");
        assert_eq!(LawStrength::Conditional.to_string(), "conditional");
        assert_eq!(LawStrength::Heuristic.to_string(), "heuristic");
    }

    #[test]
    fn test_strength_weights() {
        assert_eq!(LawStrength::Proved.weight_millionths(), MILLION);
        assert_eq!(LawStrength::Empirical.weight_millionths(), 750_000);
        assert_eq!(LawStrength::Conditional.weight_millionths(), 500_000);
        assert_eq!(LawStrength::Heuristic.weight_millionths(), 250_000);
    }

    #[test]
    fn test_strength_serde_roundtrip() {
        for strength in LawStrength::ALL {
            let json = serde_json::to_string(strength).unwrap();
            let back: LawStrength = serde_json::from_str(&json).unwrap();
            assert_eq!(*strength, back);
        }
    }

    // --- PromotionStatus ---

    #[test]
    fn test_status_display() {
        assert_eq!(PromotionStatus::Pending.to_string(), "pending");
        assert_eq!(PromotionStatus::Promoted.to_string(), "promoted");
        assert_eq!(PromotionStatus::Superseded.to_string(), "superseded");
        assert_eq!(PromotionStatus::Revoked.to_string(), "revoked");
        assert_eq!(PromotionStatus::Expired.to_string(), "expired");
    }

    #[test]
    fn test_status_is_active() {
        assert!(PromotionStatus::Pending.is_active());
        assert!(PromotionStatus::Promoted.is_active());
        assert!(!PromotionStatus::Superseded.is_active());
        assert!(!PromotionStatus::Revoked.is_active());
        assert!(!PromotionStatus::Expired.is_active());
    }

    #[test]
    fn test_status_all() {
        assert_eq!(PromotionStatus::ALL.len(), 5);
    }

    #[test]
    fn test_status_serde_roundtrip() {
        for status in PromotionStatus::ALL {
            let json = serde_json::to_string(status).unwrap();
            let back: PromotionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, back);
        }
    }

    // --- AcceptedLaw ---

    #[test]
    fn test_accepted_law_creation() {
        let law = test_law();
        assert_eq!(law.law_id, "law-001");
        assert_eq!(law.strength, LawStrength::Proved);
        assert_eq!(law.scope_tags.len(), 2);
    }

    #[test]
    fn test_accepted_law_priority() {
        let proved = test_law();
        let empirical = test_law_empirical();
        assert!(proved.promotion_priority_millionths() > empirical.promotion_priority_millionths());
    }

    #[test]
    fn test_accepted_law_priority_formula() {
        let law = test_law(); // Proved, rank=800_000
        // 60% * 1_000_000 + 40% * 800_000 = 600_000 + 320_000 = 920_000
        assert_eq!(law.promotion_priority_millionths(), 920_000);
    }

    #[test]
    fn test_accepted_law_hash_determinism() {
        let l1 = test_law();
        let l2 = test_law();
        assert_eq!(l1.law_hash, l2.law_hash);
    }

    #[test]
    fn test_accepted_law_display() {
        let law = test_law();
        let display = law.to_string();
        assert!(display.contains("AcceptedLaw"));
        assert!(display.contains("law-001"));
    }

    #[test]
    fn test_accepted_law_serde_roundtrip() {
        let law = test_law();
        let json = serde_json::to_string(&law).unwrap();
        let back: AcceptedLaw = serde_json::from_str(&json).unwrap();
        assert_eq!(law, back);
    }

    // --- RewriteRule ---

    #[test]
    fn test_rewrite_rule_creation() {
        let law = test_law();
        let rule = RewriteRule::from_law(
            "rw-001",
            &law,
            "typeof x === 'string'",
            "x is_string_tagged",
            "x.tag == STRING",
            1_200_000,
        );
        assert_eq!(rule.rule_id, "rw-001");
        assert_eq!(rule.source_law_id, "law-001");
        assert!(rule.semantics_preserving);
    }

    #[test]
    fn test_rewrite_rule_display() {
        let law = test_law();
        let rule = RewriteRule::from_law("rw-001", &law, "p", "r", "g", 1_100_000);
        let display = rule.to_string();
        assert!(display.contains("RewriteRule"));
    }

    #[test]
    fn test_rewrite_rule_serde_roundtrip() {
        let law = test_law();
        let rule = RewriteRule::from_law("rw-001", &law, "p", "r", "g", 1_100_000);
        let json = serde_json::to_string(&rule).unwrap();
        let back: RewriteRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    #[test]
    fn test_rewrite_rule_hash_determinism() {
        let law = test_law();
        let r1 = RewriteRule::from_law("rw-x", &law, "p", "r", "g", 1_050_000);
        let r2 = RewriteRule::from_law("rw-x", &law, "p", "r", "g", 1_050_000);
        assert_eq!(r1.rule_hash, r2.rule_hash);
    }

    // --- RewritePack ---

    #[test]
    fn test_rewrite_pack_creation() {
        let pack = RewritePack::new("pack-001", test_epoch());
        assert_eq!(pack.pack_id, "pack-001");
        assert_eq!(pack.rule_count(), 0);
    }

    #[test]
    fn test_rewrite_pack_add_rule() {
        let mut pack = RewritePack::new("pack-001", test_epoch());
        let law = test_law();
        let rule = RewriteRule::from_law("rw-001", &law, "p", "r", "g", MILLION);
        pack.add_rule(rule);
        assert_eq!(pack.rule_count(), 1);
    }

    #[test]
    fn test_rewrite_pack_serde_roundtrip() {
        let pack = RewritePack::new("pack-001", test_epoch());
        let json = serde_json::to_string(&pack).unwrap();
        let back: RewritePack = serde_json::from_str(&json).unwrap();
        assert_eq!(pack, back);
    }

    // --- SynthesisSeed ---

    #[test]
    fn test_synthesis_seed_creation() {
        let law = test_law();
        let seed = SynthesisSeed::from_law(
            "syn-001",
            &law,
            "function test_$param() { return $param.length; }",
            vec!["param".to_string()],
            "result >= 0",
        );
        assert_eq!(seed.seed_id, "syn-001");
        assert_eq!(
            seed.priority_millionths,
            law.promotion_priority_millionths()
        );
    }

    #[test]
    fn test_synthesis_seed_display() {
        let law = test_law();
        let seed = SynthesisSeed::from_law("syn-001", &law, "t", vec![], "p");
        let display = seed.to_string();
        assert!(display.contains("SynthesisSeed"));
    }

    #[test]
    fn test_synthesis_seed_serde_roundtrip() {
        let law = test_law();
        let seed = SynthesisSeed::from_law("syn-001", &law, "t", vec!["a".into()], "p");
        let json = serde_json::to_string(&seed).unwrap();
        let back: SynthesisSeed = serde_json::from_str(&json).unwrap();
        assert_eq!(seed, back);
    }

    // --- SynthesisLane ---

    #[test]
    fn test_synthesis_lane_creation() {
        let lane = SynthesisLane::new("lane-001", test_epoch());
        assert_eq!(lane.seed_count(), 0);
    }

    #[test]
    fn test_synthesis_lane_add_seed() {
        let mut lane = SynthesisLane::new("lane-001", test_epoch());
        let law = test_law();
        let seed = SynthesisSeed::from_law("syn-001", &law, "t", vec![], "p");
        lane.add_seed(seed);
        assert_eq!(lane.seed_count(), 1);
    }

    // --- SupportAtlasEntry ---

    #[test]
    fn test_atlas_entry_creation() {
        let law = test_law();
        let entry = SupportAtlasEntry::from_law("ae-001", &law, "string.length", 750_000);
        assert_eq!(entry.domain, "string.length");
        assert!(!entry.workload_validated);
        assert_eq!(entry.scope_tags.len(), 2);
    }

    #[test]
    fn test_atlas_entry_validate() {
        let law = test_law();
        let mut entry = SupportAtlasEntry::from_law("ae-001", &law, "string.length", 750_000);
        let hash_before = entry.entry_hash;
        entry.validate();
        assert!(entry.workload_validated);
        assert_ne!(entry.entry_hash, hash_before);
    }

    #[test]
    fn test_atlas_entry_serde_roundtrip() {
        let law = test_law();
        let entry = SupportAtlasEntry::from_law("ae-001", &law, "d", 500_000);
        let json = serde_json::to_string(&entry).unwrap();
        let back: SupportAtlasEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // --- SupportAtlas ---

    #[test]
    fn test_support_atlas_creation() {
        let atlas = SupportAtlas::new("atlas-001", test_epoch());
        assert_eq!(atlas.entry_count(), 0);
        assert!(atlas.covered_domains().is_empty());
    }

    #[test]
    fn test_support_atlas_covered_domains() {
        let mut atlas = SupportAtlas::new("atlas-001", test_epoch());
        let law = test_law();
        atlas.add_entry(SupportAtlasEntry::from_law(
            "e1",
            &law,
            "string.length",
            500_000,
        ));
        atlas.add_entry(SupportAtlasEntry::from_law(
            "e2",
            &law,
            "array.push",
            600_000,
        ));
        atlas.add_entry(SupportAtlasEntry::from_law(
            "e3",
            &law,
            "string.length",
            700_000,
        ));
        assert_eq!(atlas.covered_domains().len(), 2);
    }

    // --- FrontierEntry ---

    #[test]
    fn test_frontier_entry_creation() {
        let law = test_law();
        let entry = FrontierEntry::from_law("f-001", &law, "regex.backtracking", 300_000);
        assert!(!entry.explored);
        assert_eq!(entry.expected_gain_millionths, 300_000);
    }

    #[test]
    fn test_frontier_entry_mark_explored() {
        let law = test_law();
        let mut entry = FrontierEntry::from_law("f-001", &law, "regex", 300_000);
        entry.mark_explored();
        assert!(entry.explored);
    }

    #[test]
    fn test_frontier_entry_serde_roundtrip() {
        let law = test_law();
        let entry = FrontierEntry::from_law("f-001", &law, "r", 200_000);
        let json = serde_json::to_string(&entry).unwrap();
        let back: FrontierEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // --- FrontierLedger ---

    #[test]
    fn test_frontier_ledger_creation() {
        let ledger = FrontierLedger::new("ledger-001", test_epoch());
        assert_eq!(ledger.entry_count(), 0);
        assert_eq!(ledger.unexplored_count(), 0);
    }

    #[test]
    fn test_frontier_ledger_unexplored() {
        let mut ledger = FrontierLedger::new("ledger-001", test_epoch());
        let law = test_law();
        let mut e1 = FrontierEntry::from_law("f1", &law, "r1", 100_000);
        let e2 = FrontierEntry::from_law("f2", &law, "r2", 200_000);
        e1.mark_explored();
        ledger.add_entry(e1);
        ledger.add_entry(e2);
        assert_eq!(ledger.entry_count(), 2);
        assert_eq!(ledger.unexplored_count(), 1);
    }

    // --- PromotionReceipt ---

    #[test]
    fn test_receipt_creation() {
        let receipt = PromotionReceipt::new(
            "pr-001",
            "law-001",
            PromotionTarget::RewritePack,
            "rw-001",
            test_epoch(),
            "test promotion",
        );
        assert_eq!(receipt.status, PromotionStatus::Promoted);
    }

    #[test]
    fn test_receipt_revoke() {
        let mut receipt = PromotionReceipt::new(
            "pr-001",
            "law-001",
            PromotionTarget::RewritePack,
            "rw-001",
            test_epoch(),
            "test",
        );
        receipt.revoke("counterexample found");
        assert_eq!(receipt.status, PromotionStatus::Revoked);
        assert!(receipt.rationale.contains("REVOKED"));
    }

    #[test]
    fn test_receipt_supersede() {
        let mut receipt = PromotionReceipt::new(
            "pr-001",
            "law-001",
            PromotionTarget::SynthesisLane,
            "syn-001",
            test_epoch(),
            "test",
        );
        receipt.supersede("law-002");
        assert_eq!(receipt.status, PromotionStatus::Superseded);
        assert!(receipt.rationale.contains("law-002"));
    }

    #[test]
    fn test_receipt_display() {
        let receipt = PromotionReceipt::new(
            "pr-001",
            "law-001",
            PromotionTarget::FrontierLedger,
            "f-001",
            test_epoch(),
            "test",
        );
        let display = receipt.to_string();
        assert!(display.contains("PromotionReceipt"));
        assert!(display.contains("law-001"));
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let receipt = PromotionReceipt::new(
            "pr-001",
            "law-001",
            PromotionTarget::SupportAtlas,
            "ae-001",
            test_epoch(),
            "test",
        );
        let json = serde_json::to_string(&receipt).unwrap();
        let back: PromotionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn test_receipt_hash_determinism() {
        let r1 = PromotionReceipt::new(
            "p",
            "l",
            PromotionTarget::RewritePack,
            "a",
            test_epoch(),
            "r",
        );
        let r2 = PromotionReceipt::new(
            "p",
            "l",
            PromotionTarget::RewritePack,
            "a",
            test_epoch(),
            "r",
        );
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    // --- PromotionPipeline ---

    #[test]
    fn test_pipeline_creation() {
        let pipeline = PromotionPipeline::new("pipe-001", test_epoch());
        assert_eq!(pipeline.total_promotions(), 0);
        assert_eq!(pipeline.active_promotions(), 0);
    }

    #[test]
    fn test_pipeline_promote_to_rewrite() {
        let mut pipeline = PromotionPipeline::new("pipe-001", test_epoch());
        let law = test_law();
        let receipt = pipeline.promote_to_rewrite(&law, "typeof x", "tag_check", "true", 1_100_000);
        assert_eq!(receipt.target, PromotionTarget::RewritePack);
        assert_eq!(pipeline.rewrite_pack.rule_count(), 1);
    }

    #[test]
    fn test_pipeline_promote_to_synthesis() {
        let mut pipeline = PromotionPipeline::new("pipe-001", test_epoch());
        let law = test_law();
        let receipt = pipeline.promote_to_synthesis(&law, "test_$p() {}", vec!["p".into()], "true");
        assert_eq!(receipt.target, PromotionTarget::SynthesisLane);
        assert_eq!(pipeline.synthesis_lane.seed_count(), 1);
    }

    #[test]
    fn test_pipeline_promote_to_atlas() {
        let mut pipeline = PromotionPipeline::new("pipe-001", test_epoch());
        let law = test_law();
        let receipt = pipeline.promote_to_atlas(&law, "string.length", 800_000);
        assert_eq!(receipt.target, PromotionTarget::SupportAtlas);
        assert_eq!(pipeline.support_atlas.entry_count(), 1);
    }

    #[test]
    fn test_pipeline_promote_to_frontier() {
        let mut pipeline = PromotionPipeline::new("pipe-001", test_epoch());
        let law = test_law();
        let receipt = pipeline.promote_to_frontier(&law, "regex.backtrack", 500_000);
        assert_eq!(receipt.target, PromotionTarget::FrontierLedger);
        assert_eq!(pipeline.frontier_ledger.entry_count(), 1);
    }

    #[test]
    fn test_pipeline_multi_promote() {
        let mut pipeline = PromotionPipeline::new("pipe-001", test_epoch());
        let law1 = test_law();
        let law2 = test_law_empirical();
        pipeline.promote_to_rewrite(&law1, "p1", "r1", "g1", MILLION);
        pipeline.promote_to_synthesis(&law1, "t", vec![], "e");
        pipeline.promote_to_atlas(&law2, "array.push", 600_000);
        pipeline.promote_to_frontier(&law2, "weakref.finalization", 400_000);
        assert_eq!(pipeline.total_promotions(), 4);
        assert_eq!(pipeline.active_promotions(), 4);
    }

    #[test]
    fn test_pipeline_summary_report() {
        let mut pipeline = PromotionPipeline::new("pipe-001", test_epoch());
        let law = test_law();
        pipeline.promote_to_rewrite(&law, "p", "r", "g", MILLION);
        pipeline.promote_to_atlas(&law, "d", 500_000);
        pipeline.promote_to_frontier(&law, "f", 300_000);
        let report = pipeline.summary_report();
        assert_eq!(report.total_promotions, 3);
        assert_eq!(report.rewrite_rules, 1);
        assert_eq!(report.atlas_entries, 1);
        assert_eq!(report.frontier_entries, 1);
        assert_eq!(report.unexplored_frontiers, 1);
    }

    #[test]
    fn test_pipeline_display() {
        let pipeline = PromotionPipeline::new("pipe-001", test_epoch());
        let display = pipeline.to_string();
        assert!(display.contains("PromotionPipeline"));
    }

    #[test]
    fn test_pipeline_serde_roundtrip() {
        let mut pipeline = PromotionPipeline::new("pipe-001", test_epoch());
        let law = test_law();
        pipeline.promote_to_rewrite(&law, "p", "r", "g", MILLION);
        let json = serde_json::to_string(&pipeline).unwrap();
        let back: PromotionPipeline = serde_json::from_str(&json).unwrap();
        assert_eq!(pipeline, back);
    }

    #[test]
    fn test_pipeline_hash_determinism() {
        let p1 = PromotionPipeline::new("pipe-001", test_epoch());
        let p2 = PromotionPipeline::new("pipe-001", test_epoch());
        assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
    }

    // --- PromotionSummaryReport ---

    #[test]
    fn test_summary_report_display() {
        let report = PromotionSummaryReport {
            total_promotions: 10,
            active_promotions: 8,
            rewrite_rules: 3,
            synthesis_seeds: 2,
            atlas_entries: 3,
            frontier_entries: 2,
            unexplored_frontiers: 1,
            covered_domains: 5,
            epoch: test_epoch(),
        };
        let display = report.to_string();
        assert!(display.contains("PromotionSummary"));
    }

    #[test]
    fn test_summary_report_serde_roundtrip() {
        let report = PromotionSummaryReport {
            total_promotions: 5,
            active_promotions: 4,
            rewrite_rules: 2,
            synthesis_seeds: 1,
            atlas_entries: 1,
            frontier_entries: 1,
            unexplored_frontiers: 1,
            covered_domains: 2,
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: PromotionSummaryReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // --- Integration-style tests ---

    #[test]
    fn test_full_promotion_lifecycle() {
        let epoch = test_epoch();
        let mut pipeline = PromotionPipeline::new("lifecycle", epoch);

        // Accept and promote a proved law
        let proved_law = AcceptedLaw::new(
            "law-lifecycle-1",
            "cand-lc-1",
            "Number.isFinite(x) => typeof x === 'number'",
            LawStrength::Proved,
            vec!["number-ops".into()],
            900_000,
            epoch,
            vec!["proof-001".into()],
        );
        pipeline.promote_to_rewrite(
            &proved_law,
            "Number.isFinite(x)",
            "x.tag == NUMBER && x.is_finite",
            "x.type_feedback == number",
            1_300_000,
        );
        pipeline.promote_to_atlas(&proved_law, "Number.isFinite", 900_000);

        // Accept and promote a heuristic law
        let heuristic_law = AcceptedLaw::new(
            "law-lifecycle-2",
            "cand-lc-2",
            "most arrays are dense and < 1000 elements",
            LawStrength::Heuristic,
            vec!["array-layout".into()],
            400_000,
            epoch,
            vec!["campaign-001".into()],
        );
        pipeline.promote_to_frontier(&heuristic_law, "sparse-array-optimization", 250_000);

        let report = pipeline.summary_report();
        assert_eq!(report.total_promotions, 3);
        assert_eq!(report.rewrite_rules, 1);
        assert_eq!(report.atlas_entries, 1);
        assert_eq!(report.frontier_entries, 1);

        // Proved law has higher priority than heuristic
        assert!(
            proved_law.promotion_priority_millionths()
                > heuristic_law.promotion_priority_millionths()
        );
    }

    #[test]
    fn test_revocation_lifecycle() {
        let mut pipeline = PromotionPipeline::new("revoke-test", test_epoch());
        let law = test_law();
        pipeline.promote_to_rewrite(&law, "p", "r", "g", MILLION);
        assert_eq!(pipeline.active_promotions(), 1);

        // Revoke
        pipeline.receipts[0].revoke("counterexample found in campaign-042");
        assert_eq!(pipeline.active_promotions(), 0);
        assert_eq!(pipeline.total_promotions(), 1);
    }

    #[test]
    fn test_supersession_lifecycle() {
        let mut pipeline = PromotionPipeline::new("super-test", test_epoch());
        let law1 = test_law();
        let law2 = test_law_empirical();
        pipeline.promote_to_atlas(&law1, "string.ops", 500_000);
        pipeline.promote_to_atlas(&law2, "string.ops", 700_000);

        // Supersede first promotion with second
        pipeline.receipts[0].supersede(&law2.law_id);
        assert_eq!(pipeline.active_promotions(), 1); // only second is active
    }

    #[test]
    fn test_empty_pipeline_summary() {
        let pipeline = PromotionPipeline::new("empty", test_epoch());
        let report = pipeline.summary_report();
        assert_eq!(report.total_promotions, 0);
        assert_eq!(report.active_promotions, 0);
        assert_eq!(report.rewrite_rules, 0);
        assert_eq!(report.synthesis_seeds, 0);
        assert_eq!(report.atlas_entries, 0);
        assert_eq!(report.frontier_entries, 0);
        assert_eq!(report.covered_domains, 0);
    }

    #[test]
    fn test_pipeline_hash_changes_on_promotion() {
        let mut pipeline = PromotionPipeline::new("hash-test", test_epoch());
        let hash_before = pipeline.pipeline_hash;
        let law = test_law();
        pipeline.promote_to_rewrite(&law, "p", "r", "g", MILLION);
        assert_ne!(pipeline.pipeline_hash, hash_before);
    }
}
