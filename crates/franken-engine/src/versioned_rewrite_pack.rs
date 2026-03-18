//! Versioned rewrite packs, interference metadata, and deterministic cost models.
//!
//! Bead: bd-1lsy.7.7.1 [RGC-607A]
//!
//! Organizes rewrite rules into version-compatible, content-addressed packs
//! with interference tracking and deterministic cost models.  Packs are the
//! unit of optimization deployment: they carry their own schema version,
//! rule set, cost model, and interference metadata so the optimizer can
//! compose, compare, and roll back at pack granularity.
//!
//! # Design decisions
//!
//! - **Pack versioning** uses major.minor semantic versioning. A pack can
//!   only be applied if its version is compatible with the current schema.
//! - **Interference metadata** tracks per-rule-pair conflict potential so
//!   the optimizer can detect when two rules in the same or different packs
//!   may produce order-dependent or contradictory results.
//! - **Cost model** assigns a deterministic cost (millionths) to each IR3
//!   instruction class and rewrite rule, enabling greedy and budget-bounded
//!   optimization without floating-point nondeterminism.
//! - **Pack catalog** is a versioned registry of all available packs with
//!   compatibility checking and content-hash dedup.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "versioned_rewrite_pack";
pub const BEAD_ID: &str = "bd-1lsy.7.7.1";
pub const PACK_SCHEMA_VERSION: &str = "franken-engine.versioned-rewrite-pack.v1";
pub const CATALOG_SCHEMA_VERSION: &str = "franken-engine.rewrite-pack-catalog.v1";
pub const COST_MODEL_SCHEMA_VERSION: &str = "franken-engine.deterministic-cost-model.v1";
pub const INTERFERENCE_SCHEMA_VERSION: &str = "franken-engine.rewrite-interference.v1";

/// One million — unit for fixed-point millionths arithmetic.
const MILLION: i64 = 1_000_000;

/// Maximum number of rules per pack.
pub const MAX_RULES_PER_PACK: usize = 256;

/// Maximum number of interference entries per pack pair.
pub const MAX_INTERFERENCE_ENTRIES: usize = 1024;

// ---------------------------------------------------------------------------
// PackVersion — semantic versioning for packs
// ---------------------------------------------------------------------------

/// Semantic version for a rewrite pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackVersion {
    /// Major version (breaking changes).
    pub major: u32,
    /// Minor version (additive changes).
    pub minor: u32,
}

impl PackVersion {
    /// Current default version.
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    /// Check whether `self` (the host) is compatible with a pack at `pack_ver`.
    /// Compatible if same major and host minor >= pack minor.
    pub fn is_compatible_with(&self, pack_ver: &Self) -> bool {
        self.major == pack_ver.major && self.minor >= pack_ver.minor
    }
}

impl fmt::Display for PackVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ---------------------------------------------------------------------------
// InstructionCostClass — cost categories for IR3 instructions
// ---------------------------------------------------------------------------

/// Cost class for IR3 instruction families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionCostClass {
    /// Arithmetic operations (add, sub, mul, div, mod, exp).
    Arithmetic,
    /// Comparison operations (lt, gt, eq, strict_eq, etc.).
    Comparison,
    /// Bitwise operations (and, or, xor, shl, shr).
    Bitwise,
    /// Property access (get, set, delete, in).
    PropertyAccess,
    /// Control flow (jump, call, return).
    ControlFlow,
    /// Allocation (new_object, new_array, template_literal).
    Allocation,
    /// Hostcall invocation.
    Hostcall,
    /// Closure creation and capture.
    ClosureOps,
    /// Module operations (import, resolve).
    ModuleOps,
    /// Exception handling (throw, catch).
    ExceptionOps,
}

impl fmt::Display for InstructionCostClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arithmetic => write!(f, "arithmetic"),
            Self::Comparison => write!(f, "comparison"),
            Self::Bitwise => write!(f, "bitwise"),
            Self::PropertyAccess => write!(f, "property_access"),
            Self::ControlFlow => write!(f, "control_flow"),
            Self::Allocation => write!(f, "allocation"),
            Self::Hostcall => write!(f, "hostcall"),
            Self::ClosureOps => write!(f, "closure_ops"),
            Self::ModuleOps => write!(f, "module_ops"),
            Self::ExceptionOps => write!(f, "exception_ops"),
        }
    }
}

impl InstructionCostClass {
    pub const ALL: &[Self] = &[
        Self::Arithmetic,
        Self::Comparison,
        Self::Bitwise,
        Self::PropertyAccess,
        Self::ControlFlow,
        Self::Allocation,
        Self::Hostcall,
        Self::ClosureOps,
        Self::ModuleOps,
        Self::ExceptionOps,
    ];
}

// ---------------------------------------------------------------------------
// DeterministicCostModel — per-instruction-class costs
// ---------------------------------------------------------------------------

/// A deterministic cost model mapping instruction classes and rewrite rules
/// to fixed-point millionths costs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicCostModel {
    /// Schema version.
    pub schema_version: String,
    /// Model identifier.
    pub model_id: String,
    /// Per-instruction-class base costs (millionths).
    pub instruction_costs: BTreeMap<InstructionCostClass, i64>,
    /// Per-rule expected gain when the rule fires (millionths, positive = saving).
    pub rule_gains: BTreeMap<String, i64>,
    /// Per-rule application cost (overhead of pattern matching + transform, millionths).
    pub rule_application_costs: BTreeMap<String, i64>,
    /// Content hash (deterministic).
    pub content_hash: ContentHash,
}

impl DeterministicCostModel {
    /// Create a new cost model.
    pub fn new(
        model_id: &str,
        instruction_costs: BTreeMap<InstructionCostClass, i64>,
        rule_gains: BTreeMap<String, i64>,
        rule_application_costs: BTreeMap<String, i64>,
    ) -> Self {
        let content_hash = Self::compute_hash(
            model_id,
            &instruction_costs,
            &rule_gains,
            &rule_application_costs,
        );
        Self {
            schema_version: COST_MODEL_SCHEMA_VERSION.into(),
            model_id: model_id.into(),
            instruction_costs,
            rule_gains,
            rule_application_costs,
            content_hash,
        }
    }

    /// Get the cost for an instruction class. Returns 0 if not specified.
    pub fn instruction_cost(&self, class: InstructionCostClass) -> i64 {
        self.instruction_costs.get(&class).copied().unwrap_or(0)
    }

    /// Get the expected gain for a rule. Returns 0 if not specified.
    pub fn rule_gain(&self, rule_id: &str) -> i64 {
        self.rule_gains.get(rule_id).copied().unwrap_or(0)
    }

    /// Net gain for applying a rule: gain minus application cost (millionths).
    pub fn net_gain(&self, rule_id: &str) -> i64 {
        let gain = self.rule_gains.get(rule_id).copied().unwrap_or(0);
        let cost = self
            .rule_application_costs
            .get(rule_id)
            .copied()
            .unwrap_or(0);
        gain.saturating_sub(cost)
    }

    /// Create a default cost model with baseline instruction costs.
    pub fn default_baseline(model_id: &str) -> Self {
        let mut costs = BTreeMap::new();
        costs.insert(InstructionCostClass::Arithmetic, MILLION);
        costs.insert(InstructionCostClass::Comparison, MILLION);
        costs.insert(InstructionCostClass::Bitwise, MILLION / 2);
        costs.insert(InstructionCostClass::PropertyAccess, 5 * MILLION);
        costs.insert(InstructionCostClass::ControlFlow, 2 * MILLION);
        costs.insert(InstructionCostClass::Allocation, 10 * MILLION);
        costs.insert(InstructionCostClass::Hostcall, 50 * MILLION);
        costs.insert(InstructionCostClass::ClosureOps, 8 * MILLION);
        costs.insert(InstructionCostClass::ModuleOps, 20 * MILLION);
        costs.insert(InstructionCostClass::ExceptionOps, 15 * MILLION);
        Self::new(model_id, costs, BTreeMap::new(), BTreeMap::new())
    }

    fn compute_hash(
        model_id: &str,
        instruction_costs: &BTreeMap<InstructionCostClass, i64>,
        rule_gains: &BTreeMap<String, i64>,
        rule_application_costs: &BTreeMap<String, i64>,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(model_id.as_bytes());
        for (class, &cost) in instruction_costs {
            hasher.update([*class as u8]);
            hasher.update(cost.to_le_bytes());
        }
        for (rule_id, &gain) in rule_gains {
            hasher.update(rule_id.as_bytes());
            hasher.update(gain.to_le_bytes());
        }
        for (rule_id, &cost) in rule_application_costs {
            hasher.update(rule_id.as_bytes());
            hasher.update(cost.to_le_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// RewriteRuleEntry — a rule within a pack
// ---------------------------------------------------------------------------

/// A rewrite rule family for categorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewriteCategory {
    /// Algebraic simplification (constant folding, identity removal).
    AlgebraicSimplification,
    /// Dead code elimination.
    DeadCodeElimination,
    /// Common subexpression elimination.
    CommonSubexpression,
    /// Partial evaluation (constant propagation, specialization).
    PartialEvaluation,
    /// Effect hoisting (moving pure computations out of loops).
    EffectHoisting,
    /// Object shape specialization.
    ShapeSpecialization,
    /// React-specific render optimization.
    ReactRenderOptimization,
    /// String operation fusion.
    StringFusion,
    /// Array operation vectorization prep.
    ArrayOptimization,
    /// Custom / user-defined category.
    Custom,
}

impl fmt::Display for RewriteCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlgebraicSimplification => write!(f, "algebraic_simplification"),
            Self::DeadCodeElimination => write!(f, "dead_code_elimination"),
            Self::CommonSubexpression => write!(f, "common_subexpression"),
            Self::PartialEvaluation => write!(f, "partial_evaluation"),
            Self::EffectHoisting => write!(f, "effect_hoisting"),
            Self::ShapeSpecialization => write!(f, "shape_specialization"),
            Self::ReactRenderOptimization => write!(f, "react_render_optimization"),
            Self::StringFusion => write!(f, "string_fusion"),
            Self::ArrayOptimization => write!(f, "array_optimization"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

/// A single rewrite rule entry within a versioned pack.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RewriteRuleEntry {
    /// Unique rule identifier within the pack.
    pub rule_id: String,
    /// Category of the rewrite.
    pub category: RewriteCategory,
    /// Human-readable description.
    pub description: String,
    /// Content hash of the pattern (what the rule matches).
    pub pattern_hash: ContentHash,
    /// Content hash of the replacement (what the rule produces).
    pub replacement_hash: ContentHash,
    /// Whether the rule is provably sound (preserves semantics).
    pub proven_sound: bool,
    /// Priority (millionths). Higher = applied first when multiple rules match.
    pub priority_millionths: i64,
    /// Instruction cost classes this rule affects.
    pub affected_cost_classes: BTreeSet<InstructionCostClass>,
    /// Whether the rule is enabled by default.
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// RuleInterference — interference between rules
// ---------------------------------------------------------------------------

/// Kind of interference between two rewrite rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleInterferenceKind {
    /// No interference: rules can be applied independently.
    None,
    /// Rules may conflict (one blocks the other's pattern).
    PatternConflict,
    /// Rules produce different results depending on application order.
    OrderDependent,
    /// Rules modify the same IR region and may compose unsoundly.
    SemanticOverlap,
    /// Rules compete for the same budget.
    BudgetContention,
}

impl fmt::Display for RuleInterferenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::PatternConflict => write!(f, "pattern_conflict"),
            Self::OrderDependent => write!(f, "order_dependent"),
            Self::SemanticOverlap => write!(f, "semantic_overlap"),
            Self::BudgetContention => write!(f, "budget_contention"),
        }
    }
}

/// An interference record between two rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuleInterference {
    /// First rule.
    pub rule_a: String,
    /// Second rule.
    pub rule_b: String,
    /// Kind of interference.
    pub kind: RuleInterferenceKind,
    /// Whether this interference is blocking (prevents co-application).
    pub is_blocking: bool,
    /// Human-readable detail.
    pub detail: String,
}

/// Aggregate interference metadata for a pack or pair of packs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceMetadata {
    /// Schema version.
    pub schema_version: String,
    /// Individual interference entries.
    pub entries: Vec<RuleInterference>,
    /// Count of blocking interferences.
    pub blocking_count: usize,
    /// Count of non-blocking interferences.
    pub non_blocking_count: usize,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl InterferenceMetadata {
    /// Build interference metadata from entries.
    pub fn build(entries: Vec<RuleInterference>) -> Self {
        let blocking_count = entries.iter().filter(|e| e.is_blocking).count();
        let non_blocking_count = entries.len() - blocking_count;

        let content_hash = Self::compute_hash(&entries);

        Self {
            schema_version: INTERFERENCE_SCHEMA_VERSION.into(),
            entries,
            blocking_count,
            non_blocking_count,
            content_hash,
        }
    }

    /// Whether there are any blocking interferences.
    pub fn has_blocking(&self) -> bool {
        self.blocking_count > 0
    }

    /// Whether the pack is interference-free.
    pub fn is_clean(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all interferences involving a specific rule.
    pub fn for_rule(&self, rule_id: &str) -> Vec<&RuleInterference> {
        self.entries
            .iter()
            .filter(|e| e.rule_a == rule_id || e.rule_b == rule_id)
            .collect()
    }

    fn compute_hash(entries: &[RuleInterference]) -> ContentHash {
        let mut hasher = Sha256::new();
        for entry in entries {
            hasher.update(entry.rule_a.as_bytes());
            hasher.update(entry.rule_b.as_bytes());
            hasher.update([entry.kind as u8]);
            hasher.update([u8::from(entry.is_blocking)]);
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// RewritePack — versioned collection of rules
// ---------------------------------------------------------------------------

/// A versioned, content-addressed collection of rewrite rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewritePack {
    /// Schema version.
    pub schema_version: String,
    /// Pack identifier.
    pub pack_id: String,
    /// Pack version.
    pub version: PackVersion,
    /// Security epoch at creation time.
    pub epoch: SecurityEpoch,
    /// Human-readable description.
    pub description: String,
    /// Rules in this pack.
    pub rules: Vec<RewriteRuleEntry>,
    /// Intra-pack interference metadata.
    pub interference: InterferenceMetadata,
    /// Associated cost model identifier.
    pub cost_model_id: String,
    /// Categories present in this pack.
    pub categories: BTreeSet<RewriteCategory>,
    /// Number of proven-sound rules.
    pub proven_sound_count: usize,
    /// Content hash (deterministic).
    pub content_hash: ContentHash,
}

impl RewritePack {
    /// Create a new rewrite pack.
    pub fn new(
        pack_id: &str,
        version: PackVersion,
        epoch: SecurityEpoch,
        description: &str,
        rules: Vec<RewriteRuleEntry>,
        interference: InterferenceMetadata,
        cost_model_id: &str,
    ) -> Self {
        let categories: BTreeSet<RewriteCategory> = rules.iter().map(|r| r.category).collect();
        let proven_sound_count = rules.iter().filter(|r| r.proven_sound).count();

        let content_hash = Self::compute_hash(pack_id, version, epoch, &rules);

        Self {
            schema_version: PACK_SCHEMA_VERSION.into(),
            pack_id: pack_id.into(),
            version,
            epoch,
            description: description.into(),
            rules,
            interference,
            cost_model_id: cost_model_id.into(),
            categories,
            proven_sound_count,
            content_hash,
        }
    }

    /// Total number of rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Number of enabled rules.
    pub fn enabled_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }

    /// Fraction of rules that are proven sound (millionths).
    pub fn soundness_rate_millionths(&self) -> i64 {
        if self.rules.is_empty() {
            return 0;
        }
        let total = self.rules.len() as i64;
        (self.proven_sound_count as i64)
            .checked_mul(MILLION)
            .unwrap_or(0)
            / total
    }

    /// Whether this pack has any blocking internal interferences.
    pub fn has_internal_blocking(&self) -> bool {
        self.interference.has_blocking()
    }

    /// Get a rule by ID.
    pub fn rule_by_id(&self, rule_id: &str) -> Option<&RewriteRuleEntry> {
        self.rules.iter().find(|r| r.rule_id == rule_id)
    }

    /// Get all rules in a category.
    pub fn rules_in_category(&self, cat: RewriteCategory) -> Vec<&RewriteRuleEntry> {
        self.rules.iter().filter(|r| r.category == cat).collect()
    }

    fn compute_hash(
        pack_id: &str,
        version: PackVersion,
        epoch: SecurityEpoch,
        rules: &[RewriteRuleEntry],
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(pack_id.as_bytes());
        hasher.update(version.major.to_le_bytes());
        hasher.update(version.minor.to_le_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        for rule in rules {
            hasher.update(rule.rule_id.as_bytes());
            hasher.update(rule.pattern_hash.as_bytes());
            hasher.update(rule.replacement_hash.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// PackCatalog — registry of available packs
// ---------------------------------------------------------------------------

/// A catalog of available rewrite packs with version compatibility checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackCatalog {
    /// Schema version.
    pub schema_version: String,
    /// Catalog identifier.
    pub catalog_id: String,
    /// Registered packs, keyed by pack_id.
    pub packs: BTreeMap<String, RewritePack>,
    /// Cross-pack interference metadata, keyed by "packA::packB".
    pub cross_interference: BTreeMap<String, InterferenceMetadata>,
    /// Total rule count across all packs.
    pub total_rule_count: usize,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl PackCatalog {
    /// Create an empty catalog.
    pub fn new(catalog_id: &str) -> Self {
        Self {
            schema_version: CATALOG_SCHEMA_VERSION.into(),
            catalog_id: catalog_id.into(),
            packs: BTreeMap::new(),
            cross_interference: BTreeMap::new(),
            total_rule_count: 0,
            content_hash: ContentHash::compute(catalog_id.as_bytes()),
        }
    }

    /// Register a pack. Returns false if a pack with the same ID already exists.
    pub fn register(&mut self, pack: RewritePack) -> bool {
        if self.packs.contains_key(&pack.pack_id) {
            return false;
        }
        self.total_rule_count += pack.rule_count();
        self.packs.insert(pack.pack_id.clone(), pack);
        self.recompute_hash();
        true
    }

    /// Get a pack by ID.
    pub fn get(&self, pack_id: &str) -> Option<&RewritePack> {
        self.packs.get(pack_id)
    }

    /// Number of registered packs.
    pub fn pack_count(&self) -> usize {
        self.packs.len()
    }

    /// Find all packs compatible with a given version.
    pub fn compatible_packs(&self, host_version: &PackVersion) -> Vec<&RewritePack> {
        self.packs
            .values()
            .filter(|p| host_version.is_compatible_with(&p.version))
            .collect()
    }

    /// Record cross-pack interference.
    pub fn add_cross_interference(
        &mut self,
        pack_a: &str,
        pack_b: &str,
        metadata: InterferenceMetadata,
    ) {
        let key = if pack_a < pack_b {
            format!("{pack_a}::{pack_b}")
        } else {
            format!("{pack_b}::{pack_a}")
        };
        self.cross_interference.insert(key, metadata);
        self.recompute_hash();
    }

    /// Check whether two packs have blocking cross-interference.
    pub fn has_cross_blocking(&self, pack_a: &str, pack_b: &str) -> bool {
        let key = if pack_a < pack_b {
            format!("{pack_a}::{pack_b}")
        } else {
            format!("{pack_b}::{pack_a}")
        };
        self.cross_interference
            .get(&key)
            .is_some_and(|m| m.has_blocking())
    }

    fn recompute_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.catalog_id.as_bytes());
        for (id, pack) in &self.packs {
            hasher.update(id.as_bytes());
            hasher.update(pack.content_hash.as_bytes());
        }
        for (key, meta) in &self.cross_interference {
            hasher.update(key.as_bytes());
            hasher.update(meta.content_hash.as_bytes());
        }
        self.content_hash = ContentHash::compute(&hasher.finalize());
    }
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

    fn test_rule(id: &str, category: RewriteCategory, sound: bool) -> RewriteRuleEntry {
        RewriteRuleEntry {
            rule_id: id.into(),
            category,
            description: format!("test rule {id}"),
            pattern_hash: ContentHash::compute(format!("pat:{id}").as_bytes()),
            replacement_hash: ContentHash::compute(format!("rep:{id}").as_bytes()),
            proven_sound: sound,
            priority_millionths: MILLION,
            affected_cost_classes: BTreeSet::from([InstructionCostClass::Arithmetic]),
            enabled: true,
        }
    }

    fn test_interference(a: &str, b: &str, kind: RuleInterferenceKind) -> RuleInterference {
        RuleInterference {
            rule_a: a.into(),
            rule_b: b.into(),
            kind,
            is_blocking: kind == RuleInterferenceKind::SemanticOverlap,
            detail: format!("interference {a}-{b}"),
        }
    }

    fn test_pack(id: &str, rules: Vec<RewriteRuleEntry>) -> RewritePack {
        let interference = InterferenceMetadata::build(vec![]);
        RewritePack::new(
            id,
            PackVersion::CURRENT,
            test_epoch(),
            "test pack",
            rules,
            interference,
            "default",
        )
    }

    // --- PackVersion ---

    #[test]
    fn version_display() {
        assert_eq!(format!("{}", PackVersion::CURRENT), "1.0");
        let v = PackVersion { major: 2, minor: 3 };
        assert_eq!(format!("{v}"), "2.3");
    }

    #[test]
    fn version_compatibility() {
        let host = PackVersion { major: 1, minor: 2 };
        assert!(host.is_compatible_with(&PackVersion { major: 1, minor: 0 }));
        assert!(host.is_compatible_with(&PackVersion { major: 1, minor: 2 }));
        assert!(!host.is_compatible_with(&PackVersion { major: 1, minor: 3 }));
        assert!(!host.is_compatible_with(&PackVersion { major: 2, minor: 0 }));
    }

    #[test]
    fn version_serde_roundtrip() {
        let v = PackVersion::CURRENT;
        let json = serde_json::to_string(&v).unwrap();
        let back: PackVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn version_ordering() {
        assert!(PackVersion { major: 1, minor: 0 } < PackVersion { major: 1, minor: 1 });
        assert!(PackVersion { major: 1, minor: 9 } < PackVersion { major: 2, minor: 0 });
    }

    // --- InstructionCostClass ---

    #[test]
    fn cost_class_display() {
        assert_eq!(
            format!("{}", InstructionCostClass::Arithmetic),
            "arithmetic"
        );
        assert_eq!(format!("{}", InstructionCostClass::Hostcall), "hostcall");
        assert_eq!(
            format!("{}", InstructionCostClass::Allocation),
            "allocation"
        );
    }

    #[test]
    fn cost_class_serde_roundtrip() {
        for class in InstructionCostClass::ALL {
            let json = serde_json::to_string(class).unwrap();
            let back: InstructionCostClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*class, back);
        }
    }

    // --- DeterministicCostModel ---

    #[test]
    fn cost_model_default_baseline() {
        let model = DeterministicCostModel::default_baseline("baseline-1");
        assert_eq!(
            model.instruction_cost(InstructionCostClass::Arithmetic),
            MILLION
        );
        assert_eq!(
            model.instruction_cost(InstructionCostClass::Hostcall),
            50 * MILLION
        );
        assert_eq!(
            model.instruction_cost(InstructionCostClass::Allocation),
            10 * MILLION
        );
    }

    #[test]
    fn cost_model_rule_gains() {
        let mut gains = BTreeMap::new();
        gains.insert("fold_const".into(), 5 * MILLION);
        let mut app_costs = BTreeMap::new();
        app_costs.insert("fold_const".into(), MILLION);
        let model = DeterministicCostModel::new("test", BTreeMap::new(), gains, app_costs);
        assert_eq!(model.rule_gain("fold_const"), 5 * MILLION);
        assert_eq!(model.net_gain("fold_const"), 4 * MILLION);
        assert_eq!(model.net_gain("nonexistent"), 0);
    }

    #[test]
    fn cost_model_serde_roundtrip() {
        let model = DeterministicCostModel::default_baseline("serde-test");
        let json = serde_json::to_string(&model).unwrap();
        let back: DeterministicCostModel = serde_json::from_str(&json).unwrap();
        assert_eq!(model, back);
    }

    #[test]
    fn cost_model_deterministic_hash() {
        let m1 = DeterministicCostModel::default_baseline("det");
        let m2 = DeterministicCostModel::default_baseline("det");
        assert_eq!(m1.content_hash, m2.content_hash);
    }

    #[test]
    fn cost_model_missing_class_returns_zero() {
        let model =
            DeterministicCostModel::new("empty", BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        assert_eq!(model.instruction_cost(InstructionCostClass::Hostcall), 0);
    }

    // --- RewriteCategory ---

    #[test]
    fn category_display() {
        assert_eq!(
            format!("{}", RewriteCategory::DeadCodeElimination),
            "dead_code_elimination"
        );
        assert_eq!(
            format!("{}", RewriteCategory::ShapeSpecialization),
            "shape_specialization"
        );
    }

    #[test]
    fn category_serde_roundtrip() {
        for cat in [
            RewriteCategory::AlgebraicSimplification,
            RewriteCategory::DeadCodeElimination,
            RewriteCategory::CommonSubexpression,
            RewriteCategory::PartialEvaluation,
            RewriteCategory::EffectHoisting,
            RewriteCategory::ShapeSpecialization,
            RewriteCategory::ReactRenderOptimization,
            RewriteCategory::StringFusion,
            RewriteCategory::ArrayOptimization,
            RewriteCategory::Custom,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let back: RewriteCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    // --- RuleInterferenceKind ---

    #[test]
    fn interference_kind_display() {
        assert_eq!(format!("{}", RuleInterferenceKind::None), "none");
        assert_eq!(
            format!("{}", RuleInterferenceKind::OrderDependent),
            "order_dependent"
        );
    }

    #[test]
    fn interference_kind_serde_roundtrip() {
        for kind in [
            RuleInterferenceKind::None,
            RuleInterferenceKind::PatternConflict,
            RuleInterferenceKind::OrderDependent,
            RuleInterferenceKind::SemanticOverlap,
            RuleInterferenceKind::BudgetContention,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: RuleInterferenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // --- InterferenceMetadata ---

    #[test]
    fn interference_metadata_empty() {
        let meta = InterferenceMetadata::build(vec![]);
        assert!(meta.is_clean());
        assert!(!meta.has_blocking());
        assert_eq!(meta.blocking_count, 0);
    }

    #[test]
    fn interference_metadata_with_blocking() {
        let entries = vec![
            test_interference("r1", "r2", RuleInterferenceKind::SemanticOverlap),
            test_interference("r1", "r3", RuleInterferenceKind::PatternConflict),
        ];
        let meta = InterferenceMetadata::build(entries);
        assert!(meta.has_blocking());
        assert_eq!(meta.blocking_count, 1);
        assert_eq!(meta.non_blocking_count, 1);
    }

    #[test]
    fn interference_metadata_for_rule() {
        let entries = vec![
            test_interference("r1", "r2", RuleInterferenceKind::PatternConflict),
            test_interference("r3", "r4", RuleInterferenceKind::OrderDependent),
        ];
        let meta = InterferenceMetadata::build(entries);
        assert_eq!(meta.for_rule("r1").len(), 1);
        assert_eq!(meta.for_rule("r5").len(), 0);
    }

    #[test]
    fn interference_metadata_serde_roundtrip() {
        let meta = InterferenceMetadata::build(vec![test_interference(
            "a",
            "b",
            RuleInterferenceKind::None,
        )]);
        let json = serde_json::to_string(&meta).unwrap();
        let back: InterferenceMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
    }

    #[test]
    fn interference_metadata_deterministic_hash() {
        let m1 = InterferenceMetadata::build(vec![test_interference(
            "x",
            "y",
            RuleInterferenceKind::PatternConflict,
        )]);
        let m2 = InterferenceMetadata::build(vec![test_interference(
            "x",
            "y",
            RuleInterferenceKind::PatternConflict,
        )]);
        assert_eq!(m1.content_hash, m2.content_hash);
    }

    // --- RewritePack ---

    #[test]
    fn pack_empty() {
        let pack = test_pack("empty", vec![]);
        assert_eq!(pack.rule_count(), 0);
        assert_eq!(pack.enabled_count(), 0);
        assert_eq!(pack.soundness_rate_millionths(), 0);
    }

    #[test]
    fn pack_with_rules() {
        let rules = vec![
            test_rule("r1", RewriteCategory::AlgebraicSimplification, true),
            test_rule("r2", RewriteCategory::DeadCodeElimination, false),
            test_rule("r3", RewriteCategory::AlgebraicSimplification, true),
        ];
        let pack = test_pack("basic", rules);
        assert_eq!(pack.rule_count(), 3);
        assert_eq!(pack.enabled_count(), 3);
        assert_eq!(pack.proven_sound_count, 2);
        assert!(
            pack.categories
                .contains(&RewriteCategory::AlgebraicSimplification)
        );
        assert!(
            pack.categories
                .contains(&RewriteCategory::DeadCodeElimination)
        );
    }

    #[test]
    fn pack_soundness_rate() {
        let rules = vec![
            test_rule("s1", RewriteCategory::Custom, true),
            test_rule("s2", RewriteCategory::Custom, false),
        ];
        let pack = test_pack("soundness", rules);
        assert_eq!(pack.soundness_rate_millionths(), 500_000);
    }

    #[test]
    fn pack_rule_by_id() {
        let rules = vec![test_rule("find-me", RewriteCategory::Custom, true)];
        let pack = test_pack("find", rules);
        assert!(pack.rule_by_id("find-me").is_some());
        assert!(pack.rule_by_id("not-here").is_none());
    }

    #[test]
    fn pack_rules_in_category() {
        let rules = vec![
            test_rule("a1", RewriteCategory::AlgebraicSimplification, true),
            test_rule("d1", RewriteCategory::DeadCodeElimination, true),
            test_rule("a2", RewriteCategory::AlgebraicSimplification, true),
        ];
        let pack = test_pack("categorized", rules);
        assert_eq!(
            pack.rules_in_category(RewriteCategory::AlgebraicSimplification)
                .len(),
            2
        );
        assert_eq!(
            pack.rules_in_category(RewriteCategory::DeadCodeElimination)
                .len(),
            1
        );
        assert_eq!(pack.rules_in_category(RewriteCategory::Custom).len(), 0);
    }

    #[test]
    fn pack_serde_roundtrip() {
        let pack = test_pack(
            "serde",
            vec![test_rule("r1", RewriteCategory::Custom, true)],
        );
        let json = serde_json::to_string(&pack).unwrap();
        let back: RewritePack = serde_json::from_str(&json).unwrap();
        assert_eq!(pack, back);
    }

    #[test]
    fn pack_deterministic_hash() {
        let p1 = test_pack("det", vec![test_rule("r1", RewriteCategory::Custom, true)]);
        let p2 = test_pack("det", vec![test_rule("r1", RewriteCategory::Custom, true)]);
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn pack_has_internal_blocking() {
        let interference = InterferenceMetadata::build(vec![test_interference(
            "r1",
            "r2",
            RuleInterferenceKind::SemanticOverlap,
        )]);
        let pack = RewritePack::new(
            "blocking",
            PackVersion::CURRENT,
            test_epoch(),
            "test",
            vec![test_rule("r1", RewriteCategory::Custom, true)],
            interference,
            "default",
        );
        assert!(pack.has_internal_blocking());
    }

    // --- PackCatalog ---

    #[test]
    fn catalog_empty() {
        let catalog = PackCatalog::new("empty");
        assert_eq!(catalog.pack_count(), 0);
        assert_eq!(catalog.total_rule_count, 0);
    }

    #[test]
    fn catalog_register() {
        let mut catalog = PackCatalog::new("test");
        let pack = test_pack("p1", vec![test_rule("r1", RewriteCategory::Custom, true)]);
        assert!(catalog.register(pack));
        assert_eq!(catalog.pack_count(), 1);
        assert_eq!(catalog.total_rule_count, 1);
    }

    #[test]
    fn catalog_register_duplicate_fails() {
        let mut catalog = PackCatalog::new("test");
        let p1 = test_pack("same-id", vec![]);
        let p2 = test_pack("same-id", vec![]);
        assert!(catalog.register(p1));
        assert!(!catalog.register(p2));
    }

    #[test]
    fn catalog_get() {
        let mut catalog = PackCatalog::new("test");
        catalog.register(test_pack("p1", vec![]));
        assert!(catalog.get("p1").is_some());
        assert!(catalog.get("p2").is_none());
    }

    #[test]
    fn catalog_compatible_packs() {
        let mut catalog = PackCatalog::new("test");
        let v1 = RewritePack::new(
            "old",
            PackVersion { major: 1, minor: 0 },
            test_epoch(),
            "old",
            vec![],
            InterferenceMetadata::build(vec![]),
            "default",
        );
        let v2 = RewritePack::new(
            "new",
            PackVersion { major: 2, minor: 0 },
            test_epoch(),
            "new",
            vec![],
            InterferenceMetadata::build(vec![]),
            "default",
        );
        catalog.register(v1);
        catalog.register(v2);

        let host = PackVersion { major: 1, minor: 1 };
        let compatible = catalog.compatible_packs(&host);
        assert_eq!(compatible.len(), 1);
        assert_eq!(compatible[0].pack_id, "old");
    }

    #[test]
    fn catalog_cross_interference() {
        let mut catalog = PackCatalog::new("test");
        catalog.register(test_pack("a", vec![]));
        catalog.register(test_pack("b", vec![]));

        let meta = InterferenceMetadata::build(vec![test_interference(
            "a:r1",
            "b:r1",
            RuleInterferenceKind::SemanticOverlap,
        )]);
        catalog.add_cross_interference("a", "b", meta);
        assert!(catalog.has_cross_blocking("a", "b"));
        assert!(catalog.has_cross_blocking("b", "a")); // symmetric
        assert!(!catalog.has_cross_blocking("a", "c"));
    }

    #[test]
    fn catalog_serde_roundtrip() {
        let catalog = PackCatalog::new("serde");
        let json = serde_json::to_string(&catalog).unwrap();
        let back: PackCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(catalog, back);
    }

    // --- RewriteRuleEntry serde ---

    #[test]
    fn rule_entry_serde_roundtrip() {
        let rule = test_rule("serde-rule", RewriteCategory::EffectHoisting, true);
        let json = serde_json::to_string(&rule).unwrap();
        let back: RewriteRuleEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }

    // -----------------------------------------------------------------------
    // Deep enrichment tests (PearlTower 2026-03-18)
    // -----------------------------------------------------------------------

    #[test]
    fn version_compatibility_same_version() {
        let v = PackVersion::CURRENT;
        assert!(v.is_compatible_with(&v));
    }

    #[test]
    fn version_compatibility_zero() {
        let zero = PackVersion { major: 0, minor: 0 };
        assert!(zero.is_compatible_with(&zero));
    }

    #[test]
    fn cost_class_display_all() {
        for class in InstructionCostClass::ALL {
            assert!(!class.to_string().is_empty());
        }
    }

    #[test]
    fn cost_class_all_count() {
        assert!(InstructionCostClass::ALL.len() >= 8);
    }

    #[test]
    fn cost_model_different_ids_different_hash() {
        let m1 = DeterministicCostModel::default_baseline("model-a");
        let m2 = DeterministicCostModel::default_baseline("model-b");
        assert_ne!(m1.content_hash, m2.content_hash);
    }

    #[test]
    fn category_all_display_unique() {
        let names: BTreeSet<String> = [
            RewriteCategory::AlgebraicSimplification,
            RewriteCategory::DeadCodeElimination,
            RewriteCategory::CommonSubexpression,
            RewriteCategory::PartialEvaluation,
            RewriteCategory::EffectHoisting,
            RewriteCategory::ShapeSpecialization,
            RewriteCategory::ReactRenderOptimization,
            RewriteCategory::StringFusion,
            RewriteCategory::ArrayOptimization,
            RewriteCategory::Custom,
        ]
        .iter()
        .map(|c| c.to_string())
        .collect();
        assert_eq!(names.len(), 10);
    }

    #[test]
    fn interference_for_rule_symmetric() {
        let entries = vec![test_interference(
            "r1",
            "r2",
            RuleInterferenceKind::PatternConflict,
        )];
        let meta = InterferenceMetadata::build(entries);
        assert_eq!(meta.for_rule("r1").len(), 1);
        assert_eq!(meta.for_rule("r2").len(), 1);
    }

    #[test]
    fn pack_schema_version_correct() {
        let pack = test_pack("schema", vec![]);
        assert_eq!(pack.schema_version, PACK_SCHEMA_VERSION);
        assert_eq!(pack.bead_id, BEAD_ID);
    }

    #[test]
    fn pack_content_hash_changes_with_rules() {
        let p1 = test_pack("same", vec![]);
        let p2 = test_pack("same", vec![test_rule("r1", RewriteCategory::Custom, true)]);
        assert_ne!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn pack_disabled_rule_not_in_enabled_count() {
        let mut rule = test_rule("dis", RewriteCategory::Custom, true);
        rule.enabled = false;
        let pack = test_pack("disabled", vec![rule]);
        assert_eq!(pack.rule_count(), 1);
        assert_eq!(pack.enabled_count(), 0);
    }

    #[test]
    fn pack_soundness_rate_all_sound() {
        let rules = vec![
            test_rule("s1", RewriteCategory::Custom, true),
            test_rule("s2", RewriteCategory::Custom, true),
        ];
        let pack = test_pack("all-sound", rules);
        assert_eq!(pack.soundness_rate_millionths(), MILLION);
    }

    #[test]
    fn pack_soundness_rate_none_sound() {
        let rules = vec![
            test_rule("s1", RewriteCategory::Custom, false),
            test_rule("s2", RewriteCategory::Custom, false),
        ];
        let pack = test_pack("none-sound", rules);
        assert_eq!(pack.soundness_rate_millionths(), 0);
    }

    #[test]
    fn catalog_deterministic_hash() {
        let c1 = PackCatalog::new("det");
        let c2 = PackCatalog::new("det");
        assert_eq!(c1.catalog_hash, c2.catalog_hash);
    }

    #[test]
    fn catalog_schema_version() {
        let catalog = PackCatalog::new("test");
        assert_eq!(catalog.schema_version, CATALOG_SCHEMA_VERSION);
    }

    #[test]
    fn schema_constants_non_empty() {
        assert!(!COMPONENT.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!PACK_SCHEMA_VERSION.is_empty());
        assert!(!CATALOG_SCHEMA_VERSION.is_empty());
        assert!(!COST_MODEL_SCHEMA_VERSION.is_empty());
        assert!(!INTERFERENCE_SCHEMA_VERSION.is_empty());
    }

    #[test]
    fn max_rules_per_pack_positive() {
        assert!(MAX_RULES_PER_PACK > 0);
    }

    #[test]
    fn max_interference_entries_positive() {
        assert!(MAX_INTERFERENCE_ENTRIES > 0);
    }

    #[test]
    fn interference_kind_ordering() {
        assert!(RuleInterferenceKind::None < RuleInterferenceKind::PatternConflict);
        assert!(RuleInterferenceKind::PatternConflict < RuleInterferenceKind::OrderDependent);
    }

    #[test]
    fn catalog_multiple_packs() {
        let mut catalog = PackCatalog::new("multi");
        for i in 0..5 {
            let pack = test_pack(
                &format!("pack-{i}"),
                vec![test_rule(&format!("r{i}"), RewriteCategory::Custom, true)],
            );
            assert!(catalog.register(pack));
        }
        assert_eq!(catalog.pack_count(), 5);
        assert_eq!(catalog.total_rule_count, 5);
    }

    #[test]
    fn rule_interference_serde() {
        let interf = test_interference("a", "b", RuleInterferenceKind::BudgetContention);
        let json = serde_json::to_string(&interf).unwrap();
        let back: RuleInterference = serde_json::from_str(&json).unwrap();
        assert_eq!(interf, back);
    }
}
