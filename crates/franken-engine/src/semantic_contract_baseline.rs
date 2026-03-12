//! Semantic Contract Baseline — FRX-11.1 Parallel Track A
//!
//! Produces the semantic substrate that all downstream tracks depend on:
//! - Compatibility corpus with prioritised trace fixtures
//! - Hook and effect semantic contracts with adjudication rules
//! - Machine-checkable contract packages for compiler/runtime/verification
//! - Frozen baseline artifact sets for milestone cut lines
//! - Drift alerts when downstream assumptions violate the semantic contract

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use crate::hash_tiers::ContentHash;
use crate::static_analysis_graph::ComponentDescriptor;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Default drift sensitivity: 50 000 millionths (5%)
const DEFAULT_DRIFT_SENSITIVITY: i64 = 50_000;

/// Maximum fixtures per corpus.
const MAX_CORPUS_FIXTURES: usize = 10_000;

/// Maximum contracts per package.
const MAX_CONTRACTS_PER_PACKAGE: usize = 500;

/// Maximum adjudication rules per package.
const MAX_ADJUDICATION_RULES: usize = 1_000;

/// Schema version string.
pub const SEMANTIC_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.semantic_contract_baseline.v1";

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SemanticContractVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemanticContractVersion {
    pub const CURRENT: Self = Self {
        major: 0,
        minor: 1,
        patch: 0,
    };

    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl fmt::Display for SemanticContractVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// Fixture / Corpus types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FixtureCategory {
    HookState,
    HookEffect,
    HookMemo,
    HookRef,
    HookReducer,
    HookContext,
    ConcurrentRendering,
    Suspense,
    ErrorBoundary,
    Hydration,
    Portal,
    RefEdgeCase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FixturePriority {
    Critical,
    High,
    Medium,
    Low,
}

impl FixturePriority {
    pub fn weight_millionths(&self) -> i64 {
        match self {
            Self::Critical => MILLION,
            Self::High => 750_000,
            Self::Medium => 500_000,
            Self::Low => 250_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MutationKind {
    SetAttribute,
    RemoveAttribute,
    AppendChild,
    RemoveChild,
    SetTextContent,
    InsertBefore,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DomMutation {
    pub target_path: String,
    pub kind: MutationKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFixture {
    pub id: EngineObjectId,
    pub name: String,
    pub category: FixtureCategory,
    pub priority: FixturePriority,
    pub input_hash: ContentHash,
    pub expected_trace_hash: ContentHash,
    pub expected_dom_mutations: Vec<DomMutation>,
    pub expected_effect_order: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityCorpus {
    pub version: SemanticContractVersion,
    pub fixtures: Vec<TraceFixture>,
    pub created_epoch: u64,
    pub frozen: bool,
    pub corpus_hash: ContentHash,
}

impl CompatibilityCorpus {
    pub fn new(version: SemanticContractVersion, epoch: u64) -> Self {
        Self {
            version,
            fixtures: Vec::new(),
            created_epoch: epoch,
            frozen: false,
            corpus_hash: ContentHash::compute(b"empty_corpus"),
        }
    }

    pub fn add_fixture(&mut self, fixture: TraceFixture) -> Result<(), FoundationError> {
        if self.frozen {
            return Err(FoundationError::CorpusAlreadyFrozen);
        }
        if self.fixtures.len() >= MAX_CORPUS_FIXTURES {
            return Err(FoundationError::CorpusCapacityExceeded);
        }
        if self.fixtures.iter().any(|f| f.id == fixture.id) {
            return Err(FoundationError::DuplicateFixture);
        }
        self.fixtures.push(fixture);
        self.recompute_hash();
        Ok(())
    }

    pub fn freeze(&mut self) -> Result<(), FoundationError> {
        if self.frozen {
            return Err(FoundationError::CorpusAlreadyFrozen);
        }
        if self.fixtures.is_empty() {
            return Err(FoundationError::EmptyCorpus);
        }
        self.frozen = true;
        self.recompute_hash();
        Ok(())
    }

    pub fn fixtures_by_priority(&self) -> Vec<&TraceFixture> {
        let mut sorted: Vec<&TraceFixture> = self.fixtures.iter().collect();
        sorted.sort_by_key(|f| f.priority);
        sorted
    }

    pub fn fixtures_by_category(&self, cat: &FixtureCategory) -> Vec<&TraceFixture> {
        self.fixtures
            .iter()
            .filter(|f| &f.category == cat)
            .collect()
    }

    pub fn coverage_score_millionths(&self) -> i64 {
        if self.fixtures.is_empty() {
            return 0;
        }
        let categories_present: std::collections::BTreeSet<_> =
            self.fixtures.iter().map(|f| &f.category).collect();
        let total_categories = 12i64; // FixtureCategory variant count
        let covered = categories_present.len() as i64;
        covered * MILLION / total_categories
    }

    pub fn weighted_priority_score_millionths(&self) -> i64 {
        if self.fixtures.is_empty() {
            return 0;
        }
        let total_weight: i64 = self
            .fixtures
            .iter()
            .map(|f| f.priority.weight_millionths())
            .sum();
        total_weight / self.fixtures.len() as i64
    }

    fn recompute_hash(&mut self) {
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(self.version.to_string().as_bytes());
        hasher_input.extend_from_slice(&self.created_epoch.to_le_bytes());
        hasher_input.push(u8::from(self.frozen));
        for fixture in &self.fixtures {
            hasher_input.extend_from_slice(fixture.input_hash.as_bytes());
            hasher_input.extend_from_slice(fixture.expected_trace_hash.as_bytes());
        }
        self.corpus_hash = ContentHash::compute(&hasher_input);
    }
}

// ---------------------------------------------------------------------------
// Hook semantic contracts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HookKind {
    UseState,
    UseEffect,
    UseMemo,
    UseRef,
    UseReducer,
    UseContext,
    UseCallback,
    UseLayoutEffect,
    UseImperativeHandle,
    UseDebugValue,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InvocationRule {
    MustBeTopLevel,
    MustNotBeConditional,
    MustNotBeInLoop,
    MustBeInFunctionComponent,
    OrderPreservedAcrossRenders,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OrderingConstraint {
    pub before: String,
    pub after: String,
    pub strict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CleanupPolicy {
    RunOnUnmount,
    RunBeforeRerun,
    NoCleanup,
    ConditionalCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Fatal,
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ForbiddenPattern {
    pub description: String,
    pub pattern_hash: ContentHash,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSemanticContract {
    pub hook_kind: HookKind,
    pub invocation_rules: Vec<InvocationRule>,
    pub ordering_constraints: Vec<OrderingConstraint>,
    pub cleanup_semantics: CleanupPolicy,
    pub forbidden_patterns: Vec<ForbiddenPattern>,
}

impl HookSemanticContract {
    pub fn canonical_use_state() -> Self {
        Self {
            hook_kind: HookKind::UseState,
            invocation_rules: vec![
                InvocationRule::MustBeTopLevel,
                InvocationRule::MustNotBeConditional,
                InvocationRule::MustNotBeInLoop,
                InvocationRule::MustBeInFunctionComponent,
                InvocationRule::OrderPreservedAcrossRenders,
            ],
            ordering_constraints: Vec::new(),
            cleanup_semantics: CleanupPolicy::NoCleanup,
            forbidden_patterns: Vec::new(),
        }
    }

    pub fn canonical_use_effect() -> Self {
        Self {
            hook_kind: HookKind::UseEffect,
            invocation_rules: vec![
                InvocationRule::MustBeTopLevel,
                InvocationRule::MustNotBeConditional,
                InvocationRule::MustNotBeInLoop,
                InvocationRule::MustBeInFunctionComponent,
                InvocationRule::OrderPreservedAcrossRenders,
            ],
            ordering_constraints: Vec::new(),
            cleanup_semantics: CleanupPolicy::RunBeforeRerun,
            forbidden_patterns: Vec::new(),
        }
    }

    pub fn contract_hash(&self) -> ContentHash {
        let mut data = Vec::new();
        data.extend_from_slice(format!("{:?}", self.hook_kind).as_bytes());
        for rule in &self.invocation_rules {
            data.extend_from_slice(format!("{:?}", rule).as_bytes());
        }
        for constraint in &self.ordering_constraints {
            data.extend_from_slice(constraint.before.as_bytes());
            data.extend_from_slice(constraint.after.as_bytes());
            data.push(u8::from(constraint.strict));
        }
        data.extend_from_slice(format!("{:?}", self.cleanup_semantics).as_bytes());
        for pat in &self.forbidden_patterns {
            data.extend_from_slice(pat.pattern_hash.as_bytes());
        }
        ContentHash::compute(&data)
    }
}

// ---------------------------------------------------------------------------
// Effect semantic contracts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EffectKind {
    DomMutation,
    NetworkIo,
    TimerSetup,
    StateUpdate,
    Subscription,
    CustomEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EffectTiming {
    AfterRender,
    BeforePaint,
    Synchronous,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SideEffectBoundary {
    Contained,
    Leaks,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DeterminismLevel {
    FullyDeterministic,
    OrderDeterministic,
    Nondeterministic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectSemanticContract {
    pub effect_kind: EffectKind,
    pub timing: EffectTiming,
    pub capability_requirements: Vec<String>,
    pub side_effect_boundary: SideEffectBoundary,
    pub determinism_guarantee: DeterminismLevel,
}

impl EffectSemanticContract {
    pub fn canonical_dom_mutation() -> Self {
        Self {
            effect_kind: EffectKind::DomMutation,
            timing: EffectTiming::AfterRender,
            capability_requirements: vec!["dom.mutate".to_string()],
            side_effect_boundary: SideEffectBoundary::Contained,
            determinism_guarantee: DeterminismLevel::FullyDeterministic,
        }
    }

    pub fn canonical_state_update() -> Self {
        Self {
            effect_kind: EffectKind::StateUpdate,
            timing: EffectTiming::Synchronous,
            capability_requirements: vec!["state.write".to_string()],
            side_effect_boundary: SideEffectBoundary::Contained,
            determinism_guarantee: DeterminismLevel::FullyDeterministic,
        }
    }

    pub fn contract_hash(&self) -> ContentHash {
        let mut data = Vec::new();
        data.extend_from_slice(format!("{:?}", self.effect_kind).as_bytes());
        data.extend_from_slice(format!("{:?}", self.timing).as_bytes());
        for cap in &self.capability_requirements {
            data.extend_from_slice(cap.as_bytes());
        }
        data.extend_from_slice(format!("{:?}", self.side_effect_boundary).as_bytes());
        data.extend_from_slice(format!("{:?}", self.determinism_guarantee).as_bytes());
        ContentHash::compute(&data)
    }

    pub fn is_deterministic(&self) -> bool {
        matches!(
            self.determinism_guarantee,
            DeterminismLevel::FullyDeterministic | DeterminismLevel::OrderDeterministic
        )
    }
}

// ---------------------------------------------------------------------------
// Adjudication rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AdjudicationCategory {
    AmbiguousOrdering,
    UndefinedEdgeCase,
    VersionConflict,
    PlatformDivergence,
    SpecGap,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AdjudicationResolution {
    PreferReactBehavior,
    PreferDeterministic,
    PreferConservative,
    RequireExplicitFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjudicationRule {
    pub id: EngineObjectId,
    pub name: String,
    pub category: AdjudicationCategory,
    pub condition: String,
    pub resolution: AdjudicationResolution,
    pub rationale: String,
    pub precedent_fixture_ids: Vec<EngineObjectId>,
}

impl AdjudicationRule {
    pub fn rule_hash(&self) -> ContentHash {
        let mut data = Vec::new();
        data.extend_from_slice(self.name.as_bytes());
        data.extend_from_slice(format!("{:?}", self.category).as_bytes());
        data.extend_from_slice(self.condition.as_bytes());
        data.extend_from_slice(format!("{:?}", self.resolution).as_bytes());
        ContentHash::compute(&data)
    }
}

// ---------------------------------------------------------------------------
// Contract Package
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractPackage {
    pub version: SemanticContractVersion,
    pub corpus: CompatibilityCorpus,
    pub hook_contracts: Vec<HookSemanticContract>,
    pub effect_contracts: Vec<EffectSemanticContract>,
    pub adjudication_rules: Vec<AdjudicationRule>,
    pub package_hash: ContentHash,
    pub frozen_at_epoch: Option<u64>,
}

impl ContractPackage {
    pub fn new(corpus: CompatibilityCorpus) -> Result<Self, FoundationError> {
        let version = corpus.version.clone();
        let mut pkg = Self {
            version,
            corpus,
            hook_contracts: Vec::new(),
            effect_contracts: Vec::new(),
            adjudication_rules: Vec::new(),
            package_hash: ContentHash::compute(b"empty_package"),
            frozen_at_epoch: None,
        };
        pkg.recompute_hash();
        Ok(pkg)
    }

    pub fn add_hook_contract(
        &mut self,
        contract: HookSemanticContract,
    ) -> Result<(), FoundationError> {
        if self.frozen_at_epoch.is_some() {
            return Err(FoundationError::PackageAlreadyFrozen);
        }
        if self.hook_contracts.len() + self.effect_contracts.len() >= MAX_CONTRACTS_PER_PACKAGE {
            return Err(FoundationError::ContractCapacityExceeded);
        }
        self.hook_contracts.push(contract);
        self.recompute_hash();
        Ok(())
    }

    pub fn add_effect_contract(
        &mut self,
        contract: EffectSemanticContract,
    ) -> Result<(), FoundationError> {
        if self.frozen_at_epoch.is_some() {
            return Err(FoundationError::PackageAlreadyFrozen);
        }
        if self.hook_contracts.len() + self.effect_contracts.len() >= MAX_CONTRACTS_PER_PACKAGE {
            return Err(FoundationError::ContractCapacityExceeded);
        }
        self.effect_contracts.push(contract);
        self.recompute_hash();
        Ok(())
    }

    pub fn add_adjudication_rule(&mut self, rule: AdjudicationRule) -> Result<(), FoundationError> {
        if self.frozen_at_epoch.is_some() {
            return Err(FoundationError::PackageAlreadyFrozen);
        }
        if self.adjudication_rules.len() >= MAX_ADJUDICATION_RULES {
            return Err(FoundationError::AdjudicationCapacityExceeded);
        }
        self.adjudication_rules.push(rule);
        self.recompute_hash();
        Ok(())
    }

    pub fn freeze(&mut self, epoch: u64) -> Result<(), FoundationError> {
        if self.frozen_at_epoch.is_some() {
            return Err(FoundationError::PackageAlreadyFrozen);
        }
        if self.hook_contracts.is_empty() && self.effect_contracts.is_empty() {
            return Err(FoundationError::EmptyPackage);
        }
        self.frozen_at_epoch = Some(epoch);
        self.recompute_hash();
        Ok(())
    }

    pub fn is_frozen(&self) -> bool {
        self.frozen_at_epoch.is_some()
    }

    pub fn total_contracts(&self) -> usize {
        self.hook_contracts.len() + self.effect_contracts.len()
    }

    pub fn validate(&self) -> Result<PackageValidation, FoundationError> {
        let mut warnings = Vec::new();

        // Check corpus coverage
        let coverage = self.corpus.coverage_score_millionths();
        if coverage < 500_000 {
            warnings.push("Corpus coverage below 50%".to_string());
        }

        // Check hook contract completeness
        let hook_kinds_covered: std::collections::BTreeSet<_> =
            self.hook_contracts.iter().map(|c| &c.hook_kind).collect();
        let core_hooks = [
            HookKind::UseState,
            HookKind::UseEffect,
            HookKind::UseMemo,
            HookKind::UseRef,
        ];
        for hook in &core_hooks {
            if !hook_kinds_covered.contains(hook) {
                warnings.push(format!("Missing contract for core hook {:?}", hook));
            }
        }

        // Check determinism coverage
        let non_deterministic_effects: Vec<_> = self
            .effect_contracts
            .iter()
            .filter(|c| !c.is_deterministic())
            .collect();
        if !non_deterministic_effects.is_empty() {
            warnings.push(format!(
                "{} non-deterministic effect contracts present",
                non_deterministic_effects.len()
            ));
        }

        Ok(PackageValidation {
            is_valid: warnings.is_empty(),
            coverage_millionths: coverage,
            hook_coverage_count: hook_kinds_covered.len(),
            effect_contract_count: self.effect_contracts.len(),
            adjudication_rule_count: self.adjudication_rules.len(),
            warnings,
        })
    }

    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.version.to_string().as_bytes());
        data.extend_from_slice(self.corpus.corpus_hash.as_bytes());
        for hc in &self.hook_contracts {
            data.extend_from_slice(hc.contract_hash().as_bytes());
        }
        for ec in &self.effect_contracts {
            data.extend_from_slice(ec.contract_hash().as_bytes());
        }
        for ar in &self.adjudication_rules {
            data.extend_from_slice(ar.rule_hash().as_bytes());
        }
        if let Some(epoch) = self.frozen_at_epoch {
            data.extend_from_slice(&epoch.to_le_bytes());
        }
        self.package_hash = ContentHash::compute(&data);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageValidation {
    pub is_valid: bool,
    pub coverage_millionths: i64,
    pub hook_coverage_count: usize,
    pub effect_contract_count: usize,
    pub adjudication_rule_count: usize,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Local Semantic Atlas (FRX-14.1)
// ---------------------------------------------------------------------------

pub const LOCAL_SEMANTIC_ATLAS_SCHEMA_VERSION: &str = "franken-engine.local-semantic-atlas.v1";
pub const LOCAL_SEMANTIC_ATLAS_BEAD_ID: &str = "bd-mjh3.14.1";
pub const LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_FIXTURE_LINK: &str = "FE-FRX-14-1-LOCAL-0001";
pub const LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_TRACE_LINK: &str = "FE-FRX-14-1-LOCAL-0002";
pub const LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_CONTEXT_ASSUMPTIONS: &str = "FE-FRX-14-1-LOCAL-0003";
pub const LOCAL_SEMANTIC_ATLAS_DEBT_EMPTY_LOCAL_CONTRACT: &str = "FE-FRX-14-1-LOCAL-0004";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSemanticAtlasInput {
    pub component: ComponentDescriptor,
    pub fixture_refs: Vec<String>,
    pub trace_refs: Vec<String>,
    pub assumption_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSemanticAtlasEntry {
    pub component_id: String,
    pub module_path: String,
    pub export_name: Option<String>,
    pub hook_signature: Vec<String>,
    pub effect_signature: Vec<String>,
    pub required_contexts: Vec<String>,
    pub provided_contexts: Vec<String>,
    pub capability_requirements: Vec<String>,
    pub assumption_keys: Vec<String>,
    pub fixture_refs: Vec<String>,
    pub trace_refs: Vec<String>,
    pub content_hash: ContentHash,
}

impl LocalSemanticAtlasEntry {
    pub fn from_input(input: LocalSemanticAtlasInput) -> Self {
        let hook_signature = input
            .component
            .hook_slots
            .iter()
            .map(|slot| {
                let dep_count = slot
                    .dependency_count
                    .map(|count| count.to_string())
                    .unwrap_or_else(|| "none".to_string());
                format!(
                    "slot={};kind={};label={};deps={};cleanup={}",
                    slot.slot_index, slot.kind, slot.label, dep_count, slot.has_cleanup
                )
            })
            .collect::<Vec<_>>();

        let effect_signature = input
            .component
            .capability_boundary
            .hook_effects
            .iter()
            .map(|effect| {
                let capabilities = effect
                    .required_capabilities
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("+");
                format!(
                    "boundary={:?};caps={};idempotent={};commutative={};cost_millionths={}",
                    effect.boundary,
                    capabilities,
                    effect.idempotent,
                    effect.commutative,
                    effect.estimated_cost_millionths
                )
            })
            .collect::<Vec<_>>();

        let required_contexts = sorted_unique(input.component.consumed_contexts.clone());
        let provided_contexts = sorted_unique(input.component.provided_contexts.clone());
        let capability_requirements = input
            .component
            .capability_boundary
            .all_capabilities()
            .into_iter()
            .collect::<Vec<_>>();
        let assumption_keys = sorted_unique(input.assumption_keys);
        let fixture_refs = sorted_unique(input.fixture_refs);
        let trace_refs = sorted_unique(input.trace_refs);

        let mut entry = Self {
            component_id: input.component.id.0,
            module_path: input.component.module_path,
            export_name: input.component.export_name,
            hook_signature,
            effect_signature,
            required_contexts,
            provided_contexts,
            capability_requirements,
            assumption_keys,
            fixture_refs,
            trace_refs,
            content_hash: ContentHash::compute(b"local_semantic_atlas_entry"),
        };
        entry.recompute_hash();
        entry
    }

    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.component_id.as_bytes());
        data.extend_from_slice(self.module_path.as_bytes());
        if let Some(export_name) = &self.export_name {
            data.extend_from_slice(export_name.as_bytes());
        }
        for value in &self.hook_signature {
            data.extend_from_slice(value.as_bytes());
        }
        for value in &self.effect_signature {
            data.extend_from_slice(value.as_bytes());
        }
        for value in &self.required_contexts {
            data.extend_from_slice(value.as_bytes());
        }
        for value in &self.provided_contexts {
            data.extend_from_slice(value.as_bytes());
        }
        for value in &self.capability_requirements {
            data.extend_from_slice(value.as_bytes());
        }
        for value in &self.assumption_keys {
            data.extend_from_slice(value.as_bytes());
        }
        for value in &self.fixture_refs {
            data.extend_from_slice(value.as_bytes());
        }
        for value in &self.trace_refs {
            data.extend_from_slice(value.as_bytes());
        }
        self.content_hash = ContentHash::compute(&data);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSemanticContractDebt {
    pub component_id: String,
    pub debt_code: String,
    pub description: String,
    pub blocking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSemanticAtlas {
    pub schema_version: String,
    pub bead_id: String,
    pub version: SemanticContractVersion,
    pub generated_epoch: u64,
    pub entries: Vec<LocalSemanticAtlasEntry>,
    pub quality_debt: Vec<LocalSemanticContractDebt>,
    pub atlas_hash: ContentHash,
}

impl LocalSemanticAtlas {
    pub fn from_inputs(
        version: SemanticContractVersion,
        generated_epoch: u64,
        inputs: Vec<LocalSemanticAtlasInput>,
    ) -> Self {
        let mut entries = inputs
            .into_iter()
            .map(LocalSemanticAtlasEntry::from_input)
            .collect::<Vec<_>>();
        entries.sort_by(|lhs, rhs| lhs.component_id.cmp(&rhs.component_id));

        let mut quality_debt = entries
            .iter()
            .flat_map(Self::debt_for_entry)
            .collect::<Vec<_>>();
        quality_debt.sort_by(|lhs, rhs| {
            lhs.component_id
                .cmp(&rhs.component_id)
                .then_with(|| lhs.debt_code.cmp(&rhs.debt_code))
        });

        let mut atlas = Self {
            schema_version: LOCAL_SEMANTIC_ATLAS_SCHEMA_VERSION.to_string(),
            bead_id: LOCAL_SEMANTIC_ATLAS_BEAD_ID.to_string(),
            version,
            generated_epoch,
            entries,
            quality_debt,
            atlas_hash: ContentHash::compute(b"local_semantic_atlas"),
        };
        atlas.recompute_hash();
        atlas
    }

    pub fn entry(&self, component_id: &str) -> Option<&LocalSemanticAtlasEntry> {
        self.entries
            .iter()
            .find(|entry| entry.component_id == component_id)
    }

    pub fn blocking_debt_count(&self) -> usize {
        self.quality_debt
            .iter()
            .filter(|debt| debt.blocking)
            .count()
    }

    pub fn validate(&self) -> LocalSemanticAtlasValidation {
        let mut warnings = Vec::new();
        if self.entries.is_empty() {
            warnings.push("atlas has no component entries".to_string());
        }

        let mut seen_component_ids = BTreeSet::new();
        for entry in &self.entries {
            if !seen_component_ids.insert(entry.component_id.clone()) {
                warnings.push(format!("duplicate component entry: {}", entry.component_id));
            }
        }

        let blocking_debt_count = self.blocking_debt_count();
        let is_valid = warnings.is_empty() && blocking_debt_count == 0;
        LocalSemanticAtlasValidation {
            is_valid,
            entry_count: self.entries.len(),
            total_debt_count: self.quality_debt.len(),
            blocking_debt_count,
            warnings,
        }
    }

    fn debt_for_entry(entry: &LocalSemanticAtlasEntry) -> Vec<LocalSemanticContractDebt> {
        let mut debt = Vec::new();
        if entry.fixture_refs.is_empty() {
            debt.push(LocalSemanticContractDebt {
                component_id: entry.component_id.clone(),
                debt_code: LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_FIXTURE_LINK.to_string(),
                description: "missing compatibility fixture linkage for local semantic contract"
                    .to_string(),
                blocking: true,
            });
        }
        if entry.trace_refs.is_empty() {
            debt.push(LocalSemanticContractDebt {
                component_id: entry.component_id.clone(),
                debt_code: LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_TRACE_LINK.to_string(),
                description: "missing observable trace linkage for local semantic contract"
                    .to_string(),
                blocking: true,
            });
        }
        if !entry.required_contexts.is_empty() && entry.assumption_keys.is_empty() {
            debt.push(LocalSemanticContractDebt {
                component_id: entry.component_id.clone(),
                debt_code: LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_CONTEXT_ASSUMPTIONS.to_string(),
                description: "consumed contexts require explicit local assumption keys".to_string(),
                blocking: true,
            });
        }
        if entry.hook_signature.is_empty() && entry.effect_signature.is_empty() {
            debt.push(LocalSemanticContractDebt {
                component_id: entry.component_id.clone(),
                debt_code: LOCAL_SEMANTIC_ATLAS_DEBT_EMPTY_LOCAL_CONTRACT.to_string(),
                description: "component has no hook/effect local contract surface".to_string(),
                blocking: true,
            });
        }
        debt
    }

    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.schema_version.as_bytes());
        data.extend_from_slice(self.bead_id.as_bytes());
        data.extend_from_slice(self.version.to_string().as_bytes());
        data.extend_from_slice(&self.generated_epoch.to_le_bytes());
        for entry in &self.entries {
            data.extend_from_slice(entry.content_hash.as_bytes());
        }
        for debt in &self.quality_debt {
            data.extend_from_slice(debt.component_id.as_bytes());
            data.extend_from_slice(debt.debt_code.as_bytes());
            data.extend_from_slice(debt.description.as_bytes());
            data.push(u8::from(debt.blocking));
        }
        self.atlas_hash = ContentHash::compute(&data);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSemanticAtlasValidation {
    pub is_valid: bool,
    pub entry_count: usize,
    pub total_debt_count: usize,
    pub blocking_debt_count: usize,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Frozen Baseline
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConsumerLane {
    Compiler,
    Runtime,
    Verification,
    Optimization,
    Governance,
    Adoption,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenBaseline {
    pub package: ContractPackage,
    pub cut_line_id: String,
    pub freeze_epoch: u64,
    pub baseline_hash: ContentHash,
    pub consumer_lanes: Vec<ConsumerLane>,
}

impl FrozenBaseline {
    pub fn create(
        mut package: ContractPackage,
        cut_line_id: String,
        epoch: u64,
        lanes: Vec<ConsumerLane>,
    ) -> Result<Self, FoundationError> {
        if !package.corpus.frozen {
            package.corpus.freeze()?;
        }
        if !package.is_frozen() {
            package.freeze(epoch)?;
        }
        if lanes.is_empty() {
            return Err(FoundationError::NoConsumerLanes);
        }

        let baseline_hash = {
            let mut data = Vec::new();
            data.extend_from_slice(package.package_hash.as_bytes());
            data.extend_from_slice(cut_line_id.as_bytes());
            data.extend_from_slice(&epoch.to_le_bytes());
            ContentHash::compute(&data)
        };

        Ok(Self {
            package,
            cut_line_id,
            freeze_epoch: epoch,
            baseline_hash,
            consumer_lanes: lanes,
        })
    }

    pub fn serves_lane(&self, lane: &ConsumerLane) -> bool {
        self.consumer_lanes.contains(lane)
    }
}

// ---------------------------------------------------------------------------
// Drift Detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DriftKind {
    SemanticRegression,
    OrderingViolation,
    EffectBoundaryLeak,
    HookContractBreach,
    AdjudicationOverride,
    CorpusCoverageDrop,
    VersionIncompatibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftAlert {
    pub id: EngineObjectId,
    pub kind: DriftKind,
    pub severity: ViolationSeverity,
    pub source_lane: ConsumerLane,
    pub violated_contract_hash: Option<ContentHash>,
    pub description: String,
    pub detected_epoch: u64,
    pub evidence_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftDetector {
    pub baseline: FrozenBaseline,
    pub alerts: Vec<DriftAlert>,
    pub sensitivity_threshold_millionths: i64,
    pub alert_count_by_kind: BTreeMap<DriftKind, u64>,
}

impl DriftDetector {
    pub fn new(baseline: FrozenBaseline) -> Self {
        Self {
            baseline,
            alerts: Vec::new(),
            sensitivity_threshold_millionths: DEFAULT_DRIFT_SENSITIVITY,
            alert_count_by_kind: BTreeMap::new(),
        }
    }

    pub fn with_sensitivity(mut self, sensitivity_millionths: i64) -> Self {
        self.sensitivity_threshold_millionths = sensitivity_millionths;
        self
    }

    pub fn record_alert(&mut self, alert: DriftAlert) {
        let count = self
            .alert_count_by_kind
            .entry(alert.kind.clone())
            .or_insert(0);
        *count += 1;
        self.alerts.push(alert);
    }

    pub fn check_trace_compliance(
        &mut self,
        fixture_id: &EngineObjectId,
        actual_trace_hash: &ContentHash,
        lane: ConsumerLane,
        epoch: u64,
    ) -> Option<DriftAlert> {
        let fixture = self
            .baseline
            .package
            .corpus
            .fixtures
            .iter()
            .find(|f| f.id == *fixture_id)?;

        if fixture.expected_trace_hash == *actual_trace_hash {
            return None;
        }

        let severity = match fixture.priority {
            FixturePriority::Critical => ViolationSeverity::Fatal,
            FixturePriority::High => ViolationSeverity::Error,
            FixturePriority::Medium => ViolationSeverity::Warning,
            FixturePriority::Low => ViolationSeverity::Info,
        };

        let evidence_hash = {
            let mut data = Vec::new();
            data.extend_from_slice(fixture.expected_trace_hash.as_bytes());
            data.extend_from_slice(actual_trace_hash.as_bytes());
            ContentHash::compute(&data)
        };

        let alert = DriftAlert {
            id: fixture.id.clone(),
            kind: DriftKind::SemanticRegression,
            severity,
            source_lane: lane,
            violated_contract_hash: Some(fixture.expected_trace_hash),
            description: format!(
                "Trace mismatch for fixture '{}': expected {}, got {}",
                fixture.name,
                hex_prefix(&fixture.expected_trace_hash),
                hex_prefix(actual_trace_hash),
            ),
            detected_epoch: epoch,
            evidence_hash,
        };

        self.record_alert(alert.clone());
        Some(alert)
    }

    pub fn check_effect_boundary(
        &mut self,
        effect_kind: &EffectKind,
        observed_boundary: &SideEffectBoundary,
        lane: ConsumerLane,
        epoch: u64,
    ) -> Option<DriftAlert> {
        let contract = self
            .baseline
            .package
            .effect_contracts
            .iter()
            .find(|c| c.effect_kind == *effect_kind)?;

        if contract.side_effect_boundary == *observed_boundary {
            return None;
        }

        if *observed_boundary == SideEffectBoundary::Leaks
            && contract.side_effect_boundary == SideEffectBoundary::Contained
        {
            let alert = DriftAlert {
                id: derive_drift_alert_id(&format!("effect_boundary_{:?}_{epoch}", effect_kind)),
                kind: DriftKind::EffectBoundaryLeak,
                severity: ViolationSeverity::Error,
                source_lane: lane,
                violated_contract_hash: Some(contract.contract_hash()),
                description: format!(
                    "Effect {:?} leaks side effects (contract requires Contained)",
                    effect_kind
                ),
                detected_epoch: epoch,
                evidence_hash: contract.contract_hash(),
            };

            self.record_alert(alert.clone());
            return Some(alert);
        }

        None
    }

    pub fn check_hook_ordering(
        &mut self,
        hook_kind: &HookKind,
        is_conditional: bool,
        lane: ConsumerLane,
        epoch: u64,
    ) -> Option<DriftAlert> {
        let contract = self
            .baseline
            .package
            .hook_contracts
            .iter()
            .find(|c| c.hook_kind == *hook_kind)?;

        if is_conditional
            && contract
                .invocation_rules
                .contains(&InvocationRule::MustNotBeConditional)
        {
            let alert = DriftAlert {
                id: derive_drift_alert_id(&format!("hook_ordering_{:?}_{epoch}", hook_kind)),
                kind: DriftKind::HookContractBreach,
                severity: ViolationSeverity::Fatal,
                source_lane: lane,
                violated_contract_hash: Some(contract.contract_hash()),
                description: format!(
                    "Hook {:?} invoked conditionally (contract forbids conditional invocation)",
                    hook_kind
                ),
                detected_epoch: epoch,
                evidence_hash: contract.contract_hash(),
            };

            self.record_alert(alert.clone());
            return Some(alert);
        }

        None
    }

    pub fn fatal_alert_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|a| a.severity == ViolationSeverity::Fatal)
            .count()
    }

    pub fn alerts_for_lane(&self, lane: &ConsumerLane) -> Vec<&DriftAlert> {
        self.alerts
            .iter()
            .filter(|a| a.source_lane == *lane)
            .collect()
    }

    pub fn exceeds_threshold(&self) -> bool {
        if self.alerts.is_empty() {
            return false;
        }
        let fatal_count = self.fatal_alert_count() as i64;
        let total_fixtures = self.baseline.package.corpus.fixtures.len().max(1) as i64;
        let drift_ratio = fatal_count * MILLION / total_fixtures;
        drift_ratio > self.sensitivity_threshold_millionths
    }

    pub fn summary(&self) -> DriftSummary {
        let total_fixtures = self.baseline.package.corpus.fixtures.len();
        DriftSummary {
            total_alerts: self.alerts.len(),
            fatal_count: self.fatal_alert_count(),
            error_count: self
                .alerts
                .iter()
                .filter(|a| a.severity == ViolationSeverity::Error)
                .count(),
            warning_count: self
                .alerts
                .iter()
                .filter(|a| a.severity == ViolationSeverity::Warning)
                .count(),
            info_count: self
                .alerts
                .iter()
                .filter(|a| a.severity == ViolationSeverity::Info)
                .count(),
            exceeds_threshold: self.exceeds_threshold(),
            drift_ratio_millionths: if total_fixtures > 0 {
                self.fatal_alert_count() as i64 * MILLION / total_fixtures as i64
            } else {
                0
            },
            alerts_by_kind: self.alert_count_by_kind.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftSummary {
    pub total_alerts: usize,
    pub fatal_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub exceeds_threshold: bool,
    pub drift_ratio_millionths: i64,
    pub alerts_by_kind: BTreeMap<DriftKind, u64>,
}

// ---------------------------------------------------------------------------
// Foundation manager
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FoundationEvent {
    CorpusCreated {
        version: SemanticContractVersion,
        epoch: u64,
    },
    FixtureAdded {
        fixture_name: String,
        category: FixtureCategory,
        priority: FixturePriority,
    },
    CorpusFrozen {
        fixture_count: usize,
        corpus_hash: ContentHash,
    },
    PackageCreated {
        version: SemanticContractVersion,
    },
    ContractAdded {
        contract_type: String,
    },
    PackageFrozen {
        epoch: u64,
        package_hash: ContentHash,
    },
    BaselineFrozen {
        cut_line_id: String,
        epoch: u64,
        baseline_hash: ContentHash,
    },
    DriftDetected {
        kind: DriftKind,
        severity: ViolationSeverity,
        lane: ConsumerLane,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticContractFoundation {
    pub packages: Vec<ContractPackage>,
    pub frozen_baselines: Vec<FrozenBaseline>,
    pub drift_detector: Option<DriftDetector>,
    pub event_log: Vec<FoundationEvent>,
}

impl SemanticContractFoundation {
    pub fn new() -> Self {
        Self {
            packages: Vec::new(),
            frozen_baselines: Vec::new(),
            drift_detector: None,
            event_log: Vec::new(),
        }
    }

    pub fn register_package(&mut self, package: ContractPackage) {
        self.event_log.push(FoundationEvent::PackageCreated {
            version: package.version.clone(),
        });
        self.packages.push(package);
    }

    pub fn freeze_baseline(
        &mut self,
        package_index: usize,
        cut_line_id: String,
        epoch: u64,
        lanes: Vec<ConsumerLane>,
    ) -> Result<usize, FoundationError> {
        let package = self
            .packages
            .get(package_index)
            .ok_or(FoundationError::PackageNotFound)?
            .clone();

        let baseline = FrozenBaseline::create(package, cut_line_id.clone(), epoch, lanes)?;
        self.event_log.push(FoundationEvent::BaselineFrozen {
            cut_line_id,
            epoch,
            baseline_hash: baseline.baseline_hash,
        });
        self.frozen_baselines.push(baseline);
        Ok(self.frozen_baselines.len() - 1)
    }

    pub fn activate_drift_detection(
        &mut self,
        baseline_index: usize,
    ) -> Result<(), FoundationError> {
        let baseline = self
            .frozen_baselines
            .get(baseline_index)
            .ok_or(FoundationError::BaselineNotFound)?
            .clone();

        self.drift_detector = Some(DriftDetector::new(baseline));
        Ok(())
    }

    pub fn latest_baseline(&self) -> Option<&FrozenBaseline> {
        self.frozen_baselines.last()
    }

    pub fn latest_package(&self) -> Option<&ContractPackage> {
        self.packages.last()
    }
}

impl Default for SemanticContractFoundation {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FoundationError {
    CorpusAlreadyFrozen,
    CorpusCapacityExceeded,
    DuplicateFixture,
    EmptyCorpus,
    EmptyPackage,
    PackageAlreadyFrozen,
    PackageNotFound,
    BaselineNotFound,
    ContractCapacityExceeded,
    AdjudicationCapacityExceeded,
    NoConsumerLanes,
    InvalidContract(String),
    IncompatibleVersion,
}

impl fmt::Display for FoundationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorpusAlreadyFrozen => write!(f, "corpus is already frozen"),
            Self::CorpusCapacityExceeded => {
                write!(f, "corpus capacity exceeded (max {})", MAX_CORPUS_FIXTURES)
            }
            Self::DuplicateFixture => write!(f, "duplicate fixture ID"),
            Self::EmptyCorpus => write!(f, "cannot freeze empty corpus"),
            Self::EmptyPackage => write!(f, "cannot freeze package with no contracts"),
            Self::PackageAlreadyFrozen => write!(f, "package is already frozen"),
            Self::PackageNotFound => write!(f, "package not found"),
            Self::BaselineNotFound => write!(f, "baseline not found"),
            Self::ContractCapacityExceeded => write!(f, "contract capacity exceeded"),
            Self::AdjudicationCapacityExceeded => write!(f, "adjudication rule capacity exceeded"),
            Self::NoConsumerLanes => write!(f, "at least one consumer lane required"),
            Self::InvalidContract(msg) => write!(f, "invalid contract: {}", msg),
            Self::IncompatibleVersion => write!(f, "incompatible contract version"),
        }
    }
}

impl std::error::Error for FoundationError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn hex_prefix(hash: &ContentHash) -> String {
    let bytes = hash.as_bytes();
    if bytes.len() >= 4 {
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    } else {
        "????".to_string()
    }
}

fn derive_drift_alert_id(label: &str) -> EngineObjectId {
    let schema = SchemaId::from_definition(SEMANTIC_CONTRACT_SCHEMA_VERSION.as_bytes());
    derive_id(
        ObjectDomain::EvidenceRecord,
        "drift",
        &schema,
        label.as_bytes(),
    )
    .unwrap_or_else(|_| {
        derive_id(ObjectDomain::EvidenceRecord, "drift", &schema, b"fallback").expect("fallback id")
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{ObjectDomain, SchemaId, derive_id};

    fn make_id(label: &str) -> EngineObjectId {
        let schema = SchemaId::from_definition(SEMANTIC_CONTRACT_SCHEMA_VERSION.as_bytes());
        derive_id(
            ObjectDomain::EvidenceRecord,
            "tests.semantic_contract_baseline",
            &schema,
            label.as_bytes(),
        )
        .expect("derive id")
    }

    fn make_fixture(name: &str, cat: FixtureCategory, prio: FixturePriority) -> TraceFixture {
        TraceFixture {
            id: make_id(name),
            name: name.to_string(),
            category: cat,
            priority: prio,
            input_hash: ContentHash::compute(name.as_bytes()),
            expected_trace_hash: ContentHash::compute(format!("trace_{}", name).as_bytes()),
            expected_dom_mutations: vec![DomMutation {
                target_path: "/div/span".to_string(),
                kind: MutationKind::SetTextContent,
                value: "hello".to_string(),
            }],
            expected_effect_order: vec!["effect_a".to_string()],
            metadata: BTreeMap::new(),
        }
    }

    fn make_corpus_with_fixtures(count: usize) -> CompatibilityCorpus {
        let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        for i in 0..count {
            let fixture = make_fixture(
                &format!("fix_{}", i),
                FixtureCategory::HookState,
                FixturePriority::High,
            );
            corpus.add_fixture(fixture).unwrap();
        }
        corpus
    }

    fn make_full_package() -> ContractPackage {
        let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        let categories = [
            FixtureCategory::HookState,
            FixtureCategory::HookEffect,
            FixtureCategory::HookMemo,
            FixtureCategory::HookRef,
            FixtureCategory::HookReducer,
            FixtureCategory::HookContext,
            FixtureCategory::ConcurrentRendering,
            FixtureCategory::Suspense,
            FixtureCategory::ErrorBoundary,
            FixtureCategory::Hydration,
            FixtureCategory::Portal,
            FixtureCategory::RefEdgeCase,
        ];
        for (i, cat) in categories.iter().enumerate() {
            corpus
                .add_fixture(make_fixture(
                    &format!("cat_{}", i),
                    cat.clone(),
                    FixturePriority::Critical,
                ))
                .unwrap();
        }
        let mut pkg = ContractPackage::new(corpus).unwrap();
        pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
            .unwrap();
        pkg.add_hook_contract(HookSemanticContract::canonical_use_effect())
            .unwrap();
        pkg.add_effect_contract(EffectSemanticContract::canonical_dom_mutation())
            .unwrap();
        pkg.add_effect_contract(EffectSemanticContract::canonical_state_update())
            .unwrap();
        pkg
    }

    // --- Version tests ---

    #[test]
    fn version_display() {
        assert_eq!(SemanticContractVersion::CURRENT.to_string(), "0.1.0");
    }

    #[test]
    fn version_compatibility_same() {
        let v = SemanticContractVersion::CURRENT;
        assert!(v.is_compatible_with(&v));
    }

    #[test]
    fn version_compatibility_minor_upgrade() {
        let v1 = SemanticContractVersion {
            major: 0,
            minor: 2,
            patch: 0,
        };
        let v2 = SemanticContractVersion {
            major: 0,
            minor: 1,
            patch: 0,
        };
        assert!(v1.is_compatible_with(&v2));
        assert!(!v2.is_compatible_with(&v1));
    }

    #[test]
    fn version_incompatible_major() {
        let v1 = SemanticContractVersion {
            major: 1,
            minor: 0,
            patch: 0,
        };
        let v2 = SemanticContractVersion::CURRENT;
        assert!(!v1.is_compatible_with(&v2));
    }

    // --- Fixture priority tests ---

    #[test]
    fn priority_weights() {
        assert_eq!(FixturePriority::Critical.weight_millionths(), MILLION);
        assert_eq!(FixturePriority::High.weight_millionths(), 750_000);
        assert_eq!(FixturePriority::Medium.weight_millionths(), 500_000);
        assert_eq!(FixturePriority::Low.weight_millionths(), 250_000);
    }

    #[test]
    fn priority_ordering() {
        assert!(FixturePriority::Critical < FixturePriority::High);
        assert!(FixturePriority::High < FixturePriority::Medium);
    }

    // --- Corpus tests ---

    #[test]
    fn corpus_new_empty() {
        let corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        assert!(!corpus.frozen);
        assert!(corpus.fixtures.is_empty());
    }

    #[test]
    fn corpus_add_fixture() {
        let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        let fix = make_fixture("test1", FixtureCategory::HookState, FixturePriority::High);
        corpus.add_fixture(fix).unwrap();
        assert_eq!(corpus.fixtures.len(), 1);
    }

    #[test]
    fn corpus_reject_duplicate() {
        let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        let fix = make_fixture("dup", FixtureCategory::HookState, FixturePriority::High);
        corpus.add_fixture(fix.clone()).unwrap();
        assert_eq!(
            corpus.add_fixture(fix),
            Err(FoundationError::DuplicateFixture)
        );
    }

    #[test]
    fn corpus_freeze() {
        let mut corpus = make_corpus_with_fixtures(3);
        corpus.freeze().unwrap();
        assert!(corpus.frozen);
    }

    #[test]
    fn corpus_freeze_empty_fails() {
        let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        assert_eq!(corpus.freeze(), Err(FoundationError::EmptyCorpus));
    }

    #[test]
    fn corpus_frozen_reject_add() {
        let mut corpus = make_corpus_with_fixtures(1);
        corpus.freeze().unwrap();
        let fix = make_fixture("new", FixtureCategory::HookEffect, FixturePriority::Low);
        assert_eq!(
            corpus.add_fixture(fix),
            Err(FoundationError::CorpusAlreadyFrozen)
        );
    }

    #[test]
    fn corpus_double_freeze_fails() {
        let mut corpus = make_corpus_with_fixtures(1);
        corpus.freeze().unwrap();
        assert_eq!(corpus.freeze(), Err(FoundationError::CorpusAlreadyFrozen));
    }

    #[test]
    fn corpus_coverage_single_category() {
        let corpus = make_corpus_with_fixtures(5);
        // All HookState -> 1/12 coverage
        let coverage = corpus.coverage_score_millionths();
        assert_eq!(coverage, MILLION / 12);
    }

    #[test]
    fn corpus_coverage_all_categories() {
        let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        let cats = [
            FixtureCategory::HookState,
            FixtureCategory::HookEffect,
            FixtureCategory::HookMemo,
            FixtureCategory::HookRef,
            FixtureCategory::HookReducer,
            FixtureCategory::HookContext,
            FixtureCategory::ConcurrentRendering,
            FixtureCategory::Suspense,
            FixtureCategory::ErrorBoundary,
            FixtureCategory::Hydration,
            FixtureCategory::Portal,
            FixtureCategory::RefEdgeCase,
        ];
        for (i, cat) in cats.iter().enumerate() {
            corpus
                .add_fixture(make_fixture(
                    &format!("all_{}", i),
                    cat.clone(),
                    FixturePriority::Medium,
                ))
                .unwrap();
        }
        assert_eq!(corpus.coverage_score_millionths(), MILLION);
    }

    #[test]
    fn corpus_weighted_priority_score() {
        let corpus = make_corpus_with_fixtures(3); // all High
        assert_eq!(corpus.weighted_priority_score_millionths(), 750_000);
    }

    #[test]
    fn corpus_fixtures_by_priority() {
        let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        corpus
            .add_fixture(make_fixture(
                "low",
                FixtureCategory::HookState,
                FixturePriority::Low,
            ))
            .unwrap();
        corpus
            .add_fixture(make_fixture(
                "crit",
                FixtureCategory::HookEffect,
                FixturePriority::Critical,
            ))
            .unwrap();
        let sorted = corpus.fixtures_by_priority();
        assert_eq!(sorted[0].priority, FixturePriority::Critical);
        assert_eq!(sorted[1].priority, FixturePriority::Low);
    }

    #[test]
    fn corpus_fixtures_by_category() {
        let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        corpus
            .add_fixture(make_fixture(
                "a",
                FixtureCategory::HookState,
                FixturePriority::High,
            ))
            .unwrap();
        corpus
            .add_fixture(make_fixture(
                "b",
                FixtureCategory::Suspense,
                FixturePriority::High,
            ))
            .unwrap();
        assert_eq!(
            corpus
                .fixtures_by_category(&FixtureCategory::Suspense)
                .len(),
            1
        );
        assert_eq!(
            corpus.fixtures_by_category(&FixtureCategory::Portal).len(),
            0
        );
    }

    #[test]
    fn corpus_hash_changes_on_add() {
        let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        let h1 = corpus.corpus_hash;
        corpus
            .add_fixture(make_fixture(
                "x",
                FixtureCategory::HookState,
                FixturePriority::High,
            ))
            .unwrap();
        assert_ne!(h1, corpus.corpus_hash);
    }

    #[test]
    fn corpus_hash_changes_on_freeze() {
        let mut corpus = make_corpus_with_fixtures(2);
        let h1 = corpus.corpus_hash;
        corpus.freeze().unwrap();
        assert_ne!(h1, corpus.corpus_hash);
    }

    // --- Hook contract tests ---

    #[test]
    fn hook_canonical_use_state() {
        let c = HookSemanticContract::canonical_use_state();
        assert_eq!(c.hook_kind, HookKind::UseState);
        assert_eq!(c.invocation_rules.len(), 5);
        assert_eq!(c.cleanup_semantics, CleanupPolicy::NoCleanup);
    }

    #[test]
    fn hook_canonical_use_effect() {
        let c = HookSemanticContract::canonical_use_effect();
        assert_eq!(c.hook_kind, HookKind::UseEffect);
        assert_eq!(c.cleanup_semantics, CleanupPolicy::RunBeforeRerun);
    }

    #[test]
    fn hook_contract_hash_deterministic() {
        let c1 = HookSemanticContract::canonical_use_state();
        let c2 = HookSemanticContract::canonical_use_state();
        assert_eq!(c1.contract_hash(), c2.contract_hash());
    }

    #[test]
    fn hook_contract_hash_differs_by_kind() {
        let c1 = HookSemanticContract::canonical_use_state();
        let c2 = HookSemanticContract::canonical_use_effect();
        assert_ne!(c1.contract_hash(), c2.contract_hash());
    }

    // --- Effect contract tests ---

    #[test]
    fn effect_canonical_dom_mutation() {
        let c = EffectSemanticContract::canonical_dom_mutation();
        assert_eq!(c.effect_kind, EffectKind::DomMutation);
        assert!(c.is_deterministic());
        assert_eq!(c.side_effect_boundary, SideEffectBoundary::Contained);
    }

    #[test]
    fn effect_canonical_state_update() {
        let c = EffectSemanticContract::canonical_state_update();
        assert_eq!(c.effect_kind, EffectKind::StateUpdate);
        assert!(c.is_deterministic());
    }

    #[test]
    fn effect_nondeterministic() {
        let c = EffectSemanticContract {
            effect_kind: EffectKind::NetworkIo,
            timing: EffectTiming::Deferred,
            capability_requirements: vec!["net.fetch".to_string()],
            side_effect_boundary: SideEffectBoundary::Leaks,
            determinism_guarantee: DeterminismLevel::Nondeterministic,
        };
        assert!(!c.is_deterministic());
    }

    #[test]
    fn effect_contract_hash_deterministic() {
        let c1 = EffectSemanticContract::canonical_dom_mutation();
        let c2 = EffectSemanticContract::canonical_dom_mutation();
        assert_eq!(c1.contract_hash(), c2.contract_hash());
    }

    // --- Adjudication tests ---

    #[test]
    fn adjudication_rule_hash() {
        let r = AdjudicationRule {
            id: make_id("adj1"),
            name: "effect_ordering_ambiguity".to_string(),
            category: AdjudicationCategory::AmbiguousOrdering,
            condition: "concurrent effects with shared deps".to_string(),
            resolution: AdjudicationResolution::PreferDeterministic,
            rationale: "Determinism preserves replay correctness".to_string(),
            precedent_fixture_ids: vec![make_id("fix1")],
        };
        let h1 = r.rule_hash();
        let h2 = r.rule_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn adjudication_categories_exhaustive() {
        let cats = [
            AdjudicationCategory::AmbiguousOrdering,
            AdjudicationCategory::UndefinedEdgeCase,
            AdjudicationCategory::VersionConflict,
            AdjudicationCategory::PlatformDivergence,
            AdjudicationCategory::SpecGap,
        ];
        assert_eq!(cats.len(), 5);
    }

    // --- Contract Package tests ---

    #[test]
    fn package_create() {
        let corpus = make_corpus_with_fixtures(3);
        let pkg = ContractPackage::new(corpus).unwrap();
        assert!(!pkg.is_frozen());
        assert_eq!(pkg.total_contracts(), 0);
    }

    #[test]
    fn package_add_hook_contract() {
        let corpus = make_corpus_with_fixtures(1);
        let mut pkg = ContractPackage::new(corpus).unwrap();
        pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
            .unwrap();
        assert_eq!(pkg.total_contracts(), 1);
    }

    #[test]
    fn package_add_effect_contract() {
        let corpus = make_corpus_with_fixtures(1);
        let mut pkg = ContractPackage::new(corpus).unwrap();
        pkg.add_effect_contract(EffectSemanticContract::canonical_dom_mutation())
            .unwrap();
        assert_eq!(pkg.total_contracts(), 1);
    }

    #[test]
    fn package_add_adjudication_rule() {
        let corpus = make_corpus_with_fixtures(1);
        let mut pkg = ContractPackage::new(corpus).unwrap();
        let rule = AdjudicationRule {
            id: make_id("r1"),
            name: "test_rule".to_string(),
            category: AdjudicationCategory::SpecGap,
            condition: "always".to_string(),
            resolution: AdjudicationResolution::PreferConservative,
            rationale: "safety first".to_string(),
            precedent_fixture_ids: Vec::new(),
        };
        pkg.add_adjudication_rule(rule).unwrap();
        assert_eq!(pkg.adjudication_rules.len(), 1);
    }

    #[test]
    fn package_freeze() {
        let mut pkg = make_full_package();
        pkg.freeze(100).unwrap();
        assert!(pkg.is_frozen());
        assert_eq!(pkg.frozen_at_epoch, Some(100));
    }

    #[test]
    fn package_freeze_empty_fails() {
        let corpus = make_corpus_with_fixtures(1);
        let mut pkg = ContractPackage::new(corpus).unwrap();
        assert_eq!(pkg.freeze(1), Err(FoundationError::EmptyPackage));
    }

    #[test]
    fn package_double_freeze_fails() {
        let mut pkg = make_full_package();
        pkg.freeze(1).unwrap();
        assert_eq!(pkg.freeze(2), Err(FoundationError::PackageAlreadyFrozen));
    }

    #[test]
    fn package_frozen_reject_add() {
        let mut pkg = make_full_package();
        pkg.freeze(1).unwrap();
        assert_eq!(
            pkg.add_hook_contract(HookSemanticContract::canonical_use_state()),
            Err(FoundationError::PackageAlreadyFrozen)
        );
    }

    #[test]
    fn package_hash_changes_on_add() {
        let corpus = make_corpus_with_fixtures(1);
        let mut pkg = ContractPackage::new(corpus).unwrap();
        let h1 = pkg.package_hash;
        pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
            .unwrap();
        assert_ne!(h1, pkg.package_hash);
    }

    #[test]
    fn package_validate_full() {
        let pkg = make_full_package();
        let v = pkg.validate().unwrap();
        assert_eq!(v.coverage_millionths, MILLION);
        // Missing UseMemo/UseRef contracts
        assert!(!v.warnings.is_empty());
    }

    #[test]
    fn package_validate_with_all_core_hooks() {
        let mut pkg = make_full_package();
        pkg.add_hook_contract(HookSemanticContract {
            hook_kind: HookKind::UseMemo,
            invocation_rules: vec![InvocationRule::MustBeTopLevel],
            ordering_constraints: Vec::new(),
            cleanup_semantics: CleanupPolicy::NoCleanup,
            forbidden_patterns: Vec::new(),
        })
        .unwrap();
        pkg.add_hook_contract(HookSemanticContract {
            hook_kind: HookKind::UseRef,
            invocation_rules: vec![InvocationRule::MustBeTopLevel],
            ordering_constraints: Vec::new(),
            cleanup_semantics: CleanupPolicy::NoCleanup,
            forbidden_patterns: Vec::new(),
        })
        .unwrap();
        let v = pkg.validate().unwrap();
        assert!(v.is_valid);
    }

    // --- Frozen Baseline tests ---

    #[test]
    fn baseline_create() {
        let pkg = make_full_package();
        let baseline = FrozenBaseline::create(
            pkg,
            "C0".to_string(),
            100,
            vec![ConsumerLane::Compiler, ConsumerLane::Runtime],
        )
        .unwrap();
        assert_eq!(baseline.cut_line_id, "C0");
        assert!(baseline.serves_lane(&ConsumerLane::Compiler));
        assert!(!baseline.serves_lane(&ConsumerLane::Governance));
    }

    #[test]
    fn baseline_no_lanes_fails() {
        let pkg = make_full_package();
        assert_eq!(
            FrozenBaseline::create(pkg, "C0".to_string(), 1, vec![]),
            Err(FoundationError::NoConsumerLanes)
        );
    }

    #[test]
    fn baseline_auto_freezes_package() {
        let pkg = make_full_package();
        assert!(!pkg.is_frozen());
        let baseline =
            FrozenBaseline::create(pkg, "C0".to_string(), 10, vec![ConsumerLane::Verification])
                .unwrap();
        assert!(baseline.package.is_frozen());
    }

    #[test]
    fn baseline_hash_deterministic() {
        let pkg1 = make_full_package();
        let pkg2 = make_full_package();
        let b1 = FrozenBaseline::create(pkg1, "C0".to_string(), 10, vec![ConsumerLane::Compiler])
            .unwrap();
        let b2 = FrozenBaseline::create(pkg2, "C0".to_string(), 10, vec![ConsumerLane::Compiler])
            .unwrap();
        assert_eq!(b1.baseline_hash, b2.baseline_hash);
    }

    // --- Drift Detection tests ---

    #[test]
    fn drift_detector_new() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Compiler],
        )
        .unwrap();
        let detector = DriftDetector::new(baseline);
        assert!(detector.alerts.is_empty());
        assert!(!detector.exceeds_threshold());
    }

    #[test]
    fn drift_detector_custom_sensitivity() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Compiler],
        )
        .unwrap();
        let detector = DriftDetector::new(baseline).with_sensitivity(100_000);
        assert_eq!(detector.sensitivity_threshold_millionths, 100_000);
    }

    #[test]
    fn drift_check_trace_compliance_pass() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Runtime],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline.clone());
        let fixture = &baseline.package.corpus.fixtures[0];
        let result = detector.check_trace_compliance(
            &fixture.id,
            &fixture.expected_trace_hash,
            ConsumerLane::Runtime,
            2,
        );
        assert!(result.is_none());
    }

    #[test]
    fn drift_check_trace_compliance_fail() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Runtime],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline.clone());
        let fixture = &baseline.package.corpus.fixtures[0];
        let bad_hash = ContentHash::compute(b"wrong_trace");
        let result =
            detector.check_trace_compliance(&fixture.id, &bad_hash, ConsumerLane::Runtime, 2);
        assert!(result.is_some());
        let alert = result.unwrap();
        assert_eq!(alert.kind, DriftKind::SemanticRegression);
        assert_eq!(alert.severity, ViolationSeverity::Fatal); // Critical fixture
    }

    #[test]
    fn drift_check_trace_unknown_fixture() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Runtime],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline);
        let result = detector.check_trace_compliance(
            &make_id("nonexistent"),
            &ContentHash::compute(b"x"),
            ConsumerLane::Runtime,
            2,
        );
        assert!(result.is_none());
    }

    #[test]
    fn drift_check_effect_boundary_pass() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Runtime],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline);
        let result = detector.check_effect_boundary(
            &EffectKind::DomMutation,
            &SideEffectBoundary::Contained,
            ConsumerLane::Runtime,
            2,
        );
        assert!(result.is_none());
    }

    #[test]
    fn drift_check_effect_boundary_leak() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Runtime],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline);
        let result = detector.check_effect_boundary(
            &EffectKind::DomMutation,
            &SideEffectBoundary::Leaks,
            ConsumerLane::Runtime,
            2,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, DriftKind::EffectBoundaryLeak);
    }

    #[test]
    fn drift_check_hook_ordering_pass() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Compiler],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline);
        let result = detector.check_hook_ordering(
            &HookKind::UseState,
            false, // not conditional
            ConsumerLane::Compiler,
            2,
        );
        assert!(result.is_none());
    }

    #[test]
    fn drift_check_hook_ordering_conditional_violation() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Compiler],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline);
        let result = detector.check_hook_ordering(
            &HookKind::UseState,
            true, // conditional!
            ConsumerLane::Compiler,
            2,
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, DriftKind::HookContractBreach);
    }

    #[test]
    fn drift_fatal_alert_count() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Runtime],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline.clone());
        // Trigger fatal alerts on all critical fixtures
        for fixture in &baseline.package.corpus.fixtures {
            let bad = ContentHash::compute(b"bad");
            detector.check_trace_compliance(&fixture.id, &bad, ConsumerLane::Runtime, 2);
        }
        assert_eq!(detector.fatal_alert_count(), 12); // all 12 are Critical priority
    }

    #[test]
    fn drift_exceeds_threshold() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Runtime],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline.clone()).with_sensitivity(1); // very sensitive
        let fixture = &baseline.package.corpus.fixtures[0];
        detector.check_trace_compliance(
            &fixture.id,
            &ContentHash::compute(b"bad"),
            ConsumerLane::Runtime,
            2,
        );
        assert!(detector.exceeds_threshold());
    }

    #[test]
    fn drift_alerts_for_lane() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Runtime, ConsumerLane::Compiler],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline.clone());
        let fixture = &baseline.package.corpus.fixtures[0];
        detector.check_trace_compliance(
            &fixture.id,
            &ContentHash::compute(b"bad"),
            ConsumerLane::Runtime,
            2,
        );
        detector.check_hook_ordering(&HookKind::UseState, true, ConsumerLane::Compiler, 3);
        assert_eq!(detector.alerts_for_lane(&ConsumerLane::Runtime).len(), 1);
        assert_eq!(detector.alerts_for_lane(&ConsumerLane::Compiler).len(), 1);
        assert_eq!(
            detector.alerts_for_lane(&ConsumerLane::Verification).len(),
            0
        );
    }

    #[test]
    fn drift_summary() {
        let baseline = FrozenBaseline::create(
            make_full_package(),
            "C0".to_string(),
            1,
            vec![ConsumerLane::Runtime],
        )
        .unwrap();
        let mut detector = DriftDetector::new(baseline.clone());
        let fixture = &baseline.package.corpus.fixtures[0];
        detector.check_trace_compliance(
            &fixture.id,
            &ContentHash::compute(b"bad"),
            ConsumerLane::Runtime,
            2,
        );
        let summary = detector.summary();
        assert_eq!(summary.total_alerts, 1);
        assert_eq!(summary.fatal_count, 1);
        assert!(
            summary
                .alerts_by_kind
                .contains_key(&DriftKind::SemanticRegression)
        );
    }

    // --- Foundation manager tests ---

    #[test]
    fn foundation_new() {
        let f = SemanticContractFoundation::new();
        assert!(f.packages.is_empty());
        assert!(f.frozen_baselines.is_empty());
        assert!(f.drift_detector.is_none());
    }

    #[test]
    fn foundation_default() {
        let f = SemanticContractFoundation::default();
        assert!(f.packages.is_empty());
    }

    #[test]
    fn foundation_register_package() {
        let mut f = SemanticContractFoundation::new();
        f.register_package(make_full_package());
        assert_eq!(f.packages.len(), 1);
        assert_eq!(f.event_log.len(), 1);
    }

    #[test]
    fn foundation_freeze_baseline() {
        let mut f = SemanticContractFoundation::new();
        f.register_package(make_full_package());
        let idx = f
            .freeze_baseline(0, "C0".to_string(), 10, vec![ConsumerLane::Compiler])
            .unwrap();
        assert_eq!(idx, 0);
        assert_eq!(f.frozen_baselines.len(), 1);
    }

    #[test]
    fn foundation_freeze_baseline_bad_index() {
        let mut f = SemanticContractFoundation::new();
        assert_eq!(
            f.freeze_baseline(0, "C0".to_string(), 1, vec![ConsumerLane::Compiler]),
            Err(FoundationError::PackageNotFound)
        );
    }

    #[test]
    fn foundation_activate_drift_detection() {
        let mut f = SemanticContractFoundation::new();
        f.register_package(make_full_package());
        f.freeze_baseline(0, "C0".to_string(), 10, vec![ConsumerLane::Compiler])
            .unwrap();
        f.activate_drift_detection(0).unwrap();
        assert!(f.drift_detector.is_some());
    }

    #[test]
    fn foundation_activate_drift_bad_index() {
        let mut f = SemanticContractFoundation::new();
        assert_eq!(
            f.activate_drift_detection(0),
            Err(FoundationError::BaselineNotFound)
        );
    }

    #[test]
    fn foundation_latest_baseline() {
        let mut f = SemanticContractFoundation::new();
        assert!(f.latest_baseline().is_none());
        f.register_package(make_full_package());
        f.freeze_baseline(0, "C0".to_string(), 10, vec![ConsumerLane::Compiler])
            .unwrap();
        assert!(f.latest_baseline().is_some());
    }

    #[test]
    fn foundation_latest_package() {
        let mut f = SemanticContractFoundation::new();
        assert!(f.latest_package().is_none());
        f.register_package(make_full_package());
        assert!(f.latest_package().is_some());
    }

    // --- Serde round-trip tests ---

    #[test]
    fn serde_version() {
        let v = SemanticContractVersion::CURRENT;
        let json = serde_json::to_string(&v).unwrap();
        let v2: SemanticContractVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn serde_fixture() {
        let fix = make_fixture(
            "serde_test",
            FixtureCategory::HookState,
            FixturePriority::High,
        );
        let json = serde_json::to_string(&fix).unwrap();
        let fix2: TraceFixture = serde_json::from_str(&json).unwrap();
        assert_eq!(fix, fix2);
    }

    #[test]
    fn serde_corpus() {
        let corpus = make_corpus_with_fixtures(3);
        let json = serde_json::to_string(&corpus).unwrap();
        let c2: CompatibilityCorpus = serde_json::from_str(&json).unwrap();
        assert_eq!(corpus, c2);
    }

    #[test]
    fn serde_hook_contract() {
        let c = HookSemanticContract::canonical_use_state();
        let json = serde_json::to_string(&c).unwrap();
        let c2: HookSemanticContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn serde_effect_contract() {
        let c = EffectSemanticContract::canonical_dom_mutation();
        let json = serde_json::to_string(&c).unwrap();
        let c2: EffectSemanticContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn serde_package() {
        let pkg = make_full_package();
        let json = serde_json::to_string(&pkg).unwrap();
        let p2: ContractPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(pkg, p2);
    }

    #[test]
    fn serde_drift_alert() {
        let alert = DriftAlert {
            id: make_id("alert1"),
            kind: DriftKind::SemanticRegression,
            severity: ViolationSeverity::Fatal,
            source_lane: ConsumerLane::Runtime,
            violated_contract_hash: Some(ContentHash::compute(b"contract")),
            description: "test drift".to_string(),
            detected_epoch: 5,
            evidence_hash: ContentHash::compute(b"evidence"),
        };
        let json = serde_json::to_string(&alert).unwrap();
        let a2: DriftAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(alert, a2);
    }

    #[test]
    fn serde_foundation() {
        let mut f = SemanticContractFoundation::new();
        f.register_package(make_full_package());
        let json = serde_json::to_string(&f).unwrap();
        let f2: SemanticContractFoundation = serde_json::from_str(&json).unwrap();
        assert_eq!(f, f2);
    }

    #[test]
    fn serde_drift_summary() {
        let summary = DriftSummary {
            total_alerts: 3,
            fatal_count: 1,
            error_count: 1,
            warning_count: 1,
            info_count: 0,
            exceeds_threshold: false,
            drift_ratio_millionths: 83_333,
            alerts_by_kind: BTreeMap::new(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let s2: DriftSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, s2);
    }

    // --- Error Display tests ---

    #[test]
    fn error_display() {
        assert_eq!(
            FoundationError::CorpusAlreadyFrozen.to_string(),
            "corpus is already frozen"
        );
        assert_eq!(
            FoundationError::EmptyCorpus.to_string(),
            "cannot freeze empty corpus"
        );
        assert_eq!(
            FoundationError::PackageNotFound.to_string(),
            "package not found"
        );
        assert_eq!(
            FoundationError::NoConsumerLanes.to_string(),
            "at least one consumer lane required"
        );
    }

    #[test]
    fn error_is_error_trait() {
        let err: Box<dyn std::error::Error> =
            Box::new(FoundationError::InvalidContract("test".to_string()));
        assert!(err.to_string().contains("test"));
    }

    // --- DOM mutation tests ---

    #[test]
    fn dom_mutation_serde() {
        let m = DomMutation {
            target_path: "/div".to_string(),
            kind: MutationKind::AppendChild,
            value: "<span>hi</span>".to_string(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let m2: DomMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn mutation_kind_variants() {
        let kinds = [
            MutationKind::SetAttribute,
            MutationKind::RemoveAttribute,
            MutationKind::AppendChild,
            MutationKind::RemoveChild,
            MutationKind::SetTextContent,
            MutationKind::InsertBefore,
        ];
        assert_eq!(kinds.len(), 6);
    }

    // --- Integration / end-to-end flow ---

    #[test]
    fn end_to_end_freeze_and_detect_drift() {
        // 1. Build corpus
        let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
        corpus
            .add_fixture(make_fixture(
                "state_basic",
                FixtureCategory::HookState,
                FixturePriority::Critical,
            ))
            .unwrap();
        corpus
            .add_fixture(make_fixture(
                "effect_basic",
                FixtureCategory::HookEffect,
                FixturePriority::High,
            ))
            .unwrap();

        // 2. Build package
        let mut pkg = ContractPackage::new(corpus).unwrap();
        pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
            .unwrap();
        pkg.add_effect_contract(EffectSemanticContract::canonical_dom_mutation())
            .unwrap();

        // 3. Foundation + freeze
        let mut foundation = SemanticContractFoundation::new();
        foundation.register_package(pkg);
        foundation
            .freeze_baseline(
                0,
                "M1".to_string(),
                100,
                vec![
                    ConsumerLane::Compiler,
                    ConsumerLane::Runtime,
                    ConsumerLane::Verification,
                ],
            )
            .unwrap();
        foundation.activate_drift_detection(0).unwrap();

        // 4. Check compliance — pass
        let baseline = foundation.latest_baseline().unwrap().clone();
        let fixture = &baseline.package.corpus.fixtures[0];
        let detector = foundation.drift_detector.as_mut().unwrap();
        let result = detector.check_trace_compliance(
            &fixture.id,
            &fixture.expected_trace_hash,
            ConsumerLane::Runtime,
            101,
        );
        assert!(result.is_none());

        // 5. Check compliance — fail
        let bad_hash = ContentHash::compute(b"diverged_trace");
        let alert = detector
            .check_trace_compliance(&fixture.id, &bad_hash, ConsumerLane::Runtime, 102)
            .unwrap();
        assert_eq!(alert.kind, DriftKind::SemanticRegression);
        assert_eq!(alert.severity, ViolationSeverity::Fatal);

        // 6. Summary
        let summary = detector.summary();
        assert_eq!(summary.total_alerts, 1);
        assert_eq!(summary.fatal_count, 1);
    }

    #[test]
    fn end_to_end_multiple_baselines() {
        let mut foundation = SemanticContractFoundation::new();

        // Package v1
        foundation.register_package(make_full_package());
        foundation
            .freeze_baseline(0, "C0".to_string(), 10, vec![ConsumerLane::Compiler])
            .unwrap();

        // Package v2
        foundation.register_package(make_full_package());
        foundation
            .freeze_baseline(
                1,
                "C1".to_string(),
                20,
                vec![ConsumerLane::Compiler, ConsumerLane::Runtime],
            )
            .unwrap();

        assert_eq!(foundation.frozen_baselines.len(), 2);
        assert_eq!(foundation.latest_baseline().unwrap().cut_line_id, "C1");
    }

    fn make_local_semantic_component(component_id: &str) -> ComponentDescriptor {
        use crate::ir_contract::EffectBoundary;
        use crate::static_analysis_graph::{
            CapabilityBoundary, ComponentId, EffectClassification, HookKind as GraphHookKind,
            HookSlot,
        };

        let mut direct_capabilities = BTreeSet::new();
        direct_capabilities.insert("dom.mutate".to_string());

        ComponentDescriptor {
            id: ComponentId::new(component_id),
            is_function_component: true,
            module_path: format!("src/{component_id}.tsx"),
            export_name: Some(component_id.to_string()),
            hook_slots: vec![HookSlot {
                slot_index: 0,
                kind: GraphHookKind::Effect,
                label: "useEffect(fetchUser)".to_string(),
                dependency_count: Some(1),
                has_cleanup: true,
                source_offset: 12,
                dependency_hash: None,
            }],
            props: BTreeMap::new(),
            consumed_contexts: vec!["AuthContext".to_string()],
            provided_contexts: vec!["FeatureFlags".to_string()],
            capability_boundary: CapabilityBoundary {
                direct_capabilities,
                transitive_capabilities: BTreeSet::new(),
                render_effect: EffectBoundary::Pure,
                hook_effects: vec![EffectClassification {
                    boundary: EffectBoundary::WriteEffect,
                    required_capabilities: {
                        let mut caps = BTreeSet::new();
                        caps.insert("dom.mutate".to_string());
                        caps
                    },
                    idempotent: true,
                    commutative: false,
                    estimated_cost_millionths: 25_000,
                }],
                is_boundary: true,
                boundary_tags: Vec::new(),
            },
            is_pure: false,
            content_hash: ContentHash::compute(component_id.as_bytes()),
            children: Vec::new(),
        }
    }

    #[test]
    fn local_semantic_atlas_entry_normalizes_and_hashes_deterministically() {
        let component = make_local_semantic_component("UserPanel");
        let input_a = LocalSemanticAtlasInput {
            component: component.clone(),
            fixture_refs: vec!["compat.hooks.order.user_panel".to_string()],
            trace_refs: vec!["trace.user_panel.hooks_order".to_string()],
            assumption_keys: vec![
                "ctx.auth.stable_identity".to_string(),
                "scheduler.effect_order.passive".to_string(),
            ],
        };
        let input_b = LocalSemanticAtlasInput {
            component,
            fixture_refs: vec!["compat.hooks.order.user_panel".to_string()],
            trace_refs: vec!["trace.user_panel.hooks_order".to_string()],
            assumption_keys: vec![
                "scheduler.effect_order.passive".to_string(),
                "ctx.auth.stable_identity".to_string(),
            ],
        };

        let entry_a = LocalSemanticAtlasEntry::from_input(input_a);
        let entry_b = LocalSemanticAtlasEntry::from_input(input_b);
        assert_eq!(entry_a.content_hash, entry_b.content_hash);
        assert_eq!(
            entry_a.assumption_keys,
            vec![
                "ctx.auth.stable_identity".to_string(),
                "scheduler.effect_order.passive".to_string()
            ]
        );
    }

    #[test]
    fn local_semantic_atlas_reports_blocking_quality_debt_for_missing_links() {
        let atlas = LocalSemanticAtlas::from_inputs(
            SemanticContractVersion::CURRENT,
            42,
            vec![LocalSemanticAtlasInput {
                component: make_local_semantic_component("MissingLinks"),
                fixture_refs: Vec::new(),
                trace_refs: Vec::new(),
                assumption_keys: Vec::new(),
            }],
        );

        assert_eq!(atlas.blocking_debt_count(), 3);
        let debt_codes = atlas
            .quality_debt
            .iter()
            .map(|debt| debt.debt_code.as_str())
            .collect::<Vec<_>>();
        assert!(debt_codes.contains(&LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_FIXTURE_LINK));
        assert!(debt_codes.contains(&LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_TRACE_LINK));
        assert!(debt_codes.contains(&LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_CONTEXT_ASSUMPTIONS));

        let validation = atlas.validate();
        assert!(!validation.is_valid);
        assert_eq!(validation.blocking_debt_count, 3);
    }

    #[test]
    fn local_semantic_atlas_passes_when_links_and_assumptions_exist() {
        let atlas = LocalSemanticAtlas::from_inputs(
            SemanticContractVersion::CURRENT,
            99,
            vec![LocalSemanticAtlasInput {
                component: make_local_semantic_component("ReadyComponent"),
                fixture_refs: vec!["compat.hooks.order.ready_component".to_string()],
                trace_refs: vec!["trace.ready_component.effects".to_string()],
                assumption_keys: vec!["ctx.auth.stable_identity".to_string()],
            }],
        );

        let validation = atlas.validate();
        assert!(validation.is_valid);
        assert_eq!(validation.blocking_debt_count, 0);
        assert!(atlas.entry("ReadyComponent").is_some());
    }

    #[test]
    fn schema_version_constant() {
        assert_eq!(
            SEMANTIC_CONTRACT_SCHEMA_VERSION,
            "franken-engine.semantic_contract_baseline.v1"
        );
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn fixture_category_serde_roundtrip_all_variants() {
        let variants = [
            FixtureCategory::HookState,
            FixtureCategory::HookEffect,
            FixtureCategory::HookMemo,
            FixtureCategory::HookRef,
            FixtureCategory::HookReducer,
            FixtureCategory::HookContext,
            FixtureCategory::ConcurrentRendering,
            FixtureCategory::Suspense,
            FixtureCategory::ErrorBoundary,
            FixtureCategory::Hydration,
            FixtureCategory::Portal,
            FixtureCategory::RefEdgeCase,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FixtureCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 12);
    }

    #[test]
    fn hook_kind_serde_roundtrip_all_variants() {
        let variants = [
            HookKind::UseState,
            HookKind::UseEffect,
            HookKind::UseMemo,
            HookKind::UseRef,
            HookKind::UseReducer,
            HookKind::UseContext,
            HookKind::UseCallback,
            HookKind::UseLayoutEffect,
            HookKind::UseImperativeHandle,
            HookKind::UseDebugValue,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: HookKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 10);
    }

    #[test]
    fn invocation_rule_serde_roundtrip_all_variants() {
        let variants = [
            InvocationRule::MustBeTopLevel,
            InvocationRule::MustNotBeConditional,
            InvocationRule::MustNotBeInLoop,
            InvocationRule::MustBeInFunctionComponent,
            InvocationRule::OrderPreservedAcrossRenders,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: InvocationRule = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 5);
    }

    #[test]
    fn cleanup_policy_serde_roundtrip_all_variants() {
        let variants = [
            CleanupPolicy::RunOnUnmount,
            CleanupPolicy::RunBeforeRerun,
            CleanupPolicy::NoCleanup,
            CleanupPolicy::ConditionalCleanup,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: CleanupPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn effect_kind_serde_roundtrip_all_variants() {
        let variants = [
            EffectKind::DomMutation,
            EffectKind::NetworkIo,
            EffectKind::TimerSetup,
            EffectKind::StateUpdate,
            EffectKind::Subscription,
            EffectKind::CustomEffect,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EffectKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn effect_timing_serde_roundtrip_all_variants() {
        let variants = [
            EffectTiming::AfterRender,
            EffectTiming::BeforePaint,
            EffectTiming::Synchronous,
            EffectTiming::Deferred,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EffectTiming = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn consumer_lane_serde_roundtrip_all_variants() {
        let variants = [
            ConsumerLane::Compiler,
            ConsumerLane::Runtime,
            ConsumerLane::Verification,
            ConsumerLane::Optimization,
            ConsumerLane::Governance,
            ConsumerLane::Adoption,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ConsumerLane = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn drift_kind_serde_roundtrip_all_variants() {
        let variants = [
            DriftKind::SemanticRegression,
            DriftKind::OrderingViolation,
            DriftKind::EffectBoundaryLeak,
            DriftKind::HookContractBreach,
            DriftKind::AdjudicationOverride,
            DriftKind::CorpusCoverageDrop,
            DriftKind::VersionIncompatibility,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DriftKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 7);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn foundation_error_source_returns_none_all_variants() {
        use std::error::Error as _;
        let variants: Vec<FoundationError> = vec![
            FoundationError::CorpusAlreadyFrozen,
            FoundationError::CorpusCapacityExceeded,
            FoundationError::DuplicateFixture,
            FoundationError::EmptyCorpus,
            FoundationError::EmptyPackage,
            FoundationError::PackageAlreadyFrozen,
            FoundationError::PackageNotFound,
            FoundationError::BaselineNotFound,
            FoundationError::ContractCapacityExceeded,
            FoundationError::AdjudicationCapacityExceeded,
            FoundationError::NoConsumerLanes,
            FoundationError::InvalidContract("x".to_string()),
            FoundationError::IncompatibleVersion,
        ];
        for v in &variants {
            assert!(v.source().is_none(), "expected None source for {v}");
        }
        assert_eq!(variants.len(), 13);
    }

    #[test]
    fn foundation_error_display_exact_all_13() {
        assert_eq!(
            FoundationError::CorpusCapacityExceeded.to_string(),
            "corpus capacity exceeded (max 10000)"
        );
        assert_eq!(
            FoundationError::DuplicateFixture.to_string(),
            "duplicate fixture ID"
        );
        assert_eq!(
            FoundationError::EmptyPackage.to_string(),
            "cannot freeze package with no contracts"
        );
        assert_eq!(
            FoundationError::PackageAlreadyFrozen.to_string(),
            "package is already frozen"
        );
        assert_eq!(
            FoundationError::BaselineNotFound.to_string(),
            "baseline not found"
        );
        assert_eq!(
            FoundationError::ContractCapacityExceeded.to_string(),
            "contract capacity exceeded"
        );
        assert_eq!(
            FoundationError::AdjudicationCapacityExceeded.to_string(),
            "adjudication rule capacity exceeded"
        );
        assert_eq!(
            FoundationError::InvalidContract("bad hook".to_string()).to_string(),
            "invalid contract: bad hook"
        );
        assert_eq!(
            FoundationError::IncompatibleVersion.to_string(),
            "incompatible contract version"
        );
    }

    #[test]
    fn foundation_error_serde_roundtrip_all_variants() {
        let variants: Vec<FoundationError> = vec![
            FoundationError::CorpusAlreadyFrozen,
            FoundationError::CorpusCapacityExceeded,
            FoundationError::DuplicateFixture,
            FoundationError::EmptyCorpus,
            FoundationError::EmptyPackage,
            FoundationError::PackageAlreadyFrozen,
            FoundationError::PackageNotFound,
            FoundationError::BaselineNotFound,
            FoundationError::ContractCapacityExceeded,
            FoundationError::AdjudicationCapacityExceeded,
            FoundationError::NoConsumerLanes,
            FoundationError::InvalidContract("msg".to_string()),
            FoundationError::IncompatibleVersion,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FoundationError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn violation_severity_serde_roundtrip_all_variants() {
        let variants = [
            ViolationSeverity::Fatal,
            ViolationSeverity::Error,
            ViolationSeverity::Warning,
            ViolationSeverity::Info,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ViolationSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 4);
    }

    #[test]
    fn adjudication_category_serde_roundtrip_all_variants() {
        let variants = [
            AdjudicationCategory::AmbiguousOrdering,
            AdjudicationCategory::UndefinedEdgeCase,
            AdjudicationCategory::VersionConflict,
            AdjudicationCategory::PlatformDivergence,
            AdjudicationCategory::SpecGap,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: AdjudicationCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 5);
    }

    #[test]
    fn adjudication_resolution_serde_roundtrip_all_variants() {
        let variants = [
            AdjudicationResolution::PreferReactBehavior,
            AdjudicationResolution::PreferDeterministic,
            AdjudicationResolution::PreferConservative,
            AdjudicationResolution::RequireExplicitFallback,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: AdjudicationResolution = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 4);
    }

    #[test]
    fn side_effect_boundary_serde_roundtrip_all_variants() {
        let variants = [
            SideEffectBoundary::Contained,
            SideEffectBoundary::Leaks,
            SideEffectBoundary::Unknown,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SideEffectBoundary = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 3);
    }

    #[test]
    fn determinism_level_serde_roundtrip_all_variants() {
        let variants = [
            DeterminismLevel::FullyDeterministic,
            DeterminismLevel::OrderDeterministic,
            DeterminismLevel::Nondeterministic,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DeterminismLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 3);
    }

    #[test]
    fn mutation_kind_serde_roundtrip_all_variants() {
        let variants = [
            MutationKind::SetAttribute,
            MutationKind::RemoveAttribute,
            MutationKind::AppendChild,
            MutationKind::RemoveChild,
            MutationKind::SetTextContent,
            MutationKind::InsertBefore,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: MutationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn fixture_priority_serde_roundtrip_all_variants() {
        let variants = [
            FixturePriority::Critical,
            FixturePriority::High,
            FixturePriority::Medium,
            FixturePriority::Low,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FixturePriority = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 4);
    }

    #[test]
    fn effect_is_deterministic_all_levels() {
        let make = |level: DeterminismLevel| EffectSemanticContract {
            effect_kind: EffectKind::StateUpdate,
            timing: EffectTiming::Synchronous,
            capability_requirements: vec![],
            side_effect_boundary: SideEffectBoundary::Contained,
            determinism_guarantee: level,
        };
        assert!(make(DeterminismLevel::FullyDeterministic).is_deterministic());
        assert!(make(DeterminismLevel::OrderDeterministic).is_deterministic());
        assert!(!make(DeterminismLevel::Nondeterministic).is_deterministic());
    }

    #[test]
    fn frozen_baseline_serves_lane_present_and_absent() {
        let mut corpus = make_corpus_with_fixtures(3);
        corpus.freeze().unwrap();
        let mut pkg = ContractPackage::new(corpus).unwrap();
        pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
            .unwrap();
        let lanes = vec![ConsumerLane::Compiler, ConsumerLane::Runtime];
        let baseline = FrozenBaseline::create(pkg, "cut-1".into(), 10, lanes).unwrap();
        assert!(baseline.serves_lane(&ConsumerLane::Compiler));
        assert!(baseline.serves_lane(&ConsumerLane::Runtime));
        assert!(!baseline.serves_lane(&ConsumerLane::Verification));
        assert!(!baseline.serves_lane(&ConsumerLane::Governance));
    }

    #[test]
    fn version_is_compatible_with_same_major_higher_patch() {
        let v1 = SemanticContractVersion {
            major: 0,
            minor: 1,
            patch: 5,
        };
        let v2 = SemanticContractVersion {
            major: 0,
            minor: 1,
            patch: 0,
        };
        assert!(v1.is_compatible_with(&v2));
        assert!(v2.is_compatible_with(&v1));
    }

    #[test]
    fn version_display_custom() {
        let v = SemanticContractVersion {
            major: 2,
            minor: 3,
            patch: 7,
        };
        assert_eq!(v.to_string(), "2.3.7");
    }

    #[test]
    fn adjudication_rule_hash_differs_by_resolution() {
        let make = |res: AdjudicationResolution| {
            let rule = AdjudicationRule {
                id: make_id("adj-hash-test"),
                name: "same-name".to_string(),
                category: AdjudicationCategory::SpecGap,
                condition: "same-cond".to_string(),
                resolution: res,
                rationale: "does not matter".to_string(),
                precedent_fixture_ids: vec![],
            };
            rule.rule_hash()
        };
        let h1 = make(AdjudicationResolution::PreferReactBehavior);
        let h2 = make(AdjudicationResolution::PreferDeterministic);
        let h3 = make(AdjudicationResolution::PreferConservative);
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
    }

    #[test]
    fn effect_contract_hash_differs_by_boundary() {
        let make = |boundary: SideEffectBoundary| {
            let c = EffectSemanticContract {
                effect_kind: EffectKind::NetworkIo,
                timing: EffectTiming::Deferred,
                capability_requirements: vec!["net.fetch".to_string()],
                side_effect_boundary: boundary,
                determinism_guarantee: DeterminismLevel::Nondeterministic,
            };
            c.contract_hash()
        };
        let h1 = make(SideEffectBoundary::Contained);
        let h2 = make(SideEffectBoundary::Leaks);
        let h3 = make(SideEffectBoundary::Unknown);
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
    }
}
