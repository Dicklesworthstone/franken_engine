#![forbid(unsafe_code)]

//! React component-shape and render-purity catalog.
//!
//! Implements [RGC-609A]: infer component-shape and render-purity catalogs from
//! the native React lane so the optimizer can identify pure or mostly-pure regions
//! suitable for partial evaluation.
//!
//! The catalog consumes lowered JSX elements, hook manifests, and shape
//! descriptors to classify each component's render purity and prop-flow
//! structure. This feeds into later partial-evaluation specialization.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::hook_effect_contract::{HookKind, HookManifest};
use crate::react_jsx_lowering::{ElementType, LoweredChild, LoweredElement};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum prop count before a component is classified as high-arity.
const HIGH_ARITY_THRESHOLD: usize = 12;

/// Maximum children depth before a component is classified as deeply nested.
const DEEP_NESTING_THRESHOLD: usize = 8;

/// Minimum number of test observations to classify purity with confidence.
const MIN_OBSERVATIONS_FOR_CONFIDENCE: u64 = 5;

/// Fixed-point multiplier (1_000_000 = 1.0).
const FP_UNIT: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Prop classification
// ---------------------------------------------------------------------------

/// How a prop flows through the component render path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PropFlowKind {
    /// Rendered directly into JSX output.
    Rendered,
    /// Forwarded to a child component as-is.
    PassedDown,
    /// Used in a computation that produces render output.
    Computed,
    /// Used as a key or ref (special React semantics).
    KeyOrRef,
    /// Used only in effect hooks (not in render path).
    EffectOnly,
    /// Spread into child props.
    Spread,
    /// Not observed in any render or effect path.
    Unused,
}

impl PropFlowKind {
    /// Whether this flow contributes to render output.
    pub fn affects_render(&self) -> bool {
        matches!(
            self,
            PropFlowKind::Rendered | PropFlowKind::PassedDown | PropFlowKind::Computed
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PropFlowKind::Rendered => "rendered",
            PropFlowKind::PassedDown => "passed_down",
            PropFlowKind::Computed => "computed",
            PropFlowKind::KeyOrRef => "key_or_ref",
            PropFlowKind::EffectOnly => "effect_only",
            PropFlowKind::Spread => "spread",
            PropFlowKind::Unused => "unused",
        }
    }
}

impl fmt::Display for PropFlowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Prop shape
// ---------------------------------------------------------------------------

/// Inferred type of a prop value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PropValueKind {
    StringLiteral,
    NumberLiteral,
    BooleanLiteral,
    NullOrUndefined,
    Callback,
    ReactElement,
    Array,
    Object,
    Unknown,
}

impl PropValueKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PropValueKind::StringLiteral => "string",
            PropValueKind::NumberLiteral => "number",
            PropValueKind::BooleanLiteral => "boolean",
            PropValueKind::NullOrUndefined => "null_or_undefined",
            PropValueKind::Callback => "callback",
            PropValueKind::ReactElement => "react_element",
            PropValueKind::Array => "array",
            PropValueKind::Object => "object",
            PropValueKind::Unknown => "unknown",
        }
    }

    /// Whether this value type is always immutable.
    pub fn is_immutable(&self) -> bool {
        matches!(
            self,
            PropValueKind::StringLiteral
                | PropValueKind::NumberLiteral
                | PropValueKind::BooleanLiteral
                | PropValueKind::NullOrUndefined
        )
    }
}

impl fmt::Display for PropValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Description of a single prop in a component's shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropDescriptor {
    pub name: String,
    pub value_kind: PropValueKind,
    pub flow: PropFlowKind,
    pub is_required: bool,
    pub observation_count: u64,
}

impl PropDescriptor {
    pub fn new(name: &str, value_kind: PropValueKind, flow: PropFlowKind) -> Self {
        Self {
            name: name.to_string(),
            value_kind,
            flow,
            is_required: false,
            observation_count: 1,
        }
    }

    /// Whether this prop contributes to render purity analysis.
    pub fn is_render_relevant(&self) -> bool {
        self.flow.affects_render()
    }
}

// ---------------------------------------------------------------------------
// Render purity classification
// ---------------------------------------------------------------------------

/// Classification of a component's render purity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RenderPurityClass {
    /// Render is a pure function of props and state: no side effects,
    /// no external reads, deterministic output.
    Pure,
    /// Render is pure under specific conditions (e.g., no spread props,
    /// no dynamic keys, no context reads).
    ConditionallyPure,
    /// Render has observable side effects or non-deterministic behavior.
    Impure,
    /// Insufficient evidence to classify.
    Unknown,
}

impl RenderPurityClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            RenderPurityClass::Pure => "pure",
            RenderPurityClass::ConditionallyPure => "conditionally_pure",
            RenderPurityClass::Impure => "impure",
            RenderPurityClass::Unknown => "unknown",
        }
    }

    /// Whether this classification allows partial evaluation.
    pub fn allows_partial_eval(&self) -> bool {
        matches!(
            self,
            RenderPurityClass::Pure | RenderPurityClass::ConditionallyPure
        )
    }
}

impl fmt::Display for RenderPurityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reason why a component's render was classified as impure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ImpurityReason {
    /// Component uses an effect hook in render path.
    EffectInRenderPath,
    /// Component reads mutable external state (e.g., `useSyncExternalStore`).
    ExternalStateRead,
    /// Component uses `useRef` for mutable state.
    MutableRef,
    /// Component has spread props that prevent static analysis.
    SpreadProps,
    /// Component uses dynamic element types.
    DynamicElementType,
    /// Component uses context that may change.
    ContextDependency,
    /// Component has conditional hook calls (violates rules of hooks).
    ConditionalHooks,
    /// Component performs non-deterministic computation.
    NonDeterministic,
    /// Insufficient observations.
    InsufficientEvidence,
}

impl ImpurityReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            ImpurityReason::EffectInRenderPath => "effect_in_render_path",
            ImpurityReason::ExternalStateRead => "external_state_read",
            ImpurityReason::MutableRef => "mutable_ref",
            ImpurityReason::SpreadProps => "spread_props",
            ImpurityReason::DynamicElementType => "dynamic_element_type",
            ImpurityReason::ContextDependency => "context_dependency",
            ImpurityReason::ConditionalHooks => "conditional_hooks",
            ImpurityReason::NonDeterministic => "non_deterministic",
            ImpurityReason::InsufficientEvidence => "insufficient_evidence",
        }
    }

    /// Severity weight for impurity reasons (higher = worse for optimization).
    pub fn severity_weight(&self) -> u64 {
        match self {
            ImpurityReason::EffectInRenderPath => 900_000,
            ImpurityReason::ExternalStateRead => 800_000,
            ImpurityReason::MutableRef => 700_000,
            ImpurityReason::NonDeterministic => 1_000_000,
            ImpurityReason::ConditionalHooks => 950_000,
            ImpurityReason::SpreadProps => 300_000,
            ImpurityReason::DynamicElementType => 400_000,
            ImpurityReason::ContextDependency => 500_000,
            ImpurityReason::InsufficientEvidence => 100_000,
        }
    }
}

impl fmt::Display for ImpurityReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Hook profile
// ---------------------------------------------------------------------------

/// Summary of hooks used by a component.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookProfile {
    pub state_hooks: u32,
    pub effect_hooks: u32,
    pub memo_hooks: u32,
    pub ref_hooks: u32,
    pub context_hooks: u32,
    pub callback_hooks: u32,
    pub other_hooks: u32,
    pub total_hooks: u32,
    pub has_conditional_hooks: bool,
}

impl HookProfile {
    /// Build a profile from a hook manifest.
    pub fn from_manifest(manifest: &HookManifest) -> Self {
        let mut profile = HookProfile::default();
        for slot in &manifest.slots {
            profile.total_hooks += 1;
            match slot.kind {
                HookKind::State | HookKind::Reducer => profile.state_hooks += 1,
                HookKind::Effect | HookKind::LayoutEffect | HookKind::InsertionEffect => {
                    profile.effect_hooks += 1;
                }
                HookKind::Memo | HookKind::DeferredValue => profile.memo_hooks += 1,
                HookKind::Ref | HookKind::ImperativeHandle => profile.ref_hooks += 1,
                HookKind::Context => profile.context_hooks += 1,
                HookKind::Callback => profile.callback_hooks += 1,
                _ => profile.other_hooks += 1,
            }
        }
        profile
    }

    /// Whether this profile contains hooks that produce side effects.
    pub fn has_effects(&self) -> bool {
        self.effect_hooks > 0
    }

    /// Whether this profile is stateless (no state or reducer hooks).
    pub fn is_stateless(&self) -> bool {
        self.state_hooks == 0
    }

    /// Whether this profile reads external context.
    pub fn reads_context(&self) -> bool {
        self.context_hooks > 0
    }

    /// Whether this profile uses mutable refs.
    pub fn uses_refs(&self) -> bool {
        self.ref_hooks > 0
    }
}

// ---------------------------------------------------------------------------
// Component shape
// ---------------------------------------------------------------------------

/// Complete shape descriptor for a React component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentShape {
    pub component_name: String,
    pub props: Vec<PropDescriptor>,
    pub hook_profile: HookProfile,
    pub render_purity: RenderPurityClass,
    pub impurity_reasons: BTreeSet<ImpurityReason>,
    pub children_element_types: BTreeSet<String>,
    pub max_render_depth: usize,
    pub has_spread_props: bool,
    pub has_dynamic_children: bool,
    pub observation_count: u64,
    pub evidence_hash: String,
}

impl ComponentShape {
    /// Create a new component shape with default values.
    pub fn new(name: &str) -> Self {
        Self {
            component_name: name.to_string(),
            props: Vec::new(),
            hook_profile: HookProfile::default(),
            render_purity: RenderPurityClass::Unknown,
            impurity_reasons: BTreeSet::new(),
            children_element_types: BTreeSet::new(),
            max_render_depth: 0,
            has_spread_props: false,
            has_dynamic_children: false,
            observation_count: 0,
            evidence_hash: String::new(),
        }
    }

    /// Add a prop descriptor to this shape.
    pub fn add_prop(&mut self, prop: PropDescriptor) {
        if let Some(existing) = self.props.iter_mut().find(|p| p.name == prop.name) {
            existing.observation_count += 1;
            if prop.value_kind != PropValueKind::Unknown {
                existing.value_kind = prop.value_kind;
            }
        } else {
            self.props.push(prop);
        }
    }

    /// Number of props.
    pub fn prop_count(&self) -> usize {
        self.props.len()
    }

    /// Whether this component has high arity.
    pub fn is_high_arity(&self) -> bool {
        self.props.len() >= HIGH_ARITY_THRESHOLD
    }

    /// Whether this component has deep nesting in its render output.
    pub fn is_deeply_nested(&self) -> bool {
        self.max_render_depth >= DEEP_NESTING_THRESHOLD
    }

    /// Whether this component is eligible for partial evaluation.
    pub fn is_partial_eval_eligible(&self) -> bool {
        self.render_purity.allows_partial_eval() && !self.has_spread_props
    }

    /// Compute the render-relevant prop count.
    pub fn render_relevant_prop_count(&self) -> usize {
        self.props.iter().filter(|p| p.is_render_relevant()).count()
    }

    /// Count props of a specific flow kind.
    pub fn props_by_flow(&self, flow: PropFlowKind) -> usize {
        self.props.iter().filter(|p| p.flow == flow).count()
    }

    /// Compute the evidence hash for this shape.
    pub fn compute_evidence_hash(&mut self) {
        let input = format!(
            "{}:{}:{}:{}:{}:{}",
            self.component_name,
            self.prop_count(),
            self.hook_profile.total_hooks,
            self.render_purity.as_str(),
            self.max_render_depth,
            self.observation_count,
        );
        self.evidence_hash = hex_encode(ContentHash::compute(input.as_bytes()).as_bytes());
    }
}

impl fmt::Display for ComponentShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ComponentShape({}, props={}, hooks={}, purity={})",
            self.component_name,
            self.prop_count(),
            self.hook_profile.total_hooks,
            self.render_purity
        )
    }
}

// ---------------------------------------------------------------------------
// Purity analysis
// ---------------------------------------------------------------------------

/// Configuration for purity classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurityConfig {
    /// Minimum observations before classifying as pure.
    pub min_observations: u64,
    /// Whether context reads automatically downgrade to conditionally-pure.
    pub context_downgrades_purity: bool,
    /// Whether spread props automatically downgrade to conditionally-pure.
    pub spread_downgrades_purity: bool,
    /// Maximum impurity severity sum before downgrading from conditionally-pure.
    pub max_conditional_severity: u64,
}

impl Default for PurityConfig {
    fn default() -> Self {
        Self {
            min_observations: MIN_OBSERVATIONS_FOR_CONFIDENCE,
            context_downgrades_purity: true,
            spread_downgrades_purity: true,
            max_conditional_severity: 500_000,
        }
    }
}

/// Classify the render purity of a component based on its shape.
pub fn classify_purity(shape: &ComponentShape, config: &PurityConfig) -> PurityClassification {
    let mut reasons = BTreeSet::new();

    // Insufficient evidence check.
    if shape.observation_count < config.min_observations {
        reasons.insert(ImpurityReason::InsufficientEvidence);
        return PurityClassification {
            class: RenderPurityClass::Unknown,
            reasons,
            severity_total: ImpurityReason::InsufficientEvidence.severity_weight(),
            confidence_fp: 0,
        };
    }

    // Effect hooks in render path.
    if shape.hook_profile.has_effects() {
        reasons.insert(ImpurityReason::EffectInRenderPath);
    }

    // Context dependency.
    if shape.hook_profile.reads_context() {
        reasons.insert(ImpurityReason::ContextDependency);
    }

    // Mutable refs.
    if shape.hook_profile.uses_refs() {
        reasons.insert(ImpurityReason::MutableRef);
    }

    // Conditional hooks.
    if shape.hook_profile.has_conditional_hooks {
        reasons.insert(ImpurityReason::ConditionalHooks);
    }

    // Spread props.
    if shape.has_spread_props {
        reasons.insert(ImpurityReason::SpreadProps);
    }

    // Dynamic children.
    if shape.has_dynamic_children {
        reasons.insert(ImpurityReason::DynamicElementType);
    }

    // Compute severity total.
    let severity_total: u64 = reasons.iter().map(|r| r.severity_weight()).sum();

    // Classify.
    let class = if reasons.is_empty() {
        RenderPurityClass::Pure
    } else if reasons.contains(&ImpurityReason::ConditionalHooks)
        || reasons.contains(&ImpurityReason::NonDeterministic)
    {
        // Hard impurity: cannot optimize.
        RenderPurityClass::Impure
    } else if severity_total > config.max_conditional_severity {
        RenderPurityClass::Impure
    } else {
        // Soft impurity: can optimize under conditions.
        RenderPurityClass::ConditionallyPure
    };

    // Confidence is higher when more observations are available.
    let obs_ratio = shape.observation_count.min(100) * FP_UNIT / 100;
    let confidence_fp = if reasons.is_empty() {
        obs_ratio
    } else {
        obs_ratio * 800_000 / FP_UNIT
    };

    PurityClassification {
        class,
        reasons,
        severity_total,
        confidence_fp,
    }
}

/// Result of purity classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurityClassification {
    pub class: RenderPurityClass,
    pub reasons: BTreeSet<ImpurityReason>,
    pub severity_total: u64,
    /// Confidence in fixed-point millionths (FP_UNIT = 1.0).
    pub confidence_fp: u64,
}

// ---------------------------------------------------------------------------
// Element tree analysis
// ---------------------------------------------------------------------------

/// Analyze a lowered element tree to extract render structure evidence.
pub fn analyze_render_tree(root: &LoweredElement) -> RenderTreeAnalysis {
    let mut analysis = RenderTreeAnalysis::default();
    walk_element(root, 0, &mut analysis);
    analysis
}

fn walk_element(element: &LoweredElement, depth: usize, analysis: &mut RenderTreeAnalysis) {
    analysis.total_elements += 1;
    if depth > analysis.max_depth {
        analysis.max_depth = depth;
    }

    match &element.element_type {
        ElementType::Intrinsic { tag } => {
            analysis.intrinsic_count += 1;
            analysis.intrinsic_tags.insert(tag.clone());
        }
        ElementType::Component { name } => {
            analysis.component_count += 1;
            analysis.component_refs.insert(name.clone());
        }
        ElementType::Fragment => {
            analysis.fragment_count += 1;
        }
    }

    if element.props.has_spreads {
        analysis.has_spreads = true;
    }

    // Check for key extraction (stable iteration pattern).
    if element.props.extracted_key.is_some() {
        analysis.keyed_elements += 1;
    }

    // Recurse into children.
    for child in &element.children {
        if let LoweredChild::Element(inner) = child {
            walk_element(inner, depth + 1, analysis);
        }
    }
}

/// Analysis results from walking a lowered element tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderTreeAnalysis {
    pub total_elements: usize,
    pub intrinsic_count: usize,
    pub component_count: usize,
    pub fragment_count: usize,
    pub max_depth: usize,
    pub keyed_elements: usize,
    pub has_spreads: bool,
    pub intrinsic_tags: BTreeSet<String>,
    pub component_refs: BTreeSet<String>,
}

impl RenderTreeAnalysis {
    /// Whether this tree has a simple structure (few elements, low depth).
    pub fn is_simple(&self) -> bool {
        self.total_elements <= 5 && self.max_depth <= 3 && !self.has_spreads
    }

    /// Whether this tree references other components (not just intrinsics).
    pub fn has_component_children(&self) -> bool {
        self.component_count > 0
    }
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

/// The component-shape catalog: a registry of analyzed component shapes
/// with purity classifications and optimization eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentShapeCatalog {
    pub components: BTreeMap<String, ComponentShape>,
    pub config: PurityConfig,
    pub analysis_epoch: u64,
    pub total_observations: u64,
}

impl ComponentShapeCatalog {
    /// Create a new empty catalog.
    pub fn new() -> Self {
        Self {
            components: BTreeMap::new(),
            config: PurityConfig::default(),
            analysis_epoch: 0,
            total_observations: 0,
        }
    }

    /// Create a catalog with custom purity config.
    pub fn with_config(config: PurityConfig) -> Self {
        Self {
            components: BTreeMap::new(),
            config,
            analysis_epoch: 0,
            total_observations: 0,
        }
    }

    /// Register a component shape in the catalog.
    pub fn register(&mut self, mut shape: ComponentShape) {
        shape.observation_count += 1;
        self.total_observations += 1;

        // Classify purity.
        let classification = classify_purity(&shape, &self.config);
        shape.render_purity = classification.class;
        shape.impurity_reasons = classification.reasons;
        shape.compute_evidence_hash();

        self.components
            .entry(shape.component_name.clone())
            .and_modify(|existing| {
                existing.observation_count += 1;
                existing.render_purity = shape.render_purity;
                existing.impurity_reasons = shape.impurity_reasons.clone();
                existing.compute_evidence_hash();
            })
            .or_insert(shape);
    }

    /// Register a component from a hook manifest and lowered element tree.
    pub fn register_from_evidence(
        &mut self,
        component_name: &str,
        manifest: &HookManifest,
        render_tree: &RenderTreeAnalysis,
    ) {
        let mut shape = ComponentShape::new(component_name);
        shape.hook_profile = HookProfile::from_manifest(manifest);
        shape.max_render_depth = render_tree.max_depth;
        shape.has_spread_props = render_tree.has_spreads;
        shape.has_dynamic_children = render_tree.has_component_children();
        shape.children_element_types = render_tree.component_refs.clone();

        // Merge intrinsic tags as children too.
        for tag in &render_tree.intrinsic_tags {
            shape.children_element_types.insert(tag.clone());
        }

        self.register(shape);
    }

    /// Get a component's shape.
    pub fn get(&self, name: &str) -> Option<&ComponentShape> {
        self.components.get(name)
    }

    /// Number of registered components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Get all components classified as pure.
    pub fn pure_components(&self) -> Vec<&ComponentShape> {
        self.components
            .values()
            .filter(|c| c.render_purity == RenderPurityClass::Pure)
            .collect()
    }

    /// Get all components eligible for partial evaluation.
    pub fn partial_eval_eligible(&self) -> Vec<&ComponentShape> {
        self.components
            .values()
            .filter(|c| c.is_partial_eval_eligible())
            .collect()
    }

    /// Get all impure components with their reasons.
    pub fn impure_components(&self) -> Vec<(&ComponentShape, &BTreeSet<ImpurityReason>)> {
        self.components
            .values()
            .filter(|c| c.render_purity == RenderPurityClass::Impure)
            .map(|c| (c, &c.impurity_reasons))
            .collect()
    }

    /// Compute catalog summary statistics.
    pub fn summary(&self) -> CatalogSummary {
        let mut summary = CatalogSummary {
            total_components: self.components.len(),
            ..Default::default()
        };
        for shape in self.components.values() {
            match shape.render_purity {
                RenderPurityClass::Pure => summary.pure_count += 1,
                RenderPurityClass::ConditionallyPure => summary.conditionally_pure_count += 1,
                RenderPurityClass::Impure => summary.impure_count += 1,
                RenderPurityClass::Unknown => summary.unknown_count += 1,
            }
            if shape.is_partial_eval_eligible() {
                summary.partial_eval_eligible_count += 1;
            }
            if shape.is_high_arity() {
                summary.high_arity_count += 1;
            }
            summary.total_props += shape.prop_count();
            summary.total_hooks += shape.hook_profile.total_hooks as usize;
        }
        if summary.total_components > 0 {
            summary.purity_ratio_fp =
                (summary.pure_count as u64) * FP_UNIT / (summary.total_components as u64);
        }
        summary
    }

    /// Generate a catalog receipt for evidence audit.
    pub fn generate_receipt(&self) -> CatalogReceipt {
        let summary = self.summary();
        let component_hashes: Vec<(String, String)> = self
            .components
            .iter()
            .map(|(name, shape)| (name.clone(), shape.evidence_hash.clone()))
            .collect();

        let mut receipt_input = String::new();
        for (name, hash) in &component_hashes {
            receipt_input.push_str(name);
            receipt_input.push(':');
            receipt_input.push_str(hash);
            receipt_input.push(';');
        }

        let receipt_hash = hex_encode(ContentHash::compute(receipt_input.as_bytes()).as_bytes());

        CatalogReceipt {
            epoch: self.analysis_epoch,
            component_count: summary.total_components,
            pure_count: summary.pure_count,
            partial_eval_eligible: summary.partial_eval_eligible_count,
            purity_ratio_fp: summary.purity_ratio_fp,
            receipt_hash,
            component_hashes,
        }
    }

    /// Advance the analysis epoch.
    pub fn advance_epoch(&mut self) {
        self.analysis_epoch += 1;
    }

    /// Reclassify all components with current config.
    pub fn reclassify_all(&mut self) {
        let config = self.config.clone();
        for shape in self.components.values_mut() {
            let classification = classify_purity(shape, &config);
            shape.render_purity = classification.class;
            shape.impurity_reasons = classification.reasons;
            shape.compute_evidence_hash();
        }
    }
}

impl Default for ComponentShapeCatalog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Summary and receipt types
// ---------------------------------------------------------------------------

/// Summary statistics for the catalog.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSummary {
    pub total_components: usize,
    pub pure_count: usize,
    pub conditionally_pure_count: usize,
    pub impure_count: usize,
    pub unknown_count: usize,
    pub partial_eval_eligible_count: usize,
    pub high_arity_count: usize,
    pub total_props: usize,
    pub total_hooks: usize,
    /// Ratio of pure components in fixed-point millionths.
    pub purity_ratio_fp: u64,
}

/// Evidence receipt for audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogReceipt {
    pub epoch: u64,
    pub component_count: usize,
    pub pure_count: usize,
    pub partial_eval_eligible: usize,
    pub purity_ratio_fp: u64,
    pub receipt_hash: String,
    pub component_hashes: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook_effect_contract::{HookSlot, HookSlotIndex};
    use crate::react_jsx_lowering::LoweredPropValue;

    // -- PropFlowKind tests --

    #[test]
    fn prop_flow_affects_render() {
        assert!(PropFlowKind::Rendered.affects_render());
        assert!(PropFlowKind::PassedDown.affects_render());
        assert!(PropFlowKind::Computed.affects_render());
        assert!(!PropFlowKind::EffectOnly.affects_render());
        assert!(!PropFlowKind::Unused.affects_render());
        assert!(!PropFlowKind::KeyOrRef.affects_render());
        assert!(!PropFlowKind::Spread.affects_render());
    }

    #[test]
    fn prop_flow_as_str_display() {
        assert_eq!(PropFlowKind::Rendered.as_str(), "rendered");
        assert_eq!(format!("{}", PropFlowKind::Computed), "computed");
        assert_eq!(PropFlowKind::Unused.as_str(), "unused");
    }

    // -- PropValueKind tests --

    #[test]
    fn prop_value_immutability() {
        assert!(PropValueKind::StringLiteral.is_immutable());
        assert!(PropValueKind::NumberLiteral.is_immutable());
        assert!(PropValueKind::BooleanLiteral.is_immutable());
        assert!(PropValueKind::NullOrUndefined.is_immutable());
        assert!(!PropValueKind::Callback.is_immutable());
        assert!(!PropValueKind::ReactElement.is_immutable());
        assert!(!PropValueKind::Array.is_immutable());
        assert!(!PropValueKind::Object.is_immutable());
        assert!(!PropValueKind::Unknown.is_immutable());
    }

    #[test]
    fn prop_value_as_str() {
        assert_eq!(PropValueKind::StringLiteral.as_str(), "string");
        assert_eq!(format!("{}", PropValueKind::Callback), "callback");
    }

    // -- PropDescriptor tests --

    #[test]
    fn prop_descriptor_creation() {
        let prop =
            PropDescriptor::new("onClick", PropValueKind::Callback, PropFlowKind::EffectOnly);
        assert_eq!(prop.name, "onClick");
        assert_eq!(prop.value_kind, PropValueKind::Callback);
        assert_eq!(prop.flow, PropFlowKind::EffectOnly);
        assert!(!prop.is_required);
        assert_eq!(prop.observation_count, 1);
        assert!(!prop.is_render_relevant());
    }

    #[test]
    fn prop_descriptor_render_relevant() {
        let rendered = PropDescriptor::new(
            "title",
            PropValueKind::StringLiteral,
            PropFlowKind::Rendered,
        );
        assert!(rendered.is_render_relevant());

        let unused =
            PropDescriptor::new("debug", PropValueKind::BooleanLiteral, PropFlowKind::Unused);
        assert!(!unused.is_render_relevant());
    }

    // -- RenderPurityClass tests --

    #[test]
    fn purity_class_allows_partial_eval() {
        assert!(RenderPurityClass::Pure.allows_partial_eval());
        assert!(RenderPurityClass::ConditionallyPure.allows_partial_eval());
        assert!(!RenderPurityClass::Impure.allows_partial_eval());
        assert!(!RenderPurityClass::Unknown.allows_partial_eval());
    }

    #[test]
    fn purity_class_as_str() {
        assert_eq!(RenderPurityClass::Pure.as_str(), "pure");
        assert_eq!(format!("{}", RenderPurityClass::Impure), "impure");
    }

    // -- ImpurityReason tests --

    #[test]
    fn impurity_severity_ordering() {
        assert!(
            ImpurityReason::NonDeterministic.severity_weight()
                > ImpurityReason::EffectInRenderPath.severity_weight()
        );
        assert!(
            ImpurityReason::EffectInRenderPath.severity_weight()
                > ImpurityReason::SpreadProps.severity_weight()
        );
        assert!(
            ImpurityReason::InsufficientEvidence.severity_weight()
                < ImpurityReason::SpreadProps.severity_weight()
        );
    }

    #[test]
    fn impurity_reason_as_str() {
        assert_eq!(ImpurityReason::MutableRef.as_str(), "mutable_ref");
        assert_eq!(
            format!("{}", ImpurityReason::ConditionalHooks),
            "conditional_hooks"
        );
    }

    // -- HookProfile tests --

    fn make_manifest(hooks: &[HookKind]) -> HookManifest {
        HookManifest {
            component_name: "TestComponent".to_string(),
            slots: hooks
                .iter()
                .enumerate()
                .map(|(i, kind)| HookSlot {
                    index: HookSlotIndex(i as u32),
                    kind: *kind,
                    deps: None,
                })
                .collect(),
            version: 1,
        }
    }

    #[test]
    fn hook_profile_from_manifest_empty() {
        let manifest = make_manifest(&[]);
        let profile = HookProfile::from_manifest(&manifest);
        assert_eq!(profile.total_hooks, 0);
        assert!(!profile.has_effects());
        assert!(profile.is_stateless());
        assert!(!profile.reads_context());
    }

    #[test]
    fn hook_profile_from_manifest_mixed() {
        let manifest = make_manifest(&[
            HookKind::State,
            HookKind::Effect,
            HookKind::Memo,
            HookKind::Context,
            HookKind::Ref,
            HookKind::Callback,
        ]);
        let profile = HookProfile::from_manifest(&manifest);
        assert_eq!(profile.total_hooks, 6);
        assert_eq!(profile.state_hooks, 1);
        assert_eq!(profile.effect_hooks, 1);
        assert_eq!(profile.memo_hooks, 1);
        assert_eq!(profile.context_hooks, 1);
        assert_eq!(profile.ref_hooks, 1);
        assert_eq!(profile.callback_hooks, 1);
        assert!(profile.has_effects());
        assert!(!profile.is_stateless());
        assert!(profile.reads_context());
        assert!(profile.uses_refs());
    }

    #[test]
    fn hook_profile_stateless_with_memo() {
        let manifest = make_manifest(&[HookKind::Memo, HookKind::Callback]);
        let profile = HookProfile::from_manifest(&manifest);
        assert!(profile.is_stateless());
        assert!(!profile.has_effects());
    }

    #[test]
    fn hook_profile_reducer_counts_as_state() {
        let manifest = make_manifest(&[HookKind::Reducer]);
        let profile = HookProfile::from_manifest(&manifest);
        assert_eq!(profile.state_hooks, 1);
        assert!(!profile.is_stateless());
    }

    #[test]
    fn hook_profile_layout_effect_counts_as_effect() {
        let manifest = make_manifest(&[HookKind::LayoutEffect]);
        let profile = HookProfile::from_manifest(&manifest);
        assert_eq!(profile.effect_hooks, 1);
        assert!(profile.has_effects());
    }

    // -- ComponentShape tests --

    #[test]
    fn component_shape_creation() {
        let shape = ComponentShape::new("MyButton");
        assert_eq!(shape.component_name, "MyButton");
        assert_eq!(shape.prop_count(), 0);
        assert!(!shape.is_high_arity());
        assert!(!shape.is_deeply_nested());
        assert_eq!(shape.render_purity, RenderPurityClass::Unknown);
    }

    #[test]
    fn component_shape_add_prop_dedup() {
        let mut shape = ComponentShape::new("Card");
        shape.add_prop(PropDescriptor::new(
            "title",
            PropValueKind::StringLiteral,
            PropFlowKind::Rendered,
        ));
        shape.add_prop(PropDescriptor::new(
            "title",
            PropValueKind::Unknown,
            PropFlowKind::Rendered,
        ));
        assert_eq!(shape.prop_count(), 1);
        // Should keep the non-Unknown type and increment observation count.
        assert_eq!(shape.props[0].value_kind, PropValueKind::StringLiteral);
        assert_eq!(shape.props[0].observation_count, 2);
    }

    #[test]
    fn component_shape_add_prop_updates_kind() {
        let mut shape = ComponentShape::new("Card");
        shape.add_prop(PropDescriptor::new(
            "title",
            PropValueKind::Unknown,
            PropFlowKind::Rendered,
        ));
        shape.add_prop(PropDescriptor::new(
            "title",
            PropValueKind::NumberLiteral,
            PropFlowKind::Rendered,
        ));
        assert_eq!(shape.props[0].value_kind, PropValueKind::NumberLiteral);
    }

    #[test]
    fn component_shape_high_arity() {
        let mut shape = ComponentShape::new("Form");
        for i in 0..HIGH_ARITY_THRESHOLD {
            shape.add_prop(PropDescriptor::new(
                &format!("prop{i}"),
                PropValueKind::Unknown,
                PropFlowKind::Rendered,
            ));
        }
        assert!(shape.is_high_arity());
    }

    #[test]
    fn component_shape_deep_nesting() {
        let mut shape = ComponentShape::new("DeepTree");
        shape.max_render_depth = DEEP_NESTING_THRESHOLD;
        assert!(shape.is_deeply_nested());
        shape.max_render_depth = DEEP_NESTING_THRESHOLD - 1;
        assert!(!shape.is_deeply_nested());
    }

    #[test]
    fn component_shape_partial_eval_eligible() {
        let mut shape = ComponentShape::new("Pure");
        shape.render_purity = RenderPurityClass::Pure;
        shape.has_spread_props = false;
        assert!(shape.is_partial_eval_eligible());

        shape.has_spread_props = true;
        assert!(!shape.is_partial_eval_eligible());

        shape.has_spread_props = false;
        shape.render_purity = RenderPurityClass::Impure;
        assert!(!shape.is_partial_eval_eligible());
    }

    #[test]
    fn component_shape_render_relevant_props() {
        let mut shape = ComponentShape::new("Mixed");
        shape.add_prop(PropDescriptor::new(
            "title",
            PropValueKind::StringLiteral,
            PropFlowKind::Rendered,
        ));
        shape.add_prop(PropDescriptor::new(
            "onClick",
            PropValueKind::Callback,
            PropFlowKind::EffectOnly,
        ));
        shape.add_prop(PropDescriptor::new(
            "data",
            PropValueKind::Object,
            PropFlowKind::PassedDown,
        ));
        assert_eq!(shape.render_relevant_prop_count(), 2);
    }

    #[test]
    fn component_shape_props_by_flow() {
        let mut shape = ComponentShape::new("Test");
        shape.add_prop(PropDescriptor::new(
            "a",
            PropValueKind::Unknown,
            PropFlowKind::Rendered,
        ));
        shape.add_prop(PropDescriptor::new(
            "b",
            PropValueKind::Unknown,
            PropFlowKind::Rendered,
        ));
        shape.add_prop(PropDescriptor::new(
            "c",
            PropValueKind::Unknown,
            PropFlowKind::Unused,
        ));
        assert_eq!(shape.props_by_flow(PropFlowKind::Rendered), 2);
        assert_eq!(shape.props_by_flow(PropFlowKind::Unused), 1);
        assert_eq!(shape.props_by_flow(PropFlowKind::Spread), 0);
    }

    #[test]
    fn component_shape_evidence_hash() {
        let mut shape = ComponentShape::new("Hashed");
        shape.observation_count = 5;
        shape.compute_evidence_hash();
        assert!(!shape.evidence_hash.is_empty());
        let hash1 = shape.evidence_hash.clone();

        shape.observation_count = 10;
        shape.compute_evidence_hash();
        assert_ne!(shape.evidence_hash, hash1);
    }

    #[test]
    fn component_shape_display() {
        let mut shape = ComponentShape::new("Button");
        shape.hook_profile.total_hooks = 3;
        shape.render_purity = RenderPurityClass::Pure;
        let display = format!("{shape}");
        assert!(display.contains("Button"));
        assert!(display.contains("hooks=3"));
        assert!(display.contains("purity=pure"));
    }

    // -- Purity classification tests --

    #[test]
    fn classify_purity_pure_component() {
        let mut shape = ComponentShape::new("PureComp");
        shape.observation_count = 10;
        let config = PurityConfig::default();
        let result = classify_purity(&shape, &config);
        assert_eq!(result.class, RenderPurityClass::Pure);
        assert!(result.reasons.is_empty());
    }

    #[test]
    fn classify_purity_insufficient_evidence() {
        let shape = ComponentShape::new("NewComp");
        let config = PurityConfig::default();
        let result = classify_purity(&shape, &config);
        assert_eq!(result.class, RenderPurityClass::Unknown);
        assert!(
            result
                .reasons
                .contains(&ImpurityReason::InsufficientEvidence)
        );
    }

    #[test]
    fn classify_purity_with_effects() {
        let mut shape = ComponentShape::new("EffectComp");
        shape.observation_count = 10;
        shape.hook_profile.effect_hooks = 1;
        let config = PurityConfig::default();
        let result = classify_purity(&shape, &config);
        assert!(result.reasons.contains(&ImpurityReason::EffectInRenderPath));
        // Effect alone exceeds default max_conditional_severity of 500_000
        // (effect weight = 900_000).
        assert_eq!(result.class, RenderPurityClass::Impure);
    }

    #[test]
    fn classify_purity_context_only() {
        let mut shape = ComponentShape::new("CtxComp");
        shape.observation_count = 10;
        shape.hook_profile.context_hooks = 1;
        let config = PurityConfig::default();
        let result = classify_purity(&shape, &config);
        assert!(result.reasons.contains(&ImpurityReason::ContextDependency));
        // Context weight = 500_000, equals max_conditional_severity (> not >=).
        assert_eq!(result.class, RenderPurityClass::ConditionallyPure);
    }

    #[test]
    fn classify_purity_spread_only() {
        let mut shape = ComponentShape::new("SpreadComp");
        shape.observation_count = 10;
        shape.has_spread_props = true;
        let config = PurityConfig::default();
        let result = classify_purity(&shape, &config);
        assert!(result.reasons.contains(&ImpurityReason::SpreadProps));
        // Spread weight = 300_000 < max_conditional_severity 500_000.
        assert_eq!(result.class, RenderPurityClass::ConditionallyPure);
    }

    #[test]
    fn classify_purity_conditional_hooks_is_impure() {
        let mut shape = ComponentShape::new("BadHooks");
        shape.observation_count = 10;
        shape.hook_profile.has_conditional_hooks = true;
        let config = PurityConfig::default();
        let result = classify_purity(&shape, &config);
        assert_eq!(result.class, RenderPurityClass::Impure);
    }

    #[test]
    fn classify_purity_custom_config() {
        let mut shape = ComponentShape::new("Custom");
        shape.observation_count = 10;
        shape.hook_profile.context_hooks = 1;
        let config = PurityConfig {
            max_conditional_severity: 600_000,
            ..Default::default()
        };
        let result = classify_purity(&shape, &config);
        // Context weight = 500_000 < 600_000
        assert_eq!(result.class, RenderPurityClass::ConditionallyPure);
    }

    // -- RenderTreeAnalysis tests --

    fn make_element(tag: &str) -> LoweredElement {
        LoweredElement {
            element_type: ElementType::Intrinsic {
                tag: tag.to_string(),
            },
            props: crate::react_jsx_lowering::LoweredProps {
                entries: vec![],
                has_spreads: false,
                extracted_key: None,
                extracted_ref: None,
            },
            children: vec![],
            call_convention: crate::react_jsx_lowering::CallConvention::Classic {
                object: "React".to_string(),
                method: "createElement".to_string(),
            },
            source_location: None,
            is_static_children: false,
            depth: 0,
            span: crate::ast::SourceSpan::new(0, 0, 1, 1, 1, 1),
        }
    }

    fn make_component_element(name: &str) -> LoweredElement {
        let mut el = make_element("div");
        el.element_type = ElementType::Component {
            name: name.to_string(),
        };
        el
    }

    #[test]
    fn render_tree_analysis_single_element() {
        let el = make_element("div");
        let analysis = analyze_render_tree(&el);
        assert_eq!(analysis.total_elements, 1);
        assert_eq!(analysis.intrinsic_count, 1);
        assert_eq!(analysis.max_depth, 0);
        assert!(analysis.intrinsic_tags.contains("div"));
        assert!(analysis.is_simple());
    }

    #[test]
    fn render_tree_analysis_nested() {
        let mut root = make_element("div");
        let mut child = make_element("span");
        child
            .children
            .push(LoweredChild::Element(Box::new(make_element("a"))));
        root.children.push(LoweredChild::Element(Box::new(child)));
        root.children
            .push(LoweredChild::Element(Box::new(make_component_element(
                "Button",
            ))));

        let analysis = analyze_render_tree(&root);
        assert_eq!(analysis.total_elements, 4);
        assert_eq!(analysis.intrinsic_count, 3);
        assert_eq!(analysis.component_count, 1);
        assert_eq!(analysis.max_depth, 2);
        assert!(analysis.component_refs.contains("Button"));
        assert!(analysis.has_component_children());
    }

    #[test]
    fn render_tree_analysis_fragment() {
        let mut root = make_element("div");
        root.element_type = ElementType::Fragment;
        root.children
            .push(LoweredChild::Element(Box::new(make_element("p"))));
        let analysis = analyze_render_tree(&root);
        assert_eq!(analysis.fragment_count, 1);
        assert_eq!(analysis.intrinsic_count, 1);
    }

    #[test]
    fn render_tree_analysis_with_spreads() {
        let mut el = make_element("div");
        el.props.has_spreads = true;
        let analysis = analyze_render_tree(&el);
        assert!(analysis.has_spreads);
        assert!(!analysis.is_simple());
    }

    #[test]
    fn render_tree_analysis_keyed_elements() {
        let mut el = make_element("li");
        el.props.extracted_key = Some(LoweredPropValue::StringLiteral {
            value: "item-1".to_string(),
        });
        let analysis = analyze_render_tree(&el);
        assert_eq!(analysis.keyed_elements, 1);
    }

    // -- Catalog tests --

    #[test]
    fn catalog_creation() {
        let catalog = ComponentShapeCatalog::new();
        assert_eq!(catalog.component_count(), 0);
        assert_eq!(catalog.total_observations, 0);
    }

    #[test]
    fn catalog_register_component() {
        let mut catalog = ComponentShapeCatalog::new();
        let mut shape = ComponentShape::new("Button");
        shape.observation_count = 10;
        catalog.register(shape);
        assert_eq!(catalog.component_count(), 1);
        assert!(catalog.get("Button").is_some());
    }

    #[test]
    fn catalog_register_dedup() {
        let mut catalog = ComponentShapeCatalog::new();
        let mut shape1 = ComponentShape::new("Card");
        shape1.observation_count = 5;
        catalog.register(shape1);

        let mut shape2 = ComponentShape::new("Card");
        shape2.observation_count = 5;
        catalog.register(shape2);

        assert_eq!(catalog.component_count(), 1);
        let card = catalog.get("Card").unwrap();
        assert!(card.observation_count > 1);
    }

    #[test]
    fn catalog_register_from_evidence() {
        let mut catalog = ComponentShapeCatalog::new();
        let manifest = make_manifest(&[HookKind::State, HookKind::Memo]);
        let analysis = RenderTreeAnalysis {
            total_elements: 3,
            max_depth: 2,
            ..Default::default()
        };
        catalog.register_from_evidence("DataTable", &manifest, &analysis);
        let shape = catalog.get("DataTable").unwrap();
        assert_eq!(shape.hook_profile.state_hooks, 1);
        assert_eq!(shape.hook_profile.memo_hooks, 1);
    }

    #[test]
    fn catalog_pure_components() {
        let mut catalog = ComponentShapeCatalog::new();
        // Pure component (enough observations, no hooks).
        let mut pure = ComponentShape::new("Pure");
        pure.observation_count = 10;
        catalog.register(pure);

        // Impure component (effects).
        let mut impure = ComponentShape::new("Impure");
        impure.observation_count = 10;
        impure.hook_profile.effect_hooks = 1;
        catalog.register(impure);

        let pures = catalog.pure_components();
        assert_eq!(pures.len(), 1);
        assert_eq!(pures[0].component_name, "Pure");
    }

    #[test]
    fn catalog_partial_eval_eligible() {
        let mut catalog = ComponentShapeCatalog::new();

        let mut pure_no_spread = ComponentShape::new("Eligible");
        pure_no_spread.observation_count = 10;
        catalog.register(pure_no_spread);

        let mut pure_with_spread = ComponentShape::new("NotEligible");
        pure_with_spread.observation_count = 10;
        pure_with_spread.has_spread_props = true;
        catalog.register(pure_with_spread);

        let eligible = catalog.partial_eval_eligible();
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].component_name, "Eligible");
    }

    #[test]
    fn catalog_impure_components() {
        let mut catalog = ComponentShapeCatalog::new();

        let mut impure = ComponentShape::new("SideEffects");
        impure.observation_count = 10;
        impure.hook_profile.effect_hooks = 2;
        catalog.register(impure);

        let impures = catalog.impure_components();
        assert_eq!(impures.len(), 1);
        assert!(impures[0].1.contains(&ImpurityReason::EffectInRenderPath));
    }

    #[test]
    fn catalog_summary() {
        let mut catalog = ComponentShapeCatalog::new();

        let mut pure = ComponentShape::new("A");
        pure.observation_count = 10;
        catalog.register(pure);

        let mut impure = ComponentShape::new("B");
        impure.observation_count = 10;
        impure.hook_profile.effect_hooks = 1;
        catalog.register(impure);

        let summary = catalog.summary();
        assert_eq!(summary.total_components, 2);
        assert_eq!(summary.pure_count, 1);
        assert_eq!(summary.impure_count, 1);
        assert_eq!(summary.purity_ratio_fp, 500_000); // 1/2 = 0.5
    }

    #[test]
    fn catalog_receipt() {
        let mut catalog = ComponentShapeCatalog::new();
        let mut shape = ComponentShape::new("TestComp");
        shape.observation_count = 10;
        catalog.register(shape);

        let receipt = catalog.generate_receipt();
        assert_eq!(receipt.component_count, 1);
        assert!(!receipt.receipt_hash.is_empty());
        assert_eq!(receipt.component_hashes.len(), 1);
    }

    #[test]
    fn catalog_advance_epoch() {
        let mut catalog = ComponentShapeCatalog::new();
        assert_eq!(catalog.analysis_epoch, 0);
        catalog.advance_epoch();
        assert_eq!(catalog.analysis_epoch, 1);
    }

    #[test]
    fn catalog_reclassify_all() {
        let mut catalog = ComponentShapeCatalog::new();
        let mut shape = ComponentShape::new("Reclass");
        shape.observation_count = 10;
        shape.has_spread_props = true;
        catalog.register(shape);
        assert_eq!(
            catalog.get("Reclass").unwrap().render_purity,
            RenderPurityClass::ConditionallyPure
        );

        // Change config to make spread not a downgrade factor.
        catalog.config.max_conditional_severity = 1_000_000;
        catalog.reclassify_all();
        assert_eq!(
            catalog.get("Reclass").unwrap().render_purity,
            RenderPurityClass::ConditionallyPure
        );
    }

    #[test]
    fn catalog_with_custom_config() {
        let config = PurityConfig {
            min_observations: 1,
            ..Default::default()
        };
        let mut catalog = ComponentShapeCatalog::with_config(config);
        let shape = ComponentShape::new("Quick");
        catalog.register(shape);
        // With min_observations=1, should classify even with 1 observation.
        assert_ne!(
            catalog.get("Quick").unwrap().render_purity,
            RenderPurityClass::Unknown
        );
    }

    // -- Serde roundtrip tests --

    #[test]
    fn serde_roundtrip_prop_flow_kind() {
        let val = PropFlowKind::Computed;
        let json = serde_json::to_string(&val).unwrap();
        let back: PropFlowKind = serde_json::from_str(&json).unwrap();
        assert_eq!(val, back);
    }

    #[test]
    fn serde_roundtrip_purity_class() {
        let val = RenderPurityClass::ConditionallyPure;
        let json = serde_json::to_string(&val).unwrap();
        let back: RenderPurityClass = serde_json::from_str(&json).unwrap();
        assert_eq!(val, back);
    }

    #[test]
    fn serde_roundtrip_component_shape() {
        let mut shape = ComponentShape::new("Serde");
        shape.observation_count = 5;
        shape.add_prop(PropDescriptor::new(
            "x",
            PropValueKind::NumberLiteral,
            PropFlowKind::Rendered,
        ));
        shape.compute_evidence_hash();
        let json = serde_json::to_string(&shape).unwrap();
        let back: ComponentShape = serde_json::from_str(&json).unwrap();
        assert_eq!(shape, back);
    }

    #[test]
    fn serde_roundtrip_catalog_summary() {
        let summary = CatalogSummary {
            total_components: 5,
            pure_count: 3,
            purity_ratio_fp: 600_000,
            ..Default::default()
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: CatalogSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn serde_roundtrip_catalog_receipt() {
        let receipt = CatalogReceipt {
            epoch: 1,
            component_count: 2,
            pure_count: 1,
            partial_eval_eligible: 1,
            purity_ratio_fp: 500_000,
            receipt_hash: "abc123".to_string(),
            component_hashes: vec![("Comp".to_string(), "hash".to_string())],
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let back: CatalogReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn serde_roundtrip_impurity_reason() {
        for reason in [
            ImpurityReason::EffectInRenderPath,
            ImpurityReason::ExternalStateRead,
            ImpurityReason::MutableRef,
            ImpurityReason::SpreadProps,
            ImpurityReason::DynamicElementType,
            ImpurityReason::ContextDependency,
            ImpurityReason::ConditionalHooks,
            ImpurityReason::NonDeterministic,
            ImpurityReason::InsufficientEvidence,
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            let back: ImpurityReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, back);
        }
    }

    #[test]
    fn serde_roundtrip_hook_profile() {
        let profile = HookProfile {
            state_hooks: 2,
            effect_hooks: 1,
            memo_hooks: 3,
            total_hooks: 6,
            ..Default::default()
        };
        let json = serde_json::to_string(&profile).unwrap();
        let back: HookProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, back);
    }

    // -- Edge case tests --

    #[test]
    fn empty_catalog_summary() {
        let catalog = ComponentShapeCatalog::new();
        let summary = catalog.summary();
        assert_eq!(summary.total_components, 0);
        assert_eq!(summary.purity_ratio_fp, 0);
    }

    #[test]
    fn empty_catalog_receipt() {
        let catalog = ComponentShapeCatalog::new();
        let receipt = catalog.generate_receipt();
        assert_eq!(receipt.component_count, 0);
        assert!(!receipt.receipt_hash.is_empty());
    }

    #[test]
    fn deeply_nested_tree() {
        let mut current = make_element("div");
        for i in 0..10 {
            let mut parent = make_element(&format!("level{i}"));
            parent
                .children
                .push(LoweredChild::Element(Box::new(current)));
            current = parent;
        }
        let analysis = analyze_render_tree(&current);
        assert_eq!(analysis.max_depth, 10);
        assert!(!analysis.is_simple());
    }

    #[test]
    fn render_tree_many_siblings() {
        let mut root = make_element("ul");
        for i in 0..20 {
            let mut li = make_element("li");
            li.props.extracted_key = Some(LoweredPropValue::StringLiteral {
                value: format!("item-{i}"),
            });
            root.children.push(LoweredChild::Element(Box::new(li)));
        }
        let analysis = analyze_render_tree(&root);
        assert_eq!(analysis.total_elements, 21);
        assert_eq!(analysis.keyed_elements, 20);
        assert_eq!(analysis.max_depth, 1);
    }

    #[test]
    fn confidence_increases_with_observations() {
        let config = PurityConfig::default();

        let mut shape5 = ComponentShape::new("Low");
        shape5.observation_count = 5;
        let r5 = classify_purity(&shape5, &config);

        let mut shape50 = ComponentShape::new("High");
        shape50.observation_count = 50;
        let r50 = classify_purity(&shape50, &config);

        assert!(r50.confidence_fp > r5.confidence_fp);
    }

    #[test]
    fn all_prop_flow_kinds_covered() {
        let flows = [
            PropFlowKind::Rendered,
            PropFlowKind::PassedDown,
            PropFlowKind::Computed,
            PropFlowKind::KeyOrRef,
            PropFlowKind::EffectOnly,
            PropFlowKind::Spread,
            PropFlowKind::Unused,
        ];
        for flow in flows {
            assert!(!flow.as_str().is_empty());
            let _ = format!("{flow}");
        }
    }

    #[test]
    fn all_prop_value_kinds_covered() {
        let kinds = [
            PropValueKind::StringLiteral,
            PropValueKind::NumberLiteral,
            PropValueKind::BooleanLiteral,
            PropValueKind::NullOrUndefined,
            PropValueKind::Callback,
            PropValueKind::ReactElement,
            PropValueKind::Array,
            PropValueKind::Object,
            PropValueKind::Unknown,
        ];
        for kind in kinds {
            assert!(!kind.as_str().is_empty());
            let _ = format!("{kind}");
        }
    }
}
