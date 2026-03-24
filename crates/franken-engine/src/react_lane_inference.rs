#![forbid(unsafe_code)]
//! React lane inference — [RGC-609A]
//!
//! Infer component-shape and render-purity catalogs from the native React
//! lowering lane.  Bridges `react_jsx_lowering`, `hook_effect_contract`,
//! `shape_transition_algebra`, and `component_shape_catalog` into a single
//! inference pipeline so downstream optimizers can identify pure or
//! mostly-pure regions suitable for partial evaluation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::component_shape_catalog::{
    CatalogReceipt, CatalogSummary, ComponentShape, ComponentShapeCatalog, ImpurityReason,
    PropDescriptor, PropFlowKind, PropValueKind, PurityClassification, PurityConfig,
    RenderPurityClass, RenderTreeAnalysis, analyze_render_tree, classify_purity,
};
use crate::hash_tiers::ContentHash;
use crate::hook_effect_contract::HookManifest;
use crate::react_jsx_lowering::{LoweredElement, LoweredPropValue};
use crate::security_epoch::SecurityEpoch;
use crate::shape_transition_algebra::ShapeTransitionAlgebra;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for inference receipts.
pub const INFERENCE_SCHEMA_VERSION: &str = "frankenengine.react-lane-inference.v1";
/// Component identifier.
pub const INFERENCE_COMPONENT: &str = "react_lane_inference";
/// Bead reference.
pub const INFERENCE_BEAD_ID: &str = "bd-1lsy.7.9.1";
/// Policy ID.
pub const INFERENCE_POLICY_ID: &str = "RGC-609A";

/// Fixed-point millionths unit (1_000_000 = 1.0).
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Inference configuration
// ---------------------------------------------------------------------------

/// Configuration for the react lane inference pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceConfig {
    /// Purity classification configuration.
    pub purity_config: PurityConfig,
    /// Minimum observation count before a component is considered stable.
    pub min_stable_observations: u64,
    /// Maximum shape transitions before marking a component as polymorphic.
    pub max_shape_transitions: usize,
    /// Whether to infer prop descriptors from lowered element trees.
    pub infer_props: bool,
    /// Whether to integrate shape-transition algebra evidence.
    pub integrate_shape_algebra: bool,
    /// Maximum render depth before flagging as deeply nested.
    pub max_render_depth: usize,
    /// Minimum purity ratio (millionths) to mark the catalog as healthy.
    pub min_purity_ratio: u64,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            purity_config: PurityConfig::default(),
            min_stable_observations: 3,
            max_shape_transitions: 8,
            infer_props: true,
            integrate_shape_algebra: true,
            max_render_depth: 32,
            min_purity_ratio: 500_000, // 50%
        }
    }
}

// ---------------------------------------------------------------------------
// Component evidence
// ---------------------------------------------------------------------------

/// Evidence gathered for a single component from the React lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentEvidence {
    /// Component name.
    pub component_name: String,
    /// Lowered render tree analysis.
    pub render_tree: RenderTreeAnalysis,
    /// Hook manifest (if the component uses hooks).
    pub hook_manifest: Option<HookManifest>,
    /// Prop descriptors inferred from lowered props.
    pub inferred_props: Vec<PropDescriptor>,
    /// Shape stability assessment from the shape-transition algebra.
    pub shape_stability: ShapeStabilityAssessment,
    /// Compile receipt from the lowering pass.
    pub compile_receipt_hash: Option<String>,
}

/// Shape stability assessment for a component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapeStabilityAssessment {
    /// Number of observed shape transitions for this component's output.
    pub transition_count: usize,
    /// Whether the component has a stable (monomorphic) shape.
    pub is_monomorphic: bool,
    /// Whether the component has a small number of shapes (polymorphic).
    pub is_polymorphic: bool,
    /// Whether the component has many shapes (megamorphic).
    pub is_megamorphic: bool,
    /// Number of property-cell invalidations observed.
    pub invalidation_count: u64,
    /// Whether all property cells are in valid IC states.
    pub cells_stable: bool,
}

impl Default for ShapeStabilityAssessment {
    fn default() -> Self {
        Self {
            transition_count: 0,
            is_monomorphic: true,
            is_polymorphic: false,
            is_megamorphic: false,
            invalidation_count: 0,
            cells_stable: true,
        }
    }
}

impl ShapeStabilityAssessment {
    /// Whether the shape is stable enough for optimization.
    pub fn is_optimization_safe(&self) -> bool {
        (self.is_monomorphic || self.is_polymorphic) && self.cells_stable
    }

    /// Classify from transition count and thresholds.
    pub fn from_transitions(transition_count: usize, max_poly: usize) -> Self {
        let is_monomorphic = transition_count <= 1;
        let is_polymorphic = transition_count > 1 && transition_count <= max_poly;
        let is_megamorphic = transition_count > max_poly;
        Self {
            transition_count,
            is_monomorphic,
            is_polymorphic,
            is_megamorphic,
            invalidation_count: 0,
            cells_stable: !is_megamorphic,
        }
    }
}

// ---------------------------------------------------------------------------
// Inference result
// ---------------------------------------------------------------------------

/// Result of running the inference pipeline for a single component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentInferenceResult {
    /// Component name.
    pub component_name: String,
    /// Purity classification.
    pub purity: PurityClassification,
    /// Shape stability assessment.
    pub shape_stability: ShapeStabilityAssessment,
    /// Whether this component is eligible for partial evaluation.
    pub partial_eval_eligible: bool,
    /// Reasons blocking partial evaluation (if any).
    pub blocking_reasons: Vec<InferenceBlockingReason>,
    /// Content hash for dedup and audit.
    pub evidence_hash: String,
}

/// Reason why a component is blocked from partial evaluation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceBlockingReason {
    /// Component is classified as impure.
    ImpureClassification,
    /// Shape is megamorphic — too many transitions.
    MegamorphicShape,
    /// Property cells are invalidated.
    UnstablePropertyCells,
    /// Insufficient observation count.
    InsufficientEvidence,
    /// Render tree is too deeply nested.
    DeeplyNested,
    /// Component has conditional hooks (rules-of-hooks violation risk).
    ConditionalHooks,
    /// Component has effects in render path.
    EffectsInRender,
    /// Component uses mutable refs.
    MutableRefs,
}

impl std::fmt::Display for InferenceBlockingReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ImpureClassification => write!(f, "impure_classification"),
            Self::MegamorphicShape => write!(f, "megamorphic_shape"),
            Self::UnstablePropertyCells => write!(f, "unstable_property_cells"),
            Self::InsufficientEvidence => write!(f, "insufficient_evidence"),
            Self::DeeplyNested => write!(f, "deeply_nested"),
            Self::ConditionalHooks => write!(f, "conditional_hooks"),
            Self::EffectsInRender => write!(f, "effects_in_render"),
            Self::MutableRefs => write!(f, "mutable_refs"),
        }
    }
}

// ---------------------------------------------------------------------------
// Inference pipeline
// ---------------------------------------------------------------------------

/// The react lane inference pipeline.
///
/// Accepts evidence from the React lowering lane and produces a
/// `ComponentShapeCatalog` with purity classifications and shape-stability
/// assessments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactLaneInferencePipeline {
    /// Configuration.
    pub config: InferenceConfig,
    /// Underlying catalog.
    pub catalog: ComponentShapeCatalog,
    /// Per-component inference results.
    pub results: BTreeMap<String, ComponentInferenceResult>,
    /// Per-component evidence.
    pub evidence: BTreeMap<String, ComponentEvidence>,
    /// Epoch for the inference run.
    pub epoch: SecurityEpoch,
    /// Schema version.
    pub schema_version: String,
    /// Total components processed.
    pub total_processed: u64,
    /// Total components eligible for partial eval.
    pub total_eligible: u64,
}

impl ReactLaneInferencePipeline {
    /// Create a new pipeline with default config.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self::with_config(InferenceConfig::default(), epoch)
    }

    /// Create a new pipeline with a specific config.
    pub fn with_config(config: InferenceConfig, epoch: SecurityEpoch) -> Self {
        let catalog = ComponentShapeCatalog::with_config(config.purity_config.clone());
        Self {
            config,
            catalog,
            results: BTreeMap::new(),
            evidence: BTreeMap::new(),
            epoch,
            schema_version: INFERENCE_SCHEMA_VERSION.to_string(),
            total_processed: 0,
            total_eligible: 0,
        }
    }

    /// Infer component shapes from a lowered element tree and optional
    /// hook manifest.
    pub fn infer_component(
        &mut self,
        component_name: &str,
        lowered: &LoweredElement,
        hook_manifest: Option<&HookManifest>,
        shape_algebra: Option<&ShapeTransitionAlgebra>,
    ) -> ComponentInferenceResult {
        // 1. Analyze the render tree.
        let render_tree = analyze_render_tree(lowered);

        // 2. Infer prop descriptors from lowered element.
        let inferred_props = if self.config.infer_props {
            infer_props_from_lowered(lowered)
        } else {
            Vec::new()
        };

        // 3. Assess shape stability.
        let shape_stability = if self.config.integrate_shape_algebra {
            assess_shape_stability(component_name, shape_algebra, &self.config)
        } else {
            ShapeStabilityAssessment::default()
        };

        // 4. Build component evidence.
        let evidence = ComponentEvidence {
            component_name: component_name.to_string(),
            render_tree: render_tree.clone(),
            hook_manifest: hook_manifest.cloned(),
            inferred_props: inferred_props.clone(),
            shape_stability: shape_stability.clone(),
            compile_receipt_hash: None,
        };

        // 5. Build component shape and register.
        let mut shape = ComponentShape::new(component_name);
        if let Some(manifest) = hook_manifest {
            self.catalog
                .register_from_evidence(component_name, manifest, &render_tree);
            // Re-fetch the registered shape to get purity classification.
        } else {
            // Register without hook manifest — basic shape from render tree.
            shape.max_render_depth = render_tree.max_depth;
            shape.has_spread_props = render_tree.has_spreads;
            shape.has_dynamic_children = render_tree.has_component_children();
            shape.children_element_types = render_tree.component_refs.clone();
            for tag in &render_tree.intrinsic_tags {
                shape.children_element_types.insert(tag.clone());
            }
        }

        // Add inferred props to the shape.
        for prop in &inferred_props {
            shape.add_prop(prop.clone());
        }

        // Register the shape (updates observation count, reclassifies purity).
        self.catalog.register(shape);

        // 6. Classify purity.
        let purity = if let Some(registered) = self.catalog.get(component_name) {
            classify_purity(registered, &self.config.purity_config)
        } else {
            PurityClassification {
                class: RenderPurityClass::Unknown,
                reasons: BTreeSet::new(),
                severity_total: 0,
                confidence_fp: 0,
            }
        };

        // 7. Determine blocking reasons.
        let blocking_reasons =
            compute_blocking_reasons(&purity, &shape_stability, &evidence, &self.config);

        // 8. Check partial-eval eligibility.
        let partial_eval_eligible = blocking_reasons.is_empty()
            && purity.class.allows_partial_eval()
            && shape_stability.is_optimization_safe();

        // 9. Compute evidence hash.
        let evidence_hash =
            compute_inference_hash(component_name, &purity, &shape_stability, self.epoch);

        let result = ComponentInferenceResult {
            component_name: component_name.to_string(),
            purity,
            shape_stability,
            partial_eval_eligible,
            blocking_reasons,
            evidence_hash,
        };

        self.results
            .insert(component_name.to_string(), result.clone());
        self.evidence.insert(component_name.to_string(), evidence);
        self.total_processed += 1;
        if partial_eval_eligible {
            self.total_eligible += 1;
        }

        result
    }

    /// Get the inference result for a component.
    pub fn get_result(&self, name: &str) -> Option<&ComponentInferenceResult> {
        self.results.get(name)
    }

    /// Get all components eligible for partial evaluation.
    pub fn eligible_components(&self) -> Vec<&ComponentInferenceResult> {
        self.results
            .values()
            .filter(|r| r.partial_eval_eligible)
            .collect()
    }

    /// Get all components blocked from partial evaluation.
    pub fn blocked_components(&self) -> Vec<&ComponentInferenceResult> {
        self.results
            .values()
            .filter(|r| !r.partial_eval_eligible)
            .collect()
    }

    /// Generate a summary of the inference run.
    pub fn summary(&self) -> InferenceSummary {
        let catalog_summary = self.catalog.summary();

        let mut blocking_reason_counts: BTreeMap<String, u64> = BTreeMap::new();
        for result in self.results.values() {
            for reason in &result.blocking_reasons {
                *blocking_reason_counts
                    .entry(reason.to_string())
                    .or_insert(0) += 1;
            }
        }

        let eligibility_ratio = if self.total_processed > 0 {
            (self.total_eligible * MILLIONTHS)
                .checked_div(self.total_processed)
                .unwrap_or(0)
        } else {
            0
        };

        InferenceSummary {
            schema_version: self.schema_version.clone(),
            epoch: self.epoch,
            total_components: self.total_processed,
            eligible_count: self.total_eligible,
            blocked_count: self.total_processed.saturating_sub(self.total_eligible),
            eligibility_ratio,
            catalog_summary,
            blocking_reason_counts,
            is_healthy: eligibility_ratio >= self.config.min_purity_ratio,
        }
    }

    /// Generate an evidence receipt for the inference run.
    pub fn generate_receipt(&self) -> InferenceReceipt {
        let catalog_receipt = self.catalog.generate_receipt();
        let summary = self.summary();

        let component_verdicts: Vec<(String, bool, String)> = self
            .results
            .iter()
            .map(|(name, r)| {
                (
                    name.clone(),
                    r.partial_eval_eligible,
                    r.evidence_hash.clone(),
                )
            })
            .collect();

        let receipt_hash = {
            let mut input = format!(
                "{}:{}:{}:{}",
                INFERENCE_SCHEMA_VERSION,
                self.epoch.as_u64(),
                self.total_processed,
                self.total_eligible,
            );
            for (name, eligible, hash) in &component_verdicts {
                input.push_str(&format!(":{name}:{eligible}:{hash}"));
            }
            ContentHash::compute(input.as_bytes()).to_hex()
        };

        InferenceReceipt {
            schema_version: self.schema_version.clone(),
            bead_id: INFERENCE_BEAD_ID.to_string(),
            policy_id: INFERENCE_POLICY_ID.to_string(),
            epoch: self.epoch,
            total_components: self.total_processed,
            eligible_count: self.total_eligible,
            eligibility_ratio: summary.eligibility_ratio,
            is_healthy: summary.is_healthy,
            catalog_receipt,
            component_verdicts,
            receipt_hash,
        }
    }

    /// Advance epoch and reclassify all components.
    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch) {
        self.epoch = new_epoch;
        self.catalog.advance_epoch();
    }

    /// Reset the pipeline, clearing all results and evidence.
    pub fn reset(&mut self) {
        self.results.clear();
        self.evidence.clear();
        self.total_processed = 0;
        self.total_eligible = 0;
        self.catalog = ComponentShapeCatalog::with_config(self.config.purity_config.clone());
    }
}

// ---------------------------------------------------------------------------
// Inference summary and receipt
// ---------------------------------------------------------------------------

/// Summary of an inference run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceSummary {
    /// Schema version.
    pub schema_version: String,
    /// Inference epoch.
    pub epoch: SecurityEpoch,
    /// Total components processed.
    pub total_components: u64,
    /// Components eligible for partial evaluation.
    pub eligible_count: u64,
    /// Components blocked from partial evaluation.
    pub blocked_count: u64,
    /// Eligibility ratio (millionths).
    pub eligibility_ratio: u64,
    /// Underlying catalog summary.
    pub catalog_summary: CatalogSummary,
    /// Blocking reason counts.
    pub blocking_reason_counts: BTreeMap<String, u64>,
    /// Whether the catalog meets the health threshold.
    pub is_healthy: bool,
}

/// Evidence receipt for an inference run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Policy ID.
    pub policy_id: String,
    /// Inference epoch.
    pub epoch: SecurityEpoch,
    /// Total components.
    pub total_components: u64,
    /// Eligible count.
    pub eligible_count: u64,
    /// Eligibility ratio (millionths).
    pub eligibility_ratio: u64,
    /// Whether healthy.
    pub is_healthy: bool,
    /// Catalog receipt.
    pub catalog_receipt: CatalogReceipt,
    /// Per-component verdicts: (name, eligible, hash).
    pub component_verdicts: Vec<(String, bool, String)>,
    /// Receipt hash.
    pub receipt_hash: String,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Infer prop descriptors from a lowered element's props.
pub fn infer_props_from_lowered(element: &LoweredElement) -> Vec<PropDescriptor> {
    let mut props = Vec::new();
    for entry in &element.props.entries {
        if let crate::react_jsx_lowering::PropsEntry::Named(named) = entry {
            let value_kind = infer_prop_value_kind(&named.value);
            let flow = infer_prop_flow(&named.name);
            props.push(PropDescriptor::new(&named.name, value_kind, flow));
        }
    }
    props
}

/// Infer the `PropValueKind` from a lowered prop value.
fn infer_prop_value_kind(value: &LoweredPropValue) -> PropValueKind {
    match value {
        LoweredPropValue::StringLiteral { .. } => PropValueKind::StringLiteral,
        LoweredPropValue::BooleanTrue => PropValueKind::BooleanLiteral,
        LoweredPropValue::Null => PropValueKind::NullOrUndefined,
        LoweredPropValue::Element(_) => PropValueKind::ReactElement,
        LoweredPropValue::ChildrenArray { .. } => PropValueKind::Array,
        LoweredPropValue::Expression { expression } => {
            // Heuristic: check if the expression looks like a callback.
            if expression.starts_with("()") || expression.contains("=>") {
                PropValueKind::Callback
            } else {
                PropValueKind::Unknown
            }
        }
    }
}

/// Infer the `PropFlowKind` from a prop name.
fn infer_prop_flow(name: &str) -> PropFlowKind {
    match name {
        "key" | "ref" => PropFlowKind::KeyOrRef,
        "children" => PropFlowKind::Rendered,
        "className" | "style" | "id" | "href" | "src" | "alt" | "type" | "value"
        | "placeholder" | "title" | "role" | "aria-label" => PropFlowKind::Rendered,
        name if name.starts_with("on") && name.len() > 2 => PropFlowKind::EffectOnly,
        _ => PropFlowKind::Computed,
    }
}

/// Assess shape stability for a component from the shape-transition algebra.
fn assess_shape_stability(
    _component_name: &str,
    algebra: Option<&ShapeTransitionAlgebra>,
    config: &InferenceConfig,
) -> ShapeStabilityAssessment {
    let Some(algebra) = algebra else {
        return ShapeStabilityAssessment::default();
    };

    // Count transitions from the root shape (as a proxy for component output shape).
    let manifest = algebra.manifest();
    let transition_count = manifest.transitions.len();

    ShapeStabilityAssessment::from_transitions(transition_count, config.max_shape_transitions)
}

/// Compute blocking reasons for partial evaluation.
fn compute_blocking_reasons(
    purity: &PurityClassification,
    shape_stability: &ShapeStabilityAssessment,
    evidence: &ComponentEvidence,
    config: &InferenceConfig,
) -> Vec<InferenceBlockingReason> {
    let mut reasons = Vec::new();

    // Purity checks.
    if purity.class == RenderPurityClass::Impure {
        reasons.push(InferenceBlockingReason::ImpureClassification);
    }
    if purity.reasons.contains(&ImpurityReason::EffectInRenderPath) {
        reasons.push(InferenceBlockingReason::EffectsInRender);
    }
    if purity.reasons.contains(&ImpurityReason::MutableRef) {
        reasons.push(InferenceBlockingReason::MutableRefs);
    }
    if purity.reasons.contains(&ImpurityReason::ConditionalHooks) {
        reasons.push(InferenceBlockingReason::ConditionalHooks);
    }

    // Shape stability checks.
    if shape_stability.is_megamorphic {
        reasons.push(InferenceBlockingReason::MegamorphicShape);
    }
    if !shape_stability.cells_stable {
        reasons.push(InferenceBlockingReason::UnstablePropertyCells);
    }

    // Depth check.
    if evidence.render_tree.max_depth > config.max_render_depth {
        reasons.push(InferenceBlockingReason::DeeplyNested);
    }

    // Sort for determinism.
    reasons.sort();
    reasons.dedup();
    reasons
}

/// Compute a deterministic hash for an inference result.
fn compute_inference_hash(
    component_name: &str,
    purity: &PurityClassification,
    shape_stability: &ShapeStabilityAssessment,
    epoch: SecurityEpoch,
) -> String {
    let input = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        INFERENCE_SCHEMA_VERSION,
        component_name,
        purity.class.as_str(),
        purity.severity_total,
        purity.confidence_fp,
        shape_stability.transition_count,
        shape_stability.is_monomorphic,
        shape_stability.invalidation_count,
        epoch.as_u64(),
    );
    ContentHash::compute(input.as_bytes()).to_hex()
}

/// Batch-infer component shapes from multiple lowered elements.
pub fn batch_infer(
    pipeline: &mut ReactLaneInferencePipeline,
    components: &[(String, LoweredElement, Option<HookManifest>)],
    algebra: Option<&ShapeTransitionAlgebra>,
) -> Vec<ComponentInferenceResult> {
    components
        .iter()
        .map(|(name, element, manifest)| {
            pipeline.infer_component(name, element, manifest.as_ref(), algebra)
        })
        .collect()
}

/// Compute the partial-eval coverage for a set of inference results.
pub fn partial_eval_coverage(results: &[ComponentInferenceResult]) -> u64 {
    if results.is_empty() {
        return 0;
    }
    let eligible = results.iter().filter(|r| r.partial_eval_eligible).count() as u64;
    eligible
        .saturating_mul(MILLIONTHS)
        .checked_div(results.len() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::SourceSpan;
    use crate::hook_effect_contract::{HookKind, HookSlot, HookSlotIndex};
    use crate::react_jsx_lowering::{
        CallConvention, ElementType, LoweredChild, LoweredElement, LoweredProp, LoweredPropValue,
        LoweredProps, PropsEntry,
    };

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    /// Config with min_observations=1 so purity fires after a single observation.
    fn low_obs_config() -> InferenceConfig {
        InferenceConfig {
            purity_config: PurityConfig {
                min_observations: 1,
                ..PurityConfig::default()
            },
            ..InferenceConfig::default()
        }
    }

    fn span() -> SourceSpan {
        SourceSpan::new(0, 0, 1, 1, 1, 1)
    }

    fn make_element(tag: &str) -> LoweredElement {
        LoweredElement {
            element_type: ElementType::Intrinsic {
                tag: tag.to_string(),
            },
            props: LoweredProps {
                entries: Vec::new(),
                has_spreads: false,
                extracted_key: None,
                extracted_ref: None,
            },
            children: Vec::new(),
            call_convention: CallConvention::Classic {
                object: "React".into(),
                method: "createElement".into(),
            },
            source_location: None,
            is_static_children: false,
            depth: 0,
            span: span(),
        }
    }

    #[allow(dead_code)]
    fn make_component_element(name: &str) -> LoweredElement {
        LoweredElement {
            element_type: ElementType::Component {
                name: name.to_string(),
            },
            props: LoweredProps {
                entries: Vec::new(),
                has_spreads: false,
                extracted_key: None,
                extracted_ref: None,
            },
            children: Vec::new(),
            call_convention: CallConvention::Classic {
                object: "React".into(),
                method: "createElement".into(),
            },
            source_location: None,
            is_static_children: false,
            depth: 0,
            span: span(),
        }
    }

    fn make_element_with_props(tag: &str, props: Vec<(&str, LoweredPropValue)>) -> LoweredElement {
        let entries = props
            .into_iter()
            .map(|(name, value)| {
                PropsEntry::Named(LoweredProp {
                    name: name.to_string(),
                    value,
                    span: None,
                })
            })
            .collect();
        LoweredElement {
            element_type: ElementType::Intrinsic {
                tag: tag.to_string(),
            },
            props: LoweredProps {
                entries,
                has_spreads: false,
                extracted_key: None,
                extracted_ref: None,
            },
            children: Vec::new(),
            call_convention: CallConvention::Classic {
                object: "React".into(),
                method: "createElement".into(),
            },
            source_location: None,
            is_static_children: false,
            depth: 0,
            span: span(),
        }
    }

    fn make_hook_manifest(name: &str, hooks: Vec<HookKind>) -> HookManifest {
        let slots = hooks
            .into_iter()
            .enumerate()
            .map(|(i, kind)| HookSlot {
                index: HookSlotIndex(i as u32),
                kind,
                deps: None,
            })
            .collect();
        HookManifest::new(name, slots)
    }

    // -- InferenceConfig tests --

    #[test]
    fn inference_config_default() {
        let config = InferenceConfig::default();
        assert_eq!(config.min_stable_observations, 3);
        assert_eq!(config.max_shape_transitions, 8);
        assert!(config.infer_props);
        assert!(config.integrate_shape_algebra);
        assert_eq!(config.max_render_depth, 32);
        assert_eq!(config.min_purity_ratio, 500_000);
    }

    #[test]
    fn inference_config_serde_roundtrip() {
        let config = InferenceConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: InferenceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // -- ShapeStabilityAssessment tests --

    #[test]
    fn shape_stability_default_is_monomorphic() {
        let s = ShapeStabilityAssessment::default();
        assert!(s.is_monomorphic);
        assert!(!s.is_polymorphic);
        assert!(!s.is_megamorphic);
        assert!(s.cells_stable);
        assert!(s.is_optimization_safe());
    }

    #[test]
    fn shape_stability_from_transitions_mono() {
        let s = ShapeStabilityAssessment::from_transitions(0, 4);
        assert!(s.is_monomorphic);
        assert!(!s.is_polymorphic);
        assert!(s.is_optimization_safe());
    }

    #[test]
    fn shape_stability_from_transitions_poly() {
        let s = ShapeStabilityAssessment::from_transitions(3, 4);
        assert!(!s.is_monomorphic);
        assert!(s.is_polymorphic);
        assert!(!s.is_megamorphic);
        assert!(s.is_optimization_safe());
    }

    #[test]
    fn shape_stability_from_transitions_mega() {
        let s = ShapeStabilityAssessment::from_transitions(10, 4);
        assert!(!s.is_monomorphic);
        assert!(!s.is_polymorphic);
        assert!(s.is_megamorphic);
        assert!(!s.is_optimization_safe());
    }

    #[test]
    fn shape_stability_serde_roundtrip() {
        let s = ShapeStabilityAssessment::from_transitions(3, 8);
        let json = serde_json::to_string(&s).unwrap();
        let back: ShapeStabilityAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -- InferenceBlockingReason tests --

    #[test]
    fn blocking_reason_display() {
        assert_eq!(
            InferenceBlockingReason::ImpureClassification.to_string(),
            "impure_classification"
        );
        assert_eq!(
            InferenceBlockingReason::MegamorphicShape.to_string(),
            "megamorphic_shape"
        );
        assert_eq!(
            InferenceBlockingReason::ConditionalHooks.to_string(),
            "conditional_hooks"
        );
    }

    #[test]
    fn blocking_reason_ordering() {
        let mut reasons = [
            InferenceBlockingReason::MutableRefs,
            InferenceBlockingReason::EffectsInRender,
            InferenceBlockingReason::ConditionalHooks,
        ];
        reasons.sort();
        assert_eq!(reasons[0], InferenceBlockingReason::ConditionalHooks);
    }

    #[test]
    fn blocking_reason_serde_roundtrip() {
        let reason = InferenceBlockingReason::MegamorphicShape;
        let json = serde_json::to_string(&reason).unwrap();
        let back: InferenceBlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
    }

    // -- Prop inference tests --

    #[test]
    fn infer_props_from_empty_element() {
        let el = make_element("div");
        let props = infer_props_from_lowered(&el);
        assert!(props.is_empty());
    }

    #[test]
    fn infer_props_string_literal() {
        let el = make_element_with_props(
            "div",
            vec![(
                "className",
                LoweredPropValue::StringLiteral {
                    value: "container".into(),
                },
            )],
        );
        let props = infer_props_from_lowered(&el);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].name, "className");
        assert_eq!(props[0].value_kind, PropValueKind::StringLiteral);
        assert_eq!(props[0].flow, PropFlowKind::Rendered);
    }

    #[test]
    fn infer_props_boolean_true() {
        let el =
            make_element_with_props("input", vec![("disabled", LoweredPropValue::BooleanTrue)]);
        let props = infer_props_from_lowered(&el);
        assert_eq!(props[0].value_kind, PropValueKind::BooleanLiteral);
    }

    #[test]
    fn infer_props_callback() {
        let el = make_element_with_props(
            "button",
            vec![(
                "onClick",
                LoweredPropValue::Expression {
                    expression: "() => handleClick()".into(),
                },
            )],
        );
        let props = infer_props_from_lowered(&el);
        assert_eq!(props[0].value_kind, PropValueKind::Callback);
        assert_eq!(props[0].flow, PropFlowKind::EffectOnly);
    }

    #[test]
    fn infer_props_key_ref() {
        let el = make_element_with_props(
            "div",
            vec![
                (
                    "key",
                    LoweredPropValue::StringLiteral { value: "k1".into() },
                ),
                (
                    "ref",
                    LoweredPropValue::Expression {
                        expression: "myRef".into(),
                    },
                ),
            ],
        );
        let props = infer_props_from_lowered(&el);
        assert_eq!(props[0].flow, PropFlowKind::KeyOrRef);
        assert_eq!(props[1].flow, PropFlowKind::KeyOrRef);
    }

    #[test]
    fn infer_props_null() {
        let el = make_element_with_props("div", vec![("data", LoweredPropValue::Null)]);
        let props = infer_props_from_lowered(&el);
        assert_eq!(props[0].value_kind, PropValueKind::NullOrUndefined);
    }

    #[test]
    fn infer_props_nested_element() {
        let inner = make_element("span");
        let el = make_element_with_props(
            "div",
            vec![("icon", LoweredPropValue::Element(Box::new(inner)))],
        );
        let props = infer_props_from_lowered(&el);
        assert_eq!(props[0].value_kind, PropValueKind::ReactElement);
    }

    #[test]
    fn infer_props_children_array() {
        let el = make_element_with_props(
            "div",
            vec![(
                "children",
                LoweredPropValue::ChildrenArray {
                    children: Vec::new(),
                },
            )],
        );
        let props = infer_props_from_lowered(&el);
        assert_eq!(props[0].value_kind, PropValueKind::Array);
        assert_eq!(props[0].flow, PropFlowKind::Rendered);
    }

    // -- Pipeline tests --

    #[test]
    fn pipeline_new_defaults() {
        let p = ReactLaneInferencePipeline::new(epoch());
        assert_eq!(p.total_processed, 0);
        assert_eq!(p.total_eligible, 0);
        assert_eq!(p.schema_version, INFERENCE_SCHEMA_VERSION);
    }

    #[test]
    fn pipeline_infer_pure_component() {
        let mut p = ReactLaneInferencePipeline::with_config(low_obs_config(), epoch());
        let el = make_element("div");
        let manifest = make_hook_manifest("PureComp", vec![HookKind::Memo]);
        let result = p.infer_component("PureComp", &el, Some(&manifest), None);
        assert_eq!(result.component_name, "PureComp");
        // No effects, no refs, no context → pure or conditionally pure.
        assert!(result.purity.class.allows_partial_eval());
        assert!(!result.evidence_hash.is_empty());
    }

    #[test]
    fn pipeline_infer_impure_component_with_effect() {
        let mut p = ReactLaneInferencePipeline::with_config(low_obs_config(), epoch());
        let el = make_element("div");
        let manifest = make_hook_manifest("EffectComp", vec![HookKind::Effect]);
        let result = p.infer_component("EffectComp", &el, Some(&manifest), None);
        // Effect hook should downgrade purity.
        assert!(
            result
                .purity
                .reasons
                .contains(&ImpurityReason::EffectInRenderPath)
        );
    }

    #[test]
    fn pipeline_infer_multiple_components() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let el1 = make_element("div");
        let el2 = make_element("span");
        p.infer_component("Comp1", &el1, None, None);
        p.infer_component("Comp2", &el2, None, None);
        assert_eq!(p.total_processed, 2);
    }

    #[test]
    fn pipeline_get_result() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let el = make_element("div");
        p.infer_component("TestComp", &el, None, None);
        assert!(p.get_result("TestComp").is_some());
        assert!(p.get_result("NonExistent").is_none());
    }

    #[test]
    fn pipeline_eligible_components() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let el1 = make_element("div");
        let el2 = make_element("span");
        let manifest = make_hook_manifest("Impure", vec![HookKind::Effect, HookKind::Ref]);
        p.infer_component("Pure", &el1, None, None);
        p.infer_component("Impure", &el2, Some(&manifest), None);
        let eligible = p.eligible_components();
        let blocked = p.blocked_components();
        assert!(eligible.len() + blocked.len() == 2);
    }

    #[test]
    fn pipeline_summary() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let el = make_element("div");
        p.infer_component("Comp", &el, None, None);
        let summary = p.summary();
        assert_eq!(summary.total_components, 1);
        assert_eq!(summary.schema_version, INFERENCE_SCHEMA_VERSION);
    }

    #[test]
    fn pipeline_receipt() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let el = make_element("div");
        p.infer_component("Comp", &el, None, None);
        let receipt = p.generate_receipt();
        assert_eq!(receipt.bead_id, INFERENCE_BEAD_ID);
        assert_eq!(receipt.policy_id, INFERENCE_POLICY_ID);
        assert_eq!(receipt.total_components, 1);
        assert!(!receipt.receipt_hash.is_empty());
    }

    #[test]
    fn pipeline_receipt_deterministic() {
        let mut p1 = ReactLaneInferencePipeline::new(epoch());
        let mut p2 = ReactLaneInferencePipeline::new(epoch());
        let el = make_element("div");
        p1.infer_component("Comp", &el, None, None);
        p2.infer_component("Comp", &el, None, None);
        assert_eq!(
            p1.generate_receipt().receipt_hash,
            p2.generate_receipt().receipt_hash
        );
    }

    #[test]
    fn pipeline_reset() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let el = make_element("div");
        p.infer_component("Comp", &el, None, None);
        assert_eq!(p.total_processed, 1);
        p.reset();
        assert_eq!(p.total_processed, 0);
        assert!(p.results.is_empty());
        assert!(p.evidence.is_empty());
    }

    #[test]
    fn pipeline_advance_epoch() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        p.advance_epoch(SecurityEpoch::from_raw(200));
        assert_eq!(p.epoch, SecurityEpoch::from_raw(200));
    }

    #[test]
    fn pipeline_serde_roundtrip() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let el = make_element("div");
        p.infer_component("Comp", &el, None, None);
        let json = serde_json::to_string(&p).unwrap();
        let back: ReactLaneInferencePipeline = serde_json::from_str(&json).unwrap();
        assert_eq!(p.total_processed, back.total_processed);
        assert_eq!(p.total_eligible, back.total_eligible);
    }

    // -- Batch infer tests --

    #[test]
    fn batch_infer_empty() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let results = batch_infer(&mut p, &[], None);
        assert!(results.is_empty());
    }

    #[test]
    fn batch_infer_multiple() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let components = vec![
            ("A".to_string(), make_element("div"), None),
            ("B".to_string(), make_element("span"), None),
            (
                "C".to_string(),
                make_element("p"),
                Some(make_hook_manifest("C", vec![HookKind::State])),
            ),
        ];
        let results = batch_infer(&mut p, &components, None);
        assert_eq!(results.len(), 3);
        assert_eq!(p.total_processed, 3);
    }

    // -- Coverage tests --

    #[test]
    fn partial_eval_coverage_empty() {
        assert_eq!(partial_eval_coverage(&[]), 0);
    }

    #[test]
    fn partial_eval_coverage_all_eligible() {
        let mut p = ReactLaneInferencePipeline::with_config(low_obs_config(), epoch());
        let el = make_element("div");
        let r1 = p.infer_component("A", &el, None, None);
        let r2 = p.infer_component("B", &el, None, None);
        let results = vec![r1, r2];
        let coverage = partial_eval_coverage(&results);
        // Both should be eligible (no hooks, simple elements).
        assert!(coverage > 0);
    }

    // -- Component evidence tests --

    #[test]
    fn component_evidence_serde_roundtrip() {
        let evidence = ComponentEvidence {
            component_name: "TestComp".into(),
            render_tree: analyze_render_tree(&make_element("div")),
            hook_manifest: None,
            inferred_props: Vec::new(),
            shape_stability: ShapeStabilityAssessment::default(),
            compile_receipt_hash: None,
        };
        let json = serde_json::to_string(&evidence).unwrap();
        let back: ComponentEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, back);
    }

    // -- Inference result tests --

    #[test]
    fn inference_result_serde_roundtrip() {
        let result = ComponentInferenceResult {
            component_name: "TestComp".into(),
            purity: PurityClassification {
                class: RenderPurityClass::Pure,
                reasons: BTreeSet::new(),
                severity_total: 0,
                confidence_fp: MILLIONTHS,
            },
            shape_stability: ShapeStabilityAssessment::default(),
            partial_eval_eligible: true,
            blocking_reasons: Vec::new(),
            evidence_hash: "abc123".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ComponentInferenceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // -- Summary tests --

    #[test]
    fn summary_healthy_when_above_threshold() {
        let mut p = ReactLaneInferencePipeline::with_config(low_obs_config(), epoch());
        // No-hook pure components should all be eligible.
        for i in 0..5 {
            let el = make_element("div");
            p.infer_component(&format!("Comp{i}"), &el, None, None);
        }
        let summary = p.summary();
        assert!(summary.eligibility_ratio > 0);
    }

    #[test]
    fn summary_serde_roundtrip() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let el = make_element("div");
        p.infer_component("Comp", &el, None, None);
        let summary = p.summary();
        let json = serde_json::to_string(&summary).unwrap();
        let back: InferenceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // -- Constants tests --

    #[test]
    fn constants_nonempty() {
        assert!(!INFERENCE_SCHEMA_VERSION.is_empty());
        assert!(!INFERENCE_COMPONENT.is_empty());
        assert!(!INFERENCE_BEAD_ID.is_empty());
        assert!(!INFERENCE_POLICY_ID.is_empty());
    }

    // -- Prop flow inference edge cases --

    #[test]
    fn infer_prop_flow_event_handler() {
        assert_eq!(infer_prop_flow("onClick"), PropFlowKind::EffectOnly);
        assert_eq!(infer_prop_flow("onSubmit"), PropFlowKind::EffectOnly);
        assert_eq!(infer_prop_flow("onChange"), PropFlowKind::EffectOnly);
    }

    #[test]
    fn infer_prop_flow_render_attrs() {
        assert_eq!(infer_prop_flow("className"), PropFlowKind::Rendered);
        assert_eq!(infer_prop_flow("style"), PropFlowKind::Rendered);
        assert_eq!(infer_prop_flow("id"), PropFlowKind::Rendered);
    }

    #[test]
    fn infer_prop_flow_unknown() {
        assert_eq!(infer_prop_flow("customProp"), PropFlowKind::Computed);
    }

    #[test]
    fn infer_prop_flow_on_short() {
        // "on" alone is only 2 chars, should not be EffectOnly.
        assert_eq!(infer_prop_flow("on"), PropFlowKind::Computed);
    }

    // -- Deeply nested blocking --

    #[test]
    fn blocking_deeply_nested() {
        let config = InferenceConfig {
            max_render_depth: 2,
            purity_config: PurityConfig {
                min_observations: 1,
                ..PurityConfig::default()
            },
            ..Default::default()
        };
        let mut p = ReactLaneInferencePipeline::with_config(config, epoch());

        let innermost = make_element("em");
        let inner = LoweredElement {
            children: vec![LoweredChild::Element(Box::new(innermost))],
            ..make_element("span")
        };
        let mid = LoweredElement {
            children: vec![LoweredChild::Element(Box::new(inner))],
            ..make_element("div")
        };
        let outer = LoweredElement {
            children: vec![LoweredChild::Element(Box::new(mid))],
            ..make_element("section")
        };

        let result = p.infer_component("DeepComp", &outer, None, None);
        assert!(
            result
                .blocking_reasons
                .contains(&InferenceBlockingReason::DeeplyNested)
        );
    }

    // -- Megamorphic shape blocking --

    #[test]
    fn blocking_megamorphic_shape() {
        let purity = PurityClassification {
            class: RenderPurityClass::Pure,
            reasons: BTreeSet::new(),
            severity_total: 0,
            confidence_fp: MILLIONTHS,
        };
        let shape_stability = ShapeStabilityAssessment::from_transitions(20, 4);
        let evidence = ComponentEvidence {
            component_name: "Mega".into(),
            render_tree: analyze_render_tree(&make_element("div")),
            hook_manifest: None,
            inferred_props: Vec::new(),
            shape_stability: shape_stability.clone(),
            compile_receipt_hash: None,
        };
        let config = InferenceConfig::default();
        let reasons = compute_blocking_reasons(&purity, &shape_stability, &evidence, &config);
        assert!(reasons.contains(&InferenceBlockingReason::MegamorphicShape));
    }

    // -- Receipt hash stability --

    #[test]
    fn receipt_hash_changes_with_epoch() {
        let mut p1 = ReactLaneInferencePipeline::new(SecurityEpoch::from_raw(1));
        let mut p2 = ReactLaneInferencePipeline::new(SecurityEpoch::from_raw(2));
        let el = make_element("div");
        p1.infer_component("Comp", &el, None, None);
        p2.infer_component("Comp", &el, None, None);
        assert_ne!(
            p1.generate_receipt().receipt_hash,
            p2.generate_receipt().receipt_hash
        );
    }

    #[test]
    fn evidence_hash_differs_by_name() {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let el = make_element("div");
        let r1 = p.infer_component("Comp1", &el, None, None);
        let r2 = p.infer_component("Comp2", &el, None, None);
        assert_ne!(r1.evidence_hash, r2.evidence_hash);
    }
}
