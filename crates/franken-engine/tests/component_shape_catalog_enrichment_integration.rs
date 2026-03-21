#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for `component_shape_catalog`.

use std::collections::BTreeSet;

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::component_shape_catalog::{
    CatalogSummary, ComponentShape, ComponentShapeCatalog, HookProfile, ImpurityReason,
    PropDescriptor, PropFlowKind, PropValueKind, PurityClassification, PurityConfig,
    RenderPurityClass, RenderTreeAnalysis, analyze_render_tree, classify_purity,
};
use frankenengine_engine::hook_effect_contract::{HookKind, HookManifest, HookSlot, HookSlotIndex};
use frankenengine_engine::react_jsx_lowering::{
    CallConvention, ElementType, LoweredChild, LoweredElement, LoweredProps,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dummy_span() -> SourceSpan {
    SourceSpan::new(0, 0, 1, 1, 1, 1)
}

fn make_props(has_spreads: bool) -> LoweredProps {
    LoweredProps {
        entries: vec![],
        has_spreads,
        extracted_key: None,
        extracted_ref: None,
    }
}

fn make_element(tag: &str) -> LoweredElement {
    LoweredElement {
        element_type: ElementType::Intrinsic {
            tag: tag.to_string(),
        },
        props: make_props(false),
        children: vec![],
        call_convention: CallConvention::Classic {
            object: "React".to_string(),
            method: "createElement".to_string(),
        },
        source_location: None,
        is_static_children: false,
        depth: 0,
        span: dummy_span(),
    }
}

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

fn make_pure_shape(name: &str) -> ComponentShape {
    let mut shape = ComponentShape::new(name);
    shape.observation_count = 10;
    shape
}

fn make_impure_shape(name: &str) -> ComponentShape {
    let mut shape = ComponentShape::new(name);
    shape.observation_count = 10;
    shape.hook_profile.effect_hooks = 1;
    shape
}

// ---------------------------------------------------------------------------
// PropFlowKind
// ---------------------------------------------------------------------------

#[test]
fn prop_flow_kind_rendered_affects_render() {
    assert!(PropFlowKind::Rendered.affects_render());
}

#[test]
fn prop_flow_kind_passed_down_affects_render() {
    assert!(PropFlowKind::PassedDown.affects_render());
}

#[test]
fn prop_flow_kind_computed_affects_render() {
    assert!(PropFlowKind::Computed.affects_render());
}

#[test]
fn prop_flow_kind_effect_only_does_not_affect() {
    assert!(!PropFlowKind::EffectOnly.affects_render());
}

#[test]
fn prop_flow_kind_unused_does_not_affect() {
    assert!(!PropFlowKind::Unused.affects_render());
}

#[test]
fn prop_flow_kind_display_distinct() {
    let kinds = [
        PropFlowKind::Rendered,
        PropFlowKind::PassedDown,
        PropFlowKind::Computed,
        PropFlowKind::KeyOrRef,
        PropFlowKind::EffectOnly,
        PropFlowKind::Spread,
        PropFlowKind::Unused,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), kinds.len());
}

#[test]
fn prop_flow_kind_serde_roundtrip() {
    let kinds = [
        PropFlowKind::Rendered,
        PropFlowKind::PassedDown,
        PropFlowKind::Computed,
        PropFlowKind::KeyOrRef,
        PropFlowKind::EffectOnly,
        PropFlowKind::Spread,
        PropFlowKind::Unused,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: PropFlowKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// PropValueKind
// ---------------------------------------------------------------------------

#[test]
fn prop_value_kind_immutable_primitives() {
    assert!(PropValueKind::StringLiteral.is_immutable());
    assert!(PropValueKind::NumberLiteral.is_immutable());
    assert!(PropValueKind::BooleanLiteral.is_immutable());
    assert!(PropValueKind::NullOrUndefined.is_immutable());
}

#[test]
fn prop_value_kind_mutable_types() {
    assert!(!PropValueKind::Callback.is_immutable());
    assert!(!PropValueKind::ReactElement.is_immutable());
    assert!(!PropValueKind::Array.is_immutable());
    assert!(!PropValueKind::Object.is_immutable());
    assert!(!PropValueKind::Unknown.is_immutable());
}

#[test]
fn prop_value_kind_display_distinct() {
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
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), kinds.len());
}

#[test]
fn prop_value_kind_serde_roundtrip() {
    for k in &[
        PropValueKind::StringLiteral,
        PropValueKind::Callback,
        PropValueKind::Unknown,
    ] {
        let json = serde_json::to_string(k).unwrap();
        let back: PropValueKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// PropDescriptor
// ---------------------------------------------------------------------------

#[test]
fn prop_descriptor_new_defaults() {
    let p = PropDescriptor::new(
        "title",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    );
    assert_eq!(p.name, "title");
    assert!(!p.is_required);
    assert_eq!(p.observation_count, 1);
}

#[test]
fn prop_descriptor_render_relevant() {
    let p = PropDescriptor::new("x", PropValueKind::NumberLiteral, PropFlowKind::Rendered);
    assert!(p.is_render_relevant());
}

#[test]
fn prop_descriptor_not_render_relevant_effect_only() {
    let p = PropDescriptor::new("cb", PropValueKind::Callback, PropFlowKind::EffectOnly);
    assert!(!p.is_render_relevant());
}

#[test]
fn prop_descriptor_serde_roundtrip() {
    let p = PropDescriptor::new(
        "label",
        PropValueKind::StringLiteral,
        PropFlowKind::PassedDown,
    );
    let json = serde_json::to_string(&p).unwrap();
    let back: PropDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// RenderPurityClass
// ---------------------------------------------------------------------------

#[test]
fn render_purity_class_pure_allows_partial_eval() {
    assert!(RenderPurityClass::Pure.allows_partial_eval());
}

#[test]
fn render_purity_class_conditionally_pure_allows_partial_eval() {
    assert!(RenderPurityClass::ConditionallyPure.allows_partial_eval());
}

#[test]
fn render_purity_class_impure_disallows_partial_eval() {
    assert!(!RenderPurityClass::Impure.allows_partial_eval());
}

#[test]
fn render_purity_class_unknown_disallows_partial_eval() {
    assert!(!RenderPurityClass::Unknown.allows_partial_eval());
}

#[test]
fn render_purity_class_display_distinct() {
    let classes = [
        RenderPurityClass::Pure,
        RenderPurityClass::ConditionallyPure,
        RenderPurityClass::Impure,
        RenderPurityClass::Unknown,
    ];
    let displays: BTreeSet<String> = classes.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), classes.len());
}

#[test]
fn render_purity_class_serde_roundtrip() {
    for c in &[
        RenderPurityClass::Pure,
        RenderPurityClass::Impure,
        RenderPurityClass::Unknown,
    ] {
        let json = serde_json::to_string(c).unwrap();
        let back: RenderPurityClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ---------------------------------------------------------------------------
// ImpurityReason
// ---------------------------------------------------------------------------

#[test]
fn impurity_reason_display_distinct() {
    let reasons = [
        ImpurityReason::EffectInRenderPath,
        ImpurityReason::ExternalStateRead,
        ImpurityReason::MutableRef,
        ImpurityReason::SpreadProps,
        ImpurityReason::DynamicElementType,
        ImpurityReason::ContextDependency,
        ImpurityReason::ConditionalHooks,
        ImpurityReason::NonDeterministic,
        ImpurityReason::InsufficientEvidence,
    ];
    let displays: BTreeSet<String> = reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), reasons.len());
}

#[test]
fn impurity_reason_severity_weights_positive() {
    let reasons = [
        ImpurityReason::EffectInRenderPath,
        ImpurityReason::ExternalStateRead,
        ImpurityReason::MutableRef,
        ImpurityReason::SpreadProps,
        ImpurityReason::DynamicElementType,
        ImpurityReason::ContextDependency,
        ImpurityReason::ConditionalHooks,
        ImpurityReason::NonDeterministic,
        ImpurityReason::InsufficientEvidence,
    ];
    for r in &reasons {
        assert!(
            r.severity_weight() > 0,
            "severity_weight for {r} should be > 0"
        );
    }
}

#[test]
fn impurity_reason_non_deterministic_has_highest_weight() {
    let max = ImpurityReason::NonDeterministic.severity_weight();
    let others = [
        ImpurityReason::EffectInRenderPath,
        ImpurityReason::ExternalStateRead,
        ImpurityReason::MutableRef,
        ImpurityReason::SpreadProps,
        ImpurityReason::DynamicElementType,
        ImpurityReason::ContextDependency,
        ImpurityReason::InsufficientEvidence,
    ];
    for r in &others {
        assert!(r.severity_weight() <= max);
    }
}

// ---------------------------------------------------------------------------
// HookProfile
// ---------------------------------------------------------------------------

#[test]
fn hook_profile_default_is_empty() {
    let p = HookProfile::default();
    assert_eq!(p.total_hooks, 0);
    assert!(!p.has_effects());
    assert!(p.is_stateless());
    assert!(!p.reads_context());
    assert!(!p.uses_refs());
}

#[test]
fn hook_profile_from_manifest_counts() {
    let manifest = make_manifest(&[HookKind::State, HookKind::Effect, HookKind::Context]);
    let p = HookProfile::from_manifest(&manifest);
    assert_eq!(p.total_hooks, 3);
    assert_eq!(p.state_hooks, 1);
    assert_eq!(p.effect_hooks, 1);
    assert_eq!(p.context_hooks, 1);
    assert!(p.has_effects());
    assert!(!p.is_stateless());
    assert!(p.reads_context());
}

#[test]
fn hook_profile_serde_roundtrip() {
    let p = HookProfile::from_manifest(&make_manifest(&[HookKind::Memo, HookKind::Ref]));
    let json = serde_json::to_string(&p).unwrap();
    let back: HookProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// ComponentShape
// ---------------------------------------------------------------------------

#[test]
fn component_shape_new_defaults() {
    let shape = ComponentShape::new("MyComp");
    assert_eq!(shape.component_name, "MyComp");
    assert_eq!(shape.prop_count(), 0);
    assert_eq!(shape.render_purity, RenderPurityClass::Unknown);
    assert_eq!(shape.observation_count, 0);
    assert!(!shape.is_high_arity());
    assert!(!shape.is_deeply_nested());
}

#[test]
fn component_shape_add_prop_increments() {
    let mut shape = ComponentShape::new("C");
    shape.add_prop(PropDescriptor::new(
        "a",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    assert_eq!(shape.prop_count(), 1);
    shape.add_prop(PropDescriptor::new(
        "b",
        PropValueKind::NumberLiteral,
        PropFlowKind::Computed,
    ));
    assert_eq!(shape.prop_count(), 2);
}

#[test]
fn component_shape_add_prop_deduplicates() {
    let mut shape = ComponentShape::new("C");
    shape.add_prop(PropDescriptor::new(
        "a",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "a",
        PropValueKind::NumberLiteral,
        PropFlowKind::Rendered,
    ));
    assert_eq!(shape.prop_count(), 1);
    // Second add updates kind and increments observation
    assert_eq!(shape.props[0].value_kind, PropValueKind::NumberLiteral);
    assert_eq!(shape.props[0].observation_count, 2);
}

#[test]
fn component_shape_render_relevant_prop_count() {
    let mut shape = ComponentShape::new("C");
    shape.add_prop(PropDescriptor::new(
        "a",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "b",
        PropValueKind::Callback,
        PropFlowKind::EffectOnly,
    ));
    assert_eq!(shape.render_relevant_prop_count(), 1);
}

#[test]
fn component_shape_props_by_flow() {
    let mut shape = ComponentShape::new("C");
    shape.add_prop(PropDescriptor::new(
        "a",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "b",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "c",
        PropValueKind::Callback,
        PropFlowKind::EffectOnly,
    ));
    assert_eq!(shape.props_by_flow(PropFlowKind::Rendered), 2);
    assert_eq!(shape.props_by_flow(PropFlowKind::EffectOnly), 1);
    assert_eq!(shape.props_by_flow(PropFlowKind::Unused), 0);
}

#[test]
fn component_shape_display() {
    let shape = ComponentShape::new("Widget");
    let display = format!("{shape}");
    assert!(display.contains("Widget"));
    assert!(display.contains("ComponentShape"));
}

#[test]
fn component_shape_serde_roundtrip() {
    let shape = make_pure_shape("TestC");
    let json = serde_json::to_string(&shape).unwrap();
    let back: ComponentShape = serde_json::from_str(&json).unwrap();
    assert_eq!(shape, back);
}

#[test]
fn component_shape_compute_evidence_hash_deterministic() {
    let mut s1 = make_pure_shape("A");
    let mut s2 = make_pure_shape("A");
    s1.compute_evidence_hash();
    s2.compute_evidence_hash();
    assert_eq!(s1.evidence_hash, s2.evidence_hash);
    assert!(!s1.evidence_hash.is_empty());
}

#[test]
fn component_shape_partial_eval_eligible_pure_no_spread() {
    let mut shape = make_pure_shape("PureComp");
    shape.render_purity = RenderPurityClass::Pure;
    shape.has_spread_props = false;
    assert!(shape.is_partial_eval_eligible());
}

#[test]
fn component_shape_partial_eval_not_eligible_spread() {
    let mut shape = make_pure_shape("SpreadComp");
    shape.render_purity = RenderPurityClass::Pure;
    shape.has_spread_props = true;
    assert!(!shape.is_partial_eval_eligible());
}

// ---------------------------------------------------------------------------
// classify_purity
// ---------------------------------------------------------------------------

#[test]
fn classify_purity_pure_shape() {
    let shape = make_pure_shape("PureComp");
    let result = classify_purity(&shape, &PurityConfig::default());
    assert_eq!(result.class, RenderPurityClass::Pure);
    assert!(result.reasons.is_empty());
}

#[test]
fn classify_purity_impure_due_to_effects() {
    let shape = make_impure_shape("EffectComp");
    let result = classify_purity(&shape, &PurityConfig::default());
    assert!(result.reasons.contains(&ImpurityReason::EffectInRenderPath));
}

#[test]
fn classify_purity_insufficient_evidence() {
    let shape = ComponentShape::new("TooNew");
    let result = classify_purity(&shape, &PurityConfig::default());
    assert_eq!(result.class, RenderPurityClass::Unknown);
    assert!(
        result
            .reasons
            .contains(&ImpurityReason::InsufficientEvidence)
    );
}

#[test]
fn classify_purity_conditional_hooks_is_impure() {
    let mut shape = make_pure_shape("CondHooks");
    shape.hook_profile.has_conditional_hooks = true;
    let result = classify_purity(&shape, &PurityConfig::default());
    assert_eq!(result.class, RenderPurityClass::Impure);
}

#[test]
fn classify_purity_serde_roundtrip() {
    let shape = make_pure_shape("X");
    let result = classify_purity(&shape, &PurityConfig::default());
    let json = serde_json::to_string(&result).unwrap();
    let back: PurityClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// PurityConfig
// ---------------------------------------------------------------------------

#[test]
fn purity_config_default_sensible() {
    let c = PurityConfig::default();
    assert!(c.min_observations > 0);
    assert!(c.context_downgrades_purity);
    assert!(c.spread_downgrades_purity);
    assert!(c.max_conditional_severity > 0);
}

#[test]
fn purity_config_serde_roundtrip() {
    let c = PurityConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: PurityConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// analyze_render_tree
// ---------------------------------------------------------------------------

#[test]
fn analyze_render_tree_single_intrinsic() {
    let el = make_element("div");
    let analysis = analyze_render_tree(&el);
    assert_eq!(analysis.total_elements, 1);
    assert_eq!(analysis.intrinsic_count, 1);
    assert!(analysis.intrinsic_tags.contains("div"));
}

#[test]
fn analyze_render_tree_with_children() {
    let mut parent = make_element("div");
    parent
        .children
        .push(LoweredChild::Element(Box::new(make_element("span"))));
    parent
        .children
        .push(LoweredChild::Element(Box::new(make_element("p"))));
    let analysis = analyze_render_tree(&parent);
    assert_eq!(analysis.total_elements, 3);
    assert_eq!(analysis.max_depth, 1);
}

#[test]
fn analyze_render_tree_serde_roundtrip() {
    let el = make_element("section");
    let analysis = analyze_render_tree(&el);
    let json = serde_json::to_string(&analysis).unwrap();
    let back: RenderTreeAnalysis = serde_json::from_str(&json).unwrap();
    assert_eq!(analysis, back);
}

// ---------------------------------------------------------------------------
// ComponentShapeCatalog
// ---------------------------------------------------------------------------

#[test]
fn catalog_new_is_empty() {
    let catalog = ComponentShapeCatalog::new();
    assert_eq!(catalog.component_count(), 0);
    assert!(catalog.components.is_empty());
}

#[test]
fn catalog_register_and_retrieve() {
    let mut catalog = ComponentShapeCatalog::new();
    catalog.register(make_pure_shape("Button"));
    assert_eq!(catalog.component_count(), 1);
    assert!(catalog.get("Button").is_some());
}

#[test]
fn catalog_summary() {
    let mut catalog = ComponentShapeCatalog::new();
    let mut pure_shape = make_pure_shape("Pure");
    pure_shape.render_purity = RenderPurityClass::Pure;
    catalog.register(pure_shape);

    let mut impure_shape = make_impure_shape("Impure");
    impure_shape.render_purity = RenderPurityClass::Impure;
    catalog.register(impure_shape);

    let summary = catalog.summary();
    assert_eq!(summary.total_components, 2);
}

#[test]
fn catalog_summary_serde_roundtrip() {
    let mut catalog = ComponentShapeCatalog::new();
    catalog.register(make_pure_shape("A"));
    let summary = catalog.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: CatalogSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}
