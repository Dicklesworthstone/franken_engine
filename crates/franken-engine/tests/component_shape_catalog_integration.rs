//! Integration tests for the `component_shape_catalog` module (bd-1lsy.7.9.1).
//!
//! Covers PropFlowKind, PropValueKind, PropDescriptor, ComponentShape, HookProfile,
//! RenderPurityClass, ImpurityReason, PurityConfig, purity classification,
//! RenderTreeAnalysis, ComponentShapeCatalog, CatalogSummary, CatalogReceipt,
//! serde roundtrips, determinism, boundary cases, and end-to-end pipelines.

use std::collections::BTreeSet;

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::component_shape_catalog::{
    CatalogReceipt, CatalogSummary, ComponentShape, ComponentShapeCatalog, HookProfile,
    ImpurityReason, PropDescriptor, PropFlowKind, PropValueKind, PurityClassification,
    PurityConfig, RenderPurityClass, RenderTreeAnalysis, analyze_render_tree, classify_purity,
};
use frankenengine_engine::hook_effect_contract::{HookKind, HookManifest, HookSlot, HookSlotIndex};
use frankenengine_engine::react_jsx_lowering::{
    CallConvention, ElementType, LoweredChild, LoweredElement, LoweredPropValue, LoweredProps,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

fn dummy_span() -> SourceSpan {
    SourceSpan::new(0, 0, 1, 1, 1, 1)
}

fn make_lowered_props(has_spreads: bool) -> LoweredProps {
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
        props: make_lowered_props(false),
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

fn make_component_element(name: &str) -> LoweredElement {
    let mut el = make_element("div");
    el.element_type = ElementType::Component {
        name: name.to_string(),
    };
    el
}

fn make_fragment_element() -> LoweredElement {
    let mut el = make_element("div");
    el.element_type = ElementType::Fragment;
    el
}

/// Build a pure shape with enough observations to be classified.
fn make_pure_shape(name: &str) -> ComponentShape {
    let mut shape = ComponentShape::new(name);
    shape.observation_count = 10;
    shape
}

/// Build an impure shape (has effect hooks).
fn make_impure_shape(name: &str) -> ComponentShape {
    let mut shape = ComponentShape::new(name);
    shape.observation_count = 10;
    shape.hook_profile.effect_hooks = 1;
    shape
}

// ---------------------------------------------------------------------------
// 1. PropFlowKind tests
// ---------------------------------------------------------------------------

#[test]
fn prop_flow_kind_affects_render_all_variants() {
    assert!(PropFlowKind::Rendered.affects_render());
    assert!(PropFlowKind::PassedDown.affects_render());
    assert!(PropFlowKind::Computed.affects_render());
    assert!(!PropFlowKind::KeyOrRef.affects_render());
    assert!(!PropFlowKind::EffectOnly.affects_render());
    assert!(!PropFlowKind::Spread.affects_render());
    assert!(!PropFlowKind::Unused.affects_render());
}

#[test]
fn prop_flow_kind_as_str_all_variants() {
    assert_eq!(PropFlowKind::Rendered.as_str(), "rendered");
    assert_eq!(PropFlowKind::PassedDown.as_str(), "passed_down");
    assert_eq!(PropFlowKind::Computed.as_str(), "computed");
    assert_eq!(PropFlowKind::KeyOrRef.as_str(), "key_or_ref");
    assert_eq!(PropFlowKind::EffectOnly.as_str(), "effect_only");
    assert_eq!(PropFlowKind::Spread.as_str(), "spread");
    assert_eq!(PropFlowKind::Unused.as_str(), "unused");
}

#[test]
fn prop_flow_kind_display_matches_as_str() {
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
        assert_eq!(format!("{flow}"), flow.as_str());
    }
}

// ---------------------------------------------------------------------------
// 2. PropValueKind tests
// ---------------------------------------------------------------------------

#[test]
fn prop_value_kind_as_str_all_variants() {
    assert_eq!(PropValueKind::StringLiteral.as_str(), "string");
    assert_eq!(PropValueKind::NumberLiteral.as_str(), "number");
    assert_eq!(PropValueKind::BooleanLiteral.as_str(), "boolean");
    assert_eq!(PropValueKind::NullOrUndefined.as_str(), "null_or_undefined");
    assert_eq!(PropValueKind::Callback.as_str(), "callback");
    assert_eq!(PropValueKind::ReactElement.as_str(), "react_element");
    assert_eq!(PropValueKind::Array.as_str(), "array");
    assert_eq!(PropValueKind::Object.as_str(), "object");
    assert_eq!(PropValueKind::Unknown.as_str(), "unknown");
}

#[test]
fn prop_value_kind_is_immutable() {
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
fn prop_value_kind_display_matches_as_str() {
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
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

// ---------------------------------------------------------------------------
// 3. PropDescriptor construction
// ---------------------------------------------------------------------------

#[test]
fn prop_descriptor_new_defaults() {
    let prop = PropDescriptor::new(
        "className",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    );
    assert_eq!(prop.name, "className");
    assert_eq!(prop.value_kind, PropValueKind::StringLiteral);
    assert_eq!(prop.flow, PropFlowKind::Rendered);
    assert!(!prop.is_required);
    assert_eq!(prop.observation_count, 1);
}

#[test]
fn prop_descriptor_render_relevance() {
    let rendered = PropDescriptor::new(
        "title",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    );
    assert!(rendered.is_render_relevant());

    let effect = PropDescriptor::new("onMount", PropValueKind::Callback, PropFlowKind::EffectOnly);
    assert!(!effect.is_render_relevant());

    let key = PropDescriptor::new("key", PropValueKind::StringLiteral, PropFlowKind::KeyOrRef);
    assert!(!key.is_render_relevant());
}

#[test]
fn prop_descriptor_required_field() {
    let mut prop = PropDescriptor::new("id", PropValueKind::StringLiteral, PropFlowKind::Rendered);
    assert!(!prop.is_required);
    prop.is_required = true;
    assert!(prop.is_required);
}

// ---------------------------------------------------------------------------
// 4. ComponentShape construction and analysis
// ---------------------------------------------------------------------------

#[test]
fn component_shape_new_defaults() {
    let shape = ComponentShape::new("MyComponent");
    assert_eq!(shape.component_name, "MyComponent");
    assert_eq!(shape.prop_count(), 0);
    assert_eq!(shape.render_purity, RenderPurityClass::Unknown);
    assert!(shape.impurity_reasons.is_empty());
    assert!(shape.children_element_types.is_empty());
    assert_eq!(shape.max_render_depth, 0);
    assert!(!shape.has_spread_props);
    assert!(!shape.has_dynamic_children);
    assert_eq!(shape.observation_count, 0);
    assert!(shape.evidence_hash.is_empty());
}

#[test]
fn component_shape_add_prop_increments_count() {
    let mut shape = ComponentShape::new("Card");
    shape.add_prop(PropDescriptor::new(
        "title",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "subtitle",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    assert_eq!(shape.prop_count(), 2);
}

#[test]
fn component_shape_add_prop_dedup_updates_observation() {
    let mut shape = ComponentShape::new("Button");
    shape.add_prop(PropDescriptor::new(
        "label",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "label",
        PropValueKind::Unknown,
        PropFlowKind::Rendered,
    ));
    assert_eq!(shape.prop_count(), 1);
    // Keeps the non-Unknown kind.
    assert_eq!(shape.props[0].value_kind, PropValueKind::StringLiteral);
    assert_eq!(shape.props[0].observation_count, 2);
}

#[test]
fn component_shape_add_prop_dedup_upgrades_unknown_kind() {
    let mut shape = ComponentShape::new("Input");
    shape.add_prop(PropDescriptor::new(
        "value",
        PropValueKind::Unknown,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "value",
        PropValueKind::NumberLiteral,
        PropFlowKind::Rendered,
    ));
    assert_eq!(shape.props[0].value_kind, PropValueKind::NumberLiteral);
}

#[test]
fn component_shape_high_arity_threshold() {
    let mut shape = ComponentShape::new("Form");
    for i in 0..11 {
        shape.add_prop(PropDescriptor::new(
            &format!("field{i}"),
            PropValueKind::Unknown,
            PropFlowKind::Rendered,
        ));
    }
    assert!(!shape.is_high_arity()); // 11 < 12

    shape.add_prop(PropDescriptor::new(
        "field11",
        PropValueKind::Unknown,
        PropFlowKind::Rendered,
    ));
    assert!(shape.is_high_arity()); // 12 >= 12
}

#[test]
fn component_shape_deeply_nested_threshold() {
    let mut shape = ComponentShape::new("Tree");
    shape.max_render_depth = 7;
    assert!(!shape.is_deeply_nested()); // 7 < 8

    shape.max_render_depth = 8;
    assert!(shape.is_deeply_nested()); // 8 >= 8
}

#[test]
fn component_shape_partial_eval_eligibility() {
    let mut shape = ComponentShape::new("PureComp");
    shape.render_purity = RenderPurityClass::Pure;
    shape.has_spread_props = false;
    assert!(shape.is_partial_eval_eligible());

    // Spread disqualifies.
    shape.has_spread_props = true;
    assert!(!shape.is_partial_eval_eligible());

    // Impure disqualifies.
    shape.has_spread_props = false;
    shape.render_purity = RenderPurityClass::Impure;
    assert!(!shape.is_partial_eval_eligible());

    // ConditionallyPure without spread qualifies.
    shape.render_purity = RenderPurityClass::ConditionallyPure;
    assert!(shape.is_partial_eval_eligible());

    // Unknown does not qualify.
    shape.render_purity = RenderPurityClass::Unknown;
    assert!(!shape.is_partial_eval_eligible());
}

#[test]
fn component_shape_render_relevant_prop_count() {
    let mut shape = ComponentShape::new("Mixed");
    shape.add_prop(PropDescriptor::new(
        "title",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "data",
        PropValueKind::Object,
        PropFlowKind::PassedDown,
    ));
    shape.add_prop(PropDescriptor::new(
        "onClick",
        PropValueKind::Callback,
        PropFlowKind::EffectOnly,
    ));
    shape.add_prop(PropDescriptor::new(
        "debug",
        PropValueKind::BooleanLiteral,
        PropFlowKind::Unused,
    ));
    assert_eq!(shape.render_relevant_prop_count(), 2); // Rendered + PassedDown
}

#[test]
fn component_shape_props_by_flow_counts() {
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
    shape.add_prop(PropDescriptor::new(
        "d",
        PropValueKind::Unknown,
        PropFlowKind::KeyOrRef,
    ));
    assert_eq!(shape.props_by_flow(PropFlowKind::Rendered), 2);
    assert_eq!(shape.props_by_flow(PropFlowKind::Unused), 1);
    assert_eq!(shape.props_by_flow(PropFlowKind::KeyOrRef), 1);
    assert_eq!(shape.props_by_flow(PropFlowKind::Spread), 0);
}

#[test]
fn component_shape_evidence_hash_changes_on_mutation() {
    let mut shape = ComponentShape::new("HashTest");
    shape.observation_count = 5;
    shape.compute_evidence_hash();
    let hash1 = shape.evidence_hash.clone();
    assert!(!hash1.is_empty());

    shape.observation_count = 10;
    shape.compute_evidence_hash();
    assert_ne!(shape.evidence_hash, hash1);
}

#[test]
fn component_shape_display_format() {
    let mut shape = ComponentShape::new("Button");
    shape.hook_profile.total_hooks = 3;
    shape.render_purity = RenderPurityClass::Pure;
    shape.add_prop(PropDescriptor::new(
        "label",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    let display = format!("{shape}");
    assert!(display.contains("Button"));
    assert!(display.contains("props=1"));
    assert!(display.contains("hooks=3"));
    assert!(display.contains("purity=pure"));
}

// ---------------------------------------------------------------------------
// 5. Render purity classification
// ---------------------------------------------------------------------------

#[test]
fn classify_purity_pure_component() {
    let mut shape = ComponentShape::new("Pure");
    shape.observation_count = 10;
    let config = PurityConfig::default();
    let result = classify_purity(&shape, &config);
    assert_eq!(result.class, RenderPurityClass::Pure);
    assert!(result.reasons.is_empty());
    assert_eq!(result.severity_total, 0);
    assert!(result.confidence_fp > 0);
}

#[test]
fn classify_purity_insufficient_evidence() {
    let shape = ComponentShape::new("New");
    let config = PurityConfig::default();
    let result = classify_purity(&shape, &config);
    assert_eq!(result.class, RenderPurityClass::Unknown);
    assert!(
        result
            .reasons
            .contains(&ImpurityReason::InsufficientEvidence)
    );
    assert_eq!(result.confidence_fp, 0);
}

#[test]
fn classify_purity_effects_produce_impure() {
    let mut shape = ComponentShape::new("WithEffect");
    shape.observation_count = 10;
    shape.hook_profile.effect_hooks = 1;
    let config = PurityConfig::default();
    let result = classify_purity(&shape, &config);
    assert_eq!(result.class, RenderPurityClass::Impure);
    assert!(result.reasons.contains(&ImpurityReason::EffectInRenderPath));
}

#[test]
fn classify_purity_context_produces_conditionally_pure() {
    let mut shape = ComponentShape::new("WithCtx");
    shape.observation_count = 10;
    shape.hook_profile.context_hooks = 1;
    let config = PurityConfig::default();
    let result = classify_purity(&shape, &config);
    assert_eq!(result.class, RenderPurityClass::ConditionallyPure);
    assert!(result.reasons.contains(&ImpurityReason::ContextDependency));
}

#[test]
fn classify_purity_spread_produces_conditionally_pure() {
    let mut shape = ComponentShape::new("WithSpread");
    shape.observation_count = 10;
    shape.has_spread_props = true;
    let config = PurityConfig::default();
    let result = classify_purity(&shape, &config);
    assert_eq!(result.class, RenderPurityClass::ConditionallyPure);
    assert!(result.reasons.contains(&ImpurityReason::SpreadProps));
}

#[test]
fn classify_purity_conditional_hooks_is_hard_impure() {
    let mut shape = ComponentShape::new("BadHooks");
    shape.observation_count = 10;
    shape.hook_profile.has_conditional_hooks = true;
    let config = PurityConfig::default();
    let result = classify_purity(&shape, &config);
    assert_eq!(result.class, RenderPurityClass::Impure);
    assert!(result.reasons.contains(&ImpurityReason::ConditionalHooks));
}

#[test]
fn classify_purity_refs_below_severity_threshold() {
    let mut shape = ComponentShape::new("WithRef");
    shape.observation_count = 10;
    shape.hook_profile.ref_hooks = 1;
    let config = PurityConfig {
        max_conditional_severity: 800_000,
        ..Default::default()
    };
    let result = classify_purity(&shape, &config);
    // MutableRef weight = 700_000 < 800_000
    assert_eq!(result.class, RenderPurityClass::ConditionallyPure);
    assert!(result.reasons.contains(&ImpurityReason::MutableRef));
}

#[test]
fn classify_purity_confidence_increases_with_observations() {
    let config = PurityConfig::default();

    let mut low = ComponentShape::new("Low");
    low.observation_count = 5;
    let r_low = classify_purity(&low, &config);

    let mut high = ComponentShape::new("High");
    high.observation_count = 80;
    let r_high = classify_purity(&high, &config);

    assert!(r_high.confidence_fp > r_low.confidence_fp);
}

#[test]
fn classify_purity_custom_min_observations() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut shape = ComponentShape::new("Quick");
    shape.observation_count = 1;
    let result = classify_purity(&shape, &config);
    // 1 observation meets the min_observations=1 threshold.
    assert_ne!(result.class, RenderPurityClass::Unknown);
}

// ---------------------------------------------------------------------------
// 6. HookProfile from manifest
// ---------------------------------------------------------------------------

#[test]
fn hook_profile_from_empty_manifest() {
    let manifest = make_manifest(&[]);
    let profile = HookProfile::from_manifest(&manifest);
    assert_eq!(profile.total_hooks, 0);
    assert!(!profile.has_effects());
    assert!(profile.is_stateless());
    assert!(!profile.reads_context());
    assert!(!profile.uses_refs());
}

#[test]
fn hook_profile_from_mixed_manifest() {
    let manifest = make_manifest(&[
        HookKind::State,
        HookKind::Reducer,
        HookKind::Effect,
        HookKind::LayoutEffect,
        HookKind::InsertionEffect,
        HookKind::Memo,
        HookKind::DeferredValue,
        HookKind::Ref,
        HookKind::ImperativeHandle,
        HookKind::Context,
        HookKind::Callback,
        HookKind::DebugValue,
    ]);
    let profile = HookProfile::from_manifest(&manifest);
    assert_eq!(profile.total_hooks, 12);
    assert_eq!(profile.state_hooks, 2); // State + Reducer
    assert_eq!(profile.effect_hooks, 3); // Effect + LayoutEffect + InsertionEffect
    assert_eq!(profile.memo_hooks, 2); // Memo + DeferredValue
    assert_eq!(profile.ref_hooks, 2); // Ref + ImperativeHandle
    assert_eq!(profile.context_hooks, 1);
    assert_eq!(profile.callback_hooks, 1);
    assert_eq!(profile.other_hooks, 1); // DebugValue
    assert!(profile.has_effects());
    assert!(!profile.is_stateless());
    assert!(profile.reads_context());
    assert!(profile.uses_refs());
}

// ---------------------------------------------------------------------------
// 7. RenderPurityClass and ImpurityReason
// ---------------------------------------------------------------------------

#[test]
fn render_purity_class_allows_partial_eval() {
    assert!(RenderPurityClass::Pure.allows_partial_eval());
    assert!(RenderPurityClass::ConditionallyPure.allows_partial_eval());
    assert!(!RenderPurityClass::Impure.allows_partial_eval());
    assert!(!RenderPurityClass::Unknown.allows_partial_eval());
}

#[test]
fn render_purity_class_as_str_and_display() {
    assert_eq!(RenderPurityClass::Pure.as_str(), "pure");
    assert_eq!(
        RenderPurityClass::ConditionallyPure.as_str(),
        "conditionally_pure"
    );
    assert_eq!(RenderPurityClass::Impure.as_str(), "impure");
    assert_eq!(RenderPurityClass::Unknown.as_str(), "unknown");
    for class in [
        RenderPurityClass::Pure,
        RenderPurityClass::ConditionallyPure,
        RenderPurityClass::Impure,
        RenderPurityClass::Unknown,
    ] {
        assert_eq!(format!("{class}"), class.as_str());
    }
}

#[test]
fn impurity_reason_severity_weight_ordering() {
    assert!(
        ImpurityReason::NonDeterministic.severity_weight()
            > ImpurityReason::ConditionalHooks.severity_weight()
    );
    assert!(
        ImpurityReason::ConditionalHooks.severity_weight()
            > ImpurityReason::EffectInRenderPath.severity_weight()
    );
    assert!(
        ImpurityReason::EffectInRenderPath.severity_weight()
            > ImpurityReason::ExternalStateRead.severity_weight()
    );
    assert!(
        ImpurityReason::InsufficientEvidence.severity_weight()
            < ImpurityReason::SpreadProps.severity_weight()
    );
}

#[test]
fn impurity_reason_as_str_all_variants() {
    assert_eq!(
        ImpurityReason::EffectInRenderPath.as_str(),
        "effect_in_render_path"
    );
    assert_eq!(
        ImpurityReason::ExternalStateRead.as_str(),
        "external_state_read"
    );
    assert_eq!(ImpurityReason::MutableRef.as_str(), "mutable_ref");
    assert_eq!(ImpurityReason::SpreadProps.as_str(), "spread_props");
    assert_eq!(
        ImpurityReason::DynamicElementType.as_str(),
        "dynamic_element_type"
    );
    assert_eq!(
        ImpurityReason::ContextDependency.as_str(),
        "context_dependency"
    );
    assert_eq!(
        ImpurityReason::ConditionalHooks.as_str(),
        "conditional_hooks"
    );
    assert_eq!(
        ImpurityReason::NonDeterministic.as_str(),
        "non_deterministic"
    );
    assert_eq!(
        ImpurityReason::InsufficientEvidence.as_str(),
        "insufficient_evidence"
    );
}

// ---------------------------------------------------------------------------
// 8. RenderTreeAnalysis via analyze_render_tree
// ---------------------------------------------------------------------------

#[test]
fn render_tree_analysis_single_intrinsic() {
    let el = make_element("div");
    let analysis = analyze_render_tree(&el);
    assert_eq!(analysis.total_elements, 1);
    assert_eq!(analysis.intrinsic_count, 1);
    assert_eq!(analysis.component_count, 0);
    assert_eq!(analysis.fragment_count, 0);
    assert_eq!(analysis.max_depth, 0);
    assert!(analysis.intrinsic_tags.contains("div"));
    assert!(analysis.is_simple());
    assert!(!analysis.has_component_children());
}

#[test]
fn render_tree_analysis_nested_elements() {
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
    let mut root = make_fragment_element();
    root.children
        .push(LoweredChild::Element(Box::new(make_element("p"))));
    root.children
        .push(LoweredChild::Element(Box::new(make_element("span"))));
    let analysis = analyze_render_tree(&root);
    assert_eq!(analysis.fragment_count, 1);
    assert_eq!(analysis.intrinsic_count, 2);
    assert_eq!(analysis.total_elements, 3);
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
        value: "key-1".to_string(),
    });
    let analysis = analyze_render_tree(&el);
    assert_eq!(analysis.keyed_elements, 1);
}

#[test]
fn render_tree_analysis_deeply_nested_chain() {
    let mut current = make_element("leaf");
    for i in 0..15 {
        let mut parent = make_element(&format!("level{i}"));
        parent
            .children
            .push(LoweredChild::Element(Box::new(current)));
        current = parent;
    }
    let analysis = analyze_render_tree(&current);
    assert_eq!(analysis.max_depth, 15);
    assert!(!analysis.is_simple());
}

// ---------------------------------------------------------------------------
// 9. Catalog building and querying
// ---------------------------------------------------------------------------

#[test]
fn catalog_new_is_empty() {
    let catalog = ComponentShapeCatalog::new();
    assert_eq!(catalog.component_count(), 0);
    assert_eq!(catalog.total_observations, 0);
    assert_eq!(catalog.analysis_epoch, 0);
}

#[test]
fn catalog_register_and_get() {
    let mut catalog = ComponentShapeCatalog::new();
    let shape = make_pure_shape("Button");
    catalog.register(shape);
    assert_eq!(catalog.component_count(), 1);
    let got = catalog.get("Button").unwrap();
    assert_eq!(got.component_name, "Button");
}

#[test]
fn catalog_register_deduplicates() {
    let mut catalog = ComponentShapeCatalog::new();
    let shape1 = make_pure_shape("Card");
    catalog.register(shape1);

    let shape2 = make_pure_shape("Card");
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
        total_elements: 5,
        max_depth: 2,
        component_refs: {
            let mut s = BTreeSet::new();
            s.insert("ChildComp".to_string());
            s
        },
        intrinsic_tags: {
            let mut s = BTreeSet::new();
            s.insert("div".to_string());
            s
        },
        has_spreads: false,
        ..Default::default()
    };
    catalog.register_from_evidence("DataTable", &manifest, &analysis);
    let shape = catalog.get("DataTable").unwrap();
    assert_eq!(shape.hook_profile.state_hooks, 1);
    assert_eq!(shape.hook_profile.memo_hooks, 1);
    assert_eq!(shape.max_render_depth, 2);
    assert!(shape.children_element_types.contains("ChildComp"));
    assert!(shape.children_element_types.contains("div"));
    assert!(shape.has_dynamic_children); // component_count > 0 => true
}

#[test]
fn catalog_pure_components_filter() {
    let mut catalog = ComponentShapeCatalog::new();
    catalog.register(make_pure_shape("PureA"));
    catalog.register(make_pure_shape("PureB"));
    catalog.register(make_impure_shape("ImpureC"));

    let pures = catalog.pure_components();
    assert_eq!(pures.len(), 2);
    let names: BTreeSet<&str> = pures.iter().map(|s| s.component_name.as_str()).collect();
    assert!(names.contains("PureA"));
    assert!(names.contains("PureB"));
}

#[test]
fn catalog_impure_components_with_reasons() {
    let mut catalog = ComponentShapeCatalog::new();
    catalog.register(make_pure_shape("Pure"));
    catalog.register(make_impure_shape("Impure"));

    let impures = catalog.impure_components();
    assert_eq!(impures.len(), 1);
    assert_eq!(impures[0].0.component_name, "Impure");
    assert!(impures[0].1.contains(&ImpurityReason::EffectInRenderPath));
}

#[test]
fn catalog_partial_eval_eligible_filter() {
    let mut catalog = ComponentShapeCatalog::new();
    catalog.register(make_pure_shape("Eligible"));

    let mut spread_shape = make_pure_shape("WithSpread");
    spread_shape.has_spread_props = true;
    catalog.register(spread_shape);

    let eligible = catalog.partial_eval_eligible();
    assert_eq!(eligible.len(), 1);
    assert_eq!(eligible[0].component_name, "Eligible");
}

#[test]
fn catalog_get_nonexistent_returns_none() {
    let catalog = ComponentShapeCatalog::new();
    assert!(catalog.get("NonExistent").is_none());
}

// ---------------------------------------------------------------------------
// 10. CatalogSummary and coverage metrics
// ---------------------------------------------------------------------------

#[test]
fn catalog_summary_mixed() {
    let mut catalog = ComponentShapeCatalog::new();

    catalog.register(make_pure_shape("A"));
    catalog.register(make_pure_shape("B"));
    catalog.register(make_impure_shape("C"));

    let mut ctx_shape = ComponentShape::new("D");
    ctx_shape.observation_count = 10;
    ctx_shape.hook_profile.context_hooks = 1;
    catalog.register(ctx_shape);

    let summary = catalog.summary();
    assert_eq!(summary.total_components, 4);
    assert_eq!(summary.pure_count, 2);
    assert_eq!(summary.impure_count, 1);
    assert_eq!(summary.conditionally_pure_count, 1);
    assert_eq!(summary.purity_ratio_fp, 500_000); // 2/4 = 0.5
}

#[test]
fn catalog_summary_empty() {
    let catalog = ComponentShapeCatalog::new();
    let summary = catalog.summary();
    assert_eq!(summary.total_components, 0);
    assert_eq!(summary.purity_ratio_fp, 0);
    assert_eq!(summary.total_props, 0);
    assert_eq!(summary.total_hooks, 0);
}

#[test]
fn catalog_summary_counts_props_and_hooks() {
    let mut catalog = ComponentShapeCatalog::new();
    let mut shape = make_pure_shape("Comp");
    shape.add_prop(PropDescriptor::new(
        "a",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "b",
        PropValueKind::NumberLiteral,
        PropFlowKind::Computed,
    ));
    shape.hook_profile.total_hooks = 3;
    catalog.register(shape);

    let summary = catalog.summary();
    assert_eq!(summary.total_props, 2);
    assert_eq!(summary.total_hooks, 3);
}

#[test]
fn catalog_summary_high_arity_count() {
    let mut catalog = ComponentShapeCatalog::new();
    let mut shape = make_pure_shape("BigForm");
    for i in 0..12 {
        shape.add_prop(PropDescriptor::new(
            &format!("field{i}"),
            PropValueKind::Unknown,
            PropFlowKind::Rendered,
        ));
    }
    catalog.register(shape);
    let summary = catalog.summary();
    assert_eq!(summary.high_arity_count, 1);
}

// ---------------------------------------------------------------------------
// 11. CatalogReceipt
// ---------------------------------------------------------------------------

#[test]
fn catalog_receipt_nonempty() {
    let mut catalog = ComponentShapeCatalog::new();
    catalog.register(make_pure_shape("Alpha"));
    catalog.register(make_impure_shape("Beta"));

    let receipt = catalog.generate_receipt();
    assert_eq!(receipt.component_count, 2);
    assert_eq!(receipt.pure_count, 1);
    assert!(!receipt.receipt_hash.is_empty());
    assert_eq!(receipt.component_hashes.len(), 2);
}

#[test]
fn catalog_receipt_empty_catalog() {
    let catalog = ComponentShapeCatalog::new();
    let receipt = catalog.generate_receipt();
    assert_eq!(receipt.component_count, 0);
    assert_eq!(receipt.pure_count, 0);
    assert!(!receipt.receipt_hash.is_empty());
    assert!(receipt.component_hashes.is_empty());
}

#[test]
fn catalog_advance_epoch() {
    let mut catalog = ComponentShapeCatalog::new();
    assert_eq!(catalog.analysis_epoch, 0);
    catalog.advance_epoch();
    assert_eq!(catalog.analysis_epoch, 1);
    catalog.advance_epoch();
    assert_eq!(catalog.analysis_epoch, 2);
}

#[test]
fn catalog_reclassify_all_with_new_config() {
    let mut catalog = ComponentShapeCatalog::new();

    // Register with default config: spread => ConditionallyPure (severity 300k < 500k).
    let mut shape = ComponentShape::new("SpreadComp");
    shape.observation_count = 10;
    shape.has_spread_props = true;
    catalog.register(shape);
    assert_eq!(
        catalog.get("SpreadComp").unwrap().render_purity,
        RenderPurityClass::ConditionallyPure
    );

    // Lower the threshold so 300k > 200k => Impure.
    catalog.config.max_conditional_severity = 200_000;
    catalog.reclassify_all();
    assert_eq!(
        catalog.get("SpreadComp").unwrap().render_purity,
        RenderPurityClass::Impure
    );
}

#[test]
fn catalog_with_custom_config() {
    let config = PurityConfig {
        min_observations: 1,
        context_downgrades_purity: false,
        spread_downgrades_purity: false,
        max_conditional_severity: 1_000_000,
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);
    let shape = ComponentShape::new("Quick");
    catalog.register(shape);
    // With min_observations=1, the registration provides 1 observation.
    assert_ne!(
        catalog.get("Quick").unwrap().render_purity,
        RenderPurityClass::Unknown
    );
}

// ---------------------------------------------------------------------------
// 12. Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_prop_flow_kind() {
    for flow in [
        PropFlowKind::Rendered,
        PropFlowKind::PassedDown,
        PropFlowKind::Computed,
        PropFlowKind::KeyOrRef,
        PropFlowKind::EffectOnly,
        PropFlowKind::Spread,
        PropFlowKind::Unused,
    ] {
        let json = serde_json::to_string(&flow).unwrap();
        let back: PropFlowKind = serde_json::from_str(&json).unwrap();
        assert_eq!(flow, back);
    }
}

#[test]
fn serde_roundtrip_prop_value_kind() {
    for kind in [
        PropValueKind::StringLiteral,
        PropValueKind::NumberLiteral,
        PropValueKind::BooleanLiteral,
        PropValueKind::NullOrUndefined,
        PropValueKind::Callback,
        PropValueKind::ReactElement,
        PropValueKind::Array,
        PropValueKind::Object,
        PropValueKind::Unknown,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: PropValueKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn serde_roundtrip_render_purity_class() {
    for class in [
        RenderPurityClass::Pure,
        RenderPurityClass::ConditionallyPure,
        RenderPurityClass::Impure,
        RenderPurityClass::Unknown,
    ] {
        let json = serde_json::to_string(&class).unwrap();
        let back: RenderPurityClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, back);
    }
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
fn serde_roundtrip_component_shape() {
    let mut shape = ComponentShape::new("SerdeTest");
    shape.observation_count = 5;
    shape.add_prop(PropDescriptor::new(
        "x",
        PropValueKind::NumberLiteral,
        PropFlowKind::Rendered,
    ));
    shape.hook_profile.state_hooks = 1;
    shape.hook_profile.total_hooks = 1;
    shape.render_purity = RenderPurityClass::Pure;
    shape.compute_evidence_hash();
    let json = serde_json::to_string(&shape).unwrap();
    let back: ComponentShape = serde_json::from_str(&json).unwrap();
    assert_eq!(shape, back);
}

#[test]
fn serde_roundtrip_catalog_summary() {
    let summary = CatalogSummary {
        total_components: 10,
        pure_count: 5,
        conditionally_pure_count: 3,
        impure_count: 1,
        unknown_count: 1,
        partial_eval_eligible_count: 8,
        high_arity_count: 2,
        total_props: 40,
        total_hooks: 15,
        purity_ratio_fp: 500_000,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: CatalogSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn serde_roundtrip_catalog_receipt() {
    let receipt = CatalogReceipt {
        epoch: 3,
        component_count: 2,
        pure_count: 1,
        partial_eval_eligible: 1,
        purity_ratio_fp: 500_000,
        receipt_hash: "deadbeef01".to_string(),
        component_hashes: vec![
            ("A".to_string(), "hash_a".to_string()),
            ("B".to_string(), "hash_b".to_string()),
        ],
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: CatalogReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn serde_roundtrip_hook_profile() {
    let profile = HookProfile {
        state_hooks: 2,
        effect_hooks: 1,
        memo_hooks: 3,
        ref_hooks: 1,
        context_hooks: 0,
        callback_hooks: 1,
        other_hooks: 0,
        total_hooks: 8,
        has_conditional_hooks: false,
    };
    let json = serde_json::to_string(&profile).unwrap();
    let back: HookProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
}

#[test]
fn serde_roundtrip_purity_classification() {
    let mut reasons = BTreeSet::new();
    reasons.insert(ImpurityReason::SpreadProps);
    let classification = PurityClassification {
        class: RenderPurityClass::ConditionallyPure,
        reasons,
        severity_total: 300_000,
        confidence_fp: 80_000,
    };
    let json = serde_json::to_string(&classification).unwrap();
    let back: PurityClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(classification, back);
}

#[test]
fn serde_roundtrip_render_tree_analysis() {
    let mut tags = BTreeSet::new();
    tags.insert("div".to_string());
    tags.insert("span".to_string());
    let analysis = RenderTreeAnalysis {
        total_elements: 5,
        intrinsic_count: 3,
        component_count: 2,
        fragment_count: 0,
        max_depth: 3,
        keyed_elements: 1,
        has_spreads: false,
        intrinsic_tags: tags,
        component_refs: BTreeSet::new(),
    };
    let json = serde_json::to_string(&analysis).unwrap();
    let back: RenderTreeAnalysis = serde_json::from_str(&json).unwrap();
    assert_eq!(analysis, back);
}

// ---------------------------------------------------------------------------
// 13. Determinism
// ---------------------------------------------------------------------------

#[test]
fn deterministic_purity_classification() {
    let config = PurityConfig::default();
    let mut shape = ComponentShape::new("DetTest");
    shape.observation_count = 20;
    shape.hook_profile.context_hooks = 1;
    shape.has_spread_props = true;

    let r1 = classify_purity(&shape, &config);
    let r2 = classify_purity(&shape, &config);
    assert_eq!(r1, r2);
}

#[test]
fn deterministic_evidence_hash() {
    let mut s1 = ComponentShape::new("Deterministic");
    s1.observation_count = 10;
    s1.hook_profile.total_hooks = 2;
    s1.render_purity = RenderPurityClass::Pure;
    s1.compute_evidence_hash();

    let mut s2 = ComponentShape::new("Deterministic");
    s2.observation_count = 10;
    s2.hook_profile.total_hooks = 2;
    s2.render_purity = RenderPurityClass::Pure;
    s2.compute_evidence_hash();

    assert_eq!(s1.evidence_hash, s2.evidence_hash);
}

#[test]
fn deterministic_catalog_receipt() {
    let build_catalog = || {
        let mut catalog = ComponentShapeCatalog::new();
        catalog.register(make_pure_shape("Alpha"));
        catalog.register(make_impure_shape("Beta"));
        catalog.generate_receipt()
    };

    let r1 = build_catalog();
    let r2 = build_catalog();
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
    assert_eq!(r1.component_hashes, r2.component_hashes);
}

// ---------------------------------------------------------------------------
// 14. Boundary cases
// ---------------------------------------------------------------------------

#[test]
fn single_component_catalog() {
    let mut catalog = ComponentShapeCatalog::new();
    catalog.register(make_pure_shape("Only"));
    let summary = catalog.summary();
    assert_eq!(summary.total_components, 1);
    assert_eq!(summary.pure_count, 1);
    assert_eq!(summary.purity_ratio_fp, 1_000_000); // 1/1 = 1.0
}

#[test]
fn high_arity_component_13_props() {
    let mut shape = ComponentShape::new("BigForm");
    for i in 0..13 {
        shape.add_prop(PropDescriptor::new(
            &format!("prop{i}"),
            PropValueKind::Unknown,
            PropFlowKind::Rendered,
        ));
    }
    assert!(shape.is_high_arity());
    assert_eq!(shape.prop_count(), 13);
}

#[test]
fn many_siblings_render_tree() {
    let mut root = make_element("ul");
    for i in 0..50 {
        let mut li = make_element("li");
        li.props.extracted_key = Some(LoweredPropValue::StringLiteral {
            value: format!("item-{i}"),
        });
        root.children.push(LoweredChild::Element(Box::new(li)));
    }
    let analysis = analyze_render_tree(&root);
    assert_eq!(analysis.total_elements, 51);
    assert_eq!(analysis.keyed_elements, 50);
    assert_eq!(analysis.max_depth, 1);
}

#[test]
fn multiple_impurity_reasons_accumulate() {
    let mut shape = ComponentShape::new("Complex");
    shape.observation_count = 10;
    shape.hook_profile.effect_hooks = 1;
    shape.hook_profile.context_hooks = 1;
    shape.hook_profile.ref_hooks = 1;
    shape.has_spread_props = true;
    shape.has_dynamic_children = true;

    let config = PurityConfig::default();
    let result = classify_purity(&shape, &config);
    assert_eq!(result.class, RenderPurityClass::Impure);
    assert!(result.reasons.contains(&ImpurityReason::EffectInRenderPath));
    assert!(result.reasons.contains(&ImpurityReason::ContextDependency));
    assert!(result.reasons.contains(&ImpurityReason::MutableRef));
    assert!(result.reasons.contains(&ImpurityReason::SpreadProps));
    assert!(result.reasons.contains(&ImpurityReason::DynamicElementType));
    assert!(result.severity_total > 0);
}

#[test]
fn dynamic_children_flag_from_evidence() {
    let mut catalog = ComponentShapeCatalog::new();
    let manifest = make_manifest(&[]);
    let analysis = RenderTreeAnalysis {
        component_count: 2,
        component_refs: {
            let mut s = BTreeSet::new();
            s.insert("Child1".to_string());
            s.insert("Child2".to_string());
            s
        },
        ..Default::default()
    };
    catalog.register_from_evidence("Parent", &manifest, &analysis);
    let shape = catalog.get("Parent").unwrap();
    assert!(shape.has_dynamic_children);
}

// ---------------------------------------------------------------------------
// 15. End-to-end pipeline
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_declare_props_build_shape_classify_catalog_query() {
    // Step 1: Declare props.
    let props = vec![
        PropDescriptor::new(
            "title",
            PropValueKind::StringLiteral,
            PropFlowKind::Rendered,
        ),
        PropDescriptor::new(
            "count",
            PropValueKind::NumberLiteral,
            PropFlowKind::Computed,
        ),
        PropDescriptor::new("onClick", PropValueKind::Callback, PropFlowKind::EffectOnly),
        PropDescriptor::new("key", PropValueKind::StringLiteral, PropFlowKind::KeyOrRef),
    ];

    // Step 2: Build shape.
    let mut shape = ComponentShape::new("Counter");
    for prop in props {
        shape.add_prop(prop);
    }
    shape.observation_count = 20;
    shape.hook_profile = HookProfile {
        state_hooks: 1,
        memo_hooks: 1,
        total_hooks: 2,
        ..Default::default()
    };
    shape.max_render_depth = 3;

    // Step 3: Classify purity (should be Pure: no effects, no context, no spread).
    let config = PurityConfig::default();
    let classification = classify_purity(&shape, &config);
    assert_eq!(classification.class, RenderPurityClass::Pure);
    assert!(classification.reasons.is_empty());

    // Step 4: Build catalog and register.
    let mut catalog = ComponentShapeCatalog::new();
    catalog.register(shape);

    // Step 5: Query.
    let counter = catalog.get("Counter").unwrap();
    assert_eq!(counter.render_purity, RenderPurityClass::Pure);
    assert_eq!(counter.prop_count(), 4);
    assert_eq!(counter.render_relevant_prop_count(), 2); // Rendered + Computed
    assert!(counter.is_partial_eval_eligible());
    assert!(!counter.is_high_arity());
    assert!(!counter.is_deeply_nested());

    // Step 6: Verify catalog summary.
    let summary = catalog.summary();
    assert_eq!(summary.total_components, 1);
    assert_eq!(summary.pure_count, 1);
    assert_eq!(summary.purity_ratio_fp, 1_000_000);
    assert_eq!(summary.partial_eval_eligible_count, 1);

    // Step 7: Generate receipt.
    let receipt = catalog.generate_receipt();
    assert_eq!(receipt.component_count, 1);
    assert!(!receipt.receipt_hash.is_empty());
}

#[test]
fn end_to_end_from_render_tree_evidence() {
    // Build a render tree.
    let mut root = make_element("div");
    let mut child_span = make_element("span");
    child_span
        .children
        .push(LoweredChild::Element(Box::new(make_element("strong"))));
    root.children
        .push(LoweredChild::Element(Box::new(child_span)));
    root.children
        .push(LoweredChild::Element(Box::new(make_component_element(
            "Icon",
        ))));

    // Analyze the render tree.
    let analysis = analyze_render_tree(&root);
    assert_eq!(analysis.max_depth, 2);
    assert!(analysis.has_component_children());

    // Build a manifest with state + memo hooks.
    let manifest = make_manifest(&[HookKind::State, HookKind::Memo]);

    // Register from evidence into catalog.
    let mut catalog = ComponentShapeCatalog::new();
    catalog.register_from_evidence("Card", &manifest, &analysis);

    let shape = catalog.get("Card").unwrap();
    assert_eq!(shape.hook_profile.state_hooks, 1);
    assert_eq!(shape.hook_profile.memo_hooks, 1);
    assert_eq!(shape.max_render_depth, 2);
    assert!(shape.children_element_types.contains("Icon"));
    assert!(shape.children_element_types.contains("div"));
    assert!(shape.children_element_types.contains("span"));
    assert!(shape.children_element_types.contains("strong"));
}

#[test]
fn end_to_end_multi_component_catalog_lifecycle() {
    let config = PurityConfig {
        min_observations: 2,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);

    // Register several components with varying purities.
    let mut pure1 = ComponentShape::new("Header");
    pure1.observation_count = 10;
    catalog.register(pure1);

    let mut pure2 = ComponentShape::new("Footer");
    pure2.observation_count = 10;
    catalog.register(pure2);

    let mut ctx = ComponentShape::new("ThemeProvider");
    ctx.observation_count = 10;
    ctx.hook_profile.context_hooks = 1;
    catalog.register(ctx);

    let mut effects = ComponentShape::new("DataFetcher");
    effects.observation_count = 10;
    effects.hook_profile.effect_hooks = 2;
    catalog.register(effects);

    let unknown = ComponentShape::new("NewComp");
    // observation_count = 0 < min_observations = 2 => Unknown
    catalog.register(unknown);

    // Verify summary.
    let summary = catalog.summary();
    assert_eq!(summary.total_components, 5);
    assert_eq!(summary.pure_count, 2);
    assert_eq!(summary.conditionally_pure_count, 1);
    assert_eq!(summary.impure_count, 1);
    assert_eq!(summary.unknown_count, 1);

    // Advance epoch and reclassify.
    catalog.advance_epoch();
    assert_eq!(catalog.analysis_epoch, 1);
    catalog.reclassify_all();

    // Generate receipt.
    let receipt = catalog.generate_receipt();
    assert_eq!(receipt.epoch, 1);
    assert_eq!(receipt.component_count, 5);
    assert!(!receipt.receipt_hash.is_empty());
    assert_eq!(receipt.component_hashes.len(), 5);
}
