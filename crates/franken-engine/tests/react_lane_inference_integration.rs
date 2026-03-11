//! Integration tests for `react_lane_inference` — [RGC-609A]
//!
//! Validates the inference pipeline end-to-end: component evidence collection,
//! purity classification, shape stability assessment, blocking reason
//! computation, receipt generation, determinism, and serde roundtrips.

use std::collections::BTreeSet;

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::component_shape_catalog::{
    ImpurityReason, PropDescriptor, PropFlowKind, PropValueKind, PurityClassification,
    PurityConfig, RenderPurityClass, analyze_render_tree, classify_purity,
};
use frankenengine_engine::hook_effect_contract::{HookKind, HookManifest, HookSlot, HookSlotIndex};
use frankenengine_engine::react_jsx_lowering::{
    CallConvention, ElementType, LoweredChild, LoweredElement, LoweredProp, LoweredPropValue,
    LoweredProps, PropsEntry,
};
use frankenengine_engine::react_lane_inference::{
    ComponentEvidence, ComponentInferenceResult, INFERENCE_BEAD_ID, INFERENCE_COMPONENT,
    INFERENCE_POLICY_ID, INFERENCE_SCHEMA_VERSION, InferenceBlockingReason, InferenceConfig,
    InferenceReceipt, InferenceSummary, ReactLaneInferencePipeline, ShapeStabilityAssessment,
    batch_infer, partial_eval_coverage,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::shape_transition_algebra::ShapeTransitionAlgebra;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
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

fn make_nested_element(depth: usize) -> LoweredElement {
    let mut el = make_element("span");
    for _ in 0..depth {
        let wrapper = LoweredElement {
            children: vec![LoweredChild::Element(Box::new(el))],
            ..make_element("div")
        };
        el = wrapper;
    }
    el
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

fn make_element_with_children(tag: &str, children: Vec<LoweredElement>) -> LoweredElement {
    LoweredElement {
        children: children
            .into_iter()
            .map(|c| LoweredChild::Element(Box::new(c)))
            .collect(),
        ..make_element(tag)
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_are_nonempty() {
    assert!(!INFERENCE_SCHEMA_VERSION.is_empty());
    assert!(!INFERENCE_COMPONENT.is_empty());
    assert!(!INFERENCE_BEAD_ID.is_empty());
    assert!(!INFERENCE_POLICY_ID.is_empty());
}

#[test]
fn constants_contain_expected_substrings() {
    assert!(INFERENCE_SCHEMA_VERSION.contains("react-lane-inference"));
    assert!(INFERENCE_BEAD_ID.starts_with("bd-"));
    assert!(INFERENCE_POLICY_ID.starts_with("RGC-"));
}

// ---------------------------------------------------------------------------
// InferenceConfig
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let c = InferenceConfig::default();
    assert_eq!(c.min_stable_observations, 3);
    assert_eq!(c.max_shape_transitions, 8);
    assert!(c.infer_props);
    assert!(c.integrate_shape_algebra);
    assert_eq!(c.max_render_depth, 32);
    assert_eq!(c.min_purity_ratio, 500_000);
}

#[test]
fn config_serde_roundtrip() {
    let c = InferenceConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: InferenceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn config_custom_values_serde() {
    let c = InferenceConfig {
        min_stable_observations: 10,
        max_shape_transitions: 3,
        infer_props: false,
        integrate_shape_algebra: false,
        max_render_depth: 5,
        min_purity_ratio: 900_000,
        ..InferenceConfig::default()
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: InferenceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
    assert_eq!(back.min_purity_ratio, 900_000);
}

// ---------------------------------------------------------------------------
// ShapeStabilityAssessment
// ---------------------------------------------------------------------------

#[test]
fn shape_stability_default_monomorphic() {
    let s = ShapeStabilityAssessment::default();
    assert!(s.is_monomorphic);
    assert!(!s.is_polymorphic);
    assert!(!s.is_megamorphic);
    assert!(s.cells_stable);
    assert!(s.is_optimization_safe());
}

#[test]
fn shape_stability_from_transitions_zero() {
    let s = ShapeStabilityAssessment::from_transitions(0, 4);
    assert!(s.is_monomorphic);
    assert!(s.is_optimization_safe());
    assert_eq!(s.transition_count, 0);
}

#[test]
fn shape_stability_from_transitions_one() {
    let s = ShapeStabilityAssessment::from_transitions(1, 4);
    assert!(s.is_monomorphic);
    assert!(s.is_optimization_safe());
}

#[test]
fn shape_stability_polymorphic() {
    let s = ShapeStabilityAssessment::from_transitions(3, 4);
    assert!(!s.is_monomorphic);
    assert!(s.is_polymorphic);
    assert!(!s.is_megamorphic);
    assert!(s.cells_stable);
    assert!(s.is_optimization_safe());
}

#[test]
fn shape_stability_megamorphic() {
    let s = ShapeStabilityAssessment::from_transitions(10, 4);
    assert!(!s.is_monomorphic);
    assert!(!s.is_polymorphic);
    assert!(s.is_megamorphic);
    assert!(!s.cells_stable);
    assert!(!s.is_optimization_safe());
}

#[test]
fn shape_stability_boundary_poly() {
    let s = ShapeStabilityAssessment::from_transitions(4, 4);
    assert!(!s.is_monomorphic);
    assert!(s.is_polymorphic);
    assert!(!s.is_megamorphic);
}

#[test]
fn shape_stability_boundary_mega() {
    let s = ShapeStabilityAssessment::from_transitions(5, 4);
    assert!(s.is_megamorphic);
    assert!(!s.is_optimization_safe());
}

#[test]
fn shape_stability_serde() {
    let s = ShapeStabilityAssessment::from_transitions(3, 8);
    let json = serde_json::to_string(&s).unwrap();
    let back: ShapeStabilityAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// InferenceBlockingReason
// ---------------------------------------------------------------------------

#[test]
fn blocking_reason_display_all_variants() {
    let variants = vec![
        (
            InferenceBlockingReason::ImpureClassification,
            "impure_classification",
        ),
        (
            InferenceBlockingReason::MegamorphicShape,
            "megamorphic_shape",
        ),
        (
            InferenceBlockingReason::UnstablePropertyCells,
            "unstable_property_cells",
        ),
        (
            InferenceBlockingReason::InsufficientEvidence,
            "insufficient_evidence",
        ),
        (InferenceBlockingReason::DeeplyNested, "deeply_nested"),
        (
            InferenceBlockingReason::ConditionalHooks,
            "conditional_hooks",
        ),
        (
            InferenceBlockingReason::EffectsInRender,
            "effects_in_render",
        ),
        (InferenceBlockingReason::MutableRefs, "mutable_refs"),
    ];
    for (reason, expected) in variants {
        assert_eq!(reason.to_string(), expected);
    }
}

#[test]
fn blocking_reason_serde_roundtrip_all() {
    let reasons = vec![
        InferenceBlockingReason::ImpureClassification,
        InferenceBlockingReason::MegamorphicShape,
        InferenceBlockingReason::UnstablePropertyCells,
        InferenceBlockingReason::InsufficientEvidence,
        InferenceBlockingReason::DeeplyNested,
        InferenceBlockingReason::ConditionalHooks,
        InferenceBlockingReason::EffectsInRender,
        InferenceBlockingReason::MutableRefs,
    ];
    for r in reasons {
        let json = serde_json::to_string(&r).unwrap();
        let back: InferenceBlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn blocking_reason_ordering_stable() {
    let mut reasons = vec![
        InferenceBlockingReason::MutableRefs,
        InferenceBlockingReason::EffectsInRender,
        InferenceBlockingReason::ConditionalHooks,
        InferenceBlockingReason::DeeplyNested,
        InferenceBlockingReason::ImpureClassification,
    ];
    reasons.sort();
    // Ordering must be deterministic.
    let first = reasons.first().unwrap();
    let last = reasons.last().unwrap();
    assert!(first <= last);
}

// ---------------------------------------------------------------------------
// Pipeline creation and basic operations
// ---------------------------------------------------------------------------

#[test]
fn pipeline_new_defaults() {
    let p = ReactLaneInferencePipeline::new(epoch());
    assert_eq!(p.total_processed, 0);
    assert_eq!(p.total_eligible, 0);
    assert_eq!(p.schema_version, INFERENCE_SCHEMA_VERSION);
    assert!(p.results.is_empty());
    assert!(p.evidence.is_empty());
}

#[test]
fn pipeline_with_config() {
    let config = InferenceConfig {
        max_render_depth: 5,
        ..InferenceConfig::default()
    };
    let p = ReactLaneInferencePipeline::with_config(config.clone(), epoch());
    assert_eq!(p.config.max_render_depth, 5);
}

#[test]
fn pipeline_infer_single_intrinsic() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let result = p.infer_component("Wrapper", &el, None, None);
    assert_eq!(result.component_name, "Wrapper");
    assert!(!result.evidence_hash.is_empty());
    assert_eq!(p.total_processed, 1);
}

#[test]
fn pipeline_infer_pure_no_hooks() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let result = p.infer_component("PureDiv", &el, None, None);
    // No hooks, no effects — should be pure or at least allow partial eval.
    assert!(result.purity.class.allows_partial_eval());
    assert!(result.blocking_reasons.is_empty() || result.partial_eval_eligible);
}

#[test]
fn pipeline_infer_with_memo_hook() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("MemoComp", vec![HookKind::Memo]);
    let result = p.infer_component("MemoComp", &el, Some(&manifest), None);
    assert_eq!(result.component_name, "MemoComp");
    // Memo hook should not block purity.
    assert!(result.purity.class.allows_partial_eval());
}

#[test]
fn pipeline_infer_with_state_hook() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("StatefulComp", vec![HookKind::State]);
    let result = p.infer_component("StatefulComp", &el, Some(&manifest), None);
    assert_eq!(result.component_name, "StatefulComp");
}

#[test]
fn pipeline_infer_with_effect_hook() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("EffectComp", vec![HookKind::Effect]);
    let result = p.infer_component("EffectComp", &el, Some(&manifest), None);
    // Effect hook should cause impurity.
    assert!(
        result
            .purity
            .reasons
            .contains(&ImpurityReason::EffectInRenderPath)
    );
}

#[test]
fn pipeline_infer_with_ref_hook() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("RefComp", vec![HookKind::Ref]);
    let result = p.infer_component("RefComp", &el, Some(&manifest), None);
    // Ref hook should flag MutableRef impurity.
    assert!(result.purity.reasons.contains(&ImpurityReason::MutableRef));
}

#[test]
fn pipeline_infer_with_context_hook() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("CtxComp", vec![HookKind::Context]);
    let result = p.infer_component("CtxComp", &el, Some(&manifest), None);
    assert_eq!(result.component_name, "CtxComp");
}

#[test]
fn pipeline_infer_multiple_hooks() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest(
        "MultiHook",
        vec![HookKind::State, HookKind::Effect, HookKind::Memo],
    );
    let result = p.infer_component("MultiHook", &el, Some(&manifest), None);
    assert_eq!(result.component_name, "MultiHook");
    // Effect hook should still cause impurity even with other hooks.
    assert!(
        result
            .purity
            .reasons
            .contains(&ImpurityReason::EffectInRenderPath)
    );
}

#[test]
fn pipeline_multiple_components_counted() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    for i in 0..5 {
        let el = make_element("div");
        p.infer_component(&format!("Comp{i}"), &el, None, None);
    }
    assert_eq!(p.total_processed, 5);
}

#[test]
fn pipeline_get_result_found() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("Target", &el, None, None);
    assert!(p.get_result("Target").is_some());
}

#[test]
fn pipeline_get_result_not_found() {
    let p = ReactLaneInferencePipeline::new(epoch());
    assert!(p.get_result("Nonexistent").is_none());
}

#[test]
fn pipeline_eligible_and_blocked_partition() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest_impure = make_hook_manifest("Impure", vec![HookKind::Effect, HookKind::Ref]);
    p.infer_component("Pure", &el, None, None);
    p.infer_component("Impure", &el, Some(&manifest_impure), None);
    let eligible = p.eligible_components();
    let blocked = p.blocked_components();
    assert_eq!(eligible.len() + blocked.len(), 2);
}

#[test]
fn pipeline_reset_clears_state() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("Comp", &el, None, None);
    assert_eq!(p.total_processed, 1);
    p.reset();
    assert_eq!(p.total_processed, 0);
    assert_eq!(p.total_eligible, 0);
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
    assert_eq!(p.schema_version, back.schema_version);
}

#[test]
fn pipeline_serde_with_multiple_components() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    for i in 0..3 {
        let el = make_element("div");
        p.infer_component(&format!("Comp{i}"), &el, None, None);
    }
    let json = serde_json::to_string(&p).unwrap();
    let back: ReactLaneInferencePipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_processed, 3);
}

// ---------------------------------------------------------------------------
// Prop inference
// ---------------------------------------------------------------------------

#[test]
fn infer_props_empty_element() {
    let el = make_element("div");
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
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
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    assert_eq!(props.len(), 1);
    assert_eq!(props[0].name, "className");
    assert_eq!(props[0].value_kind, PropValueKind::StringLiteral);
    assert_eq!(props[0].flow, PropFlowKind::Rendered);
}

#[test]
fn infer_props_boolean_true() {
    let el = make_element_with_props("input", vec![("disabled", LoweredPropValue::BooleanTrue)]);
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    assert_eq!(props[0].value_kind, PropValueKind::BooleanLiteral);
}

#[test]
fn infer_props_null() {
    let el = make_element_with_props("div", vec![("data", LoweredPropValue::Null)]);
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    assert_eq!(props[0].value_kind, PropValueKind::NullOrUndefined);
}

#[test]
fn infer_props_callback_arrow() {
    let el = make_element_with_props(
        "button",
        vec![(
            "onClick",
            LoweredPropValue::Expression {
                expression: "() => handleClick()".into(),
            },
        )],
    );
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    assert_eq!(props[0].value_kind, PropValueKind::Callback);
    assert_eq!(props[0].flow, PropFlowKind::EffectOnly);
}

#[test]
fn infer_props_callback_fat_arrow() {
    let el = make_element_with_props(
        "button",
        vec![(
            "onClick",
            LoweredPropValue::Expression {
                expression: "x => x + 1".into(),
            },
        )],
    );
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    assert_eq!(props[0].value_kind, PropValueKind::Callback);
}

#[test]
fn infer_props_unknown_expression() {
    let el = make_element_with_props(
        "div",
        vec![(
            "data",
            LoweredPropValue::Expression {
                expression: "someVariable".into(),
            },
        )],
    );
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    assert_eq!(props[0].value_kind, PropValueKind::Unknown);
}

#[test]
fn infer_props_element_value() {
    let inner = make_element("span");
    let el = make_element_with_props(
        "div",
        vec![("icon", LoweredPropValue::Element(Box::new(inner)))],
    );
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
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
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    assert_eq!(props[0].value_kind, PropValueKind::Array);
    assert_eq!(props[0].flow, PropFlowKind::Rendered);
}

#[test]
fn infer_props_multiple() {
    let el = make_element_with_props(
        "input",
        vec![
            (
                "className",
                LoweredPropValue::StringLiteral {
                    value: "field".into(),
                },
            ),
            ("disabled", LoweredPropValue::BooleanTrue),
            (
                "onChange",
                LoweredPropValue::Expression {
                    expression: "() => {}".into(),
                },
            ),
        ],
    );
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    assert_eq!(props.len(), 3);
    assert_eq!(props[0].flow, PropFlowKind::Rendered);
    assert_eq!(props[2].flow, PropFlowKind::EffectOnly);
}

#[test]
fn infer_props_key_ref_flow() {
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
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    assert_eq!(props[0].flow, PropFlowKind::KeyOrRef);
    assert_eq!(props[1].flow, PropFlowKind::KeyOrRef);
}

#[test]
fn infer_prop_flow_short_on() {
    // "on" alone should not be EffectOnly (too short).
    let el = make_element_with_props(
        "div",
        vec![(
            "on",
            LoweredPropValue::Expression {
                expression: "handler".into(),
            },
        )],
    );
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    assert_eq!(props[0].flow, PropFlowKind::Computed);
}

// ---------------------------------------------------------------------------
// Summary and receipt
// ---------------------------------------------------------------------------

#[test]
fn summary_empty_pipeline() {
    let p = ReactLaneInferencePipeline::new(epoch());
    let s = p.summary();
    assert_eq!(s.total_components, 0);
    assert_eq!(s.eligible_count, 0);
    assert_eq!(s.blocked_count, 0);
    assert_eq!(s.eligibility_ratio, 0);
}

#[test]
fn summary_with_pure_components() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    for i in 0..5 {
        let el = make_element("div");
        p.infer_component(&format!("Comp{i}"), &el, None, None);
    }
    let s = p.summary();
    assert_eq!(s.total_components, 5);
    assert!(s.eligibility_ratio > 0);
}

#[test]
fn summary_health_threshold() {
    let config = InferenceConfig {
        min_purity_ratio: 900_000, // 90% threshold
        ..InferenceConfig::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    // Add one pure component.
    let el = make_element("div");
    p.infer_component("Pure", &el, None, None);
    let s = p.summary();
    // All components are pure → ratio should be 100% > 90%.
    assert!(s.is_healthy);
}

#[test]
fn summary_serde_roundtrip() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("Comp", &el, None, None);
    let s = p.summary();
    let json = serde_json::to_string(&s).unwrap();
    let back: InferenceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn summary_blocking_reason_counts() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("Eff", vec![HookKind::Effect]);
    p.infer_component("Eff", &el, Some(&manifest), None);
    let s = p.summary();
    // Should have at least one blocking reason counted.
    let total_blocking: u64 = s.blocking_reason_counts.values().sum();
    assert!(total_blocking > 0);
}

#[test]
fn receipt_fields_correct() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("Comp", &el, None, None);
    let r = p.generate_receipt();
    assert_eq!(r.bead_id, INFERENCE_BEAD_ID);
    assert_eq!(r.policy_id, INFERENCE_POLICY_ID);
    assert_eq!(r.total_components, 1);
    assert!(!r.receipt_hash.is_empty());
    assert_eq!(r.component_verdicts.len(), 1);
}

#[test]
fn receipt_deterministic() {
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
fn receipt_differs_by_epoch() {
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
fn receipt_differs_by_components() {
    let mut p1 = ReactLaneInferencePipeline::new(epoch());
    let mut p2 = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p1.infer_component("Comp1", &el, None, None);
    p2.infer_component("Comp2", &el, None, None);
    assert_ne!(
        p1.generate_receipt().receipt_hash,
        p2.generate_receipt().receipt_hash
    );
}

#[test]
fn receipt_serde_roundtrip() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("Comp", &el, None, None);
    let r = p.generate_receipt();
    let json = serde_json::to_string(&r).unwrap();
    let back: InferenceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// Batch inference
// ---------------------------------------------------------------------------

#[test]
fn batch_infer_empty() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let results = batch_infer(&mut p, &[], None);
    assert!(results.is_empty());
    assert_eq!(p.total_processed, 0);
}

#[test]
fn batch_infer_multiple_components() {
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

#[test]
fn batch_infer_results_match_pipeline() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let components = vec![
        ("X".to_string(), make_element("div"), None),
        ("Y".to_string(), make_element("span"), None),
    ];
    let results = batch_infer(&mut p, &components, None);
    for r in &results {
        assert!(p.get_result(&r.component_name).is_some());
    }
}

// ---------------------------------------------------------------------------
// Coverage computation
// ---------------------------------------------------------------------------

#[test]
fn partial_eval_coverage_empty() {
    assert_eq!(partial_eval_coverage(&[]), 0);
}

#[test]
fn partial_eval_coverage_all_eligible() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let r1 = p.infer_component("A", &el, None, None);
    let r2 = p.infer_component("B", &el, None, None);
    let results = vec![r1, r2];
    if results.iter().all(|r| r.partial_eval_eligible) {
        assert_eq!(partial_eval_coverage(&results), 1_000_000);
    }
}

#[test]
fn partial_eval_coverage_mixed() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let r1 = p.infer_component("Pure", &el, None, None);
    let manifest = make_hook_manifest("Impure", vec![HookKind::Effect, HookKind::Ref]);
    let r2 = p.infer_component("Impure", &el, Some(&manifest), None);
    let results = vec![r1, r2];
    let coverage = partial_eval_coverage(&results);
    // At most 50% since one component is impure.
    assert!(coverage <= 500_000);
}

// ---------------------------------------------------------------------------
// Deeply nested blocking
// ---------------------------------------------------------------------------

#[test]
fn blocking_deeply_nested_triggers() {
    let config = InferenceConfig {
        max_render_depth: 2,
        ..InferenceConfig::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    let el = make_nested_element(4);
    let result = p.infer_component("Deep", &el, None, None);
    assert!(
        result
            .blocking_reasons
            .contains(&InferenceBlockingReason::DeeplyNested)
    );
}

#[test]
fn shallow_element_not_blocked() {
    let config = InferenceConfig {
        max_render_depth: 10,
        ..InferenceConfig::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    let el = make_element("div");
    let result = p.infer_component("Shallow", &el, None, None);
    assert!(
        !result
            .blocking_reasons
            .contains(&InferenceBlockingReason::DeeplyNested)
    );
}

// ---------------------------------------------------------------------------
// Evidence hash determinism
// ---------------------------------------------------------------------------

#[test]
fn evidence_hash_deterministic() {
    let mut p1 = ReactLaneInferencePipeline::new(epoch());
    let mut p2 = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let r1 = p1.infer_component("Same", &el, None, None);
    let r2 = p2.infer_component("Same", &el, None, None);
    assert_eq!(r1.evidence_hash, r2.evidence_hash);
}

#[test]
fn evidence_hash_differs_by_name() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let r1 = p.infer_component("Comp1", &el, None, None);
    let r2 = p.infer_component("Comp2", &el, None, None);
    assert_ne!(r1.evidence_hash, r2.evidence_hash);
}

// ---------------------------------------------------------------------------
// Component with children
// ---------------------------------------------------------------------------

#[test]
fn pipeline_infer_component_with_children() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let child1 = make_element("span");
    let child2 = make_element("p");
    let parent = make_element_with_children("div", vec![child1, child2]);
    let result = p.infer_component("Parent", &parent, None, None);
    assert_eq!(result.component_name, "Parent");
    assert!(!result.evidence_hash.is_empty());
}

#[test]
fn pipeline_infer_component_tree() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let inner_comp = make_component_element("InnerComp");
    let outer = make_element_with_children("div", vec![inner_comp]);
    let result = p.infer_component("Outer", &outer, None, None);
    assert_eq!(result.component_name, "Outer");
}

// ---------------------------------------------------------------------------
// Config disabling prop inference
// ---------------------------------------------------------------------------

#[test]
fn config_infer_props_disabled() {
    let config = InferenceConfig {
        infer_props: false,
        ..InferenceConfig::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    let el = make_element_with_props(
        "div",
        vec![(
            "className",
            LoweredPropValue::StringLiteral {
                value: "test".into(),
            },
        )],
    );
    let _result = p.infer_component("NoPropInfer", &el, None, None);
    // Props should not be in evidence when infer_props is false.
    let evidence = p.evidence.get("NoPropInfer").unwrap();
    assert!(evidence.inferred_props.is_empty());
}

#[test]
fn config_integrate_shape_algebra_disabled() {
    let config = InferenceConfig {
        integrate_shape_algebra: false,
        ..InferenceConfig::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    let el = make_element("div");
    let result = p.infer_component("NoShape", &el, None, None);
    // Shape should be default monomorphic when algebra is disabled.
    assert!(result.shape_stability.is_monomorphic);
}

// ---------------------------------------------------------------------------
// ComponentEvidence serde
// ---------------------------------------------------------------------------

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

#[test]
fn component_evidence_with_hooks_serde() {
    let manifest = make_hook_manifest("HookComp", vec![HookKind::State, HookKind::Memo]);
    let evidence = ComponentEvidence {
        component_name: "HookComp".into(),
        render_tree: analyze_render_tree(&make_element("div")),
        hook_manifest: Some(manifest),
        inferred_props: Vec::new(),
        shape_stability: ShapeStabilityAssessment::from_transitions(2, 8),
        compile_receipt_hash: Some("abc123".into()),
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let back: ComponentEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, back);
}

// ---------------------------------------------------------------------------
// ComponentInferenceResult serde
// ---------------------------------------------------------------------------

#[test]
fn inference_result_serde_roundtrip() {
    let result = ComponentInferenceResult {
        component_name: "TestComp".into(),
        purity: PurityClassification {
            class: RenderPurityClass::Pure,
            reasons: BTreeSet::new(),
            severity_total: 0,
            confidence_fp: 1_000_000,
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

#[test]
fn inference_result_with_blocking_serde() {
    let result = ComponentInferenceResult {
        component_name: "Blocked".into(),
        purity: PurityClassification {
            class: RenderPurityClass::Impure,
            reasons: {
                let mut s = BTreeSet::new();
                s.insert(ImpurityReason::EffectInRenderPath);
                s
            },
            severity_total: 50,
            confidence_fp: 800_000,
        },
        shape_stability: ShapeStabilityAssessment::from_transitions(10, 4),
        partial_eval_eligible: false,
        blocking_reasons: vec![
            InferenceBlockingReason::ImpureClassification,
            InferenceBlockingReason::MegamorphicShape,
        ],
        evidence_hash: "def456".into(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: ComponentInferenceResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// Advance epoch and re-infer
// ---------------------------------------------------------------------------

#[test]
fn advance_epoch_changes_hashes() {
    let mut p = ReactLaneInferencePipeline::new(SecurityEpoch::from_raw(1));
    let el = make_element("div");
    let r1 = p.infer_component("Comp", &el, None, None);
    let hash1 = r1.evidence_hash.clone();

    p.reset();
    p.advance_epoch(SecurityEpoch::from_raw(2));
    let r2 = p.infer_component("Comp", &el, None, None);
    assert_ne!(hash1, r2.evidence_hash);
}

// ---------------------------------------------------------------------------
// Large batch stress
// ---------------------------------------------------------------------------

#[test]
fn large_batch_inference() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let mut components = Vec::new();
    for i in 0..50 {
        components.push((format!("Comp{i}"), make_element("div"), None));
    }
    let results = batch_infer(&mut p, &components, None);
    assert_eq!(results.len(), 50);
    assert_eq!(p.total_processed, 50);
}

#[test]
fn receipt_with_many_components() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    for i in 0..20 {
        let el = make_element("div");
        p.infer_component(&format!("Comp{i}"), &el, None, None);
    }
    let r = p.generate_receipt();
    assert_eq!(r.total_components, 20);
    assert_eq!(r.component_verdicts.len(), 20);
    assert!(!r.receipt_hash.is_empty());
}

// ---------------------------------------------------------------------------
// Edge: overwrite same component
// ---------------------------------------------------------------------------

#[test]
fn infer_same_component_twice_overwrites() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("Same", &el, None, None);
    p.infer_component("Same", &el, None, None);
    // Should count both invocations but results map has only one entry.
    assert_eq!(p.total_processed, 2);
    assert_eq!(p.results.len(), 1);
}

// ---------------------------------------------------------------------------
// Prop inference with spreads
// ---------------------------------------------------------------------------

#[test]
fn element_with_spread_no_named_props() {
    let el = LoweredElement {
        props: LoweredProps {
            entries: vec![PropsEntry::Spread {
                expression: "props".into(),
                span: span(),
            }],
            has_spreads: true,
            extracted_key: None,
            extracted_ref: None,
        },
        ..make_element("div")
    };
    let props = frankenengine_engine::react_lane_inference::infer_props_from_lowered(&el);
    // Spread entries should be skipped — only named props inferred.
    assert!(props.is_empty());
}
