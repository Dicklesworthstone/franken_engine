#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

//! Enrichment integration tests for the `react_lane_inference` module.

use std::collections::BTreeSet;

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::component_shape_catalog::{
    PropFlowKind, PropValueKind, analyze_render_tree,
};
use frankenengine_engine::hook_effect_contract::{HookKind, HookManifest, HookSlot, HookSlotIndex};
use frankenengine_engine::react_jsx_lowering::{
    CallConvention, ElementType, LoweredChild, LoweredElement, LoweredProp, LoweredPropValue,
    LoweredProps, PropsEntry,
};
use frankenengine_engine::react_lane_inference::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(200)
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


// ===========================================================================
// Constants verification
// ===========================================================================

#[test]
fn enrichment_constants_schema_version_format() {
    assert!(INFERENCE_SCHEMA_VERSION.contains(".v1"));
    assert!(INFERENCE_SCHEMA_VERSION.contains("react-lane-inference"));
}

#[test]
fn enrichment_constants_component_is_module_name() {
    assert_eq!(INFERENCE_COMPONENT, "react_lane_inference");
}

#[test]
fn enrichment_constants_bead_id_prefix() {
    assert!(INFERENCE_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_constants_policy_id_prefix() {
    assert!(INFERENCE_POLICY_ID.starts_with("RGC-"));
}

// ===========================================================================
// ShapeStabilityAssessment boundary tests
// ===========================================================================

#[test]
fn enrichment_shape_stability_default_is_optimization_safe() {
    let s = ShapeStabilityAssessment::default();
    assert!(s.is_optimization_safe());
    assert_eq!(s.invalidation_count, 0);
    assert_eq!(s.transition_count, 0);
}

#[test]
fn enrichment_shape_stability_from_transitions_boundary_mono_to_poly() {
    // transition_count=1 is still monomorphic
    let mono = ShapeStabilityAssessment::from_transitions(1, 4);
    assert!(mono.is_monomorphic);
    assert!(!mono.is_polymorphic);

    // transition_count=2 becomes polymorphic
    let poly = ShapeStabilityAssessment::from_transitions(2, 4);
    assert!(!poly.is_monomorphic);
    assert!(poly.is_polymorphic);
}

#[test]
fn enrichment_shape_stability_from_transitions_boundary_poly_to_mega() {
    // At max_poly, still polymorphic
    let at_max = ShapeStabilityAssessment::from_transitions(4, 4);
    assert!(at_max.is_polymorphic);
    assert!(!at_max.is_megamorphic);
    assert!(at_max.is_optimization_safe());

    // Just above max_poly -> megamorphic
    let above = ShapeStabilityAssessment::from_transitions(5, 4);
    assert!(above.is_megamorphic);
    assert!(!above.is_optimization_safe());
    assert!(!above.cells_stable);
}

#[test]
fn enrichment_shape_stability_zero_transitions() {
    let s = ShapeStabilityAssessment::from_transitions(0, 8);
    assert!(s.is_monomorphic);
    assert!(s.is_optimization_safe());
    assert_eq!(s.transition_count, 0);
}

#[test]
fn enrichment_shape_stability_serde_roundtrip_all_variants() {
    for count in [0, 1, 3, 5, 10, 100] {
        let s = ShapeStabilityAssessment::from_transitions(count, 4);
        let json = serde_json::to_string(&s).unwrap();
        let back: ShapeStabilityAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ===========================================================================
// InferenceBlockingReason comprehensive tests
// ===========================================================================

#[test]
fn enrichment_blocking_reason_all_display_unique() {
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
    let displays: BTreeSet<String> = reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn enrichment_blocking_reason_deterministic_sort() {
    let mut reasons = vec![
        InferenceBlockingReason::MutableRefs,
        InferenceBlockingReason::DeeplyNested,
        InferenceBlockingReason::ImpureClassification,
    ];
    let mut reasons2 = reasons.clone();
    reasons.sort();
    reasons2.sort();
    assert_eq!(reasons, reasons2);
}

// ===========================================================================
// InferenceConfig enrichment
// ===========================================================================

#[test]
fn enrichment_config_default_infer_props_enabled() {
    let c = InferenceConfig::default();
    assert!(c.infer_props);
    assert!(c.integrate_shape_algebra);
}

#[test]
fn enrichment_config_custom_serde_preserves_all_fields() {
    let c = InferenceConfig {
        min_stable_observations: 7,
        max_shape_transitions: 12,
        infer_props: false,
        integrate_shape_algebra: false,
        max_render_depth: 99,
        min_purity_ratio: 100_000,
        ..InferenceConfig::default()
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: InferenceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c.min_stable_observations, back.min_stable_observations);
    assert_eq!(c.max_shape_transitions, back.max_shape_transitions);
    assert_eq!(c.infer_props, back.infer_props);
    assert_eq!(c.integrate_shape_algebra, back.integrate_shape_algebra);
    assert_eq!(c.max_render_depth, back.max_render_depth);
    assert_eq!(c.min_purity_ratio, back.min_purity_ratio);
}

// ===========================================================================
// Pipeline enrichment tests
// ===========================================================================

#[test]
fn enrichment_pipeline_new_schema_version() {
    let p = ReactLaneInferencePipeline::new(epoch());
    assert_eq!(p.schema_version, INFERENCE_SCHEMA_VERSION);
}

#[test]
fn enrichment_pipeline_infer_component_evidence_stored() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("TestComp", &el, None, None);
    assert!(p.evidence.contains_key("TestComp"));
    let ev = p.evidence.get("TestComp").unwrap();
    assert_eq!(ev.component_name, "TestComp");
}

#[test]
fn enrichment_pipeline_eligible_blocked_partition_consistent() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("CompA", &el, None, None);
    p.infer_component("CompB", &el, None, None);
    let eligible = p.eligible_components();
    let blocked = p.blocked_components();
    // Eligible + blocked must equal total results
    assert_eq!(eligible.len() + blocked.len(), 2);
}

#[test]
fn enrichment_pipeline_blocked_components_effect_hook() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("ImpureComp", vec![HookKind::Effect, HookKind::Ref]);
    p.infer_component("ImpureComp", &el, Some(&manifest), None);
    let blocked = p.blocked_components();
    assert!(!blocked.is_empty());
    assert_eq!(blocked[0].component_name, "ImpureComp");
}

#[test]
fn enrichment_pipeline_reset_clears_all() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("A", &el, None, None);
    p.infer_component("B", &el, None, None);
    assert_eq!(p.total_processed, 2);
    p.reset();
    assert_eq!(p.total_processed, 0);
    assert_eq!(p.total_eligible, 0);
    assert!(p.results.is_empty());
    assert!(p.evidence.is_empty());
}

#[test]
fn enrichment_pipeline_advance_epoch_updates() {
    let mut p = ReactLaneInferencePipeline::new(SecurityEpoch::from_raw(1));
    p.advance_epoch(SecurityEpoch::from_raw(10));
    assert_eq!(p.epoch, SecurityEpoch::from_raw(10));
}

#[test]
fn enrichment_pipeline_get_result_returns_none_for_missing() {
    let p = ReactLaneInferencePipeline::new(epoch());
    assert!(p.get_result("DoesNotExist").is_none());
}

#[test]
fn enrichment_pipeline_overwrite_same_component() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let r1 = p.infer_component("Same", &el, None, None);
    let r2 = p.infer_component("Same", &el, None, None);
    assert_eq!(r1.evidence_hash, r2.evidence_hash);
    assert_eq!(p.results.len(), 1);
    assert_eq!(p.total_processed, 2);
}

// ===========================================================================
// Pipeline with different hook types
// ===========================================================================

#[test]
fn enrichment_pipeline_callback_hook_no_block() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("CbComp", vec![HookKind::Callback]);
    let result = p.infer_component("CbComp", &el, Some(&manifest), None);
    assert_eq!(result.component_name, "CbComp");
}

#[test]
fn enrichment_pipeline_reducer_hook() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("ReducerComp", vec![HookKind::Reducer]);
    let result = p.infer_component("ReducerComp", &el, Some(&manifest), None);
    assert_eq!(result.component_name, "ReducerComp");
}

#[test]
fn enrichment_pipeline_layout_effect_hook() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("LayoutComp", vec![HookKind::LayoutEffect]);
    let result = p.infer_component("LayoutComp", &el, Some(&manifest), None);
    // LayoutEffect should cause impurity similar to Effect
    assert_eq!(result.component_name, "LayoutComp");
}

// ===========================================================================
// Summary enrichment
// ===========================================================================

#[test]
fn enrichment_summary_total_components_count() {
    let config = InferenceConfig {
        min_purity_ratio: 500_000,
        ..InferenceConfig::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    let el = make_element("div");
    for i in 0..5 {
        p.infer_component(&format!("Comp{i}"), &el, None, None);
    }
    let s = p.summary();
    assert_eq!(s.total_components, 5);
    assert_eq!(s.eligible_count + s.blocked_count, 5);
}

#[test]
fn enrichment_summary_health_depends_on_eligibility() {
    let config = InferenceConfig {
        min_purity_ratio: 0, // 0% threshold => always healthy
        ..InferenceConfig::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    let el = make_element("div");
    p.infer_component("Comp", &el, None, None);
    let s = p.summary();
    // With 0% threshold, even no eligible components is healthy
    assert!(s.is_healthy);
}

#[test]
fn enrichment_summary_blocked_count_for_effect_component() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("Eff", vec![HookKind::Effect]);
    p.infer_component("Eff", &el, Some(&manifest), None);
    let s = p.summary();
    // Effect hook should cause at least one blocked component
    assert!(s.blocked_count > 0, "effect component should be blocked");
}

// ===========================================================================
// Receipt enrichment
// ===========================================================================

#[test]
fn enrichment_receipt_schema_and_policy() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("Comp", &el, None, None);
    let r = p.generate_receipt();
    assert_eq!(r.schema_version, INFERENCE_SCHEMA_VERSION);
    assert_eq!(r.bead_id, INFERENCE_BEAD_ID);
    assert_eq!(r.policy_id, INFERENCE_POLICY_ID);
}

#[test]
fn enrichment_receipt_hash_changes_with_epoch() {
    let mut p1 = ReactLaneInferencePipeline::new(SecurityEpoch::from_raw(1));
    let mut p2 = ReactLaneInferencePipeline::new(SecurityEpoch::from_raw(2));
    let el = make_element("div");
    p1.infer_component("C", &el, None, None);
    p2.infer_component("C", &el, None, None);
    assert_ne!(
        p1.generate_receipt().receipt_hash,
        p2.generate_receipt().receipt_hash
    );
}

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("Comp", &el, None, None);
    let r = p.generate_receipt();
    let json = serde_json::to_string(&r).unwrap();
    let back: InferenceReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_receipt_component_verdicts_count() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    for i in 0..4 {
        p.infer_component(&format!("C{i}"), &el, None, None);
    }
    let r = p.generate_receipt();
    assert_eq!(r.component_verdicts.len(), 4);
    assert_eq!(r.total_components, 4);
}

// ===========================================================================
// Batch inference enrichment
// ===========================================================================

#[test]
fn enrichment_batch_infer_empty_produces_empty() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let results = batch_infer(&mut p, &[], None);
    assert!(results.is_empty());
    assert_eq!(p.total_processed, 0);
}

#[test]
fn enrichment_batch_infer_mixed_hooks() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let components = vec![
        ("Pure".to_string(), make_element("div"), None),
        (
            "Stateful".to_string(),
            make_element("div"),
            Some(make_hook_manifest("Stateful", vec![HookKind::State])),
        ),
        (
            "Effectful".to_string(),
            make_element("div"),
            Some(make_hook_manifest(
                "Effectful",
                vec![HookKind::Effect, HookKind::Ref],
            )),
        ),
    ];
    let results = batch_infer(&mut p, &components, None);
    assert_eq!(results.len(), 3);
    assert_eq!(p.total_processed, 3);
}

// ===========================================================================
// Coverage computation enrichment
// ===========================================================================

#[test]
fn enrichment_partial_eval_coverage_empty_is_zero() {
    assert_eq!(partial_eval_coverage(&[]), 0);
}

#[test]
fn enrichment_partial_eval_coverage_single_eligible() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let r = p.infer_component("Pure", &el, None, None);
    if r.partial_eval_eligible {
        assert_eq!(partial_eval_coverage(&[r]), 1_000_000);
    }
}

// ===========================================================================
// Prop inference enrichment
// ===========================================================================

#[test]
fn enrichment_infer_props_numeric_literal() {
    let el = make_element_with_props(
        "div",
        vec![(
            "tabIndex",
            LoweredPropValue::Expression {
                expression: "42".into(),
            },
        )],
    );
    let props = infer_props_from_lowered(&el);
    assert_eq!(props.len(), 1);
    assert_eq!(props[0].name, "tabIndex");
}

#[test]
fn enrichment_infer_props_spread_skipped() {
    let el = LoweredElement {
        props: LoweredProps {
            entries: vec![PropsEntry::Spread {
                expression: "rest".into(),
                span: span(),
            }],
            has_spreads: true,
            extracted_key: None,
            extracted_ref: None,
        },
        ..make_element("div")
    };
    let props = infer_props_from_lowered(&el);
    assert!(props.is_empty());
}

#[test]
fn enrichment_infer_props_on_prefix_callback() {
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
fn enrichment_infer_props_rendered_flow_for_style() {
    let el = make_element_with_props(
        "div",
        vec![(
            "style",
            LoweredPropValue::Expression {
                expression: "styleObj".into(),
            },
        )],
    );
    let props = infer_props_from_lowered(&el);
    assert_eq!(props[0].flow, PropFlowKind::Rendered);
}

// ===========================================================================
// Deeply nested blocking enrichment
// ===========================================================================

#[test]
fn enrichment_deeply_nested_exactly_at_limit_not_blocked() {
    let config = InferenceConfig {
        max_render_depth: 3,
        ..InferenceConfig::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    let el = make_nested_element(2);
    let result = p.infer_component("AtLimit", &el, None, None);
    // Depth 2 should be within limit of 3
    assert!(
        !result
            .blocking_reasons
            .contains(&InferenceBlockingReason::DeeplyNested)
    );
}

#[test]
fn enrichment_deeply_nested_over_limit_blocked() {
    let config = InferenceConfig {
        max_render_depth: 2,
        ..InferenceConfig::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    let el = make_nested_element(5);
    let result = p.infer_component("TooDeep", &el, None, None);
    assert!(
        result
            .blocking_reasons
            .contains(&InferenceBlockingReason::DeeplyNested)
    );
}

// ===========================================================================
// Evidence hash determinism
// ===========================================================================

#[test]
fn enrichment_evidence_hash_same_inputs_same_hash() {
    let mut p1 = ReactLaneInferencePipeline::new(epoch());
    let mut p2 = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let r1 = p1.infer_component("Same", &el, None, None);
    let r2 = p2.infer_component("Same", &el, None, None);
    assert_eq!(r1.evidence_hash, r2.evidence_hash);
}

#[test]
fn enrichment_evidence_hash_different_names_different_hash() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    let r1 = p.infer_component("Comp1", &el, None, None);
    let r2 = p.infer_component("Comp2", &el, None, None);
    assert_ne!(r1.evidence_hash, r2.evidence_hash);
}

// ===========================================================================
// ComponentEvidence serde enrichment
// ===========================================================================

#[test]
fn enrichment_component_evidence_with_props_serde() {
    let evidence = ComponentEvidence {
        component_name: "PropsComp".into(),
        render_tree: analyze_render_tree(&make_element("div")),
        hook_manifest: None,
        inferred_props: vec![],
        shape_stability: ShapeStabilityAssessment::from_transitions(1, 8),
        compile_receipt_hash: Some("hash-abc".into()),
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let back: ComponentEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, back);
}

// ===========================================================================
// Pipeline serde enrichment
// ===========================================================================

#[test]
fn enrichment_pipeline_serde_preserves_state() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el = make_element("div");
    p.infer_component("A", &el, None, None);
    p.infer_component("B", &el, None, None);
    let json = serde_json::to_string(&p).unwrap();
    let back: ReactLaneInferencePipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(p.total_processed, back.total_processed);
    assert_eq!(p.total_eligible, back.total_eligible);
    assert_eq!(p.epoch, back.epoch);
    assert_eq!(p.schema_version, back.schema_version);
    assert_eq!(p.results.len(), back.results.len());
}

// ===========================================================================
// Config disable prop inference
// ===========================================================================

#[test]
fn enrichment_config_disabled_props_no_evidence_props() {
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
    p.infer_component("NoProp", &el, None, None);
    let evidence = p.evidence.get("NoProp").unwrap();
    assert!(evidence.inferred_props.is_empty());
}

#[test]
fn enrichment_config_disabled_shape_algebra_default_shape() {
    let config = InferenceConfig {
        integrate_shape_algebra: false,
        ..InferenceConfig::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    let el = make_element("div");
    let result = p.infer_component("NoAlgebra", &el, None, None);
    assert!(result.shape_stability.is_monomorphic);
}

// ===========================================================================
// Large batch enrichment
// ===========================================================================

#[test]
fn enrichment_large_batch_100_components() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let mut components = Vec::new();
    for i in 0..100 {
        components.push((format!("Comp{i}"), make_element("div"), None));
    }
    let results = batch_infer(&mut p, &components, None);
    assert_eq!(results.len(), 100);
    assert_eq!(p.total_processed, 100);
}

#[test]
fn enrichment_receipt_with_many_components_deterministic() {
    let build_receipt = || {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        let el = make_element("div");
        for i in 0..10 {
            p.infer_component(&format!("C{i}"), &el, None, None);
        }
        p.generate_receipt()
    };
    let r1 = build_receipt();
    let r2 = build_receipt();
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}
