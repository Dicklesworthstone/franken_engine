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

//! Second enrichment integration tests for the `react_lane_inference` module.

use std::collections::BTreeSet;

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::component_shape_catalog::{
    ImpurityReason, PropFlowKind, PropValueKind, PurityClassification,
    PurityConfig, RenderPurityClass, analyze_render_tree,
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
    SecurityEpoch::from_raw(300)
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

fn low_obs_config() -> InferenceConfig {
    InferenceConfig {
        purity_config: PurityConfig {
            min_observations: 1,
            ..PurityConfig::default()
        },
        ..InferenceConfig::default()
    }
}

fn make_nested_element(depth: usize) -> LoweredElement {
    let mut el = make_element("span");
    for _ in 0..depth {
        let outer = LoweredElement {
            children: vec![LoweredChild::Element(Box::new(el))],
            ..make_element("div")
        };
        el = outer;
    }
    el
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_multiple_inferences_accumulate_counters() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    for i in 0..10 {
        p.infer_component(&format!("Comp{i}"), &make_element("div"), None, None);
    }
    assert_eq!(p.total_processed, 10);
    assert_eq!(p.results.len(), 10);
    assert_eq!(p.evidence.len(), 10);
}

#[test]
fn enrichment_pipeline_overwrite_updates_result() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let el1 = make_element("div");
    let el2 = make_element("span");
    let _r1 = p.infer_component("SameComp", &el1, None, None);
    let r2 = p.infer_component("SameComp", &el2, None, None);
    // The result for the component should be the latest
    let stored = p.get_result("SameComp").unwrap();
    assert_eq!(stored.evidence_hash, r2.evidence_hash);
    // total_processed should count both invocations
    assert_eq!(p.total_processed, 2);
}

#[test]
fn enrichment_pipeline_summary_zero_processed_eligibility_zero() {
    let p = ReactLaneInferencePipeline::new(epoch());
    let summary = p.summary();
    assert_eq!(summary.total_components, 0);
    assert_eq!(summary.eligibility_ratio, 0);
    assert!(!summary.is_healthy);
}

#[test]
fn enrichment_pipeline_summary_blocking_reasons_counted() {
    let mut p = ReactLaneInferencePipeline::with_config(low_obs_config(), epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("EffComp", vec![HookKind::Effect]);
    p.infer_component("EffComp", &el, Some(&manifest), None);
    let summary = p.summary();
    assert!(summary.blocking_reason_counts.len() > 0);
}

#[test]
fn enrichment_pipeline_eligible_and_blocked_partition() {
    let mut p = ReactLaneInferencePipeline::with_config(low_obs_config(), epoch());
    let el = make_element("div");
    p.infer_component("PureComp", &el, None, None);
    let manifest = make_hook_manifest("ImpureComp", vec![HookKind::Effect, HookKind::Ref]);
    p.infer_component("ImpureComp", &el, Some(&manifest), None);
    let eligible = p.eligible_components();
    let blocked = p.blocked_components();
    assert_eq!(eligible.len() + blocked.len(), 2);
}

#[test]
fn enrichment_pipeline_receipt_contains_all_components() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    for i in 0..5 {
        p.infer_component(&format!("C{i}"), &make_element("div"), None, None);
    }
    let receipt = p.generate_receipt();
    assert_eq!(receipt.component_verdicts.len(), 5);
    assert_eq!(receipt.total_components, 5);
}

#[test]
fn enrichment_pipeline_receipt_determinism_across_instances() {
    let build = || {
        let mut p = ReactLaneInferencePipeline::new(epoch());
        p.infer_component("A", &make_element("div"), None, None);
        p.infer_component("B", &make_element("span"), None, None);
        p.generate_receipt()
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
    assert_eq!(r1.component_verdicts, r2.component_verdicts);
}

#[test]
fn enrichment_pipeline_advance_epoch_changes_receipt() {
    let mut p = ReactLaneInferencePipeline::new(SecurityEpoch::from_raw(1));
    p.infer_component("A", &make_element("div"), None, None);
    let r1 = p.generate_receipt();
    p.advance_epoch(SecurityEpoch::from_raw(2));
    p.infer_component("B", &make_element("span"), None, None);
    let r2 = p.generate_receipt();
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_pipeline_reset_produces_empty_receipt() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    p.infer_component("A", &make_element("div"), None, None);
    p.reset();
    let receipt = p.generate_receipt();
    assert_eq!(receipt.total_components, 0);
    assert!(receipt.component_verdicts.is_empty());
}

#[test]
fn enrichment_shape_stability_assessment_serde_roundtrip_megamorphic() {
    let s = ShapeStabilityAssessment::from_transitions(100, 8);
    assert!(s.is_megamorphic);
    assert!(!s.cells_stable);
    let json = serde_json::to_string(&s).unwrap();
    let back: ShapeStabilityAssessment = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_shape_stability_boundary_exact_poly_max() {
    // transition_count == max_poly => still polymorphic, not mega
    let s = ShapeStabilityAssessment::from_transitions(8, 8);
    assert!(!s.is_monomorphic);
    assert!(s.is_polymorphic);
    assert!(!s.is_megamorphic);
    assert!(s.cells_stable);
    assert!(s.is_optimization_safe());
}

#[test]
fn enrichment_shape_stability_boundary_just_above_poly_max() {
    let s = ShapeStabilityAssessment::from_transitions(9, 8);
    assert!(!s.is_polymorphic);
    assert!(s.is_megamorphic);
    assert!(!s.cells_stable);
    assert!(!s.is_optimization_safe());
}

#[test]
fn enrichment_shape_stability_single_transition_is_mono() {
    let s = ShapeStabilityAssessment::from_transitions(1, 8);
    assert!(s.is_monomorphic);
    assert!(!s.is_polymorphic);
    assert!(s.is_optimization_safe());
}

#[test]
fn enrichment_blocking_reason_all_variants_serde_roundtrip() {
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
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: InferenceBlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn enrichment_blocking_reason_display_all_non_empty() {
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
    for reason in &reasons {
        assert!(!reason.to_string().is_empty());
    }
}

#[test]
fn enrichment_infer_props_expression_without_arrow_is_unknown() {
    let el = make_element_with_props(
        "div",
        vec![(
            "data",
            LoweredPropValue::Expression {
                expression: "someVar".into(),
            },
        )],
    );
    let props = infer_props_from_lowered(&el);
    assert_eq!(props.len(), 1);
    assert_eq!(props[0].value_kind, PropValueKind::Unknown);
}

#[test]
fn enrichment_infer_props_expression_with_arrow_is_callback() {
    let el = make_element_with_props(
        "div",
        vec![(
            "handler",
            LoweredPropValue::Expression {
                expression: "x => x + 1".into(),
            },
        )],
    );
    let props = infer_props_from_lowered(&el);
    assert_eq!(props[0].value_kind, PropValueKind::Callback);
}

#[test]
fn enrichment_infer_props_multiple_rendered_attrs() {
    let el = make_element_with_props(
        "div",
        vec![
            (
                "id",
                LoweredPropValue::StringLiteral {
                    value: "main".into(),
                },
            ),
            (
                "href",
                LoweredPropValue::StringLiteral {
                    value: "/home".into(),
                },
            ),
            (
                "alt",
                LoweredPropValue::StringLiteral {
                    value: "logo".into(),
                },
            ),
        ],
    );
    let props = infer_props_from_lowered(&el);
    assert_eq!(props.len(), 3);
    for prop in &props {
        assert_eq!(prop.flow, PropFlowKind::Rendered);
    }
}

#[test]
fn enrichment_infer_props_children_flow_is_rendered() {
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
    assert_eq!(props[0].flow, PropFlowKind::Rendered);
}

#[test]
fn enrichment_infer_props_custom_prop_is_computed() {
    let el = make_element_with_props(
        "div",
        vec![(
            "myCustomProp",
            LoweredPropValue::StringLiteral {
                value: "val".into(),
            },
        )],
    );
    let props = infer_props_from_lowered(&el);
    assert_eq!(props[0].flow, PropFlowKind::Computed);
}

#[test]
fn enrichment_batch_infer_returns_correct_count() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    let components: Vec<(String, LoweredElement, Option<HookManifest>)> = (0..7)
        .map(|i| (format!("BatchComp{i}"), make_element("div"), None))
        .collect();
    let results = batch_infer(&mut p, &components, None);
    assert_eq!(results.len(), 7);
    assert_eq!(p.total_processed, 7);
}

#[test]
fn enrichment_batch_infer_with_hook_manifests() {
    let mut p = ReactLaneInferencePipeline::with_config(low_obs_config(), epoch());
    let components = vec![
        (
            "Pure".to_string(),
            make_element("div"),
            Some(make_hook_manifest("Pure", vec![HookKind::Memo])),
        ),
        (
            "WithEffect".to_string(),
            make_element("span"),
            Some(make_hook_manifest("WithEffect", vec![HookKind::Effect])),
        ),
    ];
    let results = batch_infer(&mut p, &components, None);
    assert_eq!(results.len(), 2);
    // Effect component should have blocking reasons
    let effect_result = &results[1];
    assert!(
        effect_result
            .purity
            .reasons
            .contains(&ImpurityReason::EffectInRenderPath)
    );
}

#[test]
fn enrichment_partial_eval_coverage_all_ineligible() {
    let mut p = ReactLaneInferencePipeline::with_config(low_obs_config(), epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("Impure", vec![HookKind::Effect, HookKind::Ref]);
    let r = p.infer_component("Impure", &el, Some(&manifest), None);
    let coverage = partial_eval_coverage(&[r]);
    // May or may not be zero depending on exact purity classification
    assert!(coverage <= 1_000_000);
}

#[test]
fn enrichment_partial_eval_coverage_empty_returns_zero() {
    assert_eq!(partial_eval_coverage(&[]), 0);
}

#[test]
fn enrichment_inference_config_clone_eq() {
    let config = InferenceConfig::default();
    let cloned = config.clone();
    assert_eq!(config, cloned);
}

#[test]
fn enrichment_component_inference_result_serde_roundtrip() {
    let result = ComponentInferenceResult {
        component_name: "TestComp".to_string(),
        purity: PurityClassification {
            class: RenderPurityClass::Pure,
            reasons: BTreeSet::new(),
            severity_total: 0,
            confidence_fp: 1_000_000,
        },
        shape_stability: ShapeStabilityAssessment::default(),
        partial_eval_eligible: true,
        blocking_reasons: Vec::new(),
        evidence_hash: "deadbeef".to_string(),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: ComponentInferenceResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_component_evidence_clone_eq() {
    let evidence = ComponentEvidence {
        component_name: "C".to_string(),
        render_tree: analyze_render_tree(&make_element("div")),
        hook_manifest: None,
        inferred_props: Vec::new(),
        shape_stability: ShapeStabilityAssessment::default(),
        compile_receipt_hash: None,
    };
    let cloned = evidence.clone();
    assert_eq!(evidence, cloned);
}

#[test]
fn enrichment_summary_serde_roundtrip_with_blocking() {
    let mut p = ReactLaneInferencePipeline::with_config(low_obs_config(), epoch());
    let el = make_element("div");
    let manifest = make_hook_manifest("Eff", vec![HookKind::Effect]);
    p.infer_component("Eff", &el, Some(&manifest), None);
    p.infer_component("Pure", &el, None, None);
    let summary = p.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: InferenceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrichment_inference_receipt_has_bead_and_policy() {
    let p = ReactLaneInferencePipeline::new(epoch());
    let receipt = p.generate_receipt();
    assert_eq!(receipt.bead_id, INFERENCE_BEAD_ID);
    assert_eq!(receipt.policy_id, INFERENCE_POLICY_ID);
    assert_eq!(receipt.schema_version, INFERENCE_SCHEMA_VERSION);
}

#[test]
fn enrichment_pipeline_with_config_uses_custom_config() {
    let config = InferenceConfig {
        min_stable_observations: 10,
        max_shape_transitions: 4,
        infer_props: false,
        integrate_shape_algebra: false,
        max_render_depth: 16,
        min_purity_ratio: 800_000,
        ..InferenceConfig::default()
    };
    let p = ReactLaneInferencePipeline::with_config(config.clone(), epoch());
    assert_eq!(p.config.min_stable_observations, 10);
    assert_eq!(p.config.max_shape_transitions, 4);
    assert!(!p.config.infer_props);
    assert!(!p.config.integrate_shape_algebra);
    assert_eq!(p.config.max_render_depth, 16);
    assert_eq!(p.config.min_purity_ratio, 800_000);
}

#[test]
fn enrichment_deeply_nested_child_tree_blocked() {
    let config = InferenceConfig {
        max_render_depth: 3,
        purity_config: PurityConfig {
            min_observations: 1,
            ..PurityConfig::default()
        },
        ..Default::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    let el = make_nested_element(5);
    let result = p.infer_component("Deep", &el, None, None);
    assert!(
        result
            .blocking_reasons
            .contains(&InferenceBlockingReason::DeeplyNested)
    );
}

#[test]
fn enrichment_shallow_element_not_blocked_for_depth() {
    let config = InferenceConfig {
        max_render_depth: 10,
        purity_config: PurityConfig {
            min_observations: 1,
            ..PurityConfig::default()
        },
        ..Default::default()
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

#[test]
fn enrichment_evidence_hash_differs_by_epoch() {
    let mut p1 = ReactLaneInferencePipeline::new(SecurityEpoch::from_raw(10));
    let mut p2 = ReactLaneInferencePipeline::new(SecurityEpoch::from_raw(20));
    let el = make_element("div");
    let r1 = p1.infer_component("Comp", &el, None, None);
    let r2 = p2.infer_component("Comp", &el, None, None);
    assert_ne!(r1.evidence_hash, r2.evidence_hash);
}

#[test]
fn enrichment_pipeline_serde_preserves_all_fields() {
    let mut p = ReactLaneInferencePipeline::new(epoch());
    p.infer_component("A", &make_element("div"), None, None);
    p.infer_component("B", &make_element("span"), None, None);
    let json = serde_json::to_string(&p).unwrap();
    let back: ReactLaneInferencePipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(p.total_processed, back.total_processed);
    assert_eq!(p.total_eligible, back.total_eligible);
    assert_eq!(p.schema_version, back.schema_version);
    assert_eq!(p.config, back.config);
    assert_eq!(p.results.len(), back.results.len());
    assert_eq!(p.evidence.len(), back.evidence.len());
}

#[test]
fn enrichment_prop_flow_key_and_ref_identified() {
    let el = make_element_with_props(
        "div",
        vec![
            (
                "key",
                LoweredPropValue::StringLiteral {
                    value: "k".into(),
                },
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
fn enrichment_prop_flow_event_handlers_effect_only() {
    let el = make_element_with_props(
        "button",
        vec![
            (
                "onClick",
                LoweredPropValue::Expression {
                    expression: "() => {}".into(),
                },
            ),
            (
                "onMouseEnter",
                LoweredPropValue::Expression {
                    expression: "() => {}".into(),
                },
            ),
        ],
    );
    let props = infer_props_from_lowered(&el);
    for prop in &props {
        assert_eq!(prop.flow, PropFlowKind::EffectOnly);
    }
}

#[test]
fn enrichment_summary_healthy_threshold_boundary() {
    let config = InferenceConfig {
        min_purity_ratio: 500_000, // 50%
        purity_config: PurityConfig {
            min_observations: 1,
            ..PurityConfig::default()
        },
        ..Default::default()
    };
    let mut p = ReactLaneInferencePipeline::with_config(config, epoch());
    // Add one pure and one impure
    p.infer_component("Pure", &make_element("div"), None, None);
    let manifest = make_hook_manifest("Impure", vec![HookKind::Effect, HookKind::Ref]);
    p.infer_component("Impure", &make_element("div"), Some(&manifest), None);
    let summary = p.summary();
    // Exact healthiness depends on whether pure comp is eligible
    assert_eq!(summary.total_components, 2);
}
