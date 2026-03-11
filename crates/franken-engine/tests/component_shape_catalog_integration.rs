//! Integration tests for component_shape_catalog module.
//!
//! Bead: bd-1lsy.7.9.1 [RGC-609A]

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy
)]

use frankenengine_engine::component_shape_catalog::*;
use frankenengine_engine::hook_effect_contract::{HookKind, HookManifest, HookSlot};
use frankenengine_engine::react_jsx_lowering::{
    CallConvention, ElementType, LoweredChild, LoweredElement, LoweredPropValue, LoweredProps,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_manifest(hooks: &[HookKind]) -> HookManifest {
    HookManifest {
        component_name: "TestComponent".to_string(),
        slots: hooks
            .iter()
            .enumerate()
            .map(|(i, kind)| HookSlot {
                index: frankenengine_engine::hook_effect_contract::HookSlotIndex(i as u32),
                kind: *kind,
                deps: None,
            })
            .collect(),
        version: 1,
    }
}

fn make_element(tag: &str) -> LoweredElement {
    LoweredElement {
        element_type: ElementType::Intrinsic {
            tag: tag.to_string(),
        },
        props: LoweredProps {
            entries: vec![],
            has_spreads: false,
            extracted_key: None,
            extracted_ref: None,
        },
        children: vec![],
        call_convention: CallConvention::Classic {
            object: "React".to_string(),
            method: "createElement".to_string(),
        },
        source_location: None,
        is_static_children: false,
        depth: 0,
        span: frankenengine_engine::ast::SourceSpan::new(0, 0, 1, 1, 1, 1),
    }
}

fn make_component_element(name: &str) -> LoweredElement {
    let mut el = make_element("div");
    el.element_type = ElementType::Component {
        name: name.to_string(),
    };
    el
}

fn make_fragment() -> LoweredElement {
    let mut el = make_element("div");
    el.element_type = ElementType::Fragment;
    el
}

fn pure_shape(name: &str) -> ComponentShape {
    let mut shape = ComponentShape::new(name);
    shape.observation_count = 10;
    shape
}

fn impure_shape(name: &str) -> ComponentShape {
    let mut shape = ComponentShape::new(name);
    shape.observation_count = 10;
    shape.hook_profile.effect_hooks = 2;
    shape
}

// ---------------------------------------------------------------------------
// Catalog lifecycle
// ---------------------------------------------------------------------------

#[test]
fn catalog_lifecycle_register_and_query() {
    let mut catalog = ComponentShapeCatalog::new();

    let s1 = pure_shape("Header");
    let s2 = impure_shape("Sidebar");
    catalog.register(s1);
    catalog.register(s2);

    assert_eq!(catalog.component_count(), 2);
    assert!(catalog.get("Header").is_some());
    assert!(catalog.get("Sidebar").is_some());
    assert!(catalog.get("Missing").is_none());
}

#[test]
fn catalog_register_multiple_observations() {
    let mut catalog = ComponentShapeCatalog::new();

    for _ in 0..5 {
        catalog.register(pure_shape("Button"));
    }

    assert_eq!(catalog.component_count(), 1);
    let btn = catalog.get("Button").unwrap();
    assert!(btn.observation_count >= 5);
}

#[test]
fn catalog_from_evidence_integration() {
    let mut catalog = ComponentShapeCatalog::new();

    let manifest = make_manifest(&[HookKind::State, HookKind::Effect, HookKind::Memo]);
    let mut root = make_element("div");
    root.children
        .push(LoweredChild::Element(Box::new(make_element("span"))));
    root.children
        .push(LoweredChild::Element(Box::new(make_component_element(
            "Child",
        ))));
    let tree_analysis = analyze_render_tree(&root);

    catalog.register_from_evidence("Parent", &manifest, &tree_analysis);

    let shape = catalog.get("Parent").unwrap();
    assert_eq!(shape.hook_profile.state_hooks, 1);
    assert_eq!(shape.hook_profile.effect_hooks, 1);
    assert_eq!(shape.hook_profile.memo_hooks, 1);
    assert!(shape.children_element_types.contains("Child"));
    assert!(shape.children_element_types.contains("span"));
}

// ---------------------------------------------------------------------------
// Purity classification integration
// ---------------------------------------------------------------------------

#[test]
fn pure_stateless_component() {
    let mut catalog = ComponentShapeCatalog::new();
    let manifest = make_manifest(&[]);
    let tree = analyze_render_tree(&make_element("div"));
    catalog.register_from_evidence("Stateless", &manifest, &tree);

    let shape = catalog.get("Stateless").unwrap();
    // With default config, 1 observation < min_observations (5), so Unknown.
    assert_eq!(shape.render_purity, RenderPurityClass::Unknown);
}

#[test]
fn pure_stateless_with_enough_observations() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);
    let manifest = make_manifest(&[]);
    let tree = analyze_render_tree(&make_element("div"));
    catalog.register_from_evidence("Stateless", &manifest, &tree);

    let shape = catalog.get("Stateless").unwrap();
    assert_eq!(shape.render_purity, RenderPurityClass::Pure);
}

#[test]
fn impure_effect_component() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);
    let manifest = make_manifest(&[HookKind::Effect]);
    let tree = analyze_render_tree(&make_element("div"));
    catalog.register_from_evidence("EffectComp", &manifest, &tree);

    let shape = catalog.get("EffectComp").unwrap();
    assert_eq!(shape.render_purity, RenderPurityClass::Impure);
    assert!(
        shape
            .impurity_reasons
            .contains(&ImpurityReason::EffectInRenderPath)
    );
}

#[test]
fn conditionally_pure_with_spread() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);
    let manifest = make_manifest(&[HookKind::State]);
    let mut el = make_element("div");
    el.props.has_spreads = true;
    let tree = analyze_render_tree(&el);
    catalog.register_from_evidence("SpreadComp", &manifest, &tree);

    let shape = catalog.get("SpreadComp").unwrap();
    assert_eq!(shape.render_purity, RenderPurityClass::ConditionallyPure);
    assert!(
        shape
            .impurity_reasons
            .contains(&ImpurityReason::SpreadProps)
    );
}

#[test]
fn context_dependency_classification() {
    let config = PurityConfig {
        min_observations: 1,
        max_conditional_severity: 600_000,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);
    let manifest = make_manifest(&[HookKind::Context]);
    let tree = analyze_render_tree(&make_element("div"));
    catalog.register_from_evidence("CtxComp", &manifest, &tree);

    let shape = catalog.get("CtxComp").unwrap();
    assert_eq!(shape.render_purity, RenderPurityClass::ConditionallyPure);
    assert!(
        shape
            .impurity_reasons
            .contains(&ImpurityReason::ContextDependency)
    );
}

#[test]
fn conditional_hooks_always_impure() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);
    let mut shape = ComponentShape::new("BadHooks");
    shape.hook_profile.has_conditional_hooks = true;
    catalog.register(shape);

    let s = catalog.get("BadHooks").unwrap();
    assert_eq!(s.render_purity, RenderPurityClass::Impure);
}

// ---------------------------------------------------------------------------
// Render tree analysis
// ---------------------------------------------------------------------------

#[test]
fn simple_tree_analysis() {
    let el = make_element("button");
    let analysis = analyze_render_tree(&el);
    assert!(analysis.is_simple());
    assert_eq!(analysis.total_elements, 1);
    assert!(!analysis.has_component_children());
}

#[test]
fn complex_tree_analysis() {
    let mut root = make_element("div");
    let mut section = make_element("section");
    let mut article = make_element("article");
    article
        .children
        .push(LoweredChild::Element(Box::new(make_element("p"))));
    article
        .children
        .push(LoweredChild::Element(Box::new(make_component_element(
            "Highlight",
        ))));
    section
        .children
        .push(LoweredChild::Element(Box::new(article)));
    root.children.push(LoweredChild::Element(Box::new(section)));
    root.children
        .push(LoweredChild::Element(Box::new(make_component_element(
            "Footer",
        ))));

    let analysis = analyze_render_tree(&root);
    assert_eq!(analysis.total_elements, 6);
    assert_eq!(analysis.intrinsic_count, 4);
    assert_eq!(analysis.component_count, 2);
    assert_eq!(analysis.max_depth, 3);
    assert!(analysis.has_component_children());
    assert!(analysis.component_refs.contains("Highlight"));
    assert!(analysis.component_refs.contains("Footer"));
}

#[test]
fn fragment_tree_analysis() {
    let mut root = make_fragment();
    root.children
        .push(LoweredChild::Element(Box::new(make_element("h1"))));
    root.children
        .push(LoweredChild::Element(Box::new(make_element("p"))));

    let analysis = analyze_render_tree(&root);
    assert_eq!(analysis.fragment_count, 1);
    assert_eq!(analysis.intrinsic_count, 2);
    assert_eq!(analysis.total_elements, 3);
}

#[test]
fn keyed_list_analysis() {
    let mut ul = make_element("ul");
    for i in 0..10 {
        let mut li = make_element("li");
        li.props.extracted_key = Some(LoweredPropValue::StringLiteral {
            value: format!("key-{i}"),
        });
        ul.children.push(LoweredChild::Element(Box::new(li)));
    }

    let analysis = analyze_render_tree(&ul);
    assert_eq!(analysis.keyed_elements, 10);
    assert_eq!(analysis.total_elements, 11);
}

#[test]
fn spread_detection_in_tree() {
    let mut el = make_element("input");
    el.props.has_spreads = true;

    let analysis = analyze_render_tree(&el);
    assert!(analysis.has_spreads);
    assert!(!analysis.is_simple());
}

// ---------------------------------------------------------------------------
// Prop analysis
// ---------------------------------------------------------------------------

#[test]
fn prop_flow_classification() {
    let rendered = PropDescriptor::new(
        "title",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    );
    let callback =
        PropDescriptor::new("onClick", PropValueKind::Callback, PropFlowKind::EffectOnly);
    let forwarded = PropDescriptor::new("style", PropValueKind::Object, PropFlowKind::PassedDown);

    assert!(rendered.is_render_relevant());
    assert!(!callback.is_render_relevant());
    assert!(forwarded.is_render_relevant());
}

#[test]
fn prop_dedup_preserves_non_unknown_type() {
    let mut shape = ComponentShape::new("Dedup");
    shape.add_prop(PropDescriptor::new(
        "data",
        PropValueKind::Unknown,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "data",
        PropValueKind::Array,
        PropFlowKind::Rendered,
    ));
    shape.add_prop(PropDescriptor::new(
        "data",
        PropValueKind::Unknown,
        PropFlowKind::Rendered,
    ));

    assert_eq!(shape.prop_count(), 1);
    assert_eq!(shape.props[0].value_kind, PropValueKind::Array);
    assert_eq!(shape.props[0].observation_count, 3);
}

#[test]
fn high_arity_detection() {
    let mut shape = ComponentShape::new("BigForm");
    for i in 0..15 {
        shape.add_prop(PropDescriptor::new(
            &format!("field_{i}"),
            PropValueKind::StringLiteral,
            PropFlowKind::Rendered,
        ));
    }
    assert!(shape.is_high_arity());
    assert_eq!(shape.prop_count(), 15);
}

// ---------------------------------------------------------------------------
// Hook profile analysis
// ---------------------------------------------------------------------------

#[test]
fn hook_profile_comprehensive() {
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
        HookKind::Transition,
        HookKind::Id,
        HookKind::SyncExternalStore,
    ]);
    let profile = HookProfile::from_manifest(&manifest);

    assert_eq!(profile.total_hooks, 15);
    assert_eq!(profile.state_hooks, 2); // State + Reducer
    assert_eq!(profile.effect_hooks, 3); // Effect + LayoutEffect + InsertionEffect
    assert_eq!(profile.memo_hooks, 2); // Memo + DeferredValue
    assert_eq!(profile.ref_hooks, 2); // Ref + ImperativeHandle
    assert_eq!(profile.context_hooks, 1);
    assert_eq!(profile.callback_hooks, 1);
    assert_eq!(profile.other_hooks, 4); // DebugValue + Transition + Id + SyncExternalStore

    assert!(profile.has_effects());
    assert!(!profile.is_stateless());
    assert!(profile.reads_context());
    assert!(profile.uses_refs());
}

#[test]
fn hook_profile_stateless_memo_only() {
    let manifest = make_manifest(&[HookKind::Memo, HookKind::Callback]);
    let profile = HookProfile::from_manifest(&manifest);

    assert!(profile.is_stateless());
    assert!(!profile.has_effects());
    assert_eq!(profile.memo_hooks, 1);
    assert_eq!(profile.callback_hooks, 1);
}

// ---------------------------------------------------------------------------
// Catalog queries
// ---------------------------------------------------------------------------

#[test]
fn catalog_pure_vs_impure_filtering() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);

    // Register pure components.
    for name in ["Icon", "Badge", "Divider", "Spacer"] {
        catalog.register(pure_shape(name));
    }

    // Register impure components.
    for name in ["Timer", "DataFetcher"] {
        catalog.register(impure_shape(name));
    }

    assert_eq!(catalog.pure_components().len(), 4);
    assert_eq!(catalog.impure_components().len(), 2);
    assert_eq!(catalog.partial_eval_eligible().len(), 4);
}

#[test]
fn catalog_summary_comprehensive() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);

    catalog.register(pure_shape("A"));
    catalog.register(pure_shape("B"));
    catalog.register(impure_shape("C"));

    // Conditionally pure.
    let mut spread = ComponentShape::new("D");
    spread.observation_count = 10;
    spread.has_spread_props = true;
    catalog.register(spread);

    let summary = catalog.summary();
    assert_eq!(summary.total_components, 4);
    assert_eq!(summary.pure_count, 2);
    assert_eq!(summary.impure_count, 1);
    assert_eq!(summary.conditionally_pure_count, 1);
    assert!(summary.purity_ratio_fp == 500_000); // 2/4 = 0.5
}

#[test]
fn catalog_receipt_deterministic() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);
    catalog.register(pure_shape("X"));
    catalog.register(pure_shape("Y"));

    let r1 = catalog.generate_receipt();
    let r2 = catalog.generate_receipt();
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn catalog_receipt_changes_with_different_data() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };

    let mut cat1 = ComponentShapeCatalog::with_config(config.clone());
    cat1.register(pure_shape("A"));
    let r1 = cat1.generate_receipt();

    let mut cat2 = ComponentShapeCatalog::with_config(config);
    cat2.register(pure_shape("B"));
    let r2 = cat2.generate_receipt();

    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

// ---------------------------------------------------------------------------
// Reclassification
// ---------------------------------------------------------------------------

#[test]
fn reclassify_with_new_config() {
    let config = PurityConfig {
        min_observations: 1,
        max_conditional_severity: 400_000,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);

    let mut shape = ComponentShape::new("CtxUser");
    shape.observation_count = 10;
    shape.hook_profile.context_hooks = 1;
    catalog.register(shape);

    // Context weight = 500_000 > 400_000 => Impure.
    assert_eq!(
        catalog.get("CtxUser").unwrap().render_purity,
        RenderPurityClass::Impure
    );

    // Relax config and reclassify.
    catalog.config.max_conditional_severity = 600_000;
    catalog.reclassify_all();
    assert_eq!(
        catalog.get("CtxUser").unwrap().render_purity,
        RenderPurityClass::ConditionallyPure
    );
}

#[test]
fn reclassify_preserves_component_count() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);
    catalog.register(pure_shape("A"));
    catalog.register(impure_shape("B"));

    let count_before = catalog.component_count();
    catalog.reclassify_all();
    assert_eq!(catalog.component_count(), count_before);
}

// ---------------------------------------------------------------------------
// Epoch management
// ---------------------------------------------------------------------------

#[test]
fn epoch_advancement() {
    let mut catalog = ComponentShapeCatalog::new();
    assert_eq!(catalog.analysis_epoch, 0);

    catalog.advance_epoch();
    assert_eq!(catalog.analysis_epoch, 1);

    catalog.advance_epoch();
    assert_eq!(catalog.analysis_epoch, 2);

    let receipt = catalog.generate_receipt();
    assert_eq!(receipt.epoch, 2);
}

// ---------------------------------------------------------------------------
// Partial evaluation eligibility
// ---------------------------------------------------------------------------

#[test]
fn partial_eval_requires_purity_and_no_spread() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);

    // Pure + no spread => eligible.
    catalog.register(pure_shape("Eligible"));
    assert!(catalog.get("Eligible").unwrap().is_partial_eval_eligible());

    // Pure + spread => not eligible.
    let mut spread = pure_shape("Spread");
    spread.has_spread_props = true;
    catalog.register(spread);
    assert!(!catalog.get("Spread").unwrap().is_partial_eval_eligible());

    // Impure + no spread => not eligible.
    catalog.register(impure_shape("Impure"));
    assert!(!catalog.get("Impure").unwrap().is_partial_eval_eligible());
}

// ---------------------------------------------------------------------------
// Deep nesting detection
// ---------------------------------------------------------------------------

#[test]
fn deep_nesting_detection_from_tree() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);

    // Build deep tree (depth > 8).
    let mut current = make_element("span");
    for _ in 0..10 {
        let mut parent = make_element("div");
        parent
            .children
            .push(LoweredChild::Element(Box::new(current)));
        current = parent;
    }
    let analysis = analyze_render_tree(&current);
    let manifest = make_manifest(&[]);
    catalog.register_from_evidence("DeepComp", &manifest, &analysis);

    let shape = catalog.get("DeepComp").unwrap();
    assert!(shape.is_deeply_nested());
    assert_eq!(shape.max_render_depth, 10);
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn serde_full_catalog_roundtrip() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);

    let mut s = ComponentShape::new("Complete");
    s.observation_count = 10;
    s.add_prop(PropDescriptor::new(
        "title",
        PropValueKind::StringLiteral,
        PropFlowKind::Rendered,
    ));
    s.add_prop(PropDescriptor::new(
        "onClick",
        PropValueKind::Callback,
        PropFlowKind::EffectOnly,
    ));
    catalog.register(s);

    let json = serde_json::to_string(&catalog).unwrap();
    let restored: ComponentShapeCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, restored);
}

#[test]
fn serde_purity_classification_roundtrip() {
    let classification = PurityClassification {
        class: RenderPurityClass::ConditionallyPure,
        reasons: [
            ImpurityReason::SpreadProps,
            ImpurityReason::ContextDependency,
        ]
        .into_iter()
        .collect(),
        severity_total: 800_000,
        confidence_fp: 500_000,
    };
    let json = serde_json::to_string(&classification).unwrap();
    let restored: PurityClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(classification, restored);
}

#[test]
fn serde_render_tree_analysis_roundtrip() {
    let mut root = make_element("div");
    root.children
        .push(LoweredChild::Element(Box::new(make_component_element(
            "Child",
        ))));
    let analysis = analyze_render_tree(&root);

    let json = serde_json::to_string(&analysis).unwrap();
    let restored: RenderTreeAnalysis = serde_json::from_str(&json).unwrap();
    assert_eq!(analysis, restored);
}

// ---------------------------------------------------------------------------
// Evidence hash determinism
// ---------------------------------------------------------------------------

#[test]
fn evidence_hash_deterministic_across_registrations() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };

    let mut cat1 = ComponentShapeCatalog::with_config(config.clone());
    cat1.register(pure_shape("Det"));
    let h1 = cat1.get("Det").unwrap().evidence_hash.clone();

    let mut cat2 = ComponentShapeCatalog::with_config(config);
    cat2.register(pure_shape("Det"));
    let h2 = cat2.get("Det").unwrap().evidence_hash.clone();

    assert_eq!(h1, h2);
}

// ---------------------------------------------------------------------------
// Mixed component scenarios
// ---------------------------------------------------------------------------

#[test]
fn realistic_react_app_catalog() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);

    // Pure components.
    for name in ["Button", "Icon", "Text", "Badge", "Divider", "Avatar"] {
        let manifest = make_manifest(&[]);
        let tree = analyze_render_tree(&make_element("span"));
        catalog.register_from_evidence(name, &manifest, &tree);
    }

    // Stateful but no effects (pure render).
    for name in ["Counter", "Toggle"] {
        let manifest = make_manifest(&[HookKind::State]);
        let tree = analyze_render_tree(&make_element("div"));
        catalog.register_from_evidence(name, &manifest, &tree);
    }

    // Components with effects (impure).
    for name in ["DataFetcher", "Timer", "WebSocket"] {
        let manifest = make_manifest(&[HookKind::State, HookKind::Effect]);
        let tree = analyze_render_tree(&make_element("div"));
        catalog.register_from_evidence(name, &manifest, &tree);
    }

    // Context consumers.
    for name in ["ThemeProvider", "AuthGuard"] {
        let manifest = make_manifest(&[HookKind::Context]);
        let tree = analyze_render_tree(&make_element("div"));
        catalog.register_from_evidence(name, &manifest, &tree);
    }

    let summary = catalog.summary();
    assert_eq!(summary.total_components, 13);

    // Pure components: Button, Icon, Text, Badge, Divider, Avatar, Counter, Toggle = 8.
    assert_eq!(summary.pure_count, 8);

    // Impure: DataFetcher, Timer, WebSocket, ThemeProvider, AuthGuard = 5.
    assert_eq!(summary.impure_count, 5);

    // Partial eval eligible: pure + no spread = 8.
    assert_eq!(summary.partial_eval_eligible_count, 8);
}

#[test]
fn catalog_with_all_impurity_reasons() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };
    let mut catalog = ComponentShapeCatalog::with_config(config);

    let mut shape = ComponentShape::new("AllImpure");
    shape.observation_count = 10;
    shape.hook_profile.effect_hooks = 1;
    shape.hook_profile.context_hooks = 1;
    shape.hook_profile.ref_hooks = 1;
    shape.hook_profile.has_conditional_hooks = true;
    shape.has_spread_props = true;
    shape.has_dynamic_children = true;
    catalog.register(shape);

    let s = catalog.get("AllImpure").unwrap();
    assert_eq!(s.render_purity, RenderPurityClass::Impure);
    assert!(
        s.impurity_reasons
            .contains(&ImpurityReason::EffectInRenderPath)
    );
    assert!(
        s.impurity_reasons
            .contains(&ImpurityReason::ContextDependency)
    );
    assert!(s.impurity_reasons.contains(&ImpurityReason::MutableRef));
    assert!(
        s.impurity_reasons
            .contains(&ImpurityReason::ConditionalHooks)
    );
    assert!(s.impurity_reasons.contains(&ImpurityReason::SpreadProps));
    assert!(
        s.impurity_reasons
            .contains(&ImpurityReason::DynamicElementType)
    );
}

// ---------------------------------------------------------------------------
// Display formatting
// ---------------------------------------------------------------------------

#[test]
fn display_formatting_coverage() {
    let shape = pure_shape("DisplayTest");
    let display = format!("{shape}");
    assert!(display.contains("DisplayTest"));
    assert!(display.contains("props=0"));

    for flow in [
        PropFlowKind::Rendered,
        PropFlowKind::PassedDown,
        PropFlowKind::Computed,
        PropFlowKind::KeyOrRef,
        PropFlowKind::EffectOnly,
        PropFlowKind::Spread,
        PropFlowKind::Unused,
    ] {
        assert!(!format!("{flow}").is_empty());
    }

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
        assert!(!format!("{kind}").is_empty());
    }

    for class in [
        RenderPurityClass::Pure,
        RenderPurityClass::ConditionallyPure,
        RenderPurityClass::Impure,
        RenderPurityClass::Unknown,
    ] {
        assert!(!format!("{class}").is_empty());
    }

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
        assert!(!format!("{reason}").is_empty());
    }
}

// ---------------------------------------------------------------------------
// Confidence scoring
// ---------------------------------------------------------------------------

#[test]
fn confidence_scales_with_observations() {
    let config = PurityConfig {
        min_observations: 1,
        ..Default::default()
    };

    let mut low = ComponentShape::new("Low");
    low.observation_count = 5;
    let r_low = classify_purity(&low, &config);

    let mut high = ComponentShape::new("High");
    high.observation_count = 100;
    let r_high = classify_purity(&high, &config);

    assert!(r_high.confidence_fp >= r_low.confidence_fp);
}

// ---------------------------------------------------------------------------
// Impurity severity
// ---------------------------------------------------------------------------

#[test]
fn severity_ordering() {
    assert!(
        ImpurityReason::NonDeterministic.severity_weight()
            > ImpurityReason::EffectInRenderPath.severity_weight()
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
        ImpurityReason::ExternalStateRead.severity_weight()
            > ImpurityReason::MutableRef.severity_weight()
    );
    assert!(
        ImpurityReason::ContextDependency.severity_weight()
            > ImpurityReason::DynamicElementType.severity_weight()
    );
    assert!(
        ImpurityReason::DynamicElementType.severity_weight()
            > ImpurityReason::SpreadProps.severity_weight()
    );
    assert!(
        ImpurityReason::SpreadProps.severity_weight()
            > ImpurityReason::InsufficientEvidence.severity_weight()
    );
}

// ---------------------------------------------------------------------------
// Default config
// ---------------------------------------------------------------------------

#[test]
fn default_config_values() {
    let config = PurityConfig::default();
    assert_eq!(config.min_observations, 5);
    assert!(config.context_downgrades_purity);
    assert!(config.spread_downgrades_purity);
    assert_eq!(config.max_conditional_severity, 500_000);
}
