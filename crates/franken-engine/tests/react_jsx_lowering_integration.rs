//! Integration tests for the React JSX lowering module.
//!
//! These tests verify the end-to-end lowering pipeline from JSX AST nodes
//! to lowered React element trees, covering classic mode, automatic mode,
//! dev/prod builds, fragment handling, key/ref extraction, nested elements,
//! spread attributes, whitespace trimming, evidence corpus, and compile receipts.

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::jsx_tsx_parser::{
    JsxAttribute, JsxAttributeValue, JsxChild, JsxElement, JsxElementName, JsxFeatureFamily,
    JsxFragment, JsxNode, JsxParseResult, JsxRuntimeMode,
};
use frankenengine_engine::react_jsx_lowering::{
    BuildMode, CallConvention, ElementType, LoweredPropValue, LoweredProps, LoweringDiagnosticCode,
    PropsEntry, REACT_LOWERING_COMPONENT, REACT_LOWERING_POLICY_ID, REACT_LOWERING_SCHEMA_VERSION,
    ReactLoweringConfig, ReactLoweringError, ReactLoweringResult, compute_lowering_receipt,
    lower_jsx_to_react, lower_parse_result, lowering_corpus, run_lowering_corpus,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn span() -> SourceSpan {
    SourceSpan::new(0, 10, 1, 0, 1, 10)
}

fn classic() -> ReactLoweringConfig {
    ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        build_mode: BuildMode::Production,
        ..Default::default()
    }
}

fn automatic() -> ReactLoweringConfig {
    ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Production,
        ..Default::default()
    }
}

fn dev_auto() -> ReactLoweringConfig {
    ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Development,
        source_file: Some("app.tsx".to_string()),
        ..Default::default()
    }
}

fn div_node(attrs: Vec<JsxAttribute>, children: Vec<JsxChild>) -> JsxNode {
    let sc = children.is_empty();
    JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "div".to_string(),
            span: span(),
        },
        attributes: attrs,
        children,
        self_closing: sc,
        span: span(),
    })
}

fn component_node(name: &str, attrs: Vec<JsxAttribute>, children: Vec<JsxChild>) -> JsxNode {
    let sc = children.is_empty();
    JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: name.to_string(),
            span: span(),
        },
        attributes: attrs,
        children,
        self_closing: sc,
        span: span(),
    })
}

fn text_child(text: &str) -> JsxChild {
    JsxChild::Text {
        value: text.to_string(),
        span: span(),
    }
}

fn expr_child(expr: &str) -> JsxChild {
    JsxChild::ExpressionContainer {
        expression: expr.to_string(),
        span: span(),
    }
}

fn str_attr(name: &str, value: &str) -> JsxAttribute {
    JsxAttribute::Named {
        name: name.to_string(),
        value: JsxAttributeValue::StringLiteral {
            value: value.to_string(),
        },
        span: span(),
    }
}

fn expr_attr(name: &str, expr: &str) -> JsxAttribute {
    JsxAttribute::Named {
        name: name.to_string(),
        value: JsxAttributeValue::Expression {
            expression: expr.to_string(),
        },
        span: span(),
    }
}

fn bool_attr(name: &str) -> JsxAttribute {
    JsxAttribute::Named {
        name: name.to_string(),
        value: JsxAttributeValue::ImplicitTrue,
        span: span(),
    }
}

fn spread_attr(expr: &str) -> JsxAttribute {
    JsxAttribute::Spread {
        expression: expr.to_string(),
        span: span(),
    }
}

// ---------------------------------------------------------------------------
// Classic Mode Integration
// ---------------------------------------------------------------------------

#[test]
fn test_classic_intrinsic_element_roundtrip() {
    let node = div_node(vec![str_attr("id", "root")], vec![text_child("Hello")]);
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert_eq!(
        result.element.element_type,
        ElementType::Intrinsic {
            tag: "div".to_string()
        }
    );
    assert!(matches!(
        result.element.call_convention,
        CallConvention::Classic { .. }
    ));
    assert_eq!(result.element.children.len(), 1);
    assert_eq!(result.element.props.named_count(), 1);
}

#[test]
fn test_classic_component_element() {
    let node = component_node(
        "Button",
        vec![expr_attr("onClick", "handler"), bool_attr("primary")],
        vec![text_child("Submit")],
    );
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert_eq!(
        result.element.element_type,
        ElementType::Component {
            name: "Button".to_string()
        }
    );
    assert_eq!(result.element.props.named_count(), 2);
    assert_eq!(result.element.children.len(), 1);
}

#[test]
fn test_classic_empty_self_closing() {
    let node = div_node(vec![], vec![]);
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert!(result.element.children.is_empty());
    assert!(result.element.props.is_empty());
    assert_eq!(result.stats.elements_lowered, 1);
}

#[test]
fn test_classic_multiple_children() {
    let node = div_node(
        vec![],
        vec![text_child("A"), expr_child("b"), text_child("C")],
    );
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert_eq!(result.element.children.len(), 3);
    assert_eq!(result.stats.text_children, 2);
    assert_eq!(result.stats.expression_children, 1);
}

#[test]
fn test_classic_key_not_in_props() {
    let node = component_node(
        "Item",
        vec![expr_attr("key", "item.id"), str_attr("data", "value")],
        vec![],
    );
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert!(result.element.props.extracted_key.is_some());
    // key should NOT be in the named props
    assert_eq!(result.element.props.named_count(), 1);
    assert!(result.element.props.entries.iter().all(|e| match e {
        PropsEntry::Named(p) => p.name != "key",
        _ => true,
    }));
}

#[test]
fn test_classic_ref_not_in_props() {
    let node = div_node(
        vec![expr_attr("ref", "myRef"), str_attr("id", "main")],
        vec![],
    );
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert!(result.element.props.extracted_ref.is_some());
    assert_eq!(result.element.props.named_count(), 1);
}

#[test]
fn test_classic_call_convention_object_method() {
    let result = lower_jsx_to_react(&div_node(vec![], vec![]), &classic()).unwrap();
    match &result.element.call_convention {
        CallConvention::Classic { object, method } => {
            assert_eq!(object, "React");
            assert_eq!(method, "createElement");
        }
        _ => panic!("Expected Classic call convention"),
    }
}

#[test]
fn test_classic_fragment_element_type() {
    let node = JsxNode::Fragment(JsxFragment {
        children: vec![text_child("A"), text_child("B")],
        span: span(),
    });
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert_eq!(result.element.element_type, ElementType::Fragment);
    assert_eq!(result.element.children.len(), 2);
    assert_eq!(result.stats.fragments_lowered, 1);
}

// ---------------------------------------------------------------------------
// Automatic Mode Integration
// ---------------------------------------------------------------------------

#[test]
fn test_automatic_single_child_jsx_factory() {
    let node = div_node(vec![], vec![text_child("Hello")]);
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();

    match &result.element.call_convention {
        CallConvention::Automatic { factory, .. } => {
            assert_eq!(factory, "jsx");
        }
        _ => panic!("Expected Automatic"),
    }
}

#[test]
fn test_automatic_multiple_children_jsxs_factory() {
    let node = div_node(vec![], vec![text_child("A"), text_child("B")]);
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();

    match &result.element.call_convention {
        CallConvention::Automatic { factory, .. } => {
            assert_eq!(factory, "jsxs");
        }
        _ => panic!("Expected Automatic"),
    }
}

#[test]
fn test_automatic_children_folded_into_props() {
    let node = div_node(
        vec![str_attr("className", "container")],
        vec![text_child("Hello")],
    );
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();

    // In automatic mode, children are in props, not separate
    assert!(result.element.children.is_empty());
    let has_children_prop = result.element.props.entries.iter().any(|e| match e {
        PropsEntry::Named(p) => p.name == "children",
        _ => false,
    });
    assert!(has_children_prop);
}

#[test]
fn test_automatic_no_children_no_children_prop() {
    let node = div_node(vec![str_attr("id", "empty")], vec![]);
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();

    let has_children_prop = result.element.props.entries.iter().any(|e| match e {
        PropsEntry::Named(p) => p.name == "children",
        _ => false,
    });
    assert!(!has_children_prop);
}

#[test]
fn test_automatic_import_source_production() {
    let result = lower_jsx_to_react(&div_node(vec![], vec![]), &automatic()).unwrap();

    assert!(
        result
            .required_imports
            .iter()
            .any(|i| i.source == "react/jsx-runtime")
    );
}

#[test]
fn test_automatic_import_source_development() {
    let result = lower_jsx_to_react(&div_node(vec![], vec![]), &dev_auto()).unwrap();

    assert!(
        result
            .required_imports
            .iter()
            .any(|i| i.source == "react/jsx-dev-runtime")
    );
}

#[test]
fn test_automatic_fragment_requires_import() {
    let node = JsxNode::Fragment(JsxFragment {
        children: vec![text_child("x")],
        span: span(),
    });
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();

    assert!(result.required_imports.iter().any(|i| i.name == "Fragment"));
}

// ---------------------------------------------------------------------------
// Dev vs Prod Mode
// ---------------------------------------------------------------------------

#[test]
fn test_dev_mode_jsxdev_factory() {
    let result = lower_jsx_to_react(&div_node(vec![], vec![]), &dev_auto()).unwrap();
    match &result.element.call_convention {
        CallConvention::Automatic { factory, .. } => {
            assert_eq!(factory, "jsxDEV");
        }
        _ => panic!("Expected Automatic"),
    }
}

#[test]
fn test_dev_mode_source_location_present() {
    let result = lower_jsx_to_react(&div_node(vec![], vec![]), &dev_auto()).unwrap();
    let loc = result.element.source_location.as_ref().unwrap();
    assert_eq!(loc.file_name.as_deref(), Some("app.tsx"));
    assert_eq!(loc.line_number, 1);
    assert_eq!(loc.column_number, 0);
}

#[test]
fn test_prod_mode_no_source_location() {
    let result = lower_jsx_to_react(&div_node(vec![], vec![]), &automatic()).unwrap();
    assert!(result.element.source_location.is_none());
}

#[test]
fn test_dev_diagnostic_emitted() {
    let result = lower_jsx_to_react(&div_node(vec![], vec![]), &dev_auto()).unwrap();
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.code == LoweringDiagnosticCode::DevMetadataEmitted)
    );
}

// ---------------------------------------------------------------------------
// Nested Elements
// ---------------------------------------------------------------------------

#[test]
fn test_nested_elements_depth_tracking() {
    let inner = JsxChild::Element(Box::new(JsxElement {
        name: JsxElementName::Identifier {
            name: "span".to_string(),
            span: span(),
        },
        attributes: vec![],
        children: vec![text_child("deep")],
        self_closing: false,
        span: span(),
    }));
    let node = div_node(vec![], vec![inner]);
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert_eq!(result.stats.elements_lowered, 2);
    assert_eq!(result.stats.max_depth_reached, 1);
}

#[test]
fn test_deeply_nested_elements() {
    // Build 5-level deep nesting
    let mut current = JsxElement {
        name: JsxElementName::Identifier {
            name: "p".to_string(),
            span: span(),
        },
        attributes: vec![],
        children: vec![text_child("leaf")],
        self_closing: false,
        span: span(),
    };

    for tag in ["span", "section", "article", "main"] {
        current = JsxElement {
            name: JsxElementName::Identifier {
                name: tag.to_string(),
                span: span(),
            },
            attributes: vec![],
            children: vec![JsxChild::Element(Box::new(current))],
            self_closing: false,
            span: span(),
        };
    }

    let node = JsxNode::Element(current);
    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    assert_eq!(result.stats.elements_lowered, 5);
    assert_eq!(result.stats.max_depth_reached, 4);
}

#[test]
fn test_depth_exceeded_error() {
    let cfg = ReactLoweringConfig {
        max_depth: 2,
        ..classic()
    };

    let deep = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "a".to_string(),
            span: span(),
        },
        attributes: vec![],
        children: vec![JsxChild::Element(Box::new(JsxElement {
            name: JsxElementName::Identifier {
                name: "b".to_string(),
                span: span(),
            },
            attributes: vec![],
            children: vec![JsxChild::Element(Box::new(JsxElement {
                name: JsxElementName::Identifier {
                    name: "c".to_string(),
                    span: span(),
                },
                attributes: vec![],
                children: vec![],
                self_closing: true,
                span: span(),
            }))],
            self_closing: false,
            span: span(),
        }))],
        self_closing: false,
        span: span(),
    });

    let result = lower_jsx_to_react(&deep, &cfg);
    assert!(matches!(
        result,
        Err(ReactLoweringError::DepthExceeded { max_depth: 2, .. })
    ));
}

// ---------------------------------------------------------------------------
// Spread Attributes
// ---------------------------------------------------------------------------

#[test]
fn test_spread_has_spreads_flag() {
    let node = div_node(vec![spread_attr("props")], vec![]);
    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    assert!(result.element.props.has_spreads);
}

#[test]
fn test_spread_diagnostic() {
    let node = div_node(vec![spread_attr("p")], vec![]);
    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.code == LoweringDiagnosticCode::SpreadRequiresRuntime)
    );
}

#[test]
fn test_mixed_props_and_spread_order_preserved() {
    let node = div_node(
        vec![
            str_attr("id", "x"),
            spread_attr("rest"),
            str_attr("className", "y"),
        ],
        vec![],
    );
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert_eq!(result.element.props.entries.len(), 3);
    assert!(matches!(
        &result.element.props.entries[0],
        PropsEntry::Named(p) if p.name == "id"
    ));
    assert!(matches!(
        &result.element.props.entries[1],
        PropsEntry::Spread { .. }
    ));
    assert!(matches!(
        &result.element.props.entries[2],
        PropsEntry::Named(p) if p.name == "className"
    ));
}

// ---------------------------------------------------------------------------
// Whitespace Trimming
// ---------------------------------------------------------------------------

#[test]
fn test_whitespace_only_children_removed() {
    let node = div_node(vec![], vec![text_child("  \n  \n  ")]);
    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    assert!(result.element.children.is_empty());
}

#[test]
fn test_meaningful_text_preserved() {
    let node = div_node(vec![], vec![text_child("Hello World")]);
    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    assert_eq!(result.element.children.len(), 1);
}

// ---------------------------------------------------------------------------
// Member Expression & Namespaced Elements
// ---------------------------------------------------------------------------

#[test]
fn test_member_expression_element() {
    let node = JsxNode::Element(JsxElement {
        name: JsxElementName::MemberExpression {
            segments: vec!["Ctx".to_string(), "Provider".to_string()],
            span: span(),
        },
        attributes: vec![expr_attr("value", "val")],
        children: vec![expr_child("children")],
        self_closing: false,
        span: span(),
    });
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert_eq!(
        result.element.element_type,
        ElementType::Component {
            name: "Ctx.Provider".to_string()
        }
    );
}

#[test]
fn test_namespaced_element_warning() {
    let node = JsxNode::Element(JsxElement {
        name: JsxElementName::NamespacedName {
            namespace: "svg".to_string(),
            name: "rect".to_string(),
            span: span(),
        },
        attributes: vec![],
        children: vec![],
        self_closing: true,
        span: span(),
    });
    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.code == LoweringDiagnosticCode::NamespacedElement)
    );
}

// ---------------------------------------------------------------------------
// Preserve Mode
// ---------------------------------------------------------------------------

#[test]
fn test_preserve_mode_returns_error() {
    let cfg = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Preserve,
        ..Default::default()
    };
    let result = lower_jsx_to_react(&div_node(vec![], vec![]), &cfg);
    assert!(matches!(result, Err(ReactLoweringError::PreserveMode)));
}

// ---------------------------------------------------------------------------
// Custom Pragmas
// ---------------------------------------------------------------------------

#[test]
fn test_custom_classic_pragma_preact() {
    let cfg = ReactLoweringConfig {
        classic_pragma: Some("h".to_string()),
        ..classic()
    };
    let result = lower_jsx_to_react(&div_node(vec![], vec![]), &cfg).unwrap();
    match &result.element.call_convention {
        CallConvention::Classic { object, .. } => assert_eq!(object, "h"),
        _ => panic!("Expected Classic"),
    }
}

#[test]
fn test_custom_automatic_import_source() {
    let cfg = ReactLoweringConfig {
        automatic_import_source: Some("preact/jsx-runtime".to_string()),
        ..automatic()
    };
    let result = lower_jsx_to_react(&div_node(vec![], vec![]), &cfg).unwrap();
    assert!(
        result
            .required_imports
            .iter()
            .any(|i| i.source == "preact/jsx-runtime")
    );
}

// ---------------------------------------------------------------------------
// Feature Family Tracking
// ---------------------------------------------------------------------------

#[test]
fn test_feature_families_comprehensive() {
    let node = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "div".to_string(),
            span: span(),
        },
        attributes: vec![
            str_attr("className", "x"),
            expr_attr("key", "k"),
            spread_attr("rest"),
        ],
        children: vec![
            text_child("text"),
            expr_child("expr"),
            JsxChild::Element(Box::new(JsxElement {
                name: JsxElementName::Identifier {
                    name: "span".to_string(),
                    span: span(),
                },
                attributes: vec![],
                children: vec![],
                self_closing: true,
                span: span(),
            })),
        ],
        self_closing: false,
        span: span(),
    });

    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    let families = &result.feature_families_used;

    assert!(families.contains(&JsxFeatureFamily::Element));
    assert!(families.contains(&JsxFeatureFamily::StringAttribute));
    assert!(families.contains(&JsxFeatureFamily::SpreadAttribute));
    assert!(families.contains(&JsxFeatureFamily::TextChild));
    assert!(families.contains(&JsxFeatureFamily::ExpressionChild));
    assert!(families.contains(&JsxFeatureFamily::KeyProp));
    assert!(families.contains(&JsxFeatureFamily::NestedElement));
}

// ---------------------------------------------------------------------------
// Stats Verification
// ---------------------------------------------------------------------------

#[test]
fn test_stats_comprehensive() {
    let node = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "div".to_string(),
            span: span(),
        },
        attributes: vec![
            str_attr("a", "1"),
            str_attr("b", "2"),
            expr_attr("key", "k"),
            expr_attr("ref", "r"),
            spread_attr("rest"),
        ],
        children: vec![text_child("t1"), text_child("t2"), expr_child("e1")],
        self_closing: false,
        span: span(),
    });

    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    assert_eq!(result.stats.elements_lowered, 1);
    assert_eq!(result.stats.total_props, 4); // a, b, key, ref (not spread)
    assert_eq!(result.stats.spread_attributes, 1);
    assert_eq!(result.stats.text_children, 2);
    assert_eq!(result.stats.expression_children, 1);
    assert_eq!(result.stats.keys_extracted, 1);
    assert_eq!(result.stats.refs_extracted, 1);
}

// ---------------------------------------------------------------------------
// Duplicate Key
// ---------------------------------------------------------------------------

#[test]
fn test_duplicate_key_last_wins() {
    let node = div_node(
        vec![
            expr_attr("key", "first"),
            str_attr("id", "x"),
            expr_attr("key", "second"),
        ],
        vec![],
    );
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.code == LoweringDiagnosticCode::DuplicateKey)
    );

    match &result.element.props.extracted_key {
        Some(LoweredPropValue::Expression { expression }) => {
            assert_eq!(expression, "second");
        }
        other => panic!("Expected Expression, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Serde Round-trips
// ---------------------------------------------------------------------------

#[test]
fn test_full_result_serde_roundtrip() {
    let node = div_node(
        vec![str_attr("id", "main"), expr_attr("onClick", "fn")],
        vec![text_child("Hello"), expr_child("name")],
    );
    let result = lower_jsx_to_react(&node, &classic()).unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let back: ReactLoweringResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.element, back.element);
    assert_eq!(result.stats, back.stats);
}

#[test]
fn test_config_serde_roundtrip() {
    let cfg = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Development,
        source_file: Some("test.tsx".to_string()),
        emit_self: true,
        emit_source: true,
        classic_pragma: None,
        classic_fragment_pragma: None,
        automatic_import_source: Some("preact/jsx-runtime".to_string()),
        max_depth: 32,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ReactLoweringConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn test_element_type_serde() {
    for et in [
        ElementType::Intrinsic {
            tag: "div".to_string(),
        },
        ElementType::Component {
            name: "App".to_string(),
        },
        ElementType::Fragment,
    ] {
        let json = serde_json::to_string(&et).unwrap();
        let back: ElementType = serde_json::from_str(&json).unwrap();
        assert_eq!(et, back);
    }
}

#[test]
fn test_error_serde_roundtrip() {
    for err in [
        ReactLoweringError::PreserveMode,
        ReactLoweringError::DepthExceeded {
            max_depth: 64,
            span: span(),
        },
        ReactLoweringError::InternalError {
            message: "test".to_string(),
        },
    ] {
        let json = serde_json::to_string(&err).unwrap();
        let back: ReactLoweringError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ---------------------------------------------------------------------------
// Evidence Corpus
// ---------------------------------------------------------------------------

#[test]
fn test_corpus_has_specimens() {
    let corpus = lowering_corpus();
    assert!(corpus.len() >= 10);
}

#[test]
fn test_corpus_specimen_labels_unique() {
    let corpus = lowering_corpus();
    let mut labels: Vec<&str> = corpus.iter().map(|s| s.label.as_str()).collect();
    let original_len = labels.len();
    labels.sort();
    labels.dedup();
    assert_eq!(original_len, labels.len());
}

#[test]
fn test_run_corpus_classic_passes() {
    let manifest = run_lowering_corpus(&classic());
    assert_eq!(
        manifest.fail_count, 0,
        "Classic corpus failures: {}",
        manifest.fail_count
    );
    assert!(manifest.pass_count >= 10);
}

#[test]
fn test_run_corpus_automatic_passes() {
    let manifest = run_lowering_corpus(&automatic());
    assert_eq!(
        manifest.fail_count, 0,
        "Automatic corpus failures: {}",
        manifest.fail_count
    );
    assert!(manifest.pass_count >= 10);
}

#[test]
fn test_run_corpus_preserve_all_skipped() {
    let cfg = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Preserve,
        ..Default::default()
    };
    let manifest = run_lowering_corpus(&cfg);
    assert_eq!(manifest.pass_count, 0);
    assert_eq!(manifest.skip_count, manifest.total_specimens);
}

#[test]
fn test_corpus_manifest_deterministic() {
    let m1 = run_lowering_corpus(&classic());
    let m2 = run_lowering_corpus(&classic());
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
    assert_eq!(m1.evidence.len(), m2.evidence.len());
}

// ---------------------------------------------------------------------------
// Compile Receipts
// ---------------------------------------------------------------------------

#[test]
fn test_compile_receipt_schema_version() {
    let node = div_node(vec![], vec![]);
    let pr = JsxParseResult {
        node: node.clone(),
        diagnostics: vec![],
        feature_families_used: vec![],
    };
    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    let receipt = compute_lowering_receipt(&pr, &result, &classic());

    assert_eq!(receipt.schema_version, REACT_LOWERING_SCHEMA_VERSION);
}

#[test]
fn test_compile_receipt_deterministic() {
    let node = div_node(vec![str_attr("id", "x")], vec![text_child("hi")]);
    let pr = JsxParseResult {
        node: node.clone(),
        diagnostics: vec![],
        feature_families_used: vec![],
    };
    let cfg = classic();
    let result = lower_jsx_to_react(&node, &cfg).unwrap();

    let r1 = compute_lowering_receipt(&pr, &result, &cfg);
    let r2 = compute_lowering_receipt(&pr, &result, &cfg);
    assert_eq!(r1.input_hash, r2.input_hash);
    assert_eq!(r1.output_hash, r2.output_hash);
}

#[test]
fn test_compile_receipt_config_summary() {
    let cfg = ReactLoweringConfig {
        classic_pragma: Some("h".to_string()),
        ..classic()
    };
    let node = div_node(vec![], vec![]);
    let pr = JsxParseResult {
        node: node.clone(),
        diagnostics: vec![],
        feature_families_used: vec![],
    };
    let result = lower_jsx_to_react(&node, &cfg).unwrap();
    let receipt = compute_lowering_receipt(&pr, &result, &cfg);

    assert_eq!(receipt.config_summary.runtime_mode, "classic");
    assert!(receipt.config_summary.has_custom_pragma);
}

// ---------------------------------------------------------------------------
// lower_parse_result API
// ---------------------------------------------------------------------------

#[test]
fn test_lower_parse_result_api() {
    let pr = JsxParseResult {
        node: div_node(vec![str_attr("id", "main")], vec![]),
        diagnostics: vec![],
        feature_families_used: vec![],
    };
    let result = lower_parse_result(&pr, &classic()).unwrap();
    assert_eq!(
        result.element.element_type,
        ElementType::Intrinsic {
            tag: "div".to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// Diagnostic Codes
// ---------------------------------------------------------------------------

#[test]
fn test_diagnostic_codes_have_prefix() {
    let codes = [
        LoweringDiagnosticCode::PreserveModeNoOp,
        LoweringDiagnosticCode::DepthExceeded,
        LoweringDiagnosticCode::SpreadRequiresRuntime,
        LoweringDiagnosticCode::NamespacedElement,
        LoweringDiagnosticCode::KeyOnFragment,
        LoweringDiagnosticCode::RefOnFragment,
        LoweringDiagnosticCode::EmptyTextTrimmed,
        LoweringDiagnosticCode::DevMetadataEmitted,
        LoweringDiagnosticCode::ChildrenInProps,
        LoweringDiagnosticCode::DuplicateKey,
    ];
    for code in &codes {
        let s = code.code_str();
        assert!(s.starts_with("FE-RJL-"), "Code {} missing prefix", s);
    }
}

#[test]
fn test_diagnostic_display() {
    let code = LoweringDiagnosticCode::SpreadRequiresRuntime;
    assert_eq!(format!("{code}"), "FE-RJL-0003");
}

// ---------------------------------------------------------------------------
// Error Display
// ---------------------------------------------------------------------------

#[test]
fn test_error_display_preserve() {
    let err = ReactLoweringError::PreserveMode;
    let msg = format!("{err}");
    assert!(msg.contains("preserve"));
}

#[test]
fn test_error_display_depth() {
    let err = ReactLoweringError::DepthExceeded {
        max_depth: 42,
        span: span(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("42"));
}

#[test]
fn test_error_display_internal() {
    let err = ReactLoweringError::InternalError {
        message: "oops".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("oops"));
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_constants() {
    assert!(!REACT_LOWERING_SCHEMA_VERSION.is_empty());
    assert!(!REACT_LOWERING_COMPONENT.is_empty());
    assert!(!REACT_LOWERING_POLICY_ID.is_empty());
    assert_eq!(REACT_LOWERING_POLICY_ID, "RGC-206B");
}

// ---------------------------------------------------------------------------
// BuildMode
// ---------------------------------------------------------------------------

#[test]
fn test_build_mode_values() {
    assert_eq!(BuildMode::Development.as_str(), "development");
    assert_eq!(BuildMode::Production.as_str(), "production");
    assert_eq!(format!("{}", BuildMode::Development), "development");
    assert_eq!(format!("{}", BuildMode::Production), "production");
}

#[test]
fn test_build_mode_serde() {
    for mode in [BuildMode::Development, BuildMode::Production] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: BuildMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

// ---------------------------------------------------------------------------
// ElementType
// ---------------------------------------------------------------------------

#[test]
fn test_element_type_canonical_values() {
    assert_eq!(
        ElementType::Intrinsic {
            tag: "div".to_string()
        }
        .canonical_value(),
        "intrinsic:div"
    );
    assert_eq!(
        ElementType::Component {
            name: "App".to_string()
        }
        .canonical_value(),
        "component:App"
    );
    assert_eq!(ElementType::Fragment.canonical_value(), "fragment");
}

// ---------------------------------------------------------------------------
// LoweredProps
// ---------------------------------------------------------------------------

#[test]
fn test_lowered_props_empty_check() {
    let empty = LoweredProps {
        entries: vec![],
        has_spreads: false,
        extracted_key: None,
        extracted_ref: None,
    };
    assert!(empty.is_empty());
    assert_eq!(empty.named_count(), 0);

    let with_key = LoweredProps {
        entries: vec![],
        has_spreads: false,
        extracted_key: Some(LoweredPropValue::StringLiteral {
            value: "k".to_string(),
        }),
        extracted_ref: None,
    };
    assert!(!with_key.is_empty());
}

// ---------------------------------------------------------------------------
// Fragment in Automatic Mode
// ---------------------------------------------------------------------------

#[test]
fn test_automatic_fragment_children_in_props() {
    let node = JsxNode::Fragment(JsxFragment {
        children: vec![text_child("A"), text_child("B")],
        span: span(),
    });
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();

    // Fragment in automatic mode should have children in props
    assert!(result.element.children.is_empty());
    assert!(
        result
            .element
            .props
            .entries
            .iter()
            .any(|e| matches!(e, PropsEntry::Named(p) if p.name == "children"))
    );
}

// ---------------------------------------------------------------------------
// Complex Real-World Scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_realistic_react_component() {
    // <App className="root" onClick={handler}>
    //   <Header title="My App" />
    //   <main>
    //     {content}
    //   </main>
    //   <Footer />
    // </App>
    let node = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "App".to_string(),
            span: span(),
        },
        attributes: vec![
            str_attr("className", "root"),
            expr_attr("onClick", "handler"),
        ],
        children: vec![
            JsxChild::Element(Box::new(JsxElement {
                name: JsxElementName::Identifier {
                    name: "Header".to_string(),
                    span: span(),
                },
                attributes: vec![str_attr("title", "My App")],
                children: vec![],
                self_closing: true,
                span: span(),
            })),
            JsxChild::Element(Box::new(JsxElement {
                name: JsxElementName::Identifier {
                    name: "main".to_string(),
                    span: span(),
                },
                attributes: vec![],
                children: vec![expr_child("content")],
                self_closing: false,
                span: span(),
            })),
            JsxChild::Element(Box::new(JsxElement {
                name: JsxElementName::Identifier {
                    name: "Footer".to_string(),
                    span: span(),
                },
                attributes: vec![],
                children: vec![],
                self_closing: true,
                span: span(),
            })),
        ],
        self_closing: false,
        span: span(),
    });

    // Test in both modes
    let classic_result = lower_jsx_to_react(&node, &classic()).unwrap();
    assert_eq!(classic_result.stats.elements_lowered, 4); // App + Header + main + Footer
    assert_eq!(classic_result.element.children.len(), 3);
    assert_eq!(classic_result.element.props.named_count(), 2);

    let auto_result = lower_jsx_to_react(&node, &automatic()).unwrap();
    assert_eq!(auto_result.stats.elements_lowered, 4);
    // In automatic mode, children are in props
    assert!(auto_result.element.children.is_empty());
    // Should use jsxs (multiple children)
    match &auto_result.element.call_convention {
        CallConvention::Automatic { factory, .. } => assert_eq!(factory, "jsxs"),
        _ => panic!("Expected Automatic"),
    }
}

#[test]
fn test_list_rendering_pattern() {
    // <ul>
    //   <li key="1">A</li>
    //   <li key="2">B</li>
    //   <li key="3">C</li>
    // </ul>
    let items: Vec<JsxChild> = (1..=3)
        .map(|i| {
            JsxChild::Element(Box::new(JsxElement {
                name: JsxElementName::Identifier {
                    name: "li".to_string(),
                    span: span(),
                },
                attributes: vec![JsxAttribute::Named {
                    name: "key".to_string(),
                    value: JsxAttributeValue::StringLiteral {
                        value: format!("{i}"),
                    },
                    span: span(),
                }],
                children: vec![text_child(match i {
                    1 => "A",
                    2 => "B",
                    _ => "C",
                })],
                self_closing: false,
                span: span(),
            }))
        })
        .collect();

    let node = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "ul".to_string(),
            span: span(),
        },
        attributes: vec![],
        children: items,
        self_closing: false,
        span: span(),
    });

    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    assert_eq!(result.stats.elements_lowered, 4); // ul + 3 li
    assert_eq!(result.stats.keys_extracted, 3);
}
