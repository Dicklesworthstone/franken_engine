#![forbid(unsafe_code)]

//! Enrichment integration tests for react_jsx_lowering [RGC-206B].

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::jsx_tsx_parser::{
    JsxAttribute, JsxAttributeValue, JsxChild, JsxElement, JsxElementName, JsxFragment, JsxNode,
    JsxParseResult, JsxRuntimeMode,
};
use frankenengine_engine::react_jsx_lowering::{
    BuildMode, CallConvention, ConfigSummary, ElementType, LoweredChild, LoweredProp,
    LoweredPropValue, LoweredProps, LoweringCompileReceipt, LoweringDiagnostic,
    LoweringDiagnosticCode, LoweringDiagnosticSeverity, LoweringRunManifest, LoweringSpecimen,
    LoweringSpecimenEvidence, LoweringStats, LoweringVerdict, PropsEntry, REACT_LOWERING_COMPONENT,
    REACT_LOWERING_POLICY_ID, REACT_LOWERING_SCHEMA_VERSION, ReactLoweringConfig,
    ReactLoweringError, RequiredImport, SourceLocation, compute_lowering_receipt,
    lower_jsx_to_react, lowering_corpus, run_lowering_corpus,
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

fn text_child(text: &str) -> JsxChild {
    JsxChild::Text {
        value: text.to_string(),
        span: span(),
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips for types not covered by base tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lowering_verdict_serde_all_variants() {
    let verdicts = [
        LoweringVerdict::Pass,
        LoweringVerdict::PassWithDiagnostics,
        LoweringVerdict::Fail,
        LoweringVerdict::Skipped,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: LoweringVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *v);
    }
}

#[test]
fn enrichment_lowering_diagnostic_severity_serde() {
    let sevs = [
        LoweringDiagnosticSeverity::Info,
        LoweringDiagnosticSeverity::Warning,
        LoweringDiagnosticSeverity::Error,
    ];
    for s in &sevs {
        let json = serde_json::to_string(s).unwrap();
        let back: LoweringDiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *s);
    }
}

#[test]
fn enrichment_lowering_diagnostic_code_serde_all() {
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
    for c in &codes {
        let json = serde_json::to_string(c).unwrap();
        let back: LoweringDiagnosticCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *c);
    }
}

#[test]
fn enrichment_lowering_diagnostic_code_strings_unique() {
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
    let strs: BTreeSet<&str> = codes.iter().map(|c| c.code_str()).collect();
    assert_eq!(strs.len(), codes.len());
}

#[test]
fn enrichment_lowering_diagnostic_serde_roundtrip() {
    let diag = LoweringDiagnostic {
        code: LoweringDiagnosticCode::SpreadRequiresRuntime,
        severity: LoweringDiagnosticSeverity::Info,
        message: "Spread needs runtime merge".to_string(),
        span: Some(span()),
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: LoweringDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(back, diag);
}

#[test]
fn enrichment_lowering_diagnostic_no_span_serde() {
    let diag = LoweringDiagnostic {
        code: LoweringDiagnosticCode::EmptyTextTrimmed,
        severity: LoweringDiagnosticSeverity::Warning,
        message: "trimmed".to_string(),
        span: None,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: LoweringDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(back.span, None);
}

#[test]
fn enrichment_required_import_serde_roundtrip() {
    let imp = RequiredImport {
        source: "react/jsx-runtime".to_string(),
        name: "jsx".to_string(),
        is_default: false,
    };
    let json = serde_json::to_string(&imp).unwrap();
    let back: RequiredImport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, imp);
}

#[test]
fn enrichment_lowering_stats_default_all_zero() {
    let stats = LoweringStats::default();
    assert_eq!(stats.elements_lowered, 0);
    assert_eq!(stats.fragments_lowered, 0);
    assert_eq!(stats.text_children, 0);
    assert_eq!(stats.expression_children, 0);
    assert_eq!(stats.spread_attributes, 0);
    assert_eq!(stats.max_depth_reached, 0);
    assert_eq!(stats.total_props, 0);
    assert_eq!(stats.keys_extracted, 0);
    assert_eq!(stats.refs_extracted, 0);
}

#[test]
fn enrichment_lowering_stats_serde_roundtrip() {
    let stats = LoweringStats {
        elements_lowered: 5,
        fragments_lowered: 2,
        text_children: 3,
        expression_children: 1,
        spread_attributes: 1,
        max_depth_reached: 3,
        total_props: 10,
        keys_extracted: 2,
        refs_extracted: 1,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let back: LoweringStats = serde_json::from_str(&json).unwrap();
    assert_eq!(back, stats);
}

#[test]
fn enrichment_config_summary_serde_roundtrip() {
    let cs = ConfigSummary {
        runtime_mode: "automatic".to_string(),
        build_mode: "production".to_string(),
        has_custom_pragma: false,
        has_custom_fragment: false,
        has_custom_import_source: true,
    };
    let json = serde_json::to_string(&cs).unwrap();
    let back: ConfigSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cs);
}

#[test]
fn enrichment_config_summary_from_config_default() {
    let config = ReactLoweringConfig::default();
    let cs = ConfigSummary::from_config(&config);
    assert_eq!(cs.runtime_mode, "automatic");
    assert_eq!(cs.build_mode, "production");
    assert!(!cs.has_custom_pragma);
    assert!(!cs.has_custom_fragment);
    assert!(!cs.has_custom_import_source);
}

#[test]
fn enrichment_config_summary_from_config_custom() {
    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        build_mode: BuildMode::Development,
        classic_pragma: Some("h".to_string()),
        classic_fragment_pragma: Some("Fragment".to_string()),
        automatic_import_source: Some("preact/jsx-runtime".to_string()),
        ..Default::default()
    };
    let cs = ConfigSummary::from_config(&config);
    assert_eq!(cs.runtime_mode, "classic");
    assert_eq!(cs.build_mode, "development");
    assert!(cs.has_custom_pragma);
    assert!(cs.has_custom_fragment);
    assert!(cs.has_custom_import_source);
}

#[test]
fn enrichment_lowering_compile_receipt_serde_roundtrip() {
    let node = div_node(vec![str_attr("id", "x")], vec![text_child("hi")]);
    let config = automatic();
    let parse_result = JsxParseResult {
        node: node.clone(),
        feature_families_used: vec![],
        diagnostics: vec![],
    };
    let result = lower_jsx_to_react(&node, &config).unwrap();
    let receipt = compute_lowering_receipt(&parse_result, &result, &config);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: LoweringCompileReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back.schema_version, receipt.schema_version);
    assert_eq!(back.input_hash, receipt.input_hash);
    assert_eq!(back.output_hash, receipt.output_hash);
}

#[test]
fn enrichment_source_location_serde_roundtrip() {
    let loc = SourceLocation {
        file_name: Some("app.tsx".to_string()),
        line_number: 42,
        column_number: 8,
    };
    let json = serde_json::to_string(&loc).unwrap();
    let back: SourceLocation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, loc);
}

#[test]
fn enrichment_source_location_no_filename_serde() {
    let loc = SourceLocation {
        file_name: None,
        line_number: 1,
        column_number: 0,
    };
    let json = serde_json::to_string(&loc).unwrap();
    let back: SourceLocation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.file_name, None);
}

#[test]
fn enrichment_lowering_specimen_serde_roundtrip() {
    let spec = LoweringSpecimen {
        label: "test_spec".to_string(),
        node: div_node(vec![], vec![]),
        features: vec![],
        expected_element_type: "intrinsic:div".to_string(),
        expected_child_count: 0,
    };
    let json = serde_json::to_string(&spec).unwrap();
    let back: LoweringSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(back.label, "test_spec");
}

#[test]
fn enrichment_lowering_specimen_evidence_serde_roundtrip() {
    let ev = LoweringSpecimenEvidence {
        label: "spec_1".to_string(),
        verdict: LoweringVerdict::Pass,
        element_type_match: true,
        child_count_match: true,
        diagnostic_count: 0,
        error: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: LoweringSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ev);
}

#[test]
fn enrichment_lowering_specimen_evidence_with_error_serde() {
    let ev = LoweringSpecimenEvidence {
        label: "spec_fail".to_string(),
        verdict: LoweringVerdict::Fail,
        element_type_match: false,
        child_count_match: false,
        diagnostic_count: 0,
        error: Some("depth exceeded".to_string()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: LoweringSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error, Some("depth exceeded".to_string()));
}

#[test]
fn enrichment_lowering_run_manifest_serde_roundtrip() {
    let manifest = run_lowering_corpus(&classic());
    let json = serde_json::to_string(&manifest).unwrap();
    let back: LoweringRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_specimens, manifest.total_specimens);
    assert_eq!(back.manifest_hash, manifest.manifest_hash);
}

// ---------------------------------------------------------------------------
// LoweredPropValue serde per variant
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lowered_prop_value_string_literal_serde() {
    let v = LoweredPropValue::StringLiteral {
        value: "hello".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: LoweredPropValue = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enrichment_lowered_prop_value_boolean_true_serde() {
    let v = LoweredPropValue::BooleanTrue;
    let json = serde_json::to_string(&v).unwrap();
    let back: LoweredPropValue = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enrichment_lowered_prop_value_expression_serde() {
    let v = LoweredPropValue::Expression {
        expression: "foo()".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: LoweredPropValue = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn enrichment_lowered_prop_value_null_serde() {
    let v = LoweredPropValue::Null;
    let json = serde_json::to_string(&v).unwrap();
    let back: LoweredPropValue = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ---------------------------------------------------------------------------
// PropsEntry serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_props_entry_named_serde() {
    let entry = PropsEntry::Named(LoweredProp {
        name: "className".to_string(),
        value: LoweredPropValue::StringLiteral {
            value: "box".to_string(),
        },
        span: Some(span()),
    });
    let json = serde_json::to_string(&entry).unwrap();
    let back: PropsEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn enrichment_props_entry_spread_serde() {
    let entry = PropsEntry::Spread {
        expression: "restProps".to_string(),
        span: span(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: PropsEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ---------------------------------------------------------------------------
// LoweredProps named_count and is_empty
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lowered_props_named_count_mixed() {
    let props = LoweredProps {
        entries: vec![
            PropsEntry::Named(LoweredProp {
                name: "a".to_string(),
                value: LoweredPropValue::BooleanTrue,
                span: None,
            }),
            PropsEntry::Spread {
                expression: "x".to_string(),
                span: span(),
            },
            PropsEntry::Named(LoweredProp {
                name: "b".to_string(),
                value: LoweredPropValue::Null,
                span: None,
            }),
        ],
        has_spreads: true,
        extracted_key: None,
        extracted_ref: None,
    };
    assert_eq!(props.named_count(), 2);
    assert!(!props.is_empty());
}

#[test]
fn enrichment_lowered_props_empty_with_key_is_not_empty() {
    let props = LoweredProps {
        entries: vec![],
        has_spreads: false,
        extracted_key: Some(LoweredPropValue::StringLiteral {
            value: "k1".to_string(),
        }),
        extracted_ref: None,
    };
    assert!(!props.is_empty());
}

#[test]
fn enrichment_lowered_props_empty_with_ref_is_not_empty() {
    let props = LoweredProps {
        entries: vec![],
        has_spreads: false,
        extracted_key: None,
        extracted_ref: Some(LoweredPropValue::Expression {
            expression: "myRef".to_string(),
        }),
    };
    assert!(!props.is_empty());
}

// ---------------------------------------------------------------------------
// CallConvention serde per variant
// ---------------------------------------------------------------------------

#[test]
fn enrichment_call_convention_classic_serde() {
    let cc = CallConvention::Classic {
        object: "React".to_string(),
        method: "createElement".to_string(),
    };
    let json = serde_json::to_string(&cc).unwrap();
    let back: CallConvention = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cc);
}

#[test]
fn enrichment_call_convention_automatic_serde() {
    let cc = CallConvention::Automatic {
        factory: "jsx".to_string(),
        import_source: "react/jsx-runtime".to_string(),
    };
    let json = serde_json::to_string(&cc).unwrap();
    let back: CallConvention = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cc);
}

// ---------------------------------------------------------------------------
// LoweredChild serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lowered_child_text_serde() {
    let child = LoweredChild::Text {
        value: "hello".to_string(),
        span: span(),
    };
    let json = serde_json::to_string(&child).unwrap();
    let back: LoweredChild = serde_json::from_str(&json).unwrap();
    assert_eq!(back, child);
}

#[test]
fn enrichment_lowered_child_expression_serde() {
    let child = LoweredChild::Expression {
        expression: "count".to_string(),
        span: span(),
    };
    let json = serde_json::to_string(&child).unwrap();
    let back: LoweredChild = serde_json::from_str(&json).unwrap();
    assert_eq!(back, child);
}

// ---------------------------------------------------------------------------
// ElementType canonical values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_element_type_fragment_canonical() {
    let et = ElementType::Fragment;
    assert_eq!(et.canonical_value(), "fragment");
}

#[test]
fn enrichment_element_type_intrinsic_canonical() {
    let et = ElementType::Intrinsic {
        tag: "span".to_string(),
    };
    assert_eq!(et.canonical_value(), "intrinsic:span");
}

#[test]
fn enrichment_element_type_component_canonical() {
    let et = ElementType::Component {
        name: "App".to_string(),
    };
    assert_eq!(et.canonical_value(), "component:App");
}

// ---------------------------------------------------------------------------
// ReactLoweringConfig accessors
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_classic_object_default() {
    let config = classic();
    assert_eq!(config.classic_object(), "React");
}

#[test]
fn enrichment_config_classic_object_custom() {
    let config = ReactLoweringConfig {
        classic_pragma: Some("h".to_string()),
        ..classic()
    };
    assert_eq!(config.classic_object(), "h");
}

#[test]
fn enrichment_config_classic_fragment_default() {
    let config = classic();
    assert_eq!(config.classic_fragment(), "React.Fragment");
}

#[test]
fn enrichment_config_classic_fragment_custom() {
    let config = ReactLoweringConfig {
        classic_fragment_pragma: Some("Fragment".to_string()),
        ..classic()
    };
    assert_eq!(config.classic_fragment(), "Fragment");
}

#[test]
fn enrichment_config_automatic_import_prod() {
    let config = automatic();
    assert_eq!(config.automatic_import(), "react/jsx-runtime");
}

#[test]
fn enrichment_config_automatic_import_dev() {
    let config = dev_auto();
    assert_eq!(config.automatic_import(), "react/jsx-dev-runtime");
}

#[test]
fn enrichment_config_automatic_import_custom() {
    let config = ReactLoweringConfig {
        automatic_import_source: Some("preact/jsx-runtime".to_string()),
        ..automatic()
    };
    assert_eq!(config.automatic_import(), "preact/jsx-runtime");
}

#[test]
fn enrichment_config_automatic_factory_zero_children() {
    let config = automatic();
    assert_eq!(config.automatic_factory(0), "jsx");
}

#[test]
fn enrichment_config_automatic_factory_one_child() {
    let config = automatic();
    assert_eq!(config.automatic_factory(1), "jsx");
}

#[test]
fn enrichment_config_automatic_factory_two_children() {
    let config = automatic();
    assert_eq!(config.automatic_factory(2), "jsxs");
}

#[test]
fn enrichment_config_automatic_factory_dev_always_jsxdev() {
    let config = dev_auto();
    assert_eq!(config.automatic_factory(0), "jsxDEV");
    assert_eq!(config.automatic_factory(1), "jsxDEV");
    assert_eq!(config.automatic_factory(5), "jsxDEV");
}

// ---------------------------------------------------------------------------
// ReactLoweringError serde and Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_preserve_serde() {
    let err = ReactLoweringError::PreserveMode;
    let json = serde_json::to_string(&err).unwrap();
    let back: ReactLoweringError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

#[test]
fn enrichment_error_depth_exceeded_serde() {
    let err = ReactLoweringError::DepthExceeded {
        max_depth: 64,
        span: span(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ReactLoweringError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

#[test]
fn enrichment_error_internal_serde() {
    let err = ReactLoweringError::InternalError {
        message: "invariant violated".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: ReactLoweringError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ---------------------------------------------------------------------------
// BuildMode
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_mode_display_unique() {
    assert_ne!(
        BuildMode::Development.as_str(),
        BuildMode::Production.as_str()
    );
    assert_eq!(format!("{}", BuildMode::Development), "development");
    assert_eq!(format!("{}", BuildMode::Production), "production");
}

// ---------------------------------------------------------------------------
// Corpus invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_corpus_all_expected_element_types_non_empty() {
    let corpus = lowering_corpus();
    for spec in &corpus {
        assert!(
            !spec.expected_element_type.is_empty(),
            "specimen {} has empty expected type",
            spec.label
        );
    }
}

#[test]
fn enrichment_corpus_covers_fragment_specimen() {
    let corpus = lowering_corpus();
    let has_fragment = corpus.iter().any(|s| s.expected_element_type == "fragment");
    assert!(has_fragment, "corpus should include a fragment specimen");
}

#[test]
fn enrichment_corpus_covers_component_specimen() {
    let corpus = lowering_corpus();
    let has_component = corpus
        .iter()
        .any(|s| s.expected_element_type.starts_with("component:"));
    assert!(has_component, "corpus should include a component specimen");
}

#[test]
fn enrichment_corpus_covers_intrinsic_specimen() {
    let corpus = lowering_corpus();
    let has_intrinsic = corpus
        .iter()
        .any(|s| s.expected_element_type.starts_with("intrinsic:"));
    assert!(has_intrinsic, "corpus should include an intrinsic specimen");
}

#[test]
fn enrichment_corpus_run_dev_mode_all_pass_or_diag() {
    let manifest = run_lowering_corpus(&dev_auto());
    assert_eq!(manifest.fail_count, 0);
    assert!(manifest.pass_count > 0);
}

// ---------------------------------------------------------------------------
// Automatic mode children-in-props contract
// ---------------------------------------------------------------------------

#[test]
fn enrichment_automatic_single_text_child_folded_as_string() {
    let node = div_node(vec![], vec![text_child("hello")]);
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();
    // Children should be in props, not in element.children
    assert!(result.element.children.is_empty());
    // Find children prop
    let children_prop = result
        .element
        .props
        .entries
        .iter()
        .find(|e| matches!(e, PropsEntry::Named(p) if p.name == "children"));
    assert!(children_prop.is_some());
    // Single text child folded as StringLiteral, not array
    if let Some(PropsEntry::Named(p)) = children_prop {
        assert!(matches!(p.value, LoweredPropValue::StringLiteral { .. }));
    }
}

#[test]
fn enrichment_automatic_multiple_children_folded_as_array() {
    let node = div_node(vec![], vec![text_child("A"), text_child("B")]);
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();
    assert!(result.element.children.is_empty());
    let children_prop = result
        .element
        .props
        .entries
        .iter()
        .find(|e| matches!(e, PropsEntry::Named(p) if p.name == "children"));
    assert!(children_prop.is_some());
    if let Some(PropsEntry::Named(p)) = children_prop {
        assert!(matches!(p.value, LoweredPropValue::ChildrenArray { .. }));
    }
}

#[test]
fn enrichment_classic_children_stay_in_element() {
    let node = div_node(vec![], vec![text_child("hello")]);
    let result = lower_jsx_to_react(&node, &classic()).unwrap();
    assert_eq!(result.element.children.len(), 1);
    // No children prop in classic mode
    let has_children_prop = result
        .element
        .props
        .entries
        .iter()
        .any(|e| matches!(e, PropsEntry::Named(p) if p.name == "children"));
    assert!(!has_children_prop);
}

// ---------------------------------------------------------------------------
// Dev mode source location
// ---------------------------------------------------------------------------

#[test]
fn enrichment_dev_source_location_file_and_line() {
    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Development,
        source_file: Some("components/Button.tsx".to_string()),
        emit_source: true,
        ..Default::default()
    };
    let node = div_node(vec![], vec![]);
    let result = lower_jsx_to_react(&node, &config).unwrap();
    let loc = result.element.source_location.as_ref().unwrap();
    assert_eq!(loc.file_name, Some("components/Button.tsx".to_string()));
}

#[test]
fn enrichment_dev_emit_source_false_no_location() {
    let config = ReactLoweringConfig {
        runtime_mode: JsxRuntimeMode::Automatic,
        build_mode: BuildMode::Development,
        source_file: Some("app.tsx".to_string()),
        emit_source: false,
        ..Default::default()
    };
    let node = div_node(vec![], vec![]);
    let result = lower_jsx_to_react(&node, &config).unwrap();
    assert!(result.element.source_location.is_none());
}

// ---------------------------------------------------------------------------
// Fragment lowering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fragment_automatic_imports_fragment_symbol() {
    let frag = JsxNode::Fragment(JsxFragment {
        children: vec![text_child("A")],
        span: span(),
    });
    let result = lower_jsx_to_react(&frag, &automatic()).unwrap();
    assert_eq!(result.element.element_type, ElementType::Fragment);
    let has_fragment_import = result.required_imports.iter().any(|i| i.name == "Fragment");
    assert!(has_fragment_import);
}

#[test]
fn enrichment_fragment_classic_no_extra_import() {
    let frag = JsxNode::Fragment(JsxFragment {
        children: vec![text_child("A")],
        span: span(),
    });
    let result = lower_jsx_to_react(&frag, &classic()).unwrap();
    assert_eq!(result.element.element_type, ElementType::Fragment);
    // Classic uses React.Fragment — no additional import
    let has_fragment_import = result.required_imports.iter().any(|i| i.name == "Fragment");
    assert!(!has_fragment_import);
}

// ---------------------------------------------------------------------------
// Constants validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_prefix() {
    assert!(REACT_LOWERING_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_constants_component_non_empty() {
    assert!(!REACT_LOWERING_COMPONENT.is_empty());
}

#[test]
fn enrichment_constants_policy_id_prefix() {
    assert!(REACT_LOWERING_POLICY_ID.starts_with("RGC-"));
}

// ---------------------------------------------------------------------------
// Compile receipt determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compile_receipt_changes_with_config() {
    let node = div_node(vec![str_attr("id", "x")], vec![text_child("hi")]);
    let parse_result = JsxParseResult {
        node: node.clone(),
        feature_families_used: vec![],
        diagnostics: vec![],
    };
    let r1 = lower_jsx_to_react(&node, &automatic()).unwrap();
    let r2 = lower_jsx_to_react(&node, &classic()).unwrap();
    let receipt1 = compute_lowering_receipt(&parse_result, &r1, &automatic());
    let receipt2 = compute_lowering_receipt(&parse_result, &r2, &classic());
    // Different config → different output hash
    assert_ne!(receipt1.output_hash, receipt2.output_hash);
    assert_ne!(
        receipt1.config_summary.runtime_mode,
        receipt2.config_summary.runtime_mode
    );
}

// ---------------------------------------------------------------------------
// Key extraction with expression attribute
// ---------------------------------------------------------------------------

#[test]
fn enrichment_key_extraction_removes_from_props() {
    let node = div_node(
        vec![
            str_attr("id", "root"),
            expr_attr("key", "item.id"),
            str_attr("className", "box"),
        ],
        vec![],
    );
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();
    assert!(result.element.props.extracted_key.is_some());
    // key should NOT appear in named props
    let key_in_entries = result
        .element
        .props
        .entries
        .iter()
        .any(|e| matches!(e, PropsEntry::Named(p) if p.name == "key"));
    assert!(!key_in_entries);
    // Other props remain
    assert_eq!(result.element.props.named_count(), 2); // id and className
}

// ---------------------------------------------------------------------------
// Stats tracking
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stats_keys_and_refs_counted() {
    let node = div_node(
        vec![
            expr_attr("key", "k1"),
            expr_attr("ref", "r1"),
            str_attr("id", "x"),
        ],
        vec![],
    );
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();
    assert_eq!(result.stats.keys_extracted, 1);
    assert_eq!(result.stats.refs_extracted, 1);
    assert_eq!(result.stats.total_props, 3); // key + ref + id all counted
}

#[test]
fn enrichment_stats_spread_counted() {
    let node = div_node(
        vec![
            str_attr("id", "x"),
            JsxAttribute::Spread {
                expression: "rest".to_string(),
                span: span(),
            },
        ],
        vec![],
    );
    let result = lower_jsx_to_react(&node, &automatic()).unwrap();
    assert_eq!(result.stats.spread_attributes, 1);
}
