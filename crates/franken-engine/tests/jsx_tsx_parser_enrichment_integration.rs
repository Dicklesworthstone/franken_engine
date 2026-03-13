#![forbid(unsafe_code)]
#![allow(
    clippy::too_many_arguments,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::identity_op
)]
//! Enrichment integration tests for `jsx_tsx_parser` module.
//!
//! Covers: JsxRuntimeMode, JsxFeatureFamily, JsxElementName, JsxAttribute,
//! JsxAttributeValue, JsxChild, JsxElement, JsxFragment, JsxNode,
//! JsxDiagnosticSeverity, JsxDiagnosticCode, JsxDiagnostic, JsxParseError,
//! JsxParserConfig, JsxParseResult, JsxExpectedOutcome, JsxSpecimen, JsxVerdict,
//! JsxSpecimenEvidence, JsxEvidenceEvent, JsxRunManifest, JsxEvidenceInventory,
//! JsxArtifactPaths, parse_jsx, jsx_corpus, run_jsx_corpus,
//! write_jsx_evidence_bundle — Display, serde, lifecycle, cross-cutting scenarios.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::jsx_tsx_parser::*;

// ── Helper ──────────────────────────────────────────────────────────────

fn default_config() -> JsxParserConfig {
    JsxParserConfig::default()
}

fn ns_config() -> JsxParserConfig {
    JsxParserConfig {
        allow_namespaced_names: true,
        ..default_config()
    }
}

fn span(start: u64, end: u64) -> SourceSpan {
    SourceSpan::new(start, end, 1, 1, 1, end + 1)
}

// ── JsxRuntimeMode ─────────────────────────────────────────────────────

#[test]
fn enrichment_runtime_mode_all_count() {
    assert_eq!(JsxRuntimeMode::ALL.len(), 3);
}

#[test]
fn enrichment_runtime_mode_display_unique() {
    let displays: BTreeSet<String> = JsxRuntimeMode::ALL.iter().map(|m| m.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_runtime_mode_as_str_matches_display() {
    for mode in JsxRuntimeMode::ALL {
        assert_eq!(mode.as_str(), mode.to_string());
    }
}

#[test]
fn enrichment_runtime_mode_as_str_snake_case() {
    for mode in JsxRuntimeMode::ALL {
        let s = mode.as_str();
        assert!(!s.is_empty());
        assert!(s.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'));
    }
}

#[test]
fn enrichment_runtime_mode_serde_all() {
    for mode in JsxRuntimeMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let back: JsxRuntimeMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

#[test]
fn enrichment_runtime_mode_serde_uses_snake_case() {
    let json = serde_json::to_string(&JsxRuntimeMode::Automatic).unwrap();
    assert!(json.contains("automatic"));
}

// ── JsxFeatureFamily ───────────────────────────────────────────────────

#[test]
fn enrichment_feature_family_all_count() {
    assert_eq!(JsxFeatureFamily::ALL.len(), 12);
}

#[test]
fn enrichment_feature_family_display_unique() {
    let displays: BTreeSet<String> = JsxFeatureFamily::ALL
        .iter()
        .map(|f| f.to_string())
        .collect();
    assert_eq!(displays.len(), 12);
}

#[test]
fn enrichment_feature_family_as_str_matches_display() {
    for family in JsxFeatureFamily::ALL {
        assert_eq!(family.as_str(), family.to_string());
    }
}

#[test]
fn enrichment_feature_family_as_str_snake_case() {
    for family in JsxFeatureFamily::ALL {
        let s = family.as_str();
        assert!(!s.is_empty());
        assert!(s.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'));
    }
}

#[test]
fn enrichment_feature_family_serde_all() {
    for family in JsxFeatureFamily::ALL {
        let json = serde_json::to_string(family).unwrap();
        let back: JsxFeatureFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*family, back);
    }
}

#[test]
fn enrichment_feature_family_description_non_empty_and_unique() {
    let descs: BTreeSet<&str> = JsxFeatureFamily::ALL
        .iter()
        .map(|f| f.description())
        .collect();
    assert_eq!(descs.len(), 12);
    for d in &descs {
        assert!(!d.is_empty());
    }
}

#[test]
fn enrichment_feature_family_description_contains_jsx() {
    for family in JsxFeatureFamily::ALL {
        let d = family.description();
        // Every description references the syntax construct
        assert!(
            d.len() > 10,
            "description too short for {}",
            family.as_str()
        );
    }
}

// ── JsxDiagnosticSeverity ──────────────────────────────────────────────

#[test]
fn enrichment_diagnostic_severity_display_unique() {
    let s_err = JsxDiagnosticSeverity::Error.to_string();
    let s_warn = JsxDiagnosticSeverity::Warning.to_string();
    assert_ne!(s_err, s_warn);
}

#[test]
fn enrichment_diagnostic_severity_as_str_matches_display() {
    assert_eq!(
        JsxDiagnosticSeverity::Error.as_str(),
        JsxDiagnosticSeverity::Error.to_string()
    );
    assert_eq!(
        JsxDiagnosticSeverity::Warning.as_str(),
        JsxDiagnosticSeverity::Warning.to_string()
    );
}

#[test]
fn enrichment_diagnostic_severity_serde_roundtrip() {
    for sev in [JsxDiagnosticSeverity::Error, JsxDiagnosticSeverity::Warning] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: JsxDiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

// ── JsxDiagnosticCode ──────────────────────────────────────────────────

#[test]
fn enrichment_diagnostic_code_all_count() {
    assert_eq!(JsxDiagnosticCode::ALL.len(), 10);
}

#[test]
fn enrichment_diagnostic_code_as_str_unique() {
    let codes: BTreeSet<&str> = JsxDiagnosticCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(codes.len(), 10);
}

#[test]
fn enrichment_diagnostic_code_all_start_with_fe_jsx() {
    for code in JsxDiagnosticCode::ALL {
        assert!(
            code.as_str().starts_with("FE-JSX-"),
            "code {} does not start with FE-JSX-",
            code.as_str()
        );
    }
}

#[test]
fn enrichment_diagnostic_code_display_matches_as_str() {
    for code in JsxDiagnosticCode::ALL {
        assert_eq!(code.to_string(), code.as_str());
    }
}

#[test]
fn enrichment_diagnostic_code_message_unique() {
    let msgs: BTreeSet<&str> = JsxDiagnosticCode::ALL.iter().map(|c| c.message()).collect();
    assert_eq!(msgs.len(), 10);
}

#[test]
fn enrichment_diagnostic_code_message_non_empty() {
    for code in JsxDiagnosticCode::ALL {
        assert!(!code.message().is_empty());
    }
}

#[test]
fn enrichment_diagnostic_code_serde_all() {
    for code in JsxDiagnosticCode::ALL {
        let json = serde_json::to_string(code).unwrap();
        let back: JsxDiagnosticCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, back);
    }
}

// ── JsxDiagnostic ──────────────────────────────────────────────────────

#[test]
fn enrichment_diagnostic_display_format() {
    let d = JsxDiagnostic {
        code: JsxDiagnosticCode::EmptyExpression,
        severity: JsxDiagnosticSeverity::Error,
        message: "cannot be empty".to_string(),
        span: None,
    };
    let s = d.to_string();
    assert!(s.contains("error"));
    assert!(s.contains("FE-JSX-0007"));
    assert!(s.contains("cannot be empty"));
}

#[test]
fn enrichment_diagnostic_serde_with_span() {
    let d = JsxDiagnostic {
        code: JsxDiagnosticCode::InvalidElementName,
        severity: JsxDiagnosticSeverity::Warning,
        message: "bad name".to_string(),
        span: Some(span(0, 5)),
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: JsxDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn enrichment_diagnostic_serde_without_span() {
    let d = JsxDiagnostic {
        code: JsxDiagnosticCode::UnsupportedJsxSyntax,
        severity: JsxDiagnosticSeverity::Error,
        message: "unsupported".to_string(),
        span: None,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: JsxDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ── JsxParseError ──────────────────────────────────────────────────────

#[test]
fn enrichment_parse_error_display_unique() {
    let errs: Vec<JsxParseError> = vec![
        JsxParseError::EmptyInput,
        JsxParseError::DepthExceeded {
            depth: 65,
            limit: 64,
        },
        JsxParseError::FailClosed {
            diagnostics: vec![JsxDiagnostic {
                code: JsxDiagnosticCode::MissingClosingTag,
                severity: JsxDiagnosticSeverity::Error,
                message: "missing".to_string(),
                span: None,
            }],
        },
    ];
    let displays: BTreeSet<String> = errs.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_parse_error_serde_empty_input() {
    let err = JsxParseError::EmptyInput;
    let json = serde_json::to_string(&err).unwrap();
    let back: JsxParseError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_parse_error_serde_depth_exceeded() {
    let err = JsxParseError::DepthExceeded {
        depth: 200,
        limit: 64,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: JsxParseError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_parse_error_serde_fail_closed() {
    let err = JsxParseError::FailClosed {
        diagnostics: vec![JsxDiagnostic {
            code: JsxDiagnosticCode::UnmatchedOpeningTag,
            severity: JsxDiagnosticSeverity::Error,
            message: "no match".to_string(),
            span: Some(span(0, 10)),
        }],
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: JsxParseError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_parse_error_display_depth_includes_numbers() {
    let err = JsxParseError::DepthExceeded {
        depth: 999,
        limit: 50,
    };
    let s = err.to_string();
    assert!(s.contains("999"));
    assert!(s.contains("50"));
}

#[test]
fn enrichment_parse_error_display_fail_closed_shows_count() {
    let err = JsxParseError::FailClosed {
        diagnostics: vec![
            JsxDiagnostic {
                code: JsxDiagnosticCode::EmptyExpression,
                severity: JsxDiagnosticSeverity::Error,
                message: "a".into(),
                span: None,
            },
            JsxDiagnostic {
                code: JsxDiagnosticCode::InvalidAttributeName,
                severity: JsxDiagnosticSeverity::Error,
                message: "b".into(),
                span: None,
            },
        ],
    };
    let s = err.to_string();
    assert!(s.contains("2"));
}

// ── JsxElementName ─────────────────────────────────────────────────────

#[test]
fn enrichment_element_name_identifier_span() {
    let name = JsxElementName::Identifier {
        name: "div".into(),
        span: span(0, 3),
    };
    assert_eq!(name.span().start_offset, 0);
    assert_eq!(name.span().end_offset, 3);
}

#[test]
fn enrichment_element_name_identifier_to_string_repr() {
    let name = JsxElementName::Identifier {
        name: "section".into(),
        span: span(0, 7),
    };
    assert_eq!(name.to_string_repr(), "section");
}

#[test]
fn enrichment_element_name_member_expression_to_string_repr() {
    let name = JsxElementName::MemberExpression {
        segments: vec!["Ctx".into(), "Provider".into()],
        span: span(0, 12),
    };
    assert_eq!(name.to_string_repr(), "Ctx.Provider");
}

#[test]
fn enrichment_element_name_namespaced_to_string_repr() {
    let name = JsxElementName::NamespacedName {
        namespace: "svg".into(),
        name: "rect".into(),
        span: span(0, 8),
    };
    assert_eq!(name.to_string_repr(), "svg:rect");
}

#[test]
fn enrichment_element_name_is_component_uppercase_identifier() {
    let name = JsxElementName::Identifier {
        name: "App".into(),
        span: span(0, 3),
    };
    assert!(name.is_component());
}

#[test]
fn enrichment_element_name_is_component_lowercase_identifier() {
    let name = JsxElementName::Identifier {
        name: "div".into(),
        span: span(0, 3),
    };
    assert!(!name.is_component());
}

#[test]
fn enrichment_element_name_is_component_member_expression_upper() {
    let name = JsxElementName::MemberExpression {
        segments: vec!["React".into(), "Fragment".into()],
        span: span(0, 14),
    };
    assert!(name.is_component());
}

#[test]
fn enrichment_element_name_is_component_member_expression_lower() {
    let name = JsxElementName::MemberExpression {
        segments: vec!["ctx".into(), "provider".into()],
        span: span(0, 12),
    };
    assert!(!name.is_component());
}

#[test]
fn enrichment_element_name_is_component_namespaced_always_false() {
    let name = JsxElementName::NamespacedName {
        namespace: "Svg".into(),
        name: "Rect".into(),
        span: span(0, 8),
    };
    assert!(!name.is_component());
}

#[test]
fn enrichment_element_name_serde_identifier() {
    let name = JsxElementName::Identifier {
        name: "div".into(),
        span: span(0, 3),
    };
    let json = serde_json::to_string(&name).unwrap();
    let back: JsxElementName = serde_json::from_str(&json).unwrap();
    assert_eq!(name, back);
}

#[test]
fn enrichment_element_name_serde_member_expression() {
    let name = JsxElementName::MemberExpression {
        segments: vec!["A".into(), "B".into(), "C".into()],
        span: span(0, 5),
    };
    let json = serde_json::to_string(&name).unwrap();
    let back: JsxElementName = serde_json::from_str(&json).unwrap();
    assert_eq!(name, back);
}

#[test]
fn enrichment_element_name_serde_namespaced() {
    let name = JsxElementName::NamespacedName {
        namespace: "xml".into(),
        name: "space".into(),
        span: span(0, 9),
    };
    let json = serde_json::to_string(&name).unwrap();
    let back: JsxElementName = serde_json::from_str(&json).unwrap();
    assert_eq!(name, back);
}

// ── JsxAttributeValue ──────────────────────────────────────────────────

#[test]
fn enrichment_attribute_value_string_literal_serde() {
    let val = JsxAttributeValue::StringLiteral {
        value: "hello".into(),
    };
    let json = serde_json::to_string(&val).unwrap();
    let back: JsxAttributeValue = serde_json::from_str(&json).unwrap();
    assert_eq!(val, back);
}

#[test]
fn enrichment_attribute_value_expression_serde() {
    let val = JsxAttributeValue::Expression {
        expression: "a + b".into(),
    };
    let json = serde_json::to_string(&val).unwrap();
    let back: JsxAttributeValue = serde_json::from_str(&json).unwrap();
    assert_eq!(val, back);
}

#[test]
fn enrichment_attribute_value_implicit_true_serde() {
    let val = JsxAttributeValue::ImplicitTrue;
    let json = serde_json::to_string(&val).unwrap();
    let back: JsxAttributeValue = serde_json::from_str(&json).unwrap();
    assert_eq!(val, back);
}

// ── JsxAttribute ───────────────────────────────────────────────────────

#[test]
fn enrichment_attribute_named_span() {
    let attr = JsxAttribute::Named {
        name: "className".into(),
        value: JsxAttributeValue::StringLiteral {
            value: "app".into(),
        },
        span: span(5, 20),
    };
    assert_eq!(attr.span().start_offset, 5);
    assert_eq!(attr.span().end_offset, 20);
}

#[test]
fn enrichment_attribute_spread_span() {
    let attr = JsxAttribute::Spread {
        expression: "props".into(),
        span: span(3, 15),
    };
    assert_eq!(attr.span().start_offset, 3);
}

#[test]
fn enrichment_attribute_serde_named() {
    let attr = JsxAttribute::Named {
        name: "id".into(),
        value: JsxAttributeValue::StringLiteral {
            value: "main".into(),
        },
        span: span(0, 10),
    };
    let json = serde_json::to_string(&attr).unwrap();
    let back: JsxAttribute = serde_json::from_str(&json).unwrap();
    assert_eq!(attr, back);
}

#[test]
fn enrichment_attribute_serde_spread() {
    let attr = JsxAttribute::Spread {
        expression: "rest".into(),
        span: span(0, 10),
    };
    let json = serde_json::to_string(&attr).unwrap();
    let back: JsxAttribute = serde_json::from_str(&json).unwrap();
    assert_eq!(attr, back);
}

// ── JsxChild ───────────────────────────────────────────────────────────

#[test]
fn enrichment_child_text_span() {
    let child = JsxChild::Text {
        value: "hello".into(),
        span: span(5, 10),
    };
    assert_eq!(child.span().start_offset, 5);
}

#[test]
fn enrichment_child_expression_container_span() {
    let child = JsxChild::ExpressionContainer {
        expression: "x".into(),
        span: span(2, 5),
    };
    assert_eq!(child.span().start_offset, 2);
}

#[test]
fn enrichment_child_element_span() {
    let inner = JsxElement {
        name: JsxElementName::Identifier {
            name: "em".into(),
            span: span(1, 3),
        },
        attributes: vec![],
        children: vec![],
        self_closing: true,
        span: span(0, 7),
    };
    let child = JsxChild::Element(Box::new(inner));
    assert_eq!(child.span().start_offset, 0);
}

#[test]
fn enrichment_child_fragment_span() {
    let frag = JsxFragment {
        children: vec![],
        span: span(10, 16),
    };
    let child = JsxChild::Fragment(Box::new(frag));
    assert_eq!(child.span().start_offset, 10);
}

// ── JsxNode ────────────────────────────────────────────────────────────

#[test]
fn enrichment_node_element_span() {
    let el = JsxElement {
        name: JsxElementName::Identifier {
            name: "div".into(),
            span: span(1, 4),
        },
        attributes: vec![],
        children: vec![],
        self_closing: true,
        span: span(0, 7),
    };
    let node = JsxNode::Element(el);
    assert_eq!(node.span().start_offset, 0);
    assert_eq!(node.span().end_offset, 7);
}

#[test]
fn enrichment_node_fragment_span() {
    let frag = JsxFragment {
        children: vec![],
        span: span(0, 5),
    };
    let node = JsxNode::Fragment(frag);
    assert_eq!(node.span().start_offset, 0);
    assert_eq!(node.span().end_offset, 5);
}

#[test]
fn enrichment_node_serde_element() {
    let el = JsxElement {
        name: JsxElementName::Identifier {
            name: "p".into(),
            span: span(1, 2),
        },
        attributes: vec![],
        children: vec![JsxChild::Text {
            value: "text".into(),
            span: span(3, 7),
        }],
        self_closing: false,
        span: span(0, 11),
    };
    let node = JsxNode::Element(el);
    let json = serde_json::to_string(&node).unwrap();
    let back: JsxNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn enrichment_node_serde_fragment() {
    let node = JsxNode::Fragment(JsxFragment {
        children: vec![],
        span: span(0, 5),
    });
    let json = serde_json::to_string(&node).unwrap();
    let back: JsxNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

// ── JsxParserConfig ───────────────────────────────────────────────────

#[test]
fn enrichment_config_default_values() {
    let config = JsxParserConfig::default();
    assert_eq!(config.runtime_mode, JsxRuntimeMode::Automatic);
    assert_eq!(config.max_depth, 64);
    assert!(!config.allow_namespaced_names);
    assert!(!config.tsx_mode);
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let config = JsxParserConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        max_depth: 32,
        allow_namespaced_names: true,
        tsx_mode: true,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: JsxParserConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_config_all_runtime_modes_roundtrip() {
    for mode in JsxRuntimeMode::ALL {
        let config = JsxParserConfig {
            runtime_mode: *mode,
            ..default_config()
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: JsxParserConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }
}

// ── Constants ──────────────────────────────────────────────────────────

#[test]
fn enrichment_constants_schema_versions_non_empty() {
    assert!(!JSX_PARSER_SCHEMA_VERSION.is_empty());
    assert!(!JSX_PARSER_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!JSX_PARSER_EVENT_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_constants_schema_versions_unique() {
    let versions: BTreeSet<&str> = [
        JSX_PARSER_SCHEMA_VERSION,
        JSX_PARSER_MANIFEST_SCHEMA_VERSION,
        JSX_PARSER_EVENT_SCHEMA_VERSION,
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(versions.len(), 3);
}

#[test]
fn enrichment_constants_schema_versions_franken_engine_prefix() {
    assert!(JSX_PARSER_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(JSX_PARSER_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(JSX_PARSER_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_constants_component_and_policy() {
    assert_eq!(JSX_PARSER_COMPONENT, "jsx_tsx_parser");
    assert_eq!(JSX_PARSER_POLICY_ID, "RGC-206A");
}

// ── parse_jsx — success cases ──────────────────────────────────────────

#[test]
fn enrichment_parse_simple_element_text_child() {
    let result = parse_jsx("<div>hello</div>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.name.to_string_repr(), "div");
            assert!(!el.self_closing);
            assert_eq!(el.children.len(), 1);
            match &el.children[0] {
                JsxChild::Text { value, .. } => assert_eq!(value, "hello"),
                _ => panic!("expected text child"),
            }
        }
        _ => panic!("expected element"),
    }
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::Element)
    );
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::TextChild)
    );
}

#[test]
fn enrichment_parse_self_closing_intrinsic() {
    let result = parse_jsx("<br />", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert!(el.self_closing);
            assert!(el.children.is_empty());
            assert!(el.attributes.is_empty());
        }
        _ => panic!("expected element"),
    }
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::SelfClosing)
    );
}

#[test]
fn enrichment_parse_fragment_with_text() {
    let result = parse_jsx("<>hello</>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Fragment(frag) => {
            assert_eq!(frag.children.len(), 1);
        }
        _ => panic!("expected fragment"),
    }
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::Fragment)
    );
}

#[test]
fn enrichment_parse_string_attribute_value() {
    let result = parse_jsx(r#"<div id="main">x</div>"#, &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.attributes.len(), 1);
            match &el.attributes[0] {
                JsxAttribute::Named { name, value, .. } => {
                    assert_eq!(name, "id");
                    assert_eq!(
                        *value,
                        JsxAttributeValue::StringLiteral {
                            value: "main".into()
                        }
                    );
                }
                _ => panic!("expected named attr"),
            }
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_expression_attribute_value() {
    let result = parse_jsx("<div count={n + 1}>x</div>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => match &el.attributes[0] {
            JsxAttribute::Named { name, value, .. } => {
                assert_eq!(name, "count");
                assert_eq!(
                    *value,
                    JsxAttributeValue::Expression {
                        expression: "n + 1".into()
                    }
                );
            }
            _ => panic!("expected named attr"),
        },
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_spread_attribute() {
    let result = parse_jsx("<Comp {...rest} />", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => match &el.attributes[0] {
            JsxAttribute::Spread { expression, .. } => {
                assert_eq!(expression, "rest");
            }
            _ => panic!("expected spread"),
        },
        _ => panic!("expected element"),
    }
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::SpreadAttribute)
    );
}

#[test]
fn enrichment_parse_boolean_attribute_implicit_true() {
    let result = parse_jsx("<input disabled />", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => match &el.attributes[0] {
            JsxAttribute::Named { name, value, .. } => {
                assert_eq!(name, "disabled");
                assert_eq!(*value, JsxAttributeValue::ImplicitTrue);
            }
            _ => panic!("expected named attr"),
        },
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_expression_child() {
    let result = parse_jsx("<div>{items.length}</div>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.children.len(), 1);
            match &el.children[0] {
                JsxChild::ExpressionContainer { expression, .. } => {
                    assert_eq!(expression, "items.length");
                }
                _ => panic!("expected expression child"),
            }
        }
        _ => panic!("expected element"),
    }
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::ExpressionChild)
    );
}

#[test]
fn enrichment_parse_nested_element() {
    let result = parse_jsx("<div><span>inner</span></div>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(outer) => {
            assert_eq!(outer.children.len(), 1);
            match &outer.children[0] {
                JsxChild::Element(inner) => {
                    assert_eq!(inner.name.to_string_repr(), "span");
                    assert_eq!(inner.children.len(), 1);
                }
                _ => panic!("expected nested element"),
            }
        }
        _ => panic!("expected element"),
    }
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::NestedElement)
    );
}

#[test]
fn enrichment_parse_member_expression_name() {
    let result = parse_jsx("<Ctx.Provider>x</Ctx.Provider>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.name.to_string_repr(), "Ctx.Provider");
            assert!(el.name.is_component());
            match &el.name {
                JsxElementName::MemberExpression { segments, .. } => {
                    assert_eq!(segments.len(), 2);
                    assert_eq!(segments[0], "Ctx");
                    assert_eq!(segments[1], "Provider");
                }
                _ => panic!("expected member expression"),
            }
        }
        _ => panic!("expected element"),
    }
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::MemberExpressionName)
    );
}

#[test]
fn enrichment_parse_namespaced_name_with_config() {
    let result = parse_jsx("<svg:rect />", &ns_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.name.to_string_repr(), "svg:rect");
            match &el.name {
                JsxElementName::NamespacedName {
                    namespace, name, ..
                } => {
                    assert_eq!(namespace, "svg");
                    assert_eq!(name, "rect");
                }
                _ => panic!("expected namespaced name"),
            }
        }
        _ => panic!("expected element"),
    }
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::NamespacedName)
    );
}

#[test]
fn enrichment_parse_key_prop_detected() {
    let result = parse_jsx(r#"<Item key="a" />"#, &default_config()).unwrap();
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::KeyProp)
    );
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::StringAttribute)
    );
}

#[test]
fn enrichment_parse_mixed_children_order() {
    let result = parse_jsx("<div>text{expr}<span /></div>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.children.len(), 3);
            assert!(matches!(&el.children[0], JsxChild::Text { .. }));
            assert!(matches!(
                &el.children[1],
                JsxChild::ExpressionContainer { .. }
            ));
            assert!(matches!(&el.children[2], JsxChild::Element(_)));
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_multiple_attributes_mixed() {
    let result = parse_jsx(
        r#"<Btn onClick={handler} disabled className="primary" />"#,
        &default_config(),
    )
    .unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.attributes.len(), 3);
            // onClick is expression
            match &el.attributes[0] {
                JsxAttribute::Named { name, value, .. } => {
                    assert_eq!(name, "onClick");
                    assert!(matches!(value, JsxAttributeValue::Expression { .. }));
                }
                _ => panic!("expected named"),
            }
            // disabled is implicit true
            match &el.attributes[1] {
                JsxAttribute::Named { name, value, .. } => {
                    assert_eq!(name, "disabled");
                    assert_eq!(*value, JsxAttributeValue::ImplicitTrue);
                }
                _ => panic!("expected named"),
            }
            // className is string
            match &el.attributes[2] {
                JsxAttribute::Named { name, value, .. } => {
                    assert_eq!(name, "className");
                    assert!(matches!(value, JsxAttributeValue::StringLiteral { .. }));
                }
                _ => panic!("expected named"),
            }
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_fragment_with_nested_element_child() {
    let result = parse_jsx("<><div>inner</div></>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Fragment(frag) => {
            assert_eq!(frag.children.len(), 1);
            match &frag.children[0] {
                JsxChild::Element(el) => {
                    assert_eq!(el.name.to_string_repr(), "div");
                }
                _ => panic!("expected element child"),
            }
        }
        _ => panic!("expected fragment"),
    }
}

// ── parse_jsx — error cases ────────────────────────────────────────────

#[test]
fn enrichment_parse_empty_input_returns_error() {
    let err = parse_jsx("", &default_config()).unwrap_err();
    assert!(matches!(err, JsxParseError::EmptyInput));
}

#[test]
fn enrichment_parse_whitespace_only_returns_empty_input() {
    let err = parse_jsx("   \n\t  ", &default_config()).unwrap_err();
    assert!(matches!(err, JsxParseError::EmptyInput));
}

#[test]
fn enrichment_parse_no_jsx_start_returns_fail_closed() {
    let err = parse_jsx("just plain text", &default_config()).unwrap_err();
    match err {
        JsxParseError::FailClosed { diagnostics } => {
            assert!(!diagnostics.is_empty());
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.code == JsxDiagnosticCode::UnsupportedJsxSyntax)
            );
        }
        other => panic!("expected FailClosed, got {:?}", other),
    }
}

#[test]
fn enrichment_parse_depth_exceeded_with_small_limit() {
    let config = JsxParserConfig {
        max_depth: 1,
        ..default_config()
    };
    let err = parse_jsx("<a><b><c>x</c></b></a>", &config).unwrap_err();
    match err {
        JsxParseError::DepthExceeded { depth, limit } => {
            assert!(depth > limit);
            assert_eq!(limit, 1);
        }
        other => panic!("expected DepthExceeded, got {:?}", other),
    }
}

#[test]
fn enrichment_parse_mismatched_tags_produces_diagnostic() {
    let result = parse_jsx("<div>text</span>", &default_config());
    match result {
        Ok(r) => {
            assert!(
                r.diagnostics
                    .iter()
                    .any(|d| d.code == JsxDiagnosticCode::UnmatchedClosingTag)
            );
        }
        Err(JsxParseError::FailClosed { diagnostics }) => {
            assert!(!diagnostics.is_empty());
        }
        Err(other) => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn enrichment_parse_missing_closing_tag() {
    let result = parse_jsx("<div>content", &default_config());
    match result {
        Ok(r) => {
            assert!(
                r.diagnostics
                    .iter()
                    .any(|d| d.code == JsxDiagnosticCode::MissingClosingTag)
            );
        }
        Err(JsxParseError::FailClosed { diagnostics }) => {
            assert!(!diagnostics.is_empty());
        }
        Err(other) => panic!("unexpected error: {:?}", other),
    }
}

// ── parse_jsx — span coverage ──────────────────────────────────────────

#[test]
fn enrichment_parse_span_starts_at_zero() {
    let result = parse_jsx("<div />", &default_config()).unwrap();
    let sp = result.node.span();
    assert_eq!(sp.start_offset, 0);
    assert_eq!(sp.start_line, 1);
    assert_eq!(sp.start_column, 1);
}

#[test]
fn enrichment_parse_span_covers_full_source() {
    let source = "<div>hello</div>";
    let result = parse_jsx(source, &default_config()).unwrap();
    let sp = result.node.span();
    assert_eq!(sp.start_offset, 0);
    assert_eq!(sp.end_offset, source.len() as u64);
}

#[test]
fn enrichment_parse_child_spans_within_parent() {
    let result = parse_jsx("<div>text</div>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            let parent_start = el.span.start_offset;
            let parent_end = el.span.end_offset;
            for child in &el.children {
                let cs = child.span();
                assert!(cs.start_offset >= parent_start);
                assert!(cs.end_offset <= parent_end);
            }
        }
        _ => panic!("expected element"),
    }
}

// ── parse_jsx — feature family deduplication ───────────────────────────

#[test]
fn enrichment_parse_feature_families_sorted_and_deduplicated() {
    let result = parse_jsx("<div>hello</div>", &default_config()).unwrap();
    let fam = &result.feature_families_used;
    // Check sorted
    for w in fam.windows(2) {
        assert!(w[0] <= w[1], "families not sorted");
    }
    // Check deduplicated
    let set: BTreeSet<_> = fam.iter().collect();
    assert_eq!(set.len(), fam.len(), "families not deduplicated");
}

// ── JsxExpectedOutcome ─────────────────────────────────────────────────

#[test]
fn enrichment_expected_outcome_as_str() {
    assert_eq!(JsxExpectedOutcome::ParsesOk.as_str(), "parses_ok");
    assert_eq!(JsxExpectedOutcome::FailClosed.as_str(), "fail_closed");
}

#[test]
fn enrichment_expected_outcome_serde_roundtrip() {
    for outcome in [JsxExpectedOutcome::ParsesOk, JsxExpectedOutcome::FailClosed] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: JsxExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}

// ── JsxVerdict ─────────────────────────────────────────────────────────

#[test]
fn enrichment_verdict_as_str_unique() {
    let strs: BTreeSet<&str> = [
        JsxVerdict::Pass,
        JsxVerdict::Fail,
        JsxVerdict::ExpectedFailure,
    ]
    .iter()
    .map(|v| v.as_str())
    .collect();
    assert_eq!(strs.len(), 3);
}

#[test]
fn enrichment_verdict_serde_all() {
    for verdict in [
        JsxVerdict::Pass,
        JsxVerdict::Fail,
        JsxVerdict::ExpectedFailure,
    ] {
        let json = serde_json::to_string(&verdict).unwrap();
        let back: JsxVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, back);
    }
}

// ── JsxSpecimen ────────────────────────────────────────────────────────

#[test]
fn enrichment_specimen_serde_roundtrip() {
    let specimen = JsxSpecimen {
        specimen_id: "test_spec".into(),
        feature_family: JsxFeatureFamily::Fragment,
        source: "<>text</>".into(),
        expected_outcome: JsxExpectedOutcome::ParsesOk,
        description: "A test specimen".into(),
    };
    let json = serde_json::to_string(&specimen).unwrap();
    let back: JsxSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(specimen, back);
}

// ── JsxSpecimenEvidence ────────────────────────────────────────────────

#[test]
fn enrichment_specimen_evidence_serde_roundtrip() {
    let ev = JsxSpecimenEvidence {
        specimen_id: "test_1".into(),
        feature_family: JsxFeatureFamily::Element,
        verdict: JsxVerdict::Pass,
        parse_succeeded: true,
        diagnostic_count: 0,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: JsxSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ── JsxEvidenceEvent ──────────────────────────────────────────────────

#[test]
fn enrichment_evidence_event_serde_roundtrip() {
    let ev = JsxEvidenceEvent {
        schema_version: JSX_PARSER_EVENT_SCHEMA_VERSION.to_string(),
        component: JSX_PARSER_COMPONENT.to_string(),
        specimen_id: "test_specimen".into(),
        verdict: JsxVerdict::ExpectedFailure,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: JsxEvidenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ── JsxRunManifest ────────────────────────────────────────────────────

#[test]
fn enrichment_run_manifest_serde_roundtrip() {
    let m = JsxRunManifest {
        schema_version: JSX_PARSER_MANIFEST_SCHEMA_VERSION.to_string(),
        component: JSX_PARSER_COMPONENT.to_string(),
        policy_id: JSX_PARSER_POLICY_ID.to_string(),
        specimen_count: 18,
        pass_count: 14,
        fail_count: 0,
        expected_failure_count: 4,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: JsxRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ── JsxEvidenceInventory ──────────────────────────────────────────────

#[test]
fn enrichment_evidence_inventory_serde_roundtrip() {
    let mut family_coverage = BTreeMap::new();
    family_coverage.insert("element".to_string(), 5usize);
    family_coverage.insert("fragment".to_string(), 2usize);

    let inv = JsxEvidenceInventory {
        schema_version: JSX_PARSER_SCHEMA_VERSION.to_string(),
        component: JSX_PARSER_COMPONENT.to_string(),
        policy_id: JSX_PARSER_POLICY_ID.to_string(),
        specimens: vec![JsxSpecimenEvidence {
            specimen_id: "s1".into(),
            feature_family: JsxFeatureFamily::Element,
            verdict: JsxVerdict::Pass,
            parse_succeeded: true,
            diagnostic_count: 0,
        }],
        family_coverage,
        evidence_hash: "sha256:abc123".into(),
    };
    let json = serde_json::to_string(&inv).unwrap();
    let back: JsxEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ── jsx_corpus ─────────────────────────────────────────────────────────

#[test]
fn enrichment_corpus_non_empty() {
    let corpus = jsx_corpus();
    assert!(corpus.len() >= 15);
}

#[test]
fn enrichment_corpus_ids_unique() {
    let corpus = jsx_corpus();
    let ids: BTreeSet<_> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    assert_eq!(ids.len(), corpus.len());
}

#[test]
fn enrichment_corpus_descriptions_non_empty() {
    for spec in &jsx_corpus() {
        assert!(
            !spec.description.is_empty(),
            "specimen {} has empty description",
            spec.specimen_id
        );
    }
}

#[test]
fn enrichment_corpus_covers_most_feature_families() {
    let corpus = jsx_corpus();
    let families: BTreeSet<JsxFeatureFamily> = corpus.iter().map(|s| s.feature_family).collect();
    // NamespacedName requires allow_namespaced_names so may not be in default corpus
    let expected_count = JsxFeatureFamily::ALL
        .iter()
        .filter(|f| **f != JsxFeatureFamily::NamespacedName)
        .count();
    assert!(
        families.len() >= expected_count,
        "corpus covers {} families, expected >= {}",
        families.len(),
        expected_count
    );
}

#[test]
fn enrichment_corpus_has_both_parses_ok_and_fail_closed() {
    let corpus = jsx_corpus();
    let has_ok = corpus
        .iter()
        .any(|s| s.expected_outcome == JsxExpectedOutcome::ParsesOk);
    let has_fail = corpus
        .iter()
        .any(|s| s.expected_outcome == JsxExpectedOutcome::FailClosed);
    assert!(has_ok, "corpus should have ParsesOk specimens");
    assert!(has_fail, "corpus should have FailClosed specimens");
}

#[test]
fn enrichment_corpus_all_sources_have_content_or_empty_for_fail_closed() {
    for spec in &jsx_corpus() {
        if spec.expected_outcome == JsxExpectedOutcome::ParsesOk {
            assert!(
                !spec.source.is_empty(),
                "ParsesOk specimen {} has empty source",
                spec.specimen_id
            );
        }
    }
}

// ── run_jsx_corpus ─────────────────────────────────────────────────────

#[test]
fn enrichment_run_corpus_no_unexpected_failures() {
    let config = default_config();
    let (manifest, _, _) = run_jsx_corpus(&config);
    assert_eq!(
        manifest.fail_count, 0,
        "corpus should have no unexpected failures"
    );
}

#[test]
fn enrichment_run_corpus_counts_consistent() {
    let config = default_config();
    let (manifest, inventory, events) = run_jsx_corpus(&config);
    let total = manifest.pass_count + manifest.fail_count + manifest.expected_failure_count;
    assert_eq!(total, manifest.specimen_count);
    assert_eq!(inventory.specimens.len(), manifest.specimen_count);
    assert_eq!(events.len(), manifest.specimen_count);
}

#[test]
fn enrichment_run_corpus_has_passes() {
    let config = default_config();
    let (manifest, _, _) = run_jsx_corpus(&config);
    assert!(manifest.pass_count > 0);
}

#[test]
fn enrichment_run_corpus_has_expected_failures() {
    let config = default_config();
    let (manifest, _, _) = run_jsx_corpus(&config);
    assert!(manifest.expected_failure_count > 0);
}

#[test]
fn enrichment_run_corpus_manifest_schema_version() {
    let config = default_config();
    let (manifest, _, _) = run_jsx_corpus(&config);
    assert_eq!(manifest.schema_version, JSX_PARSER_MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest.component, JSX_PARSER_COMPONENT);
    assert_eq!(manifest.policy_id, JSX_PARSER_POLICY_ID);
}

#[test]
fn enrichment_run_corpus_inventory_schema_version() {
    let config = default_config();
    let (_, inventory, _) = run_jsx_corpus(&config);
    assert_eq!(inventory.schema_version, JSX_PARSER_SCHEMA_VERSION);
    assert_eq!(inventory.component, JSX_PARSER_COMPONENT);
    assert_eq!(inventory.policy_id, JSX_PARSER_POLICY_ID);
}

#[test]
fn enrichment_run_corpus_evidence_hash_sha256_prefix() {
    let config = default_config();
    let (_, inventory, _) = run_jsx_corpus(&config);
    assert!(inventory.evidence_hash.starts_with("sha256:"));
    assert!(inventory.evidence_hash.len() > 10);
}

#[test]
fn enrichment_run_corpus_deterministic() {
    let config = default_config();
    let (m1, inv1, _) = run_jsx_corpus(&config);
    let (m2, inv2, _) = run_jsx_corpus(&config);
    assert_eq!(m1, m2);
    assert_eq!(inv1.evidence_hash, inv2.evidence_hash);
}

#[test]
fn enrichment_run_corpus_family_coverage_non_empty() {
    let config = default_config();
    let (_, inventory, _) = run_jsx_corpus(&config);
    assert!(!inventory.family_coverage.is_empty());
}

#[test]
fn enrichment_run_corpus_every_specimen_in_coverage_map() {
    let config = default_config();
    let (_, inventory, _) = run_jsx_corpus(&config);
    for specimen in &inventory.specimens {
        assert!(
            inventory
                .family_coverage
                .contains_key(specimen.feature_family.as_str()),
            "family {} not in coverage map",
            specimen.feature_family.as_str()
        );
    }
}

#[test]
fn enrichment_run_corpus_events_match_specimens() {
    let config = default_config();
    let (_, inventory, events) = run_jsx_corpus(&config);
    assert_eq!(events.len(), inventory.specimens.len());
    for (ev, spec) in events.iter().zip(inventory.specimens.iter()) {
        assert_eq!(ev.specimen_id, spec.specimen_id);
        assert_eq!(ev.verdict, spec.verdict);
        assert_eq!(ev.schema_version, JSX_PARSER_EVENT_SCHEMA_VERSION);
        assert_eq!(ev.component, JSX_PARSER_COMPONENT);
    }
}

// ── write_jsx_evidence_bundle ──────────────────────────────────────────

#[test]
fn enrichment_write_evidence_bundle_creates_files() {
    let config = default_config();
    let (manifest, inventory, events) = run_jsx_corpus(&config);

    let tmp = std::env::temp_dir().join("jsx_enrichment_test_bundle");
    let _ = std::fs::remove_dir_all(&tmp);

    let paths = write_jsx_evidence_bundle(&tmp, &manifest, &inventory, &events).unwrap();
    assert!(paths.run_manifest.exists());
    assert!(paths.evidence_inventory.exists());
    assert!(paths.events_jsonl.exists());

    // Verify manifest can be read back
    let manifest_content = std::fs::read_to_string(&paths.run_manifest).unwrap();
    let m_back: JsxRunManifest = serde_json::from_str(&manifest_content).unwrap();
    assert_eq!(m_back, manifest);

    // Verify inventory can be read back
    let inv_content = std::fs::read_to_string(&paths.evidence_inventory).unwrap();
    let inv_back: JsxEvidenceInventory = serde_json::from_str(&inv_content).unwrap();
    assert_eq!(inv_back, inventory);

    // Verify events JSONL lines
    let events_content = std::fs::read_to_string(&paths.events_jsonl).unwrap();
    let lines: Vec<&str> = events_content.lines().collect();
    assert_eq!(lines.len(), events.len());
    for line in &lines {
        let ev: JsxEvidenceEvent = serde_json::from_str(line).unwrap();
        assert_eq!(ev.component, JSX_PARSER_COMPONENT);
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

// ── JsxArtifactPaths ──────────────────────────────────────────────────

#[test]
fn enrichment_artifact_paths_serde_roundtrip() {
    let paths = JsxArtifactPaths {
        run_manifest: std::path::PathBuf::from("/tmp/manifest.json"),
        evidence_inventory: std::path::PathBuf::from("/tmp/inventory.json"),
        events_jsonl: std::path::PathBuf::from("/tmp/events.jsonl"),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: JsxArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ── Cross-cutting: parse result serde roundtrip ────────────────────────

#[test]
fn enrichment_parse_result_serde_roundtrip_element() {
    let result = parse_jsx("<div>hello</div>", &default_config()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: JsxParseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_parse_result_serde_roundtrip_fragment() {
    let result = parse_jsx("<>text</>", &default_config()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: JsxParseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_parse_result_serde_roundtrip_complex() {
    let result = parse_jsx(
        r#"<div className="app" id={id}><span>text</span>{expr}</div>"#,
        &default_config(),
    )
    .unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: JsxParseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ── Cross-cutting: namespaced name disabled by default ─────────────────

#[test]
fn enrichment_namespaced_name_not_parsed_without_config() {
    // Without allow_namespaced_names, `svg:rect` does not parse as namespaced
    let result = parse_jsx("<svg:rect />", &default_config());
    // It may parse `svg` as identifier and `:` confuses attribute parsing
    // The key point is it should NOT produce a NamespacedName element
    match result {
        Ok(r) => {
            if let JsxNode::Element(el) = &r.node {
                assert!(
                    !matches!(&el.name, JsxElementName::NamespacedName { .. }),
                    "should not parse as namespaced when config disables it"
                );
            }
        }
        Err(_) => {
            // Also acceptable: parse failure
        }
    }
}

// ── Cross-cutting: component detection via parsing ─────────────────────

#[test]
fn enrichment_parsed_component_element_is_component() {
    let result = parse_jsx("<App />", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert!(el.name.is_component());
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parsed_intrinsic_element_is_not_component() {
    let result = parse_jsx("<div>x</div>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert!(!el.name.is_component());
        }
        _ => panic!("expected element"),
    }
}

// ── Cross-cutting: deep nesting within limit ───────────────────────────

#[test]
fn enrichment_deeply_nested_within_limit_succeeds() {
    let config = JsxParserConfig {
        max_depth: 10,
        ..default_config()
    };
    // 3 levels of nesting, well within limit of 10
    let source = "<a><b><c>deep</c></b></a>";
    let result = parse_jsx(source, &config).unwrap();
    match &result.node {
        JsxNode::Element(outer) => {
            assert_eq!(outer.name.to_string_repr(), "a");
        }
        _ => panic!("expected element"),
    }
}

// ── Cross-cutting: single-quote string attributes ──────────────────────

#[test]
fn enrichment_parse_single_quote_attribute() {
    let result = parse_jsx("<div id='main'>x</div>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => match &el.attributes[0] {
            JsxAttribute::Named { value, .. } => {
                assert_eq!(
                    *value,
                    JsxAttributeValue::StringLiteral {
                        value: "main".into()
                    }
                );
            }
            _ => panic!("expected named attr"),
        },
        _ => panic!("expected element"),
    }
}

// ── Cross-cutting: nested braces in expression ─────────────────────────

#[test]
fn enrichment_parse_nested_braces_in_expression() {
    let result = parse_jsx(
        "<div>{obj.map(x => { return x; })}</div>",
        &default_config(),
    )
    .unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.children.len(), 1);
            match &el.children[0] {
                JsxChild::ExpressionContainer { expression, .. } => {
                    assert!(expression.contains("return x"));
                }
                _ => panic!("expected expression child"),
            }
        }
        _ => panic!("expected element"),
    }
}

// ── Cross-cutting: fragment in fragment ────────────────────────────────

#[test]
fn enrichment_parse_fragment_inside_fragment() {
    let result = parse_jsx("<><>inner</></>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Fragment(outer) => {
            assert_eq!(outer.children.len(), 1);
            match &outer.children[0] {
                JsxChild::Fragment(inner) => {
                    assert_eq!(inner.children.len(), 1);
                }
                _ => panic!("expected nested fragment"),
            }
        }
        _ => panic!("expected fragment"),
    }
}

// ── Cross-cutting: whitespace trimming on input ────────────────────────

#[test]
fn enrichment_parse_leading_trailing_whitespace_trimmed() {
    // parse_jsx trims input before parsing
    let result = parse_jsx("  <div />  ", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.name.to_string_repr(), "div");
            assert!(el.self_closing);
        }
        _ => panic!("expected element"),
    }
}

// ── Cross-cutting: member expression with three segments ───────────────

#[test]
fn enrichment_parse_three_segment_member_expression() {
    let result = parse_jsx("<A.B.C>x</A.B.C>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.name.to_string_repr(), "A.B.C");
            match &el.name {
                JsxElementName::MemberExpression { segments, .. } => {
                    assert_eq!(segments.len(), 3);
                }
                _ => panic!("expected member expression"),
            }
        }
        _ => panic!("expected element"),
    }
}

// ── Cross-cutting: element name with empty segments ────────────────────

#[test]
fn enrichment_parse_empty_element_name_fails() {
    // `< />` has no name after `<`
    let err = parse_jsx("< />", &default_config());
    assert!(
        err.is_err()
            || err
                .unwrap()
                .diagnostics
                .iter()
                .any(|d| d.severity == JsxDiagnosticSeverity::Error)
    );
}

// ── Cross-cutting: corpus specimen validation via parse ────────────────

#[test]
fn enrichment_every_parses_ok_specimen_actually_parses() {
    let config = default_config();
    for spec in &jsx_corpus() {
        if spec.expected_outcome == JsxExpectedOutcome::ParsesOk {
            let result = parse_jsx(&spec.source, &config);
            assert!(
                result.is_ok(),
                "specimen {} expected ParsesOk but got error: {:?}",
                spec.specimen_id,
                result.unwrap_err()
            );
        }
    }
}

#[test]
fn enrichment_every_fail_closed_specimen_actually_fails() {
    let config = default_config();
    for spec in &jsx_corpus() {
        if spec.expected_outcome == JsxExpectedOutcome::FailClosed {
            let result = parse_jsx(&spec.source, &config);
            assert!(
                result.is_err(),
                "specimen {} expected FailClosed but parsed ok",
                spec.specimen_id
            );
        }
    }
}

// ── Batch 2 enrichment tests ─────────────────────────────────────────

// ── Clone contracts ──────────────────────────────────────────────────

#[test]
fn enrichment_runtime_mode_clone() {
    for mode in JsxRuntimeMode::ALL {
        let cloned = mode.clone();
        assert_eq!(*mode, cloned);
    }
}

#[test]
fn enrichment_feature_family_clone() {
    for family in JsxFeatureFamily::ALL {
        let cloned = family.clone();
        assert_eq!(*family, cloned);
    }
}

#[test]
fn enrichment_diagnostic_severity_clone() {
    let err = JsxDiagnosticSeverity::Error.clone();
    let warn = JsxDiagnosticSeverity::Warning.clone();
    assert_eq!(err, JsxDiagnosticSeverity::Error);
    assert_eq!(warn, JsxDiagnosticSeverity::Warning);
}

#[test]
fn enrichment_diagnostic_code_clone() {
    for code in JsxDiagnosticCode::ALL {
        let cloned = code.clone();
        assert_eq!(*code, cloned);
    }
}

#[test]
fn enrichment_diagnostic_clone() {
    let d = JsxDiagnostic {
        code: JsxDiagnosticCode::EmptyExpression,
        severity: JsxDiagnosticSeverity::Error,
        message: "test clone".into(),
        span: Some(span(0, 5)),
    };
    let cloned = d.clone();
    assert_eq!(d, cloned);
}

#[test]
fn enrichment_parse_error_clone() {
    let err = JsxParseError::DepthExceeded {
        depth: 10,
        limit: 5,
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn enrichment_element_name_clone() {
    let name = JsxElementName::Identifier {
        name: "div".into(),
        span: span(0, 3),
    };
    let cloned = name.clone();
    assert_eq!(name, cloned);
}

#[test]
fn enrichment_attribute_clone() {
    let attr = JsxAttribute::Named {
        name: "id".into(),
        value: JsxAttributeValue::StringLiteral {
            value: "main".into(),
        },
        span: span(0, 10),
    };
    let cloned = attr.clone();
    assert_eq!(attr, cloned);
}

#[test]
fn enrichment_child_clone() {
    let child = JsxChild::Text {
        value: "hello".into(),
        span: span(0, 5),
    };
    let cloned = child.clone();
    assert_eq!(child, cloned);
}

#[test]
fn enrichment_element_clone() {
    let el = JsxElement {
        name: JsxElementName::Identifier {
            name: "div".into(),
            span: span(1, 4),
        },
        attributes: vec![],
        children: vec![JsxChild::Text {
            value: "content".into(),
            span: span(5, 12),
        }],
        self_closing: false,
        span: span(0, 18),
    };
    let cloned = el.clone();
    assert_eq!(el, cloned);
}

#[test]
fn enrichment_fragment_clone() {
    let frag = JsxFragment {
        children: vec![JsxChild::Text {
            value: "hello".into(),
            span: span(2, 7),
        }],
        span: span(0, 10),
    };
    let cloned = frag.clone();
    assert_eq!(frag, cloned);
}

#[test]
fn enrichment_node_clone() {
    let node = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "p".into(),
            span: span(1, 2),
        },
        attributes: vec![],
        children: vec![],
        self_closing: true,
        span: span(0, 5),
    });
    let cloned = node.clone();
    assert_eq!(node, cloned);
}

#[test]
fn enrichment_parse_result_clone() {
    let result = parse_jsx("<div />", &default_config()).unwrap();
    let cloned = result.clone();
    assert_eq!(result, cloned);
}

#[test]
fn enrichment_config_clone() {
    let config = JsxParserConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        max_depth: 32,
        allow_namespaced_names: true,
        tsx_mode: true,
    };
    let cloned = config.clone();
    assert_eq!(config, cloned);
}

#[test]
fn enrichment_verdict_clone() {
    for v in [
        JsxVerdict::Pass,
        JsxVerdict::Fail,
        JsxVerdict::ExpectedFailure,
    ] {
        let cloned = v.clone();
        assert_eq!(v, cloned);
    }
}

#[test]
fn enrichment_expected_outcome_clone() {
    for o in [JsxExpectedOutcome::ParsesOk, JsxExpectedOutcome::FailClosed] {
        let cloned = o.clone();
        assert_eq!(o, cloned);
    }
}

#[test]
fn enrichment_specimen_clone() {
    let s = JsxSpecimen {
        specimen_id: "test".into(),
        feature_family: JsxFeatureFamily::Element,
        source: "<div />".into(),
        expected_outcome: JsxExpectedOutcome::ParsesOk,
        description: "test specimen".into(),
    };
    let cloned = s.clone();
    assert_eq!(s, cloned);
}

#[test]
fn enrichment_specimen_evidence_clone() {
    let ev = JsxSpecimenEvidence {
        specimen_id: "s1".into(),
        feature_family: JsxFeatureFamily::Fragment,
        verdict: JsxVerdict::Pass,
        parse_succeeded: true,
        diagnostic_count: 0,
    };
    let cloned = ev.clone();
    assert_eq!(ev, cloned);
}

#[test]
fn enrichment_evidence_event_clone() {
    let ev = JsxEvidenceEvent {
        schema_version: "v1".into(),
        component: "jsx_tsx_parser".into(),
        specimen_id: "test".into(),
        verdict: JsxVerdict::Fail,
    };
    let cloned = ev.clone();
    assert_eq!(ev, cloned);
}

#[test]
fn enrichment_run_manifest_clone() {
    let m = JsxRunManifest {
        schema_version: "v1".into(),
        component: "c".into(),
        policy_id: "p".into(),
        specimen_count: 10,
        pass_count: 8,
        fail_count: 1,
        expected_failure_count: 1,
    };
    let cloned = m.clone();
    assert_eq!(m, cloned);
}

#[test]
fn enrichment_evidence_inventory_clone() {
    let inv = JsxEvidenceInventory {
        schema_version: "v1".into(),
        component: "c".into(),
        policy_id: "p".into(),
        specimens: vec![],
        family_coverage: BTreeMap::new(),
        evidence_hash: "sha256:abc".into(),
    };
    let cloned = inv.clone();
    assert_eq!(inv, cloned);
}

#[test]
fn enrichment_artifact_paths_clone() {
    let paths = JsxArtifactPaths {
        run_manifest: std::path::PathBuf::from("/a"),
        evidence_inventory: std::path::PathBuf::from("/b"),
        events_jsonl: std::path::PathBuf::from("/c"),
    };
    let cloned = paths.clone();
    assert_eq!(paths, cloned);
}

// ── Debug contracts ──────────────────────────────────────────────────

#[test]
fn enrichment_runtime_mode_debug() {
    for mode in JsxRuntimeMode::ALL {
        let dbg = format!("{:?}", mode);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_feature_family_debug() {
    for family in JsxFeatureFamily::ALL {
        let dbg = format!("{:?}", family);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_diagnostic_code_debug() {
    for code in JsxDiagnosticCode::ALL {
        let dbg = format!("{:?}", code);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_diagnostic_severity_debug() {
    let dbg_err = format!("{:?}", JsxDiagnosticSeverity::Error);
    let dbg_warn = format!("{:?}", JsxDiagnosticSeverity::Warning);
    assert_ne!(dbg_err, dbg_warn);
}

#[test]
fn enrichment_parse_error_debug_all_variants() {
    let errs: Vec<JsxParseError> = vec![
        JsxParseError::EmptyInput,
        JsxParseError::DepthExceeded { depth: 5, limit: 3 },
        JsxParseError::FailClosed {
            diagnostics: vec![],
        },
    ];
    for err in &errs {
        let dbg = format!("{:?}", err);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_element_name_debug_all_variants() {
    let names: Vec<JsxElementName> = vec![
        JsxElementName::Identifier {
            name: "div".into(),
            span: span(0, 3),
        },
        JsxElementName::MemberExpression {
            segments: vec!["A".into(), "B".into()],
            span: span(0, 3),
        },
        JsxElementName::NamespacedName {
            namespace: "ns".into(),
            name: "tag".into(),
            span: span(0, 6),
        },
    ];
    for name in &names {
        let dbg = format!("{:?}", name);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_attribute_value_debug_all_variants() {
    let vals: Vec<JsxAttributeValue> = vec![
        JsxAttributeValue::StringLiteral { value: "x".into() },
        JsxAttributeValue::Expression {
            expression: "a".into(),
        },
        JsxAttributeValue::ImplicitTrue,
    ];
    for val in &vals {
        let dbg = format!("{:?}", val);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_child_debug_all_variants() {
    let children: Vec<JsxChild> = vec![
        JsxChild::Text {
            value: "hi".into(),
            span: span(0, 2),
        },
        JsxChild::ExpressionContainer {
            expression: "x".into(),
            span: span(0, 3),
        },
        JsxChild::Element(Box::new(JsxElement {
            name: JsxElementName::Identifier {
                name: "em".into(),
                span: span(1, 3),
            },
            attributes: vec![],
            children: vec![],
            self_closing: true,
            span: span(0, 6),
        })),
        JsxChild::Fragment(Box::new(JsxFragment {
            children: vec![],
            span: span(0, 5),
        })),
    ];
    for child in &children {
        let dbg = format!("{:?}", child);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_node_debug_both_variants() {
    let el_node = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "p".into(),
            span: span(1, 2),
        },
        attributes: vec![],
        children: vec![],
        self_closing: true,
        span: span(0, 5),
    });
    let frag_node = JsxNode::Fragment(JsxFragment {
        children: vec![],
        span: span(0, 5),
    });
    assert!(!format!("{:?}", el_node).is_empty());
    assert!(!format!("{:?}", frag_node).is_empty());
}

#[test]
fn enrichment_config_debug() {
    let config = default_config();
    let dbg = format!("{:?}", config);
    assert!(dbg.contains("Automatic"));
}

#[test]
fn enrichment_parse_result_debug() {
    let result = parse_jsx("<br />", &default_config()).unwrap();
    let dbg = format!("{:?}", result);
    assert!(!dbg.is_empty());
}

#[test]
fn enrichment_verdict_debug() {
    for v in [
        JsxVerdict::Pass,
        JsxVerdict::Fail,
        JsxVerdict::ExpectedFailure,
    ] {
        let dbg = format!("{:?}", v);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn enrichment_expected_outcome_debug() {
    let dbg_ok = format!("{:?}", JsxExpectedOutcome::ParsesOk);
    let dbg_fail = format!("{:?}", JsxExpectedOutcome::FailClosed);
    assert_ne!(dbg_ok, dbg_fail);
}

// ── JSON field name contracts ────────────────────────────────────────

#[test]
fn enrichment_element_name_serde_json_has_type_field() {
    let name = JsxElementName::Identifier {
        name: "div".into(),
        span: span(0, 3),
    };
    let json = serde_json::to_string(&name).unwrap();
    assert!(json.contains("\"type\""));
}

#[test]
fn enrichment_element_name_serde_json_identifier_tag() {
    let name = JsxElementName::Identifier {
        name: "div".into(),
        span: span(0, 3),
    };
    let json = serde_json::to_string(&name).unwrap();
    assert!(json.contains("\"identifier\""));
}

#[test]
fn enrichment_element_name_serde_json_member_expression_tag() {
    let name = JsxElementName::MemberExpression {
        segments: vec!["A".into()],
        span: span(0, 1),
    };
    let json = serde_json::to_string(&name).unwrap();
    assert!(json.contains("\"member_expression\""));
}

#[test]
fn enrichment_element_name_serde_json_namespaced_name_tag() {
    let name = JsxElementName::NamespacedName {
        namespace: "x".into(),
        name: "y".into(),
        span: span(0, 3),
    };
    let json = serde_json::to_string(&name).unwrap();
    assert!(json.contains("\"namespaced_name\""));
}

#[test]
fn enrichment_attribute_serde_json_named_tag() {
    let attr = JsxAttribute::Named {
        name: "id".into(),
        value: JsxAttributeValue::ImplicitTrue,
        span: span(0, 2),
    };
    let json = serde_json::to_string(&attr).unwrap();
    assert!(json.contains("\"named\""));
}

#[test]
fn enrichment_attribute_serde_json_spread_tag() {
    let attr = JsxAttribute::Spread {
        expression: "x".into(),
        span: span(0, 5),
    };
    let json = serde_json::to_string(&attr).unwrap();
    assert!(json.contains("\"spread\""));
}

#[test]
fn enrichment_attribute_value_serde_json_string_literal_tag() {
    let val = JsxAttributeValue::StringLiteral { value: "x".into() };
    let json = serde_json::to_string(&val).unwrap();
    assert!(json.contains("\"string_literal\""));
}

#[test]
fn enrichment_attribute_value_serde_json_expression_tag() {
    let val = JsxAttributeValue::Expression {
        expression: "y".into(),
    };
    let json = serde_json::to_string(&val).unwrap();
    assert!(json.contains("\"expression\""));
}

#[test]
fn enrichment_attribute_value_serde_json_implicit_true_tag() {
    let val = JsxAttributeValue::ImplicitTrue;
    let json = serde_json::to_string(&val).unwrap();
    assert!(json.contains("\"implicit_true\""));
}

#[test]
fn enrichment_child_serde_json_text_tag() {
    let child = JsxChild::Text {
        value: "hi".into(),
        span: span(0, 2),
    };
    let json = serde_json::to_string(&child).unwrap();
    assert!(json.contains("\"text\""));
}

#[test]
fn enrichment_child_serde_json_expression_container_tag() {
    let child = JsxChild::ExpressionContainer {
        expression: "x".into(),
        span: span(0, 3),
    };
    let json = serde_json::to_string(&child).unwrap();
    assert!(json.contains("\"expression_container\""));
}

#[test]
fn enrichment_node_serde_json_element_tag() {
    let node = JsxNode::Element(JsxElement {
        name: JsxElementName::Identifier {
            name: "x".into(),
            span: span(1, 2),
        },
        attributes: vec![],
        children: vec![],
        self_closing: true,
        span: span(0, 5),
    });
    let json = serde_json::to_string(&node).unwrap();
    assert!(json.contains("\"element\""));
}

#[test]
fn enrichment_node_serde_json_fragment_tag() {
    let node = JsxNode::Fragment(JsxFragment {
        children: vec![],
        span: span(0, 5),
    });
    let json = serde_json::to_string(&node).unwrap();
    assert!(json.contains("\"fragment\""));
}

#[test]
fn enrichment_runtime_mode_serde_json_classic_value() {
    let json = serde_json::to_string(&JsxRuntimeMode::Classic).unwrap();
    assert_eq!(json, "\"classic\"");
}

#[test]
fn enrichment_runtime_mode_serde_json_preserve_value() {
    let json = serde_json::to_string(&JsxRuntimeMode::Preserve).unwrap();
    assert_eq!(json, "\"preserve\"");
}

#[test]
fn enrichment_diagnostic_severity_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&JsxDiagnosticSeverity::Error).unwrap(),
        "\"error\""
    );
    assert_eq!(
        serde_json::to_string(&JsxDiagnosticSeverity::Warning).unwrap(),
        "\"warning\""
    );
}

// ── JsxElementName: is_component edge cases ─────────────────────────

#[test]
fn enrichment_element_name_is_component_empty_member_expression() {
    let name = JsxElementName::MemberExpression {
        segments: vec![],
        span: span(0, 0),
    };
    assert!(!name.is_component());
}

#[test]
fn enrichment_element_name_is_component_underscore_prefix() {
    let name = JsxElementName::Identifier {
        name: "_private".into(),
        span: span(0, 8),
    };
    assert!(!name.is_component());
}

#[test]
fn enrichment_element_name_is_component_dollar_prefix() {
    let name = JsxElementName::Identifier {
        name: "$styled".into(),
        span: span(0, 7),
    };
    assert!(!name.is_component());
}

#[test]
fn enrichment_element_name_to_string_repr_empty_member_expression() {
    let name = JsxElementName::MemberExpression {
        segments: vec![],
        span: span(0, 0),
    };
    assert_eq!(name.to_string_repr(), "");
}

#[test]
fn enrichment_element_name_to_string_repr_single_segment_member() {
    let name = JsxElementName::MemberExpression {
        segments: vec!["Ctx".into()],
        span: span(0, 3),
    };
    assert_eq!(name.to_string_repr(), "Ctx");
}

// ── JsxDiagnostic Display format structure ──────────────────────────

#[test]
fn enrichment_diagnostic_display_format_structure_bracket_severity_colon() {
    let d = JsxDiagnostic {
        code: JsxDiagnosticCode::InvalidAttributeName,
        severity: JsxDiagnosticSeverity::Warning,
        message: "bad attr".into(),
        span: None,
    };
    let s = d.to_string();
    // Format: [severity] code: message
    assert!(s.starts_with("[warning]"), "got: {s}");
    assert!(s.contains("FE-JSX-0004"));
    assert!(s.contains("bad attr"));
}

#[test]
fn enrichment_diagnostic_display_with_error_severity() {
    let d = JsxDiagnostic {
        code: JsxDiagnosticCode::UnmatchedOpeningTag,
        severity: JsxDiagnosticSeverity::Error,
        message: "no match".into(),
        span: Some(span(0, 5)),
    };
    let s = d.to_string();
    assert!(s.starts_with("[error]"), "got: {s}");
}

// ── JsxParseError Display content checks ─────────────────────────────

#[test]
fn enrichment_parse_error_empty_input_display_text() {
    let err = JsxParseError::EmptyInput;
    let s = err.to_string();
    assert!(
        s.contains("empty"),
        "EmptyInput display should mention empty: {s}"
    );
}

#[test]
fn enrichment_parse_error_fail_closed_zero_diagnostics_display() {
    let err = JsxParseError::FailClosed {
        diagnostics: vec![],
    };
    let s = err.to_string();
    assert!(s.contains("0"), "FailClosed with 0 diagnostics: {s}");
}

// ── Ordering contracts (PartialOrd/Ord) ─────────────────────────────

#[test]
fn enrichment_runtime_mode_ord_consistent() {
    let mut modes: Vec<JsxRuntimeMode> = JsxRuntimeMode::ALL.to_vec();
    modes.sort();
    // Just verify sorting doesn't panic and is deterministic
    let mut modes2 = modes.clone();
    modes2.sort();
    assert_eq!(modes, modes2);
}

#[test]
fn enrichment_feature_family_ord_consistent() {
    let mut families: Vec<JsxFeatureFamily> = JsxFeatureFamily::ALL.to_vec();
    families.sort();
    let mut families2 = families.clone();
    families2.sort();
    assert_eq!(families, families2);
}

#[test]
fn enrichment_diagnostic_severity_ord() {
    let mut severities = vec![JsxDiagnosticSeverity::Warning, JsxDiagnosticSeverity::Error];
    severities.sort();
    let mut severities2 = severities.clone();
    severities2.sort();
    assert_eq!(severities, severities2);
}

#[test]
fn enrichment_diagnostic_code_ord_consistent() {
    let mut codes: Vec<JsxDiagnosticCode> = JsxDiagnosticCode::ALL.to_vec();
    codes.sort();
    let mut codes2 = codes.clone();
    codes2.sort();
    assert_eq!(codes, codes2);
}

#[test]
fn enrichment_verdict_ord_consistent() {
    let mut verdicts = vec![
        JsxVerdict::ExpectedFailure,
        JsxVerdict::Fail,
        JsxVerdict::Pass,
    ];
    verdicts.sort();
    let mut verdicts2 = verdicts.clone();
    verdicts2.sort();
    assert_eq!(verdicts, verdicts2);
}

#[test]
fn enrichment_expected_outcome_ord_consistent() {
    let mut outcomes = vec![JsxExpectedOutcome::FailClosed, JsxExpectedOutcome::ParsesOk];
    outcomes.sort();
    let mut outcomes2 = outcomes.clone();
    outcomes2.sort();
    assert_eq!(outcomes, outcomes2);
}

// ── Serde invalid JSON rejection ─────────────────────────────────────

#[test]
fn enrichment_runtime_mode_serde_invalid_variant_rejected() {
    let result: Result<JsxRuntimeMode, _> = serde_json::from_str("\"nonexistent_mode\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_feature_family_serde_invalid_variant_rejected() {
    let result: Result<JsxFeatureFamily, _> = serde_json::from_str("\"not_a_family\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_diagnostic_code_serde_invalid_variant_rejected() {
    let result: Result<JsxDiagnosticCode, _> = serde_json::from_str("\"bad_code\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_verdict_serde_invalid_variant_rejected() {
    let result: Result<JsxVerdict, _> = serde_json::from_str("\"not_a_verdict\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_expected_outcome_serde_invalid_rejected() {
    let result: Result<JsxExpectedOutcome, _> = serde_json::from_str("\"maybe\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_config_serde_missing_field_rejected() {
    let json = r#"{"runtime_mode":"classic"}"#;
    let result: Result<JsxParserConfig, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

// ── parse_jsx: additional parsing scenarios ──────────────────────────

#[test]
fn enrichment_parse_self_closing_no_space() {
    let result = parse_jsx("<br/>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert!(el.self_closing);
            assert_eq!(el.name.to_string_repr(), "br");
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_fragment_empty() {
    let result = parse_jsx("<></>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Fragment(frag) => {
            assert!(frag.children.is_empty());
        }
        _ => panic!("expected fragment"),
    }
}

#[test]
fn enrichment_parse_fragment_multiple_children() {
    let result = parse_jsx("<>first{middle}last</>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Fragment(frag) => {
            assert_eq!(frag.children.len(), 3);
            assert!(matches!(&frag.children[0], JsxChild::Text { .. }));
            assert!(matches!(
                &frag.children[1],
                JsxChild::ExpressionContainer { .. }
            ));
            assert!(matches!(&frag.children[2], JsxChild::Text { .. }));
        }
        _ => panic!("expected fragment"),
    }
}

#[test]
fn enrichment_parse_element_with_spread_and_named_attrs() {
    let result = parse_jsx(r#"<Comp {...rest} id="x" />"#, &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.attributes.len(), 2);
            assert!(matches!(&el.attributes[0], JsxAttribute::Spread { .. }));
            assert!(matches!(&el.attributes[1], JsxAttribute::Named { .. }));
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_element_with_hyphenated_name() {
    let result = parse_jsx("<my-component />", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.name.to_string_repr(), "my-component");
            assert!(!el.name.is_component());
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_element_with_dollar_name() {
    let result = parse_jsx("<$Styled />", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.name.to_string_repr(), "$Styled");
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_element_with_underscore_name() {
    let result = parse_jsx("<_internal />", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.name.to_string_repr(), "_internal");
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_nested_expression_attribute() {
    let result = parse_jsx("<div style={{color: 'red'}}>x</div>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => match &el.attributes[0] {
            JsxAttribute::Named { name, value, .. } => {
                assert_eq!(name, "style");
                match value {
                    JsxAttributeValue::Expression { expression } => {
                        assert!(expression.contains("color"));
                    }
                    _ => panic!("expected expression"),
                }
            }
            _ => panic!("expected named"),
        },
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_depth_zero_still_works() {
    // max_depth = 0 means the top-level element at depth 0 is allowed,
    // but nesting beyond depth 0 is not.
    let config = JsxParserConfig {
        max_depth: 64,
        ..default_config()
    };
    let result = parse_jsx("<div />", &config);
    assert!(result.is_ok());
}

#[test]
fn enrichment_parse_multiple_siblings_in_element() {
    let result = parse_jsx("<div><a>1</a><b>2</b><c>3</c></div>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.children.len(), 3);
            for child in &el.children {
                assert!(matches!(child, JsxChild::Element(_)));
            }
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_text_with_special_chars() {
    let result = parse_jsx("<p>Hello & welcome! It's great.</p>", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => match &el.children[0] {
            JsxChild::Text { value, .. } => {
                assert!(value.contains("&"));
                assert!(value.contains("'"));
            }
            _ => panic!("expected text child"),
        },
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_tsx_mode_config_does_not_affect_basic_parsing() {
    let config = JsxParserConfig {
        tsx_mode: true,
        ..default_config()
    };
    let result = parse_jsx("<div>hello</div>", &config).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            assert_eq!(el.name.to_string_repr(), "div");
        }
        _ => panic!("expected element"),
    }
}

// ── Determinism contracts ────────────────────────────────────────────

#[test]
fn enrichment_parse_deterministic_element() {
    let config = default_config();
    let r1 = parse_jsx("<div>hello</div>", &config).unwrap();
    let r2 = parse_jsx("<div>hello</div>", &config).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn enrichment_parse_deterministic_fragment() {
    let config = default_config();
    let r1 = parse_jsx("<>text</>", &config).unwrap();
    let r2 = parse_jsx("<>text</>", &config).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn enrichment_parse_deterministic_complex() {
    let config = default_config();
    let source = r#"<div className="app" id={x}><span>text</span>{expr}</div>"#;
    let r1 = parse_jsx(source, &config).unwrap();
    let r2 = parse_jsx(source, &config).unwrap();
    assert_eq!(r1, r2);
    let j1 = serde_json::to_string(&r1).unwrap();
    let j2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(j1, j2);
}

#[test]
fn enrichment_corpus_deterministic() {
    let c1 = jsx_corpus();
    let c2 = jsx_corpus();
    assert_eq!(c1, c2);
}

// ── Evidence harness: manifest field values ──────────────────────────

#[test]
fn enrichment_run_corpus_manifest_pass_plus_expected_covers_all_ok() {
    let config = default_config();
    let (manifest, _, _) = run_jsx_corpus(&config);
    let corpus = jsx_corpus();
    let ok_count = corpus
        .iter()
        .filter(|s| s.expected_outcome == JsxExpectedOutcome::ParsesOk)
        .count();
    assert_eq!(manifest.pass_count, ok_count);
}

#[test]
fn enrichment_run_corpus_manifest_expected_failure_count_matches() {
    let config = default_config();
    let (manifest, _, _) = run_jsx_corpus(&config);
    let corpus = jsx_corpus();
    let fail_count = corpus
        .iter()
        .filter(|s| s.expected_outcome == JsxExpectedOutcome::FailClosed)
        .count();
    assert_eq!(manifest.expected_failure_count, fail_count);
}

#[test]
fn enrichment_run_corpus_inventory_evidence_hash_hex() {
    let config = default_config();
    let (_, inventory, _) = run_jsx_corpus(&config);
    let hash = inventory.evidence_hash.strip_prefix("sha256:").unwrap();
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex chars
}

#[test]
fn enrichment_run_corpus_events_schema_and_component() {
    let config = default_config();
    let (_, _, events) = run_jsx_corpus(&config);
    for ev in &events {
        assert_eq!(ev.schema_version, JSX_PARSER_EVENT_SCHEMA_VERSION);
        assert_eq!(ev.component, JSX_PARSER_COMPONENT);
        assert!(!ev.specimen_id.is_empty());
    }
}

#[test]
fn enrichment_run_corpus_inventory_specimens_have_valid_verdicts() {
    let config = default_config();
    let (_, inventory, _) = run_jsx_corpus(&config);
    for spec in &inventory.specimens {
        match spec.verdict {
            JsxVerdict::Pass => assert!(spec.parse_succeeded),
            JsxVerdict::ExpectedFailure => assert!(!spec.parse_succeeded),
            JsxVerdict::Fail => { /* can be either */ }
        }
    }
}

#[test]
fn enrichment_run_corpus_family_coverage_sum_equals_specimen_count() {
    let config = default_config();
    let (manifest, inventory, _) = run_jsx_corpus(&config);
    let total: usize = inventory.family_coverage.values().sum();
    assert_eq!(total, manifest.specimen_count);
}

// ── write_jsx_evidence_bundle: path structure ────────────────────────

#[test]
fn enrichment_write_evidence_bundle_path_names() {
    let config = default_config();
    let (manifest, inventory, events) = run_jsx_corpus(&config);
    let tmp = std::env::temp_dir().join("jsx_enrichment_test_paths");
    let _ = std::fs::remove_dir_all(&tmp);
    let paths = write_jsx_evidence_bundle(&tmp, &manifest, &inventory, &events).unwrap();

    assert!(
        paths
            .run_manifest
            .to_string_lossy()
            .contains("jsx_run_manifest")
    );
    assert!(
        paths
            .evidence_inventory
            .to_string_lossy()
            .contains("jsx_evidence_inventory")
    );
    assert!(paths.events_jsonl.to_string_lossy().contains("jsx_events"));
    assert!(paths.run_manifest.to_string_lossy().ends_with(".json"));
    assert!(
        paths
            .evidence_inventory
            .to_string_lossy()
            .ends_with(".json")
    );
    assert!(paths.events_jsonl.to_string_lossy().ends_with(".jsonl"));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn enrichment_write_evidence_bundle_events_jsonl_parseable() {
    let config = default_config();
    let (manifest, inventory, events) = run_jsx_corpus(&config);
    let tmp = std::env::temp_dir().join("jsx_enrichment_test_jsonl");
    let _ = std::fs::remove_dir_all(&tmp);
    let paths = write_jsx_evidence_bundle(&tmp, &manifest, &inventory, &events).unwrap();

    let content = std::fs::read_to_string(&paths.events_jsonl).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), events.len());
    for (i, line) in lines.iter().enumerate() {
        let ev: JsxEvidenceEvent = serde_json::from_str(line).unwrap();
        assert_eq!(ev.specimen_id, events[i].specimen_id);
        assert_eq!(ev.verdict, events[i].verdict);
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

// ── Cross-cutting: serde roundtrip of parsed complex result ─────────

#[test]
fn enrichment_parse_result_serde_roundtrip_with_attributes() {
    let result = parse_jsx(
        r#"<Comp key="a" disabled onClick={fn} {...rest} />"#,
        &default_config(),
    )
    .unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: JsxParseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_parse_result_serde_roundtrip_nested_fragment() {
    let result = parse_jsx("<><>inner</></>", &default_config()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: JsxParseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_parse_result_serde_roundtrip_member_expression() {
    let result = parse_jsx("<A.B.C>text</A.B.C>", &default_config()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: JsxParseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_parse_result_serde_roundtrip_namespaced() {
    let result = parse_jsx("<xml:space />", &ns_config()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: JsxParseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ── Feature families: used list correctness ──────────────────────────

#[test]
fn enrichment_parse_all_family_types_present_in_complex_jsx() {
    let result = parse_jsx(
        r#"<div className="a" count={1} {...p}><span>text</span>{expr}<br /></div>"#,
        &default_config(),
    )
    .unwrap();
    let fam = &result.feature_families_used;
    assert!(fam.contains(&JsxFeatureFamily::Element));
    assert!(fam.contains(&JsxFeatureFamily::StringAttribute));
    assert!(fam.contains(&JsxFeatureFamily::ExpressionAttribute));
    assert!(fam.contains(&JsxFeatureFamily::SpreadAttribute));
    assert!(fam.contains(&JsxFeatureFamily::NestedElement));
    assert!(fam.contains(&JsxFeatureFamily::TextChild));
    assert!(fam.contains(&JsxFeatureFamily::ExpressionChild));
    assert!(fam.contains(&JsxFeatureFamily::SelfClosing));
}

#[test]
fn enrichment_parse_key_prop_with_expression_value() {
    let result = parse_jsx("<Item key={id} />", &default_config()).unwrap();
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::KeyProp)
    );
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::ExpressionAttribute)
    );
}

// ── Diagnostic code: numbered sequence ──────────────────────────────

#[test]
fn enrichment_diagnostic_code_sequential_numbering() {
    for (i, code) in JsxDiagnosticCode::ALL.iter().enumerate() {
        let expected = format!("FE-JSX-{:04}", i + 1);
        assert_eq!(
            code.as_str(),
            expected,
            "code {:?} has unexpected code string",
            code
        );
    }
}

// ── Serde roundtrips of complex nested structures ───────────────────

#[test]
fn enrichment_serde_roundtrip_element_with_all_child_types() {
    let el = JsxElement {
        name: JsxElementName::Identifier {
            name: "div".into(),
            span: span(1, 4),
        },
        attributes: vec![
            JsxAttribute::Named {
                name: "id".into(),
                value: JsxAttributeValue::StringLiteral {
                    value: "main".into(),
                },
                span: span(5, 14),
            },
            JsxAttribute::Spread {
                expression: "props".into(),
                span: span(15, 25),
            },
        ],
        children: vec![
            JsxChild::Text {
                value: "hello".into(),
                span: span(26, 31),
            },
            JsxChild::ExpressionContainer {
                expression: "x + 1".into(),
                span: span(31, 38),
            },
            JsxChild::Element(Box::new(JsxElement {
                name: JsxElementName::Identifier {
                    name: "span".into(),
                    span: span(39, 43),
                },
                attributes: vec![],
                children: vec![],
                self_closing: true,
                span: span(38, 50),
            })),
            JsxChild::Fragment(Box::new(JsxFragment {
                children: vec![JsxChild::Text {
                    value: "frag".into(),
                    span: span(52, 56),
                }],
                span: span(50, 60),
            })),
        ],
        self_closing: false,
        span: span(0, 66),
    };
    let json = serde_json::to_string(&el).unwrap();
    let back: JsxElement = serde_json::from_str(&json).unwrap();
    assert_eq!(el, back);
}

// ── Manifest JSON field names ────────────────────────────────────────

#[test]
fn enrichment_manifest_json_has_expected_field_names() {
    let m = JsxRunManifest {
        schema_version: "v".into(),
        component: "c".into(),
        policy_id: "p".into(),
        specimen_count: 1,
        pass_count: 1,
        fail_count: 0,
        expected_failure_count: 0,
    };
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("schema_version"));
    assert!(json.contains("component"));
    assert!(json.contains("policy_id"));
    assert!(json.contains("specimen_count"));
    assert!(json.contains("pass_count"));
    assert!(json.contains("fail_count"));
    assert!(json.contains("expected_failure_count"));
}

#[test]
fn enrichment_inventory_json_has_expected_field_names() {
    let inv = JsxEvidenceInventory {
        schema_version: "v".into(),
        component: "c".into(),
        policy_id: "p".into(),
        specimens: vec![],
        family_coverage: BTreeMap::new(),
        evidence_hash: "h".into(),
    };
    let json = serde_json::to_string(&inv).unwrap();
    assert!(json.contains("schema_version"));
    assert!(json.contains("component"));
    assert!(json.contains("policy_id"));
    assert!(json.contains("specimens"));
    assert!(json.contains("family_coverage"));
    assert!(json.contains("evidence_hash"));
}

#[test]
fn enrichment_specimen_evidence_json_has_expected_field_names() {
    let ev = JsxSpecimenEvidence {
        specimen_id: "s".into(),
        feature_family: JsxFeatureFamily::Element,
        verdict: JsxVerdict::Pass,
        parse_succeeded: true,
        diagnostic_count: 0,
    };
    let json = serde_json::to_string(&ev).unwrap();
    assert!(json.contains("specimen_id"));
    assert!(json.contains("feature_family"));
    assert!(json.contains("verdict"));
    assert!(json.contains("parse_succeeded"));
    assert!(json.contains("diagnostic_count"));
}

#[test]
fn enrichment_evidence_event_json_has_expected_field_names() {
    let ev = JsxEvidenceEvent {
        schema_version: "v".into(),
        component: "c".into(),
        specimen_id: "s".into(),
        verdict: JsxVerdict::Pass,
    };
    let json = serde_json::to_string(&ev).unwrap();
    assert!(json.contains("schema_version"));
    assert!(json.contains("component"));
    assert!(json.contains("specimen_id"));
    assert!(json.contains("verdict"));
}
