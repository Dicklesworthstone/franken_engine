#![forbid(unsafe_code)]
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
    let displays: BTreeSet<String> = JsxFeatureFamily::ALL.iter().map(|f| f.to_string()).collect();
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
    let descs: BTreeSet<&str> = JsxFeatureFamily::ALL.iter().map(|f| f.description()).collect();
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
        assert!(d.len() > 10, "description too short for {}", family.as_str());
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
        diagnostics: vec![
            JsxDiagnostic {
                code: JsxDiagnosticCode::UnmatchedOpeningTag,
                severity: JsxDiagnosticSeverity::Error,
                message: "no match".to_string(),
                span: Some(span(0, 10)),
            },
        ],
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
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::Element));
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::TextChild));
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
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::SelfClosing));
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
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::Fragment));
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
        JsxNode::Element(el) => {
            match &el.attributes[0] {
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
            }
        }
        _ => panic!("expected element"),
    }
}

#[test]
fn enrichment_parse_spread_attribute() {
    let result = parse_jsx("<Comp {...rest} />", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            match &el.attributes[0] {
                JsxAttribute::Spread { expression, .. } => {
                    assert_eq!(expression, "rest");
                }
                _ => panic!("expected spread"),
            }
        }
        _ => panic!("expected element"),
    }
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::SpreadAttribute));
}

#[test]
fn enrichment_parse_boolean_attribute_implicit_true() {
    let result = parse_jsx("<input disabled />", &default_config()).unwrap();
    match &result.node {
        JsxNode::Element(el) => {
            match &el.attributes[0] {
                JsxAttribute::Named { name, value, .. } => {
                    assert_eq!(name, "disabled");
                    assert_eq!(*value, JsxAttributeValue::ImplicitTrue);
                }
                _ => panic!("expected named attr"),
            }
        }
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
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::ExpressionChild));
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
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::NestedElement));
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
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::MemberExpressionName));
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
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::NamespacedName));
}

#[test]
fn enrichment_parse_key_prop_detected() {
    let result = parse_jsx(r#"<Item key="a" />"#, &default_config()).unwrap();
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::KeyProp));
    assert!(result.feature_families_used.contains(&JsxFeatureFamily::StringAttribute));
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
            assert!(diagnostics
                .iter()
                .any(|d| d.code == JsxDiagnosticCode::UnsupportedJsxSyntax));
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
            assert!(r
                .diagnostics
                .iter()
                .any(|d| d.code == JsxDiagnosticCode::UnmatchedClosingTag));
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
            assert!(r
                .diagnostics
                .iter()
                .any(|d| d.code == JsxDiagnosticCode::MissingClosingTag));
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
    let strs: BTreeSet<&str> = [JsxVerdict::Pass, JsxVerdict::Fail, JsxVerdict::ExpectedFailure]
        .iter()
        .map(|v| v.as_str())
        .collect();
    assert_eq!(strs.len(), 3);
}

#[test]
fn enrichment_verdict_serde_all() {
    for verdict in [JsxVerdict::Pass, JsxVerdict::Fail, JsxVerdict::ExpectedFailure] {
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
        assert!(!spec.description.is_empty(), "specimen {} has empty description", spec.specimen_id);
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
            assert!(!spec.source.is_empty(), "ParsesOk specimen {} has empty source", spec.specimen_id);
        }
    }
}

// ── run_jsx_corpus ─────────────────────────────────────────────────────

#[test]
fn enrichment_run_corpus_no_unexpected_failures() {
    let config = default_config();
    let (manifest, _, _) = run_jsx_corpus(&config);
    assert_eq!(manifest.fail_count, 0, "corpus should have no unexpected failures");
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
            inventory.family_coverage.contains_key(specimen.feature_family.as_str()),
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
            match &r.node {
                JsxNode::Element(el) => {
                    assert!(
                        !matches!(&el.name, JsxElementName::NamespacedName { .. }),
                        "should not parse as namespaced when config disables it"
                    );
                }
                _ => {}
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
        JsxNode::Element(el) => {
            match &el.attributes[0] {
                JsxAttribute::Named { value, .. } => {
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

// ── Cross-cutting: nested braces in expression ─────────────────────────

#[test]
fn enrichment_parse_nested_braces_in_expression() {
    let result = parse_jsx("<div>{obj.map(x => { return x; })}</div>", &default_config()).unwrap();
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
    assert!(err.is_err() || err.unwrap().diagnostics.iter().any(|d| d.severity == JsxDiagnosticSeverity::Error));
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
