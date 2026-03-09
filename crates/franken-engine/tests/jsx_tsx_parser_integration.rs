//! Integration tests for the JSX/TSX parser module (RGC-206A).

use frankenengine_engine::jsx_tsx_parser::{
    JSX_PARSER_COMPONENT, JSX_PARSER_EVENT_SCHEMA_VERSION, JSX_PARSER_MANIFEST_SCHEMA_VERSION,
    JSX_PARSER_POLICY_ID, JSX_PARSER_SCHEMA_VERSION, JsxAttribute, JsxAttributeValue, JsxChild,
    JsxDiagnosticCode, JsxDiagnosticSeverity, JsxElementName, JsxEvidenceEvent,
    JsxEvidenceInventory, JsxExpectedOutcome, JsxFeatureFamily, JsxNode, JsxParseError,
    JsxParseResult, JsxParserConfig, JsxRunManifest, JsxRuntimeMode, JsxSpecimen,
    JsxSpecimenEvidence, JsxVerdict, jsx_corpus, parse_jsx, run_jsx_corpus,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_non_empty() {
    assert!(!JSX_PARSER_SCHEMA_VERSION.is_empty());
    assert!(!JSX_PARSER_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!JSX_PARSER_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!JSX_PARSER_COMPONENT.is_empty());
    assert!(!JSX_PARSER_POLICY_ID.is_empty());
}

#[test]
fn schema_versions_contain_expected_prefix() {
    assert!(JSX_PARSER_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(JSX_PARSER_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(JSX_PARSER_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn schema_versions_unique() {
    let versions = [
        JSX_PARSER_SCHEMA_VERSION,
        JSX_PARSER_MANIFEST_SCHEMA_VERSION,
        JSX_PARSER_EVENT_SCHEMA_VERSION,
    ];
    for i in 0..versions.len() {
        for j in (i + 1)..versions.len() {
            assert_ne!(versions[i], versions[j], "schema versions must be unique");
        }
    }
}

// ---------------------------------------------------------------------------
// JsxRuntimeMode
// ---------------------------------------------------------------------------

#[test]
fn runtime_mode_all_variants_covered() {
    let all = JsxRuntimeMode::ALL;
    assert!(all.len() >= 3);
    assert!(all.contains(&JsxRuntimeMode::Classic));
    assert!(all.contains(&JsxRuntimeMode::Automatic));
    assert!(all.contains(&JsxRuntimeMode::Preserve));
}

#[test]
fn runtime_mode_as_str_non_empty() {
    for mode in JsxRuntimeMode::ALL {
        assert!(!mode.as_str().is_empty());
    }
}

#[test]
fn runtime_mode_display_matches_as_str() {
    for mode in JsxRuntimeMode::ALL {
        assert_eq!(format!("{mode}"), mode.as_str());
    }
}

#[test]
fn runtime_mode_serde_round_trip() {
    for mode in JsxRuntimeMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let back: JsxRuntimeMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

// ---------------------------------------------------------------------------
// JsxFeatureFamily
// ---------------------------------------------------------------------------

#[test]
fn feature_family_all_has_twelve_variants() {
    assert_eq!(JsxFeatureFamily::ALL.len(), 12);
}

#[test]
fn feature_family_as_str_unique() {
    let strs: Vec<&str> = JsxFeatureFamily::ALL.iter().map(|f| f.as_str()).collect();
    for i in 0..strs.len() {
        for j in (i + 1)..strs.len() {
            assert_ne!(strs[i], strs[j], "feature family as_str must be unique");
        }
    }
}

#[test]
fn feature_family_description_non_empty() {
    for f in JsxFeatureFamily::ALL {
        assert!(!f.description().is_empty(), "{:?} has empty description", f);
    }
}

#[test]
fn feature_family_display_matches_as_str() {
    for f in JsxFeatureFamily::ALL {
        assert_eq!(format!("{f}"), f.as_str());
    }
}

#[test]
fn feature_family_serde_round_trip() {
    for f in JsxFeatureFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: JsxFeatureFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
    }
}

// ---------------------------------------------------------------------------
// JsxDiagnosticCode
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_code_all_non_empty() {
    assert!(!JsxDiagnosticCode::ALL.is_empty());
}

#[test]
fn diagnostic_code_as_str_starts_with_prefix() {
    for code in JsxDiagnosticCode::ALL {
        assert!(
            code.as_str().starts_with("FE-JSX-"),
            "{:?} has unexpected code prefix: {}",
            code,
            code.as_str()
        );
    }
}

#[test]
fn diagnostic_code_message_non_empty() {
    for code in JsxDiagnosticCode::ALL {
        assert!(!code.message().is_empty(), "{:?} has empty message", code);
    }
}

#[test]
fn diagnostic_code_display_matches_as_str() {
    for code in JsxDiagnosticCode::ALL {
        assert_eq!(format!("{code}"), code.as_str());
    }
}

#[test]
fn diagnostic_code_serde_round_trip() {
    for code in JsxDiagnosticCode::ALL {
        let json = serde_json::to_string(code).unwrap();
        let back: JsxDiagnosticCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, back);
    }
}

// ---------------------------------------------------------------------------
// JsxDiagnosticSeverity
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_severity_as_str() {
    assert_eq!(JsxDiagnosticSeverity::Error.as_str(), "error");
    assert_eq!(JsxDiagnosticSeverity::Warning.as_str(), "warning");
}

#[test]
fn diagnostic_severity_display() {
    assert_eq!(format!("{}", JsxDiagnosticSeverity::Error), "error");
    assert_eq!(format!("{}", JsxDiagnosticSeverity::Warning), "warning");
}

// ---------------------------------------------------------------------------
// JsxParserConfig
// ---------------------------------------------------------------------------

#[test]
fn default_config_has_reasonable_values() {
    let config = JsxParserConfig::default();
    assert_eq!(config.runtime_mode, JsxRuntimeMode::Automatic);
    assert!(config.max_depth > 0);
    assert!(config.max_depth <= 128);
}

#[test]
fn config_serde_round_trip() {
    let config = JsxParserConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: JsxParserConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn config_custom_values_round_trip() {
    let config = JsxParserConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        max_depth: 8,
        allow_namespaced_names: true,
        tsx_mode: true,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: JsxParserConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// JsxExpectedOutcome / JsxVerdict
// ---------------------------------------------------------------------------

#[test]
fn expected_outcome_as_str() {
    assert_eq!(JsxExpectedOutcome::ParsesOk.as_str(), "parses_ok");
    assert_eq!(JsxExpectedOutcome::FailClosed.as_str(), "fail_closed");
}

#[test]
fn verdict_as_str() {
    assert_eq!(JsxVerdict::Pass.as_str(), "pass");
    assert_eq!(JsxVerdict::Fail.as_str(), "fail");
    assert_eq!(JsxVerdict::ExpectedFailure.as_str(), "expected_failure");
}

#[test]
fn verdict_serde_round_trip() {
    for v in [
        JsxVerdict::Pass,
        JsxVerdict::Fail,
        JsxVerdict::ExpectedFailure,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: JsxVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// parse_jsx — successful cases
// ---------------------------------------------------------------------------

#[test]
fn parse_simple_element() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div></div>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(!el.self_closing);
        assert!(el.children.is_empty());
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_self_closing_element() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<br/>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(el.self_closing);
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_component_element() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<MyComponent/>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(el.name.is_component());
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_fragment() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<></>", &config).unwrap();
    assert!(matches!(result.node, JsxNode::Fragment(_)));
}

#[test]
fn parse_string_attribute() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div id=\"test\"></div>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert_eq!(el.attributes.len(), 1);
        if let JsxAttribute::Named {
            ref name,
            ref value,
            ..
        } = el.attributes[0]
        {
            assert_eq!(name, "id");
            assert!(matches!(value, JsxAttributeValue::StringLiteral { .. }));
        } else {
            panic!("expected Named attribute");
        }
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_expression_attribute() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div count={42}></div>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(!el.attributes.is_empty());
        if let JsxAttribute::Named { ref value, .. } = el.attributes[0] {
            assert!(matches!(value, JsxAttributeValue::Expression { .. }));
        }
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_spread_attribute() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div {...props}></div>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(!el.attributes.is_empty());
        assert!(matches!(el.attributes[0], JsxAttribute::Spread { .. }));
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_text_child() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<p>hello</p>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(!el.children.is_empty());
        assert!(matches!(el.children[0], JsxChild::Text { .. }));
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_expression_child() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<p>{value}</p>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(!el.children.is_empty());
        assert!(matches!(
            el.children[0],
            JsxChild::ExpressionContainer { .. }
        ));
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_nested_elements() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div><span></span></div>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(!el.children.is_empty());
        assert!(matches!(el.children[0], JsxChild::Element(_)));
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_member_expression_name() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<Foo.Bar/>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(matches!(el.name, JsxElementName::MemberExpression { .. }));
        assert_eq!(el.name.to_string_repr(), "Foo.Bar");
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_namespaced_name() {
    let config = JsxParserConfig {
        allow_namespaced_names: true,
        ..JsxParserConfig::default()
    };
    let result = parse_jsx("<xml:lang/>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(matches!(el.name, JsxElementName::NamespacedName { .. }));
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_boolean_attribute() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<input disabled/>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(!el.attributes.is_empty());
        if let JsxAttribute::Named { ref value, .. } = el.attributes[0] {
            assert!(matches!(value, JsxAttributeValue::ImplicitTrue));
        }
    } else {
        panic!("expected Element node");
    }
}

#[test]
fn parse_key_prop() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<li key=\"item-1\"></li>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(!el.attributes.is_empty());
        if let JsxAttribute::Named { ref name, .. } = el.attributes[0] {
            assert_eq!(name, "key");
        }
    } else {
        panic!("expected Element node");
    }
}

// ---------------------------------------------------------------------------
// parse_jsx — feature families used
// ---------------------------------------------------------------------------

#[test]
fn feature_families_reported_for_element() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div></div>", &config).unwrap();
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::Element)
    );
}

#[test]
fn feature_families_reported_for_self_closing() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<br/>", &config).unwrap();
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::SelfClosing)
    );
}

#[test]
fn feature_families_reported_for_fragment() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<></>", &config).unwrap();
    assert!(
        result
            .feature_families_used
            .contains(&JsxFeatureFamily::Fragment)
    );
}

// ---------------------------------------------------------------------------
// parse_jsx — error cases
// ---------------------------------------------------------------------------

#[test]
fn parse_empty_input_returns_error() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("", &config);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), JsxParseError::EmptyInput));
}

#[test]
fn parse_depth_exceeded() {
    let config = JsxParserConfig {
        max_depth: 2,
        ..JsxParserConfig::default()
    };
    // Build deeply nested JSX
    let mut source = String::new();
    for _ in 0..5 {
        source.push_str("<div>");
    }
    for _ in 0..5 {
        source.push_str("</div>");
    }
    let result = parse_jsx(&source, &config);
    assert!(result.is_err());
}

#[test]
fn parse_error_display_non_empty() {
    let err = JsxParseError::EmptyInput;
    let display = format!("{err}");
    assert!(!display.is_empty());
}

#[test]
fn parse_error_depth_exceeded_display() {
    let err = JsxParseError::DepthExceeded {
        depth: 65,
        limit: 64,
    };
    let display = format!("{err}");
    assert!(!display.is_empty());
}

// ---------------------------------------------------------------------------
// JsxElementName methods
// ---------------------------------------------------------------------------

#[test]
fn element_name_identifier_is_not_component() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div></div>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(!el.name.is_component());
    } else {
        panic!("expected Element");
    }
}

#[test]
fn element_name_component_starts_uppercase() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<App/>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(el.name.is_component());
    } else {
        panic!("expected Element");
    }
}

#[test]
fn element_name_to_string_repr() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div></div>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert_eq!(el.name.to_string_repr(), "div");
    } else {
        panic!("expected Element");
    }
}

// ---------------------------------------------------------------------------
// Span tracking
// ---------------------------------------------------------------------------

#[test]
fn span_offsets_are_within_source() {
    let config = JsxParserConfig::default();
    let source = "<div>hello</div>";
    let result = parse_jsx(source, &config).unwrap();
    let span = result.node.span();
    assert!(span.start_offset <= source.len() as u64);
    assert!(span.end_offset <= source.len() as u64);
    assert!(span.start_offset <= span.end_offset);
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

#[test]
fn corpus_non_empty() {
    let corpus = jsx_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn corpus_covers_most_feature_families() {
    let corpus = jsx_corpus();
    let covered: std::collections::BTreeSet<_> = corpus.iter().map(|s| s.feature_family).collect();
    // The corpus should cover the majority of feature families.
    // NamespacedName may be excluded since it requires special config.
    assert!(
        covered.len() >= 10,
        "corpus covers too few families: {}",
        covered.len()
    );
}

#[test]
fn corpus_specimen_ids_unique() {
    let corpus = jsx_corpus();
    let ids: Vec<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i], ids[j], "duplicate specimen id: {}", ids[i]);
        }
    }
}

#[test]
fn corpus_specimens_have_non_empty_ids_and_descriptions() {
    let corpus = jsx_corpus();
    for s in &corpus {
        assert!(!s.specimen_id.is_empty());
        assert!(!s.description.is_empty());
    }
}

#[test]
fn corpus_specimen_serde_round_trip() {
    let corpus = jsx_corpus();
    for s in &corpus {
        let json = serde_json::to_string(s).unwrap();
        let back: JsxSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// run_jsx_corpus
// ---------------------------------------------------------------------------

#[test]
fn run_corpus_produces_manifest() {
    let config = JsxParserConfig::default();
    let (manifest, _inventory, _events) = run_jsx_corpus(&config);
    assert_eq!(manifest.schema_version, JSX_PARSER_MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest.component, JSX_PARSER_COMPONENT);
    assert_eq!(manifest.policy_id, JSX_PARSER_POLICY_ID);
    assert!(manifest.specimen_count > 0);
}

#[test]
fn run_corpus_manifest_counts_consistent() {
    let config = JsxParserConfig::default();
    let (manifest, _inventory, _events) = run_jsx_corpus(&config);
    assert_eq!(
        manifest.specimen_count,
        manifest.pass_count + manifest.fail_count + manifest.expected_failure_count
    );
}

#[test]
fn run_corpus_produces_inventory() {
    let config = JsxParserConfig::default();
    let (_manifest, inventory, _events) = run_jsx_corpus(&config);
    assert_eq!(inventory.schema_version, JSX_PARSER_SCHEMA_VERSION);
    assert_eq!(inventory.component, JSX_PARSER_COMPONENT);
    assert!(!inventory.specimens.is_empty());
    assert!(!inventory.evidence_hash.is_empty());
}

#[test]
fn run_corpus_inventory_family_coverage() {
    let config = JsxParserConfig::default();
    let (_manifest, inventory, _events) = run_jsx_corpus(&config);
    assert!(!inventory.family_coverage.is_empty());
    for count in inventory.family_coverage.values() {
        assert!(*count > 0);
    }
}

#[test]
fn run_corpus_produces_events() {
    let config = JsxParserConfig::default();
    let (_manifest, _inventory, events) = run_jsx_corpus(&config);
    assert!(!events.is_empty());
    for ev in &events {
        assert_eq!(ev.schema_version, JSX_PARSER_EVENT_SCHEMA_VERSION);
        assert_eq!(ev.component, JSX_PARSER_COMPONENT);
    }
}

#[test]
fn run_corpus_event_count_matches_specimen_count() {
    let config = JsxParserConfig::default();
    let (manifest, _inventory, events) = run_jsx_corpus(&config);
    assert_eq!(events.len(), manifest.specimen_count);
}

#[test]
fn run_corpus_deterministic() {
    let config = JsxParserConfig::default();
    let (m1, inv1, ev1) = run_jsx_corpus(&config);
    let (m2, inv2, ev2) = run_jsx_corpus(&config);
    assert_eq!(m1, m2);
    assert_eq!(inv1, inv2);
    assert_eq!(ev1, ev2);
}

#[test]
fn run_corpus_evidence_hash_deterministic() {
    let config = JsxParserConfig::default();
    let (_, inv1, _) = run_jsx_corpus(&config);
    let (_, inv2, _) = run_jsx_corpus(&config);
    assert_eq!(inv1.evidence_hash, inv2.evidence_hash);
}

// ---------------------------------------------------------------------------
// Serde round-trips for evidence types
// ---------------------------------------------------------------------------

#[test]
fn serde_round_trip_manifest() {
    let config = JsxParserConfig::default();
    let (manifest, _, _) = run_jsx_corpus(&config);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: JsxRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn serde_round_trip_inventory() {
    let config = JsxParserConfig::default();
    let (_, inventory, _) = run_jsx_corpus(&config);
    let json = serde_json::to_string(&inventory).unwrap();
    let back: JsxEvidenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inventory, back);
}

#[test]
fn serde_round_trip_evidence_event() {
    let config = JsxParserConfig::default();
    let (_, _, events) = run_jsx_corpus(&config);
    for ev in &events {
        let json = serde_json::to_string(ev).unwrap();
        let back: JsxEvidenceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*ev, back);
    }
}

#[test]
fn serde_round_trip_specimen_evidence() {
    let evidence = JsxSpecimenEvidence {
        specimen_id: "test-001".into(),
        feature_family: JsxFeatureFamily::Element,
        verdict: JsxVerdict::Pass,
        parse_succeeded: true,
        diagnostic_count: 0,
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let back: JsxSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, back);
}

#[test]
fn serde_round_trip_parse_result() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div></div>", &config).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: JsxParseResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn serde_round_trip_parse_error() {
    let err = JsxParseError::EmptyInput;
    let json = serde_json::to_string(&err).unwrap();
    let back: JsxParseError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ---------------------------------------------------------------------------
// Mixed children
// ---------------------------------------------------------------------------

#[test]
fn parse_mixed_children() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div>text{expr}<span/></div>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert!(el.children.len() >= 2);
    } else {
        panic!("expected Element");
    }
}

// ---------------------------------------------------------------------------
// Multiple attributes
// ---------------------------------------------------------------------------

#[test]
fn parse_multiple_attributes() {
    let config = JsxParserConfig::default();
    let result = parse_jsx("<div id=\"a\" class=\"b\"></div>", &config).unwrap();
    if let JsxNode::Element(ref el) = result.node {
        assert_eq!(el.attributes.len(), 2);
    } else {
        panic!("expected Element");
    }
}

// ---------------------------------------------------------------------------
// Runtime modes affect nothing structural (just metadata)
// ---------------------------------------------------------------------------

#[test]
fn classic_mode_parses_same_structure() {
    let config = JsxParserConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        ..JsxParserConfig::default()
    };
    let result = parse_jsx("<div></div>", &config).unwrap();
    assert!(matches!(result.node, JsxNode::Element(_)));
}

#[test]
fn preserve_mode_parses_same_structure() {
    let config = JsxParserConfig {
        runtime_mode: JsxRuntimeMode::Preserve,
        ..JsxParserConfig::default()
    };
    let result = parse_jsx("<div></div>", &config).unwrap();
    assert!(matches!(result.node, JsxNode::Element(_)));
}
