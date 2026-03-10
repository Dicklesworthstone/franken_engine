//! Integration tests for the `parser` module of `frankenengine_engine`.
//!
//! Covers constants, error codes, diagnostics, taxonomy, parser modes/budgets,
//! grammar completeness, event IR, materialization, and full parse lifecycle.

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
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::deterministic_serde::CanonicalValue;
use frankenengine_engine::parser::*;

// ---------------------------------------------------------------------------
// Section 1: Constants (non-empty, correct prefixes)
// ---------------------------------------------------------------------------

#[test]
fn constants_parse_event_ir_are_non_empty_and_prefixed() {
    assert!(!PARSE_EVENT_IR_CONTRACT_VERSION.is_empty());
    assert!(!PARSE_EVENT_IR_SCHEMA_VERSION.is_empty());
    assert_eq!(PARSE_EVENT_IR_HASH_ALGORITHM, "sha256");
    assert!(PARSE_EVENT_IR_HASH_PREFIX.starts_with("sha256"));
    assert!(!PARSE_EVENT_IR_POLICY_ID.is_empty());
    assert!(!PARSE_EVENT_IR_COMPONENT.is_empty());
    assert!(PARSE_EVENT_IR_TRACE_PREFIX.starts_with("trace-"));
    assert!(PARSE_EVENT_IR_DECISION_PREFIX.starts_with("decision-"));
}

#[test]
fn constants_ast_materializer_are_non_empty() {
    assert!(!PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION.is_empty());
    assert!(!PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION.is_empty());
    assert!(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX.starts_with("ast-node-"));
}

#[test]
fn constants_diagnostic_are_non_empty() {
    assert!(!PARSER_DIAGNOSTIC_TAXONOMY_VERSION.is_empty());
    assert!(!PARSER_DIAGNOSTIC_SCHEMA_VERSION.is_empty());
    assert_eq!(PARSER_DIAGNOSTIC_HASH_ALGORITHM, "sha256");
    assert!(PARSER_DIAGNOSTIC_HASH_PREFIX.starts_with("sha256"));
}

// ---------------------------------------------------------------------------
// Section 2: ParseErrorCode
// ---------------------------------------------------------------------------

#[test]
fn parse_error_code_all_has_seven_elements() {
    assert_eq!(ParseErrorCode::ALL.len(), 7);
}

#[test]
fn parse_error_code_as_str_returns_non_empty_stable_strings() {
    for code in &ParseErrorCode::ALL {
        let s = code.as_str();
        assert!(!s.is_empty(), "as_str for {:?} should be non-empty", code);
    }
    assert_eq!(ParseErrorCode::EmptySource.as_str(), "empty_source");
    assert_eq!(ParseErrorCode::InvalidGoal.as_str(), "invalid_goal");
    assert_eq!(
        ParseErrorCode::UnsupportedSyntax.as_str(),
        "unsupported_syntax"
    );
    assert_eq!(ParseErrorCode::IoReadFailed.as_str(), "io_read_failed");
    assert_eq!(ParseErrorCode::InvalidUtf8.as_str(), "invalid_utf8");
    assert_eq!(ParseErrorCode::SourceTooLarge.as_str(), "source_too_large");
    assert_eq!(ParseErrorCode::BudgetExceeded.as_str(), "budget_exceeded");
}

#[test]
fn parse_error_code_stable_diagnostic_codes_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for code in &ParseErrorCode::ALL {
        let diag = code.stable_diagnostic_code();
        assert!(
            seen.insert(diag.to_string()),
            "duplicate diagnostic code: {}",
            diag
        );
        assert!(
            diag.starts_with("FE-PARSER-DIAG-"),
            "diagnostic code should start with FE-PARSER-DIAG-: {}",
            diag
        );
    }
}

#[test]
fn parse_error_code_diagnostic_category_mapping() {
    assert_eq!(
        ParseErrorCode::EmptySource.diagnostic_category(),
        ParseDiagnosticCategory::Input
    );
    assert_eq!(
        ParseErrorCode::InvalidGoal.diagnostic_category(),
        ParseDiagnosticCategory::Goal
    );
    assert_eq!(
        ParseErrorCode::UnsupportedSyntax.diagnostic_category(),
        ParseDiagnosticCategory::Syntax
    );
    assert_eq!(
        ParseErrorCode::IoReadFailed.diagnostic_category(),
        ParseDiagnosticCategory::System
    );
    assert_eq!(
        ParseErrorCode::InvalidUtf8.diagnostic_category(),
        ParseDiagnosticCategory::Encoding
    );
    assert_eq!(
        ParseErrorCode::SourceTooLarge.diagnostic_category(),
        ParseDiagnosticCategory::Resource
    );
    assert_eq!(
        ParseErrorCode::BudgetExceeded.diagnostic_category(),
        ParseDiagnosticCategory::Resource
    );
}

#[test]
fn parse_error_code_diagnostic_severity_mapping() {
    // Error severity
    assert_eq!(
        ParseErrorCode::EmptySource.diagnostic_severity(),
        ParseDiagnosticSeverity::Error
    );
    assert_eq!(
        ParseErrorCode::InvalidGoal.diagnostic_severity(),
        ParseDiagnosticSeverity::Error
    );
    assert_eq!(
        ParseErrorCode::UnsupportedSyntax.diagnostic_severity(),
        ParseDiagnosticSeverity::Error
    );
    assert_eq!(
        ParseErrorCode::InvalidUtf8.diagnostic_severity(),
        ParseDiagnosticSeverity::Error
    );
    // Fatal severity
    assert_eq!(
        ParseErrorCode::IoReadFailed.diagnostic_severity(),
        ParseDiagnosticSeverity::Fatal
    );
    assert_eq!(
        ParseErrorCode::SourceTooLarge.diagnostic_severity(),
        ParseDiagnosticSeverity::Fatal
    );
    assert_eq!(
        ParseErrorCode::BudgetExceeded.diagnostic_severity(),
        ParseDiagnosticSeverity::Fatal
    );
}

#[test]
fn parse_error_code_message_template_budget_exceeded_variants() {
    let base = ParseErrorCode::BudgetExceeded.diagnostic_message_template(None);
    assert!(base.contains("budget"));

    let bytes = ParseErrorCode::BudgetExceeded
        .diagnostic_message_template(Some(ParseBudgetKind::SourceBytes));
    assert!(bytes.contains("source byte"));

    let tokens = ParseErrorCode::BudgetExceeded
        .diagnostic_message_template(Some(ParseBudgetKind::TokenCount));
    assert!(tokens.contains("token"));

    let depth = ParseErrorCode::BudgetExceeded
        .diagnostic_message_template(Some(ParseBudgetKind::RecursionDepth));
    assert!(depth.contains("recursion"));
}

#[test]
fn parse_error_code_serde_round_trip() {
    for code in &ParseErrorCode::ALL {
        let json = serde_json::to_string(code).unwrap();
        let decoded: ParseErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, decoded);
    }
}

// ---------------------------------------------------------------------------
// Section 3: ParseDiagnosticCategory and ParseDiagnosticSeverity
// ---------------------------------------------------------------------------

#[test]
fn parse_diagnostic_category_as_str() {
    assert_eq!(ParseDiagnosticCategory::Input.as_str(), "input");
    assert_eq!(ParseDiagnosticCategory::Goal.as_str(), "goal");
    assert_eq!(ParseDiagnosticCategory::Syntax.as_str(), "syntax");
    assert_eq!(ParseDiagnosticCategory::Encoding.as_str(), "encoding");
    assert_eq!(ParseDiagnosticCategory::Resource.as_str(), "resource");
    assert_eq!(ParseDiagnosticCategory::System.as_str(), "system");
}

#[test]
fn parse_diagnostic_category_serde_round_trip() {
    let categories = [
        ParseDiagnosticCategory::Input,
        ParseDiagnosticCategory::Goal,
        ParseDiagnosticCategory::Syntax,
        ParseDiagnosticCategory::Encoding,
        ParseDiagnosticCategory::Resource,
        ParseDiagnosticCategory::System,
    ];
    for cat in &categories {
        let json = serde_json::to_string(cat).unwrap();
        let decoded: ParseDiagnosticCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, decoded);
    }
}

#[test]
fn parse_diagnostic_severity_as_str() {
    assert_eq!(ParseDiagnosticSeverity::Error.as_str(), "error");
    assert_eq!(ParseDiagnosticSeverity::Fatal.as_str(), "fatal");
}

#[test]
fn parse_diagnostic_severity_serde_round_trip() {
    for sev in &[
        ParseDiagnosticSeverity::Error,
        ParseDiagnosticSeverity::Fatal,
    ] {
        let json = serde_json::to_string(sev).unwrap();
        let decoded: ParseDiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*sev, decoded);
    }
}

// ---------------------------------------------------------------------------
// Section 4: ParseDiagnosticTaxonomy
// ---------------------------------------------------------------------------

#[test]
fn taxonomy_v1_produces_seven_rules() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    assert_eq!(taxonomy.rules.len(), 7);
    assert_eq!(
        taxonomy.taxonomy_version,
        ParseDiagnosticTaxonomy::taxonomy_version()
    );
}

#[test]
fn taxonomy_v1_rule_for_each_error_code() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    for code in &ParseErrorCode::ALL {
        let rule = taxonomy.rule_for(*code);
        assert!(rule.is_some(), "taxonomy should have a rule for {:?}", code);
        let rule = rule.unwrap();
        assert_eq!(rule.parse_error_code, *code);
        assert_eq!(rule.diagnostic_code, code.stable_diagnostic_code());
        assert_eq!(rule.category, code.diagnostic_category());
        assert_eq!(rule.severity, code.diagnostic_severity());
    }
}

#[test]
fn taxonomy_v1_serde_round_trip() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    let json = serde_json::to_string(&taxonomy).unwrap();
    let decoded: ParseDiagnosticTaxonomy = serde_json::from_str(&json).unwrap();
    assert_eq!(taxonomy, decoded);
}

// ---------------------------------------------------------------------------
// Section 5: ParserMode, ParserBudget, ParserOptions
// ---------------------------------------------------------------------------

#[test]
fn parser_mode_scalar_reference_as_str() {
    assert_eq!(ParserMode::ScalarReference.as_str(), "scalar_reference");
}

#[test]
fn parser_mode_serde_round_trip() {
    let mode = ParserMode::ScalarReference;
    let json = serde_json::to_string(&mode).unwrap();
    let decoded: ParserMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, decoded);
}

#[test]
fn parser_budget_default_values() {
    let budget = ParserBudget::default();
    assert_eq!(budget.max_source_bytes, 1_048_576); // 1 MB
    assert_eq!(budget.max_token_count, 65_536);
    assert_eq!(budget.max_recursion_depth, 256);
}

#[test]
fn parser_budget_serde_round_trip() {
    let budget = ParserBudget::default();
    let json = serde_json::to_string(&budget).unwrap();
    let decoded: ParserBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, decoded);
}

#[test]
fn parser_options_default_values() {
    let opts = ParserOptions::default();
    assert_eq!(opts.mode, ParserMode::ScalarReference);
    assert_eq!(opts.budget, ParserBudget::default());
}

#[test]
fn parser_options_serde_round_trip() {
    let opts = ParserOptions::default();
    let json = serde_json::to_string(&opts).unwrap();
    let decoded: ParserOptions = serde_json::from_str(&json).unwrap();
    assert_eq!(opts, decoded);
}

// ---------------------------------------------------------------------------
// Section 6: ParseBudgetKind
// ---------------------------------------------------------------------------

#[test]
fn parse_budget_kind_as_str() {
    assert_eq!(ParseBudgetKind::SourceBytes.as_str(), "source_bytes");
    assert_eq!(ParseBudgetKind::TokenCount.as_str(), "token_count");
    assert_eq!(ParseBudgetKind::RecursionDepth.as_str(), "recursion_depth");
}

#[test]
fn parse_budget_kind_serde_round_trip() {
    for kind in &[
        ParseBudgetKind::SourceBytes,
        ParseBudgetKind::TokenCount,
        ParseBudgetKind::RecursionDepth,
    ] {
        let json = serde_json::to_string(kind).unwrap();
        let decoded: ParseBudgetKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, decoded);
    }
}

// ---------------------------------------------------------------------------
// Section 7: ParseFailureWitness
// ---------------------------------------------------------------------------

#[test]
fn parse_failure_witness_canonical_value_is_map() {
    let witness = ParseFailureWitness {
        mode: ParserMode::ScalarReference,
        budget_kind: Some(ParseBudgetKind::SourceBytes),
        source_bytes: 2_000_000,
        token_count: 100,
        max_recursion_observed: 5,
        max_source_bytes: 1_048_576,
        max_token_count: 65_536,
        max_recursion_depth: 256,
    };
    let cv = witness.canonical_value();
    match &cv {
        CanonicalValue::Map(map) => {
            assert!(map.contains_key("mode"));
            assert!(map.contains_key("budget_kind"));
            assert!(map.contains_key("source_bytes"));
            assert!(map.contains_key("max_source_bytes"));
        }
        other => panic!("expected Map, got {:?}", other),
    }
}

#[test]
fn parse_failure_witness_canonical_value_null_budget_kind() {
    let witness = ParseFailureWitness {
        mode: ParserMode::ScalarReference,
        budget_kind: None,
        source_bytes: 100,
        token_count: 10,
        max_recursion_observed: 1,
        max_source_bytes: 1_048_576,
        max_token_count: 65_536,
        max_recursion_depth: 256,
    };
    let cv = witness.canonical_value();
    if let CanonicalValue::Map(map) = &cv {
        assert_eq!(map.get("budget_kind"), Some(&CanonicalValue::Null));
    } else {
        panic!("expected Map");
    }
}

// ---------------------------------------------------------------------------
// Section 8: GrammarCoverageStatus serde
// ---------------------------------------------------------------------------

#[test]
fn grammar_coverage_status_serde_round_trip() {
    let statuses = [
        GrammarCoverageStatus::Supported,
        GrammarCoverageStatus::Partial,
        GrammarCoverageStatus::Unsupported,
        GrammarCoverageStatus::NotApplicable,
    ];
    for status in &statuses {
        let json = serde_json::to_string(status).unwrap();
        let decoded: GrammarCoverageStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, decoded);
    }
}

// ---------------------------------------------------------------------------
// Section 9: GrammarCompletenessMatrix
// ---------------------------------------------------------------------------

#[test]
fn grammar_completeness_matrix_has_families() {
    let matrix = GrammarCompletenessMatrix::scalar_reference_es2020();
    assert!(
        !matrix.families.is_empty(),
        "scalar reference matrix should have grammar families"
    );
    assert_eq!(matrix.parser_mode, ParserMode::ScalarReference);
    assert_eq!(
        matrix.schema_version,
        GrammarCompletenessMatrix::SCHEMA_VERSION
    );
}

#[test]
fn grammar_completeness_matrix_summary_values() {
    let matrix = GrammarCompletenessMatrix::scalar_reference_es2020();
    let summary = matrix.summary();
    assert_eq!(summary.family_count, matrix.families.len() as u64);
    assert!(summary.supported_families > 0);
    assert!(summary.completeness_millionths > 0);
    assert!(summary.completeness_millionths <= 1_000_000);
    // supported + partial + unsupported = family_count
    assert_eq!(
        summary.supported_families
            + summary.partially_supported_families
            + summary.unsupported_families,
        summary.family_count
    );
}

#[test]
fn grammar_completeness_matrix_serde_round_trip() {
    let matrix = GrammarCompletenessMatrix::scalar_reference_es2020();
    let json = serde_json::to_string(&matrix).unwrap();
    let decoded: GrammarCompletenessMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(matrix, decoded);
}

// ---------------------------------------------------------------------------
// Section 10: ParseError Display, serde, normalized_diagnostic
// ---------------------------------------------------------------------------

#[test]
fn parse_error_display_without_span() {
    let parser = CanonicalEs2020Parser;
    let err = parser.parse_with_options("", ParseGoal::Script, &ParserOptions::default());
    let error = err.unwrap_err();
    let display = format!("{}", error);
    assert!(
        display.contains("source="),
        "Display without span should contain source="
    );
    assert!(
        !display.contains("line="),
        "should not contain line= if span is None"
    );
}

#[test]
fn parse_error_display_with_span() {
    let parser = CanonicalEs2020Parser;
    let err = parser.parse_with_options(
        "import x from \"m\";\n",
        ParseGoal::Script,
        &ParserOptions::default(),
    );
    let error = err.unwrap_err();
    let display = format!("{}", error);
    assert!(
        display.contains("line="),
        "Display with span should contain line="
    );
    assert!(display.contains("column="));
}

#[test]
fn parse_error_serde_round_trip() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse_with_options("", ParseGoal::Script, &ParserOptions::default())
        .unwrap_err();
    let json = serde_json::to_string(&err).unwrap();
    let decoded: ParseError = serde_json::from_str(&json).unwrap();
    assert_eq!(err.code, decoded.code);
    assert_eq!(err.message, decoded.message);
    assert_eq!(err.source_label, decoded.source_label);
}

#[test]
fn parse_error_normalized_diagnostic_produces_envelope() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse_with_options("", ParseGoal::Script, &ParserOptions::default())
        .unwrap_err();
    let envelope = err.normalized_diagnostic();
    assert_eq!(envelope.parse_error_code, ParseErrorCode::EmptySource);
    assert_eq!(
        envelope.schema_version,
        ParseDiagnosticEnvelope::schema_version()
    );
    assert_eq!(
        envelope.taxonomy_version,
        ParseDiagnosticEnvelope::taxonomy_version()
    );
}

// ---------------------------------------------------------------------------
// Section 11: ParseDiagnosticEnvelope
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_envelope_from_parse_error_canonical_determinism() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse_with_options("", ParseGoal::Script, &ParserOptions::default())
        .unwrap_err();
    let env1 = ParseDiagnosticEnvelope::from_parse_error(&err);
    let env2 = ParseDiagnosticEnvelope::from_parse_error(&err);
    assert_eq!(env1.canonical_bytes(), env2.canonical_bytes());
    assert_eq!(env1.canonical_hash(), env2.canonical_hash());
    assert!(env1.canonical_hash().starts_with("sha256:"));
}

#[test]
fn diagnostic_envelope_serde_round_trip() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse_with_options("", ParseGoal::Script, &ParserOptions::default())
        .unwrap_err();
    let envelope = ParseDiagnosticEnvelope::from_parse_error(&err);
    let json = serde_json::to_string(&envelope).unwrap();
    let decoded: ParseDiagnosticEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope, decoded);
}

#[test]
fn diagnostic_envelope_canonical_value_is_map_with_expected_keys() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse_with_options("", ParseGoal::Script, &ParserOptions::default())
        .unwrap_err();
    let envelope = ParseDiagnosticEnvelope::from_parse_error(&err);
    let cv = envelope.canonical_value();
    if let CanonicalValue::Map(map) = &cv {
        let expected_keys = [
            "schema_version",
            "taxonomy_version",
            "hash_algorithm",
            "hash_prefix",
            "parse_error_code",
            "diagnostic_code",
            "category",
            "severity",
            "message_template",
            "source_label",
            "span",
            "budget_kind",
            "witness",
        ];
        for key in &expected_keys {
            assert!(map.contains_key(*key), "missing key: {}", key);
        }
    } else {
        panic!("expected Map");
    }
}

// ---------------------------------------------------------------------------
// Section 12: ParseEventKind
// ---------------------------------------------------------------------------

#[test]
fn parse_event_kind_as_str() {
    assert_eq!(ParseEventKind::ParseStarted.as_str(), "parse_started");
    assert_eq!(ParseEventKind::StatementParsed.as_str(), "statement_parsed");
    assert_eq!(ParseEventKind::ParseCompleted.as_str(), "parse_completed");
    assert_eq!(ParseEventKind::ParseFailed.as_str(), "parse_failed");
}

#[test]
fn parse_event_kind_canonical_value_is_string() {
    for kind in &[
        ParseEventKind::ParseStarted,
        ParseEventKind::StatementParsed,
        ParseEventKind::ParseCompleted,
        ParseEventKind::ParseFailed,
    ] {
        let cv = kind.canonical_value();
        match &cv {
            CanonicalValue::String(s) => assert_eq!(s, kind.as_str()),
            other => panic!("expected String, got {:?}", other),
        }
    }
}

#[test]
fn parse_event_kind_serde_round_trip() {
    for kind in &[
        ParseEventKind::ParseStarted,
        ParseEventKind::StatementParsed,
        ParseEventKind::ParseCompleted,
        ParseEventKind::ParseFailed,
    ] {
        let json = serde_json::to_string(kind).unwrap();
        let decoded: ParseEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, decoded);
    }
}

// ---------------------------------------------------------------------------
// Section 13: ParseEvent canonical_value
// ---------------------------------------------------------------------------

#[test]
fn parse_event_canonical_value_has_expected_keys() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let (result, event_ir) = parser.parse_with_event_ir("42;\n", ParseGoal::Script, &opts);
    assert!(result.is_ok());
    assert!(!event_ir.events.is_empty());

    let first_event = &event_ir.events[0];
    let cv = first_event.canonical_value();
    if let CanonicalValue::Map(map) = &cv {
        let expected_keys = [
            "sequence",
            "kind",
            "parser_mode",
            "goal",
            "source_label",
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "outcome",
            "error_code",
            "statement_index",
            "span",
            "payload_kind",
            "payload_hash",
        ];
        for key in &expected_keys {
            assert!(map.contains_key(*key), "missing event key: {}", key);
        }
    } else {
        panic!("expected Map for event canonical_value");
    }
}

// ---------------------------------------------------------------------------
// Section 14: ParseEventIr
// ---------------------------------------------------------------------------

#[test]
fn parse_event_ir_from_syntax_tree_deterministic() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let tree = parser
        .parse_with_options("42;\n", ParseGoal::Script, &opts)
        .unwrap();
    let ir1 = ParseEventIr::from_syntax_tree(&tree, "<test>", ParserMode::ScalarReference);
    let ir2 = ParseEventIr::from_syntax_tree(&tree, "<test>", ParserMode::ScalarReference);
    assert_eq!(ir1.canonical_hash(), ir2.canonical_hash());
    assert!(ir1.canonical_hash().starts_with("sha256:"));
    assert_eq!(ir1.contract_version, ParseEventIr::contract_version());
    assert_eq!(ir1.schema_version, ParseEventIr::schema_version());
}

#[test]
fn parse_event_ir_from_parse_source_deterministic() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let source = "42;\n";
    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .unwrap();
    let ir1 = ParseEventIr::from_parse_source(&tree, source, "<test>", ParserMode::ScalarReference);
    let ir2 = ParseEventIr::from_parse_source(&tree, source, "<test>", ParserMode::ScalarReference);
    assert_eq!(ir1.canonical_bytes(), ir2.canonical_bytes());
    assert_eq!(ir1.canonical_hash(), ir2.canonical_hash());
}

#[test]
fn parse_event_ir_from_parse_error_contains_failed_event() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse_with_options("", ParseGoal::Script, &ParserOptions::default())
        .unwrap_err();
    let ir = ParseEventIr::from_parse_error(&err, ParseGoal::Script, ParserMode::ScalarReference);
    assert_eq!(ir.events.len(), 2);
    assert_eq!(ir.events[0].kind, ParseEventKind::ParseStarted);
    assert_eq!(ir.events[1].kind, ParseEventKind::ParseFailed);
    assert_eq!(ir.events[1].error_code, Some(ParseErrorCode::EmptySource));
}

#[test]
fn parse_event_ir_canonical_value_has_expected_keys() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let (_, ir) = parser.parse_with_event_ir("42;\n", ParseGoal::Script, &opts);
    let cv = ir.canonical_value();
    if let CanonicalValue::Map(map) = &cv {
        let expected_keys = [
            "schema_version",
            "contract_version",
            "hash_algorithm",
            "hash_prefix",
            "parser_mode",
            "goal",
            "source_label",
            "event_count",
            "events",
        ];
        for key in &expected_keys {
            assert!(map.contains_key(*key), "missing ir key: {}", key);
        }
    } else {
        panic!("expected Map");
    }
}

#[test]
fn parse_event_ir_serde_round_trip() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let (_, ir) = parser.parse_with_event_ir("42;\n", ParseGoal::Script, &opts);
    let json = serde_json::to_string(&ir).unwrap();
    let decoded: ParseEventIr = serde_json::from_str(&json).unwrap();
    assert_eq!(ir, decoded);
}

// ---------------------------------------------------------------------------
// Section 15: Materialization
// ---------------------------------------------------------------------------

#[test]
fn materialize_from_source_happy_path() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let source = "42;\n";
    let (result, ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &opts);
    assert!(result.is_ok());
    let materialized = ir.materialize_from_source(source, &opts).unwrap();
    assert_eq!(
        materialized.contract_version,
        MaterializedSyntaxTree::contract_version()
    );
    assert_eq!(
        materialized.schema_version,
        MaterializedSyntaxTree::schema_version()
    );
    assert_eq!(materialized.statement_nodes.len(), 1);
    assert!(materialized.root_node_id.starts_with("ast-node-"));
    assert!(
        materialized.statement_nodes[0]
            .node_id
            .starts_with("ast-node-")
    );
}

#[test]
fn materialize_from_syntax_tree_happy_path() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let source = "42;\n";
    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .unwrap();
    let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    let materialized = ir.materialize_from_syntax_tree(&tree).unwrap();
    assert_eq!(materialized.syntax_tree, tree);
    assert_eq!(materialized.statement_nodes.len(), 1);
}

#[test]
fn materialize_from_failed_event_stream_returns_error() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let (err, ir) = parser.parse_with_event_ir("", ParseGoal::Script, &opts);
    assert!(err.is_err());
    let mat_result = ir.materialize_from_source("", &opts);
    assert!(mat_result.is_err());
    let mat_err = mat_result.unwrap_err();
    assert_eq!(
        mat_err.code,
        ParseEventMaterializationErrorCode::ParseFailedEventStream
    );
}

#[test]
fn materialized_syntax_tree_canonical_hash_deterministic() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let source = "42;\n";
    let (_, ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &opts);
    let m1 = ir.materialize_from_source(source, &opts).unwrap();
    let m2 = ir.materialize_from_source(source, &opts).unwrap();
    assert_eq!(m1.canonical_hash(), m2.canonical_hash());
    assert!(m1.canonical_hash().starts_with("sha256:"));
}

#[test]
fn materialized_statement_node_canonical_value_is_map() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let source = "42;\n";
    let (_, ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &opts);
    let mat = ir.materialize_from_source(source, &opts).unwrap();
    let node_cv = mat.statement_nodes[0].canonical_value();
    if let CanonicalValue::Map(map) = &node_cv {
        assert!(map.contains_key("node_id"));
        assert!(map.contains_key("sequence"));
        assert!(map.contains_key("statement_index"));
        assert!(map.contains_key("payload_hash"));
        assert!(map.contains_key("span"));
    } else {
        panic!("expected Map");
    }
}

// ---------------------------------------------------------------------------
// Section 16: CanonicalEs2020Parser
// ---------------------------------------------------------------------------

#[test]
fn canonical_parser_parse_simple_script() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let tree = parser
        .parse_with_options("42;\n", ParseGoal::Script, &opts)
        .unwrap();
    assert_eq!(tree.goal, ParseGoal::Script);
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn canonical_parser_parse_module_import() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let tree = parser
        .parse_with_options("import x from \"m\";\n", ParseGoal::Module, &opts)
        .unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn canonical_parser_parse_module_export_default() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let tree = parser
        .parse_with_options("export default 42;\n", ParseGoal::Module, &opts)
        .unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn canonical_parser_parse_empty_source_error() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let err = parser
        .parse_with_options("", ParseGoal::Script, &opts)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::EmptySource);
}

#[test]
fn canonical_parser_parse_whitespace_only_empty_source_error() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let err = parser
        .parse_with_options("   \n  \t\n", ParseGoal::Script, &opts)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::EmptySource);
}

#[test]
fn canonical_parser_parse_budget_exceeded_source_bytes() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 5,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        },
    };
    let err = parser
        .parse_with_options("123456789;\n", ParseGoal::Script, &opts)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
    assert!(err.witness.is_some());
    let witness = err.witness.as_ref().unwrap();
    assert_eq!(witness.budget_kind, Some(ParseBudgetKind::SourceBytes));
}

#[test]
fn canonical_parser_parse_budget_exceeded_token_count() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1_048_576,
            max_token_count: 1,
            max_recursion_depth: 256,
        },
    };
    // "42;\n" has more than 1 token
    let err = parser
        .parse_with_options("42;\n", ParseGoal::Script, &opts)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
    assert!(err.witness.is_some());
    let witness = err.witness.as_ref().unwrap();
    assert_eq!(witness.budget_kind, Some(ParseBudgetKind::TokenCount));
}

#[test]
fn canonical_parser_parse_with_event_ir_success() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let (result, ir) = parser.parse_with_event_ir("42;\n", ParseGoal::Script, &opts);
    assert!(result.is_ok());
    // Events: ParseStarted, StatementParsed(0), ParseCompleted
    assert_eq!(ir.events.len(), 3);
    assert_eq!(ir.events[0].kind, ParseEventKind::ParseStarted);
    assert_eq!(ir.events[1].kind, ParseEventKind::StatementParsed);
    assert_eq!(ir.events[2].kind, ParseEventKind::ParseCompleted);
}

#[test]
fn canonical_parser_parse_with_event_ir_failure() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let (result, ir) = parser.parse_with_event_ir("", ParseGoal::Script, &opts);
    assert!(result.is_err());
    assert_eq!(ir.events.len(), 2);
    assert_eq!(ir.events[0].kind, ParseEventKind::ParseStarted);
    assert_eq!(ir.events[1].kind, ParseEventKind::ParseFailed);
}

#[test]
fn canonical_parser_parse_with_materialized_ast_success() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let (result, ir, mat) = parser.parse_with_materialized_ast("42;\n", ParseGoal::Script, &opts);
    assert!(result.is_ok());
    assert_eq!(ir.events.len(), 3);
    let mat = mat.unwrap();
    assert_eq!(mat.statement_nodes.len(), 1);
}

#[test]
fn canonical_parser_parse_with_materialized_ast_failure() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let (result, ir, mat) = parser.parse_with_materialized_ast("", ParseGoal::Script, &opts);
    assert!(result.is_err());
    assert_eq!(ir.events.len(), 2);
    assert!(mat.is_err());
}

#[test]
fn canonical_parser_scalar_reference_grammar_matrix() {
    let parser = CanonicalEs2020Parser;
    let matrix = parser.scalar_reference_grammar_matrix();
    assert_eq!(
        matrix.schema_version,
        GrammarCompletenessMatrix::SCHEMA_VERSION
    );
    assert!(!matrix.families.is_empty());
}

// ---------------------------------------------------------------------------
// Section 17: Es2020Parser trait
// ---------------------------------------------------------------------------

#[test]
fn es2020_parser_trait_parse_with_str() {
    let parser = CanonicalEs2020Parser;
    let tree = parser.parse("42;\n", ParseGoal::Script).unwrap();
    assert_eq!(tree.goal, ParseGoal::Script);
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn es2020_parser_trait_parse_with_string() {
    let parser = CanonicalEs2020Parser;
    let input = String::from("42;\n");
    let tree = parser.parse(input, ParseGoal::Script).unwrap();
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn es2020_parser_trait_parse_with_stream_input() {
    let parser = CanonicalEs2020Parser;
    let cursor = std::io::Cursor::new(b"42;\n");
    let stream = StreamInput::new(cursor, "<stream>");
    let tree = parser.parse(stream, ParseGoal::Script).unwrap();
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn es2020_parser_trait_import_in_script_goal_error() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("import x from \"m\";\n", ParseGoal::Script)
        .unwrap_err();
    assert_eq!(err.code, ParseErrorCode::InvalidGoal);
}

// ---------------------------------------------------------------------------
// Section 18: Full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_parse_event_ir_materialize_hash_consistency() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let source = "42;\n";

    // Step 1: Parse
    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .unwrap();
    let tree_hash = tree.canonical_hash();

    // Step 2: Create event IR from parse source
    let ir =
        ParseEventIr::from_parse_source(&tree, source, "<lifecycle>", ParserMode::ScalarReference);
    assert_eq!(ir.goal, ParseGoal::Script);
    assert_eq!(ir.parser_mode, ParserMode::ScalarReference);

    // The last event (ParseCompleted) should have the tree hash as payload_hash
    let completed = ir.events.last().unwrap();
    assert_eq!(completed.kind, ParseEventKind::ParseCompleted);
    assert_eq!(completed.payload_hash.as_deref(), Some(tree_hash.as_str()));

    // Step 3: Materialize from syntax tree
    let materialized = ir.materialize_from_syntax_tree(&tree).unwrap();
    assert_eq!(materialized.syntax_tree, tree);
    assert_eq!(materialized.goal, ParseGoal::Script);

    // Step 4: Hash consistency across repeated materialization
    let ir2 =
        ParseEventIr::from_parse_source(&tree, source, "<lifecycle>", ParserMode::ScalarReference);
    assert_eq!(ir.canonical_hash(), ir2.canonical_hash());

    let mat2 = ir2.materialize_from_syntax_tree(&tree).unwrap();
    assert_eq!(materialized.canonical_hash(), mat2.canonical_hash());
}

#[test]
fn full_lifecycle_module_with_multiple_statements() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let source = "import x from \"m\";\nexport default 42;\n";

    let (result, ir, mat) = parser.parse_with_materialized_ast(source, ParseGoal::Module, &opts);
    let tree = result.unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
    assert_eq!(tree.body.len(), 2);

    // Events: ParseStarted, StatementParsed(0), StatementParsed(1), ParseCompleted
    assert_eq!(ir.events.len(), 4);

    let mat = mat.unwrap();
    assert_eq!(mat.statement_nodes.len(), 2);
    assert_eq!(mat.statement_nodes[0].statement_index, 0);
    assert_eq!(mat.statement_nodes[1].statement_index, 1);

    // Node IDs should be unique
    assert_ne!(
        mat.statement_nodes[0].node_id,
        mat.statement_nodes[1].node_id
    );
    assert_ne!(mat.root_node_id, mat.statement_nodes[0].node_id);
}

#[test]
fn parse_event_materialization_error_display_without_sequence() {
    let err = ParseEventMaterializationError {
        code: ParseEventMaterializationErrorCode::ParseFailedEventStream,
        message: "test error".to_string(),
        sequence: None,
    };
    let display = format!("{}", err);
    assert!(display.contains("parse_failed_event_stream"));
    assert!(display.contains("test error"));
    assert!(!display.contains("sequence="));
}

#[test]
fn parse_event_materialization_error_display_with_sequence() {
    let err = ParseEventMaterializationError {
        code: ParseEventMaterializationErrorCode::InvalidEventSequence,
        message: "bad sequence".to_string(),
        sequence: Some(3),
    };
    let display = format!("{}", err);
    assert!(display.contains("sequence=3"));
}

#[test]
fn parse_event_materialization_error_code_as_str_all_variants() {
    let codes = [
        (
            ParseEventMaterializationErrorCode::UnsupportedContractVersion,
            "unsupported_contract_version",
        ),
        (
            ParseEventMaterializationErrorCode::UnsupportedSchemaVersion,
            "unsupported_schema_version",
        ),
        (
            ParseEventMaterializationErrorCode::ParseFailedEventStream,
            "parse_failed_event_stream",
        ),
        (
            ParseEventMaterializationErrorCode::MissingParseStarted,
            "missing_parse_started",
        ),
        (
            ParseEventMaterializationErrorCode::MissingParseCompleted,
            "missing_parse_completed",
        ),
        (
            ParseEventMaterializationErrorCode::InvalidEventSequence,
            "invalid_event_sequence",
        ),
        (
            ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
            "inconsistent_event_envelope",
        ),
        (
            ParseEventMaterializationErrorCode::GoalMismatch,
            "goal_mismatch",
        ),
        (
            ParseEventMaterializationErrorCode::ModeMismatch,
            "mode_mismatch",
        ),
        (
            ParseEventMaterializationErrorCode::StatementCountMismatch,
            "statement_count_mismatch",
        ),
        (
            ParseEventMaterializationErrorCode::StatementIndexMismatch,
            "statement_index_mismatch",
        ),
        (
            ParseEventMaterializationErrorCode::StatementKindMismatch,
            "statement_kind_mismatch",
        ),
        (
            ParseEventMaterializationErrorCode::StatementHashMismatch,
            "statement_hash_mismatch",
        ),
        (
            ParseEventMaterializationErrorCode::StatementSpanMismatch,
            "statement_span_mismatch",
        ),
        (
            ParseEventMaterializationErrorCode::SourceHashMismatch,
            "source_hash_mismatch",
        ),
        (
            ParseEventMaterializationErrorCode::AstHashMismatch,
            "ast_hash_mismatch",
        ),
        (
            ParseEventMaterializationErrorCode::SourceParseFailed,
            "source_parse_failed",
        ),
    ];
    for (code, expected) in &codes {
        assert_eq!(code.as_str(), *expected, "mismatch for {:?}", code);
    }
}

#[test]
fn parse_event_materialization_error_serde_round_trip() {
    let err = ParseEventMaterializationError {
        code: ParseEventMaterializationErrorCode::GoalMismatch,
        message: "goal does not match".to_string(),
        sequence: Some(0),
    };
    let json = serde_json::to_string(&err).unwrap();
    let decoded: ParseEventMaterializationError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, decoded);
}

#[test]
fn canonical_parser_var_declaration_parsing() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let tree = parser
        .parse_with_options("var x = 42;\n", ParseGoal::Script, &opts)
        .unwrap();
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn canonical_parser_boolean_null_undefined_literals() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let source = "true;\nfalse;\nnull;\nundefined;\n";
    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &opts)
        .unwrap();
    assert_eq!(tree.body.len(), 4);
}

#[test]
fn canonical_parser_string_literals() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let tree = parser
        .parse_with_options("\"hello\";\n", ParseGoal::Script, &opts)
        .unwrap();
    assert_eq!(tree.body.len(), 1);
}

#[test]
fn parse_event_ir_event_sequences_are_gap_free() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let source = "42;\n100;\n200;\n";
    let (result, ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &opts);
    assert!(result.is_ok());
    // 3 statements: ParseStarted(0), Statement(1), Statement(2), Statement(3), ParseCompleted(4)
    assert_eq!(ir.events.len(), 5);
    for (i, event) in ir.events.iter().enumerate() {
        assert_eq!(event.sequence, i as u64, "sequence gap at index {}", i);
    }
}

#[test]
fn materialized_syntax_tree_canonical_value_has_expected_keys() {
    let parser = CanonicalEs2020Parser;
    let opts = ParserOptions::default();
    let source = "42;\n";
    let (_, ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &opts);
    let mat = ir.materialize_from_source(source, &opts).unwrap();
    let cv = mat.canonical_value();
    if let CanonicalValue::Map(map) = &cv {
        let expected = [
            "schema_version",
            "contract_version",
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "parser_mode",
            "goal",
            "source_label",
            "root_node_id",
            "statement_nodes",
            "syntax_tree",
        ];
        for key in &expected {
            assert!(map.contains_key(*key), "missing materialized key: {}", key);
        }
    } else {
        panic!("expected Map");
    }
}
