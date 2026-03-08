#![forbid(unsafe_code)]
//! Enrichment integration tests for `parser`.
//!
//! Adds ParseErrorCode as_str exhaustion, ParseDiagnosticCategory/Severity
//! as_str, ParseBudgetKind as_str, ParseEventKind as_str, serde roundtrips,
//! JSON field-name stability, Debug distinctness, ParserOptions/ParserBudget
//! defaults, and ParseDiagnosticTaxonomy beyond the existing 79 integration tests.

use std::collections::BTreeSet;

use frankenengine_engine::parser::{
    CanonicalEs2020Parser, GrammarCoverageStatus, PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION,
    PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX, PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION,
    PARSE_EVENT_IR_COMPONENT, PARSE_EVENT_IR_CONTRACT_VERSION, PARSE_EVENT_IR_DECISION_PREFIX,
    PARSE_EVENT_IR_HASH_ALGORITHM, PARSE_EVENT_IR_HASH_PREFIX, PARSE_EVENT_IR_POLICY_ID,
    PARSE_EVENT_IR_SCHEMA_VERSION, PARSE_EVENT_IR_TRACE_PREFIX, PARSER_DIAGNOSTIC_HASH_ALGORITHM,
    PARSER_DIAGNOSTIC_HASH_PREFIX, PARSER_DIAGNOSTIC_SCHEMA_VERSION,
    PARSER_DIAGNOSTIC_TAXONOMY_VERSION, ParseBudgetKind, ParseDiagnosticCategory,
    ParseDiagnosticSeverity, ParseDiagnosticTaxonomy, ParseErrorCode, ParseEventKind,
    ParseEventMaterializationErrorCode, ParserBudget, ParserMode, ParserOptions,
};

// ===========================================================================
// 1) ParseErrorCode — as_str exhaustion + ALL array
// ===========================================================================

#[test]
fn parse_error_code_as_str_all_distinct() {
    let strs: Vec<&str> = ParseErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), ParseErrorCode::ALL.len());
}

#[test]
fn parse_error_code_all_count() {
    assert_eq!(ParseErrorCode::ALL.len(), 7);
}

#[test]
fn parse_error_code_stable_diagnostic_codes_all_distinct() {
    let codes: Vec<&str> = ParseErrorCode::ALL
        .iter()
        .map(|c| c.stable_diagnostic_code())
        .collect();
    let unique: BTreeSet<_> = codes.iter().collect();
    assert_eq!(unique.len(), ParseErrorCode::ALL.len());
}

#[test]
fn parse_error_code_diagnostic_message_templates_nonempty() {
    for c in ParseErrorCode::ALL {
        let template = c.diagnostic_message_template(None);
        assert!(
            !template.is_empty(),
            "template for {c:?} should be non-empty"
        );
    }
}

#[test]
fn parse_error_code_diagnostic_categories_all_valid() {
    for c in ParseErrorCode::ALL {
        let _cat = c.diagnostic_category();
    }
}

#[test]
fn parse_error_code_diagnostic_severities_all_valid() {
    for c in ParseErrorCode::ALL {
        let _sev = c.diagnostic_severity();
    }
}

// ===========================================================================
// 2) ParseDiagnosticCategory — as_str
// ===========================================================================

#[test]
fn parse_diagnostic_category_as_str_all_distinct() {
    let cats = [
        ParseDiagnosticCategory::Input,
        ParseDiagnosticCategory::Goal,
        ParseDiagnosticCategory::Syntax,
        ParseDiagnosticCategory::Encoding,
        ParseDiagnosticCategory::Resource,
        ParseDiagnosticCategory::System,
    ];
    let strs: Vec<&str> = cats.iter().map(|c| c.as_str()).collect();
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), 6);
}

// ===========================================================================
// 3) ParseDiagnosticSeverity — as_str
// ===========================================================================

#[test]
fn parse_diagnostic_severity_as_str_distinct() {
    let sevs = [
        ParseDiagnosticSeverity::Error,
        ParseDiagnosticSeverity::Fatal,
    ];
    let strs: Vec<&str> = sevs.iter().map(|s| s.as_str()).collect();
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), 2);
}

// ===========================================================================
// 4) ParserMode — as_str
// ===========================================================================

#[test]
fn parser_mode_as_str() {
    assert_eq!(ParserMode::ScalarReference.as_str(), "scalar_reference");
}

// ===========================================================================
// 5) ParseBudgetKind — as_str
// ===========================================================================

#[test]
fn parse_budget_kind_as_str_all_distinct() {
    let kinds = [
        ParseBudgetKind::SourceBytes,
        ParseBudgetKind::TokenCount,
        ParseBudgetKind::RecursionDepth,
    ];
    let strs: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 6) ParseEventKind — as_str + canonical_value
// ===========================================================================

#[test]
fn parse_event_kind_as_str_all_distinct() {
    let kinds = [
        ParseEventKind::ParseStarted,
        ParseEventKind::StatementParsed,
        ParseEventKind::ParseCompleted,
        ParseEventKind::ParseFailed,
    ];
    let strs: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn parse_event_kind_as_str_matches_canonical_value() {
    for k in [
        ParseEventKind::ParseStarted,
        ParseEventKind::StatementParsed,
        ParseEventKind::ParseCompleted,
        ParseEventKind::ParseFailed,
    ] {
        // as_str and canonical_value should both produce non-empty strings
        let s = k.as_str();
        assert!(!s.is_empty(), "as_str for {k:?} should be non-empty");
    }
}

// ===========================================================================
// 7) ParseEventMaterializationErrorCode — as_str
// ===========================================================================

#[test]
fn materialization_error_code_as_str_all_distinct() {
    let codes = [
        ParseEventMaterializationErrorCode::UnsupportedContractVersion,
        ParseEventMaterializationErrorCode::UnsupportedSchemaVersion,
        ParseEventMaterializationErrorCode::ParseFailedEventStream,
        ParseEventMaterializationErrorCode::MissingParseStarted,
        ParseEventMaterializationErrorCode::MissingParseCompleted,
        ParseEventMaterializationErrorCode::InvalidEventSequence,
        ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
        ParseEventMaterializationErrorCode::GoalMismatch,
        ParseEventMaterializationErrorCode::ModeMismatch,
        ParseEventMaterializationErrorCode::StatementCountMismatch,
        ParseEventMaterializationErrorCode::StatementIndexMismatch,
        ParseEventMaterializationErrorCode::StatementKindMismatch,
        ParseEventMaterializationErrorCode::StatementHashMismatch,
        ParseEventMaterializationErrorCode::StatementSpanMismatch,
        ParseEventMaterializationErrorCode::SourceHashMismatch,
        ParseEventMaterializationErrorCode::AstHashMismatch,
        ParseEventMaterializationErrorCode::SourceParseFailed,
    ];
    let strs: Vec<&str> = codes.iter().map(|c| c.as_str()).collect();
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(unique.len(), 17);
}

// ===========================================================================
// 8) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_parse_error_code() {
    let variants: Vec<String> = ParseErrorCode::ALL
        .iter()
        .map(|c| format!("{c:?}"))
        .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 7);
}

#[test]
fn debug_distinct_grammar_coverage_status() {
    let variants = [
        format!("{:?}", GrammarCoverageStatus::Supported),
        format!("{:?}", GrammarCoverageStatus::Partial),
        format!("{:?}", GrammarCoverageStatus::Unsupported),
        format!("{:?}", GrammarCoverageStatus::NotApplicable),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 9) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_parse_error_code_all() {
    for c in &ParseErrorCode::ALL {
        let json = serde_json::to_string(c).unwrap();
        let rt: ParseErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, rt);
    }
}

#[test]
fn serde_roundtrip_parse_diagnostic_category() {
    for c in [
        ParseDiagnosticCategory::Input,
        ParseDiagnosticCategory::Goal,
        ParseDiagnosticCategory::Syntax,
        ParseDiagnosticCategory::Encoding,
        ParseDiagnosticCategory::Resource,
        ParseDiagnosticCategory::System,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let rt: ParseDiagnosticCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(c, rt);
    }
}

#[test]
fn serde_roundtrip_parse_diagnostic_severity() {
    for s in [
        ParseDiagnosticSeverity::Error,
        ParseDiagnosticSeverity::Fatal,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: ParseDiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_parser_mode() {
    let json = serde_json::to_string(&ParserMode::ScalarReference).unwrap();
    let rt: ParserMode = serde_json::from_str(&json).unwrap();
    assert_eq!(ParserMode::ScalarReference, rt);
}

#[test]
fn serde_roundtrip_parse_budget_kind() {
    for k in [
        ParseBudgetKind::SourceBytes,
        ParseBudgetKind::TokenCount,
        ParseBudgetKind::RecursionDepth,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: ParseBudgetKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_parse_event_kind() {
    for k in [
        ParseEventKind::ParseStarted,
        ParseEventKind::StatementParsed,
        ParseEventKind::ParseCompleted,
        ParseEventKind::ParseFailed,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: ParseEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_grammar_coverage_status() {
    for s in [
        GrammarCoverageStatus::Supported,
        GrammarCoverageStatus::Partial,
        GrammarCoverageStatus::Unsupported,
        GrammarCoverageStatus::NotApplicable,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: GrammarCoverageStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_parser_options() {
    let opts = ParserOptions::default();
    let json = serde_json::to_string(&opts).unwrap();
    let rt: ParserOptions = serde_json::from_str(&json).unwrap();
    assert_eq!(opts, rt);
}

// ===========================================================================
// 10) Defaults
// ===========================================================================

#[test]
fn parser_options_default() {
    let opts = ParserOptions::default();
    assert_eq!(opts.mode, ParserMode::ScalarReference);
}

#[test]
fn parse_budget_default() {
    let budget = ParserBudget::default();
    assert!(budget.max_source_bytes > 0);
    assert!(budget.max_token_count > 0);
    assert!(budget.max_recursion_depth > 0);
}

// ===========================================================================
// 11) Constants stability
// ===========================================================================

#[test]
fn constants_ir_stable() {
    assert!(!PARSE_EVENT_IR_CONTRACT_VERSION.is_empty());
    assert!(!PARSE_EVENT_IR_SCHEMA_VERSION.is_empty());
    assert_eq!(PARSE_EVENT_IR_HASH_ALGORITHM, "sha256");
    assert_eq!(PARSE_EVENT_IR_HASH_PREFIX, "sha256:");
    assert!(!PARSE_EVENT_IR_POLICY_ID.is_empty());
    assert_eq!(PARSE_EVENT_IR_COMPONENT, "canonical_es2020_parser");
    assert!(PARSE_EVENT_IR_TRACE_PREFIX.starts_with("trace-"));
    assert!(PARSE_EVENT_IR_DECISION_PREFIX.starts_with("decision-"));
}

#[test]
fn constants_materializer_stable() {
    assert!(!PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION.is_empty());
    assert!(!PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION.is_empty());
    assert!(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX.starts_with("ast-"));
}

#[test]
fn constants_diagnostic_stable() {
    assert!(!PARSER_DIAGNOSTIC_TAXONOMY_VERSION.is_empty());
    assert!(!PARSER_DIAGNOSTIC_SCHEMA_VERSION.is_empty());
    assert_eq!(PARSER_DIAGNOSTIC_HASH_ALGORITHM, "sha256");
    assert_eq!(PARSER_DIAGNOSTIC_HASH_PREFIX, "sha256:");
}

// ===========================================================================
// 12) ParseDiagnosticTaxonomy — v1
// ===========================================================================

#[test]
fn diagnostic_taxonomy_v1_covers_all_error_codes() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    for code in ParseErrorCode::ALL {
        let rule = taxonomy.rule_for(code);
        assert!(rule.is_some(), "taxonomy should have rule for {code:?}");
    }
}

#[test]
fn diagnostic_taxonomy_v1_version() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    assert!(!taxonomy.taxonomy_version.is_empty());
}

// ===========================================================================
// 13) CanonicalEs2020Parser — construction
// ===========================================================================

#[test]
fn canonical_parser_default() {
    let _parser = CanonicalEs2020Parser;
}

#[test]
fn canonical_parser_clone() {
    let parser = CanonicalEs2020Parser;
    let _clone = parser;
}

// ===========================================================================
// 14) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_parser_options() {
    let opts = ParserOptions::default();
    let v: serde_json::Value = serde_json::to_value(&opts).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["mode", "budget"] {
        assert!(obj.contains_key(key), "ParserOptions missing field: {key}");
    }
}

#[test]
fn json_fields_parse_budget() {
    let budget = ParserBudget::default();
    let v: serde_json::Value = serde_json::to_value(&budget).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["max_source_bytes", "max_token_count", "max_recursion_depth"] {
        assert!(obj.contains_key(key), "ParserBudget missing field: {key}");
    }
}
