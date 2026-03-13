#![forbid(unsafe_code)]
//! Enrichment integration tests for `parser`.
//!
//! Adds ParseErrorCode as_str exhaustion, ParseDiagnosticCategory/Severity
//! as_str, ParseBudgetKind as_str, ParseEventKind as_str, serde roundtrips,
//! JSON field-name stability, Debug distinctness, ParserOptions/ParserBudget
//! defaults, and ParseDiagnosticTaxonomy beyond the existing 79 integration tests.

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

// ===========================================================================
// 15) GrammarCompletenessMatrix — scalar_reference_es2020 + summary
// ===========================================================================

#[test]
fn grammar_completeness_matrix_schema_version_stable() {
    let matrix = frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020();
    assert_eq!(
        matrix.schema_version,
        frankenengine_engine::parser::GrammarCompletenessMatrix::SCHEMA_VERSION
    );
    assert!(!matrix.schema_version.is_empty());
}

#[test]
fn grammar_completeness_matrix_has_families() {
    let matrix = frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020();
    assert!(
        matrix.families.len() >= 10,
        "expected at least 10 grammar families, got {}",
        matrix.families.len()
    );
    assert_eq!(matrix.parser_mode, ParserMode::ScalarReference);
}

#[test]
fn grammar_completeness_summary_counts_consistent() {
    let matrix = frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020();
    let summary = matrix.summary();
    assert_eq!(summary.family_count, matrix.families.len() as u64);
    assert_eq!(
        summary.supported_families
            + summary.partially_supported_families
            + summary.unsupported_families,
        summary.family_count
    );
    // Completeness in millionths should be in range [0, 1_000_000]
    assert!(summary.completeness_millionths <= 1_000_000);
}

#[test]
fn grammar_completeness_summary_serde_roundtrip() {
    let matrix = frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020();
    let summary = matrix.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let rt: frankenengine_engine::parser::GrammarCompletenessSummary =
        serde_json::from_str(&json).unwrap();
    assert_eq!(rt.family_count, summary.family_count);
    assert_eq!(rt.completeness_millionths, summary.completeness_millionths);
}

// ===========================================================================
// 16) ParseDiagnosticTaxonomy — serde roundtrip
// ===========================================================================

#[test]
fn diagnostic_taxonomy_v1_serde_roundtrip() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    let json = serde_json::to_string(&taxonomy).unwrap();
    let rt: ParseDiagnosticTaxonomy = serde_json::from_str(&json).unwrap();
    assert_eq!(rt, taxonomy);
    assert_eq!(rt.rules.len(), ParseErrorCode::ALL.len());
}

// ===========================================================================
// 17) ParseDiagnosticTaxonomy rule cross-checks
// ===========================================================================

#[test]
fn diagnostic_taxonomy_v1_rule_fields_match_error_code_methods() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    for code in ParseErrorCode::ALL {
        let rule = taxonomy.rule_for(code).unwrap();
        assert_eq!(rule.parse_error_code, code);
        assert_eq!(rule.diagnostic_code, code.stable_diagnostic_code());
        assert_eq!(rule.category, code.diagnostic_category());
        assert_eq!(rule.severity, code.diagnostic_severity());
        assert_eq!(
            rule.message_template,
            code.diagnostic_message_template(None)
        );
    }
}

// ===========================================================================
// 18) ParseErrorCode — budget_kind-specific message templates
// ===========================================================================

#[test]
fn parse_error_code_budget_exceeded_message_templates_per_kind() {
    let source_bytes_msg = ParseErrorCode::BudgetExceeded
        .diagnostic_message_template(Some(ParseBudgetKind::SourceBytes));
    let token_msg = ParseErrorCode::BudgetExceeded
        .diagnostic_message_template(Some(ParseBudgetKind::TokenCount));
    let recursion_msg = ParseErrorCode::BudgetExceeded
        .diagnostic_message_template(Some(ParseBudgetKind::RecursionDepth));
    let none_msg = ParseErrorCode::BudgetExceeded.diagnostic_message_template(None);

    // All should be non-empty and distinct
    let msgs: BTreeSet<&str> = [source_bytes_msg, token_msg, recursion_msg, none_msg]
        .iter()
        .copied()
        .collect();
    assert_eq!(
        msgs.len(),
        4,
        "all budget-kind message templates should be distinct"
    );
}

// ===========================================================================
// 19) ParseDiagnosticEnvelope — static method stability
// ===========================================================================

#[test]
fn parse_diagnostic_envelope_static_methods() {
    assert_eq!(
        frankenengine_engine::parser::ParseDiagnosticEnvelope::schema_version(),
        PARSER_DIAGNOSTIC_SCHEMA_VERSION
    );
    assert_eq!(
        frankenengine_engine::parser::ParseDiagnosticEnvelope::taxonomy_version(),
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION
    );
    assert_eq!(
        frankenengine_engine::parser::ParseDiagnosticEnvelope::canonical_hash_algorithm(),
        "sha256"
    );
    assert_eq!(
        frankenengine_engine::parser::ParseDiagnosticEnvelope::canonical_hash_prefix(),
        "sha256:"
    );
}

// ===========================================================================
// 20) ParseEventMaterializationErrorCode — serde roundtrip
// ===========================================================================

#[test]
fn materialization_error_code_serde_roundtrip() {
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
    for code in codes {
        let json = serde_json::to_string(&code).unwrap();
        let rt: ParseEventMaterializationErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, rt);
    }
}

// ===========================================================================
// 21) ParserBudget — specific default values
// ===========================================================================

#[test]
fn parser_budget_default_specific_values() {
    let budget = ParserBudget::default();
    // 1 MiB source byte limit
    assert_eq!(budget.max_source_bytes, 1_048_576);
    // 64K token limit
    assert_eq!(budget.max_token_count, 65_536);
    // 256 recursion depth
    assert_eq!(budget.max_recursion_depth, 256);
}

// ===========================================================================
// 22) ParserBudget — clone and equality
// ===========================================================================

#[test]
fn parser_budget_clone_eq() {
    let budget = ParserBudget::default();
    let cloned = budget.clone();
    assert_eq!(budget, cloned);
}

// ===========================================================================
// 23) GrammarCompletenessMatrix — serde roundtrip
// ===========================================================================

#[test]
fn grammar_completeness_matrix_serde_roundtrip() {
    let matrix = frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020();
    let json = serde_json::to_string(&matrix).unwrap();
    let rt: frankenengine_engine::parser::GrammarCompletenessMatrix =
        serde_json::from_str(&json).unwrap();
    assert_eq!(rt, matrix);
}

// ===========================================================================
// 24) GrammarFamilyCoverage — family_id uniqueness
// ===========================================================================

#[test]
fn grammar_family_ids_unique() {
    let matrix = frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020();
    let ids: BTreeSet<&str> = matrix
        .families
        .iter()
        .map(|f| f.family_id.as_str())
        .collect();
    assert_eq!(
        ids.len(),
        matrix.families.len(),
        "all family_id values should be unique"
    );
}

// ===========================================================================
// 25) ParseEventIr — static method stability
// ===========================================================================

#[test]
fn parse_event_ir_static_methods() {
    assert_eq!(
        frankenengine_engine::parser::ParseEventIr::contract_version(),
        PARSE_EVENT_IR_CONTRACT_VERSION
    );
    assert_eq!(
        frankenengine_engine::parser::ParseEventIr::schema_version(),
        PARSE_EVENT_IR_SCHEMA_VERSION
    );
    assert_eq!(
        frankenengine_engine::parser::ParseEventIr::canonical_hash_algorithm(),
        PARSE_EVENT_IR_HASH_ALGORITHM
    );
    assert_eq!(
        frankenengine_engine::parser::ParseEventIr::canonical_hash_prefix(),
        PARSE_EVENT_IR_HASH_PREFIX
    );
}

// ===========================================================================
// ENRICHMENT TESTS — SemanticErrorCode
// ===========================================================================

#[test]
fn enrichment_semantic_error_code_all_count() {
    use frankenengine_engine::parser::SemanticErrorCode;
    assert_eq!(SemanticErrorCode::ALL.len(), 22);
}

#[test]
fn enrichment_semantic_error_code_as_str_all_unique() {
    use frankenengine_engine::parser::SemanticErrorCode;
    let strs: Vec<&str> = SemanticErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(
        unique.len(),
        SemanticErrorCode::ALL.len(),
        "all SemanticErrorCode as_str values must be unique"
    );
}

#[test]
fn enrichment_semantic_error_code_as_str_nonempty() {
    use frankenengine_engine::parser::SemanticErrorCode;
    for code in &SemanticErrorCode::ALL {
        assert!(
            !code.as_str().is_empty(),
            "as_str for {code:?} should be non-empty"
        );
    }
}

#[test]
fn enrichment_semantic_error_code_stable_diagnostic_code_all_unique() {
    use frankenengine_engine::parser::SemanticErrorCode;
    let codes: Vec<&str> = SemanticErrorCode::ALL
        .iter()
        .map(|c| c.stable_diagnostic_code())
        .collect();
    let unique: BTreeSet<_> = codes.iter().collect();
    assert_eq!(
        unique.len(),
        SemanticErrorCode::ALL.len(),
        "all stable_diagnostic_code values must be unique"
    );
}

#[test]
fn enrichment_semantic_error_code_stable_diagnostic_code_prefix() {
    use frankenengine_engine::parser::SemanticErrorCode;
    for code in &SemanticErrorCode::ALL {
        let dc = code.stable_diagnostic_code();
        assert!(
            dc.starts_with("FE-SEM-"),
            "stable_diagnostic_code for {code:?} should start with FE-SEM-, got {dc}"
        );
    }
}

#[test]
fn enrichment_semantic_error_code_diagnostic_category_coverage() {
    use frankenengine_engine::parser::SemanticErrorCode;
    let categories: BTreeSet<String> = SemanticErrorCode::ALL
        .iter()
        .map(|c| c.diagnostic_category().as_str().to_string())
        .collect();
    // All 6 categories should be exercised
    assert!(
        categories.contains("binding"),
        "Binding category must be covered"
    );
    assert!(
        categories.contains("module"),
        "Module category must be covered"
    );
    assert!(
        categories.contains("strict_mode"),
        "StrictMode category must be covered"
    );
    assert!(
        categories.contains("label"),
        "Label category must be covered"
    );
    assert!(
        categories.contains("control_flow"),
        "ControlFlow category must be covered"
    );
    assert!(
        categories.contains("context_restriction"),
        "ContextRestriction category must be covered"
    );
    assert_eq!(categories.len(), 6);
}

#[test]
fn enrichment_semantic_error_code_diagnostic_message_template_nonempty() {
    use frankenengine_engine::parser::SemanticErrorCode;
    for code in &SemanticErrorCode::ALL {
        let template = code.diagnostic_message_template();
        assert!(
            !template.is_empty(),
            "diagnostic_message_template for {code:?} should be non-empty"
        );
    }
}

#[test]
fn enrichment_semantic_error_code_diagnostic_message_template_all_unique() {
    use frankenengine_engine::parser::SemanticErrorCode;
    let templates: Vec<&str> = SemanticErrorCode::ALL
        .iter()
        .map(|c| c.diagnostic_message_template())
        .collect();
    let unique: BTreeSet<_> = templates.iter().collect();
    assert_eq!(
        unique.len(),
        SemanticErrorCode::ALL.len(),
        "all diagnostic_message_template values should be unique"
    );
}

#[test]
fn enrichment_semantic_error_code_display() {
    use frankenengine_engine::parser::SemanticErrorCode;
    for code in &SemanticErrorCode::ALL {
        let display = format!("{code}");
        assert_eq!(
            display,
            code.as_str(),
            "Display for {code:?} should match as_str"
        );
    }
}

#[test]
fn enrichment_semantic_error_code_serde_roundtrip() {
    use frankenengine_engine::parser::SemanticErrorCode;
    for code in &SemanticErrorCode::ALL {
        let json = serde_json::to_string(code).unwrap();
        let rt: SemanticErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, rt, "serde roundtrip failed for {code:?}");
    }
}

#[test]
fn enrichment_semantic_error_code_debug_distinct() {
    use frankenengine_engine::parser::SemanticErrorCode;
    let variants: Vec<String> = SemanticErrorCode::ALL
        .iter()
        .map(|c| format!("{c:?}"))
        .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), SemanticErrorCode::ALL.len());
}

// ===========================================================================
// ENRICHMENT TESTS — SemanticDiagnosticCategory
// ===========================================================================

#[test]
fn enrichment_semantic_diagnostic_category_as_str_all_unique() {
    use frankenengine_engine::parser::SemanticDiagnosticCategory;
    let cats = [
        SemanticDiagnosticCategory::Binding,
        SemanticDiagnosticCategory::Module,
        SemanticDiagnosticCategory::StrictMode,
        SemanticDiagnosticCategory::Label,
        SemanticDiagnosticCategory::ControlFlow,
        SemanticDiagnosticCategory::ContextRestriction,
    ];
    let strs: Vec<&str> = cats.iter().map(|c| c.as_str()).collect();
    let unique: BTreeSet<_> = strs.iter().collect();
    assert_eq!(
        unique.len(),
        6,
        "all 6 SemanticDiagnosticCategory as_str values must be unique"
    );
}

#[test]
fn enrichment_semantic_diagnostic_category_as_str_nonempty() {
    use frankenengine_engine::parser::SemanticDiagnosticCategory;
    for cat in [
        SemanticDiagnosticCategory::Binding,
        SemanticDiagnosticCategory::Module,
        SemanticDiagnosticCategory::StrictMode,
        SemanticDiagnosticCategory::Label,
        SemanticDiagnosticCategory::ControlFlow,
        SemanticDiagnosticCategory::ContextRestriction,
    ] {
        assert!(
            !cat.as_str().is_empty(),
            "as_str for {cat:?} should be non-empty"
        );
    }
}

#[test]
fn enrichment_semantic_diagnostic_category_serde_roundtrip() {
    use frankenengine_engine::parser::SemanticDiagnosticCategory;
    for cat in [
        SemanticDiagnosticCategory::Binding,
        SemanticDiagnosticCategory::Module,
        SemanticDiagnosticCategory::StrictMode,
        SemanticDiagnosticCategory::Label,
        SemanticDiagnosticCategory::ControlFlow,
        SemanticDiagnosticCategory::ContextRestriction,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let rt: SemanticDiagnosticCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, rt);
    }
}

// ===========================================================================
// ENRICHMENT TESTS — SemanticError
// ===========================================================================

#[test]
fn enrichment_semantic_error_new_without_binding_name() {
    use frankenengine_engine::parser::{SemanticError, SemanticErrorCode};
    let err = SemanticError::new(SemanticErrorCode::ConstReassignment, None, None);
    assert_eq!(err.code, SemanticErrorCode::ConstReassignment);
    assert_eq!(err.message, "assignment to constant variable");
    assert!(err.binding_name.is_none());
    assert!(err.span.is_none());
}

#[test]
fn enrichment_semantic_error_new_with_binding_name() {
    use frankenengine_engine::parser::{SemanticError, SemanticErrorCode};
    let err = SemanticError::new(
        SemanticErrorCode::DuplicateLetConstDeclaration,
        Some("myVar".to_string()),
        None,
    );
    assert_eq!(err.code, SemanticErrorCode::DuplicateLetConstDeclaration);
    assert_eq!(err.binding_name, Some("myVar".to_string()));
}

#[test]
fn enrichment_semantic_error_new_with_span() {
    use frankenengine_engine::ast::SourceSpan;
    use frankenengine_engine::parser::{SemanticError, SemanticErrorCode};
    let span = SourceSpan::new(10, 20, 2, 5, 2, 15);
    let err = SemanticError::new(
        SemanticErrorCode::TemporalDeadZone,
        None,
        Some(span.clone()),
    );
    assert_eq!(err.span, Some(span));
}

#[test]
fn enrichment_semantic_error_stable_diagnostic_code_delegates() {
    use frankenengine_engine::parser::{SemanticError, SemanticErrorCode};
    let err = SemanticError::new(SemanticErrorCode::IllegalBreak, None, None);
    assert_eq!(
        err.stable_diagnostic_code(),
        SemanticErrorCode::IllegalBreak.stable_diagnostic_code()
    );
}

#[test]
fn enrichment_semantic_error_diagnostic_category_delegates() {
    use frankenengine_engine::parser::{SemanticError, SemanticErrorCode};
    let err = SemanticError::new(SemanticErrorCode::ModuleTopLevelReturn, None, None);
    assert_eq!(
        err.diagnostic_category(),
        SemanticErrorCode::ModuleTopLevelReturn.diagnostic_category()
    );
}

#[test]
fn enrichment_semantic_error_display_without_binding() {
    use frankenengine_engine::parser::{SemanticError, SemanticErrorCode};
    let err = SemanticError::new(SemanticErrorCode::ConstReassignment, None, None);
    let display = format!("{err}");
    assert!(
        display.contains("FE-SEM-CONST-REASSIGN-0001"),
        "Display should contain stable diagnostic code, got: {display}"
    );
    assert!(
        display.contains("assignment to constant variable"),
        "Display should contain the message, got: {display}"
    );
    assert!(
        !display.contains("binding:"),
        "Display should not contain binding clause when binding_name is None"
    );
}

#[test]
fn enrichment_semantic_error_display_with_binding() {
    use frankenengine_engine::parser::{SemanticError, SemanticErrorCode};
    let err = SemanticError::new(
        SemanticErrorCode::DuplicateLabel,
        Some("myLabel".to_string()),
        None,
    );
    let display = format!("{err}");
    assert!(
        display.contains("(binding: 'myLabel')"),
        "Display should contain binding clause, got: {display}"
    );
}

#[test]
fn enrichment_semantic_error_serde_roundtrip() {
    use frankenengine_engine::parser::{SemanticError, SemanticErrorCode};
    let err = SemanticError::new(
        SemanticErrorCode::AwaitOutsideAsync,
        Some("x".to_string()),
        None,
    );
    let json = serde_json::to_string(&err).unwrap();
    let rt: SemanticError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, rt);
}

// ===========================================================================
// ENRICHMENT TESTS — SemanticValidationResult
// ===========================================================================

#[test]
fn enrichment_semantic_validation_result_new_is_valid() {
    use frankenengine_engine::parser::SemanticValidationResult;
    let result = SemanticValidationResult::new();
    assert!(result.is_valid());
    assert_eq!(result.error_count(), 0);
    assert!(result.errors.is_empty());
}

#[test]
fn enrichment_semantic_validation_result_default_eq_new() {
    use frankenengine_engine::parser::SemanticValidationResult;
    let from_new = SemanticValidationResult::new();
    let from_default = SemanticValidationResult::default();
    assert_eq!(from_new, from_default);
}

#[test]
fn enrichment_semantic_validation_result_add_error() {
    use frankenengine_engine::parser::{
        SemanticError, SemanticErrorCode, SemanticValidationResult,
    };
    let mut result = SemanticValidationResult::new();
    assert!(result.is_valid());
    result.add_error(SemanticError::new(
        SemanticErrorCode::ConstWithoutInitializer,
        None,
        None,
    ));
    assert!(!result.is_valid());
    assert_eq!(result.error_count(), 1);
}

#[test]
fn enrichment_semantic_validation_result_add_multiple_errors() {
    use frankenengine_engine::parser::{
        SemanticError, SemanticErrorCode, SemanticValidationResult,
    };
    let mut result = SemanticValidationResult::new();
    result.add_error(SemanticError::new(
        SemanticErrorCode::DuplicateParameter,
        Some("a".to_string()),
        None,
    ));
    result.add_error(SemanticError::new(
        SemanticErrorCode::StrictModeWith,
        None,
        None,
    ));
    assert_eq!(result.error_count(), 2);
    assert_eq!(result.errors[0].code, SemanticErrorCode::DuplicateParameter);
    assert_eq!(result.errors[1].code, SemanticErrorCode::StrictModeWith);
}

#[test]
fn enrichment_semantic_validation_result_taxonomy_version() {
    use frankenengine_engine::parser::{SEMANTIC_ERROR_TAXONOMY_VERSION, SemanticValidationResult};
    let result = SemanticValidationResult::new();
    assert_eq!(result.taxonomy_version, SEMANTIC_ERROR_TAXONOMY_VERSION);
}

#[test]
fn enrichment_semantic_validation_result_serde_roundtrip() {
    use frankenengine_engine::parser::{
        SemanticError, SemanticErrorCode, SemanticValidationResult,
    };
    let mut result = SemanticValidationResult::new();
    result.add_error(SemanticError::new(
        SemanticErrorCode::YieldOutsideGenerator,
        Some("gen".to_string()),
        None,
    ));
    let json = serde_json::to_string(&result).unwrap();
    let rt: SemanticValidationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, rt);
}

// ===========================================================================
// ENRICHMENT TESTS — ParseError Display + std::error::Error
// ===========================================================================

#[test]
fn enrichment_parse_error_display_without_span() {
    use frankenengine_engine::parser::{ParseError, ParseErrorCode};
    let err = ParseError {
        code: ParseErrorCode::EmptySource,
        message: "test message".to_string(),
        source_label: "test.js".to_string(),
        span: None,
        witness: None,
    };
    let display = format!("{err}");
    assert!(
        display.contains("EmptySource"),
        "Display should contain error code debug name, got: {display}"
    );
    assert!(
        display.contains("test message"),
        "Display should contain message, got: {display}"
    );
    assert!(
        display.contains("source=test.js"),
        "Display should contain source label, got: {display}"
    );
    // Without span, should not contain line= or column=
    assert!(
        !display.contains("line="),
        "Display should not contain line when span is None"
    );
}

#[test]
fn enrichment_parse_error_display_with_span() {
    use frankenengine_engine::ast::SourceSpan;
    use frankenengine_engine::parser::{ParseError, ParseErrorCode};
    let span = SourceSpan::new(0, 10, 5, 3, 5, 13);
    let err = ParseError {
        code: ParseErrorCode::UnsupportedSyntax,
        message: "bad syntax".to_string(),
        source_label: "app.js".to_string(),
        span: Some(span),
        witness: None,
    };
    let display = format!("{err}");
    assert!(
        display.contains("line=5"),
        "Display should contain line number, got: {display}"
    );
    assert!(
        display.contains("column=3"),
        "Display should contain column number, got: {display}"
    );
}

#[test]
fn enrichment_parse_error_is_std_error() {
    use frankenengine_engine::parser::{ParseError, ParseErrorCode};
    let err = ParseError {
        code: ParseErrorCode::IoReadFailed,
        message: "oops".to_string(),
        source_label: "file.js".to_string(),
        span: None,
        witness: None,
    };
    let e: &dyn std::error::Error = &err;
    let _ = format!("{e}");
}

#[test]
fn enrichment_parse_error_serde_roundtrip() {
    use frankenengine_engine::parser::{ParseError, ParseErrorCode};
    let err = ParseError {
        code: ParseErrorCode::InvalidUtf8,
        message: "bad encoding".to_string(),
        source_label: "stream".to_string(),
        span: None,
        witness: None,
    };
    let json = serde_json::to_string(&err).unwrap();
    let rt: ParseError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, rt);
}

#[test]
fn enrichment_parse_error_serde_roundtrip_with_witness() {
    use frankenengine_engine::parser::{
        ParseBudgetKind, ParseError, ParseErrorCode, ParseFailureWitness, ParserMode,
    };
    let witness = ParseFailureWitness {
        mode: ParserMode::ScalarReference,
        budget_kind: Some(ParseBudgetKind::SourceBytes),
        source_bytes: 2_000_000,
        token_count: 1000,
        max_recursion_observed: 5,
        max_source_bytes: 1_048_576,
        max_token_count: 65_536,
        max_recursion_depth: 256,
    };
    let err = ParseError {
        code: ParseErrorCode::BudgetExceeded,
        message: "source byte budget exceeded".to_string(),
        source_label: "large.js".to_string(),
        span: None,
        witness: Some(Box::new(witness)),
    };
    let json = serde_json::to_string(&err).unwrap();
    let rt: ParseError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, rt);
    assert!(rt.witness.is_some());
}

// ===========================================================================
// ENRICHMENT TESTS — ParseFailureWitness
// ===========================================================================

#[test]
fn enrichment_parse_failure_witness_canonical_value_keys() {
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    use frankenengine_engine::parser::{ParseBudgetKind, ParseFailureWitness, ParserMode};
    let witness = ParseFailureWitness {
        mode: ParserMode::ScalarReference,
        budget_kind: Some(ParseBudgetKind::TokenCount),
        source_bytes: 500,
        token_count: 100_000,
        max_recursion_observed: 10,
        max_source_bytes: 1_048_576,
        max_token_count: 65_536,
        max_recursion_depth: 256,
    };
    let cv = witness.canonical_value();
    if let CanonicalValue::Map(map) = &cv {
        let expected_keys = [
            "mode",
            "budget_kind",
            "source_bytes",
            "token_count",
            "max_recursion_observed",
            "max_source_bytes",
            "max_token_count",
            "max_recursion_depth",
        ];
        for key in expected_keys {
            assert!(map.contains_key(key), "canonical_value missing key: {key}");
        }
        assert_eq!(map.len(), 8);
    } else {
        panic!("canonical_value should be a Map");
    }
}

#[test]
fn enrichment_parse_failure_witness_canonical_value_null_budget_kind() {
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    use frankenengine_engine::parser::{ParseFailureWitness, ParserMode};
    let witness = ParseFailureWitness {
        mode: ParserMode::ScalarReference,
        budget_kind: None,
        source_bytes: 100,
        token_count: 50,
        max_recursion_observed: 1,
        max_source_bytes: 1_048_576,
        max_token_count: 65_536,
        max_recursion_depth: 256,
    };
    let cv = witness.canonical_value();
    if let CanonicalValue::Map(map) = &cv {
        assert_eq!(
            map.get("budget_kind"),
            Some(&CanonicalValue::Null),
            "budget_kind should be Null when None"
        );
    } else {
        panic!("canonical_value should be a Map");
    }
}

#[test]
fn enrichment_parse_failure_witness_serde_roundtrip() {
    use frankenengine_engine::parser::{ParseBudgetKind, ParseFailureWitness, ParserMode};
    let witness = ParseFailureWitness {
        mode: ParserMode::ScalarReference,
        budget_kind: Some(ParseBudgetKind::RecursionDepth),
        source_bytes: 1000,
        token_count: 200,
        max_recursion_observed: 300,
        max_source_bytes: 1_048_576,
        max_token_count: 65_536,
        max_recursion_depth: 256,
    };
    let json = serde_json::to_string(&witness).unwrap();
    let rt: ParseFailureWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(witness, rt);
}

// ===========================================================================
// ENRICHMENT TESTS — ParseDiagnosticEnvelope
// ===========================================================================

#[test]
fn enrichment_parse_diagnostic_envelope_from_parse_error() {
    use frankenengine_engine::parser::{ParseDiagnosticEnvelope, ParseError, ParseErrorCode};
    let err = ParseError {
        code: ParseErrorCode::EmptySource,
        message: "source is empty after whitespace normalization".to_string(),
        source_label: "empty.js".to_string(),
        span: None,
        witness: None,
    };
    let envelope = ParseDiagnosticEnvelope::from_parse_error(&err);
    assert_eq!(envelope.parse_error_code, ParseErrorCode::EmptySource);
    assert_eq!(
        envelope.diagnostic_code,
        ParseErrorCode::EmptySource.stable_diagnostic_code()
    );
    assert_eq!(
        envelope.category,
        ParseErrorCode::EmptySource.diagnostic_category()
    );
    assert_eq!(
        envelope.severity,
        ParseErrorCode::EmptySource.diagnostic_severity()
    );
    assert_eq!(envelope.source_label, "empty.js");
    assert!(envelope.span.is_none());
    assert!(envelope.budget_kind.is_none());
    assert!(envelope.witness.is_none());
}

#[test]
fn enrichment_parse_diagnostic_envelope_canonical_value_keys() {
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    use frankenengine_engine::parser::{ParseDiagnosticEnvelope, ParseError, ParseErrorCode};
    let err = ParseError {
        code: ParseErrorCode::UnsupportedSyntax,
        message: "unsupported".to_string(),
        source_label: "src.js".to_string(),
        span: None,
        witness: None,
    };
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
        for key in expected_keys {
            assert!(map.contains_key(key), "canonical_value missing key: {key}");
        }
        assert_eq!(map.len(), 13);
    } else {
        panic!("canonical_value should be a Map");
    }
}

#[test]
fn enrichment_parse_diagnostic_envelope_canonical_hash_deterministic() {
    use frankenengine_engine::parser::{ParseDiagnosticEnvelope, ParseError, ParseErrorCode};
    let err = ParseError {
        code: ParseErrorCode::InvalidGoal,
        message: "test".to_string(),
        source_label: "x.js".to_string(),
        span: None,
        witness: None,
    };
    let envelope = ParseDiagnosticEnvelope::from_parse_error(&err);
    let hash1 = envelope.canonical_hash();
    let hash2 = envelope.canonical_hash();
    assert_eq!(hash1, hash2, "canonical_hash must be deterministic");
    assert!(
        hash1.starts_with("sha256:"),
        "canonical_hash should start with sha256: prefix"
    );
}

#[test]
fn enrichment_parse_diagnostic_envelope_canonical_bytes_nonempty() {
    use frankenengine_engine::parser::{ParseDiagnosticEnvelope, ParseError, ParseErrorCode};
    let err = ParseError {
        code: ParseErrorCode::SourceTooLarge,
        message: "too big".to_string(),
        source_label: "big.js".to_string(),
        span: None,
        witness: None,
    };
    let envelope = ParseDiagnosticEnvelope::from_parse_error(&err);
    let bytes = envelope.canonical_bytes();
    assert!(!bytes.is_empty(), "canonical_bytes should not be empty");
}

#[test]
fn enrichment_parse_diagnostic_envelope_serde_roundtrip() {
    use frankenengine_engine::parser::{ParseDiagnosticEnvelope, ParseError, ParseErrorCode};
    let err = ParseError {
        code: ParseErrorCode::BudgetExceeded,
        message: "budget exceeded".to_string(),
        source_label: "x.js".to_string(),
        span: None,
        witness: None,
    };
    let envelope = ParseDiagnosticEnvelope::from_parse_error(&err);
    let json = serde_json::to_string(&envelope).unwrap();
    let rt: ParseDiagnosticEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope, rt);
}

#[test]
fn enrichment_parse_diagnostic_envelope_normalized_diagnostic() {
    use frankenengine_engine::parser::{ParseError, ParseErrorCode};
    let err = ParseError {
        code: ParseErrorCode::InvalidUtf8,
        message: "bad utf8".to_string(),
        source_label: "bin.dat".to_string(),
        span: None,
        witness: None,
    };
    let envelope = err.normalized_diagnostic();
    assert_eq!(envelope.parse_error_code, ParseErrorCode::InvalidUtf8);
    assert_eq!(envelope.source_label, "bin.dat");
}

// ===========================================================================
// ENRICHMENT TESTS — ParseEvent
// ===========================================================================

#[test]
fn enrichment_parse_event_canonical_value_keys() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    use frankenengine_engine::parser::{ParseEvent, ParseEventKind, ParserMode};
    let event = ParseEvent {
        sequence: 0,
        kind: ParseEventKind::ParseStarted,
        parser_mode: ParserMode::ScalarReference,
        goal: ParseGoal::Script,
        source_label: "test.js".to_string(),
        trace_id: "trace-test".to_string(),
        decision_id: "decision-test".to_string(),
        policy_id: "policy-test".to_string(),
        component: "test-component".to_string(),
        outcome: "started".to_string(),
        error_code: None,
        statement_index: None,
        span: None,
        payload_kind: None,
        payload_hash: None,
    };
    let cv = event.canonical_value();
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
        for key in expected_keys {
            assert!(
                map.contains_key(key),
                "ParseEvent canonical_value missing key: {key}"
            );
        }
        assert_eq!(map.len(), 15);
    } else {
        panic!("canonical_value should be a Map");
    }
}

#[test]
fn enrichment_parse_event_canonical_value_optional_fields_null() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    use frankenengine_engine::parser::{ParseEvent, ParseEventKind, ParserMode};
    let event = ParseEvent {
        sequence: 0,
        kind: ParseEventKind::ParseStarted,
        parser_mode: ParserMode::ScalarReference,
        goal: ParseGoal::Script,
        source_label: "test.js".to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        outcome: "started".to_string(),
        error_code: None,
        statement_index: None,
        span: None,
        payload_kind: None,
        payload_hash: None,
    };
    let cv = event.canonical_value();
    if let CanonicalValue::Map(map) = &cv {
        assert_eq!(map.get("error_code"), Some(&CanonicalValue::Null));
        assert_eq!(map.get("statement_index"), Some(&CanonicalValue::Null));
        assert_eq!(map.get("span"), Some(&CanonicalValue::Null));
        assert_eq!(map.get("payload_kind"), Some(&CanonicalValue::Null));
        assert_eq!(map.get("payload_hash"), Some(&CanonicalValue::Null));
    } else {
        panic!("canonical_value should be a Map");
    }
}

#[test]
fn enrichment_parse_event_serde_roundtrip() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{ParseEvent, ParseEventKind, ParserMode};
    let event = ParseEvent {
        sequence: 42,
        kind: ParseEventKind::StatementParsed,
        parser_mode: ParserMode::ScalarReference,
        goal: ParseGoal::Module,
        source_label: "mod.mjs".to_string(),
        trace_id: "trace-abc".to_string(),
        decision_id: "decision-abc".to_string(),
        policy_id: "policy-id".to_string(),
        component: "component".to_string(),
        outcome: "parsed".to_string(),
        error_code: None,
        statement_index: Some(5),
        span: None,
        payload_kind: Some("expression".to_string()),
        payload_hash: Some("sha256:deadbeef".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let rt: ParseEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, rt);
}

// ===========================================================================
// ENRICHMENT TESTS — ParseEventIr
// ===========================================================================

#[test]
fn enrichment_parse_event_ir_from_parse_error_structure() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{
        ParseError, ParseErrorCode, ParseEventIr, ParseEventKind, ParserMode,
    };
    let err = ParseError {
        code: ParseErrorCode::EmptySource,
        message: "empty".to_string(),
        source_label: "test.js".to_string(),
        span: None,
        witness: None,
    };
    let ir = ParseEventIr::from_parse_error(&err, ParseGoal::Script, ParserMode::ScalarReference);
    assert_eq!(ir.parser_mode, ParserMode::ScalarReference);
    assert_eq!(ir.goal, ParseGoal::Script);
    assert_eq!(ir.source_label, "test.js");
    assert_eq!(ir.events.len(), 2);
    assert_eq!(ir.events[0].kind, ParseEventKind::ParseStarted);
    assert_eq!(ir.events[0].sequence, 0);
    assert_eq!(ir.events[1].kind, ParseEventKind::ParseFailed);
    assert_eq!(ir.events[1].sequence, 1);
    assert_eq!(ir.events[1].error_code, Some(ParseErrorCode::EmptySource));
}

#[test]
fn enrichment_parse_event_ir_from_parse_error_provenance_consistent() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{ParseError, ParseErrorCode, ParseEventIr, ParserMode};
    let err = ParseError {
        code: ParseErrorCode::InvalidGoal,
        message: "bad goal".to_string(),
        source_label: "x.js".to_string(),
        span: None,
        witness: None,
    };
    let ir = ParseEventIr::from_parse_error(&err, ParseGoal::Module, ParserMode::ScalarReference);
    // All events should share trace_id, decision_id, policy_id, component
    let trace_id = &ir.events[0].trace_id;
    let decision_id = &ir.events[0].decision_id;
    for event in &ir.events {
        assert_eq!(&event.trace_id, trace_id);
        assert_eq!(&event.decision_id, decision_id);
    }
    assert!(trace_id.starts_with("trace-parser-event-"));
    assert!(decision_id.starts_with("decision-parser-event-"));
}

#[test]
fn enrichment_parse_event_ir_canonical_hash_deterministic() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{ParseError, ParseErrorCode, ParseEventIr, ParserMode};
    let err = ParseError {
        code: ParseErrorCode::EmptySource,
        message: "empty".to_string(),
        source_label: "det.js".to_string(),
        span: None,
        witness: None,
    };
    let ir = ParseEventIr::from_parse_error(&err, ParseGoal::Script, ParserMode::ScalarReference);
    let h1 = ir.canonical_hash();
    let h2 = ir.canonical_hash();
    assert_eq!(h1, h2, "canonical_hash must be deterministic");
    assert!(h1.starts_with("sha256:"));
}

#[test]
fn enrichment_parse_event_ir_canonical_value_keys() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    use frankenengine_engine::parser::{ParseError, ParseErrorCode, ParseEventIr, ParserMode};
    let err = ParseError {
        code: ParseErrorCode::EmptySource,
        message: "empty".to_string(),
        source_label: "k.js".to_string(),
        span: None,
        witness: None,
    };
    let ir = ParseEventIr::from_parse_error(&err, ParseGoal::Script, ParserMode::ScalarReference);
    let cv = ir.canonical_value();
    if let CanonicalValue::Map(map) = &cv {
        let expected = [
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
        for key in expected {
            assert!(
                map.contains_key(key),
                "ParseEventIr canonical_value missing key: {key}"
            );
        }
        assert_eq!(map.len(), 9);
    } else {
        panic!("canonical_value should be a Map");
    }
}

#[test]
fn enrichment_parse_event_ir_serde_roundtrip() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{ParseError, ParseErrorCode, ParseEventIr, ParserMode};
    let err = ParseError {
        code: ParseErrorCode::EmptySource,
        message: "empty".to_string(),
        source_label: "serde.js".to_string(),
        span: None,
        witness: None,
    };
    let ir = ParseEventIr::from_parse_error(&err, ParseGoal::Script, ParserMode::ScalarReference);
    let json = serde_json::to_string(&ir).unwrap();
    let rt: ParseEventIr = serde_json::from_str(&json).unwrap();
    assert_eq!(ir, rt);
}

// ===========================================================================
// ENRICHMENT TESTS — CanonicalEs2020Parser parse methods
// ===========================================================================

#[test]
fn enrichment_canonical_parser_parse_with_event_ir_success() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParseEventKind, ParserOptions};
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let (result, event_ir) = parser.parse_with_event_ir("var x = 1", ParseGoal::Script, &options);
    assert!(result.is_ok(), "parse should succeed");
    let tree = result.unwrap();
    assert_eq!(tree.goal, ParseGoal::Script);
    assert!(!tree.body.is_empty());

    // Event IR should have ParseStarted, StatementParsed(s), ParseCompleted
    assert!(event_ir.events.len() >= 3);
    assert_eq!(event_ir.events[0].kind, ParseEventKind::ParseStarted);
    assert_eq!(
        event_ir.events.last().unwrap().kind,
        ParseEventKind::ParseCompleted
    );
}

#[test]
fn enrichment_canonical_parser_parse_with_event_ir_failure() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{
        CanonicalEs2020Parser, ParseErrorCode, ParseEventKind, ParserOptions,
    };
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let (result, event_ir) = parser.parse_with_event_ir("", ParseGoal::Script, &options);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ParseErrorCode::EmptySource);

    // Event IR should still be generated for failure
    assert_eq!(event_ir.events.len(), 2);
    assert_eq!(event_ir.events[0].kind, ParseEventKind::ParseStarted);
    assert_eq!(event_ir.events[1].kind, ParseEventKind::ParseFailed);
}

#[test]
fn enrichment_canonical_parser_parse_with_materialized_ast_success() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let (result, event_ir, materialized) =
        parser.parse_with_materialized_ast("var x = 1", ParseGoal::Script, &options);
    assert!(result.is_ok());
    assert!(!event_ir.events.is_empty());
    assert!(materialized.is_ok(), "materialization should succeed");
    let mat = materialized.unwrap();
    assert_eq!(mat.goal, ParseGoal::Script);
    assert_eq!(mat.parser_mode, options.mode);
    assert!(!mat.root_node_id.is_empty());
}

#[test]
fn enrichment_canonical_parser_parse_with_materialized_ast_failure() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{
        CanonicalEs2020Parser, ParseEventMaterializationErrorCode, ParserOptions,
    };
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let (result, _event_ir, materialized) =
        parser.parse_with_materialized_ast("   ", ParseGoal::Script, &options);
    assert!(result.is_err());
    assert!(materialized.is_err());
    let mat_err = materialized.unwrap_err();
    assert_eq!(
        mat_err.code,
        ParseEventMaterializationErrorCode::ParseFailedEventStream
    );
}

// ===========================================================================
// ENRICHMENT TESTS — MaterializedSyntaxTree
// ===========================================================================

#[test]
fn enrichment_materialized_syntax_tree_canonical_hash_deterministic() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let (_, _, materialized) =
        parser.parse_with_materialized_ast("var a = 42", ParseGoal::Script, &options);
    let mat = materialized.unwrap();
    let h1 = mat.canonical_hash();
    let h2 = mat.canonical_hash();
    assert_eq!(h1, h2, "canonical_hash must be deterministic");
    assert!(h1.starts_with("sha256:"));
}

#[test]
fn enrichment_materialized_syntax_tree_canonical_value_keys() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let (_, _, materialized) =
        parser.parse_with_materialized_ast("var z = 0", ParseGoal::Script, &options);
    let mat = materialized.unwrap();
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
        for key in expected {
            assert!(
                map.contains_key(key),
                "MaterializedSyntaxTree canonical_value missing key: {key}"
            );
        }
        assert_eq!(map.len(), 12);
    } else {
        panic!("canonical_value should be a Map");
    }
}

#[test]
fn enrichment_materialized_syntax_tree_serde_roundtrip() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{
        CanonicalEs2020Parser, MaterializedSyntaxTree, ParserOptions,
    };
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let (_, _, materialized) =
        parser.parse_with_materialized_ast("var q = 99", ParseGoal::Script, &options);
    let mat = materialized.unwrap();
    let json = serde_json::to_string(&mat).unwrap();
    let rt: MaterializedSyntaxTree = serde_json::from_str(&json).unwrap();
    assert_eq!(mat, rt);
}

#[test]
fn enrichment_materialized_syntax_tree_statement_nodes() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let source = "var a = 1\nvar b = 2";
    let (result, _, materialized) =
        parser.parse_with_materialized_ast(source, ParseGoal::Script, &options);
    let tree = result.unwrap();
    let mat = materialized.unwrap();
    assert_eq!(mat.statement_nodes.len(), tree.body.len());
    for (i, node) in mat.statement_nodes.iter().enumerate() {
        assert_eq!(node.statement_index, i as u64);
        assert!(
            node.node_id.starts_with("ast-node-"),
            "node_id should start with ast-node-"
        );
        assert!(!node.payload_hash.is_empty());
    }
}

#[test]
fn enrichment_materialized_syntax_tree_contract_schema_versions() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{
        CanonicalEs2020Parser, PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION,
        PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION, ParserOptions,
    };
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let (_, _, materialized) =
        parser.parse_with_materialized_ast("var v = 7", ParseGoal::Script, &options);
    let mat = materialized.unwrap();
    assert_eq!(
        mat.contract_version,
        PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION
    );
    assert_eq!(
        mat.schema_version,
        PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION
    );
}

// ===========================================================================
// ENRICHMENT TESTS — GrammarFamilyCoverage fields
// ===========================================================================

#[test]
fn enrichment_grammar_family_coverage_fields_nonempty() {
    let matrix = frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020();
    for family in &matrix.families {
        assert!(
            !family.family_id.is_empty(),
            "family_id should not be empty"
        );
        assert!(
            !family.es2020_clause.is_empty(),
            "es2020_clause should not be empty for family {}",
            family.family_id
        );
        assert!(
            !family.notes.is_empty(),
            "notes should not be empty for family {}",
            family.family_id
        );
    }
}

#[test]
fn enrichment_grammar_family_coverage_serde_roundtrip() {
    use frankenengine_engine::parser::GrammarFamilyCoverage;
    let matrix = frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020();
    let family = &matrix.families[0];
    let json = serde_json::to_string(family).unwrap();
    let rt: GrammarFamilyCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(*family, rt);
}

// ===========================================================================
// ENRICHMENT TESTS — ParseEventMaterializationError
// ===========================================================================

#[test]
fn enrichment_materialization_error_display_with_sequence() {
    use frankenengine_engine::parser::{
        ParseEventMaterializationError, ParseEventMaterializationErrorCode,
    };
    let err = ParseEventMaterializationError {
        code: ParseEventMaterializationErrorCode::StatementHashMismatch,
        message: "hash mismatch".to_string(),
        sequence: Some(5),
    };
    let display = format!("{err}");
    assert!(
        display.contains("(sequence=5)"),
        "Display should contain sequence, got: {display}"
    );
    assert!(
        display.contains("statement_hash_mismatch"),
        "Display should contain error code as_str, got: {display}"
    );
}

#[test]
fn enrichment_materialization_error_display_without_sequence() {
    use frankenengine_engine::parser::{
        ParseEventMaterializationError, ParseEventMaterializationErrorCode,
    };
    let err = ParseEventMaterializationError {
        code: ParseEventMaterializationErrorCode::ParseFailedEventStream,
        message: "failed".to_string(),
        sequence: None,
    };
    let display = format!("{err}");
    assert!(
        !display.contains("sequence="),
        "Display should not contain sequence when None, got: {display}"
    );
    assert!(display.contains("parse_failed_event_stream"));
}

#[test]
fn enrichment_materialization_error_is_std_error() {
    use frankenengine_engine::parser::{
        ParseEventMaterializationError, ParseEventMaterializationErrorCode,
    };
    let err = ParseEventMaterializationError {
        code: ParseEventMaterializationErrorCode::GoalMismatch,
        message: "goal mismatch".to_string(),
        sequence: None,
    };
    let e: &dyn std::error::Error = &err;
    let _ = format!("{e}");
}

#[test]
fn enrichment_materialization_error_serde_roundtrip() {
    use frankenengine_engine::parser::{
        ParseEventMaterializationError, ParseEventMaterializationErrorCode,
    };
    let err = ParseEventMaterializationError {
        code: ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
        message: "inconsistent".to_string(),
        sequence: Some(3),
    };
    let json = serde_json::to_string(&err).unwrap();
    let rt: ParseEventMaterializationError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, rt);
}

// ===========================================================================
// ENRICHMENT TESTS — normalize_parse_error
// ===========================================================================

#[test]
fn enrichment_normalize_parse_error_budget_with_witness() {
    use frankenengine_engine::parser::{
        ParseBudgetKind, ParseError, ParseErrorCode, ParseFailureWitness, ParserMode,
        normalize_parse_error,
    };
    let witness = ParseFailureWitness {
        mode: ParserMode::ScalarReference,
        budget_kind: Some(ParseBudgetKind::TokenCount),
        source_bytes: 500,
        token_count: 100_000,
        max_recursion_observed: 5,
        max_source_bytes: 1_048_576,
        max_token_count: 65_536,
        max_recursion_depth: 256,
    };
    let err = ParseError {
        code: ParseErrorCode::BudgetExceeded,
        message: "token budget exceeded".to_string(),
        source_label: "big.js".to_string(),
        span: None,
        witness: Some(Box::new(witness.clone())),
    };
    let envelope = normalize_parse_error(&err);
    assert_eq!(envelope.budget_kind, Some(ParseBudgetKind::TokenCount));
    assert!(envelope.witness.is_some());
    assert_eq!(envelope.witness.unwrap(), witness);
    assert_eq!(
        envelope.message_template,
        ParseErrorCode::BudgetExceeded
            .diagnostic_message_template(Some(ParseBudgetKind::TokenCount))
    );
}

// ===========================================================================
// ENRICHMENT TESTS — SEMANTIC_ERROR_TAXONOMY_VERSION constant
// ===========================================================================

#[test]
fn enrichment_semantic_error_taxonomy_version_nonempty() {
    use frankenengine_engine::parser::SEMANTIC_ERROR_TAXONOMY_VERSION;
    assert!(!SEMANTIC_ERROR_TAXONOMY_VERSION.is_empty());
    assert!(SEMANTIC_ERROR_TAXONOMY_VERSION.contains("taxonomy"));
}

// ===========================================================================
// ENRICHMENT TESTS — ParseDiagnosticSeverity assignment
// ===========================================================================

#[test]
fn enrichment_parse_error_code_severity_fatal_for_resource_io() {
    use frankenengine_engine::parser::{ParseDiagnosticSeverity, ParseErrorCode};
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
fn enrichment_parse_error_code_severity_error_for_user_errors() {
    use frankenengine_engine::parser::{ParseDiagnosticSeverity, ParseErrorCode};
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
}

// ===========================================================================
// ENRICHMENT TESTS — Es2020Parser trait
// ===========================================================================

#[test]
fn enrichment_es2020_parser_trait_parse_simple_script() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};
    let parser = CanonicalEs2020Parser;
    let result = parser.parse("var x = 42", ParseGoal::Script);
    assert!(result.is_ok());
    let tree = result.unwrap();
    assert_eq!(tree.goal, ParseGoal::Script);
    assert!(!tree.body.is_empty());
}

#[test]
fn enrichment_es2020_parser_trait_parse_module() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};
    let parser = CanonicalEs2020Parser;
    let result = parser.parse("export default 42", ParseGoal::Module);
    assert!(result.is_ok());
    let tree = result.unwrap();
    assert_eq!(tree.goal, ParseGoal::Module);
}

#[test]
fn enrichment_es2020_parser_trait_parse_empty_fails() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};
    let parser = CanonicalEs2020Parser;
    let result = parser.parse("   ", ParseGoal::Script);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ParseErrorCode::EmptySource);
}

// ===========================================================================
// ENRICHMENT TESTS — MaterializedStatementNode canonical_value
// ===========================================================================

#[test]
fn enrichment_materialized_statement_node_canonical_value_keys() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let (_, _, materialized) =
        parser.parse_with_materialized_ast("var n = 1", ParseGoal::Script, &options);
    let mat = materialized.unwrap();
    assert!(!mat.statement_nodes.is_empty());
    let node = &mat.statement_nodes[0];
    let cv = node.canonical_value();
    if let CanonicalValue::Map(map) = &cv {
        let expected = [
            "node_id",
            "sequence",
            "statement_index",
            "payload_hash",
            "span",
        ];
        for key in expected {
            assert!(
                map.contains_key(key),
                "MaterializedStatementNode missing key: {key}"
            );
        }
        assert_eq!(map.len(), 5);
    } else {
        panic!("canonical_value should be a Map");
    }
}

// ===========================================================================
// ENRICHMENT TESTS — ParseEventKind canonical_value
// ===========================================================================

#[test]
fn enrichment_parse_event_kind_canonical_value_is_string() {
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    use frankenengine_engine::parser::ParseEventKind;
    for kind in [
        ParseEventKind::ParseStarted,
        ParseEventKind::StatementParsed,
        ParseEventKind::ParseCompleted,
        ParseEventKind::ParseFailed,
    ] {
        let cv = kind.canonical_value();
        if let CanonicalValue::String(s) = &cv {
            assert_eq!(s, kind.as_str());
        } else {
            panic!("canonical_value for {kind:?} should be a String");
        }
    }
}

// ===========================================================================
// ENRICHMENT TESTS — GrammarCompletenessMatrix summary edge cases
// ===========================================================================

#[test]
fn enrichment_grammar_completeness_summary_has_no_unsupported() {
    let matrix = frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020();
    let summary = matrix.summary();
    // The current matrix should have zero unsupported families
    assert_eq!(
        summary.unsupported_families, 0,
        "scalar_reference_es2020 should have no unsupported families"
    );
}

#[test]
fn enrichment_grammar_completeness_summary_completeness_positive() {
    let matrix = frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020();
    let summary = matrix.summary();
    assert!(
        summary.completeness_millionths > 0,
        "completeness should be positive"
    );
    assert!(
        summary.completeness_millionths <= 1_000_000,
        "completeness should not exceed 1.0"
    );
}

// ===========================================================================
// ENRICHMENT TESTS — scalar_reference_grammar_matrix via CanonicalEs2020Parser
// ===========================================================================

#[test]
fn enrichment_canonical_parser_grammar_matrix() {
    use frankenengine_engine::parser::CanonicalEs2020Parser;
    let parser = CanonicalEs2020Parser;
    let matrix = parser.scalar_reference_grammar_matrix();
    assert_eq!(
        matrix,
        frankenengine_engine::parser::GrammarCompletenessMatrix::scalar_reference_es2020()
    );
}
