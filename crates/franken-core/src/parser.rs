// Deterministic parser interface for ES2020 script/module goals.
//
// The parser trait is generic over input source and emits canonical `IR0`
// syntax artifacts from `crate::ast`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::ast::ParseGoal;
use crate::ast::{
    ArrowBody, AssignmentOperator, BinaryOperator, BindingPattern, BlockStatement, BreakStatement,
    CatchClause, ClassDeclaration, ContinueStatement, DoWhileStatement, ExportDeclaration,
    ExportKind, Expression, ExpressionStatement, ForInStatement, ForOfStatement, ForStatement,
    FunctionDeclaration, FunctionParam, IfStatement, ImportClause, ImportDeclaration,
    ImportSpecifier, LabeledStatement, MethodDefinition, MethodKind, NamedExportClause,
    ObjectPatternProperty, ObjectProperty, ObjectPropertyKind, ReturnStatement, SourceSpan,
    Statement, SwitchCase, SwitchStatement, SyntaxTree, ThrowStatement, TryCatchStatement,
    UnaryOperator, UpdateOperator, VariableDeclaration, VariableDeclarationKind,
    VariableDeclarator, WhileStatement,
};
use crate::deterministic_serde::{self, CanonicalValue};
use crate::js_string::JsString;

pub type ParseResult<T> = Result<T, ParseError>;

/// Versioned Parse Event IR contract identifier.
pub const PARSE_EVENT_IR_CONTRACT_VERSION: &str = "franken-engine.parser-event-ir.contract.v2";
/// Versioned Parse Event IR schema identifier.
pub const PARSE_EVENT_IR_SCHEMA_VERSION: &str = "franken-engine.parser-event-ir.schema.v2";
/// Hash algorithm used for Parse Event IR canonical hashes.
pub const PARSE_EVENT_IR_HASH_ALGORITHM: &str = "sha256";
/// Hash prefix used for Parse Event IR canonical hashes.
pub const PARSE_EVENT_IR_HASH_PREFIX: &str = "sha256:";
/// Stable policy identifier used for parser event provenance.
pub const PARSE_EVENT_IR_POLICY_ID: &str = "franken-engine.parser-event-producer.policy.v1";
/// Stable component identifier used for parser event provenance.
pub const PARSE_EVENT_IR_COMPONENT: &str = "canonical_es2020_parser";
/// Stable prefix used for parse event trace IDs.
pub const PARSE_EVENT_IR_TRACE_PREFIX: &str = "trace-parser-event-";
/// Stable prefix used for parse event decision IDs.
pub const PARSE_EVENT_IR_DECISION_PREFIX: &str = "decision-parser-event-";
/// Versioned event->AST materializer contract identifier.
pub const PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION: &str =
    "franken-engine.parser-event-ast-materializer.contract.v1";
/// Versioned event->AST materializer schema identifier.
pub const PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION: &str =
    "franken-engine.parser-event-ast-materializer.schema.v1";
/// Stable prefix used for materialized AST node IDs.
pub const PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX: &str = "ast-node-";
/// Versioned parser diagnostics taxonomy identifier.
pub const PARSER_DIAGNOSTIC_TAXONOMY_VERSION: &str =
    "franken-engine.parser-diagnostics.taxonomy.v1";
/// Versioned normalized parser diagnostics schema identifier.
pub const PARSER_DIAGNOSTIC_SCHEMA_VERSION: &str = "franken-engine.parser-diagnostics.schema.v1";
/// Hash algorithm used for normalized parser diagnostics hashes.
pub const PARSER_DIAGNOSTIC_HASH_ALGORITHM: &str = "sha256";
/// Hash prefix used for normalized parser diagnostics hashes.
pub const PARSER_DIAGNOSTIC_HASH_PREFIX: &str = "sha256:";

/// Stable parse error codes for deterministic diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseErrorCode {
    EmptySource,
    InvalidGoal,
    UnsupportedSyntax,
    IoReadFailed,
    InvalidUtf8,
    SourceTooLarge,
    BudgetExceeded,
}

impl ParseErrorCode {
    pub const ALL: [Self; 7] = [
        Self::EmptySource,
        Self::InvalidGoal,
        Self::UnsupportedSyntax,
        Self::IoReadFailed,
        Self::InvalidUtf8,
        Self::SourceTooLarge,
        Self::BudgetExceeded,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptySource => "empty_source",
            Self::InvalidGoal => "invalid_goal",
            Self::UnsupportedSyntax => "unsupported_syntax",
            Self::IoReadFailed => "io_read_failed",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::SourceTooLarge => "source_too_large",
            Self::BudgetExceeded => "budget_exceeded",
        }
    }

    pub const fn stable_diagnostic_code(self) -> &'static str {
        match self {
            Self::EmptySource => "FE-PARSER-DIAG-EMPTY-SOURCE-0001",
            Self::InvalidGoal => "FE-PARSER-DIAG-INVALID-GOAL-0001",
            Self::UnsupportedSyntax => "FE-PARSER-DIAG-UNSUPPORTED-SYNTAX-0001",
            Self::IoReadFailed => "FE-PARSER-DIAG-IO-READ-FAILED-0001",
            Self::InvalidUtf8 => "FE-PARSER-DIAG-INVALID-UTF8-0001",
            Self::SourceTooLarge => "FE-PARSER-DIAG-SOURCE-TOO-LARGE-0001",
            Self::BudgetExceeded => "FE-PARSER-DIAG-BUDGET-EXCEEDED-0001",
        }
    }

    pub const fn diagnostic_category(self) -> ParseDiagnosticCategory {
        match self {
            Self::EmptySource => ParseDiagnosticCategory::Input,
            Self::InvalidGoal => ParseDiagnosticCategory::Goal,
            Self::UnsupportedSyntax => ParseDiagnosticCategory::Syntax,
            Self::IoReadFailed => ParseDiagnosticCategory::System,
            Self::InvalidUtf8 => ParseDiagnosticCategory::Encoding,
            Self::SourceTooLarge | Self::BudgetExceeded => ParseDiagnosticCategory::Resource,
        }
    }

    pub const fn diagnostic_severity(self) -> ParseDiagnosticSeverity {
        match self {
            Self::IoReadFailed | Self::SourceTooLarge | Self::BudgetExceeded => {
                ParseDiagnosticSeverity::Fatal
            }
            Self::EmptySource | Self::InvalidGoal | Self::UnsupportedSyntax | Self::InvalidUtf8 => {
                ParseDiagnosticSeverity::Error
            }
        }
    }

    pub const fn diagnostic_message_template(
        self,
        budget_kind: Option<ParseBudgetKind>,
    ) -> &'static str {
        match self {
            Self::EmptySource => "source is empty after whitespace normalization",
            Self::InvalidGoal => "declaration is invalid for selected parse goal",
            Self::UnsupportedSyntax => "statement or expression is unsupported by parser scaffold",
            Self::IoReadFailed => "parser input could not be read",
            Self::InvalidUtf8 => "parser input is not valid UTF-8",
            Self::SourceTooLarge => "source length/offset exceeds supported limits",
            Self::BudgetExceeded => match budget_kind {
                Some(ParseBudgetKind::SourceBytes) => "source byte budget exceeded",
                Some(ParseBudgetKind::TokenCount) => "token budget exceeded",
                Some(ParseBudgetKind::RecursionDepth) => "recursion depth budget exceeded",
                None => "parser budget exceeded",
            },
        }
    }
}

/// Deterministic parser diagnostic category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseDiagnosticCategory {
    Input,
    Goal,
    Syntax,
    Encoding,
    Resource,
    System,
}

impl ParseDiagnosticCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Goal => "goal",
            Self::Syntax => "syntax",
            Self::Encoding => "encoding",
            Self::Resource => "resource",
            Self::System => "system",
        }
    }
}

/// Deterministic parser diagnostic severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseDiagnosticSeverity {
    Error,
    Fatal,
}

impl ParseDiagnosticSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }
}

/// Taxonomy row for one stable parser diagnostic code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseDiagnosticRule {
    pub parse_error_code: ParseErrorCode,
    pub diagnostic_code: String,
    pub category: ParseDiagnosticCategory,
    pub severity: ParseDiagnosticSeverity,
    pub message_template: String,
}

/// Versioned parser diagnostics taxonomy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseDiagnosticTaxonomy {
    pub taxonomy_version: String,
    pub rules: Vec<ParseDiagnosticRule>,
}

impl ParseDiagnosticTaxonomy {
    pub const fn taxonomy_version() -> &'static str {
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION
    }

    pub fn v1() -> Self {
        let rules = ParseErrorCode::ALL
            .iter()
            .map(|code| ParseDiagnosticRule {
                parse_error_code: *code,
                diagnostic_code: code.stable_diagnostic_code().to_string(),
                category: code.diagnostic_category(),
                severity: code.diagnostic_severity(),
                message_template: code.diagnostic_message_template(None).to_string(),
            })
            .collect();
        Self {
            taxonomy_version: Self::taxonomy_version().to_string(),
            rules,
        }
    }

    pub fn rule_for(&self, code: ParseErrorCode) -> Option<&ParseDiagnosticRule> {
        self.rules.iter().find(|rule| rule.parse_error_code == code)
    }
}

/// Parser mode selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserMode {
    /// Deterministic scalar reference parser used as the oracle baseline.
    ScalarReference,
}

impl ParserMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScalarReference => "scalar_reference",
        }
    }
}

/// Deterministic parser budget limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserBudget {
    pub max_source_bytes: u64,
    pub max_token_count: u64,
    pub max_recursion_depth: u64,
}

impl Default for ParserBudget {
    fn default() -> Self {
        Self {
            max_source_bytes: 1_048_576,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        }
    }
}

/// Parser options controlling mode and deterministic budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserOptions {
    pub mode: ParserMode,
    pub budget: ParserBudget,
}

impl Default for ParserOptions {
    fn default() -> Self {
        Self {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget::default(),
        }
    }
}

/// Which budget category exhausted during parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseBudgetKind {
    SourceBytes,
    TokenCount,
    RecursionDepth,
}

impl ParseBudgetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceBytes => "source_bytes",
            Self::TokenCount => "token_count",
            Self::RecursionDepth => "recursion_depth",
        }
    }
}

/// Deterministic parse failure witness emitted for budget failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseFailureWitness {
    pub mode: ParserMode,
    pub budget_kind: Option<ParseBudgetKind>,
    pub source_bytes: u64,
    pub token_count: u64,
    pub max_recursion_observed: u64,
    pub max_source_bytes: u64,
    pub max_token_count: u64,
    pub max_recursion_depth: u64,
}

impl ParseFailureWitness {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "mode".to_string(),
            CanonicalValue::String(self.mode.as_str().to_string()),
        );
        map.insert(
            "budget_kind".to_string(),
            self.budget_kind
                .map(|kind| CanonicalValue::String(kind.as_str().to_string()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "source_bytes".to_string(),
            CanonicalValue::U64(self.source_bytes),
        );
        map.insert(
            "token_count".to_string(),
            CanonicalValue::U64(self.token_count),
        );
        map.insert(
            "max_recursion_observed".to_string(),
            CanonicalValue::U64(self.max_recursion_observed),
        );
        map.insert(
            "max_source_bytes".to_string(),
            CanonicalValue::U64(self.max_source_bytes),
        );
        map.insert(
            "max_token_count".to_string(),
            CanonicalValue::U64(self.max_token_count),
        );
        map.insert(
            "max_recursion_depth".to_string(),
            CanonicalValue::U64(self.max_recursion_depth),
        );
        CanonicalValue::Map(map)
    }
}

/// Coverage status for a grammar family in Script/Module goals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrammarCoverageStatus {
    Supported,
    Partial,
    Unsupported,
    NotApplicable,
}

impl GrammarCoverageStatus {
    fn score_numer(self) -> u64 {
        match self {
            Self::Supported | Self::NotApplicable => 1000,
            Self::Partial => 500,
            Self::Unsupported => 0,
        }
    }
}

/// Single grammar-family row for completeness tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrammarFamilyCoverage {
    pub family_id: String,
    pub es2020_clause: String,
    pub script_goal: GrammarCoverageStatus,
    pub module_goal: GrammarCoverageStatus,
    pub notes: String,
}

/// Full scalar parser completeness matrix for ES2020 families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrammarCompletenessMatrix {
    pub schema_version: String,
    pub parser_mode: ParserMode,
    pub families: Vec<GrammarFamilyCoverage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrammarCompletenessSummary {
    pub family_count: u64,
    pub supported_families: u64,
    pub partially_supported_families: u64,
    pub unsupported_families: u64,
    pub completeness_millionths: u64,
}

/// Deterministic parse error envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseError {
    pub code: ParseErrorCode,
    pub message: String,
    pub source_label: String,
    pub span: Option<SourceSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<Box<ParseFailureWitness>>,
}

impl ParseError {
    fn new(
        code: ParseErrorCode,
        message: impl Into<String>,
        source_label: impl Into<String>,
        span: Option<SourceSpan>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source_label: source_label.into(),
            span,
            witness: None,
        }
    }

    fn with_witness(
        code: ParseErrorCode,
        message: impl Into<String>,
        source_label: impl Into<String>,
        span: Option<SourceSpan>,
        witness: ParseFailureWitness,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source_label: source_label.into(),
            span,
            witness: Some(Box::new(witness)),
        }
    }

    pub fn normalized_diagnostic(&self) -> ParseDiagnosticEnvelope {
        normalize_parse_error(self)
    }
}

/// Canonical parser diagnostic envelope derived from a parse error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseDiagnosticEnvelope {
    pub schema_version: String,
    pub taxonomy_version: String,
    pub hash_algorithm: String,
    pub hash_prefix: String,
    pub parse_error_code: ParseErrorCode,
    pub diagnostic_code: String,
    pub category: ParseDiagnosticCategory,
    pub severity: ParseDiagnosticSeverity,
    pub message_template: String,
    pub source_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_kind: Option<ParseBudgetKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<ParseFailureWitness>,
}

impl ParseDiagnosticEnvelope {
    pub const fn schema_version() -> &'static str {
        PARSER_DIAGNOSTIC_SCHEMA_VERSION
    }

    pub const fn taxonomy_version() -> &'static str {
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION
    }

    pub const fn canonical_hash_algorithm() -> &'static str {
        PARSER_DIAGNOSTIC_HASH_ALGORITHM
    }

    pub const fn canonical_hash_prefix() -> &'static str {
        PARSER_DIAGNOSTIC_HASH_PREFIX
    }

    pub fn from_parse_error(error: &ParseError) -> Self {
        normalize_parse_error(error)
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "taxonomy_version".to_string(),
            CanonicalValue::String(self.taxonomy_version.clone()),
        );
        map.insert(
            "hash_algorithm".to_string(),
            CanonicalValue::String(self.hash_algorithm.clone()),
        );
        map.insert(
            "hash_prefix".to_string(),
            CanonicalValue::String(self.hash_prefix.clone()),
        );
        map.insert(
            "parse_error_code".to_string(),
            CanonicalValue::String(self.parse_error_code.as_str().to_string()),
        );
        map.insert(
            "diagnostic_code".to_string(),
            CanonicalValue::String(self.diagnostic_code.clone()),
        );
        map.insert(
            "category".to_string(),
            CanonicalValue::String(self.category.as_str().to_string()),
        );
        map.insert(
            "severity".to_string(),
            CanonicalValue::String(self.severity.as_str().to_string()),
        );
        map.insert(
            "message_template".to_string(),
            CanonicalValue::String(self.message_template.clone()),
        );
        map.insert(
            "source_label".to_string(),
            CanonicalValue::String(self.source_label.clone()),
        );
        map.insert(
            "span".to_string(),
            self.span
                .as_ref()
                .map(SourceSpan::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "budget_kind".to_string(),
            self.budget_kind
                .map(|kind| CanonicalValue::String(kind.as_str().to_string()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "witness".to_string(),
            self.witness
                .as_ref()
                .map(ParseFailureWitness::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!("{}{}", self.hash_prefix, hex::encode(digest))
    }
}

/// Normalize a parse error into the deterministic diagnostics envelope contract.
pub fn normalize_parse_error(error: &ParseError) -> ParseDiagnosticEnvelope {
    let budget_kind = error
        .witness
        .as_ref()
        .and_then(|witness| witness.budget_kind);
    ParseDiagnosticEnvelope {
        schema_version: ParseDiagnosticEnvelope::schema_version().to_string(),
        taxonomy_version: ParseDiagnosticEnvelope::taxonomy_version().to_string(),
        hash_algorithm: ParseDiagnosticEnvelope::canonical_hash_algorithm().to_string(),
        hash_prefix: ParseDiagnosticEnvelope::canonical_hash_prefix().to_string(),
        parse_error_code: error.code,
        diagnostic_code: error.code.stable_diagnostic_code().to_string(),
        category: error.code.diagnostic_category(),
        severity: error.code.diagnostic_severity(),
        message_template: error
            .code
            .diagnostic_message_template(budget_kind)
            .to_string(),
        source_label: error.source_label.clone(),
        span: error.span.clone(),
        budget_kind,
        witness: error
            .witness
            .as_ref()
            .map(|witness| witness.as_ref().clone()),
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.span {
            Some(span) => write!(
                f,
                "{:?}: {} (source={}, line={}, column={})",
                self.code, self.message, self.source_label, span.start_line, span.start_column
            ),
            None => write!(
                f,
                "{:?}: {} (source={})",
                self.code, self.message, self.source_label
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Stable parse event kinds used by the Parse Event IR schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseEventKind {
    ParseStarted,
    StatementParsed,
    ParseCompleted,
    ParseFailed,
}

impl ParseEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ParseStarted => "parse_started",
            Self::StatementParsed => "statement_parsed",
            Self::ParseCompleted => "parse_completed",
            Self::ParseFailed => "parse_failed",
        }
    }

    pub fn canonical_value(self) -> CanonicalValue {
        CanonicalValue::String(self.as_str().to_string())
    }
}

/// Canonical parse-event record with deterministic provenance fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseEvent {
    pub sequence: u64,
    pub kind: ParseEventKind,
    pub parser_mode: ParserMode,
    pub goal: ParseGoal,
    pub source_label: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<ParseErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,
}

impl ParseEvent {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("sequence".to_string(), CanonicalValue::U64(self.sequence));
        map.insert("kind".to_string(), self.kind.canonical_value());
        map.insert(
            "parser_mode".to_string(),
            CanonicalValue::String(self.parser_mode.as_str().to_string()),
        );
        map.insert(
            "goal".to_string(),
            CanonicalValue::String(self.goal.as_str().to_string()),
        );
        map.insert(
            "source_label".to_string(),
            CanonicalValue::String(self.source_label.clone()),
        );
        map.insert(
            "trace_id".to_string(),
            CanonicalValue::String(self.trace_id.clone()),
        );
        map.insert(
            "decision_id".to_string(),
            CanonicalValue::String(self.decision_id.clone()),
        );
        map.insert(
            "policy_id".to_string(),
            CanonicalValue::String(self.policy_id.clone()),
        );
        map.insert(
            "component".to_string(),
            CanonicalValue::String(self.component.clone()),
        );
        map.insert(
            "outcome".to_string(),
            CanonicalValue::String(self.outcome.clone()),
        );
        map.insert(
            "error_code".to_string(),
            self.error_code
                .map(|code| CanonicalValue::String(code.as_str().to_string()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "statement_index".to_string(),
            self.statement_index
                .map(CanonicalValue::U64)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "span".to_string(),
            self.span
                .as_ref()
                .map(SourceSpan::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "payload_kind".to_string(),
            self.payload_kind
                .as_ref()
                .map(|value| CanonicalValue::String(value.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "payload_hash".to_string(),
            self.payload_hash
                .as_ref()
                .map(|value| CanonicalValue::String(value.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        CanonicalValue::Map(map)
    }
}

/// Versioned Parse Event IR envelope with deterministic canonical serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseEventIr {
    pub schema_version: String,
    pub contract_version: String,
    pub parser_mode: ParserMode,
    pub goal: ParseGoal,
    pub source_label: String,
    pub events: Vec<ParseEvent>,
}

impl ParseEventIr {
    pub const fn contract_version() -> &'static str {
        PARSE_EVENT_IR_CONTRACT_VERSION
    }

    pub const fn schema_version() -> &'static str {
        PARSE_EVENT_IR_SCHEMA_VERSION
    }

    pub const fn canonical_hash_algorithm() -> &'static str {
        PARSE_EVENT_IR_HASH_ALGORITHM
    }

    pub const fn canonical_hash_prefix() -> &'static str {
        PARSE_EVENT_IR_HASH_PREFIX
    }

    pub fn from_syntax_tree(
        tree: &SyntaxTree,
        source_label: impl Into<String>,
        parser_mode: ParserMode,
    ) -> Self {
        let source_label = source_label.into();
        let source_fingerprint = canonical_value_hash(&tree.canonical_value());
        let (trace_id, decision_id) =
            parse_event_provenance_ids(&source_label, parser_mode, tree.goal, &source_fingerprint);
        Self::from_syntax_tree_with_provenance(
            tree,
            source_label,
            parser_mode,
            trace_id,
            decision_id,
            Some(("syntax_tree".to_string(), source_fingerprint)),
        )
    }

    pub fn from_parse_source(
        tree: &SyntaxTree,
        source_text: &str,
        source_label: impl Into<String>,
        parser_mode: ParserMode,
    ) -> Self {
        let source_label = source_label.into();
        let source_fingerprint = canonical_string_hash(source_text);
        let (trace_id, decision_id) =
            parse_event_provenance_ids(&source_label, parser_mode, tree.goal, &source_fingerprint);
        Self::from_syntax_tree_with_provenance(
            tree,
            source_label,
            parser_mode,
            trace_id,
            decision_id,
            Some(("source_text".to_string(), source_fingerprint)),
        )
    }

    pub fn from_parse_error(error: &ParseError, goal: ParseGoal, parser_mode: ParserMode) -> Self {
        let source_label = error.source_label.clone();
        let diagnostic = ParseDiagnosticEnvelope::from_parse_error(error);
        let diagnostic_hash = diagnostic.canonical_hash();
        let (trace_id, decision_id) =
            parse_event_provenance_ids(&source_label, parser_mode, goal, &diagnostic_hash);
        let events = vec![
            ParseEvent {
                sequence: 0,
                kind: ParseEventKind::ParseStarted,
                parser_mode,
                goal,
                source_label: source_label.clone(),
                trace_id: trace_id.clone(),
                decision_id: decision_id.clone(),
                policy_id: PARSE_EVENT_IR_POLICY_ID.to_string(),
                component: PARSE_EVENT_IR_COMPONENT.to_string(),
                outcome: "started".to_string(),
                error_code: None,
                statement_index: None,
                span: None,
                payload_kind: Some("parse_diagnostic".to_string()),
                payload_hash: Some(diagnostic_hash.clone()),
            },
            ParseEvent {
                sequence: 1,
                kind: ParseEventKind::ParseFailed,
                parser_mode,
                goal,
                source_label: source_label.clone(),
                trace_id,
                decision_id,
                policy_id: PARSE_EVENT_IR_POLICY_ID.to_string(),
                component: PARSE_EVENT_IR_COMPONENT.to_string(),
                outcome: "failure".to_string(),
                error_code: Some(error.code),
                statement_index: None,
                span: error.span.clone(),
                payload_kind: Some("parse_diagnostic".to_string()),
                payload_hash: Some(diagnostic_hash),
            },
        ];
        Self {
            schema_version: Self::schema_version().to_string(),
            contract_version: Self::contract_version().to_string(),
            parser_mode,
            goal,
            source_label,
            events,
        }
    }

    fn from_syntax_tree_with_provenance(
        tree: &SyntaxTree,
        source_label: String,
        parser_mode: ParserMode,
        trace_id: String,
        decision_id: String,
        started_payload: Option<(String, String)>,
    ) -> Self {
        let mut events = Vec::new();
        events.push(ParseEvent {
            sequence: 0,
            kind: ParseEventKind::ParseStarted,
            parser_mode,
            goal: tree.goal,
            source_label: source_label.clone(),
            trace_id: trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: PARSE_EVENT_IR_POLICY_ID.to_string(),
            component: PARSE_EVENT_IR_COMPONENT.to_string(),
            outcome: "started".to_string(),
            error_code: None,
            statement_index: None,
            span: None,
            payload_kind: started_payload.as_ref().map(|(kind, _)| kind.clone()),
            payload_hash: started_payload.as_ref().map(|(_, hash)| hash.clone()),
        });

        for (index, statement) in tree.body.iter().enumerate() {
            let statement_index = index as u64;
            events.push(ParseEvent {
                sequence: statement_index.saturating_add(1),
                kind: ParseEventKind::StatementParsed,
                parser_mode,
                goal: tree.goal,
                source_label: source_label.clone(),
                trace_id: trace_id.clone(),
                decision_id: decision_id.clone(),
                policy_id: PARSE_EVENT_IR_POLICY_ID.to_string(),
                component: PARSE_EVENT_IR_COMPONENT.to_string(),
                outcome: "parsed".to_string(),
                error_code: None,
                statement_index: Some(statement_index),
                span: Some(statement.span().clone()),
                payload_kind: Some(statement_kind_label(statement).to_string()),
                payload_hash: Some(canonical_value_hash(&statement.canonical_value())),
            });
        }

        events.push(ParseEvent {
            sequence: (tree.body.len() as u64).saturating_add(1),
            kind: ParseEventKind::ParseCompleted,
            parser_mode,
            goal: tree.goal,
            source_label: source_label.clone(),
            trace_id,
            decision_id,
            policy_id: PARSE_EVENT_IR_POLICY_ID.to_string(),
            component: PARSE_EVENT_IR_COMPONENT.to_string(),
            outcome: "success".to_string(),
            error_code: None,
            statement_index: None,
            span: Some(tree.span.clone()),
            payload_kind: Some("syntax_tree".to_string()),
            payload_hash: Some(canonical_value_hash(&tree.canonical_value())),
        });

        Self {
            schema_version: Self::schema_version().to_string(),
            contract_version: Self::contract_version().to_string(),
            parser_mode,
            goal: tree.goal,
            source_label,
            events,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "contract_version".to_string(),
            CanonicalValue::String(self.contract_version.clone()),
        );
        map.insert(
            "hash_algorithm".to_string(),
            CanonicalValue::String(Self::canonical_hash_algorithm().to_string()),
        );
        map.insert(
            "hash_prefix".to_string(),
            CanonicalValue::String(Self::canonical_hash_prefix().to_string()),
        );
        map.insert(
            "parser_mode".to_string(),
            CanonicalValue::String(self.parser_mode.as_str().to_string()),
        );
        map.insert(
            "goal".to_string(),
            CanonicalValue::String(self.goal.as_str().to_string()),
        );
        map.insert(
            "source_label".to_string(),
            CanonicalValue::String(self.source_label.clone()),
        );
        map.insert(
            "event_count".to_string(),
            CanonicalValue::U64(self.events.len() as u64),
        );
        map.insert(
            "events".to_string(),
            CanonicalValue::Array(
                self.events
                    .iter()
                    .map(ParseEvent::canonical_value)
                    .collect(),
            ),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!("{}{}", Self::canonical_hash_prefix(), hex::encode(digest))
    }

    /// Materialize a deterministic AST witness from this event stream and source text.
    ///
    /// This verifies event ordering/provenance/payload parity, then emits a stable
    /// node-id projection over the canonical AST.
    pub fn materialize_from_source(
        &self,
        source_text: &str,
        options: &ParserOptions,
    ) -> ParseEventMaterializationResult<MaterializedSyntaxTree> {
        if self
            .events
            .iter()
            .any(|event| matches!(event.kind, ParseEventKind::ParseFailed))
        {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::ParseFailedEventStream,
                "cannot materialize AST from a failed parse event stream".to_string(),
                None,
            ));
        }
        if options.mode != self.parser_mode {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::ModeMismatch,
                format!(
                    "materializer mode mismatch: event_ir={} options={}",
                    self.parser_mode.as_str(),
                    options.mode.as_str()
                ),
                None,
            ));
        }
        let parsed =
            parse_source(source_text, &self.source_label, self.goal, options).map_err(|err| {
                ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::SourceParseFailed,
                    format!(
                        "source parse failed while materializing from event stream: {} ({})",
                        err.code.as_str(),
                        err.message
                    ),
                    None,
                )
            })?;
        let materialization_tree = self.historical_root_span_tree(&parsed).unwrap_or(parsed);
        self.materialize_with_tree(&materialization_tree, Some(source_text))
    }

    fn historical_root_span_tree(&self, current: &SyntaxTree) -> Option<SyntaxTree> {
        if current.span.end_column == 1 {
            return None;
        }
        let completed = self.events.last()?;
        if completed.kind != ParseEventKind::ParseCompleted
            || completed.payload_kind.as_deref() != Some("syntax_tree")
        {
            return None;
        }

        let mut historical_span = current.span.clone();
        historical_span.end_column = 1;
        if completed.span.as_ref() != Some(&historical_span) {
            return None;
        }

        let mut historical_tree = current.clone();
        historical_tree.span = historical_span;
        let historical_hash = historical_tree.canonical_hash();
        (completed.payload_hash.as_deref() == Some(historical_hash.as_str()))
            .then_some(historical_tree)
    }

    /// Materialize a deterministic AST witness from this event stream and a canonical AST.
    pub fn materialize_from_syntax_tree(
        &self,
        tree: &SyntaxTree,
    ) -> ParseEventMaterializationResult<MaterializedSyntaxTree> {
        self.materialize_with_tree(tree, None)
    }

    fn materialize_with_tree(
        &self,
        tree: &SyntaxTree,
        source_text: Option<&str>,
    ) -> ParseEventMaterializationResult<MaterializedSyntaxTree> {
        if self.contract_version != Self::contract_version() {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::UnsupportedContractVersion,
                format!(
                    "unsupported event-ir contract version: {}",
                    self.contract_version
                ),
                None,
            ));
        }
        if self.schema_version != Self::schema_version() {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::UnsupportedSchemaVersion,
                format!(
                    "unsupported event-ir schema version: {}",
                    self.schema_version
                ),
                None,
            ));
        }
        if self.events.is_empty() {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::MissingParseStarted,
                "event stream is empty".to_string(),
                None,
            ));
        }
        if self.goal != tree.goal {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::GoalMismatch,
                format!(
                    "materializer goal mismatch: event_ir={} syntax_tree={}",
                    self.goal.as_str(),
                    tree.goal.as_str()
                ),
                None,
            ));
        }
        if self
            .events
            .iter()
            .any(|event| matches!(event.kind, ParseEventKind::ParseFailed))
        {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::ParseFailedEventStream,
                "cannot materialize AST from a failed parse event stream".to_string(),
                None,
            ));
        }

        for (expected_sequence, event) in self.events.iter().enumerate() {
            let expected_sequence = expected_sequence as u64;
            if event.sequence != expected_sequence {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::InvalidEventSequence,
                    format!(
                        "non-gap-free event sequence: expected {} got {}",
                        expected_sequence, event.sequence
                    ),
                    Some(event.sequence),
                ));
            }
        }

        let started = self.events.first().ok_or_else(|| {
            ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::MissingParseStarted,
                "event stream is empty".to_string(),
                None,
            )
        })?;
        if started.kind != ParseEventKind::ParseStarted || started.sequence != 0 {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::MissingParseStarted,
                "first event must be parse_started at sequence 0".to_string(),
                Some(started.sequence),
            ));
        }
        let completed = self.events.last().ok_or_else(|| {
            ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::MissingParseCompleted,
                "event stream is empty".to_string(),
                None,
            )
        })?;
        if completed.kind != ParseEventKind::ParseCompleted {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::MissingParseCompleted,
                "final event must be parse_completed".to_string(),
                Some(completed.sequence),
            ));
        }

        let trace_id = started.trace_id.clone();
        let decision_id = started.decision_id.clone();
        let policy_id = started.policy_id.clone();
        let component = started.component.clone();

        for event in &self.events {
            if event.trace_id != trace_id
                || event.decision_id != decision_id
                || event.policy_id != policy_id
                || event.component != component
                || event.parser_mode != self.parser_mode
                || event.goal != self.goal
                || event.source_label != self.source_label
            {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
                    format!("inconsistent event envelope at sequence {}", event.sequence),
                    Some(event.sequence),
                ));
            }
        }

        let tree_hash = tree.canonical_hash();
        if let Some(payload_kind) = started.payload_kind.as_deref() {
            match payload_kind {
                "source_text" => {
                    if let Some(source_text) = source_text {
                        let source_hash = canonical_string_hash(source_text);
                        if started.payload_hash.as_deref() != Some(source_hash.as_str()) {
                            return Err(ParseEventMaterializationError::new(
                                ParseEventMaterializationErrorCode::SourceHashMismatch,
                                "parse_started payload_hash does not match source_text canonical hash"
                                    .to_string(),
                                Some(started.sequence),
                            ));
                        }
                    }
                }
                "syntax_tree" => {
                    if started.payload_hash.as_deref() != Some(tree_hash.as_str()) {
                        return Err(ParseEventMaterializationError::new(
                            ParseEventMaterializationErrorCode::AstHashMismatch,
                            "parse_started payload_hash does not match syntax_tree canonical hash"
                                .to_string(),
                            Some(started.sequence),
                        ));
                    }
                }
                other => {
                    return Err(ParseEventMaterializationError::new(
                        ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
                        format!("unsupported parse_started payload_kind: {other}"),
                        Some(started.sequence),
                    ));
                }
            }
        }

        let statement_events: Vec<&ParseEvent> = self
            .events
            .iter()
            .filter(|event| event.kind == ParseEventKind::StatementParsed)
            .collect();
        if statement_events.len() != tree.body.len() {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::StatementCountMismatch,
                format!(
                    "statement event count mismatch: events={} syntax_tree={}",
                    statement_events.len(),
                    tree.body.len()
                ),
                None,
            ));
        }

        let mut statement_nodes = Vec::with_capacity(statement_events.len());
        for (expected_idx, (event, statement)) in
            statement_events.iter().zip(tree.body.iter()).enumerate()
        {
            let expected_idx_u64 = expected_idx as u64;
            if event.statement_index != Some(expected_idx_u64) {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::StatementIndexMismatch,
                    format!(
                        "statement index mismatch at sequence {}: expected {} got {:?}",
                        event.sequence, expected_idx_u64, event.statement_index
                    ),
                    Some(event.sequence),
                ));
            }
            let expected_kind = statement_kind_label(statement);
            if event.payload_kind.as_deref() != Some(expected_kind) {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::StatementKindMismatch,
                    format!(
                        "statement payload kind mismatch at sequence {}: expected {} got {:?}",
                        event.sequence, expected_kind, event.payload_kind
                    ),
                    Some(event.sequence),
                ));
            }
            let expected_hash = canonical_value_hash(&statement.canonical_value());
            if event.payload_hash.as_deref() != Some(expected_hash.as_str()) {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::StatementHashMismatch,
                    format!(
                        "statement payload hash mismatch at sequence {}",
                        event.sequence
                    ),
                    Some(event.sequence),
                ));
            }
            if event.span.as_ref() != Some(statement.span()) {
                return Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::StatementSpanMismatch,
                    format!("statement span mismatch at sequence {}", event.sequence),
                    Some(event.sequence),
                ));
            }

            let node_id = parse_event_ast_node_id(
                &trace_id,
                &decision_id,
                event.sequence,
                event.payload_hash.as_deref(),
            );
            statement_nodes.push(MaterializedStatementNode {
                node_id,
                sequence: event.sequence,
                statement_index: expected_idx_u64,
                payload_hash: expected_hash,
                span: statement.span().clone(),
            });
        }

        if completed.payload_kind.as_deref() != Some("syntax_tree") {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
                "parse_completed payload_kind must be syntax_tree".to_string(),
                Some(completed.sequence),
            ));
        }
        if completed.payload_hash.as_deref() != Some(tree_hash.as_str()) {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::AstHashMismatch,
                "parse_completed payload_hash does not match syntax_tree canonical hash"
                    .to_string(),
                Some(completed.sequence),
            ));
        }
        if completed.span.as_ref() != Some(&tree.span) {
            return Err(ParseEventMaterializationError::new(
                ParseEventMaterializationErrorCode::StatementSpanMismatch,
                "parse_completed span does not match syntax_tree span".to_string(),
                Some(completed.sequence),
            ));
        }

        let root_node_id = parse_event_ast_node_id(
            &trace_id,
            &decision_id,
            completed.sequence,
            completed.payload_hash.as_deref(),
        );
        Ok(MaterializedSyntaxTree {
            schema_version: MaterializedSyntaxTree::schema_version().to_string(),
            contract_version: MaterializedSyntaxTree::contract_version().to_string(),
            trace_id,
            decision_id,
            policy_id,
            component,
            parser_mode: self.parser_mode,
            goal: self.goal,
            source_label: self.source_label.clone(),
            root_node_id,
            statement_nodes,
            syntax_tree: tree.clone(),
        })
    }
}

pub type ParseEventMaterializationResult<T> = Result<T, ParseEventMaterializationError>;

/// Stable materialization failure codes for event->AST replay lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseEventMaterializationErrorCode {
    UnsupportedContractVersion,
    UnsupportedSchemaVersion,
    ParseFailedEventStream,
    MissingParseStarted,
    MissingParseCompleted,
    InvalidEventSequence,
    InconsistentEventEnvelope,
    GoalMismatch,
    ModeMismatch,
    StatementCountMismatch,
    StatementIndexMismatch,
    StatementKindMismatch,
    StatementHashMismatch,
    StatementSpanMismatch,
    SourceHashMismatch,
    AstHashMismatch,
    SourceParseFailed,
}

impl ParseEventMaterializationErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedContractVersion => "unsupported_contract_version",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::ParseFailedEventStream => "parse_failed_event_stream",
            Self::MissingParseStarted => "missing_parse_started",
            Self::MissingParseCompleted => "missing_parse_completed",
            Self::InvalidEventSequence => "invalid_event_sequence",
            Self::InconsistentEventEnvelope => "inconsistent_event_envelope",
            Self::GoalMismatch => "goal_mismatch",
            Self::ModeMismatch => "mode_mismatch",
            Self::StatementCountMismatch => "statement_count_mismatch",
            Self::StatementIndexMismatch => "statement_index_mismatch",
            Self::StatementKindMismatch => "statement_kind_mismatch",
            Self::StatementHashMismatch => "statement_hash_mismatch",
            Self::StatementSpanMismatch => "statement_span_mismatch",
            Self::SourceHashMismatch => "source_hash_mismatch",
            Self::AstHashMismatch => "ast_hash_mismatch",
            Self::SourceParseFailed => "source_parse_failed",
        }
    }
}

/// Deterministic materializer failure with stable code + message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseEventMaterializationError {
    pub code: ParseEventMaterializationErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

impl ParseEventMaterializationError {
    fn new(
        code: ParseEventMaterializationErrorCode,
        message: String,
        sequence: Option<u64>,
    ) -> Self {
        Self {
            code,
            message,
            sequence,
        }
    }
}

impl fmt::Display for ParseEventMaterializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(sequence) = self.sequence {
            write!(
                f,
                "{} (sequence={}): {}",
                self.code.as_str(),
                sequence,
                self.message
            )
        } else {
            write!(f, "{}: {}", self.code.as_str(), self.message)
        }
    }
}

impl std::error::Error for ParseEventMaterializationError {}

/// Stable statement-node witness emitted by the deterministic AST materializer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedStatementNode {
    pub node_id: String,
    pub sequence: u64,
    pub statement_index: u64,
    pub payload_hash: String,
    pub span: SourceSpan,
}

impl MaterializedStatementNode {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "node_id".to_string(),
            CanonicalValue::String(self.node_id.clone()),
        );
        map.insert("sequence".to_string(), CanonicalValue::U64(self.sequence));
        map.insert(
            "statement_index".to_string(),
            CanonicalValue::U64(self.statement_index),
        );
        map.insert(
            "payload_hash".to_string(),
            CanonicalValue::String(self.payload_hash.clone()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

/// Deterministic AST materialization output projected from Parse Event IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedSyntaxTree {
    pub schema_version: String,
    pub contract_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub parser_mode: ParserMode,
    pub goal: ParseGoal,
    pub source_label: String,
    pub root_node_id: String,
    pub statement_nodes: Vec<MaterializedStatementNode>,
    pub syntax_tree: SyntaxTree,
}

impl MaterializedSyntaxTree {
    pub const fn contract_version() -> &'static str {
        PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION
    }

    pub const fn schema_version() -> &'static str {
        PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "contract_version".to_string(),
            CanonicalValue::String(self.contract_version.clone()),
        );
        map.insert(
            "trace_id".to_string(),
            CanonicalValue::String(self.trace_id.clone()),
        );
        map.insert(
            "decision_id".to_string(),
            CanonicalValue::String(self.decision_id.clone()),
        );
        map.insert(
            "policy_id".to_string(),
            CanonicalValue::String(self.policy_id.clone()),
        );
        map.insert(
            "component".to_string(),
            CanonicalValue::String(self.component.clone()),
        );
        map.insert(
            "parser_mode".to_string(),
            CanonicalValue::String(self.parser_mode.as_str().to_string()),
        );
        map.insert(
            "goal".to_string(),
            CanonicalValue::String(self.goal.as_str().to_string()),
        );
        map.insert(
            "source_label".to_string(),
            CanonicalValue::String(self.source_label.clone()),
        );
        map.insert(
            "root_node_id".to_string(),
            CanonicalValue::String(self.root_node_id.clone()),
        );
        map.insert(
            "statement_nodes".to_string(),
            CanonicalValue::Array(
                self.statement_nodes
                    .iter()
                    .map(MaterializedStatementNode::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "syntax_tree".to_string(),
            self.syntax_tree.canonical_value(),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!(
            "{}{}",
            ParseEventIr::canonical_hash_prefix(),
            hex::encode(digest)
        )
    }
}

fn canonical_value_hash(value: &CanonicalValue) -> String {
    let digest = Sha256::digest(deterministic_serde::encode_value(value));
    format!("{PARSE_EVENT_IR_HASH_PREFIX}{}", hex::encode(digest))
}

fn canonical_string_hash(value: &str) -> String {
    canonical_value_hash(&CanonicalValue::String(value.to_string()))
}

fn parse_event_provenance_ids(
    source_label: &str,
    parser_mode: ParserMode,
    goal: ParseGoal,
    input_fingerprint: &str,
) -> (String, String) {
    let mut seed = BTreeMap::new();
    seed.insert(
        "source_label".to_string(),
        CanonicalValue::String(source_label.to_string()),
    );
    seed.insert(
        "parser_mode".to_string(),
        CanonicalValue::String(parser_mode.as_str().to_string()),
    );
    seed.insert(
        "goal".to_string(),
        CanonicalValue::String(goal.as_str().to_string()),
    );
    seed.insert(
        "input_fingerprint".to_string(),
        CanonicalValue::String(input_fingerprint.to_string()),
    );
    seed.insert(
        "policy_id".to_string(),
        CanonicalValue::String(PARSE_EVENT_IR_POLICY_ID.to_string()),
    );
    seed.insert(
        "component".to_string(),
        CanonicalValue::String(PARSE_EVENT_IR_COMPONENT.to_string()),
    );
    let digest = Sha256::digest(deterministic_serde::encode_value(&CanonicalValue::Map(
        seed,
    )));
    let digest_hex = hex::encode(digest);
    let suffix = &digest_hex[..24];
    (
        format!("{PARSE_EVENT_IR_TRACE_PREFIX}{suffix}"),
        format!("{PARSE_EVENT_IR_DECISION_PREFIX}{suffix}"),
    )
}

fn parse_event_ast_node_id(
    trace_id: &str,
    decision_id: &str,
    sequence: u64,
    payload_hash: Option<&str>,
) -> String {
    let mut seed = BTreeMap::new();
    seed.insert(
        "trace_id".to_string(),
        CanonicalValue::String(trace_id.to_string()),
    );
    seed.insert(
        "decision_id".to_string(),
        CanonicalValue::String(decision_id.to_string()),
    );
    seed.insert("sequence".to_string(), CanonicalValue::U64(sequence));
    seed.insert(
        "payload_hash".to_string(),
        payload_hash
            .map(|hash| CanonicalValue::String(hash.to_string()))
            .unwrap_or(CanonicalValue::Null),
    );
    let digest = Sha256::digest(deterministic_serde::encode_value(&CanonicalValue::Map(
        seed,
    )));
    let digest_hex = hex::encode(digest);
    let suffix = &digest_hex[..24];
    format!("{PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX}{suffix}")
}

fn statement_kind_label(statement: &Statement) -> &'static str {
    match statement {
        Statement::Import(_) => "import",
        Statement::Export(_) => "export",
        Statement::VariableDeclaration(_) => "variable_declaration",
        Statement::Expression(_) => "expression",
        Statement::Block(_) => "block",
        Statement::If(_) => "if",
        Statement::For(_) => "for",
        Statement::While(_) => "while",
        Statement::DoWhile(_) => "do_while",
        Statement::Return(_) => "return",
        Statement::Throw(_) => "throw",
        Statement::TryCatch(_) => "try_catch",
        Statement::Switch(_) => "switch",
        Statement::Break(_) => "break",
        Statement::Continue(_) => "continue",
        Statement::FunctionDeclaration(_) => "function_declaration",
        Statement::ClassDeclaration(_) => "class_declaration",
        Statement::ForIn(_) => "for_in",
        Statement::ForOf(_) => "for_of",
        Statement::Labeled(_) => "labeled",
    }
}

impl GrammarCompletenessMatrix {
    pub const SCHEMA_VERSION: &'static str = "franken-engine.parser-grammar-completeness.v1";

    pub fn scalar_reference_es2020() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            parser_mode: ParserMode::ScalarReference,
            families: vec![
                GrammarFamilyCoverage {
                    family_id: "program.statement_list".to_string(),
                    es2020_clause: "ECMA-262 §14.2".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Line/semicolon segmented statement list is deterministic.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "statement.expression".to_string(),
                    es2020_clause: "ECMA-262 §14.5".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Expression statements are canonicalized with stable whitespace handling."
                        .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "literal.numeric_signed_i64".to_string(),
                    es2020_clause: "ECMA-262 §12.8.3".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes:
                        "Deterministic signed i64 literals include decimal/hex/octal/binary forms."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "literal.string_single_double_quote".to_string(),
                    es2020_clause: "ECMA-262 §12.8.4".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Single/double quoted literals are parsed deterministically.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "literal.boolean".to_string(),
                    es2020_clause: "ECMA-262 §12.9.3".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "true/false recognized as dedicated literals.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "literal.null".to_string(),
                    es2020_clause: "ECMA-262 §12.9.4".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "null recognized as dedicated literal.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "literal.undefined".to_string(),
                    es2020_clause: "ECMA-262 §18.1.3 / §12.1".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "undefined is an IdentifierReference; lowering resolves lexical shadowing before folding the immutable global value."
                        .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.await".to_string(),
                    es2020_clause: "ECMA-262 §14.8".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Prefix await expression is parsed recursively with stable AST output."
                        .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "module.import_default".to_string(),
                    es2020_clause: "ECMA-262 §15.2.2".to_string(),
                    script_goal: GrammarCoverageStatus::NotApplicable,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Supports `import x from \"m\"`.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "module.import_side_effect".to_string(),
                    es2020_clause: "ECMA-262 §15.2.2".to_string(),
                    script_goal: GrammarCoverageStatus::NotApplicable,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Supports `import \"m\"`.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "module.import_named_namespace".to_string(),
                    es2020_clause: "ECMA-262 §15.2.2".to_string(),
                    script_goal: GrammarCoverageStatus::NotApplicable,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes:
                        "Supports named (`{ a, b as c }`), namespace (`* as ns`), and mixed default+named/namespace import clauses with deterministic binding projection."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "module.export_default".to_string(),
                    es2020_clause: "ECMA-262 §15.2.3".to_string(),
                    script_goal: GrammarCoverageStatus::NotApplicable,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Supports `export default <expr>`.".to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "module.export_named_clause".to_string(),
                    es2020_clause: "ECMA-262 §15.2.3".to_string(),
                    script_goal: GrammarCoverageStatus::NotApplicable,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes:
                        "Supports `export { ... }` and `export { ... } from \"m\"` with deterministic clause validation."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "statement.variable_declaration".to_string(),
                    es2020_clause: "ECMA-262 §14.3".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes:
                        "Supports `var`/`let`/`const` declarations including destructuring bindings."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "statement.function_declaration".to_string(),
                    es2020_clause: "ECMA-262 §14.1".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Function declarations with async/generator flags, params, and body."
                        .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.binary_precedence".to_string(),
                    es2020_clause: "ECMA-262 §13.15".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Full precedence scanning for 25 binary operators."
                        .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.call_member_chain".to_string(),
                    es2020_clause: "ECMA-262 §13.3".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Call expressions, dot member access, computed member access."
                        .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.object_array_literal".to_string(),
                    es2020_clause: "ECMA-262 §13.2".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "Array literals with holes, object literals with shorthand."
                        .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.template_literal".to_string(),
                    es2020_clause: "ECMA-262 §13.2.8".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes:
                        "Template literals with interpolation and tagged forms are parsed into deterministic scaffold expressions."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "expression.arrow_function".to_string(),
                    es2020_clause: "ECMA-262 §14.2".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes:
                        "Arrow functions support async/sync forms and binding-pattern parameters."
                            .to_string(),
                },
                GrammarFamilyCoverage {
                    family_id: "statement.control_flow".to_string(),
                    es2020_clause: "ECMA-262 §14".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "if/else, for, while, do-while, switch/case, try/catch/finally, break, continue, return, throw."
                        .to_string(),
                },
            ],
        }
    }

    pub fn summary(&self) -> GrammarCompletenessSummary {
        let mut supported = 0u64;
        let mut partial = 0u64;
        let mut unsupported = 0u64;
        let mut score = 0u64;

        for family in &self.families {
            let family_score =
                (family.script_goal.score_numer() + family.module_goal.score_numer()) / 2;
            score = score.saturating_add(family_score);

            if family_score == 1000 {
                supported = supported.saturating_add(1);
            } else if family_score == 0 {
                unsupported = unsupported.saturating_add(1);
            } else {
                partial = partial.saturating_add(1);
            }
        }

        let family_count = self.families.len() as u64;
        let completeness_millionths = if family_count == 0 {
            0
        } else {
            score.saturating_mul(1_000_000) / family_count.saturating_mul(1000)
        };

        GrammarCompletenessSummary {
            family_count,
            supported_families: supported,
            partially_supported_families: partial,
            unsupported_families: unsupported,
            completeness_millionths,
        }
    }
}

/// Concrete source text resolved from a parser input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserSource {
    pub label: String,
    pub text: String,
}

/// Input adapter trait: parse from strings, files, or stream wrappers.
pub trait ParserInput {
    fn into_source(self) -> ParseResult<ParserSource>;
}

impl ParserInput for &str {
    fn into_source(self) -> ParseResult<ParserSource> {
        Ok(ParserSource {
            label: "<inline>".to_string(),
            text: self.to_string(),
        })
    }
}

impl ParserInput for String {
    fn into_source(self) -> ParseResult<ParserSource> {
        Ok(ParserSource {
            label: "<inline>".to_string(),
            text: self,
        })
    }
}

impl ParserInput for ParserSource {
    fn into_source(self) -> ParseResult<ParserSource> {
        Ok(self)
    }
}

impl ParserInput for &Path {
    fn into_source(self) -> ParseResult<ParserSource> {
        let text = fs::read_to_string(self).map_err(|error| {
            ParseError::new(
                ParseErrorCode::IoReadFailed,
                format!("failed to read source file: {error}"),
                self.display().to_string(),
                None,
            )
        })?;
        Ok(ParserSource {
            label: self.display().to_string(),
            text,
        })
    }
}

impl ParserInput for PathBuf {
    fn into_source(self) -> ParseResult<ParserSource> {
        self.as_path().into_source()
    }
}

/// Stream-backed parser input wrapper.
#[derive(Debug)]
pub struct StreamInput<R> {
    label: String,
    reader: R,
}

impl<R> StreamInput<R> {
    pub fn new(reader: R, label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            reader,
        }
    }
}

impl<R> ParserInput for StreamInput<R>
where
    R: Read,
{
    fn into_source(mut self) -> ParseResult<ParserSource> {
        let mut bytes = Vec::new();
        self.reader.read_to_end(&mut bytes).map_err(|error| {
            ParseError::new(
                ParseErrorCode::IoReadFailed,
                format!("failed to read source stream: {error}"),
                self.label.clone(),
                None,
            )
        })?;
        let text = String::from_utf8(bytes).map_err(|error| {
            ParseError::new(
                ParseErrorCode::InvalidUtf8,
                format!("stream contains invalid UTF-8: {error}"),
                self.label.clone(),
                None,
            )
        })?;
        Ok(ParserSource {
            label: self.label,
            text,
        })
    }
}

/// Parser trait for ES2020 script/module goals.
pub trait Es2020Parser {
    fn parse<I>(&self, input: I, goal: ParseGoal) -> ParseResult<SyntaxTree>
    where
        I: ParserInput;
}

/// Deterministic parser implementation used by current VM-core scaffolding.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanonicalEs2020Parser;

impl CanonicalEs2020Parser {
    pub fn parse_with_options<I>(
        &self,
        input: I,
        goal: ParseGoal,
        options: &ParserOptions,
    ) -> ParseResult<SyntaxTree>
    where
        I: ParserInput,
    {
        let (result, _event_ir) = self.parse_with_event_ir(input, goal, options);
        result
    }

    /// Parse input while emitting a deterministic Parse Event IR stream.
    ///
    /// This method always returns a Parse Event IR value, including when parsing
    /// fails, so callers can persist replay-ready provenance for diagnostics.
    pub fn parse_with_event_ir<I>(
        &self,
        input: I,
        goal: ParseGoal,
        options: &ParserOptions,
    ) -> (ParseResult<SyntaxTree>, ParseEventIr)
    where
        I: ParserInput,
    {
        match input.into_source() {
            // Tree AND event-IR construction share one provisioned stack:
            // the event-IR builder recurses over the tree with the same
            // depth profile as the descent (bd-47ae4).
            Ok(source) => with_provisioned_parse_stack(options, || {
                match parse_source_on_current_stack(&source.text, &source.label, goal, options) {
                    Ok(tree) => {
                        let event_ir = ParseEventIr::from_parse_source(
                            &tree,
                            &source.text,
                            source.label,
                            options.mode,
                        );
                        (Ok(tree), event_ir)
                    }
                    Err(error) => {
                        let event_ir = ParseEventIr::from_parse_error(&error, goal, options.mode);
                        (Err(error), event_ir)
                    }
                }
            }),
            Err(error) => {
                let event_ir = ParseEventIr::from_parse_error(&error, goal, options.mode);
                (Err(error), event_ir)
            }
        }
    }

    /// Parse input, emit deterministic event IR, and materialize deterministic AST node witnesses.
    pub fn parse_with_materialized_ast<I>(
        &self,
        input: I,
        goal: ParseGoal,
        options: &ParserOptions,
    ) -> (
        ParseResult<SyntaxTree>,
        ParseEventIr,
        ParseEventMaterializationResult<MaterializedSyntaxTree>,
    )
    where
        I: ParserInput,
    {
        match input.into_source() {
            // Tree, event-IR, and witness materialization share one
            // provisioned stack: both walkers recurse over the tree with the
            // same depth profile as the descent (bd-47ae4).
            Ok(source) => with_provisioned_parse_stack(options, || {
                match parse_source_on_current_stack(&source.text, &source.label, goal, options) {
                    Ok(tree) => {
                        let event_ir = ParseEventIr::from_parse_source(
                            &tree,
                            &source.text,
                            source.label.clone(),
                            options.mode,
                        );
                        let materialized =
                            event_ir.materialize_with_tree(&tree, Some(&source.text));
                        (Ok(tree), event_ir, materialized)
                    }
                    Err(error) => {
                        let event_ir = ParseEventIr::from_parse_error(&error, goal, options.mode);
                        let materialized = Err(ParseEventMaterializationError::new(
                            ParseEventMaterializationErrorCode::ParseFailedEventStream,
                            "cannot materialize AST for failed parse".to_string(),
                            None,
                        ));
                        (Err(error), event_ir, materialized)
                    }
                }
            }),
            Err(error) => {
                let event_ir = ParseEventIr::from_parse_error(&error, goal, options.mode);
                let materialized = Err(ParseEventMaterializationError::new(
                    ParseEventMaterializationErrorCode::ParseFailedEventStream,
                    "cannot materialize AST for failed parse".to_string(),
                    None,
                ));
                (Err(error), event_ir, materialized)
            }
        }
    }

    pub fn scalar_reference_grammar_matrix(&self) -> GrammarCompletenessMatrix {
        GrammarCompletenessMatrix::scalar_reference_es2020()
    }
}

impl Es2020Parser for CanonicalEs2020Parser {
    fn parse<I>(&self, input: I, goal: ParseGoal) -> ParseResult<SyntaxTree>
    where
        I: ParserInput,
    {
        self.parse_with_options(input, goal, &ParserOptions::default())
    }
}

#[derive(Debug)]
struct ParseExecutionContext<'a> {
    source_label: &'a str,
    options: &'a ParserOptions,
    goal: ParseGoal,
    strict_mode: bool,
    await_identifier_reserved: bool,
    yield_identifier_reserved: bool,
    allow_await_expression: bool,
    allow_yield_expression: bool,
    source_bytes: u64,
    token_count: u64,
    max_recursion_observed: u64,
    /// Current statement nesting depth (if/for/while/try/switch/function bodies).
    /// Guards against stack overflow from deeply nested statements.
    statement_depth: u64,
    /// Current binding-pattern nesting depth (destructuring: `[[[...]]]`,
    /// `{a:{b:{c:...}}}`). This recursive descent is separate from the
    /// statement and expression guards, so it needs its own bounded owner.
    pattern_depth: u64,
}

/// The lexical meaning of a contextual keyword while a delimiter scan is in
/// progress.  A scanner needs three states rather than a boolean: ordinary
/// functions treat `await`/`yield` as identifiers, async/generator parameter
/// lists reserve them without permitting expressions, and the corresponding
/// function bodies enable the prefix-expression grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextualKeywordScanMode {
    Identifier,
    Reserved,
    PrefixExpression,
}

/// The grammar parameters needed by lexical-goal scans.  Keep this private and
/// deliberately smaller than `ParseExecutionContext`: delimiter discovery must
/// not acquire parser budgets, diagnostics, or source ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScanGrammarContext {
    strict: bool,
    starts_in_statement_position: bool,
    await_mode: ContextualKeywordScanMode,
    yield_mode: ContextualKeywordScanMode,
}

impl ScanGrammarContext {
    const SLOPPY_SCRIPT: Self = Self {
        strict: false,
        starts_in_statement_position: true,
        await_mode: ContextualKeywordScanMode::Identifier,
        yield_mode: ContextualKeywordScanMode::Identifier,
    };

    const STRICT_SCRIPT: Self = Self {
        strict: true,
        starts_in_statement_position: true,
        await_mode: ContextualKeywordScanMode::Identifier,
        yield_mode: ContextualKeywordScanMode::Reserved,
    };

    fn from_execution_context(context: &ParseExecutionContext<'_>) -> Self {
        Self {
            strict: context.strict_mode,
            starts_in_statement_position: true,
            await_mode: if context.allow_await_expression {
                ContextualKeywordScanMode::PrefixExpression
            } else if context.await_identifier_reserved {
                ContextualKeywordScanMode::Reserved
            } else {
                ContextualKeywordScanMode::Identifier
            },
            yield_mode: if context.allow_yield_expression {
                ContextualKeywordScanMode::PrefixExpression
            } else if context.yield_identifier_reserved || context.strict_mode {
                ContextualKeywordScanMode::Reserved
            } else {
                ContextualKeywordScanMode::Identifier
            },
        }
    }

    const fn expression(mut self) -> Self {
        self.starts_in_statement_position = false;
        self
    }

    const fn function_parameters(is_async: bool, is_generator: bool, strict: bool) -> Self {
        Self {
            strict,
            starts_in_statement_position: false,
            await_mode: if is_async {
                ContextualKeywordScanMode::Reserved
            } else {
                ContextualKeywordScanMode::Identifier
            },
            yield_mode: if is_generator || strict {
                ContextualKeywordScanMode::Reserved
            } else {
                ContextualKeywordScanMode::Identifier
            },
        }
    }

    const fn function_body(is_async: bool, is_generator: bool, strict: bool) -> Self {
        Self {
            strict,
            starts_in_statement_position: true,
            await_mode: if is_async {
                ContextualKeywordScanMode::PrefixExpression
            } else {
                ContextualKeywordScanMode::Identifier
            },
            yield_mode: if is_generator {
                ContextualKeywordScanMode::PrefixExpression
            } else if strict {
                ContextualKeywordScanMode::Reserved
            } else {
                ContextualKeywordScanMode::Identifier
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlashGoal {
    RegExp,
    Div,
}

impl<'a> ParseExecutionContext<'a> {
    fn next_depth(&mut self, depth: u64) {
        if depth > self.max_recursion_observed {
            self.max_recursion_observed = depth;
        }
    }

    fn witness(&self, budget_kind: Option<ParseBudgetKind>) -> ParseFailureWitness {
        ParseFailureWitness {
            mode: self.options.mode,
            budget_kind,
            source_bytes: self.source_bytes,
            token_count: self.token_count,
            max_recursion_observed: self.max_recursion_observed,
            max_source_bytes: self.options.budget.max_source_bytes,
            max_token_count: self.options.budget.max_token_count,
            max_recursion_depth: self.options.budget.max_recursion_depth,
        }
    }
}

fn with_grammar_context<'a, T>(
    context: &mut ParseExecutionContext<'a>,
    strict_mode: bool,
    await_identifier_reserved: bool,
    yield_identifier_reserved: bool,
    allow_await_expression: bool,
    allow_yield_expression: bool,
    parse: impl FnOnce(&mut ParseExecutionContext<'a>) -> ParseResult<T>,
) -> ParseResult<T> {
    let previous = (
        context.strict_mode,
        context.await_identifier_reserved,
        context.yield_identifier_reserved,
        context.allow_await_expression,
        context.allow_yield_expression,
    );
    context.strict_mode = strict_mode;
    context.await_identifier_reserved = await_identifier_reserved;
    context.yield_identifier_reserved = yield_identifier_reserved;
    context.allow_await_expression = allow_await_expression;
    context.allow_yield_expression = allow_yield_expression;
    let result = parse(context);
    context.strict_mode = previous.0;
    context.await_identifier_reserved = previous.1;
    context.yield_identifier_reserved = previous.2;
    context.allow_await_expression = previous.3;
    context.allow_yield_expression = previous.4;
    result
}

/// A logical line that may span multiple physical lines (for block statements).
struct LogicalLine {
    text: String,
    byte_offset: u64,
    start_line: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    end_line: u64,
}

fn merge_logical_lines_identifier_opens_control_header(identifier: &str) -> bool {
    matches!(
        identifier,
        "catch" | "for" | "if" | "switch" | "while" | "with"
    )
}

fn merge_logical_lines_identifier_awaits_statement(identifier: &str) -> bool {
    matches!(identifier, "catch" | "do" | "else" | "finally" | "try")
}

fn merge_logical_lines_update_is_prefix(
    last_significant: Option<char>,
    trailing_identifier: &str,
    trailing_identifier_is_member: bool,
    grammar_context: ScanGrammarContext,
) -> bool {
    match last_significant {
        None => true,
        Some(
            '(' | '{' | '[' | ',' | ';' | ':' | '=' | '!' | '?' | '&' | '|' | '^' | '~' | '*' | '%'
            | '+' | '-' | '<' | '>' | '/',
        ) => true,
        Some(ch) if ch.is_ascii_alphabetic() || ch == '_' || ch == '$' => {
            identifier_slash_goal(
                trailing_identifier,
                trailing_identifier_is_member,
                grammar_context,
            )
            .0 == SlashGoal::RegExp
        }
        _ => false,
    }
}

fn statement_clause_continues(statement: &str, following: &str) -> bool {
    (starts_with_keyword(statement, "if") && starts_with_keyword(following, "else"))
        || (starts_with_keyword(statement, "do") && starts_with_keyword(following, "while"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingClauseKind {
    IfAwaitElse,
    ElseAwaitStatement,
    ElseExpressionContinuation,
    ElseDeclarationContinuation,
    ElseIfAwaitBody,
    ElseIfExpressionContinuation,
    ElseIfDeclarationContinuation,
    TryAwaitHandler,
    CatchAwaitParameter,
    CatchAwaitBody,
    CatchAwaitFinally,
    FinallyAwaitBody,
    DoAwaitWhile,
    DoWhileAwaitCondition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingClauseContinuation {
    kind: PendingClauseKind,
    fragment_start: usize,
    deferred_statement_owner: Option<Arc<PendingStatementOwner>>,
    owner_stack_complete: bool,
    declaration_initializer_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingStatementOwner {
    kind: PendingStatementClauseKind,
    parent: Option<Arc<Self>>,
}

struct DirectStatementOwnerStack<'a> {
    body: &'a str,
    owners: Option<Arc<PendingStatementOwner>>,
    owner_count: usize,
    statement_depth: usize,
    saw_if_owner: bool,
}

fn push_pending_statement_owner(
    owners: Option<Arc<PendingStatementOwner>>,
    kind: PendingStatementClauseKind,
) -> Arc<PendingStatementOwner> {
    Arc::new(PendingStatementOwner {
        kind,
        parent: owners,
    })
}

fn push_pending_statement_owners(
    mut owners: Option<Arc<PendingStatementOwner>>,
    kind: PendingStatementClauseKind,
    count: usize,
) -> Option<Arc<PendingStatementOwner>> {
    for _ in 0..count {
        owners = Some(push_pending_statement_owner(owners, kind));
    }
    owners
}

fn direct_statement_owner_stack<'a>(
    statement: &'a str,
    base_owner: Option<Arc<PendingStatementOwner>>,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
) -> Option<DirectStatementOwnerStack<'a>> {
    let mut body = trim_binding_pattern_trivia_with_context(statement, grammar_context)?;
    let mut owners = base_owner;
    let mut owner_count = 0usize;
    let mut statement_depth = 0usize;
    let mut saw_if_owner = false;
    loop {
        if starts_with_keyword(body, "do") {
            owners = Some(push_pending_statement_owner(
                owners,
                PendingStatementClauseKind::DoWhile,
            ));
            owner_count = owner_count.saturating_add(1);
            statement_depth = statement_depth.saturating_add(1);
            if statement_depth >= completion_recursion_limit {
                return None;
            }
            let next_body = clause_keyword_tail(body, "do", grammar_context)?;
            body = next_body;
            continue;
        }
        let Some(wrapper) = ["if", "while", "for", "with"]
            .into_iter()
            .find(|keyword| starts_with_keyword(body, keyword))
        else {
            break;
        };
        statement_depth = statement_depth.saturating_add(1);
        if statement_depth >= completion_recursion_limit {
            return None;
        }
        let wrapper_tail = clause_keyword_tail(body, wrapper, grammar_context)?;
        let (_, next_body) =
            extract_balanced_with_context(wrapper_tail, '(', ')', grammar_context)?;
        let next_body = trim_binding_pattern_trivia_with_context(next_body, grammar_context)?;
        if wrapper == "if" {
            owners = Some(push_pending_statement_owner(
                owners,
                PendingStatementClauseKind::IfElse,
            ));
            owner_count = owner_count.saturating_add(1);
            saw_if_owner = true;
        }
        body = next_body;
    }

    Some(DirectStatementOwnerStack {
        body,
        owners,
        owner_count,
        statement_depth,
        saw_if_owner,
    })
}

fn direct_statement_owner_stack_with_complete_body(
    statement: &str,
    base_owner: Option<Arc<PendingStatementOwner>>,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
    completion_memo: &mut DoWhileCompletionMemo,
) -> Option<Arc<PendingStatementOwner>> {
    let DirectStatementOwnerStack {
        body,
        owners,
        owner_count,
        statement_depth,
        saw_if_owner,
    } = direct_statement_owner_stack(
        statement,
        base_owner,
        grammar_context,
        completion_recursion_limit,
    )?;
    if saw_if_owner
        && !find_top_level_keyword_indices_with_context(body, "else", grammar_context).is_empty()
    {
        return None;
    }
    let following = match owners.as_deref().map(|owner| owner.kind) {
        Some(PendingStatementClauseKind::IfElse) => "else",
        Some(PendingStatementClauseKind::DoWhile) => "while",
        Some(PendingStatementClauseKind::TryHandler | PendingStatementClauseKind::CatchFinally) => {
            return None;
        }
        None => return None,
    };
    (owner_count > 0
        && statement_is_complete_before_clause_with_limit(
            body,
            following,
            grammar_context,
            completion_recursion_limit.saturating_sub(statement_depth),
            completion_memo,
        ))
    .then_some(owners)
    .flatten()
}

fn pending_clause_from_owner_stack(
    mut owner: Option<Arc<PendingStatementOwner>>,
    following: &str,
    fragment_start: usize,
) -> Option<PendingClauseContinuation> {
    while let Some(current) = owner {
        let parent = current.parent.clone();
        match current.kind {
            PendingStatementClauseKind::IfElse => {
                if starts_with_keyword(following, "else") {
                    return Some(pending_clause_with_deferred_statement_owner(
                        PendingClauseKind::IfAwaitElse,
                        fragment_start,
                        parent,
                    ));
                }
                owner = parent;
            }
            PendingStatementClauseKind::DoWhile => {
                return starts_with_keyword(following, "while").then_some(
                    pending_clause_with_deferred_statement_owner(
                        PendingClauseKind::DoAwaitWhile,
                        fragment_start,
                        parent,
                    ),
                );
            }
            PendingStatementClauseKind::TryHandler | PendingStatementClauseKind::CatchFinally => {
                return None;
            }
        }
    }
    None
}

fn pending_clause_after_statement(
    statement: &str,
    following: &str,
    fragment_start: usize,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
    completion_memo: &mut DoWhileCompletionMemo,
) -> Option<PendingClauseContinuation> {
    if starts_with_keyword(statement, "try") {
        let pending = pending_clause_with_kind(PendingClauseKind::TryAwaitHandler, fragment_start);
        if let Some(continuation) = pending_clause_after_try_prefix(
            statement,
            following,
            fragment_start,
            pending,
            grammar_context,
        ) {
            return Some(continuation);
        }
    }
    if let Some(DirectStatementOwnerStack {
        body,
        owners,
        owner_count,
        ..
    }) =
        direct_statement_owner_stack(statement, None, grammar_context, completion_recursion_limit)
        && owner_count > 0
        && starts_with_keyword(body, "try")
    {
        let pending = pending_clause_with_deferred_statement_owner(
            PendingClauseKind::TryAwaitHandler,
            fragment_start,
            owners,
        );
        if let Some(continuation) = pending_clause_after_try_prefix(
            body,
            following,
            fragment_start,
            pending,
            grammar_context,
        ) {
            return Some(continuation);
        }
    }
    let direct_do_waits_for_following_while =
        starts_with_keyword(statement, "do") && starts_with_keyword(following, "while");
    if direct_do_waits_for_following_while
        && do_while_statement_is_complete_with_limit(
            statement,
            grammar_context,
            completion_recursion_limit,
            completion_memo,
        )
    {
        return None;
    }
    if let Some(owners) = direct_statement_owner_stack_with_complete_body(
        statement,
        None,
        grammar_context,
        completion_recursion_limit,
        completion_memo,
    ) && let Some(pending) =
        pending_clause_from_owner_stack(Some(owners), following, fragment_start)
    {
        return Some(pending);
    }
    if starts_with_keyword(statement, "if") && starts_with_keyword(following, "else") {
        return Some(pending_clause_with_kind(
            PendingClauseKind::IfAwaitElse,
            fragment_start,
        ));
    }
    if starts_with_keyword(statement, "do") && starts_with_keyword(following, "while") {
        let mut pending = pending_clause_with_kind(PendingClauseKind::DoAwaitWhile, fragment_start);
        pending.owner_stack_complete = false;
        return Some(pending);
    }
    advance_clause_statement(
        pending_clause_with_kind(PendingClauseKind::ElseAwaitStatement, fragment_start),
        statement,
        following,
        fragment_start,
        false,
        (grammar_context, completion_recursion_limit, completion_memo),
    )
}

fn clause_keyword_tail<'a>(
    source: &'a str,
    keyword: &str,
    grammar_context: ScanGrammarContext,
) -> Option<&'a str> {
    let source = trim_binding_pattern_leading_trivia_with_context(source, grammar_context)?;
    if !starts_with_keyword(source, keyword) {
        return None;
    }
    trim_binding_pattern_leading_trivia_with_context(source.strip_prefix(keyword)?, grammar_context)
}

fn balanced_block_tail(source: &str, grammar_context: ScanGrammarContext) -> Option<&str> {
    if !source.starts_with('{') {
        return None;
    }
    let (_, rest) = extract_balanced_with_context(source, '{', '}', grammar_context)?;
    trim_binding_pattern_trivia_with_context(rest, grammar_context)
}

fn catch_clause_tail_after_body(
    fragment: &str,
    grammar_context: ScanGrammarContext,
) -> Option<&str> {
    let after_catch = clause_keyword_tail(fragment, "catch", grammar_context)?;
    if after_catch.is_empty() {
        return None;
    }
    let body_source = if after_catch.starts_with('(') {
        let (_, remaining) = extract_balanced_with_context(after_catch, '(', ')', grammar_context)?;
        trim_binding_pattern_leading_trivia_with_context(remaining, grammar_context)
            .unwrap_or_default()
    } else {
        after_catch
    };
    balanced_block_tail(body_source, grammar_context)
}

fn finally_clause_tail_after_body(
    fragment: &str,
    grammar_context: ScanGrammarContext,
) -> Option<&str> {
    let body = clause_keyword_tail(fragment, "finally", grammar_context)?;
    balanced_block_tail(body, grammar_context)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParenthesizedStatementStatus {
    MissingCondition,
    MissingBody,
    Complete,
    Invalid,
}

fn parenthesized_statement_status(
    source: &str,
    keyword: &str,
    grammar_context: ScanGrammarContext,
) -> Option<ParenthesizedStatementStatus> {
    let tail = clause_keyword_tail(source, keyword, grammar_context)?;
    if tail.is_empty() {
        return Some(ParenthesizedStatementStatus::MissingCondition);
    }
    if !tail.starts_with('(') {
        return Some(ParenthesizedStatementStatus::Invalid);
    }
    let Some((_, body)) = extract_balanced_with_context(tail, '(', ')', grammar_context) else {
        return Some(ParenthesizedStatementStatus::Invalid);
    };
    let body =
        trim_binding_pattern_leading_trivia_with_context(body, grammar_context).unwrap_or_default();
    if body.is_empty() {
        Some(ParenthesizedStatementStatus::MissingBody)
    } else {
        Some(ParenthesizedStatementStatus::Complete)
    }
}

fn source_ends_expression_continuation(source: &str, grammar_context: ScanGrammarContext) -> bool {
    let Some(source) = trim_binding_pattern_trivia_with_context(source, grammar_context) else {
        return false;
    };
    let state =
        scan_binding_pattern_source_until_with_context(source, grammar_context, |_, _, _, _| true);
    if !state.complete {
        return false;
    }
    if !state.trailing_identifier_is_member
        && matches!(
            state.trailing_identifier.as_str(),
            "in" | "instanceof" | "typeof" | "void" | "delete" | "new"
        )
    {
        return true;
    }
    match state.last_significant {
        Some(
            '+' | '-' | '*' | '/' | '%' | '<' | '>' | '=' | '!' | '&' | '|' | '^' | '?' | ':' | ','
            | '~',
        ) => true,
        Some('.') => !source_ends_complete_decimal_dot(source),
        _ => false,
    }
}

fn source_ends_complete_decimal_dot(source: &str) -> bool {
    let Some(prefix) = source.strip_suffix('.') else {
        return false;
    };
    let token_start = prefix
        .char_indices()
        .rev()
        .find(|(_, ch)| !ch.is_ascii_digit() && *ch != '_')
        .map_or(0, |(index, ch)| index.saturating_add(ch.len_utf8()));
    if token_start > 0 {
        let preceding = prefix[..token_start].chars().next_back();
        if preceding.is_some_and(|ch| ch == '.' || is_identifier_part_character(ch))
            || signed_decimal_exponent_precedes(prefix, token_start)
        {
            return false;
        }
    }
    parse_f64_numeric_literal(&source[token_start..]).is_some()
}

fn signed_decimal_exponent_precedes(prefix: &str, trailing_digits_start: usize) -> bool {
    let Some(before_sign) = prefix.get(..trailing_digits_start) else {
        return false;
    };
    let Some(before_exponent_marker) = before_sign
        .strip_suffix('+')
        .or_else(|| before_sign.strip_suffix('-'))
        .and_then(|source| {
            source
                .strip_suffix('e')
                .or_else(|| source.strip_suffix('E'))
        })
    else {
        return false;
    };
    let mantissa_start = before_exponent_marker
        .char_indices()
        .rev()
        .find(|(_, ch)| !ch.is_ascii_digit() && *ch != '_' && *ch != '.')
        .map_or(0, |(index, ch)| index.saturating_add(ch.len_utf8()));
    if mantissa_start == before_exponent_marker.len()
        || (mantissa_start > 0
            && before_exponent_marker[..mantissa_start]
                .chars()
                .next_back()
                .is_some_and(is_identifier_part_character))
    {
        return false;
    }
    parse_f64_numeric_literal(&prefix[mantissa_start..]).is_some()
}

fn source_ends_postfix_update(source: &str, grammar_context: ScanGrammarContext) -> bool {
    let Some(source) = trim_binding_pattern_trivia_with_context(source, grammar_context) else {
        return false;
    };
    let state =
        scan_binding_pattern_source_until_with_context(source, grammar_context, |_, _, _, _| true);
    state.complete && state.ends_postfix_update
}

fn starts_postfix_expression_continuation(source: &str) -> bool {
    let source = source.trim_start_matches(is_binding_pattern_whitespace);
    is_optional_chaining_punctuator(source.as_bytes(), 0)
        || matches!(source.chars().next(), Some('(' | '[' | '.' | '`'))
}

fn is_optional_chaining_punctuator(bytes: &[u8], index: usize) -> bool {
    bytes.get(index) == Some(&b'?')
        && bytes.get(index + 1) == Some(&b'.')
        && !bytes.get(index + 2).is_some_and(u8::is_ascii_digit)
}

fn is_conditional_question_punctuator(bytes: &[u8], index: usize) -> bool {
    bytes.get(index) == Some(&b'?')
        && index
            .checked_sub(1)
            .and_then(|previous| bytes.get(previous))
            != Some(&b'?')
        && bytes.get(index + 1) != Some(&b'?')
        && !is_optional_chaining_punctuator(bytes, index)
}

fn restricted_statement_ends_at_line_terminator(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> bool {
    ["break", "continue"]
        .into_iter()
        .any(|keyword| clause_keyword_tail(source, keyword, grammar_context).is_some())
        || ["return", "throw"].into_iter().any(|keyword| {
            clause_keyword_tail(source, keyword, grammar_context).is_some_and(str::is_empty)
        })
}

fn expression_statement_continues(
    source: &str,
    next_after_trivia: &str,
    grammar_context: ScanGrammarContext,
) -> bool {
    if restricted_statement_ends_at_line_terminator(source, grammar_context)
        || (source_ends_postfix_update(source, grammar_context)
            && starts_postfix_expression_continuation(next_after_trivia))
    {
        return false;
    }
    source_ends_expression_continuation(source, grammar_context)
        || starts_directive_expression_continuation(next_after_trivia)
        || top_level_conditional_punctuation_balance(source, grammar_context)
            .is_some_and(|(unmatched_questions, _)| unmatched_questions > 0)
}

fn statement_allows_expression_continuation(
    statement: &str,
    grammar_context: ScanGrammarContext,
) -> bool {
    let Some(statement) = trim_binding_pattern_trivia_with_context(statement, grammar_context)
    else {
        return false;
    };
    if parse_variable_declaration_kind(statement).is_some()
        || starts_with_keyword(statement, "function")
        || starts_with_keyword(statement, "class")
        || strip_async_function_keyword(statement).is_some()
    {
        return false;
    }
    if let Some(import_tail) = clause_keyword_tail(statement, "import", grammar_context) {
        return import_tail.is_empty()
            || import_tail.starts_with('(')
            || import_tail.starts_with('.');
    }
    if let Some(export_tail) = clause_keyword_tail(statement, "export", grammar_context) {
        let Some(default_tail) = strip_contextual_keyword(export_tail, "default") else {
            return false;
        };
        return !starts_with_keyword(default_tail, "function")
            && !starts_with_keyword(default_tail, "class")
            && strip_async_function_keyword(default_tail).is_none();
    }
    true
}

fn pending_clause_with_kind(
    kind: PendingClauseKind,
    fragment_start: usize,
) -> PendingClauseContinuation {
    PendingClauseContinuation {
        kind,
        fragment_start,
        deferred_statement_owner: None,
        owner_stack_complete: true,
        declaration_initializer_active: false,
    }
}

fn pending_clause_with_deferred_statement_owner(
    kind: PendingClauseKind,
    fragment_start: usize,
    deferred_statement_owner: Option<Arc<PendingStatementOwner>>,
) -> PendingClauseContinuation {
    let mut pending = pending_clause_with_kind(kind, fragment_start);
    pending.deferred_statement_owner = deferred_statement_owner;
    pending
}

fn continue_pending_clause(
    kind: PendingClauseKind,
    fragment_start: usize,
    pending: &PendingClauseContinuation,
) -> PendingClauseContinuation {
    let mut continuation = pending_clause_with_deferred_statement_owner(
        kind,
        fragment_start,
        pending.deferred_statement_owner.clone(),
    );
    continuation.owner_stack_complete = pending.owner_stack_complete;
    continuation
}

fn defer_pending_if_owners(
    mut pending: PendingClauseContinuation,
    count: usize,
) -> PendingClauseContinuation {
    pending.deferred_statement_owner = push_pending_statement_owners(
        pending.deferred_statement_owner,
        PendingStatementClauseKind::IfElse,
        count,
    );
    pending
}

fn completed_clause_statement(
    await_else_after_completion: bool,
    next_after_trivia: &str,
    current_len: usize,
    pending: &PendingClauseContinuation,
) -> Option<PendingClauseContinuation> {
    if await_else_after_completion && starts_with_keyword(next_after_trivia, "else") {
        Some(continue_pending_clause(
            PendingClauseKind::IfAwaitElse,
            current_len,
            pending,
        ))
    } else {
        let mut continuation = pending_clause_from_owner_stack(
            pending.deferred_statement_owner.clone(),
            next_after_trivia,
            current_len,
        );
        if let Some(continuation) = continuation.as_mut() {
            continuation.owner_stack_complete = pending.owner_stack_complete;
        }
        continuation
    }
}

fn completed_catch_clause(
    pending: &PendingClauseContinuation,
    handler_tail: &str,
    next_after_trivia: &str,
    current_len: usize,
    grammar_context: ScanGrammarContext,
) -> Option<PendingClauseContinuation> {
    if handler_tail.is_empty() {
        if starts_with_keyword(next_after_trivia, "finally") {
            Some(continue_pending_clause(
                PendingClauseKind::CatchAwaitFinally,
                current_len,
                pending,
            ))
        } else {
            completed_clause_statement(false, next_after_trivia, current_len, pending)
        }
    } else if starts_with_keyword(handler_tail, "finally") {
        let finalizer_body = clause_keyword_tail(handler_tail, "finally", grammar_context)?;
        if finalizer_body.is_empty() && next_after_trivia.starts_with('{') {
            Some(continue_pending_clause(
                PendingClauseKind::FinallyAwaitBody,
                current_len,
                pending,
            ))
        } else if finally_clause_tail_after_body(handler_tail, grammar_context)
            .is_some_and(str::is_empty)
        {
            completed_clause_statement(false, next_after_trivia, current_len, pending)
        } else {
            None
        }
    } else {
        None
    }
}

fn pending_clause_after_try_prefix(
    statement: &str,
    following: &str,
    current_len: usize,
    pending: PendingClauseContinuation,
    grammar_context: ScanGrammarContext,
) -> Option<PendingClauseContinuation> {
    let try_body = clause_keyword_tail(statement, "try", grammar_context)?;
    let (_, tail) = extract_balanced_with_context(try_body, '{', '}', grammar_context)?;
    let tail = trim_binding_pattern_trivia_with_context(tail, grammar_context)?;
    if tail.is_empty() {
        return (starts_with_keyword(following, "catch")
            || starts_with_keyword(following, "finally"))
        .then_some(pending);
    }

    if starts_with_keyword(tail, "catch") {
        let after_catch = clause_keyword_tail(tail, "catch", grammar_context)?;
        if after_catch.is_empty() {
            return if following.starts_with('(') {
                Some(continue_pending_clause(
                    PendingClauseKind::CatchAwaitParameter,
                    current_len,
                    &pending,
                ))
            } else if following.starts_with('{') {
                Some(continue_pending_clause(
                    PendingClauseKind::CatchAwaitBody,
                    current_len,
                    &pending,
                ))
            } else {
                None
            };
        }
        let body_source = if after_catch.starts_with('(') {
            let (_, remaining) =
                extract_balanced_with_context(after_catch, '(', ')', grammar_context)?;
            let remaining =
                trim_binding_pattern_leading_trivia_with_context(remaining, grammar_context)?;
            if remaining.is_empty() {
                return following.starts_with('{').then(|| {
                    continue_pending_clause(
                        PendingClauseKind::CatchAwaitBody,
                        current_len,
                        &pending,
                    )
                });
            }
            remaining
        } else {
            after_catch
        };
        let handler_tail = balanced_block_tail(body_source, grammar_context)?;
        return completed_catch_clause(
            &pending,
            handler_tail,
            following,
            current_len,
            grammar_context,
        );
    }

    if starts_with_keyword(tail, "finally") {
        let finalizer_body = clause_keyword_tail(tail, "finally", grammar_context)?;
        if finalizer_body.is_empty() {
            return following.starts_with('{').then(|| {
                continue_pending_clause(PendingClauseKind::FinallyAwaitBody, current_len, &pending)
            });
        }
        return finally_clause_tail_after_body(tail, grammar_context)
            .is_some_and(str::is_empty)
            .then(|| completed_clause_statement(false, following, current_len, &pending))
            .flatten();
    }

    None
}

fn advance_clause_statement(
    pending: PendingClauseContinuation,
    mut statement: &str,
    next_after_trivia: &str,
    current_len: usize,
    await_else_after_completion: bool,
    completion: (ScanGrammarContext, usize, &mut DoWhileCompletionMemo),
) -> Option<PendingClauseContinuation> {
    let (grammar_context, completion_recursion_limit, completion_memo) = completion;
    let mut direct_if_depth = usize::from(await_else_after_completion);
    loop {
        if starts_with_keyword(statement, "if") {
            match parenthesized_statement_status(statement, "if", grammar_context) {
                Some(ParenthesizedStatementStatus::MissingCondition)
                    if next_after_trivia.starts_with('(') =>
                {
                    return Some(pending);
                }
                Some(ParenthesizedStatementStatus::MissingBody) => {
                    let continuation = continue_pending_clause(
                        PendingClauseKind::ElseIfAwaitBody,
                        current_len,
                        &pending,
                    );
                    return Some(defer_pending_if_owners(continuation, direct_if_depth));
                }
                Some(ParenthesizedStatementStatus::Complete) => {
                    let tail = clause_keyword_tail(statement, "if", grammar_context)?;
                    let (_, body) = extract_balanced_with_context(tail, '(', ')', grammar_context)?;
                    statement =
                        trim_binding_pattern_leading_trivia_with_context(body, grammar_context)?;
                    direct_if_depth = direct_if_depth.saturating_add(1);
                    continue;
                }
                Some(ParenthesizedStatementStatus::Invalid)
                | Some(ParenthesizedStatementStatus::MissingCondition)
                | None => return None,
            }
        }

        let mut matched_parenthesized_statement = false;
        for keyword in ["while", "for", "with", "switch"] {
            if !starts_with_keyword(statement, keyword) {
                continue;
            }
            matched_parenthesized_statement = true;
            match parenthesized_statement_status(statement, keyword, grammar_context) {
                Some(ParenthesizedStatementStatus::MissingCondition)
                    if next_after_trivia.starts_with('(') =>
                {
                    return Some(pending);
                }
                Some(ParenthesizedStatementStatus::MissingBody) => {
                    let kind = if direct_if_depth > 0 {
                        PendingClauseKind::ElseIfAwaitBody
                    } else {
                        PendingClauseKind::ElseAwaitStatement
                    };
                    let continuation = continue_pending_clause(kind, current_len, &pending);
                    return Some(defer_pending_if_owners(
                        continuation,
                        direct_if_depth.saturating_sub(1),
                    ));
                }
                Some(ParenthesizedStatementStatus::Complete) => {
                    let tail = clause_keyword_tail(statement, keyword, grammar_context)?;
                    let (_, body) = extract_balanced_with_context(tail, '(', ')', grammar_context)?;
                    statement =
                        trim_binding_pattern_leading_trivia_with_context(body, grammar_context)?;
                    break;
                }
                Some(ParenthesizedStatementStatus::Invalid)
                | Some(ParenthesizedStatementStatus::MissingCondition)
                | None => return None,
            }
        }
        if matched_parenthesized_statement {
            continue;
        }

        if starts_with_keyword(statement, "try") {
            let try_pending = defer_pending_if_owners(
                continue_pending_clause(PendingClauseKind::TryAwaitHandler, current_len, &pending),
                direct_if_depth,
            );
            return pending_clause_after_try_prefix(
                statement,
                next_after_trivia,
                current_len,
                try_pending,
                grammar_context,
            );
        }
        if starts_with_keyword(statement, "do") {
            if do_while_statement_is_complete_with_limit(
                statement,
                grammar_context,
                completion_recursion_limit,
                completion_memo,
            ) {
                let completed_pending =
                    defer_pending_if_owners(pending.clone(), direct_if_depth.saturating_sub(1));
                return completed_clause_statement(
                    direct_if_depth > 0,
                    next_after_trivia,
                    current_len,
                    &completed_pending,
                );
            }
            if starts_with_keyword(next_after_trivia, "while") {
                let base_owner = push_pending_statement_owners(
                    pending.deferred_statement_owner.clone(),
                    PendingStatementClauseKind::IfElse,
                    direct_if_depth,
                );
                let owners = direct_statement_owner_stack_with_complete_body(
                    statement,
                    base_owner,
                    grammar_context,
                    completion_recursion_limit,
                    completion_memo,
                )?;
                let mut continuation =
                    pending_clause_from_owner_stack(Some(owners), next_after_trivia, current_len);
                if let Some(continuation) = continuation.as_mut() {
                    continuation.owner_stack_complete = pending.owner_stack_complete;
                }
                return continuation;
            }
        }

        if declaration_source_needs_continuation(statement, next_after_trivia, grammar_context) {
            let kind = if direct_if_depth > 0 {
                PendingClauseKind::ElseIfDeclarationContinuation
            } else {
                PendingClauseKind::ElseDeclarationContinuation
            };
            let mut continuation = defer_pending_if_owners(
                continue_pending_clause(kind, current_len, &pending),
                direct_if_depth.saturating_sub(1),
            );
            continuation.declaration_initializer_active =
                declaration_source_has_active_initializer(statement, grammar_context);
            return Some(continuation);
        }
        if statement_allows_expression_continuation(statement, grammar_context)
            && expression_statement_continues(statement, next_after_trivia, grammar_context)
        {
            let kind = if direct_if_depth > 0 {
                PendingClauseKind::ElseIfExpressionContinuation
            } else {
                PendingClauseKind::ElseExpressionContinuation
            };
            let continuation = continue_pending_clause(kind, current_len, &pending);
            return Some(defer_pending_if_owners(
                continuation,
                direct_if_depth.saturating_sub(1),
            ));
        }
        let completed_pending =
            defer_pending_if_owners(pending.clone(), direct_if_depth.saturating_sub(1));
        return completed_clause_statement(
            direct_if_depth > 0,
            next_after_trivia,
            current_len,
            &completed_pending,
        );
    }
}

fn advance_pending_clause(
    pending: PendingClauseContinuation,
    current_text: &str,
    next_after_trivia: &str,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
    completion_memo: &mut DoWhileCompletionMemo,
) -> Option<PendingClauseContinuation> {
    let fragment = current_text.get(pending.fragment_start..)?;
    let fragment = trim_binding_pattern_trivia_with_context(fragment, grammar_context)?;
    if fragment.is_empty() {
        return Some(pending);
    }

    match pending.kind {
        PendingClauseKind::IfAwaitElse => {
            if !starts_with_keyword(fragment, "else") {
                return None;
            }
            let alternate = clause_keyword_tail(fragment, "else", grammar_context)?;
            if alternate.is_empty() {
                return Some(continue_pending_clause(
                    PendingClauseKind::ElseAwaitStatement,
                    current_text.len(),
                    &pending,
                ));
            }
            advance_clause_statement(
                pending,
                alternate,
                next_after_trivia,
                current_text.len(),
                false,
                (grammar_context, completion_recursion_limit, completion_memo),
            )
        }
        PendingClauseKind::ElseAwaitStatement => advance_clause_statement(
            pending,
            fragment,
            next_after_trivia,
            current_text.len(),
            false,
            (grammar_context, completion_recursion_limit, completion_memo),
        ),
        PendingClauseKind::ElseExpressionContinuation => {
            if expression_statement_continues(fragment, next_after_trivia, grammar_context) {
                Some(continue_pending_clause(
                    PendingClauseKind::ElseExpressionContinuation,
                    current_text.len(),
                    &pending,
                ))
            } else {
                completed_clause_statement(false, next_after_trivia, current_text.len(), &pending)
            }
        }
        PendingClauseKind::ElseDeclarationContinuation => {
            let line_ends_continuation = fragment.ends_with(',')
                || fragment.ends_with('=')
                || source_ends_expression_continuation(fragment, grammar_context);
            if pending_declaration_fragment_needs_continuation(
                fragment,
                line_ends_continuation,
                pending.declaration_initializer_active,
                next_after_trivia,
                grammar_context,
                completion_recursion_limit,
                completion_memo,
            ) {
                let mut continuation = continue_pending_clause(
                    PendingClauseKind::ElseDeclarationContinuation,
                    current_text.len(),
                    &pending,
                );
                continuation.declaration_initializer_active =
                    pending.declaration_initializer_active;
                Some(continuation)
            } else {
                completed_clause_statement(false, next_after_trivia, current_text.len(), &pending)
            }
        }
        PendingClauseKind::ElseIfAwaitBody => advance_clause_statement(
            pending,
            fragment,
            next_after_trivia,
            current_text.len(),
            true,
            (grammar_context, completion_recursion_limit, completion_memo),
        ),
        PendingClauseKind::ElseIfExpressionContinuation => {
            if expression_statement_continues(fragment, next_after_trivia, grammar_context) {
                Some(continue_pending_clause(
                    PendingClauseKind::ElseIfExpressionContinuation,
                    current_text.len(),
                    &pending,
                ))
            } else {
                completed_clause_statement(true, next_after_trivia, current_text.len(), &pending)
            }
        }
        PendingClauseKind::ElseIfDeclarationContinuation => {
            let line_ends_continuation = fragment.ends_with(',')
                || fragment.ends_with('=')
                || source_ends_expression_continuation(fragment, grammar_context);
            if pending_declaration_fragment_needs_continuation(
                fragment,
                line_ends_continuation,
                pending.declaration_initializer_active,
                next_after_trivia,
                grammar_context,
                completion_recursion_limit,
                completion_memo,
            ) {
                let mut continuation = continue_pending_clause(
                    PendingClauseKind::ElseIfDeclarationContinuation,
                    current_text.len(),
                    &pending,
                );
                continuation.declaration_initializer_active =
                    pending.declaration_initializer_active;
                Some(continuation)
            } else {
                completed_clause_statement(true, next_after_trivia, current_text.len(), &pending)
            }
        }
        PendingClauseKind::TryAwaitHandler => {
            if starts_with_keyword(fragment, "catch") {
                let after_catch = clause_keyword_tail(fragment, "catch", grammar_context)?;
                if after_catch.is_empty() {
                    return if next_after_trivia.starts_with('{') {
                        Some(continue_pending_clause(
                            PendingClauseKind::CatchAwaitBody,
                            current_text.len(),
                            &pending,
                        ))
                    } else if next_after_trivia.starts_with('(') {
                        Some(pending)
                    } else {
                        None
                    };
                }
                if after_catch.starts_with('(') {
                    let (_, body) =
                        extract_balanced_with_context(after_catch, '(', ')', grammar_context)?;
                    if trim_binding_pattern_leading_trivia_with_context(body, grammar_context)
                        .is_some_and(str::is_empty)
                    {
                        return Some(continue_pending_clause(
                            PendingClauseKind::CatchAwaitBody,
                            current_text.len(),
                            &pending,
                        ));
                    }
                }
                let handler_tail = catch_clause_tail_after_body(fragment, grammar_context)?;
                completed_catch_clause(
                    &pending,
                    handler_tail,
                    next_after_trivia,
                    current_text.len(),
                    grammar_context,
                )
            } else if starts_with_keyword(fragment, "finally") {
                let body = clause_keyword_tail(fragment, "finally", grammar_context)?;
                if body.is_empty() && next_after_trivia.starts_with('{') {
                    Some(continue_pending_clause(
                        PendingClauseKind::FinallyAwaitBody,
                        current_text.len(),
                        &pending,
                    ))
                } else if finally_clause_tail_after_body(fragment, grammar_context)
                    .is_some_and(str::is_empty)
                {
                    completed_clause_statement(
                        false,
                        next_after_trivia,
                        current_text.len(),
                        &pending,
                    )
                } else {
                    None
                }
            } else {
                None
            }
        }
        PendingClauseKind::CatchAwaitParameter => {
            let (_, body_source) =
                extract_balanced_with_context(fragment, '(', ')', grammar_context)?;
            let body_source =
                trim_binding_pattern_leading_trivia_with_context(body_source, grammar_context)?;
            if body_source.is_empty() {
                next_after_trivia.starts_with('{').then(|| {
                    continue_pending_clause(
                        PendingClauseKind::CatchAwaitBody,
                        current_text.len(),
                        &pending,
                    )
                })
            } else {
                let handler_tail = balanced_block_tail(body_source, grammar_context)?;
                completed_catch_clause(
                    &pending,
                    handler_tail,
                    next_after_trivia,
                    current_text.len(),
                    grammar_context,
                )
            }
        }
        PendingClauseKind::CatchAwaitBody => {
            let handler_tail = balanced_block_tail(fragment, grammar_context)?;
            completed_catch_clause(
                &pending,
                handler_tail,
                next_after_trivia,
                current_text.len(),
                grammar_context,
            )
        }
        PendingClauseKind::CatchAwaitFinally => {
            if !starts_with_keyword(fragment, "finally") {
                return None;
            }
            let body = clause_keyword_tail(fragment, "finally", grammar_context)?;
            if body.is_empty() && next_after_trivia.starts_with('{') {
                Some(continue_pending_clause(
                    PendingClauseKind::FinallyAwaitBody,
                    current_text.len(),
                    &pending,
                ))
            } else if finally_clause_tail_after_body(fragment, grammar_context)
                .is_some_and(str::is_empty)
            {
                completed_clause_statement(false, next_after_trivia, current_text.len(), &pending)
            } else {
                None
            }
        }
        PendingClauseKind::FinallyAwaitBody => {
            if !balanced_block_tail(fragment, grammar_context).is_some_and(str::is_empty) {
                return None;
            }
            completed_clause_statement(false, next_after_trivia, current_text.len(), &pending)
        }
        PendingClauseKind::DoAwaitWhile => {
            if !starts_with_keyword(fragment, "while") {
                return None;
            }
            let condition = clause_keyword_tail(fragment, "while", grammar_context)?;
            if condition.is_empty() && next_after_trivia.starts_with('(') {
                Some(continue_pending_clause(
                    PendingClauseKind::DoWhileAwaitCondition,
                    current_text.len(),
                    &pending,
                ))
            } else {
                None
            }
        }
        PendingClauseKind::DoWhileAwaitCondition => None,
    }
}

fn advance_direct_do_while_clause(
    pending: &PendingClauseContinuation,
    current_text: &str,
    next_after_trivia: &str,
    grammar_context: ScanGrammarContext,
) -> Option<Option<PendingClauseContinuation>> {
    if !pending.owner_stack_complete {
        return None;
    }
    let fragment = current_text.get(pending.fragment_start..)?;
    let fragment = trim_binding_pattern_trivia_with_context(fragment, grammar_context)?;
    let condition = match pending.kind {
        PendingClauseKind::DoAwaitWhile => clause_keyword_tail(fragment, "while", grammar_context)?,
        PendingClauseKind::DoWhileAwaitCondition => fragment,
        _ => return None,
    };
    let (_, rest) = extract_balanced_with_context(condition, '(', ')', grammar_context)?;
    let rest = trim_binding_pattern_trivia_with_context(rest, grammar_context)?;
    let rest = if let Some(rest) = rest.strip_prefix(';') {
        trim_binding_pattern_trivia_with_context(rest, grammar_context)?
    } else {
        rest
    };
    if !rest.is_empty() {
        return None;
    }
    Some(completed_clause_statement(
        false,
        next_after_trivia,
        current_text.len(),
        pending,
    ))
}

#[derive(Debug, Clone, Copy)]
struct PhysicalLine<'a> {
    segment: &'a str,
    content: &'a str,
    terminator: &'a str,
}

fn source_line_terminator_ranges(source: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut chars = source.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '\r' => {
                let end = if matches!(chars.peek(), Some((_, '\n'))) {
                    chars.next().map_or(index.saturating_add(1), |(next, ch)| {
                        next.saturating_add(ch.len_utf8())
                    })
                } else {
                    index.saturating_add(ch.len_utf8())
                };
                ranges.push((index, end));
            }
            '\n' | '\u{2028}' | '\u{2029}' => {
                ranges.push((index, index.saturating_add(ch.len_utf8())));
            }
            _ => {}
        }
    }
    ranges
}

fn physical_line_segments(source: &str) -> Vec<PhysicalLine<'_>> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    for (terminator_start, terminator_end) in source_line_terminator_ranges(source) {
        lines.push(PhysicalLine {
            segment: &source[start..terminator_end],
            content: &source[start..terminator_start],
            terminator: &source[terminator_start..terminator_end],
        });
        start = terminator_end;
    }
    if start < source.len() {
        lines.push(PhysicalLine {
            segment: &source[start..],
            content: &source[start..],
            terminator: "",
        });
    }
    lines
}

fn next_significant_offsets_after_physical_lines(
    text: &str,
    physical_lines: &[PhysicalLine<'_>],
    grammar_context: ScanGrammarContext,
) -> Vec<Option<usize>> {
    let mut boundaries = Vec::new();
    let mut boundary = 0usize;
    for physical_line in physical_lines {
        boundary = boundary.saturating_add(physical_line.segment.len());
        boundaries.push(boundary);
    }

    let mut next_offsets = vec![None; boundaries.len()];
    let mut next_boundary = 0usize;
    scan_binding_pattern_source_with_context(text, grammar_context, |index, ch, _, quoted| {
        if !quoted && is_binding_pattern_whitespace(ch) {
            return;
        }
        while next_boundary < boundaries.len() && boundaries[next_boundary] <= index {
            next_offsets[next_boundary] = Some(index);
            next_boundary = next_boundary.saturating_add(1);
        }
    });
    next_offsets
}

fn trailing_statement_source_unfiltered<'a>(
    source: &'a str,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
    completion_memo: &mut DoWhileCompletionMemo,
) -> Option<&'a str> {
    trim_binding_pattern_trivia_with_context(source, grammar_context)
        .and_then(|source| {
            split_statement_segments_with_completion_limit_and_memo(
                source,
                grammar_context,
                completion_recursion_limit,
                completion_memo,
            )
            .last()
            .map(|(_, _, statement)| *statement)
        })
        .and_then(|source| trim_binding_pattern_trivia_with_context(source, grammar_context))
}

fn trailing_statement_source<'a>(
    source: &'a str,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
    completion_memo: &mut DoWhileCompletionMemo,
) -> Option<&'a str> {
    let source = trim_binding_pattern_trivia_with_context(source, grammar_context)?;
    if source.ends_with(';') {
        return None;
    }
    trailing_statement_source_unfiltered(
        source,
        grammar_context,
        completion_recursion_limit,
        completion_memo,
    )
}

fn trailing_statement_source_before_clause<'a>(
    source: &'a str,
    following: &str,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
    completion_memo: &mut DoWhileCompletionMemo,
) -> Option<&'a str> {
    let may_follow_terminated_body = ["else", "while"]
        .into_iter()
        .any(|keyword| starts_with_keyword(following, keyword));
    if may_follow_terminated_body {
        trailing_statement_source_unfiltered(
            source,
            grammar_context,
            completion_recursion_limit,
            completion_memo,
        )
    } else {
        trailing_statement_source(
            source,
            grammar_context,
            completion_recursion_limit,
            completion_memo,
        )
    }
}

fn declaration_source_needs_continuation(
    source: &str,
    next_after_trivia: &str,
    grammar_context: ScanGrammarContext,
) -> bool {
    let Some(kind) = variable_declaration_prefix_kind(source) else {
        return false;
    };
    let body = source
        .strip_prefix(kind.as_str())
        .and_then(|source| trim_binding_pattern_trivia_with_context(source, grammar_context))
        .unwrap_or_default();
    let next = next_after_trivia.chars().next();
    let next_starts_binding = matches!(next, Some('{' | '['))
        || next_after_trivia.starts_with('\\')
        || canonical_leading_source_identifier(next_after_trivia).is_some();
    let let_expression_continues = kind == VariableDeclarationKind::Let
        && starts_directive_expression_continuation(next_after_trivia);
    let next_selects_declaration = if kind == VariableDeclarationKind::Let {
        let_starts_lexical_declaration(next_after_trivia)
    } else {
        next_starts_binding
    };
    let initializer_continues = split_var_declarator_segments_with_context(body, grammar_context)
        .last()
        .and_then(|declarator| {
            let (_, initializer) = split_var_declarator_assignment(declarator, grammar_context);
            initializer
        })
        .and_then(|initializer| {
            trim_binding_pattern_trivia_with_context(initializer, grammar_context)
        })
        .is_some_and(|initializer| {
            expression_statement_continues(initializer, next_after_trivia, grammar_context)
        });
    !next_after_trivia.is_empty()
        && ((body.is_empty() && (next_selects_declaration || let_expression_continues))
            || source.ends_with(',')
            || source.ends_with('=')
            || matches!(next, Some(',' | '='))
            || initializer_continues)
}

fn declaration_source_has_active_initializer(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> bool {
    let Some(kind) = variable_declaration_prefix_kind(source) else {
        return false;
    };
    let body = source
        .strip_prefix(kind.as_str())
        .and_then(|source| trim_binding_pattern_trivia_with_context(source, grammar_context))
        .unwrap_or_default();
    declaration_fragment_has_active_initializer(body, false, grammar_context)
}

fn declaration_fragment_has_active_initializer(
    fragment: &str,
    initializer_was_active: bool,
    grammar_context: ScanGrammarContext,
) -> bool {
    let mut last_declarator_boundary_end = None;
    scan_binding_pattern_source_with_context(
        fragment,
        grammar_context,
        |index, ch, depth, quoted| {
            if !quoted && depth == 0 && matches!(ch, ',' | ';') {
                last_declarator_boundary_end = Some(index.saturating_add(ch.len_utf8()));
            }
        },
    );
    let active_declarator = last_declarator_boundary_end
        .and_then(|start| fragment.get(start..))
        .unwrap_or(fragment);
    let fragment_has_initializer =
        split_var_declarator_assignment(active_declarator, grammar_context)
            .1
            .is_some();
    if last_declarator_boundary_end.is_some() {
        fragment_has_initializer
    } else {
        initializer_was_active || fragment_has_initializer
    }
}

fn pending_declaration_fragment_needs_continuation(
    line: &str,
    line_ends_continuation: bool,
    initializer_is_active: bool,
    next_after_trivia: &str,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
    completion_memo: &mut DoWhileCompletionMemo,
) -> bool {
    let next = next_after_trivia.chars().next();
    let next_continues_declaration =
        !next_after_trivia.is_empty() && matches!(next, Some(',' | '='));
    let Some(source) = trim_binding_pattern_trivia_with_context(line, grammar_context) else {
        // The opening quote/comment can be on an earlier physical line, so a
        // closing fragment need not be self-contained lexical input.
        return line_ends_continuation
            || next_continues_declaration
            || (initializer_is_active
                && starts_directive_expression_continuation(next_after_trivia));
    };
    if source.is_empty() {
        return true;
    }
    let Some(trailing_source) = trailing_statement_source(
        source,
        grammar_context,
        completion_recursion_limit,
        completion_memo,
    ) else {
        return initializer_is_active
            && starts_directive_expression_continuation(next_after_trivia);
    };
    if declaration_source_needs_continuation(trailing_source, next_after_trivia, grammar_context) {
        return true;
    }
    if initializer_is_active
        && expression_statement_continues(trailing_source, next_after_trivia, grammar_context)
    {
        return true;
    }
    !next_after_trivia.is_empty()
        && (trailing_source.ends_with(',')
            || trailing_source.ends_with('=')
            || next_continues_declaration)
}

fn trailing_statement_continuation_state(
    source: &str,
    next_after_trivia: &str,
    fragment_start: usize,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
    completion_memo: &mut DoWhileCompletionMemo,
) -> (bool, bool, Option<PendingClauseContinuation>) {
    let trailing_source = trailing_statement_source_before_clause(
        source,
        next_after_trivia,
        grammar_context,
        completion_recursion_limit,
        completion_memo,
    );
    let declaration_continues = trailing_source.is_some_and(|source| {
        declaration_source_needs_continuation(source, next_after_trivia, grammar_context)
    });
    let declaration_initializer = trailing_source
        .is_some_and(|source| declaration_source_has_active_initializer(source, grammar_context));
    let clause_continues = trailing_source.and_then(|source| {
        pending_clause_after_statement(
            source,
            next_after_trivia,
            fragment_start,
            grammar_context,
            completion_recursion_limit,
            completion_memo,
        )
    });
    (
        declaration_continues,
        declaration_initializer,
        clause_continues,
    )
}

/// Merge physical lines into logical lines by tracking brace/paren/bracket depth.
/// When a line ends with unbalanced delimiters, subsequent lines are merged until balance.
#[cfg(test)]
fn merge_logical_lines_with_context(
    text: &str,
    grammar_context: ScanGrammarContext,
) -> Vec<LogicalLine> {
    merge_logical_lines_with_completion_limit(
        text,
        grammar_context,
        STATEMENT_COMPLETION_RECURSION_LIMIT,
    )
}

fn merge_logical_lines_with_completion_limit(
    text: &str,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
) -> Vec<LogicalLine> {
    let physical_lines = physical_line_segments(text);
    let next_significant_offsets =
        next_significant_offsets_after_physical_lines(text, &physical_lines, grammar_context);
    let mut regexp_slash_positions = BTreeSet::new();
    let scan_state = scan_binding_pattern_source_until_with_context(
        text,
        grammar_context,
        |index, ch, _depth, quoted| {
            if quoted && ch == '/' && parse_regexp_literal_prefix(&text[index..]).is_some() {
                regexp_slash_positions.insert(index);
            }
            true
        },
    );
    let template_literal_ends: BTreeMap<usize, usize> =
        scan_state.template_literal_ranges.into_iter().collect();
    let mut result = Vec::new();
    let mut current_text = String::with_capacity(text.len());
    let mut completion_memo = BTreeMap::new();
    let mut current_byte_offset: u64 = 0;
    let mut current_start_line: u64 = 0;
    let mut byte_offset: u64 = 0;
    let mut brace_depth: i64 = 0;
    let mut paren_depth: i64 = 0;
    let mut bracket_depth: i64 = 0;
    let mut in_quote: Option<char> = None;
    let mut in_block_comment = false;
    let mut in_regex_literal = false;
    let mut in_template_literal: Option<usize> = None;
    let mut regex_in_char_class = false;
    let mut escaped = false;
    let mut accumulating = false;
    let mut pending_declaration_continuation = false;
    let mut pending_declaration_initializer = false;
    let mut pending_declaration_trailing_statement_start = None;
    let mut top_level_conditional_depth = 0usize;
    let mut pending_clause_continuation: Option<PendingClauseContinuation> = None;
    let mut last_significant: Option<char> = None;
    let mut trailing_identifier = String::new();
    let mut trailing_identifier_is_member = false;
    let mut identifier_token_open = false;
    let mut control_paren_stack = Vec::new();
    let mut block_brace_stack = Vec::new();
    let mut statement_goal = true;
    let mut previous_line_terminator = "";

    for (line_idx, physical_line) in physical_lines.iter().copied().enumerate() {
        let line_no = (line_idx as u64).saturating_add(1);
        let segment = physical_line.segment;
        let line = physical_line.content;

        if !accumulating {
            completion_memo.clear();
            current_text.clear();
            current_byte_offset = byte_offset;
            current_start_line = line_no;
            last_significant = None;
            trailing_identifier.clear();
            trailing_identifier_is_member = false;
            identifier_token_open = false;
            control_paren_stack.clear();
            block_brace_stack.clear();
            statement_goal = true;
            pending_declaration_initializer = false;
            pending_declaration_trailing_statement_start = None;
            top_level_conditional_depth = 0;
        } else if in_quote.is_some() {
            if escaped {
                // Preserve LineContinuation provenance until literal cooking.
                // Besides directive recognition for strings, retaining the
                // physical line boundary keeps spans after a template aligned
                // with the original source.
                current_text.push_str(previous_line_terminator);
                escaped = false;
            } else {
                // Preserve an unescaped line ending so the literal parser can
                // reject it (or retain it for a template) instead of silently
                // changing an invalid string into one containing a space.
                current_text.push_str(previous_line_terminator);
            }
        } else {
            if identifier_token_open
                && !trailing_identifier_is_member
                && merge_logical_lines_identifier_awaits_statement(&trailing_identifier)
            {
                statement_goal = true;
            }
            // Preserve physical line boundaries inside balanced constructs.
            // Besides ASI, directive prologues and line comments depend on
            // LineTerminator provenance; flattening this to a space loses it.
            current_text.push_str(previous_line_terminator);
            identifier_token_open = false;
        }
        current_text.push_str(line);
        let current_line_start = current_text.len().saturating_sub(line.len());

        let mut line_has_significant_code = false;
        let mut chars = line.char_indices().peekable();
        while let Some((line_byte_index, ch)) = chars.next() {
            let absolute_index = usize::try_from(byte_offset)
                .unwrap_or(usize::MAX)
                .saturating_add(line_byte_index);
            if in_block_comment {
                if ch == '*' && matches!(chars.peek(), Some((_, '/'))) {
                    chars.next();
                    in_block_comment = false;
                }
                continue;
            }
            if let Some(q) = in_quote {
                line_has_significant_code = true;
                if escaped {
                    escaped = false;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    continue;
                }
                if ch == q {
                    in_quote = None;
                }
                continue;
            }
            if in_regex_literal {
                line_has_significant_code = true;
                if escaped {
                    escaped = false;
                    continue;
                }
                match ch {
                    '\\' => {
                        escaped = true;
                    }
                    '[' if !regex_in_char_class => {
                        regex_in_char_class = true;
                    }
                    ']' if regex_in_char_class => {
                        regex_in_char_class = false;
                    }
                    '/' if !regex_in_char_class => {
                        in_regex_literal = false;
                        last_significant = Some(')');
                        trailing_identifier.clear();
                        trailing_identifier_is_member = false;
                        identifier_token_open = false;
                        statement_goal = false;
                    }
                    _ => {}
                }
                continue;
            }
            if let Some(template_end) = in_template_literal {
                line_has_significant_code = true;
                if absolute_index.saturating_add(ch.len_utf8()) >= template_end {
                    in_template_literal = None;
                    last_significant = Some(')');
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                    identifier_token_open = false;
                    statement_goal = false;
                }
                continue;
            }
            if let Some(template_end) = template_literal_ends.get(&absolute_index).copied() {
                line_has_significant_code = true;
                in_template_literal = Some(template_end);
                trailing_identifier.clear();
                trailing_identifier_is_member = false;
                identifier_token_open = false;
                statement_goal = false;
                continue;
            }
            let identifier_continues = ch.is_ascii_alphabetic()
                || matches!(ch, '_' | '$')
                || (ch.is_ascii_digit() && identifier_token_open);
            if identifier_token_open && !identifier_continues {
                if !trailing_identifier_is_member
                    && merge_logical_lines_identifier_awaits_statement(&trailing_identifier)
                {
                    statement_goal = true;
                }
                identifier_token_open = false;
            }
            if matches!(ch, '+' | '-') && chars.peek().is_some_and(|(_, next)| *next == ch) {
                let prefix_position = (line_idx > 0 && !line_has_significant_code)
                    || merge_logical_lines_update_is_prefix(
                        last_significant,
                        trailing_identifier.as_str(),
                        trailing_identifier_is_member,
                        grammar_context,
                    );
                chars.next();
                line_has_significant_code = true;
                last_significant = Some(if prefix_position { ch } else { ')' });
                trailing_identifier.clear();
                trailing_identifier_is_member = false;
                identifier_token_open = false;
                statement_goal = false;
                continue;
            }
            match ch {
                '/' => match chars.peek() {
                    Some((_, '/')) => {
                        identifier_token_open = false;
                        break;
                    }
                    Some((_, '*')) => {
                        chars.next();
                        in_block_comment = true;
                        identifier_token_open = false;
                    }
                    _ if regexp_slash_positions.contains(&absolute_index) => {
                        line_has_significant_code = true;
                        in_regex_literal = true;
                        regex_in_char_class = false;
                        escaped = false;
                        trailing_identifier.clear();
                        trailing_identifier_is_member = false;
                        identifier_token_open = false;
                        statement_goal = false;
                    }
                    _ => {
                        line_has_significant_code = true;
                        last_significant = Some('/');
                        trailing_identifier.clear();
                        trailing_identifier_is_member = false;
                        identifier_token_open = false;
                        statement_goal = false;
                    }
                },
                '\'' | '"' | '`' => {
                    line_has_significant_code = true;
                    in_quote = Some(ch);
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                    identifier_token_open = false;
                    statement_goal = false;
                }
                '{' => {
                    let is_block = statement_goal;
                    block_brace_stack.push(is_block);
                    line_has_significant_code = true;
                    brace_depth += 1;
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                    identifier_token_open = false;
                    statement_goal = is_block;
                }
                '}' => {
                    let is_block = block_brace_stack.pop().unwrap_or(false);
                    line_has_significant_code = true;
                    brace_depth -= 1;
                    last_significant = Some(if is_block { '{' } else { ch });
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                    identifier_token_open = false;
                    statement_goal = is_block;
                }
                '(' => {
                    let is_control_header = !trailing_identifier_is_member
                        && merge_logical_lines_identifier_opens_control_header(
                            &trailing_identifier,
                        );
                    control_paren_stack.push(is_control_header);
                    line_has_significant_code = true;
                    paren_depth += 1;
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                    identifier_token_open = false;
                    statement_goal = false;
                }
                ')' => {
                    let is_control_header = control_paren_stack.pop().unwrap_or(false);
                    line_has_significant_code = true;
                    paren_depth -= 1;
                    last_significant = Some(if is_control_header { '{' } else { ch });
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                    identifier_token_open = false;
                    statement_goal = is_control_header;
                }
                '[' => {
                    line_has_significant_code = true;
                    bracket_depth += 1;
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                    identifier_token_open = false;
                    statement_goal = false;
                }
                ']' => {
                    line_has_significant_code = true;
                    bracket_depth -= 1;
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                    identifier_token_open = false;
                    statement_goal = false;
                }
                ch if is_binding_pattern_whitespace(ch) => {
                    identifier_token_open = false;
                }
                ch if ch.is_ascii_alphabetic() || ch == '_' || ch == '$' => {
                    line_has_significant_code = true;
                    if !identifier_token_open {
                        trailing_identifier.clear();
                        trailing_identifier_is_member = last_significant == Some('.');
                    }
                    trailing_identifier.push(ch);
                    identifier_token_open = true;
                    last_significant = Some(ch);
                    statement_goal = false;
                }
                ch if ch.is_ascii_digit() => {
                    line_has_significant_code = true;
                    if identifier_token_open {
                        trailing_identifier.push(ch);
                    } else {
                        trailing_identifier.clear();
                        trailing_identifier_is_member = false;
                    }
                    last_significant = Some(ch);
                    statement_goal = false;
                }
                ch => {
                    line_has_significant_code = true;
                    if brace_depth <= 0 && paren_depth <= 0 && bracket_depth <= 0 {
                        if accumulating && pending_declaration_continuation {
                            if matches!(ch, ',' | ';') {
                                pending_declaration_initializer = false;
                                if ch == ';' {
                                    pending_declaration_trailing_statement_start = Some(
                                        current_line_start
                                            .saturating_add(line_byte_index)
                                            .saturating_add(ch.len_utf8()),
                                    );
                                }
                            } else if ch == '=' {
                                let next = chars.peek().map(|(_, next)| *next);
                                let part_of_non_initializer = matches!(
                                    last_significant,
                                    Some('=') | Some('!') | Some('<') | Some('>')
                                ) || matches!(next, Some('=' | '>'));
                                if !part_of_non_initializer {
                                    pending_declaration_initializer = true;
                                }
                            }
                        }
                        if let Some(pending) = pending_clause_continuation.as_mut()
                            && matches!(
                                pending.kind,
                                PendingClauseKind::ElseDeclarationContinuation
                                    | PendingClauseKind::ElseIfDeclarationContinuation
                            )
                        {
                            if matches!(ch, ',' | ';') {
                                pending.declaration_initializer_active = false;
                            } else if ch == '=' {
                                let next = chars.peek().map(|(_, next)| *next);
                                let part_of_non_initializer = matches!(
                                    last_significant,
                                    Some('=') | Some('!') | Some('<') | Some('>')
                                ) || matches!(next, Some('=' | '>'));
                                if !part_of_non_initializer {
                                    pending.declaration_initializer_active = true;
                                }
                            }
                        }
                        if ch == ';' && accumulating && pending_clause_continuation.is_some() {
                            pending_declaration_trailing_statement_start = Some(
                                current_line_start
                                    .saturating_add(line_byte_index)
                                    .saturating_add(ch.len_utf8()),
                            );
                        }
                        if ch == '?'
                            && is_conditional_question_punctuator(text.as_bytes(), absolute_index)
                        {
                            top_level_conditional_depth =
                                top_level_conditional_depth.saturating_add(1);
                        } else if ch == ':' && top_level_conditional_depth > 0 {
                            top_level_conditional_depth =
                                top_level_conditional_depth.saturating_sub(1);
                        } else if ch == ';' {
                            top_level_conditional_depth = 0;
                        }
                    }
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                    identifier_token_open = false;
                    statement_goal = ch == ';' && paren_depth <= 0;
                }
            }
        }

        byte_offset = byte_offset.saturating_add(segment.len() as u64);

        // A LineTerminator is permitted between a declaration keyword and its
        // first binding, regardless of whether comment, BOM, or ordinary
        // whitespace precedes it. In sloppy Script, however, `let` can also be
        // an IdentifierReference: `let\n++x` must remain two ASI-separated
        // statements. Look through following trivia and continue only when the
        // next token can actually begin a binding.
        let may_flush = brace_depth <= 0
            && paren_depth <= 0
            && bracket_depth <= 0
            && in_quote.is_none()
            && !in_block_comment
            && !in_regex_literal
            && in_template_literal.is_none();
        // Only inspect the accumulated statement list once its lexical state
        // is otherwise flushable. The physical-line fast path handles ordinary
        // comma/operator continuations; the incremental conditional depth
        // preserves `?\nvalue\n:\nalternate` without rescanning prior lines.
        let (declaration_needs_binding, clause_continues) = if may_flush {
            let remaining_source = usize::try_from(byte_offset)
                .ok()
                .and_then(|offset| text.get(offset..))
                .unwrap_or_default();
            let next_after_trivia = next_significant_offsets
                .get(line_idx)
                .and_then(|offset| *offset)
                .and_then(|offset| text.get(offset..))
                .unwrap_or_else(|| trim_directive_trivia(remaining_source).0);
            if accumulating && pending_declaration_continuation {
                if let Some(statement_start) = pending_declaration_trailing_statement_start.take() {
                    let trailing_fragment = current_text.get(statement_start..).unwrap_or_default();
                    let (declaration_continues, declaration_initializer, clause_continues) =
                        trailing_statement_continuation_state(
                            trailing_fragment,
                            next_after_trivia,
                            current_text.len(),
                            grammar_context,
                            completion_recursion_limit,
                            &mut completion_memo,
                        );
                    pending_declaration_initializer = declaration_initializer;
                    (declaration_continues, clause_continues)
                } else {
                    let line_ends_continuation = line_has_significant_code
                        && (matches!(last_significant, Some(',' | '='))
                            || source_ends_expression_continuation(line, grammar_context));
                    let fragment_continues = !line_has_significant_code
                        || pending_declaration_fragment_needs_continuation(
                            line,
                            line_ends_continuation,
                            pending_declaration_initializer,
                            next_after_trivia,
                            grammar_context,
                            completion_recursion_limit,
                            &mut completion_memo,
                        );
                    (
                        fragment_continues
                            || line_ends_continuation
                            || top_level_conditional_depth > 0,
                        None,
                    )
                }
            } else if accumulating && pending_clause_continuation.is_some() {
                if let (Some(statement_start), Some(pending)) = (
                    pending_declaration_trailing_statement_start,
                    pending_clause_continuation.clone(),
                ) {
                    let trailing_fragment =
                        current_text.get(statement_start..).and_then(|fragment| {
                            trim_binding_pattern_trivia_with_context(fragment, grammar_context)
                        });
                    let tail_starts_else = trailing_fragment
                        .is_some_and(|fragment| starts_with_keyword(fragment, "else"));
                    let tail_starts_while = trailing_fragment
                        .is_some_and(|fragment| starts_with_keyword(fragment, "while"));
                    if tail_starts_else
                        && matches!(
                            pending.kind,
                            PendingClauseKind::ElseIfAwaitBody
                                | PendingClauseKind::ElseIfExpressionContinuation
                                | PendingClauseKind::ElseIfDeclarationContinuation
                        )
                    {
                        pending_clause_continuation = Some(PendingClauseContinuation {
                            kind: PendingClauseKind::IfAwaitElse,
                            fragment_start: statement_start,
                            deferred_statement_owner: pending.deferred_statement_owner.clone(),
                            owner_stack_complete: pending.owner_stack_complete,
                            declaration_initializer_active: false,
                        });
                        pending_declaration_trailing_statement_start = None;
                    } else if tail_starts_while
                        && matches!(
                            pending.kind,
                            PendingClauseKind::DoAwaitWhile
                                | PendingClauseKind::DoWhileAwaitCondition
                        )
                    {
                        pending_declaration_trailing_statement_start = None;
                    }
                }
                let trailing_statement_start =
                    pending_declaration_trailing_statement_start.filter(|start| {
                        current_text.get(*start..).is_some_and(|fragment| {
                            trim_binding_pattern_trivia_with_context(fragment, grammar_context)
                                .is_some_and(|fragment| !fragment.is_empty())
                        })
                    });
                if let Some(statement_start) = trailing_statement_start {
                    pending_declaration_trailing_statement_start = None;
                    let trailing_fragment = current_text.get(statement_start..).unwrap_or_default();
                    let (declaration_continues, declaration_initializer, clause_continues) =
                        trailing_statement_continuation_state(
                            trailing_fragment,
                            next_after_trivia,
                            current_text.len(),
                            grammar_context,
                            completion_recursion_limit,
                            &mut completion_memo,
                        );
                    pending_declaration_initializer = declaration_initializer;
                    (declaration_continues, clause_continues)
                } else {
                    pending_declaration_trailing_statement_start = None;
                    (
                        false,
                        if !line_has_significant_code {
                            pending_clause_continuation.clone()
                        } else {
                            let pending = pending_clause_continuation
                                .clone()
                                .expect("pending continuation checked above");
                            if let Some(direct_continuation) = advance_direct_do_while_clause(
                                &pending,
                                &current_text,
                                next_after_trivia,
                                grammar_context,
                            ) {
                                direct_continuation
                            } else {
                                advance_pending_clause(
                                    pending.clone(),
                                    &current_text,
                                    next_after_trivia,
                                    grammar_context,
                                    completion_recursion_limit,
                                    &mut completion_memo,
                                )
                                .or_else(|| {
                                    (top_level_conditional_depth > 0
                                        && (matches!(
                                            pending.kind,
                                            PendingClauseKind::ElseExpressionContinuation
                                                | PendingClauseKind::ElseIfExpressionContinuation
                                        ) || (pending.declaration_initializer_active
                                            && matches!(
                                            pending.kind,
                                            PendingClauseKind::ElseDeclarationContinuation
                                                | PendingClauseKind::ElseIfDeclarationContinuation
                                        ))))
                                    .then_some(
                                        PendingClauseContinuation {
                                            kind: pending.kind,
                                            fragment_start: current_text.len(),
                                            deferred_statement_owner: pending
                                                .deferred_statement_owner
                                                .clone(),
                                            owner_stack_complete: pending.owner_stack_complete,
                                            declaration_initializer_active: pending
                                                .declaration_initializer_active,
                                        },
                                    )
                                })
                                .or_else(|| {
                                    matches!(
                                        pending.kind,
                                        PendingClauseKind::DoAwaitWhile
                                            | PendingClauseKind::DoWhileAwaitCondition
                                    )
                                    .then(|| {
                                        trailing_statement_source_before_clause(
                                            &current_text,
                                            next_after_trivia,
                                            grammar_context,
                                            completion_recursion_limit,
                                            &mut completion_memo,
                                        )
                                        .and_then(
                                            |source| {
                                                pending_clause_after_statement(
                                                    source,
                                                    next_after_trivia,
                                                    current_text.len(),
                                                    grammar_context,
                                                    completion_recursion_limit,
                                                    &mut completion_memo,
                                                )
                                            },
                                        )
                                    })
                                    .flatten()
                                })
                            }
                        },
                    )
                }
            } else {
                let (declaration_continues, declaration_initializer, clause_continues) =
                    trailing_statement_continuation_state(
                        &current_text,
                        next_after_trivia,
                        current_text.len(),
                        grammar_context,
                        completion_recursion_limit,
                        &mut completion_memo,
                    );
                pending_declaration_initializer = declaration_initializer;
                (declaration_continues, clause_continues)
            }
        } else {
            (
                pending_declaration_continuation,
                pending_clause_continuation,
            )
        };
        if may_flush && !declaration_needs_binding && clause_continues.is_none() {
            let trimmed = current_text.trim();
            if !trimmed.is_empty() {
                result.push(LogicalLine {
                    text: current_text.clone(),
                    byte_offset: current_byte_offset,
                    start_line: current_start_line,
                    end_line: line_no,
                });
            }
            brace_depth = 0;
            paren_depth = 0;
            bracket_depth = 0;
            escaped = false;
            in_regex_literal = false;
            regex_in_char_class = false;
            in_template_literal = None;
            last_significant = None;
            trailing_identifier.clear();
            trailing_identifier_is_member = false;
            identifier_token_open = false;
            control_paren_stack.clear();
            block_brace_stack.clear();
            statement_goal = true;
            pending_declaration_initializer = false;
            pending_declaration_trailing_statement_start = None;
            top_level_conditional_depth = 0;
            accumulating = false;
            pending_declaration_continuation = false;
            pending_clause_continuation = None;
        } else {
            accumulating = true;
            pending_declaration_continuation = declaration_needs_binding;
            pending_declaration_initializer &= declaration_needs_binding;
            pending_clause_continuation = clause_continues;
        }
        previous_line_terminator = physical_line.terminator;
    }

    if accumulating {
        let trimmed = current_text.trim();
        if !trimmed.is_empty() {
            result.push(LogicalLine {
                text: current_text,
                byte_offset: current_byte_offset,
                start_line: current_start_line,
                end_line: physical_lines.len().max(1) as u64,
            });
        }
    }

    result
}

#[cfg(test)]
fn merge_logical_lines(text: &str) -> Vec<LogicalLine> {
    merge_logical_lines_with_context(text, ScanGrammarContext::SLOPPY_SCRIPT)
}

fn is_identifier_part_character(ch: char) -> bool {
    matches!(ch, '$' | '_' | '\\' | '\u{200C}' | '\u{200D}') || unicode_id_start::is_id_continue(ch)
}

fn starts_identifier_part(source: &str) -> bool {
    source
        .chars()
        .next()
        .is_some_and(is_identifier_part_character)
}

fn starts_directive_expression_continuation(source: &str) -> bool {
    let source = source.trim_start_matches(is_binding_pattern_whitespace);
    if source.starts_with("++") || source.starts_with("--") {
        return false;
    }
    if source.starts_with('.') && source.as_bytes().get(1).is_some_and(u8::is_ascii_digit) {
        return false;
    }
    if source.starts_with("!=") {
        return true;
    }
    matches!(
        source.chars().next(),
        Some(
            '(' | '['
                | '`'
                | '.'
                | '+'
                | '-'
                | '*'
                | '/'
                | '%'
                | '<'
                | '>'
                | '='
                | '&'
                | '|'
                | '^'
                | '?'
                | ','
        )
    ) || source
        .strip_prefix("in")
        .is_some_and(|rest| !starts_identifier_part(rest))
        || source
            .strip_prefix("instanceof")
            .is_some_and(|rest| !starts_identifier_part(rest))
}

fn trim_directive_trivia(mut source: &str) -> (&str, bool) {
    let mut saw_line_terminator = false;
    loop {
        let mut whitespace_end = 0usize;
        for (index, ch) in source.char_indices() {
            if is_binding_pattern_whitespace(ch) {
                saw_line_terminator |= matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}');
                whitespace_end = index + ch.len_utf8();
            } else {
                break;
            }
        }
        source = &source[whitespace_end..];

        if let Some(line_comment) = source.strip_prefix("//") {
            let newline = line_comment
                .char_indices()
                .find(|(_, ch)| matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
                .map(|(index, _)| index);
            let Some(newline) = newline else {
                return ("", saw_line_terminator);
            };
            source = &line_comment[newline..];
            continue;
        }
        if let Some(block_comment) = source.strip_prefix("/*") {
            let Some(end) = block_comment.find("*/") else {
                return (source, saw_line_terminator);
            };
            let comment = &block_comment[..end];
            saw_line_terminator |= comment
                .chars()
                .any(|ch| matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}'));
            source = &block_comment[end + 2..];
            continue;
        }
        return (source, saw_line_terminator);
    }
}

fn has_use_strict_directive(mut source: &str) -> bool {
    loop {
        (source, _) = trim_directive_trivia(source);
        let Some(delimiter) = source.chars().next().filter(|ch| matches!(ch, '\'' | '"')) else {
            return false;
        };

        let mut escaped = false;
        let mut closing_index = None;
        for (index, ch) in source[delimiter.len_utf8()..].char_indices() {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == delimiter {
                closing_index = Some(delimiter.len_utf8() + index);
                break;
            } else if matches!(ch, '\n' | '\r') {
                return false;
            }
        }
        let Some(closing_index) = closing_index else {
            return false;
        };
        let directive = &source[delimiter.len_utf8()..closing_index];
        let after_literal = &source[closing_index + delimiter.len_utf8()..];
        let (after_trivia, saw_line_terminator) = trim_directive_trivia(after_literal);
        let terminated = after_trivia.is_empty()
            || after_trivia.starts_with(';')
            || (saw_line_terminator && !starts_directive_expression_continuation(after_trivia));
        if !terminated {
            return false;
        }
        if directive == "use strict" {
            return true;
        }

        source = if let Some(rest) = after_trivia.strip_prefix(';') {
            rest
        } else if saw_line_terminator {
            after_trivia
        } else {
            return false;
        };
    }
}

/// Conservative native-stack bound per recursion level for the recursive
/// descent. Debug builds accumulate several parser frames per statement
/// level; the depth-64 wrapped do/if/do-while chain empirically exhausts a
/// 1 MiB thread under debug codegen, i.e. more than 16 KiB per level
/// (bd-47ae4).
const PARSE_STACK_BYTES_PER_RECURSION_LEVEL: usize = 64 * 1024;

/// Fixed headroom for lexing, logical-line scanning, and the frames below
/// the statement recursion.
const PARSE_STACK_BASE_BYTES: usize = 4 * 1024 * 1024;

/// Run parse-shaped recursive work with a native stack provisioned from the
/// declared recursion budget (bd-47ae4).
///
/// The `max_recursion_depth` guard returns a recoverable [`ParseError`], but
/// only if it is reached BEFORE the OS stack overflows. Callers routinely run
/// the parser on small stacks (test-harness worker threads default to 2 MiB),
/// where a within-budget chain aborted the whole process with SIGABRT —
/// fail-open at the process boundary. Executing the work on a dedicated
/// scoped thread sized from the budget makes the guard, not the OS, the
/// terminating authority regardless of the caller's stack. The event-IR and
/// witness materializers recurse over the produced tree with the same depth
/// profile, so entry points wrap tree + event-IR construction in ONE
/// provisioned scope rather than only the descent. If the thread cannot be
/// spawned the work degrades to the caller's stack, which is exactly the
/// pre-fix behavior.
fn with_provisioned_parse_stack<T, F>(options: &ParserOptions, run: F) -> T
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    let budget_depth = usize::try_from(options.budget.max_recursion_depth).unwrap_or(usize::MAX);
    let stack_bytes = PARSE_STACK_BASE_BYTES
        .saturating_add(budget_depth.saturating_mul(PARSE_STACK_BYTES_PER_RECURSION_LEVEL));
    // The slot lets the closure survive a failed spawn (Builder::spawn_scoped
    // consumes its argument even on error); the mutex is uncontended — only
    // one of the two arms ever takes it.
    let run_slot = std::sync::Mutex::new(Some(run));
    let take_and_run = || {
        (run_slot
            .lock()
            .expect("parse closure slot is never poisoned")
            .take()
            .expect("parse closure is consumed exactly once"))()
    };
    std::thread::scope(|scope| {
        match std::thread::Builder::new()
            .name("franken-core-parse".to_string())
            .stack_size(stack_bytes)
            .spawn_scoped(scope, take_and_run)
        {
            Ok(handle) => handle
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
            Err(_) => take_and_run(),
        }
    })
}

fn parse_source(
    text: &str,
    source_label: &str,
    goal: ParseGoal,
    options: &ParserOptions,
) -> ParseResult<SyntaxTree> {
    with_provisioned_parse_stack(options, || {
        parse_source_on_current_stack(text, source_label, goal, options)
    })
}

fn parse_source_on_current_stack(
    text: &str,
    source_label: &str,
    goal: ParseGoal,
    options: &ParserOptions,
) -> ParseResult<SyntaxTree> {
    if text.trim().is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::EmptySource,
            "source is empty after whitespace normalization",
            source_label.to_string(),
            None,
        ));
    }

    let source_bytes = to_u64(text.len(), source_label, None)?;
    let token_count = count_lexical_tokens(text);
    let mut context = ParseExecutionContext {
        source_label,
        options,
        goal,
        strict_mode: goal == ParseGoal::Module || has_use_strict_directive(text),
        await_identifier_reserved: goal == ParseGoal::Module,
        yield_identifier_reserved: false,
        allow_await_expression: goal == ParseGoal::Module,
        allow_yield_expression: false,
        source_bytes,
        token_count,
        max_recursion_observed: 0,
        statement_depth: 0,
        pattern_depth: 0,
    };

    if source_bytes > options.budget.max_source_bytes {
        return Err(ParseError::with_witness(
            ParseErrorCode::BudgetExceeded,
            format!(
                "source byte budget exceeded: source_bytes={} max_source_bytes={}",
                source_bytes, options.budget.max_source_bytes
            ),
            source_label.to_string(),
            None,
            context.witness(Some(ParseBudgetKind::SourceBytes)),
        ));
    }

    if token_count > options.budget.max_token_count {
        return Err(ParseError::with_witness(
            ParseErrorCode::BudgetExceeded,
            format!(
                "token budget exceeded: token_count={} max_token_count={}",
                token_count, options.budget.max_token_count
            ),
            source_label.to_string(),
            None,
            context.witness(Some(ParseBudgetKind::TokenCount)),
        ));
    }

    let completion_recursion_limit =
        usize::try_from(context.options.budget.max_recursion_depth).unwrap_or(usize::MAX);
    let logical_lines = merge_logical_lines_with_completion_limit(
        text,
        ScanGrammarContext::from_execution_context(&context),
        completion_recursion_limit,
    );
    let source_line_starts = source_line_start_offsets(text);
    let mut statements = Vec::new();

    for logical_line in &logical_lines {
        let logical_line_starts = logical_line_start_offsets(&logical_line.text);
        for (start_in_line, end_in_line, statement_text) in
            split_statement_segments_with_completion_limit(
                &logical_line.text,
                ScanGrammarContext::from_execution_context(&context),
                completion_recursion_limit,
            )
        {
            let (start_line, start_column) =
                logical_line_position(&logical_line_starts, logical_line.start_line, start_in_line);
            let (end_line, end_column) =
                logical_line_position(&logical_line_starts, logical_line.start_line, end_in_line);
            let span = SourceSpan::new(
                source_offset_at_position(&source_line_starts, start_line, start_column)
                    .unwrap_or_else(|| {
                        logical_line
                            .byte_offset
                            .saturating_add(start_in_line as u64)
                    }),
                source_offset_at_position(&source_line_starts, end_line, end_column)
                    .unwrap_or_else(|| logical_line.byte_offset.saturating_add(end_in_line as u64)),
                start_line,
                start_column,
                end_line,
                end_column,
            );
            statements.extend(parse_module_statement_segment(
                statement_text,
                goal,
                span,
                &mut context,
            )?);
        }
    }

    let source_len = to_u64(text.len(), source_label, None)?;
    let (end_line, end_column) =
        source_end_position(&source_line_starts, source_len, source_label)?;
    let span = SourceSpan::new(0, source_len, 1, 1, end_line, end_column);
    Ok(SyntaxTree {
        goal,
        body: statements,
        span,
    })
}

/// Keep exported declarations in the same declaration-plus-export form used
/// by the engine twin. Binding resolution and function hoisting then see the
/// original declaration, including its async/generator flags.
fn parse_module_statement_segment(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Vec<Statement>> {
    if goal == ParseGoal::Module
        && let Some(declaration_text) = clause_keyword_tail(
            statement,
            "export",
            ScanGrammarContext::from_execution_context(context),
        )
        && (parse_variable_declaration_kind(declaration_text).is_some()
            || starts_named_exportable_declaration(declaration_text))
    {
        let prefix = &statement[..statement.len().saturating_sub(declaration_text.len())];
        let terminators = source_line_terminator_ranges(prefix);
        let start_line = span.start_line.saturating_add(terminators.len() as u64);
        let start_column = terminators.last().map_or_else(
            || span.start_column.saturating_add(prefix.len() as u64),
            |(_, end)| prefix.len().saturating_sub(*end).saturating_add(1) as u64,
        );
        let declaration_span = SourceSpan::new(
            span.start_offset.saturating_add(prefix.len() as u64),
            span.end_offset,
            start_line,
            start_column,
            span.end_line,
            span.end_column,
        );
        let declaration = parse_statement(declaration_text, goal, declaration_span, context)?;
        let names: Vec<String> = match &declaration {
            Statement::VariableDeclaration(declaration) => declaration
                .declarations
                .iter()
                .flat_map(|declarator| declarator.pattern.binding_names())
                .map(str::to_string)
                .collect(),
            Statement::FunctionDeclaration(function) => function.name.iter().cloned().collect(),
            Statement::ClassDeclaration(class) => class.name.iter().cloned().collect(),
            _ => Vec::new(),
        };
        if names.is_empty() {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "named export declaration must introduce at least one binding",
                context.source_label.to_string(),
                Some(span),
            ));
        }
        return Ok(vec![
            declaration,
            Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause(format!("{{ {} }}", names.join(", ")).into()),
                span,
            }),
        ]);
    }

    Ok(vec![parse_statement(statement, goal, span, context)?])
}

fn starts_named_exportable_declaration(statement: &str) -> bool {
    starts_with_keyword(statement, "function")
        || strip_async_function_keyword(statement).is_some()
        || starts_with_keyword(statement, "class")
}

fn starts_with_export_block_statement(text: &str, grammar_context: ScanGrammarContext) -> bool {
    let Some(rest) = clause_keyword_tail(text, "export", grammar_context) else {
        return false;
    };
    let declaration = clause_keyword_tail(rest, "default", grammar_context).unwrap_or(rest);
    starts_named_exportable_declaration(declaration)
}

fn source_line_start_offsets(source: &str) -> Vec<u64> {
    let mut offsets = vec![0];
    offsets.extend(
        source_line_terminator_ranges(source)
            .into_iter()
            .map(|(_, end)| end as u64),
    );
    offsets
}

fn source_end_position(
    line_starts: &[u64],
    source_len: u64,
    source_label: &str,
) -> ParseResult<(u64, u64)> {
    let end_line = to_u64(line_starts.len(), source_label, None)?;
    let final_line_start = line_starts.last().copied().unwrap_or(0);
    let end_column = source_len
        .saturating_sub(final_line_start)
        .saturating_add(1);
    Ok((end_line, end_column))
}

fn logical_line_start_offsets(source: &str) -> Vec<usize> {
    let mut offsets = vec![0];
    offsets.extend(
        source_line_terminator_ranges(source)
            .into_iter()
            .map(|(_, end)| end),
    );
    offsets
}

fn logical_line_position(line_starts: &[usize], first_line: u64, offset: usize) -> (u64, u64) {
    let line_index = line_starts
        .partition_point(|line_start| *line_start <= offset)
        .saturating_sub(1);
    let line = first_line.saturating_add(line_index as u64);
    let column = offset
        .saturating_sub(line_starts.get(line_index).copied().unwrap_or(0))
        .saturating_add(1) as u64;
    (line, column)
}

fn source_offset_at_position(line_starts: &[u64], line: u64, column: u64) -> Option<u64> {
    let line_index = usize::try_from(line.checked_sub(1)?).ok()?;
    line_starts
        .get(line_index)
        .copied()
        .map(|start| start.saturating_add(column.saturating_sub(1)))
}

#[cfg(test)]
fn line_count(source: &str) -> u64 {
    (source_line_terminator_ranges(source).len() as u64).saturating_add(1)
}

fn find_top_level_keyword_indices_with_context(
    source: &str,
    keyword: &str,
    grammar_context: ScanGrammarContext,
) -> Vec<usize> {
    let mut found = Vec::new();
    let mut previous_significant = None;
    scan_binding_pattern_source_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            if !quoted
                && depth == 0
                && previous_significant != Some('.')
                && source[index..].starts_with(keyword)
                && !source[..index]
                    .chars()
                    .next_back()
                    .is_some_and(is_identifier_part_character)
                && !starts_identifier_part(&source[index + keyword.len()..])
            {
                found.push(index);
            }
            if !quoted && !is_binding_pattern_whitespace(ch) {
                previous_significant = Some(ch);
            }
        },
    );
    found
}

fn find_last_top_level_keyword_with_context(
    source: &str,
    keyword: &str,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    find_top_level_keyword_indices_with_context(source, keyword, grammar_context)
        .into_iter()
        .next_back()
}

#[cfg(test)]
const STATEMENT_COMPLETION_RECURSION_LIMIT: usize = 256;
type DoWhileCompletionMemo = BTreeMap<(usize, usize, usize), Option<usize>>;

fn statement_is_complete_before_clause_with_limit(
    source: &str,
    following: &str,
    grammar_context: ScanGrammarContext,
    remaining_depth: usize,
    memo: &mut DoWhileCompletionMemo,
) -> bool {
    if remaining_depth == 0 {
        return false;
    }
    let Some(source) = trim_binding_pattern_trivia_with_context(source, grammar_context) else {
        return false;
    };
    if starts_with_keyword(source, "do") {
        return do_while_statement_is_complete_with_limit(
            source,
            grammar_context,
            remaining_depth,
            memo,
        );
    }
    if starts_with_keyword(source, "if") {
        let Some(after_if) = clause_keyword_tail(source, "if", grammar_context) else {
            return false;
        };
        let Some((_, body)) = extract_balanced_with_context(after_if, '(', ')', grammar_context)
        else {
            return false;
        };
        let Some(body) = trim_binding_pattern_trivia_with_context(body, grammar_context) else {
            return false;
        };
        if body.is_empty() {
            return false;
        }
        for else_index in find_top_level_keyword_indices_with_context(body, "else", grammar_context)
        {
            if !statement_is_complete_before_clause_with_limit(
                &body[..else_index],
                "else",
                grammar_context,
                remaining_depth.saturating_sub(1),
                memo,
            ) {
                continue;
            }
            let Some(alternate) = clause_keyword_tail(&body[else_index..], "else", grammar_context)
            else {
                return false;
            };
            if alternate.is_empty() {
                return false;
            }
            return statement_is_complete_before_clause_with_limit(
                alternate,
                following,
                grammar_context,
                remaining_depth.saturating_sub(1),
                memo,
            );
        }
        if starts_with_keyword(following, "else") {
            return false;
        }
        return statement_is_complete_before_clause_with_limit(
            body,
            following,
            grammar_context,
            remaining_depth.saturating_sub(1),
            memo,
        );
    }
    for keyword in ["while", "for", "with", "switch"] {
        if !starts_with_keyword(source, keyword) {
            continue;
        }
        if parenthesized_statement_status(source, keyword, grammar_context)
            != Some(ParenthesizedStatementStatus::Complete)
        {
            return false;
        }
        let Some(tail) = clause_keyword_tail(source, keyword, grammar_context) else {
            return false;
        };
        let Some((_, body)) = extract_balanced_with_context(tail, '(', ')', grammar_context) else {
            return false;
        };
        let Some(body) = trim_binding_pattern_trivia_with_context(body, grammar_context) else {
            return false;
        };
        if body.is_empty() {
            return false;
        }
        return statement_is_complete_before_clause_with_limit(
            body,
            following,
            grammar_context,
            remaining_depth.saturating_sub(1),
            memo,
        );
    }
    advance_clause_statement(
        pending_clause_with_kind(PendingClauseKind::ElseAwaitStatement, 0),
        source,
        following,
        source.len(),
        false,
        (grammar_context, remaining_depth, memo),
    )
    .is_none()
}

#[cfg(test)]
fn do_while_statement_is_complete(source: &str, grammar_context: ScanGrammarContext) -> bool {
    do_while_statement_is_complete_with_recursion_limit(
        source,
        grammar_context,
        STATEMENT_COMPLETION_RECURSION_LIMIT,
    )
}

#[cfg(test)]
fn do_while_statement_is_complete_with_recursion_limit(
    source: &str,
    grammar_context: ScanGrammarContext,
    recursion_limit: usize,
) -> bool {
    let mut memo = BTreeMap::new();
    do_while_statement_is_complete_with_limit(source, grammar_context, recursion_limit, &mut memo)
}

fn do_while_statement_is_complete_with_limit(
    source: &str,
    grammar_context: ScanGrammarContext,
    remaining_depth: usize,
    memo: &mut DoWhileCompletionMemo,
) -> bool {
    if remaining_depth == 0 {
        return false;
    }
    let source = trim_directive_trivia(source).0;
    do_while_statement_complete_prefix_with_limit(source, grammar_context, remaining_depth, memo)
        .is_some_and(|end| {
            let rest = trim_directive_trivia(&source[end..]).0;
            rest.is_empty() || rest == ";"
        })
}

fn do_while_statement_complete_prefix_with_limit(
    source: &str,
    grammar_context: ScanGrammarContext,
    remaining_depth: usize,
    memo: &mut DoWhileCompletionMemo,
) -> Option<usize> {
    if remaining_depth == 0 {
        return None;
    }
    let source = trim_directive_trivia(source).0;
    let memo_key = (source.as_ptr() as usize, source.len(), remaining_depth);
    if let Some(cached) = memo.get(&memo_key) {
        return *cached;
    }
    let result =
        do_while_statement_complete_prefix_uncached(source, grammar_context, remaining_depth, memo);
    memo.insert(memo_key, result);
    result
}

fn do_while_statement_complete_prefix_uncached(
    source: &str,
    grammar_context: ScanGrammarContext,
    remaining_depth: usize,
    memo: &mut DoWhileCompletionMemo,
) -> Option<usize> {
    let after_do = clause_keyword_tail(source, "do", grammar_context)?;
    for while_index in
        find_top_level_keyword_indices_with_context(after_do, "while", grammar_context)
    {
        let body =
            trim_binding_pattern_trivia_with_context(&after_do[..while_index], grammar_context)?;
        if body.is_empty()
            || !statement_is_complete_before_clause_with_limit(
                body,
                "while",
                grammar_context,
                remaining_depth.saturating_sub(1),
                memo,
            )
        {
            continue;
        }
        let Some(after_while) =
            clause_keyword_tail(&after_do[while_index..], "while", grammar_context)
        else {
            continue;
        };
        let Some((_, rest)) = extract_balanced_with_context(after_while, '(', ')', grammar_context)
        else {
            continue;
        };
        return Some((rest.as_ptr() as usize).saturating_sub(source.as_ptr() as usize));
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingStatementClauseKind {
    IfElse,
    DoWhile,
    TryHandler,
    CatchFinally,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingStatementClause {
    kind: PendingStatementClauseKind,
    start_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveDoWhileTrailer {
    do_start: usize,
    condition_started: bool,
    condition_end: Option<usize>,
}

impl ActiveDoWhileTrailer {
    fn awaiting_condition(do_start: usize) -> Self {
        Self {
            do_start,
            condition_started: false,
            condition_end: None,
        }
    }
}

fn direct_statement_wrapper_prefix_owns_child(
    source: &str,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
) -> bool {
    let Some(mut prefix) = trim_binding_pattern_trivia_with_context(source, grammar_context) else {
        return false;
    };
    for _ in 0..completion_recursion_limit {
        if prefix.is_empty() {
            return true;
        }
        let Some(wrapper) = ["if", "while", "for", "with"]
            .into_iter()
            .find(|keyword| starts_with_keyword(prefix, keyword))
        else {
            return false;
        };
        let Some(wrapper_tail) = clause_keyword_tail(prefix, wrapper, grammar_context) else {
            return false;
        };
        let Some((_, next_prefix)) =
            extract_balanced_with_context(wrapper_tail, '(', ')', grammar_context)
        else {
            return false;
        };
        let Some(next_prefix) =
            trim_binding_pattern_trivia_with_context(next_prefix, grammar_context)
        else {
            return false;
        };
        prefix = next_prefix;
    }
    false
}

fn take_pending_statement_clause(
    pending: &mut Vec<PendingStatementClause>,
    kind: PendingStatementClauseKind,
) -> Option<PendingStatementClause> {
    let index = pending
        .iter()
        .rposition(|candidate| candidate.kind == kind)?;
    let clause = pending[index];
    pending.truncate(index);
    Some(clause)
}

fn consume_pending_statement_clause(
    pending: &mut Vec<PendingStatementClause>,
    kind: PendingStatementClauseKind,
) -> bool {
    take_pending_statement_clause(pending, kind).is_some()
}

fn transition_pending_statement_clause(
    pending: &mut Vec<PendingStatementClause>,
    from: PendingStatementClauseKind,
    to: PendingStatementClauseKind,
) -> bool {
    let Some(index) = pending.iter().rposition(|clause| clause.kind == from) else {
        return false;
    };
    let clause = pending[index];
    pending.truncate(index);
    pending.push(PendingStatementClause {
        kind: to,
        start_index: clause.start_index,
    });
    true
}

fn consume_pending_try_finalizer(pending: &mut Vec<PendingStatementClause>) -> bool {
    let Some(index) = pending.iter().rposition(|clause| {
        matches!(
            clause.kind,
            PendingStatementClauseKind::TryHandler | PendingStatementClauseKind::CatchFinally
        )
    }) else {
        return false;
    };
    pending.truncate(index);
    true
}

fn pending_try_clause_continues(
    pending: &mut Vec<PendingStatementClause>,
    following: &str,
) -> bool {
    if starts_with_keyword(following, "catch") {
        transition_pending_statement_clause(
            pending,
            PendingStatementClauseKind::TryHandler,
            PendingStatementClauseKind::CatchFinally,
        )
    } else if starts_with_keyword(following, "finally") {
        consume_pending_try_finalizer(pending)
    } else {
        false
    }
}

fn retire_completed_do_while_clauses(
    pending: &mut Vec<PendingStatementClause>,
    source: &str,
    statement_end: usize,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
    memo: &mut DoWhileCompletionMemo,
) {
    while let Some(index) = pending
        .iter()
        .rposition(|clause| clause.kind == PendingStatementClauseKind::DoWhile)
    {
        let clause = pending[index];
        if do_while_statement_complete_prefix_with_limit(
            &source[clause.start_index..statement_end],
            grammar_context,
            completion_recursion_limit,
            memo,
        )
        .is_none()
        {
            break;
        }
        pending.truncate(index);
    }
}

fn is_label_identifier_in_scan_context(name: &str, grammar_context: ScanGrammarContext) -> bool {
    !is_always_reserved_word(name)
        && !(grammar_context.strict && is_strict_reserved_word(name))
        && !(name == "await" && grammar_context.await_mode != ContextualKeywordScanMode::Identifier)
        && !(name == "yield" && grammar_context.yield_mode != ContextualKeywordScanMode::Identifier)
}

/// Strip one or more leading `label:` prefixes from a statement segment.
///
/// The segment splitter uses the returned inner statement solely to decide
/// whether a closing brace terminates the segment. Keeping label recognition
/// grammar-aware prevents a ternary or a contextually reserved word from being
/// mistaken for a label while allowing nested labels around compound bodies.
fn strip_leading_labels(segment: &str, grammar_context: ScanGrammarContext) -> &str {
    let mut segment = trim_directive_trivia(segment).0;
    loop {
        let Some(colon_index) = find_top_level_colon_with_context(segment, grammar_context) else {
            return segment;
        };
        let label_source = segment[..colon_index].trim();
        let Some(label) = canonical_source_identifier_name(label_source) else {
            return segment;
        };
        if !is_label_identifier_in_scan_context(&label, grammar_context) {
            return segment;
        }
        segment = trim_directive_trivia(&segment[colon_index + 1..]).0;
    }
}

#[cfg(test)]
fn split_statement_segments_with_context(
    line: &str,
    grammar_context: ScanGrammarContext,
) -> Vec<(usize, usize, &str)> {
    split_statement_segments_with_completion_limit(
        line,
        grammar_context,
        STATEMENT_COMPLETION_RECURSION_LIMIT,
    )
}

fn split_statement_segments_with_completion_limit(
    line: &str,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
) -> Vec<(usize, usize, &str)> {
    let mut completion_memo = BTreeMap::new();
    split_statement_segments_with_completion_limit_and_memo(
        line,
        grammar_context,
        completion_recursion_limit,
        &mut completion_memo,
    )
}

fn split_statement_segments_with_completion_limit_and_memo<'a>(
    line: &'a str,
    grammar_context: ScanGrammarContext,
    completion_recursion_limit: usize,
    completion_memo: &mut DoWhileCompletionMemo,
) -> Vec<(usize, usize, &'a str)> {
    let mut out = Vec::new();
    let mut segment_start = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut pending_statement_clauses: Vec<PendingStatementClause> = Vec::new();
    let mut previous_significant = None;
    let mut previous_significant_end = segment_start;
    let mut active_do_while_trailer: Option<ActiveDoWhileTrailer> = None;

    scan_binding_pattern_source_with_context(line, grammar_context, |index, ch, depth, quoted| {
        if quoted {
            let begins_comment = line[index..].starts_with("//") || line[index..].starts_with("/*");
            if !begins_comment
                && let Some(condition_end) =
                    active_do_while_trailer.and_then(|active| active.condition_end)
                && index >= condition_end
                && trim_binding_pattern_trivia_with_context(
                    &line[condition_end..index],
                    grammar_context,
                )
                .is_some_and(str::is_empty)
            {
                push_segment(&mut out, line, segment_start, index, grammar_context);
                segment_start = index;
                pending_statement_clauses.clear();
                previous_significant = None;
                previous_significant_end = index;
                active_do_while_trailer = None;
            }
            return;
        }
        if depth == 0 && async_function_asi_boundary(line, segment_start, index, grammar_context) {
            push_segment(&mut out, line, segment_start, index, grammar_context);
            segment_start = index;
            pending_statement_clauses.clear();
            previous_significant = None;
            previous_significant_end = index;
            active_do_while_trailer = None;
        }
        let starts_do = depth == 0
            && previous_significant != Some('.')
            && line[index..].starts_with("do")
            && !line[..index]
                .chars()
                .next_back()
                .is_some_and(is_identifier_part_character)
            && !starts_identifier_part(&line[index + "do".len()..]);
        let starts_while = depth == 0
            && previous_significant != Some('.')
            && line[index..].starts_with("while")
            && !line[..index]
                .chars()
                .next_back()
                .is_some_and(is_identifier_part_character)
            && !starts_identifier_part(&line[index + "while".len()..]);
        let starts_if = depth == 0
            && previous_significant != Some('.')
            && line[index..].starts_with("if")
            && !line[..index]
                .chars()
                .next_back()
                .is_some_and(is_identifier_part_character)
            && !starts_identifier_part(&line[index + "if".len()..]);
        let starts_try = depth == 0
            && previous_significant != Some('.')
            && line[index..].starts_with("try")
            && !line[..index]
                .chars()
                .next_back()
                .is_some_and(is_identifier_part_character)
            && !starts_identifier_part(&line[index + "try".len()..]);
        let starts_else = depth == 0
            && previous_significant != Some('.')
            && line[index..].starts_with("else")
            && !line[..index]
                .chars()
                .next_back()
                .is_some_and(is_identifier_part_character)
            && !starts_identifier_part(&line[index + "else".len()..]);

        let mut claimed_current_while = false;
        if !is_binding_pattern_whitespace(ch)
            && let Some(active) = active_do_while_trailer
            && let Some(condition_end) = active.condition_end
            && index >= condition_end
            && trim_binding_pattern_trivia_with_context(
                &line[condition_end..index],
                grammar_context,
            )
            .is_some_and(str::is_empty)
            && ch != ';'
        {
            if starts_while {
                let parent_index = pending_statement_clauses.iter().rposition(|clause| {
                    clause.kind == PendingStatementClauseKind::DoWhile
                        && clause.start_index < active.do_start
                });
                let parent_body_is_complete = parent_index.is_some_and(|parent_index| {
                    let parent = pending_statement_clauses[parent_index];
                    let direct_or_wrapped_body = clause_keyword_tail(
                        &line[parent.start_index..active.do_start],
                        "do",
                        grammar_context,
                    )
                    .is_some_and(|body_prefix| {
                        direct_statement_wrapper_prefix_owns_child(
                            body_prefix,
                            grammar_context,
                            completion_recursion_limit,
                        )
                    });
                    direct_or_wrapped_body
                        || clause_keyword_tail(
                            &line[parent.start_index..index],
                            "do",
                            grammar_context,
                        )
                        .is_some_and(|body| {
                            statement_is_complete_before_clause_with_limit(
                                body,
                                "while",
                                grammar_context,
                                completion_recursion_limit,
                                completion_memo,
                            )
                        })
                });
                if parent_body_is_complete {
                    let parent_index =
                        parent_index.expect("a complete parent body requires a pending do");
                    let parent = pending_statement_clauses[parent_index];
                    pending_statement_clauses.truncate(parent_index);
                    active_do_while_trailer =
                        Some(ActiveDoWhileTrailer::awaiting_condition(parent.start_index));
                    claimed_current_while = true;
                } else {
                    push_segment(&mut out, line, segment_start, index, grammar_context);
                    segment_start = index;
                    pending_statement_clauses.clear();
                    previous_significant = None;
                    previous_significant_end = index;
                    active_do_while_trailer = None;
                }
            } else if starts_else
                && consume_pending_statement_clause(
                    &mut pending_statement_clauses,
                    PendingStatementClauseKind::IfElse,
                )
            {
                active_do_while_trailer = None;
            } else if ch != '}' {
                push_segment(&mut out, line, segment_start, index, grammar_context);
                segment_start = index;
                pending_statement_clauses.clear();
                previous_significant = None;
                previous_significant_end = index;
                active_do_while_trailer = None;
            }
        }

        if starts_while
            && !claimed_current_while
            && active_do_while_trailer.is_none()
            && !source_line_terminator_ranges(&line[previous_significant_end..index]).is_empty()
            && let Some(do_index) = pending_statement_clauses
                .iter()
                .rposition(|clause| clause.kind == PendingStatementClauseKind::DoWhile)
        {
            let clause = pending_statement_clauses[do_index];
            let body_is_complete =
                clause_keyword_tail(&line[clause.start_index..index], "do", grammar_context)
                    .is_some_and(|body| {
                        statement_is_complete_before_clause_with_limit(
                            body,
                            "while",
                            grammar_context,
                            completion_recursion_limit,
                            completion_memo,
                        )
                    });
            if body_is_complete {
                pending_statement_clauses.truncate(do_index);
                active_do_while_trailer =
                    Some(ActiveDoWhileTrailer::awaiting_condition(clause.start_index));
            }
        }

        if starts_do {
            pending_statement_clauses.push(PendingStatementClause {
                kind: PendingStatementClauseKind::DoWhile,
                start_index: index,
            });
        }
        if starts_if {
            pending_statement_clauses.push(PendingStatementClause {
                kind: PendingStatementClauseKind::IfElse,
                start_index: index,
            });
        }
        if starts_try {
            pending_statement_clauses.push(PendingStatementClause {
                kind: PendingStatementClauseKind::TryHandler,
                start_index: index,
            });
        }
        let mut split_segment = false;
        match ch {
            '(' => {
                if paren_depth == 0
                    && let Some(active) = active_do_while_trailer.as_mut()
                    && !active.condition_started
                {
                    active.condition_started = true;
                }
                paren_depth = paren_depth.saturating_add(1);
            }
            ')' => {
                paren_depth = paren_depth.saturating_sub(1);
                if paren_depth == 0
                    && let Some(active) = active_do_while_trailer.as_mut()
                    && active.condition_started
                    && active.condition_end.is_none()
                {
                    active.condition_end = Some(index.saturating_add(ch.len_utf8()));
                }
            }
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => {
                let was_positive = brace_depth > 0;
                brace_depth = brace_depth.saturating_sub(1);
                // A closing brace that returns to brace_depth==0 may
                // terminate a block-level statement (function decl,
                // if/else, for, while, etc.).  Only split here when the
                // CURRENT segment starts with a block keyword so we
                // don't break function expressions or object literals
                // embedded in larger expressions.
                if was_positive && brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 {
                    let seg = trim_directive_trivia(&line[segment_start..]).0;
                    let segment_body = strip_leading_labels(seg, grammar_context);
                    let starts_with_block = starts_with_keyword(segment_body, "function")
                        || strip_async_function_keyword(segment_body).is_some()
                        || segment_body.starts_with('{')
                        || starts_with_keyword(segment_body, "if")
                        || starts_with_keyword(segment_body, "for")
                        || starts_with_keyword(segment_body, "while")
                        || starts_with_keyword(segment_body, "with")
                        || starts_with_keyword(segment_body, "do")
                        || starts_with_keyword(segment_body, "try")
                        || starts_with_keyword(segment_body, "switch")
                        || starts_with_keyword(segment_body, "class")
                        || starts_with_export_block_statement(segment_body, grammar_context);
                    if starts_with_block {
                        let after = index.saturating_add(1);
                        let rest_with_trivia = &line[after..];
                        let rest = trim_directive_trivia(rest_with_trivia).0;
                        let pending_clause_continues =
                            if pending_try_clause_continues(&mut pending_statement_clauses, rest) {
                                true
                            } else if starts_with_keyword(rest, "while") {
                                let consumed = take_pending_statement_clause(
                                    &mut pending_statement_clauses,
                                    PendingStatementClauseKind::DoWhile,
                                );
                                if let Some(clause) = consumed {
                                    active_do_while_trailer =
                                        Some(ActiveDoWhileTrailer::awaiting_condition(
                                            clause.start_index,
                                        ));
                                }
                                consumed.is_some()
                            } else if starts_with_keyword(rest, "else") {
                                consume_pending_statement_clause(
                                    &mut pending_statement_clauses,
                                    PendingStatementClauseKind::IfElse,
                                )
                            } else {
                                false
                            };
                        let continues =
                            statement_clause_continues(seg, rest) || pending_clause_continues;
                        if !rest_with_trivia.trim_start().is_empty() && !continues {
                            push_segment(&mut out, line, segment_start, after, grammar_context);
                            segment_start = after;
                            pending_statement_clauses.clear();
                            previous_significant = None;
                            previous_significant_end = after;
                            active_do_while_trailer = None;
                            split_segment = true;
                        }
                    }
                }
            }
            ';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                let after = index.saturating_add(ch.len_utf8());
                let rest = trim_directive_trivia(&line[after..]).0;
                let terminates_active_trailer = active_do_while_trailer
                    .and_then(|active| active.condition_end)
                    .is_some_and(|condition_end| {
                        trim_binding_pattern_trivia_with_context(
                            &line[condition_end..index],
                            grammar_context,
                        )
                        .is_some_and(str::is_empty)
                    });
                if !terminates_active_trailer {
                    retire_completed_do_while_clauses(
                        &mut pending_statement_clauses,
                        line,
                        index,
                        grammar_context,
                        completion_recursion_limit,
                        completion_memo,
                    );
                }
                active_do_while_trailer = None;
                let continues = if starts_with_keyword(rest, "while") {
                    let consumed = take_pending_statement_clause(
                        &mut pending_statement_clauses,
                        PendingStatementClauseKind::DoWhile,
                    );
                    if let Some(clause) = consumed {
                        active_do_while_trailer =
                            Some(ActiveDoWhileTrailer::awaiting_condition(clause.start_index));
                    }
                    consumed.is_some()
                } else if starts_with_keyword(rest, "else") {
                    consume_pending_statement_clause(
                        &mut pending_statement_clauses,
                        PendingStatementClauseKind::IfElse,
                    )
                } else {
                    false
                };
                if !continues {
                    push_segment(&mut out, line, segment_start, index, grammar_context);
                    segment_start = after;
                    pending_statement_clauses.clear();
                    previous_significant = None;
                    previous_significant_end = after;
                    active_do_while_trailer = None;
                    split_segment = true;
                }
            }
            _ => {}
        }
        if !split_segment && !is_binding_pattern_whitespace(ch) {
            previous_significant = Some(ch);
            previous_significant_end = index.saturating_add(ch.len_utf8());
        }
    });
    push_segment(&mut out, line, segment_start, line.len(), grammar_context);
    out
}

#[cfg(test)]
fn split_statement_segments(line: &str) -> Vec<(usize, usize, &str)> {
    split_statement_segments_with_context(line, ScanGrammarContext::SLOPPY_SCRIPT)
}

fn async_function_asi_boundary(
    line: &str,
    segment_start: usize,
    function_start: usize,
    grammar_context: ScanGrammarContext,
) -> bool {
    if !starts_with_keyword(&line[function_start..], "function") {
        return false;
    }
    let prefix = &line[segment_start..function_start];
    let Some((_, significant_end)) =
        binding_pattern_trivia_bounds_with_context(prefix, grammar_context)
    else {
        return false;
    };
    let significant = &prefix[..significant_end];
    if canonical_trailing_source_identifier(significant).as_deref() != Some("async") {
        return false;
    }
    let (remaining, saw_line_terminator) = trim_directive_trivia(&prefix[significant_end..]);
    saw_line_terminator && remaining.is_empty()
}

fn canonical_trailing_source_identifier(source: &str) -> Option<String> {
    source.char_indices().find_map(|(start, _)| {
        if source[..start]
            .chars()
            .next_back()
            .is_some_and(is_identifier_part_character)
        {
            return None;
        }
        canonical_leading_source_identifier(&source[start..])
            .filter(|(_, consumed)| start.saturating_add(*consumed) == source.len())
            .map(|(identifier, _)| identifier)
    })
}

/// Returns true when `text` starts with `kw` and the next source character is
/// not an ECMAScript IdentifierPart (or `kw` reaches the end of the string).
fn starts_with_keyword(text: &str, kw: &str) -> bool {
    text.strip_prefix(kw)
        .is_some_and(|rest| !starts_identifier_part(rest))
}

fn push_segment<'a>(
    out: &mut Vec<(usize, usize, &'a str)>,
    line: &'a str,
    start: usize,
    end: usize,
    grammar_context: ScanGrammarContext,
) {
    if end < start {
        return;
    }
    let raw = &line[start..end];
    let (trimmed_start, trimmed_end) = if let Some((lexical_start, lexical_end)) =
        binding_pattern_trivia_bounds_with_context(raw, grammar_context)
    {
        (
            start.saturating_add(lexical_start),
            start.saturating_add(lexical_end),
        )
    } else {
        // Preserve incomplete lexical input for the parser's diagnostic
        // path instead of dropping it as if it were complete trivia.
        let leading = raw.len().saturating_sub(raw.trim_start().len());
        let trailing = raw.len().saturating_sub(raw.trim_end().len());
        (start.saturating_add(leading), end.saturating_sub(trailing))
    };
    if trimmed_end <= trimmed_start {
        return;
    }
    let trimmed = &line[trimmed_start..trimmed_end];
    out.push((trimmed_start, trimmed_end, trimmed));
}

#[allow(dead_code)]
fn span_for_segment(
    line_start_offset: usize,
    line_no: u64,
    start_in_line: usize,
    end_in_line: usize,
    source_label: &str,
) -> ParseResult<SourceSpan> {
    let start_offset = line_start_offset
        .checked_add(start_in_line)
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::SourceTooLarge,
                "source offset overflow",
                source_label.to_string(),
                None,
            )
        })
        .and_then(|v| to_u64(v, source_label, None))?;
    let end_offset = line_start_offset
        .checked_add(end_in_line)
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::SourceTooLarge,
                "source offset overflow",
                source_label.to_string(),
                None,
            )
        })
        .and_then(|v| to_u64(v, source_label, None))?;
    let start_column = to_u64(start_in_line.saturating_add(1), source_label, None)?;
    let end_column = to_u64(end_in_line.saturating_add(1), source_label, None)?;
    Ok(SourceSpan::new(
        start_offset,
        end_offset,
        line_no,
        start_column,
        line_no,
        end_column,
    ))
}

fn parse_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    // Guard against stack overflow from deeply nested statements (if/for/while/try/switch/fn).
    context.statement_depth += 1;
    if context.statement_depth > context.options.budget.max_recursion_depth {
        context.statement_depth -= 1;
        return Err(ParseError::new(
            ParseErrorCode::BudgetExceeded,
            format!(
                "statement nesting budget exceeded: depth={} max={}",
                context.statement_depth, context.options.budget.max_recursion_depth
            ),
            context.source_label.to_string(),
            Some(span),
        ));
    }
    let result = parse_statement_inner(statement, goal, span, context);
    context.statement_depth -= 1;
    result
}

fn parse_statement_inner(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let static_import = clause_keyword_tail(
        statement,
        "import",
        ScanGrammarContext::from_execution_context(context),
    )
    .is_some_and(|tail| !tail.starts_with('(') && !tail.starts_with('.'));
    if static_import {
        if goal == ParseGoal::Script {
            return Err(ParseError::new(
                ParseErrorCode::InvalidGoal,
                "import declarations are only valid in module goal",
                context.source_label.to_string(),
                Some(span),
            ));
        }
        return parse_import(statement, context.source_label, span).map(Statement::Import);
    }

    if starts_with_keyword(statement, "export") {
        if goal == ParseGoal::Script {
            return Err(ParseError::new(
                ParseErrorCode::InvalidGoal,
                "export declarations are only valid in module goal",
                context.source_label.to_string(),
                Some(span),
            ));
        }
        return parse_export(statement, span, context).map(Statement::Export);
    }

    if let Some(kind) = parse_variable_declaration_kind(statement) {
        return parse_variable_declaration(statement, kind, span, context)
            .map(Statement::VariableDeclaration);
    }

    if starts_with_keyword(statement, "catch") || starts_with_keyword(statement, "finally") {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "catch/finally clause requires a matching try statement",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    if starts_with_keyword(statement, "else") {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "else clause requires a matching if statement",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    // Control flow statement dispatch
    if statement.starts_with("if ") || statement.starts_with("if(") {
        return self::parse_if_statement(statement, goal, span, context);
    }
    if statement.starts_with("for ") || statement.starts_with("for(") {
        return self::parse_for_statement(statement, goal, span, context);
    }
    if statement.starts_with("while ") || statement.starts_with("while(") {
        return self::parse_while_statement(statement, goal, span, context);
    }
    if statement.starts_with("do ") || statement.starts_with("do{") {
        return self::parse_do_while_statement(statement, goal, span, context);
    }
    if statement == "return"
        || statement.starts_with("return ")
        || statement.starts_with("return;")
        || statement.starts_with("return(")
    {
        return self::parse_return_statement(statement, span, context);
    }
    if statement.starts_with("throw ") || statement.starts_with("throw(") {
        return self::parse_throw_statement(statement, span, context);
    }
    if statement.starts_with("try ") || statement.starts_with("try{") {
        return self::parse_try_catch_statement(statement, goal, span, context);
    }
    if statement.starts_with("switch ") || statement.starts_with("switch(") {
        return self::parse_switch_statement(statement, goal, span, context);
    }
    if statement == "break" || statement.starts_with("break ") || statement.starts_with("break;") {
        return self::parse_break_statement(statement, span, context);
    }
    if statement == "continue"
        || statement.starts_with("continue ")
        || statement.starts_with("continue;")
    {
        return self::parse_continue_statement(statement, span, context);
    }
    if starts_with_keyword(statement, "function")
        || strip_async_function_keyword(statement).is_some()
    {
        return self::parse_function_declaration(statement, span, context);
    }
    if starts_with_keyword(statement, "class") {
        return self::parse_class_declaration(statement, span, context);
    }
    if statement.starts_with('{') && statement.ends_with('}') {
        return self::parse_block_statement(statement, goal, span, context);
    }

    // Labelled statement: `label: <statement>` (ECMA-262 §14.13). A top-level
    // colon is a label delimiter only when its prefix is an IdentifierReference
    // in the current grammar context; ternaries and object-literal properties
    // therefore continue through the expression parser.
    let grammar_context = ScanGrammarContext::from_execution_context(context);
    if let Some(colon_index) = find_top_level_colon_with_context(statement, grammar_context) {
        let label_source = statement[..colon_index].trim();
        if let Some(label) = canonical_source_identifier_name(label_source) {
            if !is_context_identifier_reference(&label, context) {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "label must be an IdentifierReference in this grammar context",
                    context.source_label.to_string(),
                    Some(span),
                ));
            }
            let body_source = statement[colon_index + 1..].trim();
            if body_source.is_empty() {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "labelled statement is missing its body",
                    context.source_label.to_string(),
                    Some(span),
                ));
            }
            let body = parse_statement(body_source, goal, span.clone(), context)?;
            return Ok(Statement::Labeled(LabeledStatement {
                label,
                body: Box::new(body),
                span,
            }));
        }
    }

    let expression_source = statement.strip_suffix(';').unwrap_or(statement).trim();
    let expression = parse_expression_allowing_sequence(expression_source, &span, context, 1)?;
    Ok(Statement::Expression(ExpressionStatement {
        expression,
        span,
    }))
}

fn parse_import(
    statement: &str,
    source_label: &str,
    span: SourceSpan,
) -> ParseResult<ImportDeclaration> {
    let body =
        clause_keyword_tail(statement, "import", ScanGrammarContext::SLOPPY_SCRIPT).unwrap_or("");
    if body.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "import declaration is missing clause",
            source_label.to_string(),
            Some(span),
        ));
    }

    if let Some(source) = parse_quoted_string(body) {
        return Ok(ImportDeclaration {
            clause: ImportClause::SideEffect,
            binding: None,
            source,
            span,
        });
    }

    let (binding_raw, source_raw) = split_import_from_clause(body).ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "import declaration must be `import <binding-clause> from <quoted-source>` or `import <quoted-source>`",
            source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    let clause = parse_import_binding_clause(binding_raw.trim(), source_label, &span)?;
    let source = trim_binding_pattern_trivia(source_raw)
        .and_then(parse_quoted_string)
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "import source must be quoted",
                source_label.to_string(),
                Some(span.clone()),
            )
        })?;

    Ok(ImportDeclaration {
        binding: clause.primary_binding().map(str::to_string),
        clause,
        source,
        span,
    })
}

fn split_import_from_clause(body: &str) -> Option<(&str, &str)> {
    let mut split = None;
    scan_binding_pattern_source(body, |index, ch, depth, quoted| {
        if quoted || depth != 0 || ch != 'f' {
            return;
        }
        let Some(trailing) = body[index..].strip_prefix("from") else {
            return;
        };
        let starts_token = !body[..index]
            .chars()
            .next_back()
            .is_some_and(is_identifier_part_character);
        if starts_token && !starts_identifier_part(trailing) {
            // `from` is also a legal imported/local IdentifierName. The final
            // top-level token is the import-clause separator (`import from
            // from 'pkg'`, `import {from as local} from 'pkg'`).
            split = Some(index);
        }
    });
    let split = split?;
    Some((&body[..split], &body[split + "from".len()..]))
}

fn parse_import_binding_clause(
    binding_clause: &str,
    source_label: &str,
    span: &SourceSpan,
) -> ParseResult<ImportClause> {
    let binding_clause = trim_binding_pattern_trivia(binding_clause).ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "import binding clause has unterminated lexical trivia",
            source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    if binding_clause.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "import declaration is missing binding clause",
            source_label.to_string(),
            Some(span.clone()),
        ));
    }

    if let Some(local) = canonical_module_binding_identifier(binding_clause) {
        return Ok(ImportClause::Default { local });
    }

    if let Some(namespace_binding) = parse_namespace_import_binding(binding_clause) {
        return Ok(ImportClause::Namespace {
            local: namespace_binding,
        });
    }

    if is_named_import_clause(binding_clause) {
        let specifiers = parse_named_import_specifiers(binding_clause, source_label, span)?;
        return Ok(ImportClause::Named { specifiers });
    }

    let combined_clause_parts = split_top_level_commas(binding_clause);
    if let [default_binding_raw, trailing_clause_raw] = combined_clause_parts.as_slice() {
        let default_binding_source =
            trim_binding_pattern_trivia(default_binding_raw).ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "default import binding has unterminated lexical trivia",
                    source_label.to_string(),
                    Some(span.clone()),
                )
            })?;
        let trailing_clause =
            trim_binding_pattern_trivia(trailing_clause_raw).ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "combined import clause has unterminated lexical trivia",
                    source_label.to_string(),
                    Some(span.clone()),
                )
            })?;

        let Some(default_binding) = canonical_module_binding_identifier(default_binding_source)
        else {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "default import binding must be a non-keyword identifier",
                source_label.to_string(),
                Some(span.clone()),
            ));
        };

        if let Some(namespace_binding) = parse_namespace_import_binding(trailing_clause) {
            return Ok(ImportClause::DefaultAndNamespace {
                default: default_binding,
                namespace: namespace_binding,
            });
        }

        if is_named_import_clause(trailing_clause) {
            let specifiers = parse_named_import_specifiers(trailing_clause, source_label, span)?;
            return Ok(ImportClause::DefaultAndNamed {
                default: default_binding,
                specifiers,
            });
        }
    }

    Err(ParseError::new(
        ParseErrorCode::UnsupportedSyntax,
        "unsupported import binding clause; supported forms: default, namespace (`* as ns`), named (`{ a, b as c }`), and default+namespace/named",
        source_label.to_string(),
        Some(span.clone()),
    ))
}

fn parse_namespace_import_binding(clause: &str) -> Option<String> {
    let rest = trim_binding_pattern_leading_trivia(clause.strip_prefix('*')?)?;
    let rest = strip_contextual_keyword(rest, "as")?;
    canonical_module_binding_identifier(rest)
}

/// Named module lists allow one trailing comma, but never a missing entry.
/// Trim lexical trivia at each boundary without joining identifier tokens;
/// commas and braces inside comments must not become list delimiters.
fn named_module_specifier_entries(source: &str) -> Option<Vec<&str>> {
    let source = trim_binding_pattern_trivia(source)?;
    if source.is_empty() {
        return Some(Vec::new());
    }

    let mut entries = split_top_level_commas(source);
    if entries.len() > 1 && entries.last().is_some_and(|entry| entry.is_empty()) {
        entries.pop();
    }
    entries
        .into_iter()
        .map(|entry| trim_binding_pattern_trivia(entry).filter(|entry| !entry.is_empty()))
        .collect()
}

fn is_named_import_clause(clause: &str) -> bool {
    let clause = clause.trim();
    let Some(inner) = clause
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return false;
    };

    named_module_specifier_entries(inner).is_some_and(|entries| {
        entries
            .into_iter()
            .all(|specifier| parse_named_import_specifier_parts(specifier).is_some())
    })
}

fn parse_named_import_specifiers(
    clause: &str,
    source_label: &str,
    span: &SourceSpan,
) -> ParseResult<Vec<ImportSpecifier>> {
    let clause = clause.trim();
    let Some(inner) = clause
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "named import clause must be wrapped in `{}`",
            source_label.to_string(),
            Some(span.clone()),
        ));
    };

    let entries = named_module_specifier_entries(inner).ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "named import specifier list contains an empty entry or unterminated trivia",
            source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    let mut specifiers = Vec::with_capacity(entries.len());
    let mut seen_local = BTreeSet::new();

    for specifier in entries {
        let Some((import_name, local_name)) = parse_named_import_specifier_parts(specifier) else {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "unsupported named import specifier; expected `IdentifierName` or `IdentifierName as BindingIdentifier`",
                source_label.to_string(),
                Some(span.clone()),
            ));
        };

        if !seen_local.insert(local_name.clone()) {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "import binding has already been declared",
                source_label.to_string(),
                Some(span.clone()),
            ));
        }

        specifiers.push(ImportSpecifier {
            import_name,
            local_name,
        });
    }

    Ok(specifiers)
}

fn parse_named_import_specifier_parts(specifier: &str) -> Option<(String, String)> {
    let specifier = trim_binding_pattern_trivia(specifier)?;
    let (import_name, import_name_end) = canonical_leading_source_identifier(specifier)?;
    let trailing = trim_binding_pattern_leading_trivia(&specifier[import_name_end..])?;

    if trailing.is_empty() {
        let local_name = canonical_module_binding_identifier(specifier)?;
        return Some((import_name, local_name));
    }

    let local_source = strip_contextual_keyword(trailing, "as")?;
    let local_name = canonical_module_binding_identifier(local_source)?;
    Some((import_name, local_name))
}

fn parse_export(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<ExportDeclaration> {
    let grammar_context = ScanGrammarContext::from_execution_context(context);
    let body = clause_keyword_tail(statement, "export", grammar_context).unwrap_or("");
    if body.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "export declaration is missing clause",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    let kind = if let Some(default_expr) = clause_keyword_tail(body, "default", grammar_context) {
        ExportKind::Default(parse_expression(default_expr.trim(), &span, context, 1)?)
    } else {
        ExportKind::NamedClause(parse_named_export_clause(
            body,
            context.source_label,
            &span,
        )?)
    };
    Ok(ExportDeclaration { kind, span })
}

fn parse_named_export_clause(
    clause: &str,
    source_label: &str,
    span: &SourceSpan,
) -> ParseResult<NamedExportClause> {
    let clause = clause.trim();
    if !clause.starts_with('{') {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "named export clause must start with `{`",
            source_label.to_string(),
            Some(span.clone()),
        ));
    }

    let Some((specifiers, trailing)) =
        extract_balanced_with_context(clause, '{', '}', ScanGrammarContext::SLOPPY_SCRIPT)
    else {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "named export clause is missing `}`",
            source_label.to_string(),
            Some(span.clone()),
        ));
    };

    let canonical_specifiers = parse_named_export_specifiers(specifiers, source_label, span)?;
    // Keep historical wire spelling for already-supported lists. New trailing
    // commas, comments, and escaped names are emitted as validated identifiers
    // so consumers of canonical_head never need to re-lex source trivia.
    let legacy_specifiers: Vec<_> = specifiers.split(',').collect();
    let legacy_compatible = legacy_specifiers.len() == canonical_specifiers.len()
        && legacy_specifiers
            .iter()
            .zip(&canonical_specifiers)
            .all(|(source, canonical)| canonicalize_whitespace(source.trim()) == *canonical);
    let canonical_head =
        if legacy_compatible || (canonical_specifiers.is_empty() && specifiers.trim().is_empty()) {
            canonicalize_whitespace(&clause[..clause.len() - trailing.len()])
        } else if canonical_specifiers.is_empty() {
            "{}".to_string()
        } else {
            format!("{{ {} }}", canonical_specifiers.join(", "))
        };
    let trailing = trim_binding_pattern_trivia(trailing).ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "named export trailing clause has unterminated lexical trivia",
            source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let source = if !trailing.is_empty() {
        let Some(source_raw) = strip_contextual_keyword(trailing, "from") else {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "named export trailing clause must be `from <quoted-source>`",
                source_label.to_string(),
                Some(span.clone()),
            ));
        };

        let source = trim_binding_pattern_trivia(source_raw)
            .and_then(parse_quoted_string)
            .ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "export source must be quoted",
                    source_label.to_string(),
                    Some(span.clone()),
                )
            })?;
        Some(source)
    } else {
        None
    };

    Ok(NamedExportClause::new(canonical_head, source))
}

fn parse_named_export_specifiers(
    specifiers: &str,
    source_label: &str,
    span: &SourceSpan,
) -> ParseResult<Vec<String>> {
    let entries = named_module_specifier_entries(specifiers).ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "named export specifier list contains an empty entry or unterminated trivia",
            source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let mut canonical = Vec::with_capacity(entries.len());
    for specifier in entries {
        let (local, exported) = parse_named_export_specifier_parts(specifier).ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "unsupported named export specifier; expected `name` or `name as alias`",
                source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        canonical.push(match exported {
            Some(exported) => format!("{local} as {exported}"),
            None => local,
        });
    }

    Ok(canonical)
}

fn parse_named_export_specifier_parts(specifier: &str) -> Option<(String, Option<String>)> {
    let (local, local_end) = canonical_leading_source_identifier(specifier)?;
    let trailing = trim_binding_pattern_leading_trivia(&specifier[local_end..])?;
    if trailing.is_empty() {
        return Some((local, None));
    }
    let exported_source = strip_contextual_keyword(trailing, "as")?;
    let exported = canonical_source_identifier_name(trim_binding_pattern_trivia(exported_source)?)?;
    Some((local, Some(exported)))
}

// ---------------------------------------------------------------------------
// Binding pattern parser (destructuring)
// ---------------------------------------------------------------------------

fn canonical_source_identifier_name(source: &str) -> Option<String> {
    let identifier = if source.contains('\\') {
        decode_binding_property_identifier_escapes(source)?
    } else {
        source.to_string()
    };
    is_binding_property_identifier_name(&identifier).then_some(identifier)
}

fn decode_identifier_unicode_escape_prefix(source: &str) -> Option<(char, usize)> {
    let unicode = source.strip_prefix(r"\u")?;
    if let Some(braced) = unicode.strip_prefix('{') {
        let closing = braced.find('}')?;
        let digits = &braced[..closing];
        if digits.is_empty() || !digits.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return None;
        }
        let value = u32::from_str_radix(digits, 16).ok()?;
        return Some((char::from_u32(value)?, 3 + closing + 1));
    }

    let digits = unicode.get(..4)?;
    if !digits.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some((char::from_u32(u32::from_str_radix(digits, 16).ok()?)?, 6))
}

fn canonical_leading_source_identifier(source: &str) -> Option<(String, usize)> {
    let mut canonical = String::new();
    let mut offset = 0usize;
    while offset < source.len() {
        let remaining = &source[offset..];
        let (ch, consumed) = if remaining.starts_with('\\') {
            let Some(decoded) = decode_identifier_unicode_escape_prefix(remaining) else {
                break;
            };
            decoded
        } else {
            let ch = remaining.chars().next()?;
            (ch, ch.len_utf8())
        };
        let valid = if canonical.is_empty() {
            matches!(ch, '$' | '_') || unicode_id_start::is_id_start(ch)
        } else {
            matches!(ch, '$' | '_' | '\u{200C}' | '\u{200D}')
                || unicode_id_start::is_id_continue(ch)
        };
        if !valid {
            break;
        }
        canonical.push(ch);
        offset = offset.saturating_add(consumed);
    }
    (!canonical.is_empty()).then_some((canonical, offset))
}

fn looks_like_malformed_identifier_escape(source: &str) -> bool {
    source.starts_with('\\')
        || canonical_leading_source_identifier(source).is_some_and(|(_, end)| {
            source
                .as_bytes()
                .get(end)
                .is_some_and(|byte| *byte == b'\\')
        })
}

fn starts_with_invalid_identifier_continue(source: &str) -> bool {
    source.chars().next().is_some_and(|ch| {
        matches!(ch, '\u{200C}' | '\u{200D}')
            || (!ch.is_ascii_digit()
                && !unicode_id_start::is_id_start(ch)
                && unicode_id_start::is_id_continue(ch))
    })
}

fn is_reserved_contextual_identifier_prefix(
    source: &str,
    context: &ParseExecutionContext<'_>,
) -> bool {
    canonical_leading_source_identifier(source).is_some_and(|(identifier, _)| {
        (identifier == "await"
            && (context.goal == ParseGoal::Module || context.await_identifier_reserved))
            || (identifier == "yield" && context.yield_identifier_reserved)
    })
}

fn parse_simple_binding_identifier(
    source: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<Option<String>> {
    let Some(identifier) = canonical_source_identifier_name(source) else {
        return Ok(None);
    };
    if !is_context_binding_identifier(&identifier, context) {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("invalid binding identifier: `{source}` canonicalizes to `{identifier}`"),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(Some(identifier))
}

fn parse_required_binding_identifier(
    source: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
    strict_mode: bool,
    await_identifier_reserved: bool,
    yield_identifier_reserved: bool,
) -> ParseResult<String> {
    let source = trim_binding_pattern_trivia(source).ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "binding identifier has unterminated lexical trivia",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let identifier = canonical_source_identifier_name(source).ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("invalid binding identifier spelling: `{source}`"),
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    if !is_binding_identifier_in_grammar(
        &identifier,
        context.goal,
        strict_mode,
        await_identifier_reserved,
        yield_identifier_reserved,
    ) {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("invalid binding identifier: `{source}` canonicalizes to `{identifier}`"),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(identifier)
}

fn parse_identifier_reference(
    source: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<Option<String>> {
    let Some(identifier) = canonical_source_identifier_name(source) else {
        if starts_with_invalid_identifier_continue(source)
            || is_reserved_contextual_identifier_prefix(source, context)
            || looks_like_malformed_identifier_escape(source)
        {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("invalid identifier reference: `{source}`"),
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        return Ok(None);
    };
    if !is_context_identifier_reference(&identifier, context) {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("invalid identifier reference: `{source}` canonicalizes to `{identifier}`"),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(Some(identifier))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingFunctionScan {
    is_async: bool,
    is_generator: bool,
    is_expression: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FunctionParameterScan {
    function: PendingFunctionScan,
    outer_context: ScanGrammarContext,
    strict: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FunctionBodyScan {
    function: PendingFunctionScan,
    outer_context: ScanGrammarContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingArrowBodyScan {
    function: PendingFunctionScan,
    outer_context: ScanGrammarContext,
    body_depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArrowExpressionScan {
    outer_context: ScanGrammarContext,
    body_depth: usize,
    conditional_depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingClassScan {
    is_expression: bool,
    header_depth: usize,
    in_heritage: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ForHeadScan {
    body_depth: usize,
    declaration_seen: bool,
    binding_seen: bool,
    separator_seen: bool,
    initializer_seen: bool,
    classic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParenScanRole {
    Group,
    ControlHead,
    ForHead(ForHeadScan),
}

fn identifier_slash_goal(
    identifier: &str,
    is_member_name: bool,
    grammar_context: ScanGrammarContext,
) -> (SlashGoal, bool) {
    if is_member_name {
        return (SlashGoal::Div, false);
    }

    let contextual_mode = match identifier {
        "await" => Some(grammar_context.await_mode),
        "yield" => Some(grammar_context.yield_mode),
        _ => None,
    };
    if let Some(mode) = contextual_mode {
        return match mode {
            ContextualKeywordScanMode::Identifier => (SlashGoal::Div, false),
            ContextualKeywordScanMode::Reserved => (SlashGoal::RegExp, true),
            ContextualKeywordScanMode::PrefixExpression => (SlashGoal::RegExp, false),
        };
    }

    if matches!(
        identifier,
        "case"
            | "delete"
            | "do"
            | "else"
            | "in"
            | "instanceof"
            | "new"
            | "return"
            | "throw"
            | "typeof"
            | "void"
    ) {
        (SlashGoal::RegExp, false)
    } else {
        (SlashGoal::Div, false)
    }
}

fn numeric_literal_prefix_len(source: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let first = *bytes.first()?;
    if first == b'.' && !bytes.get(1).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    if !first.is_ascii_digit() && first != b'.' {
        return None;
    }

    if first == b'0'
        && let Some(radix_prefix) = bytes.get(1).copied()
        && matches!(radix_prefix, b'x' | b'X' | b'o' | b'O' | b'b' | b'B')
    {
        let mut index = 2usize;
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            index = index.saturating_add(1);
        }
        if bytes.get(index) == Some(&b'n') {
            index = index.saturating_add(1);
        }
        return Some(index);
    }

    let mut index = 0usize;
    while bytes
        .get(index)
        .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
    {
        index = index.saturating_add(1);
    }
    if bytes.get(index) == Some(&b'.') {
        index = index.saturating_add(1);
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
        {
            index = index.saturating_add(1);
        }
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        let exponent_start = index;
        index = index.saturating_add(1);
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index = index.saturating_add(1);
        }
        let digit_start = index;
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'_')
        {
            index = index.saturating_add(1);
        }
        if index == digit_start {
            index = exponent_start;
        }
    }
    if bytes.get(index) == Some(&b'n') {
        index = index.saturating_add(1);
    }
    Some(index.max(1))
}

/// Visit lexical code points in a binding-pattern source slice.
///
/// Comments are trivia and are not visited. Quoted text is visited with
/// `quoted = true`, so delimiter consumers can ignore punctuation inside a
/// string while trivia trimming still keeps the entire literal. `depth` is
/// the aggregate delimiter depth before the current code point is applied.
/// The returned state records whether the full input was lexically complete;
/// consumers may also stop the scan early by returning false from `visit`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BindingPatternScanState {
    complete: bool,
    lexically_complete: bool,
    last_significant: Option<char>,
    trailing_identifier: String,
    trailing_identifier_is_member: bool,
    ends_postfix_update: bool,
    template_literal_ranges: Vec<(usize, usize)>,
}

fn scan_binding_pattern_source_until_with_context_seeded(
    source: &str,
    initial_grammar_context: ScanGrammarContext,
    initial_class_body_depth: Option<usize>,
    mut visit: impl FnMut(usize, char, usize, bool) -> bool,
) -> BindingPatternScanState {
    let mut chars = source.char_indices().peekable();
    let mut depth = 0usize;
    let mut in_quote: Option<char> = None;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut escaped = false;
    let mut last_significant = None;
    let mut trailing_identifier = String::new();
    let mut trailing_identifier_is_member = false;
    let mut identifier_token_open = false;
    let mut ends_postfix_update = false;
    let mut line_terminator_since_significant = false;
    let mut delimiter_stack = Vec::new();
    let mut control_paren_stack: Vec<ParenScanRole> = Vec::new();
    let mut block_brace_stack = Vec::new();
    let mut function_parameter_stack: Vec<Option<FunctionParameterScan>> = Vec::new();
    let mut function_body_stack: Vec<Option<FunctionBodyScan>> = Vec::new();
    let mut arrow_paren_head_stack: Vec<Option<bool>> = Vec::new();
    let mut arrow_expression_stack: Vec<ArrowExpressionScan> = Vec::new();
    let mut grammar_context = initial_grammar_context;
    let mut slash_goal = SlashGoal::RegExp;
    let mut invalid_contextual_keyword = false;
    let mut lexically_complete = true;
    let mut template_literal_ranges = Vec::new();
    let mut identifier_started_at_statement_goal =
        initial_grammar_context.starts_in_statement_position;
    let mut identifier_preceded_by_line_terminator = false;
    let mut previous_identifier = String::new();
    let mut previous_identifier_started_at_statement_goal =
        initial_grammar_context.starts_in_statement_position;
    let mut pending_function: Option<PendingFunctionScan> = None;
    let mut pending_function_body: Option<FunctionParameterScan> = None;
    let mut pending_arrow_head: Option<bool> = None;
    let mut pending_arrow_body: Option<PendingArrowBodyScan> = None;
    let mut pending_classes: Vec<PendingClassScan> = Vec::new();
    let mut class_body_stack: Vec<Option<PendingClassScan>> = Vec::new();
    let mut active_class_body_depths: Vec<usize> = initial_class_body_depth.into_iter().collect();
    let mut statement_goal = initial_grammar_context.starts_in_statement_position;

    macro_rules! visit_or_stop {
        ($index:expr, $ch:expr, $depth:expr, $quoted:expr) => {
            if !visit($index, $ch, $depth, $quoted) {
                return BindingPatternScanState {
                    complete: lexically_complete && !invalid_contextual_keyword,
                    lexically_complete,
                    last_significant,
                    trailing_identifier,
                    trailing_identifier_is_member,
                    ends_postfix_update,
                    template_literal_ranges,
                };
            }
        };
    }

    macro_rules! finish_identifier {
        () => {
            if identifier_token_open {
                let identifier = trailing_identifier.as_str();
                let in_class_method_header = active_class_body_depths.last() == Some(&depth);
                let (next_goal, invalid) =
                    if in_class_method_header && !trailing_identifier_is_member {
                        (SlashGoal::Div, false)
                    } else {
                        identifier_slash_goal(
                            identifier,
                            trailing_identifier_is_member,
                            grammar_context,
                        )
                    };
                invalid_contextual_keyword |= invalid;

                let mut for_head_goal = None;
                if !trailing_identifier_is_member
                    && let Some(ParenScanRole::ForHead(for_head)) = control_paren_stack.last_mut()
                    && depth == for_head.body_depth
                    && !for_head.classic
                {
                    if !for_head.declaration_seen
                        && !for_head.binding_seen
                        && matches!(identifier, "let" | "const" | "var")
                    {
                        for_head.declaration_seen = true;
                        for_head_goal = Some(SlashGoal::RegExp);
                    } else if !for_head.binding_seen {
                        for_head.binding_seen = true;
                    } else if !for_head.separator_seen
                        && !for_head.initializer_seen
                        && matches!(identifier, "in" | "of")
                    {
                        for_head.separator_seen = true;
                        for_head_goal = Some(SlashGoal::RegExp);
                    }
                }

                if !trailing_identifier_is_member && identifier == "function" {
                    let is_async =
                        previous_identifier == "async" && !identifier_preceded_by_line_terminator;
                    pending_function = Some(PendingFunctionScan {
                        is_async,
                        is_generator: false,
                        is_expression: if is_async {
                            !previous_identifier_started_at_statement_goal
                        } else {
                            !identifier_started_at_statement_goal
                        },
                    });
                    slash_goal = SlashGoal::RegExp;
                } else if !trailing_identifier_is_member && identifier == "class" {
                    pending_classes.push(PendingClassScan {
                        is_expression: !identifier_started_at_statement_goal,
                        header_depth: depth,
                        in_heritage: false,
                    });
                    slash_goal = SlashGoal::RegExp;
                } else {
                    slash_goal = for_head_goal.unwrap_or(next_goal);
                }

                if !trailing_identifier_is_member
                    && identifier == "extends"
                    && let Some(class) = pending_classes.last_mut()
                    && class.header_depth == depth
                {
                    class.in_heritage = true;
                    slash_goal = SlashGoal::RegExp;
                }

                if !trailing_identifier_is_member
                    && merge_logical_lines_identifier_awaits_statement(identifier)
                {
                    statement_goal = true;
                }

                pending_arrow_head = (!trailing_identifier_is_member).then_some(
                    previous_identifier == "async" && !identifier_preceded_by_line_terminator,
                );

                previous_identifier.clear();
                previous_identifier.push_str(identifier);
                previous_identifier_started_at_statement_goal =
                    identifier_started_at_statement_goal;
                identifier_token_open = false;
            }
        };
    }

    while let Some((index, ch)) = chars.next() {
        if in_line_comment {
            if matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
                in_line_comment = false;
                line_terminator_since_significant = true;
            }
            continue;
        }
        if in_block_comment {
            if matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
                line_terminator_since_significant = true;
            }
            if ch == '*' && chars.peek().is_some_and(|(_, next)| *next == '/') {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }
        if let Some(quote) = in_quote {
            visit_or_stop!(index, ch, depth, true);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                in_quote = None;
            }
            continue;
        }

        let identifier_continues = ch.is_ascii_alphabetic()
            || matches!(ch, '_' | '$')
            || (ch.is_ascii_digit() && identifier_token_open);
        if identifier_token_open && !identifier_continues {
            finish_identifier!();
        }

        if ch == '?'
            && is_conditional_question_punctuator(source.as_bytes(), index)
            && let Some(arrow) = arrow_expression_stack.last_mut()
            && arrow.body_depth == depth
        {
            arrow.conditional_depth = arrow.conditional_depth.saturating_add(1);
        }
        let mut arrow_boundary = matches!(ch, ')' | ']' | '}' | ',' | ';');
        if ch == ':'
            && let Some(arrow) = arrow_expression_stack.last_mut()
            && arrow.body_depth == depth
        {
            if arrow.conditional_depth > 0 {
                arrow.conditional_depth = arrow.conditional_depth.saturating_sub(1);
            } else {
                arrow_boundary = true;
            }
        }
        if arrow_boundary {
            while arrow_expression_stack
                .last()
                .is_some_and(|arrow| arrow.body_depth == depth)
            {
                let arrow = arrow_expression_stack
                    .pop()
                    .expect("the arrow expression frame was just observed");
                grammar_context = arrow.outer_context;
            }
        }

        if ch == '='
            && chars.peek().is_some_and(|(_, next)| *next == '>')
            && let Some(is_async) = pending_arrow_head.take()
        {
            visit_or_stop!(index, ch, depth, false);
            if let Some((next_index, next_ch)) = chars.next() {
                visit_or_stop!(next_index, next_ch, depth, false);
            }
            pending_arrow_body = Some(PendingArrowBodyScan {
                function: PendingFunctionScan {
                    is_async,
                    is_generator: false,
                    is_expression: true,
                },
                outer_context: grammar_context,
                body_depth: depth,
            });
            last_significant = Some('>');
            trailing_identifier.clear();
            trailing_identifier_is_member = false;
            identifier_token_open = false;
            ends_postfix_update = false;
            line_terminator_since_significant = false;
            statement_goal = false;
            slash_goal = SlashGoal::RegExp;
            previous_identifier.clear();
            continue;
        }

        let begins_comment = ch == '/'
            && chars
                .peek()
                .is_some_and(|(_, next)| matches!(*next, '/' | '*'));
        if !is_binding_pattern_whitespace(ch)
            && !begins_comment
            && let Some(arrow) = pending_arrow_body.take()
        {
            if ch == '{' {
                pending_function_body = Some(FunctionParameterScan {
                    function: arrow.function,
                    outer_context: arrow.outer_context,
                    strict: arrow.outer_context.strict,
                });
            } else {
                grammar_context = ScanGrammarContext::function_body(
                    arrow.function.is_async,
                    false,
                    arrow.outer_context.strict,
                );
                arrow_expression_stack.push(ArrowExpressionScan {
                    outer_context: arrow.outer_context,
                    body_depth: arrow.body_depth,
                    conditional_depth: 0,
                });
                slash_goal = SlashGoal::RegExp;
            }
        }

        let starts_identifier = matches!(ch, '$' | '_' | '\\') || unicode_id_start::is_id_start(ch);
        if starts_identifier {
            if let Some((identifier, consumed)) =
                canonical_leading_source_identifier(&source[index..])
            {
                let identifier_end = index.saturating_add(consumed);
                let is_member_name = last_significant == Some('.');
                let next_token = trim_directive_trivia(&source[identifier_end..]).0;
                let is_object_property_name = block_brace_stack.last() == Some(&false)
                    && (next_token.starts_with(':') || next_token.starts_with('('));
                let started_at_statement_goal = statement_goal;
                let preceded_by_line_terminator = line_terminator_since_significant;
                visit_or_stop!(index, ch, depth, false);
                while let Some((next_index, next_ch)) = chars.peek().copied() {
                    if next_index >= identifier_end {
                        break;
                    }
                    chars.next();
                    // The canonical identifier lexer has already validated
                    // this entire token. Keep its remaining source spelling
                    // opaque to delimiter visitors so braces in a braced
                    // Unicode escape (for example `\u{61}wait`) cannot close
                    // the surrounding interpolation or computed key.
                    visit_or_stop!(next_index, next_ch, depth, true);
                }
                trailing_identifier = identifier;
                trailing_identifier_is_member = is_member_name || is_object_property_name;
                identifier_started_at_statement_goal = started_at_statement_goal;
                identifier_preceded_by_line_terminator = preceded_by_line_terminator;
                identifier_token_open = true;
                last_significant = Some('a');
                statement_goal = false;
                finish_identifier!();
                ends_postfix_update = false;
                line_terminator_since_significant = false;
                continue;
            }
            if ch == '\\' {
                lexically_complete = false;
            }
        }

        if (ch.is_ascii_digit()
            || (ch == '.' && chars.peek().is_some_and(|(_, next)| next.is_ascii_digit())))
            && let Some(consumed) = numeric_literal_prefix_len(&source[index..])
        {
            let literal_end = index.saturating_add(consumed);
            visit_or_stop!(index, ch, depth, false);
            while let Some((next_index, next_ch)) = chars.peek().copied() {
                if next_index >= literal_end {
                    break;
                }
                chars.next();
                visit_or_stop!(next_index, next_ch, depth, false);
            }
            last_significant = Some(')');
            trailing_identifier.clear();
            trailing_identifier_is_member = false;
            identifier_token_open = false;
            ends_postfix_update = false;
            line_terminator_since_significant = false;
            statement_goal = false;
            slash_goal = SlashGoal::Div;
            previous_identifier.clear();
            pending_arrow_head = None;
            continue;
        }

        if matches!(ch, '+' | '-') && chars.peek().is_some_and(|(_, next)| *next == ch) {
            let prefix_position =
                line_terminator_since_significant || slash_goal == SlashGoal::RegExp;
            visit_or_stop!(index, ch, depth, false);
            if let Some((next_index, next_ch)) = chars.next() {
                visit_or_stop!(next_index, next_ch, depth, false);
            }
            // Prefix ++/-- still expects an expression; postfix ++/-- ends
            // one. Preserve that distinction for the following `/` token.
            last_significant = Some(if prefix_position { ch } else { ')' });
            ends_postfix_update = !prefix_position;
            trailing_identifier.clear();
            trailing_identifier_is_member = false;
            identifier_token_open = false;
            line_terminator_since_significant = false;
            statement_goal = false;
            slash_goal = if prefix_position {
                SlashGoal::RegExp
            } else {
                SlashGoal::Div
            };
            previous_identifier.clear();
            continue;
        }

        if ch == '/' {
            match chars.peek().map(|(_, next)| *next) {
                Some('/') => {
                    chars.next();
                    in_line_comment = true;
                    identifier_token_open = false;
                    continue;
                }
                Some('*') => {
                    chars.next();
                    in_block_comment = true;
                    identifier_token_open = false;
                    continue;
                }
                _ => {}
            }
            if slash_goal == SlashGoal::RegExp {
                if let Some(prefix) = parse_regexp_literal_prefix(&source[index..]) {
                    let regexp_end = index.saturating_add(prefix.consumed);
                    visit_or_stop!(index, ch, depth, true);
                    while let Some((next_index, next_ch)) = chars.peek().copied() {
                        if next_index >= regexp_end {
                            break;
                        }
                        chars.next();
                        visit_or_stop!(next_index, next_ch, depth, true);
                    }
                    // A completed RegExp literal is an operand. Use an operand
                    // sentinel rather than its closing slash, which would make a
                    // following division slash look like another RegExp opener.
                    last_significant = Some(')');
                    ends_postfix_update = false;
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                    identifier_token_open = false;
                    line_terminator_since_significant = false;
                    statement_goal = false;
                    slash_goal = SlashGoal::Div;
                    previous_identifier.clear();
                    continue;
                }
                lexically_complete = false;
            }
        }
        if ch == '`' {
            if let Some(template_end) =
                skip_template_literal_with_context(source, index, grammar_context)
            {
                template_literal_ranges.push((index, template_end));
                visit_or_stop!(index, ch, depth, true);
                while let Some((next_index, next_ch)) = chars.peek().copied() {
                    if next_index >= template_end {
                        break;
                    }
                    chars.next();
                    visit_or_stop!(next_index, next_ch, depth, true);
                }
                last_significant = Some('`');
                ends_postfix_update = false;
                trailing_identifier.clear();
                trailing_identifier_is_member = false;
                identifier_token_open = false;
                line_terminator_since_significant = false;
                statement_goal = false;
                slash_goal = SlashGoal::Div;
                previous_identifier.clear();
                continue;
            }
            lexically_complete = false;
        }
        if matches!(ch, '\'' | '"' | '`') {
            visit_or_stop!(index, ch, depth, true);
            in_quote = Some(ch);
            escaped = false;
            last_significant = Some(ch);
            ends_postfix_update = false;
            trailing_identifier.clear();
            trailing_identifier_is_member = false;
            identifier_token_open = false;
            line_terminator_since_significant = false;
            statement_goal = false;
            slash_goal = SlashGoal::Div;
            previous_identifier.clear();
            continue;
        }

        visit_or_stop!(index, ch, depth, false);
        match ch {
            '(' => {
                let is_control_header = !trailing_identifier_is_member
                    && merge_logical_lines_identifier_opens_control_header(&trailing_identifier);
                let paren_role = if !trailing_identifier_is_member && trailing_identifier == "for" {
                    ParenScanRole::ForHead(ForHeadScan {
                        body_depth: depth.saturating_add(1),
                        declaration_seen: false,
                        binding_seen: false,
                        separator_seen: false,
                        initializer_seen: false,
                        classic: false,
                    })
                } else if is_control_header {
                    ParenScanRole::ControlHead
                } else {
                    ParenScanRole::Group
                };
                let arrow_head = (paren_role == ParenScanRole::Group).then(|| {
                    !trailing_identifier_is_member
                        && trailing_identifier == "async"
                        && !line_terminator_since_significant
                });
                let arrow_head = arrow_head.and_then(|is_async| {
                    (is_async || slash_goal == SlashGoal::RegExp).then_some(is_async)
                });
                control_paren_stack.push(paren_role);
                arrow_paren_head_stack.push(arrow_head);
                let class_method_parameters = (active_class_body_depths.last() == Some(&depth)
                    && pending_function.is_none()
                    && paren_role == ParenScanRole::Group)
                    .then_some(PendingFunctionScan {
                        is_async: false,
                        is_generator: false,
                        is_expression: false,
                    });
                let function_parameters =
                    pending_function
                        .take()
                        .or(class_method_parameters)
                        .map(|function| {
                            let strict =
                                class_method_parameters.is_some() || grammar_context.strict;
                            let parameters = FunctionParameterScan {
                                function,
                                outer_context: grammar_context,
                                strict,
                            };
                            grammar_context = ScanGrammarContext::function_parameters(
                                function.is_async,
                                function.is_generator,
                                strict,
                            );
                            parameters
                        });
                function_parameter_stack.push(function_parameters);
                delimiter_stack.push('(');
                depth = depth.saturating_add(1);
                trailing_identifier.clear();
                trailing_identifier_is_member = false;
                identifier_token_open = false;
                last_significant = Some(ch);
                statement_goal = false;
                slash_goal = SlashGoal::RegExp;
                previous_identifier.clear();
            }
            ')' => {
                if delimiter_stack.last() == Some(&'(') {
                    delimiter_stack.pop();
                } else {
                    lexically_complete = false;
                }
                pending_arrow_head = arrow_paren_head_stack.pop().flatten();
                let is_control_header = matches!(
                    control_paren_stack.pop(),
                    Some(ParenScanRole::ControlHead | ParenScanRole::ForHead(_))
                );
                if let Some(parameters) = function_parameter_stack.pop().flatten() {
                    grammar_context = parameters.outer_context;
                    pending_function_body = Some(parameters);
                }
                depth = depth.saturating_sub(1);
                trailing_identifier.clear();
                trailing_identifier_is_member = false;
                identifier_token_open = false;
                last_significant = Some(if is_control_header { '{' } else { ch });
                statement_goal = is_control_header;
                slash_goal = if is_control_header || pending_function_body.is_some() {
                    SlashGoal::RegExp
                } else {
                    SlashGoal::Div
                };
                previous_identifier.clear();
            }
            '{' => {
                if let Some(ParenScanRole::ForHead(for_head)) = control_paren_stack.last_mut()
                    && depth == for_head.body_depth
                    && !for_head.classic
                    && !for_head.binding_seen
                {
                    for_head.binding_seen = true;
                }
                let function_body = pending_function_body.take().map(|parameters| {
                    grammar_context = ScanGrammarContext::function_body(
                        parameters.function.is_async,
                        parameters.function.is_generator,
                        parameters.strict,
                    );
                    FunctionBodyScan {
                        function: parameters.function,
                        outer_context: parameters.outer_context,
                    }
                });
                let class_body = (function_body.is_none()
                    && pending_classes.last().is_some_and(|class| {
                        class.header_depth == depth
                            && (!class.in_heritage || slash_goal == SlashGoal::Div)
                    }))
                .then(|| {
                    pending_classes
                        .pop()
                        .expect("the pending class header was just observed")
                });
                let is_block = function_body.is_some() || class_body.is_some() || statement_goal;
                block_brace_stack.push(is_block);
                function_body_stack.push(function_body);
                class_body_stack.push(class_body);
                if class_body.is_some() {
                    active_class_body_depths.push(depth.saturating_add(1));
                }
                delimiter_stack.push('{');
                depth = depth.saturating_add(1);
                trailing_identifier.clear();
                trailing_identifier_is_member = false;
                identifier_token_open = false;
                last_significant = Some(ch);
                statement_goal = true;
                slash_goal = SlashGoal::RegExp;
                previous_identifier.clear();
            }
            '}' => {
                if delimiter_stack.last() == Some(&'{') {
                    delimiter_stack.pop();
                } else {
                    lexically_complete = false;
                }
                let is_block = block_brace_stack.pop().unwrap_or(false);
                let function_body = function_body_stack.pop().flatten();
                let class_body = class_body_stack.pop().flatten();
                if class_body.is_some() {
                    active_class_body_depths.pop();
                }
                if let Some(function_body) = function_body {
                    grammar_context = function_body.outer_context;
                }
                depth = depth.saturating_sub(1);
                trailing_identifier.clear();
                trailing_identifier_is_member = false;
                identifier_token_open = false;
                let closes_expression = function_body
                    .is_some_and(|body| body.function.is_expression)
                    || class_body.is_some_and(|body| body.is_expression)
                    || (!is_block && function_body.is_none());
                last_significant = Some(if closes_expression { ch } else { '{' });
                statement_goal = !closes_expression;
                slash_goal = if closes_expression {
                    SlashGoal::Div
                } else {
                    SlashGoal::RegExp
                };
                previous_identifier.clear();
            }
            '[' => {
                if let Some(ParenScanRole::ForHead(for_head)) = control_paren_stack.last_mut()
                    && depth == for_head.body_depth
                    && !for_head.classic
                    && !for_head.binding_seen
                {
                    for_head.binding_seen = true;
                }
                delimiter_stack.push('[');
                depth = depth.saturating_add(1);
                trailing_identifier.clear();
                trailing_identifier_is_member = false;
                identifier_token_open = false;
                last_significant = Some(ch);
                statement_goal = false;
                slash_goal = SlashGoal::RegExp;
                previous_identifier.clear();
            }
            ']' => {
                if delimiter_stack.last() == Some(&'[') {
                    delimiter_stack.pop();
                } else {
                    lexically_complete = false;
                }
                depth = depth.saturating_sub(1);
                trailing_identifier.clear();
                trailing_identifier_is_member = false;
                identifier_token_open = false;
                last_significant = Some(ch);
                statement_goal = false;
                slash_goal = SlashGoal::Div;
                previous_identifier.clear();
            }
            ch if is_binding_pattern_whitespace(ch) => {
                if matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
                    line_terminator_since_significant = true;
                }
                continue;
            }
            ch if ch.is_ascii_alphabetic() || matches!(ch, '_' | '$') => {
                if !identifier_token_open {
                    trailing_identifier.clear();
                    trailing_identifier_is_member = last_significant == Some('.');
                    identifier_started_at_statement_goal = statement_goal;
                    identifier_preceded_by_line_terminator = line_terminator_since_significant;
                }
                trailing_identifier.push(ch);
                identifier_token_open = true;
                last_significant = Some(ch);
                statement_goal = false;
            }
            ch if ch.is_ascii_digit() => {
                if identifier_token_open {
                    trailing_identifier.push(ch);
                } else {
                    trailing_identifier.clear();
                    trailing_identifier_is_member = false;
                }
                last_significant = Some(ch);
                statement_goal = false;
                slash_goal = SlashGoal::Div;
                previous_identifier.clear();
            }
            ch => {
                if let Some(ParenScanRole::ForHead(for_head)) = control_paren_stack.last_mut()
                    && depth == for_head.body_depth
                {
                    if ch == ';' {
                        for_head.classic = true;
                    } else if ch == '=' && !for_head.separator_seen {
                        for_head.initializer_seen = true;
                    }
                }
                if ch == '*'
                    && let Some(function) = pending_function.as_mut()
                {
                    function.is_generator = true;
                } else if !matches!(ch, '.') {
                    previous_identifier.clear();
                }
                trailing_identifier.clear();
                trailing_identifier_is_member = false;
                identifier_token_open = false;
                last_significant = Some(ch);
                statement_goal = ch == ';' && control_paren_stack.is_empty();
                slash_goal = if matches!(ch, ')' | ']' | '}') {
                    SlashGoal::Div
                } else {
                    SlashGoal::RegExp
                };
            }
        }
        ends_postfix_update = false;
        line_terminator_since_significant = false;
    }

    // At end of input only the contextual-keyword validity contributes to
    // the returned scan state. Expanding `finish_identifier!` here would also
    // update slash/statement/function lookahead state that no later token can
    // observe, producing unused-assignment warnings in non-test builds.
    if identifier_token_open {
        let in_class_method_header = active_class_body_depths.last() == Some(&depth);
        let invalid = if in_class_method_header && !trailing_identifier_is_member {
            false
        } else {
            identifier_slash_goal(
                trailing_identifier.as_str(),
                trailing_identifier_is_member,
                grammar_context,
            )
            .1
        };
        invalid_contextual_keyword |= invalid;
    }

    let lexically_complete =
        lexically_complete && !in_block_comment && in_quote.is_none() && delimiter_stack.is_empty();
    BindingPatternScanState {
        complete: lexically_complete && !invalid_contextual_keyword,
        lexically_complete,
        last_significant,
        trailing_identifier,
        trailing_identifier_is_member,
        ends_postfix_update,
        template_literal_ranges,
    }
}

fn scan_binding_pattern_source_until_with_context(
    source: &str,
    grammar_context: ScanGrammarContext,
    visit: impl FnMut(usize, char, usize, bool) -> bool,
) -> BindingPatternScanState {
    scan_binding_pattern_source_until_with_context_seeded(source, grammar_context, None, visit)
}

fn scan_binding_pattern_source_until(
    source: &str,
    visit: impl FnMut(usize, char, usize, bool) -> bool,
) -> BindingPatternScanState {
    scan_binding_pattern_source_until_with_context(source, ScanGrammarContext::SLOPPY_SCRIPT, visit)
}

fn scan_binding_pattern_source(
    source: &str,
    mut visit: impl FnMut(usize, char, usize, bool),
) -> bool {
    scan_binding_pattern_source_until(source, |index, ch, depth, quoted| {
        visit(index, ch, depth, quoted);
        true
    })
    .complete
}

fn scan_binding_pattern_source_with_context(
    source: &str,
    grammar_context: ScanGrammarContext,
    mut visit: impl FnMut(usize, char, usize, bool),
) -> bool {
    scan_binding_pattern_source_until_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            visit(index, ch, depth, quoted);
            true
        },
    )
    .complete
}

fn scan_binding_pattern_source_with_context_seeded(
    source: &str,
    grammar_context: ScanGrammarContext,
    initial_class_body_depth: usize,
    mut visit: impl FnMut(usize, char, usize, bool),
) -> bool {
    scan_binding_pattern_source_until_with_context_seeded(
        source,
        grammar_context,
        Some(initial_class_body_depth),
        |index, ch, depth, quoted| {
            visit(index, ch, depth, quoted);
            true
        },
    )
    .complete
}

fn is_binding_pattern_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn contains_non_ecmascript_whitespace_with_context(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> bool {
    let mut found = false;
    scan_binding_pattern_source_until_with_context(source, grammar_context, |_, ch, _, quoted| {
        if !quoted && ch.is_whitespace() && !is_binding_pattern_whitespace(ch) {
            found = true;
            false
        } else {
            true
        }
    });
    found
}

fn trim_binding_pattern_leading_trivia(source: &str) -> Option<&str> {
    trim_binding_pattern_leading_trivia_with_context(source, ScanGrammarContext::SLOPPY_SCRIPT)
}

fn trim_binding_pattern_leading_trivia_with_context(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Option<&str> {
    let mut first_significant = None;
    let state = scan_binding_pattern_source_until_with_context(
        source,
        grammar_context,
        |index, ch, _, quoted| {
            if quoted || !is_binding_pattern_whitespace(ch) {
                first_significant = Some(index);
                false
            } else {
                true
            }
        },
    );
    if let Some(first_significant) = first_significant {
        Some(&source[first_significant..])
    } else if state.complete {
        Some("")
    } else {
        None
    }
}

/// Remove only leading and trailing lexical trivia from a binding-pattern
/// slice. Comments between token characters remain inside the returned slice,
/// so invalid token splices such as `va/*c*/lue` are rejected rather than
/// silently concatenated.
fn binding_pattern_trivia_bounds(source: &str) -> Option<(usize, usize)> {
    binding_pattern_trivia_bounds_with_context(source, ScanGrammarContext::SLOPPY_SCRIPT)
}

fn binding_pattern_trivia_bounds_with_context(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Option<(usize, usize)> {
    let mut first_significant = None;
    let mut last_significant_end = 0usize;
    let complete = scan_binding_pattern_source_with_context(
        source,
        grammar_context,
        |index, ch, _, quoted| {
            if quoted || !is_binding_pattern_whitespace(ch) {
                first_significant.get_or_insert(index);
                last_significant_end = index.saturating_add(ch.len_utf8());
            }
        },
    );
    if !complete {
        return None;
    }
    Some((first_significant.unwrap_or(0), last_significant_end))
}

fn trim_binding_pattern_trivia(source: &str) -> Option<&str> {
    let (start, end) = binding_pattern_trivia_bounds(source)?;
    Some(&source[start..end])
}

fn trim_binding_pattern_trivia_with_context(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Option<&str> {
    let (start, end) = binding_pattern_trivia_bounds_with_context(source, grammar_context)?;
    Some(&source[start..end])
}

/// Parse a binding pattern: identifier, `{ ... }` object, or `[ ... ]` array.
fn parse_binding_pattern(
    source: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    grammar_context: ScanGrammarContext,
) -> ParseResult<BindingPattern> {
    // Binding containers recurse through their object/array elements without
    // entering either parse_statement or parse_expression. Bound that third
    // recursion lane explicitly so hostile nesting returns deterministic
    // budget evidence instead of overflowing the native stack (bd-ogiqj).
    context.pattern_depth = context.pattern_depth.saturating_add(1);
    let depth = context.pattern_depth;
    context.next_depth(depth);
    if depth > context.options.budget.max_recursion_depth {
        let max = context.options.budget.max_recursion_depth;
        let witness = context.witness(Some(ParseBudgetKind::RecursionDepth));
        context.pattern_depth = context.pattern_depth.saturating_sub(1);
        return Err(ParseError::with_witness(
            ParseErrorCode::BudgetExceeded,
            format!("binding-pattern nesting budget exceeded: depth={depth} max={max}"),
            context.source_label.to_string(),
            Some(span.clone()),
            witness,
        ));
    }

    let result = parse_binding_pattern_inner(source, span, context, grammar_context);
    context.pattern_depth = context.pattern_depth.saturating_sub(1);
    result
}

fn parse_binding_pattern_inner(
    source: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    grammar_context: ScanGrammarContext,
) -> ParseResult<BindingPattern> {
    let trimmed =
        trim_binding_pattern_trivia_with_context(source, grammar_context).ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "unterminated comment or quoted literal in binding pattern",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
    if trimmed.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "empty binding pattern",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }

    // Rest element: `...pattern`
    if let Some(rest_source) = trimmed.strip_prefix("...") {
        let inner = parse_binding_pattern(rest_source, span, context, grammar_context)?;
        // ES2020 13.3.3 / 14.1: a rest element or rest parameter has no
        // initializer (`[...x = 1]`, `(...args = [])`).
        if matches!(inner, BindingPattern::AssignmentPattern { .. }) {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "a rest element cannot have an initializer",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        return Ok(BindingPattern::Rest(Box::new(inner)));
    }

    // Default value: `pattern = expr` (only at top level of a pattern element)
    // We need to be careful not to match `=` inside nested patterns.
    if let Some(eq_pos) = find_top_level_eq(trimmed, grammar_context) {
        let left_src =
            trim_binding_pattern_trivia_with_context(&trimmed[..eq_pos], grammar_context);
        let right_src =
            trim_binding_pattern_trivia_with_context(&trimmed[eq_pos + 1..], grammar_context);
        if let (Some(left_src), Some(right_src)) = (left_src, right_src)
            && !left_src.is_empty()
            && !right_src.is_empty()
        {
            let left = parse_binding_pattern(left_src, span, context, grammar_context)?;
            let right = parse_expression(right_src, span, context, 1)?;
            return Ok(BindingPattern::AssignmentPattern {
                left: Box::new(left),
                right,
            });
        }
    }

    // Object pattern: `{ ... }`
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        let inner = &trimmed[1..trimmed.len() - 1];
        return parse_object_binding_pattern(inner, span, context, grammar_context);
    }

    // Array pattern: `[ ... ]`
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1];
        return parse_array_binding_pattern(inner, span, context, grammar_context);
    }

    // Simple BindingIdentifier: decode permitted Unicode escapes before
    // allocating the binding so escaped and literal spellings share one name.
    if let Some(identifier) = parse_simple_binding_identifier(trimmed, span, context)? {
        return Ok(BindingPattern::Identifier(identifier));
    }

    Err(ParseError::new(
        ParseErrorCode::UnsupportedSyntax,
        format!("unsupported binding pattern: `{trimmed}`"),
        context.source_label.to_string(),
        Some(span.clone()),
    ))
}

/// Find `=` at the top level (not inside brackets, parens, braces, or strings).
fn find_top_level_eq(source: &str, grammar_context: ScanGrammarContext) -> Option<usize> {
    let mut found = None;
    let mut previous_significant = None;
    scan_binding_pattern_source_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            if found.is_some() || quoted {
                return;
            }
            if depth == 0 && ch == '=' {
                // Comments and whitespace are trivia, so use the previous
                // significant code point rather than the raw byte before `=`.
                // This accepts `x/* trivia */=1` without mistaking the comment's
                // closing slash for a `/=` compound assignment.
                let next = source.as_bytes().get(index + 1).copied();
                let is_compound = matches!(
                    previous_significant,
                    Some(
                        '<' | '>' | '!' | '=' | '+' | '-' | '*' | '/' | '%' | '&' | '|' | '^' | '~'
                    )
                );
                if next != Some(b'=') && next != Some(b'>') && !is_compound {
                    found = Some(index);
                }
            }
            if !is_binding_pattern_whitespace(ch) {
                previous_significant = Some(ch);
            }
        },
    );
    found
}

/// Parse object destructuring pattern contents (inside `{ ... }`).
fn parse_object_binding_pattern(
    inner: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    grammar_context: ScanGrammarContext,
) -> ParseResult<BindingPattern> {
    let inner =
        trim_binding_pattern_trivia_with_context(inner, grammar_context).ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "unterminated comment or quoted literal in object binding pattern",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
    if inner.is_empty() {
        return Ok(BindingPattern::ObjectPattern(Vec::new()));
    }

    let has_trailing_comma = inner.ends_with(',');
    let segments = split_pattern_elements_with_context(inner, grammar_context);
    let mut properties = Vec::with_capacity(segments.len());
    let mut seen_rest = false;

    for segment in &segments {
        let seg = trim_binding_pattern_trivia_with_context(segment, grammar_context).ok_or_else(
            || {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "unterminated comment or quoted literal in object binding property",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            },
        )?;

        if seen_rest {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "rest element must be the absolute last property in object pattern (no trailing commas allowed)",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }

        if seg.is_empty() {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "object binding pattern contains an empty property",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }

        // Rest element in object pattern: `...rest`
        if let Some(rest_src) = seg.strip_prefix("...") {
            seen_rest = true;
            let inner_pat = parse_binding_pattern(rest_src, span, context, grammar_context)?;
            let key_name = inner_pat
                .as_identifier()
                .unwrap_or_else(|| rest_src.trim())
                .to_string();
            properties.push(ObjectPatternProperty {
                key: Expression::Identifier(key_name),
                value: BindingPattern::Rest(Box::new(inner_pat)),
                computed: false,
                shorthand: false,
            });
            continue;
        }

        // Computed key: `[expr]: pattern`
        if seg.starts_with('[')
            && let Some(bracket_end) = find_binding_pattern_computed_key_end(seg, grammar_context)
        {
            let key_src =
                trim_binding_pattern_trivia_with_context(&seg[1..bracket_end], grammar_context)
                    .ok_or_else(|| {
                        ParseError::new(
                            ParseErrorCode::UnsupportedSyntax,
                            "unterminated trivia in computed object binding key",
                            context.source_label.to_string(),
                            Some(span.clone()),
                        )
                    })?;
            let after_bracket =
                trim_binding_pattern_trivia_with_context(&seg[bracket_end + 1..], grammar_context)
                    .ok_or_else(|| {
                        ParseError::new(
                            ParseErrorCode::UnsupportedSyntax,
                            "unterminated trivia after computed object binding key",
                            context.source_label.to_string(),
                            Some(span.clone()),
                        )
                    })?;
            if let Some(value_src) = after_bracket.strip_prefix(':') {
                let key = parse_expression(key_src, span, context, 1)?;
                let value = parse_binding_pattern(value_src, span, context, grammar_context)?;
                properties.push(ObjectPatternProperty {
                    key,
                    value,
                    computed: true,
                    shorthand: false,
                });
                continue;
            }
        }

        // Key-value: `key: pattern` or shorthand: `key` or `key = default`
        if let Some(colon_pos) = find_top_level_colon_in_pattern(seg, grammar_context) {
            let key_src = &seg[..colon_pos];
            let value_src = &seg[colon_pos + 1..];
            let key = parse_static_binding_property_key(key_src, span, context, grammar_context)?;
            let value = parse_binding_pattern(value_src, span, context, grammar_context)?;
            properties.push(ObjectPatternProperty {
                key,
                value,
                computed: false,
                shorthand: false,
            });
        } else {
            // Shorthand: `x` or `x = default`
            let value = parse_binding_pattern(seg, span, context, grammar_context)?;
            let key_name = match &value {
                BindingPattern::Identifier(n) => n.clone(),
                BindingPattern::AssignmentPattern { left, .. } => {
                    left.as_identifier().unwrap_or("").to_string()
                }
                _ => seg.to_string(),
            };
            properties.push(ObjectPatternProperty {
                key: Expression::Identifier(key_name),
                value,
                computed: false,
                shorthand: true,
            });
        }
    }

    if has_trailing_comma
        && properties
            .last()
            .is_some_and(|property| matches!(&property.value, BindingPattern::Rest(_)))
    {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "rest element must be the absolute last property in object pattern (no trailing commas allowed)",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }

    Ok(BindingPattern::ObjectPattern(properties))
}

fn parse_static_binding_property_key(
    source: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
    grammar_context: ScanGrammarContext,
) -> ParseResult<Expression> {
    let source =
        trim_binding_pattern_trivia_with_context(source, grammar_context).ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("invalid static object-binding property key: `{source}`"),
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
    parse_static_property_name(source, span, context, "object-binding")
}

fn parse_static_object_property_key(
    source: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<Expression> {
    parse_static_property_name(source, span, context, "object-literal")
}

/// Parse a non-computed object property name into its semantic form.
///
/// Keeping the source spelling in an `Identifier` is observably wrong for
/// quoted, escaped, numeric, and BigInt names: lowering would ask the runtime
/// for a property literally named `0x10` or `'value'`. Store quoted and BigInt
/// names as their exact string keys, numeric names as canonical numeric or
/// string AST forms, and decode `IdentifierName` Unicode escapes before
/// lowering (bd-h4esx, bd-y74cd).
fn parse_static_property_name(
    source: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
    construct: &str,
) -> ParseResult<Expression> {
    let invalid_key = || {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("invalid static {construct} property key: `{source}`"),
            context.source_label.to_string(),
            Some(span.clone()),
        )
    };

    if matches!(source.as_bytes().first(), Some(b'\'' | b'"')) {
        let cooked = parse_quoted_expression_string(source, legacy_decimal_escape_mode(context))
            .ok_or_else(&invalid_key)?;
        return Ok(Expression::StringLiteral(cooked));
    }

    if source.ends_with('n') && binding_numeric_key_starts_like_literal(source) {
        let key = parse_bigint_binding_property_key(source).ok_or_else(&invalid_key)?;
        return Ok(Expression::StringLiteral(key.into()));
    }

    if binding_numeric_key_starts_like_literal(source) {
        return parse_numeric_binding_property_key(source).ok_or_else(&invalid_key);
    }

    let identifier = if source.contains('\\') {
        decode_binding_property_identifier_escapes(source).ok_or_else(&invalid_key)?
    } else {
        source.to_string()
    };
    if !is_binding_property_identifier_name(&identifier) {
        return Err(invalid_key());
    }
    Ok(Expression::Identifier(identifier))
}

fn is_binding_property_identifier_name(source: &str) -> bool {
    let mut chars = source.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    // ECMAScript IdentifierName uses Unicode ID_Start/ID_Continue (not the
    // normalization-closed XID classes), plus its four explicit additions.
    (matches!(first, '$' | '_') || unicode_id_start::is_id_start(first))
        && chars.all(|ch| {
            matches!(ch, '$' | '_' | '\u{200C}' | '\u{200D}')
                || unicode_id_start::is_id_continue(ch)
        })
}

fn binding_numeric_key_starts_like_literal(source: &str) -> bool {
    let bytes = source.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_digit)
        || (bytes.first() == Some(&b'.') && bytes.get(1).is_some_and(u8::is_ascii_digit))
        || (matches!(bytes.first(), Some(b'+' | b'-'))
            && bytes
                .get(1)
                .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'.'))
}

fn strip_valid_numeric_separators(source: &str, is_digit: impl Fn(char) -> bool) -> Option<String> {
    let chars = source.chars().collect::<Vec<_>>();
    let mut cleaned = String::with_capacity(source.len());
    for (index, ch) in chars.iter().copied().enumerate() {
        if ch == '_' {
            let previous = index.checked_sub(1).and_then(|i| chars.get(i)).copied();
            let next = chars.get(index + 1).copied();
            if !previous.is_some_and(&is_digit) || !next.is_some_and(&is_digit) {
                return None;
            }
        } else {
            cleaned.push(ch);
        }
    }
    Some(cleaned)
}

fn radix_digits_to_decimal(digits: &str, radix: u32) -> Option<String> {
    let mut decimal_digits = vec![0u8];
    for ch in digits.chars() {
        let mut carry = ch.to_digit(radix)?;
        for digit in &mut decimal_digits {
            let value = u32::from(*digit).checked_mul(radix)?.checked_add(carry)?;
            *digit = u8::try_from(value % 10).ok()?;
            carry = value / 10;
        }
        while carry != 0 {
            decimal_digits.push(u8::try_from(carry % 10).ok()?);
            carry /= 10;
        }
    }
    while decimal_digits.len() > 1 && decimal_digits.last() == Some(&0) {
        decimal_digits.pop();
    }
    Some(
        decimal_digits
            .iter()
            .rev()
            .map(|digit| char::from(b'0' + *digit))
            .collect(),
    )
}

fn prefixed_integer_literal(source: &str) -> Option<(u32, &str)> {
    source
        .strip_prefix("0x")
        .or_else(|| source.strip_prefix("0X"))
        .map(|digits| (16, digits))
        .or_else(|| {
            source
                .strip_prefix("0o")
                .or_else(|| source.strip_prefix("0O"))
                .map(|digits| (8, digits))
        })
        .or_else(|| {
            source
                .strip_prefix("0b")
                .or_else(|| source.strip_prefix("0B"))
                .map(|digits| (2, digits))
        })
}

fn parse_bigint_binding_property_key(source: &str) -> Option<String> {
    let body = source.strip_suffix('n')?;
    let (radix, digits, prefixed) = match prefixed_integer_literal(body) {
        Some((radix, digits)) => (radix, digits, true),
        None => (10, body, false),
    };
    let cleaned = strip_valid_numeric_separators(digits, |ch| ch.is_digit(radix))?;
    if cleaned.is_empty() || !cleaned.chars().all(|ch| ch.is_digit(radix)) {
        return None;
    }
    if !prefixed && cleaned.len() > 1 && cleaned.starts_with('0') {
        return None;
    }
    if radix == 10 {
        return Some(cleaned);
    }
    radix_digits_to_decimal(&cleaned, radix)
}

fn parse_numeric_binding_property_key(source: &str) -> Option<Expression> {
    if matches!(source.as_bytes().first(), Some(b'+' | b'-')) {
        return None;
    }

    if let Some((radix, digits)) = prefixed_integer_literal(source) {
        let cleaned = strip_valid_numeric_separators(digits, |ch| ch.is_digit(radix))?;
        if cleaned.is_empty() || !cleaned.chars().all(|ch| ch.is_digit(radix)) {
            return None;
        }
        let decimal = radix_digits_to_decimal(&cleaned, radix)?;
        return decimal
            .parse::<f64>()
            .ok()
            .map(binding_numeric_value_expression);
    }

    let cleaned = strip_valid_numeric_separators(source, |ch| ch.is_ascii_digit())?;
    if cleaned.is_empty()
        || !cleaned
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | 'e' | 'E' | '+' | '-'))
    {
        return None;
    }
    for (index, ch) in cleaned.char_indices() {
        if matches!(ch, '+' | '-')
            && (index == 0 || !matches!(cleaned.as_bytes().get(index - 1), Some(b'e' | b'E')))
        {
            return None;
        }
    }
    let significand_end = cleaned.find(['e', 'E']).unwrap_or(cleaned.len());
    let significand = &cleaned[..significand_end];
    if significand.starts_with('0')
        && significand
            .as_bytes()
            .get(1)
            .is_some_and(u8::is_ascii_digit)
    {
        // Annex-B legacy octal spellings are not part of the canonical ES2020
        // numeric-literal path. Fail closed instead of silently treating `012`
        // as decimal 12 (its sloppy-script property key would be `10`).
        return None;
    }
    cleaned
        .parse::<f64>()
        .ok()
        .map(binding_numeric_value_expression)
}

fn binding_numeric_value_expression(value: f64) -> Expression {
    const MAX_EXACT_INTEGER: f64 = 9_007_199_254_740_992.0;
    if value.is_finite() && (0.0..=MAX_EXACT_INTEGER).contains(&value) && value.fract() == 0.0 {
        Expression::NumericLiteral(value as i64)
    } else {
        Expression::StringLiteral(js_number_property_key(value).into())
    }
}

/// ECMAScript Number::toString formatting for a property key.
fn js_number_property_key(value: f64) -> String {
    let mut buffer = ryu_js::Buffer::new();
    buffer.format(value).to_string()
}

fn decode_binding_unicode_escape_value(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Option<u32> {
    if chars.peek() == Some(&'{') {
        chars.next();
        let mut code = 0u32;
        let mut digits = 0usize;
        loop {
            match chars.next()? {
                '}' => break,
                ch => {
                    code = code.checked_mul(16)?.checked_add(ch.to_digit(16)?)?;
                    if code > 0x0010_FFFF {
                        return None;
                    }
                    digits = digits.checked_add(1)?;
                }
            }
        }
        (digits != 0).then_some(code)
    } else {
        let mut code = 0u32;
        for _ in 0..4 {
            code = code
                .checked_mul(16)?
                .checked_add(chars.next()?.to_digit(16)?)?;
        }
        Some(code)
    }
}

fn decode_binding_property_identifier_escapes(source: &str) -> Option<String> {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        if chars.next()? != 'u' {
            return None;
        }
        out.push(char::from_u32(decode_binding_unicode_escape_value(
            &mut chars,
        )?)?);
    }
    Some(out)
}

fn find_binding_pattern_computed_key_end(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    if !source.starts_with('[') {
        return None;
    }
    let mut closing_index = None;
    scan_binding_pattern_source_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            if closing_index.is_none() && !quoted && ch == ']' && depth == 1 {
                closing_index = Some(index);
            }
        },
    );
    closing_index
}

/// Find `:` at the top level of a pattern element.
fn find_top_level_colon_in_pattern(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    let mut found = None;
    scan_binding_pattern_source_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            if found.is_none() && !quoted && depth == 0 && ch == ':' {
                found = Some(index);
            }
        },
    );
    found
}

/// Parse array destructuring pattern contents (inside `[ ... ]`).
fn parse_array_binding_pattern(
    inner: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    grammar_context: ScanGrammarContext,
) -> ParseResult<BindingPattern> {
    let inner =
        trim_binding_pattern_trivia_with_context(inner, grammar_context).ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "unterminated comment or quoted literal in array binding pattern",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
    if inner.is_empty() {
        return Ok(BindingPattern::ArrayPattern(Vec::new()));
    }

    let has_trailing_comma = inner.ends_with(',');
    let segments = split_pattern_elements_with_context(inner, grammar_context);
    let mut elements = Vec::with_capacity(segments.len());

    for segment in &segments {
        let seg = trim_binding_pattern_trivia_with_context(segment, grammar_context).ok_or_else(
            || {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "unterminated comment or quoted literal in array binding element",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            },
        )?;
        if seg.is_empty() {
            elements.push(None); // hole
        } else {
            elements.push(Some(parse_binding_pattern(
                seg,
                span,
                context,
                grammar_context,
            )?));
        }
    }

    // ES2020 early error: rest element must be last, at most one
    let rest_positions: Vec<usize> = elements
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, Some(BindingPattern::Rest(_))))
        .map(|(i, _)| i)
        .collect();
    if rest_positions.len() > 1 {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "array pattern has more than one rest element",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    if let Some(&pos) = rest_positions.first() {
        // Rest must be the absolute last element (no trailing commas/holes allowed after it)
        if pos != elements.len() - 1 || has_trailing_comma {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "rest element must be the last element in array pattern",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
    }

    Ok(BindingPattern::ArrayPattern(elements))
}

/// Split pattern elements on commas at the top level.
#[cfg(test)]
fn split_pattern_elements(source: &str) -> Vec<&str> {
    split_pattern_elements_with_context(source, ScanGrammarContext::SLOPPY_SCRIPT)
}

fn split_pattern_elements_with_context(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    scan_binding_pattern_source_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            if !quoted && depth == 0 && ch == ',' {
                out.push(&source[start..index]);
                start = index.saturating_add(ch.len_utf8());
            }
        },
    );
    out.push(&source[start..]);
    if let Some(last) = out.last()
        && trim_binding_pattern_trivia_with_context(last, grammar_context)
            .is_some_and(str::is_empty)
        && trim_binding_pattern_trivia_with_context(source, grammar_context)
            .is_some_and(|trimmed| trimmed.ends_with(','))
    {
        out.pop();
    }
    out
}

fn variable_declaration_prefix_kind(statement: &str) -> Option<VariableDeclarationKind> {
    for kind in [
        VariableDeclarationKind::Var,
        VariableDeclarationKind::Let,
        VariableDeclarationKind::Const,
    ] {
        let Some(rest) = statement.strip_prefix(kind.as_str()) else {
            continue;
        };
        if rest.is_empty() {
            return Some(kind);
        }
        let next_char = rest.chars().next().unwrap();
        if is_binding_pattern_whitespace(next_char)
            || next_char == '['
            || next_char == '{'
            || rest.starts_with("//")
            || rest.starts_with("/*")
        {
            return Some(kind);
        }
    }
    None
}

fn let_starts_lexical_declaration(source_after_let: &str) -> bool {
    let after_trivia = trim_directive_trivia(source_after_let).0;
    if after_trivia.is_empty()
        || strip_contextual_keyword(after_trivia, "in").is_some()
        || strip_contextual_keyword(after_trivia, "instanceof").is_some()
    {
        return false;
    }

    matches!(after_trivia.chars().next(), Some('[' | '{' | '\\'))
        || canonical_leading_source_identifier(after_trivia)
            .is_some_and(|(name, _)| !is_always_reserved_word(&name))
        // Preserve fail-closed handling for an unterminated block comment;
        // complete comments have already been consumed as lexical trivia.
        || after_trivia.starts_with("/*")
}

fn parse_variable_declaration_kind(statement: &str) -> Option<VariableDeclarationKind> {
    let kind = variable_declaration_prefix_kind(statement)?;
    (kind != VariableDeclarationKind::Let
        || statement
            .strip_prefix(kind.as_str())
            .is_some_and(let_starts_lexical_declaration))
    .then_some(kind)
}

fn validate_lexical_binding_names(
    kind: VariableDeclarationKind,
    pattern: &BindingPattern,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    if kind != VariableDeclarationKind::Var && pattern.binding_names().contains(&"let") {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "lexical declarations cannot bind the name `let`",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

fn parse_variable_declaration(
    statement: &str,
    kind: VariableDeclarationKind,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<VariableDeclaration> {
    let keyword = kind.as_str();
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
    let body_source = statement.strip_prefix(keyword).unwrap();
    let body = trim_binding_pattern_leading_trivia_with_context(body_source, grammar_context)
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("{keyword} declaration has unterminated leading trivia"),
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
    if body.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("{keyword} declaration must include at least one binding"),
            context.source_label.to_string(),
            Some(span),
        ));
    }

    let declarator_segments = split_var_declarator_segments_with_context(body, grammar_context);
    if declarator_segments.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("{keyword} declaration must include at least one binding"),
            context.source_label.to_string(),
            Some(span),
        ));
    }

    let mut declarations = Vec::with_capacity(declarator_segments.len());
    for declarator in declarator_segments {
        let (name_raw, initializer_raw) =
            split_var_declarator_assignment(declarator, grammar_context);
        let pattern = parse_binding_pattern(name_raw, &span, context, grammar_context)?;
        validate_lexical_binding_names(kind, &pattern, &span, context)?;

        let initializer = match initializer_raw {
            Some(initializer_source) => {
                let initializer_source =
                    trim_binding_pattern_trivia_with_context(initializer_source, grammar_context)
                        .ok_or_else(|| {
                        ParseError::new(
                            ParseErrorCode::UnsupportedSyntax,
                            format!("{keyword} initializer has unterminated lexical trivia"),
                            context.source_label.to_string(),
                            Some(span.clone()),
                        )
                    })?;
                if initializer_source.is_empty() {
                    return Err(ParseError::new(
                        ParseErrorCode::UnsupportedSyntax,
                        format!("{keyword} initializer expression is empty"),
                        context.source_label.to_string(),
                        Some(span.clone()),
                    ));
                }
                Some(parse_expression(initializer_source, &span, context, 1)?)
            }
            None if kind == VariableDeclarationKind::Const => {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "const declarations must include an initializer in parser scaffold",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            }
            None => None,
        };

        declarations.push(VariableDeclarator {
            pattern,
            initializer,
            span: span.clone(),
        });
    }

    Ok(VariableDeclaration {
        kind,
        declarations,
        span,
    })
}

#[cfg(test)]
fn split_var_declarator_segments(source: &str) -> Vec<&str> {
    split_var_declarator_segments_with_context(source, ScanGrammarContext::SLOPPY_SCRIPT)
}

fn split_var_declarator_segments_with_context(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Vec<&str> {
    let mut out = Vec::new();
    let mut segment_start = 0usize;
    scan_binding_pattern_source_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            if !quoted && depth == 0 && ch == ',' {
                push_var_declarator_segment(&mut out, source, segment_start, index);
                segment_start = index.saturating_add(ch.len_utf8());
            }
        },
    );
    push_var_declarator_segment(&mut out, source, segment_start, source.len());
    out
}

fn push_var_declarator_segment<'a>(
    out: &mut Vec<&'a str>,
    source: &'a str,
    start: usize,
    end: usize,
) {
    if end < start {
        return;
    }
    let raw = &source[start..end];
    if raw.chars().all(is_binding_pattern_whitespace) {
        return;
    }
    out.push(raw);
}

fn split_var_declarator_assignment(
    segment: &str,
    grammar_context: ScanGrammarContext,
) -> (&str, Option<&str>) {
    let mut assignment = None;
    let mut previous_significant = None;
    scan_binding_pattern_source_with_context(
        segment,
        grammar_context,
        |index, ch, depth, quoted| {
            if assignment.is_some() || quoted {
                return;
            }
            if depth == 0 && ch == '=' {
                let next = segment[index.saturating_add(ch.len_utf8())..]
                    .chars()
                    .next();
                let part_of_comparison = matches!(
                    previous_significant,
                    Some('=') | Some('!') | Some('<') | Some('>')
                ) || matches!(next, Some('='));
                if !part_of_comparison {
                    assignment = Some(index);
                }
            }
            if !is_binding_pattern_whitespace(ch) {
                previous_significant = Some(ch);
            }
        },
    );
    if let Some(index) = assignment {
        let rhs_start = index.saturating_add('='.len_utf8());
        return (&segment[..index], Some(&segment[rhs_start..]));
    }

    (segment, None)
}

/// Parse the AssignmentExpression grammar. Callers whose grammar admits the
/// comma operator must use `parse_expression_allowing_sequence`; argument,
/// initializer, and property lists keep their own comma separators.
fn parse_expression(
    expression: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    context.next_depth(recursion_depth);
    if recursion_depth > context.options.budget.max_recursion_depth {
        return Err(ParseError::with_witness(
            ParseErrorCode::BudgetExceeded,
            format!(
                "recursion budget exceeded: depth={} max_recursion_depth={}",
                recursion_depth, context.options.budget.max_recursion_depth
            ),
            context.source_label.to_string(),
            Some(span.clone()),
            context.witness(Some(ParseBudgetKind::RecursionDepth)),
        ));
    }

    // Comments and the full ES WhiteSpace set are lexical trivia at an
    // expression boundary. Keep internal trivia in place so it cannot join
    // identifier tokens, but discard leading/trailing trivia before recursive
    // postfix and binary parsing (for example `let/**/(4)` and `let\u{FEFF}(4)`).
    let scan_context = ScanGrammarContext::from_execution_context(context).expression();
    let expression = trim_binding_pattern_trivia_with_context(expression, scan_context)
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "unterminated lexical trivia at expression boundary",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
    if expression.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "empty expression statement",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    if contains_non_ecmascript_whitespace_with_context(expression, scan_context) {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "non-ECMAScript whitespace at expression boundary",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    if split_top_level_commas_with_context(expression, scan_context).len() > 1 {
        return Err(unsupported_expression_syntax_error(
            "a comma expression requires parentheses in this grammar position",
            span,
            context,
        ));
    }

    // Arrow function: lowest precedence (lower than assignment).
    if let Some(result) = try_parse_arrow_function(expression, span, context, recursion_depth) {
        return result;
    }

    // YieldExpression is an AssignmentExpression form, so it must claim the
    // whole trailing assignment before the higher-precedence binary scanner.
    if context.allow_yield_expression
        && let Some(rest) = strip_contextual_keyword(expression, "yield")
    {
        return parse_yield_expression(rest, span, context, recursion_depth);
    }

    // Try assignment first (lowest precedence apart from comma).
    if let Some(result) = try_parse_assignment(expression, span, context, recursion_depth) {
        return result;
    }

    // Try ternary conditional: expr ? expr : expr
    if let Some(result) = try_parse_conditional(expression, span, context, recursion_depth) {
        return result;
    }

    // Prefix / postfix increment & decrement (`++` / `--`). MUST run before the
    // binary scanner, which would otherwise mis-split `i++` on its `+` (and
    // before unary, which collapsed `++i` to a double `UnaryPlus`) — bd-my5ar.
    if let Some(result) = try_parse_update(expression, span, context, recursion_depth) {
        return result;
    }

    // Try binary expression with precedence scanning.
    if let Some(result) = try_parse_binary(expression, span, context, recursion_depth) {
        return result;
    }

    // Unary prefix operators.
    if let Some(result) = try_parse_unary_prefix(expression, span, context, recursion_depth) {
        return result;
    }

    // Postfix: call and member access on a primary expression.
    let primary = parse_primary_expression(expression, span, context, recursion_depth)?;
    Ok(primary)
}

fn strip_contextual_keyword<'a>(source: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = source.strip_prefix(keyword)?;
    if starts_identifier_part(rest) {
        None
    } else {
        Some(rest)
    }
}

fn strip_async_function_keyword(source: &str) -> Option<&str> {
    let after_async = strip_contextual_keyword(source, "async")?;
    let (after_trivia, saw_line_terminator) = trim_directive_trivia(after_async);
    if saw_line_terminator {
        return None;
    }
    strip_contextual_keyword(after_trivia, "function")
}

fn parse_yield_expression(
    rest: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    let (rest, saw_line_terminator) = trim_directive_trivia(rest);
    if saw_line_terminator
        && !rest.is_empty()
        && !rest.starts_with(';')
        && !rest.starts_with(')')
        && !rest.starts_with('}')
    {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "a yield expression cannot attach an argument across a LineTerminator",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    let (delegate, rest) = if let Some(after_star) = rest.strip_prefix('*') {
        (true, after_star.trim_start())
    } else {
        (false, rest)
    };
    let argument = if rest.is_empty()
        || rest.starts_with(';')
        || rest.starts_with(')')
        || rest.starts_with('}')
    {
        None
    } else {
        Some(Box::new(parse_expression(
            rest,
            span,
            context,
            recursion_depth + 1,
        )?))
    };
    Ok(Expression::Yield { argument, delegate })
}

/// Parse a primary (atomic) expression — literals, identifiers, grouping, etc.
fn parse_primary_expression(
    expression: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    let expression = expression.trim();

    let legacy_decimal_escapes = legacy_decimal_escape_mode(context);
    if let Some(value) = parse_quoted_expression_string(expression, legacy_decimal_escapes) {
        return Ok(Expression::StringLiteral(value));
    }

    // A malformed quoted expression must not fall through to `Raw`. A valid,
    // balanced quoted literal may still be the base of a postfix chain such
    // as `"abc".length`; record that valid leading literal and let the real
    // postfix parser validate its complete tail below.
    let has_valid_quoted_prefix = if matches!(expression.as_bytes().first(), Some(b'"' | b'\'')) {
        let valid = leading_string_literal_end(expression)
            .and_then(|end| {
                parse_quoted_expression_string(&expression[..end], legacy_decimal_escapes)
            })
            .is_some();
        if !valid {
            return Err(unsupported_expression_syntax_error(
                "unterminated or malformed string literal",
                span,
                context,
            ));
        }
        true
    } else {
        false
    };

    // Regex literal: /pattern/flags
    if let Some((pattern, flags)) = parse_regexp_literal(expression) {
        return Ok(Expression::RegExpLiteral { pattern, flags });
    }

    if let Some(value) = parse_i64_numeric_literal(expression) {
        // The integer AST carrier cannot preserve the sign of zero.
        if value == 0 && expression.starts_with('-') {
            return Ok(Expression::FloatLiteral((-0.0_f64).to_bits()));
        }
        return Ok(Expression::NumericLiteral(value));
    }

    // Try float literal (decimal, scientific notation)
    if let Some(value) = parse_f64_numeric_literal(expression) {
        return Ok(Expression::FloatLiteral(value.to_bits()));
    }

    if expression == "true" {
        return Ok(Expression::BooleanLiteral(true));
    }
    if expression == "false" {
        return Ok(Expression::BooleanLiteral(false));
    }
    if expression == "null" {
        return Ok(Expression::NullLiteral);
    }
    if expression == "this" {
        return Ok(Expression::This);
    }
    if expression == "super" {
        return Ok(Expression::Super);
    }

    if let Some(rest) = strip_contextual_keyword(expression, "await")
        && !rest.is_empty()
        && (context.allow_await_expression
            || (context.goal == ParseGoal::Script
                && !context.await_identifier_reserved
                && rest.chars().next().is_some_and(char::is_whitespace)))
    {
        let nested = parse_expression(rest.trim_start(), span, context, recursion_depth + 1)?;
        return Ok(Expression::Await(Box::new(nested)));
    }

    // spread element: `...expr`
    if let Some(rest) = expression.strip_prefix("...") {
        let inner = parse_expression(rest.trim_start(), span, context, recursion_depth + 1)?;
        return Ok(Expression::SpreadElement(Box::new(inner)));
    }

    // new expression: `new Foo(args)`
    if let Some(rest) = expression
        .strip_prefix("new ")
        .or_else(|| expression.strip_prefix("new\t"))
    {
        return parse_new_expression(rest.trim(), span, context, recursion_depth);
    }

    // Async function expressions require no LineTerminator between `async`
    // and `function`; comments without a terminator remain lexical trivia.
    if let Some((identifier, identifier_end)) = canonical_leading_source_identifier(expression)
        && identifier == "async"
        && &expression[..identifier_end] != "async"
    {
        let (after_identifier, _) = trim_directive_trivia(&expression[identifier_end..]);
        if starts_with_keyword(after_identifier, "function") {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "escaped IdentifierName spelling cannot act as the contextual `async` keyword",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
    }
    if let Some(after_async) = strip_contextual_keyword(expression, "async") {
        let (after_trivia, saw_line_terminator) = trim_directive_trivia(after_async);
        if let Some(rest) = after_trivia.strip_prefix("function").filter(|rest| {
            rest.starts_with('(')
                || rest.starts_with('*')
                || trim_directive_trivia(rest).0.len() < rest.len()
        }) {
            if saw_line_terminator {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "line terminator is not allowed between `async` and a function expression",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            }
            return parse_function_expression(rest, true, span, context, recursion_depth);
        }
    }

    // Function expression: `function(a, b) { ... }` or `function name(a, b) { ... }`
    if let Some(rest) = expression.strip_prefix("function").filter(|r| {
        r.starts_with('(') || r.starts_with('*') || trim_directive_trivia(r).0.len() < r.len()
    }) {
        return parse_function_expression(rest, false, span, context, recursion_depth);
    }

    // Class expression: `class { ... }`, `class Name { ... }`, or
    // `class extends Base { ... }`.
    if expression == "class" || expression.starts_with("class ") || expression.starts_with("class{")
    {
        return parse_class_expression(expression, span, context);
    }

    // Template literal: `text ${expr} text`
    if expression.starts_with('`') && expression.ends_with('`') {
        return parse_template_literal(expression, span, context, recursion_depth);
    }

    // Parenthesized expression.
    if expression.starts_with('(')
        && expression.ends_with(')')
        && let Some((inner, rest)) = extract_balanced_with_context(
            expression,
            '(',
            ')',
            ScanGrammarContext::from_execution_context(context).expression(),
        )
        && rest.trim().is_empty()
    {
        return parse_expression_allowing_sequence(inner, span, context, recursion_depth + 1);
    }

    // Array literal: [a, b, c]
    if expression.starts_with('[')
        && expression.ends_with(']')
        && let Some((inner, rest)) = extract_balanced_with_context(
            expression,
            '[',
            ']',
            ScanGrammarContext::from_execution_context(context).expression(),
        )
        && rest.trim().is_empty()
    {
        return parse_array_literal(inner, span, context, recursion_depth);
    }

    // Object literal: {a: 1, b: 2}
    if expression.starts_with('{')
        && expression.ends_with('}')
        && let Some((inner, rest)) = extract_balanced_with_context(
            expression,
            '{',
            '}',
            ScanGrammarContext::from_execution_context(context).expression(),
        )
        && rest.trim().is_empty()
    {
        return parse_object_literal(inner, span, context, recursion_depth);
    }

    // Call expression: callee(args) or callee(args).member etc.
    if let Some(result) = try_parse_postfix(expression, span, context, recursion_depth) {
        return result;
    }

    if let Some(prefix) = parse_regexp_literal_prefix(expression) {
        if let Some(flag_error) = prefix.flag_error {
            let message = match flag_error {
                RegExpFlagError::Duplicate(flag) => {
                    format!("duplicate RegExp literal flag `{flag}`")
                }
                RegExpFlagError::Unsupported(flag) => {
                    format!("unsupported RegExp literal flag `{flag}`")
                }
            };
            return Err(unsupported_expression_syntax_error(&message, span, context));
        }
        if prefix.consumed < expression.len() {
            return Err(unsupported_expression_syntax_error(
                "unsupported or malformed RegExp-literal postfix expression",
                span,
                context,
            ));
        }
    }

    if let Some(identifier) = parse_identifier_reference(expression, span, context)? {
        return Ok(Expression::Identifier(identifier));
    }

    if has_valid_quoted_prefix {
        return Err(unsupported_expression_syntax_error(
            "unsupported or malformed string-literal postfix expression",
            span,
            context,
        ));
    }

    Ok(Expression::Raw(canonicalize_whitespace(expression)))
}

// ---------------------------------------------------------------------------
// Arrow function parsing
// ---------------------------------------------------------------------------

/// Try to parse an arrow function expression.
///
/// Handles:
///   `(params) => expr`
///   `(params) => { stmts }`
///   `ident => expr`
///   `ident => { stmts }`
///   `async (params) => expr`
///   `async ident => expr`
fn try_parse_arrow_function(
    expr: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> Option<ParseResult<Expression>> {
    let (is_async, rest) = if let Some(after_async) = strip_contextual_keyword(expr, "async") {
        let (trimmed, saw_line_terminator) = trim_directive_trivia(after_async);
        let consumed_trivia = trimmed.len() < after_async.len();
        let starts_with_identifier = matches!(
            trimmed.chars().next(),
            Some(ch) if matches!(ch, '$' | '_') || unicode_id_start::is_id_start(ch)
        ) || trimmed.starts_with(r"\u");
        // `async(` could be a call. An async-arrow head requires separating
        // lexical trivia and forbids a LineTerminator before its parameter.
        if !saw_line_terminator
            && (trimmed.starts_with('(') || (consumed_trivia && starts_with_identifier))
        {
            (true, trimmed)
        } else {
            (false, expr)
        }
    } else {
        (false, expr)
    };

    if rest.starts_with('(') {
        // (params) => body
        let parameter_scan_context =
            ScanGrammarContext::function_parameters(is_async, false, context.strict_mode);
        let (params_src, after_params) =
            extract_balanced_with_context(rest, '(', ')', parameter_scan_context)?;
        let (after, saw_line_terminator) = trim_directive_trivia(after_params);
        if saw_line_terminator && after.starts_with("=>") {
            return Some(Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "line terminator is not allowed before an arrow token",
                context.source_label.to_string(),
                Some(span.clone()),
            )));
        }
        let body_src = after.strip_prefix("=>")?;
        let body_src = body_src.trim();

        let arrow_param_strict_mode = context.strict_mode;
        let arrow_param_await_reserved = context.await_identifier_reserved || is_async;
        let arrow_param_yield_reserved = context.yield_identifier_reserved;
        let params = match with_grammar_context(
            context,
            arrow_param_strict_mode,
            arrow_param_await_reserved,
            arrow_param_yield_reserved,
            false,
            false,
            |context| parse_arrow_params(params_src, span, context),
        ) {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };
        Some(parse_arrow_body(
            body_src,
            params,
            is_async,
            span,
            context,
            recursion_depth,
        ))
    } else {
        // ident => body (single param, no parens)
        // Find `=>` that isn't inside lexical trivia or nested delimiters.
        let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
        let arrow_pos = find_top_level_arrow(rest, grammar_context)?;
        let (param_with_trailing_trivia, _) = trim_directive_trivia(&rest[..arrow_pos]);
        let param_name = match trim_binding_pattern_trivia(param_with_trailing_trivia) {
            Some(param_name) => param_name,
            None => {
                return Some(Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "unterminated comment or quoted literal in arrow parameter",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )));
            }
        };
        let trailing_trivia = param_with_trailing_trivia
            .strip_prefix(param_name)
            .unwrap_or_default();
        let (_, saw_line_terminator) = trim_directive_trivia(trailing_trivia);
        if saw_line_terminator {
            return Some(Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "line terminator is not allowed before an arrow token",
                context.source_label.to_string(),
                Some(span.clone()),
            )));
        }
        let param_name = match parse_simple_binding_identifier(param_name, span, context) {
            Ok(Some(name)) => name,
            Ok(None) => {
                if !is_async
                    && (arrow_belongs_to_outer_assignment_or_conditional(
                        rest,
                        arrow_pos,
                        grammar_context,
                    ) || arrow_belongs_to_outer_yield(rest, arrow_pos, grammar_context))
                {
                    return None;
                }
                return Some(Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    format!("invalid unparenthesized arrow parameter: `{param_name}`"),
                    context.source_label.to_string(),
                    Some(span.clone()),
                )));
            }
            Err(error) => return Some(Err(error)),
        };
        let body_src = rest[arrow_pos + 2..].trim();
        let params = vec![FunctionParam {
            pattern: BindingPattern::Identifier(param_name),
            span: span.clone(),
        }];
        Some(parse_arrow_body(
            body_src,
            params,
            is_async,
            span,
            context,
            recursion_depth,
        ))
    }
}

/// Parse comma-separated arrow function parameters (supports destructuring).
fn parse_arrow_params(
    params_src: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Vec<FunctionParam>> {
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
    let params_src = trim_binding_pattern_trivia_with_context(params_src, grammar_context)
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "unterminated comment or quoted literal in function parameters",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
    if params_src.is_empty() {
        return Ok(Vec::new());
    }
    let has_trailing_comma = params_src.ends_with(',');
    let segments = split_pattern_elements_with_context(params_src, grammar_context);
    let mut params = Vec::with_capacity(segments.len());
    for segment in &segments {
        let seg = trim_binding_pattern_trivia_with_context(segment, grammar_context).ok_or_else(
            || {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "unterminated comment or quoted literal in function parameter",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            },
        )?;
        if seg.is_empty() {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "function parameter list contains an empty parameter",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        let pattern = parse_binding_pattern(seg, span, context, grammar_context)?;
        params.push(FunctionParam {
            pattern,
            span: span.clone(),
        });
    }
    if has_trailing_comma
        && params
            .last()
            .is_some_and(|parameter| matches!(&parameter.pattern, BindingPattern::Rest(_)))
    {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "rest parameter cannot have a trailing comma",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(params)
}

fn validate_parameter_binding_names(
    params: &[FunctionParam],
    strict_mode: bool,
    is_async: bool,
    is_generator: bool,
    is_arrow: bool,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    let is_simple = params
        .iter()
        .all(|parameter| matches!(&parameter.pattern, BindingPattern::Identifier(_)));
    let duplicates_are_error = strict_mode || is_async || is_generator || is_arrow || !is_simple;
    let mut seen = BTreeSet::new();
    for name in params
        .iter()
        .flat_map(|parameter| parameter.pattern.binding_names())
    {
        let invalid = (is_async && name == "await")
            || (is_generator && name == "yield")
            || (strict_mode
                && (is_strict_reserved_word(name) || matches!(name, "eval" | "arguments")));
        if invalid {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("invalid function parameter binding `{name}` in its grammar context"),
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        if !seen.insert(name) && duplicates_are_error {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("duplicate function parameter binding `{name}` is not allowed"),
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
    }
    Ok(())
}

fn validate_use_strict_parameter_list(
    params: &[FunctionParam],
    has_own_use_strict_directive: bool,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    if has_own_use_strict_directive
        && params
            .iter()
            .any(|parameter| !matches!(&parameter.pattern, BindingPattern::Identifier(_)))
    {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "a function with non-simple parameters cannot contain a use strict directive",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

/// Parse the body of an arrow function — either `{ block }` or expression.
fn parse_arrow_body(
    body_src: &str,
    params: Vec<FunctionParam>,
    is_async: bool,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    let block_source = body_src
        .starts_with('{')
        .then(|| {
            extract_balanced_with_context(
                body_src,
                '{',
                '}',
                ScanGrammarContext::function_body(is_async, false, context.strict_mode),
            )
        })
        .flatten();
    if body_src.starts_with('{') && block_source.is_none() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "arrow function block has unbalanced braces",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    let has_own_use_strict_directive =
        block_source.is_some_and(|(block_src, _)| has_use_strict_directive(block_src));
    let strict_mode = context.strict_mode || has_own_use_strict_directive;
    validate_parameter_binding_names(&params, strict_mode, is_async, false, true, span, context)?;
    validate_use_strict_parameter_list(&params, has_own_use_strict_directive, span, context)?;

    with_grammar_context(
        context,
        strict_mode,
        is_async,
        false,
        is_async,
        false,
        |context| {
            let body = if let Some((block_src, _)) = block_source {
                let statements =
                    parse_body_statements(block_src, ParseGoal::Script, span, context)?;
                ArrowBody::Block(BlockStatement {
                    body: statements,
                    span: span.clone(),
                })
            } else {
                let expression = parse_expression(body_src, span, context, recursion_depth + 1)?;
                ArrowBody::Expression(Box::new(expression))
            };
            Ok(Expression::ArrowFunction {
                params,
                body,
                is_async,
            })
        },
    )
}

/// Find `=>` at the top level (not inside quotes/brackets/parens).
fn find_top_level_arrow(s: &str, grammar_context: ScanGrammarContext) -> Option<usize> {
    let mut found = None;
    scan_binding_pattern_source_with_context(s, grammar_context, |index, _, depth, quoted| {
        if found.is_none() && !quoted && depth == 0 && s[index..].starts_with("=>") {
            found = Some(index);
        }
    });
    found
}

/// Whether the first top-level arrow token belongs to a recursively nested
/// assignment RHS or ternary branch rather than to the whole expression.
///
/// Arrow parsing runs before assignment and conditional parsing. Deferring
/// these two complete outer forms lets their recursive expression parsing own
/// the arrow while retaining the direct malformed-head error for expressions
/// such as `a + b => c`.
fn arrow_belongs_to_outer_assignment_or_conditional(
    source: &str,
    arrow_pos: usize,
    grammar_context: ScanGrammarContext,
) -> bool {
    let prefix = &source[..arrow_pos];
    let bytes = source.as_bytes();
    let mut has_assignment = false;
    let mut conditional_question = None;
    let complete = scan_binding_pattern_source_with_context(
        prefix,
        grammar_context,
        |index, ch, depth, quoted| {
            if quoted || depth != 0 {
                return;
            }
            if match_assignment_operator_at(bytes, index).is_some() {
                has_assignment = true;
            } else if conditional_question.is_none()
                && ch == '?'
                && is_conditional_question_punctuator(bytes, index)
            {
                conditional_question = Some(index);
            }
        },
    );
    complete
        && (has_assignment
            || conditional_question.is_some_and(|question| {
                find_ternary_colon(&source[question + 1..], grammar_context).is_some()
            }))
}

fn arrow_belongs_to_outer_yield(
    source: &str,
    arrow_pos: usize,
    grammar_context: ScanGrammarContext,
) -> bool {
    if grammar_context.yield_mode != ContextualKeywordScanMode::PrefixExpression {
        return false;
    }
    let Some(rest) = strip_contextual_keyword(&source[..arrow_pos], "yield") else {
        return false;
    };
    let (rest, saw_line_terminator) = trim_directive_trivia(rest);
    if saw_line_terminator {
        return false;
    }
    let argument = rest
        .strip_prefix('*')
        .map_or(rest, |after_star| trim_directive_trivia(after_star).0);
    !argument.is_empty()
}

// ---------------------------------------------------------------------------
// New expression parsing
// ---------------------------------------------------------------------------

fn parse_new_expression(
    rest: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    // `rest` is everything after `new `, e.g. `Foo(a, b)` or `Foo` or `Foo.Bar()`
    //
    // A member / call / index chain that follows the constructor's argument list
    // binds to the NEW RESULT, not the callee: per ES2020 §13.3, `new X(a).b`
    // parses as `(new X(a)).b` (and `new X(a)()` / `new X(a)[i]` likewise). The
    // base cases below only handle a `rest` whose constructor call is the whole
    // expression; when a trailing chain follows the `)`, re-group explicitly so
    // the trailing access applies to the constructed object, reusing the existing
    // postfix (member/call/index) machinery (bd-7rj0t; engine donor bd-if9uy).
    // The parenthesized form is known-good, so this is a faithful regrouping
    // rather than new parsing logic.
    let (nested_new_count, _) = strip_leading_new_operators(rest);
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
    if let Some((_open, close)) =
        find_constructor_arguments_before_postfix(rest, nested_new_count, grammar_context)
    {
        let trailing = strip_leading_new_postfix_trivia(&rest[close + 1..]);
        let grouped = format!("(new {}){}", &rest[..=close], trailing);
        return parse_expression(&grouped, span, context, recursion_depth + 1);
    }

    // Find the arguments list at the end, if any.
    if rest.ends_with(')')
        && let Some((callee_src, args_inner)) = {
            let open = find_matching_open_paren_with_context(rest, grammar_context);
            open.map(|pos| (rest[..pos].trim(), &rest[pos + 1..rest.len() - 1]))
                .filter(|(callee_src, _)| !callee_src.is_empty())
        }
    {
        if callee_src.ends_with("?.") {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "optional chaining cannot be used in constructor position",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        let callee = parse_expression(callee_src, span, context, recursion_depth + 1)?;
        let arguments = if args_inner.trim().is_empty() {
            Vec::new()
        } else {
            parse_comma_separated_exprs(args_inner, span, context, recursion_depth + 1)?
        };
        if contains_optional_chain(&callee) {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "optional chaining cannot be used in constructor position",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        return Ok(Expression::New {
            callee: Box::new(callee),
            arguments,
        });
    }
    // `new Foo` without arguments.
    let callee = parse_expression(rest, span, context, recursion_depth + 1)?;
    if contains_optional_chain(&callee) {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "optional chaining cannot be used in constructor position",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(Expression::New {
        callee: Box::new(callee),
        arguments: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// Template literal parsing
// ---------------------------------------------------------------------------

fn skip_template_literal_with_context(
    source: &str,
    start: usize,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    if source.as_bytes().get(start) != Some(&b'`') {
        return None;
    }

    let mut index = start.saturating_add(1);
    while index < source.len() {
        let ch = source[index..].chars().next()?;
        match ch {
            '\\' => {
                index = index.saturating_add(ch.len_utf8());
                if index < source.len() {
                    let escaped = source[index..].chars().next()?;
                    index = index.saturating_add(escaped.len_utf8());
                }
            }
            '`' => return Some(index.saturating_add(ch.len_utf8())),
            '$' if source.as_bytes().get(index + 1) == Some(&b'{') => {
                let expression_start = index.saturating_add(2);
                let relative_end = find_template_interpolation_end(
                    &source[expression_start..],
                    grammar_context.expression(),
                )?;
                index = expression_start
                    .saturating_add(relative_end)
                    .saturating_add('}'.len_utf8());
            }
            _ => index = index.saturating_add(ch.len_utf8()),
        }
    }
    None
}

fn find_template_interpolation_end(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    let mut closing_index = None;
    let state = scan_binding_pattern_source_until_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            if !quoted && depth == 0 && ch == '}' {
                closing_index = Some(index);
                false
            } else {
                true
            }
        },
    );
    state.complete.then_some(closing_index).flatten()
}

fn parse_template_literal(
    expression: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    // Strip outer backticks.
    let inner = &expression[1..expression.len() - 1];
    let bytes = inner.as_bytes();
    let mut quasis = Vec::new();
    let mut expressions = Vec::new();
    let mut current_quasi = String::new();
    let mut i = 0;
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let escaped_source = &inner[i + 1..];
            let escaped_char = escaped_source
                .chars()
                .next()
                .expect("the byte following a template escape must exist");
            if matches!(escaped_char, '\n' | '\u{2028}' | '\u{2029}') {
                i = i.saturating_add(1 + escaped_char.len_utf8());
                continue;
            }
            if escaped_char == '\r' {
                i = i.saturating_add(2);
                if bytes.get(i) == Some(&b'\n') {
                    i = i.saturating_add(1);
                }
                continue;
            }
            // Escaped character — include literally. Advance past the
            // full UTF-8 codepoint that follows the backslash so we
            // don't split multi-byte characters.
            let esc_start = i;
            i += 1; // skip backslash
            // Advance past the full character after the backslash.
            if bytes[i] < 0x80 {
                i += 1;
            } else {
                // Decode the UTF-8 lead byte to find the codepoint length.
                let cp_len = if bytes[i] & 0xE0 == 0xC0 {
                    2
                } else if bytes[i] & 0xF0 == 0xE0 {
                    3
                } else {
                    4
                };
                i += cp_len;
            }
            // Safety: inner is valid UTF-8, and esc_start..i spans
            // a backslash followed by a complete codepoint.
            let end = i.min(inner.len());
            current_quasi.push_str(&inner[esc_start..end]);
            continue;
        }
        if bytes[i] == b'\r' {
            // Template TV normalizes CR and CRLF source characters to LF.
            current_quasi.push('\n');
            i = i.saturating_add(1);
            if bytes.get(i) == Some(&b'\n') {
                i = i.saturating_add(1);
            }
            continue;
        }
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            // Start of template expression.
            quasis.push(current_quasi.clone());
            current_quasi.clear();
            i += 2; // skip `${`
            let start = i;
            let Some(relative_end) =
                find_template_interpolation_end(&inner[start..], grammar_context)
            else {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "template literal interpolation is lexically incomplete or has unbalanced braces",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            };
            i = start.saturating_add(relative_end);
            let expr_src = &inner[start..i];
            let expr = parse_expression_allowing_sequence(
                expr_src.trim(),
                span,
                context,
                recursion_depth + 1,
            )?;
            expressions.push(expr);
            i += 1; // skip closing `}`
            continue;
        }
        // Advance by a full UTF-8 codepoint, not a single byte.
        if bytes[i] < 0x80 {
            current_quasi.push(bytes[i] as char);
            i += 1;
        } else {
            let cp_len = if bytes[i] & 0xE0 == 0xC0 {
                2
            } else if bytes[i] & 0xF0 == 0xE0 {
                3
            } else {
                4
            };
            let end = (i + cp_len).min(inner.len());
            current_quasi.push_str(&inner[i..end]);
            i = end;
        }
    }
    quasis.push(current_quasi);

    Ok(Expression::TemplateLiteral {
        quasis,
        expressions,
    })
}

// ---------------------------------------------------------------------------
// Assignment parsing
// ---------------------------------------------------------------------------

/// Try to parse an assignment expression: lhs op= rhs
fn try_parse_assignment(
    expr: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> Option<ParseResult<Expression>> {
    // Scan for assignment operators at top-level (depth 0).
    let bytes = expr.as_bytes();
    let mut assignment = None;
    let mut update_token_end = 0;
    let complete = scan_binding_pattern_source_with_context(
        expr,
        ScanGrammarContext::from_execution_context(context).expression(),
        |index, _ch, depth, quoted| {
            if assignment.is_some() || quoted || depth != 0 || index < update_token_end {
                return;
            }
            // The lexical scanner visits both bytes of an update token. Its
            // second + or - cannot begin += or -= in x++==y or x--===y.
            if matches!(bytes[index], b'+' | b'-') && bytes.get(index + 1) == Some(&bytes[index]) {
                update_token_end = index + 2;
                return;
            }
            let Some((operator, len)) = match_assignment_operator_at(bytes, index) else {
                return;
            };
            // A recognized operator owns this expression even when an operand
            // is missing. Let recursive parsing reject that operand instead of
            // falling through to a Raw expression that lowering can execute.
            assignment = Some((operator, index, len));
        },
    );
    if !complete {
        return Some(Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "lexically incomplete expression while scanning assignment operators",
            context.source_label.to_string(),
            Some(span.clone()),
        )));
    }
    let (op, index, len) = assignment?;
    let lhs = expr[..index].trim();
    let rhs = expr[index + len..].trim();
    let left = match parse_expression(lhs, span, context, recursion_depth + 1) {
        Ok(e) => e,
        Err(e) => return Some(Err(e)),
    };
    if contains_optional_chain(&left) {
        return Some(Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "optional chaining cannot be used as an assignment target",
            context.source_label.to_string(),
            Some(span.clone()),
        )));
    }
    let right = match parse_expression(rhs, span, context, recursion_depth + 1) {
        Ok(e) => e,
        Err(e) => return Some(Err(e)),
    };
    Some(Ok(Expression::Assignment {
        operator: op,
        left: Box::new(left),
        right: Box::new(right),
    }))
}

/// Match an assignment operator at byte position `i`. Returns (operator, byte_length).
fn match_assignment_operator_at(bytes: &[u8], i: usize) -> Option<(AssignmentOperator, usize)> {
    let remaining = bytes.len() - i;

    // Never match `=` that is preceded by another operator character (part of ==, !=, <=, >=, ===, !==).
    let prev_is_operator = i > 0 && matches!(bytes[i - 1], b'=' | b'!' | b'<' | b'>');

    // 4-char: >>>=
    if remaining >= 4 && &bytes[i..i + 4] == b">>>=" {
        return Some((AssignmentOperator::UnsignedRightShiftAssign, 4));
    }
    // 3-char compound assignments
    if remaining >= 3 {
        let three = &bytes[i..i + 3];
        let op = match three {
            b"<<=" => Some(AssignmentOperator::LeftShiftAssign),
            b">>=" => Some(AssignmentOperator::RightShiftAssign),
            b"**=" => Some(AssignmentOperator::ExponentiateAssign),
            b"&&=" => Some(AssignmentOperator::LogicalAndAssign),
            b"||=" => Some(AssignmentOperator::LogicalOrAssign),
            b"??=" => Some(AssignmentOperator::NullishCoalescingAssign),
            _ => None,
        };
        if let Some(op) = op {
            return Some((op, 3));
        }
    }
    // 2-char compound assignments
    if remaining >= 2 {
        let two = &bytes[i..i + 2];
        let op = match two {
            b"+=" => Some(AssignmentOperator::AddAssign),
            b"-=" => Some(AssignmentOperator::SubtractAssign),
            b"*=" => Some(AssignmentOperator::MultiplyAssign),
            b"/=" => Some(AssignmentOperator::DivideAssign),
            b"%=" => Some(AssignmentOperator::RemainderAssign),
            b"&=" => Some(AssignmentOperator::BitwiseAndAssign),
            b"|=" => Some(AssignmentOperator::BitwiseOrAssign),
            b"^=" => Some(AssignmentOperator::BitwiseXorAssign),
            _ => None,
        };
        if let Some(op) = op {
            return Some((op, 2));
        }
        // Check for plain `=` that is NOT part of ==, ===, !=, !==, <=, >=, =>.
        if bytes[i] == b'=' && bytes[i + 1] != b'=' && bytes[i + 1] != b'>' && !prev_is_operator {
            return Some((AssignmentOperator::Assign, 1));
        }
    }
    // 1-char: plain `=` at end of string
    if remaining == 1 && bytes[i] == b'=' && !prev_is_operator {
        return Some((AssignmentOperator::Assign, 1));
    }
    None
}

// ---------------------------------------------------------------------------
// Conditional (ternary) parsing
// ---------------------------------------------------------------------------

fn try_parse_conditional(
    expr: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> Option<ParseResult<Expression>> {
    // Find top-level `?` that is not `?.` (optional chaining) or `??` (nullish).
    let bytes = expr.as_bytes();
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
    let mut question = None;
    let complete = scan_binding_pattern_source_with_context(
        expr,
        grammar_context,
        |index, ch, depth, quoted| {
            if question.is_none()
                && !quoted
                && depth == 0
                && ch == '?'
                && is_conditional_question_punctuator(bytes, index)
            {
                question = Some(index);
            }
        },
    );
    if !complete {
        return Some(Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "lexically incomplete expression while scanning a conditional expression",
            context.source_label.to_string(),
            Some(span.clone()),
        )));
    }
    let question = question?;
    let test_src = expr[..question].trim();
    let rest = &expr[question + 1..];
    let Some(colon_idx) = find_ternary_colon(rest, grammar_context) else {
        return Some(Err(unsupported_expression_syntax_error(
            "conditional expression is missing its matching `:`",
            span,
            context,
        )));
    };
    let consequent_src = rest[..colon_idx].trim();
    let alternate_src = rest[colon_idx + 1..].trim();
    if test_src.is_empty() || consequent_src.is_empty() || alternate_src.is_empty() {
        return Some(Err(unsupported_expression_syntax_error(
            "conditional expression has an empty operand",
            span,
            context,
        )));
    }
    if top_level_conditional_punctuation_balance(alternate_src, grammar_context)
        .is_none_or(|(_, unmatched_colon)| unmatched_colon)
    {
        return Some(Err(unsupported_expression_syntax_error(
            "conditional expression has unmatched `:` punctuation",
            span,
            context,
        )));
    }
    let test = match parse_expression(test_src, span, context, recursion_depth + 1) {
        Ok(e) => e,
        Err(e) => return Some(Err(e)),
    };
    let consequent = match parse_expression(consequent_src, span, context, recursion_depth + 1) {
        Ok(e) => e,
        Err(e) => return Some(Err(e)),
    };
    let alternate = match parse_expression(alternate_src, span, context, recursion_depth + 1) {
        Ok(e) => e,
        Err(e) => return Some(Err(e)),
    };
    Some(Ok(Expression::Conditional {
        test: Box::new(test),
        consequent: Box::new(consequent),
        alternate: Box::new(alternate),
    }))
}

/// Find the index of a top-level `:` outside nested delimiters and lexical
/// literals. In particular, RegExp character classes and escapes may contain
/// bracket/colon bytes that must not close a computed object key.
#[cfg(test)]
fn find_top_level_colon(s: &str) -> Option<usize> {
    find_top_level_colon_with_context(s, ScanGrammarContext::SLOPPY_SCRIPT)
}

fn find_top_level_colon_with_context(
    s: &str,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    let mut colon = None;
    scan_binding_pattern_source_until_with_context(
        s,
        grammar_context,
        |index, ch, depth, quoted| {
            if !quoted && depth == 0 && ch == ':' {
                colon = Some(index);
                false
            } else {
                true
            }
        },
    );
    colon
}

/// Find the `:` that matches the *first* top-level `?` of a ternary, given the
/// slice *after* that `?`. Unlike [`find_top_level_colon`], this skips the `:`
/// of any nested ternary by tracking `?` depth, so `b ? c : d : e` returns the
/// index of the second (outer) `:`, grouping `a ? b ? c : d : e` as
/// `a ? (b ? c : d) : e`. `?.` (optional chaining) and `??` (nullish) are not
/// ternary `?`. (A dedicated finder rather than changing `find_top_level_colon`,
/// which labeled statements and object/type patterns also rely on.)
fn find_ternary_colon(s: &str, grammar_context: ScanGrammarContext) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut question_depth = 0usize;
    let mut colon = None;
    let complete =
        scan_binding_pattern_source_with_context(s, grammar_context, |index, ch, depth, quoted| {
            if quoted || depth != 0 || colon.is_some() {
                return;
            }
            if ch == '?' && is_conditional_question_punctuator(bytes, index) {
                question_depth += 1;
            } else if ch == ':' {
                if question_depth == 0 {
                    colon = Some(index);
                    return;
                }
                question_depth -= 1;
            }
        });
    if complete { colon } else { None }
}

fn top_level_conditional_punctuation_balance(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Option<(usize, bool)> {
    let bytes = source.as_bytes();
    let mut unmatched_questions = 0usize;
    let mut unmatched_colon = false;
    let complete = scan_binding_pattern_source_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            if quoted || depth != 0 {
                return;
            }
            if ch == '?' && is_conditional_question_punctuator(bytes, index) {
                unmatched_questions = unmatched_questions.saturating_add(1);
            } else if ch == ':' {
                if unmatched_questions == 0 {
                    unmatched_colon = true;
                } else {
                    unmatched_questions = unmatched_questions.saturating_sub(1);
                }
            }
        },
    );
    complete.then_some((unmatched_questions, unmatched_colon))
}

// ---------------------------------------------------------------------------
// Binary expression parsing with precedence scanning
// ---------------------------------------------------------------------------

/// Whether `b`, as the last significant byte before a `+`/`-`, means that
/// `+`/`-` is a unary sign rather than a binary operator. True for operator and
/// open-delimiter/separator bytes (after which an operand has not yet appeared).
fn is_operator_context_byte(b: u8) -> bool {
    matches!(
        b,
        b'+' | b'-'
            | b'*'
            | b'/'
            | b'%'
            | b'<'
            | b'>'
            | b'='
            | b'&'
            | b'|'
            | b'^'
            | b'~'
            | b'!'
            | b'('
            | b'['
            | b'{'
            | b','
            | b';'
            | b':'
            | b'?'
    )
}

fn generator_function_marker_prefix(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    let mut in_quote: Option<u8> = None;
    let mut escaped = false;
    let mut last_significant_end = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(quote) = in_quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote {
                in_quote = None;
                last_significant_end = index + 1;
            }
            index += 1;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let Some(comment_end) = prefix[index + 2..].find("*/") else {
                return false;
            };
            index += 2 + comment_end + 2;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index = prefix[index + 2..]
                .char_indices()
                .find(|(_, ch)| matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
                .map_or(bytes.len(), |(offset, ch)| {
                    index + 2 + offset + ch.len_utf8()
                });
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            in_quote = Some(byte);
            index += 1;
            continue;
        }
        if prefix.is_char_boundary(index)
            && prefix[index..].starts_with("function")
            && trim_directive_trivia(&prefix[index + "function".len()..])
                .0
                .is_empty()
        {
            let boundary = prefix[..last_significant_end].trim_end();
            if boundary.is_empty()
                || boundary
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| is_operator_context_byte(*byte))
                || [
                    "async", "await", "yield", "typeof", "void", "delete", "return", "throw", "new",
                ]
                .iter()
                .any(|keyword| {
                    boundary.strip_suffix(keyword).is_some_and(|before| {
                        let before = before.trim_end();
                        before.is_empty()
                            || before
                                .as_bytes()
                                .last()
                                .is_some_and(|byte| is_operator_context_byte(*byte))
                    })
                })
            {
                return true;
            }
        }
        if prefix.is_char_boundary(index) {
            let Some(ch) = prefix[index..].chars().next() else {
                break;
            };
            if !is_binding_pattern_whitespace(ch) {
                last_significant_end = index + ch.len_utf8();
            }
            index += ch.len_utf8();
        } else {
            index += 1;
        }
    }
    false
}

/// Try to find and parse a binary expression by locating the lowest-precedence
/// top-level operator and recursively parsing left and right operands.
fn try_parse_binary(
    expr: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> Option<ParseResult<Expression>> {
    let bytes = expr.as_bytes();

    // Track the lowest-precedence operator found at top level.
    let mut best_op: Option<BinaryOperator> = None;
    let mut best_pos: usize = 0;
    let mut best_len: usize = 0;
    let mut skip_until = 0usize;
    let mut saw_nullish_coalescing = false;
    let mut saw_logical_operator = false;
    let mut saw_disallowed_mixture = false;
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
    let complete =
        scan_binding_pattern_source_with_context(expr, grammar_context, |i, ch, depth, quoted| {
            if quoted || depth != 0 || i < skip_until {
                return;
            }
            if ch == ',' {
                saw_disallowed_mixture |= saw_nullish_coalescing && saw_logical_operator;
                saw_nullish_coalescing = false;
                saw_logical_operator = false;
                return;
            }
            let Some((op, len)) = match_binary_operator_at(bytes, i) else {
                return;
            };
            let generator_function_marker = matches!(op, BinaryOperator::Multiply)
                && generator_function_marker_prefix(&expr[..i]);
            if generator_function_marker {
                skip_until = i.saturating_add(len);
                return;
            }
            match op {
                BinaryOperator::NullishCoalescing => saw_nullish_coalescing = true,
                BinaryOperator::LogicalAnd | BinaryOperator::LogicalOr => {
                    saw_logical_operator = true;
                }
                _ => {}
            }
            // For the same precedence, prefer the rightmost for right-associative,
            // leftmost for left-associative.
            let dominated = if let Some(ref prev) = best_op {
                let prev_prec = prev.precedence();
                let new_prec = op.precedence();
                if new_prec < prev_prec {
                    true
                } else if new_prec == prev_prec {
                    // Left-associative: split at the rightmost occurrence.
                    !op.is_right_associative()
                } else {
                    false
                }
            } else {
                true
            };
            if dominated {
                // Make sure we have non-empty operands on both sides.
                let lhs = expr[..i].trim();
                let rhs = expr[i + len..].trim();
                // A `+`/`-` in unary position (no left operand, or the
                // preceding significant byte is itself an operator) is a sign
                // belonging to the right operand, not a binary split point —
                // e.g. the `-` in `2 * -3`, `a - -b`, or `2 ** -1`. Skipping it
                // lets the real binary operator win the split.
                let unary_sign = matches!(op, BinaryOperator::Add | BinaryOperator::Subtract)
                    && !source_ends_postfix_update(lhs, grammar_context)
                    && lhs
                        .as_bytes()
                        .last()
                        .is_none_or(|&c| is_operator_context_byte(c));
                let exponent_sign = matches!(op, BinaryOperator::Add | BinaryOperator::Subtract)
                    && is_decimal_exponent_sign(bytes, i);
                if !lhs.is_empty() && !rhs.is_empty() && !unary_sign && !exponent_sign {
                    best_op = Some(op);
                    best_pos = i;
                    best_len = len;
                }
            }
            skip_until = i.saturating_add(len);
        });
    if !complete {
        return Some(Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "lexically incomplete expression while scanning binary operators",
            context.source_label.to_string(),
            Some(span.clone()),
        )));
    }
    if saw_disallowed_mixture || (saw_nullish_coalescing && saw_logical_operator) {
        return Some(Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "unparenthesized `??` cannot be mixed with `&&` or `||`",
            context.source_label.to_string(),
            Some(span.clone()),
        )));
    }

    let op = best_op?;
    let lhs_src = expr[..best_pos].trim();
    let rhs_src = expr[best_pos + best_len..].trim();
    let left = match parse_expression(lhs_src, span, context, recursion_depth + 1) {
        Ok(e) => e,
        Err(e) => return Some(Err(e)),
    };
    let right = match parse_expression(rhs_src, span, context, recursion_depth + 1) {
        Ok(e) => e,
        Err(e) => return Some(Err(e)),
    };
    Some(Ok(Expression::Binary {
        operator: op,
        left: Box::new(left),
        right: Box::new(right),
    }))
}

/// A signed decimal exponent belongs to the numeric token. Inspect the
/// contiguous mantissa and its boundary so `name1e-2` and `0x1e-2` retain
/// their subtraction operator.
fn is_decimal_exponent_sign(bytes: &[u8], index: usize) -> bool {
    if index < 2
        || !matches!(bytes[index - 1], b'e' | b'E')
        || !bytes.get(index + 1).is_some_and(u8::is_ascii_digit)
    {
        return false;
    }
    let end = index - 1;
    let mut start = end;
    while start > 0 && matches!(bytes[start - 1], b'0'..=b'9' | b'.' | b'_') {
        start -= 1;
    }
    if start == end
        || (start > 0
            && (bytes[start - 1] >= 0x80 || is_identifier_part_character(bytes[start - 1] as char)))
    {
        return false;
    }
    let mantissa = &bytes[start..end];
    mantissa.iter().any(u8::is_ascii_digit) && mantissa.iter().filter(|&&c| c == b'.').count() <= 1
}

/// Match a binary operator at byte position `i`. Returns (operator, byte_length).
fn match_binary_operator_at(bytes: &[u8], i: usize) -> Option<(BinaryOperator, usize)> {
    let remaining = bytes.len() - i;

    // Check for keyword operators first (instanceof, in).
    if remaining >= 10 && &bytes[i..i + 10] == b"instanceof" {
        let before_ok = i == 0 || !is_identifier_continue(bytes[i - 1] as char);
        let after_ok = i + 10 >= bytes.len() || !is_identifier_continue(bytes[i + 10] as char);
        if before_ok && after_ok {
            return Some((BinaryOperator::Instanceof, 10));
        }
    }
    if remaining >= 2 && &bytes[i..i + 2] == b"in" {
        let before_ok = i == 0 || !is_identifier_continue(bytes[i - 1] as char);
        let after_ok = i + 2 >= bytes.len() || !is_identifier_continue(bytes[i + 2] as char);
        if before_ok && after_ok {
            return Some((BinaryOperator::In, 2));
        }
    }

    // 3-char operators
    if remaining >= 3 {
        let three = &bytes[i..i + 3];
        let op = match three {
            b"===" => Some(BinaryOperator::StrictEqual),
            b"!==" => Some(BinaryOperator::StrictNotEqual),
            b">>>" => Some(BinaryOperator::UnsignedRightShift),
            b"**=" | b"<<=" | b">>=" | b"&&=" | b"||=" | b"??=" => return None, // assignment, not binary
            _ => None,
        };
        if let Some(op) = op {
            return Some((op, 3));
        }
    }

    // 2-char operators
    if remaining >= 2 {
        let two = &bytes[i..i + 2];
        let op = match two {
            b"==" => Some(BinaryOperator::Equal),
            b"!=" => Some(BinaryOperator::NotEqual),
            b"<=" => Some(BinaryOperator::LessThanOrEqual),
            b">=" => Some(BinaryOperator::GreaterThanOrEqual),
            b"&&" => Some(BinaryOperator::LogicalAnd),
            b"||" => Some(BinaryOperator::LogicalOr),
            b"??" => Some(BinaryOperator::NullishCoalescing),
            b"**" => Some(BinaryOperator::Exponentiate),
            b"<<" => Some(BinaryOperator::LeftShift),
            b">>" => Some(BinaryOperator::RightShift),
            // Skip assignment operators.
            b"+=" | b"-=" | b"*=" | b"/=" | b"%=" | b"&=" | b"|=" | b"^=" => return None,
            b"=>" | b"++" | b"--" => return None, // arrow/update, not binary
            _ => None,
        };
        if let Some(op) = op {
            return Some((op, 2));
        }
    }

    // 1-char operators (avoid matching unary-only or assignment-only chars).
    if remaining >= 1 {
        let op = match bytes[i] {
            b'+' => Some(BinaryOperator::Add),
            b'-' => Some(BinaryOperator::Subtract),
            b'*' => {
                // Avoid matching ** (already handled above).
                if remaining >= 2 && bytes[i + 1] == b'*' {
                    return None;
                }
                Some(BinaryOperator::Multiply)
            }
            b'/' => Some(BinaryOperator::Divide),
            b'%' => Some(BinaryOperator::Remainder),
            b'<' => {
                if remaining >= 2 && bytes[i + 1] == b'<' {
                    return None;
                } // already matched
                if remaining >= 2 && bytes[i + 1] == b'=' {
                    return None;
                }
                Some(BinaryOperator::LessThan)
            }
            b'>' => {
                if remaining >= 2 && bytes[i + 1] == b'>' {
                    return None;
                }
                if remaining >= 2 && bytes[i + 1] == b'=' {
                    return None;
                }
                // Skip `>` that is part of `=>` (arrow).
                if i > 0 && bytes[i - 1] == b'=' {
                    return None;
                }
                Some(BinaryOperator::GreaterThan)
            }
            b'&' => {
                if remaining >= 2 && bytes[i + 1] == b'&' {
                    return None;
                }
                if remaining >= 2 && bytes[i + 1] == b'=' {
                    return None;
                }
                Some(BinaryOperator::BitwiseAnd)
            }
            b'|' => {
                if remaining >= 2 && bytes[i + 1] == b'|' {
                    return None;
                }
                if remaining >= 2 && bytes[i + 1] == b'=' {
                    return None;
                }
                Some(BinaryOperator::BitwiseOr)
            }
            b'^' => {
                if remaining >= 2 && bytes[i + 1] == b'=' {
                    return None;
                }
                Some(BinaryOperator::BitwiseXor)
            }
            b'=' => return None, // assignment, not binary
            _ => None,
        };
        if let Some(op) = op {
            return Some((op, 1));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Unary prefix parsing
// ---------------------------------------------------------------------------

/// bd-my5ar: Parse prefix / postfix `++` / `--` update expressions. The
/// string-based parser previously had no notion of update operators, so postfix
/// `i++` was mis-split by the binary `+` scanner into `i + Raw("+")` and prefix
/// `++i` collapsed into a double `UnaryPlus` (`+(+i)`) — neither actually
/// incremented the operand, which surfaced as the franken-engine <-> franken-core
/// loop-accumulate completion-value divergence (`for (var i…; i++)` never advanced
/// `i`).
///
/// bd-xi3bk: identifier operands now become a faithful
/// `Expression::Update { operator, argument, prefix }` node whose lowering reads
/// the operand, `ToNumber`-coerces it, writes back operand ± 1, and yields the
/// prior value for a postfix update or the new value for a prefix update. This
/// fixes both the *value* of a consumed postfix update (`x = i++` now yields i's
/// prior value) and the coercion of a non-numeric operand (`++`/`--` operate
/// numerically, unlike `+= 1` which would string-concatenate).
///
/// bd-rmxao: member operands (`obj.x++`, `a[i]--`) now also become an
/// `Expression::Update`, whose lowering stashes the object and computed key in
/// internal bindings so the reference is evaluated exactly once and reused for
/// the load and the store (a string-based `obj.x = +obj.x + 1` desugar would
/// double-evaluate a side-effecting object/key). Only `OptionalMember` operands
/// keep the compound-assignment desugar.
fn try_parse_update(
    expr: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> Option<ParseResult<Expression>> {
    let trimmed = expr.trim();

    // The operand of `++`/`--` must be a simple assignment target (reference).
    fn is_update_target(expression: &Expression) -> bool {
        matches!(
            expression,
            Expression::Identifier(_)
                | Expression::Member { .. }
                | Expression::OptionalMember { .. }
        )
    }

    // Identifier and member operands become a faithful `Update` node carrying
    // ToNumber + prefix/postfix result-value semantics; its lowering evaluates a
    // member reference's object and computed key exactly once (bd-xi3bk,
    // bd-rmxao). Only an `OptionalMember` operand keeps the compound-assignment
    // desugar — an optional-chain lvalue (`obj?.x++`) is not a valid assignment
    // target, and that desugar's lowering fails closed on it.
    fn build_update(arg: Expression, op: UpdateOperator, prefix: bool) -> Expression {
        if matches!(arg, Expression::Identifier(_) | Expression::Member { .. }) {
            Expression::Update {
                operator: op,
                argument: Box::new(arg),
                prefix,
            }
        } else {
            let assign = match op {
                UpdateOperator::Increment => AssignmentOperator::AddAssign,
                UpdateOperator::Decrement => AssignmentOperator::SubtractAssign,
            };
            Expression::Assignment {
                operator: assign,
                left: Box::new(arg),
                right: Box::new(Expression::NumericLiteral(1)),
            }
        }
    }

    for (token, op) in [
        ("++", UpdateOperator::Increment),
        ("--", UpdateOperator::Decrement),
    ] {
        let sym = token.as_bytes()[0];
        // Prefix: `++x` / `--x`.
        if let Some(rest) = trimmed.strip_prefix(token) {
            let rest = rest.trim();
            // Guard against `+++…`/`---…` chains and a missing operand: the
            // operand itself must not start with the same `+`/`-` symbol.
            if !rest.is_empty()
                && rest.as_bytes()[0] != sym
                && let Ok(arg) = parse_expression(rest, span, context, recursion_depth + 1)
                && is_update_target(&arg)
            {
                return Some(Ok(build_update(arg, op, true)));
            }
        }
        // Postfix: `x++` / `x--`.
        if let Some(head) = trimmed.strip_suffix(token) {
            let head = head.trim();
            // Guard against `x+++…`/`x---…` and operator-adjacent forms: the
            // target itself must not end with the same `+`/`-` symbol.
            if !head.is_empty()
                && head.as_bytes()[head.len() - 1] != sym
                && let Ok(arg) = parse_expression(head, span, context, recursion_depth + 1)
                && is_update_target(&arg)
            {
                return Some(Ok(build_update(arg, op, false)));
            }
        }
    }

    None
}

fn try_parse_unary_prefix(
    expr: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> Option<ParseResult<Expression>> {
    // Keyword-style unary: typeof, void, delete
    for (prefix, op) in [
        ("typeof ", UnaryOperator::Typeof),
        ("void ", UnaryOperator::Void),
        ("delete ", UnaryOperator::Delete),
    ] {
        if let Some(rest) = expr.strip_prefix(prefix) {
            let arg = match parse_expression(rest.trim(), span, context, recursion_depth + 1) {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            return Some(Ok(Expression::Unary {
                operator: op,
                argument: Box::new(arg),
            }));
        }
    }

    // Symbol-style unary: !, ~, +, -
    if expr.len() >= 2 {
        let (op, rest) = match expr.as_bytes()[0] {
            b'!' if expr.as_bytes()[1] != b'=' => (Some(UnaryOperator::LogicalNot), &expr[1..]),
            b'~' => (Some(UnaryOperator::BitwiseNot), &expr[1..]),
            b'-' if !expr.as_bytes()[1].is_ascii_digit() => {
                (Some(UnaryOperator::Negate), &expr[1..])
            }
            b'+' if !expr.as_bytes()[1].is_ascii_digit() => {
                (Some(UnaryOperator::UnaryPlus), &expr[1..])
            }
            _ => (None, expr),
        };
        if let Some(op) = op {
            let arg = match parse_expression(rest.trim(), span, context, recursion_depth + 1) {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            return Some(Ok(Expression::Unary {
                operator: op,
                argument: Box::new(arg),
            }));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Postfix: call, member access
// ---------------------------------------------------------------------------

/// Try to parse postfix operations (call, member access) on a primary expression.
fn try_parse_postfix(
    expr: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> Option<ParseResult<Expression>> {
    // Look for the last top-level `.` or `(` or `[` to split callee/object from access.
    // For `a.b.c(d)`, we need to find the right split point.

    // Strategy: find if the expression ends with `)` or `]`, suggesting call/member.
    let bytes = expr.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();

    // Tagged template (scaffold form): `tag`...`` or `obj.tag`...``.
    // The current AST does not have a dedicated tagged-template variant,
    // so we preserve deterministic structure as a call with one template arg.
    if bytes[bytes.len() - 1] == b'`'
        && let Some(template_start) = find_top_level_template_start(expr, grammar_context)
        && template_start > 0
    {
        let callee_src = expr[..template_start].trim();
        let template_src = expr[template_start..].trim();
        if !callee_src.is_empty() && template_src.starts_with('`') && template_src.ends_with('`') {
            return Some(Err(unsupported_expression_syntax_error(
                "tagged template expressions are not supported",
                span,
                context,
            )));
        }
    }

    // Call expression: ends with `)`
    if bytes[bytes.len() - 1] == b')'
        && let Some(open_paren) = find_matching_open_paren_with_context(expr, grammar_context)
        && open_paren > 0
    {
        let callee_src =
            match trim_binding_pattern_trivia_with_context(&expr[..open_paren], grammar_context) {
                Some(callee_src) => callee_src,
                None => {
                    return Some(Err(unsupported_expression_syntax_error(
                        "unterminated lexical trivia in call callee",
                        span,
                        context,
                    )));
                }
            };
        let args_src = &expr[open_paren + 1..expr.len() - 1]; // between ( and )
        let (callee_src, optional) = if let Some(stripped) = callee_src.strip_suffix("?.") {
            (stripped.trim(), true)
        } else {
            (callee_src, false)
        };
        if callee_src.is_empty() {
            return Some(Err(optional_chaining_syntax_error(
                "optional chaining call is missing a callee",
                span,
                context,
            )));
        }
        // Preserve the scaffold's pre-existing dynamic-import carrier until
        // the AST grows a dedicated ImportCall node. A bare `import` remains
        // a reserved IdentifierReference everywhere else.
        let callee = if !optional && callee_src == "import" {
            Expression::Identifier("import".to_string())
        } else {
            match parse_expression(callee_src, span, context, recursion_depth + 1) {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            }
        };
        let arguments =
            match parse_comma_separated_exprs(args_src, span, context, recursion_depth + 1) {
                Ok(a) => a,
                Err(e) => return Some(Err(e)),
            };
        return Some(Ok(if optional {
            Expression::OptionalCall {
                callee: Box::new(callee),
                arguments,
            }
        } else {
            Expression::Call {
                callee: Box::new(callee),
                arguments,
            }
        }));
    }

    // Computed member: ends with `]`
    if bytes[bytes.len() - 1] == b']'
        && let Some(open_bracket) = find_matching_open_bracket_with_context(expr, grammar_context)
        && open_bracket > 0
    {
        let object_src = match trim_binding_pattern_trivia_with_context(
            &expr[..open_bracket],
            grammar_context,
        ) {
            Some(object_src) => object_src,
            None => {
                return Some(Err(unsupported_expression_syntax_error(
                    "unterminated lexical trivia in computed member object",
                    span,
                    context,
                )));
            }
        };
        let prop_src = &expr[open_bracket + 1..expr.len() - 1];
        let (object_src, optional) = if let Some(stripped) = object_src.strip_suffix("?.") {
            (stripped.trim(), true)
        } else {
            (object_src, false)
        };
        if object_src.is_empty() {
            return Some(Err(optional_chaining_syntax_error(
                "optional chaining member access is missing an object",
                span,
                context,
            )));
        }
        let object = match parse_expression(object_src, span, context, recursion_depth + 1) {
            Ok(e) => e,
            Err(e) => return Some(Err(e)),
        };
        let property = match parse_expression_allowing_sequence(
            prop_src,
            span,
            context,
            recursion_depth + 1,
        ) {
            Ok(e) => e,
            Err(e) => return Some(Err(e)),
        };
        return Some(Ok(if optional {
            Expression::OptionalMember {
                object: Box::new(object),
                property: Box::new(property),
                computed: true,
            }
        } else {
            Expression::Member {
                object: Box::new(object),
                property: Box::new(property),
                computed: true,
            }
        }));
    }

    // Dot member access: a.b
    if let Some(dot_pos) = find_last_top_level_dot(expr, grammar_context) {
        let raw_object_src = &expr[..dot_pos];
        // IdentifierName is the one postfix operand that is not recursively
        // parsed as an Expression, so normalize its lexical boundary here.
        // Keep comments *inside* a token slice intact: `va/*c*/lue` must not
        // be joined into `value`.
        let property_src = match trim_binding_pattern_trivia(&expr[dot_pos + 1..]) {
            Some(property_src) => property_src,
            None => {
                return Some(Err(unsupported_expression_syntax_error(
                    "unterminated lexical trivia in member property",
                    span,
                    context,
                )));
            }
        };
        let (object_src, optional) = if let Some(stripped) = raw_object_src.strip_suffix('?') {
            (stripped.trim(), true)
        } else {
            let object_src = raw_object_src.trim();
            if trim_binding_pattern_trivia_with_context(object_src, grammar_context)
                .is_some_and(|lexical_object_src| lexical_object_src.ends_with('?'))
            {
                return Some(Err(optional_chaining_syntax_error(
                    "optional chaining punctuator `?.` cannot contain lexical trivia",
                    span,
                    context,
                )));
            }
            (object_src, false)
        };
        if optional && !is_identifier(property_src) {
            return Some(Err(optional_chaining_syntax_error(
                "optional chaining property access requires an identifier after `?.`",
                span,
                context,
            )));
        }
        if object_src == "new" && property_src == "target" {
            return Some(Ok(Expression::NewTarget));
        }
        if let Some(message) = unsupported_meta_property_message(object_src, property_src) {
            return Some(Err(unsupported_expression_syntax_error(
                message, span, context,
            )));
        }
        if !object_src.is_empty() && is_identifier(property_src) {
            let object = match parse_expression(object_src, span, context, recursion_depth + 1) {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            return Some(Ok(if optional {
                Expression::OptionalMember {
                    object: Box::new(object),
                    property: Box::new(Expression::Identifier(property_src.to_string())),
                    computed: false,
                }
            } else {
                Expression::Member {
                    object: Box::new(object),
                    property: Box::new(Expression::Identifier(property_src.to_string())),
                    computed: false,
                }
            }));
        }
    }

    if find_last_top_level_optional_chain(expr, grammar_context).is_some() {
        return Some(Err(optional_chaining_syntax_error(
            "unsupported optional chaining form",
            span,
            context,
        )));
    }

    None
}

fn optional_chaining_syntax_error(
    message: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseError {
    ParseError::new(
        ParseErrorCode::UnsupportedSyntax,
        message,
        context.source_label.to_string(),
        Some(span.clone()),
    )
}

fn unsupported_expression_syntax_error(
    message: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseError {
    ParseError::new(
        ParseErrorCode::UnsupportedSyntax,
        message,
        context.source_label.to_string(),
        Some(span.clone()),
    )
}

fn unsupported_meta_property_message(object_src: &str, property_src: &str) -> Option<&'static str> {
    match (object_src, property_src) {
        ("import", "meta") => Some("import.meta meta-property is not supported"),
        ("new", "target") => Some("new.target meta-property is not supported"),
        _ => None,
    }
}

fn contains_optional_chain(expression: &Expression) -> bool {
    match expression {
        Expression::OptionalCall { .. } | Expression::OptionalMember { .. } => true,
        Expression::Await(inner) => contains_optional_chain(inner),
        Expression::Yield { argument, .. } => argument
            .as_ref()
            .is_some_and(|a| contains_optional_chain(a)),
        Expression::SpreadElement(inner) => contains_optional_chain(inner),
        Expression::Binary { left, right, .. } | Expression::Assignment { left, right, .. } => {
            contains_optional_chain(left) || contains_optional_chain(right)
        }
        Expression::Unary { argument, .. } => contains_optional_chain(argument),
        Expression::Update { argument, .. } => contains_optional_chain(argument),
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            contains_optional_chain(test)
                || contains_optional_chain(consequent)
                || contains_optional_chain(alternate)
        }
        Expression::Call { callee, arguments } => {
            contains_optional_chain(callee) || arguments.iter().any(contains_optional_chain)
        }
        Expression::Member {
            object, property, ..
        } => contains_optional_chain(object) || contains_optional_chain(property),
        Expression::ArrayLiteral(elements) => {
            elements.iter().flatten().any(contains_optional_chain)
        }
        Expression::ObjectLiteral(properties) => properties.iter().any(|property| {
            contains_optional_chain(&property.key) || contains_optional_chain(&property.value)
        }),
        Expression::ArrowFunction { body, .. } => match body {
            ArrowBody::Expression(expr) => contains_optional_chain(expr),
            ArrowBody::Block(_) => false,
        },
        Expression::New { callee, arguments } => {
            contains_optional_chain(callee) || arguments.iter().any(contains_optional_chain)
        }
        Expression::TemplateLiteral { expressions, .. } => {
            expressions.iter().any(contains_optional_chain)
        }
        Expression::Identifier(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::FloatLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral
        | Expression::UndefinedLiteral
        | Expression::This
        | Expression::NewTarget
        | Expression::Super
        | Expression::Function { .. }
        | Expression::Raw(_)
        | Expression::RegExpLiteral { .. }
        | Expression::ClassExpression { .. } => false,
    }
}

/// Find the first top-level backtick that begins a trailing template literal.
fn find_top_level_template_start(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    let mut top_level_backticks = BTreeSet::new();
    let state = scan_binding_pattern_source_until_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            if quoted && ch == '`' && depth == 0 {
                top_level_backticks.insert(index);
            }
            true
        },
    );
    state
        .template_literal_ranges
        .into_iter()
        .map(|(start, _)| start)
        .find(|start| top_level_backticks.contains(start))
}

/// Find the top-level constructor-argument pair immediately before a result-side
/// postfix chain. Leading parenthesized callees and function parameter lists are
/// skipped because their suffix is not a postfix on a constructed result.
/// Returns `(open_index, close_index)` so the result-side chain can be regrouped
/// outside `new` (bd-7rj0t).
fn strip_leading_new_operators(mut input: &str) -> (usize, &str) {
    let mut count = 0;
    loop {
        if input == "new" {
            return (count + 1, "");
        }
        let Some(rest) = input
            .strip_prefix("new ")
            .or_else(|| input.strip_prefix("new\t"))
        else {
            return (count, input);
        };
        count += 1;
        input = rest.trim_start();
    }
}

fn strip_leading_new_postfix_trivia(mut input: &str) -> &str {
    loop {
        input = input.trim_start();
        if let Some(line_comment) = input.strip_prefix("//") {
            let Some(line_end) = line_comment.find(['\n', '\r']) else {
                return "";
            };
            input = &line_comment[line_end..];
            continue;
        }
        if let Some(block_comment) = input.strip_prefix("/*") {
            let Some(comment_end) = block_comment.find("*/") else {
                return "";
            };
            input = &block_comment[comment_end + 2..];
            continue;
        }
        return input;
    }
}

fn find_constructor_arguments_before_postfix(
    s: &str,
    mut argument_pairs_to_skip: usize,
    grammar_context: ScanGrammarContext,
) -> Option<(usize, usize)> {
    let mut open: Option<usize> = None;
    let mut found = None;
    let complete =
        scan_binding_pattern_source_with_context(s, grammar_context, |index, ch, depth, quoted| {
            if quoted || found.is_some() {
                return;
            }
            if ch == '(' && depth == 0 {
                open = Some(index);
                return;
            }
            if ch != ')' || depth != 1 {
                return;
            }
            let Some(open_index) = open.take() else {
                return;
            };
            let (_, callee_src) = strip_leading_new_operators(s[..open_index].trim());
            let trailing = strip_leading_new_postfix_trivia(&s[index + 1..]);
            if callee_src.is_empty()
                || !(trailing.starts_with('.')
                    || trailing.starts_with('[')
                    || trailing.starts_with('(')
                    || trailing.starts_with("?."))
            {
                return;
            }
            if argument_pairs_to_skip > 0 {
                argument_pairs_to_skip -= 1;
            } else {
                found = Some((open_index, index));
            }
        });
    if complete { found } else { None }
}

fn find_matching_open_paren_with_context(
    s: &str,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    find_matching_final_delimiter_with_context(s, '(', ')', grammar_context)
}

fn find_matching_open_bracket_with_context(
    s: &str,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    find_matching_final_delimiter_with_context(s, '[', ']', grammar_context)
}

fn find_matching_final_delimiter_with_context(
    s: &str,
    open: char,
    close: char,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    let final_index = s.len().checked_sub(close.len_utf8())?;
    let mut stack = Vec::new();
    let mut matching_open = None;
    let mut imbalanced = false;
    let complete =
        scan_binding_pattern_source_with_context(s, grammar_context, |index, ch, _, quoted| {
            if quoted || imbalanced {
                return;
            }
            if ch == open {
                stack.push(index);
            } else if ch == close {
                let Some(open_index) = stack.pop() else {
                    imbalanced = true;
                    return;
                };
                if index == final_index {
                    matching_open = Some(open_index);
                }
            }
        });
    if complete && !imbalanced && stack.is_empty() {
        matching_open
    } else {
        None
    }
}

/// Find the last top-level `.` (not inside delimiters, quotes, or numeric literals).
fn find_last_top_level_dot(s: &str, grammar_context: ScanGrammarContext) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut last_dot: Option<usize> = None;

    scan_binding_pattern_source_with_context(s, grammar_context, |index, ch, depth, quoted| {
        if !quoted && depth == 0 && ch == '.' {
            // Make sure this isn't a numeric dot (e.g., "3.14").
            let before_digit = index > 0 && bytes[index - 1].is_ascii_digit();
            let after_digit = index + 1 < bytes.len() && bytes[index + 1].is_ascii_digit();
            if !(before_digit && after_digit) {
                last_dot = Some(index);
            }
        }
    });
    last_dot
}

fn find_last_top_level_optional_chain(
    s: &str,
    grammar_context: ScanGrammarContext,
) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut last_optional: Option<usize> = None;

    scan_binding_pattern_source_with_context(s, grammar_context, |index, ch, depth, quoted| {
        if !quoted && depth == 0 && ch == '?' && is_optional_chaining_punctuator(bytes, index) {
            last_optional = Some(index);
        }
    });

    last_optional
}

// ---------------------------------------------------------------------------
// Array/object literal parsing
// ---------------------------------------------------------------------------

fn parse_array_literal(
    inner: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return Ok(Expression::ArrayLiteral(Vec::new()));
    }
    let parts = split_top_level_commas_with_context(
        trimmed,
        ScanGrammarContext::from_execution_context(context).expression(),
    );
    let mut elements = Vec::new();
    for part in &parts {
        let p = part.trim();
        if p.is_empty() {
            elements.push(None);
        } else {
            elements.push(Some(parse_expression(
                p,
                span,
                context,
                recursion_depth + 1,
            )?));
        }
    }
    if let Some(None) = elements.last()
        && trimmed.ends_with(',')
    {
        elements.pop();
    }
    Ok(Expression::ArrayLiteral(elements))
}

fn parse_object_literal(
    inner: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return Ok(Expression::ObjectLiteral(Vec::new()));
    }
    let parts = split_top_level_commas_with_context(
        trimmed,
        ScanGrammarContext::from_execution_context(context).expression(),
    );
    let mut properties = Vec::new();
    for part in &parts {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        // Spread property: `{ ...expr }` — parse the inner expression.
        if let Some(rest) = p.strip_prefix("...") {
            let inner = parse_expression(rest.trim_start(), span, context, recursion_depth + 1)?;
            let spread = Expression::SpreadElement(Box::new(inner));
            properties.push(ObjectProperty {
                key: spread.clone(),
                value: spread,
                computed: false,
                shorthand: true,
                kind: ObjectPropertyKind::Data,
            });
        } else if let Some(colon_idx) = find_top_level_colon_with_context(
            p,
            ScanGrammarContext::from_execution_context(context).expression(),
        ) {
            // Split on first top-level colon for key:value.
            let key_src = p[..colon_idx].trim();
            let value_src = p[colon_idx + 1..].trim();
            let computed = key_src.starts_with('[');
            let key = if computed {
                let error_source_label = context.source_label.to_string();
                let error_span = span.clone();
                let invalid_computed_key = || {
                    ParseError::new(
                        ParseErrorCode::UnsupportedSyntax,
                        format!("invalid computed object-literal property key: `{key_src}`"),
                        error_source_label.clone(),
                        Some(error_span.clone()),
                    )
                };
                let (inner, rest) = extract_balanced_with_context(
                    key_src,
                    '[',
                    ']',
                    ScanGrammarContext::from_execution_context(context).expression(),
                )
                .ok_or_else(&invalid_computed_key)?;
                if inner.trim().is_empty()
                    || !rest.trim().is_empty()
                    || split_top_level_commas_with_context(
                        inner,
                        ScanGrammarContext::from_execution_context(context).expression(),
                    )
                    .len()
                        > 1
                {
                    return Err(invalid_computed_key());
                }
                let key = parse_expression(inner.trim(), span, context, recursion_depth + 1)?;
                if matches!(&key, Expression::Raw(_) | Expression::SpreadElement(_)) {
                    return Err(invalid_computed_key());
                }
                key
            } else {
                parse_static_object_property_key(key_src, span, context)?
            };
            let value = parse_expression(value_src, span, context, recursion_depth + 1)?;
            properties.push(ObjectProperty {
                key,
                value,
                computed,
                shorthand: false,
                kind: ObjectPropertyKind::Data,
            });
        } else if let Some((key, value, computed, kind)) =
            try_parse_object_method(p, span, context, recursion_depth)?
        {
            // Preserve the concise-method distinction even though the body
            // payload shares the ordinary function-expression representation.
            properties.push(ObjectProperty {
                key,
                value,
                computed,
                shorthand: false,
                kind,
            });
        } else {
            // Shorthand property: { x } means { x: x }
            let invalid_shorthand = || {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    format!("invalid object-literal shorthand property: `{p}`"),
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            };
            let Expression::Identifier(name) = parse_static_object_property_key(p, span, context)
                .map_err(|_| invalid_shorthand())?
            else {
                return Err(invalid_shorthand());
            };
            if !is_context_identifier_reference(&name, context) {
                return Err(invalid_shorthand());
            }
            let key = Expression::Identifier(name.clone());
            let value = Expression::Identifier(name);
            properties.push(ObjectProperty {
                key,
                value,
                computed: false,
                shorthand: true,
                kind: ObjectPropertyKind::Data,
            });
        }
    }
    Ok(Expression::ObjectLiteral(properties))
}

/// Parse concise object methods and accessor definitions, including computed
/// names. A method named `get`, `set`, or `async` remains an ordinary method.
///
/// The function payload remains an anonymous ordinary-function-shaped body, but
/// the enclosing property kind preserves its descriptor and [[HomeObject]]
/// semantics. Generator methods remain outside this bounded subset.
fn try_parse_object_method(
    part: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Option<(Expression, Expression, bool, ObjectPropertyKind)>> {
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
    let part = trim_directive_trivia(part).0;
    let (kind, part) = [
        ("get", ObjectPropertyKind::Get),
        ("set", ObjectPropertyKind::Set),
    ]
    .into_iter()
    .find_map(|(keyword, kind)| {
        let after_keyword = strip_contextual_keyword(part, keyword)?;
        let after_trivia = trim_directive_trivia(after_keyword).0;
        (!after_trivia.starts_with('(') && !after_trivia.is_empty()).then_some((kind, after_trivia))
    })
    .unwrap_or((ObjectPropertyKind::Method, part));
    let (is_async, part) = if kind == ObjectPropertyKind::Method
        && let Some(after_async) = strip_contextual_keyword(part, "async")
    {
        let (after_trivia, saw_line_terminator) = trim_directive_trivia(after_async);
        if after_trivia.starts_with('(') {
            (false, part)
        } else if saw_line_terminator {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "async object-method modifier cannot cross a line terminator",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        } else {
            (true, after_trivia)
        }
    } else {
        (false, part)
    };
    if is_async && part.starts_with('*') {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "async generator object methods are not yet supported",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }

    if part.starts_with('[') {
        let Some((key_inner, after_key)) =
            extract_balanced_with_context(part, '[', ']', grammar_context)
        else {
            return Ok(None);
        };
        let function_source = trim_directive_trivia(after_key).0;
        if !function_source.starts_with('(') {
            return Ok(None);
        }
        let error_source_label = context.source_label.to_string();
        let error_span = span.clone();
        let invalid_computed_key = || {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("invalid computed object-literal method key: `[{key_inner}]`"),
                error_source_label.clone(),
                Some(error_span.clone()),
            )
        };
        if key_inner.trim().is_empty() {
            return Err(invalid_computed_key());
        }
        let key = parse_expression(key_inner.trim(), span, context, recursion_depth + 1)?;
        if matches!(&key, Expression::Raw(_) | Expression::SpreadElement(_)) {
            return Err(invalid_computed_key());
        }
        validate_object_method_source_consumed(function_source, is_async, span, context)?;
        let value = parse_function_expression(
            function_source,
            is_async,
            span,
            context,
            recursion_depth + 1,
        )?;
        validate_object_method_parameter_names(&value, span, context)?;
        validate_object_accessor_parameters(kind, &value, span, context)?;
        return Ok(Some((key, value, true, kind)));
    }

    let mut parameter_list_index = None;
    scan_binding_pattern_source_until_with_context(
        part,
        grammar_context,
        |index, ch, depth, quoted| {
            if !quoted && depth == 0 && ch == '(' {
                parameter_list_index = Some(index);
                false
            } else {
                true
            }
        },
    );
    let Some(parameter_list_index) = parameter_list_index else {
        return Ok(None);
    };
    let Some(key_source) = trim_binding_pattern_trivia(&part[..parameter_list_index]) else {
        return Ok(None);
    };
    if key_source.is_empty() {
        return Ok(None);
    }
    let Ok(key) = parse_static_object_property_key(key_source, span, context) else {
        return Ok(None);
    };
    let function_source = &part[parameter_list_index..];
    validate_object_method_source_consumed(function_source, is_async, span, context)?;
    let value = parse_function_expression(
        function_source,
        is_async,
        span,
        context,
        recursion_depth + 1,
    )?;
    validate_object_method_parameter_names(&value, span, context)?;
    validate_object_accessor_parameters(kind, &value, span, context)?;
    Ok(Some((key, value, false, kind)))
}

fn validate_object_accessor_parameters(
    kind: ObjectPropertyKind,
    value: &Expression,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    let Expression::Function { params, .. } = value else {
        return Ok(());
    };
    let invalid = match kind {
        ObjectPropertyKind::Get => !params.is_empty(),
        ObjectPropertyKind::Set => {
            params.len() != 1 || matches!(&params[0].pattern, BindingPattern::Rest(_))
        }
        ObjectPropertyKind::Data | ObjectPropertyKind::Method => false,
    };
    if invalid {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "a getter takes no parameters; a setter takes exactly one non-rest parameter",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

fn validate_object_method_source_consumed(
    function_source: &str,
    is_async: bool,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    let (_, after_params) = extract_balanced_with_context(
        function_source,
        '(',
        ')',
        ScanGrammarContext::function_parameters(is_async, false, context.strict_mode),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "object method has an unbalanced parameter list",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let (_, trailing) = extract_balanced_with_context(
        trim_directive_trivia(after_params).0,
        '{',
        '}',
        ScanGrammarContext::function_body(is_async, false, context.strict_mode),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "object method requires a braced body",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let (trailing, _) = trim_directive_trivia(trailing);
    if !trailing.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "object method has trailing source after its body",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

fn validate_object_method_parameter_names(
    value: &Expression,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    let Expression::Function { params, .. } = value else {
        return Ok(());
    };
    let mut seen = BTreeSet::new();
    for name in params
        .iter()
        .flat_map(|parameter| parameter.pattern.binding_names())
    {
        if !seen.insert(name) {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("duplicate object-method parameter binding `{name}` is not allowed"),
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Comma splitting for argument lists and array/object literals
// ---------------------------------------------------------------------------

/// Split a string by top-level commas (not inside delimiters or quotes).
fn split_top_level_commas(s: &str) -> Vec<&str> {
    split_top_level_commas_with_context(s, ScanGrammarContext::SLOPPY_SCRIPT)
}

fn split_top_level_commas_with_context(s: &str, grammar_context: ScanGrammarContext) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;

    scan_binding_pattern_source_with_context(s, grammar_context, |index, ch, depth, quoted| {
        if !quoted && depth == 0 && ch == ',' {
            parts.push(&s[start..index]);
            start = index + ch.len_utf8();
        }
    });
    parts.push(&s[start..]);
    parts
}

/// Parse the full Expression grammar, including its lowest-precedence comma
/// operator. Each operand is an AssignmentExpression; missing operands,
/// trailing commas, and spread syntax are not valid sequence expressions.
fn parse_expression_allowing_sequence(
    expression: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
    let parts = split_top_level_commas_with_context(expression, grammar_context);
    if parts.len() == 1 {
        return parse_expression(expression, span, context, recursion_depth);
    }

    let mut operands = Vec::with_capacity(parts.len());
    for part in parts {
        let operand = parse_expression(part, span, context, recursion_depth)?;
        if matches!(&operand, Expression::SpreadElement(_)) {
            return Err(unsupported_expression_syntax_error(
                "spread is not allowed in a sequence expression",
                span,
                context,
            ));
        }
        operands.push(operand);
    }
    Ok(build_sequence_expression(operands, span))
}

/// Evaluate sequence operands as call arguments in their original scope, then
/// return the last argument from an identity arrow. Its generated parameter
/// names cannot shadow operands, which execute before entering that arrow.
/// Chunks keep long sequences within the existing call-register budget.
fn build_sequence_expression(operands: Vec<Expression>, span: &SourceSpan) -> Expression {
    const SEQUENCE_CHUNK: usize = 64;

    fn sequence_call(operands: Vec<Expression>, span: &SourceSpan) -> Expression {
        let params = (0..operands.len())
            .map(|index| FunctionParam {
                pattern: BindingPattern::Identifier(format!("__seq_{index}")),
                span: span.clone(),
            })
            .collect();
        let last = format!("__seq_{}", operands.len() - 1);
        Expression::Call {
            callee: Box::new(Expression::ArrowFunction {
                params,
                body: ArrowBody::Expression(Box::new(Expression::Identifier(last))),
                is_async: false,
            }),
            arguments: operands,
        }
    }

    debug_assert!(operands.len() >= 2);
    let mut operands = operands.into_iter();
    let mut sequence = sequence_call(operands.by_ref().take(SEQUENCE_CHUNK).collect(), span);
    loop {
        let rest: Vec<_> = operands.by_ref().take(SEQUENCE_CHUNK - 1).collect();
        if rest.is_empty() {
            return sequence;
        }
        let mut next = Vec::with_capacity(rest.len() + 1);
        next.push(sequence);
        next.extend(rest);
        sequence = sequence_call(next, span);
    }
}

/// Parse a comma-separated list of expressions (for function call arguments).
fn parse_comma_separated_exprs(
    s: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Vec<Expression>> {
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
    let trimmed =
        trim_binding_pattern_trivia_with_context(s, grammar_context).ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "unterminated lexical trivia in call arguments",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let parts = split_top_level_commas_with_context(trimmed, grammar_context);
    let mut exprs = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        let p =
            trim_binding_pattern_trivia_with_context(part, grammar_context).ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "unterminated lexical trivia in call argument",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            })?;
        if p.is_empty() {
            if index + 1 == parts.len() && parts.len() > 1 {
                continue;
            }
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "missing expression in call argument list",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        exprs.push(parse_expression(p, span, context, recursion_depth + 1)?);
    }
    Ok(exprs)
}

fn parse_i64_numeric_literal(input: &str) -> Option<i64> {
    let (is_neg, digits) = if let Some(rest) = input.strip_prefix('-') {
        (true, rest)
    } else {
        (false, input)
    };

    if digits.is_empty() {
        return None;
    }

    // Strip optional numeric separators (ES2021 but commonly supported).
    let cleaned: String;
    let digits_ref = if digits.contains('_') {
        cleaned = digits.replace('_', "");
        cleaned.as_str()
    } else {
        digits
    };

    let value_u64 = if let Some(hex) = digits_ref
        .strip_prefix("0x")
        .or_else(|| digits_ref.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u64::from_str_radix(hex, 16).ok()?
    } else if let Some(oct) = digits_ref
        .strip_prefix("0o")
        .or_else(|| digits_ref.strip_prefix("0O"))
    {
        if oct.is_empty() || !oct.chars().all(|c| matches!(c, '0'..='7')) {
            return None;
        }
        u64::from_str_radix(oct, 8).ok()?
    } else if let Some(bin) = digits_ref
        .strip_prefix("0b")
        .or_else(|| digits_ref.strip_prefix("0B"))
    {
        if bin.is_empty() || !bin.chars().all(|c| c == '0' || c == '1') {
            return None;
        }
        u64::from_str_radix(bin, 2).ok()?
    } else if digits_ref.chars().all(|c| c.is_ascii_digit()) {
        digits_ref.parse::<u64>().ok()?
    } else {
        return None;
    };

    if is_neg {
        if value_u64 > (i64::MAX as u64 + 1) {
            return None;
        }
        Some(value_u64.wrapping_neg() as i64)
    } else {
        if value_u64 > (i64::MAX as u64) {
            return None;
        }
        Some(value_u64 as i64)
    }
}

/// Parse a floating-point numeric literal: decimal (1.5), leading dot (.5),
/// trailing dot (1.), or scientific notation (1e10, 1.5e-3).
fn parse_f64_numeric_literal(input: &str) -> Option<f64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Strip numeric separators
    let cleaned: String;
    let digits_ref = if trimmed.contains('_') {
        cleaned = trimmed.replace('_', "");
        cleaned.as_str()
    } else {
        trimmed
    };

    // Decimal integer literals beyond i64 still denote Numbers. They reach
    // this fallback after parse_i64_numeric_literal and must round to f64,
    // rather than becoming an unparsed Raw expression.
    let decimal_integer = digits_ref
        .strip_prefix('-')
        .unwrap_or(digits_ref)
        .bytes()
        .all(|byte| byte.is_ascii_digit());
    if decimal_integer && parse_i64_numeric_literal(digits_ref).is_some() {
        return None;
    }
    if !decimal_integer
        && !digits_ref.contains('.')
        && !digits_ref.contains('e')
        && !digits_ref.contains('E')
    {
        return None;
    }

    // Try to parse as f64
    digits_ref.parse::<f64>().ok()
}

fn push_char_utf16(units: &mut Vec<u16>, value: char) {
    let mut encoded = [0_u16; 2];
    units.extend_from_slice(value.encode_utf16(&mut encoded));
}

/// Decode the numeric payload after a `\u` escape without forcing it through
/// Rust's Unicode-scalar-only `char` carrier. Four-digit escapes denote one
/// UTF-16 code unit and may therefore be a surrogate. Braced escapes denote a
/// code point up to U+10FFFF; values in the surrogate range remain one exact
/// code unit, matching ECMAScript string values.
fn decode_quoted_unicode_escape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Option<u32> {
    if chars.peek() == Some(&'{') {
        chars.next();
        let mut value = 0_u32;
        let mut digits = 0_u32;
        loop {
            match chars.next()? {
                '}' if digits > 0 => break,
                '}' => return None,
                ch => {
                    value = value.checked_mul(16)?.checked_add(ch.to_digit(16)?)?;
                    if value > 0x10_FFFF {
                        return None;
                    }
                    digits += 1;
                }
            }
        }
        Some(value)
    } else {
        let mut value = 0_u32;
        for _ in 0..4 {
            value = value
                .checked_mul(16)?
                .checked_add(chars.next()?.to_digit(16)?)?;
        }
        Some(value)
    }
}

/// If `expr` begins with a quoted literal, return the byte index immediately
/// after its closing delimiter. This scanner recognizes only the lexical
/// extent; callers must still run [`parse_quoted_expression_string`] over the
/// returned prefix to validate escape payloads.
fn leading_string_literal_end(expr: &str) -> Option<usize> {
    let mut chars = expr.char_indices().peekable();
    let (_, delimiter) = chars.next()?;
    if !matches!(delimiter, '\'' | '"') {
        return None;
    }

    while let Some((index, ch)) = chars.next() {
        match ch {
            '\\' => {
                let (_, escaped) = chars.next()?;
                if escaped == '\r' && chars.peek().is_some_and(|(_, next)| *next == '\n') {
                    chars.next();
                }
            }
            '\n' | '\r' => return None,
            ch if ch == delimiter => return Some(index + ch.len_utf8()),
            _ => {}
        }
    }
    None
}

/// Cook one quoted expression literal into its exact ECMAScript UTF-16 value.
/// Unlike a Rust `String`, [`JsString`] can retain unpaired surrogate escapes.
/// Adjacent high/low units are normalized by `JsString::from_code_units`, so
/// paired escapes still heal to the ordinary UTF-8 fast representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyDecimalEscapeMode {
    AnnexBSloppy,
    Reject,
}

fn legacy_decimal_escape_mode(context: &ParseExecutionContext<'_>) -> LegacyDecimalEscapeMode {
    if context.goal == ParseGoal::Script && !context.strict_mode {
        LegacyDecimalEscapeMode::AnnexBSloppy
    } else {
        LegacyDecimalEscapeMode::Reject
    }
}

fn decode_legacy_decimal_escape(
    first: char,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    mode: LegacyDecimalEscapeMode,
) -> Option<u16> {
    if mode == LegacyDecimalEscapeMode::Reject {
        return None;
    }
    if matches!(first, '8' | '9') {
        // NonOctalDecimalEscapeSequence contributes the digit character, not
        // its numeric value.
        return u16::try_from(u32::from(first)).ok();
    }

    let mut value = first.to_digit(8)?;
    let following_limit = if matches!(first, '0'..='3') { 2 } else { 1 };
    for _ in 0..following_limit {
        let Some(digit) = chars.peek().and_then(|next| next.to_digit(8)) else {
            break;
        };
        chars.next();
        value = value.checked_mul(8)?.checked_add(digit)?;
    }
    u16::try_from(value).ok()
}

fn parse_quoted_expression_string(
    input: &str,
    legacy_mode: LegacyDecimalEscapeMode,
) -> Option<JsString> {
    if input.len() < 2 {
        return None;
    }
    let delimiter = input.chars().next()?;
    if !matches!(delimiter, '\'' | '"') || input.chars().next_back()? != delimiter {
        return None;
    }
    let inner = &input[delimiter.len_utf8()..input.len() - delimiter.len_utf8()];
    let mut units = Vec::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            if ch == delimiter || matches!(ch, '\n' | '\r') {
                return None;
            }
            push_char_utf16(&mut units, ch);
            continue;
        }

        let escaped = chars.next()?;
        match escaped {
            '\n' | '\u{2028}' | '\u{2029}' => {}
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            'n' => units.push(u16::from(b'\n')),
            't' => units.push(u16::from(b'\t')),
            'r' => units.push(u16::from(b'\r')),
            'b' => units.push(0x0008),
            'f' => units.push(0x000C),
            'v' => units.push(0x000B),
            '0' if !chars.peek().is_some_and(char::is_ascii_digit) => units.push(0),
            decimal @ '0'..='9' => {
                units.push(decode_legacy_decimal_escape(
                    decimal,
                    &mut chars,
                    legacy_mode,
                )?);
            }
            '\\' => units.push(u16::from(b'\\')),
            '\'' => units.push(u16::from(b'\'')),
            '"' => units.push(u16::from(b'"')),
            '`' => units.push(u16::from(b'`')),
            'x' => {
                let high = chars.next()?.to_digit(16)?;
                let low = chars.next()?.to_digit(16)?;
                units.push(u16::try_from(high * 16 + low).ok()?);
            }
            'u' => {
                let value = decode_quoted_unicode_escape(&mut chars)?;
                if let Ok(unit) = u16::try_from(value) {
                    units.push(unit);
                } else {
                    push_char_utf16(&mut units, char::from_u32(value)?);
                }
            }
            // ES NonEscapeCharacter: the escape contributes the character
            // itself (for example `\q` cooks to `q`).
            other => push_char_utf16(&mut units, other),
        }
    }
    Some(JsString::from_code_units(&units))
}

/// Parse a quoted module source exactly, including lone UTF-16 surrogates.
/// Cooking is shared with expression literals and never projects through
/// UTF-8, so distinct exact module keys remain distinct through lowering.
pub(crate) fn parse_quoted_string(input: &str) -> Option<JsString> {
    parse_quoted_expression_string(input, LegacyDecimalEscapeMode::Reject)
}

/// Parse a regex literal: `/pattern/flags`.
///
/// The pattern may contain escaped slashes (`\/`) or character classes with
/// slashes (`[/]`). Flags are the parser's supported RegExp flag set: d, g, i, m, s, u, y.
fn parse_regexp_literal(input: &str) -> Option<(String, String)> {
    let input = input.trim();
    let prefix = parse_regexp_literal_prefix(input)?;
    (prefix.consumed == input.len() && prefix.flag_error.is_none())
        .then_some((prefix.pattern, prefix.flags))
}

struct RegExpLiteralPrefix {
    pattern: String,
    flags: String,
    consumed: usize,
    flag_error: Option<RegExpFlagError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegExpFlagError {
    Duplicate(char),
    Unsupported(char),
}

fn regexp_flag_error(flags: &str) -> Option<RegExpFlagError> {
    let mut seen = 0u8;
    for flag in flags.chars() {
        let bit = match flag {
            'd' => 1 << 0,
            'g' => 1 << 1,
            'i' => 1 << 2,
            'm' => 1 << 3,
            's' => 1 << 4,
            'u' => 1 << 5,
            'y' => 1 << 6,
            unsupported => return Some(RegExpFlagError::Unsupported(unsupported)),
        };
        if seen & bit != 0 {
            return Some(RegExpFlagError::Duplicate(flag));
        }
        seen |= bit;
    }
    None
}

fn regexp_flag_tail_len(source: &str) -> usize {
    let mut offset = 0usize;
    while offset < source.len() {
        let remaining = &source[offset..];
        if remaining.starts_with('\\') {
            let consumed = decode_identifier_unicode_escape_prefix(remaining)
                .map_or(1, |(_decoded, consumed)| consumed);
            offset = offset.saturating_add(consumed);
            continue;
        }
        let Some(ch) = remaining.chars().next() else {
            break;
        };
        if !is_identifier_part_character(ch) {
            break;
        }
        offset = offset.saturating_add(ch.len_utf8());
    }
    offset
}

fn parse_regexp_literal_prefix(input: &str) -> Option<RegExpLiteralPrefix> {
    let input = input.trim();
    if !input.starts_with('/') {
        return None;
    }

    // Find the closing slash, handling escapes and character classes
    let bytes = input.as_bytes();
    let mut i = 1; // Start after opening slash
    let mut in_char_class = false;
    let mut prev_escape = false;

    while i < bytes.len() {
        if input.is_char_boundary(i)
            && input[i..]
                .chars()
                .next()
                .is_some_and(|ch| matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
        {
            return None;
        }
        let c = bytes[i];
        if prev_escape {
            prev_escape = false;
            i += 1;
            continue;
        }
        if c == b'\\' {
            prev_escape = true;
            i += 1;
            continue;
        }
        if c == b'[' && !in_char_class {
            in_char_class = true;
        } else if c == b']' && in_char_class {
            in_char_class = false;
        } else if c == b'/' && !in_char_class {
            // Found closing slash
            let pattern = &input[1..i];
            let rest = &input[i + 1..];
            // RegExp flags lexically consume an IdentifierPart sequence. Keep
            // that complete extent even when validation fails so delimiter and
            // slash-goal scanners do not reinterpret an invalid flag tail as
            // surrounding source. The parser's existing accepted set is
            // `dgimsuy`; duplicates and every other spelling fail separately.
            let flag_len = regexp_flag_tail_len(rest);
            let flags = rest[..flag_len].to_string();
            return Some(RegExpLiteralPrefix {
                pattern: pattern.to_string(),
                flag_error: regexp_flag_error(&flags),
                flags,
                consumed: i + 1 + flag_len,
            });
        }
        i += 1;
    }

    None
}

const LEX_CLASS_WHITESPACE: u8 = 1 << 0;
const LEX_CLASS_IDENTIFIER_START: u8 = 1 << 1;
const LEX_CLASS_IDENTIFIER_CONTINUE: u8 = 1 << 2;
const LEX_CLASS_DIGIT: u8 = 1 << 3;
const LEX_CLASS_QUOTE: u8 = 1 << 4;
const LEX_CLASS_TWO_CHAR_OPERATOR_LEAD: u8 = 1 << 5;

const LEX_BYTE_CLASS_TABLE: [u8; 256] = build_lex_byte_class_table();

const fn build_lex_byte_class_table() -> [u8; 256] {
    let mut table = [0u8; 256];

    table[b' ' as usize] |= LEX_CLASS_WHITESPACE;
    table[b'\t' as usize] |= LEX_CLASS_WHITESPACE;
    table[b'\n' as usize] |= LEX_CLASS_WHITESPACE;
    table[b'\r' as usize] |= LEX_CLASS_WHITESPACE;
    table[0x0b] |= LEX_CLASS_WHITESPACE;
    table[0x0c] |= LEX_CLASS_WHITESPACE;

    let mut value = b'a';
    while value <= b'z' {
        table[value as usize] |= LEX_CLASS_IDENTIFIER_START | LEX_CLASS_IDENTIFIER_CONTINUE;
        value = value.saturating_add(1);
    }
    value = b'A';
    while value <= b'Z' {
        table[value as usize] |= LEX_CLASS_IDENTIFIER_START | LEX_CLASS_IDENTIFIER_CONTINUE;
        value = value.saturating_add(1);
    }

    value = b'0';
    while value <= b'9' {
        table[value as usize] |= LEX_CLASS_DIGIT | LEX_CLASS_IDENTIFIER_CONTINUE;
        value = value.saturating_add(1);
    }

    table[b'_' as usize] |= LEX_CLASS_IDENTIFIER_START | LEX_CLASS_IDENTIFIER_CONTINUE;
    table[b'$' as usize] |= LEX_CLASS_IDENTIFIER_START | LEX_CLASS_IDENTIFIER_CONTINUE;

    table[b'\'' as usize] |= LEX_CLASS_QUOTE;
    table[b'"' as usize] |= LEX_CLASS_QUOTE;

    table[b'=' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'!' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'<' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'>' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'&' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'|' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;
    table[b'?' as usize] |= LEX_CLASS_TWO_CHAR_OPERATOR_LEAD;

    table
}

#[inline]
const fn lex_class(byte: u8) -> u8 {
    LEX_BYTE_CLASS_TABLE[byte as usize]
}

#[inline]
const fn lex_has_class(byte: u8, class_mask: u8) -> bool {
    (lex_class(byte) & class_mask) != 0
}

#[inline]
const fn is_two_char_operator(first: u8, second: u8) -> bool {
    matches!(
        (first, second),
        (b'=', b'=')
            | (b'!', b'=')
            | (b'<', b'=')
            | (b'>', b'=')
            | (b'&', b'&')
            | (b'|', b'|')
            | (b'?', b'?')
            | (b'=', b'>')
    )
}

#[inline]
const fn utf8_codepoint_len_from_lead(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if (lead & 0b1110_0000) == 0b1100_0000 {
        2
    } else if (lead & 0b1111_0000) == 0b1110_0000 {
        3
    } else if (lead & 0b1111_1000) == 0b1111_0000 {
        4
    } else {
        1
    }
}

#[inline]
const fn is_utf8_continuation(byte: u8) -> bool {
    (byte & 0b1100_0000) == 0b1000_0000
}

fn advance_utf8_boundary_safe(bytes: &[u8], index: usize) -> usize {
    if index >= bytes.len() {
        return bytes.len();
    }

    let width = utf8_codepoint_len_from_lead(bytes[index]);
    let fallback = index.saturating_add(1);
    if width == 1 || index.saturating_add(width) > bytes.len() {
        return fallback;
    }

    let mut offset = index + 1;
    while offset < index + width {
        if !is_utf8_continuation(bytes[offset]) {
            return fallback;
        }
        offset = offset.saturating_add(1);
    }

    index + width
}

#[derive(Debug)]
struct Utf8BoundarySafeScanner<'a> {
    bytes: &'a [u8],
    index: usize,
    token_count: u64,
}

impl<'a> Utf8BoundarySafeScanner<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            index: 0,
            token_count: 0,
        }
    }

    fn count_tokens(mut self) -> u64 {
        while self.index < self.bytes.len() {
            let byte = self.bytes[self.index];

            if lex_has_class(byte, LEX_CLASS_WHITESPACE) {
                self.index = self.index.saturating_add(1);
                continue;
            }

            if lex_has_class(byte, LEX_CLASS_IDENTIFIER_START) {
                self.scan_identifier();
                self.bump_token();
                continue;
            }

            if lex_has_class(byte, LEX_CLASS_DIGIT) {
                self.scan_numeric_literal();
                self.bump_token();
                continue;
            }

            if lex_has_class(byte, LEX_CLASS_QUOTE) {
                self.scan_string_literal(byte);
                self.bump_token();
                continue;
            }

            if byte == b'`' {
                self.scan_template_literal();
                self.bump_token();
                continue;
            }

            if lex_has_class(byte, LEX_CLASS_TWO_CHAR_OPERATOR_LEAD)
                && self.index + 1 < self.bytes.len()
                && is_two_char_operator(byte, self.bytes[self.index + 1])
            {
                self.index = self.index.saturating_add(2);
                self.bump_token();
                continue;
            }

            self.advance_single_symbol();
            self.bump_token();
        }

        self.token_count
    }

    fn scan_identifier(&mut self) {
        self.index = self.index.saturating_add(1);
        while self.index < self.bytes.len()
            && lex_has_class(self.bytes[self.index], LEX_CLASS_IDENTIFIER_CONTINUE)
        {
            self.index = self.index.saturating_add(1);
        }
    }

    fn scan_numeric_literal(&mut self) {
        self.index = self.index.saturating_add(1);
        while self.index < self.bytes.len()
            && lex_has_class(self.bytes[self.index], LEX_CLASS_DIGIT)
        {
            self.index = self.index.saturating_add(1);
        }
    }

    fn scan_string_literal(&mut self, quote: u8) {
        self.index = self.index.saturating_add(1);

        while self.index < self.bytes.len() {
            let current = self.bytes[self.index];

            if current == b'\\' {
                self.index = self.index.saturating_add(1);
                if self.index < self.bytes.len() {
                    if self.bytes[self.index].is_ascii() {
                        self.index = self.index.saturating_add(1);
                    } else {
                        self.index = advance_utf8_boundary_safe(self.bytes, self.index);
                    }
                }
                continue;
            }

            if current == quote {
                self.index = self.index.saturating_add(1);
                break;
            }

            if current == b'\n' || current == b'\r' {
                break;
            }

            if current.is_ascii() {
                self.index = self.index.saturating_add(1);
            } else {
                self.index = advance_utf8_boundary_safe(self.bytes, self.index);
            }
        }
    }

    fn scan_template_literal(&mut self) {
        // Skip opening backtick.
        self.index = self.index.saturating_add(1);
        let mut brace_depth: u32 = 0;
        while self.index < self.bytes.len() {
            let current = self.bytes[self.index];
            if current == b'\\' {
                // Skip escape sequence.
                self.index = self.index.saturating_add(1);
                if self.index < self.bytes.len() {
                    if self.bytes[self.index].is_ascii() {
                        self.index = self.index.saturating_add(1);
                    } else {
                        self.index = advance_utf8_boundary_safe(self.bytes, self.index);
                    }
                }
                continue;
            }
            if brace_depth > 0 {
                if current == b'{' {
                    brace_depth = brace_depth.saturating_add(1);
                } else if current == b'}' {
                    brace_depth = brace_depth.saturating_sub(1);
                }
                self.index = self.index.saturating_add(1);
                continue;
            }
            if current == b'$'
                && self.index + 1 < self.bytes.len()
                && self.bytes[self.index + 1] == b'{'
            {
                brace_depth = 1;
                self.index = self.index.saturating_add(2);
                continue;
            }
            if current == b'`' {
                self.index = self.index.saturating_add(1);
                break;
            }
            if current.is_ascii() {
                self.index = self.index.saturating_add(1);
            } else {
                self.index = advance_utf8_boundary_safe(self.bytes, self.index);
            }
        }
    }

    fn advance_single_symbol(&mut self) {
        if self.bytes[self.index].is_ascii() {
            self.index = self.index.saturating_add(1);
        } else {
            self.index = advance_utf8_boundary_safe(self.bytes, self.index);
        }
    }

    fn bump_token(&mut self) {
        self.token_count = self.token_count.saturating_add(1);
    }
}

fn count_lexical_tokens(input: &str) -> u64 {
    let token_count = Utf8BoundarySafeScanner::new(input.as_bytes()).count_tokens();
    if input.is_ascii() {
        debug_assert_eq!(token_count, count_lexical_tokens_scalar_reference(input));
    }
    token_count
}

fn count_lexical_tokens_scalar_reference(input: &str) -> u64 {
    let bytes = input.as_bytes();
    let mut index = 0usize;
    let mut token_count = 0u64;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index = index.saturating_add(1);
            continue;
        }

        let ch = byte as char;
        if is_identifier_start(ch) {
            index = index.saturating_add(1);
            while index < bytes.len() && is_identifier_continue(bytes[index] as char) {
                index = index.saturating_add(1);
            }
            token_count = token_count.saturating_add(1);
            continue;
        }

        if byte.is_ascii_digit() {
            index = index.saturating_add(1);
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index = index.saturating_add(1);
            }
            token_count = token_count.saturating_add(1);
            continue;
        }

        if byte == b'\'' || byte == b'"' {
            let quote = byte;
            index = index.saturating_add(1);
            let mut terminated = false;

            while index < bytes.len() {
                let current = bytes[index];
                if current == b'\\' {
                    index = index.saturating_add(2);
                    continue;
                }
                if current == quote {
                    index = index.saturating_add(1);
                    terminated = true;
                    break;
                }
                if current == b'\n' || current == b'\r' {
                    break;
                }
                index = index.saturating_add(1);
            }

            if !terminated {
                // Token budget accounting must not force stricter syntax acceptance
                // than the parser surface itself; keep unmatched quotes tokenized.
                token_count = token_count.saturating_add(1);
                continue;
            }

            token_count = token_count.saturating_add(1);
            continue;
        }

        if byte == b'`' {
            index = index.saturating_add(1);
            let mut brace_depth = 0u32;

            while index < bytes.len() {
                let current = bytes[index];
                if current == b'\\' {
                    index = index.saturating_add(2).min(bytes.len());
                    continue;
                }
                if brace_depth > 0 {
                    if current == b'{' {
                        brace_depth = brace_depth.saturating_add(1);
                    } else if current == b'}' {
                        brace_depth = brace_depth.saturating_sub(1);
                    }
                    index = index.saturating_add(1);
                    continue;
                }
                if current == b'$' && index + 1 < bytes.len() && bytes[index + 1] == b'{' {
                    brace_depth = 1;
                    index = index.saturating_add(2);
                    continue;
                }
                if current == b'`' {
                    index = index.saturating_add(1);
                    break;
                }
                index = index.saturating_add(1);
            }

            token_count = token_count.saturating_add(1);
            continue;
        }

        if index + 1 < bytes.len() && is_two_char_operator(bytes[index], bytes[index + 1]) {
            index = index.saturating_add(2);
            token_count = token_count.saturating_add(1);
            continue;
        }

        index = index.saturating_add(1);
        token_count = token_count.saturating_add(1);
    }

    token_count
}

fn is_identifier_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_' || ch == '$'
}

fn is_identifier_continue(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'
}

fn is_identifier(input: &str) -> bool {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !is_identifier_start(first) {
        return false;
    }
    chars.all(is_identifier_continue)
}

fn canonical_module_binding_identifier(input: &str) -> Option<String> {
    let input = trim_binding_pattern_trivia(input)?;
    let identifier = canonical_source_identifier_name(input)?;
    (!is_disallowed_module_binding_name(&identifier)
        && !matches!(identifier.as_str(), "eval" | "arguments"))
    .then_some(identifier)
}

fn is_always_reserved_word(name: &str) -> bool {
    matches!(
        name,
        "break"
            | "case"
            | "catch"
            | "class"
            | "const"
            | "continue"
            | "debugger"
            | "default"
            | "delete"
            | "do"
            | "else"
            | "enum"
            | "export"
            | "extends"
            | "false"
            | "finally"
            | "for"
            | "function"
            | "if"
            | "import"
            | "in"
            | "instanceof"
            | "new"
            | "null"
            | "return"
            | "super"
            | "switch"
            | "this"
            | "throw"
            | "true"
            | "try"
            | "typeof"
            | "var"
            | "void"
            | "while"
            | "with"
    )
}

fn is_strict_reserved_word(name: &str) -> bool {
    matches!(
        name,
        "implements"
            | "interface"
            | "let"
            | "package"
            | "private"
            | "protected"
            | "public"
            | "static"
            | "yield"
    )
}

fn is_identifier_reference_in_grammar(
    name: &str,
    goal: ParseGoal,
    strict_mode: bool,
    await_identifier_reserved: bool,
    yield_identifier_reserved: bool,
) -> bool {
    !is_always_reserved_word(name)
        && !(strict_mode && is_strict_reserved_word(name))
        && !(yield_identifier_reserved && name == "yield")
        && !((goal == ParseGoal::Module || await_identifier_reserved) && name == "await")
}

fn is_binding_identifier_in_grammar(
    name: &str,
    goal: ParseGoal,
    strict_mode: bool,
    await_identifier_reserved: bool,
    yield_identifier_reserved: bool,
) -> bool {
    is_identifier_reference_in_grammar(
        name,
        goal,
        strict_mode,
        await_identifier_reserved,
        yield_identifier_reserved,
    ) && !(strict_mode && matches!(name, "eval" | "arguments"))
}

fn is_context_identifier_reference(name: &str, context: &ParseExecutionContext<'_>) -> bool {
    is_identifier_reference_in_grammar(
        name,
        context.goal,
        context.strict_mode,
        context.await_identifier_reserved,
        context.yield_identifier_reserved,
    )
}

fn is_context_binding_identifier(name: &str, context: &ParseExecutionContext<'_>) -> bool {
    is_binding_identifier_in_grammar(
        name,
        context.goal,
        context.strict_mode,
        context.await_identifier_reserved,
        context.yield_identifier_reserved,
    )
}

fn is_disallowed_module_binding_name(name: &str) -> bool {
    is_always_reserved_word(name) || is_strict_reserved_word(name) || name == "await"
}

fn canonicalize_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn to_u64(value: usize, source_label: &str, span: Option<SourceSpan>) -> ParseResult<u64> {
    u64::try_from(value).map_err(|_| {
        ParseError::new(
            ParseErrorCode::SourceTooLarge,
            "source length/offset does not fit into u64",
            source_label.to_string(),
            span,
        )
    })
}

// ---------------------------------------------------------------------------
// Static Semantics Error Taxonomy (ES2020 early errors)
// ---------------------------------------------------------------------------

/// Versioned static-semantics error taxonomy identifier.
pub const SEMANTIC_ERROR_TAXONOMY_VERSION: &str = "franken-engine.static-semantics.taxonomy.v1";

/// Stable error codes for ES2020 static-semantics early errors.
///
/// These are checked during the IR0→IR1 lowering pass to reject programs
/// that parse successfully but violate binding, scope, or module rules
/// specified by the ES2020 specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticErrorCode {
    /// `let` or `const` name already declared in the same scope.
    DuplicateLetConstDeclaration,
    /// `var` declaration conflicts with existing `let`/`const` in the same scope.
    VarConflictsWithLexical,
    /// `let`/`const` declaration conflicts with existing `var` in the same scope.
    LexicalConflictsWithVar,
    /// `const` declaration without an initializer.
    ConstWithoutInitializer,
    /// Attempted reassignment to a `const` binding.
    ConstReassignment,
    /// Reference to a `let`/`const` binding before its declaration (TDZ).
    TemporalDeadZone,
    /// `import` binding redeclared in the same module scope.
    DuplicateImportBinding,
    /// `export default` appears more than once in a module.
    DuplicateDefaultExport,
    /// Named export references an undeclared binding.
    UndeclaredExportBinding,
    /// `return` statement at module top-level (invalid).
    ModuleTopLevelReturn,
    /// `import`/`export` in script goal (caught by parser, included for completeness).
    ModuleDeclarationInScript,
    /// Duplicate parameter name in strict mode or arrow/method.
    DuplicateParameter,
    /// `eval` or `arguments` used as binding name in strict mode.
    StrictModeRestrictedBinding,
    /// `delete` of a plain identifier in strict mode.
    StrictModeDeleteIdentifier,
    /// Octal literal in strict mode.
    StrictModeOctalLiteral,
    /// `with` statement in strict mode.
    StrictModeWith,
    /// Duplicate label in the same label set.
    DuplicateLabel,
    /// `break`/`continue` references a non-existent label.
    UndefinedLabel,
    /// `break` outside of a loop or switch.
    IllegalBreak,
    /// `continue` outside of a loop.
    IllegalContinue,
    /// `await` used outside of an async context.
    AwaitOutsideAsync,
    /// `yield` used outside of a generator.
    YieldOutsideGenerator,
}

impl SemanticErrorCode {
    pub const ALL: [Self; 22] = [
        Self::DuplicateLetConstDeclaration,
        Self::VarConflictsWithLexical,
        Self::LexicalConflictsWithVar,
        Self::ConstWithoutInitializer,
        Self::ConstReassignment,
        Self::TemporalDeadZone,
        Self::DuplicateImportBinding,
        Self::DuplicateDefaultExport,
        Self::UndeclaredExportBinding,
        Self::ModuleTopLevelReturn,
        Self::ModuleDeclarationInScript,
        Self::DuplicateParameter,
        Self::StrictModeRestrictedBinding,
        Self::StrictModeDeleteIdentifier,
        Self::StrictModeOctalLiteral,
        Self::StrictModeWith,
        Self::DuplicateLabel,
        Self::UndefinedLabel,
        Self::IllegalBreak,
        Self::IllegalContinue,
        Self::AwaitOutsideAsync,
        Self::YieldOutsideGenerator,
    ];

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DuplicateLetConstDeclaration => "duplicate_let_const_declaration",
            Self::VarConflictsWithLexical => "var_conflicts_with_lexical",
            Self::LexicalConflictsWithVar => "lexical_conflicts_with_var",
            Self::ConstWithoutInitializer => "const_without_initializer",
            Self::ConstReassignment => "const_reassignment",
            Self::TemporalDeadZone => "temporal_dead_zone",
            Self::DuplicateImportBinding => "duplicate_import_binding",
            Self::DuplicateDefaultExport => "duplicate_default_export",
            Self::UndeclaredExportBinding => "undeclared_export_binding",
            Self::ModuleTopLevelReturn => "module_top_level_return",
            Self::ModuleDeclarationInScript => "module_declaration_in_script",
            Self::DuplicateParameter => "duplicate_parameter",
            Self::StrictModeRestrictedBinding => "strict_mode_restricted_binding",
            Self::StrictModeDeleteIdentifier => "strict_mode_delete_identifier",
            Self::StrictModeOctalLiteral => "strict_mode_octal_literal",
            Self::StrictModeWith => "strict_mode_with",
            Self::DuplicateLabel => "duplicate_label",
            Self::UndefinedLabel => "undefined_label",
            Self::IllegalBreak => "illegal_break",
            Self::IllegalContinue => "illegal_continue",
            Self::AwaitOutsideAsync => "await_outside_async",
            Self::YieldOutsideGenerator => "yield_outside_generator",
        }
    }

    pub const fn stable_diagnostic_code(&self) -> &'static str {
        match self {
            Self::DuplicateLetConstDeclaration => "FE-SEM-DUPLICATE-LEXICAL-0001",
            Self::VarConflictsWithLexical => "FE-SEM-VAR-LEXICAL-CONFLICT-0001",
            Self::LexicalConflictsWithVar => "FE-SEM-LEXICAL-VAR-CONFLICT-0001",
            Self::ConstWithoutInitializer => "FE-SEM-CONST-NO-INIT-0001",
            Self::ConstReassignment => "FE-SEM-CONST-REASSIGN-0001",
            Self::TemporalDeadZone => "FE-SEM-TDZ-0001",
            Self::DuplicateImportBinding => "FE-SEM-DUPLICATE-IMPORT-0001",
            Self::DuplicateDefaultExport => "FE-SEM-DUPLICATE-DEFAULT-EXPORT-0001",
            Self::UndeclaredExportBinding => "FE-SEM-UNDECLARED-EXPORT-0001",
            Self::ModuleTopLevelReturn => "FE-SEM-MODULE-RETURN-0001",
            Self::ModuleDeclarationInScript => "FE-SEM-MODULE-IN-SCRIPT-0001",
            Self::DuplicateParameter => "FE-SEM-DUPLICATE-PARAM-0001",
            Self::StrictModeRestrictedBinding => "FE-SEM-STRICT-RESTRICTED-0001",
            Self::StrictModeDeleteIdentifier => "FE-SEM-STRICT-DELETE-0001",
            Self::StrictModeOctalLiteral => "FE-SEM-STRICT-OCTAL-0001",
            Self::StrictModeWith => "FE-SEM-STRICT-WITH-0001",
            Self::DuplicateLabel => "FE-SEM-DUPLICATE-LABEL-0001",
            Self::UndefinedLabel => "FE-SEM-UNDEFINED-LABEL-0001",
            Self::IllegalBreak => "FE-SEM-ILLEGAL-BREAK-0001",
            Self::IllegalContinue => "FE-SEM-ILLEGAL-CONTINUE-0001",
            Self::AwaitOutsideAsync => "FE-SEM-AWAIT-OUTSIDE-ASYNC-0001",
            Self::YieldOutsideGenerator => "FE-SEM-YIELD-OUTSIDE-GENERATOR-0001",
        }
    }

    pub const fn diagnostic_category(&self) -> SemanticDiagnosticCategory {
        match self {
            Self::DuplicateLetConstDeclaration
            | Self::VarConflictsWithLexical
            | Self::LexicalConflictsWithVar
            | Self::DuplicateImportBinding => SemanticDiagnosticCategory::Binding,
            Self::ConstWithoutInitializer | Self::ConstReassignment | Self::TemporalDeadZone => {
                SemanticDiagnosticCategory::Binding
            }
            Self::DuplicateDefaultExport
            | Self::UndeclaredExportBinding
            | Self::ModuleTopLevelReturn
            | Self::ModuleDeclarationInScript => SemanticDiagnosticCategory::Module,
            Self::DuplicateParameter
            | Self::StrictModeRestrictedBinding
            | Self::StrictModeDeleteIdentifier
            | Self::StrictModeOctalLiteral
            | Self::StrictModeWith => SemanticDiagnosticCategory::StrictMode,
            Self::DuplicateLabel | Self::UndefinedLabel => SemanticDiagnosticCategory::Label,
            Self::IllegalBreak | Self::IllegalContinue => SemanticDiagnosticCategory::ControlFlow,
            Self::AwaitOutsideAsync | Self::YieldOutsideGenerator => {
                SemanticDiagnosticCategory::ContextRestriction
            }
        }
    }

    pub const fn diagnostic_message_template(&self) -> &'static str {
        match self {
            Self::DuplicateLetConstDeclaration => {
                "identifier has already been declared with let/const in this scope"
            }
            Self::VarConflictsWithLexical => {
                "var declaration conflicts with existing let/const binding in same scope"
            }
            Self::LexicalConflictsWithVar => {
                "let/const declaration conflicts with existing var binding in same scope"
            }
            Self::ConstWithoutInitializer => "const declaration requires an initializer",
            Self::ConstReassignment => "assignment to constant variable",
            Self::TemporalDeadZone => "cannot access lexical binding before initialization",
            Self::DuplicateImportBinding => "import binding has already been declared",
            Self::DuplicateDefaultExport => "module may not have more than one default export",
            Self::UndeclaredExportBinding => "exported name is not declared in module scope",
            Self::ModuleTopLevelReturn => "return statement is not allowed at module top-level",
            Self::ModuleDeclarationInScript => {
                "import/export declarations may only appear in module goal"
            }
            Self::DuplicateParameter => "duplicate parameter name is not allowed",
            Self::StrictModeRestrictedBinding => {
                "eval and arguments cannot be used as binding names in strict mode"
            }
            Self::StrictModeDeleteIdentifier => {
                "delete of an unqualified identifier is not allowed in strict mode"
            }
            Self::StrictModeOctalLiteral => "octal literals are not allowed in strict mode",
            Self::StrictModeWith => "with statements are not allowed in strict mode",
            Self::DuplicateLabel => "label has already been declared in this label set",
            Self::UndefinedLabel => "label is not defined in the current label set",
            Self::IllegalBreak => "break statement is not inside a loop or switch",
            Self::IllegalContinue => "continue statement is not inside a loop",
            Self::AwaitOutsideAsync => "await expression is only valid inside an async function",
            Self::YieldOutsideGenerator => {
                "yield expression is only valid inside a generator function"
            }
        }
    }
}

impl fmt::Display for SemanticErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Diagnostic category for static-semantics errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticDiagnosticCategory {
    /// Binding-level errors (declarations, redeclarations, TDZ).
    Binding,
    /// Module-specific errors (export/import rules).
    Module,
    /// Strict-mode violations.
    StrictMode,
    /// Label errors (duplicate/undefined).
    Label,
    /// Control-flow errors (break/continue outside valid context).
    ControlFlow,
    /// Context-restriction errors (await/yield outside valid context).
    ContextRestriction,
}

impl SemanticDiagnosticCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Binding => "binding",
            Self::Module => "module",
            Self::StrictMode => "strict_mode",
            Self::Label => "label",
            Self::ControlFlow => "control_flow",
            Self::ContextRestriction => "context_restriction",
        }
    }
}

/// A single static-semantics early error with source span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticError {
    pub code: SemanticErrorCode,
    pub message: String,
    pub binding_name: Option<String>,
    pub span: Option<crate::ast::SourceSpan>,
}

impl SemanticError {
    pub fn new(
        code: SemanticErrorCode,
        binding_name: Option<String>,
        span: Option<crate::ast::SourceSpan>,
    ) -> Self {
        let message = code.diagnostic_message_template().to_string();
        Self {
            code,
            message,
            binding_name,
            span,
        }
    }

    pub fn stable_diagnostic_code(&self) -> &'static str {
        self.code.stable_diagnostic_code()
    }

    pub fn diagnostic_category(&self) -> SemanticDiagnosticCategory {
        self.code.diagnostic_category()
    }
}

impl fmt::Display for SemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}",
            self.code.stable_diagnostic_code(),
            self.message
        )?;
        if let Some(name) = &self.binding_name {
            write!(f, " (binding: '{name}')")?;
        }
        Ok(())
    }
}

/// Result of static-semantics validation pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticValidationResult {
    pub errors: Vec<SemanticError>,
    pub taxonomy_version: String,
}

impl SemanticValidationResult {
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            taxonomy_version: SEMANTIC_ERROR_TAXONOMY_VERSION.to_string(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn add_error(&mut self, error: SemanticError) {
        self.errors.push(error);
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
}

impl Default for SemanticValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Control flow statement parsers
// ---------------------------------------------------------------------------

/// Extract the content between balanced delimiters starting at `open_char`.
/// Returns (content_inside, rest_after_close). `s` must start with `open_char`.
#[cfg(test)]
fn extract_balanced(s: &str, open_char: char, close_char: char) -> Option<(&str, &str)> {
    extract_balanced_with_context(s, open_char, close_char, ScanGrammarContext::SLOPPY_SCRIPT)
}

fn extract_balanced_with_context(
    s: &str,
    open_char: char,
    close_char: char,
    grammar_context: ScanGrammarContext,
) -> Option<(&str, &str)> {
    extract_balanced_with_context_seeded(s, open_char, close_char, grammar_context, None)
}

fn extract_balanced_with_context_seeded(
    s: &str,
    open_char: char,
    close_char: char,
    grammar_context: ScanGrammarContext,
    initial_class_body_depth: Option<usize>,
) -> Option<(&str, &str)> {
    if !s.starts_with(open_char) {
        return None;
    }
    let mut closing_index = None;
    let state = scan_binding_pattern_source_until_with_context_seeded(
        s,
        grammar_context,
        initial_class_body_depth,
        |index, ch, depth, quoted| {
            if closing_index.is_none() && !quoted && ch == close_char && depth == 1 {
                closing_index = Some(index);
                false
            } else {
                true
            }
        },
    );
    if !state.lexically_complete {
        return None;
    }
    let closing_index = closing_index?;
    let inner_start = open_char.len_utf8();
    let rest_start = closing_index.saturating_add(close_char.len_utf8());
    Some((&s[inner_start..closing_index], &s[rest_start..]))
}

fn top_level_yield_asi_split(source: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut in_quote: Option<u8> = None;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut escaped = false;
    let mut last_significant: Option<char> = None;
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];
        if in_line_comment {
            let line_terminator = source
                .is_char_boundary(index)
                .then(|| source[index..].chars().next())
                .flatten()
                .filter(|ch| matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}'));
            if let Some(line_terminator) = line_terminator {
                in_line_comment = false;
                index += line_terminator.len_utf8();
            } else {
                index += 1;
            }
            continue;
        }
        if in_block_comment {
            if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                in_block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if let Some(quote) = in_quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote {
                in_quote = None;
            }
            index += 1;
            continue;
        }

        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            in_line_comment = true;
            index += 2;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            in_block_comment = true;
            index += 2;
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => {
                in_quote = Some(byte);
                last_significant = Some(char::from(byte));
                index += 1;
                continue;
            }
            b'(' => paren_depth = paren_depth.saturating_add(1),
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' => bracket_depth = bracket_depth.saturating_add(1),
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'{' => brace_depth = brace_depth.saturating_add(1),
            b'}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }

        if paren_depth == 0
            && bracket_depth == 0
            && brace_depth == 0
            && source.is_char_boundary(index)
            && source[index..].starts_with("yield")
            && last_significant != Some('.')
            && source[..index].chars().next_back().is_none_or(|ch| {
                !matches!(ch, '$' | '_' | '\u{200C}' | '\u{200D}')
                    && !unicode_id_start::is_id_continue(ch)
            })
            && !starts_identifier_part(&source[index + "yield".len()..])
        {
            let rest = &source[index + "yield".len()..];
            let (after_trivia, saw_line_terminator) = trim_directive_trivia(rest);
            if saw_line_terminator
                && !after_trivia.is_empty()
                && !after_trivia.starts_with(',')
                && !after_trivia.starts_with(';')
            {
                return Some(index + "yield".len() + rest.len() - after_trivia.len());
            }
            index += "yield".len();
            continue;
        }
        if source.is_char_boundary(index)
            && let Some(ch) = source[index..].chars().next()
            && !is_binding_pattern_whitespace(ch)
        {
            last_significant = Some(ch);
        }
        index += 1;
    }
    None
}

fn split_top_level_yield_asi_segments(mut source: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    while let Some(split) = top_level_yield_asi_split(source) {
        let (before, after) = source.split_at(split);
        let before = before.trim();
        if !before.is_empty() {
            segments.push(before);
        }
        source = after.trim_start();
    }
    let source = source.trim();
    if !source.is_empty() {
        segments.push(source);
    }
    segments
}

/// Parse a block `{ ... }` body into a list of statements.
fn parse_body_statements(
    body_src: &str,
    goal: ParseGoal,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Vec<Statement>> {
    let trimmed = body_src.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let completion_recursion_limit =
        usize::try_from(context.options.budget.max_recursion_depth).unwrap_or(usize::MAX);
    let logical_lines = merge_logical_lines_with_completion_limit(
        trimmed,
        ScanGrammarContext::from_execution_context(context),
        completion_recursion_limit,
    );
    let mut stmts = Vec::new();
    for ll in &logical_lines {
        for (_start, _end, text) in split_statement_segments_with_completion_limit(
            &ll.text,
            ScanGrammarContext::from_execution_context(context),
            completion_recursion_limit,
        ) {
            if context.allow_yield_expression {
                for text in split_top_level_yield_asi_segments(text) {
                    let inner_span = span.clone();
                    stmts.push(parse_statement(text, goal, inner_span, context)?);
                }
            } else {
                let inner_span = span.clone();
                stmts.push(parse_statement(text, goal, inner_span, context)?);
            }
        }
    }
    Ok(stmts)
}

fn parse_block_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let (inner, _rest) = extract_balanced_with_context(
        statement,
        '{',
        '}',
        ScanGrammarContext::from_execution_context(context),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "unbalanced braces in block statement",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let body = parse_body_statements(inner, goal, &span, context)?;
    Ok(Statement::Block(BlockStatement { body, span }))
}

fn parse_if_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    // Strip "if" prefix and find the condition in parens.
    let after_if = statement
        .strip_prefix("if")
        .unwrap_or(statement)
        .trim_start();
    let (condition_src, rest) = extract_balanced_with_context(
        after_if,
        '(',
        ')',
        ScanGrammarContext::from_execution_context(context),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "if statement requires a parenthesized condition",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let condition = parse_expression_allowing_sequence(condition_src.trim(), &span, context, 1)?;

    let rest = rest.trim();
    // Split consequent from optional else.
    let (consequent_src, alternate_src) = if rest.starts_with('{') {
        if let Some((block_inner, after_block)) = extract_balanced_with_context(
            rest,
            '{',
            '}',
            ScanGrammarContext::from_execution_context(context),
        ) {
            let after = trim_directive_trivia(after_block).0;
            (
                format!("{{{block_inner}}}"),
                after
                    .strip_prefix("else")
                    .map(|after_else| trim_directive_trivia(after_else).0.trim_end().to_string()),
            )
        } else {
            (rest.to_string(), None)
        }
    } else {
        // Single-statement consequent: find "else" boundary.
        if let Some(else_idx) = find_top_level_else(rest) {
            let cons = rest[..else_idx].trim().to_string();
            let alt = rest[else_idx + 4..].trim().to_string();
            (cons, Some(alt))
        } else {
            (rest.to_string(), None)
        }
    };

    let consequent_stmt = parse_statement(consequent_src.trim(), goal, span.clone(), context)?;

    let alternate = if let Some(alt_src) = alternate_src {
        if !alt_src.is_empty() {
            Some(Box::new(parse_statement(
                alt_src.trim(),
                goal,
                span.clone(),
                context,
            )?))
        } else {
            None
        }
    } else {
        None
    };

    Ok(Statement::If(IfStatement {
        condition,
        consequent: Box::new(consequent_stmt),
        alternate,
        span,
    }))
}

/// Find the index of a top-level "else" keyword (not inside braces/parens/quotes).
fn find_top_level_else(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth_brace: i64 = 0;
    let mut depth_paren: i64 = 0;
    let mut in_quote: Option<u8> = None;
    let mut escaped = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                i += 1;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                in_quote = Some(b);
                i += 1;
                continue;
            }
            b'{' => {
                depth_brace += 1;
                i += 1;
                continue;
            }
            b'}' => {
                depth_brace -= 1;
                i += 1;
                continue;
            }
            b'(' => {
                depth_paren += 1;
                i += 1;
                continue;
            }
            b')' => {
                depth_paren -= 1;
                i += 1;
                continue;
            }
            _ => {}
        }
        if depth_brace == 0
            && depth_paren == 0
            && i + 4 <= bytes.len()
            && &bytes[i..i + 4] == b"else"
        {
            // Ensure "else" is a keyword boundary.
            let before_ok = i == 0 || !is_identifier_continue(bytes[i - 1] as char);
            let after_ok = i + 4 >= bytes.len() || !is_identifier_continue(bytes[i + 4] as char);
            if before_ok && after_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Split a C-style `for` header into `(init, condition, update)` on the first
/// two *top-level* semicolons (ignoring `;` inside `()`/`[]`/`{}`/quotes).
/// Anything after the second top-level `;` stays in `update` (matching the
/// previous `splitn(3, ';')` leniency). Returns `None` if fewer than two
/// top-level semicolons are present.
fn split_for_header(header: &str) -> Option<(&str, &str, &str)> {
    let bytes = header.as_bytes();
    let mut depth_paren: i64 = 0;
    let mut depth_bracket: i64 = 0;
    let mut depth_brace: i64 = 0;
    let mut in_quote: Option<u8> = None;
    let mut escaped = false;
    let mut semis: [usize; 2] = [0, 0];
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => in_quote = Some(b),
            b'(' => depth_paren += 1,
            b')' => depth_paren -= 1,
            b'[' => depth_bracket += 1,
            b']' => depth_bracket -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            b';' if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && count < 2 => {
                semis[count] = i;
                count += 1;
            }
            _ => {}
        }
        i += 1;
    }
    if count < 2 {
        return None;
    }
    Some((
        &header[..semis[0]],
        &header[semis[0] + 1..semis[1]],
        &header[semis[1] + 1..],
    ))
}

fn extract_for_header_with_context(
    statement: &str,
    grammar_context: ScanGrammarContext,
) -> Option<(&str, &str)> {
    let after_keyword = statement.strip_prefix("for")?;
    let after_trivia = trim_directive_trivia(after_keyword).0;
    if !after_trivia.starts_with('(') {
        return None;
    }
    let opening_index = statement.len().saturating_sub(after_trivia.len());
    let mut closing_index = None;
    let state = scan_binding_pattern_source_until_with_context(
        statement,
        grammar_context,
        |index, ch, depth, quoted| {
            if !quoted && ch == ')' && depth == 1 && index > opening_index {
                closing_index = Some(index);
                false
            } else {
                true
            }
        },
    );
    if !state.lexically_complete {
        return None;
    }
    let closing_index = closing_index?;
    Some((
        &statement[opening_index + '('.len_utf8()..closing_index],
        &statement[closing_index + ')'.len_utf8()..],
    ))
}

fn parse_for_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let (header_src, rest) = extract_for_header_with_context(
        statement,
        ScanGrammarContext::from_execution_context(context),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "for statement requires a parenthesized header",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    // Detect for-in / for-of before trying semicolon split.
    if let Some(forin) = try_parse_for_in_of(header_src, rest, &span, goal, context)? {
        return Ok(forin);
    }

    // Split header by top-level semicolons: init; condition; update. The split
    // must be nesting-aware so a `;` inside an arrow/block body or a string in
    // a header clause (e.g. `for (let f = () => { a; return b; }; i < n; i++)`)
    // does not mis-split the three parts.
    let (init_src, cond_src, update_src) = match split_for_header(header_src) {
        Some((init, cond, update)) => (init.trim(), cond.trim(), update.trim()),
        None => {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "for statement header must have three semicolon-separated parts",
                context.source_label.to_string(),
                Some(span),
            ));
        }
    };

    let init = if init_src.is_empty() {
        None
    } else {
        Some(Box::new(parse_statement(
            init_src,
            goal,
            span.clone(),
            context,
        )?))
    };
    let condition = if cond_src.is_empty() {
        None
    } else {
        Some(parse_expression_allowing_sequence(
            cond_src, &span, context, 1,
        )?)
    };
    let update = if update_src.is_empty() {
        None
    } else {
        Some(parse_expression_allowing_sequence(
            update_src, &span, context, 1,
        )?)
    };

    let body_src = rest.trim();
    let body = parse_statement(body_src, goal, span.clone(), context)?;

    Ok(Statement::For(ForStatement {
        init,
        condition,
        update,
        body: Box::new(body),
        span,
    }))
}

/// Detect `for (binding in expr)` or `for (binding of expr)` patterns.
/// Returns `Some(Statement)` if matched, `None` for a classic C-style for.
fn try_parse_for_in_of(
    header: &str,
    rest: &str,
    span: &SourceSpan,
    goal: ParseGoal,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Option<Statement>> {
    // A contextual `of` may itself be the binding name (`for (let of of
    // values)`). Try top-level keyword-token candidates in source order and
    // keep the first whose left side is a complete binding.
    let mut selected = None;
    let statement_context = ScanGrammarContext::from_execution_context(context);
    let grammar_context = statement_context.expression();
    for (keyword, split_pos) in find_top_level_for_in_of_keywords(header, statement_context) {
        let Some(lhs) =
            trim_binding_pattern_trivia_with_context(&header[..split_pos], grammar_context)
        else {
            continue;
        };
        let Some(rhs) = trim_binding_pattern_trivia_with_context(
            &header[split_pos + keyword.len()..],
            grammar_context,
        ) else {
            continue;
        };
        if lhs.is_empty() || rhs.is_empty() {
            continue;
        }

        // Parse binding: optionally `let x`, `const x`, `var x`, or bare `x`.
        // The declaration keyword may be followed immediately by comment/BOM
        // trivia or by a pattern delimiter.
        let mut binding_kind = parse_variable_declaration_kind(lhs);
        if keyword == "of" && binding_kind.is_none() && lhs == "let" {
            // `let` is a valid sloppy assignment target in for-in, but the
            // corresponding for-of form is an early error. Skipping this
            // candidate also lets `for (let of of values)` select the second
            // contextual `of`, where `let of` is a lexical declaration.
            continue;
        }
        let binding_src = if let Some(kind) = binding_kind {
            let Some(binding_src) = lhs.strip_prefix(kind.as_str()).and_then(|source| {
                trim_binding_pattern_trivia_with_context(source, grammar_context)
            }) else {
                continue;
            };
            if binding_src.is_empty()
                && lhs == "let"
                && keyword == "in"
                && goal == ParseGoal::Script
                && !context.strict_mode
            {
                // In sloppy Script grammar, bare `let` remains an Identifier
                // assignment target in `for (let in object)`.
                binding_kind = None;
                lhs
            } else {
                binding_src
            }
        } else {
            lhs
        };
        let parsed_binding =
            match parse_binding_pattern(binding_src, span, context, grammar_context) {
                Ok(binding) => binding,
                Err(error) if error.code == ParseErrorCode::BudgetExceeded => return Err(error),
                Err(_) => continue,
            };
        // Annex B.3.5 permits exactly one legacy loop-head initializer:
        // `for (var BindingIdentifier = AssignmentExpression in Expression)`
        // in non-strict Script code. Keep it separate from binding-pattern
        // defaults so lowering can evaluate it once before the RHS, including
        // when enumeration is empty. Every lexical, for-of, assignment-target,
        // destructuring, strict, module, rest, and multi-declarator form keeps
        // the ordinary early-error posture.
        let (binding, pre_loop_initializer) = match parsed_binding {
            BindingPattern::AssignmentPattern { left, right }
                if keyword == "in"
                    && binding_kind == Some(VariableDeclarationKind::Var)
                    && goal == ParseGoal::Script
                    && !context.strict_mode
                    && matches!(
                        split_var_declarator_segments_with_context(binding_src, grammar_context)
                            .as_slice(),
                        [declarator] if *declarator == binding_src
                    )
                    && !matches!(&right, Expression::Raw(_)) =>
            {
                let BindingPattern::Identifier(name) = *left else {
                    continue;
                };
                (BindingPattern::Identifier(name), Some(right))
            }
            BindingPattern::AssignmentPattern { .. } | BindingPattern::Rest(_) => continue,
            binding => (binding, None),
        };
        // ES2020's for-of early errors reserve bare `async`; declaration
        // bindings and the analogous for-in assignment target remain valid.
        if keyword == "of"
            && binding_kind.is_none()
            && matches!(&binding, BindingPattern::Identifier(name) if name == "async")
        {
            continue;
        }
        selected = Some((keyword, binding_kind, binding, pre_loop_initializer, rhs));
        break;
    }
    let Some((keyword, binding_kind, binding, pre_loop_initializer, rhs)) = selected else {
        return Ok(None);
    };
    if let Some(kind) = binding_kind {
        validate_lexical_binding_names(kind, &binding, span, context)?;
    }

    let body_src = rest.trim();
    let body = parse_statement(body_src, goal, span.clone(), context)?;

    if keyword == "in" {
        let object = parse_expression_allowing_sequence(rhs, span, context, 1)?;
        Ok(Some(Statement::ForIn(ForInStatement {
            binding,
            binding_kind,
            pre_loop_initializer,
            object,
            body: Box::new(body),
            span: span.clone(),
        })))
    } else {
        // ForIn accepts Expression, but ForOf requires AssignmentExpression:
        // `of first, second` is invalid unless the sequence is parenthesized.
        let iterable = parse_expression(rhs, span, context, 1)?;
        Ok(Some(Statement::ForOf(ForOfStatement {
            binding,
            binding_kind,
            iterable,
            body: Box::new(body),
            span: span.clone(),
        })))
    }
}

/// Find top-level `in`/`of` IdentifierName tokens in source order. Comments,
/// BOM, and other whitespace may separate either side of the token; member
/// names such as `object.of` are not loop delimiters.
fn find_top_level_for_in_of_keywords(
    src: &str,
    grammar_context: ScanGrammarContext,
) -> Vec<(&'static str, usize)> {
    let mut found = Vec::new();
    let mut previous_significant = None;
    scan_binding_pattern_source_with_context(src, grammar_context, |index, ch, depth, quoted| {
        if quoted {
            return;
        }
        if depth == 0 && previous_significant != Some('.') {
            for keyword in ["in", "of"] {
                let end = index.saturating_add(keyword.len());
                if ch == keyword.as_bytes()[0] as char
                    && src[index..].starts_with(keyword)
                    && !src[..index].chars().next_back().is_some_and(|previous| {
                        matches!(previous, '$' | '_' | '\\' | '\u{200C}' | '\u{200D}')
                            || unicode_id_start::is_id_continue(previous)
                    })
                    && !starts_identifier_part(&src[end..])
                {
                    found.push((keyword, index));
                    break;
                }
            }
        }
        if !is_binding_pattern_whitespace(ch) {
            previous_significant = Some(ch);
        }
    });
    found
}

fn parse_while_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let after_while = statement
        .strip_prefix("while")
        .unwrap_or(statement)
        .trim_start();
    let (condition_src, rest) = extract_balanced_with_context(
        after_while,
        '(',
        ')',
        ScanGrammarContext::from_execution_context(context),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "while statement requires a parenthesized condition",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let condition = parse_expression_allowing_sequence(condition_src.trim(), &span, context, 1)?;
    let body = parse_statement(rest.trim(), goal, span.clone(), context)?;
    Ok(Statement::While(WhileStatement {
        condition,
        body: Box::new(body),
        span,
    }))
}

fn parse_do_while_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let after_do = statement
        .strip_prefix("do")
        .unwrap_or(statement)
        .trim_start();
    // Body is a block or single statement, followed by "while(condition)"
    let (body_src, rest) = if after_do.starts_with('{') {
        let (inner, r) = extract_balanced_with_context(
            after_do,
            '{',
            '}',
            ScanGrammarContext::from_execution_context(context),
        )
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "do-while body has unbalanced braces",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        (format!("{{{inner}}}"), r.to_string())
    } else {
        let statement_context = ScanGrammarContext::from_execution_context(context);
        let while_idx =
            find_last_top_level_keyword_with_context(after_do, "while", statement_context)
                .ok_or_else(|| {
                    ParseError::new(
                        ParseErrorCode::UnsupportedSyntax,
                        "do-while statement requires 'while' after body",
                        context.source_label.to_string(),
                        Some(span.clone()),
                    )
                })?;
        (
            after_do[..while_idx].trim().to_string(),
            after_do[while_idx..].to_string(),
        )
    };

    let body = parse_statement(body_src.trim(), goal, span.clone(), context)?;

    let rest = trim_directive_trivia(&rest).0;
    let rest = rest.strip_prefix("while").unwrap_or(rest);
    let rest = trim_directive_trivia(rest).0;
    let (condition_src, _) = extract_balanced_with_context(
        rest,
        '(',
        ')',
        ScanGrammarContext::from_execution_context(context),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "do-while requires a parenthesized condition after 'while'",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let condition = parse_expression_allowing_sequence(condition_src.trim(), &span, context, 1)?;

    Ok(Statement::DoWhile(DoWhileStatement {
        body: Box::new(body),
        condition,
        span,
    }))
}

fn parse_return_statement(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let body = statement.strip_prefix("return").unwrap_or("").trim();
    let body = body.strip_suffix(';').unwrap_or(body).trim();
    let argument = if body.is_empty() {
        None
    } else {
        Some(parse_expression_allowing_sequence(body, &span, context, 1)?)
    };
    Ok(Statement::Return(ReturnStatement { argument, span }))
}

fn parse_throw_statement(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let body = statement.strip_prefix("throw").unwrap_or("").trim();
    let body = body.strip_suffix(';').unwrap_or(body).trim();
    if body.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "throw statement requires an argument",
            context.source_label.to_string(),
            Some(span),
        ));
    }
    let argument = parse_expression_allowing_sequence(body, &span, context, 1)?;
    Ok(Statement::Throw(ThrowStatement { argument, span }))
}

fn parse_try_catch_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let after_try = statement
        .strip_prefix("try")
        .unwrap_or(statement)
        .trim_start();

    // Parse the try block.
    let (try_inner, rest) = extract_balanced_with_context(
        after_try,
        '{',
        '}',
        ScanGrammarContext::from_execution_context(context),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "try statement requires a braced block",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let try_body = parse_body_statements(try_inner, goal, &span, context)?;
    let try_block = BlockStatement {
        body: try_body,
        span: span.clone(),
    };

    let rest = trim_directive_trivia(rest).0;

    // Parse optional catch clause.
    let (handler, rest) = if rest.starts_with("catch") {
        let after_catch = rest.strip_prefix("catch").unwrap_or(rest);
        let after_catch = trim_directive_trivia(after_catch).0;
        let (param, after_param) = if after_catch.starts_with('(') {
            let (p, r) = extract_balanced_with_context(
                after_catch,
                '(',
                ')',
                ScanGrammarContext::from_execution_context(context),
            )
            .ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "catch clause has unbalanced parentheses",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            })?;
            let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
            let parameter_source = trim_binding_pattern_trivia_with_context(p, grammar_context)
                .ok_or_else(|| {
                    ParseError::new(
                        ParseErrorCode::UnsupportedSyntax,
                        "catch binding has unterminated lexical trivia",
                        context.source_label.to_string(),
                        Some(span.clone()),
                    )
                })?;
            let parameter_pattern =
                parse_binding_pattern(parameter_source, &span, context, grammar_context)?;
            let mut seen_names = BTreeSet::new();
            if parameter_pattern
                .binding_names()
                .into_iter()
                .any(|name| !seen_names.insert(name.to_string()))
            {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "catch BindingPattern cannot contain duplicate binding names",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            }
            let parameter = match parameter_pattern {
                BindingPattern::Identifier(name) => name,
                // CatchClause's legacy AST carrier is still a String. Parse
                // structured patterns here so every nested binding is checked,
                // while preserving the source spelling until that carrier is
                // widened by its dedicated destructuring work.
                BindingPattern::ObjectPattern(_) | BindingPattern::ArrayPattern(_) => {
                    parameter_source.to_string()
                }
                BindingPattern::AssignmentPattern { .. } | BindingPattern::Rest(_) => {
                    return Err(ParseError::new(
                        ParseErrorCode::UnsupportedSyntax,
                        "catch parameter must be a BindingIdentifier or BindingPattern",
                        context.source_label.to_string(),
                        Some(span.clone()),
                    ));
                }
            };
            (Some(parameter), r)
        } else {
            (None, after_catch)
        };
        let after_param = trim_directive_trivia(after_param).0;
        let (catch_inner, rest2) = extract_balanced_with_context(
            after_param,
            '{',
            '}',
            ScanGrammarContext::from_execution_context(context),
        )
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "catch clause requires a braced block",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        let catch_body = parse_body_statements(catch_inner, goal, &span, context)?;
        (
            Some(CatchClause {
                parameter: param,
                body: BlockStatement {
                    body: catch_body,
                    span: span.clone(),
                },
                span: span.clone(),
            }),
            trim_directive_trivia(rest2).0,
        )
    } else {
        (None, rest)
    };

    // Parse optional finally clause.
    let finalizer = if rest.starts_with("finally") {
        let after_finally = rest.strip_prefix("finally").unwrap_or(rest);
        let after_finally = trim_directive_trivia(after_finally).0;
        let (finally_inner, _) = extract_balanced_with_context(
            after_finally,
            '{',
            '}',
            ScanGrammarContext::from_execution_context(context),
        )
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "finally clause requires a braced block",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        let finally_body = parse_body_statements(finally_inner, goal, &span, context)?;
        Some(BlockStatement {
            body: finally_body,
            span: span.clone(),
        })
    } else {
        None
    };

    if handler.is_none() && finalizer.is_none() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "try statement requires at least a catch or finally clause",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    Ok(Statement::TryCatch(TryCatchStatement {
        block: try_block,
        handler,
        finalizer,
        span,
    }))
}

fn parse_switch_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let after_switch = statement
        .strip_prefix("switch")
        .unwrap_or(statement)
        .trim_start();
    let (disc_src, rest) = extract_balanced_with_context(
        after_switch,
        '(',
        ')',
        ScanGrammarContext::from_execution_context(context),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "switch statement requires a parenthesized discriminant",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let discriminant = parse_expression_allowing_sequence(disc_src.trim(), &span, context, 1)?;

    let rest = rest.trim();
    let (body_src, _) = extract_balanced_with_context(
        rest,
        '{',
        '}',
        ScanGrammarContext::from_execution_context(context),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "switch statement requires a braced body",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    // Parse case/default clauses.
    let mut cases = Vec::new();
    let mut remaining = body_src.trim();
    while !remaining.is_empty() {
        if remaining.starts_with("case ") {
            let after_case = remaining.strip_prefix("case ").unwrap_or(remaining);
            let colon_idx = find_ternary_colon(
                after_case,
                ScanGrammarContext::from_execution_context(context).expression(),
            )
            .ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "switch case requires a colon after test expression",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            })?;
            let test_src = after_case[..colon_idx].trim();
            let test = Some(parse_expression_allowing_sequence(
                test_src, &span, context, 1,
            )?);
            let after_colon = after_case[colon_idx + 1..].trim();
            let (consequent_src, next) = split_at_next_case(after_colon);
            let consequent = parse_body_statements(consequent_src.trim(), goal, &span, context)?;
            cases.push(SwitchCase {
                test,
                consequent,
                span: span.clone(),
            });
            remaining = next.trim();
        } else if remaining.starts_with("default") {
            let after_default = remaining
                .strip_prefix("default")
                .unwrap_or(remaining)
                .trim_start();
            let after_default = after_default
                .strip_prefix(':')
                .unwrap_or(after_default)
                .trim();
            let (consequent_src, next) = split_at_next_case(after_default);
            let consequent = parse_body_statements(consequent_src.trim(), goal, &span, context)?;
            cases.push(SwitchCase {
                test: None,
                consequent,
                span: span.clone(),
            });
            remaining = next.trim();
        } else {
            // Skip whitespace or unexpected content.
            break;
        }
    }

    Ok(Statement::Switch(SwitchStatement {
        discriminant,
        cases,
        span,
    }))
}

/// Split switch body at the next `case` or `default` keyword at the top level.
fn split_at_next_case(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    let mut depth_brace: i64 = 0;
    let mut in_quote: Option<u8> = None;
    let mut escaped = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                i += 1;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                in_quote = Some(b);
                i += 1;
                continue;
            }
            b'{' => {
                depth_brace += 1;
                i += 1;
                continue;
            }
            b'}' => {
                depth_brace -= 1;
                i += 1;
                continue;
            }
            _ => {}
        }
        if depth_brace == 0 {
            // Check for "case " or "default" at keyword boundary.
            let before_ok = i == 0 || !is_identifier_continue(bytes[i - 1] as char);
            if before_ok {
                if i + 5 <= bytes.len() && &bytes[i..i + 5] == b"case " {
                    return (&s[..i], &s[i..]);
                }
                if i + 7 <= bytes.len() && &bytes[i..i + 7] == b"default" {
                    let after_ok =
                        i + 7 >= bytes.len() || !is_identifier_continue(bytes[i + 7] as char);
                    if after_ok {
                        return (&s[..i], &s[i..]);
                    }
                }
            }
        }
        i += 1;
    }
    (s, "")
}

fn parse_break_statement(
    statement: &str,
    span: SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let body = statement.strip_prefix("break").unwrap_or("").trim();
    let body = body.strip_suffix(';').unwrap_or(body).trim();
    let label = if body.is_empty() {
        None
    } else {
        let label = canonical_source_identifier_name(body)
            .filter(|label| is_context_identifier_reference(label, context));
        Some(label.ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "break label must be an IdentifierReference",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?)
    };
    Ok(Statement::Break(BreakStatement { label, span }))
}

fn parse_continue_statement(
    statement: &str,
    span: SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let body = statement.strip_prefix("continue").unwrap_or("").trim();
    let body = body.strip_suffix(';').unwrap_or(body).trim();
    let label = if body.is_empty() {
        None
    } else {
        let label = canonical_source_identifier_name(body)
            .filter(|label| is_context_identifier_reference(label, context));
        Some(label.ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "continue label must be an IdentifierReference",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?)
    };
    Ok(Statement::Continue(ContinueStatement { label, span }))
}

/// Parse a function expression: `function(a, b) { ... }` or `function name(a, b) { ... }`.
/// `rest` is the text after the `function` keyword (already stripped).
fn parse_function_expression(
    rest: &str,
    is_async: bool,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    _recursion_depth: u64,
) -> ParseResult<Expression> {
    let (rest, _) = trim_directive_trivia(rest);
    let is_generator = rest.starts_with('*');
    let rest = if is_generator { &rest[1..] } else { rest };
    let (rest, _) = trim_directive_trivia(rest);

    // Parse optional name (function expressions can be anonymous).
    let (name_source, rest) = if rest.starts_with('(') {
        (None, rest)
    } else {
        let paren_idx = rest.find('(').ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "function expression requires a parameter list",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        let name = rest[..paren_idx].trim();
        (
            if name.is_empty() { None } else { Some(name) },
            &rest[paren_idx..],
        )
    };

    // Parse parameters.
    let (params_src, rest) = extract_balanced_with_context(
        rest,
        '(',
        ')',
        ScanGrammarContext::function_parameters(is_async, is_generator, context.strict_mode),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "function expression has unbalanced parentheses",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    // Parse body.
    let rest = trim_directive_trivia(rest).0;
    let (body_src, _) = extract_balanced_with_context(
        rest,
        '{',
        '}',
        ScanGrammarContext::function_body(is_async, is_generator, context.strict_mode),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "function expression requires a braced body",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let goal = ParseGoal::Script;
    let has_own_use_strict_directive = has_use_strict_directive(body_src);
    let strict_mode = context.strict_mode || has_own_use_strict_directive;
    // FunctionExpression does not inherit the surrounding Await/Yield grammar
    // parameters for its optional name. Async/generator expressions supply
    // their own restrictions; ordinary named expressions reset both.
    let name = name_source
        .map(|source| {
            parse_required_binding_identifier(
                source,
                span,
                context,
                strict_mode,
                is_async,
                is_generator,
            )
        })
        .transpose()?;
    let params = with_grammar_context(
        context,
        strict_mode,
        is_async,
        is_generator,
        false,
        false,
        |context| parse_arrow_params(params_src, span, context),
    )?;
    validate_parameter_binding_names(
        &params,
        strict_mode,
        is_async,
        is_generator,
        false,
        span,
        context,
    )?;
    validate_use_strict_parameter_list(&params, has_own_use_strict_directive, span, context)?;
    let body_stmts = with_grammar_context(
        context,
        strict_mode,
        is_async,
        is_generator,
        is_async,
        is_generator,
        |context| parse_body_statements(body_src, goal, span, context),
    )?;

    Ok(Expression::Function {
        name,
        params,
        body: BlockStatement {
            body: body_stmts,
            span: span.clone(),
        },
        is_async,
        is_generator,
    })
}

fn parse_class_declaration(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let (name, super_class, methods) = parse_class_parts(statement, &span, context)?;
    if name.is_none() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "class declarations require a binding name",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    Ok(Statement::ClassDeclaration(ClassDeclaration {
        name,
        super_class,
        body: methods,
        span,
    }))
}

fn parse_class_expression(
    expression: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Expression> {
    let (name, super_class, methods) = parse_class_parts(expression, span, context)?;
    Ok(Expression::ClassExpression {
        name,
        super_class,
        body: methods,
    })
}

type ParsedClassParts = (
    Option<String>,
    Option<Box<Expression>>,
    Vec<MethodDefinition>,
);

fn top_level_class_body_candidates(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> Vec<usize> {
    let mut candidates = Vec::new();
    scan_binding_pattern_source_with_context(
        source,
        grammar_context,
        |index, ch, depth, quoted| {
            if !quoted && depth == 0 && ch == '{' {
                candidates.push(index);
            }
        },
    );
    candidates
}

fn parse_class_parts(
    source: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<ParsedClassParts> {
    let rest = source.strip_prefix("class").unwrap_or(source).trim_start();

    // Parse optional class name and optional `extends` clause.
    let (name_source, rest) = if rest.starts_with('{') || rest.starts_with("extends ") {
        (None, rest)
    } else {
        // Name is everything up to `{` or `extends`.
        let end = rest
            .find('{')
            .unwrap_or(rest.len())
            .min(rest.find(" extends ").unwrap_or(rest.len()));
        let name = rest[..end].trim();
        (
            if name.is_empty() { None } else { Some(name) },
            &rest[end..],
        )
    };
    // Class definitions are always strict. Their optional binding name still
    // inherits the surrounding Await/Yield grammar parameters (so `class
    // await {}` is valid in sloppy Script but not inside an async function).
    let name = name_source
        .map(|source| {
            parse_required_binding_identifier(
                source,
                span,
                context,
                true,
                context.await_identifier_reserved,
                context.yield_identifier_reserved,
            )
        })
        .transpose()?;

    let rest = rest.trim_start();

    // Parse optional extends clause.
    let (super_class, rest) = if let Some(after_extends) = rest.strip_prefix("extends ") {
        let scan_context = ScanGrammarContext::from_execution_context(context).expression();
        let mut parsed_heritage = None;
        for brace in top_level_class_body_candidates(after_extends, scan_context) {
            let super_name = after_extends[..brace].trim();
            if super_name.is_empty() {
                continue;
            }
            let Ok(super_class) =
                with_grammar_context(context, true, false, false, false, false, |context| {
                    parse_expression(super_name, span, context, 1)
                })
            else {
                continue;
            };
            if extract_balanced_with_context_seeded(
                &after_extends[brace..],
                '{',
                '}',
                scan_context,
                Some(1),
            )
            .is_some()
            {
                parsed_heritage = Some((Box::new(super_class), &after_extends[brace..]));
                break;
            }
        }
        let (super_class, class_body) = parsed_heritage.ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "class extends clause requires a superclass expression and braced body",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        (Some(super_class), class_body)
    } else {
        (None, rest)
    };

    // Parse class body { ... }.
    let (body_src, _) = extract_balanced_with_context_seeded(
        rest,
        '{',
        '}',
        ScanGrammarContext::from_execution_context(context),
        Some(1),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "class declaration requires a braced body",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    let methods = parse_class_body(body_src, span, context)?;

    Ok((name, super_class, methods))
}

/// Parse the contents of a class body into a list of MethodDefinitions.
fn parse_class_body(
    body: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Vec<MethodDefinition>> {
    let mut methods = Vec::new();
    let body = body.trim();
    if body.is_empty() {
        return Ok(methods);
    }

    // Split on top-level method boundaries.  Each method looks like:
    // [static] [async|get|set] name(...) { ... }
    // A closing brace at the outer member depth ends a method. Semicolon
    // segments are retained so unsupported native fields cannot disappear.
    let segments = split_class_members(body);
    for segment in segments {
        let segment = trim_directive_trivia(segment).0.trim_end();
        if segment.is_empty() || segment == ";" {
            continue;
        }
        let static_prefix = strip_contextual_keyword(segment, "static")
            .map(|after| trim_directive_trivia(after).0)
            .filter(|after| !after.is_empty() && !after.starts_with('('));
        let is_static = static_prefix.is_some();
        let rest = static_prefix.unwrap_or(segment);

        let (is_async, rest) = if let Some(after_async) = strip_contextual_keyword(rest, "async") {
            let (after_trivia, saw_line_terminator) = trim_directive_trivia(after_async);
            if after_trivia.starts_with('(') {
                // `async() {}` is an ordinary method named "async".
                (false, rest)
            } else if saw_line_terminator {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "async class-method modifier cannot cross a line terminator",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            } else {
                (true, after_trivia)
            }
        } else {
            (false, rest)
        };
        if is_async && rest.starts_with('*') {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "async generator class methods are not yet supported",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        let kind;
        let rest = if is_async {
            kind = MethodKind::AsyncMethod;
            rest
        } else if let Some(after) = strip_contextual_keyword(rest, "get")
            .map(|after| trim_directive_trivia(after).0)
            .filter(|after| !after.starts_with('('))
        {
            kind = MethodKind::Get;
            after
        } else if let Some(after) = strip_contextual_keyword(rest, "set")
            .map(|after| trim_directive_trivia(after).0)
            .filter(|after| !after.starts_with('('))
        {
            kind = MethodKind::Set;
            after
        } else {
            kind = MethodKind::Method;
            rest
        };

        // Core represents methods, not native fields/private elements. A
        // parameter list must follow one complete property key: searching for
        // any `(` accepted `field = function() {}` as a bogus method name.
        // The lexical depth also skips calls and braces inside computed keys.
        let error_source_label = context.source_label.to_string();
        let unsupported_member = || {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!(
                    "unsupported class member (native fields and private elements are not implemented): `{segment}`"
                ),
                error_source_label.clone(),
                Some(span.clone()),
            )
        };
        let mut paren_idx = None;
        scan_binding_pattern_source_until_with_context(
            rest,
            ScanGrammarContext::STRICT_SCRIPT.expression(),
            |index, ch, depth, quoted| {
                if !quoted && depth == 0 && ch == '(' {
                    paren_idx = Some(index);
                    false
                } else {
                    true
                }
            },
        );
        let paren_idx = paren_idx.ok_or_else(&unsupported_member)?;
        // This slice is an IdentifierName/property key, not a strict-mode
        // IdentifierReference: `yield()` and `return()` are valid names.
        // Computed-key expressions are still parsed in strict mode below.
        let method_name =
            trim_binding_pattern_trivia(&rest[..paren_idx]).ok_or_else(&unsupported_member)?;
        let (key, computed) = if method_name.starts_with('[') {
            let (inner, trailing) = extract_balanced_with_context(
                method_name,
                '[',
                ']',
                ScanGrammarContext::STRICT_SCRIPT.expression(),
            )
            .ok_or_else(&unsupported_member)?;
            if inner.trim().is_empty() || !trim_directive_trivia(trailing).0.is_empty() {
                return Err(unsupported_member());
            }
            let key = with_grammar_context(context, true, false, false, false, false, |context| {
                parse_expression(inner.trim(), span, context, 1)
            })?;
            if matches!(key, Expression::Raw(_) | Expression::SpreadElement(_)) {
                return Err(unsupported_member());
            }
            (key, true)
        } else {
            (
                with_grammar_context(context, true, false, false, false, false, |context| {
                    parse_static_property_name(method_name, span, context, "class-method")
                })
                .map_err(|_| unsupported_member())?,
                false,
            )
        };
        let is_constructor = !is_static
            && !computed
            && match &key {
                Expression::Identifier(name) => name == "constructor",
                Expression::StringLiteral(name) => name.as_str() == Some("constructor"),
                _ => false,
            };
        if is_async && is_constructor {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "class constructors cannot be async",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        let actual_kind = if is_constructor {
            MethodKind::Constructor
        } else {
            kind
        };
        let rest = &rest[paren_idx..];

        // Parse parameters.
        let (params_src, rest) = extract_balanced_with_context(
            rest,
            '(',
            ')',
            ScanGrammarContext::function_parameters(is_async, false, true),
        )
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "class method has unbalanced parentheses",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        // Parse method body.
        let rest = trim_directive_trivia(rest).0;
        let (body_src, _) = extract_balanced_with_context(
            rest,
            '{',
            '}',
            ScanGrammarContext::function_body(is_async, false, true),
        )
        .ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "class method requires a braced body",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        let goal = ParseGoal::Script;
        let has_own_use_strict_directive = has_use_strict_directive(body_src);
        let params =
            with_grammar_context(context, true, is_async, false, false, false, |context| {
                parse_arrow_params(params_src, span, context)
            })?;
        validate_parameter_binding_names(&params, true, is_async, false, false, span, context)?;
        validate_use_strict_parameter_list(&params, has_own_use_strict_directive, span, context)?;
        let body_stmts =
            with_grammar_context(context, true, is_async, false, is_async, false, |context| {
                parse_body_statements(body_src, goal, span, context)
            })?;

        methods.push(MethodDefinition {
            key,
            kind: actual_kind,
            params,
            body: BlockStatement {
                body: body_stmts,
                span: span.clone(),
            },
            is_static,
            computed,
            span: span.clone(),
        });
    }

    Ok(methods)
}

/// Split class body into individual method segments.
fn split_class_members(body: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;

    scan_binding_pattern_source_with_context_seeded(
        body,
        ScanGrammarContext::STRICT_SCRIPT,
        0,
        |index, ch, depth, quoted| {
            if quoted {
                return;
            }
            match ch {
                '}' if depth == 1 => {
                    let end = index.saturating_add(ch.len_utf8());
                    segments.push(&body[start..end]);
                    start = end;
                }
                ';' if depth == 0 => {
                    // Preserve fields for the parser's UnsupportedSyntax path;
                    // dropping their text silently removed initialization.
                    let end = index.saturating_add(ch.len_utf8());
                    segments.push(&body[start..end]);
                    start = end;
                }
                _ => {}
            }
        },
    );
    let remaining = body[start..].trim();
    if !remaining.is_empty() {
        segments.push(remaining);
    }
    segments
}

fn parse_function_declaration(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let (is_async, rest) = if let Some(rest) = strip_async_function_keyword(statement) {
        (true, rest)
    } else {
        (
            false,
            strip_contextual_keyword(statement, "function").unwrap_or(statement),
        )
    };
    let (rest, _) = trim_directive_trivia(rest);
    let is_generator = rest.starts_with('*');
    let rest = if is_generator { &rest[1..] } else { rest };
    let (rest, _) = trim_directive_trivia(rest);

    // Parse function name (optional for expressions, required for declarations).
    let (name_source, rest) = if rest.starts_with('(') {
        (None, rest)
    } else {
        // Extract name up to '('.
        let paren_idx = rest.find('(').ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "function declaration requires a parameter list",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        let name = rest[..paren_idx].trim();
        (
            if name.is_empty() { None } else { Some(name) },
            &rest[paren_idx..],
        )
    };

    if name_source.is_none() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "function declarations require a binding name",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    // Parse parameters.
    let (params_src, rest) = extract_balanced_with_context(
        rest,
        '(',
        ')',
        ScanGrammarContext::function_parameters(is_async, is_generator, context.strict_mode),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "function declaration has unbalanced parentheses",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    // Parse body.
    let rest = rest.trim_start();
    let (body_src, _) = extract_balanced_with_context(
        rest,
        '{',
        '}',
        ScanGrammarContext::function_body(is_async, is_generator, context.strict_mode),
    )
    .ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "function declaration requires a braced body",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let goal = ParseGoal::Script; // Function bodies use script goal.
    let has_own_use_strict_directive = has_use_strict_directive(body_src);
    let strict_mode = context.strict_mode || has_own_use_strict_directive;
    // FunctionDeclaration names inherit the surrounding Await/Yield grammar
    // parameters. The declaration's own async/generator marker constrains its
    // parameters and body, but does not by itself reserve the declaration name
    // (`async function await(){}` is valid in sloppy Script).
    let name = name_source
        .map(|source| {
            parse_required_binding_identifier(
                source,
                &span,
                context,
                strict_mode,
                context.await_identifier_reserved,
                context.yield_identifier_reserved,
            )
        })
        .transpose()?;
    let params = with_grammar_context(
        context,
        strict_mode,
        is_async,
        is_generator,
        false,
        false,
        |context| parse_arrow_params(params_src, &span, context),
    )?;
    validate_parameter_binding_names(
        &params,
        strict_mode,
        is_async,
        is_generator,
        false,
        &span,
        context,
    )?;
    validate_use_strict_parameter_list(&params, has_own_use_strict_directive, &span, context)?;
    let body_stmts = with_grammar_context(
        context,
        strict_mode,
        is_async,
        is_generator,
        is_async,
        is_generator,
        |context| parse_body_statements(body_src, goal, &span, context),
    )?;

    Ok(Statement::FunctionDeclaration(FunctionDeclaration {
        name,
        params,
        body: BlockStatement {
            body: body_stmts,
            span: span.clone(),
        },
        is_async,
        is_generator,
        span,
    }))
}

#[cfg(test)]
#[path = "parser_inline_tests.rs"]
mod tests;
